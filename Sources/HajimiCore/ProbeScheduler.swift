import Foundation

/// Process-wide admission for manual latency tests and automatic policy probes.
/// Admission happens under a lock, before any asynchronous work is enqueued.
/// A single deadline timer is parked while idle; finished requests do not leave
/// one retained timeout closure per probe behind.
public final class ProbeScheduler {
    public static let shared = ProbeScheduler()

    public enum Failure: Error, LocalizedError, Equatable {
        case capacityExceeded
        case connectionBudgetExceeded
        case queueWaitExpired
        case requestExpired
        case cancelled

        public var errorDescription: String? {
            switch self {
            case .capacityExceeded: return "测速队列已满，请稍后重试"
            case .connectionBudgetExceeded: return "测速连接尚在建立或清理，已达资源限额，请稍后重试"
            case .queueWaitExpired: return "测速排队等待超时"
            case .requestExpired: return "测速请求超时"
            case .cancelled: return "测速已取消"
            }
        }
    }

    public struct Snapshot: Equatable {
        public var active: Int
        public var queued: Int
        public var maximumActive: Int
        public var maximumQueued: Int
        public var completed: UInt64
        public var rejected: UInt64
        public var cancelled: UInt64
        public var queueTimeouts: UInt64
        public var requestTimeouts: UInt64
        public var pendingConnections: Int
        public var rejectedConnections: UInt64
        public var latestQueueWaitMilliseconds: Double?
    }

    public final class ConnectionReservation {
        private let id: UUID
        private weak var scheduler: ProbeScheduler?

        fileprivate init(id: UUID, scheduler: ProbeScheduler) { self.id = id; self.scheduler = scheduler }

        /// Release only after the underlying connect callback has arrived (and
        /// a late successful stream has been closed), not on logical timeout.
        /// Dropping this handle deliberately does not return a physical slot.
        public func release() { scheduler?.releaseConnection(id) }
    }

    public final class Ticket {
        public let id: UUID
        private weak var scheduler: ProbeScheduler?

        fileprivate init(id: UUID, scheduler: ProbeScheduler) {
            self.id = id; self.scheduler = scheduler
        }

        /// Idempotent. Dropping a ticket does not implicitly cancel the probe.
        public func cancel() { scheduler?.cancel(id) }
    }

    public final class Lease {
        public let queue: DispatchQueue
        /// Monotonic absolute deadline, including time already spent waiting.
        public let deadline: DispatchTime
        private let id: UUID
        private weak var scheduler: ProbeScheduler?

        fileprivate init(id: UUID, queue: DispatchQueue, deadline: DispatchTime,
                         scheduler: ProbeScheduler) {
            self.id = id; self.queue = queue; self.deadline = deadline
            self.scheduler = scheduler
        }

        public var isActive: Bool { scheduler?.isActive(id) == true }

        /// The handler runs on this lease's serial lane, on completion as well
        /// as cancellation. Register it before starting resource-owning work.
        /// If cancellation already won, the handler is still invoked and false
        /// is returned, so a caller must not start a new connection afterward.
        @discardableResult
        public func setCancellationHandler(_ handler: @escaping () -> Void) -> Bool {
            guard let scheduler else { queue.async(execute: handler); return false }
            return scheduler.registerCancellation(id, queue: queue, handler: handler)
        }

        /// Exactly one completion or scheduler failure wins. A late completion
        /// must clean up its resources, but must not deliver a second result.
        @discardableResult
        public func complete() -> Bool { scheduler?.complete(id) == true }
    }

    private final class Entry {
        let id: UUID
        let submitted: DispatchTime
        let queueDeadline: DispatchTime
        let requestDeadline: DispatchTime
        let timeout: TimeInterval
        let callbackQueue: DispatchQueue
        let start: (Lease) -> Void
        let failure: (Failure) -> Void
        var lease: Lease?
        var cancellation: (() -> Void)?
        var expiration: DispatchTime

        init(id: UUID, submitted: DispatchTime, queueWait: TimeInterval,
             timeout: TimeInterval, callbackQueue: DispatchQueue,
             start: @escaping (Lease) -> Void, failure: @escaping (Failure) -> Void) {
            self.id = id; self.submitted = submitted; self.timeout = timeout
            queueDeadline = submitted + queueWait
            requestDeadline = submitted + queueWait + timeout
            expiration = queueDeadline
            self.callbackQueue = callbackQueue; self.start = start; self.failure = failure
        }
    }

    private struct Effects {
        var starts: [Entry] = []
        var failures: [(Entry, Failure)] = []
        var cleanups: [(DispatchQueue, () -> Void)] = []

        mutating func append(_ other: Effects) {
            starts += other.starts; failures += other.failures; cleanups += other.cleanups
        }
    }

    private let lock = NSLock()
    private let workerQueue: DispatchQueue
    private let timer: DispatchSourceTimer
    private let maximumActive: Int
    private let maximumQueued: Int
    private var entries: [UUID: Entry] = [:]
    private var pending: [UUID] = []
    private var active = 0
    private var completed: UInt64 = 0
    private var rejected: UInt64 = 0
    private var cancelled: UInt64 = 0
    private var queueTimeouts: UInt64 = 0
    private var requestTimeouts: UInt64 = 0
    private var pendingConnections = Set<UUID>()
    private var rejectedConnections: UInt64 = 0
    private var latestQueueWaitMilliseconds: Double?

    public init(maximumActive: Int = 8, maximumQueued: Int = 512) {
        self.maximumActive = min(64, max(1, maximumActive))
        self.maximumQueued = min(4_096, max(0, maximumQueued))
        let label = "app.hajimi.probes.\(UUID().uuidString)"
        workerQueue = DispatchQueue(label: label + ".workers", qos: .utility,
                                    attributes: .concurrent)
        timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: label + ".deadlines", qos: .utility))
        timer.schedule(deadline: .distantFuture)
        timer.setEventHandler { [weak self] in self?.expire() }
        timer.resume()
    }

    deinit { timer.setEventHandler {}; timer.cancel() }

    /// `queueWait` bounds time before a slot becomes available. `timeout`
    /// bounds actual work; the absolute request deadline is submission time
    /// plus both budgets. Network latency starts in `start`, not in this queue.
    @discardableResult
    public func submit(timeout: TimeInterval, queueWait: TimeInterval = 20,
                       callbackQueue: DispatchQueue,
                       start: @escaping (Lease) -> Void,
                       failure: @escaping (Failure) -> Void) -> Ticket {
        let id = UUID()
        let ticket = Ticket(id: id, scheduler: self)
        let timeout = Self.budget(timeout, fallback: 5, maximum: 300)
        let queueWait = Self.budget(queueWait, fallback: 20, maximum: 60)
        let now = DispatchTime.now()
        let entry = Entry(id: id, submitted: now, queueWait: queueWait, timeout: timeout,
                          callbackQueue: callbackQueue, start: start, failure: failure)
        lock.lock()
        var effects = advanceLocked(now: now)
        if active >= maximumActive && pending.count >= maximumQueued {
            rejected &+= 1
            effects.failures.append((entry, .capacityExceeded))
        } else {
            entries[id] = entry
            pending.append(id)
            effects.append(advanceLocked(now: now))
        }
        lock.unlock()
        perform(effects)
        return ticket
    }

    public func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(active: active, queued: pending.count,
                        maximumActive: maximumActive, maximumQueued: maximumQueued,
                        completed: completed, rejected: rejected, cancelled: cancelled,
                        queueTimeouts: queueTimeouts, requestTimeouts: requestTimeouts,
                        pendingConnections: pendingConnections.count, rejectedConnections: rejectedConnections,
                        latestQueueWaitMilliseconds: latestQueueWaitMilliseconds)
    }

    /// Separate physical admission for connectors that do not yet expose an
    /// in-progress cancellation handle. A cancelled logical lease must not
    /// admit an unbounded chain of still-establishing native connections.
    public func reservePendingConnection() -> ConnectionReservation? {
        lock.lock(); defer { lock.unlock() }
        guard pendingConnections.count < maximumActive else { rejectedConnections &+= 1; return nil }
        let id = UUID()
        pendingConnections.insert(id)
        return ConnectionReservation(id: id, scheduler: self)
    }

    private func releaseConnection(_ id: UUID) {
        lock.lock(); pendingConnections.remove(id); lock.unlock()
    }

    private static func budget(_ value: TimeInterval, fallback: TimeInterval,
                               maximum: TimeInterval) -> TimeInterval {
        value.isFinite && value > 0 ? min(maximum, max(0.01, value)) : fallback
    }

    private func isActive(_ id: UUID) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let entry = entries[id], entry.lease != nil else { return false }
        return DispatchTime.now().uptimeNanoseconds < entry.expiration.uptimeNanoseconds
    }

    private func registerCancellation(_ id: UUID, queue: DispatchQueue,
                                      handler: @escaping () -> Void) -> Bool {
        lock.lock()
        let live: Bool
        if let entry = entries[id], entry.lease != nil,
           DispatchTime.now().uptimeNanoseconds < entry.expiration.uptimeNanoseconds {
            // A probe installs one cleanup closure before owning any resource.
            entry.cancellation = handler
            live = true
        } else { live = false }
        lock.unlock()
        if !live { queue.async(execute: handler) }
        return live
    }

    private func complete(_ id: UUID) -> Bool {
        let now = DispatchTime.now()
        lock.lock()
        var effects = advanceLocked(now: now)
        let won: Bool
        if let entry = entries.removeValue(forKey: id), let lease = entry.lease {
            active -= 1; completed &+= 1; won = true
            if let cancellation = entry.cancellation { effects.cleanups.append((lease.queue, cancellation)) }
        } else { won = false }
        effects.append(advanceLocked(now: now))
        lock.unlock()
        perform(effects)
        return won
    }

    private func cancel(_ id: UUID) {
        lock.lock()
        var effects = advanceLocked(now: .now())
        if let entry = entries.removeValue(forKey: id) {
            if let lease = entry.lease {
                active -= 1
                if let cancellation = entry.cancellation { effects.cleanups.append((lease.queue, cancellation)) }
            }
            cancelled &+= 1
            effects.failures.append((entry, .cancelled))
        }
        effects.append(advanceLocked(now: .now()))
        lock.unlock()
        perform(effects)
    }

    private func expire() {
        lock.lock()
        let effects = advanceLocked(now: .now())
        lock.unlock()
        perform(effects)
    }

    /// Lock held. Drops expired requests before starting more work, so a busy
    /// timer queue cannot make an already-expired queued probe dial a socket.
    private func advanceLocked(now: DispatchTime) -> Effects {
        var effects = Effects()
        for entry in Array(entries.values) where now.uptimeNanoseconds >= entry.expiration.uptimeNanoseconds {
            entries.removeValue(forKey: entry.id)
            if let lease = entry.lease {
                active -= 1; requestTimeouts &+= 1
                if let cancellation = entry.cancellation { effects.cleanups.append((lease.queue, cancellation)) }
                effects.failures.append((entry, .requestExpired))
            } else {
                queueTimeouts &+= 1
                effects.failures.append((entry, .queueWaitExpired))
            }
        }
        pending.removeAll { entries[$0] == nil }
        while active < maximumActive, !pending.isEmpty {
            let id = pending.removeFirst()
            guard let entry = entries[id] else { continue }
            entry.expiration = DispatchTime(uptimeNanoseconds: min(entry.requestDeadline.uptimeNanoseconds,
                                                                   (now + entry.timeout).uptimeNanoseconds))
            let lane = DispatchQueue(label: "app.hajimi.probe.\(id.uuidString)", target: workerQueue)
            entry.lease = Lease(id: id, queue: lane, deadline: entry.expiration, scheduler: self)
            active += 1
            latestQueueWaitMilliseconds = Double(now.uptimeNanoseconds - entry.submitted.uptimeNanoseconds) / 1_000_000
            effects.starts.append(entry)
        }
        let deadline = entries.values.map(\.expiration).min { $0.uptimeNanoseconds < $1.uptimeNanoseconds }
            ?? .distantFuture
        timer.schedule(deadline: deadline, leeway: .milliseconds(5))
        return effects
    }

    private func perform(_ effects: Effects) {
        for (queue, cleanup) in effects.cleanups { queue.async(execute: cleanup) }
        for (entry, failure) in effects.failures {
            entry.callbackQueue.async { entry.failure(failure) }
        }
        for entry in effects.starts {
            guard let lease = entry.lease else { continue }
            lease.queue.async {
                guard lease.isActive else { return }
                entry.start(lease)
            }
        }
    }
}

/// Pure in-memory admission/deadline/cancellation regressions. No listener,
/// DNS request, network interface lookup or UI is constructed by these tests.
public enum ProbeSchedulerSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "测速调度自检失败：\(text)" }
    }

    private final class State {
        let lock = NSLock()
        var leases: [ProbeScheduler.Lease] = []
        var failures: [ProbeScheduler.Failure] = []
        var cleanups = 0
        let started = DispatchSemaphore(value: 0)
        let failed = DispatchSemaphore(value: 0)

        func start(_ lease: ProbeScheduler.Lease) {
            lease.setCancellationHandler { [weak self] in
                guard let self else { return }
                self.lock.lock(); self.cleanups += 1; self.lock.unlock()
            }
            lock.lock(); leases.append(lease); lock.unlock(); started.signal()
        }

        func fail(_ failure: ProbeScheduler.Failure) {
            lock.lock(); failures.append(failure); lock.unlock(); failed.signal()
        }
    }

    public static func run() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        let callbacks = DispatchQueue(label: "app.hajimi.probes.selftest.callbacks")
        let scheduler = ProbeScheduler(maximumActive: 2, maximumQueued: 2)
        let state = State()
        var tickets: [ProbeScheduler.Ticket] = []
        for _ in 0..<5 {
            tickets.append(scheduler.submit(timeout: 3, queueWait: 3, callbackQueue: callbacks,
                                            start: state.start, failure: state.fail))
        }
        try require(state.started.wait(timeout: .now() + 2) == .success
                    && state.started.wait(timeout: .now() + 2) == .success,
                    "并发名额没有按预期启动")
        try require(state.failed.wait(timeout: .now() + 2) == .success, "队列超限未明确失败")
        let full = scheduler.snapshot()
        try require(full.active == 2 && full.queued == 2 && full.rejected == 1,
                    "全局活跃或排队名额越界")
        state.lock.lock(); let first = state.leases[0]; let failures = state.failures; state.lock.unlock()
        try require(failures == [.capacityExceeded], "超限错误类型错误")
        try require(first.complete() && !first.complete(), "完成回调未实现恰好一次")
        try require(state.started.wait(timeout: .now() + 2) == .success, "释放名额后排队任务未启动")
        tickets.forEach { $0.cancel() }
        callbacks.sync {}
        try require(scheduler.snapshot().active == 0 && scheduler.snapshot().queued == 0,
                    "取消未释放全部调度名额")

        let deadlines = ProbeScheduler(maximumActive: 1, maximumQueued: 1)
        let timed = State()
        let running = deadlines.submit(timeout: 0.15, queueWait: 2, callbackQueue: callbacks,
                                       start: timed.start, failure: timed.fail)
        try require(timed.started.wait(timeout: .now() + 2) == .success, "超时测试未启动")
        _ = deadlines.submit(timeout: 2, queueWait: 0.03, callbackQueue: callbacks,
                             start: timed.start, failure: timed.fail)
        try require(timed.failed.wait(timeout: .now() + 2) == .success
                    && timed.failed.wait(timeout: .now() + 2) == .success,
                    "队列或请求 deadline 没有完成失败回调")
        timed.lock.lock(); let timedFailures = timed.failures; let late = timed.leases[0]; timed.lock.unlock()
        try require(timedFailures.contains(.queueWaitExpired) && timedFailures.contains(.requestExpired),
                    "未区分排队与运行超时")
        try require(!late.complete(), "迟到完成复活了已结束的请求")
        running.cancel()
        try require(deadlines.snapshot().active == 0 && deadlines.snapshot().queued == 0,
                    "超时遗留名额")

        let racing = ProbeScheduler(maximumActive: 1, maximumQueued: 0)
        let raced = State()
        let ticket = racing.submit(timeout: 3, callbackQueue: callbacks, start: raced.start, failure: raced.fail)
        try require(raced.started.wait(timeout: .now() + 2) == .success, "竞态测试未启动")
        raced.lock.lock(); let lease = raced.leases[0]; raced.lock.unlock()
        let group = DispatchGroup()
        let wins = NSLock()
        var completions = 0
        for index in 0..<32 {
            group.enter()
            DispatchQueue.global().async {
                if index.isMultiple(of: 2) { ticket.cancel() }
                else if lease.complete() { wins.lock(); completions += 1; wins.unlock() }
                group.leave()
            }
        }
        try require(group.wait(timeout: .now() + 2) == .success, "取消/完成竞态测试超时")
        callbacks.sync {}
        raced.lock.lock(); let failureCount = raced.failures.count; raced.lock.unlock()
        try require(completions + failureCount == 1 && racing.snapshot().active == 0,
                    "取消与完成重复投递或遗留名额")

        let physical = ProbeScheduler(maximumActive: 1)
        guard let pending = physical.reservePendingConnection() else {
            throw Failure(text: "物理 pending 名额没有分配")
        }
        let held = State()
        let logical = physical.submit(timeout: 3, callbackQueue: callbacks, start: held.start, failure: held.fail)
        try require(held.started.wait(timeout: .now() + 2) == .success, "物理预算测试未启动")
        logical.cancel()
        try require(physical.snapshot().active == 0 && physical.snapshot().pendingConnections == 1
                    && physical.reservePendingConnection() == nil,
                    "逻辑取消提前归还了尚未结束的物理连接名额")
        pending.release(); pending.release()
        try require(physical.snapshot().pendingConnections == 0 && physical.reservePendingConnection() != nil,
                    "迟到回调未释放物理名额或重复释放造成错误")
    }
}

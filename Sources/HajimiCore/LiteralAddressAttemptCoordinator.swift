import Foundation
import Darwin

public enum NodeConnectionAdmissionError: Error, LocalizedError, CustomNSError {
    case capacityExceeded
    public static var errorDomain: String { "app.hajimi.node-connection-admission" }
    public var errorCode: Int { 1 }
    public var errorDescription: String? { "节点解析或连接资源已达上限，请稍后重试" }
    public var errorUserInfo: [String: Any] { [NSLocalizedDescriptionKey: errorDescription!] }
}

enum LiteralAddressAttemptClock {
    static var now: TimeInterval {
        #if canImport(Darwin)
        let nanos = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
        if nanos > 0 { return Double(nanos) / 1_000_000_000 }
        #endif
        return Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
    }
}

private struct LiteralAddressAttemptFailure: LocalizedError {
    let text: String
    var errorDescription: String? { text }
}

/// Counts physical attempts, including revoked attempts whose dialer has not
/// delivered its callback yet. Cancellation alone never returns a slot.
final class LiteralAddressAttemptBudget {
    static let shared = LiteralAddressAttemptBudget(limit: 128)
    private let lock = NSLock()
    private let limit: Int
    private var count = 0

    init(limit: Int) { self.limit = min(128, max(0, limit)) }
    var usage: Int { lock.lock(); defer { lock.unlock() }; return count }

    func reserve() -> LiteralAddressAttemptReservation? {
        lock.lock()
        guard count < limit else { lock.unlock(); return nil }
        count += 1; lock.unlock()
        return LiteralAddressAttemptReservation { [self] in
            lock.lock(); count -= 1; lock.unlock()
        }
    }
}

final class LiteralAddressAttemptReservation {
    private let lock = NSLock()
    private var release: (() -> Void)?
    init(_ release: @escaping () -> Void) { self.release = release }
    func complete() {
        lock.lock(); let action = release; release = nil; lock.unlock()
        action?()
    }
    // Deliberately no deinit release: an abandoned, unacknowledged physical
    // dial must not make room for an unbounded number of replacement dials.
}

private final class LiteralAddressAttemptCancellation {
    private let lock = NSLock()
    private var action: (() -> Void)?
    init(_ action: @escaping () -> Void) { self.action = action }
    func cancel() {
        lock.lock(); let work = action; action = nil; lock.unlock()
        work?()
    }
}

private final class LiteralAddressAttemptPublication {
    private enum State { case pending, revoked, published }
    private let lock = NSLock()
    private var state = State.pending
    var revoked: Bool { lock.lock(); defer { lock.unlock() }; return state == .revoked }
    func revoke() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard state == .pending else { return false }
        state = .revoked; return true
    }
    func publish(allowed: Bool) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let accepted = state == .pending && allowed
        state = .published
        return accepted
    }
}

private final class LiteralAddressAttemptDelivery<Connection: AnyObject> {
    private let lock = NSLock()
    private var delivered = false
    private weak var first: Connection?
    private let reservation: LiteralAddressAttemptReservation
    init(_ reservation: LiteralAddressAttemptReservation) { self.reservation = reservation }
    func accept(_ result: Result<Connection, Error>) -> Bool {
        lock.lock()
        guard !delivered else { lock.unlock(); return false }
        delivered = true
        if case .success(let value) = result { first = value }
        lock.unlock()
        reservation.complete()
        return true
    }
    func isOriginal(_ value: Connection) -> Bool {
        lock.lock(); defer { lock.unlock() }; return first === value
    }
}

/// A bounded, literal-only Happy Eyeballs owner. The DNS caller supplies one
/// monotonic absolute deadline; every dial receives only its remaining time.
/// The caller's SNI, interface and configuration generation belong in `dial`
/// and `permitted`, not in the candidate address. No resolver is used here.
final class LiteralAddressAttemptCoordinator<Connection: AnyObject> {
    typealias Dial = (String, TimeInterval, @escaping (Result<Connection, Error>) -> Void) -> (() -> Void)
    typealias Schedule = (TimeInterval, @escaping () -> Void) -> (() -> Void)

    private struct Attempt {
        var cancellation: LiteralAddressAttemptCancellation?
        var timeoutCancellation: LiteralAddressAttemptCancellation?
        let deadline: TimeInterval
        var expired = false
    }
    private let queue: DispatchQueue
    private let callbackQueue: DispatchQueue
    private let clock: () -> TimeInterval
    private let scheduler: Schedule
    private let budget: LiteralAddressAttemptBudget
    private let deadline: TimeInterval
    private let started: TimeInterval
    private let stagger: TimeInterval
    private let maximumConcurrent: Int
    private let permitted: () -> Bool
    private let dial: Dial
    private let dispose: (Connection) -> Void
    private let publication = LiteralAddressAttemptPublication()
    private var addresses: [String]?
    private var next = 0
    private var attempts: [UUID: Attempt] = [:]
    private var deadlineCancellation: LiteralAddressAttemptCancellation?
    private var staggerCancellation: LiteralAddressAttemptCancellation?
    private var lastError: Error?
    private var lastTime: TimeInterval
    private var completion: ((Result<Connection, Error>) -> Void)?
    private var finished = false
    private var keepAlive: LiteralAddressAttemptCoordinator?

    @discardableResult
    static func start(addresses: [String], deadline: TimeInterval, queue: DispatchQueue,
                      stagger: TimeInterval = 0.2, maximumConcurrent: Int = 2,
                      permitted: @escaping () -> Bool = { true },
                      clock: @escaping () -> TimeInterval = { LiteralAddressAttemptClock.now },
                      schedule: Schedule? = nil, budget: LiteralAddressAttemptBudget = .shared,
                      dial: @escaping Dial, dispose: @escaping (Connection) -> Void,
                      completion: @escaping (Result<Connection, Error>) -> Void)
        -> LiteralAddressAttemptCoordinator {
        let owner = LiteralAddressAttemptCoordinator(addresses: addresses, deadline: deadline,
            queue: queue, stagger: stagger, maximumConcurrent: maximumConcurrent,
            permitted: permitted, clock: clock, schedule: schedule, budget: budget,
            dial: dial, dispose: dispose, completion: completion)
        owner.queue.async { [owner] in owner.begin() }
        return owner
    }

    private init(addresses: [String], deadline: TimeInterval, queue target: DispatchQueue,
                 stagger: TimeInterval, maximumConcurrent: Int, permitted: @escaping () -> Bool,
                 clock: @escaping () -> TimeInterval, schedule: Schedule?,
                 budget: LiteralAddressAttemptBudget, dial: @escaping Dial,
                 dispose: @escaping (Connection) -> Void,
                 completion: @escaping (Result<Connection, Error>) -> Void) {
        let queue = DispatchQueue(label: "app.hajimi.address-attempts", qos: .userInitiated, target: target)
        self.queue = queue; callbackQueue = target; self.clock = clock
        scheduler = schedule ?? { delay, work in
            let item = DispatchWorkItem(block: work)
            queue.asyncAfter(deadline: .now() + max(0, delay), execute: item)
            return { item.cancel() }
        }
        self.budget = budget; self.permitted = permitted; self.dial = dial; self.dispose = dispose
        self.completion = completion
        started = clock(); lastTime = started
        self.deadline = deadline.isFinite ? min(deadline, started + 12) : started
        self.stagger = stagger.isFinite ? min(1, max(0.01, stagger)) : 0.2
        self.maximumConcurrent = min(2, max(1, maximumConcurrent))
        self.addresses = Self.orderedLiterals(addresses)
    }

    func cancel() {
        guard publication.revoke() else { return }
        queue.async { [self] in finish(.failure(Self.failure("地址连接已取消"))) }
    }

    private func remaining() -> TimeInterval {
        let now = clock()
        guard now.isFinite, now >= lastTime else { return 0 }
        lastTime = now
        return deadline - now
    }

    private func begin() {
        keepAlive = self
        guard let addresses, !addresses.isEmpty else {
            finish(.failure(Self.failure("连接候选必须是有界的 literal IP 地址"))); return
        }
        guard started.isFinite, remaining() > 0, !publication.revoked, permitted() else {
            finish(.failure(Self.failure("地址连接已取消、过期或配置已更新"))); return
        }
        deadlineCancellation = LiteralAddressAttemptCancellation(scheduler(remaining()) { [weak self] in
            guard let self else { return }
            self.queue.async { self.finish(.failure(Self.failure("地址连接超过总截止时间"))) }
        })
        launch()
        scheduleNext()
    }

    private func launch() {
        guard !finished, let addresses, next < addresses.count, attempts.count < maximumConcurrent else { return }
        guard remaining() > 0, !publication.revoked, permitted() else {
            finish(.failure(Self.failure("地址连接已取消、过期或配置已更新"))); return
        }
        guard let reservation = budget.reserve() else {
            lastError = NodeConnectionAdmissionError.capacityExceeded
            if attempts.isEmpty { finish(.failure(lastError!)) }
            return
        }
        let id = UUID(), address = addresses[next]
        let available = remaining()
        guard available > 0 else {
            reservation.complete(); finish(.failure(Self.failure("地址连接超过总截止时间"))); return
        }
        let waves = max(1, (addresses.count - next + attempts.count + maximumConcurrent - 1) / maximumConcurrent)
        let duration = available / Double(waves)
        let attemptDeadline = clock() + duration
        next += 1; attempts[id] = Attempt(deadline: attemptDeadline)
        let delivery = LiteralAddressAttemptDelivery<Connection>(reservation), dispose = self.dispose
        let cancel = dial(address, duration) { [weak self, delivery] result in
            guard delivery.accept(result) else {
                if case .success(let value) = result, !delivery.isOriginal(value) { dispose(value) }
                return
            }
            guard let self else {
                if case .success(let value) = result { dispose(value) }
                return
            }
            self.queue.async { self.receive(result, id: id) }
        }
        attempts[id]?.cancellation = LiteralAddressAttemptCancellation(cancel)
        attempts[id]?.timeoutCancellation = LiteralAddressAttemptCancellation(scheduler(duration) { [weak self] in
            guard let self else { return }
            self.queue.async {
                guard !self.finished, self.attempts[id] != nil else { return }
                self.attempts[id]?.expired = true
                self.attempts[id]?.cancellation?.cancel()
                // Do not launch another candidate until this physical dial's
                // callback acknowledges cancellation and returns its slot.
            }
        })
    }

    private func scheduleNext() {
        guard !finished, staggerCancellation == nil, let addresses,
              next < addresses.count, !attempts.isEmpty, attempts.count < maximumConcurrent else { return }
        staggerCancellation = LiteralAddressAttemptCancellation(scheduler(min(stagger, max(0, remaining()))) { [weak self] in
            guard let self else { return }
            self.queue.async {
                self.staggerCancellation = nil
                self.launch(); self.scheduleNext()
            }
        })
    }

    private func receive(_ result: Result<Connection, Error>, id: UUID) {
        guard !finished, let attempt = attempts.removeValue(forKey: id) else {
            if case .success(let value) = result { dispose(value) }
            return
        }
        attempt.timeoutCancellation?.cancel()
        guard remaining() > 0, !publication.revoked, permitted() else {
            attempt.cancellation?.cancel()
            if case .success(let value) = result { dispose(value) }
            finish(.failure(Self.failure("地址连接已取消、过期或配置已更新"))); return
        }
        let effectiveResult: Result<Connection, Error>
        if attempt.expired || clock() >= attempt.deadline {
            if case .success(let value) = result { dispose(value) }
            effectiveResult = .failure(Self.failure("候选 IP 连接预算已到；尝试后续地址"))
        } else { effectiveResult = result }
        switch effectiveResult {
        case .success: finish(effectiveResult)
        case .failure(let error):
            attempt.cancellation?.cancel(); lastError = error
            staggerCancellation?.cancel(); staggerCancellation = nil
            launch()
            if let addresses, next == addresses.count, attempts.isEmpty { finish(.failure(error)) }
            else { scheduleNext() }
        }
    }

    private func finish(_ result: Result<Connection, Error>) {
        guard !finished else { return }
        finished = true
        deadlineCancellation?.cancel(); deadlineCancellation = nil
        staggerCancellation?.cancel(); staggerCancellation = nil
        let losers = attempts.values.compactMap(\.cancellation)
        attempts.values.compactMap(\.timeoutCancellation).forEach { $0.cancel() }
        attempts.removeAll(); losers.forEach { $0.cancel() }
        let done = completion; completion = nil
        let publication = self.publication, permitted = self.permitted
        let deadline = self.deadline, clock = self.clock, dispose = self.dispose
        callbackQueue.async {
            switch result {
            case .success(let value):
                if publication.publish(allowed: clock() < deadline && permitted()) { done?(result) }
                else {
                    dispose(value)
                    done?(.failure(Self.failure("已拒绝发布过期或已取消的地址连接")))
                }
            case .failure:
                _ = publication.publish(allowed: true)
                done?(result)
            }
        }
        keepAlive = nil
    }

    /// Alternates address families while retaining the resolver's preferred
    /// first family. Rejects the whole vector if it contains a hostname.
    private static func orderedLiterals(_ values: [String]) -> [String]? {
        guard !values.isEmpty, values.count <= 16 else { return nil }
        var v4: [String] = [], v6: [String] = [], seen = Set<String>()
        var firstV6 = false
        for value in values {
            guard value.utf8.count <= 47 else { return nil }
            let value = DoHEndpoint.unbracketed(value)
            var address4 = in_addr(), address6 = in6_addr()
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let canonical: String
            let ipv6: Bool
            if inet_pton(AF_INET, value, &address4) == 1 {
                guard inet_ntop(AF_INET, &address4, &buffer, socklen_t(buffer.count)) != nil else { return nil }
                canonical = String(cString: buffer); ipv6 = false
            } else if inet_pton(AF_INET6, value, &address6) == 1 {
                guard inet_ntop(AF_INET6, &address6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
                canonical = String(cString: buffer); ipv6 = true
            } else { return nil }
            guard seen.insert(canonical).inserted else { continue }
            if seen.count == 1 { firstV6 = ipv6 }
            if ipv6 { v6.append(canonical) } else { v4.append(canonical) }
        }
        var result: [String] = []
        for index in 0..<max(v4.count, v6.count) {
            if firstV6 {
                if index < v6.count { result.append(v6[index]) }
                if index < v4.count { result.append(v4[index]) }
            } else {
                if index < v4.count { result.append(v4[index]) }
                if index < v6.count { result.append(v6[index]) }
            }
        }
        return result
    }

    private static func failure(_ text: String) -> Error { LiteralAddressAttemptFailure(text: text) }
    fileprivate func drainForSelfTest() { queue.sync {} }
}

public enum LiteralAddressAttemptCoordinatorSelfTest {
    private final class Stream {
        private let lock = NSLock()
        private var closes = 0
        func cancel() { lock.lock(); closes += 1; lock.unlock() }
        var cancellations: Int { lock.lock(); defer { lock.unlock() }; return closes }
    }
    private final class Clock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ delta: TimeInterval) { lock.lock(); value += delta; lock.unlock() }
    }
    private final class Timers {
        private let lock = NSLock()
        private let clock: Clock
        private var events: [UUID: (TimeInterval, () -> Void)] = [:]
        init(_ clock: Clock) { self.clock = clock }
        func schedule(_ delay: TimeInterval, _ work: @escaping () -> Void) -> () -> Void {
            let id = UUID()
            lock.lock(); events[id] = (clock.now() + delay, work); lock.unlock()
            return { [weak self] in
                guard let self else { return }
                self.lock.lock(); self.events.removeValue(forKey: id); self.lock.unlock()
            }
        }
        func advance(_ delta: TimeInterval) {
            clock.advance(delta)
            lock.lock()
            let due = events.filter { $0.value.0 <= clock.now() }
            due.keys.forEach { events.removeValue(forKey: $0) }
            lock.unlock()
            due.values.forEach { $0.1() }
        }
    }
    private final class Probe {
        struct Request {
            let address: String
            let timeout: TimeInterval
            let completion: (Result<Stream, Error>) -> Void
            var cancellations = 0
        }
        private let lock = NSLock()
        private var requests: [Request] = []
        private var acknowledgeCancellation = false
        func acknowledgeOnCancel() { lock.lock(); acknowledgeCancellation = true; lock.unlock() }
        func dial(_ address: String, _ timeout: TimeInterval,
                  _ completion: @escaping (Result<Stream, Error>) -> Void) -> () -> Void {
            lock.lock(); let index = requests.count
            requests.append(Request(address: address, timeout: timeout, completion: completion)); lock.unlock()
            return { [self] in
                lock.lock(); requests[index].cancellations += 1
                let acknowledge = acknowledgeCancellation, done = requests[index].completion
                lock.unlock()
                if acknowledge { done(.failure(LiteralAddressAttemptFailure(text: "acknowledged cancelled fixture"))) }
            }
        }
        var snapshot: [Request] { lock.lock(); defer { lock.unlock() }; return requests }
        func succeed(_ index: Int, _ stream: Stream) { snapshot[index].completion(.success(stream)) }
        func fail(_ index: Int) { snapshot[index].completion(.failure(LiteralAddressAttemptFailure(text: "fixture"))) }
    }
    private final class ResultBox {
        private let lock = NSLock()
        private var values: [Result<Stream, Error>] = []
        func append(_ value: Result<Stream, Error>) { lock.lock(); values.append(value); lock.unlock() }
        var snapshot: [Result<Stream, Error>] { lock.lock(); defer { lock.unlock() }; return values }
    }

    public static func run() throws {
        func expect(_ value: Bool, _ text: String) throws {
            guard value else { throw LiteralAddressAttemptFailure(text: "地址竞速自检失败：\(text)") }
        }
        let callbacks = DispatchQueue(label: "app.hajimi.address-attempts.selftest.callbacks")
        func drain(_ owner: LiteralAddressAttemptCoordinator<Stream>) {
            for _ in 0..<4 { owner.drainForSelfTest(); callbacks.sync {} }
        }
        func start(_ addresses: [String], _ clock: Clock, _ timers: Timers, _ probe: Probe,
                   _ box: ResultBox, _ budget: LiteralAddressAttemptBudget,
                   permitted: @escaping () -> Bool = { true }, maximumConcurrent: Int = 2)
            -> LiteralAddressAttemptCoordinator<Stream> {
            LiteralAddressAttemptCoordinator.start(addresses: addresses, deadline: clock.now() + 2,
                queue: callbacks, maximumConcurrent: maximumConcurrent, permitted: permitted,
                clock: clock.now, schedule: timers.schedule, budget: budget, dial: probe.dial,
                dispose: { $0.cancel() }, completion: box.append)
        }

        do {
            let clock = Clock(), timers = Timers(clock), probe = Probe(), box = ResultBox()
            let budget = LiteralAddressAttemptBudget(limit: 4)
            let owner = start(["203.0.113.1", "203.0.113.2", "2001:db8::1"], clock, timers, probe, box, budget)
            drain(owner)
            try expect(probe.snapshot.count == 1 && budget.usage == 1, "cold start must launch one physical attempt")
            timers.advance(0.2); drain(owner)
            try expect(probe.snapshot.count == 2 && probe.snapshot[1].address == "2001:db8::1",
                       "stagger must alternate families with only two concurrent attempts")
            try expect(abs(probe.snapshot[1].timeout - 0.9) < 0.0001, "retry did not divide the original deadline across remaining waves")
            let winner = Stream(); probe.succeed(1, winner); drain(owner)
            try expect(box.snapshot.count == 1 && (try? box.snapshot[0].get()) === winner,
                       "winner was not published exactly once")
            try expect(probe.snapshot[0].cancellations == 1 && probe.snapshot[1].cancellations == 0,
                       "loser cancellation touched the winner owner")
            try expect(budget.usage == 1, "cancelled physical attempt returned its slot before callback")
            let late = Stream(); probe.succeed(0, late); drain(owner)
            probe.succeed(1, winner); owner.cancel(); drain(owner)
            try expect(late.cancellations == 1 && winner.cancellations == 0 && budget.usage == 0,
                       "late loser leaked or duplicate/completed cancellation closed the winner")
        }
        do {
            let clock = Clock(), timers = Timers(clock), probe = Probe(), box = ResultBox()
            probe.acknowledgeOnCancel()
            let budget = LiteralAddressAttemptBudget(limit: 2)
            let owner = start(["203.0.113.30", "203.0.113.31", "203.0.113.32"], clock, timers, probe, box, budget)
            drain(owner); timers.advance(0.2); drain(owner)
            try expect(probe.snapshot.count == 2 && budget.usage == 2, "blackhole fixture did not occupy both physical lanes")
            timers.advance(0.8); drain(owner)
            try expect(probe.snapshot.count == 3 && probe.snapshot[0].cancellations == 1
                       && budget.usage == 2 && clock.now() < 102,
                       "first two held addresses starved the healthy third candidate")
            let winner = Stream(); probe.succeed(2, winner); drain(owner)
            try expect(box.snapshot.count == 1 && (try? box.snapshot[0].get()) === winner
                       && winner.cancellations == 0 && budget.usage == 0,
                       "healthy third address did not win within the original deadline")
        }
        do {
            let clock = Clock(), timers = Timers(clock), probe = Probe(), box = ResultBox()
            let owner = start(["203.0.113.3", "203.0.113.4"], clock, timers, probe, box,
                              LiteralAddressAttemptBudget(limit: 2), maximumConcurrent: 1)
            drain(owner); probe.fail(0); drain(owner)
            try expect(probe.snapshot.count == 2 && probe.snapshot[1].timeout == 2,
                       "sequential failure did not advance immediately within the same deadline")
            probe.fail(1); drain(owner)
            try expect(box.snapshot.count == 1 && (try? box.snapshot[0].get()) == nil,
                       "all-address failure did not finish exactly once")
        }
        do {
            let clock = Clock(), timers = Timers(clock), probe = Probe(), box = ResultBox()
            let budget = LiteralAddressAttemptBudget(limit: 2)
            let owner = start(["203.0.113.5", "::1"], clock, timers, probe, box, budget)
            drain(owner); timers.advance(0.2); drain(owner); timers.advance(1.8); drain(owner)
            try expect(box.snapshot.count == 1 && (try? box.snapshot[0].get()) == nil
                       && probe.snapshot.allSatisfy { $0.cancellations == 1 } && budget.usage == 2,
                       "deadline did not revoke attempts while retaining physical slots")
            let first = Stream(), second = Stream()
            probe.succeed(0, first); probe.succeed(1, second); drain(owner)
            try expect(first.cancellations == 1 && second.cancellations == 1 && budget.usage == 0,
                       "expired late results escaped closure or leaked slots")
        }
        do {
            let clock = Clock(), timers = Timers(clock), probe = Probe(), box = ResultBox()
            let gate = NSLock(); var current = true
            let owner = start(["203.0.113.6"], clock, timers, probe, box,
                              LiteralAddressAttemptBudget(limit: 1), permitted: {
                gate.lock(); defer { gate.unlock() }; return current
            })
            drain(owner); gate.lock(); current = false; gate.unlock()
            let stale = Stream(); probe.succeed(0, stale); drain(owner)
            try expect(stale.cancellations == 1 && box.snapshot.count == 1
                       && (try? box.snapshot[0].get()) == nil, "generation/interface change published a stale stream")
        }
        do {
            let budget = LiteralAddressAttemptBudget(limit: 3)
            var held: [(LiteralAddressAttemptCoordinator<Stream>, Probe)] = []
            for index in 0..<3 {
                let clock = Clock(), timers = Timers(clock), probe = Probe(), box = ResultBox()
                let owner = start(["203.0.113.\(index + 10)"], clock, timers, probe, box, budget)
                drain(owner); owner.cancel(); drain(owner); held.append((owner, probe))
            }
            try expect(budget.usage == 3, "cancel freed unacknowledged physical dial capacity")
            let clock = Clock(), timers = Timers(clock), denied = Probe(), deniedBox = ResultBox()
            let deniedOwner = start(["203.0.113.20"], clock, timers, denied, deniedBox, budget)
            drain(deniedOwner)
            let typedAdmission: Bool
            if case .failure(let error)? = deniedBox.snapshot.first { typedAdmission = error is NodeConnectionAdmissionError }
            else { typedAdmission = false }
            try expect(denied.snapshot.isEmpty && deniedBox.snapshot.count == 1,
                       "physical admission cap was bypassed by cancelled requests")
            try expect(typedAdmission, "physical resource rejection lost its typed deferred/admission error")
            for (owner, probe) in held { probe.fail(0); drain(owner) }
            let recovered = Probe(), recoveredBox = ResultBox()
            let recoveredOwner = start(["203.0.113.21"], clock, timers, recovered, recoveredBox, budget)
            drain(recoveredOwner)
            try expect(budget.usage == 1 && recovered.snapshot.count == 1, "late callbacks did not recover capacity")
            recovered.fail(0); drain(recoveredOwner)
        }
        for addresses in [["public.example"], ["203.0.113.1", "bad host"], Array(repeating: "::1", count: 17)] {
            let clock = Clock(), timers = Timers(clock), probe = Probe(), box = ResultBox()
            let owner = start(addresses, clock, timers, probe, box, LiteralAddressAttemptBudget(limit: 2))
            drain(owner)
            try expect(probe.snapshot.isEmpty && box.snapshot.count == 1,
                       "invalid/oversized candidates reached a physical dialer")
        }
    }
}

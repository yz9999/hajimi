// Appended to verbatim production declarations by test_dns_progress_rotation.py.
// These adapters cancel real dispatch timers and invoke their production
// callbacks on the owning queue after an injected monotonic clock advances.
// Every transport below is an in-memory peer; there are no sockets or TLS.

private extension DNSAdaptiveQueryDatagram {
    func auditPauseTimersOnQueue() {
        deadlineTimer?.cancel()
        for attempt in active.values {
            attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel()
        }
    }
    func auditDrain() { queue.sync { auditPauseTimersOnQueue() } }
    func auditStartHedge() {
        queue.sync {
            guard let primaryToken else { return }
            startHedge(after: primaryToken); auditPauseTimersOnQueue()
        }
    }
    func auditFireRotation() {
        queue.sync {
            if let token = active.keys.first(where: { $0 != primaryToken }) { rotateHedge(token) }
            auditPauseTimersOnQueue()
        }
    }
    func auditFireDeadline() {
        queue.sync { overallDeadlineReached(); auditPauseTimersOnQueue() }
        auditDrain()
    }
    var auditState: (attempts: Int, active: Int, deadline: TimeInterval, started: TimeInterval) {
        queue.sync { (attemptCount, active.count, deadline, exchangeStarted) }
    }
    func auditHoldOwner(entered: DispatchSemaphore, release: DispatchSemaphore) {
        queue.async {
            entered.signal()
            _ = release.wait(timeout: .now() + 3)
        }
    }
}

private extension DNSAdaptiveUpstreamSelector {
    func auditHealth(scope: String, candidate: String) -> (successes: Int, failures: Int) {
        lock.lock(); defer { lock.unlock() }
        let value = scopes[scope]?.health[candidate]
        return (value?.successes ?? 0, value?.failures ?? 0)
    }
}

@main
private enum DNSProgressRotationMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private final class Clock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        private let system: Bool
        init(system: Bool = false) { self.system = system }
        func now() -> TimeInterval {
            if system { return ProcessInfo.processInfo.systemUptime }
            lock.lock(); defer { lock.unlock() }; return value
        }
        func advance(to elapsed: TimeInterval) {
            precondition(!system)
            lock.lock(); value = 100 + elapsed; lock.unlock()
        }
    }
    private final class Permission {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }
    private final class Probe {
        private let lock = NSLock()
        private var peers: [Int: MemoryTransport] = [:]
        private var answerValues: [Data] = [], errorValues: [Error] = []
        private var forwardedReceive: ((Data) -> Void)?, forwardedFailure: ((Error) -> Void)?
        func add(_ peer: MemoryTransport, index: Int) { lock.lock(); peers[index] = peer; lock.unlock() }
        func peer(_ index: Int) -> MemoryTransport? { lock.lock(); defer { lock.unlock() }; return peers[index] }
        func receive(_ value: Data) {
            lock.lock(); answerValues.append(value); let forwarded = forwardedReceive; lock.unlock(); forwarded?(value)
        }
        func failure(_ value: Error) {
            lock.lock(); errorValues.append(value); let forwarded = forwardedFailure; lock.unlock(); forwarded?(value)
        }
        func forward(receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            lock.lock(); forwardedReceive = receive; forwardedFailure = failure; lock.unlock()
        }
        var snapshot: (answers: [Data], errors: [Error]) {
            lock.lock(); defer { lock.unlock() }; return (answerValues, errorValues)
        }
    }
    private final class MemoryTransport: NativeRoutedDatagram, DNSQueryCancellationAcknowledging,
        DNSQueryExecutionContextAccepting, DNSQueryTransportEvidenceProviding {
        private let clock: Clock, receive: (Data) -> Void, failure: (Error) -> Void
        private let lock = NSLock()
        private var context: DNSQueryExecutionContext?
        private var query: Data?
        private var closed = false
        private var beganTransport = false
        private var reasons: [DNSAttemptCancellationReason] = []
        private let evidence: DNSQueryTransportEvidence
        private let startsTransportImmediately: Bool
        private let onSend: ((Data) -> Void)?, onCancel: (() -> Void)?
        init(clock: Clock, evidence: DNSQueryTransportEvidence,
             startsTransportImmediately: Bool = true,
             onSend: ((Data) -> Void)? = nil, onCancel: (() -> Void)? = nil,
             receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            self.clock = clock; self.evidence = evidence; self.receive = receive; self.failure = failure
            self.startsTransportImmediately = startsTransportImmediately
            self.onSend = onSend; self.onCancel = onCancel
        }
        func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
            lock.lock(); self.context = context; lock.unlock()
        }
        func send(_ data: Data) {
            lock.lock(); query = data
            if startsTransportImmediately { beganTransport = true }
            let context = self.context; lock.unlock()
            if startsTransportImmediately { context?.record(.transportStarted, at: clock.now()) }
            onSend?(data)
        }
        func emit(_ event: DNSConnectionAttemptEvent, elapsed: TimeInterval) {
            lock.lock()
            if event == .transportStarted { beganTransport = true }
            let context = self.context; lock.unlock()
            context?.record(event, at: 100 + elapsed)
        }
        func restartPhysicalTransport(elapsed: TimeInterval) {
            lock.lock(); let context = self.context; beganTransport = true; lock.unlock()
            let id = UUID(); context?.beginConnectionAttempt(id)
            context?.record(.transportStarted, attemptID: id, at: 100 + elapsed)
        }
        var hasContext: Bool { lock.lock(); defer { lock.unlock() }; return context != nil }
        var cancellationReasons: [DNSAttemptCancellationReason] {
            lock.lock(); defer { lock.unlock() }; return reasons
        }
        func answer(code: UInt8 = 0, forceLate: Bool = false) {
            lock.lock(); let data = query, stopped = closed, context = self.context; lock.unlock()
            guard forceLate || !stopped, var data else { return }
            data[2] = 0x81; data[3] = 0x80 | code
            context?.record(.responseStarted, at: clock.now())
            context?.record(.responseComplete, at: clock.now())
            receive(data)
        }
        func fail(_ error: Error) { failure(error) }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence {
            lock.lock(); defer { lock.unlock() }; return beganTransport ? evidence : .notStarted
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) { cancel(reason: .callerCancelled, completion: completion) }
        func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
            lock.lock()
            let first = !closed
            if first { reasons.append(reason) }
            closed = true; let context = self.context; lock.unlock()
            context?.record(.requestFinished, at: clock.now())
            if first { onCancel?() }
            completion()
        }
    }
    private final class RealTimerProbe {
        let lock = NSLock(), done = DispatchSemaphore(value: 0)
        var starts: [Int: TimeInterval] = [:], stops: [Int: Int] = [:]
        var live = Set<Int>(), peak = 0
        var answers: [Data] = [], errors: [Error] = [], completedAt: TimeInterval?
        func sent(_ index: Int) {
            lock.lock(); starts[index] = ProcessInfo.processInfo.systemUptime
            live.insert(index); peak = max(peak, live.count); lock.unlock()
        }
        func stopped(_ index: Int) {
            lock.lock(); stops[index, default: 0] += 1; live.remove(index); lock.unlock()
        }
        func received(_ answer: Data) {
            lock.lock(); answers.append(answer); completedAt = ProcessInfo.processInfo.systemUptime; lock.unlock()
            done.signal()
        }
        func failed(_ error: Error) {
            lock.lock(); errors.append(error); completedAt = ProcessInfo.processInfo.systemUptime; lock.unlock()
            done.signal()
        }
    }
    /// Matches the existing opaque memory fixtures: there is no observed TCP
    /// or TLS phase to protect. The wrapper only hides the progress protocol;
    /// all timers, clock reads and cancellation receipts remain real.
    private final class OpaqueTimerTransport: NativeRoutedDatagram, DNSQueryCancellationAcknowledging {
        let memory: MemoryTransport
        init(_ memory: MemoryTransport) { self.memory = memory }
        func send(_ data: Data) { memory.send(data) }
        func cancel() { memory.cancel() }
        func cancel(completion: @escaping () -> Void) { memory.cancel(completion: completion) }
        func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
            memory.cancel(reason: reason, completion: completion)
        }
    }
    private final class DeadlineFenceProbe {
        private let lock = NSLock()
        private var values: [DNSProxyFallbackBarrier?] = []
        let completed = DispatchSemaphore(value: 0)
        func record(_ value: DNSProxyFallbackBarrier?) {
            lock.lock(); values.append(value); lock.unlock(); completed.signal()
        }
        var snapshots: [DNSProxyFallbackBarrier?] {
            lock.lock(); defer { lock.unlock() }; return values
        }
    }
    /// A logical cancellation receipt that can expose already-admitted native
    /// metadata only when explicitly released by the test. There are no FDs.
    private final class HeldFenceTransport: NativeRoutedDatagram, DNSQueryCancellationAcknowledging,
        DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding, DNSQueryExecutionContextAccepting {
        private let lock = NSLock()
        private let clock: Clock
        private var context: DNSQueryExecutionContext?
        private var barrier: DNSProxyFallbackBarrier?
        private var acknowledgements: [() -> Void] = []
        private var released = false
        let cancellationBegan = DispatchSemaphore(value: 0)
        init(clock: Clock) { self.clock = clock }
        func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
            lock.lock(); self.context = context; lock.unlock()
        }
        func send(_ data: Data) {
            lock.lock(); let context = self.context; lock.unlock()
            context?.record(.transportStarted, at: clock.now())
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock()
            if released { lock.unlock(); completion(); return }
            acknowledgements.append(completion)
            lock.unlock(); cancellationBegan.signal()
        }
        func acknowledge(_ value: DNSProxyFallbackBarrier?, duplicate: Bool = false) {
            lock.lock()
            guard !released else { lock.unlock(); return }
            barrier = value; released = true
            let callbacks = acknowledgements; acknowledgements.removeAll()
            lock.unlock()
            for callback in callbacks { callback(); if duplicate { callback() } }
        }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
            lock.lock(); defer { lock.unlock() }; return barrier
        }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { .fresh }
    }
    private final class UnfencedTransport: NativeRoutedDatagram {
        private(set) var cancellationCount = 0
        func send(_ data: Data) {}
        func cancel() { cancellationCount += 1 }
    }
    /// Bridging this otherwise opaque error is observable and can block. The
    /// admission callback must retain it before performing any such bridge.
    private final class BridgeSensitiveError: CustomNSError {
        private let lock = NSLock()
        private var calls = 0
        private let release = DispatchSemaphore(value: 0)
        static var errorDomain: String { "fixture.opaque-error" }
        var errorCode: Int { 5317 }
        var errorUserInfo: [String: Any] {
            lock.lock(); calls += 1; lock.unlock()
            _ = release.wait(timeout: .now() + 2)
            return [:]
        }
        var bridgeCount: Int { lock.lock(); defer { lock.unlock() }; return calls }
        func releaseBridge() { release.signal() }
    }
    private final class Fixture {
        let clock: Clock, permission: Permission, selector: DNSAdaptiveUpstreamSelector, probe: Probe
        let flow: DNSAdaptiveQueryDatagram, candidates: [DNSUpstreamCandidate]
        let scope = "memory-progress-rotation"
        let query: Data
        init(coldMilliseconds: [Double?] = [nil, nil, nil], hotLast: Bool = false,
             pendingThirdMilliseconds: Double? = nil,
             phaseHistory: DNSQueryProgressSnapshot? = nil,
             evidence: DNSQueryTransportEvidence = .fresh, candidateCount: Int = 3,
             autoSend: Bool = true, startsTransportImmediately: Bool = true) throws {
            let clock = Clock(), permission = Permission(), probe = Probe()
            let selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let scope = "memory-progress-rotation"
            let candidates = (0..<candidateCount).map { index in
                DNSUpstreamCandidate(upstream: .doh(DoHEndpoint(
                    "https://candidate-\(index).fixture.invalid/dns-query#203.0.113.\(70 + index)")!), bootstrap: nil)
            }
            let ids = candidates.map(\.id)
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            for (index, milliseconds) in coldMilliseconds.enumerated() {
                if let milliseconds {
                    selector.record(selector.beginObservation(scopeKey: scope, candidateID: ids[index]),
                        milliseconds: milliseconds, success: true, transport: .fresh, progress: phaseHistory)
                }
            }
            if hotLast {
                for _ in 0..<64 {
                    selector.record(selector.beginObservation(scopeKey: scope, candidateID: ids.last!),
                        milliseconds: 1, success: true, transport: .reused)
                }
            }
            if let pendingThirdMilliseconds {
                selector.recordPendingLatencyLowerBound(scopeKey: scope, candidateID: ids[2],
                    milliseconds: pendingThirdMilliseconds)
            }
            try require(selector.orderedCandidates(scopeKey: scope, candidateIDs: ids) == ids,
                        "Synthetic history changed approved candidate order")
            guard let query = DNSMessageInspection.query(for: "progress.fixture.invalid", type: 1, id: 0x5316) else {
                throw Failure(text: "Cannot create memory question")
            }
            self.clock = clock; self.permission = permission; self.selector = selector
            self.probe = probe; self.candidates = candidates; self.query = query
            flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector, scopeKey: scope,
                queue: DispatchQueue(label: "audit.dns-progress"), permitted: permission.permits,
                factory: { candidate, _, receive, failure in
                    let peer = MemoryTransport(clock: clock, evidence: evidence,
                        startsTransportImmediately: startsTransportImmediately, receive: receive, failure: failure)
                    probe.add(peer, index: ids.firstIndex(of: candidate.id)!); return peer
                }, receive: probe.receive, failure: probe.failure,
                timeout: 8, absoluteDeadline: 108, clock: clock.now)
            if autoSend {
                flow.send(query); flow.auditDrain()
                try require(flow.auditState.attempts == 1 && peer(0).hasContext,
                            "Initial physical attempt did not receive its execution context")
            }
        }
        deinit { flow.cancel() }
        func peer(_ index: Int) -> MemoryTransport {
            guard let value = probe.peer(index) else { preconditionFailure("Missing memory peer \(index)") }
            return value
        }
        func hedge(at elapsed: TimeInterval = 0.75) {
            clock.advance(to: elapsed); flow.auditStartHedge()
        }
        func rotate(at elapsed: TimeInterval) {
            clock.advance(to: elapsed); flow.auditFireRotation()
        }
        func answer(_ index: Int, at elapsed: TimeInterval, code: UInt8 = 0, forceLate: Bool = false) {
            clock.advance(to: elapsed); peer(index).answer(code: code, forceLate: forceLate); flow.auditDrain()
        }
        func fail(_ index: Int, at elapsed: TimeInterval) {
            clock.advance(to: elapsed)
            peer(index).fail(NWError.posix(.ECONNRESET)); flow.auditDrain()
        }
        func deadline() { clock.advance(to: 8); flow.auditFireDeadline() }
        func cancel() throws {
            let done = DispatchSemaphore(value: 0); flow.cancel { done.signal() }
            try require(done.wait(timeout: .now() + 1) == .success, "Memory cancellation ACK did not drain")
            flow.auditDrain()
        }
        func failures(_ index: Int) -> Int {
            selector.auditHealth(scope: scope, candidate: candidates[index].id).failures
        }
        func requireSuccess(_ text: String) throws {
            let result = probe.snapshot
            try require(result.answers.count == 1 && result.errors.isEmpty
                        && DNSMessageInspection.responseMatchesQuery(result.answers[0], query: query)
                        && flow.auditState.active == 0 && flow.auditState.deadline == 108, text)
        }
    }

    private final class Timers {
        private final class Item {
            let deadline: TimeInterval, queue: DispatchQueue, work: () -> Void
            var cancelled = false
            init(deadline: TimeInterval, queue: DispatchQueue, work: @escaping () -> Void) {
                self.deadline = deadline; self.queue = queue; self.work = work
            }
        }
        private let clock: Clock, lock = NSLock()
        private var items: [Item] = []
        init(clock: Clock) { self.clock = clock }
        var schedule: DNSProxyFallbackQueryDatagram.Schedule {
            { [self] queue, delay, work in
                let item = Item(deadline: clock.now() + delay, queue: queue, work: work)
                lock.lock(); items.append(item); lock.unlock()
                return { [self] in lock.lock(); item.cancelled = true; lock.unlock() }
            }
        }
        func fireDue() {
            let now = clock.now()
            lock.lock()
            let due = items.filter { !$0.cancelled && $0.deadline <= now }
            for item in due { item.cancelled = true }
            lock.unlock()
            for item in due { item.queue.async(execute: item.work) }
        }
        var nextDeadline: TimeInterval? {
            lock.lock(); defer { lock.unlock() }
            return items.filter { !$0.cancelled }.map(\.deadline).min()
        }
    }
    private final class ParentFixture {
        let child: Fixture, timers: Timers, probe: Probe
        let parent: DNSProxyFallbackQueryDatagram
        init(coldMilliseconds: [Double?] = [nil, nil], hotLast: Bool = false) throws {
            let child = try Fixture(coldMilliseconds: coldMilliseconds, hotLast: hotLast,
                                    candidateCount: 2, autoSend: false)
            let timers = Timers(clock: child.clock), probe = Probe()
            self.child = child; self.timers = timers; self.probe = probe
            parent = DNSProxyFallbackQueryDatagram(queue: DispatchQueue(label: "audit.dns-progress-parent"),
                absoluteDeadline: 108, permitted: child.permission.permits,
                knownMilliseconds: {
                    child.candidates.compactMap {
                        child.selector.planningLatencyMilliseconds(scopeKey: child.scope, candidateID: $0.id)
                    }
                }, encrypted: { _, absolute, receive, failure in
                    try require(absolute == 108, "Parent changed the child's original absolute deadline")
                    child.probe.forward(receive: receive, failure: failure); return child.flow
                }, fallback: { _, absolute, receive, failure in
                    try require(absolute == 108, "Fallback restarted the original absolute deadline")
                    let fallback = MemoryTransport(clock: child.clock, evidence: .fresh,
                                                   receive: receive, failure: failure)
                    probe.add(fallback, index: 99); return fallback
                }, receive: probe.receive, failure: probe.failure, clock: child.clock.now,
                schedule: timers.schedule, diagnostics: NetworkPerformanceDiagnostics())
            parent.send(child.query); drain()
            try require(child.flow.auditState.attempts == 1 && child.peer(0).hasContext,
                        "Parent did not admit its encrypted child with context")
        }
        deinit { parent.cancel() }
        func drain() {
            // Parent checkpoint -> child owning queue -> parent decision ->
            // child cancellation ACK -> parent phase transition.
            for _ in 0..<4 { parent.drainQueueForSelfTest(); child.flow.auditDrain() }
            parent.drainQueueForSelfTest()
        }
        func checkpoint(at elapsed: TimeInterval) {
            child.clock.advance(to: elapsed); timers.fireDue(); drain()
        }
    }

    private static func require(_ value: Bool, _ message: String) throws {
        if !value { throw Failure(text: message) }
    }
    private static func check(_ name: String, _ body: () throws -> Void) throws {
        try body(); print("PASS: \(name)"); fflush(stdout)
    }

    private static func heterogeneousProviderFixture(thirdCold: Double? = nil,
                                                      backupCold: Double? = nil) throws -> Fixture {
        // A different query supplies successful first-provider history after
        // this query has already admitted its configured primary and backup.
        // Both of this query's live providers remain blackholed; the unknown
        // third provider must still get its independent bounded rescue turn.
        let fixture = try Fixture()
        fixture.hedge(at: 0.75)
        fixture.clock.advance(to: 3.6)
        let phases = DNSQueryProgressSnapshot(stage: .completed, changedAt: 103.6,
            transportStartedAt: 100, transportReadyAt: 100.6,
            tlsStartedAt: 100.6, tlsReadyAt: 103.1,
            querySentAt: 103.1, responseStartedAt: 103.5, responseCompletedAt: 103.6)
        fixture.selector.record(fixture.selector.beginObservation(scopeKey: fixture.scope,
            candidateID: fixture.candidates[0].id), milliseconds: 3600,
            success: true, transport: .fresh, progress: phases)
        for (index, value) in [(1, backupCold), (2, thirdCold)] {
            if let value {
                fixture.selector.record(fixture.selector.beginObservation(scopeKey: fixture.scope,
                    candidateID: fixture.candidates[index].id), milliseconds: value,
                    success: true, transport: .fresh)
            }
        }
        try require(fixture.flow.auditState.attempts == 2 && fixture.probe.peer(2) == nil,
                    "Concurrent history changed the already-admitted candidate order")
        return fixture
    }

    private static func deadlineFenceFlow(clock: Clock, transport: NativeRoutedDatagram,
        probe: Probe, protectProxyFallback: Bool = false, factoryFinishesAt: TimeInterval? = nil)
        -> (flow: DNSAdaptiveQueryDatagram, selector: DNSAdaptiveUpstreamSelector,
                         candidate: DNSUpstreamCandidate, query: Data) {
        let candidate = DNSUpstreamCandidate(upstream: .doh(DoHEndpoint(
            "https://fence.fixture.invalid/dns-query#203.0.113.90")!), bootstrap: nil)
        let selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
        let query = DNSMessageInspection.query(for: "fence.fixture.invalid", type: 1, id: 0x5317)!
        let flow = DNSAdaptiveQueryDatagram(candidates: [candidate], selector: selector,
            scopeKey: "deadline-fence", queue: DispatchQueue(label: "audit.deadline-fence"),
            permitted: { true }, factory: { _, _, _, _ in
                if let factoryFinishesAt { clock.advance(to: factoryFinishesAt) }
                return transport
            },
            receive: probe.receive, failure: probe.failure, timeout: 8,
            absoluteDeadline: 108, clock: clock.now, protectProxyFallback: protectProxyFallback)
        flow.send(query); flow.auditDrain()
        return (flow, selector, candidate, query)
    }

    private static func requireFollowingQueryCanRotate(_ fixture: Fixture) throws {
        // Make the just-measured candidate the backup. This detects both a
        // polluted third-candidate budget and a polluted backup RTT allowance.
        fixture.selector.record(fixture.selector.beginObservation(scopeKey: fixture.scope,
            candidateID: fixture.candidates[1].id), milliseconds: 100, success: true, transport: .fresh)
        let ids = fixture.candidates.map(\.id)
        try require(fixture.selector.orderedCandidates(scopeKey: fixture.scope, candidateIDs: ids)
                    == [ids[1], ids[0], ids[2]], "Follow-up control did not put the measured cold path in its backup slot")
        let started = fixture.clock.now(), probe = Probe()
        let flow = DNSAdaptiveQueryDatagram(candidates: fixture.candidates, selector: fixture.selector,
            scopeKey: fixture.scope, queue: DispatchQueue(label: "audit.dns-following-cold-success"),
            permitted: fixture.permission.permits, factory: { candidate, _, receive, failure in
                let peer = MemoryTransport(clock: fixture.clock, evidence: .fresh, receive: receive, failure: failure)
                probe.add(peer, index: ids.firstIndex(of: candidate.id)!); return peer
            }, receive: probe.receive, failure: probe.failure, timeout: 8,
            absoluteDeadline: started + 8, clock: fixture.clock.now)
        defer { flow.cancel() }
        flow.send(fixture.query); flow.auditDrain()
        fixture.clock.advance(to: started - 100 + 0.75); flow.auditStartHedge()
        fixture.clock.advance(to: started - 100 + 5.334); flow.auditFireRotation()
        try require(flow.auditState.attempts == 3 && flow.auditState.active == 2
                    && probe.peer(0)?.cancellationReasons == [.hedgeRotation]
                    && probe.peer(1)?.cancellationReasons.isEmpty == true,
                    "A 7.7s logical idle/queue RTT prevented the next eight-second query from rotating its 0.5s cold backup")
        fixture.clock.advance(to: started - 100 + 5.6); probe.peer(2)?.answer(); flow.auditDrain()
        try require(probe.snapshot.answers.count == 1 && probe.snapshot.errors.isEmpty
                    && flow.auditState.active == 0 && flow.auditState.deadline == started + 8,
                    "Following query did not finish inside its own unchanged eight-second deadline")
    }

    private static func requireFollowingParentCanCheckpoint(_ fixture: Fixture) throws {
        fixture.selector.record(fixture.selector.beginObservation(scopeKey: fixture.scope,
            candidateID: fixture.candidates[1].id), milliseconds: 100, success: true, transport: .fresh)
        let candidates = [fixture.candidates[1], fixture.candidates[0]], ids = candidates.map(\.id)
        let started = fixture.clock.now(), probe = Probe(), timers = Timers(clock: fixture.clock)
        var child: DNSAdaptiveQueryDatagram?
        let parent = DNSProxyFallbackQueryDatagram(queue: DispatchQueue(label: "audit.following-parent"),
            absoluteDeadline: started + 8, permitted: fixture.permission.permits,
            knownMilliseconds: {
                candidates.compactMap {
                    fixture.selector.planningLatencyMilliseconds(scopeKey: fixture.scope, candidateID: $0.id)
                }
            }, encrypted: { queue, absolute, receive, failure in
                let flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: fixture.selector,
                    scopeKey: fixture.scope, queue: queue, permitted: fixture.permission.permits,
                    factory: { candidate, _, receive, failure in
                        let peer = MemoryTransport(clock: fixture.clock, evidence: .fresh, receive: receive, failure: failure)
                        probe.add(peer, index: ids.firstIndex(of: candidate.id)!); return peer
                    }, receive: receive, failure: failure, timeout: 8, absoluteDeadline: absolute,
                    clock: fixture.clock.now, protectProxyFallback: true)
                child = flow; return flow
            }, fallback: { _, absolute, receive, failure in
                try require(absolute == started + 8, "Following fallback restarted its absolute deadline")
                let peer = MemoryTransport(clock: fixture.clock, evidence: .fresh, receive: receive, failure: failure)
                probe.add(peer, index: 99); return peer
            }, receive: probe.receive, failure: probe.failure, clock: fixture.clock.now,
            schedule: timers.schedule, diagnostics: NetworkPerformanceDiagnostics())
        defer { parent.cancel() }
        func drain() {
            for _ in 0..<4 { parent.drainQueueForSelfTest(); child?.auditDrain() }
            parent.drainQueueForSelfTest()
        }
        parent.send(fixture.query); drain()
        guard let child else { throw Failure(text: "Following parent did not create its encrypted child") }
        fixture.clock.advance(to: started - 100 + 0.75); child.auditStartHedge()
        fixture.clock.advance(to: started - 100 + 3.1); timers.fireDue(); drain()
        try require(probe.peer(99) == nil && probe.snapshot.errors.isEmpty
                    && (timers.nextDeadline ?? 0) > started + 3.1
                    && (timers.nextDeadline ?? .infinity) < started + 4,
                    "Old 7.7s logical RTT erased the following two-candidate parent's useful phase checkpoint")
        fixture.clock.advance(to: started - 100 + 3.9); timers.fireDue(); drain()
        try require(probe.peer(99) != nil && probe.snapshot.errors.isEmpty
                    && probe.peer(1)?.cancellationReasons == [.encryptedPhaseDeadline],
                    "Following parent kept a blackholed 0.5s cold backup until its entire eight-second deadline")
        fixture.clock.advance(to: started - 100 + 8); timers.fireDue(); drain()
        try require(probe.snapshot.answers.isEmpty && probe.snapshot.errors.count == 1
                    && probe.snapshot.errors[0] is DNSQueryTimeoutError && timers.nextDeadline == nil
                    && child.auditState.deadline == started + 8,
                    "Following parent extended its total deadline after the cold-aware checkpoint")
    }

    private static func realTimerThirdRescue(timeout: TimeInterval) throws {
        let clock = Clock(system: true), probe = RealTimerProbe(), selector = DNSAdaptiveUpstreamSelector()
        let candidates = (0..<3).map { index in
            DNSUpstreamCandidate(upstream: .doh(DoHEndpoint(
                "https://real-timer-\(index).fixture.invalid/dns-query#203.0.113.\(70 + index)")!), bootstrap: nil)
        }
        let ids = candidates.map(\.id), absolute = clock.now() + timeout
        let query = DNSMessageInspection.query(for: "real-timer.fixture.invalid", type: 1, id: 0x5327)!
        let flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector,
            scopeKey: "real-timer-\(timeout)", queue: DispatchQueue(label: "audit.real-dns-timer", qos: .userInitiated),
            permitted: { true }, factory: { candidate, queue, receive, failure in
                let index = ids.firstIndex(of: candidate.id)!
                return OpaqueTimerTransport(MemoryTransport(clock: clock, evidence: .unknown, onSend: { data in
                    probe.sent(index)
                    guard index == 2 else { return }
                    queue.asyncAfter(deadline: .now() + 0.005) {
                        var answer = data; answer[2] = 0x81; answer[3] = 0x80; receive(answer)
                    }
                }, onCancel: { probe.stopped(index) }, receive: receive, failure: failure))
            }, receive: probe.received, failure: probe.failed, timeout: timeout,
            absoluteDeadline: absolute, clock: clock.now)
        defer { flow.cancel() }
        flow.send(query)
        try require(probe.done.wait(timeout: .now() + 2) == .success, "Real dispatch timer did not complete its query")
        let ack = DispatchSemaphore(value: 0); flow.cancel { ack.signal() }
        try require(ack.wait(timeout: .now() + 1) == .success, "Real-timer cleanup did not ACK")
        let state = flow.auditState
        probe.lock.lock()
        let starts = probe.starts, stops = probe.stops, answers = probe.answers, errors = probe.errors
        let completed = probe.completedAt, peak = probe.peak, active = probe.live.count
        probe.lock.unlock()
        let baseline = state.started + (state.deadline - state.started) * (2.0 / 3.0)
        guard let third = starts[2], let completed else {
            throw Failure(text: "Unknown third missed its \(Int(timeout * 1000))ms real-timer rescue: attempts=\(state.attempts), errors=\(errors.count)")
        }
        try require(answers.count == 1 && errors.isEmpty && DNSMessageInspection.responseMatchesQuery(answers[0], query: query)
                    && starts.count == 3 && state.attempts == 3 && peak == 2 && active == 0 && state.active == 0
                    && stops.count == 3 && stops.values.allSatisfy({ $0 == 1 })
                    && third >= baseline && completed < state.deadline && state.deadline == absolute,
                    "Real timer violated the conservative boundary, two-live/three-attempt limit or original deadline")
        print("Real dispatch third rescue: parent=\(Int(timeout * 1000))ms, third=\(Int((third - state.started) * 1000))ms, complete=\(Int((completed - state.started) * 1000))ms, peak=\(peak), attempts=\(state.attempts)")
    }

    private static func run() throws {
        try check("candidate-local progress is monotonic, correlated and terminal") {
            let parent = DNSQueryExecutionContext(), first = parent.child(), second = parent.child()
            try require(first.rootID == parent.rootID && second.rootID == parent.rootID
                        && first.candidateID != second.candidateID, "Execution context lost root/candidate identity")
            first.record(.transportStarted, at: 100)
            first.record(.tlsStarted, at: 101)
            first.record(.transportReady, at: 101.5)
            first.record(.tlsWaiting, at: 101.75)
            try require(first.progress().stage == .tlsHandshaking && first.progress().changedAt == 101
                        && second.progress().stage == .notStarted,
                        "Late/same-stage callbacks reset progress or crossed candidates")
            first.record(.tlsReady, at: 102); first.record(.querySent, at: 102.1)
            first.record(.responseStarted, at: 102.2); first.record(.requestFinished, at: 102.3)
            first.record(.responseComplete, at: 102.4)
            try require(first.progress().stage == .receivingResponse && first.progress().responseCompletedAt == nil,
                        "A late callback revived a finished execution context")
            let oldID = UUID(), currentID = UUID()
            first.beginConnectionAttempt(oldID)
            first.record(.tlsReady, attemptID: oldID, at: 103)
            first.beginConnectionAttempt(currentID)
            first.record(.transportStarted, attemptID: currentID, at: 104)
            first.record(.querySent, attemptID: oldID, at: 104.1)
            first.record(.requestFinished, attemptID: oldID, at: 104.2)
            first.record(.tlsStarted, attemptID: currentID, at: 104.3)
            try require(first.progress().stage == .tlsHandshaking && first.progress().tlsReadyAt == nil
                        && first.progress().querySentAt == nil && first.progress().changedAt == 104.3,
                        "Old physical-generation callbacks changed or terminated a new attempt")
        }
        try check("TLS began 48ms before the conservative timer: retain backup and accept its answer") {
            let fixture = try Fixture(); fixture.hedge()
            fixture.peer(1).emit(.transportReady, elapsed: 5.28)
            fixture.peer(1).emit(.tlsStarted, elapsed: 5.285)
            fixture.rotate(at: 5.3334)
            try require(fixture.flow.auditState.attempts == 2 && fixture.flow.auditState.active == 2
                        && fixture.peer(1).cancellationReasons.isEmpty,
                        "The rotation timer cancelled a TLS handshake after only 48ms")
            fixture.answer(1, at: 5.8); try fixture.requireSuccess("Progressing backup did not complete")
            try require((0..<3).allSatisfy { fixture.failures($0) == 0 }, "Successful race losers became failures")
        }
        try check("fresh cold cost prevents a 2.67s replacement window; hot reuse cannot erase it") {
            let fixture = try Fixture(coldMilliseconds: [1000, 2000, 3600], hotLast: true)
            try require((fixture.selector.knownLatencyMilliseconds(scopeKey: fixture.scope,
                        candidateID: fixture.candidates[2].id) ?? .infinity) < 10,
                        "Warm reuse control was not actually fast")
            fixture.hedge(); fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 2 && fixture.peer(1).cancellationReasons.isEmpty,
                        "A known 3.6s cold path replaced a live backup with only 2.67s left")
            fixture.answer(1, at: 6); try fixture.requireSuccess("Cold-cost protected backup did not finish")
        }
        try check("another provider's 3.6s history cannot exclude an unknown 1.2s third") {
            let fixture = try heterogeneousProviderFixture()
            let phases: [DNSAdaptiveLatencyPhase] = [.cold, .transport, .tls, .response]
            for index in [1, 2] {
                for phase in phases {
                    try require(fixture.selector.estimatedMilliseconds(scopeKey: fixture.scope,
                        candidateID: fixture.candidates[index].id, phase: phase) == nil,
                        "An unmeasured provider inherited another provider's phase cost")
                }
            }
            fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 3 && fixture.probe.peer(2) != nil
                        && fixture.peer(0).cancellationReasons.isEmpty
                        && fixture.peer(1).cancellationReasons == [.hedgeRotation],
                        "An unrelated 3.6s sample blocked the useful 2.67s third-candidate window")
            fixture.answer(2, at: 6.534)
            try fixture.requireSuccess("Unknown fast third was not accepted after 1.2s")
            try require((0..<3).allSatisfy { fixture.failures($0) == 0 },
                        "A successful heterogeneous-provider race fabricated provider failures")
        }
        try check("a third provider's own 3.6s history still rejects an insufficient window") {
            let fixture = try heterogeneousProviderFixture(thirdCold: 3600)
            try require(fixture.selector.estimatedMilliseconds(scopeKey: fixture.scope,
                candidateID: fixture.candidates[2].id, phase: .cold) == 3600,
                "The third provider lost its own measured cold cost")
            fixture.rotate(at: 5.334); fixture.rotate(at: 6.201)
            try require(fixture.flow.auditState.attempts == 2 && fixture.probe.peer(2) == nil
                        && fixture.peer(1).cancellationReasons.isEmpty,
                        "Candidate-only planning discarded the third provider's own slow measurement")
            fixture.deadline()
            let result = fixture.probe.snapshot
            try require(result.answers.isEmpty && result.errors.count == 1
                        && result.errors[0] is DNSQueryTimeoutError
                        && fixture.flow.auditState.deadline == 108 && fixture.flow.auditState.active == 0
                        && fixture.failures(2) == 0,
                        "Known-slow third extended the deadline or acquired an unobserved failure")
        }
        try check("a third provider's own 1.2s history permits its useful replacement window") {
            let fixture = try heterogeneousProviderFixture(thirdCold: 1200)
            fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 3 && fixture.probe.peer(2) != nil
                        && fixture.peer(1).cancellationReasons == [.hedgeRotation],
                        "A measured fast third borrowed the slower first provider's cold cost")
            fixture.answer(2, at: 6.534)
            try fixture.requireSuccess("Own measured fast third did not complete within eight seconds")
        }
        try check("a backup's own 3.6s cost retains headroom before a known-fast third is tried") {
            let fixture = try heterogeneousProviderFixture(thirdCold: 1200, backupCold: 3600)
            fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 2 && fixture.probe.peer(2) == nil
                        && fixture.peer(1).cancellationReasons.isEmpty,
                        "Candidate-only planning clipped a backup inside its own measured headroom")
            fixture.rotate(at: 6.201)
            try require(fixture.flow.auditState.attempts == 3 && fixture.probe.peer(2) != nil
                        && fixture.peer(1).cancellationReasons == [.hedgeRotation],
                        "An expired slow-backup allowance prevented a useful known-fast third")
            fixture.answer(2, at: 7.401)
            try fixture.requireSuccess("Known-fast third did not finish after the backup's full headroom")
        }
        try check("a blackholed backup still rotates when an unknown third has a useful window") {
            let fixture = try Fixture(); fixture.hedge(); fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 3 && fixture.flow.auditState.active == 2
                        && fixture.peer(0).cancellationReasons.isEmpty
                        && fixture.peer(1).cancellationReasons == [.hedgeRotation],
                        "Conservative blackhole rotation stopped or cancelled the original primary")
            fixture.answer(2, at: 5.6); try fixture.requireSuccess("Third approved candidate could not win")
            try require((0..<3).allSatisfy { fixture.failures($0) == 0 }, "Rotation/cancel became provider failures")
        }
        try check("recent DNS send receives response headroom at the rotation boundary") {
            let fixture = try Fixture(); fixture.hedge()
            fixture.peer(1).emit(.tlsStarted, elapsed: 4)
            fixture.peer(1).emit(.tlsReady, elapsed: 5.2)
            fixture.peer(1).emit(.querySendStarted, elapsed: 5.22)
            fixture.peer(1).emit(.querySent, elapsed: 5.24)
            fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 2 && fixture.peer(1).cancellationReasons.isEmpty,
                        "Rotation clipped the first DNS response window after a completed TLS handshake")
            fixture.answer(1, at: 5.45); try fixture.requireSuccess("Response-progress backup did not finish")
        }
        try check("old TLS progress cannot postpone blackhole rotation forever") {
            let fixture = try Fixture(); fixture.hedge()
            fixture.peer(1).emit(.tlsStarted, elapsed: 4)
            fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 3
                        && fixture.peer(1).cancellationReasons == [.hedgeRotation],
                        "An expired TLS grace window blocked the only remaining approved candidate")
            fixture.answer(2, at: 5.6); try fixture.requireSuccess("Third candidate failed after expired TLS grace")
        }
        try check("measured TLS phase cost supplies useful grace beyond the one-second default") {
            let history = DNSQueryProgressSnapshot(stage: .completed, changedAt: 101.2,
                transportStartedAt: 100, transportReadyAt: 100.05,
                tlsStartedAt: 100.05, tlsReadyAt: 101.15,
                querySentAt: 101.15, responseStartedAt: 101.19, responseCompletedAt: 101.2)
            let fixture = try Fixture(coldMilliseconds: [1200, 1300, 1400], phaseHistory: history)
            fixture.hedge(); fixture.peer(1).emit(.tlsStarted, elapsed: 4)
            fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 2 && fixture.peer(1).cancellationReasons.isEmpty,
                        "Measured 1.1s TLS was clipped after its default-only one-second allowance")
            fixture.rotate(at: 5.8)
            try require(fixture.flow.auditState.attempts == 3 && fixture.peer(1).cancellationReasons == [.hedgeRotation],
                        "Measured TLS allowance never expired despite a useful third-candidate window")
            fixture.answer(2, at: 5.9); try fixture.requireSuccess("Third candidate failed after measured TLS grace")
        }
        try check("a completed child reply survives a timer queued before its delivery") {
            let fixture = try Fixture(); fixture.hedge()
            fixture.peer(1).emit(.responseComplete, elapsed: 5.3)
            fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 2 && fixture.peer(1).cancellationReasons.isEmpty,
                        "Rotation discarded a child reply already completed before callback delivery")
            fixture.answer(1, at: 5.4); try fixture.requireSuccess("Completed child reply was not delivered once")
        }
        try check("two-candidate parent checkpoint preserves TLS begun 48ms earlier") {
            let fixture = try ParentFixture(); fixture.child.hedge()
            fixture.child.peer(1).emit(.tlsStarted, elapsed: 2.952)
            fixture.checkpoint(at: 3)
            try require(fixture.probe.peer(99) == nil && fixture.probe.snapshot.errors.isEmpty
                        && fixture.child.peer(1).cancellationReasons.isEmpty
                        && (fixture.timers.nextDeadline ?? 0) >= 103.952
                        && (fixture.timers.nextDeadline ?? .infinity) <= 108,
                        "Parent's three-second checkpoint cut a fresh TLS phase or extended the total deadline")
            fixture.child.answer(1, at: 3.9); fixture.drain()
            try require(fixture.probe.snapshot.answers.count == 1 && fixture.probe.snapshot.errors.isEmpty
                        && fixture.probe.peer(99) == nil && fixture.child.flow.auditState.active == 0,
                        "Protected two-candidate reply lost to an unnecessary fallback")
        }
        try check("two-candidate parent waits for measured cold setup and still ends at eight seconds") {
            let fixture = try ParentFixture(coldMilliseconds: [2500, 4000], hotLast: true)
            fixture.child.hedge(); fixture.checkpoint(at: 4.7)
            try require(fixture.probe.peer(99) == nil && fixture.child.peer(1).cancellationReasons.isEmpty
                        && (fixture.timers.nextDeadline ?? 0) > 105.5
                        && (fixture.timers.nextDeadline ?? .infinity) <= 108,
                        "Fast reused RTT shortened a measured four-second cold setup at the parent checkpoint")
            fixture.checkpoint(at: 5.5)
            try require(fixture.probe.peer(99) == nil, "Measured cold setup lost its promised phase window")
            fixture.checkpoint(at: 6)
            try require(fixture.probe.peer(99) == nil,
                        "Cold-aware parent ignored its measured four-second encrypted window headroom")
            fixture.checkpoint(at: 7.4)
            try require(fixture.probe.peer(99) == nil && fixture.probe.snapshot.errors.isEmpty
                        && fixture.child.peer(1).cancellationReasons.isEmpty,
                        "Known slow encrypted backup was truncated despite its conservative cold allowance")
            fixture.checkpoint(at: 8)
            let result = fixture.probe.snapshot
            try require(result.answers.isEmpty && result.errors.count == 1 && result.errors[0] is DNSQueryTimeoutError
                        && fixture.timers.nextDeadline == nil && fixture.child.flow.auditState.deadline == 108
                        && fixture.child.flow.auditState.active == 0 && fixture.probe.peer(99) == nil
                        && fixture.child.peer(0).cancellationReasons == [.overallDeadline]
                        && fixture.child.peer(1).cancellationReasons == [.overallDeadline],
                        "Cold-cost continuation restarted or extended the original parent deadline")
        }
        try check("a 1.2s late fresh attempt times out without fabricated provider failure") {
            let fixture = try Fixture(); fixture.hedge(); fixture.fail(1, at: 6.8)
            try require(fixture.flow.auditState.attempts == 3 && fixture.peer(2).hasContext,
                        "A real error failed to free the live slot for a final candidate")
            fixture.deadline()
            let result = fixture.probe.snapshot
            try require(result.answers.isEmpty && result.errors.count == 1 && result.errors[0] is DNSQueryTimeoutError
                        && fixture.flow.auditState.active == 0 && fixture.flow.auditState.deadline == 108
                        && fixture.failures(0) == 1 && fixture.failures(1) == 1 && fixture.failures(2) == 0,
                        "Late cold admission was mis-scored or the original eight-second deadline moved")
            fixture.answer(2, at: 8.1, forceLate: true)
            try require(fixture.probe.snapshot.errors.count == 1 && fixture.probe.snapshot.answers.isEmpty
                        && fixture.failures(2) == 0, "Late answer revived a deadline result or health sample")
        }
        try check("a fresh third with enough time still contributes its genuine timeout") {
            let fixture = try Fixture(); fixture.hedge(); fixture.rotate(at: 5.334); fixture.deadline()
            let result = fixture.probe.snapshot
            try require(result.errors.count == 1 && result.errors[0] is DNSQueryTimeoutError
                        && fixture.failures(0) == 1 && fixture.failures(1) == 0 && fixture.failures(2) == 1
                        && fixture.flow.auditState.active == 0,
                        "Useful-window blackhole escaped health failure or a rotated loser acquired one")
        }
        try check("stale reuse cannot charge its seven-second wait to a final 0.8s fresh generation") {
            let fixture = try Fixture(evidence: .reusedThenFresh); fixture.hedge()
            fixture.peer(1).emit(.connectionReused, elapsed: 0.75)
            fixture.peer(1).restartPhysicalTransport(elapsed: 7.2)
            fixture.deadline()
            let result = fixture.probe.snapshot
            try require(result.answers.isEmpty && result.errors.count == 1 && result.errors[0] is DNSQueryTimeoutError
                        && fixture.failures(0) == 1 && fixture.failures(1) == 0
                        && fixture.flow.auditState.active == 0 && fixture.flow.auditState.deadline == 108,
                        "A short fresh retry inherited stale reuse time as a completed cold failure sample")
        }
        try check("a fresh generation after stale reuse still fails when it had three useful seconds") {
            let fixture = try Fixture(evidence: .reusedThenFresh); fixture.hedge()
            fixture.peer(1).emit(.connectionReused, elapsed: 0.75)
            fixture.peer(1).restartPhysicalTransport(elapsed: 5)
            fixture.deadline()
            try require(fixture.probe.snapshot.errors.count == 1 && fixture.failures(0) == 1
                        && fixture.failures(1) == 1 && fixture.flow.auditState.active == 0,
                        "Reused-then-fresh exemption hid an adequately observed physical timeout")
        }
        try check("local admission queue time is excluded from the final fresh connection window") {
            let fixture = try Fixture(candidateCount: 1, startsTransportImmediately: false)
            fixture.peer(0).emit(.transportStarted, elapsed: 7.2); fixture.deadline()
            let result = fixture.probe.snapshot
            try require(result.answers.isEmpty && result.errors.count == 1 && result.errors[0] is DNSQueryTimeoutError
                        && fixture.failures(0) == 0 && fixture.flow.auditState.active == 0
                        && fixture.flow.auditState.deadline == 108,
                        "Local queue delay was mistaken for eight seconds of provider connection opportunity")
        }
        try check("successful fresh retry records 0.5s physical cost while retaining its 7.7s logical RTT") {
            let fixture = try Fixture(evidence: .reusedThenFresh)
            fixture.peer(0).emit(.connectionReused, elapsed: 0)
            fixture.peer(0).restartPhysicalTransport(elapsed: 7.2)
            fixture.answer(0, at: 7.7); try fixture.requireSuccess("Fresh retry's valid reply did not complete")
            let cold = fixture.selector.estimatedMilliseconds(scopeKey: fixture.scope,
                candidateID: fixture.candidates[0].id, phase: .cold)
            let logical = fixture.selector.knownLatencyMilliseconds(scopeKey: fixture.scope,
                candidateID: fixture.candidates[0].id)
            try require(abs((cold ?? 0) - 500) < 0.01 && abs((logical ?? 0) - 7700) < 0.01,
                        "Successful fresh retry charged old idle waiting to its measured cold cost or lost the logical RTT")
            try requireFollowingQueryCanRotate(fixture)
        }
        try check("successful fresh dial excludes 7.2s local queue time from its cold history and later rotation") {
            let fixture = try Fixture(startsTransportImmediately: false)
            fixture.peer(0).emit(.transportStarted, elapsed: 7.2)
            fixture.answer(0, at: 7.7); try fixture.requireSuccess("Queued fresh dial's valid reply did not complete")
            let cold = fixture.selector.estimatedMilliseconds(scopeKey: fixture.scope,
                candidateID: fixture.candidates[0].id, phase: .cold)
            let logical = fixture.selector.knownLatencyMilliseconds(scopeKey: fixture.scope,
                candidateID: fixture.candidates[0].id)
            try require(abs((cold ?? 0) - 500) < 0.01 && abs((logical ?? 0) - 7700) < 0.01,
                        "Local queue waiting became cold DNS connection history")
            try requireFollowingQueryCanRotate(fixture)
        }
        try check("a successful 0.5s fresh retry cannot erase the next two-candidate parent's phase checkpoint") {
            let fixture = try Fixture(evidence: .reusedThenFresh)
            fixture.peer(0).emit(.connectionReused, elapsed: 0)
            fixture.peer(0).restartPhysicalTransport(elapsed: 7.2)
            fixture.answer(0, at: 7.7); try fixture.requireSuccess("Parent control fresh retry did not succeed")
            try requireFollowingParentCanCheckpoint(fixture)
        }
        try check("incomplete physical stamps cannot fabricate cold history; legacy explicit samples stay compatible") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let scope = "missing-physical-stamps", candidate = "only-approved-candidate"
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: [candidate])
            let missingStart = DNSQueryProgressSnapshot(stage: .completed, changedAt: 107.7,
                transportStartedAt: nil, transportReadyAt: nil, tlsStartedAt: nil, tlsReadyAt: nil,
                querySentAt: nil, responseStartedAt: 107.6, responseCompletedAt: 107.7)
            let missingEnd = DNSQueryProgressSnapshot(stage: .awaitingResponse, changedAt: 107.3,
                transportStartedAt: 107.2, transportReadyAt: nil, tlsStartedAt: nil, tlsReadyAt: nil,
                querySentAt: 107.3, responseStartedAt: nil, responseCompletedAt: nil)
            clock.advance(to: 7.7)
            for (transport, progress) in [(DNSQueryTransportEvidence.fresh, missingStart), (.reusedThenFresh, missingEnd)] {
                selector.record(selector.beginObservation(scopeKey: scope, candidateID: candidate),
                    milliseconds: 7700, success: true, transport: transport, progress: progress)
                try require(selector.estimatedMilliseconds(scopeKey: scope, candidateID: candidate, phase: .cold) == nil,
                            "A successful logical RTT fabricated missing physical cold timestamps")
            }
            try require(selector.knownLatencyMilliseconds(scopeKey: scope, candidateID: candidate) == 7700,
                        "Missing physical stamps discarded a real successful logical RTT")
            selector.record(selector.beginObservation(scopeKey: scope, candidateID: candidate),
                            milliseconds: 500, success: true, transport: .fresh)
            try require(selector.estimatedMilliseconds(scopeKey: scope, candidateID: candidate, phase: .cold) == 500,
                        "The public explicit fresh-sample API lost its established meaning")
            let directScope = "joint-direct-tcp-tls"
            _ = selector.orderedCandidates(scopeKey: directScope, candidateIDs: [candidate])
            let jointTLS = DNSQueryProgressSnapshot(stage: .completed, changedAt: 107.7,
                transportStartedAt: nil, transportReadyAt: nil, tlsStartedAt: 107.2, tlsReadyAt: 107.6,
                querySentAt: 107.61, responseStartedAt: 107.69, responseCompletedAt: 107.7)
            selector.record(selector.beginObservation(scopeKey: directScope, candidateID: candidate),
                milliseconds: 7700, success: true, transport: .fresh, progress: jointTLS)
            try require(abs((selector.estimatedMilliseconds(scopeKey: directScope,
                        candidateID: candidate, phase: .cold) ?? 0) - 500) < 0.01,
                        "A joint direct TCP/TLS start could not supply its real physical cold duration")
        }
        try check("caller cancellation drains once without scoring pending providers") {
            let fixture = try Fixture(); fixture.hedge(); try fixture.cancel()
            fixture.answer(1, at: 1, forceLate: true)
            let result = fixture.probe.snapshot
            try require(result.answers.isEmpty && result.errors.isEmpty && fixture.flow.auditState.active == 0
                        && fixture.peer(0).cancellationReasons == [.callerCancelled]
                        && fixture.peer(1).cancellationReasons == [.callerCancelled]
                        && (0..<3).allSatisfy { fixture.failures($0) == 0 },
                        "Caller cancellation delivered a result, double cancelled or changed provider health")
        }
        try check("terminal REFUSED fences a later positive answer and further candidates") {
            let fixture = try Fixture(); fixture.hedge()
            fixture.answer(1, at: 1, code: 5); fixture.answer(0, at: 1.1, forceLate: true)
            let result = fixture.probe.snapshot
            try require(result.answers.count == 1 && result.answers[0][3] & 0x0f == 5
                        && result.errors.isEmpty && fixture.flow.auditState.attempts == 2
                        && (0..<3).allSatisfy { fixture.failures($0) == 0 },
                        "REFUSED triggered provider shopping, accepted a late answer or polluted network health")
        }
        try check("policy revocation at rotation prevents new I/O and late positive delivery") {
            let fixture = try Fixture(); fixture.hedge(); fixture.permission.revoke()
            fixture.rotate(at: 5.334); fixture.answer(0, at: 5.4, forceLate: true)
            let result = fixture.probe.snapshot
            try require(result.answers.count == 1 && result.answers[0][3] & 0x0f == 2
                        && result.errors.isEmpty && fixture.flow.auditState.attempts == 2
                        && fixture.peer(0).cancellationReasons == [.policyChanged]
                        && fixture.peer(1).cancellationReasons == [.policyChanged]
                        && (0..<3).allSatisfy { fixture.failures($0) == 0 },
                        "Revoked policy admitted a third dial, accepted an old answer or marked providers failed")
        }
        try check("unknown third is rescued by real 300ms dispatch timers without moving the two-thirds boundary") {
            try realTimerThirdRescue(timeout: 0.3)
        }
        try check("unknown third is rescued by real 450ms dispatch timers within its original deadline") {
            try realTimerThirdRescue(timeout: 0.45)
        }
        try check("measured cold replacement windows never borrow the unknown-path timer allowance") {
            let fixture = try Fixture(); fixture.hedge(); fixture.clock.advance(to: 5.334)
            fixture.selector.record(fixture.selector.beginObservation(scopeKey: fixture.scope,
                candidateID: fixture.candidates[2].id), milliseconds: 2120, success: true, transport: .fresh)
            fixture.rotate(at: 5.334)
            try require(fixture.flow.auditState.attempts == 2 && fixture.peer(1).cancellationReasons.isEmpty,
                        "Timer allowance reduced a measured 2.7s cold window to fit only 2.666s")
            fixture.answer(1, at: 5.6); try fixture.requireSuccess("Measured-window backup did not finish")
        }
        try check("EOF/TLS original cause survives later cancellation; teardown errors remain distinguishable") {
            let diagnostics = NetworkPerformanceDiagnostics()
            func attempt() -> DNSConnectionAttemptTrace {
                diagnostics.beginDNSAttempt(requestID: UUID(), transport: .doh, purpose: .query,
                    serverName: "doh.pub", endpointIdentity: "memory-endpoint", address: "203.0.113.70")
            }
            let failed = attempt()
            failed.record(.rawEOF)
            failed.record(.tlsFailure, error: NWError.tls(-9816))
            failed.cancel(.hedgeRotation); failed.record(.localCancel)
            failed.record(.rawFailure, error: NSError(domain: "app.hajimi.cpp-protocol", code: 1))
            let stopped = attempt()
            stopped.cancel(.winnerSelected); stopped.record(.localCancel)
            stopped.record(.rawFailure, error: NSError(domain: "app.hajimi.cpp-protocol", code: 1))
            let snapshots = diagnostics.snapshot().dnsConnectionAttempts
            guard let failure = snapshots.first(where: { $0.id == failed.id }),
                  let cancellation = snapshots.first(where: { $0.id == stopped.id }) else {
                throw Failure(text: "Physical attempt diagnostics were not retained")
            }
            try require(failure.firstCarrierClosure?.event == .rawEOF
                        && failure.firstError?.codes.first?.code == -9816
                        && failure.firstErrorBeforeCancellation?.codes.first?.code == -9816
                        && failure.cancellationReason == .hedgeRotation
                        && cancellation.firstErrorBeforeCancellation == nil
                        && cancellation.firstError?.codes.first?.code == 1,
                        "Later cancellation/teardown overwrote or fabricated a pre-cancel native cause")
        }
        try check("encrypted-only deadline fence waits for ACK-auth metadata without penalizing the provider") {
            let clock = Clock(), peer = HeldFenceTransport(clock: clock), probe = Probe(), fence = DeadlineFenceProbe()
            let fixture = deadlineFenceFlow(clock: clock, transport: peer, probe: probe)
            defer { peer.acknowledge(nil); fixture.flow.cancel() }
            clock.advance(to: 8)
            fixture.flow.queryDeadlineReached(completion: fence.record)
            try require(peer.cancellationBegan.wait(timeout: .now() + 1) == .success,
                        "Deadline did not reach the real child's logical cancellation")
            fixture.flow.auditDrain()
            try require(fence.snapshots.isEmpty && fixture.flow.proxyFallbackBarrier() == nil,
                        "Deadline completion escaped before the pending child receipt")
            peer.acknowledge(.failure(EncryptedDNSQueryFailure.authentication), duplicate: true)
            try require(fence.completed.wait(timeout: .now() + 1) == .success,
                        "Authentication receipt never completed its deadline fence")
            fixture.flow.auditDrain()
            guard fence.snapshots.count == 1,
                  case .failure(let error)? = fence.snapshots[0] else {
                throw Failure(text: "Authentication metadata was lost or deadline completion repeated")
            }
            try require(EncryptedDNSQueryFailure.classify(error) == .authentication
                        && fixture.selector.auditHealth(scope: "deadline-fence", candidate: fixture.candidate.id).failures == 0
                        && probe.snapshot.errors.count == 1 && probe.snapshot.errors[0] is DNSQueryTimeoutError
                        && fixture.flow.auditState.deadline == 108 && fixture.flow.auditState.active == 0,
                        "ACK authentication became a provider timeout, lost the original deadline or leaked live work")
        }
        try check("cancel and deadline handoff never acknowledge an empty group before queued cleanup enters it") {
            for deadlineFirst in [true, false] {
                let clock = Clock(), peer = HeldFenceTransport(clock: clock), probe = Probe()
                let fence = DeadlineFenceProbe(), cancellation = DeadlineFenceProbe()
                let fixture = deadlineFenceFlow(clock: clock, transport: peer, probe: probe)
                let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
                defer { release.signal(); peer.acknowledge(nil); fixture.flow.cancel() }
                fixture.flow.auditHoldOwner(entered: entered, release: release)
                try require(entered.wait(timeout: .now() + 1) == .success, "Owner queue did not enter the controlled handoff gap")
                clock.advance(to: 8)
                if deadlineFirst { fixture.flow.queryDeadlineReached(completion: fence.record) }
                fixture.flow.cancel(reason: .callerCancelled) { cancellation.record(nil) }
                if !deadlineFirst { fixture.flow.queryDeadlineReached(completion: fence.record) }
                // In deadline-first order, closed is visible to the first
                // queued deadline callback while cancel cleanup is still
                // behind it. The old empty-group notify completed too early.
                release.signal()
                try require(peer.cancellationBegan.wait(timeout: .now() + 1) == .success,
                            "Queued cancel did not enter the child's real receipt group")
                fixture.flow.auditDrain()
                try require(fence.snapshots.isEmpty && cancellation.snapshots.isEmpty,
                            "Empty-group deadline/cancel handoff acknowledged before the child's receipt")
                peer.acknowledge(nil, duplicate: true)
                try require(fence.completed.wait(timeout: .now() + 1) == .success
                            && cancellation.completed.wait(timeout: .now() + 1) == .success,
                            "Deadline/cancel handoff failed to complete after its real receipt")
                fixture.flow.auditDrain()
                guard fence.snapshots.count == 1, cancellation.snapshots.count == 1,
                      case .failure(let error)? = fence.snapshots[0] else {
                    throw Failure(text: "Deadline/cancel race repeated its completion or lost its cancellation barrier")
                }
                try require(EncryptedDNSQueryFailure.classify(error) == .cancelled
                            && probe.snapshot.answers.isEmpty && probe.snapshot.errors.isEmpty
                            && fixture.selector.auditHealth(scope: "deadline-fence", candidate: fixture.candidate.id).failures == 0
                            && fixture.flow.auditState.active == 0,
                            "Cancelled deadline race sponsored recovery, delivered a result or changed health")
            }
        }
        try check("a custom child without logical ACK returns a configuration barrier at the deadline fence") {
            for protected in [false, true] {
                let clock = Clock(), peer = UnfencedTransport(), probe = Probe(), fence = DeadlineFenceProbe()
                let fixture = deadlineFenceFlow(clock: clock, transport: peer, probe: probe,
                    protectProxyFallback: protected, factoryFinishesAt: protected ? 8.01 : nil)
                defer { fixture.flow.cancel() }
                if !protected { clock.advance(to: 8) }
                fixture.flow.queryDeadlineReached(completion: fence.record)
                try require(fence.completed.wait(timeout: .now() + 1) == .success,
                            "Unfenced custom child failed to complete its explicit non-recovery result")
                fixture.flow.auditDrain()
                guard fence.snapshots.count == 1, case .failure(let error)? = fence.snapshots[0] else {
                    throw Failure(text: "Adopted or protected unadopted child permitted a fresh generation")
                }
                try require(EncryptedDNSQueryFailure.classify(error) == .configuration
                            && peer.cancellationCount == 1 && fixture.flow.auditState.active == 0
                            && fixture.flow.auditState.deadline == 108,
                            "Unfenced adopted or protected factory child was treated as a verified receipt")
            }
        }
        try check("positive, REFUSED and original-error snapshots survive ACK without premature bridging") {
            for code: UInt8 in [0, 5] {
                let clock = Clock(), peer = HeldFenceTransport(clock: clock), probe = Probe(), fence = DeadlineFenceProbe()
                let fixture = deadlineFenceFlow(clock: clock, transport: peer, probe: probe)
                defer { peer.acknowledge(nil); fixture.flow.cancel() }
                var answer = fixture.query; answer[2] = 0x81; answer[3] = 0x80 | code
                clock.advance(to: 8)
                fixture.flow.queryDeadlineReached(completion: fence.record)
                try require(peer.cancellationBegan.wait(timeout: .now() + 1) == .success,
                            "Reply snapshot test never entered the child's cancellation receipt")
                fixture.flow.auditDrain()
                try require(fence.snapshots.isEmpty, "Reply deadline snapshot was returned before the child's ACK")
                peer.acknowledge(.answer(answer), duplicate: true)
                try require(fence.completed.wait(timeout: .now() + 1) == .success,
                            "Admitted reply snapshot was never returned after its cancellation ACK")
                fixture.flow.auditDrain()
                guard fence.snapshots.count == 1, case .answer(let received)? = fence.snapshots[0] else {
                    throw Failure(text: "Positive/REFUSED snapshot disappeared or completion repeated")
                }
                try require(received == answer && received[3] & 0x0f == code
                            && fixture.selector.auditHealth(scope: "deadline-fence", candidate: fixture.candidate.id).failures == 0
                            && fixture.flow.auditState.deadline == 108 && fixture.flow.auditState.active == 0,
                            "Positive/REFUSED reply changed, became a timeout health sample or moved the deadline")
            }
            do {
                let fixture = try Fixture(), fence = DeadlineFenceProbe()
                fixture.hedge()
                let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
                fixture.flow.auditHoldOwner(entered: entered, release: release)
                defer { release.signal() }
                try require(entered.wait(timeout: .now() + 1) == .success,
                            "REFUSED/positive admission test failed to hold the owner queue")
                fixture.clock.advance(to: 7.9)
                // Both native callbacks register synchronously while their
                // delivery blocks remain behind the blocked owner queue.
                fixture.peer(0).answer(code: 5)
                fixture.peer(1).answer(code: 0)
                fixture.clock.advance(to: 8)
                fixture.flow.queryDeadlineReached(completion: fence.record)
                release.signal()
                try require(fence.completed.wait(timeout: .now() + 1) == .success,
                            "Direct REFUSED/positive race did not finish its deadline receipt")
                fixture.flow.auditDrain()
                guard fence.snapshots.count == 1, case .answer(let answer)? = fence.snapshots[0] else {
                    throw Failure(text: "Queued positive erased a previously admitted REFUSED at the deadline")
                }
                try require(answer[3] & 0x0f == 5 && fixture.probe.snapshot.answers.isEmpty
                            && fixture.failures(0) == 0 && fixture.failures(1) == 0
                            && fixture.flow.auditState.active == 0 && fixture.flow.auditState.deadline == 108,
                            "Direct REFUSED was replaced, delivered late or charged as provider timeout")
            }
            do {
                let fixture = try Fixture(candidateCount: 1), fence = DeadlineFenceProbe()
                let original = BridgeSensitiveError()
                let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
                let callbackFinished = DispatchSemaphore(value: 0)
                fixture.flow.auditHoldOwner(entered: entered, release: release)
                defer { original.releaseBridge(); release.signal() }
                try require(entered.wait(timeout: .now() + 1) == .success,
                            "Original-error admission test failed to hold the owner queue")
                fixture.clock.advance(to: 7.9)
                // MemoryTransport acknowledges logical cancellation but has
                // no barrier-provider metadata that could mask lost callback
                // admission. Never classify/bridge the probe in assertions.
                DispatchQueue.global(qos: .userInitiated).async {
                    fixture.peer(0).fail(original); callbackFinished.signal()
                }
                try require(callbackFinished.wait(timeout: .now() + 0.5) == .success
                            && original.bridgeCount == 0,
                            "Original error bridged NSError before its deny metadata was admitted")
                fixture.clock.advance(to: 8)
                fixture.flow.queryDeadlineReached(completion: fence.record)
                release.signal()
                try require(fence.completed.wait(timeout: .now() + 1) == .success,
                            "Original error did not survive the deadline cancellation receipt")
                fixture.flow.auditDrain()
                guard fence.snapshots.count == 1, case .failure(let error)? = fence.snapshots[0],
                      let retained = error as? BridgeSensitiveError, retained === original else {
                    throw Failure(text: "Original-error callback returned an empty or replaced deadline barrier")
                }
                try require(original.bridgeCount == 0 && fixture.failures(0) == 0
                            && fixture.probe.snapshot.answers.isEmpty
                            && fixture.flow.auditState.active == 0 && fixture.flow.auditState.deadline == 108,
                            "Original-error fence bridged, scored a network timeout or moved its deadline")
            }
        }
        print("DNS progress rotation passed: 34 production memory/clock cases, including heterogeneous providers, logical deadline ACK races and real 300/450ms timers; logical-live<=2, attempts<=3, original deadlines preserved")
    }

    static func main() {
        do { try run() }
        catch {
            FileHandle.standardError.write(Data("DNS progress rotation failed: \(error.localizedDescription)\n".utf8))
            Darwin.exit(1)
        }
    }
}

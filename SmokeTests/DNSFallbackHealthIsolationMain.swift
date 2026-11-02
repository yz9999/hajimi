import Foundation

/// Real fallback sequence with injected clocks, timers and memory peers only.
@main enum DNSFallbackHealthIsolationMain {
    private struct Failure: Error { let text: String }
    private static var assertions = 0, cases = 0
    private static func require(_ value: @autoclosure () -> Bool, _ text: String) throws {
        assertions += 1
        if !value() { throw Failure(text: text) }
    }
    private static func runCase(_ name: String, _ work: () throws -> Void) throws {
        do { try work(); cases += 1; print("PASS \(name)") }
        catch { print("FAIL \(name): \(error)"); throw error }
    }
    private final class Clock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ delta: TimeInterval) { lock.lock(); value += delta; lock.unlock() }
    }
    private final class Timers {
        private final class Item {
            let at: TimeInterval, queue: DispatchQueue, work: () -> Void
            var cancelled = false
            init(at: TimeInterval, queue: DispatchQueue, work: @escaping () -> Void) {
                self.at = at; self.queue = queue; self.work = work
            }
        }
        private let clock: Clock, lock = NSLock()
        private var items: [Item] = []
        init(_ clock: Clock) { self.clock = clock }
        var schedule: DNSProxyFallbackQueryDatagram.Schedule {
            { queue, delay, work in
                let item = Item(at: self.clock.now() + delay, queue: queue, work: work)
                self.lock.lock(); self.items.append(item); self.lock.unlock()
                return { self.lock.lock(); item.cancelled = true; self.lock.unlock() }
            }
        }
        func fire() {
            lock.lock()
            let due = items.filter { !$0.cancelled && $0.at <= clock.now() }
            items.removeAll { $0.cancelled || $0.at <= clock.now() }
            lock.unlock()
            due.forEach { $0.queue.async(execute: $0.work) }
        }
    }
    private final class Peer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging,
                              DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding {
        private let lock = NSLock()
        private let receive: (Data) -> Void, failure: (Error) -> Void
        private let evidence: DNSQueryTransportEvidence
        private var hold: Bool, callbacks: [() -> Void] = []
        private var barrier: DNSProxyFallbackBarrier?, sent: [Data] = []
        private var reasons: [DNSAttemptCancellationReason] = []
        init(receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void,
             evidence: DNSQueryTransportEvidence, hold: Bool) {
            self.receive = receive; self.failure = failure; self.evidence = evidence; self.hold = hold
        }
        func send(_ data: Data) { lock.lock(); sent.append(data); lock.unlock() }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) { cancel(reason: .callerCancelled, completion: completion) }
        func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
            lock.lock(); reasons.append(reason)
            if hold { callbacks.append(completion); lock.unlock() }
            else { lock.unlock(); completion() }
        }
        func acknowledge(barrier: DNSProxyFallbackBarrier? = nil, duplicate: Bool = false) {
            lock.lock(); self.barrier = barrier; hold = false
            let values = callbacks; callbacks.removeAll(); lock.unlock()
            values.forEach { callback in callback(); if duplicate { callback() } }
        }
        func answer(_ data: Data) { receive(data) }
        func fail(_ error: Error) { failure(error) }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { lock.lock(); defer { lock.unlock() }; return barrier }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { evidence }
        var queries: [Data] { lock.lock(); defer { lock.unlock() }; return sent }
        var cancelReasons: [DNSAttemptCancellationReason] { lock.lock(); defer { lock.unlock() }; return reasons }
    }
    private final class History {
        let clock = Clock()
        let scope = "memory-only-fallback-query-health-isolation"
        let servers = [DNSProxyFallbackServer("203.0.113.80")!, DNSProxyFallbackServer("203.0.113.81")!]
        lazy var selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        var ids: [String] { servers.map { [$0.host, String($0.port)].map { "\($0.utf8.count):\($0)" }.joined() } }
        func healthScope(_ query: Data) -> String {
            DNSAdaptiveUpstreamSelector.queryHealthScope(scopeKey: scope, query: query)
        }
        func order(_ query: Data) -> [String] { selector.orderedCandidates(scopeKey: healthScope(query), candidateIDs: ids) }
        func latency(_ query: Data, index: Int) -> Double? {
            selector.knownLatencyMilliseconds(scopeKey: healthScope(query), candidateID: ids[index])
        }
    }
    private final class Fixture {
        let history: History, query: Data, deadline: TimeInterval
        private let lock = NSLock(), evidence: DNSQueryTransportEvidence
        private let holdIndices: Set<Int>
        private var allowed = true, peerValues: [Peer] = [], serverValues: [DNSProxyFallbackServer] = []
        private var deadlineValues: [TimeInterval] = [], answers: [Data] = [], errors: [Error] = []
        private lazy var timers = Timers(history.clock)
        private lazy var sequence = DNSProxyFallbackResolverSequence(
            servers: history.servers, selector: history.selector, scopeKey: history.scope,
            queue: .global(qos: .userInitiated), absoluteDeadline: deadline,
            permitted: { [weak self] in self?.isAllowed ?? false },
            factory: { [weak self] server, _, deadline, receive, failure in
                guard let self else { throw EncryptedDNSQueryFailure.cancelled }
                self.lock.lock(); let index = self.peerValues.count
                let peer = Peer(receive: receive, failure: failure, evidence: self.evidence,
                                hold: self.holdIndices.contains(index))
                self.peerValues.append(peer); self.serverValues.append(server); self.deadlineValues.append(deadline)
                self.lock.unlock(); return peer
            }, receive: { [weak self] answer in
                guard let self else { return }; self.lock.lock(); self.answers.append(answer); self.lock.unlock()
            }, failure: { [weak self] error in
                guard let self else { return }; self.lock.lock(); self.errors.append(error); self.lock.unlock()
            }, clock: history.clock.now, schedule: timers.schedule,
            diagnostics: NetworkPerformanceDiagnostics())
        init(_ history: History, type: UInt16 = 1, name: String = "forward.example.test",
             duration: TimeInterval = 8, evidence: DNSQueryTransportEvidence = .fresh,
             holdIndices: Set<Int> = []) {
            self.history = history
            query = DNSMessageInspection.query(for: name, type: type, id: 0x4851)!
            deadline = history.clock.now() + duration; self.evidence = evidence; self.holdIndices = holdIndices
        }
        var isAllowed: Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        var peers: [Peer] { lock.lock(); defer { lock.unlock() }; return peerValues }
        var servers: [DNSProxyFallbackServer] { lock.lock(); defer { lock.unlock() }; return serverValues }
        var deadlines: [TimeInterval] { lock.lock(); defer { lock.unlock() }; return deadlineValues }
        var received: [Data] { lock.lock(); defer { lock.unlock() }; return answers }
        var failures: [Error] { lock.lock(); defer { lock.unlock() }; return errors }
        func start() { sequence.send(query); settle() }
        func sendAgain(_ data: Data) { sequence.send(data); settle() }
        func settle() { for _ in 0..<12 { sequence.drainQueueForSelfTest() } }
        func advance(_ delta: TimeInterval) { history.clock.advance(delta); timers.fire(); settle() }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
        func cancel() { sequence.cancel(); settle() }
        func signalDeadline() { sequence.queryDeadlineReached(); settle() }
        func stop() { cancel(); peers.forEach { $0.acknowledge() }; settle() }
        func goodAnswer() -> Data {
            var answer = query; answer[2] = 0x81; answer[3] = 0x80; return answer
        }
        func refusedAnswer() -> Data { DNSMessageInspection.errorResponse(to: query, code: .refused)! }
        func succeed(_ milliseconds: Double = 20) { advance(milliseconds / 1000); peers.last!.answer(goodAnswer()); settle() }
    }
    private static func learnForward(_ history: History) throws {
        let fixture = Fixture(history); defer { fixture.stop() }; fixture.start()
        try require(fixture.servers == [history.servers[0]], "forward seed did not use configured primary")
        fixture.succeed()
        try require(fixture.received.count == 1 && fixture.failures.isEmpty, "forward seed did not complete")
        try require(history.order(fixture.query).first == history.ids[0], "forward seed was not learned")
    }
    private static func ptrTimeoutIsolation() throws {
        let names = ["1.0.0.1.in-addr.arpa", "1.0.0.10.in-addr.arpa", "1.0.19.198.in-addr.arpa", "b._dns-sd._udp.example.test"]
        for name in names {
            for type: UInt16 in [1, 28, 65] {
                try runCase("PTR timeout \(name) preserves forward type \(type)") {
                    let history = History(); try learnForward(history)
                    let reverse = Fixture(history, type: 12, name: name); defer { reverse.stop() }; reverse.start()
                    try require(reverse.servers == [history.servers[0]], "PTR did not start with primary")
                    let forward = Fixture(history, type: type); defer { forward.stop() }
                    let before = history.latency(forward.query, index: 0)
                    reverse.advance(4)
                    try require(reverse.servers == history.servers, "real PTR timeout did not advance to approved backup")
                    try require(reverse.peers[0].cancelReasons == [.requestDeadline], "PTR timeout lost real cancellation reason")
                    try require(history.order(reverse.query).first == history.ids[1], "PTR timeout did not train reverse health")
                    try require(history.order(forward.query).first == history.ids[0]
                                && history.latency(forward.query, index: 0) == before,
                                "PTR timeout polluted forward preference or latency")
                    reverse.succeed(10)
                    try require(reverse.received.count == 1 && reverse.failures.isEmpty, "PTR backup failed to complete")
                    forward.start()
                    try require(forward.servers == [history.servers[0]], "actual forward sequence inherited PTR cooldown")
                    forward.succeed(5)
                    try require(forward.received.count == 1 && forward.failures.isEmpty, "forward query failed after PTR timeout")
                }
            }
        }
    }
    private static func ordinarySharingAndReverseRecovery() throws {
        try runCase("A AAAA HTTPS retain shared health") {
            let history = History(); try learnForward(history)
            let ipv6 = Fixture(history, type: 28); defer { ipv6.stop() }; ipv6.start()
            ipv6.advance(4)
            try require(ipv6.servers == history.servers, "AAAA timeout did not fail over")
            ipv6.succeed(10)
            try require(history.order(ipv6.query).first == history.ids[1], "AAAA failed primary was not cooling")
            for type: UInt16 in [65, 1, 28] {
                let query = Fixture(history, type: type); defer { query.stop() }; query.start()
                try require(query.servers == [history.servers[1]], "ordinary type \(type) lost shared health")
                query.succeed(5)
                try require(query.received.count == 1 && query.failures.isEmpty, "ordinary type \(type) failed")
            }
        }
        try runCase("PTR success cannot clear forward cooldown") {
            let history = History()
            let forward = Fixture(history); defer { forward.stop() }; forward.start(); forward.advance(4); forward.succeed(10)
            try require(history.order(forward.query).first == history.ids[1], "forward cooldown fixture did not train")
            let reverse = Fixture(history, type: 12, name: "1.0.0.1.in-addr.arpa")
            defer { reverse.stop() }; reverse.start()
            try require(reverse.servers == [history.servers[0]], "forward timeout polluted reverse preference")
            reverse.succeed(5)
            try require(history.order(reverse.query).first == history.ids[0]
                        && history.order(forward.query).first == history.ids[1], "PTR success cleared forward cooldown")
            let next = Fixture(history, type: 65); defer { next.stop() }; next.start()
            try require(next.servers == [history.servers[1]], "forward sequence ignored its existing cooldown")
        }
    }
    private static func cancellationAndBarriers() throws {
        for type: UInt16 in [1, 12] {
            try runCase("type \(type) caller cancellation remains unscored") {
                let history = History(); let fixture = Fixture(history, type: type, holdIndices: [0])
                defer { fixture.stop() }; fixture.start(); fixture.advance(0.2); fixture.cancel()
                fixture.advance(8); fixture.peers[0].acknowledge(duplicate: true); fixture.settle(); fixture.signalDeadline()
                try require(fixture.servers.count == 1 && fixture.received.isEmpty && fixture.failures.isEmpty,
                            "caller cancellation produced a terminal result or replacement")
                try require(fixture.peers[0].cancelReasons == [.callerCancelled], "caller cancellation duplicated or changed reason")
                try require(history.order(fixture.query).first == history.ids[0]
                            && history.latency(fixture.query, index: 0) == nil, "caller cancellation trained health")
            }
            try runCase("type \(type) authentication terminates without failover") {
                let history = History(); let fixture = Fixture(history, type: type); defer { fixture.stop() }; fixture.start()
                fixture.peers[0].fail(EncryptedDNSQueryFailure.authentication); fixture.settle()
                try require(fixture.failures.count == 1
                            && (fixture.failures[0] as? EncryptedDNSQueryFailure) == .authentication,
                            "authentication failure was rewritten")
                try require(fixture.servers.count == 1 && history.order(fixture.query).first == history.ids[0]
                            && history.latency(fixture.query, index: 0) == nil, "authentication authorized retry or trained health")
            }
            try runCase("type \(type) REFUSED remains exact final answer") {
                let history = History(); let fixture = Fixture(history, type: type); defer { fixture.stop() }; fixture.start()
                let answer = fixture.refusedAnswer(); fixture.peers[0].answer(answer); fixture.settle()
                try require(fixture.received == [answer] && fixture.failures.isEmpty && fixture.servers.count == 1,
                            "REFUSED was changed, retried or delivered more than once")
                try require(history.order(fixture.query).first == history.ids[0]
                            && history.latency(fixture.query, index: 0) == nil, "REFUSED trained provider health")
            }
            for refused in [false, true] {
                try runCase("type \(type) delayed ACK \(refused ? "REFUSED" : "authentication") barrier") {
                    let history = History(); let fixture = Fixture(history, type: type, holdIndices: [0])
                    defer { fixture.stop() }; fixture.start(); fixture.advance(4)
                    try require(fixture.servers.count == 1 && history.order(fixture.query).first == history.ids[0],
                                "timeout advanced or trained before ACK fence")
                    let answer = fixture.refusedAnswer()
                    fixture.peers[0].acknowledge(barrier: refused ? .answer(answer) : .failure(EncryptedDNSQueryFailure.authentication),
                                                 duplicate: true)
                    fixture.settle()
                    try require(fixture.servers.count == 1 && history.order(fixture.query).first == history.ids[0],
                                "ACK denial authorized replacement or trained failure")
                    if refused {
                        try require(fixture.received == [answer] && fixture.failures.isEmpty, "ACK REFUSED was not preserved")
                    } else {
                        try require(fixture.received.isEmpty && fixture.failures.count == 1
                                    && (fixture.failures[0] as? EncryptedDNSQueryFailure) == .authentication,
                                    "ACK authentication was not preserved")
                    }
                }
            }
        }
        try runCase("cancel during PTR timeout ACK cannot train or retry") {
            let history = History(); let fixture = Fixture(history, type: 12, holdIndices: [0])
            defer { fixture.stop() }; fixture.start(); fixture.advance(4); fixture.cancel()
            fixture.peers[0].acknowledge(duplicate: true); fixture.settle(); fixture.advance(4)
            try require(fixture.servers.count == 1 && fixture.failures.isEmpty && fixture.received.isEmpty,
                        "cancelled PTR transition resumed or delivered result")
            try require(history.order(fixture.query).first == history.ids[0], "cancelled PTR transition trained failure")
        }
        try runCase("not-started PTR timeout does not train health") {
            let history = History(); let fixture = Fixture(history, type: 12, evidence: .notStarted)
            defer { fixture.stop() }; fixture.start(); fixture.advance(4)
            try require(fixture.servers == history.servers && history.order(fixture.query).first == history.ids[0],
                        "not-started PTR timeout trained provider health")
        }
    }
    private static func deadlineAndAuthorization() throws {
        for type: UInt16 in [1, 12] {
            try runCase("type \(type) original total deadline survives delayed ACK") {
                let history = History(); let fixture = Fixture(history, type: type, holdIndices: [1])
                defer { fixture.stop() }; fixture.start(); fixture.advance(4)
                try require(fixture.deadlines.count == 2 && fixture.deadlines[0] == 104 && fixture.deadlines[1] == 108,
                            "fallback factory extended or reset original deadline")
                fixture.advance(4)
                try require(fixture.failures.count == 1 && fixture.failures[0] is DNSQueryTimeoutError
                            && fixture.received.isEmpty && fixture.servers.count == 2,
                            "total deadline waited for cancellation ACK or retried")
                try require(fixture.peers[1].cancelReasons == [.overallDeadline], "total timeout cancellation reason changed")
                fixture.peers[1].acknowledge(duplicate: true); fixture.settle(); fixture.signalDeadline(); fixture.advance(10)
                fixture.peers[1].answer(fixture.goodAnswer()); fixture.settle()
                try require(fixture.failures.count == 1 && fixture.received.isEmpty && fixture.servers.count == 2,
                            "late ACK/timer/answer duplicated terminal result")
            }
            try runCase("type \(type) expired admission does not dial") {
                let history = History(); let fixture = Fixture(history, type: type, duration: 0)
                defer { fixture.stop() }; fixture.start()
                try require(fixture.servers.isEmpty && fixture.failures.count == 1
                            && fixture.failures[0] is DNSQueryTimeoutError, "expired original deadline created a transport")
            }
            try runCase("type \(type) authorization revocation cannot retry or train") {
                let history = History(); let fixture = Fixture(history, type: type); defer { fixture.stop() }; fixture.start()
                fixture.revoke(); fixture.advance(4)
                try require(fixture.servers.count == 1 && fixture.failures.count == 1
                            && (fixture.failures[0] as? EncryptedDNSQueryFailure) == .policy,
                            "revoked permission allowed replacement or lost policy error")
                try require(history.order(fixture.query).first == history.ids[0], "policy revocation trained a failure")
            }
        }
        try runCase("second send cannot change admitted health scope") {
            let history = History(); let fixture = Fixture(history); defer { fixture.stop() }; fixture.start()
            let reverse = DNSMessageInspection.query(for: "1.0.0.1.in-addr.arpa", type: 12, id: 0x4852)!
            fixture.sendAgain(reverse); fixture.succeed(10)
            try require(fixture.peers[0].queries == [fixture.query] && fixture.received.count == 1,
                        "duplicate send replaced admitted query")
            try require(history.latency(fixture.query, index: 0) != nil && history.latency(reverse, index: 0) == nil,
                        "duplicate send changed health domain")
        }
    }
    static func main() throws {
        try ptrTimeoutIsolation()
        try ordinarySharingAndReverseRecovery()
        try cancellationAndBarriers()
        try deadlineAndAuthorization()
        print("Fallback health isolation passed: \(cases) cases / \(assertions) assertions; exact production sequence, memory-only clock/peers, no sockets")
    }
}

import Foundation
import HajimiDNS

/// Deterministic memory peers and separate parent/child timer queues exercise
/// total-deadline ownership. No native transport, listener, DNS or profile I/O.
enum DNSFallbackDeadlineHealthSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "代理 DNS 期限健康自检失败：\(text)" }
    }
    private static func require(_ value: Bool, _ text: String) throws {
        if !value { throw Failure(text: text) }
    }
    private final class Clock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func set(_ value: TimeInterval) { lock.lock(); self.value = value; lock.unlock() }
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
    private final class Peer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding,
                              DNSQueryTransportEvidenceProviding {
        private let lock = NSLock(), failOnSend: ((Error) -> Void)?
        private let evidence: DNSQueryTransportEvidence
        private var hold: Bool, callbacks: [() -> Void] = [], cancels = 0
        private var barrier: DNSProxyFallbackBarrier?
        init(evidence: DNSQueryTransportEvidence = .fresh, hold: Bool = false,
             failOnSend: ((Error) -> Void)? = nil) {
            self.evidence = evidence; self.hold = hold; self.failOnSend = failOnSend
        }
        func send(_ data: Data) { failOnSend?(EncryptedDNSQueryFailure.network) }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); cancels += 1
            if hold { callbacks.append(completion); lock.unlock() }
            else { lock.unlock(); completion() }
        }
        func acknowledge(barrier: DNSProxyFallbackBarrier? = nil, duplicate: Bool = false) {
            lock.lock(); self.barrier = barrier; hold = false
            let values = callbacks; callbacks.removeAll(); lock.unlock()
            values.forEach { callback in callback(); if duplicate { callback() } }
        }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { lock.lock(); defer { lock.unlock() }; return barrier }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { evidence }
        var cancelCount: Int { lock.lock(); defer { lock.unlock() }; return cancels }
    }
    private final class Fixture {
        let clock = Clock()
        let query = DNSMessageInspection.query(for: "deadline-health.example.test", type: 1, id: 0x7351)!
        let servers = [DNSProxyFallbackServer("203.0.113.60")!, DNSProxyFallbackServer("203.0.113.61")!]
        let scope = "memory-only-fallback-deadline-health"
        private let lock = NSLock()
        private var allowed = true, errors = 0, peers: [Peer] = []
        private let tailEvidence: DNSQueryTransportEvidence, holdFirst: Bool
        private(set) var sequence: DNSProxyFallbackResolverSequence?
        lazy var selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        lazy var parentTimers = Timers(clock)
        lazy var childTimers = Timers(clock)
        lazy var parent = DNSProxyFallbackQueryDatagram(queue: .global(qos: .userInitiated),
            absoluteDeadline: 108, permitted: { [weak self] in self?.isAllowed ?? false },
            knownMilliseconds: { [] }, encrypted: { _, _, _, failure in Peer(failOnSend: failure) },
            fallback: { [weak self] queue, deadline, receive, failure in
                guard let self else { throw EncryptedDNSQueryFailure.cancelled }
                let child = DNSProxyFallbackResolverSequence(servers: self.servers, selector: self.selector,
                    scopeKey: self.scope, queue: queue, absoluteDeadline: deadline,
                    permitted: { [weak self] in self?.isAllowed ?? false },
                    factory: { [weak self] _, _, _, _, _ in
                        guard let self else { throw EncryptedDNSQueryFailure.cancelled }
                        self.lock.lock(); let index = self.peers.count
                        let peer = Peer(evidence: index == 0 ? .fresh : self.tailEvidence,
                                        hold: index > 0 || self.holdFirst)
                        self.peers.append(peer); self.lock.unlock(); return peer
                    }, receive: receive, failure: failure, clock: self.clock.now, schedule: self.childTimers.schedule)
                self.lock.lock(); self.sequence = child; self.lock.unlock(); return child
            }, receive: { _ in }, failure: { [weak self] _ in
                guard let self else { return }; self.lock.lock(); self.errors += 1; self.lock.unlock()
            }, clock: clock.now, schedule: parentTimers.schedule, diagnostics: NetworkPerformanceDiagnostics())
        init(tailEvidence: DNSQueryTransportEvidence = .fresh, holdFirst: Bool = false) {
            self.tailEvidence = tailEvidence; self.holdFirst = holdFirst
        }
        var isAllowed: Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        var failureCount: Int { lock.lock(); defer { lock.unlock() }; return errors }
        var transports: [Peer] { lock.lock(); defer { lock.unlock() }; return peers }
        var preferred: DNSProxyFallbackServer? {
            let ids = servers.map { [ $0.host, String($0.port) ].map { "\($0.utf8.count):\($0)" }.joined() }
            let first = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids).first
            return zip(servers, ids).first { $0.1 == first }?.0
        }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
        func settle() {
            for _ in 0..<16 {
                parent.drainQueueForSelfTest()
                lock.lock(); let child = sequence; lock.unlock(); child?.drainQueueForSelfTest()
            }
        }
        func start() {
            parent.send(query); settle()
            clock.set(104); childTimers.fire(); settle()
        }
        func deadline(parentFirst: Bool) {
            clock.set(108)
            if parentFirst { parentTimers.fire() } else { childTimers.fire() }
            settle()
        }
        func stop() {
            parent.cancel(); transports.forEach { $0.acknowledge() }; settle()
            sequence?.cancel(); settle()
        }
    }

    static func run() throws {
        var cases = 0
        for parentFirst in [true, false] {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start()
            try require(fixture.transports.count == 2 && fixture.preferred == fixture.servers[1],
                        "fixture did not reach its final approved resolver")
            let tail = fixture.transports[1]
            fixture.deadline(parentFirst: parentFirst)
            try require(fixture.failureCount == 1 && tail.cancelCount == 1
                        && fixture.preferred == fixture.servers[1],
                        "total timeout waited for ACK, canceled twice or trained before its fence")
            tail.acknowledge(duplicate: true); fixture.settle()
            fixture.parentTimers.fire(); fixture.childTimers.fire(); fixture.sequence?.queryDeadlineReached(); fixture.settle()
            try require(fixture.failureCount == 1 && tail.cancelCount == 1
                        && fixture.preferred == fixture.servers[0],
                        "final observed timeout was lost or terminal callbacks were duplicated")
            cases += 1
        }
        for exclusion in 0..<5 {
            let fixture = Fixture(tailEvidence: exclusion == 0 ? .notStarted : .fresh)
            defer { fixture.stop() }; fixture.start()
            let tail = fixture.transports[1]
            fixture.deadline(parentFirst: true)
            let barrier: DNSProxyFallbackBarrier?
            switch exclusion {
            case 1: barrier = .failure(EncryptedDNSQueryFailure.authentication)
            case 2: barrier = .failure(EncryptedDNSQueryFailure.other)
            case 3: barrier = .answer(DNSMessageInspection.errorResponse(to: fixture.query, code: .refused)!)
            default: barrier = nil
            }
            if exclusion == 4 { fixture.revoke() }
            tail.acknowledge(barrier: barrier); fixture.settle()
            try require(fixture.failureCount == 1 && fixture.preferred == fixture.servers[1],
                        "not-started, native denial, negative answer or policy revocation polluted provider health")
            cases += 1
        }
        for duringTransition in [false, true] {
            let fixture = Fixture(holdFirst: duringTransition); defer { fixture.stop() }; fixture.start()
            let peer = fixture.transports.last!
            fixture.parent.cancel(); fixture.settle()
            fixture.clock.set(108); fixture.parentTimers.fire(); fixture.childTimers.fire(); fixture.settle()
            peer.acknowledge(); fixture.settle()
            let expected = duringTransition ? fixture.servers[0] : fixture.servers[1]
            try require(fixture.failureCount == 0 && peer.cancelCount == 1 && fixture.preferred == expected,
                        "ordinary client cancellation was recorded as a provider failure")
            cases += 1
        }
        do {
            let fixture = Fixture(holdFirst: true); defer { fixture.stop() }; fixture.start()
            let first = fixture.transports[0]
            fixture.deadline(parentFirst: true)
            try require(fixture.failureCount == 1 && first.cancelCount == 1 && fixture.transports.count == 1,
                        "deadline duplicated a pending earlier cancellation or waited for its ACK")
            first.acknowledge(); fixture.settle()
            try require(fixture.preferred == fixture.servers[1] && fixture.transports.count == 1,
                        "earlier observed failure disappeared across total deadline or started a late replacement")
            cases += 1
        }
        do {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start()
            let tail = fixture.transports[1]
            fixture.deadline(parentFirst: true)
            fixture.sequence?.cancel(); fixture.settle()
            tail.acknowledge(); fixture.settle()
            try require(fixture.failureCount == 1 && fixture.preferred == fixture.servers[0],
                        "post-timeout cleanup rewrote an already-admitted total timeout as client cancel")
            cases += 1
        }
        print("Proxy DNS total-deadline health checks passed: \(cases) memory cases, parent/child timer order, ACK denial fence, queued/policy/client-cancel exclusions and one terminal callback")
    }
}

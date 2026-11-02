import Foundation

/// Memory-only integration checks for the actual coordinator/fallback classes.
/// No listener, DNS provider, route, Helper, profile, or GUI is involved.
@main enum DNSQueryLineageMain {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { "DNS query lineage check failed: \(message)" }
    }
    private static func require(_ value: Bool, _ message: String) throws {
        if !value { throw Failure(message: message) }
    }
    private static let callbacks = DispatchQueue(label: "app.hajimi.dns.lineage-check.callbacks")

    private static func query(_ id: UInt16, name: String = "private-query.example.test") -> Data {
        DNSMessageInspection.query(for: name, type: 1, id: id)!
    }
    private static func answer(_ query: Data) -> Data {
        let end = DNSMessageInspection.singleQuestion(in: query)!.questionEnd
        var response = Data(query.prefix(end))
        response[2] = 0x81; response[3] = 0x80
        for index in 6...11 { response[index] = 0 }
        response[7] = 1
        response.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7])
        return response
    }

    private final class Peer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSQueryExecutionContextAccepting {
        private let lock = NSLock()
        private let receive: (Data) -> Void, failure: (Error) -> Void
        private var value: DNSQueryExecutionContext?, sentContext: DNSQueryExecutionContext?, payload: Data?
        private var cancellations = 0
        init(receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            self.receive = receive; self.failure = failure
        }
        func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
            lock.lock(); value = context; lock.unlock()
        }
        func send(_ data: Data) {
            lock.lock(); sentContext = value; payload = data; lock.unlock()
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); cancellations += 1; lock.unlock(); completion()
        }
        var contextAtSend: DNSQueryExecutionContext? { lock.lock(); defer { lock.unlock() }; return sentContext }
        var cancelCount: Int { lock.lock(); defer { lock.unlock() }; return cancellations }
        func reply() {
            lock.lock(); let query = payload; lock.unlock()
            if let query { receive(DNSQueryLineageMain.answer(query)) }
        }
        func fail() { failure(EncryptedDNSQueryFailure.network) }
    }
    private final class Harness {
        private let lock = NSLock()
        private var values: [Peer] = []
        var peers: [Peer] { lock.lock(); defer { lock.unlock() }; return values }
        var factory: DNSQueryCoordinator.Factory {
            { _, receive, failure in
                let peer = Peer(receive: receive, failure: failure)
                self.lock.lock(); self.values.append(peer); self.lock.unlock(); return peer
            }
        }
    }
    private final class CompletionLedger {
        private let lock = NSLock()
        private var values: [(UUID, Bool)] = []
        func callback(_ id: UUID, query: Data) -> (Data?) -> Void {
            { response in
                let valid = response.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true
                self.lock.lock(); self.values.append((id, valid)); self.lock.unlock()
            }
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return values.count }
        var allValid: Bool { lock.lock(); defer { lock.unlock() }; return values.allSatisfy { $0.1 } }
    }

    private static func mergedRootAndWaiterOutcomes() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), harness = Harness(), ledger = CompletionLedger()
        let coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
        var ids: [UUID] = []
        for index in UInt16(1)...32 {
            let message = query(index), marker = UUID()
            ids.append(coordinator.resolve(scope: "private-policy", query: message, callbackQueue: callbacks,
                permitted: { true }, factory: harness.factory, completion: ledger.callback(marker, query: message)))
        }
        let admitted = coordinator.statistics
        try require(admitted.upstreamQueries == 1 && admitted.mergedQueries == 31, "single flight changed")
        guard let peer = harness.peers.first, let context = peer.contextAtSend else {
            throw Failure(message: "coordinator did not install context before send")
        }
        let open = diagnostics.snapshot().dnsLogicalQueries
        try require(open.count == 1 && open[0].rootID == context.rootID && open[0].admittedCount == 32
                    && open[0].mergedCount == 31 && open[0].finishedCount == 0, "merged root admission mismatch")
        coordinator.cancel(ids[0])
        coordinator.cancel(ids[1], deadlineExpired: true)
        _ = coordinator.statistics; callbacks.sync {}
        try require(peer.cancelCount == 0, "one waiter cancelled shared transport")
        peer.reply(); _ = coordinator.statistics; callbacks.sync {}
        let closed = diagnostics.snapshot().dnsLogicalQueries
        try require(closed.count == 1 && closed[0].finishedCount == 32
                    && closed[0].outcomeCounts["success"] == 30
                    && closed[0].outcomeCounts["failure"] == 1
                    && closed[0].outcomeCounts["cancelled"] == 1
                    && closed[0].failureCounts["timeout"] == 1, "per-waiter terminal counts mismatch")
        try require(Set(closed[0].waiters.map(\.waiterID)) == Set(ids)
                    && closed[0].waiters.allSatisfy { $0.outcome != nil }, "missing waiter final outcome")
        try require(ledger.count == 30 && ledger.allValid && peer.cancelCount == 1, "response IDs/cancel ownership changed")
        coordinator.cancel(ids[1], deadlineExpired: true); peer.reply(); peer.fail()
        _ = coordinator.statistics; callbacks.sync {}
        try require(diagnostics.snapshot().dnsLogicalQueries == closed && ledger.count == 30,
                    "late completion duplicated a final outcome")
        let serialized = String(data: try JSONEncoder().encode(closed), encoding: .utf8)!
        try require(!serialized.contains("private-policy") && !serialized.contains("private-query")
                    && !serialized.contains("203.0.113"), "query/policy/address entered logical diagnostics")
    }

    private static func noIOFinalOutcomes() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), cache = DNSQueryCache(), harness = Harness()
        let coordinator = DNSQueryCoordinator(cache: cache, maximumPending: 0, diagnostics: diagnostics)
        let message = query(0x7351)
        try require(cache.store(scopeKey: "cached-policy", query: message, response: answer(message)), "cache setup failed")
        coordinator.resolve(scope: "cached-policy", query: message, callbackQueue: callbacks,
            permitted: { true }, factory: harness.factory, completion: { _ in })
        coordinator.resolve(scope: "denied-policy", query: message, callbackQueue: callbacks,
            permitted: { false }, factory: harness.factory, completion: { _ in })
        coordinator.resolve(scope: "expired-policy", query: message, callbackQueue: callbacks,
            absoluteDeadline: 0, permitted: { true }, factory: harness.factory, completion: { _ in })
        coordinator.resolve(scope: "full-policy", query: message, callbackQueue: callbacks,
            permitted: { true }, factory: harness.factory, completion: { _ in })
        _ = coordinator.statistics; callbacks.sync {}
        let roots = diagnostics.snapshot().dnsLogicalQueries
        try require(roots.count == 4 && roots.allSatisfy { $0.admittedCount == 1 && $0.finishedCount == 1
                    && $0.mergedCount == 0 }, "cache/refusal root records missing")
        try require(roots.reduce(UInt64(0)) { $0 + ($1.outcomeCounts["success"] ?? 0) } == 1
                    && roots.reduce(UInt64(0)) { $0 + ($1.outcomeCounts["cancelled"] ?? 0) } == 1
                    && roots.reduce(UInt64(0)) { $0 + ($1.failureCounts["timeout"] ?? 0) } == 1
                    && roots.reduce(UInt64(0)) { $0 + ($1.failureCounts["capacity"] ?? 0) } == 1,
                    "cache/refusal final reasons changed")
        try require(harness.peers.isEmpty, "cache/refusal path started I/O")
    }

    private static func omittedWaitersRemainCounted() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), harness = Harness()
        let coordinator = DNSQueryCoordinator(maximumWaitersPerQuery: 96, diagnostics: diagnostics)
        var ids: [UUID] = []
        for index in UInt16(1)...80 {
            ids.append(coordinator.resolve(scope: "large-merge-policy", query: query(index), callbackQueue: callbacks,
                permitted: { true }, factory: harness.factory, completion: { _ in }))
        }
        _ = coordinator.statistics
        for id in ids.suffix(16) { coordinator.cancel(id) }
        _ = coordinator.statistics; callbacks.sync {}
        harness.peers.first?.reply(); _ = coordinator.statistics; callbacks.sync {}
        let roots = diagnostics.snapshot().dnsLogicalQueries
        try require(roots.count == 1 && roots[0].waiters.count == 64 && roots[0].omittedWaiters == 16
                    && roots[0].admittedCount == 80 && roots[0].mergedCount == 79
                    && roots[0].finishedCount == 80 && roots[0].outcomeCounts["success"] == 64
                    && roots[0].outcomeCounts["cancelled"] == 16,
                    "bounded waiter detail dropped aggregate completion counts")
        for id in ids.suffix(16) { coordinator.cancel(id) }
        harness.peers.first?.reply(); _ = coordinator.statistics; callbacks.sync {}
        try require(diagnostics.snapshot().dnsLogicalQueries == roots,
                    "late omitted-waiter completion escaped coordinator at-most-once fence")
    }

    private static func fallbackContextAndDeadline() throws {
        let context = DNSQueryExecutionContext(), lock = NSLock()
        var encryptedPeer: Peer?, sequence: DNSProxyFallbackResolverSequence?, fallbackPeers: [Peer] = []
        var phaseDeadlines: [TimeInterval] = [], candidateDeadlines: [TimeInterval] = [], replies = 0, failures = 0
        let schedule: DNSProxyFallbackQueryDatagram.Schedule = { _, _, _ in {} }
        let selector = DNSAdaptiveUpstreamSelector(clock: { 100 }, probeInterval: 3600, probeEvery: 1024)
        let parent = DNSProxyFallbackQueryDatagram(queue: .global(qos: .userInitiated),
            absoluteDeadline: 108, permitted: { true }, knownMilliseconds: { [] },
            encrypted: { _, deadline, receive, failure in
                let peer = Peer(receive: receive, failure: failure)
                lock.lock(); phaseDeadlines.append(deadline); encryptedPeer = peer; lock.unlock(); return peer
            }, fallback: { queue, deadline, receive, failure in
                let value = DNSProxyFallbackResolverSequence(
                    servers: [DNSProxyFallbackServer("203.0.113.60")!, DNSProxyFallbackServer("203.0.113.61")!],
                    selector: selector, scopeKey: "private-fallback-policy", queue: queue,
                    absoluteDeadline: deadline, permitted: { true },
                    factory: { _, _, childDeadline, receive, failure in
                        let peer = Peer(receive: receive, failure: failure)
                        lock.lock(); candidateDeadlines.append(childDeadline); fallbackPeers.append(peer); lock.unlock(); return peer
                    }, receive: receive, failure: failure, clock: { 100 }, schedule: schedule,
                    diagnostics: NetworkPerformanceDiagnostics())
                lock.lock(); phaseDeadlines.append(deadline); sequence = value; lock.unlock(); return value
            }, receive: { _ in lock.lock(); replies += 1; lock.unlock() },
            failure: { _ in lock.lock(); failures += 1; lock.unlock() }, clock: { 100 }, schedule: schedule,
            diagnostics: NetworkPerformanceDiagnostics())
        func settle() {
            for _ in 0..<8 {
                parent.drainQueueForSelfTest()
                lock.lock(); let child = sequence; lock.unlock(); child?.drainQueueForSelfTest()
            }
        }
        parent.setDNSQueryExecutionContext(context)
        parent.send(query(0x7352)); settle()
        parent.setDNSQueryExecutionContext(DNSQueryExecutionContext())
        lock.lock(); let first = encryptedPeer; lock.unlock()
        try require(first?.contextAtSend?.rootID == context.rootID, "encrypted phase lost root")
        first?.fail(); settle()
        lock.lock(); let second = fallbackPeers.first; let child = sequence; lock.unlock()
        try require(second?.contextAtSend?.rootID == context.rootID, "fallback phase lost root")
        child?.setDNSQueryExecutionContext(DNSQueryExecutionContext())
        second?.fail(); settle()
        lock.lock(); let peers = fallbackPeers; let deadlines = phaseDeadlines; let physicalDeadlines = candidateDeadlines; lock.unlock()
        let contexts = ([first].compactMap { $0 } + peers).compactMap(\.contextAtSend)
        try require(contexts.count == 3 && contexts.allSatisfy { $0.rootID == context.rootID }
                    && Set(contexts.map(\.candidateID)).count == 3, "candidates reused context or changed root after send")
        try require(deadlines == [108, 108] && physicalDeadlines.count == 2
                    && physicalDeadlines.allSatisfy { $0 > 100 && $0 <= 108 }, "fallback extended parent absolute deadline")
        peers.last?.reply(); settle()
        lock.lock(); let result = (replies, failures); lock.unlock()
        try require(result.0 == 1 && result.1 == 0, "fallback answer/terminal behavior changed")
    }

    static func main() throws {
        try mergedRootAndWaiterOutcomes()
        try noIOFinalOutcomes()
        try omittedWaitersRemainCounted()
        try fallbackContextAndDeadline()
        print("DNS logical lineage passed: 32/80 merged waiters, mixed final outcomes, bounded detail with full counts, late callback fence, cache/refusal roots, unique fallback candidates, original deadline, private payload exclusion")
        try DNSQueryCoordinatorSelfTest.run()
        try DNSProxyFallbackSelfTest.runNarrow()
        try DNSFallbackDeadlineHealthSelfTest.run()
    }
}

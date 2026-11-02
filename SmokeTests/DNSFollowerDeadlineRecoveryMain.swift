import Foundation

/// Memory peers expose an explicitly released owner-queue fence. No native
/// socket cancellation receipt or network response is synthesized by this test.
@main enum DNSFollowerDeadlineRecoveryMain {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { "DNS follower recovery check failed: \(message)" }
    }
    private static func require(_ value: Bool, _ message: String) throws {
        if !value { throw Failure(message: message) }
    }
    private static let callbacks = DispatchQueue(label: "app.hajimi.dns.follower-check.callbacks")
    private static func now() -> TimeInterval { ProcessInfo.processInfo.systemUptime }
    private static func query(_ id: UInt16) -> Data {
        DNSMessageInspection.query(for: "private-follower.example.test", type: 1, id: id)!
    }
    private static func answer(_ query: Data, rcode: UInt8 = 0, suffix: UInt8 = 7) -> Data {
        let end = DNSMessageInspection.singleQuestion(in: query)!.questionEnd
        var response = Data(query.prefix(end)); response[2] = 0x81; response[3] = 0x80 | rcode
        for index in 6...11 { response[index] = 0 }
        if rcode == 0 {
            response[7] = 1
            response.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, suffix])
        }
        return response
    }
    private final class Ledger {
        struct Receipt { let label: String, response: Data?, at: TimeInterval }
        private let condition = NSCondition()
        private var values: [Receipt] = []
        var receipts: [Receipt] { condition.lock(); defer { condition.unlock() }; return values }
        func callback(_ label: String) -> (Data?) -> Void {
            { response in
                self.condition.lock(); self.values.append(Receipt(label: label, response: response, at: now()))
                self.condition.broadcast(); self.condition.unlock()
            }
        }
        func wait(_ label: String) throws -> Receipt {
            condition.lock(); defer { condition.unlock() }
            let limit = Date(timeIntervalSinceNow: 3)
            while !values.contains(where: { $0.label == label }) {
                if !condition.wait(until: limit) { throw Failure(message: "missing callback \(label)") }
            }
            return values.first { $0.label == label }!
        }
    }
    private final class Peer: NativeRoutedDatagram, DNSQueryDeadlineAcknowledging, DNSQueryCancellationAcknowledging,
                              DNSQueryExecutionContextAccepting {
        let owner: String
        private let receive: (Data) -> Void, failure: (Error) -> Void
        private let lock = NSLock(), reached = DispatchSemaphore(value: 0)
        private var message: Data?, context: DNSQueryExecutionContext?
        private var acknowledgements: [(DNSProxyFallbackBarrier?) -> Void] = []
        private var deadlines = 0, cancels = 0
        init(owner: String, receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            self.owner = owner; self.receive = receive; self.failure = failure
        }
        func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
            lock.lock(); self.context = context; lock.unlock()
        }
        func send(_ data: Data) { lock.lock(); message = data; lock.unlock() }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); cancels += 1; lock.unlock(); completion()
        }
        func queryDeadlineReached() { queryDeadlineReached(completion: { _ in }) }
        func queryDeadlineReached(completion: @escaping (DNSProxyFallbackBarrier?) -> Void) {
            lock.lock(); deadlines += 1; acknowledgements.append(completion); lock.unlock(); reached.signal()
        }
        func waitForDeadline() throws {
            try require(reached.wait(timeout: .now() + 3) == .success, "owner deadline did not reach \(owner)")
        }
        func acknowledge(_ barrier: DNSProxyFallbackBarrier? = nil) {
            lock.lock(); let callbacks = acknowledgements; acknowledgements.removeAll(); lock.unlock()
            callbacks.forEach { $0(barrier) }
        }
        var query: Data? { lock.lock(); defer { lock.unlock() }; return message }
        var rootID: UUID? { lock.lock(); defer { lock.unlock() }; return context?.rootID }
        var candidateID: UUID? { lock.lock(); defer { lock.unlock() }; return context?.candidateID }
        var deadlineCount: Int { lock.lock(); defer { lock.unlock() }; return deadlines }
        var cancelCount: Int { lock.lock(); defer { lock.unlock() }; return cancels }
        func reply(rcode: UInt8 = 0, suffix: UInt8 = 7) { if let query { receive(answer(query, rcode: rcode, suffix: suffix)) } }
        func invalidReply() { if var response = query.map({ answer($0) }) { response[1] ^= 1; receive(response) } }
        func fail(_ error: Error) { failure(error) }
    }
    private final class Harness {
        private let lock = NSLock()
        private var values: [Peer] = []
        var peers: [Peer] { lock.lock(); defer { lock.unlock() }; return values }
        func factory(_ owner: String, deadline: TimeInterval) -> DNSQueryCoordinator.Factory {
            { _, receive, failure in
                // Production factories capture the caller's original deadline;
                // a replacement using the expired leader's factory must fail.
                guard now() < deadline else { throw DNSQueryTimeoutError() }
                let peer = Peer(owner: owner, receive: receive, failure: failure)
                self.lock.lock(); self.values.append(peer); self.lock.unlock(); return peer
            }
        }
    }
    @discardableResult private static func add(_ coordinator: DNSQueryCoordinator, _ harness: Harness,
                                               _ ledger: Ledger, _ label: String, id: UInt16,
                                               deadline: TimeInterval, scope: String = "private-policy") -> UUID {
        coordinator.resolve(scope: scope, query: query(id), callbackQueue: callbacks,
            absoluteDeadline: deadline, permitted: { true }, factory: harness.factory(label, deadline: deadline),
            completion: ledger.callback(label))
    }
    private static func settle(_ coordinator: DNSQueryCoordinator) {
        _ = coordinator.statistics; callbacks.sync {}
    }
    private static func peer(_ harness: Harness, _ owner: String) throws -> Peer {
        guard let peer = harness.peers.first(where: { $0.owner == owner }), peer.query != nil else {
            throw Failure(message: "missing sent peer \(owner)")
        }
        return peer
    }

    private static func laterFollowerUsesOwnFactoryAndRoot() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
        let harness = Harness(), ledger = Ledger(), started = now()
        let leader = add(coordinator, harness, ledger, "old", id: 1, deadline: started + 0.14)
        let first = add(coordinator, harness, ledger, "short", id: 2, deadline: started + 0.85)
        let latest = add(coordinator, harness, ledger, "latest", id: 3, deadline: started + 1.2)
        settle(coordinator)
        let old = try peer(harness, "old"), root = old.rootID
        try old.waitForDeadline(); let expired = try ledger.wait("old"); settle(coordinator)
        try require(expired.response == nil && expired.at >= started + 0.13,
                    "original leader received a late answer or an early timeout")
        _ = add(coordinator, harness, ledger, "during-ack", id: 4, deadline: started + 1.0)
        settle(coordinator); old.reply(); settle(coordinator)
        try require(harness.peers.count == 1 && ledger.receipts.count == 1
                    && coordinator.statistics.pendingQueries == 1 && old.cancelCount == 0,
                    "a follower escaped the real deadline fence")
        old.acknowledge(); settle(coordinator)
        let replacement = try peer(harness, "latest")
        try require(harness.peers.count == 2 && replacement.rootID == root
                    && replacement.candidateID != old.candidateID && replacement.query == query(3),
                    "latest follower's factory/context/query did not sponsor the replacement")
        old.reply(suffix: 99); old.fail(EncryptedDNSQueryFailure.authentication); old.acknowledge()
        settle(coordinator)
        try require(ledger.receipts.count == 1 && coordinator.statistics.cacheHits == 0,
                    "old generation completed or cached a replacement")
        replacement.reply()
        for name in ["short", "latest", "during-ack"] {
            let receipt = try ledger.wait(name)
            try require(receipt.response?.last == 7, "late follower received the old generation's response")
        }
        settle(coordinator)
        let snapshot = diagnostics.snapshot(), roots = snapshot.dnsLogicalQueries
        try require(roots.count == 1 && roots[0].rootID == root && roots[0].admittedCount == 4
                    && roots[0].mergedCount == 3 && roots[0].finishedCount == 4
                    && roots[0].failureCounts["timeout"] == 1 && roots[0].outcomeCounts["success"] == 3
                    && roots[0].scheduling?.upstreamStartCount == 2,
                    "generation transfer duplicated logical query/waiter/failure metrics")
        try require(Set(roots[0].waiters.map(\.waiterID)).isSuperset(of: [leader, first, latest])
                    && snapshot.dnsQueries == 4 && snapshot.dnsMergedQueries == 3
                    && snapshot.dnsFailures == 1 && old.deadlineCount == 1,
                    "original waiter IDs, query counts or genuine deadline ownership changed")
    }

    private static func barriersAfterFenceRemainTerminal() throws {
        let cases: [(String, DNSProxyFallbackBarrier?, DNSQueryFailureReason?)] = [
            ("auth", .failure(EncryptedDNSQueryFailure.authentication), .authentication),
            ("capacity", .failure(EncryptedDNSQueryFailure.capacity), .capacity),
            ("policy", .failure(EncryptedDNSQueryFailure.policy), .configurationOrPolicy),
            ("invalid-snapshot", .answer(Data([0, 1])), .invalidResponse),
            ("refused", nil, .upstreamOrResponse),
            ("invalid-callback", nil, .invalidResponse),
        ]
        for (name, barrier, reason) in cases {
            let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
            let harness = Harness(), ledger = Ledger(), started = now()
            add(coordinator, harness, ledger, "old", id: 10, deadline: started + 0.08)
            add(coordinator, harness, ledger, "live", id: 11, deadline: started + 1)
            settle(coordinator); let old = try peer(harness, "old")
            try old.waitForDeadline(); _ = try ledger.wait("old")
            if name == "invalid-callback" { old.invalidReply(); settle(coordinator); old.acknowledge() }
            else if name == "refused" { old.acknowledge(.answer(answer(query(10), rcode: 5))) }
            else { old.acknowledge(barrier) }
            let live = try ledger.wait("live"); settle(coordinator)
            if name == "refused" {
                try require(live.response == answer(query(11), rcode: 5), "REFUSED was erased or response ID changed")
            } else { try require(live.response == nil, "denial returned an answer: \(name)") }
            try require(harness.peers.count == 1 && coordinator.statistics.pendingQueries == 0,
                        "deadline handoff retried a terminal barrier: \(name)")
            let counts = diagnostics.snapshot().dnsFailureReasons
            try require(counts[.timeout] == 1 && counts[reason!] == 1,
                        "deadline erased original barrier classification: \(name)")
        }
    }

    private static func fencedPositiveServesOnlyLiveCallerWithoutCache() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
        let harness = Harness(), ledger = Ledger(), started = now()
        add(coordinator, harness, ledger, "old", id: 20, deadline: started + 0.08)
        add(coordinator, harness, ledger, "live", id: 21, deadline: started + 1)
        settle(coordinator); let old = try peer(harness, "old")
        try old.waitForDeadline(); _ = try ledger.wait("old")
        old.acknowledge(.answer(answer(query(20))))
        try require(try ledger.wait("live").response == answer(query(21)), "fenced live follower response was lost")
        settle(coordinator)
        add(coordinator, harness, ledger, "fresh", id: 22, deadline: now() + 1)
        settle(coordinator)
        try require(harness.peers.count == 2 && coordinator.statistics.cacheHits == 0,
                    "retained old answer restarted its wire TTL in the cache")
        try peer(harness, "fresh").reply(); _ = try ledger.wait("fresh")
    }

    private static func emptyRetirementStillFencesNewCaller() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
        let harness = Harness(), ledger = Ledger(), started = now()
        add(coordinator, harness, ledger, "old", id: 30, deadline: started + 0.08)
        settle(coordinator); let old = try peer(harness, "old")
        try old.waitForDeadline(); _ = try ledger.wait("old"); settle(coordinator)
        try require(coordinator.statistics.pendingQueries == 1 && coordinator.statistics.waitingClients == 0,
                    "empty retirement released its key before the real child ACK")
        let cancelled = add(coordinator, harness, ledger, "cancel", id: 31, deadline: now() + 1)
        settle(coordinator); coordinator.cancel(cancelled); settle(coordinator)
        add(coordinator, harness, ledger, "new", id: 32, deadline: now() + 1)
        settle(coordinator)
        try require(harness.peers.count == 1 && coordinator.statistics.pendingQueries == 1,
                    "last waiter cancellation admitted I/O around the old barrier")
        old.acknowledge(.failure(EncryptedDNSQueryFailure.authentication))
        try require(try ledger.wait("new").response == nil, "new caller bypassed an admitted auth failure")
        settle(coordinator)
        try require(harness.peers.count == 1 && ledger.receipts.count == 2
                    && diagnostics.snapshot().dnsCancelledQueries == 1,
                    "empty retirement lost cancellation ownership or reopened the child")
    }

    private static func deadlinesRemainIndependentWhileAckWaits() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
        let harness = Harness(), ledger = Ledger(), started = now()
        add(coordinator, harness, ledger, "old", id: 40, deadline: started + 0.08)
        add(coordinator, harness, ledger, "short", id: 41, deadline: started + 0.16)
        add(coordinator, harness, ledger, "live", id: 42, deadline: started + 1)
        settle(coordinator); let old = try peer(harness, "old")
        try old.waitForDeadline(); _ = try ledger.wait("old"); let short = try ledger.wait("short")
        try require(short.response == nil && short.at >= started + 0.15,
                    "short follower inherited an old timeout or waited beyond its original timer")
        old.acknowledge(); settle(coordinator); try peer(harness, "live").reply()
        _ = try ledger.wait("live"); settle(coordinator)
        try require(ledger.receipts.count == 3 && diagnostics.snapshot().dnsFailureReasons == [.timeout: 2],
                    "ACK wait extended follower deadlines or duplicated outcomes")
    }

    private static func queuedGenerationRejoinsFifoWithOwnFactory() throws {
        let coordinator = DNSQueryCoordinator(maximumActiveUpstreams: 1, diagnostics: NetworkPerformanceDiagnostics())
        let harness = Harness(), ledger = Ledger(), started = now()
        add(coordinator, harness, ledger, "busy", id: 50, deadline: started + 2, scope: "busy")
        add(coordinator, harness, ledger, "expired-queued", id: 51, deadline: started + 0.08, scope: "shared")
        add(coordinator, harness, ledger, "ahead", id: 52, deadline: started + 2, scope: "ahead")
        add(coordinator, harness, ledger, "replacement", id: 53, deadline: started + 2, scope: "shared")
        settle(coordinator); _ = try ledger.wait("expired-queued"); settle(coordinator)
        try require(harness.peers.count == 1 && coordinator.statistics.queuedUpstreams == 2,
                    "unstarted generation expiry dialed around the FIFO limit")
        try peer(harness, "busy").reply(); _ = try ledger.wait("busy"); settle(coordinator)
        try require(harness.peers.map(\.owner) == ["busy", "ahead"], "replacement skipped older queued work")
        try peer(harness, "ahead").reply(); _ = try ledger.wait("ahead"); settle(coordinator)
        try require(harness.peers.map(\.owner) == ["busy", "ahead", "replacement"],
                    "queued expired leader's captured factory replaced the live follower's")
        try peer(harness, "replacement").reply(); _ = try ledger.wait("replacement")
    }

    private static func earlyTypedTimeoutKeepsExistingBehavior() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
        let harness = Harness(), ledger = Ledger(), started = now()
        add(coordinator, harness, ledger, "old", id: 60, deadline: started + 2)
        add(coordinator, harness, ledger, "follower", id: 61, deadline: started + 3)
        settle(coordinator); let old = try peer(harness, "old")
        old.fail(DNSQueryTimeoutError())
        _ = try ledger.wait("old"); _ = try ledger.wait("follower"); settle(coordinator)
        try require(harness.peers.count == 1 && old.deadlineCount == 0 && old.cancelCount == 1
                    && coordinator.statistics.pendingQueries == 0 && diagnostics.snapshot().dnsFailures == 2,
                    "an early typed timeout acquired a new budget or delayed existing failure delivery")
    }

    private static func retiredChildKeepsItsLogicalSlotUntilAck() throws {
        let coordinator = DNSQueryCoordinator(maximumActiveUpstreams: 1, diagnostics: NetworkPerformanceDiagnostics())
        let harness = Harness(), ledger = Ledger(), started = now()
        add(coordinator, harness, ledger, "old", id: 70, deadline: started + 0.08)
        add(coordinator, harness, ledger, "live", id: 71, deadline: started + 1)
        add(coordinator, harness, ledger, "other", id: 72, deadline: started + 1, scope: "other")
        settle(coordinator); let old = try peer(harness, "old")
        try old.waitForDeadline(); _ = try ledger.wait("old"); settle(coordinator)
        try require(harness.peers.count == 1 && coordinator.statistics.activeUpstreams == 1
                    && coordinator.statistics.queuedUpstreams == 1,
                    "an unacknowledged retired child released its logical slot")
        old.acknowledge(); settle(coordinator)
        try require(harness.peers.map(\.owner) == ["old", "other"], "retirement replacement bypassed older FIFO work")
        try peer(harness, "other").reply(); _ = try ledger.wait("other"); settle(coordinator)
        try peer(harness, "live").reply(); _ = try ledger.wait("live"); settle(coordinator)
        try require(coordinator.statistics.activeUpstreams == 0, "ACK-driven replacement leaked its logical slot")
    }

    private static func multipleGenuineGenerationsKeepOneLineage() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
        let harness = Harness(), ledger = Ledger(), started = now()
        add(coordinator, harness, ledger, "first", id: 80, deadline: started + 0.08)
        add(coordinator, harness, ledger, "second", id: 81, deadline: started + 0.28)
        settle(coordinator); let first = try peer(harness, "first")
        try first.waitForDeadline(); _ = try ledger.wait("first"); first.acknowledge(); settle(coordinator)
        let second = try peer(harness, "second")
        add(coordinator, harness, ledger, "third", id: 82, deadline: started + 1)
        settle(coordinator); try second.waitForDeadline(); _ = try ledger.wait("second")
        second.acknowledge(); settle(coordinator); let third = try peer(harness, "third")
        first.reply(suffix: 98); second.reply(suffix: 99); settle(coordinator)
        try require(ledger.receipts.count == 2 && third.rootID == first.rootID && third.rootID == second.rootID,
                    "an old generation revived a caller or changed root")
        third.reply(); _ = try ledger.wait("third"); settle(coordinator)
        let roots = diagnostics.snapshot().dnsLogicalQueries
        try require(harness.peers.count == 3 && roots.count == 1 && roots[0].admittedCount == 3
                    && roots[0].finishedCount == 3 && roots[0].mergedCount == 2
                    && roots[0].failureCounts["timeout"] == 2 && roots[0].scheduling?.upstreamStartCount == 3,
                    "multiple genuine generations duplicated logical counts or retried an old sponsor")
    }

    private static func shortLastFollowerCannotAdvanceGenerationDeadline() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
        let harness = Harness(), ledger = Ledger(), started = now()
        let leader = add(coordinator, harness, ledger, "old", id: 90, deadline: started + 1.5)
        add(coordinator, harness, ledger, "short", id: 91, deadline: started + 0.08)
        settle(coordinator); let old = try peer(harness, "old")
        coordinator.cancel(leader); settle(coordinator); _ = try ledger.wait("short"); settle(coordinator)
        try require(coordinator.statistics.pendingQueries == 0,
                    "an earlier follower's timer falsely retired a still-budgeted generation")
        add(coordinator, harness, ledger, "new", id: 92, deadline: now() + 1)
        settle(coordinator); let fresh = try peer(harness, "new")
        try require(fresh.rootID != old.rootID && diagnostics.snapshot().dnsLogicalQueries.count == 2,
                    "an early last-follower timeout sponsored a continuation of the old generation")
        old.acknowledge(); old.reply(suffix: 99); settle(coordinator)
        try require(ledger.receipts.count == 1, "an early canceled generation completed a new caller")
        fresh.reply(); _ = try ledger.wait("new")
    }

    static func main() throws {
        try laterFollowerUsesOwnFactoryAndRoot()
        try barriersAfterFenceRemainTerminal()
        try fencedPositiveServesOnlyLiveCallerWithoutCache()
        try emptyRetirementStillFencesNewCaller()
        try deadlinesRemainIndependentWhileAckWaits()
        try queuedGenerationRejoinsFifoWithOwnFactory()
        try earlyTypedTimeoutKeepsExistingBehavior()
        try retiredChildKeepsItsLogicalSlotUntilAck()
        try multipleGenuineGenerationsKeepOneLineage()
        try shortLastFollowerCannotAdvanceGenerationDeadline()
        print("DNS follower deadline recovery passed: original caller timers/factories/IDs/root, latest-deadline leader, real ACK fence including empty groups, terminal auth/capacity/policy/REFUSED/invalid barriers, retained positives without cache, FIFO and early-timeout compatibility")
    }
}

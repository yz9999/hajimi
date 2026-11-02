// Actual Coordinator -> Adaptive -> shared DoHResolver -> DoHRoutedDatagram.
// Both comparison cases keep the production 8-second deadline, global16,
// cold4, active16, at most two live attempts and at most three candidates.
// The metadata dialer and HTTP byte peers never create a socket.
private enum ProxyEngine {
    static var currentOutboundInterface: NWInterface? {
        preconditionFailure("Startup memory fixture attempted direct transport")
    }
}

private func startupSystemUptimeDeadline(_ deadline: DispatchTime) -> TimeInterval {
    let captured = DispatchTime.now().uptimeNanoseconds
    let uptime = ProcessInfo.processInfo.systemUptime
    let distance = deadline.uptimeNanoseconds >= captured
        ? Double(deadline.uptimeNanoseconds - captured)
        : -Double(captured - deadline.uptimeNanoseconds)
    return uptime + distance / 1_000_000_000
}

private extension DoHResolver {
    func startupDrain() { requests.drainQueueForSelfTest() }
    var startupPressure: (registered: Int, active: Int, waiting: Int, physical: Int) {
        requests.pressureForSelfTest
    }
    func startupDeadline(_ id: UUID) -> TimeInterval? {
        requests.originalDeadlineForSelfTest(id).map(startupSystemUptimeDeadline)
    }
    var startupAllDeadlines: [TimeInterval] { requests.startupAllDeadlines }
}

private extension EncryptedDNSRequestPool {
    var startupAllDeadlines: [TimeInterval] {
        lock.lock(); let values = Array(requests.values); lock.unlock()
        return values.map { startupSystemUptimeDeadline($0.originalDeadlineForSelfTest) }
    }
}

private extension DNSAdaptiveQueryDatagram {
    func startupDrain() { queue.sync {} }
    func startupPauseOwnTimer() { queue.sync { deadlineTimer?.cancel(); deadlineTimer = nil } }
    var startupCounters: (attempts: Int, live: Int, deadline: TimeInterval) {
        queue.sync { (attemptCount, active.count, deadline) }
    }
}

@main private enum DNSStartupSchedulingMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private static func now() -> TimeInterval { ProcessInfo.processInfo.systemUptime }
    private static var checks = 0
    private static func require(_ value: Bool, _ text: @autoclosure () -> String) throws {
        checks += 1
        if !value { throw Failure(text: text()) }
    }
    private static func until(_ text: @autoclosure () -> String, seconds: TimeInterval = 3,
                              _ body: () -> Bool) throws {
        let deadline = now() + seconds
        while !body() && now() < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.005))
        }
        try require(body(), text())
    }
    private static func query(_ index: Int, prefix: String = "startup") -> Data {
        DNSMessageInspection.query(for: "\(prefix)-\(index).fixture.invalid",
            type: [UInt16(1), 28, 65][index % 3], id: UInt16(0x5000 + index))!
    }
    private static func answer(_ query: Data) -> Data {
        let end = DNSMessageInspection.singleQuestion(in: query)!.questionEnd
        var response = Data(query.prefix(end)); response[2] = 0x81; response[3] = 0x80
        for index in 6...11 { response[index] = 0 }
        return response // Authenticated, matching NOERROR without a cacheable TTL.
    }

    private final class Peer: NativeOutboundByteStream {
        private let lock = NSLock()
        private let queue = DispatchQueue(label: "fixture.startup.http-peer")
        private var reader: ((Data?, Bool, Error?) -> Void)?
        private var buffered: Data?, lastQuery: Data?
        private var automaticDelay: TimeInterval?
        private var closed = false, pendingReply = false, writes = 0, lateReplies = 0
        private var ids: [UInt16] = []
        func automaticallyReply(after delay: TimeInterval) {
            lock.lock(); automaticDelay = delay; lock.unlock()
        }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            guard let boundary = data.range(of: Data("\r\n\r\n".utf8)) else {
                completion(Failure(text: "Real DoH request lacked HTTP headers")); return
            }
            let query = Data(data[boundary.upperBound...])
            guard DNSMessageInspection.singleQuestion(in: query) != nil else {
                completion(Failure(text: "Real DoH request lacked its original DNS question")); return
            }
            lock.lock()
            guard !closed else { lock.unlock(); completion(NativeOutboundError.cancelled); return }
            writes += 1; lastQuery = query
            ids.append(UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1]))
            let delay = automaticDelay
            if delay != nil { pendingReply = true }
            lock.unlock(); completion(nil)
            if let delay { queue.asyncAfter(deadline: .now() + delay) { [self] in reply(to: query) } }
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            if let buffered { self.buffered = nil; lock.unlock(); completion(buffered, false, nil); return }
            guard !closed, reader == nil else {
                lock.unlock(); completion(nil, true, NativeOutboundError.cancelled); return
            }
            reader = completion; lock.unlock()
        }
        func reply() {
            lock.lock(); let query = lastQuery; lock.unlock()
            if let query { reply(to: query) }
        }
        private func reply(to query: Data) {
            let response = answer(query)
            let wire = Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(response.count)\r\n\r\n".utf8) + response
            lock.lock(); pendingReply = false
            if closed { lateReplies += 1 }
            let callback = reader; reader = nil
            if callback == nil && !closed { buffered = wire }
            lock.unlock()
            // Deliberately deliver an already-scheduled reply after close.
            // Production tokens, rather than this fixture, must reject it.
            callback?(wire, false, nil)
        }
        func cancel() {
            lock.lock(); closed = true; buffered = nil
            let callback = pendingReply ? nil : reader
            if !pendingReply { reader = nil }
            lock.unlock(); callback?(nil, true, NativeOutboundError.cancelled)
        }
        var snapshot: (closed: Bool, writes: Int, late: Int, ids: [UInt16]) {
            lock.lock(); defer { lock.unlock() }; return (closed, writes, lateReplies, ids)
        }
    }

    private final class Dialer {
        private struct Dial {
            let complete: (Result<any NativeOutboundByteStream, Error>) -> Void
            let trace: DNSConnectionAttemptTrace
            var callbacks = 0, cancellations = 0
            var peer: Peer?
        }
        struct Snapshot {
            let opens: Int, pending: [Int], peak: Int, callbacks: [Int], cancellations: [Int], peers: [Peer]
            let traceIDs: [UUID]
        }
        private let lock = NSLock()
        private var dials: [Dial] = []
        private var peak = 0
        var value: MetadataAwareEncryptedDNSStreamDialer {
            { [self] _, _, _, _, trace, _, completion in
                trace.record(.transportStarted)
                lock.lock(); let index = dials.count
                dials.append(Dial(complete: completion, trace: trace))
                peak = max(peak, dials.filter { $0.callbacks == 0 }.count)
                lock.unlock()
                return { [self] in lock.lock(); dials[index].cancellations += 1; lock.unlock() }
            }
        }
        @discardableResult func succeed(_ index: Int) throws -> Peer {
            let peer = Peer()
            lock.lock()
            guard dials.indices.contains(index), dials[index].callbacks == 0 else {
                lock.unlock(); throw Failure(text: "Physical completion was absent or repeated at dial \(index)")
            }
            dials[index].callbacks += 1; dials[index].peer = peer
            let complete = dials[index].complete, trace = dials[index].trace
            lock.unlock()
            trace.record(.transportReady); trace.record(.tlsStarted); trace.record(.tlsReady)
            complete(.success(peer)); return peer
        }
        func timeout(_ index: Int) throws {
            lock.lock()
            guard dials.indices.contains(index), dials[index].callbacks == 0 else {
                lock.unlock(); throw Failure(text: "Native timeout callback was absent or repeated")
            }
            dials[index].callbacks += 1
            let complete = dials[index].complete, trace = dials[index].trace
            lock.unlock()
            trace.record(.transportFailure, error: EncryptedDNSQueryFailure.timeout)
            complete(.failure(EncryptedDNSQueryFailure.timeout))
        }
        var snapshot: Snapshot {
            lock.lock(); defer { lock.unlock() }
            return Snapshot(opens: dials.count, pending: dials.indices.filter { dials[$0].callbacks == 0 }, peak: peak,
                callbacks: dials.map(\.callbacks), cancellations: dials.map(\.cancellations),
                peers: dials.compactMap(\.peer), traceIDs: dials.map { $0.trace.id })
        }
    }

    private final class Owner {
        let dialer = Dialer(), budget = SOCKSUDPGlobalBudget(resources: 64, packets: 0, bytes: 0)
        let resolver: DoHResolver
        init(_ index: Int, localTimeout: DispatchTimeInterval = .seconds(8)) {
            resolver = DoHResolver(endpoint: DoHEndpoint("https://provider-\(index).fixture.invalid/dns-query#203.0.113.\(70 + index)")!,
                metadataStreamDialer: dialer.value, bootstrapTimeout: localTimeout, resourceBudget: budget)
        }
        func holdFourColdQueries() throws {
            // Real connection-only prewarming coalesces behind an existing
            // entry/dial. Distinct ordinary requests are required to occupy
            // all four genuine cold reservations without bypassing that rule.
            for index in 1000..<1004 { _ = resolver.resolve(query: query(index, prefix: "pressure"), completion: { _ in }) }
            try until("Held cold starts: expected=4, observed=\(dialer.snapshot.pending.count)") {
                self.dialer.snapshot.pending.count == 4
            }
            resolver.startupDrain()
        }
        func prepareFourWarmPeers() throws -> [Peer] {
            let book = Book()
            for index in 0..<4 {
                let message = query(index, prefix: "prepare")
                _ = resolver.resolve(query: message, completion: { book.record(index, query: message, answer: $0, deadline: now() + 8) })
            }
            try until("Warm preparation did not start exactly four cold dials") { self.dialer.snapshot.opens == 4 }
            var peers: [Peer] = []
            for index in 0..<4 { peers.append(try dialer.succeed(index)) }
            try until("Warm preparation did not send its four real HTTP requests") { peers.allSatisfy { $0.snapshot.writes == 1 } }
            try holdFourColdQueries() // Warm peers stay busy, so these consume four actual cold reservations.
            peers.forEach { $0.reply() }
            try until("Warm preparation responses did not complete") { book.count == 4 }
            try until("Warm availability: expected=4 reusable/0 cold, observed=\(resolver.schedulingAvailability)") {
                let value = self.resolver.schedulingAvailability; return value.reusable == 4 && value.cold == 0
            }
            peers.forEach { $0.automaticallyReply(after: 0.96) }
            return peers
        }
        func close() throws {
            resolver.cancel(); resolver.startupDrain()
            let pending = dialer.snapshot.pending
            try require(pending.allSatisfy { dialer.snapshot.cancellations[$0] == 1 },
                        "Pending native dial cancellation: expected exactly one request before physical ACK")
            for index in pending { _ = try dialer.succeed(index) }
            try until("Late physical success retained a stream or native reservation") {
                self.resolver.startupDrain()
                return self.budget.usage.resources == 0 && self.dialer.snapshot.peers.allSatisfy { $0.snapshot.closed }
            }
            try require(dialer.snapshot.callbacks.allSatisfy { $0 == 1 }, "Physical callback expected exactly once")
            try require(dialer.snapshot.cancellations.allSatisfy { $0 <= 1 }, "Native cancellation action repeated")
            try require(pending.allSatisfy { dialer.snapshot.peers[$0].snapshot.writes == 0 },
                        "Late physical success sent revoked HTTP/DNS bytes")
            try require(dialer.snapshot.peak <= 4, "Cold physical peak: expected<=4, observed=\(dialer.snapshot.peak)")
        }
        deinit { resolver.cancel() }
    }

    private final class Book {
        struct Receipt {
            let success: Bool, elapsed: TimeInterval, deadline: TimeInterval, delivered: TimeInterval
            let responseCode: UInt8?
        }
        private let lock = NSLock()
        private var receipts: [Int: [Receipt]] = [:]
        private var attempts: [Int: Int] = [:], live: [Int: Int] = [:], peaks: [Int: Int] = [:]
        private var roots = Set<UUID>()
        func record(_ index: Int, query: Data, answer: Data?, deadline: TimeInterval) {
            let received = now(), valid = answer.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true
            let code = answer.flatMap { $0.count >= 4 ? $0[$0.startIndex + 3] & 0x0f : nil }
            lock.lock(); receipts[index, default: []].append(Receipt(success: valid, elapsed: received - (deadline - 8),
                deadline: deadline, delivered: received, responseCode: code)); lock.unlock()
        }
        func began(_ index: Int) {
            lock.lock(); attempts[index, default: 0] += 1; live[index, default: 0] += 1
            peaks[index] = max(peaks[index, default: 0], live[index]!); lock.unlock()
        }
        func stopped(_ index: Int) { lock.lock(); live[index, default: 0] -= 1; lock.unlock() }
        func root(_ context: DNSQueryExecutionContext) { lock.lock(); roots.insert(context.rootID); lock.unlock() }
        var count: Int { lock.lock(); defer { lock.unlock() }; return receipts.values.reduce(0) { $0 + $1.count } }
        var snapshot: (receipts: [Int: [Receipt]], attempts: [Int: Int], live: [Int: Int], peaks: [Int: Int], roots: Set<UUID>) {
            lock.lock(); defer { lock.unlock() }; return (receipts, attempts, live, peaks, roots)
        }
    }

    private final class CountedFlow: NativeRoutedDatagram, DNSQueryCancellationAcknowledging,
        DNSQueryExecutionContextAccepting, DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding {
        private let flow: DoHRoutedDatagram, book: Book, index: Int
        private let lock = NSLock()
        private var stopped = false
        init(_ flow: DoHRoutedDatagram, book: Book, index: Int) {
            self.flow = flow; self.book = book; self.index = index; book.began(index)
        }
        func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
            book.root(context); flow.setDNSQueryExecutionContext(context)
        }
        func send(_ data: Data) { flow.send(data) }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) { cancel(reason: .callerCancelled, completion: completion) }
        func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
            lock.lock(); let first = !stopped; stopped = true; lock.unlock()
            if first { book.stopped(index) }
            flow.cancel(reason: reason, completion: completion)
        }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { flow.proxyFallbackBarrier() }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { flow.dnsQueryTransportEvidence() }
    }

    private static func startupBurst(availabilityEnabled: Bool) throws -> [String: Any] {
        let blocked = Owner(0), warm = Owner(1)
        defer { try? blocked.close(); try? warm.close() }
        try blocked.holdFourColdQueries()
        let peers = try warm.prepareFourWarmPeers()
        let diagnostics = NetworkPerformanceDiagnostics.shared
        diagnostics.reset()
        let coordinator = DNSQueryCoordinator(), selector = DNSAdaptiveUpstreamSelector(), book = Book()
        let callbacks = DispatchQueue(label: "fixture.startup.result")
        let candidates = (0..<2).map { index in
            DNSUpstreamCandidate(upstream: .doh(DoHEndpoint("https://provider-\(index).fixture.invalid/dns-query#203.0.113.\(70 + index)")!), bootstrap: nil)
        }
        let owners = [blocked, warm], scope = availabilityEnabled ? "available" : "legacy-order"
        var peakGlobal = 0
        for index in 0..<32 {
            let message = query(index), originalDeadline = now() + 8
            coordinator.resolve(scope: scope, query: message, callbackQueue: callbacks,
                absoluteDeadline: originalDeadline, permitted: { true }, factory: { queue, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector, scopeKey: scope,
                        queue: queue, permitted: { true }, factory: { candidate, _, receive, failure in
                            let owner = owners[candidates.firstIndex(where: { $0.id == candidate.id })!]
                            return CountedFlow(DoHRoutedDatagram(resolver: owner.resolver, receive: receive, failure: failure),
                                book: book, index: index)
                        }, receive: receive, failure: failure,
                        availability: availabilityEnabled ? { candidate in
                            owners[candidates.firstIndex(where: { $0.id == candidate.id })!].resolver.schedulingAvailability
                        } : nil,
                        absoluteDeadline: originalDeadline)
                }, completion: { book.record(index, query: message, answer: $0, deadline: originalDeadline) })
        }
        let initial = coordinator.statistics
        try require(initial.activeUpstreams == 16 && initial.queuedUpstreams == 16,
                    "Initial global queue: expected=16 active/16 queued, observed=\(initial.activeUpstreams)/\(initial.queuedUpstreams)")
        try until("Startup results: expected=32, observed=\(book.count)", seconds: 10) {
            peakGlobal = max(peakGlobal, coordinator.statistics.activeUpstreams)
            return book.count == 32
        }
        callbacks.sync {}
        try until("Completed adaptive children retained logical attempts") { book.snapshot.live.values.allSatisfy { $0 == 0 } }
        let ledger = book.snapshot, receipts = ledger.receipts.values.flatMap { $0 }, successes = receipts.filter(\.success)
        let state = coordinator.statistics, snapshot = diagnostics.snapshot()
        let roots = snapshot.dnsLogicalQueries.filter { ledger.roots.contains($0.rootID) }
        let exchanges = snapshot.dnsQueryExchanges.filter { $0.rootID.map(ledger.roots.contains) ?? false }
        let globallyQueued = roots.filter { ($0.scheduling?.maximumCoordinatorQueueMilliseconds ?? 0) >= 500 }
        let locallyQueued = exchanges.filter { ($0.resolverQueueMilliseconds ?? 0) >= 100
            && ($0.resolverQueueReasons ?? []).contains(.coldConnectionLimit) }
        let doubleQueuedRoots = Set(globallyQueued.map(\.rootID)).intersection(locallyQueued.compactMap(\.rootID))
        try require(Set(ledger.receipts.keys) == Set(0..<32) && ledger.receipts.values.allSatisfy { $0.count == 1 },
                    "Logical results expected exactly one callback for IDs 0..<32")
        try require(successes.allSatisfy { $0.delivered < $0.deadline }, "A success was delivered after its original 8-second deadline")
        try require(peakGlobal <= 16 && state.activeUpstreams == 0 && state.pendingQueries == 0 && state.queuedUpstreams == 0,
                    "Global bound/cleanup: peak=\(peakGlobal), pending=\(state.pendingQueries), active=\(state.activeUpstreams)")
        try require(ledger.peaks.values.allSatisfy { $0 <= 2 } && ledger.attempts.values.allSatisfy { $0 <= 3 },
                    "Adaptive bound: peaks=\(ledger.peaks), attempts=\(ledger.attempts)")
        try require(globallyQueued.count >= 16 && !locallyQueued.isEmpty && !doubleQueuedRoots.isEmpty,
                    "Missing actual double-queue evidence: global=\(globallyQueued.count), local=\(locallyQueued.count), shared=\(doubleQueuedRoots.count)")
        try require(blocked.dialer.snapshot.opens == 4 && warm.dialer.snapshot.opens == 8
                    && blocked.dialer.snapshot.pending.count == 4 && warm.dialer.snapshot.pending.count == 4,
                    "Queued attempts created extra cold dials or released pending physical ACKs")
        try require(exchanges.filter { !$0.reusedConnection }.allSatisfy { $0.physicalAttemptIDs.isEmpty },
                    "A purely queued candidate invented physical transport evidence")
        try require(selector.knownLatencyMilliseconds(scopeKey: scope, candidateID: candidates[0].id) == nil
                    && selector.schedulingPriority(scopeKey: scope, candidateID: candidates[0].id) == 1,
                    "Local-only waiting fabricated a provider success or cooldown penalty")
        let failures = receipts.count - successes.count
        if availabilityEnabled {
            try require(successes.count == 32 && failures == 0,
                        "Availability-aware startup: expected=32 success/0 failure, observed=\(successes.count)/\(failures)")
        } else {
            try require(successes.count > 0 && failures >= 4,
                        "Before startup characterization: expected partial original-deadline failures>=4, observed=\(successes.count) success/\(failures) failure")
            try require(roots.reduce(UInt64(0)) { $0 + ($1.failureCounts["timeout"] ?? 0) } == UInt64(failures),
                        "Before failures were not classified as their original logical timeouts")
        }
        let beforeLate = book.count
        try blocked.close(); try warm.close()
        try until("Before's already-scheduled late HTTP replies did not reach their callback fence", seconds: 2) {
            availabilityEnabled || peers.reduce(0) { $0 + $1.snapshot.late } >= min(peers.count, failures)
        }
        callbacks.sync {}
        try require(book.count == beforeLate && coordinator.statistics.cacheHits == 0,
                    "Late data/native ACK duplicated a caller or revived cache state")
        return ["availabilityEnabled": availabilityEnabled, "queries": receipts.count, "success": successes.count,
            "failure": failures, "originalDeadlineMilliseconds": 8000, "maximumSuccessfulMilliseconds":
                (successes.map(\.elapsed).max() ?? 0) * 1000,
            "globalPeak": peakGlobal, "globallyQueuedRoots": globallyQueued.count,
            "locallyQueuedExchanges": locallyQueued.count, "doubleQueuedRoots": doubleQueuedRoots.count,
            "coldPeaks": owners.map { $0.dialer.snapshot.peak }, "physicalDials": owners.map { $0.dialer.snapshot.opens },
            "maximumRootAttempts": ledger.attempts.values.max() ?? 0, "maximumRootLive": ledger.peaks.values.max() ?? 0]
    }

    private static func contextDeadlinePropagation() throws {
        let owner = Owner(2)
        defer { try? owner.close() }
        let deadline = now() + 0.25
        let context = DNSQueryExecutionContext(absoluteDeadline: deadline)
        try require(context.child().absoluteDeadline == context.absoluteDeadline, "Child context lost its inherited original deadline")
        let message = query(100), book = Book()
        let id = owner.resolver.resolveResult(query: message, completion: { result in
            let response: Data?; if case .success(let value) = result { response = value } else { response = nil }
            book.record(100, query: message, answer: response, deadline: deadline)
        }, executionContext: context.child())
        guard let id else { throw Failure(text: "Context deadline query was not registered") }
        try until("Context deadline query did not start its controlled physical dial") { owner.dialer.snapshot.opens == 1 }
        guard let actual = owner.resolver.startupDeadline(id) else { throw Failure(text: "Missing endpoint's original deadline") }
        try require(abs(actual - deadline) < 0.003,
                    "Endpoint deadline propagation: expected≈\(deadline), observed=\(actual)")
        try until("Endpoint restarted an inherited 250ms deadline", seconds: 1) { book.count == 1 }
        try require(book.snapshot.receipts[100]?.first?.success == false, "Held endpoint accepted an answer without TLS readiness")
        try owner.close()
        try require(book.count == 1, "Late native context-deadline ACK repeated logical completion")
    }

    private static func earliestEndpointDeadline() throws {
        let owner = Owner(3)
        defer { try? owner.close() }
        try owner.holdFourColdQueries()
        let shared = now() + 1, later = now() + 2
        let book = Book()
        var contexts: [Int: DNSQueryExecutionContext] = [:]
        for (index, deadline) in [(200, later), (201, shared), (202, shared)] {
            let message = query(index), context = DNSQueryExecutionContext(absoluteDeadline: deadline)
            contexts[index] = context
            _ = owner.resolver.resolveResult(query: message, completion: { result in
                let response: Data?; if case .success(let value) = result { response = value } else { response = nil }
                book.record(index, query: message, answer: response, deadline: deadline)
            }, executionContext: context)
        }
        owner.resolver.startupDrain()
        try require(owner.dialer.snapshot.opens == 4, "Deadline-order requests bypassed cold4 before a physical ACK")
        _ = try owner.dialer.succeed(0) // Its pressure query remains busy; one real cold receipt becomes available.
        try until("Earliest endpoint request did not receive the next cold reservation") { owner.dialer.snapshot.opens == 5 }
        let firstTrace = owner.dialer.snapshot.traceIDs[4]
        let firstRoot = NetworkPerformanceDiagnostics.shared.snapshot().dnsConnectionAttempts.first { $0.id == firstTrace }?.rootID
        try require(firstRoot == contexts[201]?.rootID,
                    "Earliest endpoint order: expected first early root=\(contexts[201]!.rootID), observed=\(String(describing: firstRoot))")
        let first = try owner.dialer.succeed(4)
        try until("Earliest endpoint request did not send its original HTTP/DNS payload") { first.snapshot.writes == 1 }
        try require(first.snapshot.ids == [UInt16(0x5000 + 201)],
                    "Earliest endpoint send: expected ID=\(0x5000 + 201), observed=\(first.snapshot.ids)")
        try until("Equal-deadline endpoint request did not receive its FIFO cold reservation") { owner.dialer.snapshot.opens == 6 }
        let secondTrace = owner.dialer.snapshot.traceIDs[5]
        let nextRoot = NetworkPerformanceDiagnostics.shared.snapshot().dnsConnectionAttempts.first { $0.id == secondTrace }?.rootID
        try require(nextRoot == contexts[202]?.rootID,
                    "Equal-deadline FIFO: expected second early root=\(contexts[202]!.rootID), observed=\(String(describing: nextRoot))")
        try owner.close()
        try require(book.count == 3 && book.snapshot.receipts.values.allSatisfy { $0.count == 1 },
                    "Deadline-priority cleanup lost exactly-once queued callers")
    }

    private static func coordinatorContextDeadline() throws {
        let owner = Owner(4), coordinator = DNSQueryCoordinator(), book = Book()
        defer { try? owner.close() }
        let message = query(300), deadline = now() + 0.25
        let candidate = DNSUpstreamCandidate(upstream: .doh(DoHEndpoint("https://deadline.fixture.invalid/dns-query#203.0.113.74")!), bootstrap: nil)
        coordinator.resolve(scope: "inherited-deadline", query: message,
            callbackQueue: DispatchQueue(label: "fixture.startup.deadline-result"), absoluteDeadline: deadline,
            permitted: { true }, factory: { queue, receive, failure in
                // No absoluteDeadline argument below: the actual coordinator
                // execution context must cap both Adaptive and endpoint.
                DNSAdaptiveQueryDatagram(candidates: [candidate], selector: DNSAdaptiveUpstreamSelector(),
                    scopeKey: "inherited-deadline", queue: queue, permitted: { true },
                    factory: { _, _, receive, failure in
                        DoHRoutedDatagram(resolver: owner.resolver, receive: receive, failure: failure)
                    }, receive: receive, failure: failure)
            }, completion: { book.record(300, query: message, answer: $0, deadline: deadline) })
        try until("Coordinator context did not reach the endpoint physical-dial path") { owner.dialer.snapshot.opens == 1 }
        let deadlines = owner.resolver.startupAllDeadlines
        try require(deadlines.count == 1 && abs(deadlines[0] - deadline) < 0.003,
                    "Coordinator -> Adaptive -> endpoint deadline: expected≈\(deadline), observed=\(deadlines)")
        try until("Coordinator context deadline restarted at an inner layer", seconds: 1) { book.count == 1 }
        try require(book.snapshot.receipts[300]?.first?.success == false,
                    "Held inherited-deadline query invented a successful DNS answer")
        try owner.close()
        try require(book.count == 1 && coordinator.statistics.activeUpstreams == 0,
                    "Inherited deadline ACK repeated a caller or retained a global slot")
    }

    private final class Permission {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }
    private static func revokedPermissionAndLateACK() throws {
        let owner = Owner(5), permission = Permission(), book = Book(), cache = DNSQueryCache()
        let coordinator = DNSQueryCoordinator(cache: cache)
        defer { try? owner.close() }
        let candidate = DNSUpstreamCandidate(upstream: .doh(DoHEndpoint("https://permission.fixture.invalid/dns-query#203.0.113.75")!), bootstrap: nil)
        let callbacks = DispatchQueue(label: "fixture.startup.permission-results")
        func submit(_ index: Int) {
            let message = query(index), deadline = now() + 8
            coordinator.resolve(scope: "revocable-policy", query: message, callbackQueue: callbacks,
                absoluteDeadline: deadline, permitted: permission.permits,
                factory: { queue, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: [candidate], selector: DNSAdaptiveUpstreamSelector(),
                        scopeKey: "revocable-policy", queue: queue, permitted: permission.permits,
                        factory: { _, _, receive, failure in
                            CountedFlow(DoHRoutedDatagram(resolver: owner.resolver, receive: receive, failure: failure),
                                book: book, index: index)
                        }, receive: receive, failure: failure,
                        availability: { _ in owner.resolver.schedulingAvailability })
                }, completion: { book.record(index, query: message, answer: $0, deadline: deadline) })
        }
        submit(400)
        try until("Revocation fixture did not begin its one controlled physical dial") { owner.dialer.snapshot.opens == 1 }
        permission.revoke(); coordinator.invalidate(); submit(401)
        try until("Revocation did not finish original and pre-admission callers") { book.count == 2 }
        try require(owner.dialer.snapshot.opens == 1 && owner.dialer.snapshot.pending == [0],
                    "Logical policy cleanup released a native slot before its physical ACK")
        try owner.close(); callbacks.sync {}
        try require(book.count == 2 && book.snapshot.receipts.values.allSatisfy { $0.count == 1 && !$0[0].success }
                    && cache.usage.entries == 0 && coordinator.statistics.pendingQueries == 0,
                    "Late physical success revived permission, cache state or a completed caller")
    }

    // These short cases exercise real Adaptive decisions with an inert memory
    // datagram. They do not duplicate its ranking or change its timer budget.
    private final class OrderPeer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging,
        DNSQueryTransportEvidenceProviding {
        let receive: (Data) -> Void, failure: (Error) -> Void
        private var message: Data?
        init(receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            self.receive = receive; self.failure = failure
        }
        func send(_ data: Data) { message = data }
        func cancel() {}
        func cancel(completion: @escaping () -> Void) { completion() }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { .notStarted }
        func fail() { failure(EncryptedDNSQueryFailure.network) }
        func respond(code: UInt8) {
            guard let message else { return }
            var response = answer(message); response[3] = 0x80 | code; receive(response)
        }
    }
    private final class OrderProbe {
        private let lock = NSLock()
        private var values: [(String, OrderPeer)] = []
        func make(_ id: String, receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) -> OrderPeer {
            let peer = OrderPeer(receive: receive, failure: failure)
            lock.lock(); values.append((id, peer)); lock.unlock(); return peer
        }
        var snapshot: [(String, OrderPeer)] { lock.lock(); defer { lock.unlock() }; return values }
    }
    private static func availabilityOrderingBoundaries() throws -> Int {
        let encrypted = (0..<4).map { index in
            DNSUpstreamCandidate(upstream: .doh(DoHEndpoint("https://order-\(index).fixture.invalid/dns-query#203.0.113.\(80 + index)")!), bootstrap: nil)
        }
        let ids = encrypted.map(\.id)
        var groups = 0
        func run(_ label: String, candidates: [DNSUpstreamCandidate] = encrypted,
                 selector: DNSAdaptiveUpstreamSelector = DNSAdaptiveUpstreamSelector(probeInterval: 3600),
                 hints: [String: (reusable: Int, cold: Int)], expected: String,
                 plaintextApproved: Bool = false) throws {
            let probe = OrderProbe()
            let flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector, scopeKey: label,
                queue: DispatchQueue(label: "fixture.startup.order.\(label)"), permitted: { true },
                factory: { candidate, _, receive, failure in probe.make(candidate.id, receive: receive, failure: failure) },
                receive: { _ in }, failure: { _ in }, availability: { hints[$0.id] },
                allowApprovedProxyPlaintext: plaintextApproved)
            defer { flow.cancel() }
            flow.send(query(500)); flow.startupDrain()
            try require(probe.snapshot.first?.0 == expected,
                        "\(label): expected first=\(expected), observed=\(probe.snapshot.map { $0.0 })")
            try require(flow.startupCounters.attempts == 1 && flow.startupCounters.live == 1,
                        "\(label): initial availability choice expanded attempts")
            groups += 1
        }
        try run("unknown-warm", hints: [ids[0]: (0, 4), ids[1]: (4, 0)], expected: ids[1])
        try run("local-cold-pressure", hints: [ids[0]: (0, 0), ids[1]: (0, 1)], expected: ids[1])
        try run("nil-hint-available-alternate", hints: [ids[1]: (0, 1)], expected: ids[1])
        try run("unavailable-stable-order", hints: Dictionary(uniqueKeysWithValues: ids.map { ($0, (0, 0)) }), expected: ids[0])
        let healthy = DNSAdaptiveUpstreamSelector(probeInterval: 3600)
        _ = healthy.orderedCandidates(scopeKey: "healthy-before-unknown-warm", candidateIDs: ids)
        healthy.record(scopeKey: "healthy-before-unknown-warm", candidateID: ids[0], milliseconds: 50, success: true)
        try run("healthy-before-unknown-warm", selector: healthy, hints: [ids[0]: (0, 0), ids[1]: (4, 0)], expected: ids[0])
        let cooling = DNSAdaptiveUpstreamSelector(probeInterval: 3600)
        _ = cooling.orderedCandidates(scopeKey: "cooldown-not-promoted", candidateIDs: ids)
        cooling.record(scopeKey: "cooldown-not-promoted", candidateID: ids[1], milliseconds: 50, success: false)
        try run("cooldown-not-promoted", selector: cooling, hints: [ids[0]: (0, 0), ids[1]: (4, 0)], expected: ids[0])
        var probeTime: TimeInterval = 100
        let exploring = DNSAdaptiveUpstreamSelector(clock: { probeTime }, probeInterval: 0.1, probeEvery: 2)
        _ = exploring.orderedCandidates(scopeKey: "explicit-exploration", candidateIDs: ids)
        exploring.record(scopeKey: "explicit-exploration", candidateID: ids[0], milliseconds: 20, success: true)
        probeTime = 101
        try run("explicit-exploration", selector: exploring, hints: [ids[0]: (4, 0), ids[1]: (0, 0)], expected: ids[1])
        let plain = DNSUpstreamCandidate(upstream: .plain(host: "203.0.113.90", port: 53), bootstrap: nil)
        try run("encrypted-phase-retained", candidates: [encrypted[0], plain],
                hints: [ids[0]: (0, 0), plain.id: (4, 0)], expected: ids[0], plaintextApproved: true)
        try run("approved-plain-phase-retained", candidates: [plain, encrypted[0]],
                hints: [plain.id: (0, 0), ids[0]: (4, 0)], expected: plain.id, plaintextApproved: true)
        let mixedProbe = OrderProbe()
        let mixed = DNSAdaptiveQueryDatagram(candidates: [encrypted[0], plain, encrypted[1]],
            selector: DNSAdaptiveUpstreamSelector(probeInterval: 3600), scopeKey: "mixed-positions",
            queue: DispatchQueue(label: "fixture.startup.mixed-positions"), permitted: { true },
            factory: { candidate, _, receive, failure in mixedProbe.make(candidate.id, receive: receive, failure: failure) },
            receive: { _ in }, failure: { _ in }, availability: { $0.id == ids[1] ? (4, 0) : (0, 0) },
            allowApprovedProxyPlaintext: true)
        mixed.send(query(503)); mixed.startupDrain()
        try require(mixedProbe.snapshot.first?.0 == ids[1], "Mixed-mode warm approved encrypted candidate was not eligible")
        mixedProbe.snapshot[0].1.fail(); mixed.startupDrain()
        try require(mixedProbe.snapshot.count == 2 && mixedProbe.snapshot[1].0 == plain.id,
                    "Moving a warm encrypted candidate changed the approved encrypted/plain category positions")
        mixed.cancel(); groups += 1
        let limited = OrderProbe()
        let flow = DNSAdaptiveQueryDatagram(candidates: encrypted, selector: DNSAdaptiveUpstreamSelector(probeInterval: 3600),
            scopeKey: "fourth-excluded", queue: DispatchQueue(label: "fixture.startup.prefix-three"), permitted: { true },
            factory: { candidate, _, receive, failure in limited.make(candidate.id, receive: receive, failure: failure) },
            receive: { _ in }, failure: { _ in }, availability: { $0.id == ids[3] ? (4, 0) : (0, 0) })
        flow.send(query(501)); flow.startupDrain()
        for index in 0..<3 {
            try require(limited.snapshot.count == index + 1, "Prefix3 lost an approved attempt")
            limited.snapshot[index].1.fail(); flow.startupDrain()
        }
        try require(limited.snapshot.map { $0.0 } == Array(ids.prefix(3)) && flow.startupCounters.attempts == 3
                    && flow.startupCounters.live == 0,
                    "Warm fourth candidate escaped the preselected three-attempt allowance")
        flow.cancel(); groups += 1
        let services = [
            DNSUpstreamCandidate(upstream: .doh(DoHEndpoint("https://cloudflare-dns.com/dns-query#1.1.1.1")!), bootstrap: nil),
            DNSUpstreamCandidate(upstream: .doh(DoHEndpoint("https://cloudflare-dns.com/dns-query#2606:4700:4700::1111")!), bootstrap: nil),
            DNSUpstreamCandidate(upstream: .doh(DoHEndpoint("https://dns.google/dns-query#8.8.8.8")!), bootstrap: nil),
        ]
        let diversity = OrderProbe()
        let diverse = DNSAdaptiveQueryDatagram(candidates: services, selector: DNSAdaptiveUpstreamSelector(probeInterval: 3600),
            scopeKey: "servfail-diversity", queue: DispatchQueue(label: "fixture.startup.servfail"), permitted: { true },
            factory: { candidate, _, receive, failure in diversity.make(candidate.id, receive: receive, failure: failure) },
            receive: { _ in }, failure: { _ in }, availability: { $0.id == services[2].id ? (0, 1) : (4, 0) })
        defer { diverse.cancel() }
        diverse.send(query(502)); diverse.startupDrain()
        try require(diversity.snapshot.first?.0 == services[0].id, "SERVFAIL fixture did not begin on Cloudflare IPv4")
        diversity.snapshot[0].1.respond(code: 2); diverse.startupDrain()
        try require(diversity.snapshot.count == 2 && diversity.snapshot[1].0 == services[2].id,
                    "Warm same-service IPv6 overrode SERVFAIL cross-provider priority")
        diversity.snapshot[1].1.fail(); diverse.startupDrain()
        try require(diversity.snapshot.count == 3 && diversity.snapshot[2].0 == services[1].id,
                    "SERVFAIL candidate diversity expanded or lost the final approved candidate")
        groups += 1
        return groups
    }

    private final class MarkedPeer: NativeRoutedDatagram, DNSQueryDeadlineAcknowledging,
        DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding {
        private let lock = NSLock()
        private let receive: (Data) -> Void, failure: (Error) -> Void
        private let automaticAnswer: Bool
        private var message: Data?, deadlineACK: ((DNSProxyFallbackBarrier?) -> Void)?
        private var barrier: DNSProxyFallbackBarrier?, emitted = false, deadlineEntered = false
        init(automaticAnswer: Bool, receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            self.automaticAnswer = automaticAnswer; self.receive = receive; self.failure = failure
        }
        func send(_ data: Data) {
            lock.lock(); message = data; lock.unlock()
            if automaticAnswer { respond(code: 0) }
        }
        func emitTimeout(marked: Bool) {
            failure(DNSQueryTimeoutError(inheritedDeadlineReached: marked))
            lock.lock(); emitted = true; lock.unlock()
        }
        func respond(code: UInt8) {
            lock.lock(); let message = message; lock.unlock()
            guard let message else { return }
            var response = answer(message); response[3] = 0x80 | code; receive(response)
        }
        func queryDeadlineReached() { queryDeadlineReached(completion: { _ in }) }
        func queryDeadlineReached(completion: @escaping (DNSProxyFallbackBarrier?) -> Void) {
            lock.lock(); deadlineEntered = true; deadlineACK = completion; lock.unlock()
        }
        func acknowledge(_ value: DNSProxyFallbackBarrier?) {
            lock.lock(); barrier = value; let completion = deadlineACK; deadlineACK = nil; lock.unlock()
            completion?(value)
        }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { lock.lock(); defer { lock.unlock() }; return barrier }
        func cancel() {}
        func cancel(completion: @escaping () -> Void) { completion() }
        var state: (emitted: Bool, deadlineEntered: Bool) {
            lock.lock(); defer { lock.unlock() }; return (emitted, deadlineEntered)
        }
    }
    private final class MarkedProbe {
        private let lock = NSLock()
        private var values: [MarkedPeer] = []
        func make(receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) -> MarkedPeer {
            lock.lock()
            let peer = MarkedPeer(automaticAnswer: !values.isEmpty, receive: receive, failure: failure)
            values.append(peer); lock.unlock(); return peer
        }
        var peers: [MarkedPeer] { lock.lock(); defer { lock.unlock() }; return values }
    }
    private static func inheritedTimeoutFollowerFences() throws -> Int {
        var groups = 0
        for mode in ["new-generation", "authentication", "refused", "ordinary-timeout"] {
            let cache = DNSQueryCache(), probe = MarkedProbe(), book = Book()
            let coordinator = DNSQueryCoordinator(cache: cache)
            let callbacks = DispatchQueue(label: "fixture.startup.marked.\(mode)")
            let message = query(600, prefix: "marked-\(mode)")
            var follower = message; follower[0] = 0x70; follower[1] = 0x01
            let ordinary = mode == "ordinary-timeout"
            let originalDeadline = now() + (ordinary ? 0.8 : 0.18), followerDeadline = now() + 1.2
            let factory: DNSQueryCoordinator.Factory = { _, receive, failure in probe.make(receive: receive, failure: failure) }
            coordinator.resolve(scope: mode, query: message, callbackQueue: callbacks,
                absoluteDeadline: originalDeadline, permitted: { true }, factory: factory,
                completion: { book.record(600, query: message, answer: $0, deadline: originalDeadline) })
            coordinator.resolve(scope: mode, query: follower, callbackQueue: callbacks,
                absoluteDeadline: followerDeadline, permitted: { true }, factory: factory,
                completion: { book.record(601, query: follower, answer: $0, deadline: followerDeadline) })
            _ = coordinator.statistics
            try require(probe.peers.count == 1 && coordinator.statistics.mergedQueries == 1,
                        "\(mode): later caller failed to merge into one old generation")
            let old = probe.peers[0]
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { old.emitTimeout(marked: !ordinary) }
            try until("\(mode): controlled early timeout was not emitted") { old.state.emitted }
            _ = coordinator.statistics; callbacks.sync {}
            if ordinary {
                try until("Ordinary child timeout lost its existing immediate failure semantics") { book.count == 2 }
                try require(book.snapshot.receipts.values.allSatisfy { $0.count == 1 && !$0[0].success
                    && $0[0].delivered < originalDeadline } && probe.peers.count == 1 && !old.state.deadlineEntered,
                    "Unmarked timeout incorrectly sponsored a deadline retirement/handoff")
                groups += 1; continue
            }
            try require(now() < originalDeadline && book.count == 0 && coordinator.statistics.waitingClients == 2,
                        "\(mode): marked child timeout completed callers before their original deadline")
            try until("\(mode): original waiter deadline did not finish exactly one caller", seconds: 1) { book.count == 1 }
            try until("\(mode): coordinator did not enter its held real deadline ACK") { old.state.deadlineEntered }
            try require(book.snapshot.receipts[600]?.first?.success == false
                        && book.snapshot.receipts[600]!.first!.delivered >= originalDeadline - 0.003
                        && book.snapshot.receipts[601] == nil && probe.peers.count == 1,
                        "\(mode): expired waiter revived or later follower crossed the held ACK")
            switch mode {
            case "authentication": old.acknowledge(.failure(EncryptedDNSQueryFailure.authentication))
            case "refused":
                var refused = answer(message); refused[3] = 0x85
                old.acknowledge(.answer(refused))
            default: old.acknowledge(nil)
            }
            try until("\(mode): held deadline ACK did not finish the still-live original follower", seconds: 1) { book.count == 2 }
            callbacks.sync {}
            let result = book.snapshot.receipts[601]!.first!
            try require(result.delivered < followerDeadline && book.snapshot.receipts.values.allSatisfy { $0.count == 1 },
                        "\(mode): follower deadline reset or completion repeated")
            switch mode {
            case "authentication":
                try require(!result.success && probe.peers.count == 1,
                            "Authentication ACK barrier permitted a fresh generation")
            case "refused":
                try require(result.responseCode == 5 && probe.peers.count == 1,
                            "REFUSED ACK barrier was discarded or restarted a generation")
            default:
                try require(result.success && result.responseCode == 0 && probe.peers.count == 2,
                            "Safe marked-deadline retirement did not preserve the later follower's new generation")
            }
            old.respond(code: 0); old.emitTimeout(marked: true)
            _ = coordinator.statistics; callbacks.sync {}
            try require(book.count == 2 && coordinator.statistics.pendingQueries == 0 && cache.usage.entries == 0,
                        "\(mode): old generation's late callbacks revived a caller or stale cache")
            groups += 1
        }
        return groups
    }

    private final class ErrorBox {
        private let lock = NSLock()
        private var errors: [Error] = [], answers = 0
        func failure(_ error: Error) { lock.lock(); errors.append(error); lock.unlock() }
        func received(_ answer: Data) { lock.lock(); answers += 1; lock.unlock() }
        var snapshot: (errors: [Error], answers: Int) { lock.lock(); defer { lock.unlock() }; return (errors, answers) }
    }
    private static func realPoolTimeoutSourceMarker() throws -> Int {
        var groups = 0
        for phaseDeadline in [false, true] {
            let owner = Owner(phaseDeadline ? 7 : 6), errors = ErrorBox()
            defer { try? owner.close() }
            let short = now() + 0.22, parentDeadline = phaseDeadline ? now() + 8 : short
            let candidate = DNSUpstreamCandidate(upstream: .doh(DoHEndpoint("https://marker.fixture.invalid/dns-query#203.0.113.76")!), bootstrap: nil)
            let flow = DNSAdaptiveQueryDatagram(candidates: [candidate], selector: DNSAdaptiveUpstreamSelector(),
                scopeKey: "real-pool-marker-\(phaseDeadline)", queue: DispatchQueue(label: "fixture.startup.pool-marker"),
                permitted: { true }, factory: { _, _, receive, failure in
                    DoHRoutedDatagram(resolver: owner.resolver, receive: receive, failure: failure)
                }, receive: errors.received, failure: errors.failure,
                absoluteDeadline: phaseDeadline ? short : nil)
            flow.setDNSQueryExecutionContext(DNSQueryExecutionContext(absoluteDeadline: parentDeadline))
            flow.send(query(700 + groups)); flow.startupDrain()
            try until("Real marker fixture did not begin one held physical dial") { owner.dialer.snapshot.opens == 1 }
            // Force the real endpoint timer to win this two-timer race. No
            // clock/deadline is changed, and the endpoint remains production.
            flow.startupPauseOwnTimer()
            try until("Real provider timer did not propagate its typed timeout", seconds: 1) { !errors.snapshot.errors.isEmpty }
            guard let typed = errors.snapshot.errors.first as? DNSQueryTimeoutError else {
                throw Failure(text: "Real pool -> Adaptive lost the typed timeout source")
            }
            try require(typed.inheritedDeadlineReached == !phaseDeadline && errors.snapshot.errors.count == 1
                        && errors.snapshot.answers == 0,
                        "Real pool timeout marker: parent phase=\(phaseDeadline), expected marker=\(!phaseDeadline), observed=\(typed.inheritedDeadlineReached)")
            try require(now() >= short - 0.003 && flow.startupCounters.deadline <= parentDeadline,
                        "Marker bypassed its actual deadline or extended the parent budget")
            try owner.close(); flow.startupDrain()
            try require(errors.snapshot.errors.count == 1, "Late physical ACK repeated an inherited/phase timeout")
            flow.cancel(); groups += 1
        }
        return groups
    }

    private static func timeoutMarkerNegativeBoundaries() throws -> Int {
        let inherited = DNSQueryExecutionContext(absoluteDeadline: now() + 8)
        inherited.recordInheritedDeadlineReached()
        let child = inherited.child()
        try require(inherited.inheritedDeadlineReached && !child.inheritedDeadlineReached
                    && child.absoluteDeadline == inherited.absoluteDeadline,
                    "A new child inherited stale candidate-local timeout evidence")
        for localTimeout in [true, false] {
            let owner = Owner(localTimeout ? 8 : 9, localTimeout: localTimeout ? .milliseconds(70) : .seconds(8))
            defer { try? owner.close() }
            let deadline = now() + 1, context = DNSQueryExecutionContext(absoluteDeadline: deadline)
            let message = query(localTimeout ? 800 : 801), book = Book()
            _ = owner.resolver.resolveResult(query: message, completion: { result in
                let response: Data?; if case .success(let answer) = result { response = answer } else { response = nil }
                book.record(800, query: message, answer: response, deadline: deadline)
            }, executionContext: context)
            try until("Negative-marker query did not start one controlled physical dial") { owner.dialer.snapshot.opens == 1 }
            if !localTimeout { try owner.dialer.timeout(0) }
            try until("Negative-marker timeout did not finish its real endpoint", seconds: 1) { book.count == 1 }
            try require(!context.inheritedDeadlineReached && now() < deadline
                        && book.snapshot.receipts[800]?.first?.success == false,
                        "A \(localTimeout ? "short local timer" : "premature native timeout") fabricated inherited deadline evidence")
            try owner.close()
            try require(book.count == 1, "Negative-marker cleanup duplicated an endpoint completion")
        }
        let dialer = Dialer(), budget = SOCKSUDPGlobalBudget(resources: 64, packets: 0, bytes: 0)
        let pool = EncryptedDNSRequestPool(protocol: .https(DoHEndpoint("https://explicit-phase.fixture.invalid/dns-query#203.0.113.81")!),
            label: "fixture.startup.explicit-phase", streamDialer: nil, cancellableStreamDialer: nil,
            metadataStreamDialer: dialer.value, timeout: .seconds(8), idleTimeout: 15, idleLimit: 4,
            idleHandoffGrace: 8, activeLimit: DoHResolver.maximumConcurrentQueries,
            clock: { Date(timeIntervalSince1970: SOCKSUDPResourceLimits.now) }, resourceBudget: budget)
        defer { pool.cancel() }
        let callerDeadline = now() + 1, context = DNSQueryExecutionContext(absoluteDeadline: callerDeadline)
        let explicitDeadline = now() + 0.08, message = query(802), book = Book()
        _ = pool.resolveResult(query: message, completion: { result in
            let response: Data?; if case .success(let answer) = result { response = answer } else { response = nil }
            book.record(802, query: message, answer: response, deadline: callerDeadline)
        }, absoluteDeadline: explicitDeadline, executionContext: context)
        try until("Explicit phase marker fixture did not start its actual provider timer") { dialer.snapshot.opens == 1 }
        try until("Explicit phase deadline did not expire its endpoint", seconds: 1) { book.count == 1 }
        try require(!context.inheritedDeadlineReached && now() < callerDeadline,
                    "An explicit pool deadline different from its context fabricated inherited total-deadline evidence")
        pool.cancel(); pool.drainQueueForSelfTest()
        try require(dialer.snapshot.pending == [0] && dialer.snapshot.cancellations == [1],
                    "Explicit phase cleanup released a native reservation before its original callback")
        let late = try dialer.succeed(0)
        try until("Explicit phase's late physical ACK retained a stream or native reservation") {
            pool.drainQueueForSelfTest()
            return late.snapshot.closed && budget.usage.resources == 0
        }
        try require(late.snapshot.writes == 0 && book.count == 1 && dialer.snapshot.callbacks == [1],
                    "Explicit phase's late ACK sent data or repeated a completion")
        return 4
    }

    static func main() {
        do {
            try require(DoHResolver.maximumConcurrentQueries == 16 && DoHResolver.maximumConcurrentConnectionAttempts == 4,
                        "Production DoH limits changed from active16/cold4")
            let before = try startupBurst(availabilityEnabled: false)
            print("PASS startup before: " + String(data: try JSONSerialization.data(withJSONObject: before, options: [.sortedKeys]), encoding: .utf8)!)
            let after = try startupBurst(availabilityEnabled: true)
            print("PASS startup after: " + String(data: try JSONSerialization.data(withJSONObject: after, options: [.sortedKeys]), encoding: .utf8)!)
            try contextDeadlinePropagation(); print("PASS inherited context deadline reaches the real provider pool")
            try coordinatorContextDeadline(); print("PASS coordinator context caps both Adaptive and provider deadlines")
            try earliestEndpointDeadline(); print("PASS endpoint earliest original deadline and equal-deadline FIFO")
            try revokedPermissionAndLateACK(); print("PASS policy revocation survives logical cleanup and late physical ACK")
            let boundaryGroups = try availabilityOrderingBoundaries()
            print("PASS availability ordering boundaries: \(boundaryGroups) groups")
            let followerGroups = try inheritedTimeoutFollowerFences()
            print("PASS early inherited timeout follower and held-ACK barriers: \(followerGroups) groups")
            let timeoutSourceGroups = try realPoolTimeoutSourceMarker()
            print("PASS real provider -> Adaptive original/phase timeout markers: \(timeoutSourceGroups) groups")
            let markerNegativeGroups = try timeoutMarkerNegativeBoundaries()
            print("PASS timeout marker negative boundaries: \(markerNegativeGroups) groups")
            let report: [String: Any] = ["checks": checks, "before": before, "after": after,
                "contextDeadlinePropagation": true, "earliestEndpointDeadline": true,
                "coordinatorContextDeadline": true, "revokedPermissionAndLateACK": true,
                "availabilityOrderingBoundaryGroups": boundaryGroups,
                "inheritedTimeoutFollowerGroups": followerGroups, "realPoolTimeoutSourceGroups": timeoutSourceGroups,
                "timeoutMarkerNegativeGroups": markerNegativeGroups,
                "externalNetworkOperations": 0, "systemConfigurationChanges": 0]
            print(String(data: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!)
        } catch {
            FileHandle.standardError.write(Data("DNS startup scheduling fixture failed: \(error.localizedDescription)\n".utf8)); exit(1)
        }
    }
}

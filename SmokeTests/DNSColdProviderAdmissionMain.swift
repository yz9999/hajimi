// Test-only adapters appended to verbatim production declarations. Timers are
// driven on their real owning queue with a monotonic memory clock. Peers and
// pool snapshots are memory objects; this executable never opens a socket.
private extension DNSAdaptiveQueryDatagram {
    func coldAuditPauseTimers() {
        deadlineTimer?.cancel()
        for attempt in active.values {
            attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel()
        }
    }
    func coldAuditDrain() { queue.sync { coldAuditPauseTimers() } }
    func coldAuditHedge() {
        queue.sync {
            if let primaryToken { startHedge(after: primaryToken) }
            coldAuditPauseTimers()
        }
    }
    func coldAuditRotate() {
        queue.sync {
            if let token = active.keys.first(where: { $0 != primaryToken }) { rotateHedge(token) }
            coldAuditPauseTimers()
        }
    }
    func coldAuditDeadline() {
        queue.sync { overallDeadlineReached(); coldAuditPauseTimers() }
        coldAuditDrain()
    }
    var coldAuditState: (attempts: Int, active: Int, deadline: TimeInterval) {
        queue.sync { (attemptCount, active.count, deadline) }
    }
    var coldAuditRotationScheduled: Bool {
        queue.sync { active.values.contains { $0.rotationTimer != nil } }
    }
}

private extension DNSAdaptiveUpstreamSelector {
    func coldAuditQueryCount(_ key: String) -> UInt64 {
        lock.lock(); defer { lock.unlock() }; return scopes[key]?.queries ?? 0
    }
    func coldAuditHealth(_ key: String, _ candidate: String) -> (successes: Int, failures: Int) {
        lock.lock(); defer { lock.unlock() }
        let value = scopes[key]?.health[candidate]
        return (value?.successes ?? 0, value?.failures ?? 0)
    }
}

@main private enum DNSColdProviderAdmissionMain {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    static var assertions = 0, cases = 0
    static func require(_ value: @autoclosure () -> Bool, _ text: String) throws {
        assertions += 1
        guard value() else { throw Failure(text: text) }
    }
    static func check(_ name: String, _ body: () throws -> Void) throws {
        try body(); cases += 1; print("PASS", name)
    }
    static func emit(_ value: [String: Any]) {
        print(String(data: try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), encoding: .utf8)!)
    }
    static func candidate(_ text: String) -> DNSUpstreamCandidate {
        DNSUpstreamCandidate(upstream: .doh(DoHEndpoint(text)!), bootstrap: nil)
    }
    static let google1 = candidate("https://dns.google/dns-query#8.8.8.8")
    static let google2 = candidate("https://dns.google/dns-query#8.8.4.4")
    static let cloudflare = candidate("https://cloudflare-dns.com/dns-query#1.1.1.1")
    static let dnspod = candidate("https://doh.pub/dns-query#1.12.12.12")
    static var approved: [DNSUpstreamCandidate] { [google1, google2, cloudflare, dnspod] }

    final class Clock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ elapsed: TimeInterval) { lock.lock(); value = 100 + elapsed; lock.unlock() }
    }
    final class Permission {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }
    struct Capacity {
        var reusable: Int, cold: Int
        init(_ reusable: Int = 0, _ cold: Int = 0) { self.reusable = reusable; self.cold = cold }
    }
    /// A controllable snapshot, not a replacement production pool. In the
    /// overlapping-query test a cold lease is returned only by acknowledge(),
    /// so a logical cancellation cannot manufacture new native dial capacity.
    final class Slots {
        private let lock = NSLock()
        private var values: [String: Capacity] = [:]
        private var leases: [UUID: String] = [:]
        private(set) var peakLeases = 0
        let reserveOnSend: Bool
        init(_ capacities: [Capacity?] = [], candidates: [DNSUpstreamCandidate] = approved,
             reserveOnSend: Bool = false) {
            self.reserveOnSend = reserveOnSend
            for (index, value) in capacities.enumerated() where candidates.indices.contains(index) {
                if let value { values[candidates[index].id] = value }
            }
        }
        func availability(_ candidate: DNSUpstreamCandidate) -> (reusable: Int, cold: Int)? {
            lock.lock(); defer { lock.unlock() }
            guard let value = values[candidate.id] else { return nil }
            return (value.reusable, value.cold)
        }
        func set(_ candidate: DNSUpstreamCandidate, _ capacity: Capacity?) {
            lock.lock(); values[candidate.id] = capacity; lock.unlock()
        }
        func lease(_ candidate: DNSUpstreamCandidate) -> (DNSQueryTransportEvidence, UUID?) {
            lock.lock(); defer { lock.unlock() }
            guard var value = values[candidate.id] else { return (.fresh, nil) }
            if value.reusable > 0 { return (.reused, nil) }
            guard value.cold > 0 else { return (.notStarted, nil) }
            guard reserveOnSend else { return (.fresh, nil) }
            value.cold -= 1; values[candidate.id] = value
            let id = UUID(); leases[id] = candidate.id; peakLeases = max(peakLeases, leases.count)
            return (.fresh, id)
        }
        func release(_ id: UUID?) {
            guard let id else { return }
            lock.lock(); defer { lock.unlock() }
            guard let candidate = leases.removeValue(forKey: id), var value = values[candidate] else { return }
            value.cold += 1; values[candidate] = value
        }
        var outstanding: Int { lock.lock(); defer { lock.unlock() }; return leases.count }
    }
    final class MemoryPeer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging,
        DNSQueryExecutionContextAccepting, DNSQueryTransportEvidenceProviding {
        let receive: (Data) -> Void, failure: (Error) -> Void
        private let lock = NSLock()
        private let clock: Clock, candidate: DNSUpstreamCandidate, slots: Slots
        private let onSend: () -> Void, onCancel: () -> Void
        private let hold: Bool
        private var context: DNSQueryExecutionContext?
        private var evidence = DNSQueryTransportEvidence.notStarted
        private var leaseID: UUID?
        private var cancelled = false, acknowledged = false
        private var acknowledgements: [() -> Void] = []
        private var reasons: [DNSAttemptCancellationReason] = []
        init(clock: Clock, candidate: DNSUpstreamCandidate, slots: Slots, hold: Bool,
             onSend: @escaping () -> Void, onCancel: @escaping () -> Void,
             receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            self.clock = clock; self.candidate = candidate; self.slots = slots; self.hold = hold
            self.onSend = onSend; self.onCancel = onCancel; self.receive = receive; self.failure = failure
        }
        func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
            lock.lock(); self.context = context; lock.unlock()
        }
        func send(_ data: Data) {
            let lease = slots.lease(candidate)
            lock.lock(); evidence = lease.0; leaseID = lease.1; let context = self.context; lock.unlock()
            if lease.0 == .fresh { context?.record(.transportStarted, at: clock.now()) }
            if lease.0 == .reused { context?.record(.connectionReused, at: clock.now()) }
            onSend()
        }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence {
            lock.lock(); defer { lock.unlock() }; return evidence
        }
        func querySent() {
            lock.lock(); let context = self.context; lock.unlock()
            context?.record(.querySent, at: clock.now())
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) { cancel(reason: .callerCancelled, completion: completion) }
        func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
            lock.lock(); let first = !cancelled; cancelled = true
            if first { reasons.append(reason) }
            if hold && !acknowledged { acknowledgements.append(completion); lock.unlock() }
            else { lock.unlock(); completion(); releaseLease() }
            if first { onCancel() }
        }
        private func releaseLease() {
            lock.lock(); let id = leaseID; leaseID = nil; lock.unlock(); slots.release(id)
        }
        func acknowledge(duplicate: Bool = false) {
            lock.lock(); acknowledged = true; let callbacks = acknowledgements
            acknowledgements.removeAll(); lock.unlock()
            releaseLease()
            for callback in callbacks { callback(); if duplicate { callback() } }
        }
        var cancellationReasons: [DNSAttemptCancellationReason] {
            lock.lock(); defer { lock.unlock() }; return reasons
        }
        var inheritedDeadline: TimeInterval? { lock.lock(); defer { lock.unlock() }; return context?.absoluteDeadline }
    }
    final class Scenario {
        let clock: Clock, permission = Permission(), slots: Slots
        let selector: DNSAdaptiveUpstreamSelector
        let candidates: [DNSUpstreamCandidate], scope: String
        let query: Data
        let lock = NSLock()
        private var peers: [Int: MemoryPeer] = [:], factories: [Int] = [], sends: [Int] = []
        private var activePeers = Set<Int>(), peak = 0
        private var answerValues: [Data] = [], errorValues: [Error] = []
        private var selectorCallsBefore: UInt64 = 0
        var flow: DNSAdaptiveQueryDatagram!
        init(candidates: [DNSUpstreamCandidate] = approved, slots: Slots? = nil,
             clock: Clock = Clock(), selector: DNSAdaptiveUpstreamSelector? = nil,
             scope: String = "cold-provider-admission", hold: Bool = false,
             healthyPrimary: Bool = false, coldHistory: [Double?] = [], autoSend: Bool = true,
             allowPlaintext: Bool = false, protectFallback: Bool = false,
             factoryInterruption: ((Permission, Clock) -> Void)? = nil) {
            self.clock = clock; self.candidates = candidates; self.scope = scope
            self.slots = slots ?? Slots(candidates: candidates)
            let selector = selector ?? DNSAdaptiveUpstreamSelector(clock: clock.now)
            self.selector = selector
            query = DNSMessageInspection.query(for: "cold-admission.fixture.invalid", type: 1, id: 0x3621)!
            if healthyPrimary || !coldHistory.isEmpty {
                _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: candidates.map(\.id))
                if healthyPrimary {
                    selector.record(selector.beginObservation(scopeKey: scope, candidateID: candidates[0].id),
                                    milliseconds: 80, success: true, transport: .fresh)
                }
                for (index, milliseconds) in coldHistory.enumerated() where candidates.indices.contains(index) {
                    if let milliseconds {
                        selector.record(selector.beginObservation(scopeKey: scope, candidateID: candidates[index].id),
                                        milliseconds: milliseconds, success: true, transport: .fresh)
                    }
                }
            }
            selectorCallsBefore = selector.coldAuditQueryCount(scope)
            flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector, scopeKey: scope,
                queue: DispatchQueue(label: "cold-provider-memory-callback"), permitted: permission.permits,
                factory: { [weak self] candidate, _, receive, failure in
                    guard let self, let index = self.candidates.firstIndex(where: { $0.id == candidate.id }) else {
                        throw Failure(text: "Factory received an unapproved candidate")
                    }
                    let peer = MemoryPeer(clock: self.clock, candidate: candidate, slots: self.slots, hold: hold,
                        onSend: { [weak self] in
                            guard let self else { return }
                            self.lock.lock(); self.sends.append(index); self.activePeers.insert(index)
                            self.peak = max(self.peak, self.activePeers.count); self.lock.unlock()
                        }, onCancel: { [weak self] in
                            guard let self else { return }
                            self.lock.lock(); self.activePeers.remove(index); self.lock.unlock()
                        }, receive: receive, failure: failure)
                    self.lock.lock(); self.factories.append(index); self.peers[index] = peer; self.lock.unlock()
                    factoryInterruption?(self.permission, self.clock)
                    return peer
                }, receive: { [weak self] answer in
                    guard let self else { return }; self.lock.lock(); self.answerValues.append(answer); self.lock.unlock()
                }, failure: { [weak self] error in
                    guard let self else { return }; self.lock.lock(); self.errorValues.append(error); self.lock.unlock()
                }, availability: self.slots.availability, timeout: 8, absoluteDeadline: 108, clock: clock.now,
                protectProxyFallback: protectFallback, allowApprovedProxyPlaintext: allowPlaintext)
            if autoSend { send() }
        }
        deinit {
            flow?.cancel(); flow?.coldAuditDrain()
            for index in snapshot.factories { peer(index)?.acknowledge() }
        }
        func send() { flow.send(query); flow.coldAuditDrain() }
        func peer(_ index: Int) -> MemoryPeer? { lock.lock(); defer { lock.unlock() }; return peers[index] }
        func answer(_ index: Int, rcode: UInt8 = 0) throws {
            guard let peer = peer(index) else { throw Failure(text: "Candidate \(index) was never admitted") }
            var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail)!
            answer[3] = (answer[3] & 0xf0) | rcode
            peer.receive(answer); flow.coldAuditDrain()
        }
        func fail(_ index: Int, _ error: Error = EncryptedDNSQueryFailure.network) throws {
            guard let peer = peer(index) else { throw Failure(text: "Candidate \(index) was never admitted") }
            peer.failure(error); flow.coldAuditDrain()
        }
        var snapshot: (factories: [Int], sends: [Int], live: Int, peak: Int, answers: [Data], errors: [Error]) {
            lock.lock(); defer { lock.unlock() }
            return (factories, sends, activePeers.count, peak, answerValues, errorValues)
        }
        func integrity(expectedSelectorCalls: UInt64? = 1) throws {
            let value = snapshot, state = flow.coldAuditState
            try require(value.factories.count <= 3 && state.attempts <= 3, "Three-attempt cap changed")
            try require(value.peak <= 2 && state.active <= 2, "Two-live cap changed")
            try require(Set(value.factories).count == value.factories.count,
                        "Candidate was admitted more than once")
            try require(value.factories.allSatisfy(candidates.indices.contains), "An unapproved endpoint was dialed")
            try require(state.attempts == value.factories.count, "Attempt bookkeeping disagrees with factory admission")
            try require(state.deadline == 108, "Original absolute deadline was extended")
            if let expectedSelectorCalls {
                try require(selector.coldAuditQueryCount(scope) == selectorCallsBefore + expectedSelectorCalls,
                            "Pool snapshot refresh spent another selector query/exploration")
            }
            try require(value.sends.allSatisfy { peer($0)?.inheritedDeadline == 108 },
                        "A child did not inherit the original deadline")
        }
        func trace(_ name: String, fixed: Bool) {
            let value = snapshot
            emit(["case": name, "fixed": fixed, "factories": value.factories, "sends": value.sends,
                  "answers": value.answers.count, "errors": value.errors.count, "maximumLive": value.peak,
                  "deadline": flow.coldAuditState.deadline, "atMilliseconds": (clock.now() - 100) * 1000])
        }
    }

    static func regressions(fixed: Bool) throws {
        for reusable in [true, false] {
            try check("blocked first three admit fourth approved \(reusable ? "reusable" : "cold-ready") provider") {
                let slots = Slots([Capacity(), Capacity(), Capacity(), reusable ? Capacity(1, 0) : Capacity(0, 1)])
                let s = Scenario(slots: slots)
                try require(s.snapshot.sends == (fixed ? [3] : [0]),
                            "Full approved pool did not bypass explicitly blocked prefix")
                if fixed { s.clock.advance(0.08); try s.answer(3) }
                else { s.clock.advance(8); s.flow.coldAuditDeadline() }
                try require(s.snapshot.answers.count == (fixed ? 1 : 0)
                            && s.snapshot.errors.count == (fixed ? 0 : 1), "Cold-prefix outcome differs from before/after control")
                try s.integrity(); s.trace(reusable ? "blocked-prefix-reusable" : "blocked-prefix-cold", fixed: fixed)
            }
        }
        try check("soft hedge rereads full approved pool after another query opens a reusable channel") {
            let slots = Slots([Capacity(0, 1), Capacity(), Capacity(), Capacity()])
            let s = Scenario(slots: slots)
            try require(s.snapshot.sends == [0], "Unexpected initial primary")
            slots.set(dnspod, Capacity(1, 0)); s.clock.advance(1); s.flow.coldAuditHedge()
            try require(s.snapshot.sends == (fixed ? [0, 3] : [0, 1]),
                        "Soft hedge used stale prefix availability")
            try require(s.peer(0)?.cancellationReasons.isEmpty == true, "A live primary was retired for the new provider")
            if fixed { s.clock.advance(1.08); try s.answer(3) }
            else { s.clock.advance(8); s.flow.coldAuditDeadline() }
            try require(s.snapshot.answers.count == (fixed ? 1 : 0), "Approved ready provider did not rescue the original query")
            try s.integrity(); s.trace("soft-budget-new-reuse", fixed: fixed)
        }
        try check("stalled connecting primary uses a different available service at soft budget") {
            let slots = Slots(Array(repeating: Capacity(0, 1), count: 4))
            let s = Scenario(slots: slots)
            s.clock.advance(1); s.flow.coldAuditHedge()
            let attempts = s.snapshot.sends
            try require(attempts.count == 2 && attempts[0] == 0, "Soft hedge did not keep a single primary")
            let different = s.candidates[attempts[1]].upstream.resolverServiceID != google1.upstream.resolverServiceID
            try require(different == fixed, "Soft hedge repeated a stalled service despite another available approved service")
            try require(s.peer(0)?.cancellationReasons.isEmpty == true, "Provider diversity clipped the original primary")
            try s.answer(attempts[1]); try s.integrity(); s.trace("soft-budget-provider-diversity", fixed: fixed)
        }
        try check("third slot refreshes availability before conservative hedge rotation") {
            let slots = Slots([Capacity(0, 1), Capacity(0, 1), Capacity(), Capacity()])
            let s = Scenario(slots: slots)
            s.clock.advance(1); s.flow.coldAuditHedge()
            try require(s.snapshot.sends == [0, 1], "An unavailable service displaced an available backup")
            try require(s.flow.coldAuditRotationScheduled, "Production did not schedule the rotation callback exercised by this fixture")
            slots.set(dnspod, Capacity(0, 1)); s.clock.advance(5.4); s.flow.coldAuditRotate()
            try require(s.snapshot.sends == (fixed ? [0, 1, 3] : [0, 1, 2]),
                        "Third slot did not refresh the complete approved pool")
            try require(s.peer(0)?.cancellationReasons.isEmpty == true
                        && s.peer(1)?.cancellationReasons == [.hedgeRotation], "Rotation changed cancellation ownership")
            if fixed { s.clock.advance(5.48); try s.answer(3) }
            else { s.clock.advance(8); s.flow.coldAuditDeadline() }
            try s.integrity(); s.trace("rotation-new-cold-capacity", fixed: fixed)
        }
        try check("scheduled third rescue uses ready reuse despite a newly measured slow cold handshake") {
            let slots = Slots([Capacity(0, 1), Capacity(0, 1), Capacity(), Capacity()])
            let s = Scenario(slots: slots)
            s.clock.advance(1); s.flow.coldAuditHedge()
            try require(s.snapshot.sends == [0, 1] && s.flow.coldAuditRotationScheduled,
                        "Slow-cold control did not begin with a real production rotation timer")
            s.selector.record(s.selector.beginObservation(scopeKey: s.scope, candidateID: cloudflare.id),
                              milliseconds: 6_000, success: true, transport: .fresh)
            slots.set(cloudflare, Capacity(1, 0))
            s.clock.advance(5.4); s.flow.coldAuditRotate()
            try require(s.snapshot.sends == (fixed ? [0, 1, 2] : [0, 1]),
                        "Historical cold cost blocked a connection already available for reuse")
            if fixed { s.clock.advance(5.48); try s.answer(2) }
            else { s.clock.advance(8); s.flow.coldAuditDeadline() }
            try s.integrity(); s.trace("slow-cold-ready-reuse", fixed: fixed)
        }
        try check("original two-thirds checkpoint observes reuse when an earlier slow cold estimate prevented rotation") {
            let slots = Slots([Capacity(0, 1), Capacity(0, 1), Capacity(), Capacity()])
            let s = Scenario(slots: slots, coldHistory: [80, 100, 6_000, nil])
            try require(s.snapshot.sends == [0], "Synthetic cold history changed the primary")
            s.clock.advance(1); s.flow.coldAuditHedge()
            try require(s.snapshot.sends == [0, 1], "Unavailable providers displaced a viable same-service backup")
            try require(s.flow.coldAuditRotationScheduled == fixed,
                        "Slow third cold estimate did not reproduce the before/after checkpoint difference")
            slots.set(dnspod, Capacity(1, 0))
            try require(s.peer(0)?.cancellationReasons.isEmpty == true && s.peer(1)?.cancellationReasons.isEmpty == true,
                        "Availability change itself cancelled a live transport before the conservative boundary")
            s.clock.advance(5.4)
            if s.flow.coldAuditRotationScheduled { s.flow.coldAuditRotate() }
            try require(s.snapshot.sends == (fixed ? [0, 1, 3] : [0, 1]),
                        "Two-thirds checkpoint did not reconsider the newly reusable approved provider")
            if fixed { s.clock.advance(5.48); try s.answer(3) }
            else { s.clock.advance(8); s.flow.coldAuditDeadline() }
            try s.integrity(); s.trace("slow-initial-cold-checkpoint", fixed: fixed)
        }
        try check("available reusable fourth candidate outranks a cold candidate inside the prefix") {
            let s = Scenario(slots: Slots([Capacity(), Capacity(), Capacity(0, 1), Capacity(1, 0)]))
            try require(s.snapshot.sends == (fixed ? [3] : [2]), "Ready reuse was not considered outside prefix")
            try s.answer(fixed ? 3 : 2); try s.integrity()
        }
        try check("overlapping queries stop queuing behind four occupied cold slots in one concrete pool") {
            let slots = Slots([Capacity(0, 4), Capacity(), Capacity(), Capacity(0, 8)], reserveOnSend: true)
            let clock = Clock()
            var flows: [Scenario] = []
            for index in 0..<8 {
                flows.append(Scenario(slots: slots, clock: clock, scope: "overlap-\(index)", hold: true))
            }
            try require(flows.prefix(4).allSatisfy { $0.snapshot.sends == [0] }, "First four concrete-pool leases changed")
            try require(flows.suffix(4).allSatisfy { $0.snapshot.sends == (fixed ? [3] : [0]) },
                        "Exhausted cold pool kept swallowing new callers instead of admitting another approved provider")
            try require(slots.outstanding == (fixed ? 8 : 4), "Cold lease accounting differs from the admitted physical attempts")
            flows[0].flow.cancel(); flows[0].flow.coldAuditDrain()
            try require(slots.availability(google1)?.cold == 0, "Logical cancellation released a pending native cold lease early")
            flows[0].peer(0)?.acknowledge(duplicate: true)
            try require(slots.availability(google1)?.cold == 1, "Real cancellation receipt did not return exactly one lease")
            for flow in flows { try flow.integrity() }
            for flow in flows { flow.flow.cancel(); flow.flow.coldAuditDrain() }
            try require(slots.outstanding == (fixed ? 7 : 3), "Bulk logical cancellation invented reusable native capacity")
            for flow in flows { for index in flow.snapshot.factories { flow.peer(index)?.acknowledge(duplicate: true) } }
            try require(slots.outstanding == 0 && slots.availability(google1)?.cold == 4
                        && slots.availability(dnspod)?.cold == 8, "Native receipts leaked or over-released cold reservations")
            emit(["case": "eight-overlapping-queries", "fixed": fixed,
                  "firstCandidates": flows.map { $0.snapshot.sends[0] }, "peakNativeLeases": slots.peakLeases])
        }
        try check("simultaneous queries share selector state and recover from racing cold admission snapshots") {
            let slots = Slots([Capacity(0, 4), Capacity(), Capacity(), Capacity(0, 8)], reserveOnSend: true)
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: { 100 })
            let storeLock = NSLock(), scope = "simultaneous-admission"
            var stored = [Scenario?](repeating: nil, count: 8)
            DispatchQueue.concurrentPerform(iterations: stored.count) { index in
                let flow = Scenario(slots: slots, clock: clock, selector: selector, scope: scope, hold: true)
                storeLock.lock(); stored[index] = flow; storeLock.unlock()
            }
            let flows = stored.map { $0! }, initial = flows.map { $0.snapshot.sends[0] }
            try require(initial.allSatisfy { fixed ? [0, 3].contains($0) : $0 == 0 },
                        "Racing admission added an unapproved or explicitly blocked replacement")
            try require(slots.availability(google1)?.cold == 0,
                        "A concrete pool did not enforce its four pending cold reservations")
            // Readiness is advisory. Two queries may both observe the final
            // slot before either factory claims it; the later soft admission
            // must rescue that queued loser using the other approved pool.
            for flow in flows where flow.snapshot.sends == [3] { try flow.answer(3) }
            clock.advance(1)
            for flow in flows where flow.snapshot.answers.isEmpty { flow.flow.coldAuditHedge() }
            try require(flows.allSatisfy { $0.snapshot.sends.contains(3) == fixed },
                        "Concurrent stale snapshots prevented another approved service from participating")
            if fixed {
                clock.advance(1.08)
                for flow in flows where flow.snapshot.answers.isEmpty { try flow.answer(3) }
            } else {
                clock.advance(8)
                for flow in flows { flow.flow.coldAuditDeadline() }
            }
            try require(flows.allSatisfy { $0.snapshot.answers.count == (fixed ? 1 : 0)
                        && $0.snapshot.errors.count == (fixed ? 0 : 1) }, "Concurrent query outcomes differ from control")
            try require(selector.coldAuditQueryCount(scope) == 8,
                        "Concurrent readiness refresh duplicated selector calls or exploration budget")
            for flow in flows { try flow.integrity(expectedSelectorCalls: nil) }
            for flow in flows { for index in flow.snapshot.factories { flow.peer(index)?.acknowledge(duplicate: true) } }
            try require(slots.outstanding == 0, "Concurrent transports leaked native cancellation leases")
            emit(["case": "eight-simultaneous-queries", "fixed": fixed, "initialCandidates": initial,
                  "finalCandidates": flows.map { $0.snapshot.sends }, "selectorCalls": selector.coldAuditQueryCount(scope),
                  "peakNativeLeases": slots.peakLeases])
        }
    }

    static func invariants() throws {
        try check("unknown snapshots do not claim an available external provider") {
            let s = Scenario()
            try require(s.snapshot.sends == [0], "nil availability promoted an unmeasured outsider")
            try s.answer(0); try s.integrity()
        }
        try check("equally unavailable approved providers preserve the original primary") {
            let s = Scenario(slots: Slots(Array(repeating: Capacity(), count: 4)))
            try require(s.snapshot.sends == [0], "Empty pool snapshots invented readiness or discarded the primary")
            try s.answer(0); try s.integrity()
        }
        try check("a currently successful primary stays ahead of unknown reusable candidates") {
            let s = Scenario(slots: Slots([Capacity(0, 1), Capacity(), Capacity(), Capacity(1, 0)]), healthyPrimary: true)
            try require(s.snapshot.sends == [0], "Availability overrode verified healthy primary")
            s.peer(0)?.querySent(); try s.answer(0); try s.integrity()
        }
        try check("a checkpoint keeps its live hedge when the third candidate still has no useful completion window") {
            let slots = Slots([Capacity(0, 1), Capacity(0, 1), Capacity(), Capacity()])
            let s = Scenario(slots: slots, coldHistory: [80, 100, 6_000, nil])
            s.clock.advance(1); s.flow.coldAuditHedge()
            s.clock.advance(5.4)
            if s.flow.coldAuditRotationScheduled { s.flow.coldAuditRotate() }
            try require(s.snapshot.sends == [0, 1] && s.snapshot.live == 2
                        && s.peer(0)?.cancellationReasons.isEmpty == true && s.peer(1)?.cancellationReasons.isEmpty == true,
                        "A checkpoint retired a live hedge without a usable third-candidate window")
            try require(!s.flow.coldAuditRotationScheduled, "Checkpoint without a usable candidate created polling")
            try s.answer(1); try s.integrity()
        }
        try check("reusable third candidate with a slow measured response cannot truncate a live hedge") {
            let slots = Slots([Capacity(0, 1), Capacity(0, 1), Capacity(), Capacity()])
            let s = Scenario(slots: slots)
            s.clock.advance(1); s.flow.coldAuditHedge()
            try require(s.flow.coldAuditRotationScheduled, "Slow-response control did not have a real rotation timer")
            let history = DNSQueryProgressSnapshot(stage: .completed, changedAt: 99,
                transportStartedAt: 92, transportReadyAt: 92.1, tlsStartedAt: 92.1, tlsReadyAt: 92.2,
                querySentAt: 93, responseStartedAt: 98.9, responseCompletedAt: 99)
            s.selector.record(s.selector.beginObservation(scopeKey: s.scope, candidateID: cloudflare.id),
                              milliseconds: 7_000, success: true, transport: .fresh, progress: history)
            slots.set(cloudflare, Capacity(1, 0))
            s.clock.advance(5.4); s.flow.coldAuditRotate()
            try require(s.snapshot.sends == [0, 1] && s.snapshot.live == 2
                        && s.peer(1)?.cancellationReasons.isEmpty == true,
                        "Reusable socket hint erased a measured slow response window")
            try s.answer(1); try s.integrity()
        }
        try check("reuse remains preferred within the same health class and original ties remain stable") {
            let s = Scenario(slots: Slots([Capacity(0, 1), Capacity(1, 0), Capacity(0, 1), Capacity(1, 0)]))
            try require(s.snapshot.sends == [1], "Cold setup displaced existing same-class reusable connection")
            try s.answer(1); try s.integrity()
        }
        try check("unapproved DNSPod is never added even when all approved candidates are blocked") {
            let approved = [google1, google2, cloudflare]
            let slots = Slots([Capacity(), Capacity(), Capacity(), Capacity(1, 0)])
            let s = Scenario(candidates: approved, slots: slots)
            s.clock.advance(1); s.flow.coldAuditHedge(); s.clock.advance(5.4); s.flow.coldAuditRotate()
            try require(!s.snapshot.factories.contains(3), "Provider availability granted DNS policy authority")
            s.clock.advance(8); s.flow.coldAuditDeadline(); try s.integrity()
        }
        try check("single approved service retains its alternative IPs") {
            let third = candidate("https://dns.google/dns-query#203.0.113.77")
            let values = [google1, google2, third]
            let s = Scenario(candidates: values, slots: Slots(Array(repeating: Capacity(0, 1), count: 3), candidates: values))
            s.clock.advance(1); s.flow.coldAuditHedge()
            try require(s.flow.coldAuditRotationScheduled, "Single-provider third attempt lacked an actual scheduled rotation")
            s.clock.advance(5.4); s.flow.coldAuditRotate()
            try require(s.snapshot.sends == [0, 1, 2], "Service diversity removed approved alternate-IP recovery")
            try s.answer(2); try s.integrity()
        }
        try check("mixed approved transports preserve encrypted/plain phase positions") {
            let plain = DNSUpstreamCandidate(upstream: .plain(host: "192.0.2.53", port: 53), bootstrap: nil)
            let values = [google1, plain, google2, dnspod]
            let s = Scenario(candidates: values,
                slots: Slots([Capacity(0, 1), Capacity(1, 0), Capacity(), Capacity()], candidates: values),
                allowPlaintext: true)
            try require(s.snapshot.sends == [0], "Plaintext reuse crossed encrypted phase boundary")
            try s.fail(0)
            try require(s.snapshot.sends == [0, 1], "Approved plaintext phase position changed")
            try s.answer(1); try s.integrity()
        }
        try check("encrypted-only configuration rejects plaintext before opening any factory") {
            let plain = DNSUpstreamCandidate(upstream: .plain(host: "192.0.2.53", port: 53), bootstrap: nil)
            let s = Scenario(candidates: [google1, plain, dnspod])
            try require(s.snapshot.factories.isEmpty && s.snapshot.sends.isEmpty && s.snapshot.errors.count == 1,
                        "Candidate refresh authorized plaintext/system DNS fallback")
        }
        try check("initial denied policy does not create any transport") {
            let s = Scenario(autoSend: false)
            s.permission.revoke(); s.send()
            try require(s.snapshot.factories.isEmpty && s.snapshot.sends.isEmpty && s.snapshot.errors.count == 1,
                        "Initial policy denial reached a factory")
        }
        try check("revoked policy before soft admission prevents the new provider send") {
            let slots = Slots([Capacity(0, 1), Capacity(), Capacity(), Capacity()])
            let s = Scenario(slots: slots)
            slots.set(dnspod, Capacity(1, 0)); s.permission.revoke(); s.clock.advance(1); s.flow.coldAuditHedge()
            try require(s.snapshot.sends == [0] && s.snapshot.errors.isEmpty && s.snapshot.answers.count == 1
                        && s.snapshot.answers[0][3] & 0x0f == 2, "Policy revocation admitted a later available provider")
            try s.integrity()
        }
        try check("factory return rechecks policy before sending") {
            let s = Scenario(factoryInterruption: { permission, _ in permission.revoke() })
            try require(s.snapshot.factories == [0] && s.snapshot.sends.isEmpty && s.snapshot.errors.isEmpty
                        && s.snapshot.answers.count == 1 && s.snapshot.answers[0][3] & 0x0f == 2,
                        "Revoked factory return still sent a query")
            try s.integrity()
        }
        try check("factory return rechecks original deadline before sending") {
            let s = Scenario(factoryInterruption: { _, clock in clock.advance(8) })
            try require(s.snapshot.factories == [0] && s.snapshot.sends.isEmpty && s.snapshot.errors.count == 1,
                        "Expired factory return still sent a query")
            try s.integrity()
        }
        try check("too-late third rescue cannot replace the original deadline") {
            let slots = Slots([Capacity(0, 1), Capacity(0, 1), Capacity(), Capacity()])
            let s = Scenario(slots: slots)
            s.clock.advance(1); s.flow.coldAuditHedge()
            try require(s.flow.coldAuditRotationScheduled, "Deadline control lacked an actual production rotation timer")
            slots.set(dnspod, Capacity(0, 1)); s.clock.advance(7.9); s.flow.coldAuditRotate()
            try require(s.snapshot.sends.count == 2, "Insufficient third-candidate completion budget was ignored")
            s.clock.advance(8); s.flow.coldAuditDeadline()
            try require(s.snapshot.errors.count == 1 && s.snapshot.errors[0] is DNSQueryTimeoutError,
                        "Original deadline did not end the cold queue")
            s.flow.coldAuditHedge(); try s.answer(0)
            try require(s.snapshot.sends.count == 2 && s.snapshot.answers.isEmpty, "Late readiness reopened expired query")
            try s.integrity()
        }
        try check("local terminal failures do not fan out into a newly available provider") {
            for error in [EncryptedDNSQueryFailure.capacity, .policy, .configuration, .cancelled] {
                let slots = Slots([Capacity(0, 1), Capacity(), Capacity(), Capacity()])
                let s = Scenario(slots: slots)
                slots.set(dnspod, Capacity(1, 0)); try s.fail(0, error)
                s.clock.advance(1); s.flow.coldAuditHedge()
                try require(s.snapshot.sends == [0] && s.snapshot.errors.count == 1,
                            "Local failure was mistaken for provider cold-queue congestion")
                let health = s.selector.coldAuditHealth(s.scope, google1.id)
                try require(health.successes == 0 && health.failures == 0, "Local backpressure penalized resolver health")
                try s.integrity()
            }
        }
        try check("client cancellation fences late callbacks and waits for actual child receipts") {
            let slots = Slots([Capacity(0, 1), Capacity(), Capacity(), Capacity()])
            let s = Scenario(slots: slots, hold: true), done = DispatchSemaphore(value: 0)
            slots.set(dnspod, Capacity(1, 0))
            s.flow.cancel { done.signal() }; s.flow.coldAuditDrain()
            s.clock.advance(1); s.flow.coldAuditHedge(); try s.answer(0)
            try require(s.snapshot.sends == [0] && s.snapshot.answers.isEmpty && s.snapshot.errors.isEmpty,
                        "Cancelled query resumed or delivered a late answer")
            try require(done.wait(timeout: .now()) == .timedOut, "Cancellation completed before physical child receipt")
            s.peer(0)?.acknowledge(duplicate: true)
            try require(done.wait(timeout: .now() + 2) == .success && done.wait(timeout: .now()) == .timedOut,
                        "Cancellation acknowledgement leaked or completed twice")
            try s.integrity()
        }
    }

    static func main() {
        do {
            let fixed = CommandLine.arguments.dropFirst().first != "before"
            try regressions(fixed: fixed); try invariants()
            print("DNS cold provider admission checks passed: \(cases) cases, \(assertions) assertions; expected=\(fixed ? "after" : "before")")
        } catch {
            fputs("FAIL DNS cold provider admission: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}

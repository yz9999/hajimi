// Test-only adapters appended to exact production declarations. A controlled
// monotonic clock invokes real owner-queue callbacks; peers never open sockets.
import CoreFoundation

private extension DNSAdaptiveQueryDatagram {
    func recoveryAuditPauseTimers() {
        deadlineTimer?.cancel()
        for attempt in active.values {
            attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel()
        }
    }
    func recoveryAuditDrain() { queue.sync { recoveryAuditPauseTimers() } }
    func recoveryAuditHedge() {
        queue.sync {
            if let primaryToken { startHedge(after: primaryToken) }
            recoveryAuditPauseTimers()
        }
    }
    func recoveryAuditLiveHedge() {
        queue.sync {
            if let token = active.first(where: { $0.value.hedgeTimer != nil })?.key { startHedge(after: token) }
            recoveryAuditPauseTimers()
        }
    }
    func recoveryAuditRotate() {
        queue.sync {
            if let token = active.keys.first(where: { $0 != primaryToken }) { rotateHedge(token) }
            recoveryAuditPauseTimers()
        }
    }
    func recoveryAuditDeadline() {
        queue.sync { overallDeadlineReached(); recoveryAuditPauseTimers() }
        recoveryAuditDrain()
    }
    var recoveryAuditState: (attempts: Int, active: Int, deadline: TimeInterval) {
        queue.sync { (attemptCount, active.count, deadline) }
    }
}

@main private enum DNSPostSendRecoveryMain {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    static var cases = 0, assertions = 0
    static var casePrefix: String { CommandLine.arguments.dropFirst(2).first ?? "" }
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        assertions += 1
        guard condition() else { throw Failure(text: message) }
    }
    static func check(_ name: String, _ body: () throws -> Void) throws {
        guard casePrefix.isEmpty || name.hasPrefix(casePrefix) else { return }
        try body(); cases += 1; print("PASS", name)
    }
    static func emit(_ value: [String: Any]) {
        print(String(data: try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), encoding: .utf8)!)
    }
    static func candidate(_ value: String) -> DNSUpstreamCandidate {
        DNSUpstreamCandidate(upstream: .doh(DoHEndpoint(value)!), bootstrap: nil)
    }
    static let dnspod = candidate("https://doh.pub/dns-query#1.12.12.12")
    static let cloudflare = candidate("https://cloudflare-dns.com/dns-query#1.1.1.1")
    static let google = candidate("https://dns.google/dns-query#8.8.8.8")
    static var approved: [DNSUpstreamCandidate] { [dnspod, cloudflare, google] }

    final class Clock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ elapsed: TimeInterval) { lock.lock(); value = 100 + elapsed; lock.unlock() }
    }
    final class Permission {
        private let lock = NSLock()
        private var value = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return value }
        func revoke() { lock.lock(); value = false; lock.unlock() }
    }
    final class Slots {
        private let lock = NSLock()
        private var values: [String: (reusable: Int, cold: Int)] = [:]
        init(_ candidates: [DNSUpstreamCandidate]) {
            for candidate in candidates { values[candidate.id] = (0, 1) }
        }
        func availability(_ candidate: DNSUpstreamCandidate) -> (reusable: Int, cold: Int)? {
            lock.lock(); defer { lock.unlock() }; return values[candidate.id]
        }
        func set(_ candidate: DNSUpstreamCandidate, reusable: Int = 0, cold: Int = 1) {
            lock.lock(); values[candidate.id] = (reusable, cold); lock.unlock()
        }
    }
    final class MemoryPeer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging,
        DNSQueryExecutionContextAccepting, DNSQueryTransportEvidenceProviding {
        let receive: (Data) -> Void, failure: (Error) -> Void
        private let lock = NSLock()
        private let clock: Clock, evidence: DNSQueryTransportEvidence
        private let onSend: () -> Void, onCancel: () -> Void
        private let holdAcknowledgements: Bool
        private var context: DNSQueryExecutionContext?
        private let traceDiagnostics: NetworkPerformanceDiagnostics?
        private var nativeTrace: DNSConnectionAttemptTrace?
        private var cancelled = false, acknowledged = false
        private var acknowledgementValues: [() -> Void] = []
        private var reasons: [DNSAttemptCancellationReason] = []
        init(clock: Clock, evidence: DNSQueryTransportEvidence, hold: Bool, nativeTrace: Bool,
             onSend: @escaping () -> Void, onCancel: @escaping () -> Void,
             receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            self.clock = clock; self.evidence = evidence; holdAcknowledgements = hold
            traceDiagnostics = nativeTrace ? NetworkPerformanceDiagnostics() : nil
            self.onSend = onSend; self.onCancel = onCancel; self.receive = receive; self.failure = failure
        }
        func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
            let trace = traceDiagnostics?.beginDNSAttempt(requestID: UUID(), transport: .doh,
                purpose: .query, serverName: "memory.fixture.invalid", endpointIdentity: "memory-peer",
                address: "192.0.2.53", context: context)
            lock.lock(); self.context = context; nativeTrace = trace; lock.unlock()
        }
        func send(_ data: Data) {
            lock.lock(); let context = self.context; lock.unlock()
            if evidence == .reused { context?.record(.connectionReused, at: clock.now()) }
            else if evidence != .notStarted { context?.record(.transportStarted, at: clock.now()) }
            onSend()
        }
        func sent() {
            lock.lock(); let context = self.context; lock.unlock()
            context?.record(.transportReady, at: clock.now())
            context?.record(.tlsStarted, at: clock.now())
            context?.record(.tlsReady, at: clock.now())
            context?.record(.querySent, at: clock.now())
        }
        func record(_ event: DNSConnectionAttemptEvent) {
            lock.lock(); let context = self.context; lock.unlock()
            context?.record(event, at: clock.now())
        }
        func recordNative(_ event: DNSConnectionAttemptEvent, error: Error? = nil) throws {
            lock.lock(); let trace = nativeTrace; lock.unlock()
            guard let trace else { throw Failure(text: "Native-proof case omitted its real production trace") }
            trace.record(event, error: error)
        }
        func cancelNative(_ reason: DNSAttemptCancellationReason) throws {
            lock.lock(); let trace = nativeTrace; lock.unlock()
            guard let trace else { throw Failure(text: "Native cancellation omitted its production trace") }
            trace.cancel(reason)
        }
        func obsoleteTraceAfterNewGeneration() throws -> DNSConnectionAttemptTrace {
            lock.lock(); let old = nativeTrace, context = self.context; lock.unlock()
            guard let old, let context, let diagnostics = traceDiagnostics else {
                throw Failure(text: "Generation control omitted its real production trace/context")
            }
            let trace = diagnostics.beginDNSAttempt(requestID: UUID(), transport: .doh,
                purpose: .query, serverName: "memory.fixture.invalid", endpointIdentity: "new-memory-generation",
                address: "192.0.2.53", context: context)
            lock.lock(); nativeTrace = trace; lock.unlock()
            return old
        }
        var hasNativeResetEvidence: Bool {
            lock.lock(); let context = self.context; lock.unlock()
            return context?.hasConnectionResetBeforeCancellation ?? false
        }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { evidence }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) { cancel(reason: .callerCancelled, completion: completion) }
        func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
            lock.lock(); let first = !cancelled; cancelled = true
            let trace = nativeTrace
            if first { reasons.append(reason) }
            if holdAcknowledgements && !acknowledged { acknowledgementValues.append(completion); lock.unlock() }
            else { lock.unlock(); completion() }
            if first { trace?.cancel(reason) }
            if first { onCancel() }
        }
        func acknowledge(duplicate: Bool = false) {
            lock.lock(); acknowledged = true; let values = acknowledgementValues
            acknowledgementValues.removeAll(); lock.unlock()
            for value in values { value(); if duplicate { value() } }
        }
        var inheritedDeadline: TimeInterval? { lock.lock(); defer { lock.unlock() }; return context?.absoluteDeadline }
        var cancellationReasons: [DNSAttemptCancellationReason] { lock.lock(); defer { lock.unlock() }; return reasons }
    }
    final class Scenario {
        let clock = Clock(), permission = Permission()
        let candidates: [DNSUpstreamCandidate], slots: Slots
        let selector: DNSAdaptiveUpstreamSelector, scope = "post-send-recovery"
        let query: Data
        let lock = NSLock()
        private var peers: [MemoryPeer] = [], factories: [Int] = [], sends: [Int] = []
        private var live = Set<Int>(), peak = 0, sameCandidatePeak = 0
        private var answerValues: [Data] = [], errorValues: [Error] = []
        var flow: DNSAdaptiveQueryDatagram!
        init(healthyPrimary: Bool = true, evidence: DNSQueryTransportEvidence = .fresh,
             type: UInt16 = 1, queryClass: UInt16 = 1, candidates: [DNSUpstreamCandidate] = approved,
             hold: Bool = false, autoSend: Bool = true,
             historyScope: String? = nil,
             primaryCancellationAdvance: TimeInterval? = nil,
             cancellationAdvanceSerial: Int = 0, nativeTrace: Bool = false,
             allowPlaintext: Bool = false,
             cancellationObserver: ((Int, Slots, Clock) -> Void)? = nil,
             factoryCheck: ((Int, Int, Permission, Clock) throws -> Void)? = nil) {
            self.candidates = candidates; slots = Slots(candidates)
            selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            var question = DNSMessageInspection.query(for: "post-send.fixture.invalid", type: type, id: 0x3721)!
            question[question.endIndex - 2] = UInt8(truncatingIfNeeded: queryClass >> 8)
            question[question.endIndex - 1] = UInt8(truncatingIfNeeded: queryClass)
            query = question
            if healthyPrimary {
                let key = DNSAdaptiveUpstreamSelector.queryHealthScope(scopeKey: historyScope ?? scope, query: query)
                _ = selector.orderedCandidates(scopeKey: key, candidateIDs: candidates.map(\.id))
                selector.record(selector.beginObservation(scopeKey: key, candidateID: candidates[0].id),
                                milliseconds: 80, success: true, transport: .fresh)
            }
            flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector, scopeKey: scope,
                queue: DispatchQueue(label: "post-send-memory-callback"), permitted: permission.permits,
                factory: { [weak self] candidate, _, receive, failure in
                    guard let self, let index = self.candidates.firstIndex(where: { $0.id == candidate.id }) else {
                        throw Failure(text: "Factory received unapproved DNS candidate")
                    }
                    self.lock.lock(); let serial = self.peers.count; self.factories.append(index); self.lock.unlock()
                    try factoryCheck?(index, serial, self.permission, self.clock)
                    let peer = MemoryPeer(clock: self.clock, evidence: serial == 0 ? evidence : .fresh,
                        hold: hold, nativeTrace: nativeTrace, onSend: { [weak self] in
                            guard let self else { return }
                            self.lock.lock(); self.sends.append(index); self.live.insert(serial)
                            self.peak = max(self.peak, self.live.count)
                            let same = self.live.filter { self.factories[$0] == index }.count
                            self.sameCandidatePeak = max(self.sameCandidatePeak, same); self.lock.unlock()
                        }, onCancel: { [weak self] in
                            guard let self else { return }; self.lock.lock(); self.live.remove(serial); self.lock.unlock()
                            if serial == cancellationAdvanceSerial, let primaryCancellationAdvance {
                                self.clock.advance(primaryCancellationAdvance)
                            }
                            cancellationObserver?(serial, self.slots, self.clock)
                        }, receive: receive, failure: failure)
                    self.lock.lock(); self.peers.append(peer); self.lock.unlock()
                    return peer
                }, receive: { [weak self] answer in
                    guard let self else { return }; self.lock.lock(); self.answerValues.append(answer); self.lock.unlock()
                }, failure: { [weak self] error in
                    guard let self else { return }; self.lock.lock(); self.errorValues.append(error); self.lock.unlock()
                }, availability: slots.availability, timeout: 8, clock: clock.now,
                protectProxyFallback: true, allowApprovedProxyPlaintext: allowPlaintext)
            if autoSend { flow.send(query); flow.recoveryAuditDrain() }
        }
        deinit {
            flow?.cancel(); flow?.recoveryAuditDrain()
            for peer in allPeers { peer.acknowledge() }
        }
        var allPeers: [MemoryPeer] { lock.lock(); defer { lock.unlock() }; return peers }
        func peer(_ serial: Int) throws -> MemoryPeer {
            lock.lock(); defer { lock.unlock() }
            guard peers.indices.contains(serial) else { throw Failure(text: "Missing peer serial \(serial)") }
            return peers[serial]
        }
        func hedge(at elapsed: Double = 0.8) throws {
            clock.advance(elapsed); flow.recoveryAuditHedge()
            try require(snapshot.sends.count == 2, "Control did not establish two live attempts")
        }
        func fail(_ serial: Int, error: Error = EncryptedDNSQueryFailure.network) throws {
            try peer(serial).failure(error); flow.recoveryAuditDrain()
        }
        func answer(_ serial: Int) throws {
            var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail)!
            answer[3] &= 0xf0
            try peer(serial).receive(answer); flow.recoveryAuditDrain()
        }
        func seed(_ index: Int, milliseconds: Double = 90) {
            let key = DNSAdaptiveUpstreamSelector.queryHealthScope(scopeKey: scope, query: query)
            selector.record(selector.beginObservation(scopeKey: key, candidateID: candidates[index].id),
                            milliseconds: milliseconds, success: true, transport: .fresh)
        }
        func prepareSentFailure() throws {
            try require(snapshot.sends == [0], "Verified DNSPod was not primary")
            try hedge(); clock.advance(2); try peer(0).sent(); clock.advance(2.2)
        }
        func prepareColdFailure(omit: [DNSConnectionAttemptEvent] = [], partial: Bool = false) throws {
            try require(snapshot.sends == [0], "First lookup did not use the configured approved primary")
            clock.advance(0.0635)
            if !omit.contains(.transportReady) { try peer(0).record(.transportReady) }
            clock.advance(0.0636); try peer(0).record(.tlsStarted)
            try hedge(at: 0.8)
            clock.advance(1.5521)
            if !omit.contains(.tlsReady) { try peer(0).record(.tlsReady) }
            clock.advance(1.5526)
            if !omit.contains(.querySent) { try peer(0).record(.querySent) }
            if partial { try peer(0).record(.responseStarted) }
            clock.advance(1.6093)
        }
        func prepareNativeReset(_ failed: Int, sent: Bool = false,
                                omit: [DNSConnectionAttemptEvent] = []) throws {
            try require(snapshot.sends == [0], "Native control did not retain the approved primary")
            if failed == 1 { try hedge(at: 0.8) }
            clock.advance(failed == 0 ? 0.0635 : 0.8527)
            if !omit.contains(.transportReady) { try peer(failed).record(.transportReady) }
            clock.advance(failed == 0 ? 0.0636 : 0.8528)
            if !omit.contains(.tlsStarted) { try peer(failed).record(.tlsStarted) }
            if failed == 0 { try hedge(at: 0.8) }
            if sent {
                clock.advance(failed == 0 ? 1.5521 : 0.92486)
                if !omit.contains(.tlsReady) { try peer(failed).record(.tlsReady) }
                clock.advance(failed == 0 ? 1.5526 : 0.925438)
                if !omit.contains(.querySent) { try peer(failed).record(.querySent) }
            }
            clock.advance(failed == 0 ? 1.6093 : (sent ? 0.947818 : 0.9053))
        }
        var snapshot: (factories: [Int], sends: [Int], live: Int, peak: Int, same: Int, answers: [Data], errors: [Error]) {
            lock.lock(); defer { lock.unlock() }
            return (factories, sends, live.count, peak, sameCandidatePeak, answerValues, errorValues)
        }
        func integrity() throws {
            let value = snapshot, state = flow.recoveryAuditState
            try require(value.factories.count <= 3 && state.attempts <= 3, "Recovery exceeded three-attempt budget")
            try require(value.peak <= 2 && state.active <= 2, "Recovery exceeded two-live budget")
            try require(value.same <= 1, "Recovery overlapped two attempts to the same candidate")
            try require(value.factories.allSatisfy(candidates.indices.contains), "Recovery invented an unapproved endpoint")
            try require(state.attempts == value.factories.count, "Factory count disagrees with logical attempts")
            try require(state.deadline == 108, "Recovery extended the original absolute deadline")
            try require(allPeers.filter { !$0.cancellationReasons.contains(.policyChanged) }.allSatisfy {
                $0.inheritedDeadline == 108
            }, "A sent child failed to inherit the same original deadline")
            try require(value.answers.count + value.errors.count <= 1, "Client completed more than once")
        }
        func trace(_ name: String, fixed: Bool) {
            let value = snapshot
            emit(["case": name, "fixed": fixed, "factories": value.factories, "sends": value.sends,
                  "answers": value.answers.count, "errors": value.errors.count,
                  "maximumLive": value.peak, "maximumSameCandidateLive": value.same,
                  "deadline": flow.recoveryAuditState.deadline, "atMilliseconds": (clock.now() - 100) * 1000])
        }
    }

    static func positiveControls(fixed: Bool) throws {
        let errors: [(String, Error)] = [
            ("native-reset", NWError.posix(.ECONNRESET)),
            ("original-posix-reset", NSError(domain: NSPOSIXErrorDomain, code: 54)),
            ("classified-network", EncryptedDNSQueryFailure.network),
        ]
        for type in [UInt16(1), 28] {
            for (label, error) in errors {
                try check("known fresh provider post-send \(label) type \(type) recovers within original three slots") {
                    let s = Scenario(type: type)
                    try s.prepareSentFailure(); try s.fail(0, error: error)
                    try require(s.snapshot.factories == (fixed ? [0, 1, 0] : [0, 1, 2]),
                                "Last slot did not match known-provider before/after control")
                    try require(s.snapshot.answers.isEmpty && s.snapshot.errors.isEmpty, "Failure finished before recovery opportunity")
                    if fixed { s.clock.advance(2.28); try s.peer(2).sent(); try s.answer(2) }
                    else { s.clock.advance(8); s.flow.recoveryAuditDeadline() }
                    try require(s.snapshot.answers.count == (fixed ? 1 : 0)
                                && s.snapshot.errors.count == (fixed ? 0 : 1), "Original control failure or bounded recovery was not reproduced")
                    try require(s.snapshot.factories.count == 3, "Recovery added or skipped a logical attempt")
                    try s.integrity(); s.trace("\(label)-qtype-\(type)", fixed: fixed)
                }
            }
        }
        try check("in-flight success survives a concurrent failure and authorizes bounded recovery") {
            let s = Scenario(healthyPrimary: false)
            try s.hedge(); s.clock.advance(2); try s.peer(0).sent()
            s.clock.advance(2.005); s.seed(0)
            s.clock.advance(2.1)
            s.selector.record(s.selector.beginObservation(scopeKey: s.scope, candidateID: dnspod.id),
                              milliseconds: 2100, success: false, transport: .fresh)
            s.clock.advance(2.2); try s.fail(0)
            try require(s.snapshot.sends == (fixed ? [0, 1, 0] : [0, 1, 2]),
                        "Recovery missed an authenticated success learned after this query admission")
            if fixed { s.clock.advance(2.28); try s.answer(2) }
            else { s.clock.advance(8); s.flow.recoveryAuditDeadline() }
            try require(s.snapshot.answers.count == (fixed ? 1 : 0), "In-flight success did not improve the original control outcome")
            try s.integrity(); s.trace("concurrent-success-then-cooldown", fixed: fixed)
        }
    }

    static func eligibilityControls() throws {
        try check("connection failure before querySent retains provider diversity") {
            let s = Scenario(); try s.hedge(); s.clock.advance(2.2); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Unsent connection failure retried the primary")
            try s.integrity()
        }
        try check("unmeasured TXT retains the existing verified-history requirement") {
            let s = Scenario(healthyPrimary: false, type: 16); try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Unmeasured provider consumed a recovery slot")
            try s.integrity()
        }
        try check("success history from a different route scope cannot authorize recovery") {
            let s = Scenario(type: 16, historyScope: "other-direct-interface-node"); try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Recovery borrowed health across scope boundary")
            try s.integrity()
        }
        try check("querySent without authenticated TLS readiness cannot authorize recovery") {
            let s = Scenario(); try s.hedge(); s.clock.advance(2)
            try s.peer(0).record(.querySent); s.clock.advance(2.2); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Missing authenticated TLS readiness triggered recovery")
            try s.integrity()
        }
        try check("completed response cannot be replaced by post-send network recovery") {
            let s = Scenario(); try s.prepareSentFailure(); try s.peer(0).record(.responseComplete)
            try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Already completed response triggered a duplicate recovery query")
            try s.integrity()
        }
        try check("reused-only reset does not pose as measured fresh connection failure") {
            let s = Scenario(evidence: .reused); try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Reused-only transport triggered fresh-path recovery")
            try s.integrity()
        }
        try check("reused-then-fresh cannot acquire strictly-fresh recovery privilege") {
            let s = Scenario(evidence: .reusedThenFresh); try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Reused-then-fresh transport acquired fresh-only recovery")
            try s.integrity()
        }
        try check("healthy remaining provider keeps the final candidate slot") {
            let s = Scenario(); try s.prepareSentFailure(); s.seed(2); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Primary retry displaced a proven healthy remaining provider")
            s.clock.advance(2.28); try s.answer(2); try s.integrity()
        }
        try check("reusable remaining provider keeps the final candidate slot") {
            let s = Scenario(); try s.prepareSentFailure(); s.slots.set(google, reusable: 1); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Primary retry displaced a reusable approved provider")
            s.clock.advance(2.28); try s.answer(2); try s.integrity()
        }
        try check("proven available provider outside the original prefix keeps a rescue opportunity") {
            let extra = candidate("https://dns.alidns.com/dns-query#223.5.5.5")
            let s = Scenario(candidates: approved + [extra]); try s.prepareSentFailure(); s.seed(3); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 3], "Recovery displaced a proven available fourth approved provider")
            s.clock.advance(2.28); try s.answer(2); try s.integrity()
        }
        try check("an exhausted primary pool cannot be treated as recoverable capacity") {
            let s = Scenario(); try s.prepareSentFailure(); s.slots.set(dnspod, cold: 0); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Recovery queued into an explicitly exhausted primary pool")
            try s.integrity()
        }
        try check("recovery cannot start without an admitted different provider hedge") {
            let s = Scenario(); s.clock.advance(0.2); try s.peer(0).sent(); s.clock.advance(0.3); try s.fail(0)
            try require(s.snapshot.sends == [0, 1], "First failure spent another slot on the same provider")
            try s.integrity()
        }
        try check("two IPs of one provider retain the last cross-provider rescue opportunity") {
            let sibling = candidate("https://doh.pub/dns-query#120.53.53.53")
            let s = Scenario(candidates: [dnspod, sibling, google])
            s.slots.set(google, cold: 0)
            try s.hedge()
            try require(s.snapshot.sends == [0, 1], "Control did not admit both IPs of the same provider")
            try require(s.candidates[0].upstream.resolverServiceID == s.candidates[1].upstream.resolverServiceID,
                        "Same-provider control accidentally used a different resolver service")
            s.clock.advance(2); try s.peer(0).sent(); s.clock.advance(2.2)
            s.slots.set(google, cold: 1); try s.fail(0, error: NWError.posix(.ECONNRESET))
            try require(s.snapshot.sends == [0, 1, 2], "Third same-provider dial erased the cross-provider rescue opportunity")
            s.clock.advance(2.28); try s.answer(2); try s.integrity()
        }
        try check("an approved plaintext hedge cannot authorize extra encrypted same-provider recovery") {
            let plain = DNSUpstreamCandidate(upstream: .plain(host: "192.0.2.53", port: 53), bootstrap: nil)
            let s = Scenario(candidates: [dnspod, plain, google], allowPlaintext: true)
            try s.prepareSentFailure(); try s.fail(0, error: NWError.posix(.ECONNRESET))
            try require(s.snapshot.sends == [0, 1, 2], "Plaintext hedge was counted as an encrypted cross-provider attempt")
            s.clock.advance(2.28); try s.answer(2); try s.integrity()
        }
        try check("a sent healthy hedge failure cannot retry as the original primary") {
            let s = Scenario(); try s.hedge(); s.seed(1); s.clock.advance(2); try s.peer(1).sent()
            s.clock.advance(2.2); try s.fail(1)
            try require(s.snapshot.sends == [0, 1, 2], "Failed backup acquired original-primary retry privilege")
            try s.integrity()
        }
        try check("one approved candidate cannot create additional attempt slots") {
            let s = Scenario(candidates: [dnspod]); s.clock.advance(2); try s.peer(0).sent()
            s.clock.advance(2.2); try s.fail(0)
            try require(s.snapshot.sends == [0] && s.snapshot.errors.count == 1, "Single candidate was retried outside available slots")
            try s.integrity()
        }
        try check("two approved candidates cannot create a third attempt slot") {
            let s = Scenario(candidates: [dnspod, cloudflare]); try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.sends == [0, 1], "Two-candidate plan grew a third logical slot")
            try s.integrity()
        }
        for (label, error) in [
            ("timeout", EncryptedDNSQueryFailure.timeout),
            ("authentication", .authentication), ("capacity", .capacity),
            ("policy", .policy), ("configuration", .configuration),
            ("cancelled", .cancelled), ("invalid-response", .invalidResponse), ("unknown", .other),
        ] {
            try check("\(label) cannot become a post-send network recovery") {
                let s = Scenario(); try s.prepareSentFailure(); try s.fail(0, error: error)
                try require(s.snapshot.sends.filter { $0 == 0 }.count == 1, "Non-network failure retried the primary")
                if error == .capacity {
                    try require(s.snapshot.sends == [0, 1], "Capacity failure fanned out a new connection")
                }
                if [.policy, .configuration, .cancelled].contains(error) {
                    try require(s.snapshot.errors.count == 1 && s.snapshot.live == 0, "Local terminal failure did not close the query")
                }
                if error == .authentication {
                    if case .failure(let barrier)? = s.flow.proxyFallbackBarrier() {
                        try require(EncryptedDNSQueryFailure.classify(barrier) == .authentication, "Authentication barrier was replaced")
                    } else { throw Failure(text: "Authentication failure lost its fallback deny barrier") }
                }
                try s.integrity()
            }
        }
        try check("silent sent PTR remains bounded by original timeout without primary replay") {
            let s = Scenario(type: 12); try s.prepareSentFailure()
            s.clock.advance(5.4); s.flow.recoveryAuditRotate()
            try require(s.snapshot.sends == [0, 1, 2], "PTR silence created an unsupported primary replay")
            s.clock.advance(8); s.flow.recoveryAuditDeadline()
            try require(s.snapshot.answers.isEmpty && s.snapshot.errors.count == 1, "PTR silence did not keep the original deadline")
            try s.integrity()
        }
        try check("remaining budget too short cannot fund the primary recovery") {
            let s = Scenario(); try s.hedge(); s.clock.advance(7.98); try s.peer(0).sent()
            s.clock.advance(7.99); try s.fail(0)
            try require(s.snapshot.sends.filter { $0 == 0 }.count == 1, "Recovery started without its measured completion window")
            s.clock.advance(8); s.flow.recoveryAuditDeadline(); try s.integrity()
        }
        try check("synchronous cancellation work rechecks remaining recovery budget") {
            let s = Scenario(primaryCancellationAdvance: 7.9); try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Recovery trusted its old budget after synchronous cancellation consumed time")
            try require(s.clock.now() == 107.9, "Control did not consume time inside the actual cancellation callback")
            s.clock.advance(8); s.flow.recoveryAuditDeadline(); try s.integrity()
        }
        try check("original deadline blocks all new admission") {
            let s = Scenario(); try s.hedge(); s.clock.advance(7.9); try s.peer(0).sent()
            s.clock.advance(8); try s.fail(0); s.flow.recoveryAuditDeadline()
            try require(s.snapshot.sends == [0, 1] && s.snapshot.errors.count == 1, "Expired query admitted a recovery transport")
            try s.integrity()
        }
        try check("policy revocation before failure rejects candidate recovery") {
            let s = Scenario(); try s.prepareSentFailure(); s.permission.revoke(); try s.fail(0)
            try require(s.snapshot.sends == [0, 1] && s.snapshot.answers.count == 1
                        && s.snapshot.answers[0][3] & 0x0f == 2, "Revoked policy admitted a replacement or lost SERVFAIL")
            try s.integrity()
        }
    }

    static func firstLookupControls(enabled: Bool, verifiedRecovery: Bool) throws {
        let failures: [(String, Error)] = [
            ("native-reset", NWError.posix(.ECONNRESET)),
            ("original-posix-reset", NSError(domain: NSPOSIXErrorDomain, code: 54)),
            ("classified-network", EncryptedDNSQueryFailure.network),
        ]
        for type in [UInt16(1), 28, 64, 65] {
            for (label, error) in failures {
                try check("first lookup reset \(label) type \(type) closes the Build41 cold-history gap") {
                    let s = Scenario(healthyPrimary: false, type: type)
                    let scope = DNSAdaptiveUpstreamSelector.queryHealthScope(scopeKey: s.scope, query: s.query)
                    try require(s.selector.knownLatencyMilliseconds(scopeKey: scope, candidateID: dnspod.id) == nil,
                                "Cold-history fixture invented a successful DNS response")
                    try s.prepareColdFailure(); try s.fail(0, error: error)
                    try require(s.snapshot.sends == (enabled ? [0, 1, 0] : [0, 1, 2]),
                                "First authenticated sent lookup did not use the expected bounded recovery slot")
                    try require(s.snapshot.answers.isEmpty && s.snapshot.errors.isEmpty,
                                "First reset delivered a premature final result")
                    try require(s.selector.knownLatencyMilliseconds(scopeKey: scope, candidateID: dnspod.id) == nil,
                                "Transport-only evidence was recorded as successful DNS health")
                    if enabled {
                        s.clock.advance(1.72); try s.peer(2).sent()
                        s.clock.advance(1.78); try s.answer(2)
                    } else {
                        s.clock.advance(8); s.flow.recoveryAuditDeadline()
                    }
                    try require(s.snapshot.answers.count == (enabled ? 1 : 0)
                                && s.snapshot.errors.count == (enabled ? 0 : 1),
                                "Build41 timeout/new first-lookup recovery control outcome disagrees")
                    try require(s.snapshot.factories.count == 3, "Cold recovery created an additional attempt slot")
                    try s.integrity(); s.trace("first-lookup-\(label)-qtype-\(type)", fixed: enabled)
                }
            }
        }
        for missing in [DNSConnectionAttemptEvent.transportReady, .tlsReady, .querySent] {
            try check("first lookup missing \(missing.rawValue) cannot use cold-history recovery") {
                let s = Scenario(healthyPrimary: false, type: 28)
                try s.prepareColdFailure(omit: [missing]); try s.fail(0)
                try require(s.snapshot.sends == [0, 1, 2], "Incomplete first-lookup transport evidence retried primary")
                try s.integrity()
            }
        }
        try check("first lookup partial response cannot use cold-history recovery") {
            let s = Scenario(healthyPrimary: false, type: 28)
            try s.prepareColdFailure(partial: true); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Partial first response acquired unverified recovery privilege")
            try s.integrity()
        }
        try check("first lookup completed response cannot be replayed") {
            let s = Scenario(healthyPrimary: false, type: 28)
            try s.prepareColdFailure(); try s.peer(0).record(.responseComplete); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Completed response was replayed by cold-history recovery")
            try s.integrity()
        }
        for evidence in [DNSQueryTransportEvidence.notStarted, .unknown, .reused, .reusedThenFresh] {
            try check("first lookup transport \(evidence) cannot pose as strictly fresh") {
                let s = Scenario(healthyPrimary: false, evidence: evidence, type: 28)
                try s.prepareColdFailure(); try s.fail(0)
                try require(s.snapshot.sends == [0, 1, 2], "Non-fresh first query retried primary")
                try s.integrity()
            }
        }
        for type in [UInt16(2), 5, 6, 12, 15, 16, 33, 252, 255] {
            try check("first lookup type \(type) retains the verified-history requirement") {
                let s = Scenario(healthyPrimary: false, type: type)
                try s.prepareColdFailure(); try s.fail(0)
                try require(s.snapshot.sends == [0, 1, 2], "Unsupported record type acquired first-lookup replay")
                try s.integrity()
            }
        }
        for queryClass in [UInt16(0), 3, 255] {
            try check("first lookup class \(queryClass) cannot use IN-only recovery") {
                let s = Scenario(healthyPrimary: false, type: 28, queryClass: queryClass)
                try s.prepareColdFailure(); try s.fail(0)
                try require(s.snapshot.sends == [0, 1, 2], "Non-IN query acquired first-lookup replay")
                try s.integrity()
            }
        }
        for (label, error) in [
            ("timeout", EncryptedDNSQueryFailure.timeout), ("authentication", .authentication),
            ("capacity", .capacity), ("policy", .policy), ("configuration", .configuration),
            ("cancelled", .cancelled), ("invalid-response", .invalidResponse), ("unknown", .other),
        ] {
            try check("first lookup \(label) cannot be promoted to typed-network recovery") {
                let s = Scenario(healthyPrimary: false, type: 28)
                try s.prepareColdFailure(); try s.fail(0, error: error)
                try require(s.snapshot.sends.filter { $0 == 0 }.count == 1, "Non-network first failure retried primary")
                if error == .authentication {
                    if case .failure(let barrier)? = s.flow.proxyFallbackBarrier() {
                        try require(EncryptedDNSQueryFailure.classify(barrier) == .authentication,
                                    "First authentication failure lost deny barrier")
                    } else { throw Failure(text: "First authentication failure lost fallback barrier") }
                }
                if error == .capacity { try require(s.snapshot.sends == [0, 1], "First capacity failure fanned out") }
                try s.integrity()
            }
        }
        try check("first lookup cannot replace a measured remaining approved candidate") {
            let s = Scenario(healthyPrimary: false, type: 28)
            try s.prepareColdFailure(); s.seed(2); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Cold recovery displaced a proven approved alternative")
            try s.integrity()
        }
        try check("first lookup cannot replace a reusable remaining approved candidate") {
            let s = Scenario(healthyPrimary: false, type: 28)
            try s.prepareColdFailure(); s.slots.set(google, reusable: 1); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Cold recovery displaced a reusable approved alternative")
            try s.integrity()
        }
        try check("first lookup cannot recover into exhausted primary capacity") {
            let s = Scenario(healthyPrimary: false, type: 28)
            try s.prepareColdFailure(); s.slots.set(dnspod, cold: 0); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Cold recovery ignored primary capacity")
            try s.integrity()
        }
        try check("first lookup must retain a different encrypted service hedge") {
            let sibling = candidate("https://doh.pub/dns-query#120.53.53.53")
            let s = Scenario(healthyPrimary: false, type: 28, candidates: [dnspod, sibling, google])
            s.slots.set(google, cold: 0); try s.prepareColdFailure(); s.slots.set(google, cold: 1); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Same-service hedge sponsored unmeasured primary retry")
            try s.integrity()
        }
        try check("first lookup checks its original remaining completion window") {
            let s = Scenario(healthyPrimary: false, type: 28); try s.prepareColdFailure()
            s.clock.advance(7.99); try s.fail(0)
            try require(s.snapshot.sends.filter { $0 == 0 }.count == 1, "Cold recovery extended its minimum window")
            s.clock.advance(8); s.flow.recoveryAuditDeadline(); try s.integrity()
        }
        try check("first lookup rechecks its window after synchronous primary cancellation") {
            let s = Scenario(healthyPrimary: false, type: 28, primaryCancellationAdvance: 7.99)
            try s.prepareColdFailure(); try s.fail(0)
            try require(s.snapshot.sends.filter { $0 == 0 }.count == 1 && s.clock.now() == 107.99,
                        "Cold recovery spent a stale budget after cancellation")
            s.clock.advance(8); s.flow.recoveryAuditDeadline(); try s.integrity()
        }
        try check("first lookup policy revocation at factory cannot send recovered query") {
            let s = Scenario(healthyPrimary: false, type: 28,
                factoryCheck: { _, serial, permission, _ in if serial == 2 { permission.revoke() } })
            try s.prepareColdFailure(); try s.fail(0)
            try require(s.snapshot.factories == (enabled ? [0, 1, 0] : [0, 1, 2]), "First recovery missed factory authority fence")
            try require(s.snapshot.sends == [0, 1] && s.snapshot.answers.count == 1
                        && s.snapshot.answers[0][3] & 0x0f == 2, "Factory revocation authorized first-query send")
            try s.integrity()
        }
        for type in [UInt16(12), 16] {
            try check("verified type \(type) keeps legacy recovery despite a partial first response") {
                let s = Scenario(type: type); try s.prepareColdFailure(partial: true); try s.fail(0)
                try require(s.snapshot.sends == (verifiedRecovery ? [0, 1, 0] : [0, 1, 2]),
                            "First-lookup guard changed the established verified-provider path")
                try s.integrity()
            }
        }
        try check("verified TXT keeps legacy TLS-ready recovery without separate TCP-ready event") {
            let s = Scenario(type: 16); try s.prepareColdFailure(omit: [.transportReady]); try s.fail(0)
            try require(s.snapshot.sends == (verifiedRecovery ? [0, 1, 0] : [0, 1, 2]),
                        "Cold-only TCP-ready requirement changed verified history semantics")
            try s.integrity()
        }
    }

    static func nativeResetPositiveControls(enabled: Bool) throws {
        let cfError = CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainPOSIX, 54, nil)!
        // CFError/NSError are toll-free bridged. This preserves the actual
        // __NSCFError object returned by the native Network framework bridge.
        let nativeCFError = unsafeBitCast(cfError, to: NSError.self)
        let errors: [(String, Error)] = [
            ("NWError54", NWError.posix(.ECONNRESET)),
            ("NSError54", NSError(domain: NSPOSIXErrorDomain, code: 54)),
            ("CFError54", nativeCFError),
        ]
        let phases: [(String, Int, Bool)] = [
            ("primary handshake", 0, false), ("hedge handshake", 1, false),
            ("hedge post-send", 1, true),
            ("primary ready-before-send", 0, false), ("hedge ready-before-send", 1, false),
        ]
        for type in [UInt16(1), 28, 64, 65] {
            for (phase, failed, sent) in phases {
                for (label, error) in errors {
                    try check("native reset \(phase) \(label) type \(type) uses the existing last slot") {
                        let s = Scenario(healthyPrimary: false, type: type, nativeTrace: true)
                        try s.prepareNativeReset(failed, sent: sent)
                        let peer = try s.peer(failed)
                        if phase.contains("ready-before-send") { try peer.record(.tlsReady) }
                        try peer.recordNative(.rawFailure, error: error)
                        try require(peer.hasNativeResetEvidence, "Real native POSIX54 trace failed to retain its evidence")
                        try peer.recordNative(sent ? .responseFailure : .tlsFailure, error: error)
                        try peer.recordNative(.requestFinished)
                        try require(peer.hasNativeResetEvidence,
                                    "Physical requestFinished erased a reset observed before completion")
                        try s.fail(failed, error: error)
                        try require(s.snapshot.sends == (enabled ? [0, 1, failed] : [0, 1, 2]),
                                    "Trusted native reset did not use the expected bounded candidate recovery")
                        try require(s.snapshot.answers.isEmpty && s.snapshot.errors.isEmpty,
                                    "Native reset completed the caller before its remaining opportunity")
                        if enabled {
                            s.clock.advance(1.72); try s.peer(2).sent()
                            s.clock.advance(1.78); try s.answer(2)
                        } else {
                            s.clock.advance(8); s.flow.recoveryAuditDeadline()
                        }
                        try require(s.snapshot.answers.count == (enabled ? 1 : 0)
                                    && s.snapshot.errors.count == (enabled ? 0 : 1),
                                    "Native reset before/after control outcome disagrees")
                        try s.integrity(); s.trace("native-\(phase)-\(label)-qtype-\(type)", fixed: enabled)
                    }
                }
            }
        }
        for (phase, failed, sent) in phases {
            try check("native reset \(phase) keeps original raw54 despite typed network callback") {
                let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
                try s.prepareNativeReset(failed, sent: sent)
                if phase.contains("ready-before-send") { try s.peer(failed).record(.tlsReady) }
                try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                try s.peer(failed).recordNative(.requestFinished)
                try s.fail(failed)
                try require(s.snapshot.sends == (enabled ? [0, 1, failed] : [0, 1, 2]),
                            "Typed callback hid or invented original native reset evidence")
                try s.integrity()
            }
        }
    }

    static func nativeResetExclusionControls() throws {
        let invalidErrors: [(String, Error)] = [
            ("native57", NWError.posix(.ENOTCONN)),
            ("NSError57", NSError(domain: NSPOSIXErrorDomain, code: 57)),
            ("typed network only", EncryptedDNSQueryFailure.network),
            ("TLS authentication", EncryptedDNSQueryFailure.authentication),
            ("wrong NSError domain", NSError(domain: "fixture.untrusted", code: 54)),
        ]
        for failed in [0, 1] {
            for (label, error) in invalidErrors {
                try check("native reset \(label) at token \(failed) cannot manufacture exact54 evidence") {
                    let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
                    try s.prepareNativeReset(failed)
                    let peer = try s.peer(failed)
                    try peer.recordNative(.rawFailure, error: error)
                    try require(!peer.hasNativeResetEvidence,
                                "Untrusted/non-54 error created a native reset observation")
                    try s.fail(failed, error: error)
                    try require(s.snapshot.sends == [0, 1, 2], "Non-54 handshake failure retried the same candidate")
                    try s.integrity()
                }
            }
            try check("native reset original callback54 at token \(failed) still needs raw trace evidence") {
                let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
                try s.prepareNativeReset(failed)
                try s.fail(failed, error: NWError.posix(.ECONNRESET))
                try require(s.snapshot.sends == [0, 1, 2], "Callback shape alone authorized native recovery")
                try s.integrity()
            }
            try check("native reset authentication callback at token \(failed) preserves deny barrier") {
                let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
                try s.prepareNativeReset(failed)
                try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                try s.fail(failed, error: EncryptedDNSQueryFailure.authentication)
                try require(s.snapshot.sends == [0, 1, 2], "Native reset overrode authentication failure")
                if case .failure(let error)? = s.flow.proxyFallbackBarrier() {
                    try require(EncryptedDNSQueryFailure.classify(error) == .authentication,
                                "Native reset erased authentication fallback denial")
                } else { throw Failure(text: "Native reset lost authentication deny barrier") }
                try s.integrity()
            }
            for boundary in ["cancel request", "local close", "request finished", "old generation"] {
                try check("native reset after \(boundary) at token \(failed) cannot authorize recovery") {
                    let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
                    try s.prepareNativeReset(failed)
                    let peer = try s.peer(failed)
                    switch boundary {
                    case "cancel request": try peer.cancelNative(.hedgeRotation)
                    case "local close": try peer.recordNative(.localCancel)
                    case "request finished": try peer.recordNative(.requestFinished)
                    default:
                        let old = try peer.obsoleteTraceAfterNewGeneration()
                        try peer.record(.transportReady); try peer.record(.tlsStarted)
                        old.record(.rawFailure, error: NWError.posix(.ECONNRESET))
                    }
                    if boundary != "old generation" {
                        try peer.recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                    }
                    try require(!peer.hasNativeResetEvidence, "Late physical error acquired reset authority")
                    try s.fail(failed)
                    try require(s.snapshot.sends == [0, 1, 2], "Late/stale native reset retried a candidate")
                    try s.integrity()
                }
            }
            for missing in [DNSConnectionAttemptEvent.transportReady, .tlsStarted] {
                try check("native reset token \(failed) missing \(missing.rawValue) remains ineligible") {
                    let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
                    try s.prepareNativeReset(failed, omit: [missing])
                    try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                    try s.fail(failed)
                    try require(s.snapshot.sends == [0, 1, 2], "Incomplete handshake acquired native recovery")
                    try s.integrity()
                }
            }
        }
        for response in [DNSConnectionAttemptEvent.responseStarted, .responseComplete] {
            try check("native reset hedge after \(response.rawValue) cannot replay a response") {
                let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
                try s.prepareNativeReset(1, sent: true); try s.peer(1).record(response)
                try s.peer(1).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(1)
                try require(s.snapshot.sends == [0, 1, 2], "Partial/completed reply acquired native recovery")
                try s.integrity()
            }
        }
        for failed in [0, 1] {
            for type in [UInt16(12), 16, 255] {
                try check("native reset type \(type) token \(failed) cannot broaden ordinary recovery") {
                    let s = Scenario(healthyPrimary: false, type: type, nativeTrace: true)
                    try s.prepareNativeReset(failed)
                    try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(failed)
                    try require(s.snapshot.sends == [0, 1, 2], "Non-ordinary native reset acquired replay")
                    try s.integrity()
                }
            }
            for queryClass in [UInt16(3), 255] {
                try check("native reset class \(queryClass) token \(failed) cannot broaden IN recovery") {
                    let s = Scenario(healthyPrimary: false, type: 28, queryClass: queryClass, nativeTrace: true)
                    try s.prepareNativeReset(failed)
                    try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(failed)
                    try require(s.snapshot.sends == [0, 1, 2], "Non-IN native reset acquired replay")
                    try s.integrity()
                }
            }
        }
        for evidence in [DNSQueryTransportEvidence.notStarted, .unknown, .reused, .reusedThenFresh] {
            try check("native reset transport \(evidence) cannot acquire strictly-fresh recovery") {
                let s = Scenario(healthyPrimary: false, evidence: evidence, type: 28, nativeTrace: true)
                try s.prepareNativeReset(0)
                try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(0)
                try require(s.snapshot.sends == [0, 1, 2], "Non-fresh native reset acquired recovery")
                try s.integrity()
            }
        }
    }

    static func nativeResetBudgetControls(enabled: Bool) throws {
        for failed in [0, 1] {
            for guardName in ["measured alternative", "reusable alternative", "failed candidate capacity"] {
                try check("native reset token \(failed) retains \(guardName) guard") {
                    let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
                    try s.prepareNativeReset(failed)
                    if guardName == "measured alternative" { s.seed(2) }
                    else if guardName == "reusable alternative" { s.slots.set(google, reusable: 1) }
                    else { s.slots.set(s.candidates[failed], cold: 0) }
                    try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(failed)
                    try require(s.snapshot.sends == [0, 1, 2], "Native recovery bypassed candidate/capacity evidence")
                    try s.integrity()
                }
            }
            try check("native reset token \(failed) rechecks deadline after synchronous cancellation") {
                let s = Scenario(healthyPrimary: false, type: 28, primaryCancellationAdvance: 7.99,
                    cancellationAdvanceSerial: failed, nativeTrace: true)
                try s.prepareNativeReset(failed)
                try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(failed)
                try require(s.snapshot.sends.filter { $0 == failed }.count == 1 && s.clock.now() == 107.99,
                            "Native recovery used a stale cancellation budget")
                s.clock.advance(8); s.flow.recoveryAuditDeadline(); try s.integrity()
            }
            try check("native reset token \(failed) factory revocation prevents recovered send") {
                let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true,
                    factoryCheck: { _, serial, permission, _ in if serial == 2 { permission.revoke() } })
                try s.prepareNativeReset(failed)
                try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(failed)
                try require(s.snapshot.factories == (enabled ? [0, 1, failed] : [0, 1, 2]),
                            "Native recovery missed its final factory authority check")
                try require(s.snapshot.sends == [0, 1] && s.snapshot.answers.count == 1
                            && s.snapshot.answers[0][3] & 0x0f == 2, "Factory revocation authorized native send")
                try s.integrity()
            }
        }
        for failed in [0, 1] {
            try check("native reset token \(failed) cannot use another IP of the same service as diversity") {
                let sibling = candidate("https://doh.pub/dns-query#120.53.53.53")
                let s = Scenario(healthyPrimary: false, type: 28, candidates: [dnspod, sibling, google], nativeTrace: true)
                s.slots.set(google, cold: 0); try s.prepareNativeReset(failed); s.slots.set(google, cold: 1)
                try s.peer(failed).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(failed)
                try require(s.snapshot.sends == [0, 1, 2], "Same-service survivor sponsored native retry")
                try s.integrity()
            }
        }
        try check("native reset cannot use an approved plaintext survivor as encrypted diversity") {
            let plain = DNSUpstreamCandidate(upstream: .plain(host: "192.0.2.53", port: 53), bootstrap: nil)
            let s = Scenario(healthyPrimary: false, type: 28, candidates: [dnspod, plain, google],
                nativeTrace: true, allowPlaintext: true)
            try s.prepareNativeReset(0)
            try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(0)
            try require(s.snapshot.sends == [0, 1, 2], "Plaintext survivor sponsored native encrypted retry")
            try s.integrity()
        }
        try check("native reset without a live hedge cannot spend an extra primary attempt") {
            let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
            s.clock.advance(0.1); try s.peer(0).record(.transportReady); try s.peer(0).record(.tlsStarted)
            s.clock.advance(0.3); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(0)
            try require(s.snapshot.sends == [0, 1], "Native reset grew a same-provider slot before its hedge")
            try s.integrity()
        }
        try check("native reset hedge recovery shares the one-retry budget across all candidates") {
            let s = Scenario(healthyPrimary: false, type: 28, nativeTrace: true)
            try s.prepareNativeReset(1)
            try s.peer(1).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(1)
            try require(s.snapshot.sends == (enabled ? [0, 1, 1] : [0, 1, 2]), "Hedge did not enter its expected last slot")
            try s.fail(1); try s.answer(1)
            s.clock.advance(1.0); try s.peer(0).record(.transportReady); try s.peer(0).record(.tlsStarted)
            try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(0)
            try s.peer(2).record(.transportReady); try s.peer(2).record(.tlsStarted)
            try s.peer(2).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(2)
            for serial in 0..<3 { try s.fail(serial); try s.answer(serial) }
            try require(s.snapshot.factories.count == 3 && s.snapshot.errors.count == 1 && s.snapshot.answers.isEmpty,
                        "Native recovery created a fourth attempt or revived a stale completed candidate")
            try s.integrity()
        }
    }

    static func lifecycleControls(fixed: Bool) throws {
        try check("recovery is at most once and duplicate stale callbacks cannot create a fourth attempt") {
            let s = Scenario(); try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.sends == (fixed ? [0, 1, 0] : [0, 1, 2]), "Control did not reach the third slot")
            try s.fail(0); try s.answer(0)
            try require(s.snapshot.factories.count == 3 && s.snapshot.answers.isEmpty, "Stale failed-token callback revived the primary")
            s.clock.advance(2.3); try s.peer(2).sent(); try s.fail(2)
            try s.fail(2); try s.answer(2)
            try require(s.snapshot.factories.count == 3 && s.snapshot.answers.isEmpty, "Failed recovery created another attempt or late answer")
            try s.fail(1)
            try require(s.snapshot.errors.count == 1 && s.snapshot.factories.count == 3, "Exhausted recovery did not finish exactly once")
            try s.integrity()
        }
        try check("successful third-slot recovery fences late answers and errors from every retired token") {
            let s = Scenario(); try s.prepareSentFailure(); try s.fail(0)
            s.clock.advance(2.28); try s.answer(2)
            for serial in 0..<3 { try s.fail(serial); try s.answer(serial) }
            s.clock.advance(8); s.flow.recoveryAuditDeadline()
            try require(s.snapshot.answers.count == 1 && s.snapshot.errors.isEmpty && s.snapshot.factories.count == 3,
                        "Retired callbacks or deadline completed a successful query again")
            try s.integrity()
        }
        try check("policy change inside the final factory prevents send after new recovery selection") {
            let s = Scenario(factoryCheck: { _, serial, permission, _ in if serial == 2 { permission.revoke() } })
            try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.factories == (fixed ? [0, 1, 0] : [0, 1, 2]), "Policy race did not enter the selected final factory")
            try require(s.snapshot.sends == [0, 1] && s.snapshot.answers.count == 1
                        && s.snapshot.answers[0][3] & 0x0f == 2, "Factory policy race sent an unauthorized query or lost SERVFAIL")
            let unadopted = try s.peer(2)
            try require(unadopted.cancellationReasons == [.policyChanged], "Unadopted final transport was not cancelled for policy")
            try s.integrity()
        }
        try check("final factory remains an authority boundary even for a previously successful candidate") {
            let s = Scenario(factoryCheck: { _, serial, _, _ in
                if serial == 2 { throw DNSPolicyFailure.refused("memory factory now rejects route") }
            })
            try s.prepareSentFailure(); try s.fail(0)
            try require(s.snapshot.sends == [0, 1] && s.snapshot.errors.count == 1, "Recovery bypassed factory route denial")
            try require(s.snapshot.factories.count == 3, "Route denial created a fourth factory call")
            try s.integrity()
        }
        try check("cancellation waits for every real child receipt and tolerates duplicate acknowledgements") {
            let s = Scenario(hold: true); try s.prepareSentFailure(); try s.fail(0)
            let done = DispatchSemaphore(value: 0)
            s.flow.cancel { done.signal() }; s.flow.recoveryAuditDrain()
            try require(done.wait(timeout: .now()) == .timedOut, "Cancellation completed before physical child receipts")
            for serial in 0..<3 {
                try s.peer(serial).acknowledge(duplicate: true)
                if serial < 2 { try require(done.wait(timeout: .now()) == .timedOut, "Partial receipts completed cancellation early") }
            }
            try require(done.wait(timeout: .now() + 2) == .success && done.wait(timeout: .now()) == .timedOut,
                        "Recovery leaked a receipt or completed cancellation twice")
            for serial in 0..<3 { try s.answer(serial); try s.fail(serial) }
            try require(s.snapshot.answers.isEmpty && s.snapshot.errors.isEmpty && s.snapshot.factories.count == 3,
                        "Cancelled recovery resumed on late callbacks")
            try s.integrity()
        }
    }

    static func approvedRecoverySelectionControls(fixed: Bool) throws {
        let sibling = candidate("https://doh.pub/dns-query#120.53.53.53")
        for reusableBeforeSend in [false, true] {
            try check("build43 warm verified sibling before-send \(reusableBeforeSend) keeps its immediate second slot") {
                let s = Scenario(candidates: approved + [sibling], autoSend: false, nativeTrace: true)
                s.seed(3, milliseconds: 90)
                if reusableBeforeSend {
                    // Equal idle hints preserve the ranked original primary.
                    // Its stale checkout then produces the observed fresh dial.
                    s.slots.set(dnspod, reusable: 1); s.slots.set(sibling, reusable: 1)
                }
                s.flow.send(s.query); s.flow.recoveryAuditDrain()
                try require(s.snapshot.sends == [0], "Warm audit changed the original primary")
                s.slots.set(dnspod, reusable: 0); s.slots.set(sibling, reusable: 1)
                s.clock.advance(0.054); try s.peer(0).record(.transportReady)
                s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
                s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                try s.fail(0)
                try require(s.snapshot.sends == [0, 3], "A verified reusable sibling waited behind an unmeasured cross-provider soft budget")
                s.clock.advance(0.145); try s.answer(1)
                try require(s.snapshot.answers.count == 1 && s.snapshot.errors.isEmpty
                            && s.snapshot.sends == [0, 3], "The immediate warm path launched an unnecessary third attempt")
                try s.integrity(); s.trace("build43-warm-sibling-before-send-\(reusableBeforeSend)", fixed: true)
            }
        }
        for exclusion in ["cold", "cooling", "TLS-only", "capacity-zero"] {
            try check("build43 warm sibling \(exclusion) cannot acquire immediate recovery priority") {
                let s = Scenario(candidates: approved + [sibling], autoSend: false, nativeTrace: true)
                if exclusion != "TLS-only" { s.seed(3, milliseconds: 90) }
                s.flow.send(s.query); s.flow.recoveryAuditDrain()
                if exclusion == "cooling" {
                    s.selector.record(s.selector.beginObservation(scopeKey: s.scope, candidateID: sibling.id),
                                      milliseconds: 100, success: false, transport: .fresh)
                }
                s.slots.set(sibling, reusable: ["cold", "capacity-zero"].contains(exclusion) ? 0 : 1,
                            cold: exclusion == "capacity-zero" ? 0 : 1)
                s.clock.advance(0.054); try s.peer(0).record(.transportReady)
                s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
                s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                try s.fail(0)
                try require(s.snapshot.sends == (fixed ? [0, 1] : [0, 3]),
                            "An excluded sibling consumed the immediate same-service recovery slot")
                if fixed {
                    s.clock.advance(0.95); s.flow.recoveryAuditLiveHedge()
                    try require(s.snapshot.sends == (exclusion == "cold" ? [0, 1, 3] : [0, 1, 0]),
                                "Excluded warm evidence bypassed the existing third-slot candidate constraints")
                }
                try s.integrity()
            }
        }
        try check("build43 warm verified sibling retains the original plaintext second phase") {
            let plain = DNSUpstreamCandidate(upstream: .plain(host: "192.0.2.53", port: 53), bootstrap: nil)
            let s = Scenario(candidates: [dnspod, plain, cloudflare, sibling], nativeTrace: true, allowPlaintext: true)
            s.seed(3, milliseconds: 90); s.slots.set(sibling, reusable: 1)
            s.clock.advance(0.054); try s.peer(0).record(.transportReady)
            s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
            s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
            try s.fail(0)
            try require(s.snapshot.sends == [0, 1], "Warm reset recovery replaced the approved plaintext second phase")
            try s.integrity()
        }
        try check("build43 warm sibling in the third prefix moves once and cannot overlap itself") {
            let s = Scenario(candidates: [dnspod, cloudflare, sibling], nativeTrace: true)
            s.seed(2, milliseconds: 90); s.slots.set(sibling, reusable: 1); s.slots.set(cloudflare, cold: 0)
            s.clock.advance(0.054); try s.peer(0).record(.transportReady)
            s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
            s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
            try s.fail(0)
            try require(s.snapshot.sends == [0, 2], "Verified third-prefix sibling did not enter the second slot")
            s.clock.advance(0.95); s.flow.recoveryAuditLiveHedge()
            try require(s.snapshot.sends == [0, 2, 1] && s.snapshot.same == 1,
                        "Moving the warm sibling left a duplicate that overlapped the same candidate")
            try s.integrity()
        }
        try check("build43 warm sibling move leaves an approved plaintext third phase") {
            let plain = DNSUpstreamCandidate(upstream: .plain(host: "192.0.2.53", port: 53), bootstrap: nil)
            let s = Scenario(candidates: [dnspod, cloudflare, plain, sibling], nativeTrace: true, allowPlaintext: true)
            s.seed(3, milliseconds: 90); s.slots.set(sibling, reusable: 1)
            s.clock.advance(0.054); try s.peer(0).record(.transportReady)
            s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
            s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
            try s.fail(0); s.clock.advance(0.95); s.flow.recoveryAuditLiveHedge()
            try require(s.snapshot.sends == [0, 3, 2], "Warm move erased the explicit plaintext third phase")
            try s.integrity()
        }
        for change in ["reuse-lost", "deadline", "short-window", "invalid-clock"] {
            try check("build43 warm sibling rechecks \(change) after original cancellation") {
                let s = Scenario(candidates: approved + [sibling], autoSend: false, nativeTrace: true,
                    cancellationObserver: { serial, slots, clock in
                        guard serial == 0 else { return }
                        switch change {
                        case "reuse-lost": slots.set(sibling, reusable: 0, cold: 0)
                        case "deadline": clock.advance(8)
                        case "short-window": clock.advance(7.8)
                        default: clock.advance(.nan)
                        }
                    })
                s.seed(3, milliseconds: 90); s.flow.send(s.query); s.flow.recoveryAuditDrain()
                s.slots.set(sibling, reusable: 1)
                s.clock.advance(0.054); try s.peer(0).record(.transportReady)
                s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
                s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                try s.fail(0)
                try require(s.snapshot.sends == (["reuse-lost", "short-window"].contains(change) ? [0, 1] : [0]),
                            "Warm admission used a stale hint or stale completion window after cancellation")
                try s.integrity()
            }
        }
        try check("build43 warm same-IP alias cannot acquire immediate different-address priority") {
            let alias = candidate("https://1.12.12.12/dns-query")
            let s = Scenario(candidates: approved + [alias], nativeTrace: true)
            s.seed(3, milliseconds: 90); s.slots.set(alias, reusable: 1)
            try require(alias.id != dnspod.id && alias.upstream.resolverServiceID == dnspod.upstream.resolverServiceID
                        && alias.upstream.target.host == dnspod.upstream.target.host,
                        "Same-IP alias control did not represent distinct approved endpoint identities")
            s.clock.advance(0.054); try s.peer(0).record(.transportReady)
            s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
            s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
            try s.fail(0)
            try require(s.snapshot.sends == [0, 1], "A same-IP alias bypassed the first cross-provider opportunity")
            try s.integrity()
        }
        try check("build43 warm factory revocation cannot send the selected sibling") {
            let s = Scenario(candidates: approved + [sibling], autoSend: false, nativeTrace: true,
                             factoryCheck: { _, serial, permission, _ in if serial == 1 { permission.revoke() } })
            s.seed(3, milliseconds: 90); s.flow.send(s.query); s.flow.recoveryAuditDrain()
            s.slots.set(sibling, reusable: 1)
            s.clock.advance(0.054); try s.peer(0).record(.transportReady)
            s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
            s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
            try s.fail(0)
            try require(s.snapshot.factories == [0, 3] && s.snapshot.sends == [0]
                        && s.snapshot.answers.count == 1 && s.snapshot.answers[0][3] & 0x0f == 2
                        && s.snapshot.errors.isEmpty, "Warm availability bypassed the final factory authority check")
            try s.integrity()
        }
        for type in [UInt16(1), 28, 65] {
            for primaryBlocked in [false, true] {
                try check("build43 verified sibling type \(type) primary-blocked \(primaryBlocked) takes the last slot") {
                    let s = Scenario(type: type, candidates: approved + [sibling], nativeTrace: true)
                    s.seed(3, milliseconds: 90)
                    try s.prepareNativeReset(0, sent: type == 65)
                    if primaryBlocked { s.slots.set(dnspod, cold: 0) }
                    let peer = try s.peer(0)
                    try peer.recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                    try require(peer.hasNativeResetEvidence, "Native reset control omitted provenance")
                    try s.fail(0)
                    try require(s.snapshot.sends == (fixed ? [0, 1, 3] : [0, 1, 2]),
                                "An available verified sibling only vetoed recovery without taking the slot")
                    if fixed { s.clock.advance(2); try s.answer(2) }
                    else { s.clock.advance(8); s.flow.recoveryAuditDeadline() }
                    try require(s.snapshot.answers.count == (fixed ? 1 : 0)
                                && s.snapshot.errors.count == (fixed ? 0 : 1), "Verified sibling did not resolve the controlled outage")
                    try s.integrity(); s.trace("build43-verified-sibling-\(type)-blocked-\(primaryBlocked)", fixed: fixed)
                }
            }
        }
        try check("build43 cooling sibling history cannot veto an available original path") {
            let s = Scenario(candidates: approved + [sibling], nativeTrace: true)
            s.seed(3); try s.prepareNativeReset(0)
            s.selector.record(s.selector.beginObservation(scopeKey: s.scope, candidateID: sibling.id),
                              milliseconds: 100, success: false, transport: .fresh)
            try require(s.selector.schedulingPriority(scopeKey: s.scope, candidateID: sibling.id) == 2
                        && s.selector.knownLatencyMilliseconds(scopeKey: s.scope, candidateID: sibling.id) != nil,
                        "Cooling fixture lost the historical latency that caused the original veto")
            try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(0)
            try require(s.snapshot.sends == (fixed ? [0, 1, 0] : [0, 1, 2]), "Cooling history still masqueraded as a healthy alternative")
            try s.integrity()
        }
        try check("build43 a slower measured alternative cannot hide a second one that fits") {
            let slow = candidate("https://dns.alidns.com/dns-query#223.5.5.5")
            let s = Scenario(candidates: approved + [slow, sibling], nativeTrace: true)
            try s.prepareNativeReset(0)
            s.seed(3, milliseconds: 7000); s.seed(4, milliseconds: 90)
            try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(0)
            try require(s.snapshot.sends == (fixed ? [0, 1, 4] : [0, 1, 3]),
                        "A known path outside the completion window hid a viable approved alternative")
            try s.integrity()
        }
        try check("build43 the live other service cannot take the last slot with its second IP") {
            let otherAddress = candidate("https://cloudflare-dns.com/dns-query#1.0.0.1")
            let s = Scenario(candidates: approved + [otherAddress], nativeTrace: true)
            try s.prepareNativeReset(0); s.seed(3)
            try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(0)
            try require(s.snapshot.sends == (fixed ? [0, 1, 0] : [0, 1, 2]),
                        "A second address duplicated the surviving provider instead of recovering the failed service")
            try s.integrity()
        }
        try check("build43 a reusable same-service sibling without DNS history cannot pose as verified") {
            let s = Scenario(healthyPrimary: false, candidates: approved + [sibling], nativeTrace: true)
            s.slots.set(sibling, reusable: 1)
            s.clock.advance(0.054); try s.peer(0).record(.transportReady)
            s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
            s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
            try s.fail(0); s.clock.advance(0.95); s.flow.recoveryAuditLiveHedge()
            try require(s.snapshot.sends == (fixed ? [0, 1, 0] : [0, 3, 1]),
                        "TLS-only readiness changed the expected provider ordering: \(s.snapshot.sends)")
            try require(s.selector.knownLatencyMilliseconds(scopeKey: s.scope, candidateID: sibling.id) == nil,
                        "A reusable hint manufactured a DNS success observation")
            try s.integrity()
        }
        try check("build43 deferred encrypted reset retains an approved plaintext third phase") {
            let plain = DNSUpstreamCandidate(upstream: .plain(host: "192.0.2.53", port: 53), bootstrap: nil)
            let s = Scenario(candidates: [dnspod, cloudflare, plain], nativeTrace: true, allowPlaintext: true)
            s.clock.advance(0.054); try s.peer(0).record(.transportReady)
            s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
            s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
            try s.fail(0); s.clock.advance(0.95); s.flow.recoveryAuditLiveHedge()
            try require(s.snapshot.sends == [0, 1, 2], "Deferred recovery overwrote the explicit mixed-mode phase")
            try s.integrity()
        }
        for proof in ["original", "sibling", "none"] {
            try check("build43 early exact reset with \(proof) history waits for a different service") {
                let s = Scenario(healthyPrimary: proof == "original", candidates: approved + [sibling], nativeTrace: true)
                if proof == "sibling" { s.seed(3) }
                s.clock.advance(0.054); try s.peer(0).record(.transportReady)
                s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
                s.clock.advance(0.123)
                let peer = try s.peer(0)
                try peer.recordNative(.rawFailure, error: NWError.posix(.ECONNRESET)); try s.fail(0)
                try require(s.snapshot.sends == [0, 1], "Early reset immediately replayed its provider before giving another service a slot")
                s.clock.advance(0.95); s.flow.recoveryAuditLiveHedge()
                let recovery = fixed
                let index = proof == "sibling" ? 3 : 0
                try require(s.snapshot.sends == (recovery ? [0, 1, index] : [0, 1, 2]),
                            "Early reset lost its exact native recovery evidence")
                if recovery { s.clock.advance(1.2); try s.answer(2) }
                else { s.clock.advance(8); s.flow.recoveryAuditDeadline() }
                try require(s.snapshot.answers.count == (recovery ? 1 : 0)
                            && s.snapshot.errors.count == (recovery ? 0 : 1), "Early reset outcome did not match its bounded evidence")
                try s.integrity(); s.trace("build43-early-reset-\(proof)", fixed: recovery)
            }
        }
        for boundary in ["positive", "refused", "policy", "capacity", "deadline", "no-capacity"] {
            try check("build43 deferred exact reset honors \(boundary) before third admission") {
                let s = Scenario(nativeTrace: true)
                s.clock.advance(0.054); try s.peer(0).record(.transportReady)
                s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
                s.clock.advance(0.123); try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                try s.fail(0)
                try require(s.snapshot.sends == [0, 1], "Boundary fixture did not retain cross-provider ordering")
                switch boundary {
                case "positive": try s.answer(1)
                case "refused":
                    try s.peer(1).receive(DNSMessageInspection.errorResponse(to: s.query, code: .refused)!)
                    s.flow.recoveryAuditDrain()
                case "policy": s.permission.revoke()
                case "capacity": try s.fail(1, error: EncryptedDNSQueryFailure.capacity)
                case "deadline": s.clock.advance(8); s.flow.recoveryAuditDeadline()
                default: s.slots.set(dnspod, cold: 0)
                }
                s.clock.advance(boundary == "deadline" ? 8 : 0.95); s.flow.recoveryAuditLiveHedge()
                try require(s.snapshot.sends == (boundary == "no-capacity" ? [0, 1, 2] : [0, 1]),
                            "Deferred recovery escaped a terminal boundary or exhausted pool")
                if boundary == "refused" { try require(((s.snapshot.answers.first?[3] ?? 0) & 0x0f) == 5, "Deferred recovery erased REFUSED") }
                try s.integrity()
            }
        }
        for exclusion in ["typed-network", "authentication", "late-reset", "finished-reset", "old-generation", "reused", "reused-then-fresh", "PTR", "TXT", "non-IN"] {
            try check("build43 early \(exclusion) cannot retain native ordinary reset privilege") {
                let type: UInt16 = exclusion == "PTR" ? 12 : (exclusion == "TXT" ? 16 : 1)
                let evidence: DNSQueryTransportEvidence = exclusion == "reused" ? .reused
                    : (exclusion == "reused-then-fresh" ? .reusedThenFresh : .fresh)
                let s = Scenario(evidence: evidence, type: type, queryClass: exclusion == "non-IN" ? 3 : 1, nativeTrace: true)
                s.clock.advance(0.054); try s.peer(0).record(.transportReady)
                s.clock.advance(0.055); try s.peer(0).record(.tlsStarted)
                s.clock.advance(0.123)
                if exclusion == "late-reset" { try s.peer(0).cancelNative(.cleanup) }
                if exclusion == "finished-reset" { try s.peer(0).recordNative(.requestFinished) }
                if exclusion == "old-generation" {
                    let old = try s.peer(0).obsoleteTraceAfterNewGeneration()
                    old.record(.rawFailure, error: NWError.posix(.ECONNRESET))
                } else if exclusion != "typed-network" {
                    try s.peer(0).recordNative(.rawFailure, error: NWError.posix(.ECONNRESET))
                }
                try s.fail(0, error: exclusion == "authentication" ? EncryptedDNSQueryFailure.authentication : .network)
                s.clock.advance(0.95); s.flow.recoveryAuditLiveHedge()
                try require(s.snapshot.sends == [0, 1, 2], "An excluded failure retained deferred same-provider replay")
                try s.integrity()
            }
        }
    }

    static func main() {
        do {
            let mode = CommandLine.arguments.dropFirst().first ?? "after"
            let fixed = mode != "before"
            if mode == "after" || mode == "build42-final" {
                try approvedRecoverySelectionControls(fixed: mode == "after")
            }
            try positiveControls(fixed: fixed)
            try eligibilityControls()
            try lifecycleControls(fixed: fixed)
            try firstLookupControls(enabled: ["after", "build42-initial", "build42-final"].contains(mode), verifiedRecovery: fixed)
            try nativeResetPositiveControls(enabled: mode == "after" || mode == "build42-final")
            try nativeResetExclusionControls()
            try nativeResetBudgetControls(enabled: mode == "after" || mode == "build42-final")
            try require(cases > 0, "Case filter did not execute a regression")
            print("DNS post-send recovery checks passed: \(cases) cases, \(assertions) assertions; expected=\(mode)")
        } catch {
            fputs("FAIL DNS post-send recovery: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}

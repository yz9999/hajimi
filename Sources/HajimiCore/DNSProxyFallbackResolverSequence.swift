import Foundation
import HajimiDNS

/// Serial retries within an already-authorized proxy-only TCP fallback phase.
/// This class cannot choose a route, add a resolver, authorize plaintext, or
/// extend the parent deadline. Every factory invocation revalidates the route.
final class DNSProxyFallbackResolverSequence: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSQueryDeadlineAwareDatagram,
                                             DNSQueryExecutionContextAccepting {
    typealias Factory = (DNSProxyFallbackServer, DispatchQueue, TimeInterval,
                         @escaping (Data) -> Void, @escaping (Error) -> Void) throws -> (NativeRoutedDatagram & DNSQueryCancellationAcknowledging)
    typealias Schedule = DNSProxyFallbackQueryDatagram.Schedule
    private let servers: [DNSProxyFallbackServer], selector: DNSAdaptiveUpstreamSelector
    private var scopeKey: String
    private let queue: DispatchQueue, absoluteDeadline: TimeInterval
    private let permitted: () -> Bool, clock: () -> TimeInterval, schedule: Schedule
    private let factory: Factory, receive: (Data) -> Void, failure: (Error) -> Void
    private let diagnostics: NetworkPerformanceDiagnostics
    private let admission = NSLock(), cancellations = DispatchGroup()
    private var closed = false, admitted = false, deadlineSignalled = false
    private var executionContext = DNSQueryExecutionContext()
    private var cancellationReason: DNSAttemptCancellationReason?
    private var finished = false, transitioning = false, epoch: UInt64 = 0
    private var query: Data?, transport: DNSQueryCancellationAcknowledging?
    private var ordered: [DNSProxyFallbackServer] = [], next = 0
    private var current: DNSProxyFallbackServer?, attemptStarted: TimeInterval = 0
    private var observation: DNSAdaptiveUpstreamSelector.Observation?
    private var overallTimer: (() -> Void)?, attemptTimer: (() -> Void)?
    private var lastError: Error = DNSQueryTimeoutError()

    init(servers: [DNSProxyFallbackServer], selector: DNSAdaptiveUpstreamSelector, scopeKey: String,
         queue: DispatchQueue, absoluteDeadline: TimeInterval, permitted: @escaping () -> Bool,
         factory: @escaping Factory, receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         schedule: @escaping Schedule = DNSProxyFallbackResolverSequence.scheduleTimer,
         diagnostics: NetworkPerformanceDiagnostics = .shared) {
        self.servers = servers; self.selector = selector; self.scopeKey = scopeKey
        self.queue = DispatchQueue(label: "app.hajimi.dns.proxy-resolver-sequence", qos: .userInitiated, target: queue)
        self.absoluteDeadline = absoluteDeadline; self.permitted = permitted
        self.factory = factory; self.receive = receive; self.failure = failure
        self.clock = clock; self.schedule = schedule; self.diagnostics = diagnostics
    }

    private static func scheduleTimer(queue: DispatchQueue, delay: TimeInterval, work: @escaping () -> Void) -> (() -> Void) {
        let timer = DispatchWorkItem(block: work)
        queue.asyncAfter(deadline: .now() + max(0, delay), execute: timer)
        return { timer.cancel() }
    }
    private static func id(_ server: DNSProxyFallbackServer) -> String {
        [server.host, String(server.port)].map { "\($0.utf8.count):\($0)" }.joined()
    }
    private var stopped: Bool {
        admission.lock(); defer { admission.unlock() }; return closed || deadlineSignalled
    }

    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
        admission.lock(); defer { admission.unlock() }
        guard !admitted, !closed, !deadlineSignalled else { return }
        executionContext = context
    }

    func send(_ data: Data) {
        admission.lock()
        guard !closed, !deadlineSignalled, !admitted else { admission.unlock(); return }
        admitted = true; admission.unlock()
        queue.async {
            guard !self.stopped else { return }
            guard !self.servers.isEmpty, self.servers.count <= Profile.maximumDNSProxyFallbackServers,
                  DNSMessageInspection.singleQuestion(in: data) != nil else {
                self.finish(error: EncryptedDNSQueryFailure.configuration); return
            }
            guard self.permitted() else { self.finish(error: EncryptedDNSQueryFailure.policy); return }
            let now = self.clock()
            guard now.isFinite, self.absoluteDeadline.isFinite, now < self.absoluteDeadline else {
                self.finish(error: DNSQueryTimeoutError()); return
            }
            self.query = data
            self.scopeKey = DNSAdaptiveUpstreamSelector.queryHealthScope(scopeKey: self.scopeKey, query: data)
            let ids = self.selector.orderedCandidates(scopeKey: self.scopeKey, candidateIDs: self.servers.map(Self.id))
            self.ordered = ids.prefix(3).compactMap { id in self.servers.first { Self.id($0) == id } }
            self.overallTimer = self.schedule(self.queue, self.absoluteDeadline - now) { [weak self] in
                self?.overallDeadlineReached()
            }
            self.beginAttempt()
        }
    }

    private func beginAttempt() {
        guard !finished, !stopped, !transitioning, let query else { return }
        guard permitted() else { finish(error: EncryptedDNSQueryFailure.policy); return }
        let now = clock(), remaining = absoluteDeadline - now
        guard now.isFinite, remaining > 0 else { overallDeadlineReached(); return }
        guard next < ordered.count else { finish(error: lastError); return }
        let server = ordered[next]; next += 1
        current = server; attemptStarted = now; epoch &+= 1; let token = epoch
        observation = selector.beginObservation(scopeKey: scopeKey, candidateID: Self.id(server))
        // Each cold attempt must have time to establish its proxy tunnel and
        // exchange DNS. Dividing five remaining seconds across three servers
        // otherwise cancels every healthy 2–3s tunnel before it can answer and
        // prevents the selector from ever learning a successful latency.
        // Early failures still leave room for up to three approved servers;
        // the parent deadline always caps the minimum setup window.
        let share = remaining / Double(ordered.count - next + 1)
        let setupWindow = selector.knownLatencyMilliseconds(scopeKey: scopeKey, candidateID: Self.id(server))
            .map { $0 / 1_000 * 1.75 + 0.25 } ?? 3
        let deadline = min(absoluteDeadline, now + max(share, setupWindow))
        if next > 1 { diagnostics.recordDNS(.failover) }
        diagnostics.recordDNS(.upstreamAttempt)
        attemptTimer = schedule(queue, max(0, deadline - now)) { [weak self] in
            self?.failed(DNSQueryTimeoutError(), token: token)
        }
        do {
            let child = try factory(server, queue, deadline, { [weak self] answer in
                self?.queue.async { self?.accept(answer, token: token) }
            }, { [weak self] error in
                self?.queue.async { self?.failed(error, token: token) }
            })
            guard !finished, !stopped, permitted(), clock() < absoluteDeadline else {
                cancelChild(child, reason: .policyChanged)
                if !finished { finish(error: EncryptedDNSQueryFailure.policy) }; return
            }
            (child as? DNSQueryExecutionContextAccepting)?
                .setDNSQueryExecutionContext(executionContext.child())
            transport = child; child.send(query)
        } catch { failed(error, token: token) }
    }

    private func accept(_ answer: Data, token: UInt64) {
        guard !finished, !stopped, !transitioning, epoch == token, let query else { return }
        guard permitted() else { finish(error: EncryptedDNSQueryFailure.policy); return }
        guard clock().isFinite, clock() < absoluteDeadline else { overallDeadlineReached(); return }
        guard DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
            finish(error: EncryptedDNSQueryFailure.invalidResponse); return
        }
        let code = answer[answer.startIndex + 3] & 0x0f
        if [UInt8(0), 3].contains(code) {
            selector.record(observation, milliseconds: max(0, clock() - attemptStarted) * 1_000,
                            success: true, transport: transportEvidence())
        }
        // NXDOMAIN, NODATA, REFUSED and other valid DNS results terminate the
        // query unchanged. They are never permission to shop for an answer.
        finish(answer: answer)
    }

    private func failed(_ error: Error, token: UInt64) {
        guard !finished, !stopped, !transitioning, epoch == token else { return }
        guard permitted() else { finish(error: EncryptedDNSQueryFailure.policy); return }
        let reason = EncryptedDNSQueryFailure.classify(error)
        guard clock().isFinite, clock() < absoluteDeadline else {
            // An actual non-network denial is not a provider timeout, even
            // when its callback shares the total deadline's queue turn.
            if reason.permitsProxyFallback { overallDeadlineReached() }
            else { finish(error: DNSQueryTimeoutError()) }
            return
        }
        guard reason.permitsProxyFallback else { finish(error: error); return }
        let old = transport
        if let barrier = (old as? DNSProxyFallbackBarrierProviding)?.proxyFallbackBarrier() {
            finish(barrier: barrier); return
        }
        let failedObservation = observation, failedEvidence = transportEvidence()
        let failedMilliseconds = max(0, clock() - attemptStarted) * 1_000
        lastError = error; attemptTimer?(); attemptTimer = nil
        transitioning = true; epoch &+= 1; let transition = epoch
        // This canceled owner and its receipt now belong to the ACK closure.
        // A total deadline must neither cancel it twice nor discard a failure
        // already observed while the original query still had time remaining.
        transport = nil; observation = nil
        cancelChild(old, reason: error is DNSQueryTimeoutError ? .requestDeadline : .cleanup) { [self] in
            recordFailureAfterAcknowledgement(failedObservation, evidence: failedEvidence,
                milliseconds: failedMilliseconds, child: old)
            guard !self.finished, !self.stopped, self.epoch == transition else { return }
            guard self.permitted() else { self.finish(error: EncryptedDNSQueryFailure.policy); return }
            guard self.clock().isFinite, self.clock() < self.absoluteDeadline else {
                self.overallDeadlineReached(); return
            }
            // Cancellation ACK fences queued authentication failures and
            // negative replies before another approved resolver can start.
            if let barrier = (old as? DNSProxyFallbackBarrierProviding)?.proxyFallbackBarrier() {
                self.finish(barrier: barrier); return
            }
            self.transport = nil; self.transitioning = false; self.beginAttempt()
        }
    }

    private func finish(barrier: DNSProxyFallbackBarrier) {
        guard permitted() else { finish(error: EncryptedDNSQueryFailure.policy); return }
        guard clock().isFinite, clock() < absoluteDeadline else { finish(error: DNSQueryTimeoutError()); return }
        switch barrier {
        case .failure(let error): finish(error: error)
        case .answer(let answer):
            guard let query, DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
                finish(error: EncryptedDNSQueryFailure.invalidResponse); return
            }
            finish(answer: answer)
        }
    }
    private func transportEvidence() -> DNSQueryTransportEvidence {
        (transport as? DNSQueryTransportEvidenceProviding)?.dnsQueryTransportEvidence() ?? .unknown
    }

    private func recordFailureAfterAcknowledgement(_ observation: DNSAdaptiveUpstreamSelector.Observation?,
                                                   evidence: DNSQueryTransportEvidence,
                                                   milliseconds: Double,
                                                   child: DNSQueryCancellationAcknowledging?) {
        admission.lock(); let allowed = !closed || deadlineSignalled; admission.unlock()
        guard allowed, permitted(), evidence != .notStarted,
              (child as? DNSProxyFallbackBarrierProviding)?.proxyFallbackBarrier() == nil else { return }
        selector.record(observation, milliseconds: milliseconds, success: false, transport: evidence)
    }

    private func overallDeadlineReached() {
        admission.lock()
        // The first terminal admission distinguishes a real total timeout
        // from ordinary client cancellation, including either queue order.
        let cancelled = closed && !deadlineSignalled
        if !cancelled { deadlineSignalled = true }
        admission.unlock()
        guard !finished, !cancelled else { return }
        guard permitted() else {
            finish(error: EncryptedDNSQueryFailure.policy, completingDeadline: true); return
        }
        let old = transport, observed = observation, evidence = transportEvidence()
        let now = clock()
        let milliseconds = now.isFinite ? max(0, min(now, absoluteDeadline) - attemptStarted) * 1_000 : .nan
        observation = nil
        finish(error: DNSQueryTimeoutError(), completingDeadline: true) { [self] in
            // The user already received its timeout. Wait only to classify
            // this health receipt: logical ACK exposes native deny/negative
            // metadata, without extending the deadline or holding a new dial.
            recordFailureAfterAcknowledgement(observed, evidence: evidence,
                milliseconds: milliseconds, child: old)
        }
    }

    private func cancelChild(_ child: DNSQueryCancellationAcknowledging?,
                             reason: DNSAttemptCancellationReason = .cleanup,
                             completion: @escaping () -> Void = {}) {
        guard let child else { queue.async(execute: completion); return }
        cancellations.enter()
        let group = cancellations, queue = queue, once = NSLock()
        var acknowledged = false
        child.cancel(reason: reason) {
            once.lock(); guard !acknowledged else { once.unlock(); return }
            acknowledged = true; once.unlock(); group.leave()
            queue.async(execute: completion)
        }
    }
    private func finish(answer: Data? = nil, error: Error? = nil,
                        completingDeadline: Bool = false, afterCancellation: @escaping () -> Void = {}) {
        admission.lock(); let cancelled = closed && !(completingDeadline && deadlineSignalled); admission.unlock()
        guard !finished, !cancelled else { return }
        finished = true; epoch &+= 1
        overallTimer?(); attemptTimer?(); overallTimer = nil; attemptTimer = nil
        let reason: DNSAttemptCancellationReason = completingDeadline ? .overallDeadline
            : (answer != nil ? .winnerSelected
                : ((error as? EncryptedDNSQueryFailure) == .policy ? .policyChanged
                    : (error is DNSQueryTimeoutError ? .overallDeadline : .cleanup)))
        let child = transport; transport = nil; query = nil
        cancelChild(child, reason: reason, completion: afterCancellation)
        if let answer { receive(answer) } else if let error { failure(error) }
    }
    func queryDeadlineReached() {
        admission.lock(); guard !closed, !deadlineSignalled else { admission.unlock(); return }
        deadlineSignalled = true; admission.unlock()
        queue.async { self.overallDeadlineReached() }
    }
    func cancel() { cancel(completion: {}) }
    func cancel(completion: @escaping () -> Void) {
        cancel(reason: .callerCancelled, completion: completion)
    }
    func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        admission.lock()
        if !closed { cancellationReason = reason }
        let reason = cancellationReason ?? reason
        closed = true; let deadlineOwnsTermination = deadlineSignalled; admission.unlock()
        queue.async {
            if deadlineOwnsTermination {
                self.overallDeadlineReached()
            } else if !self.finished {
                self.finished = true; self.epoch &+= 1
                self.overallTimer?(); self.attemptTimer?(); self.overallTimer = nil; self.attemptTimer = nil
                let child = self.transport; self.transport = nil; self.query = nil
                self.cancelChild(child, reason: reason)
            }
            self.cancellations.notify(queue: self.queue, execute: completion)
        }
    }
    func drainQueueForSelfTest() { queue.sync {} }
    func enqueueForSelfTest(_ work: @escaping () -> Void) { queue.async(execute: work) }
}

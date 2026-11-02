import Foundation

/// Preserve a child's original absolute deadline across the coordinator;
/// racing parent and child timers must both report a real timeout, not turn
/// it into a generic upstream error or a client cancellation.
package struct DNSQueryTimeoutError: LocalizedError {
    package let inheritedDeadlineReached: Bool
    package init(inheritedDeadlineReached: Bool = false) {
        self.inheritedDeadlineReached = inheritedDeadlineReached
    }
    package var errorDescription: String? { "加密 DNS 总查询超时" }
}

/// A router-local cache, single-flight gate and bounded FIFO upstream governor.
/// Every caller must have passed
/// the original destination, QNAME and resolver policy checks before joining.
/// The caller supplies a policy/interface scope and rechecks its epoch before
/// delivery; a DNS ID is never a cache key or another client's response ID.
package final class DNSQueryCoordinator {
    package typealias Factory = (DispatchQueue, @escaping (Data) -> Void,
                         @escaping (Error) -> Void) throws -> DNSQueryDatagram

    package struct Statistics {
        package let upstreamQueries: Int
        package let cacheHits: Int
        package let mergedQueries: Int
        package let pendingQueries: Int
        package let waitingClients: Int
        package let activeUpstreams: Int
        package let queuedUpstreams: Int
    }

    private struct Key: Hashable {
        let scope: String
        let question: Data
        // Unsafe/complex questions are forwarded unchanged and never merged.
        // Common read-only unsigned IN queries can share IO without storage.
        let unique: UUID?
    }
    private final class Waiter {
        let id: UUID
        let query: Data
        let queue: DispatchQueue
        let started: UInt64
        let deadline: DispatchTime
        let permitted: () -> Bool
        let factory: Factory
        let completion: (Data?) -> Void
        var timeout: DispatchWorkItem?
        // Installed once on the coordinator queue, before any handoff. A
        // follower shares the leader's logical root, not its own response ID.
        var rootID: UUID?
        private let observation = NSLock()
        private var observed = false

        init(id: UUID, query: Data, queue: DispatchQueue, started: UInt64, deadline: DispatchTime,
             permitted: @escaping () -> Bool, factory: @escaping Factory,
             completion: @escaping (Data?) -> Void) {
            self.id = id; self.query = query; self.queue = queue; self.started = started; self.deadline = deadline
            self.permitted = permitted; self.factory = factory; self.completion = completion
        }

        func admitObservation() -> Bool {
            observation.lock(); defer { observation.unlock() }
            guard !observed else { return false }
            observed = true; return true
        }
    }
    private final class Pending {
        let token = UUID()
        let executionContext: DNSQueryExecutionContext
        let query: Data
        let prepared: DNSQueryCache.PreparedQuery
        let permitted: () -> Bool
        let factory: Factory
        let deadline: DispatchTime
        var waiters: [UUID: Waiter] = [:]
        var transport: DNSQueryDatagram?
        var timeout: DispatchWorkItem?
        var retiring = false, retirementAcknowledged = false
        var retirementBarrier: DNSProxyFallbackBarrier?
        let queuedAt = DNSQueryMonotonicClock.now()

        init(query: Data, prepared: DNSQueryCache.PreparedQuery,
             permitted: @escaping () -> Bool, factory: @escaping Factory,
             deadline: DispatchTime, executionContext: DNSQueryExecutionContext = DNSQueryExecutionContext()) {
            self.query = query; self.prepared = prepared; self.permitted = permitted
            self.factory = factory; self.deadline = deadline; self.executionContext = executionContext
        }
    }
    private struct QueuedLeader {
        let key: Key
        let token: UUID
    }

    private let queue = DispatchQueue(label: "app.hajimi.dns.single-flight", qos: .userInitiated)
    private let cache: DNSQueryCache
    private let diagnostics: any DNSQueryObserver
    private let classifyFailure: (Error) -> DNSQueryFailureClassification
    private let makeInvalidResponseError: () -> Error
    private let maximumPending: Int
    private let maximumWaiters: Int
    private let maximumWaitersPerQuery: Int
    private let maximumActiveUpstreams: Int
    private let timeout: DispatchTimeInterval
    private var pending: [Key: Pending] = [:]
    private var requests: [UUID: Key] = [:]
    // The admitted logical work stays bounded by the existing waiter budget;
    // a browsing burst is queued instead of becoming a burst of TCP/TLS dials.
    // These slots describe logical queries, not native cancellation/FD ACKs.
    private var running = Set<UUID>()
    private var waiting: [QueuedLeader] = []
    private var pumping = false, invalidating = false
    private var upstreamQueries = 0, cacheHits = 0, mergedQueries = 0

    package init(cache: DNSQueryCache = DNSQueryCache(), maximumPending: Int = 512,
         maximumWaiters: Int = 512, maximumWaitersPerQuery: Int = 64,
         maximumActiveUpstreams: Int = 16,
         timeout: DispatchTimeInterval = .seconds(8),
         observer: any DNSQueryObserver,
         classifyFailure: @escaping (Error) -> DNSQueryFailureClassification,
         makeInvalidResponseError: @escaping () -> Error) {
        self.cache = cache
        self.diagnostics = observer
        self.classifyFailure = classifyFailure
        self.makeInvalidResponseError = makeInvalidResponseError
        self.maximumPending = max(0, maximumPending)
        self.maximumWaiters = max(0, maximumWaiters)
        self.maximumWaitersPerQuery = max(0, maximumWaitersPerQuery)
        self.maximumActiveUpstreams = min(max(0, maximumActiveUpstreams), max(0, maximumPending))
        self.timeout = timeout
    }

    @discardableResult
    package func resolve(scope: String, query: Data, callbackQueue: DispatchQueue,
                 absoluteDeadline: TimeInterval? = nil,
                 permitted: @escaping () -> Bool,
                 factory: @escaping Factory, completion: @escaping (Data?) -> Void) -> UUID {
        let id = UUID()
        let waiter = Waiter(id: id, query: query, queue: callbackQueue,
                            started: DNSQueryMonotonicClock.now(),
                            deadline: Self.queryDeadline(timeout: timeout, absoluteDeadline: absoluteDeadline),
                            permitted: permitted, factory: factory, completion: completion)
        diagnostics.recordDNS(.query)
        queue.async {
            guard permitted() else { self.deliver(nil, to: waiter, outcome: .cancelled); return }
            guard DispatchTime.now() < waiter.deadline else {
                self.deliver(nil, to: waiter, failureReason: .timeout); return
            }
            let prepared = DNSQueryCache.prepare(query)
            self.diagnostics.recordDNS(prepared.cacheEligible ? .cacheEligible : .cacheBypassed)
            if let response = self.cache.lookup(scopeKey: scope, prepared: prepared) {
                self.cacheHits += 1
                self.diagnostics.recordDNS(.cacheHit)
                self.deliver(response, to: waiter)
                return
            }
            let identity = prepared.coalescingIdentity
            let key = Key(scope: scope, question: identity ?? query,
                          unique: identity == nil ? id : nil)
            if let active = self.pending[key], DispatchTime.now() >= active.deadline {
                self.finish(key, token: active.token, answer: nil, deadlineExpired: true)
            }
            guard self.requests.count < self.maximumWaiters,
                  self.maximumWaitersPerQuery > 0 else {
                self.deliver(nil, to: waiter, failureReason: .capacity); return
            }
            if let active = self.pending[key] {
                guard active.waiters.count < self.maximumWaitersPerQuery else {
                    self.deliver(nil, to: waiter, failureReason: .capacity); return
                }
                active.waiters[id] = waiter; self.requests[id] = key
                self.associate(waiter, context: active.executionContext, merged: true)
                // Each original caller owns its timer across generations.
                // It cannot extend the current leader's transport deadline.
                self.scheduleWaiterDeadline(waiter)
                self.mergedQueries += 1
                self.diagnostics.recordDNS(.merged)
                self.resumeFollowers(key, active: active)
                return
            }
            guard self.pending.count < self.maximumPending, self.maximumActiveUpstreams > 0 else {
                self.deliver(nil, to: waiter, failureReason: .capacity); return
            }
            let active = Pending(query: query, prepared: prepared, permitted: permitted, factory: factory,
                                 deadline: waiter.deadline)
            self.associate(waiter, context: active.executionContext)
            active.waiters[id] = waiter
            self.pending[key] = active; self.requests[id] = key
            self.scheduleWaiterDeadline(waiter)
            self.enqueue(key, active: active)
            self.pumpStarts()
        }
        return id
    }

    package func cancel(_ id: UUID, deadlineExpired: Bool = false) {
        queue.async {
            guard let key = self.requests.removeValue(forKey: id), let active = self.pending[key] else { return }
            if let waiter = active.waiters.removeValue(forKey: id) {
                waiter.timeout?.cancel()
                // The outer ingress timer can precede this coordinator's
                // timer. Do not drop a genuine total timeout from diagnostics
                // merely because it arrives through the cancellation API.
                waiter.queue.async {
                    self.observe(waiter, outcome: deadlineExpired && waiter.permitted() ? .failure : .cancelled,
                                 failureReason: .timeout)
                }
            }
            // Cancelling a leader is not permission to cancel followers.
            if active.waiters.isEmpty {
                self.finish(key, token: active.token, answer: nil,
                            deadlineExpired: deadlineExpired, cancelled: !deadlineExpired,
                            cancellationReason: .callerCancelled)
            }
        }
    }

    package func invalidate() {
        queue.async {
            // Completing an active entry normally starts the next FIFO item.
            // An epoch flush must first revoke EVERY old queued factory.
            self.invalidating = true
            self.cache.removeAll()
            for (key, active) in Array(self.pending) {
                self.finish(key, token: active.token, answer: nil, cancelled: true,
                            cancellationReason: .policyChanged)
            }
            self.waiting.removeAll()
            self.invalidating = false
            self.pumpStarts()
        }
    }

    package var statistics: Statistics {
        queue.sync {
            Statistics(upstreamQueries: upstreamQueries, cacheHits: cacheHits,
                       mergedQueries: mergedQueries, pendingQueries: pending.count,
                       waitingClients: requests.count, activeUpstreams: running.count,
                       queuedUpstreams: waiting.count)
        }
    }

    package func deadlineForSelfTest(scope: String, query: Data) -> UInt64? {
        queue.sync {
            guard let identity = DNSQueryCache.coalescingIdentity(for: query) else { return nil }
            return pending[Key(scope: scope, question: identity, unique: nil)]?.deadline.uptimeNanoseconds
        }
    }

    private func finish(_ key: Key, token: UUID, answer: Data?, deadlineExpired: Bool = false,
                        cancelled: Bool = false, failureReason: DNSQueryFailureReason = .upstreamOrResponse,
                        error: Error? = nil,
                        fromCache: Bool = false,
                        cancellationReason: DNSAttemptCancellationReason = .cleanup) {
        guard let active = pending[key], active.token == token else { return }
        let permissionRevoked = !cancelled && !active.permitted()
        let interrupted = cancelled || permissionRevoked
        let expired = !interrupted && (deadlineExpired || DispatchTime.now() >= active.deadline)
        if !interrupted, !expired,
           let timeout = error as? DNSQueryTimeoutError, timeout.inheritedDeadlineReached,
           active.transport is any DNSQueryDeadlineAcknowledging {
            // A child's converted clock can reach this same inherited deadline
            // before our installed timer. Keep the group and its deny metadata
            // until that original timer performs the real retirement fence.
            // No new timer or additional query budget is created here.
            retainRetirementBarrier(answer: answer, error: error, active: active)
            return
        }
        if active.retiring, !active.retirementAcknowledged {
            retainRetirementBarrier(answer: answer, error: error, active: active)
            if interrupted {
                for waiter in active.waiters.values {
                    requests.removeValue(forKey: waiter.id); waiter.timeout?.cancel()
                    deliver(nil, to: waiter, outcome: .cancelled)
                }
                active.waiters.removeAll()
            }
            // Even an empty group reserves its bounded key until the real
            // fence returns. A newly admitted caller cannot skip a pending
            // auth/REFUSED snapshot by arriving between the last timeout and
            // the old child's logical ACK.
            return
        }
        if !interrupted, active.retiring {
            // The generation remains installed until the real deadline fence
            // returns. Old callbacks can only retain a deny/negative barrier;
            // they cannot complete or cache a replacement's answer.
            retainRetirementBarrier(answer: answer, error: error, active: active)
            return
        }
        if !interrupted, expired, DispatchTime.now() >= active.deadline,
           active.transport == nil || active.transport is any DNSQueryDeadlineAcknowledging {
            retire(key, active: active, transport: active.transport as? any DNSQueryDeadlineAcknowledging,
                   answer: answer, error: error)
            return
        }
        pending.removeValue(forKey: key)
        running.remove(token)
        // Eagerly remove tombstones: repeated cancel/admit cycles must not
        // retain an unbounded FIFO behind a single slow active leader.
        waiting.removeAll { $0.token == token }
        active.timeout?.cancel()
        if active.retiring {
            // Deadline cleanup already owns the child. A later caller/policy
            // cancellation must not overwrite its original timeout admission.
        } else if expired, let timed = active.transport as? any DNSQueryDeadlineAwareDatagram {
            timed.queryDeadlineReached()
        } else if let acknowledging = active.transport as? any DNSQueryCancellationAcknowledging {
            acknowledging.cancel(reason: expired ? .overallDeadline
                : (permissionRevoked ? .policyChanged : cancellationReason), completion: {})
        } else { active.transport?.cancel() }
        active.transport = nil
        let accepted = answer.flatMap { response -> Data? in
            guard !interrupted, !expired,
                  DNSMessageInspection.responseMatchesQuery(response, query: active.query) else { return nil }
            return response
        }
        if let accepted, !fromCache, active.prepared.cacheEligible {
            let stored = cache.store(scopeKey: key.scope, prepared: active.prepared, response: accepted)
            diagnostics.recordDNS(stored ? .cacheStore : .cacheStoreRejected)
        }
        for (id, waiter) in active.waiters {
            requests.removeValue(forKey: id)
            waiter.timeout?.cancel()
            let response = accepted.flatMap { DNSQueryCache.rewritingResponseID($0, for: waiter.query) }
            deliver(response, to: waiter, outcome: interrupted ? .cancelled : nil,
                    failureReason: expired ? .timeout : failureReason)
        }
        active.waiters.removeAll()
        pumpStarts()
    }

    private func enqueue(_ key: Key, active: Pending) {
        let token = active.token
        let deadline = DispatchWorkItem { [weak self] in
            self?.finish(key, token: token, answer: nil, deadlineExpired: true)
        }
        active.timeout = deadline
        queue.asyncAfter(deadline: active.deadline, execute: deadline)
        waiting.append(QueuedLeader(key: key, token: token))
    }

    private func scheduleWaiterDeadline(_ waiter: Waiter) {
        guard waiter.timeout == nil else { return }
        let id = waiter.id
        let timer = DispatchWorkItem { [weak self] in self?.expireWaiter(id) }
        waiter.timeout = timer
        queue.asyncAfter(deadline: waiter.deadline, execute: timer)
    }

    private func retainRetirementBarrier(answer: Data?, error: Error?, active: Pending) {
        if let answer {
            if !DNSMessageInspection.responseMatchesQuery(answer, query: active.query) {
                if active.retirementBarrier == nil {
                    active.retirementBarrier = .failure(makeInvalidResponseError())
                }
            } else if ![UInt8(0), 3].contains(answer[answer.startIndex + 3] & 0x0f),
                      active.retirementBarrier == nil {
                // A valid negative result, including REFUSED, is terminal.
                // Positive callbacks after retirement are ignored; the fenced
                // child owns any answer admitted before revoking registration.
                active.retirementBarrier = .answer(answer)
            }
        }
        if let error, !isTypedTimeout(error),
           !classifyFailure(error).permitsProxyFallback,
           active.retirementBarrier == nil {
            active.retirementBarrier = .failure(error)
        }
    }

    private func retire(_ key: Key, active: Pending, transport: (any DNSQueryDeadlineAcknowledging)?,
                        answer: Data?, error: Error?) {
        active.retiring = true
        active.timeout?.cancel(); active.timeout = nil
        waiting.removeAll { $0.token == active.token }
        retainRetirementBarrier(answer: answer, error: error, active: active)
        for waiter in Array(active.waiters.values) where waiter.deadline <= active.deadline || DispatchTime.now() >= waiter.deadline {
            active.waiters.removeValue(forKey: waiter.id); requests.removeValue(forKey: waiter.id)
            waiter.timeout?.cancel()
            deliver(nil, to: waiter, failureReason: .timeout)
        }
        let token = active.token
        // Hold the child through its real logical ACK, even if every original
        // caller cancels meanwhile. Its native attempt leases remain separate.
        let acknowledged: (DNSProxyFallbackBarrier?) -> Void = { [weak self, transport] barrier in
            self?.queue.async {
                _ = transport
                guard let self, let current = self.pending[key], current.token == token,
                      current.retiring, !current.retirementAcknowledged else { return }
                self.running.remove(token)
                current.retirementAcknowledged = true; current.transport = nil
                if current.retirementBarrier == nil { current.retirementBarrier = barrier }
                self.resumeFollowers(key, active: current)
            }
        }
        if let transport {
            transport.queryDeadlineReached(completion: acknowledged)
            queue.asyncAfter(deadline: .now() + 2.0) {
                acknowledged(nil)
            }
        }
        else { acknowledged(nil) } // An unstarted/throwing factory registered no child I/O.
        pumpStarts()
    }

    private func resumeFollowers(_ key: Key, active: Pending) {
        guard pending[key] === active, active.retiring, active.retirementAcknowledged else { return }
        guard active.permitted() else {
            finish(key, token: active.token, answer: nil, cancelled: true,
                   cancellationReason: .policyChanged); return
        }
        for waiter in Array(active.waiters.values) {
            if !waiter.permitted() {
                active.waiters.removeValue(forKey: waiter.id); requests.removeValue(forKey: waiter.id)
                waiter.timeout?.cancel(); deliver(nil, to: waiter, outcome: .cancelled)
            } else if DispatchTime.now() >= waiter.deadline {
                active.waiters.removeValue(forKey: waiter.id); requests.removeValue(forKey: waiter.id)
                waiter.timeout?.cancel(); deliver(nil, to: waiter, failureReason: .timeout)
            }
        }
        guard !active.waiters.isEmpty else {
            finish(key, token: active.token, answer: nil, cancelled: true); return
        }
        if let barrier = active.retirementBarrier {
            pending.removeValue(forKey: key)
            for waiter in active.waiters.values {
                requests.removeValue(forKey: waiter.id); waiter.timeout?.cancel()
                switch barrier {
                case .failure(let error): deliver(nil, to: waiter, failureReason: self.failureReason(error))
                case .answer(let answer):
                    let matched = DNSMessageInspection.responseMatchesQuery(answer, query: active.query)
                    let response = matched ? DNSQueryCache.rewritingResponseID(answer, for: waiter.query) : nil
                    // A fenced retained answer may serve a caller that still
                    // has its own budget, but never revives an expired waiter
                    // or restarts the old answer's cache TTL.
                    deliver(response, to: waiter, failureReason: matched ? .upstreamOrResponse : .invalidResponse)
                }
            }
            active.waiters.removeAll(); pumpStarts(); return
        }
        // Only a genuinely expired generation can transfer ownership. Choose
        // the latest original deadline so existing followers share one new
        // child instead of repeatedly sponsoring the same admitted burst.
        guard let leader = active.waiters.values.filter({ $0.deadline > active.deadline }).max(by: {
            if $0.deadline != $1.deadline { return $0.deadline < $1.deadline }
            if $0.started != $1.started { return $0.started > $1.started }
            return $0.id.uuidString > $1.id.uuidString
        }) else {
            finish(key, token: active.token, answer: nil, cancelled: true); return
        }
        let replacement = Pending(query: leader.query, prepared: DNSQueryCache.prepare(leader.query),
            permitted: leader.permitted, factory: leader.factory, deadline: leader.deadline,
            executionContext: active.executionContext.child(
                absoluteDeadline: Self.absoluteDeadline(leader.deadline)))
        replacement.waiters = active.waiters; active.waiters.removeAll()
        pending[key] = replacement
        enqueue(key, active: replacement)
        pumpStarts()
    }

    private static func queryDeadline(timeout: DispatchTimeInterval,
                                      absoluteDeadline: TimeInterval?) -> DispatchTime {
        // Capture the budget at resolve() invocation, not on queue admission
        // or after a leader acquires its upstream slot.
        let now = DispatchTime.now(), local = now + timeout
        guard let absoluteDeadline else { return local }
        guard absoluteDeadline.isFinite else { return now }
        let inherited = now + max(0, absoluteDeadline - ProcessInfo.processInfo.systemUptime)
        return min(local, inherited)
    }

    private static func absoluteDeadline(_ deadline: DispatchTime) -> TimeInterval {
        // Translate the remaining duration, not the epochs of Darwin's two
        // monotonic clocks. Capture uptime first so conversion cannot add time.
        let uptime = ProcessInfo.processInfo.systemUptime
        let now = DispatchTime.now().uptimeNanoseconds
        let remaining = deadline.uptimeNanoseconds > now
            ? Double(deadline.uptimeNanoseconds - now) / 1_000_000_000 : 0
        return uptime + remaining
    }

    private func expireWaiter(_ id: UUID) {
        guard let key = requests[id], let active = pending[key], let waiter = active.waiters[id] else { return }
        active.waiters.removeValue(forKey: id)
        requests.removeValue(forKey: id); waiter.timeout?.cancel()
        deliver(nil, to: waiter, failureReason: .timeout)
        if active.waiters.isEmpty {
            finish(key, token: active.token, answer: nil, deadlineExpired: !active.retiring,
                   cancelled: active.retiring)
        }
    }

    private func pumpStarts() {
        guard !pumping, !invalidating else { return }
        pumping = true
        defer { pumping = false }
        while running.count < maximumActiveUpstreams, !waiting.isEmpty {
            let leader = waiting.removeFirst()
            let key = leader.key, token = leader.token
            guard let active = pending[key], active.token == token, !active.retiring else { continue }
            guard active.permitted() else {
                finish(key, token: token, answer: nil, cancelled: true,
                       cancellationReason: .policyChanged); continue
            }
            let now = DispatchTime.now()
            guard now < active.deadline else {
                finish(key, token: token, answer: nil, deadlineExpired: true); continue
            }
            // A shorter-lived follower's timer may be behind this pump on the
            // owner queue. Retire it before either cache delivery or new IO.
            for (id, waiter) in Array(active.waiters) where now >= waiter.deadline {
                expireWaiter(id)
            }
            guard pending[key] === active, !active.waiters.isEmpty else { continue }
            if let answer = cache.lookup(scopeKey: key.scope, prepared: active.prepared) {
                cacheHits += active.waiters.count
                diagnostics.recordDNS(.cacheHit, count: active.waiters.count)
                // A queued cache hit retains the original expiry. Re-storing
                // its rounded-down wire TTL could extend it on every handoff.
                finish(key, token: token, answer: answer, fromCache: true); continue
            }
            running.insert(token)
            diagnostics.recordDNSUpstreamStart(rootID: active.executionContext.rootID,
                generationID: token, queuedAt: active.queuedAt, started: DNSQueryMonotonicClock.now())
            do {
                active.transport = try active.factory(queue, { [weak self] answer in
                    self?.queue.async { self?.finish(key, token: token, answer: answer) }
                }, { [weak self] error in
                    self?.queue.async {
                        guard let self else { return }
                        self.finish(key, token: token, answer: nil, failureReason: self.failureReason(error), error: error)
                    }
                })
                // A delayed factory cannot gain permission from an earlier
                // admission or receive a fresh timeout when its slot opens.
                guard active.permitted() else {
                    finish(key, token: token, answer: nil, cancelled: true,
                           cancellationReason: .policyChanged); continue
                }
                guard DispatchTime.now() < active.deadline else {
                    finish(key, token: token, answer: nil, deadlineExpired: true); continue
                }
                (active.transport as? DNSQueryExecutionContextAccepting)?
                    .setDNSQueryExecutionContext(active.executionContext.child(
                        absoluteDeadline: Self.absoluteDeadline(active.deadline)))
                upstreamQueries += 1
                active.transport?.send(active.query)
            } catch {
                finish(key, token: token, answer: nil, failureReason: self.failureReason(error), error: error)
            }
        }
    }

    private func deliver(_ answer: Data?, to waiter: Waiter,
                         outcome: DNSQueryOutcome? = nil,
                         failureReason: DNSQueryFailureReason = .upstreamOrResponse) {
        // Completion is admitted here on the coordinator, before the original
        // deadline. A busy caller queue must not retroactively turn an already
        // completed response into an upstream timeout or let its later timer
        // overtake an earlier FIFO answer. Permission is still rechecked at
        // the actual handoff; an expired queued leader/follower gets no answer.
        let expired = DispatchTime.now() >= waiter.deadline
        let admitted = expired ? nil : answer
        let admittedReason: DNSQueryFailureReason = answer != nil && expired ? .timeout : failureReason
        // Cache hits and pre-admission refusals have no physical attempt, but
        // still need a single-waiter root beside the application DNS counters.
        // Reserve it only after the original deadline/admission decision.
        associate(waiter)
        waiter.queue.async {
            let current = waiter.permitted()
            let response = current ? admitted : nil
            let code: UInt8? = response.flatMap {
                $0.count >= 4 ? $0[$0.startIndex + 3] & 0x0f : nil
            }
            // NXDOMAIN is a valid completed lookup, not an unavailable resolver.
            let resolvedOutcome: DNSQueryOutcome = !current ? .cancelled
                : outcome ?? (code == 0 || code == 3 ? .success : .failure)
            // Known failures also retain their original classification across
            // callback delay; no successful completion restarts any IO budget.
            self.observe(waiter, outcome: resolvedOutcome, failureReason: admittedReason)
            waiter.completion(response)
        }
    }

    private func observe(_ waiter: Waiter, outcome: DNSQueryOutcome,
                         failureReason: DNSQueryFailureReason) {
        guard waiter.admitObservation() else { return }
        let milliseconds = DNSQueryMonotonicClock.elapsedMilliseconds(since: waiter.started)
        diagnostics.recordResolution(milliseconds: milliseconds, outcome: outcome)
        if outcome == .failure { diagnostics.recordDNSFailure(failureReason) }
        else if outcome == .cancelled { diagnostics.recordDNS(.cancelled) }
        if let rootID = waiter.rootID {
            diagnostics.finishDNSQueryWaiter(rootID: rootID, waiterID: waiter.id, outcome: outcome,
                failureReason: outcome == .failure ? failureReason : nil, milliseconds: milliseconds)
        }
    }

    private func associate(_ waiter: Waiter, context: DNSQueryExecutionContext? = nil, merged: Bool = false) {
        guard waiter.rootID == nil else { return }
        let rootID = context?.rootID ?? UUID()
        waiter.rootID = rootID
        let deadline = Double(waiter.deadline.uptimeNanoseconds) / 1_000_000_000
        if merged {
            diagnostics.joinDNSQuery(rootID: rootID, waiterID: waiter.id,
                started: waiter.started, absoluteDeadline: deadline)
        } else {
            diagnostics.beginDNSQuery(rootID: rootID, waiterID: waiter.id,
                started: waiter.started, absoluteDeadline: deadline)
        }
    }

    private func failureReason(_ error: Error) -> DNSQueryFailureReason {
        classifyFailure(error).reason
    }

    private func isTypedTimeout(_ error: Error) -> Bool {
        classifyFailure(error).isTimeout
    }

    deinit {
        pending.values.forEach {
            $0.timeout?.cancel()
            if $0.retiring {
                // The deadline fence independently retains its closing child.
            } else if let acknowledging = $0.transport as? any DNSQueryCancellationAcknowledging {
                acknowledging.cancel(reason: .cleanup, completion: {})
            } else { $0.transport?.cancel() }
            $0.waiters.values.forEach { $0.timeout?.cancel() }
        }
    }
}

/// A one-query lease over the coordinator. It preserves the datagram interface
/// used by UDP and framed TCP ingress without sharing cancellation ownership.
package final class DNSCoalescedQueryDatagram: DNSQueryDeadlineAwareDatagram {
    private let coordinator: DNSQueryCoordinator
    private let scope: String
    private let queue: DispatchQueue
    private let absoluteDeadline: TimeInterval?
    private let permitted: () -> Bool
    private let factory: DNSQueryCoordinator.Factory
    private let receive: (Data) -> Void
    private let failure: (Error) -> Void
    private let admission = NSLock()
    private var closed = false
    private var started = false
    private var request: UUID?

    package init(coordinator: DNSQueryCoordinator, scope: String, queue: DispatchQueue,
         absoluteDeadline: TimeInterval? = nil,
         permitted: @escaping () -> Bool, factory: @escaping DNSQueryCoordinator.Factory,
         receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
        self.coordinator = coordinator; self.scope = scope
        self.queue = DispatchQueue(label: "app.hajimi.dns.single-flight.lease", target: queue)
        self.absoluteDeadline = absoluteDeadline
        self.permitted = permitted; self.factory = factory
        self.receive = receive; self.failure = failure
    }

    package func send(_ data: Data) {
        queue.async {
            self.admission.lock(); let stopped = self.closed; self.admission.unlock()
            guard !stopped, !self.started else { return }
            self.started = true
            self.request = self.coordinator.resolve(scope: self.scope, query: data, callbackQueue: self.queue,
                absoluteDeadline: self.absoluteDeadline,
                permitted: self.permitted, factory: self.factory) { [weak self] answer in
                guard let self else { return }
                self.request = nil
                self.admission.lock(); let stopped = self.closed; self.admission.unlock()
                guard !stopped else { return }
                if let answer { self.receive(answer) }
                else { self.failure(DNSQueryCoordinationError()) }
            }
        }
    }

    package func queryDeadlineReached() { stop(deadlineExpired: true) }
    package func cancel() { stop(deadlineExpired: false) }
    private func stop(deadlineExpired: Bool) {
        admission.lock()
        guard !closed else { admission.unlock(); return }
        closed = true; admission.unlock()
        queue.async {
            if let request = self.request {
                self.coordinator.cancel(request, deadlineExpired: deadlineExpired); self.request = nil
            }
        }
    }

    deinit { if let request { coordinator.cancel(request) } }
}

private struct DNSQueryCoordinationError: LocalizedError {
    var errorDescription: String? { "DNS 查询失败、已取消或策略已更新；未绕过当前 DNS 出口策略" }
}

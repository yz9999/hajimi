import Foundation

/// Per-question evidence from the transport owner, not an inference from the
/// previous query. A stale idle connection followed by a fresh dial is cold.
public enum DNSQueryTransportEvidence: Equatable {
    case unknown, notStarted, fresh, reused, reusedThenFresh
}

package enum DNSAdaptiveLatencyPhase { case cold, transport, tls, response }

/// Router-local health observations, never resolver or policy authority. The
/// caller passes only already-approved encrypted candidates and owns the wire
/// deadline. Exploration substitutes one primary; it never creates fan-out.
public final class DNSAdaptiveUpstreamSelector {
    /// The caller owns this bounded-lifetime receipt. The selector retains no
    /// in-flight ticket table; all mutable ticket state uses its owner's lock.
    public final class Observation {
        fileprivate let owner: UUID, scope: UUID
        fileprivate let scopeKey: String, candidateID: String
        fileprivate var consumed = false
        fileprivate init(owner: UUID, scope: UUID, scopeKey: String, candidateID: String) {
            self.owner = owner; self.scope = scope
            self.scopeKey = scopeKey; self.candidateID = candidateID
        }
    }

    private struct LatencySample { let milliseconds: Double, observedAt: TimeInterval }
    private struct LatencyWindow {
        var mean: Double?
        var samples: [LatencySample] = []
        mutating func record(_ milliseconds: Double, now: TimeInterval) {
            mean = mean.map { $0 * 0.75 + milliseconds * 0.25 } ?? milliseconds
            if samples.isEmpty { samples.reserveCapacity(sampleLimit) }
            if samples.count == sampleLimit { samples.removeFirst() }
            samples.append(LatencySample(milliseconds: milliseconds, observedAt: now))
        }
        mutating func expire(now: TimeInterval) {
            samples.removeAll { now - $0.observedAt >= maximumAge }
            if samples.isEmpty { mean = nil }
        }
        func estimate(now: TimeInterval) -> Double? {
            guard let mean, let latest = samples.last else { return nil }
            let weighted = samples.filter { now - $0.observedAt < maximumAge }.map {
                (milliseconds: $0.milliseconds, weight: decayFactor(now - $0.observedAt))
            }.sorted { $0.milliseconds < $1.milliseconds }
            let target = weighted.reduce(0) { $0 + $1.weight } * 0.95
            guard target > 0 else { return nil }
            var accumulated = 0.0, tail = weighted.last!.milliseconds
            for sample in weighted {
                accumulated += sample.weight
                if accumulated >= target { tail = sample.milliseconds; break }
            }
            // Old path measurements gradually lose influence even when only
            // one successful sample exists; they never become fabricated RTTs.
            let confidence = decayFactor(now - latest.observedAt)
            return (mean * 0.5 + tail * 0.5) * confidence + 500 * (1 - confidence)
        }
        func jitter(now: TimeInterval) -> Double? {
            let active = samples.filter { now - $0.observedAt < maximumAge }
            guard active.count >= 2 else { return active.isEmpty ? nil : 0 }
            var weightSum = 0.0
            var weightedMean = 0.0
            for s in active {
                let w = decayFactor(now - s.observedAt)
                weightSum += w
                weightedMean += w * s.milliseconds
            }
            guard weightSum > 0 else { return nil }
            weightedMean /= weightSum
            var varianceSum = 0.0
            for s in active {
                let w = decayFactor(now - s.observedAt)
                let diff = s.milliseconds - weightedMean
                varianceSum += w * diff * diff
            }
            return sqrt(max(0, varianceSum / weightSum))
        }
    }

    private struct Health {
        // Kept separately from the ranking score for deadline consumers.
        var latency: Double?
        var lastSuccess: TimeInterval?
        var unknown = LatencyWindow(), fresh = LatencyWindow(), reused = LatencyWindow()
        var transportSetup = LatencyWindow(), tlsHandshake = LatencyWindow(), response = LatencyWindow()
        var successWeight = 0.0, failureWeight = 0.0
        var updatedAt: TimeInterval?
        var pendingLatencyLowerBound: Double?
        var pendingAt: TimeInterval?
        var failures = 0
        var successes = 0
        var cooldown: TimeInterval = 0
        var lastUsed: TimeInterval = 0

        mutating func decay(now: TimeInterval) {
            if let updatedAt {
                let factor = decayFactor(now - updatedAt)
                successWeight *= factor; failureWeight *= factor
            }
            updatedAt = now
            unknown.expire(now: now); fresh.expire(now: now); reused.expire(now: now)
            transportSetup.expire(now: now); tlsHandshake.expire(now: now); response.expire(now: now)
            if let lastSuccess, now - lastSuccess >= maximumAge { latency = nil; successes = 0 }
            if let pendingAt, now - pendingAt >= maximumAge {
                pendingLatencyLowerBound = nil; self.pendingAt = nil
            }
            if successWeight + failureWeight < 0.01 { failures = 0 }
        }

        var successProbability: Double {
            // A bounded prior avoids declaring a provider perfect from one
            // success, or permanently unavailable after one old failure.
            (successWeight + 8) / (successWeight + failureWeight + 10)
        }

        func hasCurrentSuccess(now: TimeInterval) -> Bool {
            guard let lastSuccess else { return false }
            return successes > 0 && failures == 0 && cooldown <= now
                && now - lastSuccess < maximumAge
        }

        func score(now: TimeInterval) -> Double {
            // Without current pool evidence, prefer a measured cold cost. Hot
            // successes cannot erase cold setup cost or pose as fresh samples.
            let measured = fresh.estimate(now: now) ?? unknown.estimate(now: now)
            let reusedEstimate = reused.estimate(now: now)
            let latency = measured ?? max(500, reusedEstimate ?? 500)
            let pending = pendingLatencyLowerBound.map {
                $0 * decayFactor(now - (pendingAt ?? now))
            } ?? 0
            let effectiveLatency = (measured == nil && reusedEstimate == nil)
                ? (latency + pending)
                : max(latency, pending)
            return effectiveLatency + (1 - successProbability) * 8_000
        }
    }
    private struct Scope {
        let id = UUID()
        var health: [String: Health]
        var preferred: String?
        var queries: UInt64 = 0
        var lastProbe: TimeInterval
        var access: UInt64 = 0
        let cost: Int
    }
    private static let sampleLimit = 8
    private static let maximumAge: TimeInterval = 15 * 60
    private static func decayFactor(_ elapsed: TimeInterval) -> Double {
        pow(0.5, max(0, elapsed) / 120)
    }
    private let lock = NSLock()
    private let identity = UUID()
    private let clock: () -> TimeInterval
    private let maximumScopes: Int, maximumBytes: Int, probeEvery: UInt64
    private let probeInterval: TimeInterval
    private var scopes: [String: Scope] = [:]
    private var bytes = 0
    private var access: UInt64 = 0
    private var lastClock: TimeInterval?

    public init(clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
                maximumScopes: Int = 128, maximumBytes: Int = 2 * 1024 * 1024,
                probeInterval: TimeInterval = 30, probeEvery: Int = 16) {
        self.clock = clock
        self.maximumScopes = min(128, max(0, maximumScopes))
        self.maximumBytes = min(8 * 1024 * 1024, max(0, maximumBytes))
        self.probeInterval = probeInterval.isFinite ? min(3600, max(0.001, probeInterval)) : 30
        self.probeEvery = UInt64(min(1024, max(2, probeEvery)))
    }

    /// A resolver may answer ordinary names while reverse questions time out.
    /// Keep those answer-health observations in two bounded domains, without
    /// changing transport reuse, cache identity or resolver authorization.
    /// Ordinary types retain their shared history; names and PTR target
    /// categories never create additional health domains.
    package static func queryHealthScope(scopeKey: String, query: Data) -> String {
        guard DNSMessageInspection.singleQuestion(in: query)?.type == 12 else { return scopeKey }
        return ["reverse-query-health-v1", scopeKey]
            .map { "\($0.utf8.count):\($0)" }.joined()
    }

    /// Must be called for a real upstream exchange, not cache hits or waiters
    /// joining single-flight. The returned order contains no added endpoint.
    public func orderedCandidates(scopeKey: String, candidateIDs: [String]) -> [String] {
        schedulingOrder(scopeKey: scopeKey, candidateIDs: candidateIDs).candidateIDs
    }

    /// Keep the bounded exploration decision with this particular query.
    /// Reading a later global scope snapshot could confuse concurrent probes.
    package func schedulingOrder(scopeKey: String, candidateIDs: [String])
        -> (candidateIDs: [String], explorationID: String?) {
        var seen = Set<String>(), values: [String] = []
        // At most 16 configured providers with two built-in IP variants each.
        // This only bounds observations; the caller still authorizes providers
        // and admits at most three attempts, with two live transports.
        for id in candidateIDs where !id.isEmpty && seen.insert(id).inserted {
            values.append(id)
            if values.count == 32 { break }
        }
        guard !values.isEmpty else { return ([], nil) }
        guard maximumScopes > 0, scopeKey.utf8.count <= 131_072,
              values.allSatisfy({ $0.utf8.count <= 8192 }) else { return (values, nil) }
        // Reserve the full retained sample capacity up front, including each
        // array's allocation allowance. Growth cannot outrun byte admission.
        let candidateCost = MemoryLayout<Health>.stride
            + 6 * (Self.sampleLimit * MemoryLayout<LatencySample>.stride + 64) + 128
        let cost = scopeKey.utf8.count + values.reduce(192) { $0 + $1.utf8.count + candidateCost }
        guard cost <= maximumBytes else { return (values, nil) }
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now) else { return (values, nil) }
        var state: Scope
        if let existing = scopes[scopeKey], Set(existing.health.keys) == Set(values) { state = existing }
        else {
            let previous = scopes[scopeKey]?.health ?? [:]
            remove(scopeKey)
            while !scopes.isEmpty && (scopes.count >= maximumScopes || cost > maximumBytes - bytes) {
                guard let oldest = scopes.min(by: { $0.value.access < $1.value.access })?.key else { return (values, nil) }
                remove(oldest)
            }
            guard scopes.count < maximumScopes, cost <= maximumBytes - bytes else { return (values, nil) }
            state = Scope(health: Dictionary(uniqueKeysWithValues: values.map { ($0, previous[$0] ?? Health()) }),
                          lastProbe: now, cost: cost)
            bytes += cost
        }
        for id in values { state.health[id]!.decay(now: now) }
        let positions = Dictionary(uniqueKeysWithValues: values.enumerated().map { ($0.element, $0.offset) })
        let scores = Dictionary(uniqueKeysWithValues: values.map { ($0, state.health[$0]!.score(now: now)) })
        var ordered = values.sorted { left, right in
            let a = state.health[left]!, b = state.health[right]!
            let aCooling = a.cooldown > now, bCooling = b.cooldown > now
            if aCooling != bCooling { return !aCooling }
            // An untried backup's 2100ms prior is not a measured advantage
            // over a working path whose cold setup happened to be slower.
            // Keep current successes ahead during ordinary selection; the
            // existing bounded probe below may still explore an unknown IP.
            let aSucceeded = a.hasCurrentSuccess(now: now), bSucceeded = b.hasCurrentSuccess(now: now)
            if aSucceeded != bSucceeded { return aSucceeded }
            let aScore = scores[left]!, bScore = scores[right]!
            return aScore == bScore ? positions[left]! < positions[right]! : aScore < bScore
        }
        if let preferred = state.preferred, let previous = state.health[preferred],
           previous.cooldown <= now,
           previous.successWeight + previous.failureWeight >= 0.01 || previous.pendingLatencyLowerBound != nil,
           let best = ordered.first, best != preferred,
           previous.hasCurrentSuccess(now: now) == state.health[best]!.hasCurrentSuccess(now: now) {
            // Merely choosing a cold candidate or issuing a receipt supplies
            // no health evidence. Only measured outcomes or a live pending
            // lower bound may keep a prior preference against current order.
            let improvement = scores[preferred]! - scores[best]!
            if improvement < max(25, scores[preferred]! * 0.1) {
                ordered.removeAll { $0 == preferred }; ordered.insert(preferred, at: 0)
            }
        }
        state.preferred = ordered.first
        state.queries &+= 1
        var explorationID: String?
        if ordered.count > 1, state.queries % probeEvery == 0, now - state.lastProbe >= probeInterval {
            let alternatives = ordered.dropFirst().filter { state.health[$0]!.cooldown <= now }
            if let probe = alternatives.min(by: { left, right in
                let a = state.health[left]!, b = state.health[right]!
                if (a.successes == 0) != (b.successes == 0) { return a.successes == 0 }
                return a.lastUsed == b.lastUsed ? positions[left]! < positions[right]! : a.lastUsed < b.lastUsed
            }) {
                ordered.removeAll { $0 == probe }; ordered.insert(probe, at: 0)
                explorationID = probe
                state.health[probe]!.pendingLatencyLowerBound = nil
                state.health[probe]!.pendingAt = nil
                state.lastProbe = now
            }
        }
        if let first = ordered.first { state.health[first]!.lastUsed = now }
        access &+= 1; state.access = access; scopes[scopeKey] = state
        return (ordered, explorationID)
    }

    public func record(scopeKey: String, candidateID: String, milliseconds: Double, success: Bool) {
        guard milliseconds.isFinite, milliseconds >= 0 else { return }
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now) else { return }
        recordLocked(scopeKey: scopeKey, candidateID: candidateID, milliseconds: milliseconds,
                     success: success, transport: .unknown, now: now)
    }

    /// Only existing approved candidate state can issue a receipt. Issuing one
    /// does not count a query, spend an exploration opportunity or create I/O.
    public func beginObservation(scopeKey: String, candidateID: String) -> Observation? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), var state = scopes[scopeKey], state.health[candidateID] != nil else { return nil }
        state.health[candidateID]!.lastUsed = now
        access &+= 1; state.access = access; scopes[scopeKey] = state
        return Observation(owner: identity, scope: state.id, scopeKey: scopeKey, candidateID: candidateID)
    }

    public func record(_ observation: Observation?, milliseconds: Double, success: Bool,
                       transport: DNSQueryTransportEvidence = .unknown) {
        record(observation, milliseconds: milliseconds, success: success, transport: transport, progress: nil)
    }

    package func record(_ observation: Observation?, milliseconds: Double, success: Bool,
                transport: DNSQueryTransportEvidence, progress: DNSQueryProgressSnapshot?) {
        guard milliseconds.isFinite, milliseconds >= 0 else { return }
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), consume(observation) else { return }
        guard transport != .notStarted, let observation else { return }
        recordLocked(scopeKey: observation.scopeKey, candidateID: observation.candidateID,
                     milliseconds: milliseconds, success: success, transport: transport, now: now, progress: progress)
    }

    private func consume(_ observation: Observation?) -> Bool {
        guard let observation, observation.owner == identity, !observation.consumed,
              scopes[observation.scopeKey]?.id == observation.scope,
              scopes[observation.scopeKey]?.health[observation.candidateID] != nil else { return false }
        observation.consumed = true
        return true
    }

    private func recordLocked(scopeKey: String, candidateID: String, milliseconds: Double,
                              success: Bool, transport: DNSQueryTransportEvidence, now: TimeInterval,
                              progress: DNSQueryProgressSnapshot? = nil) {
        guard var state = scopes[scopeKey], var health = state.health[candidateID] else { return }
        health.decay(now: now)
        if success {
            let elapsed = min(60_000, milliseconds)
            func duration(_ start: TimeInterval?, _ end: TimeInterval?) -> Double? {
                guard let start, let end, start.isFinite, end.isFinite, end >= start else { return nil }
                return min(60_000, (end - start) * 1000)
            }
            health.latency = health.latency.map { $0 * 0.75 + elapsed * 0.25 } ?? elapsed
            health.lastSuccess = now; health.successWeight += 1
            switch transport {
            case .fresh, .reusedThenFresh:
                if let progress {
                    // A stale idle lease or local queue may have consumed most
                    // of the logical RTT before this physical dial existed.
                    // Direct NW TLS has one combined TCP/TLS start event.
                    if let cold = duration(progress.transportStartedAt ?? progress.tlsStartedAt, progress.responseCompletedAt) {
                        health.fresh.record(cold, now: now)
                    }
                } else { health.fresh.record(elapsed, now: now) }
            case .reused: health.reused.record(elapsed, now: now)
            case .unknown: health.unknown.record(elapsed, now: now)
            case .notStarted: return
            }
            if let progress, transport == .fresh || transport == .reusedThenFresh {
                if let value = duration(progress.transportStartedAt, progress.transportReadyAt) {
                    health.transportSetup.record(value, now: now)
                }
                if let value = duration(progress.tlsStartedAt, progress.tlsReadyAt) {
                    health.tlsHandshake.record(value, now: now)
                }
                if let value = duration(progress.querySentAt, progress.responseCompletedAt) {
                    health.response.record(value, now: now)
                }
            }
            health.successes = min(1_000_000, health.successes + 1)
            health.failures = 0; health.cooldown = now
            health.pendingLatencyLowerBound = nil; health.pendingAt = nil
        } else {
            health.failureWeight += 1
            health.failures = min(10, health.failures + 1)
            health.cooldown = now + min(30, pow(2, Double(health.failures - 1)))
        }
        let weight = health.successWeight + health.failureWeight
        if weight > 32 { health.successWeight *= 32 / weight; health.failureWeight *= 32 / weight }
        state.health[candidateID] = health
        access &+= 1; state.access = access; scopes[scopeKey] = state
    }

    /// Only a valid code 0/3 answer may supply this observation about still
    /// pending losers. It affects ordering without calling them failures or
    /// preventing normal recovery exploration. A probe or real success resets
    /// the hint; unknown/flushed scopes cannot be recreated by a late result.
    package func recordPendingLatencyLowerBound(scopeKey: String, candidateID: String, milliseconds: Double) {
        guard milliseconds.isFinite, milliseconds >= 0 else { return }
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now) else { return }
        recordPendingLocked(scopeKey: scopeKey, candidateID: candidateID, milliseconds: milliseconds, now: now)
    }

    /// A winner supplies one censored observation for a losing attempt. It is
    /// terminal for that receipt, but never a failure or an invented success.
    package func recordPendingLatencyLowerBound(_ observation: Observation?, milliseconds: Double) {
        guard milliseconds.isFinite, milliseconds >= 0 else { return }
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), consume(observation), let observation else { return }
        recordPendingLocked(scopeKey: observation.scopeKey, candidateID: observation.candidateID,
                            milliseconds: milliseconds, now: now)
    }

    private func recordPendingLocked(scopeKey: String, candidateID: String, milliseconds: Double, now: TimeInterval) {
        guard var state = scopes[scopeKey], var health = state.health[candidateID] else { return }
        health.decay(now: now)
        let previous = health.pendingLatencyLowerBound.map {
            $0 * Self.decayFactor(now - (health.pendingAt ?? now))
        } ?? 0
        let sample = min(60_000, milliseconds)
        health.pendingLatencyLowerBound = health.successes == 0
            ? min(60_000, previous + sample)
            : max(previous, sample)
        health.pendingAt = now
        state.health[candidateID] = health
        access &+= 1; state.access = access; scopes[scopeKey] = state
    }

    /// A successful observed RTT, not a provider authorization or timeout.
    /// A bounded caller may use this to leave a known-slow approved alternate
    /// enough time inside its existing overall deadline. Reading never creates
    /// a scope, changes ordering, or revives a flushed health observation.
    package func knownLatencyMilliseconds(scopeKey: String, candidateID: String) -> Double? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), let health = scopes[scopeKey]?.health[candidateID],
              let lastSuccess = health.lastSuccess, now - lastSuccess < Self.maximumAge else { return nil }
        return health.latency
    }

    /// Another query may validate this same path while a cold request is in
    /// flight. Read that actual DNS success independently of a concurrent
    /// failure's cooldown; a prewarm/TLS success never creates this evidence.
    package func hasSuccessfulResponse(scopeKey: String, candidateID: String,
                                       since started: TimeInterval) -> Bool {
        guard started.isFinite, started >= 0 else { return false }
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), started <= now,
              let lastSuccess = scopes[scopeKey]?.health[candidateID]?.lastSuccess else { return false }
        return lastSuccess >= started && now - lastSuccess < Self.maximumAge
    }

    /// Local connection availability may break ties inside a health class,
    /// but cannot promote an unverified or cooling path over current success.
    /// Reading this hint neither creates a scope nor spends an exploration.
    package func schedulingPriority(scopeKey: String, candidateID: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard now.isFinite, let health = scopes[scopeKey]?.health[candidateID] else { return 1 }
        if health.cooldown > now { return 2 }
        return health.hasCurrentSuccess(now: now) ? 0 : 1
    }

    /// Deadline planning uses this candidate's successful observations, never
    /// another provider's cold cost or ranking penalties. Sharing a proxy route
    /// does not make different resolvers' TCP/TLS/response costs equivalent;
    /// an unmeasured candidate retains the bounded unknown-path allowance.
    package func estimatedMilliseconds(scopeKey: String, candidateID: String,
                               phase: DNSAdaptiveLatencyPhase) -> Double? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), let scope = scopes[scopeKey], scope.health[candidateID] != nil else { return nil }
        func estimate(_ health: Health) -> Double? {
            switch phase {
            case .cold: return health.fresh.estimate(now: now)
            case .transport: return health.transportSetup.estimate(now: now)
            case .tls: return health.tlsHandshake.estimate(now: now)
            case .response: return health.response.estimate(now: now)
            }
        }
        return estimate(scope.health[candidateID]!)
    }

    package func planningLatencyMilliseconds(scopeKey: String, candidateID: String) -> Double? {
        estimatedMilliseconds(scopeKey: scopeKey, candidateID: candidateID, phase: .cold)
            ?? knownLatencyMilliseconds(scopeKey: scopeKey, candidateID: candidateID)
    }

    /// Decayed RTT standard deviation (jitter in milliseconds) across recent
    /// valid observations for this candidate. Reading never mutates state.
    public func jitterMilliseconds(scopeKey: String, candidateID: String) -> Double? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), let health = scopes[scopeKey]?.health[candidateID],
              let lastSuccess = health.lastSuccess, now - lastSuccess < Self.maximumAge else { return nil }
        return health.fresh.jitter(now: now)
            ?? health.reused.jitter(now: now)
            ?? health.unknown.jitter(now: now)
    }

    /// Multi-Armed Bandit UCB1 + Cornish-Fisher 95th-percentile tail latency +
    /// Empirical Bayes Beta(8,2) reliability score (lower is better).
    public func ucb1ExplorationScore(scopeKey: String, candidateID: String,
                                     hasReusableConnection: Bool = false) -> Double? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), let state = scopes[scopeKey],
              var health = state.health[candidateID] else { return nil }
        health.decay(now: now)
        let baseScore = health.score(now: now)
        let jitter = health.fresh.jitter(now: now) ?? health.reused.jitter(now: now) ?? health.unknown.jitter(now: now) ?? 0
        let reuseFactor = hasReusableConnection ? 0.65 : 1.0
        let tailAdjusted = baseScore * reuseFactor + 1.6448536 * jitter * reuseFactor
        let totalQueries = max(1, state.queries)
        let sampleCount = max(1, health.successes + health.failures)
        let bonus = 18.0 * sqrt(log(Double(totalQueries + 1)) / Double(sampleCount)) * health.successProbability
        return max(1.0, tailAdjusted - bonus)
    }

    public func removeAll() {
        lock.lock(); scopes.removeAll(); bytes = 0; lastClock = nil; lock.unlock()
    }
    public var usage: (scopes: Int, bytes: Int) {
        lock.lock(); defer { lock.unlock() }; return (scopes.count, bytes)
    }
    private func remove(_ key: String) { if let value = scopes.removeValue(forKey: key) { bytes -= value.cost } }
    private func checkClock(_ now: TimeInterval) -> Bool {
        guard now.isFinite else { scopes.removeAll(); bytes = 0; lastClock = nil; return false }
        if let previous = lastClock, now < previous {
            scopes.removeAll(); bytes = 0; lastClock = now; return false
        }
        lastClock = now; return true
    }
}

/// A soft launch delay only. It neither declares a provider failed nor changes
/// the overall query deadline or the caller's approved/live-attempt bounds.
package enum DNSAdaptiveHedgeBudget {
    package static func delay(remaining: TimeInterval, attemptsLeft: Int,
                      primaryMilliseconds: Double?, alternateMilliseconds: Double?) -> TimeInterval {
        guard remaining.isFinite, remaining > 0 else { return 0 }
        func seconds(_ milliseconds: Double?) -> TimeInterval? {
            guard let milliseconds, milliseconds.isFinite, milliseconds >= 0 else { return nil }
            return milliseconds / 1000
        }
        // A blackholed first IP should not consume 8/3 seconds before an
        // approved alternate is even allowed to start. A measured healthy
        // primary gets RTT headroom rather than an unconditional fixed wait.
        let launchDelay = seconds(primaryMilliseconds).map { min(1.5, max(0.15, $0 * 1.5 + 0.05)) } ?? 0.75
        var budget = min(remaining, max(0.001, min(launchDelay, remaining / Double(max(1, attemptsLeft)))))
        if let alternate = seconds(alternateMilliseconds) {
            // Leave a known-slow alternate enough of this same total deadline.
            budget = min(budget, max(0.001, remaining - alternate * 1.25))
        }
        return budget
    }

    /// Jitter-aware Happy Eyeballs v2/v3 soft hedge delay incorporating
    /// Cornish-Fisher 95th-percentile RTT variance headroom (mu + 1.65 * sigma).
    package static func delayWithJitter(remaining: TimeInterval, attemptsLeft: Int,
                                        primaryMilliseconds: Double?, primaryJitterMilliseconds: Double?,
                                        alternateMilliseconds: Double?) -> TimeInterval {
        let jitterAdjustedPrimary: Double? = primaryMilliseconds.map { base in
            guard base.isFinite, base >= 0 else { return base }
            let sigma = (primaryJitterMilliseconds?.isFinite == true && (primaryJitterMilliseconds ?? 0) > 0)
                ? min(500, primaryJitterMilliseconds!) : 0
            return base + 1.1 * sigma
        }
        return delay(remaining: remaining, attemptsLeft: attemptsLeft,
                     primaryMilliseconds: jitterAdjustedPrimary, alternateMilliseconds: alternateMilliseconds)
    }
}

/// Pure health-state checks, no DNS exchange, listener or system changes.
public enum DNSAdaptiveUpstreamSelectorSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS 自适应选择自检失败：\(text)" }
    }
    private final class Clock {
        var value: TimeInterval = 100
        func now() -> TimeInterval { value }
    }
    private static func require(_ condition: Bool, _ text: String) throws {
        if !condition { throw Failure(text: text) }
    }
    public static func run() throws {
        let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 1, probeEvery: 2)
        let ids = ["first", "second"]
        try require(selector.knownLatencyMilliseconds(scopeKey: "route-A", candidateID: "first") == nil,
                    "读取未知 RTT 创建了健康记录")
        try require(selector.orderedCandidates(scopeKey: "route-A", candidateIDs: ids) == ids,
                    "冷启动没有保持配置顺序")
        selector.record(scopeKey: "route-A", candidateID: "first", milliseconds: 400, success: true)
        selector.record(scopeKey: "route-A", candidateID: "second", milliseconds: 40, success: true)
        try require(selector.knownLatencyMilliseconds(scopeKey: "route-A", candidateID: "second") == 40
                    && selector.knownLatencyMilliseconds(scopeKey: "route-B", candidateID: "second") == nil,
                    "成功 RTT 读取丢失或跨 scope 共享")
        try require(selector.orderedCandidates(scopeKey: "route-A", candidateIDs: ids).first == "second",
                    "成功耗时没有参与择优")
        selector.record(scopeKey: "route-A", candidateID: "second", milliseconds: 20, success: false)
        try require(selector.orderedCandidates(scopeKey: "route-A", candidateIDs: ids).first == "first",
                    "失败冷却没有避开故障端点")
        clock.value += 2
        try require(selector.orderedCandidates(scopeKey: "route-A", candidateIDs: ids).first == "second",
                    "恢复探测没有限定替换一条 primary")
        selector.record(scopeKey: "route-A", candidateID: "second", milliseconds: 10, success: true)
        try require(selector.orderedCandidates(scopeKey: "route-B", candidateIDs: ids) == ids,
                    "健康数据跨策略作用域共享")
        selector.record(scopeKey: "route-B", candidateID: "first", milliseconds: .nan, success: false)
        try require(selector.orderedCandidates(scopeKey: "route-B", candidateIDs: ids) == ids,
                    "异常计时污染健康状态")
        let bounded = DNSAdaptiveUpstreamSelector(clock: clock.now, maximumScopes: 2, maximumBytes: 8192)
        for scope in ["A", "B", "C"] { _ = bounded.orderedCandidates(scopeKey: scope, candidateIDs: ids) }
        try require(bounded.usage.scopes == 2 && bounded.usage.bytes <= 8192, "健康缓存超出资源边界")
        clock.value = 0
        try require(selector.orderedCandidates(scopeKey: "route-A", candidateIDs: ids) == ids
                    && selector.usage.scopes == 0, "时钟倒退仍沿用旧健康状态")
        selector.removeAll()
        try require(selector.knownLatencyMilliseconds(scopeKey: "route-A", candidateID: "second") == nil,
                    "flush 后 RTT 读取复活旧健康记录")
        selector.record(scopeKey: "route-A", candidateID: "second", milliseconds: 1, success: true)
        try require(selector.usage.scopes == 0, "迟到结果复活已清空的选择状态")
        try pendingLowerBoundHints()
        try hedgeBudgetBounds()
        try reliabilityAndTailLatency()
        try transportEvidenceAndStaleness()
        try coldPreferenceNeutrality()
        try stablePreferenceAndExploration()
        try observationReceipts()
        try observationInvalidation()
        try boundedHealthStorage()
        try concurrentObservationReceipts()
        try ucb1AndJitterDiagnostics()
    }

    private static func ucb1AndJitterDiagnostics() throws {
        let clock = Clock(), ids = ["steady", "spiky"]
        let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        _ = selector.orderedCandidates(scopeKey: "ucb-scope", candidateIDs: ids)
        for sample in [40.0, 42.0, 38.0, 40.0] {
            try observe(selector, "steady", milliseconds: sample, scope: "ucb-scope")
        }
        for sample in [20.0, 260.0, 25.0, 300.0] {
            try observe(selector, "spiky", milliseconds: sample, scope: "ucb-scope")
        }
        guard let steadyJitter = selector.jitterMilliseconds(scopeKey: "ucb-scope", candidateID: "steady"),
              let spikyJitter = selector.jitterMilliseconds(scopeKey: "ucb-scope", candidateID: "spiky"),
              let coldUCB = selector.ucb1ExplorationScore(scopeKey: "ucb-scope", candidateID: "steady", hasReusableConnection: false),
              let hotUCB = selector.ucb1ExplorationScore(scopeKey: "ucb-scope", candidateID: "steady", hasReusableConnection: true) else {
            throw Failure(text: "UCB1 评分或 RTT 抖动标准差读取失败")
        }
        try require(steadyJitter < 5 && spikyJitter > 80 && hotUCB < coldUCB,
                    "Welford-West 抖动估算或连接复用 UCB1 折扣异常")
        let baseDelay = DNSAdaptiveHedgeBudget.delay(remaining: 4.0, attemptsLeft: 2, primaryMilliseconds: 100, alternateMilliseconds: nil)
        let jitterDelay = DNSAdaptiveHedgeBudget.delayWithJitter(remaining: 4.0, attemptsLeft: 2,
            primaryMilliseconds: 100, primaryJitterMilliseconds: 50, alternateMilliseconds: nil)
        try require(jitterDelay > baseDelay && jitterDelay <= 1.5,
                    "抖动感知的 Happy Eyeballs 并发对冲预算未留出方差裕量")
    }

    private static func pendingLowerBoundHints() throws {
        let clock = Clock(), ids = ["pending", "winner"]
        let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 0.001, probeEvery: 2)
        try require(selector.orderedCandidates(scopeKey: "hints-A", candidateIDs: ids) == ids,
                    "hint 作用域初始顺序无效")
        selector.record(scopeKey: "hints-A", candidateID: "winner", milliseconds: 550, success: true)
        selector.recordPendingLatencyLowerBound(scopeKey: "hints-A", candidateID: "pending", milliseconds: 1200)
        selector.recordPendingLatencyLowerBound(scopeKey: "hints-A", candidateID: "pending", milliseconds: .nan)
        try require(selector.orderedCandidates(scopeKey: "hints-A", candidateIDs: ids).first == "winner"
                    && selector.knownLatencyMilliseconds(scopeKey: "hints-A", candidateID: "pending") == nil
                    && selector.orderedCandidates(scopeKey: "hints-B", candidateIDs: ids) == ids,
                    "pending 下界未避开慢 loser、被伪造为成功 RTT 或跨 scope 共享")
        clock.value += 0.01
        _ = selector.orderedCandidates(scopeKey: "hints-A", candidateIDs: ids)
        try require(selector.orderedCandidates(scopeKey: "hints-A", candidateIDs: ids).first == "pending"
                    && selector.orderedCandidates(scopeKey: "hints-A", candidateIDs: ids).first == "winner",
                    "下界 hint 阻止恢复 probe 或一次探测替换了稳定 primary")
        selector.recordPendingLatencyLowerBound(scopeKey: "hints-A", candidateID: "pending", milliseconds: 2000)
        selector.record(scopeKey: "hints-A", candidateID: "pending", milliseconds: 100, success: true)
        try require(selector.orderedCandidates(scopeKey: "hints-A", candidateIDs: ids).first == "pending",
                    "真实成功没有清除旧 pending 下界")
        let many = (0..<40).map { "variant-\($0)" }
        try require(selector.orderedCandidates(scopeKey: "hints-many", candidateIDs: many).count == 32,
                    "地址 variant 健康记录超过 32 个的有限上限")
        selector.removeAll()
        selector.recordPendingLatencyLowerBound(scopeKey: "hints-A", candidateID: "pending", milliseconds: 5000)
        try require(selector.usage.scopes == 0, "迟到 pending 下界复活已清空 scope")
    }

    private static func hedgeBudgetBounds() throws {
        let clock = Clock(), deadline = clock.now() + 8
        func budget(_ primary: Double? = nil, _ alternate: Double? = nil, attempts: Int = 3) -> TimeInterval {
            DNSAdaptiveHedgeBudget.delay(remaining: deadline - clock.now(), attemptsLeft: attempts,
                                        primaryMilliseconds: primary, alternateMilliseconds: alternate)
        }
        try require(budget() == 0.75 && budget(attempts: 2) == 0.75,
                    "冷 primary 仍等待固定 8/3 或 4 秒后才启动备用")
        try require(abs(budget(200) - 0.35) < 0.000001 && budget(0) == 0.15
                    && budget(20) == 0.15 && budget(1000) == 1.5 && budget(4500) == 1.5,
                    "健康 primary RTT 裕量或 150..1500ms 软预算边界无效")
        try require(abs(budget(nil, 6000) - 0.5) < 0.000001 && budget(nil, 6400) == 0.001,
                    "已知慢 alternate 没有保留 RTT×1.25 的剩余总预算")
        try require(budget(.nan) == 0.75 && budget(.infinity) == 0.75
                    && budget(-1) == 0.75 && budget(nil, .nan) == 0.75,
                    "无效健康时钟数据改变了有界 cold launch delay")
        clock.value = deadline - 0.3
        try require(abs(budget(1000) - 0.1) < 0.000001
                    && abs(budget(1000, nil, attempts: 2) - 0.15) < 0.000001,
                    "末期 soft hedge 没有服从剩余时间/剩余尝试的限额")
        clock.value = deadline - 0.0005
        let tiny = budget()
        try require(tiny > 0 && tiny <= deadline - clock.now(), "亚毫秒 soft timer 超过剩余总期限")
        clock.value = deadline
        try require(budget() == 0, "总期限已到仍授予正的候选启动预算")
        clock.value += 1
        try require(budget() == 0, "过期单调时钟允许候选复活")
    }

    private static func observe(_ selector: DNSAdaptiveUpstreamSelector, _ candidate: String,
                                milliseconds: Double, success: Bool = true,
                                transport: DNSQueryTransportEvidence = .fresh,
                                scope: String = "health") throws {
        let receipt = selector.beginObservation(scopeKey: scope, candidateID: candidate)
        try require(receipt != nil, "已准入候选未能创建观察票据")
        selector.record(receipt, milliseconds: milliseconds, success: success, transport: transport)
    }

    private static func reliabilityAndTailLatency() throws {
        let clock = Clock()
        let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        let ids = ["quick", "stable"]
        _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        for index in 0..<24 {
            try observe(selector, "quick", milliseconds: 20, success: index % 3 != 0)
            try observe(selector, "stable", milliseconds: 250)
        }
        try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "stable"
                    && selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "quick") == 20
                    && selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "stable") == 250,
                    "快速高失败端点压过可靠端点，或健康罚分污染成功 RTT")

        let tail = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        let tailIDs = ["spiky", "steady"]
        _ = tail.orderedCandidates(scopeKey: "health", candidateIDs: tailIDs)
        for sample in [2000.0, 10, 10, 10, 10, 10, 10, 10] {
            try observe(tail, "spiky", milliseconds: sample)
            try observe(tail, "steady", milliseconds: 400)
        }
        try require((tail.knownLatencyMilliseconds(scopeKey: "health", candidateID: "spiky") ?? 400) < 400
                    && tail.orderedCandidates(scopeKey: "health", candidateIDs: tailIDs).first == "steady",
                    "尾延迟没有补足仅使用平均 RTT 的错误择优")
        for _ in 0..<8 { try observe(tail, "spiky", milliseconds: 10) }
        try require(tail.orderedCandidates(scopeKey: "health", candidateIDs: tailIDs).first == "spiky",
                    "有限尾延迟样本退出后仍永久惩罚已恢复端点")

        let lowerBound = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        let boundIDs = ["pending", "measured"]
        _ = lowerBound.orderedCandidates(scopeKey: "health", candidateIDs: boundIDs)
        lowerBound.recordPendingLatencyLowerBound(scopeKey: "health", candidateID: "pending", milliseconds: 60_000)
        clock.value += 120
        lowerBound.recordPendingLatencyLowerBound(scopeKey: "health", candidateID: "pending", milliseconds: 100)
        // A pending bound is not a success, even when its decayed score is
        // smaller than this deliberately slow, successful measurement.
        try observe(lowerBound, "measured", milliseconds: 40_000)
        try require(lowerBound.orderedCandidates(scopeKey: "health", candidateIDs: boundIDs).first == "measured"
                    && lowerBound.knownLatencyMilliseconds(scopeKey: "health", candidateID: "pending") == nil,
                    "未成功的下界 hint 压过有效成功，或被当作成功 RTT")
    }

    private static func transportEvidenceAndStaleness() throws {
        let clock = Clock(), ids = ["coldSlow", "coldSteady"]
        let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        try observe(selector, "coldSlow", milliseconds: 1600)
        for _ in 0..<64 { try observe(selector, "coldSlow", milliseconds: 5, transport: .reused) }
        for _ in 0..<32 { try observe(selector, "coldSteady", milliseconds: 600) }
        try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "coldSteady"
                    && (selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "coldSlow") ?? 10) < 10,
                    "大量快速复用抹掉了独立冷启动成本，或成功 RTT 被冷成本替换")

        let hot = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        let hotIDs = ["onlyHot", "knownCold"]
        _ = hot.orderedCandidates(scopeKey: "health", candidateIDs: hotIDs)
        for _ in 0..<16 {
            try observe(hot, "onlyHot", milliseconds: 5, transport: .reused)
            try observe(hot, "knownCold", milliseconds: 200)
        }
        try require(hot.orderedCandidates(scopeKey: "health", candidateIDs: hotIDs).first == "knownCold",
                    "仅有热连接证据被当成已知冷连接耗时")
        try observe(hot, "onlyHot", milliseconds: 10, transport: .reusedThenFresh)
        try require(hot.orderedCandidates(scopeKey: "health", candidateIDs: hotIDs).first == "onlyHot",
                    "陈旧复用连接后重新拨号未更新冷连接样本")

        let aged = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        let agedIDs = ["old", "recent"]
        _ = aged.orderedCandidates(scopeKey: "health", candidateIDs: agedIDs)
        for _ in 0..<24 {
            try observe(aged, "old", milliseconds: 20)
            try observe(aged, "recent", milliseconds: 400)
        }
        try require(aged.orderedCandidates(scopeKey: "health", candidateIDs: agedIDs).first == "old",
                    "时效测试未能建立原有偏好")
        clock.value += 901
        try observe(aged, "recent", milliseconds: 400)
        try require(aged.knownLatencyMilliseconds(scopeKey: "health", candidateID: "old") == nil
                    && aged.orderedCandidates(scopeKey: "health", candidateIDs: agedIDs).first == "recent",
                    "过期成功 RTT 或旧健康权重压过近期有效证据")
    }

    private static func coldPreferenceNeutrality() throws {
        let clock = Clock(), ids = ["first", "second", "third"]
        let permutations = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]
        for issueReceipts in [false, true] {
            let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
            _ = selector.orderedCandidates(scopeKey: "cold", candidateIDs: ids)
            if issueReceipts {
                for id in ids {
                    try require(selector.beginObservation(scopeKey: "cold", candidateID: id) != nil,
                                "冷候选无法领取观察票据")
                }
            }
            for permutation in permutations {
                let configured = permutation.map { ids[$0] }
                try require(selector.orderedCandidates(scopeKey: "cold", candidateIDs: configured) == configured,
                            "无健康证据的冷候选或仅领取票据仍锁定旧偏好")
            }
            try require(ids.allSatisfy { selector.knownLatencyMilliseconds(scopeKey: "cold", candidateID: $0) == nil },
                        "冷偏好或仅领取票据制造了成功 RTT")
        }
    }

    private static func stablePreferenceAndExploration() throws {
        let clock = Clock(), ids = ["incumbent", "challenger"]
        let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        for _ in 0..<32 {
            try observe(selector, "incumbent", milliseconds: 300)
            try observe(selector, "challenger", milliseconds: 290)
        }
        try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "incumbent"
                    && selector.orderedCandidates(scopeKey: "health", candidateIDs: ids.reversed()).first == "incumbent",
                    "很小的得分差造成 primary 抖动")
        for _ in 0..<8 { try observe(selector, "challenger", milliseconds: 80) }
        try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "challenger",
                    "明显改善无法替换稳定 primary")
        try observe(selector, "challenger", milliseconds: 100, success: false)
        try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "incumbent",
                    "稳定偏好阻止绕过实际故障端点")

        let probe = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 1, probeEvery: 2)
        _ = probe.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        for _ in 0..<16 {
            try observe(probe, "incumbent", milliseconds: 1000)
            try observe(probe, "challenger", milliseconds: 20)
        }
        try require(probe.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "challenger",
                    "探测测试未能建立稳定 primary")
        for _ in 0..<63 { _ = probe.beginObservation(scopeKey: "health", candidateID: "incumbent") }
        clock.value += 1
        let third = probe.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        let fourth = probe.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        let fifth = probe.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        let sixth = probe.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        try require(third.first == "challenger" && fourth.first == "incumbent"
                    && fifth.first == "challenger" && sixth.first == "challenger"
                    && [third, fourth, fifth, sixth].allSatisfy({ Set($0) == Set(ids) && $0.count == ids.count }),
                    "票据创建消耗前台查询计数、探测突破间隔或添加了未批准候选")
    }

    private static func observationReceipts() throws {
        let clock = Clock(), ids = ["primary", "pending"]
        let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600, probeEvery: 1024)
        try require(selector.beginObservation(scopeKey: "health", candidateID: "primary") == nil
                    && selector.usage.scopes == 0, "票据创建复活未知 scope")
        _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        let success = selector.beginObservation(scopeKey: "health", candidateID: "primary")
        selector.record(success, milliseconds: 20, success: true, transport: .fresh)
        selector.record(success, milliseconds: 100, success: false, transport: .fresh)
        let pending = selector.beginObservation(scopeKey: "health", candidateID: "pending")
        selector.recordPendingLatencyLowerBound(pending, milliseconds: 3000)
        selector.record(pending, milliseconds: 1, success: true, transport: .fresh)
        let queued = selector.beginObservation(scopeKey: "health", candidateID: "primary")
        selector.record(queued, milliseconds: 8000, success: false, transport: .notStarted)
        selector.record(queued, milliseconds: 1, success: true, transport: .fresh)
        try require(selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "primary") == 20
                    && selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "pending") == nil
                    && selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "primary",
                    "重复、迟到或未启动传输的终态污染健康或重复消费票据")

        let foreign = DNSAdaptiveUpstreamSelector(clock: clock.now)
        _ = foreign.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        let owned = selector.beginObservation(scopeKey: "health", candidateID: "primary")
        foreign.record(owned, milliseconds: 1000, success: true, transport: .fresh)
        selector.record(owned, milliseconds: 44, success: true, transport: .fresh)
        let invalid = selector.beginObservation(scopeKey: "health", candidateID: "primary")
        selector.record(invalid, milliseconds: .nan, success: false, transport: .fresh)
        selector.record(invalid, milliseconds: 66, success: true, transport: .fresh)
        try require(foreign.knownLatencyMilliseconds(scopeKey: "health", candidateID: "primary") == nil
                    && selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "primary") == 36,
                    "外部 selector 消费了原票据，或无效样本提前消费有效票据")
    }

    private static func observationInvalidation() throws {
        let ids = ["primary", "other"]
        func check(_ name: String, invalidate: (DNSAdaptiveUpstreamSelector, Clock) -> Void) throws {
            let clock = Clock()
            let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, maximumScopes: 1)
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            let old = selector.beginObservation(scopeKey: "health", candidateID: "primary")
            invalidate(selector, clock)
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            selector.record(old, milliseconds: 1, success: true, transport: .fresh)
            try require(selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "primary") == nil,
                        "\(name) 后旧票据污染了同名新 scope")
            try observe(selector, "primary", milliseconds: 100)
            try require(selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "primary") == 100,
                        "\(name) 后有效新票据无法记录")
        }
        try check("flush") { selector, _ in selector.removeAll() }
        try check("eviction") { selector, _ in
            _ = selector.orderedCandidates(scopeKey: "replacement", candidateIDs: ids)
        }
        try check("候选集合替换") { selector, _ in
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids + ["new"])
        }
        try check("时钟倒退") { selector, clock in
            clock.value -= 1
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        }
        try check("非有限时钟") { selector, clock in
            clock.value = .nan
            _ = selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "primary")
            clock.value = 101
        }
    }

    private static func boundedHealthStorage() throws {
        let selector = DNSAdaptiveUpstreamSelector(clock: { 100 }, maximumScopes: 1000,
                                                   maximumBytes: 8 * 1024 * 1024)
        let ids = (0..<40).map { "provider-\($0)" }
        for index in 0..<160 {
            let ordered = selector.orderedCandidates(scopeKey: "scope-\(index)", candidateIDs: ids)
            try require(ordered == Array(ids.prefix(32)), "候选数量硬边界改变了获准候选顺序")
        }
        try require(selector.usage.scopes == 128 && selector.usage.bytes <= 8 * 1024 * 1024,
                    "健康 scope 或完整样本容量超过硬边界")

        let one = DNSAdaptiveUpstreamSelector(clock: { 100 })
        let pair = ["a", "b"]
        _ = one.orderedCandidates(scopeKey: "A", candidateIDs: pair)
        let scopeBytes = one.usage.bytes
        try require(scopeBytes > 0, "单 scope 字节预算为空")
        let bounded = DNSAdaptiveUpstreamSelector(clock: { 100 }, maximumBytes: scopeBytes * 2)
        for key in ["A", "B", "C"] { _ = bounded.orderedCandidates(scopeKey: key, candidateIDs: pair) }
        try require(bounded.usage.scopes == 2 && bounded.usage.bytes == scopeBytes * 2
                    && bounded.beginObservation(scopeKey: "A", candidateID: "a") == nil,
                    "完整样本容量未按字节准入或最近未用 scope 未淘汰")
        let tooSmall = DNSAdaptiveUpstreamSelector(clock: { 100 }, maximumBytes: scopeBytes - 1)
        try require(tooSmall.orderedCandidates(scopeKey: "A", candidateIDs: pair) == pair
                    && tooSmall.usage.scopes == 0 && tooSmall.usage.bytes == 0,
                    "字节预算不足时仍分配健康状态或阻止原有候选")
    }

    private static func concurrentObservationReceipts() throws {
        let selector = DNSAdaptiveUpstreamSelector(clock: { 100 }, probeInterval: 3600, probeEvery: 1024)
        let ids = ["shared", "other"]
        _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
        let bytes = selector.usage.bytes
        let shared = selector.beginObservation(scopeKey: "health", candidateID: "shared")
        DispatchQueue.concurrentPerform(iterations: 256) { _ in
            selector.record(shared, milliseconds: 80, success: true, transport: .fresh)
            let next = selector.beginObservation(scopeKey: "health", candidateID: "other")
            selector.record(next, milliseconds: 5000, success: true, transport: .reused)
        }
        selector.record(shared, milliseconds: 8000, success: false, transport: .fresh)
        try require(selector.usage.scopes == 1 && selector.usage.bytes == bytes
                    && selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "shared") == 80
                    && selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "other") == 5000
                    && selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "shared",
                    "并发重复票据、迟到终态或样本增长突破有界健康状态")
    }
}

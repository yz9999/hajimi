import Foundation
import Network
#if canImport(HajimiProtocolCXX)
import HajimiProtocolCXX
#endif

// MARK: - Group options

/// Health-check settings for one `url-test` or `fallback` group.
public struct PolicyHealthOptions: Equatable {
    /// Plain HTTP on purpose: a 204 endpoint over TCP measures the proxy path
    /// without adding a TLS handshake whose cost varies by cipher and by
    /// whether the outbound already terminates TLS itself.
    public static let defaultTestURL = "http://www.gstatic.com/generate_204"

    public var testURL: String
    public var host: String
    public var port: UInt16
    public var path: String
    public var interval: TimeInterval
    public var timeout: TimeInterval
    /// Hysteresis. A challenger must beat the member in use by more than this
    /// before traffic moves, otherwise two nodes with near-identical latency
    /// would swap on every round and reset every connection each time.
    public var tolerance: TimeInterval

    public init?(parameters: [String: String]) {
        let raw = parameters["url"] ?? parameters["test-url"]
            ?? parameters["internet-test-url"] ?? Self.defaultTestURL
        guard let parsed = Self.parse(raw) else { return nil }
        testURL = raw
        host = parsed.host
        port = parsed.port
        path = parsed.path
        interval = Self.seconds(parameters["interval"], default: 600)
        timeout = Self.seconds(parameters["timeout"], default: 5)
        // Surge and Clash both express tolerance in milliseconds.
        tolerance = (Double(parameters["tolerance"] ?? "") ?? 150) / 1000
    }

    private static func seconds(_ raw: String?, default fallback: TimeInterval) -> TimeInterval {
        guard let raw, let value = Double(raw), value.isFinite, value > 0 else { return fallback }
        return value
    }

    static func parse(_ raw: String) -> (host: String, port: UInt16, path: String)? {
        guard let components = URLComponents(string: raw), let host = components.host,
              !host.isEmpty else { return nil }
        let scheme = (components.scheme ?? "http").lowercased()
        guard scheme == "http" || scheme == "https" else { return nil }
        // URLComponents does not range-check the port, so an out-of-range
        // value from a subscription-supplied URL would trap the initialiser.
        let rawPort = components.port ?? (scheme == "https" ? 443 : 80)
        guard rawPort > 0, rawPort <= Int(UInt16.max) else { return nil }
        let port = UInt16(rawPort)
        let path = components.path.isEmpty ? "/" : components.path
        return (host, port, path)
    }
}

// MARK: - Selection policy

/// Turns probe results into a member choice.
///
/// Kept pure and separate from the probing so the behaviour that decides where
/// traffic goes can be exercised directly, including the cases that only show
/// up when nodes fail.
public enum PolicySelectionPolicy {
    /// `url-test`: the lowest latency wins, subject to hysteresis.
    ///
    /// Returns nil when nothing is healthy, which leaves the previous selection
    /// in place rather than blackholing traffic on a member already known to be
    /// down.
    public static func urlTest(members: [String], latencies: [String: TimeInterval],
                               current: String?, tolerance: TimeInterval) -> String? {
        let healthy = members.compactMap { member -> (String, TimeInterval)? in
            guard let latency = latencies[member] else { return nil }
            return (member, latency)
        }
        guard let best = healthy.min(by: { $0.1 < $1.1 }) else { return nil }
        guard let current, members.contains(current),
              let currentLatency = latencies[current] else { return best.0 }
        // Only move when the challenger is meaningfully faster.
        return best.1 + tolerance < currentLatency ? best.0 : current
    }

    /// `fallback`: the first healthy member in declared order.
    ///
    /// Order is the user's stated preference, so a recovered higher-priority
    /// member takes traffic back rather than sticking to whatever answered last.
    public static func fallback(members: [String],
                                latencies: [String: TimeInterval]) -> String? {
        members.first { latencies[$0] != nil }
    }

    /// Traffic context for Contextual Thompson Sampling (Russo & Van Roy, Stanford).
    public enum TrafficContext: String, Equatable {
        case interactiveLatency = "interactive"
        case bulkThroughput = "bulk"
    }

    /// Discounted Normal-Gamma / Beta-Binomial posterior state per node for
    /// passive in-band telemetry and Contextual Thompson Sampling.
    public struct ContextualPosterior: Equatable {
        public var alpha: Double = 8.0
        public var beta: Double = 2.0
        public var meanLatency: Double = 0.150
        public var varianceLatency: Double = 0.0025
        public var ewmaThroughputBps: Double = 5_000_000
        public var sampleCount: Int = 0
        public var lastObservedAt: TimeInterval = 0

        public init() {}

        public mutating func observe(success: Bool, latency: TimeInterval?,
                                     throughputBps: Double? = nil,
                                     now: TimeInterval, halfLife: TimeInterval = 180) {
            if lastObservedAt > 0, now > lastObservedAt {
                let gamma = pow(0.5, (now - lastObservedAt) / max(10, halfLife))
                alpha = 1.0 + (alpha - 1.0) * gamma
                beta = 1.0 + (beta - 1.0) * gamma
            }
            lastObservedAt = max(lastObservedAt, now)
            sampleCount += 1
            if success {
                alpha += 1.0
                if let rtt = latency, rtt.isFinite, rtt >= 0 {
                    let lr = min(max(rtt, 0.001), 15.0)
                    let weight = sampleCount == 1 ? 1.0 : 0.25
                    let delta = lr - meanLatency
                    meanLatency += weight * delta
                    varianceLatency = max(1e-6, (1.0 - weight) * (varianceLatency + weight * delta * delta))
                }
                if let bps = throughputBps, bps.isFinite, bps > 0 {
                    ewmaThroughputBps = ewmaThroughputBps * 0.75 + bps * 0.25
                }
            } else {
                beta += 1.5
            }
        }

        /// Draws a deterministic/seeded Thompson Sample cost (lower is better) for the given traffic context.
        public func sampleCost(context: TrafficContext, unitNormalZ: Double) -> Double {
            let reliability = alpha / max(1.0, alpha + beta)
            let uncertaintyScale = 1.0 / sqrt(Double(max(1, sampleCount)))
            let stdDev = sqrt(max(1e-6, varianceLatency)) * (1.0 + 0.5 * uncertaintyScale)
            let sampledRTT = max(0.001, meanLatency + unitNormalZ * stdDev)
            let failurePenalty = (1.0 - reliability) * 4.0
            switch context {
            case .interactiveLatency:
                return sampledRTT + failurePenalty
            case .bulkThroughput:
                let mbps = max(0.5, ewmaThroughputBps / 1_000_000.0)
                let throughputCost = 1.5 / mbps
                return sampledRTT * 0.35 + throughputCost * 0.65 + failurePenalty
            }
        }
    }

    /// Selects a member using Discounted Contextual Thompson Sampling over in-band posteriors.
    public static func contextualThompsonSample(
        members: [String],
        posteriors: [String: ContextualPosterior],
        context: TrafficContext,
        seed: UInt64 = 0x517cc1b727220a95
    ) -> String? {
        guard !members.isEmpty else { return nil }
        var state = seed
        func nextGaussianZ() -> Double {
            state = state &* 6364136223846793005 &+ 1442695040888963407
            let u1 = max(1e-7, min(1.0 - 1e-7, Double((state >> 11) & 0x1fffff) / Double(0x200000)))
            state = state &* 6364136223846793005 &+ 1442695040888963407
            let u2 = Double((state >> 11) & 0x1fffff) / Double(0x200000)
            // Bounded Box-Muller clamped to [-2.0, 2.0] to prevent extreme outlier flips
            let z = sqrt(-2.0 * log(u1)) * cos(2.0 * .pi * u2)
            return max(-2.0, min(2.0, z))
        }
        var bestMember: String?
        var bestScore = Double.infinity
        for member in members {
            let posterior = posteriors[member] ?? ContextualPosterior()
            let z = nextGaussianZ()
            let score = posterior.sampleCost(context: context, unitNormalZ: z)
            if score < bestScore {
                bestScore = score
                bestMember = member
            }
        }
        return bestMember
    }

    /// `smart`: Risk-adjusted multi-factor selection using Welford-West online
    /// variance (EWMVar), Cornish-Fisher 90th-percentile tail latency (mu + 1.28155*sigma),
    /// Empirical Bayes Beta-Binomial posterior reliability, and Mathis TCP loss penalty.
    public static func smart(members: [String], latencies: [String: TimeInterval],
                             costs: [String: TimeInterval],
                             current: String?, tolerance: TimeInterval) -> String? {
        let scored = members.compactMap { member -> (String, TimeInterval)? in
            guard let latency = latencies[member] else { return nil }
            let effectiveCost = costs[member] ?? latency
            return (member, effectiveCost)
        }
        guard let best = scored.min(by: { $0.1 < $1.1 }) else { return nil }
        guard let current, members.contains(current),
              let currentLatency = latencies[current] else { return best.0 }
        let currentCost = costs[current] ?? currentLatency
        return best.1 + tolerance < currentCost ? best.0 : current
    }

    static func select(group: PolicyGroup, latencies: [String: TimeInterval],
                       costs: [String: TimeInterval] = [:],
                       current: String?, tolerance: TimeInterval,
                       deferredMembers: Set<String> = []) -> String? {
        guard deferredMembers.isEmpty else { return current }
        switch group.kind {
        case .urlTest:
            return urlTest(members: group.members, latencies: latencies,
                           current: current, tolerance: tolerance)
        case .smart:
            return smart(members: group.members, latencies: latencies, costs: costs,
                         current: current, tolerance: tolerance)
        case .fallback:
            return fallback(members: group.members, latencies: latencies)
        case .select, .loadBalance, .subnet:
            return nil
        }
    }
}

// MARK: - Probe

public enum PolicyProbe {
    public enum Outcome: Equatable {
        /// nil means actual admitted network work failed.
        case measured(TimeInterval?)
        /// Resource/queue failures are not evidence that a node is unhealthy.
        case deferred(ProbeScheduler.Failure)
    }

    typealias Connector = (ResolvedRoute, RequestTarget, Bool, DispatchQueue,
                          @escaping (Result<(any NativeOutboundByteStream, Data), Error>) -> Void) -> Void

    static let routedConnector: Connector = { route, target, plainHTTP, lane, callback in
        TunnelConnector.connect(route: route, target: target, plainHTTP: plainHTTP,
                                queue: lane, completion: callback)
    }

    /// Dials `route` and times a plain HTTP request through it.
    ///
    /// The measurement is time-to-first-response-byte, which includes the
    /// outbound handshake — that is the delay a user actually pays on a new
    /// connection, so it is the right thing to rank members by.
    @discardableResult
    public static func measure(route: ResolvedRoute, options: PolicyHealthOptions,
                               queue: DispatchQueue, scheduler: ProbeScheduler = .shared,
                               completion: @escaping (TimeInterval?) -> Void) -> ProbeScheduler.Ticket {
        measureResult(route: route, options: options, queue: queue, scheduler: scheduler) { outcome in
            if case .measured(let latency) = outcome { completion(latency) }
            else { completion(nil) }
        }
    }

    @discardableResult
    public static func measureResult(route: ResolvedRoute, options: PolicyHealthOptions,
                                     queue: DispatchQueue, scheduler: ProbeScheduler = .shared,
                                     completion: @escaping (Outcome) -> Void) -> ProbeScheduler.Ticket {
        measureResult(route: route, options: options, queue: queue, scheduler: scheduler,
                      connector: routedConnector, completion: completion)
    }

    /// Injection exists only to exercise cancellation and late-stream races
    /// with in-memory streams; production always uses the real routed dialer.
    static func measureResult(route: ResolvedRoute, options: PolicyHealthOptions,
                              queue: DispatchQueue, scheduler: ProbeScheduler,
                              connector: @escaping Connector,
                              completion: @escaping (Outcome) -> Void) -> ProbeScheduler.Ticket {
        let resources = ProbeStreamLifetime()
        return scheduler.submit(timeout: options.timeout, callbackQueue: queue, start: { lease in
            guard lease.setCancellationHandler({ _ = resources.finish() }) else { return }
            if case .reject = route {
                _ = resources.finish()
                if lease.complete() { queue.async { completion(.measured(nil)) } }
                return
            }
            // This reservation outlives a logical timeout while connect has no
            // cancellation handle. Only its eventual callback returns the slot.
            guard let reservation = scheduler.reservePendingConnection() else {
                _ = resources.finish()
                if lease.complete() { queue.async { completion(.deferred(.connectionBudgetExceeded)) } }
                return
            }
            guard lease.isActive, resources.begin() else { reservation.release(); return }
            let target = RequestTarget(host: options.host, port: options.port, protocolName: "TCP")
            let finish: (TimeInterval?) -> Void = { latency in
                let result = resources.finish()
                guard result.won, lease.complete() else { return }
                if let started = result.started {
                    NetworkPerformanceDiagnostics.shared.record(.probeFirstByte,
                        milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started),
                        success: latency != nil)
                }
                queue.async { completion(.measured(latency)) }
            }
            let finishDeferred: () -> Void = {
                let result = resources.finish()
                guard result.won, lease.complete() else { return }
                queue.async { completion(.deferred(.connectionBudgetExceeded)) }
            }
            connector(route, target, false, lease.queue) { result in
                switch result {
                case .failure(let error):
                    reservation.release()
                    if isAdmissionFailure(error) { finishDeferred() }
                    else { finish(nil) }
                case .success(let (stream, initial)):
                    guard resources.install(stream) else {
                        // Installation and finish share one lock. No exchange
                        // can flip an ended request back to an unfinished state.
                        reservation.release()
                        return
                    }
                    reservation.release()
                    guard lease.isActive else { _ = resources.finish(); return }
                    let request = "GET \(options.path) HTTP/1.1\r\nHost: \(options.host)\r\n"
                        + "User-Agent: Hajimi\r\nConnection: close\r\n\r\n"
                    stream.send(Data(request.utf8)) { error in
                        if let error {
                            if isAdmissionFailure(error) { finishDeferred() }
                            else { finish(nil) }
                            return
                        }
                        guard let started = resources.startedAt else { finish(nil); return }
                        readStatusLine(stream: stream, buffered: initial, started: started,
                                       isActive: { !resources.isFinished && lease.isActive }, completion: finish)
                    }
                }
            }
        }, failure: { failure in
            let result = resources.finish()
            if failure == .requestExpired, let started = result.started {
                NetworkPerformanceDiagnostics.shared.record(.probeFirstByte,
                    milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started), success: false)
                completion(.measured(nil))
            } else { completion(.deferred(failure)) }
        })
    }

    private static func isAdmissionFailure(_ error: Error) -> Bool {
        let value = error as NSError
        return value.domain == NodeConnectionAdmissionError.errorDomain
            && value.code == NodeConnectionAdmissionError.capacityExceeded.errorCode
    }

    /// Reads until an HTTP status line is available. Anything that is not an
    /// HTTP response means the path is broken even though the socket opened,
    /// which is exactly the failure a TCP-only latency test misses.
    private static func readStatusLine(stream: any NativeOutboundByteStream, buffered: Data,
                                       started: UInt64, attempt: Int = 0,
                                       accumulated: Data = Data(),
                                       isActive: @escaping () -> Bool,
                                       completion: @escaping (TimeInterval?) -> Void) {
        guard isActive() else { return }
        var buffer = accumulated
        buffer.append(buffered)
        if let range = buffer.range(of: Data("\r\n".utf8)) {
            let line = String(data: buffer[buffer.startIndex..<range.lowerBound],
                              encoding: .utf8) ?? ""
            guard line.hasPrefix("HTTP/1.") else { completion(nil); return }
            completion(NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started) / 1_000)
            return
        }
        guard buffer.count < 8 * 1024, attempt < 32 else { completion(nil); return }
        stream.receive(maximum: 4096) { data, isComplete, error in
            guard error == nil, let data, !data.isEmpty else {
                completion(nil); return
            }
            guard !isComplete || !data.isEmpty else { completion(nil); return }
            readStatusLine(stream: stream, buffered: data, started: started,
                           attempt: attempt + 1, accumulated: buffer, isActive: isActive,
                           completion: completion)
        }
    }
}

/// One lock owns both the ended flag and the stream slot. In particular, a
/// timeout between checking the flag and registering a stream cannot leak it.
private final class ProbeStreamLifetime {
    private let lock = NSLock()
    private var finished = false
    private var live: (any NativeOutboundByteStream)?
    private var started: UInt64?

    var isFinished: Bool { lock.lock(); defer { lock.unlock() }; return finished }
    var startedAt: UInt64? { lock.lock(); defer { lock.unlock() }; return started }

    func begin() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !finished else { return false }
        started = NetworkPerformanceDiagnostics.now()
        return true
    }

    func install(_ stream: any NativeOutboundByteStream) -> Bool {
        lock.lock()
        let accepted = !finished && live == nil
        if accepted { live = stream }
        lock.unlock()
        if !accepted { stream.cancel() }
        return accepted
    }

    func finish() -> (won: Bool, started: UInt64?) {
        lock.lock()
        let won = !finished
        finished = true
        let stream = live
        live = nil
        let started = started
        lock.unlock()
        stream?.cancel()
        return (won, started)
    }
}

// MARK: - Monitor

private struct PolicyHealthCallbacks {
    let selections: (([String: String]) -> Void)?
    let report: ((PolicyHealthMonitor.Report) -> Void)?
}

/// Drives `url-test` and `fallback` groups.
///
/// Results are published as ordinary group selections, which the routing path
/// already consults ahead of a group's declared order. That keeps the hot path
/// untouched: routing has no idea health checking exists.
public final class PolicyHealthMonitor {
    public struct Report: Equatable {
        public var group: String
        public var selected: String?
        public var latencies: [String: TimeInterval]
        public var checkedAt: Date
        public var deferredMembers: Set<String> = []
    }

    /// Fires with the full set of automatic selections whenever one changes.
    /// Legacy setters are serialized; an existing round retains its original
    /// callbacks. Use the atomic update overload when replacing configuration.
    public var onSelectionsChanged: (([String: String]) -> Void)? {
        get { onQueue { callbacks.selections } }
        set { onQueue { callbacks = PolicyHealthCallbacks(selections: newValue, report: callbacks.report) } }
    }
    /// Fires after every round so the UI can show per-member latency.
    public var onReport: ((Report) -> Void)? {
        get { onQueue { callbacks.report } }
        set { onQueue { callbacks = PolicyHealthCallbacks(selections: callbacks.selections, report: newValue) } }
    }

    private let queue = DispatchQueue(label: "app.hajimi.policy-health", qos: .utility)
    private let queueKey = DispatchSpecificKey<UInt8>()
    private var callbacks = PolicyHealthCallbacks(selections: nil, report: nil)
    private let scheduler: ProbeScheduler
    private let connector: PolicyProbe.Connector
    private var profile: Profile?
    private var timer: DispatchSourceTimer?
    private var selections: [String: String] = [:]
    private var lastChecked: [String: Date] = [:]
    private var epoch: UInt64 = 0
    private var rounds: [String: ProbeRound] = [:]
    private var tickets: [UUID: ProbeScheduler.Ticket] = [:]
    private var lastLatencies: [String: [String: TimeInterval]] = [:]
    private var contextualPosteriors: [String: [String: PolicySelectionPolicy.ContextualPosterior]] = [:]
    #if canImport(HajimiProtocolCXX)
    private var smartNodeStats: [String: [String: hajimi_smart_node_stats]] = [:]
    #endif
    private var retryAfter: [String: Date] = [:]
    private let submissionWindow = 32
    private var roundRobinCursor = 0

    public init(scheduler: ProbeScheduler = .shared) {
        self.scheduler = scheduler; connector = PolicyProbe.routedConnector
        queue.setSpecific(key: queueKey, value: 1)
    }

    init(scheduler: ProbeScheduler, connector: @escaping PolicyProbe.Connector) {
        self.scheduler = scheduler; self.connector = connector
        queue.setSpecific(key: queueKey, value: 1)
    }

    deinit { timer?.cancel(); tickets.values.forEach { $0.cancel() } }

    /// Groups whose member this monitor owns. Manual selection stays with the
    /// user for every other kind.
    public static func managesSelection(of group: PolicyGroup) -> Bool {
        group.kind == .urlTest || group.kind == .fallback || group.kind == .smart
    }

    /// Passive in-band telemetry: updates a member's contextual posterior directly
    /// from real connection TTFB and throughput without sending extra network probes.
    public func recordPassiveObservation(group: String, member: String,
                                         success: Bool, latency: TimeInterval?,
                                         throughputBps: Double? = nil,
                                         now: TimeInterval = Date().timeIntervalSince1970) {
        onQueue {
            var groupPosteriors = contextualPosteriors[group] ?? [:]
            var posterior = groupPosteriors[member] ?? PolicySelectionPolicy.ContextualPosterior()
            posterior.observe(success: success, latency: latency, throughputBps: throughputBps, now: now)
            groupPosteriors[member] = posterior
            contextualPosteriors[group] = groupPosteriors
        }
    }

    public func update(profile: Profile) {
        queue.async { self.updateLocked(profile: profile) }
    }

    /// Configuration and delivery callbacks become current in one queue turn.
    /// An old result cannot be relabelled with a newly installed UI epoch.
    public func update(profile: Profile,
                       onSelectionsChanged: (([String: String]) -> Void)?,
                       onReport: ((Report) -> Void)?) {
        let callbacks = PolicyHealthCallbacks(selections: onSelectionsChanged, report: onReport)
        queue.async {
            self.callbacks = callbacks
            self.updateLocked(profile: profile)
        }
    }

    private func onQueue<Value>(_ body: () -> Value) -> Value {
        if DispatchQueue.getSpecific(key: queueKey) == 1 { return body() }
        return queue.sync(execute: body)
    }

    private func updateLocked(profile: Profile) {
        invalidateRounds()
        self.profile = profile
        lastLatencies.removeAll()
        #if canImport(HajimiProtocolCXX)
        smartNodeStats.removeAll()
        #endif
        retryAfter.removeAll()
        let managed = Set(profile.groups.values
            .filter { Self.managesSelection(of: $0) }.map(\.name))
        // Drop state for groups that disappeared or changed kind.
        selections = selections.filter { managed.contains($0.key) }
        lastChecked = lastChecked.filter { managed.contains($0.key) }
        guard !managed.isEmpty else { stopLocked(); return }
        startLocked()
        runDueProbes(force: true)
    }

    public func stop() { queue.async { self.stopLocked() } }

    /// Immediately re-tests every managed group, ignoring its interval.
    public func refresh() { queue.async { self.runDueProbes(force: true) } }

    public var currentSelections: [String: String] { onQueue { selections } }

    private func startLocked() {
        guard timer == nil else { return }
        let source = DispatchSource.makeTimerSource(queue: queue)
        // One shared tick; each group decides whether its own interval elapsed.
        source.schedule(deadline: .now() + 5, repeating: 5, leeway: .seconds(1))
        source.setEventHandler { [weak self] in self?.runDueProbes(force: false) }
        timer = source
        source.resume()
    }

    private func stopLocked() {
        timer?.cancel(); timer = nil
        invalidateRounds()
    }

    private func invalidateRounds() {
        epoch &+= 1
        let old = Array(tickets.values)
        tickets.removeAll(); rounds.removeAll(); roundRobinCursor = 0
        old.forEach { $0.cancel() }
    }

    private func runDueProbes(force: Bool) {
        guard let profile else { return }
        let now = Date()
        for group in profile.groups.values where Self.managesSelection(of: group) {
            guard let options = PolicyHealthOptions(parameters: group.parameters) else { continue }
            guard rounds[group.name] == nil, !group.members.isEmpty else { continue }
            if !force {
                if let retry = retryAfter[group.name] {
                    guard now >= retry else { continue }
                } else if let last = lastChecked[group.name],
                          now.timeIntervalSince(last) < options.interval { continue }
            }
            rounds[group.name] = ProbeRound(group: group, options: options, profile: profile,
                                           selections: selections, epoch: epoch, callbacks: callbacks)
        }
        pumpProbes()
    }

    /// A sliding window, rather than one scheduler submission per subscription
    /// member, also bounds outstanding logical work for very large profiles.
    private func pumpProbes() {
        let ordered = rounds.values.sorted(by: { $0.group.name < $1.group.name })
        guard !ordered.isEmpty else { return }
        var skipped = 0
        while tickets.count < submissionWindow, skipped < ordered.count {
            let round = ordered[roundRobinCursor % ordered.count]
            roundRobinCursor = (roundRobinCursor + 1) % ordered.count
            guard round.nextMember < round.group.members.count else { skipped += 1; continue }
            skipped = 0
            let member = round.group.members[round.nextMember]
            round.nextMember += 1
            let target = RequestTarget(host: round.options.host, port: round.options.port, protocolName: "TCP")
            let route = round.profile.route(for: target, mode: .proxy, globalPolicy: member,
                                            groupSelections: round.selections)
            let requestID = UUID()
            let ticket = PolicyProbe.measureResult(route: route, options: round.options,
                                                   queue: queue, scheduler: scheduler,
                                                   connector: connector) { [weak self, weak round] outcome in
                guard let self, let round, self.epoch == round.epoch,
                      self.rounds[round.group.name] === round else { return }
                self.tickets.removeValue(forKey: requestID)
                if let complete = round.collected.record(member: member, outcome: outcome) {
                    self.finish(round: round, result: complete)
                }
                self.pumpProbes()
            }
            tickets[requestID] = ticket
        }
    }

    private func finish(round: ProbeRound, result: ProbeCollector.Result) {
        let group = round.group
        let options = round.options
        rounds.removeValue(forKey: group.name)
        lastChecked[group.name] = Date()
        let latencies = result.merging(previous: lastLatencies[group.name] ?? [:])
        lastLatencies[group.name] = latencies
        var smartCosts: [String: TimeInterval] = [:]
        #if canImport(HajimiProtocolCXX)
        let nowSec = Date().timeIntervalSinceReferenceDate
        var groupStats = smartNodeStats[group.name] ?? [:]
        for (member, rtt) in result.latencies {
            var st = groupStats[member] ?? {
                var s = hajimi_smart_node_stats()
                hajimi_smart_stats_init(&s)
                return s
            }()
            hajimi_smart_stats_observe(&st, 1, rtt, nowSec)
            groupStats[member] = st
        }
        for member in result.unreachable {
            var st = groupStats[member] ?? {
                var s = hajimi_smart_node_stats()
                hajimi_smart_stats_init(&s)
                return s
            }()
            hajimi_smart_stats_observe(&st, 0, 0.0, nowSec)
            groupStats[member] = st
        }
        for (member, st) in groupStats where latencies[member] != nil {
            smartCosts[member] = withUnsafePointer(to: st) {
                hajimi_smart_stats_cost($0, nowSec)
            }
        }
        smartNodeStats[group.name] = groupStats
        #endif
        if result.deferred.isEmpty { retryAfter.removeValue(forKey: group.name) }
        else { retryAfter[group.name] = Date().addingTimeInterval(max(5, min(30, options.interval))) }
        let previous = selections[group.name]
        // Not obtaining a slot is not a negative health observation. Preserve
        // previous healthy data and do not switch based on a partial round.
        let chosen = PolicySelectionPolicy.select(group: group, latencies: latencies,
            costs: smartCosts, current: previous, tolerance: options.tolerance, deferredMembers: result.deferred)
        if let chosen { selections[group.name] = chosen }
        let snapshot = selections
        round.callbacks.report?(Report(group: group.name, selected: chosen,
                         latencies: latencies, checkedAt: Date(), deferredMembers: result.deferred))
        if chosen != previous, chosen != nil {
            round.callbacks.selections?(snapshot)
        }
    }
}

private final class ProbeRound {
    let group: PolicyGroup
    let options: PolicyHealthOptions
    let profile: Profile
    let selections: [String: String]
    let epoch: UInt64
    let collected: ProbeCollector
    let callbacks: PolicyHealthCallbacks
    var nextMember = 0

    init(group: PolicyGroup, options: PolicyHealthOptions, profile: Profile,
         selections: [String: String], epoch: UInt64, callbacks: PolicyHealthCallbacks) {
        self.group = group; self.options = options; self.profile = profile
        self.selections = selections; self.epoch = epoch
        self.callbacks = callbacks
        collected = ProbeCollector(expected: group.members.count)
    }
}

/// Gathers one round of concurrent probes and reports once they have all
/// answered.
private final class ProbeCollector {
    struct Result {
        var latencies: [String: TimeInterval] = [:]
        var unreachable = Set<String>()
        var deferred = Set<String>()

        func merging(previous: [String: TimeInterval]) -> [String: TimeInterval] {
            var merged = previous
            for member in unreachable { merged.removeValue(forKey: member) }
            for (member, latency) in latencies { merged[member] = latency }
            return merged
        }
    }
    private let lock = NSLock()
    private let expected: Int
    private var result = Result()
    private var answered = 0

    init(expected: Int) { self.expected = expected }

    /// Returns the complete result set on the final answer, nil before that.
    func record(member: String, outcome: PolicyProbe.Outcome) -> Result? {
        lock.lock(); defer { lock.unlock() }
        guard answered < expected else { return nil }
        switch outcome {
        case .measured(let latency):
            if let latency { result.latencies[member] = latency }
            else { result.unreachable.insert(member) }
        case .deferred: result.deferred.insert(member)
        }
        answered += 1
        return answered == expected ? result : nil
    }
}

// MARK: - Self-test

public enum PolicyHealthSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "策略健康检查自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try runInMemory()
        try probeAgainstLoopback()
    }

    /// The performance regression target uses this entry point. It contains
    /// only pure policies, fake byte streams and bounded dispatch timers.
    public static func runInMemory() throws {
        try optionParsing()
        try urlTestSelection()
        try fallbackSelection()
        try deferredRound()
        try lateProbeCleanup()
        try monitorEpoch()
        try resourceAdmission()
        try callbackConfigurationBinding()
        try contextualThompsonSamplingSelfTest()
    }

    private static func contextualThompsonSamplingSelfTest() throws {
        var fastInteractive = PolicySelectionPolicy.ContextualPosterior()
        var highBandwidth = PolicySelectionPolicy.ContextualPosterior()
        for i in 1...12 {
            fastInteractive.observe(success: true, latency: 0.035, throughputBps: 2_000_000, now: Double(i))
            highBandwidth.observe(success: true, latency: 0.140, throughputBps: 85_000_000, now: Double(i))
        }
        let posteriors = ["LowRTT": fastInteractive, "HighBW": highBandwidth]
        let chosenInteractive = PolicySelectionPolicy.contextualThompsonSample(
            members: ["LowRTT", "HighBW"], posteriors: posteriors, context: .interactiveLatency, seed: 42
        )
        let chosenBulk = PolicySelectionPolicy.contextualThompsonSample(
            members: ["LowRTT", "HighBW"], posteriors: posteriors, context: .bulkThroughput, seed: 42
        )
        try expect(chosenInteractive == "LowRTT" && chosenBulk == "HighBW",
                   "上下文汤普森采样未按交互低延迟与大吞吐上下文区分最优节点")
    }

    private static func deferredRound() throws {
        let collected = ProbeCollector(expected: 3)
        try expect(collected.record(member: "A", outcome: .deferred(.queueWaitExpired)) == nil,
                   "部分轮次过早发布")
        try expect(collected.record(member: "B", outcome: .measured(0.05)) == nil,
                   "部分轮次过早发布")
        guard let round = collected.record(member: "C", outcome: .measured(nil)) else {
            throw Failure(text: "完整轮次未发布")
        }
        let latencies = round.merging(previous: ["A": 0.1, "C": 0.2])
        try expect(latencies == ["A": 0.1, "B": 0.05] && round.deferred == ["A"],
                   "排队失败被误判为不可达或真实失败未移除旧数据")
        let group = PolicyGroup(name: "test", kind: .urlTest, members: ["A", "B", "C"])
        try expect(PolicySelectionPolicy.select(group: group, latencies: latencies, current: "A",
            tolerance: 0, deferredMembers: round.deferred) == "A", "资源受限轮次触发了错误切换")
        try expect(PolicySelectionPolicy.select(group: group, latencies: latencies, current: nil,
            tolerance: 0, deferredMembers: round.deferred) == nil, "部分轮次捏造了初始健康选择")
        try expect(collected.record(member: "A", outcome: .measured(0.01)) == nil, "完整轮次重复发布")
    }

    private final class MemoryStream: NativeOutboundByteStream {
        let lock = NSLock()
        var cancels = 0
        var sends = 0
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); sends += 1; lock.unlock(); completion(nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            completion(Data("HTTP/1.1 204 No Content\r\n\r\n".utf8), true, nil)
        }
        func cancel() { lock.lock(); cancels += 1; lock.unlock() }
    }

    private final class MemoryProbe {
        let lock = NSLock()
        var callback: ((Swift.Result<(any NativeOutboundByteStream, Data), Error>) -> Void)?
        var outcomes: [PolicyProbe.Outcome] = []
        let started = DispatchSemaphore(value: 0)
        let completed = DispatchSemaphore(value: 0)
        func connect(_ callback: @escaping (Swift.Result<(any NativeOutboundByteStream, Data), Error>) -> Void) {
            lock.lock(); self.callback = callback; lock.unlock(); started.signal()
        }
        func finish(_ outcome: PolicyProbe.Outcome) {
            lock.lock(); outcomes.append(outcome); lock.unlock(); completed.signal()
        }
    }

    private static func lateProbeCleanup() throws {
        guard let options = PolicyHealthOptions(parameters: ["url": "http://memory.invalid/check", "timeout": "0.03"]) else {
            throw Failure(text: "内存测试参数无效")
        }
        let scheduler = ProbeScheduler(maximumActive: 1, maximumQueued: 1)
        let callbacks = DispatchQueue(label: "app.hajimi.policy-health.memory-tests")
        let memory = MemoryProbe()
        _ = PolicyProbe.measureResult(route: .direct("DIRECT"), options: options,
            queue: callbacks, scheduler: scheduler,
            connector: { _, _, _, _, callback in memory.connect(callback) }, completion: memory.finish)
        try expect(memory.started.wait(timeout: .now() + 2) == .success, "内存建连没有启动")
        try expect(memory.completed.wait(timeout: .now() + 2) == .success, "探测 deadline 未结束")
        try expect(scheduler.snapshot().active == 0 && scheduler.snapshot().pendingConnections == 1,
                   "逻辑超时提前释放了建立中的物理连接")
        memory.lock.lock(); let callback = memory.callback; memory.lock.unlock()
        guard let callback else { throw Failure(text: "内存建连回调缺失") }
        let late = MemoryStream()
        callback(.success((late, Data())))
        let duplicate = MemoryStream()
        callback(.success((duplicate, Data())))
        callbacks.sync {}
        late.lock.lock(); let lateCounts = (late.cancels, late.sends); late.lock.unlock()
        duplicate.lock.lock(); let duplicateCounts = (duplicate.cancels, duplicate.sends); duplicate.lock.unlock()
        memory.lock.lock(); let outcomes = memory.outcomes; memory.lock.unlock()
        try expect(lateCounts == (1, 0) && duplicateCounts == (1, 0) && outcomes == [.measured(nil)],
                   "迟到 stream 未关闭、请求复活或重复完成")
        try expect(scheduler.snapshot().pendingConnections == 0, "迟到回调遗留物理名额")

        // Registration racing an ended flag must close exactly one stream,
        // irrespective of which thread acquired the lifetime lock first.
        for _ in 0..<64 {
            let lifetime = ProbeStreamLifetime()
            let stream = MemoryStream()
            let done = DispatchGroup()
            done.enter(); DispatchQueue.global().async { _ = lifetime.install(stream); done.leave() }
            done.enter(); DispatchQueue.global().async { _ = lifetime.finish(); done.leave() }
            try expect(done.wait(timeout: .now() + 2) == .success, "stream 登记/结束竞态超时")
            _ = lifetime.finish()
            stream.lock.lock(); let cancels = stream.cancels; stream.lock.unlock()
            try expect(cancels == 1 && lifetime.isFinished, "登记/结束竞态漏关或重复关闭 stream")
        }
    }

    private final class MemoryMonitor {
        let lock = NSLock()
        var callbacks: [((Swift.Result<(any NativeOutboundByteStream, Data), Error>) -> Void)] = []
        var reports: [PolicyHealthMonitor.Report] = []
        let started = DispatchSemaphore(value: 0)
        let reported = DispatchSemaphore(value: 0)

        func connect(_ callback: @escaping (Swift.Result<(any NativeOutboundByteStream, Data), Error>) -> Void) {
            lock.lock(); callbacks.append(callback); lock.unlock(); started.signal()
        }
        func report(_ report: PolicyHealthMonitor.Report) {
            lock.lock(); reports.append(report); lock.unlock(); reported.signal()
        }
    }

    private static func monitorEpoch() throws {
        let scheduler = ProbeScheduler(maximumActive: 1, maximumQueued: 4)
        let memory = MemoryMonitor()
        let monitor = PolicyHealthMonitor(scheduler: scheduler,
            connector: { _, _, _, _, callback in memory.connect(callback) })
        monitor.onReport = memory.report
        var old = Profile()
        old.proxies["A"] = ProxyPolicy(name: "A", kind: .direct)
        old.proxies["B"] = ProxyPolicy(name: "B", kind: .direct)
        old.groups["automatic"] = PolicyGroup(name: "automatic", kind: .urlTest, members: ["A"],
            parameters: ["url": "http://memory.invalid/check", "timeout": "3"])
        old.groupOrder = ["automatic"]
        monitor.update(profile: old)
        try expect(memory.started.wait(timeout: .now() + 2) == .success, "旧配置健康探测未启动")
        var current = old
        current.groups["automatic"]?.members = ["B"]
        monitor.update(profile: current)
        try expect(memory.reported.wait(timeout: .now() + 2) == .success, "资源受限新轮次未报告")
        memory.lock.lock(); let oldCallback = memory.callbacks[0]; let deferred = memory.reports[0]; memory.lock.unlock()
        try expect(deferred.deferredMembers == ["B"] && deferred.latencies.isEmpty
                    && monitor.currentSelections["automatic"] == nil,
                    "配置更新后的资源限额被误判为健康状态")
        let late = MemoryStream()
        oldCallback(.success((late, Data())))
        late.lock.lock(); let closed = late.cancels; late.lock.unlock()
        try expect(closed == 1 && scheduler.snapshot().pendingConnections == 0,
                    "旧配置迟到 stream 没有关闭或保留了物理名额")
        monitor.refresh()
        try expect(memory.started.wait(timeout: .now() + 2) == .success, "物理名额回收后新探测未启动")
        memory.lock.lock(); let callback = memory.callbacks[1]; memory.lock.unlock()
        callback(.success((MemoryStream(), Data("HTTP/1.1 204 No Content\r\n".utf8))))
        try expect(memory.reported.wait(timeout: .now() + 2) == .success, "新配置探测未发布")
        let selections = monitor.currentSelections
        memory.lock.lock(); let reports = memory.reports; memory.lock.unlock()
        try expect(selections["automatic"] == "B" && reports.count == 2
                    && reports.allSatisfy { $0.latencies["A"] == nil }
                    && reports.last?.latencies["B"] != nil,
                    "旧配置回调污染了新配置结果或选择")
        monitor.stop()
        _ = monitor.currentSelections
    }

    private static func resourceAdmission() throws {
        guard let options = PolicyHealthOptions(parameters: ["url": "http://memory.invalid/check", "timeout": "3"]) else {
            throw Failure(text: "资源限额测试参数无效")
        }
        let scheduler = ProbeScheduler(maximumActive: 1)
        let callbacks = DispatchQueue(label: "app.hajimi.policy-health.admission-tests")
        let before = NetworkPerformanceDiagnostics.shared.snapshot().stages[.probeFirstByte]?.count
        let errors: [Error] = [NodeConnectionAdmissionError.capacityExceeded,
            NSError(domain: NodeConnectionAdmissionError.errorDomain,
                    code: NodeConnectionAdmissionError.capacityExceeded.errorCode)]
        for error in errors {
            let memory = MemoryProbe()
            _ = PolicyProbe.measureResult(route: .direct("DIRECT"), options: options,
                queue: callbacks, scheduler: scheduler,
                connector: { _, _, _, _, done in done(.failure(error)) }, completion: memory.finish)
            try expect(memory.completed.wait(timeout: .now() + 2) == .success, "资源限额未完成探测回调")
            memory.lock.lock(); let outcomes = memory.outcomes; memory.lock.unlock()
            try expect(outcomes == [.deferred(.connectionBudgetExceeded)],
                       "Swift/NSError 资源拒绝被误判为节点不可达")
        }
        try expect(scheduler.snapshot().pendingConnections == 0
                    && NetworkPerformanceDiagnostics.shared.snapshot().stages[.probeFirstByte]?.count == before,
                    "资源拒绝遗留连接名额或污染网络时延样本")
    }

    private final class MemoryBoundUI {
        let lock = NSLock()
        var currentEpoch: UInt64 = 1
        var reportEpochs: [UInt64] = []
        var selectionEpochs: [UInt64] = []
        var acceptedSelection: String?
        var acceptedLatencies: [String: TimeInterval] = [:]
        let reported = DispatchSemaphore(value: 0)

        func advanceEpoch() { lock.lock(); currentEpoch = 2; lock.unlock() }
        func report(_ report: PolicyHealthMonitor.Report, epoch: UInt64) {
            lock.lock()
            reportEpochs.append(epoch)
            if epoch == currentEpoch { acceptedLatencies = report.latencies }
            lock.unlock(); reported.signal()
        }
        func select(_ selections: [String: String], epoch: UInt64) {
            lock.lock()
            selectionEpochs.append(epoch)
            if epoch == currentEpoch { acceptedSelection = selections["automatic"] }
            lock.unlock()
        }
    }

    private static func callbackConfigurationBinding() throws {
        let scheduler = ProbeScheduler(maximumActive: 1)
        let memory = MemoryMonitor()
        let ui = MemoryBoundUI()
        let monitor = PolicyHealthMonitor(scheduler: scheduler,
            connector: { _, _, _, _, callback in memory.connect(callback) })
        var old = Profile()
        old.proxies["A"] = ProxyPolicy(name: "A", kind: .direct)
        old.proxies["B"] = ProxyPolicy(name: "B", kind: .direct)
        old.groups["automatic"] = PolicyGroup(name: "automatic", kind: .urlTest, members: ["A"],
            parameters: ["url": "http://memory.invalid/check", "timeout": "3"])
        old.groupOrder = ["automatic"]
        monitor.update(profile: old,
                       onSelectionsChanged: { ui.select($0, epoch: 1) },
                       onReport: { ui.report($0, epoch: 1) })
        try expect(memory.started.wait(timeout: .now() + 2) == .success, "回调绑定测试旧 round 未启动")

        // Deterministically reproduce the former gap: the UI has advanced its
        // epoch and installed new callbacks, but its new profile update has
        // not entered the monitor queue yet. Then the old round completes.
        ui.advanceEpoch()
        monitor.onSelectionsChanged = { ui.select($0, epoch: 2) }
        monitor.onReport = { ui.report($0, epoch: 2) }
        _ = monitor.currentSelections // installation barrier, not a sleep
        memory.lock.lock(); let oldCallback = memory.callbacks[0]; memory.lock.unlock()
        oldCallback(.success((MemoryStream(), Data("HTTP/1.1 204 No Content\r\n".utf8))))
        try expect(ui.reported.wait(timeout: .now() + 2) == .success, "旧 round 没有完成回调")
        _ = monitor.currentSelections // both report and selection have finished
        ui.lock.lock()
        let oldDelivery = (ui.reportEpochs, ui.selectionEpochs, ui.acceptedSelection, ui.acceptedLatencies)
        ui.lock.unlock()
        try expect(oldDelivery.0 == [1] && oldDelivery.1 == [1]
                    && oldDelivery.2 == nil && oldDelivery.3.isEmpty,
                    "旧 round 被复贴新 UI epoch，污染新配置 report/selection")

        var current = old
        current.groups["automatic"]?.members = ["B"]
        monitor.update(profile: current,
                       onSelectionsChanged: { ui.select($0, epoch: 2) },
                       onReport: { ui.report($0, epoch: 2) })
        try expect(memory.started.wait(timeout: .now() + 2) == .success, "原子新配置 round 未启动")
        memory.lock.lock(); let callback = memory.callbacks[1]; memory.lock.unlock()
        callback(.success((MemoryStream(), Data("HTTP/1.1 204 No Content\r\n".utf8))))
        try expect(ui.reported.wait(timeout: .now() + 2) == .success, "新配置没有报告")
        _ = monitor.currentSelections
        ui.lock.lock()
        let currentDelivery = (ui.reportEpochs, ui.selectionEpochs, ui.acceptedSelection, ui.acceptedLatencies)
        ui.lock.unlock()
        try expect(currentDelivery.0 == [1, 2] && currentDelivery.1 == [1, 2]
                    && currentDelivery.2 == "B" && currentDelivery.3["A"] == nil
                    && currentDelivery.3["B"] != nil,
                    "新 round 没有绑定同一配置的回调或仍含旧成员")
        monitor.stop()
        _ = monitor.currentSelections
    }

    /// Exercises the real probe path against a loopback server.
    ///
    /// The case that matters is the third one: a member whose socket opens but
    /// which never speaks HTTP must be reported unhealthy. A TCP-connect
    /// latency test — which is what the node list already offers — calls that
    /// member healthy, which is exactly how a dead proxy keeps receiving
    /// traffic.
    private static func probeAgainstLoopback() throws {
        let healthy = try LoopbackServer(response: Data("HTTP/1.1 204 No Content\r\n\r\n".utf8))
        defer { healthy.stop() }
        guard let options = PolicyHealthOptions(parameters: [
            "url": "http://127.0.0.1:\(healthy.port)/generate_204", "timeout": "3",
        ]) else { throw Failure(text: "回环测试地址无法解析") }
        guard let latency = measure(options: options) else {
            throw Failure(text: "回环 HTTP 服务未被判定为健康")
        }
        try expect(latency >= 0 && latency < 3, "回环延迟不合理：\(latency)")

        // Speaks TCP, never speaks HTTP.
        let broken = try LoopbackServer(response: Data("NOT-HTTP garbage\r\n\r\n".utf8))
        defer { broken.stop() }
        guard let brokenOptions = PolicyHealthOptions(parameters: [
            "url": "http://127.0.0.1:\(broken.port)/generate_204", "timeout": "3",
        ]) else { throw Failure(text: "回环测试地址无法解析") }
        try expect(measure(options: brokenOptions) == nil,
                   "非 HTTP 响应被误判为健康 —— 纯 TCP 测延迟正是漏在这里")

        // Nothing listening at all.
        let closed = try LoopbackServer(response: Data())
        let closedPort = closed.port
        closed.stop()
        guard let closedOptions = PolicyHealthOptions(parameters: [
            "url": "http://127.0.0.1:\(closedPort)/generate_204", "timeout": "2",
        ]) else { throw Failure(text: "回环测试地址无法解析") }
        try expect(measure(options: closedOptions) == nil, "无监听端口被误判为健康")
    }

    private static func measure(options: PolicyHealthOptions) -> TimeInterval? {
        let queue = DispatchQueue(label: "app.hajimi.policy-health.selftest")
        let semaphore = DispatchSemaphore(value: 0)
        var result: TimeInterval?
        PolicyProbe.measure(route: .direct("DIRECT"), options: options, queue: queue) {
            result = $0
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + options.timeout + 3) == .success else { return nil }
        return result
    }
    private static func optionParsing() throws {
        guard let defaults = PolicyHealthOptions(parameters: [:]) else {
            throw Failure(text: "默认参数无法解析")
        }
        try expect(defaults.host == "www.gstatic.com", "默认测试地址错误")
        try expect(defaults.port == 80, "默认端口错误")
        try expect(defaults.path == "/generate_204", "默认路径错误")
        try expect(defaults.interval == 600, "默认间隔错误")
        try expect(abs(defaults.tolerance - 0.150) < 1e-9, "默认容差应为 150 毫秒")

        guard let custom = PolicyHealthOptions(parameters: [
            "url": "https://example.org:8443/probe",
            "interval": "30", "timeout": "2", "tolerance": "50",
        ]) else { throw Failure(text: "自定义参数无法解析") }
        try expect(custom.host == "example.org" && custom.port == 8443,
                   "自定义主机/端口解析错误")
        try expect(custom.path == "/probe", "自定义路径解析错误")
        try expect(custom.interval == 30 && custom.timeout == 2, "自定义间隔/超时解析错误")
        try expect(abs(custom.tolerance - 0.050) < 1e-9, "自定义容差解析错误")

        // A non-HTTP scheme is a configuration error, not something to guess at.
        try expect(PolicyHealthOptions(parameters: ["url": "ftp://example.org/x"]) == nil,
                   "非 HTTP 测试地址未被拒绝")
        try expect(PolicyHealthOptions(parameters: ["url": "not a url"]) == nil,
                   "非法测试地址未被拒绝")
        // A zero or negative interval must fall back rather than busy-loop.
        guard let clamped = PolicyHealthOptions(parameters: ["interval": "0"]) else {
            throw Failure(text: "零间隔参数无法解析")
        }
        try expect(clamped.interval == 600, "零间隔未回退到默认值")
    }

    private static func urlTestSelection() throws {
        let members = ["A", "B", "C"]
        let tolerance: TimeInterval = 0.150

        // With nothing selected yet, the fastest healthy member wins.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: ["A": 0.30, "B": 0.10, "C": 0.20],
            current: nil, tolerance: tolerance) == "B", "未选出最低延迟成员")

        // A challenger inside the tolerance band must not cause a switch.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: ["A": 0.30, "B": 0.10, "C": 0.20],
            current: "C", tolerance: tolerance) == "C",
            "容差范围内发生了不必要的切换")

        // Beyond the band it must switch.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: ["A": 0.30, "B": 0.01, "C": 0.20],
            current: "C", tolerance: tolerance) == "B",
            "超出容差后未切换到更快成员")

        // An unhealthy current member is abandoned immediately.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: ["A": 0.30], current: "C",
            tolerance: tolerance) == "A", "当前成员失效后未切换")

        // Everything down leaves the decision to the caller.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: [:], current: "B",
            tolerance: tolerance) == nil, "全部失效时不应给出选择")
    }

    private static func fallbackSelection() throws {
        let members = ["Primary", "Secondary", "Tertiary"]
        try expect(PolicySelectionPolicy.fallback(
            members: members, latencies: ["Primary": 0.5, "Secondary": 0.01]) == "Primary",
            "fallback 应优先声明顺序而非最低延迟")
        try expect(PolicySelectionPolicy.fallback(
            members: members, latencies: ["Secondary": 0.2, "Tertiary": 0.1]) == "Secondary",
            "首个成员失效后未降级到第二个")
        // Recovery must take traffic back to the preferred member.
        try expect(PolicySelectionPolicy.fallback(
            members: members, latencies: ["Primary": 0.9, "Tertiary": 0.1]) == "Primary",
            "首个成员恢复后未回切")
        try expect(PolicySelectionPolicy.fallback(members: members, latencies: [:]) == nil,
                   "全部失效时不应给出选择")
    }
}

/// Minimal loopback TCP server that replies with a fixed byte string.
private final class LoopbackServer {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "app.hajimi.policy-health.loopback")
    let port: UInt16

    init(response: Data) throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
            if case .failed = state { ready.signal() }
        }
        let connectionQueue = queue
        listener.newConnectionHandler = { connection in
            connection.start(queue: connectionQueue)
            // Read the request, then answer. The probe only needs the status
            // line, so a single send is enough.
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                guard !response.isEmpty else { connection.cancel(); return }
                connection.send(content: response, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success,
              let assigned = listener.port?.rawValue else {
            listener.cancel()
            throw PolicyHealthSelfTest.Failure(text: "无法启动回环测试服务")
        }
        port = assigned
    }

    func stop() { listener.cancel() }
}

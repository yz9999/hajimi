import Foundation
import Dispatch
import Network
import Darwin

// The runner inserts verbatim production declarations at these boundaries.
// Only policy preparation, resource stores and transport I/O are controlled.
// Existing DNS pool fixtures separately exercise the actual transport owners.
// INSERT_PRODUCTION_DEPENDENCIES

private struct FixtureProfile { var dnsPrewarmEnabled = true }
private struct FixtureUpstream { let encrypted: Bool }
private struct DNSQueryPlan {
    let generation: UInt64
    let upstream: FixtureUpstream
    let candidates: [Int]
}
private enum DNSQueryPreparation { case upstream(DNSQueryPlan), answer(Data) }
enum EncryptedDNSQueryFailure: Error { case cancelled }
private enum FixturePolicy { case allowed, refused, plaintext, stalePlan, candidateRefused }
private enum FixtureFailure: Error, CustomStringConvertible {
    case failed(String)
    var description: String { switch self { case .failed(let message): return message } }
}

private final class FixtureEvents {
    private let lock = NSLock()
    private var events: [String] = []
    private var transports: [FixtureTransport] = []
    let started = DispatchSemaphore(value: 0)
    func add(_ event: String) { lock.lock(); events.append(event); lock.unlock() }
    func made(_ transport: FixtureTransport) {
        lock.lock(); transports.append(transport); events.append("dial"); lock.unlock()
        started.signal()
    }
    var snapshot: ([String], [FixtureTransport]) {
        lock.lock(); defer { lock.unlock() }; return (events, transports)
    }
}

private final class FixtureTransport: NativeRoutedDatagram, DNSConnectionPrewarming,
                                      DNSQueryCancellationAcknowledging {
    private let lock = NSLock()
    private var completion: ((Result<Void, EncryptedDNSQueryFailure>) -> Void)?
    private var sent = 0, prepared = 0, closed = false
    private var reason: DNSAttemptCancellationReason?
    private var deadlineRemaining: TimeInterval = 0
    func send(_ data: Data) { lock.lock(); sent += 1; lock.unlock() }
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Void, EncryptedDNSQueryFailure>) -> Void) {
        lock.lock(); prepared += 1
        deadlineRemaining = absoluteDeadline - ProcessInfo.processInfo.systemUptime
        self.completion = completion; lock.unlock()
    }
    func cancel() { cancel(reason: .callerCancelled, completion: {}) }
    func cancel(completion: @escaping () -> Void) {
        cancel(reason: .callerCancelled, completion: completion)
    }
    func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        lock.lock(); closed = true; self.reason = reason
        let callback = self.completion; self.completion = nil; lock.unlock()
        callback?(.failure(.cancelled)); completion()
    }
    var snapshot: (sent: Int, prepared: Int, closed: Bool,
                   reason: DNSAttemptCancellationReason?, remaining: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        return (sent, prepared, closed, reason, deadlineRemaining)
    }
}

// These owners stay empty in this scheduling fixture. The real detach/cancel
// declarations still own prewarm work, epoch changes and all memory transports.
private final class FixtureRetiredOwner {
    func cancel(reason: DNSAttemptCancellationReason) {}
    func cancel() {}
}
private final class FixtureOwnerStore {
    func remove(_ predicate: (Int) -> Bool) -> [FixtureRetiredOwner] { [] }
}
private final class FixtureInvalidation { func invalidate() {}; func removeAll() {} }
private final class DNSRouteDecisionCache {}
private final class PolicyDNSDatagram {
    func cancel() {}
    func invalidateForPolicyUpdate() {}
}
private enum NetworkPerformanceOutcome { case success, failure, cancelled }
private enum NetworkPerformanceStage { case dnsConnectionPrewarm }
private final class NetworkPerformanceDiagnostics {
    static let shared = NetworkPerformanceDiagnostics()
    static func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
    static func elapsedMilliseconds(since start: UInt64) -> Double {
        Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    }
    func record(_ stage: NetworkPerformanceStage, milliseconds: Double,
                outcome: NetworkPerformanceOutcome) {}
}

private final class NativePacketRouter {
    private let configurationLock = NSLock()
    private var configurationGeneration: UInt64 = 0
    private var profile: FixtureProfile
    private var dnsRouteCache = DNSRouteDecisionCache()
    private var dnsFlows: [WeakDNSQueryDatagram] = []
    private let dnsAdaptiveSelector = FixtureInvalidation()
    private let dnsQueryCoordinator = FixtureInvalidation()
    private let dohLock = NSLock()
    private let dohResolvers = FixtureOwnerStore(), dotResolvers = FixtureOwnerStore()
    private let proxyTCPDNSResolvers = FixtureOwnerStore()
    private var bootstrapResolvers: [Int: FixtureRetiredOwner] = [:]
    private var memoryFixtureAfterDNSFlushUnlock: (() -> Void)?
    private let policy: FixturePolicy
    private let events: FixtureEvents

    // INSERT_PRODUCTION_ROUTER_FIELDS
    // INSERT_PRODUCTION_ROUTER_METHODS

    init(enabled: Bool = true, policy: FixturePolicy = .allowed, events: FixtureEvents) {
        profile = FixtureProfile(dnsPrewarmEnabled: enabled)
        self.policy = policy; self.events = events
    }
    private func prepareDNSQuery(_ data: Data, original: RequestTarget,
                                 synthesizeFakeIP: Bool) throws -> DNSQueryPreparation {
        guard policy != .refused, !synthesizeFakeIP,
              original.host == "198.18.16.2", original.port == 53,
              DNSMessageInspection.singleQuestion(in: data)?.name == "dns-prewarm.invalid" else {
            throw FixtureFailure.failed("controlled policy refused prewarm")
        }
        return .upstream(DNSQueryPlan(
            generation: policy == .stalePlan ? configurationGeneration &- 1 : configurationGeneration,
            upstream: FixtureUpstream(encrypted: policy != .plaintext), candidates: [0, 1, 2]))
    }
    private func revalidatedCandidatePlan(_ plan: DNSQueryPlan, candidate: Int) throws -> DNSQueryPlan {
        if policy == .candidateRefused { throw FixtureFailure.failed("controlled candidate refused") }
        return plan
    }
    private func makeDNSUpstream(plan: DNSQueryPlan, queue: DispatchQueue,
                                 receive: @escaping (Data) -> Void,
                                 failure: @escaping (Error) -> Void) throws -> NativeRoutedDatagram {
        let transport = FixtureTransport(); events.made(transport); return transport
    }
    func holdForFixture() throws -> () -> Void {
        let entered = DispatchSemaphore(value: 0), released = DispatchSemaphore(value: 0)
        dnsPrewarmQueue.async {
            entered.signal(); _ = released.wait(timeout: .now() + 4)
        }
        try Fixture.expect(entered.wait(timeout: .now() + 2) == .success, "prewarm queue blocker did not start")
        return { released.signal() }
    }
    func markerForFixture() -> DispatchSemaphore {
        let done = DispatchSemaphore(value: 0)
        dnsPrewarmQueue.async { self.events.add("marker"); done.signal() }
        return done
    }
    func drainForFixture() { dnsPrewarmQueue.sync {} }
    func staleEntryForFixture() -> (() -> Void)? {
        guard let identity = dnsPrewarmIdentity else { return nil }
        return { self.beginDNSPrewarm(identity) }
    }
}

private final class ProxyEngine {
    private let stateQueue = DispatchQueue(label: "fixture.engine.state")
    private let dnsPacketRouter: NativePacketRouter?
    static var currentOutboundInterface: NWInterface? { nil }
    init(router: NativePacketRouter?) { dnsPacketRouter = router }
    // INSERT_PRODUCTION_ENGINE_METHOD
}

private enum Fixture {
    static var assertions = 0
    static var scenarios: [String] = []
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        assertions += 1
        guard condition() else { throw FixtureFailure.failed(message) }
    }
    static func wait(_ semaphore: DispatchSemaphore, _ message: String) throws {
        try expect(semaphore.wait(timeout: .now() + 2) == .success, message)
    }
    static func scheduling(immediate: Bool) throws {
        let events = FixtureEvents(), router = NativePacketRouter(events: events)
        let engine = ProxyEngine(router: router), release = try router.holdForFixture()
        defer { router.cancelDNSQueries() }
        let enqueueStarted = ProcessInfo.processInfo.systemUptime
        if immediate { engine.prewarmDNS(immediately: true) } else { engine.prewarmDNS() }
        let marker = router.markerForFixture()
        let enqueueDuration = ProcessInfo.processInfo.systemUptime - enqueueStarted
        release()
        try expect(enqueueDuration < 0.20, "fixture enqueue phase exceeded the production delay; host was overloaded")
        try wait(marker, "prewarm queue marker was lost")
        try wait(events.started, "first approved prewarm did not start")
        try wait(events.started, "second approved prewarm did not start")
        router.drainForFixture()
        let (order, peers) = events.snapshot
        try expect(order == (immediate ? ["dial", "dial", "marker"] : ["marker", "dial", "dial"]),
                   immediate ? "immediately:true did not reach the real router's immediate dispatch branch"
                             : "default engine call no longer retained the router's delayed dispatch")
        try expect(peers.count == 2, "prewarm exceeded the two-candidate cap")
        try expect(peers.allSatisfy { $0.snapshot.sent == 0 && $0.snapshot.prepared == 1 },
                   "prewarm sent DNS payload or skipped the prewarm transport capability")
        try expect(peers.allSatisfy { (2.5...3.0).contains($0.snapshot.remaining) },
                   "immediate entry changed the original three-second preparation deadline")
        engine.prewarmDNS(immediately: true)
        router.drainForFixture()
        try expect(events.snapshot.1.count == 2, "same-epoch immediate entry duplicated connections")
        router.cancelDNSQueries()
        router.drainForFixture()
        try expect(peers.allSatisfy { $0.snapshot.closed && $0.snapshot.reason == .policyChanged },
                   "actual epoch teardown did not cancel in-flight prewarm transports")
        scenarios.append(immediate ? "immediate forwarding and dispatch" : "default delayed dispatch")
    }
    static func policyBoundaries() throws {
        for (name, enabled, policy) in [
            ("opt out", false, FixturePolicy.allowed),
            ("policy refusal", true, .refused),
            ("plaintext refusal", true, .plaintext),
            ("stale prepared plan", true, .stalePlan),
            ("candidate revalidation refusal", true, .candidateRefused),
        ] {
            let events = FixtureEvents(), router = NativePacketRouter(enabled: enabled, policy: policy, events: events)
            let engine = ProxyEngine(router: router)
            engine.prewarmDNS(immediately: true)
            router.drainForFixture()
            try expect(events.snapshot.1.isEmpty, "immediate prewarm bypassed \(name)")
            router.cancelDNSQueries()
            scenarios.append(name)
        }
    }
    static func cancelledEpoch() throws {
        let events = FixtureEvents(), router = NativePacketRouter(events: events)
        let engine = ProxyEngine(router: router), release = try router.holdForFixture()
        defer { router.cancelDNSQueries() }
        engine.prewarmDNS(immediately: true)
        guard let lateBegin = router.staleEntryForFixture() else {
            release(); throw FixtureFailure.failed("production did not register a prewarm identity")
        }
        router.cancelDNSQueries(keepFlows: true)
        let marker = router.markerForFixture()
        release()
        try wait(marker, "cancelled prewarm did not release its queue")
        try expect(events.snapshot.1.isEmpty, "cancelled queued immediate work still dialled")
        // Force a late callback past GCD cancellation. The verbatim production
        // begin method must independently reject its captured old epoch.
        lateBegin()
        try expect(events.snapshot.1.isEmpty, "old-epoch begin callback dialled after cancellation")
        engine.prewarmDNS(immediately: true)
        try wait(events.started, "fresh epoch did not permit first prewarm")
        try wait(events.started, "fresh epoch did not permit second prewarm")
        router.drainForFixture()
        try expect(events.snapshot.1.count == 2, "fresh epoch inherited stale duplicate suppression")
        scenarios.append("queued cancellation, late old epoch and fresh epoch")
    }
    static func run() throws {
        try scheduling(immediate: true)
        try scheduling(immediate: false)
        try policyBoundaries()
        try cancelledEpoch()
        ProxyEngine(router: nil).prewarmDNS(immediately: true)
        scenarios.append("engine without router")
        let report: [String: Any] = ["passed": true, "assertions": assertions, "scenarios": scenarios,
            "scope": "verbatim engine forwarding and router scheduling/epoch/teardown methods; controlled policy and memory transports"]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
    }
}

@main
private enum DNSImmediatePrewarmMain {
    static func main() {
        do { try Fixture.run() }
        catch {
            FileHandle.standardError.write(Data("FAIL: \(error)\n".utf8)); exit(1)
        }
    }
}

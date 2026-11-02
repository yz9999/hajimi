import Foundation
import Dispatch
import Darwin
import HajimiCore
import HajimiRuntime
import HajimiDiagnosticsUI

// The copied manager includes a diagnostics entry that these lifecycle cases
// never invoke. Model its signatures only, and fail immediately if a scenario
// accidentally enters it; these substitutes do not prove diagnostic behavior.
enum ProxyEngineStatus: Equatable { case stopped, starting, running, failed(String) }
final class NetworkConnectivityDiagnosticsSession {
    func cancel() { fatalError("Diagnostics are outside the enhanced handoff fixture") }
}

extension ProxyEngine {
    func startNetworkDiagnostics(callbackQueue: DispatchQueue,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        fatalError("Diagnostics are outside the enhanced handoff fixture")
    }
    static func unavailableNetworkDiagnostics(detail: String, callbackQueue: DispatchQueue,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        fatalError("Diagnostics are outside the enhanced handoff fixture")
    }
}

extension NativePacketRouter {
    func startNetworkDiagnostics(callbackQueue: DispatchQueue, ownerIsCurrent: @escaping () -> Bool,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        fatalError("Diagnostics are outside the enhanced handoff fixture")
    }
}

// Only actual I/O/platform owners are substituted. Profile, OutboundMode,
// RoutingReloadGate, runtime state and IPC values compile from real sources.
enum ProxyBypassCollectionError: Error { case unresolved([String]), networkChanged, tooManyHosts }

private struct FixtureError: LocalizedError {
    let text: String
    var errorDescription: String? { text }
}

/// A platform scheduling boundary, not a rewritten manager method. Legacy
/// lifecycle cases hold scheduled work for deterministic handoff assertions;
/// reconnect timing cases use the real dispatch queue and original deadline.
/// Explicit perform() deliberately delivers even a cancelled body, so stale
/// ticket tests verify the production authority checks as well as GCD cancel.
final class DispatchWorkItem {
    let dispatched: Dispatch.DispatchWorkItem
    private let body: () -> Void
    init(block: @escaping () -> Void) {
        body = block
        dispatched = Dispatch.DispatchWorkItem(block: block)
    }
    func cancel() { dispatched.cancel() }
    func perform() { body() }
}

extension DispatchQueue {
    func async(execute work: DispatchWorkItem) {
        HandoffFixture.recordRebindSchedule(delay: 0)
        guard !HandoffFixture.lock.withLock({ HandoffFixture.holdScheduledRebinds }) else { return }
        async(execute: work.dispatched)
    }
    func asyncAfter(deadline: DispatchTime, execute work: DispatchWorkItem) {
        let now = DispatchTime.now().uptimeNanoseconds
        let delay = deadline.uptimeNanoseconds > now ? Double(deadline.uptimeNanoseconds - now) / 1_000_000_000 : 0
        HandoffFixture.recordRebindSchedule(delay: delay)
        guard !HandoffFixture.lock.withLock({ HandoffFixture.holdScheduledRebinds }) else { return }
        asyncAfter(deadline: deadline, execute: work.dispatched)
    }
}

// These same-module names intentionally shadow the imported platform types.
// The production observer closures compile unchanged, but can only receive
// values from these memory objects. No NW monitor or workspace is created.
struct NWPath {
    let available: Bool
}

final class NWPathMonitor {
    private static let registryLock = NSLock()
    private static var monitors: [NWPathMonitor] = []
    private let lock = NSLock()
    private var target: DispatchQueue?
    private var stopped = false
    var pathUpdateHandler: ((NWPath) -> Void)?
    init() { Self.registryLock.withLock { Self.monitors.append(self) } }
    static var latest: NWPathMonitor? { registryLock.withLock { monitors.last } }
    func start(queue: DispatchQueue) {
        lock.withLock { target = queue; stopped = false }
        HandoffFixture.event("observer.path.started")
    }
    func cancel() {
        lock.withLock { stopped = true }
        HandoffFixture.event("observer.path.cancelled")
    }
    func capturedDelivery(_ path: NWPath) -> () -> Void {
        let values = lock.withLock { (target, pathUpdateHandler) }
        return {
            values.0?.async {
                HandoffFixture.event("observer.path.delivered")
                values.1?(path)
            }
        }
    }
    func emit(_ path: NWPath) {
        guard lock.withLock({ !stopped }) else { return }
        capturedDelivery(path)()
    }
}

final class MemoryWorkspaceNotificationCenter {
    private final class Observer: NSObject {
        let callback: (Notification) -> Void
        init(_ callback: @escaping (Notification) -> Void) { self.callback = callback }
    }
    private let lock = NSLock()
    private var observers: [Observer] = []
    func addObserver(forName name: Notification.Name?, object: Any?, queue: OperationQueue?,
                     using block: @escaping (Notification) -> Void) -> NSObjectProtocol {
        let observer = Observer(block)
        lock.withLock { observers.append(observer) }
        HandoffFixture.event("observer.wake.installed")
        return observer
    }
    func removeObserver(_ value: Any) {
        guard let observer = value as? Observer else { return }
        lock.withLock { observers.removeAll { $0 === observer } }
        HandoffFixture.event("observer.wake.removed")
    }
    var capturedCallbacks: [(Notification) -> Void] { lock.withLock { observers.map(\.callback) } }
    func postWake() { Self.deliver(capturedCallbacks) }
    static func deliver(_ callbacks: [(Notification) -> Void]) {
        for callback in callbacks { callback(Notification(name: NSWorkspace.didWakeNotification)) }
    }
}

final class NSWorkspace {
    static let shared = NSWorkspace()
    static let didWakeNotification = Notification.Name("memory.hajimi.workspace.wake")
    let notificationCenter = MemoryWorkspaceNotificationCenter()
}

enum HandoffFixture {
    static let lock = NSLock()
    static var events: [String] = []
    static var timedEvents: [(name: String, at: TimeInterval)] = []
    static var scheduledRebindDelays: [TimeInterval] = []
    static var holdScheduledRebinds = true
    private static var statuses: [EnhancedModeManager.Status] = []
    static var blockedStage: String?
    static let releaseStage = DispatchSemaphore(value: 0)
    static var state = HajimiHelperTunnelState(running: false)
    static var startedResult: Result<EnhancedModeManager.State, Error>?
    static var stoppedResult: Result<Void, Error>?
    static var reloadResult: Result<Void, Error>?
    static var preparedFD: Int32 = -1
    static var sentinelFD: Int32 = -1
    static var nativeFD: Int32 = -1
    static var readerReady = false
    static var failReaderStart = false
    static var failReaderReady = false
    static var failCommit = false
    static var failReload = false
    static var physicalNetworkNotReady = false
    static var preparePhysicalNetworkNotReadyCount = 0
    static var failPrepare = false
    static var failCommitWithPendingCleanup = false
    static var pendingCleanup = false
    static var stopShouldFail = false
    static var bypassAddresses = ["192.0.2.99"]
    static var routerExcludedRoutes: [[String]] = []
    static var helperExcludedRoutes: [[String]] = []
    static var helperBypassRequests: [[String]] = []
    static var preparedExcludedRoutes: [[String]] = []
    static var preparedBypassRequests: [[String]] = []
    static var createdRouterExcludedRoutes: [[String]] = []
    static var collectedExcludedRoutes: [[String]] = []
    static var holdBypassResults = false
    private static var heldBypassResults: [() -> Void] = []
    private static var physicalNetwork = network()
    private static var prepareSequence = 0

    static func network(available: Bool = true, address: String = "192.0.2.7",
                        gateway: String? = "192.0.2.1") -> EnhancedNetworkSnapshot {
        EnhancedNetworkSnapshot(available: available, interfaceName: "en-fixture", interfaceIndex: 7,
            addresses: [address], gateways: gateway.map { [$0] } ?? [])
    }
    static func setNetwork(_ value: EnhancedNetworkSnapshot) { lock.withLock { physicalNetwork = value } }
    static func networkSnapshot(path: NWPath?, boundInterface: String?) -> EnhancedNetworkSnapshot {
        let value = lock.withLock { physicalNetwork }
        return EnhancedNetworkSnapshot(available: value.available && (path?.available ?? true),
            interfaceName: boundInterface ?? value.interfaceName, interfaceIndex: value.interfaceIndex,
            addresses: value.addresses, gateways: value.gateways, associationStamp: value.associationStamp)
    }
    static func defaultInterface() throws -> String {
        let value = lock.withLock { physicalNetwork }
        guard value.available else { throw EnhancedModeManager.ManagerError.defaultInterfaceMissing }
        return value.interfaceName
    }
    static func nextSessionToken() -> String {
        lock.withLock { prepareSequence += 1; return "fixture-session-\(prepareSequence)" }
    }
    static func retainBypassResult(_ callback: @escaping () -> Void) -> Bool {
        lock.withLock {
            guard holdBypassResults else { return false }
            heldBypassResults.append(callback); events.append("bypass.held")
            return true
        }
    }
    static func releaseBypassResults() {
        let callbacks = lock.withLock { () -> [() -> Void] in
            holdBypassResults = false
            let result = heldBypassResults; heldBypassResults = []
            return result
        }
        for callback in callbacks { callback() }
    }

    static func event(_ text: String) {
        lock.withLock {
            events.append(text)
            timedEvents.append((text, ProcessInfo.processInfo.systemUptime))
        }
    }
    static func recordRebindSchedule(delay: TimeInterval) {
        lock.withLock { scheduledRebindDelays.append(delay) }
    }
    static func recordStatus(_ status: EnhancedModeManager.Status) {
        lock.withLock {
            statuses.append(status)
            switch status {
            case .starting: events.append("status.starting")
            case .running: events.append("status.running")
            case .stopping: events.append("status.stopping")
            case .stopped: events.append("status.stopped")
            case .failed: events.append("status.failed")
            #if HAVE_PERSISTENT_ENHANCED_RECOVERY
            case .waitingForNetwork: events.append("status.waiting")
            #endif
            }
        }
    }
    static func contains(_ text: String) -> Bool { lock.withLock { events.contains(text) } }
    static func count(_ text: String) -> Int { lock.withLock { events.filter { $0 == text }.count } }
    static func hitStage(_ text: String) {
        event("stage.\(text)")
        guard lock.withLock({ blockedStage == text }) else { return }
        if releaseStage.wait(timeout: .now() + 8) != .success {
            event("stage.timeout.\(text)")
        }
    }
    static func snapshot() -> HajimiHelperTunnelState { lock.withLock { state } }
    static func completeRecovery(restoredSessionToken: String? = nil) {
        lock.withLock {
            let token = restoredSessionToken ?? state.sessionToken ?? state.lastRestoredSessionToken
            pendingCleanup = false
            state = HajimiHelperTunnelState(running: false)
            state.lastRestoredSessionToken = token
            events.append("network.restored")
        }
    }
    static func simulateRestart() {
        lock.withLock {
            pendingCleanup = false
            state = HajimiHelperTunnelState(running: false)
            events.append("helper.restarted")
        }
    }
    static func makePending() {
        lock.withLock {
            pendingCleanup = true
            state.running = false
            state.phase = nil
            state.networkCleanupPending = true
        }
    }
}

final class ProxyEngine {
    struct RuntimeSnapshot { var status: ProxyEngineStatus }
    struct Interface { var name: String }
    private static var interface: String?
    static var currentOutboundInterface: Interface? {
        HandoffFixture.lock.withLock { interface.map { Interface(name: $0) } }
    }
    func runtimeSnapshot() -> RuntimeSnapshot { RuntimeSnapshot(status: .running) }
    func setOutboundInterface(name: String?, completion: @escaping (Result<Void, Error>) -> Void) {
        HandoffFixture.lock.withLock { Self.interface = name }
        HandoffFixture.event(name == nil ? "engine.unbind" : "engine.bind")
        DispatchQueue.global().async {
            if name != nil { HandoffFixture.hitStage("binding") }
            completion(.success(()))
        }
    }
    func flushDNS(prewarm: Bool = true) { HandoffFixture.event("engine.flush") }
    func prewarmDNS(immediately: Bool = false) {
        HandoffFixture.event("engine.prewarm")
        HandoffFixture.event(immediately ? "engine.prewarm.immediate" : "engine.prewarm.deferred")
    }
}

final class NativePacketRouter {
    init(profile: Profile, mode: OutboundMode, globalPolicy: String,
         groupSelections: [String: String], fakeIPStoreURL: URL? = nil) {
        HandoffFixture.lock.withLock { HandoffFixture.createdRouterExcludedRoutes.append(profile.tunExcludedRoutes) }
        HandoffFixture.event("router.create")
    }
    static func setOutboundInterface(name: String?, completion: @escaping (Result<Void, Error>) -> Void) {
        HandoffFixture.event(name == nil ? "router.unbind" : "router.bind")
        completion(.success(()))
    }
    func update(profile: Profile, mode: OutboundMode, globalPolicy: String,
                groupSelections: [String: String]) {
        HandoffFixture.lock.withLock { HandoffFixture.routerExcludedRoutes.append(profile.tunExcludedRoutes) }
        HandoffFixture.event("router.update")
    }
    func prewarmDNS(immediately: Bool = false) {
        HandoffFixture.event("router.prewarm")
        HandoffFixture.event(immediately ? "router.prewarm.immediate" : "router.prewarm.deferred")
    }
    func flushDNS(prewarm: Bool = true) { HandoffFixture.event("router.flush") }
    func flushFakeIP() {}
    func fakeIPSnapshot() -> [(domain: String, address: String)] { [] }
}

struct NativeTunnelStatistics {
    var activeFlows = 0, totalFlows = 0
    var uploadedBytes: UInt64 = 0, downloadedBytes: UInt64 = 0
}

final class NativeTunnel {
    static var physicalInterfaceName: String?
    private var fd: Int32 = -1
    init(router: NativePacketRouter) throws {}
    @discardableResult
    func start(fileDescriptor: Int32, interfaceName: String) throws -> String {
        fd = fileDescriptor
        HandoffFixture.lock.withLock { HandoffFixture.nativeFD = fd }
        HandoffFixture.event("reader.start")
        if HandoffFixture.failReaderStart {
            stop()
            // Immediately reuse the closed number. An erroneous second close
            // by the manager would close this unrelated sentinel descriptor.
            let sentinel = Darwin.open("/dev/null", O_RDONLY)
            HandoffFixture.lock.withLock { HandoffFixture.sentinelFD = sentinel }
            throw FixtureError(text: "injected reader start failure")
        }
        return interfaceName
    }
    func waitUntilReaderReady(timeout: TimeInterval = 3) throws {
        HandoffFixture.hitStage("reader")
        if HandoffFixture.failReaderReady { throw FixtureError(text: "injected reader readiness failure") }
        HandoffFixture.lock.withLock { HandoffFixture.readerReady = true }
        HandoffFixture.event("reader.ready")
    }
    func stop() {
        guard fd >= 0 else { return }
        HandoffFixture.event("reader.stop")
        Darwin.close(fd); fd = -1
        HandoffFixture.lock.withLock { HandoffFixture.nativeFD = -1; HandoffFixture.readerReady = false }
    }
    func resetFlows() { HandoffFixture.event("reader.resetFlows") }
    func statistics() -> NativeTunnelStatistics { NativeTunnelStatistics() }
}

enum ProxyBypassAddresses {
    static func collect(profile: Profile, mode: OutboundMode, globalPolicy: String,
                        groupSelections: [String: String]) -> [String] {
        HandoffFixture.lock.withLock {
            HandoffFixture.collectedExcludedRoutes.append(profile.tunExcludedRoutes)
            return HandoffFixture.bypassAddresses
        }
    }
    static func collectAsync(profile: Profile, mode: OutboundMode, globalPolicy: String,
                             groupSelections: [String: String], queue: DispatchQueue,
                             completion: @escaping (Result<[String], Error>) -> Void) {
        HandoffFixture.event("bypass.collect")
        HandoffFixture.lock.withLock { HandoffFixture.collectedExcludedRoutes.append(profile.tunExcludedRoutes) }
        let held = HandoffFixture.lock.withLock { HandoffFixture.bypassAddresses }
        if HandoffFixture.retainBypassResult({ queue.async { completion(.success(held)) } }) { return }
        DispatchQueue.global().async {
            HandoffFixture.hitStage("bypass")
            let result = HandoffFixture.lock.withLock { HandoffFixture.bypassAddresses }
            queue.async { completion(.success(result)) }
        }
    }
    static func invalidateCache() {}
}

final class PrivilegedHelperClient {
    enum ClientError: LocalizedError {
        case invalidResponse, helperUnavailable, physicalNetworkNotReady
        case command(String), helper(String)
        var errorDescription: String? {
            switch self {
            case .invalidResponse: return "invalid fixture response"
            case .helperUnavailable: return "fixture unavailable"
            case .physicalNetworkNotReady: return "memory physical gateway is not ready"
            case .command(let message), .helper(let message): return message
            }
        }
    }
    struct TunnelSession {
        let state: HajimiHelperTunnelState
        let fileDescriptor: Int32
    }
    func ensureInstalled(completion: @escaping (Result<Void, Error>) -> Void) {
        DispatchQueue.global().async {
            HandoffFixture.hitStage("installation")
            DispatchQueue.main.async { completion(.success(())) }
        }
    }
    func status(keepAlive: Bool = true) throws -> HajimiHelperTunnelState {
        HandoffFixture.event("helper.status")
        HandoffFixture.event(keepAlive ? "helper.status.heartbeat" : "helper.status.readonly")
        return HandoffFixture.snapshot()
    }
    func prepare(fakeIPEnabled: Bool, bypassAddresses: [String], excludedRoutes: [String] = [],
                 includedRoutes: [String] = []) throws -> TunnelSession {
        HandoffFixture.event("helper.prepare")
        HandoffFixture.lock.withLock {
            HandoffFixture.preparedExcludedRoutes.append(excludedRoutes)
            HandoffFixture.preparedBypassRequests.append(bypassAddresses)
        }
        HandoffFixture.hitStage("prepare")
        let unavailable = HandoffFixture.lock.withLock { () -> Bool in
            guard HandoffFixture.preparePhysicalNetworkNotReadyCount > 0 else { return false }
            HandoffFixture.preparePhysicalNetworkNotReadyCount -= 1
            return true
        }
        if unavailable {
            HandoffFixture.event("helper.prepare.physical-not-ready")
            throw ClientError.physicalNetworkNotReady
        }
        if HandoffFixture.lock.withLock({ HandoffFixture.failPrepare }) {
            HandoffFixture.event("helper.prepare.fatal")
            throw ClientError.helper("injected preparation failure requiring manual attention")
        }
        let fd = Darwin.open("/dev/null", O_RDONLY)
        guard fd >= 0 else { throw ClientError.command("open fixture descriptor failed") }
        let prepared = HajimiHelperTunnelState(running: false, phase: .prepared,
            sessionToken: HandoffFixture.nextSessionToken(), tunnelInterface: "utun-fixture", physicalInterface: "en-fixture")
        HandoffFixture.lock.withLock { HandoffFixture.preparedFD = fd; HandoffFixture.state = prepared }
        return TunnelSession(state: prepared, fileDescriptor: fd)
    }
    func commit(sessionToken: String) throws -> HajimiHelperTunnelState {
        HandoffFixture.event("helper.commit")
        guard HandoffFixture.lock.withLock({ HandoffFixture.readerReady && HandoffFixture.nativeFD >= 0 }) else {
            throw FixtureError(text: "commit called before reader was ready")
        }
        HandoffFixture.hitStage("commit")
        if HandoffFixture.failCommitWithPendingCleanup {
            HandoffFixture.makePending()
            throw ClientError.command("Operation timed out")
        }
        if HandoffFixture.failCommit {
            HandoffFixture.completeRecovery()
            throw ClientError.helper("injected commit failure after verified rollback")
        }
        return HandoffFixture.lock.withLock {
            HandoffFixture.state.running = true
            HandoffFixture.state.phase = .running
            HandoffFixture.state.startedAt = Date()
            return HandoffFixture.state
        }
    }
    func stop(sessionToken: String? = nil) throws -> HajimiHelperTunnelState {
        HandoffFixture.event("helper.stop")
        let current = HandoffFixture.snapshot()
        let alreadyRestored = !current.running && current.phase == nil &&
            current.networkCleanupPending == false && current.sessionToken == nil &&
            sessionToken != nil && current.lastRestoredSessionToken == sessionToken
        if let sessionToken, current.sessionToken != sessionToken, !alreadyRestored {
            throw ClientError.helper("fixture session changed")
        }
        if alreadyRestored { return current }
        if HandoffFixture.stopShouldFail || HandoffFixture.lock.withLock({ HandoffFixture.pendingCleanup }) {
            HandoffFixture.makePending()
            throw ClientError.helper("fixture network cleanup pending")
        }
        HandoffFixture.completeRecovery()
        return HandoffFixture.snapshot()
    }
    func reload(fakeIPEnabled: Bool, bypassAddresses: [String], excludedRoutes: [String] = [],
                includedRoutes: [String] = [], sessionToken: String? = nil) throws -> HajimiHelperTunnelState {
        HandoffFixture.event("helper.reload")
        HandoffFixture.lock.withLock {
            HandoffFixture.helperExcludedRoutes.append(excludedRoutes)
            HandoffFixture.helperBypassRequests.append(bypassAddresses)
        }
        HandoffFixture.hitStage("reload")
        if HandoffFixture.lock.withLock({ HandoffFixture.physicalNetworkNotReady }) {
            HandoffFixture.event("helper.reload.physical-not-ready")
            throw ClientError.physicalNetworkNotReady
        }
        if HandoffFixture.failReload { throw ClientError.helper("expected controlled reload failure") }
        HandoffFixture.event("helper.reload.applied")
        return HandoffFixture.snapshot()
    }
}

@main
private enum EnhancedHandoffMain {
    static var assertions = 0
    static func expect(_ condition: @autoclosure () -> Bool, _ text: String) throws {
        assertions += 1
        if !condition() { throw FixtureError(text: text) }
    }
    static func wait(_ predicate: () -> Bool, timeout: TimeInterval = 6,
                     failureMessage: String = "timed out waiting for controlled lifecycle event") throws {
        let until = Date().addingTimeInterval(timeout)
        while !predicate(), Date() < until {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        try expect(predicate(), failureMessage)
    }
    static func waitWithoutMainQueue(_ predicate: () -> Bool, timeout: TimeInterval = 4) throws {
        let until = Date().addingTimeInterval(timeout)
        let yield = DispatchSemaphore(value: 0)
        while !predicate(), Date() < until {
            _ = yield.wait(timeout: .now() + .milliseconds(5))
        }
        try expect(predicate(), "timed out waiting while a main-queue completion was deliberately held")
    }
    static func before(_ first: String, _ second: String) -> Bool {
        HandoffFixture.lock.withLock {
            guard let a = HandoffFixture.events.firstIndex(of: first),
                  let b = HandoffFixture.events.firstIndex(of: second) else { return false }
            return a < b
        }
    }
    static func start(_ manager: EnhancedModeManager, _ engine: ProxyEngine,
                      profile: Profile = Profile(), selections: [String: String] = [:]) {
        manager.start(profile: profile, mode: .proxy, globalPolicy: "fixture", groupSelections: selections,
                      engine: engine) { result in
            HandoffFixture.lock.withLock { HandoffFixture.startedResult = result }
            HandoffFixture.event("start.completed")
        }
    }
    static func stop(_ manager: EnhancedModeManager, _ engine: ProxyEngine) {
        manager.stop(engine: engine) { result in
            HandoffFixture.lock.withLock { HandoffFixture.stoppedResult = result }
            HandoffFixture.event("stop.completed")
        }
    }
    static func assertStartFailed() throws {
        guard case .failure? = HandoffFixture.lock.withLock({ HandoffFixture.startedResult }) else {
            throw FixtureError(text: "start unexpectedly succeeded after cancellation or injected failure")
        }
    }
    static func assertStartSucceeded() throws {
        guard case .success? = HandoffFixture.lock.withLock({ HandoffFixture.startedResult }) else {
            throw FixtureError(text: "ordinary prepared startup failed")
        }
    }
    static var configuration: NetworkDiagnosticsConfiguration {
        NetworkDiagnosticsConfiguration(mode: "proxy", selectedPolicy: "fixture", groupSelections: [:],
                                        profileRevision: 1, systemProxy: false)
    }
    static func runtime(_ manager: EnhancedModeManager, _ engine: ProxyEngine) throws -> AppNetworkRuntime {
        let listener = RuntimeLifecycle()
        guard let ticket = listener.reserve(), listener.markOwned(ticket), listener.markRunning(ticket) else {
            throw FixtureError(text: "cannot establish memory-only companion listener")
        }
        return AppNetworkRuntime(engine: engine, enhancedMode: manager, listenerLifecycle: listener)
    }
    static func verifyRetainedReader(_ manager: EnhancedModeManager, _ engine: ProxyEngine) throws {
        let adapter = try runtime(manager, engine)
        let pendingContext = adapter.context(configuration: configuration)
        try expect(manager.lifecycleSnapshot.isPresent && !manager.lifecycleSnapshot.isReady
                   && pendingContext.backend == .enhanced && !pendingContext.engineRunning,
                   "cleanup-pending owner fell back to an available listener")
        try expect(!HandoffFixture.contains("reader.stop"), "reader closed before network cleanup was verified")
        try expect(HandoffFixture.lock.withLock { HandoffFixture.nativeFD >= 0 }, "prepared reader not retained")
        let prepares = HandoffFixture.count("helper.prepare")
        HandoffFixture.lock.withLock { HandoffFixture.startedResult = nil }
        start(manager, engine)
        try wait { HandoffFixture.lock.withLock { HandoffFixture.startedResult != nil } }
        try assertStartFailed()
        try expect(HandoffFixture.count("helper.prepare") == prepares, "new prepare ran during pending cleanup")
        // Observe at least two real recovery polling turns while the helper
        // still reports pending. Neither may close the packet reader.
        let statusBefore = HandoffFixture.count("helper.status.readonly")
        try wait({ HandoffFixture.count("helper.status.readonly") >= statusBefore + 2 }, timeout: 7)
        try expect(!HandoffFixture.contains("reader.stop"), "a pending status was mistaken for restored routes")
        HandoffFixture.lock.withLock { HandoffFixture.stopShouldFail = false }
        HandoffFixture.completeRecovery()
        // Reader stop is an intermediate event inside queue-owned cleanup;
        // the lifecycle's terminal ACK follows binding/state release. Observe
        // that actual ACK before asserting the adapter's replacement owner.
        try wait({ HandoffFixture.contains("reader.stop") && !manager.lifecycleSnapshot.isPresent }, timeout: 6)
        try expect(before("network.restored", "reader.stop"), "reader closed before explicit recovery confirmation")
        let restoredContext = adapter.context(configuration: configuration)
        try expect(!manager.lifecycleSnapshot.isPresent && restoredContext.backend == .listener,
                   "verified restoration did not release the enhanced owner")
    }
    static func verifyRestartCannotProveRecovery() throws {
        try expect(!HandoffFixture.contains("reader.stop"), "reader closed before simulated helper restart")
        let oldToken = HandoffFixture.snapshot().sessionToken
        try expect(oldToken != nil, "pending recovery did not preserve an owned token")
        HandoffFixture.simulateRestart()
        let afterRestart = HandoffFixture.count("helper.status.readonly")
        try wait({ HandoffFixture.count("helper.status.readonly") >= afterRestart + 2 }, timeout: 9)
        try expect(!HandoffFixture.contains("reader.stop"),
                   "a restarted helper's empty snapshot was mistaken for old-session restoration")
        HandoffFixture.lock.withLock {
            HandoffFixture.state.lastRestoredSessionToken = "a-different-restored-session"
        }
        let afterWrongACK = HandoffFixture.count("helper.status.readonly")
        try wait({ HandoffFixture.count("helper.status.readonly") >= afterWrongACK + 2 }, timeout: 7)
        try expect(!HandoffFixture.contains("reader.stop"),
                   "an unrelated restored-session ACK released the old reader")
        HandoffFixture.lock.withLock { HandoffFixture.stopShouldFail = false }
        HandoffFixture.completeRecovery(restoredSessionToken: oldToken)
        try wait({ HandoffFixture.contains("reader.stop") }, timeout: 6)
        try expect(before("network.restored", "reader.stop"),
                   "the reader was released before its exact restoration ACK")
    }
    static func verifyReloadLifecycle(_ manager: EnhancedModeManager) throws {
        let original = Profile()
        let firstLifecycle = manager.lifecycleSnapshot
        try manager.reload(profile: original, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
        try expect(HandoffFixture.count("helper.reload") == 0 && HandoffFixture.count("router.update") == 0,
                   "equivalent configuration after actual manager start was reloaded")
        try expect(manager.lifecycleSnapshot == firstLifecycle && firstLifecycle.isReady,
                   "equivalent actual owner reload changed the lifecycle epoch")
        var changed = original; changed.dnsPrewarmEnabled = false
        try manager.reload(profile: changed, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
        let changedLifecycle = manager.lifecycleSnapshot
        try expect(changedLifecycle.isReady && changedLifecycle.revision != firstLifecycle.revision
                   && changedLifecycle.sessionID == firstLifecycle.sessionID,
                   "actual owner reload did not change readiness revision within the owned session")
        try expect(HandoffFixture.count("helper.reload") == 1 && HandoffFixture.count("router.update") == 1
                   && HandoffFixture.count("reader.resetFlows") == 1,
                   "real manager did not reload changed configuration exactly once")
        try manager.reload(profile: changed, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
        try expect(manager.lifecycleSnapshot == changedLifecycle,
                   "deduplicated actual owner reload changed readiness/session")
        try expect(HandoffFixture.count("helper.reload") == 1 && HandoffFixture.count("router.update") == 1,
                   "real manager same-configuration reentrant record failed to preserve the new baseline")
        var failed = changed; failed.tunExcludedRoutes = ["192.0.2.0/24"]
        HandoffFixture.failReload = true
        do {
            try manager.reload(profile: failed, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
            throw FixtureError(text: "controlled helper reload failure did not propagate")
        } catch let error as PrivilegedHelperClient.ClientError {
            guard case .helper(let text) = error, text == "expected controlled reload failure" else { throw error }
        }
        let failedLifecycle = manager.lifecycleSnapshot
        try expect(failedLifecycle.isPresent && !failedLifecycle.isReady && failedLifecycle.needsRecovery,
                   "actual partial reload failure left diagnostics ready")
        HandoffFixture.failReload = false
        try manager.reload(profile: changed, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
        try expect(HandoffFixture.count("helper.reload") == 3 && HandoffFixture.count("router.update") == 3
                   && HandoffFixture.count("reader.resetFlows") == 3,
                   "failed actual manager reload made same-baseline recovery a no-op")
        try expect(manager.lifecycleSnapshot.isReady && !manager.lifecycleSnapshot.needsRecovery,
                   "real same-baseline recovery did not restore readiness")
        try manager.reload(profile: changed, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
        try expect(HandoffFixture.count("helper.reload") == 3 && HandoffFixture.count("router.update") == 3,
                   "successful actual manager recovery did not restore reload deduplication")
    }

    /// Drain the owner queue and its already-enqueued status deliveries. This
    /// pumps only Foundation's current run loop, never NSApplication or a view.
    static func synchronize(_ manager: EnhancedModeManager) throws {
        manager.fixtureNetworkBarrier()
        let marker = "memory.main.barrier." + UUID().uuidString
        DispatchQueue.main.async { HandoffFixture.event(marker) }
        try wait { HandoffFixture.contains(marker) }
    }
    static func observePath(_ manager: EnhancedModeManager, available: Bool,
                            gateway: String? = "192.0.2.1") throws {
        HandoffFixture.setNetwork(HandoffFixture.network(available: available, gateway: gateway))
        guard let monitor = NWPathMonitor.latest else { throw FixtureError(text: "Production did not create a memory path monitor") }
        monitor.emit(NWPath(available: available))
        try synchronize(manager)
    }
    static func performPending(_ manager: EnhancedModeManager) throws {
        try expect(manager.fixtureNetworkPendingWork() != nil, "Expected actual debounce work was not scheduled")
        manager.fixtureNetworkPerformPendingWork()
        try synchronize(manager)
    }
    static func monitor(_ manager: EnhancedModeManager) throws {
        let marker = "memory.monitor.barrier." + UUID().uuidString
        manager.fixtureLifecycleMonitor { HandoffFixture.event(marker) }
        try wait { HandoffFixture.contains(marker) }
        try synchronize(manager)
    }
    static func startNetworkOwner(_ manager: EnhancedModeManager, _ engine: ProxyEngine) throws {
        let completed = HandoffFixture.count("start.completed")
        HandoffFixture.lock.withLock { HandoffFixture.startedResult = nil }
        start(manager, engine)
        try wait { HandoffFixture.count("start.completed") == completed + 1 }
        try assertStartSucceeded()
        try synchronize(manager)
        try expect(NWPathMonitor.latest != nil && HandoffFixture.contains("observer.state.installed"),
                   "Real startNetworkObservers did not install the memory observation boundaries")
        try expect(manager.lifecycleSnapshot.isReady, "Memory owner was not ready before injected network changes")
    }
    static func expectRetainedOwner(_ manager: EnhancedModeManager, session: UUID,
                                    stoppedReaders: Int = 0, stoppedHelpers: Int = 0) throws {
        try expect(manager.isEnabled && manager.lifecycleSnapshot.isPresent
                   && manager.lifecycleSnapshot.sessionID == session,
                   "Transient physical network loss released or replaced the enhanced owner")
        try expect(HandoffFixture.count("reader.stop") == stoppedReaders
                   && HandoffFixture.count("helper.stop") == stoppedHelpers,
                   "Transient physical network loss tore down capture or its reader")
        try expect(HandoffFixture.lock.withLock { HandoffFixture.nativeFD >= 0 }
                   && ProxyEngine.currentOutboundInterface?.name == "en-fixture",
                   "Offline enhanced mode lost the reader or cleared its physical binding")
    }

    static func requestedPoll(_ manager: EnhancedModeManager) throws {
        let marker = "memory.requested.barrier." + UUID().uuidString
        manager.fixtureRequestedConnectionPoll { HandoffFixture.event(marker) }
        try wait { HandoffFixture.contains(marker) }
        try synchronize(manager)
    }

    static func cleanupPoll(_ manager: EnhancedModeManager) throws {
        let marker = "memory.cleanup.barrier." + UUID().uuidString
        manager.fixtureCleanupRecoveryPoll { HandoffFixture.event(marker) }
        try wait { HandoffFixture.contains(marker) }
        try synchronize(manager)
    }

    static func expectRequestedWait(_ manager: EnhancedModeManager) throws {
        try expect(manager.isRequested && !manager.lifecycleSnapshot.isReady,
                   "Temporary network loss discarded the user's enhanced-mode request")
        #if HAVE_PERSISTENT_ENHANCED_RECOVERY
        try expect(HandoffFixture.count("status.waiting") > 0,
                   "A retained enhanced-mode request did not publish its waiting state")
        #endif
    }

    /// A complete restoration receipt belongs to the old token, never to a
    /// daemon restart or another App. The next start must be a new handoff.
    static func enterRequestedWait(_ manager: EnhancedModeManager,
                                   _ engine: ProxyEngine) throws -> (UUID, String) {
        try startNetworkOwner(manager, engine)
        let session = manager.lifecycleSnapshot.sessionID
        guard let token = HandoffFixture.snapshot().sessionToken else {
            throw FixtureError(text: "No owned Helper token before controlled restoration")
        }
        HandoffFixture.setNetwork(HandoffFixture.network(available: false))
        HandoffFixture.completeRecovery(restoredSessionToken: token)
        try monitor(manager)
        try expectRequestedWait(manager)
        try expect(!manager.lifecycleSnapshot.isPresent && !manager.isEnabled
                   && HandoffFixture.count("reader.stop") == 1,
                   "Verified restoration did not release the obsolete reader before waiting")
        try expect(HandoffFixture.count("helper.prepare") == 1,
                   "An offline recovery attempted a new capture handoff")
        return (session, token)
    }

    static func expectRequestedRestart(_ manager: EnhancedModeManager,
                                       previousSession: UUID?, previousToken: String?,
                                       expectedPrepares: Int = 2) throws {
        try wait({ manager.lifecycleSnapshot.isReady }, timeout: 12)
        try synchronize(manager)
        try expect(manager.isRequested && manager.isEnabled,
                   "Automatic recovery did not retain the user's request and actual running state")
        if let previousSession {
            try expect(manager.lifecycleSnapshot.sessionID != previousSession,
                       "A destroyed capture session was incorrectly revived instead of replaced")
        }
        if let previousToken {
            try expect(HandoffFixture.snapshot().sessionToken != previousToken,
                       "Automatic recovery reused the restored Helper session token")
        }
        try expect(HandoffFixture.count("helper.prepare") == expectedPrepares
                   && HandoffFixture.count("stage.installation") == 1,
                   "Automatic recovery duplicated prepare or repeated installation/authorization")
        let tail = HandoffFixture.lock.withLock { () -> [String] in
            guard let position = HandoffFixture.events.lastIndex(of: "helper.prepare") else { return [] }
            return Array(HandoffFixture.events[position...])
        }
        let boundaries = ["helper.prepare", "reader.start", "reader.ready", "helper.commit", "status.running"]
        let positions = boundaries.compactMap { tail.firstIndex(of: $0) }
        try expect(positions.count == boundaries.count && positions == positions.sorted(),
                   "Automatic recovery captured traffic before its new packet reader was ready")
    }

    static func finishRequested(_ manager: EnhancedModeManager, _ engine: ProxyEngine) throws {
        let stopped = HandoffFixture.count("stop.completed")
        stop(manager, engine)
        try expect(!manager.isRequested, "Explicit stop did not synchronously revoke the persistent request")
        try wait { HandoffFixture.count("stop.completed") == stopped + 1 }
        try expect(!manager.lifecycleSnapshot.isPresent && !manager.lifecycleSnapshot.isReady,
                   "Explicit stop left the restored enhanced owner present")
    }

    static func runRequested(_ name: String, _ manager: EnhancedModeManager,
                             _ engine: ProxyEngine) throws {
        // The original cold-request cases wait for real automatic reconnects
        // (including their five-second throttle). Only the existing live
        // same-session case explicitly delivers pending work by hand.
        if name != "requested-same-session-offline" {
            HandoffFixture.lock.withLock { HandoffFixture.holdScheduledRebinds = false }
        }
        if name == "requested-reconnect-throttle" {
            HandoffFixture.lock.withLock { HandoffFixture.preparePhysicalNetworkNotReadyCount = 1 }
            start(manager, engine)
            try wait { HandoffFixture.contains("start.completed") }
            try assertStartFailed()
            try expectRequestedWait(manager)
            try expect(HandoffFixture.count("helper.prepare") == 1,
                       "Controlled first cold session did not reach preparation")
            HandoffFixture.lock.withLock { HandoffFixture.holdScheduledRebinds = false }
            try observePath(manager, available: false)
            try observePath(manager, available: true)
            guard let path = NWPathMonitor.latest else { throw FixtureError(text: "No cold recovery monitor") }
            for _ in 0..<500 { path.emit(NWPath(available: true)) }
            try synchronize(manager)
            RunLoop.current.run(until: Date().addingTimeInterval(0.25))
            let delays = HandoffFixture.lock.withLock { HandoffFixture.scheduledRebindDelays }
            try expect(!delays.isEmpty && delays.allSatisfy { $0 > 4.0 && $0 <= 5.0 }
                       && HandoffFixture.count("helper.prepare") == 1
                       && HandoffFixture.count("reader.start") == 0,
                       "Fast live recovery removed the five-second throttle for full cold sessions")
            try finishRequested(manager, engine)
            return
        }
        if name == "requested-same-session-offline" {
            try startNetworkOwner(manager, engine)
            let previous = manager.lifecycleSnapshot.sessionID
            let token = HandoffFixture.snapshot().sessionToken
            try observePath(manager, available: false)
            try performPending(manager)
            try expectRequestedWait(manager)
            try expectRetainedOwner(manager, session: previous)
            try observePath(manager, available: true)
            try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady && manager.isRequested
                       && manager.lifecycleSnapshot.sessionID == previous
                       && HandoffFixture.snapshot().sessionToken == token
                       && HandoffFixture.count("helper.prepare") == 1,
                       "Surviving offline tunnel was replaced instead of rebound within its owned session")
            try finishRequested(manager, engine)
            return
        }
        if name == "requested-initial-offline" {
            HandoffFixture.setNetwork(HandoffFixture.network(available: false))
            start(manager, engine)
            try wait { HandoffFixture.contains("start.completed") }
            try assertStartFailed()
            try expectRequestedWait(manager)
            try expect(!manager.lifecycleSnapshot.isPresent
                       && HandoffFixture.count("helper.prepare") == 0
                       && HandoffFixture.count("reader.start") == 0,
                       "Initial offline request prepared capture or pretended to own a tunnel")
            HandoffFixture.setNetwork(HandoffFixture.network())
            try requestedPoll(manager)
            try expectRequestedRestart(manager, previousSession: nil, previousToken: nil, expectedPrepares: 1)
            try finishRequested(manager, engine)
            return
        }

        if name == "requested-cleanup-ack" {
            try startNetworkOwner(manager, engine)
            let previous = manager.lifecycleSnapshot.sessionID
            guard let token = HandoffFixture.snapshot().sessionToken else {
                throw FixtureError(text: "No initial cleanup token")
            }
            HandoffFixture.setNetwork(HandoffFixture.network(available: false))
            HandoffFixture.makePending()
            try monitor(manager)
            try expect(manager.isRequested && manager.lifecycleSnapshot.isPresent
                       && HandoffFixture.count("reader.stop") == 0,
                       "Unconfirmed old capture lost its reader or the user's persistent request")
            try requestedPoll(manager); try cleanupPoll(manager)
            HandoffFixture.simulateRestart()
            try cleanupPoll(manager); try requestedPoll(manager)
            HandoffFixture.lock.withLock { HandoffFixture.state.lastRestoredSessionToken = "foreign-restored-token" }
            try cleanupPoll(manager); try requestedPoll(manager)
            try expect(HandoffFixture.count("reader.stop") == 0
                       && HandoffFixture.count("helper.prepare") == 1,
                       "An empty or foreign restoration snapshot authorized a replacement capture")
            HandoffFixture.completeRecovery(restoredSessionToken: token)
            try cleanupPoll(manager)
            try expectRequestedWait(manager)
            try expect(HandoffFixture.count("reader.stop") == 1 && !manager.lifecycleSnapshot.isPresent,
                       "Exact old-token cleanup ACK did not release only the obsolete capture")
            HandoffFixture.setNetwork(HandoffFixture.network())
            try requestedPoll(manager)
            try expectRequestedRestart(manager, previousSession: previous, previousToken: token)
            try finishRequested(manager, engine)
            return
        }

        let (previous, token) = try enterRequestedWait(manager, engine)
        switch name {
        case "requested-restored-offline":
            for _ in 0..<5 { try requestedPoll(manager) }
            try expectRequestedWait(manager)
            try expect(HandoffFixture.count("helper.prepare") == 1,
                       "Repeated offline checks attempted new Helper capture")
            HandoffFixture.setNetwork(HandoffFixture.network())
            try requestedPoll(manager)
            try expectRequestedRestart(manager, previousSession: previous, previousToken: token)

        case "requested-prepare-network-wait":
            HandoffFixture.lock.withLock { HandoffFixture.preparePhysicalNetworkNotReadyCount = 1 }
            HandoffFixture.setNetwork(HandoffFixture.network())
            try requestedPoll(manager)
            try wait { HandoffFixture.contains("helper.prepare.physical-not-ready") }
            try synchronize(manager)
            try expectRequestedWait(manager)
            try expect(HandoffFixture.count("reader.start") == 1
                       && HandoffFixture.count("helper.commit") == 1,
                       "A deferred Helper preparation created or committed an incomplete reader")
            try requestedPoll(manager)
            try expectRequestedRestart(manager, previousSession: previous, previousToken: token, expectedPrepares: 3)

        case "requested-prepare-fatal-pause":
            HandoffFixture.lock.withLock { HandoffFixture.failPrepare = true }
            HandoffFixture.setNetwork(HandoffFixture.network())
            try requestedPoll(manager)
            try wait { HandoffFixture.contains("helper.prepare.fatal") }
            try synchronize(manager)
            for _ in 0..<10 { try requestedPoll(manager) }
            try expect(manager.isRequested && !manager.lifecycleSnapshot.isPresent
                       && !manager.lifecycleSnapshot.isReady
                       && HandoffFixture.count("helper.prepare") == 2
                       && manager.fixtureNetworkPendingWork() == nil,
                       "A preparation error requiring manual attention entered an automatic capture restart loop")

        case "requested-foreign-session":
            HandoffFixture.lock.withLock {
                HandoffFixture.state = HajimiHelperTunnelState(running: true, phase: .running,
                    sessionToken: "foreign-running-token", tunnelInterface: "utun-foreign",
                    physicalInterface: "en-fixture")
            }
            HandoffFixture.setNetwork(HandoffFixture.network())
            let helperStops = HandoffFixture.count("helper.stop")
            for _ in 0..<5 { try requestedPoll(manager) }
            try expect(manager.isRequested && !manager.lifecycleSnapshot.isReady
                       && HandoffFixture.count("helper.prepare") == 1
                       && HandoffFixture.count("helper.stop") == helperStops
                       && HandoffFixture.snapshot().sessionToken == "foreign-running-token",
                       "Automatic recovery stopped, adopted or prepared over another App's Helper session")

        case "requested-stop-waiting", "requested-shutdown-waiting":
            let previousPath = NWPathMonitor.latest?.capturedDelivery(NWPath(available: true))
            let previousWake = NSWorkspace.shared.notificationCenter.capturedCallbacks
            if name == "requested-stop-waiting" { try finishRequested(manager, engine) }
            else {
                manager.shutdownForQuit()
                try expect(!manager.isRequested, "Quit retained authority to reopen enhanced capture")
            }
            HandoffFixture.setNetwork(HandoffFixture.network())
            previousPath?(); MemoryWorkspaceNotificationCenter.deliver(previousWake)
            for _ in 0..<5 { try requestedPoll(manager) }
            try expect(!manager.isRequested && !manager.lifecycleSnapshot.isPresent
                       && HandoffFixture.count("helper.prepare") == 1
                       && HandoffFixture.count("reader.start") == 1
                       && HandoffFixture.count("status.running") == 1,
                       "A late physical-network event reopened explicitly disabled enhanced mode")
            return

        case "requested-stop-bypass":
            HandoffFixture.lock.withLock { HandoffFixture.holdBypassResults = true }
            HandoffFixture.setNetwork(HandoffFixture.network())
            try requestedPoll(manager)
            try wait { HandoffFixture.count("bypass.held") == 1 }
            try finishRequested(manager, engine)
            HandoffFixture.releaseBypassResults()
            try synchronize(manager)
            for _ in 0..<3 { try requestedPoll(manager) }
            try expect(!manager.isRequested && !manager.lifecycleSnapshot.isPresent
                       && HandoffFixture.count("helper.prepare") == 1
                       && HandoffFixture.count("reader.start") == 1
                       && HandoffFixture.count("status.running") == 1,
                       "A late bypass resolution prepared capture after automatic recovery was cancelled")
            return

        case "requested-stop-prepare", "requested-stop-reader", "requested-stop-commit":
            let stage = String(name.dropFirst("requested-stop-".count))
            let previousStages = HandoffFixture.count("stage.\(stage)")
            HandoffFixture.lock.withLock { HandoffFixture.blockedStage = stage }
            HandoffFixture.setNetwork(HandoffFixture.network())
            manager.fixtureRequestedConnectionPoll { HandoffFixture.event("requested.blocked.poll.completed") }
            try wait { HandoffFixture.count("stage.\(stage)") == previousStages + 1 }
            stop(manager, engine)
            try expect(!manager.isRequested && !manager.lifecycleSnapshot.isReady,
                       "Manual stop failed to revoke a blocked automatic restart synchronously")
            HandoffFixture.releaseStage.signal()
            try wait { HandoffFixture.count("stop.completed") == 1 }
            for _ in 0..<3 { try requestedPoll(manager) }
            try expect(!manager.lifecycleSnapshot.isPresent
                       && HandoffFixture.count("helper.prepare") == 2
                       && HandoffFixture.count("status.running") == 1
                       && HandoffFixture.count("helper.commit") == (stage == "commit" ? 2 : 1),
                       "A cancelled restart crossed capture readiness or reappeared after its late completion")
            if HandoffFixture.preparedFD >= 0 {
                try expect(fcntl(HandoffFixture.preparedFD, F_GETFD) == -1 && errno == EBADF,
                           "Cancelled automatic restart leaked its ordinary handed-off descriptor")
            }
            return

        case "requested-latest-configuration":
            var first = Profile(); first.tunExcludedRoutes = ["203.0.113.0/24"]
            var newest = first; newest.tunExcludedRoutes = ["198.51.100.0/24"]
            try manager.reload(profile: first, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
            try manager.reload(profile: newest, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
            HandoffFixture.lock.withLock { HandoffFixture.bypassAddresses = ["192.0.2.103"] }
            HandoffFixture.setNetwork(HandoffFixture.network())
            try requestedPoll(manager)
            try expectRequestedRestart(manager, previousSession: previous, previousToken: token)
            try expect(HandoffFixture.lock.withLock {
                HandoffFixture.preparedExcludedRoutes.last == newest.tunExcludedRoutes
                    && HandoffFixture.createdRouterExcludedRoutes.last == newest.tunExcludedRoutes
                    && HandoffFixture.collectedExcludedRoutes.last == newest.tunExcludedRoutes
                    && HandoffFixture.preparedBypassRequests.last == ["192.0.2.103"]
            }, "Restart used obsolete routing or bypass data instead of the latest requested configuration")

        case "requested-late-configuration":
            HandoffFixture.lock.withLock { HandoffFixture.holdBypassResults = true }
            HandoffFixture.setNetwork(HandoffFixture.network())
            try requestedPoll(manager)
            try wait { HandoffFixture.count("bypass.held") == 1 }
            var newest = Profile(); newest.tunExcludedRoutes = ["198.51.100.0/24"]
            try manager.reload(profile: newest, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
            HandoffFixture.lock.withLock { HandoffFixture.bypassAddresses = ["192.0.2.104"] }
            HandoffFixture.releaseBypassResults()
            try synchronize(manager)
            try requestedPoll(manager)
            try expectRequestedRestart(manager, previousSession: previous, previousToken: token)
            try expect(HandoffFixture.lock.withLock {
                HandoffFixture.preparedExcludedRoutes.last == newest.tunExcludedRoutes
                    && HandoffFixture.createdRouterExcludedRoutes.last == newest.tunExcludedRoutes
                    && HandoffFixture.preparedBypassRequests.last == ["192.0.2.104"]
            }, "A superseded asynchronous bypass completion applied old settings during restart")

        case "requested-notification-burst":
            HandoffFixture.lock.withLock { HandoffFixture.holdBypassResults = true }
            HandoffFixture.setNetwork(HandoffFixture.network())
            for _ in 0..<100 { try requestedPoll(manager) }
            try wait { HandoffFixture.count("bypass.held") == 1 }
            try expect(HandoffFixture.count("helper.prepare") == 1,
                       "Repeated recovery polls duplicated an in-flight asynchronous prepare")
            HandoffFixture.releaseBypassResults()
            try expectRequestedRestart(manager, previousSession: previous, previousToken: token)
            for _ in 0..<100 { try requestedPoll(manager) }
            try expect(HandoffFixture.count("helper.prepare") == 2,
                       "Repeated recovery polls restarted an already ready enhanced session")

        default: throw FixtureError(text: "unknown persistent-request scenario: \(name)")
        }
        try finishRequested(manager, engine)
    }

    static func runNetwork(_ name: String, _ manager: EnhancedModeManager, _ engine: ProxyEngine) throws {
        try startNetworkOwner(manager, engine)
        let initial = manager.lifecycleSnapshot
        let flushes = HandoffFixture.count("engine.flush")
        let binds = HandoffFixture.count("engine.bind")
        let prepares = HandoffFixture.count("helper.prepare")

        if name.hasPrefix("network-reconnect-") {
            try runReconnect(name, manager, engine)
            return
        }

        switch name {
        case "network-duplicate-first-frame":
            guard let path = NWPathMonitor.latest else { throw FixtureError(text: "No initial path callback") }
            for _ in 0..<500 { path.emit(NWPath(available: true)) }
            try synchronize(manager)
            try expect(manager.fixtureNetworkPendingWork() == nil
                       && HandoffFixture.count("engine.flush") == flushes
                       && HandoffFixture.count("engine.bind") == binds
                       && HandoffFixture.count("helper.reload") == 0,
                       "Equivalent first/path frames flushed DNS, rebound or postponed work")
            try expect(manager.lifecycleSnapshot == initial, "Equivalent first/path frames revoked readiness")

        case "network-first-frame-offline":
            try observePath(manager, available: false)
            try performPending(manager)
            try expectRetainedOwner(manager, session: initial.sessionID)
            try expect(HandoffFixture.count("engine.flush") == flushes + 1
                       && HandoffFixture.count("helper.reload") == 0,
                       "Real first offline frame was ignored or attempted offline route mutation")
            try observePath(manager, available: true); try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady, "First-frame loss did not recover on the same physical identity")

        case "network-offline-online-debounce":
            try observePath(manager, available: false)
            guard let offline = manager.fixtureNetworkPendingWork() else { throw FixtureError(text: "Offline frame lacked debounce work") }
            try observePath(manager, available: true)
            manager.fixtureNetworkRunStale(offline)
            try expect(HandoffFixture.count("engine.flush") == flushes, "Cancelled offline work ran before the current recovered action")
            try performPending(manager)
            try expectRetainedOwner(manager, session: initial.sessionID)
            try expect(manager.lifecycleSnapshot.isReady && HandoffFixture.count("helper.reload") == 1
                       && HandoffFixture.count("engine.flush") == flushes + 1,
                       "Same-interface/IP recovery inside debounce lost its unavailable latch or ran twice")

        case "network-offline-online-after-debounce":
            try observePath(manager, available: false); try performPending(manager)
            try expectRetainedOwner(manager, session: initial.sessionID)
            try expect(HandoffFixture.count("helper.reload") == 0 && manager.fixtureNetworkPendingWork() != nil,
                       "Offline action mutated helper routes or lost its bounded readiness probe")
            try observePath(manager, available: true); try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady && !manager.lifecycleSnapshot.needsRecovery
                       && HandoffFixture.count("helper.reload.applied") == 1,
                       "Same-interface/IP recovery after an offline action did not restore the current owner")

        case "network-offline-bypass":
            // No path callback: the periodic operation must inspect current
            // physical state itself, rather than relying on a recent event.
            let collections = HandoffFixture.count("bypass.collect")
            HandoffFixture.setNetwork(HandoffFixture.network(available: false))
            HandoffFixture.lock.withLock {
                HandoffFixture.bypassAddresses = ["192.0.2.100"]
                HandoffFixture.holdBypassResults = true
            }
            manager.fixtureLifecycleRefreshBypass(); try synchronize(manager)
            try expect(HandoffFixture.count("bypass.collect") == collections
                       && HandoffFixture.count("helper.reload") == 0,
                       "Periodic bypass work started a resolution or helper reload while the physical network was offline")
            HandoffFixture.releaseBypassResults()

        case "network-offline-bypass-late-result":
            HandoffFixture.lock.withLock {
                HandoffFixture.bypassAddresses = ["192.0.2.100"]
                HandoffFixture.holdBypassResults = true
            }
            manager.fixtureLifecycleRefreshBypass(); try synchronize(manager)
            try expect(HandoffFixture.count("bypass.held") == 1, "Online bypass result was not held at the actual callback boundary")
            try observePath(manager, available: false)
            // Do not execute offline debounce: its generation invalidation
            // would mask the separate callback-side physical readiness guard.
            HandoffFixture.releaseBypassResults(); try synchronize(manager)
            try expect(HandoffFixture.count("helper.reload") == 0,
                       "A DNS result admitted online mutated helper routes after physical loss")
            try performPending(manager)
            try expectRetainedOwner(manager, session: initial.sessionID)

        case "network-bypass-preflight-recovery":
            HandoffFixture.lock.withLock {
                HandoffFixture.bypassAddresses = ["192.0.2.100"]
                HandoffFixture.physicalNetworkNotReady = true
            }
            manager.fixtureLifecycleRefreshBypass()
            try wait { HandoffFixture.count("helper.reload.physical-not-ready") == 1 }
            try synchronize(manager)
            try expectRetainedOwner(manager, session: initial.sessionID)
            try expect(HandoffFixture.count("status.failed") == 0
                       && manager.fixtureNetworkPendingWork() != nil
                       && manager.lifecycleSnapshot.needsRecovery,
                       "Deferred bypass preflight lost its recovery work or reported a terminal failure")
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = false }
            try performPending(manager)
            try wait {
                HandoffFixture.lock.withLock { HandoffFixture.helperBypassRequests.last == ["192.0.2.100"] }
                    && manager.lifecycleSnapshot.isReady
            }
            try expect(!manager.lifecycleSnapshot.needsRecovery
                       && HandoffFixture.count("helper.reload.applied") >= 1,
                       "Actual bypass preflight recovery did not reconcile current routes")

        case "network-dhcp-late-gateway":
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = true }
            try observePath(manager, available: true, gateway: nil); try performPending(manager)
            try expectRetainedOwner(manager, session: initial.sessionID)
            try expect(HandoffFixture.count("helper.reload.physical-not-ready") == 1
                       && HandoffFixture.count("helper.reload.applied") == 0
                       && HandoffFixture.count("status.failed") == 0,
                       "Missing DHCP gateway was treated as destructive failure or emitted terminal failure")
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = false }
            HandoffFixture.setNetwork(HandoffFixture.network(gateway: "192.0.2.254"))
            try monitor(manager); try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady && HandoffFixture.count("helper.reload.applied") == 1,
                       "Healthy monitor did not observe the late DHCP gateway without another path notification")

        case "network-health-retry":
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = true }
            try observePath(manager, available: true, gateway: "192.0.2.2"); try performPending(manager)
            let failedFlushes = HandoffFixture.count("engine.flush")
            try expect(!manager.lifecycleSnapshot.isReady && manager.lifecycleSnapshot.needsRecovery
                       && HandoffFixture.count("status.failed") == 0,
                       "Recoverable preflight failure lost its retry state or emitted terminal failure")
            guard let path = NWPathMonitor.latest else { throw FixtureError(text: "No path monitor for duplicate recovery notifications") }
            let readinessProbe = manager.fixtureNetworkPendingWork()
            for _ in 0..<500 { path.emit(NWPath(available: true)) }
            try synchronize(manager)
            try expect(readinessProbe != nil && manager.fixtureNetworkPendingWork() === readinessProbe
                       && HandoffFixture.count("helper.reload") == 1,
                       "Equivalent notifications busy-looped or postponed a bounded readiness probe")
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = false }
            try monitor(manager)
            try expect(!manager.lifecycleSnapshot.isReady && manager.fixtureNetworkPendingWork() != nil,
                       "Healthy heartbeat erased recovery before scheduling its actual retry")
            let pending = manager.fixtureNetworkPendingWork()
            try monitor(manager)
            try expect(manager.fixtureNetworkPendingWork() === pending, "Another monitor turn duplicated or postponed the bounded retry")
            try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady && HandoffFixture.count("helper.reload") == 2
                       && HandoffFixture.count("engine.flush") == failedFlushes,
                       "Health retry failed to recover or repeatedly invalidated fresh DNS work")

        case "network-health-detects-recovery":
            try observePath(manager, available: false); try performPending(manager)
            try expectRetainedOwner(manager, session: initial.sessionID)
            HandoffFixture.setNetwork(HandoffFixture.network())
            try monitor(manager)
            try expect(manager.fixtureNetworkPendingWork() != nil,
                       "Healthy monitor depended on another path notification to notice same-IP online recovery")
            try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady && HandoffFixture.count("helper.reload.applied") == 1,
                       "Monitor-discovered recovery did not complete a real rebind")

        case "network-pending-configuration-recovery":
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = true }
            var first = Profile(); first.tunExcludedRoutes = ["203.0.113.0/24"]
            var newest = first; newest.tunExcludedRoutes = ["198.51.100.0/24"]
            for desired in [first, newest] {
                do {
                    try manager.reload(profile: desired, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
                } catch let error as PrivilegedHelperClient.ClientError {
                    guard case .physicalNetworkNotReady = error else { throw error }
                }
            }
            try synchronize(manager)
            try expectRetainedOwner(manager, session: initial.sessionID)
            try expect(manager.lifecycleSnapshot.needsRecovery && !manager.lifecycleSnapshot.isReady
                       && manager.fixtureAppliedExcludedRoutes() == []
                       && HandoffFixture.count("helper.reload.applied") == 0,
                       "A deferred configuration was published as applied before helper routes committed")
            guard let superseded = manager.fixtureNetworkPendingWork() else {
                throw FixtureError(text: "Deferred configurations lost their pending recovery")
            }
            let deferredReloads = HandoffFixture.count("helper.reload")
            manager.fixtureNetworkRunStale(superseded)
            let latestWork = manager.fixtureNetworkPendingWork()
            try expect(latestWork != nil && latestWork !== superseded
                       && HandoffFixture.count("helper.reload") == deferredReloads,
                       "Superseded configuration work did not hand off to fresh authority without mutating Helper")
            manager.fixtureNetworkRunStale(superseded)
            try expect(manager.fixtureNetworkPendingWork() === latestWork
                       && HandoffFixture.count("helper.reload") == deferredReloads,
                       "Repeated old configuration delivery consumed the new recovery ticket")
            HandoffFixture.lock.withLock {
                HandoffFixture.physicalNetworkNotReady = false
                HandoffFixture.bypassAddresses = ["192.0.2.102"]
            }
            try monitor(manager); try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady && !manager.lifecycleSnapshot.needsRecovery
                       && manager.fixtureAppliedExcludedRoutes() == newest.tunExcludedRoutes,
                       "Network recovery confirmed old applied configuration instead of the latest desired settings")
            try expect(HandoffFixture.lock.withLock {
                HandoffFixture.routerExcludedRoutes.last == newest.tunExcludedRoutes
                    && HandoffFixture.helperExcludedRoutes.last == newest.tunExcludedRoutes
                    && HandoffFixture.collectedExcludedRoutes.last == newest.tunExcludedRoutes
                    && HandoffFixture.helperBypassRequests.last == ["192.0.2.102"]
            }, "Recovery did not reconcile the current desired router profile and freshly collected helper bypass routes")

        case "network-stale-work-and-path", "network-stale-wake":
            guard let previousMonitor = NWPathMonitor.latest else { throw FixtureError(text: "No observer to retain") }
            let oldPath = previousMonitor.capturedDelivery(NWPath(available: false))
            let oldWake = NSWorkspace.shared.notificationCenter.capturedCallbacks
            try observePath(manager, available: true, gateway: "192.0.2.2")
            guard let oldWork = manager.fixtureNetworkPendingWork() else { throw FixtureError(text: "No pending work to cancel across sessions") }
            stop(manager, engine); try wait { HandoffFixture.count("stop.completed") == 1 }
            HandoffFixture.setNetwork(HandoffFixture.network())
            try startNetworkOwner(manager, engine)
            let replacement = manager.lifecycleSnapshot
            let replacementFlushes = HandoffFixture.count("engine.flush")
            let replacementBinds = HandoffFixture.count("engine.bind")
            if name == "network-stale-work-and-path" {
                oldPath(); manager.fixtureNetworkRunStale(oldWork)
            } else {
                MemoryWorkspaceNotificationCenter.deliver(oldWake)
            }
            try synchronize(manager)
            try expect(replacement.sessionID != initial.sessionID && manager.lifecycleSnapshot == replacement
                       && HandoffFixture.count("engine.flush") == replacementFlushes
                       && HandoffFixture.count("engine.bind") == replacementBinds
                       && HandoffFixture.count("helper.reload") == 0 && manager.fixtureNetworkPendingWork() == nil,
                       "Old path, wake or debounce callback mutated a replacement enhanced session")

        case "network-user-stop-fences":
            guard let path = NWPathMonitor.latest else { throw FixtureError(text: "No observer before explicit stop") }
            let oldPath = path.capturedDelivery(NWPath(available: true))
            let oldWake = NSWorkspace.shared.notificationCenter.capturedCallbacks
            try observePath(manager, available: false)
            guard let oldWork = manager.fixtureNetworkPendingWork() else { throw FixtureError(text: "No offline work before stop") }
            stop(manager, engine); try wait { HandoffFixture.count("stop.completed") == 1 }
            HandoffFixture.setNetwork(HandoffFixture.network())
            oldPath(); MemoryWorkspaceNotificationCenter.deliver(oldWake)
            manager.fixtureNetworkRunStale(oldWork); try monitor(manager)
            try expect(!manager.isEnabled && !manager.lifecycleSnapshot.isPresent
                       && HandoffFixture.count("helper.prepare") == prepares
                       && HandoffFixture.count("helper.reload") == 0
                       && HandoffFixture.count("reader.start") == 1,
                       "Physical recovery or a late callback automatically reopened explicitly stopped enhanced mode")
            return

        case "network-stop-during-rebind":
            try observePath(manager, available: true, gateway: "192.0.2.2")
            guard let work = manager.fixtureNetworkPendingWork() else { throw FixtureError(text: "No rebind to race against stop") }
            let stages = HandoffFixture.count("stage.binding")
            HandoffFixture.lock.withLock { HandoffFixture.blockedStage = "binding" }
            manager.fixtureNetworkPerform(work) { HandoffFixture.event("network.rebind.late.completed") }
            try wait { HandoffFixture.count("stage.binding") == stages + 1 }
            stop(manager, engine)
            try expect(!manager.lifecycleSnapshot.isReady, "User stop did not synchronously revoke a rebinding owner")
            HandoffFixture.releaseStage.signal()
            try wait { HandoffFixture.contains("network.rebind.late.completed") && HandoffFixture.count("stop.completed") == 1 }
            try synchronize(manager)
            try expect(!manager.lifecycleSnapshot.isPresent && HandoffFixture.count("helper.reload") == 0
                       && HandoffFixture.count("status.running") == 1,
                       "Late outbound binding completion revived or reloaded an explicitly stopped session")
            return

        default: throw FixtureError(text: "unknown network scenario: \(name)")
        }
        let stopped = HandoffFixture.count("stop.completed")
        stop(manager, engine)
        try wait { HandoffFixture.count("stop.completed") == stopped + 1 }
    }

    /// These cases retain the exact production scheduler/rebind bodies. The
    /// first three release real GCD work and measure actual memory-owner
    /// recovery, so a frozen 1.5-second scheduler/5-second fallback cannot pass.
    static func runReconnect(_ name: String, _ manager: EnhancedModeManager,
                             _ engine: ProxyEngine) throws {
        let session = manager.lifecycleSnapshot.sessionID
        let token = HandoffFixture.snapshot().sessionToken
        let flushes = HandoffFixture.count("engine.flush")
        let binds = HandoffFixture.count("engine.bind")
        let prepares = HandoffFixture.count("helper.prepare")

        switch name {
        case "network-reconnect-immediate":
            try observePath(manager, available: false)
            try performPending(manager)
            try expectRetainedOwner(manager, session: session)
            HandoffFixture.lock.withLock { HandoffFixture.holdScheduledRebinds = false }
            let readyAt = ProcessInfo.processInfo.systemUptime
            try observePath(manager, available: true)
            try wait({ HandoffFixture.count("helper.reload.applied") == 1 }, timeout: 0.8,
                     failureMessage: "Ready same-IP event did not restore the existing owner within 800ms; fixed 1.5-second scheduling remains")
            let elapsed = ProcessInfo.processInfo.systemUptime - readyAt
            try expect(elapsed < 0.8 && manager.lifecycleSnapshot.isReady,
                       "Ready same-IP event retained the old fixed 1.5-second wait")
            try expect(HandoffFixture.count("engine.flush") == flushes + 1,
                       "Availability-only recovery repeatedly invalidated the same uplink DNS")
            print("METRIC ready-event-memory-recovery-ms=\(Int(elapsed * 1000))")

        case "network-reconnect-dhcp-probe":
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = true }
            try observePath(manager, available: true, gateway: "192.0.2.2")
            HandoffFixture.lock.withLock { HandoffFixture.holdScheduledRebinds = false }
            try performPending(manager)
            try expect(HandoffFixture.count("helper.reload.physical-not-ready") == 1,
                       "The controlled Helper readiness deferral was not reached")
            let readyAt = ProcessInfo.processInfo.systemUptime
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = false }
            try wait({ HandoffFixture.count("helper.reload.applied") == 1 }, timeout: 0.8,
                     failureMessage: "Explicit Helper readiness deferral did not retry within 800ms without a new event; five-second-only recovery remains")
            try expect(HandoffFixture.count("helper.reload") == 2 && manager.lifecycleSnapshot.isReady
                       && HandoffFixture.count("engine.flush") == flushes + 1,
                       "An explicit DHCP readiness deferral waited for the five-second monitor or flushed DNS twice")
            print("METRIC helper-ready-without-event-memory-recovery-ms=\(Int((ProcessInfo.processInfo.systemUptime - readyAt) * 1000))")

        case "network-reconnect-missing-ready-event":
            try observePath(manager, available: false)
            HandoffFixture.lock.withLock { HandoffFixture.holdScheduledRebinds = false }
            try performPending(manager)
            try expect(HandoffFixture.count("helper.reload") == 0,
                       "Offline probe mutated Helper routes")
            let readyAt = ProcessInfo.processInfo.systemUptime
            HandoffFixture.setNetwork(HandoffFixture.network())
            try wait({ HandoffFixture.count("helper.reload.applied") == 1 }, timeout: 0.8,
                     failureMessage: "Missing ready event was not recovered from a fresh physical snapshot within 800ms; five-second-only polling remains")
            try expect(manager.lifecycleSnapshot.isReady,
                       "A missed ready event could not be recovered by a fresh physical snapshot probe")
            print("METRIC missing-event-memory-recovery-ms=\(Int((ProcessInfo.processInfo.systemUptime - readyAt) * 1000))")

        case "network-reconnect-probe-bound":
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = true }
            try observePath(manager, available: true, gateway: "192.0.2.2")
            try performPending(manager)
            guard let path = NWPathMonitor.latest else { throw FixtureError(text: "No path monitor") }
            for expected in 1...3 {
                let pending = manager.fixtureNetworkPendingWork()
                try expect(pending != nil, "Readiness recovery lost its bounded short probe")
                for _ in 0..<500 { path.emit(NWPath(available: true)) }
                try synchronize(manager)
                try monitor(manager)
                try expect(manager.fixtureNetworkPendingWork() === pending
                           && HandoffFixture.count("helper.reload") == expected,
                           "Duplicate events or a monitor turn replayed/postponed a pending short probe")
                try performPending(manager)
            }
            try expect(manager.fixtureNetworkPendingWork() == nil && HandoffFixture.count("helper.reload") == 4,
                       "Readiness recovery exceeded its three short retries")
            let delays = HandoffFixture.lock.withLock { HandoffFixture.scheduledRebindDelays }
            try expect(delays.count == 4 && abs(delays[0]) < 0.02
                       && abs(delays[1] - 0.15) < 0.02 && abs(delays[2] - 0.4) < 0.02
                       && abs(delays[3] - 1.0) < 0.02,
                       "The exact production scheduler did not apply 0/150/400/1000ms")
            try expect(HandoffFixture.count("engine.flush") == flushes + 1,
                       "Short readiness retries repeatedly invalidated DNS")
            try monitor(manager)
            try expect(manager.fixtureNetworkPendingWork() != nil,
                       "Exhausted short recovery did not fall back to the existing healthy monitor")
            try performPending(manager)
            try expect(manager.fixtureNetworkPendingWork() == nil && HandoffFixture.count("helper.reload") == 5,
                       "The low-frequency monitor silently refilled fast retry allowance")

        case "network-reconnect-offline-probe-bound":
            try observePath(manager, available: false)
            try performPending(manager)
            for _ in 0..<3 { try performPending(manager) }
            try expect(manager.fixtureNetworkPendingWork() == nil && HandoffFixture.count("helper.reload") == 0
                       && HandoffFixture.count("engine.bind") == binds
                       && HandoffFixture.count("engine.flush") == flushes + 1,
                       "Offline probes bound an uplink, touched Helper routes or exceeded their bound")
            try expectRetainedOwner(manager, session: session)

        case "network-reconnect-probe-new-identity":
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = true }
            try observePath(manager, available: true, gateway: "192.0.2.2")
            try performPending(manager)
            guard let oldProbe = manager.fixtureNetworkPendingWork() else { throw FixtureError(text: "No old probe") }
            try observePath(manager, available: true, gateway: "192.0.2.3")
            let current = manager.fixtureNetworkPendingWork()
            manager.fixtureNetworkRunStale(oldProbe)
            try expect(manager.fixtureNetworkPendingWork() === current && HandoffFixture.count("helper.reload") == 1,
                       "A cancelled old probe consumed a newer network identity")
            try performPending(manager)
            try expect(HandoffFixture.count("engine.flush") == flushes + 2,
                       "A different gateway inherited the previous uplink DNS epoch")
            let delay = HandoffFixture.lock.withLock { HandoffFixture.scheduledRebindDelays.last ?? -1 }
            try expect(abs(delay - 0.15) < 0.02, "A true new network identity did not reset the bounded probe budget")
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = false }
            try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady && HandoffFixture.count("engine.flush") == flushes + 2,
                       "The new gateway probe did not recover without another DNS invalidation")

        case "network-reconnect-probe-cancel":
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = true }
            try observePath(manager, available: true, gateway: "192.0.2.2")
            try performPending(manager)
            guard let oldProbe = manager.fixtureNetworkPendingWork() else { throw FixtureError(text: "No probe to cancel") }
            stop(manager, engine); try wait { HandoffFixture.count("stop.completed") == 1 }
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = false }
            manager.fixtureNetworkRunStale(oldProbe)
            try monitor(manager)
            try expect(!manager.isRequested && !manager.lifecycleSnapshot.isPresent
                       && HandoffFixture.count("helper.reload") == 1
                       && HandoffFixture.count("helper.prepare") == prepares,
                       "A cancelled readiness probe reopened explicitly stopped enhanced mode")
            return

        case "network-reconnect-probe-config":
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = true }
            try observePath(manager, available: true, gateway: "192.0.2.2")
            try performPending(manager)
            guard let oldProbe = manager.fixtureNetworkPendingWork() else { throw FixtureError(text: "No probe before new config") }
            var latest = Profile(); latest.tunExcludedRoutes = ["198.51.100.0/24"]
            do {
                try manager.reload(profile: latest, mode: .proxy, globalPolicy: "fixture", groupSelections: [:])
            } catch let error as PrivilegedHelperClient.ClientError {
                guard case .physicalNetworkNotReady = error else { throw error }
            }
            let reloads = HandoffFixture.count("helper.reload")
            manager.fixtureNetworkRunStale(oldProbe)
            let replacement = manager.fixtureNetworkPendingWork()
            try expect(HandoffFixture.count("helper.reload") == reloads && replacement != nil && replacement !== oldProbe,
                       "A superseded probe failed to issue fresh configuration authority without Helper mutation")
            manager.fixtureNetworkRunStale(oldProbe)
            try expect(manager.fixtureNetworkPendingWork() === replacement && HandoffFixture.count("helper.reload") == reloads,
                       "Repeated old probe delivery consumed the replacement configuration ticket")
            try performPending(manager)
            let remainingDelay = HandoffFixture.lock.withLock { HandoffFixture.scheduledRebindDelays.last ?? -1 }
            try expect(abs(remainingDelay - 0.4) < 0.02 && HandoffFixture.count("helper.reload") == reloads + 1,
                       "Configuration authority replacement reset the spent short readiness budget")
            HandoffFixture.lock.withLock { HandoffFixture.physicalNetworkNotReady = false }
            try performPending(manager)
            try expect(manager.lifecycleSnapshot.isReady && manager.fixtureAppliedExcludedRoutes() == latest.tunExcludedRoutes,
                       "Configuration replacement lost its safe recovery of current settings")
            let recovered = HandoffFixture.count("helper.reload")
            manager.fixtureNetworkRunStale(oldProbe)
            try expect(HandoffFixture.count("helper.reload") == recovered,
                       "An already retired configuration probe replayed after successful recovery")

        case "network-reconnect-unknown-failure":
            HandoffFixture.lock.withLock { HandoffFixture.failReload = true }
            try observePath(manager, available: true, gateway: "192.0.2.2")
            try performPending(manager)
            try expect(HandoffFixture.count("helper.reload") == 1 && manager.fixtureNetworkPendingWork() == nil,
                       "An unknown Helper mutation error incorrectly received a fast replay")
            try monitor(manager); try performPending(manager)
            try expect(HandoffFixture.count("helper.reload") == 2 && manager.fixtureNetworkPendingWork() == nil,
                       "A low-frequency failure silently refilled fast readiness permission")
            HandoffFixture.lock.withLock { HandoffFixture.failReload = false }

        case "network-reconnect-single-bind-prewarm":
            try observePath(manager, available: true, gateway: "192.0.2.2")
            try performPending(manager)
            try expect(HandoffFixture.count("engine.bind") == binds + 1 && HandoffFixture.count("router.bind") == 0,
                       "Rebind repeated the shared asynchronous physical-interface resolve")
            try expect(HandoffFixture.count("engine.prewarm.immediate") == 1
                       && HandoffFixture.count("router.prewarm.immediate") == 2,
                       "Committed uplink recovery retained the deferred DNS prewarm")
            try expect(before("helper.reload.applied", "engine.prewarm.immediate"),
                       "DNS prewarm ran before successful Helper route/DNS protection")
            let events = HandoffFixture.lock.withLock { HandoffFixture.events }
            try expect(events.lastIndex(of: "helper.reload.applied")! < events.lastIndex(of: "router.prewarm.immediate")!,
                       "Router DNS prewarm ran before the new protected uplink was confirmed")

        case "network-reconnect-duplicate-ready":
            try observePath(manager, available: true, gateway: "192.0.2.2")
            try performPending(manager)
            guard let path = NWPathMonitor.latest else { throw FixtureError(text: "No path monitor") }
            let stable = manager.lifecycleSnapshot
            for _ in 0..<1_000 { path.emit(NWPath(available: true)) }
            try synchronize(manager)
            try expect(manager.fixtureNetworkPendingWork() == nil && manager.lifecycleSnapshot == stable
                       && HandoffFixture.count("helper.reload") == 1 && HandoffFixture.count("reader.resetFlows") == 1
                       && HandoffFixture.count("engine.flush") == flushes + 1,
                       "Duplicate ready events reopened a completed recovery or cancelled fresh DNS")

        default: throw FixtureError(text: "unknown reconnect scenario: \(name)")
        }
        try expect(manager.lifecycleSnapshot.sessionID == session && HandoffFixture.snapshot().sessionToken == token
                   && HandoffFixture.count("helper.prepare") == prepares && HandoffFixture.count("reader.start") == 1,
                   "Fast recovery replaced its existing token/TUN/packet reader")
        let stopped = HandoffFixture.count("stop.completed")
        stop(manager, engine); try wait { HandoffFixture.count("stop.completed") == stopped + 1 }
    }

    static func run(_ name: String) throws {
        let manager = EnhancedModeManager(applicationSupportDirectory: URL(fileURLWithPath: "/nonexistent/hajimi-fixture"))
        let engine = ProxyEngine()
        manager.onStatus = HandoffFixture.recordStatus
        if name.hasPrefix("requested-") {
            try runRequested(name, manager, engine)
            return
        }
        if name.hasPrefix("network-") {
            try runNetwork(name, manager, engine)
            return
        }
        if name.hasPrefix("stop-") && name != "stop-pending-recovery" && name != "stop-restart-empty-status"
            && name != "stop-reload" {
            let stage = String(name.dropFirst("stop-".count))
            HandoffFixture.blockedStage = stage
            start(manager, engine)
            try wait { HandoffFixture.contains("stage.\(stage)") }
            let adapter = try runtime(manager, engine)
            if ["binding", "prepare", "reader", "commit"].contains(stage) {
                let context = adapter.context(configuration: configuration)
                try expect(manager.state == nil && context.backend == .enhanced && !context.engineRunning
                           && context.boundInterfaceName == "en-fixture",
                           "prepared owner was ready, lost its binding, or fell back while state was nil")
            }
            stop(manager, engine)
            try expect(!manager.lifecycleSnapshot.isReady,
                       "stop did not synchronously revoke the actual enhanced owner")
            HandoffFixture.releaseStage.signal()
            try wait { HandoffFixture.contains("start.completed") && HandoffFixture.contains("stop.completed") }
            try assertStartFailed()
            adapter.observe(enhancedStatus: .running(interface: "stale", physicalInterface: "stale"))
            try expect(!manager.lifecycleSnapshot.isPresent
                       && adapter.context(configuration: configuration).backend == .listener,
                       "late running status revived a verified stopped enhanced owner")
            try expect(HandoffFixture.count("helper.commit") == (stage == "commit" ? 1 : 0),
                       "a cancelled startup crossed the commit boundary")
            if HandoffFixture.contains("reader.start") {
                try expect(before("helper.stop", "reader.stop"), "stop closed reader before removing captured routes")
            }
            if HandoffFixture.preparedFD >= 0 {
                try expect(fcntl(HandoffFixture.preparedFD, F_GETFD) == -1 && errno == EBADF,
                           "cancelled startup leaked its handed-off descriptor")
            }
            return
        }
        if name == "stop-reload" {
            start(manager, engine)
            try wait { HandoffFixture.contains("start.completed") }
            try assertStartSucceeded()
            let adapter = try runtime(manager, engine)
            let original = adapter.context(configuration: configuration)
            let firstOwner = manager.lifecycleSnapshot
            var changed = Profile(); changed.dnsPrewarmEnabled = false
            HandoffFixture.blockedStage = "reload"
            let next = changed
            DispatchQueue.global().async {
                let result = Result { try manager.reload(profile: next, mode: .proxy,
                    globalPolicy: "fixture", groupSelections: [:]) }
                HandoffFixture.lock.withLock { HandoffFixture.reloadResult = result }
                HandoffFixture.event("reload.completed")
            }
            try wait { HandoffFixture.contains("stage.reload") }
            let reloading = adapter.context(configuration: configuration)
            try expect(manager.lifecycleSnapshot.isReloading && reloading.backend == .enhanced
                       && !reloading.engineRunning && reloading.runtimeSessionID != original.runtimeSessionID,
                       "actual blocked reload did not revoke old diagnostics")
            stop(manager, engine)
            try expect(manager.lifecycleSnapshot.phase == .stopping && manager.lifecycleSnapshot.isPresent,
                       "stop during blocked reload did not synchronously retain/revoke the owner")
            HandoffFixture.releaseStage.signal()
            try wait { HandoffFixture.contains("reload.completed") && HandoffFixture.contains("stop.completed") }
            guard case .failure? = HandoffFixture.lock.withLock({ HandoffFixture.reloadResult }) else {
                throw FixtureError(text: "late reload success crossed a stop intent")
            }
            try expect(!manager.lifecycleSnapshot.isPresent && !manager.lifecycleSnapshot.isReady
                       && adapter.context(configuration: configuration).backend == .listener,
                       "cancelled reload revived enhanced readiness or leaked ownership")
            HandoffFixture.blockedStage = nil
            let startCount = HandoffFixture.count("start.completed")
            start(manager, engine)
            try wait { HandoffFixture.count("start.completed") > startCount }
            try assertStartSucceeded()
            let restarted = adapter.context(configuration: configuration)
            try expect(manager.lifecycleSnapshot.isReady && manager.lifecycleSnapshot.sessionID != firstOwner.sessionID
                       && restarted.backend == .enhanced && restarted.runtimeSessionID != original.runtimeSessionID,
                       "same-config actual stop/start reused the previous session")
            let stopCount = HandoffFixture.count("stop.completed")
            stop(manager, engine)
            try wait { HandoffFixture.count("stop.completed") > stopCount }
            return
        }
        if name == "unrelated-reload" {
            var profile = Profile()
            for (index, node) in ["fixture", "A", "B"].enumerated() {
                profile.proxies[node] = ProxyPolicy(name: node, kind: .native,
                    host: "192.0.2.\(10 + index)", port: 443, adapterType: "vmess",
                    parameters: ["uuid": "controlled-memory-fixture"])
            }
            profile.groups["Unused"] = PolicyGroup(name: "Unused", members: ["A", "B"])
            profile.rules = [.init(kind: .final, policy: "fixture", sourceLine: 1)]
            start(manager, engine, profile: profile, selections: ["Unused": "A"])
            try wait { HandoffFixture.contains("start.completed") }
            try assertStartSucceeded()
            let before = manager.lifecycleSnapshot
            try manager.reload(profile: profile, mode: .proxy, globalPolicy: "fixture", groupSelections: ["Unused": "B"])
            try expect(manager.lifecycleSnapshot == before && HandoffFixture.count("helper.reload") == 0
                       && HandoffFixture.count("router.update") == 0 && HandoffFixture.count("reader.resetFlows") == 0,
                       "unrelated metadata-only actual owner reload changed the epoch or external resources")
            stop(manager, engine)
            try wait { HandoffFixture.contains("stop.completed") }
            return
        }
        if ["rebind-recovery", "bypass-recovery", "bypass-stop-reload"].contains(name) {
            start(manager, engine)
            try wait { HandoffFixture.contains("start.completed") }
            try assertStartSucceeded()
            let initial = manager.lifecycleSnapshot
            if name == "rebind-recovery" {
                HandoffFixture.failReload = true
                manager.fixtureLifecycleRebind { HandoffFixture.event("rebind.failed.completed") }
                try wait { HandoffFixture.contains("rebind.failed.completed") }
                let failed = manager.lifecycleSnapshot
                try expect(failed.isPresent && !failed.isReady && failed.needsRecovery
                           && failed.sessionID == initial.sessionID,
                           "actual rebind helper failure did not retain the recovery barrier")
                manager.fixtureLifecycleMonitor { HandoffFixture.event("monitor.after-failure") }
                try wait { HandoffFixture.contains("monitor.after-failure") }
                try expect(!manager.lifecycleSnapshot.isReady && manager.lifecycleSnapshot.needsRecovery,
                           "healthy heartbeat erased a failed physical rebind")
                HandoffFixture.failReload = false
                manager.fixtureLifecycleRebind(retrying: true) { HandoffFixture.event("rebind.recovered.completed") }
                try wait { HandoffFixture.contains("rebind.recovered.completed") }
                try expect(manager.lifecycleSnapshot.isReady && !manager.lifecycleSnapshot.needsRecovery
                           && HandoffFixture.count("helper.reload") == 2,
                           "actual network-gate retry did not execute and confirm real rebind recovery")
            } else {
                manager.fixtureLifecycleRefreshBypass()
                manager.fixtureLifecycleMonitor { HandoffFixture.event("unchanged-bypass.barrier") }
                try wait { HandoffFixture.contains("unchanged-bypass.barrier") }
                try expect(manager.lifecycleSnapshot == initial && HandoffFixture.count("helper.reload") == 0,
                           "periodic unchanged bypass inventory revoked diagnostics or changed routes")
                HandoffFixture.lock.withLock { HandoffFixture.bypassAddresses = ["192.0.2.100"] }
                if name == "bypass-stop-reload" {
                    HandoffFixture.blockedStage = "reload"
                    manager.fixtureLifecycleRefreshBypass()
                    try wait { HandoffFixture.contains("stage.reload") }
                    try expect(manager.lifecycleSnapshot.isReloading && !manager.lifecycleSnapshot.isReady,
                               "actual bypass route mutation did not revoke readiness")
                    stop(manager, engine)
                    try expect(manager.lifecycleSnapshot.phase == .stopping && manager.lifecycleSnapshot.isPresent,
                               "bypass mutation stop did not synchronously revoke/retain owner")
                    HandoffFixture.releaseStage.signal()
                    try wait { HandoffFixture.contains("stop.completed") }
                    try expect(!manager.lifecycleSnapshot.isPresent && !manager.lifecycleSnapshot.isReady,
                               "late bypass reload success revived a stopped session")
                    return
                }
                HandoffFixture.failReload = true
                manager.fixtureLifecycleRefreshBypass()
                try wait { HandoffFixture.count("helper.reload") == 1 && !manager.lifecycleSnapshot.isReloading }
                try expect(manager.lifecycleSnapshot.needsRecovery && !manager.lifecycleSnapshot.isReady,
                           "actual bypass route failure did not retain recovery")
                manager.fixtureLifecycleMonitor { HandoffFixture.event("monitor.after-bypass-failure") }
                try wait { HandoffFixture.contains("monitor.after-bypass-failure") }
                try expect(manager.lifecycleSnapshot.needsRecovery && !manager.lifecycleSnapshot.isReady,
                           "healthy heartbeat erased failed bypass mutation")
                HandoffFixture.failReload = false
                manager.fixtureLifecycleRefreshBypass()
                try wait { HandoffFixture.count("helper.reload") == 2 && manager.lifecycleSnapshot.isReady }
                try expect(!manager.lifecycleSnapshot.needsRecovery,
                           "actual periodic bypass retry did not confirm recovery")
            }
            stop(manager, engine)
            try wait { HandoffFixture.contains("stop.completed") }
            return
        }
        if name == "late-success-cancelled" {
            HandoffFixture.blockedStage = "prepare"
            start(manager, engine)
            try wait { HandoffFixture.contains("stage.prepare") }
            HandoffFixture.releaseStage.signal()
            // Hold the main queue until the real start body has finished and
            // enqueued its completion. The queued DNS operation is a barrier
            // behind that body; its fake router adapter emits an observable
            // event without running a public network query.
            try waitWithoutMainQueue { manager.state != nil }
            manager.flushDNS()
            try waitWithoutMainQueue { HandoffFixture.contains("router.flush") }
            try expect(!HandoffFixture.contains("start.completed"), "fixture failed to hold main completion")
            stop(manager, engine)
            try wait { HandoffFixture.contains("start.completed") && HandoffFixture.contains("stop.completed") }
            try assertStartFailed()
            try expect(before("helper.stop", "reader.stop"), "late cancellation discarded the reader before helper teardown")
            return
        }
        if name == "shutdown-prepare" {
            HandoffFixture.blockedStage = "prepare"
            start(manager, engine)
            try wait { HandoffFixture.contains("stage.prepare") }
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { HandoffFixture.releaseStage.signal() }
            manager.shutdownForQuit()
            try wait { HandoffFixture.contains("start.completed") }
            try assertStartFailed()
            try expect(!HandoffFixture.contains("helper.commit"), "quit allowed blocked prepare to commit")
            return
        }
        switch name {
        case "reader-start-failure": HandoffFixture.failReaderStart = true
        case "reader-ready-failure": HandoffFixture.failReaderReady = true
        case "commit-failure": HandoffFixture.failCommit = true
        case "commit-pending-recovery": HandoffFixture.failCommitWithPendingCleanup = true
        case "commit-restart-empty-status": HandoffFixture.failCommitWithPendingCleanup = true
        default: break
        }
        start(manager, engine)
        try wait { HandoffFixture.contains("start.completed") }
        switch name {
        case "reader-start-failure":
            try assertStartFailed()
            try expect(!HandoffFixture.contains("helper.commit"), "failed reader was committed")
            try expect(HandoffFixture.sentinelFD >= 0 && fcntl(HandoffFixture.sentinelFD, F_GETFD) >= 0,
                       "reader adoption failure closed a reused descriptor twice")
        case "reader-ready-failure":
            try assertStartFailed()
            try expect(!HandoffFixture.contains("helper.commit"), "unacknowledged reader was committed")
            try expect(before("helper.stop", "reader.stop"), "ready failure discarded reader before cleanup")
        case "commit-failure":
            try assertStartFailed()
            try wait { HandoffFixture.contains("reader.stop") }
            try expect(before("reader.ready", "helper.commit") && before("network.restored", "reader.stop"),
                       "commit failure violated reader/route ownership order")
        case "commit-pending-recovery":
            try assertStartFailed()
            try verifyRetainedReader(manager, engine)
        case "commit-restart-empty-status":
            try assertStartFailed()
            try verifyRestartCannotProveRecovery()
        case "running-restart-empty-status":
            // The ordinary initial helper snapshot has no previous ACK. It
            // permits a new owned start, but the same empty state after that
            // helper dies cannot prove restoration of this now-owned tunnel.
            try assertStartSucceeded()
            try verifyRestartCannotProveRecovery()
        case "stop-pending-recovery", "stop-restart-empty-status":
            try assertStartSucceeded()
            HandoffFixture.stopShouldFail = true
            stop(manager, engine)
            try wait { HandoffFixture.contains("stop.completed") }
            guard case .failure? = HandoffFixture.lock.withLock({ HandoffFixture.stoppedResult }) else {
                throw FixtureError(text: "failed helper teardown was reported as successful")
            }
            if name == "stop-restart-empty-status" { try verifyRestartCannotProveRecovery() }
            else { try verifyRetainedReader(manager, engine) }
        case "success":
            try assertStartSucceeded()
            try expect(before("router.prewarm", "helper.commit"), "DNS prewarm was deferred until after traffic capture")
            try expect(before("reader.start", "reader.ready") && before("reader.ready", "helper.commit"),
                       "routes were committed before actual reader readiness")
            try verifyReloadLifecycle(manager)
            stop(manager, engine)
            try wait { HandoffFixture.contains("stop.completed") }
            try expect(before("helper.stop", "reader.stop") && before("reader.stop", "engine.unbind"),
                       "successful teardown did not preserve reader and physical binding until route removal")
        default: throw FixtureError(text: "unknown scenario: \(name)")
        }
        withExtendedLifetime((manager, engine)) {}
    }
    static func main() {
        let name = CommandLine.arguments.dropFirst().first ?? "success"
        do {
            try run(name)
            print("PASS App enhanced handoff: \(name); \(assertions) assertions; memory observers, no system network changes")
            if name.contains("reconnect") {
                let delays = HandoffFixture.lock.withLock { HandoffFixture.scheduledRebindDelays.map { Int(($0 * 1000).rounded()) } }
                print("METRIC scheduled-rebind-delays-ms=\(delays)")
            }
            fflush(stdout)
            // Each scenario is a fresh process. Avoid unrelated ARC/quit work
            // after the explicit tested stop or controlled failure observation.
            _exit(0)
        } catch {
            print("FAIL App enhanced handoff: \(name): \(error.localizedDescription)")
            print(HandoffFixture.lock.withLock { HandoffFixture.events.joined(separator: " -> ") })
            print("METRIC scheduled-rebind-delays-ms=\(HandoffFixture.lock.withLock { HandoffFixture.scheduledRebindDelays.map { Int(($0 * 1000).rounded()) } })")
            fflush(stdout)
            _exit(1)
        }
    }
}

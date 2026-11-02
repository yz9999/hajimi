import Foundation
import HajimiCore
import HajimiRuntime

// The runner inserts exact production Main declarations at the marker below.
// Only resource/UI/rule-preparation boundaries and preferences are in memory.
// No App/Helper, listener, interface lookup, resolver or OS preference is used.
final class UserDefaults {
    static let standard = UserDefaults()
    private var values: [String: Any] = [:]
    func object(forKey key: String) -> Any? { values[key] }
    func bool(forKey key: String) -> Bool { values[key] as? Bool ?? false }
    func set(_ value: Any?, forKey key: String) { values[key] = value }
    func reset() { values = [:] }
}

private struct FixtureError: LocalizedError {
    let text: String
    var errorDescription: String? { text }
}
enum ProxyEngineStatus: Equatable { case stopped, starting, running, failed(String) }
final class FixtureButton {
    enum State { case on, off }
    var state: State = .off
    var isEnabled = true
}
final class FixtureLabel {
    enum Color { case systemRed, systemGreen, secondaryLabelColor }
    var stringValue = ""
    var textColor: Color = .secondaryLabelColor
}
final class NSAlert {
    enum Response { case alertFirstButtonReturn }
    var messageText = "", informativeText = ""
    func addButton(withTitle: String) {}
    func runModal() -> Response { .alertFirstButtonReturn }
}
final class FixtureHelperClient {
    var uninstalls = 0
    func uninstall(completion: @escaping (Result<Void, Error>) -> Void) {
        uninstalls += 1; completion(.success(()))
    }
}
final class ProxyEngine {
    struct RuntimeSnapshot { var status: ProxyEngineStatus }
    var status: ProxyEngineStatus = .stopped
    var onStatus: ((ProxyEngineStatus) -> Void)?
    var starts = 0, stops = 0, updates = 0
    var failStart = false
    var deferReady = false
    var activeHTTPListen = Profile().httpListen
    func stop() { stops += 1; status = .stopped; onStatus?(.stopped) }
    func start(profile: Profile, mode: OutboundMode, globalPolicy: String,
               groupSelections: [String: String]) throws {
        starts += 1
        if failStart { status = .failed("controlled"); throw FixtureError(text: "controlled engine start failure") }
        activeHTTPListen = profile.httpListen
        status = deferReady ? .starting : .running; onStatus?(status)
    }
    func runtimeSnapshot() -> RuntimeSnapshot { RuntimeSnapshot(status: status) }
    func updateRouting(mode: OutboundMode, globalPolicy: String, groupSelections: [String: String]) {
        updates += 1
    }
}
final class ProtocolAdapterManager {
    var preparations = 0, stops = 0
    var failPreparation = false
    func prepare(profile: Profile) throws -> Profile {
        preparations += 1
        if failPreparation { throw FixtureError(text: "controlled adapter failure") }
        return profile
    }
    func stop() { stops += 1 }
}
final class SystemProxyManager {
    var isEnabledByHajimi = false
    var completions: [(Result<Void, Error>) -> Void] = []
    var enables: [(Result<Void, Error>) -> Void] = []
    var enabledAddresses: [ListenAddress] = []
    var repoints: [(Result<Void, Error>) -> Void] = []
    func disable(completion: @escaping (Result<Void, Error>) -> Void) { completions.append(completion) }
    func enable(address: ListenAddress, bypassDomains: [String],
                completion: @escaping (Result<Void, Error>) -> Void) {
        enabledAddresses.append(address); enables.append(completion)
    }
    func repoint(from: ListenAddress, to: ListenAddress,
                 completion: @escaping (Result<Void, Error>) -> Void) { repoints.append(completion) }
    func complete(_ index: Int = 0) {
        isEnabledByHajimi = false
        completions[index](.success(()))
    }
    func completeEnable(_ index: Int = 0) { isEnabledByHajimi = true; enables[index](.success(())) }
    func completeRepoint(_ index: Int = 0) { repoints[index](.success(())) }
}
final class EnhancedModeManager {
    enum Status { case stopped, starting, running(interface: String, physicalInterface: String), stopping, failed(String), waitingForNetwork(String) }
    struct State { var tunnelInterface = "fixture" }
    let lifecycle = RuntimeLifecycle()
    var state: State?
    var isEnabled: Bool { state != nil }
    var isRequested = false
    var lifecycleSnapshot: RuntimeLifecycle.Snapshot { lifecycle.snapshot }
    var starts = 0, stops = 0, reloads = 0
    var reloadModes: [OutboundMode] = []
    private var callbacks: [(Result<State, Error>) -> Void] = []
    var existingCompletions: [(Result<Void, Error>) -> Void] = []
    private var tickets: [RuntimeLifecycle.Ticket] = []
    func prepareExistingSession(engine: ProxyEngine, completion: @escaping (Result<Void, Error>) -> Void) {
        existingCompletions.append(completion)
    }
    func start(profile: Profile, mode: OutboundMode, globalPolicy: String,
               groupSelections: [String: String], engine: ProxyEngine,
               completion: @escaping (Result<State, Error>) -> Void) {
        guard let ticket = lifecycle.reserve() else { completion(.failure(FixtureError(text: "already running"))); return }
        isRequested = true
        starts += 1; callbacks.append(completion); tickets.append(ticket)
        lifecycle.markOwned(ticket)
    }
    func complete(_ index: Int = 0) {
        if lifecycle.isCurrent(tickets[index]) {
            state = State(); lifecycle.markRunning(tickets[index])
        }
        // Deliberately deliver success even after stop to test the App fence.
        callbacks[index](.success(State()))
    }
    func stop(engine: ProxyEngine, completion: @escaping (Result<Void, Error>) -> Void) {
        isRequested = false
        stops += 1
        if let ticket = lifecycle.cancel() { lifecycle.confirmStopped(ticket) }
        state = nil
        completion(.success(()))
    }
    func failForNetwork(_ index: Int = 0) {
        if let ticket = lifecycle.cancel() { lifecycle.confirmStopped(ticket) }
        state = nil
        callbacks[index](.failure(FixtureError(text: "physical network not ready")))
    }
    func reload(profile: Profile, mode: OutboundMode, globalPolicy: String,
                groupSelections: [String: String]) throws { reloads += 1; reloadModes.append(mode) }
}
final class FixtureNetworkRuntime {
    var changes = 0
    func lifecycleDidChange() { changes += 1 }
    func observe(listenerStatus: ProxyEngineStatus) {}
    func observe(enhancedStatus: EnhancedModeManager.Status) {}
    func observe(systemProxyResult: Result<Void, Error>) {}
}

// @INSERT_MAIN_VALUE_DECLARATIONS@

final class MainWindowController: NSObject {
    private let engine = ProxyEngine()
    private let protocolAdapters = ProtocolAdapterManager()
    private let systemProxy = SystemProxyManager()
    private let enhancedMode = EnhancedModeManager()
    private let helperClient = FixtureHelperClient()
    private let listenerLifecycle = RuntimeLifecycle()
    private var listenerTicket: RuntimeLifecycle.Ticket?
    private let enhancedRequestIntent = RuntimeLifecycle()
    private let launchRestoreIntent = RuntimeLifecycle()
    private var launchRestoreTicket: RuntimeLifecycle.Ticket?
    private let networkRuntime = FixtureNetworkRuntime()
    private let routingReloadGate = RoutingReloadGate()
    private var engineStatus: ProxyEngineStatus = .stopped
    private var enhancedActiveConnections = 0
    private var profile = Profile()
    private var resolvedProfile: Profile?
    private var launchProfilePlan = LaunchProfilePlan.ready(Profile())
    private var profileRevision = 1
    private var selectedMode = OutboundMode.proxy
    private var selectedPolicy = "fixture"
    private var groupSelections: [String: String] = [:]
    private let startButton = FixtureButton()
    private let enhancedModeButton = FixtureButton()
    private let helperInstallButton = FixtureButton(), helperUninstallButton = FixtureButton()
    private let helperStatusLabel = FixtureLabel()
    private let systemProxyButton = FixtureButton()
    private let statusLabel = FixtureLabel()
    private let dataPlaneRuntimeValue = FixtureLabel()
    private var pendingSystemProxyRestore = false
    private var staleSystemProxyCleanupAttempted = false
    private var systemProxyRecoveryInFlight = false
    private var systemProxyRebindInFlight = false
    private var systemProxyEnableRequests = 0
    private var systemProxyDisableRequests = 0
    private var systemProxyAppliedAddress: ListenAddress?
    private var systemProxyIsOrWillBeEnabled: Bool { systemProxy.isEnabledByHajimi || pendingSystemProxyRestore }
    private var restoringLaunchSession = true
    private var completedRestores = 0
    private var messages: [String] = []
    private var preparations: [(Result<Profile, Error>) -> Void] = []

    override init() {
        super.init()
        engine.onStatus = { [weak self] in self?.engineStatus = $0 }
    }
    private func prepareRuleSetsInBackground(_ source: Profile,
        completion: @escaping (Result<Profile, Error>) -> Void) { preparations.append(completion) }
    private func refreshRulesPage() {}
    private func refreshSettings() {}
    private func refreshPolicyHealth() {}
    private func refreshRuleSetsAutomatically() {}
    private func refreshStartupSubscriptionsIfNeeded() {}
    private func refreshConnectionStatus() {}
    private func persistEnhancedMode(_ enabled: Bool) { UserDefaults.standard.set(enabled, forKey: "enhancedModeEnabled") }
    private func persistSystemProxy(_ enabled: Bool) { UserDefaults.standard.set(enabled, forKey: "systemProxyEnabled") }
    private func showMessage(title: String, text: String) { messages.append(title + text) }
    private func showError(title: String, error: Error) { messages.append(title + error.localizedDescription) }
    private func apply(status: ProxyEngineStatus) { engineStatus = status }

    // @INSERT_MAIN_LIFECYCLE_DECLARATIONS@

    static func runChecks() throws {
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw FixtureError(text: text) }
        }
        func fresh() -> MainWindowController {
            UserDefaults.standard.reset()
            UserDefaults.standard.set(false, forKey: "systemProxyEnabled")
            return MainWindowController()
        }
        func drainMainQueue() {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        do {
            let owner = fresh()
            owner.systemProxyButton.state = .on; owner.toggleSystemProxy()
            try require(owner.systemProxy.enables.isEmpty && owner.engine.starts == 0
                && owner.preparations.isEmpty && owner.systemProxyButton.state == .off,
                        "system proxy started a disabled local listener or changed OS settings")
            try require(owner.messages.count == 1
                && owner.messages[0].contains("请先开启本地代理")
                && owner.messages[0].contains("设置 → 本地代理"),
                        "disabled local proxy did not explain where to enable HTTP / SOCKS5")
        }
        do {
            let owner = fresh()
            owner.enhancedMode.start(profile: Profile(), mode: .proxy, globalPolicy: "fixture",
                groupSelections: [:], engine: owner.engine) { _ in }
            owner.enhancedMode.complete()
            owner.systemProxyButton.state = .on; owner.toggleSystemProxy()
            try require(owner.enhancedMode.lifecycleSnapshot.isReady && owner.listenerTicket == nil
                && owner.systemProxy.enables.isEmpty && owner.engine.starts == 0
                && owner.messages.count == 1 && owner.systemProxyButton.state == .off,
                        "ready enhanced mode was mistaken for a ready HTTP / SOCKS5 listener")
            owner.enhancedModeButton.state = .off; owner.toggleEnhancedMode()
        }
        do {
            let owner = fresh()
            owner.engine.deferReady = true
            try owner.startEngineThrowing(prepared: Profile())
            let starting = owner.listenerLifecycle.snapshot
            owner.systemProxyButton.state = .on; owner.toggleSystemProxy()
            try require(starting.isPresent && !starting.isReady
                && owner.systemProxy.enables.isEmpty && owner.messages.count == 1
                && owner.systemProxyButton.state == .off,
                        "system proxy pointed at a listener before the actual Core ready callback")
            owner.engine.status = .running
            try require(owner.acceptListenerStatus(.running, sessionID: starting.sessionID),
                        "controlled real listener ready callback was rejected")
            owner.messages.removeAll()
            owner.systemProxyButton.state = .on; owner.toggleSystemProxy()
            try require(owner.systemProxy.enables.count == 1 && owner.messages.isEmpty,
                        "ready HTTP / SOCKS5 listener showed an unnecessary prompt or did not enable system proxy")
            owner.systemProxy.completeEnable()
            try require(owner.systemProxyButton.state == .on && owner.messages.isEmpty
                && owner.systemProxyAppliedAddress == owner.engine.activeHTTPListen
                && owner.systemProxy.enabledAddresses == [owner.engine.activeHTTPListen],
                        "ready system proxy did not use the actual HTTP listen address without prompting")
            owner.disableSystemProxyAndStopEngine(); owner.systemProxy.complete()
            try require(!owner.systemProxy.isEnabledByHajimi && !owner.listenerLifecycle.snapshot.isPresent,
                        "system proxy disable failed to restore before listener cleanup")
        }
        do {
            let owner = fresh()
            owner.startEngine()
            try require(owner.listenerLifecycle.snapshot.startupPending && !owner.listenerLifecycle.snapshot.isPresent
                && owner.preparations.count == 1 && owner.engine.starts == 0, "Main preparation created resources or was not reserved")
            owner.stopProxyEngine()
            let stopped = owner.listenerLifecycle.snapshot
            owner.preparations[0](.success(Profile()))
            try require(owner.engine.starts == 0 && owner.listenerLifecycle.snapshot == stopped,
                        "actual Main stop→late rule completion started the engine")
            owner.startEngine(); owner.preparations[1](.success(Profile()))
            let running = owner.listenerLifecycle.snapshot
            try require(owner.engine.starts == 1 && running.isReady && running.isPresent && !running.startupPending,
                        "actual Main did not mark successful real listener ownership")
            if let ticket = owner.listenerTicket { owner.listenerLifecycle.release(ticket) }
            try require(owner.listenerLifecycle.snapshot == running && owner.listenerLifecycle.reserve() == nil,
                        "startup release freed Main's running session")
            owner.preparations[0](.success(Profile()))
            try require(owner.engine.starts == 1 && owner.listenerLifecycle.snapshot == running,
                        "older preparation touched the replacement listener")
            try owner.startEngineThrowing(prepared: Profile())
            try require(owner.listenerLifecycle.snapshot.isReady && owner.listenerLifecycle.snapshot.sessionID != running.sessionID,
                        "same-configuration programmatic restart reused Main's session")
            owner.stopProxyEngine()
        }
        do {
            let owner = fresh()
            owner.toggleEngine(); owner.startEngine()
            try require(owner.preparations.count == 1 && owner.isEngineActive, "duplicate start reserved multiple preparations")
            owner.toggleEngine(); owner.preparations[0](.success(Profile()))
            try require(owner.engine.starts == 0 && !owner.listenerLifecycle.snapshot.startupPending,
                        "actual toggle failed to stop an engine still preparing rules")
        }
        do {
            let owner = fresh()
            owner.startEngine()
            owner.systemProxy.isEnabledByHajimi = true
            UserDefaults.standard.set(true, forKey: "systemProxyEnabled")
            owner.disableSystemProxyAndStopEngine()
            let stopping = owner.listenerLifecycle.snapshot
            owner.preparations[0](.success(Profile())); owner.startEngine()
            try require(owner.engine.starts == 0 && owner.preparations.count == 1
                && stopping.phase == .stopping && owner.listenerLifecycle.snapshot == stopping,
                        "pending system-proxy restore did not synchronously revoke rule preparation")
            owner.systemProxy.complete()
            try require(owner.listenerLifecycle.snapshot.phase == .stopped && !owner.listenerLifecycle.snapshot.startupPending,
                        "system-proxy restore ACK did not permit actual listener cleanup")
            owner.startEngine(); owner.preparations[1](.success(Profile()))
            try require(owner.listenerLifecycle.snapshot.isReady, "listener failed to restart after restoration/cleanup ACK")
            owner.stopProxyEngine()
        }
        do {
            let owner = fresh()
            owner.startEngine(); owner.profileRevision += 1
            owner.preparations[0](.success(Profile()))
            try require(owner.engine.starts == 0 && !owner.listenerLifecycle.snapshot.startupPending,
                        "changed profile started through an obsolete prepared callback")
            owner.startEngine(); owner.preparations[1](.success(Profile()))
            try require(owner.listenerLifecycle.snapshot.isReady, "stale profile preparation leaked its reservation")
            owner.stopProxyEngine()
        }
        for adapterFailure in [true, false] {
            let owner = fresh()
            owner.protocolAdapters.failPreparation = adapterFailure
            owner.engine.failStart = !adapterFailure
            owner.startEngine(); owner.preparations[0](.success(Profile()))
            try require(owner.listenerLifecycle.snapshot.phase == .failed && !owner.listenerLifecycle.snapshot.isPresent
                && !owner.listenerLifecycle.snapshot.startupPending && owner.protocolAdapters.stops > 0,
                        "actual adapter/listener failure retained resources or lost error state")
            owner.protocolAdapters.failPreparation = false; owner.engine.failStart = false
            owner.startEngine(); owner.preparations[1](.success(Profile()))
            try require(owner.listenerLifecycle.snapshot.isReady, "failed actual start prevented a later valid startup")
            owner.stopProxyEngine()
        }
        do {
            let owner = fresh()
            owner.engine.deferReady = true
            owner.startEngine(); owner.preparations[0](.success(Profile()))
            let preparing = owner.listenerLifecycle.snapshot
            try require(preparing.isPresent && preparing.startupPending && !preparing.isReady
                && preparing.phase == .starting, "NW start return bypassed the actual Core readiness gate")
            owner.selectedMode = .direct
            owner.updateEngineRouting()
            try require(owner.engine.updates == 0 && owner.listenerLifecycle.snapshot == preparing,
                        "starting Core was reloaded before its readiness gate")
            owner.engine.status = .running
            try require(owner.acceptListenerStatus(.running, sessionID: preparing.sessionID)
                && owner.listenerLifecycle.snapshot.isReady && owner.engine.updates == 1,
                        "actual Core ready did not apply the UI selection changed during startup")
            let failure = ProxyEngineStatus.failed("controlled async NW failure")
            owner.engine.status = failure
            try require(owner.acceptListenerStatus(failure, sessionID: preparing.sessionID),
                        "current async Core failure was rejected")
            owner.apply(status: failure)
            try require(!owner.listenerLifecycle.snapshot.isPresent && owner.listenerLifecycle.snapshot.phase == .failed,
                        "Core stop→failed left Main owning resources and blocked retry")
            owner.startEngine()
            let retrying = owner.listenerLifecycle.snapshot
            try require(owner.preparations.count == 2 && retrying.startupPending && !retrying.isPresent,
                        "retry after async failure silently failed to reserve a new start")
            try require(!owner.acceptListenerStatus(failure, sessionID: preparing.sessionID)
                && !owner.acceptListenerStatus(failure, sessionID: retrying.sessionID)
                && owner.listenerLifecycle.snapshot == retrying,
                        "old queued failed freed a replacement rule preparation")
            owner.preparations[1](.success(Profile()))
            let replacement = owner.listenerLifecycle.snapshot
            owner.engine.status = .running
            try require(!owner.acceptListenerStatus(.running, sessionID: preparing.sessionID)
                && owner.acceptListenerStatus(.running, sessionID: replacement.sessionID)
                && owner.listenerLifecycle.snapshot.isReady,
                        "stale ready regained authority or replacement ready was lost")
            owner.stopProxyEngine()
        }
        do {
            let owner = fresh()
            owner.enhancedMode.start(profile: Profile(), mode: .proxy, globalPolicy: "fixture",
                groupSelections: [:], engine: owner.engine) { _ in }
            owner.enhancedMode.complete()
            owner.engine.deferReady = true
            owner.startEngine(); owner.preparations[0](.success(Profile()))
            let preparing = owner.listenerLifecycle.snapshot
            owner.selectedMode = .direct; owner.updateEngineRouting()
            try require(owner.enhancedMode.reloads == 1 && owner.enhancedMode.reloadModes == [.direct]
                && owner.engine.updates == 0 && !owner.listenerLifecycle.snapshot.isReady,
                        "listener startup deferred the independent running TUN selection")
            let failure = ProxyEngineStatus.failed("controlled pending-listener failure")
            owner.engine.status = failure
            try require(owner.acceptListenerStatus(failure, sessionID: preparing.sessionID)
                && owner.enhancedMode.lifecycleSnapshot.isReady && owner.enhancedMode.reloadModes == [.direct],
                        "listener startup failure discarded the already-applied TUN selection")
            owner.stopProxyEngine()
            owner.enhancedModeButton.state = .off; owner.toggleEnhancedMode()
        }
        do {
            let owner = fresh()
            try owner.startEngineThrowing(prepared: Profile())
            owner.systemProxy.isEnabledByHajimi = true
            UserDefaults.standard.set(true, forKey: "systemProxyEnabled")
            owner.disableSystemProxyAndStopEngine(); owner.disableSystemProxyAndStopEngine()
            try require(owner.systemProxy.completions.count == 2, "fixture did not queue duplicate system-proxy stops")
            owner.systemProxy.complete(0)
            owner.startEngine(); owner.preparations[0](.success(Profile()))
            let replacement = owner.listenerLifecycle.snapshot, stops = owner.engine.stops
            owner.systemProxy.complete(1)
            try require(owner.listenerLifecycle.snapshot == replacement && replacement.isReady
                && owner.engine.stops == stops, "second old disable completion stopped the replacement listener")
            owner.stopProxyEngine()
        }
        for terminal in ["ready", "delayed-ready", "delayed-failure"] {
            let delayedReady = terminal != "ready"
            let owner = fresh()
            try owner.startEngineThrowing(prepared: Profile())
            owner.systemProxy.isEnabledByHajimi = true
            UserDefaults.standard.set(true, forKey: "systemProxyEnabled")
            owner.toggleEngine()
            try require(!owner.systemProxyButton.isEnabled && !owner.startButton.isEnabled,
                        "real toggle pending disable did not establish both UI gates")
            owner.engine.deferReady = delayedReady
            try owner.startEngineThrowing(prepared: Profile())
            let replacement = owner.listenerLifecycle.snapshot, stops = owner.engine.stops
            owner.systemProxy.complete()
            try require(owner.listenerLifecycle.snapshot == replacement && owner.engine.stops == stops
                && owner.systemProxyButton.isEnabled && owner.systemProxyButton.state == .off
                && owner.startButton.isEnabled == !delayedReady
                && !UserDefaults.standard.bool(forKey: "systemProxyEnabled"),
                        "single stale disable left controls disabled or stopped the replacement owner")
            if delayedReady {
                if terminal == "delayed-ready" {
                    owner.engine.status = .running
                    try require(owner.acceptListenerStatus(.running, sessionID: replacement.sessionID)
                        && owner.startButton.isEnabled && owner.listenerLifecycle.snapshot.isReady,
                                "replacement Core readiness did not restore the engine button")
                } else {
                    let failure = ProxyEngineStatus.failed("controlled replacement readiness failure")
                    owner.engine.status = failure
                    try require(owner.acceptListenerStatus(failure, sessionID: replacement.sessionID)
                        && owner.startButton.isEnabled && !owner.listenerLifecycle.snapshot.isPresent,
                                "replacement Core failure left the retry button disabled or leaked ownership")
                    owner.apply(status: failure)
                    owner.toggleEngine()
                    try require(owner.preparations.count == 1 && owner.listenerLifecycle.snapshot.startupPending,
                                "real toggle after replacement failure could not retry")
                }
            }
            owner.stopProxyEngine()
        }
        for restore in [false, true] {
            let owner = fresh()
            try owner.startEngineThrowing(prepared: Profile())
            if restore {
                owner.pendingSystemProxyRestore = true; owner.applyPendingSystemProxyRestore()
            } else {
                owner.systemProxyButton.state = .on; owner.toggleSystemProxy()
            }
            try require(owner.systemProxy.enables.count == 1, "actual enable/restore path failed to request the controlled operation")
            try owner.startEngineThrowing(prepared: Profile())
            let replacement = owner.listenerLifecycle.snapshot
            owner.systemProxy.completeEnable()
            try require(!UserDefaults.standard.bool(forKey: "systemProxyEnabled")
                && owner.systemProxy.completions.count == 1 && owner.listenerLifecycle.snapshot == replacement,
                        "stale enable/restore completion persisted a replacement session or failed to restore OS proxy")
            owner.systemProxy.complete()
            owner.stopProxyEngine()
        }
        do {
            let owner = fresh()
            try owner.startEngineThrowing(prepared: Profile())
            owner.systemProxy.isEnabledByHajimi = true
            owner.systemProxyAppliedAddress = ListenAddress(host: "127.0.0.1", port: 12345)
            owner.reconcileSystemProxyListener()
            try require(owner.systemProxy.repoints.count == 1, "actual listener reconcile did not request controlled repoint")
            try owner.startEngineThrowing(prepared: Profile())
            let replacement = owner.listenerLifecycle.snapshot
            owner.systemProxy.completeRepoint()
            try require(!UserDefaults.standard.bool(forKey: "systemProxyEnabled")
                && owner.systemProxy.completions.count == 1 && owner.listenerLifecycle.snapshot == replacement,
                        "old repoint completion adopted a replacement listener")
            owner.systemProxy.complete()
            owner.stopProxyEngine()
        }
        for preparedExisting in [false, true] {
            let owner = fresh()
            owner.prepareLaunchSession()
            try require(owner.restoringLaunchSession && owner.launchRestoreIntent.snapshot.startupPending,
                        "front launch preparation did not retain its restore intent")
            if preparedExisting {
                drainMainQueue()
                try require(owner.enhancedMode.existingCompletions.count == 1,
                            "actual launch preparation did not reach its controlled boundary")
            }
            owner.stopProxyEngine()
            try require(!owner.restoringLaunchSession && owner.launchRestoreTicket == nil
                && !owner.launchRestoreIntent.snapshot.startupPending,
                        "front launch cancellation left the application restoring forever")
            UserDefaults.standard.set(true, forKey: "proxyEngineEnabled")
            owner.startEngine(); owner.preparations[0](.success(Profile()))
            let running = owner.listenerLifecycle.snapshot
            try require(running.isReady && !owner.restoringLaunchSession,
                        "ordinary ready startup after front cancellation retained restore mode")
            if preparedExisting { owner.enhancedMode.existingCompletions[0](.success(())) }
            else { drainMainQueue() }
            try require(owner.listenerLifecycle.snapshot == running && !owner.restoringLaunchSession
                && owner.preparations.count == 1 && owner.engine.starts == 1
                && owner.enhancedMode.existingCompletions.count == (preparedExisting ? 1 : 0),
                        "late front launch callback changed the ordinary ready replacement or restore flag")
            owner.stopProxyEngine()
        }
        do {
            let owner = fresh()
            owner.systemProxy.isEnabledByHajimi = true
            UserDefaults.standard.set(true, forKey: "proxyEngineEnabled")
            owner.restoreLastSession()
            try require(owner.systemProxy.completions.count == 1 && owner.preparations.isEmpty,
                        "launch stale snapshot cleanup did not hold restore before rule preparation")
            owner.stopProxyEngine()
            UserDefaults.standard.set(true, forKey: "proxyEngineEnabled")
            owner.systemProxy.complete()
            try require(owner.preparations.isEmpty && owner.engine.starts == 0,
                        "old launch cleanup completion recursively restarted after user stop")
        }
        do {
            let owner = fresh()
            for (index, node) in ["fixture", "A", "B"].enumerated() {
                owner.profile.proxies[node] = ProxyPolicy(name: node, kind: .native, host: "192.0.2.\(10 + index)",
                    port: 443, adapterType: "vmess", parameters: ["uuid": "memory-only"])
            }
            owner.profile.groups["Unused"] = PolicyGroup(name: "Unused", members: ["A", "B"])
            owner.profile.rules = [.init(kind: .final, policy: "fixture", sourceLine: 1)]
            owner.groupSelections = ["Unused": "A"]
            try owner.startEngineThrowing(prepared: owner.profile)
            let initial = owner.listenerLifecycle.snapshot
            owner.updateEngineRouting()
            owner.groupSelections["Unused"] = "B"; owner.updateEngineRouting()
            try require(owner.engine.updates == 0 && owner.listenerLifecycle.snapshot == initial,
                        "equivalent/unrelated Main routing notification revoked diagnostics or updated resources")
            var changed = owner.profile; changed.dnsPrewarmEnabled = false
            owner.resolvedProfile = changed
            owner.updateEngineRouting()
            try require(owner.engine.updates == 1 && owner.listenerLifecycle.snapshot.isReady
                && owner.listenerLifecycle.snapshot.revision != initial.revision
                && owner.listenerLifecycle.snapshot.sessionID == initial.sessionID,
                        "actual Main routing update did not revise the owned listener")
            let baseline = RoutingReloadGate.Configuration(profile: changed, mode: .proxy,
                globalPolicy: "fixture", groupSelections: owner.groupSelections)
            var failed = baseline; failed.profile.tunExcludedRoutes = ["192.0.2.0/24"]
            var actions = 0
            do {
                try owner.routingReloadGate.apply(failed) {
                    try owner.reloadListener { actions += 1; throw FixtureError(text: "controlled partial reload") }
                }
                throw FixtureError(text: "injected Main reload failure was swallowed")
            } catch let error as FixtureError where error.text == "controlled partial reload" {}
            try require(owner.routingReloadGate.needsRecovery && owner.listenerLifecycle.snapshot.needsRecovery
                && !owner.listenerLifecycle.snapshot.isReady, "actual Main reload wrapper did not retain recovery barrier")
            try owner.routingReloadGate.apply(baseline) { try owner.reloadListener { actions += 1 } }
            try require(actions == 2 && owner.listenerLifecycle.snapshot.isReady && !owner.routingReloadGate.needsRecovery,
                        "real Main gate skipped same-baseline recovery after partial failure")
            let recovered = owner.listenerLifecycle.snapshot
            try owner.routingReloadGate.apply(baseline) { try owner.reloadListener { actions += 1 } }
            try require(actions == 2 && owner.listenerLifecycle.snapshot == recovered,
                        "successful recovery did not restore deduplication")
            do {
                try owner.reloadListener { owner.stopProxyEngine(); try owner.startEngineThrowing(prepared: owner.profile) }
                throw FixtureError(text: "stale actual Main reload completion was accepted")
            } catch let error as ProfileApplyError {
                try require(error.localizedDescription == "代理引擎重载已取消", "wrong stale-reload rejection")
            }
            try require(owner.listenerLifecycle.snapshot.isReady && owner.listenerLifecycle.snapshot.sessionID != recovered.sessionID,
                        "old Main reload completion modified a replacement listener")
            owner.stopProxyEngine()
        }
        do {
            let owner = fresh()
            owner.enhancedModeButton.state = .on; owner.toggleEnhancedMode()
            try require(owner.preparations.count == 1 && owner.enhancedRequestIntent.snapshot.startupPending,
                        "enhanced UI preparation was not reserved")
            owner.enhancedModeButton.state = .off; owner.toggleEnhancedMode()
            owner.preparations[0](.success(Profile()))
            try require(owner.enhancedMode.starts == 0 && !owner.enhancedRequestIntent.snapshot.startupPending,
                        "disabled-button stop failed to cancel enhanced rule preparation")
            owner.enhancedModeButton.state = .on; owner.toggleEnhancedMode()
            owner.preparations[1](.success(Profile()))
            try require(owner.enhancedMode.starts == 1 && owner.enhancedMode.state == nil
                && owner.enhancedMode.lifecycleSnapshot.isPresent, "enhanced prepared fake boundary was not established")
            owner.enhancedModeButton.state = .off; owner.toggleEnhancedMode()
            owner.enhancedMode.complete()
            try require(owner.enhancedMode.stops == 1 && !UserDefaults.standard.bool(forKey: "enhancedModeEnabled")
                && owner.enhancedModeButton.state == .off, "late enhanced success revived a stopped UI request")
        }
        for stopListener in [true, false] {
            let owner = fresh()
            UserDefaults.standard.set(true, forKey: "proxyEngineEnabled")
            UserDefaults.standard.set(true, forKey: "enhancedModeEnabled")
            owner.restoreLastSession()
            try require(owner.preparations.count == 1, "launch restore did not share rule preparation")
            if stopListener { owner.stopProxyEngine() }
            else { owner.enhancedModeButton.state = .off; owner.toggleEnhancedMode() }
            owner.preparations[0](.success(Profile()))
            try require(owner.engine.starts == (stopListener ? 0 : 1)
                && owner.enhancedMode.starts == (stopListener ? 1 : 0),
                        "launch restore ignored the canceled owner's ticket or canceled its independent peer")
            if stopListener { owner.enhancedMode.complete() }
            owner.stopProxyEngine()
            owner.enhancedModeButton.state = .off; owner.toggleEnhancedMode()
        }
        do {
            let owner = fresh()
            owner.enhancedModeButton.state = .on; owner.toggleEnhancedMode()
            owner.preparations[0](.success(Profile()))
            owner.enhancedMode.failForNetwork()
            try require(owner.enhancedMode.isRequested && owner.isEnhancedModeActive
                && UserDefaults.standard.bool(forKey: "enhancedModeEnabled")
                && owner.enhancedModeButton.state == .on && owner.enhancedModeButton.isEnabled,
                        "offline startup discarded persistent user intent or made it impossible to cancel")
            try require(owner.messages.isEmpty, "temporary offline startup showed a fatal start dialog")
            owner.apply(enhancedStatus: .waitingForNetwork("等待物理网络"))
            try require(owner.enhancedModeButton.state == .on && owner.enhancedModeButton.isEnabled
                && owner.dataPlaneRuntimeValue.stringValue == "等待物理网络", "waiting status did not retain an actionable on switch")
            owner.apply(enhancedStatus: .failed("helper stopped after restoration"))
            try require(UserDefaults.standard.bool(forKey: "enhancedModeEnabled")
                && owner.enhancedModeButton.state == .on, "unexpected Helper failure cleared saved user intent")
            owner.apply(enhancedStatus: .stopped)
            try require(owner.enhancedModeButton.state == .on, "internal session release switched off requested enhanced mode")
            owner.selectedMode = .direct
            owner.updateEngineRouting()
            try require(owner.enhancedMode.reloadModes == [.direct], "configuration updates were lost while waiting without a tunnel")
            owner.enhancedModeButton.state = .off; owner.toggleEnhancedMode()
            try require(owner.enhancedMode.stops == 1 && !owner.enhancedMode.isRequested
                && !owner.isEnhancedModeActive && !UserDefaults.standard.bool(forKey: "enhancedModeEnabled"),
                        "manual off without current resources failed to revoke reconnect intent")
            owner.apply(enhancedStatus: .waitingForNetwork("late waiting status"))
            try require(owner.enhancedModeButton.state == .off, "late waiting event reopened a manually stopped switch")
        }
        for waiting in [false, true] {
            let owner = fresh()
            owner.enhancedModeButton.state = .on; owner.toggleEnhancedMode()
            if waiting {
                owner.preparations[0](.success(Profile()))
                owner.enhancedMode.failForNetwork()
            }
            owner.uninstallHelperFromSettings()
            if !waiting { owner.preparations[0](.success(Profile())) }
            try require(owner.helperClient.uninstalls == 1 && !owner.enhancedMode.isRequested
                && !owner.enhancedRequestIntent.snapshot.startupPending
                && !UserDefaults.standard.bool(forKey: "enhancedModeEnabled"),
                        "Helper uninstall retained a pending startup or reconnect request")
            try require(owner.enhancedMode.starts == (waiting ? 1 : 0)
                && owner.enhancedMode.stops == (waiting ? 1 : 0),
                        "Helper uninstall failed to cancel the correct preparation/waiting owner")
        }
        print("Main lifecycle self-test passed: \(assertions) assertions; exact production local-proxy readiness/prompt, start/stop/late-preparation, restore, reload/recovery, replacement and enhanced UI intents; no platform/network operations")
    }
}

@main
enum MainLifecycleMain {
    static func main() {
        do { try MainWindowController.runChecks() }
        catch { print("FAIL Main lifecycle: \(error.localizedDescription)"); fflush(stdout); exit(1) }
    }
}

import Foundation
import AppKit
import Network
import Darwin
import SystemConfiguration
import HajimiCore
import HajimiIPC
import HajimiNativeCore

/// Enhanced mode controller. The root helper only owns utun + routes + DNS;
/// the userspace TCP/UDP data plane and every outbound protocol run here in
/// the unprivileged App after receiving the utun file descriptor.
final class EnhancedModeManager {
    enum Status: Equatable {
        case stopped
        case starting
        case waitingForNetwork(String)
        case running(interface: String, physicalInterface: String)
        case stopping
        case failed(String)
    }

    struct State: Equatable {
        var tunnelInterface: String
        var physicalInterface: String
        var startedAt: Date
        var dataPlane: String
    }

    enum ManagerError: LocalizedError {
        case alreadyRunning
        case helperAlreadyRunning
        case defaultInterfaceMissing
        case invalidHelperState
        case startCancelled
        case tunnelAttachFailed(String)
        case cleanupFailed(start: String, cleanup: String)

        var errorDescription: String? {
            switch self {
            case .alreadyRunning: return "增强模式已经运行"
            case .helperAlreadyRunning: return "root Helper 已有活动隧道，请先关闭另一个 Hajimi 会话"
            case .defaultInterfaceMissing: return "无法确定当前物理默认网络接口"
            case .invalidHelperState: return "root Helper 返回的增强模式状态不完整"
            case .startCancelled: return "增强模式启动已取消"
            case .tunnelAttachFailed(let value): return "无法接管 utun 数据面：\(value)"
            case .cleanupFailed(let start, let cleanup):
                return "增强模式启动失败：\(start)；恢复系统网络未确认：\(cleanup)"
            }
        }
    }

    var onStatus: ((Status) -> Void)?
    var onStatistics: ((Int, Int, UInt64, UInt64) -> Void)?

    private let queue = DispatchQueue(label: "app.hajimi.enhanced-mode", qos: .userInitiated)
    /// A route/DNS reload can occupy `queue` longer than the helper's 3-second
    /// liveness budget. Keep status heartbeats independent of that work.
    private let heartbeatQueue = DispatchQueue(label: "app.hajimi.enhanced-heartbeat", qos: .userInitiated)
    private let helper = PrivilegedHelperClient()
    private let lock = NSLock()
    private let startupIntent = EnhancedStartupIntent()
    /// The user's request outlives a particular utun/session. These values are
    /// protected by `lock`, including synchronous cancellation during IPC.
    private var connectionRequested = false
    private var connectionRequestEpoch: UInt64 = 0
    private var requestedConfigurationRevision: UInt64 = 0
    private var requestedConfiguration: AppliedConfiguration?
    private weak var requestedEngine: ProxyEngine?
    /// Only present while there is no usable session. Physical callbacks run
    /// immediately; this poll covers a missing path/DHCP callback.
    private var requestedStartTimer: DispatchSourceTimer?
    private var requestedRecoveryPending = false
    private var nextRequestedStartAt: TimeInterval = 0
    private var recoverAfterCleanup = false
    private var suspendedRecoveryFailure: String?
    private var lastWaitingMessage: String?
    /// Queue-owned, including the prepared interval before `state` is running.
    private var startupTicket: EnhancedStartupIntent.Ticket?
    private var startupRequestAuthority: (epoch: UInt64, revision: UInt64)?
    private var ownedSessionToken: String?
    private var cleanupPending = false
    private var networkRecoveryTimer: DispatchSourceTimer?
    private var cachedState: State?
    private var monitorTimer: DispatchSourceTimer?
    private var statisticsTimer: DispatchSourceTimer?
    /// Created/cancelled on `queue`; its handler never touches queue-owned state.
    private var heartbeatTimer: DispatchSourceTimer?
    private var monitorFailures = 0
    private weak var boundEngine: ProxyEngine?
    private var appliedConfiguration: AppliedConfiguration?
    /// A failed configuration reload must recover the latest requested
    /// routing, never certify the previous Helper settings against a new router.
    private var pendingConfiguration: AppliedConfiguration?
    /// Confined to `queue`; a failed partial helper/router reload stays dirty
    /// so even an equal old configuration must execute its recovery action.
    private let routingReloadGate = RoutingReloadGate()
    private var pathMonitor: NWPathMonitor?
    private var wakeObservers: [NSObjectProtocol] = []
    private var wakeFollowUpWorkItems: [DispatchWorkItem] = []
    private var pendingRebind: DispatchWorkItem?
    /// These snapshots/tickets are confined to `queue`; no network identifier
    /// is persisted or added to controller diagnostics.
    private var networkStateStore: SCDynamicStore?
    private lazy var snapshotStore: SCDynamicStore? = SCDynamicStoreCreate(
        nil, "app.hajimi.physical-network.snapshot" as CFString, nil, nil)
    private var networkChangeGate = EnhancedNetworkChangeGate()
    private var latestNetworkPath: NWPath?
    private var startupNetworkSnapshot: EnhancedNetworkSnapshot?
    private var cachedFallbackGateways: (interfaceName: String, addresses: [String], gateways: [String])?
    /// App-owned data plane. Lives only while enhanced mode is running.
    private var tunnel: NativeTunnel?
    private var router: NativePacketRouter?
    /// Last host routes installed on the physical gateway. Compared after
    /// periodic DNS so a node IP change can refresh bypass routes without
    /// tearing the data plane down.
    private var lastBypassAddresses: [String] = []
    private var bypassRefreshTimer: DispatchSourceTimer?
    /// Queue-owned. A DNS result may only update the helper for the session
    /// and configuration that launched it (even when the contents are equal).
    private var configurationGeneration: UInt64 = 0
    private var bypassRefreshInFlight: UInt64?

    private typealias AppliedConfiguration = RoutingReloadGate.Configuration

    private let applicationSupportDirectory: URL

    init(applicationSupportDirectory: URL) {
        self.applicationSupportDirectory = applicationSupportDirectory
        queue.setSpecific(key: Self.queueKey, value: true)
        cachedState = nil
        // Do not stop a tunnel merely because another App instance is running.
        // A previous process's orphaned routes are removed by the helper's
        // own liveness watchdog; this instance has no FD or ownership yet.
    }

    deinit {
        pathMonitor?.cancel()
        if let networkStateStore { SCDynamicStoreSetDispatchQueue(networkStateStore, nil) }
        for observer in wakeObservers {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        wakeFollowUpWorkItems.forEach { $0.cancel() }
        startupIntent.cancel()
        // Withdraw capture before releasing the packet reader. A failed
        // teardown leaves recovery to the Helper watchdog as this process exits.
        let cleanup = {
            self.stopHeartbeat()
            if let token = self.ownedSessionToken { _ = try? self.helper.stop(sessionToken: token) }
            self.router?.flushDNS(prewarm: false)
            self.tunnel?.stop()
            self.tunnel = nil
            self.router = nil
            self.monitorTimer?.cancel(); self.monitorTimer = nil
            self.statisticsTimer?.cancel(); self.statisticsTimer = nil
            self.networkRecoveryTimer?.cancel(); self.networkRecoveryTimer = nil
            self.requestedStartTimer?.cancel(); self.requestedStartTimer = nil
            self.bypassRefreshTimer?.cancel(); self.bypassRefreshTimer = nil
            self.setAppliedConfiguration(nil)
        }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { cleanup() }
        else { queue.sync(execute: cleanup) }
    }

    /// Best-effort teardown of this App's own tunnel on quit. Never send stop
    /// to a helper session belonging to another running Hajimi process.
    func shutdownForQuit() {
        let ticket = cancelConnectionRequest()
        let work = {
            // Keep the reader alive if restoration is still pending. The
            // process exit and absence of heartbeats trigger Helper recovery.
            try? self.stopOwnedSession(engine: self.boundEngine, cancelledTicket: ticket)
        }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { work() }
        else { queue.sync(execute: work) }
    }

    var state: State? { lock.withLock { cachedState } }
    var isEnabled: Bool { state != nil }
    var isRequested: Bool { lock.withLock { connectionRequested } }
    var lifecycleSnapshot: EnhancedStartupIntent.Snapshot { startupIntent.snapshot }

    /// The TUN router is independent of the optional HTTP/SOCKS listeners.
    /// Resolve its owner asynchronously: Helper work may occupy `queue`, and
    /// a stopped/hidden diagnostic window must revoke a pending request too.
    func startNetworkDiagnostics(callbackQueue: DispatchQueue = .main,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkDiagnosticsRequest {
        let request = NetworkDiagnosticsRequest()
        queue.async { [weak self, weak request] in
            guard let self, let request, !request.isCancelled else { return }
            let update: (NetworkConnectivityDiagnosticsSnapshot) -> Void = { [weak request] snapshot in
                guard request?.isCancelled == false else { return }
                onUpdate(snapshot)
            }
            let lifecycle = self.startupIntent.snapshot
            guard lifecycle.isReady, let state = self.state, !self.cleanupPending,
                  self.ownedSessionToken != nil, self.tunnel != nil,
                  let router = self.router, let ticket = self.startupTicket,
                  self.startupIntent.isCurrent(ticket) else {
                let session = ProxyEngine.unavailableNetworkDiagnostics(
                    detail: "增强模式尚未就绪或正在恢复网络；请等待后重新检测",
                    callbackQueue: callbackQueue, onUpdate: update)
                request.installCancellation { session.cancel() }
                return
            }
            let session = router.startNetworkDiagnostics(callbackQueue: callbackQueue,
                ownerIsCurrent: { [weak self, weak request] in
                    guard let self, request?.isCancelled == false else { return false }
                    // Both reads are lock protected; never synchronously
                    // re-enter the manager queue from a probe worker.
                    let current = self.startupIntent.snapshot
                    return current.isReady && current.revision == lifecycle.revision
                        && self.startupIntent.isCurrent(ticket) && self.state == state
                }, onUpdate: update)
            request.installCancellation { session.cancel() }
        }
        return request
    }

    func prepareExistingSession(engine: ProxyEngine,
                                completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            // A running tunnel may belong to another App process. Do not
            // interfere with it; orphaned sessions expire in the helper.
            guard self.state == nil, self.ownedSessionToken == nil, self.startupTicket == nil else {
                DispatchQueue.main.async { completion(.success(())) }
                return
            }
            engine.setOutboundInterface(name: nil) { _ in
                DispatchQueue.main.async { completion(.success(())) }
            }
        }
    }

    func start(profile: Profile, mode: OutboundMode, globalPolicy: String,
               groupSelections: [String: String], engine: ProxyEngine,
               completion: @escaping (Result<State, Error>) -> Void) {
        let configuration = AppliedConfiguration(profile: profile, mode: mode,
            globalPolicy: globalPolicy, groupSelections: groupSelections)
        let request: (EnhancedStartupIntent.Ticket, UInt64, UInt64)? = lock.withLock {
            guard let ticket = startupIntent.reserve() else { return nil }
            connectionRequested = true
            connectionRequestEpoch &+= 1
            requestedConfigurationRevision &+= 1
            requestedConfiguration = configuration
            requestedEngine = engine
            return (ticket, connectionRequestEpoch, requestedConfigurationRevision)
        }
        guard let (ticket, epoch, revision) = request else {
            DispatchQueue.main.async { completion(.failure(ManagerError.alreadyRunning)) }
            return
        }
        NativeOutboundFactory.invalidateForNetworkChange()
        SecureDNSHostResolver.shared.flush()
        beginStart(ticket: ticket, configuration: configuration, engine: engine,
                   epoch: epoch, revision: revision, installHelper: true,
                   completion: completion)
    }

    /// Automatic reconnect only uses the already-installed, compatible Helper.
    /// It never opens an installation or authorization prompt in the background.
    private func beginStart(ticket: EnhancedStartupIntent.Ticket,
                            configuration: AppliedConfiguration, engine: ProxyEngine,
                            epoch: UInt64, revision: UInt64, installHelper: Bool,
                            completion: @escaping (Result<State, Error>) -> Void) {
        let profile = configuration.profile
        let mode = configuration.mode
        let globalPolicy = configuration.globalPolicy
        let groupSelections = configuration.groupSelections
        emit(.starting)
        let installed: (Result<Void, Error>) -> Void = { [weak self, weak engine] installation in
            guard let self, let engine else { return }
            guard self.startupIntent.isCurrent(ticket),
                  self.isCurrentConnectionRequest(epoch: epoch, revision: revision) else {
                self.startupIntent.release(ticket)
                self.queue.async { self.resumeSupersededStart(epoch: epoch, revision: revision) }
                completion(.failure(ManagerError.startCancelled))
                return
            }
            switch installation {
            case .failure(let error):
                self.queue.async {
                    guard self.startupIntent.isCurrent(ticket),
                          self.isCurrentConnectionRequest(epoch: epoch, revision: revision) else {
                        self.startupIntent.release(ticket)
                        self.resumeSupersededStart(epoch: epoch, revision: revision)
                        DispatchQueue.main.async { completion(.failure(ManagerError.startCancelled)) }
                        return
                    }
                    self.startupIntent.markFailure(ticket)
                    self.startupIntent.release(ticket, preservingFailure: true)
                    self.suspendRequestedRecovery()
                    self.emit(.failed(error.localizedDescription))
                    DispatchQueue.main.async { completion(.failure(error)) }
                }
            case .success:
                self.queue.async {
                    guard self.startupIntent.isCurrent(ticket),
                          self.isCurrentConnectionRequest(epoch: epoch, revision: revision) else {
                        self.startupIntent.release(ticket)
                        self.resumeSupersededStart(epoch: epoch, revision: revision)
                        DispatchQueue.main.async { completion(.failure(ManagerError.startCancelled)) }
                        return
                    }
                    self.suspendRequestedRecovery()
                    self.stopNetworkObservers()
                    self.startupTicket = ticket
                    self.startupRequestAuthority = (epoch, revision)
                    self.invalidateBypassRefresh()
                    let generation = self.configurationGeneration
                    do {
                        guard self.physicalNetworkSnapshot().available else {
                            throw ManagerError.defaultInterfaceMissing
                        }
                        _ = try self.defaultInterface()
                    } catch {
                        let waiting = Self.isNetworkReadinessFailure(error) &&
                            self.isCurrentConnectionRequest(epoch: epoch)
                        if !waiting { self.startupIntent.markFailure(ticket) }
                        self.startupIntent.release(ticket, preservingFailure: !waiting)
                        if self.startupTicket == ticket { self.startupTicket = nil }
                        if waiting {
                            self.nextRequestedStartAt = 0
                            self.waitForRequestedConnection("等待 Wi-Fi 或其他物理网络就绪，增强模式会自动连接")
                        } else if self.isCurrentConnectionRequest(epoch: epoch) {
                            self.suspendRequestedRecovery()
                            self.emit(.failed(error.localizedDescription))
                        }
                        DispatchQueue.main.async { completion(.failure(error)) }
                        return
                    }
                    self.nextRequestedStartAt = ProcessInfo.processInfo.systemUptime + 0.25
                    ProxyBypassAddresses.collectAsync(
                        profile: profile, mode: mode, globalPolicy: globalPolicy,
                        groupSelections: groupSelections, queue: self.queue) { [weak self, weak engine] resolution in
                    guard let self, let engine else { return }
                    guard self.startupIntent.isCurrent(ticket),
                          generation == self.configurationGeneration,
                          self.isCurrentConnectionRequest(epoch: epoch, revision: revision) else {
                        self.startupIntent.release(ticket)
                        if self.startupTicket == ticket { self.startupTicket = nil }
                        self.resumeSupersededStart(epoch: epoch, revision: revision)
                        DispatchQueue.main.async {
                            completion(.failure(ManagerError.startCancelled))
                        }
                        return
                    }
                    var ownsStartResources = false
                    var pendingTunnelFD: Int32?
                    do {
                        try self.requireCurrentStart(ticket, generation: generation)
                        if self.state != nil || self.ownedSessionToken != nil || self.cleanupPending {
                            throw ManagerError.alreadyRunning
                        }
                        let bypass = try resolution.get()
                        let previous = try self.helper.status(keepAlive: false)
                        if previous.running || previous.phase != nil || previous.networkCleanupPending != false {
                            throw ManagerError.helperAlreadyRunning
                        }
                        let physical = try self.defaultInterface()
                        self.boundEngine = engine
                        ownsStartResources = true
                        self.startupIntent.markOwned(ticket)
                        try self.bindOutbound(engine: engine, physical: physical)
                        self.startupNetworkSnapshot = self.physicalNetworkSnapshot(boundInterface: physical)
                        try self.requireCurrentStart(ticket, generation: generation)
                        self.startHeartbeat()
                        let session = try self.helper.prepare(
                            fakeIPEnabled: profile.shouldHijackSystemDNS,
                            bypassAddresses: bypass,
                            excludedRoutes: profile.tunExcludedRoutes,
                            includedRoutes: profile.tunIncludedRoutes)
                        pendingTunnelFD = session.fileDescriptor
                        guard let token = session.state.sessionToken,
                              let interface = session.state.tunnelInterface,
                              let preparedPhysical = session.state.physicalInterface else {
                            throw ManagerError.invalidHelperState
                        }
                        self.ownedSessionToken = token
                        try self.requireCurrentStart(ticket, generation: generation)
                        // The Helper may have observed a newer physical uplink.
                        // Bind before creating or warming the final TUN router.
                        if preparedPhysical != physical {
                            try self.bindOutbound(engine: engine, physical: preparedPhysical)
                            self.startupNetworkSnapshot = self.physicalNetworkSnapshot(boundInterface: preparedPhysical)
                        }
                        try self.requireStartupNetwork(physical: preparedPhysical)
                        try self.attachDataPlane(
                            pendingFileDescriptor: &pendingTunnelFD,
                            interfaceName: interface,
                            profile: profile, mode: mode,
                            globalPolicy: globalPolicy,
                            groupSelections: groupSelections)
                        guard let native = self.tunnel else { throw ManagerError.invalidHelperState }
                        try self.requireCurrentStart(ticket, generation: generation)
                        try native.waitUntilReaderReady(timeout: 2)
                        try self.requireCurrentStart(ticket, generation: generation)
                        try self.requireStartupNetwork(physical: preparedPhysical)
                        // The only traffic-capture operation is after a real
                        // registration ACK from the final data plane's reader.
                        let committed = try self.helper.commit(sessionToken: token)
                        try self.requireCurrentStart(ticket, generation: generation)
                        guard let helperState = Self.state(from: committed),
                              helperState.tunnelInterface == interface,
                              helperState.physicalInterface == preparedPhysical else {
                            throw ManagerError.invalidHelperState
                        }
                        try self.requireStartupNetwork(physical: preparedPhysical)
                        try self.requireCurrentStart(ticket, generation: generation)
                        self.setState(helperState)
                        self.lastBypassAddresses = Self.normalizedBypass(bypass)
                        self.setAppliedConfiguration(AppliedConfiguration(
                            profile: profile, mode: mode, globalPolicy: globalPolicy,
                            groupSelections: groupSelections))
                        guard self.startupIntent.markRunning(ticket) else { throw ManagerError.startCancelled }
                        self.monitorFailures = 0
                        self.lastWaitingMessage = nil
                        self.startMonitor()
                        self.emit(.running(interface: helperState.tunnelInterface,
                                           physicalInterface: helperState.physicalInterface))
                        DispatchQueue.main.async {
                            guard self.startupIntent.isCurrent(ticket) else {
                                completion(.failure(ManagerError.startCancelled)); return
                            }
                            completion(.success(helperState))
                        }
                    } catch {
                        if case ManagerError.startCancelled = error {} else {
                            self.startupIntent.markFailure(ticket)
                        }
                        let cleanupError = ownsStartResources
                            ? self.rollbackFailedStart(
                                engine: engine,
                                pendingTunnelFD: pendingTunnelFD)
                            : nil
                        self.startupNetworkSnapshot = nil
                        if !ownsStartResources {
                            self.startupIntent.release(ticket, preservingFailure: true)
                            if self.startupTicket == ticket { self.startupTicket = nil }
                        }
                        let failure: Error
                        if let cleanupError {
                            failure = ManagerError.cleanupFailed(
                                start: error.localizedDescription,
                                cleanup: cleanupError.localizedDescription)
                        } else {
                            failure = error
                        }
                        let retry = self.isCurrentConnectionRequest(epoch: epoch) &&
                            (Self.isNetworkReadinessFailure(error) ||
                             !self.isCurrentConnectionRequest(epoch: epoch, revision: revision))
                        if retry {
                            ProxyBypassAddresses.invalidateCache()
                            NativeOutboundFactory.invalidateForNetworkChange()
                            self.recoverAfterCleanup = self.cleanupPending
                            self.waitForRequestedConnection("网络正在恢复，增强模式保持开启并会自动重新连接")
                        } else if case ManagerError.startCancelled = failure {
                            if !self.cleanupPending { self.emit(.stopped) }
                        } else {
                            self.suspendRequestedRecovery()
                            if self.cleanupPending { self.suspendedRecoveryFailure = failure.localizedDescription }
                            self.emit(.failed(failure.localizedDescription))
                        }
                        DispatchQueue.main.async { completion(.failure(failure)) }
                    }
                    }
                }
            }
        }
        if installHelper { helper.ensureInstalled(completion: installed) }
        else { installed(.success(())) }
    }

    private func isCurrentConnectionRequest(epoch: UInt64, revision: UInt64? = nil) -> Bool {
        lock.withLock {
            connectionRequested && connectionRequestEpoch == epoch && requestedEngine != nil &&
                (revision == nil || requestedConfigurationRevision == revision)
        }
    }

    /// Revoked before queueing any stop work, so an in-flight commit or DNS
    /// callback cannot resurrect a session after a user turns enhanced off.
    private func cancelConnectionRequest() -> EnhancedStartupIntent.Ticket? {
        lock.withLock {
            connectionRequested = false
            connectionRequestEpoch &+= 1
            requestedConfigurationRevision &+= 1
            requestedConfiguration = nil
            requestedEngine = nil
            return startupIntent.cancel()
        }
    }

    private static func isNetworkReadinessFailure(_ error: Error) -> Bool {
        if case ManagerError.defaultInterfaceMissing = error { return true }
        if case ProxyBypassCollectionError.networkChanged = error { return true }
        if case ProxyBypassCollectionError.unresolved = error { return true }
        if case PrivilegedHelperClient.ClientError.physicalNetworkNotReady = error { return true }
        return false
    }

    private func emitWaiting(_ message: String) {
        guard isRequested, lastWaitingMessage != message else { return }
        lastWaitingMessage = message
        emit(.waitingForNetwork(message))
    }

    private func suspendRequestedRecovery() {
        requestedStartTimer?.cancel(); requestedStartTimer = nil
        requestedRecoveryPending = false
        recoverAfterCleanup = false
        suspendedRecoveryFailure = nil
    }

    /// A single five-second poll complements path/wake callbacks. The same
    /// network gate used by live rebinds fences duplicate events. Full new
    /// sessions retain their five-second start limit even when events arrive.
    private func waitForRequestedConnection(_ message: String) {
        guard isRequested else { return }
        emitWaiting(message)
        guard state == nil, ownedSessionToken == nil, !cleanupPending else { return }
        requestedRecoveryPending = true
        startNetworkObservers()
        guard requestedStartTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(300), repeating: .milliseconds(500), leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in self?.checkRequestedConnection() }
        requestedStartTimer = timer
        timer.resume()
    }

    private func resumeSupersededStart(epoch: UInt64, revision: UInt64) {
        guard isCurrentConnectionRequest(epoch: epoch),
              !isCurrentConnectionRequest(epoch: epoch, revision: revision) else { return }
        recoverAfterCleanup = cleanupPending
        waitForRequestedConnection("配置已更新，增强模式将按最新配置自动连接")
        checkRequestedConnection()
    }

    private func checkRequestedConnection() {
        guard requestedRecoveryPending, isRequested, state == nil,
              ownedSessionToken == nil, !cleanupPending,
              !startupIntent.snapshot.startupPending else { return }
        let network = physicalNetworkSnapshot()
        if let changed = networkChangeGate.observe(network, session: networkChangeGate.session) {
            scheduleRebindCheck(changed)
        } else if let retry = networkChangeGate.retry(session: networkChangeGate.session) {
            scheduleRebindCheck(retry)
        } else if network.available,
                  let ready = networkChangeGate.requestRecovery(network, session: networkChangeGate.session) {
            scheduleRebindCheck(ready)
        }
    }

    private func attemptRequestedStart(change: EnhancedNetworkChangeGate.Action) {
        let authority = lock.withLock { (connectionRequestEpoch, requestedConfigurationRevision) }
        var accepted = false
        defer {
            networkChangeGate.finished(change, succeeded: accepted)
            if !accepted, requestedRecoveryPending, state == nil, ownedSessionToken == nil,
               !cleanupPending, isCurrentConnectionRequest(epoch: authority.0, revision: authority.1),
               let retry = networkChangeGate.retryReadinessSoon(session: networkChangeGate.session) {
                scheduleRebindCheck(retry.ticket, after: retry.delay)
            }
        }
        let current = physicalNetworkSnapshot()
        guard requestedRecoveryPending, state == nil, ownedSessionToken == nil,
              !cleanupPending, current.available, change.snapshot.available,
              current.hasSameIdentity(as: change.snapshot),
              let physical = try? defaultInterface(), physical == current.interfaceName else { return }
        let request: (EnhancedStartupIntent.Ticket, AppliedConfiguration, ProxyEngine, UInt64, UInt64)? = lock.withLock {
            guard connectionRequested, let configuration = requestedConfiguration,
                  let engine = requestedEngine, let ticket = startupIntent.reserve() else { return nil }
            return (ticket, configuration, engine, connectionRequestEpoch, requestedConfigurationRevision)
        }
        guard let (ticket, configuration, engine, epoch, revision) = request else { return }
        accepted = true
        beginStart(ticket: ticket, configuration: configuration, engine: engine,
                   epoch: epoch, revision: revision, installHelper: false) { _ in }
    }

    private func requireCurrentStart(_ ticket: EnhancedStartupIntent.Ticket, generation: UInt64) throws {
        guard startupIntent.isCurrent(ticket), generation == configurationGeneration,
              let request = startupRequestAuthority,
              isCurrentConnectionRequest(epoch: request.epoch, revision: request.revision) else {
            throw ManagerError.startCancelled
        }
    }

    private func requireStartupNetwork(physical: String) throws {
        let current = physicalNetworkSnapshot(boundInterface: physical)
        guard let original = startupNetworkSnapshot, original.available, current.available,
              original.hasSameIdentity(as: current), try defaultInterface() == physical else {
            throw ProxyBypassCollectionError.networkChanged
        }
    }

    private func bindOutbound(engine: ProxyEngine, physical: String) throws {
        let semaphore = DispatchSemaphore(value: 0)
        var binding: Result<Void, Error> = .failure(ManagerError.defaultInterfaceMissing)
        engine.setOutboundInterface(name: physical) { binding = $0; semaphore.signal() }
        guard semaphore.wait(timeout: .now() + 5) == .success else {
            throw ManagerError.defaultInterfaceMissing
        }
        do { try binding.get() }
        catch { throw ManagerError.defaultInterfaceMissing }
        // Both APIs share the binding above; avoid a second asynchronous
        // resolve that could complete after cancellation and restore old state.
        NativeTunnel.physicalInterfaceName = physical
    }

    /// Only prepare's token proves ownership. An uncertain commit may already
    /// capture traffic: retain its reader and uplink until restoration is proved.
    private func rollbackFailedStart(engine: ProxyEngine,
                                     pendingTunnelFD: Int32?) -> Error? {
        if let pendingTunnelFD { Darwin.close(pendingTunnelFD) }
        do { try stopOwnedSession(engine: engine, cancelledTicket: startupTicket, preservingFailure: true); return nil }
        catch { return error }
    }

    func stop(engine: ProxyEngine, completion: @escaping (Result<Void, Error>) -> Void) {
        let ticket = cancelConnectionRequest()
        queue.async {
            do {
                try self.stopOwnedSession(engine: engine, cancelledTicket: ticket)
                DispatchQueue.main.async { completion(.success(())) }
            } catch {
                self.emit(.failed(error.localizedDescription))
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    func flushFakeIP() {
        router?.flushFakeIP()
    }

    func flushDNS() {
        queue.async { self.router?.flushDNS() }
    }

    func fakeIPEntries() -> [(domain: String, address: String)] {
        router?.fakeIPSnapshot() ?? []
    }

    func reload(profile: Profile, mode: OutboundMode, globalPolicy: String,
                groupSelections: [String: String]) throws {
        let configuration = AppliedConfiguration(
            profile: profile, mode: mode, globalPolicy: globalPolicy,
            groupSelections: groupSelections)
        let desiredChanged = lock.withLock { () -> Bool in
            guard connectionRequested, requestedConfiguration != configuration else { return false }
            requestedConfiguration = configuration
            requestedConfigurationRevision &+= 1
            return true
        }
        try queue.sync {
            guard state != nil, !cleanupPending, let token = ownedSessionToken else {
                if desiredChanged {
                    invalidateBypassRefresh()
                    if !startupIntent.snapshot.startupPending {
                        recoverAfterCleanup = cleanupPending
                        waitForRequestedConnection("配置已更新，增强模式将按最新配置自动连接")
                        checkRequestedConnection()
                    }
                }
                return
            }
            pendingConfiguration = configuration
            let reloaded = try routingReloadGate.apply(configuration) {
                guard let reloadTicket = startupIntent.beginReload() else { throw ManagerError.startCancelled }
                do {
                    // Invalidate DNS work already launched, including when the
                    // reload fails after partially changing helper settings.
                    invalidateBypassRefresh()
                    router?.update(profile: profile, mode: mode, globalPolicy: globalPolicy,
                                   groupSelections: groupSelections)
                    tunnel?.resetFlows()
                    let collected = ProxyBypassAddresses.collect(
                        profile: profile, mode: mode, globalPolicy: globalPolicy,
                        groupSelections: groupSelections)
                    // Preserve already-installed physical bypass host routes when switching
                    // between Rule and Global modes or switching nodes on the same network
                    // session, so an expired 60s DNS cache entry never tears down a working
                    // proxy server host route while refreshBypassRoutesIfNeeded() is in flight.
                    let bypass: [String]
                    if mode == .direct || lastBypassAddresses.isEmpty {
                        bypass = collected
                    } else {
                        bypass = Array(Self.normalizedBypass(collected + lastBypassAddresses).prefix(64))
                    }
                    guard startupIntent.isCurrent(reloadTicket) else { throw ManagerError.startCancelled }
                    let helperState = try helper.reload(fakeIPEnabled: profile.shouldHijackSystemDNS,
                                                        bypassAddresses: bypass,
                                                        excludedRoutes: profile.tunExcludedRoutes,
                                                        includedRoutes: profile.tunIncludedRoutes,
                                                        sessionToken: token)
                    guard let state = Self.state(from: helperState) else {
                        throw ManagerError.invalidHelperState
                    }
                    lastBypassAddresses = Self.normalizedBypass(bypass)
                    setState(state)
                    setAppliedConfiguration(configuration)
                    guard startupIntent.finishReload(reloadTicket, success: true) else { throw ManagerError.startCancelled }
                } catch {
                    _ = startupIntent.finishReload(reloadTicket, success: false)
                    if case PrivilegedHelperClient.ClientError.physicalNetworkNotReady = error {
                        requestNetworkRebind()
                    }
                    throw error
                }
            }
            pendingConfiguration = nil
            if !reloaded {
                // Only proven-unobservable selection metadata changed. The
                // in-flight bypass result has the same route/dependency set;
                // do not revoke its epoch or erase encrypted DNS warm state.
                lock.withLock { appliedConfiguration = configuration }
            } else {
                refreshBypassRoutesIfNeeded()
            }
        }
    }

    func stopSynchronously(engine: ProxyEngine) throws {
        let ticket = cancelConnectionRequest()
        let work = { try self.stopOwnedSession(engine: engine, cancelledTicket: ticket) }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { try work() }
        else { try queue.sync(execute: work) }
    }

    /// Runs on `queue`. Revocation precedes reader shutdown even for a
    /// prepared or uncertain session that has never published `state`.
    private func stopOwnedSession(engine: ProxyEngine?,
                                  cancelledTicket: EnhancedStartupIntent.Ticket?,
                                  preservingFailure: Bool = false) throws {
        // A late duplicate stop cannot tear down a subsequently reserved
        // session after the original stop has already confirmed cleanup.
        if let current = startupTicket, current != cancelledTicket { return }
        suspendRequestedRecovery()
        setAppliedConfiguration(nil)
        lastBypassAddresses = []
        cancelMonitorTimer()
        stopNetworkObservers()
        stopHeartbeat()
        if ownedSessionToken != nil { emit(.stopping) }
        do {
            if let token = ownedSessionToken { _ = try helper.stop(sessionToken: token) }
        } catch {
            cleanupPending = true
            if let ticket = startupTicket ?? cancelledTicket { startupIntent.markRecovery(ticket) }
            beginNetworkRecovery()
            throw error
        }
        releaseLocalResources(engine: engine, cancelledTicket: cancelledTicket, preservingFailure: preservingFailure)
        emit(.stopped)
    }

    private func releaseLocalResources(engine: ProxyEngine?,
                                       cancelledTicket: EnhancedStartupIntent.Ticket?,
                                       preservingFailure: Bool = false) {
        networkRecoveryTimer?.cancel(); networkRecoveryTimer = nil
        cleanupPending = false
        ownedSessionToken = nil
        startupRequestAuthority = nil
        router?.flushDNS(prewarm: false)
        tunnel?.stop()
        tunnel = nil
        router = nil
        setState(nil)
        engine?.setOutboundInterface(name: nil) { _ in }
        NativePacketRouter.setOutboundInterface(name: nil) { _ in }
        NativeTunnel.physicalInterfaceName = nil
        boundEngine = nil
        if let ticket = startupTicket {
            startupIntent.confirmStopped(ticket, preservingFailure: preservingFailure)
            startupTicket = nil
        }
        if let ticket = cancelledTicket { startupIntent.confirmStopped(ticket, preservingFailure: preservingFailure) }
        recoverAfterCleanup = false
    }

    private func beginNetworkRecovery() {
        guard networkRecoveryTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(150), repeating: .milliseconds(300),
                       leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in self?.checkNetworkRecovery() }
        networkRecoveryTimer = timer
        timer.resume()
    }

    private func checkNetworkRecovery() {
        guard cleanupPending, let token = ownedSessionToken else { return }
        // `ping` is read-only. A normal status heartbeat here would prevent
        // the very watchdog cleanup we are waiting for after a failed stop.
        guard let value = try? helper.status(keepAlive: false),
              value.networkCleanupPending == false,
              value.lastRestoredSessionToken == token else { return }
        // An empty snapshot after a daemon restart is not a restoration ACK.
        // The old token must never be sent as a stop for a replacement session.
        let reconnect = recoverAfterCleanup && isRequested
        let pausedFailure = suspendedRecoveryFailure
        releaseLocalResources(engine: boundEngine, cancelledTicket: startupTicket,
                              preservingFailure: !reconnect && pausedFailure != nil)
        if reconnect {
            waitForRequestedConnection("系统网络已恢复，等待物理网络就绪后自动连接增强模式")
            checkRequestedConnection()
        } else if isRequested, let pausedFailure { emit(.failed(pausedFailure)) }
        else { emit(.stopped) }
    }

    private func attachDataPlane(pendingFileDescriptor: inout Int32?, interfaceName: String,
                                 profile: Profile, mode: OutboundMode,
                                 globalPolicy: String,
                                 groupSelections: [String: String]) throws {
        let store = applicationSupportDirectory.appendingPathComponent("virtual-ip.json")
        let packetRouter = NativePacketRouter(profile: profile, mode: mode,
                                              globalPolicy: globalPolicy,
                                              groupSelections: groupSelections,
                                              fakeIPStoreURL: store)
        router = packetRouter
        packetRouter.prewarmDNS(immediately: true)
        let native = try NativeTunnel(router: packetRouter)
        tunnel = native
        guard let fileDescriptor = pendingFileDescriptor else { throw ManagerError.invalidHelperState }
        // start takes ownership even on fcntl failure; clear the caller's FD
        // before that call, so rollback can never close a recycled descriptor.
        pendingFileDescriptor = nil
        do {
            _ = try native.start(fileDescriptor: fileDescriptor,
                                 interfaceName: interfaceName)
        } catch {
            throw ManagerError.tunnelAttachFailed(error.localizedDescription)
        }
    }

    private func cancelMonitorTimer() {
        let work = {
            self.monitorTimer?.cancel(); self.monitorTimer = nil
            self.statisticsTimer?.cancel(); self.statisticsTimer = nil
            self.bypassRefreshTimer?.cancel(); self.bypassRefreshTimer = nil
        }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { work() }
        else { queue.sync(execute: work) }
    }

    private func clearBoundEngine() {
        let work = { self.boundEngine = nil }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { work() }
        else { queue.sync(execute: work) }
    }

    private static let queueKey = DispatchSpecificKey<Bool>()

    /// Keep the helper's three-second watchdog fed even while route reloads
    /// or DNS resolution occupy the serial enhanced-mode work queue.
    private func startHeartbeat() {
        guard heartbeatTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: heartbeatQueue)
        timer.schedule(deadline: .now() + .milliseconds(750), repeating: .milliseconds(750),
                       leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            _ = try? self.helper.status()
        }
        heartbeatTimer = timer
        timer.resume()
    }

    private func stopHeartbeat() {
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
    }

    private func startMonitor() {
        let token = ownedSessionToken
        queue.async {
            guard self.state != nil, !self.cleanupPending,
                  token != nil, token == self.ownedSessionToken else { return }
            self.monitorTimer?.cancel()
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(100))
            timer.setEventHandler { [weak self] in self?.monitorOnce() }
            self.monitorTimer = timer
            timer.resume()

            self.statisticsTimer?.cancel()
            let stats = DispatchSource.makeTimerSource(queue: self.queue)
            // Local traffic counters do not wait for a helper status request.
            // The independent heartbeat above handles watchdog liveness.
            stats.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(100))
            stats.setEventHandler { [weak self] in
                guard let self else { return }
                if let statistics = self.tunnel?.statistics() {
                    self.emitStatistics(active: statistics.activeFlows,
                                        total: statistics.totalFlows,
                                        up: statistics.uploadedBytes,
                                        down: statistics.downloadedBytes)
                }
            }
            self.statisticsTimer = stats
            stats.resume()

            self.bypassRefreshTimer?.cancel()
            let bypassTimer = DispatchSource.makeTimerSource(queue: self.queue)
            // Node A/AAAA records rotate independently of the default route.
            // Re-resolve on a long interval so a CDN or provider IP change
            // cannot black-hole the outbound by leaving a stale host route.
            bypassTimer.schedule(deadline: .now() + 30, repeating: 30, leeway: .seconds(5))
            bypassTimer.setEventHandler { [weak self] in self?.refreshBypassRoutesIfNeeded() }
            self.bypassRefreshTimer = bypassTimer
            bypassTimer.resume()
        }
        startNetworkObservers()
    }

    private final class NetworkStateCallbackContext {
        weak var owner: EnhancedModeManager?
        let session: UInt64
        init(owner: EnhancedModeManager, session: UInt64) {
            self.owner = owner; self.session = session
        }
    }

    /// Observe operational State only, never Setup preferences or DNS. The
    /// callback compares a physical snapshot, so our own utun/service updates
    /// and changes on an unused interface cannot flush a healthy DNS pool.
    private func installNetworkStateObserver(session: UInt64) {
        let owner = NetworkStateCallbackContext(owner: self, session: session)
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(owner).toOpaque(),
            retain: { info in
                UnsafeRawPointer(Unmanaged<NetworkStateCallbackContext>.fromOpaque(info).retain().toOpaque())
            }, release: { info in
                Unmanaged<NetworkStateCallbackContext>.fromOpaque(info).release()
            }, copyDescription: nil)
        guard let store = withExtendedLifetime(owner, { SCDynamicStoreCreate(nil,
            "app.hajimi.physical-network" as CFString,
            { _, _, info in
                guard let info else { return }
                let context = Unmanaged<NetworkStateCallbackContext>.fromOpaque(info).takeUnretainedValue()
                guard let owner = context.owner, owner.state != nil || owner.requestedRecoveryPending,
                      owner.networkChangeGate.session == context.session else { return }
                if let ticket = owner.networkChangeGate.observe(
                    owner.physicalNetworkSnapshot(), session: context.session) {
                    owner.scheduleRebindCheck(ticket)
                }
            }, &context) }) else { return }
        let keys = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] as CFArray
        let patterns = ["^State:/Network/Interface/[^/]+/(IPv4|IPv6|Link|AirPort)$",
                        "^State:/Network/Service/[^/]+/(IPv4|IPv6)$"] as CFArray
        guard SCDynamicStoreSetNotificationKeys(store, keys, patterns),
              SCDynamicStoreSetDispatchQueue(store, queue) else { return }
        networkStateStore = store
    }

    private func networkState(_ key: String) -> [String: Any] {
        guard let store = networkStateStore ?? snapshotStore else { return [:] }
        return SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any] ?? [:]
    }

    private static func isPhysicalInterfaceName(_ name: String) -> Bool {
        let excludedPrefixes = [
            "utun", "lo", "awdl", "llw", "ap", "anpi", "bridge", "gif", "stf",
            "xhc", "pktap", "ipsec", "ppp", "vmnet", "vboxnet", "vmenet", "tap", "tun"
        ]
        return !name.isEmpty && name.utf8.count < Int(IFNAMSIZ)
            && !excludedPrefixes.contains(where: { name.hasPrefix($0) })
            && name.utf8.allSatisfy { byte in
                (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
                    || byte == 45 || byte == 95
            }
    }

    private static func firstActivePhysicalInterface() -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return nil }
        defer { freeifaddrs(list) }
        let activeFlags = UInt32(IFF_UP | IFF_RUNNING)
        var cursor = list, visited = 0
        var candidates: [String] = []
        while let entry = cursor, visited < 4_096 {
            visited += 1; cursor = entry.pointee.ifa_next
            guard (entry.pointee.ifa_flags & activeFlags) == activeFlags,
                  let rawName = entry.pointee.ifa_name else { continue }
            let name = String(cString: rawName)
            guard isPhysicalInterfaceName(name),
                  let addr = entry.pointee.ifa_addr,
                  let numeric = numericAddress(addr) else { continue }
            let lower = numeric.lowercased()
            if lower.hasPrefix("fe80:") || lower.hasPrefix("169.254.") || lower.hasPrefix("127.") || lower == "::1" {
                continue
            }
            if name == "en0" { return name }
            if !candidates.contains(name) { candidates.append(name) }
        }
        return candidates.first
    }

    /// Read-only adapter. NWPathMonitor's localEndpoint can be nil and its
    /// availableInterfaces alone miss a DHCP renewal on the same Wi-Fi device.
    /// Select the real primary interface and compare its addresses/routers.
    private func physicalNetworkSnapshot(path: NWPath? = nil,
                                         boundInterface: String? = nil) -> EnhancedNetworkSnapshot {
        let global4 = networkState("State:/Network/Global/IPv4")
        let global6 = networkState("State:/Network/Global/IPv6")
        let names = [global4["PrimaryInterface"] as? String, global6["PrimaryInterface"] as? String]
        let preferred = names.compactMap { $0 }.first(where: Self.isPhysicalInterfaceName)
        let pathCandidate = (path ?? latestNetworkPath)?.availableInterfaces.map(\.name)
            .first(where: Self.isPhysicalInterfaceName)
        let physical: String
        if let boundInterface {
            physical = boundInterface
        } else {
            let initial = preferred ?? pathCandidate
            let initialLocal = initial.map(Self.interfaceAddresses)
            if let initial, let initialLocal, initialLocal.up, !initialLocal.addresses.isEmpty {
                physical = initial
            } else {
                let activeCandidate = Self.firstActivePhysicalInterface()
                let activeLocal = activeCandidate.map(Self.interfaceAddresses)
                if let activeCandidate, let activeLocal, activeLocal.up, !activeLocal.addresses.isEmpty {
                    physical = activeCandidate
                } else {
                    let routeCandidate = (try? defaultInterface()).flatMap {
                        Self.isPhysicalInterfaceName($0) ? $0 : nil
                    }
                    physical = routeCandidate ?? activeCandidate ?? initial ?? state?.physicalInterface ?? ""
                }
            }
        }
        let interfaceIndex = physical.withCString { if_nametoindex($0) }
        let local = Self.interfaceAddresses(physical)
        let state4 = networkState("State:/Network/Interface/\(physical)/IPv4")
        let state6 = networkState("State:/Network/Interface/\(physical)/IPv6")
        let service4 = (global4["PrimaryService"] as? String).map { networkState("State:/Network/Service/\($0)/IPv4") } ?? [:]
        let service6 = (global6["PrimaryService"] as? String).map { networkState("State:/Network/Service/\($0)/IPv6") } ?? [:]
        var gateways: [String] = []
        for value in [state4["Router"], state6["Router"],
                      (global4["PrimaryInterface"] as? String) == physical ? global4["Router"] : nil,
                      (global6["PrimaryInterface"] as? String) == physical ? global6["Router"] : nil,
                      (service4["InterfaceName"] as? String == nil || service4["InterfaceName"] as? String == physical) ? service4["Router"] : nil,
                      (service6["InterfaceName"] as? String == nil || service6["InterfaceName"] as? String == physical) ? service6["Router"] : nil] {
            if let address = value as? String, address.utf8.count <= 128 { gateways.append(address) }
        }
        if gateways.isEmpty, !physical.isEmpty, local.up, !local.addresses.isEmpty {
            if let cached = cachedFallbackGateways,
               cached.interfaceName == physical, cached.addresses == local.addresses {
                gateways.append(contentsOf: cached.gateways)
            } else {
                var resolvedGateways: [String] = []
                let process = Process(); let output = Pipe()
                process.executableURL = URL(fileURLWithPath: "/sbin/route")
                process.arguments = ["-n", "get", "-ifscope", physical, "default"]
                process.standardOutput = output; process.standardError = FileHandle.nullDevice
                if (try? process.run()) != nil {
                    process.waitUntilExit()
                    let routeText = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                    for line in routeText.components(separatedBy: .newlines) {
                        let pair = line.trimmingCharacters(in: .whitespaces)
                            .split(separator: ":", maxSplits: 1).map(String.init)
                        if pair.count == 2, pair[0] == "gateway" {
                            let gw = pair[1].trimmingCharacters(in: .whitespaces)
                            if !gw.isEmpty, !gw.hasPrefix("link#"), !gw.hasPrefix("198.18."), gw.utf8.count <= 128 {
                                resolvedGateways.append(gw)
                            }
                        }
                    }
                }
                cachedFallbackGateways = (physical, local.addresses, resolvedGateways)
                gateways.append(contentsOf: resolvedGateways)
            }
        }
        let link = networkState("State:/Network/Interface/\(physical)/Link")
        let linkActive = local.up || ((link["Active"] as? Bool) == true)
        let available = interfaceIndex != 0 && linkActive && !local.addresses.isEmpty
        let association = EnhancedWiFiAssociationStamp.make(
            from: networkState("State:/Network/Interface/\(physical)/AirPort"))
        return EnhancedNetworkSnapshot(available: available, interfaceName: physical,
            interfaceIndex: interfaceIndex, addresses: local.addresses, gateways: gateways,
            associationStamp: association)
    }

    private static func interfaceAddresses(_ name: String) -> (addresses: [String], up: Bool) {
        guard isPhysicalInterfaceName(name) else { return ([], false) }
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return ([], false) }
        defer { freeifaddrs(list) }
        let activeFlags = UInt32(IFF_UP | IFF_RUNNING)
        var cursor = list, addresses: [String] = [], up = false, visited = 0
        while let entry = cursor, visited < 4_096, addresses.count < 128 {
            visited += 1; cursor = entry.pointee.ifa_next
            guard let interface = entry.pointee.ifa_name, String(cString: interface) == name else { continue }
            up = up || (entry.pointee.ifa_flags & activeFlags) == activeFlags
            guard let raw = entry.pointee.ifa_addr, let address = numericAddress(raw) else { continue }
            let lower = address.lowercased()
            if lower.hasPrefix("fe80:") || lower.hasPrefix("169.254.") || lower.hasPrefix("127.") || lower == "::1" {
                continue
            }
            // A subnet change with the same IP is meaningful as well.
            let mask = entry.pointee.ifa_netmask.flatMap { numericAddress($0) } ?? ""
            addresses.append(mask.isEmpty ? address : address + "/" + mask)
        }
        return (addresses, up)
    }

    private static func numericAddress(_ address: UnsafePointer<sockaddr>) -> String? {
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        switch Int32(address.pointee.sa_family) {
        case AF_INET:
            var value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            guard inet_ntop(AF_INET, &value, &output, socklen_t(output.count)) != nil else { return nil }
        case AF_INET6:
            var value = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            guard inet_ntop(AF_INET6, &value, &output, socklen_t(output.count)) != nil else { return nil }
        default: return nil
        }
        return String(cString: output)
    }

    private func startNetworkObservers() {
        if DispatchQueue.getSpecific(key: Self.queueKey) == nil {
            queue.sync { self.startNetworkObservers() }
            return
        }
        let monitor: NWPathMonitor? = lock.withLock {
            guard pathMonitor == nil else { return nil }
            let created = NWPathMonitor()
            pathMonitor = created
            return created
        }
        if let monitor {
            let seed = startupNetworkSnapshot ?? physicalNetworkSnapshot()
            startupNetworkSnapshot = nil
            let startup = networkChangeGate.begin(seed: seed, boundInterface: state?.physicalInterface ?? "")
            let session = networkChangeGate.session
            installNetworkStateObserver(session: session)
            if let startup { scheduleRebindCheck(startup) }
            // A real change between seeding and installing observers must not
            // get mistaken for NWPathMonitor's initial delivery.
            if let changed = networkChangeGate.observe(physicalNetworkSnapshot(), session: session) {
                scheduleRebindCheck(changed)
            }
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self, self.state != nil || self.requestedRecoveryPending,
                      self.networkChangeGate.session == session else { return }
                self.latestNetworkPath = path
                if let changed = self.networkChangeGate.observe(self.physicalNetworkSnapshot(path: path),
                                                                session: session) {
                    self.scheduleRebindCheck(changed)
                }
            }
            monitor.start(queue: queue)
        }
        let session = networkChangeGate.session
        lock.withLock {
            guard wakeObservers.isEmpty else { return }
            let notifications: [Notification.Name] = [
                NSWorkspace.didWakeNotification,
                NSWorkspace.screensDidWakeNotification,
                NSWorkspace.sessionDidBecomeActiveNotification
            ]
            wakeObservers = notifications.map { name in
                NSWorkspace.shared.notificationCenter.addObserver(
                    forName: name, object: nil, queue: nil
                ) { [weak self] _ in
                    guard let self else { return }
                    self.heartbeatQueue.async {
                        _ = try? self.helper.status()
                    }
                    self.queue.async {
                        self.handleWakeEvent(session: session)
                        self.scheduleWakeFollowUpProbes(session: session)
                    }
                }
            }
        }
    }

    private func handleWakeEvent(session: UInt64) {
        guard state != nil || requestedRecoveryPending,
              networkChangeGate.session == session else { return }
        if state == nil { checkRequestedConnection(); return }
        monitorOnce()
        guard state != nil,
              let wake = networkChangeGate.wake(
                physicalNetworkSnapshot(), session: session) else { return }
        scheduleRebindCheck(wake)
    }

    private func scheduleWakeFollowUpProbes(session: UInt64) {
        let oldItems: [DispatchWorkItem] = lock.withLock {
            let previous = wakeFollowUpWorkItems
            wakeFollowUpWorkItems.removeAll()
            return previous
        }
        oldItems.forEach { $0.cancel() }
        // Wi-Fi re-association and DHCP/ARP recovery after screen wake or lid
        // open often complete 0.8s - 2.5s after the initial wake notification.
        let delays: [TimeInterval] = [0.8, 2.5]
        var created: [DispatchWorkItem] = []
        for delay in delays {
            let item = DispatchWorkItem { [weak self] in
                guard let self, self.state != nil || self.requestedRecoveryPending,
                      self.networkChangeGate.session == session else { return }
                if self.state == nil {
                    self.checkRequestedConnection()
                    return
                }
                if let changed = self.networkChangeGate.observe(
                    self.physicalNetworkSnapshot(), session: session) {
                    self.scheduleRebindCheck(changed)
                } else {
                    self.refreshBypassRoutesIfNeeded()
                }
            }
            created.append(item)
            queue.asyncAfter(deadline: .now() + delay, execute: item)
        }
        lock.withLock { wakeFollowUpWorkItems = created }
    }

    private func stopNetworkObservers() {
        if DispatchQueue.getSpecific(key: Self.queueKey) == nil {
            queue.sync { self.stopNetworkObservers() }
            return
        }
        networkChangeGate.stop()
        latestNetworkPath = nil
        startupNetworkSnapshot = nil
        if let networkStateStore { SCDynamicStoreSetDispatchQueue(networkStateStore, nil) }
        networkStateStore = nil
        let (monitor, observers, followUps, pending) = lock.withLock {
            let values = (pathMonitor, wakeObservers, wakeFollowUpWorkItems, pendingRebind)
            pathMonitor = nil; wakeObservers = []; wakeFollowUpWorkItems = []; pendingRebind = nil
            return values
        }
        followUps.forEach { $0.cancel() }
        pending?.cancel()
        monitor?.cancel()
        for observer in observers {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
    }

    private func scheduleRebindCheck(_ ticket: EnhancedNetworkChangeGate.Ticket,
                                     after readinessDelay: TimeInterval = 0) {
        guard isRequested, state != nil || requestedRecoveryPending else { return }
        let authority = lock.withLock { (connectionRequestEpoch, requestedConfigurationRevision) }
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.networkChangeGate.pendingTicket == ticket else { return }
            if !self.isCurrentConnectionRequest(epoch: authority.0, revision: authority.1),
               self.isCurrentConnectionRequest(epoch: authority.0), self.state != nil, !self.cleanupPending,
               self.ownedSessionToken != nil,
               self.startupTicket.map({ self.startupIntent.isCurrent($0) }) == true,
               let replacement = self.networkChangeGate.reissuePending(ticket) {
                // A still-requested owner must not wait for the five-second
                // monitor because its configuration changed during a probe.
                // Fresh authority gets a fresh ticket; this old body exits.
                self.scheduleRebindCheck(replacement)
                return
            }
            guard self.isCurrentConnectionRequest(epoch: authority.0, revision: authority.1),
                  self.state != nil || self.requestedRecoveryPending else {
                // Retire only this exact old work. Its later perform() cannot
                // clear a newer pending ticket or revive a stopped request.
                if let stale = self.networkChangeGate.take(ticket) {
                    self.lock.withLock { self.pendingRebind = nil }
                    self.networkChangeGate.finished(stale, succeeded: false)
                }
                return
            }
            // A short readiness probe also covers a missed DHCP/path event.
            // Compare fresh state before consuming the old ticket; a real
            // ready identity is handled immediately with its current payload.
            if let changed = self.networkChangeGate.observe(
                self.physicalNetworkSnapshot(), session: self.networkChangeGate.session) {
                self.scheduleRebindCheck(changed)
                return
            }
            guard let change = self.networkChangeGate.take(ticket) else { return }
            self.lock.withLock { self.pendingRebind = nil }
            if self.state == nil { self.attemptRequestedStart(change: change) }
            else { self.rebindOutboundIfNeeded(change: change) }
        }
        let previous: DispatchWorkItem? = lock.withLock {
            let old = pendingRebind
            pendingRebind = work
            return old
        }
        previous?.cancel()
        let delay = state == nil
            ? max(readinessDelay, nextRequestedStartAt - ProcessInfo.processInfo.systemUptime) : readinessDelay
        if delay > 0 { queue.asyncAfter(deadline: .now() + delay, execute: work) }
        else { queue.async(execute: work) }
    }

    private func requestNetworkRebind() {
        guard state != nil, !cleanupPending, let ticket = startupTicket,
              startupIntent.isCurrent(ticket),
              let retry = networkChangeGate.requestRecovery(
                physicalNetworkSnapshot(), session: networkChangeGate.session) else { return }
        scheduleRebindCheck(retry)
    }

    private func rebindOutboundIfNeeded(change: EnhancedNetworkChangeGate.Action) {
        guard isRequested, state != nil, !cleanupPending,
              let ticket = startupTicket, startupIntent.isCurrent(ticket),
              let token = ownedSessionToken, let engine = boundEngine,
              let configuration = pendingConfiguration ?? lock.withLock({ appliedConfiguration }) else { return }
        let authority = lock.withLock { (connectionRequestEpoch, requestedConfigurationRevision) }
        let recoveringConfiguration = pendingConfiguration != nil
        var applied = false
        var readinessDeferred = false
        defer {
            networkChangeGate.finished(change, succeeded: applied)
            if readinessDeferred, !applied, !cleanupPending, ownedSessionToken == token,
               startupIntent.isCurrent(ticket),
               isCurrentConnectionRequest(epoch: authority.0, revision: authority.1),
               let retry = networkChangeGate.retryReadinessSoon(session: networkChangeGate.session) {
                scheduleRebindCheck(retry.ticket, after: retry.delay)
            }
        }
        if !change.retrying {
            ProxyEngine.flushCachedOutboundInterfaces()
            ProxyBypassAddresses.invalidateCache()
            invalidateBypassRefresh()
            // Cached answers and idle TLS streams belong to the old uplink.
            // A failed plumbing retry must not repeatedly cancel fresh DNS.
            engine.flushDNS(prewarm: false)
            router?.flushDNS(prewarm: false)
        }
        let generation = configurationGeneration
        // Keep the existing physical binding while offline. Clearing it would
        // allow a new outbound to follow its own utun routes.
        let currentNetwork = physicalNetworkSnapshot()
        if change.snapshot.available, currentNetwork.available,
           !currentNetwork.hasSameIdentity(as: change.snapshot),
           let updated = networkChangeGate.observe(currentNetwork, session: networkChangeGate.session) {
            scheduleRebindCheck(updated)
            return
        }
        guard change.snapshot.available, currentNetwork.available,
              currentNetwork.hasSameIdentity(as: change.snapshot),
              let physical = try? defaultInterface(), physical == currentNetwork.interfaceName else {
            readinessDeferred = true
            if let ticket = startupTicket { startupIntent.markFailure(ticket) }
            emitWaiting("物理网络已断开，增强模式保持开启并等待网络恢复")
            return
        }
        guard let reloadTicket = startupIntent.beginReload() else { return }
        defer { _ = startupIntent.finishReload(reloadTicket, success: applied) }
        // DNS work from the previous uplink must not replace the routes
        // computed for the new gateway, even if the profile is unchanged.
        do { try bindOutbound(engine: engine, physical: physical) }
        catch {
            readinessDeferred = true
            emitWaiting("物理网络接口 \(physical) 正在就绪，等待恢复增强模式")
            return
        }
        guard startupIntent.isCurrent(reloadTicket), configurationGeneration == generation,
              isCurrentConnectionRequest(epoch: authority.0, revision: authority.1) else { return }
        do {
            // The verified node inventory remains valid for this unchanged
            // profile while secure DNS refresh is pending. Reconcile even on
            // the same interface: its gateway may have changed although the
            // node address list did not. Never publish a partial DNS result.
            let bypass: [String]
            if recoveringConfiguration || change.forcedByWake {
                router?.update(profile: configuration.profile, mode: configuration.mode,
                               globalPolicy: configuration.globalPolicy,
                               groupSelections: configuration.groupSelections)
                let collected = ProxyBypassAddresses.collect(
                    profile: configuration.profile, mode: configuration.mode,
                    globalPolicy: configuration.globalPolicy,
                    groupSelections: configuration.groupSelections)
                if recoveringConfiguration {
                    bypass = collected.isEmpty ? lastBypassAddresses : collected
                } else {
                    bypass = Self.normalizedBypass(lastBypassAddresses + collected)
                }
            } else {
                bypass = lastBypassAddresses
            }
            guard startupIntent.isCurrent(reloadTicket), configurationGeneration == generation,
                  isCurrentConnectionRequest(epoch: authority.0, revision: authority.1) else {
                throw ManagerError.startCancelled
            }
            let helperState = try helper.reload(
                fakeIPEnabled: configuration.profile.shouldHijackSystemDNS,
                bypassAddresses: bypass,
                excludedRoutes: configuration.profile.tunExcludedRoutes,
                includedRoutes: configuration.profile.tunIncludedRoutes,
                sessionToken: token)
            guard let value = Self.state(from: helperState), value.physicalInterface == physical,
                  helperState.sessionToken == token else {
                throw ManagerError.invalidHelperState
            }
            guard startupIntent.isCurrent(reloadTicket), configurationGeneration == generation,
                  isCurrentConnectionRequest(epoch: authority.0, revision: authority.1) else {
                throw ManagerError.startCancelled
            }
            lastBypassAddresses = Self.normalizedBypass(bypass)
            NativeOutboundFactory.invalidateForNetworkChange()
            tunnel?.resetFlows()
            setState(value)
            setAppliedConfiguration(configuration)
            pendingConfiguration = nil
            guard startupIntent.finishReload(reloadTicket, success: true) else { throw ManagerError.startCancelled }
            applied = true
            lastWaitingMessage = nil
            engine.flushDNS(prewarm: true)
            router?.flushDNS(prewarm: true)
            emit(.running(interface: value.tunnelInterface,
                          physicalInterface: value.physicalInterface))
            refreshBypassRoutesIfNeeded()
        } catch {
            if case PrivilegedHelperClient.ClientError.physicalNetworkNotReady = error {
                readinessDeferred = true
                emitWaiting("Wi-Fi 已连接，正在等待网关就绪后恢复增强模式")
                return
            }
            emit(.failed("网络切换后重新绑定 root Helper 失败：\(error.localizedDescription)"))
        }
    }

    /// Re-resolves the currently selected proxy hosts and, if the set of
    /// physical-gateway bypass addresses changed, asks the helper to replace
    /// the host routes. The data plane stays up.
    private func refreshBypassRoutesIfNeeded() {
        guard state != nil, !cleanupPending, let token = ownedSessionToken,
              bypassRefreshInFlight == nil, pendingConfiguration == nil,
              !routingReloadGate.needsRecovery else { return }
        guard let configuration = lock.withLock({ appliedConfiguration }) else { return }
        let network = physicalNetworkSnapshot()
        guard network.available else { return }
        let generation = configurationGeneration
        bypassRefreshInFlight = generation
        let profile = configuration.profile
        let mode = configuration.mode
        let globalPolicy = configuration.globalPolicy
        let groupSelections = configuration.groupSelections
        ProxyBypassAddresses.collectAsync(
            profile: profile, mode: mode, globalPolicy: globalPolicy,
            groupSelections: groupSelections, queue: queue) { [weak self] resolution in
                guard let self else { return }
                guard Self.isCurrentBypassRefresh(
                    capturedGeneration: generation,
                    currentGeneration: self.configurationGeneration,
                    inFlightGeneration: self.bypassRefreshInFlight) else { return }
                self.bypassRefreshInFlight = nil
                guard self.state != nil, !self.cleanupPending, self.ownedSessionToken == token,
                      self.pendingConfiguration == nil, !self.routingReloadGate.needsRecovery,
                      self.lock.withLock({ self.appliedConfiguration != nil }) else { return }
                let currentNetwork = self.physicalNetworkSnapshot()
                guard currentNetwork.available, currentNetwork.hasSameIdentity(as: network) else {
                    self.requestNetworkRebind()
                    return
                }
                guard case .success(let bypass) = resolution else {
                    self.queue.asyncAfter(deadline: .now() + 2) { [weak self] in
                        guard let self, self.configurationGeneration == generation else { return }
                        self.refreshBypassRoutesIfNeeded()
                    }
                    return
                }
                let normalized = Self.normalizedBypass(bypass)
                guard Self.shouldReplaceBypass(previous: self.lastBypassAddresses,
                                               next: normalized) else { return }
                guard let reloadTicket = self.startupIntent.beginReload() else { return }
                do {
                    let helperState = try self.helper.reload(
                        fakeIPEnabled: profile.shouldHijackSystemDNS,
                        bypassAddresses: bypass,
                        excludedRoutes: profile.tunExcludedRoutes,
                        includedRoutes: profile.tunIncludedRoutes,
                        sessionToken: token)
                    guard Self.state(from: helperState) != nil else { throw ManagerError.invalidHelperState }
                    guard self.startupIntent.finishReload(reloadTicket, success: true) else { throw ManagerError.startCancelled }
                    self.lastBypassAddresses = normalized
                } catch {
                    _ = self.startupIntent.finishReload(reloadTicket, success: false)
                    if case PrivilegedHelperClient.ClientError.physicalNetworkNotReady = error {
                        self.requestNetworkRebind()
                    }
                    // Preflight can defer without changing routes. Other
                    // errors may stop the Helper; monitorOnce verifies its ACK.
                }
        }
    }

    private static func normalizedBypass(_ addresses: [String]) -> [String] {
        Array(Set(addresses.map { $0.lowercased() })).sorted()
    }

    /// Pure version check: a superseded DNS completion must not clear a newer
    /// in-flight refresh or apply its old DNS/routes/DNS-hijack settings.
    static func isCurrentBypassRefresh(capturedGeneration: UInt64,
                                       currentGeneration: UInt64,
                                       inFlightGeneration: UInt64?) -> Bool {
        capturedGeneration == currentGeneration &&
            inFlightGeneration == capturedGeneration
    }

    /// A periodic resolve that lost records (timeout, NXDOMAIN blip) must not
    /// tear down working host routes. Apply the new set when it adds an
    /// address or is a genuine replacement, not when it is only a subset.
    static func shouldReplaceBypass(previous: [String], next: [String]) -> Bool {
        guard next != previous else { return false }
        if next.isEmpty { return false }
        if previous.isEmpty { return true }
        return !Set(next).isSubset(of: Set(previous))
    }

    private func monitorOnce() {
        do {
            let helperState = try helper.status()
            let recovered = monitorFailures >= 3
            monitorFailures = 0
            if let value = Self.state(from: helperState), tunnel != nil,
               helperState.sessionToken == ownedSessionToken, !cleanupPending {
                setState(value)
                // This poll uses current physical state. A cached unsatisfied
                // NWPath must not veto recovery when its next event is lost.
                let network = physicalNetworkSnapshot()
                if let changed = networkChangeGate.observe(network, session: networkChangeGate.session) {
                    scheduleRebindCheck(changed)
                }
                if lock.withLock({ appliedConfiguration != nil }),
                   let retry = networkChangeGate.retry(session: networkChangeGate.session) {
                    scheduleRebindCheck(retry)
                }
                if network.available,
                   (startupIntent.snapshot.needsRecovery || lastWaitingMessage != nil || value.physicalInterface != network.interfaceName),
                   networkChangeGate.pendingTicket == nil {
                    requestNetworkRebind()
                }
                let networkReady = network.available && networkChangeGate.pendingTicket == nil
                    && pendingConfiguration == nil && !routingReloadGate.needsRecovery
                if networkReady, !startupIntent.snapshot.needsRecovery, let ticket = startupTicket {
                    _ = startupIntent.confirmHealthy(ticket)
                }
                if (recovered || lastWaitingMessage != nil), networkReady, startupIntent.snapshot.isReady {
                    lastWaitingMessage = nil
                    emit(.running(interface: value.tunnelInterface,
                                  physicalInterface: value.physicalInterface))
                }
                if !network.available {
                    if let ticket = startupTicket { startupIntent.markFailure(ticket) }
                    emitWaiting("物理网络已断开，增强模式保持开启并等待网络恢复")
                }
            } else if ownedSessionToken != nil || tunnel != nil {
                stopHeartbeat()
                startupIntent.cancel()
                cancelMonitorTimer()
                lastBypassAddresses = []
                stopNetworkObservers()
                setAppliedConfiguration(nil)
                recoverAfterCleanup = isRequested
                if helperState.networkCleanupPending == false,
                   helperState.lastRestoredSessionToken == ownedSessionToken {
                    releaseLocalResources(engine: boundEngine, cancelledTicket: startupTicket)
                    if isRequested {
                        waitForRequestedConnection("原隧道已安全清理，增强模式保持开启并将自动重新连接")
                        checkRequestedConnection()
                    } else { emit(.stopped) }
                } else {
                    cleanupPending = true
                    if let ticket = startupTicket { startupIntent.markRecovery(ticket) }
                    beginNetworkRecovery()
                    if isRequested {
                        emitWaiting("正在等待原隧道路由与 DNS 恢复确认，随后自动重新连接")
                    } else { emit(.failed("root Helper 正在恢复系统网络")) }
                }
            }
        } catch {
            monitorFailures += 1
            if monitorFailures == 3 {
                if let ticket = startupTicket { startupIntent.markFailure(ticket) }
                emit(.failed("暂时无法连接 root Helper：\(error.localizedDescription)"))
            }
        }
    }

    private func defaultInterface() throws -> String {
        let routeInterface: ([String]) -> String? = { arguments in
            let process = Process(); let output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/sbin/route")
            process.arguments = arguments
            process.standardOutput = output; process.standardError = FileHandle.nullDevice
            guard (try? process.run()) != nil else { return nil }
            process.waitUntilExit()
            let text = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            for line in text.components(separatedBy: .newlines) {
                let pair = line.trimmingCharacters(in: .whitespaces)
                    .split(separator: ":", maxSplits: 1).map(String.init)
                if pair.count == 2, pair[0] == "interface" {
                    let value = pair[1].trimmingCharacters(in: .whitespaces)
                    if Self.isPhysicalInterfaceName(value) { return value }
                }
            }
            return nil
        }
        if let direct = routeInterface(["-n", "get", "default"]) {
            return direct
        }
        let global4 = networkState("State:/Network/Global/IPv4")
        let global6 = networkState("State:/Network/Global/IPv6")
        var candidates: [String] = []
        for raw in [global4["PrimaryInterface"] as? String,
                    global6["PrimaryInterface"] as? String,
                    Self.firstActivePhysicalInterface()] {
            if let name = raw, Self.isPhysicalInterfaceName(name), !candidates.contains(name) {
                candidates.append(name)
            }
        }
        for candidate in candidates {
            let local = Self.interfaceAddresses(candidate)
            guard local.up, !local.addresses.isEmpty else { continue }
            if let scoped = routeInterface(["-n", "get", "-ifscope", candidate, "default"]),
               scoped == candidate {
                return candidate
            }
            let state4 = networkState("State:/Network/Interface/\(candidate)/IPv4")
            let router = (state4["Router"] as? String)
                ?? ((global4["PrimaryInterface"] as? String == candidate) ? (global4["Router"] as? String) : nil)
            if let router, !router.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return candidate
            }
        }
        throw ManagerError.defaultInterfaceMissing
    }

    private static func state(from value: HajimiHelperTunnelState) -> State? {
        guard value.running, value.phase == .running, value.networkCleanupPending == false,
              value.sessionToken != nil, let tunnel = value.tunnelInterface,
              let physical = value.physicalInterface else { return nil }
        return State(tunnelInterface: tunnel, physicalInterface: physical,
                     startedAt: value.startedAt ?? Date(),
                     dataPlane: value.dataPlane)
    }

    private func setState(_ value: State?) { lock.withLock { cachedState = value } }
    private func invalidateBypassRefresh() {
        configurationGeneration &+= 1
        bypassRefreshInFlight = nil
    }
    private func setAppliedConfiguration(_ value: AppliedConfiguration?) {
        let update = {
            self.lock.withLock { self.appliedConfiguration = value }
            if let value { self.routingReloadGate.recordApplied(value) }
            else {
                self.pendingConfiguration = nil
                self.routingReloadGate.reset()
            }
            self.invalidateBypassRefresh()
        }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { update() }
        else { queue.sync(execute: update) }
    }
    private func emit(_ status: Status) {
        let epoch = lock.withLock { connectionRequestEpoch }
        DispatchQueue.main.async {
            guard self.lock.withLock({ self.connectionRequestEpoch == epoch }) else { return }
            switch status {
            case .starting, .running, .waitingForNetwork:
                guard self.isRequested else { return }
            case .stopped, .stopping, .failed: break
            }
            self.onStatus?(status)
        }
    }
    private func emitStatistics(active: Int, total: Int, up: UInt64, down: UInt64) {
        DispatchQueue.main.async {
            self.onStatistics?(active, total, up, down)
        }
    }
}

// MARK: - Proxy bypass address collection (App-side DNS)

enum ProxyBypassAddresses {
    typealias Resolver = (String, DispatchQueue,
                          @escaping (Result<[String], Error>) -> Void) -> (() -> Void)
    private static let cache = ProxyBypassAddressCache()

    /// The synchronous reload API may only inspect literals and fresh answers
    /// already obtained from encrypted DNS. It must never wait for DNS or use
    /// getaddrinfo on the UI/enhanced-mode serial queue.
    static func collect(profile: Profile, mode: OutboundMode, globalPolicy: String,
                        groupSelections: [String: String]) -> [String] {
        let hosts = selectedHosts(profile: profile, mode: mode, globalPolicy: globalPolicy,
                                  groupSelections: groupSelections)
        var addresses = cachedAddresses(for: hosts, cache: cache)
        var seen = Set(addresses)
        for host in hosts where numericAddress(host) == nil {
            for addr in cache.addresses(for: host, allowStaleWithinGeneration: true)
                where seen.insert(addr).inserted {
                addresses.append(addr)
            }
            for addr in SecureDNSHostResolver.shared.cachedAddresses(for: host, allowStaleWithinGeneration: true)
                where seen.insert(addr).inserted {
                addresses.append(addr)
            }
        }
        if mode != .direct {
            for proxy in profile.proxies.values where addresses.count < 64 {
                guard let rawHost = proxy.host?.trimmingCharacters(in: .whitespacesAndNewlines),
                      !rawHost.isEmpty, numericAddress(rawHost) == nil else { continue }
                for addr in cache.addresses(for: rawHost, allowStaleWithinGeneration: true)
                    where seen.insert(addr).inserted && addresses.count < 64 {
                    addresses.append(addr)
                }
                for addr in SecureDNSHostResolver.shared.cachedAddresses(for: rawHost, allowStaleWithinGeneration: true)
                    where seen.insert(addr).inserted && addresses.count < 64 {
                    addresses.append(addr)
                }
            }
        }
        return addresses
    }

    /// Used before the first tunnel installation and by periodic refresh.
    /// Missing proxy hosts fail closed rather than publishing an incomplete
    /// bypass inventory as ready. The whole collection has one four-second
    /// deadline; no caller queue is blocked while encrypted DNS is pending.
    static func collectAsync(profile: Profile, mode: OutboundMode, globalPolicy: String,
                             groupSelections: [String: String], queue: DispatchQueue,
                             completion: @escaping (Result<[String], Error>) -> Void) {
        let hosts = selectedHosts(profile: profile, mode: mode, globalPolicy: globalPolicy,
                                  groupSelections: groupSelections)
        let generation = cache.generation
        let selectedLower = Set(hosts.map { $0.lowercased() })
        for proxy in profile.proxies.values {
            guard let rawHost = proxy.host?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !rawHost.isEmpty, numericAddress(rawHost) == nil,
                  !selectedLower.contains(rawHost.lowercased()) else { continue }
            _ = SecureDNSHostResolver.shared.resolve(host: rawHost, queue: queue) { result in
                if case .success(let rawAddresses) = result {
                    var seen = Set<String>()
                    let values = rawAddresses.compactMap(numericAddress)
                        .filter { !$0.hasPrefix("fe80:") && seen.insert($0).inserted }
                    if !values.isEmpty {
                        cache.store(Array(values.prefix(16)), for: rawHost, generation: generation)
                    }
                }
            }
        }
        resolve(hosts: hosts, cache: cache, queue: queue, resolver: { host, callbackQueue, done in
            let id = SecureDNSHostResolver.shared.resolve(host: host, queue: callbackQueue,
                                                         completion: done)
            return { if let id { SecureDNSHostResolver.shared.cancel(id) } }
        }, completion: completion)
    }

    static func invalidateCache() {
        cache.invalidate()
        SecureDNSHostResolver.shared.flush()
    }

    static func selectedHosts(profile: Profile, mode: OutboundMode, globalPolicy: String,
                              groupSelections: [String: String]) -> [String] {
        var hosts: [String] = []
        var seen = Set<String>()
        var expandedPolicyDepths: [String: Int] = [:]
        func appendHost(_ raw: String?) {
            guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !raw.isEmpty else { return }
            let key = raw.lowercased()
            guard seen.insert(key).inserted else { return }
            hosts.append(raw)
        }
        func appendProxy(_ name: String, depth: Int = 0) {
            let key = name.lowercased()
            guard depth < 8, expandedPolicyDepths[key].map({ depth < $0 }) ?? true else { return }
            expandedPolicyDepths[key] = depth
            if let group = profile.groups[name] ?? profile.groups.first(where: {
                $0.key.caseInsensitiveCompare(name) == .orderedSame
            })?.value {
                if group.kind == .select || group.kind == .subnet {
                    let selected = groupSelections[group.name] ?? group.members.first ?? "DIRECT"
                    appendProxy(selected, depth: depth + 1)
                } else {
                    // Health-ranked and balanced groups can use any member.
                    for member in group.members { appendProxy(member, depth: depth + 1) }
                }
                return
            }
            let proxy = profile.proxies[name] ?? profile.proxies.first(where: {
                $0.key.caseInsensitiveCompare(name) == .orderedSame
            })?.value
            guard let proxy else { return }
            switch proxy.kind {
            case .http, .socks5, .native, .external:
                appendHost(proxy.host)
                if let underlying = proxy.parameters["underlying-proxy"]
                    ?? proxy.parameters["underlying_proxy"]
                    ?? proxy.parameters["dialer-proxy"] {
                    appendProxy(underlying, depth: depth + 1)
                }
            case .direct, .reject:
                break
            }
        }
        switch mode {
        case .direct: break
        case .proxy:
            appendProxy(globalPolicy)
        case .rule:
            appendProxy(globalPolicy)
            for (_, selected) in groupSelections { appendProxy(selected) }
            for rule in profile.rules { appendProxy(rule.policy) }
        }
        // Include configured literal nodes without DNS work, preserving the
        // previous collector's ability to switch to a literal backup safely.
        for proxy in profile.proxies.values {
            if let host = proxy.host, numericAddress(host) != nil { appendHost(host) }
        }
        return hosts
    }

    static func cachedAddresses(for hosts: [String], cache: ProxyBypassAddressCache,
                                now: Date = Date()) -> [String] {
        var addresses: [String] = []
        var addressSeen = Set<String>()
        for host in hosts {
            let resolved = numericAddress(host).map { [$0] } ?? cache.addresses(for: host, now: now)
            for address in resolved where addressSeen.insert(address).inserted {
                addresses.append(address)
            }
        }
        return addresses
    }

    static func numericAddress(_ host: String) -> String? {
        var v4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &v4, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
            return String(cString: buffer)
        }
        var v6 = in6_addr()
        guard host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &v6, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
        return String(cString: buffer).lowercased()
    }

    static func resolve(hosts: [String], cache: ProxyBypassAddressCache,
                        queue: DispatchQueue, timeout: TimeInterval = 4,
                        resolver: @escaping Resolver,
                        completion: @escaping (Result<[String], Error>) -> Void) {
        let work = DispatchQueue(label: "app.hajimi.encrypted-bypass-collector", qos: .utility)
        let generation = cache.generation
        work.async {
            var answers: [String: [String]] = [:]
            var unresolved: [String] = []
            var seen = Set<String>()
            for host in hosts where seen.insert(host.lowercased()).inserted {
                if let address = numericAddress(host) { answers[host] = [address] }
                else { unresolved.append(host) }
            }
            guard unresolved.count <= 128 else {
                queue.async { completion(.failure(ProxyBypassCollectionError.tooManyHosts)) }
                return
            }
            var pending = Set(unresolved)
            var finished = false
            var cancellations: [() -> Void] = []
            var deadline: DispatchWorkItem?
            func finish() {
                guard !finished else { return }
                finished = true
                deadline?.cancel()
                deadline = nil
                cancellations.forEach { $0() }
                cancellations.removeAll()
                let result: Result<[String], Error>
                if generation != cache.generation {
                    result = .failure(ProxyBypassCollectionError.networkChanged)
                } else {
                    let missing = unresolved.filter { answers[$0]?.isEmpty != false }
                    if !missing.isEmpty {
                        result = .failure(ProxyBypassCollectionError.unresolved(missing))
                    } else {
                        var addressSeen = Set<String>()
                        let addresses = hosts.flatMap { answers[$0] ?? [] }
                            .filter { addressSeen.insert($0).inserted }
                        result = .success(addresses)
                    }
                }
                queue.async { completion(result) }
            }
            guard !unresolved.isEmpty else { finish(); return }
            let expiry = DispatchWorkItem { finish() }
            deadline = expiry
            work.asyncAfter(deadline: .now() + max(0.01, timeout), execute: expiry)
            for host in unresolved {
                let cancel = resolver(host, work) { result in
                    work.async {
                        guard !finished, pending.remove(host) != nil else { return }
                        if case .success(let rawAddresses) = result {
                            var addressSeen = Set<String>()
                            let values = rawAddresses.compactMap(numericAddress)
                                .filter { !$0.hasPrefix("fe80:") && addressSeen.insert($0).inserted }
                            if !values.isEmpty {
                                answers[host] = Array(values.prefix(16))
                                cache.store(answers[host] ?? [], for: host, generation: generation)
                            }
                        }
                        if pending.isEmpty { finish() }
                    }
                }
                cancellations.append(cancel)
            }
        }
    }
}

enum ProxyBypassCollectionError: LocalizedError {
    case unresolved([String])
    case networkChanged
    case tooManyHosts

    var errorDescription: String? {
        switch self {
        case .unresolved(let hosts):
            return "无法通过加密 DNS 解析所选代理服务器（\(hosts.prefix(3).joined(separator: "、"))），增强模式未声明就绪；未回退系统 DNS"
        case .networkChanged: return "代理地址解析期间网络发生变化，请重试增强模式"
        case .tooManyHosts: return "所选代理服务器域名超过安全解析上限（128），请减少活动策略后重试"
        }
    }
}

/// This small, App-side cache is only for nonblocking route reloads. Its
/// lifetime is bounded and every network generation invalidates late results.
final class ProxyBypassAddressCache {
    private struct Entry {
        let addresses: [String]
        let expiry: Date
    }
    private let lock = NSLock()
    private var entries: [String: Entry] = [:]
    private var staleEntries: [String: Entry] = [:]
    private var version: UInt64 = 0
    var generation: UInt64 { lock.withLock { version } }

    func addresses(for host: String, now: Date = Date(),
                   allowStaleWithinGeneration: Bool = false) -> [String] {
        lock.withLock {
            let key = host.lowercased()
            if let entry = entries[key] {
                if entry.expiry > now {
                    return entry.addresses
                }
                entries.removeValue(forKey: key)
            }
            if allowStaleWithinGeneration, let stale = staleEntries[key], stale.expiry > now {
                return stale.addresses
            }
            return []
        }
    }

    func store(_ addresses: [String], for host: String, generation: UInt64,
               now: Date = Date()) {
        lock.withLock {
            guard generation == version, !addresses.isEmpty else { return }
            let key = host.lowercased()
            if entries[key] == nil, entries.count >= 128 {
                entries = entries.filter { $0.value.expiry > now }
                if entries.count >= 128 { entries.removeAll(keepingCapacity: true) }
            }
            if staleEntries[key] == nil, staleEntries.count >= 256 {
                staleEntries = staleEntries.filter { $0.value.expiry > now }
                if staleEntries.count >= 256 { staleEntries.removeAll(keepingCapacity: true) }
            }
            entries[key] = Entry(addresses: addresses, expiry: now.addingTimeInterval(60))
            staleEntries[key] = Entry(addresses: addresses, expiry: now.addingTimeInterval(3_600))
        }
    }

    func invalidate() {
        lock.withLock {
            version &+= 1
            entries.removeAll()
            staleEntries.removeAll()
        }
    }
}

/// Injected DNS fixtures only. Never constructs EnhancedModeManager, invokes
/// the shared network resolver, launches the helper, or changes system routes.
enum ProxyBypassAddressSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }

    static func run() throws {
        func expect(_ value: Bool, _ message: String) throws {
            if !value { throw Failure(text: message) }
        }
        let cache = ProxyBypassAddressCache()
        let epoch = Date(timeIntervalSince1970: 1_000)
        let firstGeneration = cache.generation
        cache.store(["203.0.113.7"], for: "Node.Example.Test", generation: firstGeneration,
                    now: epoch)
        try expect(cache.addresses(for: "node.example.test", now: epoch.addingTimeInterval(59)) ==
                   ["203.0.113.7"], "安全地址缓存应支持域名大小写规范化")
        try expect(cache.addresses(for: "node.example.test", now: epoch.addingTimeInterval(60)).isEmpty,
                   "同步重载不得使用已经过期的安全 DNS 地址")
        cache.invalidate()
        cache.store(["203.0.113.8"], for: "node.example.test", generation: firstGeneration)
        try expect(cache.addresses(for: "node.example.test").isEmpty,
                   "旧网络的迟到 DNS 结果不得重新填入新网络缓存")

        let profile = try ProfileParser.parse("""
        [Proxy]
        Node = https, node.example.test, 443, sni=node.example.test
        Unused = http, unused.example.test, 8080
        Literal = socks5, 203.0.113.9, 1080
        Parent = http, parent.example.test, 8080
        Child = socks5, child.example.test, 1080, underlying-proxy=Parent
        [Proxy Group]
        Selected = select, Node, Unused
        Balanced = load-balance, Node, Unused
        [Rule]
        FINAL,Selected
        """)
        let selected = ProxyBypassAddresses.selectedHosts(profile: profile, mode: .proxy,
                                                          globalPolicy: "Selected",
                                                          groupSelections: [:])
        try expect(selected.contains("node.example.test") && !selected.contains("unused.example.test") &&
                   selected.contains("203.0.113.9"),
                   "首启只应强制引导所选节点，未选备选域名不能阻止连接")
        let switched = ProxyBypassAddresses.selectedHosts(profile: profile, mode: .rule,
                                                          globalPolicy: "DIRECT",
                                                          groupSelections: ["Selected": "Unused"])
        try expect(switched.contains("unused.example.test") && !switched.contains("node.example.test"),
                   "规则与策略组选择必须对应真正使用的代理域名")
        let chained = ProxyBypassAddresses.selectedHosts(profile: profile, mode: .proxy,
                                                         globalPolicy: "Child", groupSelections: [:])
        try expect(chained.contains("parent.example.test") && chained.contains("child.example.test"),
                   "链式代理的节点和首跳域名都必须安全引导")
        let balanced = ProxyBypassAddresses.selectedHosts(profile: profile, mode: .proxy,
                                                          globalPolicy: "Balanced", groupSelections: [:])
        try expect(balanced.contains("node.example.test") && balanced.contains("unused.example.test"),
                   "动态选择成员的策略组必须覆盖所有可能的节点")
        let direct = ProxyBypassAddresses.selectedHosts(profile: profile, mode: .direct,
                                                        globalPolicy: "Selected", groupSelections: [:])
        try expect(direct == ["203.0.113.9"], "直连模式不能查询无关代理服务器域名")
        try expect(profile.proxies["Node"]?.host == "node.example.test" &&
                   profile.proxies["Node"]?.parameters["sni"] == "node.example.test",
                   "安全地址 pin 不能覆盖原始 host/SNI 的证书身份")

        func resolved(_ hosts: [String], using resolver: @escaping ProxyBypassAddresses.Resolver,
                      cache: ProxyBypassAddressCache = ProxyBypassAddressCache(),
                      timeout: TimeInterval = 0.2) throws -> Result<[String], Error> {
            let completionQueue = DispatchQueue(label: "app.hajimi.bypass-dns-self-test.callback")
            let semaphore = DispatchSemaphore(value: 0)
            let lock = NSLock()
            var value: Result<[String], Error>?
            ProxyBypassAddresses.resolve(hosts: hosts, cache: cache, queue: completionQueue,
                                         timeout: timeout, resolver: resolver) { result in
                lock.withLock { value = result }
                semaphore.signal()
            }
            guard semaphore.wait(timeout: .now() + 2) == .success,
                  let result = lock.withLock({ value }) else {
                throw Failure(text: "注入 DNS 收集器没有在期限内完成")
            }
            return result
        }

        var queries = 0
        let literals = try resolved(["203.0.113.1", "2001:0db8::1", "203.0.113.1"], using: { _, _, _ in
            queries += 1
            return {}
        }).get()
        try expect(literals == ["203.0.113.1", "2001:db8::1"] && queries == 0,
                   "IP literal 必须直接去重规范化，不能执行任何 DNS 查询")

        let successfulCache = ProxyBypassAddressCache()
        let secure = try resolved(["203.0.113.1", "node.example.test"], using: { host, _, done in
            queries += 1
            done(.success(["203.0.113.7", "2001:db8::7", "not-an-ip", "fe80::1", "203.0.113.7"]))
            // A buggy resolver's duplicate callback may not overwrite cache.
            done(.success(["203.0.113.200"]))
            return {}
        }, cache: successfulCache).get()
        try expect(secure == ["203.0.113.1", "203.0.113.7", "2001:db8::7"] && queries == 1,
                   "加密解析结果只能接收有效非 link-local IP，并忽略重复回调")
        try expect(ProxyBypassAddresses.cachedAddresses(for: ["node.example.test"],
                                                        cache: successfulCache) ==
                   ["203.0.113.7", "2001:db8::7"],
                   "同步重载应只复用已验证的安全缓存，不能重新调用 DNS")

        let failed = try resolved(["203.0.113.1", "missing.example.test"], using: { _, _, done in
            done(.failure(Failure(text: "injected NXDOMAIN")))
            return {}
        })
        if case .success = failed {
            throw Failure(text: "首启缺少必需域名时，不能仅凭部分 literal 路由宣布就绪")
        }
        var cancellations = 0
        let timeoutResult = try resolved(["timeout.example.test"], using: { _, _, _ in
            return { cancellations += 1 }
        }, timeout: 0.02)
        if case .success = timeoutResult { throw Failure(text: "安全解析超时不能回退系统 DNS") }
        try expect(cancellations == 1, "收集器超时必须取消待处理解析而不是无限等待")

        let changedCache = ProxyBypassAddressCache()
        let changed = try resolved(["old-network.example.test"], using: { _, _, done in
            changedCache.invalidate()
            done(.success(["203.0.113.10"]))
            return {}
        }, cache: changedCache)
        if case .success = changed { throw Failure(text: "网络换代后旧收集不能作为新会话就绪结果") }
        try expect(changedCache.addresses(for: "old-network.example.test").isEmpty,
                   "换代的旧地址不能污染安全缓存")
    }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T {
        lock(); defer { unlock() }
        return body()
    }
}

extension EnhancedModeManager {
    /// Isolated CLI regression of the actual owner entry. The native tunnel
    /// remains unstarted (descriptor -1); FINAL REJECT makes every diagnostic
    /// row an operation-free policy skip. No helper method, network monitor,
    /// listener, profile store, interface enumeration or socket is invoked.
    static func networkDiagnosticsSelfTest() throws {
        struct Failure: LocalizedError {
            let text: String
            var errorDescription: String? { "增强网络诊断归属自检失败：\(text)" }
        }
        final class SnapshotBox {
            private let lock = NSLock()
            private var snapshots: [NetworkConnectivityDiagnosticsSnapshot] = []
            let finished = DispatchSemaphore(value: 0)
            let delivered = DispatchSemaphore(value: 0)
            func add(_ value: NetworkConnectivityDiagnosticsSnapshot) {
                lock.withLock { snapshots.append(value) }
                delivered.signal()
                if !value.isRunning { finished.signal() }
            }
            var last: NetworkConnectivityDiagnosticsSnapshot? { lock.withLock { snapshots.last } }
            var count: Int { lock.withLock { snapshots.count } }
        }
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw Failure(text: text) }
        }
        try require(ProxyEngine.currentOutboundInterface == nil, "必须在无运行出口绑定的独立自检进程执行")
        let manager = EnhancedModeManager(applicationSupportDirectory:
            URL(fileURLWithPath: "/dev/null/hajimi-network-diagnostics-self-test", isDirectory: true))
        let callbacks = DispatchQueue(label: "app.hajimi.enhanced-diagnostics-owner-selftest")
        var requests: [NetworkDiagnosticsRequest] = []
        var pendingRelease: DispatchSemaphore?
        defer {
            pendingRelease?.signal()
            requests.forEach { $0.cancel() }
            manager.queue.sync {
                // Clear synthetic ownership before deinit can consider a
                // Helper teardown. No test installs an owned Helper session.
                manager.ownedSessionToken = nil
                manager.cleanupPending = false
                if let ticket = manager.startupTicket {
                    manager.startupIntent.cancel()
                    manager.startupIntent.confirmStopped(ticket)
                }
                manager.startupTicket = nil
                manager.setState(nil)
                manager.router = nil
                manager.tunnel = nil
            }
        }
        func detect() throws -> NetworkConnectivityDiagnosticsSnapshot {
            let box = SnapshotBox()
            requests.append(manager.startNetworkDiagnostics(callbackQueue: callbacks, onUpdate: box.add))
            try require(box.finished.wait(timeout: .now() + 2) == .success, "归属入口未交付终态快照")
            guard let snapshot = box.last else { throw Failure(text: "归属入口缺失快照") }
            try require(!snapshot.isRunning && snapshot.rows.count == 4, "固定回归轮次未正常完成四项检查")
            return snapshot
        }
        func unavailable(_ snapshot: NetworkConnectivityDiagnosticsSnapshot) -> Bool {
            snapshot.rows.allSatisfy {
                $0.status == .skipped && $0.endpoint.isEmpty && $0.route == "未启动"
                    && $0.detail == "增强模式尚未就绪或正在恢复网络；请等待后重新检测"
            }
        }

        let stopped = try detect()
        try require(unavailable(stopped), "无TUN会话却进入了可用路由器")
        var profile = Profile()
        profile.dnsPrewarmEnabled = false
        profile.dnsServers = ["192.0.2.53"]
        profile.encryptedDNSServers = ["https://dns.fixture.invalid/dns-query#192.0.2.54"]
        profile.rules = [.init(kind: .final, policy: "REJECT", sourceLine: 1)]
        let router = NativePacketRouter(profile: profile, mode: .rule, globalPolicy: "REJECT", groupSelections: [:])
        let tunnel = try NativeTunnel(router: router)
        try manager.queue.sync {
            guard let ticket = manager.startupIntent.reserve() else { throw Failure(text: "无法保留合成启动意图") }
            manager.startupTicket = ticket
            manager.ownedSessionToken = "memory-only-network-diagnostics-owner"
            manager.router = router
            manager.tunnel = tunnel
            manager.setState(State(tunnelInterface: "utun-fixture", physicalInterface: "en-fixture",
                startedAt: Date(timeIntervalSince1970: 1), dataPlane: "memory-only-unstarted"))
            manager.startupIntent.markOwned(ticket)
            manager.startupIntent.markRunning(ticket)
        }
        try require(manager.queue.sync { manager.boundEngine == nil }, "回归意外依赖监听引擎")
        let live = try detect()
        try require(live.rows.allSatisfy { $0.status == .skipped }, "拒绝规则轮次创建了可运行操作")
        try require(live.rows.map(\.id) == ["localLatency", "proxyLatency", "traditionalDNS-0", "encryptedDNS-0"],
                    "已有TUN路由器未进入实际诊断计划")
        try require(live.rows.filter { $0.kind == .localLatency || $0.kind == .proxyLatency }.allSatisfy {
            $0.endpoint == "http://captive.apple.com:80" && $0.detail == "固定 HTTP 测试目标被当前规则拒绝"
        }, "监听器未启动时HTTP检查错误显示核心未就绪")
        try require(live.rows.first { $0.kind == .traditionalDNS }?.detail == "普通 DNS 端点或固定测试域名被当前规则拒绝",
                    "普通DNS未使用TUN已有拒绝规则")
        try require(live.rows.first { $0.kind == .encryptedDNS }?.detail == "固定查询或该加密 DNS 端点未获当前规则许可",
                    "加密DNS未使用TUN已有许可计划")
        try require(tunnel.interfaceName == nil, "未启动的内存隧道获得了真实网卡")

        manager.queue.sync {
            manager.cleanupPending = true
            if let ticket = manager.startupTicket { manager.startupIntent.markRecovery(ticket) }
        }
        let recovering = try detect()
        try require(unavailable(recovering), "保留TUN对象但清理中仍准入诊断")
        manager.queue.sync {
            manager.cleanupPending = false
            manager.startupIntent.cancel()
        }
        let revoked = try detect()
        try require(unavailable(revoked), "已撤销启动承诺的保留TUN仍准入诊断")

        let blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        pendingRelease = release
        manager.queue.async {
            blocked.signal()
            _ = release.wait(timeout: .now() + 3)
        }
        try require(blocked.wait(timeout: .now() + 2) == .success, "无法固定归属解析的pending窗口")
        let pendingBox = SnapshotBox()
        let pending = manager.startNetworkDiagnostics(callbackQueue: callbacks, onUpdate: pendingBox.add)
        requests.append(pending)
        pending.cancel()
        try require(pending.isCancelled, "pending请求取消未同步撤销准入")
        release.signal(); pendingRelease = nil
        manager.queue.sync {}
        callbacks.sync {}
        try require(pendingBox.delivered.wait(timeout: .now() + .milliseconds(100)) == .timedOut
            && pendingBox.count == 0, "pending请求取消后仍交付诊断结果")
        print("Enhanced network diagnostics owner self-test passed: \(assertions) assertions; stopped, live TUN without listener, recovery, revoked startup and pending cancel")
    }
}

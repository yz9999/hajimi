import Foundation
import AppKit
import Network
import Darwin
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
        case tunnelAttachFailed(String)
        case cleanupFailed(start: String, cleanup: String)

        var errorDescription: String? {
            switch self {
            case .alreadyRunning: return "增强模式已经运行"
            case .helperAlreadyRunning: return "root Helper 已有活动隧道，请先关闭另一个 Hajimi 会话"
            case .defaultInterfaceMissing: return "无法确定当前物理默认网络接口"
            case .invalidHelperState: return "root Helper 返回的增强模式状态不完整"
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
    private var cachedState: State?
    private var monitorTimer: DispatchSourceTimer?
    private var statisticsTimer: DispatchSourceTimer?
    /// Created/cancelled on `queue`; its handler never touches queue-owned state.
    private var heartbeatTimer: DispatchSourceTimer?
    private var monitorFailures = 0
    private weak var boundEngine: ProxyEngine?
    private var appliedConfiguration: AppliedConfiguration?
    private var pathMonitor: NWPathMonitor?
    private var wakeObserver: NSObjectProtocol?
    private var pendingRebind: DispatchWorkItem?
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

    private struct AppliedConfiguration {
        var profile: Profile
        var mode: OutboundMode
        var globalPolicy: String
        var groupSelections: [String: String]
    }

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
        if let wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver)
        }
        // Best-effort: drop the local data plane and tell the helper to tear
        // routes down. applicationWillTerminate is the primary quit path; this
        // covers ARC teardown if that was skipped.
        let ownsHelper = state != nil
        let cleanup = {
            self.tunnel?.stop()
            self.tunnel = nil
            self.router = nil
            self.monitorTimer?.cancel(); self.monitorTimer = nil
            self.statisticsTimer?.cancel(); self.statisticsTimer = nil
            self.stopHeartbeat()
            self.bypassRefreshTimer?.cancel(); self.bypassRefreshTimer = nil
            self.setAppliedConfiguration(nil)
        }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { cleanup() }
        else { queue.sync(execute: cleanup) }
        if ownsHelper { _ = try? helper.stop() }
    }

    /// Best-effort teardown of this App's own tunnel on quit. Never send stop
    /// to a helper session belonging to another running Hajimi process.
    func shutdownForQuit() {
        var engine: ProxyEngine?
        var ownsHelper = false
        queue.sync {
            engine = boundEngine
            ownsHelper = state != nil
            tunnel?.stop()
            tunnel = nil
            router = nil
            monitorTimer?.cancel(); monitorTimer = nil
            statisticsTimer?.cancel(); statisticsTimer = nil
            stopHeartbeat()
            bypassRefreshTimer?.cancel(); bypassRefreshTimer = nil
            setAppliedConfiguration(nil)
            lastBypassAddresses = []
            setState(nil)
        }
        stopNetworkObservers()
        if ownsHelper { _ = try? helper.stop() }
        if let engine {
            let semaphore = DispatchSemaphore(value: 0)
            engine.setOutboundInterface(name: nil) { _ in semaphore.signal() }
            _ = semaphore.wait(timeout: .now() + 1)
        }
        NativePacketRouter.setOutboundInterface(name: nil) { _ in }
        NativeTunnel.physicalInterfaceName = nil
        clearBoundEngine()
        emit(.stopped)
    }

    var state: State? { lock.withLock { cachedState } }
    var isEnabled: Bool { state != nil }

    func prepareExistingSession(engine: ProxyEngine,
                                completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            // A running tunnel may belong to another App process. Do not
            // interfere with it; orphaned sessions expire in the helper.
            guard self.state == nil else {
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
        emit(.starting)
        helper.ensureInstalled { [weak self, weak engine] installation in
            guard let self, let engine else { return }
            switch installation {
            case .failure(let error):
                self.emit(.failed(error.localizedDescription))
                completion(.failure(error))
            case .success:
                self.queue.async {
                    var ownsStartResources = false
                    var helperStartRequested = false
                    var helperStartSucceeded = false
                    var pendingTunnelFD: Int32?
                    do {
                        if self.state != nil { throw ManagerError.alreadyRunning }
                        // A failed start must never tear down a tunnel owned by
                        // another process while rolling back our own changes.
                        if try self.helper.status().running {
                            throw ManagerError.helperAlreadyRunning
                        }
                        let physical = try self.defaultInterface()
                        self.boundEngine = engine
                        ownsStartResources = true
                        let semaphore = DispatchSemaphore(value: 0)
                        var binding: Result<Void, Error> = .failure(ManagerError.defaultInterfaceMissing)
                        engine.setOutboundInterface(name: physical) { binding = $0; semaphore.signal() }
                        guard semaphore.wait(timeout: .now() + 5) == .success else {
                            throw ManagerError.defaultInterfaceMissing
                        }
                        try binding.get()
                        NativePacketRouter.setOutboundInterface(name: physical) { _ in }
                        NativeTunnel.physicalInterfaceName = physical

                        let bypass = ProxyBypassAddresses.collect(
                            profile: profile, mode: mode, globalPolicy: globalPolicy,
                            groupSelections: groupSelections)
                        // The helper may publish its running state before the
                        // FD handoff and our data-plane attachment finish.
                        self.startHeartbeat()
                        helperStartRequested = true
                        let session = try self.helper.start(
                            fakeIPEnabled: profile.shouldHijackSystemDNS,
                            bypassAddresses: bypass,
                            excludedRoutes: profile.tunExcludedRoutes,
                            includedRoutes: profile.tunIncludedRoutes)
                        helperStartSucceeded = true
                        pendingTunnelFD = session.fileDescriptor

                        guard let helperState = Self.state(from: session.state) else {
                            throw ManagerError.invalidHelperState
                        }

                        // Keep ownership of the FD until the data plane has
                        // actually accepted it. Constructing NativeTunnel can
                        // throw before start() gets a chance to adopt it.
                        try self.attachDataPlane(
                            fileDescriptor: session.fileDescriptor,
                            interfaceName: helperState.tunnelInterface,
                            profile: profile, mode: mode,
                            globalPolicy: globalPolicy,
                            groupSelections: groupSelections)
                        pendingTunnelFD = nil

                        if helperState.physicalInterface != physical {
                            let second = DispatchSemaphore(value: 0)
                            var rebound: Result<Void, Error> = .failure(ManagerError.defaultInterfaceMissing)
                            engine.setOutboundInterface(name: helperState.physicalInterface) {
                                rebound = $0; second.signal()
                            }
                            _ = second.wait(timeout: .now() + 5)
                            try rebound.get()
                            NativePacketRouter.setOutboundInterface(name: helperState.physicalInterface) { _ in }
                            NativeTunnel.physicalInterfaceName = helperState.physicalInterface
                        }

                        self.setState(helperState)
                        self.lastBypassAddresses = Self.normalizedBypass(bypass)
                        self.setAppliedConfiguration(AppliedConfiguration(
                            profile: profile, mode: mode, globalPolicy: globalPolicy,
                            groupSelections: groupSelections))
                        self.monitorFailures = 0
                        self.startMonitor()
                        self.emit(.running(interface: helperState.tunnelInterface,
                                           physicalInterface: helperState.physicalInterface))
                        DispatchQueue.main.async { completion(.success(helperState)) }
                    } catch {
                        let cleanupError = ownsStartResources
                            ? self.rollbackFailedStart(
                                engine: engine,
                                stopHelper: helperStartSucceeded,
                                pendingTunnelFD: pendingTunnelFD)
                            : nil
                        let failure: Error
                        if let cleanupError {
                            failure = ManagerError.cleanupFailed(
                                start: error.localizedDescription,
                                cleanup: cleanupError.localizedDescription)
                        } else if helperStartRequested && !helperStartSucceeded &&
                                    Self.isUncertainStartError(error) {
                            // A timed-out request may still be executing in the
                            // helper. Do not stop an unknown owner's tunnel;
                            // dropping our heartbeat lets its watchdog recover.
                            failure = ManagerError.cleanupFailed(
                                start: error.localizedDescription,
                                cleanup: "Helper 启动结果未确认，已停止保活；请确认网络已恢复")
                        } else {
                            failure = error
                        }
                        self.emit(.failed(failure.localizedDescription))
                        DispatchQueue.main.async { completion(.failure(failure)) }
                    }
                }
            }
        }
    }

    private static func isUncertainStartError(_ error: Error) -> Bool {
        switch error {
        case PrivilegedHelperClient.ClientError.invalidResponse:
            return true
        case PrivilegedHelperClient.ClientError.command:
            // Socket write/read and the FD handoff can fail after the helper
            // installed routes. Do not issue stop() on an unconfirmed owner.
            return true
        default:
            return false
        }
    }

    /// Only a successful start reply proves ownership of this helper session.
    /// If start itself failed, the helper may be owned by another App process.
    private func rollbackFailedStart(engine: ProxyEngine, stopHelper: Bool,
                                     pendingTunnelFD: Int32?) -> Error? {
        stopHeartbeat()
        var cleanupError: Error?
        // Keep the App data plane running until helper.stop has removed its
        // routes. If stop fails, no heartbeat remains to defeat its watchdog.
        if stopHelper {
            do { _ = try helper.stop() }
            catch { cleanupError = error }
        }
        if let pendingTunnelFD { Darwin.close(pendingTunnelFD) }
        tunnel?.stop()
        tunnel = nil
        router = nil
        cancelMonitorTimer()
        stopNetworkObservers()
        lastBypassAddresses = []
        setAppliedConfiguration(nil)
        setState(nil)
        engine.setOutboundInterface(name: nil) { _ in }
        NativePacketRouter.setOutboundInterface(name: nil) { _ in }
        NativeTunnel.physicalInterfaceName = nil
        boundEngine = nil
        return cleanupError
    }

    func stop(engine: ProxyEngine, completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            do {
                try self.stopSynchronously(engine: engine)
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

    func fakeIPEntries() -> [(domain: String, address: String)] {
        router?.fakeIPSnapshot() ?? []
    }

    func reload(profile: Profile, mode: OutboundMode, globalPolicy: String,
                groupSelections: [String: String]) throws {
        try queue.sync {
            guard state != nil else { return }
            // Invalidate DNS work already launched, including when the manual
            // reload fails after partially changing the helper's settings.
            invalidateBypassRefresh()
            router?.update(profile: profile, mode: mode, globalPolicy: globalPolicy,
                           groupSelections: groupSelections)
            tunnel?.resetFlows()
            let bypass = ProxyBypassAddresses.collect(
                profile: profile, mode: mode, globalPolicy: globalPolicy,
                groupSelections: groupSelections)
            let helperState = try helper.reload(fakeIPEnabled: profile.shouldHijackSystemDNS,
                                                bypassAddresses: bypass,
                                                excludedRoutes: profile.tunExcludedRoutes,
                                                includedRoutes: profile.tunIncludedRoutes)
            guard let state = Self.state(from: helperState) else {
                throw ManagerError.invalidHelperState
            }
            lastBypassAddresses = Self.normalizedBypass(bypass)
            setState(state)
            setAppliedConfiguration(AppliedConfiguration(
                profile: profile, mode: mode, globalPolicy: globalPolicy,
                groupSelections: groupSelections))
        }
    }

    func stopSynchronously(engine: ProxyEngine) throws {
        guard state != nil else {
            stopHeartbeat()
            engine.setOutboundInterface(name: nil) { _ in }
            NativePacketRouter.setOutboundInterface(name: nil) { _ in }
            NativeTunnel.physicalInterfaceName = nil
            clearBoundEngine()
            return
        }
        emit(.stopping)
        let invalidateConfiguration = {
            // Invalidate queued DNS results before the potentially slow helper
            // stop, not after it, so they cannot re-install routes in between.
            self.setAppliedConfiguration(nil)
            self.lastBypassAddresses = []
        }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { invalidateConfiguration() }
        else { queue.sync(execute: invalidateConfiguration) }
        do {
            _ = try helper.stop()
        } catch {
            // Retain the data plane until the helper watchdog restores routes.
            // A live heartbeat after a failed stop would prevent that cleanup.
            stopHeartbeat()
            throw error
        }
        stopHeartbeat()
        let stopPlane = {
            self.tunnel?.stop()
            self.tunnel = nil
            self.router = nil
        }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { stopPlane() }
        else { queue.sync(execute: stopPlane) }
        cancelMonitorTimer()
        stopNetworkObservers()
        setState(nil)
        let semaphore = DispatchSemaphore(value: 0)
        engine.setOutboundInterface(name: nil) { _ in semaphore.signal() }
        _ = semaphore.wait(timeout: .now() + 2)
        NativePacketRouter.setOutboundInterface(name: nil) { _ in }
        NativeTunnel.physicalInterfaceName = nil
        clearBoundEngine()
        emit(.stopped)
    }

    private func attachDataPlane(fileDescriptor: Int32, interfaceName: String,
                                 profile: Profile, mode: OutboundMode,
                                 globalPolicy: String,
                                 groupSelections: [String: String]) throws {
        let store = applicationSupportDirectory.appendingPathComponent("virtual-ip.json")
        let packetRouter = NativePacketRouter(profile: profile, mode: mode,
                                              globalPolicy: globalPolicy,
                                              groupSelections: groupSelections,
                                              fakeIPStoreURL: store)
        let native = try NativeTunnel(router: packetRouter)
        do {
            _ = try native.start(fileDescriptor: fileDescriptor,
                                 interfaceName: interfaceName)
        } catch {
            native.stop()
            throw ManagerError.tunnelAttachFailed(error.localizedDescription)
        }
        router = packetRouter
        tunnel = native
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
        timer.schedule(deadline: .now() + 1, repeating: 1,
                       leeway: .milliseconds(100))
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
        queue.async {
            self.monitorTimer?.cancel()
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + 5, repeating: 5, leeway: .milliseconds(400))
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

    private func startNetworkObservers() {
        let monitor: NWPathMonitor? = lock.withLock {
            guard pathMonitor == nil else { return nil }
            let created = NWPathMonitor()
            pathMonitor = created
            return created
        }
        if let monitor {
            monitor.pathUpdateHandler = { [weak self] _ in self?.scheduleRebindCheck() }
            monitor.start(queue: queue)
        }
        lock.withLock {
            guard wakeObserver == nil else { return }
            wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
                forName: NSWorkspace.didWakeNotification, object: nil, queue: nil
            ) { [weak self] _ in
                guard let self else { return }
                self.queue.async {
                    guard self.state != nil else { return }
                    self.monitorOnce()
                    self.scheduleRebindCheck()
                }
            }
        }
    }

    private func stopNetworkObservers() {
        let (monitor, observer, pending) = lock.withLock {
            let values = (pathMonitor, wakeObserver, pendingRebind)
            pathMonitor = nil; wakeObserver = nil; pendingRebind = nil
            return values
        }
        pending?.cancel()
        monitor?.cancel()
        if let observer { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
    }

    private func scheduleRebindCheck() {
        queue.async {
            guard self.state != nil else { return }
            let work = DispatchWorkItem { [weak self] in self?.rebindOutboundIfNeeded() }
            let previous: DispatchWorkItem? = self.lock.withLock {
                let old = self.pendingRebind
                self.pendingRebind = work
                return old
            }
            previous?.cancel()
            self.queue.asyncAfter(deadline: .now() + 1.5, execute: work)
        }
    }

    private func rebindOutboundIfNeeded() {
        guard let current = state, let engine = boundEngine,
              let configuration = lock.withLock({ appliedConfiguration }) else { return }
        guard let physical = try? defaultInterface(),
              physical != current.physicalInterface else { return }
        // DNS work from the previous uplink must not replace the routes
        // computed for the new gateway, even if the profile is unchanged.
        invalidateBypassRefresh()
        let semaphore = DispatchSemaphore(value: 0)
        var binding: Result<Void, Error> = .failure(ManagerError.defaultInterfaceMissing)
        engine.setOutboundInterface(name: physical) { binding = $0; semaphore.signal() }
        guard semaphore.wait(timeout: .now() + 5) == .success, case .success = binding else {
            emit(.failed("网络接口已切换到 \(physical)，但重新绑定出站失败"))
            return
        }
        NativePacketRouter.setOutboundInterface(name: physical) { _ in }
        NativeTunnel.physicalInterfaceName = physical
        do {
            let bypass = ProxyBypassAddresses.collect(
                profile: configuration.profile, mode: configuration.mode,
                globalPolicy: configuration.globalPolicy,
                groupSelections: configuration.groupSelections)
            let helperState = try helper.reload(
                fakeIPEnabled: configuration.profile.shouldHijackSystemDNS,
                bypassAddresses: bypass,
                excludedRoutes: configuration.profile.tunExcludedRoutes,
                includedRoutes: configuration.profile.tunIncludedRoutes)
            lastBypassAddresses = Self.normalizedBypass(bypass)
            tunnel?.resetFlows()
            guard let value = Self.state(from: helperState) else { return }
            setState(value)
            emit(.running(interface: value.tunnelInterface,
                          physicalInterface: value.physicalInterface))
        } catch {
            emit(.failed("网络切换后重新绑定 root Helper 失败：\(error.localizedDescription)"))
        }
    }

    /// Re-resolves the currently selected proxy hosts and, if the set of
    /// physical-gateway bypass addresses changed, asks the helper to replace
    /// the host routes. The data plane stays up.
    private func refreshBypassRoutesIfNeeded() {
        guard state != nil, bypassRefreshInFlight == nil else { return }
        guard let configuration = lock.withLock({ appliedConfiguration }) else { return }
        let generation = configurationGeneration
        bypassRefreshInFlight = generation
        let profile = configuration.profile
        let mode = configuration.mode
        let globalPolicy = configuration.globalPolicy
        let groupSelections = configuration.groupSelections
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let bypass = ProxyBypassAddresses.collect(
                profile: profile, mode: mode, globalPolicy: globalPolicy,
                groupSelections: groupSelections)
            let normalized = Self.normalizedBypass(bypass)
            self?.queue.async {
                guard let self else { return }
                guard Self.isCurrentBypassRefresh(
                    capturedGeneration: generation,
                    currentGeneration: self.configurationGeneration,
                    inFlightGeneration: self.bypassRefreshInFlight) else { return }
                self.bypassRefreshInFlight = nil
                guard self.state != nil,
                      self.lock.withLock({ self.appliedConfiguration != nil }) else { return }
                guard Self.shouldReplaceBypass(previous: self.lastBypassAddresses,
                                               next: normalized) else { return }
                do {
                    let helperState = try self.helper.reload(
                        fakeIPEnabled: profile.shouldHijackSystemDNS,
                        bypassAddresses: bypass,
                        excludedRoutes: profile.tunExcludedRoutes,
                        includedRoutes: profile.tunIncludedRoutes)
                    guard Self.state(from: helperState) != nil else { return }
                    self.lastBypassAddresses = normalized
                } catch {
                    // Keep the previous routes. The next tick retries.
                }
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
            if let value = Self.state(from: helperState), tunnel != nil {
                setState(value)
                if recovered {
                    emit(.running(interface: value.tunnelInterface,
                                  physicalInterface: value.physicalInterface))
                }
            } else if state != nil {
                stopHeartbeat()
                tunnel?.stop(); tunnel = nil; router = nil
                monitorTimer?.cancel(); monitorTimer = nil
                statisticsTimer?.cancel(); statisticsTimer = nil
                bypassRefreshTimer?.cancel(); bypassRefreshTimer = nil
                lastBypassAddresses = []
                stopNetworkObservers()
                setAppliedConfiguration(nil)
                setState(nil)
                boundEngine?.setOutboundInterface(name: nil) { _ in }
                NativePacketRouter.setOutboundInterface(name: nil) { _ in }
                NativeTunnel.physicalInterfaceName = nil
                boundEngine = nil
                emit(.failed("root Helper 的隧道已停止"))
            }
        } catch {
            monitorFailures += 1
            if monitorFailures == 3 {
                emit(.failed("暂时无法连接 root Helper：\(error.localizedDescription)"))
            }
        }
    }

    private func defaultInterface() throws -> String {
        let process = Process(); let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = ["-n", "get", "default"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        let text = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        for line in text.components(separatedBy: .newlines) {
            let pair = line.trimmingCharacters(in: .whitespaces)
                .split(separator: ":", maxSplits: 1).map(String.init)
            if pair.count == 2, pair[0] == "interface" {
                let value = pair[1].trimmingCharacters(in: .whitespaces)
                if !value.hasPrefix("utun") { return value }
            }
        }
        throw ManagerError.defaultInterfaceMissing
    }

    private static func state(from value: HajimiHelperTunnelState) -> State? {
        guard value.running, let tunnel = value.tunnelInterface,
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
            self.invalidateBypassRefresh()
        }
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil { update() }
        else { queue.sync(execute: update) }
    }
    private func emit(_ status: Status) { DispatchQueue.main.async { self.onStatus?(status) } }
    private func emitStatistics(active: Int, total: Int, up: UInt64, down: UInt64) {
        DispatchQueue.main.async {
            self.onStatistics?(active, total, up, down)
        }
    }
}

// MARK: - Proxy bypass address collection (App-side DNS)

enum ProxyBypassAddresses {
    static func collect(profile: Profile, mode: OutboundMode, globalPolicy: String,
                        groupSelections: [String: String]) -> [String] {
        var hosts: [String] = []
        var seen = Set<String>()
        func appendHost(_ raw: String?) {
            guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !raw.isEmpty else { return }
            let key = raw.lowercased()
            guard seen.insert(key).inserted else { return }
            hosts.append(raw)
        }
        func appendProxy(_ name: String, depth: Int = 0) {
            guard depth < 8 else { return }
            let proxy = profile.proxies[name] ?? profile.proxies.first(where: {
                $0.key.caseInsensitiveCompare(name) == .orderedSame
            })?.value
            guard let proxy else { return }
            switch proxy.kind {
            case .http, .socks5, .native, .external:
                appendHost(proxy.host)
                if let underlying = proxy.parameters["underlying-proxy"]
                    ?? proxy.parameters["underlying_proxy"] {
                    appendProxy(underlying, depth: depth + 1)
                }
            case .direct, .reject:
                break
            }
        }
        for proxy in profile.proxies.values {
            if let host = proxy.host, isNumericIP(host) { appendHost(host) }
        }
        switch mode {
        case .direct: break
        case .proxy:
            appendProxy(globalPolicy)
            if let group = profile.groups[globalPolicy] {
                for member in group.members { appendProxy(member) }
            }
        case .rule:
            appendProxy(globalPolicy)
            for (_, selected) in groupSelections { appendProxy(selected) }
            for group in profile.groups.values.prefix(32) {
                for member in group.members.prefix(4) { appendProxy(member) }
            }
        }

        var addresses: [String] = []
        var addressSeen = Set<String>()
        let deadline = Date().addingTimeInterval(4)
        for host in hosts {
            if Date() >= deadline { break }
            for address in resolve(host, deadline: deadline) where addressSeen.insert(address).inserted {
                addresses.append(address)
            }
        }
        return addresses
    }

    private static func isNumericIP(_ host: String) -> Bool {
        var v4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return true }
        var v6 = in6_addr()
        return host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1
    }

    private static func resolve(_ host: String, deadline: Date) -> [String] {
        if isNumericIP(host) { return [host] }
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0.05 else { return [] }
        let lock = NSLock()
        var result: [String] = []
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            let resolved = lookup(host)
            lock.lock(); result = resolved; lock.unlock()
            semaphore.signal()
        }
        let timeout = DispatchTime.now() + .milliseconds(Int(min(remaining, 1.0) * 1000))
        if semaphore.wait(timeout: timeout) == .timedOut { return [] }
        lock.lock(); defer { lock.unlock() }
        return result
    }

    private static func lookup(_ host: String) -> [String] {
        var hints = addrinfo(ai_flags: AI_ADDRCONFIG, ai_family: AF_UNSPEC,
                             ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &info) == 0 else { return [] }
        defer { freeaddrinfo(info) }
        var addresses: [String] = []
        var cursor = info
        while let node = cursor {
            if node.pointee.ai_family == AF_INET, let addr = node.pointee.ai_addr {
                var sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                inet_ntop(AF_INET, &sin.sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN))
                let text = String(cString: buffer)
                if !text.isEmpty { addresses.append(text) }
            } else if node.pointee.ai_family == AF_INET6, let addr = node.pointee.ai_addr {
                var sin6 = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                inet_ntop(AF_INET6, &sin6.sin6_addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
                let text = String(cString: buffer)
                if !text.isEmpty, !text.lowercased().hasPrefix("fe80:") {
                    addresses.append(text)
                }
            }
            cursor = node.pointee.ai_next
        }
        return addresses
    }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T {
        lock(); defer { unlock() }
        return body()
    }
}

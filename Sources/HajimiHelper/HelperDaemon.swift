import Foundation
import Darwin
import Security
import HajimiIPC

/// Root-only network plumbing for enhanced mode.
///
/// Owns utun creation, interface addresses, split default routes, proxy-host
/// bypass routes and optional system-DNS redirection. The packet data plane
/// runs in the unprivileged App after it receives the utun file descriptor.
///
/// Concurrency model:
/// - `stateLock` protects the published snapshot and liveness counter. `ping` /
///   `status` only take this lock briefly and never run subprocesses.
/// - `operationQueue` serializes prepare/commit/stop/reload (the paths that shell
///   out). A wedged `route`/`ifconfig` can delay the next mutation, but cannot
///   freeze status heartbeats from the App.
final class EnhancedTunnelService {
    /// Tests inject command results and an ordinary descriptor: no utun,
    /// system routes, resolver changes or privileged process are required.
    struct Environment {
        var run: ((String, [String]) throws -> String)? = nil
        var openUTUN: (() throws -> (descriptor: Int32, name: String))? = nil
        var isProcessAlive: ((pid_t) -> Bool)? = nil
        var now: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
        var monitorHealth = true
    }
    /// Only the socket server constructs peer authority, from kernel-provided
    /// credentials and the launch daemon's configured UID, never request JSON.
    enum MutationCaller {
        case authenticatedPeer(uid: uid_t, pid: pid_t, allowedUID: uid_t)
        case daemonCleanup
    }

    private let stateLock = NSLock()
    private var currentState = HajimiHelperTunnelState(running: false)
    private var ticksSinceClientContact = 0
    /// Includes DNS, tunnel routes, physical bypasses and scoped IPv6 routes.
    /// An incomplete stop stays pending until the watchdog restores every owner.
    private var verifiedStoppedRouteCleanup = true
    private var cleanupScheduled = false
    private var ticksSinceCleanupAttempt = 0
    private var savedDNSServers: [String: [String]] = [:]
    private var proxyBypassRoutes: [InstalledBypassRoute] = []
    /// Only routes we added (including uncertain command outcomes), never
    /// pre-existing physical scoped defaults borrowed from another owner.
    private var physicalIPv6ScopedRoutes: [PhysicalIPv6ScopedRoute] = []
    /// Catch-all (or tun-included-routes) currently pointed at the tunnel.
    /// Tracked so stop/reload can delete exactly what was added.
    private var installedTunnelRoutes: [String] = []
    private var tunnelFileDescriptor: Int32 = -1
    /// PID of the App that currently owns the tunnel. Re-attach (FD hand-off)
    /// is only allowed to this process. A new PID waits for watchdog cleanup.
    private var ownerPID: pid_t = 0
    /// A clean empty inventory after restart cannot acknowledge recovery of
    /// an unknown older session. ACKs are recorded only after real cleanup,
    /// remain bound to the original peer PID, and survive a subsequent prepare.
    private var lastRestoredSessionToken: String?
    private var lastRestoredSessionOwnerPID: pid_t = 0
    /// An installed route is not usable until at least one App has received its
    /// utun FD. Track concurrent hand-offs of the same session so a failed
    /// first send cannot stop another successful re-attach in flight.
    private var sessionGeneration: UInt64 = 0
    private var pendingHandoffs = 0
    private var deliveredHandoff = false
    private var teardownScheduled = false
    private var handoffCompletion: DispatchGroup?
    private var handoffCompletionSignalled = false
    private var preparedDeadline: TimeInterval?
    private struct PreparedConfiguration {
        let fakeIPEnabled: Bool
        let bypassAddresses: [String]
        let excludedRoutes: [String]
        let includedRoutes: [String]
    }
    /// The configuration is fixed by prepare. A replayed commit can never
    /// swap routing or resolver intent underneath an already-ready reader.
    private var preparedConfiguration: PreparedConfiguration?
    /// Queue-confined guard, cleared before rollback so cleanup always runs.
    private var commitIdentity: (token: String, clientPID: pid_t)?
    private let environment: Environment

    /// Serializes mutating work. Never call `state()` from inside this queue
    /// via a path that also waits on `operationQueue` (deadlock).
    private let operationQueue = DispatchQueue(label: "app.hajimi.helper.ops")
    private var healthTimer: DispatchSourceTimer?
    private let healthQueue = DispatchQueue(label: "app.hajimi.helper.health")

    /// While the tunnel is up the App pings about once a second. Three missed
    /// ticks (~3s) means the App is gone — tear routes down immediately so a
    /// crashed GUI cannot leave the machine black-holed for long.
    private static let healthTickInterval = 1.0
    private static let healthTicksBeforeTeardown = 3
    private static let liveProcessHealthTicksBeforeTeardown = 8
    private var lastHealthTickContinuousNanos: UInt64 = 0
    private static let cleanupRetryTicks = 5
    private static let processTimeout: TimeInterval = 4.0
    private static let preparationTimeout: TimeInterval = 15.0
    private static let handoffAcknowledgementTimeout: TimeInterval = 2.0

    private let ipv4Routes = [
        "1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
        "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"
    ]
    private let ipv6Routes = ["::/1", "8000::/1"]
    // Keep the tunnel/DNS addresses separate from Lurge's 198.18.0.1/.2 and
    // fd00:7162::1.  The fake-IP allocator uses 198.19.0.0/16, so stay in
    // the other half of RFC 2544 benchmarking space.
    private let ipv4Gateway = "198.18.16.1"
    private let dnsGateway = "198.18.16.2"
    private let ipv6Gateway = "fd00:6861:6a69::1"

    init(environment: Environment = Environment()) {
        self.environment = environment
        // An unrecorded split route or DNS resolver can belong to another
        // running proxy.  A newly started helper has no proof of ownership:
        // never run a global startup sweep, especially while Lurge is active.
        if environment.monitorHealth { startHealthMonitor() }
    }

    deinit {
        healthTimer?.cancel()
    }

    // MARK: - Public API (called from IPC handlers)

    /// Heartbeat + snapshot. Must stay wait-free relative to start/stop.
    ///
    /// `clientPID` is the IPC peer. Only the tunnel owner may renew liveness
    /// while the tunnel is up — otherwise a third-party same-UID process could
    /// keep routes alive after the real App exited.
    func state(clientPID: pid_t = 0, renewLiveness: Bool = true) -> HajimiHelperTunnelState {
        stateLock.lock()
        let active = Self.hasActiveSession(currentState)
        let owner = ownerPID
        if renewLiveness && (!active || (owner > 0 && owner == clientPID)) {
            ticksSinceClientContact = 0
        }
        let value = visibleSnapshotLocked(clientPID: clientPID)
        stateLock.unlock()
        return value
    }

    struct PrepareResult {
        let state: HajimiHelperTunnelState
        let fileDescriptorToSend: Int32
        let sessionGeneration: UInt64
    }

    func prepare(fakeIPEnabled: Bool, bypassAddresses: [String],
               excludedRoutes: [String] = [],
               includedRoutes: [String] = [],
               clientPID: pid_t) throws -> PrepareResult {
        try operationQueue.sync {
            // A missing peer PID must not create an owner-less session either.
            try assertClientMayOwnTunnel(clientPID)
            if Self.hasActiveSession(snapshot()) {
                stateLock.lock()
                let expired = preparedDeadline.map { environment.now() >= $0 } == true
                stateLock.unlock()
                if expired {
                    _ = stopLocked()
                    throw HelperServiceError.command("隧道准备已超时，请重新开启增强模式")
                }
                // Only the owning App may receive another copy of the utun FD.
                // Otherwise any same-UID process could attach and inject packets.
                setOwnerPID(clientPID)
                let fd = try duplicateTunnelFileDescriptor()
                let generation = beginHandoff(newSession: false)
                noteClientContact()
                return PrepareResult(state: snapshot(forClientPID: clientPID), fileDescriptorToSend: fd,
                                   sessionGeneration: generation)
            }
            // A previous stop may have failed to delete a custom route or
            // restore a resolver. Never overwrite that only inventory with
            // a new session before retrying its cleanup.
            stateLock.lock()
            let priorCleanupPending = !verifiedStoppedRouteCleanup
            stateLock.unlock()
            guard !priorCleanupPending else {
                throw HelperServiceError.command("上次增强模式的路由或 DNS 尚未恢复，请稍后重试")
            }
            // A cold recovery must wait for DHCP before opening/configuring
            // utun. This reply owns no resources and is safe for a later new
            // prepare; ownership and pending cleanup were checked first.
            let physical = try preflightReloadPhysicalNetwork(needsGateway: true,
                captureIPv6: desiredTunnelRoutes(includedRoutes: includedRoutes).contains { $0.contains(":") }).interface
            try ensureNoConflictingTunnel()
            try ensureNoOrphanedDNSRedirect()
            let opened = try environment.openUTUN?() ?? Self.openUTUN()
            setTunnelFileDescriptor(opened.descriptor)
            // Duplicate before touching routes/DNS. Otherwise a failed dup
            // after publishing a running tunnel would leave a black hole.
            let sendFD: Int32
            do { sendFD = try duplicateTunnelFileDescriptor() }
            catch {
                closeTunnelFileDescriptor()
                throw error
            }
            do {
                try run("/sbin/ifconfig", [opened.name, ipv4Gateway, ipv4Gateway,
                                           "mtu", "9000", "up"])
                try run("/sbin/ifconfig", [opened.name, "inet6", ipv6Gateway,
                                           "prefixlen", "128", "alias"])
            } catch {
                Darwin.close(sendFD)
                let dnsRestored = restoreSystemDNS()
                let bypassCleaned = removeProxyBypassRoutes(ignoringErrors: true)
                let routesCleaned = removeRoutes(ignoringErrors: true)
                let scopedCleaned = removePhysicalIPv6ScopedRoutes()
                _ = try? run("/sbin/ifconfig", [opened.name, "down"])
                closeTunnelFileDescriptor()
                publish(HajimiHelperTunnelState(running: false),
                        markClean: dnsRestored && bypassCleaned && routesCleaned && scopedCleaned)
                if !dnsRestored || !bypassCleaned || !routesCleaned || !scopedCleaned {
                    throw HelperServiceError.command(
                        "启动失败：\(error.localizedDescription)；系统 DNS 或路由尚未恢复，Helper 将持续重试")
                }
                throw error
            }
            let newState = HajimiHelperTunnelState(
                running: false,
                phase: .prepared,
                sessionToken: UUID().uuidString,
                tunnelInterface: opened.name,
                physicalInterface: physical,
                dataPlane: "HajimiNativeCore (App)")
            preparedConfiguration = PreparedConfiguration(
                fakeIPEnabled: fakeIPEnabled,
                bypassAddresses: sanitizeBypassAddresses(bypassAddresses),
                excludedRoutes: sanitizeExcludedRoutes(excludedRoutes),
                includedRoutes: includedRoutes)
            stateLock.lock()
            preparedDeadline = environment.now() + Self.preparationTimeout
            stateLock.unlock()
            publish(newState, markClean: true)
            setOwnerPID(clientPID)
            let generation = beginHandoff(newSession: true)
            noteClientContact()
            return PrepareResult(state: snapshot(forClientPID: clientPID), fileDescriptorToSend: sendFD,
                               sessionGeneration: generation)
        }
    }

    /// App calls only after its resumed DispatchSource reader acknowledges
    /// readiness. FD delivery is acknowledged independently of operationQueue:
    /// the new IPC connection can otherwise race the previous send's return.
    func commit(sessionToken: String?, clientPID: pid_t) throws -> HajimiHelperTunnelState {
        stateLock.lock()
        let isOwnedToken = clientPID > 0 && ownerPID == clientPID &&
            sessionToken != nil && currentState.sessionToken == sessionToken
        let acknowledgement = isOwnedToken ? handoffCompletion : nil
        stateLock.unlock()
        if let acknowledgement {
            _ = acknowledgement.wait(timeout: .now() + Self.handoffAcknowledgementTimeout)
        }
        return try operationQueue.sync {
            try assertOwnedSession(sessionToken: sessionToken, clientPID: clientPID)
            let existing = snapshot()
            // An uncertain response may be retried, but never repeats mutations.
            if existing.running && existing.phase == .running { return snapshot(forClientPID: clientPID) }
            guard existing.phase == .prepared, let token = sessionToken,
                  let configuration = preparedConfiguration else {
                throw HelperServiceError.command("隧道尚未准备好，无法确认收包就绪")
            }
            stateLock.lock()
            let delivered = deliveredHandoff
            let deadline = preparedDeadline
            stateLock.unlock()
            guard delivered else {
                throw HelperServiceError.command("隧道文件描述符尚未成功交付，拒绝接管系统网络")
            }
            guard let deadline, environment.now() < deadline else {
                _ = stopLocked()
                throw HelperServiceError.command("隧道准备已超时，已取消本次启动")
            }
            var committing = existing
            committing.phase = .committing
            publish(committing, markClean: true)
            commitIdentity = (token, clientPID)
            do {
                try assertCommitStillLive()
                // The physical network can change while the App prepares its
                // reader. Validate it again before the first route mutation.
                let plan = try preflightReloadPhysicalNetwork(needsGateway: true,
                    captureIPv6: desiredTunnelRoutes(includedRoutes: configuration.includedRoutes).contains { $0.contains(":") })
                let physical = plan.interface
                guard physical == existing.physicalInterface else {
                    throw HelperServiceError.physicalNetworkNotReady("准备隧道期间物理网络已切换，等待重新准备增强模式")
                }
                try ensureNoConflictingTunnel()
                try ensureNoOrphanedDNSRedirect()
                committing.physicalInterface = physical
                publish(committing, markClean: true)
                // Protect proxy/bootstrap traffic before catch-all routes.
                // CIDR exclusions follow capture, as in revision 7.5, so
                // more-specific physical prefixes win over catch-all routes.
                try reconcileBypassRoutes(
                    hosts: configuration.bypassAddresses,
                    nets: [],
                    gateway: plan.gateway, physicalInterface: physical)
                try reconcilePhysicalIPv6ScopedRoute(desired: plan.ipv6ScopedRoute)
                try installTunnelRoutes(includedRoutes: configuration.includedRoutes)
                try reconcileBypassRoutes(
                    hosts: configuration.bypassAddresses,
                    nets: configuration.excludedRoutes,
                    gateway: plan.gateway, physicalInterface: physical)
                if configuration.fakeIPEnabled { try redirectSystemDNS() }
                try assertCommitStillLive()
            } catch {
                commitIdentity = nil
                _ = stopLocked()
                stateLock.lock()
                let cleaned = verifiedStoppedRouteCleanup
                stateLock.unlock()
                if !cleaned {
                    throw HelperServiceError.command(
                        "启动失败：\(error.localizedDescription)；系统 DNS 或路由尚未恢复，Helper 将持续重试")
                }
                throw error
            }
            commitIdentity = nil
            committing.running = true
            committing.phase = .running
            committing.startedAt = Date()
            stateLock.lock()
            preparedDeadline = nil
            stateLock.unlock()
            preparedConfiguration = nil
            publish(committing, markClean: false)
            noteClientContact()
            return snapshot(forClientPID: clientPID)
        }
    }

    /// Called after the response and ancillary FD have actually been sent (or
    /// one failed). If no hand-off of this new session succeeded, remove its
    /// routes and restore DNS immediately instead of waiting for the watchdog.
    func finishHandoff(generation: UInt64, delivered: Bool) {
        stateLock.lock()
        guard sessionGeneration == generation, pendingHandoffs > 0 else {
            stateLock.unlock()
            return
        }
        pendingHandoffs -= 1
        if delivered {
            deliveredHandoff = true
            ticksSinceClientContact = 0
        }
        if (deliveredHandoff || pendingHandoffs == 0), !handoffCompletionSignalled {
            handoffCompletionSignalled = true
            handoffCompletion?.leave()
        }
        let shouldStop = !deliveredHandoff && pendingHandoffs == 0 &&
            Self.hasActiveSession(currentState)
        stateLock.unlock()
        if shouldStop {
            operationQueue.async { [weak self] in
                guard let self else { return }
                self.stateLock.lock()
                let stillUndelivered = self.sessionGeneration == generation &&
                    !self.deliveredHandoff && self.pendingHandoffs == 0
                self.stateLock.unlock()
                guard stillUndelivered else { return }
                fputs("HajimiHelper: utun FD hand-off failed — tearing down tunnel\n", stderr)
                _ = self.stopLocked()
            }
        }
    }

    /// Daemon-internal signal/maintenance cleanup. IPC must use the overload
    /// carrying authenticated peer authority rather than this trusted path.
    func stop() throws -> HajimiHelperTunnelState {
        try stop(caller: .daemonCleanup)
    }

    func stop(caller: MutationCaller, sessionToken: String? = nil) throws -> HajimiHelperTunnelState {
        try operationQueue.sync {
            try assertMutationCallerMayOperate(caller)
            try assertOptionalSessionToken(sessionToken, caller: caller)
            _ = stopLocked()
            stateLock.lock()
            let cleaned = verifiedStoppedRouteCleanup
            stateLock.unlock()
            guard cleaned else {
                throw HelperServiceError.command(
                    "隧道已关闭，但 DNS 或路由尚未完全恢复；Helper 将在后台持续重试")
            }
            return snapshot(forCaller: caller)
        }
    }

    func reload(fakeIPEnabled: Bool, bypassAddresses: [String],
                excludedRoutes: [String] = [],
                includedRoutes: [String] = [],
                caller: MutationCaller,
                sessionToken: String? = nil) throws -> HajimiHelperTunnelState {
        try operationQueue.sync {
            // Check after entering the mutation queue, not when the request is
            // accepted: start/stop ahead of this request may change its owner.
            try assertMutationCallerMayOperate(caller)
            try assertOptionalSessionToken(sessionToken, caller: caller)
            guard snapshot().running else {
                throw HelperServiceError.command("原生 TUN 尚未运行")
            }
            var state = snapshot()
            let hosts = sanitizeBypassAddresses(bypassAddresses)
            let nets = sanitizeExcludedRoutes(excludedRoutes)
            let captureIPv6 = desiredTunnelRoutes(includedRoutes: includedRoutes).contains { $0.contains(":") }
            // Wi-Fi association and DHCP/RA readiness arrive separately. Read
            // one physical default for both interface and gateway, and resolve
            // IPv6 intent before changing any owned route or DNS setting.
            // Only this read-only preflight can report a retryable condition.
            let physical: ReloadPhysicalNetworkPlan
            do {
                physical = try preflightReloadPhysicalNetwork(needsGateway: !hosts.isEmpty || !nets.isEmpty,
                                                              captureIPv6: captureIPv6)
            } catch {
                // A confirmed conflicting/unusable route is not merely an
                // incomplete Wi-Fi reconnect. Preserve the protection failure
                // and cleanup behavior; only read-only temporary absence waits.
                if case .physicalNetworkNotReady = error as? HelperServiceError { throw error }
                _ = stopLocked()
                throw error
            }
            state.physicalInterface = physical.interface
            // DNS is touched last: if the route transition fails, it can keep
            // the original resolver and roll back its route-only changes.
            stateLock.lock()
            let scopedBefore = physicalIPv6ScopedRoutes
            let capturedIPv6Before = installedTunnelRoutes.contains { $0.contains(":") }
            stateLock.unlock()
            do {
                try reconcilePhysicalIPv6ScopedRoute(desired: physical.ipv6ScopedRoute)
            } catch {
                _ = stopLocked()
                throw error
            }
            stateLock.lock()
            let scopedTransitioned = scopedBefore != physicalIPv6ScopedRoutes || capturedIPv6Before != captureIPv6
            stateLock.unlock()
            do {
                try reconcileTunnelRoutes(includedRoutes: includedRoutes)
                try reconcileBypassRoutes(hosts: hosts, nets: nets,
                                          gateway: physical.gateway,
                                          physicalInterface: physical.interface)
                let redirectActive: Bool = {
                    stateLock.lock(); defer { stateLock.unlock() }
                    return !savedDNSServers.isEmpty
                }()
                switch FakeIPDNSRedirectPlan.plan(fakeIPEnabled: fakeIPEnabled,
                                                  redirectActive: redirectActive) {
                case .install:
                    do { try redirectSystemDNS() }
                    catch {
                        _ = stopLocked()
                        throw HelperServiceError.command(
                            "系统 DNS 重定向未能全部验证，已关闭增强模式；未完成的恢复将在后台重试：\(error.localizedDescription)")
                    }
                case .restore:
                    guard restoreSystemDNS() else {
                        _ = stopLocked()
                        throw HelperServiceError.command("系统 DNS 恢复失败，已关闭增强模式并将在后台继续重试")
                    }
                case .keep:
                    if fakeIPEnabled {
                        // Network services can be enabled or modified between
                        // reloads. Existing snapshots alone do not prove all
                        // active resolvers are still protected.
                        do { try redirectSystemDNS() }
                        catch {
                            _ = stopLocked()
                            throw HelperServiceError.command(
                                "系统 DNS 保护校验失败，已关闭增强模式；未完成的恢复将在后台重试：\(error.localizedDescription)")
                        }
                    }
                }
                publish(state, markClean: false)
                noteClientContact()
                return snapshot(forCaller: caller)
            } catch {
                // A tunnel-only rollback cannot restore an earlier scoped
                // change. Never keep reporting running with the old capture
                // and a different physical escape path after partial reload.
                if scopedTransitioned { _ = stopLocked() }
                throw error
            }
        }
    }

    // MARK: - State helpers

    private func snapshot() -> HajimiHelperTunnelState {
        stateLock.lock(); defer { stateLock.unlock() }
        return currentState
    }

    /// stateLock must be held; no operation-queue work or process probes.
    private func visibleSnapshotLocked(clientPID: pid_t) -> HajimiHelperTunnelState {
        var value = currentState
        if clientPID <= 0 || ownerPID != clientPID { value.sessionToken = nil }
        if clientPID <= 0 || lastRestoredSessionOwnerPID != clientPID {
            value.lastRestoredSessionToken = nil
        }
        return value
    }

    private func snapshot(forClientPID clientPID: pid_t) -> HajimiHelperTunnelState {
        stateLock.lock(); defer { stateLock.unlock() }
        return visibleSnapshotLocked(clientPID: clientPID)
    }

    private func snapshot(forCaller caller: MutationCaller) -> HajimiHelperTunnelState {
        switch caller {
        case .authenticatedPeer(_, let pid, _): return snapshot(forClientPID: pid)
        case .daemonCleanup: return snapshot()
        }
    }

    private func publish(_ state: HajimiHelperTunnelState, markClean: Bool) {
        stateLock.lock()
        currentState = state
        currentState.lastRestoredSessionToken = lastRestoredSessionToken
        currentState.networkCleanupPending = !Self.hasActiveSession(state) && !markClean
        verifiedStoppedRouteCleanup = !Self.hasActiveSession(state) && markClean
        if !Self.hasActiveSession(state) {
            ticksSinceCleanupAttempt = markClean ? 0 : Self.cleanupRetryTicks - 1
        }
        stateLock.unlock()
    }

    private func noteClientContact() {
        stateLock.lock()
        ticksSinceClientContact = 0
        stateLock.unlock()
    }

    private func setTunnelFileDescriptor(_ fd: Int32) {
        stateLock.lock()
        tunnelFileDescriptor = fd
        stateLock.unlock()
    }

    private func closeTunnelFileDescriptor() {
        stateLock.lock()
        let fd = tunnelFileDescriptor
        tunnelFileDescriptor = -1
        stateLock.unlock()
        if fd >= 0 { Darwin.close(fd) }
    }

    private func duplicateTunnelFileDescriptor() throws -> Int32 {
        stateLock.lock()
        let source = tunnelFileDescriptor
        stateLock.unlock()
        guard source >= 0 else {
            throw HelperServiceError.command("utun 描述符不可用")
        }
        let copy = fcntl(source, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0 else {
            throw HelperServiceError.command("复制 utun 描述符失败：\(String(cString: strerror(errno)))")
        }
        return copy
    }

    private func stopLocked() -> HajimiHelperTunnelState {
        commitIdentity = nil
        preparedConfiguration = nil
        stateLock.lock()
        sessionGeneration &+= 1
        pendingHandoffs = 0
        deliveredHandoff = false
        preparedDeadline = nil
        if !handoffCompletionSignalled {
            handoffCompletionSignalled = true
            handoffCompletion?.leave()
        }
        handoffCompletion = nil
        stateLock.unlock()
        let previous = snapshot()
        let dnsRestored = restoreSystemDNS()
        let routesRemoved = removeRoutes(ignoringErrors: true)
        let bypassRemoved = removeProxyBypassRoutes(ignoringErrors: true)
        let scopedRemoved = removePhysicalIPv6ScopedRoutes()
        let cleaned = dnsRestored && bypassRemoved && routesRemoved && scopedRemoved
        var stopped = HajimiHelperTunnelState(running: false,
                                              dataPlane: "HajimiNativeCore (App)")
        if cleaned {
            recordRestoredSession(previous.sessionToken)
            finishStoppedInterfaceCleanup(previous.tunnelInterface)
        } else {
            // The App must retain its resumed reader until recovery is
            // verified. Keep the Helper's FD/interface and token too: an
            // ifconfig down here would black-hole the unresolved routes.
            stopped.sessionToken = previous.sessionToken
            stopped.tunnelInterface = previous.tunnelInterface
            stopped.physicalInterface = previous.physicalInterface
        }
        publish(stopped, markClean: cleaned)
        if !cleaned {
            fputs("HajimiHelper: network cleanup incomplete; retrying in background\n", stderr)
        }
        noteClientContact()
        return snapshot()
    }

    private func finishStoppedInterfaceCleanup(_ interface: String?) {
        closeTunnelFileDescriptor()
        setOwnerPID(0)
        if let interface { _ = try? run("/sbin/ifconfig", [interface, "down"]) }
    }

    /// Called only after all tracked routes, bypasses and DNS snapshots have
    /// been verified restored; never for an idle/restarted Helper's empty state.
    private func recordRestoredSession(_ token: String?) {
        guard let token else { return }
        stateLock.lock()
        if ownerPID > 0 {
            lastRestoredSessionToken = token
            lastRestoredSessionOwnerPID = ownerPID
            currentState.lastRestoredSessionToken = token
        }
        stateLock.unlock()
    }

    private func setOwnerPID(_ pid: pid_t) {
        stateLock.lock()
        ownerPID = pid
        stateLock.unlock()
    }

    private func beginHandoff(newSession: Bool) -> UInt64 {
        stateLock.lock()
        defer { stateLock.unlock() }
        if newSession {
            sessionGeneration &+= 1
            pendingHandoffs = 0
            deliveredHandoff = false
            handoffCompletion = DispatchGroup()
            handoffCompletion?.enter()
            handoffCompletionSignalled = false
        }
        pendingHandoffs += 1
        return sessionGeneration
    }

    private func assertClientMayOwnTunnel(_ clientPID: pid_t) throws {
        stateLock.lock()
        let owner = ownerPID
        stateLock.unlock()
        guard clientPID > 0 else {
            throw HelperServiceError.command("无法识别客户端进程")
        }
        if owner == 0 || owner == clientPID { return }
        // A prepared session can never be inherited by another PID. The
        // watchdog first closes the old FD; a new prepare gets a fresh token.
        throw HelperServiceError.command("增强模式已由其他 Hajimi 进程占用（pid \(owner)）")
    }

    private static func hasActiveSession(_ state: HajimiHelperTunnelState) -> Bool {
        state.running || state.phase != nil
    }

    private func assertOptionalSessionToken(_ token: String?, caller: MutationCaller) throws {
        guard let token else { return }
        stateLock.lock()
        let matches = currentState.sessionToken == token
        let acknowledgementOwner: pid_t
        if case .authenticatedPeer(_, let pid, _) = caller { acknowledgementOwner = pid }
        else { acknowledgementOwner = 0 }
        let acknowledgedClean = !Self.hasActiveSession(currentState) && verifiedStoppedRouteCleanup &&
            currentState.sessionToken == nil && lastRestoredSessionToken == token &&
            acknowledgementOwner > 0 && lastRestoredSessionOwnerPID == acknowledgementOwner
        stateLock.unlock()
        guard matches || acknowledgedClean else {
            throw HelperServiceError.command("隧道会话已变更，拒绝过期操作")
        }
    }

    private func assertOwnedSession(sessionToken: String?, clientPID: pid_t) throws {
        stateLock.lock()
        let valid = clientPID > 0 && ownerPID == clientPID && sessionToken != nil &&
            currentState.sessionToken == sessionToken && Self.hasActiveSession(currentState)
        stateLock.unlock()
        guard valid else {
            throw HelperServiceError.command("隧道会话不存在、已过期或不属于当前进程")
        }
    }

    private func assertCommitStillLive() throws {
        guard let identity = commitIdentity else { return }
        stateLock.lock()
        let valid = ownerPID == identity.clientPID &&
            currentState.sessionToken == identity.token && currentState.phase == .committing &&
            ticksSinceClientContact < Self.healthTicksBeforeTeardown &&
            preparedDeadline.map { environment.now() < $0 } == true
        stateLock.unlock()
        guard valid, isProcessAlive(identity.clientPID) else {
            throw HelperServiceError.command("隧道启动已取消、客户端失联或准备超时")
        }
    }

    /// Pure permission policy, also exercised without creating utun or routes.
    static func mayMutateTunnel(caller: MutationCaller, ownerPID: pid_t,
                                ownerIsAlive: Bool) -> Bool {
        switch caller {
        case .daemonCleanup:
            return true
        case .authenticatedPeer(let uid, let pid, let allowedUID):
            // UID 0 is a kernel-authenticated root maintenance client. Sharing
            // the installing user's UID alone grants no live-session override.
            if uid == 0 { return true }
            guard uid == allowedUID, uid > 0, pid > 0 else { return false }
            return ownerPID == 0 || ownerPID == pid || !ownerIsAlive
        }
    }

    private func assertMutationCallerMayOperate(_ caller: MutationCaller) throws {
        stateLock.lock()
        let owner = ownerPID
        let preparing = currentState.phase == .prepared || currentState.phase == .committing
        stateLock.unlock()
        if preparing, case .authenticatedPeer(let uid, let pid, _) = caller,
           uid != 0, pid != owner {
            throw HelperServiceError.command("准备中的增强模式属于其他 Hajimi 进程（pid \(owner)）")
        }
        guard Self.mayMutateTunnel(caller: caller, ownerPID: owner,
                                  ownerIsAlive: isProcessAlive(owner)) else {
            if case .authenticatedPeer(_, let pid, _) = caller, pid <= 0 {
                throw HelperServiceError.command("无法识别客户端进程，拒绝修改增强模式")
            }
            throw HelperServiceError.command("增强模式已由其他 Hajimi 进程占用（pid \(owner)）")
        }
    }

    private func isProcessAlive(_ pid: pid_t) -> Bool {
        guard pid > 0 else { return false }
        if let probe = environment.isProcessAlive { return probe(pid) }
        // kill(pid, 0) probes existence without signalling; verify via sysctl
        // that the process has not become a zombie awaiting waitpid().
        guard kill(pid, 0) == 0 || errno == EPERM else { return false }
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        if sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 {
            return info.kp_proc.p_stat != SZOMB
        }
        return true
    }

    /// Drop addresses that must never become physical host routes: unspecified,
    /// loopback, link-local, multicast, and the tunnel's own 198.18/15 block.
    private func sanitizeBypassAddresses(_ addresses: [String]) -> [String] {
        addresses.filter { address in
            let value = address.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty else { return false }
            if value.contains(":") {
                let lower = value.lowercased()
                if lower == "::" || lower.hasPrefix("::1") { return false }
                if lower.hasPrefix("fe80:") || lower.hasPrefix("ff") { return false }
                return true
            }
            let parts = value.split(separator: ".").compactMap { UInt8($0) }
            guard parts.count == 4 else { return false }
            if parts[0] == 0 { return false }                     // 0.0.0.0/8
            if parts[0] == 127 { return false }                   // loopback
            if parts[0] >= 224 { return false }                   // multicast/reserved
            if parts[0] == 198 && (parts[1] == 18 || parts[1] == 19) {
                return false                                      // tunnel / fake-IP space
            }
            return true
        }
    }

    /// `tun-excluded-routes` stay as CIDRs so LAN / RFC1918 prefixes leave
    /// the tunnel as a net route, not a single host.
    func sanitizeExcludedRoutes(_ routes: [String]) -> [String] {
        Self.normalizedExcludedRoutes(routes)
    }

    static func normalizedExcludedRoutes(_ routes: [String]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for raw in routes {
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty else { continue }
            let pieces = value.split(separator: "/", maxSplits: 1).map(String.init)
            let address = pieces[0]
            if address.contains(":") {
                let lower = address.lowercased()
                if lower == "::" || lower.hasPrefix("::1") { continue }
                if lower.hasPrefix("fe80:") || lower.hasPrefix("ff") { continue }
                let prefix = pieces.count == 2 ? Int(pieces[1]) : 128
                guard let prefix, (0...128).contains(prefix) else { continue }
                let cidr = "\(address)/\(prefix)"
                if seen.insert(cidr.lowercased()).inserted { result.append(cidr) }
                continue
            }
            let parts = address.split(separator: ".").compactMap { UInt8($0) }
            guard parts.count == 4 else { continue }
            if parts[0] == 0 || parts[0] == 127 || parts[0] >= 224 { continue }
            if parts[0] == 198 && (parts[1] == 18 || parts[1] == 19) { continue }
            let prefix = pieces.count == 2 ? Int(pieces[1]) : 32
            guard let prefix, (0...32).contains(prefix) else { continue }
            let cidr = "\(address)/\(prefix)"
            if seen.insert(cidr).inserted { result.append(cidr) }
        }
        return result
    }

    /// `tun-included-routes` is an allow-list of prefixes that should go
    /// into the tunnel instead of the default 1/8…128/1 split. Same
    /// sanitizer as excluded routes, minus the 198.18/15 skip — those
    /// addresses already live on utun.
    static func normalizedIncludedRoutes(_ routes: [String]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for raw in routes {
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty else { continue }
            let pieces = value.split(separator: "/", maxSplits: 1).map(String.init)
            let address = pieces[0]
            if address.contains(":") {
                let lower = address.lowercased()
                if lower == "::" || lower.hasPrefix("::1") { continue }
                if lower.hasPrefix("fe80:") || lower.hasPrefix("ff") { continue }
                let prefix = pieces.count == 2 ? Int(pieces[1]) : 128
                guard let prefix, (0...128).contains(prefix) else { continue }
                let cidr = "\(address)/\(prefix)"
                if seen.insert(cidr.lowercased()).inserted { result.append(cidr) }
                continue
            }
            let parts = address.split(separator: ".").compactMap { UInt8($0) }
            guard parts.count == 4 else { continue }
            if parts[0] == 0 || parts[0] == 127 || parts[0] >= 224 { continue }
            let prefix = pieces.count == 2 ? Int(pieces[1]) : 32
            guard let prefix, (0...32).contains(prefix) else { continue }
            let cidr = "\(address)/\(prefix)"
            if seen.insert(cidr).inserted { result.append(cidr) }
        }
        return result
    }

    private func cleanupStoppedRoutesIfNeeded() {
        stateLock.lock()
        let needs = !Self.hasActiveSession(currentState) && !verifiedStoppedRouteCleanup
        stateLock.unlock()
        guard needs else {
            stateLock.lock()
            cleanupScheduled = false
            stateLock.unlock()
            return
        }
        let dnsRestored = restoreSystemDNS()
        stateLock.lock()
        let hasTrackedRoutes = !installedTunnelRoutes.isEmpty
        stateLock.unlock()
        let routesRemoved = !hasTrackedRoutes || removeRoutes(ignoringErrors: true)
        let bypassRemoved = removeProxyBypassRoutes(ignoringErrors: true)
        let scopedRemoved = removePhysicalIPv6ScopedRoutes()
        let cleaned = dnsRestored && bypassRemoved && routesRemoved && scopedRemoved
        if cleaned {
            let previous = snapshot()
            recordRestoredSession(previous.sessionToken)
            finishStoppedInterfaceCleanup(previous.tunnelInterface)
        }
        stateLock.lock()
        verifiedStoppedRouteCleanup = cleaned
        currentState.networkCleanupPending = !cleaned
        if cleaned {
            currentState = HajimiHelperTunnelState(running: false,
                lastRestoredSessionToken: lastRestoredSessionToken)
        }
        cleanupScheduled = false
        ticksSinceCleanupAttempt = 0
        stateLock.unlock()
    }

    // MARK: - Liveness

    private func startHealthMonitor() {
        healthTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: healthQueue)
        timer.schedule(deadline: .now() + Self.healthTickInterval,
                       repeating: Self.healthTickInterval, leeway: .milliseconds(100))
        timer.setEventHandler { [weak self] in self?.healthTick() }
        healthTimer = timer
        timer.resume()
    }

    private func healthTick() {
        stateLock.lock()
        let active = Self.hasActiveSession(currentState)
        let preparing = currentState.phase == .prepared || currentState.phase == .committing
        let owner = ownerPID
        if environment.monitorHealth {
            let continuousNow = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
            let previousNanos = lastHealthTickContinuousNanos
            lastHealthTickContinuousNanos = continuousNow
            if active, !preparing, owner > 0, isProcessAlive(owner) {
                // Keep the committed utun virtual interface permanently resident
                // across Wi-Fi disconnects, screen-off App Nap, and sleep/dark-wake
                // cycles as long as the owning HajimiApp process is alive.
                ticksSinceClientContact = 0
            } else if active, previousNanos > 0, continuousNow > previousNanos,
               Double(continuousNow - previousNanos) / 1_000_000_000 > 2.2,
               owner > 0, isProcessAlive(owner) {
                ticksSinceClientContact = 0
            }
        }
        if active { ticksSinceClientContact += 1 }
        if !active && !verifiedStoppedRouteCleanup { ticksSinceCleanupAttempt += 1 }
        let shouldRetryCleanup = Self.shouldRetryStoppedCleanup(
            running: active, cleaned: verifiedStoppedRouteCleanup,
            alreadyQueued: cleanupScheduled,
            ticksSinceAttempt: ticksSinceCleanupAttempt)
        if shouldRetryCleanup {
            cleanupScheduled = true
            ticksSinceCleanupAttempt = 0
        }
        let expired = preparing && preparedDeadline.map { environment.now() >= $0 } == true
        let teardownThreshold = (environment.monitorHealth && !preparing && owner > 0 && isProcessAlive(owner))
            ? Self.liveProcessHealthTicksBeforeTeardown
            : Self.healthTicksBeforeTeardown
        let shouldSchedule = active && !teardownScheduled &&
            (expired || (ticksSinceClientContact >= teardownThreshold &&
                         (preparing || pendingHandoffs == 0)))
        let generation = sessionGeneration
        if shouldSchedule { teardownScheduled = true }
        stateLock.unlock()
        if shouldRetryCleanup {
            operationQueue.async { [weak self] in self?.cleanupStoppedRoutesIfNeeded() }
        }
        guard shouldSchedule else { return }
        // App vanished (crash / force-quit). Drop routes without waiting for
        // the next IPC call — that is what used to leave the NIC black-holed.
        // A slow reload can sit ahead of this block in operationQueue; its
        // completion (or an independent heartbeat) may reset the missed ticks.
        operationQueue.async { [weak self] in
            guard let self else { return }
            self.stateLock.lock()
            let preparing = self.currentState.phase == .prepared || self.currentState.phase == .committing
            let expired = preparing && self.preparedDeadline.map { self.environment.now() >= $0 } == true
            let sameSession = self.ownerPID == owner && self.sessionGeneration == generation
            let shouldStop = (expired && sameSession) || Self.shouldExecuteQueuedTeardown(
                running: Self.hasActiveSession(self.currentState),
                missedTicks: self.ticksSinceClientContact,
                pendingHandoffs: preparing ? 0 : self.pendingHandoffs,
                currentOwner: self.ownerPID,
                scheduledOwner: owner,
                currentGeneration: self.sessionGeneration,
                scheduledGeneration: generation)
            self.teardownScheduled = false
            self.stateLock.unlock()
            guard shouldStop else { return }
            fputs("HajimiHelper: app liveness lost — tearing down tunnel\n", stderr)
            _ = self.stopLocked()
        }
    }

    /// Executes the exact watchdog decision with an injected monotonic clock.
    /// Never available to a live daemon's environment.
    func healthTickForSelfTest(waitForOperations: Bool = true) {
        precondition(!environment.monitorHealth && environment.run != nil)
        healthTick()
        if waitForOperations { operationQueue.sync {} }
    }

    func drainOperationsForSelfTest() {
        precondition(!environment.monitorHealth && environment.run != nil)
        operationQueue.sync {}
    }

    /// The queue can be delayed behind reload. A heartbeat or new session in
    /// the meantime invalidates its earlier decision to tear down the tunnel.
    static func shouldExecuteQueuedTeardown(running: Bool, missedTicks: Int,
                                            pendingHandoffs: Int,
                                            currentOwner: pid_t, scheduledOwner: pid_t,
                                            currentGeneration: UInt64,
                                            scheduledGeneration: UInt64) -> Bool {
        running && missedTicks >= healthTicksBeforeTeardown && pendingHandoffs == 0 &&
            currentOwner == scheduledOwner && currentGeneration == scheduledGeneration
    }

    static func shouldRetryStoppedCleanup(running: Bool, cleaned: Bool,
                                          alreadyQueued: Bool,
                                          ticksSinceAttempt: Int) -> Bool {
        !running && !cleaned && !alreadyQueued && ticksSinceAttempt >= cleanupRetryTicks
    }

    // MARK: - utun

    private static func openUTUN() throws -> (descriptor: Int32, name: String) {
        let descriptor = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        guard descriptor >= 0 else {
            throw HelperServiceError.command(String(cString: strerror(errno)))
        }
        do {
            var info = ctl_info()
            withUnsafeMutableBytes(of: &info.ctl_name) { raw in
                let name = Array("com.apple.net.utun_control".utf8) + [0]
                raw.copyBytes(from: name)
            }
            guard ioctl(descriptor, UInt(0xC0644E03), &info) == 0 else {
                throw HelperServiceError.command(String(cString: strerror(errno)))
            }
            var address = sockaddr_ctl()
            address.sc_len = UInt8(MemoryLayout<sockaddr_ctl>.size)
            address.sc_family = UInt8(AF_SYSTEM)
            address.ss_sysaddr = UInt16(AF_SYS_CONTROL)
            address.sc_id = info.ctl_id
            address.sc_unit = 0
            let connected = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_ctl>.size))
                }
            }
            guard connected == 0 else {
                throw HelperServiceError.command(String(cString: strerror(errno)))
            }
            var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            var length = socklen_t(name.count)
            guard getsockopt(descriptor, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &name, &length) == 0 else {
                throw HelperServiceError.command("无法读取接口名称：\(String(cString: strerror(errno)))")
            }
            let flags = fcntl(descriptor, F_GETFL, 0)
            if flags >= 0 { _ = fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) }
            _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC)
            for candidate in [Int32(4 * 1024 * 1024), Int32(2 * 1024 * 1024), Int32(1 * 1024 * 1024)] {
                var bufSize = candidate
                if setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size)) == 0 { break }
            }
            for candidate in [Int32(4 * 1024 * 1024), Int32(2 * 1024 * 1024), Int32(1 * 1024 * 1024)] {
                var bufSize = candidate
                if setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size)) == 0 { break }
            }
            return (descriptor, String(cString: name))
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    // MARK: System resolver

    private func networkServices() throws -> [String] {
        try SystemDNSRedirectTransaction.enabledServices(
            from: run("/usr/sbin/networksetup", ["-listallnetworkservices"]))
    }

    static func configuredDNSServers(from output: String) -> [String] {
        let lines = output.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return lines.first?.contains("aren't any") == true ? [] : lines
    }

    private static let dnsSnapshotURL = URL(
        fileURLWithPath: "/Library/Application Support/Hajimi/dns-redirect-snapshot.json"
    )

    private func loadPersistedDNSSnapshot() -> [String: [String]] {
        guard environment.run == nil,
              let data = try? Data(contentsOf: Self.dnsSnapshotURL),
              let decoded = try? JSONDecoder().decode([String: [String]].self, from: data) else {
            return [:]
        }
        return decoded
    }

    private func savePersistedDNSSnapshot(_ snapshot: [String: [String]]) {
        guard environment.run == nil else { return }
        if snapshot.isEmpty {
            try? FileManager.default.removeItem(at: Self.dnsSnapshotURL)
            return
        }
        let dir = Self.dnsSnapshotURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(snapshot) {
            try? data.write(to: Self.dnsSnapshotURL, options: .atomic)
        }
    }

    /// An orphaned override has no recoverable original DNS configuration in
    /// injected test fixtures, whereas in production we recover from the
    /// persisted snapshot or reset the stale Hajimi sink to DHCP ("Empty").
    private func ensureNoOrphanedDNSRedirect() throws {
        let services = try networkServices()
        guard !services.isEmpty else {
            throw HelperServiceError.command("无法读取网络服务，拒绝在 DNS 所有权不明时启动增强模式")
        }
        var persisted = loadPersistedDNSSnapshot()
        var persistedChanged = false
        for service in services {
            let output = try run("/usr/sbin/networksetup", ["-getdnsservers", service])
            if try SystemDNSRedirectTransaction.servers(from: output) == [dnsGateway] {
                guard environment.run == nil else {
                    throw HelperServiceError.command(
                        "网络服务 \(service) 仍指向旧 Hajimi DNS，原始 DNS 已不可恢复；请手动检查 DNS 后再启动")
                }
                stateLock.lock()
                let inMemory = savedDNSServers[service]
                stateLock.unlock()
                let candidate = inMemory ?? persisted[service] ?? []
                let recovered = candidate == [dnsGateway] ? [] : candidate
                let args = recovered.isEmpty ? ["Empty"] : recovered
                _ = try? run("/usr/sbin/networksetup", ["-setdnsservers", service] + args)
                let verifyOutput = try run("/usr/sbin/networksetup", ["-getdnsservers", service])
                if try SystemDNSRedirectTransaction.servers(from: verifyOutput) == [dnsGateway] {
                    throw HelperServiceError.command(
                        "网络服务 \(service) 仍指向旧 Hajimi DNS，自动恢复失败；请手动检查 DNS 后再启动")
                }
                if persisted.removeValue(forKey: service) != nil {
                    persistedChanged = true
                }
                stateLock.lock()
                savedDNSServers.removeValue(forKey: service)
                stateLock.unlock()
            }
        }
        if persistedChanged {
            savePersistedDNSSnapshot(persisted)
        }
    }

    private func redirectSystemDNS() throws {
        stateLock.lock()
        var saved = savedDNSServers
        stateLock.unlock()
        if saved.isEmpty {
            let persisted = loadPersistedDNSSnapshot()
            if !persisted.isEmpty {
                saved = persisted
            }
        }
        defer {
            stateLock.lock()
            savedDNSServers = saved
            stateLock.unlock()
            savePersistedDNSSnapshot(saved)
        }
        try SystemDNSRedirectTransaction.install(
            services: networkServices(), sink: dnsGateway, saved: &saved,
            read: { service in
                try SystemDNSRedirectTransaction.servers(
                    from: self.run("/usr/sbin/networksetup", ["-getdnsservers", service]))
            }, write: { service, servers in
                try self.run("/usr/sbin/networksetup", ["-setdnsservers", service] + servers)
            })
    }

    @discardableResult
    private func restoreSystemDNS() -> Bool {
        stateLock.lock()
        var saved = savedDNSServers
        stateLock.unlock()
        if saved.isEmpty {
            let persisted = loadPersistedDNSSnapshot()
            if !persisted.isEmpty {
                saved = persisted
            }
        }
        let failed = SystemDNSRedirectTransaction.restore(
            sink: dnsGateway, saved: saved,
            read: { service in
                try SystemDNSRedirectTransaction.servers(
                    from: self.run("/usr/sbin/networksetup", ["-getdnsservers", service]))
            }, write: { service, servers in
                let values = servers.isEmpty ? ["Empty"] : servers
                try self.run("/usr/sbin/networksetup", ["-setdnsservers", service] + values)
            })
        stateLock.lock()
        // Mutations run on operationQueue. Keep failed services so a stopped
        // helper can retry restoration instead of abandoning a broken resolver.
        savedDNSServers = failed
        stateLock.unlock()
        savePersistedDNSSnapshot(failed)
        return failed.isEmpty
    }

    private func defaultInterface() throws -> String {
        let output = try run("/sbin/route", ["-n", "get", "default"])
        guard let interface = routeInterface(output), !interface.hasPrefix("utun") else {
            throw HelperServiceError.defaultInterfaceMissing
        }
        return interface
    }

    private func ensureNoConflictingTunnel() throws {
        // Check the entire kernel table: probing only 1.1.1.1 misses another
        // app's split tunnel whose routes target a different destination.
        for family in ["inet", "inet6"] {
            let table = try run("/usr/sbin/netstat", ["-nr", "-f", family])
            guard table.contains("Destination"), table.contains("Netif") else {
                throw HelperServiceError.command("无法读取 \(family) 路由表，已阻止增强模式")
            }
            if let route = Self.firstConflictingTunnelRoute(in: table) {
                throw HelperServiceError.conflictingTunnel(route)
            }
        }
        if let interfaces = try? run("/sbin/ifconfig", []), interfaces.contains("fd00::9999:9999") {
            throw HelperServiceError.conflictingTunnel("Surge utun")
        }
        if let output = try? run("/sbin/route", ["-n", "get", "1.1.1.1"]),
           let interface = routeInterface(output), interface.hasPrefix("utun") {
            throw HelperServiceError.conflictingTunnel(interface)
        }
        if let output = try? run("/sbin/route", ["-n", "get", "-inet6", "2606:4700:4700::1111"]),
           let interface = routeInterface(output), interface.hasPrefix("utun") {
            throw HelperServiceError.conflictingTunnel(interface)
        }
    }

    /// Ignore only macOS's dormant scoped utun IPv6 defaults, link-local/
    /// multicast entries, and the tunnel's own local address. All other utun
    /// routes, including a foreign app's custom split routes, are a conflict.
    static func firstConflictingTunnelRoute(in table: String) -> String? {
        for line in table.components(separatedBy: .newlines) {
            let fields = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            guard fields.count >= 4, fields[3].hasPrefix("utun") else { continue }
            let destination = fields[0].lowercased()
            let gateway = fields[1].lowercased()
            let flags = fields[2]
            if destination.hasPrefix("fe80:") || destination.hasPrefix("ff") { continue }
            if destination == "default" && gateway.hasPrefix("fe80:") && flags.contains("I") {
                continue
            }
            if flags.contains("H") && !flags.contains("G") &&
                (destination == gateway || destination.hasPrefix("198.18.") ||
                 destination.hasPrefix("198.19.")) {
                continue
            }
            return "\(fields[0]) (\(fields[1]) → \(fields[3]))"
        }
        return nil
    }

    private func routeInterface(_ output: String) -> String? {
        Self.routeField("interface", in: output)
    }

    private static func routeField(_ name: String, in output: String) -> String? {
        for line in output.components(separatedBy: .newlines) {
            let pair = line.trimmingCharacters(in: .whitespaces)
                .split(separator: ":", maxSplits: 1).map(String.init)
            if pair.count == 2, pair[0] == name {
                let value = pair[1].trimmingCharacters(in: .whitespaces)
                return value.isEmpty ? nil : value
            }
        }
        return nil
    }

    private static func addressBytes(_ address: String, ipv6: Bool) -> [UInt8]? {
        if ipv6 {
            var parsed = in6_addr()
            guard address.withCString({ inet_pton(AF_INET6, $0, &parsed) }) == 1 else { return nil }
            return withUnsafeBytes(of: parsed) { Array($0) }
        }
        var parsed = in_addr()
        guard address.withCString({ inet_pton(AF_INET, $0, &parsed) }) == 1 else { return nil }
        return withUnsafeBytes(of: parsed) { Array($0) }
    }

    /// `route get -net` may fall back to a default or covering route. Verify
    /// the exact destination AND mask before any delete, not only its gateway.
    static func routeLookupIsOwned(_ output: String, route: String, gateway: String,
                                   tunnel: Bool, tunnelInterface: String? = nil,
                                   physicalInterface: String? = nil) -> Bool {
        let parts = route.split(separator: "/", maxSplits: 1).map(String.init)
        guard let requested = parts.first else { return false }
        let ipv6 = requested.contains(":")
        let bitCount = ipv6 ? 128 : 32
        let prefix = parts.count == 2 ? Int(parts[1]) : bitCount
        guard let prefix, (0...bitCount).contains(prefix),
              let expectedAddress = addressBytes(requested, ipv6: ipv6),
              let destination = routeField("destination", in: output),
              let observedAddress = addressBytes(destination, ipv6: ipv6),
              let observedGateway = routeField("gateway", in: output),
              let observedInterface = routeField("interface", in: output),
              expectedAddress.count == observedAddress.count else { return false }
        let mask: [UInt8] = (0..<expectedAddress.count).map { index in
            let remaining = prefix - index * 8
            if remaining >= 8 { return 0xff }
            if remaining <= 0 { return 0 }
            return UInt8(0xff ^ (0xff >> remaining))
        }
        if let observedMask = routeField("mask", in: output) {
            guard addressBytes(observedMask, ipv6: ipv6) == mask else { return false }
        } else {
            guard prefix == bitCount,
                  routeField("flags", in: output)?.contains("HOST") == true else { return false }
        }
        guard zip(expectedAddress, observedAddress).enumerated().allSatisfy({ index, pair in
            pair.0 & mask[index] == pair.1 & mask[index]
        }) else { return false }
        let matchedGateway: Bool
        if observedGateway == gateway {
            matchedGateway = true
        } else if observedGateway.contains(":"), gateway.contains(":"),
                  let actual = addressBytes(observedGateway, ipv6: true),
                  let expected = addressBytes(gateway, ipv6: true) {
            matchedGateway = actual == expected
        } else {
            matchedGateway = false
        }
        guard matchedGateway else { return false }
        if tunnel {
            guard observedInterface.hasPrefix("utun") else { return false }
            if let tunnelInterface, observedInterface != tunnelInterface { return false }
        } else if observedInterface.hasPrefix("utun") {
            return false
        } else if let physicalInterface, observedInterface != physicalInterface {
            return false
        }
        return true
    }

    private func currentRouteIsOurs(_ route: String, gateway: String,
                                    tunnel: Bool, physicalInterface: String? = nil) throws -> Bool {
        let address = route.split(separator: "/", maxSplits: 1).first.map(String.init) ?? route
        let fullPrefix = address.contains(":") ? 128 : 32
        let isHost = route.split(separator: "/", maxSplits: 1).last
            .flatMap { Int($0) } == fullPrefix || !route.contains("/")
        var arguments = ["-n", "get"]
        if address.contains(":") { arguments.append("-inet6") }
        arguments.append(isHost ? "-host" : "-net")
        arguments.append(isHost ? address : route)
        let output: String
        do { output = try run("/sbin/route", arguments) }
        catch {
            if Self.isMissingRoute(error) { return false }
            throw error
        }
        return Self.routeLookupIsOwned(output, route: route, gateway: gateway,
                                       tunnel: tunnel,
                                       tunnelInterface: tunnel ? snapshot().tunnelInterface : nil,
                                       physicalInterface: physicalInterface)
    }

    enum RouteMutation<Route: Hashable>: Equatable {
        case add(Route)
        case remove(Route)

        var destination: Route {
            switch self {
            case .add(let route), .remove(let route): return route
            }
        }
    }
    typealias TunnelRouteMutation = RouteMutation<String>

    struct RouteTransition<Route: Hashable> {
        let installed: [Route]
        let failure: Error?
        let rollbackFailures: [String]
        /// A subprocess timeout can happen after the kernel accepted a route.
        /// In that case even a successful rollback cannot prove the table's
        /// prior state, so close the session and retry any tracked cleanup.
        let outcomeUncertain: Bool

        var requiresTeardown: Bool { outcomeUncertain || !rollbackFailures.isEmpty }
    }
    typealias TunnelRouteTransition = RouteTransition<String>

    /// Pure route inventory transaction; `apply` can be a fake command in
    /// --self-test. Add new prefixes before removing old ones, and restore the
    /// old set if any mutation fails. Never discard a route if rollback could
    /// have left it present in the kernel.
    static func transitionTunnelRoutes(
        from installed: [String], to desired: [String],
        apply: (TunnelRouteMutation) throws -> Void
    ) -> TunnelRouteTransition {
        transitionRouteInventory(from: installed, to: desired, label: { $0 }, apply: apply)
    }

    /// The same transaction also protects physical bypass routes. An add that
    /// fails because an existing route already uses the verified physical
    /// gateway is satisfied externally and must NOT enter our delete inventory.
    static func transitionRouteInventory<Route: Hashable>(
        from installed: [Route], to desired: [Route],
        label: (Route) -> String,
        replaces: (Route, Route) -> Bool = { _, _ in false },
        alreadySatisfied: (Route, Error) -> Bool = { _, _ in false },
        apply: (RouteMutation<Route>) throws -> Void
    ) -> RouteTransition<Route> {
        let oldSet = Set(installed)
        let desiredSet = Set(desired)
        var active = oldSet
        var added: [Route] = []
        var operations: [RouteMutation<Route>] = []
        var removed = Set<Route>()
        var externallySatisfied = Set<Route>()
        var attempted: RouteMutation<Route>?
        do {
            for route in desired where !oldSet.contains(route) {
                // The kernel rejects another route at the same destination,
                // even when its gateway differs. Only callers that identify
                // such a replacement opt into removing the verified old path
                // before adding the new one; unrelated routes stay add-first.
                for previous in installed where !desiredSet.contains(previous)
                    && !removed.contains(previous) && replaces(previous, route) {
                    attempted = .remove(previous)
                    try apply(.remove(previous))
                    active.remove(previous)
                    removed.insert(previous)
                    operations.append(.remove(previous))
                }
                attempted = .add(route)
                do { try apply(.add(route)) }
                catch {
                    if alreadySatisfied(route, error) {
                        externallySatisfied.insert(route)
                        continue
                    }
                    throw error
                }
                active.insert(route)
                added.append(route)
                operations.append(.add(route))
            }
            for route in installed where !desiredSet.contains(route) && !removed.contains(route) {
                attempted = .remove(route)
                try apply(.remove(route))
                active.remove(route)
                removed.insert(route)
                operations.append(.remove(route))
            }
            return RouteTransition(installed: desired.filter { !externallySatisfied.contains($0) },
                                   failure: nil, rollbackFailures: [], outcomeUncertain: false)
        } catch {
            let failure = error
            let uncertain = (error as? HelperServiceError)?.operationMayHaveSucceeded == true
            // If `route add` timed out it may already have installed the new
            // prefix; attempt to remove it and keep it in the inventory if
            // that removal fails. A timed-out delete leaves its old prefix in
            // the inventory until stop verifies it is gone.
            if uncertain, case .add(let route)? = attempted {
                active.insert(route)
                added.append(route)
                operations.append(.add(route))
            }
            var rollbackFailures: [String] = []
            // Inverse execution order also handles same-destination gateway
            // changes: withdraw the new route before restoring its old path.
            for operation in operations.reversed() {
                switch operation {
                case .remove(let route):
                    do {
                        try apply(.add(route))
                        active.insert(route)
                    } catch {
                        active.insert(route) // May have succeeded despite an error.
                        rollbackFailures.append("恢复 \(label(route))：\(error.localizedDescription)")
                    }
                case .add(let route):
                    do {
                        try apply(.remove(route))
                        active.remove(route)
                    } catch {
                        if Self.isMissingRoute(error) {
                            active.remove(route)
                        } else {
                            rollbackFailures.append("撤销 \(label(route))：\(error.localizedDescription)")
                        }
                    }
                }
            }
            return RouteTransition(
                installed: (installed + added).filter { active.contains($0) },
                failure: failure, rollbackFailures: rollbackFailures,
                outcomeUncertain: uncertain)
        }
    }

    /// macOS `route delete` reports an absent route as an error, even though
    /// that is exactly the state teardown requires. Do not retry it forever.
    static func isMissingRoute(_ error: Error) -> Bool {
        guard let helperError = error as? HelperServiceError,
              case .command(let detail) = helperError else { return false }
        let text = detail.lowercased()
        return text.contains("not in table") || text.contains("no such process")
            || text.contains("network is unreachable") || text.contains("no route to host")
    }

    private func desiredTunnelRoutes(includedRoutes: [String]) -> [String] {
        let selected = Self.normalizedIncludedRoutes(includedRoutes)
        let ipv4 = selected.filter { !$0.contains(":") }
        let ipv6 = selected.filter { $0.contains(":") }
        let ipv4Set = ipv4.isEmpty ? ipv4Routes : ipv4
        let ipv6Set = ipv6.isEmpty && ipv4.isEmpty ? ipv6Routes : ipv6
        return ipv4Set + ipv6Set
    }

    private func applyTunnelRoute(_ mutation: TunnelRouteMutation) throws {
        let route = mutation.destination
        let command: String
        switch mutation {
        case .add: command = "add"
        case .remove:
            command = "delete"
            let gateway = route.contains(":") ? ipv6Gateway : ipv4Gateway
            // The route may have been replaced by another process since we
            // added it. A matching destination alone proves no ownership.
            guard try currentRouteIsOurs(route, gateway: gateway, tunnel: true) else { return }
        }
        let arguments = route.contains(":")
            ? ["-n", command, "-inet6", "-net", route, ipv6Gateway]
            : ["-n", command, "-net", route, ipv4Gateway]
        do { try run("/sbin/route", arguments) }
        catch {
            if case .remove = mutation, Self.isMissingRoute(error) { return }
            throw error
        }
    }

    private func reconcileTunnelRoutes(includedRoutes: [String]) throws {
        stateLock.lock()
        let recorded = installedTunnelRoutes
        stateLock.unlock()
        let previous: [String]
        do {
            previous = try recorded.filter {
                try currentRouteIsOurs($0, gateway: $0.contains(":") ? ipv6Gateway : ipv4Gateway,
                                       tunnel: true)
            }
        } catch {
            _ = stopLocked()
            throw error
        }
        let desired = desiredTunnelRoutes(includedRoutes: includedRoutes)
        let result = Self.transitionTunnelRoutes(from: previous, to: desired) { mutation in
            try self.applyTunnelRoute(mutation)
        }
        var retained = Set<String>()
        let inventory = result.failure == nil ? result.installed
            : (recorded + result.installed).filter { retained.insert($0).inserted }
        stateLock.lock()
        installedTunnelRoutes = inventory
        stateLock.unlock()
        guard let failure = result.failure else { return }
        if result.requiresTeardown || previous != recorded {
            _ = stopLocked()
            let rollback = result.rollbackFailures.joined(separator: "；")
            throw HelperServiceError.command(
                "路由更新失败且无法确认已恢复，已关闭增强模式：\(failure.localizedDescription)" +
                (rollback.isEmpty ? "" : "；\(rollback)"))
        }
        throw failure
    }

    /// A failed deletion must stay recorded: custom tun-included-routes are
    /// unknown to a fresh helper and cannot be reconstructed from the defaults.
    @discardableResult
    private func removeRoutes(ignoringErrors: Bool) -> Bool {
        stateLock.lock()
        let installed = installedTunnelRoutes
        stateLock.unlock()
        // Empty inventory is NOT proof that any matching route is ours. In
        // particular, Lurge uses the same split destinations; never sweep it.
        guard !installed.isEmpty else { return true }
        let failed = Self.routesRequiringRetry(installed) { route in
            do { try applyTunnelRoute(.remove(route)); return true }
            catch {
                if !ignoringErrors { fputs("\(error)\n", stderr) }
                return false
            }
        }
        stateLock.lock()
        installedTunnelRoutes = failed
        stateLock.unlock()
        return failed.isEmpty
    }

    static func routesRequiringRetry(_ installed: [String],
                                     remove: (String) -> Bool) -> [String] {
        installed.filter { !remove($0) }
    }

    private func installTunnelRoutes(includedRoutes: [String]) throws {
        var installed: [String] = []
        var attempted: String?
        do {
            for route in desiredTunnelRoutes(includedRoutes: includedRoutes) {
                attempted = route
                try applyTunnelRoute(.add(route))
                installed.append(route)
                attempted = nil
            }
        } catch {
            if let attempted,
               (error as? HelperServiceError)?.operationMayHaveSucceeded == true {
                // A timed-out add may already have taken effect. Delete it
                // during failed-start cleanup and retain it on any failure.
                installed.append(attempted)
            }
            stateLock.lock()
            installedTunnelRoutes = installed
            stateLock.unlock()
            throw error
        }
        stateLock.lock()
        installedTunnelRoutes = installed
        stateLock.unlock()
    }

    struct InstalledBypassRoute: Hashable {
        let destination: String
        let isIPv6: Bool
        let isNetwork: Bool
        /// The exact physical gateway used when installed. A later route at
        /// the same destination but a different gateway belongs to somebody
        /// else and must not be deleted by this Helper.
        let gateway: String
        let physicalInterface: String?

        init(destination: String, isIPv6: Bool, isNetwork: Bool, gateway: String,
             physicalInterface: String? = nil) {
            self.destination = destination
            self.isIPv6 = isIPv6
            self.isNetwork = isNetwork
            self.gateway = gateway
            self.physicalInterface = physicalInterface
        }

        func hasSameDestination(as other: Self) -> Bool {
            destination == other.destination && isIPv6 == other.isIPv6 && isNetwork == other.isNetwork
        }
    }

    private func scopedIPv6Observation(_ route: PhysicalIPv6ScopedRoute) throws
        -> PhysicalIPv6ScopedRoute.Observation? {
        do { return try PhysicalIPv6ScopedRoute.observation(run("/sbin/route", route.lookupArguments)) }
        catch {
            if Self.isMissingRoute(error) { return nil }
            throw error
        }
    }

    private func removePhysicalIPv6ScopedRoutes(keeping desired: PhysicalIPv6ScopedRoute? = nil) -> Bool {
        stateLock.lock(); let owned = physicalIPv6ScopedRoutes; stateLock.unlock()
        var pending: [PhysicalIPv6ScopedRoute] = []
        for route in owned {
            if route == desired { pending.append(route); continue }
            do {
                if let observed = try scopedIPv6Observation(route), route.matches(observed) {
                    do { try run("/sbin/route", route.mutationArguments("delete")) }
                    catch { if !Self.isMissingRoute(error) { throw error } }
                    if let after = try scopedIPv6Observation(route), route.matches(after) {
                        throw HelperServiceError.command("物理 IPv6 scoped 默认路由仍未清理")
                    }
                }
                // Missing, unscoped fallback, or a precise external replacement
                // is not ours to delete. Malformed/failed queries throw above.
            } catch { pending.append(route) }
        }
        stateLock.lock(); physicalIPv6ScopedRoutes = pending; stateLock.unlock()
        return pending.allSatisfy { $0 == desired }
    }

    private func desiredPhysicalIPv6ScopedRoute(physicalInterface: String, captureIPv6: Bool) throws
        -> PhysicalIPv6ScopedRoute? {
        guard captureIPv6 else { return nil }
        do {
            return try PhysicalIPv6ScopedRoute.physicalDefault(
                run("/sbin/route", ["-n", "get", "-inet6", "default"]), interface: physicalInterface)
        } catch {
            if Self.isMissingRoute(error) { return nil }
            throw error
        }
    }

    private func reconcilePhysicalIPv6ScopedRoute(physicalInterface: String, captureIPv6: Bool) throws {
        let desired = try desiredPhysicalIPv6ScopedRoute(physicalInterface: physicalInterface, captureIPv6: captureIPv6)
        try reconcilePhysicalIPv6ScopedRoute(desired: desired)
    }

    private func reconcilePhysicalIPv6ScopedRoute(desired: PhysicalIPv6ScopedRoute?) throws {
        guard removePhysicalIPv6ScopedRoutes(keeping: desired) else {
            throw HelperServiceError.command("旧物理 IPv6 scoped 默认路由尚未恢复")
        }
        guard let desired else { return }
        if let observed = try scopedIPv6Observation(desired), observed.isScoped {
            guard desired.matches(observed) else {
                throw HelperServiceError.command("已有其他物理 IPv6 scoped 默认路由，拒绝覆盖")
            }
            return // Borrow an existing exact route; do not acquire ownership.
        }
        // An unscoped default returned by get -ifscope is only a fallback,
        // never evidence that the interface-scoped route already exists.
        stateLock.lock(); physicalIPv6ScopedRoutes.removeAll { $0 == desired }; stateLock.unlock()
        func trackAttempt() {
            stateLock.lock()
            if !physicalIPv6ScopedRoutes.contains(desired) { physicalIPv6ScopedRoutes.append(desired) }
            stateLock.unlock()
        }
        do {
            try run("/sbin/route", desired.mutationArguments("add"))
            trackAttempt() // Before any post-add query or liveness check.
        }
        catch {
            if (error as? HelperServiceError)?.operationMayHaveSucceeded == true {
                trackAttempt(); throw error
            }
            let text = error.localizedDescription.lowercased()
            if (text.contains("file exists") || text.contains("already in table")),
               let observed = try? scopedIPv6Observation(desired), desired.matches(observed) {
                return // Another owner won the add race; borrow, never delete.
            }
            throw error // A deterministic no-effect failure owns no route.
        }
        guard let verified = try scopedIPv6Observation(desired), verified.isUp, desired.matches(verified) else {
            throw HelperServiceError.command("物理 IPv6 scoped 默认路由安装后未通过精确校验")
        }
    }

    private struct ReloadPhysicalNetworkPlan {
        let interface: String
        let gateway: String?
        let ipv6ScopedRoute: PhysicalIPv6ScopedRoute?
    }

    /// Every operation here is read-only. In particular, a failed route get
    /// (even its timeout) cannot have installed a route or changed DNS. Keep
    /// the running owner/session untouched and let the App retry on recovery.
    private func preflightReloadPhysicalNetwork(needsGateway: Bool, captureIPv6: Bool) throws
        -> ReloadPhysicalNetworkPlan {
        func notReady(_ detail: String) -> HelperServiceError {
            .physicalNetworkNotReady("物理网络尚未就绪，请等待重新连接：" + detail)
        }
        func parseRouteFields(_ output: String) throws -> [String: String] {
            var fields: [String: String] = [:]
            for line in output.split(separator: "\n") {
                let pair = line.split(separator: ":", maxSplits: 1).map {
                    String($0).trimmingCharacters(in: .whitespaces)
                }
                if pair.count == 2, ["destination", "mask", "gateway", "interface", "flags"].contains(pair[0]) {
                    guard fields[pair[0]] == nil else { throw HelperServiceError.command("物理默认路由字段重复") }
                    fields[pair[0]] = pair[1]
                }
            }
            return fields
        }
        func isValidIPv4Gateway(_ value: String) -> Bool {
            guard ![ipv4Gateway, dnsGateway, ipv6Gateway].contains(value),
                  let bytes = Self.addressBytes(value, ipv6: false), bytes.count == 4,
                  bytes[0] != 0, bytes[0] != 127, bytes[0] < 224 else {
                return false
            }
            return true
        }
        func probeFallbackDefaultFields() -> [String: String]? {
            // Only probe real kernel interfaces/tables when not running injected test fixtures.
            guard environment.run == nil else { return nil }
            var candidates: [String] = []
            stateLock.lock()
            let lastPhysical = currentState.physicalInterface
            stateLock.unlock()
            if let lastPhysical, PhysicalIPv6ScopedRoute.validInterface(lastPhysical) {
                candidates.append(lastPhysical)
            }
            var list: UnsafeMutablePointer<ifaddrs>?
            if getifaddrs(&list) == 0 {
                defer { freeifaddrs(list) }
                let activeFlags = UInt32(IFF_UP | IFF_RUNNING)
                var cursor = list, visited = 0
                while let entry = cursor, visited < 4_096 {
                    visited += 1; cursor = entry.pointee.ifa_next
                    guard (entry.pointee.ifa_flags & activeFlags) == activeFlags,
                          let rawName = entry.pointee.ifa_name else { continue }
                    let name = String(cString: rawName)
                    guard PhysicalIPv6ScopedRoute.validInterface(name),
                          let addr = entry.pointee.ifa_addr,
                          Int32(addr.pointee.sa_family) == AF_INET else { continue }
                    var v4 = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    guard inet_ntop(AF_INET, &v4, &buf, socklen_t(buf.count)) != nil else { continue }
                    let ip = String(cString: buf)
                    if ip.hasPrefix("127.") || ip.hasPrefix("169.254.") { continue }
                    if name == "en0" && !candidates.contains("en0") {
                        candidates.insert("en0", at: 0)
                    } else if !candidates.contains(name) {
                        candidates.append(name)
                    }
                }
            }
            for candidate in candidates {
                if let scopedOut = try? run("/sbin/route", ["-n", "get", "-ifscope", candidate, "default"]),
                   let parsed = try? parseRouteFields(scopedOut),
                   parsed["interface"] == candidate,
                   let gw = parsed["gateway"], isValidIPv4Gateway(gw) {
                    return parsed
                }
            }
            if let table = try? run("/usr/sbin/netstat", ["-nr", "-f", "inet"]) {
                for line in table.components(separatedBy: .newlines) {
                    let cols = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
                    guard cols.count >= 4 else { continue }
                    let dest = cols[0], gw = cols[1], fl = cols[2], netif = cols[3]
                    guard ["default", "0.0.0.0", "0.0.0.0/0"].contains(dest),
                          PhysicalIPv6ScopedRoute.validInterface(netif),
                          fl.contains("U"), fl.contains("G"),
                          isValidIPv4Gateway(gw) else { continue }
                    return [
                        "destination": "default",
                        "mask": "default",
                        "gateway": gw,
                        "interface": netif,
                        "flags": "<UP,GATEWAY,DONE,STATIC>"
                    ]
                }
            }
            return nil
        }
        func readDefault(ipv6: Bool, scopedInterface: String? = nil) throws -> String? {
            do {
                return try run("/sbin/route", ipv6 ? ["-n", "get", "-inet6", "default"] : ["-n", "get", "default"])
            } catch {
                if ipv6 {
                    if let scopedInterface, environment.run == nil,
                       let scopedOut = try? run("/sbin/route", ["-n", "get", "-inet6", "-ifscope", scopedInterface, "default"]) {
                        return scopedOut
                    }
                    if Self.isMissingRoute(error) { return nil }
                }
                throw notReady(error.localizedDescription)
            }
        }
        let initialOutput = try? readDefault(ipv6: false)
        var fields: [String: String]
        if let initialOutput {
            fields = try parseRouteFields(initialOutput)
        } else if let fallback = probeFallbackDefaultFields() {
            fields = fallback
        } else {
            _ = try readDefault(ipv6: false)
            throw notReady("物理默认路由尚未就绪")
        }
        stateLock.lock()
        let currentTunnel = currentState.tunnelInterface
        stateLock.unlock()
        let rawInterface = fields["interface"] ?? ""
        let rawFlags = Set((fields["flags"] ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
            .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).uppercased() })
        let rawGateway = fields["gateway"] ?? ""
        let needsFallbackProbe = rawInterface.isEmpty
            || (currentTunnel != nil && !currentTunnel!.isEmpty && rawInterface == currentTunnel)
            || !rawFlags.contains("UP")
            || (needsGateway && (rawGateway.isEmpty || !rawFlags.contains("GATEWAY")))
        if needsFallbackProbe, let fallback = probeFallbackDefaultFields() {
            fields = fallback
        }
        guard let interface = fields["interface"], !interface.isEmpty else {
            throw notReady("无法确定物理默认网络接口")
        }
        if let currentTunnel, !currentTunnel.isEmpty, interface == currentTunnel {
            throw notReady("物理默认路由尚未就绪")
        }
        guard PhysicalIPv6ScopedRoute.validInterface(interface) else {
            throw HelperServiceError.command("默认路由不是有效的物理网络接口，拒绝更新增强模式")
        }
        if let value = fields["gateway"], [ipv4Gateway, dnsGateway, ipv6Gateway].contains(value) {
            throw HelperServiceError.command("无法解析物理默认网关（当前指向隧道）")
        }
        guard let destination = fields["destination"], let mask = fields["mask"],
              let flagText = fields["flags"] else { throw notReady("物理默认路由信息尚不完整") }
        let flags = Set(flagText.trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
            .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).uppercased() })
        guard ["default", "0.0.0.0", "0.0.0.0/0"].contains(destination),
              ["default", "0.0.0.0"].contains(mask),
              !flags.contains("HOST"), !flags.contains("REJECT"), !flags.contains("BLACKHOLE") else {
            throw HelperServiceError.command("查询结果不是可用的物理默认路由")
        }
        guard flags.contains("UP") else { throw notReady("物理默认路由尚未可用") }
        let gateway: String?
        if needsGateway {
            guard let value = fields["gateway"], !value.isEmpty, flags.contains("GATEWAY") else {
                throw notReady("物理默认网关尚未就绪")
            }
            guard let bytes = Self.addressBytes(value, ipv6: false), bytes.count == 4,
                  bytes[0] != 0, bytes[0] != 127, bytes[0] < 224 else {
                throw HelperServiceError.command("物理默认网关不是有效的 IPv4 网关")
            }
            gateway = value
        } else { gateway = nil }
        let ipv6: PhysicalIPv6ScopedRoute?
        if captureIPv6, let output = try readDefault(ipv6: true, scopedInterface: interface) {
            // Successful but conflicting/malformed observations retain their
            // protection error. They must never be labelled temporary absence.
            ipv6 = try PhysicalIPv6ScopedRoute.physicalDefault(output, interface: interface)
        } else { ipv6 = nil }
        return ReloadPhysicalNetworkPlan(interface: interface, gateway: gateway, ipv6ScopedRoute: ipv6)
    }

    private func defaultGateway(from routeGetOutput: String) throws -> String {
        for line in routeGetOutput.components(separatedBy: .newlines) {
            let pair = line.trimmingCharacters(in: .whitespaces)
                .split(separator: ":", maxSplits: 1).map(String.init)
            if pair.count == 2, pair[0] == "gateway" {
                let value = pair[1].trimmingCharacters(in: .whitespaces)
                if !value.isEmpty { return value }
            }
        }
        throw HelperServiceError.command("无法解析默认网关")
    }

    private func desiredBypassRoutes(hosts: [String], nets: [String],
                                     gateway: String?, physicalInterface: String) -> [InstalledBypassRoute] {
        guard let gateway else { return [] }
        var desired: [InstalledBypassRoute] = []
        var seen = Set<InstalledBypassRoute>()
        func append(_ route: InstalledBypassRoute) {
            if seen.insert(route).inserted { desired.append(route) }
        }
        for address in hosts.prefix(64) {
            let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let isIPv6 = trimmed.contains(":")
            if isIPv6 != gateway.contains(":") { continue }
            append(InstalledBypassRoute(destination: trimmed, isIPv6: isIPv6,
                                        isNetwork: false, gateway: gateway,
                                        physicalInterface: physicalInterface))
        }
        for cidr in nets.prefix(32) {
            let isIPv6 = cidr.contains(":")
            if isIPv6 != gateway.contains(":") { continue }
            append(InstalledBypassRoute(destination: cidr, isIPv6: isIPv6,
                                        isNetwork: true, gateway: gateway,
                                        physicalInterface: physicalInterface))
        }
        return desired
    }

    private func applyBypassRoute(_ mutation: RouteMutation<InstalledBypassRoute>) throws {
        let route = mutation.destination
        var args: [String] = ["-n"]
        switch mutation {
        case .add: args.append("add")
        case .remove:
            args.append("delete")
            guard try currentRouteIsOurs(route.destination, gateway: route.gateway,
                                         tunnel: false, physicalInterface: route.physicalInterface) else { return }
        }
        if route.isIPv6 { args.append("-inet6") }
        args.append(route.isNetwork ? "-net" : "-host")
        args.append(route.destination)
        args.append(route.gateway)
        do { try run("/sbin/route", args) }
        catch {
            if case .remove = mutation, Self.isMissingRoute(error) { return }
            throw error
        }
    }

    /// A pre-existing physical route already bypasses utun and should not be
    /// owned or deleted by us. Only accept this after a failed add and a
    /// read-only route lookup confirming the active path and gateway.
    private func bypassAlreadyPhysical(_ route: InstalledBypassRoute,
                                       physicalInterface: String,
                                       error: Error) -> Bool {
        if (error as? HelperServiceError)?.operationMayHaveSucceeded == true { return false }
        guard !physicalInterface.isEmpty, !physicalInterface.hasPrefix("utun") else { return false }
        let destination = route.destination.split(separator: "/").first.map(String.init)
            ?? route.destination
        let args = route.isIPv6
            ? ["-n", "get", "-inet6", destination]
            : ["-n", "get", destination]
        guard let output = try? run("/sbin/route", args),
              routeInterface(output) == physicalInterface else { return false }
        let gateway = try? defaultGateway(from: output)
        return gateway == route.gateway || gateway == nil || gateway?.hasPrefix("link#") == true
    }

    private func reconcileBypassRoutes(hosts: [String], nets: [String],
                                       gateway: String?, physicalInterface: String) throws {
        stateLock.lock()
        let recorded = proxyBypassRoutes
        stateLock.unlock()
        let previous: [InstalledBypassRoute]
        do {
            previous = try recorded.filter {
                try currentRouteIsOurs($0.destination, gateway: $0.gateway, tunnel: false,
                                       physicalInterface: $0.physicalInterface)
            }
        } catch {
            _ = stopLocked()
            throw error
        }
        let desired = desiredBypassRoutes(hosts: hosts, nets: nets, gateway: gateway,
                                         physicalInterface: physicalInterface)
        let result = Self.transitionRouteInventory(
            from: previous, to: desired, label: { $0.destination },
            replaces: { $0.hasSameDestination(as: $1) },
            alreadySatisfied: { route, error in
                self.bypassAlreadyPhysical(route, physicalInterface: physicalInterface,
                                           error: error)
            }, apply: { try self.applyBypassRoute($0) })
        var retained = Set<InstalledBypassRoute>()
        let inventory = result.failure == nil ? result.installed
            : (recorded + result.installed).filter { retained.insert($0).inserted }
        stateLock.lock()
        proxyBypassRoutes = inventory
        stateLock.unlock()
        guard let failure = result.failure else { return }
        let rollback = result.rollbackFailures.joined(separator: "；")
        if snapshot().running {
            // Tunnel CIDRs may already be updated. On any bypass failure,
            // even a successful local rollback is not enough to claim the
            // whole reload succeeded: fail closed instead of losing a proxy
            // server's physical escape route while the App keeps using utun.
            _ = stopLocked()
            throw HelperServiceError.command(
                "代理旁路路由更新失败，已关闭增强模式：\(failure.localizedDescription)" +
                (rollback.isEmpty ? "" : "；\(rollback)"))
        }
        throw failure // Start catch removes the new utun routes and DNS.
    }

    @discardableResult
    private func removeProxyBypassRoutes(ignoringErrors: Bool) -> Bool {
        stateLock.lock()
        let routes = proxyBypassRoutes
        stateLock.unlock()
        var failed: [InstalledBypassRoute] = []
        for route in routes {
            do { try applyBypassRoute(.remove(route)) }
            catch {
                if !ignoringErrors { fputs("\(error)\n", stderr) }
                failed.append(route)
            }
        }
        stateLock.lock()
        proxyBypassRoutes = failed
        stateLock.unlock()
        return failed.isEmpty
    }

    /// Runs a short-lived helper tool with a hard deadline so a stuck
    /// `route`/`ifconfig` cannot freeze the operation queue forever.
    @discardableResult
    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        try assertCommitStillLive()
        if let command = environment.run { return try command(executable, arguments) }
        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()

        let deadline = Date().addingTimeInterval(Self.processTimeout)
        while process.isRunning, Date() < deadline {
            usleep(500)
        }
        if process.isRunning {
            process.terminate()
            let killDeadline = Date().addingTimeInterval(1)
            while process.isRunning, Date() < killDeadline { usleep(500) }
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            throw HelperServiceError.timeout(
                "\(executable) 超时（\(Int(Self.processTimeout))s）：\(arguments.joined(separator: " "))")
        }

        let output = String(data: stdout.fileHandleForReading.readDataToEndOfFile(),
                            encoding: .utf8) ?? ""
        let error = String(data: stderr.fileHandleForReading.readDataToEndOfFile(),
                           encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            let detail = error.trimmingCharacters(in: .whitespacesAndNewlines)
            throw HelperServiceError.command(detail.isEmpty
                                             ? "\(executable) 执行失败（\(process.terminationStatus)）"
                                             : detail)
        }
        return output
    }
}

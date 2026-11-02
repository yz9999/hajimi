import Foundation
import HajimiCore
import HajimiRuntime
import HajimiDiagnosticsUI

/// Presentation/configuration identity only. The Foundation runtime receives
/// an opaque revision, never policy names, profile contents or credentials.
struct NetworkDiagnosticsConfiguration: Equatable {
    var mode: String
    var selectedPolicy: String
    var groupSelections: [String: String]
    var profileRevision: Int
    var systemProxy: Bool
}

struct AppRuntimeOwnerSnapshot: Equatable {
    var endpoint: RuntimeEndpointState
    var lifecycleRevision: UInt64
    var startedAt: Date? = nil
}

/// Describes the machine's traffic capture and selected route. Optional
/// HTTP/SOCKS listeners are a separate capability, not proof of capture.
struct AppConnectionPresentation: Equatable {
    enum Tone: Equatable { case active, neutral, pending, warning, failure }

    var title: String
    var detail: String
    var tone: Tone
    var toolTip: String { "\(title)\n\(detail)" }

    static func make(mode: OutboundMode, systemProxyEnabled: Bool,
                     listener: RuntimeEndpointState, enhanced: RuntimeEndpointState,
                     enhancedRequestPending: Bool = false,
                     enhancedRequested: Bool = false, enhancedWaiting: String? = nil,
                     systemProxyChanging: Bool = false, systemProxyFailure: String? = nil,
                     listenerFailure: String? = nil, enhancedFailure: String? = nil) -> Self {
        let route = mode == .direct ? "直连" : mode.displayName
        let listenerError = listener.phase == .failed ? (listenerFailure ?? "本地代理尚未恢复") : listenerFailure
        let enhancedError = enhanced.phase == .failed ? (enhancedFailure ?? "增强模式尚未恢复") : enhancedFailure
        func result(_ title: String, _ detail: String, _ tone: Tone,
                    warnings: [String] = []) -> Self {
            Self(title: title, detail: ([detail] + warnings).joined(separator: "；"),
                 tone: warnings.isEmpty ? tone : (tone == .failure ? .failure : .warning))
        }
        if enhancedRequested, !enhancedRequestPending, enhanced.phase != .stopping,
           let enhancedWaiting {
            return result("增强模式等待网络恢复", enhancedWaiting, .pending)
        }
        let enhancedPending = enhancedRequestPending && !enhanced.isPresent
        if enhanced.isPresent || enhanced.phase == .starting || enhanced.phase == .stopping || enhancedPending {
            let phase = enhancedPending && enhanced.phase != .stopping ? RuntimePhase.starting : enhanced.phase
            switch phase {
            case .running where enhanced.isPresent:
                let warnings = (listenerError.map { ["本地代理异常：\($0)"] } ?? [])
                    + (systemProxyFailure.map { ["系统代理异常：\($0)"] } ?? [])
                return result("增强模式 · \(route)", "原生 TUN 数据面已就绪"
                    + (systemProxyChanging ? "；系统代理设置切换中" : ""), .active, warnings: warnings)
            case .starting:
                return result("增强模式正在启动", "正在准备隧道、规则与路由 · \(route)", .pending)
            case .stopping:
                return result("增强模式正在停止", "正在恢复系统路由与 DNS", .pending)
            case .failed:
                return result("增强模式异常", enhancedError ?? "隧道尚未就绪，正在等待恢复", .failure)
            case .stopped, .running:
                return result("增强模式尚未就绪", "保留的隧道会话尚未确认可用", .pending)
            }
        }
        if enhancedRequested {
            if let enhancedError {
                return result("增强模式等待恢复", enhancedError, .failure)
            }
            return result("增强模式等待网络恢复", "保持开启，网络就绪后自动恢复 · \(route)", .pending)
        }
        if systemProxyChanging {
            return result("代理模式切换中", "正在应用或恢复系统代理设置，尚未确认完成", .pending,
                warnings: systemProxyFailure.map { ["系统代理异常：\($0)"] } ?? [])
        }
        if systemProxyEnabled {
            let warnings = enhancedError.map { ["增强模式失败：\($0)"] } ?? []
            if let systemProxyFailure {
                return result("代理模式异常", "系统代理设置尚未确认：\(systemProxyFailure)", .failure,
                    warnings: warnings)
            }
            switch listener.phase {
            case .running where listener.isPresent:
                return result("代理模式 · \(route)", "系统代理已接管", .active, warnings: warnings)
            case .starting:
                return result("代理模式正在启动", "系统代理仍启用，正在等待本地代理就绪", .pending,
                    warnings: warnings)
            case .stopping:
                return result("代理模式正在停止", "正在恢复系统代理设置", .pending, warnings: warnings)
            case .failed, .stopped, .running:
                return result("代理模式异常", listenerError ?? "系统代理仍指向尚未就绪的本地代理", .failure,
                    warnings: warnings)
            }
        }
        var warnings: [String] = []
        if let systemProxyFailure { warnings.append("系统代理失败：\(systemProxyFailure)") }
        if let enhancedError { warnings.append("增强模式失败：\(enhancedError)") }
        if let listenerError { warnings.append("本地代理失败：\(listenerError)") }
        let detail = listener.isPresent && listener.phase == .running
            ? "未启用系统代理或增强模式；本地代理入口可供手动使用"
            : "未启用系统代理或增强模式；本机网络直连"
        return result(warnings.isEmpty ? "直连模式" : "直连模式 · 有异常", detail, .neutral, warnings: warnings)
    }
}

/// A capability supplied by an existing owner. Implementations neither create
/// a replacement router nor change the Helper's network responsibilities.
protocol AppRuntimeDiagnosticsOwner: AnyObject {
    func snapshot() -> AppRuntimeOwnerSnapshot
    func startDiagnostics(onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> RuntimeOperation
}

/// App composition boundary. State observation and presentation calls are
/// confined to main, matching the existing controller status delivery. The
/// Foundation coordinator and operation cancellation are independently safe
/// to use from backend callbacks; they never re-enter the manager queue.
final class AppNetworkRuntime {
    private struct Identity: Equatable {
        var configuration: NetworkDiagnosticsConfiguration
        var listenerRevision: UInt64
        var enhancedRevision: UInt64
        var enhancedStartedAt: Date?
    }

    private let listener: any AppRuntimeDiagnosticsOwner
    private let enhanced: any AppRuntimeDiagnosticsOwner
    private let coordinator: RuntimeCoordinator
    private var lastIdentity: Identity?
    private var configurationRevision: UInt64 = 0
    private var latestConfiguration: NetworkDiagnosticsConfiguration?
    private var listenerFailure: String?
    private var enhancedFailure: String?
    private var enhancedWaiting: String?
    private var systemProxyFailure: String?
    let listenerLifecycle: RuntimeLifecycle

    convenience init(engine: ProxyEngine, enhancedMode: EnhancedModeManager,
                     listenerLifecycle: RuntimeLifecycle = RuntimeLifecycle()) {
        self.init(listener: ListenerDiagnosticsOwner(engine: engine, lifecycle: listenerLifecycle),
            enhanced: EnhancedDiagnosticsOwner(manager: enhancedMode), listenerLifecycle: listenerLifecycle)
    }

    init(listener: any AppRuntimeDiagnosticsOwner, enhanced: any AppRuntimeDiagnosticsOwner,
         coordinator: RuntimeCoordinator = RuntimeCoordinator(),
         listenerLifecycle: RuntimeLifecycle = RuntimeLifecycle()) {
        self.listener = listener
        self.enhanced = enhanced
        self.coordinator = coordinator
        self.listenerLifecycle = listenerLifecycle
    }

    func observe(listenerStatus: ProxyEngineStatus) {
        if case .failed(let message) = listenerStatus { listenerFailure = message }
        else { listenerFailure = nil }
        (listener as? ListenerDiagnosticsOwner)?.observe(listenerStatus)
        refreshIfConfigured()
    }

    func observe(enhancedStatus: EnhancedModeManager.Status) {
        if case .failed(let message) = enhancedStatus { enhancedFailure = message }
        else { enhancedFailure = nil }
        if case .waitingForNetwork(let message) = enhancedStatus { enhancedWaiting = message }
        else { enhancedWaiting = nil }
        refreshIfConfigured()
    }

    func connectionPresentation(mode: OutboundMode, systemProxyEnabled: Bool,
                                systemProxyChanging: Bool = false,
                                enhancedRequestPending: Bool = false,
                                enhancedRequested: Bool = false) -> AppConnectionPresentation {
        AppConnectionPresentation.make(mode: mode, systemProxyEnabled: systemProxyEnabled,
            listener: listener.snapshot().endpoint, enhanced: enhanced.snapshot().endpoint,
            enhancedRequestPending: enhancedRequestPending,
            enhancedRequested: enhancedRequested, enhancedWaiting: enhancedWaiting,
            systemProxyChanging: systemProxyChanging, systemProxyFailure: systemProxyFailure,
            listenerFailure: listenerFailure, enhancedFailure: enhancedFailure)
    }

    func observe(systemProxyResult: Result<Void, Error>) {
        if case .failure(let error) = systemProxyResult { systemProxyFailure = error.localizedDescription }
        else { systemProxyFailure = nil }
    }

    /// Intent revocation must invalidate leases before a queued status event.
    func lifecycleDidChange() { refreshIfConfigured() }

    func context(configuration: NetworkDiagnosticsConfiguration) -> NetworkDiagnosticsRuntimeContext {
        let state = refresh(configuration: configuration)
        return NetworkDiagnosticsRuntimeContext(engineState: Self.stateLabel(state.runtime),
            engineRunning: state.runtime.ready, mode: configuration.mode,
            selectedPolicy: configuration.selectedPolicy, groupSelections: configuration.groupSelections,
            profileRevision: configuration.profileRevision, enhancedMode: state.enhanced.endpoint.isPresent,
            systemProxy: configuration.systemProxy, boundInterfaceName: state.runtime.boundInterfaceName,
            runtimeRevision: state.runtime.revision, runtimeBackend: state.runtime.backend,
            runtimeSessionID: state.runtime.sessionID)
    }

    @discardableResult
    func startDiagnostics(configuration: NetworkDiagnosticsConfiguration,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> RuntimeOperation {
        _ = refresh(configuration: configuration)
        let listener = listener, enhanced = enhanced
        return coordinator.start(onUpdate: onUpdate) { session, update in
            guard session.isReady else {
                return Self.unavailable(detail: session.backend == .enhanced
                    ? "增强模式尚未就绪或正在恢复网络；请等待后重新检测"
                    : "请先开启增强模式或启动代理引擎后再测试", onUpdate: update)
            }
            switch session.backend {
            case .enhanced: return enhanced.startDiagnostics(onUpdate: update)
            case .listener: return listener.startDiagnostics(onUpdate: update)
            case .unavailable: return Self.unavailable(onUpdate: update)
            }
        }
    }

    private func refreshIfConfigured() {
        if let latestConfiguration { _ = refresh(configuration: latestConfiguration) }
    }

    private func refresh(configuration: NetworkDiagnosticsConfiguration)
        -> (runtime: RuntimeSnapshot, enhanced: AppRuntimeOwnerSnapshot) {
        let listenerState = listener.snapshot(), enhancedState = enhanced.snapshot()
        let identity = Identity(configuration: configuration,
            listenerRevision: listenerState.lifecycleRevision,
            enhancedRevision: enhancedState.lifecycleRevision, enhancedStartedAt: enhancedState.startedAt)
        if lastIdentity != identity {
            configurationRevision &+= 1
            lastIdentity = identity
        }
        latestConfiguration = configuration
        return (coordinator.update(listener: listenerState.endpoint, enhanced: enhancedState.endpoint,
            configurationRevision: configurationRevision), enhancedState)
    }

    private static func stateLabel(_ snapshot: RuntimeSnapshot) -> String {
        let enhanced = snapshot.backend == .enhanced
        switch snapshot.phase {
        case .running: return "运行中"
        case .starting: return enhanced ? "增强模式正在启动" : "正在启动"
        case .stopping: return enhanced ? "增强模式正在停止" : "正在停止"
        case .failed: return enhanced ? "增强模式状态异常" : "启动失败"
        case .stopped: return enhanced ? "增强模式尚未就绪" : "已停止"
        }
    }

    static func request(
        start: (@escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> NetworkConnectivityDiagnosticsSession,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> RuntimeOperation {
        let operation = RuntimeOperation()
        let session = start { [weak operation] snapshot in
            guard operation?.isCancelled == false else { return }
            onUpdate(snapshot)
        }
        operation.installCancellation { session.cancel() }
        return operation
    }

    static func unavailable(detail: String = "请先开启增强模式或启动代理引擎后再测试",
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> RuntimeOperation {
        request(start: { callback in
            ProxyEngine.unavailableNetworkDiagnostics(detail: detail, callbackQueue: .main, onUpdate: callback)
        }, onUpdate: onUpdate)
    }
}

private final class ListenerDiagnosticsOwner: AppRuntimeDiagnosticsOwner {
    private let engine: ProxyEngine
    private let lifecycle: RuntimeLifecycle
    private var status: ProxyEngineStatus

    init(engine: ProxyEngine, lifecycle: RuntimeLifecycle) {
        self.engine = engine
        self.lifecycle = lifecycle
        status = engine.runtimeSnapshot().status
    }

    func observe(_ value: ProxyEngineStatus) {
        status = value
    }

    func snapshot() -> AppRuntimeOwnerSnapshot {
        let state = lifecycle.snapshot
        var phase = state.phase
        if phase == .running, status != .running {
            // Owner readiness follows successful start; the Core's own
            // status/capability must also agree before any diagnostic IO.
            switch status {
            case .stopped: phase = .stopped
            case .starting: phase = .starting
            case .failed: phase = .failed
            case .running: break
            }
        }
        return AppRuntimeOwnerSnapshot(endpoint: RuntimeEndpointState(phase: phase, isPresent: state.isPresent,
            boundInterfaceName: ProxyEngine.currentOutboundInterface?.name), lifecycleRevision: state.revision)
    }

    func startDiagnostics(onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> RuntimeOperation {
        AppNetworkRuntime.request(start: { callback in
            engine.startNetworkDiagnostics(callbackQueue: .main, onUpdate: callback)
        }, onUpdate: onUpdate)
    }
}

private final class EnhancedDiagnosticsOwner: AppRuntimeDiagnosticsOwner {
    private let manager: EnhancedModeManager

    init(manager: EnhancedModeManager) { self.manager = manager }

    func snapshot() -> AppRuntimeOwnerSnapshot {
        let lifecycle = manager.lifecycleSnapshot
        let state = manager.state
        let phase: RuntimePhase = lifecycle.isReady && state == nil ? .starting : lifecycle.phase
        return AppRuntimeOwnerSnapshot(endpoint: RuntimeEndpointState(phase: phase,
            isPresent: lifecycle.isPresent,
            boundInterfaceName: state?.physicalInterface
                ?? (lifecycle.isPresent ? ProxyEngine.currentOutboundInterface?.name : nil)),
            lifecycleRevision: lifecycle.revision, startedAt: state?.startedAt)
    }

    func startDiagnostics(onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> RuntimeOperation {
        manager.startNetworkDiagnostics(callbackQueue: .main, onUpdate: onUpdate)
    }
}

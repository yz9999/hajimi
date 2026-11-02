import AppKit
import HajimiCore
import HajimiRuntime
import HajimiDiagnosticsUI
import HajimiUIComponents

// Exact Main event, presentation and system-proxy methods are inserted by
// the runner. Only runtime owners, preferences and mutation boundaries are
// memory fixtures. No real controller, NSWindow, socket or Helper is created.
// @THEME@
// @MAIN_VALUES@

final class UserDefaults {
    static let standard = UserDefaults()
    private var values: [String: Any] = [:]
    func set(_ value: Any?, forKey key: String) { values[key] = value }
    func object(forKey key: String) -> Any? { values[key] }
    func bool(forKey key: String) -> Bool { values[key] as? Bool ?? false }
}

final class FixtureOwner: AppRuntimeDiagnosticsOwner {
    var value = AppRuntimeOwnerSnapshot(endpoint: .stopped, lifecycleRevision: 0)
    private(set) var starts = 0
    func snapshot() -> AppRuntimeOwnerSnapshot { value }
    func startDiagnostics(onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> RuntimeOperation {
        starts += 1
        return RuntimeOperation()
    }
}

final class FixtureListener {
    struct Snapshot { let status: ProxyEngineStatus }
    var status = ProxyEngineStatus.stopped
    var activeHTTPListen = ListenAddress(host: "127.0.0.1", port: 17890)
    var activeSOCKSListen = ListenAddress(host: "127.0.0.1", port: 17891)
    var onStatus: ((ProxyEngineStatus) -> Void)?
    var onEvent: ((ProxyEngineEvent) -> Void)?
    var onEventBatch: (([ProxyEngineEvent]) -> Void)?
    func runtimeSnapshot() -> Snapshot { Snapshot(status: status) }
}

final class EnhancedModeManager {
    enum Status: Equatable {
        case stopped, starting, running(interface: String, physicalInterface: String), stopping, failed(String), waitingForNetwork(String)
    }
    struct State { var physicalInterface: String; var startedAt: Date }
    var state: State?
    let lifecycle = RuntimeLifecycle()
    var lifecycleSnapshot: RuntimeLifecycle.Snapshot { lifecycle.snapshot }
    var isEnabled: Bool { state != nil }
    var isRequested = false
    var onStatus: ((Status) -> Void)?
    var onStatistics: ((Int, Int, UInt64, UInt64) -> Void)?
    func startNetworkDiagnostics(callbackQueue: DispatchQueue,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> RuntimeOperation {
        fatalError("This presentation fixture must never start real diagnostics")
    }
}

final class FixtureSystemProxy {
    var isEnabledByHajimi = false
    var enableCompletions: [(Result<Void, Error>) -> Void] = []
    var disableCompletions: [(Result<Void, Error>) -> Void] = []
    var rebindCompletions: [(Result<Void, Error>) -> Void] = []
    func enable(address: ListenAddress, bypassDomains: [String], completion: @escaping (Result<Void, Error>) -> Void) {
        enableCompletions.append(completion)
    }
    func disable(completion: @escaping (Result<Void, Error>) -> Void) { disableCompletions.append(completion) }
    func repoint(from: ListenAddress, to: ListenAddress, completion: @escaping (Result<Void, Error>) -> Void) {
        rebindCompletions.append(completion)
    }
    func completeEnable() { isEnabledByHajimi = true; enableCompletions.removeFirst()(.success(())) }
    func completeDisable() { isEnabledByHajimi = false; disableCompletions.removeFirst()(.success(())) }
    func failDisable(_ error: Error) { disableCompletions.removeFirst()(.failure(error)) }
    func failRebind(_ error: Error) { rebindCompletions.removeFirst()(.failure(error)) }
}

final class FixtureAdapters {
    var onUnexpectedExit: ((String) -> Void)?
    func stop() {}
}
final class FixtureRoutingGate { func reset() {} }
final class FixtureRate { func observe(_ value: UInt64, at: TimeInterval) {} }

private final class OverviewConnectionStatusFixture: NSObject {
    private let listenerOwner = FixtureOwner(), enhancedOwner = FixtureOwner()
    private lazy var networkRuntime = AppNetworkRuntime(listener: listenerOwner, enhanced: enhancedOwner)
    private let engine = FixtureListener()
    private let enhancedMode = EnhancedModeManager()
    private let protocolAdapters = FixtureAdapters()
    private let systemProxy = FixtureSystemProxy()
    private let listenerLifecycle = RuntimeLifecycle()
    private var listenerTicket: RuntimeLifecycle.Ticket?
    private let enhancedRequestIntent = RuntimeLifecycle()
    private let routingReloadGate = FixtureRoutingGate()
    private let enhancedUploadRate = FixtureRate(), enhancedDownloadRate = FixtureRate()
    private var engineStatus = ProxyEngineStatus.stopped
    private var profile = Profile()
    private var activeConnectionIDs = Set<UUID>()
    private var enhancedActiveConnections = 0, enhancedTotalConnections = 0
    private var enhancedUploaded: UInt64 = 0, enhancedDownloaded: UInt64 = 0
    private let modePopup = NSPopUpButton()
    private let policyPopup = NSPopUpButton()
    private let statusLabel = NSTextField(labelWithString: "已停止")
    private let sidebarStatusText = NSTextField(labelWithString: "已停止")
    private let sidebarStatusDetail = NSTextField(labelWithString: "")
    private let sidebarStatusDot = HajimiSurfaceView(fill: .tertiaryLabelColor, cornerRadius: 4)
    private let startButton = NSButton()
    private let enhancedModeButton = NSButton(checkboxWithTitle: "增强模式", target: nil, action: nil)
    private let systemProxyButton = NSButton(checkboxWithTitle: "设置为系统代理", target: nil, action: nil)
    private let dataPlaneRuntimeValue = NSTextField(labelWithString: "")
    private let httpRuntimeValue = NSTextField(labelWithString: "")
    private let socksRuntimeValue = NSTextField(labelWithString: "")
    private let routingRuntimeValue = NSTextField(labelWithString: "")
    private var pendingSystemProxyRestore = false, systemProxyRebindInFlight = false
    private var systemProxyRecoveryInFlight = false, systemProxyEnableRequests = 0
    private var systemProxyDisableRequests = 0
    private var systemProxyAppliedAddress: ListenAddress?
    private var systemProxyIsOrWillBeEnabled: Bool { systemProxy.isEnabledByHajimi || pendingSystemProxyRestore }
    private var selectedPolicy: String { policyPopup.titleOfSelectedItem ?? "DIRECT" }
    private var isSystemProxyActive: Bool { systemProxy.isEnabledByHajimi }
    private var messages: [String] = []
    private var modeUpdates = 0, localSettingUpdates = 0, backgroundRefreshes = 0

    override init() {
        super.init()
        modePopup.addItems(withTitles: OutboundMode.allCases.map(\.displayName))
        policyPopup.addItem(withTitle: "sample-node")
        bindEngine()
        refreshConnectionStatus()
    }
    private func persistSystemProxy(_ enabled: Bool) { UserDefaults.standard.set(enabled, forKey: "systemProxyEnabled") }
    private func persistEnhancedMode(_ enabled: Bool) { UserDefaults.standard.set(enabled, forKey: "enhancedModeEnabled") }
    private func updateEngineRouting() { modeUpdates += 1 }
    private func refreshActiveProxyCards() {}
    private func refreshRuleSetsAutomatically() { backgroundRefreshes += 1 }
    private func refreshLocalProxySettings() { localSettingUpdates += 1 }
    private func scheduleStatisticsUpdate() {}
    private func apply(event: ProxyEngineEvent) {}
    private func stopProxyEngine() {}
    private func showMessage(title: String, text: String) { messages.append(title + text) }
    private func showError(title: String, error: Error) { messages.append(title + error.localizedDescription) }

    // @PRODUCTION_METHODS@

    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "主页连接状态自检失败：\(text)" }
    }

    private func deliverEnhanced(_ status: EnhancedModeManager.Status,
                                 phase: RuntimePhase, present: Bool, cachedState: Bool = false) {
        enhancedOwner.value.endpoint = RuntimeEndpointState(phase: phase, isPresent: present)
        enhancedOwner.value.lifecycleRevision &+= 1
        enhancedMode.state = cachedState
            ? EnhancedModeManager.State(physicalInterface: "en-fixture", startedAt: Date(timeIntervalSince1970: 1)) : nil
        enhancedMode.onStatus?(status)
    }

    private func deliverListener(_ status: ProxyEngineStatus, ready: Bool = false) {
        if status == .starting || status == .running {
            if listenerTicket == nil {
                listenerTicket = listenerLifecycle.reserve()
                if let listenerTicket { _ = listenerLifecycle.markOwned(listenerTicket) }
            }
            if ready, let listenerTicket { _ = listenerLifecycle.markRunning(listenerTicket) }
        } else if status == .stopped {
            if let ticket = listenerLifecycle.cancel() { listenerLifecycle.confirmStopped(ticket) }
            listenerTicket = nil
        }
        engine.status = status
        let lifecycle = listenerLifecycle.snapshot
        listenerOwner.value.endpoint = RuntimeEndpointState(phase: lifecycle.phase, isPresent: lifecycle.isPresent)
        if case .failed = status { listenerOwner.value.endpoint = RuntimeEndpointState(phase: .failed, isPresent: false) }
        listenerOwner.value.lifecycleRevision &+= 1
        engine.onStatus?(status)
        RunLoop.current.run(until: Date().addingTimeInterval(0.02))
    }

    static func run() throws {
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw Failure(text: text) }
        }
        func unified(_ fixture: OverviewConnectionStatusFixture, _ text: String) throws {
            let value = fixture.connectionPresentation
            try require(fixture.statusLabel.stringValue == "● \(value.title)"
                && fixture.sidebarStatusText.stringValue == value.title
                && fixture.sidebarStatusDetail.stringValue == value.detail
                && fixture.statusItemSummary == "\(value.title) · \(value.detail)", text)
        }
        let fixture = OverviewConnectionStatusFixture()
        try require(fixture.statusLabel.stringValue == "● 直连模式", "初始直连被显示为停止")
        for mode in OutboundMode.allCases {
            fixture.modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: mode)!)
            fixture.modeChanged()
            try require(fixture.statusLabel.stringValue == "● 直连模式", "仅选出站模式即误报系统已接管")
            try unified(fixture, "初始模式更新未同步主页/侧栏/菜单")
        }
        fixture.modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: .proxy)!)
        fixture.modeChanged()
        fixture.deliverEnhanced(.starting, phase: .starting, present: false)
        try require(fixture.statusLabel.stringValue == "● 增强模式正在启动"
            && fixture.connectionPresentation.tone == .pending, "真实增强starting回调未刷新状态")
        try unified(fixture, "增强starting三处状态不一致")
        fixture.deliverEnhanced(.running(interface: "utun-fixture", physicalInterface: "en-fixture"),
            phase: .running, present: true, cachedState: true)
        try require(fixture.statusLabel.stringValue == "● 增强模式 · 全局代理"
            && fixture.dataPlaneRuntimeValue.stringValue == "Native · utun-fixture"
            && fixture.backgroundRefreshes == 1, "仅增强真实running回调仍显示停止或丢失后台刷新")
        try unified(fixture, "增强running三处状态不一致")
        for mode in OutboundMode.allCases {
            fixture.modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: mode)!)
            fixture.modeChanged()
            let route = mode == .direct ? "直连" : mode.displayName
            try require(fixture.statusLabel.stringValue == "● 增强模式 · \(route)", "增强实际modeChanged未重算路由文案")
            try unified(fixture, "增强出站模式变更三处状态不一致")
        }
        fixture.deliverListener(.stopped)
        try require(fixture.statusLabel.stringValue.hasPrefix("● 增强模式 ·"), "监听器stopped覆盖ready增强")
        fixture.deliverListener(.starting)
        try require(fixture.statusLabel.stringValue.hasPrefix("● 增强模式 ·"), "可选入口准备覆盖ready增强")
        fixture.deliverListener(.failed("controlled listener failure"))
        try require(fixture.statusLabel.stringValue.hasPrefix("● 增强模式 ·")
            && fixture.connectionPresentation.tone == .warning
            && fixture.statusLabel.toolTip!.contains("controlled listener failure"), "入口失败伪报增强停止或丢失错误")
        try unified(fixture, "入口失败后主页/侧栏/菜单不一致")
        fixture.deliverEnhanced(.stopping, phase: .stopping, present: true, cachedState: true)
        try require(fixture.statusLabel.stringValue == "● 增强模式正在停止"
            && fixture.connectionPresentation.tone == .pending, "cachedState尚在时停止被误报就绪")
        fixture.deliverEnhanced(.failed("cleanup pending"), phase: .failed, present: true, cachedState: true)
        try require(fixture.statusLabel.stringValue == "● 增强模式异常"
            && fixture.connectionPresentation.tone == .failure
            && fixture.statusLabel.toolTip!.contains("cleanup pending"), "失败清理被误报直连/ready")
        fixture.deliverEnhanced(.stopped, phase: .stopped, present: false)
        fixture.deliverListener(.stopped)
        try require(fixture.statusLabel.stringValue == "● 直连模式 · 有异常"
            && fixture.connectionPresentation.tone == .warning
            && fixture.sidebarStatusDetail.stringValue.contains("本地代理"), "增强停止后隐藏了尚未恢复的本地代理失败")
        try unified(fixture, "全关后三处状态不一致")
        fixture.deliverListener(.starting)
        fixture.deliverListener(.running, ready: true)
        fixture.deliverListener(.stopped)
        try require(fixture.statusLabel.stringValue == "● 直连模式"
            && fixture.connectionPresentation.tone == .neutral, "真实入口成功重试并停止后未清除失败")

        let pending = fixture.enhancedRequestIntent.reserve()!
        fixture.refreshConnectionStatus()
        try require(fixture.statusLabel.stringValue == "● 增强模式正在启动", "增强规则准备reservation不显示正在启动")
        fixture.enhancedRequestIntent.release(pending)
        fixture.refreshConnectionStatus()
        try require(fixture.statusLabel.stringValue == "● 直连模式", "准备取消后未回归实际模式")
        fixture.deliverListener(.starting)
        try require(fixture.statusLabel.stringValue == "● 直连模式", "仅本地入口starting被当成系统代理接管")
        fixture.deliverListener(.running, ready: true)
        try require(fixture.statusLabel.stringValue == "● 直连模式"
            && fixture.sidebarStatusDetail.stringValue.contains("手动使用"), "仅本地入口running被当成系统代理接管")
        fixture.systemProxyButton.state = .on
        fixture.toggleSystemProxy()
        try require(fixture.systemProxy.enableCompletions.count == 1
            && fixture.statusLabel.stringValue == "● 代理模式切换中", "系统代理授权结果尚未返回即误报接管")
        // The production manager writes its recovery snapshot before running
        // privileged commands. A menu read during that interval must stay pending.
        fixture.systemProxy.isEnabledByHajimi = true
        try require(fixture.connectionPresentation.tone == .pending
            && fixture.statusItemSummary.hasPrefix("代理模式切换中"), "提前写入snapshot使菜单误报代理已经接管")
        fixture.systemProxy.completeEnable()
        try require(fixture.statusLabel.stringValue.hasPrefix("● 代理模式 ·"), "真实系统代理enable成功回调未刷新")
        for mode in OutboundMode.allCases {
            fixture.modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: mode)!)
            fixture.modeChanged()
            try require(fixture.statusLabel.stringValue == "● 代理模式 · \(mode == .direct ? "直连" : mode.displayName)",
                "系统代理实际modeChanged未反映出站")
            try unified(fixture, "系统代理modeChanged三处不一致")
        }
        fixture.systemProxyButton.state = .off
        fixture.toggleSystemProxy()
        try require(fixture.statusLabel.stringValue == "● 代理模式切换中", "恢复尚未完成即误报完成接管/直连")
        fixture.systemProxy.failDisable(Failure(text: "partial disable failure"))
        try require(fixture.statusLabel.stringValue == "● 代理模式异常"
            && fixture.statusLabel.toolTip!.contains("partial disable failure"), "普通disable部分失败仍误报代理正常")
        fixture.systemProxyButton.state = .off
        fixture.toggleSystemProxy()
        fixture.systemProxy.completeDisable()
        try require(fixture.statusLabel.stringValue == "● 直连模式", "真实系统代理disable回调未刷新")
        fixture.systemProxy.isEnabledByHajimi = true
        fixture.deliverListener(.failed("controlled listener reset"))
        try require(fixture.statusLabel.stringValue == "● 代理模式切换中", "残留系统代理恢复途中被误报已完成")
        fixture.systemProxy.failDisable(Failure(text: "failed recovery"))
        try require(fixture.statusLabel.stringValue == "● 代理模式异常"
            && fixture.connectionPresentation.tone == .failure, "残留系统代理恢复失败后被误报直连/接管")
        fixture.systemProxyButton.state = .off
        fixture.toggleSystemProxy()
        fixture.systemProxy.completeDisable()
        try require(fixture.statusLabel.stringValue == "● 直连模式 · 有异常"
            && fixture.statusLabel.toolTip!.contains("controlled listener reset"), "恢复回调未反映直连或隐藏原错误")
        try unified(fixture, "系统代理失败恢复后三处不一致")
        try require(fixture.listenerOwner.starts == 0 && fixture.enhancedOwner.starts == 0,
            "主页事件测试启动了诊断 IO")
        try require(fixture.modeUpdates >= 10 && fixture.localSettingUpdates >= 7,
            "实际模式路由入口或本地入口设置刷新丢失")

        let coexist = OverviewConnectionStatusFixture()
        coexist.deliverListener(.running, ready: true)
        coexist.systemProxyButton.state = .on
        coexist.toggleSystemProxy()
        coexist.systemProxy.completeEnable()
        coexist.deliverEnhanced(.running(interface: "utun-coexist", physicalInterface: "en-fixture"),
            phase: .running, present: true, cachedState: true)
        coexist.systemProxyButton.state = .off
        coexist.toggleSystemProxy()
        try require(coexist.statusLabel.stringValue.hasPrefix("● 增强模式 ·")
            && coexist.connectionPresentation.tone == .active, "系统代理disable途中覆盖仍就绪的增强模式")
        coexist.systemProxy.failDisable(Failure(text: "coexisting system proxy failure"))
        try require(coexist.statusLabel.stringValue.hasPrefix("● 增强模式 ·")
            && coexist.connectionPresentation.tone == .warning
            && coexist.statusLabel.toolTip!.contains("coexisting system proxy failure"), "系统代理失败遮掉正常增强或错误不可见")
        try unified(coexist, "增强与系统代理失败共存时三处状态不一致")
        coexist.systemProxyButton.state = .off
        coexist.toggleSystemProxy()
        coexist.systemProxy.completeDisable()
        try require(coexist.connectionPresentation.tone == .active, "确认恢复后没有清除系统代理错误")

        let rebind = OverviewConnectionStatusFixture()
        rebind.deliverListener(.running, ready: true)
        rebind.systemProxyButton.state = .on
        rebind.toggleSystemProxy()
        rebind.systemProxy.completeEnable()
        rebind.engine.activeHTTPListen = ListenAddress(host: "127.0.0.1", port: 17892)
        rebind.deliverListener(.running, ready: true)
        try require(rebind.systemProxy.rebindCompletions.count == 1
            && rebind.connectionPresentation.tone == .pending, "端口重绑开始即误报已接管")
        rebind.systemProxy.failRebind(Failure(text: "controlled rebind failure"))
        try require(rebind.systemProxy.disableCompletions.count == 1
            && rebind.statusLabel.stringValue == "● 代理模式切换中", "重绑失败后恢复途中误报完成")
        rebind.systemProxy.failDisable(Failure(text: "controlled rebind recovery failure"))
        try require(rebind.statusLabel.stringValue == "● 代理模式异常"
            && rebind.connectionPresentation.tone == .failure
            && rebind.statusLabel.toolTip!.contains("controlled rebind recovery failure"),
            "listener仍ready且snapshot存在时把重绑恢复失败误报已接管")
        try unified(rebind, "重绑恢复失败后三处状态不一致")
        let recovering = OverviewConnectionStatusFixture()
        UserDefaults.standard.set(true, forKey: "enhancedModeEnabled")
        recovering.enhancedMode.isRequested = true
        recovering.deliverEnhanced(.waitingForNetwork("Wi-Fi 尚未取得网关"), phase: .stopped, present: false)
        try require(recovering.enhancedModeButton.state == .on && recovering.enhancedModeButton.isEnabled
            && recovering.connectionPresentation.title == "增强模式等待网络恢复"
            && recovering.connectionPresentation.tone == .pending
            && UserDefaults.standard.bool(forKey: "enhancedModeEnabled"),
                    "无隧道的等待状态清除了开启意图或伪报已就绪")
        try unified(recovering, "等待网络时主页/侧栏/菜单不一致")
        recovering.deliverEnhanced(.failed("route restoration confirmed"), phase: .stopped, present: false)
        try require(recovering.enhancedModeButton.state == .on
            && UserDefaults.standard.bool(forKey: "enhancedModeEnabled")
            && recovering.connectionPresentation.title == "增强模式等待恢复", "自动恢复期间失败清除了意图或伪报直连")
        recovering.deliverEnhanced(.running(interface: "utun-new", physicalInterface: "en-fixture"),
            phase: .running, present: true, cachedState: true)
        try require(recovering.connectionPresentation.tone == .active
            && recovering.enhancedModeButton.state == .on, "新的真实运行结果没有清除等待状态")
        recovering.enhancedMode.isRequested = false
        recovering.deliverEnhanced(.stopped, phase: .stopped, present: false)
        recovering.deliverEnhanced(.waitingForNetwork("late waiting"), phase: .stopped, present: false)
        try require(recovering.enhancedModeButton.state == .off
            && recovering.connectionPresentation.title == "直连模式", "迟到等待通知复活手动关闭或残留等待")
        print("Overview actual Main events passed: \(assertions) assertions; enhanced-only start/run/stop/failure, listener independence, mode changes, system proxy completion, sidebar/menu consistency; no windows, network owners or preferences")
    }
}

@main
private enum OverviewConnectionStatusMain {
    static func main() throws {
        _ = NSApplication.shared
        try AppNetworkRuntimeSelfTest.run()
        try OverviewConnectionStatusFixture.run()
    }
}

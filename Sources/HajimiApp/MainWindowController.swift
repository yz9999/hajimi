import AppKit
import Network
import UniformTypeIdentifiers
import HajimiCore
import HajimiDiagnosticsUI
import HajimiRuntime
import HajimiMacOSObjC
import HajimiUIComponents

struct StatusPolicyGroupSelection {
    let name: String
    let kind: PolicyGroupKind
    let members: [String]
    let selectedMember: String?
    let effectiveMember: String?

    var kindBadgeText: String {
        switch kind {
        case .select: return "手动"
        case .urlTest: return "测速"
        case .fallback: return "故障转移"
        case .loadBalance: return "负载均衡"
        case .smart: return "Smart"
        case .subnet: return "子网"
        }
    }
}

struct StatusProxyNodeItem {
    let name: String
    let protocolTag: String
    let latency: NodeLatency
    let latencyMillis: Int?
    let isOptimal: Bool
}

struct StatusBarTelemetrySnapshot {
    let running: Bool
    let enhancedMode: Bool
    let systemProxy: Bool
    let modeTitle: String
    let activeNodeName: String
    let activeNodeLatencyMillis: Int
    let uploadBytesPerSecond: Double
    let downloadBytesPerSecond: Double
    let totalUploadedBytes: UInt64
    let totalDownloadedBytes: UInt64
    let activeConnections: Int
}

private enum HajimiTheme {
    static let workspace = HajimiAppearance.workspace
    static let sidebar = HajimiAppearance.sidebar
    static let panel = HajimiAppearance.panel
    static let elevatedPanel = HajimiAppearance.elevatedPanel
    static let mutedPanel = HajimiAppearance.mutedPanel
    static let border = HajimiAppearance.border
    static let subtleDivider = HajimiAppearance.subtleDivider
    static let selection = HajimiAppearance.selection
    static let accent = HajimiAppearance.accent
    static let accentText = HajimiAppearance.accentText

    static func eyebrowPill(_ text: String) -> NSView {
        let pill = HajimiSurfaceView(
            fill: HajimiAppearance.selection,
            border: HajimiAppearance.accent.withAlphaComponent(0.24),
            cornerRadius: 6
        )
        pill.translatesAutoresizingMaskIntoConstraints = false
        let dot = HajimiSurfaceView(fill: HajimiAppearance.accent, cornerRadius: 2.5)
        dot.translatesAutoresizingMaskIntoConstraints = false
        let label = NSTextField(labelWithString: text)
        label.font = .systemFont(ofSize: 9.5, weight: .bold)
        label.textColor = HajimiAppearance.accentText
        label.translatesAutoresizingMaskIntoConstraints = false
        pill.addSubview(dot)
        pill.addSubview(label)
        NSLayoutConstraint.activate([
            dot.leadingAnchor.constraint(equalTo: pill.leadingAnchor, constant: 7),
            dot.centerYAnchor.constraint(equalTo: pill.centerYAnchor),
            dot.widthAnchor.constraint(equalToConstant: 5),
            dot.heightAnchor.constraint(equalToConstant: 5),
            label.leadingAnchor.constraint(equalTo: dot.trailingAnchor, constant: 5),
            label.trailingAnchor.constraint(equalTo: pill.trailingAnchor, constant: -8),
            label.topAnchor.constraint(equalTo: pill.topAnchor, constant: 2.5),
            label.bottomAnchor.constraint(equalTo: pill.bottomAnchor, constant: -2.5)
        ])
        return pill
    }

    static func iconTile(symbol: String, color: NSColor, size: CGFloat = 38, symbolSize: CGFloat = 17) -> HajimiSurfaceView {
        let badge = HajimiSurfaceView(
            fill: color.withAlphaComponent(0.13),
            border: color.withAlphaComponent(0.25),
            cornerRadius: min(12, round(size * 0.29))
        )
        badge.translatesAutoresizingMaskIntoConstraints = false
        let icon = NSImageView()
        icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: symbolSize, weight: .semibold)
        icon.contentTintColor = color
        icon.translatesAutoresizingMaskIntoConstraints = false
        badge.addSubview(icon)
        NSLayoutConstraint.activate([
            badge.widthAnchor.constraint(equalToConstant: size),
            badge.heightAnchor.constraint(equalToConstant: size),
            icon.centerXAnchor.constraint(equalTo: badge.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: badge.centerYAnchor)
        ])
        return badge
    }
}

/// What a new process should bring back after quit. Quit still tears the
/// helper tunnel down so leftover routes cannot black-hole the machine; this
/// is only the remembered intent.
struct SessionRestoreIntent: Equatable {
    var startEngine: Bool
    var startEnhancedMode: Bool
    var enableSystemProxy: Bool

    static func load(from defaults: UserDefaults = .standard) -> SessionRestoreIntent {
        SessionRestoreIntent(
            startEngine: (defaults.object(forKey: "proxyEngineEnabled") as? Bool) ?? true,
            startEnhancedMode: defaults.bool(forKey: "enhancedModeEnabled"),
            enableSystemProxy: defaults.bool(forKey: "systemProxyEnabled"))
    }
}

/// A missing or invalid saved profile may be displayed for repair, but it must
/// never become an implicit DIRECT configuration for restored traffic.
enum LaunchProfilePlan {
    case ready(Profile)
    case invalid(String)

    init(source: Result<String, Error>) {
        do {
            self = .ready(try ProfileParser.parse(source.get()))
        } catch {
            self = .invalid((error as? ProfileParseError)?.description ?? error.localizedDescription)
        }
    }

    var profile: Profile? {
        if case .ready(let profile) = self { return profile }
        return nil
    }

    var errorDescription: String? {
        if case .invalid(let message) = self { return message }
        return nil
    }

    func safeRestoreIntent(_ requested: SessionRestoreIntent) -> SessionRestoreIntent {
        guard case .ready = self else {
            return SessionRestoreIntent(startEngine: false, startEnhancedMode: false,
                                        enableSystemProxy: false)
        }
        return requested
    }
}

/// Keep an enabled system proxy pointed at the HTTP listener it actually uses
/// while an engine restart is in progress. A port allocator may otherwise
/// choose a different port after another process releases the configured one.
struct SystemProxyListenerPlan {
    static func preferred(configured: ListenAddress, active: ListenAddress,
                          engineRunning: Bool, systemProxyEnabled: Bool) -> ListenAddress {
        engineRunning && systemProxyEnabled ? active : configured
    }

    static func needsRebind(applied: ListenAddress?, active: ListenAddress) -> Bool {
        applied.map { $0 != active } ?? false
    }

    static func protectsConfiguration(snapshotExists: Bool, enableRequests: Int) -> Bool {
        snapshotExists || enableRequests > 0
    }

    static func needsStaleSnapshotCleanup(snapshotExists: Bool,
                                          requested: SessionRestoreIntent) -> Bool {
        snapshotExists && !requested.enableSystemProxy
    }
}

final class MainWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate,
                                  NSCollectionViewDataSource, NSCollectionViewDelegateFlowLayout, NSMenuDelegate {
    private let engine = ProxyEngine()
    private let configurationStore: ConfigurationStore
    private let systemProxy: SystemProxyManager
    private let enhancedMode: EnhancedModeManager
    private let protocolAdapters: ProtocolAdapterManager
    private let surgeRuleSets: SurgeRuleSetManager
    private let subscriptions: SubscriptionManager
    private let helperClient = PrivilegedHelperClient()

    private var profile: Profile
    private var launchProfilePlan: LaunchProfilePlan
    private var engineStatus: ProxyEngineStatus = .stopped
    private let listenerLifecycle = RuntimeLifecycle()
    private var listenerTicket: RuntimeLifecycle.Ticket?
    private let enhancedRequestIntent = RuntimeLifecycle()
    private let launchRestoreIntent = RuntimeLifecycle()
    private var launchRestoreTicket: RuntimeLifecycle.Ticket?
    private lazy var networkRuntime = AppNetworkRuntime(engine: engine, enhancedMode: enhancedMode,
        listenerLifecycle: listenerLifecycle)
    private var activeConnectionIDs = Set<UUID>()
    private var totalConnections = 0
    private var uploaded = 0
    private var downloaded = 0
    private var enhancedActiveConnections = 0
    private var enhancedTotalConnections = 0
    private var enhancedUploaded: UInt64 = 0
    private var enhancedDownloaded: UInt64 = 0

    /// One meter per source. The in-process engine reports on every flush and
    /// the helper once every few seconds, so a single meter over the summed
    /// counters would turn the helper's contribution into a spike every poll —
    /// and would read one source restarting as the other losing traffic.
    private var engineUploadRate = TrafficRateMeter(aggregationWindow: 0.5)
    private var engineDownloadRate = TrafficRateMeter(aggregationWindow: 0.5)
    private var enhancedUploadRate = TrafficRateMeter(aggregationWindow: 0.5)
    private var enhancedDownloadRate = TrafficRateMeter(aggregationWindow: 0.5)
    private var statisticsUpdateScheduled = false

    private let sidebar = HajimiSurfaceView(fill: HajimiAppearance.sidebar, cornerRadius: 0)
    private let contentContainer = NSView()
    private let dashboardView = NSView()
    private let nativeTrafficView = HJTrafficDashboardView(frame: .zero)
    private let networkExtensionController = HJNetworkExtensionController()
    private let policiesView = NSView()
    private let rulesView = NSView()
    private let profileView = NSView()
    private let aboutView = NSView()
    private let settingsView = NSView()
    private let settingsOverviewView = NSView()
    private let dnsSettingsView = NSView()

    private let statusLabel = NSTextField(labelWithString: "已停止")
    private let startButton = NSButton(title: "开启 HTTP / SOCKS5 代理", target: nil, action: nil)
    private let systemProxyButton = NSButton(checkboxWithTitle: "设置为系统代理", target: nil, action: nil)
    private let enhancedModeButton = NSButton(checkboxWithTitle: "增强模式", target: nil, action: nil)
    private let modePopup = NSPopUpButton()
    private let policyPopup = NSPopUpButton()
    private let groupPopup = NSPopUpButton()
    private let groupMemberPopup = NSPopUpButton()
    private let activeValue = NSTextField(labelWithString: "0")
    private let totalValue = NSTextField(labelWithString: "0")
    private let uploadValue = NSTextField(labelWithString: "0 B")
    private let downloadValue = NSTextField(labelWithString: "0 B")
    private let httpRuntimeValue = NSTextField(labelWithString: "")
    private let socksRuntimeValue = NSTextField(labelWithString: "")
    private let routingRuntimeValue = NSTextField(labelWithString: "")
    private let dataPlaneRuntimeValue = NSTextField(labelWithString: "HajimiNativeCore")
    private let proxyTableView = NSTableView()
    private let groupTableView = NSTableView()
    private let policyCollectionView = ContextCollectionView()
    private let rulesTableView = NSTableView()
    private let proxySearchField = NSSearchField()
    private let ruleSearchField = NSSearchField()
    private let proxyCountLabel = NSTextField(labelWithString: "")
    private let ruleCountLabel = NSTextField(labelWithString: "")
    private let ruleSelectionCountLabel = NSTextField(labelWithString: "未选择")
    private let ruleStatusLabel = NSTextField(wrappingLabelWithString: "")
    private let ruleAddButton = NSButton(title: "新增规则", target: nil, action: nil)
    private let ruleEditButton = NSButton(title: "编辑规则", target: nil, action: nil)
    private let ruleDeleteButton = NSButton(title: "删除规则", target: nil, action: nil)
    private let ruleUpdateButton = NSButton(title: "更新规则", target: nil, action: nil)
    private let ruleMultiSelectButton = NSButton(checkboxWithTitle: "多选", target: nil, action: nil)
    private let ruleSelectAllButton = NSButton(title: "全选", target: nil, action: nil)
    private let ruleClearSelectionButton = NSButton(title: "取消选择", target: nil, action: nil)
    private let policyStatusLabel = NSTextField(labelWithString: "")
    private let profileTextView = NSTextView()
    private let profileStatus = NSTextField(labelWithString: "")
    private let profilePathLabel = NSTextField(labelWithString: "")
    private let helperStatusLabel = NSTextField(labelWithString: "正在检查…")
    private let helperInstallButton = NSButton(title: "安装 Helper", target: nil, action: nil)
    private let helperUninstallButton = NSButton(title: "卸载 Helper", target: nil, action: nil)
    private let localProxyStatusLabel = NSTextField(wrappingLabelWithString: "")
    private let sidebarStatusDot = HajimiSurfaceView(fill: .tertiaryLabelColor, cornerRadius: 4)
    private let sidebarStatusText = NSTextField(labelWithString: "已停止")
    private let sidebarStatusDetail = NSTextField(labelWithString: "本机代理引擎")
    private let subscriptionSummaryLabel = NSTextField(wrappingLabelWithString: "尚未添加订阅 · 支持导入本地配置或通过 URL 下载订阅")
    private let subscriptionSelectPopup = NSPopUpButton()
    private let subscriptionUseButton = NSButton(title: "选择使用", target: nil, action: nil)
    private let subscriptionAddButton = NSButton(title: "URL 下载…", target: nil, action: nil)
    private let subscriptionImportButton = NSButton(title: "导入配置…", target: nil, action: nil)
    private let subscriptionEditButton = NSButton(title: "编辑订阅…", target: nil, action: nil)
    private let subscriptionUpdateButton = NSButton(title: "更新订阅", target: nil, action: nil)
    private let subscriptionDeleteButton = NSButton(title: "删除订阅", target: nil, action: nil)
    private let dnsSummaryLabel = NSTextField(labelWithString: "防泄漏保护 · 默认加密 DNS")
    private let dnsForm = DNSSettingsFormView()
    private let dnsSettingsStatus = NSTextField(labelWithString: "")
    private var dnsSaveRequestID: UUID?
    private var dnsConnectivityRequestID: UUID?
    private var dnsConnectivityResolver: TraditionalDNSBootstrapResolver?
    private var navigationButtons: [NSButton] = []
    private var groupSelections: [String: String] = [:]
    private var manualManagedGroupSelections = Set<String>()
    /// Confined to the main queue. An unrelated health-group result must not
    /// reach either router update, which would invalidate DNS and mux owners.
    private let routingReloadGate = RoutingReloadGate()
    /// Drives `url-test` and `fallback` groups. Its results are written into
    /// `groupSelections`, which routing already consults ahead of a group's
    /// declared order, so no routing code has to know health checking exists.
    private let policyHealth = PolicyHealthMonitor()
    private var policyLatencies: [String: [String: TimeInterval]] = [:]
    private var profileValidationGeneration = 0
    private var filteredProxyNames: [String] = []
    private var filteredRules: [RoutingRule] = []
    private var filteredRuleRows: [RuleListRow] = []
    private var filteredRuleSourceLines: [Int] = []
    private var rulesPageSourceText: String?
    private var rulesPageRevision: Int?
    private var rulesPageProfile: Profile?
    private var rulesPageRuleSetLocations = Set<String>()
    private var pendingRuleSelection: (text: String, revision: Int, lines: Set<Int>)?
    private let proxySearchDebouncer = ListSearchDebouncer()
    private let ruleSearchDebouncer = ListSearchDebouncer()
    private var proxySearchIndex: ListSearchIndex<String>?
    private var proxySearchIndexRevision: Int?
    private let ruleListPreparation = RuleListPreparation()
    private let proxySearchQueue: OperationQueue = {
        let queue = OperationQueue()
        queue.name = "app.hajimi.policy-search"
        queue.qualityOfService = .userInitiated
        queue.maxConcurrentOperationCount = 1
        return queue
    }()
    private let ruleListQueue: OperationQueue = {
        let queue = OperationQueue()
        queue.name = "app.hajimi.rule-list-preparation"
        queue.qualityOfService = .userInitiated
        queue.maxConcurrentOperationCount = 1
        return queue
    }()
    private var ruleSelectionRefreshInProgress = false
    private var ruleOperationID: UUID?
    private var ruleEditor: RuleEditorSheetController?
    private var rulePolicyEditor: RulePolicySheetController?
    private var resolvedProfile: Profile?
    private var nodeLatencies: [String: NodeLatency] = [:]
    private var nodeProbeEpoch: UInt64 = 0
    private var nodeProbeRequests: [String: UUID] = [:]
    private var nodeProbeTickets: [String: ProbeScheduler.Ticket] = [:]
    private var nodeProbeBatch: NodeProbeBatchCursor?
    private var renderedProxyOrder: [String]?
    private var renderedGroupOrder: [String]?
    private var renderedProxyPolicies: [String: ProxyPolicy] = [:]
    private var renderedGroupPolicies: [String: PolicyGroup] = [:]
    private var renderedGroupSelections: [String: String] = [:]
    private var renderedActiveProxy: String?
    private var pendingProxyCards = Set<String>()
    private var proxyCardIdentities = Set<String>()
    private var pendingGroupCards = Set<String>()
    private var policyCardRefreshWork: DispatchWorkItem?
    private var policyHealthEpoch: UInt64 = 0
    private var diagnosticsPanel: NetworkDiagnosticsPanelController?
    private var policyVisibilityObserver: NSObjectProtocol?
    private var workspaceWakeObservers: [NSObjectProtocol] = []
    private var wakeRecoveryWorkItems: [DispatchWorkItem] = []
    private var nodeEditor: SurgeProxyEditorController?
    private var groupEditor: PolicyGroupEditorController?
    private var helperInstallationStatus: PrivilegedHelperClient.InstallationStatus = .notInstalled
    /// Set at launch when the previous session had system proxy on. Applied
    /// once the HTTP listener is actually running.
    private var pendingSystemProxyRestore = false
    private var systemProxyAppliedAddress: ListenAddress?
    private var systemProxyRebindInFlight = false
    private var systemProxyRecoveryInFlight = false
    /// enable() takes a snapshot only after querying network services; protect
    /// its in-flight listener/bypass settings before that file exists.
    private var systemProxyEnableRequests = 0
    private var systemProxyDisableRequests = 0
    private var systemProxyIsOrWillBeEnabled: Bool {
        SystemProxyListenerPlan.protectsConfiguration(
            snapshotExists: systemProxy.isEnabledByHajimi,
            enableRequests: systemProxyEnableRequests)
    }
    private var staleSystemProxyCleanupAttempted = false
    private let externalController = ExternalController()
    private let ruleSetPreparationQueue = DispatchQueue(
        label: "app.hajimi.rule-set-preparation", qos: .userInitiated)
    private let automaticRuleSetQueue = DispatchQueue(
        label: "app.hajimi.rule-set-refresh", qos: .utility)
    private var ruleSetRefreshTimer: Timer?
    private var automaticRuleSetPlan = RuleSetBackgroundRefreshPlan()
    private var automaticRuleSetCacheNeedsApply = false
    private var restoringLaunchSession = true
    private var startupSubscriptionsPending = true
    private var profileRevision = 0
    private var profileApplyGeneration = 0
    private var activeProfilePreparationGeneration: Int?
    /// Last disk contents this window loaded or committed. Do not overwrite
    /// edits made by an external editor while subscriptions or RULE-SETs load.
    private var lastKnownStoredProfileText: String?

    private let byteFormatter: ByteCountFormatter = {
        let value = ByteCountFormatter()
        value.countStyle = .binary
        value.allowedUnits = [.useKB, .useMB, .useGB]
        value.includesUnit = true
        value.isAdaptive = true
        return value
    }()

    init() {
        let store = ConfigurationStore()
        configurationStore = store
        systemProxy = SystemProxyManager(applicationSupportDirectory: store.directoryURL)
        enhancedMode = EnhancedModeManager(applicationSupportDirectory: store.directoryURL)
        protocolAdapters = ProtocolAdapterManager(applicationSupportDirectory: store.directoryURL)
        surgeRuleSets = SurgeRuleSetManager(applicationSupportDirectory: store.directoryURL)
        subscriptions = SubscriptionManager(applicationSupportDirectory: store.directoryURL)
        let source: Result<String, Error> = Result { try store.loadTextThrowing() }
        let text = (try? source.get()) ?? defaultProfileText
        lastKnownStoredProfileText = try? source.get()
        launchProfilePlan = LaunchProfilePlan(source: source)
        // A placeholder keeps the editor usable until the real profile is
        // repaired; all automatic and manual starts are guarded below.
        profile = launchProfilePlan.profile ?? Profile()

        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1220, height: 820),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                              backing: .buffered, defer: false)
        window.title = "哈基米"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.minSize = NSSize(width: 980, height: 800)
        window.contentView = HajimiSurfaceView(fill: HajimiTheme.workspace, cornerRadius: 0)
        window.center()
        super.init(window: window)
        buildUI()
        bindEngine()
        externalController.attach(backend: self)
        loadProfileText(text)
        reconcileStartupActiveSubscription()
        if let error = launchProfilePlan.errorDescription {
            profileStatus.stringValue = "✕ 已阻止启动：\(error)"
            profileStatus.textColor = .systemRed
            profileStatus.toolTip = error
        }
        restorePreferences()
        restartExternalController()
        selectPage(0)
        policyVisibilityObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main
        ) { [weak self] _ in self?.applyPendingPolicyCardUpdates() }
        installWorkspaceWakeObservers()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    deinit {
        ruleSetRefreshTimer?.invalidate()
        proxySearchDebouncer.cancel()
        ruleSearchDebouncer.cancel()
        proxySearchQueue.cancelAllOperations()
        ruleListQueue.cancelAllOperations()
        nodeProbeTickets.values.forEach { $0.cancel() }
        policyCardRefreshWork?.cancel()
        if let policyVisibilityObserver { NotificationCenter.default.removeObserver(policyVisibilityObserver) }
        for observer in workspaceWakeObservers {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        wakeRecoveryWorkItems.forEach { $0.cancel() }
        policyHealth.stop()
    }

    private func installWorkspaceWakeObservers() {
        let notifications: [Notification.Name] = [
            NSWorkspace.didWakeNotification,
            NSWorkspace.screensDidWakeNotification,
            NSWorkspace.sessionDidBecomeActiveNotification
        ]
        workspaceWakeObservers = notifications.map { name in
            NSWorkspace.shared.notificationCenter.addObserver(
                forName: name, object: nil, queue: .main
            ) { [weak self] _ in
                self?.handleWorkspaceWake()
            }
        }
    }

    private func handleWorkspaceWake() {
        wakeRecoveryWorkItems.forEach { $0.cancel() }
        wakeRecoveryWorkItems.removeAll()
        if isEngineActive && !isEnhancedModeActive {
            ProxyEngine.flushCachedOutboundInterfaces()
            SecureDNSHostResolver.shared.flush()
            engine.flushDNS(prewarm: true)
            policyHealth.refresh()
        }
        let delays: [TimeInterval] = [1.0, 2.8]
        for delay in delays {
            let item = DispatchWorkItem { [weak self] in
                guard let self else { return }
                if self.isEngineActive && !self.isEnhancedModeActive {
                    ProxyEngine.flushCachedOutboundInterfaces()
                    SecureDNSHostResolver.shared.flush()
                    self.engine.flushDNS(prewarm: true)
                }
                if self.isEngineActive || self.isEnhancedModeActive {
                    self.policyHealth.refresh()
                    self.probeCaptivePortalIfNeeded()
                }
            }
            wakeRecoveryWorkItems.append(item)
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: item)
        }
    }

    func launch() {
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        let timer = Timer(timeInterval: 15, repeats: true) { [weak self] _ in
            self?.refreshRuleSetsAutomatically()
        }
        timer.tolerance = 3
        ruleSetRefreshTimer = timer
        RunLoop.main.add(timer, forMode: .common)
        prepareLaunchSession()
    }

    private func prepareLaunchSession() {
        guard let ticket = launchRestoreIntent.reserve() else { return }
        launchRestoreTicket = ticket
        DispatchQueue.main.async { [weak self] in
            guard let self, self.launchRestoreIntent.isCurrent(ticket) else { return }
            // A new process cannot adopt the previous App's utun FD. Leave a
            // live process alone; the Helper expires orphaned sessions itself.
            self.enhancedMode.prepareExistingSession(engine: self.engine) { result in
                guard self.launchRestoreIntent.isCurrent(ticket) else { return }
                if case .failure(let error) = result {
                    self.enhancedModeButton.state = .off
                    self.showError(title: "清理上次增强模式失败", error: error)
                }
                self.restoreLastSession(restoreTicket: ticket)
            }
        }
    }

    var isEngineActive: Bool {
        let lifecycle = listenerLifecycle.snapshot
        if lifecycle.startupPending || lifecycle.isPresent { return true }
        switch engineStatus { case .running, .starting: return true; default: return false }
    }

    var isSystemProxyActive: Bool { systemProxy.isEnabledByHajimi }
    var isEnhancedModeActive: Bool {
        enhancedMode.isRequested || enhancedRequestIntent.snapshot.startupPending || enhancedMode.lifecycleSnapshot.isPresent
            || enhancedMode.lifecycleSnapshot.startupPending
    }

    var onStatusBarStateChanged: (() -> Void)?

    var statusItemOutboundMode: OutboundMode { selectedMode }
    var statusItemGlobalPolicy: String {
        let current = selectedPolicy
        if profile.groups[current] != nil || (!profile.globalProxyNodes.isEmpty && !profile.globalProxyNodes.contains(current)) {
            return profile.globalProxyNodes.first ?? "DIRECT"
        }
        return current
    }
    /// Strictly real proxy nodes only — policy groups are forbidden from Global Proxy selection.
    var statusItemGlobalPolicies: [String] { profile.globalProxyNodes }

    var statusItemOptimalNodeName: String? {
        var bestName: String?
        var bestMs = Int.max
        for name in profile.globalProxyNodes {
            if case .success(let ms)? = nodeLatencies[name], ms < bestMs {
                bestMs = ms
                bestName = name
            }
        }
        return bestName
    }

    var statusItemGlobalNodeItems: [StatusProxyNodeItem] {
        let optimal = statusItemOptimalNodeName
        return profile.globalProxyNodes.map { statusItemNodeItem(named: $0, optimalName: optimal) }
    }

    private func resolveLeafProxyName(from policyName: String) -> String {
        var current = policyName
        var visited = Set<String>()
        for _ in 0..<12 {
            guard visited.insert(current).inserted, let group = profile.groups[current] else { break }
            let next = groupSelections[current].flatMap { group.members.contains($0) ? $0 : nil }
                ?? group.members.first
            guard let next else { break }
            current = next
        }
        return current
    }

    func statusItemOptimalMemberName(forGroup groupName: String) -> String? {
        guard let group = profile.groups[groupName] else { return nil }
        var bestName: String?
        var bestMs = Int.max
        for member in group.members {
            let leaf = resolveLeafProxyName(from: member)
            if case .success(let ms)? = nodeLatencies[leaf], ms < bestMs {
                bestMs = ms
                bestName = member
            }
        }
        return bestName
    }

    func statusItemNodeItem(named name: String, optimalName: String? = nil) -> StatusProxyNodeItem {
        let proto: String
        let leaf = resolveLeafProxyName(from: name)
        if let policy = profile.proxies[name] {
            if let raw = policy.adapterType, !raw.isEmpty {
                proto = raw.uppercased()
            } else {
                proto = policy.kind.rawValue.uppercased()
            }
        } else if profile.groups[name] != nil {
            proto = "GROUP"
        } else {
            proto = "DIRECT"
        }
        let lat: NodeLatency
        if name.uppercased() == "DIRECT" || leaf.uppercased() == "DIRECT" {
            lat = .untested
        } else {
            lat = nodeLatencies[name] ?? nodeLatencies[leaf] ?? .untested
        }
        let ms: Int?
        if case .success(let value) = lat {
            ms = value
        } else {
            ms = nil
        }
        let best = optimalName ?? statusItemOptimalNodeName
        return StatusProxyNodeItem(
            name: name,
            protocolTag: proto,
            latency: lat,
            latencyMillis: ms,
            isOptimal: best != nil && best == name
        )
    }

    var isStatusItemTestingNodes: Bool {
        !nodeProbeRequests.isEmpty || nodeProbeBatch != nil
    }

    var statusItemLatencySummary: String {
        let nodes = profile.globalProxyNodes
        guard !nodes.isEmpty else { return "暂无可测速节点" }
        var testedCount = 0
        var reachableCount = 0
        var fastest: Int?
        for name in nodes {
            guard let lat = nodeLatencies[name] else { continue }
            switch lat {
            case .untested, .queued, .testing:
                break
            case .success(let ms):
                testedCount += 1
                reachableCount += 1
                if let currentFastest = fastest {
                    if ms < currentFastest { fastest = ms }
                } else {
                    fastest = ms
                }
            case .failed, .unavailable:
                testedCount += 1
            }
        }
        if isStatusItemTestingNodes {
            return "⚡ 正在测速 (\(testedCount)/\(nodes.count))…"
        }
        if testedCount == 0 {
            return "⚡ 节点延迟测速（共 \(nodes.count) 个节点）"
        }
        if let fastest {
            return "⚡ 节点测速：可用 \(reachableCount)/\(nodes.count) · 最快 \(fastest) ms"
        }
        return "⚡ 节点测速：已测 \(testedCount)/\(nodes.count) · 暂无可达"
    }

    func statusItemTelemetrySnapshot(uploadRate: Double, downloadRate: Double) -> StatusBarTelemetrySnapshot {
        let activeNode: String
        switch selectedMode {
        case .direct:
            activeNode = "DIRECT"
        case .proxy:
            activeNode = statusItemGlobalPolicy
        case .rule:
            if let firstGroup = statusItemPolicyGroups.first, let selected = firstGroup.selectedMember {
                activeNode = selected
            } else {
                activeNode = profile.globalProxyNodes.first ?? "DIRECT"
            }
        }
        let latencyMs: Int
        if let lat = nodeLatencies[activeNode] {
            switch lat {
            case .success(let ms): latencyMs = max(1, ms)
            case .failed, .unavailable: latencyMs = 0
            case .untested, .queued, .testing: latencyMs = -1
            }
        } else {
            latencyMs = -1
        }
        let totalUp = UInt64(max(0, uploaded)) + enhancedUploaded
        let totalDown = UInt64(max(0, downloaded)) + enhancedDownloaded
        let activeConns = activeConnectionIDs.count + enhancedActiveConnections
        return StatusBarTelemetrySnapshot(
            running: isEngineActive,
            enhancedMode: isEnhancedModeActive,
            systemProxy: isSystemProxyActive,
            modeTitle: statusItemOutboundMode.displayName,
            activeNodeName: activeNode,
            activeNodeLatencyMillis: latencyMs,
            uploadBytesPerSecond: uploadRate,
            downloadBytesPerSecond: downloadRate,
            totalUploadedBytes: totalUp,
            totalDownloadedBytes: totalDown,
            activeConnections: activeConns
        )
    }

    func testAllNodesFromStatusItem() {
        testAllNodes()
        onStatusBarStateChanged?()
    }

    func testSingleNodeFromStatusItem(_ name: String) {
        guard profile.proxies[name] != nil else { return }
        testNode(named: name)
        onStatusBarStateChanged?()
    }

    func testActiveNodeFromStatusItem() {
        let snapshot = statusItemTelemetrySnapshot(uploadRate: 0, downloadRate: 0)
        if profile.proxies[snapshot.activeNodeName] != nil {
            testSingleNodeFromStatusItem(snapshot.activeNodeName)
        } else if let first = profile.globalProxyNodes.first {
            testSingleNodeFromStatusItem(first)
        } else {
            testAllNodesFromStatusItem()
        }
    }

    func testGroupNodesFromStatusItem(group groupName: String) {
        guard let group = profile.groups[groupName] else { return }
        let nodes = group.members.filter { profile.proxies[$0] != nil && profile.groups[$0] == nil }
        guard !nodes.isEmpty else { return }
        cancelNodeTests(refresh: false)
        for name in nodes { nodeLatencies[name] = .queued }
        nodeProbeBatch = NodeProbeBatchCursor(names: nodes)
        policyStatusLabel.stringValue = "正在测试策略组 \(groupName) 的 \(nodes.count) 个节点…"
        policyStatusLabel.textColor = .systemBlue
        pumpNodeProbeBatch(refreshStarts: false)
        schedulePolicyCardUpdates(proxies: Set(nodes), immediately: true)
        onStatusBarStateChanged?()
    }

    var statusItemPolicyGroups: [StatusPolicyGroupSelection] {
        profile.groupOrder.compactMap { name in
            guard let group = profile.groups[name], group.showsInStatusBar else { return nil }
            let current = groupSelections[name].flatMap { group.members.contains($0) ? $0 : nil }
            let isManual = !PolicyHealthMonitor.managesSelection(of: group) || manualManagedGroupSelections.contains(name)
            let explicit = isManual ? current : nil
            let effective = current ?? group.members.first
            return StatusPolicyGroupSelection(
                name: name,
                kind: group.kind,
                members: group.members,
                selectedMember: explicit,
                effectiveMember: effective
            )
        }
    }

    /// Bytes per second, engine and helper combined.
    ///
    /// This advances the measurement windows, so it is a function rather than a
    /// property: calling it twice in the same tick would consume a window and
    /// halve the reported rate.
    func statusItemTrafficRate() -> (upload: Double, download: Double) {
        let now = ProcessInfo.processInfo.systemUptime
        if isEngineActive {
            engineUploadRate.observe(UInt64(max(0, uploaded)), at: now)
            engineDownloadRate.observe(UInt64(max(0, downloaded)), at: now)
        } else {
            engineUploadRate.idle(at: now)
            engineDownloadRate.idle(at: now)
        }
        if !isEnhancedModeActive {
            enhancedUploadRate.idle(at: now)
            enhancedDownloadRate.idle(at: now)
        }
        let rates = (upload: engineUploadRate.bytesPerSecond + enhancedUploadRate.bytesPerSecond,
                     download: engineDownloadRate.bytesPerSecond + enhancedDownloadRate.bytesPerSecond)
        nativeTrafficView.update(uploadBytesPerSecond: rates.upload, downloadBytesPerSecond: rates.download,
                                 activeConnections: activeConnectionIDs.count + enhancedActiveConnections)
        return rates
    }

    var statusItemSummary: String {
        let presentation = connectionPresentation
        return "\(presentation.title) · \(presentation.detail)"
    }

    func revealFromStatusItem() {
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        applyPendingPolicyCardUpdates()
    }

    func toggleEngineFromStatusItem() { toggleEngine() }

    func toggleSystemProxyFromStatusItem() {
        systemProxyButton.state = isSystemProxyActive ? .off : .on
        toggleSystemProxy()
    }

    func toggleEnhancedModeFromStatusItem() {
        enhancedModeButton.state = isEnhancedModeActive ? .off : .on
        toggleEnhancedMode()
    }

    func selectOutboundModeFromStatusItem(_ mode: OutboundMode) {
        guard let index = OutboundMode.allCases.firstIndex(of: mode) else { return }
        modePopup.selectItem(at: index)
        modeChanged()
        onStatusBarStateChanged?()
    }

    func selectGlobalPolicyFromStatusItem(_ name: String) {
        guard profile.groups[name] == nil, profile.selectablePolicies.contains(name) else { return }
        if selectedMode != .proxy {
            modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: .proxy) ?? 2)
            UserDefaults.standard.set(OutboundMode.proxy.rawValue, forKey: "outboundMode")
            policyPopup.isEnabled = true
        }
        policyPopup.selectItem(withTitle: name)
        policyChanged()
        onStatusBarStateChanged?()
    }

    func selectGroupMemberFromStatusItem(group: String, member: String?) {
        guard let policyGroup = profile.groups[group] else { return }
        if let member, !policyGroup.members.contains(member) { return }
        setGroupSelection(group: group, member: member)
        onStatusBarStateChanged?()
    }

    /// Best-effort helper teardown for process exit. Safe to call more than once.
    func shutdownEnhancedModeForQuit() {
        if let ticket = enhancedRequestIntent.cancel() { enhancedRequestIntent.release(ticket) }
        enhancedMode.shutdownForQuit()
        networkRuntime.lifecycleDidChange()
        enhancedModeButton.state = .off
        dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
        enhancedActiveConnections = 0
        enhancedTotalConnections = 0
        enhancedUploaded = 0
        enhancedDownloaded = 0
    }

    func restoreSystemProxyBeforeQuit() throws {
        cancelLaunchRestorePreparation()
        // Enhanced mode is stopped separately in applicationShouldTerminate so
        // a system-proxy restore failure cannot leave utun routes installed.
        if enhancedMode.isEnabled { enhancedMode.shutdownForQuit() }
        // Always join the manager queue: an enable may have been enqueued but
        // not yet saved its snapshot when the user chooses Quit.
        try systemProxy.disableSynchronously()
        stopListenerResources()
        externalController.stop()
    }

    private func buildUI() {
        guard let root = window?.contentView else { return }
        sidebar.translatesAutoresizingMaskIntoConstraints = false
        contentContainer.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(sidebar)
        root.addSubview(contentContainer)
        NSLayoutConstraint.activate([
            sidebar.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            sidebar.topAnchor.constraint(equalTo: root.topAnchor),
            sidebar.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            sidebar.widthAnchor.constraint(equalToConstant: 218),
            contentContainer.leadingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            contentContainer.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            contentContainer.topAnchor.constraint(equalTo: root.topAnchor),
            contentContainer.bottomAnchor.constraint(equalTo: root.bottomAnchor)
        ])
        buildSidebar()
        buildDashboard()
        buildPolicies()
        buildRules()
        buildAbout()
        buildSettings()
        for view in [dashboardView, policiesView, rulesView, aboutView, settingsView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            contentContainer.addSubview(view)
            NSLayoutConstraint.activate([
                view.leadingAnchor.constraint(equalTo: contentContainer.leadingAnchor),
                view.trailingAnchor.constraint(equalTo: contentContainer.trailingAnchor),
                view.topAnchor.constraint(equalTo: contentContainer.topAnchor),
                view.bottomAnchor.constraint(equalTo: contentContainer.bottomAnchor)
            ])
        }
    }

    private func buildSidebar() {
        let sidebarBorder = HajimiSurfaceView(fill: HajimiAppearance.border, cornerRadius: 0)
        sidebarBorder.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(sidebarBorder)
        NSLayoutConstraint.activate([
            sidebarBorder.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            sidebarBorder.topAnchor.constraint(equalTo: sidebar.topAnchor),
            sidebarBorder.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor),
            sidebarBorder.widthAnchor.constraint(equalToConstant: 1)
        ])

        let logo = NSImageView(image: HajimiBrandIcon.makeImage())
        logo.imageScaling = .scaleProportionallyUpOrDown
        logo.imageAlignment = .alignCenter
        logo.contentTintColor = .labelColor
        logo.setAccessibilityLabel("哈基米橘猫图标")
        logo.translatesAutoresizingMaskIntoConstraints = false

        let title = NSTextField(labelWithString: "哈基米")
        title.font = .systemFont(ofSize: 21, weight: .bold)
        let subtitle = NSTextField(labelWithString: "Network Engine · macOS")
        subtitle.font = .systemFont(ofSize: 10.5, weight: .medium)
        subtitle.textColor = .secondaryLabelColor

        let titleStack = NSStackView(views: [title, subtitle])
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 2
        let logoTile = HajimiSurfaceView(fill: HajimiAppearance.elevatedPanel,
                                         border: HajimiAppearance.accent.withAlphaComponent(0.24), cornerRadius: 14)
        logoTile.addSubview(logo)
        let brand = NSStackView(views: [logoTile, titleStack])
        brand.orientation = .horizontal
        brand.alignment = .centerY
        brand.spacing = 12
        brand.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(brand)
        NSLayoutConstraint.activate([
            brand.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 18),
            brand.topAnchor.constraint(equalTo: sidebar.topAnchor, constant: 52),
            logoTile.widthAnchor.constraint(equalToConstant: 46),
            logoTile.heightAnchor.constraint(equalToConstant: 46),
            logo.widthAnchor.constraint(equalToConstant: 34),
            logo.heightAnchor.constraint(equalToConstant: 34),
            logo.centerXAnchor.constraint(equalTo: logoTile.centerXAnchor),
            logo.centerYAnchor.constraint(equalTo: logoTile.centerYAnchor)
        ])

        let entries = [
            ("总览", "rectangle.3.group"),
            ("策略", "point.3.connected.trianglepath.dotted"),
            ("规则", "list.bullet.rectangle"),
            ("功能说明", "info.circle")
        ]
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .width
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 14),
            stack.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -14),
            stack.topAnchor.constraint(equalTo: brand.bottomAnchor, constant: 30)
        ])
        for (index, entry) in entries.enumerated() {
            let button = HajimiNavigationButton(title: "  " + entry.0,
                                                target: self, action: #selector(navigate(_:)))
            button.image = NSImage(systemSymbolName: entry.1, accessibilityDescription: entry.0)?
                .withSymbolConfiguration(.init(pointSize: 14, weight: .semibold))
            button.imagePosition = .imageLeading
            button.setAccessibilityLabel(entry.0)
            button.tag = index
            navigationButtons.append(button)
            stack.addArrangedSubview(button)
            button.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }

        let settingsButton = HajimiNavigationButton(title: "  设置",
                                                    target: self, action: #selector(navigate(_:)))
        settingsButton.image = NSImage(systemSymbolName: "gearshape", accessibilityDescription: "设置")?
            .withSymbolConfiguration(.init(pointSize: 14, weight: .semibold))
        settingsButton.imagePosition = .imageLeading
        settingsButton.setAccessibilityLabel("设置")
        settingsButton.tag = 4
        settingsButton.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(settingsButton)
        navigationButtons.append(settingsButton)

        let statusCard = HajimiSurfaceView(fill: HajimiAppearance.elevatedPanel,
                                           border: HajimiAppearance.border, cornerRadius: 12)
        statusCard.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(statusCard)

        sidebarStatusDot.translatesAutoresizingMaskIntoConstraints = false
        sidebarStatusText.font = .systemFont(ofSize: 12, weight: .semibold)
        sidebarStatusDetail.font = .systemFont(ofSize: 10)
        sidebarStatusDetail.textColor = .secondaryLabelColor
        sidebarStatusDetail.lineBreakMode = .byWordWrapping
        sidebarStatusDetail.maximumNumberOfLines = 4
        sidebarStatusDetail.cell?.wraps = true
        sidebarStatusDetail.cell?.truncatesLastVisibleLine = true
        sidebarStatusDetail.preferredMaxLayoutWidth = 148
        sidebarStatusDetail.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let statusCopy = NSStackView(views: [sidebarStatusText, sidebarStatusDetail])
        statusCopy.orientation = .vertical
        statusCopy.alignment = .leading
        statusCopy.spacing = 2
        let sidebarStatus = NSStackView(views: [sidebarStatusDot, statusCopy])
        sidebarStatus.orientation = .horizontal
        sidebarStatus.alignment = .centerY
        sidebarStatus.spacing = 10
        sidebarStatus.translatesAutoresizingMaskIntoConstraints = false
        statusCard.addSubview(sidebarStatus)

        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.0"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        let versionLabel = "版本 \(version)" + (build.map { "  ·  Build \($0)" } ?? "")
        let arch = NSTextField(labelWithString: versionLabel)
        arch.font = .systemFont(ofSize: 10)
        arch.textColor = .tertiaryLabelColor
        arch.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(arch)
        NSLayoutConstraint.activate([
            settingsButton.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 14),
            settingsButton.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -14),
            settingsButton.bottomAnchor.constraint(equalTo: statusCard.topAnchor, constant: -10),
            statusCard.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 14),
            statusCard.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -14),
            statusCard.bottomAnchor.constraint(equalTo: arch.topAnchor, constant: -10),
            statusCard.heightAnchor.constraint(greaterThanOrEqualToConstant: 54),
            sidebarStatus.leadingAnchor.constraint(equalTo: statusCard.leadingAnchor, constant: 12),
            sidebarStatus.trailingAnchor.constraint(equalTo: statusCard.trailingAnchor, constant: -12),
            sidebarStatus.topAnchor.constraint(greaterThanOrEqualTo: statusCard.topAnchor, constant: 10),
            sidebarStatus.bottomAnchor.constraint(lessThanOrEqualTo: statusCard.bottomAnchor, constant: -10),
            sidebarStatus.centerYAnchor.constraint(equalTo: statusCard.centerYAnchor),
            sidebarStatusDot.widthAnchor.constraint(equalToConstant: 8),
            sidebarStatusDot.heightAnchor.constraint(equalToConstant: 8),
            arch.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 18),
            arch.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor, constant: -16)
        ])
    }

    private func buildDashboard() {
        let header = pageHeader(eyebrow: "CONTROL CENTER", title: "网络总览",
                                subtitle: "本机代理状态、路由与流量")
        dashboardView.addSubview(header)
        let diagnostics = NSButton(title: "网络诊断", target: self, action: #selector(showNetworkDiagnostics))
        diagnostics.bezelStyle = .rounded
        diagnostics.image = NSImage(systemSymbolName: "waveform.path.ecg", accessibilityDescription: nil)
        diagnostics.imagePosition = .imageLeading
        diagnostics.contentTintColor = HajimiAppearance.accentText
        diagnostics.controlSize = .large
        diagnostics.font = .systemFont(ofSize: 12, weight: .medium)
        diagnostics.translatesAutoresizingMaskIntoConstraints = false
        dashboardView.addSubview(diagnostics)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: dashboardView.topAnchor, constant: 48),
            diagnostics.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            diagnostics.topAnchor.constraint(equalTo: dashboardView.topAnchor, constant: 64)
        ])

        let controls = cardView()
        controls.translatesAutoresizingMaskIntoConstraints = false
        dashboardView.addSubview(controls)
        NSLayoutConstraint.activate([
            controls.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            controls.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            controls.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 22),
            controls.heightAnchor.constraint(equalToConstant: 126)
        ])

        statusLabel.font = .systemFont(ofSize: 19, weight: .semibold)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        systemProxyButton.target = self
        systemProxyButton.action = #selector(toggleSystemProxy)
        systemProxyButton.setButtonType(.switch)
        systemProxyButton.state = systemProxy.isEnabledByHajimi ? .on : .off
        enhancedModeButton.target = self
        enhancedModeButton.action = #selector(toggleEnhancedMode)
        enhancedModeButton.setButtonType(.switch)
        enhancedModeButton.state = enhancedMode.isEnabled ? .on : .off

        modePopup.addItems(withTitles: OutboundMode.allCases.map(\.displayName))
        modePopup.target = self
        modePopup.action = #selector(modeChanged)
        policyPopup.target = self
        policyPopup.action = #selector(policyChanged)
        policyPopup.setContentHuggingPriority(.defaultLow, for: .horizontal)
        groupPopup.target = self
        groupPopup.action = #selector(groupChanged)
        groupMemberPopup.target = self
        groupMemberPopup.action = #selector(groupMemberChanged)
        groupPopup.setContentHuggingPriority(.defaultLow, for: .horizontal)
        groupMemberPopup.setContentHuggingPriority(.defaultLow, for: .horizontal)
        for popup in [modePopup, policyPopup, groupPopup, groupMemberPopup] {
            popup.font = .systemFont(ofSize: 12)
        }

        let engineCaption = NSTextField(labelWithString: "连接状态")
        engineCaption.font = .systemFont(ofSize: 10.5, weight: .medium)
        engineCaption.textColor = .secondaryLabelColor
        let engineIdentity = NSStackView(views: [engineCaption, statusLabel])
        engineIdentity.orientation = .vertical
        engineIdentity.alignment = .leading
        engineIdentity.spacing = 3
        let primarySpacer = NSView()
        primarySpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let connectionTile = HajimiTheme.iconTile(symbol: "network", color: HajimiAppearance.accentText,
                                                  size: 44, symbolSize: 20)
        let primaryStack = NSStackView(views: [connectionTile, engineIdentity, primarySpacer,
                                               systemProxyButton, enhancedModeButton])
        primaryStack.orientation = .horizontal
        primaryStack.alignment = .centerY
        primaryStack.spacing = 14
        primaryStack.translatesAutoresizingMaskIntoConstraints = false
        let controlsDivider = HajimiSurfaceView(fill: HajimiAppearance.border, cornerRadius: 0)
        controlsDivider.translatesAutoresizingMaskIntoConstraints = false
        let routingStack = NSStackView(views: [labeledControl("出站", modePopup),
                                               labeledControl("全局策略", policyPopup), separator(),
                                               labeledControl("策略组", groupPopup),
                                               labeledControl("当前成员", groupMemberPopup)])
        routingStack.orientation = .horizontal
        routingStack.alignment = .centerY
        routingStack.spacing = 14
        routingStack.translatesAutoresizingMaskIntoConstraints = false
        controls.addSubview(primaryStack)
        controls.addSubview(controlsDivider)
        controls.addSubview(routingStack)
        NSLayoutConstraint.activate([
            primaryStack.leadingAnchor.constraint(equalTo: controls.leadingAnchor, constant: 18),
            primaryStack.trailingAnchor.constraint(equalTo: controls.trailingAnchor, constant: -18),
            primaryStack.topAnchor.constraint(equalTo: controls.topAnchor, constant: 15),
            controlsDivider.leadingAnchor.constraint(equalTo: controls.leadingAnchor, constant: 18),
            controlsDivider.trailingAnchor.constraint(equalTo: controls.trailingAnchor, constant: -18),
            controlsDivider.topAnchor.constraint(equalTo: primaryStack.bottomAnchor, constant: 11),
            controlsDivider.heightAnchor.constraint(equalToConstant: 1),
            routingStack.leadingAnchor.constraint(equalTo: controls.leadingAnchor, constant: 18),
            routingStack.trailingAnchor.constraint(lessThanOrEqualTo: controls.trailingAnchor, constant: -18),
            routingStack.bottomAnchor.constraint(equalTo: controls.bottomAnchor, constant: -14)
        ])

        let stats = NSStackView()
        stats.orientation = .horizontal
        stats.distribution = .fillEqually
        stats.spacing = 14
        stats.translatesAutoresizingMaskIntoConstraints = false
        stats.addArrangedSubview(statCard(title: "活动连接", value: activeValue, color: HajimiTheme.accent))
        stats.addArrangedSubview(statCard(title: "累计连接", value: totalValue, color: .systemIndigo))
        stats.addArrangedSubview(statCard(title: "上传流量", value: uploadValue, color: .systemBlue))
        stats.addArrangedSubview(statCard(title: "下载流量", value: downloadValue, color: HajimiTheme.accent))
        dashboardView.addSubview(stats)
        NSLayoutConstraint.activate([
            stats.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            stats.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            stats.topAnchor.constraint(equalTo: controls.bottomAnchor, constant: 16),
            stats.heightAnchor.constraint(equalToConstant: 96)
        ])

        let runtimeTitle = NSTextField(labelWithString: "运行概况")
        nativeTrafficView.translatesAutoresizingMaskIntoConstraints = false
        dashboardView.addSubview(nativeTrafficView)
        runtimeTitle.font = .systemFont(ofSize: 14, weight: .semibold)
        runtimeTitle.translatesAutoresizingMaskIntoConstraints = false
        dashboardView.addSubview(runtimeTitle)

        let runtimeCard = cardView()
        runtimeCard.translatesAutoresizingMaskIntoConstraints = false
        dashboardView.addSubview(runtimeCard)
        let runtimeColumns = NSStackView(views: [
            overviewInfoColumn(title: "HTTP 入口", value: httpRuntimeValue,
                               detail: "系统 HTTP/HTTPS 代理入口", icon: "network", color: .systemBlue),
            overviewInfoColumn(title: "SOCKS5 入口", value: socksRuntimeValue,
                               detail: "TCP 与 UDP ASSOCIATE", icon: "arrow.triangle.branch", color: HajimiTheme.accent),
            overviewInfoColumn(title: "当前路由", value: routingRuntimeValue,
                               detail: "切换策略无需重启", icon: "point.3.connected.trianglepath.dotted", color: .systemIndigo),
            overviewInfoColumn(title: "数据面", value: dataPlaneRuntimeValue,
                               detail: "连接并行 · 流量批量统计", icon: "speedometer", color: .systemOrange)
        ])
        runtimeColumns.orientation = .horizontal
        runtimeColumns.distribution = .fillEqually
        runtimeColumns.spacing = 0
        runtimeColumns.translatesAutoresizingMaskIntoConstraints = false
        runtimeCard.addSubview(runtimeColumns)

        NSLayoutConstraint.activate([
            runtimeTitle.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            nativeTrafficView.leadingAnchor.constraint(equalTo: stats.leadingAnchor),
            nativeTrafficView.trailingAnchor.constraint(equalTo: stats.trailingAnchor),
            nativeTrafficView.topAnchor.constraint(equalTo: stats.bottomAnchor, constant: 16),
            nativeTrafficView.heightAnchor.constraint(equalToConstant: 142),
            runtimeTitle.topAnchor.constraint(equalTo: nativeTrafficView.bottomAnchor, constant: 20),
            runtimeCard.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            runtimeCard.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            runtimeCard.topAnchor.constraint(equalTo: runtimeTitle.bottomAnchor, constant: 10),
            runtimeCard.heightAnchor.constraint(equalToConstant: 112),
            runtimeColumns.leadingAnchor.constraint(equalTo: runtimeCard.leadingAnchor, constant: 8),
            runtimeColumns.trailingAnchor.constraint(equalTo: runtimeCard.trailingAnchor, constant: -8),
            runtimeColumns.topAnchor.constraint(equalTo: runtimeCard.topAnchor, constant: 10),
            runtimeColumns.bottomAnchor.constraint(equalTo: runtimeCard.bottomAnchor, constant: -10)
        ])
        updateOverviewDetails()
    }

    @objc private func showNetworkDiagnostics() {
        if diagnosticsPanel == nil {
            let capabilities = NetworkDiagnosticsAppAdapter.capabilities(contextProvider: { [weak self] in
                self?.networkDiagnosticsContext ?? .unavailable
            }, startDiagnostics: { [weak self] update in
                guard let self else {
                    return AppNetworkRuntime.unavailable(onUpdate: update)
                }
                return self.networkRuntime.startDiagnostics(configuration: self.networkDiagnosticsConfiguration,
                    onUpdate: update)
            })
            diagnosticsPanel = NetworkDiagnosticsPanelController(capabilities: capabilities)
        }
        diagnosticsPanel?.showWindow(nil)
        diagnosticsPanel?.window?.makeKeyAndOrderFront(nil)
    }

    private var networkDiagnosticsContext: NetworkDiagnosticsRuntimeContext {
        networkRuntime.context(configuration: networkDiagnosticsConfiguration)
    }

    private var networkDiagnosticsConfiguration: NetworkDiagnosticsConfiguration {
        NetworkDiagnosticsConfiguration(mode: selectedMode.displayName, selectedPolicy: selectedPolicy,
            groupSelections: groupSelections, profileRevision: profileRevision, systemProxy: isSystemProxyActive)
    }

    private func buildPolicies() {
        let header = pageHeader(eyebrow: "POLICIES", title: "策略",
                                subtitle: "节点、策略组与运行时选择")
        policiesView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: policiesView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: policiesView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: policiesView.topAnchor, constant: 48)
        ])

        proxySearchField.placeholderString = "搜索名称、协议或服务器"
        proxySearchField.sendsSearchStringImmediately = true
        proxySearchField.target = self
        proxySearchField.action = #selector(proxySearchChanged)
        proxySearchField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let searchWidth = proxySearchField.widthAnchor.constraint(equalToConstant: 245)
        searchWidth.priority = NSLayoutConstraint.Priority(749)
        searchWidth.isActive = true
        proxySearchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 150).isActive = true
        proxyCountLabel.font = .systemFont(ofSize: 11)
        proxyCountLabel.textColor = .secondaryLabelColor
        let testAll = NSButton(title: "测试全部延迟", target: self, action: #selector(testAllNodes))
        testAll.image = NSImage(systemSymbolName: "bolt.horizontal", accessibilityDescription: nil)
        testAll.imagePosition = .imageLeading
        let add = NSButton(title: "新增节点", target: self, action: #selector(addProxy))
        add.image = NSImage(systemSymbolName: "plus", accessibilityDescription: nil)
        add.imagePosition = .imageLeading
        add.bezelStyle = .rounded
        let importLinks = NSButton(title: "导入链接", target: self,
                                   action: #selector(importShareLinks))
        importLinks.image = NSImage(systemSymbolName: "link.badge.plus",
                                    accessibilityDescription: nil)
        importLinks.imagePosition = .imageLeading
        importLinks.bezelStyle = .rounded
        let addGroup = NSButton(title: "新增策略组", target: self, action: #selector(addPolicyGroup))
        addGroup.image = NSImage(systemSymbolName: "plus.rectangle.on.folder", accessibilityDescription: nil)
        addGroup.imagePosition = .imageLeading
        let toolbar = NSStackView(views: [proxySearchField, proxyCountLabel, NSView(),
                                          testAll, addGroup, importLinks, add])
        toolbar.orientation = .horizontal
        toolbar.alignment = .centerY
        toolbar.spacing = 10
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        policiesView.addSubview(toolbar)

        let panel = cardView()
        panel.translatesAutoresizingMaskIntoConstraints = false
        policiesView.addSubview(panel)
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        configurePolicyCollection()
        scroll.documentView = policyCollectionView
        panel.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 6),
            scroll.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -6),
            scroll.topAnchor.constraint(equalTo: panel.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: panel.bottomAnchor, constant: -7)
        ])

        policyStatusLabel.font = .systemFont(ofSize: 10.5, weight: .medium)
        policyStatusLabel.textColor = .secondaryLabelColor
        policyStatusLabel.lineBreakMode = .byTruncatingTail
        policyStatusLabel.translatesAutoresizingMaskIntoConstraints = false
        policiesView.addSubview(policyStatusLabel)
        NSLayoutConstraint.activate([
            toolbar.leadingAnchor.constraint(equalTo: policiesView.leadingAnchor, constant: 30),
            toolbar.trailingAnchor.constraint(equalTo: policiesView.trailingAnchor, constant: -30),
            toolbar.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 19),
            panel.leadingAnchor.constraint(equalTo: policiesView.leadingAnchor, constant: 30),
            panel.trailingAnchor.constraint(equalTo: policiesView.trailingAnchor, constant: -30),
            panel.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 13),
            panel.bottomAnchor.constraint(equalTo: policyStatusLabel.topAnchor, constant: -9),
            policyStatusLabel.leadingAnchor.constraint(equalTo: policiesView.leadingAnchor, constant: 32),
            policyStatusLabel.trailingAnchor.constraint(equalTo: policiesView.trailingAnchor, constant: -30),
            policyStatusLabel.bottomAnchor.constraint(equalTo: policiesView.bottomAnchor, constant: -18)
        ])
    }

    private func configurePolicyCollection() {
        policyCollectionView.autoresizingMask = [.width]
        let layout = PolicyCardFlowLayout()
        layout.itemSize = NSSize(width: 147, height: 84)
        layout.sectionInset = NSEdgeInsets(top: 3, left: 6, bottom: 18, right: 6)
        layout.headerReferenceSize = NSSize(width: 147, height: 54)
        layout.minimumInteritemSpacing = 8
        layout.minimumLineSpacing = 8
        layout.scrollDirection = .vertical
        policyCollectionView.collectionViewLayout = layout
        policyCollectionView.dataSource = self
        policyCollectionView.delegate = self
        policyCollectionView.isSelectable = true
        policyCollectionView.backgroundColors = [.clear]
        policyCollectionView.register(ProxyCardCollectionItem.self,
                                     forItemWithIdentifier: ProxyCardCollectionItem.identifier)
        policyCollectionView.register(AddProxyCollectionItem.self,
                                     forItemWithIdentifier: AddProxyCollectionItem.identifier)
        policyCollectionView.register(GroupCardCollectionItem.self,
                                     forItemWithIdentifier: GroupCardCollectionItem.identifier)
        policyCollectionView.register(AddGroupCollectionItem.self,
                                     forItemWithIdentifier: AddGroupCollectionItem.identifier)
        policyCollectionView.register(PolicySectionHeaderView.self,
            forSupplementaryViewOfKind: NSCollectionView.elementKindSectionHeader,
            withIdentifier: PolicySectionHeaderView.identifier)
        policyCollectionView.contextMenuProvider = { [weak self] indexPath -> NSMenu? in
            guard let self else { return nil }
            let proxyNames = self.renderedProxyOrder ?? self.filteredProxyNames
            let groupNames = self.renderedGroupOrder ?? self.profile.groupOrder
            if indexPath.section == 0, proxyNames.indices.contains(indexPath.item) {
                return self.makeProxyMenu(name: proxyNames[indexPath.item])
            }
            if indexPath.section == 1, groupNames.indices.contains(indexPath.item) {
                return self.makeGroupMenu(name: groupNames[indexPath.item])
            }
            return nil
        }
        policyCollectionView.reloadData()
    }

    private func configureProxyTable() {
        proxyTableView.dataSource = self
        proxyTableView.delegate = self
        proxyTableView.headerView = nil
        proxyTableView.rowHeight = 72
        proxyTableView.intercellSpacing = NSSize(width: 0, height: 0)
        proxyTableView.backgroundColor = .clear
        proxyTableView.selectionHighlightStyle = .none
        proxyTableView.doubleAction = #selector(editSelectedProxy)
        proxyTableView.target = self
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("proxy"))
        column.resizingMask = .autoresizingMask
        proxyTableView.addTableColumn(column)
        let menu = NSMenu(title: "节点")
        menu.delegate = self
        proxyTableView.menu = menu
    }

    private func configureGroupTable() {
        groupTableView.dataSource = self
        groupTableView.delegate = self
        groupTableView.headerView = nil
        groupTableView.rowHeight = 68
        groupTableView.intercellSpacing = NSSize(width: 0, height: 0)
        groupTableView.backgroundColor = .clear
        groupTableView.selectionHighlightStyle = .none
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("group"))
        column.resizingMask = .autoresizingMask
        groupTableView.addTableColumn(column)
    }

    private func buildRules() {
        let header = pageHeader(eyebrow: "RULES", title: "规则",
                                subtitle: "管理主规则 · 多选操作与 RULE-SET 更新")
        rulesView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: rulesView.topAnchor, constant: 48)
        ])

        ruleSearchField.placeholderString = "搜索类型、值、策略或行号"
        ruleSearchField.sendsSearchStringImmediately = true
        ruleSearchField.target = self
        ruleSearchField.action = #selector(ruleSearchChanged)
        ruleSearchField.widthAnchor.constraint(equalToConstant: 250).isActive = true
        ruleCountLabel.font = .systemFont(ofSize: 11, weight: .medium)
        ruleCountLabel.textColor = .secondaryLabelColor

        let actions: [(NSButton, Selector)] = [
            (ruleAddButton, #selector(addRule)),
            (ruleEditButton, #selector(editSelectedRules)),
            (ruleDeleteButton, #selector(deleteSelectedRules)),
            (ruleUpdateButton, #selector(updateRuleSets)),
            (ruleMultiSelectButton, #selector(ruleMultiSelectionChanged)),
            (ruleSelectAllButton, #selector(selectAllRules)),
            (ruleClearSelectionButton, #selector(clearRuleSelection))
        ]
        for (button, action) in actions {
            button.target = self
            button.action = action
            button.controlSize = .small
            button.font = .systemFont(ofSize: 11.5, weight: .medium)
            if button !== ruleMultiSelectButton {
                button.bezelStyle = .rounded
                button.imagePosition = .imageLeading
            }
        }
        ruleAddButton.image = NSImage(systemSymbolName: "plus", accessibilityDescription: nil)
        ruleEditButton.image = NSImage(systemSymbolName: "pencil", accessibilityDescription: nil)
        ruleDeleteButton.image = NSImage(systemSymbolName: "trash", accessibilityDescription: nil)
        ruleUpdateButton.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
        ruleSelectAllButton.image = NSImage(systemSymbolName: "checkmark.circle", accessibilityDescription: nil)
        ruleClearSelectionButton.image = NSImage(systemSymbolName: "xmark.circle", accessibilityDescription: nil)
        ruleMultiSelectButton.toolTip = "显示逐项勾选；也可用 ⌘ / Shift 多选"
        ruleSelectAllButton.toolTip = "只选择当前搜索结果，不包含隐藏规则"
        ruleSelectionCountLabel.font = .systemFont(ofSize: 11, weight: .medium)
        ruleSelectionCountLabel.textColor = HajimiAppearance.accentText

        let toolbar = NSStackView(views: [
            ruleSearchField, ruleCountLabel, NSView(),
            ruleUpdateButton, ruleAddButton, ruleEditButton, ruleDeleteButton
        ])
        toolbar.orientation = .horizontal
        toolbar.alignment = .centerY
        toolbar.spacing = 8
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(toolbar)

        let actionBar = NSStackView(views: [
            ruleMultiSelectButton, ruleSelectAllButton, ruleClearSelectionButton,
            NSView(), ruleSelectionCountLabel
        ])
        actionBar.orientation = .horizontal
        actionBar.alignment = .centerY
        actionBar.spacing = 8
        actionBar.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(actionBar)

        let panel = cardView()
        panel.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(panel)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        configureRulesTable()
        scroll.documentView = rulesTableView
        panel.addSubview(scroll)

        ruleStatusLabel.font = .systemFont(ofSize: 10.5, weight: .medium)
        ruleStatusLabel.textColor = .secondaryLabelColor
        ruleStatusLabel.maximumNumberOfLines = 2
        ruleStatusLabel.lineBreakMode = .byTruncatingTail
        ruleStatusLabel.stringValue = "新增规则默认插入 FINAL / MATCH 之前；更新按钮刷新规则集，编辑可修改本地规则。"
        ruleStatusLabel.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(ruleStatusLabel)

        NSLayoutConstraint.activate([
            toolbar.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 30),
            toolbar.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            toolbar.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 19),
            actionBar.leadingAnchor.constraint(equalTo: toolbar.leadingAnchor),
            actionBar.trailingAnchor.constraint(equalTo: toolbar.trailingAnchor),
            actionBar.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 8),
            panel.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 30),
            panel.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            panel.topAnchor.constraint(equalTo: actionBar.bottomAnchor, constant: 10),
            panel.bottomAnchor.constraint(equalTo: ruleStatusLabel.topAnchor, constant: -9),
            scroll.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 6),
            scroll.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -6),
            scroll.topAnchor.constraint(equalTo: panel.topAnchor, constant: 4),
            scroll.bottomAnchor.constraint(equalTo: panel.bottomAnchor, constant: -6),
            ruleStatusLabel.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 32),
            ruleStatusLabel.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            ruleStatusLabel.bottomAnchor.constraint(equalTo: rulesView.bottomAnchor, constant: -18)
        ])
    }

    private func configureRulesTable() {
        rulesTableView.dataSource = self
        rulesTableView.delegate = self
        rulesTableView.allowsMultipleSelection = true
        rulesTableView.allowsEmptySelection = true
        rulesTableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        rulesTableView.target = self
        rulesTableView.doubleAction = #selector(rulesDoubleClicked)
        rulesTableView.rowHeight = 34
        rulesTableView.backgroundColor = HajimiTheme.panel
        rulesTableView.usesAlternatingRowBackgroundColors = true
        rulesTableView.headerView = NSTableHeaderView()
        let columns: [(String, String, CGFloat)] = [
            ("selected", "选择", 34),
            ("line", "行", 55), ("type", "类型", 125), ("value", "匹配值 / 资源", 380),
            ("policy", "策略", 180), ("loaded", "状态", 120)
        ]
        for item in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(item.0))
            column.title = item.1
            column.width = item.2
            column.minWidth = item.0 == "selected" ? item.2 : item.2 * 0.6
            column.resizingMask = [.autoresizingMask, .userResizingMask]
            column.isHidden = item.0 == "selected"
            rulesTableView.addTableColumn(column)
        }
        let menu = NSMenu(title: "规则操作")
        menu.delegate = self
        menu.autoenablesItems = false
        rulesTableView.menu = menu
        updateRuleSelectionControls()
    }

    private func sectionHeading(_ title: String, detail: String) -> NSStackView {
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 13.5, weight: .semibold)
        let detailLabel = NSTextField(labelWithString: detail)
        detailLabel.font = .systemFont(ofSize: 10.5)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.lineBreakMode = .byTruncatingTail
        let stack = NSStackView(views: [titleLabel, detailLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 2
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }

    private func buildProfileEditor() {
        let header = pageHeader(eyebrow: "PROFILE", title: "配置文件",
                                subtitle: "Surge INI Profile")
        profileView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: profileView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: profileView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: profileView.topAnchor, constant: 48)
        ])

        profilePathLabel.stringValue = configurationStore.profileURL.path
        profilePathLabel.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        profilePathLabel.textColor = .secondaryLabelColor
        profilePathLabel.lineBreakMode = .byTruncatingMiddle

        let reveal = NSButton(title: "在 Finder 中显示", target: self, action: #selector(revealProfile))
        let importSurge = NSButton(title: "导入 Surge 配置", target: self,
                                   action: #selector(importSurgeProfile))
        let addSubscription = NSButton(title: "添加订阅", target: self,
                                       action: #selector(addSubscriptionAction))
        let manageSubscriptions = NSButton(title: "订阅…", target: self,
                                           action: #selector(manageSubscriptionsAction))
        let validate = NSButton(title: "检查配置", target: self, action: #selector(validateProfile))
        let save = NSButton(title: "保存并重载", target: self, action: #selector(saveProfile))
        save.bezelStyle = .rounded
        save.keyEquivalent = "s"
        save.keyEquivalentModifierMask = [.command]
        let toolbar = NSStackView(views: [profilePathLabel, reveal, importSurge,
                                          addSubscription, manageSubscriptions, validate, save])
        toolbar.orientation = .horizontal
        toolbar.alignment = .centerY
        toolbar.spacing = 10
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        profileView.addSubview(toolbar)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        profileTextView.isRichText = false
        profileTextView.isAutomaticQuoteSubstitutionEnabled = false
        profileTextView.isAutomaticDashSubstitutionEnabled = false
        profileTextView.isAutomaticTextReplacementEnabled = false
        profileTextView.isContinuousSpellCheckingEnabled = false
        profileTextView.isGrammarCheckingEnabled = false
        profileTextView.isAutomaticSpellingCorrectionEnabled = false
        profileTextView.layoutManager?.allowsNonContiguousLayout = true
        profileTextView.font = .monospacedSystemFont(ofSize: 12.5, weight: .regular)
        profileTextView.textContainerInset = NSSize(width: 10, height: 10)
        profileTextView.minSize = NSSize(width: 0, height: 0)
        profileTextView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                         height: CGFloat.greatestFiniteMagnitude)
        profileTextView.isVerticallyResizable = true
        profileTextView.isHorizontallyResizable = true
        profileTextView.autoresizingMask = [.width]
        profileTextView.textContainer?.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                                               height: CGFloat.greatestFiniteMagnitude)
        profileTextView.textContainer?.widthTracksTextView = false
        scroll.documentView = profileTextView
        profileView.addSubview(scroll)

        profileStatus.font = .systemFont(ofSize: 11, weight: .medium)
        profileStatus.textColor = .secondaryLabelColor
        profileStatus.translatesAutoresizingMaskIntoConstraints = false
        profileView.addSubview(profileStatus)
        NSLayoutConstraint.activate([
            toolbar.leadingAnchor.constraint(equalTo: profileView.leadingAnchor, constant: 30),
            toolbar.trailingAnchor.constraint(equalTo: profileView.trailingAnchor, constant: -30),
            toolbar.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 20),
            profilePathLabel.widthAnchor.constraint(greaterThanOrEqualToConstant: 240),
            scroll.leadingAnchor.constraint(equalTo: profileView.leadingAnchor, constant: 30),
            scroll.trailingAnchor.constraint(equalTo: profileView.trailingAnchor, constant: -30),
            scroll.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 12),
            scroll.bottomAnchor.constraint(equalTo: profileStatus.topAnchor, constant: -8),
            profileStatus.leadingAnchor.constraint(equalTo: profileView.leadingAnchor, constant: 30),
            profileStatus.bottomAnchor.constraint(equalTo: profileView.bottomAnchor, constant: -20)
        ])
    }

    private func buildAbout() {
        let header = pageHeader(eyebrow: "CAPABILITIES", title: "运行能力",
                                subtitle: "协议能力与系统接管的实际边界")
        aboutView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: aboutView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: aboutView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: aboutView.topAnchor, constant: 48)
        ])
        let items: [(String, String, NSColor)] = [
            ("HTTP / HTTPS 出站", "CONNECT、正向转发、Basic 鉴权；TLS 默认验证证书", HajimiTheme.accent),
            ("SOCKS5 / SOCKS5-TLS", "支持用户名密码与本地 UDP；TLS 上游仅支持 TCP", HajimiTheme.accent),
            ("常见节点协议", "Swift 协议适配；C++ VLESS/Trojan 编码与 Objective-C TCP/TLS", HajimiTheme.accent),
            ("QUIC 与 AnyTLS", "Hysteria v1/v2、TUIC v5、AnyTLS 经静态链接的 Go 核心", .systemBlue),
            ("数据平面", "Objective-C++ 转发；C 报文；C++ 缓冲、重组、计时与规则", .systemIndigo),
            ("macOS 系统代理", "手动启用；恢复前检查代理设置是否仍由哈基米管理", HajimiTheme.accent),
            ("增强模式 VIF", "root Helper 接管 utun；发现其他隧道时拒绝启动与断网自愈", HajimiTheme.accent),
            ("Network Extension", "Objective-C 接入；需签名、entitlement 与原生 Provider 引擎", .systemOrange),
            ("尚未实现", "MITM、Rewrite、WireGuard 与 Gateway VM 需要单独开发", .systemOrange)
        ]
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        for item in items {
            let row = capabilityRow(item.0, detail: item.1, color: item.2)
            stack.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        let scroll = ScrollableSettingsContentView(content: stack)
        scroll.translatesAutoresizingMaskIntoConstraints = false
        aboutView.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: aboutView.leadingAnchor, constant: 22),
            scroll.trailingAnchor.constraint(equalTo: aboutView.trailingAnchor, constant: -22),
            scroll.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 16),
            scroll.bottomAnchor.constraint(equalTo: aboutView.bottomAnchor, constant: -20)
        ])
    }

    private func buildSettings() {
        for child in [settingsOverviewView, dnsSettingsView] {
            child.translatesAutoresizingMaskIntoConstraints = false
            settingsView.addSubview(child)
            NSLayoutConstraint.activate([
                child.leadingAnchor.constraint(equalTo: settingsView.leadingAnchor),
                child.trailingAnchor.constraint(equalTo: settingsView.trailingAnchor),
                child.topAnchor.constraint(equalTo: settingsView.topAnchor),
                child.bottomAnchor.constraint(equalTo: settingsView.bottomAnchor)
            ])
        }

        let header = pageHeader(eyebrow: "SETTINGS", title: "设置",
                                subtitle: "订阅管理、本地代理、Helper 与原生 DNS")
        settingsOverviewView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: settingsOverviewView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: settingsOverviewView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: settingsOverviewView.topAnchor, constant: 48)
        ])

        let subscriptionCard = cardView()
        subscriptionCard.translatesAutoresizingMaskIntoConstraints = false
        let subscriptionIcon = HajimiTheme.iconTile(symbol: "tray.full.fill", color: HajimiTheme.accent,
                                                    size: 38, symbolSize: 17)
        let subscriptionTitle = NSTextField(labelWithString: "订阅管理")
        subscriptionTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        let subscriptionDetail = NSTextField(wrappingLabelWithString:
            "增加订阅（导入本地配置或 URL 下载）、编辑 URL 订阅、删除订阅、更新订阅与选择当前使用的订阅。")
        subscriptionDetail.font = .systemFont(ofSize: 11)
        subscriptionDetail.textColor = .secondaryLabelColor
        subscriptionSummaryLabel.font = .systemFont(ofSize: 11, weight: .medium)
        subscriptionSummaryLabel.textColor = HajimiAppearance.accentText
        subscriptionSummaryLabel.maximumNumberOfLines = 2
        subscriptionSummaryLabel.lineBreakMode = .byTruncatingTail
        subscriptionSelectPopup.target = self
        subscriptionSelectPopup.action = #selector(subscriptionSelectionPopupChanged)
        subscriptionSelectPopup.controlSize = .small
        subscriptionSelectPopup.font = .systemFont(ofSize: 11.5)
        subscriptionSelectPopup.translatesAutoresizingMaskIntoConstraints = false
        subscriptionUseButton.target = self
        subscriptionUseButton.action = #selector(useSelectedSubscriptionAction)
        subscriptionUseButton.image = NSImage(systemSymbolName: "checkmark.circle", accessibilityDescription: nil)
        subscriptionAddButton.target = self
        subscriptionAddButton.action = #selector(addSubscriptionAction)
        subscriptionAddButton.image = NSImage(systemSymbolName: "link.badge.plus", accessibilityDescription: nil)
        subscriptionImportButton.target = self
        subscriptionImportButton.action = #selector(importSubscriptionFileAction)
        subscriptionImportButton.image = NSImage(systemSymbolName: "square.and.arrow.down", accessibilityDescription: nil)
        subscriptionEditButton.target = self
        subscriptionEditButton.action = #selector(editSelectedSubscriptionAction)
        subscriptionEditButton.image = NSImage(systemSymbolName: "slider.horizontal.3", accessibilityDescription: nil)
        subscriptionUpdateButton.target = self
        subscriptionUpdateButton.action = #selector(updateSelectedSubscriptionAction)
        subscriptionUpdateButton.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
        subscriptionDeleteButton.target = self
        subscriptionDeleteButton.action = #selector(deleteSelectedSubscriptionAction)
        subscriptionDeleteButton.image = NSImage(systemSymbolName: "trash", accessibilityDescription: nil)
        subscriptionDeleteButton.contentTintColor = .systemRed
        subscriptionSelectPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        for button in [subscriptionUseButton, subscriptionAddButton, subscriptionImportButton,
                       subscriptionEditButton, subscriptionUpdateButton, subscriptionDeleteButton] {
            button.bezelStyle = .rounded
            button.controlSize = .small
            button.font = .systemFont(ofSize: 11.5, weight: .medium)
            button.imagePosition = .imageLeading
            button.setContentHuggingPriority(.required, for: .horizontal)
            button.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
        }
        let subscriptionSpacer = NSView()
        subscriptionSpacer.setContentHuggingPriority(.init(1), for: .horizontal)
        subscriptionSpacer.setContentCompressionResistancePriority(.init(1), for: .horizontal)
        let subscriptionControls = NSStackView(views: [
            subscriptionSelectPopup, subscriptionUseButton, subscriptionSpacer,
            subscriptionImportButton, subscriptionAddButton,
            subscriptionEditButton, subscriptionUpdateButton, subscriptionDeleteButton
        ])
        subscriptionControls.orientation = .horizontal
        subscriptionControls.alignment = .centerY
        subscriptionControls.spacing = 4
        subscriptionControls.translatesAutoresizingMaskIntoConstraints = false
        let subscriptionStack = NSStackView(views: [
            subscriptionTitle, subscriptionDetail, subscriptionSummaryLabel, subscriptionControls
        ])
        subscriptionStack.orientation = .vertical
        subscriptionStack.alignment = .leading
        subscriptionStack.spacing = 7
        subscriptionStack.translatesAutoresizingMaskIntoConstraints = false
        subscriptionCard.addSubview(subscriptionIcon)
        subscriptionCard.addSubview(subscriptionStack)

        let localProxyCard = cardView()
        localProxyCard.translatesAutoresizingMaskIntoConstraints = false
        let localProxyIcon = HajimiTheme.iconTile(symbol: "network", color: .systemBlue,
                                                  size: 38, symbolSize: 17)
        let localProxyTitle = NSTextField(labelWithString: "本地代理")
        localProxyTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        let localProxyDetail = NSTextField(wrappingLabelWithString:
            "HTTP 与 SOCKS5 入口一起启停，供系统代理和其他客户端使用。增强模式可独立运行。")
        localProxyDetail.font = .systemFont(ofSize: 11)
        localProxyDetail.textColor = .secondaryLabelColor
        localProxyStatusLabel.font = .systemFont(ofSize: 11, weight: .medium)
        localProxyStatusLabel.textColor = .secondaryLabelColor
        localProxyStatusLabel.maximumNumberOfLines = 2
        localProxyStatusLabel.lineBreakMode = .byTruncatingTail
        let localProxyText = NSStackView(views: [localProxyTitle, localProxyDetail, localProxyStatusLabel])
        localProxyText.orientation = .vertical
        localProxyText.alignment = .leading
        localProxyText.spacing = 6
        localProxyText.translatesAutoresizingMaskIntoConstraints = false
        startButton.target = self
        startButton.action = #selector(toggleLocalProxyFromSettings)
        startButton.bezelStyle = .rounded
        startButton.setContentHuggingPriority(.required, for: .horizontal)
        startButton.setContentCompressionResistancePriority(.required, for: .horizontal)
        startButton.toolTip = "HTTP / SOCKS5 本地入口一起启停；关闭前会先恢复系统代理。"
        startButton.translatesAutoresizingMaskIntoConstraints = false
        localProxyCard.addSubview(localProxyIcon)
        localProxyCard.addSubview(localProxyText)
        localProxyCard.addSubview(startButton)

        let helperCard = cardView()
        helperCard.translatesAutoresizingMaskIntoConstraints = false
        let helperIcon = HajimiTheme.iconTile(symbol: "shield.lefthalf.filled", color: HajimiTheme.accent,
                                              size: 38, symbolSize: 17)
        let helperTitle = NSTextField(labelWithString: "增强模式 Helper")
        helperTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        let helperDetail = NSTextField(wrappingLabelWithString:
            "增强模式需要 Helper 接管本机应用流量。首次使用请安装，并在系统提示时授权。")
        helperDetail.font = .systemFont(ofSize: 11)
        helperDetail.textColor = .secondaryLabelColor
        helperStatusLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
        helperStatusLabel.textColor = .secondaryLabelColor
        helperInstallButton.target = self
        helperInstallButton.action = #selector(installHelperFromSettings)
        helperInstallButton.bezelStyle = .rounded
        helperUninstallButton.target = self
        helperUninstallButton.action = #selector(uninstallHelperFromSettings)
        helperUninstallButton.bezelStyle = .rounded
        helperUninstallButton.contentTintColor = .systemRed
        let helperButtons = NSStackView(views: [helperInstallButton, helperUninstallButton])
        helperButtons.orientation = .horizontal
        helperButtons.spacing = 8
        helperButtons.setHuggingPriority(.required, for: .horizontal)
        helperButtons.setContentCompressionResistancePriority(.required, for: .horizontal)
        for button in [helperInstallButton, helperUninstallButton] {
            button.setContentHuggingPriority(.required, for: .horizontal)
            button.setContentCompressionResistancePriority(.required, for: .horizontal)
        }
        let helperText = NSStackView(views: [helperTitle, helperDetail, helperStatusLabel])
        helperText.orientation = .vertical
        helperText.alignment = .leading
        helperText.spacing = 6
        helperText.translatesAutoresizingMaskIntoConstraints = false
        helperButtons.translatesAutoresizingMaskIntoConstraints = false
        helperCard.addSubview(helperIcon)
        helperCard.addSubview(helperText)
        helperCard.addSubview(helperButtons)

        let dnsCard = cardView()
        dnsCard.translatesAutoresizingMaskIntoConstraints = false
        let dnsIcon = HajimiTheme.iconTile(symbol: "lock.shield", color: .systemIndigo,
                                           size: 38, symbolSize: 17)
        let dnsTitle = NSTextField(labelWithString: "DNS")
        dnsTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        dnsSummaryLabel.font = .systemFont(ofSize: 11)
        dnsSummaryLabel.textColor = .secondaryLabelColor
        dnsSummaryLabel.lineBreakMode = .byTruncatingMiddle
        let dnsText = NSStackView(views: [dnsTitle, dnsSummaryLabel])
        dnsText.orientation = .vertical
        dnsText.alignment = .leading
        dnsText.spacing = 5
        dnsText.translatesAutoresizingMaskIntoConstraints = false
        let openDNS = NSButton(title: "DNS 设置…", target: self, action: #selector(openDNSSettings))
        openDNS.bezelStyle = .rounded
        openDNS.setContentHuggingPriority(.required, for: .horizontal)
        openDNS.setContentCompressionResistancePriority(.required, for: .horizontal)
        openDNS.translatesAutoresizingMaskIntoConstraints = false
        dnsCard.addSubview(dnsIcon)
        dnsCard.addSubview(dnsText)
        dnsCard.addSubview(openDNS)

        NSLayoutConstraint.activate([
            subscriptionCard.heightAnchor.constraint(equalToConstant: 158),
            subscriptionIcon.leadingAnchor.constraint(equalTo: subscriptionCard.leadingAnchor, constant: 18),
            subscriptionIcon.topAnchor.constraint(equalTo: subscriptionCard.topAnchor, constant: 20),
            subscriptionStack.leadingAnchor.constraint(equalTo: subscriptionIcon.trailingAnchor, constant: 14),
            subscriptionStack.trailingAnchor.constraint(equalTo: subscriptionCard.trailingAnchor, constant: -20),
            subscriptionStack.centerYAnchor.constraint(equalTo: subscriptionCard.centerYAnchor),
            subscriptionDetail.widthAnchor.constraint(equalTo: subscriptionStack.widthAnchor),
            subscriptionSummaryLabel.widthAnchor.constraint(equalTo: subscriptionStack.widthAnchor),
            subscriptionControls.widthAnchor.constraint(equalTo: subscriptionStack.widthAnchor),
            {
                let c = subscriptionSelectPopup.widthAnchor.constraint(greaterThanOrEqualToConstant: 80)
                c.priority = .defaultHigh
                return c
            }(),
            subscriptionSelectPopup.widthAnchor.constraint(lessThanOrEqualToConstant: 210),
            localProxyCard.heightAnchor.constraint(equalToConstant: 126),
            localProxyIcon.leadingAnchor.constraint(equalTo: localProxyCard.leadingAnchor, constant: 18),
            localProxyIcon.centerYAnchor.constraint(equalTo: localProxyCard.centerYAnchor),
            localProxyText.leadingAnchor.constraint(equalTo: localProxyIcon.trailingAnchor, constant: 14),
            localProxyText.trailingAnchor.constraint(equalTo: startButton.leadingAnchor, constant: -18),
            localProxyText.centerYAnchor.constraint(equalTo: localProxyCard.centerYAnchor),
            localProxyDetail.widthAnchor.constraint(equalTo: localProxyText.widthAnchor),
            localProxyStatusLabel.widthAnchor.constraint(equalTo: localProxyText.widthAnchor),
            startButton.trailingAnchor.constraint(equalTo: localProxyCard.trailingAnchor, constant: -20),
            startButton.centerYAnchor.constraint(equalTo: localProxyCard.centerYAnchor),
            helperCard.heightAnchor.constraint(equalToConstant: 146),
            helperIcon.leadingAnchor.constraint(equalTo: helperCard.leadingAnchor, constant: 18),
            helperIcon.centerYAnchor.constraint(equalTo: helperCard.centerYAnchor),
            helperText.leadingAnchor.constraint(equalTo: helperIcon.trailingAnchor, constant: 14),
            helperText.trailingAnchor.constraint(equalTo: helperButtons.leadingAnchor, constant: -18),
            helperText.centerYAnchor.constraint(equalTo: helperCard.centerYAnchor),
            helperButtons.trailingAnchor.constraint(equalTo: helperCard.trailingAnchor, constant: -20),
            helperButtons.centerYAnchor.constraint(equalTo: helperCard.centerYAnchor),
            helperDetail.widthAnchor.constraint(equalTo: helperText.widthAnchor),
            dnsCard.heightAnchor.constraint(equalToConstant: 100),
            dnsIcon.leadingAnchor.constraint(equalTo: dnsCard.leadingAnchor, constant: 18),
            dnsIcon.centerYAnchor.constraint(equalTo: dnsCard.centerYAnchor),
            dnsText.leadingAnchor.constraint(equalTo: dnsIcon.trailingAnchor, constant: 14),
            dnsText.centerYAnchor.constraint(equalTo: dnsCard.centerYAnchor),
            dnsText.trailingAnchor.constraint(equalTo: openDNS.leadingAnchor, constant: -20),
            dnsSummaryLabel.widthAnchor.constraint(equalTo: dnsText.widthAnchor),
            openDNS.trailingAnchor.constraint(equalTo: dnsCard.trailingAnchor, constant: -20),
            openDNS.centerYAnchor.constraint(equalTo: dnsCard.centerYAnchor)
        ])

        let extensionCard = cardView()
        extensionCard.translatesAutoresizingMaskIntoConstraints = false
        let extensionIcon = HajimiTheme.iconTile(symbol: "puzzlepiece.extension", color: .systemOrange,
                                                 size: 38, symbolSize: 17)
        let extensionTitle = NSTextField(labelWithString: "系统扩展")
        extensionTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        let extensionDetail = NSTextField(wrappingLabelWithString:
            "检查当前应用是否满足系统扩展的启用条件。此操作只检查，不会启用 VPN。")
        extensionDetail.font = .systemFont(ofSize: 11)
        extensionDetail.textColor = .secondaryLabelColor
        let extensionText = NSStackView(views: [extensionTitle, extensionDetail])
        extensionText.orientation = .vertical
        extensionText.alignment = .leading
        extensionText.spacing = 6
        extensionText.translatesAutoresizingMaskIntoConstraints = false
        let extensionCheck = NSButton(title: "检查接入条件…", target: self, action: #selector(checkNetworkExtension))
        extensionCheck.bezelStyle = .rounded
        extensionCheck.setContentHuggingPriority(.required, for: .horizontal)
        extensionCheck.setContentCompressionResistancePriority(.required, for: .horizontal)
        extensionCheck.translatesAutoresizingMaskIntoConstraints = false
        extensionCard.addSubview(extensionIcon)
        extensionCard.addSubview(extensionText)
        extensionCard.addSubview(extensionCheck)
        NSLayoutConstraint.activate([
            extensionCard.heightAnchor.constraint(equalToConstant: 100),
            extensionIcon.leadingAnchor.constraint(equalTo: extensionCard.leadingAnchor, constant: 18),
            extensionIcon.centerYAnchor.constraint(equalTo: extensionCard.centerYAnchor),
            extensionText.leadingAnchor.constraint(equalTo: extensionIcon.trailingAnchor, constant: 14),
            extensionText.centerYAnchor.constraint(equalTo: extensionCard.centerYAnchor),
            extensionText.trailingAnchor.constraint(equalTo: extensionCheck.leadingAnchor, constant: -20),
            extensionDetail.widthAnchor.constraint(equalTo: extensionText.widthAnchor),
            extensionCheck.trailingAnchor.constraint(equalTo: extensionCard.trailingAnchor, constant: -20),
            extensionCheck.centerYAnchor.constraint(equalTo: extensionCard.centerYAnchor)
        ])

        let overviewCards = NSStackView(views: [subscriptionCard, localProxyCard, helperCard, dnsCard, extensionCard])
        overviewCards.orientation = .vertical
        overviewCards.alignment = .leading
        overviewCards.spacing = 14
        for card in [subscriptionCard, localProxyCard, helperCard, dnsCard, extensionCard] {
            card.widthAnchor.constraint(equalTo: overviewCards.widthAnchor).isActive = true
        }
        let overviewScroll = ScrollableSettingsContentView(content: overviewCards)
        overviewScroll.translatesAutoresizingMaskIntoConstraints = false
        settingsOverviewView.addSubview(overviewScroll)
        NSLayoutConstraint.activate([
            overviewScroll.leadingAnchor.constraint(equalTo: settingsOverviewView.leadingAnchor, constant: 22),
            overviewScroll.trailingAnchor.constraint(equalTo: settingsOverviewView.trailingAnchor, constant: -22),
            overviewScroll.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 16),
            overviewScroll.bottomAnchor.constraint(equalTo: settingsOverviewView.bottomAnchor, constant: -20)
        ])
        refreshLocalProxySettings()

        let back = NSButton(title: "返回设置", target: self, action: #selector(closeDNSSettings))
        back.image = NSImage(systemSymbolName: "chevron.left", accessibilityDescription: nil)
        back.imagePosition = .imageLeading
        back.bezelStyle = .recessed
        back.isBordered = false
        back.translatesAutoresizingMaskIntoConstraints = false
        dnsSettingsView.addSubview(back)
        let dnsHeader = pageHeader(eyebrow: "DNS", title: "DNS 设置",
                                   subtitle: "加密 DNS 与传统 DNS 独立配置")
        dnsSettingsView.addSubview(dnsHeader)

        let dnsEditorCard = cardView()
        dnsEditorCard.translatesAutoresizingMaskIntoConstraints = false
        dnsForm.translatesAutoresizingMaskIntoConstraints = false
        dnsForm.protectionButton.target = self
        dnsForm.protectionButton.action = #selector(dnsProtectionChanged)
        dnsForm.connectivityButton.target = self
        dnsForm.connectivityButton.action = #selector(testTraditionalDNSConnectivity)
        dnsForm.proxyFallbackButton.target = self
        dnsForm.proxyFallbackButton.action = #selector(dnsProxyFallbackChanged)
        dnsForm.onBehaviorChange = { [weak self] in
            guard let self else { return }
            let draft = self.dnsForm.draft
            self.dnsSettingsStatus.stringValue = draft.selectionMode == .mixedSpeed
                ? "保存后授权批准列表内普通 DNS 经加密代理参与择优；代理出口仍可能明文"
                : "DNS 模式与后台预热有未保存修改；点击保存并应用生效"
            self.dnsSettingsStatus.textColor = draft.selectionMode == .mixedSpeed ? .systemOrange : .secondaryLabelColor
        }
        dnsEditorCard.addSubview(dnsForm)
        dnsSettingsStatus.font = .systemFont(ofSize: 11, weight: .medium)
        dnsSettingsStatus.textColor = .secondaryLabelColor
        dnsSettingsStatus.lineBreakMode = .byTruncatingTail
        dnsSettingsStatus.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let saveDNS = NSButton(title: "保存并应用", target: self, action: #selector(saveDNSSettings))
        saveDNS.keyEquivalent = "\r"
        saveDNS.controlSize = .large
        let dnsActions = NSStackView(views: [dnsSettingsStatus, NSView(), saveDNS])
        dnsActions.orientation = .horizontal
        dnsActions.alignment = .centerY
        dnsActions.translatesAutoresizingMaskIntoConstraints = false
        let dnsBody = NSStackView(views: [dnsEditorCard, dnsActions])
        dnsBody.orientation = .vertical
        dnsBody.alignment = .leading
        dnsBody.spacing = 14
        let dnsScroll = ScrollableSettingsContentView(content: dnsBody)
        dnsScroll.translatesAutoresizingMaskIntoConstraints = false
        dnsSettingsView.addSubview(dnsScroll)
        NSLayoutConstraint.activate([
            back.leadingAnchor.constraint(equalTo: dnsSettingsView.leadingAnchor, constant: 28),
            back.topAnchor.constraint(equalTo: dnsSettingsView.topAnchor, constant: 26),
            dnsHeader.leadingAnchor.constraint(equalTo: dnsSettingsView.leadingAnchor, constant: 30),
            dnsHeader.trailingAnchor.constraint(equalTo: dnsSettingsView.trailingAnchor, constant: -30),
            dnsHeader.topAnchor.constraint(equalTo: back.bottomAnchor, constant: 13),
            dnsScroll.leadingAnchor.constraint(equalTo: dnsSettingsView.leadingAnchor, constant: 30),
            dnsScroll.trailingAnchor.constraint(equalTo: dnsSettingsView.trailingAnchor, constant: -30),
            dnsScroll.topAnchor.constraint(equalTo: dnsHeader.bottomAnchor, constant: 22),
            dnsScroll.bottomAnchor.constraint(equalTo: dnsSettingsView.bottomAnchor, constant: -20),
            dnsEditorCard.widthAnchor.constraint(equalTo: dnsBody.widthAnchor),
            dnsForm.leadingAnchor.constraint(equalTo: dnsEditorCard.leadingAnchor, constant: 20),
            dnsForm.trailingAnchor.constraint(equalTo: dnsEditorCard.trailingAnchor, constant: -20),
            dnsForm.topAnchor.constraint(equalTo: dnsEditorCard.topAnchor, constant: 18),
            dnsForm.bottomAnchor.constraint(equalTo: dnsEditorCard.bottomAnchor, constant: -20),
            dnsActions.widthAnchor.constraint(equalTo: dnsBody.widthAnchor)
        ])
        dnsSettingsView.isHidden = true
        refreshDNSSettingsFields()
    }

    private func refreshSettings() {
        refreshSubscriptionSettings()
        refreshLocalProxySettings()
        refreshDNSSettingsFields()
        helperStatusLabel.stringValue = "正在检查…"
        helperStatusLabel.textColor = .secondaryLabelColor
        helperInstallButton.isEnabled = false
        helperUninstallButton.isEnabled = false
        helperClient.installationStatus { [weak self] status in
            guard let self else { return }
            self.helperInstallationStatus = status
            self.helperStatusLabel.stringValue = status.displayText
            switch status {
            case .notInstalled:
                self.helperStatusLabel.textColor = .secondaryLabelColor
                self.helperInstallButton.title = "安装 Helper"
                self.helperInstallButton.isEnabled = true
                self.helperUninstallButton.isEnabled = false
            case .needsUpdate:
                self.helperStatusLabel.textColor = .systemOrange
                self.helperInstallButton.title = "更新 Helper"
                self.helperInstallButton.isEnabled = true
                self.helperUninstallButton.isEnabled = true
            case .installed:
                self.helperStatusLabel.textColor = .systemGreen
                self.helperInstallButton.title = "重新安装"
                self.helperInstallButton.isEnabled = true
                self.helperUninstallButton.isEnabled = true
            }
        }
    }

    private func refreshLocalProxySettings() {
        if let ticket = listenerTicket, isCurrentListener(ticket) {
            localProxyStatusLabel.stringValue = "已开启 · HTTP \(engine.activeHTTPListen.host):\(engine.activeHTTPListen.port)"
                + " · SOCKS5 \(engine.activeSOCKSListen.host):\(engine.activeSOCKSListen.port)"
            localProxyStatusLabel.textColor = .systemGreen
        } else if isEngineActive {
            localProxyStatusLabel.stringValue = "正在准备本地代理，监听就绪后可设置系统代理。"
            localProxyStatusLabel.textColor = .systemOrange
        } else if case .failed(let message) = engineStatus {
            localProxyStatusLabel.stringValue = "启动失败：\(message)"
            localProxyStatusLabel.textColor = .systemRed
        } else {
            localProxyStatusLabel.stringValue = "尚未开启 · 使用系统代理前请先开启本地代理。"
            localProxyStatusLabel.textColor = .secondaryLabelColor
        }
        localProxyStatusLabel.toolTip = localProxyStatusLabel.stringValue
    }

    @objc private func toggleLocalProxyFromSettings() {
        toggleEngine()
        refreshLocalProxySettings()
    }

    private func refreshDNSSettingsFields() {
        // Navigation can happen while a DNS Save is preparing remote rules.
        // Do not replace its draft with the old profile until that request
        // finishes; only an actual user edit should change the displayed text.
        guard dnsSaveRequestID == nil else { return }
        let encrypted = profile.effectiveEncryptedDNSServers
        let traditional = profile.traditionalDNSServers
        let resolverSummary: String
        if !encrypted.isEmpty {
            let encryptedSummary = profile.configuredEncryptedDNSServers.isEmpty
                ? "默认加密 DNS" : "加密 DNS \(encrypted.count) 个"
            resolverSummary = encryptedSummary + " · 传统 DNS \(traditional.count) 个（仅引导 / 测试）"
        } else {
            resolverSummary = traditional.isEmpty ? "系统 DNS（兼容模式）" : "传统 DNS \(traditional.count) 个（兼容模式）"
        }
        let modeTitle: String
        switch profile.dnsSelectionMode {
        case .encryptedOnly: modeTitle = "仅用加密"
        case .balanced: modeTitle = "稳定均衡"
        case .mixedSpeed: modeTitle = "速度优先"
        }
        dnsSummaryLabel.stringValue = modeTitle + " · "
            + (profile.dnsPrewarmEnabled ? "后台预热 · " : "预热关闭 · ")
            + (profile.dnsLeakProtectionEnabled ? "保护开启 · " : "⚠︎ 保护关闭 · ") + resolverSummary
        if profile.dnsSelectionMode == .mixedSpeed {
            dnsSummaryLabel.stringValue += " · 普通 DNS \(profile.dnsProxyFallbackServers.count) 个（代理内日常择优）"
        } else if profile.dnsSelectionMode == .balanced && !profile.effectiveEncryptedDNSServers.isEmpty {
            dnsSummaryLabel.stringValue += profile.dnsProxyFallbackEnabled ? " · 代理内普通后备开启" : " · 普通后备关闭"
        }
        dnsSummaryLabel.toolTip = dnsSummaryLabel.stringValue
        dnsSummaryLabel.textColor = profile.dnsLeakProtectionEnabled && profile.dnsSelectionMode != .mixedSpeed
            ? .secondaryLabelColor : .systemOrange
        cancelDNSConnectivityTest()
        dnsForm.load(DNSSettingsDraft(profile: profile))
        dnsSettingsStatus.stringValue = ""
    }

    @objc private func installHelperFromSettings() {
        helperInstallButton.isEnabled = false
        helperUninstallButton.isEnabled = false
        helperStatusLabel.stringValue = "正在请求管理员授权并安装…"
        helperStatusLabel.textColor = .systemBlue
        helperClient.installOrUpdate { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                self.helperStatusLabel.stringValue = "Helper 安装完成"
                self.helperStatusLabel.textColor = .systemGreen
                self.refreshSettings()
            case .failure(let error):
                self.helperInstallButton.isEnabled = true
                self.helperUninstallButton.isEnabled = self.helperInstallationStatus != .notInstalled
                self.helperStatusLabel.stringValue = "安装失败"
                self.helperStatusLabel.textColor = .systemRed
                self.showError(title: "无法安装 Helper", error: error)
            }
        }
    }

    @objc private func uninstallHelperFromSettings() {
        let alert = NSAlert()
        alert.messageText = "卸载增强模式 Helper？"
        alert.informativeText = "哈基米会先关闭增强模式并撤销 utun 路由，然后移除 root Helper。"
        alert.addButton(withTitle: "卸载")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        cancelLaunchRestorePreparation()
        if let ticket = enhancedRequestIntent.cancel() { enhancedRequestIntent.release(ticket) }
        persistEnhancedMode(false)
        helperInstallButton.isEnabled = false
        helperUninstallButton.isEnabled = false
        helperStatusLabel.stringValue = "正在停止增强模式…"
        let uninstall: () -> Void = { [weak self] in
            guard let self else { return }
            self.helperStatusLabel.stringValue = "正在卸载…"
            self.helperClient.uninstall { [weak self] result in
                guard let self else { return }
                switch result {
                case .success:
                    self.helperStatusLabel.stringValue = "Helper 已卸载"
                    self.helperStatusLabel.textColor = .secondaryLabelColor
                    self.refreshSettings()
                case .failure(let error):
                    self.refreshSettings()
                    self.showError(title: "无法卸载 Helper", error: error)
                }
            }
        }
        if isEnhancedModeActive || enhancedMode.isEnabled {
            enhancedModeButton.isEnabled = false
            enhancedMode.stop(engine: engine) { [weak self] result in
                guard let self else { return }
                self.enhancedModeButton.isEnabled = true
                switch result {
                case .success:
                    self.enhancedModeButton.state = .off
                    self.persistEnhancedMode(false)
                    uninstall()
                case .failure(let error):
                    self.refreshSettings()
                    self.showError(title: "无法先关闭增强模式", error: error)
                }
            }
        } else {
            uninstall()
        }
    }

    @objc private func openDNSSettings() {
        refreshDNSSettingsFields()
        settingsOverviewView.isHidden = true
        dnsSettingsView.isHidden = false
    }

    @objc private func closeDNSSettings() {
        cancelDNSConnectivityTest()
        dnsSettingsView.isHidden = true
        settingsOverviewView.isHidden = false
        refreshDNSSettingsFields()
    }

    @objc private func dnsProtectionChanged() {
        let enabled = dnsForm.protectionButton.state == .on
        dnsSettingsStatus.stringValue = enabled
            ? "保存后启用保护；增强模式将接管系统 DNS"
            : "⚠︎ 保存后关闭保护，可能使用系统或明文 DNS"
        dnsSettingsStatus.textColor = enabled ? .secondaryLabelColor : .systemOrange
    }

    @objc private func dnsProxyFallbackChanged() {
        let enabled = dnsForm.proxyFallbackButton.state == .on
        dnsSettingsStatus.stringValue = enabled
            ? "保存后仅经合格加密代理回退；节点可见域名，出口仍明文"
            : "保存后关闭普通 DNS 后备；独立批准列表保留"
        dnsSettingsStatus.textColor = enabled ? .systemOrange : .secondaryLabelColor
    }

    @objc private func saveDNSSettings() {
        cancelDNSConnectivityTest()
        do {
            let submittedDraft = dnsForm.draft
            try validateDNSSettings(submittedDraft)
            let text = try submittedDraft.applying(to: profileTextView.string)
            let requestID = UUID()
            dnsSaveRequestID = requestID
            dnsSettingsStatus.stringValue = "正在后台准备 DNS 规则集…"
            dnsSettingsStatus.textColor = .systemBlue
            // Pressing Save commits this snapshot even if the user navigates
            // away. Later edits in this panel remain an unsaved draft instead
            // of being erased by the old asynchronous result.
            applyProfileTextInBackground(text, prefix: "DNS 已保存并应用",
                                         completion: { [weak self] result in
                guard let self, self.dnsSaveRequestID == requestID else { return }
                self.dnsSaveRequestID = nil
                switch result {
                case .success:
                    let draftUnchanged = self.dnsForm.draft == submittedDraft
                    if self.dnsSettingsView.isHidden || draftUnchanged {
                        self.refreshDNSSettingsFields()
                    }
                    self.dnsSettingsStatus.stringValue = draftUnchanged || self.dnsSettingsView.isHidden
                        ? "✓ DNS 已保存并应用"
                        : "✓ 先前设置已保存；当前输入还有未保存的修改"
                    self.dnsSettingsStatus.textColor = .systemGreen
                    self.dnsSettingsStatus.toolTip = nil
                case .failure(let error):
                    self.dnsSettingsStatus.stringValue = "✕ \(error.localizedDescription)"
                    self.dnsSettingsStatus.textColor = .systemRed
                    self.dnsSettingsStatus.toolTip = error.localizedDescription
                    if self.dnsSettingsView.isHidden {
                        self.showError(title: "DNS 保存失败", error: error)
                    }
                }
            })
        } catch {
            dnsSettingsStatus.stringValue = "✕ \(error.localizedDescription)"
            dnsSettingsStatus.textColor = .systemRed
            dnsSettingsStatus.toolTip = error.localizedDescription
        }
    }

    private func validateDNSSettings(_ draft: DNSSettingsDraft) throws {
        let traditional = draft.traditionalServers
        guard traditional.count <= 8, draft.encryptedServers.count <= 8 else {
            throw ProfileApplyError.message("每类 DNS 最多配置 8 个服务器")
        }
        if let invalid = traditional.first(where: { TraditionalDNSServer($0) == nil }) {
            throw ProfileApplyError.message("传统 DNS 地址无效：\(invalid)。请填写 IP 或 IP:端口，例如 223.5.5.5、[2606:4700:4700::1111]:53；DoH / DoT 请填入加密 DNS 栏。")
        }
        for raw in draft.encryptedServers {
            if raw.lowercased().hasPrefix("https://"),
               let endpoint = DoHEndpoint(raw, allowUnresolvedHost: true) {
                if endpoint.needsBootstrap && traditional.isEmpty {
                    throw ProfileApplyError.message("DoH 域名 \(endpoint.host) 需要传统 DNS 引导，或在 URL 后附 #IP 指定引导地址")
                }
            } else if raw.lowercased().hasPrefix("tls://"), DoTEndpoint(raw) != nil {
                continue
            } else {
                throw ProfileApplyError.message("加密 DNS 地址无效：\(raw)。DoH 格式为 https://域名/dns-query；DoT 格式为 tls://域名#IP。传统 DNS IP 请填入下栏。")
            }
        }
    }

    private func cancelDNSConnectivityTest() {
        dnsConnectivityRequestID = nil
        dnsConnectivityResolver?.cancel()
        dnsConnectivityResolver = nil
        dnsForm.connectivityButton.isEnabled = true
    }

    @objc private func testTraditionalDNSConnectivity() {
        cancelDNSConnectivityTest()
        let draft = dnsForm.draft
        let servers = draft.traditionalServers
        guard !servers.isEmpty, servers.count <= 8,
              servers.allSatisfy({ TraditionalDNSServer($0) != nil }) else {
            dnsSettingsStatus.stringValue = "✕ 请在传统 DNS 栏填写 1–8 个有效 IP 地址后测试"
            dnsSettingsStatus.textColor = .systemRed
            return
        }
        let requestID = UUID()
        let started = Date.timeIntervalSinceReferenceDate
        let resolver = TraditionalDNSBootstrapResolver(servers: servers, allowedDoHHosts: [])
        dnsConnectivityRequestID = requestID
        dnsConnectivityResolver = resolver
        dnsForm.connectivityButton.isEnabled = false
        dnsSettingsStatus.stringValue = "正在用传统 DNS 查询固定连通性测试域名…"
        dnsSettingsStatus.textColor = .systemBlue
        dnsSettingsStatus.toolTip = nil
        resolver.testConnectivity(queue: .main) { [weak self] result in
            guard let self, self.dnsConnectivityRequestID == requestID else { return }
            self.cancelDNSConnectivityTest()
            let changed = self.dnsForm.draft.traditionalText != draft.traditionalText
            switch result {
            case .success:
                let elapsed = Int((Date.timeIntervalSinceReferenceDate - started) * 1_000)
                self.dnsSettingsStatus.stringValue = "✓ 传统 DNS 可达（\(elapsed) ms）；未测试加密 DNS"
                    + (changed ? "；当前输入已有修改" : "")
                self.dnsSettingsStatus.textColor = .systemGreen
                self.dnsSettingsStatus.toolTip = "固定测试域名：captive.apple.com。本测试不保存配置，不代表 HTTPS 或代理连通性。"
            case .failure(let error):
                self.dnsSettingsStatus.stringValue = "✕ 传统 DNS 测试失败：\(error.localizedDescription)"
                self.dnsSettingsStatus.textColor = .systemRed
                self.dnsSettingsStatus.toolTip = error.localizedDescription
            }
        }
    }

    private func bindEngine() {
        engine.onStatus = { [weak self] status in
            guard let self else { return }
            let sessionID = self.listenerLifecycle.snapshot.sessionID
            DispatchQueue.main.async { [weak self] in
                guard let self, self.acceptListenerStatus(status, sessionID: sessionID) else { return }
                self.apply(status: status)
            }
        }
        engine.onEvent = nil
        engine.onEventBatch = { [weak self] events in
            let relevant = events.filter { event in
                if case .message = event { return false }
                return true
            }
            guard !relevant.isEmpty else { return }
            DispatchQueue.main.async {
                guard let self else { return }
                for event in relevant { self.apply(event: event) }
            }
        }
        protocolAdapters.onUnexpectedExit = { [weak self] message in
            guard let self else { return }
            self.stopProxyEngine()
            self.showMessage(title: "高级协议适配器已退出", text: message)
        }
        enhancedMode.onStatus = { [weak self] status in self?.apply(enhancedStatus: status) }
        enhancedMode.onStatistics = { [weak self] active, total, up, down in
            guard let self else { return }
            self.enhancedActiveConnections = active
            self.enhancedTotalConnections = total
            self.enhancedUploaded = up
            self.enhancedDownloaded = down
            let now = ProcessInfo.processInfo.systemUptime
            self.enhancedUploadRate.observe(up, at: now)
            self.enhancedDownloadRate.observe(down, at: now)
            self.scheduleStatisticsUpdate()
        }
    }

    private func probeCaptivePortalIfNeeded() {
        guard isEnhancedModeActive || isEngineActive else { return }
        CaptivePortalDetector.shared.checkPhysicalLink { [weak self] outcome in
            guard let self else { return }
            if case .portalRequired(let loginURL) = outcome {
                let opened = CaptivePortalDetector.shared.openPortalIfNeeded(loginURL)
                let tip = opened
                    ? "检测到当前 Wi-Fi 需网页认证（Captive Portal），已自动打开认证页：\(loginURL.host ?? loginURL.absoluteString)"
                    : "检测到当前 Wi-Fi 需网页认证（Captive Portal）：\(loginURL.host ?? loginURL.absoluteString)"
                self.sidebarStatusDetail.stringValue = tip
                self.dataPlaneRuntimeValue.stringValue = "等待 Wi-Fi 网页认证完成"
            }
        }
    }

    private func apply(enhancedStatus status: EnhancedModeManager.Status) {
        networkRuntime.observe(enhancedStatus: status)
        switch status {
        case .stopped:
            enhancedModeButton.state = enhancedMode.isRequested ? .on : .off
            enhancedModeButton.isEnabled = true
            dataPlaneRuntimeValue.stringValue = enhancedMode.isRequested ? "增强模式等待网络恢复" : "HajimiNativeCore"
            enhancedActiveConnections = 0
        case .starting, .stopping:
            enhancedModeButton.isEnabled = false
        case .waitingForNetwork(let message):
            enhancedModeButton.state = enhancedMode.isRequested ? .on : .off
            enhancedModeButton.isEnabled = true
            dataPlaneRuntimeValue.stringValue = message
            enhancedActiveConnections = 0
        case .running(let interface, _):
            enhancedModeButton.state = .on
            enhancedModeButton.isEnabled = true
            dataPlaneRuntimeValue.stringValue = "Native · \(interface)"
            refreshRuleSetsAutomatically()
        case .failed(let message):
            enhancedModeButton.state = isEnhancedModeActive ? .on : .off
            enhancedModeButton.isEnabled = true
            dataPlaneRuntimeValue.stringValue = message
        }
        refreshConnectionStatus()
    }

    private func restorePreferences() {
        let savedMode = UserDefaults.standard.string(forKey: "outboundMode")
        let mode = OutboundMode(rawValue: savedMode ?? "rule") ?? .rule
        if let saved = UserDefaults.standard.dictionary(forKey: "groupSelections") {
            groupSelections = saved.reduce(into: [:]) { result, item in
                if let value = item.value as? String { result[item.key] = value }
            }
        }
        modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: mode) ?? 0)
        refreshPolicies(preferred: UserDefaults.standard.string(forKey: "globalPolicy"))
        refreshGroups(preferred: UserDefaults.standard.string(forKey: "selectedPolicyGroup"))
        refreshPolicyPage()
        refreshRulesPage()
        updateEngineRouting()
        updateOverviewDetails()
        syncDashboardRoutingControlsVisibility()
    }

    /// Re-applies the previous session's intent. A helper owned by another
    /// process is reported as busy rather than stopped behind its back.
    private func restoreLastSession(restoreTicket preparedTicket: RuntimeLifecycle.Ticket? = nil) {
        defer { refreshConnectionStatus() }
        guard let ticket = preparedTicket ?? launchRestoreIntent.reserve(),
              launchRestoreIntent.isCurrent(ticket) else { return }
        launchRestoreTicket = ticket
        let intent = launchProfilePlan.safeRestoreIntent(SessionRestoreIntent.load())
        if let error = launchProfilePlan.errorDescription {
            pendingSystemProxyRestore = false
            if UserDefaults.standard.bool(forKey: "enhancedModeEnabled") {
                persistEnhancedMode(false)
                enhancedModeButton.state = .off
            }
            networkRuntime.observe(listenerStatus: .failed("配置无效：\(error)"))
            showMessage(title: "配置无法加载，已阻止自动连接",
                        text: "\(error)\n请在“设置 → 订阅管理”中重新选择或更新订阅。")
            // A previous crash may have left the system proxy pointing at our
            // stopped listener. Restore its snapshot rather than restarting
            // with the placeholder DIRECT profile.
            if systemProxy.isEnabledByHajimi {
                systemProxyDisableRequests += 1
                systemProxy.disable { [weak self] result in
                    self?.systemProxyDisableRequests -= 1
                    self?.networkRuntime.observe(systemProxyResult: result)
                    defer { self?.refreshConnectionStatus() }
                    if case .failure(let restoreError) = result {
                        self?.showError(title: "无法恢复旧系统代理", error: restoreError)
                    }
                }
            }
            finishLaunchRestore()
            return
        }
        if SystemProxyListenerPlan.needsStaleSnapshotCleanup(
            snapshotExists: systemProxy.isEnabledByHajimi, requested: intent) {
            guard !staleSystemProxyCleanupAttempted else {
                showMessage(title: "系统代理尚未恢复",
                            text: "旧系统代理快照仍存在；为避免连接到已停止的监听器，已阻止自动连接。请在总览中先恢复系统代理。")
                finishLaunchRestore()
                return
            }
            staleSystemProxyCleanupAttempted = true
            startButton.isEnabled = false
            systemProxyRecoveryInFlight = true
            systemProxyButton.isEnabled = false
            statusLabel.stringValue = "正在恢复旧系统代理…"
            systemProxy.disable { [weak self] result in
                guard let self else { return }
                self.networkRuntime.observe(systemProxyResult: result)
                defer { self.refreshConnectionStatus() }
                self.startButton.isEnabled = true
                self.systemProxyRecoveryInFlight = false
                self.systemProxyButton.isEnabled = true
                switch result {
                case .success:
                    self.systemProxyAppliedAddress = nil
                    self.persistSystemProxy(false)
                    self.systemProxyButton.state = .off
                    guard self.launchRestoreIntent.isCurrent(ticket) else {
                        self.finishLaunchRestore()
                        return
                    }
                    self.restoreLastSession(restoreTicket: ticket)
                case .failure(let error):
                    self.systemProxyButton.state = .on
                    self.networkRuntime.observe(listenerStatus: .failed(error.localizedDescription))
                    self.showError(title: "无法恢复旧系统代理", error: error)
                    self.finishLaunchRestore()
                }
            }
            return
        }
        pendingSystemProxyRestore = intent.startEngine && intent.enableSystemProxy
        guard intent.startEngine || intent.startEnhancedMode else {
            finishLaunchRestore()
            return
        }
        launchRestoreIntent.release(ticket)
        if launchRestoreTicket == ticket { launchRestoreTicket = nil }
        let listenerRestoreTicket = intent.startEngine ? listenerLifecycle.reserve() : nil
        let enhancedRestoreTicket = intent.startEnhancedMode ? enhancedRequestIntent.reserve() : nil
        if let listenerRestoreTicket { listenerTicket = listenerRestoreTicket }
        guard listenerRestoreTicket != nil || enhancedRestoreTicket != nil else {
            finishLaunchRestore()
            return
        }
        networkRuntime.lifecycleDidChange()
        if enhancedRestoreTicket != nil { networkRuntime.observe(enhancedStatus: .starting) }
        let revision = profileRevision
        startButton.isEnabled = false
        prepareRuleSetsInBackground(profile) { [weak self] result in
            guard let self else { return }
            defer { self.refreshConnectionStatus() }
            let listenerAllowed = listenerRestoreTicket.map(self.listenerLifecycle.isCurrent) == true
            let enhancedAllowed = enhancedRestoreTicket.map(self.enhancedRequestIntent.isCurrent) == true
            guard listenerAllowed || enhancedAllowed else { self.finishLaunchRestore(); return }
            self.startButton.isEnabled = true
            if revision != self.profileRevision {
                if let ticket = listenerRestoreTicket {
                    self.listenerLifecycle.release(ticket)
                    if self.listenerTicket == ticket { self.listenerTicket = nil }
                }
                if let ticket = enhancedRestoreTicket { self.enhancedRequestIntent.release(ticket) }
                self.networkRuntime.lifecycleDidChange()
                // A subscription refresh or user save completed while rules
                // were prepared. Restart preparation with the new profile.
                if !self.isEngineActive && !self.enhancedMode.isEnabled {
                    self.restoreLastSession()
                } else {
                    self.finishLaunchRestore()
                }
                return
            }
            switch result {
            case .failure(let error):
                if let ticket = listenerRestoreTicket {
                    self.listenerLifecycle.markFailure(ticket)
                    self.listenerLifecycle.release(ticket, preservingFailure: true)
                    if self.listenerTicket == ticket { self.listenerTicket = nil }
                }
                if let ticket = enhancedRestoreTicket { self.enhancedRequestIntent.release(ticket) }
                self.networkRuntime.lifecycleDidChange()
                self.pendingSystemProxyRestore = false
                if intent.startEnhancedMode {
                    self.persistEnhancedMode(false)
                    self.enhancedModeButton.state = .off
                }
                if intent.startEngine { self.networkRuntime.observe(listenerStatus: .failed(error.localizedDescription)) }
                if intent.startEnhancedMode { self.networkRuntime.observe(enhancedStatus: .failed(error.localizedDescription)) }
                let title = intent.startEngine ? "无法启动代理引擎" : "无法恢复增强模式"
                self.showError(title: title, error: error)
                self.finishLaunchRestore()
            case .success(let prepared):
                if listenerAllowed, let ticket = listenerRestoreTicket {
                    do { try self.startEngineThrowing(prepared: prepared, startupTicket: ticket) } catch {
                        self.pendingSystemProxyRestore = false
                        self.showError(title: "无法启动代理引擎", error: error)
                    }
                } else {
                    self.refreshConnectionStatus()
                }
                if enhancedAllowed, let ticket = enhancedRestoreTicket {
                    self.restoreEnhancedMode(prepared: prepared, requestTicket: ticket)
                } else {
                    self.finishLaunchRestore()
                }
            }
        }
    }

    private func canStartAfterSystemProxyRecovery() -> Bool {
        let unresolvedSnapshot = systemProxy.isEnabledByHajimi
            && !UserDefaults.standard.bool(forKey: "systemProxyEnabled")
        guard !systemProxyRecoveryInFlight, !unresolvedSnapshot else {
            showMessage(title: "系统代理尚未恢复",
                        text: "旧系统代理可能仍指向已关闭的监听器。请先在总览中恢复系统代理，确认网络正常后再启动。")
            return false
        }
        return true
    }

    private func restoreEnhancedMode(prepared: Profile,
                                     requestTicket preparedTicket: RuntimeLifecycle.Ticket? = nil) {
        defer { refreshConnectionStatus() }
        guard let ticket = preparedTicket ?? enhancedRequestIntent.reserve(),
              enhancedRequestIntent.isCurrent(ticket) else { finishLaunchRestore(); return }
        let tunnelProfile: Profile
        do {
            tunnelProfile = try protocolAdapters.prepare(profile: prepared)
        } catch {
            enhancedRequestIntent.release(ticket)
            networkRuntime.observe(enhancedStatus: .failed(error.localizedDescription))
            persistEnhancedMode(false)
            enhancedModeButton.state = .off
            showError(title: "无法恢复增强模式", error: error)
            finishLaunchRestore()
            return
        }
        resolvedProfile = prepared
        let revision = profileRevision
        enhancedModeButton.isEnabled = false
        enhancedMode.start(profile: tunnelProfile, mode: selectedMode,
                           globalPolicy: selectedPolicy,
                           groupSelections: groupSelections,
                           engine: engine) { [weak self] result in
            guard let self, self.enhancedRequestIntent.isCurrent(ticket) else { return }
            defer { self.refreshConnectionStatus() }
            self.enhancedRequestIntent.release(ticket)
            guard revision == self.profileRevision else {
                self.discardStaleEnhancedStart(result)
                self.finishLaunchRestore()
                return
            }
            self.enhancedModeButton.isEnabled = true
            switch result {
            case .failure(let error):
                self.persistEnhancedMode(self.enhancedMode.isRequested)
                self.enhancedModeButton.state = self.isEnhancedModeActive ? .on : .off
                if !self.enhancedMode.isRequested {
                    self.showError(title: "无法恢复增强模式", error: error)
                }
            case .success:
                self.persistEnhancedMode(true)
                self.enhancedModeButton.state = .on
            }
            self.finishLaunchRestore()
        }
        networkRuntime.lifecycleDidChange()
    }

    private func finishLaunchRestore() {
        defer { refreshConnectionStatus() }
        if let ticket = launchRestoreTicket {
            launchRestoreIntent.release(ticket)
            launchRestoreTicket = nil
        }
        guard restoringLaunchSession else { return }
        restoringLaunchSession = false
        guard launchProfilePlan.profile != nil else { return }
        refreshPolicyHealth()
        refreshRuleSetsAutomatically()
        let requested = SessionRestoreIntent.load()
        if !requested.startEngine && !requested.startEnhancedMode {
            refreshStartupSubscriptionsIfNeeded()
        }
    }

    private func refreshStartupSubscriptionsIfNeeded() {
        guard startupSubscriptionsPending else { return }
        startupSubscriptionsPending = false
        updateSubscriptions(names: subscriptions.dueForRefresh().map(\.name), announce: false)
    }

    private var ruleSetNetworkIsReady: Bool {
        RuleSetBackgroundRefreshPlan.isReady(
            restoringSession: restoringLaunchSession,
            engineRunning: engineStatus == .running,
            enhancedRunning: enhancedMode.isEnabled)
            && startButton.isEnabled && enhancedModeButton.isEnabled
    }

    /// Capture on the main queue: configured ports may have been relocated.
    /// Enhanced-only sessions use their active TUN without starting a listener.
    private var ruleSetDownloadProxy: ListenAddress? {
        engineStatus == .running ? engine.activeHTTPListen : nil
    }

    private func refreshRuleSetsAutomatically() {
        guard ruleSetNetworkIsReady, launchProfilePlan.profile != nil,
              ruleOperationID == nil, activeProfilePreparationGeneration == nil else { return }
        guard !profile.ruleSetReferences.isEmpty else {
            refreshStartupSubscriptionsIfNeeded()
            return
        }
        guard let request = automaticRuleSetPlan.begin(
            ready: true, revision: profileRevision,
            applyGeneration: profileApplyGeneration) else { return }
        let source = profile
        let proxy = ruleSetDownloadProxy
        let reconcileCache = automaticRuleSetCacheNeedsApply
        automaticRuleSetQueue.async { [weak self] in
            guard let self else { return }
            let result: Result<Profile?, Error> = Result {
                let due = self.surgeRuleSets.expiredLocations(profile: source)
                guard !due.isEmpty || reconcileCache else { return nil }
                return try self.surgeRuleSets.prepare(
                    profile: source, mode: due.isEmpty ? .cacheOnly : .refresh,
                    httpProxy: proxy)
            }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                guard request.isCurrent(revision: self.profileRevision,
                                        applyGeneration: self.profileApplyGeneration),
                      source == self.profile, self.ruleSetNetworkIsReady,
                      self.ruleOperationID == nil,
                      self.activeProfilePreparationGeneration == nil else {
                    // Downloaded files may now be fresh. Reconcile them even
                    // if the next expiry check finds nothing due.
                    self.automaticRuleSetCacheNeedsApply = true
                    self.automaticRuleSetPlan.finish(request, retrySoon: true)
                    return
                }
                do {
                    if let prepared = try result.get() {
                        let changed = try self.applyAutomaticallyRefreshedRuleSets(prepared)
                        let warnings = prepared.warnings.filter {
                            $0.contains("RULE-SET") && $0.contains("更新失败")
                        }
                        self.refreshRulesPage()
                        if self.rulesPageSourceText != nil {
                            self.ruleStatusLabel.stringValue = warnings.isEmpty
                                ? (changed ? "规则集已在后台更新并应用" : "规则集已在后台检查，内容未变化")
                                : "部分规则集更新失败，已继续使用本地缓存"
                            self.ruleStatusLabel.textColor = warnings.isEmpty ? .systemGreen : .systemOrange
                            self.ruleStatusLabel.toolTip = warnings.isEmpty ? nil : warnings.joined(separator: "\n")
                        }
                    }
                    self.automaticRuleSetCacheNeedsApply = false
                } catch {
                    // Downloads keep the previous rules; an apply failure
                    // attempts rollback and exposes any rollback error here.
                    self.automaticRuleSetCacheNeedsApply = true
                    if self.rulesPageSourceText != nil {
                        self.ruleStatusLabel.stringValue = "后台规则更新未完成，请查看详情"
                        self.ruleStatusLabel.textColor = .systemOrange
                        self.ruleStatusLabel.toolTip = error.localizedDescription
                    }
                }
                self.automaticRuleSetPlan.finish(request)
                self.refreshStartupSubscriptionsIfNeeded()
            }
        }
    }

    /// Rule bodies alone do not require rebinding HTTP/SOCKS or configuring
    /// node transports. Real TUN policy changes retain normal revalidation.
    @discardableResult
    private func applyAutomaticallyRefreshedRuleSets(_ prepared: Profile) throws -> Bool {
        let previous = resolvedProfile ?? profile
        guard previous.ruleSetContents != prepared.ruleSetContents else {
            // Refresh warnings belong to the check's status. Changing the
            // runtime profile's warnings alone would make a later routing
            // equality check mistake an unchanged download for a reload.
            return false
        }
        let runtime = try protocolAdapters.prepare(profile: prepared)
        let oldRuntime = try protocolAdapters.prepare(profile: previous)
        let configuration = RoutingReloadGate.Configuration(
            profile: runtime, mode: selectedMode, globalPolicy: selectedPolicy,
            groupSelections: groupSelections)
        let wasRunning = engineStatus == .running
        let wasEnhanced = enhancedMode.isRequested || enhancedMode.isEnabled
        do {
            try routingReloadGate.apply(configuration) {
                if wasRunning {
                    try reloadListener {
                        try engine.updateRuleSetContents(runtime.ruleSetContents, preparedProfile: runtime)
                    }
                }
                if wasEnhanced {
                    try enhancedMode.reload(profile: runtime, mode: selectedMode,
                                            globalPolicy: selectedPolicy,
                                            groupSelections: groupSelections)
                }
            }
        } catch {
            let updateError = error
            var rollbackErrors: [String] = []
            if wasRunning {
                do {
                    try reloadListener {
                        try engine.updateRuleSetContents(oldRuntime.ruleSetContents, preparedProfile: oldRuntime)
                    }
                }
                catch { rollbackErrors.append(error.localizedDescription) }
            }
            if wasEnhanced {
                do {
                    try enhancedMode.reload(profile: oldRuntime, mode: selectedMode,
                                            globalPolicy: selectedPolicy,
                                            groupSelections: groupSelections)
                } catch { rollbackErrors.append(error.localizedDescription) }
            }
            if rollbackErrors.isEmpty {
                routingReloadGate.recordApplied(.init(
                    profile: oldRuntime, mode: selectedMode, globalPolicy: selectedPolicy,
                    groupSelections: groupSelections))
                throw updateError
            }
            throw ProfileApplyError.message(
                "规则更新失败：\(updateError.localizedDescription)；恢复旧规则未完成："
                    + rollbackErrors.joined(separator: "；"))
        }
        resolvedProfile = prepared
        profileRevision &+= 1
        return true
    }

    private func applyPendingSystemProxyRestore() {
        guard pendingSystemProxyRestore else { return }
        pendingSystemProxyRestore = false
        guard let ticket = listenerTicket, isCurrentListener(ticket) else { return }
        systemProxyButton.isEnabled = false
        let address = engine.activeHTTPListen
        systemProxyEnableRequests += 1
        systemProxy.enable(address: address,
                           bypassDomains: profile.proxyBypassDomains) { [weak self] result in
            guard let self else { return }
            self.networkRuntime.observe(systemProxyResult: result)
            defer { self.refreshConnectionStatus() }
            self.systemProxyEnableRequests -= 1
            self.systemProxyButton.isEnabled = true
            guard self.isCurrentListener(ticket) else {
                self.recoverSystemProxyAfterListenerFailure()
                return
            }
            if case .failure(let error) = result {
                self.recoverSystemProxyAfterListenerFailure()
                self.showError(title: "无法恢复系统代理", error: error)
            } else {
                self.systemProxyAppliedAddress = address
                self.persistSystemProxy(true)
                self.systemProxyButton.state = .on
                self.reconcileSystemProxyListener()
            }
        }
    }

    /// The port may change even when the profile's configured address does
    /// not (for example another process grabs our port during a restart).
    /// Repoint only after the replacement HTTP listener is confirmed ready.
    private func reconcileSystemProxyListener() {
        guard let ticket = listenerTicket, isCurrentListener(ticket), systemProxy.isEnabledByHajimi,
              systemProxyEnableRequests == 0,
              !pendingSystemProxyRestore, !systemProxyRebindInFlight,
              !systemProxyRecoveryInFlight,
              let applied = systemProxyAppliedAddress,
              SystemProxyListenerPlan.needsRebind(applied: applied,
                                                   active: engine.activeHTTPListen) else { return }
        let address = engine.activeHTTPListen
        systemProxyRebindInFlight = true
        systemProxyButton.isEnabled = false
        systemProxy.repoint(from: applied, to: address) { [weak self] result in
            guard let self else { return }
            self.networkRuntime.observe(systemProxyResult: result)
            defer { self.refreshConnectionStatus() }
            self.systemProxyRebindInFlight = false
            self.systemProxyButton.isEnabled = true
            guard self.isCurrentListener(ticket) else {
                self.recoverSystemProxyAfterListenerFailure()
                return
            }
            switch result {
            case .success:
                self.systemProxyAppliedAddress = address
                self.persistSystemProxy(true)
                self.systemProxyButton.state = .on
                if self.engineStatus == .running {
                    self.reconcileSystemProxyListener()
                }
            case .failure(let error):
                self.recoverSystemProxyAfterListenerFailure()
                self.showError(title: "系统代理监听端口更新失败，正在恢复原设置", error: error)
            }
        }
    }

    /// A failed or moved HTTP listener must not leave the machine pointing at
    /// its dead port. The SystemProxyManager retains its original snapshot if
    /// any privileged command fails, so the restore can be retried by the UI.
    private func recoverSystemProxyAfterListenerFailure() {
        defer { refreshConnectionStatus() }
        guard !systemProxyRecoveryInFlight else { return }
        guard systemProxy.isEnabledByHajimi else {
            systemProxyAppliedAddress = nil
            persistSystemProxy(false)
            systemProxyButton.state = .off
            systemProxyButton.isEnabled = true
            return
        }
        systemProxyRecoveryInFlight = true
        systemProxyButton.isEnabled = false
        systemProxy.disable { [weak self] result in
            guard let self else { return }
            self.networkRuntime.observe(systemProxyResult: result)
            defer { self.refreshConnectionStatus() }
            self.systemProxyRecoveryInFlight = false
            self.systemProxyButton.isEnabled = true
            switch result {
            case .success:
                self.systemProxyAppliedAddress = nil
                self.persistSystemProxy(false)
                self.systemProxyButton.state = .off
            case .failure(let error):
                self.systemProxyButton.state = .on
                self.showError(title: "引擎已停止，但系统代理尚未恢复", error: error)
            }
        }
    }

    private func persistEnhancedMode(_ enabled: Bool) {
        UserDefaults.standard.set(enabled, forKey: "enhancedModeEnabled")
        refreshConnectionStatus()
    }

    private func persistSystemProxy(_ enabled: Bool) {
        UserDefaults.standard.set(enabled, forKey: "systemProxyEnabled")
        refreshConnectionStatus()
    }

    private var selectedMode: OutboundMode {
        let index = max(0, modePopup.indexOfSelectedItem)
        return OutboundMode.allCases[index]
    }

    private var selectedPolicy: String { policyPopup.titleOfSelectedItem ?? "DIRECT" }

    private var selectedGroup: String? {
        guard groupPopup.isEnabled else { return nil }
        return groupPopup.titleOfSelectedItem
    }

    private func refreshPolicies(preferred: String?) {
        let old = preferred ?? policyPopup.titleOfSelectedItem
        let candidates = profile.globalProxyNodes.isEmpty ? profile.selectablePolicies : profile.globalProxyNodes
        policyPopup.removeAllItems()
        policyPopup.addItems(withTitles: candidates)
        if let old, profile.groups[old] == nil, candidates.contains(old) {
            policyPopup.selectItem(withTitle: old)
        } else {
            let fallback = candidates.first ?? "DIRECT"
            policyPopup.selectItem(withTitle: fallback)
            UserDefaults.standard.set(fallback, forKey: "globalPolicy")
        }
        policyPopup.isEnabled = selectedMode == .proxy
    }

    private func refreshGroups(preferred: String?) {
        let names = profile.groupOrder.filter { name in
            guard let group = profile.groups[name], group.kind == .select else { return false }
            return group.parameters["hidden"].map(surgeBoolean) != true
        }
        let old = preferred ?? groupPopup.titleOfSelectedItem
        groupPopup.removeAllItems()
        groupPopup.addItems(withTitles: names)
        if let old, names.contains(old) { groupPopup.selectItem(withTitle: old) }
        else if !names.isEmpty { groupPopup.selectItem(at: 0) }
        groupPopup.isEnabled = !names.isEmpty
        refreshGroupMembers()
    }

    private func refreshGroupMembers() {
        groupMemberPopup.removeAllItems()
        guard let selectedGroup, let group = profile.groups[selectedGroup] else {
            groupMemberPopup.isEnabled = false
            return
        }
        groupMemberPopup.addItems(withTitles: group.members)
        if let saved = groupSelections[selectedGroup], group.members.contains(saved) {
            groupMemberPopup.selectItem(withTitle: saved)
        } else if !group.members.isEmpty { groupMemberPopup.selectItem(at: 0) }
        groupMemberPopup.isEnabled = !group.members.isEmpty
    }

    private func refreshPolicyPage() {
        pruneProxyCardMetadata()
        let groupPlan = PolicyListRefreshPlan(previousOrder: renderedGroupOrder,
                                             order: profile.groupOrder, changedNames: [])
        if groupPlan.requiresReload {
            renderedGroupOrder = profile.groupOrder
            renderedGroupPolicies = profile.groups
            renderedGroupSelections = groupSelections
            pendingGroupCards.removeAll()
        }
        let currentQuery = ListSearchIndex<String>.normalizedQuery(proxySearchField.stringValue)
        if currentQuery.isEmpty {
            proxySearchQueue.cancelAllOperations()
            proxySearchDebouncer.cancel()
            applyProxySearch(names: profile.proxyOrder, query: "",
                             total: profile.proxyOrder.count, immediately: true,
                             forceFullReload: groupPlan.requiresReload)
        } else {
            if groupPlan.requiresReload {
                policyCollectionView.reloadData()
            }
            scheduleProxySearch(after: 0)
        }
        if !groupPlan.requiresReload {
            let changed = Set(profile.groupOrder.filter {
                renderedGroupPolicies[$0] != profile.groups[$0]
                    || renderedGroupSelections[$0] != groupSelections[$0]
            })
            schedulePolicyCardUpdates(groups: changed, immediately: true)
        }
        if policyStatusLabel.stringValue.isEmpty {
            policyStatusLabel.stringValue = "延迟为服务器 TCP 建连耗时；修改节点或策略组将立即热重载并自动保存到配置文件。"
        }
    }

    private func scheduleProxySearch(after delay: TimeInterval = 0.15) {
        proxySearchQueue.cancelAllOperations()
        proxySearchDebouncer.schedule(after: delay) { [weak self] generation in
            guard let self else { return }
            let query = ListSearchIndex<String>.normalizedQuery(self.proxySearchField.stringValue)
            if query.isEmpty {
                self.applyProxySearch(names: self.profile.proxyOrder, query: "",
                                      total: self.profile.proxyOrder.count, immediately: true)
                return
            }
            let request = ListSearchRequest(generation: generation, revision: self.profileRevision,
                                            editorText: nil, query: query)
            let order = self.profile.proxyOrder
            let policies = self.profile.proxies
            let cached = self.proxySearchIndexRevision == request.revision ? self.proxySearchIndex : nil
            self.proxySearchQueue.addOperation { [weak self] in
                let index = cached ?? ListSearchIndex(order) { name in
                    guard let policy = policies[name] else { return [name] }
                    return [name, policy.adapterType ?? policy.kind.rawValue, policy.host ?? ""]
                }
                let names = index.matchingIndexes(query: query).map { index.values[$0] }
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    guard request.isCurrent(
                        generation: self.proxySearchDebouncer.generation, revision: self.profileRevision,
                        editorText: nil,
                        query: ListSearchIndex<String>.normalizedQuery(self.proxySearchField.stringValue)) else {
                        if generation == self.proxySearchDebouncer.generation { self.scheduleProxySearch(after: 0) }
                        return
                    }
                    self.proxySearchIndex = index
                    self.proxySearchIndexRevision = request.revision
                    self.applyProxySearch(names: names, query: query, total: order.count, immediately: true)
                }
            }
        }
    }

    private func applyProxySearch(names: [String], query: String, total: Int,
                                  immediately: Bool = false, forceFullReload: Bool = false) {
        let plan = PolicyListRefreshPlan(previousOrder: renderedProxyOrder, order: names, changedNames: [])
        filteredProxyNames = names
        proxyCountLabel.stringValue = query.isEmpty ? "\(total) 个节点" : "\(names.count) / \(total)"
        if plan.requiresReload || forceFullReload || renderedGroupOrder != profile.groupOrder {
            renderedProxyOrder = names
            renderedGroupOrder = profile.groupOrder
            renderedGroupPolicies = profile.groups
            renderedGroupSelections = groupSelections
            renderedActiveProxy = activeProxyCardName
            for name in names { renderedProxyPolicies[name] = profile.proxies[name] }
            // A filtered reload covers these identities only. Hidden dirty
            // cards still need to be reconciled when they become visible.
            pendingProxyCards.subtract(Set(names))
            pendingGroupCards.removeAll()
            policyCollectionView.reloadData()
        } else {
            schedulePolicyCardUpdates(immediately: immediately)
            refreshActiveProxyCards()
        }
    }

    private var activeProxyCardName: String? { selectedMode == .proxy ? selectedPolicy : nil }

    private func pruneProxyCardMetadata() {
        let pruned = PolicyCardMetadataPruning.apply(metadata: renderedProxyPolicies, dirty: pendingProxyCards,
                                                     current: profile.proxies, order: profile.proxyOrder)
        renderedProxyPolicies = pruned.metadata
        pendingProxyCards = pruned.dirty
        proxyCardIdentities = pruned.identities
    }

    private func syncDashboardRoutingControlsVisibility() {
        let mode = selectedMode
        policyPopup.superview?.isHidden = (mode != .proxy)
        groupPopup.superview?.isHidden = (mode != .rule)
        groupMemberPopup.superview?.isHidden = (mode != .rule)
        if let stack = modePopup.superview?.superview as? NSStackView, stack.views.count >= 5 {
            stack.views[2].isHidden = (mode != .rule && mode != .proxy) || true
        }
    }

    private func refreshActiveProxyCards() {
        syncDashboardRoutingControlsVisibility()
        guard renderedActiveProxy != activeProxyCardName else { return }
        schedulePolicyCardUpdates(proxies: Set([renderedActiveProxy, activeProxyCardName].compactMap { $0 }))
    }

    /// Keep dirty identities while the page/window is hidden; opening the page
    /// reconciles them once. This does not pause health checking or API updates.
    private func schedulePolicyCardUpdates(proxies: Set<String> = [], groups: Set<String> = [],
                                           immediately: Bool = false) {
        pendingProxyCards.formUnion(proxies.intersection(proxyCardIdentities))
        pendingProxyCards.formIntersection(proxyCardIdentities)
        pendingGroupCards.formUnion(groups)
        guard !pendingProxyCards.isEmpty || !pendingGroupCards.isEmpty,
              !policiesView.isHidden, window?.isVisible == true else { return }
        if immediately {
            policyCardRefreshWork?.cancel(); policyCardRefreshWork = nil
            applyPendingPolicyCardUpdates()
        } else if policyCardRefreshWork == nil {
            let work = DispatchWorkItem { [weak self] in
                self?.policyCardRefreshWork = nil
                self?.applyPendingPolicyCardUpdates()
            }
            policyCardRefreshWork = work
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(80), execute: work)
        }
    }

    private func applyPendingPolicyCardUpdates() {
        guard !policiesView.isHidden, window?.isVisible == true,
              !pendingProxyCards.isEmpty || !pendingGroupCards.isEmpty else { return }
        let proxies = pendingProxyCards.intersection(proxyCardIdentities)
        let groups = pendingGroupCards
        pendingProxyCards.removeAll(); pendingGroupCards.removeAll()
        let proxyPlan = PolicyListRefreshPlan(previousOrder: renderedProxyOrder,
                                             order: filteredProxyNames, changedNames: proxies)
        let groupPlan = PolicyListRefreshPlan(previousOrder: renderedGroupOrder,
                                             order: profile.groupOrder, changedNames: groups)
        let expectedSection0 = (renderedProxyOrder ?? filteredProxyNames).count + 1
        let expectedSection1 = (renderedGroupOrder ?? profile.groupOrder).count + 1
        let countsConsistent = policyCollectionView.numberOfSections == 2
            && policyCollectionView.numberOfItems(inSection: 0) == expectedSection0
            && policyCollectionView.numberOfItems(inSection: 1) == expectedSection1
        if proxyPlan.requiresReload || groupPlan.requiresReload || !countsConsistent {
            renderedProxyOrder = filteredProxyNames
            renderedGroupOrder = profile.groupOrder
            renderedGroupPolicies = profile.groups
            renderedGroupSelections = groupSelections
            for name in filteredProxyNames { renderedProxyPolicies[name] = profile.proxies[name] }
            renderedActiveProxy = activeProxyCardName
            policyCollectionView.reloadData()
            return
        }
        let validProxyPaths = Set(proxyPlan.paths.filter { $0.section == 0 && $0.item >= 0 && $0.item < expectedSection0 })
        if !validProxyPaths.isEmpty { policyCollectionView.reloadItems(at: validProxyPaths) }
        for name in proxies { renderedProxyPolicies[name] = profile.proxies[name] }
        if !proxies.isEmpty { renderedActiveProxy = activeProxyCardName }
        let validGroupPaths = Set(groupPlan.paths.compactMap { path -> IndexPath? in
            guard path.item >= 0 && path.item < expectedSection1 else { return nil }
            return IndexPath(item: path.item, section: 1)
        })
        if !validGroupPaths.isEmpty {
            policyCollectionView.reloadItems(at: validGroupPaths)
        }
        for name in groups {
            renderedGroupPolicies[name] = profile.groups[name]
            renderedGroupSelections[name] = groupSelections[name]
        }
    }

    private func refreshRulesPage(selecting selection: Set<Int>? = nil) {
        if let selection {
            pendingRuleSelection = (profileTextView.string, profileRevision, selection)
        }
        scheduleRuleSearch(after: 0)
    }

    private func scheduleRuleSearch(after delay: TimeInterval = 0.15) {
        ruleListQueue.cancelAllOperations()
        ruleSearchDebouncer.schedule(after: delay) { [weak self] generation in
            guard let self else { return }
            let request = ListSearchRequest(
                generation: generation, revision: self.profileRevision,
                editorText: self.profileTextView.string,
                query: ListSearchIndex<String>.normalizedQuery(self.ruleSearchField.stringValue))
            let fallback = self.resolvedProfile ?? self.profile
            let preparation = self.ruleListPreparation
            self.ruleListQueue.addOperation { [weak self] in
                let snapshot = preparation.prepare(editorText: request.editorText ?? "",
                                                   revision: request.revision, fallback: fallback,
                                                   query: request.query)
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    guard request.isCurrent(
                        generation: self.ruleSearchDebouncer.generation, revision: self.profileRevision,
                        editorText: self.profileTextView.string,
                        query: ListSearchIndex<String>.normalizedQuery(self.ruleSearchField.stringValue)) else {
                        if generation == self.ruleSearchDebouncer.generation { self.refreshRulesPage() }
                        return
                    }
                    self.applyRuleList(snapshot, request: request)
                }
            }
        }
        if !rulesPageIsEditable { ruleCountLabel.stringValue = "正在准备规则…" }
        updateRuleSelectionControls()
    }

    private func applyRuleList(_ snapshot: RuleListSnapshot, request: ListSearchRequest) {
        let previousText = rulesPageSourceText
        let selectedLines = selectedRuleSourceLines
        rulesPageSourceText = snapshot.sourceText
        rulesPageRevision = request.revision
        rulesPageProfile = snapshot.sourceText == nil ? nil : snapshot.profile
        rulesPageRuleSetLocations = snapshot.ruleSetLocations
        filteredRules = snapshot.rules
        filteredRuleRows = snapshot.rows
        filteredRuleSourceLines = snapshot.sourceLines
        if ruleOperationID == nil {
            if let error = snapshot.errorDescription {
                ruleStatusLabel.stringValue = "配置草稿无效，当前规则只读：\(error)"
                ruleStatusLabel.textColor = .systemRed
                ruleStatusLabel.toolTip = error
            } else if ruleStatusLabel.stringValue.hasPrefix("配置草稿无效，当前规则只读：") {
                ruleStatusLabel.stringValue = "新增规则默认插入 FINAL / MATCH 之前；更新按钮刷新规则集，编辑可修改本地规则。"
                ruleStatusLabel.textColor = .secondaryLabelColor
                ruleStatusLabel.toolTip = nil
            }
        }
        let ruleSetPart = snapshot.ruleSetCount == 0 ? ""
            : " · \(snapshot.ruleSetCount) 个 RULE-SET / \(snapshot.loadedRuleCount) 条子规则"
        ruleCountLabel.stringValue = request.query.isEmpty
            ? "\(snapshot.totalRuleCount) 条主规则\(ruleSetPart)"
            : "\(snapshot.rules.count) / \(snapshot.totalRuleCount)\(ruleSetPart)"
        if snapshot.sourceText != nil, request.editorText != lastKnownStoredProfileText {
            ruleCountLabel.stringValue += " · 未保存"
        }
        let retained: Set<Int>
        if let pending = pendingRuleSelection, pending.text == request.editorText,
           pending.revision == request.revision, snapshot.sourceText != nil {
            retained = pending.lines.intersection(snapshot.sourceLines)
        } else {
            retained = RuleTableSelection.retaining(
                selectedLines, visibleSourceLines: snapshot.sourceLines,
                sourceTextChanged: previousText != snapshot.sourceText || snapshot.sourceText == nil)
        }
        pendingRuleSelection = nil
        ruleSelectionRefreshInProgress = true
        rulesTableView.reloadData()
        rulesTableView.selectRowIndexes(
            RuleTableSelection.rowIndexes(sourceLines: retained,
                                          orderedSourceLines: filteredRuleSourceLines),
            byExtendingSelection: false)
        ruleSelectionRefreshInProgress = false
        updateRuleSelectionControls()
    }

    private var selectedRuleSourceLines: Set<Int> {
        RuleTableSelection.sourceLines(rows: rulesTableView.selectedRowIndexes,
                                       orderedSourceLines: filteredRuleSourceLines)
    }

    private var selectedRuleSetLocations: Set<String> {
        let rows = rulesTableView.selectedRowIndexes
        guard !rows.isEmpty else { return rulesPageRuleSetLocations }
        return Set(rows.compactMap { row in
            guard filteredRules.indices.contains(row) else { return nil }
            if case .ruleSet(let reference) = filteredRules[row].kind { return reference.location }
            return nil
        })
    }

    private var rulesPageIsEditable: Bool {
        rulesPageSourceText == profileTextView.string && rulesPageRevision == profileRevision
            && rulesPageProfile != nil
    }

    private func updateRuleSelectionControls() {
        let count = selectedRuleSourceLines.count
        let editable = rulesPageIsEditable
        let available = editable && ruleOperationID == nil
        ruleAddButton.isEnabled = available
        ruleEditButton.isEnabled = available && count > 0
        ruleEditButton.title = count > 1 ? "批量改策略" : "编辑规则"
        ruleEditButton.toolTip = count > 1
            ? "批量修改选中规则的策略，匹配值和参数保持不变"
            : "编辑所选规则；也可双击一行"
        ruleDeleteButton.isEnabled = available && count > 0
        ruleUpdateButton.isEnabled = available && !selectedRuleSetLocations.isEmpty
        ruleUpdateButton.toolTip = count == 0
            ? "强制刷新全部 RULE-SET；本地规则请使用编辑"
            : "强制刷新选中规则中的 RULE-SET；本地规则请使用编辑"
        let checking = ruleMultiSelectButton.state == .on
        rulesTableView.tableColumns.first { $0.identifier.rawValue == "selected" }?.isHidden = !checking
        ruleSelectAllButton.isHidden = !checking
        ruleClearSelectionButton.isHidden = !checking
        ruleSelectAllButton.isEnabled = !filteredRules.isEmpty && editable
        ruleClearSelectionButton.isEnabled = count > 0
        ruleSelectionCountLabel.stringValue = count == 0 ? "未选择" : "已选 \(count) 条"
    }

    private func selectRuleSourceLines(_ lines: Set<Int>) {
        rulesTableView.selectRowIndexes(
            RuleTableSelection.rowIndexes(sourceLines: lines,
                                          orderedSourceLines: filteredRuleSourceLines),
            byExtendingSelection: false)
        updateRuleSelectionControls()
    }

    private func surgeBoolean(_ value: String) -> Bool {
        ["true", "yes", "on", "1"].contains(value.lowercased())
    }

    /// Starts or re-targets health checking after the profile changes.
    ///
    /// Automatic selections are seeded into `groupSelections` immediately so a
    /// managed group does not sit on its first declared member until the first
    /// probe round lands.
    private func refreshPolicyHealth() {
        policyHealthEpoch &+= 1
        let epoch = policyHealthEpoch
        let selectionsChanged: ([String: String]) -> Void = { [weak self] selections in
            DispatchQueue.main.async {
                guard let self, self.policyHealthEpoch == epoch else { return }
                var changed = Set<String>()
                for (group, member) in selections
                where !self.manualManagedGroupSelections.contains(group) && self.groupSelections[group] != member {
                    self.groupSelections[group] = member
                    changed.insert(group)
                }
                // Automatic selections are deliberately not persisted to
                // UserDefaults: they are a live measurement, and restoring a
                // stale one at launch would point traffic at whatever was
                // fastest yesterday.
                guard !changed.isEmpty else { return }
                self.updateEngineRouting()
                self.schedulePolicyCardUpdates(groups: changed)
            }
        }
        let reportReceived: (PolicyHealthMonitor.Report) -> Void = { [weak self] report in
            DispatchQueue.main.async {
                guard let self, self.policyHealthEpoch == epoch,
                      self.profile.groups[report.group] != nil else { return }
                self.policyLatencies[report.group] = report.latencies
            }
        }
        policyHealth.update(profile: resolvedProfile ?? profile,
                            onSelectionsChanged: selectionsChanged, onReport: reportReceived)
    }

    private func updateEngineRouting() {
        defer { networkRuntime.lifecycleDidChange(); refreshConnectionStatus() }
        let lifecycle = listenerLifecycle.snapshot
        do {
            let runtime = try protocolAdapters.prepare(profile: resolvedProfile ?? profile)
            // Defer only the pending listener. An already-running TUN still
            // applies the latest selection through its own real reload gate.
            if lifecycle.isPresent && lifecycle.startupPending {
                if enhancedMode.isRequested || enhancedMode.isEnabled {
                    try enhancedMode.reload(profile: runtime, mode: selectedMode,
                                            globalPolicy: selectedPolicy, groupSelections: groupSelections)
                }
                return
            }
            let configuration = RoutingReloadGate.Configuration(
                profile: runtime, mode: selectedMode, globalPolicy: selectedPolicy,
                groupSelections: groupSelections)
            var enhancedReloaded = false
            try routingReloadGate.apply(configuration) {
                try reloadListener {
                    engine.updateRouting(mode: selectedMode, globalPolicy: selectedPolicy,
                                         groupSelections: groupSelections)
                }
                if enhancedMode.isRequested || enhancedMode.isEnabled {
                    enhancedReloaded = true
                    try enhancedMode.reload(profile: runtime, mode: selectedMode,
                                            globalPolicy: selectedPolicy,
                                            groupSelections: groupSelections)
                }
            }
            if !enhancedReloaded, (enhancedMode.isRequested || enhancedMode.isEnabled) {
                try enhancedMode.reload(profile: runtime, mode: selectedMode,
                                        globalPolicy: selectedPolicy,
                                        groupSelections: groupSelections)
            }
        } catch {
            showError(title: "原生 TUN 热重载失败", error: error)
        }
    }

    /// The App gate alone decides whether configuration has observable work.
    /// Only that work can revoke a listener diagnostic lease or require recovery.
    private func reloadListener(_ action: () throws -> Void) throws {
        guard listenerLifecycle.snapshot.isPresent else { try action(); return }
        guard let ticket = listenerLifecycle.beginReload() else {
            throw ProfileApplyError.message("代理引擎会话已撤销，无法重载")
        }
        networkRuntime.lifecycleDidChange()
        defer { networkRuntime.lifecycleDidChange() }
        do {
            try action()
            guard listenerLifecycle.finishReload(ticket, success: true) else {
                throw ProfileApplyError.message("代理引擎重载已取消")
            }
        } catch {
            _ = listenerLifecycle.finishReload(ticket, success: false)
            throw error
        }
    }

    @objc private func navigate(_ sender: NSButton) { selectPage(sender.tag) }

    private func selectPage(_ index: Int) {
        let pages = [dashboardView, policiesView, rulesView, aboutView, settingsView]
        for (pageIndex, view) in pages.enumerated() { view.isHidden = pageIndex != index }
        for (buttonIndex, button) in navigationButtons.enumerated() {
            (button as? HajimiNavigationButton)?.isCurrentPage = buttonIndex == index
        }
        if index == 1 { refreshPolicyPage(); applyPendingPolicyCardUpdates() }
        if index == 2 { refreshRulesPage() }
        if index == 4 { refreshSettings() }
    }

    @objc private func toggleEngine() {
        if isEngineActive {
            startButton.isEnabled = false
            disableSystemProxyAndStopEngine()
        } else { startEngine() }
    }

    private func disableSystemProxyAndStopEngine() {
        defer { refreshConnectionStatus() }
        cancelLaunchRestorePreparation()
        // Revoke preparation before an asynchronous system-proxy restore;
        // queued RULE-SET completion must never start behind a stop request.
        let stoppedTicket = listenerLifecycle.cancel()
        networkRuntime.lifecycleDidChange()
        if systemProxy.isEnabledByHajimi {
            systemProxyButton.isEnabled = false
            systemProxyDisableRequests += 1
            systemProxy.disable { [weak self] result in
                guard let self else { return }
                self.systemProxyDisableRequests -= 1
                self.networkRuntime.observe(systemProxyResult: result)
                defer { self.refreshConnectionStatus() }
                guard self.listenerTicket == stoppedTicket else {
                    // The restore has finished, but its listener was replaced.
                    // Reflect the current proxy snapshot without stopping it.
                    if self.listenerLifecycle.snapshot.isReady { self.startButton.isEnabled = true }
                    if self.systemProxyEnableRequests == 0, !self.systemProxyRebindInFlight,
                       !self.systemProxyRecoveryInFlight {
                        self.systemProxyButton.isEnabled = true
                        let enabled = self.systemProxy.isEnabledByHajimi
                        self.systemProxyButton.state = enabled ? .on : .off
                        if !enabled {
                            self.systemProxyAppliedAddress = nil
                            self.persistSystemProxy(false)
                        }
                    }
                    return
                }
                self.systemProxyButton.isEnabled = true
                if case .failure(let error) = result {
                    self.startButton.isEnabled = true
                    self.systemProxyButton.state = .on
                    self.showError(title: "恢复系统代理失败", error: error)
                    return
                }
                self.systemProxyButton.state = .off
                self.systemProxyAppliedAddress = nil
                self.stopProxyEngine()
                self.startButton.isEnabled = true
            }
        } else {
            stopProxyEngine()
            startButton.isEnabled = true
        }
    }

    private func startEngine() {
        guard canStartAfterSystemProxyRecovery() else { return }
        if let error = launchProfilePlan.errorDescription {
            showMessage(title: "配置无法加载", text: "\(error)\n请修复并保存配置后再启动。")
            return
        }
        guard let ticket = listenerLifecycle.reserve() else { return }
        listenerTicket = ticket
        networkRuntime.observe(listenerStatus: .starting)
        networkRuntime.lifecycleDidChange()
        refreshConnectionStatus()
        let revision = profileRevision
        startButton.isEnabled = false
        prepareRuleSetsInBackground(profile) { [weak self] result in
            guard let self, self.listenerLifecycle.isCurrent(ticket) else { return }
            defer { self.refreshConnectionStatus() }
            self.startButton.isEnabled = true
            guard revision == self.profileRevision else {
                self.listenerLifecycle.release(ticket)
                if self.listenerTicket == ticket { self.listenerTicket = nil }
                self.networkRuntime.lifecycleDidChange()
                return
            }
            do {
                try self.startEngineThrowing(prepared: result.get(), startupTicket: ticket)
            } catch {
                self.listenerLifecycle.markFailure(ticket)
                self.listenerLifecycle.release(ticket, preservingFailure: true)
                if self.listenerTicket == ticket { self.listenerTicket = nil }
                self.networkRuntime.lifecycleDidChange()
                self.protocolAdapters.stop()
                self.engineStatus = .failed(error.localizedDescription)
                self.networkRuntime.observe(listenerStatus: self.engineStatus)
                self.showError(title: "无法启动代理引擎", error: error)
            }
        }
    }

    private func prepareRuleSetsInBackground(
        _ source: Profile,
        completion: @escaping (Result<Profile, Error>) -> Void
    ) {
        let proxy = ruleSetDownloadProxy
        ruleSetPreparationQueue.async { [weak self] in
            guard let self else { return }
            let result = Result {
                do {
                    return try self.surgeRuleSets.prepare(profile: source, mode: .cacheOnly)
                } catch let error as SurgeRuleSetManager.RuleSetError where error.isMissingCache {
                    // A first load still needs every required body; never
                    // interpret missing remote rules as an empty rule set.
                    return try self.surgeRuleSets.prepare(profile: source, httpProxy: proxy)
                }
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    private func startEngineThrowing(prepared resolved: Profile,
                                     startupTicket preparedTicket: RuntimeLifecycle.Ticket? = nil) throws {
        defer { refreshConnectionStatus() }
        guard launchProfilePlan.profile != nil else {
            throw ProfileApplyError.message("已保存配置无效，请修复并保存后再启动")
        }
        if let preparedTicket {
            guard listenerLifecycle.isCurrent(preparedTicket), listenerTicket == preparedTicket else {
                throw ProfileApplyError.message("代理引擎启动已取消")
            }
        }
        // Preserve the listener address that the OS proxy is already using.
        // The configured port may become free during a reload, and re-running
        // the port allocator must not silently strand the system proxy.
        let preferredHTTP = SystemProxyListenerPlan.preferred(
            configured: resolved.httpListen, active: engine.activeHTTPListen,
            engineRunning: engineStatus == .running,
            systemProxyEnabled: systemProxyIsOrWillBeEnabled)
        routingReloadGate.reset()
        let ticket: RuntimeLifecycle.Ticket
        if let preparedTicket {
            guard listenerLifecycle.isCurrent(preparedTicket), listenerTicket == preparedTicket else {
                throw ProfileApplyError.message("代理引擎启动已取消")
            }
            ticket = preparedTicket
            engine.stop()
        } else {
            let previous = listenerLifecycle.cancel()
            networkRuntime.lifecycleDidChange()
            engine.stop()
            if let previous { listenerLifecycle.confirmStopped(previous) }
            listenerTicket = nil
            guard let next = listenerLifecycle.reserve() else {
                throw ProfileApplyError.message("代理引擎仍在清理上一会话")
            }
            ticket = next
            listenerTicket = next
        }
        defer { networkRuntime.lifecycleDidChange() }
        do {
            var runtimeProfile = try protocolAdapters.prepare(profile: resolved)
            // Compare the prepared configuration before the temporary port adjustment.
            let routingConfiguration = RoutingReloadGate.Configuration(
                profile: runtimeProfile, mode: selectedMode, globalPolicy: selectedPolicy,
                groupSelections: groupSelections)
            runtimeProfile.httpListen = preferredHTTP
            listenerLifecycle.markOwned(ticket)
            try engine.start(profile: runtimeProfile, mode: selectedMode,
                             globalPolicy: selectedPolicy, groupSelections: groupSelections)
            guard listenerLifecycle.isCurrent(ticket) else {
                throw ProfileApplyError.message("代理引擎启动已取消")
            }
            // NWListener.start is asynchronous. Actual ownership precedes
            // readiness; only the Core's two-listener ready gate can attest it.
            switch engine.runtimeSnapshot().status {
            case .running:
                guard listenerLifecycle.markRunning(ticket) else {
                    throw ProfileApplyError.message("代理引擎启动已取消")
                }
            case .starting: break
            case .failed(let reason): throw ProfileApplyError.message(reason)
            case .stopped: throw ProfileApplyError.message("代理引擎未启动")
            }
            resolvedProfile = resolved
            routingReloadGate.recordApplied(routingConfiguration)
            UserDefaults.standard.set(true, forKey: "proxyEngineEnabled")
            refreshRulesPage()
        } catch {
            listenerLifecycle.markFailure(ticket)
            engine.stop()
            protocolAdapters.stop()
            listenerLifecycle.confirmStopped(ticket, preservingFailure: true)
            if listenerTicket == ticket { listenerTicket = nil }
            throw error
        }
    }

    private func stopListenerResources() {
        let ticket = listenerLifecycle.cancel()
        networkRuntime.lifecycleDidChange()
        routingReloadGate.reset()
        engine.stop()
        protocolAdapters.stop()
        if let ticket { listenerLifecycle.confirmStopped(ticket) }
        listenerTicket = nil
        networkRuntime.lifecycleDidChange()
        apply(status: .stopped)
    }

    private func stopProxyEngine() {
        cancelLaunchRestorePreparation()
        stopListenerResources()
        systemProxyAppliedAddress = nil
        UserDefaults.standard.set(false, forKey: "proxyEngineEnabled")
        persistSystemProxy(false)
    }

    private func cancelLaunchRestorePreparation() {
        if let ticket = launchRestoreIntent.cancel() {
            restoringLaunchSession = false
            launchRestoreIntent.release(ticket)
            if launchRestoreTicket == ticket { launchRestoreTicket = nil }
        }
    }

    @objc private func toggleSystemProxy() {
        defer { refreshConnectionStatus() }
        // Status-item and controller actions can arrive while the checkbox is
        // disabled for an administrator authorization. A second enable would
        // run after the first one and briefly restore the original proxy.
        guard systemProxyButton.isEnabled, systemProxyEnableRequests == 0,
              !systemProxyRebindInFlight, !systemProxyRecoveryInFlight else {
            systemProxyButton.state = systemProxyIsOrWillBeEnabled ? .on : .off
            return
        }
        if systemProxyButton.state == .on {
            guard let ticket = listenerTicket, isCurrentListener(ticket) else {
                systemProxyButton.state = .off
                showMessage(title: "请先开启本地代理",
                            text: "请前往“设置 → 本地代理”，开启 HTTP / SOCKS5 代理，等待监听就绪后再设置为系统代理。")
                return
            }
            systemProxyButton.isEnabled = false
            // Use the ports the engine actually bound (may differ when the
            // configured HTTP/SOCKS ports were already taken).
            let address = engine.activeHTTPListen
            systemProxyEnableRequests += 1
            systemProxy.enable(address: address,
                               bypassDomains: profile.proxyBypassDomains) { [weak self] result in
                guard let self else { return }
                self.networkRuntime.observe(systemProxyResult: result)
                defer { self.refreshConnectionStatus() }
                self.systemProxyEnableRequests -= 1
                self.systemProxyButton.isEnabled = true
                guard self.isCurrentListener(ticket) else {
                    self.recoverSystemProxyAfterListenerFailure()
                    return
                }
                if case .failure(let error) = result {
                    self.recoverSystemProxyAfterListenerFailure()
                    self.showError(title: "设置系统代理失败", error: error)
                } else {
                    self.systemProxyAppliedAddress = address
                    self.persistSystemProxy(true)
                    self.systemProxyButton.state = .on
                    self.reconcileSystemProxyListener()
                }
            }
        } else {
            systemProxyButton.isEnabled = false
            systemProxyDisableRequests += 1
            systemProxy.disable { [weak self] result in
                guard let self else { return }
                self.systemProxyDisableRequests -= 1
                self.networkRuntime.observe(systemProxyResult: result)
                defer { self.refreshConnectionStatus() }
                self.systemProxyButton.isEnabled = true
                if case .failure(let error) = result {
                    self.systemProxyButton.state = .on
                    self.showError(title: "恢复系统代理失败", error: error)
                } else {
                    self.systemProxyAppliedAddress = nil
                    self.persistSystemProxy(false)
                    self.systemProxyButton.state = .off
                }
            }
        }
    }

    @objc private func toggleEnhancedMode() {
        defer { refreshConnectionStatus() }
        // Status-item and controller actions can arrive while the checkbox is
        // disabled for preparation/start; they must not queue a second start.
        guard enhancedModeButton.isEnabled || enhancedModeButton.state == .off else {
            enhancedModeButton.state = isEnhancedModeActive ? .on : .off
            return
        }
        if enhancedModeButton.state == .on {
            guard canStartAfterSystemProxyRecovery() else {
                enhancedModeButton.state = .off
                return
            }
            if let error = launchProfilePlan.errorDescription {
                enhancedModeButton.state = .off
                showMessage(title: "配置无法加载", text: "\(error)\n请修复并保存配置后再开启增强模式。")
                return
            }
            guard let ticket = enhancedRequestIntent.reserve() else { return }
            networkRuntime.observe(enhancedStatus: .starting)
            let revision = profileRevision
            enhancedModeButton.isEnabled = false
            dataPlaneRuntimeValue.stringValue = "正在准备 RULE-SET…"
            prepareRuleSetsInBackground(profile) { [weak self] result in
                guard let self, self.enhancedRequestIntent.isCurrent(ticket) else { return }
                defer { self.refreshConnectionStatus() }
                guard revision == self.profileRevision else {
                    self.enhancedRequestIntent.release(ticket)
                    self.persistEnhancedMode(false)
                    self.enhancedModeButton.state = .off
                    self.enhancedModeButton.isEnabled = true
                    self.dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                    self.showMessage(title: "配置已更新",
                                     text: "准备规则集期间配置已更新，请重新开启增强模式。")
                    return
                }
                do {
                    let prepared = try result.get()
                    let tunnelProfile = try self.protocolAdapters.prepare(profile: prepared)
                    self.resolvedProfile = prepared
                    self.dataPlaneRuntimeValue.stringValue = "正在开启原生 TUN…"
                    self.enhancedMode.start(profile: tunnelProfile, mode: self.selectedMode,
                                            globalPolicy: self.selectedPolicy,
                                            groupSelections: self.groupSelections,
                                            engine: self.engine) { [weak self] result in
                        guard let self, self.enhancedRequestIntent.isCurrent(ticket) else { return }
                        defer { self.refreshConnectionStatus() }
                        self.enhancedRequestIntent.release(ticket)
                        guard revision == self.profileRevision else {
                            self.discardStaleEnhancedStart(result)
                            return
                        }
                        self.enhancedModeButton.isEnabled = true
                        if case .failure(let error) = result {
                            self.persistEnhancedMode(self.enhancedMode.isRequested)
                            self.enhancedModeButton.state = self.isEnhancedModeActive ? .on : .off
                            if !self.enhancedMode.isRequested {
                                self.dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                                self.showError(title: "开启增强模式失败", error: error)
                            }
                        } else {
                            self.persistEnhancedMode(true)
                            self.enhancedModeButton.state = .on
                        }
                    }
                    self.persistEnhancedMode(self.enhancedMode.isRequested)
                    self.networkRuntime.lifecycleDidChange()
                } catch {
                    self.enhancedRequestIntent.release(ticket)
                    self.networkRuntime.observe(enhancedStatus: .failed(error.localizedDescription))
                    self.persistEnhancedMode(false)
                    self.enhancedModeButton.state = .off
                    self.enhancedModeButton.isEnabled = true
                    self.dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                    self.showError(title: "无法准备原生 TUN 路由", error: error)
                }
            }
        } else {
            cancelLaunchRestorePreparation()
            if let ticket = enhancedRequestIntent.cancel() { enhancedRequestIntent.release(ticket) }
            persistEnhancedMode(false)
            let lifecycle = enhancedMode.lifecycleSnapshot
            guard enhancedMode.isRequested || lifecycle.isPresent || lifecycle.startupPending || enhancedMode.isEnabled else {
                networkRuntime.observe(enhancedStatus: .stopped)
                persistEnhancedMode(false)
                enhancedModeButton.state = .off
                enhancedModeButton.isEnabled = true
                dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                return
            }
            enhancedModeButton.isEnabled = false
            enhancedMode.stop(engine: engine) { [weak self] result in
                guard let self else { return }
                defer { self.refreshConnectionStatus() }
                self.enhancedModeButton.isEnabled = true
                if case .failure(let error) = result {
                    self.enhancedModeButton.state = .on
                    self.showError(title: "关闭增强模式失败", error: error)
                } else {
                    self.persistEnhancedMode(false)
                    self.enhancedModeButton.state = .off
                }
            }
            networkRuntime.lifecycleDidChange()
        }
    }

    /// A profile saved while the helper was starting must not leave a tunnel
    /// running with the previous DNS, route and proxy settings.
    private func discardStaleEnhancedStart(_ result: Result<EnhancedModeManager.State, Error>) {
        defer { refreshConnectionStatus() }
        persistEnhancedMode(false)
        switch result {
        case .failure:
            // A deferred start may still retain a reconnect intent. Revoke
            // that intent as well as the stale UI preparation ticket.
            enhancedMode.stop(engine: engine) { [weak self] result in
                if case .failure(let error) = result {
                    self?.showError(title: "无法清理过期增强模式", error: error)
                }
            }
            enhancedModeButton.state = .off
            enhancedModeButton.isEnabled = true
            dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
            showMessage(title: "配置已更新", text: "增强模式启动期间配置已更新，请重新开启。")
        case .success:
            enhancedModeButton.isEnabled = false
            enhancedMode.stop(engine: engine) { [weak self] stopped in
                guard let self else { return }
                defer { self.refreshConnectionStatus() }
                self.enhancedModeButton.isEnabled = true
                switch stopped {
                case .success:
                    self.enhancedModeButton.state = .off
                    self.dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                    self.showMessage(title: "配置已更新",
                                     text: "已关闭使用旧配置启动的增强模式，请重新开启。")
                case .failure(let error):
                    self.enhancedModeButton.state = self.enhancedMode.isEnabled ? .on : .off
                    self.showError(title: "无法清理过期增强模式", error: error)
                }
            }
        }
    }

    @objc private func modeChanged() {
        policyPopup.isEnabled = selectedMode == .proxy
        UserDefaults.standard.set(selectedMode.rawValue, forKey: "outboundMode")
        updateEngineRouting()
        updateOverviewDetails()
        refreshActiveProxyCards()
    }

    @objc private func policyChanged() {
        UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
        updateEngineRouting()
        updateOverviewDetails()
        refreshActiveProxyCards()
    }

    @objc private func groupChanged() {
        if let selectedGroup {
            UserDefaults.standard.set(selectedGroup, forKey: "selectedPolicyGroup")
        }
        refreshGroupMembers()
    }

    @objc private func groupMemberChanged() {
        guard let selectedGroup, let member = groupMemberPopup.titleOfSelectedItem else { return }
        setGroupSelection(group: selectedGroup, member: member)
    }

    @objc private func proxySearchChanged() { scheduleProxySearch() }
    @objc private func ruleSearchChanged() { scheduleRuleSearch() }

    @objc private func ruleMultiSelectionChanged() {
        let selection = selectedRuleSourceLines
        updateRuleSelectionControls()
        ruleSelectionRefreshInProgress = true
        rulesTableView.reloadData()
        ruleSelectionRefreshInProgress = false
        selectRuleSourceLines(selection)
    }

    @objc private func selectAllRules() {
        guard rulesPageIsEditable else { refreshRulesPage(); return }
        rulesTableView.selectRowIndexes(IndexSet(integersIn: 0..<filteredRules.count),
                                        byExtendingSelection: false)
        updateRuleSelectionControls()
    }

    @objc private func clearRuleSelection() {
        rulesTableView.deselectAll(nil)
        updateRuleSelectionControls()
    }

    @objc private func ruleRowSelectionChanged(_ sender: NSButton) {
        guard rulesPageIsEditable,
              let row = filteredRules.firstIndex(where: { $0.sourceLine == sender.tag }) else {
            refreshRulesPage()
            return
        }
        var indexes = rulesTableView.selectedRowIndexes
        if sender.state == .on { indexes.insert(row) }
        else { indexes.remove(row) }
        rulesTableView.selectRowIndexes(indexes, byExtendingSelection: false)
        updateRuleSelectionControls()
    }

    @objc private func rulesDoubleClicked() {
        let row = rulesTableView.clickedRow
        guard ruleOperationID == nil, filteredRules.indices.contains(row) else { return }
        rulesTableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        editSelectedRules()
    }

    private var rulePolicyNames: [String] {
        let source = rulesPageProfile ?? profile
        var names = ["DIRECT", "REJECT"]
        for name in source.groupOrder + source.proxyOrder where !names.contains(name) {
            names.append(name)
        }
        return names
    }

    private func ruleEditingSnapshot() throws -> (text: String, revision: Int) {
        guard ruleOperationID == nil else {
            throw ProfileApplyError.message("规则操作正在进行，请稍候")
        }
        guard rulesPageIsEditable else {
            refreshRulesPage()
            throw ProfileApplyError.message("配置已变化或草稿无效，请检查后重新选择规则")
        }
        try verifyStoredProfileHasNotChanged(expected: lastKnownStoredProfileText)
        return (profileTextView.string, profileRevision)
    }

    private func verifyRuleEditingSnapshot(_ snapshot: (text: String, revision: Int)) throws {
        guard snapshot.text == profileTextView.string, snapshot.revision == profileRevision else {
            throw ProfileApplyError.message("配置在编辑期间已变化，未覆盖新内容，请关闭编辑框后重新选择")
        }
        guard ruleOperationID == nil else {
            throw ProfileApplyError.message("规则操作正在进行，请稍候")
        }
        try verifyStoredProfileHasNotChanged(expected: lastKnownStoredProfileText)
    }

    private func validateRulePolicy(_ rawPolicy: String, in text: String) throws {
        let source = try ProfileParser.parse(text)
        let policy = rawPolicy.trimmingCharacters(in: .whitespacesAndNewlines)
        guard policy == "DIRECT" || policy == "REJECT" ||
                source.proxies[policy] != nil || source.groups[policy] != nil else {
            throw ProfileApplyError.message("策略“\(policy)”不存在，请选择已有节点、策略组、DIRECT 或 REJECT")
        }
    }

    @objc private func addRule() {
        guard let window, ruleEditor == nil, rulePolicyEditor == nil else { return }
        refreshRulesPage()
        do {
            let snapshot = try ruleEditingSnapshot()
            let editor = RuleEditorSheetController(draft: nil, policyNames: rulePolicyNames) { [weak self] draft in
                guard let self else { return }
                try self.verifyRuleEditingSnapshot(snapshot)
                try self.validateRulePolicy(draft.policy, in: snapshot.text)
                var document = SurgeProfileDocument(snapshot.text)
                let line = try document.insertRule(draft)
                try self.applyRuleChange(document.text, snapshot: snapshot,
                                         prefix: "已新增并应用规则", selection: [line])
            }
            ruleEditor = editor
            guard let sheet = editor.window else { ruleEditor = nil; return }
            window.beginSheet(sheet) { [weak self] _ in self?.ruleEditor = nil }
        } catch {
            showError(title: "无法新增规则", error: error)
        }
    }

    @objc private func editSelectedRules() {
        guard let window, ruleEditor == nil, rulePolicyEditor == nil else { return }
        do {
            let snapshot = try ruleEditingSnapshot()
            let lines = selectedRuleSourceLines
            guard !lines.isEmpty else { return }
            if lines.count > 1 {
                let editor = RulePolicySheetController(count: lines.count,
                                                       policyNames: rulePolicyNames) { [weak self] policy in
                    guard let self else { return }
                    try self.verifyRuleEditingSnapshot(snapshot)
                    try self.validateRulePolicy(policy, in: snapshot.text)
                    var document = SurgeProfileDocument(snapshot.text)
                    try document.setRulePolicies(atSourceLines: lines, policy: policy)
                    try self.applyRuleChange(document.text, snapshot: snapshot,
                                             prefix: "已更新并应用 \(lines.count) 条规则的策略",
                                             selection: lines)
                }
                rulePolicyEditor = editor
                guard let sheet = editor.window else { rulePolicyEditor = nil; return }
                window.beginSheet(sheet) { [weak self] _ in self?.rulePolicyEditor = nil }
            } else if let line = lines.first {
                let draft = try SurgeProfileDocument(snapshot.text).ruleDraft(atSourceLine: line)
                let editor = RuleEditorSheetController(draft: draft,
                                                       policyNames: rulePolicyNames) { [weak self] updated in
                    guard let self else { return }
                    try self.verifyRuleEditingSnapshot(snapshot)
                    try self.validateRulePolicy(updated.policy, in: snapshot.text)
                    var document = SurgeProfileDocument(snapshot.text)
                    try document.updateRule(atSourceLine: line, draft: updated)
                    let changed = try ProfileParser.parse(document.text)
                    let catchAll = ["FINAL", "MATCH"].contains(updated.type.uppercased())
                    let selectedLine = catchAll
                        ? changed.rules.first(where: { $0.kind == .final })?.sourceLine : line
                    let selection = selectedLine.map { Set([$0]) } ?? []
                    try self.applyRuleChange(document.text, snapshot: snapshot,
                                             prefix: "已更新并应用规则",
                                             selection: selection)
                }
                ruleEditor = editor
                guard let sheet = editor.window else { ruleEditor = nil; return }
                window.beginSheet(sheet) { [weak self] _ in self?.ruleEditor = nil }
            }
        } catch {
            showError(title: "无法编辑规则", error: error)
        }
    }

    @objc private func deleteSelectedRules() {
        guard let window else { return }
        do {
            let snapshot = try ruleEditingSnapshot()
            let lines = selectedRuleSourceLines
            guard !lines.isEmpty else { return }
            let selected = filteredRules.filter { lines.contains($0.sourceLine) }
            let preview = selected.prefix(6).map { rule in
                let description = ruleDescription(rule)
                return "第 \(rule.sourceLine) 行 · \(description.type) · \(description.value.prefix(90))"
            }.joined(separator: "\n")
            let more = selected.count > 6 ? "\n…另有 \(selected.count - 6) 条" : ""
            let finalWarning = selected.contains { $0.kind == .final }
                ? "\n\n包含 FINAL / MATCH 兜底规则，删除会改变未命中流量的处理方式。" : ""
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "删除选中的 \(lines.count) 条规则？"
            alert.informativeText = preview + more + finalWarning + "\n\n只删除选中主规则，保存后应用；不会删除远程规则集源文件。"
            alert.addButton(withTitle: "删除")
            alert.addButton(withTitle: "取消")
            alert.buttons[0].keyEquivalent = ""
            alert.buttons[1].keyEquivalent = "\r"
            alert.beginSheetModal(for: window) { [weak self] response in
                guard response == .alertFirstButtonReturn, let self else { return }
                do {
                    try self.verifyRuleEditingSnapshot(snapshot)
                    var document = SurgeProfileDocument(snapshot.text)
                    try document.deleteRules(atSourceLines: lines)
                    try self.applyRuleChange(document.text, snapshot: snapshot,
                                             prefix: "已删除并应用 \(lines.count) 条规则", selection: [])
                } catch {
                    self.showError(title: "无法删除规则", error: error)
                }
            }
        } catch {
            showError(title: "无法删除规则", error: error)
        }
    }

    @objc private func updateRuleSets() {
        do {
            let snapshot = try ruleEditingSnapshot()
            let locations = selectedRuleSetLocations
            guard !locations.isEmpty else { return }
            try applyRuleChange(snapshot.text, snapshot: snapshot,
                                prefix: "已更新并应用 \(locations.count) 个规则集",
                                selection: selectedRuleSourceLines,
                                forceRefreshLocations: locations)
        } catch {
            showError(title: "无法更新规则集", error: error)
        }
    }

    private func applyRuleChange(_ text: String, snapshot: (text: String, revision: Int),
                                 prefix: String, selection: Set<Int>,
                                 forceRefreshLocations: Set<String> = []) throws {
        try verifyRuleEditingSnapshot(snapshot)
        _ = try ProfileParser.parse(text)
        let requestID = UUID()
        ruleOperationID = requestID
        ruleStatusLabel.stringValue = forceRefreshLocations.isEmpty
            ? "正在后台保存并应用规则…"
            : "正在后台更新 \(forceRefreshLocations.count) 个规则集，界面可继续使用…"
        ruleStatusLabel.textColor = .systemBlue
        ruleStatusLabel.toolTip = nil
        updateRuleSelectionControls()
        let recoveryGuard = ProfileApplyCommitGuard(generation: profileApplyGeneration &+ 1,
                                                     revision: snapshot.revision,
                                                     editorText: snapshot.text)
        applyProfileTextInBackground(
            text, prefix: prefix, keepEditorOnFailure: true,
            forceRefreshRuleSetLocations: forceRefreshLocations,
            stillApplicable: { [weak self] in self?.ruleOperationID == requestID }
        ) { [weak self] result in
            guard let self, self.ruleOperationID == requestID else { return }
            self.ruleOperationID = nil
            switch result {
            case .success:
                let warnings = (self.resolvedProfile?.warnings ?? [])
                    .filter { $0.contains("RULE-SET") && $0.contains("更新失败") }
                self.ruleStatusLabel.stringValue = warnings.isEmpty ? prefix
                    : (forceRefreshLocations.isEmpty ? prefix + "；部分资源使用旧缓存"
                       : "规则集检查已完成；部分更新失败，已继续使用旧缓存")
                self.ruleStatusLabel.textColor = warnings.isEmpty ? .systemGreen : .systemOrange
                self.ruleStatusLabel.toolTip = warnings.isEmpty ? nil : warnings.joined(separator: "\n")
                self.refreshRulesPage(selecting: selection)
            case .failure(let error):
                // Keep a recoverable UI draft only if no newer edit replaced
                // its baseline or superseded the save, even with identical text.
                // The disk and running configuration stay intact.
                let keepDraft = text != snapshot.text &&
                    recoveryGuard.isCurrent(generation: self.profileApplyGeneration,
                                            revision: self.profileRevision,
                                            editorText: self.profileTextView.string)
                if keepDraft { self.profileTextView.string = text }
                self.refreshRulesPage()
                self.ruleStatusLabel.stringValue = "未应用：\(error.localizedDescription)"
                    
                self.ruleStatusLabel.textColor = .systemRed
                self.ruleStatusLabel.toolTip = error.localizedDescription
            }
            self.updateRuleSelectionControls()
        }
    }

    @objc private func addProxy() {
        presentProxyEditor(draft: nil, originalName: nil, isNew: true)
    }

    @objc private func importShareLinks() {
        guard let window else { return }
        ShareLinkImportSheetController.present(
            on: window,
            title: "导入分享链接",
            confirmTitle: "导入节点",
            allowMultiple: true
        ) { [weak self] rawLinks in
            guard let self else { return }
            do {
                let result = try self.commitShareLinks(rawLinks)
                let shownNames = result.names.prefix(8).joined(separator: "、")
                var message = "已添加 \(result.names.count) 个节点：\(shownNames)"
                if result.names.count > 8 { message += " 等" }
                if !result.warnings.isEmpty {
                    message += "\n\n" + result.warnings.prefix(8).joined(separator: "\n")
                    if result.warnings.count > 8 {
                        message += "\n另有 \(result.warnings.count - 8) 条提示"
                    }
                }
                if self.subscriptions.isActiveSubscriptionRemoteURL {
                    message += "\n\n提示：当前使用的是 URL 下载的订阅配置，更新订阅会覆盖原文件中新增的节点或策略组信息。"
                }
                self.showMessage(title: "分享链接已导入", text: message)
            } catch {
                self.showError(title: "导入分享链接失败", error: error)
            }
        }
    }

    @objc private func addPolicyGroup() {
        presentGroupEditor(draft: nil, originalName: nil, isNew: true)
    }

    @objc private func editSelectedProxy() {
        let row = proxyTableView.clickedRow >= 0 ? proxyTableView.clickedRow : proxyTableView.selectedRow
        guard filteredProxyNames.indices.contains(row) else { return }
        editProxy(named: filteredProxyNames[row])
    }

    @objc private func proxyMenuEdit(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        editProxy(named: name)
    }

    @objc private func proxyMenuDuplicate(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String,
              let policy = profile.proxies[name] else { return }
        var draft = SurgeProxyDraft(policy: policy)
        draft.name = uniqueProxyName(basedOn: name)
        presentProxyEditor(draft: draft, originalName: nil, isNew: true)
    }

    @objc private func proxyMenuDelete(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        confirmDeleteProxy(named: name)
    }

    @objc private func proxyMenuUse(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        useProxy(named: name)
    }

    @objc private func proxyMenuTest(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        testNode(named: name)
    }

    @objc private func groupMenuEdit(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String,
              let group = profile.groups[name] else { return }
        presentGroupEditor(draft: SurgePolicyGroupDraft(group: group),
                           originalName: name, isNew: false)
    }

    @objc private func groupMenuDuplicate(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String,
              let group = profile.groups[name] else { return }
        var draft = SurgePolicyGroupDraft(group: group)
        draft.name = uniqueGroupName(basedOn: name)
        presentGroupEditor(draft: draft, originalName: nil, isNew: true)
    }

    @objc private func groupMenuDelete(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        confirmDeleteGroup(named: name)
    }

    @objc private func testAllNodes() {
        cancelNodeTests(refresh: false)
        for name in profile.proxyOrder { nodeLatencies[name] = .queued }
        nodeProbeBatch = NodeProbeBatchCursor(names: profile.proxyOrder)
        policyStatusLabel.stringValue = "正在测试 \(profile.proxyOrder.count) 个节点（独立并发队列 24，排队不计入延迟）…"
        policyStatusLabel.textColor = .systemBlue
        pumpNodeProbeBatch(refreshStarts: false)
        schedulePolicyCardUpdates(proxies: Set(profile.proxyOrder), immediately: true)
    }

    private func isEditableProxy(named name: String) -> Bool {
        guard let policy = profile.proxies[name],
              policy.kind != .direct, policy.kind != .reject else { return false }
        if policy.adapterType?.lowercased() == "wireguard" {
            return SurgeProfileDocument(profileTextView.string).containsProxy(named: name)
        }
        return true
    }

    private func editProxy(named name: String) {
        guard isEditableProxy(named: name) else {
            showMessage(title: "请在原始配置中编辑",
                        text: "“\(name)”来自 [WireGuard \(name)] 等独立配置段，暂不支持直接编辑；它仍可复制为新的 [Proxy] 节点。")
            return
        }
        guard let policy = profile.proxies[name] else { return }
        presentProxyEditor(draft: SurgeProxyDraft(policy: policy), originalName: name, isNew: false)
    }

    private func editPolicyGroup(named name: String) {
        guard let group = profile.groups[name] else { return }
        presentGroupEditor(draft: SurgePolicyGroupDraft(group: group), originalName: name, isNew: false)
    }

    private func presentProxyEditor(draft: SurgeProxyDraft?, originalName: String?, isNew: Bool) {
        guard let window, nodeEditor == nil else { return }
        let unavailable = Set(profile.proxies.keys).union(profile.groups.keys)
        let editor = SurgeProxyEditorController(draft: draft, isNew: isNew,
                                                unavailableNames: unavailable,
                                                availableProxyNames: profile.proxyOrder) { [weak self] updated in
            guard let self else { return }
            try self.commitProxyDraft(updated, originalName: originalName)
        }
        nodeEditor = editor
        guard let sheet = editor.window else { nodeEditor = nil; return }
        window.beginSheet(sheet) { [weak self] _ in self?.nodeEditor = nil }
    }

    private func presentGroupEditor(draft: SurgePolicyGroupDraft?, originalName: String?, isNew: Bool) {
        guard let window, groupEditor == nil, nodeEditor == nil else { return }
        let unavailable = Set(profile.proxies.keys).union(profile.groups.keys)
        var policies = profile.groupOrder + profile.proxyOrder
        for builtin in ["DIRECT", "REJECT"] where !policies.contains(builtin) { policies.append(builtin) }
        let editor = PolicyGroupEditorController(draft: draft, isNew: isNew,
                                                 unavailableNames: unavailable,
                                                 availablePolicies: policies) { [weak self] updated in
            guard let self else { return }
            try self.commitGroupDraft(updated, originalName: originalName)
        }
        groupEditor = editor
        guard let sheet = editor.window else { groupEditor = nil; return }
        window.beginSheet(sheet) { [weak self] _ in self?.groupEditor = nil }
    }

    private func notifyURLSubscriptionEditIfNeeded() {
        guard subscriptions.isActiveSubscriptionRemoteURL,
              let sub = subscriptions.activeSubscription else { return }
        policyStatusLabel.stringValue += "（URL 订阅提示：更新订阅会覆盖新增或修改的节点/策略组）"
        DispatchQueue.main.async { [weak self] in
            guard let self, let window = self.window else { return }
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = "已保存到配置文件（URL 订阅提示）"
            alert.informativeText = "当前使用的是 URL 下载的订阅配置“\(sub.name)”，本次编辑的节点或策略组已直接保存到本地配置文件，下次打开应用无需重新添加。\n\n请注意：后续如果执行“更新订阅”，远程下载的订阅内容将会覆盖原文件中新增或修改的节点与策略组信息。"
            alert.addButton(withTitle: "知道了")
            alert.beginSheetModal(for: window, completionHandler: nil)
        }
    }

    private func commitProxyDraft(_ draft: SurgeProxyDraft, originalName: String?) throws {
        var document = SurgeProfileDocument(profileTextView.string)
        try document.upsertProxy(originalName: originalName, draft: draft,
                                 appendToSelectGroups: originalName == nil)

        let oldSelectedPolicy = selectedPolicy
        let preferredPolicy = oldSelectedPolicy == originalName ? draft.name : oldSelectedPolicy
        let previousSelections = groupSelections
        let oldLatency = originalName.flatMap { nodeLatencies[$0] }
        let oldHost = originalName.flatMap { profile.proxies[$0]?.host }
        let oldPort = originalName.flatMap { profile.proxies[$0]?.port }
        let replacedPolicy: (from: String, to: String)? =
            (originalName != nil && originalName != draft.name) ? (originalName!, draft.name) : nil
        if let originalName, originalName != draft.name {
            for (group, member) in groupSelections where member == originalName {
                groupSelections[group] = draft.name
            }
        }
        do {
            try applyProfileText(document.text, prefix: originalName == nil ? "已添加并应用节点" : "已更新并应用节点",
                                 preferredPolicy: preferredPolicy,
                                 reusingRulesFrom: profile,
                                 replacedRulePolicy: replacedPolicy)
        } catch {
            groupSelections = previousSelections
            throw error
        }
        if let originalName, originalName != draft.name,
           let oldLatency, oldHost == draft.host, oldPort == draft.port {
            nodeLatencies[draft.name] = oldLatency
            schedulePolicyCardUpdates(proxies: [draft.name])
        }
        policyStatusLabel.stringValue = "✓ \(draft.name) 已保存到配置文件" +
            ((engineStatus == .running || engineStatus == .starting) ? "，代理引擎已热重载" : "")
        policyStatusLabel.textColor = .systemGreen
        notifyURLSubscriptionEditIfNeeded()
    }

    private func commitShareLinks(_ text: String) throws
        -> (names: [String], warnings: [String]) {
        let parsed = try ShareLinkSubscription.parse(text)
        var document = SurgeProfileDocument(profileTextView.string)
        var used = Set(profile.proxies.keys).union(profile.groups.keys)
        var names: [String] = []
        var drafts: [SurgeProxyDraft] = []
        var warnings = parsed.warnings

        for policy in parsed.proxies {
            var draft = SurgeProxyDraft(policy: policy)
            let original = draft.name
            var candidate = original
            var suffix = 2
            while used.contains(candidate) {
                candidate = "\(original) \(suffix)"
                suffix += 1
            }
            if candidate != original {
                warnings.append("节点名已调整：\(original) → \(candidate)")
            }
            draft.name = candidate
            drafts.append(draft)
            used.insert(candidate)
            names.append(candidate)
        }
        try document.insertProxies(drafts, appendToSelectGroups: true)

        try applyProfileText(document.text, prefix: "已导入分享链接",
                             preferredPolicy: selectedPolicy,
                             reusingRulesFrom: profile)
        policyStatusLabel.stringValue = "✓ 已从分享链接导入 \(names.count) 个节点并保存到配置文件"
        policyStatusLabel.textColor = .systemGreen
        notifyURLSubscriptionEditIfNeeded()
        return (names, warnings)
    }

    private func commitGroupDraft(_ draft: SurgePolicyGroupDraft, originalName: String?) throws {
        var document = SurgeProfileDocument(profileTextView.string)
        try document.upsertGroup(originalName: originalName, draft: draft)
        let preferredPolicy = selectedPolicy == originalName ? draft.name : selectedPolicy
        let previousSelections = groupSelections
        let replacedPolicy: (from: String, to: String)? =
            (originalName != nil && originalName != draft.name) ? (originalName!, draft.name) : nil
        if let originalName, originalName != draft.name {
            let oldSelection = groupSelections.removeValue(forKey: originalName)
            if let oldSelection, draft.members.contains(oldSelection) {
                groupSelections[draft.name] = oldSelection
            }
            for (group, member) in groupSelections where member == originalName {
                groupSelections[group] = draft.name
            }
        }
        do {
            try applyProfileText(document.text,
                                 prefix: originalName == nil ? "已添加并应用策略组" : "已更新并应用策略组",
                                 preferredPolicy: preferredPolicy,
                                 preferredGroup: draft.name,
                                 reusingRulesFrom: profile,
                                 replacedRulePolicy: replacedPolicy)
        } catch {
            groupSelections = previousSelections
            throw error
        }
        policyStatusLabel.stringValue = "✓ 策略组 \(draft.name) 已保存到配置文件并应用"
        policyStatusLabel.textColor = .systemGreen
        notifyURLSubscriptionEditIfNeeded()
    }

    private func confirmDeleteProxy(named name: String) {
        guard isEditableProxy(named: name) else {
            showMessage(title: "不能在节点列表删除",
                        text: "该节点来自独立的 WireGuard 配置段，请通过更新或更换订阅移除。")
            return
        }
        let groupReferences = profile.groups.values.filter { $0.members.contains(name) }.count
        let ruleReferences = profile.rules.filter { $0.policy == name }.count
        let dialerReferences = profile.adapterPolicies.filter {
            $0.parameters["underlying-proxy"] == name || $0.parameters["dialer-proxy"] == name
        }.count
        let alert = NSAlert()
        alert.messageText = "删除节点“\(name)”？"
        alert.informativeText = "将从 \(groupReferences) 个策略组移除，并把 \(ruleReferences) 条规则、\(dialerReferences) 个底层代理引用改为 DIRECT。修改会立即写入并应用。"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "删除")
        alert.addButton(withTitle: "取消")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self else { return }
            do {
                var updated = SurgeProfileDocument(self.profileTextView.string)
                try updated.deleteProxy(named: name)
                let preferred = self.selectedPolicy == name ? "DIRECT" : self.selectedPolicy
                try self.applyProfileText(updated.text, prefix: "已删除并应用节点",
                                          preferredPolicy: preferred,
                                          reusingRulesFrom: self.profile,
                                          replacedRulePolicy: (name, "DIRECT"))
                self.policyStatusLabel.stringValue = "✓ 已删除 \(name)，相关引用已安全更新"
                self.policyStatusLabel.textColor = .systemGreen
                self.notifyURLSubscriptionEditIfNeeded()
            } catch {
                self.showError(title: "删除节点失败", error: error)
            }
        }
    }

    private func confirmDeleteGroup(named name: String) {
        let nestedReferences = profile.groups.values.filter { $0.name != name && $0.members.contains(name) }.count
        let ruleReferences = profile.rules.filter { $0.policy == name }.count
        let alert = NSAlert()
        alert.messageText = "删除策略组“\(name)”？"
        alert.informativeText = "将从 \(nestedReferences) 个上级策略组移除，并把 \(ruleReferences) 条规则引用切换到 DIRECT。"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "删除")
        alert.addButton(withTitle: "取消")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self else { return }
            do {
                var document = SurgeProfileDocument(self.profileTextView.string)
                try document.deleteGroup(named: name)
                let preferred = self.selectedPolicy == name ? "DIRECT" : self.selectedPolicy
                try self.applyProfileText(document.text, prefix: "已删除并应用策略组",
                                          preferredPolicy: preferred,
                                          reusingRulesFrom: self.profile,
                                          replacedRulePolicy: (name, "DIRECT"))
                self.policyStatusLabel.stringValue = "✓ 已删除策略组 \(name)"
                self.policyStatusLabel.textColor = .systemGreen
                self.notifyURLSubscriptionEditIfNeeded()
            } catch { self.showError(title: "删除策略组失败", error: error) }
        }
    }

    private func useProxy(named name: String) {
        guard profile.groups[name] == nil, profile.selectablePolicies.contains(name) else { return }
        modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: .proxy) ?? 2)
        policyPopup.selectItem(withTitle: name)
        policyPopup.isEnabled = true
        UserDefaults.standard.set(OutboundMode.proxy.rawValue, forKey: "outboundMode")
        UserDefaults.standard.set(name, forKey: "globalPolicy")
        updateEngineRouting()
        updateOverviewDetails()
        refreshActiveProxyCards()
        policyStatusLabel.stringValue = "✓ 全局代理已切换到 \(name)，新连接立即使用"
        policyStatusLabel.textColor = .systemGreen
    }

    private func testNode(named name: String) {
        // A new manual test supersedes a running bulk round. No old queued or
        // late callback may overwrite the fresh per-node request identifier.
        if nodeProbeBatch != nil { cancelNodeTests() }
        policyStatusLabel.stringValue = "正在测试节点 TCP 建连延迟（排队不计入延迟）…"
        policyStatusLabel.textColor = .systemBlue
        startNodeProbe(named: name, requestID: UUID(), batchID: nil, refreshStart: true)
    }

    private func startNodeProbe(named name: String, requestID: UUID, batchID: UUID?, refreshStart: Bool) {
        nodeProbeTickets.removeValue(forKey: name)?.cancel()
        nodeProbeRequests[name] = requestID
        let epoch = nodeProbeEpoch
        guard let policy = profile.proxies[name], let host = policy.host, let port = policy.port else {
            // Keep even invalid-node completions asynchronous so a large
            // invalid profile cannot recursively refill the entire batch.
            DispatchQueue.main.async { [weak self] in
                self?.finishNodeProbe(named: name, requestID: requestID, batchID: batchID,
                                      epoch: epoch, result: .failure(NWError.posix(.EINVAL)))
            }
            return
        }
        nodeLatencies[name] = .testing
        if refreshStart { schedulePolicyCardUpdates(proxies: [name]) }
        let isUDP = TCPNodeLatencyProbe.usesUDPTransport(policy)
        nodeProbeTickets[name] = TCPNodeLatencyProbe.measure(host: host, port: port, udp: isUDP) { [weak self] result in
            self?.finishNodeProbe(named: name, requestID: requestID, batchID: batchID, epoch: epoch, result: result)
        }
    }

    private func finishNodeProbe(named name: String, requestID: UUID, batchID: UUID?, epoch: UInt64,
                                 result: Result<Int, Error>) {
        guard nodeProbeEpoch == epoch, nodeProbeRequests[name] == requestID else { return }
        nodeProbeRequests.removeValue(forKey: name)
        nodeProbeTickets.removeValue(forKey: name)
        switch result {
        case .success(let milliseconds): nodeLatencies[name] = .success(milliseconds)
        case .failure(let error):
            nodeLatencies[name] = NodeLatency.from(error: error)
        }
        schedulePolicyCardUpdates(proxies: [name])
        if let batchID, nodeProbeBatch?.id == batchID {
            nodeProbeBatch?.finish(requestID)
            pumpNodeProbeBatch()
        } else if nodeProbeRequests.isEmpty, nodeProbeBatch == nil {
            policyStatusLabel.stringValue = "节点 TCP 延迟测试完成；超限或排队超时不代表节点不可达"
            policyStatusLabel.textColor = .secondaryLabelColor
        }
        onStatusBarStateChanged?()
    }

    private func pumpNodeProbeBatch(refreshStarts: Bool = true) {
        guard let batchID = nodeProbeBatch?.id else { return }
        while let request = nodeProbeBatch?.takeNext() {
            startNodeProbe(named: request.name, requestID: request.id, batchID: batchID,
                           refreshStart: refreshStarts)
        }
        if nodeProbeBatch?.isComplete == true {
            let names = nodeProbeBatch?.names ?? []
            let successes = names.reduce(0) { count, name in
                if case .success? = nodeLatencies[name] { return count + 1 }; return count
            }
            let deferred = names.reduce(0) { count, name in
                if case .unavailable(let failure)? = nodeLatencies[name], failure != .requestExpired {
                    return count + 1
                }; return count
            }
            nodeProbeBatch = nil
            policyStatusLabel.stringValue = "延迟测试完成：\(successes) 个可建立 TCP 连接，\(deferred) 个未测试（资源或排队限制）"
            policyStatusLabel.textColor = .secondaryLabelColor
        }
    }

    private func cancelNodeTests(refresh: Bool = true) {
        let wasTesting = !nodeProbeRequests.isEmpty || nodeProbeBatch != nil
        nodeProbeEpoch &+= 1
        let tickets = Array(nodeProbeTickets.values)
        nodeProbeTickets.removeAll(); nodeProbeRequests.removeAll(); nodeProbeBatch = nil
        var changed = Set<String>()
        for (name, latency) in nodeLatencies where latency == .testing || latency == .queued {
            nodeLatencies[name] = .untested
            changed.insert(name)
        }
        tickets.forEach { $0.cancel() }
        if wasTesting {
            policyStatusLabel.stringValue = "上一轮测速已取消，旧结果不会覆盖当前配置"
            policyStatusLabel.textColor = .secondaryLabelColor
        }
        if refresh { schedulePolicyCardUpdates(proxies: changed) }
        else { pendingProxyCards.formUnion(changed) }
    }

    private func uniqueProxyName(basedOn name: String) -> String {
        let base = name + " 副本"
        if profile.proxies[base] == nil, profile.groups[base] == nil { return base }
        var index = 2
        while profile.proxies["\(base) \(index)"] != nil || profile.groups["\(base) \(index)"] != nil {
            index += 1
        }
        return "\(base) \(index)"
    }

    private func uniqueGroupName(basedOn name: String) -> String {
        let base = name + " 副本"
        if profile.groups[base] == nil, profile.proxies[base] == nil { return base }
        var index = 2
        while profile.groups["\(base) \(index)"] != nil || profile.proxies["\(base) \(index)"] != nil {
            index += 1
        }
        return "\(base) \(index)"
    }

    private func setGroupSelection(group name: String, member: String?) {
        if let member {
            if let group = profile.groups[name], PolicyHealthMonitor.managesSelection(of: group) {
                manualManagedGroupSelections.insert(name)
            }
            groupSelections[name] = member
        } else {
            manualManagedGroupSelections.remove(name)
            if let autoMember = policyHealth.currentSelections[name] {
                groupSelections[name] = autoMember
            } else {
                groupSelections.removeValue(forKey: name)
            }
        }
        UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
        if selectedGroup == name { refreshGroupMembers() }
        updateEngineRouting()
        updateOverviewDetails()
        schedulePolicyCardUpdates(groups: [name])
        policyStatusLabel.stringValue = member.map { "✓ \(name) 已切换到 \($0)" } ?? "✓ \(name) 已恢复配置默认行为"
        policyStatusLabel.textColor = .systemGreen
        onStatusBarStateChanged?()
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        if menu === rulesTableView.menu {
            menu.removeAllItems()
            let row = rulesTableView.clickedRow
            if filteredRules.indices.contains(row), !rulesTableView.selectedRowIndexes.contains(row) {
                rulesTableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            }
            updateRuleSelectionControls()
            func add(_ title: String, _ action: Selector, enabled: Bool) {
                let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
                item.target = self
                item.isEnabled = enabled
                menu.addItem(item)
            }
            add("新增规则…", #selector(addRule), enabled: ruleAddButton.isEnabled)
            add(ruleEditButton.title + "…", #selector(editSelectedRules), enabled: ruleEditButton.isEnabled)
            add("删除选中规则…", #selector(deleteSelectedRules), enabled: ruleDeleteButton.isEnabled)
            menu.addItem(.separator())
            add(selectedRuleSourceLines.isEmpty ? "更新全部规则集" : "更新选中规则集",
                #selector(updateRuleSets), enabled: ruleUpdateButton.isEnabled)
            menu.addItem(.separator())
            add("全选当前搜索结果", #selector(selectAllRules), enabled: ruleSelectAllButton.isEnabled)
            add("取消选择", #selector(clearRuleSelection), enabled: ruleClearSelectionButton.isEnabled)
            return
        }
        guard menu === proxyTableView.menu else { return }
        menu.removeAllItems()
        let row = proxyTableView.clickedRow >= 0 ? proxyTableView.clickedRow : proxyTableView.selectedRow
        guard filteredProxyNames.indices.contains(row) else { return }
        populateProxyMenu(menu, name: filteredProxyNames[row])
    }

    private func makeProxyMenu(name: String) -> NSMenu {
        let menu = NSMenu(title: name)
        populateProxyMenu(menu, name: name)
        return menu
    }

    @objc private func groupMenuToggleStatusBar(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String,
              let group = profile.groups[name] else { return }
        var draft = SurgePolicyGroupDraft(group: group)
        if group.showsInStatusBar {
            draft.parameters["show-in-status-bar"] = "false"
        } else if draft.parameters["hidden"].map({ ["true", "yes", "on", "1"].contains($0.lowercased()) }) == true {
            draft.parameters["show-in-status-bar"] = "true"
        } else {
            draft.parameters.removeValue(forKey: "show-in-status-bar")
        }
        do {
            try commitGroupDraft(draft, originalName: name)
            onStatusBarStateChanged?()
        } catch {
            showError(title: "无法更新状态栏显示设置", error: error)
        }
    }

    private func makeGroupMenu(name: String) -> NSMenu {
        let menu = NSMenu(title: name)
        func item(_ title: String, _ action: Selector) -> NSMenuItem {
            let value = NSMenuItem(title: title, action: action, keyEquivalent: "")
            value.target = self
            value.representedObject = name
            return value
        }
        let statusItemToggle = item("在顶部状态栏菜单中显示", #selector(groupMenuToggleStatusBar(_:)))
        statusItemToggle.state = (profile.groups[name]?.showsInStatusBar ?? true) ? .on : .off
        menu.addItem(statusItemToggle)
        menu.addItem(.separator())
        menu.addItem(item("编辑成员与选项…", #selector(groupMenuEdit(_:))))
        menu.addItem(item("复制策略组…", #selector(groupMenuDuplicate(_:))))
        menu.addItem(.separator())
        menu.addItem(item("删除策略组…", #selector(groupMenuDelete(_:))))
        return menu
    }

    private func populateProxyMenu(_ menu: NSMenu, name: String) {
        let editable = isEditableProxy(named: name)
        func item(_ title: String, _ action: Selector, enabled: Bool = true) -> NSMenuItem {
            let value = NSMenuItem(title: title, action: action, keyEquivalent: "")
            value.target = self
            value.representedObject = name
            value.isEnabled = enabled
            return value
        }
        menu.addItem(item("作为全局代理使用", #selector(proxyMenuUse(_:))))
        menu.addItem(item("测试 TCP 延迟", #selector(proxyMenuTest(_:))))
        menu.addItem(.separator())
        menu.addItem(item("编辑…", #selector(proxyMenuEdit(_:)), enabled: editable))
        menu.addItem(item("复制…", #selector(proxyMenuDuplicate(_:))))
        menu.addItem(item("删除…", #selector(proxyMenuDelete(_:)), enabled: editable))
    }

    @objc private func validateProfile() {
        let text = profileTextView.string
        let proxy = ruleSetDownloadProxy
        profileValidationGeneration += 1
        let generation = profileValidationGeneration
        profileStatus.stringValue = "正在解析 Surge Profile、更新 RULE-SET 并检查出站…"
        profileStatus.textColor = .systemBlue
        profileStatus.toolTip = nil
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result: Result<Profile, Error>
            do {
                let value = try ProfileParser.parse(text)
                let resolved = try self.surgeRuleSets.prepare(profile: value, httpProxy: proxy)
                try self.protocolAdapters.validate(profile: resolved)
                result = .success(resolved)
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async {
                guard generation == self.profileValidationGeneration,
                      text == self.profileTextView.string else { return }
                switch result {
                case .success(let value):
                    self.applyProfileValidationStatus(value, prefix: "配置有效")
                case .failure(let error):
                    self.profileStatus.stringValue = "✕ \(error.localizedDescription)"
                    self.profileStatus.textColor = .systemRed
                    self.profileStatus.toolTip = error.localizedDescription
                }
            }
        }
    }

    @objc private func saveProfile() {
        applyProfileTextInBackground(profileTextView.string, prefix: "已保存并重载")
    }

    /// Resolve remote RULE-SETs away from AppKit's main thread. The editor,
    /// running profile and subscription definitions are checked again before
    /// anything is written, since preparation may outlive a user's next edit.
    private func applyProfileTextInBackground(
        _ text: String, prefix: String, keepEditorOnFailure: Bool = false,
        allowExternalChanges: Bool = false,
        forceRefreshRuleSetLocations: Set<String> = [],
        stillApplicable: @escaping () -> Bool = { true },
        completion: @escaping (Result<Void, Error>) -> Void = { _ in }
    ) {
        profileApplyGeneration &+= 1
        profileValidationGeneration &+= 1
        let guardState = ProfileApplyCommitGuard(generation: profileApplyGeneration,
                                                 revision: profileRevision,
                                                 editorText: profileTextView.string)
        activeProfilePreparationGeneration = guardState.generation
        let expectedStoredText = allowExternalChanges ? text : lastKnownStoredProfileText
        let existingResolved = resolvedProfile
        let proxy = ruleSetDownloadProxy
        profileStatus.stringValue = "正在后台准备 RULE-SET…"
        profileStatus.textColor = .systemBlue
        profileStatus.toolTip = nil
        ruleSetPreparationQueue.async { [weak self] in
            guard let self else { return }
            let prepared: Result<(parsed: Profile, resolved: Profile), Error> = Result {
                let parsed = try ProfileParser.parse(text)
                let referencedLocations = Set(parsed.ruleSetReferences.map(\.location))
                if forceRefreshRuleSetLocations.isEmpty,
                   let existingResolved,
                   referencedLocations.isSubset(of: Set(existingResolved.ruleSetContents.keys)) {
                    var reused = parsed
                    for location in referencedLocations {
                        reused.ruleSetContents[location] = existingResolved.ruleSetContents[location]
                    }
                    if !reused.adoptCompiledRoutingRules(from: existingResolved) {
                        reused.prepareCompiledRoutingRules()
                    }
                    return (parsed, reused)
                }
                if forceRefreshRuleSetLocations.isEmpty {
                    do {
                        return (parsed, try self.surgeRuleSets.prepare(profile: parsed, mode: .cacheOnly))
                    } catch let error as SurgeRuleSetManager.RuleSetError where error.isMissingCache {
                        // Fall through to download missing cache entries.
                    }
                }
                return (parsed, try self.surgeRuleSets.prepare(
                    profile: parsed, forceRefreshLocations: forceRefreshRuleSetLocations,
                    httpProxy: proxy))
            }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                if self.activeProfilePreparationGeneration == guardState.generation {
                    self.activeProfilePreparationGeneration = nil
                }
                guard guardState.isCurrent(generation: self.profileApplyGeneration,
                                           revision: self.profileRevision,
                                           editorText: self.profileTextView.string),
                      stillApplicable() else {
                    let error = ProfileApplyError.message(
                        "配置或订阅在准备规则集期间已更改，未覆盖新内容，请重试")
                    if guardState.generation == self.profileApplyGeneration {
                        self.reportProfileApplyFailure(error)
                    }
                    completion(.failure(error))
                    return
                }
                do {
                    let result = try prepared.get()
                    try self.applyPreparedProfileText(text, parsed: result.parsed,
                                                      resolved: result.resolved,
                                                      prefix: prefix,
                                                      preferredPolicy: self.selectedPolicy,
                                                      keepEditorOnFailure: keepEditorOnFailure,
                                                      expectedStoredText: expectedStoredText)
                    completion(.success(()))
                } catch {
                    self.reportProfileApplyFailure(error)
                    completion(.failure(error))
                }
            }
        }
    }

    private func reportProfileApplyFailure(_ error: Error) {
        profileStatus.stringValue = "✕ \(error.localizedDescription)"
        profileStatus.textColor = .systemRed
        profileStatus.toolTip = error.localizedDescription
    }

    private func verifyStoredProfileHasNotChanged(expected: String?) throws {
        guard let expected else { return } // Allow repair when the initial file was unreadable.
        let actual = try configurationStore.loadTextThrowing()
        guard ProfileApplyCommitGuard.diskTextMatches(expected: expected, actual: actual) else {
            throw ProfileApplyError.message(
                "配置文件已由其他程序修改，未覆盖磁盘更改；请重新加载配置后再试")
        }
    }

    private func autoManagedHealthGroupsChanged(from oldProfile: Profile, to newProfile: Profile) -> Bool {
        let oldManaged = oldProfile.groups.filter { PolicyHealthMonitor.managesSelection(of: $0.value) }
        let newManaged = newProfile.groups.filter { PolicyHealthMonitor.managesSelection(of: $0.value) }
        guard oldManaged == newManaged else { return true }
        guard !newManaged.isEmpty else { return false }
        for group in newManaged.values {
            for member in group.members {
                if oldProfile.proxies[member] != newProfile.proxies[member] ||
                   oldProfile.groups[member] != newProfile.groups[member] {
                    return true
                }
            }
        }
        return false
    }

    private func applyProfileText(_ text: String, prefix: String,
                                  preferredPolicy: String?,
                                  preferredGroup: String? = nil,
                                  keepEditorOnFailure: Bool = false,
                                  reusingRulesFrom baseProfile: Profile? = nil,
                                  replacedRulePolicy: (from: String, to: String)? = nil) throws {
        profileApplyGeneration &+= 1
        profileValidationGeneration &+= 1
        activeProfilePreparationGeneration = nil
        let expectedStoredText = lastKnownStoredProfileText
        try verifyStoredProfileHasNotChanged(expected: expectedStoredText)
        let parsed: Profile
        if let baseProfile, !baseProfile.rules.isEmpty {
            parsed = try ProfileParser.parseReusingRules(text, baseRules: baseProfile.rules,
                                                         replacedPolicy: replacedRulePolicy)
        } else {
            parsed = try ProfileParser.parse(text)
        }
        let resolved: Profile
        let referencedLocations = Set(parsed.ruleSetReferences.map(\.location))
        if let existingResolved = resolvedProfile,
           referencedLocations.isSubset(of: Set(existingResolved.ruleSetContents.keys)) {
            var reused = parsed
            for location in referencedLocations {
                reused.ruleSetContents[location] = existingResolved.ruleSetContents[location]
            }
            if !reused.adoptCompiledRoutingRules(from: existingResolved) {
                reused.prepareCompiledRoutingRules()
            }
            resolved = reused
        } else {
            do {
                resolved = try surgeRuleSets.prepare(profile: parsed, mode: .cacheOnly)
            } catch let error as SurgeRuleSetManager.RuleSetError where error.isMissingCache {
                resolved = try surgeRuleSets.prepare(profile: parsed, httpProxy: ruleSetDownloadProxy)
            }
        }
        try applyPreparedProfileText(text, parsed: parsed, resolved: resolved,
                                     prefix: prefix, preferredPolicy: preferredPolicy,
                                     preferredGroup: preferredGroup,
                                     keepEditorOnFailure: keepEditorOnFailure,
                                     expectedStoredText: expectedStoredText,
                                     alreadyVerifiedStoredText: true)
    }

    private func applyPreparedProfileText(_ text: String, parsed: Profile,
                                          resolved: Profile, prefix: String,
                                          preferredPolicy: String?,
                                          preferredGroup: String? = nil,
                                          keepEditorOnFailure: Bool = false,
                                          expectedStoredText: String? = nil,
                                          alreadyVerifiedStoredText: Bool = false) throws {
        try protocolAdapters.validate(profile: resolved)
        if systemProxyIsOrWillBeEnabled && parsed.httpListen != profile.httpListen {
            throw ProfileApplyError.message("HTTP 监听地址已变化。请先在总览中关闭系统代理。")
        }
        if systemProxyIsOrWillBeEnabled && parsed.proxyBypassDomains != profile.proxyBypassDomains {
            throw ProfileApplyError.message("Surge skip-proxy 绕过列表已变化。请先关闭系统代理。")
        }
        let wasRunning = engineStatus == .running || engineStatus == .starting
        let wasEnhanced = enhancedMode.isRequested || enhancedMode.isEnabled
        if !alreadyVerifiedStoredText {
            try verifyStoredProfileHasNotChanged(expected: expectedStoredText)
        }
        let oldStoredText: String
        if let expectedStoredText {
            oldStoredText = expectedStoredText
        } else {
            oldStoredText = wasRunning || wasEnhanced
                ? try configurationStore.loadTextThrowing() : configurationStore.loadText()
        }
        let oldEditorText = profileTextView.string
        let oldProfile = profile
        let oldResolved = resolvedProfile
        let oldSelectedPolicy = selectedPolicy
        let oldSelectedGroup = selectedGroup
        let oldGroupSelections = groupSelections
        let oldLatencies = nodeLatencies.mapValues { $0 == .testing || $0 == .queued ? .untested : $0 }
        let oldPolicyLatencies = policyLatencies
        try configurationStore.save(text)
        cancelNodeTests(refresh: false)
        profile = parsed
        resolvedProfile = resolved
        launchProfilePlan = .ready(parsed)
        lastKnownStoredProfileText = text
        profileRevision &+= 1
        if profileTextView.string != text {
            profileTextView.string = text
        }
        refreshPolicies(preferred: preferredPolicy)
        UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
        groupSelections = groupSelections.filter { name, member in
            parsed.groups[name]?.members.contains(member) == true
        }
        UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
        refreshGroups(preferred: preferredGroup ?? oldSelectedGroup)
        nodeLatencies = nodeLatencies.filter { name, _ in
            parsed.proxies[name] != nil && parsed.proxies[name] == oldProfile.proxies[name]
        }
        policyLatencies = policyLatencies.filter { parsed.groups[$0.key] != nil }
        let controllerSettingsChanged = parsed.httpAPI != oldProfile.httpAPI
            || parsed.httpAPIKey != oldProfile.httpAPIKey
            || parsed.externalController != oldProfile.externalController
            || parsed.externalControllerKey != oldProfile.externalControllerKey

        if wasRunning || wasEnhanced {
            do {
                let runtime = try protocolAdapters.prepare(profile: resolved)
                if wasEnhanced {
                    try enhancedMode.reload(profile: runtime, mode: selectedMode,
                                            globalPolicy: selectedPolicy,
                                            groupSelections: groupSelections)
                }
                if wasRunning {
                    if engineStatus == .running &&
                       parsed.httpListen == oldProfile.httpListen &&
                       parsed.socksListen == oldProfile.socksListen {
                        var runtimeProfile = runtime
                        runtimeProfile.httpListen = engine.activeHTTPListen
                        let routingConfiguration = RoutingReloadGate.Configuration(
                            profile: runtime, mode: selectedMode, globalPolicy: selectedPolicy,
                            groupSelections: groupSelections)
                        try reloadListener {
                            engine.updateConfiguration(profile: runtimeProfile, mode: selectedMode,
                                                       globalPolicy: selectedPolicy,
                                                       groupSelections: groupSelections)
                        }
                        routingReloadGate.recordApplied(routingConfiguration)
                    } else {
                        try startEngineThrowing(prepared: resolved)
                    }
                }
            } catch {
                let restored = (try? configurationStore.save(oldStoredText)) != nil
                lastKnownStoredProfileText = restored ? oldStoredText : nil
                profile = oldProfile
                resolvedProfile = oldResolved
                launchProfilePlan = .ready(oldProfile)
                profileRevision &+= 1
                let rollbackEditorText = keepEditorOnFailure ? oldEditorText : oldStoredText
                if profileTextView.string != rollbackEditorText {
                    profileTextView.string = rollbackEditorText
                }
                refreshPolicies(preferred: oldSelectedPolicy)
                UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
                groupSelections = oldGroupSelections
                UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
                nodeLatencies = oldLatencies
                policyLatencies = oldPolicyLatencies
                refreshGroups(preferred: oldSelectedGroup)
                refreshPolicyPage()
                refreshRulesPage()
                let oldRuntimeProfile = oldResolved ?? oldProfile
                if wasEnhanced,
                   let runtime = try? protocolAdapters.prepare(profile: oldRuntimeProfile) {
                    try? enhancedMode.reload(profile: runtime, mode: selectedMode,
                                             globalPolicy: oldSelectedPolicy,
                                             groupSelections: oldGroupSelections)
                }
                if wasRunning { try? startEngineThrowing(prepared: oldRuntimeProfile) }
                refreshPolicyHealth()
                if controllerSettingsChanged { restartExternalController() }
                throw ProfileApplyError.message("新配置无法启动，已恢复旧配置：\(error.localizedDescription)")
            }
        } else {
            updateEngineRouting()
        }
        refreshPolicyPage()
        if !rulesView.isHidden {
            refreshRulesPage()
        } else {
            rulesPageProfile = resolved
        }
        updateOverviewDetails()
        if autoManagedHealthGroupsChanged(from: oldProfile, to: parsed) {
            refreshPolicyHealth()
        }
        if controllerSettingsChanged { restartExternalController() }
        applyProfileValidationStatus(resolved, prefix: prefix)
        subscriptions.syncEditedProfileText(text, proxyCount: parsed.globalProxyNodes.count)
        if !settingsView.isHidden {
            refreshSubscriptionSettings()
        }
    }

    private enum ProfileApplyError: LocalizedError {
        case message(String)
        var errorDescription: String? {
            if case .message(let value) = self { return value }
            return nil
        }
    }

    @objc private func revealProfile() {
        NSWorkspace.shared.activateFileViewerSelecting([configurationStore.profileURL])
    }

    // MARK: Subscriptions

    /// Ensures that on launch, if a subscription is selected and cached, the
    /// profile does not retain mixed nodes or groups from other subscriptions
    /// or previous unbracketed imports.
    private func reconcileStartupActiveSubscription() {
        let current = profileTextView.string
        if !profile.globalProxyNodes.isEmpty || !profile.groups.isEmpty {
            subscriptions.syncEditedProfileText(current, proxyCount: profile.globalProxyNodes.count)
            return
        }
        guard let activeName = subscriptions.selectedName,
              let prepared = try? subscriptions.prepareSelection(name: activeName) else { return }
        let cleaned = SubscriptionRefreshMerge.activate(
            (name: prepared.name, contents: prepared.contents),
            toCurrentText: { current })
        guard cleaned != current,
              let parsed = try? ProfileParser.parse(cleaned) else { return }
        profile = parsed
        launchProfilePlan = .ready(parsed)
        profileTextView.string = cleaned
        try? configurationStore.save(cleaned)
        lastKnownStoredProfileText = cleaned
    }

    private func refreshSubscriptionSettings(preferredSelection: String? = nil) {
        let all = subscriptions.all
        let activeName = subscriptions.selectedName
        let currentPopupSelection = preferredSelection ?? subscriptionSelectPopup.titleOfSelectedItem ?? activeName
        subscriptionSelectPopup.removeAllItems()
        guard !all.isEmpty else {
            subscriptionSelectPopup.addItem(withTitle: "暂无订阅")
            subscriptionSelectPopup.isEnabled = false
            subscriptionUseButton.isEnabled = false
            subscriptionEditButton.isEnabled = false
            subscriptionUpdateButton.isEnabled = false
            subscriptionDeleteButton.isEnabled = false
            subscriptionSummaryLabel.stringValue = "尚未添加订阅 · 点击“导入配置…”导入本地配置文件，或点击“URL 下载…”添加远程订阅。"
            subscriptionSummaryLabel.textColor = .secondaryLabelColor
            subscriptionSummaryLabel.toolTip = subscriptionSummaryLabel.stringValue
            return
        }
        subscriptionSelectPopup.addItems(withTitles: all.map(\.name))
        if let target = currentPopupSelection, all.contains(where: { $0.name == target }) {
            subscriptionSelectPopup.selectItem(withTitle: target)
        } else if let activeName, all.contains(where: { $0.name == activeName }) {
            subscriptionSelectPopup.selectItem(withTitle: activeName)
        }
        subscriptionSelectPopup.isEnabled = true
        let highlightedName = subscriptionSelectPopup.titleOfSelectedItem ?? activeName ?? all[0].name
        let highlighted = all.first(where: { $0.name == highlightedName }) ?? all[0]
        let managedInProfile = SubscriptionMerge.managedNames(in: profileTextView.string)
        let isUsingHighlighted = highlighted.name == activeName
            && managedInProfile == [highlighted.name]
        let isLocalFile = URL(string: highlighted.url)?.isFileURL == true
        subscriptionUseButton.isEnabled = true
        subscriptionUseButton.title = isUsingHighlighted ? "正在使用" : "选择使用"
        subscriptionEditButton.isEnabled = !isLocalFile
        subscriptionEditButton.toolTip = isLocalFile
            ? "仅 URL 订阅支持编辑 URL 与自动更新时间"
            : "编辑订阅名称、替换 URL、设置是否自动更新及更新时间"
        subscriptionUpdateButton.isEnabled = !isLocalFile
        subscriptionUpdateButton.toolTip = isLocalFile
            ? "本地导入的配置文件无需 URL 更新，编辑节点与策略组会自动保存"
            : "从远程 URL 拉取最新订阅内容"
        subscriptionDeleteButton.isEnabled = true

        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        let sourceKind = isLocalFile ? "本地导入" : "URL 订阅"
        var summary = isUsingHighlighted ? "✓ 当前使用：\(highlighted.name)" : "已选择：\(highlighted.name)（当前使用：\(activeName ?? "无")）"
        summary += " · \(sourceKind)"
        if !isLocalFile {
            if highlighted.updateInterval > 0 {
                let hours = highlighted.updateInterval / 3600
                let hoursText = hours.truncatingRemainder(dividingBy: 1) == 0
                    ? "\(Int(hours))" : String(format: "%.1f", hours)
                summary += " · 自动更新 \(hoursText)h"
            } else {
                summary += " · 仅手动更新"
            }
        }
        if let format = highlighted.lastFormat { summary += " · \(format.rawValue)" }
        summary += " · \(highlighted.lastProxyCount) 个节点"
        if isLocalFile {
            summary += " · 已保存到本地配置（无需 URL 更新）"
        } else if let updated = highlighted.lastUpdated {
            summary += " · 更新于 \(formatter.string(from: updated))"
        } else {
            summary += " · 尚未更新"
        }
        if let error = highlighted.lastError {
            summary += " · ⚠︎ \(error)"
            subscriptionSummaryLabel.textColor = .systemOrange
        } else {
            subscriptionSummaryLabel.textColor = isUsingHighlighted ? .systemGreen : .secondaryLabelColor
        }
        subscriptionSummaryLabel.stringValue = summary
        subscriptionSummaryLabel.toolTip = summary
    }

    @objc private func subscriptionSelectionPopupChanged() {
        guard let name = subscriptionSelectPopup.titleOfSelectedItem,
              subscriptions.all.contains(where: { $0.name == name }) else {
            refreshSubscriptionSettings()
            return
        }
        activateSubscription(name: name, announce: false)
    }

    @objc private func useSelectedSubscriptionAction() {
        guard let name = subscriptionSelectPopup.titleOfSelectedItem,
              subscriptions.all.contains(where: { $0.name == name }) else { return }
        activateSubscription(name: name, announce: false)
    }

    @objc private func updateSelectedSubscriptionAction() {
        let selected = subscriptionSelectPopup.titleOfSelectedItem ?? subscriptions.selectedName
        guard let name = selected, subscriptions.all.contains(where: { $0.name == name }) else {
            if let first = subscriptions.selectedName ?? subscriptions.all.first?.name {
                updateSubscriptions(names: [first], announce: true)
            }
            return
        }
        updateSubscriptions(names: [name], announce: true)
    }

    @objc private func deleteSelectedSubscriptionAction() {
        let selected = subscriptionSelectPopup.titleOfSelectedItem ?? subscriptions.selectedName
        guard let name = selected, subscriptions.all.contains(where: { $0.name == name }) else { return }
        let alert = NSAlert()
        alert.messageText = "删除订阅“\(name)”？"
        alert.informativeText = "删除后，该订阅的节点与策略组将从当前配置中移除。"
        alert.addButton(withTitle: "删除")
        alert.addButton(withTitle: "取消")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self else { return }
            self.removeSubscriptionByName(name)
        }
    }

    private func removeSubscriptionByName(_ name: String) {
        let remaining = subscriptions.all.map(\.name).filter { $0 != name }
        let initialEditorText = profileTextView.string
        let wasActive = subscriptions.selectedName == name
            || SubscriptionMerge.managedNames(in: initialEditorText).contains(name)
        if wasActive, let nextName = remaining.first {
            subscriptionSummaryLabel.stringValue = "正在删除订阅并切换到“\(nextName)”…"
            subscriptionSummaryLabel.textColor = .systemBlue
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                let nextPrepared = try? self.subscriptions.prepareSelection(name: nextName)
                let precomputedText: String
                if let nextPrepared {
                    precomputedText = SubscriptionRefreshMerge.activate(
                        (name: nextPrepared.name, contents: nextPrepared.contents),
                        toCurrentText: { initialEditorText })
                } else {
                    let removed = SubscriptionMerge.remove(name: name, from: initialEditorText)
                    precomputedText = SubscriptionMerge.reconcileDanglingRulePolicies(in: removed)
                }
                DispatchQueue.main.async {
                    let currentEditorText = self.profileTextView.string
                    if let nextPrepared {
                        let text = currentEditorText == initialEditorText
                            ? precomputedText
                            : SubscriptionRefreshMerge.activate(
                                (name: nextPrepared.name, contents: nextPrepared.contents),
                                toCurrentText: { currentEditorText })
                        self.applyProfileTextInBackground(text, prefix: "已删除订阅并切换到 \(nextName)",
                                                          stillApplicable: { [weak self] in
                            self?.subscriptions.all.contains(where: { $0.name == name }) == true
                        }) { [weak self] result in
                            guard let self else { return }
                            switch result {
                            case .success:
                                self.subscriptions.remove(name: name)
                                self.subscriptions.select(name: nextName)
                                self.subscriptions.recordApplied(nextPrepared)
                                self.refreshSubscriptionSettings(preferredSelection: nextName)
                            case .failure(let error):
                                self.refreshSubscriptionSettings()
                                self.showError(title: "删除订阅失败", error: error)
                            }
                        }
                    } else {
                        let text = currentEditorText == initialEditorText
                            ? precomputedText
                            : SubscriptionMerge.reconcileDanglingRulePolicies(
                                in: SubscriptionMerge.remove(name: name, from: currentEditorText))
                        self.applyProfileTextInBackground(text, prefix: "删除订阅",
                                                          stillApplicable: { [weak self] in
                            self?.subscriptions.all.contains(where: { $0.name == name }) == true
                        }) { [weak self] result in
                            guard let self else { return }
                            switch result {
                            case .success:
                                self.subscriptions.remove(name: name)
                                self.subscriptions.select(name: nextName)
                                self.refreshSubscriptionSettings(preferredSelection: nextName)
                            case .failure(let error):
                                self.refreshSubscriptionSettings()
                                self.showError(title: "删除订阅失败", error: error)
                            }
                        }
                    }
                }
            }
            return
        }
        subscriptionSummaryLabel.stringValue = "正在删除订阅“\(name)”…"
        subscriptionSummaryLabel.textColor = .systemBlue
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let removed = SubscriptionMerge.remove(name: name, from: initialEditorText)
            let precomputedText = SubscriptionMerge.reconcileDanglingRulePolicies(in: removed)
            DispatchQueue.main.async {
                let currentEditorText = self.profileTextView.string
                let text = currentEditorText == initialEditorText
                    ? precomputedText
                    : SubscriptionMerge.reconcileDanglingRulePolicies(
                        in: SubscriptionMerge.remove(name: name, from: currentEditorText))
                self.applyProfileTextInBackground(text, prefix: "删除订阅",
                                                  stillApplicable: { [weak self] in
                    self?.subscriptions.all.contains(where: { $0.name == name }) == true
                }) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .success:
                        self.subscriptions.remove(name: name)
                        self.refreshSubscriptionSettings()
                    case .failure(let error):
                        self.refreshSubscriptionSettings()
                        self.showError(title: "删除订阅失败", error: error)
                    }
                }
            }
        }
    }

    @objc private func importSubscriptionFileAction() {
        let panel = NSOpenPanel()
        panel.title = "导入本地订阅或配置文件"
        panel.prompt = "导入并使用"
        panel.allowsOtherFileTypes = true
        panel.allowedContentTypes = ["conf", "yaml", "yml", "ini", "txt"]
            .compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard let window else { return }
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK, let url = panel.url, let self else { return }
            self.importSubscription(fromFileURL: url)
        }
    }

    private func importSubscription(fromFileURL url: URL, customName: String? = nil) {
        let suggested = customName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let rawName = suggested.isEmpty ? url.deletingPathExtension().lastPathComponent : suggested
        let initialEditorText = profileTextView.string
        subscriptionSummaryLabel.stringValue = "正在导入配置 \(url.lastPathComponent)…"
        subscriptionSummaryLabel.textColor = .systemBlue
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let imported = Result { () -> (SubscriptionManager.PreparedUpdate, String) in
                let prepared = try self.subscriptions.importFile(name: rawName, sourceURL: url)
                let precomputed = SubscriptionRefreshMerge.activate(
                    (name: prepared.name, contents: prepared.contents),
                    toCurrentText: { initialEditorText })
                return (prepared, precomputed)
            }
            DispatchQueue.main.async {
                switch imported {
                case .failure(let error):
                    self.refreshSubscriptionSettings()
                    self.showError(title: "导入配置失败", error: error)
                case .success(let (prepared, precomputed)):
                    let currentEditorText = self.profileTextView.string
                    let merged = currentEditorText == initialEditorText
                        ? precomputed
                        : SubscriptionRefreshMerge.activate(
                            (name: prepared.name, contents: prepared.contents),
                            toCurrentText: { currentEditorText })
                    self.applyProfileTextInBackground(merged, prefix: "导入并使用订阅 \(prepared.name)",
                                                      keepEditorOnFailure: true,
                                                      stillApplicable: { [weak self] in
                        self?.subscriptions.isCurrent(prepared) == true
                    }) { [weak self] result in
                        guard let self else { return }
                        switch result {
                        case .success:
                            self.subscriptions.select(name: prepared.name)
                            self.subscriptions.recordApplied(prepared)
                            self.refreshSubscriptionSettings(preferredSelection: prepared.name)
                        case .failure(let error):
                            self.subscriptions.recordFailure(name: prepared.name, error: error)
                            self.refreshSubscriptionSettings(preferredSelection: prepared.name)
                            self.showError(title: "应用导入的订阅失败", error: error)
                        }
                    }
                }
            }
        }
    }

    private func activateSubscription(name: String, announce: Bool) {
        let initialEditorText = profileTextView.string
        subscriptionSummaryLabel.stringValue = "正在切换并加载订阅“\(name)”…"
        subscriptionSummaryLabel.textColor = .systemBlue
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let preparedResult = Result { () -> (SubscriptionManager.PreparedUpdate, String) in
                let prepared = try self.subscriptions.prepareSelection(name: name)
                let precomputed = SubscriptionRefreshMerge.activate(
                    (name: prepared.name, contents: prepared.contents),
                    toCurrentText: { initialEditorText })
                return (prepared, precomputed)
            }
            DispatchQueue.main.async {
                switch preparedResult {
                case .failure(let error):
                    self.subscriptions.recordFailure(name: name, error: error)
                    self.refreshSubscriptionSettings(preferredSelection: name)
                    self.showError(title: "切换订阅失败", error: error)
                case .success(let (prepared, precomputed)):
                    guard self.subscriptions.isCurrent(prepared) else {
                        self.refreshSubscriptionSettings()
                        return
                    }
                    let currentEditorText = self.profileTextView.string
                    let merged = currentEditorText == initialEditorText
                        ? precomputed
                        : SubscriptionRefreshMerge.activate(
                            (name: prepared.name, contents: prepared.contents),
                            toCurrentText: { currentEditorText })
                    self.applyProfileTextInBackground(merged, prefix: "已切换到订阅 \(prepared.name)",
                                                      keepEditorOnFailure: true,
                                                      stillApplicable: { [weak self] in
                        self?.subscriptions.isCurrent(prepared) == true
                    }) { [weak self] result in
                        guard let self else { return }
                        switch result {
                        case .success:
                            self.subscriptions.select(name: prepared.name)
                            self.subscriptions.recordApplied(prepared)
                            self.refreshSubscriptionSettings(preferredSelection: prepared.name)
                            if announce {
                                self.reportSubscriptionOutcome(results: [prepared.result], failures: [])
                            }
                        case .failure(let error):
                            self.subscriptions.recordFailure(name: prepared.name, error: error)
                            self.refreshSubscriptionSettings(preferredSelection: prepared.name)
                            self.showError(title: "应用订阅失败", error: error)
                        }
                    }
                }
            }
        }
    }

    private final class URLSubscriptionFormView: NSView {
        let nameField = NSTextField()
        let urlField = NSTextField()
        let autoUpdateCheckbox: NSButton
        let intervalField = NSTextField()

        init(name: String, url: String, updateInterval: TimeInterval) {
            autoUpdateCheckbox = NSButton(checkboxWithTitle: "自动更新订阅", target: nil, action: nil)
            super.init(frame: NSRect(x: 0, y: 0, width: 390, height: 118))

            let nameLabel = NSTextField(labelWithString: "订阅名称")
            nameLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
            nameLabel.frame = NSRect(x: 0, y: 92, width: 64, height: 18)

            nameField.frame = NSRect(x: 68, y: 89, width: 322, height: 22)
            nameField.placeholderString = "名称，例如 机场A（留空则自动根据地址命名）"
            nameField.stringValue = name

            let urlLabel = NSTextField(labelWithString: "订阅 URL")
            urlLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
            urlLabel.frame = NSRect(x: 0, y: 58, width: 64, height: 18)

            urlField.frame = NSRect(x: 68, y: 55, width: 322, height: 22)
            urlField.placeholderString = "https://example.com/subscribe?token=…"
            urlField.stringValue = url

            let isAuto = updateInterval > 0
            autoUpdateCheckbox.state = isAuto ? .on : .off
            autoUpdateCheckbox.target = self
            autoUpdateCheckbox.action = #selector(autoUpdateToggled)
            autoUpdateCheckbox.frame = NSRect(x: 68, y: 24, width: 112, height: 20)

            let intervalLabel = NSTextField(labelWithString: "更新时间（小时）：")
            intervalLabel.font = .systemFont(ofSize: 11.5, weight: .regular)
            intervalLabel.textColor = .secondaryLabelColor
            intervalLabel.frame = NSRect(x: 186, y: 25, width: 110, height: 18)

            let hours = isAuto ? (updateInterval / 3600) : 24
            let hoursString = hours.truncatingRemainder(dividingBy: 1) == 0
                ? "\(Int(hours))" : String(format: "%.1f", hours)
            intervalField.frame = NSRect(x: 298, y: 23, width: 92, height: 22)
            intervalField.placeholderString = "小时（如 24）"
            intervalField.stringValue = hoursString
            intervalField.isEnabled = isAuto

            let hintLabel = NSTextField(labelWithString: "勾选“自动更新订阅”后，将按设定的小时数定期拉取最新节点。")
            hintLabel.font = .systemFont(ofSize: 10.5)
            hintLabel.textColor = .tertiaryLabelColor
            hintLabel.frame = NSRect(x: 68, y: 2, width: 322, height: 16)

            [nameLabel, nameField, urlLabel, urlField,
             autoUpdateCheckbox, intervalLabel, intervalField, hintLabel].forEach(addSubview)
        }

        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

        @objc private func autoUpdateToggled() {
            let enabled = autoUpdateCheckbox.state == .on
            intervalField.isEnabled = enabled
            if enabled, (Double(intervalField.stringValue.trimmingCharacters(in: .whitespaces)) ?? 0) <= 0 {
                intervalField.stringValue = "24"
            }
        }

        var effectiveUpdateInterval: TimeInterval {
            guard autoUpdateCheckbox.state == .on else { return 0 }
            let hours = Double(intervalField.stringValue.trimmingCharacters(in: .whitespaces)) ?? 24
            return max(0.1, hours) * 3600
        }
    }

    @objc private func addSubscriptionAction() {
        let alert = NSAlert()
        alert.messageText = "增加订阅（URL 下载或导入配置）"
        alert.informativeText = "支持 Clash YAML、Surge .conf 与分享链接列表（可为 base64 包装）。"
            + "输入订阅 URL 点击“添加并使用”，或点击“导入本地配置文件…”直接从文件创建订阅。"
        alert.addButton(withTitle: "添加并使用")
        alert.addButton(withTitle: "导入本地配置文件…")
        alert.addButton(withTitle: "取消")

        let form = URLSubscriptionFormView(name: "", url: "", updateInterval: 24 * 3600)
        alert.accessoryView = form
        alert.window.initialFirstResponder = form.nameField

        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            if response == .alertSecondButtonReturn {
                self.importSubscriptionFileAction()
                return
            }
            guard response == .alertFirstButtonReturn else { return }
            let rawName = form.nameField.stringValue.trimmingCharacters(in: .whitespaces)
            let url = form.urlField.stringValue.trimmingCharacters(in: .whitespaces)
            let fallbackHost = URL(string: url)?.host ?? "订阅"
            let name = rawName.isEmpty ? self.subscriptions.uniqueName(basedOn: fallbackHost) : rawName
            do {
                try self.subscriptions.add(name: name, url: url,
                                           updateInterval: form.effectiveUpdateInterval)
                self.subscriptions.select(name: name)
                self.refreshSubscriptionSettings(preferredSelection: name)
            } catch {
                self.showError(title: "添加订阅失败", error: error)
                return
            }
            self.updateSubscriptions(names: [name], announce: true)
        }
    }

    @objc private func editSelectedSubscriptionAction() {
        let selected = subscriptionSelectPopup.titleOfSelectedItem ?? subscriptions.selectedName
        guard let originalName = selected,
              let current = subscriptions.all.first(where: { $0.name == originalName }) else { return }
        guard URL(string: current.url)?.isFileURL != true else {
            showMessage(title: "本地导入的订阅不支持编辑 URL",
                        text: "当前选择的是本地导入配置，如需更换请点击“导入配置…”或“URL 下载…”。")
            return
        }

        let alert = NSAlert()
        alert.messageText = "编辑 URL 订阅“\(current.name)”"
        alert.informativeText = "可更换订阅名称、替换订阅 URL、勾选是否自动更新并设置自动更新时间（小时）。若替换了 URL，保存后将立即拉取并切换为新订阅内容。"
        alert.addButton(withTitle: "保存")
        alert.addButton(withTitle: "保存并立即更新")
        alert.addButton(withTitle: "取消")

        let form = URLSubscriptionFormView(name: current.name,
                                           url: current.url,
                                           updateInterval: current.updateInterval)
        alert.accessoryView = form
        alert.window.initialFirstResponder = form.nameField

        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            guard response == .alertFirstButtonReturn || response == .alertSecondButtonReturn else { return }
            let forceRefresh = response == .alertSecondButtonReturn
            let rawName = form.nameField.stringValue.trimmingCharacters(in: .whitespaces)
            let url = form.urlField.stringValue.trimmingCharacters(in: .whitespaces)
            let fallbackHost = URL(string: url)?.host ?? current.name
            let requestedName = rawName.isEmpty ? fallbackHost : rawName
            do {
                let outcome = try self.subscriptions.updateSubscription(
                    originalName: originalName,
                    newName: requestedName,
                    url: url,
                    updateInterval: form.effectiveUpdateInterval)
                let newName = outcome.subscription.name
                let wasUsingOriginal = SubscriptionMerge.managedNames(in: self.profileTextView.string)
                    .contains(originalName)
                if outcome.nameChanged && wasUsingOriginal {
                    self.profileTextView.string = SubscriptionMerge.renameManagedBlock(
                        from: originalName, to: newName, in: self.profileTextView.string)
                }
                if outcome.urlChanged || forceRefresh {
                    self.subscriptions.select(name: newName)
                    self.refreshSubscriptionSettings(preferredSelection: newName)
                    self.updateSubscriptions(names: [newName], announce: true)
                } else if outcome.nameChanged && wasUsingOriginal {
                    self.applyProfileTextInBackground(self.profileTextView.string,
                                                      prefix: "已更新订阅名称为 \(newName)",
                                                      keepEditorOnFailure: true,
                                                      completion: { [weak self] _ in
                        self?.refreshSubscriptionSettings(preferredSelection: newName)
                    })
                } else {
                    self.refreshSubscriptionSettings(preferredSelection: newName)
                }
            } catch {
                self.showError(title: "编辑订阅失败", error: error)
            }
        }
    }

    @objc private func manageSubscriptionsAction() {
        selectPage(4)
    }

    private func promptRemoveSubscription(_ names: [String]) {
        guard let first = names.first else { return }
        removeSubscriptionByName(first)
    }

    /// Fetches named subscriptions off the main thread, then applies the active
    /// subscription into the latest profile text in one transaction on the main thread.
    private func updateSubscriptions(names: [String], announce: Bool) {
        guard !names.isEmpty else { return }
        let initialEditorText = profileTextView.string
        let initialSelectedName = subscriptions.selectedName
        subscriptionSummaryLabel.stringValue = "正在更新订阅：\(names.joined(separator: "、"))…"
        subscriptionSummaryLabel.textColor = .systemBlue
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var updates: [SubscriptionManager.PreparedUpdate] = []
            var failures: [String] = []
            for name in names {
                do {
                    updates.append(try self.subscriptions.prepareUpdate(name: name))
                } catch {
                    self.subscriptions.recordFailure(name: name, error: error)
                    failures.append("• \(name)：\(error.localizedDescription)")
                }
            }
            let downloadFailures = failures
            let preparedUpdates = updates
            let precomputedTarget = preparedUpdates.first(where: { $0.name == initialSelectedName }) ?? preparedUpdates.first
            let precomputedMerged = precomputedTarget.map { target in
                SubscriptionRefreshMerge.activate(
                    (name: target.name, contents: target.contents),
                    toCurrentText: { initialEditorText })
            }
            DispatchQueue.main.async {
                var failures = downloadFailures
                let current = preparedUpdates.filter { update in
                    guard self.subscriptions.isCurrent(update) else {
                        failures.append("• \(update.name)：订阅已移除或更换，未应用旧下载结果")
                        return false
                    }
                    return true
                }
                guard !current.isEmpty else {
                    self.refreshSubscriptionSettings()
                    if announce { self.reportSubscriptionOutcome(results: [], failures: failures) }
                    return
                }
                let activeTarget = current.first(where: { $0.name == self.subscriptions.selectedName }) ?? current[0]
                let currentEditorText = self.profileTextView.string
                let merged: String
                if let precomputedMerged, precomputedTarget?.name == activeTarget.name,
                   currentEditorText == initialEditorText {
                    merged = precomputedMerged
                } else {
                    merged = SubscriptionRefreshMerge.activate(
                        (name: activeTarget.name, contents: activeTarget.contents),
                        toCurrentText: { currentEditorText })
                }
                self.applyProfileTextInBackground(merged, prefix: "更新订阅",
                                                  keepEditorOnFailure: true,
                                                  stillApplicable: { [weak self] in
                    guard let self else { return false }
                    return current.allSatisfy(self.subscriptions.isCurrent)
                }) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .success:
                        self.subscriptions.select(name: activeTarget.name)
                        for update in current { self.subscriptions.recordApplied(update) }
                        self.refreshSubscriptionSettings(preferredSelection: activeTarget.name)
                        if announce {
                            self.reportSubscriptionOutcome(results: current.map(\.result),
                                                           failures: failures)
                        }
                    case .failure(let error):
                        for update in current {
                            self.subscriptions.recordFailure(name: update.name, error: error)
                        }
                        self.refreshSubscriptionSettings(preferredSelection: activeTarget.name)
                        self.showError(title: "应用订阅失败", error: error)
                    }
                }
            }
        }
    }

    private func reportSubscriptionOutcome(results: [SubscriptionManager.UpdateResult],
                                           failures: [String]) {
        let alert = NSAlert()
        alert.messageText = failures.isEmpty ? "订阅已更新" : "订阅更新部分失败"
        alert.alertStyle = failures.isEmpty ? .informational : .warning
        var lines = results.map { result -> String in
            "• \(result.name)（\(result.format.rawValue)）："
                + "\(result.proxyCount) 个节点、\(result.groupCount) 个策略组"
        }
        lines.append(contentsOf: failures)
        let warnings = results.flatMap(\.warnings)
        let skipCert = warnings.filter { $0.contains("跳过服务器证书验证") }
        let other = warnings.filter { !$0.contains("跳过服务器证书验证") }
        if !skipCert.isEmpty {
            alert.alertStyle = .warning
            lines.append("")
            lines.append("证书风险：")
            lines.append(contentsOf: skipCert.prefix(5).map { "· \($0)" })
        }
        if !other.isEmpty {
            lines.append("")
            lines.append(contentsOf: other.prefix(10).map { "· \($0)" })
            if other.count > 10 { lines.append("· 另有 \(other.count - 10) 条提示") }
        }
        alert.informativeText = lines.joined(separator: "\n")
        alert.addButton(withTitle: "好")
        if let window { alert.beginSheetModal(for: window) { _ in } } else { alert.runModal() }
    }

    @objc private func importSurgeProfile() {
        importSubscriptionFileAction()
    }

    private func loadProfileText(_ text: String) {
        profileTextView.string = text
        profileStatus.stringValue = "配置将在启动时加载"
    }

    private func applyProfileValidationStatus(_ value: Profile, prefix: String) {
        let loadedRules = value.ruleSetContents.values.reduce(0) { $0 + $1.count }
        let ruleSetText = value.ruleSetReferences.isEmpty
            ? "" : "，\(value.ruleSetReferences.count) 个 RULE-SET / \(loadedRules) 条子规则"
        let skipCertCount = value.proxiesSkippingCertificateVerification.count
        let skipCertText = skipCertCount == 0 ? "" : "，\(skipCertCount) 个节点跳过证书验证"
        let otherWarnings = value.warnings.filter { !$0.contains("跳过服务器证书验证") }
        let warningText = otherWarnings.isEmpty ? "" : "，\(otherWarnings.count) 项兼容提示"
        profileStatus.stringValue = "✓ \(prefix)：\(value.rules.count) 条主规则，\(value.proxyOrder.count) 个代理\(ruleSetText)\(skipCertText)\(warningText)"
        profileStatus.textColor = skipCertCount > 0
            ? .systemOrange
            : (value.warnings.isEmpty ? .systemGreen : .systemOrange)
        var tips = value.warnings
        if skipCertCount > 0, !tips.contains(where: { $0.contains("跳过服务器证书验证") }) {
            tips.insert(SkipCertificateWarning.message(
                names: value.proxiesSkippingCertificateVerification), at: 0)
        }
        profileStatus.toolTip = tips.isEmpty ? nil : tips.joined(separator: "\n")
    }

    /// A queued Core status belongs to the session observed at emission, and
    /// must still match the Core. Old terminal events cannot release a newer
    /// unowned RULE-SET preparation or a replacement listener.
    private func isCurrentListener(_ ticket: RuntimeLifecycle.Ticket) -> Bool {
        listenerTicket == ticket && listenerLifecycle.isCurrent(ticket)
            && listenerLifecycle.snapshot.isReady && engine.runtimeSnapshot().status == .running
    }

    private func acceptListenerStatus(_ status: ProxyEngineStatus, sessionID: UUID) -> Bool {
        let lifecycle = listenerLifecycle.snapshot
        guard lifecycle.sessionID == sessionID, engine.runtimeSnapshot().status == status else { return false }
        switch status {
        case .running:
            guard lifecycle.isPresent, let ticket = listenerTicket,
                  listenerLifecycle.markRunning(ticket) else { return false }
            updateEngineRouting()
        case .starting:
            guard lifecycle.isPresent, lifecycle.startupPending, let ticket = listenerTicket,
                  listenerLifecycle.isCurrent(ticket) else { return false }
        case .failed:
            guard lifecycle.isPresent, let ticket = listenerTicket else { return false }
            // Core emits failed only after its synchronous stop has canceled
            // listeners/flows. Adapters are our remaining owned resources.
            listenerLifecycle.markFailure(ticket)
            protocolAdapters.stop()
            listenerLifecycle.confirmStopped(ticket, preservingFailure: true)
            if listenerTicket == ticket { listenerTicket = nil }
            routingReloadGate.reset()
        case .stopped:
            guard !lifecycle.isPresent, !lifecycle.startupPending else { return false }
        }
        startButton.isEnabled = true
        networkRuntime.lifecycleDidChange()
        return true
    }

    private func apply(status: ProxyEngineStatus) {
        networkRuntime.observe(listenerStatus: status)
        engineStatus = status
        switch status {
        case .stopped:
            activeConnectionIDs.removeAll(keepingCapacity: true)
            scheduleStatisticsUpdate()
            startButton.title = "开启 HTTP / SOCKS5 代理"
        case .starting:
            startButton.title = "关闭 HTTP / SOCKS5 代理"
        case .running:
            startButton.title = "关闭 HTTP / SOCKS5 代理"
            updateOverviewDetails()
            applyPendingSystemProxyRestore()
            reconcileSystemProxyListener()
            refreshRuleSetsAutomatically()
        case .failed(let message):
            activeConnectionIDs.removeAll(keepingCapacity: true)
            scheduleStatisticsUpdate()
            startButton.title = "重试 HTTP / SOCKS5 代理"
            recoverSystemProxyAfterListenerFailure()
            showMessage(title: "代理引擎错误", text: message)
        }
        refreshLocalProxySettings()
        refreshConnectionStatus()
    }

    private var connectionPresentation: AppConnectionPresentation {
        networkRuntime.connectionPresentation(mode: selectedMode, systemProxyEnabled: isSystemProxyActive,
            systemProxyChanging: systemProxyEnableRequests > 0 || systemProxyDisableRequests > 0
                || systemProxyRebindInFlight || systemProxyRecoveryInFlight,
            enhancedRequestPending: enhancedRequestIntent.snapshot.startupPending,
            enhancedRequested: enhancedMode.isRequested)
    }

    private func refreshConnectionStatus() {
        let presentation = connectionPresentation
        statusLabel.stringValue = "● \(presentation.title)"
        sidebarStatusText.stringValue = presentation.title
        sidebarStatusDetail.stringValue = presentation.detail
        sidebarStatusDetail.lineBreakMode = .byWordWrapping
        sidebarStatusDetail.maximumNumberOfLines = 4
        sidebarStatusDetail.cell?.wraps = true
        sidebarStatusDetail.cell?.truncatesLastVisibleLine = true
        sidebarStatusDetail.toolTip = presentation.toolTip
        statusLabel.toolTip = presentation.toolTip
        dataPlaneRuntimeValue.toolTip = presentation.toolTip
        switch presentation.tone {
        case .active:
            statusLabel.textColor = HajimiAppearance.accentText
            sidebarStatusDot.fillColor = HajimiTheme.accent
        case .neutral:
            statusLabel.textColor = .secondaryLabelColor
            sidebarStatusDot.fillColor = .tertiaryLabelColor
        case .pending, .warning:
            statusLabel.textColor = .systemOrange
            sidebarStatusDot.fillColor = .systemOrange
        case .failure:
            statusLabel.textColor = .systemRed
            sidebarStatusDot.fillColor = .systemRed
        }
        if engineStatus == .running,
           engine.activeHTTPListen.port != profile.httpListen.port
            || engine.activeSOCKSListen.port != profile.socksListen.port {
            statusLabel.toolTip = presentation.toolTip
                + "\n配置端口被占用，已自动改用 HTTP :\(engine.activeHTTPListen.port)、SOCKS :\(engine.activeSOCKSListen.port)"
        }
    }

    private func apply(event: ProxyEngineEvent) {
        switch event {
        case .opened(let snapshot):
            if activeConnectionIDs.insert(snapshot.id).inserted { totalConnections += 1 }
        case .traffic(_, let up, let down):
            uploaded += up
            downloaded += down
        case .closed(let id, _):
            activeConnectionIDs.remove(id)
        case .message: break
        }
        scheduleStatisticsUpdate()
    }

    private func scheduleStatisticsUpdate() {
        guard !statisticsUpdateScheduled else { return }
        statisticsUpdateScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(200)) { [weak self] in
            guard let self else { return }
            self.statisticsUpdateScheduled = false
            self.updateStatistics()
        }
    }

    @objc private func checkNetworkExtension() {
        let alert = NSAlert()
        alert.messageText = "Network Extension 接入条件"
        if let error = networkExtensionController.availabilityError {
            alert.informativeText = error.localizedDescription +
                "\n当前增强模式仍使用 Helper + utun。没有安装或启动 VPN。"
        } else {
            alert.informativeText = "宿主签名与 Provider 包预检通过。仍需完整原生 Packet Engine、有效 provisioning 与端到端验证；尚未修改网络。"
        }
        alert.addButton(withTitle: "好")
        alert.runModal()
    }

    private func updateStatistics() {
        activeValue.stringValue = String(activeConnectionIDs.count + enhancedActiveConnections)
        totalValue.stringValue = String(totalConnections + enhancedTotalConnections)
        uploadValue.stringValue = byteString(uploaded + Int(min(enhancedUploaded, UInt64(Int.max))))
        downloadValue.stringValue = byteString(downloaded + Int(min(enhancedDownloaded, UInt64(Int.max))))
    }

    func numberOfSections(in collectionView: NSCollectionView) -> Int { 2 }

    func collectionView(_ collectionView: NSCollectionView,
                        numberOfItemsInSection section: Int) -> Int {
        guard collectionView === policyCollectionView else { return 0 }
        let proxyNames = renderedProxyOrder ?? filteredProxyNames
        let groupNames = renderedGroupOrder ?? profile.groupOrder
        if section == 0 { return proxyNames.count + 1 }
        if section == 1 { return groupNames.count + 1 }
        return 0
    }

    func collectionView(_ collectionView: NSCollectionView,
                        itemForRepresentedObjectAt indexPath: IndexPath) -> NSCollectionViewItem {
        let proxyNames = renderedProxyOrder ?? filteredProxyNames
        let groupNames = renderedGroupOrder ?? profile.groupOrder
        if collectionView === policyCollectionView, indexPath.section == 0 {
            if indexPath.item == proxyNames.count {
                let item = collectionView.makeItem(withIdentifier: AddProxyCollectionItem.identifier,
                                                   for: indexPath) as! AddProxyCollectionItem
                item.configure { [weak self] in self?.addProxy() }
                return item
            }
            if proxyNames.indices.contains(indexPath.item) {
                let name = proxyNames[indexPath.item]
                if let policy = profile.proxies[name] ?? renderedProxyPolicies[name] {
                    let item = collectionView.makeItem(withIdentifier: ProxyCardCollectionItem.identifier,
                                                   for: indexPath) as! ProxyCardCollectionItem
                    item.configure(policy: policy, latency: nodeLatencies[name] ?? .untested,
                               active: selectedMode == .proxy && selectedPolicy == name,
                               onEdit: { [weak self] in self?.editProxy(named: name) })
                    return item
                }
            }
        }
        if collectionView === policyCollectionView, indexPath.section == 1 {
            if indexPath.item == groupNames.count {
                let item = collectionView.makeItem(withIdentifier: AddGroupCollectionItem.identifier,
                                                   for: indexPath) as! AddGroupCollectionItem
                item.configure { [weak self] in self?.addPolicyGroup() }
                return item
            }
            if groupNames.indices.contains(indexPath.item) {
                let name = groupNames[indexPath.item]
                if let group = profile.groups[name] ?? renderedGroupPolicies[name] {
                    let item = collectionView.makeItem(withIdentifier: GroupCardCollectionItem.identifier,
                                                   for: indexPath) as! GroupCardCollectionItem
                    item.configure(group: group, selected: groupSelections[name] ?? renderedGroupSelections[name],
                                   onEdit: { [weak self] in self?.editPolicyGroup(named: name) }) { [weak self] member in
                        self?.setGroupSelection(group: name, member: member)
                    }
                    return item
                }
            }
        }
        // A group-section refresh may precede the asynchronous node search
        // after a profile switch. Do not force old node identities into the
        // new profile while the revision-gated result is still pending.
        let empty = NSCollectionViewItem()
        empty.view = NSView()
        return empty
    }

    func collectionView(_ collectionView: NSCollectionView,
                        viewForSupplementaryElementOfKind kind: NSCollectionView.SupplementaryElementKind,
                        at indexPath: IndexPath) -> NSView {
        let header = collectionView.makeSupplementaryView(ofKind: kind,
            withIdentifier: PolicySectionHeaderView.identifier, for: indexPath) as! PolicySectionHeaderView
        if indexPath.section == 0 {
            header.configure(title: "代理节点", detail: "双击编辑；右键可使用、测试、复制或删除")
        } else {
            header.configure(title: "策略组", detail: "下拉选择立即生效；右键编辑成员与组选项")
        }
        return header
    }

    func collectionView(_ collectionView: NSCollectionView, layout collectionViewLayout: NSCollectionViewLayout,
                        sizeForItemAt indexPath: IndexPath) -> NSSize {
        NSSize(width: 147, height: indexPath.section == 0 ? 84 : 88)
    }

    func collectionView(_ collectionView: NSCollectionView,
                        shouldSelectItemsAt indexPaths: Set<IndexPath>) -> Set<IndexPath> {
        let proxyNames = renderedProxyOrder ?? filteredProxyNames
        return Set(indexPaths.filter {
            $0.section == 0 && proxyNames.indices.contains($0.item)
                && profile.proxies[proxyNames[$0.item]] != nil
        })
    }

    func collectionView(_ collectionView: NSCollectionView,
                        didSelectItemsAt indexPaths: Set<IndexPath>) {
        let proxyNames = renderedProxyOrder ?? filteredProxyNames
        guard collectionView === policyCollectionView, let indexPath = indexPaths.first, indexPath.section == 0,
              proxyNames.indices.contains(indexPath.item),
              profile.proxies[proxyNames[indexPath.item]] != nil else { return }
        useProxy(named: proxyNames[indexPath.item])
        collectionView.deselectItems(at: indexPaths)
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        if tableView === proxyTableView { return filteredProxyNames.count }
        if tableView === groupTableView { return profile.groupOrder.count }
        if tableView === rulesTableView { return filteredRules.count }
        return 0
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard let table = notification.object as? NSTableView, table === rulesTableView,
              !ruleSelectionRefreshInProgress else { return }
        updateRuleSelectionControls()
        if ruleMultiSelectButton.state == .on,
           let column = rulesTableView.tableColumns.firstIndex(where: { $0.identifier.rawValue == "selected" }),
           !filteredRules.isEmpty {
            ruleSelectionRefreshInProgress = true
            rulesTableView.reloadData(forRowIndexes: IndexSet(integersIn: 0..<filteredRules.count),
                                      columnIndexes: IndexSet(integer: column))
            ruleSelectionRefreshInProgress = false
        }
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        if tableView === proxyTableView {
            guard filteredProxyNames.indices.contains(row),
                  let policy = profile.proxies[filteredProxyNames[row]] else { return nil }
            let name = policy.name
            let cell = ProxyNodeCellView()
            cell.configure(policy: policy, latency: nodeLatencies[name] ?? .untested,
                           isActive: selectedMode == .proxy && selectedPolicy == name,
                           onUse: { [weak self] in self?.useProxy(named: name) })
            return cell
        }
        if tableView === groupTableView {
            guard profile.groupOrder.indices.contains(row),
                  let group = profile.groups[profile.groupOrder[row]] else { return nil }
            let cell = PolicyGroupCellView()
            cell.configure(group: group, selected: groupSelections[group.name]) { [weak self] member in
                self?.setGroupSelection(group: group.name, member: member)
            }
            return cell
        }
        if tableView === rulesTableView {
            guard filteredRules.indices.contains(row), let identifier = tableColumn?.identifier else { return nil }
            let rule = filteredRules[row]
            if identifier.rawValue == "selected" {
                let checkbox = NSButton(checkboxWithTitle: "", target: self,
                                        action: #selector(ruleRowSelectionChanged(_:)))
                checkbox.tag = rule.sourceLine
                checkbox.isEnabled = rulesPageIsEditable
                checkbox.state = rulesTableView.selectedRowIndexes.contains(row) ? .on : .off
                checkbox.toolTip = "选择第 \(rule.sourceLine) 行规则"
                checkbox.setAccessibilityLabel("选择第 \(rule.sourceLine) 行规则")
                return checkbox
            }
            let description = filteredRuleRows[row]
            let cell = NSTextField(labelWithString: "")
            cell.font = identifier.rawValue == "value"
                ? .monospacedSystemFont(ofSize: 10.5, weight: .regular)
                : .systemFont(ofSize: 11)
            cell.lineBreakMode = .byTruncatingMiddle
            switch identifier.rawValue {
            case "line":
                cell.stringValue = String(rule.sourceLine)
                cell.font = .monospacedDigitSystemFont(ofSize: 10.5, weight: .regular)
                cell.textColor = .tertiaryLabelColor
            case "type":
                cell.stringValue = description.type
                cell.font = .systemFont(ofSize: 11, weight: .semibold)
                cell.textColor = HajimiAppearance.accentText
            case "value":
                cell.stringValue = description.value
                cell.toolTip = description.value
            case "policy":
                cell.stringValue = rule.policy
                cell.font = .systemFont(ofSize: 11, weight: .semibold)
                let upper = rule.policy.uppercased()
                if upper == "REJECT" || upper == "REJECT-TINYGIF" {
                    cell.textColor = .systemRed
                } else if upper == "DIRECT" {
                    cell.textColor = HajimiAppearance.accentText
                } else {
                    cell.textColor = .systemIndigo
                }
            case "loaded":
                cell.font = .systemFont(ofSize: 11, weight: .medium)
                if case .ruleSet(let reference) = rule.kind {
                    let count = (rulesPageProfile ?? resolvedProfile ?? profile).ruleSetContents[reference.location]?.count
                    cell.stringValue = count.map { "\($0) 条" } ?? "未加载"
                    cell.textColor = count == nil ? .systemOrange : HajimiAppearance.accentText
                } else {
                    cell.stringValue = "本地"
                    cell.textColor = .secondaryLabelColor
                }
            default: break
            }
            return cell
        }

        return nil
    }

    private func ruleDescription(_ rule: RoutingRule) -> (type: String, value: String) {
        RuleListRow.description(of: rule.kind)
    }

    private func restartExternalController() {
        externalController.start(profile: resolvedProfile ?? profile)
    }

    private func byteString(_ bytes: Int) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        return byteFormatter.string(fromByteCount: Int64(bytes))
    }

    private func pageHeader(eyebrow: String? = nil, title: String,
                            subtitle: String) -> NSStackView {
        let heading = NSTextField(labelWithString: title)
        heading.font = .systemFont(ofSize: 28, weight: .bold)
        let detail = NSTextField(labelWithString: subtitle)
        detail.font = .systemFont(ofSize: 12.5, weight: .regular)
        detail.textColor = .secondaryLabelColor
        var views: [NSView] = []
        if let eyebrow {
            views.append(HajimiTheme.eyebrowPill(eyebrow))
        }
        views.append(contentsOf: [heading, detail])
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = eyebrow == nil ? 5 : 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }

    private func cardView() -> NSView {
        HajimiSurfaceView(fill: HajimiTheme.panel, border: HajimiTheme.border)
    }

    private func statCard(title: String, value: NSTextField, color: NSColor) -> NSView {
        let card = cardView()
        let accentBar = HajimiSurfaceView(fill: color.withAlphaComponent(0.85), cornerRadius: 1.5)
        accentBar.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(accentBar)

        value.font = .monospacedDigitSystemFont(ofSize: 23.5, weight: .bold)
        value.textColor = .labelColor
        value.alignment = .left
        value.lineBreakMode = .byTruncatingTail
        value.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let label = NSTextField(labelWithString: title)
        label.font = .systemFont(ofSize: 11.5, weight: .semibold)
        label.textColor = .secondaryLabelColor
        let symbol: String
        switch title {
        case "活动连接": symbol = "link"
        case "累计连接": symbol = "square.stack.3d.up"
        case "上传流量": symbol = "arrow.up.right"
        default: symbol = "arrow.down.left"
        }
        let badge = HajimiTheme.iconTile(symbol: symbol, color: color, size: 28, symbolSize: 12.5)
        let heading = NSStackView(views: [label, NSView(), badge])
        heading.orientation = .horizontal
        heading.alignment = .centerY
        let stack = NSStackView(views: [heading, value])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 7
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            accentBar.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 4.5),
            accentBar.topAnchor.constraint(equalTo: card.topAnchor, constant: 16),
            accentBar.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -16),
            accentBar.widthAnchor.constraint(equalToConstant: 3),
            heading.widthAnchor.constraint(equalTo: stack.widthAnchor),
            value.widthAnchor.constraint(equalTo: stack.widthAnchor),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -15),
            stack.centerYAnchor.constraint(equalTo: card.centerYAnchor)
        ])
        return card
    }

    private func overviewInfoColumn(title: String, value: NSTextField, detail: String,
                                    icon: String, color: NSColor) -> NSView {
        let container = NSView()
        let well = HajimiSurfaceView(
            fill: HajimiTheme.mutedPanel.withAlphaComponent(0.55),
            border: HajimiTheme.subtleDivider,
            cornerRadius: 10
        )
        well.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(well)

        let badge = HajimiTheme.iconTile(symbol: icon, color: color, size: 34, symbolSize: 15)
        value.font = .monospacedSystemFont(ofSize: 13, weight: .semibold)
        value.lineBreakMode = .byTruncatingMiddle
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 10.5, weight: .semibold)
        titleLabel.textColor = .secondaryLabelColor
        let detailLabel = NSTextField(labelWithString: detail)
        detailLabel.font = .systemFont(ofSize: 10)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.lineBreakMode = .byTruncatingTail
        let text = NSStackView(views: [titleLabel, value, detailLabel])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 3
        text.translatesAutoresizingMaskIntoConstraints = false
        well.addSubview(badge)
        well.addSubview(text)
        NSLayoutConstraint.activate([
            well.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 4),
            well.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -4),
            well.topAnchor.constraint(equalTo: container.topAnchor, constant: 2),
            well.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -2),
            badge.leadingAnchor.constraint(equalTo: well.leadingAnchor, constant: 10),
            badge.centerYAnchor.constraint(equalTo: well.centerYAnchor),
            text.leadingAnchor.constraint(equalTo: badge.trailingAnchor, constant: 10),
            text.trailingAnchor.constraint(lessThanOrEqualTo: well.trailingAnchor, constant: -8),
            text.centerYAnchor.constraint(equalTo: well.centerYAnchor)
        ])
        return container
    }

    private func updateOverviewDetails() {
        let http = (engineStatus == .running || engineStatus == .starting)
            ? engine.activeHTTPListen : profile.httpListen
        let socks = (engineStatus == .running || engineStatus == .starting)
            ? engine.activeSOCKSListen : profile.socksListen
        httpRuntimeValue.stringValue = "\(http.host):\(http.port)"
        socksRuntimeValue.stringValue = "\(socks.host):\(socks.port)"
        if engineStatus == .running,
           http.port != profile.httpListen.port || socks.port != profile.socksListen.port {
            httpRuntimeValue.toolTip = "配置为 \(profile.httpListen.port)，因占用已改用 \(http.port)"
            socksRuntimeValue.toolTip = "配置为 \(profile.socksListen.port)，因占用已改用 \(socks.port)"
        } else {
            httpRuntimeValue.toolTip = nil
            socksRuntimeValue.toolTip = nil
        }
        switch selectedMode {
        case .direct: routingRuntimeValue.stringValue = "全局直连"
        case .rule: routingRuntimeValue.stringValue = "规则判定"
        case .proxy: routingRuntimeValue.stringValue = selectedPolicy
        }
        refreshConnectionStatus()
    }

    private func labeledControl(_ title: String, _ control: NSView) -> NSStackView {
        let label = NSTextField(labelWithString: title)
        label.font = .systemFont(ofSize: 10, weight: .medium)
        label.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [label, control])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 2
        return stack
    }

    private func separator() -> NSBox {
        let box = NSBox()
        box.boxType = .separator
        box.heightAnchor.constraint(equalToConstant: 30).isActive = true
        box.widthAnchor.constraint(equalToConstant: 1).isActive = true
        return box
    }

    private func capabilityRow(_ title: String, detail: String, color: NSColor) -> NSView {
        let card = cardView()
        card.translatesAutoresizingMaskIntoConstraints = false
        card.heightAnchor.constraint(equalToConstant: 64).isActive = true
        let symbol: String
        switch title {
        case "HTTP / HTTPS 出站": symbol = "globe"
        case "SOCKS5 / SOCKS5-TLS": symbol = "arrow.triangle.branch"
        case "常见节点协议": symbol = "lock.shield"
        case "QUIC 与 AnyTLS": symbol = "bolt.horizontal.circle"
        case "数据平面": symbol = "cpu"
        case "macOS 系统代理": symbol = "network"
        case "增强模式 VIF": symbol = "shield.lefthalf.filled"
        case "Network Extension": symbol = "puzzlepiece.extension"
        default: symbol = "wrench.and.screwdriver"
        }
        let icon = HajimiTheme.iconTile(symbol: symbol, color: color, size: 36, symbolSize: 16)
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 13.5, weight: .semibold)
        let detailLabel = NSTextField(labelWithString: detail)
        detailLabel.font = .systemFont(ofSize: 11)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.lineBreakMode = .byTruncatingTail
        let text = NSStackView(views: [titleLabel, detailLabel])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 3
        let isPending = color == .systemOrange
        let badgePill = HajimiSurfaceView(
            fill: color.withAlphaComponent(0.12),
            border: color.withAlphaComponent(0.24),
            cornerRadius: 6
        )
        badgePill.translatesAutoresizingMaskIntoConstraints = false
        let badgeText = NSTextField(labelWithString: isPending ? "需扩展/规划中" : "原生就绪")
        badgeText.font = .systemFont(ofSize: 10, weight: .semibold)
        badgeText.textColor = color
        badgeText.translatesAutoresizingMaskIntoConstraints = false
        badgePill.addSubview(badgeText)
        NSLayoutConstraint.activate([
            badgeText.leadingAnchor.constraint(equalTo: badgePill.leadingAnchor, constant: 8),
            badgeText.trailingAnchor.constraint(equalTo: badgePill.trailingAnchor, constant: -8),
            badgeText.topAnchor.constraint(equalTo: badgePill.topAnchor, constant: 3),
            badgeText.bottomAnchor.constraint(equalTo: badgePill.bottomAnchor, constant: -3)
        ])
        let row = NSStackView(views: [icon, text, NSView(), badgePill])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 14
        row.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 18),
            row.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -18),
            row.centerYAnchor.constraint(equalTo: card.centerYAnchor)
        ])
        return card
    }

    private func showError(title: String, error: Error) { showMessage(title: title, text: error.localizedDescription) }

    private func promptToEnableProxyEngineForSystemProxy() {
        if listenerLifecycle.snapshot.startupPending {
            pendingSystemProxyRestore = true
            refreshConnectionStatus()
            onStatusBarStateChanged?()
            return
        }
        let alert = NSAlert()
        alert.messageText = "是否开启代理功能？"
        alert.informativeText = "当前代理引擎尚未启动。选择“打开”将自动开启代理功能并启用系统代理；选择“关闭”则不开启代理功能。"
        alert.alertStyle = .informational
        alert.addButton(withTitle: "打开")
        alert.addButton(withTitle: "关闭")
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            pendingSystemProxyRestore = true
            if !isEngineActive {
                startEngine()
            }
            refreshConnectionStatus()
            onStatusBarStateChanged?()
        } else {
            pendingSystemProxyRestore = false
            systemProxyButton.state = .off
            refreshConnectionStatus()
            onStatusBarStateChanged?()
        }
    }

    private func showMessage(title: String, text: String) {
        if title == "请先开启本地代理" {
            promptToEnableProxyEngineForSystemProxy()
            return
        }
        if title == "无法启动代理引擎" {
            pendingSystemProxyRestore = false
        }
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.alertStyle = .warning
        alert.addButton(withTitle: "好")
        if let window { alert.beginSheetModal(for: window) }
    }
}

extension MainWindowController: ExternalControllerBackend {
    func controllerSnapshot() -> ExternalControllerSnapshot {
        let runtime = engine.runtimeSnapshot()
        return ExternalControllerSnapshot(
            mode: selectedMode,
            globalPolicy: selectedPolicy,
            groupSelections: groupSelections,
            profile: resolvedProfile ?? profile,
            engineStatus: engineStatus,
            httpListen: runtime.httpListen,
            socksListen: runtime.socksListen,
            uploaded: runtime.uploaded + enhancedUploaded,
            downloaded: runtime.downloaded + enhancedDownloaded,
            startedAt: runtime.startedAt,
            active: runtime.active,
            recent: runtime.recent,
            systemProxyEnabled: isSystemProxyActive,
            enhancedModeEnabled: isEnhancedModeActive,
            fakeIP: enhancedMode.fakeIPEntries(),
            policyLatencies: policyLatencies)
    }

    func controllerSetOutboundMode(_ mode: OutboundMode) {
        DispatchQueue.main.async { self.selectOutboundModeFromStatusItem(mode) }
    }

    func controllerSetGlobalPolicy(_ name: String) -> Bool {
        let known = profile.groups[name] == nil && profile.selectablePolicies.contains(name)
        if known {
            DispatchQueue.main.async { self.selectGlobalPolicyFromStatusItem(name) }
        }
        return known
    }

    func controllerSetGroupSelection(group: String, policy: String) -> Bool {
        guard profile.groups[group]?.members.contains(policy) == true else { return false }
        DispatchQueue.main.async { self.setGroupSelection(group: group, member: policy) }
        return true
    }

    func controllerSetSystemProxy(_ enabled: Bool) {
        DispatchQueue.main.async {
            guard enabled != self.isSystemProxyActive else { return }
            self.systemProxyButton.state = enabled ? .on : .off
            self.toggleSystemProxy()
        }
    }

    func controllerSetEnhancedMode(_ enabled: Bool) {
        DispatchQueue.main.async {
            guard enabled != self.isEnhancedModeActive else { return }
            self.enhancedModeButton.state = enabled ? .on : .off
            self.toggleEnhancedMode()
        }
    }

    func controllerReloadProfile() {
        DispatchQueue.main.async {
            do {
                let text = try self.configurationStore.loadTextThrowing()
                self.applyProfileTextInBackground(text, prefix: "控制器已重载",
                                                  allowExternalChanges: true,
                                                  completion: { [weak self] result in
                    guard let self, case .failure(let error) = result else { return }
                    self.showError(title: "控制器重载配置失败", error: error)
                })
            } catch {
                self.showError(title: "控制器重载配置失败", error: error)
            }
        }
    }

    func controllerFlushDNS() {
        engine.flushDNS()
        enhancedMode.flushDNS()
    }

    func controllerFlushFakeIP() {
        enhancedMode.flushFakeIP()
    }

    func controllerKillRequest(id: String) -> Bool {
        guard let uuid = UUID(uuidString: id) else { return false }
        return engine.killConnection(id: uuid)
    }

    func controllerTestGroup(_ name: String) {
        DispatchQueue.main.async { self.policyHealth.refresh() }
        _ = name
    }
}

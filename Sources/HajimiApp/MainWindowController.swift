import AppKit
import UniformTypeIdentifiers
import HajimiCore
import HajimiMacOSObjC

struct StatusPolicyGroupSelection {
    let name: String
    let members: [String]
    let selectedMember: String?
}

private enum HajimiTheme {
    private static func dynamic(light: NSColor, dark: NSColor) -> NSColor {
        NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
        }
    }

    static let workspace = dynamic(
        light: NSColor(srgbRed: 0.953, green: 0.976, blue: 0.965, alpha: 1),
        dark: NSColor(srgbRed: 0.027, green: 0.067, blue: 0.059, alpha: 1))
    static let sidebar = dynamic(
        light: NSColor(srgbRed: 0.975, green: 0.988, blue: 0.981, alpha: 1),
        dark: NSColor(srgbRed: 0.035, green: 0.082, blue: 0.071, alpha: 1))
    static let panel = dynamic(
        light: NSColor(srgbRed: 0.995, green: 0.998, blue: 0.996, alpha: 1),
        dark: NSColor(srgbRed: 0.055, green: 0.118, blue: 0.098, alpha: 1))
    static let border = dynamic(
        light: NSColor(srgbRed: 0.824, green: 0.882, blue: 0.851, alpha: 1),
        dark: NSColor(srgbRed: 0.125, green: 0.235, blue: 0.192, alpha: 1))
    static let selection = dynamic(
        light: NSColor(srgbRed: 0.858, green: 0.941, blue: 0.902, alpha: 1),
        dark: NSColor(srgbRed: 0.082, green: 0.196, blue: 0.153, alpha: 1))
    static let accent = NSColor(srgbRed: 0.216, green: 0.765, blue: 0.529, alpha: 1)
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
                                  NSCollectionViewDataSource, NSCollectionViewDelegate, NSMenuDelegate {
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

    private let sidebar = NSView()
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
    private let startButton = NSButton(title: "启动引擎", target: nil, action: nil)
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
    private let proxyCollectionView = ContextCollectionView()
    private let groupCollectionView = ContextCollectionView()
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
    private let sidebarStatusDot = NSView()
    private let sidebarStatusText = NSTextField(labelWithString: "已停止")
    private let sidebarStatusDetail = NSTextField(labelWithString: "本机代理引擎")
    private let dnsSummaryLabel = NSTextField(labelWithString: "使用系统 DNS")
    private let dnsEnabledButton = NSButton(checkboxWithTitle: "使用自定义 DNS 服务器", target: nil, action: nil)
    private let dnsServersTextView = NSTextView()
    private let dnsSettingsStatus = NSTextField(labelWithString: "")
    private var dnsSaveRequestID: UUID?
    private var navigationButtons: [NSButton] = []
    private var groupSelections: [String: String] = [:]
    /// Drives `url-test` and `fallback` groups. Its results are written into
    /// `groupSelections`, which routing already consults ahead of a group's
    /// declared order, so no routing code has to know health checking exists.
    private let policyHealth = PolicyHealthMonitor()
    private var policyLatencies: [String: [String: TimeInterval]] = [:]
    private var profileValidationGeneration = 0
    private var filteredProxyNames: [String] = []
    private var filteredRules: [RoutingRule] = []
    private var rulesPageSourceText: String?
    private var rulesPageProfile: Profile?
    private var ruleSelectionRefreshInProgress = false
    private var ruleOperationID: UUID?
    private var ruleEditor: RuleEditorSheetController?
    private var rulePolicyEditor: RulePolicySheetController?
    private var resolvedProfile: Profile?
    private var nodeLatencies: [String: NodeLatency] = [:]
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
    private var systemProxyIsOrWillBeEnabled: Bool {
        SystemProxyListenerPlan.protectsConfiguration(
            snapshotExists: systemProxy.isEnabledByHajimi,
            enableRequests: systemProxyEnableRequests)
    }
    private var staleSystemProxyCleanupAttempted = false
    private let externalController = ExternalController()
    private let ruleSetPreparationQueue = DispatchQueue(
        label: "app.hajimi.rule-set-preparation", qos: .userInitiated)
    private var engineStartGeneration = 0
    private var enhancedStartGeneration = 0
    private var profileRevision = 0
    private var profileApplyGeneration = 0
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

        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1220, height: 780),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                              backing: .buffered, defer: false)
        window.title = "哈基米"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.minSize = NSSize(width: 980, height: 800)
        window.center()
        super.init(window: window)
        buildUI()
        bindEngine()
        externalController.attach(backend: self)
        loadProfileText(text)
        if let error = launchProfilePlan.errorDescription {
            profileStatus.stringValue = "✕ 已阻止启动：\(error)"
            profileStatus.textColor = .systemRed
            profileStatus.toolTip = error
        }
        restorePreferences()
        restartExternalController()
        selectPage(0)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func launch() {
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        refreshPolicyHealth()
        // Refresh anything whose interval elapsed while the app was closed.
        // Silent: a launch-time alert would interrupt, and any failure is
        // visible in the subscription list.
        updateSubscriptions(names: subscriptions.dueForRefresh().map(\.name), announce: false)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            // A new process cannot adopt the previous App's utun FD. Leave a
            // live process alone; the Helper expires orphaned sessions itself.
            self.enhancedMode.prepareExistingSession(engine: self.engine) { result in
                if case .failure(let error) = result {
                    self.enhancedModeButton.state = .off
                    self.showError(title: "清理上次增强模式失败", error: error)
                }
                self.restoreLastSession()
            }
        }
    }

    var isEngineActive: Bool {
        switch engineStatus { case .running, .starting: return true; default: return false }
    }

    var isSystemProxyActive: Bool { systemProxy.isEnabledByHajimi }
    var isEnhancedModeActive: Bool { enhancedMode.isEnabled }

    var statusItemOutboundMode: OutboundMode { selectedMode }
    var statusItemGlobalPolicy: String { selectedPolicy }
    var statusItemGlobalPolicies: [String] { profile.selectablePolicies }
    var statusItemPolicyGroups: [StatusPolicyGroupSelection] {
        profile.groupOrder.compactMap { name in
            guard let group = profile.groups[name], group.kind == .select,
                  group.parameters["hidden"].map(surgeBoolean) != true else { return nil }
            let selected = groupSelections[name].flatMap { group.members.contains($0) ? $0 : nil }
                ?? group.members.first
            return StatusPolicyGroupSelection(name: name, members: group.members,
                                              selectedMember: selected)
        }
    }

    /// Bytes per second, engine and helper combined.
    ///
    /// This advances the measurement windows, so it is a function rather than a
    /// property: calling it twice in the same tick would consume a window and
    /// halve the reported rate.
    func statusItemTrafficRate() -> (upload: Double, download: Double) {
        let now = Date.timeIntervalSinceReferenceDate
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
        if case .failed(let message) = engineStatus { return "启动失败：\(message)" }
        if isEnhancedModeActive { return "运行中 · 增强模式 · \(selectedPolicy)" }
        if isSystemProxyActive { return "运行中 · 系统代理 · \(selectedPolicy)" }
        return isEngineActive ? "代理引擎运行中 · \(selectedPolicy)" : "代理引擎已停止"
    }

    func revealFromStatusItem() {
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
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
    }

    func selectGlobalPolicyFromStatusItem(_ name: String) {
        guard profile.selectablePolicies.contains(name) else { return }
        policyPopup.selectItem(withTitle: name)
        policyChanged()
    }

    func selectGroupMemberFromStatusItem(group: String, member: String) {
        guard profile.groups[group]?.members.contains(member) == true else { return }
        setGroupSelection(group: group, member: member)
    }

    /// Best-effort helper teardown for process exit. Safe to call more than once.
    func shutdownEnhancedModeForQuit() {
        enhancedMode.shutdownForQuit()
        enhancedModeButton.state = .off
        dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
        enhancedActiveConnections = 0
        enhancedTotalConnections = 0
        enhancedUploaded = 0
        enhancedDownloaded = 0
    }

    func restoreSystemProxyBeforeQuit() throws {
        // Enhanced mode is stopped separately in applicationShouldTerminate so
        // a system-proxy restore failure cannot leave utun routes installed.
        if enhancedMode.isEnabled { enhancedMode.shutdownForQuit() }
        // Always join the manager queue: an enable may have been enqueued but
        // not yet saved its snapshot when the user chooses Quit.
        try systemProxy.disableSynchronously()
        engine.stop()
        protocolAdapters.stop()
        externalController.stop()
    }

    private func buildUI() {
        guard let root = window?.contentView else { return }
        root.wantsLayer = true
        root.layer?.backgroundColor = HajimiTheme.workspace.cgColor
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
        buildProfileEditor()
        buildAbout()
        buildSettings()
        for view in [dashboardView, policiesView, rulesView, profileView, aboutView, settingsView] {
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
        sidebar.wantsLayer = true
        sidebar.layer?.backgroundColor = HajimiTheme.sidebar.cgColor
        sidebar.layer?.borderWidth = 0.5
        sidebar.layer?.borderColor = HajimiTheme.border.cgColor

        let logo = NSImageView(image: HajimiBrandIcon.makeImage())
        logo.imageScaling = .scaleProportionallyUpOrDown
        logo.imageAlignment = .alignCenter
        logo.contentTintColor = .labelColor
        logo.setAccessibilityLabel("哈基米橘猫图标")
        logo.translatesAutoresizingMaskIntoConstraints = false

        let title = NSTextField(labelWithString: "哈基米")
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        let subtitle = NSTextField(labelWithString: "Network Engine")
        subtitle.font = .systemFont(ofSize: 10, weight: .medium)
        subtitle.stringValue = "for macOS"
        subtitle.textColor = .secondaryLabelColor

        let titleStack = NSStackView(views: [title, subtitle])
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 0
        let brand = NSStackView(views: [logo, titleStack])
        brand.orientation = .horizontal
        brand.alignment = .centerY
        brand.spacing = 10
        brand.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(brand)
        NSLayoutConstraint.activate([
            brand.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 20),
            brand.topAnchor.constraint(equalTo: sidebar.topAnchor, constant: 54),
            logo.widthAnchor.constraint(equalToConstant: 44),
            logo.heightAnchor.constraint(equalToConstant: 44)
        ])

        let entries = [
            ("总览", "rectangle.3.group"),
            ("策略", "point.3.connected.trianglepath.dotted"),
            ("规则", "list.bullet.rectangle"),
            ("配置文件", "doc.text"),
            ("功能说明", "info.circle")
        ]
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .width
        stack.spacing = 5
        stack.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 14),
            stack.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -14),
            stack.topAnchor.constraint(equalTo: brand.bottomAnchor, constant: 34)
        ])
        for (index, entry) in entries.enumerated() {
            let button = NSButton(title: entry.0, target: self, action: #selector(navigate(_:)))
            button.tag = index
            button.bezelStyle = .recessed
            button.isBordered = false
            button.alignment = .left
            button.font = .systemFont(ofSize: 13, weight: .medium)
            button.image = NSImage(systemSymbolName: entry.1, accessibilityDescription: nil)
            button.imagePosition = .imageLeading
            button.contentTintColor = .labelColor
            button.wantsLayer = true
            button.layer?.cornerRadius = 8
            button.heightAnchor.constraint(equalToConstant: 40).isActive = true
            navigationButtons.append(button)
            stack.addArrangedSubview(button)
            button.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }

        let settingsButton = NSButton(title: "设置", target: self, action: #selector(navigate(_:)))
        settingsButton.tag = 5
        settingsButton.bezelStyle = .recessed
        settingsButton.isBordered = false
        settingsButton.alignment = .left
        settingsButton.font = .systemFont(ofSize: 13, weight: .medium)
        settingsButton.image = NSImage(systemSymbolName: "gearshape", accessibilityDescription: nil)
        settingsButton.imagePosition = .imageLeading
        settingsButton.contentTintColor = .labelColor
        settingsButton.wantsLayer = true
        settingsButton.layer?.cornerRadius = 8
        settingsButton.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(settingsButton)
        navigationButtons.append(settingsButton)
        NSLayoutConstraint.activate([
            settingsButton.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 14),
            settingsButton.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -14),
            settingsButton.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor, constant: -112),
            settingsButton.heightAnchor.constraint(equalToConstant: 40)
        ])

        sidebarStatusDot.wantsLayer = true
        sidebarStatusDot.layer?.cornerRadius = 4
        sidebarStatusDot.layer?.backgroundColor = NSColor.tertiaryLabelColor.cgColor
        sidebarStatusDot.translatesAutoresizingMaskIntoConstraints = false
        sidebarStatusText.font = .systemFont(ofSize: 12.5, weight: .semibold)
        sidebarStatusDetail.font = .systemFont(ofSize: 10)
        sidebarStatusDetail.textColor = .secondaryLabelColor
        let statusCopy = NSStackView(views: [sidebarStatusText, sidebarStatusDetail])
        statusCopy.orientation = .vertical
        statusCopy.alignment = .leading
        statusCopy.spacing = 2
        let sidebarStatus = NSStackView(views: [sidebarStatusDot, statusCopy])
        sidebarStatus.orientation = .horizontal
        sidebarStatus.alignment = .centerY
        sidebarStatus.spacing = 10
        sidebarStatus.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(sidebarStatus)

        let arch = NSTextField(labelWithString: "哈基米 0.1.0  ·  macOS")
        arch.font = .systemFont(ofSize: 10)
        arch.textColor = .tertiaryLabelColor
        arch.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(arch)
        NSLayoutConstraint.activate([
            sidebarStatus.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 20),
            sidebarStatus.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor, constant: -48),
            sidebarStatusDot.widthAnchor.constraint(equalToConstant: 8),
            sidebarStatusDot.heightAnchor.constraint(equalToConstant: 8),
            arch.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 20),
            arch.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor, constant: -18)
        ])
    }

    private func buildDashboard() {
        let header = pageHeader(eyebrow: "CONTROL CENTER", title: "网络总览",
                                subtitle: "本机代理状态、路由与流量")
        dashboardView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: dashboardView.topAnchor, constant: 48)
        ])

        let controls = cardView()
        controls.translatesAutoresizingMaskIntoConstraints = false
        dashboardView.addSubview(controls)
        NSLayoutConstraint.activate([
            controls.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            controls.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            controls.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 22),
            controls.heightAnchor.constraint(equalToConstant: 118)
        ])

        statusLabel.font = .systemFont(ofSize: 16, weight: .semibold)
        statusLabel.textColor = .secondaryLabelColor
        startButton.target = self
        startButton.action = #selector(toggleEngine)
        startButton.bezelStyle = .rounded
        startButton.bezelColor = HajimiTheme.accent
        startButton.keyEquivalent = "\r"
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

        let engineCaption = NSTextField(labelWithString: "PROXY ENGINE")
        engineCaption.font = .systemFont(ofSize: 9, weight: .bold)
        engineCaption.textColor = HajimiTheme.accent
        let engineIdentity = NSStackView(views: [engineCaption, statusLabel])
        engineIdentity.orientation = .vertical
        engineIdentity.alignment = .leading
        engineIdentity.spacing = 3
        let primarySpacer = NSView()
        primarySpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let primaryStack = NSStackView(views: [engineIdentity, primarySpacer,
                                               systemProxyButton, enhancedModeButton, startButton])
        primaryStack.orientation = .horizontal
        primaryStack.alignment = .centerY
        primaryStack.spacing = 14
        primaryStack.translatesAutoresizingMaskIntoConstraints = false
        let routingStack = NSStackView(views: [labeledControl("出站", modePopup),
                                               labeledControl("全局策略", policyPopup), separator(),
                                               labeledControl("策略组", groupPopup),
                                               labeledControl("当前成员", groupMemberPopup)])
        routingStack.orientation = .horizontal
        routingStack.alignment = .centerY
        routingStack.spacing = 14
        routingStack.translatesAutoresizingMaskIntoConstraints = false
        controls.addSubview(primaryStack)
        controls.addSubview(routingStack)
        NSLayoutConstraint.activate([
            primaryStack.leadingAnchor.constraint(equalTo: controls.leadingAnchor, constant: 18),
            primaryStack.trailingAnchor.constraint(lessThanOrEqualTo: controls.trailingAnchor, constant: -18),
            primaryStack.topAnchor.constraint(equalTo: controls.topAnchor, constant: 15),
            routingStack.leadingAnchor.constraint(equalTo: controls.leadingAnchor, constant: 18),
            routingStack.trailingAnchor.constraint(lessThanOrEqualTo: controls.trailingAnchor, constant: -18),
            routingStack.bottomAnchor.constraint(equalTo: controls.bottomAnchor, constant: -15)
        ])

        let stats = NSStackView()
        stats.orientation = .horizontal
        stats.distribution = .fillEqually
        stats.spacing = 12
        stats.translatesAutoresizingMaskIntoConstraints = false
        stats.addArrangedSubview(statCard(title: "活动连接", value: activeValue, color: HajimiTheme.accent))
        stats.addArrangedSubview(statCard(title: "累计连接", value: totalValue, color: .systemPurple))
        stats.addArrangedSubview(statCard(title: "上传流量", value: uploadValue, color: .systemOrange))
        stats.addArrangedSubview(statCard(title: "下载流量", value: downloadValue, color: .systemBlue))
        dashboardView.addSubview(stats)
        NSLayoutConstraint.activate([
            stats.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            stats.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            stats.topAnchor.constraint(equalTo: controls.bottomAnchor, constant: 14),
            stats.heightAnchor.constraint(equalToConstant: 86)
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
                               detail: "TCP 与 UDP ASSOCIATE", icon: "arrow.triangle.branch", color: .systemGreen),
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
            nativeTrafficView.topAnchor.constraint(equalTo: stats.bottomAnchor, constant: 14),
            nativeTrafficView.heightAnchor.constraint(equalToConstant: 102),
            runtimeTitle.topAnchor.constraint(equalTo: nativeTrafficView.bottomAnchor, constant: 14),
            runtimeCard.leadingAnchor.constraint(equalTo: dashboardView.leadingAnchor, constant: 30),
            runtimeCard.trailingAnchor.constraint(equalTo: dashboardView.trailingAnchor, constant: -30),
            runtimeCard.topAnchor.constraint(equalTo: runtimeTitle.bottomAnchor, constant: 10),
            runtimeCard.heightAnchor.constraint(equalToConstant: 132),
            runtimeColumns.leadingAnchor.constraint(equalTo: runtimeCard.leadingAnchor, constant: 8),
            runtimeColumns.trailingAnchor.constraint(equalTo: runtimeCard.trailingAnchor, constant: -8),
            runtimeColumns.topAnchor.constraint(equalTo: runtimeCard.topAnchor, constant: 10),
            runtimeColumns.bottomAnchor.constraint(equalTo: runtimeCard.bottomAnchor, constant: -10)
        ])
        updateOverviewDetails()
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
        proxySearchField.widthAnchor.constraint(equalToConstant: 245).isActive = true
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

        let proxyPanel = cardView()
        let groupPanel = cardView()
        proxyPanel.translatesAutoresizingMaskIntoConstraints = false
        groupPanel.translatesAutoresizingMaskIntoConstraints = false
        let panels = NSStackView(views: [proxyPanel, groupPanel])
        panels.orientation = .vertical
        panels.alignment = .leading
        panels.distribution = .fillEqually
        panels.spacing = 12
        panels.translatesAutoresizingMaskIntoConstraints = false
        policiesView.addSubview(panels)
        proxyPanel.widthAnchor.constraint(equalTo: panels.widthAnchor).isActive = true
        groupPanel.widthAnchor.constraint(equalTo: panels.widthAnchor).isActive = true

        let nodesTitle = sectionHeading("代理节点", detail: "双击编辑；右键可使用、测试、复制或删除")
        proxyPanel.addSubview(nodesTitle)
        let proxyScroll = NSScrollView()
        proxyScroll.hasVerticalScroller = true
        proxyScroll.autohidesScrollers = true
        proxyScroll.borderType = .noBorder
        proxyScroll.drawsBackground = false
        proxyScroll.translatesAutoresizingMaskIntoConstraints = false
        configureProxyCollection()
        proxyScroll.documentView = proxyCollectionView
        proxyPanel.addSubview(proxyScroll)
        NSLayoutConstraint.activate([
            nodesTitle.leadingAnchor.constraint(equalTo: proxyPanel.leadingAnchor, constant: 16),
            nodesTitle.trailingAnchor.constraint(equalTo: proxyPanel.trailingAnchor, constant: -16),
            nodesTitle.topAnchor.constraint(equalTo: proxyPanel.topAnchor, constant: 14),
            proxyScroll.leadingAnchor.constraint(equalTo: proxyPanel.leadingAnchor, constant: 6),
            proxyScroll.trailingAnchor.constraint(equalTo: proxyPanel.trailingAnchor, constant: -6),
            proxyScroll.topAnchor.constraint(equalTo: nodesTitle.bottomAnchor, constant: 10),
            proxyScroll.bottomAnchor.constraint(equalTo: proxyPanel.bottomAnchor, constant: -7)
        ])

        let groupsTitle = sectionHeading("策略组", detail: "下拉选择立即生效；右键编辑成员与组选项")
        groupPanel.addSubview(groupsTitle)
        let groupScroll = NSScrollView()
        groupScroll.hasVerticalScroller = true
        groupScroll.autohidesScrollers = true
        groupScroll.borderType = .noBorder
        groupScroll.drawsBackground = false
        groupScroll.translatesAutoresizingMaskIntoConstraints = false
        configureGroupCollection()
        groupScroll.documentView = groupCollectionView
        groupPanel.addSubview(groupScroll)
        NSLayoutConstraint.activate([
            groupsTitle.leadingAnchor.constraint(equalTo: groupPanel.leadingAnchor, constant: 16),
            groupsTitle.trailingAnchor.constraint(equalTo: groupPanel.trailingAnchor, constant: -16),
            groupsTitle.topAnchor.constraint(equalTo: groupPanel.topAnchor, constant: 14),
            groupScroll.leadingAnchor.constraint(equalTo: groupPanel.leadingAnchor, constant: 6),
            groupScroll.trailingAnchor.constraint(equalTo: groupPanel.trailingAnchor, constant: -6),
            groupScroll.topAnchor.constraint(equalTo: groupsTitle.bottomAnchor, constant: 10),
            groupScroll.bottomAnchor.constraint(equalTo: groupPanel.bottomAnchor, constant: -7)
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
            panels.leadingAnchor.constraint(equalTo: policiesView.leadingAnchor, constant: 30),
            panels.trailingAnchor.constraint(equalTo: policiesView.trailingAnchor, constant: -30),
            panels.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 13),
            panels.bottomAnchor.constraint(equalTo: policyStatusLabel.topAnchor, constant: -9),
            policyStatusLabel.leadingAnchor.constraint(equalTo: policiesView.leadingAnchor, constant: 32),
            policyStatusLabel.trailingAnchor.constraint(equalTo: policiesView.trailingAnchor, constant: -30),
            policyStatusLabel.bottomAnchor.constraint(equalTo: policiesView.bottomAnchor, constant: -18)
        ])
    }

    private func configureProxyCollection() {
        let layout = NSCollectionViewFlowLayout()
        layout.itemSize = NSSize(width: 176, height: 84)
        layout.sectionInset = NSEdgeInsets(top: 3, left: 6, bottom: 6, right: 6)
        layout.minimumInteritemSpacing = 8
        layout.minimumLineSpacing = 8
        layout.scrollDirection = .vertical
        proxyCollectionView.collectionViewLayout = layout
        proxyCollectionView.dataSource = self
        proxyCollectionView.delegate = self
        proxyCollectionView.isSelectable = true
        proxyCollectionView.backgroundColors = [.clear]
        proxyCollectionView.register(ProxyCardCollectionItem.self,
                                     forItemWithIdentifier: ProxyCardCollectionItem.identifier)
        proxyCollectionView.register(AddProxyCollectionItem.self,
                                     forItemWithIdentifier: AddProxyCollectionItem.identifier)
        proxyCollectionView.contextMenuProvider = { [weak self] indexPath -> NSMenu? in
            guard let self, self.filteredProxyNames.indices.contains(indexPath.item) else { return nil }
            return self.makeProxyMenu(name: self.filteredProxyNames[indexPath.item])
        }
    }

    private func configureGroupCollection() {
        let layout = NSCollectionViewFlowLayout()
        layout.itemSize = NSSize(width: 176, height: 88)
        layout.sectionInset = NSEdgeInsets(top: 3, left: 6, bottom: 6, right: 6)
        layout.minimumInteritemSpacing = 8
        layout.minimumLineSpacing = 8
        layout.scrollDirection = .vertical
        groupCollectionView.collectionViewLayout = layout
        groupCollectionView.dataSource = self
        groupCollectionView.delegate = self
        groupCollectionView.isSelectable = false
        groupCollectionView.backgroundColors = [.clear]
        groupCollectionView.register(GroupCardCollectionItem.self,
                                     forItemWithIdentifier: GroupCardCollectionItem.identifier)
        groupCollectionView.register(AddGroupCollectionItem.self,
                                     forItemWithIdentifier: AddGroupCollectionItem.identifier)
        groupCollectionView.contextMenuProvider = { [weak self] indexPath -> NSMenu? in
            guard let self, self.profile.groupOrder.indices.contains(indexPath.item) else { return nil }
            return self.makeGroupMenu(name: self.profile.groupOrder[indexPath.item])
        }
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
        ruleSearchField.widthAnchor.constraint(equalToConstant: 280).isActive = true
        ruleCountLabel.font = .systemFont(ofSize: 11)
        ruleCountLabel.textColor = .secondaryLabelColor
        let toolbar = NSStackView(views: [ruleSearchField, ruleCountLabel, NSView()])
        toolbar.orientation = .horizontal
        toolbar.alignment = .centerY
        toolbar.spacing = 11
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(toolbar)

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
            button.font = .systemFont(ofSize: 11.5)
            if button !== ruleMultiSelectButton { button.bezelStyle = .rounded }
        }
        ruleAddButton.image = NSImage(systemSymbolName: "plus", accessibilityDescription: nil)
        ruleEditButton.image = NSImage(systemSymbolName: "pencil", accessibilityDescription: nil)
        ruleDeleteButton.image = NSImage(systemSymbolName: "trash", accessibilityDescription: nil)
        ruleUpdateButton.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
        ruleMultiSelectButton.toolTip = "显示逐项勾选；也可用 ⌘ / Shift 多选"
        ruleSelectAllButton.toolTip = "只选择当前搜索结果，不包含隐藏规则"
        ruleSelectionCountLabel.font = .systemFont(ofSize: 10.5)
        ruleSelectionCountLabel.textColor = .secondaryLabelColor
        let actionViews: [NSView] = actions.map { $0.0 }
        let actionBar = NSStackView(views: actionViews + [NSView(), ruleSelectionCountLabel])
        actionBar.orientation = .horizontal
        actionBar.alignment = .centerY
        actionBar.spacing = 8
        actionBar.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(actionBar)

        ruleStatusLabel.font = .systemFont(ofSize: 10.5)
        ruleStatusLabel.textColor = .secondaryLabelColor
        ruleStatusLabel.maximumNumberOfLines = 2
        ruleStatusLabel.stringValue = "新增规则默认插入 FINAL / MATCH 之前；更新按钮刷新规则集，编辑可修改本地规则。"
        ruleStatusLabel.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(ruleStatusLabel)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.wantsLayer = true
        scroll.layer?.cornerRadius = 8
        scroll.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        scroll.translatesAutoresizingMaskIntoConstraints = false
        configureRulesTable()
        scroll.documentView = rulesTableView
        rulesView.addSubview(scroll)
        NSLayoutConstraint.activate([
            toolbar.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 30),
            toolbar.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            toolbar.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 20),
            actionBar.leadingAnchor.constraint(equalTo: toolbar.leadingAnchor),
            actionBar.trailingAnchor.constraint(equalTo: toolbar.trailingAnchor),
            actionBar.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 10),
            ruleStatusLabel.leadingAnchor.constraint(equalTo: toolbar.leadingAnchor),
            ruleStatusLabel.trailingAnchor.constraint(equalTo: toolbar.trailingAnchor),
            ruleStatusLabel.topAnchor.constraint(equalTo: actionBar.bottomAnchor, constant: 8),
            scroll.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 30),
            scroll.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            scroll.topAnchor.constraint(equalTo: ruleStatusLabel.bottomAnchor, constant: 12),
            scroll.bottomAnchor.constraint(equalTo: rulesView.bottomAnchor, constant: -24)
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
        rulesTableView.rowHeight = 30
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
            ("HTTP / HTTPS 出站", "CONNECT、正向转发、Basic 鉴权；TLS 默认验证证书", .systemGreen),
            ("SOCKS5 / SOCKS5-TLS", "支持用户名密码与本地 UDP；TLS 上游仅支持 TCP", .systemGreen),
            ("常见节点协议", "Swift 协议适配；C++ VLESS/Trojan 编码与 Objective-C TCP/TLS", .systemGreen),
            ("QUIC 与 AnyTLS", "Hysteria v1/v2、TUIC v5、AnyTLS 经静态链接的 Go 核心", .systemGreen),
            ("数据平面", "Objective-C++ 转发；C 报文；C++ 缓冲、重组、计时与规则", .systemGreen),
            ("macOS 系统代理", "手动启用；恢复前检查代理设置是否仍由哈基米管理", .systemGreen),
            ("增强模式 VIF", "root Helper 接管 utun；发现其他隧道时拒绝启动", .systemGreen),
            ("Network Extension", "Objective-C 接入；需签名、entitlement 与原生 Provider 引擎", .systemOrange),
            ("尚未实现", "MITM、Rewrite、WireGuard 与 Gateway VM 需要单独开发", .systemOrange)
        ]
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        aboutView.addSubview(stack)
        for item in items { stack.addArrangedSubview(capabilityRow(item.0, detail: item.1, color: item.2)) }
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: aboutView.leadingAnchor, constant: 30),
            stack.trailingAnchor.constraint(equalTo: aboutView.trailingAnchor, constant: -30),
            stack.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 28)
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
                                subtitle: "Helper 与原生 DNS")
        settingsOverviewView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: settingsOverviewView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: settingsOverviewView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: settingsOverviewView.topAnchor, constant: 48)
        ])

        let helperCard = cardView()
        helperCard.translatesAutoresizingMaskIntoConstraints = false
        settingsOverviewView.addSubview(helperCard)
        let helperTitle = NSTextField(labelWithString: "增强模式 Helper")
        helperTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        let helperDetail = NSTextField(wrappingLabelWithString:
            "Helper 只负责创建 utun、设置路由与 DNS，再把设备交给 App；协议出站不启动额外代理子进程。")
        helperDetail.font = .systemFont(ofSize: 11)
        helperDetail.textColor = .secondaryLabelColor
        helperStatusLabel.font = .systemFont(ofSize: 12, weight: .medium)
        helperStatusLabel.textColor = .secondaryLabelColor
        helperInstallButton.target = self
        helperInstallButton.action = #selector(installHelperFromSettings)
        helperUninstallButton.target = self
        helperUninstallButton.action = #selector(uninstallHelperFromSettings)
        helperUninstallButton.contentTintColor = .systemRed
        let helperButtons = NSStackView(views: [helperInstallButton, helperUninstallButton])
        helperButtons.orientation = .horizontal
        helperButtons.spacing = 8
        let helperText = NSStackView(views: [helperTitle, helperDetail, helperStatusLabel])
        helperText.orientation = .vertical
        helperText.alignment = .leading
        helperText.spacing = 7
        helperText.translatesAutoresizingMaskIntoConstraints = false
        helperButtons.translatesAutoresizingMaskIntoConstraints = false
        helperCard.addSubview(helperText)
        helperCard.addSubview(helperButtons)

        let dnsCard = cardView()
        dnsCard.translatesAutoresizingMaskIntoConstraints = false
        settingsOverviewView.addSubview(dnsCard)
        let dnsTitle = NSTextField(labelWithString: "DNS")
        dnsTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        dnsSummaryLabel.font = .systemFont(ofSize: 11)
        dnsSummaryLabel.textColor = .secondaryLabelColor
        dnsSummaryLabel.lineBreakMode = .byTruncatingMiddle
        let dnsText = NSStackView(views: [dnsTitle, dnsSummaryLabel])
        dnsText.orientation = .vertical
        dnsText.alignment = .leading
        dnsText.spacing = 6
        dnsText.translatesAutoresizingMaskIntoConstraints = false
        let openDNS = NSButton(title: "DNS 设置…", target: self, action: #selector(openDNSSettings))
        openDNS.translatesAutoresizingMaskIntoConstraints = false
        dnsCard.addSubview(dnsText)
        dnsCard.addSubview(openDNS)

        NSLayoutConstraint.activate([
            helperCard.leadingAnchor.constraint(equalTo: settingsOverviewView.leadingAnchor, constant: 30),
            helperCard.trailingAnchor.constraint(equalTo: settingsOverviewView.trailingAnchor, constant: -30),
            helperCard.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 24),
            helperCard.heightAnchor.constraint(equalToConstant: 154),
            helperText.leadingAnchor.constraint(equalTo: helperCard.leadingAnchor, constant: 20),
            helperText.trailingAnchor.constraint(lessThanOrEqualTo: helperButtons.leadingAnchor, constant: -18),
            helperText.centerYAnchor.constraint(equalTo: helperCard.centerYAnchor),
            helperButtons.trailingAnchor.constraint(equalTo: helperCard.trailingAnchor, constant: -20),
            helperButtons.centerYAnchor.constraint(equalTo: helperCard.centerYAnchor),
            helperDetail.widthAnchor.constraint(lessThanOrEqualToConstant: 530),
            dnsCard.leadingAnchor.constraint(equalTo: settingsOverviewView.leadingAnchor, constant: 30),
            dnsCard.trailingAnchor.constraint(equalTo: settingsOverviewView.trailingAnchor, constant: -30),
            dnsCard.topAnchor.constraint(equalTo: helperCard.bottomAnchor, constant: 14),
            dnsCard.heightAnchor.constraint(equalToConstant: 105),
            dnsText.leadingAnchor.constraint(equalTo: dnsCard.leadingAnchor, constant: 20),
            dnsText.centerYAnchor.constraint(equalTo: dnsCard.centerYAnchor),
            dnsText.trailingAnchor.constraint(lessThanOrEqualTo: openDNS.leadingAnchor, constant: -20),
            openDNS.trailingAnchor.constraint(equalTo: dnsCard.trailingAnchor, constant: -20),
            openDNS.centerYAnchor.constraint(equalTo: dnsCard.centerYAnchor)
        ])

        let extensionCard = cardView()
        extensionCard.translatesAutoresizingMaskIntoConstraints = false
        settingsOverviewView.addSubview(extensionCard)
        let extensionTitle = NSTextField(labelWithString: "Network Extension")
        extensionTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        let extensionDetail = NSTextField(wrappingLabelWithString:
            "Objective-C 隧道管理接口已接入。检查仅读取签名能力；不安装 VPN、不改动当前网络。")
        extensionDetail.font = .systemFont(ofSize: 11)
        extensionDetail.textColor = .secondaryLabelColor
        let extensionText = NSStackView(views: [extensionTitle, extensionDetail])
        extensionText.orientation = .vertical
        extensionText.alignment = .leading
        extensionText.spacing = 7
        extensionText.translatesAutoresizingMaskIntoConstraints = false
        let extensionCheck = NSButton(title: "检查接入条件…", target: self, action: #selector(checkNetworkExtension))
        extensionCheck.translatesAutoresizingMaskIntoConstraints = false
        extensionCard.addSubview(extensionText)
        extensionCard.addSubview(extensionCheck)
        NSLayoutConstraint.activate([
            extensionCard.leadingAnchor.constraint(equalTo: dnsCard.leadingAnchor),
            extensionCard.trailingAnchor.constraint(equalTo: dnsCard.trailingAnchor),
            extensionCard.topAnchor.constraint(equalTo: dnsCard.bottomAnchor, constant: 14),
            extensionCard.heightAnchor.constraint(equalToConstant: 105),
            extensionText.leadingAnchor.constraint(equalTo: extensionCard.leadingAnchor, constant: 20),
            extensionText.centerYAnchor.constraint(equalTo: extensionCard.centerYAnchor),
            extensionText.trailingAnchor.constraint(lessThanOrEqualTo: extensionCheck.leadingAnchor, constant: -20),
            extensionCheck.trailingAnchor.constraint(equalTo: extensionCard.trailingAnchor, constant: -20),
            extensionCheck.centerYAnchor.constraint(equalTo: extensionCard.centerYAnchor)
        ])

        let back = NSButton(title: "返回设置", target: self, action: #selector(closeDNSSettings))
        back.image = NSImage(systemSymbolName: "chevron.left", accessibilityDescription: nil)
        back.imagePosition = .imageLeading
        back.bezelStyle = .recessed
        back.isBordered = false
        back.translatesAutoresizingMaskIntoConstraints = false
        dnsSettingsView.addSubview(back)
        let dnsHeader = pageHeader(eyebrow: "DNS", title: "DNS 设置",
                                   subtitle: "解析器与域名映射")
        dnsSettingsView.addSubview(dnsHeader)

        let dnsEditorCard = cardView()
        dnsEditorCard.translatesAutoresizingMaskIntoConstraints = false
        dnsSettingsView.addSubview(dnsEditorCard)
        dnsEnabledButton.setButtonType(.switch)
        dnsEnabledButton.target = self
        dnsEnabledButton.action = #selector(dnsEnabledChanged)
        dnsEnabledButton.translatesAutoresizingMaskIntoConstraints = false
        dnsEditorCard.addSubview(dnsEnabledButton)
        let serverLabel = NSTextField(labelWithString: "DNS 服务器（每行一个，可使用 IP、主机名或 host:port）")
        serverLabel.font = .systemFont(ofSize: 11, weight: .medium)
        serverLabel.textColor = .secondaryLabelColor
        serverLabel.translatesAutoresizingMaskIntoConstraints = false
        dnsEditorCard.addSubview(serverLabel)
        let dnsScroll = NSScrollView()
        dnsScroll.hasVerticalScroller = true
        dnsScroll.borderType = .bezelBorder
        dnsScroll.translatesAutoresizingMaskIntoConstraints = false
        dnsServersTextView.isRichText = false
        dnsServersTextView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        dnsServersTextView.textContainerInset = NSSize(width: 8, height: 8)
        dnsServersTextView.frame = NSRect(x: 0, y: 0, width: 720, height: 146)
        dnsServersTextView.minSize = NSSize(width: 0, height: 146)
        dnsServersTextView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                            height: CGFloat.greatestFiniteMagnitude)
        dnsServersTextView.isVerticallyResizable = true
        dnsServersTextView.isHorizontallyResizable = false
        dnsServersTextView.autoresizingMask = [.width]
        dnsServersTextView.textContainer?.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                                                  height: CGFloat.greatestFiniteMagnitude)
        dnsServersTextView.textContainer?.widthTracksTextView = true
        dnsServersTextView.isAutomaticQuoteSubstitutionEnabled = false
        dnsServersTextView.isAutomaticDashSubstitutionEnabled = false
        dnsScroll.documentView = dnsServersTextView
        dnsEditorCard.addSubview(dnsScroll)
        let dnsNote = NSTextField(wrappingLabelWithString:
            "支持普通 UDP DNS 与 DoH。填入 https:// 端点后，未被 fake-IP 应答的查询改走加密通道；域名端点需附 bootstrap 地址（#8.8.8.8），否则解析它本身就会回到要替换掉的解析器。DoT 端点写作 tls://1.1.1.1 或 tls://dns.google#8.8.8.8。同时配置时优先用 DoH —— 它与普通 HTTPS 无异，而 DoT 的专用端口等于自报身份。")
        dnsNote.font = .systemFont(ofSize: 10.5)
        dnsNote.textColor = .secondaryLabelColor
        dnsNote.translatesAutoresizingMaskIntoConstraints = false
        dnsEditorCard.addSubview(dnsNote)
        dnsSettingsStatus.font = .systemFont(ofSize: 11, weight: .medium)
        dnsSettingsStatus.textColor = .secondaryLabelColor
        let saveDNS = NSButton(title: "保存并应用", target: self, action: #selector(saveDNSSettings))
        saveDNS.keyEquivalent = "\r"
        let dnsActions = NSStackView(views: [dnsSettingsStatus, NSView(), saveDNS])
        dnsActions.orientation = .horizontal
        dnsActions.alignment = .centerY
        dnsActions.translatesAutoresizingMaskIntoConstraints = false
        dnsSettingsView.addSubview(dnsActions)
        NSLayoutConstraint.activate([
            back.leadingAnchor.constraint(equalTo: dnsSettingsView.leadingAnchor, constant: 28),
            back.topAnchor.constraint(equalTo: dnsSettingsView.topAnchor, constant: 26),
            dnsHeader.leadingAnchor.constraint(equalTo: dnsSettingsView.leadingAnchor, constant: 30),
            dnsHeader.trailingAnchor.constraint(equalTo: dnsSettingsView.trailingAnchor, constant: -30),
            dnsHeader.topAnchor.constraint(equalTo: back.bottomAnchor, constant: 13),
            dnsEditorCard.leadingAnchor.constraint(equalTo: dnsSettingsView.leadingAnchor, constant: 30),
            dnsEditorCard.trailingAnchor.constraint(equalTo: dnsSettingsView.trailingAnchor, constant: -30),
            dnsEditorCard.topAnchor.constraint(equalTo: dnsHeader.bottomAnchor, constant: 22),
            dnsEditorCard.heightAnchor.constraint(equalToConstant: 350),
            dnsEnabledButton.leadingAnchor.constraint(equalTo: dnsEditorCard.leadingAnchor, constant: 20),
            dnsEnabledButton.topAnchor.constraint(equalTo: dnsEditorCard.topAnchor, constant: 18),
            serverLabel.leadingAnchor.constraint(equalTo: dnsEditorCard.leadingAnchor, constant: 20),
            serverLabel.topAnchor.constraint(equalTo: dnsEnabledButton.bottomAnchor, constant: 18),
            dnsScroll.leadingAnchor.constraint(equalTo: dnsEditorCard.leadingAnchor, constant: 20),
            dnsScroll.trailingAnchor.constraint(equalTo: dnsEditorCard.trailingAnchor, constant: -20),
            dnsScroll.topAnchor.constraint(equalTo: serverLabel.bottomAnchor, constant: 7),
            dnsScroll.heightAnchor.constraint(equalToConstant: 146),
            dnsNote.leadingAnchor.constraint(equalTo: dnsEditorCard.leadingAnchor, constant: 20),
            dnsNote.trailingAnchor.constraint(equalTo: dnsEditorCard.trailingAnchor, constant: -20),
            dnsNote.topAnchor.constraint(equalTo: dnsScroll.bottomAnchor, constant: 12),
            dnsActions.leadingAnchor.constraint(equalTo: dnsSettingsView.leadingAnchor, constant: 32),
            dnsActions.trailingAnchor.constraint(equalTo: dnsSettingsView.trailingAnchor, constant: -30),
            dnsActions.topAnchor.constraint(equalTo: dnsEditorCard.bottomAnchor, constant: 14)
        ])
        dnsSettingsView.isHidden = true
        refreshDNSSettingsFields()
    }

    private func refreshSettings() {
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

    private func refreshDNSSettingsFields() {
        // Navigation can happen while a DNS Save is preparing remote rules.
        // Do not replace its draft with the old profile until that request
        // finishes; only an actual user edit should change the displayed text.
        guard dnsSaveRequestID == nil else { return }
        let servers = profile.dnsServers
        dnsSummaryLabel.stringValue = servers.isEmpty
            ? "使用系统 DNS" : "自定义：" + servers.joined(separator: "，")
        dnsEnabledButton.state = servers.isEmpty ? .off : .on
        dnsServersTextView.string = servers.joined(separator: "\n")
        dnsServersTextView.isEditable = !servers.isEmpty
        dnsServersTextView.textColor = servers.isEmpty ? .secondaryLabelColor : .textColor
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
        if enhancedMode.isEnabled {
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
        dnsSettingsView.isHidden = true
        settingsOverviewView.isHidden = false
        refreshDNSSettingsFields()
    }

    @objc private func dnsEnabledChanged() {
        let enabled = dnsEnabledButton.state == .on
        dnsServersTextView.isEditable = enabled
        dnsServersTextView.textColor = enabled ? .textColor : .secondaryLabelColor
        if enabled && dnsServersTextView.string.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dnsServersTextView.string = "1.1.1.1\n8.8.8.8"
        }
    }

    @objc private func saveDNSSettings() {
        do {
            let enabled = dnsEnabledButton.state == .on
            let servers = enabled ? parsedDNSServerFields() : []
            if enabled && servers.isEmpty {
                throw ProfileApplyError.message("请至少填写一个 DNS 服务器")
            }
            if let invalid = servers.first(where: { !isValidPlainDNSServer($0) }) {
                throw ProfileApplyError.message("不支持的 DNS 地址：\(invalid)。可填普通 UDP DNS，或 DoH/DoT 端点。IP 端点直接可用（https://1.1.1.1/dns-query）；常见提供商已内置 bootstrap（\(EncryptedDNSBootstrap.knownHosts.prefix(4).joined(separator: "、")) 等）；其余域名端点需自附 bootstrap 地址，如 https://your.doh/dns-query#8.8.8.8。")
            }
            var document = SurgeProfileDocument(profileTextView.string)
            try document.setGeneralOption("dns-server",
                                          value: servers.isEmpty ? nil : servers.joined(separator: ", "))
            let dnsFields = dnsServersTextView.string
            let dnsEnabled = dnsEnabledButton.state
            let requestID = UUID()
            dnsSaveRequestID = requestID
            dnsSettingsStatus.stringValue = "正在后台准备 DNS 规则集…"
            dnsSettingsStatus.textColor = .systemBlue
            // Pressing Save commits this snapshot even if the user navigates
            // away. Later edits in this panel remain an unsaved draft instead
            // of being erased by the old asynchronous result.
            applyProfileTextInBackground(document.text, prefix: "DNS 已保存并应用",
                                         completion: { [weak self] result in
                guard let self, self.dnsSaveRequestID == requestID else { return }
                self.dnsSaveRequestID = nil
                switch result {
                case .success:
                    let draftUnchanged = self.dnsServersTextView.string == dnsFields
                        && self.dnsEnabledButton.state == dnsEnabled
                    if self.dnsSettingsView.isHidden || draftUnchanged {
                        self.refreshDNSSettingsFields()
                    }
                    self.dnsSettingsStatus.stringValue = draftUnchanged || self.dnsSettingsView.isHidden
                        ? "✓ 已保存；增强模式热重载完成"
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

    private func parsedDNSServerFields() -> [String] {
        dnsServersTextView.string
            .components(separatedBy: CharacterSet(charactersIn: ",\n\r"))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private func isValidPlainDNSServer(_ raw: String) -> Bool {
        // A DoH endpoint is validated by its own parser, which enforces HTTPS
        // and requires a bootstrap address for a named host.
        if raw.lowercased().hasPrefix("https://") { return DoHEndpoint(raw) != nil }
        if raw.lowercased().hasPrefix("tls://") { return DoTEndpoint(raw) != nil }
        var value = raw
        if value.lowercased().hasPrefix("udp://") { value.removeFirst(6) }
        guard !value.isEmpty, !value.contains("://"),
              value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              !value.contains("/"), !value.contains("#") else { return false }
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]"), close > value.index(after: value.startIndex) else { return false }
            let suffix = value[value.index(after: close)...]
            return suffix.isEmpty || (suffix.first == ":" && UInt16(suffix.dropFirst()).map { $0 > 0 } == true)
        }
        let colonCount = value.filter { $0 == ":" }.count
        if colonCount == 1, let colon = value.lastIndex(of: ":") {
            return colon > value.startIndex && UInt16(value[value.index(after: colon)...]).map { $0 > 0 } == true
        }
        return colonCount != 1 || !value.isEmpty
    }

    private func bindEngine() {
        engine.onStatus = { [weak self] status in
            DispatchQueue.main.async { self?.apply(status: status) }
        }
        engine.onEvent = { [weak self] event in
            DispatchQueue.main.async { self?.apply(event: event) }
        }
        protocolAdapters.onUnexpectedExit = { [weak self] message in
            guard let self else { return }
            self.engine.stop()
            self.showMessage(title: "高级协议适配器已退出", text: message)
        }
        enhancedMode.onStatus = { [weak self] status in
            guard let self else { return }
            switch status {
            case .stopped:
                self.enhancedModeButton.state = .off
                self.enhancedModeButton.isEnabled = true
                self.dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                self.enhancedActiveConnections = 0
            case .starting, .stopping:
                self.enhancedModeButton.isEnabled = false
            case .running(let interface, _):
                self.enhancedModeButton.state = .on
                self.enhancedModeButton.isEnabled = true
                self.dataPlaneRuntimeValue.stringValue = "Native · \(interface)"
            case .failed(let message):
                self.enhancedModeButton.state = self.enhancedMode.isEnabled ? .on : .off
                self.enhancedModeButton.isEnabled = true
                if !self.enhancedMode.isEnabled {
                    // A failed stop may have closed the helper's tunnel while
                    // leaving DNS cleanup pending. Do not auto-reopen it on
                    // the next launch before the helper finishes recovery.
                    self.persistEnhancedMode(false)
                }
                self.statusLabel.stringValue = "● 增强模式错误"
                self.statusLabel.textColor = .systemRed
                self.statusLabel.toolTip = message
            }
        }
        enhancedMode.onStatistics = { [weak self] active, total, up, down in
            guard let self else { return }
            self.enhancedActiveConnections = active
            self.enhancedTotalConnections = total
            self.enhancedUploaded = up
            self.enhancedDownloaded = down
            let now = Date.timeIntervalSinceReferenceDate
            self.enhancedUploadRate.observe(up, at: now)
            self.enhancedDownloadRate.observe(down, at: now)
            self.scheduleStatisticsUpdate()
        }
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
    }

    /// Re-applies the previous session's intent. A helper owned by another
    /// process is reported as busy rather than stopped behind its back.
    private func restoreLastSession() {
        let intent = launchProfilePlan.safeRestoreIntent(SessionRestoreIntent.load())
        if let error = launchProfilePlan.errorDescription {
            pendingSystemProxyRestore = false
            if UserDefaults.standard.bool(forKey: "enhancedModeEnabled") {
                persistEnhancedMode(false)
                enhancedModeButton.state = .off
            }
            statusLabel.stringValue = "配置无效，代理未启动"
            statusLabel.textColor = .systemRed
            showMessage(title: "配置无法加载，已阻止自动连接",
                        text: "\(error)\n请在“配置文件”中修复并保存配置。")
            // A previous crash may have left the system proxy pointing at our
            // stopped listener. Restore its snapshot rather than restarting
            // with the placeholder DIRECT profile.
            if systemProxy.isEnabledByHajimi {
                systemProxy.disable { [weak self] result in
                    if case .failure(let restoreError) = result {
                        self?.showError(title: "无法恢复旧系统代理", error: restoreError)
                    }
                }
            }
            return
        }
        if SystemProxyListenerPlan.needsStaleSnapshotCleanup(
            snapshotExists: systemProxy.isEnabledByHajimi, requested: intent) {
            guard !staleSystemProxyCleanupAttempted else {
                showMessage(title: "系统代理尚未恢复",
                            text: "旧系统代理快照仍存在；为避免连接到已停止的监听器，已阻止自动连接。请在总览中先恢复系统代理。")
                return
            }
            staleSystemProxyCleanupAttempted = true
            startButton.isEnabled = false
            systemProxyRecoveryInFlight = true
            systemProxyButton.isEnabled = false
            statusLabel.stringValue = "正在恢复旧系统代理…"
            systemProxy.disable { [weak self] result in
                guard let self else { return }
                self.startButton.isEnabled = true
                self.systemProxyRecoveryInFlight = false
                self.systemProxyButton.isEnabled = true
                switch result {
                case .success:
                    self.systemProxyAppliedAddress = nil
                    self.persistSystemProxy(false)
                    self.systemProxyButton.state = .off
                    self.restoreLastSession()
                case .failure(let error):
                    self.systemProxyButton.state = .on
                    self.statusLabel.stringValue = "系统代理未恢复，已阻止自动连接"
                    self.statusLabel.textColor = .systemRed
                    self.showError(title: "无法恢复旧系统代理", error: error)
                }
            }
            return
        }
        pendingSystemProxyRestore = intent.startEngine && intent.enableSystemProxy
        guard intent.startEngine || intent.startEnhancedMode else { return }
        let revision = profileRevision
        startButton.isEnabled = false
        statusLabel.stringValue = "正在准备规则集…"
        prepareRuleSetsInBackground(profile) { [weak self] result in
            guard let self else { return }
            self.startButton.isEnabled = true
            if revision != self.profileRevision {
                // A subscription refresh or user save completed while rules
                // were prepared. Restart preparation with the new profile.
                if !self.isEngineActive && !self.enhancedMode.isEnabled {
                    self.restoreLastSession()
                }
                return
            }
            switch result {
            case .failure(let error):
                self.pendingSystemProxyRestore = false
                if intent.startEnhancedMode {
                    self.persistEnhancedMode(false)
                    self.enhancedModeButton.state = .off
                }
                self.statusLabel.stringValue = "规则集准备失败"
                let title = intent.startEngine ? "无法启动代理引擎" : "无法恢复增强模式"
                self.showError(title: title, error: error)
            case .success(let prepared):
                if intent.startEngine {
                    do { try self.startEngineThrowing(prepared: prepared) } catch {
                        self.pendingSystemProxyRestore = false
                        self.showError(title: "无法启动代理引擎", error: error)
                    }
                } else {
                    self.statusLabel.stringValue = "已停止"
                }
                if intent.startEnhancedMode {
                    self.restoreEnhancedMode(prepared: prepared)
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

    private func restoreEnhancedMode(prepared: Profile) {
        let tunnelProfile: Profile
        do {
            tunnelProfile = try protocolAdapters.prepare(profile: prepared)
        } catch {
            persistEnhancedMode(false)
            enhancedModeButton.state = .off
            showError(title: "无法恢复增强模式", error: error)
            return
        }
        enhancedStartGeneration &+= 1
        let generation = enhancedStartGeneration
        let revision = profileRevision
        enhancedModeButton.isEnabled = false
        enhancedMode.start(profile: tunnelProfile, mode: selectedMode,
                           globalPolicy: selectedPolicy,
                           groupSelections: groupSelections,
                           engine: engine) { [weak self] result in
            guard let self, generation == self.enhancedStartGeneration else { return }
            guard revision == self.profileRevision else {
                self.discardStaleEnhancedStart(result)
                return
            }
            self.enhancedModeButton.isEnabled = true
            switch result {
            case .failure(let error):
                self.persistEnhancedMode(false)
                self.enhancedModeButton.state = .off
                self.showError(title: "无法恢复增强模式", error: error)
            case .success:
                self.persistEnhancedMode(true)
                self.enhancedModeButton.state = .on
            }
        }
    }

    private func applyPendingSystemProxyRestore() {
        guard pendingSystemProxyRestore else { return }
        pendingSystemProxyRestore = false
        guard engineStatus == .running else { return }
        systemProxyButton.isEnabled = false
        let address = engine.activeHTTPListen
        systemProxyEnableRequests += 1
        systemProxy.enable(address: address,
                           bypassDomains: profile.proxyBypassDomains) { [weak self] result in
            guard let self else { return }
            self.systemProxyEnableRequests -= 1
            self.systemProxyButton.isEnabled = true
            if case .failure(let error) = result {
                self.recoverSystemProxyAfterListenerFailure()
                self.showError(title: "无法恢复系统代理", error: error)
            } else {
                self.systemProxyAppliedAddress = address
                guard self.engineStatus == .running else {
                    self.recoverSystemProxyAfterListenerFailure()
                    return
                }
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
        guard engineStatus == .running, systemProxy.isEnabledByHajimi,
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
            self.systemProxyRebindInFlight = false
            self.systemProxyButton.isEnabled = true
            switch result {
            case .success:
                self.systemProxyAppliedAddress = address
                guard self.engineStatus == .running else {
                    self.recoverSystemProxyAfterListenerFailure()
                    return
                }
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
    }

    private func persistSystemProxy(_ enabled: Bool) {
        UserDefaults.standard.set(enabled, forKey: "systemProxyEnabled")
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
        policyPopup.removeAllItems()
        policyPopup.addItems(withTitles: profile.selectablePolicies)
        if let old, profile.selectablePolicies.contains(old) { policyPopup.selectItem(withTitle: old) }
        else { policyPopup.selectItem(withTitle: profile.selectablePolicies.first ?? "DIRECT") }
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
        let query = proxySearchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        filteredProxyNames = profile.proxyOrder.filter { name in
            guard !query.isEmpty else { return true }
            guard let policy = profile.proxies[name] else { return name.lowercased().contains(query) }
            return name.lowercased().contains(query) ||
                (policy.adapterType ?? policy.kind.rawValue).lowercased().contains(query) ||
                (policy.host ?? "").lowercased().contains(query)
        }
        proxyCountLabel.stringValue = query.isEmpty
            ? "\(profile.proxyOrder.count) 个节点"
            : "\(filteredProxyNames.count) / \(profile.proxyOrder.count)"
        proxyCollectionView.reloadData()
        groupCollectionView.reloadData()
        if policyStatusLabel.stringValue.isEmpty {
            policyStatusLabel.stringValue = "延迟为服务器 TCP 建连耗时；保存节点会短暂重启高级协议适配器，系统代理与增强模式保持开启。"
        }
    }

    private func refreshRulesPage() {
        let previousText = rulesPageSourceText
        let selectedLines = selectedRuleSourceLines
        let editorText = profileTextView.string
        var source: Profile
        do {
            if rulesPageSourceText == editorText, let cached = rulesPageProfile {
                source = cached
            } else {
                source = try ProfileParser.parse(editorText)
            }
            rulesPageSourceText = editorText
            // Reuse loaded content by resource URL while retaining the current
            // editor's rule order, values and physical source line numbers.
            let loaded = (resolvedProfile ?? profile).ruleSetContents
            source.ruleSetContents = [:]
            for reference in source.ruleSetReferences {
                if let content = loaded[reference.location] {
                    source.ruleSetContents[reference.location] = content
                }
            }
            rulesPageProfile = source
            if ruleOperationID == nil,
               ruleStatusLabel.stringValue.hasPrefix("配置草稿无效，当前规则只读：") {
                ruleStatusLabel.stringValue = "新增规则默认插入 FINAL / MATCH 之前；更新按钮刷新规则集，编辑可修改本地规则。"
                ruleStatusLabel.textColor = .secondaryLabelColor
                ruleStatusLabel.toolTip = nil
            }
        } catch {
            source = resolvedProfile ?? profile
            rulesPageSourceText = nil
            rulesPageProfile = nil
            if ruleOperationID == nil {
                ruleStatusLabel.stringValue = "配置草稿无效，当前规则只读：\(error.localizedDescription)"
                ruleStatusLabel.textColor = .systemRed
                ruleStatusLabel.toolTip = error.localizedDescription
            }
        }
        let query = ruleSearchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        filteredRules = source.rules.filter { rule in
            guard !query.isEmpty else { return true }
            let description = ruleDescription(rule)
            return description.type.lowercased().contains(query) ||
                description.value.lowercased().contains(query) ||
                rule.policy.lowercased().contains(query) || String(rule.sourceLine).contains(query)
        }
        let loaded = source.ruleSetContents.values.reduce(0) { $0 + $1.count }
        let ruleSetPart = source.ruleSetReferences.isEmpty
            ? "" : " · \(source.ruleSetReferences.count) 个 RULE-SET / \(loaded) 条子规则"
        ruleCountLabel.stringValue = query.isEmpty
            ? "\(source.rules.count) 条主规则\(ruleSetPart)"
            : "\(filteredRules.count) / \(source.rules.count)\(ruleSetPart)"
        if rulesPageSourceText != nil, editorText != lastKnownStoredProfileText {
            ruleCountLabel.stringValue += " · 未保存"
        }
        let retained = RuleTableSelection.retaining(
            selectedLines, visibleSourceLines: filteredRules.map(\.sourceLine),
            sourceTextChanged: previousText != rulesPageSourceText || rulesPageSourceText == nil)
        ruleSelectionRefreshInProgress = true
        rulesTableView.reloadData()
        rulesTableView.selectRowIndexes(
            RuleTableSelection.rowIndexes(sourceLines: retained,
                                          orderedSourceLines: filteredRules.map(\.sourceLine)),
            byExtendingSelection: false)
        ruleSelectionRefreshInProgress = false
        updateRuleSelectionControls()
    }

    private var selectedRuleSourceLines: Set<Int> {
        RuleTableSelection.sourceLines(rows: rulesTableView.selectedRowIndexes,
                                       orderedSourceLines: filteredRules.map(\.sourceLine))
    }

    private var selectedRuleSetLocations: Set<String> {
        let lines = selectedRuleSourceLines
        let source = lines.isEmpty ? (rulesPageProfile?.rules ?? [])
            : filteredRules.filter { lines.contains($0.sourceLine) }
        return Set(source.compactMap { rule in
            if case .ruleSet(let reference) = rule.kind { return reference.location }
            return nil
        })
    }

    private func updateRuleSelectionControls() {
        let count = selectedRuleSourceLines.count
        let editable = rulesPageSourceText == profileTextView.string && rulesPageProfile != nil
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
                                          orderedSourceLines: filteredRules.map(\.sourceLine)),
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
        policyHealth.onSelectionsChanged = { [weak self] selections in
            DispatchQueue.main.async {
                guard let self else { return }
                var changed = false
                for (group, member) in selections
                where self.groupSelections[group] != member {
                    self.groupSelections[group] = member
                    changed = true
                }
                // Automatic selections are deliberately not persisted to
                // UserDefaults: they are a live measurement, and restoring a
                // stale one at launch would point traffic at whatever was
                // fastest yesterday.
                guard changed else { return }
                self.updateEngineRouting()
                self.refreshPolicyPage()
            }
        }
        policyHealth.onReport = { [weak self] report in
            DispatchQueue.main.async {
                self?.policyLatencies[report.group] = report.latencies
                self?.refreshPolicyPage()
            }
        }
        policyHealth.update(profile: resolvedProfile ?? profile)
    }

    private func updateEngineRouting() {
        engine.updateRouting(mode: selectedMode, globalPolicy: selectedPolicy,
                             groupSelections: groupSelections)
        if enhancedMode.isEnabled {
            do {
                let runtime = try protocolAdapters.prepare(profile: resolvedProfile ?? profile)
                try enhancedMode.reload(profile: runtime, mode: selectedMode,
                                        globalPolicy: selectedPolicy,
                                        groupSelections: groupSelections)
            } catch {
                showError(title: "原生 TUN 热重载失败", error: error)
            }
        }
    }

    @objc private func navigate(_ sender: NSButton) { selectPage(sender.tag) }

    private func selectPage(_ index: Int) {
        let pages = [dashboardView, policiesView, rulesView, profileView, aboutView, settingsView]
        for (pageIndex, view) in pages.enumerated() { view.isHidden = pageIndex != index }
        for (buttonIndex, button) in navigationButtons.enumerated() {
            button.contentTintColor = buttonIndex == index ? HajimiTheme.accent : .labelColor
            button.font = .systemFont(ofSize: 13, weight: buttonIndex == index ? .semibold : .medium)
            button.layer?.backgroundColor = buttonIndex == index
                ? HajimiTheme.selection.cgColor : NSColor.clear.cgColor
        }
        if index == 1 { refreshPolicyPage() }
        if index == 2 { refreshRulesPage() }
        if index == 5 { refreshSettings() }
    }

    @objc private func toggleEngine() {
        switch engineStatus {
        case .running, .starting:
            startButton.isEnabled = false
            disableSystemProxyAndStopEngine()
        default: startEngine()
        }
    }

    private func disableSystemProxyAndStopEngine() {
        if systemProxy.isEnabledByHajimi {
            systemProxyButton.isEnabled = false
            systemProxy.disable { [weak self] result in
                guard let self else { return }
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
        engineStartGeneration += 1
        let generation = engineStartGeneration
        let revision = profileRevision
        startButton.isEnabled = false
        statusLabel.stringValue = "正在准备规则集…"
        prepareRuleSetsInBackground(profile) { [weak self] result in
            guard let self, generation == self.engineStartGeneration else { return }
            self.startButton.isEnabled = true
            guard revision == self.profileRevision else {
                self.statusLabel.stringValue = "配置已更新，请重新启动代理引擎"
                return
            }
            do {
                try self.startEngineThrowing(prepared: result.get())
            } catch {
                self.protocolAdapters.stop()
                self.statusLabel.stringValue = "启动失败"
                self.showError(title: "无法启动代理引擎", error: error)
            }
        }
    }

    private func prepareRuleSetsInBackground(
        _ source: Profile,
        completion: @escaping (Result<Profile, Error>) -> Void
    ) {
        ruleSetPreparationQueue.async { [weak self] in
            guard let self else { return }
            let result = Result { try self.surgeRuleSets.prepare(profile: source) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    private func startEngineThrowing(prepared resolved: Profile) throws {
        guard launchProfilePlan.profile != nil else {
            throw ProfileApplyError.message("已保存配置无效，请修复并保存后再启动")
        }
        // Preserve the listener address that the OS proxy is already using.
        // The configured port may become free during a reload, and re-running
        // the port allocator must not silently strand the system proxy.
        let preferredHTTP = SystemProxyListenerPlan.preferred(
            configured: resolved.httpListen, active: engine.activeHTTPListen,
            engineRunning: engineStatus == .running,
            systemProxyEnabled: systemProxyIsOrWillBeEnabled)
        engine.stop()
        var runtimeProfile = try protocolAdapters.prepare(profile: resolved)
        runtimeProfile.httpListen = preferredHTTP
        do {
            try engine.start(profile: runtimeProfile, mode: selectedMode,
                             globalPolicy: selectedPolicy, groupSelections: groupSelections)
            resolvedProfile = resolved
            UserDefaults.standard.set(true, forKey: "proxyEngineEnabled")
            refreshRulesPage()
        } catch {
            protocolAdapters.stop()
            throw error
        }
    }

    private func stopProxyEngine() {
        engine.stop()
        protocolAdapters.stop()
        systemProxyAppliedAddress = nil
        UserDefaults.standard.set(false, forKey: "proxyEngineEnabled")
        persistSystemProxy(false)
    }

    @objc private func toggleSystemProxy() {
        // Status-item and controller actions can arrive while the checkbox is
        // disabled for an administrator authorization. A second enable would
        // run after the first one and briefly restore the original proxy.
        guard systemProxyButton.isEnabled, systemProxyEnableRequests == 0,
              !systemProxyRebindInFlight, !systemProxyRecoveryInFlight else {
            systemProxyButton.state = systemProxyIsOrWillBeEnabled ? .on : .off
            return
        }
        if systemProxyButton.state == .on {
            guard engineStatus == .running else {
                systemProxyButton.state = .off
                showMessage(title: "请先启动引擎", text: "系统代理必须指向正在运行的 HTTP 监听器。")
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
                self.systemProxyEnableRequests -= 1
                self.systemProxyButton.isEnabled = true
                if case .failure(let error) = result {
                    self.recoverSystemProxyAfterListenerFailure()
                    self.showError(title: "设置系统代理失败", error: error)
                } else {
                    self.systemProxyAppliedAddress = address
                    guard self.engineStatus == .running else {
                        self.recoverSystemProxyAfterListenerFailure()
                        return
                    }
                    self.persistSystemProxy(true)
                    self.systemProxyButton.state = .on
                    self.reconcileSystemProxyListener()
                }
            }
        } else {
            systemProxyButton.isEnabled = false
            systemProxy.disable { [weak self] result in
                guard let self else { return }
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
        // Status-item and controller actions can arrive while the checkbox is
        // disabled for preparation/start; they must not queue a second start.
        guard enhancedModeButton.isEnabled else {
            enhancedModeButton.state = enhancedMode.isEnabled ? .on : .off
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
            enhancedStartGeneration &+= 1
            let generation = enhancedStartGeneration
            let revision = profileRevision
            enhancedModeButton.isEnabled = false
            dataPlaneRuntimeValue.stringValue = "正在准备 RULE-SET…"
            prepareRuleSetsInBackground(profile) { [weak self] result in
                guard let self, generation == self.enhancedStartGeneration else { return }
                guard revision == self.profileRevision else {
                    self.persistEnhancedMode(false)
                    self.enhancedModeButton.state = .off
                    self.enhancedModeButton.isEnabled = true
                    self.dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                    self.showMessage(title: "配置已更新",
                                     text: "准备规则集期间配置已更新，请重新开启增强模式。")
                    return
                }
                do {
                    let tunnelProfile = try self.protocolAdapters.prepare(profile: result.get())
                    self.dataPlaneRuntimeValue.stringValue = "正在开启原生 TUN…"
                    self.enhancedMode.start(profile: tunnelProfile, mode: self.selectedMode,
                                            globalPolicy: self.selectedPolicy,
                                            groupSelections: self.groupSelections,
                                            engine: self.engine) { [weak self] result in
                        guard let self, generation == self.enhancedStartGeneration else { return }
                        guard revision == self.profileRevision else {
                            self.discardStaleEnhancedStart(result)
                            return
                        }
                        self.enhancedModeButton.isEnabled = true
                        if case .failure(let error) = result {
                            self.persistEnhancedMode(false)
                            self.enhancedModeButton.state = .off
                            self.dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                            self.showError(title: "开启增强模式失败", error: error)
                        } else {
                            self.persistEnhancedMode(true)
                            self.enhancedModeButton.state = .on
                        }
                    }
                } catch {
                    self.persistEnhancedMode(false)
                    self.enhancedModeButton.state = .off
                    self.enhancedModeButton.isEnabled = true
                    self.dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
                    self.showError(title: "无法准备原生 TUN 路由", error: error)
                }
            }
        } else {
            enhancedStartGeneration &+= 1
            guard enhancedMode.isEnabled else {
                persistEnhancedMode(false)
                enhancedModeButton.state = .off
                return
            }
            enhancedModeButton.isEnabled = false
            enhancedMode.stop(engine: engine) { [weak self] result in
                guard let self else { return }
                self.enhancedModeButton.isEnabled = true
                if case .failure(let error) = result {
                    self.enhancedModeButton.state = .on
                    self.showError(title: "关闭增强模式失败", error: error)
                } else {
                    self.persistEnhancedMode(false)
                    self.enhancedModeButton.state = .off
                }
            }
        }
    }

    /// A profile saved while the helper was starting must not leave a tunnel
    /// running with the previous DNS, route and proxy settings.
    private func discardStaleEnhancedStart(_ result: Result<EnhancedModeManager.State, Error>) {
        persistEnhancedMode(false)
        switch result {
        case .failure:
            enhancedModeButton.state = .off
            enhancedModeButton.isEnabled = true
            dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
            showMessage(title: "配置已更新", text: "增强模式启动期间配置已更新，请重新开启。")
        case .success:
            enhancedModeButton.isEnabled = false
            enhancedMode.stop(engine: engine) { [weak self] stopped in
                guard let self else { return }
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
        proxyCollectionView.reloadData()
    }

    @objc private func policyChanged() {
        UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
        updateEngineRouting()
        updateOverviewDetails()
        proxyCollectionView.reloadData()
    }

    @objc private func groupChanged() {
        if let selectedGroup {
            UserDefaults.standard.set(selectedGroup, forKey: "selectedPolicyGroup")
        }
        refreshGroupMembers()
    }

    @objc private func groupMemberChanged() {
        guard let selectedGroup, let member = groupMemberPopup.titleOfSelectedItem else { return }
        // A url-test or fallback group's member is a measurement, not a
        // preference. Persisting a manual pick here would be overwritten by the
        // next probe round anyway.
        if let group = profile.groups[selectedGroup],
           PolicyHealthMonitor.managesSelection(of: group) {
            refreshGroupMembers()
            return
        }
        groupSelections[selectedGroup] = member
        UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
        updateEngineRouting()
        groupCollectionView.reloadData()
    }

    @objc private func proxySearchChanged() { refreshPolicyPage() }
    @objc private func ruleSearchChanged() { refreshRulesPage() }

    @objc private func ruleMultiSelectionChanged() {
        let selection = selectedRuleSourceLines
        updateRuleSelectionControls()
        ruleSelectionRefreshInProgress = true
        rulesTableView.reloadData()
        ruleSelectionRefreshInProgress = false
        selectRuleSourceLines(selection)
    }

    @objc private func selectAllRules() {
        rulesTableView.selectRowIndexes(IndexSet(integersIn: 0..<filteredRules.count),
                                        byExtendingSelection: false)
        updateRuleSelectionControls()
    }

    @objc private func clearRuleSelection() {
        rulesTableView.deselectAll(nil)
        updateRuleSelectionControls()
    }

    @objc private func ruleRowSelectionChanged(_ sender: NSButton) {
        guard rulesPageSourceText == profileTextView.string,
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
        guard rulesPageSourceText == profileTextView.string, rulesPageProfile != nil else {
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
                self.refreshRulesPage()
                self.selectRuleSourceLines(selection)
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
                    + (keepDraft ? "；规则草稿已保留在配置文件页，可修正后重试" : "")
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
        let alert = NSAlert()
        alert.messageText = "导入分享链接"
        alert.addButton(withTitle: "导入")
        alert.addButton(withTitle: "取消")

        let editor = NSTextView(frame: NSRect(x: 0, y: 0, width: 430, height: 130))
        editor.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        editor.isAutomaticQuoteSubstitutionEnabled = false
        editor.isAutomaticDashSubstitutionEnabled = false
        let scroll = NSScrollView(frame: editor.frame)
        scroll.documentView = editor
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        alert.accessoryView = scroll
        alert.window.initialFirstResponder = editor

        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self else { return }
            do {
                let result = try self.commitShareLinks(editor.string)
                let shownNames = result.names.prefix(8).joined(separator: "、")
                var message = "已添加 \(result.names.count) 个节点：\(shownNames)"
                if result.names.count > 8 { message += " 等" }
                if !result.warnings.isEmpty {
                    message += "\n\n" + result.warnings.prefix(8).joined(separator: "\n")
                    if result.warnings.count > 8 {
                        message += "\n另有 \(result.warnings.count - 8) 条提示"
                    }
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
        for name in profile.proxyOrder { testNode(named: name) }
        policyStatusLabel.stringValue = "正在并发测试 \(profile.proxyOrder.count) 个节点的 TCP 建连延迟…"
        policyStatusLabel.textColor = .systemBlue
    }

    private func editProxy(named name: String) {
        let document = SurgeProfileDocument(profileTextView.string)
        guard document.containsProxy(named: name) else {
            showMessage(title: "请在原始配置中编辑",
                        text: "“\(name)”来自 [WireGuard \(name)] 等独立配置段。为避免丢失 peer 字段，请在“配置文件”页面编辑该段；它仍可复制为新的 [Proxy] 节点。")
            return
        }
        guard let policy = profile.proxies[name] else { return }
        presentProxyEditor(draft: SurgeProxyDraft(policy: policy), originalName: name, isNew: false)
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

    private func commitProxyDraft(_ draft: SurgeProxyDraft, originalName: String?) throws {
        var document = SurgeProfileDocument(profileTextView.string)
        try document.upsertProxy(originalName: originalName, draft: draft)

        let oldSelectedPolicy = selectedPolicy
        let preferredPolicy = oldSelectedPolicy == originalName ? draft.name : oldSelectedPolicy
        let renamedGroups = originalName.map { oldName in
            groupSelections.compactMap { $0.value == oldName ? $0.key : nil }
        } ?? []
        let oldLatency = originalName.flatMap { nodeLatencies[$0] }
        try applyProfileText(document.text, prefix: originalName == nil ? "已添加并应用节点" : "已更新并应用节点",
                             preferredPolicy: preferredPolicy)
        if let originalName, originalName != draft.name {
            for group in renamedGroups where profile.groups[group]?.members.contains(draft.name) == true {
                groupSelections[group] = draft.name
            }
            nodeLatencies.removeValue(forKey: originalName)
            if let oldLatency { nodeLatencies[draft.name] = oldLatency }
            UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
            updateEngineRouting()
            refreshGroupMembers()
            refreshPolicyPage()
        }
        policyStatusLabel.stringValue = "✓ \(draft.name) 已写入 Profile" +
            ((engineStatus == .running || engineStatus == .starting) ? "，代理引擎已热重载" : "")
        policyStatusLabel.textColor = .systemGreen
    }

    private func commitShareLinks(_ text: String) throws
        -> (names: [String], warnings: [String]) {
        let parsed = try ShareLinkSubscription.parse(text)
        var document = SurgeProfileDocument(profileTextView.string)
        var used = Set(profile.proxies.keys).union(profile.groups.keys)
        var names: [String] = []
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
            try document.upsertProxy(originalName: nil, draft: draft)
            used.insert(candidate)
            names.append(candidate)
        }

        try applyProfileText(document.text, prefix: "已导入分享链接",
                             preferredPolicy: selectedPolicy)
        policyStatusLabel.stringValue = "✓ 已从分享链接导入 \(names.count) 个节点"
        policyStatusLabel.textColor = .systemGreen
        return (names, warnings)
    }

    private func commitGroupDraft(_ draft: SurgePolicyGroupDraft, originalName: String?) throws {
        var document = SurgeProfileDocument(profileTextView.string)
        try document.upsertGroup(originalName: originalName, draft: draft)
        let preferredPolicy = selectedPolicy == originalName ? draft.name : selectedPolicy
        let oldSelection = originalName.flatMap { groupSelections[$0] }
        try applyProfileText(document.text,
                             prefix: originalName == nil ? "已添加并应用策略组" : "已更新并应用策略组",
                             preferredPolicy: preferredPolicy)
        if let originalName, originalName != draft.name {
            groupSelections.removeValue(forKey: originalName)
            if let oldSelection, draft.members.contains(oldSelection) {
                groupSelections[draft.name] = oldSelection
            }
            for (group, member) in groupSelections where member == originalName {
                groupSelections[group] = draft.name
            }
        }
        UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
        updateEngineRouting()
        refreshGroups(preferred: draft.name)
        refreshPolicyPage()
        policyStatusLabel.stringValue = "✓ 策略组 \(draft.name) 已保存并应用"
        policyStatusLabel.textColor = .systemGreen
    }

    private func confirmDeleteProxy(named name: String) {
        let document = SurgeProfileDocument(profileTextView.string)
        guard document.containsProxy(named: name) else {
            showMessage(title: "不能在节点列表删除",
                        text: "该节点来自独立的 WireGuard 配置段，请在“配置文件”页面删除。")
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
                                          preferredPolicy: preferred)
                self.groupSelections = self.groupSelections.filter { $0.value != name }
                self.nodeLatencies.removeValue(forKey: name)
                UserDefaults.standard.set(self.groupSelections, forKey: "groupSelections")
                self.updateEngineRouting()
                self.policyStatusLabel.stringValue = "✓ 已删除 \(name)，相关引用已安全更新"
                self.policyStatusLabel.textColor = .systemGreen
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
                                          preferredPolicy: preferred)
                self.groupSelections.removeValue(forKey: name)
                self.groupSelections = self.groupSelections.filter { $0.value != name }
                UserDefaults.standard.set(self.groupSelections, forKey: "groupSelections")
                self.updateEngineRouting()
                self.refreshPolicyPage()
                self.policyStatusLabel.stringValue = "✓ 已删除策略组 \(name)"
                self.policyStatusLabel.textColor = .systemGreen
            } catch { self.showError(title: "删除策略组失败", error: error) }
        }
    }

    private func useProxy(named name: String) {
        guard profile.selectablePolicies.contains(name) else { return }
        modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: .proxy) ?? 2)
        policyPopup.selectItem(withTitle: name)
        policyPopup.isEnabled = true
        UserDefaults.standard.set(OutboundMode.proxy.rawValue, forKey: "outboundMode")
        UserDefaults.standard.set(name, forKey: "globalPolicy")
        updateEngineRouting()
        updateOverviewDetails()
        proxyCollectionView.reloadData()
        policyStatusLabel.stringValue = "✓ 全局代理已切换到 \(name)，新连接立即使用"
        policyStatusLabel.textColor = .systemGreen
    }

    private func testNode(named name: String) {
        guard let policy = profile.proxies[name], let host = policy.host, let port = policy.port else {
            nodeLatencies[name] = .failed
            proxyCollectionView.reloadData()
            return
        }
        nodeLatencies[name] = .testing
        proxyCollectionView.reloadData()
        TCPNodeLatencyProbe.measure(host: host, port: port) { [weak self] result in
            guard let self, self.profile.proxies[name]?.host == host,
                  self.profile.proxies[name]?.port == port else { return }
            switch result {
            case .success(let milliseconds): self.nodeLatencies[name] = .success(milliseconds)
            case .failure: self.nodeLatencies[name] = .failed
            }
            self.proxyCollectionView.reloadData()
            if !self.nodeLatencies.values.contains(.testing) {
                let successes = self.nodeLatencies.values.reduce(0) {
                    if case .success = $1 { return $0 + 1 }; return $0
                }
                self.policyStatusLabel.stringValue = "延迟测试完成：\(successes) 个节点可建立 TCP 连接"
                self.policyStatusLabel.textColor = .secondaryLabelColor
            }
        }
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
        if let member { groupSelections[name] = member } else { groupSelections.removeValue(forKey: name) }
        UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
        if selectedGroup == name { refreshGroupMembers() }
        updateEngineRouting()
        updateOverviewDetails()
        groupCollectionView.reloadData()
        policyStatusLabel.stringValue = member.map { "✓ \(name) 已切换到 \($0)" } ?? "✓ \(name) 已恢复配置默认行为"
        policyStatusLabel.textColor = .systemGreen
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

    private func makeGroupMenu(name: String) -> NSMenu {
        let menu = NSMenu(title: name)
        func item(_ title: String, _ action: Selector) -> NSMenuItem {
            let value = NSMenuItem(title: title, action: action, keyEquivalent: "")
            value.target = self
            value.representedObject = name
            return value
        }
        menu.addItem(item("编辑成员与选项…", #selector(groupMenuEdit(_:))))
        menu.addItem(item("复制策略组…", #selector(groupMenuDuplicate(_:))))
        menu.addItem(.separator())
        menu.addItem(item("删除策略组…", #selector(groupMenuDelete(_:))))
        return menu
    }

    private func populateProxyMenu(_ menu: NSMenu, name: String) {
        let editable = SurgeProfileDocument(profileTextView.string).containsProxy(named: name)
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
                let resolved = try self.surgeRuleSets.prepare(profile: value)
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
        let expectedStoredText = allowExternalChanges ? text : lastKnownStoredProfileText
        profileStatus.stringValue = "正在后台准备 RULE-SET…"
        profileStatus.textColor = .systemBlue
        profileStatus.toolTip = nil
        ruleSetPreparationQueue.async { [weak self] in
            guard let self else { return }
            let prepared: Result<(parsed: Profile, resolved: Profile), Error> = Result {
                let parsed = try ProfileParser.parse(text)
                return (parsed, try self.surgeRuleSets.prepare(
                    profile: parsed, forceRefreshLocations: forceRefreshRuleSetLocations))
            }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
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

    private func applyProfileText(_ text: String, prefix: String,
                                  preferredPolicy: String?,
                                  keepEditorOnFailure: Bool = false) throws {
        profileApplyGeneration &+= 1
        profileValidationGeneration &+= 1
        let expectedStoredText = lastKnownStoredProfileText
        try verifyStoredProfileHasNotChanged(expected: expectedStoredText)
        let parsed = try ProfileParser.parse(text)
        let resolved = try surgeRuleSets.prepare(profile: parsed)
        try applyPreparedProfileText(text, parsed: parsed, resolved: resolved,
                                     prefix: prefix, preferredPolicy: preferredPolicy,
                                     keepEditorOnFailure: keepEditorOnFailure,
                                     expectedStoredText: expectedStoredText)
    }

    private func applyPreparedProfileText(_ text: String, parsed: Profile,
                                          resolved: Profile, prefix: String,
                                          preferredPolicy: String?,
                                          keepEditorOnFailure: Bool = false,
                                          expectedStoredText: String? = nil) throws {
        try protocolAdapters.validate(profile: resolved)
        if systemProxyIsOrWillBeEnabled && parsed.httpListen != profile.httpListen {
            throw ProfileApplyError.message("HTTP 监听地址已变化。请先在总览中关闭系统代理。")
        }
        if systemProxyIsOrWillBeEnabled && parsed.proxyBypassDomains != profile.proxyBypassDomains {
            throw ProfileApplyError.message("Surge skip-proxy 绕过列表已变化。请先关闭系统代理。")
        }
        let wasRunning = engineStatus == .running || engineStatus == .starting
        let wasEnhanced = enhancedMode.isEnabled
        // If a live profile cannot be read, do not overwrite it with a
        // default rollback copy. An invalid profile that never started may
        // still be repaired and saved from the editor.
        let oldStoredText = wasRunning || wasEnhanced
            ? try configurationStore.loadTextThrowing() : configurationStore.loadText()
        try verifyStoredProfileHasNotChanged(expected: expectedStoredText)
        let oldEditorText = profileTextView.string
        let oldProfile = profile
        let oldResolved = resolvedProfile
        let oldSelectedPolicy = selectedPolicy
        let oldSelectedGroup = selectedGroup
        let oldGroupSelections = groupSelections
        let oldLatencies = nodeLatencies
        try configurationStore.save(text)
        profile = parsed
        resolvedProfile = resolved
        profileTextView.string = text
        refreshPolicies(preferred: preferredPolicy)
        UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
        groupSelections = groupSelections.filter { name, member in
            parsed.groups[name]?.members.contains(member) == true
        }
        UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
        refreshGroups(preferred: oldSelectedGroup)
        nodeLatencies = nodeLatencies.filter { parsed.proxies[$0.key] != nil }
        policyLatencies = policyLatencies.filter { parsed.groups[$0.key] != nil }
        refreshPolicyPage()
        refreshRulesPage()
        updateEngineRouting()
        updateOverviewDetails()
        refreshPolicyHealth()
        restartExternalController()

        if wasRunning || wasEnhanced {
            do {
                if wasEnhanced {
                    let runtime = try protocolAdapters.prepare(profile: resolved)
                    try enhancedMode.reload(profile: runtime, mode: selectedMode,
                                            globalPolicy: selectedPolicy,
                                            groupSelections: groupSelections)
                }
                if wasRunning {
                    try startEngineThrowing(prepared: resolved)
                }
            } catch {
                let restored = (try? configurationStore.save(oldStoredText)) != nil
                lastKnownStoredProfileText = restored ? oldStoredText : nil
                profile = oldProfile
                resolvedProfile = oldResolved
                profileTextView.string = keepEditorOnFailure ? oldEditorText : oldStoredText
                refreshPolicies(preferred: oldSelectedPolicy)
                UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
                groupSelections = oldGroupSelections
                UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
                nodeLatencies = oldLatencies
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
                restartExternalController()
                throw ProfileApplyError.message("新配置无法启动，已恢复旧配置：\(error.localizedDescription)")
            }
        }
        applyProfileValidationStatus(resolved, prefix: prefix)
        launchProfilePlan = .ready(parsed)
        lastKnownStoredProfileText = text
        profileRevision &+= 1
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

    @objc private func addSubscriptionAction() {
        let alert = NSAlert()
        alert.messageText = "添加订阅"
        alert.informativeText = "支持 Clash YAML 与 Surge .conf（可为 base64 包装）。"
            + "订阅内容会写入配置文件中的独立标记块，不会影响你手写的节点与规则。"
        alert.addButton(withTitle: "添加并更新")
        alert.addButton(withTitle: "取消")

        let nameField = NSTextField(frame: NSRect(x: 0, y: 58, width: 360, height: 22))
        nameField.placeholderString = "名称，例如 机场A"
        let urlField = NSTextField(frame: NSRect(x: 0, y: 30, width: 360, height: 22))
        urlField.placeholderString = "https://example.com/subscribe?token=…"
        let intervalField = NSTextField(frame: NSRect(x: 0, y: 2, width: 360, height: 22))
        intervalField.placeholderString = "自动更新间隔（小时），0 表示仅手动"
        intervalField.stringValue = "24"
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 360, height: 82))
        [nameField, urlField, intervalField].forEach(container.addSubview)
        alert.accessoryView = container
        alert.window.initialFirstResponder = nameField

        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self else { return }
            let name = nameField.stringValue.trimmingCharacters(in: .whitespaces)
            let url = urlField.stringValue.trimmingCharacters(in: .whitespaces)
            let hours = Double(intervalField.stringValue) ?? 24
            do {
                try self.subscriptions.add(name: name, url: url,
                                           updateInterval: max(0, hours) * 3600)
            } catch {
                self.showError(title: "添加订阅失败", error: error)
                return
            }
            self.updateSubscriptions(names: [name], announce: true)
        }
    }

    @objc private func manageSubscriptionsAction() {
        let all = subscriptions.all
        let alert = NSAlert()
        alert.messageText = "订阅"
        if all.isEmpty {
            alert.informativeText = "尚未添加任何订阅。"
            alert.addButton(withTitle: "好")
            alert.beginSheetModal(for: window ?? NSWindow()) { _ in }
            return
        }
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        alert.informativeText = all.map { subscription in
            var line = "• \(subscription.name)"
            if let format = subscription.lastFormat { line += "（\(format.rawValue)）" }
            line += "：\(subscription.lastProxyCount) 个节点"
            if let updated = subscription.lastUpdated {
                line += "，更新于 \(formatter.string(from: updated))"
            } else {
                line += "，尚未更新"
            }
            if let error = subscription.lastError { line += "\n   \(error)" }
            return line
        }.joined(separator: "\n")
        alert.addButton(withTitle: "全部更新")
        alert.addButton(withTitle: "移除…")
        alert.addButton(withTitle: "关闭")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            switch response {
            case .alertFirstButtonReturn:
                self.updateSubscriptions(names: all.map(\.name), announce: true)
            case .alertSecondButtonReturn:
                self.promptRemoveSubscription(all.map(\.name))
            default: break
            }
        }
    }

    private func promptRemoveSubscription(_ names: [String]) {
        let alert = NSAlert()
        alert.messageText = "移除订阅"
        alert.informativeText = "移除后，该订阅写入的节点与策略组会一并从配置中删除。"
        let popup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 300, height: 25))
        popup.addItems(withTitles: names)
        alert.accessoryView = popup
        alert.addButton(withTitle: "移除")
        alert.addButton(withTitle: "取消")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self,
                  let name = popup.titleOfSelectedItem else { return }
            let text = SubscriptionMerge.remove(name: name, from: self.profileTextView.string)
            self.applyProfileTextInBackground(text, prefix: "移除订阅",
                                              stillApplicable: { [weak self] in
                self?.subscriptions.all.contains(where: { $0.name == name }) == true
            }) { [weak self] result in
                guard let self else { return }
                switch result {
                case .success:
                    // The definition is durable only after the new profile
                    // has actually been applied and saved successfully.
                    self.subscriptions.remove(name: name)
                case .failure(let error):
                    self.showError(title: "移除订阅失败", error: error)
                }
            }
        }
    }

    /// Fetches named subscriptions off the main thread, then merges them into
    /// the latest editor text in one transaction on the main thread.
    private func updateSubscriptions(names: [String], announce: Bool) {
        guard !names.isEmpty else { return }
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
                    if announce { self.reportSubscriptionOutcome(results: [], failures: failures) }
                    return
                }
                let merged = SubscriptionRefreshMerge.apply(
                    current.map { (name: $0.name, contents: $0.contents) },
                    toCurrentText: { self.profileTextView.string })
                self.applyProfileTextInBackground(merged, prefix: "更新订阅",
                                                  keepEditorOnFailure: true,
                                                  stillApplicable: { [weak self] in
                    guard let self else { return false }
                    return current.allSatisfy(self.subscriptions.isCurrent)
                }) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .success:
                        for update in current { self.subscriptions.recordApplied(update) }
                        if announce {
                            self.reportSubscriptionOutcome(results: current.map(\.result),
                                                           failures: failures)
                        }
                    case .failure(let error):
                        for update in current {
                            self.subscriptions.recordFailure(name: update.name, error: error)
                        }
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
        let panel = NSOpenPanel()
        panel.title = "导入 Surge 配置"
        panel.prompt = "导入"
        panel.allowedContentTypes = ["conf", "ini", "txt"].compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard let window else { return }
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK, let url = panel.url, let self else { return }
            do {
                self.profileTextView.string = try String(contentsOf: url)
                self.profileStatus.stringValue = "已载入 \(url.lastPathComponent)，请检查后保存"
                self.profileStatus.textColor = .systemBlue
                self.profileStatus.toolTip = url.path
                self.validateProfile()
            } catch {
                self.showError(title: "无法读取 Surge 配置", error: error)
            }
        }
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

    private func apply(status: ProxyEngineStatus) {
        engineStatus = status
        switch status {
        case .stopped:
            activeConnectionIDs.removeAll(keepingCapacity: true)
            scheduleStatisticsUpdate()
            statusLabel.stringValue = enhancedMode.isEnabled ? "● 增强模式运行中（无 HTTP/SOCKS listener）" : "● 已停止"
            statusLabel.textColor = enhancedMode.isEnabled ? .systemGreen : .secondaryLabelColor
            sidebarStatusText.stringValue = enhancedMode.isEnabled ? "增强模式运行中" : "已停止"
            sidebarStatusDetail.stringValue = enhancedMode.isEnabled ? "原生 TUN 数据面" : "本机代理引擎"
            sidebarStatusDot.layer?.backgroundColor = (enhancedMode.isEnabled
                ? HajimiTheme.accent : NSColor.tertiaryLabelColor).cgColor
            startButton.title = "启动引擎"
        case .starting:
            statusLabel.stringValue = "● 正在启动"
            statusLabel.textColor = .systemOrange
            sidebarStatusText.stringValue = "正在启动"
            sidebarStatusDetail.stringValue = "正在准备监听与路由"
            sidebarStatusDot.layer?.backgroundColor = NSColor.systemOrange.cgColor
            startButton.title = "停止"
        case .running:
            statusLabel.stringValue =
                "● 运行中  HTTP :\(engine.activeHTTPListen.port)  SOCKS :\(engine.activeSOCKSListen.port)"
            statusLabel.textColor = .systemGreen
            sidebarStatusText.stringValue = "正在运行"
            sidebarStatusDetail.stringValue = "HTTP :\(engine.activeHTTPListen.port) · SOCKS :\(engine.activeSOCKSListen.port)"
            sidebarStatusDot.layer?.backgroundColor = HajimiTheme.accent.cgColor
            startButton.title = "停止"
            updateOverviewDetails()
            // Soft notice when ports were auto-relocated — not a hard failure.
            if engine.activeHTTPListen.port != profile.httpListen.port ||
                engine.activeSOCKSListen.port != profile.socksListen.port {
                statusLabel.toolTip =
                    "配置端口被占用，已自动改用 HTTP :\(engine.activeHTTPListen.port)、SOCKS :\(engine.activeSOCKSListen.port)"
            } else {
                statusLabel.toolTip = nil
            }
            applyPendingSystemProxyRestore()
            reconcileSystemProxyListener()
        case .failed(let message):
            activeConnectionIDs.removeAll(keepingCapacity: true)
            scheduleStatisticsUpdate()
            protocolAdapters.stop()
            statusLabel.stringValue = "● 启动失败"
            statusLabel.textColor = .systemRed
            sidebarStatusText.stringValue = "启动失败"
            sidebarStatusDetail.stringValue = message
            sidebarStatusDetail.lineBreakMode = .byTruncatingTail
            sidebarStatusDot.layer?.backgroundColor = NSColor.systemRed.cgColor
            startButton.title = "重试"
            statusLabel.toolTip = nil
            recoverSystemProxyAfterListenerFailure()
            showMessage(title: "代理引擎错误", text: message)
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

    func numberOfSections(in collectionView: NSCollectionView) -> Int { 1 }

    func collectionView(_ collectionView: NSCollectionView,
                        numberOfItemsInSection section: Int) -> Int {
        if collectionView === proxyCollectionView { return filteredProxyNames.count + 1 }
        if collectionView === groupCollectionView { return profile.groupOrder.count + 1 }
        return 0
    }

    func collectionView(_ collectionView: NSCollectionView,
                        itemForRepresentedObjectAt indexPath: IndexPath) -> NSCollectionViewItem {
        if collectionView === proxyCollectionView {
            if indexPath.item == filteredProxyNames.count {
                let item = collectionView.makeItem(withIdentifier: AddProxyCollectionItem.identifier,
                                                   for: indexPath) as! AddProxyCollectionItem
                item.configure { [weak self] in self?.addProxy() }
                return item
            }
            let name = filteredProxyNames[indexPath.item]
            let policy = profile.proxies[name]!
            let item = collectionView.makeItem(withIdentifier: ProxyCardCollectionItem.identifier,
                                               for: indexPath) as! ProxyCardCollectionItem
            item.configure(policy: policy, latency: nodeLatencies[name] ?? .untested,
                           active: selectedMode == .proxy && selectedPolicy == name,
                           onEdit: { [weak self] in self?.editProxy(named: name) })
            return item
        }
        if collectionView === groupCollectionView {
            if indexPath.item == profile.groupOrder.count {
                let item = collectionView.makeItem(withIdentifier: AddGroupCollectionItem.identifier,
                                                   for: indexPath) as! AddGroupCollectionItem
                item.configure { [weak self] in self?.addPolicyGroup() }
                return item
            }
            let name = profile.groupOrder[indexPath.item]
            let group = profile.groups[name]!
            let item = collectionView.makeItem(withIdentifier: GroupCardCollectionItem.identifier,
                                               for: indexPath) as! GroupCardCollectionItem
            item.configure(group: group, selected: groupSelections[name]) { [weak self] member in
                self?.setGroupSelection(group: name, member: member)
            }
            return item
        }
        return NSCollectionViewItem()
    }

    func collectionView(_ collectionView: NSCollectionView,
                        didSelectItemsAt indexPaths: Set<IndexPath>) {
        guard collectionView === proxyCollectionView, let indexPath = indexPaths.first,
              filteredProxyNames.indices.contains(indexPath.item) else { return }
        useProxy(named: filteredProxyNames[indexPath.item])
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
                checkbox.state = rulesTableView.selectedRowIndexes.contains(row) ? .on : .off
                checkbox.toolTip = "选择第 \(rule.sourceLine) 行规则"
                checkbox.setAccessibilityLabel("选择第 \(rule.sourceLine) 行规则")
                return checkbox
            }
            let description = ruleDescription(rule)
            let cell = NSTextField(labelWithString: "")
            cell.font = identifier.rawValue == "value"
                ? .monospacedSystemFont(ofSize: 10.5, weight: .regular)
                : .systemFont(ofSize: 11)
            cell.lineBreakMode = .byTruncatingMiddle
            switch identifier.rawValue {
            case "line":
                cell.stringValue = String(rule.sourceLine)
                cell.textColor = .tertiaryLabelColor
            case "type": cell.stringValue = description.type
            case "value":
                cell.stringValue = description.value
                cell.toolTip = description.value
            case "policy":
                cell.stringValue = rule.policy
                cell.textColor = .systemIndigo
            case "loaded":
                if case .ruleSet(let reference) = rule.kind {
                    let count = (rulesPageProfile ?? resolvedProfile ?? profile).ruleSetContents[reference.location]?.count
                    cell.stringValue = count.map { "\($0) 条" } ?? "未加载"
                    cell.textColor = count == nil ? .systemOrange : .systemGreen
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
        switch rule.kind {
        case .domain(let value): return ("DOMAIN", value)
        case .domainSuffix(let value): return ("DOMAIN-SUFFIX", value)
        case .domainKeyword(let value): return ("DOMAIN-KEYWORD", value)
        case .domainWildcard(let value): return ("DOMAIN-WILDCARD", value)
        case .ipCIDR(let value): return (value.contains(":") ? "IP-CIDR6" : "IP-CIDR", value)
        case .destinationPort(let range):
            return ("DEST-PORT", describePortRange(range))
        case .sourceIPCIDR(let value): return ("SRC-IP", value)
        case .sourcePort(let range): return ("SRC-PORT", describePortRange(range))
        case .inboundPort(let range): return ("IN-PORT", describePortRange(range))
        case .protocolName(let value): return ("PROTOCOL", value)
        case .geoIP(let value): return ("GEOIP", value)
        case .ipASN(let value): return ("IP-ASN", value)
        case .processName(let value): return ("PROCESS-NAME", value)
        case .logicalAnd(let children): return ("AND", describeLogical(children))
        case .logicalOr(let children): return ("OR", describeLogical(children))
        case .logicalNot(let child): return ("NOT", describeLogical([child]))
        case .ruleSet(let reference): return ("RULE-SET", reference.location)
        case .final: return ("FINAL", "匹配其余连接")
        }
    }

    private func describePortRange(_ range: ClosedRange<UInt16>) -> String {
        range.lowerBound == range.upperBound
            ? String(range.lowerBound) : "\(range.lowerBound)-\(range.upperBound)"
    }

    private func describeLogical(_ children: [RuleKind]) -> String {
        children.map { child in
            let description = ruleDescription(RoutingRule(kind: child, policy: "", sourceLine: 0))
            return "\(description.type),\(description.value)"
        }.joined(separator: "; ")
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
        heading.font = .systemFont(ofSize: 27, weight: .bold)
        let detail = NSTextField(labelWithString: subtitle)
        detail.font = .systemFont(ofSize: 12)
        detail.textColor = .secondaryLabelColor
        var views: [NSView] = []
        if let eyebrow {
            let label = NSTextField(labelWithString: eyebrow)
            label.font = .systemFont(ofSize: 9.5, weight: .bold)
            label.textColor = HajimiTheme.accent
            views.append(label)
        }
        views.append(contentsOf: [heading, detail])
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = eyebrow == nil ? 4 : 5
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }

    private func cardView() -> NSView {
        let view = NSView()
        view.wantsLayer = true
        view.layer?.cornerRadius = 8
        view.layer?.backgroundColor = HajimiTheme.panel.cgColor
        view.layer?.borderWidth = 1
        view.layer?.borderColor = HajimiTheme.border.cgColor
        return view
    }

    private func statCard(title: String, value: NSTextField, color: NSColor) -> NSView {
        let card = cardView()
        value.font = .monospacedDigitSystemFont(ofSize: 20, weight: .semibold)
        value.textColor = color
        let label = NSTextField(labelWithString: title)
        label.font = .systemFont(ofSize: 11, weight: .medium)
        label.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [value, label])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 3
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 15),
            stack.centerYAnchor.constraint(equalTo: card.centerYAnchor)
        ])
        return card
    }

    private func overviewInfoColumn(title: String, value: NSTextField, detail: String,
                                    icon: String, color: NSColor) -> NSView {
        let container = NSView()
        let image = NSImageView(image: NSImage(systemSymbolName: icon,
                                               accessibilityDescription: title) ?? NSImage())
        image.contentTintColor = color
        image.symbolConfiguration = .init(pointSize: 16, weight: .medium)
        image.translatesAutoresizingMaskIntoConstraints = false
        value.font = .monospacedSystemFont(ofSize: 13, weight: .semibold)
        value.lineBreakMode = .byTruncatingMiddle
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 10.5, weight: .medium)
        titleLabel.textColor = .secondaryLabelColor
        let detailLabel = NSTextField(labelWithString: detail)
        detailLabel.font = .systemFont(ofSize: 9.5)
        detailLabel.textColor = .tertiaryLabelColor
        detailLabel.lineBreakMode = .byTruncatingTail
        let text = NSStackView(views: [titleLabel, value, detailLabel])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 4
        text.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(image)
        container.addSubview(text)
        NSLayoutConstraint.activate([
            image.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            image.topAnchor.constraint(equalTo: container.topAnchor, constant: 14),
            image.widthAnchor.constraint(equalToConstant: 22),
            image.heightAnchor.constraint(equalToConstant: 22),
            text.leadingAnchor.constraint(equalTo: image.trailingAnchor, constant: 9),
            text.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -8),
            text.centerYAnchor.constraint(equalTo: container.centerYAnchor)
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
        return box
    }

    private func capabilityRow(_ title: String, detail: String, color: NSColor) -> NSView {
        let card = cardView()
        card.heightAnchor.constraint(equalToConstant: 50).isActive = true
        let dot = NSTextField(labelWithString: "●")
        dot.textColor = color
        dot.font = .systemFont(ofSize: 13)
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        let detailLabel = NSTextField(labelWithString: detail)
        detailLabel.font = .systemFont(ofSize: 11)
        detailLabel.textColor = .secondaryLabelColor
        let text = NSStackView(views: [titleLabel, detailLabel])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 3
        let row = NSStackView(views: [dot, text])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 12
        row.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 17),
            row.trailingAnchor.constraint(lessThanOrEqualTo: card.trailingAnchor, constant: -17),
            row.centerYAnchor.constraint(equalTo: card.centerYAnchor)
        ])
        return card
    }

    private func showError(title: String, error: Error) { showMessage(title: title, text: error.localizedDescription) }

    private func showMessage(title: String, text: String) {
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
        let known = profile.selectablePolicies.contains(name)
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

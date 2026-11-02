import AppKit
import Darwin
import HajimiCore
import HajimiNativeCore

// A stale/restarting privileged Helper may close its Unix socket between
// connect and write. Convert that race into EPIPE instead of terminating the
// GUI process with SIGPIPE.
signal(SIGPIPE, SIG_IGN)

/// Custom menu item view that renders a native menu selection highlight on hover
/// and invokes its action on click without dismissing the enclosing NSMenu.
private final class StatusMenuActionItemView: NSView {
    private let highlightView = NSVisualEffectView()
    private let iconView = NSImageView()
    private let titleField = NSTextField(labelWithString: "")
    private var trackingAreaRef: NSTrackingArea?
    private var isHovered = false
    private var didFireInCurrentPress = false
    var onAction: (() -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        autoresizingMask = [.width]

        highlightView.material = .selection
        highlightView.blendingMode = .withinWindow
        highlightView.state = .active
        highlightView.isEmphasized = true
        highlightView.wantsLayer = true
        highlightView.layer?.cornerRadius = 5
        highlightView.isHidden = true
        highlightView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(highlightView)

        iconView.imageScaling = .scaleProportionallyDown
        iconView.contentTintColor = .controlTextColor
        iconView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(iconView)

        titleField.font = NSFont.menuFont(ofSize: 0)
        titleField.textColor = .controlTextColor
        titleField.lineBreakMode = .byTruncatingTail
        titleField.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleField)

        NSLayoutConstraint.activate([
            highlightView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 5),
            highlightView.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -5),
            highlightView.topAnchor.constraint(equalTo: topAnchor, constant: 1),
            highlightView.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -1),
            iconView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 22),
            iconView.centerYAnchor.constraint(equalTo: centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 16),
            iconView.heightAnchor.constraint(equalToConstant: 16),
            titleField.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 6),
            titleField.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -14),
            titleField.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(title: String, image: NSImage?) {
        if titleField.stringValue != title {
            titleField.stringValue = title
        }
        if iconView.image !== image {
            iconView.image = image
        }
        updateHighlightAppearance()
    }

    func resetHoverState() {
        isHovered = false
        didFireInCurrentPress = false
        updateHighlightAppearance()
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingAreaRef {
            removeTrackingArea(trackingAreaRef)
        }
        let options: NSTrackingArea.Options = [
            .mouseEnteredAndExited,
            .mouseMoved,
            .activeAlways,
            .inVisibleRect,
            .enabledDuringMouseDrag,
        ]
        let area = NSTrackingArea(rect: bounds, options: options, owner: self, userInfo: nil)
        addTrackingArea(area)
        trackingAreaRef = area
    }

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func mouseEntered(with event: NSEvent) {
        isHovered = true
        updateHighlightAppearance()
    }

    override func mouseMoved(with event: NSEvent) {
        let inside = bounds.contains(convert(event.locationInWindow, from: nil))
        if inside != isHovered {
            isHovered = inside
            updateHighlightAppearance()
        }
    }

    override func mouseExited(with event: NSEvent) {
        isHovered = false
        updateHighlightAppearance()
    }

    override func mouseDown(with event: NSEvent) {
        didFireInCurrentPress = true
        isHovered = true
        updateHighlightAppearance()
        onAction?()
    }

    override func mouseUp(with event: NSEvent) {
        let inside = bounds.contains(convert(event.locationInWindow, from: nil))
        if !didFireInCurrentPress && inside {
            onAction?()
        }
        didFireInCurrentPress = false
        isHovered = inside
        updateHighlightAppearance()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil {
            resetHoverState()
        }
    }

    private func updateHighlightAppearance() {
        let active = isHovered || (enclosingMenuItem?.isHighlighted ?? false)
        highlightView.isHidden = !active
        let color: NSColor = active ? .selectedMenuItemTextColor : .controlTextColor
        titleField.textColor = color
        iconView.contentTintColor = color
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var mainWindowController: MainWindowController?
    private var statusItem: NSStatusItem?
    private var trafficTicker: Timer?
    private var isStatusMenuOpen = false
    private var processActivityToken: NSObjectProtocol?

    private final class PolicyGroupMenuEntry {
        let groupName: String
        let item: NSMenuItem
        let submenu: NSMenu
        let testItem: NSMenuItem
        let testView: StatusMenuActionItemView
        let defaultItem: NSMenuItem
        let separatorItem = NSMenuItem.separator()

        init(groupName: String, onTestGroup: @escaping () -> Void, target: AnyObject, defaultAction: Selector) {
            self.groupName = groupName
            self.item = NSMenuItem(title: groupName, action: nil, keyEquivalent: "")
            self.submenu = NSMenu(title: groupName)
            self.submenu.minimumWidth = 280
            self.testItem = NSMenuItem(title: "⚡ 测速本组节点", action: nil, keyEquivalent: "")
            self.testView = StatusMenuActionItemView(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
            self.testView.onAction = onTestGroup
            self.testItem.view = self.testView
            self.defaultItem = NSMenuItem(title: "配置默认", action: defaultAction, keyEquivalent: "")
            self.defaultItem.target = target
            self.defaultItem.representedObject = ["group": groupName]
            self.submenu.addItem(self.testItem)
            self.submenu.addItem(self.defaultItem)
            self.submenu.addItem(self.separatorItem)
            self.item.submenu = self.submenu
        }
    }

    private let statusSummaryItem = NSMenuItem(title: "代理引擎已停止", action: nil, keyEquivalent: "")
    private let engineItem = NSMenuItem(title: "启动代理引擎", action: #selector(toggleEngineFromStatusItem), keyEquivalent: "")
    private let systemProxyItem = NSMenuItem(title: "系统代理", action: #selector(toggleSystemProxyFromStatusItem), keyEquivalent: "")
    private let enhancedModeItem = NSMenuItem(title: "增强模式 (TUN)", action: #selector(toggleEnhancedModeFromStatusItem), keyEquivalent: "")
    private let outboundSectionHeaderItem = NSMenuItem(title: "出站模式", action: nil, keyEquivalent: "")
    private let outboundModeItem = NSMenuItem(title: "出站模式：规则判定", action: nil, keyEquivalent: "")
    private let outboundModeMenu = NSMenu(title: "出站模式")
    private let modeRuleItem = NSMenuItem(title: "规则模式（按策略组与规则分流）", action: #selector(selectOutboundMode(_:)), keyEquivalent: "1")
    private let modeProxyItem = NSMenuItem(title: "全局代理（所有流量走全局节点）", action: #selector(selectOutboundMode(_:)), keyEquivalent: "2")
    private let modeDirectItem = NSMenuItem(title: "直连模式（所有流量直接连接）", action: #selector(selectOutboundMode(_:)), keyEquivalent: "3")
    private let routingSectionSeparator = NSMenuItem.separator()
    private let globalPolicyItem = NSMenuItem(title: "全局节点", action: nil, keyEquivalent: "")
    private let globalMenu = NSMenu(title: "全局节点列表")
    private let globalTestAllItem = NSMenuItem(title: "⚡ 一键测速全部节点", action: nil, keyEquivalent: "")
    private let globalTestAllView = StatusMenuActionItemView(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
    private let globalTestSeparator = NSMenuItem.separator()
    private let policyGroupsHeaderItem = NSMenuItem(title: "策略组切换", action: nil, keyEquivalent: "")
    private let quitSeparator = NSMenuItem.separator()
    private var policyGroupMenuEntries: [String: PolicyGroupMenuEntry] = [:]
    private var activePolicyGroupMenuOrder: [String] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Prevent macOS App Nap from throttling proxy queues, timers, and
        // Helper heartbeats when the screen turns off (Display Sleep) or the
        // main window is closed to the status bar, while still allowing normal
        // idle system sleep.
        processActivityToken = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiatedAllowingIdleSystemSleep, .latencyCritical],
            reason: "Hajimi Network Proxy and Packet Tunnel Engine"
        )
        buildMainMenu()
        let controller = MainWindowController()
        mainWindowController = controller
        controller.onStatusBarStateChanged = { [weak self] in
            guard let self, self.isStatusMenuOpen, let ctrl = self.mainWindowController else { return }
            self.refreshMenuContents(controller: ctrl)
        }
        buildStatusItem()
        controller.launch()
    }

    /// Closing the red window button hides the UI but leaves the proxy and its
    /// menu-bar controls running. Only “退出哈基米” performs network cleanup.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { mainWindowController?.revealFromStatusItem() }
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Always drop the helper tunnel first. A quit that leaves utun routes
        // up black-holes the machine until the helper's liveness timer fires.
        mainWindowController?.shutdownEnhancedModeForQuit()
        do {
            try mainWindowController?.restoreSystemProxyBeforeQuit()
            return .terminateNow
        } catch {
            let alert = NSAlert()
            alert.messageText = "无法恢复系统代理"
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: "取消退出")
            alert.addButton(withTitle: "仍然退出")
            let choice = alert.runModal()
            if choice == .alertSecondButtonReturn {
                // User insisted — make sure helper routes are still gone.
                mainWindowController?.shutdownEnhancedModeForQuit()
                return .terminateNow
            }
            return .terminateCancel
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let token = processActivityToken {
            ProcessInfo.processInfo.endActivity(token)
            processActivityToken = nil
        }
        // Backup path for force-quit variants that skip shouldTerminate's
        // interactive branch after a prior failure.
        mainWindowController?.shutdownEnhancedModeForQuit()
    }

    private func buildMainMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "关于哈基米", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出哈基米", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        let editItem = NSMenuItem()
        main.addItem(editItem)
        let editMenu = NSMenu(title: "编辑")
        editMenu.addItem(withTitle: "撤销", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "剪切", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "复制", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "粘贴", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "全选", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        NSApp.mainMenu = main
    }

    private static func menuSymbol(_ name: String) -> NSImage? {
        guard let base = NSImage(systemSymbolName: name, accessibilityDescription: nil) else { return nil }
        let config = NSImage.SymbolConfiguration(pointSize: 13, weight: .medium)
        let configured = base.withSymbolConfiguration(config) ?? base
        configured.isTemplate = true
        return configured
    }

    private func buildStatusItem() {
        // Variable length: the width has to grow for the speed readout and
        // shrink back to the icon when nothing is running.
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.image = StatusBarCatIcon.makeImage()
            Self.configureTrafficButton(button)
            button.toolTip = "哈基米"
        }
        let menu = NSMenu(title: "哈基米")
        menu.minimumWidth = 280
        menu.delegate = self

        let show = NSMenuItem(title: "打开哈基米控制台", action: #selector(showFromStatusItem), keyEquivalent: "o")
        show.target = self
        show.image = Self.menuSymbol("macwindow")
        menu.addItem(show)

        statusSummaryItem.isEnabled = false
        statusSummaryItem.image = Self.menuSymbol("waveform.path.ecg")
        menu.addItem(statusSummaryItem)
        menu.addItem(.separator())

        engineItem.target = self
        systemProxyItem.target = self
        enhancedModeItem.target = self
        systemProxyItem.image = Self.menuSymbol("network")
        enhancedModeItem.image = Self.menuSymbol("shield.lefthalf.filled")
        menu.addItem(systemProxyItem)
        menu.addItem(enhancedModeItem)
        menu.addItem(.separator())

        globalTestAllView.configure(
            title: "⚡ 一键测速全部节点",
            image: Self.menuSymbol("bolt.horizontal.circle")
        )
        globalTestAllView.onAction = { [weak self] in
            self?.testAllNodesFromStatusItem()
        }
        globalTestAllItem.view = globalTestAllView
        globalMenu.minimumWidth = 280
        globalMenu.addItem(globalTestAllItem)
        globalMenu.addItem(globalTestSeparator)

        modeRuleItem.target = self
        modeRuleItem.representedObject = OutboundMode.rule.rawValue
        modeRuleItem.image = Self.menuSymbol("point.3.connected.trianglepath.dotted")

        modeProxyItem.target = self
        modeProxyItem.representedObject = OutboundMode.proxy.rawValue
        modeProxyItem.image = Self.menuSymbol("globe.asia.australia")

        modeDirectItem.target = self
        modeDirectItem.representedObject = OutboundMode.direct.rawValue
        modeDirectItem.image = Self.menuSymbol("arrow.up.right.circle")

        outboundModeMenu.minimumWidth = 240
        outboundModeMenu.addItem(modeRuleItem)
        outboundModeMenu.addItem(modeProxyItem)
        outboundModeMenu.addItem(modeDirectItem)
        outboundModeItem.image = Self.menuSymbol("point.3.connected.trianglepath.dotted")
        outboundModeItem.submenu = outboundModeMenu
        menu.addItem(outboundModeItem)
        menu.addItem(routingSectionSeparator)

        globalPolicyItem.image = Self.menuSymbol("server.rack")
        globalPolicyItem.submenu = globalMenu
        menu.addItem(globalPolicyItem)

        policyGroupsHeaderItem.isEnabled = false
        policyGroupsHeaderItem.attributedTitle = NSAttributedString(
            string: "策略组配置（可在策略组设置中控制显示）",
            attributes: [
                .font: NSFont.systemFont(ofSize: 11, weight: .semibold),
                .foregroundColor: NSColor.secondaryLabelColor
            ]
        )
        policyGroupsHeaderItem.isHidden = true
        menu.addItem(policyGroupsHeaderItem)
        menu.addItem(quitSeparator)

        let quit = NSMenuItem(title: "退出哈基米", action: #selector(quitFromStatusItem), keyEquivalent: "q")
        quit.target = self
        quit.image = Self.menuSymbol("power")
        menu.addItem(quit)

        item.menu = menu
        statusItem = item
        startTrafficTicker()
    }

    private func startTrafficTicker() {
        trafficTicker?.invalidate()
        let timer = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.refreshTrafficReadout()
        }
        RunLoop.main.add(timer, forMode: .common)
        trafficTicker = timer
        refreshTrafficReadout()
    }

    private func refreshTrafficReadout() {
        guard let button = statusItem?.button else { return }
        guard let controller = mainWindowController else {
            button.attributedTitle = NSAttributedString(string: "")
            return
        }
        let rate = controller.statusItemTrafficRate()
        button.attributedTitle = Self.trafficTitle(
            upload: TrafficRateFormatter.compact(bytesPerSecond: rate.upload),
            download: TrafficRateFormatter.compact(bytesPerSecond: rate.download))
    }

    static func configureTrafficButton(_ button: NSButton) {
        button.imagePosition = .imageLeading
    }

    static func trafficTitle(upload: String, download: String) -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .right
        paragraph.lineSpacing = -3
        paragraph.maximumLineHeight = 9
        let attributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .regular),
            .foregroundColor: NSColor.controlTextColor,
            .paragraphStyle: paragraph,
            .baselineOffset: -1,
        ]
        return NSAttributedString(string: "↑ \(upload)\n↓ \(download)", attributes: attributes)
    }

    static func validateTrafficTitleMetrics() throws {
        struct Failure: LocalizedError {
            let text: String
            var errorDescription: String? { "状态栏速率显示自检失败：\(text)" }
        }
        let title = trafficTitle(upload: "999K", download: "12M")
        let size = title.size()
        guard title.string.split(separator: "\n").count == 2 else {
            throw Failure(text: "速率标题应为两行")
        }
        guard size.height <= 22 else {
            throw Failure(text: "两行高度为 \(size.height) 点，超过菜单栏的 22 点")
        }
        guard size.height >= 12 else {
            throw Failure(text: "两行高度仅 \(size.height) 点，行距过紧会互相压盖")
        }
        guard size.width <= 60 else {
            throw Failure(text: "宽度为 \(size.width) 点，菜单栏占位过宽")
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        guard menu === statusItem?.menu, let controller = mainWindowController else { return }
        isStatusMenuOpen = true
        globalTestAllView.resetHoverState()
        for entry in policyGroupMenuEntries.values { entry.testView.resetHoverState() }
        refreshMenuContents(controller: controller)
    }

    func menuDidClose(_ menu: NSMenu) {
        guard menu === statusItem?.menu else { return }
        isStatusMenuOpen = false
        globalTestAllView.resetHoverState()
        for entry in policyGroupMenuEntries.values { entry.testView.resetHoverState() }
    }

    private func refreshMenuContents(controller: MainWindowController) {
        statusSummaryItem.title = controller.statusItemSummary
        engineItem.title = controller.isEngineActive ? "停止代理引擎" : "启动代理引擎"
        engineItem.image = Self.menuSymbol(controller.isEngineActive ? "stop.circle" : "play.circle")
        systemProxyItem.state = controller.isSystemProxyActive ? .on : .off
        enhancedModeItem.state = controller.isEnhancedModeActive ? .on : .off
        systemProxyItem.isEnabled = true
        enhancedModeItem.isEnabled = true
        rebuildRoutingMenus(controller: controller)
        statusItem?.button?.toolTip = "哈基米 · \(controller.statusItemSummary)"
    }

    private static func attributedNodeMenuTitle(node: StatusProxyNodeItem, isSelected: Bool,
                                                tabLocation: CGFloat = 156) -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.tabStops = [NSTextTab(textAlignment: .left, location: tabLocation)]
        paragraph.defaultTabInterval = tabLocation

        let result = NSMutableAttributedString()
        let nameFont = NSFont.systemFont(ofSize: 13, weight: isSelected ? .semibold : .regular)
        let nameColor = isSelected ? NSColor.labelColor : NSColor.controlTextColor
        result.append(NSAttributedString(string: node.name, attributes: [
            .font: nameFont,
            .foregroundColor: nameColor,
            .paragraphStyle: paragraph
        ]))

        let badgeText: String
        let badgeColor: NSColor
        switch node.latency {
        case .success(let ms):
            let digits = String(ms)
            let padded = String(repeating: "\u{2007}", count: max(0, 3 - digits.count)) + digits
            badgeText = "\t● \(padded) ms"
            if ms < 180 {
                badgeColor = .systemGreen
            } else if ms < 500 {
                badgeColor = .systemOrange
            } else {
                badgeColor = .systemRed
            }
        case .testing:
            badgeText = "\t◌ 测速中…"
            badgeColor = .systemBlue
        case .queued:
            badgeText = "\t◌ 排队中"
            badgeColor = .secondaryLabelColor
        case .failed:
            badgeText = "\t● 超时"
            badgeColor = .systemRed
        case .unavailable(let failure):
            badgeText = "\t● \(NodeLatency.unavailable(failure).text)"
            badgeColor = .systemOrange
        case .untested:
            badgeText = "\t· 未测速"
            badgeColor = .tertiaryLabelColor
        }

        let latFont = NSFont.monospacedDigitSystemFont(ofSize: 11.5, weight: .semibold)
        result.append(NSAttributedString(string: badgeText, attributes: [
            .font: latFont,
            .foregroundColor: badgeColor,
            .paragraphStyle: paragraph
        ]))
        if node.isOptimal {
            let optFont = NSFont.systemFont(ofSize: 10, weight: .bold)
            result.append(NSAttributedString(string: " ★最优", attributes: [
                .font: optFont,
                .foregroundColor: NSColor.systemGreen,
                .paragraphStyle: paragraph
            ]))
        }
        return result
    }

    private static func groupSymbol(for kind: PolicyGroupKind) -> NSImage? {
        switch kind {
        case .select: return menuSymbol("square.stack.3d.up")
        case .urlTest, .smart: return menuSymbol("bolt.badge.clock")
        case .fallback: return menuSymbol("arrow.triangle.swap")
        case .loadBalance: return menuSymbol("circle.grid.cross")
        case .subnet: return menuSymbol("network")
        }
    }

    private static func attributedModeMenuTitle(title: String, subtitle: String, isActive: Bool) -> NSAttributedString {
        let result = NSMutableAttributedString()
        let mainFont = NSFont.systemFont(ofSize: 13, weight: isActive ? .semibold : .regular)
        let mainColor: NSColor = isActive ? .labelColor : .controlTextColor
        result.append(NSAttributedString(string: title, attributes: [
            .font: mainFont,
            .foregroundColor: mainColor
        ]))
        let subFont = NSFont.systemFont(ofSize: 11, weight: .regular)
        let subColor: NSColor = isActive ? .secondaryLabelColor : .tertiaryLabelColor
        result.append(NSAttributedString(string: "  \(subtitle)", attributes: [
            .font: subFont,
            .foregroundColor: subColor
        ]))
        return result
    }

    private func rebuildRoutingMenus(controller: MainWindowController) {
        let activeMode = controller.statusItemOutboundMode
        let modeSpecs: [(NSMenuItem, OutboundMode, String, String)] = [
            (modeRuleItem, .rule, "规则判定", "按策略组与分流规则路由"),
            (modeProxyItem, .proxy, "全局代理", "全部流量走指定全局节点"),
            (modeDirectItem, .direct, "全局直连", "全部流量绕过代理直接连接")
        ]
        for (item, mode, title, subtitle) in modeSpecs {
            let isSelected = activeMode == mode
            item.state = isSelected ? .on : .off
            item.attributedTitle = Self.attributedModeMenuTitle(title: title, subtitle: subtitle, isActive: isSelected)
        }
        let activeModeLabel: String
        let activeModeSymbol: String
        switch activeMode {
        case .rule:
            activeModeLabel = "规则判定"
            activeModeSymbol = "point.3.connected.trianglepath.dotted"
        case .proxy:
            activeModeLabel = "全局代理"
            activeModeSymbol = "globe.asia.australia.fill"
        case .direct:
            activeModeLabel = "全局直连"
            activeModeSymbol = "arrow.up.right.circle"
        }
        outboundModeItem.title = "出站模式：\(activeModeLabel)"
        outboundModeItem.image = Self.menuSymbol(activeModeSymbol)

        // Update the persistent Global Proxy submenu in-place so an open
        // submenu stays open while node latency probes stream their results.
        let testTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测试节点延迟…" : "⚡ 一键测速全部节点"
        globalTestAllItem.title = testTitle
        globalTestAllView.configure(
            title: testTitle,
            image: Self.menuSymbol("bolt.horizontal.circle")
        )

        let globalNodes = controller.statusItemGlobalNodeItems
        let activeNodeName = controller.statusItemGlobalPolicy

        if globalNodes.isEmpty {
            while globalMenu.items.count > 2 {
                globalMenu.removeItem(at: globalMenu.items.count - 1)
            }
            let empty = NSMenuItem(title: "无可用代理节点（已禁止策略组进入全局代理）", action: nil, keyEquivalent: "")
            empty.isEnabled = false
            globalMenu.addItem(empty)
        } else {
            let existingNodeNames: [String] = globalMenu.items.dropFirst(2).compactMap { $0.representedObject as? String }
            let targetNodeNames: [String] = globalNodes.map(\.name)
            if existingNodeNames != targetNodeNames {
                while globalMenu.items.count > 2 {
                    globalMenu.removeItem(at: globalMenu.items.count - 1)
                }
                for node in globalNodes {
                    let item = NSMenuItem(title: node.name, action: #selector(selectGlobalPolicy(_:)), keyEquivalent: "")
                    item.target = self
                    item.representedObject = node.name
                    globalMenu.addItem(item)
                }
            }
            let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
            let maxNameWidth = globalNodes.map {
                ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
            }.max() ?? 120
            let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)
            globalMenu.minimumWidth = max(276, tabLocation + 132)
            for (offset, node) in globalNodes.enumerated() {
                let menuIndex = offset + 2
                guard globalMenu.items.indices.contains(menuIndex) else { continue }
                let item = globalMenu.items[menuIndex]
                let isSelected = activeNodeName == node.name
                item.state = isSelected ? .on : .off
                item.attributedTitle = Self.attributedNodeMenuTitle(
                    node: node, isSelected: isSelected, tabLocation: tabLocation)
            }
        }

        let activeGlobalNodeItem = controller.statusItemNodeItem(named: activeNodeName)
        globalPolicyItem.state = .off
        globalPolicyItem.image = Self.menuSymbol("globe.asia.australia.fill")
        if let ms = activeGlobalNodeItem.latencyMillis {
            globalPolicyItem.title = "全局节点：\(activeNodeName) (\(ms) ms)"
        } else {
            globalPolicyItem.title = "全局节点：\(activeNodeName)"
        }
        globalPolicyItem.isHidden = (activeMode != .proxy)

        rebuildPolicyGroupMenus(controller: controller, activeMode: activeMode)
    }

    private func rebuildPolicyGroupMenus(controller: MainWindowController, activeMode: OutboundMode) {
        guard let mainMenu = statusItem?.menu else { return }
        let groups = controller.statusItemPolicyGroups
        let targetNames = groups.map(\.name)
        let showGroups = (activeMode == .rule) && !groups.isEmpty

        policyGroupsHeaderItem.isHidden = !showGroups
        routingSectionSeparator.isHidden = (activeMode == .direct) || (activeMode == .rule && !showGroups)

        if activePolicyGroupMenuOrder != targetNames {
            for oldName in activePolicyGroupMenuOrder {
                if let entry = policyGroupMenuEntries[oldName], mainMenu.index(of: entry.item) >= 0 {
                    mainMenu.removeItem(entry.item)
                }
            }
            let staleKeys = Set(policyGroupMenuEntries.keys).subtracting(targetNames)
            for key in staleKeys { policyGroupMenuEntries.removeValue(forKey: key) }

            let anchorIndex = mainMenu.index(of: quitSeparator)
            var insertIndex = anchorIndex >= 0 ? anchorIndex : mainMenu.items.count
            for group in groups {
                let entry: PolicyGroupMenuEntry
                if let existing = policyGroupMenuEntries[group.name] {
                    entry = existing
                } else {
                    let groupName = group.name
                    entry = PolicyGroupMenuEntry(
                        groupName: groupName,
                        onTestGroup: { [weak self] in
                            self?.mainWindowController?.testGroupNodesFromStatusItem(group: groupName)
                        },
                        target: self,
                        defaultAction: #selector(selectPolicyGroupDefault(_:))
                    )
                    policyGroupMenuEntries[groupName] = entry
                }
                mainMenu.insertItem(entry.item, at: insertIndex)
                insertIndex += 1
            }
            activePolicyGroupMenuOrder = targetNames
        }

        for group in groups {
            guard let entry = policyGroupMenuEntries[group.name] else { continue }
            entry.item.isHidden = (activeMode != .rule)
            entry.item.image = Self.groupSymbol(for: group.kind)
            entry.item.state = (activeMode == .rule && group.selectedMember != nil) ? .on : .off

            let effective = group.effectiveMember ?? "DIRECT"
            let effectiveNodeItem = controller.statusItemNodeItem(named: effective)
            let modeTag = (group.selectedMember == nil && group.kind != .select) ? " [自动·\(group.kindBadgeText)]" : ""
            if let ms = effectiveNodeItem.latencyMillis {
                entry.item.title = "\(group.name)：\(effective)\(modeTag) (\(ms) ms)"
            } else {
                entry.item.title = "\(group.name)：\(effective)\(modeTag)"
            }

            let groupTestTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测速…" : "⚡ 测速本组节点"
            entry.testItem.title = groupTestTitle
            entry.testView.configure(
                title: groupTestTitle,
                image: Self.menuSymbol("bolt.horizontal.circle")
            )

            let firstMember = group.members.first ?? "DIRECT"
            let defaultTitle = group.kind == .select
                ? "配置默认（\(firstMember)）"
                : "自动（按\(group.kindBadgeText)策略 · 默认 \(firstMember)）"
            entry.defaultItem.title = defaultTitle
            entry.defaultItem.state = group.selectedMember == nil ? .on : .off

            let submenu = entry.submenu
            let existingMembers: [String] = submenu.items.dropFirst(3).compactMap {
                ($0.representedObject as? [String: String])?["member"]
            }
            if existingMembers != group.members {
                while submenu.items.count > 3 {
                    submenu.removeItem(at: submenu.items.count - 1)
                }
                for member in group.members {
                    let memberItem = NSMenuItem(title: member, action: #selector(selectPolicyGroupMember(_:)), keyEquivalent: "")
                    memberItem.target = self
                    memberItem.representedObject = ["group": group.name, "member": member]
                    submenu.addItem(memberItem)
                }
            }

            let optimalMember = controller.statusItemOptimalMemberName(forGroup: group.name)
            let memberNodeItems = group.members.map {
                controller.statusItemNodeItem(named: $0, optimalName: optimalMember)
            }
            let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
            let maxNameWidth = memberNodeItems.map {
                ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
            }.max() ?? 120
            let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)
            submenu.minimumWidth = max(276, tabLocation + 132)

            for (offset, nodeItem) in memberNodeItems.enumerated() {
                let menuIndex = offset + 3
                guard submenu.items.indices.contains(menuIndex) else { continue }
                let item = submenu.items[menuIndex]
                let isSelected = group.selectedMember == nodeItem.name
                    || (group.selectedMember == nil && group.effectiveMember == nodeItem.name)
                item.state = isSelected ? .on : .off
                item.attributedTitle = Self.attributedNodeMenuTitle(
                    node: nodeItem, isSelected: isSelected, tabLocation: tabLocation)
            }
        }
    }

    @objc private func showFromStatusItem() { mainWindowController?.revealFromStatusItem() }
    @objc private func toggleEngineFromStatusItem() { mainWindowController?.toggleEngineFromStatusItem() }
    @objc private func toggleSystemProxyFromStatusItem() { mainWindowController?.toggleSystemProxyFromStatusItem() }
    @objc private func toggleEnhancedModeFromStatusItem() { mainWindowController?.toggleEnhancedModeFromStatusItem() }
    @objc private func testAllNodesFromStatusItem() { mainWindowController?.testAllNodesFromStatusItem() }
    @objc private func selectOutboundMode(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String,
              let mode = OutboundMode(rawValue: raw) else { return }
        mainWindowController?.selectOutboundModeFromStatusItem(mode)
    }
    @objc private func selectGlobalPolicy(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        mainWindowController?.selectGlobalPolicyFromStatusItem(name)
    }
    @objc private func selectPolicyGroupDefault(_ sender: NSMenuItem) {
        guard let info = sender.representedObject as? [String: String],
              let group = info["group"] else { return }
        mainWindowController?.selectGroupMemberFromStatusItem(group: group, member: nil)
    }
    @objc private func selectPolicyGroupMember(_ sender: NSMenuItem) {
        guard let info = sender.representedObject as? [String: String],
              let group = info["group"],
              let member = info["member"] else { return }
        mainWindowController?.selectGroupMemberFromStatusItem(group: group, member: member)
    }
    @objc private func quitFromStatusItem() { NSApp.terminate(nil) }
}

if CommandLine.arguments.contains("--protocol-adapter-smoke-test") {
    Darwin.exit(runProtocolAdapterSmokeCheck())
}
if CommandLine.arguments.contains("--dns-security-self-test") {
    do { try runDNSSecuritySelfTest(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--dns-performance-self-test") {
    do { try runDNSPerformanceSelfTest(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--dns-proxy-fallback-self-test") {
    do { try DNSProxyFallbackSelfTest.run(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--network-optimization-self-test") {
    do { try runNetworkOptimizationSelfTest(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--dns-adaptive-loopback-test") {
    Darwin.exit(runDNSAdaptiveLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--dns-performance-loopback-test") {
    Darwin.exit(runDNSPerformanceLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--dns-loopback-test") {
    Darwin.exit(runDNSLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--dns-split-loopback-test") {
    Darwin.exit(runDNSSplitLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--proxy-performance-smoke-test") {
    Darwin.exit(runProxyPerformanceSmokeCheck())
}
if CommandLine.arguments.contains("--video-stream-loopback-test") {
    Darwin.exit(runVideoStreamLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--enhanced-helper-ipc-test") {
    Darwin.exit(runEnhancedHelperIPCCheck())
}
if CommandLine.arguments.contains("--helper-install-maintenance") {
    Darwin.exit(runHelperInstallMaintenance())
}
if CommandLine.arguments.contains("--helper-start-current-maintenance") {
    Darwin.exit(runHelperStartCurrentMaintenance())
}
if CommandLine.arguments.contains("--helper-stop-maintenance") {
    Darwin.exit(runHelperStopMaintenance())
}
if CommandLine.arguments.contains("--native-policy-live-test") {
    Darwin.exit(runSelectedNativePolicyLiveCheck())
}
if CommandLine.arguments.contains("--native-quic-codec-test") {
    Darwin.exit(runNativeQUICCodecCheck())
}
if CommandLine.arguments.contains("--ingress-security-self-test") {
    do { try runIngressSecuritySelfTest(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--native-dataplane-self-test") {
    if let failure = NativeCoreSelfTest.run() {
        FileHandle.standardError.write(Data((failure + "\n").utf8))
        Darwin.exit(1)
    }
    print("HajimiNativeCore self-test passed")
    Darwin.exit(0)
}
if CommandLine.arguments.contains("--native-tunnel-packet-load-self-test") {
    do {
        print(try NativeTunnelStreamRegressionFixture.runPacketLoad())
        Darwin.exit(0)
    } catch {
        FileHandle.standardError.write(Data("Native tunnel packet load failed: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--native-tunnel-stream-self-test") {
    do {
        print(try NativeTunnelStreamRegressionFixture.run())
        Darwin.exit(0)
    } catch {
        FileHandle.standardError.write(Data("Native tunnel stream regression failed: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--native-policy-listener-live-test") {
    Darwin.exit(runNativePolicyListenerLiveCheck())
}
if CommandLine.arguments.contains("--native-policy-stress-test") {
    Darwin.exit(runNativePolicyStressCheck())
}
if let index = CommandLine.arguments.firstIndex(of: "--surge-profile-smoke-test"),
   CommandLine.arguments.indices.contains(index + 1) {
    Darwin.exit(runSurgeProfileCompatibilityCheck(path: CommandLine.arguments[index + 1]))
}

NetworkProcessResources.prepareOpenFileLimit()
let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()

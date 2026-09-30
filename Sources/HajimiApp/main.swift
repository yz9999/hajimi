import AppKit
import Darwin
import HajimiCore
import HajimiNativeCore

// A stale/restarting privileged Helper may close its Unix socket between
// connect and write. Convert that race into EPIPE instead of terminating the
// GUI process with SIGPIPE.
signal(SIGPIPE, SIG_IGN)

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private final class GroupMemberChoice {
        let group: String
        let member: String
        init(group: String, member: String) { self.group = group; self.member = member }
    }

    private var mainWindowController: MainWindowController?
    private var statusItem: NSStatusItem?
    private var trafficTicker: Timer?
    private let statusSummaryItem = NSMenuItem(title: "代理引擎已停止", action: nil, keyEquivalent: "")
    private let engineItem = NSMenuItem(title: "启动代理引擎", action: #selector(toggleEngineFromStatusItem), keyEquivalent: "")
    private let systemProxyItem = NSMenuItem(title: "系统代理", action: #selector(toggleSystemProxyFromStatusItem), keyEquivalent: "")
    private let enhancedModeItem = NSMenuItem(title: "增强模式", action: #selector(toggleEnhancedModeFromStatusItem), keyEquivalent: "")
    private let outboundModeItem = NSMenuItem(title: "出口模式", action: nil, keyEquivalent: "")
    private let globalPolicyItem = NSMenuItem(title: "全局代理", action: nil, keyEquivalent: "")
    private let policyGroupsItem = NSMenuItem(title: "策略组", action: nil, keyEquivalent: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMainMenu()
        let controller = MainWindowController()
        mainWindowController = controller
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
        menu.delegate = self
        let show = NSMenuItem(title: "显示哈基米", action: #selector(showFromStatusItem), keyEquivalent: "")
        show.target = self
        menu.addItem(show)
        statusSummaryItem.isEnabled = false
        menu.addItem(statusSummaryItem)
        menu.addItem(.separator())
        engineItem.target = self
        systemProxyItem.target = self
        enhancedModeItem.target = self
        menu.addItem(engineItem)
        menu.addItem(systemProxyItem)
        menu.addItem(enhancedModeItem)
        menu.addItem(.separator())
        menu.addItem(outboundModeItem)
        menu.addItem(globalPolicyItem)
        menu.addItem(policyGroupsItem)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "退出哈基米", action: #selector(quitFromStatusItem), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        item.menu = menu
        statusItem = item
        startTrafficTicker()
    }

    /// Redraws the speed readout once a second.
    ///
    /// Twice a second. The measurement windows are half a second wide, so this
    /// is the rate at which genuinely new numbers exist; slower makes the
    /// readout visibly trail the traffic it is describing.
    private func startTrafficTicker() {
        trafficTicker?.invalidate()
        let timer = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.refreshTrafficReadout()
        }
        // The common modes matter: without this the readout freezes for as long
        // as a menu is open or a window is being dragged.
        RunLoop.main.add(timer, forMode: .common)
        trafficTicker = timer
        refreshTrafficReadout()
    }

    private func refreshTrafficReadout() {
        guard let button = statusItem?.button else { return }
        // Always shown. This is a speed gauge, not a mode indicator: gating it
        // on which data plane happens to be up means system-proxy traffic has
        // nowhere to appear, and a reading of zero is itself information.
        guard let controller = mainWindowController else {
            button.attributedTitle = NSAttributedString(string: "")
            return
        }
        let rate = controller.statusItemTrafficRate()
        button.attributedTitle = Self.trafficTitle(
            upload: TrafficRateFormatter.compact(bytesPerSecond: rate.upload),
            download: TrafficRateFormatter.compact(bytesPerSecond: rate.download))
    }

    /// The image has to sit beside the text rather than replace it; a status
    /// item button given only an image shows only the image.
    ///
    /// Multi-line wrapping needs no coaxing — measured against a real
    /// `NSStatusItem`, the button grows from 32 to 54 points and renders both
    /// lines with the cell left at its defaults.
    static func configureTrafficButton(_ button: NSButton) {
        button.imagePosition = .imageLeading
    }

    /// Two stacked lines inside the menu bar's 22 points.
    ///
    /// Digits are monospaced and the text is right-aligned so a value going
    /// from `9.9K` to `10K` does not shuffle everything sideways once a second,
    /// which is far more distracting than the number is useful.
    static func trafficTitle(upload: String, download: String) -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .right
        paragraph.lineSpacing = -3
        paragraph.maximumLineHeight = 9
        let attributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .regular),
            .foregroundColor: NSColor.controlTextColor,
            .paragraphStyle: paragraph,
            // Nudged down so the two lines sit centred rather than riding the
            // top of the menu bar.
            .baselineOffset: -1,
        ]
        return NSAttributedString(string: "↑ \(upload)\n↓ \(download)", attributes: attributes)
    }

    /// The menu bar gives a status item about 22 points of height and clips
    /// anything taller. Two stacked lines only just fit, and the metrics that
    /// make them fit are not visible from a build log — so they are asserted.
    static func validateTrafficTitleMetrics() throws {
        struct Failure: LocalizedError {
            let text: String
            var errorDescription: String? { "状态栏速率显示自检失败：\(text)" }
        }
        // The widest plausible reading, so the check is not passed by a narrow one.
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
        statusSummaryItem.title = controller.statusItemSummary
        engineItem.title = controller.isEngineActive ? "停止代理引擎" : "启动代理引擎"
        systemProxyItem.state = controller.isSystemProxyActive ? .on : .off
        enhancedModeItem.state = controller.isEnhancedModeActive ? .on : .off
        systemProxyItem.isEnabled = controller.isEngineActive
        enhancedModeItem.isEnabled = true
        rebuildRoutingMenus(controller: controller)
        statusItem?.button?.toolTip = "哈基米 · \(controller.statusItemSummary)"
    }

    private func rebuildRoutingMenus(controller: MainWindowController) {
        let modeMenu = NSMenu(title: "出口模式")
        for mode in OutboundMode.allCases {
            let item = NSMenuItem(title: mode.displayName,
                                  action: #selector(selectOutboundMode(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = mode.rawValue
            item.state = controller.statusItemOutboundMode == mode ? .on : .off
            modeMenu.addItem(item)
        }
        outboundModeItem.title = "出口模式：\(controller.statusItemOutboundMode.displayName)"
        outboundModeItem.submenu = modeMenu

        let globalMenu = NSMenu(title: "全局代理")
        for name in controller.statusItemGlobalPolicies {
            let item = NSMenuItem(title: name, action: #selector(selectGlobalPolicy(_:)),
                                  keyEquivalent: "")
            item.target = self
            item.representedObject = name
            item.state = controller.statusItemGlobalPolicy == name ? .on : .off
            globalMenu.addItem(item)
        }
        globalPolicyItem.title = "全局代理：\(controller.statusItemGlobalPolicy)"
        globalPolicyItem.submenu = globalMenu

        let groupsMenu = NSMenu(title: "策略组")
        for group in controller.statusItemPolicyGroups {
            let groupItem = NSMenuItem(title: group.name, action: nil, keyEquivalent: "")
            let members = NSMenu(title: group.name)
            for member in group.members {
                let item = NSMenuItem(title: member, action: #selector(selectGroupMember(_:)),
                                      keyEquivalent: "")
                item.target = self
                item.representedObject = GroupMemberChoice(group: group.name, member: member)
                item.state = group.selectedMember == member ? .on : .off
                members.addItem(item)
            }
            if group.members.isEmpty {
                let empty = NSMenuItem(title: "无可选节点", action: nil, keyEquivalent: "")
                empty.isEnabled = false
                members.addItem(empty)
            }
            groupItem.submenu = members
            groupsMenu.addItem(groupItem)
        }
        if groupsMenu.items.isEmpty {
            let empty = NSMenuItem(title: "无可见 Select 策略组", action: nil, keyEquivalent: "")
            empty.isEnabled = false
            groupsMenu.addItem(empty)
        }
        policyGroupsItem.submenu = groupsMenu

        switch controller.statusItemOutboundMode {
        case .rule:
            globalPolicyItem.isHidden = true
            policyGroupsItem.isHidden = false
        case .proxy:
            globalPolicyItem.isHidden = false
            policyGroupsItem.isHidden = true
        case .direct:
            globalPolicyItem.isHidden = true
            policyGroupsItem.isHidden = true
        }
    }

    @objc private func showFromStatusItem() { mainWindowController?.revealFromStatusItem() }
    @objc private func toggleEngineFromStatusItem() { mainWindowController?.toggleEngineFromStatusItem() }
    @objc private func toggleSystemProxyFromStatusItem() { mainWindowController?.toggleSystemProxyFromStatusItem() }
    @objc private func toggleEnhancedModeFromStatusItem() { mainWindowController?.toggleEnhancedModeFromStatusItem() }
    @objc private func selectOutboundMode(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String,
              let mode = OutboundMode(rawValue: raw) else { return }
        mainWindowController?.selectOutboundModeFromStatusItem(mode)
    }
    @objc private func selectGlobalPolicy(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        mainWindowController?.selectGlobalPolicyFromStatusItem(name)
    }
    @objc private func selectGroupMember(_ sender: NSMenuItem) {
        guard let choice = sender.representedObject as? GroupMemberChoice else { return }
        mainWindowController?.selectGroupMemberFromStatusItem(group: choice.group,
                                                               member: choice.member)
    }
    @objc private func quitFromStatusItem() { NSApp.terminate(nil) }
}

if CommandLine.arguments.contains("--protocol-adapter-smoke-test") {
    Darwin.exit(runProtocolAdapterSmokeCheck())
}
if CommandLine.arguments.contains("--proxy-performance-smoke-test") {
    Darwin.exit(runProxyPerformanceSmokeCheck())
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

let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()

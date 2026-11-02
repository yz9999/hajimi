import AppKit
import HajimiUIComponents

// Actual Main UI declarations are inserted by the companion script. The
// engine/lifecycle below are memory-only presentation inputs: no Main window,
// network owner, Helper or local listener is instantiated.
// @INSERT_THEME@

private enum OutboundMode: CaseIterable {
    case direct, rule, proxy
    var displayName: String { String(describing: self) }
}

private enum ProxyEngineStatus {
    case stopped, starting, running, failed(String)
}

private struct FixtureAddress {
    let host: String
    let port: UInt16
}

private final class FixtureEngine {
    var activeHTTPListen = FixtureAddress(host: "127.0.0.1", port: 17890)
    var activeSOCKSListen = FixtureAddress(host: "127.0.0.1", port: 17891)
}

private struct FixtureSystemProxy { var isEnabledByHajimi = false }
private struct FixtureEnhancedMode { var isEnabled = false }

private final class LocalProxyLayoutFixture: NSObject {
    private let dashboardView = NSView()
    private let settingsView = NSView()
    private let settingsOverviewView = NSView()
    private let dnsSettingsView = NSView()
    private let nativeTrafficView = NSView()
    private let statusLabel = NSTextField(labelWithString: "已停止")
    private let startButton = NSButton(title: "开启 HTTP / SOCKS5 代理", target: nil, action: nil)
    private let systemProxyButton = NSButton(checkboxWithTitle: "设置为系统代理", target: nil, action: nil)
    private let enhancedModeButton = NSButton(checkboxWithTitle: "增强模式", target: nil, action: nil)
    private let localProxyStatusLabel = NSTextField(wrappingLabelWithString: "")
    private let subscriptionSummaryLabel = NSTextField(wrappingLabelWithString: "尚未添加订阅")
    private let subscriptionSelectPopup = NSPopUpButton()
    private let subscriptionUseButton = NSButton(title: "选择使用", target: nil, action: nil)
    private let subscriptionAddButton = NSButton(title: "URL 下载…", target: nil, action: nil)
    private let subscriptionImportButton = NSButton(title: "导入配置…", target: nil, action: nil)
    private let subscriptionEditButton = NSButton(title: "编辑订阅…", target: nil, action: nil)
    private let subscriptionUpdateButton = NSButton(title: "更新订阅", target: nil, action: nil)
    private let subscriptionDeleteButton = NSButton(title: "删除订阅", target: nil, action: nil)
    private let helperStatusLabel = NSTextField(labelWithString: "正在检查…")
    private let helperInstallButton = NSButton(title: "安装 Helper", target: nil, action: nil)
    private let helperUninstallButton = NSButton(title: "卸载 Helper", target: nil, action: nil)
    private let dnsSummaryLabel = NSTextField(labelWithString: "默认加密 DNS")
    private let modePopup = NSPopUpButton()
    private let policyPopup = NSPopUpButton()
    private let groupPopup = NSPopUpButton()
    private let groupMemberPopup = NSPopUpButton()
    private let activeValue = NSTextField(labelWithString: "0")
    private let totalValue = NSTextField(labelWithString: "0")
    private let uploadValue = NSTextField(labelWithString: "0 B")
    private let downloadValue = NSTextField(labelWithString: "0 B")
    private let httpRuntimeValue = NSTextField(labelWithString: "127.0.0.1:17890")
    private let socksRuntimeValue = NSTextField(labelWithString: "127.0.0.1:17891")
    private let routingRuntimeValue = NSTextField(labelWithString: "规则判定")
    private let dataPlaneRuntimeValue = NSTextField(labelWithString: "HajimiNativeCore")
    private let systemProxy = FixtureSystemProxy()
    private let enhancedMode = FixtureEnhancedMode()
    private let engine = FixtureEngine()
    private var engineStatus: ProxyEngineStatus = .stopped
    private var listenerTicket: UUID?
    private var isEngineActive = false
    private var ready = false
    private var toggleCount = 0

    private func isCurrentListener(_ ticket: UUID) -> Bool {
        listenerTicket == ticket && ready
    }

    private func toggleEngine() { toggleCount += 1 }
    private func updateOverviewDetails() {}
    @objc private func toggleSystemProxy() {}
    @objc private func toggleEnhancedMode() {}
    @objc private func modeChanged() {}
    @objc private func policyChanged() {}
    @objc private func groupChanged() {}
    @objc private func groupMemberChanged() {}
    @objc private func showNetworkDiagnostics() {}
    @objc private func subscriptionSelectionPopupChanged() {}
    @objc private func useSelectedSubscriptionAction() {}
    @objc private func addSubscriptionAction() {}
    @objc private func importSubscriptionFileAction() {}
    @objc private func editSelectedSubscriptionAction() {}
    @objc private func updateSelectedSubscriptionAction() {}
    @objc private func deleteSelectedSubscriptionAction() {}
    @objc private func installHelperFromSettings() {}
    @objc private func uninstallHelperFromSettings() {}
    @objc private func openDNSSettings() {}
    @objc private func checkNetworkExtension() {}

    // @INSERT_PRODUCTION_UI_DECLARATIONS@

    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "本地代理设置页自检失败：\(text)" }
    }

    private static func descendants(_ view: NSView) -> [NSView] {
        view.subviews.flatMap { [$0] + descendants($0) }
    }

    static func run() throws {
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw Failure(text: text) }
        }
        let fixture = LocalProxyLayoutFixture()
        fixture.buildDashboard()
        fixture.buildSettings()
        let home = descendants(fixture.dashboardView)
        try require(!home.contains { $0 === fixture.startButton }, "主页仍包含 HTTP / SOCKS5 启停按钮")
        try require(home.contains { $0 === fixture.systemProxyButton }
                    && home.contains { $0 === fixture.enhancedModeButton }, "主页丢失系统代理或增强模式入口")
        try require(fixture.systemProxyButton.isEnabled, "本地代理关闭时系统代理入口不可点击")
        try require(descendants(fixture.settingsOverviewView).contains { $0 === fixture.startButton },
                    "设置页缺少 HTTP / SOCKS5 启停按钮")
        try require(fixture.startButton.target === fixture
                    && fixture.startButton.action == #selector(toggleLocalProxyFromSettings),
                    "设置按钮未连接到实际启停 action")
        try require(fixture.startButton.keyEquivalent.isEmpty, "隐藏的本地代理按钮仍占用全局 Return")
        try require(NSApp.sendAction(fixture.startButton.action!, to: fixture.startButton.target,
                                     from: fixture.startButton) && fixture.toggleCount == 1,
                    "实际设置 action 未恰好一次转交现有启停入口")

        try require(fixture.localProxyStatusLabel.stringValue.contains("尚未开启"), "关闭状态未同步")
        fixture.isEngineActive = true
        fixture.engineStatus = .starting
        fixture.refreshLocalProxySettings()
        try require(fixture.localProxyStatusLabel.stringValue.contains("监听就绪"), "启动中状态未同步")
        fixture.listenerTicket = UUID()
        fixture.ready = true
        fixture.engineStatus = .running
        fixture.refreshLocalProxySettings()
        try require(fixture.localProxyStatusLabel.stringValue.contains("已开启")
                    && fixture.localProxyStatusLabel.stringValue.contains("17890")
                    && fixture.localProxyStatusLabel.stringValue.contains("17891"),
                    "实际监听地址未显示在设置页")
        fixture.ready = false
        fixture.isEngineActive = false
        fixture.engineStatus = .failed(String(repeating: "端口已被占用；", count: 40))
        fixture.refreshLocalProxySettings()
        try require(fixture.localProxyStatusLabel.stringValue.hasPrefix("启动失败：")
                    && fixture.localProxyStatusLabel.toolTip == fixture.localProxyStatusLabel.stringValue,
                    "失败提示或完整错误 tooltip 缺失")

        guard let scroll = descendants(fixture.settingsOverviewView)
            .compactMap({ $0 as? ScrollableSettingsContentView }).first,
              let document = scroll.scrollView.documentView,
              let card = fixture.startButton.superview,
              let cards = scroll.content as? NSStackView,
              let lastCard = cards.arrangedSubviews.last else {
            throw Failure(text: "缺少实际可滚动设置视图")
        }
        for size in [NSSize(width: 740, height: 440), NSSize(width: 980, height: 620),
                     NSSize(width: 740, height: 360)] {
            fixture.settingsView.setFrameSize(size)
            fixture.settingsView.needsLayout = true
            fixture.settingsView.layoutSubtreeIfNeeded()
            scroll.needsLayout = true
            scroll.layoutSubtreeIfNeeded()
            let clip = scroll.scrollView.contentView
            try require(document.frame.height > clip.bounds.height,
                        "小窗口未产生可滚动内容：\(size), \(document.frame), \(clip.bounds)")
            try require(abs(document.frame.width - clip.bounds.width) < 1,
                        "设置页出现横向溢出：\(document.frame.width) / \(clip.bounds.width)")
            let buttonRect = fixture.startButton.convert(fixture.startButton.bounds, to: card)
            let statusRect = fixture.localProxyStatusLabel.convert(fixture.localProxyStatusLabel.bounds, to: card)
            try require(buttonRect.minX >= 0 && buttonRect.maxX <= card.bounds.width + 1
                        && buttonRect.minY >= 0 && buttonRect.maxY <= card.bounds.height + 1,
                        "本地代理按钮超出卡片：\(size), \(buttonRect), \(card.bounds)")
            try require(statusRect.minX >= 0 && statusRect.maxX <= buttonRect.minX
                        && statusRect.minY >= 0 && statusRect.maxY <= card.bounds.height + 1,
                        "长错误文案越界或覆盖按钮：\(size), \(statusRect), \(buttonRect), \(card.bounds)")
            clip.scroll(to: NSPoint(x: 0, y: max(0, document.frame.height - clip.bounds.height)))
            scroll.scrollView.reflectScrolledClipView(clip)
            let bottom = lastCard.convert(lastCard.bounds, to: document)
            try require(bottom.maxY <= clip.bounds.maxY + 1 && bottom.minY >= clip.bounds.minY - 1,
                        "末张设置卡片无法滚动到可见区域：\(size), \(bottom), \(clip.bounds)")
        }
        print("PASS local proxy UI: \(assertions) assertions; actual dashboard and settings overview builders, action wiring, state text, narrow/resized scroll reachability")
    }
}

@main
private enum LocalProxySettingsLayoutMain {
    static func main() throws {
        _ = NSApplication.shared
        try LocalProxyLayoutFixture.run()
    }
}

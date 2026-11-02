import AppKit
import HajimiUIComponents

/// Window visibility and timer adapter only. Diagnostics ownership and all
/// stale-result/cancellation decisions belong to the presentation feature.
public final class NetworkDiagnosticsPanelController: NSWindowController, NSWindowDelegate {
    public let feature: NetworkDiagnosticsFeature
    private var refreshTimer: Timer?

    public init(capabilities: NetworkDiagnosticsCapabilities) {
        precondition(Thread.isMainThread)
        feature = NetworkDiagnosticsFeature(capabilities: capabilities)
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 920, height: 820),
                            styleMask: [.titled, .closable, .miniaturizable, .resizable],
                            backing: .buffered, defer: false)
        panel.title = "哈基米 · 网络诊断与遥测中心 · " + capabilities.applicationVersion
        panel.minSize = NSSize(width: 850, height: 680)
        panel.backgroundColor = HajimiAppearance.workspace
        panel.isReleasedWhenClosed = false
        panel.contentView = WidthFittingScrollContentView(content: feature.view)
        super.init(window: panel)
        panel.delegate = self
        panel.center()
    }

    public required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit { refreshTimer?.invalidate() }

    public override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        reconcileTimer()
    }

    private var isVisible: Bool {
        guard let window else { return false }
        return window.isVisible && !window.isMiniaturized && window.occlusionState.contains(.visible)
    }

    private func reconcileTimer() {
        guard isVisible else { suspend(); return }
        feature.setVisible(true)
        guard refreshTimer == nil else { return }
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in self?.reconcileTimer() }
        timer.tolerance = 0.1
        RunLoop.main.add(timer, forMode: .common)
        refreshTimer = timer
    }

    private func suspend() {
        refreshTimer?.invalidate(); refreshTimer = nil
        feature.setVisible(false)
    }

    public func windowDidChangeOcclusionState(_ notification: Notification) { reconcileTimer() }
    public func windowDidDeminiaturize(_ notification: Notification) { reconcileTimer() }
    public func windowDidMiniaturize(_ notification: Notification) { suspend() }
    public func windowWillClose(_ notification: Notification) { suspend() }
}

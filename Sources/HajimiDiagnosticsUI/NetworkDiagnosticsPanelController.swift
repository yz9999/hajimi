import AppKit
import HajimiUIComponents

/// Window visibility and timer adapter only. Diagnostics ownership and all
/// stale-result/cancellation decisions belong to the presentation feature.
public final class NetworkDiagnosticsPanelController: NSWindowController, NSWindowDelegate {
    public let feature: NetworkDiagnosticsFeature
    public var onClose: (() -> Void)?
    private let scrollWrapper: WidthFittingScrollContentView
    private var refreshTimer: Timer?
    private var didClose = false

    public init(capabilities: NetworkDiagnosticsCapabilities) {
        precondition(Thread.isMainThread)
        feature = NetworkDiagnosticsFeature(capabilities: capabilities)
        scrollWrapper = WidthFittingScrollContentView(content: feature.view)
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 880, height: 680),
                            styleMask: [.titled, .closable, .miniaturizable, .resizable],
                            backing: .buffered, defer: false)
        panel.title = "哈基米 · 网络诊断 · " + capabilities.applicationVersion
        panel.minSize = NSSize(width: 850, height: 680)
        panel.backgroundColor = HajimiAppearance.workspace
        panel.isReleasedWhenClosed = false
        panel.contentView = scrollWrapper
        super.init(window: panel)
        panel.delegate = self
        panel.center()
        feature.view.onCloseDiagnostics = { [weak self] in
            self?.closeAndTeardown()
        }
    }

    public required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit {
        refreshTimer?.invalidate()
        feature.close()
    }

    public override func showWindow(_ sender: Any?) {
        didClose = false
        scrollWrapper.setSuspended(false)
        super.showWindow(sender)
        reconcileTimer()
    }

    public func closeAndTeardown() {
        precondition(Thread.isMainThread)
        guard !didClose else { return }
        window?.close()
        finishClose()
    }

    private func finishClose() {
        guard !didClose else { return }
        didClose = true
        suspend()
        window?.delegate = nil
        window?.contentView = nil
        let callback = onClose
        onClose = nil
        callback?()
    }

    private var isVisible: Bool {
        guard let window else { return false }
        return window.isVisible && !window.isMiniaturized && window.occlusionState.contains(.visible)
    }

    private func reconcileTimer() {
        guard isVisible else { suspend(); return }
        scrollWrapper.setSuspended(false)
        feature.setVisible(true)
        guard refreshTimer == nil else { return }
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            guard let self else { return }
            if self.isVisible { self.feature.refreshIfVisible() }
            else { self.suspend() }
        }
        timer.tolerance = 0.1
        RunLoop.main.add(timer, forMode: .common)
        refreshTimer = timer
    }

    private func suspend() {
        refreshTimer?.invalidate(); refreshTimer = nil
        feature.setVisible(false)
        scrollWrapper.setSuspended(true)
    }

    public func windowDidChangeOcclusionState(_ notification: Notification) { reconcileTimer() }
    public func windowDidDeminiaturize(_ notification: Notification) { reconcileTimer() }
    public func windowDidMiniaturize(_ notification: Notification) { suspend() }
    public func windowWillClose(_ notification: Notification) {
        finishClose()
    }
}

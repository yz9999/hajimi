import Foundation
import HajimiCore
import HajimiRuntime

/// A monotonic gate shared by reveal and periodic refreshes. Repeated
/// hide/reveal cycles cannot make recorder polling faster than once a second.
package struct NetworkDiagnosticsRefreshGate {
    private var lastRefresh: Double?

    package init() {}

    package mutating func shouldRefresh(visible: Bool, now: Double) -> Bool {
        guard visible, now.isFinite else { return false }
        if let lastRefresh, now - lastRefresh < 1 { return false }
        lastRefresh = now
        return true
    }
}

/// The complete presentation session, independent of NSWindow and the actual
/// App owners. Every entry point and applied state is confined to main.
public final class NetworkDiagnosticsFeature {
    public let view: NetworkDiagnosticsView
    public private(set) var isVisible = false
    public var isDetectionRunning: Bool { view.isDetectionRunning }
    public var canStartDetection: Bool { isVisible && view.canStartDetection }

    private let capabilities: NetworkDiagnosticsCapabilities
    private let statisticsQueue = DispatchQueue(label: "app.hajimi.network-diagnostics.presentation", qos: .userInitiated)
    private var statisticsRequestID: UUID?
    private var gate = NetworkDiagnosticsRefreshGate()
    private var visibilityEpoch: UInt64 = 0
    private var localCaptureID: UUID?
    private var lastLocalCapture: Double?
    private var previousLocalNetwork: LocalNetworkDiagnosticsSnapshot?
    private var previousContext: NetworkDiagnosticsRuntimeContext?
    private var session: RuntimeOperation?
    private var round = NetworkDiagnosticsRoundGuard()

    public init(capabilities: NetworkDiagnosticsCapabilities) {
        precondition(Thread.isMainThread)
        self.capabilities = capabilities
        view = NetworkDiagnosticsView(frame: .zero, applicationVersion: capabilities.applicationVersion,
            now: capabilities.now, copyReport: capabilities.copyReport, exportReport: capabilities.exportReport)
        view.showStatisticsLoading()
        view.onStartDetection = capabilities.startDiagnostics == nil ? nil : { [weak self] in
            self?.beginDetection()
        }
        view.onStopDetection = { [weak self] in self?.stopDetection() }
    }

    deinit { session?.cancel() }

    public func setVisible(_ visible: Bool) {
        precondition(Thread.isMainThread)
        if isVisible != visible { visibilityEpoch &+= 1 }
        isVisible = visible
        if visible { refreshIfVisible() }
        else { cancelDetection(reason: "检测已停止；点击“开始网络检测”重新运行。") }
    }

    public func close() { setVisible(false) }

    public func refreshIfVisible() {
        precondition(Thread.isMainThread)
        guard isVisible else { return }
        let now = Double(capabilities.now()) / 1_000_000_000
        guard gate.shouldRefresh(visible: true, now: now) else { return }
        let epoch = visibilityEpoch
        let context = capabilities.context()
        guard isVisible, visibilityEpoch == epoch else { return }
        if let previousContext, previousContext != context {
            cancelDetection(reason: "网络或配置已变化，请重新检测。", clearCompleted: true)
            view.clearLocalNetwork()
            lastLocalCapture = nil
        }
        previousContext = context
        view.applyContext(context, detectionAvailable: capabilities.startDiagnostics != nil)
        refreshStatistics(context: context, epoch: epoch)
        refreshLocalNetwork(context: context, now: now)
    }

    private func refreshStatistics(context: NetworkDiagnosticsRuntimeContext, epoch: UInt64) {
        // A slow recorder read occupies one physical slot even across
        // hide/reveal. Timer ticks cannot accumulate queued snapshots.
        guard statisticsRequestID == nil else { return }
        let id = UUID(), statistics = capabilities.statistics
        statisticsRequestID = id
        statisticsQueue.async { [weak self] in
            let prepared = autoreleasepool { NetworkDiagnosticsFormatting.prepare(statistics()) }
            DispatchQueue.main.async { [weak self] in
                guard let self, self.statisticsRequestID == id else { return }
                self.statisticsRequestID = nil
                guard self.isVisible, self.visibilityEpoch == epoch else { return }
                let currentContext = self.capabilities.context()
                // Context providers can re-enter hide/close/refresh. Check
                // again after calling one, including for a newer request.
                guard self.isVisible, self.visibilityEpoch == epoch,
                      self.statisticsRequestID == nil, self.previousContext == context,
                      currentContext == context else { return }
                self.view.apply(prepared)
            }
        }
    }

    private func refreshLocalNetwork(context: NetworkDiagnosticsRuntimeContext, now: Double) {
        guard localCaptureID == nil, lastLocalCapture.map({ now - $0 >= 5 }) ?? true else { return }
        let captureID = UUID(), epoch = visibilityEpoch
        localCaptureID = captureID
        capabilities.captureLocalNetwork(context.boundInterfaceName) { [weak self] snapshot in
            DispatchQueue.main.async { [weak self] in
                guard let self, self.localCaptureID == captureID else { return }
                // A short platform read is not interruptible. Preserve its
                // single physical slot until the real callback, even hidden.
                self.localCaptureID = nil
                let currentContext = self.capabilities.context()
                guard self.isVisible, self.visibilityEpoch == epoch,
                      currentContext == context else { return }
                if let previous = self.previousLocalNetwork,
                   !NetworkDiagnosticsSummary.sameLocalNetwork(previous, snapshot) {
                    self.cancelDetection(reason: "本地网络设置已变化，请重新检测。", clearCompleted: true)
                }
                self.previousLocalNetwork = snapshot
                self.lastLocalCapture = Double(self.capabilities.now()) / 1_000_000_000
                self.view.applyLocalNetwork(snapshot)
            }
        }
    }

    public func beginDetection() {
        precondition(Thread.isMainThread)
        guard isVisible, !view.isDetectionRunning, session == nil,
              let startDiagnostics = capabilities.startDiagnostics else { return }
        cancelDetection(reason: "正在准备检测…", clearCompleted: true)
        let epoch = visibilityEpoch
        let context = capabilities.context()
        guard isVisible, visibilityEpoch == epoch, session == nil, !view.isDetectionRunning else { return }
        previousContext = context
        view.applyContext(context, detectionAvailable: true)
        guard context.engineRunning else { return }
        let id = round.begin(context: context)
        view.prepareDetection()
        // Install our placeholder before entering a provider. A synchronous
        // hide/close/cancel revokes it before the child handle even exists.
        let operation = RuntimeOperation()
        session = operation
        let child = startDiagnostics { [weak self, weak operation] snapshot in
            DispatchQueue.main.async { [weak self, weak operation] in
                guard let self, let operation, !operation.isCancelled else { return }
                let currentContext = self.capabilities.context()
                guard self.round.accepts(id, context: currentContext, visible: self.isVisible) else { return }
                self.view.applyConnectivity(snapshot)
                if !snapshot.isRunning {
                    // A provider can run the main loop before returning its
                    // handle. Retire the round now so later progress cannot
                    // turn a completed presentation back into a running one.
                    self.round.invalidate()
                    if self.session === operation { self.session = nil }
                    operation.cancel()
                }
            }
        }
        operation.installCancellation { child.cancel() }
        let currentContext = capabilities.context()
        if !round.accepts(id, context: currentContext, visible: isVisible) {
            if session === operation { session = nil }
            operation.cancel()
        }
    }

    public func stopDetection() {
        precondition(Thread.isMainThread)
        guard session != nil || view.isDetectionRunning else { return }
        cancelDetection(reason: "本轮检测已停止；可重新开始网络检测。")
    }

    private func cancelDetection(reason: String, clearCompleted: Bool = false) {
        round.invalidate()
        let wasRunning = view.isDetectionRunning || session != nil
        let previousSession = session
        session = nil
        if wasRunning || clearCompleted { view.clearConnectivity(reason: reason) }
        previousSession?.cancel()
    }
}

import AppKit
import UniformTypeIdentifiers
import HajimiCore
import HajimiRuntime

/// Passive snapshots supplied by the existing App owners. This feature does
/// not acquire a router, create probes or read global recorder singletons.
public struct NetworkDiagnosticsStatistics {
    public let performance: NetworkPerformanceSnapshot
    public let scheduler: ProbeScheduler.Snapshot

    public init(performance: NetworkPerformanceSnapshot, scheduler: ProbeScheduler.Snapshot) {
        self.performance = performance
        self.scheduler = scheduler
    }
}

/// Context, local-capture and detection entry points are called on main.
/// Statistics must be safe to read from the feature's serial worker: recorder
/// locks and presentation formatting must not delay showing the window.
/// Providers may deliver from any queue; results are always applied on main.
/// Local capture remains a short read with at most one callback outstanding.
public struct NetworkDiagnosticsCapabilities {
    public typealias CaptureLocalNetwork = (String?, @escaping (LocalNetworkDiagnosticsSnapshot) -> Void) -> Void
    public typealias StartDiagnostics = (@escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) -> RuntimeOperation

    public let context: () -> NetworkDiagnosticsRuntimeContext
    public let statistics: () -> NetworkDiagnosticsStatistics
    public let captureLocalNetwork: CaptureLocalNetwork
    public let startDiagnostics: StartDiagnostics?
    public let now: () -> UInt64
    public let applicationVersion: String
    public let copyReport: (String) -> Void
    public let exportReport: (String, String, NSWindow?) -> Void

    public init(context: @escaping () -> NetworkDiagnosticsRuntimeContext,
                statistics: @escaping () -> NetworkDiagnosticsStatistics,
                captureLocalNetwork: @escaping CaptureLocalNetwork,
                startDiagnostics: StartDiagnostics? = nil,
                now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
                applicationVersion: String = NetworkDiagnosticsCapabilities.currentApplicationVersion,
                copyReport: @escaping (String) -> Void = NetworkDiagnosticsCapabilities.copyToPasteboard,
                exportReport: @escaping (String, String, NSWindow?) -> Void = NetworkDiagnosticsCapabilities.exportToFilePanel) {
        self.context = context
        self.statistics = statistics
        self.captureLocalNetwork = captureLocalNetwork
        self.startDiagnostics = startDiagnostics
        self.now = now
        self.applicationVersion = applicationVersion
        self.copyReport = copyReport
        self.exportReport = exportReport
    }

    public static var currentApplicationVersion: String { NetworkDiagnosticsFormatting.applicationVersion }

    public static func copyToPasteboard(_ report: String) {
        precondition(Thread.isMainThread)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(report, forType: .string)
    }

    public static func exportToFilePanel(_ report: String, defaultFilename: String, window: NSWindow?) {
        precondition(Thread.isMainThread)
        let panel = NSSavePanel()
        panel.title = "导出诊断报告文件"
        panel.prompt = "导出文件"
        panel.nameFieldLabel = "文件名："
        panel.nameFieldStringValue = defaultFilename
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.allowsOtherFileTypes = true
        panel.allowedContentTypes = [.json, .plainText]
        let writeFile: (URL) -> Void = { url in
            do {
                try Data(report.utf8).write(to: url, options: .atomic)
            } catch {
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = "导出诊断报告失败"
                alert.informativeText = error.localizedDescription
                alert.runModal()
            }
        }
        if let window {
            panel.beginSheetModal(for: window) { response in
                guard response == .OK, let url = panel.url else { return }
                writeFile(url)
            }
        } else if panel.runModal() == .OK, let url = panel.url {
            writeFile(url)
        }
    }
}

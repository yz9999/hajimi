import Foundation
import HajimiCore
import HajimiRuntime
import HajimiDiagnosticsUI

/// Supplies presentation capabilities from the App's existing owners. The
/// closures supplied by Main retain its weak captures; no replacement router,
/// listener, tunnel, configuration or Helper session is created here.
enum NetworkDiagnosticsAppAdapter {
    static func capabilities(
        contextProvider: @escaping () -> NetworkDiagnosticsRuntimeContext,
        startDiagnostics: @escaping NetworkDiagnosticsCapabilities.StartDiagnostics
    ) -> NetworkDiagnosticsCapabilities {
        let localQueue = DispatchQueue(label: "app.hajimi.network-diagnostics.local", qos: .utility)
        return NetworkDiagnosticsCapabilities(
            context: contextProvider,
            statistics: {
                // The presentation feature invokes this on its one worker;
                // waiting for either recorder lock never blocks AppKit.
                NetworkDiagnosticsStatistics(performance: NetworkPerformanceDiagnostics.shared.snapshot(),
                                             scheduler: ProbeScheduler.shared.snapshot())
            },
            captureLocalNetwork: { interfaceName, completion in
                // These bounded local reads cannot be interrupted. Always
                // acknowledge completion so the UI can release its single
                // in-flight slot; its visibility/context epoch rejects stale
                // results before they are displayed.
                localQueue.async {
                    completion(LocalNetworkDiagnostics.capture(boundPhysicalInterfaceName: interfaceName))
                }
            },
            startDiagnostics: startDiagnostics,
            now: NetworkPerformanceDiagnostics.now)
    }
}

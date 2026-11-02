import AppKit

/// The same diagnostics regression entry point is used by the maintenance
/// CLI and independent runner. Every invocation owns a fresh memory fixture.
public enum NetworkDiagnosticsUISelfTest {
    public static func run() throws {
        precondition(Thread.isMainThread)
        _ = NSApplication.shared
        try NetworkDiagnosticsPresentationSelfTest.run()
        try NetworkDiagnosticsFeatureSelfTest().run()
    }

    /// A caller-owned host may be attached to an unshown fixture window so
    /// AppKit delivers normal Auto Layout changes after asynchronous results.
    public static func runDynamicScrollLayout(in host: NSView) throws {
        precondition(Thread.isMainThread)
        try NetworkDiagnosticsScrollLayoutSelfTest.run(in: host)
    }
}

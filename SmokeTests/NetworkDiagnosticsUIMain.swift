import AppKit
import HajimiDiagnosticsUITestSupport

/// Both calls exercise the same public test-support entry used by the App
/// CLI. Running twice in one process also verifies fresh per-run ownership.
@main
enum NetworkDiagnosticsUICheck {
    static func main() throws {
        _ = NSApplication.shared
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 880, height: 680),
            styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        guard let host = window.contentView else { fatalError("missing test host") }
        for _ in 0..<2 {
            try NetworkDiagnosticsUISelfTest.run()
            try NetworkDiagnosticsUISelfTest.runDynamicScrollLayout(in: host)
            precondition(!window.isVisible && !window.isKeyWindow && !window.isMainWindow)
        }
        print("Diagnostics layout window was never ordered, activated or run; memory snapshots only")
        print("Diagnostics UI module import passed: two complete runs in one process")
    }
}

import Foundation

@main
enum ProbeSchedulerCheck {
    static func main() throws {
        try ProbeSchedulerSelfTest.run()
        try NetworkPerformanceDiagnosticsSelfTest.run()
        try PolicyRefreshPlanSelfTest.run()
        print("Probe admission, deadlines, cancellation, diagnostics aggregates and UI refresh plans passed (in-memory only)")
    }
}

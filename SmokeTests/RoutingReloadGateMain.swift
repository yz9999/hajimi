import Foundation

@main
private enum RoutingReloadGateMain {
    static func main() throws {
        try RoutingReloadGateSelfTest.run()
        print("Routing reload gate self-test passed: original configuration/dependency/lifecycle cases and reentrant reload/start/stop/failure regressions")
    }
}

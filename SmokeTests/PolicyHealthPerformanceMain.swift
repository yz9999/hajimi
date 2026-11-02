import Foundation

@main
enum PolicyHealthPerformanceCheck {
    static func main() throws {
        try PolicyHealthSelfTest.runInMemory()
        print("Policy health deferred results, late-stream cleanup and physical pending admission passed (in-memory only)")
    }
}

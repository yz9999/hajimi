import Foundation

@main
enum RuleSetBackgroundRefreshMain {
    static func main() {
        do {
            try RuleSetBackgroundRefreshPlanSelfTest.run()
            print("Rule-set background refresh checks passed: restore ordering, enhanced-only readiness, single task, generation fences and bounded retry")
        } catch {
            FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}

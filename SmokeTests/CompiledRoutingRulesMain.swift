import Foundation

@main
struct CompiledRoutingRulesMain {
    static func main() throws {
        try CompiledRoutingRulesSelfTest.run()
        if ProcessInfo.processInfo.environment["HAJIMI_RULE_BENCHMARK"] == "1" {
            try CompiledRoutingRulesSelfTest.benchmark()
        }
    }
}

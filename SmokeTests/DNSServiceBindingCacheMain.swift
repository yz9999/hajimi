import Foundation
import HajimiDNS

/// Standalone, memory-only wire regressions. Compile with the inspection and
/// independently compiled DNS module and Core diagnostics; no resolver, app or
/// user profile is opened.
@main
enum DNSServiceBindingCacheMain {
    static func main() throws {
        try DNSQueryCacheSelfTest.run()
        try NetworkPerformanceDiagnosticsSelfTest.run()
        print("DNS wire-answer cache checks passed")
    }
}

import Foundation
import HajimiCore

/// Cache/refresh fixtures use temporary local files only, never the network
/// or the user's live rule-set/configuration directory.
@main
struct RuleSetRefreshSmokeTest {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(message: message) }
    }

    static func main() {
        do {
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("hajimi-rule-refresh-" + UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let a = root.appendingPathComponent("a.rules")
            let b = root.appendingPathComponent("b.rules")
            try "DOMAIN-SUFFIX,old-a.test\n".write(to: a, atomically: true, encoding: .utf8)
            try "DOMAIN-SUFFIX,old-b.test\n".write(to: b, atomically: true, encoding: .utf8)
            let manager = SurgeRuleSetManager(applicationSupportDirectory: root)
            let source = try ProfileParser.parse("""
            [Rule]
            RULE-SET,\(a.absoluteString),REJECT,update-interval=86400
            RULE-SET,\(b.absoluteString),DIRECT,update-interval=86400
            FINAL,DIRECT
            """)
            let first = try manager.prepare(profile: source)
            try require(first.ruleSetContents[a.absoluteString] == [.domainSuffix("old-a.test")],
                        "Initial resource A load")
            try require(first.ruleSetContents[b.absoluteString] == [.domainSuffix("old-b.test")],
                        "Initial resource B load")
            print("PASS: initial local rule-set load and cache")

            try "DOMAIN-SUFFIX,new-a.test\n".write(to: a, atomically: true, encoding: .utf8)
            try "DOMAIN-SUFFIX,new-b.test\n".write(to: b, atomically: true, encoding: .utf8)
            let cached = try manager.prepare(profile: source)
            try require(cached.ruleSetContents == first.ruleSetContents,
                        "Fresh automatic cache should be retained")
            print("PASS: automatic preparation honors fresh cache")

            let selected = try manager.prepare(profile: source, forceRefreshLocations: [a.absoluteString])
            try require(selected.ruleSetContents[a.absoluteString] == [.domainSuffix("new-a.test")],
                        "Selected refresh must bypass a fresh cache")
            try require(selected.ruleSetContents[b.absoluteString] == [.domainSuffix("old-b.test")],
                        "Selected refresh must not force other fresh resources")
            try require(selected.rules == source.rules, "Refresh must preserve rule order and source lines")
            try require(selected.route(for: .init(host: "www.new-a.test", port: 443, protocolName: "TCP"),
                                       mode: .rule, globalPolicy: "DIRECT").policyName == "REJECT",
                        "Updated rule-set must become effective for routing")
            print("PASS: selected manual refresh bypasses cache and updates routing")

            let all = try manager.prepare(profile: source,
                                          forceRefreshLocations: [a.absoluteString, b.absoluteString])
            try require(all.ruleSetContents[b.absoluteString] == [.domainSuffix("new-b.test")],
                        "Refresh all must fetch every requested resource")
            print("PASS: refresh-all updates both resources")

            try FileManager.default.removeItem(at: a)
            let fallback = try manager.prepare(profile: source, forceRefreshLocations: [a.absoluteString])
            try require(fallback.ruleSetContents[a.absoluteString] == [.domainSuffix("new-a.test")],
                        "Failed manual refresh must retain the last usable cache")
            try require(fallback.warnings.contains { $0.contains("RULE-SET 更新失败") },
                        "Stale fallback must be visible as a warning")
            print("PASS: failed refresh retains cache and reports a warning")

            let missing = root.appendingPathComponent("uncached.rules")
            let invalid = try ProfileParser.parse("[Rule]\nRULE-SET,\(missing.absoluteString),REJECT\nFINAL,DIRECT\n")
            do {
                _ = try manager.prepare(profile: invalid, forceRefreshLocations: [missing.absoluteString])
                throw Failure(message: "Missing uncached resource must fail, not silently route DIRECT")
            } catch is SurgeRuleSetManager.RuleSetError {
                print("PASS: uncached resource failure does not silently bypass rules")
            }
            try require(source.ruleSetContents.isEmpty, "Preparation must not mutate the input profile")
            print("PASS: rule-set refresh smoke tests")
        } catch {
            FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}

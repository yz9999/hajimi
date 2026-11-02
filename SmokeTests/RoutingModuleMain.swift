import Foundation
import HajimiRouting

/// Fixed public-API vectors. No Profile parser, Core, C++ matcher, resolver,
/// listener, Helper, application state or user configuration participates.
@main
enum RoutingModuleMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "Routing module: \(text)" }
    }
    private static var assertions = 0

    private static func expect(_ condition: @autoclosure () -> Bool, _ text: String) throws {
        assertions += 1
        if !condition() { throw Failure(text: text) }
    }

    private static let direct = ProxyPolicy(name: "DIRECT", kind: .direct)
    private static let reject = ProxyPolicy(name: "REJECT", kind: .reject)
    private static let http = ProxyPolicy(name: "HTTP", kind: .http, host: "203.0.113.10", port: 8080,
                                         username: "memory-user", password: "memory-secret")
    private static let socks = ProxyPolicy(name: "SOCKS", kind: .socks5, host: "203.0.113.11", port: 1080)
    private static let native = ProxyPolicy(name: "NATIVE", kind: .native, host: "203.0.113.12", port: 443,
                                           adapterType: "vmess", parameters: ["uuid": "memory-only"])

    private static func table(_ rules: [RoutingRule] = [], contents: [String: [RuleKind]] = [:],
                              extraProxies: [String: ProxyPolicy] = [:],
                              groups: [String: PolicyGroup] = [:]) -> RoutingTable {
        var proxies = ["DIRECT": direct, "REJECT": reject, "HTTP": http, "SOCKS": socks, "NATIVE": native]
        proxies.merge(extraProxies) { _, newer in newer }
        return RoutingTable(rules: rules, ruleSetContents: contents, proxies: proxies, groups: groups)
    }

    private static func rule(_ kind: RuleKind, _ policy: String = "REJECT", line: Int = 1) -> RoutingRule {
        RoutingRule(kind: kind, policy: policy, sourceLine: line)
    }

    static func main() throws {
        try fixedLeafCases()
        try orderAndAlternateHost()
        try policyCases()
        try valueAndConcurrencyCases()
        print("Routing module self-test passed: \(assertions) fixed public-API assertions; rules/order, ordinary alternate-host semantics, metadata isolation, policy selection, Codable/value snapshots and concurrent readers; imported HajimiRouting without Core/native/I/O")
    }

    private static func fixedLeafCases() throws {
        let base = RequestTarget(host: "..WWW.Example.TEST..", port: 443, protocolName: "tcp",
                                 sourceHost: "192.0.2.9", sourcePort: 0, inboundPort: 7263)
        try expect(base.protocolName == "TCP", "protocol initialization normalization changed")
        let vectors: [(RuleKind, Bool)] = [
            (.domain("www.example.test"), true), (.domain("example.test"), false),
            (.domainSuffix("example.test"), true), (.domainSuffix("ample.test"), false),
            (.domainKeyword("EXAMPLE"), true), (.domainWildcard("w??.example.*"), true),
            (.domainWildcard("w?.example.test"), false), (.ipCIDR("192.0.2.0/24"), false),
            (.destinationPort(443...443), true), (.destinationPort(80...80), false),
            (.sourceIPCIDR("192.0.2.0/24"), true), (.sourceIPCIDR("198.51.100.0/24"), false),
            (.sourcePort(0...0), true), (.inboundPort(7263...7263), true),
            (.protocolName("tCp"), true), (.protocolName("UDP"), false),
            (.geoIP("CN"), false), (.ipASN("123"), false), (.processName("memory"), false),
            (.logicalAnd([.domainSuffix("example.test"), .destinationPort(443...443)]), true),
            (.logicalAnd([]), false), (.logicalOr([]), false),
            (.logicalOr([.protocolName("UDP"), .sourcePort(0...0)]), true),
            (.logicalNot(.protocolName("UDP")), true), (.final, true)
        ]
        for (index, vector) in vectors.enumerated() {
            try expect(RoutingRuleMatcher.matches(vector.0, target: base) == vector.1,
                       "fixed leaf vector \(index) changed")
        }
        let absent = RequestTarget(host: "203.0.113.8", port: 0, protocolName: "UDP")
        let zeros = RequestTarget(host: absent.host, port: 0, protocolName: "UDP",
                                  sourceHost: "", sourcePort: 0, inboundPort: 0)
        for kind: RuleKind in [.sourcePort(0...0), .inboundPort(0...0)] {
            try expect(!RoutingRuleMatcher.matches(kind, target: absent)
                && RoutingRuleMatcher.matches(kind, target: zeros), "missing metadata became numeric zero")
        }
        let literals: [(String, String, Bool)] = [
            ("203.0.113.0", "203.0.113.0/31", true), ("203.0.113.1", "203.0.113.0/31", true),
            ("203.0.113.2", "203.0.113.0/31", false), ("203.0.113.1", "0.0.0.0/0", true),
            ("2001:DB8::1%en1", "2001:db8::/127", true), ("2001:db8::2", "2001:db8::/127", false),
            ("2001:db8::1", "2001:db8::1/128", true), ("2001:db8::1", "2001:db8::/129", false),
            ("203.0.113.1", "203.0.113.0/33", false)
        ]
        for (host, cidr, expected) in literals {
            try expect(RoutingRuleMatcher.matches(.ipCIDR(cidr),
                target: .init(host: host, port: 53, protocolName: "UDP")) == expected, "CIDR \(cidr)/\(host)")
        }
        try expect(RoutingRuleMatcher.matches(.domain("caf\u{e9}.test"),
            target: .init(host: "cafe\u{301}.test", port: 443, protocolName: "TCP")),
                   "canonical Unicode domain equality changed")
        let procTarget = RequestTarget(host: "example.test", port: 443, protocolName: "TCP",
                                       processName: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        try expect(RoutingRuleMatcher.matches(.processName("Google Chrome"), target: procTarget)
            && RoutingRuleMatcher.matches(.processName("Google Chrome.app"), target: procTarget)
            && RoutingRuleMatcher.matches(.processName("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"), target: procTarget)
            && !RoutingRuleMatcher.matches(.processName("Safari"), target: procTarget),
                   "PROCESS-NAME basename/bundle/path matching failed")
    }

    private static func orderAndAlternateHost() throws {
        let original = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
                                     sourceHost: "192.0.2.8", sourcePort: 40000, inboundPort: 7263)
        let domain = rule(.domainSuffix("question.test"), "HTTP")
        let ip = rule(.ipCIDR("203.0.113.0/24"))
        let final = rule(.final, "DIRECT")
        let firstIP = table([ip, domain, final])
        let firstDomain = table([domain, ip, final])
        try expect(firstIP.route(for: original, mode: .rule, globalPolicy: "HTTP",
            alternateHost: "www.question.test") == .reject("REJECT"), "alternate host discarded original destination IP or rule order")
        try expect(firstDomain.route(for: original, mode: .rule, globalPolicy: "DIRECT",
            alternateHost: "www.question.test") == .http(http, "HTTP"), "top-level ordinary alternate-host match changed")
        try expect(firstDomain.interpretedRuleIndex(for: original, alternateHost: "www.question.test") == 0,
                   "first rule index no longer refers to source ordering")
        let source = table([rule(.sourceIPCIDR("192.0.2.0/24")), domain, final])
        try expect(source.route(for: original, mode: .rule, globalPolicy: "HTTP",
            alternateHost: "www.question.test") == .reject("REJECT"), "alternate host discarded source metadata")
        let logical = rule(.logicalAnd([.domainSuffix("question.test"), .destinationPort(53...53)]), "HTTP")
        try expect(table([logical, final]).route(for: original, mode: .rule, globalPolicy: "HTTP",
            alternateHost: "www.question.test") == .direct("DIRECT"),
                   "ordinary logical rule unexpectedly adopted DNS recursive QNAME semantics")
        let reference = RuleSetReference(location: "memory.rules")
        try expect(table([rule(.ruleSet(reference), "HTTP"), final],
                         contents: [reference.location: [.domainSuffix("question.test")]])
            .route(for: original, mode: .rule, globalPolicy: "DIRECT", alternateHost: "www.question.test") == .http(http, "HTTP"),
                   "direct domain member of ordinary rule set lost alternate host")
        try expect(table([rule(.ruleSet(reference), "HTTP"), final], contents: [reference.location: [logical.kind]])
            .route(for: original, mode: .rule, globalPolicy: "HTTP", alternateHost: "www.question.test") == .direct("DIRECT"),
                   "ordinary rule-set logical member changed to DNS recursion")
        try expect(table([rule(.ruleSet(reference)), final], contents: [reference.location: [.ruleSet(reference)]])
            .route(for: original, mode: .rule, globalPolicy: "HTTP") == .direct("DIRECT"),
                   "ordinary nested rule-set fallback became recursive")
        try expect(table().route(for: original, mode: .rule, globalPolicy: "HTTP") == .direct("DIRECT"),
                   "no matching ordinary rule did not retain direct default")
        try expect(firstIP.route(for: original, mode: .direct, globalPolicy: "HTTP") == .direct("DIRECT")
            && firstIP.route(for: original, mode: .proxy, globalPolicy: "HTTP") == .http(http, "HTTP"),
                   "explicit direct/proxy mode acquired ordinary rule semantics")
    }

    private static func policyCases() throws {
        let target = RequestTarget(host: "WWW.Example.test", port: 443, protocolName: "TCP")
        let groups = [
            "Pick": PolicyGroup(name: "Pick", members: ["HTTP", "SOCKS"]),
            "Balanced": PolicyGroup(name: "Balanced", kind: .loadBalance, members: ["HTTP", "SOCKS", "NATIVE"]),
            "Empty": PolicyGroup(name: "Empty", members: []),
            "LoopA": PolicyGroup(name: "LoopA", members: ["LoopB"]),
            "LoopB": PolicyGroup(name: "LoopB", members: ["LoopA"])
        ]
        let routing = table(groups: groups)
        try expect(routing.resolvePolicy("Pick", target: target) == .http(http, "HTTP"), "group default member changed")
        try expect(routing.resolvePolicy("Pick", target: target, groupSelections: ["Pick": "SOCKS"]) == .socks5(socks, "SOCKS"),
                   "approved group selection changed")
        try expect(routing.resolvePolicy("Pick", target: target, groupSelections: ["Pick": "Missing"]) == .http(http, "HTTP"),
                   "invalid group selection stopped using first approved member")
        try expect(routing.resolvePolicy("Empty", target: target) == .reject("Empty group: Empty"), "empty policy group opened a route")
        try expect(routing.resolvePolicy("LoopA", target: target) == .reject("Policy loop: LoopA"), "policy loop did not reject")
        try expect(routing.resolvePolicy("Missing", target: target) == .reject("Unknown: Missing"), "unknown policy did not reject")
        try expect(routing.resolvePolicy("direct", target: target) == .direct("DIRECT")
            && routing.resolvePolicy("reject-tinygif", target: target) == .reject("REJECT"), "built-in policy normalization changed")
        let balanceCases: [(RequestTarget, ResolvedRoute)] = [
            (target, .native(native, "NATIVE")),
            (.init(host: "other.test", port: 80, protocolName: "TCP"), .socks5(socks, "SOCKS")),
            (.init(host: "203.0.113.8", port: 53, protocolName: "UDP"), .socks5(socks, "SOCKS"))
        ]
        for (request, expected) in balanceCases {
            try expect(routing.resolvePolicy("Balanced", target: request) == expected, "fixed load-balance mapping changed")
        }
        for (adapter, expectedHTTP) in [("https", true), ("http", true), ("socks5", false), ("socks5-tls", false)] {
            let promoted = ProxyPolicy(name: "Promoted", kind: .native, host: "203.0.113.19", port: 443, adapterType: adapter)
            let selected = table(extraProxies: [promoted.name: promoted]).resolvePolicy(promoted.name, target: target)
            try expect(selected == (expectedHTTP ? .http(promoted, promoted.name) : .socks5(promoted, promoted.name)),
                       "promoted \(adapter) changed transport semantics")
        }
        let external = ProxyPolicy(name: "External", kind: .external, adapterType: "unsupported")
        try expect(table(extraProxies: [external.name: external]).resolvePolicy(external.name, target: target)
            == .reject("Adapter not running: External"), "unprepared external adapter opened a route")
        let subnetGroup = PolicyGroup(name: "ByLAN", kind: .subnet, members: [
            "192.168.50.0/24 = SOCKS",
            "10.0.0.0/8 = NATIVE",
            "default = HTTP"
        ])
        let smartGroup = PolicyGroup(name: "SmartGroup", kind: .smart,
                                     members: ["HTTP", "SOCKS"],
                                     parameters: ["policy-priority": "HTTP:0.2;SOCKS:2.5"])
        let advRouting = table(groups: ["ByLAN": subnetGroup, "SmartGroup": smartGroup])
        let lanTarget = RequestTarget(host: "example.test", port: 443, protocolName: "TCP", sourceHost: "192.168.50.25")
        let fallbackTarget = RequestTarget(host: "example.test", port: 443, protocolName: "TCP", sourceHost: "172.16.1.9")
        try expect(advRouting.resolvePolicy("ByLAN", target: lanTarget) == .socks5(socks, "SOCKS")
            && advRouting.resolvePolicy("ByLAN", target: fallbackTarget) == .http(http, "HTTP"),
                   "subnet group CIDR/default matching failed")
        try expect(advRouting.resolvePolicy("SmartGroup", target: target) == .socks5(socks, "SOCKS"),
                   "smart group policy-priority weighting failed")
    }

    private static func valueAndConcurrencyCases() throws {
        let reference = RuleSetReference(location: "memory.copy")
        var rules = [rule(.ruleSet(reference)), rule(.final, "DIRECT")]
        var contents = [reference.location: [RuleKind.domain("old.test")]]
        let original = table(rules, contents: contents)
        let old = RequestTarget(host: "old.test", port: 443, protocolName: "TCP")
        let new = RequestTarget(host: "new.test", port: 443, protocolName: "TCP")
        contents[reference.location] = [.domain("new.test")]
        rules[1].policy = "HTTP"
        let replacement = table(rules, contents: contents)
        try expect(original.route(for: old, mode: .rule, globalPolicy: "DIRECT") == .reject("REJECT")
            && original.route(for: new, mode: .rule, globalPolicy: "DIRECT") == .direct("DIRECT")
            && replacement.route(for: old, mode: .rule, globalPolicy: "DIRECT") == .http(http, "HTTP")
            && replacement.route(for: new, mode: .rule, globalPolicy: "DIRECT") == .reject("REJECT"),
                   "value input mutation contaminated an older routing snapshot")
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        let wire = try encoder.encode(old)
        try expect(String(data: wire, encoding: .utf8) == "{\"host\":\"old.test\",\"port\":443,\"protocolName\":\"TCP\"}",
                   "RequestTarget public Codable schema changed")
        let decodedTarget = try JSONDecoder().decode(RequestTarget.self, from: wire)
        try expect(decodedTarget == old, "RequestTarget Codable round trip changed")
        let encodedRule = try encoder.encode(rules[0])
        let decodedRule = try JSONDecoder().decode(RoutingRule.self, from: encodedRule)
        try expect(decodedRule == rules[0], "recursive rule Codable round trip changed")
        let lock = NSLock()
        var failed = false
        DispatchQueue.concurrentPerform(iterations: 128) { index in
            let chosen = index.isMultiple(of: 2) ? original : replacement
            let expected: ResolvedRoute = index.isMultiple(of: 2) ? .reject("REJECT") : .http(http, "HTTP")
            if chosen.route(for: old, mode: .rule, globalPolicy: "DIRECT") != expected {
                lock.lock(); failed = true; lock.unlock()
            }
        }
        try expect(!failed, "concurrent readers crossed independent value snapshots")
    }
}

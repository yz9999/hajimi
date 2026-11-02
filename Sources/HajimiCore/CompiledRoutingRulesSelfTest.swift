import Foundation

/// Pure synthetic rules and in-memory requests. The interpreter remains an
/// independent oracle, including its deliberately different DNS semantics.
public enum CompiledRoutingRulesSelfTest {
    private struct Failure: LocalizedError {
        let errorDescription: String?
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(errorDescription: "编译规则自检失败：" + message) }
    }

    private static func fixture(_ rules: [RuleKind], contents: [String: [RuleKind]] = [:]) -> Profile {
        var profile = Profile()
        profile.rules = rules.enumerated().map {
            RoutingRule(kind: $0.element, policy: $0.offset.isMultiple(of: 2) ? "REJECT" : "DIRECT",
                        sourceLine: $0.offset + 1)
        }
        profile.ruleSetContents = contents
        return profile
    }

    private static func dnsReference(_ profile: Profile, target: RequestTarget,
                                     name: String) -> CompiledRuleSelection {
        func matches(_ kind: RuleKind, depth: Int = 0, visited: Set<String> = []) throws -> Bool {
            guard depth < 32 else { throw Failure(errorDescription: "reference depth") }
            switch kind {
            case .domain, .domainSuffix, .domainKeyword, .domainWildcard:
                var named = target; named.host = name
                return kind.matches(named)
            case .logicalAnd(let children):
                return try children.allSatisfy { try matches($0, depth: depth + 1, visited: visited) }
            case .logicalOr(let children):
                return try children.contains { try matches($0, depth: depth + 1, visited: visited) }
            case .logicalNot(let child): return try !matches(child, depth: depth + 1, visited: visited)
            case .ruleSet(let reference):
                guard !visited.contains(reference.location) else { throw Failure(errorDescription: "reference cycle") }
                var next = visited; next.insert(reference.location)
                return try profile.ruleSetContents[reference.location]?.contains {
                    try matches($0, depth: depth + 1, visited: next)
                } ?? false
            default: return kind.matches(target)
            }
        }
        do {
            for (index, rule) in profile.rules.enumerated() where try matches(rule.kind) { return .matched(index) }
            return .noMatch
        } catch { return .invalid }
    }

    public static func run() throws {
        var comparisons = 0
        func check(_ profile: Profile, _ target: RequestTarget, alternate: String? = nil,
                   requireNative: Bool = true) throws {
            let expected = profile.interpretedRuleIndex(for: target, alternateHost: alternate)
                .map(CompiledRuleSelection.matched) ?? .noMatch
            let ordinary = profile.compiledRuleSelection(for: target, alternateHost: alternate)
            if requireNative { try expect(ordinary != .fallback, "ASCII 规则未使用编译程序") }
            if ordinary != .fallback { try expect(ordinary == expected, "普通规则结果或优先级改变") }
            let reference = expected.mapIndex { profile.rules[$0].policy }
            let expectedRoute = reference.map {
                profile.resolveRoutingPolicy($0, target: target, groupSelections: [:])
            } ?? .direct("DIRECT")
            try expect(profile.route(for: target, mode: .rule, globalPolicy: "DIRECT",
                                     alternateHost: alternate) == expectedRoute, "实际路由未保留解释器结果")
            let name = alternate ?? target.host
            let dns = profile.compiledRuleSelection(for: target, alternateHost: name, dnsSemantics: true)
            if requireNative { try expect(dns != .fallback, "ASCII DNS 规则未使用编译程序") }
            if dns != .fallback {
                try expect(dns == dnsReference(profile, target: target, name: name), "DNS QNAME/来源/递归语义改变")
            }
            comparisons += 2
        }

        let ref = RuleSetReference(location: "memory.primary")
        let nested = RuleSetReference(location: "memory.nested")
        let kinds: [RuleKind] = [.domain("exact.test"), .domainSuffix("suffix.test"),
            .domainKeyword("needle"), .domainWildcard("a*?.wild.test"), .ipCIDR("10.4.0.0/16"),
            .ipCIDR("2001:db8::/32"), .sourceIPCIDR("192.0.2.0/24"),
            .destinationPort(443...444), .sourcePort(0...0), .inboundPort(7262...7263),
            .protocolName("uDp"), .logicalAnd([.domainSuffix("logic.test"), .destinationPort(53...53)]),
            .logicalOr([.sourcePort(45000...45000), .domain("or.test")]),
            .logicalNot(.logicalOr([.domainSuffix("skip.test"), .destinationPort(53...443)])),
            .geoIP("CN"), .ipASN("123"), .processName("app"), .ruleSet(ref), .final]
        let bodies: [String: [RuleKind]] = [ref.location: [.domain("cached.test"),
            .logicalAnd([.domain("logical-cached.test"), .destinationPort(53...53)]), .ruleSet(nested)],
            nested.location: [.domain("nested.test")]]
        let targets = ["..EXACT.TEST..", "x.suffix.test.", "not-suffix.test", "a-needle.test",
                       "ab.wild.test", "aZZq.wild.test", "10.4.8.1", "10.5.1.1", "2001:DB8::8%en1",
                       "192.0.2.1", "cached.test", "logical-cached.test", "nested.test", "or.test", "other.test"]
        for kind in kinds {
            let profile = fixture([kind, .final], contents: bodies)
            for host in targets {
                for port: UInt16 in [0, 53, 443, 445] {
                    let target = RequestTarget(host: host, port: port, protocolName: port == 53 ? "udp" : "TCP",
                        sourceHost: port == 0 ? nil : "192.0.2.9", sourcePort: port == 443 ? nil : 0,
                        inboundPort: port == 445 ? 7262 : nil)
                    try check(profile, target)
                    try check(profile, target, alternate: "logical-cached.test")
                }
            }
        }
        // Empty rules and the distinction between absent and zero metadata.
        for kind: RuleKind in [.domain(""), .domainSuffix(""), .domainKeyword(""),
            .domainWildcard("*"), .logicalAnd([]), .logicalOr([]), .logicalNot(.logicalAnd([]))] {
            for host in ["", "...", "x.test"] {
                try check(fixture([kind, .final]), .init(host: host, port: 0, protocolName: "TCP"))
            }
        }
        for cidr in ["0.0.0.0/0", "128.0.0.0/1", "203.0.113.0/31", "203.0.113.1/32",
                     "::/0", "2001:db8::/127", "2001:db8::1/128", "2001:db8::/+128",
                     "2001:db8::/-0", "/2001:db8::/32", "2001:db8::%en0/32"] {
            for host in ["203.0.113.0", ".203.0.113.1.", "203.0.113.2", "2001:DB8::1%en1",
                         "2001:db8::2", "%%2001:db8::1%en1"] {
                try check(fixture([.ipCIDR(cidr), .sourceIPCIDR(cidr), .final]),
                          .init(host: host, port: 53, protocolName: "UDP", sourceHost: host))
            }
        }
        // Mixed indexed and evaluated roots must retain original order.
        let mixed = fixture(kinds, contents: bodies)
        for host in targets {
            try check(mixed, .init(host: host, port: 53, protocolName: "UDP", sourceHost: "192.0.2.10",
                                   sourcePort: 45000, inboundPort: 7263), alternate: "exact.test")
        }
        let cycle = RuleSetReference(location: "memory.cycle")
        for body: [RuleKind] in [[.ruleSet(cycle)], [.domain("safe.test"), .ruleSet(cycle)],
            [.logicalAnd([.domain("no.test"), .ruleSet(cycle)])],
            [.logicalOr([.domain("safe.test"), .ruleSet(cycle)])]] {
            for host in ["safe.test", "other.test"] {
                try check(fixture([.ruleSet(cycle), .final], contents: [cycle.location: body]),
                          .init(host: host, port: 53, protocolName: "UDP"))
            }
        }
        var deep: RuleKind = .domain("deep.test")
        for depth in 0..<40 {
            deep = .logicalNot(deep)
            if depth >= 28 {
                try check(fixture([deep, .final]), .init(host: "deep.test", port: 53, protocolName: "UDP"))
            }
        }
        // Swift identifiers compare canonical equivalents; program keys must too.
        let equivalent = RuleSetReference(location: "memory.caf\u{e9}")
        try check(fixture([.ruleSet(equivalent), .final],
                          contents: ["memory.cafe\u{301}": [.domain("unicode-key.test")]]),
                  .init(host: "unicode-key.test", port: 443, protocolName: "TCP"))
        for host in ["caf\u{e9}.test", "cafe\u{301}.test", "a\u{0}.test", "a\u{7f}.test"] {
            try check(fixture([.domainKeyword("a"), .final]),
                      .init(host: host, port: 443, protocolName: "TCP"), requireNative: false)
            try check(fixture([.domainSuffix("caf\u{e9}.test"), .final]),
                      .init(host: host, port: 443, protocolName: "TCP"), requireNative: false)
        }
        try valueAndConcurrencyChecks()
        print("Compiled routing checks passed: \(comparisons) ordinary/DNS comparisons, priority, QNAME/source isolation, CIDR/glob boundaries, cycles, Unicode fallback, value copies and concurrent readers")
    }

    private static func valueAndConcurrencyChecks() throws {
        let ref = RuleSetReference(location: "memory.value")
        let original = fixture([.ruleSet(ref), .final], contents: [ref.location: [.domain("old.test")]])
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        let before = try encoder.encode(original)
        let program = original.preparedCompiledRoutingProgram
        try expect(program != nil, "缓存准备未建立程序")
        var copy = original
        try expect(copy.preparedCompiledRoutingProgram === program, "值复制未共享不可变程序")
        copy.ruleSetContents[ref.location] = [.domain("new.test")]
        try expect(copy.preparedCompiledRoutingProgram !== program, "规则体修改未失效程序")
        let target = RequestTarget(host: "old.test", port: 443, protocolName: "TCP")
        try expect(original.compiledRuleSelection(for: target) == .matched(0)
            && copy.compiledRuleSelection(for: target) == .matched(1), "副本修改污染旧快照")
        copy = original
        copy.rules[0].kind = .domain("new.test")
        try expect(copy.preparedCompiledRoutingProgram !== program
            && original.preparedCompiledRoutingProgram === program, "主规则修改污染共享缓存")
        let decoded = try JSONDecoder().decode(Profile.self, from: before)
        try expect(decoded == original && original == fixture([.ruleSet(ref), .final],
            contents: [ref.location: [.domain("old.test")]]) && (try encoder.encode(original)) == before,
            "准备状态改变配置相等性或编码")
        let lock = NSLock()
        var failed = false
        DispatchQueue.concurrentPerform(iterations: 128) { index in
            let chosen = index.isMultiple(of: 2) ? original : copy
            let expected: CompiledRuleSelection = index.isMultiple(of: 2) ? .matched(0) : .matched(1)
            if chosen.compiledRuleSelection(for: target) != expected {
                lock.lock(); failed = true; lock.unlock()
            }
        }
        try expect(!failed, "并发读取互相修改匹配状态")
    }

    public static func benchmark() throws {
        let domainCount = 50_000, cidrCount = 8_192
        let ref = RuleSetReference(location: "memory.benchmark")
        var body = (0..<domainCount).map { RuleKind.domainSuffix("r\($0).bench.test") }
        body += (0..<cidrCount).map { .ipCIDR("10.\($0 / 256).\($0 % 256).0/24") }
        let profile = fixture([.ruleSet(ref), .final], contents: [ref.location: body])
        let started = DispatchTime.now().uptimeNanoseconds
        profile.prepareCompiledRoutingRules()
        let built = DispatchTime.now().uptimeNanoseconds
        var targets = (0..<128).map { RequestTarget(host: "x.r\(domainCount - 1 - $0).bench.test",
                                                   port: 443, protocolName: "TCP") }
        targets += (0..<32).map { RequestTarget(host: "10.31.\(255 - $0).8", port: 443, protocolName: "TCP") }
        targets += (0..<32).map { RequestTarget(host: "unmatched\($0).test", port: 443, protocolName: "TCP") }
        for target in targets {
            try expect(profile.compiledRuleSelection(for: target) != .fallback, "基准未执行编译程序")
        }
        let nativeStart = DispatchTime.now().uptimeNanoseconds
        let actual = targets.map { profile.compiledRuleSelection(for: $0) }
        let nativeEnd = DispatchTime.now().uptimeNanoseconds
        let expected = targets.map { profile.interpretedRuleIndex(for: $0).map(CompiledRuleSelection.matched) ?? .noMatch }
        let referenceEnd = DispatchTime.now().uptimeNanoseconds
        try expect(actual == expected, "大规则集基准不等价")
        func ms(_ duration: UInt64) -> String { String(format: "%.3f", Double(duration) / 1_000_000) }
        print("Synthetic rule benchmark: \(domainCount + cidrCount) rule-set entries / \(targets.count) uncached decisions; compile=\(ms(built - started))ms; compiled=\(ms(nativeEnd - nativeStart))ms; interpreter=\(ms(referenceEnd - nativeEnd))ms")
    }
}

private extension CompiledRuleSelection {
    func mapIndex<Result>(_ body: (Int) -> Result) -> Result? {
        if case .matched(let index) = self { return body(index) }
        return nil
    }
}

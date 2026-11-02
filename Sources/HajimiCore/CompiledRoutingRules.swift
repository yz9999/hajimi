import Foundation
import HajimiRouting
import HajimiRoutingCXX

typealias CompiledRuleSelection = RoutingRuleSelection

/// A transient implementation cache, excluded from Profile's encoded keys.
/// Equality deliberately ignores preparation state. Mutating either rule
/// collection replaces this storage, so old value snapshots remain valid.
final class CompiledRoutingRuleStorage: Equatable {
    private let lock = NSLock()
    private var prepared = false
    private var cached: NativeCompiledRuleProgram?

    static func == (_ lhs: CompiledRoutingRuleStorage,
                    _ rhs: CompiledRoutingRuleStorage) -> Bool { true }

    func program(for profile: Profile) -> NativeCompiledRuleProgram? {
        lock.lock(); defer { lock.unlock() }
        if !prepared {
            cached = NativeCompiledRuleProgram(profile: profile)
            prepared = true
        }
        return cached
    }
}

/// Owns one immutable C++ program. All byte spans stay borrowed for the full
/// synchronous call; C++ retains neither the request nor its source strings.
final class NativeCompiledRuleProgram {
    private let handle: OpaquePointer
    private let ruleCount: Int

    init?(profile: Profile) {
        guard Int32(exactly: profile.rules.count) != nil,
              let handle = hajimi_rules_create() else { return nil }
        var complete = false
        defer { if !complete { hajimi_rules_destroy(handle) } }

        func add(_ rule: RuleKind, depth: Int = 0) -> Int32? {
            // Leave unusual programmatically constructed deep trees to the
            // reference matcher; DNS keeps its existing depth-32 authority.
            guard depth < 256 else { return nil }
            let kind: Int32
            var text = ""
            var children: [Int32] = []
            var lower: UInt16 = 0, upper: UInt16 = 0
            switch rule {
            case .domain(let value): kind = Int32(HJ_RULE_DOMAIN); text = value
            case .domainSuffix(let value): kind = Int32(HJ_RULE_SUFFIX); text = value
            case .domainKeyword(let value): kind = Int32(HJ_RULE_KEYWORD); text = value
            case .domainWildcard(let value): kind = Int32(HJ_RULE_WILDCARD); text = value
            case .ipCIDR(let value): kind = Int32(HJ_RULE_IP_CIDR); text = value
            case .sourceIPCIDR(let value): kind = Int32(HJ_RULE_SOURCE_CIDR); text = value
            case .destinationPort(let range):
                kind = Int32(HJ_RULE_DESTINATION_PORT); lower = range.lowerBound; upper = range.upperBound
            case .sourcePort(let range):
                kind = Int32(HJ_RULE_SOURCE_PORT); lower = range.lowerBound; upper = range.upperBound
            case .inboundPort(let range):
                kind = Int32(HJ_RULE_INBOUND_PORT); lower = range.lowerBound; upper = range.upperBound
            case .protocolName(let value): kind = Int32(HJ_RULE_PROTOCOL); text = value
            case .geoIP, .ipASN, .processName: kind = Int32(HJ_RULE_NEVER)
            case .logicalAnd(let values), .logicalOr(let values):
                if case .logicalAnd = rule { kind = Int32(HJ_RULE_AND) }
                else { kind = Int32(HJ_RULE_OR) }
                for value in values {
                    guard let child = add(value, depth: depth + 1) else { return nil }
                    children.append(child)
                }
            case .logicalNot(let value):
                kind = Int32(HJ_RULE_NOT)
                guard let child = add(value, depth: depth + 1) else { return nil }
                children = [child]
            case .ruleSet(let reference):
                kind = Int32(HJ_RULE_SET)
                // Swift String keys compare canonical Unicode equivalents.
                text = reference.location.precomposedStringWithCanonicalMapping
            case .final: kind = Int32(HJ_RULE_FINAL)
            }
            let node = withSpan(text) { span in
                children.withUnsafeBufferPointer {
                    hajimi_rules_add_node(handle, kind, span.bytes, span.length,
                                          $0.baseAddress, $0.count, lower, upper)
                }
            }
            return node >= 0 ? node : nil
        }

        for location in profile.ruleSetContents.keys.sorted() {
            var children: [Int32] = []
            for rule in profile.ruleSetContents[location] ?? [] {
                guard let node = add(rule) else { return nil }
                children.append(node)
            }
            let accepted = withSpan(location.precomposedStringWithCanonicalMapping) { span in
                children.withUnsafeBufferPointer {
                    hajimi_rules_set_rule_set(handle, span.bytes, span.length,
                                              $0.baseAddress, $0.count)
                }
            }
            guard accepted == 1 else { return nil }
        }
        for (index, rule) in profile.rules.enumerated() {
            guard let node = add(rule.kind),
                  hajimi_rules_add_root(handle, node, Int32(index)) == 1 else { return nil }
        }
        guard hajimi_rules_finalize(handle) == 1 else { return nil }
        self.handle = handle
        ruleCount = profile.rules.count
        complete = true
    }

    deinit { hajimi_rules_destroy(handle) }

    func match(_ target: RequestTarget, alternateHost: String? = nil,
               dnsSemantics: Bool = false) -> CompiledRuleSelection {
        withSpan(target.host) { host in
            withSpan(target.protocolName) { proto in
                withSpan(target.sourceHost ?? "") { source in
                    withSpan(alternateHost ?? "") { alternate in
                        var input = HJRuleMatchInput()
                        input.host = host; input.protocol_name = proto; input.source_host = source
                        input.destination_port = target.port
                        input.source_port = target.sourcePort ?? 0
                        input.inbound_port = target.inboundPort ?? 0
                        input.mode = dnsSemantics ? Int32(HJ_RULE_MODE_DNS) : Int32(HJ_RULE_MODE_ORDINARY)
                        if target.sourceHost != nil { input.flags |= UInt32(HJ_RULE_HAS_SOURCE_HOST) }
                        if target.sourcePort != nil { input.flags |= UInt32(HJ_RULE_HAS_SOURCE_PORT) }
                        if target.inboundPort != nil { input.flags |= UInt32(HJ_RULE_HAS_INBOUND_PORT) }
                        if dnsSemantics {
                            input.dns_name = alternate
                            if alternateHost != nil { input.flags |= UInt32(HJ_RULE_HAS_DNS_NAME) }
                        } else {
                            input.alternate_host = alternate
                            if alternateHost != nil { input.flags |= UInt32(HJ_RULE_HAS_ALTERNATE_HOST) }
                        }
                        let result = hajimi_rules_match(handle, &input)
                        switch result {
                        case Int32(HJ_RULE_NO_MATCH): return .noMatch
                        case Int32(HJ_RULE_DNS_RECURSION_ERROR): return .invalid
                        case 0... where Int(result) < ruleCount: return .matched(Int(result))
                        default: return .fallback
                        }
                    }
                }
            }
        }
    }
}

@inline(__always)
private func withSpan<Result>(_ value: String, _ body: (HJRuleByteSpan) -> Result) -> Result {
    var contiguous = value
    return contiguous.withUTF8 { body(HJRuleByteSpan(bytes: $0.baseAddress, length: $0.count)) }
}

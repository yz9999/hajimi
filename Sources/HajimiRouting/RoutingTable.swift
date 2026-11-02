import Foundation

/// An immutable, value-only view of one owner's routing configuration.
/// It cannot read profiles, resolve addresses, retain native programs, open
/// transports or publish a route cache entry for a newer owner generation.
public struct RoutingTable: Equatable {
    public let rules: [RoutingRule]
    public let ruleSetContents: [String: [RuleKind]]
    public let proxies: [String: ProxyPolicy]
    public let groups: [String: PolicyGroup]

    public init(rules: [RoutingRule], ruleSetContents: [String: [RuleKind]],
                proxies: [String: ProxyPolicy], groups: [String: PolicyGroup]) {
        self.rules = rules
        self.ruleSetContents = ruleSetContents
        self.proxies = proxies
        self.groups = groups
    }

    public func route(for target: RequestTarget, mode: OutboundMode, globalPolicy: String,
                      groupSelections: [String: String] = [:], alternateHost: String? = nil) -> ResolvedRoute {
        route(for: target, mode: mode, globalPolicy: globalPolicy,
              groupSelections: groupSelections, alternateHost: alternateHost,
              compiledSelection: .fallback, domainMatcher: nil)
    }

    /// Core supplies only a completed result and a synchronous optional leaf
    /// matcher. No C++ handle, owner, transport or escaping closure is stored.
    package func route(for target: RequestTarget, mode: OutboundMode, globalPolicy: String,
                       groupSelections: [String: String], alternateHost: String?,
                       compiledSelection: RoutingRuleSelection,
                       domainMatcher: RoutingDomainMatcher?) -> ResolvedRoute {
        switch mode {
        case .direct:
            return .direct("DIRECT")
        case .proxy:
            return resolvePolicy(globalPolicy, target: target,
                                 groupSelections: groupSelections, visited: [])
        case .rule:
            switch compiledSelection {
            case .matched(let index) where rules.indices.contains(index):
                return resolvePolicy(rules[index].policy, target: target,
                                     groupSelections: groupSelections, visited: [])
            case .noMatch: return .direct("DIRECT")
            case .matched, .fallback, .invalid: break
            }
            for rule in rules {
                guard RoutingRuleMatcher.matches(rule, target: target, alternateHost: alternateHost,
                                                  ruleSetContents: ruleSetContents,
                                                  domainMatcher: domainMatcher) else { continue }
                return resolvePolicy(rule.policy, target: target,
                                     groupSelections: groupSelections, visited: [])
            }
            return .direct("DIRECT")
        }
    }

    public func interpretedRuleIndex(for target: RequestTarget, alternateHost: String? = nil) -> Int? {
        interpretedRuleIndex(for: target, alternateHost: alternateHost, domainMatcher: nil)
    }

    package func interpretedRuleIndex(for target: RequestTarget, alternateHost: String?,
                                      domainMatcher: RoutingDomainMatcher?) -> Int? {
        rules.firstIndex {
            RoutingRuleMatcher.matches($0, target: target, alternateHost: alternateHost,
                                       ruleSetContents: ruleSetContents, domainMatcher: domainMatcher)
        }
    }

    public func resolvePolicy(_ policy: String, target: RequestTarget,
                              groupSelections: [String: String] = [:]) -> ResolvedRoute {
        resolvePolicy(policy, target: target, groupSelections: groupSelections, visited: [])
    }

    private func resolvePolicy(_ rawName: String, target: RequestTarget,
                               groupSelections: [String: String],
                               visited: Set<String>) -> ResolvedRoute {
        let name = canonicalName(rawName)
        if visited.contains(name) { return .reject("Policy loop: \(name)") }

        if let group = groups[name] {
            var next: String?
            if let selected = groupSelections[name], group.members.contains(selected) {
                next = Self.extractSubnetTargetPolicy(selected)
            } else if group.kind == .subnet, !group.members.isEmpty {
                next = resolveSubnetMember(group: group, sourceHost: target.sourceHost)
            } else if group.kind == .loadBalance, !group.members.isEmpty {
                let useJump = group.parameters["strategy"]?.lowercased() == "jump"
                let idx = useJump
                    ? jumpConsistentIndex(for: target, count: group.members.count)
                    : stableIndex(for: target, count: group.members.count)
                next = group.members[idx]
            } else if group.kind == .smart, !group.members.isEmpty {
                next = resolveSmartMember(group: group)
            } else {
                next = group.members.first
            }
            guard let member = next else { return .reject("Empty group: \(name)") }
            var newVisited = visited
            newVisited.insert(name)
            return resolvePolicy(member, target: target,
                                 groupSelections: groupSelections, visited: newVisited)
        }

        guard let proxy = proxies[name] else { return .reject("Unknown: \(rawName)") }
        switch proxy.kind {
        case .direct: return .direct(proxy.name)
        case .reject: return .reject(proxy.name)
        case .http: return .http(proxy, proxy.name)
        case .socks5: return .socks5(proxy, proxy.name)
        case .native:
            // Promotion changes the implementation, not the wire semantics.
            // Preserve HTTP absolute-form forwarding and TLS-only UDP policy
            // for HTTP/SOCKS nodes which use a C++-backed proxy chain.
            switch proxy.adapterType?.lowercased() {
            case "http", "https": return .http(proxy, proxy.name)
            case "socks5", "socks5-tls": return .socks5(proxy, proxy.name)
            default: break
            }
            return .native(proxy, proxy.name)
        case .external: return .reject("Adapter not running: \(proxy.name)")
        }
    }

    private static func extractSubnetTargetPolicy(_ rawMember: String) -> String {
        guard let eq = rawMember.firstIndex(of: "=") else {
            return rawMember.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let rhs = rawMember[rawMember.index(after: eq)...].trimmingCharacters(in: .whitespacesAndNewlines)
        return rhs.isEmpty ? rawMember.trimmingCharacters(in: .whitespacesAndNewlines) : rhs
    }

    private func resolveSubnetMember(group: PolicyGroup, sourceHost: String?) -> String? {
        var fallbackPolicy: String? = group.parameters["default"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        var firstCandidate: String?
        for raw in group.members {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            if let eq = trimmed.firstIndex(of: "=") {
                let condition = trimmed[..<eq].trimmingCharacters(in: .whitespacesAndNewlines)
                let policy = trimmed[trimmed.index(after: eq)...].trimmingCharacters(in: .whitespacesAndNewlines)
                guard !policy.isEmpty else { continue }
                if firstCandidate == nil { firstCandidate = policy }
                if condition.caseInsensitiveCompare("default") == .orderedSame {
                    fallbackPolicy = policy
                    continue
                }
                if let sourceHost, !sourceHost.isEmpty {
                    let cidr = condition.contains("/") ? condition : (condition.contains(":") ? "\(condition)/128" : "\(condition)/32")
                    if IPCIDR.contains(sourceHost, cidr: cidr) {
                        return policy
                    }
                }
            } else {
                if firstCandidate == nil { firstCandidate = trimmed }
            }
        }
        return fallbackPolicy ?? firstCandidate ?? group.members.first
    }

    private func resolveSmartMember(group: PolicyGroup) -> String? {
        guard let prioritySpec = group.parameters["policy-priority"], !prioritySpec.isEmpty else {
            return group.members.first
        }
        var weights: [String: Double] = [:]
        for item in prioritySpec.split(whereSeparator: { $0 == ";" || $0 == "," }) {
            let pair = item.split(separator: ":", maxSplits: 1)
            guard pair.count == 2 else { continue }
            let key = pair[0].trimmingCharacters(in: .whitespacesAndNewlines)
            if let factor = Double(pair[1].trimmingCharacters(in: .whitespacesAndNewlines)),
               factor.isFinite, factor > 0 {
                weights[key] = factor
            }
        }
        guard !weights.isEmpty else { return group.members.first }
        return group.members.min { lhs, rhs in
            let w1 = weights[lhs] ?? 1.0
            let w2 = weights[rhs] ?? 1.0
            return w1 > w2
        } ?? group.members.first
    }

    private func canonicalName(_ name: String) -> String {
        if proxies[name] != nil || groups[name] != nil { return name }
        if name.uppercased() == "DIRECT" { return "DIRECT" }
        if name.uppercased().hasPrefix("REJECT") { return "REJECT" }
        return name
    }

    private func fnv1aKeyHash(for target: RequestTarget) -> UInt64 {
        var hash: UInt64 = 14_695_981_039_346_656_037
        let prime: UInt64 = 1_099_511_628_211
        let isAsciiHost = target.host.utf8.allSatisfy { $0 < 0x80 }
        if isAsciiHost {
            for byte in target.host.utf8 {
                let lower = (byte >= 65 && byte <= 90) ? (byte &+ 32) : byte
                hash = (hash ^ UInt64(lower)) &* prime
            }
        } else {
            for byte in target.host.lowercased().utf8 {
                hash = (hash ^ UInt64(byte)) &* prime
            }
        }
        hash = (hash ^ 58) &* prime // ':'
        var portVal = target.port
        if portVal == 0 {
            hash = (hash ^ 48) &* prime
        } else {
            var digits: (UInt8, UInt8, UInt8, UInt8, UInt8) = (0, 0, 0, 0, 0)
            var len = 0
            withUnsafeMutableBytes(of: &digits) { buf in
                while portVal > 0 {
                    buf[len] = UInt8(48 + (portVal % 10))
                    portVal /= 10
                    len += 1
                }
                while len > 0 {
                    len -= 1
                    hash = (hash ^ UInt64(buf[len])) &* prime
                }
            }
        }
        hash = (hash ^ 47) &* prime // '/'
        for byte in target.protocolName.utf8 {
            hash = (hash ^ UInt64(byte)) &* prime
        }
        return hash
    }

    private func stableIndex(for target: RequestTarget, count: Int) -> Int {
        guard count > 1 else { return 0 }
        return Int(fnv1aKeyHash(for: target) % UInt64(count))
    }

    /// Stafford Mix13 GF(2^64) bijection + Google Jump Consistent Hash (Lamping & Veach):
    /// O(ln N) time, O(1) memory, and minimal 1/(N+1) flow remapping when pool size changes.
    private func jumpConsistentIndex(for target: RequestTarget, count: Int) -> Int {
        guard count > 1 else { return 0 }
        var z = fnv1aKeyHash(for: target)
        z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
        z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
        var key = z ^ (z >> 31)
        var b: Int64 = -1
        var j: Int64 = 0
        let buckets = Int64(count)
        while j < buckets {
            b = j
            key = key &* 2862933555777941757 &+ 1
            j = Int64(Double(b + 1) * (Double(1 << 31) / Double((key >> 33) + 1)))
        }
        return Int(max(0, b))
    }
}

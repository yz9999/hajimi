import Foundation
import Darwin

public struct ListenAddress: Equatable, Codable {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    /// Only numeric loopback addresses are safe for an unauthenticated
    /// controller. A hostname (even `localhost`) might resolve elsewhere.
    var isLoopback: Bool {
        var ipv4 = in_addr()
        if inet_pton(AF_INET, host, &ipv4) == 1 {
            return UInt32(bigEndian: ipv4.s_addr) >> 24 == 127
        }
        var ipv6 = in6_addr()
        guard inet_pton(AF_INET6, host, &ipv6) == 1 else { return false }
        return withUnsafeBytes(of: &ipv6) { bytes in
            bytes.prefix(15).allSatisfy { $0 == 0 } && bytes[15] == 1
        }
    }
}

public enum ProxyKind: String, Equatable, Codable {
    case direct
    case reject
    case http
    case socks5
    /// Prepared in-process C++ proxy protocol implementation.
    /// Parsed profiles use `.external`; the runtime adapter manager promotes
    /// only configurations which the native implementation can fully handle.
    case native
    case external
}

public struct ProxyPolicy: Equatable, Codable {
    public var name: String
    public var kind: ProxyKind
    public var host: String?
    public var port: UInt16?
    public var username: String?
    public var password: String?
    public var adapterType: String?
    public var parameters: [String: String]

    public init(name: String, kind: ProxyKind, host: String? = nil, port: UInt16? = nil,
                username: String? = nil, password: String? = nil,
                adapterType: String? = nil, parameters: [String: String] = [:]) {
        self.name = name
        self.kind = kind
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.adapterType = adapterType
        self.parameters = parameters
    }

    /// True when this node will accept any presented server certificate.
    public var skipsCertificateVerification: Bool {
        Self.isTruthy(parameters["skip-cert-verify"])
            || Self.isTruthy(parameters["skip-common-name-verify"])
    }

    private static func isTruthy(_ value: String?) -> Bool {
        guard let value else { return false }
        return ["true", "yes", "on", "1"].contains(value.lowercased())
    }
}

public enum PolicyGroupKind: String, Equatable, Codable {
    case select
    case loadBalance
    case urlTest
    case fallback
    /// Surge `smart`: latency-ranked like url-test, with a richer scorer
    /// that Hajimi does not yet reproduce. Health checks still drive it.
    case smart
    /// Surge `subnet`: pick by source network. Until a source-subnet table
    /// is wired, routing treats it as a select group.
    case subnet
}

public struct PolicyGroup: Equatable, Codable {
    public var name: String
    public var kind: PolicyGroupKind
    public var members: [String]
    public var parameters: [String: String]

    public init(name: String, kind: PolicyGroupKind = .select, members: [String],
                parameters: [String: String] = [:]) {
        self.name = name
        self.kind = kind
        self.members = members
        self.parameters = parameters
    }
}

public struct RuleSetReference: Equatable, Hashable, Codable {
    public var location: String
    public var updateInterval: TimeInterval

    public init(location: String, updateInterval: TimeInterval = 86_400) {
        self.location = location
        self.updateInterval = updateInterval
    }
}

public indirect enum RuleKind: Equatable, Codable {
    case domain(String)
    case domainSuffix(String)
    case domainKeyword(String)
    case domainWildcard(String)
    case ipCIDR(String)
    case destinationPort(ClosedRange<UInt16>)
    case sourceIPCIDR(String)
    case sourcePort(ClosedRange<UInt16>)
    case inboundPort(ClosedRange<UInt16>)
    case protocolName(String)
    case geoIP(String)
    case ipASN(String)
    case processName(String)
    case logicalAnd([RuleKind])
    case logicalOr([RuleKind])
    case logicalNot(RuleKind)
    case ruleSet(RuleSetReference)
    case final
}

public struct RoutingRule: Equatable, Codable {
    public var kind: RuleKind
    public var policy: String
    public var sourceLine: Int

    public init(kind: RuleKind, policy: String, sourceLine: Int) {
        self.kind = kind
        self.policy = policy
        self.sourceLine = sourceLine
    }
}

public struct RequestTarget: Equatable, Codable {
    public var host: String
    public var port: UInt16
    public var protocolName: String
    /// Client address when the data plane can see it (HTTP/SOCKS peer or
    /// utun inner source). SRC-IP rules stay inert without this.
    public var sourceHost: String?
    public var sourcePort: UInt16?
    /// Listener port that accepted the connection. TUN flows leave this nil.
    public var inboundPort: UInt16?

    public init(host: String, port: UInt16, protocolName: String,
                sourceHost: String? = nil, sourcePort: UInt16? = nil,
                inboundPort: UInt16? = nil) {
        self.host = host
        self.port = port
        self.protocolName = protocolName.uppercased()
        self.sourceHost = sourceHost
        self.sourcePort = sourcePort
        self.inboundPort = inboundPort
    }
}

/// Shared copy for skip-cert-verify so the profile parser, subscription
/// importer and UI never drift apart.
public enum SkipCertificateWarning {
    public static let headline = "跳过服务器证书验证会失去身份认证，中间人可窃听或改写流量"

    public static func message(names: [String]) -> String {
        let unique = uniqueNames(names)
        guard !unique.isEmpty else { return headline }
        if unique.count == 1 {
            return "节点 \(unique[0]) 已跳过服务器证书验证：失去身份认证，中间人可窃听或改写流量"
        }
        if unique.count <= 3 {
            return "\(unique.count) 个节点已跳过服务器证书验证（\(unique.joined(separator: "、"))）：失去身份认证，中间人可窃听或改写流量"
        }
        return "\(unique.count) 个节点已跳过服务器证书验证（\(unique.prefix(3).joined(separator: "、")) 等）：失去身份认证，中间人可窃听或改写流量"
    }

    public static func append(names: [String], into warnings: inout [String]) {
        let unique = uniqueNames(names)
        guard !unique.isEmpty else { return }
        warnings.append(message(names: unique))
    }

    public static func lineDisablesVerification(_ line: String) -> Bool {
        let lower = line.lowercased()
        return containsTruthy(key: "skip-cert-verify", in: lower)
            || containsTruthy(key: "skip-common-name-verify", in: lower)
    }

    private static func uniqueNames(_ names: [String]) -> [String] {
        var seen = Set<String>()
        return names.filter { seen.insert($0).inserted }
    }

    private static func containsTruthy(key: String, in line: String) -> Bool {
        guard let range = line.range(of: key + "=") else { return false }
        let rest = line[range.upperBound...]
        let value = rest.prefix(while: { $0 != "," && $0 != " " && $0 != "\t" })
        return ["true", "yes", "on", "1"].contains(String(value))
    }
}

public enum OutboundMode: String, CaseIterable, Codable {
    case rule
    case direct
    case proxy

    public var displayName: String {
        switch self {
        case .rule: return "规则"
        case .direct: return "直连"
        case .proxy: return "全局代理"
        }
    }
}

public enum ResolvedRoute: Equatable {
    case direct(String)
    case reject(String)
    case http(ProxyPolicy, String)
    case socks5(ProxyPolicy, String)
    case native(ProxyPolicy, String)

    public var policyName: String {
        switch self {
        case .direct(let name), .reject(let name), .http(_, let name),
             .socks5(_, let name), .native(_, let name):
            return name
        }
    }
}

public struct Profile: Equatable, Codable {
    public var httpListen = ListenAddress(host: "127.0.0.1", port: 7262)
    public var socksListen = ListenAddress(host: "127.0.0.1", port: 7263)
    public var proxies: [String: ProxyPolicy] = [
        "DIRECT": ProxyPolicy(name: "DIRECT", kind: .direct),
        "REJECT": ProxyPolicy(name: "REJECT", kind: .reject)
    ]
    public var proxyOrder: [String] = []
    public var groups: [String: PolicyGroup] = [:]
    public var groupOrder: [String] = []
    public var rules: [RoutingRule] = []
    public var ruleSetContents: [String: [RuleKind]] = [:]
    public var proxyBypassDomains: [String] = []
    public var dnsServers: [String] = []
    /// Answer proxied lookups from a synthetic pool instead of trusting the
    /// local resolver. Off by default: it changes what every application sees
    /// for a hostname, which is not something to enable behind the user's back.
    public var fakeIPEnabled = false
    /// Surge `always-real-ip` / `fake-ip-filter`: names that must keep a
    /// real A record even when fake-IP is on.
    public var alwaysRealIP: [String] = []
    /// Surge `hijack-dns`. Non-empty means Enhanced Mode should steal
    /// system DNS the same way `fake-ip=true` does.
    public var hijackDNS: [String] = []
    /// Surge `http-api = key@host:port`.
    public var httpAPI: ListenAddress?
    public var httpAPIKey: String?
    /// Surge `external-controller-access = key@host:port`.
    public var externalController: ListenAddress?
    public var externalControllerKey: String?
    /// CIDRs that must stay on the physical gateway in Enhanced Mode.
    public var tunExcludedRoutes: [String] = []
    public var tunIncludedRoutes: [String] = []
    public var includeAllNetworks = false
    public var warnings: [String] = []
    public var surgeCompatible = false

    /// Helper should redirect system resolvers at the tunnel DNS sink.
    public var shouldHijackSystemDNS: Bool {
        fakeIPEnabled || !hijackDNS.isEmpty
    }

    public func skipsFakeIP(for domain: String) -> Bool {
        DomainPattern.any(alwaysRealIP, matches: domain)
    }

    public init() {}

    public var selectablePolicies: [String] {
        let visibleGroups = groupOrder.filter { name in
            guard let value = groups[name]?.parameters["hidden"]?.lowercased() else { return true }
            return !["true", "yes", "on", "1"].contains(value)
        }
        var result = visibleGroups + proxyOrder
        if !result.contains("DIRECT") { result.append("DIRECT") }
        return result
    }

    public var adapterPolicies: [ProxyPolicy] {
        proxyOrder.compactMap { name in
            guard let policy = proxies[name], policy.kind == .external else { return nil }
            return policy
        }
    }

    /// Proxy names that disable TLS identity checks, in profile order.
    public var proxiesSkippingCertificateVerification: [String] {
        proxyOrder.filter { proxies[$0]?.skipsCertificateVerification == true }
    }

    public var ruleSetReferences: [RuleSetReference] {
        rules.compactMap {
            guard case .ruleSet(let reference) = $0.kind else { return nil }
            return reference
        }
    }

    public func route(for target: RequestTarget, mode: OutboundMode, globalPolicy: String,
                      groupSelections: [String: String] = [:], alternateHost: String? = nil) -> ResolvedRoute {
        switch mode {
        case .direct:
            return .direct("DIRECT")
        case .proxy:
            return resolvePolicy(globalPolicy, target: target,
                                 groupSelections: groupSelections, visited: [])
        case .rule:
            for rule in rules {
                guard matches(rule: rule, target: target, alternateHost: alternateHost) else { continue }
                return resolvePolicy(rule.policy, target: target,
                                     groupSelections: groupSelections, visited: [])
            }
            return .direct("DIRECT")
        }
    }

    private func matches(rule: RoutingRule, target: RequestTarget, alternateHost: String?) -> Bool {
        if case .ruleSet(let reference) = rule.kind {
            guard let contents = ruleSetContents[reference.location] else { return false }
            return contents.contains { kind in
                matchTarget(for: kind, target: target, alternateHost: alternateHost).map(kind.matches) ?? false
            }
        }
        guard let matchTarget = matchTarget(for: rule.kind, target: target,
                                            alternateHost: alternateHost) else { return false }
        return rule.kind.matches(matchTarget)
    }

    private func matchTarget(for kind: RuleKind, target: RequestTarget,
                             alternateHost: String?) -> RequestTarget? {
        switch kind {
        case .domain, .domainSuffix, .domainKeyword, .domainWildcard:
            guard let alternateHost else { return target }
            return RequestTarget(host: alternateHost, port: target.port,
                                 protocolName: target.protocolName,
                                 sourceHost: target.sourceHost,
                                 sourcePort: target.sourcePort,
                                 inboundPort: target.inboundPort)
        case .logicalAnd(let children), .logicalOr(let children):
            _ = children
            return target
        case .logicalNot:
            return target
        case .ruleSet:
            return nil
        default:
            return target
        }
    }

    private func resolvePolicy(_ rawName: String, target: RequestTarget,
                               groupSelections: [String: String],
                               visited: Set<String>) -> ResolvedRoute {
        let name = canonicalName(rawName)
        if visited.contains(name) { return .reject("Policy loop: \(name)") }

        if let group = groups[name] {
            var next: String?
            if let selected = groupSelections[name], group.members.contains(selected) {
                next = selected
            } else if group.kind == .loadBalance, !group.members.isEmpty {
                next = group.members[stableIndex(for: target, count: group.members.count)]
            } else if group.kind == .smart, !group.members.isEmpty {
                // Until the Surge-style scorer lands, keep the first member
                // unless health checking has already written a selection.
                next = group.members.first
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

    private func canonicalName(_ name: String) -> String {
        if proxies[name] != nil || groups[name] != nil { return name }
        if name.uppercased() == "DIRECT" { return "DIRECT" }
        if name.uppercased().hasPrefix("REJECT") { return "REJECT" }
        return name
    }

    private func stableIndex(for target: RequestTarget, count: Int) -> Int {
        var hash: UInt64 = 14_695_981_039_346_656_037
        let key = "\(target.host.lowercased()):\(target.port)/\(target.protocolName)"
        for byte in key.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 1_099_511_628_211
        }
        return Int(hash % UInt64(count))
    }
}

extension RoutingRule {
    public func matches(_ target: RequestTarget) -> Bool {
        kind.matches(target)
    }
}

extension RuleKind {
    public func matches(_ target: RequestTarget) -> Bool {
        // Common ASCII rules can be checked without allocating lowercased
        // Strings. Retain the Swift path for Unicode/bridged String input and
        // for rule kinds that need richer matching semantics.
        func normalizedHost() -> String {
            target.host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        }
        switch self {
        case .domain(let value):
            #if canImport(HajimiRoutingCXX)
            if let match = NativeDomainMatcher.matches(host: target.host, pattern: value,
                                                       kind: .exact) { return match }
            #endif
            return normalizedHost() == value.lowercased()
        case .domainSuffix(let value):
            #if canImport(HajimiRoutingCXX)
            if let match = NativeDomainMatcher.matches(host: target.host, pattern: value,
                                                       kind: .suffix) { return match }
            #endif
            let host = normalizedHost()
            let suffix = value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            return host == suffix || host.hasSuffix("." + suffix)
        case .domainKeyword(let value):
            #if canImport(HajimiRoutingCXX)
            if let match = NativeDomainMatcher.matches(host: target.host, pattern: value,
                                                       kind: .keyword) { return match }
            #endif
            return normalizedHost().contains(value.lowercased())
        case .domainWildcard(let value):
            return DomainPattern.wildcard(value, matches: normalizedHost())
        case .ipCIDR(let cidr):
            return IPCIDR.contains(normalizedHost(), cidr: cidr)
        case .destinationPort(let range):
            return range.contains(target.port)
        case .sourceIPCIDR(let cidr):
            guard let source = target.sourceHost else { return false }
            return IPCIDR.contains(source, cidr: cidr)
        case .sourcePort(let range):
            guard let port = target.sourcePort else { return false }
            return range.contains(port)
        case .inboundPort(let range):
            guard let port = target.inboundPort else { return false }
            return range.contains(port)
        case .protocolName(let value):
            return target.protocolName.caseInsensitiveCompare(value) == .orderedSame
        case .geoIP, .ipASN, .processName:
            // Need MaxMind / kernel process lookup that Hajimi does not ship.
            return false
        case .logicalAnd(let children):
            return !children.isEmpty && children.allSatisfy { $0.matches(target) }
        case .logicalOr(let children):
            return children.contains { $0.matches(target) }
        case .logicalNot(let child):
            return !child.matches(target)
        case .ruleSet:
            return false
        case .final:
            return true
        }
    }
}

/// Surge-style domain patterns used by `always-real-ip` and DOMAIN-WILDCARD.
enum DomainPattern {
    static func any(_ patterns: [String], matches host: String) -> Bool {
        patterns.contains { matches($0, host: host) }
    }

    static func matches(_ pattern: String, host: String) -> Bool {
        let needle = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return false }
        let name = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if needle.contains("*") || needle.contains("?") {
            return wildcard(needle, matches: name)
        }
        let suffix = needle.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return name == suffix || name.hasSuffix("." + suffix)
    }

    static func wildcard(_ pattern: String, matches host: String) -> Bool {
        let name = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let raw = pattern.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return glob(raw, matches: name)
    }

    private static func glob(_ pattern: String, matches value: String) -> Bool {
        func walk(_ p: String.Index, _ v: String.Index) -> Bool {
            var patternIndex = p
            var valueIndex = v
            while patternIndex < pattern.endIndex {
                let character = pattern[patternIndex]
                if character == "*" {
                    let next = pattern.index(after: patternIndex)
                    if next == pattern.endIndex { return true }
                    var probe = valueIndex
                    while probe <= value.endIndex {
                        if walk(next, probe) { return true }
                        if probe == value.endIndex { break }
                        probe = value.index(after: probe)
                    }
                    return false
                }
                if valueIndex == value.endIndex { return false }
                if character != "?" && character != value[valueIndex] { return false }
                patternIndex = pattern.index(after: patternIndex)
                valueIndex = value.index(after: valueIndex)
            }
            return valueIndex == value.endIndex
        }
        return walk(pattern.startIndex, value.startIndex)
    }
}

enum IPCIDR {
    static func contains(_ address: String, cidr: String) -> Bool {
        let pieces = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard pieces.count == 2, let bits = Int(pieces[1]) else { return false }
        if pieces[0].contains(":"), (0...128).contains(bits) {
            return containsIPv6(address, network: pieces[0], bits: bits)
        }
        guard (0...32).contains(bits), let ip = ipv4Value(address),
              let network = ipv4Value(pieces[0]) else { return false }
        let mask: UInt32 = bits == 0 ? 0 : UInt32.max << UInt32(32 - bits)
        return (ip & mask) == (network & mask)
    }

    private static func ipv4Value(_ string: String) -> UInt32? {
        var address = in_addr()
        guard inet_pton(AF_INET, string, &address) == 1 else { return nil }
        return UInt32(bigEndian: address.s_addr)
    }

    private static func containsIPv6(_ rawAddress: String, network: String, bits: Int) -> Bool {
        let addressString = rawAddress.split(separator: "%", maxSplits: 1).first.map(String.init) ?? rawAddress
        var address = in6_addr()
        var networkAddress = in6_addr()
        guard inet_pton(AF_INET6, addressString, &address) == 1,
              inet_pton(AF_INET6, network, &networkAddress) == 1 else { return false }
        let addressBytes = withUnsafeBytes(of: &address) { Array($0) }
        let networkBytes = withUnsafeBytes(of: &networkAddress) { Array($0) }
        let fullBytes = bits / 8
        if fullBytes > 0 && addressBytes.prefix(fullBytes) != networkBytes.prefix(fullBytes) { return false }
        let remaining = bits % 8
        guard remaining > 0 else { return true }
        let mask = UInt8.max << UInt8(8 - remaining)
        return addressBytes[fullBytes] & mask == networkBytes[fullBytes] & mask
    }
}

public struct ProfileParseError: Error, Equatable, CustomStringConvertible, LocalizedError {
    public var line: Int
    public var message: String
    public var description: String { line > 0 ? "第 \(line) 行：\(message)" : message }
    public var errorDescription: String? { description }
}

public enum ProfileParser {
    public static func parse(_ text: String) throws -> Profile {
        var profile = Profile()
        var section = ""
        var sectionDisplayName = ""
        var generalOptions: [String: String] = [:]
        var controllerOptionLines: [String: Int] = [:]
        var explicitHTTPListen = false
        var explicitSOCKSListen = false
        var wireGuardValues: [String: [String: String]] = [:]
        var wireGuardOrder: [String] = []
        var warnedSections = Set<String>()
        // Foundation's newline character set splits CR and LF separately.
        // Keep sourceLine aligned with physical lines for targeted UI edits.
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n")
            .components(separatedBy: .newlines)

        for (index, rawLine) in lines.enumerated() {
            let lineNumber = index + 1
            let line = stripComment(rawLine, preservingDNSBootstrap: section == "general")
                .trimmingCharacters(in: .whitespacesAndNewlines.union(CharacterSet(charactersIn: "\u{feff}")))
            if line.isEmpty { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                sectionDisplayName = String(line.dropFirst().dropLast())
                    .trimmingCharacters(in: .whitespaces)
                section = sectionDisplayName.lowercased()
                if section.hasPrefix("wireguard ") {
                    if wireGuardValues[sectionDisplayName] == nil {
                        wireGuardValues[sectionDisplayName] = [:]
                        wireGuardOrder.append(sectionDisplayName)
                    }
                    profile.surgeCompatible = true
                } else if !supportedSections.contains(section), !warnedSections.contains(section) {
                    warnedSections.insert(section)
                    profile.warnings.append("已兼容读取但忽略 [\(sectionDisplayName)] 段")
                    profile.surgeCompatible = true
                }
                continue
            }

            switch section {
            case "general":
                let pair = try keyValue(line, number: lineNumber)
                let key = pair.0.lowercased()
                generalOptions[key] = pair.1
                switch key {
                case "http-listen":
                    profile.httpListen = try listenAddress(pair.1, number: lineNumber)
                    explicitHTTPListen = true
                case "socks5-listen":
                    profile.socksListen = try listenAddress(pair.1, number: lineNumber)
                    explicitSOCKSListen = true
                case "http-api", "external-controller-access", "external-controller":
                    controllerOptionLines[key] = lineNumber
                    profile.surgeCompatible = true
                default:
                    profile.surgeCompatible = true
                }
            case "proxy":
                let pair = try keyValue(line, number: lineNumber)
                let policy = try proxy(name: pair.0, value: pair.1, number: lineNumber)
                profile.proxies[pair.0] = policy
                if !["DIRECT", "REJECT"].contains(pair.0), !profile.proxyOrder.contains(pair.0) {
                    profile.proxyOrder.append(pair.0)
                }
            case "proxy group":
                let pair = try keyValue(line, number: lineNumber)
                let parsed = try proxyGroup(name: pair.0, value: pair.1, number: lineNumber)
                profile.groups[pair.0] = parsed.group
                if !profile.groupOrder.contains(pair.0) { profile.groupOrder.append(pair.0) }
                if let warning = parsed.warning { profile.warnings.append(warning) }
                if parsed.group.kind != .select || !parsed.group.parameters.isEmpty {
                    profile.surgeCompatible = true
                }
            case "rule":
                if let parsed = try rule(line, number: lineNumber) {
                    profile.rules.append(parsed)
                    if case .ruleSet = parsed.kind { profile.surgeCompatible = true }
                } else {
                    let type = csv(line).first?.uppercased() ?? "未知"
                    profile.warnings.append("第 \(lineNumber) 行已忽略暂不支持的规则 \(type)")
                }
            default:
                if section.hasPrefix("wireguard ") {
                    let pair = try keyValue(line, number: lineNumber)
                    wireGuardValues[sectionDisplayName]?[pair.0.lowercased()] = pair.1
                } else if section.isEmpty {
                    throw ProfileParseError(line: lineNumber, message: "请先声明配置段")
                }
            }
        }

        try applyGeneralOptions(generalOptions, controllerOptionLines: controllerOptionLines,
                                explicitHTTPListen: explicitHTTPListen,
                                explicitSOCKSListen: explicitSOCKSListen, profile: &profile)
        for name in wireGuardOrder {
            guard let values = wireGuardValues[name] else { continue }
            let policyName = String(name.dropFirst("WireGuard ".count))
            let policy = try wireGuardPolicy(name: policyName, values: values)
            if profile.proxies[policyName] == nil {
                profile.proxies[policyName] = policy
                profile.proxyOrder.append(policyName)
            } else {
                profile.warnings.append("WireGuard 策略 \(policyName) 与 [Proxy] 同名，已使用 [Proxy] 定义")
            }
        }
        applyGroupOptions(profile: &profile)
        appendSkipCertificateWarning(to: &profile)
        return profile
    }

    /// Surfaces skip-cert-verify as a profile-level warning so the UI and
    /// subscription import path can show it without each scanning parameters.
    static func appendSkipCertificateWarning(to profile: inout Profile) {
        let names = profile.proxiesSkippingCertificateVerification
        guard !names.isEmpty else { return }
        profile.warnings.append(SkipCertificateWarning.message(names: names))
    }

    private static let supportedSections: Set<String> = ["general", "proxy", "proxy group", "rule"]

    private static func applyGeneralOptions(_ options: [String: String],
                                            controllerOptionLines: [String: Int],
                                            explicitHTTPListen: Bool,
                                            explicitSOCKSListen: Bool,
                                            profile: inout Profile) throws {
        let allowWiFi = options["allow-wifi-access"].map(isTrue) ?? false
        let host = allowWiFi ? "0.0.0.0" : "127.0.0.1"
        if !explicitHTTPListen, let value = options["wifi-access-http-port"],
           let port = UInt16(value), port > 0 {
            profile.httpListen = ListenAddress(host: host, port: port)
        }
        if !explicitSOCKSListen, let value = options["wifi-access-socks5-port"],
           let port = UInt16(value), port > 0 {
            profile.socksListen = ListenAddress(host: host, port: port)
        }
        if let bypass = options["skip-proxy"] {
            profile.proxyBypassDomains = csv(bypass).filter { !$0.isEmpty }
        }
        if let raw = options["fake-ip"] ?? options["fake-ip-filter-mode"] {
            profile.fakeIPEnabled = isTrue(raw)
        }
        if let dns = options["dns-server"] {
            profile.dnsServers = csv(dns).filter { !$0.isEmpty }
        }
        if let always = options["always-real-ip"] ?? options["fake-ip-filter"] {
            profile.alwaysRealIP = csv(always).filter { !$0.isEmpty }
        }
        if let hijack = options["hijack-dns"] {
            profile.hijackDNS = csv(hijack).filter { !$0.isEmpty }
        }
        if let excluded = options["tun-excluded-routes"] ?? options["excluded-routes"] {
            profile.tunExcludedRoutes = csv(excluded).filter { !$0.isEmpty }
        }
        if let included = options["tun-included-routes"] ?? options["included-routes"] {
            profile.tunIncludedRoutes = csv(included).filter { !$0.isEmpty }
        }
        if let includeAll = options["include-all-networks"] {
            profile.includeAllNetworks = isTrue(includeAll)
        }
        if let httpAPI = options["http-api"] {
            let parsed = try controllerEndpoint(httpAPI, option: "http-api",
                                                line: controllerOptionLines["http-api"] ?? 0)
            profile.httpAPIKey = parsed.key
            profile.httpAPI = parsed.address
        }
        let controllerOption = options["external-controller-access"] != nil
            ? "external-controller-access" : "external-controller"
        if let controller = options[controllerOption] {
            let parsed = try controllerEndpoint(controller, option: controllerOption,
                                                line: controllerOptionLines[controllerOption] ?? 0)
            profile.externalControllerKey = parsed.key
            profile.externalController = parsed.address
        }
    }

    /// Surge writes these as `key@host:port`. Bare endpoints are only allowed
    /// on a numeric loopback address to prevent remote unauthenticated access.
    private static func controllerEndpoint(_ raw: String, option: String, line: Int)
        throws -> (key: String, address: ListenAddress) {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            throw ProfileParseError(line: line, message: "\(option) 控制接口地址不能为空")
        }
        let key: String
        let endpoint: String
        if let at = value.firstIndex(of: "@") {
            key = value[..<at].trimmingCharacters(in: .whitespacesAndNewlines)
            endpoint = value[value.index(after: at)...]
                .trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            key = ""
            endpoint = value
        }
        guard let pair = splitHostPort(endpoint),
              let port = UInt16(pair.1), port > 0 else {
            throw ProfileParseError(line: line, message: "\(option) 控制接口地址或端口无效")
        }
        let host = pair.0.isEmpty ? "127.0.0.1" : pair.0
        let address = ListenAddress(host: host, port: port)
        guard !key.isEmpty || address.isLoopback else {
            throw ProfileParseError(line: line, message:
                "\(option) 监听 \(host):\(port) 为非回环地址，必须设置密钥（key@host:port）；无密钥仅允许 127.0.0.0/8 或 [::1]")
        }
        return (key, address)
    }

    private static func applyGroupOptions(profile: inout Profile) {
        for name in profile.groupOrder {
            guard var group = profile.groups[name] else { continue }
            if group.parameters["include-all-proxies"].map(isTrue) == true {
                for proxy in profile.proxyOrder where !group.members.contains(proxy) {
                    group.members.append(proxy)
                }
            }
            profile.groups[name] = group
        }
        // Second pass: `include-other-group` copies another group's members
        // after those groups have already absorbed include-all-proxies.
        for _ in 0..<8 {
            var changed = false
            for name in profile.groupOrder {
                guard var group = profile.groups[name],
                      let raw = group.parameters["include-other-group"] else { continue }
                for otherName in csv(raw) where otherName != name {
                    guard let other = profile.groups[otherName] else { continue }
                    for member in other.members where !group.members.contains(member) {
                        group.members.append(member)
                        changed = true
                    }
                }
                profile.groups[name] = group
            }
            if !changed { break }
        }
    }

    private static func proxyGroup(name: String, value: String, number: Int)
        throws -> (group: PolicyGroup, warning: String?) {
        let fields = csv(value)
        guard let rawType = fields.first?.lowercased(), fields.count >= 2 else {
            throw ProfileParseError(line: number, message: "策略组字段不足")
        }
        let kind: PolicyGroupKind
        var warning: String?
        switch rawType.replacingOccurrences(of: "_", with: "-") {
        case "select": kind = .select
        case "load-balance": kind = .loadBalance
        case "url-test": kind = .urlTest
        case "fallback": kind = .fallback
        case "smart": kind = .smart
        case "subnet": kind = .subnet
        default:
            kind = .fallback
            warning = "第 \(number) 行策略组类型 \(rawType) 暂按 fallback（首个可用成员）处理"
        }

        var members: [String] = []
        var parameters: [String: String] = [:]
        for field in fields.dropFirst() where !field.isEmpty {
            if let equal = field.firstIndex(of: "=") {
                let key = field[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
                if groupParameterNames.contains(key) {
                    parameters[key] = field[field.index(after: equal)...]
                        .trimmingCharacters(in: .whitespaces)
                    continue
                }
            }
            members.append(field)
        }
        return (PolicyGroup(name: name, kind: kind, members: members, parameters: parameters), warning)
    }

    private static let groupParameterNames: Set<String> = [
        "hidden", "include-all-proxies", "include-other-group", "policy-path", "url",
        "interval", "timeout", "tolerance", "evaluate-before-use", "update-interval",
        "no-alert", "external-policy-modifier", "persistent", "weight", "algorithm",
        "policy-regex-filter", "policy-regex-filter-exclude", "policy-name-filter", "icon",
        "test-url", "internet-test-url", "use-cache", "strategy", "max-failed-times",
        "include-other-group-regex", "policy-priority"
    ]

    private static func stripComment(_ line: String, preservingDNSBootstrap: Bool) -> String {
        let dnsValueStart: String.Index?
        if preservingDNSBootstrap, let equal = line.firstIndex(of: "="),
           line[..<equal].trimmingCharacters(in: .whitespaces).lowercased() == "dns-server" {
            dnsValueStart = line.index(after: equal)
        } else {
            dnsValueStart = nil
        }
        var quote: Character?
        var escaped = false
        var mayStartQuote = true
        for index in line.indices {
            let character = line[index]
            if let activeQuote = quote {
                if escaped { escaped = false; continue }
                if character == "\\" { escaped = true; continue }
                if character == activeQuote { quote = nil; mayStartQuote = false }
                continue
            }
            if (character == "\"" || character == "'") && mayStartQuote {
                quote = character
                continue
            }
            if character == "#" {
                if let dnsValueStart,
                   isDNSBootstrapMarker(in: line, at: index, valueStart: dnsValueStart) {
                    continue
                }
                return String(line[..<index])
            }
            if character == "," || character == "=" {
                mayStartQuote = true
            } else if !character.isWhitespace {
                mayStartQuote = false
            }
        }
        return line
    }

    /// In `dns-server`, a URL fragment is a bootstrap address only when it is
    /// attached to a DoH/DoT URL and is a complete IP literal. All other `#`
    /// characters retain their usual comment semantics, including in lists.
    private static func isDNSBootstrapMarker(in line: String, at hash: String.Index,
                                             valueStart: String.Index) -> Bool {
        guard hash > valueStart, !line[line.index(before: hash)].isWhitespace else {
            return false
        }
        let prefix = line[valueStart..<hash]
        let start = prefix.lastIndex(of: ",").map { line.index(after: $0) } ?? valueStart
        let endpoint = prefix[start...].trimmingCharacters(in: .whitespaces)
        let lower = endpoint.lowercased()
        guard (lower.hasPrefix("https://") || lower.hasPrefix("tls://")),
              !endpoint.contains(where: \.isWhitespace) else { return false }
        let suffix = line[line.index(after: hash)...]
        let address = String(suffix.prefix { $0 != "," && $0 != "#" && !$0.isWhitespace })
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return true }
        var ipv6 = in6_addr()
        return address.withCString { inet_pton(AF_INET6, $0, &ipv6) } == 1
    }

    private static func keyValue(_ line: String, number: Int) throws -> (String, String) {
        guard let index = line.firstIndex(of: "=") else {
            throw ProfileParseError(line: number, message: "缺少 =")
        }
        let key = line[..<index].trimmingCharacters(in: .whitespaces)
        let value = line[line.index(after: index)...].trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty, !value.isEmpty else {
            throw ProfileParseError(line: number, message: "键或值为空")
        }
        return (key, value)
    }

    private static func listenAddress(_ value: String, number: Int) throws -> ListenAddress {
        let pair = splitHostPort(value)
        guard let pair, !pair.0.isEmpty, let port = UInt16(pair.1), port > 0 else {
            throw ProfileParseError(line: number, message: "监听地址应为 host:port")
        }
        return ListenAddress(host: pair.0, port: port)
    }

    private static func proxy(name: String, value: String, number: Int) throws -> ProxyPolicy {
        let fields = csv(value)
        guard let rawType = fields.first?.lowercased() else {
            throw ProfileParseError(line: number, message: "代理定义为空")
        }
        let type = canonicalProxyType(rawType)
        if type == "direct" { return ProxyPolicy(name: name, kind: .direct) }
        if type == "reject" { return ProxyPolicy(name: name, kind: .reject) }
        guard fields.count >= 3, !fields[1].isEmpty, let port = UInt16(fields[2]), port > 0 else {
            throw ProfileParseError(line: number, message: "代理应包含类型、主机和端口")
        }
        if advancedProxyTypes.contains(type) {
            let parameters = advancedParameters(type: type, fields: Array(fields.dropFirst(3)))
            return ProxyPolicy(name: name, kind: .external, host: fields[1], port: port,
                               adapterType: type, parameters: parameters)
        }
        let adapterType: String
        let requiresTLS: Bool
        switch type {
        case "http", "socks5": adapterType = type; requiresTLS = false
        case "https": adapterType = "http"; requiresTLS = true
        case "socks5-tls", "socks5tls": adapterType = "socks5"; requiresTLS = true
        default:
            throw ProfileParseError(line: number,
                                    message: "不支持的代理类型 \(rawType)")
        }
        var parameters = advancedParameters(type: adapterType, fields: Array(fields.dropFirst(3)))
        if let tls = parameters["tls"]?.lowercased() {
            guard ["true", "yes", "on", "1", "false", "no", "off", "0"].contains(tls) else {
                throw ProfileParseError(line: number, message: "代理 tls=\(tls) 不是有效布尔值")
            }
            if requiresTLS && ["false", "no", "off", "0"].contains(tls) {
                throw ProfileParseError(line: number, message: "\(rawType) 不允许关闭 TLS")
            }
        }
        // HTTPS/SOCKS5-TLS are ordinary HTTP/SOCKS5 wire protocols over a
        // verified TLS connection. Do not leave them as inert `.external`
        // policies just because their carrier is encrypted.
        if requiresTLS { parameters["tls"] = "true" }
        let username = parameters["username"]
        let password = parameters["password"]
        if parameters["underlying-proxy"] != nil || parameters["dialer-proxy"] != nil {
            return ProxyPolicy(name: name, kind: .external, host: fields[1], port: port,
                               adapterType: adapterType, parameters: parameters)
        }
        return ProxyPolicy(name: name, kind: adapterType == "http" ? .http : .socks5,
                           host: fields[1], port: port, username: username, password: password,
                           parameters: parameters)
    }

    private static let advancedProxyTypes: Set<String> = [
        "ss", "ssr", "snell", "vmess", "vless", "trojan", "anytls",
        "hysteria", "hysteria2", "tuic", "ssh", "wireguard"
    ]

    private static func wireGuardPolicy(name: String, values: [String: String]) throws -> ProxyPolicy {
        guard let privateKey = values["private-key"], !privateKey.isEmpty,
              let selfIP = values["self-ip"], !selfIP.isEmpty,
              let rawPeer = values["peer"] else {
            throw ProfileParseError(line: 0,
                                    message: "[\(name)] 缺少 private-key、self-ip 或 peer")
        }
        var peer = rawPeer.trimmingCharacters(in: .whitespaces)
        if peer.hasPrefix("("), peer.hasSuffix(")") {
            peer = String(peer.dropFirst().dropLast())
        }
        var peerValues: [String: String] = [:]
        for field in csv(peer) {
            guard let equal = field.firstIndex(of: "=") else { continue }
            let key = field[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            var value = field[field.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            value = value.trimmingCharacters(in: CharacterSet(charactersIn: "()"))
                .trimmingCharacters(in: .whitespaces)
            peerValues[key] = value
        }
        guard let endpoint = peerValues["endpoint"], let endpointPair = splitHostPort(endpoint),
              let port = UInt16(endpointPair.1), port > 0,
              let publicKey = peerValues["public-key"], !publicKey.isEmpty else {
            throw ProfileParseError(line: 0,
                                    message: "[\(name)] 的 peer 缺少有效 endpoint 或 public-key")
        }
        var parameters: [String: String] = [
            "private-key": privateKey,
            "ip": selfIP,
            "public-key": publicKey,
            "udp": "true"
        ]
        if let ipv6 = values["self-ip-v6"] { parameters["ipv6"] = ipv6 }
        if let mtu = values["mtu"] { parameters["mtu"] = mtu }
        if let allowedIPs = peerValues["allowed-ips"] { parameters["allowed-ips"] = allowedIPs }
        if let preSharedKey = peerValues["pre-shared-key"] {
            parameters["pre-shared-key"] = preSharedKey
        }
        if let reserved = peerValues["reserved"] { parameters["reserved"] = reserved }
        return ProxyPolicy(name: name, kind: .external, host: endpointPair.0, port: port,
                           adapterType: "wireguard", parameters: parameters)
    }

    private static func canonicalProxyType(_ value: String) -> String {
        let compact = value.replacingOccurrences(of: "-", with: "").lowercased()
        switch compact {
        case "shadowsocks": return "ss"
        case "shadowsocksr": return "ssr"
        case "hy", "hysteria1": return "hysteria"
        case "hy2": return "hysteria2"
        default: return advancedProxyTypes.contains(compact) ? compact : value.lowercased()
        }
    }

    private static func advancedParameters(type: String, fields: [String]) -> [String: String] {
        var result: [String: String] = [:]
        let nonEmptyFields = fields.filter { !$0.isEmpty }
        let explicitKeys = Set(nonEmptyFields.compactMap { field -> String? in
            guard let equal = field.firstIndex(of: "=") else { return nil }
            let key = field[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            return advancedParameterNames.contains(key) ? key : nil
        })
        let positionalCandidates = nonEmptyFields.filter { field in
            if let equal = field.firstIndex(of: "=") {
                let key = field[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
                return !advancedParameterNames.contains(key)
            }
            return true
        }
        let positionalKeys = positionalParameterKeys(type: type,
                                                     candidateCount: positionalCandidates.count,
                                                     explicitKeys: explicitKeys)
        var positionalIndex = 0

        for field in nonEmptyFields {
            if let equal = field.firstIndex(of: "=") {
                let key = field[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
                let value = field[field.index(after: equal)...].trimmingCharacters(in: .whitespaces)
                let requiredSlotsFilled = positionalKeys.allSatisfy { result[$0] != nil }
                if !key.isEmpty && (advancedParameterNames.contains(key) || requiredSlotsFilled) {
                    result[key] = value
                    continue
                }
            }

            while positionalIndex < positionalKeys.count && result[positionalKeys[positionalIndex]] != nil {
                positionalIndex += 1
            }
            if positionalIndex < positionalKeys.count {
                result[positionalKeys[positionalIndex]] = field
                positionalIndex += 1
            } else if let equal = field.firstIndex(of: "=") {
                let key = field[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
                let value = field[field.index(after: equal)...].trimmingCharacters(in: .whitespaces)
                if !key.isEmpty { result[key] = value }
            }
        }
        return result
    }

    private static func positionalParameterKeys(type: String, candidateCount: Int,
                                                explicitKeys: Set<String>) -> [String] {
        switch type {
        case "ss": return ["cipher", "password"]
        case "ssr": return ["cipher", "password", "protocol", "obfs"]
        case "snell": return ["psk", "version"]
        case "vmess", "vless": return ["uuid"]
        case "trojan", "anytls", "hysteria2": return ["password"]
        case "hysteria": return ["auth-str", "up", "down"]
        case "tuic":
            return candidateCount >= 2 || explicitKeys.contains("uuid") || explicitKeys.contains("password")
                ? ["uuid", "password"] : ["token"]
        case "ssh": return ["username", "password"]
        case "http", "socks5": return ["username", "password"]
        default: return []
        }
    }

    /// Known names disambiguate `key=value` options from positional secrets
    /// that themselves contain `=` (common with base64 credentials).
    private static let advancedParameterNames: Set<String> = [
        "cipher", "password", "protocol", "protocol-param", "obfs", "obfs-param",
        "obfs-mode", "obfs-host", "obfs-password", "obfs-protocol", "psk", "version",
        "reuse", "uuid", "alter-id", "alterid", "flow", "security", "tls", "alpn", "udp",
        "udp-relay", "network", "sni", "servername", "skip-cert-verify",
        "skip-common-name-verify", "fingerprint", "client-fingerprint", "certificate",
        "private-key", "private-key-passphrase", "username", "user", "host-key",
        "host-key-algorithms", "packet-addr", "xudp", "packet-encoding", "encryption",
        "global-padding", "authenticated-length", "ws", "ws-path", "ws-host",
        "ws-headers", "ws-max-early-data", "ws-early-data-header-name",
        "ws-v2ray-http-upgrade", "ws-v2ray-http-upgrade-fast-open", "grpc-service-name",
        "grpc-user-agent", "grpc-ping-interval", "grpc-max-connections", "grpc-min-streams",
        "xhttp-path", "xhttp-host", "xhttp-mode", "xhttp-padding-bytes",
        "kcp-header", "kcp-header-domain", "kcp-seed", "kcp-mtu", "kcp-tti",
        "kcp-congestion", "kcp-uplink-capacity", "kcp-downlink-capacity",
        "grpc-max-streams", "reality-public-key", "reality-short-id",
        "reality-support-x25519mlkem768", "auth", "auth-str", "up", "down", "up-speed",
        "down-speed", "upload-bandwidth", "download-bandwidth", "ports", "recv-window",
        "recv-window-conn", "disable-mtu-discovery", "fast-open", "hop-interval", "cwnd",
        "bbr-profile", "udp-mtu", "token", "heartbeat-interval", "reduce-rtt",
        "request-timeout", "udp-relay-mode", "congestion-controller", "disable-sni",
        "max-udp-relay-packet-size", "max-open-streams", "max-datagram-frame-size",
        "udp-over-stream", "udp-over-stream-version", "idle-session-check-interval",
        "idle-session-timeout", "min-idle-session", "interface-name", "ip-version", "tfo",
        "mptcp", "dialer-proxy", "underlying-proxy", "vmess-aead", "public-key",
        "pre-shared-key", "allowed-ips", "reserved", "ip", "ipv6", "mtu", "workers",
        "persistent-keepalive", "remote-dns-resolve", "dns", "refresh-server-ip-interval",
        "server-cert-fingerprint-sha256", "tls-verification"
    ]

    private static func rule(_ line: String, number: Int) throws -> RoutingRule? {
        let fields = csv(line)
        guard fields.count >= 2 else {
            throw ProfileParseError(line: number, message: "规则字段不足")
        }
        let type = fields[0].uppercased()
        if type == "FINAL" || type == "MATCH" {
            return RoutingRule(kind: .final, policy: fields[1], sourceLine: number)
        }
        guard fields.count >= 3 else {
            throw ProfileParseError(line: number, message: "规则缺少策略")
        }
        let kind: RuleKind
        switch type {
        case "DOMAIN": kind = .domain(fields[1])
        case "DOMAIN-SUFFIX": kind = .domainSuffix(fields[1])
        case "DOMAIN-KEYWORD": kind = .domainKeyword(fields[1])
        case "DOMAIN-WILDCARD": kind = .domainWildcard(fields[1])
        case "IP-CIDR", "IP-CIDR6": kind = .ipCIDR(fields[1])
        case "SRC-IP", "SRC-IP-CIDR", "SOURCE-IP-CIDR": kind = .sourceIPCIDR(fields[1])
        case "SRC-PORT", "SOURCE-PORT":
            kind = .sourcePort(try portRange(fields[1], number: number))
        case "IN-PORT":
            kind = .inboundPort(try portRange(fields[1], number: number))
        case "GEOIP": kind = .geoIP(fields[1])
        case "IP-ASN": kind = .ipASN(fields[1])
        case "PROCESS-NAME": kind = .processName(fields[1])
        case "AND", "OR", "NOT":
            return try parseLogicalLine(line, number: number)
        case "RULE-SET":
            let parameters = parameterMap(Array(fields.dropFirst(3)))
            let interval = parameters["update-interval"].flatMap(TimeInterval.init) ?? 86_400
            kind = .ruleSet(RuleSetReference(location: fields[1], updateInterval: max(60, interval)))
        case "DEST-PORT":
            kind = .destinationPort(try portRange(fields[1], number: number))
        case "PROTOCOL": kind = .protocolName(fields[1])
        default: return nil
        }
        return RoutingRule(kind: kind, policy: fields[2], sourceLine: number)
    }

    private static func portRange(_ raw: String, number: Int) throws -> ClosedRange<UInt16> {
        let bounds = raw.split(separator: "-", maxSplits: 1).compactMap { UInt16($0) }
        guard let first = bounds.first,
              bounds.count != 2 || bounds[1] >= first else {
            throw ProfileParseError(line: number, message: "无效端口")
        }
        return first...(bounds.count == 2 ? bounds[1] : first)
    }

    /// Surge writes `AND,((DOMAIN,a),(DOMAIN-SUFFIX,b)),POLICY`. The operands
    /// contain commas, so this line cannot go through the ordinary CSV split.
    private static func parseLogicalLine(_ line: String, number: Int) throws -> RoutingRule? {
        guard let firstComma = firstTopLevelComma(in: line) else { return nil }
        let type = line[..<firstComma].trimmingCharacters(in: .whitespaces).uppercased()
        let rest = String(line[line.index(after: firstComma)...])
        guard let operandEnd = firstTopLevelComma(in: rest) else { return nil }
        let operands = String(rest[..<operandEnd])
        // The policy may be quoted and followed by options such as no-resolve.
        // It is the first field after the operands, not the last comma field.
        let policyFields = csv(String(rest[rest.index(after: operandEnd)...]))
        let policy = policyFields.first ?? ""
        guard !policy.isEmpty,
              let kind = try logicalRule(type: type, fields: [type, operands, policy],
                                         number: number) else { return nil }
        return RoutingRule(kind: kind, policy: policy, sourceLine: number)
    }

    /// Surge writes `AND,((DOMAIN,a),(DOMAIN-SUFFIX,b)),POLICY`. Nested
    /// parentheses survive because this path never CSV-splits the operands.
    private static func logicalRule(type: String, fields: [String], number: Int) throws -> RuleKind? {
        guard fields.count >= 2 else { return nil }
        let children = try parseLogicalOperands(fields[1], number: number)
        switch type {
        case "AND":
            guard !children.isEmpty else { return nil }
            return .logicalAnd(children)
        case "OR":
            guard !children.isEmpty else { return nil }
            return .logicalOr(children)
        case "NOT":
            guard children.count == 1, let first = children.first else {
                throw ProfileParseError(line: number, message: "NOT 逻辑规则只能包含一个条件")
            }
            return .logicalNot(first)
        default:
            return nil
        }
    }

    private static func firstTopLevelComma(in value: String) -> String.Index? {
        topLevelCommas(in: value).first
    }

    private static func topLevelCommas(in value: String) -> [String.Index] {
        var depth = 0
        var quote: Character?
        var escaped = false
        var mayStartQuote = true
        var result: [String.Index] = []
        for index in value.indices {
            let character = value[index]
            if let active = quote {
                if escaped { escaped = false }
                else if character == "\\" { escaped = true }
                else if character == active { quote = nil; mayStartQuote = false }
                continue
            }
            if (character == "\"" || character == "'") && mayStartQuote {
                quote = character
                continue
            }
            switch character {
            case "(": depth += 1; mayStartQuote = true
            case ")": depth = max(0, depth - 1); mayStartQuote = false
            case ",":
                if depth == 0 { result.append(index) }
                mayStartQuote = true
            case "=": mayStartQuote = true
            default: break
            }
            if !character.isWhitespace && character != "(" && character != "," && character != "=" {
                mayStartQuote = false
            }
        }
        return result
    }

    private static func parseLogicalOperands(_ raw: String, number: Int) throws -> [RuleKind] {
        var value = raw.trimmingCharacters(in: .whitespaces)
        if value.hasPrefix("("), value.hasSuffix(")") {
            value = String(value.dropFirst().dropLast())
        }
        var kinds: [RuleKind] = []
        for operand in splitTopLevelLogicalOperands(value) {
            let inner = operand.trimmingCharacters(in: .whitespaces)
            let stripped = inner.hasPrefix("(") && inner.hasSuffix(")")
                ? String(inner.dropFirst().dropLast()) : inner
            guard let kind = try ruleKind(stripped, number: number) else {
                throw ProfileParseError(line: number, message: "无法解析逻辑规则 \(operand)")
            }
            kinds.append(kind)
        }
        return kinds
    }

    /// Type + match value only. Logical children never carry a policy.
    private static func ruleKind(_ line: String, number: Int) throws -> RuleKind? {
        if let firstComma = firstTopLevelComma(in: line) {
            let type = line[..<firstComma].trimmingCharacters(in: .whitespaces).uppercased()
            if type == "AND" || type == "OR" || type == "NOT" {
                let payload = String(line[line.index(after: firstComma)...])
                return try logicalRule(type: type, fields: [type, payload, "DIRECT"], number: number)
            }
        }
        let fields = csv(line)
        guard !fields.isEmpty else { return nil }
        let type = fields[0].uppercased()
        guard fields.count >= 2 else { return nil }
        switch type {
        case "DOMAIN": return .domain(fields[1])
        case "DOMAIN-SUFFIX": return .domainSuffix(fields[1])
        case "DOMAIN-KEYWORD": return .domainKeyword(fields[1])
        case "DOMAIN-WILDCARD": return .domainWildcard(fields[1])
        case "IP-CIDR", "IP-CIDR6": return .ipCIDR(fields[1])
        case "SRC-IP", "SRC-IP-CIDR", "SOURCE-IP-CIDR": return .sourceIPCIDR(fields[1])
        case "SRC-PORT", "SOURCE-PORT": return .sourcePort(try portRange(fields[1], number: number))
        case "IN-PORT": return .inboundPort(try portRange(fields[1], number: number))
        case "GEOIP": return .geoIP(fields[1])
        case "IP-ASN": return .ipASN(fields[1])
        case "PROCESS-NAME": return .processName(fields[1])
        case "DEST-PORT": return .destinationPort(try portRange(fields[1], number: number))
        case "PROTOCOL": return .protocolName(fields[1])
        default: return nil
        }
    }

    private static func splitTopLevelLogicalOperands(_ value: String) -> [String] {
        var result: [String] = []
        var start = value.startIndex
        for comma in topLevelCommas(in: value) {
            let trimmed = value[start..<comma].trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty { result.append(trimmed) }
            start = value.index(after: comma)
        }
        let trimmed = value[start...].trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty { result.append(trimmed) }
        return result
    }

    private static func parameterMap(_ fields: [String]) -> [String: String] {
        var result: [String: String] = [:]
        for field in fields {
            guard let equal = field.firstIndex(of: "=") else { continue }
            let key = field[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            let value = field[field.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            if !key.isEmpty { result[key] = value }
        }
        return result
    }

    private static func isTrue(_ value: String) -> Bool {
        ["true", "yes", "on", "1"].contains(value.lowercased())
    }

    private static func csv(_ value: String) -> [String] {
        var result: [String] = []
        var field = ""
        var quote: Character?
        var escaped = false
        var mayStartQuote = true

        func appendField() {
            result.append(field.trimmingCharacters(in: .whitespaces))
            field.removeAll(keepingCapacity: true)
            mayStartQuote = true
        }

        for character in value {
            if let activeQuote = quote {
                if escaped {
                    field.append(character)
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == activeQuote {
                    quote = nil
                    mayStartQuote = false
                } else {
                    field.append(character)
                }
                continue
            }
            if (character == "\"" || character == "'") && mayStartQuote {
                quote = character
            } else if character == "," {
                appendField()
            } else {
                field.append(character)
                if character == "=" {
                    mayStartQuote = true
                } else if !character.isWhitespace {
                    mayStartQuote = false
                }
            }
        }
        if escaped { field.append("\\") }
        appendField()
        return result
    }

    private static func splitHostPort(_ value: String) -> (String, String)? {
        if value.hasPrefix("["), let bracket = value.firstIndex(of: "]") {
            let host = String(value[value.index(after: value.startIndex)..<bracket])
            let rest = value[value.index(after: bracket)...]
            guard rest.first == ":" else { return nil }
            return (host, String(rest.dropFirst()))
        }
        guard let colon = value.lastIndex(of: ":") else { return nil }
        return (String(value[..<colon]), String(value[value.index(after: colon)...]))
    }
}

public struct SurgeRuleSetParseResult: Equatable {
    public var rules: [RuleKind]
    public var ignoredTypes: [String: Int]

    public init(rules: [RuleKind], ignoredTypes: [String: Int]) {
        self.rules = rules
        self.ignoredTypes = ignoredTypes
    }
}

public enum SurgeRuleSetParser {
    public static func parse(_ text: String) -> SurgeRuleSetParseResult {
        var rules: [RuleKind] = []
        var ignored: [String: Int] = [:]
        for rawLine in text.components(separatedBy: .newlines) {
            var line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines
                .union(CharacterSet(charactersIn: "\u{feff}")))
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";") else { continue }
            if line == "payload:" || line == "rules:" { continue }
            if line.hasPrefix("-") {
                line = String(line.dropFirst()).trimmingCharacters(in: .whitespaces)
            }
            line = line.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            let fields = csv(line)
            guard fields.count >= 2 else { continue }
            let type = fields[0].uppercased()
            let kind: RuleKind?
            switch type {
            case "DOMAIN": kind = .domain(fields[1])
            case "DOMAIN-SUFFIX": kind = .domainSuffix(fields[1])
            case "DOMAIN-KEYWORD": kind = .domainKeyword(fields[1])
            case "DOMAIN-WILDCARD": kind = .domainWildcard(fields[1])
            case "IP-CIDR", "IP-CIDR6": kind = .ipCIDR(fields[1])
            case "SRC-IP", "SRC-IP-CIDR", "SOURCE-IP-CIDR": kind = .sourceIPCIDR(fields[1])
            case "SRC-PORT", "SOURCE-PORT":
                kind = parsePortRange(fields[1]).map(RuleKind.sourcePort)
            case "IN-PORT":
                kind = parsePortRange(fields[1]).map(RuleKind.inboundPort)
            case "GEOIP": kind = .geoIP(fields[1])
            case "IP-ASN": kind = .ipASN(fields[1])
            case "PROCESS-NAME": kind = .processName(fields[1])
            case "DEST-PORT":
                kind = parsePortRange(fields[1]).map(RuleKind.destinationPort)
            case "PROTOCOL": kind = .protocolName(fields[1])
            default:
                ignored[type, default: 0] += 1
                kind = nil
            }
            if let kind { rules.append(kind) }
        }
        return SurgeRuleSetParseResult(rules: rules, ignoredTypes: ignored)
    }

    private static func parsePortRange(_ raw: String) -> ClosedRange<UInt16>? {
        let bounds = raw.split(separator: "-", maxSplits: 1).compactMap { UInt16($0) }
        guard let first = bounds.first,
              bounds.count != 2 || bounds[1] >= first else { return nil }
        return first...(bounds.count == 2 ? bounds[1] : first)
    }

    private static func csv(_ value: String) -> [String] {
        var result: [String] = []
        var field = ""
        var quote: Character?
        for character in value {
            if let active = quote {
                if character == active { quote = nil } else { field.append(character) }
            } else if character == "\"" || character == "'" {
                quote = character
            } else if character == "," {
                result.append(field.trimmingCharacters(in: .whitespaces))
                field = ""
            } else {
                field.append(character)
            }
        }
        result.append(field.trimmingCharacters(in: .whitespaces))
        return result
    }
}

public let defaultProfileText = """
# Hajimi 示例配置。修改后点击“保存并重载”。
[General]
http-listen = 127.0.0.1:7262
socks5-listen = 127.0.0.1:7263

[Proxy]
# 示例：ProxyA = http, proxy.example.com, 8080, username, password
# 示例：ProxyB = socks5, 127.0.0.1, 1080
# 高级：SS = ss, server.example.com, 8388, aes-128-gcm, password
# 高级：VLESS = vless, server.example.com, 443, uuid, tls=true, servername=server.example.com
# 高级：HY2 = hysteria2, server.example.com, 443, password, sni=server.example.com

[Proxy Group]
Proxy = select, DIRECT

[Rule]
DOMAIN-SUFFIX,local,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT
FINAL,Proxy
"""

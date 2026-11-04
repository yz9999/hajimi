import Foundation
import Darwin
@_exported import HajimiRouting

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

/// An explicitly approved ordinary DNS endpoint for encrypted-proxy-only
/// fallback. This pure parser never resolves names or opens a connection.
/// It is deliberately separate from bootstrap/connectivity DNS settings.
public struct DNSProxyFallbackServer: Equatable {
    public let host: String
    public let port: UInt16

    public init?(_ raw: String) {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= 512,
              value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              !value.contains("%"), !value.contains("://") else { return nil }
        var host = value, port: UInt16 = 53
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]") else { return nil }
            host = String(value[value.index(after: value.startIndex)..<close])
            guard host.contains(":") else { return nil }
            let suffix = value[value.index(after: close)...]
            if !suffix.isEmpty {
                guard suffix.first == ":", let parsed = UInt16(suffix.dropFirst()), parsed > 0 else { return nil }
                port = parsed
            }
        } else if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":") {
            host = String(value[..<colon])
            guard let parsed = UInt16(value[value.index(after: colon)...]), parsed > 0 else { return nil }
            port = parsed
        }
        guard let normalized = Self.usableAddress(host) else { return nil }
        self.host = normalized; self.port = port
    }

    private static func usableIPv4(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 4, bytes[0] != 0, bytes[0] != 127, bytes[0] < 224 else { return false }
        if bytes[0] == 169 && bytes[1] == 254 { return false }
        // Cover the whole fake-IP range, including both current and legacy
        // tunnel DNS sinks, rather than blocking only one gateway address.
        if bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19) { return false }
        return true
    }

    private static func usableAddress(_ raw: String) -> String? {
        var ipv4 = in_addr()
        if raw.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            guard usableIPv4(withUnsafeBytes(of: &ipv4) { Array($0) }) else { return nil }
            var output = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &ipv4, &output, socklen_t(output.count)) != nil else { return nil }
            return String(cString: output)
        }
        var ipv6 = in6_addr()
        guard raw.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
        guard !bytes.allSatisfy({ $0 == 0 }),
              !(bytes.prefix(15).allSatisfy({ $0 == 0 }) && bytes[15] == 1),
              bytes[0] != 255, !(bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80),
              !bytes.starts(with: [0xfd, 0, 0x68, 0x61, 0x6a, 0x69]),
              !bytes.starts(with: [0xfd, 0, 0x71, 0x62]) else { return nil }
        if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 255, bytes[11] == 255 {
            guard usableIPv4(Array(bytes.suffix(4))) else { return nil }
        }
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &ipv6, &output, socklen_t(output.count)) != nil else { return nil }
        return String(cString: output)
    }
}

public enum DNSProxyFallbackValidationError: LocalizedError {
    case tooManyServers
    case noApprovedServers
    case noApprovedServersForMixedMode
    case invalidServer(Int)

    public var errorDescription: String? {
        switch self {
        case .tooManyServers: return "代理内普通 DNS 后备最多配置 8 个服务器"
        case .noApprovedServers: return "启用代理内普通 DNS 后备前，请单独填写明确批准的 IP 服务器；不会自动使用传统 DNS 栏"
        case .noApprovedServersForMixedMode: return "速度优先模式需要单独填写明确批准的普通 DNS IP 服务器；选择并保存此模式即允许名单参与日常择优，不会自动使用传统 DNS 栏"
        case .invalidServer(let index):
            return "代理内普通 DNS 后备第 \(index + 1) 项无效：请填写数字 IP 或 IP:端口；不能使用域名、URI、系统 DNS、回环、链路本地或隧道/FakeIP 地址"
        }
    }
}

/// Ordinary DNS permission is independent of the bootstrap resolver list.
/// Mixed mode is an explicit approval to use its separate numeric-IP list
/// for regular queries, always inside a qualified encrypted proxy.
public enum DNSSelectionMode: String, Codable, CaseIterable {
    case encryptedOnly = "encrypted-only"
    case balanced = "balanced"
    case mixedSpeed = "mixed-speed"
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
    public var rules: [RoutingRule] = [] {
        didSet { invalidateCompiledRoutingRules() }
    }
    public var ruleSetContents: [String: [RuleKind]] = [:] {
        didSet { invalidateCompiledRoutingRules() }
    }
    #if canImport(HajimiRoutingCXX)
    // Copies share an immutable prepared program until either rule collection
    // changes. The storage is transient and equality-neutral, like a cache.
    private var compiledRuleStorage = CompiledRoutingRuleStorage()
    #endif
    public var proxyBypassDomains: [String] = []
    /// `dns-server` now holds traditional resolvers. Encrypted entries in old
    /// profiles remain readable and are separated without rewriting the file.
    public var dnsServers: [String] = []
    public var encryptedDNSServers: [String] = []
    public var dnsSelectionMode: DNSSelectionMode = .balanced
    /// Connection preparation only; no application DNS question is sent.
    public var dnsPrewarmEnabled = true
    /// Protect DNS handled by the proxy/TUN. Disabling this is an explicit
    /// compatibility choice, never a fallback after a resolver failure.
    public var dnsLeakProtectionEnabled = true
    /// Independent opt-in to failure-only ordinary DNS in balanced mode.
    /// Other modes retain this setting without changing its authorization.
    /// Mixed mode explicitly approves the same separate server list for
    /// regular selection. The proxy exit is plaintext and can see QNAMEs.
    public var dnsProxyFallbackEnabled = false
    public var dnsProxyFallbackServers: [String] = []
    public static let maximumDNSProxyFallbackServers = 8

    public func validateDNSProxyFallbackSettings() throws {
        guard dnsProxyFallbackServers.count <= Self.maximumDNSProxyFallbackServers else {
            throw DNSProxyFallbackValidationError.tooManyServers
        }
        if dnsProxyFallbackEnabled && dnsProxyFallbackServers.isEmpty {
            throw DNSProxyFallbackValidationError.noApprovedServers
        }
        if dnsSelectionMode == .mixedSpeed && dnsProxyFallbackServers.isEmpty {
            throw DNSProxyFallbackValidationError.noApprovedServersForMixedMode
        }
        for (index, raw) in dnsProxyFallbackServers.enumerated() where DNSProxyFallbackServer(raw) == nil {
            throw DNSProxyFallbackValidationError.invalidServer(index)
        }
    }
    /// A pinned endpoint needs neither a plaintext bootstrap lookup nor the
    /// system resolver. The original name remains the TLS identity.
    public static let defaultSecureDNSServers = [
        "https://cloudflare-dns.com/dns-query#1.1.1.1"
    ]
    public var traditionalDNSServers: [String] {
        Self.uniqueDNSValues(dnsServers.filter { !Self.isEncryptedDNSValue($0) })
    }
    public var configuredEncryptedDNSServers: [String] {
        // Keep *every* value from the encrypted option, including malformed
        // ones. Runtime validation must fail closed instead of silently
        // dropping an invalid encrypted endpoint and choosing plaintext.
        Self.uniqueDNSValues(encryptedDNSServers + dnsServers.filter(Self.isEncryptedDNSValue))
    }
    public var effectiveEncryptedDNSServers: [String] {
        let configured = configuredEncryptedDNSServers
        if !configured.isEmpty { return configured }
        // Explicit encrypted/mixed modes never inherit the legacy
        // traditional-only application path, including with protection off.
        if dnsSelectionMode != .balanced { return Self.defaultSecureDNSServers }
        return traditionalDNSServers.isEmpty && dnsLeakProtectionEnabled ? Self.defaultSecureDNSServers : []
    }
    public var effectiveDNSServers: [String] {
        let encrypted = effectiveEncryptedDNSServers
        // A traditional resolver is never an application-query fallback when
        // any encrypted DNS is configured, even with protection opted out.
        return encrypted.isEmpty ? traditionalDNSServers : encrypted
    }
    private static func isEncryptedDNSValue(_ raw: String) -> Bool {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return value.hasPrefix("https://") || value.hasPrefix("tls://")
    }
    private static func uniqueDNSValues(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && seen.insert($0).inserted }
    }
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
        dnsLeakProtectionEnabled || fakeIPEnabled || !hijackDNS.isEmpty
    }

    public func skipsFakeIP(for domain: String) -> Bool {
        DomainPattern.any(alwaysRealIP, matches: domain)
    }

    public init() {}

    private mutating func invalidateCompiledRoutingRules() {
        #if canImport(HajimiRoutingCXX)
        compiledRuleStorage = CompiledRoutingRuleStorage()
        #endif
    }

    /// Prepare once when publishing a configuration, before accepting traffic.
    /// Standalone configuration tools retain the interpreter without C++.
    public func prepareCompiledRoutingRules() {
        #if canImport(HajimiRoutingCXX)
        _ = compiledRuleStorage.program(for: self)
        #endif
    }

    /// Share a prepared snapshot only after proving that its executable input
    /// is identical. Node selection, credentials and DNS settings stay local.
    @discardableResult
    public mutating func adoptCompiledRoutingRules(from source: Profile) -> Bool {
        guard rules.count == source.rules.count,
              zip(rules, source.rules).allSatisfy({ $0.kind == $1.kind }),
              ruleSetContents == source.ruleSetContents else { return false }
        #if canImport(HajimiRoutingCXX)
        compiledRuleStorage = source.compiledRuleStorage
        #endif
        return true
    }

    #if canImport(HajimiRoutingCXX)
    var preparedCompiledRoutingProgram: NativeCompiledRuleProgram? {
        compiledRuleStorage.program(for: self)
    }

    func compiledRuleSelection(for target: RequestTarget, alternateHost: String? = nil,
                               dnsSemantics: Bool = false) -> CompiledRuleSelection {
        compiledRuleStorage.program(for: self)?.match(
            target, alternateHost: alternateHost, dnsSemantics: dnsSemantics) ?? .fallback
    }
    #endif

    private enum CodingKeys: String, CodingKey {
        case httpListen, socksListen, proxies, proxyOrder, groups, groupOrder, rules
        case ruleSetContents, proxyBypassDomains, dnsServers, encryptedDNSServers
        case dnsLeakProtectionEnabled, fakeIPEnabled, alwaysRealIP, hijackDNS
        case dnsProxyFallbackEnabled, dnsProxyFallbackServers
        case dnsSelectionMode, dnsPrewarmEnabled
        case httpAPI, httpAPIKey, externalController, externalControllerKey
        case tunExcludedRoutes, tunIncludedRoutes, includeAllNetworks, warnings, surgeCompatible
    }

    /// Adding the split DNS option must not invalidate previously encoded
    /// profiles. All existing fields retain their original decoding rules.
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        httpListen = try values.decode(ListenAddress.self, forKey: .httpListen)
        socksListen = try values.decode(ListenAddress.self, forKey: .socksListen)
        proxies = try values.decode([String: ProxyPolicy].self, forKey: .proxies)
        proxyOrder = try values.decode([String].self, forKey: .proxyOrder)
        groups = try values.decode([String: PolicyGroup].self, forKey: .groups)
        groupOrder = try values.decode([String].self, forKey: .groupOrder)
        rules = try values.decode([RoutingRule].self, forKey: .rules)
        ruleSetContents = try values.decode([String: [RuleKind]].self, forKey: .ruleSetContents)
        proxyBypassDomains = try values.decode([String].self, forKey: .proxyBypassDomains)
        dnsServers = try values.decode([String].self, forKey: .dnsServers)
        encryptedDNSServers = try values.decodeIfPresent([String].self, forKey: .encryptedDNSServers) ?? []
        dnsSelectionMode = try values.decodeIfPresent(DNSSelectionMode.self, forKey: .dnsSelectionMode) ?? .balanced
        dnsPrewarmEnabled = try values.decodeIfPresent(Bool.self, forKey: .dnsPrewarmEnabled) ?? true
        dnsLeakProtectionEnabled = try values.decode(Bool.self, forKey: .dnsLeakProtectionEnabled)
        dnsProxyFallbackEnabled = try values.decodeIfPresent(Bool.self, forKey: .dnsProxyFallbackEnabled) ?? false
        dnsProxyFallbackServers = try values.decodeIfPresent([String].self, forKey: .dnsProxyFallbackServers) ?? []
        do { try validateDNSProxyFallbackSettings() }
        catch {
            throw DecodingError.dataCorruptedError(forKey: .dnsProxyFallbackServers, in: values,
                debugDescription: "Invalid explicit encrypted-proxy DNS fallback configuration")
        }
        fakeIPEnabled = try values.decode(Bool.self, forKey: .fakeIPEnabled)
        alwaysRealIP = try values.decode([String].self, forKey: .alwaysRealIP)
        hijackDNS = try values.decode([String].self, forKey: .hijackDNS)
        httpAPI = try values.decodeIfPresent(ListenAddress.self, forKey: .httpAPI)
        httpAPIKey = try values.decodeIfPresent(String.self, forKey: .httpAPIKey)
        externalController = try values.decodeIfPresent(ListenAddress.self, forKey: .externalController)
        externalControllerKey = try values.decodeIfPresent(String.self, forKey: .externalControllerKey)
        tunExcludedRoutes = try values.decode([String].self, forKey: .tunExcludedRoutes)
        tunIncludedRoutes = try values.decode([String].self, forKey: .tunIncludedRoutes)
        includeAllNetworks = try values.decode(Bool.self, forKey: .includeAllNetworks)
        warnings = try values.decode([String].self, forKey: .warnings)
        surgeCompatible = try values.decode(Bool.self, forKey: .surgeCompatible)
    }

    /// Real proxy nodes eligible for Global Proxy selection (strictly excludes policy groups, DIRECT, and REJECT).
    public var globalProxyNodes: [String] {
        var seen = Set<String>()
        return proxyOrder.filter { name in
            guard groups[name] == nil,
                  let proxy = proxies[name],
                  proxy.kind != .direct,
                  proxy.kind != .reject,
                  name != "DIRECT",
                  name != "REJECT" else {
                return false
            }
            return seen.insert(name).inserted
        }
    }

    /// Selectable policies for Global Proxy mode: strictly real proxy nodes (with DIRECT fallback),
    /// forbidding any policy group from entering Global Proxy selection.
    public var selectablePolicies: [String] {
        var result = globalProxyNodes
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
        var selection: RoutingRuleSelection = .fallback
        #if canImport(HajimiRoutingCXX)
        if mode == .rule, target.processName == nil {
            selection = compiledRuleSelection(for: target, alternateHost: alternateHost)
        }
        #endif
        return routingTable.route(for: target, mode: mode, globalPolicy: globalPolicy,
                                  groupSelections: groupSelections, alternateHost: alternateHost,
                                  compiledSelection: selection, domainMatcher: coreRoutingDomainMatch)
    }

    /// Kept as the independent semantic reference for compiled-rule checks.
    func interpretedRuleIndex(for target: RequestTarget, alternateHost: String? = nil) -> Int? {
        routingTable.interpretedRuleIndex(for: target, alternateHost: alternateHost,
                                         domainMatcher: coreRoutingDomainMatch)
    }

    func resolveRoutingPolicy(_ policy: String, target: RequestTarget,
                              groupSelections: [String: String]) -> ResolvedRoute {
        routingTable.resolvePolicy(policy, target: target, groupSelections: groupSelections)
    }

    private var routingTable: RoutingTable {
        RoutingTable(rules: rules, ruleSetContents: ruleSetContents, proxies: proxies, groups: groups)
    }
}

extension RoutingRule {
    public func matches(_ target: RequestTarget) -> Bool {
        kind.matches(target)
    }
}

extension RuleKind {
    public func matches(_ target: RequestTarget) -> Bool {
        RoutingRuleMatcher.matches(self, target: target, domainMatcher: coreRoutingDomainMatch)
    }
}

/// Preserve the existing C++ ASCII fast path while the interpreter itself
/// lives in the independent routing module. This closure never escapes a
/// synchronous match and does not transfer the native program/cache owner.
private func coreRoutingDomainMatch(_ host: String, _ pattern: String,
                                    _ kind: RoutingDomainMatchKind) -> Bool? {
    #if canImport(HajimiRoutingCXX)
    guard let nativeKind = NativeDomainMatcher.Kind(rawValue: kind.rawValue) else { return nil }
    return NativeDomainMatcher.matches(host: host, pattern: pattern, kind: nativeKind)
    #else
    return nil
    #endif
}

public struct ProfileParseError: Error, Equatable, CustomStringConvertible, LocalizedError {
    public var line: Int
    public var message: String
    public var description: String { line > 0 ? "第 \(line) 行：\(message)" : message }
    public var errorDescription: String? { description }
}

public enum ProfileParser {
    /// Fast-path parser for `[Proxy]` and `[Proxy Group]` edits where `[Rule]`
    /// bodies are unchanged (aside from line shifts and optional policy renames).
    public static func parseReusingRules(_ text: String,
                                         baseRules: [RoutingRule],
                                         replacedPolicy: (from: String, to: String)? = nil) throws -> Profile {
        try parseInternal(text, reusableRules: baseRules, replacedPolicy: replacedPolicy)
    }

    public static func parse(_ text: String) throws -> Profile {
        try parseInternal(text, reusableRules: nil, replacedPolicy: nil)
    }

    private static func parseInternal(_ text: String,
                                      reusableRules: [RoutingRule]?,
                                      replacedPolicy: (from: String, to: String)?) throws -> Profile {
        var profile = Profile()
        var section = ""
        var sectionDisplayName = ""
        var generalOptions: [String: String] = [:]
        var controllerOptionLines: [String: Int] = [:]
        var explicitHTTPListen = false
        var explicitSOCKSListen = false
        var wireGuardValues: [String: [String: String]] = [:]
        var wireGuardOrder: [String] = []
        var consumedWireGuardSections = Set<String>()
        var warnedSections = Set<String>()
        // Foundation's newline character set splits CR and LF separately.
        // Keep sourceLine aligned with physical lines for targeted UI edits.
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n")
            .components(separatedBy: .newlines)

        if text.range(of: "[wireguard ", options: .caseInsensitive) != nil {
            var wgSec = ""
            var wgDisplay = ""
            for (idx, rawL) in lines.enumerated() {
                let l = stripComment(rawL, preservingDNSBootstrap: false)
                    .trimmingCharacters(in: .whitespacesAndNewlines.union(CharacterSet(charactersIn: "\u{feff}")))
                if l.isEmpty { continue }
                if l.hasPrefix("[") && l.hasSuffix("]") && !l.contains("=") {
                    wgDisplay = String(l.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                    wgSec = wgDisplay.lowercased()
                    if wgSec.hasPrefix("wireguard ") {
                        if wireGuardValues[wgDisplay] == nil {
                            wireGuardValues[wgDisplay] = [:]
                            wireGuardOrder.append(wgDisplay)
                        }
                    }
                    continue
                }
                if wgSec.hasPrefix("wireguard "), let pair = try? keyValue(l, number: idx + 1) {
                    wireGuardValues[wgDisplay]?[pair.0.lowercased()] = pair.1
                }
            }
        }

        lineLoop: for (index, rawLine) in lines.enumerated() {
            let lineNumber = index + 1
            let line = stripComment(rawLine, preservingDNSBootstrap: section == "general")
                .trimmingCharacters(in: .whitespacesAndNewlines.union(CharacterSet(charactersIn: "\u{feff}")))
            if line.isEmpty { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") && !line.contains("=") {
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
                let policy = try proxy(name: pair.0, value: pair.1, number: lineNumber,
                                       wireGuardValues: wireGuardValues,
                                       wireGuardOrder: wireGuardOrder,
                                       consumedWireGuardSections: &consumedWireGuardSections)
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
                if let reusableRules, !reusableRules.isEmpty, profile.rules.isEmpty {
                    let hasSubsequentSection = lines[(index + 1)...].contains { candidate in
                        guard let first = candidate.first(where: { $0 != " " && $0 != "\t" }),
                              first == "[" else { return false }
                        let trimmed = stripComment(candidate, preservingDNSBootstrap: false)
                            .trimmingCharacters(in: .whitespacesAndNewlines)
                        return trimmed.hasPrefix("[") && trimmed.hasSuffix("]") && !trimmed.contains("=")
                    }
                    if !hasSubsequentSection {
                        let lineDelta = lineNumber - reusableRules[0].sourceLine
                        var adapted = reusableRules
                        for idx in adapted.indices {
                            adapted[idx].sourceLine += lineDelta
                            if let replacedPolicy, adapted[idx].policy == replacedPolicy.from {
                                adapted[idx].policy = replacedPolicy.to
                            }
                            if case .ruleSet = adapted[idx].kind {
                                profile.surgeCompatible = true
                            }
                        }
                        profile.rules = adapted
                        break lineLoop
                    }
                }
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
            if consumedWireGuardSections.contains(name) { continue }
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
        if let dns = options["encrypted-dns-server"] {
            profile.encryptedDNSServers = csv(dns).filter { !$0.isEmpty }
        }
        if let raw = options["dns-selection-mode"] {
            guard let mode = DNSSelectionMode(rawValue: raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) else {
                throw ProfileParseError(line: 0, message: "dns-selection-mode 必须为 encrypted-only、balanced 或 mixed-speed")
            }
            profile.dnsSelectionMode = mode
        }
        if let raw = options["dns-prewarm"] {
            switch raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "true", "yes", "on", "1": profile.dnsPrewarmEnabled = true
            case "false", "no", "off", "0": profile.dnsPrewarmEnabled = false
            default: throw ProfileParseError(line: 0, message: "dns-prewarm 必须为 true 或 false")
            }
        }
        if let raw = options["dns-leak-protection"] {
            switch raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "true", "yes", "on", "1": profile.dnsLeakProtectionEnabled = true
            case "false", "no", "off", "0": profile.dnsLeakProtectionEnabled = false
            default:
                throw ProfileParseError(line: 0, message: "dns-leak-protection 必须为 true 或 false")
            }
        }
        if let raw = options["dns-proxy-fallback"] {
            switch raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "true", "yes", "on", "1": profile.dnsProxyFallbackEnabled = true
            case "false", "no", "off", "0": profile.dnsProxyFallbackEnabled = false
            default: throw ProfileParseError(line: 0, message: "dns-proxy-fallback 必须为 true 或 false")
            }
        }
        if let raw = options["dns-proxy-fallback-server"] {
            profile.dnsProxyFallbackServers = csv(raw).filter { !$0.isEmpty }
        }
        do { try profile.validateDNSProxyFallbackSettings() }
        catch {
            throw ProfileParseError(line: 0, message: (error as? LocalizedError)?.errorDescription
                ?? "代理内普通 DNS 后备配置无效")
        }
        if profile.dnsSelectionMode == .mixedSpeed {
            profile.warnings.append("已选择速度优先：独立批准名单内的普通 DNS 可参与日常择优，仅经合格加密代理；本机绝不直连，但代理出口仍明文、节点可见查询域名")
        } else if profile.dnsSelectionMode == .balanced && profile.dnsProxyFallbackEnabled {
            profile.warnings.append("已启用代理内普通 DNS 后备：仅在加密 DNS 网络失败/超时时经合格加密代理回退；本机绝不直连，但代理出口仍明文、节点可见查询域名")
        }
        if !profile.dnsLeakProtectionEnabled {
            profile.warnings.append("DNS 防泄漏保护已关闭：未接管的解析可能使用系统或明文 DNS")
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
        "hidden", "show-in-status-bar", "include-all-proxies", "include-other-group", "policy-path", "url",
        "interval", "timeout", "tolerance", "evaluate-before-use", "update-interval",
        "no-alert", "external-policy-modifier", "persistent", "weight", "algorithm",
        "policy-regex-filter", "policy-regex-filter-exclude", "policy-name-filter", "icon",
        "test-url", "internet-test-url", "use-cache", "strategy", "max-failed-times",
        "include-other-group-regex", "policy-priority"
    ]

    private static func stripComment(_ line: String, preservingDNSBootstrap: Bool) -> String {
        let dnsValueStart = preservingDNSBootstrap ? Self.dnsValueStart(in: line) : nil
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

    static func dnsValueStart(in line: String) -> String.Index? {
        guard let equal = line.firstIndex(of: "=") else { return nil }
        let key = line[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
        guard key == "dns-server" || key == "encrypted-dns-server" else { return nil }
        return line.index(after: equal)
    }

    /// In either DNS option, a URL fragment is a bootstrap address only when it is
    /// attached to a DoH/DoT URL and is a complete IP literal. All other `#`
    /// characters retain their usual comment semantics, including in lists.
    static func isDNSBootstrapMarker(in line: String, at hash: String.Index,
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
        var address = String(suffix.prefix { $0 != "," && $0 != "#" && !$0.isWhitespace })
        if address.hasPrefix("["), address.hasSuffix("]") {
            address = String(address.dropFirst().dropLast())
        }
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

    private static func proxy(name: String, value: String, number: Int,
                              wireGuardValues: [String: [String: String]] = [:],
                              wireGuardOrder: [String] = [],
                              consumedWireGuardSections: inout Set<String>) throws -> ProxyPolicy {
        let fields = csv(value)
        guard let rawType = fields.first?.lowercased() else {
            throw ProfileParseError(line: number, message: "代理定义为空")
        }
        let type = canonicalProxyType(rawType)
        if type == "direct" { return ProxyPolicy(name: name, kind: .direct) }
        if type == "reject" { return ProxyPolicy(name: name, kind: .reject) }
        // Support Surge `[Proxy]` WireGuard syntax: `Node = wireguard, section-name=WGTest`
        // referencing `[WireGuard WGTest]`, or inline `wireguard, endpoint=host:port, ...`.
        if type == "wireguard",
           (fields.count < 3 || fields[1].contains("=") || UInt16(fields[2]) == nil) {
            let inlineParams = advancedParameters(type: type, fields: Array(fields.dropFirst()))
            let targetSec = (inlineParams["section-name"] ?? name).trimmingCharacters(in: .whitespaces)
            if let matchedHeader = wireGuardOrder.first(where: {
                String($0.dropFirst("WireGuard ".count))
                    .trimmingCharacters(in: .whitespaces)
                    .caseInsensitiveCompare(targetSec) == .orderedSame
            }), let wgSection = wireGuardValues[matchedHeader] {
                consumedWireGuardSections.insert(matchedHeader)
                var mergedSection = wgSection
                for (k, v) in inlineParams where k != "section-name" && mergedSection[k] == nil {
                    mergedSection[k] = v
                }
                var policy = try wireGuardPolicy(name: name, values: mergedSection, line: number)
                for (k, v) in inlineParams where k != "section-name" {
                    policy.parameters[k] = v
                }
                return policy
            }
            if let ep = inlineParams["endpoint"], let epPair = splitHostPort(ep),
               let epPort = UInt16(epPair.1), epPort > 0 {
                var params = inlineParams
                params.removeValue(forKey: "section-name")
                params.removeValue(forKey: "endpoint")
                if params["udp"] == nil { params["udp"] = "true" }
                return ProxyPolicy(name: name, kind: .external, host: epPair.0, port: epPort,
                                   adapterType: "wireguard", parameters: params)
            }
        }
        // Tolerate legacy 4-positional-field SSH syntax `ssh, host, username, port, ...`
        // in addition to standard `ssh, host, port, username=..., ...`.
        if type == "ssh", fields.count >= 4, !fields[1].isEmpty,
           UInt16(fields[2]) == nil, !fields[2].contains("="),
           let altPort = UInt16(fields[3]), altPort > 0 {
            var sshFields = ["username=\(fields[2])"]
            sshFields.append(contentsOf: fields.dropFirst(4))
            let parameters = advancedParameters(type: type, fields: sshFields)
            return ProxyPolicy(name: name, kind: .external, host: fields[1], port: altPort,
                               adapterType: type, parameters: parameters)
        }
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
                           adapterType: type, parameters: parameters)
    }

    private static let advancedProxyTypes: Set<String> = [
        "ss", "ssr", "snell", "vmess", "vless", "trojan", "anytls",
        "sudoku", "mieru", "trusttunnel",
        "hysteria", "hysteria2", "tuic", "ssh", "wireguard"
    ]

    private static func wireGuardPolicy(name: String, values: [String: String], line: Int = 0) throws -> ProxyPolicy {
        guard let privateKey = values["private-key"], !privateKey.isEmpty,
              let selfIP = values["self-ip"] ?? values["ip"], !selfIP.isEmpty,
              let rawPeer = values["peer"] else {
            throw ProfileParseError(line: line,
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
        if let dnsServer = values["dns-server"] { parameters["dns-server"] = dnsServer }
        if let allowedIPs = peerValues["allowed-ips"] { parameters["allowed-ips"] = allowedIPs }
        if let preSharedKey = peerValues["pre-shared-key"] ?? peerValues["preshared-key"] {
            parameters["pre-shared-key"] = preSharedKey
        }
        if let keepalive = peerValues["keepalive"] ?? peerValues["persistent-keepalive"] {
            parameters["persistent-keepalive"] = keepalive
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
        if let method = result["encrypt-method"], result["cipher"] == nil {
            result["cipher"] = method
        }
        if (type == "vmess" || type == "vless"),
           let username = result["username"], result["uuid"] == nil {
            result["uuid"] = username
        }
        if let authStr = result["auth-string"] ?? result["auth_str"], result["auth-str"] == nil {
            result["auth-str"] = authStr
        }
        if let upMbps = result["up_mbps"] ?? result["upmbps"], result["up"] == nil {
            result["up"] = upMbps
        }
        if let downMbps = result["down_mbps"] ?? result["downmbps"], result["down"] == nil {
            result["down"] = downMbps
        }
        if type == "wireguard" {
            if let selfIP = result.removeValue(forKey: "self-ip"), result["ip"] == nil {
                result["ip"] = selfIP
            }
            if let selfIPv6 = result.removeValue(forKey: "self-ip-v6"), result["ipv6"] == nil {
                result["ipv6"] = selfIPv6
            }
            if let psk = result.removeValue(forKey: "preshared-key"), result["pre-shared-key"] == nil {
                result["pre-shared-key"] = psk
            }
            if result["udp"] == nil {
                result["udp"] = "true"
            }
        }
        return result
    }

    private static func positionalParameterKeys(type: String, candidateCount: Int,
                                                explicitKeys: Set<String>) -> [String] {
        switch type {
        case "ss":
            return explicitKeys.contains("encrypt-method") && !explicitKeys.contains("cipher")
                ? ["password"] : ["cipher", "password"]
        case "ssr":
            return explicitKeys.contains("encrypt-method") && !explicitKeys.contains("cipher")
                ? ["password", "protocol", "obfs"] : ["cipher", "password", "protocol", "obfs"]
        case "snell": return ["psk", "version"]
        case "vmess", "vless":
            return (explicitKeys.contains("username") || explicitKeys.contains("uuid")) ? [] : ["uuid"]
        case "trojan", "anytls", "hysteria2": return ["password"]
        case "hysteria": return ["auth-str", "up", "down"]
        case "tuic":
            return candidateCount >= 2 || explicitKeys.contains("uuid") || explicitKeys.contains("password")
                ? ["uuid", "password"] : ["token"]
        case "sudoku": return ["key"]
        case "mieru", "trusttunnel": return ["username", "password"]
        case "ssh": return ["username", "password"]
        case "http", "socks5": return ["username", "password"]
        default: return []
        }
    }

    /// Known names disambiguate `key=value` options from positional secrets
    /// that themselves contain `=` (common with base64 credentials).
    private static let advancedParameterNames: Set<String> = [
        "cipher", "encrypt-method", "password", "protocol", "protocol-param", "obfs", "obfs-param",
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
        "grpc-max-streams", "reality-public-key", "reality-short-id", "short-id",
        "reality-support-x25519mlkem768", "auth", "auth-str", "auth-string", "auth_str",
        "up", "down", "up-speed", "up_mbps", "down_mbps", "upmbps", "downmbps",
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
        "server-cert-fingerprint-sha256", "tls-verification",
        "key", "aead-method", "padding-min", "padding-max", "table-type", "ascii",
        "custom-table", "custom-tables", "enable-pure-downlink", "http-mask",
        "disable-http-mask", "http-mask-mode", "http-mask-tls", "http-mask-host",
        "http-mask-multiplex", "multiplex", "path-root", "transport", "multiplexing",
        "handshake-mode", "port-range", "traffic-pattern", "quic",
        "section-name", "self-ip", "self-ip-v6", "dns-server", "keepalive",
        "preshared-key", "endpoint"
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
Proxy = select, DIRECT, include-all-proxies=true

[Rule]
DOMAIN-SUFFIX,local,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT
FINAL,Proxy
"""

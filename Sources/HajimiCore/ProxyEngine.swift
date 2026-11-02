import Foundation
import HajimiDNS
import Network
import Security
import Darwin
import HajimiProxyRuntime
import HajimiCXXProtocolBridge

// Keep the virtual origin used for application-side DNS policy checks equal
// to HelperDaemon's system DNS sink, never to the legacy Lurge gateway.
private let protectedSystemDNSGateway = "198.18.16.2"

private enum DNSApplicationResolutionPolicy {
    static func usesQueryRouter(_ profile: Profile) -> Bool {
        // Explicit encrypted DNS also governs application DIRECT hostnames.
        // Opting out of system interception does not opt out of that choice;
        // node/bootstrap resolution remains a separate facility.
        profile.dnsLeakProtectionEnabled || !profile.configuredEncryptedDNSServers.isEmpty
    }
}

public enum ProxyEngineStatus: Equatable {
    case stopped
    case starting
    case running
    case failed(String)
}

public struct ConnectionSnapshot: Equatable {
    public let id: UUID
    public let openedAt: Date
    public let client: String
    public let method: String
    public let host: String
    public let port: UInt16
    public let policy: String

    public init(id: UUID, openedAt: Date, client: String, method: String,
                host: String, port: UInt16, policy: String) {
        self.id = id
        self.openedAt = openedAt
        self.client = client
        self.method = method
        self.host = host
        self.port = port
        self.policy = policy
    }
}

public enum ProxyEngineEvent {
    case opened(ConnectionSnapshot)
    case traffic(id: UUID, uploaded: Int, downloaded: Int)
    case closed(id: UUID, error: String?)
    case message(String)
}

private func replacingReferencedRuleSetContents(in profile: Profile,
                                               with contents: [String: [RuleKind]]) throws -> Profile {
    let locations = Set(profile.ruleSetReferences.map(\.location))
    guard locations.allSatisfy({ contents[$0] != nil }) else {
        throw EngineError("RULE-SET 更新不完整，已保留当前运行规则")
    }
    var updated = profile
    for location in locations { updated.ruleSetContents[location] = contents[location] }
    return updated
}

/// An HTTP/SOCKS upstream wrapped in TLS cannot carry RFC 1928 UDP. Treat
/// malformed TLS flags as protected as well: a bad setting must not silently
/// authorize a plaintext DNS or UDP fallback.
private func isTLSOnlyUpstream(_ route: ResolvedRoute) -> Bool {
    let proxy: ProxyPolicy
    switch route {
    case .http(let value, _), .socks5(let value, _): proxy = value
    case .native(let value, _) where ["http", "https", "socks5", "socks5-tls"]
        .contains(value.adapterType?.lowercased() ?? ""): proxy = value
    default: return false
    }
    let type = proxy.adapterType?.lowercased() ?? ""
    if ["https", "socks5-tls"].contains(type) || (proxy.parameters["security"] ?? "").lowercased() == "tls" {
        return true
    }
    let flag = (proxy.parameters["tls"] ?? "false")
        .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return !["false", "no", "off", "0"].contains(flag)
}

private func safeSOCKSUDPRoute(_ selected: ResolvedRoute,
                               destinationPort: UInt16) -> ResolvedRoute {
    guard destinationPort == 53 else { return selected }
    if case .reject = selected { return selected }
    return isTLSOnlyUpstream(selected)
        ? .reject("TLS 上游不支持 UDP DNS；已阻止明文直连") : selected
}

private func safeTCPDNSRoute(_ selected: ResolvedRoute,
                             destinationPort: UInt16) -> ResolvedRoute {
    // DNS uses the same selected policy as every other TCP destination.
    // In particular, a non-TLS proxy is not permission to bypass that proxy.
    selected
}

/// Offline privacy vectors for the local SOCKS UDP DNS exception.
public enum UDPPrivacyPolicySelfTest {
    public static func failure() -> String? {
        let secureSOCKS = ProxyPolicy(name: "SecureSOCKS", kind: .socks5,
            host: "127.0.0.1", port: 443, parameters: ["tls": "true"])
        let secureHTTP = ProxyPolicy(name: "SecureHTTP", kind: .http,
            host: "127.0.0.1", port: 443, parameters: ["tls": "true"])
        let unsafeFlag = ProxyPolicy(name: "Invalid", kind: .socks5,
            host: "127.0.0.1", port: 443, parameters: ["tls": "unexpected"])
        let secureAlias = ProxyPolicy(name: "SecureAlias", kind: .socks5,
            host: "127.0.0.1", port: 443, adapterType: "socks5-tls")
        let contradictoryAlias = ProxyPolicy(name: "ContradictoryAlias", kind: .http,
            host: "127.0.0.1", port: 443, adapterType: "https", parameters: ["tls": "false"])
        let chainedTLS = ProxyPolicy(name: "ChainedTLS", kind: .native,
            host: "127.0.0.1", port: 443, adapterType: "socks5",
            parameters: ["tls": "true", "underlying-proxy": "Hop"])
        for route in [ResolvedRoute.socks5(secureSOCKS, secureSOCKS.name),
                      .http(secureHTTP, secureHTTP.name),
                      .socks5(unsafeFlag, unsafeFlag.name),
                      .socks5(secureAlias, secureAlias.name),
                      .http(contradictoryAlias, contradictoryAlias.name),
                      .native(chainedTLS, chainedTLS.name)] {
            guard case .reject = safeSOCKSUDPRoute(route, destinationPort: 53) else {
                return "TLS SOCKS/HTTPS UDP DNS must never fall back to DIRECT"
            }
        }
        guard case .direct = safeSOCKSUDPRoute(.direct("DIRECT"), destinationPort: 53) else {
            return "explicit DIRECT DNS route was unexpectedly rejected"
        }
        for port in [UInt16(53), UInt16(443)] {
            guard case .reject("DNS blocked") = safeSOCKSUDPRoute(.reject("DNS blocked"), destinationPort: port),
                  case .reject("DNS blocked") = safeTCPDNSRoute(.reject("DNS blocked"), destinationPort: port) else {
                return "an explicit REJECT must survive TCP and SOCKS UDP DNS compatibility routing"
            }
        }
        guard case .socks5 = safeTCPDNSRoute(.socks5(secureSOCKS, secureSOCKS.name), destinationPort: 53),
              case .direct = safeTCPDNSRoute(.direct("DIRECT"), destinationPort: 53) else {
            return "TCP DNS must preserve its TLS route and explicit DIRECT compatibility"
        }
        guard case .socks5 = safeSOCKSUDPRoute(.socks5(secureSOCKS, secureSOCKS.name),
                                              destinationPort: 443) else {
            return "non-DNS SOCKS route was incorrectly rewritten"
        }
        let plainSOCKS = ProxyPolicy(name: "PlainSOCKS", kind: .socks5,
                                    host: "127.0.0.1", port: 1080)
        let native = ProxyPolicy(name: "Native", kind: .native, host: "127.0.0.1", port: 443,
                                 adapterType: "trojan", parameters: ["password": "test"])
        for selected in [ResolvedRoute.socks5(plainSOCKS, plainSOCKS.name), .native(native, native.name)] {
            guard safeSOCKSUDPRoute(selected, destinationPort: 53) == selected,
                  safeTCPDNSRoute(selected, destinationPort: 53) == selected else {
                return "DNS compatibility routing bypassed the selected proxy"
            }
        }
        return nil
    }
}

private enum DNSConfiguredUpstream {
    case doh(DoHEndpoint)
    case dot(DoTEndpoint)
    case plain(host: String, port: UInt16)

    var target: RequestTarget {
        switch self {
        case .doh(let endpoint):
            return RequestTarget(host: endpoint.connectHost, port: endpoint.port, protocolName: "TCP")
        case .dot(let endpoint):
            return RequestTarget(host: endpoint.connectHost, port: endpoint.port, protocolName: "TCP")
        case .plain(let host, let port):
            return RequestTarget(host: host, port: port, protocolName: "TCP")
        }
    }

    var identityHost: String {
        switch self {
        case .doh(let endpoint): return endpoint.host
        case .dot(let endpoint): return endpoint.host
        case .plain(let host, _): return host
        }
    }

    var encrypted: Bool {
        switch self { case .doh, .dot: return true; case .plain: return false }
    }

    var builtinAddressVariants: [DNSConfiguredUpstream] {
        if case .doh(let endpoint) = self { return endpoint.builtinAddressVariants.map { .doh($0) } }
        return [self]
    }

    /// Local reverse-zone discovery can be answered here only when the
    /// configuration cannot name an enterprise resolver. Service grouping is
    /// insufficient: a familiar TLS identity may have a custom/private pin.
    var isStandardPublicEncryptedResolver: Bool {
        let host = identityHost.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let addresses: [String]
        if DoHEndpoint.isAddressLiteral(host) {
            guard EncryptedDNSBootstrap.table.values.contains(where: { $0.contains(host) }) else { return false }
            addresses = [host]
        } else {
            addresses = EncryptedDNSBootstrap.addresses(for: host)
        }
        switch self {
        case .doh(let endpoint):
            guard let components = URLComponents(url: endpoint.url, resolvingAgainstBaseURL: false),
                  components.scheme?.lowercased() == "https", components.user == nil,
                  components.password == nil, components.percentEncodedPath == "/dns-query",
                  components.percentEncodedQuery == nil, components.fragment == nil,
                  endpoint.port == 443, !endpoint.needsBootstrap else { return false }
            return addresses.contains(endpoint.connectHost)
        case .dot(let endpoint):
            return endpoint.port == 853 && addresses.contains(endpoint.connectHost)
        case .plain: return false
        }
    }

    var candidateID: String {
        let fields: [String]
        switch self {
        case .doh(let endpoint): fields = ["doh", endpoint.url.absoluteString, endpoint.connectHost]
        case .dot(let endpoint): fields = ["dot", endpoint.host, endpoint.connectHost, String(endpoint.port)]
        case .plain(let host, let port): fields = ["plain", host, String(port)]
        }
        return fields.map { "\($0.utf8.count):\($0)" }.joined()
    }

    /// A scheduling hint over already-approved endpoints, never resolver
    /// authority. A pinned dial IP does not create a different recursive
    /// service. Only standard built-in identities and their published dial
    /// addresses share aliases; custom ports, DoH paths and query parameters
    /// keep their own identity. Grouping never approves a plaintext resolver.
    var resolverServiceID: String {
        var host = identityHost.lowercased()
        if host.hasSuffix(".") { host.removeLast() }
        let builtin: String?
        switch host {
        case "dns.google", "8.8.8.8", "8.8.4.4": builtin = "google"
        case "cloudflare-dns.com", "one.one.one.one", "mozilla.cloudflare-dns.com", "1.1.1.1", "1.0.0.1": builtin = "cloudflare"
        case "doh.pub", "dot.pub", "1.12.12.12", "120.53.53.53": builtin = "dnspod"
        case "dns.alidns.com", "223.5.5.5", "223.6.6.6": builtin = "alidns"
        case "dns.quad9.net", "9.9.9.9", "149.112.112.112": builtin = "quad9"
        case "dns.adguard-dns.com", "94.140.14.14", "94.140.15.15": builtin = "adguard"
        case "dns.sb", "doh.dns.sb", "185.222.222.222", "45.11.45.11": builtin = "dnssb"
        default: builtin = nil
        }
        let fields: [String]
        switch self {
        case .doh(let endpoint):
            let components = URLComponents(url: endpoint.url, resolvingAgainstBaseURL: false)
            let path = components?.percentEncodedPath ?? endpoint.url.path
            let query = components?.percentEncodedQuery
            if let builtin, endpoint.port == 443, path == "/dns-query", query == nil {
                fields = ["builtin", builtin]
            } else {
                fields = ["doh", host, String(endpoint.port), path] + (query.map { ["query", $0] } ?? [])
            }
        case .dot(let endpoint):
            if let builtin, endpoint.port == 853 { fields = ["builtin", builtin] }
            else { fields = ["dot", host, String(endpoint.port)] }
        case .plain(_, let port):
            if let builtin, port == 53 { fields = ["builtin", builtin] }
            else { fields = ["plain", host, String(port)] }
        }
        return fields.map { "\($0.utf8.count):\($0)" }.joined()
    }
}

/// Memoizes only the pure route computation of one immutable router epoch.
/// Every original/question/resolver permission check still executes; a hit is
/// its already-computed decision, not permission to skip that check. Keys and
/// routes remain process-local and are never included in diagnostics.
private final class DNSRouteDecisionCache {
    struct Key: Hashable {
        let generation: UInt64
        let mode: String
        let name: String
        let host: String
        let port: UInt16
        let protocolName: String
        let sourceHost: String?
        let sourcePort: UInt16?
        let inboundPort: UInt16?
    }

    private let lock = NSLock()
    private let maximumEntries: Int
    private let maximumKeyBytes: Int
    private var values: [Key: ResolvedRoute] = [:]
    private var insertionOrder: [Key] = []
    private var nextEviction = 0
    private var hits: UInt64 = 0

    init(maximumEntries: Int = 1_024, maximumKeyBytes: Int = 1_024) {
        self.maximumEntries = min(1_024, max(0, maximumEntries))
        self.maximumKeyBytes = min(1_024, max(0, maximumKeyBytes))
    }

    private func mayRetain(_ key: Key) -> Bool {
        guard maximumEntries > 0, maximumKeyBytes >= 64 else { return false }
        var bytes = 64
        for field in [key.mode, key.name, key.host, key.protocolName, key.sourceHost] {
            guard let field else { continue }
            let count = field.utf8.count
            guard count <= maximumKeyBytes - bytes else { return false }
            bytes += count
        }
        return true
    }

    func lookup(_ key: Key) -> ResolvedRoute? {
        guard mayRetain(key) else { return nil }
        lock.lock(); defer { lock.unlock() }
        guard let value = values[key] else { return nil }
        if hits < UInt64.max { hits += 1 }
        return value
    }

    func insert(_ value: ResolvedRoute, for key: Key) {
        guard mayRetain(key) else { return }
        lock.lock(); defer { lock.unlock() }
        // Concurrent misses may finish in either order. The epoch is pure,
        // so keep the first decision without duplicating FIFO bookkeeping.
        guard values[key] == nil else { return }
        if insertionOrder.count < maximumEntries {
            insertionOrder.append(key)
        } else {
            values.removeValue(forKey: insertionOrder[nextEviction])
            insertionOrder[nextEviction] = key
            nextEviction = (nextEviction + 1) % maximumEntries
        }
        values[key] = value
    }

    var snapshotForSelfTest: (entries: Int, hits: UInt64) {
        lock.lock(); defer { lock.unlock() }; return (values.count, hits)
    }
}

/// DNS domain rules refer to the question, while address/source/port rules
/// still refer to the DNS connection. This also applies inside logical rules
/// and rule sets; replacing the entire destination with QNAME would lose IP
/// and source deny rules.
private struct DNSRoutingSnapshot {
    let profile: Profile
    let mode: OutboundMode
    let globalPolicy: String
    let selections: [String: String]
    let generation: UInt64
    let sourcePortSensitive: Bool
    let routeCache: DNSRouteDecisionCache?

    init(profile: Profile, mode: OutboundMode, globalPolicy: String,
         selections: [String: String], generation: UInt64,
         sourcePortSensitive: Bool, routeCache: DNSRouteDecisionCache? = nil) {
        self.profile = profile; self.mode = mode; self.globalPolicy = globalPolicy
        self.selections = selections; self.generation = generation
        self.sourcePortSensitive = sourcePortSensitive; self.routeCache = routeCache
    }

    /// UDP clients normally change their ephemeral port between questions.
    /// Only include that port when a loaded rule can observe it; all other
    /// source/inbound metadata and every policy check remain per-query.
    static func usesSourcePortRules(_ profile: Profile) -> Bool {
        func observesPort(_ kind: RuleKind, depth: Int = 0) -> Bool {
            guard depth < 32 else { return true }
            switch kind {
            case .sourcePort: return true
            case .logicalAnd(let children), .logicalOr(let children):
                return children.contains { observesPort($0, depth: depth + 1) }
            case .logicalNot(let child): return observesPort(child, depth: depth + 1)
            default: return false
            }
        }
        return profile.rules.contains { observesPort($0.kind) }
            || profile.ruleSetContents.values.contains { $0.contains { observesPort($0) } }
    }

    func queryScope(upstreams: [DNSConfiguredUpstream], route: ResolvedRoute,
                    original: RequestTarget, interfaceName: String?,
                    fallbackServers: [DNSProxyFallbackServer] = []) -> String {
        // The approved set is stable across health-driven primary changes.
        // Cache/single-flight must not authorize another resolver or inherit
        // an answer from a different policy-approved candidate set.
        let provider = ["approved-upstreams", String(upstreams.count)] + upstreams.map(\.candidateID)
        let routeFields: [String]
        switch route {
        case .direct(let name): routeFields = ["direct", name]
        case .reject(let name): routeFields = ["reject", name]
        case .http(let node, let name): routeFields = ["http", name, node.name]
        case .socks5(let node, let name): routeFields = ["socks5", name, node.name]
        case .native(let node, let name): routeFields = ["native", name, node.name]
        }
        func optional(_ value: String?) -> String { value.map { "s" + $0 } ?? "n" }
        let fallbackFields = ["proxy-fallback-v1", profile.dnsProxyFallbackEnabled ? "enabled" : "disabled",
                              String(fallbackServers.count)] + fallbackServers.flatMap { [$0.host, String($0.port)] }
        let fields = [String(generation), optional(interfaceName), profile.dnsSelectionMode.rawValue] + provider + fallbackFields + routeFields
            + [original.host, String(original.port), original.protocolName,
               optional(original.sourceHost), optional(original.inboundPort.map(String.init)),
               sourcePortSensitive ? optional(original.sourcePort.map(String.init)) : "unobserved-port"]
        // Length-prefixes prevent arbitrary policy names from creating a key
        // collision. The configuration epoch identifies the complete node,
        // including its chain, without copying credentials into cache keys.
        return fields.map { "\($0.utf8.count):\($0)" }.joined()
    }

    /// Quality observations may be shared by identical physical paths, but
    /// never carry cache, single-flight, pool or resolver authorization. A new
    /// client port must not make the same approved provider look cold again.
    /// The complete epoch, interface, selected node and approved set remain
    /// partitioned; original/source policy is still rechecked for every query.
    func healthScope(upstreams: [DNSConfiguredUpstream], route: ResolvedRoute,
                     interfaceName: String?, fallbackServers: [DNSProxyFallbackServer] = []) -> String {
        let provider = ["approved-upstreams", String(upstreams.count)] + upstreams.map(\.candidateID)
        let routeFields: [String]
        switch route {
        case .direct(let name): routeFields = ["direct", name]
        case .reject(let name): routeFields = ["reject", name]
        case .http(let node, let name): routeFields = ["http", name, node.name]
        case .socks5(let node, let name): routeFields = ["socks5", name, node.name]
        case .native(let node, let name): routeFields = ["native", name, node.name]
        }
        let interface = interfaceName.map { "s" + $0 } ?? "n"
        let ordinary = fallbackServers.flatMap { [$0.host, String($0.port)] }
        let fields = ["health-only", String(generation), interface, profile.dnsSelectionMode.rawValue] + provider + routeFields + ordinary
        return fields.map { "\($0.utf8.count):\($0)" }.joined()
    }

    /// Transport reuse is not answer reuse or query permission. Sources and
    /// original DNS destinations still partition queryScope and are checked
    /// before every lease; they do not change an already-authorized physical
    /// route. The epoch identifies the full node configuration and its chain.
    /// Keep each dial IP, authenticated identity, protocol and URL separate.
    func transportScope(upstream: DNSConfiguredUpstream, route: ResolvedRoute,
                        interfaceName: String?) -> String {
        let routeFields: [String]
        switch route {
        case .direct: routeFields = ["direct"]
        case .reject(let name): routeFields = ["reject", name]
        case .http(let node, _): routeFields = ["http", node.name]
        case .socks5(let node, _): routeFields = ["socks5", node.name]
        case .native(let node, _): routeFields = ["native", node.name]
        }
        let interface = interfaceName.map { "s" + $0 } ?? "n"
        let fields = ["transport-only-v1", String(generation), interface, upstream.candidateID] + routeFields
        return fields.map { "\($0.utf8.count):\($0)" }.joined()
    }

    func route(_ target: RequestTarget, name: String? = nil,
               mode override: OutboundMode? = nil) -> ResolvedRoute {
        let effectiveMode = override ?? mode
        guard let routeCache else { return uncachedRoute(target, name: name, mode: effectiveMode) }
        let key = DNSRouteDecisionCache.Key(generation: generation, mode: effectiveMode.rawValue,
            name: name ?? target.host, host: target.host, port: target.port,
            protocolName: target.protocolName, sourceHost: target.sourceHost,
            sourcePort: sourcePortSensitive ? target.sourcePort : nil, inboundPort: target.inboundPort)
        if let cached = routeCache.lookup(key) { return cached }
        // Neither the router configuration lock nor the cache lock is held
        // while scanning rule sets or resolving a policy group.
        let selected = uncachedRoute(target, name: name, mode: effectiveMode)
        routeCache.insert(selected, for: key)
        return selected
    }

    private func uncachedRoute(_ target: RequestTarget, name: String?,
                               mode effectiveMode: OutboundMode) -> ResolvedRoute {
        guard effectiveMode == .rule else {
            return profile.route(for: target, mode: effectiveMode, globalPolicy: globalPolicy,
                                 groupSelections: selections)
        }
        #if canImport(HajimiRoutingCXX)
        switch profile.compiledRuleSelection(for: target, alternateHost: name ?? target.host,
                                             dnsSemantics: true) {
        case .matched(let index):
            return profile.resolveRoutingPolicy(profile.rules[index].policy, target: target,
                                                groupSelections: selections)
        case .noMatch: return .direct("DIRECT")
        case .invalid: return .reject("DNS 规则递归超限或规则集循环，已阻止回退")
        case .fallback: break
        }
        #endif
        do {
            for rule in profile.rules where try matches(rule.kind, target: target, name: name ?? target.host) {
                return profile.resolveRoutingPolicy(rule.policy, target: target,
                                                    groupSelections: selections)
            }
        } catch { return .reject("DNS 规则递归超限或规则集循环，已阻止回退") }
        return .direct("DIRECT")
    }

    private func matches(_ kind: RuleKind, target: RequestTarget, name: String,
                         depth: Int = 0, ruleSets: Set<String> = []) throws -> Bool {
        guard depth < 32 else { throw DNSPolicyFailure.configuration("DNS 规则递归超限") }
        switch kind {
        case .domain, .domainSuffix, .domainKeyword, .domainWildcard:
            var named = target; named.host = name
            return kind.matches(named)
        case .logicalAnd(let children): return try children.allSatisfy {
            try matches($0, target: target, name: name, depth: depth + 1, ruleSets: ruleSets)
        }
        case .logicalOr(let children): return try children.contains {
            try matches($0, target: target, name: name, depth: depth + 1, ruleSets: ruleSets)
        }
        case .logicalNot(let child): return try !matches(child, target: target, name: name, depth: depth + 1, ruleSets: ruleSets)
        case .ruleSet(let reference):
            guard !ruleSets.contains(reference.location) else { throw DNSPolicyFailure.configuration("DNS 规则集循环") }
            var visited = ruleSets; visited.insert(reference.location)
            return try profile.ruleSetContents[reference.location]?.contains {
                try matches($0, target: target, name: name, depth: depth + 1, ruleSets: visited)
            } ?? false
        default: return kind.matches(target)
        }
    }

    func requireAllowedOriginal(_ target: RequestTarget) throws {
        for selected in [route(target), route(target, mode: .rule)] {
            if case .reject(let reason) = selected { throw DNSPolicyFailure.refused(reason) }
        }
    }

    func requireAllowedResolver(_ upstream: DNSConfiguredUpstream,
                                original: RequestTarget) throws {
        var endpoint = upstream.target
        endpoint.sourceHost = original.sourceHost; endpoint.sourcePort = original.sourcePort
        endpoint.inboundPort = original.inboundPort
        for selected in [route(endpoint, mode: .rule),
                         route(endpoint, name: upstream.identityHost, mode: .rule)] {
            if case .reject(let reason) = selected { throw DNSPolicyFailure.refused(reason) }
        }
    }

    func configuredUpstream(original: RequestTarget) throws -> DNSConfiguredUpstream {
        let encrypted = try encryptedUpstreams()
        // Once encrypted DNS is configured, traditional entries have a
        // bootstrap-only purpose, including when protection is opted out.
        // Do not even parse unrelated legacy plaintext values on this path.
        if let doh = encrypted.first(where: { if case .doh = $0 { return true }; return false }) { return doh }
        if let first = encrypted.first { return first }
        var plain: [DNSConfiguredUpstream] = []
        for raw in profile.traditionalDNSServers {
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            let lower = value.lowercased()
            if lower == "system" {
                if !profile.dnsLeakProtectionEnabled {
                    plain.append(.plain(host: original.host, port: original.port))
                }
            } else {
                guard let server = DNSUpstream.parse(value) else {
                    throw DNSPolicyFailure.configuration("DNS 上游地址无效，已阻止回退直连")
                }
                plain.append(.plain(host: server.host, port: server.port))
            }
        }
        if let first = plain.first { return first }
        if profile.dnsLeakProtectionEnabled { return Self.secureDefault }
        return .plain(host: original.host, port: original.port)
    }

    private func encryptedUpstreams() throws -> [DNSConfiguredUpstream] {
        var result: [DNSConfiguredUpstream] = []
        guard profile.effectiveEncryptedDNSServers.count <= 16 else {
            throw DNSPolicyFailure.configuration("加密 DNS 候选超过 16 个，已拒绝无界尝试")
        }
        // Validate every encrypted value, not compactMap: one malformed entry
        // must not silently replace encrypted DNS with a traditional resolver.
        for value in profile.effectiveEncryptedDNSServers {
            if value.lowercased().hasPrefix("https://") {
                guard let endpoint = DoHEndpoint(value, allowUnresolvedHost: true) else {
                    throw DNSPolicyFailure.configuration("加密 DNS 中的 DoH 地址无效")
                }
                guard !endpoint.needsBootstrap || !profile.traditionalDNSServers.isEmpty else {
                    throw DNSPolicyFailure.configuration("该 DoH 域名无固定 IP；请配置传统 DNS 用于引导")
                }
                result.append(.doh(endpoint))
            } else if value.lowercased().hasPrefix("tls://") {
                guard let endpoint = DoTEndpoint(value) else {
                    throw DNSPolicyFailure.configuration("加密 DNS 中的 DoT 地址无效或缺少固定 IP")
                }
                result.append(.dot(endpoint))
            } else { throw DNSPolicyFailure.configuration("加密 DNS 只能使用 https:// 或 tls://，已阻止传统回退") }
        }
        return result
    }

    func permitsLocalServiceDiscoveryResponse() throws -> Bool {
        // Examine every original entry, including resolvers excluded by
        // policy. An optional enterprise plaintext fallback also keeps the
        // query on its existing upstream path, regardless of current route.
        guard profile.dnsSelectionMode != .mixedSpeed,
              !(profile.dnsSelectionMode == .balanced && profile.dnsProxyFallbackEnabled) else { return false }
        let configured = try encryptedUpstreams()
        return !configured.isEmpty && configured.allSatisfy(\.isStandardPublicEncryptedResolver)
    }

    func approvedCandidates(original: RequestTarget) throws -> [DNSUpstreamCandidate] {
        let configured = try encryptedUpstreams()
        if configured.isEmpty {
            let upstream = try configuredUpstream(original: original)
            try requireAllowedResolver(upstream, original: original)
            return [DNSUpstreamCandidate(upstream: upstream, bootstrap: nil)]
        }
        // Preserve the historic DoH-first cold start. Interleave addresses by
        // waves, so every configured provider's first IP precedes its backup.
        // This is still the same configured provider, URL and TLS identity.
        let providers = configured.filter { if case .doh = $0 { return true }; return false }
            + configured.filter { if case .doh = $0 { return false }; return true }
        let variants = providers.map(\.builtinAddressVariants)
        guard variants.reduce(0, { $0 + $1.count }) <= 32 else {
            throw DNSPolicyFailure.configuration("加密 DNS 批准地址超过 32 个，已拒绝无界候选")
        }
        let waves = variants.map(\.count).max() ?? 0
        let ordered = (0..<waves).flatMap { wave in variants.compactMap { wave < $0.count ? $0[wave] : nil } }
        var approved: [DNSUpstreamCandidate] = [], refusal: Error?, seen = Set<String>()
        for upstream in ordered {
            do {
                try requireAllowedResolver(upstream, original: original)
                let bootstrap = try bootstrapConfiguration(for: upstream, original: original)
                if seen.insert(upstream.candidateID).inserted {
                    approved.append(DNSUpstreamCandidate(upstream: upstream, bootstrap: bootstrap))
                }
            } catch DNSPolicyFailure.refused(let reason) {
                // A blocked resolver is not a failed exchange and receives no
                // dial or health penalty. Original/QNAME deny checks happen
                // outside this filter and always terminate the query.
                refusal = DNSPolicyFailure.refused(reason)
            }
        }
        guard !approved.isEmpty else {
            throw refusal ?? DNSPolicyFailure.refused("全部已配置加密 DNS 解析器被策略拒绝")
        }
        return approved
    }

    func approvedProxyFallbackServers(route selected: ResolvedRoute,
                                      original: RequestTarget) throws -> [DNSProxyFallbackServer] {
        guard profile.dnsSelectionMode == .mixedSpeed ||
                (profile.dnsSelectionMode == .balanced && profile.dnsProxyFallbackEnabled) else { return [] }
        guard
              DNSProxyFallbackTransportPolicy.permits(selected, policies: profile.proxies) else { return [] }
        do { try profile.validateDNSProxyFallbackSettings() }
        catch { throw DNSPolicyFailure.configuration("代理 DNS 回退需要有效且显式授权的数字解析器列表") }
        var approved: [DNSProxyFallbackServer] = []
        for raw in profile.dnsProxyFallbackServers {
            guard let server = DNSProxyFallbackServer(raw) else {
                throw DNSPolicyFailure.configuration("代理 DNS 回退解析器无效，已阻止降级")
            }
            do {
                try requireAllowedResolver(.plain(host: server.host, port: server.port), original: original)
                if !approved.contains(server) { approved.append(server) }
            } catch DNSPolicyFailure.refused {
                // A denied optional resolver is not an unavailable encrypted
                // provider. It never dials, and cannot authorize another path.
                continue
            }
        }
        return approved
    }

    func bootstrapConfiguration(for upstream: DNSConfiguredUpstream,
                                original: RequestTarget) throws -> DNSBootstrapConfiguration? {
        guard case .doh(let endpoint) = upstream, endpoint.needsBootstrap else { return nil }
        let allowed = try encryptedUpstreams().compactMap { value -> String? in
            guard case .doh(let doh) = value, !DoHEndpoint.isAddressLiteral(doh.host) else { return nil }
            return doh.host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        }
        let configuration = DNSBootstrapConfiguration(servers: profile.traditionalDNSServers,
                                                       allowedHosts: Array(Set(allowed)).sorted())
        try requireAllowedBootstrap(configuration, host: endpoint.host, original: original)
        return configuration
    }

    func requireAllowedBootstrap(_ configuration: DNSBootstrapConfiguration, host: String,
                                  original: RequestTarget) throws {
        let normalized = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard configuration.allowedHosts.contains(normalized), !configuration.servers.isEmpty else {
            throw DNSPolicyFailure.configuration("传统 DNS 仅允许引导已配置的 DoH 域名")
        }
        for raw in configuration.servers {
            guard let server = TraditionalDNSServer(raw) else {
                throw DNSPolicyFailure.configuration("DoH 引导需要有效的传统 DNS IP，不能使用系统 DNS 或递归地址")
            }
            // The bootstrap exchange can upgrade a truncated UDP answer to
            // TCP. Deny either path before invoking the shared resolver.
            for proto in ["UDP", "TCP"] {
                let target = RequestTarget(host: server.host, port: server.port, protocolName: proto,
                    sourceHost: original.sourceHost, sourcePort: original.sourcePort, inboundPort: original.inboundPort)
                for route in [route(target, mode: .rule), route(target, name: normalized, mode: .rule)] {
                    if case .reject(let reason) = route { throw DNSPolicyFailure.refused(reason) }
                }
            }
        }
    }

    static var secureDefault: DNSConfiguredUpstream {
        // A literal bootstrap prevents the DNS transport from depending on
        // the system resolver it is replacing. No plaintext fallback exists.
        .doh(DoHEndpoint("https://cloudflare-dns.com/dns-query#1.1.1.1")!)
    }
}

private enum DNSPolicyFailure: LocalizedError {
    case refused(String)
    case configuration(String)
    var errorDescription: String? {
        switch self { case .refused(let text): return "DNS 策略拒绝：\(text)"
        case .configuration(let text): return text }
    }
    var responseCode: DNSResponseCode {
        switch self { case .refused: return .refused; case .configuration: return .servfail }
    }
}

private struct DNSQueryPlan {
    let upstream: DNSConfiguredUpstream
    let candidates: [DNSUpstreamCandidate]
    let route: ResolvedRoute
    let original: RequestTarget
    let generation: UInt64
    let bootstrap: DNSBootstrapConfiguration?
    let scopeKey: String
    let healthScopeKey: String
    let interfaceName: String?
    let questionName: String?
    let fallbackServers: [DNSProxyFallbackServer]

    init(upstream: DNSConfiguredUpstream, candidates: [DNSUpstreamCandidate], route: ResolvedRoute,
         original: RequestTarget, generation: UInt64, bootstrap: DNSBootstrapConfiguration?,
         scopeKey: String, healthScopeKey: String, interfaceName: String?,
         questionName: String? = nil, fallbackServers: [DNSProxyFallbackServer] = []) {
        self.upstream = upstream; self.candidates = candidates; self.route = route; self.original = original
        self.generation = generation; self.bootstrap = bootstrap; self.scopeKey = scopeKey
        self.healthScopeKey = healthScopeKey; self.interfaceName = interfaceName
        self.questionName = questionName; self.fallbackServers = fallbackServers
    }
}

private struct DNSUpstreamCandidate {
    let upstream: DNSConfiguredUpstream
    let bootstrap: DNSBootstrapConfiguration?
    var id: String { upstream.candidateID }
}

private struct DNSBootstrapConfiguration: Hashable {
    let servers: [String]
    let allowedHosts: [String]
}

private struct DNSBootstrapCacheKey: Hashable {
    let generation: UInt64
    let configuration: DNSBootstrapConfiguration
    let interfaceName: String?
}

private enum DNSQueryPreparation {
    case answer(Data, generation: UInt64)
    case upstream(DNSQueryPlan)
}

private final class WeakDNSQueryDatagram {
    weak var value: PolicyDNSDatagram?
    init(_ value: PolicyDNSDatagram) { self.value = value }
}

/// Listener-free routing core used directly by the utun data plane.
public final class NativePacketRouter {
    public static func setOutboundInterface(name: String?,
                                            completion: @escaping (Result<Void, Error>) -> Void) {
        guard let name else { OutboundInterfaceBinding.set(nil); completion(.success(())); return }
        OutboundInterfaceBinding.resolve(name: name, completion: completion)
    }
    private let configurationLock = NSLock()
    private var profile: Profile
    private var mode: OutboundMode
    private var globalPolicy: String
    private var groupSelections: [String: String]
    private var configurationGeneration: UInt64 = 0
    private var dnsSourcePortSensitive: Bool
    private var profileUsesProcessRules = false
    // Replace, never reset, at every epoch transition: an old snapshot may
    // finish computing after reload, but can populate only its old cache.
    private var dnsRouteCache = DNSRouteDecisionCache()
    /// UDP/443 fallback and UDP-reject are consulted on every datagram.
    /// Caching the last few destinations avoids re-stringifying and
    /// re-walking the rule table tens of thousands of times a second.
    private var udpCapabilityCache: [UDPCapabilityKey: (generation: UInt64, quicFallback: Bool, reject: Bool)] = [:]
    private struct UDPCapabilityKey: Hashable {
        let host: String
        let resolvedHost: String
        let alternateHost: String?
        let port: UInt16
        let sourceHost: String?
        let sourcePort: UInt16?
        let inboundPort: UInt16?
    }
    private let dnsMapping = DNSMappingCache()
    private let dnsQueryCoordinator = DNSQueryCoordinator(maximumActiveUpstreams: 64)
    private let dnsAdaptiveSelector = DNSAdaptiveUpstreamSelector()
    // Assigned only by the explicitly guarded CLI fixture below. Production
    // initializers never accept test anchors or a configurable TLS override.
    private var loopbackFixtureDNSStreamDialer: EncryptedDNSStreamDialer?
    private var loopbackFixtureDNSTLSUpgrader: DNSFixtureTLSUpgrader?
    // Assigned only by the memory-only regression entry below. This is not
    // an initializer option, a live configuration or a production TLS hook.
    fileprivate var memoryFixtureDNSStreamDialer: MetadataAwareEncryptedDNSStreamDialer?
    fileprivate var memoryFixtureAfterDNSFlushUnlock: (() -> Void)?
    private let fakeIP: FakeIPAllocator
    private let dohLock = NSLock()
    private let dohResolvers = BoundedConnectionOwnerCache<String, DoHResolver>(
        maximumEntries: 64, maximumBytes: 2 * 1_024 * 1_024)
    private let dotResolvers = BoundedConnectionOwnerCache<String, DoTResolver>(
        maximumEntries: 64, maximumBytes: 2 * 1_024 * 1_024)
    private let proxyTCPDNSResolvers = BoundedConnectionOwnerCache<String, ProxyTCPDNSResolver>(
        maximumEntries: 64, maximumBytes: 2 * 1_024 * 1_024)
    private var bootstrapResolvers: [DNSBootstrapCacheKey: TraditionalDNSBootstrapResolver] = [:]
    private var dnsFlows: [WeakDNSQueryDatagram] = []
    private let dnsPrewarmQueue = DispatchQueue(label: "app.hajimi.dns.prewarm", qos: .utility)
    private struct DNSPrewarmIdentity: Equatable {
        let generation: UInt64
        let interfaceName: String?
    }
    private var dnsPrewarmIdentity: DNSPrewarmIdentity?
    private var dnsPrewarmActivated = false
    private var dnsPrewarmWork: DispatchWorkItem?
    private var dnsPrewarmFlows: [UUID: NativeRoutedDatagram] = [:]

    public init(profile: Profile, mode: OutboundMode, globalPolicy: String,
                groupSelections: [String: String],
                fakeIPStoreURL: URL? = nil) {
        profile.prepareCompiledRoutingRules()
        self.profile = profile; self.mode = mode; self.globalPolicy = globalPolicy
        self.groupSelections = groupSelections
        self.dnsSourcePortSensitive = DNSRoutingSnapshot.usesSourcePortRules(profile)
        self.profileUsesProcessRules = Self.containsProcessNameRules(profile)
        self.fakeIP = fakeIPStoreURL.map(FakeIPAllocator.init(persistingAt:)) ?? FakeIPAllocator()
        NativeOutboundFactory.configure(policies: profile.proxies)
    }

    public func update(profile: Profile, mode: OutboundMode, globalPolicy: String,
                       groupSelections: [String: String]) {
        profile.prepareCompiledRoutingRules()
        // Keep existing fake-IP mappings. A connection opened against an
        // address minted before the reload still has to reverse-map; wiping
        // here also destroyed the on-disk store every time a group flipped.
        // Names that now route DIRECT simply stop receiving new synthetics.
        configurationLock.lock()
        let proxiesChanged = self.profile.proxies != profile.proxies
        self.profile = profile; self.mode = mode; self.globalPolicy = globalPolicy
        self.groupSelections = groupSelections
        dnsSourcePortSensitive = DNSRoutingSnapshot.usesSourcePortRules(profile)
        profileUsesProcessRules = Self.containsProcessNameRules(profile)
        configurationGeneration &+= 1
        dnsRouteCache = DNSRouteDecisionCache()
        udpCapabilityCache.removeAll(keepingCapacity: true)
        let flows = dnsFlows.compactMap(\.value)
        dnsFlows = flows.map(WeakDNSQueryDatagram.init)
        let retireDNSResources = detachEncryptedResolversLocked()
        // Publish the matching complete node/chain table before exposing this
        // router epoch. When only mode/group selections or rules changed, avoid
        // bumping the C++ outbound generation and cancelling in-flight handshakes.
        if proxiesChanged {
            NativeOutboundFactory.configure(policies: profile.proxies)
        }
        // Enqueue invalidation before exposing the new epoch. A freshly
        // prepared query can then never be ahead of this old-work flush.
        dnsQueryCoordinator.invalidate()
        configurationLock.unlock()
        retireDNSResources()
        flows.forEach { $0.invalidateForPolicyUpdate() }
        rescheduleDNSPrewarmIfActive()
    }

    public func updateSelections(mode: OutboundMode, globalPolicy: String,
                                 groupSelections: [String: String]) {
        configurationLock.lock()
        guard self.mode != mode || self.globalPolicy != globalPolicy || self.groupSelections != groupSelections else {
            configurationLock.unlock()
            return
        }
        self.mode = mode; self.globalPolicy = globalPolicy
        self.groupSelections = groupSelections
        configurationGeneration &+= 1
        dnsRouteCache = DNSRouteDecisionCache()
        udpCapabilityCache.removeAll(keepingCapacity: true)
        let flows = dnsFlows.compactMap(\.value)
        dnsFlows = flows.map(WeakDNSQueryDatagram.init)
        let retireDNSResources = detachEncryptedResolversLocked()
        dnsQueryCoordinator.invalidate()
        configurationLock.unlock()
        retireDNSResources()
        flows.forEach { $0.invalidateForPolicyUpdate() }
        rescheduleDNSPrewarmIfActive()
    }

    /// Rule bodies change policy/DNS authority, but never node credentials or
    /// carrier ownership. Reconfiguring the outbound factory here would close
    /// shared mux streams that are already carrying application traffic.
    @discardableResult
    fileprivate func updateRuleSetContents(from prepared: Profile) throws -> Bool {
        configurationLock.lock()
        var updated: Profile
        do { updated = try replacingReferencedRuleSetContents(in: profile, with: prepared.ruleSetContents) }
        catch { configurationLock.unlock(); throw error }
        guard updated.ruleSetContents != profile.ruleSetContents else {
            configurationLock.unlock(); return false
        }
        // The engine compiled this immutable snapshot before taking our lock.
        // Do not build the same indexes twice or block DNS readers to do so.
        guard updated.adoptCompiledRoutingRules(from: prepared) else {
            configurationLock.unlock()
            throw EngineError("RULE-SET 准备结果与当前规则不一致，已保留运行规则")
        }
        profile = updated
        dnsSourcePortSensitive = DNSRoutingSnapshot.usesSourcePortRules(updated)
        profileUsesProcessRules = Self.containsProcessNameRules(updated)
        configurationGeneration &+= 1
        dnsRouteCache = DNSRouteDecisionCache()
        udpCapabilityCache.removeAll(keepingCapacity: true)
        let flows = dnsFlows.compactMap(\.value)
        dnsFlows = flows.map(WeakDNSQueryDatagram.init)
        let retireDNSResources = detachEncryptedResolversLocked()
        dnsQueryCoordinator.invalidate()
        configurationLock.unlock()
        retireDNSResources()
        flows.forEach { $0.invalidateForPolicyUpdate() }
        rescheduleDNSPrewarmIfActive()
        return true
    }

    private static func containsProcessNameRules(_ profile: Profile) -> Bool {
        func kindUsesProcess(_ kind: RuleKind) -> Bool {
            switch kind {
            case .processName: return true
            case .logicalAnd(let children), .logicalOr(let children):
                return children.contains(where: kindUsesProcess)
            case .logicalNot(let child):
                return kindUsesProcess(child)
            case .ruleSet(let ref):
                return profile.ruleSetContents[ref.location]?.contains(where: kindUsesProcess) ?? false
            default:
                return false
            }
        }
        return profile.rules.contains { kindUsesProcess($0.kind) }
    }

    private func route(for target: RequestTarget) -> ResolvedRoute {
        configurationLock.lock()
        let profile = self.profile, mode = self.mode, policy = globalPolicy
        let selections = groupSelections
        let usesProcess = profileUsesProcessRules
        configurationLock.unlock()
        var effectiveTarget = target
        if usesProcess, effectiveTarget.processName == nil, let port = effectiveTarget.sourcePort, port > 0 {
            let isTCP = effectiveTarget.protocolName.uppercased() != "UDP"
            effectiveTarget.processName = LocalProcessSocketCache.shared.resolveProcessPath(port: port, isTCP: isTCP)
        }
        return profile.route(for: effectiveTarget, mode: mode, globalPolicy: policy,
                             groupSelections: selections,
                             alternateHost: dnsMapping.domain(for: effectiveTarget.host))
    }

    /// Maps a fake-IP address back to the hostname it was minted for.
    ///
    /// TCP already did this before dialling; UDP/QUIC must use the same path so
    /// domain rules and the outbound destination see the name rather than a
    /// 198.19.0.0/16 address that no server can reach.
    public func resolvedDestinationHost(_ host: String) -> String {
        fakeIP.domain(for: host) ?? host
    }

    /// Returns true only when UDP/443 would be tunnelled through a reliable
    /// byte stream.  Native UDP/QUIC routes remain untouched.
    public func prefersTCPFallbackForQUIC(host: String, sourceHost: String? = nil,
                                         sourcePort: UInt16? = nil, inboundPort: UInt16? = nil) -> Bool {
        udpCapability(host: host, port: 443, sourceHost: sourceHost,
                      sourcePort: sourcePort, inboundPort: inboundPort).quicFallback
    }

    /// True when the selected outbound cannot carry this datagram at all.
    ///
    /// Dropping it silently makes every UDP-dependent application wait out its
    /// own timeout — a browser retries QUIC, a game client stalls, a resolver
    /// hangs. An ICMP port-unreachable says so immediately, which is what lets
    /// them fall back to TCP or report a clear error.
    public func rejectsUDP(host: String, port: UInt16, sourceHost: String? = nil,
                           sourcePort: UInt16? = nil, inboundPort: UInt16? = nil) -> Bool {
        // DNS is an application protocol here, not an exception granting
        // permission to send a raw UDP packet. Its query policy is checked
        // once the QNAME is available, and a TCP-only proxy can carry framed
        // DNS through that same proxy. Invalid configuration still fails shut.
        if port == 53 {
            let target = RequestTarget(host: resolvedDestinationHost(host), port: port,
                                       protocolName: "UDP", sourceHost: sourceHost,
                                       sourcePort: sourcePort, inboundPort: inboundPort)
            do {
                let snapshot = dnsSnapshot()
                try snapshot.requireAllowedOriginal(target)
                _ = try snapshot.configuredUpstream(original: target)
                return false
            } catch { return true }
        }
        return udpCapability(host: host, port: port, sourceHost: sourceHost,
                             sourcePort: sourcePort, inboundPort: inboundPort).reject
    }

    private func udpCapability(host: String, port: UInt16, sourceHost: String?,
                               sourcePort: UInt16?, inboundPort: UInt16?) -> (quicFallback: Bool, reject: Bool) {
        while true {
            configurationLock.lock()
            let generation = configurationGeneration
            // DNS/fake-IP aliases may change or expire without a profile reload.
            // Cache the exact identities used by this routing computation, not
            // just the literal destination that happened to represent them.
            let resolved = resolvedDestinationHost(host)
            let alternate = dnsMapping.domain(for: resolved)
            let key = UDPCapabilityKey(host: host, resolvedHost: resolved, alternateHost: alternate,
                                      port: port, sourceHost: sourceHost,
                                      sourcePort: sourcePort, inboundPort: inboundPort)
            if let cached = udpCapabilityCache[key], cached.generation == generation {
                configurationLock.unlock()
                return (cached.quicFallback, cached.reject)
            }
            // Route and cache admission must share ONE configuration snapshot.
            // route(for:) takes its own snapshot, which could otherwise combine
            // an old capability computation with a newly cleared generation.
            let snapshot = (profile: profile, mode: mode, policy: globalPolicy, selections: groupSelections)
            configurationLock.unlock()
            let target = RequestTarget(host: resolved, port: port,
                                       protocolName: "UDP", sourceHost: sourceHost,
                                       sourcePort: sourcePort, inboundPort: inboundPort)
            let selected = snapshot.profile.route(for: target, mode: snapshot.mode,
                globalPolicy: snapshot.policy, groupSelections: snapshot.selections,
                alternateHost: alternate)
            let value: (Bool, Bool)
            switch selected {
            case .direct:
                value = (false, false)
            case .reject, .http, .socks5:
                value = (false, true)
            case .native(let policy, _):
                value = (NativeOutboundFactory.carriesUDPOverReliableStream(policy),
                         !NativeOutboundFactory.supportsUDP(policy))
            }
            configurationLock.lock()
            guard configurationGeneration == generation else {
                configurationLock.unlock()
                continue // Never return or re-cache a superseded route result.
            }
            if udpCapabilityCache.count >= 2_048 { udpCapabilityCache.removeAll(keepingCapacity: true) }
            udpCapabilityCache[key] = (generation, value.0, value.1)
            configurationLock.unlock()
            return value
        }
    }

    /// Fake-IP applies only where a name would actually be proxied; direct
    /// destinations keep their real addresses so LAN hosts, captive portals and
    /// split-tunnel rules behave exactly as before. `always-real-ip` wins.
    private func wouldProxy(_ name: String) -> Bool {
        configurationLock.lock()
        let skip = profile.skipsFakeIP(for: name)
        configurationLock.unlock()
        if skip { return false }
        let target = RequestTarget(host: name, port: 443, protocolName: "TCP")
        switch route(for: target) {
        case .http, .socks5, .native: return true
        case .direct, .reject: return false
        }
    }

    public func shouldSynthesizeFakeIP(for name: String) -> Bool {
        wouldProxy(name)
    }

    /// True when the selected outbound node explicitly disables IPv6 forwarding
    /// (`ipv6=false` or `ip-version=ipv4-only`), allowing AAAA lookups to
    /// fast-return an empty NOERROR without waiting on Happy Eyeballs timeout.
    public static func policyDisablesIPv6(_ policy: ProxyPolicy) -> Bool {
        let ipv6Flag = policy.parameters["ipv6"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let ipVersion = policy.parameters["ip-version"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ipv6Flag == "false" || ipv6Flag == "0" || ipv6Flag == "no" || ipVersion == "ipv4-only" || ipVersion == "v4-only"
    }

    public func shouldSuppressAAAA(for name: String) -> Bool {
        let target = RequestTarget(host: name, port: 443, protocolName: "TCP")
        switch route(for: target) {
        case .native(let policy, _), .http(let policy, _), .socks5(let policy, _):
            return Self.policyDisablesIPv6(policy)
        case .direct, .reject:
            return false
        }
    }

    public func flushFakeIP() {
        fakeIP.removeAll()
    }

    public func fakeIPSnapshot() -> [(domain: String, address: String)] {
        fakeIP.snapshot()
    }

    public func hostname(forFakeAddress address: String) -> String? {
        fakeIP.domain(for: address)
    }

    private func dnsSnapshot() -> DNSRoutingSnapshot {
        configurationLock.lock(); defer { configurationLock.unlock() }
        return DNSRoutingSnapshot(profile: profile, mode: mode, globalPolicy: globalPolicy,
                                  selections: groupSelections, generation: configurationGeneration,
                                  sourcePortSensitive: dnsSourcePortSensitive, routeCache: dnsRouteCache)
    }

    fileprivate func dnsRoutingSnapshotForSelfTest() -> DNSRoutingSnapshot { dnsSnapshot() }

    fileprivate func isCurrentDNSGeneration(_ generation: UInt64) -> Bool {
        configurationLock.lock(); defer { configurationLock.unlock() }
        return generation == configurationGeneration
    }

    private func isCurrentDNSPlan(_ plan: DNSQueryPlan) -> Bool {
        isCurrentDNSGeneration(plan.generation)
            && ProxyEngine.currentOutboundInterface?.name == plan.interfaceName
    }

    /// Called while holding configurationLock, with the epoch transition.
    /// Detach old owners atomically; cancellation happens outside all locks.
    /// A new-epoch lease can neither be cleared accidentally nor arrive as an
    /// old-key insertion after this detach (commit uses the same lock order).
    private func detachEncryptedResolversLocked() -> () -> Void {
        dnsPrewarmWork?.cancel(); dnsPrewarmWork = nil; dnsPrewarmIdentity = nil
        let warming = Array(dnsPrewarmFlows.values); dnsPrewarmFlows.removeAll()
        dnsAdaptiveSelector.removeAll()
        dohLock.lock()
        let doh = dohResolvers.remove { _ in true }, dot = dotResolvers.remove { _ in true }
        let proxyTCP = proxyTCPDNSResolvers.remove { _ in true }
        let bootstrap = Array(bootstrapResolvers.values)
        bootstrapResolvers.removeAll()
        dohLock.unlock()
        return {
            warming.forEach { transport in
                if let acknowledging = transport as? DNSQueryCancellationAcknowledging {
                    acknowledging.cancel(reason: .policyChanged, completion: {})
                } else { transport.cancel() }
            }
            doh.forEach { $0.cancel(reason: .policyChanged) }; dot.forEach { $0.cancel(reason: .policyChanged) }
            proxyTCP.forEach { $0.cancel(reason: .policyChanged) }
            bootstrap.forEach { $0.cancel() }
        }
    }

    fileprivate func cancelDNSQueries(keepFlows: Bool = false) {
        configurationLock.lock()
        if !keepFlows { dnsPrewarmActivated = false }
        configurationGeneration &+= 1
        dnsRouteCache = DNSRouteDecisionCache()
        let flows = dnsFlows.compactMap(\.value)
        dnsFlows = keepFlows ? flows.map(WeakDNSQueryDatagram.init) : []
        let retireDNSResources = detachEncryptedResolversLocked()
        dnsQueryCoordinator.invalidate()
        configurationLock.unlock()
        memoryFixtureAfterDNSFlushUnlock?()
        retireDNSResources()
        flows.forEach { if keepFlows { $0.invalidateForPolicyUpdate() } else { $0.cancel() } }
    }

    /// Forget answers and pooled transports without changing any routes or
    /// system DNS settings. Existing associations may issue fresh questions.
    public func flushDNS(prewarm: Bool = true) {
        dnsMapping.removeAll()
        cancelDNSQueries(keepFlows: true)
        if prewarm { rescheduleDNSPrewarmIfActive() }
    }

    private func rescheduleDNSPrewarmIfActive() {
        configurationLock.lock(); let active = dnsPrewarmActivated; configurationLock.unlock()
        if active { prewarmDNS() }
    }

    /// Returns immediately. Only this router's already-approved encrypted
    /// routes are prepared; each later question still authorizes its own lease.
    public func prewarmDNS(immediately: Bool = false) {
        configurationLock.lock()
        dnsPrewarmActivated = true
        let identity = DNSPrewarmIdentity(generation: configurationGeneration,
                                         interfaceName: ProxyEngine.currentOutboundInterface?.name)
        guard profile.dnsPrewarmEnabled, dnsPrewarmIdentity != identity else {
            configurationLock.unlock(); return
        }
        dnsPrewarmWork?.cancel()
        let old = Array(dnsPrewarmFlows.values); dnsPrewarmFlows.removeAll()
        dnsPrewarmIdentity = identity
        let work = DispatchWorkItem { [weak self] in self?.beginDNSPrewarm(identity) }
        dnsPrewarmWork = work
        configurationLock.unlock()
        old.forEach { transport in
            if let acknowledging = transport as? DNSQueryCancellationAcknowledging {
                acknowledging.cancel(reason: .prewarmSuperseded, completion: {})
            } else { transport.cancel() }
        }
        // An enhanced-mode reader is prepared before routes capture any
        // traffic, so its final router can warm concurrently with the Helper.
        if immediately { dnsPrewarmQueue.async(execute: work) }
        else { dnsPrewarmQueue.asyncAfter(deadline: .now() + 0.25, execute: work) }
    }

    private func beginDNSPrewarm(_ identity: DNSPrewarmIdentity) {
        guard isCurrentDNSGeneration(identity.generation),
              ProxyEngine.currentOutboundInterface?.name == identity.interfaceName,
              let query = DNSMessageInspection.query(for: "dns-prewarm.invalid", type: 1, id: 0) else { return }
        let original = RequestTarget(host: "198.18.16.2", port: 53, protocolName: "UDP")
        guard case .upstream(let plan) = try? prepareDNSQuery(query, original: original, synthesizeFakeIP: false),
              plan.generation == identity.generation, plan.upstream.encrypted else { return }
        // Use each configured provider's first approved path; no plaintext,
        // queries, health success or periodic polling is generated here.
        for candidate in plan.candidates.prefix(2) {
            do {
                let chosen = try revalidatedCandidatePlan(plan, candidate: candidate)
                let token = UUID(), started = NetworkPerformanceDiagnostics.now()
                let transport = try makeDNSUpstream(plan: chosen, queue: dnsPrewarmQueue,
                    receive: { _ in }, failure: { _ in })
                guard let preparation = transport as? DNSConnectionPrewarming else { transport.cancel(); continue }
                configurationLock.lock()
                guard dnsPrewarmIdentity == identity, profile.dnsPrewarmEnabled,
                      configurationGeneration == identity.generation,
                      ProxyEngine.currentOutboundInterface?.name == identity.interfaceName else {
                    configurationLock.unlock()
                    if let acknowledging = transport as? DNSQueryCancellationAcknowledging {
                        acknowledging.cancel(reason: .policyChanged, completion: {})
                    } else { transport.cancel() }
                    return
                }
                dnsPrewarmFlows[token] = transport
                // Register before the epoch lock is released; detach will
                // cancel even an in-progress pool registration via its fence.
                preparation.prewarm(absoluteDeadline: ProcessInfo.processInfo.systemUptime + 3) { [weak self] result in
                    guard let self else { return }
                    self.dnsPrewarmQueue.async {
                        self.configurationLock.lock()
                        let completed = self.dnsPrewarmFlows.removeValue(forKey: token)
                        let current = self.dnsPrewarmIdentity == identity
                        self.configurationLock.unlock()
                        if let acknowledging = completed as? DNSQueryCancellationAcknowledging {
                            acknowledging.cancel(reason: .cleanup, completion: {})
                        } else { completed?.cancel() }
                        let outcome: NetworkPerformanceOutcome
                        if !current { outcome = .cancelled }
                        else if case .success = result { outcome = .success }
                        else if case .failure(.cancelled) = result { outcome = .cancelled }
                        else { outcome = .failure }
                        NetworkPerformanceDiagnostics.shared.record(.dnsConnectionPrewarm,
                            milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started), outcome: outcome)
                    }
                }
                configurationLock.unlock()
            } catch { continue }
        }
    }

    fileprivate func prepareDNSQuery(_ data: Data, original: RequestTarget,
                                      synthesizeFakeIP: Bool = true) throws -> DNSQueryPreparation {
        let preparationStarted = NetworkPerformanceDiagnostics.now()
        defer {
            // Policy preparation precedes the wire coordinator, including on
            // a DNS answer-cache hit. Do not count another logical query or
            // label a deliberate policy refusal as an upstream failure.
            NetworkPerformanceDiagnostics.shared.record(.dnsPolicyPreparation,
                milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: preparationStarted))
        }
        let snapshot = dnsSnapshot()
        try snapshot.requireAllowedOriginal(original)
        guard let question = DNSMessageInspection.singleQuestion(in: data) else {
            guard let response = DNSMessageInspection.errorResponse(to: data, code: .formerr) else {
                throw DNSPolicyFailure.configuration("DNS 查询格式无效")
            }
            return .answer(response, generation: snapshot.generation)
        }
        var routingTarget = original
        if original.host == protectedSystemDNSGateway, !question.name.isEmpty {
            // Do not let the synthetic TUN DNS gateway IP (198.18.16.2) match
            // IP-CIDR,198.18.0.0/15,DIRECT in LAN rules before domain rules and
            // FINAL policy evaluation.
            routingTarget.host = question.name
        }
        let selected = snapshot.route(routingTarget, name: question.name)
        for route in [selected, snapshot.route(routingTarget, name: question.name, mode: .rule)] {
            if case .reject(let reason) = route { throw DNSPolicyFailure.refused(reason) }
        }
        var candidates = try snapshot.approvedCandidates(original: original)
        var upstream = candidates[0].upstream
        if case .direct = selected, snapshot.profile.dnsLeakProtectionEnabled, !upstream.encrypted {
            // Explicit plaintext resolvers remain usable through a selected
            // proxy. A DIRECT name rule is not permission for plaintext DNS
            // while leak protection is enabled.
            upstream = DNSRoutingSnapshot.secureDefault
            try snapshot.requireAllowedResolver(upstream, original: original)
            candidates = [DNSUpstreamCandidate(upstream: upstream, bootstrap: nil)]
        }
        let bootstrap = candidates[0].bootstrap
        if synthesizeFakeIP, snapshot.profile.fakeIPEnabled, !snapshot.profile.skipsFakeIP(for: question.name),
           question.`class` == 1, let synthetic = FakeIPResponder.question(in: data) {
            switch selected {
            case .http, .socks5, .native:
                let address = synthetic.kind == .a ? fakeIP.address(for: synthetic.name) : nil
                if let answer = FakeIPResponder.reply(to: data, question: synthetic, address: address) {
                    return .answer(answer, generation: snapshot.generation)
                }
            case .direct, .reject: break
            }
        }
        if question.type == 28, question.`class` == 1,
           let synthetic = FakeIPResponder.question(in: data) {
            switch selected {
            case .native(let policy, _), .http(let policy, _), .socks5(let policy, _):
                if Self.policyDisablesIPv6(policy),
                   let answer = FakeIPResponder.reply(to: data, question: synthetic, address: nil) {
                    return .answer(answer, generation: snapshot.generation)
                }
            case .direct, .reject:
                break
            }
        }
        let interfaceName = ProxyEngine.currentOutboundInterface?.name
        let fallbackServers = upstream.encrypted
            ? try snapshot.approvedProxyFallbackServers(route: selected, original: original) : []
        if let answer = DNSMessageInspection.localServiceDiscoveryResponse(to: data, question: question),
           try snapshot.permitsLocalServiceDiscoveryResponse() {
            // All original/QNAME/resolver/configuration checks above still
            // run. Deliver through the same epoch/cancellation fence as other
            // local answers; do not cache this empty discovery result.
            return .answer(answer, generation: snapshot.generation)
        }
        return .upstream(DNSQueryPlan(upstream: upstream, candidates: candidates, route: selected,
                                      original: original, generation: snapshot.generation, bootstrap: bootstrap,
                                      scopeKey: snapshot.queryScope(upstreams: candidates.map(\.upstream), route: selected,
                                          original: original, interfaceName: interfaceName, fallbackServers: fallbackServers),
                                      healthScopeKey: snapshot.healthScope(upstreams: candidates.map(\.upstream),
                                          route: selected, interfaceName: interfaceName, fallbackServers: fallbackServers),
                                      interfaceName: interfaceName, questionName: question.name, fallbackServers: fallbackServers))
    }

    fileprivate func makeDNSDatagram(original: RequestTarget, queue: DispatchQueue,
                                      synthesizeFakeIP: Bool = true,
                                      receive: @escaping (Data) -> Void,
                                      failure: @escaping (Error) -> Void) throws -> PolicyDNSDatagram {
        let snapshot = dnsSnapshot()
        try snapshot.requireAllowedOriginal(original)
        _ = try snapshot.configuredUpstream(original: original)
        let flow = try PolicyDNSDatagram(router: self, original: original, queue: queue,
                                        synthesizeFakeIP: synthesizeFakeIP,
                                        receive: { [weak self] data in
            self?.recordDNSResponse(data); receive(data)
        }, failure: failure)
        configurationLock.lock()
        dnsFlows.removeAll { $0.value == nil }
        dnsFlows.append(WeakDNSQueryDatagram(flow))
        configurationLock.unlock()
        return flow
    }

    fileprivate func makeDNSUpstream(plan: DNSQueryPlan, queue: DispatchQueue,
                                    receive: @escaping (Data) -> Void,
                                    failure: @escaping (Error) -> Void) throws -> NativeRoutedDatagram {
        guard isCurrentDNSPlan(plan) else {
            throw DNSPolicyFailure.configuration("DNS 策略已更新，请重新查询")
        }
        if case .doh(let endpoint) = plan.upstream, endpoint.needsBootstrap {
            let resolver = try bootstrapResolver(for: plan)
            let interfaceName = plan.interfaceName
            return DoHBootstrapDatagram(endpoint: endpoint, resolver: resolver, queue: queue,
                permitted: { [weak self] in
                    self?.isCurrentDNSGeneration(plan.generation) == true
                        && ProxyEngine.currentOutboundInterface?.name == interfaceName
                }, makeEncrypted: { [weak self] address in
                    guard let self else { throw EngineError("DNS 路由核心已释放") }
                    let resolved = try self.resolvedBootstrapPlan(plan, address: address)
                    return try self.makeDNSUpstream(plan: resolved, queue: queue, receive: receive, failure: failure)
                }, failure: failure)
        }
        let dialer: MetadataAwareEncryptedDNSStreamDialer = { [weak self] host, port, name, queue, trace, observeFailure, completion in
            let route: DNSAttemptRoute
            if case .direct = plan.route { route = .direct } else { route = .proxy }
            trace.setRoute(route, identity: plan.healthScopeKey)
            guard let self, self.isCurrentDNSPlan(plan),
                  DoHEndpoint.isAddressLiteral(host) else {
                let error = EngineError("DNS 路由已更新或 bootstrap 不是 IP，已阻止直连回退")
                trace.record(.transportFailure, error: error, admitting: { observeFailure(error) })
                if DoHEndpoint.isAddressLiteral(host) { trace.cancel(.policyChanged) }
                completion(.failure(error))
                return nil
            }
            if let fixtureDialer = self.memoryFixtureDNSStreamDialer {
                // The fixture cannot turn an arbitrary resolver or real node
                // into an unverified encrypted transport. Its only peers are
                // loopback and documentation-range metadata; no sockets exist.
                let fixtureHost = host == "127.0.0.1" || host.hasPrefix("192.0.2.")
                    || host.hasPrefix("198.51.100.") || host.hasPrefix("203.0.113.")
                guard fixtureHost else {
                    completion(.failure(EncryptedDNSQueryFailure.configuration)); return nil
                }
                return fixtureDialer(host, port, name, queue, trace, observeFailure) { result in
                    if case .failure(let error) = result { observeFailure(error) }
                    guard self.isCurrentDNSPlan(plan) else {
                        if case .success(let stream) = result { stream.cancel() }
                        completion(.failure(EncryptedDNSQueryFailure.policy)); return
                    }
                    completion(result)
                }
            }
            if let fixtureDialer = self.loopbackFixtureDNSStreamDialer {
                guard case .direct = plan.route, host == "127.0.0.1", name == "127.0.0.1" else {
                    completion(.failure(EngineError("DNS 回环 fixture 不允许外部地址或代理路由"))); return nil
                }
                fixtureDialer(host, port, name, queue) { result in
                    if case .failure(let error) = result { observeFailure(error) }
                    guard self.isCurrentDNSPlan(plan) else {
                        if case .success(let stream) = result { stream.cancel() }
                        completion(.failure(EngineError("DNS 路由已更新"))); return
                    }
                    completion(result)
                }
                return nil
            }
            let target = RequestTarget(host: host, port: port, protocolName: "TCP")
            let alpn: [String]
            if case .dot = plan.upstream { alpn = [] } else { alpn = ["http/1.1"] }
            let attempt = DNSRoutedTLSConnectionAttempt(queue: queue,
                permitted: { self.isCurrentDNSPlan(plan) }, connect: { ready in
                    TunnelConnector.beginConnect(route: plan.route, target: target, plainHTTP: false,
                        queue: queue, waitForSetupAcknowledgement: true) {
                            ready($0.map { $0.0 })
                        }
                }, upgrade: { stream, observeTLSFailure, ready in
                    if let fixtureUpgrade = self.loopbackFixtureDNSTLSUpgrader {
                        return fixtureUpgrade(stream, host, port, name, queue, alpn, trace, observeTLSFailure, ready)
                    }
                    return NativeOutboundFactory.beginTLSUpgrade(stream: stream, serverName: name,
                        queue: queue, alpn: alpn, failureObserver: observeTLSFailure,
                        attemptTrace: trace, completion: ready)
                }, failureObserver: observeFailure, attemptTrace: trace, completion: completion)
            attempt.start()
            return { attempt.cancel() }
        }
        // Never use the protected answer/source scope as a physical pool key.
        // Fresh queries have already passed revalidatedCandidatePlan; a lease
        // shares only this authenticated path, not cached answers or authority.
        let snapshot = dnsSnapshot()
        guard snapshot.generation == plan.generation else { throw EncryptedDNSQueryFailure.policy }
        let key = snapshot.transportScope(upstream: plan.upstream, route: plan.route,
                                          interfaceName: plan.interfaceName)
        switch plan.upstream {
        case .doh(let endpoint):
            configurationLock.lock()
            guard configurationGeneration == plan.generation,
                  ProxyEngine.currentOutboundInterface?.name == plan.interfaceName else {
                configurationLock.unlock(); throw EncryptedDNSQueryFailure.policy
            }
            dohLock.lock()
            if let lease = dohResolvers.acquire(key) {
                dohLock.unlock(); configurationLock.unlock()
                return DNSResolverLeaseDatagram(transport: DoHRoutedDatagram(resolver: lease.owner,
                    receive: receive, failure: failure), owner: lease)
            }
            let resolver = DoHResolver(endpoint: endpoint, metadataStreamDialer: dialer)
            let insertion = dohResolvers.insert(resolver, for: key, cost: key.utf8.count + 1_024)
            dohLock.unlock(); configurationLock.unlock()
            guard let insertion else { resolver.cancel(); throw EncryptedDNSQueryFailure.capacity }
            insertion.retired.forEach { $0.cancel() }
            return DNSResolverLeaseDatagram(transport: DoHRoutedDatagram(resolver: insertion.lease.owner,
                receive: receive, failure: failure), owner: insertion.lease)
        case .dot(let endpoint):
            configurationLock.lock()
            guard configurationGeneration == plan.generation,
                  ProxyEngine.currentOutboundInterface?.name == plan.interfaceName else {
                configurationLock.unlock(); throw EncryptedDNSQueryFailure.policy
            }
            dohLock.lock()
            if let lease = dotResolvers.acquire(key) {
                dohLock.unlock(); configurationLock.unlock()
                return DNSResolverLeaseDatagram(transport: DoTRoutedDatagram(resolver: lease.owner,
                    receive: receive, failure: failure), owner: lease)
            }
            let resolver = DoTResolver(endpoint: endpoint, metadataStreamDialer: dialer)
            let insertion = dotResolvers.insert(resolver, for: key, cost: key.utf8.count + 1_024)
            dohLock.unlock(); configurationLock.unlock()
            guard let insertion else { resolver.cancel(); throw EncryptedDNSQueryFailure.capacity }
            insertion.retired.forEach { $0.cancel() }
            return DNSResolverLeaseDatagram(transport: DoTRoutedDatagram(resolver: insertion.lease.owner,
                receive: receive, failure: failure), owner: insertion.lease)
        case .plain:
            if case .direct = plan.route, plan.original.protocolName != "TCP" {
                return try DirectRoutedDatagram(target: plan.upstream.target, queue: queue,
                                                permitted: { [weak self] in
                    self?.isCurrentDNSGeneration(plan.generation) ?? false
                }, receive: receive, failure: failure)
            }
            // DNS over TCP is supported by HTTP CONNECT, SOCKS and stream-only
            // native nodes too. A missing UDP relay must never mean DIRECT.
            return TCPDNSQueryDatagram(route: plan.route, target: plan.upstream.target,
                                       queue: queue, permitted: { [weak self] in
                self?.isCurrentDNSPlan(plan) ?? false
            }, receive: receive, failure: failure)
        }
    }

    fileprivate func makeOptimizedDNSUpstream(plan: DNSQueryPlan, queue: DispatchQueue,
        factory: DNSQueryCoordinator.Factory? = nil,
        adaptiveFactory: DNSAdaptiveQueryDatagram.Factory? = nil, adaptiveTimeout: TimeInterval = 8,
        proxyTCPFactory: DNSProxyFallbackResolverSequence.Factory? = nil,
        queryDeadline: TimeInterval? = nil,
        receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) throws -> NativeRoutedDatagram {
        guard isCurrentDNSPlan(plan) else { throw DNSPolicyFailure.configuration("DNS 策略或网络接口已更新") }
        let selectionMode = dnsSnapshot().profile.dnsSelectionMode
        let build: DNSQueryCoordinator.Factory = factory ?? { [weak self] queue, receive, failure in
            guard let self else { throw EngineError("DNS 路由核心已释放") }
            if plan.upstream.encrypted {
                let maximum = adaptiveTimeout.isFinite ? min(8, max(0.001, adaptiveTimeout)) : 8
                let remaining = queryDeadline.map { $0 - ProcessInfo.processInfo.systemUptime } ?? maximum
                guard remaining.isFinite, remaining > 0 else { throw DNSQueryTimeoutError() }
                if selectionMode == .mixedSpeed, !plan.fallbackServers.isEmpty {
                    let deadline = queryDeadline ?? (ProcessInfo.processInfo.systemUptime + min(maximum, remaining))
                    // Explicit mixed-mode approval is separate from failure
                    // fallback. Start encrypted first on a cold scope, then
                    // let the same bounded selector compare approved TCP DNS.
                    let ordinary = plan.fallbackServers.map {
                        DNSUpstreamCandidate(upstream: .plain(host: $0.host, port: $0.port), bootstrap: nil)
                    }
                    let count = max(plan.candidates.count, ordinary.count)
                    let mixed = (0..<count).flatMap { index -> [DNSUpstreamCandidate] in
                        var wave: [DNSUpstreamCandidate] = []
                        if index < plan.candidates.count { wave.append(plan.candidates[index]) }
                        if index < ordinary.count { wave.append(ordinary[index]) }
                        return wave
                    }.prefix(32).map { $0 }
                    return DNSAdaptiveQueryDatagram(candidates: mixed, selector: self.dnsAdaptiveSelector,
                        scopeKey: plan.healthScopeKey, queue: queue,
                        permitted: { [weak self] in self?.isCurrentDNSPlan(plan) ?? false },
                        factory: { [weak self] candidate, worker, receive, failure in
                            guard let self else { throw EncryptedDNSQueryFailure.configuration }
                            if candidate.upstream.encrypted {
                                if let adaptiveFactory { return try adaptiveFactory(candidate, worker, receive, failure) }
                                let chosen = try self.revalidatedCandidatePlan(plan, candidate: candidate)
                                return try self.makeDNSUpstream(plan: chosen, queue: worker, receive: receive, failure: failure)
                            }
                            guard case .plain(let host, let port) = candidate.upstream,
                                  let server = plan.fallbackServers.first(where: { $0.host == host && $0.port == port }) else {
                                throw EncryptedDNSQueryFailure.policy
                            }
                            if let proxyTCPFactory {
                                _ = try self.revalidatedProxyFallbackPlan(plan, server: server)
                                return try proxyTCPFactory(server, worker, deadline, receive, failure)
                            }
                            return try self.makeProxyTCPFallbackUpstream(plan: plan, server: server,
                                absoluteDeadline: deadline, receive: receive, failure: failure)
                        }, receive: receive, failure: failure,
                        availability: adaptiveFactory == nil ? { [weak self] in self?.dnsTransportAvailability(plan: plan, candidate: $0) } : nil,
                        timeout: min(maximum, remaining),
                        absoluteDeadline: deadline, allowApprovedProxyPlaintext: true)
                }
                if !plan.fallbackServers.isEmpty {
                    let deadline = queryDeadline ?? (ProcessInfo.processInfo.systemUptime + min(maximum, remaining))
                    let candidateFactory: DNSAdaptiveQueryDatagram.Factory = adaptiveFactory ?? { [weak self] candidate, worker, receive, failure in
                        guard let self else { throw EncryptedDNSQueryFailure.configuration }
                        let chosen = try self.revalidatedCandidatePlan(plan, candidate: candidate)
                        return try self.makeDNSUpstream(plan: chosen, queue: worker, receive: receive, failure: failure)
                    }
                    return DNSProxyFallbackQueryDatagram(queue: queue, absoluteDeadline: deadline,
                        permitted: { [weak self] in self?.isCurrentDNSPlan(plan) ?? false },
                        knownMilliseconds: { [weak self] in
                            guard let self else { return [] }
                            return plan.candidates.compactMap {
                                self.dnsAdaptiveSelector.planningLatencyMilliseconds(scopeKey: plan.healthScopeKey, candidateID: $0.id)
                            }
                        }, encrypted: { [weak self] worker, absolute, receive, failure in
                            guard let self else { throw EncryptedDNSQueryFailure.configuration }
                            return DNSAdaptiveQueryDatagram(candidates: plan.candidates, selector: self.dnsAdaptiveSelector,
                                scopeKey: plan.healthScopeKey, queue: worker,
                                permitted: { [weak self] in self?.isCurrentDNSPlan(plan) ?? false },
                                factory: candidateFactory, receive: receive, failure: failure,
                                availability: adaptiveFactory == nil ? { [weak self] in self?.dnsTransportAvailability(plan: plan, candidate: $0) } : nil,
                                timeout: min(8, max(0.001, absolute - ProcessInfo.processInfo.systemUptime)),
                                absoluteDeadline: absolute, protectProxyFallback: true)
                        }, fallback: { [weak self] worker, absolute, receive, failure in
                            guard let self else { throw EncryptedDNSQueryFailure.configuration }
                            let fields = ["proxy-tcp-fallback-v2", plan.healthScopeKey]
                                + plan.fallbackServers.flatMap { [$0.host, String($0.port)] }
                            let healthScope = fields.map { "\($0.utf8.count):\($0)" }.joined()
                            return DNSProxyFallbackResolverSequence(servers: plan.fallbackServers,
                                selector: self.dnsAdaptiveSelector, scopeKey: healthScope,
                                queue: worker, absoluteDeadline: absolute,
                                permitted: { [weak self] in self?.isCurrentDNSPlan(plan) ?? false },
                                factory: { [weak self] server, worker, deadline, receive, failure in
                                    guard let self else { throw EncryptedDNSQueryFailure.configuration }
                                    if let proxyTCPFactory {
                                        _ = try self.revalidatedProxyFallbackPlan(plan, server: server)
                                        return try proxyTCPFactory(server, worker, deadline, receive, failure)
                                    }
                                    return try self.makeProxyTCPFallbackUpstream(plan: plan, server: server,
                                        absoluteDeadline: deadline, receive: receive, failure: failure)
                                }, receive: receive, failure: failure)
                        }, receive: receive, failure: failure)
                }
                return DNSAdaptiveQueryDatagram(candidates: plan.candidates, selector: self.dnsAdaptiveSelector,
                    scopeKey: plan.healthScopeKey, queue: queue,
                    permitted: { [weak self] in self?.isCurrentDNSPlan(plan) ?? false },
                    factory: adaptiveFactory ?? { [weak self] candidate, queue, receive, failure in
                        guard let self else { throw EngineError("DNS 路由核心已释放") }
                        let chosen = try self.revalidatedCandidatePlan(plan, candidate: candidate)
                        return try self.makeDNSUpstream(plan: chosen, queue: queue, receive: receive, failure: failure)
                    }, receive: receive, failure: failure,
                    availability: adaptiveFactory == nil ? { [weak self] in self?.dnsTransportAvailability(plan: plan, candidate: $0) } : nil,
                    timeout: min(maximum, remaining),
                    absoluteDeadline: queryDeadline)
            }
            NetworkPerformanceDiagnostics.shared.recordDNS(.upstreamAttempt)
            return try self.makeDNSUpstream(plan: plan, queue: queue, receive: receive, failure: failure)
        }
        let start: DNSQueryCoordinator.Factory = { worker, receive, failure in
            if let deadline = queryDeadline {
                guard deadline.isFinite, deadline > ProcessInfo.processInfo.systemUptime else { throw DNSQueryTimeoutError() }
            }
            let transport = try build(worker, receive, failure)
            if let deadline = queryDeadline, deadline <= ProcessInfo.processInfo.systemUptime {
                transport.cancel(); throw DNSQueryTimeoutError()
            }
            return transport
        }
        return DNSCoalescedQueryDatagram(coordinator: dnsQueryCoordinator, scope: plan.scopeKey, queue: queue,
            absoluteDeadline: queryDeadline,
            permitted: { [weak self] in self?.isCurrentDNSPlan(plan) ?? false },
            factory: start, receive: receive, failure: failure)
    }

    /// Read scalar pool pressure using the same physical scope as the factory.
    /// This supplies no routing authority, bootstrap result or transport lease;
    /// makeDNSUpstream still revalidates the selected candidate before IO.
    private func dnsTransportAvailability(plan: DNSQueryPlan,
                                          candidate: DNSUpstreamCandidate) -> (reusable: Int, cold: Int)? {
        guard candidate.upstream.encrypted,
              plan.candidates.contains(where: { $0.id == candidate.id }) else { return nil }
        let snapshot = dnsSnapshot()
        guard snapshot.generation == plan.generation,
              ProxyEngine.currentOutboundInterface?.name == plan.interfaceName else { return nil }
        let key = snapshot.transportScope(upstream: candidate.upstream, route: plan.route,
                                          interfaceName: plan.interfaceName)
        switch candidate.upstream {
        case .doh(let endpoint):
            guard !endpoint.needsBootstrap else { return nil }
            return dohResolvers.peek(key)?.schedulingAvailability
                ?? (reusable: 0, cold: DoHResolver.maximumConcurrentConnectionAttempts)
        case .dot:
            return dotResolvers.peek(key)?.schedulingAvailability
                ?? (reusable: 0, cold: DoTResolver.maximumConcurrentConnectionAttempts)
        case .plain: return nil
        }
    }

    private func revalidatedCandidatePlan(_ plan: DNSQueryPlan, candidate: DNSUpstreamCandidate) throws -> DNSQueryPlan {
        guard isCurrentDNSPlan(plan), plan.candidates.contains(where: { $0.id == candidate.id }) else {
            throw DNSPolicyFailure.configuration("DNS 候选不在批准集合内或策略已更新")
        }
        let snapshot = dnsSnapshot()
        try snapshot.requireAllowedOriginal(plan.original)
        try snapshot.requireAllowedResolver(candidate.upstream, original: plan.original)
        if let bootstrap = candidate.bootstrap {
            try snapshot.requireAllowedBootstrap(bootstrap, host: candidate.upstream.identityHost, original: plan.original)
        }
        return DNSQueryPlan(upstream: candidate.upstream, candidates: plan.candidates, route: plan.route,
                            original: plan.original, generation: plan.generation, bootstrap: candidate.bootstrap,
                            scopeKey: plan.scopeKey, healthScopeKey: plan.healthScopeKey,
                            interfaceName: plan.interfaceName, questionName: plan.questionName,
                            fallbackServers: plan.fallbackServers)
    }

    fileprivate func revalidatedProxyFallbackPlan(_ plan: DNSQueryPlan, server: DNSProxyFallbackServer) throws -> DNSQueryPlan {
        guard isCurrentDNSPlan(plan), plan.upstream.encrypted, plan.fallbackServers.contains(server),
              let name = plan.questionName else { throw EncryptedDNSQueryFailure.policy }
        let snapshot = dnsSnapshot()
        guard snapshot.profile.dnsSelectionMode == .mixedSpeed ||
                (snapshot.profile.dnsSelectionMode == .balanced && snapshot.profile.dnsProxyFallbackEnabled) else {
            throw EncryptedDNSQueryFailure.policy
        }
        guard
              DNSProxyFallbackTransportPolicy.permits(plan.route, policies: snapshot.profile.proxies),
              snapshot.route(plan.original, name: name) == plan.route else { throw EncryptedDNSQueryFailure.policy }
        try snapshot.requireAllowedOriginal(plan.original)
        if case .reject = snapshot.route(plan.original, name: name, mode: .rule) { throw EncryptedDNSQueryFailure.policy }
        let approved = try snapshot.approvedProxyFallbackServers(route: plan.route, original: plan.original)
        guard approved == plan.fallbackServers else { throw EncryptedDNSQueryFailure.policy }
        let upstream = DNSConfiguredUpstream.plain(host: server.host, port: server.port)
        try snapshot.requireAllowedResolver(upstream, original: plan.original)
        return DNSQueryPlan(upstream: upstream, candidates: plan.candidates, route: plan.route,
            original: plan.original, generation: plan.generation, bootstrap: nil,
            scopeKey: plan.scopeKey, healthScopeKey: plan.healthScopeKey, interfaceName: plan.interfaceName,
            questionName: plan.questionName, fallbackServers: plan.fallbackServers)
    }

    /// Authorization belongs to this question; the key and owner carry only
    /// its actual authenticated transport. Source-port changes can reuse a
    /// clean DNS TCP stream only after this independent route revalidation.
    fileprivate func makeProxyTCPFallbackUpstream(plan: DNSQueryPlan, server: DNSProxyFallbackServer,
        absoluteDeadline: TimeInterval, dialer injectedDialer: MetadataAwareEncryptedDNSStreamDialer? = nil,
        receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) throws -> (NativeRoutedDatagram & DNSQueryCancellationAcknowledging) {
        let chosen = try revalidatedProxyFallbackPlan(plan, server: server)
        guard absoluteDeadline.isFinite, absoluteDeadline > ProcessInfo.processInfo.systemUptime else {
            throw DNSQueryTimeoutError()
        }
        let snapshot = dnsSnapshot()
        guard snapshot.generation == chosen.generation else { throw EncryptedDNSQueryFailure.policy }
        let key = "proxy-tcp-fallback-v1|" + snapshot.transportScope(
            upstream: chosen.upstream, route: chosen.route, interfaceName: chosen.interfaceName)
        let permitted: () -> Bool = { [weak self] in self?.isCurrentDNSPlan(chosen) ?? false }
        let dialer: MetadataAwareEncryptedDNSStreamDialer = { host, port, name, worker, trace, observeFailure, done in
            trace.setRoute(.proxy, identity: chosen.healthScopeKey)
            guard permitted(), host == server.host, port == server.port, name == server.host else {
                observeFailure(EncryptedDNSQueryFailure.policy); done(.failure(EncryptedDNSQueryFailure.policy)); return nil
            }
            if let injectedDialer { return injectedDialer(host, port, name, worker, trace, observeFailure, done) }
            // The selected route was revalidated as an encrypted, verified
            // proxy. Its native cancellation receipt retains physical setup
            // admission until the real callback, including after a timeout.
            return TunnelConnector.beginConnect(route: chosen.route, target: chosen.upstream.target,
                plainHTTP: false, queue: worker, waitForSetupAcknowledgement: true) { result in
                    if case .failure(let error) = result { observeFailure(error) }
                    guard permitted() else {
                        if case .success(let pair) = result { pair.0.cancel() }
                        done(.failure(EncryptedDNSQueryFailure.policy)); return
                    }
                    switch result {
                    case .failure(let error): done(.failure(error))
                    case .success(let pair):
                        guard pair.1.isEmpty else {
                            pair.0.cancel(); observeFailure(EncryptedDNSQueryFailure.invalidResponse)
                            done(.failure(EncryptedDNSQueryFailure.invalidResponse)); return
                        }
                        done(.success(pair.0))
                    }
                }
        }
        configurationLock.lock()
        guard configurationGeneration == chosen.generation,
              ProxyEngine.currentOutboundInterface?.name == chosen.interfaceName else {
            configurationLock.unlock(); throw EncryptedDNSQueryFailure.policy
        }
        dohLock.lock()
        let lease: BoundedConnectionOwnerLease<ProxyTCPDNSResolver>
        if let existing = proxyTCPDNSResolvers.acquire(key) {
            lease = existing; dohLock.unlock(); configurationLock.unlock()
        } else {
            let resolver = ProxyTCPDNSResolver(server: server, metadataStreamDialer: dialer)
            let insertion = proxyTCPDNSResolvers.insert(resolver, for: key, cost: key.utf8.count + 1_024)
            dohLock.unlock(); configurationLock.unlock()
            guard let insertion else { resolver.cancel(); throw EncryptedDNSQueryFailure.capacity }
            insertion.retired.forEach { $0.cancel() }; lease = insertion.lease
        }
        return DNSResolverLeaseDatagram(transport: ProxyTCPDNSRoutedDatagram(resolver: lease.owner,
            absoluteDeadline: absoluteDeadline, permitted: permitted, receive: receive, failure: failure), owner: lease)
    }

    fileprivate func bootstrapResolver(for plan: DNSQueryPlan,
                                         exchange: TraditionalDNSWireExchange? = nil) throws -> TraditionalDNSBootstrapResolver {
        guard isCurrentDNSPlan(plan), let configuration = plan.bootstrap else {
            throw DNSPolicyFailure.configuration("DoH 引导配置缺失或策略已更新")
        }
        let snapshot = dnsSnapshot()
        try snapshot.requireAllowedBootstrap(configuration, host: plan.upstream.identityHost, original: plan.original)
        let key = DNSBootstrapCacheKey(generation: plan.generation, configuration: configuration,
                                      interfaceName: plan.interfaceName)
        configurationLock.lock()
        guard configurationGeneration == plan.generation,
              ProxyEngine.currentOutboundInterface?.name == plan.interfaceName else {
            configurationLock.unlock(); throw EncryptedDNSQueryFailure.policy
        }
        dohLock.lock()
        if let resolver = bootstrapResolvers[key] { dohLock.unlock(); configurationLock.unlock(); return resolver }
        var evicted: [TraditionalDNSBootstrapResolver] = []
        if bootstrapResolvers.count >= 16 { evicted = Array(bootstrapResolvers.values); bootstrapResolvers.removeAll() }
        let resolver = TraditionalDNSBootstrapResolver(servers: configuration.servers,
            allowedDoHHosts: configuration.allowedHosts, timeout: 4, exchange: exchange)
        bootstrapResolvers[key] = resolver; dohLock.unlock(); configurationLock.unlock()
        evicted.forEach { $0.cancel() }
        return resolver
    }

    fileprivate func resolvedBootstrapPlan(_ plan: DNSQueryPlan, address: String) throws -> DNSQueryPlan {
        guard isCurrentDNSPlan(plan), case .doh(let endpoint) = plan.upstream,
              let configuration = plan.bootstrap,
              TraditionalDNSServer(address) != nil,
              let resolved = endpoint.resolvingBootstrap(to: address) else {
            throw DNSPolicyFailure.configuration("DoH 引导未返回有效 IP 或策略已更新")
        }
        let snapshot = dnsSnapshot()
        try snapshot.requireAllowedOriginal(plan.original)
        try snapshot.requireAllowedBootstrap(configuration, host: endpoint.host, original: plan.original)
        let upstream = DNSConfiguredUpstream.doh(resolved)
        // Keep the configured hostname as TLS identity but re-check both the
        // returned dial IP and that identity before constructing any socket.
        try snapshot.requireAllowedResolver(upstream, original: plan.original)
        return DNSQueryPlan(upstream: upstream, candidates: plan.candidates, route: plan.route, original: plan.original,
                            generation: plan.generation, bootstrap: nil,
                            scopeKey: plan.scopeKey, healthScopeKey: plan.healthScopeKey,
                            interfaceName: plan.interfaceName, questionName: plan.questionName,
                            fallbackServers: plan.fallbackServers)
    }

    private func recordDNSResponse(_ data: Data) {
        for record in DNSMessageInspection.addressAnswers(in: data) {
            dnsMapping.set(domain: record.domain, for: record.address, ttl: record.ttl)
        }
    }

    public func connectTCP(host: String, port: UInt16, queue: DispatchQueue,
                           sourceHost: String? = nil, sourcePort: UInt16? = nil,
                           inboundPort: UInt16? = nil,
                           synthesizeFakeIP: Bool = true,
                           completion: @escaping (Result<NativeOutboundByteStream, Error>) -> Void) {
        // A fake address only ever exists because this router handed it out, so
        // recovering the hostname here is what lets the outbound receive the
        // name rather than an address the local resolver may have forged.
        let original = RequestTarget(host: resolvedDestinationHost(host), port: port,
                                     protocolName: "TCP",
                                     sourceHost: sourceHost, sourcePort: sourcePort, inboundPort: inboundPort)
        if port == 53 {
            do {
                let stream = DNSFramedByteStream(queue: queue)
                let datagram = try makeDNSDatagram(original: original, queue: queue,
                    synthesizeFakeIP: synthesizeFakeIP,
                    receive: { [weak stream] in stream?.receiveDNSResponse($0) },
                    failure: { [weak stream] in stream?.fail($0) })
                stream.attach(datagram)
                completion(.success(stream))
            } catch { completion(.failure(error)) }
            return
        }
        connectRoutedTCP(route: route(for: original), target: original,
                         plainHTTP: false, queue: queue, completion: completion)
    }

    fileprivate func connectRoutedTCP(route selected: ResolvedRoute, target: RequestTarget,
                                      plainHTTP: Bool, queue: DispatchQueue,
                                      completion: @escaping (Result<NativeOutboundByteStream, Error>) -> Void) {
        let snapshot = dnsSnapshot()
        let interfaceName = ProxyEngine.currentOutboundInterface?.name
        let deadline = LiteralAddressAttemptClock.now + 12
        guard case .direct = selected, DNSApplicationResolutionPolicy.usesQueryRouter(snapshot.profile),
              !DoHEndpoint.isAddressLiteral(target.host) else {
            TunnelConnector.connect(route: selected, target: target, plainHTTP: plainHTTP, queue: queue,
                completion: { [weak self] result in
                    guard let self, self.isCurrentDNSGeneration(snapshot.generation),
                          ProxyEngine.currentOutboundInterface?.name == interfaceName else {
                        if case .success(let pair) = result { pair.0.cancel() }
                        completion(.failure(EngineError("连接期间目标策略或接口已更新，已拒绝旧连接"))); return
                    }
                    completion(result.map { $0.0 })
                })
            return
        }
        resolveAddresses(for: target.host, queue: queue, sourceTarget: target) { [weak self] result in
            guard let self else { completion(.failure(EngineError("DNS 路由核心已释放"))); return }
            guard self.isCurrentDNSGeneration(snapshot.generation),
                  ProxyEngine.currentOutboundInterface?.name == interfaceName else {
                completion(.failure(EngineError("解析期间目标路由已更新，已阻止旧 DIRECT 连接"))); return
            }
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let addresses):
                self.connectDirectAddresses(addresses, selected: selected, target: target,
                                            generation: snapshot.generation, interfaceName: interfaceName,
                                            deadline: deadline, queue: queue, completion: completion)
            }
        }
    }

    private func connectDirectAddresses(_ addresses: [String], selected: ResolvedRoute,
                                        target: RequestTarget, generation: UInt64, interfaceName: String?,
                                        deadline: TimeInterval, queue: DispatchQueue,
                                        completion: @escaping (Result<NativeOutboundByteStream, Error>) -> Void) {
        guard isCurrentDNSGeneration(generation),
              ProxyEngine.currentOutboundInterface?.name == interfaceName else {
            completion(.failure(EngineError("目标路由已更新，已阻止旧 DIRECT 连接"))); return
        }
        let snapshot = dnsSnapshot()
        var refusal: String?
        let approved = addresses.filter { address in
            guard DoHEndpoint.isAddressLiteral(address) else { return false }
            var resolved = target; resolved.host = address
            if case .reject(let reason) = snapshot.route(resolved, mode: .rule) {
                refusal = reason; return false
            }
            return true
        }
        guard !approved.isEmpty else {
            completion(.failure(EngineError(refusal.map { "解析目标被策略拒绝：\($0)" }
                ?? "DNS 没有返回可连接的地址"))); return
        }
        // Every address has passed policy before the physical race. An epoch
        // or interface change revokes all attempts, including their late dials.
        ObjCNetworkByteStream.connectAddresses(approved, port: target.port,
            interfaceName: interfaceName, queue: queue, deadline: deadline,
            permitted: { [weak self] in
                guard let self else { return false }
                return self.isCurrentDNSGeneration(generation)
                    && ProxyEngine.currentOutboundInterface?.name == interfaceName
            }) { result in completion(result.map { $0 as any NativeOutboundByteStream }) }
    }

    /// Application DIRECT hostnames use the same QNAME policy gate as wire
    /// DNS. Node/bootstrap resolution is intentionally a separate facility.
    public func resolveAddresses(for host: String, queue: DispatchQueue,
                                  sourceTarget: RequestTarget? = nil,
                                  completion: @escaping (Result<[String], Error>) -> Void) {
        if DoHEndpoint.isAddressLiteral(host) { queue.async { completion(.success([host])) }; return }
        if host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) == "localhost" {
            do {
                guard let query = DNSMessageInspection.query(for: host, type: 1) else { throw EngineError("localhost DNS 名称无效") }
                let original = RequestTarget(host: protectedSystemDNSGateway, port: 53, protocolName: "UDP",
                                             sourceHost: sourceTarget?.sourceHost, sourcePort: sourceTarget?.sourcePort,
                                             inboundPort: sourceTarget?.inboundPort)
                _ = try prepareDNSQuery(query, original: original, synthesizeFakeIP: false)
            } catch { queue.async { completion(.failure(error)) }; return }
            queue.async { completion(.success(["127.0.0.1", "::1"])) }; return
        }
        let generation = dnsSnapshot().generation
        let interfaceName = ProxyEngine.currentOutboundInterface?.name
        let operation = DNSAddressResolution(queue: queue, permitted: { [weak self] in
            self?.isCurrentDNSGeneration(generation) == true
                && ProxyEngine.currentOutboundInterface?.name == interfaceName
        }, completion: completion)
        operation.start(router: self, host: host, sourceTarget: sourceTarget)
    }

    public func makeUDPFlow(host: String, port: UInt16, queue: DispatchQueue,
                            sourceHost: String? = nil, sourcePort: UInt16? = nil,
                            inboundPort: UInt16? = nil,
                            receive: @escaping (Data) -> Void,
                            failure: @escaping (Error) -> Void) throws -> NativeRoutedDatagram {
        // Same reverse map as TCP: without it the outbound tries to reach the
        // synthetic 198.19.x.x address and every UDP flow for a proxied name fails.
        let original = RequestTarget(host: resolvedDestinationHost(host), port: port,
                                     protocolName: "UDP",
                                     sourceHost: sourceHost, sourcePort: sourcePort, inboundPort: inboundPort)
        let selected = route(for: original)
        // Check before creating a resolver, synthesizing fake IPs, or opening
        // a direct DNS socket. All of those are still network access policies.
        if case .reject(let reason) = selected { throw EngineError("策略拒绝：\(reason)") }
        if port == 53 {
            return try makeDNSDatagram(original: original, queue: queue, receive: receive, failure: failure)
        }
        switch selected {
        case .direct:
            let snapshot = dnsSnapshot()
            let resolver: DirectRoutedDatagram.HostResolver? = DNSApplicationResolutionPolicy.usesQueryRouter(snapshot.profile)
                ? { [weak self] host, done in
                    guard let self else { done(.failure(EngineError("DNS 路由核心已释放"))); return }
                    self.resolveAddresses(for: host, queue: queue, sourceTarget: original) { result in
                        guard self.isCurrentDNSGeneration(snapshot.generation) else {
                            done(.failure(EngineError("目标路由已更新，已阻止旧 DIRECT UDP 连接"))); return
                        }
                        if case .success(let addresses) = result, let address = addresses.first {
                            var destination = original; destination.host = address
                            if case .reject(let reason) = self.dnsSnapshot().route(destination, mode: .rule) {
                                done(.failure(EngineError("解析后的 UDP 目标被策略拒绝：\(reason)"))); return
                            }
                        }
                        done(result)
                    }
                } : nil
            return try DirectRoutedDatagram(target: original, queue: queue,
                                            resolveHost: resolver, permitted: { [weak self] in
                self?.isCurrentDNSGeneration(snapshot.generation) ?? false
            }, receive: receive, failure: failure)
        case .native(let policy, _):
            return try NativePolicyRoutedDatagram(policy: policy, target: original, queue: queue,
                                                  receive: receive, failure: failure)
        case .reject(let reason): throw EngineError("策略拒绝：\(reason)")
        case .http: throw EngineError("HTTP 出站不支持 UDP")
        case .socks5: throw EngineError("TUN 直连数据面暂不支持 SOCKS5 UDP 出站")
        }
    }
}

extension NativePacketRouter {
    /// This entry point is inert without the exact CLI fixture flag. All
    /// endpoint/profile/anchor guards run before constructing the router or
    /// any socket, and the injected trust stays on this instance only.
    public static func runDNSAdaptiveLoopbackFixture(profileText: String, scenario: String,
                                                     anchorDER: Data? = nil) throws -> String {
        let fixture = try DNSAdaptiveLoopbackFixture(profileText: profileText, scenario: scenario,
                                                     anchorDER: anchorDER)
        let router = NativePacketRouter(profile: fixture.profile, mode: .rule,
                                        globalPolicy: "DIRECT", groupSelections: [:])
        router.loopbackFixtureDNSStreamDialer = fixture.streamDialer
        router.loopbackFixtureDNSTLSUpgrader = fixture.tlsUpgrader
        var warmCandidate: DNSFixtureCandidateWarmup?
        if fixture.measuresThirdCandidateRotation {
            warmCandidate = { index, query, queue, receive, failure in
                let original = RequestTarget(host: "127.0.0.1", port: 53, protocolName: "UDP",
                    sourceHost: "127.0.0.1", sourcePort: 41000)
                guard case .upstream(let plan) = try router.prepareDNSQuery(query, original: original),
                      plan.candidates.count == 3, (0..<3).contains(index),
                      let question = DNSMessageInspection.singleQuestion(in: query),
                      question.name.hasPrefix("rotation.setup-") || question.name.hasPrefix("rotation.warm-") else {
                    throw DNSPolicyFailure.configuration("三候选回环预热必须保持固定问题与批准集合")
                }
                let candidate = plan.candidates[index]
                let chosen = try router.revalidatedCandidatePlan(plan, candidate: candidate)
                _ = router.dnsAdaptiveSelector.orderedCandidates(scopeKey: plan.healthScopeKey,
                    candidateIDs: plan.candidates.map(\.id))
                let started = ProcessInfo.processInfo.systemUptime
                return try router.makeDNSUpstream(plan: chosen, queue: queue, receive: { answer in
                    guard router.isCurrentDNSPlan(chosen),
                          DNSMessageInspection.responseMatchesQuery(answer, query: query),
                          [UInt8(0), 3].contains(answer[answer.startIndex + 3] & 0x0f) else {
                        failure(EncryptedDNSQueryFailure.invalidResponse); return
                    }
                    // Measure only a real authenticated successful exchange.
                    // Setup probes establish the genuine pooled carrier; the
                    // following warm probe measures its successful wire RTT.
                    if question.name.hasPrefix("rotation.warm-") {
                        router.dnsAdaptiveSelector.record(scopeKey: plan.healthScopeKey, candidateID: candidate.id,
                            milliseconds: max(0, ProcessInfo.processInfo.systemUptime - started) * 1000, success: true)
                    }
                    receive(answer)
                }, failure: failure)
            }
        }
        return try fixture.run(router: router, queryStatistics: { router.dnsQueryCoordinator.statistics },
                               warmCandidate: warmCandidate)
    }
}

/// A socket may carry questions for many unrelated names. Select and validate
/// the policy for each DNS message, never once per DNS server/association.
private final class PolicyDNSDatagram: NativeRoutedDatagram {
    private struct Transaction {
        let query: Data
        let generation: UInt64
        let reservation: SOCKSUDPReservation
        let connectionReservation: SOCKSUDPReservation
        var transport: NativeRoutedDatagram?
        var timeout: DispatchWorkItem?
    }
    private let router: NativePacketRouter
    private let original: RequestTarget
    private let queue: DispatchQueue
    private let queueSpecificKey = DispatchSpecificKey<Bool>()
    private let queryTimeout: DispatchTimeInterval
    private let upstreamFactory: DNSQueryCoordinator.Factory?
    private let synthesizeFakeIP: Bool
    private let receiveHandler: (Data) -> Void
    private let failureHandler: (Error) -> Void
    private let admission = NSLock()
    private let resource: SOCKSUDPReservation
    private var closed = false
    private var admittedPackets = 0, admittedBytes = 0
    private var transactions: [UUID: Transaction] = [:]
    fileprivate var fakeIPSynthesisEnabled: Bool { synthesizeFakeIP }

    // Short deadlines and the factory override are private memory-test inputs;
    // routed application callers keep the eight-second verified defaults.
    init(router: NativePacketRouter, original: RequestTarget, queue: DispatchQueue,
         synthesizeFakeIP: Bool, receive: @escaping (Data) -> Void,
         failure: @escaping (Error) -> Void,
         queryTimeout: DispatchTimeInterval = .seconds(8),
         upstreamFactory: DNSQueryCoordinator.Factory? = nil) throws {
        guard let resource = SOCKSUDPResourceLimits.shared.reserveResource() else {
            throw EngineError("DNS 会话资源已达上限")
        }
        self.router = router; self.original = original; self.synthesizeFakeIP = synthesizeFakeIP
        self.queue = DispatchQueue(label: "app.hajimi.dns.query-policy", target: queue)
        self.queryTimeout = queryTimeout; self.upstreamFactory = upstreamFactory
        self.resource = resource; receiveHandler = receive; failureHandler = failure
        self.queue.setSpecific(key: queueSpecificKey, value: true)
    }

    func send(_ data: Data) {
        admission.lock(); let stopped = closed; admission.unlock()
        guard !stopped else { return }
        let queryDeadline = Self.timeoutSeconds(queryTimeout).map {
            ProcessInfo.processInfo.systemUptime + $0
        }
        let prepared: DNSQueryPreparation
        do {
            prepared = try router.prepareDNSQuery(data, original: original,
                                                  synthesizeFakeIP: synthesizeFakeIP)
        } catch {
            let code = (error as? DNSPolicyFailure)?.responseCode ?? .servfail
            if let answer = DNSMessageInspection.errorResponse(to: data, code: code) { deliver(answer) }
            return
        }
        switch prepared {
        case .answer(let answer, let generation):
            deliverLocalAnswer(answer, query: data, generation: generation)
        case .upstream(let plan):
            admission.lock()
            guard !closed, admittedPackets < 64, data.count <= 256 * 1_024 - admittedBytes,
                  let leases = DNSQueryResourceBudget.reserve(bytes: data.count) else {
                admission.unlock()
                if let answer = DNSMessageInspection.errorResponse(to: data, code: .servfail) { deliver(answer) }
                return
            }
            admittedPackets += 1; admittedBytes += data.count; admission.unlock()
            let id = UUID()
            queue.async {
                self.admission.lock(); let stopped = self.closed; self.admission.unlock()
                guard !stopped else {
                    self.release(data.count); leases.payload.release(); leases.connection.release(); return
                }
                guard self.router.isCurrentDNSGeneration(plan.generation) else {
                    self.release(data.count); leases.payload.release(); leases.connection.release()
                    if let reply = DNSMessageInspection.errorResponse(to: data, code: .servfail) { self.deliver(reply) }
                    return
                }
                self.transactions[id] = Transaction(query: data, generation: plan.generation,
                                                    reservation: leases.payload,
                                                    connectionReservation: leases.connection)
                // Share one monotonic budget with delayed coordinator/adaptive
                // work; a later child queue must not receive a fresh eight seconds.
                let timeout = DispatchWorkItem { [weak self] in
                    self?.finish(id, answer: nil, deadlineExpired: true)
                }
                self.transactions[id]?.timeout = timeout
                let remaining = queryDeadline.map { max(0, $0 - ProcessInfo.processInfo.systemUptime) }
                self.queue.asyncAfter(deadline: remaining.map { .now() + $0 } ?? .distantFuture, execute: timeout)
                do {
                    let transport = try self.router.makeOptimizedDNSUpstream(plan: plan, queue: self.queue,
                        factory: self.upstreamFactory,
                        queryDeadline: queryDeadline,
                        receive: { [weak self] answer in self?.finishOnQueue(id, answer: answer) },
                        failure: { [weak self] _ in self?.finishOnQueue(id, answer: nil) })
                    self.transactions[id]?.transport = transport
                    transport.send(data)
                } catch { self.finish(id, answer: nil) }
            }
        }
    }

    private static func timeoutSeconds(_ interval: DispatchTimeInterval) -> TimeInterval? {
        let seconds: TimeInterval
        switch interval {
        case .seconds(let value): seconds = Double(value)
        case .milliseconds(let value): seconds = Double(value) / 1_000
        case .microseconds(let value): seconds = Double(value) / 1_000_000
        case .nanoseconds(let value): seconds = Double(value) / 1_000_000_000
        case .never: return nil // Only the private fixture can disable its parent timer.
        @unknown default: return 0
        }
        return max(0, seconds)
    }

    private func finishOnQueue(_ id: UUID, answer: Data?) {
        // A coalesced lease already delivers on a queue targeting this serial
        // policy queue. A second hop can put an earlier queued answer behind
        // an elapsed timer. Foreign-thread callbacks still need dispatch.
        if DispatchQueue.getSpecific(key: queueSpecificKey) == true {
            finish(id, answer: answer)
        } else {
            queue.async { [weak self] in self?.finish(id, answer: answer) }
        }
    }

    private func finish(_ id: UUID, answer: Data?, deadlineExpired: Bool = false) {
        guard let transaction = transactions.removeValue(forKey: id) else { return }
        transaction.timeout?.cancel()
        if deadlineExpired, let timed = transaction.transport as? any DNSQueryDeadlineAwareDatagram {
            timed.queryDeadlineReached()
        } else { transaction.transport?.cancel() }
        transaction.reservation.release(); transaction.connectionReservation.release()
        release(transaction.query.count)
        let accepted = answer.flatMap { reply -> Data? in
            guard router.isCurrentDNSGeneration(transaction.generation),
                  DNSMessageInspection.responseMatchesQuery(reply, query: transaction.query) else { return nil }
            return reply
        }
        if let response = accepted ?? DNSMessageInspection.errorResponse(to: transaction.query, code: .servfail) {
            deliver(response)
        }
    }

    private func release(_ count: Int) {
        admission.lock(); admittedPackets -= 1; admittedBytes -= count; admission.unlock()
    }

    private func deliver(_ response: Data) {
        admission.lock(); let stopped = closed; admission.unlock()
        if !stopped { receiveHandler(response) }
    }

    private func deliverLocalAnswer(_ answer: Data, query: Data, generation: UInt64) {
        let work = { [self] in
            admission.lock(); let stopped = closed; admission.unlock()
            guard !stopped else { return }
            // A synthetic/FORMERR answer has no upstream transaction whose
            // finish path checks the epoch. Check at the actual owner-queue
            // handoff, not before enqueueing: reload/flush may run meanwhile.
            // isCurrentDNSGeneration releases its lock before user callbacks.
            let response = router.isCurrentDNSGeneration(generation)
                ? answer : DNSMessageInspection.errorResponse(to: query, code: .servfail)
            if let response { deliver(response) }
        }
        if DispatchQueue.getSpecific(key: queueSpecificKey) == true { work() }
        else { queue.async(execute: work) }
    }

    func invalidateForPolicyUpdate() {
        queue.async {
            // The association survives an epoch transition. A new question
            // may already be queued here; only revoke its stale transactions.
            for (id, transaction) in Array(self.transactions)
                where !self.router.isCurrentDNSGeneration(transaction.generation) {
                self.finish(id, answer: nil)
            }
        }
    }

    func cancel() {
        admission.lock(); closed = true; admission.unlock()
        queue.async {
            for transaction in self.transactions.values {
                transaction.timeout?.cancel(); transaction.transport?.cancel()
                transaction.reservation.release(); transaction.connectionReservation.release()
                self.release(transaction.query.count)
            }
            self.transactions.removeAll(); self.resource.release()
        }
    }

    deinit {
        transactions.values.forEach { $0.timeout?.cancel(); $0.transport?.cancel() }
        resource.release()
    }
}

private extension PolicyDNSDatagram {
    func drainQueueForSelfTest() { queue.sync {} }
    func activeTransactionForSelfTest() -> UUID? { queue.sync { transactions.keys.first } }
    func completeFromAnyThreadForSelfTest(_ id: UUID, answer: Data?) { finishOnQueue(id, answer: answer) }
    static func timeoutSecondsForSelfTest(_ interval: DispatchTimeInterval) -> TimeInterval? { timeoutSeconds(interval) }
}

/// Real policy/coordinator/lease callbacks over memory-only transports. The
/// short parent deadline preserves the production eight-second ordering race
/// without occupying a test process for eight seconds per boundary case.
private enum PolicyDNSCallbackQueueSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS 回调队列自检失败：\(text)" }
    }
    private static func expect(_ condition: Bool, _ text: String) throws {
        guard condition else { throw Failure(text: text) }
    }
    private static func wait(_ semaphore: DispatchSemaphore, _ text: String) throws {
        try expect(semaphore.wait(timeout: .now() + 2) == .success, text)
    }

    private final class MemoryTransport: NativeRoutedDatagram {
        let sent = DispatchSemaphore(value: 0), canceled = DispatchSemaphore(value: 0)
        let processed = DispatchSemaphore(value: 0)
        private let queue: DispatchQueue
        private let receive: (Data) -> Void
        private let lock = NSLock()
        private var question: Data?
        private var cancels = 0
        init(queue: DispatchQueue, receive: @escaping (Data) -> Void) {
            self.queue = queue; self.receive = receive
        }
        func send(_ data: Data) { lock.lock(); question = data; lock.unlock(); sent.signal() }
        func cancel() {
            lock.lock(); cancels += 1; let first = cancels == 1; lock.unlock()
            if first { canceled.signal() }
        }
        var cancelCount: Int { lock.lock(); defer { lock.unlock() }; return cancels }
        func answer(wrongID: Bool = false) -> Data {
            lock.lock(); var answer = question!; lock.unlock()
            answer[2] = 0x81; answer[3] = 0x80
            for index in 6...11 { answer[index] = 0 }
            if wrongID { answer[1] ^= 1 }
            return answer
        }
        func reply(wrongID: Bool = false) {
            // Deliberately allow late/duplicate callbacks after cancellation.
            receive(answer(wrongID: wrongID))
            // The factory's queue is the real coordinator queue. Its finish
            // is enqueued by receive() before this acknowledgment barrier.
            queue.async { self.processed.signal() }
        }
    }
    private final class Broker {
        let offered = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var value: MemoryTransport?
        var transport: MemoryTransport { lock.lock(); defer { lock.unlock() }; return value! }
        var factory: DNSQueryCoordinator.Factory {
            { queue, receive, _ in
                let transport = MemoryTransport(queue: queue, receive: receive)
                self.lock.lock(); self.value = transport; self.lock.unlock()
                self.offered.signal()
                return transport
            }
        }
    }
    private final class Responses {
        let received = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var answers: [Data] = []
        private var failures = 0
        func receive(_ answer: Data) { lock.lock(); answers.append(answer); lock.unlock(); received.signal() }
        func fail(_ error: Error) { lock.lock(); failures += 1; lock.unlock(); received.signal() }
        var snapshot: (answers: [Data], failures: Int) {
            lock.lock(); defer { lock.unlock() }; return (answers, failures)
        }
    }
    private final class Fixture {
        let parent = DispatchQueue(label: "app.hajimi.dns.policy-callback-self-test.parent")
        let broker = Broker(), responses = Responses()
        let profile: Profile
        let router: NativePacketRouter
        let flow: PolicyDNSDatagram
        let query: Data
        init(localAnswers: Bool = false) throws {
            var profile = Profile()
            profile.fakeIPEnabled = localAnswers
            // An omitted test override could only target a closed loopback
            // port; it cannot cause a public resolver/system DNS fallback.
            profile.encryptedDNSServers = ["https://127.0.0.1:1/dns-query"]
            profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
            if localAnswers {
                let node = ProxyPolicy(name: "MemoryNode", kind: .native, host: "127.0.0.1", port: 1,
                    adapterType: "trojan", parameters: ["password": "memory-only"])
                profile.proxies[node.name] = node
                profile.rules[0] = RoutingRule(kind: .final, policy: node.name, sourceLine: 1)
            }
            self.profile = profile
            query = DNSMessageInspection.query(for: "callback-policy.selftest.invalid",
                                               type: localAnswers ? 1 : 28, id: 0x4101)!
            router = NativePacketRouter(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            flow = try PolicyDNSDatagram(router: router,
                original: RequestTarget(host: "127.0.0.1", port: 53, protocolName: "UDP"), queue: parent,
                synthesizeFakeIP: localAnswers, receive: responses.receive, failure: responses.fail,
                queryTimeout: .milliseconds(150), upstreamFactory: broker.factory)
        }
        func start() throws {
            flow.send(query)
            try wait(broker.offered, "未进入内存工厂")
            try wait(broker.transport.sent, "真实 coordinator/lease 未发送查询")
        }
        func stop() { flow.cancel(); flow.drainQueueForSelfTest(); parent.sync {} }
        func requireOneResponse(_ code: UInt8, _ text: String) throws {
            try wait(responses.received, text)
            flow.drainQueueForSelfTest(); parent.sync {}
            let values = responses.snapshot
            try expect(values.failures == 0 && values.answers.count == 1
                       && DNSMessageInspection.responseMatchesQuery(values.answers[0], query: query)
                       && values.answers[0][3] & 0x0f == code, text)
        }
        func requireNoFurtherResponse(_ text: String) throws {
            try expect(responses.received.wait(timeout: .now() + .milliseconds(180)) == .timedOut, text)
        }
    }

    static func run() throws {
        try expect(PolicyDNSDatagram.timeoutSecondsForSelfTest(.seconds(8)) == 8
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.milliseconds(150)) == 0.15
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.microseconds(150_000)) == 0.15
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.nanoseconds(150_000_000)) == 0.15
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.seconds(-1)) == 0
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.never) == nil,
                   "绝对预算单位换算、负预算或 private never 语义错误")
        // Local replies have no coordinator transaction. Hold their actual
        // delivery queue while an epoch changes; neither a cached route nor a
        // precomputed FakeIP answer may survive that handoff unchecked.
        for change in 0..<3 {
            let fixture = try Fixture(localAnswers: true)
            let blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal(); fixture.stop() }
            fixture.parent.async { blocked.signal(); _ = release.wait(timeout: .now() + 2) }
            try wait(blocked, "本地合成答复未能阻塞实际交付队列")
            fixture.flow.send(fixture.query)
            try expect(fixture.responses.received.wait(timeout: .now() + .milliseconds(20)) == .timedOut,
                       "本地合成答复绕过 owner 队列提前交付")
            if change == 1 {
                var rejected = fixture.profile
                rejected.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)]
                fixture.router.update(profile: rejected, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            } else if change == 2 { fixture.router.flushDNS() }
            release.signal()
            try fixture.requireOneResponse(change == 0 ? 0 : 2,
                "本地合成答复跨 epoch 交付旧地址或没有返回 SERVFAIL")
            let records = DNSMessageInspection.addressAnswers(in: fixture.responses.snapshot.answers[0])
            if change == 0 {
                try expect(records.count == 1 && IPCIDR.contains(records[0].address, cidr: "198.19.0.0/16"),
                           "未变化 epoch 的合成答复丢失 FakeIP")
            } else { try expect(records.isEmpty, "过期本地答复仍泄露旧合成地址") }
            try expect(fixture.broker.offered.wait(timeout: .now()) == .timedOut,
                       "本地 epoch 检查意外启动了上游工厂")
            try fixture.requireNoFurtherResponse("本地答复重复交付或由计时器复活")
        }
        for shouldFlush in [false, true] {
            let fixture = try Fixture(localAnswers: true)
            let blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal(); fixture.stop() }
            var malformed = fixture.query
            malformed[4] = 0; malformed[5] = 2 // Two questions declared, only one supplied.
            fixture.parent.async { blocked.signal(); _ = release.wait(timeout: .now() + 2) }
            try wait(blocked, "FORMERR 答复未能阻塞实际交付队列")
            fixture.flow.send(malformed)
            try expect(fixture.responses.received.wait(timeout: .now() + .milliseconds(20)) == .timedOut,
                       "FORMERR 答复绕过 owner 队列")
            if shouldFlush { fixture.router.flushDNS() }
            release.signal()
            try wait(fixture.responses.received, "FORMERR/过期 SERVFAIL 未交付，形成静默超时")
            fixture.flow.drainQueueForSelfTest(); fixture.parent.sync {}
            let responses = fixture.responses.snapshot
            let expectedCode: UInt8 = shouldFlush ? 2 : 1
            try expect(responses.failures == 0 && responses.answers.count == 1
                       && responses.answers[0].count >= 12
                       && responses.answers[0][0] == malformed[0] && responses.answers[0][1] == malformed[1]
                       && responses.answers[0][3] & 0x0f == expectedCode,
                       "FORMERR 未保留 epoch/ID 或过期时没有改为 SERVFAIL")
            try expect(fixture.broker.offered.wait(timeout: .now()) == .timedOut,
                       "FORMERR epoch 回归意外启动上游工厂")
            try fixture.requireNoFurtherResponse("FORMERR/过期 SERVFAIL 被重复交付")
        }
        // The reply is accepted before the deadline, then held on the lease's
        // parent/target queue past expiry. The old second hop returned SERVFAIL.
        do {
            let fixture = try Fixture(), blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal(); fixture.stop() }
            try fixture.start()
            fixture.parent.async { blocked.signal(); _ = release.wait(timeout: .now() + 2) }
            try wait(blocked, "target 队列未进入受控排队")
            fixture.broker.transport.reply()
            try wait(fixture.broker.transport.processed, "deadline 前答复未被 coordinator 接受")
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(300)) { release.signal() }
            try fixture.requireOneResponse(0, "target 队列已有答复被第二次 dispatch 的 timeout 越过")
            try fixture.requireNoFurtherResponse("已完成答复被 parent timer 重复完成")
        }
        // Calls from unrelated threads must not mutate policy state off queue.
        do {
            let fixture = try Fixture(), blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal(); fixture.stop() }
            try fixture.start()
            guard let id = fixture.flow.activeTransactionForSelfTest() else { throw Failure(text: "无活动事务") }
            let answer = fixture.broker.transport.answer()
            fixture.parent.async { blocked.signal(); _ = release.wait(timeout: .now() + 2) }
            try wait(blocked, "任意线程负测未阻塞 owner 队列")
            fixture.flow.completeFromAnyThreadForSelfTest(id, answer: answer)
            try expect(fixture.responses.received.wait(timeout: .now() + .milliseconds(20)) == .timedOut,
                       "任意线程绕过了 owner 队列")
            release.signal()
            try fixture.requireOneResponse(0, "任意线程答复没有经串行 owner 交付")
            try fixture.requireNoFurtherResponse("任意线程完成后计时器重复回包")
        }
        // An answer that really arrives after the parent timeout stays rejected.
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start()
            try fixture.requireOneResponse(2, "真正迟到的查询没有按原截止时间返回 SERVFAIL")
            fixture.broker.transport.reply()
            try wait(fixture.broker.transport.processed, "迟到答复未进入 token 校验")
            try fixture.requireNoFurtherResponse("真正超时后迟到答复复活了事务")
        }
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start(); fixture.flow.cancel()
            try wait(fixture.broker.transport.canceled, "普通取消未关闭自己的 transport")
            fixture.broker.transport.reply()
            try wait(fixture.broker.transport.processed, "已取消事务的迟到回调未抵达")
            try fixture.requireNoFurtherResponse("取消后的答复或 timer 仍向客户端回包")
            try expect(fixture.responses.snapshot.answers.isEmpty && fixture.broker.transport.cancelCount == 1,
                       "普通取消被复活或重复取消下层")
        }
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start()
            fixture.router.update(profile: fixture.profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            fixture.flow.invalidateForPolicyUpdate()
            try fixture.requireOneResponse(2, "epoch 更新未撤销旧策略事务")
            fixture.broker.transport.reply()
            try wait(fixture.broker.transport.processed, "旧 epoch 答复未进入 token 校验")
            try fixture.requireNoFurtherResponse("旧 epoch 答复被重新交付")
        }
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start(); fixture.broker.transport.reply(); fixture.broker.transport.reply()
            try fixture.requireOneResponse(0, "重复 callback 丢失合法首答复")
            try fixture.requireNoFurtherResponse("重复 callback 或 timer 产生第二个答复")
            try expect(fixture.broker.transport.cancelCount == 1, "重复 callback 多次取消同一 transport")
        }
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start(); fixture.broker.transport.reply(wrongID: true)
            try fixture.requireOneResponse(2, "错 ID 答复被 inline 路径接纳")
            try fixture.requireNoFurtherResponse("错 ID 事务被 timer 重复完成")
        }
        print("DNS policy callback queue checks passed: local answer epochs, target handoff, foreign-thread dispatch, genuine timeout, cancellation, epoch, duplicate callbacks and wrong ID")
    }
}

/// An intercepted datagram can now create a TCP/TLS transaction. Reserve a
/// process-wide connection slot as well as wire bytes before dispatching it;
/// the larger packet budget alone must not authorize thousands of sockets.
/// Both leases survive until that logical query completes or is cancelled.
private enum DNSQueryResourceBudget {
    static func reserve(bytes: Int, budget: SOCKSUDPGlobalBudget = SOCKSUDPResourceLimits.shared)
        -> (payload: SOCKSUDPReservation, connection: SOCKSUDPReservation)? {
        guard let connection = budget.reserveResource() else { return nil }
        guard let payload = budget.reservePacket(bytes: bytes) else { connection.release(); return nil }
        return (payload, connection)
    }
}

/// One bounded encrypted query with at most two live approved candidates. A
/// soft budget starts a hedge but never truncates an otherwise healthy primary
/// before the overall deadline. No endpoint is added here: policy approved the
/// complete set before admission. A refusal after admission remains terminal.
private final class DNSAdaptiveQueryDatagram: NativeRoutedDatagram, DNSQueryDeadlineAcknowledging, DNSQueryPhaseDeadlineAcknowledging, DNSProxyFallbackBarrierProviding, DNSQueryEncryptedPhaseScheduling, DNSQueryExecutionContextAccepting {
    typealias Factory = (DNSUpstreamCandidate, DispatchQueue, @escaping (Data) -> Void,
                         @escaping (Error) -> Void) throws -> NativeRoutedDatagram
    private let candidates: [DNSUpstreamCandidate]
    private let selector: DNSAdaptiveUpstreamSelector
    private var scopeKey: String
    private let queue: DispatchQueue
    private let permitted: () -> Bool, factory: Factory
    private let receive: (Data) -> Void, failure: (Error) -> Void
    private let availability: ((DNSUpstreamCandidate) -> (reusable: Int, cold: Int)?)?
    private let timeout: TimeInterval, absoluteDeadline: TimeInterval?, clock: () -> TimeInterval
    private let protectProxyFallback: Bool
    private let allowApprovedProxyPlaintext: Bool
    private let cancellations = DispatchGroup()
    private let admission = NSLock()
    private var barrierTokens = Set<UUID>()
    private var fallbackErrorBarrier: Error?
    private var fallbackAnswerBarrier: Data?
    private var deadlineRefusalBarrier: Data?
    private var barrierQuestion: Data?
    private var barrierChildren: [DNSProxyFallbackBarrierProviding] = []
    private var deadlineFenceAvailable = true
    private var closed = false, deadlineSignalled = false, started = false, finished = false
    private var cancellationReason: DNSAttemptCancellationReason?
    private var executionContext = DNSQueryExecutionContext()
    private var query: Data?
    private var approvedOrder: [DNSUpstreamCandidate] = []
    private var ordered: [DNSUpstreamCandidate] = []
    private var explorationID: String?
    private var preferUntriedServices = false
    private var preferAvailableUntriedServices = false
    private var usedNetworkRecovery = false
    private var deferredNetworkReset: DNSUpstreamCandidate?
    private var next = 0, attemptCount = 0
    private var primaryToken: UUID?
    private struct Attempt {
        let candidate: DNSUpstreamCandidate, started: TimeInterval
        let observation: DNSAdaptiveUpstreamSelector.Observation?
        let context: DNSQueryExecutionContext
        let minimumColdObservation: TimeInterval
        let hadVerifiedSuccessAtAdmission: Bool
        var transport: NativeRoutedDatagram?
        var hedgeTimer: DispatchWorkItem?
        var rotationTimer: DispatchWorkItem?
    }
    private struct RetiredObservation {
        let candidate: DNSUpstreamCandidate
        let milliseconds: Double
        let observation: DNSAdaptiveUpstreamSelector.Observation?
        let evidence: DNSQueryTransportEvidence
    }
    private var active: [UUID: Attempt] = [:]
    private var retired: [RetiredObservation] = []
    private var lastNetworkError: Error?
    private var localCapacityError: Error?
    private var deadline: TimeInterval = 0, exchangeStarted: TimeInterval = 0, exchangeBudget: TimeInterval = 0
    private var deadlineTimer: DispatchWorkItem?

    init(candidates: [DNSUpstreamCandidate], selector: DNSAdaptiveUpstreamSelector, scopeKey: String,
         queue: DispatchQueue, permitted: @escaping () -> Bool, factory: @escaping Factory,
         receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void,
        availability: ((DNSUpstreamCandidate) -> (reusable: Int, cold: Int)?)? = nil,
        timeout: TimeInterval = 8, absoluteDeadline: TimeInterval? = nil,
        clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        protectProxyFallback: Bool = false, allowApprovedProxyPlaintext: Bool = false) {
        self.candidates = candidates; self.selector = selector; self.scopeKey = scopeKey
        self.queue = DispatchQueue(label: "app.hajimi.dns.adaptive-query", target: queue)
        self.permitted = permitted; self.factory = factory; self.receive = receive; self.failure = failure
        self.availability = availability
        self.timeout = timeout.isFinite ? min(8, max(0.001, timeout)) : 8
        self.absoluteDeadline = absoluteDeadline; self.clock = clock
        self.protectProxyFallback = protectProxyFallback
        self.allowApprovedProxyPlaintext = allowApprovedProxyPlaintext
    }
    private var isClosed: Bool {
        admission.lock(); defer { admission.unlock() }; return closed || deadlineSignalled
    }
    private var isClientCancelled: Bool { admission.lock(); defer { admission.unlock() }; return closed }

    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
        admission.lock(); defer { admission.unlock() }
        if !started, !closed { executionContext = context }
    }

    func send(_ data: Data) {
        admission.lock()
        guard !closed, !deadlineSignalled, !started else { admission.unlock(); return }
        started = true; admission.unlock()
        queue.async {
            guard !self.isClosed else { return }
            guard self.permitted(), self.candidates.allSatisfy({ $0.upstream.encrypted || self.allowApprovedProxyPlaintext }) else {
                self.finishFailure(DNSPolicyFailure.configuration("DNS 批准集合或策略已失效"),
                                   cancellationReason: .policyChanged); return
            }
            let now = self.clock()
            guard now.isFinite else { self.finishFailure(EngineError("DNS 单调时钟无效")); return }
            self.query = data; self.exchangeStarted = now
            self.admission.lock(); self.barrierQuestion = data; self.admission.unlock()
            if let absoluteDeadline = self.absoluteDeadline, !absoluteDeadline.isFinite {
                self.finishFailure(DNSQueryTimeoutError(), reason: "overall-deadline", cancellationReason: .overallDeadline); return
            }
            self.deadline = min(self.absoluteDeadline ?? (now + self.timeout),
                                self.executionContext.absoluteDeadline ?? (now + self.timeout), now + self.timeout)
            self.exchangeBudget = self.deadline - now
            guard self.exchangeBudget > 0 else {
                self.finishFailure(DNSQueryTimeoutError(inheritedDeadlineReached:
                    self.executionContext.absoluteDeadline == self.deadline),
                    reason: "overall-deadline", cancellationReason: .overallDeadline); return
            }
            // This one-query owner selects its answer-health domain once.
            // A reverse-query timeout must not cool a working ordinary DNS
            // path; the approved candidates and physical pools stay shared.
            self.scopeKey = DNSAdaptiveUpstreamSelector.queryHealthScope(scopeKey: self.scopeKey, query: data)
            let order = self.selector.schedulingOrder(scopeKey: self.scopeKey, candidateIDs: self.candidates.map(\.id))
            self.explorationID = order.explorationID
            self.approvedOrder = order.candidateIDs.compactMap { id in self.candidates.first { $0.id == id } }
            self.ordered = Array(self.approvedOrder.prefix(3))
            let timer = DispatchWorkItem { [weak self] in
                self?.overallDeadlineReached()
            }
            self.deadlineTimer = timer; self.queue.asyncAfter(deadline: .now() + self.exchangeBudget, execute: timer)
            self.beginAttempt()
        }
    }

    private func beginAttempt(reason: String = "initial", refreshCandidates: Bool = true) {
        guard !finished, !isClosed, let query else { return }
        guard permitted() else {
            finishFailure(DNSPolicyFailure.configuration("DNS 策略或接口已更新"), reason: "policy-update",
                          cancellationReason: .policyChanged); return
        }
        if let localCapacityError {
            if active.isEmpty { finishFailure(localCapacityError, reason: "local-capacity") }
            return
        }
        guard active.count < 2 else { return }
        let now = clock(), remaining = deadline - now
        guard now.isFinite else { finishFailure(EngineError("DNS 单调时钟无效"), reason: "clock-invalid"); return }
        guard remaining > 0 else { overallDeadlineReached(); return }
        guard attemptCount < 3, next < ordered.count else {
            if active.isEmpty {
                finishFailure(lastNetworkError ?? EngineError("所有批准的加密 DNS 尝试失败"), reason: "attempts-exhausted")
            }
            return
        }
        if refreshCandidates {
            if let reset = deferredNetworkReset, !usedNetworkRecovery,
               attemptCount == 2, next == 2, ordered.count == 3, ordered[next].upstream.encrypted,
               active.contains(where: { $0.value.candidate.upstream.encrypted
                   && $0.value.candidate.upstream.resolverServiceID != reset.upstream.resolverServiceID }),
               let replacement = availableRecoveryCandidate(for: reset) {
                ordered[next] = replacement
                usedNetworkRecovery = true
            } else { preferAvailableCandidate() }
        }
        let candidate = ordered[next]; next += 1
        if next == ordered.count { deferredNetworkReset = nil }
        let token = UUID()
        active[token] = Attempt(candidate: candidate, started: now,
            observation: selector.beginObservation(scopeKey: scopeKey, candidateID: candidate.id),
            context: executionContext.child(candidateID: token, absoluteDeadline: deadline),
            minimumColdObservation: coldCompletionWindow(candidate),
            hadVerifiedSuccessAtAdmission: selector.schedulingPriority(scopeKey: scopeKey, candidateID: candidate.id) == 0)
        admission.lock(); barrierTokens.insert(token); admission.unlock()
        if attemptCount == 0 { primaryToken = token }
        // Plan against the next usable approved candidate as well. A blocked
        // address in the old prefix must not lend its cold estimate to a
        // different provider that can already reuse a connection.
        preferAvailableCandidate()
        let attemptsLeft = ordered.count - next + 1
        let canHedge = next < ordered.count && active.count < 2
        let budget = canHedge ? DNSAdaptiveHedgeBudget.delay(remaining: remaining, attemptsLeft: attemptsLeft,
            primaryMilliseconds: planningLatencyMilliseconds(candidate),
            alternateMilliseconds: planningLatencyMilliseconds(ordered[next])) : remaining
        if canHedge {
            let timer = DispatchWorkItem { [weak self] in self?.startHedge(after: token) }
            active[token]?.hedgeTimer = timer
            queue.asyncAfter(deadline: .now() + budget, execute: timer)
        } else if active.count == 2, next < ordered.count, token != primaryToken {
            // Keep the first primary until the original overall deadline. A
            // never-measured hedge must not occupy the second slot until 8s
            // and prevent the third approved candidate from ever starting.
            // A previously fast hedge can blackhole too. Give measured RTT
            // 1.5x headroom plus 50ms, and retain a known-slow hedge whenever
            // no useful third-candidate window fits the original deadline.
            scheduleHedgeRotation(token, now: now)
        }
        // Logical attempt = an approved candidate entering its factory/send
        // path, including an immediate network/dial factory error. It does
        // not assert that a TLS handshake or packet exchange succeeded.
        if attemptCount > 0 { NetworkPerformanceDiagnostics.shared.recordDNS(.failover) }
        attemptCount += 1; NetworkPerformanceDiagnostics.shared.recordDNS(.upstreamAttempt)
        nativeDebug("dns adaptive attempt candidate_index=\(candidateIndex(candidate)) ordinal=\(attemptCount) active=\(active.count) budget_ms=\(Int(budget * 1000)) budget_kind=\(canHedge ? "hedge" : "overall") reason=\(reason)")
        do {
            let connection = try factory(candidate, queue, { [weak self] answer in
                self?.registerFallbackAnswer(answer, query: query, token: token)
                self?.queue.async { self?.accept(answer, token: token) }
            }, { [weak self] error in
                self?.registerFallbackError(error, token: token)
                self?.queue.async { self?.attemptFailure(error, token: token) }
            })
            if let provider = connection as? DNSProxyFallbackBarrierProviding {
                admission.lock(); barrierChildren.append(provider); admission.unlock()
            }
            if protectProxyFallback, !(connection is DNSQueryCancellationAcknowledging) {
                cancelUnadoptedTransport(connection, reason: .cleanup)
                finishFailure(EncryptedDNSQueryFailure.configuration); return
            }
            guard !isClosed, permitted() else {
                cancelUnadoptedTransport(connection, reason: .policyChanged)
                finishFailure(DNSPolicyFailure.configuration("DNS 尝试期间策略已更新"), reason: "policy-update",
                              cancellationReason: .policyChanged); return
            }
            guard clock() < deadline else {
                cancelUnadoptedTransport(connection, reason: .overallDeadline); overallDeadlineReached(); return
            }
            active[token]?.transport = connection
            if let context = active[token]?.context {
                (connection as? DNSQueryExecutionContextAccepting)?.setDNSQueryExecutionContext(context)
            }
            connection.send(query)
        } catch { registerFallbackError(error, token: token); attemptFailure(error, token: token) }
    }

    private func preferAvailableCandidate() {
        guard let availability, next < ordered.count else { return }
        let preferred = ordered[next]
        guard next != 0 || preferred.id != explorationID else { return }
        let priority = selector.schedulingPriority(scopeKey: scopeKey, candidateID: preferred.id)
        let startedIDs = Set(ordered.prefix(next).map(\.id))
        let startedServices = Set(ordered.prefix(next).map { $0.upstream.resolverServiceID })
        let preferredServiceStarted = startedServices.contains(preferred.upstream.resolverServiceID)
        // Three attempts is an admission limit, not a truncation of the
        // approved resolver set. Read only scoped scalar hints, once per
        // candidate; the factory still revalidates policy and owns admission.
        // Keep mixed mode's encrypted/plain phase positions unchanged.
        func rank(_ candidate: DNSUpstreamCandidate) -> Int {
            guard let value = availability(candidate) else { return 2 }
            if value.reusable > 0 { return 0 }
            return value.cold > 0 ? 1 : 2
        }
        let choices = approvedOrder.filter {
            !startedIDs.contains($0.id) && $0.upstream.encrypted == preferred.upstream.encrypted
        }.map { (candidate: $0, rank: rank($0),
                 priority: selector.schedulingPriority(scopeKey: scopeKey, candidateID: $0.id)) }
        var selected = preferred
        var best = choices.first { $0.candidate.id == preferred.id }?.rank ?? 2
        // The primary has already used its soft observation budget. Give an
        // available, non-cooling different service a backup slot before a
        // second address of that same stalled service. Keep every live
        // primary/handshake and Build9's conservative rotation boundary.
        // An absent pool hint is not evidence of available capacity.
        if next > 0, preferAvailableUntriedServices,
           let alternative = choices.filter({
               $0.rank < 2 && $0.priority < 2
                   && !startedServices.contains($0.candidate.upstream.resolverServiceID)
           }).min(by: {
               $0.priority == $1.priority ? $0.rank < $1.rank : $0.priority < $1.priority
           }) {
            selected = alternative.candidate; best = alternative.rank
        } else {
            for choice in choices {
                guard choice.priority == priority,
                      !preferUntriedServices || startedServices.contains(choice.candidate.upstream.resolverServiceID) == preferredServiceStarted else { continue }
                if choice.rank < best { selected = choice.candidate; best = choice.rank }
            }
        }
        guard selected.id != preferred.id else { return }
        let positions = (next..<ordered.count).filter {
            ordered[$0].upstream.encrypted == preferred.upstream.encrypted
        }
        let replacements = [selected] + positions.map { ordered[$0] }.filter { $0.id != selected.id }
        for (offset, position) in positions.enumerated() { ordered[position] = replacements[offset] }
        nativeDebug("dns adaptive available candidate_index=\(candidateIndex(selected)) rank=\(best) diverse=\(preferAvailableUntriedServices)")
    }

    private func startHedge(after token: UUID) {
        guard !finished, !isClosed, let attempt = active[token] else { return }
        active[token]?.hedgeTimer = nil
        preferAvailableUntriedServices = true
        nativeDebug("dns adaptive hedge candidate_index=\(candidateIndex(attempt.candidate)) elapsed_ms=\(elapsedMilliseconds(since: attempt.started)) active=\(active.count)")
        // This is deliberately not a failure: a valid late primary response
        // may still win, and its health history must not acquire a timeout.
        beginAttempt(reason: "soft-budget")
    }

    private func hedgeRotationTime(_ attempt: Attempt) -> TimeInterval {
        let base = exchangeStarted + exchangeBudget * (2.0 / 3.0)
        let milliseconds = planningLatencyMilliseconds(attempt.candidate)
        let backupHeadroom = (milliseconds ?? 0) / 1000 * 1.5 + 0.05
        // A successful RTT may come from a reused channel while this attempt
        // still needs a new TCP/TLS connection. Keep Build9's conservative
        // boundary so warm history cannot prematurely cancel that setup.
        return max(base, attempt.started + backupHeadroom, progressDeadline(attempt))
    }

    private func measuredColdCompletionWindow(_ candidate: DNSUpstreamCandidate) -> TimeInterval? {
        selector.estimatedMilliseconds(scopeKey: scopeKey, candidateID: candidate.id, phase: .cold)
            .map { $0 / 1000 * 1.25 + 0.05 }
    }

    private func coldCompletionWindow(_ candidate: DNSUpstreamCandidate) -> TimeInterval {
        if let measured = measuredColdCompletionWindow(candidate) { return measured }
        // Unknown paths still get a bounded third-candidate rescue window.
        // Once cold costs are observed, a warm RTT cannot shrink this window.
        return max(0.001, min(2, exchangeBudget / 3))
    }

    private func planningLatencyMilliseconds(_ candidate: DNSUpstreamCandidate) -> Double? {
        selector.planningLatencyMilliseconds(scopeKey: scopeKey, candidateID: candidate.id)
    }

    private func minimumThirdWindow() -> TimeInterval {
        guard next < ordered.count else { return .infinity }
        return minimumCompletionWindow(ordered[next])
    }

    private func minimumCompletionWindow(_ candidate: DNSUpstreamCandidate) -> TimeInterval {
        let minimum = min(1, exchangeBudget / 6)
        if let capacity = availability?(candidate), capacity.reusable > 0 {
            // A reusable stream does not need its historical cold handshake.
            // The hint remains advisory: checkout can still reject stale
            // ingress and the original deadline/health attribution stay put.
            let response = selector.estimatedMilliseconds(scopeKey: scopeKey,
                candidateID: candidate.id, phase: .response) ?? 0
            return max(minimum, response / 1000 * 1.5 + 0.05)
        }
        if let measured = measuredColdCompletionWindow(candidate) { return max(minimum, measured) }
        // Leave bounded dispatch slack around the nominal 2/3 boundary. An
        // unknown rescue estimate must allow a real timer to arrive slightly
        // late; measured cold costs retain their full completion headroom.
        let schedulingSlack = min(0.05, exchangeBudget / 12)
        let unmeasured = max(0.001, min(2, exchangeBudget / 3))
        return max(minimum, unmeasured - schedulingSlack)
    }

    private func progressDeadline(_ attempt: Attempt) -> TimeInterval {
        let progress = attempt.context.progress()
        func allowance(_ phase: DNSAdaptiveLatencyPhase, minimum: TimeInterval) -> TimeInterval {
            let measured = selector.estimatedMilliseconds(scopeKey: scopeKey, candidateID: attempt.candidate.id, phase: phase)
            return max(minimum, (measured ?? 0) / 1000 * 1.5 + 0.05)
        }
        if let started = progress.tlsStartedAt, progress.tlsReadyAt == nil {
            return started + allowance(.tls, minimum: 1)
        }
        switch progress.stage {
        case .transportConnecting:
            return (progress.transportStartedAt ?? attempt.started) + allowance(.transport, minimum: 1)
        case .ready, .sending, .awaitingResponse:
            return (progress.querySentAt ?? progress.changedAt) + allowance(.response, minimum: 0.25)
        case .receivingResponse:
            return progress.changedAt + allowance(.response, minimum: 0.25)
        case .completed:
            // A validated reply already exists on the child callback path.
            return deadline
        case .notStarted, .tlsHandshaking: return 0
        }
    }

    private func scheduleHedgeRotation(_ token: UUID, now: TimeInterval) {
        guard let attempt = active[token], next < ordered.count, token != primaryToken else { return }
        preferAvailableCandidate()
        let rotateAfter = max(0.001, hedgeRotationTime(attempt) - now)
        let delay: TimeInterval
        if rotateAfter < deadline - now,
           deadline - now - rotateAfter >= minimumThirdWindow() {
            delay = rotateAfter
        } else {
            // A currently slow/cold third may have a reusable stream by the
            // original conservative boundary. Recheck once there, without
            // polling, retiring the hedge early, or relaxing its progress
            // window. rotateHedge revalidates the actual candidate/headroom.
            let checkpoint = exchangeStarted + exchangeBudget * (2.0 / 3.0) - now
            guard availability != nil, checkpoint > 0, checkpoint < deadline - now else { return }
            delay = max(0.001, checkpoint)
        }
        let timer = DispatchWorkItem { [weak self] in self?.rotateHedge(token) }
        active[token]?.rotationTimer = timer
        queue.asyncAfter(deadline: .now() + delay, execute: timer)
    }

    private func rotateHedge(_ token: UUID) {
        guard !finished, !isClosed, token != primaryToken,
              let attempt = active[token], next < ordered.count else { return }
        active[token]?.rotationTimer = nil
        guard permitted() else {
            finishFailure(DNSPolicyFailure.configuration("DNS 轮替期间策略或接口已更新"), reason: "policy-update",
                          cancellationReason: .policyChanged); return
        }
        let now = clock()
        guard now.isFinite else {
            finishFailure(EngineError("DNS 单调时钟无效"), reason: "clock-invalid"); return
        }
        guard now < deadline else { overallDeadlineReached(); return }
        preferAvailableCandidate()
        // A concurrent query may have measured a slower RTT since admission.
        // Recompute headroom before retirement, never use a stale short timer
        // to clip that newly observed slow-but-working backup.
        if hedgeRotationTime(attempt) > now + 0.001 {
            scheduleHedgeRotation(token, now: now); return
        }
        guard deadline - now >= minimumThirdWindow() else { return }
        retired.append(RetiredObservation(candidate: attempt.candidate,
            milliseconds: max(0, now - attempt.started) * 1000,
            observation: attempt.observation, evidence: transportEvidence(attempt.transport)))
        nativeDebug("dns adaptive retire candidate_index=\(candidateIndex(attempt.candidate)) elapsed_ms=\(elapsedMilliseconds(since: attempt.started)) reason=late-hedge")
        // Remove the token before cancel(), including synchronous callbacks.
        // Transport/native pending-dial admission is still owned by its own
        // existing cancellation/acknowledgement path, not released here.
        clearAttempt(token, reason: .hedgeRotation)
        // Keep the candidate whose completion window was checked above.
        // Cancel may publish a different pool hint before the next admission.
        beginAttempt(reason: "hedge-rotation", refreshCandidates: false)
    }

    private func accept(_ answer: Data, token: UUID) {
        guard !finished, !isClosed, let attempt = active[token], let query else { return }
        guard permitted() else {
            finishFailure(DNSPolicyFailure.configuration("DNS 应答期间策略已更新"), reason: "policy-update",
                          cancellationReason: .policyChanged); return
        }
        guard DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
            networkFailure(token: token, error: EngineError("加密 DNS 应答与原问题不匹配"), reason: "response-mismatch"); return
        }
        let code = answer[answer.startIndex + 3] & 0x0f
        nativeDebug("dns adaptive response candidate_index=\(candidateIndex(attempt.candidate)) elapsed_ms=\(elapsedMilliseconds(since: attempt.started)) rcode=\(code)")
        if code == 2 {
            prioritizeUntriedResolverServices()
            networkFailure(token: token, error: EngineError("加密 DNS 上游 SERVFAIL"), reason: "servfail"); return
        }
        // An authenticated REFUSED is terminal. Other valid DNS results,
        // notably NXDOMAIN/NODATA, are not outages to shop across providers.
        if code == 0 || code == 3 {
            selector.record(attempt.observation, milliseconds: max(0, clock() - attempt.started) * 1000,
                            success: true, transport: transportEvidence(attempt.transport), progress: attempt.context.progress())
            for (pendingToken, pending) in active where pendingToken != token {
                // We only know it has not replied yet. This is a latency lower
                // bound, not a timeout, outage, failure count or cooldown.
                if transportEvidence(pending.transport) != .notStarted {
                    selector.recordPendingLatencyLowerBound(pending.observation,
                        milliseconds: max(0, clock() - pending.started) * 1000)
                }
            }
            for observation in retired {
                // A valid authenticated winner legitimizes only the elapsed
                // lower bound observed before retirement, never an invented
                // timeout, network failure, cooldown or post-cancel latency.
                if observation.evidence != .notStarted {
                    selector.recordPendingLatencyLowerBound(observation.observation,
                        milliseconds: observation.milliseconds)
                }
            }
        }
        finishAnswer(answer)
    }

    private func prioritizeUntriedResolverServices() {
        // Retain Build9's original three slots, started prefix and all live
        // transports. Only a matching upstream SERVFAIL makes trying
        // another recursive service preferable to another IP of the same
        // service. The complete rank was approved before this query began.
        let remaining = ordered.count - next
        guard remaining > 0 else { return }
        preferUntriedServices = true
        preferAvailableUntriedServices = true
        let started = Array(ordered.prefix(next))
        let usedIDs = Set(started.map(\.id))
        let available = approvedOrder.filter { !usedIDs.contains($0.id) }
        var covered = Set(started.map { $0.upstream.resolverServiceID })
        var tail: [DNSUpstreamCandidate] = []
        for candidate in available where covered.insert(candidate.upstream.resolverServiceID).inserted {
            tail.append(candidate)
            if tail.count == remaining { break }
        }
        if tail.count < remaining {
            let selected = Set(tail.map(\.id))
            for candidate in available where !selected.contains(candidate.id) {
                tail.append(candidate)
                if tail.count == remaining { break }
            }
        }
        ordered = started + tail
    }

    private func attemptFailure(_ error: Error, token: UUID) {
        guard !finished, !isClosed, active[token] != nil else { return }
        if error is DNSPolicyFailure { finishFailure(error, reason: "policy-denial", cancellationReason: .policyChanged) }
        else { networkFailure(token: token, error: error) }
    }

    private func registerFallbackError(_ error: Error, token: UUID) {
        // Retain the same terminal metadata for a coordinator deadline fence,
        // including encrypted-only queries with no plaintext fallback phase.
        if error is DNSQueryTimeoutError { return }
        if let known = error as? EncryptedDNSQueryFailure, known.permitsProxyFallback { return }
        if let network = error as? NWError,
           EncryptedDNSQueryFailure.classify(network).permitsProxyFallback { return }
        if case .timeout? = error as? TraditionalDNSBootstrapError { return }
        // An unknown Error can perform arbitrary work while bridging NSError.
        // Retain that original value before any such classification so a slow
        // bridge cannot let deadline cancellation pass an empty deny snapshot.
        admission.lock(); defer { admission.unlock() }
        guard !closed, barrierTokens.contains(token) else { return }
        // Never replace an authentication/unknown barrier with another
        // candidate's network outage, timeout or synthetic SERVFAIL.
        if fallbackErrorBarrier == nil { fallbackErrorBarrier = error }
    }

    private func registerFallbackAnswer(_ answer: Data, query: Data, token: UUID) {
        guard DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
            registerFallbackError(EncryptedDNSQueryFailure.invalidResponse, token: token); return
        }
        admission.lock(); defer { admission.unlock() }
        guard !closed, barrierTokens.contains(token) else { return }
        let code = answer[answer.startIndex + 3] & 0x0f
        if code == 5, deadlineRefusalBarrier == nil { deadlineRefusalBarrier = answer }
        if code == 0 || code == 3 { fallbackAnswerBarrier = answer }
        else if fallbackAnswerBarrier == nil { fallbackAnswerBarrier = answer }
    }

    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
        admission.lock()
        var answer = fallbackAnswerBarrier, error = fallbackErrorBarrier
        let question = barrierQuestion, children = barrierChildren
        admission.unlock()
        for child in children {
            guard let barrier = child.proxyFallbackBarrier() else { continue }
            switch barrier {
            case .failure(let blocked): if error == nil { error = blocked }
            case .answer(let received):
                guard let question, DNSMessageInspection.responseMatchesQuery(received, query: question) else {
                    if error == nil { error = EncryptedDNSQueryFailure.invalidResponse }; continue
                }
                if answer == nil || [UInt8(0), 3].contains(received[received.startIndex + 3] & 0x0f) { answer = received }
            }
        }
        if let answer, [UInt8(0), 3].contains(answer[answer.startIndex + 3] & 0x0f) { return .answer(answer) }
        if let error { return .failure(error) }
        return answer.map(DNSProxyFallbackBarrier.answer)
    }
    private func queryDeadlineBarrier() -> DNSProxyFallbackBarrier? {
        admission.lock()
        let refused = deadlineRefusalBarrier, question = barrierQuestion, children = barrierChildren
        admission.unlock()
        // A previously admitted REFUSED stays terminal for later callers too.
        // Other candidates may already have positive replies queued when the
        // deadline closes admission; those cannot erase this refusal fence.
        if let refused { return .answer(refused) }
        for child in children {
            if case .answer(let answer)? = child.proxyFallbackBarrier(), let question,
               DNSMessageInspection.responseMatchesQuery(answer, query: question),
               answer[answer.startIndex + 3] & 0x0f == 5 { return .answer(answer) }
        }
        return proxyFallbackBarrier()
    }

    private func hasNativeOrdinaryQueryReset(_ attempt: Attempt) -> Bool {
        guard query.flatMap({ DNSMessageInspection.singleQuestion(in: $0) }).map({
            $0.`class` == 1 && [UInt16(1), 28, 64, 65].contains($0.type)
        }) == true else { return false }
        return attempt.context.connectionResetProgress().map {
            $0.transportReadyAt != nil && $0.tlsStartedAt != nil
                && $0.responseStartedAt == nil && $0.responseCompletedAt == nil
        } == true
    }

    private func availableRecoveryCandidate(for failed: DNSUpstreamCandidate) -> DNSUpstreamCandidate? {
        guard let availability else { return nil }
        let remaining = deadline - clock()
        guard remaining.isFinite, remaining > 0 else { return nil }
        let startedIDs = Set(ordered.prefix(next).map(\.id))
        let otherLiveServices = Set(active.values.filter { $0.candidate.id != failed.id }
            .map { $0.candidate.upstream.resolverServiceID })
        // A measured approved alternative keeps its chance by actually taking
        // this slot. Previously another IP could veto recovery here, while
        // provider-diversity ordering then admitted an unmeasured third party.
        let choices = approvedOrder.enumerated().compactMap { index, candidate
            -> (candidate: DNSUpstreamCandidate, priority: Int, rank: Int, index: Int)? in
            guard candidate.upstream.encrypted, !startedIDs.contains(candidate.id),
                  !otherLiveServices.contains(candidate.upstream.resolverServiceID),
                  let capacity = availability(candidate), capacity.reusable > 0 || capacity.cold > 0 else { return nil }
            let priority = selector.schedulingPriority(scopeKey: scopeKey, candidateID: candidate.id)
            guard priority == 0 || (priority < 2 && capacity.reusable > 0
                && candidate.upstream.resolverServiceID != failed.upstream.resolverServiceID),
                  remaining >= minimumCompletionWindow(candidate) else { return nil }
            return (candidate, priority, capacity.reusable > 0 ? 0 : 1, index)
        }
        if let best = choices.min(by: {
            if $0.priority != $1.priority { return $0.priority < $1.priority }
            if $0.rank != $1.rank { return $0.rank < $1.rank }
            return $0.index < $1.index
        }) { return best.candidate }
        guard let capacity = availability(failed), capacity.reusable > 0 || capacity.cold > 0,
              remaining >= minimumCompletionWindow(failed) else { return nil }
        return failed
    }

    private func networkRecoveryCandidate(_ attempt: Attempt, token: UUID,
                                           category: EncryptedDNSQueryFailure) -> DNSUpstreamCandidate? {
        // Spend only the existing last slot, after a different hedge is live.
        // An approved candidate may suffer a real connection reset while
        // another provider is still blackholing. Ordinary queries can use
        // exact, attempt-local reset evidence during TLS too; a new attempt
        // must authenticate TLS normally before it can send any question.
        guard !usedNetworkRecovery, category == .network,
              attemptCount == 2, next == 2, ordered.count == 3, active.count == 2,
              attempt.candidate.upstream.encrypted, ordered[next].upstream.encrypted,
              transportEvidence(attempt.transport) == .fresh, availability != nil else { return nil }
        guard active.contains(where: { other in
            other.key != token && other.value.candidate.upstream.encrypted
                && other.value.candidate.upstream.resolverServiceID != attempt.candidate.upstream.resolverServiceID
        }) else { return nil }
        let progress = attempt.context.progress()
        let ordinaryQuery = query.flatMap { DNSMessageInspection.singleQuestion(in: $0) }.map {
            $0.`class` == 1 && [UInt16(1), 28, 64, 65].contains($0.type)
        } ?? false
        let verified = attempt.hadVerifiedSuccessAtAdmission || selector.hasSuccessfulResponse(
            scopeKey: scopeKey, candidateID: attempt.candidate.id, since: attempt.started)
        let sentPrimary = token == primaryToken && progress.tlsReadyAt != nil && progress.querySentAt != nil
            && (verified || (ordinaryQuery && progress.transportReadyAt != nil && progress.responseStartedAt == nil))
        // This evidence lives on the physical attempt, independently of the
        // bounded diagnostics ring. Generic network categories, trust errors,
        // late idle callbacks and resets after cancellation cannot grant it.
        // A hedge with this evidence can also recover in the same last slot.
        let nativeReset = hasNativeOrdinaryQueryReset(attempt)
        guard progress.responseCompletedAt == nil, sentPrimary || nativeReset else { return nil }
        return availableRecoveryCandidate(for: attempt.candidate)
    }

    private func networkFailure(token: UUID, error: Error, reason: String = "network-error") {
        guard !finished, !isClosed, let attempt = active[token] else { return }
        guard permitted() else {
            finishFailure(DNSPolicyFailure.configuration("DNS 失败期间策略已更新"), reason: "policy-update",
                          cancellationReason: .policyChanged); return
        }
        nativeDebug("dns adaptive failure candidate_index=\(candidateIndex(attempt.candidate)) elapsed_ms=\(elapsedMilliseconds(since: attempt.started)) reason=\(reason) error=\(Self.debugErrorCategory(error))")
        if EncryptedDNSQueryFailure.classify(error) == .capacity {
            // Local backpressure says nothing about this provider's health.
            // Do not fan out more dials into the same exhausted process, or
            // discard a still-running healthy primary because its hedge was
            // denied admission. The deny barrier still forbids plaintext.
            localCapacityError = error
            for live in active.keys {
                active[live]?.hedgeTimer?.cancel(); active[live]?.hedgeTimer = nil
                active[live]?.rotationTimer?.cancel(); active[live]?.rotationTimer = nil
            }
            clearAttempt(token)
            if active.isEmpty { finishFailure(error, reason: "local-capacity") }
            return
        }
        let reasonCategory = EncryptedDNSQueryFailure.classify(error)
        if reasonCategory == .cancelled || reasonCategory == .policy || reasonCategory == .configuration {
            finishFailure(error, reason: "local-revocation",
                          cancellationReason: reasonCategory == .cancelled ? .cleanup : .policyChanged); return
        }
        if reasonCategory == .timeout, attempt.context.inheritedDeadlineReached {
            overallDeadlineReached(); return
        }
        let recoveryCandidate = networkRecoveryCandidate(attempt, token: token, category: reasonCategory)
        let earlyNativeReset = !usedNetworkRecovery && reasonCategory == .network
            && attemptCount == 1 && next == 1 && ordered.count == 3 && active.count == 1
            && attempt.candidate.upstream.encrypted && transportEvidence(attempt.transport) == .fresh
            && hasNativeOrdinaryQueryReset(attempt)
        // A child now owns the same original deadline as its parent. Its
        // timeout callback can win the timer race; keep the parent's existing
        // minimum cold observation rule for health attribution in either order.
        if transportEvidence(attempt.transport) != .notStarted,
           reasonCategory != .timeout || canAttributeDeadlineFailure(attempt) {
            selector.record(attempt.observation, milliseconds: max(0, clock() - attempt.started) * 1000,
                            success: false, transport: transportEvidence(attempt.transport))
        }
        lastNetworkError = error; clearAttempt(token)
        if earlyNativeReset {
            // Cancellation can consume time or change the pool hint. Select
            // the warm alternative only after that work has finished.
            let remaining = deadline - clock()
            let warmSibling = remaining.isFinite && remaining > 0 && ordered[next].upstream.encrypted ? approvedOrder.first { candidate in
                guard candidate.id != attempt.candidate.id, candidate.upstream.encrypted,
                      candidate.upstream.resolverServiceID == attempt.candidate.upstream.resolverServiceID,
                      candidate.upstream.target.host != attempt.candidate.upstream.target.host,
                      selector.schedulingPriority(scopeKey: scopeKey, candidateID: candidate.id) == 0,
                      let capacity = availability?(candidate), capacity.reusable > 0 else { return false }
                return remaining >= minimumCompletionWindow(candidate)
            } : nil
            if let warmSibling {
                // Move within the encrypted tail, retaining mixed-mode phase
                // positions and removing any existing third-slot duplicate.
                let positions = (next..<ordered.count).filter { ordered[$0].upstream.encrypted }
                let replacements = [warmSibling] + positions.map { ordered[$0] }.filter { $0.id != warmSibling.id }
                for (offset, position) in positions.enumerated() { ordered[position] = replacements[offset] }
                beginAttempt(reason: "warm-reset-alternative", refreshCandidates: false)
                return
            }
            // Replaying the failed address first gives no new path. Admit
            // another service in slot two and retain only this candidate
            // until the existing third-slot soft budget is available.
            deferredNetworkReset = attempt.candidate
            preferAvailableUntriedServices = true
        }
        if let recoveryCandidate {
            // Cancellation may synchronously consume time or change an idle
            // hint. Check the completion window again before spending it.
            let remaining = deadline - clock()
            if remaining.isFinite, remaining >= minimumCompletionWindow(recoveryCandidate) {
                usedNetworkRecovery = true
                ordered[next] = recoveryCandidate
                // The failed token is already gone. Recheck policy/deadline
                // in the factory with a new observation/context, no new slot.
                let recoveryReason = attempt.context.progress().tlsReadyAt == nil
                    ? "tls-reset-recovery" : "post-send-network-recovery"
                beginAttempt(reason: recoveryReason, refreshCandidates: false)
                return
            }
        }
        if next < ordered.count, clock() < deadline { beginAttempt(reason: "replacement") }
        else if active.isEmpty { finishFailure(error, reason: "attempts-exhausted") }
    }
    private func overallDeadlineReached() {
        admission.lock(); let cancelled = closed
        if !cancelled { deadlineSignalled = true }
        admission.unlock()
        guard !finished, !cancelled else { return }
        guard permitted() else {
            finishFailure(DNSPolicyFailure.configuration("DNS 总期限期间策略已更新"),
                          reason: "policy-update", completingDeadline: true, cancellationReason: .policyChanged); return
        }
        let expired = active.values.filter(canAttributeDeadlineFailure).map {
            RetiredObservation(candidate: $0.candidate,
                milliseconds: max(0, clock() - $0.started) * 1000,
                observation: $0.observation, evidence: transportEvidence($0.transport))
        }
        for attempt in active.values where transportEvidence(attempt.transport) != .notStarted {
            nativeDebug("dns adaptive failure candidate_index=\(candidateIndex(attempt.candidate)) elapsed_ms=\(elapsedMilliseconds(since: attempt.started)) reason=overall-deadline error=engine")
        }
        finishFailure(DNSQueryTimeoutError(inheritedDeadlineReached: executionContext.absoluteDeadline == deadline),
                      reason: "overall-deadline", completingDeadline: true,
                      cancellationReason: .overallDeadline)
        // Return at the original deadline, but learn only after logical child
        // cancellation has exposed already-admitted deny/answer metadata.
        cancellations.notify(queue: queue) {
            guard self.permitted(), self.proxyFallbackBarrier() == nil else { return }
            for observation in expired where observation.evidence != .notStarted {
                self.selector.record(observation.observation, milliseconds: observation.milliseconds,
                                     success: false, transport: observation.evidence)
            }
        }
    }
    private func clearAttempt(_ token: UUID, reason: DNSAttemptCancellationReason = .cleanup) {
        guard let attempt = active.removeValue(forKey: token) else { return }
        admission.lock(); barrierTokens.remove(token); admission.unlock()
        attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel(); cancelTransport(attempt.transport, reason: reason)
    }
    private func transportEvidence(_ transport: NativeRoutedDatagram?) -> DNSQueryTransportEvidence {
        (transport as? DNSQueryTransportEvidenceProviding)?.dnsQueryTransportEvidence() ?? .unknown
    }
    private func canAttributeDeadlineFailure(_ attempt: Attempt) -> Bool {
        let evidence = transportEvidence(attempt.transport)
        // The query still times out at its original deadline. A late cold
        // replacement with less than one normal setup window is not, however,
        // a completed measurement of this provider's availability.
        guard evidence == .fresh || evidence == .reusedThenFresh else { return true }
        let progress = attempt.context.progress()
        let coldStarted = max(attempt.started, progress.transportStartedAt ?? progress.tlsStartedAt ?? attempt.started)
        return clock() - coldStarted >= attempt.minimumColdObservation
    }
    private func clearAttempts(reason: DNSAttemptCancellationReason) {
        let attempts = Array(active.values); active.removeAll()
        admission.lock(); barrierTokens.removeAll(); admission.unlock()
        // Remove all tokens before cancellation, so even a synchronous late
        // callback cannot recreate a completed or policy-invalid query.
        for attempt in attempts {
            attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel(); cancelTransport(attempt.transport, reason: reason)
        }
        retired.removeAll()
    }
    private func cancelUnadoptedTransport(_ transport: NativeRoutedDatagram, reason: DNSAttemptCancellationReason) {
        cancelTransport(transport, reason: reason)
    }
    private func cancelTransport(_ transport: NativeRoutedDatagram?, reason: DNSAttemptCancellationReason) {
        guard let transport else { return }
        guard let acknowledging = transport as? DNSQueryCancellationAcknowledging else {
            // Such a custom transport keeps its original cancellation behavior,
            // but cannot promise a deadline fence for a new query generation.
            admission.lock(); deadlineFenceAvailable = false; admission.unlock()
            transport.cancel(); return
        }
        cancellations.enter()
        let group = cancellations, once = NSLock()
        var acknowledged = false
        acknowledging.cancel(reason: reason) {
            once.lock()
            guard !acknowledged else { once.unlock(); return }
            acknowledged = true; once.unlock(); group.leave()
        }
    }
    private func finishAnswer(_ answer: Data, completingDeadline: Bool = false,
                              cancellationReason: DNSAttemptCancellationReason = .winnerSelected) {
        guard !finished, !(completingDeadline ? isClientCancelled : isClosed) else { return }
        nativeDebug("dns adaptive finish elapsed_ms=\(elapsedMilliseconds(since: exchangeStarted)) attempts=\(attemptCount) reason=answer rcode=\(answer[answer.startIndex + 3] & 0x0f)")
        finished = true; deadlineTimer?.cancel(); deadlineTimer = nil; clearAttempts(reason: cancellationReason); query = nil
        receive(answer)
    }
    private func finishFailure(_ error: Error, reason: String = "failed", completingDeadline: Bool = false,
                               cancellationReason: DNSAttemptCancellationReason = .cleanup) {
        guard !finished, !(completingDeadline ? isClientCancelled : isClosed) else { return }
        if protectProxyFallback, let barrier = proxyFallbackBarrier() {
            switch barrier {
            case .answer(let answer): finishAnswer(answer, completingDeadline: completingDeadline,
                                                   cancellationReason: cancellationReason); return
            case .failure(let blocked):
                finished = true; deadlineTimer?.cancel(); deadlineTimer = nil; clearAttempts(reason: cancellationReason); query = nil
                failure(blocked); return
            }
        }
        if let policy = error as? DNSPolicyFailure, let query,
           let reply = DNSMessageInspection.errorResponse(to: query, code: policy.responseCode) {
            nativeDebug("dns adaptive policy reason=\(reason) error=\(Self.debugErrorCategory(error))")
            finishAnswer(reply, completingDeadline: completingDeadline, cancellationReason: .policyChanged); return
        }
        nativeDebug("dns adaptive finish elapsed_ms=\(elapsedMilliseconds(since: exchangeStarted)) attempts=\(attemptCount) reason=\(reason) error=\(Self.debugErrorCategory(error))")
        finished = true; deadlineTimer?.cancel(); deadlineTimer = nil; clearAttempts(reason: cancellationReason); query = nil
        failure(error)
    }
    func queryDeadlineReached() {
        admission.lock()
        guard !closed, !deadlineSignalled else { admission.unlock(); return }
        deadlineSignalled = true
        // Keep this instance alive after the parent drops its transport. Mark
        // admission synchronously so an already queued late answer cannot
        // record a success or a hint after the parent returned SERVFAIL.
        queue.async { self.overallDeadlineReached() }
        admission.unlock()
    }
    func queryDeadlineReached(completion: @escaping (DNSProxyFallbackBarrier?) -> Void) {
        admission.lock()
        if !closed { deadlineSignalled = true }
        // Atomically hand off under the same lock as cancel(). Seeing closed
        // therefore also means its owner-queue cleanup has been submitted.
        queue.async {
            self.overallDeadlineReached()
            self.notifyAfterLogicalFinish {
                self.admission.lock()
                let cancelled = self.closed, available = self.deadlineFenceAvailable
                self.admission.unlock()
                if cancelled { completion(.failure(EncryptedDNSQueryFailure.cancelled)) }
                else if !available { completion(.failure(EncryptedDNSQueryFailure.configuration)) }
                else { completion(self.queryDeadlineBarrier()) }
            }
        }
        admission.unlock()
    }
    private func notifyAfterLogicalFinish(_ completion: @escaping () -> Void) {
        // A concurrent cancel may close admission while this queue is already
        // running a deadline callback. Its queued cleanup must first enter all
        // child cancellation groups; a notify on the still-empty group would
        // acknowledge too early. All calls here already own a finish/cancel.
        guard finished else {
            queue.async { self.notifyAfterLogicalFinish(completion) }; return
        }
        cancellations.notify(queue: queue, execute: completion)
    }
    func phaseDeadlineReached(completion: @escaping () -> Void) {
        admission.lock()
        if !closed { deadlineSignalled = true }
        admission.unlock()
        queue.async {
            guard !self.finished, !self.isClientCancelled else {
                self.notifyAfterLogicalFinish(completion); return
            }
            self.deadlineTimer?.cancel(); self.deadlineTimer = nil
            let expired = self.active.values.filter(self.canAttributeDeadlineFailure).map {
                RetiredObservation(candidate: $0.candidate,
                    milliseconds: max(0, self.clock() - $0.started) * 1000,
                    observation: $0.observation, evidence: self.transportEvidence($0.transport))
            }
            self.clearAttempts(reason: .encryptedPhaseDeadline)
            self.cancellations.notify(queue: self.queue) {
                guard !self.finished, !self.isClientCancelled else { completion(); return }
                guard self.permitted() else {
                    self.finishFailure(DNSPolicyFailure.configuration("DNS 加密阶段截止期间策略已更新"),
                        reason: "policy-update", completingDeadline: true, cancellationReason: .policyChanged)
                    completion(); return
                }
                // Cancellation ACK may expose an already admitted answer or
                // authentication/capacity failure. Keep its terminal barrier
                // without mislabeling it as a provider's network timeout.
                if self.proxyFallbackBarrier() == nil {
                    for observation in expired where observation.evidence != .notStarted {
                        self.selector.record(observation.observation,
                            milliseconds: observation.milliseconds, success: false, transport: observation.evidence)
                    }
                }
                self.finishFailure(DNSQueryTimeoutError(), reason: "encrypted-phase-deadline",
                    completingDeadline: true, cancellationReason: .encryptedPhaseDeadline)
                completion()
            }
        }
    }
    func encryptedPhaseContinuationDeadline(completion: @escaping (TimeInterval?) -> Void) {
        queue.async {
            guard !self.finished, !self.isClosed, self.permitted(), !self.active.isEmpty else {
                completion(nil); return
            }
            // Three approved candidates share the original exchange budget.
            // Build9 keeps the primary and only rotates the hedge near 2/3
            // of that budget, so a parent checkpoint must not erase its turn.
            if self.next < self.ordered.count || self.attemptCount >= 3 {
                completion(self.deadline); return
            }
            // Even a late-started second candidate needs a useful cold
            // TCP/TLS window; a fast reused RTT cannot shorten that allowance.
            let required = self.active.values.map { attempt -> TimeInterval in
                let known = self.planningLatencyMilliseconds(attempt.candidate) ?? 0
                return max(attempt.started + max(3, known / 1000 * 1.75 + 0.25),
                    attempt.started + max(attempt.minimumColdObservation, self.coldCompletionWindow(attempt.candidate)),
                    self.progressDeadline(attempt))
            }.max() ?? self.clock()
            completion(min(self.deadline, required))
        }
    }
    func cancel() { cancel(completion: {}) }
    func cancel(completion: @escaping () -> Void) {
        cancel(reason: .callerCancelled, completion: completion)
    }
    func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        admission.lock()
        if !closed { cancellationReason = reason }
        let reason = cancellationReason ?? reason
        closed = true
        queue.async {
            if !self.finished {
                nativeDebug("dns adaptive finish elapsed_ms=\(self.elapsedMilliseconds(since: self.exchangeStarted)) attempts=\(self.attemptCount) reason=cancelled")
            }
            self.finished = true; self.deadlineTimer?.cancel(); self.deadlineTimer = nil
            self.clearAttempts(reason: reason); self.query = nil
            self.cancellations.notify(queue: self.queue, execute: completion)
        }
        admission.unlock()
    }
    // Only numeric indices, elapsed time and fixed categories are permitted
    // here. Candidate IDs, error descriptions and NSError domains can embed
    // configured URLs, queried names, policy labels or credentials.
    private func candidateIndex(_ candidate: DNSUpstreamCandidate) -> Int {
        candidates.firstIndex { $0.id == candidate.id } ?? -1
    }
    private func elapsedMilliseconds(since started: TimeInterval) -> Int {
        let elapsed = clock() - started
        return elapsed.isFinite ? Int(min(60_000, max(0, elapsed * 1000))) : 0
    }
    private static func debugErrorCategory(_ error: Error) -> String {
        if error is DNSQueryTimeoutError { return "query-timeout" }
        if let policy = error as? DNSPolicyFailure {
            switch policy { case .refused: return "policy-refused"; case .configuration: return "policy-invalid" }
        }
        if let native = error as? NativeOutboundError {
            switch native {
            case .unsupported: return "native-unsupported"
            case .connection: return "native-connection"
            case .protocolError: return "native-protocol"
            case .crypto: return "native-crypto"
            case .cancelled: return "native-cancelled"
            }
        }
        if let network = error as? NWError {
            switch network {
            case .posix(let code): return "posix-\(code.rawValue)"
            case .dns(let code): return "dns-\(code)"
            case .tls(let code): return "tls-\(code)"
            @unknown default: return "network-other"
            }
        }
        if error is EngineError { return "engine" }
        let bridged = error as NSError
        switch bridged.domain {
        case NSPOSIXErrorDomain: return "posix-\(bridged.code)"
        case NSOSStatusErrorDomain: return "osstatus-\(bridged.code)"
        case NSURLErrorDomain: return "url-\(bridged.code)"
        case NSCocoaErrorDomain: return "cocoa-\(bridged.code)"
        default: return "other"
        }
    }
    deinit {
        deadlineTimer?.cancel()
        for attempt in active.values {
            attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel()
            if let acknowledging = attempt.transport as? DNSQueryCancellationAcknowledging {
                acknowledging.cancel(reason: .cleanup, completion: {})
            } else { attempt.transport?.cancel() }
        }
    }
}

/// The only input to traditional DNS is the configured DoH service hostname.
/// Retain the application query locally until a numeric, policy-approved dial
/// address is available; failures never forward that query to a plain server.
private final class DoHBootstrapDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding, DNSConnectionPrewarming, DNSQueryExecutionContextAccepting {
    private let endpoint: DoHEndpoint
    private let resolver: TraditionalDNSBootstrapResolver
    private let queue: DispatchQueue
    private let permitted: () -> Bool
    private let makeEncrypted: (String) throws -> NativeRoutedDatagram
    private let failure: (Error) -> Void
    private let admission = NSLock()
    private var closed = false, started = false
    private var cancellationReason: DNSAttemptCancellationReason?
    private var executionContext: DNSQueryExecutionContext?
    private var request: UUID?
    private var encrypted: NativeRoutedDatagram?
    private var preparationTimer: DispatchWorkItem?
    private var preparationCompletion: ((Result<Void, EncryptedDNSQueryFailure>) -> Void)?

    init(endpoint: DoHEndpoint, resolver: TraditionalDNSBootstrapResolver, queue: DispatchQueue,
         permitted: @escaping () -> Bool,
         makeEncrypted: @escaping (String) throws -> NativeRoutedDatagram,
         failure: @escaping (Error) -> Void) {
        self.endpoint = endpoint; self.resolver = resolver
        self.queue = DispatchQueue(label: "app.hajimi.dns.doh-bootstrap-gateway", target: queue)
        self.permitted = permitted; self.makeEncrypted = makeEncrypted; self.failure = failure
    }
    private var isClosed: Bool { admission.lock(); defer { admission.unlock() }; return closed }

    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
        admission.lock(); defer { admission.unlock() }
        if !started, !closed { executionContext = context }
    }

    func send(_ data: Data) {
        start(data: data, preparationDeadline: nil, prepared: nil)
    }
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Void, EncryptedDNSQueryFailure>) -> Void) {
        start(data: nil, preparationDeadline: absoluteDeadline, prepared: completion)
    }
    private func start(data: Data?, preparationDeadline: TimeInterval?,
                       prepared: ((Result<Void, EncryptedDNSQueryFailure>) -> Void)?) {
        admission.lock()
        guard !closed, !started else { admission.unlock(); prepared?(.failure(.cancelled)); return }
        started = true; admission.unlock()
        queue.async {
            guard !self.isClosed else { return }
            self.preparationCompletion = prepared
            if let preparationDeadline {
                let remaining = preparationDeadline - ProcessInfo.processInfo.systemUptime
                guard remaining.isFinite, remaining > 0 else { self.fail(EncryptedDNSQueryFailure.timeout); return }
                let timer = DispatchWorkItem { [weak self] in
                    guard let self, !self.isClosed else { return }
                    self.finishPreparation(.failure(.timeout))
                    self.cancel(reason: .requestDeadline, completion: {})
                }
                self.preparationTimer = timer
                self.queue.asyncAfter(deadline: .now() + remaining, execute: timer)
            }
            guard self.permitted() else { self.fail(EncryptedDNSQueryFailure.policy); return }
            self.request = self.resolver.resolveDoHHost(self.endpoint.host, queue: self.queue) { [weak self] result in
                guard let self else { return }; self.request = nil
                guard !self.isClosed else { return }
                guard self.permitted() else { self.fail(EncryptedDNSQueryFailure.policy); return }
                do {
                    let addresses = try result.get()
                    guard let address = addresses.first else { throw EngineError("DoH 引导未返回 IP") }
                    let transport = try self.makeEncrypted(address)
                    guard !self.isClosed, self.permitted() else {
                        self.admission.lock(); let reason = self.cancellationReason ?? .policyChanged; self.admission.unlock()
                        self.cancelEncrypted(transport, reason: reason, completion: {})
                        if !self.isClosed { self.fail(EncryptedDNSQueryFailure.policy) }
                        return
                    }
                    self.admission.lock(); self.encrypted = transport; self.admission.unlock()
                    if let context = self.executionContext {
                        (transport as? DNSQueryExecutionContextAccepting)?.setDNSQueryExecutionContext(context)
                    }
                    if let preparationDeadline {
                        guard let preparation = transport as? DNSConnectionPrewarming else {
                            transport.cancel(); self.fail(EncryptedDNSQueryFailure.configuration); return
                        }
                        preparation.prewarm(absoluteDeadline: preparationDeadline) { [weak self] result in
                            self?.queue.async {
                                guard let self, !self.isClosed else { return }
                                self.finishPreparation(result)
                            }
                        }
                    } else if let data { transport.send(data) }
                } catch { self.fail(error) }
            }
        }
    }
    private func fail(_ error: Error) {
        if preparationCompletion != nil { finishPreparation(.failure(EncryptedDNSQueryFailure.classify(error))) }
        else { failure(error) }
    }
    private func finishPreparation(_ result: Result<Void, EncryptedDNSQueryFailure>) {
        preparationTimer?.cancel(); preparationTimer = nil
        let completion = preparationCompletion; preparationCompletion = nil; completion?(result)
    }
    func cancel() { cancel(completion: {}) }
    func cancel(completion: @escaping () -> Void) {
        cancel(reason: .callerCancelled, completion: completion)
    }
    func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        admission.lock()
        if !closed { cancellationReason = reason }
        let reason = cancellationReason ?? reason
        closed = true; admission.unlock()
        queue.async {
            self.preparationTimer?.cancel(); self.preparationTimer = nil; self.preparationCompletion = nil
            if let request = self.request { self.resolver.cancel(request); self.request = nil }
            self.admission.lock(); let child = self.encrypted; self.admission.unlock()
            if let child { self.cancelEncrypted(child, reason: reason, completion: completion) }
            else { completion() }
        }
    }
    private func cancelEncrypted(_ child: NativeRoutedDatagram, reason: DNSAttemptCancellationReason,
                                  completion: @escaping () -> Void) {
        if let acknowledging = child as? DNSQueryCancellationAcknowledging {
            acknowledging.cancel(reason: reason, completion: completion)
        } else { child.cancel(); completion() }
    }
    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
        admission.lock(); let provider = encrypted as? DNSProxyFallbackBarrierProviding; admission.unlock()
        return provider?.proxyFallbackBarrier()
    }
    func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence {
        admission.lock(); let provider = encrypted as? DNSQueryTransportEvidenceProviding; admission.unlock()
        return provider?.dnsQueryTransportEvidence() ?? .notStarted
    }
    deinit {
        preparationTimer?.cancel(); if let request { resolver.cancel(request) }
        if let encrypted { cancelEncrypted(encrypted, reason: .cleanup, completion: {}) }
    }
}

private final class TCPDNSQueryDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSQueryDeadlineAwareDatagram, DNSProxyFallbackBarrierProviding {
    typealias Dialer = (ResolvedRoute, RequestTarget, DispatchQueue,
                       @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) -> (() -> Void)?
    private let route: ResolvedRoute, target: RequestTarget
    private let queue: DispatchQueue
    private let permitted: () -> Bool
    private let receiveHandler: (Data) -> Void, failureHandler: (Error) -> Void
    private var stream: NativeOutboundByteStream?
    private var buffer = Data()
    private var started = false, stopped = false
    private let admission = NSLock()
    private var revoked = false
    private var fallbackBarrier: DNSProxyFallbackBarrier?
    private var fallbackQuestion: Data?, fallbackIngress = Data()
    private let absoluteDeadline: TimeInterval?, dialer: Dialer
    private let afterReplyIngressForSelfTest: (() -> Void)?
    private var pendingConnect: (() -> Void)?, timer: DispatchWorkItem?, query: Data?

    init(route: ResolvedRoute, target: RequestTarget, queue: DispatchQueue,
         permitted: @escaping () -> Bool = { true },
         receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void,
         absoluteDeadline: TimeInterval? = nil, dialer: Dialer? = nil,
         afterReplyIngressForSelfTest: (() -> Void)? = nil) {
        self.route = route; self.target = target
        self.queue = DispatchQueue(label: "app.hajimi.dns.proxy-tcp-query", target: queue)
        self.permitted = permitted
        receiveHandler = receive; failureHandler = failure
        self.absoluteDeadline = absoluteDeadline
        self.afterReplyIngressForSelfTest = afterReplyIngressForSelfTest
        self.dialer = dialer ?? { route, target, worker, done in
            TunnelConnector.beginConnect(route: route, target: target, plainHTTP: false, queue: worker,
                                         waitForSetupAcknowledgement: true, completion: done)
        }
    }

    private var allowed: Bool {
        admission.lock(); let active = !revoked; admission.unlock()
        return active && permitted() && (absoluteDeadline.map { $0.isFinite && ProcessInfo.processInfo.systemUptime < $0 } ?? true)
    }

    func send(_ data: Data) {
        queue.async {
            guard !self.started, !self.stopped, (12...65_535).contains(data.count) else { return }
            guard self.allowed else { self.fail(EncryptedDNSQueryFailure.policy); return }
            self.admission.lock()
            guard !self.revoked else { self.admission.unlock(); self.fail(EncryptedDNSQueryFailure.policy); return }
            self.fallbackQuestion = data
            self.admission.unlock()
            self.started = true; self.query = data
            if let deadline = self.absoluteDeadline {
                let timer = DispatchWorkItem { [weak self] in self?.fail(DNSQueryTimeoutError()) }
                self.timer = timer; self.queue.asyncAfter(deadline: .now() + max(0, deadline - ProcessInfo.processInfo.systemUptime), execute: timer)
            }
            self.pendingConnect = self.dialer(self.route, self.target, self.queue) { result in
                if case .failure(let error) = result { self.observeFallbackFailure(error) }
                self.queue.async {
                    self.pendingConnect = nil
                    guard !self.stopped else { if case .success(let pair) = result { pair.0.cancel() }; return }
                    guard self.allowed else {
                        if case .success(let pair) = result { pair.0.cancel() }
                        self.fail(EncryptedDNSQueryFailure.policy); return
                    }
                    switch result {
                    case .failure(let error): self.fail(error)
                    case .success(let pair):
                        self.stream = pair.0
                        var framed = Data([UInt8(data.count >> 8), UInt8(data.count & 0xff)])
                        framed.append(data)
                        pair.0.send(framed) { [weak self] error in
                            if let error { self?.observeFallbackFailure(error) }
                            self?.queue.async {
                                if let error { self?.fail(error) } else { self?.read() }
                            }
                        }
                    }
                }
            }
        }
    }

    private func read() {
        guard !stopped, let stream else { return }
        guard allowed else { fail(EncryptedDNSQueryFailure.policy); return }
        stream.receive(maximum: 65_537 - buffer.count) { [weak self] data, complete, error in
            // Admit DNS metadata before the asynchronous submission gap. A
            // cancel may win after this callback but before its queue block.
            self?.observeFallbackIngress(data, complete: complete, error: error)
            self?.afterReplyIngressForSelfTest?()
            self?.queue.async {
                guard let self, !self.stopped else { return }
                guard self.allowed else {
                    self.fail(EncryptedDNSQueryFailure.policy); return
                }
                if let error { self.fail(error); return }
                if let data {
                    guard data.count <= 65_537 - self.buffer.count else { self.fail(EncryptedDNSQueryFailure.invalidResponse); return }
                    self.buffer.append(data)
                }
                if self.buffer.count >= 2 {
                    let length = Int(self.buffer[self.buffer.startIndex]) << 8
                        | Int(self.buffer[self.buffer.startIndex + 1])
                    guard length >= 12 else { self.fail(EncryptedDNSQueryFailure.invalidResponse); return }
                    if self.buffer.count >= length + 2 {
                        guard self.buffer.count == length + 2 else { self.fail(EncryptedDNSQueryFailure.invalidResponse); return }
                        let answer = Data(self.buffer.dropFirst(2))
                        guard let query = self.query, DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
                            self.fail(EncryptedDNSQueryFailure.invalidResponse); return
                        }
                        self.observeFallbackAnswer(answer)
                        self.stopped = true; self.timer?.cancel(); self.timer = nil
                        self.stream?.cancel(); self.stream = nil; self.query = nil
                        self.receiveHandler(answer); return
                    }
                }
                if complete { self.fail(self.buffer.isEmpty ? EncryptedDNSQueryFailure.network : .invalidResponse) }
                else { self.read() }
            }
        }
    }

    private func fail(_ error: Error) {
        guard !stopped else { return }; stopped = true; timer?.cancel(); timer = nil
        observeFallbackFailure(error)
        pendingConnect?(); pendingConnect = nil; stream?.cancel(); stream = nil
        query = nil; buffer.removeAll(); failureHandler(error)
    }
    private func observeFallbackFailure(_ error: Error) {
        let reason = EncryptedDNSQueryFailure.classify(error)
        guard !reason.permitsProxyFallback, reason != .cancelled else { return }
        admission.lock(); defer { admission.unlock() }
        guard !revoked, fallbackBarrier == nil else { return }
        fallbackBarrier = .failure(error)
    }
    private func observeFallbackAnswer(_ answer: Data) {
        admission.lock()
        if fallbackBarrier == nil { fallbackBarrier = .answer(answer) }
        admission.unlock()
    }
    private func observeFallbackIngress(_ data: Data?, complete: Bool, error: Error?) {
        let denial = error.map(EncryptedDNSQueryFailure.classify)
        admission.lock(); defer { admission.unlock() }
        guard !revoked, fallbackBarrier == nil, let query = fallbackQuestion else { return }
        if let error, let denial, !denial.permitsProxyFallback, denial != .cancelled {
            fallbackBarrier = .failure(error); return
        }
        // One bounded metadata-only framer, protected by the same admission
        // lock as cancel(). It neither submits I/O nor publishes a response.
        // This retains pre-cancel auth/negative/invalid results even if the
        // delivery block has not yet reached the child's serial queue.
        let input = data ?? Data()
        guard input.count <= 65_537 - fallbackIngress.count else {
            fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse); return
        }
        fallbackIngress.append(input)
        let received = fallbackIngress
        guard received.count >= 2 else {
            if complete, !received.isEmpty { fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse) }
            return
        }
        let length = Int(received[received.startIndex]) << 8 | Int(received[received.startIndex + 1])
        guard length >= 12, received.count <= length + 2 else {
            fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse); return
        }
        if received.count == length + 2 {
            let answer = Data(received.dropFirst(2))
            guard DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
                fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse); return
            }
            fallbackBarrier = .answer(answer)
        } else if complete {
            fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse)
        }
    }
    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
        admission.lock(); defer { admission.unlock() }; return fallbackBarrier
    }
    func cancel() { cancel(completion: {}) }
    func cancel(completion: @escaping () -> Void) {
        admission.lock(); revoked = true; admission.unlock()
        queue.async {
            self.stopped = true; self.timer?.cancel(); self.timer = nil
            self.pendingConnect?(); self.pendingConnect = nil; self.stream?.cancel(); self.stream = nil
            self.query = nil; self.buffer.removeAll(); completion()
            self.admission.lock(); self.fallbackQuestion = nil; self.fallbackIngress.removeAll(); self.admission.unlock()
        }
    }
    func queryDeadlineReached() {
        admission.lock(); revoked = true; admission.unlock()
        queue.async { self.fail(DNSQueryTimeoutError()) }
    }
    fileprivate func drainQueueForSelfTest() { queue.sync {} }
    deinit { timer?.cancel(); pendingConnect?(); stream?.cancel() }
}

/// RFC 1035 TCP framing, with bounded input and no assumptions about read or
/// write boundaries. Multiple queries in one write and split prefixes work.
private struct DNSLengthFramer {
    private var buffer = Data()
    mutating func append(_ data: Data) throws -> [Data] {
        guard data.count <= 256 * 1_024 - buffer.count else { throw EngineError("DNS TCP 输入缓冲超限") }
        buffer.append(data)
        var offset = 0, frames: [Data] = []
        while buffer.count - offset >= 2 {
            let length = Int(buffer[buffer.startIndex + offset]) << 8
                | Int(buffer[buffer.startIndex + offset + 1])
            guard length >= 12 else { throw EngineError("DNS TCP 查询长度无效") }
            guard buffer.count - offset >= length + 2 else { break }
            guard frames.count < 64 else { throw EngineError("DNS TCP 合并查询数量超限") }
            frames.append(Data(buffer[(buffer.startIndex + offset + 2)..<(buffer.startIndex + offset + 2 + length)]))
            offset += length + 2
        }
        if offset > 0 { buffer = Data(buffer.dropFirst(offset)) }
        guard buffer.count <= 65_537 else { throw EngineError("DNS TCP 未完成帧缓冲超限") }
        return frames
    }
}

private final class DNSFramedByteStream: NativeOutboundByteStream {
    private let queue: DispatchQueue
    private let admission = NSLock()
    private var reservedWrites = 0, reservedBytes = 0, admissionClosed = false
    private var datagram: NativeRoutedDatagram?
    private var framer = DNSLengthFramer()
    private var output = Data()
    private var outstanding = 0, bufferedResponses = 0
    private var outputFrameLengths: [Int] = []
    private var receiver: (maximum: Int, callback: (Data?, Bool, Error?) -> Void)?
    private var stopped = false
    private var terminalError: Error?
    fileprivate var fakeIPSynthesisEnabled: Bool {
        (datagram as? PolicyDNSDatagram)?.fakeIPSynthesisEnabled ?? false
    }

    init(queue: DispatchQueue) { self.queue = DispatchQueue(label: "app.hajimi.dns.tcp-ingress", target: queue) }
    func attach(_ datagram: NativeRoutedDatagram) { self.datagram = datagram }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        admission.lock()
        guard !admissionClosed, reservedWrites < 64, data.count <= 256 * 1_024 - reservedBytes else {
            admission.unlock(); completion(EngineError("DNS TCP 发送缓冲超限或已关闭")); return
        }
        reservedWrites += 1; reservedBytes += data.count; admission.unlock()
        queue.async {
            self.admission.lock(); self.reservedWrites -= 1; self.reservedBytes -= data.count; self.admission.unlock()
            guard !self.stopped, let datagram = self.datagram else { completion(self.terminalError ?? EngineError("DNS TCP 已关闭")); return }
            do {
                let queries = try self.framer.append(data)
                guard queries.count <= 64 - self.outstanding else { throw EngineError("DNS TCP 未完成查询超限") }
                self.outstanding += queries.count
                queries.forEach(datagram.send)
                completion(nil)
            } catch { self.stop(error); completion(error) }
        }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async {
            guard maximum > 0, self.receiver == nil else { completion(nil, true, EngineError("DNS TCP 读取参数或并发读取无效")); return }
            self.receiver = (min(maximum, 65_536), completion); self.flushReceive()
        }
    }

    func receiveDNSResponse(_ data: Data) {
        queue.async {
            guard !self.stopped else { return }
            guard (12...65_535).contains(data.count), self.outstanding > 0,
                  self.bufferedResponses < 64, data.count + 2 <= 1_024 * 1_024 - self.output.count else {
                self.stop(EngineError("DNS TCP 应答缓冲超限或收到非请求应答")); return
            }
            self.outstanding -= 1; self.bufferedResponses += 1
            self.outputFrameLengths.append(data.count + 2)
            self.output.append(contentsOf: [UInt8(data.count >> 8), UInt8(data.count & 0xff)])
            self.output.append(data); self.flushReceive()
        }
    }

    private func flushReceive() {
        guard let receiver else { return }
        if !output.isEmpty {
            let chunk = Data(output.prefix(receiver.maximum))
            output = Data(output.dropFirst(chunk.count))
            var consumed = chunk.count
            while consumed > 0, let length = outputFrameLengths.first {
                if consumed >= length {
                    consumed -= length; outputFrameLengths.removeFirst(); bufferedResponses -= 1
                } else {
                    outputFrameLengths[0] -= consumed; consumed = 0
                }
            }
            self.receiver = nil; receiver.callback(chunk, false, nil)
        } else if stopped {
            self.receiver = nil; receiver.callback(nil, true, terminalError)
        }
    }

    private func stop(_ error: Error?) {
        guard !stopped else { return }; stopped = true; terminalError = error
        admission.lock(); admissionClosed = true; admission.unlock()
        datagram?.cancel(); datagram = nil; output.removeAll(); bufferedResponses = 0; outputFrameLengths.removeAll()
        flushReceive()
    }
    func fail(_ error: Error) { queue.async { self.stop(error) } }
    func cancel() { admission.lock(); admissionClosed = true; admission.unlock(); queue.async { self.stop(nil) } }
    deinit { datagram?.cancel() }
}

private final class DNSAddressResolution {
    typealias DatagramFactory = (RequestTarget, DispatchQueue, @escaping (Data) -> Void,
                                 @escaping (Error) -> Void) throws -> NativeRoutedDatagram
    private let queue: DispatchQueue
    private let permitted: () -> Bool
    private let totalTimeout: TimeInterval
    // Only this file's memory-only regression supplies a factory or shorter
    // deadline. Production construction keeps the routed wire query path.
    private let datagramFactory: DatagramFactory?
    private let admission = NSLock()
    private var cancelled = false
    private var started = false
    private var completion: ((Result<[String], Error>) -> Void)?
    private var flow: NativeRoutedDatagram?
    private var pending: [UInt16: Data] = [:]
    private var addresses: [String] = []
    private var timeout: DispatchWorkItem?
    private var addressGrace: DispatchWorkItem?
    private var sawRefusal = false

    init(queue: DispatchQueue, permitted: @escaping () -> Bool = { true },
         totalTimeout: TimeInterval = 10, datagramFactory: DatagramFactory? = nil,
         completion: @escaping (Result<[String], Error>) -> Void) {
        self.queue = DispatchQueue(label: "app.hajimi.dns.direct-address", target: queue)
        self.permitted = permitted; self.datagramFactory = datagramFactory
        self.totalTimeout = totalTimeout.isFinite ? min(10, max(0.001, totalTimeout)) : 10
        self.completion = completion
    }
    private var isCancelled: Bool {
        admission.lock(); defer { admission.unlock() }; return cancelled
    }
    func start(router: NativePacketRouter, host: String, sourceTarget: RequestTarget?) {
        let id = UInt16.random(in: UInt16.min...UInt16.max), secondID = id &+ 1
        guard let a = DNSMessageInspection.query(for: host, type: 1, id: id),
              let aaaa = DNSMessageInspection.query(for: host, type: 28, id: secondID) else {
            queue.async { self.finish(.failure(EngineError("目标域名不能编码为 DNS 查询"))) }; return
        }
        let target = RequestTarget(host: protectedSystemDNSGateway, port: 53, protocolName: "UDP",
                                   sourceHost: sourceTarget?.sourceHost, sourcePort: sourceTarget?.sourcePort,
                                   inboundPort: sourceTarget?.inboundPort)
        queue.async {
            guard self.completion != nil, !self.started else { return }
            self.started = true
            guard !self.isCancelled, self.permitted() else {
                self.finish(.failure(EngineError("DNS 地址解析已取消或策略/接口已更新"))); return
            }
            self.pending = [id: a, secondID: aaaa]
            let receive: (Data) -> Void = { [self] answer in self.queue.async { self.accept(answer) } }
            let failure: (Error) -> Void = { [self] error in
                self.queue.async {
                    self.finish(self.addresses.isEmpty ? .failure(error) : .success(self.addresses))
                }
            }
            do {
                // DIRECT destinations need real addresses, even if a DNS-specific
                // rule routes the question through a proxy with fake-IP enabled.
                if let factory = self.datagramFactory {
                    self.flow = try factory(target, self.queue, receive, failure)
                } else {
                    self.flow = try router.makeDNSDatagram(original: target, queue: self.queue,
                        synthesizeFakeIP: false, receive: receive, failure: failure)
                }
            } catch { self.finish(.failure(error)); return }
            guard !self.isCancelled, self.permitted() else {
                self.finish(.failure(EngineError("DNS 地址解析期间策略或接口已更新"))); return
            }
            let deadline = DispatchWorkItem { [weak self] in self?.deadlineReached() }
            self.timeout = deadline
            self.queue.asyncAfter(deadline: .now() + self.totalTimeout, execute: deadline)
            self.flow?.send(a); self.flow?.send(aaaa)
        }
    }
    private func accept(_ answer: Data) {
        guard completion != nil, answer.count >= 12 else { return }
        guard !isCancelled, permitted() else {
            finish(.failure(EngineError("DNS 应答期间策略或接口已更新"))); return
        }
        let id = UInt16(answer[answer.startIndex]) << 8 | UInt16(answer[answer.startIndex + 1])
        guard let query = pending[id], DNSMessageInspection.responseMatchesQuery(answer, query: query) else { return }
        pending.removeValue(forKey: id)
        sawRefusal = sawRefusal || answer[answer.startIndex + 3] & 0x0f == 5
        for record in DNSMessageInspection.addressAnswers(in: answer) where !addresses.contains(record.address) {
            if !FakeIPAllocator.isFake(record.address) { addresses.append(record.address) }
        }
        if pending.isEmpty {
            if addresses.isEmpty { finish(.failure(EngineError(sawRefusal ? "域名解析被 DNS 策略拒绝" : "加密/代理 DNS 未返回地址"))) }
            else { finish(.success(addresses)) }
        } else if addressGrace == nil, addresses.contains(where: { !$0.contains(":") }) {
            // This is internal DIRECT address discovery, not an application
            // wire DNS reply. Keep a short DNS resolution delay to collect a
            // prompt AAAA, but a silent/broken AAAA must not hold valid IPv4
            // for the full 8-second routed-query deadline. An IPv6-only first
            // answer still waits for A: this one-shot API cannot append a late
            // IPv4 fallback to an already-running Happy Eyeballs dial.
            let grace = DispatchWorkItem { [weak self] in
                guard let self else { return }; self.finish(.success(self.addresses))
            }
            addressGrace = grace; queue.asyncAfter(deadline: .now() + 0.05, execute: grace)
        }
    }
    private func deadlineReached() {
        // Preserve a usable family even if the other query never delivers a
        // response. finish performs the final policy/interface/cancel check.
        if addresses.isEmpty { finish(.failure(EngineError("DNS 地址解析超时"))) }
        else { finish(.success(addresses)) }
    }
    private func finish(_ result: Result<[String], Error>) {
        guard let callback = completion else { return }; completion = nil
        timeout?.cancel(); timeout = nil; addressGrace?.cancel(); addressGrace = nil
        flow?.cancel(); flow = nil; pending.removeAll()
        if isCancelled { callback(.failure(EngineError("DNS 地址解析已取消"))) }
        else if !permitted() { callback(.failure(EngineError("DNS 地址解析期间策略或接口已更新"))) }
        else { callback(result) }
        addresses.removeAll()
    }
    func cancel() {
        admission.lock(); cancelled = true; admission.unlock()
        queue.async { self.finish(.failure(EngineError("DNS 地址解析已取消"))) }
    }
    deinit { timeout?.cancel(); addressGrace?.cancel(); flow?.cancel() }
}

// Memory self-tests drive the original callbacks on their owning queue. Stop
// dispatch work items inside the fixture factory, before even a 1ms hedge can
// race the test driver; production exchanges never call these checkpoints.
private extension DNSAdaptiveQueryDatagram {
    func pauseAdaptiveTimersForSelfTest() {
        dispatchPrecondition(condition: .onQueue(queue))
        deadlineTimer?.cancel()
        for attempt in active.values {
            attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel()
        }
    }
    func drainAdaptiveQueueForSelfTest() {
        queue.sync { pauseAdaptiveTimersForSelfTest() }
    }
    func fireAdaptiveHedgeForSelfTest() -> Bool {
        queue.sync {
            guard let primaryToken, active[primaryToken]?.hedgeTimer != nil else { return false }
            startHedge(after: primaryToken); pauseAdaptiveTimersForSelfTest(); return true
        }
    }
    func fireAdaptiveRotationForSelfTest() -> Bool {
        queue.sync {
            guard let token = active.keys.first(where: { $0 != primaryToken }),
                  active[token]?.rotationTimer != nil else { return false }
            rotateHedge(token); pauseAdaptiveTimersForSelfTest(); return true
        }
    }
    var adaptiveStateForSelfTest: (started: TimeInterval, deadline: TimeInterval, attempts: Int, active: Int) {
        queue.sync { (exchangeStarted, deadline, attemptCount, active.count) }
    }
}

/// Pure routing/framing regressions plus a fake-IP TCP round trip. No test in
/// this suite starts a listener, opens an outbound socket or changes DNS.
public enum DNSSecurityRoutingSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS 路由安全自检失败：\(text)" }
    }
    private static func expect(_ condition: @autoclosure () throws -> Bool, _ text: String) throws {
        guard try condition() else { throw Failure(text: text) }
    }
    private static func query(_ name: String, _ type: UInt16, id: UInt16 = 0x4545) throws -> Data {
        guard let data = DNSMessageInspection.query(for: name, type: type, id: id) else {
            throw Failure(text: "查询构造失败")
        }
        return data
    }
    private static func plan(_ router: NativePacketRouter, name: String = "allowed.example.test",
                             type: UInt16 = 1, original: RequestTarget? = nil) throws -> DNSQueryPlan {
        let target = original ?? RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")
        guard case .upstream(let plan) = try router.prepareDNSQuery(query(name, type), original: target) else {
            throw Failure(text: "真实查询被意外合成")
        }
        return plan
    }
    private static func router(_ profile: Profile, mode: OutboundMode = .rule,
                               global: String = "Node") -> NativePacketRouter {
        NativePacketRouter(profile: profile, mode: mode, globalPolicy: global, groupSelections: [:])
    }
    private static func refusal(_ router: NativePacketRouter, name: String, type: UInt16,
                                original: RequestTarget? = nil) throws {
        do { _ = try plan(router, name: name, type: type, original: original) }
        catch DNSPolicyFailure.refused { return }
        throw Failure(text: "\(name)/\(type) 的显式拒绝被绕过")
    }

    /// Owned, in-memory regression path for the opt-in proxy DNS downgrade.
    /// None of these checks can invoke a resolver, native dial or listener.
    public static func runProxyFallbackTests() throws {
        try proxyFallbackRoutingPolicy()
        try dnsSelectionModes()
        try dnsPrewarmLifecycle()
        try proxyFallbackTCPFraming()
        try proxyFallbackIngressFence()
        try proxyFallbackPooledTransport()
        try proxyFallbackAdaptiveBarriers()
        try proxyFallbackEncryptedPhaseHealth()
    }

    private final class PrewarmMemoryPeer: NativeOutboundByteStream {
        private let lock = NSLock()
        private var reader: ((Data?, Bool, Error?) -> Void)?
        private var closed = false, sends = 0
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); sends += 1; lock.unlock(); completion(nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); reader = completion; lock.unlock()
        }
        func cancel() {
            lock.lock(); closed = true; let callback = reader; reader = nil; lock.unlock()
            callback?(nil, true, EncryptedDNSQueryFailure.cancelled)
        }
        var snapshot: (closed: Bool, sends: Int) { lock.lock(); defer { lock.unlock() }; return (closed, sends) }
    }
    private static func dnsPrewarmLifecycle() throws {
        var configured = proxyFallbackProfile()
        configured.encryptedDNSServers += ["https://203.0.113.71/dns-query", "tls://203.0.113.72"]
        configured.dnsSelectionMode = .encryptedOnly
        for scenario in 0..<4 {
            var profile = configured
            if scenario == 0 { profile.dnsPrewarmEnabled = false }
            if scenario == 3 { profile.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)] }
            let source = router(profile), started = DispatchSemaphore(value: 0), lock = NSLock()
            var peers: [PrewarmMemoryPeer] = []
            source.memoryFixtureDNSStreamDialer = { _, _, _, _, _, _, done in
                let peer = PrewarmMemoryPeer()
                lock.lock(); peers.append(peer); lock.unlock(); started.signal(); done(.success(peer)); return nil
            }
            source.prewarmDNS()
            if scenario == 1 { source.cancelDNSQueries() }
            if scenario == 2 {
                profile.dnsPrewarmEnabled = false
                source.update(profile: profile, mode: .rule, globalPolicy: "Node", groupSelections: [:])
            }
            try expect(started.wait(timeout: .now() + 0.35) == .timedOut,
                       "关闭、停止、旧代际或REJECT仍触发预热连接")
            lock.lock(); let count = peers.count; lock.unlock()
            try expect(count == 0, "预热越过取消或策略边界")
            source.cancelDNSQueries()
        }
        let source = router(configured), started = DispatchSemaphore(value: 0), lock = NSLock()
        var peers: [PrewarmMemoryPeer] = []
        source.memoryFixtureDNSStreamDialer = { _, _, _, _, _, _, done in
            let peer = PrewarmMemoryPeer()
            lock.lock(); peers.append(peer); lock.unlock(); started.signal(); done(.success(peer)); return nil
        }
        defer { source.cancelDNSQueries() }
        source.prewarmDNS()
        try expect(started.wait(timeout: .now() + 1) == .success && started.wait(timeout: .now() + 1) == .success,
                   "启动预热没有准备两个获准加密候选")
        source.prewarmDNS()
        try expect(started.wait(timeout: .now() + 0.35) == .timedOut, "同一代际重复预热或超过两个候选")
        lock.lock(); let first = peers; lock.unlock()
        try expect(first.count == 2 && first.allSatisfy { $0.snapshot.sends == 0 },
                   "预热发送了DNS消息或无界启动候选")
        var disabled = configured; disabled.dnsPrewarmEnabled = false
        source.update(profile: disabled, mode: .rule, globalPolicy: "Node", groupSelections: [:])
        try expect(started.wait(timeout: .now() + 0.35) == .timedOut && first.allSatisfy { $0.snapshot.closed },
                   "关闭预热未清理旧连接，或重新创建了连接")
        print("DNS prewarm lifecycle: opt-out, stop, epoch revocation, REJECT, two-candidate cap, duplicate suppression and zero DNS payload passed")
    }

    private static func dnsSelectionModes() throws {
        var balanced = proxyFallbackProfile(); balanced.dnsProxyFallbackEnabled = false
        let b = try plan(router(balanced))
        var encrypted = balanced; encrypted.dnsSelectionMode = .encryptedOnly; encrypted.dnsProxyFallbackEnabled = true
        let a = try plan(router(encrypted))
        var mixed = balanced; mixed.dnsSelectionMode = .mixedSpeed
        let source = router(mixed), c = try plan(source)
        try expect(a.fallbackServers.isEmpty && b.fallbackServers.isEmpty && c.fallbackServers.count == 2,
                   "DNS模式未保持加密独用、显式后备与混合批准的不同权限")
        try expect(a.scopeKey != b.scopeKey && b.scopeKey != c.scopeKey && a.healthScopeKey != c.healthScopeKey,
                   "DNS模式切换沿用了不同授权模式的答案或健康作用域")
        let plain = try source.revalidatedProxyFallbackPlan(c, server: c.fallbackServers[0])
        try expect(plain.route == c.route && !plain.upstream.encrypted && !mixed.dnsProxyFallbackEnabled,
                   "混合模式错误依赖后备开关或离开已批准代理")
        for selection: DNSSelectionMode in [.encryptedOnly, .mixedSpeed] {
            var traditional = mixed
            traditional.dnsSelectionMode = selection; traditional.encryptedDNSServers = []
            traditional.dnsLeakProtectionEnabled = false
            try expect(try plan(router(traditional)).upstream.encrypted,
                       "明确加密或混合模式仍降回旧纯传统DNS路径")
        }
        var direct = mixed; direct.dnsLeakProtectionEnabled = false
        direct.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        try expect(try plan(router(direct)).fallbackServers.isEmpty,
                   "混合模式在DIRECT路由或保护关闭时泄露普通DNS")
        var denied = mixed
        denied.rules.insert(RoutingRule(kind: .domainSuffix("example.test"), policy: "REJECT", sourceLine: 0), at: 0)
        try refusal(router(denied), name: "allowed.example.test", type: 1)

        // Exercise the real coordinator, mixed scheduler and health receipts.
        // Both encrypted peers are silent; the explicitly approved ordinary
        // peer answers. The next fresh question should start with that winner.
        for round in 0..<2 {
            let probe = AdaptiveProbe(), message = try query("mixed-\(round).example.test", 1)
            let approved = try plan(source, name: "mixed-\(round).example.test")
            let flow = try source.makeOptimizedDNSUpstream(plan: approved, queue: .global(),
                adaptiveFactory: { candidate, _, _, _ in
                    AdaptiveAcknowledgedMemoryTransport(send: { _ in probe.attempted(candidate) }, cancel: probe.transportCancelled)
                }, proxyTCPFactory: { server, worker, _, receive, _ in
                    let candidate = DNSUpstreamCandidate(upstream: .plain(host: server.host, port: server.port), bootstrap: nil)
                    return AdaptiveAcknowledgedMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        worker.asyncAfter(deadline: .now() + 0.01) { receive(bootstrapAnswer(data)!) }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }
            flow.send(message); try awaitAdaptive(probe, query: message, waitTimeout: 2)
            try expect(probe.snapshot.attempts == (round == 0
                ? [approved.candidates[0].upstream.target.host, approved.fallbackServers[0].host]
                : [approved.fallbackServers[0].host]) && probe.concurrency.peak <= 2,
                "混合模式未使用真实批准普通候选、未学习获胜路径或超出两条在途")
        }
        print("DNS modes: encrypted-only, balanced authorization, mixed proxy-only ranking, scope separation and first/next-query learning passed")
    }

    private static func proxyFallbackProfile() -> Profile {
        var profile = Profile()
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
            adapterType: "vmess", parameters: ["uuid": "12345678-1234-1234-1234-1234567890ab"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        profile.dnsServers = ["203.0.113.61"]
        profile.encryptedDNSServers = ["https://203.0.113.70/dns-query"]
        profile.dnsProxyFallbackEnabled = true
        profile.dnsProxyFallbackServers = ["203.0.113.60", "203.0.113.62:5353"]
        return profile
    }

    private static func proxyFallbackRoutingPolicy() throws {
        let base = proxyFallbackProfile()
        let original = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7263)
        let source = router(base), approved = try plan(source, original: original)
        try expect(approved.fallbackServers.map(\.host) == ["203.0.113.60", "203.0.113.62"]
                   && approved.questionName == "allowed.example.test" && approved.original == original,
                   "显式回退列表混入传统引导 DNS 或丢失应用问题/元数据")
        let fallback = try source.revalidatedProxyFallbackPlan(approved, server: approved.fallbackServers[0])
        try expect(fallback.route == approved.route && fallback.upstream.target.host == "203.0.113.60"
                   && fallback.upstream.target.port == 53 && fallback.upstream.target.protocolName == "TCP"
                   && !fallback.upstream.encrypted, "回退切换了实际代理、使用 UDP 或改变解析器角色")

        var disabled = base; disabled.dnsProxyFallbackEnabled = false
        let disabledPlan = try plan(router(disabled), original: original)
        try expect(disabledPlan.fallbackServers.isEmpty && disabledPlan.scopeKey != approved.scopeKey,
                   "关闭回退仍授权名单或沿用旧查询 scope")
        disabled.dnsProxyFallbackServers = []
        try expect(try plan(router(disabled), original: original).fallbackServers.isEmpty,
                   "传统/bootstrap-only DNS 被自动迁移成应用回退解析器")
        var missing = base; missing.dnsProxyFallbackServers = []
        do { _ = try plan(router(missing), original: original)
            throw Failure(text: "开启回退但没有显式名单仍准入")
        } catch DNSPolicyFailure.configuration {}

        var direct = base; direct.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        try expect(try plan(router(direct, global: "Node"), original: original).fallbackServers.isEmpty,
                   "选定 DIRECT 被安全 global 节点替换并触发回退")
        var clear = base
        clear.proxies["Node"] = ProxyPolicy(name: "Node", kind: .socks5,
            host: "203.0.113.10", port: 1080)
        try expect(try plan(router(clear), original: original).fallbackServers.isEmpty,
                   "未加密实际节点被误当作安全 DNS 代理")
        var invalid = base; invalid.encryptedDNSServers = ["https://dns.google"]
        do { _ = try plan(router(invalid), original: original)
            throw Failure(text: "无效加密配置被普通 DNS 回退掩盖")
        } catch DNSPolicyFailure.configuration {}

        for deny in [RuleKind.domain("allowed.example.test"), .ipCIDR("203.0.113.53/32"),
                     .sourceIPCIDR("192.0.2.1/32"), .sourcePort(41000...41000), .inboundPort(7263...7263)] {
            var denied = base
            denied.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            for mode in [OutboundMode.rule, .proxy] {
                try refusal(router(denied, mode: mode), name: "allowed.example.test", type: 1, original: original)
            }
        }
        for deny in [RuleKind.ipCIDR("203.0.113.60/32"), .domain("203.0.113.60")] {
            var filtered = base
            filtered.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            let selected = try plan(router(filtered, mode: .proxy), original: original)
            try expect(selected.fallbackServers.map(\.host) == ["203.0.113.62"]
                       && selected.scopeKey != approved.scopeKey,
                       "被拒绝的备用解析器仍准入或未隔离完整批准集合")
        }
        var reordered = base; reordered.dnsProxyFallbackServers.reverse()
        try expect(try plan(router(reordered), original: original).scopeKey != approved.scopeKey,
                   "完整回退列表/次序未进入 cache 与 single-flight scope")
        var alternate = original; alternate.sourceHost = "192.0.2.2"
        try expect(try plan(source, original: alternate).scopeKey != approved.scopeKey, "回退 scope 跨来源 IP")
        alternate = original; alternate.inboundPort = 7264
        try expect(try plan(source, original: alternate).scopeKey != approved.scopeKey, "回退 scope 跨入站端口")
        alternate = original; alternate.protocolName = "TCP"
        try expect(try plan(source, original: alternate).scopeKey != approved.scopeKey, "回退 scope 混同 UDP/TCP")
        alternate = original; alternate.host = "203.0.113.54"
        try expect(try plan(source, original: alternate).scopeKey != approved.scopeKey, "回退 scope 丢失原目的地址")

        var nested = base
        let reference = RuleSetReference(location: "memory.proxy-fallback.source-port")
        nested.ruleSetContents[reference.location] = [.logicalNot(.logicalNot(.sourcePort(41001...41001)))]
        nested.rules.insert(RoutingRule(kind: .ruleSet(reference), policy: "REJECT", sourceLine: 0), at: 0)
        let scoped = router(nested), first = try plan(scoped, original: original)
        alternate = original; alternate.sourcePort = 41002
        try expect(try plan(scoped, original: alternate).scopeKey != first.scopeKey,
                   "规则集内 SRC-PORT 未隔离回退查询 scope")
        alternate.sourcePort = 41001
        try refusal(scoped, name: "allowed.example.test", type: 1, original: alternate)

        func revoked(_ decision: DNSQueryPlan) throws {
            do { _ = try source.revalidatedProxyFallbackPlan(decision, server: decision.fallbackServers[0])
                throw Failure(text: "失效策略/接口代际仍授权回退")
            } catch EncryptedDNSQueryFailure.policy {}
        }
        let wrongInterface = DNSQueryPlan(upstream: approved.upstream, candidates: approved.candidates,
            route: approved.route, original: approved.original, generation: approved.generation,
            bootstrap: approved.bootstrap, scopeKey: approved.scopeKey, healthScopeKey: approved.healthScopeKey,
            interfaceName: "owned-nonexistent-fallback-interface", questionName: approved.questionName,
            fallbackServers: approved.fallbackServers)
        try revoked(wrongInterface)
        source.flushDNS(); try revoked(approved)
        let afterFlush = try plan(source, original: original)
        source.update(profile: disabled, mode: .rule, globalPolicy: "Node", groupSelections: [:])
        try revoked(afterFlush)
    }

    private final class ProxyFallbackMemoryStream: NativeOutboundByteStream {
        private let lock = NSLock()
        private var input: [(Data?, Bool, Error?)]
        private var writes: [Data] = [], cancellations = 0
        init(_ chunks: [(Data?, Bool, Error?)]) { input = chunks }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); writes.append(data); lock.unlock(); completion(nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); let chunk = input.isEmpty ? (nil, true, nil) : input.removeFirst(); lock.unlock()
            completion(chunk.0, chunk.1, chunk.2)
        }
        func cancel() { lock.lock(); cancellations += 1; lock.unlock() }
        var snapshot: (writes: [Data], cancellations: Int) {
            lock.lock(); defer { lock.unlock() }; return (writes, cancellations)
        }
    }
    private final class ProxyFallbackDialProbe {
        typealias Completion = (Result<(any OutboundByteStream, Data), Error>) -> Void
        private let lock = NSLock()
        private var callback: Completion?, calls = 0, cancellations = 0
        func begin(_ callback: @escaping Completion) { lock.lock(); calls += 1; self.callback = callback; lock.unlock() }
        func cancel() { lock.lock(); cancellations += 1; lock.unlock() }
        func ready(_ result: Result<(any OutboundByteStream, Data), Error>) {
            lock.lock(); let callback = self.callback; self.callback = nil; lock.unlock(); callback?(result)
        }
        var snapshot: (calls: Int, cancellations: Int) {
            lock.lock(); defer { lock.unlock() }; return (calls, cancellations)
        }
    }

    private final class ProxyFallbackControlledStream: NativeOutboundByteStream {
        let receiving = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var callback: ((Data?, Bool, Error?) -> Void)?
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); callback = completion; lock.unlock(); receiving.signal()
        }
        func emit(_ data: Data?, error: Error? = nil) {
            lock.lock(); let callback = callback; self.callback = nil; lock.unlock()
            callback?(data, true, error)
        }
        func cancel() {}
    }

    private final class ProxyFallbackPooledMemoryStream: NativeOutboundByteStream {
        let closed = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var input: Data?
        private var receiver: ((Data?, Bool, Error?) -> Void)?
        private var stopped = false, sends = 0
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            let query = Data(data.dropFirst(2))
            guard data.count >= 14, Int(data[0]) << 8 | Int(data[1]) == query.count,
                  var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail) else {
                completion(EncryptedDNSQueryFailure.invalidResponse); return
            }
            answer[3] &= 0xf0
            let frame = Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer
            lock.lock()
            guard !stopped, input == nil else { lock.unlock(); completion(EncryptedDNSQueryFailure.cancelled); return }
            sends += 1
            let callback = receiver; receiver = nil
            if callback == nil { input = frame }
            lock.unlock(); completion(nil); callback?(frame, false, nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped, receiver == nil else { lock.unlock(); completion(nil, true, EncryptedDNSQueryFailure.cancelled); return }
            if let input {
                self.input = nil; lock.unlock(); completion(input, false, nil)
            } else { receiver = completion; lock.unlock() }
        }
        func cancel() {
            lock.lock(); guard !stopped else { lock.unlock(); return }
            stopped = true; input = nil; let callback = receiver; receiver = nil; lock.unlock()
            callback?(nil, true, EncryptedDNSQueryFailure.cancelled); closed.signal()
        }
        var sendCount: Int { lock.lock(); defer { lock.unlock() }; return sends }
    }

    private static func proxyFallbackPooledTransport() throws {
        var profile = proxyFallbackProfile()
        profile.rules.insert(RoutingRule(kind: .sourcePort(65_000...65_000), policy: "REJECT", sourceLine: 1), at: 0)
        let source = router(profile), nativeLock = NSLock()
        var streams: [ProxyFallbackPooledMemoryStream] = []
        let dialer: MetadataAwareEncryptedDNSStreamDialer = { host, port, name, _, _, observe, done in
            guard (host == "203.0.113.60" && port == 53) || (host == "203.0.113.62" && port == 5353), host == name else {
                observe(EncryptedDNSQueryFailure.policy); done(.failure(EncryptedDNSQueryFailure.policy)); return nil
            }
            let stream = ProxyFallbackPooledMemoryStream()
            nativeLock.lock(); streams.append(stream); nativeLock.unlock(); done(.success(stream)); return nil
        }
        func peers() -> [ProxyFallbackPooledMemoryStream] { nativeLock.lock(); defer { nativeLock.unlock() }; return streams }
        func exchange(_ decision: DNSQueryPlan, server: Int = 0, id: UInt16) throws {
            let message = try query(decision.questionName!, 1, id: id), result = AdaptiveProbe()
            let flow = try source.makeProxyTCPFallbackUpstream(plan: decision, server: decision.fallbackServers[server],
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 1, dialer: dialer,
                receive: result.received, failure: result.failed)
            flow.send(message); try awaitAdaptive(result, query: message, expectFailure: false)
            let cancelled = DispatchSemaphore(value: 0); flow.cancel { cancelled.signal() }
            try expect(cancelled.wait(timeout: .now() + 1) == .success, "pooled router lease did not ACK its question")
        }
        let one = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 42_001, inboundPort: 7263)
        var two = one; two.sourcePort = 42_002
        let first = try plan(source, name: "first.router-pool.example", original: one)
        let second = try plan(source, name: "second.router-pool.example", original: two)
        try expect(first.scopeKey != second.scopeKey, "pooled router fixture did not partition question source ports")
        let unused = try source.makeProxyTCPFallbackUpstream(plan: first, server: first.fallbackServers[0],
            absoluteDeadline: ProcessInfo.processInfo.systemUptime + 1, dialer: dialer, receive: { _ in }, failure: { _ in })
        try expect(peers().isEmpty, "borrowing a fallback resolver pre-dialed an unrequested stream")
        unused.cancel()
        try exchange(first, id: 0x7501); try exchange(second, id: 0x7502)
        try expect(peers().count == 1 && peers()[0].sendCount == 2,
                   "authorized source-port/QNAME changes fragmented the physical fallback pool")
        try exchange(second, server: 1, id: 0x7503)
        let beforeFlush = peers()
        try expect(beforeFlush.count == 2 && beforeFlush[1].sendCount == 1,
                   "another approved fallback resolver borrowed the first resolver's connection")
        source.flushDNS()
        for stream in beforeFlush {
            try expect(stream.closed.wait(timeout: .now() + 1) == .success, "DNS epoch flush retained an old fallback pool")
        }
        do {
            _ = try source.makeProxyTCPFallbackUpstream(plan: first, server: first.fallbackServers[0],
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 1, dialer: dialer, receive: { _ in }, failure: { _ in })
            throw Failure(text: "old question authority revived a flushed proxy TCP resolver")
        } catch EncryptedDNSQueryFailure.policy {}
        let fresh = try plan(source, name: "fresh.router-pool.example", original: one)
        try exchange(fresh, id: 0x7504)
        try expect(peers().count == 3, "new epoch reused an old authenticated fallback transport")
        source.flushDNS()
    }

    private static func proxyFallbackIngressFence() throws {
        let source = router(proxyFallbackProfile()), approved = try plan(source)
        let decision = try source.revalidatedProxyFallbackPlan(approved, server: approved.fallbackServers[0])
        let query = try self.query("fallback-native-ingress.example.test", 1)
        for mode in 0..<8 {
            let stream = ProxyFallbackControlledStream(), probe = AdaptiveProbe()
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let returned = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
            let flow = TCPDNSQueryDatagram(route: decision.route, target: decision.upstream.target,
                queue: .global(qos: .userInitiated), receive: probe.received, failure: probe.failed,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8,
                dialer: { _, _, _, done in done(.success((stream, Data()))); return {} },
                afterReplyIngressForSelfTest: { entered.signal(); _ = release.wait(timeout: .now() + 2) })
            defer { release.signal(); flow.cancel(); flow.drainQueueForSelfTest() }
            flow.send(query)
            try expect(stream.receiving.wait(timeout: .now() + 1) == .success, "TCP DNS 原生回调尚未登记")
            var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail)!
            let code: UInt8 = mode == 0 ? 0 : mode == 1 ? 3 : mode == 2 ? 5 : 2
            answer[3] = (answer[3] & 0xf0) | code
            if mode == 4 { answer[0] ^= 1 }
            var frame = Data([UInt8(answer.count >> 8), UInt8(answer.count & 0xff)]); frame.append(answer)
            if mode == 6 { frame = Data(frame.prefix(1)) }
            if mode == 7 { frame = Data(frame.dropLast()) }
            let admittedFrame = frame
            DispatchQueue.global(qos: .userInitiated).async {
                stream.emit(mode == 5 ? nil : admittedFrame, error: mode == 5 ? EncryptedDNSQueryFailure.authentication : nil)
                returned.signal()
            }
            try expect(entered.wait(timeout: .now() + 1) == .success, "TCP DNS ingress→queue 窗口未打开")
            flow.cancel { cancelled.signal() }
            try expect(cancelled.wait(timeout: .now() + 1) == .success, "TCP DNS 取消逻辑 ACK 未完成")
            guard let barrier = flow.proxyFallbackBarrier() else { throw Failure(text: "取消擦除了已准入原生 metadata") }
            switch barrier {
            case .answer(let received):
                try expect(mode < 4 && received == answer, "TCP DNS 原生否定/正向答复 barrier 改变 ID 或问题")
            case .failure(let error):
                try expect(EncryptedDNSQueryFailure.classify(error) == (mode == 5 ? .authentication : .invalidResponse),
                           "TCP DNS 认证/错误 ID barrier 被弱化")
            }
            release.signal()
            try expect(returned.wait(timeout: .now() + 1) == .success, "TCP DNS 晚到 native read 未返回")
            flow.drainQueueForSelfTest()
            try expect(probe.snapshot.answers.isEmpty && probe.snapshot.error == nil,
                       "取消的 TCP DNS 原生结果仍交付给客户端")
        }
    }

    private static func proxyFallbackTCPFraming() throws {
        let profile = proxyFallbackProfile(), source = router(profile), decision = try plan(source)
        let fallback = try source.revalidatedProxyFallbackPlan(decision, server: decision.fallbackServers[0])
        let message = try query("allowed.example.test", 1), answer = bootstrapAnswer(message)!
        func framed(_ data: Data) -> Data {
            var frame = Data([UInt8(data.count >> 8), UInt8(data.count & 0xff)]); frame.append(data); return frame
        }
        let frame = framed(answer)
        func exchange(_ chunks: [(Data?, Bool, Error?)], succeeds: Bool) throws {
            let stream = ProxyFallbackMemoryStream(chunks), probe = AdaptiveProbe()
            let transport = TCPDNSQueryDatagram(route: fallback.route, target: fallback.upstream.target,
                queue: .global(), receive: probe.received, failure: probe.failed,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8,
                dialer: { route, target, _, ready in
                    try? expect(route == decision.route && target == fallback.upstream.target
                                && target.protocolName == "TCP" && DoHEndpoint.isAddressLiteral(target.host),
                                "内存 TCP 回退尝试了替代/global/DIRECT/system/UDP 拨号")
                    guard route == decision.route, target == fallback.upstream.target,
                          target.protocolName == "TCP", DoHEndpoint.isAddressLiteral(target.host) else {
                        ready(.failure(EncryptedDNSQueryFailure.policy)); return nil
                    }
                    ready(.success((stream, Data()))); return {}
                })
            defer { transport.cancel(); transport.drainQueueForSelfTest() }
            transport.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: !succeeds)
            for _ in 0..<8 { transport.drainQueueForSelfTest() }
            try expect(stream.snapshot.writes == [framed(message)] && stream.snapshot.cancellations == 1,
                       "回退未恰好发送一份 TCP DNS 帧或未关闭字节流")
        }
        try exchange([(Data(frame.prefix(1)), false, nil), (Data(frame[1..<7]), false, nil),
                      (Data(frame.dropFirst(7)), true, nil)], succeeds: true)
        var wrongID = answer; wrongID[0] ^= 1
        let wrongName = bootstrapAnswer(try query("wrong.example.test", 1))!
        var extra = frame; extra.append(0)
        for invalid in [framed(wrongID), framed(wrongName), extra, Data(frame.dropLast()), Data([0, 1, 0])] {
            try exchange([(invalid, true, nil)], succeeds: false)
        }
        for revoke in [false, true] {
            let pending = ProxyFallbackDialProbe(), probe = AdaptiveProbe(), gate = AdaptivePolicyGate()
            let stream = ProxyFallbackMemoryStream([(frame, true, nil)])
            let transport = TCPDNSQueryDatagram(route: fallback.route, target: fallback.upstream.target,
                queue: .global(), permitted: gate.permits, receive: probe.received, failure: probe.failed,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8,
                dialer: { _, _, _, ready in pending.begin(ready); return pending.cancel })
            defer { transport.cancel(); transport.drainQueueForSelfTest() }
            transport.send(message); transport.drainQueueForSelfTest()
            try expect(pending.snapshot.calls == 1, "内存 pending beginConnect 未建立")
            if revoke { gate.revoke() }
            else {
                let done = DispatchSemaphore(value: 0)
                transport.cancel { done.signal() }
                try expect(done.wait(timeout: .now() + 2) == .success && pending.snapshot.cancellations == 1,
                           "取消没有撤销 pending beginConnect 或 ACK 过早")
            }
            pending.ready(.success((stream, Data())))
            for _ in 0..<8 { transport.drainQueueForSelfTest() }
            try expect(stream.snapshot.writes.isEmpty && stream.snapshot.cancellations == 1
                       && probe.snapshot.answers.isEmpty, "取消/策略撤销后的 late ready 发出了明文查询")
            if revoke { try expect(probe.snapshot.error != nil, "策略撤销没有 fail closed") }
            else { try expect(probe.snapshot.error == nil, "主动取消仍交付错误/应答") }
        }
    }

    private final class ProxyFallbackMemoryDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding {
        private let lock = NSLock()
        private var barrier: DNSProxyFallbackBarrier?
        private let sendHandler: (Data) -> Void, cancellationBarrier: DNSProxyFallbackBarrier?
        init(cancellationBarrier: DNSProxyFallbackBarrier? = nil, send: @escaping (Data) -> Void) {
            self.cancellationBarrier = cancellationBarrier; sendHandler = send
        }
        func send(_ data: Data) { sendHandler(data) }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); if let cancellationBarrier { barrier = cancellationBarrier }; lock.unlock()
            completion(); completion() // malformed duplicate ACK must not over-leave a DispatchGroup
        }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { lock.lock(); defer { lock.unlock() }; return barrier }
    }

    private static func proxyFallbackAdaptiveBarriers() throws {
        let profile = adaptiveProfile(), source = router(profile), approved = try plan(source)
        let message = try query("allowed.example.test", 1)
        for hidden in [EncryptedDNSQueryFailure.authentication, .other, .capacity] {
            let started = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: DNSAdaptiveUpstreamSelector(),
                scopeKey: approved.healthScopeKey, queue: .global(), permitted: { true },
                factory: { _, _, _, _ in
                    ProxyFallbackMemoryDatagram(cancellationBarrier: .failure(hidden), send: { _ in started.signal() })
                }, receive: { _ in }, failure: { _ in }, protectProxyFallback: true)
            flow.send(message)
            try expect(started.wait(timeout: .now() + 2) == .success, "内存加密 phase 未启动")
            flow.cancel { cancelled.signal() }
            try expect(cancelled.wait(timeout: .now() + 2) == .success, "加密子查询取消 ACK 未完成")
            guard case .failure(let error)? = flow.proxyFallbackBarrier() else {
                throw Failure(text: "ACK 后已 retired 子请求的私有 barrier 丢失")
            }
            try expect(error as? EncryptedDNSQueryFailure == hidden, "ACK 后 hidden barrier 被其他候选覆盖")
        }
        for successfulBackup in [false, true] {
            let probe = AdaptiveProbe()
            let negative = DNSMessageInspection.errorResponse(to: message, code: .servfail)!
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: DNSAdaptiveUpstreamSelector(),
                scopeKey: approved.healthScopeKey, queue: .global(), permitted: { true },
                factory: { candidate, _, receive, failure in
                    ProxyFallbackMemoryDatagram(send: { query in
                        if candidate.id == approved.candidates[0].id { receive(negative) }
                        else if successfulBackup { receive(bootstrapAnswer(query)!) }
                        else { failure(EncryptedDNSQueryFailure.timeout) }
                    })
                }, receive: probe.received, failure: probe.failed, protectProxyFallback: true)
            defer { flow.cancel() }
            flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.answers.first?[3] == (successfulBackup ? 0x80 : 0x82),
                       "SERVFAIL 被 timeout 洗掉或阻止合格加密备用成功")
        }
        var phaseProfile = profile
        phaseProfile.encryptedDNSServers.append("https://third.phase-barrier.selftest.invalid/dns-query#203.0.113.72")
        let phaseApproved = try plan(router(phaseProfile)), ids = phaseApproved.candidates.map(\.id)
        let negative = DNSMessageInspection.errorResponse(to: message, code: .servfail)!
        let positive = bootstrapAnswer(message)!
        let barriers: [DNSProxyFallbackBarrier] = [.failure(EncryptedDNSQueryFailure.authentication),
            .failure(EncryptedDNSQueryFailure.capacity), .answer(negative), .answer(positive)]
        for barrier in barriers {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let flow = DNSAdaptiveQueryDatagram(candidates: phaseApproved.candidates, selector: selector,
                scopeKey: phaseApproved.healthScopeKey, queue: .global(), permitted: { true },
                factory: { candidate, _, _, _ in
                    ProxyFallbackMemoryDatagram(cancellationBarrier: barrier, send: { _ in probe.attempted(candidate) })
                }, receive: probe.received, failure: probe.failed, protectProxyFallback: true)
            defer { flow.cancel() }
            flow.send(message)
            try expect(probe.started.wait(timeout: .now() + 2) == .success, "加密阶段 barrier 查询未启动")
            let acknowledged = DispatchSemaphore(value: 0)
            flow.phaseDeadlineReached { acknowledged.signal() }
            try expect(acknowledged.wait(timeout: .now() + 2) == .success
                       && selector.orderedCandidates(scopeKey: phaseApproved.healthScopeKey, candidateIDs: ids) == ids,
                       "加密阶段 ACK 后认证/容量/合法应答 barrier 被误记为提供商网络超时")
            switch barrier {
            case .failure(let error):
                try expect(probe.snapshot.error.map(EncryptedDNSQueryFailure.classify) == EncryptedDNSQueryFailure.classify(error)
                           && probe.snapshot.answers.isEmpty, "阶段截止擦除了认证或容量错误")
            case .answer(let answer):
                try expect(probe.snapshot.answers == [answer] && probe.snapshot.error == nil,
                           "阶段截止擦除了已准入合法正向或否定应答")
            }
        }
    }

    private static func proxyFallbackEncryptedPhaseHealth() throws {
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let approved = try plan(router(profile)), message = try query("phase-health.example.test", 1)
        let ids = approved.candidates.map(\.id), selector = DNSAdaptiveUpstreamSelector()
        let fallbackStarted = DispatchSemaphore(value: 0)
        func exchange(_ probe: AdaptiveProbe, selector: DNSAdaptiveUpstreamSelector) -> DNSProxyFallbackQueryDatagram {
            DNSProxyFallbackQueryDatagram(queue: .global(qos: .userInitiated),
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8, permitted: { true },
                knownMilliseconds: {
                    ids.compactMap { selector.knownLatencyMilliseconds(scopeKey: approved.healthScopeKey, candidateID: $0) }
                }, encrypted: { queue, absolute, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                        scopeKey: approved.healthScopeKey, queue: queue, permitted: { true },
                        factory: { candidate, _, receive, _ in
                            ProxyFallbackMemoryDatagram(send: { data in
                                probe.attempted(candidate)
                                if candidate.id == ids[2] { receive(bootstrapAnswer(data)!) }
                            })
                        }, receive: receive, failure: failure, absoluteDeadline: absolute,
                        protectProxyFallback: true)
                }, fallback: { _, _, receive, _ in
                    ProxyFallbackMemoryDatagram(send: { data in
                        fallbackStarted.signal(); receive(bootstrapAnswer(data)!)
                    })
                }, receive: probe.received, failure: probe.failed)
        }

        // The first wave must reach its third approved encrypted candidate;
        // learning only after an unnecessary ordinary fallback is too late.
        let firstProbe = AdaptiveProbe(), first = exchange(firstProbe, selector: selector)
        defer { first.cancel() }
        first.send(message); try awaitAdaptive(firstProbe, query: message, waitTimeout: 7)
        try expect(firstProbe.snapshot.attempts == approved.candidates.prefix(3).map { $0.upstream.target.host }
                   && fallbackStarted.wait(timeout: .now()) == .timedOut,
                   "首批查询未等到第三个获准加密候选，或错误启动了普通后备")
        let secondProbe = AdaptiveProbe(), second = exchange(secondProbe, selector: selector)
        defer { second.cancel() }
        second.send(message); try awaitAdaptive(secondProbe, query: message)
        try expect(secondProbe.snapshot.attempts == [approved.candidates[2].upstream.target.host]
                   && fallbackStarted.wait(timeout: .now()) == .timedOut,
                   "加密成功后的健康学习未让下一查询优先使用可用候选")

        let cancelledSelector = DNSAdaptiveUpstreamSelector(), cancelledProbe = AdaptiveProbe()
        let cancelled = exchange(cancelledProbe, selector: cancelledSelector)
        cancelled.send(message)
        try expect(cancelledProbe.started.wait(timeout: .now() + 1) == .success, "待取消加密 phase 未启动")
        let acknowledged = DispatchSemaphore(value: 0)
        cancelled.cancel { acknowledged.signal() }
        try expect(acknowledged.wait(timeout: .now() + 2) == .success
                   && cancelledSelector.orderedCandidates(scopeKey: approved.healthScopeKey, candidateIDs: ids) == ids
                   && cancelledProbe.snapshot.answers.isEmpty && cancelledProbe.snapshot.error == nil,
                   "客户端取消被误记为加密提供商超时或仍交付结果")
    }

    public static func run() throws {
        if let text = UDPPrivacyPolicySelfTest.failure() { throw Failure(text: text) }
        try routing()
        try localServiceDiscoveryRouting()
        try routeDecisionCache()
        try dnsPurposeIsolation()
        try DNSAdaptiveUpstreamSelectorSelfTest.run()
        try adaptiveCandidatePolicy()
        try adaptiveBuiltinAddressVariants()
        try adaptiveEncryptedExchanges()
        try adaptiveLocalCapacityIsolation()
        try productionEncryptedCapacityIsolation()
        try adaptiveShortHedgeBudgets()
        try adaptiveHedgedExchanges()
        try adaptiveParentDeadlineHealth()
        try adaptiveHealthScopeIsolationAndBurst()
        try adaptiveHedgeRotation()
        try adaptiveQueuedAbsoluteDeadlines()
        try directHostnameDNSConfiguration()
        try directAddressResolutionGrace()
        try asynchronousBootstrap()
        try queryPerformancePolicyIsolation()
        try DNSResolverLeaseSelfTest.run()
        try transportScopeAndManyClientBurst()
        try PolicyDNSCallbackQueueSelfTest.run()
        try framing()
        try resourceBudget()
        try framedFakeIPRoundTrip()
        if let text = ProxyEngine.localDNSIsolationSelfTest() { throw Failure(text: text) }
    }

    private static func localServiceDiscoveryRouting() throws {
        let name = "lb._dns-sd._udp.1.168.192.in-addr.arpa"
        let message = try query(name, 12)
        let original = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7263)
        var profile = proxyFallbackProfile()
        profile.dnsServers = []
        profile.encryptedDNSServers = ["https://doh.pub/dns-query#1.12.12.12",
            "https://dns.google/dns-query#8.8.8.8", "https://cloudflare-dns.com/dns-query#1.1.1.1"]
        profile.dnsProxyFallbackEnabled = false; profile.dnsProxyFallbackServers = []
        func requireLocal(_ source: NativePacketRouter, wire: Data = message) throws {
            guard case .answer(let answer, let generation) = try source.prepareDNSQuery(wire, original: original) else {
                throw Failure(text: "标准公共加密配置未本地处理保留反向区DNS-SD")
            }
            var expected = wire; expected[2] = 0x81; expected[3] = 0x80
            try expect(answer == expected && source.isCurrentDNSGeneration(generation)
                       && DNSMessageInspection.responseMatchesQuery(answer, query: wire),
                       "本地DNS-SD空答丢失ID、大小写、NOERROR或当前代际")
        }
        func requireUpstream(_ value: Profile, wire: Data = message) throws {
            guard case .upstream = try router(value).prepareDNSQuery(wire, original: original) else {
                throw Failure(text: "自定义/企业解析器或普通DNS问题被本地DNS-SD分支覆盖")
            }
        }
        for endpoint in ["https://doh.pub/dns-query", "https://dns.google/dns-query#8.8.4.4",
                         "tls://dot.pub", "https://1.1.1.1/dns-query", "tls://1.1.1.1"] {
            var standard = profile; standard.encryptedDNSServers = [endpoint]
            try requireLocal(router(standard))
        }
        for mode: OutboundMode in [.rule, .proxy, .direct] { try requireLocal(router(profile, mode: mode)) }
        var defaults = profile; defaults.encryptedDNSServers = []
        try requireLocal(router(defaults)) // The effective default is a pinned public resolver.
        for endpoint in ["https://doh.pub/dns-query#192.168.1.53", "https://doh.pub/dns-query#127.0.0.1",
                         "https://doh.pub/dns-query#8.8.8.8", "https://doh.pub/enterprise-query",
                         "https://doh.pub:8443/dns-query", "https://doh.pub/dns-query?profile=private",
                         "https://doh.pub/dns-query?", "https://doh.pub/dns%2Dquery",
                         "https://192.168.1.53/dns-query", "https://enterprise.selftest.invalid/dns-query#1.1.1.1",
                         "https://1.1.1.1/dns-query#8.8.8.8", "tls://dot.pub#192.168.1.53", "tls://dot.pub:8853"] {
            var custom = profile; custom.encryptedDNSServers = [endpoint]
            try requireUpstream(custom)
        }
        for deny in [RuleKind.domain("enterprise.selftest.invalid"), .ipCIDR("192.168.1.53/32")] {
            var enterprise = profile
            enterprise.encryptedDNSServers.append("https://enterprise.selftest.invalid/dns-query#192.168.1.53")
            enterprise.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            let chosen = try plan(router(enterprise), name: name, type: 12, original: original)
            try expect(chosen.candidates.allSatisfy { $0.upstream.isStandardPublicEncryptedResolver },
                       "企业解析器过滤样本没有真正只留下公共候选")
            try requireUpstream(enterprise)
        }
        var partialDeny = profile
        partialDeny.rules.insert(RoutingRule(kind: .domain("doh.pub"), policy: "REJECT", sourceLine: 0), at: 0)
        try requireLocal(router(partialDeny)) // Another approved public resolver remains.
        for selection: DNSSelectionMode in [.balanced, .mixedSpeed] {
            var fallback = profile; fallback.dnsSelectionMode = selection
            fallback.dnsProxyFallbackEnabled = selection == .balanced
            fallback.dnsProxyFallbackServers = ["192.168.1.53"]
            try requireUpstream(fallback)
            fallback.dnsProxyFallbackServers = []
            do { _ = try router(fallback).prepareDNSQuery(message, original: original)
                throw Failure(text: "本地DNS-SD分支掩盖了活动普通DNS后备的无效配置")
            } catch DNSPolicyFailure.configuration {}
        }
        var encryptedOnly = profile
        encryptedOnly.dnsSelectionMode = .encryptedOnly; encryptedOnly.dnsProxyFallbackEnabled = true
        encryptedOnly.dnsProxyFallbackServers = ["192.168.1.53"]
        try requireLocal(router(encryptedOnly)) // Inactive stored fallback settings grant no authority.
        var traditional = profile; traditional.encryptedDNSServers = []; traditional.dnsServers = ["192.168.1.53"]
        try requireUpstream(traditional)
        traditional.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        try requireUpstream(traditional) // A DIRECT secureDefault replacement must not change the original resolver view.
        traditional.dnsServers = []; traditional.dnsLeakProtectionEnabled = false
        try requireUpstream(traditional)
        for remote in ["b._dns-sd._udp.example.test", "b._dns-sd._udp.local",
                       "b._dns-sd._udp.8.8.8.8.in-addr.arpa", "1.1.168.192.in-addr.arpa",
                       "_services._dns-sd._udp.1.168.192.in-addr.arpa"] {
            try requireUpstream(profile, wire: query(remote, 12))
        }
        var edns = message; edns[11] = 1
        edns.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0])
        try requireUpstream(profile, wire: edns)
        for deny in [RuleKind.ipCIDR("203.0.113.53/32"), .domain(name), .sourceIPCIDR("192.0.2.1/32"),
                     .sourcePort(41000...41000), .inboundPort(7263...7263)] {
            var rejected = profile
            rejected.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            for mode: OutboundMode in [.rule, .proxy, .direct] {
                try refusal(router(rejected, mode: mode), name: name, type: 12, original: original)
            }
        }
        for deny in [RuleKind.domain("doh.pub"), .ipCIDR("1.12.12.12/32")] {
            var rejected = profile; rejected.encryptedDNSServers = [profile.encryptedDNSServers[0]]
            rejected.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            for mode: OutboundMode in [.rule, .proxy, .direct] {
                try refusal(router(rejected, mode: mode), name: name, type: 12, original: original)
            }
        }
        for values in [["https://dns.google"], profile.encryptedDNSServers + ["not-an-encrypted-resolver"]] {
            var invalid = profile; invalid.encryptedDNSServers = values
            do { _ = try router(invalid).prepareDNSQuery(message, original: original)
                throw Failure(text: "本地DNS-SD分支掩盖了无效加密解析器配置")
            } catch DNSPolicyFailure.configuration {}
        }

        // Real policy associations use a trapping memory factory: an accidental
        // upstream path fails the test and cannot open a public socket. Hold the
        // actual owner queue across flush/update/cancel to exercise delivery.
        for change in 0..<5 {
            let source = router(profile), replies = AdaptiveProbe(), factory = BootstrapProbe()
            let parent = DispatchQueue(label: "app.hajimi.dns.local-discovery-self-test.\(change)")
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let flow = try PolicyDNSDatagram(router: source, original: original, queue: parent,
                synthesizeFakeIP: false, receive: replies.received, failure: replies.failed,
                queryTimeout: .milliseconds(150), upstreamFactory: { _, _, _ in
                    factory.lock.lock(); factory.builds += 1; factory.lock.unlock()
                    throw Failure(text: "本地DNS-SD意外调用上游工厂")
                })
            defer { release.signal(); flow.cancel(); flow.drainQueueForSelfTest(); parent.sync {} }
            parent.async { entered.signal(); _ = release.wait(timeout: .now() + 2) }
            try expect(entered.wait(timeout: .now() + 2) == .success, "DNS-SD交付队列未进入受控排队")
            flow.send(message)
            try expect(replies.done.wait(timeout: .now()) == .timedOut, "本地DNS-SD绕过owner队列提前回包")
            if change == 1 || change == 4 { source.flushDNS() }
            if change == 2 {
                var rejected = profile
                rejected.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)]
                source.update(profile: rejected, mode: .rule, globalPolicy: "Node", groupSelections: [:])
            }
            if change >= 3 { flow.cancel() }
            release.signal(); flow.drainQueueForSelfTest(); parent.sync {}
            if change >= 3 {
                try expect(replies.done.wait(timeout: .now()) == .timedOut
                           && replies.snapshot.answers.isEmpty && replies.snapshot.error == nil,
                           "已取消DNS-SD交付了旧空答或错误回调")
            } else {
                try expect(replies.done.wait(timeout: .now() + 2) == .success, "本地DNS-SD没有完成队列交付")
                let result = replies.snapshot
                let code: UInt8 = change == 0 ? 0 : 2
                try expect(result.error == nil && result.answers.count == 1
                           && DNSMessageInspection.responseMatchesQuery(result.answers[0], query: message)
                           && result.answers[0][3] & 15 == code,
                           "本地DNS-SD跨代际交付旧NOERROR或没有返回一次SERVFAIL")
                if change == 1 {
                    let fresh = try query(name, 12, id: 0x4646)
                    flow.send(fresh)
                    try expect(replies.done.wait(timeout: .now() + 2) == .success, "flush后新DNS-SD问题没有完成")
                    try expect(replies.snapshot.answers.count == 2
                               && DNSMessageInspection.responseMatchesQuery(replies.snapshot.answers[1], query: fresh)
                               && replies.snapshot.answers[1][3] & 15 == 0,
                               "旧代际SERVFAIL影响了新代际DNS-SD本地空答")
                }
            }
            flow.drainQueueForSelfTest()
            factory.lock.lock(); let builds = factory.builds; factory.lock.unlock()
            try expect(builds == 0, "本地DNS-SD创建了上游transport、共享查询或连接")
        }
        // An excluded private/custom view still enters the real coordinator;
        // its only transport is this explicit, immediate memory responder.
        for endpoint in ["https://doh.pub/dns-query#192.168.1.53", "https://doh.pub/enterprise-query"] {
            var custom = profile; custom.encryptedDNSServers = [endpoint]
            let source = router(custom), replies = AdaptiveProbe(), factory = BootstrapProbe()
            let flow = try PolicyDNSDatagram(router: source, original: original, queue: .global(),
                synthesizeFakeIP: false, receive: replies.received, failure: replies.failed,
                queryTimeout: .seconds(2), upstreamFactory: { _, receive, _ in
                    factory.lock.lock(); factory.builds += 1; factory.lock.unlock()
                    return BootstrapMemoryTransport { data in receive(bootstrapAnswer(data)!) }
                })
            defer { flow.cancel(); flow.drainQueueForSelfTest() }
            flow.send(message)
            try expect(replies.done.wait(timeout: .now() + 2) == .success, "自定义DNS视图未进入内存上游")
            flow.drainQueueForSelfTest()
            factory.lock.lock(); let builds = factory.builds; factory.lock.unlock()
            try expect(builds == 1 && replies.snapshot.error == nil && replies.snapshot.answers.count == 1
                       && DNSMessageInspection.responseMatchesQuery(replies.snapshot.answers[0], query: message),
                       "自定义DNS视图被本地空答覆盖或没有经过真实coordinator")
        }
        print("DNS-SD local routing: public-only endpoint gate, enterprise/fallback ownership, full policy/configuration checks, zero upstream calls and epoch/cancel delivery fences passed")
    }

    private static func transportScopeAndManyClientBurst() throws {
        let makeRouter: DNSTransportScopeSelfTest.MakeRouter = { profile, dialer in
            // No wire plaintext fallback, real helper, listener or configurable
            // trust override is allowed in this private memory-only factory.
            precondition(!profile.dnsProxyFallbackEnabled && !profile.fakeIPEnabled)
            let value = router(profile, global: "DIRECT")
            value.memoryFixtureDNSStreamDialer = dialer
            return value
        }
        try DNSTransportScopeSelfTest.run(makeRouter: makeRouter, inspect: { value, query, original, interface in
            guard case .upstream(let decision) = try value.prepareDNSQuery(query, original: original,
                                                                           synthesizeFakeIP: false) else {
                throw Failure(text: "传输复用回归查询被意外合成")
            }
            let snapshot = value.dnsRoutingSnapshotForSelfTest()
            return DNSTransportScopeSelfTest.ScopeSnapshot(queryScope: decision.scopeKey,
                transportScope: snapshot.transportScope(upstream: decision.upstream, route: decision.route,
                    interfaceName: interface ?? decision.interfaceName), generation: decision.generation)
        })
        try DNSEpochTransitionSelfTest.run(makeRouter: makeRouter,
            installAfterFlushGate: { $0.memoryFixtureAfterDNSFlushUnlock = $1 },
            drainFlow: { ($0 as? PolicyDNSDatagram)?.drainQueueForSelfTest() })
    }

    private static func routeDecisionCache() throws {
        let source = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7263)
        func snapshot(_ profile: Profile, mode: OutboundMode = .rule, global: String = "DIRECT",
                      selections: [String: String] = [:], cache: DNSRouteDecisionCache? = nil) -> DNSRoutingSnapshot {
            DNSRoutingSnapshot(profile: profile, mode: mode, globalPolicy: global,
                selections: selections, generation: 7,
                sourcePortSensitive: DNSRoutingSnapshot.usesSourcePortRules(profile), routeCache: cache)
        }
        var basic = Profile()
        basic.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        do {
            let cache = DNSRouteDecisionCache(), cached = snapshot(basic, cache: cache)
            try expect(cached.route(source) == snapshot(basic).route(source), "路由决策缓存改变冷态结果")
            _ = cached.route(source)
            var ephemeral = source; ephemeral.sourcePort = 41001
            _ = cached.route(ephemeral)
            try expect(cache.snapshotForSelfTest.entries == 1 && cache.snapshotForSelfTest.hits == 2,
                       "同一上下文或无 SRC-PORT 规则的临时端口未命中决策缓存")
            var variants: [RequestTarget] = []
            var value = source; value.sourceHost = nil; variants.append(value)
            value = source; value.sourceHost = ""; variants.append(value)
            value = source; value.sourceHost = "192.0.2.2"; variants.append(value)
            value = source; value.host = "203.0.113.54"; variants.append(value)
            value = source; value.port = 5353; variants.append(value)
            value = source; value.protocolName = "TCP"; variants.append(value)
            value = source; value.inboundPort = nil; variants.append(value)
            value = source; value.inboundPort = 0; variants.append(value)
            value = source; value.inboundPort = 7264; variants.append(value)
            for target in variants {
                try expect(cached.route(target) == snapshot(basic).route(target), "元数据决策缓存改变路由")
            }
            _ = cached.route(source, name: "one.example.test")
            _ = cached.route(source, name: "two.example.test")
            _ = cached.route(source, name: "")
            _ = cached.route(source, mode: .proxy)
            _ = cached.route(source, mode: .direct)
            try expect(cache.snapshotForSelfTest.entries == variants.count + 6,
                       "决策缓存混合 nil/空值、原地址/QNAME、协议或模式")
        }
        do {
            var denied = basic
            denied.rules = [
                RoutingRule(kind: .domain("blocked.example.test"), policy: "REJECT", sourceLine: 1),
                RoutingRule(kind: .ipCIDR("203.0.113.54/32"), policy: "REJECT", sourceLine: 2),
                RoutingRule(kind: .sourceIPCIDR("192.0.2.2/32"), policy: "REJECT", sourceLine: 3),
                RoutingRule(kind: .logicalAnd([.sourcePort(41001...41001), .protocolName("UDP")]),
                    policy: "REJECT", sourceLine: 4),
                RoutingRule(kind: .inboundPort(7264...7264), policy: "REJECT", sourceLine: 5),
                RoutingRule(kind: .destinationPort(5353...5353), policy: "REJECT", sourceLine: 6),
                RoutingRule(kind: .protocolName("TCP"), policy: "REJECT", sourceLine: 7),
                RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 8)]
            let cached = snapshot(denied, cache: DNSRouteDecisionCache()), plain = snapshot(denied)
            try expect(cached.route(source) == .direct("DIRECT"), "拒绝样本错误地覆盖允许上下文")
            var targets: [(RequestTarget, String?)] = [(source, "blocked.example.test")]
            var value = source; value.host = "203.0.113.54"; targets.append((value, nil))
            value = source; value.sourceHost = "192.0.2.2"; targets.append((value, nil))
            value = source; value.sourcePort = 41001; targets.append((value, nil))
            value = source; value.inboundPort = 7264; targets.append((value, nil))
            value = source; value.port = 5353; targets.append((value, nil))
            value = source; value.protocolName = "TCP"; targets.append((value, nil))
            for (target, name) in targets {
                for _ in 0..<2 {
                    let decision = cached.route(target, name: name)
                    guard case .reject = decision else { throw Failure(text: "热决策缓存绕过 REJECT") }
                    try expect(decision == plain.route(target, name: name), "缓存和完整拒绝匹配不一致")
                }
            }
            let reference = RuleSetReference(location: "memory.route-cache.source-port")
            denied.ruleSetContents[reference.location] = [.logicalNot(.logicalNot(.sourcePort(41001...41001)))]
            denied.rules = [RoutingRule(kind: .ruleSet(reference), policy: "REJECT", sourceLine: 1),
                            RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2)]
            let nestedCache = DNSRouteDecisionCache(), nested = snapshot(denied, cache: nestedCache)
            try expect(nested.sourcePortSensitive && nested.route(source) == .direct("DIRECT"),
                       "嵌套规则集未检测 SRC-PORT 敏感性")
            value = source; value.sourcePort = 41001
            try expect(nested.route(value) == .reject("REJECT"), "嵌套 SRC-PORT 拒绝继承了允许端口")
            value.sourcePort = nil; _ = nested.route(value)
            value.sourcePort = 0; _ = nested.route(value)
            try expect(nestedCache.snapshotForSelfTest.entries == 4, "敏感源端口的 nil/零值被混同")
        }
        do {
            let kinds: [RuleKind] = [
                .logicalOr([.domain("blocked.example.test"), .sourceIPCIDR("192.0.2.2/32")]),
                .logicalAnd([.logicalNot(.domain("allowed.example.test")), .protocolName("UDP")]),
                .logicalNot(.logicalOr([.domain("allowed.example.test"), .destinationPort(443...443)]))]
            for kind in kinds {
                var logical = basic
                logical.rules.insert(RoutingRule(kind: kind, policy: "REJECT", sourceLine: 0), at: 0)
                let cached = snapshot(logical, cache: DNSRouteDecisionCache()), plain = snapshot(logical)
                for name in ["allowed.example.test", "blocked.example.test"] {
                    for _ in 0..<2 {
                        try expect(cached.route(source, name: name) == plain.route(source, name: name),
                                   "AND/OR/NOT 复合规则的热缓存改变了完整匹配")
                    }
                }
            }
        }
        do {
            var provider = basic
            provider.rules.insert(RoutingRule(kind: .ipCIDR("1.0.0.1/32"), policy: "REJECT", sourceLine: 0), at: 0)
            let first = DNSConfiguredUpstream.doh(DoHEndpoint("https://cloudflare-dns.com/dns-query#1.1.1.1")!)
            let second = DNSConfiguredUpstream.doh(DoHEndpoint("https://cloudflare-dns.com/dns-query#1.0.0.1")!)
            let cached = snapshot(provider, cache: DNSRouteDecisionCache())
            for _ in 0..<2 {
                try cached.requireAllowedResolver(first, original: source)
                do { try cached.requireAllowedResolver(second, original: source)
                    throw Failure(text: "同 provider 的第二个 IP 绕过拒绝")
                } catch DNSPolicyFailure.refused {}
            }
            provider.rules[0] = RoutingRule(kind: .domain("cloudflare-dns.com"), policy: "REJECT", sourceLine: 0)
            let identity = snapshot(provider, cache: DNSRouteDecisionCache())
            for upstream in [first, second] {
                do { try identity.requireAllowedResolver(upstream, original: source)
                    throw Failure(text: "provider 身份拒绝被 IP 决策缓存绕过")
                } catch DNSPolicyFailure.refused {}
            }
        }
        do {
            var grouped = basic
            let one = ProxyPolicy(name: "One", kind: .native, host: "203.0.113.10", port: 443,
                                  adapterType: "trojan", parameters: ["password": "memory-only"])
            let two = ProxyPolicy(name: "Two", kind: .native, host: "203.0.113.11", port: 443,
                                  adapterType: "trojan", parameters: ["password": "memory-only"])
            grouped.proxies[one.name] = one; grouped.proxies[two.name] = two
            grouped.groups["Balanced"] = PolicyGroup(name: "Balanced", kind: .loadBalance, members: [one.name, two.name])
            let cache = DNSRouteDecisionCache()
            let cached = snapshot(grouped, mode: .proxy, global: "Balanced", cache: cache)
            let plain = snapshot(grouped, mode: .proxy, global: "Balanced")
            var variants = [source]
            var value = source; value.host = "203.0.113.54"; variants.append(value)
            value = source; value.port = 443; variants.append(value)
            value = source; value.protocolName = "TCP"; variants.append(value)
            for target in variants {
                try expect(cached.route(target) == plain.route(target) && cached.route(target) == plain.route(target),
                           "load-balance 决策缓存丢失 host/port/protocol 哈希")
            }
            value = source; value.sourcePort = 41001
            try expect(cached.route(value) == plain.route(source) && cache.snapshotForSelfTest.entries == variants.count,
                       "load-balance 意外依赖无规则观察的临时源端口")
            let selected = snapshot(grouped, mode: .proxy, global: "Balanced",
                                    selections: ["Balanced": two.name], cache: DNSRouteDecisionCache())
            try expect(selected.route(source) == .native(two, two.name), "新的策略组选项继承旧快照决策")
            let routed = NativePacketRouter(profile: grouped, mode: .proxy, globalPolicy: "Balanced",
                                             groupSelections: ["Balanced": one.name])
            let before = routed.dnsRoutingSnapshotForSelfTest()
            try expect(before.route(source) == .native(one, one.name), "策略组更新样本未预热旧决策")
            routed.update(profile: grouped, mode: .proxy, globalPolicy: "Balanced",
                          groupSelections: ["Balanced": two.name])
            let after = routed.dnsRoutingSnapshotForSelfTest()
            try expect(after.routeCache !== before.routeCache && after.route(source) == .native(two, two.name),
                       "同一 profile 的策略组选项更新未替换决策 epoch")
            let loop = PolicyGroup(name: "Loop", members: ["Loop"])
            grouped.groups[loop.name] = loop
            let cyclic = snapshot(grouped, mode: .proxy, global: loop.name, cache: DNSRouteDecisionCache())
            try expect(cyclic.route(source) == snapshot(grouped, mode: .proxy, global: loop.name).route(source),
                       "策略组循环被缓存改为直连")
        }
        do {
            var recursive = basic
            let loop = RuleSetReference(location: "memory.route-cache.loop")
            recursive.rules.insert(RoutingRule(kind: .ruleSet(loop), policy: "DIRECT", sourceLine: 0), at: 0)
            recursive.ruleSetContents[loop.location] = [.ruleSet(loop)]
            let cached = snapshot(recursive, cache: DNSRouteDecisionCache())
            for _ in 0..<2 {
                guard case .reject = cached.route(source) else { throw Failure(text: "规则集循环没有 fail closed") }
                try expect(cached.route(source) == snapshot(recursive).route(source), "循环规则缓存改变拒绝原因")
            }
            var deep: RuleKind = .domain("unmatched.example.test")
            for _ in 0..<40 { deep = .logicalNot(deep) }
            recursive.rules[0] = RoutingRule(kind: deep, policy: "DIRECT", sourceLine: 0)
            let depth = snapshot(recursive, cache: DNSRouteDecisionCache())
            guard case .reject = depth.route(source) else { throw Failure(text: "超深逻辑规则缓存没有 fail closed") }
            var finalFirst = recursive
            finalFirst.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1),
                                RoutingRule(kind: .final, policy: "REJECT", sourceLine: 2)]
            try expect(snapshot(finalFirst, cache: DNSRouteDecisionCache()).route(source) == .direct("DIRECT"),
                       "缓存改变了 FINAL 的首条命中语义")
        }
        do {
            let cache = DNSRouteDecisionCache(maximumEntries: 2), cached = snapshot(basic, cache: cache)
            for name in ["one.example.test", "two.example.test", "three.example.test", "one.example.test"] {
                try expect(cached.route(source, name: name) == snapshot(basic).route(source, name: name),
                           "FIFO 淘汰改变了路由结果")
            }
            try expect(cache.snapshotForSelfTest.entries == 2, "决策缓存容量没有上限")
            let before = cache.snapshotForSelfTest
            let longName = String(repeating: "x", count: 2_048)
            _ = cached.route(source, name: longName); _ = cached.route(source, name: longName)
            try expect(cache.snapshotForSelfTest.entries == before.entries && cache.snapshotForSelfTest.hits == before.hits,
                       "超长决策 key 被缓存并延长了生命周期")
            let disabled = DNSRouteDecisionCache(maximumEntries: 0)
            _ = snapshot(basic, cache: disabled).route(source)
            try expect(disabled.snapshotForSelfTest.entries == 0, "零容量缓存仍保留决策")
        }
        do {
            var concurrentProfile = basic
            concurrentProfile.rules.insert(RoutingRule(kind: .domain("blocked.example.test"),
                policy: "REJECT", sourceLine: 0), at: 0)
            let cache = DNSRouteDecisionCache(maximumEntries: 8)
            let cached = snapshot(concurrentProfile, cache: cache), plain = snapshot(concurrentProfile)
            let lock = NSLock(); var matched = true
            DispatchQueue.concurrentPerform(iterations: 64) { index in
                var target = source; target.sourcePort = UInt16(42000 + index)
                let name = index % 2 == 0 ? "allowed.example.test" : "blocked.example.test"
                if cached.route(target, name: name) != plain.route(target, name: name) {
                    lock.lock(); matched = false; lock.unlock()
                }
            }
            try expect(matched && cache.snapshotForSelfTest.entries == 2,
                       "并发 miss 覆盖了拒绝决策或重复预留了缓存容量")
        }
        do {
            let routed = router(basic), old = routed.dnsRoutingSnapshotForSelfTest()
            _ = old.route(source)
            let release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
            defer { release.signal() }
            DispatchQueue.global(qos: .userInitiated).async {
                release.wait()
                _ = old.route(source, name: "late.example.test")
                done.signal()
            }
            routed.flushDNS()
            let fresh = routed.dnsRoutingSnapshotForSelfTest()
            try expect(old.routeCache !== fresh.routeCache && !routed.isCurrentDNSGeneration(old.generation),
                       "flush 重置了旧对象而非替换决策缓存 epoch")
            release.signal()
            try expect(done.wait(timeout: .now() + 2) == .success && fresh.routeCache?.snapshotForSelfTest.entries == 0,
                       "旧快照迟到计算污染了新 epoch")
            var changed = basic
            changed.rules[0] = RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)
            routed.update(profile: changed, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            let updated = routed.dnsRoutingSnapshotForSelfTest()
            try expect(updated.routeCache !== fresh.routeCache && updated.route(source) == .reject("REJECT"),
                       "profile 更新继承旧允许决策或未替换缓存")
            try refusal(routed, name: "allowed.example.test", type: 1, original: source)
        }
        do {
            var changing = basic
            let reference = RuleSetReference(location: "memory.route-cache.contents")
            changing.rules = [RoutingRule(kind: .ruleSet(reference), policy: "DIRECT", sourceLine: 1),
                              RoutingRule(kind: .final, policy: "REJECT", sourceLine: 2)]
            changing.ruleSetContents[reference.location] = [.domain("allowed.example.test")]
            let routed = router(changing), before = routed.dnsRoutingSnapshotForSelfTest()
            try expect(before.route(source, name: "allowed.example.test") == .direct("DIRECT"),
                       "规则集内容更新样本未预热允许决策")
            changing.ruleSetContents[reference.location] = [.domain("other.example.test")]
            routed.update(profile: changing, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            let after = routed.dnsRoutingSnapshotForSelfTest()
            try expect(before.routeCache !== after.routeCache
                       && after.route(source, name: "allowed.example.test") == .reject("REJECT"),
                       "主规则未变的规则集更新继承旧允许缓存")
        }
        do {
            let before = NetworkPerformanceDiagnostics.shared.snapshot()
            _ = try plan(router(basic), original: source)
            let after = NetworkPerformanceDiagnostics.shared.snapshot()
            try expect(after.dnsQueries == before.dnsQueries && after.dnsFailures == before.dnsFailures
                       && after.stages[.dnsPolicyPreparation]?.count
                            == (before.stages[.dnsPolicyPreparation]?.count ?? 0) + 1,
                       "策略准备计量重复统计逻辑 DNS 或没有覆盖 cache 前工作")
        }
    }

    private static func queryPerformancePolicyIsolation() throws {
        var profile = Profile()
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let routed = router(profile)
        let probe = BootstrapProbe()
        let queue = DispatchQueue(label: "app.hajimi.dns.policy-cache-self-test")
        let message = try query("allowed.example.test", 1)
        let source = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
                                   sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7263)
        func exchange(_ decision: DNSQueryPlan, query: Data? = nil) throws {
            let query = query ?? message
            let complete = DispatchSemaphore(value: 0), lock = NSLock()
            var valid = false
            let transport = try routed.makeOptimizedDNSUpstream(plan: decision, queue: queue,
                factory: { _, receive, _ in
                    probe.lock.lock(); probe.builds += 1; probe.lock.unlock()
                    return BootstrapMemoryTransport { request in
                        if let response = bootstrapAnswer(request) { receive(response) }
                    }
                }, receive: { answer in
                    lock.lock(); valid = DNSMessageInspection.responseMatchesQuery(answer, query: query); lock.unlock()
                    complete.signal()
                }, failure: { _ in complete.signal() })
            defer { transport.cancel() }
            transport.send(query)
            try expect(complete.wait(timeout: .now() + 3) == .success, "策略缓存回包超时")
            lock.lock(); let accepted = valid; lock.unlock()
            try expect(accepted, "策略缓存回包丢失 ID 或问题身份")
        }
        let first = try plan(routed, original: source)
        try exchange(first)
        var other = source; other.sourcePort = 41001
        let ephemeral = try plan(routed, original: other)
        try expect(first.scopeKey == ephemeral.scopeKey, "无源端口规则时临时 UDP 端口破坏缓存命中")
        try exchange(ephemeral, query: try query("allowed.example.test", 1, id: 0x4546))
        probe.lock.lock(); let warmBuilds = probe.builds; probe.lock.unlock()
        try expect(warmBuilds == 1, "缓存命中仍创建第二个上游")
        other.sourceHost = "192.0.2.2"
        try expect(first.scopeKey != (try plan(routed, original: other)).scopeKey, "缓存跨来源 IP 共享")
        other = source; other.inboundPort = 7264
        try expect(first.scopeKey != (try plan(routed, original: other)).scopeKey, "缓存跨入站端口共享")
        other = source; other.host = "203.0.113.54"
        try expect(first.scopeKey != (try plan(routed, original: other)).scopeKey, "缓存丢失原 DNS 目的地址")
        other = source; other.protocolName = "TCP"
        try expect(first.scopeKey != (try plan(routed, original: other)).scopeKey, "缓存丢失 UDP/TCP 身份")

        let nested = RuleSetReference(location: "memory.source-port.selftest")
        profile.ruleSetContents[nested.location] = [.logicalNot(.logicalNot(.sourcePort(41001...41001)))]
        profile.rules = [RoutingRule(kind: .ruleSet(nested), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2)]
        routed.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
        let portScoped = try plan(routed, original: source)
        other = source; other.sourcePort = 41002
        try expect(portScoped.scopeKey != (try plan(routed, original: other)).scopeKey,
                   "嵌套规则集 SRC-PORT 没有隔离缓存")
        other.sourcePort = 41001
        try refusal(routed, name: "allowed.example.test", type: 1, original: other)
        try exchange(portScoped)
        probe.lock.lock(); let changedBuilds = probe.builds; probe.lock.unlock()
        try expect(changedBuilds == 2, "策略更新未撤销旧缓存")

        for deny in [RuleKind.domain("allowed.example.test"), .ipCIDR("203.0.113.53/32"),
                     .domain("cloudflare-dns.com"), .ipCIDR("1.1.1.1/32")] {
            profile.rules = [RoutingRule(kind: deny, policy: "REJECT", sourceLine: 1),
                             RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2)]
            routed.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            try refusal(routed, name: "allowed.example.test", type: 1, original: source)
        }
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        routed.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
        let beforeFlush = try plan(routed, original: source)
        try exchange(beforeFlush)
        routed.flushDNS()
        try expect(!routed.isCurrentDNSGeneration(beforeFlush.generation), "清空 DNS 未撤销在途查询代次")
        try exchange(try plan(routed, original: source))
        probe.lock.lock(); let flushedBuilds = probe.builds; probe.lock.unlock()
        try expect(flushedBuilds == 4, "清空 DNS 后仍返回旧缓存")
    }

    private static func resourceBudget() throws {
        let budget = SOCKSUDPGlobalBudget(resources: 2, packets: 4, bytes: 8)
        guard let first = DNSQueryResourceBudget.reserve(bytes: 4, budget: budget),
              let second = DNSQueryResourceBudget.reserve(bytes: 4, budget: budget) else {
            throw Failure(text: "DNS 事务资源预算样本无法预留")
        }
        try expect(DNSQueryResourceBudget.reserve(bytes: 0, budget: budget) == nil,
                   "DNS TCP 事务绕过全局连接名额上限")
        try expect(budget.usage.resources == 2 && budget.usage.packets == 2 && budget.usage.bytes == 8,
                   "DNS 拒绝的事务遗留连接/载荷名额")
        first.payload.release(); first.connection.release()
        guard let replacement = DNSQueryResourceBudget.reserve(bytes: 0, budget: budget) else {
            throw Failure(text: "DNS 已释放的连接名额无法复用")
        }
        second.payload.release(); second.connection.release()
        replacement.payload.release(); replacement.connection.release()
        try expect(DNSQueryResourceBudget.reserve(bytes: 9, budget: budget) == nil
                   && DNSQueryResourceBudget.reserve(bytes: -1, budget: budget) == nil,
                   "DNS 无效或超预算载荷被接受")
        try expect(budget.usage.resources == 0 && budget.usage.packets == 0 && budget.usage.bytes == 0,
                   "DNS 拒绝、完成或取消后没有释放全局预算")
    }

    private static func routing() throws {
        var profile = Profile()
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                               adapterType: "trojan", parameters: ["password": "test"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        let target = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")
        let kinds: [UInt16] = [1, 28, 15, 16, 64, 65, 255]
        for mode: OutboundMode in [.proxy, .rule] {
            let routed = router(profile, mode: mode)
            for type in kinds {
                let decision = try plan(routed, type: type)
                try expect(decision.route == .native(node, node.name), "QTYPE \(type) 丢失选定代理")
                try expect(decision.upstream.encrypted, "默认查询不是加密 DNS")
                try expect(DoHEndpoint.isAddressLiteral(decision.upstream.target.host), "解析器使用隐式系统 bootstrap")
            }
        }
        profile.dnsServers = ["udp://203.0.113.60:5353"]
        let plainProxy = try plan(router(profile, mode: .proxy))
        try expect(plainProxy.route == .native(node, node.name) && !plainProxy.upstream.encrypted,
                   "自定义明文 DNS 未保持代理承载")
        let transport = try router(profile).makeDNSUpstream(plan: plainProxy, queue: .global(),
                                                           receive: { _ in }, failure: { _ in })
        try expect(transport is TCPDNSQueryDatagram, "无 UDP 的 DNS 被降级为直接套接字")
        transport.cancel()

        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let direct = try plan(router(profile))
        try expect(direct.upstream.encrypted && direct.upstream.target.host == "1.1.1.1",
                   "DIRECT 规则下明文 DNS 未替换成固定 bootstrap 加密 DNS")
        profile.dnsLeakProtectionEnabled = false
        let optedOut = try plan(router(profile))
        try expect(!optedOut.upstream.encrypted && optedOut.upstream.target.port == 5353,
                   "显式关闭保护未保留明文 DNS 兼容配置")
        profile.dnsLeakProtectionEnabled = true
        profile.dnsServers = []
        profile.fakeIPEnabled = true
        profile.rules = [RoutingRule(kind: .domain("blocked.example.test"), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .final, policy: node.name, sourceLine: 2)]
        let mixed = router(profile)
        for type in kinds { try refusal(mixed, name: "blocked.example.test", type: type) }
        let flow = try mixed.makeDNSDatagram(original: target, queue: .global(),
                                            receive: { _ in }, failure: { _ in })
        flow.cancel()
        for type in [UInt16(15), 16, 64, 65, 255] {
            let decision = try plan(mixed, type: type)
            try expect(decision.route == .native(node, node.name), "fake-IP 非 A/AAAA 查询绕过代理")
        }
        profile.alwaysRealIP = ["*.example.test"]
        let real = try plan(router(profile))
        try expect(real.route == .native(node, node.name), "fake-IP filter 将真实查询降级 DIRECT")

        // Denies are checked even in global-proxy mode, including original
        // address, QNAME, actual bootstrap address and resolver identity.
        profile.fakeIPEnabled = false; profile.alwaysRealIP = []
        for rule in [RuleKind.ipCIDR("203.0.113.53/32"), .domain("blocked.example.test"),
                     .ipCIDR("1.1.1.1/32"), .domain("cloudflare-dns.com")] {
            profile.rules = [RoutingRule(kind: rule, policy: "REJECT", sourceLine: 1),
                             RoutingRule(kind: .final, policy: node.name, sourceLine: 2)]
            let rejected = router(profile, mode: .proxy)
            for type in kinds { try refusal(rejected, name: "blocked.example.test", type: type) }
        }

        profile.rules = [RoutingRule(kind: .logicalAnd([.domain("logical.example.test"),
            .destinationPort(53...53), .protocolName("UDP"), .sourceIPCIDR("127.0.0.0/8"), .inboundPort(7263...7263)]),
            policy: node.name, sourceLine: 1), RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2)]
        let source = RequestTarget(host: target.host, port: 53, protocolName: "UDP",
                                   sourceHost: "127.0.0.1", sourcePort: 12345, inboundPort: 7263)
        let logical = try plan(router(profile), name: "logical.example.test", original: source)
        try expect(logical.route == .native(node, node.name) && logical.original == source,
                   "逻辑 QNAME 规则丢失原目的、协议或入站元数据")
        var tcp = source; tcp.protocolName = "TCP"
        let tcpDecision = try plan(router(profile), name: "logical.example.test", original: tcp)
        try expect(tcpDecision.route == .direct("DIRECT") && tcpDecision.original.protocolName == "TCP",
                   "TCP 查询被错误标记为 UDP")

        for invalid in ["https://unknown.invalid/dns-query", "https://dns.google", "tls://unknown.invalid",
                        "http://1.1.1.1/dns-query", "udp://1.1.1.1:0", "1.1.1.1:garbage"] {
            profile.dnsServers = [invalid]
            do { _ = try plan(router(profile)) }
            catch DNSPolicyFailure.configuration { continue }
            throw Failure(text: "坏 DNS 配置静默回退：\(invalid)")
        }

        profile.dnsServers = []; profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        let changed = router(profile)
        let old = try plan(changed)
        profile.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)]
        changed.update(profile: profile, mode: .rule, globalPolicy: node.name, groupSelections: [:])
        try expect(!changed.isCurrentDNSGeneration(old.generation), "策略切换没有撤销旧 DNS generation")
        try refusal(changed, name: "allowed.example.test", type: 65)
    }

    private static func dnsPurposeIsolation() throws {
        var profile = Profile()
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                               adapterType: "trojan", parameters: ["password": "test"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        profile.dnsServers = ["malformed-traditional:bad", "system", "198.18.16.2"]
        profile.encryptedDNSServers = ["https://203.0.113.77/dns-query"]
        for protection in [true, false] {
            profile.dnsLeakProtectionEnabled = protection
            for type: UInt16 in [1, 16, 28, 65] {
                let decision = try plan(router(profile), type: type)
                try expect(decision.upstream.encrypted && decision.upstream.target.host == "203.0.113.77"
                           && decision.bootstrap == nil, "已固定加密 DNS 被无关传统配置阻断或降级")
            }
        }
        profile.encryptedDNSServers = []
        profile.dnsServers = ["203.0.113.60", "https://203.0.113.77/dns-query"]
        try expect(try plan(router(profile)).upstream.encrypted, "旧混合 dns-server 中的加密条目被降级传统")
        for invalid in ["not-an-encrypted-url", "http://203.0.113.77/dns-query",
                        "https://dns.google", "https://dns.google/dns-query#hostname.invalid"] {
            profile.encryptedDNSServers = [invalid]
            do { _ = try plan(router(profile)) }
            catch DNSPolicyFailure.configuration { continue }
            throw Failure(text: "无效 encrypted-dns-server 回退旧传统/加密条目")
        }
        profile.encryptedDNSServers = ["https://doh.bootstrap.selftest.invalid/dns-query"]
        profile.dnsServers = []
        do { _ = try plan(router(profile)) }
        catch DNSPolicyFailure.configuration { profile.dnsServers = ["203.0.113.60:5353"] }
        guard !profile.dnsServers.isEmpty else { throw Failure(text: "未固定未知 DoH 无传统引导仍被接受") }
        let deferred = try plan(router(profile))
        guard case .doh(let endpoint) = deferred.upstream else { throw Failure(text: "延后引导丢失 DoH 类型") }
        try expect(endpoint.needsBootstrap && deferred.bootstrap?.allowedHosts == [endpoint.host],
                   "未知 DoH 未进入专用白名单引导路径")
        for invalid in ["system", "hostname.invalid", "198.18.16.2", "198.19.0.1", "[::ffff:198.18.16.2]"] {
            profile.dnsServers = [invalid]
            do { _ = try plan(router(profile)) }
            catch DNSPolicyFailure.configuration { continue }
            throw Failure(text: "DoH 引导接受系统、非数字或递归传统 DNS 地址")
        }
        profile.dnsServers = ["203.0.113.60:5353"]
        for deny in [RuleKind.ipCIDR("203.0.113.60/32"), .domain(endpoint.host)] {
            profile.rules = [RoutingRule(kind: deny, policy: "REJECT", sourceLine: 1),
                             RoutingRule(kind: .final, policy: node.name, sourceLine: 2)]
            try refusal(router(profile, mode: .proxy), name: "private.user.example.test", type: 65)
        }
        profile.rules = [RoutingRule(kind: .ipCIDR("203.0.113.77/32"), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .final, policy: node.name, sourceLine: 2)]
        let deniedIP = router(profile, mode: .proxy), decision = try plan(deniedIP)
        do { _ = try deniedIP.resolvedBootstrapPlan(decision, address: "203.0.113.77") }
        catch DNSPolicyFailure.refused { return }
        throw Failure(text: "DoH 域名被允许后绕过新引导 IP 的 REJECT")
    }

    private static func directHostnameDNSConfiguration() throws {
        var profile = Profile()
        profile.dnsLeakProtectionEnabled = false
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        profile.dnsServers = ["203.0.113.60"]
        try expect(!DNSApplicationResolutionPolicy.usesQueryRouter(profile),
                   "无加密 DNS 的 legacy opt-out 改变应用 DIRECT 解析路径")
        profile.encryptedDNSServers = ["https://203.0.113.77/dns-query"]
        try expect(DNSApplicationResolutionPolicy.usesQueryRouter(profile) && !profile.shouldHijackSystemDNS,
                   "显式加密 DNS 未用于 DIRECT 名称或意外打开系统 DNS 拦截")
        let configured = try plan(router(profile), name: "direct.application.selftest.invalid")
        try expect(configured.route == .direct("DIRECT") && configured.upstream.encrypted
                   && configured.upstream.target.host == "203.0.113.77",
                   "应用 DIRECT 查询丢失指定加密 DNS 或使用默认解析器")
        profile.encryptedDNSServers = []
        profile.dnsServers.append("https://203.0.113.77/dns-query")
        let legacy = try plan(router(profile))
        try expect(DNSApplicationResolutionPolicy.usesQueryRouter(profile)
                   && legacy.upstream.target.host == "203.0.113.77",
                   "旧混合 DNS 中的显式加密选项未用于 DIRECT 名称")
        profile.encryptedDNSServers = ["malformed-encrypted-endpoint"]
        try expect(DNSApplicationResolutionPolicy.usesQueryRouter(profile),
                   "坏加密配置允许 DIRECT 名称绕过自定义查询路由")
        do { _ = try plan(router(profile)) }
        catch DNSPolicyFailure.configuration {
            profile.encryptedDNSServers = []; profile.dnsServers = []
            try expect(!DNSApplicationResolutionPolicy.usesQueryRouter(profile),
                       "空加密配置改变显式关闭保护的应用兼容行为")
            profile.dnsLeakProtectionEnabled = true
            try expect(DNSApplicationResolutionPolicy.usesQueryRouter(profile),
                       "默认保护未通过应用查询路由解析 DIRECT 名称")
            return
        }
        throw Failure(text: "坏加密配置的 DIRECT 查询回退其它 DNS")
    }

    private final class AddressResolutionProbe {
        let lock = NSLock(), done = DispatchSemaphore(value: 0)
        private let started = NetworkPerformanceDiagnostics.now()
        private var queries: [UInt16] = [], callbacks = 0, cancellations = 0
        private var addresses: [String] = []
        private var error: Error?
        private var elapsed: Double = 0
        func sent(_ type: UInt16) { lock.lock(); queries.append(type); lock.unlock() }
        func cancelled() { lock.lock(); cancellations += 1; lock.unlock() }
        func completed(_ result: Result<[String], Error>) {
            lock.lock(); callbacks += 1
            elapsed = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started)
            switch result { case .success(let value): addresses = value; case .failure(let value): error = value }
            lock.unlock(); done.signal()
        }
        var snapshot: (queries: [UInt16], callbacks: Int, cancellations: Int,
                       addresses: [String], error: Error?, elapsed: Double) {
            lock.lock(); defer { lock.unlock() }
            return (queries, callbacks, cancellations, addresses, error, elapsed)
        }
    }

    /// Only internal DIRECT discovery may shorten the wait for the other
    /// family. These fixtures cannot dial: both questions use an injected
    /// memory datagram, with deliberately late replies after cancellation.
    private static func directAddressResolutionGrace() throws {
        enum Reply { case address, nodata, servfail, refused, fake, mismatch }
        typealias Scheduled = (delay: TimeInterval, reply: Reply)
        var initialProfile = Profile()
        initialProfile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let profile = initialProfile
        let deliveries = DispatchGroup()
        var completed: [AddressResolutionProbe] = []
        let ipv4 = "203.0.113.77", ipv6 = "2001:db8::77"
        let sourceTarget = RequestTarget(host: "direct.address.selftest.invalid", port: 443,
            protocolName: "TCP", sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7262)

        func run(_ label: String, replies: [UInt16: Scheduled], timeout: TimeInterval = 0.7,
                 cancelAfter: TimeInterval? = nil, invalidateAfter: TimeInterval? = nil,
                 interfaceChangeAfter: TimeInterval? = nil) throws -> AddressResolutionProbe {
            let source = router(profile), generation = try plan(source).generation
            let interfaceGate = AdaptivePolicyGate(), probe = AddressResolutionProbe()
            let queue = DispatchQueue(label: "app.hajimi.dns.address-grace-self-test." + label)
            let operation = DNSAddressResolution(queue: queue, permitted: {
                source.isCurrentDNSGeneration(generation) && interfaceGate.permits()
            }, totalTimeout: timeout, datagramFactory: { original, worker, receive, _ in
                try expect(original.host == protectedSystemDNSGateway && original.port == 53
                           && original.protocolName == "UDP" && original.sourceHost == sourceTarget.sourceHost
                           && original.sourcePort == sourceTarget.sourcePort
                           && original.inboundPort == sourceTarget.inboundPort,
                           "DIRECT 解析丢失 DNS 原目的或来源元数据")
                return AdaptiveMemoryTransport(send: { query in
                    guard let question = DNSMessageInspection.singleQuestion(in: query) else { return }
                    probe.sent(question.type)
                    guard let selected = replies[question.type] else { return }
                    var answer = Data(query.prefix(question.questionEnd))
                    answer[2] = 0x81; answer[3] = 0x80
                    switch selected.reply {
                    case .address, .fake:
                        answer[7] = 1
                        let bytes: [UInt8]
                        if question.type == 1 {
                            bytes = selected.reply == .fake ? [198, 19, 0, 77] : [203, 0, 113, 77]
                        } else {
                            bytes = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77]
                        }
                        answer.append(contentsOf: [0xc0, 0x0c, 0, UInt8(question.type), 0, 1,
                            0, 0, 0, 60, 0, UInt8(bytes.count)])
                        answer.append(contentsOf: bytes)
                    case .nodata: break
                    case .servfail: answer[3] = 0x82
                    case .refused: answer[3] = 0x85
                    case .mismatch:
                        if let wrong = DNSMessageInspection.query(for: "wrong.address.selftest.invalid",
                            type: question.type, id: UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1])) {
                            answer = wrong; answer[2] = 0x81; answer[3] = 0x80; answer[7] = 1
                            answer.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1,
                                0, 0, 0, 60, 0, 4, 203, 0, 113, 77])
                        }
                    }
                    let response = answer
                    deliveries.enter()
                    worker.asyncAfter(deadline: .now() + selected.delay) {
                        receive(response); deliveries.leave()
                    }
                }, cancel: probe.cancelled)
            }, completion: probe.completed)
            operation.start(router: source, host: sourceTarget.host, sourceTarget: sourceTarget)
            if let delay = cancelAfter { queue.asyncAfter(deadline: .now() + delay) { operation.cancel() } }
            if let delay = invalidateAfter {
                queue.asyncAfter(deadline: .now() + delay) {
                    var denied = profile
                    denied.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)]
                    source.update(profile: denied, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
                }
            }
            if let delay = interfaceChangeAfter {
                queue.asyncAfter(deadline: .now() + delay) { interfaceGate.revoke() }
            }
            try expect(probe.done.wait(timeout: .now() + 2) == .success, "DIRECT 解析场景没有完成：\(label)")
            queue.sync {}
            let state = probe.snapshot
            try expect(state.queries.sorted() == [1, 28] && state.callbacks == 1 && state.cancellations == 1,
                       "DIRECT 解析没有发送两族、未释放 datagram 或重复完成：\(label)")
            completed.append(probe); withExtendedLifetime(operation) {}
            return probe
        }
        func success(_ probe: AddressResolutionProbe, _ addresses: [String], _ text: String) throws {
            let state = probe.snapshot
            try expect(state.error == nil && Set(state.addresses) == Set(addresses), text)
        }
        let fastA: Scheduled = (0.005, .address)
        let blackhole = try run("A-valid-AAAA-silent", replies: [1: fastA])
        try success(blackhole, [ipv4], "AAAA 沉默使已经有效的 A 超时或丢失")
        try expect(blackhole.snapshot.elapsed < 500, "有效 IPv4 仍等到了完整 DNS 超时")
        for reply: Reply in [.nodata, .servfail, .refused, .address] {
            let late = try run("A-valid-AAAA-late-\(reply)", replies: [1: fastA, 28: (0.4, reply)])
            try success(late, [ipv4], "慢 AAAA 拖住有效 IPv4 或迟到回复改变已完成结果")
            try expect(late.snapshot.elapsed < 300, "DIRECT A 首答未在有限 grace 后完成")
        }
        let both = try run("both-fast", replies: [1: fastA, 28: (0.01, .address)])
        try success(both, [ipv4, ipv6], "grace 丢弃及时到达的另一族地址")
        let v6First = try run("IPv6-first-IPv4-late", replies: [28: fastA, 1: (0.18, .address)])
        try success(v6First, [ipv4, ipv6], "IPv6 首答过早结束导致 IPv4 fallback 丢失")
        try expect(v6First.snapshot.elapsed >= 150, "IPv6-only 首答裁掉仍待返回的 IPv4")
        let v6AtDeadline = try run("IPv6-valid-A-silent", replies: [28: fastA], timeout: 0.12)
        try success(v6AtDeadline, [ipv6], "总截止丢弃已经获得的有效 IPv6")
        try expect(v6AtDeadline.snapshot.elapsed >= 100, "IPv6 首答未等原有 A 截止")
        let aNoData = try run("A-empty-AAAA-valid", replies: [1: (0.005, .nodata), 28: (0.03, .address)])
        try success(aNoData, [ipv6], "A NODATA 误拒绝已有效的 IPv6")
        for (label, replies) in [
            ("both-empty", [UInt16(1): (0.005, Reply.nodata), 28: (0.01, .nodata)]),
            ("both-failed", [UInt16(1): (0.005, Reply.servfail), 28: (0.01, .refused)]),
            ("fake-address", [UInt16(1): (0.005, Reply.fake), 28: (0.01, .nodata)]),
            ("wrong-question", [UInt16(1): (0.005, Reply.mismatch), 28: (0.01, .nodata)])
        ] {
            let result = try run(label, replies: replies, timeout: 0.12).snapshot
            try expect(result.error != nil && result.addresses.isEmpty,
                       "空/失败/伪造 DNS 首答没有 fail closed：\(label)")
        }
        let cancel = try run("cancel-after-A", replies: [1: fastA, 28: (0.1, .address)], cancelAfter: 0.02)
        let revoke = try run("policy-update-after-A", replies: [1: fastA, 28: (0.1, .address)], invalidateAfter: 0.02)
        let rebound = try run("interface-change-after-A", replies: [1: fastA, 28: (0.1, .address)], interfaceChangeAfter: 0.02)
        for result in [cancel.snapshot, revoke.snapshot, rebound.snapshot] {
            try expect(result.error != nil && result.addresses.isEmpty, "取消或策略/接口更新仍送出旧地址")
        }
        try expect(deliveries.wait(timeout: .now() + 1) == .success, "迟到的 DIRECT 回包没有排空")
        try expect(completed.allSatisfy { $0.snapshot.callbacks == 1 }, "取消后的迟到回包触发第二次完成")
    }

    private final class AdaptiveProbe {
        let lock = NSLock(), done = DispatchSemaphore(value: 0)
        let started = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
        let late = DispatchSemaphore(value: 0)
        var attempts: [String] = [], answers: [Data] = []
        var activeAttempts = 0, peakActiveAttempts = 0, cancelledAttempts = 0
        var error: Error?
        func attempted(_ candidate: DNSUpstreamCandidate) {
            lock.lock(); attempts.append(candidate.upstream.target.host)
            activeAttempts += 1; peakActiveAttempts = max(peakActiveAttempts, activeAttempts)
            lock.unlock(); started.signal()
        }
        func transportCancelled() {
            lock.lock(); activeAttempts = max(0, activeAttempts - 1); cancelledAttempts += 1; lock.unlock()
            cancelled.signal()
        }
        func received(_ data: Data) { lock.lock(); answers.append(data); lock.unlock(); done.signal() }
        func failed(_ error: Error) { lock.lock(); self.error = error; lock.unlock(); done.signal() }
        var snapshot: (attempts: [String], answers: [Data], error: Error?) {
            lock.lock(); defer { lock.unlock() }; return (attempts, answers, error)
        }
        var concurrency: (active: Int, peak: Int, cancelled: Int) {
            lock.lock(); defer { lock.unlock() }; return (activeAttempts, peakActiveAttempts, cancelledAttempts)
        }
    }
    private final class AdaptiveManualClock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func advance(to elapsed: TimeInterval) {
            lock.lock(); defer { lock.unlock() }
            precondition(100 + elapsed >= value); value = 100 + elapsed
        }
    }
    private final class AdaptiveManualReply {
        private let lock = NSLock()
        private var reply: (() -> Void)?
        private var cancelled = false
        func prepare(_ reply: @escaping () -> Void) { lock.lock(); self.reply = reply; lock.unlock() }
        func recordCancellation() { lock.lock(); cancelled = true; lock.unlock() }
        var wasCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
        func release() -> Bool {
            lock.lock(); let reply = self.reply; self.reply = nil; lock.unlock()
            guard let reply else { return false }; reply(); return true
        }
    }
    private final class AdaptiveMemoryTransport: NativeRoutedDatagram {
        let onSend: (Data) -> Void, onCancel: () -> Void
        init(send: @escaping (Data) -> Void, cancel: @escaping () -> Void = {}) {
            onSend = send; onCancel = cancel
        }
        func send(_ data: Data) { onSend(data) }
        func cancel() { onCancel() }
    }
    private final class AdaptiveAcknowledgedMemoryTransport: NativeRoutedDatagram, DNSQueryCancellationAcknowledging {
        private let lock = NSLock()
        private var closed = false
        private let onSend: (Data) -> Void, onCancel: () -> Void
        init(send: @escaping (Data) -> Void, cancel: @escaping () -> Void = {}) {
            onSend = send; onCancel = cancel
        }
        func send(_ data: Data) {
            lock.lock(); let stopped = closed; lock.unlock()
            if !stopped { onSend(data) }
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); let first = !closed; closed = true; lock.unlock()
            if first { onCancel() }
            completion()
        }
    }
    private static func adaptiveProfile() -> Profile {
        var profile = Profile()
        profile.dnsServers = ["203.0.113.60"]
        profile.encryptedDNSServers = ["https://primary.adaptive.selftest.invalid/dns-query#203.0.113.70",
                                       "https://secondary.adaptive.selftest.invalid/dns-query#203.0.113.71"]
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        return profile
    }
    private static func adaptiveExchange(_ routed: NativePacketRouter, plan: DNSQueryPlan, message: Data,
        probe: AdaptiveProbe, timeout: TimeInterval = 1, factory: @escaping DNSAdaptiveQueryDatagram.Factory)
        throws -> NativeRoutedDatagram {
        let flow = try routed.makeOptimizedDNSUpstream(plan: plan,
            queue: DispatchQueue(label: "app.hajimi.dns.adaptive-self-test"),
            adaptiveFactory: factory, adaptiveTimeout: timeout,
            receive: probe.received, failure: probe.failed)
        flow.send(message); return flow
    }
    private static func awaitAdaptive(_ probe: AdaptiveProbe, query: Data, expectFailure: Bool = false,
                                      waitTimeout: TimeInterval = 3) throws {
        try expect(probe.done.wait(timeout: .now() + waitTimeout) == .success, "自适应 DNS 内存交换没有完成")
        let result = probe.snapshot
        if expectFailure { try expect(result.error != nil && result.answers.isEmpty, "失效交换仍返回应用答案"); return }
        if let error = result.error {
            let name = DNSMessageInspection.singleQuestion(in: query)?.name ?? "unknown-self-test-question"
            print("DNS adaptive memory self-test failed: question=\(name), error_type=\(String(reflecting: type(of: error))), attempts=\(result.attempts.count)")
            throw error
        }
        try expect(result.answers.count == 1 && DNSMessageInspection.responseMatchesQuery(result.answers[0], query: query),
                   "自适应 DNS 返回错误问题、ID 或重复回包")
    }
    private static func adaptiveCandidatePolicy() throws {
        let base = adaptiveProfile(), source = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")
        let originalSet = try plan(router(base), original: source)
        for (blocked, allowed) in [("203.0.113.71", "203.0.113.70"), ("203.0.113.70", "203.0.113.71")] {
            var profile = base
            profile.rules.insert(RoutingRule(kind: .ipCIDR(blocked + "/32"), policy: "REJECT", sourceLine: 0), at: 0)
            let routed = router(profile), decision = try plan(routed, original: source), probe = AdaptiveProbe()
            try expect(decision.candidates.count == 1 && decision.upstream.target.host == allowed
                       && decision.scopeKey != originalSet.scopeKey, "被拒绝候选未剔除或批准集合没有进入缓存 scope")
            let message = try query("allowed.example.test", 1)
            let flow = try adaptiveExchange(routed, plan: decision, message: message, probe: probe) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    probe.attempted(candidate)
                    if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts == [allowed], "REJECT 解析器仍被拨号或作为网络失败绕过")
        }
        var denied = base
        denied.rules.insert(RoutingRule(kind: .logicalOr([.ipCIDR("203.0.113.70/32"), .ipCIDR("203.0.113.71/32")]),
                                       policy: "REJECT", sourceLine: 0), at: 0)
        try refusal(router(denied), name: "allowed.example.test", type: 1)
        denied = base
        denied.rules.insert(RoutingRule(kind: .domain("blocked.example.test"), policy: "REJECT", sourceLine: 0), at: 0)
        try refusal(router(denied), name: "blocked.example.test", type: 1)
        denied = base
        denied.rules.insert(RoutingRule(kind: .ipCIDR("203.0.113.53/32"), policy: "REJECT", sourceLine: 0), at: 0)
        try refusal(router(denied), name: "allowed.example.test", type: 1, original: source)
    }
    private static func adaptiveBuiltinAddressVariants() throws {
        var profile = Profile()
        profile.dnsServers = ["203.0.113.60"]
        profile.encryptedDNSServers = ["https://doh.pub/dns-query", "https://dns.quad9.net/dns-query"]
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let ips = ["1.12.12.12", "9.9.9.9", "120.53.53.53", "149.112.112.112"]
        let names = ["doh.pub", "dns.quad9.net", "doh.pub", "dns.quad9.net"]
        let full = try plan(router(profile))
        try expect(full.candidates.map { $0.upstream.target.host } == ips
                   && full.candidates.map { $0.upstream.identityHost } == names
                   && full.candidates.allSatisfy({ $0.upstream.encrypted && $0.bootstrap == nil }),
                   "内置备用未按提供商波次排列或改变身份/变成传统 DNS")
        for candidate in full.candidates {
            guard case .doh(let endpoint) = candidate.upstream else { throw Failure(text: "DoH variant 丢失类型") }
            try expect(endpoint.url.absoluteString == "https://\(endpoint.host)/dns-query", "备用 IP 改变配置的 URL")
        }
        for blocked in ips {
            var denied = profile
            denied.rules.insert(RoutingRule(kind: .ipCIDR(blocked + "/32"), policy: "REJECT", sourceLine: 0), at: 0)
            let source = router(denied), approved = try plan(source), probe = AdaptiveProbe()
            try expect(approved.candidates.map { $0.upstream.target.host } == ips.filter { $0 != blocked }
                       && approved.scopeKey != full.scopeKey, "备用 IP 未逐一 REJECT 预检或批准集合未隔离 scope")
            let message = try query("adaptive-variant-policy.example.test", 1)
            let flow = try adaptiveExchange(source, plan: approved, message: message, probe: probe) { candidate, queue, receive, _ in
                try expect(candidate.upstream.target.host != blocked, "REJECT 的备用 IP 仍进入 factory")
                return AdaptiveMemoryTransport(send: { data in
                    probe.attempted(candidate)
                    if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
            defer { flow.cancel() }; try awaitAdaptive(probe, query: message)
        }
        var deniedIdentity = profile
        deniedIdentity.rules.insert(RoutingRule(kind: .domain("doh.pub"), policy: "REJECT", sourceLine: 0), at: 0)
        let allowed = try plan(router(deniedIdentity))
        try expect(allowed.candidates.map { $0.upstream.target.host } == ["9.9.9.9", "149.112.112.112"]
                   && allowed.scopeKey != full.scopeKey, "同 provider 备用绕过 TLS 身份域名拒绝")
        var explicit = profile
        explicit.encryptedDNSServers = ["https://doh.pub/dns-query#1.12.12.12",
                                        "https://dns.quad9.net/dns-query#149.112.112.112"]
        let pinned = try plan(router(explicit))
        try expect(pinned.candidates.map { $0.upstream.target.host } == ["1.12.12.12", "149.112.112.112"]
                   && pinned.scopeKey != full.scopeKey, "显式 #pin 扩展到备用或与自动集合共享 scope")
        var mixed = profile
        mixed.encryptedDNSServers = ["tls://dot.pub", "https://doh.pub/dns-query"]
        try expect((try plan(router(mixed))).candidates.map { $0.upstream.identityHost } == ["doh.pub", "dot.pub", "doh.pub"],
                   "波次扩展改变 DoH-first 顺序或扩展未授权的 DoT 地址")
        var maximum = profile
        maximum.encryptedDNSServers = (0..<16).map { "https://doh.pub/dns-query?slot=\($0)" }
        try expect((try plan(router(maximum))).candidates.count == 32, "16 合法配置的有限 32 地址集合被截断")
        maximum.encryptedDNSServers.append("https://doh.pub/dns-query?slot=16")
        do { _ = try plan(router(maximum)); throw Failure(text: "超过 16 个配置仍获批准") }
        catch DNSPolicyFailure.configuration { }

        // Keep first IP alive while the other provider fails; its approved
        // same-provider backup occupies the newly available second live slot.
        let source = router(profile), probe = AdaptiveProbe()
        let message = try query("adaptive-builtin-backup.example.test", 1)
        let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-builtin-backup.example.test"),
            message: message, probe: probe, timeout: 2) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    probe.attempted(candidate)
                    switch candidate.upstream.target.host {
                    case "1.12.12.12": break
                    case "120.53.53.53":
                        if let reply = bootstrapAnswer(data) { queue.asyncAfter(deadline: .now() + 0.55) { receive(reply) } }
                    default:
                        if let failed = DNSMessageInspection.errorResponse(to: data, code: .servfail) { queue.async { receive(failed) } }
                    }
                }, cancel: probe.transportCancelled)
            }
        defer { flow.cancel() }; try awaitAdaptive(probe, query: message)
        try expect(probe.snapshot.attempts == Array(ips.prefix(3)) && probe.concurrency.peak == 2
                   && probe.concurrency.active == 0 && probe.concurrency.cancelled == 3,
                   "内置备用未补位或突破 2 活跃/3 尝试预算")
        let nextProbe = AdaptiveProbe(), fresh = try query("adaptive-builtin-preferred.example.test", 1)
        let nextFlow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-builtin-preferred.example.test"),
            message: fresh, probe: nextProbe, timeout: 2) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    nextProbe.attempted(candidate)
                    if candidate.upstream.target.host == "120.53.53.53", let reply = bootstrapAnswer(data) {
                        queue.asyncAfter(deadline: .now() + 0.55) { receive(reply) }
                    } else if let failed = DNSMessageInspection.errorResponse(to: data, code: .servfail) { queue.async { receive(failed) } }
                }, cancel: nextProbe.transportCancelled)
            }
        defer { nextFlow.cancel() }; try awaitAdaptive(nextProbe, query: fresh)
        try expect(!nextProbe.snapshot.attempts.contains("1.12.12.12") && nextProbe.snapshot.attempts.last == "120.53.53.53",
                   "winner 取消的慢 primary 仍以未知 500ms 抢过健康备用")
    }

    private static func adaptiveEncryptedExchanges() throws {
        let profile = adaptiveProfile(), routed = router(profile)
        let firstQuery = try query("adaptive-first.example.test", 1), firstPlan = try plan(routed, name: "adaptive-first.example.test")
        let first = AdaptiveProbe()
        let failedPrimary = try adaptiveExchange(routed, plan: firstPlan, message: firstQuery, probe: first) {
            candidate, queue, receive, failure in
            let expectedIdentity = candidate.upstream.target.host == "203.0.113.70"
                ? "primary.adaptive.selftest.invalid" : "secondary.adaptive.selftest.invalid"
            try expect(candidate.upstream.identityHost == expectedIdentity && candidate.upstream.encrypted,
                       "failover 改变原 TLS 身份或候选变成传统 DNS")
            return AdaptiveMemoryTransport(send: { data in
                first.attempted(candidate)
                if candidate.upstream.target.host == "203.0.113.70" { queue.async { failure(EngineError("内存 TLS 失败")) } }
                else if let answer = bootstrapAnswer(data) { queue.async { receive(answer) } }
            })
        }
        defer { failedPrimary.cancel() }
        try awaitAdaptive(first, query: firstQuery)
        try expect(first.snapshot.attempts == ["203.0.113.70", "203.0.113.71"], "网络失败未切换至批准的加密备用")
        let secondQuery = try query("adaptive-next.example.test", 1), second = AdaptiveProbe()
        let secondFlow = try adaptiveExchange(routed, plan: plan(routed, name: "adaptive-next.example.test"),
            message: secondQuery, probe: second) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    second.attempted(candidate)
                    if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
        defer { secondFlow.cancel() }
        try awaitAdaptive(second, query: secondQuery)
        try expect(second.snapshot.attempts == ["203.0.113.71"] && secondFlow is DNSCoalescedQueryDatagram,
                   "故障后择优没有避开失败端点或绕过了 single-flight")

        let throwingSource = router(profile), throwingProbe = AdaptiveProbe()
        let throwingQuery = try query("adaptive-factory-throw.example.test", 1)
        let beforeAttempts = NetworkPerformanceDiagnostics.shared.snapshot()
        let throwingFlow = try adaptiveExchange(throwingSource,
            plan: plan(throwingSource, name: "adaptive-factory-throw.example.test"),
            message: throwingQuery, probe: throwingProbe) { candidate, queue, receive, _ in
                throwingProbe.attempted(candidate)
                if candidate.upstream.target.host == "203.0.113.70" { throw EngineError("内存拨号 factory 立即失败") }
                return AdaptiveMemoryTransport(send: { data in
                    if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
        defer { throwingFlow.cancel() }
        try awaitAdaptive(throwingProbe, query: throwingQuery)
        let afterAttempts = NetworkPerformanceDiagnostics.shared.snapshot()
        try expect(throwingProbe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                   && afterAttempts.dnsUpstreamAttempts == beforeAttempts.dnsUpstreamAttempts + 2
                   && afterAttempts.dnsFailovers == beforeAttempts.dnsFailovers + 1,
                   "立即 factory 网络错误没有进入逻辑尝试/failover 计数")
        let cachedProbe = AdaptiveProbe()
        let cachedFlow = try adaptiveExchange(throwingSource,
            plan: plan(throwingSource, name: "adaptive-factory-throw.example.test"),
            message: throwingQuery, probe: cachedProbe) { _, _, _, _ in
                throw Failure(text: "缓存命中仍启动上游 factory")
            }
        defer { cachedFlow.cancel() }
        try awaitAdaptive(cachedProbe, query: throwingQuery)
        let afterCached = NetworkPerformanceDiagnostics.shared.snapshot()
        try expect(afterCached.dnsUpstreamAttempts == afterAttempts.dnsUpstreamAttempts
                   && afterCached.dnsFailovers == afterAttempts.dnsFailovers,
                   "cache hit 重复增加上游尝试或故障切换计数")

        for code: UInt8 in [3, 5] {
            let source = router(profile), message = try query("adaptive-terminal.example.test", 1), probe = AdaptiveProbe()
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-terminal.example.test"),
                message: message, probe: probe) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if var reply = DNSMessageInspection.errorResponse(to: data, code: .refused) {
                            reply[3] = (reply[3] & 0xf0) | code
                            let answer = reply; queue.async { receive(answer) }
                        }
                    })
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts == ["203.0.113.70"] && probe.snapshot.answers[0][3] & 0x0f == code,
                       "NXDOMAIN/REFUSED 被跨供应商重试")
        }

        // An upstream REFUSED and a late local policy denial are both terminal.
        for localPolicy in [false, true] {
            let source = router(profile), message = try query("adaptive-refused.example.test", 1), probe = AdaptiveProbe()
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-refused.example.test"),
                message: message, probe: probe) { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        queue.async {
                            if localPolicy { failure(DNSPolicyFailure.refused("返回的解析器 IP 被拒绝")) }
                            else if let reply = DNSMessageInspection.errorResponse(to: data, code: .refused) { receive(reply) }
                        }
                    })
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts == ["203.0.113.70"] && probe.snapshot.answers[0][3] & 0x0f == 5,
                       "REFUSED 被当网络失败改走备用解析器")
        }

        var dotProfile = profile
        dotProfile.encryptedDNSServers[1] = "tls://secondary.adaptive.selftest.invalid#203.0.113.71"
        let dotSource = router(dotProfile), dotProbe = AdaptiveProbe(), dotQuery = try query("adaptive-dot.example.test", 1)
        let dotFlow = try adaptiveExchange(dotSource, plan: plan(dotSource, name: "adaptive-dot.example.test"),
            message: dotQuery, probe: dotProbe) { candidate, queue, receive, failure in
                if candidate.upstream.target.host == "203.0.113.71" {
                    guard case .dot = candidate.upstream else { throw Failure(text: "DoH 故障没有保留配置的 DoT 类型") }
                    try expect(candidate.upstream.identityHost == "secondary.adaptive.selftest.invalid", "DoT TLS 身份改变")
                }
                return AdaptiveMemoryTransport(send: { data in
                    dotProbe.attempted(candidate)
                    if candidate.upstream.target.host == "203.0.113.70" { queue.async { failure(EngineError("内存 DoH 失败")) } }
                    else if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
        defer { dotFlow.cancel() }
        try awaitAdaptive(dotProbe, query: dotQuery)
        try expect(dotProbe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"], "DoH→已批准 DoT 故障切换失败")

        var exhaustedProfile = profile
        exhaustedProfile.encryptedDNSServers += ["https://third.adaptive.selftest.invalid/dns-query#203.0.113.72",
                                                 "https://fourth.adaptive.selftest.invalid/dns-query#203.0.113.73"]
        let exhaustedSource = router(exhaustedProfile), exhausted = AdaptiveProbe(), exhaustedQuery = try query("adaptive-exhausted.example.test", 1)
        let exhaustedFlow = try adaptiveExchange(exhaustedSource, plan: plan(exhaustedSource, name: "adaptive-exhausted.example.test"),
            message: exhaustedQuery, probe: exhausted) { candidate, queue, _, failure in
                AdaptiveMemoryTransport(send: { _ in
                    exhausted.attempted(candidate); queue.async { failure(EngineError("内存加密端点全失败")) }
                })
            }
        defer { exhaustedFlow.cancel() }
        try awaitAdaptive(exhausted, query: exhaustedQuery, expectFailure: true)
        try expect(exhausted.snapshot.attempts == ["203.0.113.70", "203.0.113.71", "203.0.113.72"],
                   "单问题超过三次尝试或加密失败回退传统 DNS")

        let timedSource = router(profile), timedQuery = try query("adaptive-timeout.example.test", 1), timed = AdaptiveProbe()
        let timedFlow = try adaptiveExchange(timedSource, plan: plan(timedSource, name: "adaptive-timeout.example.test"),
            message: timedQuery, probe: timed, timeout: 0.4) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    timed.attempted(candidate)
                    guard let reply = bootstrapAnswer(data) else { return }
                    if candidate.upstream.target.host == "203.0.113.70" {
                        queue.asyncAfter(deadline: .now() + 0.3) { receive(reply); timed.late.signal() }
                    } else { queue.async { receive(reply) } }
                }, cancel: { timed.cancelled.signal() })
            }
        defer { timedFlow.cancel() }
        try awaitAdaptive(timed, query: timedQuery)
        try expect(timed.late.wait(timeout: .now() + 2) == .success
                   && timed.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                   && timed.snapshot.answers.count == 1, "超时/迟到回包复活旧尝试或产生重复应答")

        for flush in [true, false] {
            let source = router(profile), message = try query("adaptive-epoch.example.test", 1), probe = AdaptiveProbe()
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-epoch.example.test"),
                message: message, probe: probe) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if let reply = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 0.1) { receive(reply); probe.late.signal() }
                        }
                    }, cancel: { probe.cancelled.signal() })
                }
            defer { flow.cancel() }
            try expect(probe.started.wait(timeout: .now() + 2) == .success, "待撤销 adaptive 交换未开始")
            if flush { source.flushDNS() }
            else { source.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:]) }
            try awaitAdaptive(probe, query: message, expectFailure: true)
            try expect(probe.cancelled.wait(timeout: .now() + 2) == .success
                       && probe.late.wait(timeout: .now() + 2) == .success
                       && probe.snapshot.attempts == ["203.0.113.70"], "flush/代次更新后旧尝试仍切换或未取消")
        }
        let cancelledSource = router(profile), cancelled = AdaptiveProbe(), message = try query("adaptive-cancel.example.test", 1)
        let flow = try adaptiveExchange(cancelledSource, plan: plan(cancelledSource, name: "adaptive-cancel.example.test"),
            message: message, probe: cancelled) { candidate, _, _, _ in
                AdaptiveMemoryTransport(send: { _ in cancelled.attempted(candidate) }, cancel: { cancelled.cancelled.signal() })
            }
        try expect(cancelled.started.wait(timeout: .now() + 2) == .success, "待取消 adaptive 交换未开始")
        flow.cancel()
        try expect(cancelled.cancelled.wait(timeout: .now() + 2) == .success && cancelled.snapshot.answers.isEmpty,
                   "客户端取消未撤销自己的 adaptive 请求")
    }

    private static func adaptiveHedgedExchanges() throws {
        let profile = adaptiveProfile()

        // Reproduce the real four-second cutoff, not just a fast backup win:
        // the healthy primary replies at 4.5 s, still within the 8 s query
        // deadline, while the approved backup has no response at all.
        do {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-late-primary.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-late-primary.example.test"),
                message: message, probe: probe, timeout: 8) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.upstream.target.host == "203.0.113.70", let reply = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 4.5) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message, waitTimeout: 7)
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            try expect(probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.concurrency.peak == 2 && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 2 && elapsed >= 4 && elapsed < 8,
                       "soft hedge 截断了 4s 后仍健康的 primary 或没有撤销自己的备用")

            // Seed the fresh question independently: the real 4.5s exchange's
            // censored backup sample can fall on either side of the selector's
            // 10% hysteresis when dispatch delivers the primary slightly late.
            // This case tests known-alternate budget, not that ranking boundary.
            let fresh = try query("adaptive-known-slow-alternate.example.test", 1), nextProbe = AdaptiveProbe()
            let approved = try plan(source, name: "adaptive-known-slow-alternate.example.test")
            let ids = approved.candidates.map(\.id), scope = approved.healthScopeKey
            let clock = AdaptiveManualClock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let replyGate = AdaptiveManualReply()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            selector.record(scopeKey: scope, candidateID: ids[0], milliseconds: 4500, success: true)
            selector.record(scopeKey: scope, candidateID: ids[1], milliseconds: 100, success: true)
            try expect(selector.orderedCandidates(scopeKey: scope, candidateIDs: ids) == [ids[1], ids[0]],
                       "两个已有成功记录的候选没有按各自快慢历史排序")
            let hedgeDelay = DNSAdaptiveHedgeBudget.delay(remaining: 0.4, attemptsLeft: 2,
                primaryMilliseconds: selector.planningLatencyMilliseconds(scopeKey: scope, candidateID: ids[1]),
                alternateMilliseconds: selector.planningLatencyMilliseconds(scopeKey: scope, candidateID: ids[0]))
            try expect(hedgeDelay == 0.001, "已知 4.5s alternate 没有在原 400ms 内获最早 hedge 预算")
            let absolute = clock.now() + 0.4
            weak var checkpointFlow: DNSAdaptiveQueryDatagram?
            let nextFlow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, _, receive, _ in
                    checkpointFlow?.pauseAdaptiveTimersForSelfTest()
                    return AdaptiveMemoryTransport(send: { data in
                        nextProbe.attempted(candidate)
                        if candidate.upstream.target.host == "203.0.113.70", let answer = bootstrapAnswer(data) {
                            // The explicit fixture reply is released 300ms
                            // after the known alternate's admitted 1ms start.
                            replyGate.prepare { receive(answer) }
                        }
                    }, cancel: nextProbe.transportCancelled)
                }, receive: nextProbe.received, failure: nextProbe.failed, timeout: 0.4,
                absoluteDeadline: absolute, clock: clock.now)
            checkpointFlow = nextFlow
            defer { nextFlow.cancel() }
            nextFlow.send(fresh); nextFlow.drainAdaptiveQueueForSelfTest()
            try expect(nextProbe.snapshot.attempts == ["203.0.113.71"], "已知较快 primary 没有先按独立历史启动")
            clock.advance(to: hedgeDelay)
            try expect(nextFlow.fireAdaptiveHedgeForSelfTest(), "原生已知 alternate hedge checkpoint 未装载")
            clock.advance(to: hedgeDelay + 0.3)
            try expect(replyGate.release(), "已知慢 alternate 没有获发送和真实答复入口")
            try awaitAdaptive(nextProbe, query: fresh)
            let state = nextFlow.adaptiveStateForSelfTest
            try expect(nextProbe.snapshot.attempts == ["203.0.113.71", "203.0.113.70"]
                       && nextProbe.concurrency.peak == 2 && nextProbe.concurrency.active == 0
                       && nextProbe.concurrency.cancelled == 2 && state.attempts == 2 && state.active == 0
                       && state.started == 100 && state.deadline == absolute && clock.now() < absolute,
                       "fresh question 没给已知慢但健康 alternate 留足 overall 预算")
        }

        // A backup SERVFAIL must not finish an exchange whose primary is
        // still healthy. Its later, otherwise valid answer is a stale token
        // and must be ignored even before the primary eventually succeeds.
        do {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-servfail.example.test", 1)
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-servfail.example.test"),
                message: message, probe: probe, timeout: 0.4) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        guard let reply = bootstrapAnswer(data) else { return }
                        if candidate.upstream.target.host == "203.0.113.70" {
                            queue.asyncAfter(deadline: .now() + 0.3) { receive(reply) }
                        } else {
                            if let failed = DNSMessageInspection.errorResponse(to: data, code: .servfail) {
                                queue.async { receive(failed) }
                            }
                            var stale = reply; stale[stale.count - 1] = 78
                            let late = stale
                            queue.asyncAfter(deadline: .now() + 0.03) { receive(late); probe.late.signal() }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success
                       && DNSMessageInspection.addressAnswers(in: probe.snapshot.answers[0]).map(\.address) == ["203.0.113.77"]
                       && probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 2,
                       "备用 SERVFAIL 终止仍活跃 primary 或迟到 token 被采纳")
        }

        // The third approved candidate may replace a genuinely failed hedge,
        // but neither a fourth attempt nor three simultaneous transports is
        // permitted. Retain and later reject the first primary's late reply.
        do {
            var extended = profile
            extended.encryptedDNSServers += ["https://third.adaptive.selftest.invalid/dns-query#203.0.113.72",
                                             "https://fourth.adaptive.selftest.invalid/dns-query#203.0.113.73"]
            let source = router(extended), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-slots.example.test", 1)
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-slots.example.test"),
                message: message, probe: probe, timeout: 0.6) { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        switch candidate.upstream.target.host {
                        case "203.0.113.70":
                            if let reply = bootstrapAnswer(data) {
                                queue.asyncAfter(deadline: .now() + 0.45) { receive(reply); probe.late.signal() }
                            }
                        case "203.0.113.71": queue.async { failure(EngineError("内存 hedge 网络失败")) }
                        default:
                            if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success
                       && probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71", "203.0.113.72"]
                       && probe.concurrency.peak == 2 && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 3 && probe.snapshot.answers.count == 1,
                       "失败 hedge 补位超过 2 活跃/3 总尝试或迟到 primary 复活")
        }

        // The first primary retains the original deadline. A late unmeasured
        // hedge can rotate once without turning retirement into an outage.
        do {
            var extended = profile
            extended.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
            let source = router(extended), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-deadline.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-deadline.example.test"),
                message: message, probe: probe, timeout: 0.3) { candidate, _, _, _ in
                    AdaptiveMemoryTransport(send: { _ in probe.attempted(candidate) }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message, expectFailure: true)
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            try expect(probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71", "203.0.113.72"]
                       && probe.concurrency.peak == 2 && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 3 && elapsed >= 0.25 && elapsed < 1.5,
                       "unknown hedge 轮替丢失 primary、超过 2 live/3 attempts 或延长总期限")
        }

        // First observed NODATA/NXDOMAIN/REFUSED or local policy denial remains
        // terminal even with a positive primary already awaiting its reply.
        for code: UInt8 in [0, 3, 5, 255] {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-terminal.example.test", 1)
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-terminal.example.test"),
                message: message, probe: probe, timeout: 0.4) { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.upstream.target.host == "203.0.113.70", let reply = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 0.3) { receive(reply); probe.late.signal() }
                        } else {
                            queue.async {
                                if code == 255 { failure(DNSPolicyFailure.refused("内存候选策略拒绝")); return }
                                if var reply = DNSMessageInspection.errorResponse(to: data, code: .refused) {
                                    reply[3] = (reply[3] & 0xf0) | code; receive(reply)
                                }
                            }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success
                       && probe.snapshot.answers.count == 1 && probe.snapshot.answers[0][3] & 0x0f == (code == 255 ? 5 : code)
                       && DNSMessageInspection.addressAnswers(in: probe.snapshot.answers[0]).isEmpty
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 2,
                       "活跃 hedge 的明确否定/策略拒绝被忽略、跨供应商重试或没有取消 primary")
        }

        // Policy invalidation and client cancellation revoke both requests,
        // not only the most recently started hedge. All later replies remain
        // inert and must not start another approved candidate.
        for revoke in 0..<3 {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-revoke.example.test", 1)
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-revoke.example.test"),
                message: message, probe: probe, timeout: 0.4) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if let reply = bootstrapAnswer(data) {
                            let delay = candidate.upstream.target.host == "203.0.113.70" ? 0.3 : 0.1
                            queue.asyncAfter(deadline: .now() + delay) { receive(reply); probe.late.signal() }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            for _ in 0..<2 {
                try expect(probe.started.wait(timeout: .now() + 1) == .success, "待撤销 hedge 的两个候选未同时开始")
            }
            switch revoke {
            case 0: source.flushDNS()
            case 1: source.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            default: flow.cancel()
            }
            if revoke < 2 { try awaitAdaptive(probe, query: message, expectFailure: true) }
            for _ in 0..<2 {
                try expect(probe.cancelled.wait(timeout: .now() + 1) == .success
                           && probe.late.wait(timeout: .now() + 1) == .success, "双候选撤销未取消各自请求或缺迟到回调")
            }
            try expect(probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.snapshot.answers.isEmpty && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 2, "撤销后 hedge 接纳旧答案、继续切换或取消范围不完整")
        }
    }

    private final class AdaptivePolicyGate {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }

    private static func adaptiveShortHedgeBudgets() throws {
        let profile = adaptiveProfile()
        // The normal total deadline stays eight seconds. Only the approved
        // backup launch becomes shorter; the blackholed primary remains live.
        do {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-cold-short-hedge.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-cold-short-hedge.example.test"),
                message: message, probe: probe, timeout: 8) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.upstream.target.host == "203.0.113.71", let reply = bootstrapAnswer(data) {
                            queue.async { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }; try awaitAdaptive(probe, query: message, waitTimeout: 2)
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            try expect(elapsed >= 0.6 && elapsed <= 1.5
                       && probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 2,
                       "8s 冷查询仍长时间等待坏 primary 或超出 750ms 有界备用启动")
        }
        let approved = try plan(router(profile)), ids = approved.candidates.map(\.id)
        func observedSelector(_ candidates: [DNSUpstreamCandidate], scope: String) -> DNSAdaptiveUpstreamSelector {
            let selector = DNSAdaptiveUpstreamSelector()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: candidates.map(\.id))
            for (index, candidate) in candidates.enumerated() {
                selector.record(scopeKey: scope, candidateID: candidate.id,
                                milliseconds: index == 0 ? 2500 : index == 1 ? 3500 : 6000, success: true)
            }
            return selector
        }
        // A measured slow primary gets a hedge by 1.5s, but a legitimate 2.1s
        // primary reply must still win if that hedge has no response.
        do {
            let selector = observedSelector(approved.candidates, scope: approved.scopeKey), probe = AdaptiveProbe()
            let message = try query("adaptive-known-primary-retained.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let flow = DNSCoalescedQueryDatagram(coordinator: DNSQueryCoordinator(), scope: approved.scopeKey,
                queue: .global(), permitted: { true }, factory: { queue, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                        scopeKey: approved.scopeKey, queue: queue, permitted: { true },
                        factory: { candidate, queue, receive, _ in
                            AdaptiveMemoryTransport(send: { data in
                                probe.attempted(candidate)
                                if candidate.id == ids[0], let reply = bootstrapAnswer(data) {
                                    queue.asyncAfter(deadline: .now() + 2.1) { receive(reply) }
                                }
                            }, cancel: probe.transportCancelled)
                        }, receive: receive, failure: failure, timeout: 8)
                }, receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, waitTimeout: 3.5)
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            try expect(elapsed >= 2 && elapsed < 3.5
                       && probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 2,
                       "known RTT 的 1.5s 软预算未启动备用或取消了仍健康 primary")
        }
        var extended = profile
        extended.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let three = try plan(router(extended)), threeIDs = three.candidates.map(\.id)
        // RTT-driven short hedges do not turn ordinary cancellation into an
        // outage, nor make pending candidates escape a parent's total timeout.
        for deadline in [false, true] {
            let selector = observedSelector(three.candidates, scope: three.scopeKey), probe = AdaptiveProbe()
            let healthDrained = DispatchSemaphore(value: 0)
            let coordinator = DNSQueryCoordinator(timeout: .milliseconds(400))
            let message = try query("adaptive-known-budget-finish.example.test", 1)
            let flow = DNSCoalescedQueryDatagram(coordinator: coordinator, scope: three.scopeKey,
                queue: .global(), permitted: { true }, factory: { queue, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: three.candidates, selector: selector,
                        scopeKey: three.scopeKey, queue: queue, permitted: { true },
                        factory: { candidate, ownerQueue, _, _ in
                            AdaptiveMemoryTransport(send: { _ in probe.attempted(candidate) }, cancel: {
                                probe.transportCancelled()
                                // The deadline turn submits health after peer
                                // cancellation. Two passive FIFO hops observe
                                // that submission without an extra cancel/ACK.
                                ownerQueue.async { ownerQueue.async { healthDrained.signal() } }
                            })
                        }, receive: receive, failure: failure, timeout: 0.4)
                }, receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }; flow.send(message)
            for _ in 0..<2 {
                try expect(probe.started.wait(timeout: .now() + 1) == .success, "known RTT 负测的两个候选未同时启动")
            }
            if deadline { try awaitAdaptive(probe, query: message, expectFailure: true) }
            else { flow.cancel() }
            for _ in 0..<2 {
                try expect(probe.cancelled.wait(timeout: .now() + 1) == .success, "known RTT 结束未取消两个自己的请求")
            }
            for _ in 0..<2 {
                try expect(healthDrained.wait(timeout: .now() + 1) == .success, "known RTT 结束未排空真实 owner 队列的健康回执")
            }
            let next = selector.orderedCandidates(scopeKey: three.scopeKey, candidateIDs: threeIDs)
            try expect(next.first == (deadline ? threeIDs[2] : threeIDs[0])
                       && selector.knownLatencyMilliseconds(scopeKey: three.scopeKey, candidateID: threeIDs[0]) == 2500
                       && probe.snapshot.answers.isEmpty && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 2,
                       "known RTT 下 user cancel 被罚、总 timeout 不罚或 live transport 泄漏")
        }
    }

    private static func adaptiveLocalCapacityIsolation() throws {
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.capacity.selftest.invalid/dns-query#203.0.113.72")
        let approved = try plan(router(profile)), ids = approved.candidates.map(\.id)
        for primaryDenied in [false, true] {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: approved.healthScopeKey, candidateIDs: ids)
            for (index, candidate) in approved.candidates.enumerated() {
                selector.record(scopeKey: approved.healthScopeKey, candidateID: candidate.id,
                                milliseconds: index == 0 ? 20 : index == 1 ? 500 : 900, success: true)
            }
            let message = try query("adaptive-capacity-isolation.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                scopeKey: approved.healthScopeKey, queue: .global(qos: .userInitiated), permitted: { true },
                factory: { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if primaryDenied || candidate.id != ids[0] {
                            queue.async { failure(NodeConnectionAdmissionError.capacityExceeded) }
                        } else if let answer = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 0.3) { receive(answer) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 1)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: primaryDenied)
            let order = selector.orderedCandidates(scopeKey: approved.healthScopeKey, candidateIDs: ids)
            try expect(probe.snapshot.attempts == approved.candidates.prefix(primaryDenied ? 1 : 2).map { $0.upstream.target.host }
                       && order == ids && probe.concurrency.active == 0,
                       "本地满额导致更多拨号、健康 primary 被丢弃或解析器健康排序被污染")
            if primaryDenied {
                try expect(probe.snapshot.error.map(EncryptedDNSQueryFailure.classify) == .capacity,
                           "真实容量失败被误归网络失败或授权降级")
            } else {
                try expect(selector.knownLatencyMilliseconds(scopeKey: approved.healthScopeKey, candidateID: ids[1]) == 500,
                           "被准入拒绝的 hedge 改写 RTT")
            }
        }
        for latePrimaryDenied in [false, true] {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: approved.healthScopeKey, candidateIDs: ids)
            for (index, candidate) in approved.candidates.enumerated() {
                selector.record(scopeKey: approved.healthScopeKey, candidateID: candidate.id,
                                milliseconds: index == 0 ? 20 : index == 1 ? 500 : 900, success: true)
            }
            let message = try query("adaptive-late-capacity-isolation.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                scopeKey: approved.healthScopeKey, queue: .global(qos: .userInitiated), permitted: { true },
                factory: { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[0] {
                            queue.asyncAfter(deadline: .now() + 0.25) {
                                failure(latePrimaryDenied ? NodeConnectionAdmissionError.capacityExceeded : EncryptedDNSQueryFailure.network)
                            }
                        } else if latePrimaryDenied, candidate.id == ids[1], let answer = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 0.6) { receive(answer) }
                        } else { queue.async { failure(NodeConnectionAdmissionError.capacityExceeded) } }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 1)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: !latePrimaryDenied)
            try expect(probe.snapshot.attempts == approved.candidates.prefix(2).map { $0.upstream.target.host }
                       && probe.concurrency.peak == 2 && probe.concurrency.active == 0,
                       "late primary capacity 的轮替 timer 或后续网络错误继续拨号第三候选")
            if !latePrimaryDenied {
                try expect(probe.snapshot.error.map(EncryptedDNSQueryFailure.classify) == .capacity,
                           "曾有本地容量 deny 的交换最终丢失了容量屏障")
            }
        }
    }

    private final class ProductionCapacityDialProbe {
        private let lock = NSLock()
        private var hosts: [String] = []
        func observed(_ host: String) { lock.lock(); hosts.append(host); lock.unlock() }
        var snapshot: [String] { lock.lock(); defer { lock.unlock() }; return hosts }
    }

    private static func productionEncryptedCapacityIsolation() throws {
        for tls in [false, true] {
            var profile = adaptiveProfile()
            profile.dnsProxyFallbackEnabled = false
            profile.encryptedDNSServers = (0..<3).map { index in
                tls ? "tls://203.0.113.\(70 + index):853"
                    : "https://capacity-\(index).selftest.invalid/dns-query#203.0.113.\(70 + index)"
            }
            let source = router(profile), dials = ProductionCapacityDialProbe()
            source.memoryFixtureDNSStreamDialer = { host, _, _, _, _, observe, done in
                dials.observed(host)
                observe(NodeConnectionAdmissionError.capacityExceeded)
                done(.failure(NodeConnectionAdmissionError.capacityExceeded)); return {}
            }
            defer { source.flushDNS() }
            let worker = DispatchQueue(label: "app.hajimi.dns.production-capacity-self-test")
            let name = "capacity-raw-owned.example.test", rawPlan = try plan(source, name: name)
            try expect(rawPlan.fallbackServers.isEmpty && rawPlan.candidates.count == 3,
                       "容量回归没有进入无普通回退的三个批准候选")
            // Both owner insert and owner-cache acquire must preserve the
            // typed failure. Do not exercise an adaptiveFactory test double.
            for _ in 0..<2 {
                let message = try query(name, 1), probe = AdaptiveProbe()
                let flow = try source.makeDNSUpstream(plan: rawPlan, queue: worker,
                                                      receive: probe.received, failure: probe.failed)
                flow.send(message); try awaitAdaptive(probe, query: message, expectFailure: true)
                try expect(probe.snapshot.error.map(EncryptedDNSQueryFailure.classify) == .capacity
                           && probe.snapshot.answers.isEmpty, "严格 resolver 工厂将容量转换成了上游 SERVFAIL")
                let ack = DispatchSemaphore(value: 0)
                (flow as? DNSQueryCancellationAcknowledging)?.cancel { ack.signal() }
                try expect(ack.wait(timeout: .now() + 1) == .success, "严格 resolver 容量取消 ACK 未完成")
            }
            let before = NetworkPerformanceDiagnostics.shared.snapshot()
            for index in 0..<2 {
                let name = "capacity-optimized-\(index).example.test", message = try query(name, 1), probe = AdaptiveProbe()
                let flow = try source.makeOptimizedDNSUpstream(plan: plan(source, name: name), queue: worker,
                                                               receive: probe.received, failure: probe.failed)
                flow.send(message); try awaitAdaptive(probe, query: message, expectFailure: true)
                // The public coordinator facade intentionally returns a
                // privacy-preserving generic Error. Its aggregate retains
                // the real reason, asserted below; retry policy must have
                // consumed the typed failure before that facade boundary.
                try expect(probe.snapshot.error != nil && probe.snapshot.answers.isEmpty,
                           "无普通回退的容量拒绝仍被当作成功答案")
                flow.cancel()
            }
            let after = NetworkPerformanceDiagnostics.shared.snapshot()
            try expect(dials.snapshot == Array(repeating: "203.0.113.70", count: 4)
                       && after.dnsUpstreamAttempts - before.dnsUpstreamAttempts == 2
                       && after.dnsFailureReasons[.capacity, default: 0] - before.dnsFailureReasons[.capacity, default: 0] == 2,
                       "无普通回退路径在容量拒绝后拨号备用、罚首选或伪报上游失败")
            let message = try query("capacity-client-servfail.example.test", 1, id: 0x5a5a), client = AdaptiveProbe()
            let facade = try source.makeDNSDatagram(original: RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP"),
                queue: worker, synthesizeFakeIP: false, receive: client.received, failure: client.failed)
            facade.send(message); try awaitAdaptive(client, query: message)
            facade.cancel(); worker.sync {}
            try expect(client.snapshot.answers[0][3] & 0x0f == 2 && dials.snapshot.count == 5,
                       "保留 typed 容量破坏客户端单次同 ID SERVFAIL 契约")
        }
        print("DNS production capacity isolation passed: DoH/DoT new/acquired owners, real adaptive factories without fallback, no provider penalty/fanout and exactly one client SERVFAIL")
    }

    private enum ParentDeadlineReason: String { case deadline, caller, policy, other }
    private enum ParentDeadlineMethod: String { case deadline, cancel }
    private static func parentDeadlineReason(_ state: DNSParentDeadlineMemoryState) -> ParentDeadlineReason {
        if !state.permitted { return .policy }
        if state.closed { return .caller }
        return state.deadlineSignalled ? .deadline : .other
    }

    private struct ParentDeadlineOwnerReceipt {
        let token: UUID, candidate: Int, createdAt: UInt64
        var sends = 0, cancels = 0, lates = 0, drains = 0, fences = 0
        var sendAt: UInt64?, cancelAt: UInt64?, lateAt: UInt64?, drainAt: UInt64?, fenceAt: UInt64?
        var cancelState: DNSParentDeadlineMemoryState?, fenceState: DNSParentDeadlineMemoryState?
    }
    private struct ParentDeadlineLedgerState {
        let mode: Int
        var owners: [ParentDeadlineOwnerReceipt] = [] // Never more than three; never remove an owner.
        var faults = 0, peakLive = 0, actions = 0, parentCalls = 0
        var firstForeign: UUID?, actionOwner: UUID?, actionAt: UInt64?
        var parentMethod: ParentDeadlineMethod?, parentAt: UInt64?
        var parentLive = Set<UUID>(), parentRetired = Set<UUID>()
        var terminalState: DNSParentDeadlineMemoryState?, terminalAt: UInt64?
        var terminalCandidates = Set<Int>()
        var terminalFenceState: DNSParentDeadlineMemoryState?, terminalFenceAt: UInt64?
        func diagnostics() -> String {
            let reason = terminalState.map { DNSSecurityRoutingSelfTest.parentDeadlineReason($0).rawValue } ?? "unobserved"
            let childFirst = terminalAt.flatMap { ended in parentAt.map { ended < $0 } }
            let receipts = owners.map {
                "owner=\($0.token.uuidString), candidate=\($0.candidate), created=1, send=\($0.sends), cancel=\($0.cancels), late=\($0.lates), drain=\($0.drains), fence=\($0.fences), createdNs=\($0.createdAt), sendNs=\($0.sendAt.map { String($0) } ?? "none"), cancelNs=\($0.cancelAt.map { String($0) } ?? "none"), lateNs=\($0.lateAt.map { String($0) } ?? "none"), drainNs=\($0.drainAt.map { String($0) } ?? "none"), fenceNs=\($0.fenceAt.map { String($0) } ?? "none")"
            }.joined(separator: " | ")
            return "mode=\(mode), parent=\(parentMethod?.rawValue ?? "unobserved"), child=\(reason), childEndedBeforeParent=\(childFirst.map { String($0) } ?? "unobserved"), owners=\(owners.count), peakLive=\(peakLive), terminalCandidates=\(terminalCandidates.sorted()), actionNs=\(actionAt.map { String($0) } ?? "none"), parentNs=\(parentAt.map { String($0) } ?? "none"), childEndNs=\(terminalAt.map { String($0) } ?? "none"), quiescenceNs=\(terminalFenceAt.map { String($0) } ?? "none"), faults=\(faults), firstForeign=\(firstForeign?.uuidString ?? "none"); \(receipts)"
        }
    }
    private final class ParentDeadlineOwnerLedger {
        private enum Event { case send, cancel(DNSParentDeadlineMemoryState?), late, drain, fence(DNSParentDeadlineMemoryState?) }
        let terminalFence = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var state: ParentDeadlineLedgerState
        init(mode: Int) { state = ParentDeadlineLedgerState(mode: mode) }
        init(forMemoryVector state: ParentDeadlineLedgerState) { self.state = state }
        func fault() { lock.lock(); state.faults += 1; lock.unlock() }
        func create(candidate: Int) -> UUID {
            let token = UUID(), now = DispatchTime.now().uptimeNanoseconds
            lock.lock(); defer { lock.unlock() }
            guard state.owners.count < 3 else { state.faults += 1; state.firstForeign = state.firstForeign ?? token; return token }
            if state.parentCalls != 0 || state.terminalState != nil { state.faults += 1 }
            state.owners.append(ParentDeadlineOwnerReceipt(token: token, candidate: candidate, createdAt: now))
            state.peakLive = max(state.peakLive, state.owners.filter { $0.cancels == 0 }.count)
            return token
        }
        func sent(_ token: UUID) -> Bool { record(.send, token: token) }
        func cancelled(_ token: UUID, child: DNSParentDeadlineMemoryState?) { _ = record(.cancel(child), token: token) }
        func late(_ token: UUID) { _ = record(.late, token: token) }
        func drained(_ token: UUID) { _ = record(.drain, token: token) }
        func fenced(_ token: UUID, child: DNSParentDeadlineMemoryState?) { _ = record(.fence(child), token: token) }
        private func record(_ event: Event, token: UUID) -> Bool {
            let now = DispatchTime.now().uptimeNanoseconds
            var secondSend = false, wakeTerminal = false
            lock.lock()
            guard let index = state.owners.firstIndex(where: { $0.token == token }) else {
                state.faults += 1; state.firstForeign = state.firstForeign ?? token; lock.unlock(); return false
            }
            var owner = state.owners[index]
            switch event {
            case .send:
                owner.sends += 1; owner.sendAt = owner.sendAt ?? now
                if state.parentCalls != 0 || state.terminalState != nil { state.faults += 1 }
                secondSend = owner.sends == 1 && state.owners.filter { $0.sends > 0 }.count == 1
            case .cancel(let child):
                owner.cancels += 1; owner.cancelAt = owner.cancelAt ?? now
                owner.cancelState = owner.cancelState ?? child
                if let child {
                    if child.finished, state.terminalState == nil {
                        state.terminalState = child; state.terminalAt = now
                        state.terminalCandidates = Set(state.owners.map(\.candidate)).subtracting(child.retiredCandidates)
                    }
                } else { state.faults += 1 }
            case .late:
                owner.lates += 1; owner.lateAt = owner.lateAt ?? now
                if owner.sends != 1 || owner.cancels != 1 || state.terminalState == nil { state.faults += 1 }
            case .drain:
                owner.drains += 1; owner.drainAt = owner.drainAt ?? now
                if owner.lates != 1 { state.faults += 1 }
            case .fence(let child):
                owner.fences += 1; owner.fenceAt = owner.fenceAt ?? now
                owner.fenceState = owner.fenceState ?? child
                if let child {
                    if child.finished, child.activeCandidates.isEmpty, state.terminalFenceState == nil {
                        state.terminalFenceState = child; state.terminalFenceAt = now; wakeTerminal = true
                    }
                } else { state.faults += 1 }
            }
            state.owners[index] = owner
            lock.unlock()
            if wakeTerminal { terminalFence.signal() } // Passive owner-queue observation, never a native/kernel ACK.
            return secondSend
        }
        func action(_ token: UUID) {
            let now = DispatchTime.now().uptimeNanoseconds
            lock.lock(); state.actions += 1; state.actionOwner = state.actionOwner ?? token
            state.actionAt = state.actionAt ?? now; lock.unlock()
        }
        func parentEnded(_ method: ParentDeadlineMethod) {
            let now = DispatchTime.now().uptimeNanoseconds
            lock.lock(); defer { lock.unlock() }
            state.parentCalls += 1
            guard state.parentAt == nil else { return }
            state.parentAt = now; state.parentMethod = method
            state.parentLive = Set(state.owners.filter { $0.cancels == 0 }.map(\.token))
            state.parentRetired = Set(state.owners.filter {
                $0.cancelState?.finished == false && $0.cancelState?.retiredCandidates.contains($0.candidate) == true
            }.map(\.token))
        }
        var snapshot: ParentDeadlineLedgerState { lock.lock(); defer { lock.unlock() }; return state }
    }
    private final class ParentDeadlineReferences {
        private let lock = NSLock()
        private weak var child: DNSAdaptiveQueryDatagram?
        private weak var lease: DNSCoalescedQueryDatagram?
        func setChild(_ child: DNSAdaptiveQueryDatagram) { lock.lock(); self.child = child; lock.unlock() }
        func setLease(_ lease: DNSCoalescedQueryDatagram) { lock.lock(); self.lease = lease; lock.unlock() }
        var currentChild: DNSAdaptiveQueryDatagram? { lock.lock(); defer { lock.unlock() }; return child }
        var currentLease: DNSCoalescedQueryDatagram? { lock.lock(); defer { lock.unlock() }; return lease }
    }
    /// Transparent fixture metadata only; every operation reaches the real
    /// adaptive child, without extra cancel calls or manufactured acknowledgements.
    private final class ParentDeadlineObservedChild: NativeRoutedDatagram, DNSQueryDeadlineAwareDatagram {
        let child: DNSAdaptiveQueryDatagram, ledger: ParentDeadlineOwnerLedger
        init(_ child: DNSAdaptiveQueryDatagram, ledger: ParentDeadlineOwnerLedger) { self.child = child; self.ledger = ledger }
        func send(_ data: Data) { child.send(data) }
        func queryDeadlineReached() { ledger.parentEnded(.deadline); child.queryDeadlineReached() }
        func cancel() { ledger.parentEnded(.cancel); child.cancel() }
    }
    private struct ParentDeadlineOutcome {
        var ledger: ParentDeadlineLedgerState
        var orders: [[Int]], rtts: [Double?]
        var sent: Int, cancelled: Int, active: Int, peak: Int, answers: Int, pending: Int
    }
    private static let parentDeadlinePermutations = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]
    private static func parentDeadlineOracle(_ result: ParentDeadlineOutcome) -> String? {
        let state = result.ledger, owners = state.owners
        guard state.faults == 0, state.firstForeign == nil, (0..<4).contains(state.mode), (2...3).contains(owners.count),
              Set(owners.map(\.token)).count == owners.count,
              owners.map(\.candidate) == Array(0..<owners.count), state.peakLive == 2, result.peak == 2 else {
            return "foreign/duplicate/post-terminal owner or invalid admission bound"
        }
        guard state.parentCalls == 1, let method = state.parentMethod, let parentAt = state.parentAt,
              let terminal = state.terminalState, let terminalAt = state.terminalAt,
              let fence = state.terminalFenceState, let fenceAt = state.terminalFenceAt,
              terminal.finished, terminal.activeCandidates.isEmpty, fence.finished, fence.activeCandidates.isEmpty,
              fence.retiredCandidates.isEmpty,
              terminal.attempts == owners.count, fence.attempts == owners.count, terminalAt <= fenceAt else {
            return "missing actual parent/child terminal or passive quiescence receipt"
        }
        guard state.actions == (state.mode == 0 ? 0 : 1),
              state.actionOwner == (state.mode == 0 ? nil : owners[1].token) else { return "incorrect second-send action receipt" }
        if state.mode == 0 {
            guard state.actionAt == nil else { return "unrequested caller action" }
        } else {
            guard let actionAt = state.actionAt, let secondSendAt = owners[1].sendAt,
                  secondSendAt <= actionAt, actionAt <= parentAt, actionAt <= terminalAt else { return "second-send action lost its actual event ordering" }
        }
        let retired = Set(owners.filter {
            $0.cancelState?.finished == false && $0.cancelState?.retiredCandidates.contains($0.candidate) == true
        }.map(\.candidate))
        guard retired.isSubset(of: [1]), terminal.retiredCandidates == retired,
              state.terminalCandidates == Set(owners.map(\.candidate)).subtracting(retired),
              (1...2).contains(state.terminalCandidates.count) else { return "terminal/retired owner identity mismatch" }
        let liveAtParent = Set(owners.filter {
            $0.createdAt <= parentAt && ($0.cancelAt.map { $0 > parentAt } ?? true)
        }.map(\.token))
        let retiredAtParent = Set(owners.filter {
            retired.contains($0.candidate) && ($0.cancelAt.map { $0 <= parentAt } ?? false)
        }.map(\.token))
        guard state.parentLive == liveAtParent, state.parentRetired == retiredAtParent else { return "parent event owner-set mismatch" }
        let reason = parentDeadlineReason(terminal)
        let requiredReason: ParentDeadlineReason = state.mode < 2 ? .deadline : state.mode == 2 ? .caller : .policy
        let requiredMethod: ParentDeadlineMethod = state.mode < 2 ? .deadline : .cancel
        // A truthful deadline winning a caller-cancel race is still a failed
        // caller scenario, never permission to change this oracle's purpose.
        guard reason == requiredReason, method == requiredMethod else { return "actual termination does not belong to this requested scenario" }
        for owner in owners {
            guard (0...1).contains(owner.sends), owner.cancels == 1, owner.fences == 1,
                  let cancelAt = owner.cancelAt, let ownerFenceAt = owner.fenceAt,
                  let cancellation = owner.cancelState, let observation = owner.fenceState,
                  owner.createdAt <= parentAt, owner.createdAt <= terminalAt,
                  owner.createdAt <= cancelAt, cancelAt <= ownerFenceAt,
                  (1...owners.count).contains(cancellation.attempts), cancellation.activeCandidates.count <= 2,
                  (1...owners.count).contains(observation.attempts), observation.activeCandidates.count <= 2,
                  cancellation.activeCandidates.isSubset(of: Set(0..<cancellation.attempts)),
                  cancellation.retiredCandidates.isSubset(of: [1]),
                  observation.activeCandidates.isSubset(of: Set(0..<observation.attempts)),
                  observation.retiredCandidates.isSubset(of: [1]) else { return "missing/duplicate/foreign owner cancellation or observation" }
            if cancellation.finished {
                guard cancellation.activeCandidates.isEmpty, parentDeadlineReason(cancellation) == reason,
                      !retired.contains(owner.candidate) else { return "owner cleanup has inconsistent terminal identity" }
            } else if retired.contains(owner.candidate) {
                guard owner.sends == 1, !cancellation.closed, !cancellation.deadlineSignalled, cancellation.permitted,
                      !cancellation.activeCandidates.contains(owner.candidate) else { return "retirement is not an actual nonterminal owner event" }
            } else {
                // A returned factory owner may lose its remaining budget
                // before send. It still needs its own real cancellation.
                guard owner.sends == 0, cancellation.activeCandidates.contains(owner.candidate) else { return "unclassified preterminal cancellation" }
            }
            if owner.sends == 1 {
                guard owner.lates == 1, owner.drains == 1, let sendAt = owner.sendAt,
                      let lateAt = owner.lateAt, let drainAt = owner.drainAt,
                      owner.createdAt <= sendAt, sendAt <= parentAt, sendAt <= terminalAt,
                      sendAt <= cancelAt, cancelAt <= lateAt,
                      terminalAt <= lateAt, lateAt <= drainAt else { return "missing/duplicate/early late-owner callback or drain" }
            } else if owner.lates != 0 || owner.drains != 0 || owner.sendAt != nil || owner.lateAt != nil || owner.drainAt != nil {
                return "unsent owner fabricated a late callback"
            }
        }
        let sent = owners.filter { $0.sends == 1 }.count
        guard (2...3).contains(sent), result.sent == sent, result.cancelled == owners.count,
              result.active == 0, result.answers == 0, result.pending == 0,
              result.rtts.count == 3, result.rtts.allSatisfy({ $0 == nil }), result.orders.count == 6 else {
            return "late answer/RTT revival, leaked work, or receipt aggregate mismatch"
        }
        let penalized = reason == .deadline ? state.terminalCandidates : Set<Int>()
        for (input, order) in zip(parentDeadlinePermutations, result.orders) {
            let untouched = input.filter { !penalized.contains($0) }
            // The actual failure calls can have distinct cooldown instants.
            // Verify exact membership, not a timer-sensitive tie inside the
            // failed partition; neutral/untouched candidates keep input order.
            guard order.count == 3, Set(order) == Set(input),
                  Array(order.prefix(untouched.count)) == untouched,
                  Set(order.dropFirst(untouched.count)) == penalized else {
                return "deadline-active health partition or caller/policy neutrality mismatch"
            }
        }
        return nil
    }

    private static func parentDeadlineVector(owners count: Int, reason: ParentDeadlineReason = .deadline,
        mode: Int = 0, retireSecond: Bool = false, unsentThird: Bool = false) -> ParentDeadlineOutcome {
        let retires = retireSecond || count == 3
        let retired: Set<Int> = retires ? [1] : []
        let ended = DNSParentDeadlineMemoryState(finished: true, closed: reason == .caller,
            deadlineSignalled: reason == .deadline, permitted: reason != .policy,
            attempts: count, activeCandidates: [], retiredCandidates: retired)
        let quiet = DNSParentDeadlineMemoryState(finished: true, closed: ended.closed,
            deadlineSignalled: ended.deadlineSignalled, permitted: ended.permitted,
            attempts: count, activeCandidates: [], retiredCandidates: [])
        var state = ParentDeadlineLedgerState(mode: mode)
        state.peakLive = 2; state.parentCalls = 1
        state.parentMethod = reason == .deadline ? .deadline : .cancel
        state.parentAt = unsentThird ? 1_000 : 800
        state.terminalState = ended; state.terminalAt = 900
        state.terminalFenceState = quiet; state.terminalFenceAt = unsentThird ? 1_049 : 1_050
        for index in 0..<count {
            var owner = ParentDeadlineOwnerReceipt(token: UUID(), candidate: index,
                createdAt: index == 0 ? 100 : index == 1 ? 300 : 700)
            owner.sends = unsentThird && index == 2 ? 0 : 1
            if owner.sends == 1 { owner.sendAt = owner.createdAt + 10 }
            owner.cancels = 1; owner.fences = 1
            owner.cancelAt = UInt64(900 + index); owner.cancelState = ended
            owner.fenceAt = UInt64(1_050 + index); owner.fenceState = quiet
            if retires && index == 1 {
                owner.cancelAt = 600
                owner.cancelState = DNSParentDeadlineMemoryState(finished: false, closed: false,
                    deadlineSignalled: false, permitted: true, attempts: 2,
                    activeCandidates: [0], retiredCandidates: [1])
                if unsentThird { owner.fenceAt = 1_049 }
                else {
                    owner.fenceAt = 760
                    owner.fenceState = DNSParentDeadlineMemoryState(finished: false, closed: false,
                        deadlineSignalled: false, permitted: true, attempts: count,
                        activeCandidates: count == 3 ? [0, 2] : [0], retiredCandidates: [1])
                }
            } else if unsentThird && index == 2 {
                owner.cancelAt = 850
                owner.cancelState = DNSParentDeadlineMemoryState(finished: false, closed: false,
                    deadlineSignalled: false, permitted: true, attempts: 3,
                    activeCandidates: [0, 2], retiredCandidates: [1])
            }
            if owner.sends == 1 {
                owner.lates = 1; owner.drains = 1
                owner.lateAt = UInt64(1_200 + index); owner.drainAt = UInt64(1_300 + index)
            }
            state.owners.append(owner)
        }
        state.terminalCandidates = Set(state.owners.map(\.candidate)).subtracting(retired)
        state.parentLive = Set(state.owners.filter { $0.cancelAt! > state.parentAt! }.map(\.token))
        state.parentRetired = Set(state.owners.filter { retired.contains($0.candidate) }.map(\.token))
        if mode != 0 { state.actions = 1; state.actionOwner = state.owners[1].token; state.actionAt = 311 }
        let penalized = reason == .deadline ? state.terminalCandidates : Set<Int>()
        return ParentDeadlineOutcome(ledger: state,
            orders: parentDeadlinePermutations.map { input in
                input.filter { !penalized.contains($0) } + input.filter { penalized.contains($0) }
            }, rtts: [nil, nil, nil], sent: state.owners.filter { $0.sends == 1 }.count,
            cancelled: count, active: 0, peak: 2, answers: 0, pending: 0)
    }
    private static func parentDeadlineOwnerOracleVectors() throws {
        let two = parentDeadlineVector(owners: 2), three = parentDeadlineVector(owners: 3)
        let caller = parentDeadlineVector(owners: 2, reason: .caller, mode: 2)
        let policy = parentDeadlineVector(owners: 2, reason: .policy, mode: 3)
        var reorderedFailures = two
        reorderedFailures.orders = two.orders.map { [$0[0]] + Array($0.dropFirst().reversed()) }
        let positives = [two, three, caller, policy, reorderedFailures,
            parentDeadlineVector(owners: 2, mode: 1),
            parentDeadlineVector(owners: 2, retireSecond: true),
            parentDeadlineVector(owners: 3, unsentThird: true)]
        for vector in positives {
            try expect(parentDeadlineOracle(vector) == nil, "合法 2/3 owner、退役或未发送 owner 被拒绝")
        }
        let negatives: [(String, ParentDeadlineOutcome, (inout ParentDeadlineOutcome) -> Void)] = [
            ("missing cancel", three, { $0.ledger.owners[2].cancels = 0 }),
            ("duplicate hides missing", three, { $0.ledger.owners[0].cancels = 2; $0.ledger.owners[2].cancels = 0 }),
            ("foreign cancel", two, { $0.ledger.faults = 1; $0.ledger.firstForeign = UUID() }),
            ("duplicate owner", two, { value in
                let old = value.ledger.owners[1]
                value.ledger.owners[1] = ParentDeadlineOwnerReceipt(token: value.ledger.owners[0].token,
                    candidate: old.candidate, createdAt: old.createdAt)
            }),
            ("foreign candidate", three, { value in
                let old = value.ledger.owners[2]
                value.ledger.owners[2] = ParentDeadlineOwnerReceipt(token: old.token, candidate: 3, createdAt: old.createdAt)
            }),
            ("fourth owner", three, { $0.ledger.owners.append(ParentDeadlineOwnerReceipt(token: UUID(), candidate: 3, createdAt: 800)) }),
            ("missing late", three, { $0.ledger.owners[2].lates = 0 }),
            ("duplicate hides missing late", three, { $0.ledger.owners[0].lates = 2; $0.ledger.owners[2].lates = 0 }),
            ("missing drain", two, { $0.ledger.owners[0].drains = 0 }),
            ("missing fence", two, { $0.ledger.owners[0].fences = 0 }),
            ("duplicate fence", two, { $0.ledger.owners[0].fences = 2 }),
            ("missing terminal", two, { $0.ledger.terminalState = nil }),
            ("missing quiescence", two, { $0.ledger.terminalFenceState = nil }),
            ("unbound foreign metadata", two, { $0.ledger.firstForeign = UUID() }),
            ("wrong live identity", three, { $0.ledger.parentLive = [UUID()] }),
            ("wrong retired identity", three, { $0.ledger.parentRetired = [] }),
            ("wrong terminal participant", three, { $0.ledger.terminalCandidates = [0, 1] }),
            ("late before cancel", two, { $0.ledger.owners[0].lateAt = 500 }),
            ("post-terminal send", two, { $0.ledger.owners[0].sendAt = 1_000 }),
            ("caller health penalty", caller, { $0.orders = three.orders }),
            ("policy health penalty", policy, { $0.orders = two.orders }),
            ("deadline not penalized", two, { $0.orders = parentDeadlinePermutations }),
            ("retired health penalty", three, { $0.orders = two.orders }),
            ("late RTT revival", two, { $0.rtts[0] = 500 }),
            ("late application answer", two, { $0.answers = 1 }),
            ("pending leaked", two, { $0.pending = 1 }),
            ("three live", three, { $0.ledger.peakLive = 3 }),
            ("mode0 caller with matching neutral health", parentDeadlineVector(owners: 2, reason: .caller), { _ in }),
            ("mode1 caller with matching neutral health", parentDeadlineVector(owners: 2, reason: .caller, mode: 1), { _ in }),
            ("mode2 deadline with matching penalized health", parentDeadlineVector(owners: 2, mode: 2), { _ in }),
            ("mode3 deadline with matching penalized health", parentDeadlineVector(owners: 2, mode: 3), { _ in }),
            ("mode3 caller with matching neutral health", parentDeadlineVector(owners: 2, reason: .caller, mode: 3), { _ in }),
            ("mode0 child-first deadline wrong parent method", parentDeadlineVector(owners: 3, unsentThird: true), { $0.ledger.parentMethod = .cancel }),
            ("mode1 child-first deadline wrong parent method", parentDeadlineVector(owners: 3, mode: 1, unsentThird: true), { $0.ledger.parentMethod = .cancel }),
            ("mode2 caller wrong parent method", caller, { $0.ledger.parentMethod = .deadline }),
            ("mode3 policy wrong parent method", policy, { $0.ledger.parentMethod = .deadline }),
            ("unsent fabricated late", parentDeadlineVector(owners: 3, unsentThird: true), { value in
                value.ledger.owners[2].lates = 1; value.ledger.owners[2].drains = 1
                value.ledger.owners[2].lateAt = 1_202; value.ledger.owners[2].drainAt = 1_302
            })
        ]
        for (name, original, alter) in negatives {
            var broken = original; alter(&broken)
            try expect(parentDeadlineOracle(broken) != nil, "owner oracle 接受负向量：\(name)")
        }
        // Exercise actual ledger admission rather than relying only on a
        // synthetic fault flag: no foreign or duplicate callback is deduped.
        let foreign = ParentDeadlineOwnerLedger(forMemoryVector: two.ledger)
        foreign.cancelled(UUID(), child: two.ledger.terminalState)
        var foreignResult = two; foreignResult.ledger = foreign.snapshot
        try expect(parentDeadlineOracle(foreignResult) != nil, "实际 ledger 接受 foreign cancel")
        let duplicate = ParentDeadlineOwnerLedger(forMemoryVector: three.ledger)
        duplicate.cancelled(three.ledger.owners[0].token, child: three.ledger.terminalState)
        var duplicateResult = three; duplicateResult.ledger = duplicate.snapshot
        try expect(parentDeadlineOracle(duplicateResult) != nil, "实际 ledger 去重并接受 duplicate cancel")
        print("DNS parent-deadline owner oracle vectors passed: \(positives.count) positive / \(negatives.count + 2) negative, exact identities and truthful termination health")
    }

    private static func adaptiveParentDeadlineHealth() throws {
        try parentDeadlineOwnerOracleVectors()
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let approved = try plan(router(profile)), ids = approved.candidates.map(\.id)
        // Actual coordinator + actual adaptive child, with equal 350ms timers.
        // The 30ms factory setup normally places the parent first, but actual
        // receipts, not wall-clock assumptions, determine cleanup and health.
        for mode in 0..<4 {
            let coordinator = DNSQueryCoordinator(timeout: .milliseconds(350))
            let selector = DNSAdaptiveUpstreamSelector(), gate = AdaptivePolicyGate(), probe = AdaptiveProbe()
            let ledger = ParentDeadlineOwnerLedger(mode: mode), references = ParentDeadlineReferences()
            defer { print("DNS parent-deadline memory receipts: \(ledger.snapshot.diagnostics())") }
            let message = try query("adaptive-parent-deadline.example.test", 1)
            let flow = DNSCoalescedQueryDatagram(coordinator: coordinator, scope: approved.scopeKey,
                queue: DispatchQueue(label: "app.hajimi.dns.parent-deadline-self-test"),
                permitted: gate.permits, factory: { queue, receive, failure in
                    Thread.sleep(forTimeInterval: 0.03)
                    let child = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                        scopeKey: approved.scopeKey, queue: queue, permitted: gate.permits,
                        factory: { candidate, queue, receive, _ in
                            let owner = ledger.create(candidate: ids.firstIndex(of: candidate.id) ?? -1)
                            return AdaptiveMemoryTransport(send: { data in
                                if data != message { ledger.fault() }
                                let secondSend = ledger.sent(owner)
                                probe.attempted(candidate)
                                // Perform the original action at the actual
                                // second send, not after a main-thread wakeup.
                                if secondSend, mode != 0 {
                                    ledger.action(owner)
                                    switch mode {
                                    case 1:
                                        if let lease = references.currentLease { lease.queryDeadlineReached() }
                                        else { ledger.fault() }
                                    case 2:
                                        if let lease = references.currentLease { lease.cancel() }
                                        else { ledger.fault() }
                                    case 3: gate.revoke()
                                    default: ledger.fault()
                                    }
                                }
                                if let reply = bootstrapAnswer(data) {
                                    queue.asyncAfter(deadline: .now() + 0.5) {
                                        ledger.late(owner)
                                        if !DNSMessageInspection.responseMatchesQuery(reply, query: message) { ledger.fault() }
                                        receive(reply)
                                        // receive() queues accept() on this
                                        // same child queue. This FIFO marker
                                        // observes that handoff; it is no ACK.
                                        queue.async { ledger.drained(owner); probe.late.signal() }
                                    }
                                } else { ledger.fault() }
                            }, cancel: {
                                let actualChild = references.currentChild
                                ledger.cancelled(owner, child: actualChild?.parentDeadlineStateForMemorySelfTest())
                                probe.transportCancelled()
                                // Retain only an already observed cancel's
                                // child until this bounded passive inspection.
                                // No cancel/finish call can create the receipt.
                                queue.async {
                                    ledger.fenced(owner, child: actualChild?.parentDeadlineStateForMemorySelfTest())
                                }
                            })
                        }, receive: receive, failure: failure, timeout: 0.35)
                    references.setChild(child)
                    return ParentDeadlineObservedChild(child, ledger: ledger)
                }, receive: probe.received, failure: probe.failed)
            references.setLease(flow)
            defer { flow.cancel() }
            let began = ProcessInfo.processInfo.systemUptime; flow.send(message)
            for _ in 0..<2 {
                try expect(probe.started.wait(timeout: .now() + 1) == .success,
                           "父期限 mode \(mode) 未形成两个真实 send owner")
            }
            if mode == 0 || mode == 3 {
                try awaitAdaptive(probe, query: message, expectFailure: true)
                try expect(ProcessInfo.processInfo.systemUptime - began < 0.8,
                           "父期限等待子 timer 或延长了等待者的总预算")
            }
            let cancellationDeadline = DispatchTime.now() + 1
            try expect(ledger.terminalFence.wait(timeout: cancellationDeadline) == .success,
                       "父期限 mode \(mode) 缺少实际 finished/active0 被动观察；\(ledger.snapshot.diagnostics())")
            let ended = ledger.snapshot
            for _ in ended.owners {
                try expect(probe.cancelled.wait(timeout: cancellationDeadline) == .success,
                           "父期限 mode \(mode) 缺少 factory owner 的真实取消调用；\(ledger.snapshot.diagnostics())")
            }
            for _ in ended.owners.filter({ $0.sends == 1 }) {
                try expect(probe.late.wait(timeout: .now() + 1) == .success,
                           "父期限 mode \(mode) 缺少已发送 owner 的 late/drain；\(ledger.snapshot.diagnostics())")
            }
            // Keep all three approved IDs for each observation: querying a
            // subset would remove the omitted candidates' health records.
            // Seven total order reads remain below the exploration cadence.
            let orders = parentDeadlinePermutations.map { permutation in
                selector.orderedCandidates(scopeKey: approved.scopeKey, candidateIDs: permutation.map { ids[$0] })
                    .map { ids.firstIndex(of: $0) ?? -1 }
            }
            let rtts = ids.map { selector.knownLatencyMilliseconds(scopeKey: approved.scopeKey, candidateID: $0) }
            let callbacks = probe.snapshot, concurrency = probe.concurrency
            let outcome = ParentDeadlineOutcome(ledger: ledger.snapshot, orders: orders, rtts: rtts,
                sent: callbacks.attempts.count, cancelled: concurrency.cancelled, active: concurrency.active,
                peak: concurrency.peak, answers: callbacks.answers.count, pending: coordinator.statistics.pendingQueries)
            if let failure = parentDeadlineOracle(outcome) {
                throw Failure(text: "parent deadline owner oracle: \(failure); \(outcome.ledger.diagnostics())")
            }
        }

        // One expired ingress lease cannot expire single-flight followers.
        let coordinator = DNSQueryCoordinator(timeout: .milliseconds(600))
        let selector = DNSAdaptiveUpstreamSelector(), lifecycle = AdaptiveProbe()
        let leader = AdaptiveProbe(), follower = AdaptiveProbe()
        let first = try query("adaptive-expired-leader.example.test", 1, id: 0x7101)
        let second = try query("adaptive-expired-leader.example.test", 1, id: 0x7102)
        let leaderFlow = DNSCoalescedQueryDatagram(coordinator: coordinator, scope: approved.scopeKey,
            queue: .global(), permitted: { true }, factory: { queue, receive, failure in
                DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                    scopeKey: approved.scopeKey, queue: queue, permitted: { true },
                    factory: { candidate, queue, receive, _ in
                        AdaptiveMemoryTransport(send: { data in
                            lifecycle.attempted(candidate)
                            if candidate.id == ids[0], let reply = bootstrapAnswer(data) {
                                queue.asyncAfter(deadline: .now() + 0.3) { receive(reply) }
                            }
                        }, cancel: lifecycle.transportCancelled)
                    }, receive: receive, failure: failure, timeout: 0.6)
            }, receive: leader.received, failure: leader.failed)
        defer { leaderFlow.cancel() }; leaderFlow.send(first)
        try expect(lifecycle.started.wait(timeout: .now() + 1) == .success, "single-flight leader 未开始")
        let followerFlow = DNSCoalescedQueryDatagram(coordinator: coordinator, scope: approved.scopeKey,
            queue: .global(), permitted: { true }, factory: { _, _, _ in
                throw Failure(text: "同问题 follower 启动第二个 adaptive")
            }, receive: follower.received, failure: follower.failed)
        defer { followerFlow.cancel() }; followerFlow.send(second)
        let joinDeadline = ProcessInfo.processInfo.systemUptime + 1
        while coordinator.statistics.waitingClients < 2 && ProcessInfo.processInfo.systemUptime < joinDeadline {
            Thread.sleep(forTimeInterval: 0.001)
        }
        try expect(coordinator.statistics.waitingClients == 2, "single-flight follower 未加入")
        try expect(lifecycle.started.wait(timeout: .now() + 1) == .success, "single-flight hedge 未开始")
        leaderFlow.queryDeadlineReached()
        try awaitAdaptive(follower, query: second)
        try expect(leader.snapshot.answers.isEmpty && leader.snapshot.error == nil
                   && lifecycle.concurrency.cancelled == 2
                   && selector.knownLatencyMilliseconds(scopeKey: approved.scopeKey, candidateID: ids[0]) != nil,
                   "单个过期 lease 取消 follower 或误记仍有所有者的健康交换为 timeout")
    }

    private final class AdaptiveBurstProbe {
        let lock = NSLock(), done = DispatchGroup()
        private var expected: [UInt16: Data] = [:], responses: [UInt16: Data] = [:]
        private var callbacks: [UInt16: Int] = [:], active: [UInt16: Int] = [:]
        private var attempts: [String: Int] = [:]
        private var failed = 0, invalid = 0, peak = 0
        func expectQuery(_ query: Data) -> UInt16 {
            let id = UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1])
            lock.lock(); expected[id] = query; lock.unlock(); done.enter(); return id
        }
        func attempted(_ candidate: DNSUpstreamCandidate, id: UInt16) {
            lock.lock(); attempts[candidate.upstream.target.host, default: 0] += 1
            active[id, default: 0] += 1; peak = max(peak, active[id]!); lock.unlock()
        }
        func cancelled(_ id: UInt16) {
            lock.lock(); active[id, default: 0] -= 1
            if active[id]! < 0 { invalid += 1 }; lock.unlock()
        }
        func completed(_ answer: Data?, id: UInt16) {
            lock.lock(); callbacks[id, default: 0] += 1
            let first = callbacks[id] == 1
            if !first { invalid += 1 }
            if let answer, let query = expected[id], DNSMessageInspection.responseMatchesQuery(answer, query: query) {
                responses[id] = answer
            } else { failed += 1 }
            lock.unlock(); if first { done.leave() }
        }
        var snapshot: (responses: Int, failed: Int, invalid: Int, peak: Int, active: Int, attempts: [String: Int]) {
            lock.lock(); defer { lock.unlock() }
            return (responses.count, failed, invalid, peak, active.values.reduce(0, +), attempts)
        }
    }

    private static func adaptiveHealthScopeIsolationAndBurst() throws {
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        // Force the original cache/pool scope to observe every source port.
        profile.rules.insert(RoutingRule(kind: .sourcePort(41001...41001), policy: "REJECT", sourceLine: 0), at: 0)
        profile.rules.insert(RoutingRule(kind: .logicalAnd([.sourcePort(52000...52000),
            .ipCIDR("203.0.113.71/32")]), policy: "REJECT", sourceLine: 0), at: 0)
        let source = router(profile)
        let original = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 50000, inboundPort: 7263)
        let first = try plan(source, original: original)
        for change in 0..<5 {
            var other = original
            switch change {
            case 0: other.sourcePort = 50001
            case 1: other.sourceHost = "192.0.2.2"
            case 2: other.inboundPort = 7264
            case 3: other.protocolName = "TCP"
            default: other.host = "203.0.113.54"
            }
            let next = try plan(source, original: other)
            try expect(next.scopeKey != first.scopeKey && next.healthScopeKey == first.healthScopeKey,
                       "共享健康状态放宽了 cache/单飞 scope 或同出站路径仍被来源碎片化")
        }
        var deniedPort = original; deniedPort.sourcePort = 41001
        try refusal(source, name: "allowed.example.test", type: 1, original: deniedPort)
        var filtered = original; filtered.sourcePort = 52000
        let filteredPlan = try plan(source, original: filtered)
        try expect(filteredPlan.candidates.count == 2 && filteredPlan.healthScopeKey != first.healthScopeKey,
                   "健康状态跨不同 source 策略批准集合共享")
        let snapshot = DNSRoutingSnapshot(profile: profile, mode: .rule, globalPolicy: "DIRECT", selections: [:],
            generation: first.generation, sourcePortSensitive: true)
        let providers = first.candidates.map(\.upstream)
        let otherNode = ProxyPolicy(name: "HealthOtherNode", kind: .http, host: "127.0.0.1", port: 1)
        try expect(snapshot.healthScope(upstreams: providers, route: .http(otherNode, otherNode.name),
                   interfaceName: first.interfaceName) != first.healthScopeKey,
                   "健康状态跨不同选定 node/route 共享")
        try expect(snapshot.healthScope(upstreams: providers, route: first.route,
                   interfaceName: "en-health-fixture") != first.healthScopeKey,
                   "健康状态跨物理接口共享")

        let trace = AdaptiveBurstProbe(), queue = DispatchQueue(label: "app.hajimi.dns.health-scope-burst-self-test")
        var fullScopes = Set<String>(), healthScopes = Set<String>(), flows: [NativeRoutedDatagram] = []
        for index in 0..<64 {
            var target = original; target.sourcePort = UInt16(50000 + index)
            let message = try query("adaptive-burst-\(index).example.test", 1, id: UInt16(0x8100 + index))
            guard case .upstream(let decision) = try source.prepareDNSQuery(message, original: target) else {
                throw Failure(text: "共享健康 burst 被意外合成")
            }
            fullScopes.insert(decision.scopeKey); healthScopes.insert(decision.healthScopeKey)
            let id = trace.expectQuery(message)
            let flow = try source.makeOptimizedDNSUpstream(plan: decision, queue: queue,
                adaptiveFactory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        trace.attempted(candidate, id: id)
                        if candidate.upstream.target.host == "203.0.113.72", let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.01) { receive(reply) }
                        }
                    }, cancel: { trace.cancelled(id) })
                }, adaptiveTimeout: 0.45, receive: { trace.completed($0, id: id) },
                failure: { _ in trace.completed(nil, id: id) })
            flows.append(flow); flow.send(message)
        }
        try expect(fullScopes.count == 64 && healthScopes.count == 1,
                   "64 来源端口没有保持独立缓存 scope/单一健康 path")
        try expect(trace.done.wait(timeout: .now() + 2) == .success, "64 跨来源健康 burst 未完成")
        let result = trace.snapshot
        try expect(result.responses == 64 && result.failed == 0 && result.invalid == 0
                   && result.peak <= 2 && result.active == 0
                   && result.attempts["203.0.113.72"] == 64
                   && result.attempts.values.reduce(0, +) <= 192,
                   "前两个 provider 沉默仍饿死第三候选、超过 2 live/3 attempts 或跨 ID 回包")
        flows.forEach { $0.cancel() }

        // New client tuples get the learned preference, not another client's
        // answer or transport: strict source scopes still require an exchange.
        for index in 0..<4 {
            var target = original
            target.host = "203.0.113.54"; target.protocolName = "TCP"; target.sourcePort = UInt16(52100 + index)
            target.sourceHost = "192.0.2.\(index + 2)"; target.inboundPort = 7264
            let message = try query("adaptive-burst-0.example.test", 1, id: UInt16(0x8200 + index))
            let decision = try plan(source, name: "adaptive-burst-0.example.test", original: target)
            try expect(!fullScopes.contains(decision.scopeKey) && decision.healthScopeKey == first.healthScopeKey,
                       "新的来源直接复用了旧 cache/单飞 scope")
            let probe = AdaptiveProbe()
            let flow = try adaptiveExchange(source, plan: decision, message: message, probe: probe) { candidate, worker, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    probe.attempted(candidate)
                    if let reply = bootstrapAnswer(data) { worker.async { receive(reply) } }
                }, cancel: probe.transportCancelled)
            }
            defer { flow.cancel() }; try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts == ["203.0.113.72"],
                       "新来源丢失同出站健康择优或借健康状态跳过真实交换")
        }
        profile.rules.insert(RoutingRule(kind: .domain("blocked.health.example.test"), policy: "REJECT", sourceLine: 0), at: 0)
        source.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
        try expect(try plan(source, original: original).healthScopeKey != first.healthScopeKey,
                   "健康状态跨配置代次共享")
        try refusal(source, name: "blocked.health.example.test", type: 1, original: original)
        withExtendedLifetime(flows) {}
        print("DNS health-scope burst passed: 64 strict source scopes / 1 health path, 64 replies, at most 2 live / 3 attempts")
    }

    private static func adaptiveHedgeRotation() throws {
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let approved = try plan(router(profile)), ids = approved.candidates.map(\.id)
        let scope = approved.healthScopeKey
        // The primary survives a rotated hedge and may still win late.
        do {
            let clock = AdaptiveManualClock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let probe = AdaptiveProbe(), reply = AdaptiveManualReply(), absolute = clock.now() + 0.45
            let message = try query("rotation-primary-retained.example.test", 1)
            weak var checkpointFlow: DNSAdaptiveQueryDatagram?
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, _, receive, _ in
                    checkpointFlow?.pauseAdaptiveTimersForSelfTest()
                    return AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[0], let answer = bootstrapAnswer(data) {
                            reply.prepare { receive(answer) }
                        }
                    }, cancel: {
                        if candidate.id == ids[0] { reply.recordCancellation() }
                        probe.transportCancelled()
                    })
                }, receive: probe.received, failure: probe.failed, timeout: 0.45,
                absoluteDeadline: absolute, clock: clock.now)
            checkpointFlow = flow
            defer { flow.cancel() }; flow.send(message); flow.drainAdaptiveQueueForSelfTest()
            clock.advance(to: 0.15)
            try expect(flow.fireAdaptiveHedgeForSelfTest(), "primary 保留夹具没有装载原生 hedge callback")
            clock.advance(to: 0.3)
            try expect(flow.fireAdaptiveRotationForSelfTest(), "primary 保留夹具没有装载原生 rotation callback")
            try expect(probe.snapshot.attempts.count == 3 && probe.concurrency.active == 2
                       && probe.concurrency.cancelled == 1 && !reply.wasCancelled,
                       "轮替时未只退役 hedge，或提前取消仍可成功的 primary")
            clock.advance(to: 0.39)
            try expect(reply.release(), "轮替保留的 primary 没有可交付答复")
            try awaitAdaptive(probe, query: message)
            let state = flow.adaptiveStateForSelfTest
            try expect(probe.snapshot.attempts.count == 3 && probe.concurrency.peak == 2
                       && probe.concurrency.cancelled == 3 && probe.concurrency.active == 0
                       && state.attempts == 3 && state.active == 0 && state.started == 100
                       && state.deadline == absolute && clock.now() < absolute,
                       "轮替取消了仍可成功的慢 primary")
        }
        // Retirement is not a network error. Both an error delivered from
        // cancel() and a later valid old-hedge answer are obsolete tokens.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let message = try query("rotation-late-token.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        guard var reply = bootstrapAnswer(data) else { return }
                        reply[reply.count - 1] = candidate.id == ids[2] ? 79 : 78
                        let response = reply
                        if candidate.id == ids[1] {
                            worker.asyncAfter(deadline: .now() + 0.23) { receive(response); probe.late.signal() }
                        } else if candidate.id == ids[2] {
                            worker.asyncAfter(deadline: .now() + 0.01) { receive(response) }
                        }
                    }, cancel: {
                        probe.transportCancelled()
                        if candidate.id == ids[1] { failure(EngineError("退役 hedge 的同步取消回调")) }
                    })
                }, receive: probe.received, failure: probe.failed, timeout: 0.45)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success
                       && DNSMessageInspection.addressAnswers(in: probe.snapshot.answers[0]).map(\.address) == ["203.0.113.79"]
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 3,
                       "late retired reply/error 复活或覆盖第三候选答案")
            // The two never-successful losers still tie at their prior score:
            // a cancellation error would have incorrectly cooled the hedge.
            try expect(selector.orderedCandidates(scopeKey: scope, candidateIDs: [ids[1], ids[0]]).first == ids[1],
                       "退役 hedge 被伪记网络失败或 cooldown")
        }
        for knownMilliseconds: Double in [10, 300] {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            selector.record(scopeKey: scope, candidateID: ids[0], milliseconds: 1, success: true)
            selector.record(scopeKey: scope, candidateID: ids[1], milliseconds: knownMilliseconds, success: true)
            selector.record(scopeKey: scope, candidateID: ids[2], milliseconds: 1000, success: true)
            let slowWorking = knownMilliseconds == 300
            let message = try query("rotation-known-\(Int(knownMilliseconds)).example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        guard let reply = bootstrapAnswer(data) else { return }
                        if slowWorking, candidate.id == ids[1] {
                            worker.asyncAfter(deadline: .now() + 0.24) { receive(reply) }
                        } else if !slowWorking, candidate.id == ids[2] { worker.async { receive(reply) } }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 0.45)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts.count == (slowWorking ? 2 : 3)
                       && probe.concurrency.peak == 2,
                       "已知慢 hedge 被剪掉或曾经快但现沉默的 hedge 仍饿死第三候选")
        }
        // A new concurrent RTT observation must extend the pending hedge's
        // headroom even after its short rotation timer was already scheduled.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let message = try query("rotation-new-slow-rtt.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[1], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.02) {
                                selector.record(scopeKey: scope, candidateID: candidate.id, milliseconds: 300, success: true)
                            }
                            worker.asyncAfter(deadline: .now() + 0.24) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 0.45)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts.count == 2, "旧 rotation timer 剪掉刚测得慢 RTT 的健康 hedge")
        }
        // A refusal delivered by the third approved provider is terminal;
        // rotating the slot cannot turn it into provider-shopping.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let message = try query("rotation-terminal-refused.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[0], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.4) { receive(reply); probe.late.signal() }
                        } else if candidate.id == ids[2], let refusal = DNSMessageInspection.errorResponse(to: data, code: .refused) {
                            worker.async { receive(refusal) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 0.45)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success && probe.snapshot.answers.count == 1
                       && probe.snapshot.answers[0][3] & 0x0f == 5 && probe.snapshot.attempts.count == 3,
                       "第三 provider REFUSED 后继续接受旧 positive 或多开候选")
        }
        // A third provider's warm RTT must not turn into a cold-connection
        // timeout for the live hedge. Both known and unknown third providers
        // retain the conservative 8s * 2/3 rotation boundary.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            for (index, milliseconds) in [1.0, 10.0, 100.0].enumerated() {
                selector.record(scopeKey: scope, candidateID: ids[index], milliseconds: milliseconds, success: true)
            }
            let message = try query("rotation-measured-third-eight-second.example.test", 1)
            let started = ProcessInfo.processInfo.systemUptime
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[2], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.1) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 8,
                absoluteDeadline: started + 8)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message, waitTimeout: 7)
            let elapsed = ProcessInfo.processInfo.systemUptime - started
            try expect(elapsed >= 8.0 * (2.0 / 3.0) && elapsed < 8
                       && probe.snapshot.attempts.count == 3 && probe.snapshot.answers.count == 1
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 3,
                       "第三候选成功 RTT 仍提前取消冷 hedge，或突破原期限/2 live/3 attempt")
            print("DNS measured-third conservative rotation: parent=8000ms, rotation=5333ms, elapsed=\(Int(elapsed * 1000))ms, attempts=3, live-peak=2")
        }
        // A measured slow-but-working hedge keeps RTT headroom even though a
        // measured third path is available. Warm history cannot replace that
        // currently working path before its conservative rotation boundary.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            for (index, milliseconds) in [1.0, 500.0, 1000.0].enumerated() {
                selector.record(scopeKey: scope, candidateID: ids[index], milliseconds: milliseconds, success: true)
            }
            let message = try query("rotation-slow-measured-hedge-eight-second.example.test", 1)
            let started = ProcessInfo.processInfo.systemUptime
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[1], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.6) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 8,
                absoluteDeadline: started + 8)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts.count == 2 && probe.snapshot.answers.count == 1
                       && probe.concurrency.peak == 2,
                       "加速第三候选剪掉仍在测得 RTT 裕量内的合法慢 hedge")
        }
        // Warm RTT must not act as a cold TCP/TLS setup timeout. A backup
        // previously measured at 10ms may need 400/800ms for a fresh carrier;
        // replacing it with the known 1000ms third path would only add work.
        for setupSeconds in [0.4, 0.8] {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            for (index, milliseconds) in [1.0, 10.0, 1000.0].enumerated() {
                selector.record(scopeKey: scope, candidateID: ids[index], milliseconds: milliseconds, success: true)
            }
            let message = try query("rotation-warm-to-cold-\(Int(setupSeconds * 1000)).example.test", 1)
            let started = ProcessInfo.processInfo.systemUptime
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[1], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + setupSeconds) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 8,
                absoluteDeadline: started + 8)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts.count == 2 && probe.snapshot.answers.count == 1
                       && probe.concurrency.peak == 2,
                       "暖 RTT 被当作冷握手超时，剪掉 \(Int(setupSeconds * 1000))ms 合法 backup")
        }
        try adaptiveWarmHistoryColdPhase(approved: approved)
    }

    private static func adaptiveWarmHistoryColdPhase(approved: DNSQueryPlan) throws {
        let ids = approved.candidates.map(\.id), scope = approved.healthScopeKey
        // These are synthetic historical successes and a memory response
        // delay, not measured TLS. The production parent/child state machines
        // retain the real 8s deadline and default 3s encrypted phase window.
        let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe(), gate = AdaptivePolicyGate()
        _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
        for (index, milliseconds) in [1.0, 10.0, 100.0].enumerated() {
            selector.record(scopeKey: scope, candidateID: ids[index], milliseconds: milliseconds, success: true)
        }
        try expect(selector.orderedCandidates(scopeKey: scope, candidateIDs: ids) == ids,
                   "冷连接回归改变了候选顺序")
        let message = try query("rotation-warm-history-cold-phase.example.test", 1)
        let lock = NSLock(), worker = DispatchQueue(label: "app.hajimi.dns.cold-phase-self-test", qos: .userInitiated)
        var fallbackCalls = 0, hedgeReady = false, cancelledHedgeBeforeReady = false
        let started = ProcessInfo.processInfo.systemUptime
        let flow = DNSProxyFallbackQueryDatagram(queue: worker, absoluteDeadline: started + 8,
            permitted: gate.permits, knownMilliseconds: {
                ids.compactMap { selector.knownLatencyMilliseconds(scopeKey: scope, candidateID: $0) }
            }, encrypted: { queue, absolute, receive, failure in
                DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                    queue: queue, permitted: gate.permits, factory: { candidate, queue, receive, _ in
                        AdaptiveAcknowledgedMemoryTransport(send: { data in
                            probe.attempted(candidate)
                            guard candidate.id == ids[1], let answer = bootstrapAnswer(data) else { return }
                            queue.asyncAfter(deadline: .now() + 2.3) {
                                lock.lock(); hedgeReady = true; lock.unlock()
                                receive(answer)
                            }
                        }, cancel: {
                            lock.lock()
                            if candidate.id == ids[1] && !hedgeReady { cancelledHedgeBeforeReady = true }
                            lock.unlock(); probe.transportCancelled()
                        })
                    }, receive: receive, failure: failure, timeout: 8,
                    absoluteDeadline: absolute, protectProxyFallback: true)
            }, fallback: { _, absolute, _, failure in
                lock.lock(); fallbackCalls += 1; lock.unlock()
                return AdaptiveAcknowledgedMemoryTransport(send: { _ in
                    failure(absolute > ProcessInfo.processInfo.systemUptime
                        ? EncryptedDNSQueryFailure.network : DNSQueryTimeoutError())
                })
            }, receive: probe.received, failure: probe.failed)
        defer { flow.cancel() }
        flow.send(message); try awaitAdaptive(probe, query: message, waitTimeout: 4)
        let elapsed = ProcessInfo.processInfo.systemUptime - started
        let acknowledged = DispatchSemaphore(value: 0)
        flow.cancel { acknowledged.signal() }
        try expect(acknowledged.wait(timeout: .now() + 1) == .success, "冷连接回归未完成取消 ACK")
        lock.lock(); let fallbackCount = fallbackCalls, clipped = cancelledHedgeBeforeReady; lock.unlock()
        try expect(elapsed >= 2.3 && elapsed < 3 && !clipped && fallbackCount == 0
                   && probe.snapshot.attempts == approved.candidates.prefix(2).map { $0.upstream.target.host }
                   && probe.snapshot.answers.count == 1 && probe.concurrency.peak == 2
                   && probe.concurrency.active == 0 && probe.concurrency.cancelled == 2,
                   "快历史剪掉 2.3s 冷 hedge、触发不必要回退或突破并发/取消约束")
        // Client cancellation and permission revocation still reject an old
        // answer before it can revive history, deliver data or start fallback.
        for revoke in [false, true] {
            let stopped = AdaptiveProbe(), permission = AdaptivePolicyGate()
            let callbackLock = NSLock(); var late: (() -> Void)?
            let forbiddenFallback = DispatchSemaphore(value: 0)
            let pending = DNSProxyFallbackQueryDatagram(queue: worker,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8,
                permitted: permission.permits, knownMilliseconds: { [1, 10, 100] }, encrypted: { queue, absolute, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: DNSAdaptiveUpstreamSelector(),
                        scopeKey: scope, queue: queue, permitted: permission.permits,
                        factory: { candidate, queue, receive, _ in
                            AdaptiveAcknowledgedMemoryTransport(send: { data in
                                callbackLock.lock()
                                late = { queue.async { receive(bootstrapAnswer(data)!) } }
                                callbackLock.unlock(); stopped.attempted(candidate)
                            }, cancel: stopped.transportCancelled)
                        }, receive: receive, failure: failure, absoluteDeadline: absolute, protectProxyFallback: true)
                }, fallback: { _, _, _, _ in
                    forbiddenFallback.signal(); return AdaptiveAcknowledgedMemoryTransport(send: { _ in })
                }, receive: stopped.received, failure: stopped.failed)
            defer { pending.cancel() }
            pending.send(message)
            try expect(stopped.started.wait(timeout: .now() + 1) == .success, "待撤销加密阶段未启动")
            if revoke { permission.revoke() }
            else {
                let cancelled = DispatchSemaphore(value: 0); pending.cancel { cancelled.signal() }
                try expect(cancelled.wait(timeout: .now() + 1) == .success, "客户端取消缺少 ACK")
            }
            callbackLock.lock(); let deliverLate = late; callbackLock.unlock(); deliverLate?()
            if revoke { try awaitAdaptive(stopped, query: message, expectFailure: true) }
            else { try expect(stopped.done.wait(timeout: .now() + 0.05) == .timedOut, "取消后仍交付结果") }
            try expect(stopped.snapshot.answers.isEmpty && forbiddenFallback.wait(timeout: .now()) == .timedOut,
                       "撤销后旧答案恢复或启动了未授权回退")
        }
        print("DNS warm-history cold-phase regression: memory-delay=2300ms, elapsed=\(Int(elapsed * 1000))ms, fallback=0, attempts=2, live-peak=2, cancel/policy fenced")
    }

    private static func adaptiveQueuedAbsoluteDeadlines() throws {
        let profile = adaptiveProfile(), source = router(profile), approved = try plan(source)
        let queue = DispatchQueue(label: "app.hajimi.dns.absolute-deadline-self-test")
        // The real coordinator must not even enter a queued/expired factory,
        // and the typed failure must be recorded once as a timeout.
        do {
            let message = try query("adaptive-expired-before-factory.example.test", 1)
            let probe = AdaptiveProbe(), construction = BootstrapProbe()
            let before = NetworkPerformanceDiagnostics.shared.snapshot().dnsFailureReasons[.timeout, default: 0]
            let flow = try source.makeOptimizedDNSUpstream(plan: approved, queue: queue, factory: { _, _, _ in
                construction.lock.lock(); construction.builds += 1; construction.lock.unlock()
                return BootstrapMemoryTransport { _ in }
            }, queryDeadline: ProcessInfo.processInfo.systemUptime - 0.01,
                receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: true)
            construction.lock.lock(); let builds = construction.builds; construction.lock.unlock()
            let after = NetworkPerformanceDiagnostics.shared.snapshot().dnsFailureReasons[.timeout, default: 0]
            try expect(builds == 0 && after == before + 1, "已过期的 queued factory 仍建连或误记通用失败")
        }
        // Setup work may consume the remaining budget after the entry guard.
        // Its returned transport is canceled without sending the DNS query.
        do {
            let message = try query("adaptive-expired-in-factory.example.test", 1)
            let probe = AdaptiveProbe(), construction = BootstrapProbe()
            let lock = NSLock(); var sends = 0, cancels = 0
            let flow = try source.makeOptimizedDNSUpstream(plan: approved, queue: queue, factory: { _, _, _ in
                construction.lock.lock(); construction.builds += 1; construction.lock.unlock()
                Thread.sleep(forTimeInterval: 0.25)
                return AdaptiveMemoryTransport(send: { _ in lock.lock(); sends += 1; lock.unlock() },
                    cancel: { lock.lock(); cancels += 1; lock.unlock() })
            }, queryDeadline: ProcessInfo.processInfo.systemUptime + 0.2,
                receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: true)
            lock.lock(); let sent = sends, closed = cancels; lock.unlock()
            construction.lock.lock(); let builds = construction.builds; construction.lock.unlock()
            try expect(builds == 1 && sent == 0 && closed == 1,
                       "factory 消耗完 absolute budget 后仍发送查询或未释放 transport")
        }
        var three = profile
        three.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let decision = try plan(router(three)), ids = decision.candidates.map(\.id)
        for expired in [true, false] {
            let blocked = DispatchQueue(label: "app.hajimi.dns.blocked-deadline-self-test")
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            blocked.async { entered.signal(); _ = release.wait(timeout: .now() + 2) }
            try expect(entered.wait(timeout: .now() + 1) == .success, "absolute deadline fixture 未阻塞其队列")
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let message = try query(expired ? "adaptive-expired-on-send.example.test" : "adaptive-remaining-rotation.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let deadline = began + (expired ? 0.05 : 0.9)
            let flow = DNSAdaptiveQueryDatagram(candidates: decision.candidates, selector: selector,
                scopeKey: decision.healthScopeKey, queue: blocked, permitted: { true },
                factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[2], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.01) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 8, absoluteDeadline: deadline)
            defer { flow.cancel() }; flow.send(message)
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) { release.signal() }
            try awaitAdaptive(probe, query: message, expectFailure: expired)
            if expired {
                try expect(probe.snapshot.attempts.isEmpty && selector.usage.scopes == 0
                           && probe.snapshot.error is DNSQueryTimeoutError,
                           "send 队列延误后重新给了 8s 或仍拨号/写入健康状态")
            } else {
                try expect(probe.snapshot.attempts.count == 3 && probe.concurrency.peak == 2
                           && ProcessInfo.processInfo.systemUptime - began < 0.85,
                           "排队后 rotation 未按真实剩余预算运行或超过 parent absolute deadline")
            }
        }
    }

    private final class BootstrapProbe {
        let lock = NSLock(), done = DispatchSemaphore(value: 0)
        let started = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
        var names: [String] = [], payloads: [Data] = [], builds = 0
        var error: Error?
        func record(_ name: String) { lock.lock(); names.append(name); lock.unlock() }
        func fail(_ error: Error) { lock.lock(); self.error = error; lock.unlock(); done.signal() }
    }
    private final class BootstrapMemoryTransport: NativeRoutedDatagram {
        let onSend: (Data) -> Void
        init(_ onSend: @escaping (Data) -> Void) { self.onSend = onSend }
        func send(_ data: Data) { onSend(data) }
        func cancel() {}
    }
    private static func bootstrapAnswer(_ query: Data) -> Data? {
        guard let question = DNSMessageInspection.singleQuestion(in: query) else { return nil }
        var answer = Data(query.prefix(question.questionEnd))
        answer[2] = 0x81; answer[3] = 0x80
        for offset in 6...11 { answer[offset] = 0 }
        if question.type == 1 {
            answer[7] = 1
            answer.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 77])
        }
        return answer
    }

    private static func asynchronousBootstrap() throws {
        var profile = Profile()
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                               adapterType: "trojan", parameters: ["password": "test"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        profile.dnsServers = ["203.0.113.60:5353"]
        profile.encryptedDNSServers = ["https://doh.bootstrap.selftest.invalid/dns-query"]
        let source = router(profile), decision = try plan(source, name: "private.user.example.test", type: 65)
        guard case .doh(let endpoint) = decision.upstream else { throw Failure(text: "引导测试端点不是 DoH") }
        let probe = BootstrapProbe(), queue = DispatchQueue(label: "app.hajimi.dns.bootstrap-routing-test")
        let wire: TraditionalDNSWireExchange = { _, query, queue, completion in
            guard let question = DNSMessageInspection.singleQuestion(in: query), let reply = bootstrapAnswer(query) else {
                queue.async { completion(.failure(Failure(text: "传统引导问题无效"))) }; return {}
            }
            probe.record(question.name)
            queue.async { completion(.success(reply)) }
            return {}
        }
        let resolver = try source.bootstrapResolver(for: decision, exchange: wire)
        try expect(try source.bootstrapResolver(for: decision, exchange: wire) === resolver,
                   "同用途/代次/接口的 DoH 引导解析器未复用")
        let original = try query("private.user.example.test", 65)
        let gateway = DoHBootstrapDatagram(endpoint: endpoint, resolver: resolver, queue: queue,
            permitted: { source.isCurrentDNSGeneration(decision.generation) }, makeEncrypted: { address in
                let resolved = try source.resolvedBootstrapPlan(decision, address: address)
                try expect(resolved.route == decision.route && resolved.upstream.identityHost == endpoint.host
                           && resolved.upstream.target.host == "203.0.113.77" && resolved.bootstrap == nil,
                           "引导改变 TLS 身份、所选代理或仍使用主机名拨号")
                probe.lock.lock(); probe.builds += 1; probe.lock.unlock()
                return BootstrapMemoryTransport { data in
                    probe.lock.lock(); probe.payloads.append(data); probe.lock.unlock(); probe.done.signal()
                }
            }, failure: probe.fail)
        gateway.send(original)
        guard probe.done.wait(timeout: .now() + 2) == .success else { throw Failure(text: "内存 DoH 引导未完成") }
        probe.lock.lock(); let error = probe.error, names = probe.names, payloads = probe.payloads; probe.lock.unlock()
        if let error { throw error }
        try expect(!names.isEmpty && names.allSatisfy { $0 == endpoint.host } && payloads == [original],
                   "普通应用 QNAME 泄入传统 DNS 或原查询未只交加密传输")
        gateway.cancel()

        let denied = DispatchSemaphore(value: 0)
        let id = resolver.resolveDoHHost("private.user.example.test", queue: queue) { result in
            if case .failure = result { denied.signal() }
        }
        try expect(id == nil && denied.wait(timeout: .now() + 2) == .success,
                   "引导解析器允许调用任意应用域名")
        probe.lock.lock(); let namesAfterDenied = probe.names; probe.lock.unlock()
        try expect(namesAfterDenied == names, "白名单拒绝仍产生传统 DNS 交换")

        // Hold a memory wire transaction so update must cancel the actual
        // cached resolver, not merely ignore a late application response.
        let pendingSource = router(profile), pendingPlan = try plan(pendingSource)
        let pending = BootstrapProbe()
        let heldWire: TraditionalDNSWireExchange = { _, query, _, _ in
            if let question = DNSMessageInspection.singleQuestion(in: query) { pending.record(question.name) }
            pending.started.signal(); return { pending.cancelled.signal() }
        }
        let old = try pendingSource.bootstrapResolver(for: pendingPlan, exchange: heldWire)
        let waiting = DoHBootstrapDatagram(endpoint: endpoint, resolver: old, queue: queue,
            permitted: { pendingSource.isCurrentDNSGeneration(pendingPlan.generation) },
            makeEncrypted: { _ in
                pending.lock.lock(); pending.builds += 1; pending.lock.unlock()
                return BootstrapMemoryTransport { _ in pending.done.signal() }
            }, failure: pending.fail)
        waiting.send(original)
        guard pending.started.wait(timeout: .now() + 2) == .success else { throw Failure(text: "待取消引导未启动") }
        pendingSource.update(profile: profile, mode: .rule, globalPolicy: node.name, groupSelections: [:])
        try expect(pending.cancelled.wait(timeout: .now() + 2) == .success
                   && pending.done.wait(timeout: .now() + 2) == .success,
                   "策略更新没有撤销旧引导请求")
        pending.lock.lock(); let builds = pending.builds; pending.lock.unlock()
        try expect(builds == 0, "旧引导完成后仍构建应用加密查询")
        let replacement = try pendingSource.bootstrapResolver(for: plan(pendingSource), exchange: heldWire)
        try expect(replacement !== old, "配置更新复用已失效引导解析器")
        waiting.cancel(); replacement.cancel(); resolver.cancel()

        let cancelled = BootstrapProbe()
        let cancelResolver = TraditionalDNSBootstrapResolver(servers: profile.traditionalDNSServers,
            allowedDoHHosts: [endpoint.host], timeout: 4, exchange: { _, _, _, _ in
                cancelled.started.signal(); return { cancelled.cancelled.signal() }
            })
        let cancelGateway = DoHBootstrapDatagram(endpoint: endpoint, resolver: cancelResolver, queue: queue,
            permitted: { true }, makeEncrypted: { _ in
                cancelled.lock.lock(); cancelled.builds += 1; cancelled.lock.unlock()
                return BootstrapMemoryTransport { _ in }
            }, failure: cancelled.fail)
        cancelGateway.send(original)
        guard cancelled.started.wait(timeout: .now() + 2) == .success else { throw Failure(text: "可取消引导未启动") }
        cancelGateway.cancel()
        try expect(cancelled.cancelled.wait(timeout: .now() + 2) == .success, "单 flow 取消未撤销自己的引导事务")
        cancelled.lock.lock(); let cancelBuilds = cancelled.builds; cancelled.lock.unlock()
        try expect(cancelBuilds == 0, "已取消引导仍送出普通 QNAME")
        cancelResolver.cancel()
    }

    private static func frame(_ query: Data) -> Data {
        var framed = Data([UInt8(query.count >> 8), UInt8(query.count & 0xff)])
        framed.append(query); return framed
    }
    private static func framing() throws {
        let first = try query("first.example.test", 1), second = try query("second.example.test", 65)
        let bytes = frame(first) + frame(second)
        var framer = DNSLengthFramer(), decoded: [Data] = []
        for byte in bytes { decoded += try framer.append(Data([byte])) }
        try expect(decoded == [first, second], "DNS TCP 单字节拆包/前缀未正确复原")
        var merged = DNSLengthFramer()
        try expect(try merged.append(bytes) == [first, second], "DNS TCP 合包未解析多个查询")
        for invalid in [Data([0, 0]), Data([0, 11]), Data(repeating: 0, count: 256 * 1_024 + 1)] {
            var bounded = DNSLengthFramer()
            do { _ = try bounded.append(invalid) }
            catch { continue }
            throw Failure(text: "DNS TCP 无效长度/超大输入未拒绝")
        }
        let maximum = Data(repeating: 0x41, count: 65_535)
        var maxFramer = DNSLengthFramer()
        try expect(try maxFramer.append(Data([0xff])).isEmpty, "DNS TCP 半前缀被当成整帧")
        try expect(try maxFramer.append(Data([0xff]) + maximum) == [maximum], "DNS TCP 最大帧长度边界错误")
    }

    private static func framedFakeIPRoundTrip() throws {
        var profile = Profile(); profile.fakeIPEnabled = true
        profile.proxies["Node"] = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                                             adapterType: "trojan", parameters: ["password": "test"])
        profile.rules = [RoutingRule(kind: .domain("blocked.example.test"), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .final, policy: "Node", sourceLine: 2)]
        let router = self.router(profile), queue = DispatchQueue(label: "app.hajimi.dns.framed-selftest")
        var stream: NativeOutboundByteStream?
        router.connectTCP(host: "203.0.113.53", port: 53, queue: queue) { result in
            if case .success(let value) = result { stream = value }
        }
        guard let stream else { throw Failure(text: "DNS TCP gateway 未建立") }
        defer { stream.cancel() }
        let a = try query("fake.example.test", 1, id: 1), aaaa = try query("fake.example.test", 28, id: 2)
        let denied = try query("blocked.example.test", 16, id: 3)
        let all = frame(a) + frame(aaaa) + frame(denied)
        let writes = DispatchGroup(), lock = NSLock()
        var failure: Error?
        for chunk in [Data(all.prefix(1)), Data(all.dropFirst(1).prefix(7)), Data(all.dropFirst(8))] {
            writes.enter(); stream.send(chunk) { error in
                if let error { lock.lock(); failure = error; lock.unlock() }; writes.leave()
            }
        }
        guard writes.wait(timeout: .now() + 2) == .success else { throw Failure(text: "DNS TCP 发送未完成") }
        lock.lock(); let writeError = failure; lock.unlock()
        if let writeError { throw writeError }
        let done = DispatchSemaphore(value: 0)
        var responses: [Data] = [], decoder = DNSLengthFramer(), receivedBytes = 0
        func read() {
            stream.receive(maximum: 3) { data, complete, error in
                if let error { failure = error; done.signal(); return }
                if let data {
                    receivedBytes += data.count
                    do { responses += try decoder.append(data) }
                    catch { failure = error; done.signal(); return }
                }
                if responses.count == 3 { done.signal(); return }
                if complete || receivedBytes > 1_024 { failure = Failure(text: "DNS TCP 回包截断或超限"); done.signal(); return }
                read()
            }
        }
        read()
        guard done.wait(timeout: .now() + 2) == .success else { throw Failure(text: "DNS TCP fake-IP 回包超时") }
        if let failure { throw failure }
        // DNS-over-TCP permits pipelined answers out of order. Refusals may
        // finish before queued local synthesis; correlate every payload with
        // its question rather than assuming a callback scheduling order.
        guard let aReply = responses.first(where: { DNSMessageInspection.responseMatchesQuery($0, query: a) }),
              let aaaaReply = responses.first(where: { DNSMessageInspection.responseMatchesQuery($0, query: aaaa) }),
              let deniedReply = responses.first(where: { DNSMessageInspection.responseMatchesQuery($0, query: denied) }) else {
            throw Failure(text: "DNS TCP 回包丢失或混淆查询 ID/身份")
        }
        let records = DNSMessageInspection.addressAnswers(in: aReply)
        try expect(records.count == 1 && FakeIPAllocator.isFake(records[0].address), "TCP A 查询没有 fake-IP")
        try expect(aaaaReply[aaaaReply.startIndex + 7] == 0 && aaaaReply[aaaaReply.startIndex + 3] & 0x0f == 0,
                   "TCP AAAA 查询未保持空 NOERROR")
        try expect(deniedReply[deniedReply.startIndex + 3] & 0x0f == 5, "TCP 非 A 查询绕过域名 REJECT")
    }
}

/// Only the private parent-deadline memory fixture reads these values. No
/// production path calls this accessor or receives a cancellation receipt.
private struct DNSParentDeadlineMemoryState {
    let finished: Bool, closed: Bool, deadlineSignalled: Bool, permitted: Bool
    let attempts: Int
    let activeCandidates: Set<Int>, retiredCandidates: Set<Int>
}

private extension DNSAdaptiveQueryDatagram {
    func parentDeadlineStateForMemorySelfTest() -> DNSParentDeadlineMemoryState {
        // The original factory supplies this exact serial owner queue. Never
        // queue.sync here, mutate the child, or manufacture a native ACK.
        dispatchPrecondition(condition: .onQueue(queue))
        admission.lock()
        let clientClosed = closed, expired = deadlineSignalled
        admission.unlock()
        return DNSParentDeadlineMemoryState(finished: finished, closed: clientClosed,
            deadlineSignalled: expired, permitted: permitted(), attempts: attemptCount,
            activeCandidates: Set(active.values.map { candidateIndex($0.candidate) }),
            retiredCandidates: Set(retired.map { candidateIndex($0.candidate) }))
    }
}

private enum DNSUpstream {
    static func parse(_ rawValue: String) -> (host: String, port: UInt16)? {
        var value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.lowercased() != "system" else { return nil }
        if value.lowercased().hasPrefix("udp://") { value.removeFirst(6) }
        // DoH and DoT entries are handled by their own resolvers; treating the
        // URL as a host:port pair here would send plaintext DNS to port 443.
        guard !value.contains("://"), !value.contains(where: { $0.isWhitespace }),
              !value.contains(where: { "/\\#?@;=".contains($0) }) else { return nil }
        if value.hasPrefix("[") , let close = value.firstIndex(of: "]") {
            let host = String(value[value.index(after: value.startIndex)..<close])
            guard DoHEndpoint.isAddressLiteral(host) else { return nil }
            let suffix = value[value.index(after: close)...]
            if suffix.isEmpty { return host.isEmpty ? nil : (host, 53) }
            guard suffix.first == ":", let port = UInt16(suffix.dropFirst()), port > 0 else { return nil }
            return host.isEmpty ? nil : (host, port)
        }
        if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":") {
            guard let port = UInt16(value[value.index(after: colon)...]), port > 0 else { return nil }
            let host = String(value[..<colon])
            return host.isEmpty ? nil : (host, port)
        }
        if value.contains(":"), !DoHEndpoint.isAddressLiteral(value) { return nil }
        if value.contains("[") || value.contains("]") { return nil }
        return (value, 53)
    }
}

public protocol NativeRoutedDatagram: DNSQueryDatagram {
    func send(_ data: Data)
    func cancel()
}

private final class DirectRoutedDatagram: NativeRoutedDatagram {
    typealias HostResolver = (String, @escaping (Result<[String], Error>) -> Void) -> Void
    private var connection: NWConnection?
    private let queue: DispatchQueue
    private let permitted: () -> Bool
    private let admission = NSLock()
    private var closed = false, admittedPackets = 0, admittedBytes = 0
    private let receiveHandler: (Data) -> Void
    private let failureHandler: (Error) -> Void
    private var pending: [Data] = []
    private var ready = false, stopped = false
    init(target: RequestTarget, queue: DispatchQueue, resolveHost: HostResolver? = nil,
         permitted: @escaping () -> Bool = { true },
         receive: @escaping (Data) -> Void,
         failure: @escaping (Error) -> Void) throws {
        guard let port = NWEndpoint.Port(rawValue: target.port) else { throw EngineError("UDP 端口无效") }
        self.queue = DispatchQueue(label: "app.hajimi.direct-datagram", target: queue)
        self.permitted = permitted
        receiveHandler = receive; failureHandler = failure
        if let resolveHost, !DoHEndpoint.isAddressLiteral(target.host) {
            resolveHost(target.host) { [weak self] result in
                self?.queue.async {
                    guard let self, !self.stopped else { return }
                    switch result {
                    case .failure(let error): self.fail(error)
                    case .success(let addresses):
                        guard let host = addresses.first, DoHEndpoint.isAddressLiteral(host) else {
                            self.fail(EngineError("DNS 未返回有效的 UDP 目标 IP")); return
                        }
                        self.start(host: host, port: port)
                    }
                }
            }
        } else { start(host: target.host, port: port) }
    }
    private func start(host: String, port: NWEndpoint.Port) {
        guard permitted() else { fail(EngineError("UDP 路由已更新，已阻止旧 DIRECT 套接字")); return }
        let parameters = NWParameters.udp
        parameters.requiredInterface = OutboundInterfaceBinding.current
        let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state {
                self.ready = true; let values = self.pending; self.pending.removeAll()
                values.forEach(self.write); self.read()
            }
            if case .failed(let error) = state { self.fail(error) }
        }
        connection.start(queue: queue)
    }
    func send(_ data: Data) {
        admission.lock()
        guard !closed, admittedPackets < 64, data.count <= 256 * 1_024 - admittedBytes else { admission.unlock(); return }
        admittedPackets += 1; admittedBytes += data.count; admission.unlock()
        queue.async {
            guard !self.stopped else { self.release(data.count); return }
            if self.ready { self.write(data) } else { self.pending.append(data) }
        }
    }
    private func write(_ data: Data) {
        guard !stopped, let connection else { release(data.count); return }
        guard permitted() else { release(data.count); fail(EngineError("UDP 路由已更新，已阻止旧 DIRECT 数据报")); return }
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self else { return }; self.release(data.count)
            if let error { self.fail(error) }
        })
    }
    private func release(_ count: Int) { admission.lock(); admittedPackets -= 1; admittedBytes -= count; admission.unlock() }
    private func stop() {
        guard !stopped else { return }; stopped = true
        admission.lock(); closed = true; admission.unlock()
        pending.forEach { release($0.count) }; pending.removeAll()
        connection?.cancel(); connection = nil
    }
    func cancel() { admission.lock(); closed = true; admission.unlock(); queue.async { self.stop() } }
    private func read() {
        connection?.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.stopped else { return }
            if let error { self.fail(error); return }
            if let data { self.receiveHandler(data) }; self.read()
        }
    }
    private func fail(_ error: Error) { guard !stopped else { return }; stop(); failureHandler(error) }
    deinit { connection?.cancel() }
}

private final class NativePolicyRoutedDatagram: NativeRoutedDatagram {
    private let target: RequestTarget
    private let session: NativeOutboundDatagramSession
    init(policy: ProxyPolicy, target: RequestTarget, queue: DispatchQueue,
         receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) throws {
        self.target = target
        session = try NativeOutboundFactory.makeDatagramSession(policy: policy, queue: queue,
            receive: { _, data in receive(data) }, failure: failure)
    }
    func send(_ data: Data) { session.send(data, to: target) }
    func cancel() { session.cancel() }
}

public final class ProxyEngine {
    public var onStatus: ((ProxyEngineStatus) -> Void)?
    public var onEvent: ((ProxyEngineEvent) -> Void)?
    /// UI clients can cross their main-queue boundary once per flush rather
    /// than once per connection. The legacy observer still receives each
    /// event; subscribe to only one hook when mutating the same UI model.
    public var onEventBatch: (([ProxyEngineEvent]) -> Void)?

    /// Listener callbacks stay serialized, while every accepted connection
    /// receives its own serial lane targeting this concurrent worker pool.
    /// This avoids one slow tunnel blocking all other tunnels under load.
    private let queue = DispatchQueue(label: "app.hajimi.proxy-engine.listener", qos: .userInitiated,
                                      autoreleaseFrequency: .workItem)
    private let workerQueue = DispatchQueue(label: "app.hajimi.proxy-engine.workers", qos: .userInitiated,
                                            attributes: .concurrent, autoreleaseFrequency: .workItem)
    private let stateQueue = DispatchQueue(label: "app.hajimi.proxy-engine.state")
    private let eventQueue = DispatchQueue(label: "app.hajimi.proxy-engine.events", qos: .utility,
                                           autoreleaseFrequency: .workItem)
    private let handlersLock = NSLock()
    private let lifecycleLock = NSRecursiveLock()
    private var listenerGeneration = UUID()
    private let maximumInboundConnections: Int
    fileprivate let httpHandshakeTimeout: TimeInterval
    private var httpListener: NWListener?
    private var socksListener: NWListener?
    private var handlers: [UUID: AnyObject] = [:]
    private var profile = Profile()
    private var mode: OutboundMode = .rule
    private var globalPolicy = "DIRECT"
    private var groupSelections: [String: String] = [:]
    private let dnsMapping = DNSMappingCache()
    private var dnsPacketRouter: NativePacketRouter?
    // Readers and writers share stateQueue, including listener transitions;
    // lifecycle-only locking would not synchronize Dashboard snapshots.
    private var status: ProxyEngineStatus = .stopped
    private var httpListenerReady = false
    private var socksListenerReady = false
    private var startReadyTimeout: DispatchWorkItem?
    private var httpRebindAttempts = 0
    private var socksRebindAttempts = 0
    private var nextConnectionQueueID: UInt64 = 0
    private var routingGeneration: UInt64 = 0
    private var routeCache: [RouteCacheKey: ResolvedRoute] = [:]
    private var pendingTraffic: [UUID: (uploaded: Int, downloaded: Int)] = [:]
    private var trafficFlushScheduled = false
    private var liveConnections: [UUID: ConnectionSnapshot] = [:]
    private var recentConnections: [ConnectionSnapshot] = []
    private var uploadedTotal: UInt64 = 0
    private var downloadedTotal: UInt64 = 0
    private var startedAt: Date?
    /// Ports actually bound after start. May differ from the profile when the
    /// preferred HTTP/SOCKS ports were already taken.
    private var httpListenAddress = ListenAddress(host: "127.0.0.1", port: 7262)
    private var socksListenAddress = ListenAddress(host: "127.0.0.1", port: 7263)
    // Snapshot readers may run on stateQueue while start/stop hold the
    // lifecycle lock. Use the short registry lock here, not lifecycleLock,
    // to avoid a stateQueue <-> lifecycleLock lock-order inversion.
    public private(set) var activeHTTPListen: ListenAddress {
        get { handlersLock.lock(); defer { handlersLock.unlock() }; return httpListenAddress }
        set { handlersLock.lock(); httpListenAddress = newValue; handlersLock.unlock() }
    }
    public private(set) var activeSOCKSListen: ListenAddress {
        get { handlersLock.lock(); defer { handlersLock.unlock() }; return socksListenAddress }
        set { handlersLock.lock(); socksListenAddress = newValue; handlersLock.unlock() }
    }

    public init(maximumInboundConnections: Int = 512,
                httpHandshakeTimeout: TimeInterval = 15) {
        self.maximumInboundConnections = max(1, min(maximumInboundConnections, 4_096))
        self.httpHandshakeTimeout = httpHandshakeTimeout.isFinite
            ? max(0.05, min(httpHandshakeTimeout, 60)) : 15
    }

    /// Includes unfinished handshakes, not just established traffic sessions.
    public var inboundConnectionCount: Int {
        handlersLock.lock(); defer { handlersLock.unlock() }
        return handlers.count
    }

    /// Pure lifecycle regression: construct listeners without starting them,
    /// then replay their actual callbacks after stop and a single-role rebind.
    /// No listener binds a port, no outbound connection starts, and no system
    /// network configuration is consulted or changed.
    public static func listenerLifecycleSelfTest() -> String? {
        let engine = ProxyEngine()
        engine.lifecycleLock.lock(); defer { engine.lifecycleLock.unlock(); engine.stop() }
        do {
            func listener(_ port: UInt16) throws -> NWListener {
                try engine.makeListener(address: ListenAddress(host: "127.0.0.1", port: port), kind: "test")
            }
            let oldHTTP = try listener(49_151)
            let oldSOCKS = try listener(49_150)
            let epoch = engine.listenerGeneration
            engine.httpListener = oldHTTP; engine.socksListener = oldSOCKS
            engine.configureState(oldHTTP, name: "test", role: .http, generation: epoch)
            engine.configureState(oldSOCKS, name: "test", role: .socks, generation: epoch)
            let oldState = oldHTTP.stateUpdateHandler
            let oldAccept = oldHTTP.newConnectionHandler
            engine.stop()
            let http = try listener(49_149), socks = try listener(49_148)
            engine.httpListener = http; engine.socksListener = socks
            engine.setStatus(.starting)
            oldState?(.ready)
            oldState?(.failed(NWError.posix(.ECONNRESET)))
            oldAccept?(NWConnection(host: "127.0.0.1", port: .any, using: .tcp))
            guard engine.httpListener === http, engine.socksListener === socks,
                  engine.inboundConnectionCount == 0,
                  engine.stateQueue.sync(execute: { engine.status }) == .starting else {
                return "old listener callback mutated a new generation"
            }
            let current = engine.listenerGeneration
            engine.configureState(http, name: "test", role: .http, generation: current)
            engine.configureState(socks, name: "test", role: .socks, generation: current)
            let rebound = try listener(49_147)
            let beforeRebindState = http.stateUpdateHandler
            engine.httpListener = rebound
            engine.configureState(rebound, name: "test", role: .http, generation: current)
            beforeRebindState?(.waiting(NWError.posix(.EADDRINUSE)))
            guard engine.httpListener === rebound, !engine.httpListenerReady else {
                return "replaced listener callback bypassed its role identity"
            }
            socks.stateUpdateHandler?(.ready)
            rebound.stateUpdateHandler?(.ready)
            guard engine.socksListenerReady, engine.httpListenerReady,
                  engine.stateQueue.sync(execute: { engine.status }) == .running else {
                return "single-role rebind invalidated the still-current sibling"
            }
            return nil
        } catch { return "listener lifecycle fixture: \(error.localizedDescription)" }
    }

    /// Construct unstarted listener owners and retain a memory stream owner;
    /// no port is bound and no outbound connection or Helper is started.
    public static func ruleSetReloadSelfTest() -> String? {
        final class HeldStreamHandler: CancellableConnectionHandler {
            private(set) var cancellations = 0
            func cancel() { cancellations += 1 }
        }
        let engine = ProxyEngine()
        defer { engine.stop() }
        do {
            let first = RuleSetReference(location: "memory.hot-rules.first")
            let second = RuleSetReference(location: "memory.hot-rules.second")
            var profile = Profile()
            profile.rules = [RoutingRule(kind: .ruleSet(first), policy: "REJECT", sourceLine: 1),
                RoutingRule(kind: .ruleSet(second), policy: "REJECT", sourceLine: 2),
                RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 3)]
            profile.ruleSetContents = [first.location: [.domain("old.hot-rules.test")],
                second.location: [.domain("stable.hot-rules.test")],
                "memory.unreferenced": [.domain("retained.hot-rules.test")]]
            let router = NativePacketRouter(profile: profile, mode: .rule, globalPolicy: "DIRECT",
                groupSelections: ["memory.selection": "DIRECT"])
            let httpAddress = ListenAddress(host: "127.0.0.1", port: 49_148)
            let socksAddress = ListenAddress(host: "127.0.0.1", port: 49_147)
            let http = try engine.makeListener(address: httpAddress, kind: "test")
            let socks = try engine.makeListener(address: socksAddress, kind: "test")
            engine.httpListener = http; engine.socksListener = socks
            engine.httpListenerReady = true; engine.socksListenerReady = true
            engine.activeHTTPListen = httpAddress; engine.activeSOCKSListen = socksAddress
            let held = HeldStreamHandler(), id = UUID(), started = Date()
            engine.handlersLock.lock(); engine.handlers[id] = held; engine.handlersLock.unlock()
            let connection = ConnectionSnapshot(id: id, openedAt: started, client: "memory", method: "HTTPS",
                host: "published.hot-rules.test", port: 443, policy: "DIRECT")
            engine.stateQueue.sync {
                engine.profile = profile; engine.dnsPacketRouter = router; engine.status = .running
                engine.groupSelections = ["memory.selection": "DIRECT"]
                engine.startedAt = started; engine.uploadedTotal = 123; engine.downloadedTotal = 456
                engine.liveConnections[id] = connection
            }
            let old = RequestTarget(host: "old.hot-rules.test", port: 443, protocolName: "HTTPS")
            let next = RequestTarget(host: "new.hot-rules.test", port: 443, protocolName: "HTTPS")
            guard case .reject = engine.route(for: old), engine.route(for: next) == .direct("DIRECT") else {
                return "initial memory rule routes were not cached"
            }
            let listenerGeneration = engine.listenerGeneration
            let routingGeneration = engine.routingRevision()
            let dnsGeneration = router.dnsRoutingSnapshotForSelfTest().generation
            let cached = engine.stateQueue.sync { engine.routeCache.count }
            var unchanged = profile.ruleSetContents
            unchanged["memory.unreferenced"] = [.domain("ignored.hot-rules.test")]
            guard try !engine.updateRuleSetContents(unchanged), engine.routingRevision() == routingGeneration,
                  engine.stateQueue.sync(execute: { engine.routeCache.count }) == cached,
                  router.dnsRoutingSnapshotForSelfTest().generation == dnsGeneration else {
                return "equivalent or unreferenced rule data invalidated live routing"
            }
            do {
                _ = try engine.updateRuleSetContents([first.location: [.domain(next.host)]])
                return "incomplete rule bodies replaced the running policy"
            } catch {}
            guard engine.runtimeSnapshot().profile == profile, engine.routingRevision() == routingGeneration,
                  engine.stateQueue.sync(execute: { engine.routeCache.count }) == cached,
                  router.dnsRoutingSnapshotForSelfTest().generation == dnsGeneration else {
                return "rejected rule update partially mutated routing or DNS"
            }
            var changed = unchanged
            changed[first.location] = [.domain(next.host)]
            var expected = profile; expected.ruleSetContents[first.location] = [.domain(next.host)]
            expected.prepareCompiledRoutingRules()
            var preparedHint = expected
            preparedHint.dnsServers = ["192.0.2.53"]
            preparedHint.proxies["memory.hint-only"] = ProxyPolicy(name: "memory.hint-only", kind: .socks5,
                host: "203.0.113.40", port: 1080, username: "hint-user", password: "hint-secret")
            guard try engine.updateRuleSetContents(changed, preparedProfile: preparedHint),
                  engine.routingRevision() == routingGeneration &+ 1,
                  engine.stateQueue.sync(execute: { engine.routeCache.isEmpty }),
                  router.dnsRoutingSnapshotForSelfTest().generation == dnsGeneration &+ 1 else {
                return "changed rule bodies did not advance both routing policies and clear old decisions"
            }
            let runtime = engine.runtimeSnapshot(), dns = router.dnsRoutingSnapshotForSelfTest()
            #if canImport(HajimiRoutingCXX)
            guard let preparedProgram = expected.preparedCompiledRoutingProgram,
                  runtime.profile.preparedCompiledRoutingProgram === preparedProgram,
                  dns.profile.preparedCompiledRoutingProgram === preparedProgram else {
                return "rule refresh rebuilt prepared indexes on the caller or under the DNS configuration lock"
            }
            #endif
            let original = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")
            guard engine.route(for: old) == .direct("DIRECT"), case .reject = engine.route(for: next),
                  case .reject = dns.route(original, name: next.host), dns.profile == expected,
                  runtime.profile == expected, runtime.mode == .rule, runtime.globalPolicy == "DIRECT",
                  runtime.groupSelections == ["memory.selection": "DIRECT"] else {
                return "new HTTP/SOCKS/DNS decisions did not use the new rule bodies exclusively"
            }
            engine.handlersLock.lock(); let retained = engine.handlers[id] === held; engine.handlersLock.unlock()
            guard retained, held.cancellations == 0, engine.httpListener === http, engine.socksListener === socks,
                  engine.listenerGeneration == listenerGeneration, engine.httpListenerReady, engine.socksListenerReady,
                  runtime.status == .running, runtime.httpListen == httpAddress, runtime.socksListen == socksAddress,
                  runtime.active == [connection], runtime.startedAt == started,
                  runtime.uploaded == 123, runtime.downloaded == 456 else {
                return "rule refresh replaced listeners, cancelled a published stream or reset traffic state"
            }
            // A stale hint supplies no policy authority. Its indexes must be
            // ignored while the complete, valid body update still succeeds.
            guard try engine.updateRuleSetContents(profile.ruleSetContents, preparedProfile: expected),
                  engine.runtimeSnapshot().profile == profile,
                  case .reject = engine.route(for: old),
                  engine.route(for: next) == .direct("DIRECT") else {
                return "a mismatching prepared hint changed or rejected the requested rule bodies"
            }
            #if canImport(HajimiRoutingCXX)
            let restored = engine.runtimeSnapshot().profile
            guard let restoredProgram = restored.preparedCompiledRoutingProgram,
                  restoredProgram !== preparedProgram,
                  router.dnsRoutingSnapshotForSelfTest().profile.preparedCompiledRoutingProgram === restoredProgram else {
                return "stale prepared indexes survived a different body update"
            }
            #endif
            return nil
        } catch { return "rule-set reload fixture: \(error.localizedDescription)" }
    }

    public static func requestHeaderBoundarySelfTest() -> String? {
        ConnectionReader.headerBoundarySelfTest()
    }

    /// Uses the actual event lane without binding listeners or dialing peers.
    public static func eventBatchSelfTest() -> String? {
        let engine = ProxyEngine()
        let lock = NSLock()
        let flushed = DispatchSemaphore(value: 0)
        let first = UUID(), second = UUID(), third = UUID()
        var batches: [[String]] = [], legacy: [String] = []
        func description(_ event: ProxyEngineEvent) -> String {
            switch event {
            case .opened(let snapshot): return "opened:\(snapshot.id)"
            case .traffic(let id, let uploaded, let downloaded): return "traffic:\(id):\(uploaded):\(downloaded)"
            case .closed(let id, _): return "closed:\(id)"
            case .message(let value): return "message:\(value)"
            }
        }
        engine.onEventBatch = { events in
            let text = events.map(description)
            lock.lock(); batches.append(text); lock.unlock()
            if text.contains("traffic:\(second):20:30") && text.contains("traffic:\(third):5:6") {
                flushed.signal()
            }
        }
        engine.onEvent = { event in
            lock.lock(); legacy.append(description(event)); lock.unlock()
        }
        engine.eventQueue.sync {
            for id in [first, second, third] {
                engine.processEvent(.opened(ConnectionSnapshot(id: id, openedAt: Date(), client: "fixture",
                    method: "TCP", host: "127.0.0.1", port: 1, policy: "DIRECT")))
            }
            engine.processEvent(.traffic(id: first, uploaded: 10, downloaded: 10))
            engine.processEvent(.traffic(id: first, uploaded: 2, downloaded: 4))
            engine.processEvent(.traffic(id: second, uploaded: 20, downloaded: 30))
            engine.processEvent(.traffic(id: third, uploaded: 5, downloaded: 6))
            engine.processEvent(.closed(id: first, error: nil))
        }
        guard flushed.wait(timeout: .now() + 3) == .success else {
            return "traffic batch flush did not finish"
        }
        engine.eventQueue.sync {}
        lock.lock(); let observed = batches, oldObserver = legacy; lock.unlock()
        guard observed.contains(["traffic:\(first):12:14", "closed:\(first)"]),
              observed.flatMap({ $0 }) == oldObserver,
              observed.count == 5, oldObserver.count == 7 else {
            return "batch delivery lost traffic, close ordering or legacy callbacks"
        }
        let totals = engine.stateQueue.sync { (engine.uploadedTotal, engine.downloadedTotal) }
        guard totals.0 == 37 && totals.1 == 50 else { return "batching changed cumulative counters" }
        return nil
    }

    public struct RuntimeSnapshot: Equatable {
        public var status: ProxyEngineStatus
        public var mode: OutboundMode
        public var globalPolicy: String
        public var groupSelections: [String: String]
        public var profile: Profile
        public var httpListen: ListenAddress
        public var socksListen: ListenAddress
        public var uploaded: UInt64
        public var downloaded: UInt64
        public var startedAt: Date?
        public var active: [ConnectionSnapshot]
        public var recent: [ConnectionSnapshot]
    }

    public func runtimeSnapshot() -> RuntimeSnapshot {
        stateQueue.sync {
            RuntimeSnapshot(status: status, mode: mode, globalPolicy: globalPolicy,
                            groupSelections: groupSelections, profile: profile,
                            httpListen: activeHTTPListen, socksListen: activeSOCKSListen,
                            uploaded: uploadedTotal, downloaded: downloadedTotal,
                            startedAt: startedAt,
                            active: Array(liveConnections.values)
                                .sorted { $0.openedAt > $1.openedAt },
                            recent: recentConnections)
        }
    }

    public func killConnection(id: UUID) -> Bool {
        handlersLock.lock()
        let handler = handlers.removeValue(forKey: id)
        handlersLock.unlock()
        (handler as? CancellableConnectionHandler)?.cancel()
        return handler != nil
    }

    public func flushDNS(prewarm: Bool = true) {
        dnsMapping.removeAll()
        SecureDNSHostResolver.shared.flush()
        NativeOutboundFactory.invalidateForNetworkChange()
        stateQueue.sync { dnsPacketRouter }?.flushDNS(prewarm: prewarm)
    }

    public static func flushCachedOutboundInterfaces() {
        OutboundInterfaceBinding.flushKnownInterfaces()
        HJFlushCachedRuntimeInterfaces()
        HJFlushCachedBridgeInterfaces()
    }

    public func prewarmDNS(immediately: Bool = false) {
        stateQueue.sync { dnsPacketRouter }?.prewarmDNS(immediately: immediately)
    }

    /// Native protocol implementations share the same physical-interface
    /// binding as DIRECT/HTTP/SOCKS sockets while enhanced mode is active.
    public static var currentOutboundInterface: NWInterface? {
        OutboundInterfaceBinding.current
    }

    deinit { stop() }

    public func updateRouting(mode: OutboundMode, globalPolicy: String,
                              groupSelections: [String: String] = [:]) {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        let snapshot = stateQueue.sync { () -> (NativePacketRouter?, Profile) in
            guard self.mode != mode || self.globalPolicy != globalPolicy ||
                    self.groupSelections != groupSelections else { return (nil, profile) }
            self.mode = mode
            self.globalPolicy = globalPolicy
            self.groupSelections = groupSelections
            self.routingGeneration &+= 1
            self.routeCache.removeAll(keepingCapacity: true)
            return (dnsPacketRouter, profile)
        }
        snapshot.0?.updateSelections(mode: mode, globalPolicy: globalPolicy,
                                      groupSelections: groupSelections)
    }

    /// Hot-reloads the active profile, outbound policies, routing rules, and
    /// selection state in place without tearing down active HTTP/SOCKS listeners.
    public func updateConfiguration(profile: Profile, mode: OutboundMode, globalPolicy: String,
                                    groupSelections: [String: String] = [:]) {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        profile.prepareCompiledRoutingRules()
        let router = stateQueue.sync { () -> NativePacketRouter? in
            self.profile = profile
            self.mode = mode
            self.globalPolicy = globalPolicy
            self.groupSelections = groupSelections
            self.routingGeneration &+= 1
            self.routeCache.removeAll(keepingCapacity: true)
            return dnsPacketRouter
        }
        router?.update(profile: profile, mode: mode, globalPolicy: globalPolicy,
                       groupSelections: groupSelections)
    }

    /// Replace only bodies of currently referenced RULE-SETs. Published TCP
    /// streams and listeners retain their ownership; new requests consult the
    /// new rules. Missing bodies reject the entire update before publication.
    /// A background-prepared profile is only an optional index-cache hint;
    /// executable inputs must match before its immutable indexes are shared.
    @discardableResult
    public func updateRuleSetContents(_ contents: [String: [RuleKind]],
                                      preparedProfile: Profile? = nil) throws -> Bool {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        let snapshot = try stateQueue.sync { () throws -> (Profile, NativePacketRouter?)? in
            let updated = try replacingReferencedRuleSetContents(in: profile, with: contents)
            guard updated.ruleSetContents != profile.ruleSetContents else { return nil }
            return (updated, dnsPacketRouter)
        }
        guard let snapshot else { return false }
        var updated = snapshot.0
        if let preparedProfile { _ = updated.adoptCompiledRoutingRules(from: preparedProfile) }
        updated.prepareCompiledRoutingRules()
        // The same lifecycle fence serializes route selection changes, starts
        // and stops, so the DNS router keeps its current node/mode snapshot.
        try snapshot.1?.updateRuleSetContents(from: updated)
        stateQueue.sync {
            profile = updated
            routingGeneration &+= 1
            routeCache.removeAll(keepingCapacity: true)
        }
        return true
    }

    /// Forces all proxy-engine outbound sockets onto the physical interface.
    /// This is used by the entitlement-free utun mode to prevent route loops.
    public func setOutboundInterface(name: String?, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let name, !name.isEmpty else {
            OutboundInterfaceBinding.set(nil)
            completion(.success(()))
            return
        }
        OutboundInterfaceBinding.resolve(name: name, completion: completion)
    }

    public func start(profile: Profile, mode: OutboundMode, globalPolicy: String,
                      groupSelections: [String: String] = [:]) throws {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        stop()
        let generation = listenerGeneration
        let router = NativePacketRouter(profile: profile, mode: mode, globalPolicy: globalPolicy,
                                        groupSelections: groupSelections)
        stateQueue.sync {
            self.profile = profile
            self.mode = mode
            self.globalPolicy = globalPolicy
            self.groupSelections = groupSelections
            self.routingGeneration &+= 1
            self.routeCache.removeAll(keepingCapacity: true)
            self.dnsPacketRouter = router
        }
        setStatus(.starting)
        stateQueue.sync {
            uploadedTotal = 0
            downloadedTotal = 0
            liveConnections.removeAll()
            recentConnections.removeAll()
            startedAt = Date()
        }
        httpListenerReady = false
        socksListenerReady = false
        httpRebindAttempts = 0
        socksRebindAttempts = 0

        // Prefer the profile ports; if either is taken, pick free ones nearby
        // (then random high ports) instead of failing the whole engine.
        let httpAddress: ListenAddress
        let socksAddress: ListenAddress
        do {
            httpAddress = try ListenPortAllocator.availableAddress(
                preferred: profile.httpListen, kind: "HTTP", excluding: [])
            socksAddress = try ListenPortAllocator.availableAddress(
                preferred: profile.socksListen, kind: "SOCKS5",
                excluding: [httpAddress.port])
        } catch {
            stop()
            setStatus(.failed(error.localizedDescription))
            throw error
        }
        activeHTTPListen = httpAddress
        activeSOCKSListen = socksAddress
        if httpAddress.port != profile.httpListen.port ||
            socksAddress.port != profile.socksListen.port {
            emit(.message(
                "监听端口已自动调整为 HTTP :\(httpAddress.port)、SOCKS5 :\(socksAddress.port)（配置端口被占用）"))
        }

        do {
            httpListener = try makeListener(address: httpAddress, kind: "HTTP")
            socksListener = try makeListener(address: socksAddress, kind: "SOCKS5")
        } catch {
            stop()
            setStatus(.failed(error.localizedDescription))
            throw error
        }

        configureState(httpListener, name: "HTTP", role: .http, generation: generation)
        configureState(socksListener, name: "SOCKS5", role: .socks, generation: generation)
        scheduleStartReadyTimeout()
        httpListener?.start(queue: queue)
        socksListener?.start(queue: queue)
        router.prewarmDNS()
    }

    public func stop() {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        // Admission and listener callbacks take this same lock. Revocation
        // precedes cancellation, including callbacks already queued by NW.
        listenerGeneration = UUID()
        cancelStartReadyTimeout()
        httpListener?.cancel()
        socksListener?.cancel()
        httpListener = nil
        socksListener = nil
        handlersLock.lock()
        let current = Array(handlers.values)
        handlers.removeAll(keepingCapacity: true)
        handlersLock.unlock()
        for item in current {
            (item as? CancellableConnectionHandler)?.cancel()
        }
        let dnsRouter = stateQueue.sync { () -> NativePacketRouter? in
            let router = dnsPacketRouter
            dnsPacketRouter = nil
            liveConnections.removeAll()
            startedAt = nil
            return router
        }
        dnsRouter?.cancelDNSQueries()
        if stateQueue.sync(execute: { status != .stopped }) { setStatus(.stopped) }
    }

    private enum ListenerRole { case http, socks }

    private func makeListener(address: ListenAddress, kind: String) throws -> NWListener {
        guard let port = NWEndpoint.Port(rawValue: address.port) else {
            throw EngineError("无效的 \(kind) 端口")
        }
        let parameters = NWParameters.tcp
        // Allow the stack to rebind quickly after a previous engine stop.
        parameters.allowLocalEndpointReuse = true
        if isLoopbackHost(address.host) {
            parameters.requiredInterfaceType = .loopback
            if let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
                ip.version = address.host.contains(":") ? .v6 : .v4
            }
            return try NWListener(using: parameters, on: port)
        }
        if address.host != "0.0.0.0" && address.host != "::" && !address.host.isEmpty {
            parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(address.host), port: port)
            return try NWListener(using: parameters)
        }
        return try NWListener(using: parameters, on: port)
    }

    private func isCurrentListener(_ listener: NWListener, role: ListenerRole,
                                   generation: UUID) -> Bool {
        guard listenerGeneration == generation else { return false }
        switch role {
        case .http: return httpListener === listener
        case .socks: return socksListener === listener
        }
    }

    private func configureState(_ optionalListener: NWListener?, name: String, role: ListenerRole,
                                generation: UUID) {
        guard let listener = optionalListener else { return }
        listener.newConnectionHandler = { [weak self, weak listener] connection in
            guard let self, let listener else { connection.cancel(); return }
            switch role {
            case .http: self.acceptHTTP(connection, from: listener, generation: generation)
            case .socks: self.acceptSOCKS(connection, from: listener, generation: generation)
            }
        }
        listener.stateUpdateHandler = { [weak self, weak listener] state in
            guard let self, let listener else { return }
            self.lifecycleLock.lock(); defer { self.lifecycleLock.unlock() }
            // Hold through stop/rebind/status mutation, not just the check.
            // Object identity also revokes old callbacks after a role rebind.
            guard self.isCurrentListener(listener, role: role, generation: generation) else { return }
            switch state {
            case .ready:
                // Prefer the kernel-assigned port if Network.framework reports one
                // (should match what we asked for).
                if let raw = listener.port?.rawValue {
                    switch role {
                    case .http:
                        self.activeHTTPListen = ListenAddress(host: self.activeHTTPListen.host,
                                                              port: raw)
                        self.httpListenerReady = true
                    case .socks:
                        self.activeSOCKSListen = ListenAddress(host: self.activeSOCKSListen.host,
                                                               port: raw)
                        self.socksListenerReady = true
                    }
                } else {
                    switch role {
                    case .http: self.httpListenerReady = true
                    case .socks: self.socksListenerReady = true
                    }
                }
                self.emit(.message("\(name) 监听器已启动 :\(listener.port?.rawValue ?? 0)"))
                if self.httpListenerReady && self.socksListenerReady {
                    self.cancelStartReadyTimeout()
                    self.setStatus(.running)
                }
            case .waiting(let error):
                // A lingering utun / path evaluator can park the listener here
                // without ever failing. One rebind is enough; looping would
                // just walk ports until the start timeout fires.
                self.emit(.message("\(name) 监听等待中：\(error.localizedDescription)"))
                if self.rebindCount(for: role) < 1,
                   self.rebindListener(name: name, role: role) {
                    return
                }
            case .failed(let error):
                // Last-resort recovery: preferred probe can race another binder.
                if Self.isAddressInUse(error),
                   self.rebindListener(name: name, role: role) {
                    return
                }
                self.stop()
                self.setStatus(.failed("\(name): \(error.localizedDescription)"))
            default: break
            }
        }
    }

    private func scheduleStartReadyTimeout() {
        cancelStartReadyTimeout()
        let generation = listenerGeneration
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.lifecycleLock.lock(); defer { self.lifecycleLock.unlock() }
            guard self.listenerGeneration == generation else { return }
            guard self.stateQueue.sync(execute: { self.status == .starting }) else { return }
            let http = self.httpListenerReady ? "就绪" : "未就绪"
            let socks = self.socksListenerReady ? "就绪" : "未就绪"
            self.stop()
            self.setStatus(.failed("HTTP/SOCKS 监听启动超时（HTTP \(http)，SOCKS \(socks)）"))
        }
        startReadyTimeout = work
        queue.asyncAfter(deadline: .now() + 8, execute: work)
    }

    private func cancelStartReadyTimeout() {
        startReadyTimeout?.cancel()
        startReadyTimeout = nil
    }

    private func rebindCount(for role: ListenerRole) -> Int {
        switch role {
        case .http: return httpRebindAttempts
        case .socks: return socksRebindAttempts
        }
    }

    /// Rebuilds one listener on a fresh free port after an async bind failure.
    @discardableResult
    private func rebindListener(name: String, role: ListenerRole) -> Bool {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        let preferred: ListenAddress
        let excluding: Set<UInt16>
        switch role {
        case .http:
            httpListener?.cancel(); httpListener = nil
            httpListenerReady = false
            httpRebindAttempts += 1
            preferred = activeHTTPListen
            excluding = [activeSOCKSListen.port]
        case .socks:
            socksListener?.cancel(); socksListener = nil
            socksListenerReady = false
            socksRebindAttempts += 1
            preferred = activeSOCKSListen
            excluding = [activeHTTPListen.port]
        }
        // Force a different port than the one that just failed.
        var blocked = excluding
        blocked.insert(preferred.port)
        guard let next = try? ListenPortAllocator.availableAddress(
            preferred: preferred, kind: name, excluding: blocked,
            forceAlternate: true) else { return false }
        guard let listener = try? makeListener(address: next, kind: name) else { return false }
        switch role {
        case .http:
            activeHTTPListen = next
            httpListener = listener
        case .socks:
            activeSOCKSListen = next
            socksListener = listener
        }
        configureState(listener, name: name, role: role, generation: listenerGeneration)
        listener.start(queue: queue)
        emit(.message("\(name) 端口被占用，已切换到 :\(next.port)"))
        return true
    }

    private static func isAddressInUse(_ error: Error) -> Bool {
        let text = error.localizedDescription.lowercased()
        if text.contains("address already in use") || text.contains("地址已经被占用")
            || text.contains("in use") || text.contains("被占用") {
            return true
        }
        let ns = error as NSError
        // POSIX EADDRINUSE = 48 on Darwin.
        return ns.domain == NSPOSIXErrorDomain && ns.code == Int(EADDRINUSE)
    }

    private func acceptHTTP(_ connection: NWConnection, from listener: NWListener, generation: UUID) {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        guard isCurrentListener(listener, role: .http, generation: generation) else { connection.cancel(); return }
        handlersLock.lock()
        guard handlers.count < maximumInboundConnections else {
            handlersLock.unlock(); connection.cancel(); return
        }
        let connectionQueue = makeConnectionQueue()
        let handler = HTTPConnectionHandler(connection: connection, engine: self, queue: connectionQueue)
        handlers[handler.id] = handler
        handlersLock.unlock()
        connection.start(queue: connectionQueue)
        connectionQueue.async { handler.start() }
    }

    private func acceptSOCKS(_ connection: NWConnection, from listener: NWListener, generation: UUID) {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        guard isCurrentListener(listener, role: .socks, generation: generation) else { connection.cancel(); return }
        handlersLock.lock()
        guard handlers.count < maximumInboundConnections else {
            handlersLock.unlock(); connection.cancel(); return
        }
        let connectionQueue = makeConnectionQueue()
        let handler = SOCKSConnectionHandler(connection: connection, engine: self, queue: connectionQueue)
        handlers[handler.id] = handler
        handlersLock.unlock()
        connection.start(queue: connectionQueue)
        connectionQueue.async { handler.start() }
    }

    private func makeConnectionQueue() -> DispatchQueue {
        nextConnectionQueueID &+= 1
        return DispatchQueue(label: "app.hajimi.proxy-engine.connection.\(nextConnectionQueueID)",
                             qos: .userInitiated, autoreleaseFrequency: .workItem,
                             target: workerQueue)
    }

    fileprivate func routingRevision() -> UInt64 {
        stateQueue.sync { routingGeneration }
    }

    fileprivate var routesDirectHostnamesViaDNS: Bool {
        stateQueue.sync { DNSApplicationResolutionPolicy.usesQueryRouter(profile) }
    }

    fileprivate func makeRoutedUDP(target: RequestTarget, queue: DispatchQueue,
                                   receive: @escaping (Data) -> Void,
                                   failure: @escaping (Error) -> Void) throws -> NativeRoutedDatagram {
        guard let router = stateQueue.sync(execute: { dnsPacketRouter }) else { throw EngineError("DNS 路由核心未启动") }
        guard !FakeIPAllocator.isFake(target.host) else {
            throw EngineError("本地代理不能猜测其它数据面的 fake-IP 映射；请使用 SOCKS 域名或对应 TUN 数据面")
        }
        if target.port == 53 {
            // The Helper/TUN data plane uses a separate allocator namespace.
            // Local proxy DNS returns real answers through the same protected
            // policy gateway rather than minting conflicting 198.19 addresses.
            return try router.makeDNSDatagram(original: target, queue: queue, synthesizeFakeIP: false,
                                               receive: receive, failure: failure)
        }
        return try router.makeUDPFlow(host: target.host, port: target.port, queue: queue,
                                       sourceHost: target.sourceHost, sourcePort: target.sourcePort,
                                       inboundPort: target.inboundPort, receive: receive, failure: failure)
    }

    fileprivate func connect(route: ResolvedRoute, target: RequestTarget, plainHTTP: Bool,
                             queue: DispatchQueue,
                             completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        guard !FakeIPAllocator.isFake(target.host) else {
            completion(.failure(EngineError("本地代理不能猜测其它数据面的 fake-IP 映射；请使用 SOCKS 域名或对应 TUN 数据面")))
            return
        }
        if target.port == 53 {
            guard let router = stateQueue.sync(execute: { dnsPacketRouter }) else {
                completion(.failure(EngineError("DNS 路由核心未启动"))); return
            }
            router.connectTCP(host: target.host, port: target.port, queue: queue,
                               sourceHost: target.sourceHost, sourcePort: target.sourcePort,
                               inboundPort: target.inboundPort, synthesizeFakeIP: false,
                               completion: { completion($0.map { ($0, Data()) }) })
            return
        }
        if case .direct = route, routesDirectHostnamesViaDNS, !DoHEndpoint.isAddressLiteral(target.host) {
            guard let router = stateQueue.sync(execute: { dnsPacketRouter }) else {
                completion(.failure(EngineError("DNS 路由核心未启动"))); return
            }
            router.connectRoutedTCP(route: route, target: target, plainHTTP: plainHTTP, queue: queue,
                                     completion: { completion($0.map { ($0, Data()) }) })
            return
        }
        TunnelConnector.connect(route: route, target: target, plainHTTP: plainHTTP,
                                queue: queue, completion: completion)
    }

    /// Replay local DNS construction and a foreign synthetic target without
    /// starting listeners. Local DNS must not create a conflicting fake pool.
    public static func localDNSIsolationSelfTest() -> String? {
        var profile = Profile(); profile.fakeIPEnabled = true
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                               adapterType: "trojan", parameters: ["password": "test"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        let engine = ProxyEngine()
        let router = NativePacketRouter(profile: profile, mode: .rule, globalPolicy: node.name, groupSelections: [:])
        engine.stateQueue.sync { engine.profile = profile; engine.dnsPacketRouter = router }
        defer { engine.stop() }
        let target = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")
        do {
            let local = try engine.makeRoutedUDP(target: target, queue: .global(), receive: { _ in }, failure: { _ in })
            defer { local.cancel() }
            guard let policy = local as? PolicyDNSDatagram, !policy.fakeIPSynthesisEnabled else {
                return "local SOCKS UDP DNS minted addresses in the TUN fake-IP namespace"
            }
            var tcpUsesRealAnswers = false
            var tcpTarget = target; tcpTarget.protocolName = "TCP"
            engine.connect(route: .native(node, node.name), target: tcpTarget, plainHTTP: false, queue: .global()) { result in
                if case .success(let pair) = result {
                    tcpUsesRealAnswers = (pair.0 as? DNSFramedByteStream)?.fakeIPSynthesisEnabled == false
                    pair.0.cancel()
                }
            }
            guard tcpUsesRealAnswers else { return "local SOCKS TCP DNS minted conflicting fake-IP addresses" }
            var fakeTarget = target; fakeTarget.host = "198.19.0.1"; fakeTarget.port = 443
            var refused = false
            engine.connect(route: .native(node, node.name), target: fakeTarget, plainHTTP: false, queue: .global()) { result in
                if case .failure = result { refused = true }
            }
            guard refused else { return "local SOCKS sent a foreign fake-IP to its selected proxy" }
            do { _ = try engine.makeRoutedUDP(target: fakeTarget, queue: .global(), receive: { _ in }, failure: { _ in }) }
            catch { return nil }
            return "local SOCKS UDP guessed a foreign fake-IP mapping"
        } catch { return error.localizedDescription }
    }

    fileprivate func route(for target: RequestTarget) -> ResolvedRoute {
        let alternateHost = dnsMapping.domain(for: target.host)
        let key = RouteCacheKey(host: target.host.lowercased(), port: target.port,
                                protocolName: target.protocolName.uppercased(),
                                alternateHost: alternateHost?.lowercased(),
                                sourceHost: target.sourceHost?.lowercased(),
                                sourcePort: target.sourcePort,
                                inboundPort: target.inboundPort)
        while true {
            let snapshot: RoutingSnapshot = stateQueue.sync {
                RoutingSnapshot(profile: profile, mode: mode, globalPolicy: globalPolicy,
                                groupSelections: groupSelections, generation: routingGeneration,
                                cached: routeCache[key])
            }
            if let cached = snapshot.cached { return cached }

            // Rule-set matching may scan thousands of entries. Compute it
            // outside the state queue; retry if a policy changed meanwhile,
            // rather than sending one last datagram down the stale route.
            let result = snapshot.profile.route(for: target, mode: snapshot.mode,
                                                globalPolicy: snapshot.globalPolicy,
                                                groupSelections: snapshot.groupSelections,
                                                alternateHost: alternateHost)
            let isCurrent = stateQueue.sync { () -> Bool in
                guard routingGeneration == snapshot.generation else { return false }
                if routeCache.count >= 8_192 { routeCache.removeAll(keepingCapacity: true) }
                routeCache[key] = result
                return true
            }
            if isCurrent { return result }
        }
    }

    fileprivate func recordDNSResponse(_ data: Data) {
        for record in DNSMessageInspection.addressAnswers(in: data) {
            dnsMapping.set(domain: record.domain, for: record.address, ttl: record.ttl)
        }
    }

    fileprivate func displayHost(for host: String) -> String {
        dnsMapping.domain(for: host) ?? host
    }

    /// Traffic callbacks can occur once per packet/read. Coalescing them to a
    /// 250 ms cadence prevents the UI and Dispatch main queue from becoming
    /// the dominant CPU consumer without affecting forwarding throughput.
    fileprivate func emit(_ event: ProxyEngineEvent) {
        eventQueue.async { [weak self] in self?.processEvent(event) }
    }

    fileprivate func handlerFinished(id: UUID) {
        handlersLock.lock()
        handlers.removeValue(forKey: id)
        handlersLock.unlock()
    }

    private func processEvent(_ event: ProxyEngineEvent) {
        switch event {
        case .opened(let snapshot):
            stateQueue.sync {
                liveConnections[snapshot.id] = snapshot
                recentConnections.insert(snapshot, at: 0)
                if recentConnections.count > 200 { recentConnections.removeLast() }
            }
            publishEvents([event])
        case .traffic(let id, let uploaded, let downloaded):
            let current = pendingTraffic[id] ?? (0, 0)
            pendingTraffic[id] = (current.uploaded + uploaded, current.downloaded + downloaded)
            stateQueue.sync {
                uploadedTotal &+= UInt64(max(0, uploaded))
                downloadedTotal &+= UInt64(max(0, downloaded))
            }
            scheduleTrafficFlush()
        case .closed(let id, _):
            var finalEvents: [ProxyEngineEvent] = []
            if let traffic = takeTraffic(for: id) { finalEvents.append(traffic) }
            _ = stateQueue.sync { liveConnections.removeValue(forKey: id) }
            finalEvents.append(event)
            publishEvents(finalEvents)
        case .message:
            publishEvents([event])
        }
    }

    private func scheduleTrafficFlush() {
        guard !trafficFlushScheduled else { return }
        trafficFlushScheduled = true
        eventQueue.asyncAfter(deadline: .now() + .milliseconds(250)) { [weak self] in
            guard let self else { return }
            self.trafficFlushScheduled = false
            let values = self.pendingTraffic
            self.pendingTraffic.removeAll(keepingCapacity: true)
            let events: [ProxyEngineEvent] = values.compactMap { id, traffic in
                guard traffic.uploaded != 0 || traffic.downloaded != 0 else { return nil }
                return .traffic(id: id, uploaded: traffic.uploaded, downloaded: traffic.downloaded)
            }
            self.publishEvents(events)
        }
    }

    private func takeTraffic(for id: UUID) -> ProxyEngineEvent? {
        guard let traffic = pendingTraffic.removeValue(forKey: id),
              traffic.uploaded != 0 || traffic.downloaded != 0 else { return nil }
        return .traffic(id: id, uploaded: traffic.uploaded, downloaded: traffic.downloaded)
    }

    private func publishEvents(_ events: [ProxyEngineEvent]) {
        guard !events.isEmpty else { return }
        onEventBatch?(events)
        if let onEvent { events.forEach(onEvent) }
    }

    private func setStatus(_ newValue: ProxyEngineStatus) {
        stateQueue.sync { status = newValue }
        // Never call client/UI code while executing on the state queue.
        onStatus?(newValue)
    }
}

private struct RouteCacheKey: Hashable {
    let host: String
    let port: UInt16
    let protocolName: String
    let alternateHost: String?
    let sourceHost: String?
    let sourcePort: UInt16?
    let inboundPort: UInt16?
}

private struct RoutingSnapshot {
    let profile: Profile
    let mode: OutboundMode
    let globalPolicy: String
    let groupSelections: [String: String]
    let generation: UInt64
    let cached: ResolvedRoute?
}

private struct EngineError: LocalizedError {
    let text: String
    init(_ text: String) { self.text = text }
    var errorDescription: String? { text }
}

enum OutboundInterfaceBinding {
    private static let lock = NSLock()
    private static var value: NWInterface?
    private static var knownInterfaces: [String: NWInterface] = [:]

    static var current: NWInterface? {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    static func set(_ interface: NWInterface?) {
        lock.lock()
        value = interface
        if let interface { knownInterfaces[interface.name] = interface }
        lock.unlock()
        NativeOutboundFactory.invalidateForNetworkChange()
    }

    static func flushKnownInterfaces() {
        lock.lock()
        knownInterfaces = knownInterfaces.filter { name, iface in
            let currentIdx = Int(name.withCString { if_nametoindex($0) })
            return currentIdx > 0 && currentIdx == iface.index
        }
        lock.unlock()
    }

    private static func cachedInterface(named name: String, index: Int) -> NWInterface? {
        guard index > 0 else { return nil }
        lock.lock(); defer { lock.unlock() }
        if let existing = value, existing.name == name, existing.index == index {
            return existing
        }
        if let known = knownInterfaces[name], known.index == index {
            return known
        }
        return nil
    }

    static func resolve(name: String, completion: @escaping (Result<Void, Error>) -> Void) {
        let kernelIndex = Int(name.withCString { if_nametoindex($0) })
        if let cached = cachedInterface(named: name, index: kernelIndex) {
            set(cached)
            completion(.success(()))
            return
        }
        let physicalMonitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        let fallbackMonitor = NWPathMonitor()
        let queue = DispatchQueue(label: "app.hajimi.interface-resolver", qos: .userInitiated)
        var completed = false
        let handlePath: (NWPath) -> Void = { path in
            guard !completed else { return }
            lock.lock()
            for iface in path.availableInterfaces {
                knownInterfaces[iface.name] = iface
            }
            lock.unlock()
            if let interface = path.availableInterfaces.first(where: { $0.name == name }) {
                completed = true
                physicalMonitor.cancel()
                fallbackMonitor.cancel()
                set(interface)
                completion(.success(()))
                return
            }
            let currentIdx = Int(name.withCString { if_nametoindex($0) })
            if let cached = cachedInterface(named: name, index: currentIdx) {
                completed = true
                physicalMonitor.cancel()
                fallbackMonitor.cancel()
                set(cached)
                completion(.success(()))
            }
        }
        physicalMonitor.pathUpdateHandler = handlePath
        fallbackMonitor.pathUpdateHandler = handlePath
        physicalMonitor.start(queue: queue)
        fallbackMonitor.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 1.2) {
            guard !completed else { return }
            completed = true
            physicalMonitor.cancel()
            fallbackMonitor.cancel()
            let currentIdx = Int(name.withCString { if_nametoindex($0) })
            if let cached = cachedInterface(named: name, index: currentIdx) {
                set(cached)
                completion(.success(()))
                return
            }
            completion(.failure(EngineError("找不到物理网络接口 \(name)")))
        }
    }
}

private protocol CancellableConnectionHandler: AnyObject {
    func cancel()
}

private final class ConnectionReader {
    private let connection: any OutboundByteStream
    private var buffer = Data()
    private var ended = false

    init(_ connection: NWConnection) { self.connection = NetworkOutboundByteStream(connection) }
    init(_ connection: any OutboundByteStream) { self.connection = connection }

    static func headerBoundarySelfTest() -> String? {
        final class Fixture: NativeOutboundByteStream {
            var chunks: [Data]
            init(_ chunks: [Data]) { self.chunks = chunks }
            func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
            func cancel() {}
            func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
                guard !chunks.isEmpty else { completion(nil, true, nil); return }
                let chunk = chunks.removeFirst()
                guard chunk.count <= maximum else { completion(nil, true, EngineError("fixture exceeded raw read limit")); return }
                completion(chunk, false, nil)
            }
        }
        let marker = Data("\r\n\r\n".utf8)
        var oversized: Result<(Data, Data), Error>?
        let bad = ConnectionReader(Fixture([Data(repeating: 97, count: 65_520),
                                           Data(repeating: 97, count: 20) + marker]))
        bad.readUntil(marker, maximum: 65_536) { oversized = $0 }
        guard case .failure(let error)? = oversized,
              error.localizedDescription.contains("65536") else {
            return "split oversized complete header escaped its 64 KiB bound"
        }
        let body = Data(repeating: 98, count: 60_000)
        var valid: Result<(Data, Data), Error>?
        let good = ConnectionReader(Fixture([Data(repeating: 97, count: 40_000), marker + body]))
        good.readUntil(marker, maximum: 65_536) { valid = $0 }
        guard case .success(let pair)? = valid, pair.0.count == 40_004, pair.1 == body else {
            return "legal body remainder was counted as oversized header"
        }
        return nil
    }

    func takeBufferedData() -> Data {
        let data = buffer
        buffer.removeAll(keepingCapacity: false)
        return data
    }

    func readExactly(_ count: Int, completion: @escaping (Result<Data, Error>) -> Void) {
        guard count >= 0 else { completion(.failure(EngineError("读取长度无效"))); return }
        if buffer.count >= count {
            let result = Data(buffer.prefix(count))
            buffer.removeFirst(count)
            completion(.success(result))
            return
        }
        receive { [weak self] result in
            switch result {
            case .success:
                self?.readExactly(count, completion: completion)
            case .failure(let error): completion(.failure(error))
            }
        }
    }

    func readUntil(_ marker: Data, maximum: Int,
                   completion: @escaping (Result<(Data, Data), Error>) -> Void) {
        if let range = buffer.range(of: marker) {
            let end = range.upperBound
            guard end <= maximum else {
                completion(.failure(EngineError("请求头超过 \(maximum) 字节")))
                return
            }
            let head = Data(buffer[..<end])
            let remainder = Data(buffer[end...])
            buffer.removeAll(keepingCapacity: false)
            completion(.success((head, remainder)))
            return
        }
        if buffer.count >= maximum {
            completion(.failure(EngineError("请求头超过 \(maximum) 字节")))
            return
        }
        receive { [weak self] result in
            switch result {
            case .success: self?.readUntil(marker, maximum: maximum, completion: completion)
            case .failure(let error): completion(.failure(error))
            }
        }
    }

    private func receive(completion: @escaping (Result<Void, Error>) -> Void) {
        guard !ended else { completion(.failure(EngineError("连接已关闭"))); return }
        connection.receive(maximum: 65_536) { [weak self] data, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.buffer.append(data) }
            if let error {
                self.ended = true
                completion(.failure(error))
            } else if complete && (data == nil || data!.isEmpty) {
                self.ended = true
                completion(.failure(EngineError("连接已关闭")))
            } else {
                completion(.success(()))
            }
        }
    }
}

private func send(_ data: Data, to connection: NWConnection,
                  completion: @escaping (Error?) -> Void) {
    connection.send(content: data, completion: .contentProcessed { error in completion(error) })
}

private func send(_ data: Data, to connection: any OutboundByteStream,
                  completion: @escaping (Error?) -> Void) {
    connection.send(data, completion: completion)
}

/// Retain an in-flight connection until it becomes ready, then release the
/// callback and state handler immediately. TLS timeout closures capture this
/// attempt weakly so busy proxy workloads do not retain every finished socket
/// until the 12-second deadline expires.
private final class TCPConnectionAttempt {
    private var connection: NWConnection?
    private var completion: ((Result<NWConnection, Error>) -> Void)?

    init(connection: NWConnection,
         completion: @escaping (Result<NWConnection, Error>) -> Void) {
        self.connection = connection
        self.completion = completion
    }

    func finish(_ result: Result<NWConnection, Error>, cancel: Bool = false) {
        guard let callback = completion else { return }
        completion = nil
        let value = connection
        connection = nil
        value?.stateUpdateHandler = nil
        if cancel { value?.cancel() }
        callback(result)
    }
}

private func connectTCP(host: String, port: UInt16,
                        tls: Bool = false, serverName: String? = nil,
                        skipCertificateVerification: Bool = false, alpn: [String] = [],
                        queue: DispatchQueue,
                        completion: @escaping (Result<NWConnection, Error>) -> Void) {
    guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
        completion(.failure(EngineError("端口无效")))
        return
    }
    let parameters: NWParameters
    if tls {
        let options = NWProtocolTLS.Options()
        // Without a custom verify block, Network.framework validates the
        // certificate chain and hostname using the server name below.
        sec_protocol_options_set_tls_server_name(options.securityProtocolOptions,
                                                 serverName?.isEmpty == false ? serverName! : host)
        alpn.forEach {
            sec_protocol_options_add_tls_application_protocol(options.securityProtocolOptions, $0)
        }
        if skipCertificateVerification {
            sec_protocol_options_set_verify_block(options.securityProtocolOptions,
                                                   { _, _, complete in complete(true) }, queue)
        }
        parameters = NWParameters(tls: options, tcp: NWProtocolTCP.Options())
    } else {
        parameters = .tcp
    }
    if !isLoopbackHost(host) { parameters.requiredInterface = OutboundInterfaceBinding.current }
    let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: parameters)
    let attempt = TCPConnectionAttempt(connection: connection, completion: completion)
    connection.stateUpdateHandler = { [attempt] state in
        switch state {
        case .ready:
            attempt.finish(.success(connection))
        case .failed(let error):
            attempt.finish(.failure(error), cancel: true)
        case .waiting(let error):
            if case .tls = error { attempt.finish(.failure(error), cancel: true) }
        case .cancelled:
            attempt.finish(.failure(EngineError("出站连接已取消")))
        default: break
        }
    }
    connection.start(queue: queue)
    if tls {
        queue.asyncAfter(deadline: .now() + 12) { [weak attempt] in
            attempt?.finish(.failure(EngineError("出站 TLS 握手超时")), cancel: true)
        }
    }
}

/// Internal rather than private so the policy health monitor can dial a
/// candidate through the exact same path a real request would take. Probing a
/// member any other way would measure something the user never experiences.
enum TunnelConnector {
    static func connect(route: ResolvedRoute, target: RequestTarget, plainHTTP: Bool,
                        queue: DispatchQueue,
                        completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        _ = beginConnect(route: route, target: target, plainHTTP: plainHTTP,
                         queue: queue, completion: completion)
    }

    @discardableResult
    static func beginConnect(route: ResolvedRoute, target: RequestTarget, plainHTTP: Bool,
                             queue: DispatchQueue,
                             waitForSetupAcknowledgement: Bool = false,
                             completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void)
        -> (() -> Void)? {
        switch route {
        case .direct:
            let attempt = ObjCNetworkByteStream.connect(host: target.host, port: target.port,
                interfaceName: isLoopbackHost(target.host) ? nil : OutboundInterfaceBinding.current?.name,
                queue: queue) {
                completion($0.map { ($0, Data()) })
            }
            return { attempt.cancel() }
        case .reject(let reason):
            completion(.failure(EngineError("策略拒绝：\(reason)")))
            return nil
        case .http(let proxy, _):
            return NativeOutboundFactory.beginConnection(policy: proxy, target: target, plainHTTP: plainHTTP, queue: queue,
                                                         waitForSetupAcknowledgement: waitForSetupAcknowledgement) {
                completion($0.map { ($0, Data()) })
            }
        case .socks5(let proxy, _):
            return NativeOutboundFactory.beginConnection(policy: proxy, target: target, queue: queue,
                                                         waitForSetupAcknowledgement: waitForSetupAcknowledgement) {
                completion($0.map { ($0, Data()) })
            }
        case .native(let proxy, _):
            return NativeOutboundFactory.beginConnection(policy: proxy, target: target, queue: queue,
                                                         waitForSetupAcknowledgement: waitForSetupAcknowledgement) {
                completion($0.map { ($0, Data()) })
            }
        }
    }

    /// HTTPS and SOCKS5-TLS use the same HTTP/SOCKS wire format after TLS.
    /// Reject unknown TLS flags and HTTP/2 ALPN rather than sending the clear
    /// protocol to a port the user expected to be protected by TLS.
    private static func connectUpstream(_ proxy: ProxyPolicy, queue: DispatchQueue,
                                        completion: @escaping (Result<any OutboundByteStream, Error>) -> Void) {
        guard let host = proxy.host, let port = proxy.port else {
            completion(.failure(EngineError("HTTP/SOCKS5 上游代理配置不完整")))
            return
        }
        let tls: Bool
        switch (proxy.parameters["tls"] ?? "false")
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "true", "yes", "on", "1": tls = true
        case "false", "no", "off", "0": tls = false
        default:
            completion(.failure(EngineError("HTTP/SOCKS5 上游 tls 参数无效，已拒绝明文连接")))
            return
        }
        let configuredALPN = proxy.parameters["alpn"].map { value in
            value.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) }
                .filter { !$0.isEmpty }
        } ?? []
        if !tls && !configuredALPN.isEmpty {
            completion(.failure(EngineError("明文 HTTP/SOCKS5 上游不能配置 TLS ALPN")))
            return
        }
        if tls && proxy.kind == .http &&
            !configuredALPN.allSatisfy({ $0 == "http/1.1" }) {
            completion(.failure(EngineError("HTTPS 上游只支持 HTTP/1.1 ALPN，不支持 h2")))
            return
        }
        let alpn = tls && proxy.kind == .http && configuredALPN.isEmpty
            ? ["http/1.1"] : configuredALPN
        ObjCNetworkByteStream.connect(host: host, port: port, tls: tls,
                   serverName: proxy.parameters["sni"] ?? proxy.parameters["servername"] ?? host,
                   skipCertificateVerification: proxy.skipsCertificateVerification,
                   alpn: alpn, interfaceName: isLoopbackHost(host) ? nil : OutboundInterfaceBinding.current?.name,
                   queue: queue) { completion($0.map { $0 as any OutboundByteStream }) }
    }

    private static func httpConnect(connection: any OutboundByteStream, proxy: ProxyPolicy,
                                    target: RequestTarget,
                                    completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        var request = "CONNECT \(hostPort(target.host, target.port)) HTTP/1.1\r\nHost: \(hostPort(target.host, target.port))\r\nProxy-Connection: Keep-Alive\r\n"
        if let username = proxy.username, let password = proxy.password {
            let token = Data("\(username):\(password)".utf8).base64EncodedString()
            request += "Proxy-Authorization: Basic \(token)\r\n"
        }
        request += "\r\n"
        send(Data(request.utf8), to: connection) { error in
            if let error { completion(.failure(error)); return }
            let reader = ConnectionReader(connection)
            reader.readUntil(Data("\r\n\r\n".utf8), maximum: 65_536) { result in
                // `ConnectionReader.receive` intentionally captures self weakly.
                // Keep this local reader alive across the asynchronous header
                // read or a valid CONNECT 200 can hang without invoking us.
                withExtendedLifetime(reader) {
                    switch result {
                    case .failure(let error): completion(.failure(error))
                    case .success(let pair):
                        let line = String(data: pair.0, encoding: .utf8)?.components(separatedBy: "\r\n").first ?? ""
                        let fields = line.split(separator: " ")
                        guard fields.count >= 2, let code = Int(fields[1]), (200...299).contains(code) else {
                            completion(.failure(EngineError("上游 HTTP 代理拒绝连接：\(line)")))
                            return
                        }
                        completion(.success((connection, pair.1)))
                    }
                }
            }
        }
    }

    private static func socksConnect(connection: any OutboundByteStream, proxy: ProxyPolicy,
                                     target: RequestTarget,
                                     completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        let reader = ConnectionReader(connection)
        let authenticated = proxy.username != nil
        send(Data([0x05, 0x01, authenticated ? 0x02 : 0x00]), to: connection) { error in
            if let error { completion(.failure(error)); return }
            reader.readExactly(2) { result in
                guard case .success(let response) = result, response.count == 2, response[0] == 0x05 else {
                    completion(.failure(result.error ?? EngineError("SOCKS5 握手失败"))); return
                }
                if response[1] == 0x02 {
                    authenticateSOCKS(connection: connection, reader: reader, proxy: proxy) { authResult in
                        switch authResult {
                        case .failure(let error): completion(.failure(error))
                        case .success: requestSOCKS(connection: connection, reader: reader, target: target, completion: completion)
                        }
                    }
                } else if response[1] == 0x00 {
                    requestSOCKS(connection: connection, reader: reader, target: target, completion: completion)
                } else {
                    completion(.failure(EngineError("SOCKS5 不接受鉴权方式")))
                }
            }
        }
    }

    private static func authenticateSOCKS(connection: any OutboundByteStream, reader: ConnectionReader,
                                          proxy: ProxyPolicy,
                                          completion: @escaping (Result<Void, Error>) -> Void) {
        let user = Data((proxy.username ?? "").utf8)
        let pass = Data((proxy.password ?? "").utf8)
        guard user.count <= 255, pass.count <= 255 else {
            completion(.failure(EngineError("SOCKS5 用户名或密码过长"))); return
        }
        var data = Data([0x01, UInt8(user.count)])
        data.append(user); data.append(UInt8(pass.count)); data.append(pass)
        send(data, to: connection) { error in
            if let error { completion(.failure(error)); return }
            reader.readExactly(2) { result in
                guard case .success(let response) = result, response.count == 2, response[1] == 0 else {
                    completion(.failure(result.error ?? EngineError("SOCKS5 鉴权失败"))); return
                }
                completion(.success(()))
            }
        }
    }

    private static func requestSOCKS(connection: any OutboundByteStream, reader: ConnectionReader,
                                     target: RequestTarget,
                                     completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        var data = Data([0x05, 0x01, 0x00])
        data.append(socksAddress(host: target.host, port: target.port))
        send(data, to: connection) { error in
            if let error { completion(.failure(error)); return }
            reader.readExactly(4) { headerResult in
                guard case .success(let header) = headerResult, header.count == 4,
                      header[0] == 0x05, header[1] == 0 else {
                    completion(.failure(headerResult.error ?? EngineError("SOCKS5 连接被拒绝"))); return
                }
                let remaining: Int
                switch header[3] {
                case 0x01: remaining = 4 + 2
                case 0x04: remaining = 16 + 2
                case 0x03:
                    reader.readExactly(1) { lengthResult in
                        guard case .success(let length) = lengthResult, let count = length.first else {
                            completion(.failure(lengthResult.error ?? EngineError("SOCKS5 响应无效"))); return
                        }
                        reader.readExactly(Int(count) + 2) { tailResult in
                            switch tailResult {
                            case .failure(let error): completion(.failure(error))
                            case .success:
                                completion(.success((connection,
                                                     reader.takeBufferedData())))
                            }
                        }
                    }
                    return
                default: completion(.failure(EngineError("SOCKS5 地址类型无效"))); return
                }
                reader.readExactly(remaining) { tailResult in
                    switch tailResult {
                    case .failure(let error): completion(.failure(error))
                    case .success:
                        completion(.success((connection,
                                             reader.takeBufferedData())))
                    }
                }
            }
        }
    }
}

private final class NetworkOutboundByteStream: OutboundByteStream {
    private let connection: NWConnection
    init(_ connection: NWConnection) { self.connection = connection }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed(completion))
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) {
            data, _, complete, error in completion(data, complete, error)
        }
    }

    func cancel() { connection.cancel() }
}

private final class ConnectionBridge {
    private let client: NWConnection
    private let remote: any OutboundByteStream
    private let id: UUID
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private var finished = false
    private var nativePump: HJStreamPump?

    init(client: NWConnection, remote: any OutboundByteStream, id: UUID, engine: ProxyEngine,
         queue: DispatchQueue) {
        self.client = client
        self.remote = remote
        self.id = id
        self.engine = engine
        self.queue = queue
    }

    func start(clientInitial: Data = Data(), remoteInitial: Data = Data()) {
        let client = self.client
        let nativeClient = HJCallbackStream(queue: queue, supportsHalfClose: true,
            receiveHandler: { maximum, done in
                client.receive(minimumIncompleteLength: 1, maximumLength: Int(clamping: maximum)) {
                    data, _, complete, error in done(data, complete, error)
                }
            }, sendHandler: { data, complete, done in
                client.send(content: data, contentContext: complete ? .finalMessage : .defaultMessage,
                            isComplete: true, completion: .contentProcessed { done($0) })
            }, cancelHandler: { client.cancel() })
        let nativeRemote: any HJByteStream
        if let stream = remote as? ObjCNetworkByteStream { nativeRemote = stream.native }
        else if let stream = remote as? NativeCXXByteStream { nativeRemote = stream.native }
        else {
            let remote = self.remote
            nativeRemote = HJCallbackStream(queue: queue, supportsHalfClose: false,
                receiveHandler: { maximum, done in remote.receive(maximum: Int(clamping: maximum), completion: done) },
                sendHandler: { data, _, done in remote.send(data ?? Data(), completion: done) },
                cancelHandler: { remote.cancel() })
        }
        let pump = HJStreamPump(client: nativeClient, remote: nativeRemote, queue: queue,
            chunkSize: 64 * 1_024, idleTimeout: 300, trafficInterval: 0.1,
            trafficHandler: { [weak self] uploaded, downloaded in
                guard let self else { return }
                self.engine?.emit(.traffic(id: self.id, uploaded: Int(clamping: uploaded), downloaded: Int(clamping: downloaded)))
            }, completion: { [weak self] error in self?.finish(error) })
        pump.firstByteHandler = { elapsed, success in
            NetworkPerformanceDiagnostics.shared.record(.firstByte, milliseconds: elapsed, success: success)
        }
        nativePump = pump
        pump.start(clientInitial: clientInitial, remoteInitial: remoteInitial)
    }

    func cancel() { finish(nil) }

    private func finish(_ error: Error?) {
        queue.async {
            guard !self.finished else { return }
            self.finished = true
            self.nativePump?.cancel(); self.nativePump = nil
            self.client.cancel(); self.remote.cancel()
            self.engine?.emit(.closed(id: self.id, error: error?.localizedDescription))
            self.engine?.handlerFinished(id: self.id)
        }
    }
}

private struct HTTPRequestHead {
    let method: String
    let rawTarget: String
    let version: String
    let host: String
    let port: UInt16
    let header: Data
    let remainder: Data

    var isConnect: Bool { method.uppercased() == "CONNECT" }

    static func parse(header: Data, remainder: Data) throws -> HTTPRequestHead {
        let native = try NativeProtocolCodec.parseHTTP(header)
        func field(_ offset: Int, _ count: Int) -> String {
            let start = header.startIndex + offset
            return String(decoding: header[start..<(start + count)], as: UTF8.self)
        }
        let method = field(native.method_offset, native.method_length)
        let rawTarget = field(native.target_offset, native.target_length)
        let version = field(native.version_offset, native.version_length)
        return HTTPRequestHead(method: method, rawTarget: rawTarget, version: version,
                               host: NativeProtocolCodec.host(native.target), port: native.target.port,
                               header: header, remainder: remainder)
    }

    func requestData(httpProxy: ProxyPolicy?) throws -> Data {
        try NativeProtocolCodec.rewriteHTTP(header + remainder, upstream: httpProxy)
    }
}

private final class HTTPConnectionHandler: CancellableConnectionHandler {
    let id = UUID()
    private let connection: NWConnection
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private var bridge: ConnectionBridge?
    private lazy var reader = ConnectionReader(connection)
    private var finished = false
    private var handshakeDeadline: DispatchWorkItem?

    init(connection: NWConnection, engine: ProxyEngine, queue: DispatchQueue) {
        self.connection = connection
        self.engine = engine
        self.queue = queue
    }

    func start() {
        guard !finished else { return }
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, !self.finished, self.bridge == nil else { return }
            self.fail(EngineError("HTTP 代理握手超时"), sendResponse: false)
        }
        handshakeDeadline = deadline
        queue.asyncAfter(deadline: .now() + (engine?.httpHandshakeTimeout ?? 15), execute: deadline)
        reader.readUntil(Data("\r\n\r\n".utf8), maximum: 65_536) { [weak self] result in
            guard let self, !self.finished else { return }
            switch result {
            case .failure(let error): self.fail(error, sendResponse: true)
            case .success(let pair):
                do { self.handle(try HTTPRequestHead.parse(header: pair.0, remainder: pair.1)) }
                catch { self.fail(error, sendResponse: true) }
            }
        }
    }

    func cancel() {
        queue.async { self.finish(nil) }
    }

    private func handle(_ request: HTTPRequestHead) {
        guard !finished, let engine else { return }
        let protocolName = request.isConnect ? "HTTPS" : "HTTP"
        let peer = peerAddress(connection.endpoint)
        let target = RequestTarget(host: request.host, port: request.port,
                                   protocolName: protocolName,
                                   sourceHost: peer.host, sourcePort: peer.port,
                                   inboundPort: engine.activeHTTPListen.port)
        let route = engine.route(for: target)
        let snapshot = ConnectionSnapshot(id: id, openedAt: Date(), client: endpointDescription(connection.endpoint),
                                          method: protocolName, host: target.host, port: target.port,
                                          policy: route.policyName)
        engine.emit(.opened(snapshot))
        if case .reject = route {
            fail(EngineError("请求被策略拒绝"), sendResponse: true)
            return
        }
        engine.connect(route: route, target: target, plainHTTP: !request.isConnect,
                                queue: queue) { [weak self] result in
            guard let self, !self.finished else {
                if case .success(let pair) = result { pair.0.cancel() }
                return
            }
            switch result {
            case .failure(let error): self.fail(error, sendResponse: true)
            case .success(let pair):
                let remote = pair.0
                if request.isConnect {
                    let established = Data("HTTP/1.1 200 Connection Established\r\nProxy-Agent: Hajimi/1.0\r\n\r\n".utf8)
                    send(established, to: self.connection) { [weak self] error in
                        guard let self, !self.finished else { remote.cancel(); return }
                        if let error { remote.cancel(); self.fail(error, sendResponse: false); return }
                        self.beginBridge(remote: remote, clientInitial: request.remainder, remoteInitial: pair.1)
                    }
                } else {
                    let httpProxy: ProxyPolicy?
                    if case .http(let proxy, _) = route { httpProxy = proxy } else { httpProxy = nil }
                    do {
                        self.beginBridge(remote: remote, clientInitial: try request.requestData(httpProxy: httpProxy),
                                         remoteInitial: pair.1)
                    } catch { remote.cancel(); self.fail(error, sendResponse: true) }
                }
            }
        }
    }

    private func beginBridge(remote: any OutboundByteStream,
                             clientInitial: Data, remoteInitial: Data) {
        guard !finished, let engine else { remote.cancel(); return }
        handshakeDeadline?.cancel(); handshakeDeadline = nil
        let bridge = ConnectionBridge(client: connection, remote: remote, id: id, engine: engine,
                                      queue: queue)
        self.bridge = bridge
        bridge.start(clientInitial: clientInitial, remoteInitial: remoteInitial)
    }

    private func fail(_ error: Error, sendResponse: Bool) {
        guard !finished else { return }
        if sendResponse {
            let body = "Hajimi: \(error.localizedDescription)\n"
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            send(Data(response.utf8), to: connection) { [weak self] _ in self?.finish(error) }
        } else { finish(error) }
    }

    private func finish(_ error: Error?) {
        guard !finished else { return }
        finished = true
        handshakeDeadline?.cancel(); handshakeDeadline = nil
        connection.cancel()
        if let bridge { self.bridge = nil; bridge.cancel(); return }
        engine?.emit(.closed(id: id, error: error?.localizedDescription))
        engine?.handlerFinished(id: id)
    }
}

private final class SOCKSConnectionHandler: CancellableConnectionHandler {
    let id = UUID()
    private let connection: NWConnection
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private var bridge: ConnectionBridge?
    private var udpAssociation: SOCKSUDPAssociation?
    private lazy var reader = ConnectionReader(connection)
    private var finished = false
    private var handshakeCarrier: HJCallbackStream?
    private var handshakeInitial = Data()

    init(connection: NWConnection, engine: ProxyEngine, queue: DispatchQueue) {
        self.connection = connection
        self.engine = engine
        self.queue = queue
    }

    func start() {
        guard !finished else { return }
        let connection = self.connection
        let carrier = HJCallbackStream(queue: queue, supportsHalfClose: true,
            receiveHandler: { maximum, done in
                connection.receive(minimumIncompleteLength: 1, maximumLength: Int(clamping: maximum)) {
                    content, _, eof, error in done(content, eof, error)
                }
            }, sendHandler: { content, eof, done in
                connection.send(content: content, contentContext: eof ? .finalMessage : .defaultMessage,
                    isComplete: true, completion: .contentProcessed { done($0) })
            }, cancelHandler: { connection.cancel() })
        // The C++ parser borrows this carrier. Retain it until routing/pumping
        // or the UDP association ends, not merely until negotiation completes.
        handshakeCarrier = carrier
        HJCppServerProtocols.acceptSOCKS5(stream: carrier, queue: queue) { [weak self] host, port, command, initial, error in
            guard let self, !self.finished else { return }
            if let error { self.finish(error); return } // C++ already sent the rejection and closed its source.
            guard let host else { self.fail(EngineError("C++ SOCKS5 未返回目标地址")); return }
            self.handshakeInitial = initial ?? Data()
            if command == 1 { self.connect(RequestTarget(host: host, port: port, protocolName: "TCP")) }
            else if command == 3 { self.handshakeInitial.removeAll(); self.startUDPAssociation() }
            else { self.fail(EngineError("C++ SOCKS5 返回未知命令")) }
        }
    }

    func cancel() {
        queue.async { self.finish(nil) }
    }

    private func readRequest() {
        reader.readExactly(4) { [weak self] result in
            guard let self else { return }
            guard case .success(let head) = result, head.count == 4, head[0] == 0x05, head[2] == 0x00 else {
                self.fail(result.error ?? EngineError("SOCKS5 请求无效")); return
            }
            self.readAddress(type: head[3]) { addressResult in
                switch addressResult {
                case .failure(let error): self.fail(error)
                case .success(let target):
                    switch head[1] {
                    case 0x01: self.connect(target)
                    case 0x03: self.startUDPAssociation()
                    default: self.fail(EngineError("SOCKS5 命令暂不支持"))
                    }
                }
            }
        }
    }

    private func readAddress(type: UInt8, completion: @escaping (Result<RequestTarget, Error>) -> Void) {
        switch type {
        case 0x01:
            reader.readExactly(6) { result in completion(result.flatMap { parseSOCKSAddress($0, type: type) }) }
        case 0x04:
            reader.readExactly(18) { result in completion(result.flatMap { parseSOCKSAddress($0, type: type) }) }
        case 0x03:
            reader.readExactly(1) { [weak self] result in
                guard let self else { return }
                guard case .success(let data) = result, let length = data.first else {
                    completion(.failure(result.error ?? EngineError("SOCKS5 域名长度无效"))); return
                }
                self.reader.readExactly(Int(length) + 2) { body in
                    completion(body.flatMap { parseSOCKSAddress($0, type: type) })
                }
            }
        default: completion(.failure(EngineError("SOCKS5 地址类型不支持")))
        }
    }

    private func connect(_ target: RequestTarget) {
        guard !finished, let engine else { return }
        let peer = peerAddress(connection.endpoint)
        let routed = RequestTarget(host: target.host, port: target.port,
                                   protocolName: target.protocolName,
                                   sourceHost: peer.host, sourcePort: peer.port,
                                   inboundPort: engine.activeSOCKSListen.port)
        let route = engine.route(for: routed)
        engine.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(),
                                               client: endpointDescription(connection.endpoint), method: "SOCKS",
                                               host: engine.displayHost(for: routed.host), port: routed.port,
                                               policy: route.policyName)))
        if case .reject = route { fail(EngineError("请求被策略拒绝")); return }
        engine.connect(route: route, target: routed, plainHTTP: false, queue: queue) { [weak self] result in
            guard let self, !self.finished else {
                if case .success(let pair) = result { pair.0.cancel() }
                return
            }
            switch result {
            case .failure(let error): self.fail(error)
            case .success(let pair):
                let response: Data
                do { response = try NativeProtocolCodec.socksReply() }
                catch { pair.0.cancel(); self.fail(error); return }
                send(response, to: self.connection) { error in
                    if let error { pair.0.cancel(); self.fail(error); return }
                    guard !self.finished, let engine = self.engine else { pair.0.cancel(); return }
                    let bridge = ConnectionBridge(client: self.connection, remote: pair.0, id: self.id,
                                                  engine: engine, queue: self.queue)
                    self.bridge = bridge
                    bridge.start(clientInitial: self.handshakeInitial, remoteInitial: pair.1)
                    self.handshakeInitial.removeAll()
                }
            }
        }
    }

    private func startUDPAssociation() {
        guard !finished, let engine else { return }
        do {
            let association = try SOCKSUDPAssociation(engine: engine, queue: queue)
            udpAssociation = association
            association.start { [weak self] result in
                guard let self, !self.finished else { association.cancel(); return }
                switch result {
                case .failure(let error): self.fail(error)
                case .success(let port):
                    let response: Data
                    do { response = try NativeProtocolCodec.socksReply(host: "127.0.0.1", port: port) }
                    catch { self.finish(error); return }
                    send(response, to: self.connection) { error in
                        if let error { self.finish(error) }
                        else { self.monitorUDPControlConnection() }
                    }
                }
            }
        } catch { fail(error) }
    }

    private func monitorUDPControlConnection() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] _, _, complete, error in
            guard let self, !self.finished else { return }
            if let error { self.finish(error) }
            else if complete { self.finish(nil) }
            else { self.monitorUDPControlConnection() }
        }
    }

    private func fail(_ error: Error) {
        guard !finished else { return }
        guard let response = try? NativeProtocolCodec.socksReply(code: 1) else { finish(error); return }
        send(response, to: connection) { [weak self] _ in self?.finish(error) }
    }

    private func finish(_ error: Error?) {
        guard !finished else { return }
        finished = true
        udpAssociation?.cancel()
        handshakeCarrier?.cancel(); handshakeCarrier = nil
        handshakeInitial.removeAll()
        connection.cancel()
        if let bridge { self.bridge = nil; bridge.cancel(); return }
        engine?.emit(.closed(id: id, error: error?.localizedDescription))
        engine?.handlerFinished(id: id)
    }
}

private final class SOCKSUDPClient {
    private struct Reply {
        let data: Data
        let completion: (Error?) -> Void
    }
    let id = UUID()
    let connection: NWConnection
    private let reservation: SOCKSUDPReservation
    private var replies = SOCKSUDPWriteQueue<Reply>()
    private(set) var closed = false
    var hasValidPacket = false

    init(connection: NWConnection, reservation: SOCKSUDPReservation) {
        self.connection = connection; self.reservation = reservation
    }

    func reply(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !closed else { completion(EngineError("SOCKS5 UDP 客户端已关闭")); return }
        guard replies.append(Reply(data: data, completion: completion), bytes: data.count) else {
            completion(EngineError("SOCKS5 UDP 客户端发送队列已达上限")); return
        }
        pumpReplies()
    }

    private func pumpReplies() {
        guard !closed, let packet = replies.beginNext() else { return }
        let packetID = packet.id, completion = packet.value.completion
        let reservation = packet.reservation
        connection.send(content: packet.value.data, completion: .contentProcessed { [weak self, reservation] error in
            reservation.release()
            if let self { _ = self.replies.complete(packetID) }
            completion(error)
            self?.pumpReplies()
        })
    }

    func close() {
        guard !closed else { return }
        closed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        let pending = replies.discard()
        reservation.release()
        for reply in pending { reply.completion(EngineError("SOCKS5 UDP 客户端已关闭")) }
    }
}

private final class SOCKSUDPAssociation {
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private let listener: NWListener
    private var clients = SOCKSUDPResourceRegistry<ObjectIdentifier, SOCKSUDPClient>(
        maximumCount: SOCKSUDPResourceLimits.clientsPerAssociation)
    private var flows = SOCKSUDPResourceRegistry<String, SOCKSUDPFlow>(
        maximumCount: SOCKSUDPResourceLimits.directFlowsPerAssociation)
    private var routedFlows = SOCKSUDPResourceRegistry<String, SOCKSRoutedUDPFlow>(
        maximumCount: SOCKSUDPResourceLimits.directFlowsPerAssociation)
    private var upstreamRelays = SOCKSUDPResourceRegistry<String, NativeUDPRelay>(
        maximumCount: SOCKSUDPResourceLimits.relaysPerAssociation)
    private var nativeRelays = SOCKSUDPResourceRegistry<String, NativeUDPRelay>(
        maximumCount: SOCKSUDPResourceLimits.relaysPerAssociation)
    private var routeCache: [String: ResolvedRoute] = [:]
    private var reportedUnsupportedTargets = Set<String>()
    private var lastRoutingRevision: UInt64 = 0
    private var cancelled = false
    private var idleReaper: DispatchWorkItem?

    init(engine: ProxyEngine, queue: DispatchQueue) throws {
        self.engine = engine
        self.queue = queue
        let parameters = NWParameters.udp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }

    func start(completion: @escaping (Result<UInt16, Error>) -> Void) {
        guard !cancelled else { completion(.failure(EngineError("SOCKS5 UDP 会话已关闭"))); return }
        var completed = false
        listener.stateUpdateHandler = { [weak self] state in
            guard let self, !self.cancelled else { return }
            guard !completed else { return }
            switch state {
            case .ready:
                guard let rawPort = self.listener.port?.rawValue else {
                    completed = true
                    completion(.failure(EngineError("无法获得 SOCKS5 UDP 端口")))
                    return
                }
                completed = true
                completion(.success(rawPort))
            case .failed(let error):
                completed = true
                completion(.failure(error))
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.accept(connection)
        }
        listener.start(queue: queue)
        scheduleIdleReaper()
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        idleReaper?.cancel(); idleReaper = nil
        listener.stateUpdateHandler = nil
        listener.cancel()
        let activeClients = clients.removeAll()
        dropRoutedState()
        activeClients.forEach { $0.close() }
    }

    /// Route caches AND already-connected UDP sockets belong to one policy
    /// generation. An old DIRECT socket must never outlive a switch to TLS.
    private func dropRoutedState() {
        let activeFlows = flows.removeAll()
        let activeRoutedFlows = routedFlows.removeAll()
        let activeRelays = upstreamRelays.removeAll()
        let activeNativeRelays = nativeRelays.removeAll()
        routeCache.removeAll(keepingCapacity: false)
        reportedUnsupportedTargets.removeAll(keepingCapacity: false)
        activeFlows.forEach { $0.cancel() }
        activeRoutedFlows.forEach { $0.cancel() }
        activeRelays.forEach { $0.cancel() }
        activeNativeRelays.forEach { $0.cancel() }
    }

    private func refreshRoutingIfNeeded(engine: ProxyEngine) {
        let current = engine.routingRevision()
        guard current != lastRoutingRevision else { return }
        lastRoutingRevision = current
        dropRoutedState()
    }

    private func accept(_ connection: NWConnection) {
        guard !cancelled, clients.hasCapacity,
              let reservation = SOCKSUDPResourceLimits.shared.reserveResource() else {
            connection.cancel(); return
        }
        let client = SOCKSUDPClient(connection: connection, reservation: reservation)
        let key = ObjectIdentifier(connection), token = client.id
        guard clients.insert(client, forKey: key, token: token) else { client.close(); return }
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection else { return }
            switch state {
            case .failed, .cancelled: self.removeClient(connection, token: token)
            default: break
            }
        }
        connection.start(queue: queue)
        receive(on: connection)
    }

    private func receive(on client: NWConnection) {
        client.receiveMessage { [weak self, weak client] data, _, _, error in
            guard let self, let client, !self.cancelled else { return }
            guard self.consume(data, client: client, error: error) else { return }
            self.receive(on: client)
        }
    }

    private func consume(_ data: Data?, client: NWConnection, error: Error?) -> Bool {
        let key = ObjectIdentifier(client)
        guard !cancelled, let record = clients.value(forKey: key), !record.closed else {
            client.cancel(); return false
        }
        if error != nil { removeClient(client, token: record.id); return false }
        if let data {
            switch parseSOCKSUDPDatagram(data) {
            case .failure:
                // Invalid traffic never refreshes an established client.
                if !record.hasValidPacket { removeClient(client, token: record.id); return false }
            case .success(let datagram):
                record.hasValidPacket = true
                clients.touch(key, token: record.id)
                handle(datagram, client: record)
            }
        }
        return true
    }

    static func resourceStateSelfTest() -> String? {
        do {
            let engine = ProxyEngine()
            let association = try SOCKSUDPAssociation(engine: engine, queue: DispatchQueue(label: "app.hajimi.udp-state-test"))
            defer { association.cancel() }
            let budget = SOCKSUDPGlobalBudget(resources: 2, packets: 1, bytes: 1)
            let connection = NWConnection(host: "127.0.0.1", port: .any, using: .udp)
            guard let oldLease = budget.reserveResource() else { return "UDP test slot unavailable" }
            let old = SOCKSUDPClient(connection: connection, reservation: oldLease)
            let key = ObjectIdentifier(connection)
            association.clients = SOCKSUDPResourceRegistry(maximumCount: 1)
            guard association.clients.insert(old, forKey: key, token: old.id),
                  !association.consume(Data([255]), client: connection, error: nil),
                  association.clients.count == 0, old.closed, budget.usage.resources == 0 else {
                return "invalid first UDP packet retained a client or resource slot"
            }
            guard let newLease = budget.reserveResource() else { return "UDP invalid-client slot was not reusable" }
            let current = SOCKSUDPClient(connection: connection, reservation: newLease)
            guard association.clients.insert(current, forKey: key, token: current.id) else {
                return "UDP replacement client was not admitted"
            }
            association.removeClient(connection, token: old.id)
            guard association.clients.count == 1, !current.closed, budget.usage.resources == 1 else {
                return "late UDP client cancellation deleted its replacement"
            }
            association.cancel()
            association.accept(NWConnection(host: "127.0.0.1", port: .any, using: .udp))
            guard association.clients.count == 0, current.closed, budget.usage.resources == 0 else {
                return "UDP association cancellation leaked or admitted late clients"
            }
            guard case .success(let empty) = parseSOCKSUDPDatagram(Data([0, 0, 0, 1, 127, 0, 0, 1, 0, 53])),
                  empty.payload.isEmpty else { return "valid empty SOCKS UDP payload was rejected" }
            return nil
        } catch { return "UDP resource state fixture: \(error.localizedDescription)" }
    }

    private func removeClient(_ connection: NWConnection, token: UUID) {
        guard let client = clients.removeValue(forKey: ObjectIdentifier(connection), token: token) else { return }
        let direct = flows.remove { $0.belongs(to: client) }
        let routed = routedFlows.remove { $0.belongs(to: client) }
        let upstream = upstreamRelays.remove { $0.belongs(to: client) }
        let native = nativeRelays.remove { $0.belongs(to: client) }
        client.close()
        direct.forEach { $0.cancel() }; routed.forEach { $0.cancel() }
        upstream.forEach { $0.cancel() }; native.forEach { $0.cancel() }
    }

    private func scheduleIdleReaper() {
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.cancelled else { return }
            let now = SOCKSUDPResourceLimits.now
            for client in self.clients.expiredValues(now: now) {
                self.removeClient(client.connection, token: client.id)
            }
            self.flows.removeExpired(now: now).forEach { $0.cancel() }
            self.routedFlows.removeExpired(now: now).forEach { $0.cancel() }
            self.upstreamRelays.removeExpired(now: now).forEach { $0.cancel() }
            self.nativeRelays.removeExpired(now: now).forEach { $0.cancel() }
            self.scheduleIdleReaper()
        }
        idleReaper = work
        queue.asyncAfter(deadline: .now() + SOCKSUDPResourceLimits.reapInterval, execute: work)
    }

    private func handle(_ datagram: SOCKSUDPDatagram, client: SOCKSUDPClient) {
        guard let engine else { return }
        refreshRoutingIfNeeded(engine: engine)
        let peer = peerAddress(client.connection.endpoint)
        let target = RequestTarget(host: datagram.target.host, port: datagram.target.port, protocolName: "UDP",
                                   sourceHost: peer.host, sourcePort: peer.port,
                                   inboundPort: engine.activeSOCKSListen.port)
        // Source ownership is part of the identity: clients using the same
        // destination/policy must not receive each other's UDP replies.
        let destinationKey = "\(target.host.lowercased())|\(target.port)|\(target.sourceHost ?? ""):\(target.sourcePort ?? 0)|\(target.inboundPort ?? 0)"
        let targetKey = SOCKSUDPResourceLimits.ownedKey(client: client.id, target: destinationKey)
        let clientKey = ObjectIdentifier(client.connection), clientToken = client.id
        if FakeIPAllocator.isFake(target.host) {
            reportUnsupported(targetKey: targetKey, target: target, client: client, engine: engine,
                route: .reject("Unmapped local fake-IP"),
                message: "本地 SOCKS UDP 不支持跨数据面的 fake-IP；请使用域名或对应 TUN 数据面")
            return
        }
        if let existing = routedFlows.value(forKey: targetKey) {
            routedFlows.touch(targetKey, token: existing.id)
            existing.send(datagram.payload); return
        }
        if target.port == 53 {
            handleRouted(datagram.payload, target: target, key: targetKey, client: client, engine: engine)
            return
        }
        if let existing = flows.value(forKey: targetKey) {
            flows.touch(targetKey, token: existing.id)
            existing.send(datagram.payload); return
        }
        let route: ResolvedRoute
        if let cached = routeCache[destinationKey] { route = cached }
        else {
            route = safeSOCKSUDPRoute(engine.route(for: target), destinationPort: target.port)
            if routeCache.count >= 2_048 { routeCache.removeAll(keepingCapacity: true) }
            routeCache[destinationKey] = route
        }
        switch route {
        case .direct:
            if engine.routesDirectHostnamesViaDNS, !DoHEndpoint.isAddressLiteral(target.host) {
                handleRouted(datagram.payload, target: target, key: targetKey, client: client, engine: engine)
                return
            }
            guard flows.hasCapacity,
                  let reservation = SOCKSUDPResourceLimits.shared.reserveResource() else { return }
            let id = UUID()
            let flow = SOCKSUDPFlow(id: id, target: target, client: client, engine: engine, queue: queue,
                reservation: reservation, onActivity: { [weak self] in
                    self?.flows.touch(targetKey, token: id)
                    self?.clients.touch(clientKey, token: clientToken)
                }, onClose: { [weak self] in self?.flows.removeValue(forKey: targetKey, token: id) })
            guard flows.insert(flow, forKey: targetKey, token: id) else { flow.cancel(); return }
            flow.send(datagram.payload)
        case .socks5(let proxy, let policyName), .native(let proxy, let policyName):
            let upstream: Bool
            if case .socks5 = route { upstream = true } else { upstream = false }
            if upstream, isTLSOnlyUpstream(route) {
                reportUnsupported(targetKey: targetKey, target: target, client: client,
                    engine: engine, route: route, message: "SOCKS5-TLS 上游不支持安全的 UDP Relay")
                return
            }
            let key = SOCKSUDPResourceLimits.ownedKey(client: client.id, target: proxy.name)
            if let relay = upstream ? upstreamRelays.value(forKey: key) : nativeRelays.value(forKey: key) {
                if upstream { upstreamRelays.touch(key, token: relay.id) }
                else { nativeRelays.touch(key, token: relay.id) }
                relay.sendDatagram(target: target, payload: datagram.payload); return
            }
            guard upstream ? upstreamRelays.hasCapacity : nativeRelays.hasCapacity,
                  let reservation = SOCKSUDPResourceLimits.shared.reserveResource() else { return }
            let id = UUID()
            do {
                let relay = try NativeUDPRelay(id: id, proxy: proxy, policyName: policyName,
                    client: client, engine: engine, queue: queue, reservation: reservation,
                    onActivity: { [weak self] in
                        guard let self else { return }
                        if upstream { self.upstreamRelays.touch(key, token: id) }
                        else { self.nativeRelays.touch(key, token: id) }
                        self.clients.touch(clientKey, token: clientToken)
                    }, onClose: { [weak self] in
                        guard let self else { return }
                        if upstream { self.upstreamRelays.removeValue(forKey: key, token: id) }
                        else { self.nativeRelays.removeValue(forKey: key, token: id) }
                    })
                let admitted: Bool
                if upstream { admitted = upstreamRelays.insert(relay, forKey: key, token: id) }
                else { admitted = nativeRelays.insert(relay, forKey: key, token: id) }
                guard admitted else { relay.cancel(); return }
                relay.sendDatagram(target: target, payload: datagram.payload)
            } catch {
                reservation.release()
                reportUnsupported(targetKey: targetKey, target: target, client: client,
                                  engine: engine, route: route, message: error.localizedDescription)
            }
        case .reject(let reason):
            reportUnsupported(targetKey: targetKey, target: target, client: client,
                              engine: engine, route: route, message: reason)
        case .http:
            reportUnsupported(targetKey: targetKey, target: target, client: client,
                              engine: engine, route: route, message: "该代理策略不支持 UDP Relay")
        }
    }

    private func handleRouted(_ payload: Data, target: RequestTarget, key: String,
                              client: SOCKSUDPClient, engine: ProxyEngine) {
        guard routedFlows.hasCapacity,
              let reservation = SOCKSUDPResourceLimits.shared.reserveResource() else { return }
        let id = UUID(), clientKey = ObjectIdentifier(client.connection), clientToken = client.id
        do {
            let flow = try SOCKSRoutedUDPFlow(id: id, target: target, client: client, engine: engine,
                queue: queue, reservation: reservation, onActivity: { [weak self] in
                    self?.routedFlows.touch(key, token: id)
                    self?.clients.touch(clientKey, token: clientToken)
                }, onClose: { [weak self] in self?.routedFlows.removeValue(forKey: key, token: id) })
            guard routedFlows.insert(flow, forKey: key, token: id) else { flow.cancel(); return }
            flow.send(payload)
        } catch {
            reservation.release()
            reportUnsupported(targetKey: key, target: target, client: client, engine: engine,
                               route: engine.route(for: target), message: error.localizedDescription)
        }
    }

    private func reportUnsupported(targetKey: String, target: RequestTarget,
                                   client: SOCKSUDPClient, engine: ProxyEngine,
                                   route: ResolvedRoute, message: String) {
                if reportedUnsupportedTargets.count >= 2_048 {
                    reportedUnsupportedTargets.removeAll(keepingCapacity: true)
                }
                guard reportedUnsupportedTargets.insert(targetKey).inserted else { return }
                let eventID = UUID()
                engine.emit(.opened(ConnectionSnapshot(id: eventID, openedAt: Date(),
                                                       client: endpointDescription(client.connection.endpoint), method: "UDP",
                                                       host: target.host, port: target.port,
                                                       policy: route.policyName)))
                engine.emit(.closed(id: eventID, error: message))
    }
}

public extension ProxyEngine {
    /// Includes pure resource-budget checks and canceled/malformed-client
    /// state replay. Constructed listeners/connections are never started.
    static func socksUDPResourceSelfTest() -> String? {
        SOCKSUDPResourcePolicySelfTest.run() ?? SOCKSUDPAssociation.resourceStateSelfTest()
    }
}

/// The shared packet router handles DNS and protected DIRECT name resolution
/// without changing source ownership or the SOCKS response address.
private final class SOCKSRoutedUDPFlow {
    let id: UUID
    private let target: RequestTarget
    private let client: SOCKSUDPClient
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private let reservation: SOCKSUDPReservation
    private let onActivity: () -> Void, onClose: () -> Void
    private var session: NativeRoutedDatagram?
    private var closed = false

    init(id: UUID, target: RequestTarget, client: SOCKSUDPClient, engine: ProxyEngine,
         queue: DispatchQueue, reservation: SOCKSUDPReservation,
         onActivity: @escaping () -> Void, onClose: @escaping () -> Void) throws {
        self.id = id; self.target = target; self.client = client; self.engine = engine
        self.queue = queue; self.reservation = reservation
        self.onActivity = onActivity; self.onClose = onClose
        session = try engine.makeRoutedUDP(target: target, queue: queue,
            receive: { [weak self] answer in self?.queue.async { self?.receive(answer) } },
            failure: { [weak self] error in self?.queue.async { self?.finish(error) } })
        engine.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(), client: endpointDescription(client.connection.endpoint),
            method: "UDP", host: target.host, port: target.port, policy: target.port == 53 ? "DNS" : "DIRECT")))
    }
    func send(_ data: Data) {
        guard !closed else { return }; onActivity(); session?.send(data)
        engine?.emit(.traffic(id: id, uploaded: data.count, downloaded: 0))
    }
    private func receive(_ data: Data) {
        guard !closed else { return }; onActivity()
        if target.port == 53 { engine?.recordDNSResponse(data) }
        do {
            let packet = try NativeProtocolCodec.encodeSOCKSUDP(target: target, payload: data)
            client.reply(packet) { [weak self] error in
                guard let self, !self.closed else { return }
                if let error { self.finish(error) }
                else { self.engine?.emit(.traffic(id: self.id, uploaded: 0, downloaded: data.count)) }
            }
        } catch { finish(error) }
    }
    func belongs(to client: SOCKSUDPClient) -> Bool { self.client === client }
    func cancel() { finish(nil) }
    private func finish(_ error: Error?) {
        guard !closed else { return }; closed = true; session?.cancel(); session = nil
        reservation.release(); onClose(); engine?.emit(.closed(id: id, error: error?.localizedDescription))
    }
    deinit { session?.cancel(); reservation.release() }
}

private final class NativeUDPRelay {
    let id: UUID
    private weak var engine: ProxyEngine?
    private let client: SOCKSUDPClient
    private let policyName: String
    private let reservation: SOCKSUDPReservation
    private let onActivity: () -> Void
    private let onClose: () -> Void
    private var session: NativeOutboundDatagramSession!
    private var closed = false
    // Stream-based UDP implementations may open a socket per target. Count
    // those logical targets globally as well as the relay itself. They retain
    // their leases until this session closes, never ahead of the C++ session.
    private var targets = SOCKSUDPResourceRegistry<String, SOCKSUDPReservation>(
        maximumCount: SOCKSUDPResourceLimits.targetsPerRelay)

    init(id: UUID, proxy: ProxyPolicy, policyName: String, client: SOCKSUDPClient,
         engine: ProxyEngine, queue: DispatchQueue, reservation: SOCKSUDPReservation,
         onActivity: @escaping () -> Void, onClose: @escaping () -> Void) throws {
        self.id = id; self.reservation = reservation; self.onActivity = onActivity
        self.client = client; self.engine = engine; self.policyName = policyName
        self.onClose = onClose
        if proxy.kind == .socks5 {
            session = try NativeCXXOutbound.makeDatagramSession(policy: proxy, queue: queue,
                receive: { [weak self] target, payload in self?.receive(target: target, payload: payload) },
                failure: { [weak self] error in self?.finish(error) })
        } else {
            session = try NativeOutboundFactory.makeDatagramSession(
                policy: proxy, queue: queue,
                receive: { [weak self] target, payload in self?.receive(target: target, payload: payload) },
                failure: { [weak self] error in self?.finish(error) })
        }
    }

    func sendDatagram(target: RequestTarget, payload: Data) {
        guard !closed else { return }
        let key = "\(target.host.lowercased())|\(target.port)"
        if targets.value(forKey: key) == nil {
            guard targets.hasCapacity, let lease = SOCKSUDPResourceLimits.shared.reserveResource() else { return }
            guard targets.insert(lease, forKey: key, token: UUID()) else { lease.release(); return }
        }
        onActivity()
        engine?.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(), client: "TUN/SOCKS UDP",
                                                method: "UDP", host: target.host, port: target.port,
                                                policy: policyName)))
        // NativeCXXDatagramSession already bounds its pre-ready AND in-flight
        // queue to 512 packets/2 MiB and submits one datagram write at a time.
        session.send(payload, to: target)
        engine?.emit(.traffic(id: id, uploaded: payload.count, downloaded: 0))
    }

    func cancel() { finish(nil) }
    func belongs(to client: SOCKSUDPClient) -> Bool { self.client === client }

    private func receive(target: RequestTarget, payload: Data) {
        guard !closed else { return }
        onActivity()
        let response: Data
        do { response = try NativeProtocolCodec.encodeSOCKSUDP(target: target, payload: payload) }
        catch { finish(error); return }
        let byteCount = payload.count
        client.reply(response) { [weak self] error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error) }
            else { self.engine?.emit(.traffic(id: self.id, uploaded: 0, downloaded: byteCount)) }
        }
    }

    private func finish(_ error: Error?) {
        guard !closed else { return }
        closed = true; session?.cancel()
        targets.removeAll().forEach { $0.release() }
        reservation.release()
        engine?.emit(.closed(id: id, error: error?.localizedDescription))
        onClose()
    }
}

private final class SOCKSUDPFlow {
    let id: UUID
    private let target: RequestTarget
    private let client: SOCKSUDPClient
    private weak var engine: ProxyEngine?
    private let remote: NWConnection
    private let reservation: SOCKSUDPReservation
    private let onActivity: () -> Void
    private let onClose: () -> Void
    private var pending = SOCKSUDPWriteQueue<Data>()
    private var ready = false
    private var closed = false

    init(id: UUID, target: RequestTarget, client: SOCKSUDPClient, engine: ProxyEngine,
         queue: DispatchQueue, reservation: SOCKSUDPReservation,
         onActivity: @escaping () -> Void, onClose: @escaping () -> Void) {
        self.id = id; self.reservation = reservation; self.onActivity = onActivity
        self.target = target
        self.client = client
        self.engine = engine
        self.onClose = onClose
        let parameters = NWParameters.udp
        if !isLoopbackHost(target.host) { parameters.requiredInterface = OutboundInterfaceBinding.current }
        remote = NWConnection(host: NWEndpoint.Host(target.host),
                              port: NWEndpoint.Port(rawValue: target.port)!, using: parameters)
        engine.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(),
                                               client: endpointDescription(client.connection.endpoint), method: "UDP",
                                               host: engine.displayHost(for: target.host), port: target.port,
                                               policy: target.port == 53 ? "DNS" : "DIRECT")))
        remote.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready:
                self.ready = true
                self.pumpWrites()
                self.receive()
            case .failed(let error): self.finish(error)
            case .cancelled: self.finish(nil)
            default: break
            }
        }
        remote.start(queue: queue)
    }

    func send(_ payload: Data) {
        guard !closed else { return }
        guard pending.append(payload, bytes: payload.count) else {
            finish(EngineError("SOCKS5 UDP 发送缓冲达到包数或内存上限")); return
        }
        pumpWrites()
    }

    private func pumpWrites() {
        guard !closed, ready, let packet = pending.beginNext() else { return }
        let packetID = packet.id, byteCount = packet.byteCount, lease = packet.reservation
        remote.send(content: packet.value, completion: .contentProcessed { [weak self, lease] error in
            lease.release()
            guard let self, !self.closed else { return }
            _ = self.pending.complete(packetID)
            if let error { self.finish(error); return }
            self.onActivity()
            self.engine?.emit(.traffic(id: self.id, uploaded: byteCount, downloaded: 0))
            self.pumpWrites()
        })
    }

    func cancel() { finish(nil) }
    func belongs(to client: SOCKSUDPClient) -> Bool { self.client === client }

    private func receive() {
        remote.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error); return }
            if let data {
                self.onActivity()
                if self.target.port == 53 { self.engine?.recordDNSResponse(data) }
                var response = Data([0x00, 0x00, 0x00])
                response.append(socksAddress(host: self.target.host, port: self.target.port))
                response.append(data)
                let byteCount = data.count
                self.client.reply(response) { [weak self] sendError in
                    guard let self, !self.closed else { return }
                    if let sendError { self.finish(sendError); return }
                    self.engine?.emit(.traffic(id: self.id, uploaded: 0, downloaded: byteCount))
                    self.receive()
                }
                return
            }
            self.receive()
        }
    }

    private func finish(_ error: Error?) {
        guard !closed else { return }
        closed = true
        _ = pending.discard()
        remote.stateUpdateHandler = nil
        remote.cancel()
        reservation.release()
        engine?.emit(.closed(id: id, error: error?.localizedDescription))
        onClose()
    }
}

/// One RFC 1928 UDP ASSOCIATE session to an upstream SOCKS5 proxy. All UDP
/// destinations selected by the same policy share the control TCP connection
/// and UDP relay socket.
private final class UpstreamSOCKSUDPRelay {
    private struct PendingDatagram {
        let target: RequestTarget
        let payload: Data
    }

    private let proxy: ProxyPolicy
    private let policyName: String
    private let client: NWConnection
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private let onClose: () -> Void
    private var control: NWConnection?
    private var controlReader: ConnectionReader?
    private var relay: NWConnection?
    private var pending: [PendingDatagram] = []
    private var eventIDs: [String: UUID] = [:]
    private var ready = false
    private var closed = false

    init(proxy: ProxyPolicy, policyName: String, client: NWConnection,
         engine: ProxyEngine, queue: DispatchQueue, onClose: @escaping () -> Void) {
        self.proxy = proxy
        self.policyName = policyName
        self.client = client
        self.engine = engine
        self.queue = queue
        self.onClose = onClose
        establishControlConnection()
    }

    func sendDatagram(target: RequestTarget, payload: Data) {
        guard !closed else { return }
        ensureEvent(for: target)
        guard ready else {
            if pending.count < 512 { pending.append(PendingDatagram(target: target, payload: payload)) }
            return
        }
        sendNow(target: target, payload: payload)
    }

    func cancel() { finish(nil) }

    private func establishControlConnection() {
        let tls = (proxy.parameters["tls"] ?? "false").lowercased()
        guard ["false", "no", "off", "0"].contains(tls) else {
            finish(EngineError("SOCKS5-TLS 上游不支持安全的 UDP Relay"))
            return
        }
        guard let host = proxy.host, let port = proxy.port else {
            finish(EngineError("SOCKS5 UDP 上游配置不完整"))
            return
        }
        connectTCP(host: host, port: port, queue: queue) { [weak self] result in
            guard let self, !self.closed else { return }
            switch result {
            case .failure(let error): self.finish(error)
            case .success(let connection):
                self.control = connection
                let reader = ConnectionReader(connection)
                self.controlReader = reader
                self.negotiateAuthentication(connection: connection, reader: reader)
            }
        }
    }

    private func negotiateAuthentication(connection: NWConnection, reader: ConnectionReader) {
        let hasCredentials = proxy.username != nil
        let greeting = Data(hasCredentials ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00])
        send(greeting, to: connection) { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            reader.readExactly(2) { result in
                guard case .success(let response) = result, response.count == 2, response[0] == 0x05 else {
                    self.finish(result.error ?? EngineError("SOCKS5 UDP 上游握手失败")); return
                }
                switch response[1] {
                case 0x00: self.requestAssociation(connection: connection, reader: reader)
                case 0x02: self.authenticate(connection: connection, reader: reader)
                default: self.finish(EngineError("SOCKS5 UDP 上游拒绝鉴权方式"))
                }
            }
        }
    }

    private func authenticate(connection: NWConnection, reader: ConnectionReader) {
        let username = Data((proxy.username ?? "").utf8)
        let password = Data((proxy.password ?? "").utf8)
        guard username.count <= 255, password.count <= 255 else {
            finish(EngineError("SOCKS5 UDP 上游用户名或密码过长")); return
        }
        var request = Data([0x01, UInt8(username.count)])
        request.append(username)
        request.append(UInt8(password.count))
        request.append(password)
        send(request, to: connection) { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            reader.readExactly(2) { result in
                guard case .success(let response) = result, response.count == 2, response[1] == 0 else {
                    self.finish(result.error ?? EngineError("SOCKS5 UDP 上游鉴权失败")); return
                }
                self.requestAssociation(connection: connection, reader: reader)
            }
        }
    }

    private func requestAssociation(connection: NWConnection, reader: ConnectionReader) {
        let request = Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        send(request, to: connection) { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            reader.readExactly(4) { result in
                guard case .success(let header) = result, header.count == 4,
                      header[0] == 0x05, header[1] == 0 else {
                    self.finish(result.error ?? EngineError("SOCKS5 上游不支持 UDP ASSOCIATE")); return
                }
                self.readBoundAddress(type: header[3], reader: reader) { addressResult in
                    switch addressResult {
                    case .failure(let error): self.finish(error)
                    case .success(let target): self.openRelay(target)
                    }
                }
            }
        }
    }

    private func readBoundAddress(type: UInt8, reader: ConnectionReader,
                                  completion: @escaping (Result<RequestTarget, Error>) -> Void) {
        switch type {
        case 0x01:
            reader.readExactly(6) { completion($0.flatMap { parseSOCKSAddress($0, type: type) }) }
        case 0x04:
            reader.readExactly(18) { completion($0.flatMap { parseSOCKSAddress($0, type: type) }) }
        case 0x03:
            reader.readExactly(1) { result in
                guard case .success(let lengthData) = result, let length = lengthData.first else {
                    completion(.failure(result.error ?? EngineError("SOCKS5 UDP Relay 地址无效"))); return
                }
                reader.readExactly(Int(length) + 2) { body in
                    completion(body.flatMap { parseSOCKSAddress($0, type: type) })
                }
            }
        default: completion(.failure(EngineError("SOCKS5 UDP Relay 地址类型无效")))
        }
    }

    private func openRelay(_ boundTarget: RequestTarget) {
        guard let proxyHost = proxy.host else { finish(EngineError("SOCKS5 上游地址为空")); return }
        let wildcard = boundTarget.host == "0.0.0.0" || boundTarget.host == "::" || boundTarget.host == "::0"
        let host = wildcard ? proxyHost : boundTarget.host
        guard boundTarget.port != 0, let port = NWEndpoint.Port(rawValue: boundTarget.port) else {
            finish(EngineError("SOCKS5 上游返回了无效 UDP Relay 端口")); return
        }
        let parameters = NWParameters.udp
        if !isLoopbackHost(host) { parameters.requiredInterface = OutboundInterfaceBinding.current }
        let relay = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
        self.relay = relay
        relay.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready:
                self.ready = true
                let buffered = self.pending
                self.pending.removeAll()
                buffered.forEach { self.sendNow(target: $0.target, payload: $0.payload) }
                self.receiveRelayDatagram()
                self.monitorControlConnection()
            case .failed(let error): self.finish(error)
            case .cancelled: self.finish(nil)
            default: break
            }
        }
        relay.start(queue: queue)
    }

    private func sendNow(target: RequestTarget, payload: Data) {
        guard let relay, !closed else { return }
        var packet = Data([0x00, 0x00, 0x00])
        packet.append(socksAddress(host: target.host, port: target.port))
        packet.append(payload)
        relay.send(content: packet, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            if let id = self.eventIDs[self.eventKey(target)] {
                self.engine?.emit(.traffic(id: id, uploaded: payload.count, downloaded: 0))
            }
        })
    }

    private func receiveRelayDatagram() {
        relay?.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error); return }
            if let data, !data.isEmpty {
                switch parseSOCKSUDPDatagram(data) {
                case .failure(let error): self.finish(error)
                case .success(let datagram):
                    self.client.send(content: data, completion: .contentProcessed { [weak self] sendError in
                        guard let self else { return }
                        if let sendError { self.finish(sendError); return }
                        if let id = self.eventIDs[self.eventKey(datagram.target)] {
                            self.engine?.emit(.traffic(id: id, uploaded: 0,
                                                       downloaded: datagram.payload.count))
                        }
                    })
                }
            }
            self.receiveRelayDatagram()
        }
    }

    private func monitorControlConnection() {
        control?.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] _, _, complete, error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error) }
            else if complete { self.finish(EngineError("SOCKS5 UDP 上游控制连接已关闭")) }
            else { self.monitorControlConnection() }
        }
    }

    private func ensureEvent(for target: RequestTarget) {
        let key = eventKey(target)
        guard eventIDs[key] == nil, let engine else { return }
        let id = UUID()
        eventIDs[key] = id
        engine.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(),
                                               client: endpointDescription(client.endpoint), method: "UDP",
                                               host: engine.displayHost(for: target.host), port: target.port,
                                               policy: policyName)))
    }

    private func eventKey(_ target: RequestTarget) -> String { "\(target.host)|\(target.port)" }

    private func finish(_ error: Error?) {
        guard !closed else { return }
        closed = true
        control?.cancel()
        relay?.cancel()
        for id in eventIDs.values { engine?.emit(.closed(id: id, error: error?.localizedDescription)) }
        eventIDs.removeAll()
        pending.removeAll()
        onClose()
    }
}

private struct SOCKSUDPDatagram {
    let target: RequestTarget
    let payload: Data
}

private func parseSOCKSUDPDatagram(_ data: Data) -> Result<SOCKSUDPDatagram, Error> {
    Result { let parsed = try NativeProtocolCodec.parseSOCKSUDP(data)
        return SOCKSUDPDatagram(target: parsed.0, payload: parsed.1) }
}

private func parseSOCKSAddress(_ data: Data, type: UInt8) -> Result<RequestTarget, Error> {
    guard data.count >= 3 else { return .failure(EngineError("SOCKS5 地址过短")) }
    let host: String
    let portBytes: Data
    switch type {
    case 0x01:
        guard data.count == 6 else { return .failure(EngineError("SOCKS5 IPv4 地址无效")) }
        host = data.prefix(4).map(String.init).joined(separator: ".")
        portBytes = data.suffix(2)
    case 0x04:
        guard data.count == 18 else { return .failure(EngineError("SOCKS5 IPv6 地址无效")) }
        var address = in6_addr()
        _ = withUnsafeMutableBytes(of: &address) { data.prefix(16).copyBytes(to: $0) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
            return .failure(EngineError("SOCKS5 IPv6 转换失败"))
        }
        host = String(cString: buffer)
        portBytes = data.suffix(2)
    case 0x03:
        guard data.count >= 3, let value = String(data: data.dropLast(2), encoding: .utf8) else {
            return .failure(EngineError("SOCKS5 域名无效"))
        }
        host = value
        portBytes = data.suffix(2)
    default: return .failure(EngineError("SOCKS5 地址类型无效"))
    }
    let port = UInt16(portBytes[portBytes.startIndex]) << 8 | UInt16(portBytes[portBytes.index(after: portBytes.startIndex)])
    return .success(RequestTarget(host: host, port: port, protocolName: "TCP"))
}

private func socksAddress(host: String, port: UInt16) -> Data {
    var ipv4 = in_addr()
    var ipv6 = in6_addr()
    var data = Data()
    if inet_pton(AF_INET, host, &ipv4) == 1 {
        data.append(0x01)
        withUnsafeBytes(of: &ipv4) { data.append(contentsOf: $0) }
    } else if inet_pton(AF_INET6, host, &ipv6) == 1 {
        data.append(0x04)
        withUnsafeBytes(of: &ipv6) { data.append(contentsOf: $0) }
    } else {
        let bytes = Data(host.utf8.prefix(255))
        data.append(0x03); data.append(UInt8(bytes.count)); data.append(bytes)
    }
    data.append(UInt8(port >> 8)); data.append(UInt8(port & 0xff))
    return data
}

/// Loopback traffic must stay on the loopback interface even while enhanced
/// mode pins ordinary outbound sockets to the physical interface. Advanced
/// protocol adapters are exposed to the engine through 127.0.0.1 listeners.
private func isLoopbackHost(_ rawHost: String) -> Bool {
    var host = rawHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    if let zone = host.firstIndex(of: "%") { host = String(host[..<zone]) }
    if host == "localhost" || host == "::1" || host.hasPrefix("127.") { return true }

    var address = in_addr()
    guard inet_pton(AF_INET, host, &address) == 1 else { return false }
    return UInt32(bigEndian: address.s_addr) >> 24 == 127
}

private func parseHostPort(_ value: String, defaultPort: UInt16) -> (String, UInt16)? {
    if value.hasPrefix("["), let bracket = value.firstIndex(of: "]") {
        let host = String(value[value.index(after: value.startIndex)..<bracket])
        let rest = value[value.index(after: bracket)...]
        if rest.first == ":", let port = UInt16(rest.dropFirst()) { return (host, port) }
        return (host, defaultPort)
    }
    if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":"),
       let port = UInt16(value[value.index(after: colon)...]) {
        return (String(value[..<colon]), port)
    }
    return value.isEmpty ? nil : (value, defaultPort)
}

private func hostPort(_ host: String, _ port: UInt16) -> String {
    host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
}

private func endpointDescription(_ endpoint: NWEndpoint) -> String {
    switch endpoint {
    case .hostPort(let host, let port): return "\(host):\(port)"
    default: return String(describing: endpoint)
    }
}

private func peerAddress(_ endpoint: NWEndpoint) -> (host: String?, port: UInt16?) {
    switch endpoint {
    case .hostPort(let host, let port):
        return (String(describing: host), port.rawValue)
    default:
        return (nil, nil)
    }
}

/// Picks a free local TCP port for HTTP/SOCKS listeners.
///
/// Prefer the profile port; if it is taken, walk nearby ports then a random
/// high range so engine start never fails solely because another proxy owns
/// 7162/7163.
enum ListenPortAllocator {
    static func availableAddress(preferred: ListenAddress, kind: String,
                                 excluding: Set<UInt16>,
                                 forceAlternate: Bool = false) throws -> ListenAddress {
        let host = preferred.host.isEmpty ? "127.0.0.1" : preferred.host
        var blocked = excluding
        if !forceAlternate, preferred.port > 0, !blocked.contains(preferred.port),
           canBind(host: host, port: preferred.port) {
            return ListenAddress(host: preferred.host, port: preferred.port)
        }
        blocked.insert(preferred.port)

        // Nearby first so the UI stays close to the configured values.
        if preferred.port > 0 {
            for delta in 1...64 {
                for candidate in [preferred.port &+ UInt16(delta),
                                  preferred.port &- UInt16(delta)] where candidate >= 1024 {
                    if blocked.contains(candidate) { continue }
                    blocked.insert(candidate)
                    if canBind(host: host, port: candidate) {
                        return ListenAddress(host: preferred.host, port: candidate)
                    }
                }
            }
        }

        // Random high ports as a last resort.
        let base = UInt16.random(in: 20_000...55_000)
        for offset in 0..<2_000 {
            let candidate = base &+ UInt16(offset)
            if candidate < 1024 || blocked.contains(candidate) { continue }
            blocked.insert(candidate)
            if canBind(host: host, port: candidate) {
                return ListenAddress(host: preferred.host, port: candidate)
            }
        }
        throw EngineError("无法为 \(kind) 找到可用监听端口")
    }

    /// True when nothing is accepting TCP on the address.
    ///
    /// This must not bind-and-close the candidate. A probe bind without
    /// `SO_REUSEADDR` leaves the port reserved; `NWListener` then either
    /// fails with EADDRINUSE or sits in `.waiting` until start times out.
    private static func canBind(host: String, port: UInt16) -> Bool {
        if host.contains(":") {
            return !isListeningIPv6(host: host, port: port)
        }
        return !isListeningIPv4(host: host, port: port)
    }

    private static func isListeningIPv4(host: String, port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { Darwin.close(fd) }
        setNonBlocking(fd)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        if host == "0.0.0.0" || host.isEmpty {
            address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        } else {
            var addr = in_addr()
            guard host.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return true }
            address.sin_addr = addr
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return connectReachedListener(fd: fd, result: result)
    }

    private static func isListeningIPv6(host: String, port: UInt16) -> Bool {
        let fd = socket(AF_INET6, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { Darwin.close(fd) }
        setNonBlocking(fd)
        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        if host == "::" || host.isEmpty {
            address.sin6_addr = in6addr_loopback
        } else {
            var addr = in6_addr()
            guard host.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return true }
            address.sin6_addr = addr
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        return connectReachedListener(fd: fd, result: result)
    }

    private static func setNonBlocking(_ fd: Int32) {
        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
    }

    /// `connect` succeeded or is in progress toward an accepting socket.
    /// `ECONNREFUSED` (and friends) means the port is free.
    private static func connectReachedListener(fd: Int32, result: Int32) -> Bool {
        if result == 0 { return true }
        let code = errno
        if code == ECONNREFUSED || code == EHOSTUNREACH || code == ENETUNREACH {
            return false
        }
        if code == EINPROGRESS || code == EWOULDBLOCK {
            var pollFD = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&pollFD, 1, 40)
            if ready > 0, pollFD.revents & Int16(POLLOUT) != 0 {
                var error: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                _ = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length)
                return error == 0
            }
            return false
        }
        return false
    }
}

private final class DNSMappingCache {
    private struct Entry {
        let domain: String
        let expiresAt: Date
    }
    private let lock = NSLock()
    private var entries: [String: Entry] = [:]

    func set(domain: String, for address: String, ttl: UInt32) {
        let lifetime = max(1, min(TimeInterval(ttl), 86_400))
        let expiration = Date().addingTimeInterval(lifetime)
        lock.lock()
        if entries.count >= 16_384 { entries.removeAll(keepingCapacity: true) }
        entries[address.lowercased()] = Entry(domain: domain.lowercased(),
                                               expiresAt: expiration)
        lock.unlock()
    }

    func domain(for address: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        let key = address.lowercased()
        guard let entry = entries[key] else { return nil }
        if entry.expiresAt <= Date() {
            entries.removeValue(forKey: key)
            return nil
        }
        return entry.domain
    }

    func removeAll() {
        lock.lock(); entries.removeAll(); lock.unlock()
    }
}

private struct DNSAddressRecord {
    let domain: String
    let address: String
    let ttl: UInt32
}

/// Test seam over `DNSMessage`, which is private to this file.
enum DNSMessageProbe {
    static func addressRecords(in data: Data) -> [(domain: String, address: String, ttl: UInt32)] {
        DNSMessageInspection.addressAnswers(in: data)
    }
}

private enum DNSMessage {
    static func addressRecords(in data: Data) -> [DNSAddressRecord] {
        guard data.count >= 12 else { return [] }
        let questionCount = Int(readUInt16(data, 4) ?? 0)
        let answerCount = Int(readUInt16(data, 6) ?? 0)
        guard questionCount > 0 else { return [] }
        var offset = 12
        guard let queryName = readName(data, offset: &offset) else { return [] }
        guard offset + 4 <= data.count else { return [] }
        offset += 4
        if questionCount > 1 {
            for _ in 1..<questionCount {
                guard readName(data, offset: &offset) != nil, offset + 4 <= data.count else { return [] }
                offset += 4
            }
        }

        var result: [DNSAddressRecord] = []
        for _ in 0..<answerCount {
            guard readName(data, offset: &offset) != nil, offset + 10 <= data.count,
                  let type = readUInt16(data, offset),
                  let ttl = readUInt32(data, offset + 4),
                  let length = readUInt16(data, offset + 8) else { break }
            offset += 10
            let count = Int(length)
            guard offset + count <= data.count else { break }
            if type == 1, count == 4 {
                let bytes = data[offset..<(offset + 4)]
                result.append(DNSAddressRecord(domain: queryName,
                                               address: bytes.map(String.init).joined(separator: "."), ttl: ttl))
            } else if type == 28, count == 16 {
                var address = in6_addr()
                _ = withUnsafeMutableBytes(of: &address) { data[offset..<(offset + 16)].copyBytes(to: $0) }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    result.append(DNSAddressRecord(domain: queryName, address: String(cString: buffer), ttl: ttl))
                }
            }
            offset += count
        }
        return result
    }

    private static func readName(_ data: Data, offset: inout Int, depth: Int = 0) -> String? {
        guard depth < 16 else { return nil }
        var labels: [String] = []
        var cursor = offset
        var consumed = 0
        var jumped = false
        while cursor < data.count {
            let length = Int(data[cursor])
            if length == 0 {
                if !jumped { consumed += 1 }
                offset += consumed
                return labels.joined(separator: ".")
            }
            if length & 0xC0 == 0xC0 {
                guard cursor + 1 < data.count else { return nil }
                let pointer = ((length & 0x3F) << 8) | Int(data[cursor + 1])
                if !jumped { consumed += 2 }
                jumped = true
                var pointerOffset = pointer
                guard let suffix = readName(data, offset: &pointerOffset, depth: depth + 1) else { return nil }
                if !suffix.isEmpty { labels.append(suffix) }
                offset += consumed
                return labels.joined(separator: ".")
            }
            guard length <= 63, cursor + 1 + length <= data.count,
                  let label = String(data: data[(cursor + 1)..<(cursor + 1 + length)], encoding: .utf8) else {
                return nil
            }
            labels.append(label)
            cursor += 1 + length
            if !jumped { consumed += 1 + length }
        }
        return nil
    }

    private static func readUInt16(_ data: Data, _ offset: Int) -> UInt16? {
        guard offset + 2 <= data.count else { return nil }
        return UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    private static func readUInt32(_ data: Data, _ offset: Int) -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        return UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 |
            UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
    }
}

private extension Result {
    var error: Failure? {
        if case .failure(let error) = self { return error }
        return nil
    }
}

// Explicit diagnostics use the existing live routing core. Constructing a
// temporary router here would reconfigure the process-wide outbound factory.
public extension ProxyEngine {
    /// An explicit terminal result for a missing or revoked App-owned data
    /// plane. Callers supply fixed UI text, never raw errors or profile values.
    static func unavailableNetworkDiagnostics(
        detail: String = "请先开启增强模式或启动代理引擎后再测试",
        callbackQueue: DispatchQueue = .main,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        let tasks = NetworkConnectivityDiagnosticKind.networkDiagnosticOrder.map { kind in
            NetworkConnectivityDiagnosticTask(row: .init(id: kind.rawValue, kind: kind,
                title: kind.networkDiagnosticTitle, endpoint: "", route: "未启动",
                status: .skipped, detail: detail))
        }
        return NetworkConnectivityDiagnosticsSession(tasks: tasks, callbackQueue: callbackQueue,
            isCurrent: { true }, onUpdate: onUpdate)
    }

    @discardableResult
    func startNetworkDiagnostics(callbackQueue: DispatchQueue = .main,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        let context = stateQueue.sync { (status, dnsPacketRouter, routingGeneration) }
        guard context.0 == .running, let router = context.1 else {
            return Self.unavailableNetworkDiagnostics(detail: "代理核心未就绪；请启动后再测试",
                callbackQueue: callbackQueue, onUpdate: onUpdate)
        }
        let capturedRoutingGeneration = context.2
        return router.startNetworkDiagnostics(callbackQueue: callbackQueue, ownerIsCurrent: { [weak self, weak router] in
            guard let self, let router else { return false }
            return self.stateQueue.sync {
                self.status == .running && self.routingGeneration == capturedRoutingGeneration && self.dnsPacketRouter === router
            }
        }, onUpdate: onUpdate)
    }
}

/// Enhanced mode owns a router independently of the optional HTTP/SOCKS
/// listeners. Diagnose that existing data plane without starting listeners or
/// constructing another router. Owner permission never replaces the router's
/// own policy generation and physical-interface checks.
public extension NativePacketRouter {
    @discardableResult
    func startNetworkDiagnostics(callbackQueue: DispatchQueue = .main,
        ownerIsCurrent: @escaping () -> Bool = { true },
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        let round = networkDiagnosticRound(ownerIsCurrent: ownerIsCurrent)
        return NetworkConnectivityDiagnosticsSession(tasks: round.tasks,
            omittedEndpointCount: round.omitted, callbackQueue: callbackQueue,
            isCurrent: round.isCurrent, onUpdate: onUpdate)
    }
}

private extension NetworkConnectivityDiagnosticKind {
    static let networkDiagnosticOrder: [Self] = [.localLatency, .proxyLatency, .traditionalDNS, .encryptedDNS]
    var networkDiagnosticTitle: String {
        switch self {
        case .localLatency: return "本地直连 HTTP 首响应"
        case .proxyLatency: return "所选代理 HTTP 首响应"
        case .traditionalDNS: return "普通 DNS 固定连通性测试"
        case .encryptedDNS: return "加密 DNS 固定 A 查询"
        case .proxyDNS: return "代理内普通 DNS 固定 A 查询"
        }
    }
}

private extension NativePacketRouter {
    static let networkDiagnosticHost = "captive.apple.com"
    static let networkDiagnosticPath = "/hotspot-detect.html"

    func networkDiagnosticSnapshot() -> DNSRoutingSnapshot { dnsSnapshot() }

    func networkDiagnosticRound(ownerIsCurrent: @escaping () -> Bool)
        -> (tasks: [NetworkConnectivityDiagnosticTask], omitted: Int, isCurrent: () -> Bool) {
        let snapshot = networkDiagnosticSnapshot()
        let generation = snapshot.generation
        let interface = ProxyEngine.currentOutboundInterface?.name
        let current: () -> Bool = { [weak self] in
            guard let self else { return false }
            return ownerIsCurrent() && self.isCurrentDNSGeneration(generation)
                && ProxyEngine.currentOutboundInterface?.name == interface
        }
        let plan = networkDiagnosticTasks(snapshot: snapshot, current: current)
        return (plan.tasks, plan.omitted, current)
    }

    func networkDiagnosticTasks(snapshot: DNSRoutingSnapshot, current: @escaping () -> Bool)
        -> (tasks: [NetworkConnectivityDiagnosticTask], omitted: Int) {
        var tasks: [NetworkConnectivityDiagnosticTask] = []
        var omitted = 0
        let boundInterface = ProxyEngine.currentOutboundInterface
        let httpTarget = RequestTarget(host: Self.networkDiagnosticHost, port: 80, protocolName: "TCP")
        let targetAllowed: Bool
        if case .reject = snapshot.route(httpTarget, mode: .rule) { targetAllowed = false }
        else { targetAllowed = true }
        let direct = ResolvedRoute.direct("DIRECT")
        let selected = snapshot.profile.route(for: httpTarget, mode: .proxy,
            globalPolicy: snapshot.globalPolicy, groupSelections: snapshot.selections)
        for (kind, route) in [(NetworkConnectivityDiagnosticKind.localLatency, direct), (.proxyLatency, selected)] {
            var row = NetworkConnectivityDiagnosticResult(id: kind.rawValue, kind: kind,
                title: kind.networkDiagnosticTitle,
                endpoint: "http://captive.apple.com:80", route: networkDiagnosticRouteLabel(route))
            if !targetAllowed {
                row.status = .skipped; row.detail = "固定 HTTP 测试目标被当前规则拒绝"
                tasks.append(.init(row: row)); continue
            }
            if kind == .proxyLatency {
                if snapshot.mode == .direct {
                    row.status = .skipped; row.detail = "当前处于直连模式，未测试代理路径"
                    tasks.append(.init(row: row)); continue
                }
                switch route {
                case .direct:
                    row.status = .skipped; row.detail = "所选策略最终为 DIRECT，没有可测代理路径"
                    tasks.append(.init(row: row)); continue
                case .reject:
                    row.status = .skipped; row.detail = "所选策略拒绝连接"
                    tasks.append(.init(row: row)); continue
                case .http(let node, _), .socks5(let node, _), .native(let node, _):
                    if let host = node.host, let port = node.port,
                       case .reject = snapshot.route(RequestTarget(host: host, port: port, protocolName: "TCP"), mode: .rule) {
                        row.status = .skipped; row.detail = "所选代理端点被当前规则拒绝"
                        tasks.append(.init(row: row)); continue
                    }
                }
            }
            tasks.append(.init(row: row, timeout: 8, operation: { [weak self] lane, _, done in
                guard let self, current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return nil }
                return self.beginNetworkDiagnosticHTTP(route: route, snapshot: snapshot,
                    queue: lane, current: current, completion: done)
            }))
        }

        let ordinary = snapshot.profile.traditionalDNSServers
        omitted += max(0, ordinary.count - 8)
        if ordinary.isEmpty {
            tasks.append(.init(row: .init(id: "traditionalDNS", kind: .traditionalDNS,
                title: NetworkConnectivityDiagnosticKind.traditionalDNS.networkDiagnosticTitle,
                endpoint: "", route: "本地固定测试", status: .skipped, detail: "未配置固定 IP 的普通 DNS")))
        }
        for (index, raw) in ordinary.prefix(8).enumerated() {
            var row = NetworkConnectivityDiagnosticResult(id: "traditionalDNS-\(index)", kind: .traditionalDNS,
                title: "普通 DNS \(index + 1) · 固定连通性测试", endpoint: "配置项 \(index + 1)", route: "本地固定测试")
            guard let server = TraditionalDNSServer(raw) else {
                row.status = .skipped; row.detail = "此配置不是可测试的固定 IP 普通 DNS；未调用系统解析器"
                tasks.append(.init(row: row)); continue
            }
            let ipv6 = server.usesIPv6Transport
            let family = ipv6 ? "IPv6" : "IPv4"
            let directRoute = server.isLoopback ? "本机回环 · 固定测试"
                : boundInterface.map { "物理接口 \($0.name) 直连 · 固定测试" }
                    ?? "本地默认路径 · 固定测试（未绑定物理接口）"
            row = .init(id: row.id, kind: row.kind,
                title: "普通 DNS \(index + 1) · \(family) 传输 / A 查询",
                endpoint: networkDiagnosticAuthority(server.host, server.port),
                route: directRoute)
            var allowed = true
            for proto in ["UDP", "TCP"] {
                let target = RequestTarget(host: server.host, port: server.port, protocolName: proto)
                for choice in [snapshot.route(target, mode: .rule),
                               snapshot.route(target, name: Self.networkDiagnosticHost, mode: .rule)] {
                    if case .reject = choice { allowed = false }
                }
            }
            guard allowed else {
                row.status = .skipped; row.detail = "普通 DNS 端点或固定测试域名被当前规则拒绝"
                tasks.append(.init(row: row)); continue
            }
            let evidence = NetworkConnectivityDNSProbeEvidence(ipv6: ipv6)
            tasks.append(.init(row: row, timeout: 4, deadlineMeasurement: evidence.deadlineMeasurement,
                operation: { lane, deadline, done in
                guard current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return nil }
                let queryID = UInt16.random(in: .min ... .max)
                let query = DNSMessageInspection.query(for: Self.networkDiagnosticHost, type: 1, id: queryID)!
                let probe = TraditionalDNSConnectivityProbe(server: server,
                    interface: boundInterface, queue: lane, deadline: deadline,
                    queryID: queryID, permitted: current, onWaitingError: evidence.observePathError) { result in
                    guard current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return }
                    switch result {
                    case .success(let response):
                        var measurement = NetworkConnectivityDNSResponse.inspect(response, query: query)
                        measurement.detail += "；本地 \(family) 传输固定测试，不授权应用明文 DNS 降级"
                        done(measurement)
                    case .failure(let error):
                        done(NetworkConnectivityDNSProbeFailure.inspect(error, ipv6: ipv6))
                    }
                }
                probe.start()
                return { probe.cancel() }
            }))
        }

        let encrypted = snapshot.profile.effectiveEncryptedDNSServers
        omitted += max(0, encrypted.count - 8)
        guard !encrypted.isEmpty else {
            tasks.append(.init(row: .init(id: "encryptedDNS", kind: .encryptedDNS,
                title: NetworkConnectivityDiagnosticKind.encryptedDNS.networkDiagnosticTitle,
                endpoint: "", route: "当前 DNS 路径", status: .skipped, detail: "当前配置未使用加密 DNS")))
            return (tasks, omitted)
        }
        let query = DNSMessageInspection.query(for: Self.networkDiagnosticHost, type: 1)!
        let original = RequestTarget(host: protectedSystemDNSGateway, port: 53, protocolName: "UDP")
        let approvedPlan: DNSQueryPlan?
        if case .upstream(let plan)? = try? prepareDNSQuery(query, original: original, synthesizeFakeIP: false) {
            approvedPlan = plan
        } else { approvedPlan = nil }
        for (index, raw) in encrypted.prefix(8).enumerated() {
            var row = NetworkConnectivityDiagnosticResult(id: "encryptedDNS-\(index)", kind: .encryptedDNS,
                title: "加密 DNS \(index + 1) · 固定 A 查询", endpoint: "配置项 \(index + 1)", route: "当前 DNS 路径")
            let upstream: DNSConfiguredUpstream?
            if raw.lowercased().hasPrefix("https://"), let endpoint = DoHEndpoint(raw, allowUnresolvedHost: true) {
                upstream = .doh(endpoint)
                row = .init(id: row.id, kind: row.kind, title: row.title,
                    endpoint: "DoH " + networkDiagnosticAuthority(endpoint.host, endpoint.port), route: row.route)
            } else if raw.lowercased().hasPrefix("tls://"), let endpoint = DoTEndpoint(raw) {
                upstream = .dot(endpoint)
                row = .init(id: row.id, kind: row.kind, title: row.title,
                    endpoint: "DoT " + networkDiagnosticAuthority(endpoint.host, endpoint.port), route: row.route)
            } else { upstream = nil }
            guard let upstream else {
                row.status = .skipped; row.detail = "加密 DNS 配置无效；未降级或替换上游"
                tasks.append(.init(row: row)); continue
            }
            guard let plan = approvedPlan,
                  let candidate = plan.candidates.first(where: { candidate in
                      upstream.builtinAddressVariants.contains(where: { $0.candidateID == candidate.id })
                  }), let chosen = try? revalidatedCandidatePlan(plan, candidate: candidate) else {
                row.status = .skipped; row.detail = "固定查询或该加密 DNS 端点未获当前规则许可"
                tasks.append(.init(row: row)); continue
            }
            row = .init(id: row.id, kind: row.kind, title: row.title,
                endpoint: row.endpoint, route: networkDiagnosticRouteLabel(chosen.route))
            tasks.append(.init(row: row, timeout: 8, operation: { [weak self] lane, _, done in
                guard let self, current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return nil }
                do {
                    // Revalidate one approved endpoint without altering its
                    // authority, answer cache, adaptive selection or fallback.
                    let fresh = try self.revalidatedCandidatePlan(plan, candidate: candidate)
                    let flow = try self.makeDNSUpstream(plan: fresh, queue: lane,
                        receive: { answer in
                            guard current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return }
                            done(NetworkConnectivityDNSResponse.inspect(answer, query: query))
                        }, failure: { error in
                            done(.init(status: .failure, detail: "加密 DNS 连接、认证或查询失败", error: error))
                        })
                    flow.send(query)
                    return {
                        if let acknowledging = flow as? DNSQueryCancellationAcknowledging {
                            acknowledging.cancel(reason: .callerCancelled, completion: {})
                        } else { flow.cancel() }
                    }
                } catch {
                    done(.init(status: .failure, detail: "当前加密 DNS 计划已失效或未获许可", error: error)); return nil
                }
            }))
        }
        return (tasks, omitted)
    }

    func beginNetworkDiagnosticHTTP(route: ResolvedRoute, snapshot: DNSRoutingSnapshot,
        queue: DispatchQueue, current: @escaping () -> Bool,
        completion: @escaping (NetworkConnectivityDiagnosticMeasurement) -> Void) -> (() -> Void)? {
        let exchange = NetworkConnectivityHTTPExchange(host: Self.networkDiagnosticHost,
            path: Self.networkDiagnosticPath, queue: queue, completion: completion)
        let target = RequestTarget(host: Self.networkDiagnosticHost, port: 80, protocolName: "TCP")
        let connect: (RequestTarget) -> Void = { addressTarget in
            guard current(), exchange.reserve(.shared) else {
                exchange.fail(.init(status: .skipped, detail: "配置已变化或共享测试连接达到上限")); return
            }
            exchange.installCancellation(TunnelConnector.beginConnect(route: route, target: addressTarget,
                plainHTTP: false, queue: queue, waitForSetupAcknowledgement: true) { result in
                    guard current() else {
                        if case .success(let pair) = result { pair.0.cancel() }
                        exchange.connected(.failure(EncryptedDNSQueryFailure.policy)); return
                    }
                    exchange.connected(result)
                })
        }
        guard case .direct = route else {
            connect(target)
            return { exchange.cancel() }
        }
        // Resolve DIRECT through the existing protected query router. Its
        // flow is individually cancellable; no system-resolver shortcut or
        // non-cancellable resolveAddresses helper is introduced for the test.
        let resolving = NetworkConnectivityProbeCleanup()
        exchange.installCancellation { resolving.cancel() }
        let query = DNSMessageInspection.query(for: Self.networkDiagnosticHost, type: 1)!
        let original = RequestTarget(host: protectedSystemDNSGateway, port: 53, protocolName: "UDP")
        do {
            let flow = try makeDNSDatagram(original: original, queue: queue, synthesizeFakeIP: false,
                receive: { answer in
                    queue.async {
                        guard current() else {
                            exchange.fail(.init(status: .cancelled, detail: "配置或接口已变化")); return
                        }
                        let inspection = NetworkConnectivityDNSResponse.inspect(answer, query: query)
                        guard inspection.status == .success else {
                            exchange.fail(.init(status: .failure,
                                detail: "本地直连测试的受保护 DNS 解析失败"
                                    + (inspection.responseCode.map { "（DNS RCODE \($0)）" } ?? ""),
                                extendedDNSErrorCodes: inspection.extendedDNSErrorCodes)); return
                        }
                        let addresses = DNSMessageInspection.addressAnswers(in: answer)
                            .map(\.address).filter { !$0.contains(":") }
                        let approved = addresses.first { address in
                            var destination = target; destination.host = address
                            if case .reject = snapshot.route(destination, mode: .rule) { return false }
                            return true
                        }
                        guard let approved else {
                            exchange.fail(.init(status: .skipped, detail: "固定 HTTP 目标的解析地址被当前规则拒绝")); return
                        }
                        resolving.cancel()
                        var literal = target; literal.host = approved
                        connect(literal)
                    }
                }, failure: { error in
                    exchange.fail(.init(status: .failure, detail: "本地直连测试的受保护 DNS 查询失败", error: error))
                })
            resolving.install {
                flow.cancel()
            }
            flow.send(query)
        } catch { exchange.fail(.init(status: .failure, detail: "本地直连测试的 DNS 计划未获许可", error: error)) }
        return { exchange.cancel() }
    }
}

private func networkDiagnosticAuthority(_ host: String, _ port: UInt16) -> String {
    (host.contains(":") ? "[\(host)]" : host) + ":\(port)"
}

private func networkDiagnosticRouteLabel(_ route: ResolvedRoute) -> String {
    switch route {
    case .direct: return "DIRECT"
    case .reject: return "REJECT"
    case .http(let node, _): return "HTTP 代理 · " + NetworkPerformanceDiagnostics.dnsOpaqueID(node.name, prefix: "node")
    case .socks5(let node, _): return "SOCKS5 代理 · " + NetworkPerformanceDiagnostics.dnsOpaqueID(node.name, prefix: "node")
    case .native(let node, _): return "原生代理 · " + NetworkPerformanceDiagnostics.dnsOpaqueID(node.name, prefix: "node")
    }
}

/// Planning-only vectors. These instantiate no resolver/stream and execute no
/// network operation; the same private authorization bridge plans production.
public enum NetworkConnectivityDiagnosticsRoutingSelfTest {
    private struct Failure: Error { let text: String }
    public static func run() throws {
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            if !condition() { throw Failure(text: text) }
        }
        func planned(_ profile: Profile, mode: OutboundMode = .rule, policy: String = "DIRECT")
            -> (tasks: [NetworkConnectivityDiagnosticTask], omitted: Int) {
            let router = NativePacketRouter(profile: profile, mode: mode, globalPolicy: policy, groupSelections: [:])
            return router.networkDiagnosticTasks(snapshot: router.networkDiagnosticSnapshot(), current: { true })
        }
        var profile = Profile()
        profile.dnsServers = ["192.0.2.53"]
        profile.encryptedDNSServers = ["https://dns.selftest.invalid/private/path?querytoken=private-credential#192.0.2.54"]
        let ordinary = NetworkConnectivityDiagnosticKind.traditionalDNS
        let encrypted = NetworkConnectivityDiagnosticKind.encryptedDNS
        let initial = planned(profile)
        try require(initial.tasks.first(where: { $0.row.kind == .proxyLatency })?.row.status == .skipped,
                    "最终 DIRECT 被规划为代理测试")
        try require(initial.tasks.first(where: { $0.row.kind == encrypted })?.operation != nil,
                    "获准加密配置未规划真实查询")
        let encoded = String(decoding: try JSONEncoder().encode(initial.tasks.map(\.row)), as: UTF8.self)
        try require(!encoded.contains("querytoken") && !encoded.contains("private-credential")
                    && !encoded.contains("/private/path") && !encoded.contains("#192.0.2.54"),
                    "端点标签回显路径、query token 或 fragment")
        var ipv6Profile = Profile()
        ipv6Profile.dnsServers = ["udp://[2001:db8::53]:5353"]
        let ipv6Task = planned(ipv6Profile).tasks.first(where: { $0.row.kind == ordinary })!
        try require(ipv6Task.operation != nil && ipv6Task.timeout == 4
                    && ipv6Task.deadlineMeasurement != nil
                    && ipv6Task.row.endpoint == "[2001:db8::53]:5353"
                    && ipv6Task.row.title.contains("IPv6 传输 / A 查询")
                    && ipv6Task.row.route.contains("固定测试"),
                    "IPv6 固定检测未保留真实传输族、端口、原期限或 deadline 证据入口")
        if ProxyEngine.currentOutboundInterface == nil {
            try require(ipv6Task.row.route.contains("未绑定物理接口"),
                        "自动出口误标为已绑定物理接口")
        }
        ipv6Profile.dnsServers = ["[::1]:5353"]
        try require(planned(ipv6Profile).tasks.first(where: { $0.row.kind == ordinary })?.row.route
                    == "本机回环 · 固定测试", "IPv6 回环被误标为物理接口直连")
        for proto in ["UDP", "TCP"] {
            var denied = profile
            denied.rules = [.init(kind: .logicalAnd([.ipCIDR("192.0.2.53/32"), .protocolName(proto)]),
                                  policy: "REJECT", sourceLine: 1)]
            let result = planned(denied).tasks.first(where: { $0.row.kind == ordinary })!
            try require(result.row.status == .skipped && result.operation == nil,
                        "普通 DNS \(proto) REJECT 仍获测试操作")
        }
        var deniedName = profile
        deniedName.rules = [.init(kind: .domain("captive.apple.com"), policy: "REJECT", sourceLine: 1)]
        try require(planned(deniedName).tasks.allSatisfy { $0.operation == nil },
                    "固定测试域名 REJECT 仍规划网络操作")
        for deniedHost in ["192.0.2.54/32", "dns.selftest.invalid"] {
            var denied = profile
            denied.rules = [.init(kind: deniedHost.contains("/") ? .ipCIDR(deniedHost) : .domain(deniedHost),
                                  policy: "REJECT", sourceLine: 1)]
            let result = planned(denied).tasks.first(where: { $0.row.kind == encrypted })!
            try require(result.row.status == .skipped && result.operation == nil,
                        "加密 DNS 身份或固定拨号 IP REJECT 仍获测试操作")
        }
        let node = ProxyPolicy(name: "private-selected-node", kind: .socks5, host: "192.0.2.90", port: 1080)
        profile.proxies[node.name] = node
        let forcedDirect = planned(profile, mode: .direct, policy: node.name)
        try require(forcedDirect.tasks.first(where: { $0.row.kind == .proxyLatency })?.operation == nil,
                    "直连模式仍执行所选代理测试")
        let rejected = planned(profile, mode: .proxy, policy: "REJECT")
        try require(rejected.tasks.first(where: { $0.row.kind == .proxyLatency })?.row.status == .skipped,
                    "最终 REJECT 被规划为代理测试")
        let selected = planned(profile, policy: node.name).tasks.first(where: { $0.row.kind == .proxyLatency })!
        try require(selected.operation != nil && selected.row.route.hasPrefix("SOCKS5 代理")
                    && !selected.row.route.contains(node.name), "所选真实代理路径未区分或暴露原始节点标签")
        var invalid = profile
        invalid.encryptedDNSServers = ["https://user:private-password@dns.selftest.invalid/private?querytoken=secret#192.0.2.54"]
        let bad = planned(invalid).tasks.first(where: { $0.row.kind == encrypted })!
        try require(bad.operation == nil && bad.row.endpoint == "配置项 1", "无效 URI 泄露凭据或仍执行查询")
        var many = Profile()
        many.dnsServers = (1...9).map { "192.0.2.\($0)" }
        many.encryptedDNSServers = (1...9).map { "https://203.0.113.\($0)/dns-query" }
        let bounded = planned(many)
        try require(bounded.tasks.filter({ $0.row.kind == ordinary }).count == 8
                    && bounded.tasks.filter({ $0.row.kind == encrypted }).count == 8 && bounded.omitted == 2,
                    "单类端点未限制八项或遗漏数错误")
        try independentRouterAndListenerOwnership()
        print("Network diagnostics route planning self-test passed: DIRECT/REJECT, UDP/TCP/QNAME/TLS-identity/pin policy, approved endpoints, URI privacy and endpoint caps")
    }

    /// Production entrypoints are exercised with permission already revoked,
    /// so their session can never start a resolver or connector. Separate plan
    /// inspection verifies that an otherwise-live TUN router has real jobs.
    private static func independentRouterAndListenerOwnership() throws {
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            if !condition() { throw Failure(text: text) }
        }
        final class SnapshotBox {
            private let lock = NSLock()
            private var value: NetworkConnectivityDiagnosticsSnapshot?
            let done = DispatchSemaphore(value: 0)
            func receive(_ snapshot: NetworkConnectivityDiagnosticsSnapshot) {
                guard !snapshot.isRunning else { return }
                lock.lock(); value = snapshot; lock.unlock(); done.signal()
            }
            var final: NetworkConnectivityDiagnosticsSnapshot? {
                lock.lock(); defer { lock.unlock() }; return value
            }
        }
        final class OwnerGate {
            private let lock = NSLock()
            private var allowed = true
            func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
            func revoke() { lock.lock(); allowed = false; lock.unlock() }
        }
        var profile = Profile()
        profile.dnsServers = ["192.0.2.53"]
        profile.encryptedDNSServers = ["https://dns.router-selftest.invalid/dns-query#192.0.2.54"]
        let router = NativePacketRouter(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
        let engine = ProxyEngine()
        try require(engine.runtimeSnapshot().status == .stopped, "监听引擎夹具意外启动")
        let owner = OwnerGate()
        let live = router.networkDiagnosticRound(ownerIsCurrent: owner.permits)
        try require(live.isCurrent() && live.tasks.contains(where: { $0.row.kind == .localLatency && $0.operation != nil })
                    && live.tasks.contains(where: { $0.row.kind == .encryptedDNS && $0.operation != nil })
                    && live.tasks.contains(where: { $0.row.kind == .traditionalDNS && $0.operation != nil }),
                    "独立 TUN router 被未启动的监听引擎错误阻止")
        owner.revoke()
        try require(!live.isCurrent(), "所属增强会话撤销后仍保留诊断权限")
        let fresh = router.networkDiagnosticRound(ownerIsCurrent: { true })
        try require(fresh.isCurrent(), "有效 router 代次未获诊断权限")
        router.flushDNS(prewarm: false)
        try require(!fresh.isCurrent(), "router DNS 代次变化后旧诊断仍有效")
        let callbackQueue = DispatchQueue(label: "app.hajimi.network-diagnostics.ownership-selftest")
        let routerBox = SnapshotBox()
        let routerSession = router.startNetworkDiagnostics(callbackQueue: callbackQueue,
            ownerIsCurrent: { false }, onUpdate: routerBox.receive)
        try require(routerBox.done.wait(timeout: .now() + 2) == .success,
                    "独立 router 的公开诊断入口未交付终态")
        try require(routerBox.final?.rows.contains(where: { $0.status == .cancelled }) == true
                    && routerBox.final?.rows.allSatisfy({ !$0.detail.contains("代理核心未就绪") }) == true,
                    "router 入口仍沿用监听引擎未启动检查或忽略所属会话许可")
        let engineBox = SnapshotBox()
        let engineSession = engine.startNetworkDiagnostics(callbackQueue: callbackQueue, onUpdate: engineBox.receive)
        try require(engineBox.done.wait(timeout: .now() + 2) == .success,
                    "未启动的监听引擎未交付明确跳过结果")
        try require(engineBox.final?.rows.count == 4
                    && engineBox.final?.rows.allSatisfy({ $0.status == .skipped && $0.detail.contains("代理核心未就绪") }) == true,
                    "旧监听入口在未启动时错误规划真实网络操作")
        let unavailableBox = SnapshotBox()
        let unavailableSession = ProxyEngine.unavailableNetworkDiagnostics(detail: "增强会话已停止或正在清理，请稍后重试",
            callbackQueue: callbackQueue, onUpdate: unavailableBox.receive)
        try require(unavailableBox.done.wait(timeout: .now() + 2) == .success
                    && unavailableBox.final?.rows.count == 4
                    && unavailableBox.final?.rows.allSatisfy({ $0.status == .skipped
                        && $0.detail == "增强会话已停止或正在清理，请稍后重试" }) == true,
                    "缺失数据面的静态入口未提供明确、无网络操作的终态")
        print("Network diagnostics ownership self-test passed: TUN router independent of stopped listeners, owner revocation, DNS generation and both public entrypoints; no network operations")
        withExtendedLifetime((routerSession, engineSession, unavailableSession, router)) {}
    }
}


/// Bounded, short-TTL (2.0s) source-port-to-process cache for PROCESS-NAME rules.
/// Avoids repeated kernel proc_pidinfo/proc_pidpath syscalls on bursty traffic
/// from the same local client port.
public final class LocalProcessSocketCache {
    public static let shared = LocalProcessSocketCache()
    private struct Key: Hashable {
        let port: UInt16
        let isTCP: Bool
    }
    private struct Entry {
        let processPath: String
        let expiresAt: TimeInterval
    }
    private let lock = NSLock()
    private var entries: [Key: Entry] = [:]
    private let ttl: TimeInterval

    public init(ttl: TimeInterval = 2.0) {
        self.ttl = max(0.1, ttl)
    }

    public func lookup(port: UInt16, isTCP: Bool, now: TimeInterval? = nil) -> String? {
        guard port > 0 else { return nil }
        let currentNow = now ?? SOCKSUDPResourceLimits.now
        let key = Key(port: port, isTCP: isTCP)
        lock.lock()
        defer { lock.unlock() }
        if let existing = entries[key], existing.expiresAt > currentNow {
            return existing.processPath
        }
        entries.removeValue(forKey: key)
        return nil
    }

    public func record(processPath: String, port: UInt16, isTCP: Bool,
                       now: TimeInterval? = nil) {
        let trimmed = processPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard port > 0, !trimmed.isEmpty else { return }
        let currentNow = now ?? SOCKSUDPResourceLimits.now
        let key = Key(port: port, isTCP: isTCP)
        lock.lock()
        if entries.count >= 512 {
            entries = entries.filter { $0.value.expiresAt > currentNow }
            if entries.count >= 512 { entries.removeAll(keepingCapacity: true) }
        }
        entries[key] = Entry(processPath: trimmed, expiresAt: currentNow + ttl)
        lock.unlock()
    }

    public func flush() {
        lock.lock()
        entries.removeAll()
        lock.unlock()
    }

    public func resolveProcessPath(port: UInt16, isTCP: Bool,
                                   now: TimeInterval? = nil) -> String? {
        let currentNow = now ?? SOCKSUDPResourceLimits.now
        if let cached = lookup(port: port, isTCP: isTCP, now: currentNow) {
            return cached
        }
        #if canImport(Darwin)
        guard let resolved = Self.queryDarwinProcessPath(port: port, isTCP: isTCP) else {
            return nil
        }
        record(processPath: resolved, port: port, isTCP: isTCP, now: currentNow)
        return resolved
        #else
        return nil
        #endif
    }

    #if canImport(Darwin)
    private static func queryDarwinProcessPath(port: UInt16, isTCP: Bool) -> String? {
        guard port > 0 else { return nil }
        let maxPIDs = 1024
        var pids = [pid_t](repeating: 0, count: maxPIDs)
        let bytesReturned = proc_listallpids(&pids, Int32(maxPIDs * MemoryLayout<pid_t>.stride))
        guard bytesReturned > 0 else { return nil }
        let pidCount = min(maxPIDs, Int(bytesReturned))
        let fdStride = MemoryLayout<proc_fdinfo>.stride
        var fdBuffer = [proc_fdinfo](repeating: proc_fdinfo(), count: 256)
        for idx in 0..<pidCount {
            let pid = pids[idx]
            guard pid > 0 else { continue }
            let fdBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fdBuffer, Int32(fdBuffer.count * fdStride))
            guard fdBytes > 0 else { continue }
            let fdCount = min(fdBuffer.count, Int(fdBytes) / fdStride)
            for fIdx in 0..<fdCount {
                let fdInfo = fdBuffer[fIdx]
                guard fdInfo.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) else { continue }
                var sockInfo = socket_fdinfo()
                let sockBytes = proc_pidfdinfo(
                    pid, fdInfo.proc_fd, PROC_PIDFDSOCKETINFO,
                    &sockInfo, Int32(MemoryLayout<socket_fdinfo>.stride)
                )
                guard sockBytes == Int32(MemoryLayout<socket_fdinfo>.stride) else { continue }
                let kind = sockInfo.psi.soi_kind
                if isTCP {
                    guard kind == Int32(SOCKINFO_TCP) else { continue }
                } else {
                    guard kind == Int32(SOCKINFO_IN) else { continue }
                }
                let rawPort = UInt16(truncatingIfNeeded: sockInfo.psi.soi_proto.pri_in.insi_lport)
                let localPort = UInt16(bigEndian: rawPort)
                if localPort == port {
                    var pathBuf = [CChar](repeating: 0, count: 4096)
                    if proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count)) > 0 {
                        return String(cString: pathBuf)
                    }
                }
            }
        }
        return nil
    }
    #endif
}

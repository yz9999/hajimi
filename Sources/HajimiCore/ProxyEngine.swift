import Foundation
import HajimiDNS
import Network
import Security
import Darwin
import HajimiProxyRuntime
import HajimiCXXProtocolBridge

// Keep the virtual origin used for application-side DNS policy checks equal
// to HelperDaemon's system DNS sink, never to the legacy Lurge gateway.
let protectedSystemDNSGateway = "198.18.16.2"

enum DNSApplicationResolutionPolicy {
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

func replacingReferencedRuleSetContents(in profile: Profile,
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
func isTLSOnlyUpstream(_ route: ResolvedRoute) -> Bool {
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

func safeSOCKSUDPRoute(_ selected: ResolvedRoute,
                               destinationPort: UInt16) -> ResolvedRoute {
    guard destinationPort == 53 else { return selected }
    if case .reject = selected { return selected }
    return isTLSOnlyUpstream(selected)
        ? .reject("TLS 上游不支持 UDP DNS；已阻止明文直连") : selected
}

func safeTCPDNSRoute(_ selected: ResolvedRoute,
                             destinationPort: UInt16) -> ResolvedRoute {
    // DNS uses the same selected policy as every other TCP destination.
    // In particular, a non-TLS proxy is not permission to bypass that proxy.
    selected
}

/// Offline privacy vectors for the local SOCKS UDP DNS exception.

enum DNSConfiguredUpstream {
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
final class DNSRouteDecisionCache {
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

    let lock = NSLock()
    let maximumEntries: Int
    let maximumKeyBytes: Int
    var values: [Key: ResolvedRoute] = [:]
    var insertionOrder: [Key] = []
    var nextEviction = 0
    var hits: UInt64 = 0

    init(maximumEntries: Int = 1_024, maximumKeyBytes: Int = 1_024) {
        self.maximumEntries = min(1_024, max(0, maximumEntries))
        self.maximumKeyBytes = min(1_024, max(0, maximumKeyBytes))
    }

    func mayRetain(_ key: Key) -> Bool {
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
struct DNSRoutingSnapshot {
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

    func uncachedRoute(_ target: RequestTarget, name: String?,
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

    func matches(_ kind: RuleKind, target: RequestTarget, name: String,
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

    func encryptedUpstreams() throws -> [DNSConfiguredUpstream] {
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

enum DNSPolicyFailure: LocalizedError {
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

struct DNSQueryPlan {
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

struct DNSUpstreamCandidate {
    let upstream: DNSConfiguredUpstream
    let bootstrap: DNSBootstrapConfiguration?
    var id: String { upstream.candidateID }
}

struct DNSBootstrapConfiguration: Hashable {
    let servers: [String]
    let allowedHosts: [String]
}

struct DNSBootstrapCacheKey: Hashable {
    let generation: UInt64
    let configuration: DNSBootstrapConfiguration
    let interfaceName: String?
}

enum DNSQueryPreparation {
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
    let configurationLock = NSLock()
    var profile: Profile
    var mode: OutboundMode
    var globalPolicy: String
    var groupSelections: [String: String]
    var configurationGeneration: UInt64 = 0
    var dnsSourcePortSensitive: Bool
    var profileUsesProcessRules = false
    // Replace, never reset, at every epoch transition: an old snapshot may
    // finish computing after reload, but can populate only its old cache.
    var dnsRouteCache = DNSRouteDecisionCache()
    /// UDP/443 fallback and UDP-reject are consulted on every datagram.
    /// Caching the last few destinations avoids re-stringifying and
    /// re-walking the rule table tens of thousands of times a second.
    var udpCapabilityCache: [UDPCapabilityKey: (generation: UInt64, quicFallback: Bool, reject: Bool)] = [:]
    var flowRouteCache: [RouteCacheKey: (generation: UInt64, route: ResolvedRoute)] = [:]
    public var currentConfigurationGeneration: UInt64 {
        configurationLock.lock(); defer { configurationLock.unlock() }
        return configurationGeneration
    }
    struct UDPCapabilityKey: Hashable {
        let host: String
        let resolvedHost: String
        let alternateHost: String?
        let port: UInt16
        let sourceHost: String?
        let sourcePort: UInt16?
        let inboundPort: UInt16?
    }
    let dnsMapping = DNSMappingCache()
    let dnsQueryCoordinator = DNSQueryCoordinator()
    let dnsAdaptiveSelector = DNSAdaptiveUpstreamSelector()
    // Assigned only by the explicitly guarded CLI fixture below. Production
    // initializers never accept test anchors or a configurable TLS override.
    var loopbackFixtureDNSStreamDialer: EncryptedDNSStreamDialer?
    var loopbackFixtureDNSTLSUpgrader: DNSFixtureTLSUpgrader?
    // Assigned only by the memory-only regression entry below. This is not
    // an initializer option, a live configuration or a production TLS hook.
    var memoryFixtureDNSStreamDialer: MetadataAwareEncryptedDNSStreamDialer?
    var memoryFixtureAfterDNSFlushUnlock: (() -> Void)?
    let fakeIP: FakeIPAllocator
    let dohLock = NSLock()
    let dohResolvers = BoundedConnectionOwnerCache<String, DoHResolver>(
        maximumEntries: 64, maximumBytes: 2 * 1_024 * 1_024)
    let dotResolvers = BoundedConnectionOwnerCache<String, DoTResolver>(
        maximumEntries: 64, maximumBytes: 2 * 1_024 * 1_024)
    let proxyTCPDNSResolvers = BoundedConnectionOwnerCache<String, ProxyTCPDNSResolver>(
        maximumEntries: 64, maximumBytes: 2 * 1_024 * 1_024)
    var bootstrapResolvers: [DNSBootstrapCacheKey: TraditionalDNSBootstrapResolver] = [:]
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
        flowRouteCache.removeAll(keepingCapacity: true)
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
        flowRouteCache.removeAll(keepingCapacity: true)
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
    func updateRuleSetContents(from prepared: Profile) throws -> Bool {
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
        flowRouteCache.removeAll(keepingCapacity: true)
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

    static func containsProcessNameRules(_ profile: Profile) -> Bool {
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

    func route(for target: RequestTarget) -> ResolvedRoute {
        let alternateHost = dnsMapping.domain(for: target.host)
        while true {
            configurationLock.lock()
            let generation = configurationGeneration
            let profile = self.profile, mode = self.mode, policy = globalPolicy
            let selections = groupSelections
            let usesProcess = profileUsesProcessRules
            let usesSourcePort = dnsSourcePortSensitive
            configurationLock.unlock()

            var effectiveTarget = target
            if usesProcess, effectiveTarget.processName == nil, let port = effectiveTarget.sourcePort, port > 0 {
                let isTCP = effectiveTarget.protocolName.uppercased() != "UDP"
                effectiveTarget.processName = LocalProcessSocketCache.shared.resolveProcessPath(port: port, isTCP: isTCP)
            }
            let key = RouteCacheKey(host: effectiveTarget.host.lowercased(), port: effectiveTarget.port,
                                    protocolName: effectiveTarget.protocolName.uppercased(),
                                    alternateHost: alternateHost?.lowercased(),
                                    sourceHost: effectiveTarget.sourceHost?.lowercased(),
                                    sourcePort: usesSourcePort ? effectiveTarget.sourcePort : nil,
                                    inboundPort: effectiveTarget.inboundPort,
                                    processName: effectiveTarget.processName)
            configurationLock.lock()
            if let cached = flowRouteCache[key], cached.generation == generation {
                configurationLock.unlock()
                return cached.route
            }
            configurationLock.unlock()

            let selected = profile.route(for: effectiveTarget, mode: mode, globalPolicy: policy,
                                         groupSelections: selections,
                                         alternateHost: alternateHost)
            configurationLock.lock()
            guard configurationGeneration == generation else {
                configurationLock.unlock()
                continue
            }
            if flowRouteCache.count >= 4_096 { flowRouteCache.removeAll(keepingCapacity: true) }
            flowRouteCache[key] = (generation, selected)
            configurationLock.unlock()
            return selected
        }
    }

    /// Maps a fake-IP address back to the hostname it was minted for.
    ///
    /// TCP already did this before dialling; UDP/QUIC must use the same path so
    /// domain rules and the outbound destination see the name rather than a
    /// 198.19.0.0/16 address that no server can reach.
    public static var onTunnelFlowEvents: (([ProxyEngineEvent]) -> Void)?

    public func resolvedDestinationHost(_ host: String) -> String {
        fakeIP.domain(for: host) ?? host
    }

    public func displayDestinationHost(_ host: String) -> String {
        let resolved = resolvedDestinationHost(host)
        return dnsMapping.domain(for: resolved) ?? resolved
    }

    public func policySummary(forHost host: String, port: UInt16, isTCP: Bool,
                              sourceHost: String? = nil, sourcePort: UInt16? = nil) -> String {
        if port == 53 { return "DNS" }
        let target = RequestTarget(host: resolvedDestinationHost(host), port: port,
                                   protocolName: isTCP ? "TCP" : "UDP",
                                   sourceHost: sourceHost, sourcePort: sourcePort)
        return route(for: target).policyName
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

    func udpCapability(host: String, port: UInt16, sourceHost: String?,
                               sourcePort: UInt16?, inboundPort: UInt16?) -> (quicFallback: Bool, reject: Bool) {
        while true {
            configurationLock.lock()
            let generation = configurationGeneration
            // DNS/fake-IP aliases may change or expire without a profile reload.
            // Cache the exact identities used by this routing computation, not
            // just the literal destination that happened to represent them.
            let resolved = resolvedDestinationHost(host)
            let alternate = dnsMapping.domain(for: resolved)
            let effectiveSourcePort = (dnsSourcePortSensitive || profileUsesProcessRules) ? sourcePort : nil
            let key = UDPCapabilityKey(host: host, resolvedHost: resolved, alternateHost: alternate,
                                      port: port, sourceHost: sourceHost,
                                      sourcePort: effectiveSourcePort, inboundPort: inboundPort)
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
    func wouldProxy(_ name: String) -> Bool {
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

    func dnsSnapshot() -> DNSRoutingSnapshot {
        configurationLock.lock(); defer { configurationLock.unlock() }
        return DNSRoutingSnapshot(profile: profile, mode: mode, globalPolicy: globalPolicy,
                                  selections: groupSelections, generation: configurationGeneration,
                                  sourcePortSensitive: dnsSourcePortSensitive, routeCache: dnsRouteCache)
    }

    func dnsRoutingSnapshotForSelfTest() -> DNSRoutingSnapshot { dnsSnapshot() }

    fileprivate func isCurrentDNSGeneration(_ generation: UInt64) -> Bool {
        configurationLock.lock(); defer { configurationLock.unlock() }
        return generation == configurationGeneration
    }

    func isCurrentDNSGenerationForInternal(_ generation: UInt64) -> Bool { isCurrentDNSGeneration(generation) }
    func cancelDNSQueriesForInternal(keepFlows: Bool = false) { cancelDNSQueries(keepFlows: keepFlows) }

    func isCurrentDNSPlan(_ plan: DNSQueryPlan) -> Bool {
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

    func rescheduleDNSPrewarmIfActive() {
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

    func prepareDNSQuery(_ data: Data, original: RequestTarget,
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

    func makeDNSDatagram(original: RequestTarget, queue: DispatchQueue,
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

    func makeDNSUpstream(plan: DNSQueryPlan, queue: DispatchQueue,
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
            let poolTuning = DNSProtocolRouterAdapter.encryptedDNSPoolTuning(for: plan.route)
            let resolver = DoHResolver(endpoint: endpoint, metadataStreamDialer: dialer,
                                       idleTimeout: poolTuning.idleTimeout,
                                       idleHandoffGrace: poolTuning.idleHandoffGrace)
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
            let poolTuning = DNSProtocolRouterAdapter.encryptedDNSPoolTuning(for: plan.route)
            let resolver = DoTResolver(endpoint: endpoint, metadataStreamDialer: dialer,
                                       idleTimeout: poolTuning.idleTimeout,
                                       idleHandoffGrace: poolTuning.idleHandoffGrace)
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

    func makeOptimizedDNSUpstream(plan: DNSQueryPlan, queue: DispatchQueue,
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
    func dnsTransportAvailability(plan: DNSQueryPlan,
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

    func revalidatedCandidatePlan(_ plan: DNSQueryPlan, candidate: DNSUpstreamCandidate) throws -> DNSQueryPlan {
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

    func revalidatedProxyFallbackPlan(_ plan: DNSQueryPlan, server: DNSProxyFallbackServer) throws -> DNSQueryPlan {
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
    func makeProxyTCPFallbackUpstream(plan: DNSQueryPlan, server: DNSProxyFallbackServer,
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
            let poolTuning = DNSProtocolRouterAdapter.encryptedDNSPoolTuning(for: chosen.route)
            let resolver = ProxyTCPDNSResolver(server: server, metadataStreamDialer: dialer,
                                               idleTimeout: poolTuning.idleTimeout,
                                               idleHandoffGrace: poolTuning.idleHandoffGrace)
            let insertion = proxyTCPDNSResolvers.insert(resolver, for: key, cost: key.utf8.count + 1_024)
            dohLock.unlock(); configurationLock.unlock()
            guard let insertion else { resolver.cancel(); throw EncryptedDNSQueryFailure.capacity }
            insertion.retired.forEach { $0.cancel() }; lease = insertion.lease
        }
        return DNSResolverLeaseDatagram(transport: ProxyTCPDNSRoutedDatagram(resolver: lease.owner,
            absoluteDeadline: absoluteDeadline, permitted: permitted, receive: receive, failure: failure), owner: lease)
    }

    func bootstrapResolver(for plan: DNSQueryPlan,
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

    func resolvedBootstrapPlan(_ plan: DNSQueryPlan, address: String) throws -> DNSQueryPlan {
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

    func recordDNSResponse(_ data: Data) {
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

    func connectRoutedTCP(route selected: ResolvedRoute, target: RequestTarget,
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

    func connectDirectAddresses(_ addresses: [String], selected: ResolvedRoute,
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

/// One bounded encrypted query with at most two live approved candidates. A
/// soft budget starts a hedge but never truncates an otherwise healthy primary
/// before the overall deadline. No endpoint is added here: policy approved the
/// complete set before admission. A refusal after admission remains terminal.
final class DNSAdaptiveQueryDatagram: NativeRoutedDatagram, DNSQueryDeadlineAcknowledging, DNSQueryPhaseDeadlineAcknowledging, DNSProxyFallbackBarrierProviding, DNSQueryEncryptedPhaseScheduling, DNSQueryExecutionContextAccepting {
    typealias Factory = (DNSUpstreamCandidate, DispatchQueue, @escaping (Data) -> Void,
                         @escaping (Error) -> Void) throws -> NativeRoutedDatagram
    let candidates: [DNSUpstreamCandidate]
    let selector: DNSAdaptiveUpstreamSelector
    var scopeKey: String
    let queue: DispatchQueue
    let permitted: () -> Bool, factory: Factory
    let receive: (Data) -> Void, failure: (Error) -> Void
    let availability: ((DNSUpstreamCandidate) -> (reusable: Int, cold: Int)?)?
    let timeout: TimeInterval, absoluteDeadline: TimeInterval?, clock: () -> TimeInterval
    let protectProxyFallback: Bool
    let allowApprovedProxyPlaintext: Bool
    let cancellations = DispatchGroup()
    let admission = NSLock()
    var barrierTokens = Set<UUID>()
    var fallbackErrorBarrier: Error?
    var fallbackAnswerBarrier: Data?
    var deadlineRefusalBarrier: Data?
    var barrierQuestion: Data?
    var barrierChildren: [DNSProxyFallbackBarrierProviding] = []
    var deadlineFenceAvailable = true
    var closed = false, deadlineSignalled = false, started = false, finished = false
    var cancellationReason: DNSAttemptCancellationReason?
    var executionContext = DNSQueryExecutionContext()
    var query: Data?
    var approvedOrder: [DNSUpstreamCandidate] = []
    var ordered: [DNSUpstreamCandidate] = []
    var explorationID: String?
    var preferUntriedServices = false
    var preferAvailableUntriedServices = false
    var usedNetworkRecovery = false
    var deferredNetworkReset: DNSUpstreamCandidate?
    var next = 0, attemptCount = 0
    var primaryToken: UUID?
    struct Attempt {
        let candidate: DNSUpstreamCandidate, started: TimeInterval
        let observation: DNSAdaptiveUpstreamSelector.Observation?
        let context: DNSQueryExecutionContext
        let minimumColdObservation: TimeInterval
        let hadVerifiedSuccessAtAdmission: Bool
        var transport: NativeRoutedDatagram?
        var hedgeTimer: DispatchWorkItem?
        var rotationTimer: DispatchWorkItem?
    }
    struct RetiredObservation {
        let candidate: DNSUpstreamCandidate
        let milliseconds: Double
        let observation: DNSAdaptiveUpstreamSelector.Observation?
        let evidence: DNSQueryTransportEvidence
    }
    var active: [UUID: Attempt] = [:]
    var retired: [RetiredObservation] = []
    var lastNetworkError: Error?
    var localCapacityError: Error?
    var deadline: TimeInterval = 0, exchangeStarted: TimeInterval = 0, exchangeBudget: TimeInterval = 0
    var deadlineTimer: DispatchWorkItem?

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
    var isClosed: Bool {
        admission.lock(); defer { admission.unlock() }; return closed || deadlineSignalled
    }
    var isClientCancelled: Bool { admission.lock(); defer { admission.unlock() }; return closed }

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

    func beginAttempt(reason: String = "initial", refreshCandidates: Bool = true) {
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
        let budget = canHedge ? DNSAdaptiveHedgeBudget.delayWithJitter(remaining: remaining, attemptsLeft: attemptsLeft,
            primaryMilliseconds: planningLatencyMilliseconds(candidate),
            primaryJitterMilliseconds: selector.jitterMilliseconds(scopeKey: scopeKey, candidateID: candidate.id),
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

    func preferAvailableCandidate() {
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

    func startHedge(after token: UUID) {
        guard !finished, !isClosed, let attempt = active[token] else { return }
        active[token]?.hedgeTimer = nil
        preferAvailableUntriedServices = true
        nativeDebug("dns adaptive hedge candidate_index=\(candidateIndex(attempt.candidate)) elapsed_ms=\(elapsedMilliseconds(since: attempt.started)) active=\(active.count)")
        // This is deliberately not a failure: a valid late primary response
        // may still win, and its health history must not acquire a timeout.
        beginAttempt(reason: "soft-budget")
    }

    func hedgeRotationTime(_ attempt: Attempt) -> TimeInterval {
        let base = exchangeStarted + exchangeBudget * (2.0 / 3.0)
        let milliseconds = planningLatencyMilliseconds(attempt.candidate)
        let backupHeadroom = (milliseconds ?? 0) / 1000 * 1.5 + 0.05
        // A successful RTT may come from a reused channel while this attempt
        // still needs a new TCP/TLS connection. Keep Build9's conservative
        // boundary so warm history cannot prematurely cancel that setup.
        return max(base, attempt.started + backupHeadroom, progressDeadline(attempt))
    }

    func measuredColdCompletionWindow(_ candidate: DNSUpstreamCandidate) -> TimeInterval? {
        selector.estimatedMilliseconds(scopeKey: scopeKey, candidateID: candidate.id, phase: .cold)
            .map { $0 / 1000 * 1.25 + 0.05 }
    }

    func coldCompletionWindow(_ candidate: DNSUpstreamCandidate) -> TimeInterval {
        if let measured = measuredColdCompletionWindow(candidate) { return measured }
        // Unknown paths still get a bounded third-candidate rescue window.
        // Once cold costs are observed, a warm RTT cannot shrink this window.
        return max(0.001, min(2, exchangeBudget / 3))
    }

    func planningLatencyMilliseconds(_ candidate: DNSUpstreamCandidate) -> Double? {
        selector.planningLatencyMilliseconds(scopeKey: scopeKey, candidateID: candidate.id)
    }

    func minimumThirdWindow() -> TimeInterval {
        guard next < ordered.count else { return .infinity }
        return minimumCompletionWindow(ordered[next])
    }

    func minimumCompletionWindow(_ candidate: DNSUpstreamCandidate) -> TimeInterval {
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

    func progressDeadline(_ attempt: Attempt) -> TimeInterval {
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

    func scheduleHedgeRotation(_ token: UUID, now: TimeInterval) {
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

    func rotateHedge(_ token: UUID) {
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

    func accept(_ answer: Data, token: UUID) {
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

    func prioritizeUntriedResolverServices() {
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

    func attemptFailure(_ error: Error, token: UUID) {
        guard !finished, !isClosed, active[token] != nil else { return }
        if error is DNSPolicyFailure { finishFailure(error, reason: "policy-denial", cancellationReason: .policyChanged) }
        else { networkFailure(token: token, error: error) }
    }

    func registerFallbackError(_ error: Error, token: UUID) {
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

    func registerFallbackAnswer(_ answer: Data, query: Data, token: UUID) {
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
    func queryDeadlineBarrier() -> DNSProxyFallbackBarrier? {
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

    func hasNativeOrdinaryQueryReset(_ attempt: Attempt) -> Bool {
        guard query.flatMap({ DNSMessageInspection.singleQuestion(in: $0) }).map({
            $0.`class` == 1 && [UInt16(1), 28, 64, 65].contains($0.type)
        }) == true else { return false }
        return attempt.context.connectionResetProgress().map {
            $0.transportReadyAt != nil && $0.tlsStartedAt != nil
                && $0.responseStartedAt == nil && $0.responseCompletedAt == nil
        } == true
    }

    func availableRecoveryCandidate(for failed: DNSUpstreamCandidate) -> DNSUpstreamCandidate? {
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

    func networkRecoveryCandidate(_ attempt: Attempt, token: UUID,
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

    func networkFailure(token: UUID, error: Error, reason: String = "network-error") {
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
    func overallDeadlineReached() {
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
    func clearAttempt(_ token: UUID, reason: DNSAttemptCancellationReason = .cleanup) {
        guard let attempt = active.removeValue(forKey: token) else { return }
        admission.lock(); barrierTokens.remove(token); admission.unlock()
        attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel(); cancelTransport(attempt.transport, reason: reason)
    }
    func transportEvidence(_ transport: NativeRoutedDatagram?) -> DNSQueryTransportEvidence {
        (transport as? DNSQueryTransportEvidenceProviding)?.dnsQueryTransportEvidence() ?? .unknown
    }
    func canAttributeDeadlineFailure(_ attempt: Attempt) -> Bool {
        let evidence = transportEvidence(attempt.transport)
        // The query still times out at its original deadline. A late cold
        // replacement with less than one normal setup window is not, however,
        // a completed measurement of this provider's availability.
        guard evidence == .fresh || evidence == .reusedThenFresh else { return true }
        let progress = attempt.context.progress()
        let coldStarted = max(attempt.started, progress.transportStartedAt ?? progress.tlsStartedAt ?? attempt.started)
        return clock() - coldStarted >= attempt.minimumColdObservation
    }
    func clearAttempts(reason: DNSAttemptCancellationReason) {
        let attempts = Array(active.values); active.removeAll()
        admission.lock(); barrierTokens.removeAll(); admission.unlock()
        // Remove all tokens before cancellation, so even a synchronous late
        // callback cannot recreate a completed or policy-invalid query.
        for attempt in attempts {
            attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel(); cancelTransport(attempt.transport, reason: reason)
        }
        retired.removeAll()
    }
    func cancelUnadoptedTransport(_ transport: NativeRoutedDatagram, reason: DNSAttemptCancellationReason) {
        cancelTransport(transport, reason: reason)
    }
    func cancelTransport(_ transport: NativeRoutedDatagram?, reason: DNSAttemptCancellationReason) {
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
    func finishAnswer(_ answer: Data, completingDeadline: Bool = false,
                              cancellationReason: DNSAttemptCancellationReason = .winnerSelected) {
        guard !finished, !(completingDeadline ? isClientCancelled : isClosed) else { return }
        nativeDebug("dns adaptive finish elapsed_ms=\(elapsedMilliseconds(since: exchangeStarted)) attempts=\(attemptCount) reason=answer rcode=\(answer[answer.startIndex + 3] & 0x0f)")
        finished = true; deadlineTimer?.cancel(); deadlineTimer = nil; clearAttempts(reason: cancellationReason); query = nil
        receive(answer)
    }
    func finishFailure(_ error: Error, reason: String = "failed", completingDeadline: Bool = false,
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
    func notifyAfterLogicalFinish(_ completion: @escaping () -> Void) {
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
    func candidateIndex(_ candidate: DNSUpstreamCandidate) -> Int {
        candidates.firstIndex { $0.id == candidate.id } ?? -1
    }
    func elapsedMilliseconds(since started: TimeInterval) -> Int {
        let elapsed = clock() - started
        return elapsed.isFinite ? Int(min(60_000, max(0, elapsed * 1000))) : 0
    }
    static func debugErrorCategory(_ error: Error) -> String {
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

extension DNSAdaptiveQueryDatagram {
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

/// Only the private parent-deadline memory fixture reads these values. No
/// production path calls this accessor or receives a cancellation receipt.
struct DNSParentDeadlineMemoryState {
    let finished: Bool, closed: Bool, deadlineSignalled: Bool, permitted: Bool
    let attempts: Int
    let activeCandidates: Set<Int>, retiredCandidates: Set<Int>
}

extension DNSAdaptiveQueryDatagram {
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

enum DNSUpstream {
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
    var connection: NWConnection?
    let queue: DispatchQueue
    let permitted: () -> Bool
    let admission = NSLock()
    var closed = false, admittedPackets = 0, admittedBytes = 0
    let receiveHandler: (Data) -> Void
    let failureHandler: (Error) -> Void
    var pending: [Data] = []
    var ready = false, stopped = false
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
    func start(host: String, port: NWEndpoint.Port) {
        guard permitted() else { fail(EngineError("UDP 路由已更新，已阻止旧 DIRECT 套接字")); return }
        let parameters = NWParameters.udp
        if !isLoopbackHost(host) {
            parameters.requiredInterface = OutboundInterfaceBinding.current
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state {
                self.ready = true; let values = self.pending; self.pending.removeAll()
                values.forEach(self.write); self.read()
            }
            if case .failed(let error) = state { self.fail(error) }
            if case .cancelled = state { self.stop() }
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
    func write(_ data: Data) {
        guard !stopped, let connection else { release(data.count); return }
        guard permitted() else { release(data.count); fail(EngineError("UDP 路由已更新，已阻止旧 DIRECT 数据报")); return }
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self else { return }; self.release(data.count)
            if let error { self.fail(error) }
        })
    }
    func release(_ count: Int) { admission.lock(); admittedPackets -= 1; admittedBytes -= count; admission.unlock() }
    func stop() {
        guard !stopped else { return }; stopped = true
        admission.lock(); closed = true; admission.unlock()
        pending.forEach { release($0.count) }; pending.removeAll()
        connection?.stateUpdateHandler = nil
        connection?.cancel(); connection = nil
    }
    func cancel() { admission.lock(); closed = true; admission.unlock(); queue.async { self.stop() } }
    func read() {
        connection?.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.stopped else { return }
            if let error { self.fail(error); return }
            if let data { self.receiveHandler(data) }; self.read()
        }
    }
    func fail(_ error: Error) { guard !stopped else { return }; stop(); failureHandler(error) }
    deinit { connection?.cancel() }
}

private final class NativePolicyRoutedDatagram: NativeRoutedDatagram {
    let target: RequestTarget
    let session: NativeOutboundDatagramSession
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
    let queue = DispatchQueue(label: "app.hajimi.proxy-engine.listener", qos: .userInitiated,
                                      autoreleaseFrequency: .workItem)
    let workerQueue = DispatchQueue(label: "app.hajimi.proxy-engine.workers", qos: .userInitiated,
                                            attributes: .concurrent, autoreleaseFrequency: .workItem)
    let stateQueue = DispatchQueue(label: "app.hajimi.proxy-engine.state")
    let eventQueue = DispatchQueue(label: "app.hajimi.proxy-engine.events", qos: .utility,
                                           autoreleaseFrequency: .workItem)
    let handlersLock = NSLock()
    let lifecycleLock = NSRecursiveLock()
    var listenerGeneration = UUID()
    let maximumInboundConnections: Int
    let httpHandshakeTimeout: TimeInterval
    var httpListener: NWListener?
    var socksListener: NWListener?
    var handlers: [UUID: AnyObject] = [:]
    var profile = Profile()
    var mode: OutboundMode = .rule
    var globalPolicy = "DIRECT"
    var groupSelections: [String: String] = [:]
    let dnsMapping = DNSMappingCache()
    var dnsPacketRouter: NativePacketRouter?
    // Readers and writers share stateQueue, including listener transitions;
    // lifecycle-only locking would not synchronize Dashboard snapshots.
    var status: ProxyEngineStatus = .stopped
    var httpListenerReady = false
    var socksListenerReady = false
    var startReadyTimeout: DispatchWorkItem?
    var httpRebindAttempts = 0
    var socksRebindAttempts = 0
    var nextConnectionQueueID: UInt64 = 0
    var routingGeneration: UInt64 = 0
    var cachedRuleFlagGeneration: UInt64 = .max
    var cachedUsesSourcePort = false
    var cachedUsesProcessRules = false
    var routeCache: [RouteCacheKey: ResolvedRoute] = [:]
    var pendingTraffic: [UUID: (uploaded: Int, downloaded: Int)] = [:]
    var pendingUploadedTotal: UInt64 = 0
    var pendingDownloadedTotal: UInt64 = 0
    var trafficFlushScheduled = false
    var liveConnections: [UUID: ConnectionSnapshot] = [:]
    var recentConnections: [ConnectionSnapshot] = []
    var uploadedTotal: UInt64 = 0
    var downloadedTotal: UInt64 = 0
    var startedAt: Date?
    /// Ports actually bound after start. May differ from the profile when the
    /// preferred HTTP/SOCKS ports were already taken.
    var httpListenAddress = ListenAddress(host: "127.0.0.1", port: 7262)
    var socksListenAddress = ListenAddress(host: "127.0.0.1", port: 7263)
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

    enum ListenerRole { case http, socks }

    func makeListener(address: ListenAddress, kind: String) throws -> NWListener {
        guard let port = NWEndpoint.Port(rawValue: address.port) else {
            throw EngineError("无效的 \(kind) 端口")
        }
        let parameters = NWParameters.tcp
        if let tcp = parameters.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
            tcp.noDelay = true
            tcp.disableAckStretching = true
        }
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

    func isCurrentListener(_ listener: NWListener, role: ListenerRole,
                                   generation: UUID) -> Bool {
        guard listenerGeneration == generation else { return false }
        switch role {
        case .http: return httpListener === listener
        case .socks: return socksListener === listener
        }
    }

    func configureState(_ optionalListener: NWListener?, name: String, role: ListenerRole,
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

    func scheduleStartReadyTimeout() {
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

    func cancelStartReadyTimeout() {
        startReadyTimeout?.cancel()
        startReadyTimeout = nil
    }

    func rebindCount(for role: ListenerRole) -> Int {
        switch role {
        case .http: return httpRebindAttempts
        case .socks: return socksRebindAttempts
        }
    }

    /// Rebuilds one listener on a fresh free port after an async bind failure.
    @discardableResult
    func rebindListener(name: String, role: ListenerRole) -> Bool {
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

    static func isAddressInUse(_ error: Error) -> Bool {
        let text = error.localizedDescription.lowercased()
        if text.contains("address already in use") || text.contains("地址已经被占用")
            || text.contains("in use") || text.contains("被占用") {
            return true
        }
        let ns = error as NSError
        // POSIX EADDRINUSE = 48 on Darwin.
        return ns.domain == NSPOSIXErrorDomain && ns.code == Int(EADDRINUSE)
    }

    func acceptHTTP(_ connection: NWConnection, from listener: NWListener, generation: UUID) {
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

    func acceptSOCKS(_ connection: NWConnection, from listener: NWListener, generation: UUID) {
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

    func makeConnectionQueue() -> DispatchQueue {
        nextConnectionQueueID &+= 1
        return DispatchQueue(label: "app.hajimi.proxy-engine.connection.\(nextConnectionQueueID)",
                             qos: .userInitiated, autoreleaseFrequency: .workItem,
                             target: workerQueue)
    }

    func routingRevision() -> UInt64 {
        stateQueue.sync { routingGeneration }
    }

    var routesDirectHostnamesViaDNS: Bool {
        stateQueue.sync { DNSApplicationResolutionPolicy.usesQueryRouter(profile) }
    }

    func makeRoutedUDP(target: RequestTarget, queue: DispatchQueue,
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

    func connect(route: ResolvedRoute, target: RequestTarget, plainHTTP: Bool,
                             queue: DispatchQueue,
                             completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        guard !FakeIPAllocator.isFake(target.host) else {
            completion(.failure(EngineError("本地代理不能猜测其它数据面的 fake-IP 映射；请使用 SOCKS 域名或对应 TUN 数据面")))
            return
        }
        let httpPort = activeHTTPListen.port
        let socksPort = activeSOCKSListen.port
        let running = stateQueue.sync { status == .running }
        if running {
            if isLoopbackHost(target.host) && (target.port == httpPort || target.port == socksPort) {
                completion(.failure(EngineError("已阻止指向本机代理监听端口 (\(target.port)) 的回环连接")))
                return
            }
            switch route {
            case .http(let proxy, _), .socks5(let proxy, _), .native(let proxy, _):
                if let host = proxy.host, let port = proxy.port,
                   isLoopbackHost(host) && (port == httpPort || port == socksPort) {
                    completion(.failure(EngineError("上游代理节点 (\(proxy.name)) 指向了本机代理监听端口 (\(port))，已阻止回环连接")))
                    return
                }
            default:
                break
            }
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

    func route(for target: RequestTarget) -> ResolvedRoute {
        let alternateHost = dnsMapping.domain(for: target.host)
        let loweredHost = target.host.lowercased()
        let upperProto = target.protocolName.uppercased()
        let loweredAlt = alternateHost?.lowercased()
        let loweredSource = target.sourceHost?.lowercased()
        var resolvedProcessName: String? = target.processName
        var processResolved = (resolvedProcessName != nil)

        while true {
            let (snapshot, usesSourcePort, usesProcess): (RoutingSnapshot, Bool, Bool) = stateQueue.sync {
                if cachedRuleFlagGeneration != routingGeneration || routeCache.isEmpty {
                    cachedRuleFlagGeneration = routingGeneration
                    cachedUsesSourcePort = DNSRoutingSnapshot.usesSourcePortRules(profile)
                    cachedUsesProcessRules = NativePacketRouter.containsProcessNameRules(profile)
                }
                let key = RouteCacheKey(host: loweredHost, port: target.port,
                                        protocolName: upperProto,
                                        alternateHost: loweredAlt,
                                        sourceHost: loweredSource,
                                        sourcePort: cachedUsesSourcePort ? target.sourcePort : nil,
                                        inboundPort: target.inboundPort,
                                        processName: cachedUsesProcessRules ? resolvedProcessName : nil)
                let snap = RoutingSnapshot(profile: profile, mode: mode, globalPolicy: globalPolicy,
                                           groupSelections: groupSelections, generation: routingGeneration,
                                           cached: (cachedUsesProcessRules && !processResolved) ? nil : routeCache[key])
                return (snap, cachedUsesSourcePort, cachedUsesProcessRules)
            }
            if let cached = snapshot.cached { return cached }

            var effectiveTarget = target
            if usesProcess && !processResolved {
                processResolved = true
                if let port = target.sourcePort, port > 0 {
                    let isTCP = upperProto != "UDP"
                    resolvedProcessName = LocalProcessSocketCache.shared.resolveProcessPath(port: port, isTCP: isTCP)
                }
                effectiveTarget.processName = resolvedProcessName
                let keyAfterProcess = RouteCacheKey(host: loweredHost, port: target.port,
                                                    protocolName: upperProto,
                                                    alternateHost: loweredAlt,
                                                    sourceHost: loweredSource,
                                                    sourcePort: usesSourcePort ? target.sourcePort : nil,
                                                    inboundPort: target.inboundPort,
                                                    processName: resolvedProcessName)
                if let hit = stateQueue.sync(execute: {
                    routingGeneration == snapshot.generation ? routeCache[keyAfterProcess] : nil
                }) {
                    return hit
                }
            } else if usesProcess {
                effectiveTarget.processName = resolvedProcessName
            }

            let key = RouteCacheKey(host: loweredHost, port: target.port,
                                    protocolName: upperProto,
                                    alternateHost: loweredAlt,
                                    sourceHost: loweredSource,
                                    sourcePort: usesSourcePort ? target.sourcePort : nil,
                                    inboundPort: target.inboundPort,
                                    processName: usesProcess ? resolvedProcessName : nil)

            // Rule-set matching may scan thousands of entries. Compute it
            // outside the state queue; retry if a policy changed meanwhile,
            // rather than sending one last datagram down the stale route.
            let result = snapshot.profile.route(for: effectiveTarget, mode: snapshot.mode,
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

    func recordDNSResponse(_ data: Data) {
        for record in DNSMessageInspection.addressAnswers(in: data) {
            dnsMapping.set(domain: record.domain, for: record.address, ttl: record.ttl)
        }
    }

    func displayHost(for host: String) -> String {
        dnsMapping.domain(for: host) ?? host
    }

    /// Traffic callbacks can occur once per packet/read. Coalescing them to a
    /// 250 ms cadence prevents the UI and Dispatch main queue from becoming
    /// the dominant CPU consumer without affecting forwarding throughput.
    func emit(_ event: ProxyEngineEvent) {
        eventQueue.async { [weak self] in self?.processEvent(event) }
    }

    func handlerFinished(id: UUID) {
        handlersLock.lock()
        handlers.removeValue(forKey: id)
        handlersLock.unlock()
    }

    func flushPendingTrafficTotals() {
        guard pendingUploadedTotal != 0 || pendingDownloadedTotal != 0 else { return }
        let up = pendingUploadedTotal
        let down = pendingDownloadedTotal
        pendingUploadedTotal = 0
        pendingDownloadedTotal = 0
        stateQueue.sync {
            uploadedTotal &+= up
            downloadedTotal &+= down
        }
    }

    func processEvent(_ event: ProxyEngineEvent) {
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
            pendingUploadedTotal &+= UInt64(max(0, uploaded))
            pendingDownloadedTotal &+= UInt64(max(0, downloaded))
            scheduleTrafficFlush()
        case .closed(let id, _):
            flushPendingTrafficTotals()
            var finalEvents: [ProxyEngineEvent] = []
            if let traffic = takeTraffic(for: id) { finalEvents.append(traffic) }
            _ = stateQueue.sync { liveConnections.removeValue(forKey: id) }
            finalEvents.append(event)
            publishEvents(finalEvents)
        case .message:
            publishEvents([event])
        }
    }

    func scheduleTrafficFlush() {
        guard !trafficFlushScheduled else { return }
        trafficFlushScheduled = true
        eventQueue.asyncAfter(deadline: .now() + .milliseconds(250)) { [weak self] in
            guard let self else { return }
            self.trafficFlushScheduled = false
            self.flushPendingTrafficTotals()
            let values = self.pendingTraffic
            self.pendingTraffic.removeAll(keepingCapacity: true)
            let events: [ProxyEngineEvent] = values.compactMap { id, traffic in
                guard traffic.uploaded != 0 || traffic.downloaded != 0 else { return nil }
                return .traffic(id: id, uploaded: traffic.uploaded, downloaded: traffic.downloaded)
            }
            self.publishEvents(events)
        }
    }

    func takeTraffic(for id: UUID) -> ProxyEngineEvent? {
        guard let traffic = pendingTraffic.removeValue(forKey: id),
              traffic.uploaded != 0 || traffic.downloaded != 0 else { return nil }
        return .traffic(id: id, uploaded: traffic.uploaded, downloaded: traffic.downloaded)
    }

    func publishEvents(_ events: [ProxyEngineEvent]) {
        guard !events.isEmpty else { return }
        onEventBatch?(events)
        if let onEvent { events.forEach(onEvent) }
    }

    func setStatus(_ newValue: ProxyEngineStatus) {
        stateQueue.sync { status = newValue }
        // Never call client/UI code while executing on the state queue.
        onStatus?(newValue)
    }
}

struct RouteCacheKey: Hashable {
    let host: String
    let port: UInt16
    let protocolName: String
    let alternateHost: String?
    let sourceHost: String?
    let sourcePort: UInt16?
    let inboundPort: UInt16?
    var processName: String? = nil
}

struct RoutingSnapshot {
    let profile: Profile
    let mode: OutboundMode
    let globalPolicy: String
    let groupSelections: [String: String]
    let generation: UInt64
    let cached: ResolvedRoute?
}

struct EngineError: LocalizedError {
    let text: String
    init(_ text: String) { self.text = text }
    var errorDescription: String? { text }
}

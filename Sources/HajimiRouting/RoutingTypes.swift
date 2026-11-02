import Foundation

// Value-only routing inputs and results. Configuration parsing, native
// adapter promotion and all transport/resource ownership remain in Core.
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

    /// True when this policy group is enabled for display and quick switching in the macOS status bar menu.
    public var showsInStatusBar: Bool {
        if let raw = parameters["show-in-status-bar"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            if ["false", "no", "off", "0"].contains(raw) { return false }
            if ["true", "yes", "on", "1"].contains(raw) { return true }
        }
        if let hidden = parameters["hidden"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
           ["true", "yes", "on", "1"].contains(hidden) {
            return false
        }
        return true
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
    /// Optional local client process executable name or path when resolved.
    public var processName: String?

    public init(host: String, port: UInt16, protocolName: String,
                sourceHost: String? = nil, sourcePort: UInt16? = nil,
                inboundPort: UInt16? = nil, processName: String? = nil) {
        self.host = host
        self.port = port
        self.protocolName = protocolName.uppercased()
        self.sourceHost = sourceHost
        self.sourcePort = sourcePort
        self.inboundPort = inboundPort
        self.processName = processName
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

/// A synchronous result supplied by Core's existing immutable C++ program.
/// The routing module never owns, compiles or retains that program.
package enum RoutingRuleSelection: Equatable {
    case matched(Int)
    case noMatch
    case fallback
    case invalid
}

/// Optional ASCII acceleration supplied by Core for one synchronous match.
/// A nil result retains the original Unicode/string implementation.
package enum RoutingDomainMatchKind: Int32 {
    case exact = 0
    case suffix = 1
    case keyword = 2
}

package typealias RoutingDomainMatcher = (String, String, RoutingDomainMatchKind) -> Bool?

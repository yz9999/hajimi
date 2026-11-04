import Foundation
import HajimiDNS
import HajimiRouting

// MARK: - Protocol-Aware DNS & Encrypted DNS Router Adapter

/// Bridges `HajimiRouting.ProxyPolicy` and `ResolvedRoute` with `HajimiDNS.DNSProtocolRulePolicy`
/// so that DNS query preparation, EDNS(0) framing, QUIC/HTTPS fallback, and Encrypted DNS
/// connection pool lifetimes automatically adapt to the active outbound protocol's rules.
public enum DNSProtocolRouterAdapter {
    public static func requirements(for policy: ProxyPolicy) -> DNSProtocolRuleRequirements {
        let rawType: String
        switch policy.kind {
        case .direct:
            rawType = "direct"
        case .reject:
            rawType = "reject"
        case .http:
            let tlsFlag = policy.parameters["tls"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            rawType = (tlsFlag == "true" || tlsFlag == "1") ? "https" : "http"
        case .socks5:
            let tlsFlag = policy.parameters["tls"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            rawType = (tlsFlag == "true" || tlsFlag == "1") ? "socks5-tls" : "socks5"
        case .native, .external:
            rawType = policy.adapterType ?? "direct"
        }
        let transport = policy.parameters["transport"] ?? policy.parameters["network"]
        let udpSupported: Bool
        let carriesOverStream: Bool
        switch policy.kind {
        case .direct:
            udpSupported = true
            carriesOverStream = false
        case .reject:
            udpSupported = false
            carriesOverStream = false
        case .http, .socks5:
            udpSupported = false
            carriesOverStream = true
        case .native, .external:
            udpSupported = NativeOutboundFactory.supportsUDP(policy)
            carriesOverStream = NativeOutboundFactory.carriesUDPOverReliableStream(policy)
        }
        let muxEnabled = MuxApplicability.isEnabled(for: policy)
        let ipv6Disabled = NativePacketRouter.policyDisablesIPv6(policy)
        let suppressHTTPSFlag = policy.parameters["suppress-quic-https"]?
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let suppressHTTPS = suppressHTTPSFlag == "true" || suppressHTTPSFlag == "1"
        return DNSProtocolRulePolicy.requirements(
            protocolType: rawType,
            transport: transport,
            udpSupported: udpSupported,
            carriesUDPOverStream: carriesOverStream,
            muxEnabled: muxEnabled,
            ipv6Disabled: ipv6Disabled,
            suppressQUICHTTPSRecords: suppressHTTPS
        )
    }

    public static func requirements(for route: ResolvedRoute) -> DNSProtocolRuleRequirements {
        switch route {
        case .direct:
            return DNSProtocolRulePolicy.requirements(protocolType: "direct")
        case .reject:
            return DNSProtocolRulePolicy.requirements(protocolType: "reject", udpSupported: false)
        case .http(let policy, _), .socks5(let policy, _), .native(let policy, _):
            return requirements(for: policy)
        }
    }

    /// Returns protocol-tuned idle connection retention parameters for `DoHResolver`, `DoTResolver`, and `ProxyTCPDNSResolver`.
    public static func encryptedDNSPoolTuning(for route: ResolvedRoute) -> (idleTimeout: TimeInterval, idleHandoffGrace: TimeInterval) {
        let req = requirements(for: route)
        return (req.recommendedEncryptedDNSIdleTimeout, req.recommendedEncryptedDNSHandoffGrace)
    }

    /// Adapts an outbound DNS wire query for the target route (e.g., clamping EDNS0 payload size to 1232B on `mieru-udp`).
    public static func adaptOutboundDNSQuery(_ query: Data, for route: ResolvedRoute) -> Data {
        let req = requirements(for: route)
        guard req.underlay == .mieruUDPSession else { return query }
        return DNSProtocolRulePolicy.clampEDNSPayloadSize(
            in: query, maxPayloadSize: req.recommendedEDNSPayloadSize)
    }
}

public enum DNSProtocolRouterAdapterSelfTest {
    public static func run() throws {
        try DNSProtocolRulePolicySelfTest.run()

        let mieruUDPPolicy = ProxyPolicy(
            name: "MieruUDPNode", kind: .native, host: "203.0.113.10", port: 2012,
            adapterType: "mieru",
            parameters: ["username": "alice", "password": "secret", "transport": "UDP", "ipv6": "false"]
        )
        let req = DNSProtocolRouterAdapter.requirements(for: .native(mieruUDPPolicy, "MieruUDPNode"))
        guard req.family == .mieru,
              req.underlay == .mieruUDPSession,
              req.prefersTCPFallbackForQUIC,
              req.suppressesAAAARecords,
              req.recommendedEDNSPayloadSize == 1232,
              req.recommendedEncryptedDNSIdleTimeout == 10.0,
              req.recommendedEncryptedDNSHandoffGrace == 5.0 else {
            throw DNSProtocolRulePolicySelfTest.Failure(text: "MieruUDP ProxyPolicy 路由规则映射不一致")
        }
    }
}

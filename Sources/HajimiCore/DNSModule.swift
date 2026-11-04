// Preserve the existing public wire/cache/health API for Core's clients while
// the DNS implementation and package-only integration contracts live separately.
@_exported import HajimiDNS

/// Unified index of Hajimi's modular DNS & Encrypted DNS subsystem:
/// - `HajimiDNS/DNSMessageInspection.swift`: Wire parsing, EDNS(0) RFC 8467 padding, RFC 7871 ECS privacy, RFC 8914 EDE, RFC 9462 DDR, RFC 9250 DoQ framing.
/// - `HajimiDNS/DNSProtocolRulePolicy.swift`: Per-protocol DNS/UDP/QUIC/EDNS0/pool-lifetime rule engine across all 14 outbound protocol families.
/// - `HajimiDNS/DNSQueryCoordinator.swift`: In-flight query coalescing, follower deadline handoff, and retirement barriers.
/// - `HajimiDNS/DNSAdaptiveUpstreamSelector.swift`: RTT/failure-aware upstream ranking and health scoping.
/// - `HajimiCore/DNSProtocolRouterAdapter.swift`: Route-to-protocol DNS policy adapter (including Mieru-UDP 1232B EDNS clamping & 10s pool keepalive alignment).
/// - `HajimiCore/EncryptedDNS.swift`: Bounded DoH/DoT/ProxyTCP connection store, request pool, and HTTP/1.1 & TCP wire engines.
/// - `HajimiCore/EncryptedDNSRoutedTLSAttempt.swift`: Proxy-to-inner-TLS two-stage handshake state machine & terminal receipt tracking.
/// - `HajimiCore/EncryptedDNSFrontierEndpoints.swift`: RFC 9250 DoQ & RFC 9230 ODoH endpoint and wire primitives.
/// - `HajimiCore/EncryptedDNSSelfTest.swift`: Extracted offline/loopback Encrypted DNS & protocol-rule regression suites.
public enum DNSModuleArchitecture {
    public static func runAllSelfTests() throws {
        try DNSProtocolRulePolicySelfTest.run()
        try DNSProtocolRouterAdapterSelfTest.run()
        try EncryptedDNSSelfTest.runOffline()
    }
}

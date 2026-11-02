import Foundation
import Darwin
import HajimiCore

/// Standalone memory-only regression. Link the already-built Core/native
/// objects; no SwiftPM, listeners, sends, DNS, profiles or browser state.
/// Before the fix, compile without HAJIMI_SOURCE_AWARE_UDP_GATE: the default
/// run must fail, and --expect-current-gap documents the exact mismatches.
/// After the fix, compile with -D HAJIMI_SOURCE_AWARE_UDP_GATE and run normally.
/// Repeatable runner (after an external build, never starts SwiftPM):
/// scripts/test_udp_fallback_policy.sh --configuration debug --work-dir /tmp/quic-policy
/// Manual zsh link recipe after the root's unified Debug build:
///
/// b=.build/x86_64-apple-macosx/debug
/// targets=(HajimiCore HajimiCXXProtocolBridge HajimiProtocolsCXX HajimiProtocolCXX HajimiProxyRuntime HajimiRoutingCXX)
/// flags=()
/// objects=()
/// for t in "${targets[@]}"; do
///   objects+=("$b/$t.build/"*.o)
///   if [[ "$t" != HajimiCore ]]; then
///     flags+=(-I "Sources/$t/include" -Xcc "-fmodule-map-file=$b/$t.build/module.modulemap")
///   fi
/// done
/// xcrun swiftc -O -parse-as-library -D HAJIMI_SOURCE_AWARE_UDP_GATE -I "$b" "${flags[@]}" \
///   SmokeTests/QUICFallbackPolicyMain.swift "${objects[@]}" \
///   .build/Vendor/HajimiQUIC/lib/libngtcp2_crypto_ossl.a .build/Vendor/HajimiQUIC/lib/libngtcp2.a \
///   .build/Vendor/HajimiQUIC/lib/libnghttp3.a .build/Vendor/HajimiSSH/lib/libssh2.a \
///   /usr/local/opt/openssl@3/lib/libssl.a /usr/local/opt/openssl@3/lib/libcrypto.a \
///   -lc++ -framework Foundation -framework Network -framework Security -framework CoreFoundation \
///   -o /tmp/quic-fallback-after
@main
enum QUICFallbackPolicyMain {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private struct Source {
        let host: String
        let port: UInt16
        let inbound: UInt16
    }

    private static func require(_ value: Bool, _ message: String) throws {
        if !value { throw Failure(message: message) }
    }

    private static func policy(_ type: String) -> ProxyPolicy {
        var parameters: [String: String] = [:]
        switch type {
        case "vmess":
            parameters = ["uuid": "00000000-0000-0000-0000-000000000001", "udp": "true"]
        case "hysteria2": parameters = ["auth-str": "memory-fixture"]
        case "tuic":
            parameters = ["uuid": "00000000-0000-0000-0000-000000000001", "password": "memory-fixture"]
        default: break
        }
        return ProxyPolicy(name: type, kind: .native, host: "203.0.113.11", port: 443,
                           adapterType: type, parameters: parameters)
    }

    private static func profile(protection: Bool) -> Profile {
        var value = Profile()
        value.fakeIPEnabled = false
        value.dnsLeakProtectionEnabled = protection
        for type in ["vmess", "hysteria2", "tuic"] { value.proxies[type] = policy(type) }
        return value
    }

    private static func router(_ profile: Profile) -> NativePacketRouter {
        // nil uses FakeIPAllocator(), whose initializer is non-persisting.
        NativePacketRouter(profile: profile, mode: .rule, globalPolicy: "DIRECT",
                           groupSelections: [:], fakeIPStoreURL: nil)
    }

    private static func fallback(_ router: NativePacketRouter, host: String, source: Source) -> Bool {
        #if HAJIMI_SOURCE_AWARE_UDP_GATE
        return router.prefersTCPFallbackForQUIC(host: host, sourceHost: source.host,
                                               sourcePort: source.port, inboundPort: source.inbound)
        #else
        return router.prefersTCPFallbackForQUIC(host: host)
        #endif
    }

    private static func rejected(_ router: NativePacketRouter, host: String, port: UInt16,
                                 source: Source) -> Bool {
        #if HAJIMI_SOURCE_AWARE_UDP_GATE
        return router.rejectsUDP(host: host, port: port, sourceHost: source.host,
                                 sourcePort: source.port, inboundPort: source.inbound)
        #else
        return router.rejectsUDP(host: host, port: port)
        #endif
    }

    private static func expected(_ route: ResolvedRoute) -> (fallback: Bool, rejected: Bool) {
        switch route {
        case .direct: return (false, false)
        case .reject, .http, .socks5: return (false, true)
        case .native(let policy, _):
            return (NativeOutboundFactory.carriesUDPOverReliableStream(policy),
                    !NativeOutboundFactory.supportsUDP(policy))
        }
    }

    private static func run(expectGap: Bool) throws {
        var gateChecks = 0, quicMismatches = 0, dnsMismatches = 0, factoryChecks = 0
        try require(NativeOutboundFactory.supportsUDP(policy("vmess")), "VMess fixture is not valid")
        for type in ["hysteria2", "tuic"] {
            let node = policy(type)
            try require(NativeOutboundFactory.supportsUDP(node)
                        && !NativeOutboundFactory.carriesUDPOverReliableStream(node),
                        "Native UDP/QUIC must remain enabled for the memory fixture")
        }

        for protection in [true, false] {
            for ipv6 in [false, true] {
                let host = ipv6 ? "2001:db8::88" : "203.0.113.88"
                let source = Source(host: ipv6 ? "2001:db8::44" : "192.0.2.44", port: 49000, inbound: 49000)
                let other = Source(host: ipv6 ? "2001:db8::45" : "192.0.2.45", port: 49001, inbound: 49001)
                let kinds: [(String, RuleKind)] = [
                    ("source-port", .sourcePort(49000...49000)),
                    ("source-IP", .sourceIPCIDR(ipv6 ? "2001:db8::44/128" : "192.0.2.44/32")),
                    ("inbound-port", .inboundPort(49000...49000))
                ]
                for (label, kind) in kinds {
                    // Populate the same host/port cache with an unrelated source
                    // first, then alternate sources. Reverse cases also prove
                    // DIRECT/native UDP are not accidentally QUIC-blocked.
                    for (selected, final) in [("vmess", "DIRECT"), ("DIRECT", "vmess"),
                                              ("REJECT", "DIRECT"), ("hysteria2", "vmess"), ("tuic", "vmess")] {
                        var value = profile(protection: protection)
                        value.rules = [RoutingRule(kind: kind, policy: selected, sourceLine: 1),
                                       RoutingRule(kind: .final, policy: final, sourceLine: 2)]
                        let routed = router(value)
                        for context in [other, source, other, source] {
                            let target = RequestTarget(host: host, port: 443, protocolName: "UDP",
                                                       sourceHost: context.host, sourcePort: context.port,
                                                       inboundPort: context.inbound)
                            let route = value.route(for: target, mode: .rule, globalPolicy: "DIRECT")
                            let want = expected(route)
                            let got = (fallback(routed, host: host, source: context),
                                       rejected(routed, host: host, port: 443, source: context))
                            gateChecks += 1
                            if got.0 != want.fallback || got.1 != want.rejected {
                                quicMismatches += 1
                                try require(expectGap, "QUIC gate disagrees with full-source UDP route (\(label)/\(selected))")
                            }
                            if selected == "REJECT" {
                                var dns = target; dns.port = 53
                                let denied: Bool
                                if case .reject = value.route(for: dns, mode: .rule, globalPolicy: "DIRECT") { denied = true }
                                else { denied = false }
                                if rejected(routed, host: host, port: 53, source: context) != denied {
                                    dnsMismatches += 1
                                    try require(expectGap, "DNS53 original-source REJECT was lost (\(label))")
                                }
                            }
                        }
                    }

                    // Real makeUDPFlow proof with NO transport-capable alternate:
                    // matching source throws REJECT before any DNS/proxy factory;
                    // an omitted source can only hit an invalid node. No sends.
                    var value = profile(protection: protection)
                    value.proxies["invalid"] = ProxyPolicy(name: "invalid", kind: .native,
                        host: "203.0.113.11", port: 443, adapterType: "vmess", parameters: [:])
                    try require(!NativeOutboundFactory.supportsUDP(value.proxies["invalid"]!),
                                "Invalid fallback must not be transport-capable")
                    value.rules = [RoutingRule(kind: kind, policy: "REJECT", sourceLine: 1),
                                   RoutingRule(kind: .final, policy: "invalid", sourceLine: 2)]
                    let routed = router(value)
                    for port: UInt16 in [53, 443] {
                        var denied = false
                        do {
                            let flow = try routed.makeUDPFlow(host: host, port: port, queue: .global(),
                                sourceHost: source.host, sourcePort: source.port, inboundPort: source.inbound,
                                receive: { _ in }, failure: { _ in })
                            flow.cancel()
                        } catch { denied = error.localizedDescription == "策略拒绝：REJECT" }
                        try require(denied, "makeUDPFlow did not use its original source (\(label))")
                        factoryChecks += 1
                    }
                }
            }
        }
        if expectGap {
            try require(quicMismatches == 120 && dnsMismatches == 24,
                        "The expected pre-fix source-routing gaps were not reproduced")
            print("QUIC source-routing gap reproduced: \(quicMismatches)/\(gateChecks) gate mismatches, \(dnsMismatches) DNS53 source-REJECT mismatches; \(factoryChecks) real no-dial factory REJECT checks passed")
        } else {
            try require(quicMismatches == 0 && dnsMismatches == 0, "A source-routing gate mismatch remains")
            print("QUIC source-routing checks passed: \(gateChecks) gate checks, \(factoryChecks) real no-dial factory REJECT checks; IPv4/IPv6, source IP/port/inbound, DIRECT/Hysteria2/TUIC, DNS53 REJECT, protection on/off (memory only)")
        }
    }

    static func main() {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            try require(arguments.isEmpty || arguments == ["--expect-current-gap"], "Unexpected memory-fixture arguments")
            try run(expectGap: !arguments.isEmpty)
        } catch {
            FileHandle.standardError.write(Data("QUIC fallback policy fixture failed: \(error.localizedDescription)\n".utf8))
            Darwin.exit(1)
        }
    }
}

import Foundation
import HajimiDiagnosticsUI
import Darwin

/// Injected local snapshots only: never opens an App, a monitor, or a socket.
@main
enum LocalNetworkDiagnosticsCheck {
    static func main() throws {
        typealias Snapshot = LocalNetworkDiagnosticsSnapshot
        var assertions = 0
        func expect(_ value: Bool, _ message: String) throws {
            assertions += 1
            if !value { throw NSError(domain: "LocalNetworkDiagnosticsFixture", code: assertions,
                                      userInfo: [NSLocalizedDescriptionKey: message]) }
        }
        func interface(_ name: String, kind: Snapshot.InterfaceKind = .physical, up: Bool = true,
                       ipv4: [String] = ["192.168.1.20"], ipv6: [String] = []) -> Snapshot.Interface {
            Snapshot.Interface(name: name, index: name == "en0" ? 4 : 9, kind: kind, isUp: up,
                               isRunning: up, ipv4Addresses: ipv4, ipv6Addresses: ipv6)
        }
        let timestamp = Date(timeIntervalSince1970: 123_456)
        let en0 = interface("en0", ipv6: ["fe80::1%en0", "2001:db8::20"])
        let tunnel = interface("utun4", kind: .tunnel, ipv4: ["198.18.0.1"], ipv6: [])
        let loopback = interface("lo0", kind: .loopback, ipv4: ["127.0.0.1"], ipv6: ["::1"])
        let configuration: [String: Any] = [
            "State:/Network/Global/IPv4": ["PrimaryInterface": "utun4", "Router": "198.18.0.2", "PrimaryService": "tunnel"],
            "State:/Network/Global/IPv6": ["PrimaryInterface": "utun4", "Router": "fd00::2"],
            "State:/Network/Global/DNS": ["ServerAddresses": ["127.0.0.1", "::1", "127.0.0.1"]],
            "State:/Network/Interface/en0/IPv4": ["Router": "192.168.1.1"],
            "State:/Network/Interface/en0/IPv6": ["Router": "fe80::2%en0"],
            "State:/Network/Interface/en0/Link": ["Active": true],
            "State:/Network/Service/wifi/IPv4": ["InterfaceName": "en0", "Router": "192.168.1.1"],
            "State:/Network/Service/wifi/DNS": ["ServerAddresses": ["192.168.1.1", "fe80::3%en0"]],
            "State:/Network/Service/tunnel/IPv4": ["InterfaceName": "utun4"],
            "State:/Network/Service/tunnel/DNS": ["ServerAddresses": ["198.18.0.2"]]
        ]
        let enhanced = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [tunnel, loopback, en0],
            configuration: configuration, boundPhysicalInterfaceName: "en0")
        try expect(enhanced.capturedAt == timestamp, "capture timestamp changed")
        try expect(enhanced.localLinkStatus == .available, "physical local link not available")
        try expect(enhanced.physicalInterfaceName == "en0" && enhanced.physicalInterfaceSelection == .boundInterface,
                   "bound physical interface not retained")
        try expect(enhanced.systemPrimaryIPv4Interface == "utun4" && enhanced.systemPrimaryIPv6Interface == "utun4",
                   "system primary mislabeled as physical")
        try expect(enhanced.gateways == ["192.168.1.1", "fe80::2%en0"], "tunnel router entered physical gateway list")
        try expect(enhanced.systemDNSServers == ["127.0.0.1", "::1"], "effective DNS configuration changed")
        try expect(enhanced.physicalDNSServers == ["192.168.1.1", "fe80::3%en0"], "DNS service interface association failed")
        try expect(enhanced.interfaces.first(where: { $0.name == "utun4" })?.kind == .tunnel,
                   "tunnel missing its kind")
        try expect(enhanced.interfaces.first(where: { $0.name == "en0" })?.ipv6Addresses == ["fe80::1%en0", "2001:db8::20"],
                   "numeric scoped IPv6 address changed")

        var splitDefault = configuration
        splitDefault["State:/Network/Global/IPv4"] = ["PrimaryInterface": "en0", "Router": "192.168.1.1", "PrimaryService": "wifi"]
        let split = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [en0, tunnel], configuration: splitDefault)
        try expect(split.physicalInterfaceName == "en0" && split.physicalInterfaceSelection == .systemPrimary,
                   "system primary physical selection failed")
        try expect(split.systemPrimaryIPv4Interface == "en0", "split-default metadata fabricated a TUN default")
        let single = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [en0, tunnel], configuration: configuration)
        try expect(single.physicalInterfaceName == "en0" && single.physicalInterfaceSelection == .singleActiveInterface,
                   "single active physical candidate not labeled as heuristic")
        let ambiguous = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp,
            interfaces: [en0, interface("en1"), tunnel], configuration: configuration)
        try expect(ambiguous.physicalInterfaceName == nil && ambiguous.localLinkStatus == .unknown,
                   "ambiguous active physical interfaces silently selected")
        let stale = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [en0, tunnel],
            configuration: splitDefault, boundPhysicalInterfaceName: "en9")
        try expect(stale.physicalInterfaceName == nil && stale.physicalInterfaceSelection == .undetermined,
                   "stale binding substituted a different interface")
        try expect(stale.collectionIssues.contains(.boundInterfaceUnavailable) && stale.gateways.isEmpty && stale.physicalDNSServers.isEmpty,
                   "stale binding exported another service's addresses")
        let tunnelBound = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [en0, tunnel],
            configuration: configuration, boundPhysicalInterfaceName: "utun4")
        try expect(tunnelBound.physicalInterfaceName == nil && tunnelBound.collectionIssues.contains(.boundInterfaceUnavailable),
                   "tunnel accepted as bound physical interface")
        var inactiveLink = splitDefault
        inactiveLink["State:/Network/Interface/en0/Link"] = ["Active": false]
        let inactive = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [en0], configuration: inactiveLink)
        try expect(inactive.localLinkStatus == .unavailable, "explicit inactive link reported available")
        let stopped = Snapshot.Interface(name: "en0", index: 4, kind: .physical, isUp: true, isRunning: false,
                                         ipv4Addresses: ["192.168.1.20"], ipv6Addresses: [])
        let stoppedSnapshot = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [stopped],
            configuration: ["State:/Network/Global/IPv4": ["PrimaryInterface": "en0"]])
        try expect(stoppedSnapshot.localLinkStatus == .unavailable, "non-running link with retained IP reported available")
        let offline = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [loopback], configuration: configuration)
        try expect(offline.localLinkStatus == .unavailable && offline.physicalInterfaceName == nil,
                   "loopback DNS or TUN primary implied a working physical link")
        let failed = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [], configuration: [:],
            issues: [.interfaceEnumerationFailed, .configurationUnavailable])
        try expect(failed.localLinkStatus == .unknown && failed.collectionIssues.count == 2,
                   "collection failure reported a known disconnected state")

        let serviceWithoutInterface = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [en0], configuration: [
            "State:/Network/Global/IPv4": ["PrimaryInterface": "en0", "PrimaryService": "wifi"],
            "State:/Network/Service/wifi/DNS": ["ServerAddresses": ["192.168.1.1"]]
        ])
        try expect(serviceWithoutInterface.physicalDNSServers == ["192.168.1.1"], "explicit primary service DNS match failed")
        let privacy = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [
            interface("en0", ipv4: ["192.168.1.20", "example.invalid", "192.168.1.20", "::1"],
                      ipv6: ["fe80::1%en0", "fe80::2%bad/name", "1.2.3.4", "\nsecret"]),
            interface("en0"), interface("bad/name"), interface(String(repeating: "x", count: 99))
        ], configuration: [
            "State:/Network/Global/IPv4": ["PrimaryInterface": "en0"],
            "State:/Network/Global/DNS": ["ServerAddresses": ["resolver.example.invalid", "192.168.1.1", "fe80::1%en0", "10.0.0.1%en0", "\nsecret"]],
            "State:/Network/Interface/en0/AirPort": ["SSID_STR": "private-ssid", "BSSID": "00:11:22:33:44:55"],
            "State:/Network/Service/wifi/DNS": ["SearchDomains": ["private.example"]]
        ])
        try expect(privacy.interfaces.count == 1 && privacy.interfaces[0].ipv4Addresses == ["192.168.1.20"],
                   "invalid or duplicate interface/address survived")
        try expect(privacy.interfaces[0].ipv6Addresses == ["fe80::1%en0"] && privacy.systemDNSServers == ["192.168.1.1", "fe80::1%en0"],
                   "non-numeric or malformed scoped address survived")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(privacy)
        let json = String(decoding: data, as: UTF8.self)
        try expect(!json.contains("private-ssid") && !json.contains("00:11:22:33:44:55") &&
                   !json.contains("private.example") && !json.contains("resolver.example.invalid"),
                   "non-IP local identifiers reached export")
        try expect(try JSONDecoder().decode(Snapshot.self, from: encoder.encode(enhanced)) == enhanced,
                   "snapshot JSON roundtrip failed")
        let many = (1...100).map { interface("en\($0)", ipv4: (1...100).map { "10.0.0.\($0)" }) }
        let bounded = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: many, configuration: [
            "State:/Network/Global/DNS": ["ServerAddresses": (1...100).map { "10.1.0.\($0)" }]
        ])
        try expect(bounded.interfaces.count == 64 && bounded.interfaces.allSatisfy { $0.ipv4Addresses.count == 32 },
                   "interface/address cardinality exceeded bounds")
        try expect(bounded.systemDNSServers.count == 32 && bounded.collectionIssues.contains(.resultsTruncated),
                   "server cardinality or truncation metadata failed")
        var noisy: [String: Any] = [:]
        for index in 0..<1_100 { noisy["State:/Network/Service/id-\(index)/IPv4"] = ["InterfaceName": "en0"] }
        let noisySnapshot = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [en0], configuration: noisy)
        try expect(noisySnapshot.collectionIssues.contains(.resultsTruncated), "configuration cardinality not bounded")
        let lock = NSLock()
        var concurrentFailure = false
        DispatchQueue.concurrentPerform(iterations: 32) { _ in
            let value = LocalNetworkDiagnostics.makeSnapshot(capturedAt: timestamp, interfaces: [tunnel, loopback, en0],
                configuration: configuration, boundPhysicalInterfaceName: "en0")
            if value != enhanced { lock.lock(); concurrentFailure = true; lock.unlock() }
        }
        try expect(!concurrentFailure, "concurrent stateless assembly changed results")
        print("Local network diagnostics: \(assertions) assertions passed (injected snapshots only)")
    }
}

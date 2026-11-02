import Foundation
import Darwin
import SystemConfiguration
import HajimiDiagnosticsUI

/// Stateless, read-only adapter. Call on a background queue: getifaddrs and the
/// dynamic-store snapshot are short local reads, without child processes,
/// reachability probes, hostname resolution, monitors, or shared mutable state.
enum LocalNetworkDiagnostics {
    private static let maximumInterfaces = 64
    private static let maximumAddresses = 32
    private static let maximumServers = 32
    private static let maximumConfigurationEntries = 1_024

    static func capture(boundPhysicalInterfaceName: String? = nil) -> LocalNetworkDiagnosticsSnapshot {
        let capturedAt = Date()
        var issues: [LocalNetworkDiagnosticsSnapshot.CollectionIssue] = []
        let interfaceKinds = knownInterfaceKinds()
        let interfaces = readInterfaces(kinds: interfaceKinds, issues: &issues)
        let store = SCDynamicStoreCreate(nil, "app.hajimi.network-diagnostics" as CFString, nil, nil)
        let keys = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6",
                    "State:/Network/Global/DNS"] as CFArray
        let patterns = ["^State:/Network/Service/[^/]+/(IPv4|IPv6|DNS)$",
                        "^State:/Network/Interface/[^/]+/(IPv4|IPv6|Link)$"] as CFArray
        let values = store.flatMap { SCDynamicStoreCopyMultiple($0, keys, patterns) as? [String: Any] }
        if values == nil { issues.append(.configurationUnavailable) }
        return makeSnapshot(capturedAt: capturedAt, interfaces: interfaces, configuration: values ?? [:],
                            boundPhysicalInterfaceName: boundPhysicalInterfaceName, issues: issues)
    }

    /// Pure assembly seam used by fixtures; production supplies only numeric
    /// addresses read above. Revalidating here also bounds all exported values.
    static func makeSnapshot(capturedAt: Date, interfaces: [LocalNetworkDiagnosticsSnapshot.Interface],
                             configuration: [String: Any], boundPhysicalInterfaceName: String? = nil,
                             issues initialIssues: [LocalNetworkDiagnosticsSnapshot.CollectionIssue] = [])
        -> LocalNetworkDiagnosticsSnapshot {
        typealias Snapshot = LocalNetworkDiagnosticsSnapshot
        var issues = initialIssues
        var seen = Set<String>()
        let normalized = interfaces.prefix(4_096).compactMap { value -> Snapshot.Interface? in
            guard validInterfaceName(value.name), seen.insert(value.name).inserted else { return nil }
            return Snapshot.Interface(name: value.name, index: value.index, kind: value.kind,
                isUp: value.isUp, isRunning: value.isRunning,
                ipv4Addresses: addresses(value.ipv4Addresses, family: AF_INET, limit: maximumAddresses),
                ipv6Addresses: addresses(value.ipv6Addresses, family: AF_INET6, limit: maximumAddresses))
        }.sorted { $0.name < $1.name }
        let boundedInterfaces = Array(normalized.prefix(maximumInterfaces))
        if normalized.count > maximumInterfaces || interfaces.count > 4_096 {
            issues.append(.resultsTruncated)
        }
        var state: [String: [String: Any]] = [:]
        // Sorting keeps truncated pathological input deterministic. The store
        // is already restricted to IPv4/IPv6/DNS/Link keys, with no SSID/MAC.
        let stateKeys = configuration.keys.filter { $0.utf8.count <= 256 }.sorted()
        for key in stateKeys.prefix(maximumConfigurationEntries) {
            if let value = configuration[key] as? [String: Any] { state[key] = value }
        }
        if stateKeys.count > maximumConfigurationEntries { issues.append(.resultsTruncated) }
        let global4 = state["State:/Network/Global/IPv4"] ?? [:]
        let global6 = state["State:/Network/Global/IPv6"] ?? [:]
        let primary4 = interfaceName(global4["PrimaryInterface"])
        let primary6 = interfaceName(global6["PrimaryInterface"])
        let byName = Dictionary(uniqueKeysWithValues: boundedInterfaces.map { ($0.name, $0) })
        func usablePhysical(_ name: String) -> Bool {
            guard let value = byName[name], value.kind == .physical || value.kind == .other else { return false }
            return value.isUp && (!value.ipv4Addresses.isEmpty || !value.ipv6Addresses.isEmpty)
        }

        var physical: String?
        var selection: Snapshot.PhysicalInterfaceSelection = .undetermined
        if let boundPhysicalInterfaceName {
            // Do not silently substitute a different interface when an active
            // tunnel's physical binding disappeared or became stale.
            if validInterfaceName(boundPhysicalInterfaceName), usablePhysical(boundPhysicalInterfaceName) {
                physical = boundPhysicalInterfaceName; selection = .boundInterface
            } else {
                issues.append(.boundInterfaceUnavailable)
            }
        } else if let primary = [primary4, primary6].compactMap({ $0 }).first(where: usablePhysical) {
            physical = primary; selection = .systemPrimary
        } else {
            let active = boundedInterfaces.filter { $0.kind == .physical && usablePhysical($0.name) }
            if active.count == 1 {
                physical = active[0].name; selection = .singleActiveInterface
            }
        }

        var gateways: [String] = []
        var physicalDNS: [String] = []
        if let physical {
            for family in ["IPv4", "IPv6"] {
                if let router = state["State:/Network/Interface/\(physical)/\(family)"]?["Router"] as? String {
                    gateways.append(router)
                }
            }
            if primary4 == physical, let router = global4["Router"] as? String { gateways.append(router) }
            if primary6 == physical, let router = global6["Router"] as? String { gateways.append(router) }
            var serviceIDs = Set<String>()
            for key in state.keys.sorted() where key.hasPrefix("State:/Network/Service/") {
                let parts = key.split(separator: "/")
                guard parts.count == 5, parts[4] == "IPv4" || parts[4] == "IPv6",
                      state[key]?["InterfaceName"] as? String == physical else { continue }
                serviceIDs.insert(String(parts[3]))
                if let router = state[key]?["Router"] as? String { gateways.append(router) }
            }
            for service in serviceIDs.sorted().prefix(maximumInterfaces) {
                physicalDNS.append(contentsOf: serverValues(state["State:/Network/Service/\(service)/DNS"]?["ServerAddresses"]))
            }
            // Some service IPv4/IPv6 dictionaries omit InterfaceName. The
            // global primary-service relationship is another explicit match.
            for global in [global4, global6] where global["PrimaryInterface"] as? String == physical {
                if let service = global["PrimaryService"] as? String, validServiceComponent(service) {
                    physicalDNS.append(contentsOf: serverValues(state["State:/Network/Service/\(service)/DNS"]?["ServerAddresses"]))
                }
            }
        }
        let systemDNS = serverValues(state["State:/Network/Global/DNS"]?["ServerAddresses"])
        let physicalAvailable = physical.flatMap { byName[$0] }.map {
            let active = state["State:/Network/Interface/\($0.name)/Link"]?["Active"] as? Bool
            return $0.isUp && (active ?? $0.isRunning) && (!$0.ipv4Addresses.isEmpty || !$0.ipv6Addresses.isEmpty)
        }
        let linkStatus: Snapshot.LinkStatus
        if let physicalAvailable { linkStatus = physicalAvailable ? .available : .unavailable }
        else if issues.contains(.interfaceEnumerationFailed) { linkStatus = .unknown }
        else if boundedInterfaces.contains(where: { $0.isUp && ($0.kind == .physical || $0.kind == .other) &&
            (!$0.ipv4Addresses.isEmpty || !$0.ipv6Addresses.isEmpty) }) { linkStatus = .unknown }
        else { linkStatus = .unavailable }
        return Snapshot(capturedAt: capturedAt, localLinkStatus: linkStatus, interfaces: boundedInterfaces,
            systemPrimaryIPv4Interface: primary4, systemPrimaryIPv6Interface: primary6,
            physicalInterfaceName: physical, physicalInterfaceSelection: selection,
            gateways: addresses(gateways, limit: 16), systemDNSServers: addresses(systemDNS, limit: maximumServers),
            physicalDNSServers: addresses(physicalDNS, limit: maximumServers),
            collectionIssues: Array(Set(issues)).sorted { $0.rawValue < $1.rawValue })
    }

    private static func knownInterfaceKinds() -> [String: LocalNetworkDiagnosticsSnapshot.InterfaceKind] {
        guard let values = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [:] }
        var result: [String: LocalNetworkDiagnosticsSnapshot.InterfaceKind] = [:]
        for value in values.prefix(256) {
            guard let raw = SCNetworkInterfaceGetBSDName(value), let type = SCNetworkInterfaceGetInterfaceType(value) else { continue }
            let name = raw as String
            guard validInterfaceName(name) else { continue }
            switch type as String {
            case "Ethernet", "IEEE80211", "FireWire", "Thunderbolt", "WWAN": result[name] = .physical
            case "PPP", "IPSec", "6to4", "VPN": result[name] = .tunnel
            default: break
            }
        }
        return result
    }

    private static func readInterfaces(kinds: [String: LocalNetworkDiagnosticsSnapshot.InterfaceKind],
                                       issues: inout [LocalNetworkDiagnosticsSnapshot.CollectionIssue])
        -> [LocalNetworkDiagnosticsSnapshot.Interface] {
        struct Entry {
            var flags: UInt32
            var ipv4: [String] = []
            var ipv6: [String] = []
        }
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { issues.append(.interfaceEnumerationFailed); return [] }
        defer { freeifaddrs(list) }
        var entries: [String: Entry] = [:], cursor = list, visited = 0
        while let item = cursor, visited < 4_096 {
            visited += 1; cursor = item.pointee.ifa_next
            guard let rawName = item.pointee.ifa_name else { continue }
            let name = String(cString: rawName)
            guard validInterfaceName(name) else { continue }
            if entries[name] == nil {
                guard entries.count < maximumInterfaces else { issues.append(.resultsTruncated); continue }
                entries[name] = Entry(flags: item.pointee.ifa_flags)
            }
            entries[name]?.flags |= item.pointee.ifa_flags
            guard let raw = item.pointee.ifa_addr, let value = numericAddress(raw, interfaceName: name) else { continue }
            if Int32(raw.pointee.sa_family) == AF_INET, entries[name]!.ipv4.count < maximumAddresses {
                entries[name]?.ipv4.append(value)
            } else if Int32(raw.pointee.sa_family) == AF_INET6, entries[name]!.ipv6.count < maximumAddresses {
                entries[name]?.ipv6.append(value)
            }
        }
        if cursor != nil { issues.append(.resultsTruncated) }
        return entries.map { name, value in
            let kind: LocalNetworkDiagnosticsSnapshot.InterfaceKind
            if value.flags & UInt32(IFF_LOOPBACK) != 0 { kind = .loopback }
            else if name.hasPrefix("utun") || name.hasPrefix("tun") || name.hasPrefix("tap") ||
                name.hasPrefix("ipsec") || name.hasPrefix("ppp") || value.flags & UInt32(IFF_POINTOPOINT) != 0 { kind = .tunnel }
            else { kind = kinds[name] ?? (name.hasPrefix("en") ? .physical : .other) }
            return LocalNetworkDiagnosticsSnapshot.Interface(name: name, index: if_nametoindex(name), kind: kind,
                isUp: value.flags & UInt32(IFF_UP) != 0, isRunning: value.flags & UInt32(IFF_RUNNING) != 0,
                ipv4Addresses: value.ipv4, ipv6Addresses: value.ipv6)
        }
    }

    private static func numericAddress(_ address: UnsafePointer<sockaddr>, interfaceName: String) -> String? {
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        switch Int32(address.pointee.sa_family) {
        case AF_INET:
            guard address.pointee.sa_len >= MemoryLayout<sockaddr_in>.size else { return nil }
            var value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            guard inet_ntop(AF_INET, &value, &output, socklen_t(output.count)) != nil else { return nil }
            return String(cString: output)
        case AF_INET6:
            guard address.pointee.sa_len >= MemoryLayout<sockaddr_in6>.size else { return nil }
            let value = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            var bytes = value.sin6_addr
            guard inet_ntop(AF_INET6, &bytes, &output, socklen_t(output.count)) != nil else { return nil }
            let literal = String(cString: output)
            return value.sin6_scope_id == 0 ? literal : literal + "%" + interfaceName
        default: return nil
        }
    }

    private static func validInterfaceName(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count < Int(IFNAMSIZ) && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95
        }
    }

    private static func interfaceName(_ value: Any?) -> String? {
        guard let value = value as? String, validInterfaceName(value) else { return nil }
        return value
    }

    private static func validServiceComponent(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && !value.contains("/") && !value.contains("\0")
    }

    private static func serverValues(_ value: Any?) -> [String] {
        (value as? [String]).map { Array($0.prefix(maximumServers)) } ?? []
    }

    private static func addresses(_ values: [String], family: Int32? = nil, limit: Int) -> [String] {
        var result: [String] = [], seen = Set<String>()
        for value in values.prefix(4_096) {
            guard value.utf8.count <= 128 else { continue }
            let pieces = value.split(separator: "%", omittingEmptySubsequences: false)
            guard pieces.count == 1 || (pieces.count == 2 && validInterfaceName(String(pieces[1]))) else { continue }
            let literal = String(pieces[0]).lowercased()
            var ipv4 = in_addr(), ipv6 = in6_addr()
            let is4 = pieces.count == 1 && literal.withCString { inet_pton(AF_INET, $0, &ipv4) } == 1
            let is6 = literal.withCString { inet_pton(AF_INET6, $0, &ipv6) } == 1
            guard (family == nil && (is4 || is6)) || (family == AF_INET && is4) || (family == AF_INET6 && is6) else { continue }
            let normalized = literal + (pieces.count == 2 ? "%" + String(pieces[1]) : "")
            guard seen.insert(normalized).inserted else { continue }
            result.append(normalized)
            if result.count == limit { break }
        }
        return result
    }
}

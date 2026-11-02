import Foundation

/// Local configuration only. Collection and normalization stay in the App's
/// platform adapter; a configured link is not proof of Internet reachability.
public struct LocalNetworkDiagnosticsSnapshot: Codable, Equatable {
    public enum LinkStatus: String, Codable { case available, unavailable, unknown }
    public enum InterfaceKind: String, Codable { case physical, tunnel, loopback, other }
    public enum PhysicalInterfaceSelection: String, Codable {
        case boundInterface, systemPrimary, singleActiveInterface, undetermined
    }
    public enum CollectionIssue: String, Codable {
        case interfaceEnumerationFailed, configurationUnavailable, resultsTruncated
        case boundInterfaceUnavailable
    }
    public struct Interface: Codable, Equatable {
        public let name: String
        public let index: UInt32
        public let kind: InterfaceKind
        public let isUp: Bool
        public let isRunning: Bool
        public let ipv4Addresses: [String]
        public let ipv6Addresses: [String]

        public init(name: String, index: UInt32, kind: InterfaceKind, isUp: Bool, isRunning: Bool,
                    ipv4Addresses: [String], ipv6Addresses: [String]) {
            self.name = name; self.index = index; self.kind = kind
            self.isUp = isUp; self.isRunning = isRunning
            self.ipv4Addresses = ipv4Addresses; self.ipv6Addresses = ipv6Addresses
        }
    }

    public let capturedAt: Date
    public let localLinkStatus: LinkStatus
    public let interfaces: [Interface]
    /// SystemConfiguration's primary service does not identify every actual route.
    public let systemPrimaryIPv4Interface: String?
    public let systemPrimaryIPv6Interface: String?
    public let physicalInterfaceName: String?
    public let physicalInterfaceSelection: PhysicalInterfaceSelection
    public let gateways: [String]
    public let systemDNSServers: [String]
    /// These can still point at the App's loopback DNS listener in enhanced mode.
    public let physicalDNSServers: [String]
    public let collectionIssues: [CollectionIssue]

    public init(capturedAt: Date, localLinkStatus: LinkStatus, interfaces: [Interface],
                systemPrimaryIPv4Interface: String?, systemPrimaryIPv6Interface: String?,
                physicalInterfaceName: String?, physicalInterfaceSelection: PhysicalInterfaceSelection,
                gateways: [String], systemDNSServers: [String], physicalDNSServers: [String],
                collectionIssues: [CollectionIssue]) {
        self.capturedAt = capturedAt; self.localLinkStatus = localLinkStatus; self.interfaces = interfaces
        self.systemPrimaryIPv4Interface = systemPrimaryIPv4Interface
        self.systemPrimaryIPv6Interface = systemPrimaryIPv6Interface
        self.physicalInterfaceName = physicalInterfaceName
        self.physicalInterfaceSelection = physicalInterfaceSelection
        self.gateways = gateways; self.systemDNSServers = systemDNSServers
        self.physicalDNSServers = physicalDNSServers; self.collectionIssues = collectionIssues
    }
}

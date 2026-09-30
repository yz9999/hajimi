import Foundation

/// The privileged helper deliberately exposes a tiny, versioned command set.
/// It never accepts executable paths, shell fragments, or a full routing
/// profile: only operations that require root (utun, routes, system DNS).
///
/// The userspace TCP/UDP data plane and every outbound protocol run in the
/// unprivileged App. After a successful `start`, the helper sends the utun
/// file descriptor over the same Unix socket with `SCM_RIGHTS`.
public enum HajimiHelperProtocol {
    public static let version = 7
    // Revision 5: install excluded CIDRs after default tunnel routes so they
    // win longest-prefix; honour tun-included-routes as a tighter default set.
    // Revision 4: install tun-excluded-routes as CIDR net routes, not hosts.
    // Revision 3: bind tunnel FD re-attach to the owning App PID; sanitize
    // bypass host routes; fix HTTP/SOCKS ready-state counting on port rebind.
    // Revision 2: non-blocking status heartbeats, process timeouts, and a
    // 3-second app-liveness teardown so a crashed GUI cannot leave routes up.
    // Revision 1 (protocol 7): data plane leaves the helper. The helper only
    // opens utun, installs split/bypass routes and optional DNS redirection,
    // then hands the utun descriptor to the App.
    public static let buildRevision = 5
    public static let label = "app.hajimi.helper"
    public static let socketPath = "/var/run/app.hajimi.helper.sock"
    public static let toolPath = "/Library/PrivilegedHelperTools/app.hajimi.helper"
    public static let launchDaemonPath = "/Library/LaunchDaemons/app.hajimi.helper.plist"
}

public struct HajimiHelperRequest: Codable, Equatable {
    public enum Action: String, Codable {
        case ping
        case status
        case start
        case reload
        case stop
    }

    public var action: Action
    /// When true, the helper points system resolvers at the tunnel DNS sink.
    public var fakeIPEnabled: Bool?
    /// Already-resolved proxy server addresses (IPv4/IPv6 literals). The App
    /// performs DNS so the helper never blocks on getaddrinfo.
    public var bypassAddresses: [String]?
    /// Surge `tun-excluded-routes`: CIDRs that stay on the physical gateway.
    public var excludedRoutes: [String]?
    /// Surge `tun-included-routes`: when non-empty, replace the default
    /// catch-all tunnel routes with this tighter set.
    public var includedRoutes: [String]?

    public init(action: Action, fakeIPEnabled: Bool? = nil,
                bypassAddresses: [String]? = nil,
                excludedRoutes: [String]? = nil,
                includedRoutes: [String]? = nil) {
        self.action = action
        self.fakeIPEnabled = fakeIPEnabled
        self.bypassAddresses = bypassAddresses
        self.excludedRoutes = excludedRoutes
        self.includedRoutes = includedRoutes
    }
}

public struct HajimiHelperTunnelState: Codable, Equatable {
    public var helperProtocolVersion: Int
    public var helperBuildRevision: Int
    public var running: Bool
    public var tunnelInterface: String?
    public var physicalInterface: String?
    public var startedAt: Date?
    public var dataPlane: String
    /// Flow counters are owned by the App data plane; the helper always
    /// reports zero so older UI bindings keep decoding.
    public var activeFlows: Int
    public var totalFlows: Int
    public var uploadedBytes: UInt64
    public var downloadedBytes: UInt64

    public init(helperProtocolVersion: Int = HajimiHelperProtocol.version,
                helperBuildRevision: Int = HajimiHelperProtocol.buildRevision,
                running: Bool, tunnelInterface: String? = nil,
                physicalInterface: String? = nil,
                startedAt: Date? = nil,
                dataPlane: String = "HajimiNativeCore (App)",
                activeFlows: Int = 0, totalFlows: Int = 0,
                uploadedBytes: UInt64 = 0, downloadedBytes: UInt64 = 0) {
        self.helperProtocolVersion = helperProtocolVersion
        self.helperBuildRevision = helperBuildRevision
        self.running = running
        self.tunnelInterface = tunnelInterface
        self.physicalInterface = physicalInterface
        self.startedAt = startedAt
        self.dataPlane = dataPlane
        self.activeFlows = activeFlows
        self.totalFlows = totalFlows
        self.uploadedBytes = uploadedBytes
        self.downloadedBytes = downloadedBytes
    }
}

public struct HajimiHelperResponse: Codable, Equatable {
    public var ok: Bool
    public var message: String?
    public var state: HajimiHelperTunnelState?
    /// When true the next datagram on the IPC socket is an `SCM_RIGHTS`
    /// message carrying the utun file descriptor.
    public var sendsTunnelFileDescriptor: Bool?

    public init(ok: Bool, message: String? = nil, state: HajimiHelperTunnelState? = nil,
                sendsTunnelFileDescriptor: Bool? = nil) {
        self.ok = ok
        self.message = message
        self.state = state
        self.sendsTunnelFileDescriptor = sendsTunnelFileDescriptor
    }
}

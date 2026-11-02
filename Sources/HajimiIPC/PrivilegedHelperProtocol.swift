import Foundation

/// The privileged helper deliberately exposes a tiny, versioned command set.
/// It never accepts executable paths, shell fragments, or a full routing
/// profile: only operations that require root (utun, routes, system DNS).
///
/// The userspace TCP/UDP data plane and every outbound protocol run in the
/// unprivileged App. `prepare` sends the utun descriptor with `SCM_RIGHTS`;
/// only `commit` after the App's reader is ready may install routes and DNS.
public enum HajimiHelperProtocol {
    public static let version = 8
    // Revision 3 (protocol 8): a reload can defer before any mutation while
    // the physical uplink is unavailable, preserving its owned tunnel.
    // Revision 2 (protocol 8): preserve the physical IPv6 interface-scoped
    // default before tunnel capture, with exact ownership and cleanup.
    // Revision 1 (protocol 8): prepare utun without capturing traffic; commit
    // only an owned, acknowledged session after the App's reader is ready.
    // Revision 6: verify DNS redirection/restoration on every enabled network
    // service; retain partial snapshots and fail/roll back on any uncertainty.
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
    // Revision 4 (protocol 8): reconcile physical routes after Wi-Fi reconnect,
    // including same-destination gateway replacement and missing owned routes.
    public static let buildRevision = 4
    public static let label = "app.hajimi.helper"
    public static let socketPath = "/var/run/app.hajimi.helper.sock"
    public static let toolPath = "/Library/PrivilegedHelperTools/app.hajimi.helper"
    public static let launchDaemonPath = "/Library/LaunchDaemons/app.hajimi.helper.plist"
}

public struct HajimiHelperRequest: Codable, Equatable {
    public enum Action: String, Codable {
        case ping
        case status
        case prepare
        case commit
        /// Deliberately rejected by protocol 8: it has no reader-ready ACK.
        case start
        case reload
        case stop
    }

    public var action: Action
    /// DNS interception intent: protection, fake-IP or hijack-dns can request
    /// this. The historical field name is retained for protocol compatibility.
    public var fakeIPEnabled: Bool?
    /// Already-resolved proxy server addresses (IPv4/IPv6 literals). The App
    /// performs DNS so the helper never blocks on getaddrinfo.
    public var bypassAddresses: [String]?
    /// Surge `tun-excluded-routes`: CIDRs that stay on the physical gateway.
    public var excludedRoutes: [String]?
    /// Surge `tun-included-routes`: when non-empty, replace the default
    /// catch-all tunnel routes with this tighter set.
    public var includedRoutes: [String]?
    /// Opaque generation token returned by prepare. Required by commit and
    /// used by session-bound cleanup so delayed work cannot stop a new tunnel.
    public var sessionToken: String?

    public init(action: Action, fakeIPEnabled: Bool? = nil,
                bypassAddresses: [String]? = nil,
                excludedRoutes: [String]? = nil,
                includedRoutes: [String]? = nil,
                sessionToken: String? = nil) {
        self.action = action
        self.fakeIPEnabled = fakeIPEnabled
        self.bypassAddresses = bypassAddresses
        self.excludedRoutes = excludedRoutes
        self.includedRoutes = includedRoutes
        self.sessionToken = sessionToken
    }
}

public enum HajimiHelperTunnelPhase: String, Codable, Equatable {
    case prepared
    case committing
    case running
}

public struct HajimiHelperTunnelState: Codable, Equatable {
    public var helperProtocolVersion: Int
    public var helperBuildRevision: Int
    public var running: Bool
    /// A prepared tunnel has a live descriptor but captures no system traffic.
    /// Optional to keep old stored/diagnostic snapshots decodable.
    public var phase: HajimiHelperTunnelPhase?
    public var sessionToken: String?
    /// False explicitly confirms that a stopped session has no unresolved
    /// currently tracked routes or resolver overrides. Historical recovery
    /// additionally requires the matching lastRestoredSessionToken ACK.
    public var networkCleanupPending: Bool?
    /// Positive recovery ACK for the last fully restored session owned by
    /// this IPC peer. A fresh/restarted Helper has no ACK for older sessions.
    public var lastRestoredSessionToken: String?
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
                running: Bool, phase: HajimiHelperTunnelPhase? = nil,
                sessionToken: String? = nil, networkCleanupPending: Bool? = false,
                lastRestoredSessionToken: String? = nil,
                tunnelInterface: String? = nil,
                physicalInterface: String? = nil,
                startedAt: Date? = nil,
                dataPlane: String = "HajimiNativeCore (App)",
                activeFlows: Int = 0, totalFlows: Int = 0,
                uploadedBytes: UInt64 = 0, downloadedBytes: UInt64 = 0) {
        self.helperProtocolVersion = helperProtocolVersion
        self.helperBuildRevision = helperBuildRevision
        self.running = running
        self.phase = phase
        self.sessionToken = sessionToken
        self.networkCleanupPending = networkCleanupPending
        self.lastRestoredSessionToken = lastRestoredSessionToken
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

public enum HajimiHelperErrorCode: String, Codable, Equatable {
    /// Read-only prepare/reload preflight, or commit preflight after exact
    /// generation cleanup, may report temporary physical network absence.
    case physicalNetworkNotReady = "physical-network-not-ready"
}

public struct HajimiHelperResponse: Codable, Equatable {
    public var ok: Bool
    public var message: String?
    public var errorCode: HajimiHelperErrorCode?
    public var state: HajimiHelperTunnelState?
    /// When true the next datagram on the IPC socket is an `SCM_RIGHTS`
    /// message carrying the utun file descriptor.
    public var sendsTunnelFileDescriptor: Bool?

    public init(ok: Bool, message: String? = nil, errorCode: HajimiHelperErrorCode? = nil,
                state: HajimiHelperTunnelState? = nil,
                sendsTunnelFileDescriptor: Bool? = nil) {
        self.ok = ok
        self.message = message
        self.errorCode = errorCode
        self.state = state
        self.sendsTunnelFileDescriptor = sendsTunnelFileDescriptor
    }
}

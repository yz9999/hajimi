import Foundation

public enum NetworkRuntimeBackend: String, Equatable {
    case enhanced, listener, unavailable

    public static func select(enhancedModeActive: Bool, listenerRunning: Bool) -> Self {
        if enhancedModeActive { return .enhanced }
        return listenerRunning ? .listener : .unavailable
    }

    public var displayName: String {
        switch self {
        case .enhanced: return "增强模式"
        case .listener: return "HTTP／SOCKS代理"
        case .unavailable: return "未启动"
        }
    }

    public func start<Value>(enhanced: () -> Value, listener: () -> Value,
                             unavailable: () -> Value) -> Value {
        switch self {
        case .enhanced: return enhanced()
        case .listener: return listener()
        case .unavailable: return unavailable()
        }
    }
}

public enum RuntimePhase: String, Equatable {
    case stopped, starting, running, stopping, failed
}

/// State supplied by an existing runtime owner, without creating a router or
/// reading platform configuration inside the runtime module.
public struct RuntimeEndpointState: Equatable {
    public var phase: RuntimePhase
    public var isPresent: Bool
    public var boundInterfaceName: String?

    public init(phase: RuntimePhase, isPresent: Bool, boundInterfaceName: String? = nil) {
        self.phase = phase
        self.isPresent = isPresent
        self.boundInterfaceName = boundInterfaceName
    }

    public static let stopped = RuntimeEndpointState(phase: .stopped, isPresent: false)
}

public struct RuntimeSnapshot: Equatable {
    public let sessionID: UUID
    public let revision: UInt64
    public let backend: NetworkRuntimeBackend
    public let ready: Bool
    public let phase: RuntimePhase
    public let boundInterfaceName: String?
}

/// A lease on one runtime revision. Unready leases remain current so their
/// adapter can publish an explicit unavailable result; IO requires isReady.
public final class RuntimeSession {
    /// Identity of this lease; the shared runtime epoch is snapshot.sessionID.
    public let id: UUID
    public let generation: UInt64
    public let snapshot: RuntimeSnapshot
    private weak var owner: RuntimeCoordinator?

    init(owner: RuntimeCoordinator, snapshot: RuntimeSnapshot) {
        self.owner = owner
        self.snapshot = snapshot
        id = UUID()
        generation = snapshot.revision
    }

    public var backend: NetworkRuntimeBackend { snapshot.backend }

    public var isCurrent: Bool {
        owner?.isCurrent(sessionID: snapshot.sessionID, revision: generation) == true
    }

    public var isReady: Bool { snapshot.ready && isCurrent }
}

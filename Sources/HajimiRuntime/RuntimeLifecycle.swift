import Foundation

/// Intent, ownership and readiness for one existing runtime owner. Methods
/// are thread safe; no Profile, platform resource or callback is stored here.
/// The owner alone attests actual acquisition/readiness/verified cleanup.
public final class RuntimeLifecycle {
    public struct Ticket: Equatable {
        fileprivate let owner: UUID
        fileprivate let generation: UInt64
    }

    public struct ReloadTicket: Equatable {
        fileprivate let session: Ticket
        fileprivate let id: UUID
    }

    public struct Snapshot: Equatable {
        public let sessionID: UUID
        public let revision: UInt64
        public let phase: RuntimePhase
        public let isPresent: Bool
        public let isReady: Bool
        public let isReloading: Bool
        public let needsRecovery: Bool
        public let startupPending: Bool
    }

    private let lock = NSLock()
    private let owner = UUID()
    private var generation: UInt64 = 0
    private var ticket: Ticket?
    private var revoked = false
    private var owned = false
    private var startupPending = false
    private var phase: RuntimePhase = .stopped
    private var recovery = false
    private var reload: ReloadTicket?
    private var revision: UInt64 = 0
    private var sessionID = UUID()

    public init() {}

    public var snapshot: Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(sessionID: sessionID, revision: revision, phase: phase,
            isPresent: owned, isReady: owned && !revoked && phase == .running && reload == nil && !recovery,
            isReloading: reload != nil, needsRecovery: recovery, startupPending: startupPending)
    }

    public func reserve() -> Ticket? {
        lock.lock(); defer { lock.unlock() }
        guard ticket == nil, !owned else { return nil }
        generation &+= 1
        let next = Ticket(owner: owner, generation: generation)
        ticket = next; revoked = false; startupPending = true
        phase = .starting; recovery = false; reload = nil
        sessionID = UUID(); revision &+= 1
        return next
    }

    /// Synchronously revokes both startup and reload completion authority.
    /// Actual resources and their reservation remain until verified cleanup.
    @discardableResult
    public func cancel() -> Ticket? {
        lock.lock(); defer { lock.unlock() }
        guard let ticket else { return nil }
        if !revoked || phase != .stopping || reload != nil {
            revoked = true; phase = .stopping; reload = nil; revision &+= 1
        }
        return ticket
    }

    public func isCurrent(_ value: Ticket) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return ticket == value && !revoked
    }

    /// Record a real acquisition even when cancellation raced its callback;
    /// this is ownership metadata, never renewed permission for I/O.
    @discardableResult
    public func markOwned(_ value: Ticket) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard ticket == value else { return false }
        if !owned { owned = true; revision &+= 1 }
        return true
    }

    /// Call only after the existing owner has passed its readiness gates.
    @discardableResult
    public func markRunning(_ value: Ticket) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard ticket == value, owned, !revoked, reload == nil, !recovery else { return false }
        if !startupPending { return phase == .running }
        guard phase == .starting else { return false }
        phase = .running; startupPending = false; revision &+= 1
        return true
    }

    /// A failure may retain prepared/running resources. A released or stopped
    /// generation has no authority to overwrite the next observation.
    public func markFailure(_ value: Ticket) {
        lock.lock(); defer { lock.unlock() }
        guard ticket == value, !revoked else { return }
        if phase != .failed || reload != nil { phase = .failed; reload = nil; revision &+= 1 }
    }

    /// A current owner may recover a transient health observation. This
    /// cannot complete startup or clear an interrupted/failed real reload.
    @discardableResult
    public func confirmHealthy(_ value: Ticket) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard ticket == value, owned, !revoked, !startupPending, !recovery, reload == nil else { return false }
        if phase != .running { phase = .running; revision &+= 1 }
        return true
    }

    public func markRecovery(_ value: Ticket) {
        lock.lock(); defer { lock.unlock() }
        guard ticket == value else { return }
        if !owned || !recovery || phase != .failed || reload != nil {
            owned = true; recovery = true; phase = .failed; reload = nil; revision &+= 1
        }
    }

    /// Completing startup work is distinct from releasing a running session.
    /// With owned resources, release cannot remove their identity or permit
    /// another start. A resource-free canceled preparation can be released.
    public func release(_ value: Ticket, preservingFailure: Bool = false) {
        lock.lock(); defer { lock.unlock() }
        guard ticket == value else { return }
        if owned {
            if startupPending { startupPending = false; revision &+= 1 }
            return
        }
        clearLocked(preservingFailure: preservingFailure)
    }

    /// The caller attests that actual cleanup/restoration has been confirmed.
    /// Stale and foreign receipts cannot release a replacement session.
    public func confirmStopped(_ value: Ticket, preservingFailure: Bool = false) {
        lock.lock(); defer { lock.unlock() }
        guard ticket == value else { return }
        clearLocked(preservingFailure: preservingFailure)
    }

    public func beginReload() -> ReloadTicket? {
        lock.lock(); defer { lock.unlock() }
        guard let ticket, owned, !revoked, !startupPending, reload == nil else { return nil }
        let next = ReloadTicket(session: ticket, id: UUID())
        reload = next; recovery = true; phase = .starting; revision &+= 1
        return next
    }

    public func isCurrent(_ value: ReloadTicket) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return reload == value && ticket == value.session && !revoked
    }

    /// A stop/new session invalidates this receipt. Failed partial reloads
    /// stay unready until the owner completes a real recovery reload.
    @discardableResult
    public func finishReload(_ value: ReloadTicket, success: Bool) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard reload == value, ticket == value.session, !revoked else { return false }
        reload = nil; recovery = !success; phase = success ? .running : .failed; revision &+= 1
        return true
    }

    private func clearLocked(preservingFailure: Bool) {
        let keepFailure = preservingFailure && !revoked && phase == .failed
        ticket = nil; revoked = false; owned = false; startupPending = false
        phase = keepFailure ? .failed : .stopped; recovery = false; reload = nil
        sessionID = UUID(); revision &+= 1
    }
}

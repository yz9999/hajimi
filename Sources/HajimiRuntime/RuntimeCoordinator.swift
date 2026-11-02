import Foundation

/// Coordinates the identity and cancellation of work performed by existing
/// runtimes. It owns no platform resources, transport, policy or configuration.
public final class RuntimeCoordinator {
    private final class WeakOperation {
        weak var value: RuntimeOperation?
        init(_ value: RuntimeOperation) { self.value = value }
    }

    private let lock = NSLock()
    private var listenerState: RuntimeEndpointState
    private var enhancedState: RuntimeEndpointState
    private var configurationRevision: UInt64
    private var revision: UInt64 = 0
    private var sessionID = UUID()
    private var valid = true
    private var operations: [WeakOperation] = []

    public init(listener: RuntimeEndpointState = .stopped,
                enhanced: RuntimeEndpointState = .stopped,
                configurationRevision: UInt64 = 0) {
        listenerState = listener
        enhancedState = enhanced
        self.configurationRevision = configurationRevision
    }

    public var snapshot: RuntimeSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return snapshotLocked()
    }

    @discardableResult
    public func update(listener: RuntimeEndpointState, enhanced: RuntimeEndpointState,
                       configurationRevision: UInt64) -> RuntimeSnapshot {
        lock.lock()
        guard listenerState != listener || enhancedState != enhanced
                || self.configurationRevision != configurationRevision else {
            let result = snapshotLocked()
            lock.unlock()
            return result
        }
        listenerState = listener
        enhancedState = enhanced
        self.configurationRevision = configurationRevision
        let cancelled = advanceLocked()
        let result = snapshotLocked()
        lock.unlock()
        cancelled.forEach { $0.cancel() }
        return result
    }

    /// Explicitly invalidates work for a lifecycle restart whose externally
    /// supplied state and configuration happen to have the same values.
    @discardableResult
    public func advanceRevision() -> RuntimeSnapshot {
        lock.lock()
        let cancelled = advanceLocked()
        let result = snapshotLocked()
        lock.unlock()
        cancelled.forEach { $0.cancel() }
        return result
    }

    public func acquireSession() -> RuntimeSession {
        lock.lock()
        let session = RuntimeSession(owner: self, snapshot: snapshotLocked())
        lock.unlock()
        return session
    }

    /// Registers cancellation with its lease atomically, then enters the
    /// supplied adapter outside the lock, including for unready snapshots.
    /// Providers must retain their own resource admission checks and support
    /// synchronous cancellation: the lease check cannot serialize arbitrary
    /// IO with a concurrent runtime update. App adapters may instead confine
    /// update and provider admission to the same serial execution domain.
    public func start<Value>(onUpdate: @escaping (Value) -> Void,
        start: (RuntimeSession, @escaping (Value) -> Void) -> RuntimeOperation) -> RuntimeOperation {
        let operation = RuntimeOperation()
        lock.lock()
        // Keep every loaded weak reference alive until after unlocking. Its
        // last release can invoke a caller's cancellation handler in deinit.
        let retained = operations.compactMap { $0.value }
        operations = retained.map { WeakOperation($0) }
        let session = RuntimeSession(owner: self, snapshot: snapshotLocked())
        operations.append(WeakOperation(operation))
        lock.unlock()
        withExtendedLifetime(retained) {}

        guard session.isCurrent && !operation.isCancelled else {
            operation.cancel()
            return operation
        }
        let child = start(session) { [weak operation, session] value in
            guard let operation, !operation.isCancelled, session.isCurrent else { return }
            onUpdate(value)
        }
        // Cancellation or a revision change during adapter startup makes this
        // a late installation and immediately cancels the returned child.
        operation.installCancellation { child.cancel() }
        return operation
    }

    func isCurrent(sessionID: UUID, revision: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return valid && self.sessionID == sessionID && self.revision == revision
    }

    private func snapshotLocked() -> RuntimeSnapshot {
        let backend: NetworkRuntimeBackend
        let endpoint: RuntimeEndpointState
        if enhancedState.isPresent {
            backend = .enhanced
            endpoint = enhancedState
        } else if listenerState.isPresent {
            backend = .listener
            endpoint = listenerState
        } else {
            backend = .unavailable
            // The listener may have failed without retaining an owner. Keep
            // that reason visible while its absent endpoint still denies IO.
            endpoint = listenerState
        }
        return RuntimeSnapshot(sessionID: sessionID, revision: revision, backend: backend,
            ready: endpoint.isPresent && endpoint.phase == .running,
            phase: endpoint.phase, boundInterfaceName: endpoint.boundInterfaceName)
    }

    /// Caller holds lock and retains this result until after unlocking.
    private func advanceLocked() -> [RuntimeOperation] {
        revision &+= 1
        sessionID = UUID()
        let cancelled = operations.compactMap { $0.value }
        operations.removeAll(keepingCapacity: true)
        return cancelled
    }

    deinit {
        lock.lock()
        valid = false
        let cancelled = advanceLocked()
        lock.unlock()
        cancelled.forEach { $0.cancel() }
    }
}

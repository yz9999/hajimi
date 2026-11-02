import Foundation

/// Installed on a per-question datagram before it is allowed to send. The
/// context carries correlation and observed progress, never routing authority.
package enum DNSQueryProgressStage: Int, Codable {
    case notStarted, transportConnecting, tlsHandshaking, ready, sending
    case awaitingResponse, receivingResponse, completed
}

package struct DNSQueryProgressSnapshot: Equatable, Codable {
    package let stage: DNSQueryProgressStage
    package let changedAt: TimeInterval
    package let transportStartedAt: TimeInterval?
    package let transportReadyAt: TimeInterval?
    package let tlsStartedAt: TimeInterval?
    package let tlsReadyAt: TimeInterval?
    package let querySentAt: TimeInterval?
    package let responseStartedAt: TimeInterval?
    package let responseCompletedAt: TimeInterval?
}

/// A small, candidate-local observation. Recording neither bridges NSError nor
/// invokes callbacks while holding this lock. Late native callbacks can retain
/// historical timestamps, but cannot move the visible stage backwards.
package final class DNSQueryExecutionContext {
    package let rootID: UUID
    package let candidateID: UUID
    /// One monotonic deadline inherited by this physical candidate's work.
    /// A successor logical generation supplies its own caller's deadline.
    package let absoluteDeadline: TimeInterval?
    private let lock = NSLock()
    private var stage = DNSQueryProgressStage.notStarted
    private var changedAt = ProcessInfo.processInfo.systemUptime
    private var transportStartedAt: TimeInterval?
    private var transportReadyAt: TimeInterval?
    private var tlsStartedAt: TimeInterval?
    private var tlsReadyAt: TimeInterval?
    private var querySentAt: TimeInterval?
    private var responseStartedAt: TimeInterval?
    private var responseCompletedAt: TimeInterval?
    private var finished = false
    private var currentAttemptID: UUID?
    private var observedInheritedDeadline = false
    private var observedConnectionReset = false
    private var connectionAttemptCancelled = false

    package init(rootID: UUID = UUID(), candidateID: UUID = UUID(),
                 absoluteDeadline: TimeInterval? = nil) {
        self.rootID = rootID; self.candidateID = candidateID
        self.absoluteDeadline = absoluteDeadline
    }

    package func child(candidateID: UUID = UUID(), absoluteDeadline: TimeInterval? = nil) -> DNSQueryExecutionContext {
        DNSQueryExecutionContext(rootID: rootID, candidateID: candidateID,
                                 absoluteDeadline: absoluteDeadline ?? self.absoluteDeadline)
    }

    /// Candidate-local timing evidence, never routing or retry authority.
    /// A new child inherits its deadline but starts without this observation.
    package func recordInheritedDeadlineReached() {
        lock.lock(); observedInheritedDeadline = true; lock.unlock()
    }

    package var inheritedDeadlineReached: Bool {
        lock.lock(); defer { lock.unlock() }; return observedInheritedDeadline
    }

    /// Native exact-reset evidence from this physical attempt, recorded before
    /// cancellation or finish. A later finish preserves already admitted
    /// evidence; an idle/old/late callback cannot create it retroactively.
    package var hasConnectionResetBeforeCancellation: Bool {
        lock.lock(); defer { lock.unlock() }; return observedConnectionReset
    }

    package func progress() -> DNSQueryProgressSnapshot {
        lock.lock(); defer { lock.unlock() }
        return progressLocked()
    }

    /// Read evidence and its physical generation's progress atomically. Two
    /// separate reads could otherwise combine old proof with a new handshake.
    package func connectionResetProgress() -> DNSQueryProgressSnapshot? {
        lock.lock(); defer { lock.unlock() }
        guard observedConnectionReset else { return nil }
        return progressLocked()
    }

    private func progressLocked() -> DNSQueryProgressSnapshot {
        return DNSQueryProgressSnapshot(stage: stage, changedAt: changedAt,
            transportStartedAt: transportStartedAt, transportReadyAt: transportReadyAt,
            tlsStartedAt: tlsStartedAt, tlsReadyAt: tlsReadyAt, querySentAt: querySentAt,
            responseStartedAt: responseStartedAt, responseCompletedAt: responseCompletedAt)
    }

    /// Only a deliberate new physical attempt (or reused lease generation)
    /// resets progress. Old native callbacks retain their original generation.
    package func beginConnectionAttempt(_ id: UUID) {
        lock.lock(); defer { lock.unlock() }
        guard currentAttemptID != id else { return }
        currentAttemptID = id; stage = .notStarted
        changedAt = ProcessInfo.processInfo.systemUptime
        transportStartedAt = nil; transportReadyAt = nil
        tlsStartedAt = nil; tlsReadyAt = nil; querySentAt = nil
        responseStartedAt = nil; responseCompletedAt = nil; finished = false
        observedConnectionReset = false; connectionAttemptCancelled = false
    }

    package func record(_ event: DNSConnectionAttemptEvent,
                attemptID: UUID? = nil,
                connectionReset: Bool = false,
                at now: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        guard now.isFinite, now >= 0 else { return }
        lock.lock(); defer { lock.unlock() }
        if let attemptID, currentAttemptID != attemptID { return }
        guard !finished else { return }
        if event == .cancelRequested || event == .localCancel { connectionAttemptCancelled = true }
        if connectionReset, attemptID != nil, !connectionAttemptCancelled,
           event == .rawFailure || event == .tlsFailure {
            observedConnectionReset = true
        }
        let next: DNSQueryProgressStage?
        switch event {
        case .transportStarted:
            if transportStartedAt == nil { transportStartedAt = now }
            next = .transportConnecting
        case .transportReady:
            if transportReadyAt == nil { transportReadyAt = now }
            next = .transportConnecting
        case .tlsStarted:
            if tlsStartedAt == nil { tlsStartedAt = now }
            next = .tlsHandshaking
        case .tlsReady:
            if tlsReadyAt == nil { tlsReadyAt = now }
            next = .ready
        case .connectionReused: next = .ready
        case .querySendStarted: next = .sending
        case .querySent:
            if querySentAt == nil { querySentAt = now }
            next = .awaitingResponse
        case .responseStarted:
            if responseStartedAt == nil { responseStartedAt = now }
            next = .receivingResponse
        case .responseComplete:
            if responseCompletedAt == nil { responseCompletedAt = now }
            next = .completed
        case .requestFinished:
            finished = true; next = nil
        default: next = nil
        }
        if let next, next.rawValue > stage.rawValue {
            changedAt = stage == .notStarted ? now : max(changedAt, now)
            stage = next
        }
    }
}

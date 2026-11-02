import Foundation

/// The query coordinator owns logical registrations, never a native socket.
/// Concrete transports expose only the additional capabilities they implement.
public protocol DNSQueryDatagram: AnyObject {
    func send(_ data: Data)
    func cancel()
}

public enum DNSAttemptCancellationReason: String, Codable {
    case callerCancelled, winnerSelected, hedgeRotation, overallDeadline, requestDeadline
    case encryptedPhaseDeadline, policyChanged, poolShutdown, prewarmSuperseded, cleanup
}

public enum DNSConnectionAttemptEvent: String, Codable {
    case transportStarted, transportReady, transportFailure, tlsStarted, tlsReady, tlsWaiting, tlsFailure
    case rawEOF, rawFailure, rawWriteFailure, bridgeEOF, bridgeFailure, handshakeTimeout, localCancel
    case cancelRequested, requestFinished
    case connectionReused, querySendStarted, querySent, responseStarted, responseComplete
    case querySendFailure, responseFailure
    case resolverQueued, resolverAdmitted
}

public enum DNSPerformanceEvent {
    case query
    case cacheHit
    case cacheEligible
    case cacheBypassed
    case cacheStore
    case cacheStoreRejected
    case merged
    case upstreamAttempt
    case failure
    case cancelled
    case failover
    case connectionReuse
    case proxyFallbackAttempt
    case proxyFallbackSuccess
    case proxyFallbackFailure
    case proxyFallbackConnectionReuse
}

/// Bounded, privacy-preserving reasons for a failed logical application
/// question. Candidate attempts, including cancelled hedges, are not questions.
public enum DNSQueryFailureReason: String, CaseIterable, Hashable {
    case upstreamOrResponse
    case timeout
    case capacity
    case authentication
    case configurationOrPolicy
    case invalidResponse
}

/// A parent may reach the logical query deadline before its child timer. This
/// notification distinguishes a real total timeout from client cancellation;
/// implementations clean up on their own queue without extending the deadline.
package protocol DNSQueryDeadlineAwareDatagram: DNSQueryDatagram {
    func queryDeadlineReached()
}

/// A real logical deadline fence, not an acknowledgement of native FD closure.
/// Only this capability can sponsor follower handoff without losing a deny.
package protocol DNSQueryDeadlineAcknowledging: DNSQueryDeadlineAwareDatagram {
    func queryDeadlineReached(completion: @escaping (DNSProxyFallbackBarrier?) -> Void)
}

/// Registration is revoked and the request has finished on its owner queue.
/// Pending native dials retain their separate leases until native completion.
package protocol DNSQueryCancellationAcknowledging: DNSQueryDatagram {
    func cancel(completion: @escaping () -> Void)
    func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void)
}

extension DNSQueryCancellationAcknowledging {
    package func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        cancel(completion: completion)
    }
}

package protocol DNSQueryPhaseDeadlineAcknowledging: DNSQueryCancellationAcknowledging {
    func phaseDeadlineReached(completion: @escaping () -> Void)
}

package protocol DNSQueryEncryptedPhaseScheduling: AnyObject {
    func encryptedPhaseContinuationDeadline(completion: @escaping (TimeInterval?) -> Void)
}

package enum DNSProxyFallbackBarrier {
    case answer(Data)
    case failure(Error)
}

package protocol DNSProxyFallbackBarrierProviding: AnyObject {
    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier?
}

package protocol DNSQueryExecutionContextAccepting: AnyObject {
    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext)
}

package protocol DNSQueryTransportEvidenceProviding: AnyObject {
    func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence
}

package enum DNSQueryOutcome {
    case success, failure, cancelled
}

/// The platform adapter retains raw Error identities and supplies only the
/// existing typed decisions. Unknown errors cannot authorize another path.
package struct DNSQueryFailureClassification {
    package let reason: DNSQueryFailureReason
    package let isTimeout: Bool
    package let permitsProxyFallback: Bool

    package init(reason: DNSQueryFailureReason, isTimeout: Bool, permitsProxyFallback: Bool) {
        self.reason = reason; self.isTimeout = isTimeout
        self.permitsProxyFallback = permitsProxyFallback
    }
}

/// Observation cannot grant authority, resolve a name, or start transport I/O.
package protocol DNSQueryObserver: AnyObject {
    func recordDNS(_ event: DNSPerformanceEvent, count: Int)
    func recordResolution(milliseconds: Double, outcome: DNSQueryOutcome)
    func recordDNSFailure(_ reason: DNSQueryFailureReason)
    func beginDNSQuery(rootID: UUID, waiterID: UUID, started: UInt64, absoluteDeadline: TimeInterval)
    func joinDNSQuery(rootID: UUID, waiterID: UUID, started: UInt64, absoluteDeadline: TimeInterval)
    func finishDNSQueryWaiter(rootID: UUID, waiterID: UUID, outcome: DNSQueryOutcome,
                              failureReason: DNSQueryFailureReason?, milliseconds: Double)
    func recordDNSUpstreamStart(rootID: UUID, generationID: UUID, queuedAt: UInt64, started: UInt64)
}

extension DNSQueryObserver {
    package func recordDNS(_ event: DNSPerformanceEvent) { recordDNS(event, count: 1) }
}

package enum DNSQueryMonotonicClock {
    package static func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
    package static func elapsedMilliseconds(since started: UInt64) -> Double {
        let now = self.now()
        return Double(now >= started ? now - started : 0) / 1_000_000
    }
}

import Foundation
import HajimiDNS

/// Keep the router's existing diagnostics and platform error classification at
/// the Core boundary. The DNS module cannot create a route or native transport.
extension DNSQueryCoordinator {
    convenience init(cache: DNSQueryCache = DNSQueryCache(), maximumPending: Int = 512,
                     maximumWaiters: Int = 512, maximumWaitersPerQuery: Int = 64,
                     maximumActiveUpstreams: Int = 16,
                     timeout: DispatchTimeInterval = .seconds(8),
                     diagnostics: NetworkPerformanceDiagnostics = .shared) {
        self.init(cache: cache, maximumPending: maximumPending,
                  maximumWaiters: maximumWaiters, maximumWaitersPerQuery: maximumWaitersPerQuery,
                  maximumActiveUpstreams: maximumActiveUpstreams, timeout: timeout,
                  observer: CoreDNSQueryObserver(diagnostics),
                  classifyFailure: CoreDNSQueryFailureAdapter.classify,
                  makeInvalidResponseError: { EncryptedDNSQueryFailure.invalidResponse })
    }
}

/// The module's one-query lease continues to satisfy the existing router API.
/// This conformance adds no deadline or native-cancellation capability.
extension DNSCoalescedQueryDatagram: NativeRoutedDatagram {}

private final class CoreDNSQueryObserver: DNSQueryObserver {
    private let diagnostics: NetworkPerformanceDiagnostics

    init(_ diagnostics: NetworkPerformanceDiagnostics) { self.diagnostics = diagnostics }

    func recordDNS(_ event: DNSPerformanceEvent, count: Int) {
        diagnostics.recordDNS(event, count: count)
    }

    func recordResolution(milliseconds: Double, outcome: DNSQueryOutcome) {
        diagnostics.record(.dnsResolution, milliseconds: milliseconds, outcome: Self.outcome(outcome))
    }

    func recordDNSFailure(_ reason: DNSQueryFailureReason) { diagnostics.recordDNSFailure(reason) }

    func beginDNSQuery(rootID: UUID, waiterID: UUID, started: UInt64, absoluteDeadline: TimeInterval) {
        diagnostics.beginDNSQuery(rootID: rootID, waiterID: waiterID,
                                  started: started, absoluteDeadline: absoluteDeadline)
    }

    func joinDNSQuery(rootID: UUID, waiterID: UUID, started: UInt64, absoluteDeadline: TimeInterval) {
        diagnostics.joinDNSQuery(rootID: rootID, waiterID: waiterID,
                                 started: started, absoluteDeadline: absoluteDeadline)
    }

    func finishDNSQueryWaiter(rootID: UUID, waiterID: UUID, outcome: DNSQueryOutcome,
                              failureReason: DNSQueryFailureReason?, milliseconds: Double) {
        diagnostics.finishDNSQueryWaiter(rootID: rootID, waiterID: waiterID,
            outcome: Self.outcome(outcome), failureReason: failureReason, milliseconds: milliseconds)
    }

    func recordDNSUpstreamStart(rootID: UUID, generationID: UUID, queuedAt: UInt64, started: UInt64) {
        diagnostics.recordDNSUpstreamStart(rootID: rootID, generationID: generationID,
                                           queuedAt: queuedAt, started: started)
    }

    private static func outcome(_ value: DNSQueryOutcome) -> NetworkPerformanceOutcome {
        switch value {
        case .success: return .success
        case .failure: return .failure
        case .cancelled: return .cancelled
        }
    }
}

private enum CoreDNSQueryFailureAdapter {
    static func classify(_ error: Error) -> DNSQueryFailureClassification {
        DNSQueryFailureClassification(reason: failureReason(error),
            isTimeout: error is DNSQueryTimeoutError || (error as? EncryptedDNSQueryFailure) == .timeout,
            permitsProxyFallback: EncryptedDNSQueryFailure.classify(error).permitsProxyFallback)
    }

    /// Preserve the original coordinator classification independently of the
    /// broader transport classifier; network errors remain upstream failures.
    private static func failureReason(_ error: Error) -> DNSQueryFailureReason {
        if error is DNSQueryTimeoutError { return .timeout }
        if let encrypted = error as? EncryptedDNSQueryFailure {
            switch encrypted {
            case .timeout: return .timeout
            case .capacity: return .capacity
            case .authentication: return .authentication
            case .policy, .configuration: return .configurationOrPolicy
            case .invalidResponse: return .invalidResponse
            default: return .upstreamOrResponse
            }
        }
        let value = error as NSError
        if error is NodeConnectionAdmissionError
            || (value.domain == NodeConnectionAdmissionError.errorDomain
                && value.code == NodeConnectionAdmissionError.capacityExceeded.errorCode) { return .capacity }
        return .upstreamOrResponse
    }
}

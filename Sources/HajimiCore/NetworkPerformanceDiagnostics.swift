import Foundation
import CoreFoundation
import HajimiDNS
import Network

public enum DNSAttemptTransport: String, Codable { case doh, dot, proxyTCP }
public enum DNSAttemptPurpose: String, Codable { case query, prewarm }
public enum DNSAttemptRoute: String, Codable { case unknown, direct, proxy }
public enum DNSAttemptOutcome: String, Codable { case success, failure, cancelled }
public enum DNSResolverQueueReason: String, Codable, CaseIterable {
    case queryLimit, coldConnectionLimit, physicalConnectionLimit
}

/// Cumulative, payload-free evidence from one traced DNS TLS stream. A raw
/// write completion reports the carrier's local completion, and plaintext
/// processing reports Network.framework's local contentProcessed callback;
/// neither is evidence of peer receipt or a remote TCP acknowledgement.
/// Raw reads can contain TLS control records rather than DNS response data.
public struct DNSStreamProgressSnapshot: Equatable, Codable {
    public fileprivate(set) var rawWriteRequestedBytes: UInt64 = 0
    public fileprivate(set) var rawWriteCompletedBytes: UInt64 = 0
    /// ByteTransport.receive has no requested-length argument, so requests
    /// are counted as operations instead of inventing a byte count.
    public fileprivate(set) var rawReadRequests: UInt64 = 0
    public fileprivate(set) var rawReadCompletedBytes: UInt64 = 0
    public fileprivate(set) var plaintextWriteRequestedBytes: UInt64 = 0
    public fileprivate(set) var plaintextWriteProcessedBytes: UInt64 = 0
    public fileprivate(set) var plaintextReadRequests: UInt64 = 0
    public fileprivate(set) var plaintextReadDeliveredBytes: UInt64 = 0

    public fileprivate(set) var lastRawWriteRequestedUptimeNanoseconds: UInt64?
    public fileprivate(set) var lastRawWriteCompletedUptimeNanoseconds: UInt64?
    public fileprivate(set) var lastRawReadRequestedUptimeNanoseconds: UInt64?
    public fileprivate(set) var lastRawReadCompletedUptimeNanoseconds: UInt64?
    public fileprivate(set) var lastPlaintextWriteRequestedUptimeNanoseconds: UInt64?
    public fileprivate(set) var lastPlaintextWriteProcessedUptimeNanoseconds: UInt64?
    public fileprivate(set) var lastPlaintextReadRequestedUptimeNanoseconds: UInt64?
    public fileprivate(set) var lastPlaintextReadDeliveredUptimeNanoseconds: UInt64?

    public init() {}

    /// A lease may start after this stream's handshake or an earlier query.
    /// Keep timestamps only for counters that actually advanced in this lease.
    /// An unavailable/reset stream cannot masquerade as an all-zero sample.
    public func delta(since baseline: DNSStreamProgressSnapshot) -> DNSStreamProgressSnapshot? {
        guard rawWriteRequestedBytes >= baseline.rawWriteRequestedBytes,
              rawWriteCompletedBytes >= baseline.rawWriteCompletedBytes,
              rawReadRequests >= baseline.rawReadRequests,
              rawReadCompletedBytes >= baseline.rawReadCompletedBytes,
              plaintextWriteRequestedBytes >= baseline.plaintextWriteRequestedBytes,
              plaintextWriteProcessedBytes >= baseline.plaintextWriteProcessedBytes,
              plaintextReadRequests >= baseline.plaintextReadRequests,
              plaintextReadDeliveredBytes >= baseline.plaintextReadDeliveredBytes else { return nil }
        var value = DNSStreamProgressSnapshot()
        value.rawWriteRequestedBytes = rawWriteRequestedBytes - baseline.rawWriteRequestedBytes
        value.rawWriteCompletedBytes = rawWriteCompletedBytes - baseline.rawWriteCompletedBytes
        value.rawReadRequests = rawReadRequests - baseline.rawReadRequests
        value.rawReadCompletedBytes = rawReadCompletedBytes - baseline.rawReadCompletedBytes
        value.plaintextWriteRequestedBytes = plaintextWriteRequestedBytes - baseline.plaintextWriteRequestedBytes
        value.plaintextWriteProcessedBytes = plaintextWriteProcessedBytes - baseline.plaintextWriteProcessedBytes
        value.plaintextReadRequests = plaintextReadRequests - baseline.plaintextReadRequests
        value.plaintextReadDeliveredBytes = plaintextReadDeliveredBytes - baseline.plaintextReadDeliveredBytes
        value.lastRawWriteRequestedUptimeNanoseconds = value.rawWriteRequestedBytes > 0 ? lastRawWriteRequestedUptimeNanoseconds : nil
        value.lastRawWriteCompletedUptimeNanoseconds = value.rawWriteCompletedBytes > 0 ? lastRawWriteCompletedUptimeNanoseconds : nil
        value.lastRawReadRequestedUptimeNanoseconds = value.rawReadRequests > 0 ? lastRawReadRequestedUptimeNanoseconds : nil
        value.lastRawReadCompletedUptimeNanoseconds = value.rawReadCompletedBytes > 0 ? lastRawReadCompletedUptimeNanoseconds : nil
        value.lastPlaintextWriteRequestedUptimeNanoseconds = value.plaintextWriteRequestedBytes > 0 ? lastPlaintextWriteRequestedUptimeNanoseconds : nil
        value.lastPlaintextWriteProcessedUptimeNanoseconds = value.plaintextWriteProcessedBytes > 0 ? lastPlaintextWriteProcessedUptimeNanoseconds : nil
        value.lastPlaintextReadRequestedUptimeNanoseconds = value.plaintextReadRequests > 0 ? lastPlaintextReadRequestedUptimeNanoseconds : nil
        value.lastPlaintextReadDeliveredUptimeNanoseconds = value.plaintextReadDeliveredBytes > 0 ? lastPlaintextReadDeliveredUptimeNanoseconds : nil
        return value
    }
}

/// nil means the stream does not provide this evidence; it is not a measured
/// zero. Physical pools, transport scheduling and cancellation remain owners
/// of their original state and do not depend on these passive counters.
public protocol DNSStreamProgressProviding: AnyObject {
    func dnsStreamProgressSnapshot() -> DNSStreamProgressSnapshot?
}

enum DNSStreamProgressEvent {
    case rawWriteRequested, rawWriteCompleted, rawReadRequested, rawReadCompleted
    case plaintextWriteRequested, plaintextWriteProcessed, plaintextReadRequested, plaintextReadDelivered
}

/// Allocated only when a DNS attempt trace enables it. No buffers, callbacks,
/// endpoint identifiers or per-chunk observations are retained.
final class DNSStreamProgressRecorder {
    private let lock = NSLock()
    private let clock: () -> UInt64
    private var value = DNSStreamProgressSnapshot()

    init(clock: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) {
        self.clock = clock
    }

    func snapshot() -> DNSStreamProgressSnapshot {
        lock.lock(); defer { lock.unlock() }; return value
    }

    func record(_ event: DNSStreamProgressEvent, bytes: Int = 0) {
        // Even the injectable clock runs outside the lock. Native I/O and its
        // completion/failure callbacks are never invoked by this recorder.
        let now = clock(), bytes = UInt64(max(0, bytes))
        func adding(_ count: UInt64, _ increment: UInt64) -> UInt64 {
            let (sum, overflow) = count.addingReportingOverflow(increment)
            return overflow ? .max : sum
        }
        func stamp(_ previous: UInt64?) -> UInt64 { max(previous ?? 0, now) }
        lock.lock(); defer { lock.unlock() }
        switch event {
        case .rawWriteRequested:
            value.rawWriteRequestedBytes = adding(value.rawWriteRequestedBytes, bytes)
            value.lastRawWriteRequestedUptimeNanoseconds = stamp(value.lastRawWriteRequestedUptimeNanoseconds)
        case .rawWriteCompleted:
            value.rawWriteCompletedBytes = adding(value.rawWriteCompletedBytes, bytes)
            value.lastRawWriteCompletedUptimeNanoseconds = stamp(value.lastRawWriteCompletedUptimeNanoseconds)
        case .rawReadRequested:
            value.rawReadRequests = adding(value.rawReadRequests, 1)
            value.lastRawReadRequestedUptimeNanoseconds = stamp(value.lastRawReadRequestedUptimeNanoseconds)
        case .rawReadCompleted:
            value.rawReadCompletedBytes = adding(value.rawReadCompletedBytes, bytes)
            value.lastRawReadCompletedUptimeNanoseconds = stamp(value.lastRawReadCompletedUptimeNanoseconds)
        case .plaintextWriteRequested:
            value.plaintextWriteRequestedBytes = adding(value.plaintextWriteRequestedBytes, bytes)
            value.lastPlaintextWriteRequestedUptimeNanoseconds = stamp(value.lastPlaintextWriteRequestedUptimeNanoseconds)
        case .plaintextWriteProcessed:
            value.plaintextWriteProcessedBytes = adding(value.plaintextWriteProcessedBytes, bytes)
            value.lastPlaintextWriteProcessedUptimeNanoseconds = stamp(value.lastPlaintextWriteProcessedUptimeNanoseconds)
        case .plaintextReadRequested:
            value.plaintextReadRequests = adding(value.plaintextReadRequests, 1)
            value.lastPlaintextReadRequestedUptimeNanoseconds = stamp(value.lastPlaintextReadRequestedUptimeNanoseconds)
        case .plaintextReadDelivered:
            value.plaintextReadDeliveredBytes = adding(value.plaintextReadDeliveredBytes, bytes)
            value.lastPlaintextReadDeliveredUptimeNanoseconds = stamp(value.lastPlaintextReadDeliveredUptimeNanoseconds)
        }
    }
}

/// Only fixed categories and numeric codes cross the diagnostic boundary.
/// In particular NSError descriptions/userInfo can contain URLs and credentials.
public struct DNSAttemptErrorCode: Equatable, Codable {
    public let domain: String
    public let code: Int
}

public struct DNSAttemptErrorSnapshot: Equatable, Codable {
    public let category: String
    public let codes: [DNSAttemptErrorCode]

    static func capture(_ error: Error) -> DNSAttemptErrorSnapshot {
        var codes: [DNSAttemptErrorCode] = []
        var next: Error? = error
        var seen = Set<ObjectIdentifier>()
        var category = "unknown"
        for _ in 0..<4 {
            guard let current = next else { break }
            let native = current as NSError
            guard seen.insert(ObjectIdentifier(native)).inserted else { break }
            let domain: String, code: Int
            if let network = current as? NWError {
                switch network {
                case .tls(let status):
                    domain = NSOSStatusErrorDomain; code = Int(status)
                case .posix(let status):
                    domain = NSPOSIXErrorDomain; code = Int(status.rawValue)
                case .dns(let status):
                    domain = "kDNSServiceErrorDomain"; code = Int(status)
                @unknown default:
                    domain = "Network.NWError"; code = native.code
                }
            } else {
                let knownDomains: Set<String> = [NSPOSIXErrorDomain, NSOSStatusErrorDomain,
                    NSURLErrorDomain, NSCocoaErrorDomain, "kCFErrorDomainCFNetwork", "kDNSServiceErrorDomain",
                    "app.hajimi.cpp-protocol", "app.hajimi.node-connection-admission", "app.hajimi.proxy-runtime",
                    "HajimiCXXProtocol", "cpp-protocol", "Network.NWError",
                    "app.hajimi.nested-tls-carrier", "HajimiCore.NativeOutboundError"]
                domain = knownDomains.contains(native.domain) ? native.domain
                    : NetworkPerformanceDiagnostics.dnsOpaqueID(native.domain, prefix: "error")
                code = native.code
            }
            codes.append(DNSAttemptErrorCode(domain: domain, code: code))
            if domain == NSOSStatusErrorDomain {
                category = code == -9816 ? "tlsClosedWithoutNotify" : "tls"
            } else if domain == NSPOSIXErrorDomain {
                if category == "unknown" {
                    category = code == Int(ECANCELED) ? "cancelled"
                        : (code == Int(ETIMEDOUT) ? "timeout" : "network")
                }
            } else if domain == NSURLErrorDomain, category == "unknown" {
                category = code == NSURLErrorCancelled ? "cancelled"
                    : (code == NSURLErrorTimedOut ? "timeout" : "urlLoading")
            } else if domain == "app.hajimi.nested-tls-carrier", category == "unknown" {
                if code == 1 { category = "carrierClosedBeforeUse" }
                else if code == 2 { category = "carrierClosedBeforeTLS" }
            } else if domain == "HajimiCore.NativeOutboundError", category == "unknown" {
                switch code {
                case 0: category = "configuration"
                case 1: category = "network"
                case 2: category = "protocol"
                case 3: category = "authentication"
                case 4: category = "cancelled"
                default: break
                }
            } else if domain == "app.hajimi.cpp-protocol", category == "unknown" {
                category = "protocol"
            }
            next = native.userInfo[NSUnderlyingErrorKey] as? Error
        }
        return DNSAttemptErrorSnapshot(category: category, codes: codes)
    }
}

public struct DNSConnectionAttemptObservation: Equatable, Codable {
    public let sequence: UInt64
    public let event: DNSConnectionAttemptEvent
    public let milliseconds: Double
    public fileprivate(set) var error: DNSAttemptErrorSnapshot?
    public let cancellationReason: DNSAttemptCancellationReason?
    /// Cumulative encrypted peer bytes at raw EOF; never retains payload.
    public fileprivate(set) var peerCiphertextBytes: UInt64?
}

public struct DNSConnectionAttemptSnapshot: Equatable, Codable {
    public let id: UUID
    public let requestID: UUID
    public let rootID: UUID?
    public let candidateID: UUID?
    public let upstreamID: String
    public let addressID: String
    public let provider: String
    public let transport: DNSAttemptTransport
    public let purpose: DNSAttemptPurpose
    public fileprivate(set) var route: DNSAttemptRoute
    public fileprivate(set) var routeID: String?
    public fileprivate(set) var transportOutcome: DNSAttemptOutcome?
    public fileprivate(set) var tlsOutcome: DNSAttemptOutcome?
    public fileprivate(set) var requestFinished: Bool
    public fileprivate(set) var firstError: DNSAttemptErrorSnapshot?
    /// Excludes error callbacks that arrived after a cancellation request or
    /// actual local close; the complete original firstError remains available.
    public fileprivate(set) var firstErrorBeforeCancellation: DNSAttemptErrorSnapshot?
    public fileprivate(set) var firstCarrierClosure: DNSConnectionAttemptObservation?
    public fileprivate(set) var firstLocalCancellation: DNSConnectionAttemptObservation?
    public fileprivate(set) var firstCancellationRequest: DNSConnectionAttemptObservation?
    public fileprivate(set) var cancellationReason: DNSAttemptCancellationReason?
    public fileprivate(set) var observations: [DNSConnectionAttemptObservation]
    public fileprivate(set) var omittedObservations: UInt64
    fileprivate var observedEventCount: UInt64
    fileprivate var firstErrorSequence: UInt64?
    fileprivate var firstErrorBeforeCancellationSequence: UInt64?
    fileprivate let started: UInt64
}

/// A small handle, also usable on native callback queues before queue hops.
/// Once its bounded ring slot has expired it cannot recreate an old attempt.
final class DNSConnectionAttemptTrace {
    let id: UUID
    private weak var diagnostics: NetworkPerformanceDiagnostics?
    private let context: DNSQueryExecutionContext?

    fileprivate init(id: UUID, diagnostics: NetworkPerformanceDiagnostics,
                     context: DNSQueryExecutionContext? = nil) {
        self.id = id; self.diagnostics = diagnostics; self.context = context
    }

    func record(_ event: DNSConnectionAttemptEvent, error: Error? = nil,
                peerCiphertextBytes: UInt64? = nil,
                admitting: (() -> Void)? = nil) {
        context?.record(event, attemptID: id,
            connectionReset: (event == .rawFailure || event == .tlsFailure)
                && Self.isNativeConnectionReset(error))
        guard let diagnostics else { admitting?(); return }
        diagnostics.observeDNSAttempt(id, event: event, error: error,
            peerCiphertextBytes: peerCiphertextBytes, admitting: admitting)
    }

    func recordRawEOF(peerCiphertextBytes: UInt64) {
        record(.rawEOF, peerCiphertextBytes: peerCiphertextBytes)
    }

    func cancel(_ reason: DNSAttemptCancellationReason) {
        context?.record(.cancelRequested, attemptID: id)
        diagnostics?.observeDNSAttempt(id, event: .cancelRequested, cancellationReason: reason)
    }

    /// The ObjC runtime supplies nw_error_copy_cf_error via toll-free bridging,
    /// whose concrete class differs from NSError on macOS. Obtain that exact
    /// native class without trusting arbitrary NSError subclass overrides.
    private static let nativeCFErrorType: Any.Type = {
        let error = CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainPOSIX,
                                  Int(POSIXErrorCode.ECONNRESET.rawValue), nil)!
        return type(of: unsafeBitCast(error, to: NSError.self))
    }()

    /// Do not bridge an arbitrary Swift/CustomNSError before the existing
    /// security admission callback. A concrete native value can establish
    /// reset provenance; a synthesized category, underlying code or custom
    /// NSError subclass cannot grant a new recovery opportunity.
    private static func isNativeConnectionReset(_ error: Error?) -> Bool {
        guard let error else { return false }
        if type(of: error) == NWError.self {
            guard case .posix(let code) = error as! NWError else { return false }
            return code == .ECONNRESET
        }
        guard type(of: error) == NSError.self || type(of: error) == nativeCFErrorType else { return false }
        let native = error as NSError
        return native.domain == NSPOSIXErrorDomain && native.code == Int(POSIXErrorCode.ECONNRESET.rawValue)
            && native.userInfo[NSUnderlyingErrorKey] == nil
    }

    func setRoute(_ route: DNSAttemptRoute, identity: String) {
        diagnostics?.updateDNSAttempt(id) {
            $0.route = route
            $0.routeID = NetworkPerformanceDiagnostics.dnsOpaqueID(identity, prefix: "route")
        }
    }

    func complete(_ stage: NetworkPerformanceStage, outcome: NetworkPerformanceOutcome) {
        let value: DNSAttemptOutcome
        switch outcome {
        case .success: value = .success
        case .failure: value = .failure
        case .cancelled: value = .cancelled
        }
        diagnostics?.updateDNSAttempt(id) {
            if stage == .dnsTLSHandshake { $0.tlsOutcome = value }
            else if stage == .dnsUpstreamConnection || stage == .dnsProxyFallbackConnection { $0.transportOutcome = value }
        }
    }
}

public struct DNSLogicalQueryWaiterSnapshot: Equatable, Codable {
    public let waiterID: UUID
    public let startedUptimeNanoseconds: UInt64
    public let absoluteDeadlineUptime: TimeInterval
    public fileprivate(set) var outcome: DNSAttemptOutcome?
    public fileprivate(set) var failureReason: String?
    public fileprivate(set) var milliseconds: Double?
}

/// Constant-size coordinator evidence survives independent exchange-ring
/// eviction. These times describe admission to upstream work, not a TCP dial.
public struct DNSLogicalQuerySchedulingSnapshot: Equatable, Codable {
    public let firstUpstreamStartedUptimeNanoseconds: UInt64
    public fileprivate(set) var latestUpstreamStartedUptimeNanoseconds: UInt64
    public fileprivate(set) var upstreamStartCount: UInt64
    public let firstCoordinatorQueueMilliseconds: Double
    public fileprivate(set) var maximumCoordinatorQueueMilliseconds: Double
}

public struct DNSLogicalQuerySnapshot: Equatable, Codable {
    public let rootID: UUID
    public fileprivate(set) var waiters: [DNSLogicalQueryWaiterSnapshot]
    public fileprivate(set) var admittedCount: UInt64
    public fileprivate(set) var mergedCount: UInt64
    public fileprivate(set) var finishedCount: UInt64
    public fileprivate(set) var outcomeCounts: [String: UInt64]
    public fileprivate(set) var failureCounts: [String: UInt64]
    public fileprivate(set) var omittedWaiters: UInt64
    /// Optional for additive compatibility with existing schema-2 exports.
    public fileprivate(set) var scheduling: DNSLogicalQuerySchedulingSnapshot?
    fileprivate let started: UInt64
}

/// One bounded sample per actual send/lease, captured before retry or close.
/// A pending idle read can be inherited by a new lease: zero new native read
/// requests does not mean there was no reader. Carrier bytes may be TLS control
/// records, and local write completion never establishes remote receipt.
public struct DNSQueryLeaseIOProgressSnapshot: Equatable, Codable {
    public let ordinal: UInt8
    public let reusedConnection: Bool
    public let sampledBeforeIdleRetry: Bool
    public let millisecondsSinceSend: Double
    public let resolverReadRequests: UInt64
    public let firstResolverReadMilliseconds: Double?
    public let pooledReadPendingAtSend: Bool
    public let pooledReadPendingAtSample: Bool
    public let plaintextResponseBytes: Int
    /// nil means this stream cannot supply a same-lease baseline and sample.
    public let stream: DNSStreamProgressSnapshot?
}

/// A leased query exchange is separate from a physical connection. In
/// particular reuse creates this record without inventing TCP or TLS stages.
public struct DNSQueryExchangeSnapshot: Equatable, Codable {
    public let id: UUID
    public let requestID: UUID
    public let rootID: UUID?
    public let candidateID: UUID?
    public let upstreamID: String
    public let transport: DNSAttemptTransport
    public fileprivate(set) var physicalAttemptIDs: [UUID]
    public fileprivate(set) var reusedConnection: Bool
    public fileprivate(set) var outcome: DNSAttemptOutcome?
    public fileprivate(set) var failureReason: String?
    public fileprivate(set) var httpStatusCode: Int?
    public fileprivate(set) var responseBytes: Int?
    public fileprivate(set) var dnsResponseCode: UInt8?
    public fileprivate(set) var responseRejection: String?
    /// Numeric wire metadata only; no question name or EDE EXTRA-TEXT.
    public fileprivate(set) var queryType: UInt16?
    /// Fixed range label for a complete IN/PTR question, never its target.
    /// Optional for existing schema-2 reports and every non-PTR exchange.
    public fileprivate(set) var ptrTargetCategory: DNSPTRTargetCategory?
    /// Fixed shape, distinct from the reverse target's address range.
    public fileprivate(set) var ptrQueryKind: DNSPTRQueryKind?
    public fileprivate(set) var queryClass: UInt16?
    public fileprivate(set) var queryFlags: UInt16?
    public fileprivate(set) var queryBytes: Int?
    public fileprivate(set) var queryAdditionalRecordCount: UInt16?
    /// At most two samples: the idle lease and its one allowed fresh retry.
    /// Absent in older reports and when no query send was attempted.
    public fileprivate(set) var leaseIOProgress: [DNSQueryLeaseIOProgressSnapshot]?
    public fileprivate(set) var extendedDNSErrorCodes: [UInt16]?
    /// Local resolver-pool wait, including a retry's wait. Never an upstream
    /// RTT or authorization failure; optional for older schema-2 reports.
    public fileprivate(set) var resolverQueueMilliseconds: Double?
    public fileprivate(set) var resolverQueueReasons: [DNSResolverQueueReason]?
    public fileprivate(set) var firstError: DNSAttemptErrorSnapshot?
    public fileprivate(set) var firstErrorBeforeCancellation: DNSAttemptErrorSnapshot?
    public fileprivate(set) var cancellationReason: DNSAttemptCancellationReason?
    public fileprivate(set) var firstCancellationRequest: DNSConnectionAttemptObservation?
    public fileprivate(set) var observations: [DNSConnectionAttemptObservation]
    public fileprivate(set) var omittedObservations: UInt64
    fileprivate var observedEventCount: UInt64
    fileprivate var firstErrorSequence: UInt64?
    fileprivate var firstErrorBeforeCancellationSequence: UInt64?
    fileprivate let started: UInt64
}

final class DNSQueryExchangeTrace {
    let id: UUID
    private weak var diagnostics: NetworkPerformanceDiagnostics?
    private let context: DNSQueryExecutionContext?
    private let progressLock = NSLock()
    private var progressAttemptID: UUID
    fileprivate init(id: UUID, diagnostics: NetworkPerformanceDiagnostics, context: DNSQueryExecutionContext?) {
        self.id = id; self.diagnostics = diagnostics; self.context = context; progressAttemptID = id
    }
    func record(_ event: DNSConnectionAttemptEvent, error: Error? = nil) {
        progressLock.lock(); let attemptID = progressAttemptID; progressLock.unlock()
        context?.record(event, attemptID: attemptID)
        diagnostics?.observeDNSExchange(id, event: event, error: error)
    }
    func cancel(_ reason: DNSAttemptCancellationReason) {
        diagnostics?.observeDNSExchange(id, event: .cancelRequested, cancellationReason: reason)
    }
    func attachPhysicalAttempt(_ id: UUID) {
        progressLock.lock(); progressAttemptID = id; progressLock.unlock()
        diagnostics?.updateDNSExchange(self.id) {
            if $0.physicalAttemptIDs.count < 2 { $0.physicalAttemptIDs.append(id) }
        }
    }
    func finish(_ outcome: DNSAttemptOutcome, failureReason: String?) {
        diagnostics?.updateDNSExchange(id) { $0.outcome = outcome; $0.failureReason = failureReason }
        record(.requestFinished)
    }
    func recordQuestion(type: UInt16, ptrTargetCategory: DNSPTRTargetCategory? = nil,
                        ptrQueryKind: DNSPTRQueryKind? = nil, queryClass: UInt16? = nil,
                        flags: UInt16? = nil, bytes: Int? = nil, additionalRecordCount: UInt16? = nil) {
        diagnostics?.updateDNSExchange(id) {
            guard $0.queryType == nil else { return }
            $0.queryType = type
            if type == 12 {
                $0.ptrTargetCategory = ptrTargetCategory
                $0.ptrQueryKind = ptrQueryKind
            }
            $0.queryClass = queryClass
            $0.queryFlags = flags
            if let bytes, (12...65_535).contains(bytes) { $0.queryBytes = bytes }
            $0.queryAdditionalRecordCount = additionalRecordCount
        }
    }
    func recordLeaseIOProgress(_ sample: DNSQueryLeaseIOProgressSnapshot) {
        diagnostics?.updateDNSExchange(id) {
            let samples = $0.leaseIOProgress ?? []
            guard samples.count < 2, !samples.contains(where: { $0.ordinal == sample.ordinal }) else { return }
            $0.leaseIOProgress = samples + [sample]
        }
    }
    func recordResolverQueue(milliseconds: Double, reasons: [DNSResolverQueueReason]) {
        guard milliseconds.isFinite, milliseconds > 0, !reasons.isEmpty else { return }
        diagnostics?.updateDNSExchange(id) {
            $0.resolverQueueMilliseconds = min(60_000,
                ($0.resolverQueueMilliseconds ?? 0) + min(60_000, milliseconds))
            // Three fixed tags bound both the export and retained storage.
            let existing = $0.resolverQueueReasons ?? []
            $0.resolverQueueReasons = DNSResolverQueueReason.allCases.filter {
                existing.contains($0) || reasons.contains($0)
            }
        }
    }
    /// Only bounded counts/status and fixed internal tags enter the export.
    /// Question names, HTTP headers and response contents are never retained.
    func recordResponse(httpStatusCode: Int? = nil, responseBytes: Int? = nil,
                        dnsResponseCode: UInt8? = nil, rejection: String? = nil,
                        extendedDNSErrorCodes: [UInt16]? = nil) {
        diagnostics?.updateDNSExchange(id) {
            if let httpStatusCode, (100...599).contains(httpStatusCode) { $0.httpStatusCode = httpStatusCode }
            if let responseBytes, responseBytes >= 0 { $0.responseBytes = min(1_048_576, responseBytes) }
            if let dnsResponseCode, dnsResponseCode <= 15 { $0.dnsResponseCode = dnsResponseCode }
            if let rejection, ["httpFraming", "dnsIdentity", "streamFraming", "emptyResponse"].contains(rejection) {
                $0.responseRejection = rejection
            }
            if let codes = extendedDNSErrorCodes, !codes.isEmpty {
                var bounded: [UInt16] = []
                bounded.reserveCapacity(8)
                for code in codes where !bounded.contains(code) {
                    bounded.append(code)
                    if bounded.count == 8 { break }
                }
                $0.extendedDNSErrorCodes = bounded
            }
        }
    }
}

/// These are observed stream stages, not a claim that an encrypted application
/// request can be decoded into HTTP timings. Connection setup includes native
/// TCP/TLS and proxy handshakes. First-byte timing starts with the first payload
/// send after that setup and ends with the first nonempty payload receive.
public enum NetworkPerformanceStage: String, CaseIterable, Hashable {
    /// CPU-side policy preparation, including refusals; no network I/O.
    case dnsPolicyPreparation
    case dnsResolution
    /// Actual local connection-pool waiting only; admission succeeds without
    /// claiming the DNS exchange itself succeeded. Original deadlines apply.
    case dnsResolverQueue
    /// Routed encrypted DNS only: transport/proxy setup, then inner TLS.
    /// These are distinct from the application connection's aggregate.
    case dnsUpstreamConnection
    case dnsTLSHandshake
    /// Background connection/TLS preparation; never a DNS-query success.
    case dnsConnectionPrewarm
    /// One encrypted phase, including its bounded failover attempts, then
    /// the opt-in proxy-only plaintext phase. Neither adds a logical query.
    case dnsEncryptedPhase
    case dnsProxyFallbackPhase
    /// Opt-in proxy TCP DNS only: a fresh proxy transport, then one framed
    /// DNS exchange. Reused connections do not repeat connection timing.
    case dnsProxyFallbackConnection
    case dnsProxyFallbackExchange
    case nodeResolution
    case connectionSetup
    case firstByte
    case probeFirstByte
}

/// A cancellation or policy/interface revocation is not evidence that the
/// network failed. It remains visible, without becoming a successful sample.
public enum NetworkPerformanceOutcome {
    case success
    case failure
    case cancelled
}

public struct NetworkStageSnapshot: Equatable {
    public var count: UInt64
    public var failureCount: UInt64
    public var cancellationCount: UInt64
    public var sampleCount: Int
    public var medianMilliseconds: Double?
    public var p95Milliseconds: Double?
    public var latestMilliseconds: Double?

    public init(count: UInt64 = 0, failureCount: UInt64 = 0, cancellationCount: UInt64 = 0,
                sampleCount: Int = 0,
                medianMilliseconds: Double? = nil, p95Milliseconds: Double? = nil,
                latestMilliseconds: Double? = nil) {
        self.count = count; self.failureCount = failureCount; self.cancellationCount = cancellationCount
        self.sampleCount = sampleCount
        self.medianMilliseconds = medianMilliseconds; self.p95Milliseconds = p95Milliseconds
        self.latestMilliseconds = latestMilliseconds
    }
}

public struct NetworkPerformanceSnapshot: Equatable {
    public var dnsQueries: UInt64
    public var dnsCacheHits: UInt64
    public var dnsCacheEligibleQueries: UInt64
    public var dnsCacheBypassedQueries: UInt64
    public var dnsCacheStoredResponses: UInt64
    public var dnsCacheRejectedResponses: UInt64
    public var dnsMergedQueries: UInt64
    public var dnsUpstreamAttempts: UInt64
    public var dnsFailures: UInt64
    public var dnsCancelledQueries: UInt64
    public var dnsFailureReasons: [DNSQueryFailureReason: UInt64]
    public var dnsFailovers: UInt64
    public var dnsConnectionsReused: UInt64
    public var dnsProxyFallbackAttempts: UInt64
    public var dnsProxyFallbackSuccesses: UInt64
    public var dnsProxyFallbackFailures: UInt64
    public var dnsProxyFallbackConnectionsReused: UInt64
    public var stages: [NetworkPerformanceStage: NetworkStageSnapshot]
    public var dnsConnectionAttempts: [DNSConnectionAttemptSnapshot]
    public var dnsLogicalQueries: [DNSLogicalQuerySnapshot]
    public var dnsQueryExchanges: [DNSQueryExchangeSnapshot]

    /// Application questions admitted to the routed query coordinator only;
    /// local FakeIP synthesis and policy refusals are not wire-cache lookups.
    public var cacheHitRate: Double? {
        guard dnsQueries > 0 else { return nil }
        return min(1, Double(dnsCacheHits) / Double(dnsQueries))
    }

    public init(dnsQueries: UInt64 = 0, dnsCacheHits: UInt64 = 0,
                dnsCacheEligibleQueries: UInt64 = 0, dnsCacheBypassedQueries: UInt64 = 0,
                dnsCacheStoredResponses: UInt64 = 0, dnsCacheRejectedResponses: UInt64 = 0,
                dnsMergedQueries: UInt64 = 0, dnsUpstreamAttempts: UInt64 = 0,
                dnsFailures: UInt64 = 0, dnsCancelledQueries: UInt64 = 0,
                dnsFailureReasons: [DNSQueryFailureReason: UInt64] = [:], dnsFailovers: UInt64 = 0,
                dnsConnectionsReused: UInt64 = 0,
                dnsProxyFallbackAttempts: UInt64 = 0, dnsProxyFallbackSuccesses: UInt64 = 0,
                dnsProxyFallbackFailures: UInt64 = 0,
                dnsProxyFallbackConnectionsReused: UInt64 = 0,
                stages: [NetworkPerformanceStage: NetworkStageSnapshot] = [:],
                dnsConnectionAttempts: [DNSConnectionAttemptSnapshot] = [],
                dnsLogicalQueries: [DNSLogicalQuerySnapshot] = [],
                dnsQueryExchanges: [DNSQueryExchangeSnapshot] = []) {
        self.dnsQueries = dnsQueries; self.dnsCacheHits = dnsCacheHits
        self.dnsCacheEligibleQueries = dnsCacheEligibleQueries
        self.dnsCacheBypassedQueries = dnsCacheBypassedQueries
        self.dnsCacheStoredResponses = dnsCacheStoredResponses
        self.dnsCacheRejectedResponses = dnsCacheRejectedResponses
        self.dnsMergedQueries = dnsMergedQueries; self.dnsUpstreamAttempts = dnsUpstreamAttempts
        self.dnsFailures = dnsFailures; self.dnsCancelledQueries = dnsCancelledQueries
        self.dnsFailureReasons = dnsFailureReasons; self.dnsFailovers = dnsFailovers
        self.dnsConnectionsReused = dnsConnectionsReused
        self.dnsProxyFallbackAttempts = dnsProxyFallbackAttempts
        self.dnsProxyFallbackSuccesses = dnsProxyFallbackSuccesses
        self.dnsProxyFallbackFailures = dnsProxyFallbackFailures
        self.dnsProxyFallbackConnectionsReused = dnsProxyFallbackConnectionsReused
        self.stages = stages
        self.dnsConnectionAttempts = dnsConnectionAttempts
        self.dnsLogicalQueries = dnsLogicalQueries
        self.dnsQueryExchanges = dnsQueryExchanges
    }
}

/// Process-local, bounded aggregates and connection observations. No domain names, destination addresses,
/// resolver URLs, credentials or payloads are retained or sent anywhere.
public final class NetworkPerformanceDiagnostics {
    public static let shared = NetworkPerformanceDiagnostics()

    private struct Window {
        var count: UInt64 = 0
        var failures: UInt64 = 0
        var cancellations: UInt64 = 0
        var values: [Double] = []
        var next = 0
        var latest: Double?

        mutating func observe(_ milliseconds: Double, outcome: NetworkPerformanceOutcome, limit: Int) {
            count = NetworkPerformanceDiagnostics.add(count, 1)
            if outcome != .success {
                if outcome == .failure { failures = NetworkPerformanceDiagnostics.add(failures, 1) }
                else { cancellations = NetworkPerformanceDiagnostics.add(cancellations, 1) }
                latest = nil
                return
            }
            latest = milliseconds
            if values.count < limit { values.append(milliseconds) }
            else { values[next] = milliseconds }
            next = (next + 1) % limit
        }

        var snapshot: NetworkStageSnapshot {
            let sorted = values.sorted()
            func percentile(_ proportion: Double) -> Double? {
                guard !sorted.isEmpty else { return nil }
                let index = max(0, min(sorted.count - 1,
                                      Int(ceil(Double(sorted.count) * proportion)) - 1))
                return sorted[index]
            }
            return NetworkStageSnapshot(count: count, failureCount: failures, cancellationCount: cancellations,
                sampleCount: sorted.count, medianMilliseconds: percentile(0.5),
                p95Milliseconds: percentile(0.95), latestMilliseconds: latest)
        }
    }

    private let lock = NSLock()
    private let maximumSamples: Int
    private var counters = NetworkPerformanceSnapshot()
    private var windows: [NetworkPerformanceStage: Window] = [:]
    private let maximumDNSAttempts: Int
    private var dnsAttempts: [DNSConnectionAttemptSnapshot] = []
    private var dnsAttemptSlots: [UUID: Int] = [:]
    private var nextDNSAttemptSlot = 0
    private var dnsLogicalQueries: [DNSLogicalQuerySnapshot] = []
    private var dnsLogicalQuerySlots: [UUID: Int] = [:]
    // One receipt per retained root, never a growing set of generations.
    private var dnsUpstreamStartReceipts: [UUID: (generationID: UUID, started: UInt64)] = [:]
    private var nextDNSLogicalQuerySlot = 0
    private var dnsExchanges: [DNSQueryExchangeSnapshot] = []
    private var dnsExchangeSlots: [UUID: Int] = [:]
    private var nextDNSExchangeSlot = 0

    public init(maximumSamples: Int = 128, maximumDNSAttempts: Int = 128) {
        self.maximumSamples = min(1_024, max(1, maximumSamples))
        self.maximumDNSAttempts = min(512, max(1, maximumDNSAttempts))
    }

    /// Keep up to half the existing slots for failures. A later burst of
    /// successful browsing must not erase the startup faults being diagnosed.
    /// The other slots continue rotating; no additional records are allocated.
    /// Prefer completed ordinary records over still-running work for eviction.
    private func dnsEvictionSlot(next: Int, count: Int, failed: (Int) -> Bool,
                                 finished: (Int) -> Bool) -> Int {
        let failureCount = (0..<count).reduce(0) { $0 + (failed($1) ? 1 : 0) }
        func first(where predicate: (Int) -> Bool) -> Int? {
            for offset in 0..<count {
                let slot = (next + offset) % count
                if predicate(slot) { return slot }
            }
            return nil
        }
        if failureCount > max(1, maximumDNSAttempts / 2),
           let slot = first(where: { failed($0) && finished($0) }) ?? first(where: failed) { return slot }
        if count >= 16, failureCount == max(1, maximumDNSAttempts / 2),
           first(where: { !failed($0) && finished($0) }) == nil,
           let slot = first(where: { failed($0) && finished($0) }) { return slot }
        return first { !failed($0) && finished($0) } ?? first { !failed($0) } ?? next
    }

    /// Swift's process-randomized Hasher keeps these identifiers local to this
    /// run. The unhashed endpoint, dial address and route are never retained.
    static func dnsOpaqueID(_ identity: String, prefix: String) -> String {
        var hasher = Hasher(); hasher.combine(identity)
        return prefix + "-" + String(UInt64(bitPattern: Int64(hasher.finalize())), radix: 16)
    }

    func beginDNSAttempt(requestID: UUID, transport: DNSAttemptTransport,
                         purpose: DNSAttemptPurpose, serverName: String,
                         endpointIdentity: String, address: String,
                         context: DNSQueryExecutionContext? = nil) -> DNSConnectionAttemptTrace {
        let provider: String
        switch serverName.lowercased() {
        case "cloudflare-dns.com", "one.one.one.one", "1.1.1.1", "1.0.0.1": provider = "Cloudflare"
        case "dns.google", "8.8.8.8", "8.8.4.4": provider = "Google"
        case "doh.pub", "dot.pub": provider = "DNSPod"
        case "dns.alidns.com", "223.5.5.5", "223.6.6.6": provider = "AliDNS"
        case "dns.quad9.net", "9.9.9.9": provider = "Quad9"
        default: provider = "custom"
        }
        let id = UUID()
        context?.beginConnectionAttempt(id)
        let value = DNSConnectionAttemptSnapshot(id: id, requestID: requestID,
            rootID: context?.rootID, candidateID: context?.candidateID,
            upstreamID: Self.dnsOpaqueID(endpointIdentity, prefix: "upstream"),
            addressID: Self.dnsOpaqueID(address, prefix: "address"), provider: provider,
            transport: transport, purpose: purpose, route: .unknown, routeID: nil,
            transportOutcome: nil, tlsOutcome: nil, requestFinished: false, firstError: nil,
            firstErrorBeforeCancellation: nil,
            firstCarrierClosure: nil, firstLocalCancellation: nil, firstCancellationRequest: nil,
            cancellationReason: nil, observations: [], omittedObservations: 0,
            observedEventCount: 0, firstErrorSequence: nil, firstErrorBeforeCancellationSequence: nil,
            started: Self.now())
        lock.lock()
        let slot: Int
        if dnsAttempts.count < maximumDNSAttempts {
            slot = dnsAttempts.count; dnsAttempts.append(value)
        } else {
            slot = dnsEvictionSlot(next: nextDNSAttemptSlot, count: dnsAttempts.count,
                failed: { self.dnsAttempts[$0].firstErrorBeforeCancellation != nil
                    || self.dnsAttempts[$0].transportOutcome == .failure || self.dnsAttempts[$0].tlsOutcome == .failure },
                finished: { self.dnsAttempts[$0].requestFinished })
            dnsAttemptSlots.removeValue(forKey: dnsAttempts[slot].id)
            dnsAttempts[slot] = value
        }
        dnsAttemptSlots[id] = slot
        nextDNSAttemptSlot = (slot + 1) % maximumDNSAttempts
        lock.unlock()
        return DNSConnectionAttemptTrace(id: id, diagnostics: self, context: context)
    }

    fileprivate func updateDNSAttempt(_ id: UUID, update: (inout DNSConnectionAttemptSnapshot) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard let slot = dnsAttemptSlots[id] else { return }
        update(&dnsAttempts[slot])
    }

    fileprivate func observeDNSAttempt(_ id: UUID, event: DNSConnectionAttemptEvent,
                                      error: Error? = nil,
                                      cancellationReason: DNSAttemptCancellationReason? = nil,
                                      peerCiphertextBytes: UInt64? = nil,
                                      admitting: (() -> Void)? = nil) {
        var sequence: UInt64?
        updateDNSAttempt(id) { attempt in
            sequence = attempt.observedEventCount
            attempt.observedEventCount = Self.add(attempt.observedEventCount, 1)
            if event == .requestFinished { attempt.requestFinished = true }
            if attempt.cancellationReason == nil { attempt.cancellationReason = cancellationReason }
            let observation = DNSConnectionAttemptObservation(sequence: sequence!, event: event,
                milliseconds: Self.elapsedMilliseconds(since: attempt.started),
                error: nil, cancellationReason: cancellationReason, peerCiphertextBytes: peerCiphertextBytes)
            if attempt.firstCarrierClosure == nil,
               [.rawEOF, .rawFailure, .rawWriteFailure, .bridgeEOF, .bridgeFailure, .localCancel].contains(event) {
                attempt.firstCarrierClosure = observation
            }
            if attempt.firstLocalCancellation == nil, event == .localCancel { attempt.firstLocalCancellation = observation }
            if attempt.firstCancellationRequest == nil, event == .cancelRequested { attempt.firstCancellationRequest = observation }
            // Keep the beginning and latest event when a noisy stream exceeds
            // its limit; firstError/cancellationReason are retained separately.
            if attempt.observations.count < 24 { attempt.observations.append(observation) }
            else {
                attempt.observations[23] = observation
                attempt.omittedObservations = Self.add(attempt.omittedObservations, 1)
            }
        }
        // Reserve order/time first, then admit the failure to its existing
        // security sink before any potentially slow Error -> NSError bridge.
        // Neither callback runs while the diagnostics lock is held.
        admitting?()
        guard let sequence, let error else { return }
        let captured = DNSAttemptErrorSnapshot.capture(error)
        updateDNSAttempt(id) { attempt in
            if let slot = attempt.observations.firstIndex(where: { $0.sequence == sequence }) {
                attempt.observations[slot].error = captured
            }
            if captured.category != "cancelled", sequence < (attempt.firstErrorSequence ?? UInt64.max) {
                attempt.firstError = captured; attempt.firstErrorSequence = sequence
            }
            let cancellationSequence = min(attempt.firstCancellationRequest?.sequence ?? UInt64.max,
                                           attempt.firstLocalCancellation?.sequence ?? UInt64.max)
            if captured.category != "cancelled", sequence < cancellationSequence,
               sequence < (attempt.firstErrorBeforeCancellationSequence ?? UInt64.max) {
                attempt.firstErrorBeforeCancellation = captured
                attempt.firstErrorBeforeCancellationSequence = sequence
            }
            if attempt.firstCarrierClosure?.sequence == sequence { attempt.firstCarrierClosure?.error = captured }
            if attempt.firstLocalCancellation?.sequence == sequence { attempt.firstLocalCancellation?.error = captured }
            if attempt.firstCancellationRequest?.sequence == sequence { attempt.firstCancellationRequest?.error = captured }
        }
    }

    func beginDNSQuery(rootID: UUID, waiterID: UUID, started: UInt64,
                       absoluteDeadline: TimeInterval) {
        guard absoluteDeadline.isFinite else { return }
        let waiter = DNSLogicalQueryWaiterSnapshot(waiterID: waiterID, startedUptimeNanoseconds: started,
            absoluteDeadlineUptime: absoluteDeadline, outcome: nil, failureReason: nil, milliseconds: nil)
        let value = DNSLogicalQuerySnapshot(rootID: rootID, waiters: [waiter], admittedCount: 1,
            mergedCount: 0, finishedCount: 0, outcomeCounts: [:], failureCounts: [:], omittedWaiters: 0,
            scheduling: nil, started: started)
        lock.lock(); defer { lock.unlock() }
        guard dnsLogicalQuerySlots[rootID] == nil else { return }
        let slot: Int
        if dnsLogicalQueries.count < maximumDNSAttempts {
            slot = dnsLogicalQueries.count; dnsLogicalQueries.append(value)
        } else {
            slot = dnsEvictionSlot(next: nextDNSLogicalQuerySlot, count: dnsLogicalQueries.count,
                failed: { self.dnsLogicalQueries[$0].outcomeCounts[DNSAttemptOutcome.failure.rawValue, default: 0] > 0 },
                finished: { self.dnsLogicalQueries[$0].finishedCount >= self.dnsLogicalQueries[$0].admittedCount })
            let evictedRoot = dnsLogicalQueries[slot].rootID
            dnsLogicalQuerySlots.removeValue(forKey: evictedRoot)
            dnsUpstreamStartReceipts.removeValue(forKey: evictedRoot)
            dnsLogicalQueries[slot] = value
        }
        dnsLogicalQuerySlots[rootID] = slot
        nextDNSLogicalQuerySlot = (slot + 1) % maximumDNSAttempts
    }

    /// The serial coordinator pump submits one immutable receipt immediately
    /// before invoking each generation's upstream factory. Replays use the
    /// original timestamps: the latest token rejects duplicates of that
    /// generation, and its monotonic start fences earlier-generation replays.
    /// This does not count another application query, waiter or failure.
    func recordDNSUpstreamStart(rootID: UUID, generationID: UUID,
                                queuedAt: UInt64, started: UInt64) {
        guard started >= queuedAt else { return }
        lock.lock(); defer { lock.unlock() }
        guard let slot = dnsLogicalQuerySlots[rootID] else { return }
        if let receipt = dnsUpstreamStartReceipts[rootID] {
            guard generationID != receipt.generationID, started > receipt.started else { return }
        }
        let queueMilliseconds = Self.elapsedMilliseconds(since: queuedAt, at: started)
        if var scheduling = dnsLogicalQueries[slot].scheduling {
            scheduling.latestUpstreamStartedUptimeNanoseconds = started
            scheduling.upstreamStartCount = Self.add(scheduling.upstreamStartCount, 1)
            scheduling.maximumCoordinatorQueueMilliseconds = max(
                scheduling.maximumCoordinatorQueueMilliseconds, queueMilliseconds)
            dnsLogicalQueries[slot].scheduling = scheduling
        } else {
            dnsLogicalQueries[slot].scheduling = DNSLogicalQuerySchedulingSnapshot(
                firstUpstreamStartedUptimeNanoseconds: started,
                latestUpstreamStartedUptimeNanoseconds: started,
                upstreamStartCount: 1, firstCoordinatorQueueMilliseconds: queueMilliseconds,
                maximumCoordinatorQueueMilliseconds: queueMilliseconds)
        }
        dnsUpstreamStartReceipts[rootID] = (generationID, started)
    }

    func joinDNSQuery(rootID: UUID, waiterID: UUID, started: UInt64,
                      absoluteDeadline: TimeInterval) {
        guard absoluteDeadline.isFinite else { return }
        lock.lock(); defer { lock.unlock() }
        guard let slot = dnsLogicalQuerySlots[rootID] else { return }
        guard !dnsLogicalQueries[slot].waiters.contains(where: { $0.waiterID == waiterID }) else { return }
        dnsLogicalQueries[slot].admittedCount = Self.add(dnsLogicalQueries[slot].admittedCount, 1)
        dnsLogicalQueries[slot].mergedCount = Self.add(dnsLogicalQueries[slot].mergedCount, 1)
        if dnsLogicalQueries[slot].waiters.count < 64 {
            dnsLogicalQueries[slot].waiters.append(DNSLogicalQueryWaiterSnapshot(waiterID: waiterID,
                startedUptimeNanoseconds: started, absoluteDeadlineUptime: absoluteDeadline,
                outcome: nil, failureReason: nil, milliseconds: nil))
        } else { dnsLogicalQueries[slot].omittedWaiters = Self.add(dnsLogicalQueries[slot].omittedWaiters, 1) }
    }

    /// The coordinator owns each waiter's at-most-once admission/completion.
    /// Retained waiters are also fenced here; omitted waiters do not create an
    /// unbounded UUID set merely for diagnostics.
    func finishDNSQueryWaiter(rootID: UUID, waiterID: UUID, outcome: NetworkPerformanceOutcome,
                              failureReason: DNSQueryFailureReason?, milliseconds: Double) {
        guard milliseconds.isFinite, milliseconds >= 0 else { return }
        let value: DNSAttemptOutcome = outcome == .success ? .success : (outcome == .failure ? .failure : .cancelled)
        lock.lock(); defer { lock.unlock() }
        guard let slot = dnsLogicalQuerySlots[rootID] else { return }
        if let index = dnsLogicalQueries[slot].waiters.firstIndex(where: { $0.waiterID == waiterID }) {
            guard dnsLogicalQueries[slot].waiters[index].outcome == nil else { return }
            dnsLogicalQueries[slot].waiters[index].outcome = value
            dnsLogicalQueries[slot].waiters[index].failureReason = failureReason?.rawValue
            dnsLogicalQueries[slot].waiters[index].milliseconds = milliseconds
        } else if dnsLogicalQueries[slot].omittedWaiters == 0 { return }
        dnsLogicalQueries[slot].finishedCount = Self.add(dnsLogicalQueries[slot].finishedCount, 1)
        let count = dnsLogicalQueries[slot].outcomeCounts[value.rawValue, default: 0]
        dnsLogicalQueries[slot].outcomeCounts[value.rawValue] = Self.add(count, 1)
        if let failureReason, value == .failure {
            let count = dnsLogicalQueries[slot].failureCounts[failureReason.rawValue, default: 0]
            dnsLogicalQueries[slot].failureCounts[failureReason.rawValue] = Self.add(count, 1)
        }
    }

    func beginDNSExchange(requestID: UUID, context: DNSQueryExecutionContext?,
                          transport: DNSAttemptTransport, endpointIdentity: String) -> DNSQueryExchangeTrace {
        let id = UUID()
        context?.beginConnectionAttempt(id)
        let value = DNSQueryExchangeSnapshot(id: id, requestID: requestID, rootID: context?.rootID,
            candidateID: context?.candidateID, upstreamID: Self.dnsOpaqueID(endpointIdentity, prefix: "upstream"),
            transport: transport, physicalAttemptIDs: [], reusedConnection: false,
            outcome: nil, failureReason: nil, httpStatusCode: nil, responseBytes: nil,
            dnsResponseCode: nil, responseRejection: nil, queryType: nil, ptrTargetCategory: nil,
            ptrQueryKind: nil, queryClass: nil, queryFlags: nil, queryBytes: nil,
            queryAdditionalRecordCount: nil, leaseIOProgress: nil,
            extendedDNSErrorCodes: nil,
            resolverQueueMilliseconds: nil, resolverQueueReasons: nil,
            firstError: nil, firstErrorBeforeCancellation: nil,
            cancellationReason: nil, firstCancellationRequest: nil,
            observations: [], omittedObservations: 0,
            observedEventCount: 0, firstErrorSequence: nil, firstErrorBeforeCancellationSequence: nil,
            started: Self.now())
        lock.lock()
        let slot: Int
        if dnsExchanges.count < maximumDNSAttempts { slot = dnsExchanges.count; dnsExchanges.append(value) }
        else {
            slot = dnsEvictionSlot(next: nextDNSExchangeSlot, count: dnsExchanges.count,
                failed: { self.dnsExchanges[$0].outcome == .failure
                    || self.dnsExchanges[$0].dnsResponseCode.map { ![UInt8(0), 3].contains($0) } == true },
                finished: { self.dnsExchanges[$0].outcome != nil })
            dnsExchangeSlots.removeValue(forKey: dnsExchanges[slot].id)
            dnsExchanges[slot] = value
        }
        dnsExchangeSlots[id] = slot
        nextDNSExchangeSlot = (slot + 1) % maximumDNSAttempts
        lock.unlock()
        return DNSQueryExchangeTrace(id: id, diagnostics: self, context: context)
    }

    fileprivate func updateDNSExchange(_ id: UUID, update: (inout DNSQueryExchangeSnapshot) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard let slot = dnsExchangeSlots[id] else { return }
        update(&dnsExchanges[slot])
    }

    fileprivate func observeDNSExchange(_ id: UUID, event: DNSConnectionAttemptEvent,
                                        error: Error? = nil,
                                        cancellationReason: DNSAttemptCancellationReason? = nil) {
        var sequence: UInt64?
        updateDNSExchange(id) { exchange in
            sequence = exchange.observedEventCount
            let observation = DNSConnectionAttemptObservation(sequence: exchange.observedEventCount,
                event: event, milliseconds: Self.elapsedMilliseconds(since: exchange.started),
                error: nil, cancellationReason: cancellationReason, peerCiphertextBytes: nil)
            exchange.observedEventCount = Self.add(exchange.observedEventCount, 1)
            if exchange.cancellationReason == nil { exchange.cancellationReason = cancellationReason }
            if exchange.firstCancellationRequest == nil, event == .cancelRequested {
                exchange.firstCancellationRequest = observation
            }
            if event == .connectionReused { exchange.reusedConnection = true }
            if exchange.observations.count < 24 { exchange.observations.append(observation) }
            else {
                exchange.observations[23] = observation
                exchange.omittedObservations = Self.add(exchange.omittedObservations, 1)
            }
        }
        guard let sequence, let error else { return }
        let captured = DNSAttemptErrorSnapshot.capture(error)
        updateDNSExchange(id) { exchange in
            if let slot = exchange.observations.firstIndex(where: { $0.sequence == sequence }) {
                exchange.observations[slot].error = captured
            }
            if captured.category != "cancelled", sequence < (exchange.firstErrorSequence ?? UInt64.max) {
                exchange.firstError = captured; exchange.firstErrorSequence = sequence
            }
            if captured.category != "cancelled",
               sequence < (exchange.firstCancellationRequest?.sequence ?? UInt64.max),
               sequence < (exchange.firstErrorBeforeCancellationSequence ?? UInt64.max) {
                exchange.firstErrorBeforeCancellation = captured
                exchange.firstErrorBeforeCancellationSequence = sequence
            }
        }
    }

    public static func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    public static func elapsedMilliseconds(since started: UInt64, at now: UInt64 = now()) -> Double {
        guard now >= started else { return 0 }
        return Double(now - started) / 1_000_000
    }

    public func record(_ stage: NetworkPerformanceStage, milliseconds: Double, success: Bool = true) {
        record(stage, milliseconds: milliseconds, outcome: success ? .success : .failure)
    }

    public func record(_ stage: NetworkPerformanceStage, milliseconds: Double,
                       outcome: NetworkPerformanceOutcome) {
        // A bad injected clock must not poison summaries or JSON serialization.
        guard milliseconds.isFinite, milliseconds >= 0 else { return }
        lock.lock(); defer { lock.unlock() }
        windows[stage, default: Window()].observe(milliseconds, outcome: outcome, limit: maximumSamples)
    }

    public func recordDNS(_ event: DNSPerformanceEvent, count: Int = 1) {
        guard count > 0 else { return }
        lock.lock(); defer { lock.unlock() }
        let amount = UInt64(count)
        switch event {
        case .query: counters.dnsQueries = Self.add(counters.dnsQueries, amount)
        case .cacheHit: counters.dnsCacheHits = Self.add(counters.dnsCacheHits, amount)
        case .cacheEligible: counters.dnsCacheEligibleQueries = Self.add(counters.dnsCacheEligibleQueries, amount)
        case .cacheBypassed: counters.dnsCacheBypassedQueries = Self.add(counters.dnsCacheBypassedQueries, amount)
        case .cacheStore: counters.dnsCacheStoredResponses = Self.add(counters.dnsCacheStoredResponses, amount)
        case .cacheStoreRejected: counters.dnsCacheRejectedResponses = Self.add(counters.dnsCacheRejectedResponses, amount)
        case .merged: counters.dnsMergedQueries = Self.add(counters.dnsMergedQueries, amount)
        case .upstreamAttempt: counters.dnsUpstreamAttempts = Self.add(counters.dnsUpstreamAttempts, amount)
        case .failure: addDNSFailure(.upstreamOrResponse, amount: amount)
        case .cancelled: counters.dnsCancelledQueries = Self.add(counters.dnsCancelledQueries, amount)
        case .failover: counters.dnsFailovers = Self.add(counters.dnsFailovers, amount)
        case .connectionReuse: counters.dnsConnectionsReused = Self.add(counters.dnsConnectionsReused, amount)
        case .proxyFallbackAttempt: counters.dnsProxyFallbackAttempts = Self.add(counters.dnsProxyFallbackAttempts, amount)
        case .proxyFallbackSuccess: counters.dnsProxyFallbackSuccesses = Self.add(counters.dnsProxyFallbackSuccesses, amount)
        case .proxyFallbackFailure: counters.dnsProxyFallbackFailures = Self.add(counters.dnsProxyFallbackFailures, amount)
        case .proxyFallbackConnectionReuse:
            counters.dnsProxyFallbackConnectionsReused = Self.add(counters.dnsProxyFallbackConnectionsReused, amount)
        }
    }

    public func recordDNSFailure(_ reason: DNSQueryFailureReason, count: Int = 1) {
        guard count > 0 else { return }
        lock.lock(); defer { lock.unlock() }
        addDNSFailure(reason, amount: UInt64(count))
    }

    /// Caller holds the aggregate lock, so the total and reasons stay coherent.
    private func addDNSFailure(_ reason: DNSQueryFailureReason, amount: UInt64) {
        counters.dnsFailures = Self.add(counters.dnsFailures, amount)
        counters.dnsFailureReasons[reason] = Self.add(counters.dnsFailureReasons[reason, default: 0], amount)
    }

    public func snapshot() -> NetworkPerformanceSnapshot {
        lock.lock(); defer { lock.unlock() }
        var result = counters
        result.stages = windows.mapValues(\.snapshot)
        result.dnsConnectionAttempts = dnsAttempts.sorted { $0.started < $1.started }
        result.dnsLogicalQueries = dnsLogicalQueries.sorted { $0.started < $1.started }
        result.dnsQueryExchanges = dnsExchanges.sorted { $0.started < $1.started }
        return result
    }

    public func reset() {
        lock.lock()
        counters = NetworkPerformanceSnapshot(); windows.removeAll()
        dnsAttempts.removeAll(); dnsAttemptSlots.removeAll(); nextDNSAttemptSlot = 0
        dnsLogicalQueries.removeAll(); dnsLogicalQuerySlots.removeAll(); nextDNSLogicalQuerySlot = 0
        dnsUpstreamStartReceipts.removeAll()
        dnsExchanges.removeAll(); dnsExchangeSlots.removeAll(); nextDNSExchangeSlot = 0
        lock.unlock()
    }

    private static func add(_ value: UInt64, _ amount: UInt64) -> UInt64 {
        let (sum, overflow) = value.addingReportingOverflow(amount)
        return overflow ? UInt64.max : sum
    }
}

public enum NetworkPerformanceDiagnosticsSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "性能诊断自检失败：\(text)" }
    }
    private struct DelayedError: CustomNSError {
        let entered: DispatchSemaphore
        let release: DispatchSemaphore
        static var errorDomain: String { NSPOSIXErrorDomain }
        var errorCode: Int { Int(ECONNRESET) }
        var errorUserInfo: [String: Any] {
            entered.signal(); _ = release.wait(timeout: .now() + 2)
            return [NSLocalizedDescriptionKey: "private-error-text"]
        }
    }

    public static func run() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        let diagnostics = NetworkPerformanceDiagnostics(maximumSamples: 4)
        try require(diagnostics.snapshot().cacheHitRate == nil, "无样本不得显示虚假的零命中率")
        diagnostics.recordDNS(.query, count: 10)
        diagnostics.recordDNS(.cacheHit, count: 6)
        diagnostics.recordDNS(.cacheEligible, count: 8)
        diagnostics.recordDNS(.cacheBypassed, count: 2)
        diagnostics.recordDNS(.cacheStore, count: 3)
        diagnostics.recordDNS(.cacheStoreRejected)
        diagnostics.recordDNS(.merged, count: 2)
        diagnostics.recordDNS(.query, count: -1)
        for value in 1...6 { diagnostics.record(.dnsResolution, milliseconds: Double(value)) }
        diagnostics.record(.dnsResolution, milliseconds: 200, success: false)
        diagnostics.record(.dnsResolution, milliseconds: 300, outcome: .cancelled)
        diagnostics.recordDNS(.cancelled, count: 3)
        diagnostics.recordDNSFailure(.timeout, count: 2)
        diagnostics.recordDNS(.failure)
        diagnostics.recordDNSFailure(.capacity)
        diagnostics.record(.dnsResolution, milliseconds: .nan)
        diagnostics.record(.dnsResolution, milliseconds: -.infinity)
        diagnostics.record(.dnsResolution, milliseconds: -1)
        let snapshot = diagnostics.snapshot()
        let stage = snapshot.stages[.dnsResolution]!
        try require(snapshot.dnsQueries == 10 && snapshot.dnsCacheHits == 6
                    && snapshot.dnsMergedQueries == 2 && snapshot.cacheHitRate == 0.6,
                    "DNS 聚合计数或命中率不正确")
        try require(snapshot.dnsCacheEligibleQueries == 8 && snapshot.dnsCacheBypassedQueries == 2
                    && snapshot.dnsCacheStoredResponses == 3 && snapshot.dnsCacheRejectedResponses == 1,
                    "缓存资格、旁路或响应存储计数丢失")
        try require(stage.count == 8 && stage.failureCount == 1 && stage.cancellationCount == 1
                    && stage.sampleCount == 4
                    && stage.medianMilliseconds == 4 && stage.p95Milliseconds == 6
                    && stage.latestMilliseconds == nil, "有界窗口或失败样本语义错误")
        try require(snapshot.dnsCancelledQueries == 3 && snapshot.dnsFailures == 4
                    && snapshot.dnsFailureReasons == [.upstreamOrResponse: 1, .timeout: 2, .capacity: 1],
                    "真实 DNS 失败分类或取消计数被丢弃、混作成功/失败")
        try require(NetworkPerformanceDiagnostics.elapsedMilliseconds(since: 10, at: 9) == 0,
                    "时钟回退导致负延迟")
        try require(NetworkPerformanceDiagnostics.elapsedMilliseconds(since: 0, at: 1_500_000) == 1.5,
                    "单调时钟换算错误")
        for stage in [NetworkPerformanceStage.dnsPolicyPreparation, .dnsResolverQueue, .dnsUpstreamConnection, .dnsTLSHandshake, .dnsConnectionPrewarm,
                      .dnsEncryptedPhase, .dnsProxyFallbackPhase,
                      .dnsProxyFallbackConnection, .dnsProxyFallbackExchange] {
            diagnostics.record(stage, milliseconds: 2)
            diagnostics.record(stage, milliseconds: 7, outcome: .failure)
            diagnostics.record(stage, milliseconds: 9, outcome: .cancelled)
            let measured = diagnostics.snapshot().stages[stage]
            try require(measured?.count == 3 && measured?.failureCount == 1
                        && measured?.cancellationCount == 1 && measured?.sampleCount == 1
                        && measured?.medianMilliseconds == 2 && measured?.p95Milliseconds == 2,
                        "DNS 规则/通道/TLS 阶段被混入解析或失败分位数")
        }
        diagnostics.recordDNS(.proxyFallbackAttempt, count: 3)
        diagnostics.recordDNS(.proxyFallbackSuccess)
        diagnostics.recordDNS(.proxyFallbackFailure)
        diagnostics.recordDNS(.proxyFallbackConnectionReuse, count: 2)
        let fallback = diagnostics.snapshot()
        try require(fallback.dnsProxyFallbackAttempts == 3 && fallback.dnsProxyFallbackSuccesses == 1
                    && fallback.dnsProxyFallbackFailures == 1 && fallback.dnsQueries == 10
                    && fallback.dnsFailures == 4 && fallback.dnsProxyFallbackConnectionsReused == 2,
                    "回退尝试或连接复用混入逻辑 DNS 查询/失败统计")
        diagnostics.reset()
        try require(diagnostics.snapshot() == NetworkPerformanceSnapshot(), "重置未清空全部聚合数据")

        let group = DispatchGroup()
        for _ in 0..<8 {
            group.enter()
            DispatchQueue.global().async {
                for _ in 0..<500 {
                    diagnostics.recordDNS(.query)
                    diagnostics.record(.connectionSetup, milliseconds: 1)
                }
                group.leave()
            }
        }
        try require(group.wait(timeout: .now() + 5) == .success, "并发聚合超时")
        let concurrent = diagnostics.snapshot()
        try require(concurrent.dnsQueries == 4_000
                    && concurrent.stages[.connectionSetup]?.count == 4_000
                    && concurrent.stages[.connectionSetup]?.sampleCount == 4, "并发聚合丢失计数或越界")
        try connectionAttemptRecords()
        try logicalSchedulingRecords()
        try resolverQueueRecords()
    }

    private static func resolverQueueRecords() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        let diagnostics = NetworkPerformanceDiagnostics(maximumDNSAttempts: 1)
        let context = DNSQueryExecutionContext()
        let trace = diagnostics.beginDNSExchange(requestID: UUID(), context: context, transport: .doh,
            endpointIdentity: "https://private-queue.invalid/secret")
        trace.recordResolverQueue(milliseconds: 0, reasons: [.coldConnectionLimit])
        trace.recordResolverQueue(milliseconds: .nan, reasons: [.queryLimit])
        trace.recordResolverQueue(milliseconds: -1, reasons: [.physicalConnectionLimit])
        try require(diagnostics.snapshot().dnsQueryExchanges[0].resolverQueueMilliseconds == nil,
                    "无实际等待或非法时间虚构了连接排队样本")
        trace.record(.resolverQueued)
        trace.recordResolverQueue(milliseconds: 12, reasons: [.coldConnectionLimit, .coldConnectionLimit])
        trace.record(.resolverAdmitted)
        trace.recordResolverQueue(milliseconds: 8, reasons: [.queryLimit])
        let snapshot = diagnostics.snapshot(), exchange = snapshot.dnsQueryExchanges[0]
        try require(exchange.resolverQueueMilliseconds == 20
                    && exchange.resolverQueueReasons == [.queryLimit, .coldConnectionLimit],
                    "重试的连接等待未累计或原因未去重")
        try require(context.progress().stage == .notStarted && snapshot.dnsFailures == 0
                    && snapshot.dnsUpstreamAttempts == 0 && snapshot.stages.isEmpty,
                    "本地连接排队被当成实际 I/O、解析器故障或网络阶段成功")
        let data = try JSONEncoder().encode(exchange)
        let encoded = String(data: data, encoding: .utf8)!
        try require(!encoded.contains("private-queue") && !encoded.contains("secret"),
                    "连接排队导出泄漏了端点身份")
        var legacy = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        legacy.removeValue(forKey: "resolverQueueMilliseconds")
        legacy.removeValue(forKey: "resolverQueueReasons")
        let old = try JSONDecoder().decode(DNSQueryExchangeSnapshot.self,
            from: JSONSerialization.data(withJSONObject: legacy))
        try require(old.resolverQueueMilliseconds == nil && old.resolverQueueReasons == nil,
                    "新增连接排队字段无法解码旧 schema-2 交换")
        for _ in 0..<100 {
            trace.recordResolverQueue(milliseconds: 60_000, reasons: DNSResolverQueueReason.allCases)
        }
        let bounded = diagnostics.snapshot().dnsQueryExchanges[0]
        try require(bounded.resolverQueueMilliseconds == 60_000
                    && bounded.resolverQueueReasons?.count == 3, "连接排队明细未限制大小")
        _ = diagnostics.beginDNSExchange(requestID: UUID(), context: nil, transport: .dot,
            endpointIdentity: "replacement")
        trace.recordResolverQueue(milliseconds: 100, reasons: [.coldConnectionLimit])
        try require(diagnostics.snapshot().dnsQueryExchanges[0].resolverQueueMilliseconds == nil,
                    "迟到排队回执复活或改写了另一轮交换")
        let carrier = DNSAttemptErrorSnapshot.capture(NSError(domain: "app.hajimi.nested-tls-carrier", code: 2))
        try require(carrier.category == "carrierClosedBeforeTLS"
                    && carrier.codes == [DNSAttemptErrorCode(domain: "app.hajimi.nested-tls-carrier", code: 2)],
                    "零 TLS 密文关闭被诊断为证书失败或丢失原始错误码")
    }

    private static func logicalSchedulingRecords() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        let diagnostics = NetworkPerformanceDiagnostics(maximumDNSAttempts: 2)
        let root = UUID(), leader = UUID(), firstGeneration = UUID(), secondGeneration = UUID()
        diagnostics.beginDNSQuery(rootID: root, waiterID: leader, started: 1_000_000, absoluteDeadline: 10)
        try require(diagnostics.snapshot().dnsLogicalQueries[0].scheduling == nil,
                    "尚未启动上游的根查询虚构了调度收据")
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: firstGeneration,
            queuedAt: 2_000_000, started: 2_000_000)
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: firstGeneration,
            queuedAt: 2_000_000, started: 2_000_000)
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: firstGeneration,
            queuedAt: 2_000_000, started: 3_000_000)
        let immediate = diagnostics.snapshot().dnsLogicalQueries[0].scheduling
        try require(immediate?.upstreamStartCount == 1
                    && immediate?.firstUpstreamStartedUptimeNanoseconds == 2_000_000
                    && immediate?.latestUpstreamStartedUptimeNanoseconds == 2_000_000
                    && immediate?.firstCoordinatorQueueMilliseconds == 0
                    && immediate?.maximumCoordinatorQueueMilliseconds == 0,
                    "零排队被丢失或同一上游代际被重复计数")
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: secondGeneration,
            queuedAt: 3_000_000, started: 5_500_000)
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: firstGeneration,
            queuedAt: 2_000_000, started: 2_000_000)
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: UUID(),
            queuedAt: 7_000_000, started: 6_000_000)
        let queued = diagnostics.snapshot().dnsLogicalQueries[0].scheduling
        try require(queued?.upstreamStartCount == 2
                    && queued?.firstUpstreamStartedUptimeNanoseconds == 2_000_000
                    && queued?.latestUpstreamStartedUptimeNanoseconds == 5_500_000
                    && queued?.firstCoordinatorQueueMilliseconds == 0
                    && queued?.maximumCoordinatorQueueMilliseconds == 2.5,
                    "新代际丢失正排队耗时或旧代际回放改写了摘要")
        // A follower generation retains its root and waiter accounting.
        let follower = UUID()
        diagnostics.joinDNSQuery(rootID: root, waiterID: follower, started: 6_000_000, absoluteDeadline: 12)
        diagnostics.finishDNSQueryWaiter(rootID: root, waiterID: leader, outcome: .failure,
            failureReason: .timeout, milliseconds: 8)
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: UUID(),
            queuedAt: 7_000_000, started: 8_000_000)
        diagnostics.finishDNSQueryWaiter(rootID: root, waiterID: follower, outcome: .success,
            failureReason: nil, milliseconds: 3)
        let followed = diagnostics.snapshot().dnsLogicalQueries[0]
        try require(followed.rootID == root && followed.scheduling?.upstreamStartCount == 3
                    && followed.admittedCount == 2 && followed.mergedCount == 1
                    && followed.finishedCount == 2 && followed.outcomeCounts == ["failure": 1, "success": 1],
                    "延续根查询的上游代际重复了等待者或丢失了最终结果")
        for index in 1...256 {
            let now = UInt64(8_000_000 + index)
            diagnostics.recordDNSUpstreamStart(rootID: root, generationID: UUID(), queuedAt: now, started: now)
        }
        let many = diagnostics.snapshot()
        let rootData = try JSONEncoder().encode(many.dnsLogicalQueries[0])
        let encodedRoot = try JSONSerialization.jsonObject(with: rootData) as! [String: Any]
        let encodedScheduling = encodedRoot["scheduling"] as? [String: Any]
        try require(many.dnsLogicalQueries.count == 1
                    && many.dnsLogicalQueries[0].scheduling?.upstreamStartCount == 259
                    && encodedScheduling?.count == 5
                    && many.dnsQueries == 0 && many.dnsFailures == 0 && many.dnsUpstreamAttempts == 0,
                    "调度代际记录无界或额外计入应用查询/上游/失败次数")
        var legacyRoot = encodedRoot
        legacyRoot.removeValue(forKey: "scheduling")
        let legacyData = try JSONSerialization.data(withJSONObject: legacyRoot)
        try require(try JSONDecoder().decode(DNSLogicalQuerySnapshot.self, from: legacyData).scheduling == nil,
                    "新增调度字段无法兼容旧 schema-2 逻辑查询")
        // Exchange eviction cannot erase this retained root's queue evidence.
        for _ in 0..<3 {
            _ = diagnostics.beginDNSExchange(requestID: UUID(), context: nil, transport: .doh,
                endpointIdentity: "scheduling-self-test")
        }
        try require(diagnostics.snapshot().dnsQueryExchanges.count == 2
                    && diagnostics.snapshot().dnsLogicalQueries[0].scheduling == many.dnsLogicalQueries[0].scheduling,
                    "交换环淘汰清除了仍保留根查询的调度证据")
        for index in 1...2 {
            diagnostics.beginDNSQuery(rootID: UUID(), waiterID: UUID(),
                started: UInt64(10_000_000 + index), absoluteDeadline: 12)
        }
        try require(diagnostics.snapshot().dnsLogicalQueries.contains(where: { $0.rootID == root }),
                    "成功／未完成记录挤出了仍需诊断的早期失败")
        // A newer failure can replace the protected old failure. A later
        // receipt still cannot recreate it after that actual eviction.
        let newerRoot = UUID(), newerWaiter = UUID()
        diagnostics.beginDNSQuery(rootID: newerRoot, waiterID: newerWaiter,
            started: 11_000_000, absoluteDeadline: 12)
        diagnostics.finishDNSQueryWaiter(rootID: newerRoot, waiterID: newerWaiter,
            outcome: .failure, failureReason: .timeout, milliseconds: 1)
        diagnostics.beginDNSQuery(rootID: UUID(), waiterID: UUID(), started: 11_500_000, absoluteDeadline: 12)
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: UUID(), queuedAt: 12_000_000, started: 13_000_000)
        try require(diagnostics.snapshot().dnsLogicalQueries.count == 2
                    && !diagnostics.snapshot().dnsLogicalQueries.contains(where: { $0.rootID == root }),
                    "迟到的调度回执复活了已淘汰根查询")
        diagnostics.reset()
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: firstGeneration,
            queuedAt: 2_000_000, started: 2_000_000)
        try require(diagnostics.snapshot() == NetworkPerformanceSnapshot(), "重置后调度回执复活了旧查询")
        // Reset also releases deduplication state for a later retained root.
        diagnostics.beginDNSQuery(rootID: root, waiterID: leader, started: 1_000_000, absoluteDeadline: 10)
        diagnostics.recordDNSUpstreamStart(rootID: root, generationID: firstGeneration,
            queuedAt: 2_000_000, started: 2_000_000)
        try require(diagnostics.snapshot().dnsLogicalQueries[0].scheduling?.upstreamStartCount == 1,
                    "重置后残留了旧根查询的代际去重状态")
    }

    private static func connectionAttemptRecords() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        let diagnostics = NetworkPerformanceDiagnostics(maximumDNSAttempts: 2)
        let requestID = UUID()
        func begin(_ address: String = "203.0.113.53") -> DNSConnectionAttemptTrace {
            diagnostics.beginDNSAttempt(requestID: requestID, transport: .doh, purpose: .query,
                serverName: "private-resolver.invalid", endpointIdentity: "https://secret:credential@private-resolver.invalid/token",
                address: address)
        }
        let first = begin(), second = begin("203.0.113.54")
        first.setRoute(.proxy, identity: "secret-proxy-route")
        first.record(.rawEOF)
        first.record(.tlsWaiting, error: NWError.tls(-9816))
        first.cancel(.hedgeRotation)
        first.record(.tlsFailure, error: NWError.posix(.ECANCELED))
        first.complete(.dnsTLSHandshake, outcome: .failure)
        let measured = diagnostics.snapshot().dnsConnectionAttempts[0]
        try require(measured.id == first.id && measured.requestID == requestID
                    && measured.provider == "custom" && measured.route == .proxy
                    && measured.firstError?.codes == [DNSAttemptErrorCode(domain: NSOSStatusErrorDomain, code: -9816)]
                    && measured.firstError?.category == "tlsClosedWithoutNotify"
                    && measured.firstErrorBeforeCancellation == measured.firstError
                    && measured.cancellationReason == .hedgeRotation && measured.tlsOutcome == .failure,
                    "单次 TLS 的原始错误、取消原因或关联标识丢失")
        try require(measured.observations.map(\.event) == [.rawEOF, .tlsWaiting, .cancelRequested, .tlsFailure]
                    && zip(measured.observations, measured.observations.dropFirst()).allSatisfy { $0.milliseconds <= $1.milliseconds },
                    "底层 EOF、TLS 错误与后续取消顺序被改写")
        let wrapped = NSError(domain: "private-domain:credential", code: 73,
            userInfo: [NSLocalizedDescriptionKey: "secret-error-content", NSUnderlyingErrorKey: NSError(
                domain: NSPOSIXErrorDomain, code: Int(ECONNRESET), userInfo: [NSLocalizedDescriptionKey: "secret-address"])])
        second.record(.rawFailure, error: wrapped)
        second.cancel(.winnerSelected)
        for _ in 0..<100 { second.record(.localCancel) }
        let bounded = diagnostics.snapshot().dnsConnectionAttempts[1]
        try require(bounded.observations.count == 24 && bounded.omittedObservations == 78
                    && bounded.firstError?.codes.map(\.code) == [73, Int(ECONNRESET)]
                    && bounded.cancellationReason == .winnerSelected, "单次记录无界或丢失底层错误链")
        let encoded = String(data: try JSONEncoder().encode(diagnostics.snapshot().dnsConnectionAttempts), encoding: .utf8)!
        try require(!["private-resolver", "secret", "credential", "203.0.113", "private-domain"].contains(where: encoded.contains),
                    "诊断导出包含域名、地址、URL、凭据或错误文本")
        let third = begin()
        first.record(.rawFailure, error: NWError.posix(.ECONNRESET))
        first.cancel(.poolShutdown)
        let recent = diagnostics.snapshot().dnsConnectionAttempts
        try require(recent.count == 2 && recent.map(\.id) == [second.id, third.id]
                    && recent[0].upstreamID == recent[1].upstreamID && recent[0].addressID != recent[1].addressID,
                    "过期回调复活旧记录或候选/拨号地址标识不稳定")
        // The first closure is useful even after an unusually noisy stream
        // exhausted its event window; do not lose it to later cleanup.
        for _ in 0..<30 { third.record(.tlsReady) }
        third.record(.rawEOF); third.record(.localCancel)
        third.record(.tlsFailure, error: NWError.tls(-9816))
        let lateClosure = diagnostics.snapshot().dnsConnectionAttempts.last!
        try require(lateClosure.firstCarrierClosure?.event == .rawEOF
                    && lateClosure.firstLocalCancellation?.event == .localCancel
                    && lateClosure.observations.count == 24,
                    "事件窗口满后丢失了首次底层关闭或本地主动取消")

        let delayed = begin()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let admitted = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        defer { release.signal() }
        DispatchQueue.global().async {
            delayed.record(.rawFailure, error: DelayedError(entered: entered, release: release),
                           admitting: { admitted.signal() })
            done.signal()
        }
        try require(admitted.wait(timeout: .now() + 2) == .success
                    && entered.wait(timeout: .now() + 2) == .success,
                    "原生错误未在 NSError 转换前取得回执")
        delayed.cancel(.overallDeadline)
        delayed.record(.tlsFailure, error: NWError.tls(-9816))
        release.signal()
        try require(done.wait(timeout: .now() + 2) == .success, "延迟错误桥接未完成")
        let ordered = diagnostics.snapshot().dnsConnectionAttempts.last!
        try require(ordered.observations.map(\.sequence) == [0, 1, 2]
                    && ordered.observations.map(\.event) == [.rawFailure, .cancelRequested, .tlsFailure]
                    && ordered.firstError?.codes.first?.code == Int(ECONNRESET)
                    && ordered.firstErrorBeforeCancellation?.codes.first?.code == Int(ECONNRESET)
                    && ordered.firstCarrierClosure?.error?.codes.first?.code == Int(ECONNRESET),
                    "较慢的错误桥接被后到取消或 TLS 错误抢占首错/时间顺序")
        diagnostics.reset()
        third.record(.tlsFailure, error: NWError.tls(-9807))
        try require(diagnostics.snapshot() == NetworkPerformanceSnapshot(), "重置后迟到事件复活连接明细")
    }
}

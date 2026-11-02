import Foundation
import CoreFoundation
import Network

@main private enum DNSConnectionResetEvidenceMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private static var groups = 0, assertions = 0
    private static var failedGroups: [String] = []
    private static let evidenceGroups = ["native reset provenance", "atomic progress and completed admission",
        "generation-bound reset evidence", "diagnostic lifetime independence", "concurrent generation snapshots"]
    private static func require(_ value: @autoclosure () throws -> Bool, _ text: String) throws {
        assertions += 1
        if try !value() { throw Failure(text: text) }
    }
    private static func check(_ name: String, _ work: () throws -> Void) {
        groups += 1
        do { try work(); print("PASS", name) }
        catch { failedGroups.append(name); print("FAIL", name, error.localizedDescription) }
    }
    private static func proof(_ context: DNSQueryExecutionContext) -> Bool {
        #if HAVE_CONNECTION_RESET_EVIDENCE
        return context.hasConnectionResetBeforeCancellation
        #else
        return false
        #endif
    }
    private static func atomicProgress(_ context: DNSQueryExecutionContext) -> DNSQueryProgressSnapshot? {
        #if HAVE_CONNECTION_RESET_EVIDENCE
        return context.connectionResetProgress()
        #else
        return nil
        #endif
    }
    private static func unboundReset(_ context: DNSQueryExecutionContext, id: UUID? = nil) {
        #if HAVE_CONNECTION_RESET_EVIDENCE
        context.record(.rawFailure, attemptID: id, connectionReset: true)
        #else
        context.record(.rawFailure, attemptID: id)
        #endif
    }
    private static func begin(_ context: DNSQueryExecutionContext, _ recorder: NetworkPerformanceDiagnostics) -> DNSConnectionAttemptTrace {
        recorder.beginDNSAttempt(requestID: UUID(), transport: .doh, purpose: .query,
            serverName: "evidence.selftest.invalid", endpointIdentity: "https://evidence.selftest.invalid/dns-query",
            address: "203.0.113.53|443", context: context)
    }
    private static func handshake(_ trace: DNSConnectionAttemptTrace) {
        trace.record(.transportStarted); trace.record(.transportReady); trace.record(.tlsStarted)
    }
    private static func cfError(_ domain: CFString = kCFErrorDomainPOSIX, code: Int = 54,
                                underlying: Error? = nil) -> NSError {
        let info = underlying.map { [NSUnderlyingErrorKey: $0] as CFDictionary }
        let native = CFErrorCreate(kCFAllocatorDefault, domain, code, info)!
        return unsafeBitCast(native, to: NSError.self)
    }
    private enum CategoryOnlyError: Error { case network }
    private final class CustomNSErrorSubclass: NSError, @unchecked Sendable {
        init() { super.init(domain: NSPOSIXErrorDomain, code: 54, userInfo: nil) }
        required init?(coder: NSCoder) { fatalError("Memory-only error has no archive") }
    }
    private final class BridgeProbe {
        private let lock = NSLock()
        private var admitted = false, beforeAdmission = 0, bridgeCount = 0
        func admit() { lock.lock(); admitted = true; lock.unlock() }
        func bridge() {
            lock.lock(); bridgeCount += 1
            if !admitted { beforeAdmission += 1 }
            lock.unlock()
        }
        var snapshot: (early: Int, total: Int) { lock.lock(); defer { lock.unlock() }; return (beforeAdmission, bridgeCount) }
    }
    private struct CustomBridgedReset: CustomNSError {
        let probe: BridgeProbe
        static var errorDomain: String { NSPOSIXErrorDomain }
        var errorCode: Int { 54 }
        var errorUserInfo: [String: Any] { probe.bridge(); return [:] }
    }

    private static func nativeProvenance() {
        check(evidenceGroups[0]) {
            let cf = cfError()
            try require(type(of: cf) != NSError.self && cf.domain == NSPOSIXErrorDomain && cf.code == 54,
                        "CF native fixture does not model nw_error_copy_cf_error toll-free output")
            let errors: [Error] = [NWError.posix(.ECONNRESET), NSError(domain: NSPOSIXErrorDomain, code: 54), cf]
            for event: DNSConnectionAttemptEvent in [.rawFailure, .tlsFailure] {
                for error in errors {
                    let context = DNSQueryExecutionContext(), recorder = NetworkPerformanceDiagnostics()
                    let trace = begin(context, recorder); handshake(trace)
                    try require(!proof(context) && atomicProgress(context) == nil, "Progress alone manufactured reset provenance")
                    trace.record(event, error: error)
                    try require(proof(context) && atomicProgress(context) == context.progress(),
                                "A native exact POSIX54 did not reach candidate-local evidence")
                    let snapshot = recorder.snapshot().dnsConnectionAttempts.first { $0.id == trace.id }
                    try require(snapshot?.firstErrorBeforeCancellation?.codes.first?.code == 54,
                                "New evidence changed original diagnostic raw error identity")
                }
            }
        }
        check("categories wrapped errors and custom bridging never grant reset evidence") {
            let reset = NSError(domain: NSPOSIXErrorDomain, code: 54)
            let authentication = NSError(domain: NSOSStatusErrorDomain, code: -9807)
            let errors: [Error] = [
                NWError.posix(.ENOTCONN), NWError.posix(.ECONNREFUSED), NWError.posix(.ECANCELED),
                NWError.posix(.ETIMEDOUT), NWError.tls(-9807), CategoryOnlyError.network,
                NSError(domain: "unrelated.error.domain", code: 54), authentication,
                NSError(domain: NSOSStatusErrorDomain, code: -9807, userInfo: [NSUnderlyingErrorKey: reset]),
                NSError(domain: NSURLErrorDomain, code: NSURLErrorSecureConnectionFailed, userInfo: [NSUnderlyingErrorKey: reset]),
                NSError(domain: NSPOSIXErrorDomain, code: 54, userInfo: [NSUnderlyingErrorKey: authentication]),
                NSError(domain: NSPOSIXErrorDomain, code: 54, userInfo: [NSUnderlyingErrorKey: reset]),
                NSError(domain: NSPOSIXErrorDomain, code: 54, userInfo: [NSUnderlyingErrorKey: NSNull()]),
                cfError(code: 57), cfError(kCFErrorDomainOSStatus, code: -9807),
                cfError(underlying: authentication), CustomNSErrorSubclass(),
            ]
            for error in errors {
                let context = DNSQueryExecutionContext(), recorder = NetworkPerformanceDiagnostics()
                let trace = begin(context, recorder); handshake(trace)
                trace.record(.rawFailure, error: error); trace.record(.tlsFailure, error: error)
                try require(!proof(context) && atomicProgress(context) == nil, "A non-native, non54 or wrapped error authorized recovery")
            }
            let bridge = BridgeProbe(), context = DNSQueryExecutionContext(), recorder = NetworkPerformanceDiagnostics()
            let trace = begin(context, recorder); handshake(trace)
            trace.record(.rawFailure, error: CustomBridgedReset(probe: bridge), admitting: bridge.admit)
            try require(!proof(context) && atomicProgress(context) == nil, "CustomNSError manufactured native provenance")
            try require(bridge.snapshot.early == 0 && bridge.snapshot.total > 0,
                        "Reset inspection bridged an arbitrary error ahead of the existing security admission callback")
        }
    }

    private static func lifecycle() {
        check(evidenceGroups[1]) {
            let context = DNSQueryExecutionContext(absoluteDeadline: 123), recorder = NetworkPerformanceDiagnostics()
            let trace = begin(context, recorder); handshake(trace)
            let encodedBefore = try JSONEncoder().encode(context.progress())
            trace.record(.rawFailure, error: NWError.posix(.ECONNRESET))
            try require(proof(context), "Native reset proof missing before request finish")
            try require(try JSONEncoder().encode(context.progress()) == encodedBefore,
                        "Private recovery evidence changed the Codable progress schema or timing")
            trace.record(.tlsFailure, error: NWError.posix(.ECONNRESET)); trace.record(.requestFinished)
            trace.cancel(.cleanup)
            try require(proof(context) && atomicProgress(context) == context.progress(),
                        "Logical finish erased previously admitted native reset evidence")
            let child = context.child()
            try require(child.rootID == context.rootID && child.absoluteDeadline == 123
                        && !proof(child) && atomicProgress(child) == nil,
                        "A child inherited native reset authority rather than only its root/deadline")
        }
        check("cancellation finish event and unbound-token fences") {
            for terminal: DNSConnectionAttemptEvent in [.cancelRequested, .localCancel, .requestFinished] {
                let context = DNSQueryExecutionContext(), recorder = NetworkPerformanceDiagnostics()
                let trace = begin(context, recorder); handshake(trace)
                if terminal == .cancelRequested { trace.cancel(.callerCancelled) }
                else { trace.record(terminal) }
                trace.record(.rawFailure, error: NWError.posix(.ECONNRESET))
                trace.record(.tlsFailure, error: cfError())
                try require(!proof(context) && atomicProgress(context) == nil, "Late reset crossed cancellation or request finish")
            }
            for event: DNSConnectionAttemptEvent in [.transportFailure, .rawWriteFailure, .bridgeFailure,
                .querySendFailure, .responseFailure, .rawEOF, .tlsWaiting] {
                let context = DNSQueryExecutionContext(), recorder = NetworkPerformanceDiagnostics()
                let trace = begin(context, recorder); handshake(trace)
                trace.record(event, error: NWError.posix(.ECONNRESET))
                try require(!proof(context), "An unrelated event manufactured raw/TLS reset provenance")
            }
            let context = DNSQueryExecutionContext()
            unboundReset(context)
            try require(!proof(context), "A context without a physical attempt gained reset evidence")
            let recorder = NetworkPerformanceDiagnostics(), trace = begin(context, recorder)
            unboundReset(context); unboundReset(context, id: UUID())
            try require(!proof(context), "Missing/foreign attempt identity authorized native reset evidence")
            trace.record(.requestFinished); trace.record(.responseComplete)
            try require(context.progress().responseCompletedAt == nil, "Recovery evidence changed existing finish/progress fencing")
        }
        check(evidenceGroups[2]) {
            let context = DNSQueryExecutionContext(), recorder = NetworkPerformanceDiagnostics()
            let old = begin(context, recorder); handshake(old)
            old.record(.rawFailure, error: NWError.posix(.ECONNRESET))
            try require(proof(context), "Old generation did not obtain native reset proof")
            context.beginConnectionAttempt(old.id)
            try require(proof(context), "Duplicate begin erased the current physical attempt's evidence")
            let fresh = begin(context, recorder)
            try require(!proof(context) && atomicProgress(context) == nil && context.progress().tlsStartedAt == nil,
                        "New physical generation inherited old reset evidence or timestamps")
            old.record(.rawFailure, error: cfError()); old.cancel(.cleanup); old.record(.requestFinished)
            try require(!proof(context), "An old trace granted new-generation recovery authority")
            handshake(fresh); fresh.record(.tlsFailure, error: NWError.posix(.ECONNRESET))
            try require(proof(context) && atomicProgress(context)?.tlsStartedAt != nil,
                        "An old cancellation/finish revoked the fresh physical attempt")
        }
    }

    private static func ringIndependence() {
        check(evidenceGroups[3]) {
            let recorder = NetworkPerformanceDiagnostics(maximumDNSAttempts: 1), context = DNSQueryExecutionContext()
            let trace = begin(context, recorder); handshake(trace)
            recorder.reset()
            trace.record(.rawFailure, error: cfError())
            try require(proof(context) && recorder.snapshot().dnsConnectionAttempts.isEmpty,
                        "Native reset proof depended on a retained diagnostic ring slot")
            var temporary: NetworkPerformanceDiagnostics? = NetworkPerformanceDiagnostics()
            weak var released = temporary
            let detachedContext = DNSQueryExecutionContext(), detached = begin(detachedContext, temporary!)
            handshake(detached); temporary = nil
            try require(released == nil, "Fixture unexpectedly retained the diagnostic recorder")
            var admitted = false
            detached.record(.rawFailure, error: NWError.posix(.ECONNRESET), admitting: { admitted = true })
            try require(proof(detachedContext) && admitted,
                        "Recorder deallocation lost candidate evidence or bypassed the security admission callback")
            let cancelled = DNSQueryExecutionContext(), detachedCancel = begin(cancelled, recorder)
            recorder.reset(); detachedCancel.cancel(.callerCancelled)
            detachedCancel.record(.rawFailure, error: NWError.posix(.ECONNRESET))
            try require(!proof(cancelled), "Cancellation depended on a retained diagnostic slot")
        }
    }

    private static func concurrentSnapshots() {
        check(evidenceGroups[4]) {
            let context = DNSQueryExecutionContext(), recorder = NetworkPerformanceDiagnostics(maximumDNSAttempts: 1)
            let group = DispatchGroup(), lock = NSLock(), readerStarted = DispatchSemaphore(value: 0)
            var failed = false, finished = false, reads = 0
            func fail() { lock.lock(); failed = true; lock.unlock() }
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                readerStarted.signal()
                while true {
                    if let snapshot = atomicProgress(context) {
                        if snapshot.transportReadyAt == nil || snapshot.transportReadyAt != snapshot.tlsStartedAt
                            || snapshot.querySentAt != nil || snapshot.stage != .tlsHandshaking { fail() }
                        lock.lock(); reads += 1; lock.unlock()
                    }
                    lock.lock(); let done = finished; lock.unlock()
                    if done { break }
                }
                group.leave()
            }
            try require(readerStarted.wait(timeout: .now() + 2) == .success, "Concurrent reader failed to start")
            var previous: DNSConnectionAttemptTrace?
            for index in 0..<256 {
                let trace = begin(context, recorder)
                previous?.record(.rawFailure, error: NWError.posix(.ECONNRESET))
                previous?.cancel(.cleanup); previous?.record(.requestFinished)
                if proof(context) { fail() }
                let stamp = TimeInterval(1000 + index)
                context.record(.transportReady, attemptID: trace.id, at: stamp)
                context.record(.tlsStarted, attemptID: trace.id, at: stamp)
                trace.record(.rawFailure, error: NWError.posix(.ECONNRESET))
                if !proof(context) { fail() }
                previous = trace
            }
            lock.lock(); finished = true; lock.unlock()
            try require(group.wait(timeout: .now() + 3) == .success, "Concurrent evidence reader did not finish")
            lock.lock(); let result = (failed, reads); lock.unlock()
            try require(!result.0 && result.1 > 0,
                        "Evidence/progress combined physical generations or missed all native reset observations")
        }
        check("native error admission order is independent of diagnostic completion") {
            let context = DNSQueryExecutionContext(), recorder = NetworkPerformanceDiagnostics()
            let trace = begin(context, recorder); handshake(trace)
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
            defer { release.signal() }
            DispatchQueue.global(qos: .userInitiated).async {
                trace.record(.rawFailure, error: NWError.posix(.ECONNRESET), admitting: {
                    entered.signal(); _ = release.wait(timeout: .now() + 2)
                })
                done.signal()
            }
            try require(entered.wait(timeout: .now() + 2) == .success, "Native error did not enter the admission window")
            let admittedBeforeCancel = proof(context)
            trace.cancel(.callerCancelled); release.signal()
            try require(done.wait(timeout: .now() + 2) == .success, "Native error admission did not drain")
            #if HAVE_CONNECTION_RESET_EVIDENCE
            try require(admittedBeforeCancel && proof(context), "A delayed diagnostic/error bridge reordered an earlier native reset after cancel")
            #else
            try require(!admittedBeforeCancel, "Baseline unexpectedly exposed reset evidence")
            #endif
            let retained = recorder.snapshot().dnsConnectionAttempts.first { $0.id == trace.id }
            try require(retained?.firstErrorBeforeCancellation?.codes.first?.code == 54,
                        "Existing diagnostic sequence reservation changed under native error/cancel interleaving")
        }
    }

    static func main() {
        nativeProvenance(); lifecycle(); ringIndependence(); concurrentSnapshots()
        let report: [String: Any] = ["groups": groups, "assertions": assertions, "failedGroups": failedGroups,
                                   "evidenceGroups": evidenceGroups, "memoryOnly": true]
        do { print(String(data: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!) }
        catch { fputs("Unable to serialize memory fixture result\n", stderr); exit(1) }
        exit(failedGroups.isEmpty ? 0 : 1)
    }
}

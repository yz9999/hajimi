import Foundation
import Network
import Security

/// Appended to exact production TLS/pool declarations by the narrow runner.
/// Only the controlled peer below is synthetic; the bridge, failure relay,
/// current-lease observation and pending NW callbacks are production code.
@main
enum NativeTLSLeaseFailureMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private static func require(_ condition: Bool, _ text: String) throws {
        if !condition { throw Failure(text: text) }
    }
    private static func wait(_ signal: DispatchSemaphore, _ text: String) throws {
        try require(signal.wait(timeout: .now() + 3) == .success, text)
    }
    private static func kind(_ error: Error?) -> String {
        guard let error else { return "nil" }
        if let nw = error as? NWError {
            switch nw {
            case .tls(let code): return "tls:\(code)"
            case .posix(let code): return "posix:\(code.rawValue)"
            case .dns(let code): return "dns:\(code)"
            @unknown default: return "nw:unknown"
            }
        }
        if let native = error as? NativeOutboundError, case .cancelled = native { return "cancelled" }
        let value = error as NSError; return "\(value.domain):\(value.code)"
    }
    private static func injectedError(_ mode: String) -> Error? {
        switch mode {
        case "tls": return NWError.tls(-9807)
        case "unknown": return NSError(domain: "NativeTLSLeaseFixture", code: 73)
        case "network": return NWError.posix(.ECONNRESET)
        default: return nil
        }
    }
    private final class Probe {
        private let lock = NSLock()
        private var closed = false
        private var errors: [String] = []
        func observe(_ error: Error) {
            lock.lock(); if !closed { errors.append(kind(error)) }; lock.unlock()
        }
        func seal() { lock.lock(); closed = true; lock.unlock() }
        var snapshot: [String] { lock.lock(); defer { lock.unlock() }; return errors }
    }
    private final class AttemptProbe {
        let diagnostics: NetworkPerformanceDiagnostics
        let trace: DNSConnectionAttemptTrace

        init() {
            let diagnostics = NetworkPerformanceDiagnostics(maximumSamples: 8, maximumDNSAttempts: 2)
            self.diagnostics = diagnostics
            trace = diagnostics.beginDNSAttempt(requestID: UUID(), transport: .doh, purpose: .query,
                serverName: "127.0.0.1", endpointIdentity: "fixed-loopback-fixture", address: "127.0.0.1")
        }

        var snapshot: DNSConnectionAttemptSnapshot {
            diagnostics.snapshot().dnsConnectionAttempts.first { $0.id == trace.id }!
        }

        @discardableResult
        func requireOrigin(_ mode: String, ready: Bool) throws -> Int {
            let value = snapshot
            let expected: DNSConnectionAttemptEvent = mode == "cancel" ? .localCancel
                : (mode == "eof" ? .rawEOF : .rawFailure)
            guard let index = value.observations.firstIndex(where: { $0.event == expected }) else {
                throw Failure(text: "native diagnostic origin missing: \(expected.rawValue)")
            }
            let origin = value.observations[index]
            if ready {
                try require(value.observations[..<index].contains { $0.event == .tlsReady },
                            "diagnostic origin preceded verified TLS readiness")
            } else {
                try require(!value.observations.contains { $0.event == .tlsReady },
                            "controlled early-EOF handshake unexpectedly became ready")
            }
            if mode == "eof" || mode == "cancel" {
                try require(origin.error == nil, "nil-error EOF/cancellation invented a native error")
            } else {
                guard let captured = origin.error, let first = value.firstError else {
                    throw Failure(text: "native diagnostic lost the original typed error")
                }
                try require(captured == first, "a later error replaced the diagnostic first error")
                if mode == "tls" {
                    try require(captured.codes.first == DNSAttemptErrorCode(domain: NSOSStatusErrorDomain, code: -9807),
                                "diagnostic erased native TLS status -9807")
                } else if mode == "network" {
                    try require(captured.codes.first == DNSAttemptErrorCode(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET)),
                                "diagnostic erased native POSIX reset status")
                } else if mode == "unknown" {
                    try require(captured.codes.first?.code == 73
                        && captured.codes.first?.domain.hasPrefix("error-") == true,
                        "unknown NSError domain was lost or retained without anonymization")
                }
            }
            if let cancelled = value.observations.firstIndex(where: { $0.event == .localCancel }) {
                try require(index <= cancelled, "cleanup cancellation preceded the observed native origin")
            }
            try require(zip(value.observations, value.observations.dropFirst()).allSatisfy {
                $0.milliseconds <= $1.milliseconds
            }, "native event timeline is not monotonic")
            return index
        }
    }
    private final class Raw: NativeOutboundByteStream {
        let connection: NWConnection
        private let lock = NSLock()
        private var pending: ((Data?, Bool, Error?) -> Void)?
        private var token = UUID()
        private var firstReadInjection: String?
        let reading = DispatchSemaphore(value: 0)
        init(_ port: UInt16, firstReadInjection: String? = nil) {
            self.firstReadInjection = firstReadInjection
            connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        }
        func start() throws {
            let ready = DispatchSemaphore(value: 0), probe = Probe()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: ready.signal()
                case .failed(let error): probe.observe(error); ready.signal()
                default: break
                }
            }
            connection.start(queue: DispatchQueue(label: "app.hajimi.fixture.tls-lease.raw"))
            try wait(ready, "controlled raw peer did not become ready")
            try require(probe.snapshot.isEmpty, "controlled raw peer failed")
        }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            connection.send(content: data, completion: .contentProcessed(completion))
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            if let injection = firstReadInjection {
                firstReadInjection = nil
                lock.unlock(); reading.signal()
                completion(nil, true, injectedError(injection))
                return
            }
            precondition(pending == nil); pending = completion
            let current = UUID(); token = current; lock.unlock(); reading.signal()
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { data, _, eof, error in
                self.lock.lock()
                guard self.token == current else { self.lock.unlock(); return }
                let callback = self.pending; self.pending = nil
                self.lock.unlock(); callback?(data, eof, error)
            }
        }
        func inject(_ mode: String) throws {
            lock.lock(); let callback = pending; pending = nil; token = UUID(); lock.unlock()
            guard let callback else { throw Failure(text: "controlled raw receive was not pending") }
            callback(nil, true, injectedError(mode))
        }
        func cancel() { connection.cancel() }
    }

    private static func upgraded(_ raw: Raw, anchor: SecCertificate, original: Probe,
                                 attempt: AttemptProbe) throws -> any NativeOutboundByteStream {
        let done = DispatchSemaphore(value: 0), lock = NSLock()
        var result: Result<any ByteTransport, Error>?
        let cancel = NestedNetworkTLSByteTransport.upgrade(raw: OutboundStreamTransport(raw),
            serverName: "127.0.0.1", skipCertificateVerification: false, alpn: ["http/1.1"],
            defaultHTTPALPN: false, fixtureAnchor: anchor, failureObserver: original.observe,
            attemptTrace: attempt.trace) {
                lock.lock(); result = $0; lock.unlock(); done.signal()
            }
        do { try wait(done, "controlled verified TLS handshake did not finish") }
        catch { cancel(); throw error }
        lock.lock(); let outcome = result; lock.unlock()
        guard case .success(let transport)? = outcome,
              let stream = transport as? any NativeOutboundByteStream else {
            throw Failure(text: "controlled verified TLS handshake failed")
        }
        return stream
    }

    private static func direct(_ stream: any NativeOutboundByteStream, raw: Raw, original: Probe,
                               attempt: AttemptProbe, mode: String, timing: String) throws {
        let first = DispatchSemaphore(value: 0), firstLock = NSLock()
        var firstOK = false
        stream.send(Data([65])) { error in
            guard error == nil else { first.signal(); return }
            stream.receive(maximum: 1024) { data, eof, error in
                firstLock.lock(); firstOK = data == Data([65]) && !eof && error == nil; firstLock.unlock(); first.signal()
            }
        }
        try wait(first, "first real TLS exchange did not finish")
        firstLock.lock(); let valid = firstOK; firstLock.unlock()
        try require(valid, "first real TLS exchange failed")
        original.seal()
        let done = DispatchSemaphore(value: 0), lock = NSLock()
        var received = "missing", count = 0
        let read = {
            stream.receive(maximum: 1024) { _, eof, error in
                lock.lock(); received = kind(error); count += 1; lock.unlock()
                if !eof { received = "nonterminal" }; done.signal()
            }
        }
        if timing == "pending" { read() }
        // Ordering is intentional: install a pending app receive before the
        // controlled raw error, or exercise I/O after the bridge has failed.
        let injected = DispatchSemaphore(value: 0), injectionLock = NSLock()
        var injectionError: Error?
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.03) {
            do { if mode == "cancel" { stream.cancel() } else { try raw.inject(mode) } }
            catch { injectionLock.lock(); injectionError = error; injectionLock.unlock() }
            injected.signal()
        }
        try wait(injected, "controlled raw injection did not run")
        injectionLock.lock(); let failed = injectionError; injectionLock.unlock()
        if let failed { throw failed }
        if timing == "late" { read() }
        try wait(done, "pending/late read did not acknowledge native failure")
        lock.lock(); let actual = received, callbacks = count; lock.unlock()
        let expected = mode == "cancel" ? "cancelled" : kind(injectedError(mode))
        try require(actual == expected && callbacks == 1,
                    "original error was replaced or duplicated: expected \(expected), got \(actual), count \(callbacks)")
        if mode != "eof" {
            let sent = DispatchSemaphore(value: 0), sendProbe = Probe()
            stream.send(Data([66])) { error in if let error { sendProbe.observe(error) }; sent.signal() }
            try wait(sent, "late send did not fail with retained original error")
            try require(sendProbe.snapshot == [expected], "late send lost its original error")
        }
        try require(original.snapshot.isEmpty, "late failure entered a sealed old lease")
        try attempt.requireOrigin(mode, ready: true)
        let firstError = attempt.snapshot.firstError
        stream.cancel()
        if let firstError {
            try require(attempt.snapshot.firstError == firstError, "local cancel replaced the diagnostic first native error")
        }
        try attempt.requireOrigin(mode, ready: true)
        print("PASS mode=\(mode) timing=\(timing) firstExchange=verified-success originalRead=\(actual) callbacks=\(callbacks) nativeTrace=retained")
    }

    private static func pooled(_ stream: any NativeOutboundByteStream, raw: Raw, original: Probe,
                               attempt: AttemptProbe, mode: String) throws {
        let queue = DispatchQueue(label: "app.hajimi.fixture.tls-lease.pool")
        let current = Probe(), first = DispatchSemaphore(value: 0), firstLock = NSLock()
        var firstOK = false
        let pooled = queue.sync { EncryptedDNSPooledConnection(stream: stream, queue: queue, onClosed: { _ in }) }
        defer { queue.sync { pooled.close() } }
        queue.async {
            pooled.send(Data([65]), failureObserver: original.observe) { error in
                guard error == nil else { first.signal(); return }
                pooled.receive { data, eof, error in
                    firstLock.lock(); firstOK = data == Data([65]) && !eof && error == nil; firstLock.unlock()
                    first.signal()
                }
            }
        }
        try wait(first, "pooled first TLS exchange did not finish")
        firstLock.lock(); let valid = firstOK; firstLock.unlock()
        try require(valid, "pooled first TLS exchange failed")
        original.seal()
        let budget = SOCKSUDPGlobalBudget(resources: 1, packets: 0, bytes: 0)
        let sent = DispatchSemaphore(value: 0)
        try queue.sync {
            try require(pooled.canReturnIdle, "first TLS exchange was not reusable")
            pooled.beginIdle(until: Date().addingTimeInterval(15), duration: 15,
                             reservation: budget.reserveResource()!)
            try require(pooled.beginLease(), "second TLS lease could not check out")
            pooled.send(Data([66]), failureObserver: current.observe) { _ in sent.signal() }
            pooled.receive { _, _, _ in }
        }
        try wait(sent, "second TLS lease did not send")
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        defer { release.signal() }
        queue.async { entered.signal(); _ = release.wait(timeout: .now() + 2) }
        try wait(entered, "could not hold current lease owner queue")
        try raw.inject(mode)
        let expected = kind(injectedError(mode))
        try require(current.snapshot.first == expected,
                    "raw error did not enter current lease synchronously before cancellation")
        try attempt.requireOrigin(mode, ready: true)
        let firstError = attempt.snapshot.firstError
        // The queued close runs before any application receive delivery can
        // publish the retained error. Its already-admitted deny must survive.
        queue.async { pooled.close() }
        release.signal(); queue.sync {}
        try require(current.snapshot.first == expected && original.snapshot.isEmpty,
                    "cleanup error replaced the current lease's first error or entered the old sealed lease")
        try require(budget.usage.resources == 0, "failure leaked an idle reservation")
        try require(attempt.snapshot.firstError == firstError, "pooled cleanup overwrote the diagnostic original error")
        try attempt.requireOrigin(mode, ready: true)
        print("PASS mode=\(mode) timing=pool-native-ingress originalError=\(expected) oldLease=sealed idleResources=0 nativeTrace=retained")
    }

    private static func earlyHandshake(_ raw: Raw, anchor: SecCertificate,
                                       original: Probe, attempt: AttemptProbe, mode: String) throws {
        let done = DispatchSemaphore(value: 0), lock = NSLock()
        var result: Result<any ByteTransport, Error>?
        let cancel = NestedNetworkTLSByteTransport.upgrade(raw: OutboundStreamTransport(raw),
            serverName: "127.0.0.1", skipCertificateVerification: false, alpn: ["http/1.1"],
            defaultHTTPALPN: false, fixtureAnchor: anchor, failureObserver: original.observe,
            attemptTrace: attempt.trace) {
                lock.lock(); result = $0; lock.unlock(); done.signal()
            }
        defer { cancel() }
        try wait(done, "early native EOF/error did not acknowledge the pending handshake")
        lock.lock(); let outcome = result; lock.unlock()
        guard case .failure(let error)? = outcome else {
            throw Failure(text: "early raw EOF/error unexpectedly established TLS")
        }
        let index = try attempt.requireOrigin(mode, ready: false)
        if mode == "eof" {
            let value = attempt.snapshot
            // This controlled first read carries no peer ciphertext at all.
            // Only that narrow case now ends without waiting for platform TLS
            // to manufacture its later closed-no-notify result. EOF after any
            // peer bytes still retains the actual native authentication path.
            let expected = "app.hajimi.nested-tls-carrier:2"
            try require(value.observations[index].peerCiphertextBytes == 0,
                        "early EOF fixture unexpectedly delivered peer TLS ciphertext")
            try require(kind(error) == expected && EncryptedDNSQueryFailure.classify(error) == .other,
                        "zero-peer EOF lost its non-downgradable carrier reason: \(kind(error))")
            try require(original.snapshot == [expected],
                        "zero-peer EOF duplicated its failure observer")
        } else {
            try require(kind(error) == kind(injectedError(mode)), "early handshake lost its original raw error")
        }
        let firstError = attempt.snapshot.firstError
        cancel()
        try require(attempt.snapshot.firstError == firstError, "late upgrade cancellation replaced the first native error")
        print("PASS mode=\(mode) timing=handshake rawOriginBeforeTLS=true retainedError=\(kind(error)) nativeTrace=retained")
    }

    static func main() throws {
        var untracedAdmissions = 0
        nativeOutboundTLSObserveFailure(.rawFailure, error: NWError.posix(.ECONNRESET),
            attemptTrace: nil, admitting: { untracedAdmissions += 1 })
        try require(untracedAdmissions == 1, "disabled tracing suppressed or duplicated failure admission")
        let observer = Probe(), relay = NativeOutboundFailureRelay(dialObserver: nil)
        relay.setStreamObserver(observer.observe)
        relay.observe(NWError.posix(.ECONNRESET))
        relay.observe(NWError.tls(-9807))
        try require(observer.snapshot == ["posix:54", "tls:-9807"] && kind(relay.terminalError) == "posix:54",
                    "first I/O failure suppressed a later admitted authentication denial")
        relay.setStreamObserver(nil)
        relay.observe(NSError(domain: "DetachedNativeTLSLeaseFixture", code: 74))
        try require(observer.snapshot.count == 2, "detached current lease received another failure")
        let args = CommandLine.arguments
        guard args.count >= 6, let port = UInt16(args[1]),
              let anchor = SecCertificateCreateWithData(nil,
                try Data(contentsOf: URL(fileURLWithPath: args[2])) as CFData) else {
            throw Failure(text: "bounded local fixture arguments unavailable")
        }
        let mode = args[3], timing = args[4]
        let raw = Raw(port, firstReadInjection: timing == "handshake" ? mode : nil)
        let original = Probe(), attempt = AttemptProbe()
        try raw.start(); defer { raw.cancel() }
        if timing == "handshake" {
            try earlyHandshake(raw, anchor: anchor, original: original, attempt: attempt, mode: mode)
            return
        }
        let stream = try upgraded(raw, anchor: anchor, original: original, attempt: attempt)
        defer { stream.cancel() }
        if timing == "pool" { try pooled(stream, raw: raw, original: original, attempt: attempt, mode: mode) }
        else { try direct(stream, raw: raw, original: original, attempt: attempt, mode: mode, timing: timing) }
    }
}

import Foundation
import Network
import Security

/// Only fixed local peers and in-memory callbacks exercise the verbatim TLS
/// owner. No resolver, App, Helper, profile or system network setting is used.
private extension NestedNetworkTLSByteTransport {
    static func progressMemoryOwner(raw: any ByteTransport, trace: DNSConnectionAttemptTrace?,
                                    observe: @escaping (Error) -> Void) -> NestedNetworkTLSByteTransport {
        NestedNetworkTLSByteTransport(raw: raw, serverName: "127.0.0.1",
            skipCertificateVerification: false, alpn: ["http/1.1"], defaultHTTPALPN: false,
            fixtureAnchor: nil, fixtureTrustObserver: nil, failureObserver: observe, attemptTrace: trace)
    }
    func progressMemoryRead() {
        queue.sync {
            let local = NWConnection(host: "127.0.0.1", port: 1, using: .tcp)
            localCipherConnection = local
            pumpRemoteCiphertext(local)
        }
    }
    func progressDrain() { queue.sync {} }
}

@main
enum NativeTLSStreamProgressMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private static var assertions = 0
    private static func require(_ condition: Bool, _ text: String) throws {
        assertions += 1
        if !condition { throw Failure(text: text) }
    }
    private static func wait(_ signal: DispatchSemaphore, _ text: String) throws {
        try require(signal.wait(timeout: .now() + 3) == .success, text)
    }
    private final class Attempt {
        let diagnostics = NetworkPerformanceDiagnostics(maximumSamples: 8, maximumDNSAttempts: 2)
        lazy var trace = diagnostics.beginDNSAttempt(requestID: UUID(), transport: .doh, purpose: .query,
            serverName: "127.0.0.1", endpointIdentity: "fixed-progress-loopback", address: "127.0.0.1")
    }
    private final class MemoryRaw: ByteTransport {
        private let lock = NSLock()
        private var reader: ((Data?, Bool, Error?) -> Void)?
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
        func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); precondition(reader == nil); reader = completion; lock.unlock()
        }
        func emit(_ data: Data, error: Error) {
            lock.lock(); let callback = reader; reader = nil; lock.unlock()
            precondition(callback != nil); callback?(data, true, error)
        }
        func cancel() { lock.lock(); reader = nil; lock.unlock() }
    }
    private final class Raw: NativeOutboundByteStream {
        private let connection: NWConnection
        private let queue = DispatchQueue(label: "app.hajimi.fixture.progress.raw")
        private let lock = NSLock()
        private var holdWrites = false
        private var held: (() -> Void)?
        let writeHeld = DispatchSemaphore(value: 0)
        init(_ port: UInt16) {
            connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        }
        func start() throws {
            let ready = DispatchSemaphore(value: 0), failed = NSLock()
            var failure: Error?
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: ready.signal()
                case .failed(let error): failed.lock(); failure = error; failed.unlock(); ready.signal()
                default: break
                }
            }
            connection.start(queue: queue)
            try wait(ready, "loopback raw connection did not start")
            failed.lock(); let error = failure; failed.unlock()
            try require(error == nil, "loopback raw connection failed")
        }
        func holdNextWriteCompletion() { lock.lock(); holdWrites = true; lock.unlock() }
        func releaseWrite() {
            lock.lock(); let callback = held; held = nil; holdWrites = false; lock.unlock()
            callback?()
        }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            connection.send(content: data, completion: .contentProcessed { error in
                self.lock.lock()
                let held = self.holdWrites && error == nil
                if held {
                    precondition(self.held == nil)
                    self.held = { completion(nil) }
                }
                self.lock.unlock()
                if held { self.writeHeld.signal() } else { completion(error) }
            })
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { data, _, done, error in
                completion(data, done, error)
            }
        }
        func cancel() { releaseWrite(); connection.cancel() }
    }
    private static func provider(_ stream: AnyObject) throws -> any DNSStreamProgressProviding {
        guard let value = stream as? any DNSStreamProgressProviding else {
            throw Failure(text: "missing-DNS-TLS-progress-evidence")
        }
        return value
    }
    private static func snapshot(_ stream: AnyObject) throws -> DNSStreamProgressSnapshot {
        guard let value = try provider(stream).dnsStreamProgressSnapshot() else {
            throw Failure(text: "missing-DNS-TLS-progress-evidence")
        }
        return value
    }
    private static func allTimestampsAbsent(_ value: DNSStreamProgressSnapshot) -> Bool {
        value.lastRawWriteRequestedUptimeNanoseconds == nil && value.lastRawWriteCompletedUptimeNanoseconds == nil
            && value.lastRawReadRequestedUptimeNanoseconds == nil && value.lastRawReadCompletedUptimeNanoseconds == nil
            && value.lastPlaintextWriteRequestedUptimeNanoseconds == nil && value.lastPlaintextWriteProcessedUptimeNanoseconds == nil
            && value.lastPlaintextReadRequestedUptimeNanoseconds == nil && value.lastPlaintextReadDeliveredUptimeNanoseconds == nil
    }

    private static func memory() throws {
        let attempt = Attempt(), raw = MemoryRaw()
        var owner: NestedNetworkTLSByteTransport!
        let failureObserved = DispatchSemaphore(value: 0), failureLock = NSLock()
        var beforeFailure: DNSStreamProgressSnapshot?
        owner = .progressMemoryOwner(raw: raw, trace: attempt.trace) { _ in
            let value = (owner! as AnyObject as? any DNSStreamProgressProviding)?.dnsStreamProgressSnapshot()
            failureLock.lock(); beforeFailure = value; failureLock.unlock(); failureObserved.signal()
        }
        defer { owner.cancel(); owner = nil }
        let start = try snapshot(owner!)
        try require(start == DNSStreamProgressSnapshot(), "traced stream did not start with measured zero counters")
        owner.progressMemoryRead()
        let read = try snapshot(owner!)
        try require(read.rawReadRequests == 1 && read.rawReadCompletedBytes == 0
                    && read.plaintextReadRequests == 0, "raw read issuance was fabricated or omitted")
        raw.emit(Data([0, 1, 2, 3, 4]), error: NWError.posix(.ECONNRESET))
        try wait(failureObserved, "original raw failure observer was not called")
        failureLock.lock(); let observed = beforeFailure; failureLock.unlock()
        try require(observed?.rawReadCompletedBytes == 5, "raw byte evidence was not visible before native failure admission")
        try require(observed?.plaintextReadDeliveredBytes == 0, "raw TLS bytes were reported as DNS plaintext")
        let inFlight = observed!.delta(since: read)!
        try require(inFlight.rawReadRequests == 0 && inFlight.rawReadCompletedBytes == 5,
                    "a previously issued raw read was mistaken for absence of in-flight I/O")
        owner.progressDrain()
        print("PASS memory-native-ingress originalFailureUnchanged=true rawBytesBeforeFailure=5 plaintextBytes=0")

        let ordinary = NestedNetworkTLSByteTransport.progressMemoryOwner(raw: MemoryRaw(), trace: nil, observe: { _ in })
        try require((ordinary as AnyObject as? any DNSStreamProgressProviding)?.dnsStreamProgressSnapshot() == nil,
                    "ordinary TLS fabricated a measured zero snapshot")
        ordinary.cancel(); ordinary.progressDrain()
        print("PASS ordinary-TLS-progress-disabled snapshot=nil")

        var clock: UInt64 = 100
        let recorder = DNSStreamProgressRecorder(clock: { clock })
        let events: [DNSStreamProgressEvent] = [.rawWriteRequested, .rawWriteCompleted, .rawReadRequested, .rawReadCompleted,
            .plaintextWriteRequested, .plaintextWriteProcessed, .plaintextReadRequested, .plaintextReadDelivered]
        for event in events { recorder.record(event, bytes: 7) }
        let first = recorder.snapshot()
        try require(first.rawWriteRequestedBytes == 7 && first.rawWriteCompletedBytes == 7
                    && first.rawReadRequests == 1 && first.rawReadCompletedBytes == 7
                    && first.plaintextWriteRequestedBytes == 7 && first.plaintextWriteProcessedBytes == 7
                    && first.plaintextReadRequests == 1 && first.plaintextReadDeliveredBytes == 7,
                    "stream progress counted requests as invented byte lengths")
        clock = 50
        for event in events { recorder.record(event, bytes: 1) }
        let second = recorder.snapshot()
        try require(second.lastRawReadCompletedUptimeNanoseconds == 100
                    && second.lastPlaintextReadDeliveredUptimeNanoseconds == 100, "clock regression moved timestamps backward")
        let difference = second.delta(since: first)!
        try require(difference.rawWriteCompletedBytes == 1 && difference.rawReadRequests == 1
                    && difference.plaintextReadDeliveredBytes == 1, "lease delta included an earlier request")
        try require(first.delta(since: second) == nil, "counter rollback became an invented zero measurement")
        try require(allTimestampsAbsent(second.delta(since: second)!), "unchanged counters retained previous-lease timestamps")
        print("PASS counter-delta requestsAreOperations=true rollback=nil unchangedTimestamps=nil monotonic=true")

        let saturated = DNSStreamProgressRecorder(clock: { 300 })
        for _ in 0..<3 { saturated.record(.rawWriteRequested, bytes: Int.max) }
        let maximum = saturated.snapshot()
        try require(maximum.rawWriteRequestedBytes == UInt64.max, "UInt64 byte count wrapped instead of saturating")
        saturated.record(.rawWriteRequested, bytes: 1)
        let noGrowth = saturated.snapshot().delta(since: maximum)!
        try require(noGrowth.rawWriteRequestedBytes == 0 && noGrowth.lastRawWriteRequestedUptimeNanoseconds == nil,
                    "a saturated unchanged count fabricated measurable progress")
        saturated.record(.rawReadCompleted, bytes: -1)
        try require(saturated.snapshot().rawReadCompletedBytes == 0, "negative byte count became unsigned overflow")
        print("PASS saturating-counters UInt64Max=true noFalseProgress=true")

        let concurrent = DNSStreamProgressRecorder()
        DispatchQueue.concurrentPerform(iterations: 1_000) { _ in
            for event in events { concurrent.record(event, bytes: 3) }
            _ = concurrent.snapshot()
        }
        let joined = concurrent.snapshot()
        try require(joined.rawWriteRequestedBytes == 3_000 && joined.rawWriteCompletedBytes == 3_000
                    && joined.rawReadRequests == 1_000 && joined.rawReadCompletedBytes == 3_000
                    && joined.plaintextWriteRequestedBytes == 3_000 && joined.plaintextWriteProcessedBytes == 3_000
                    && joined.plaintextReadRequests == 1_000 && joined.plaintextReadDeliveredBytes == 3_000,
                    "concurrent snapshots or increments lost progress")
        var reentrant: DNSStreamProgressRecorder!
        reentrant = DNSStreamProgressRecorder(clock: { _ = reentrant?.snapshot(); return 400 })
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { reentrant.record(.rawReadRequested); done.signal() }
        try wait(done, "the injectable clock was invoked under the recorder lock")
        reentrant = nil
        print("PASS concurrency 1000Writers=true reentrantClockOutsideLock=true")

        let encoded = try JSONEncoder().encode(joined)
        try require(try JSONDecoder().decode(DNSStreamProgressSnapshot.self, from: encoded) == joined,
                    "progress JSON changed cumulative counters")
        let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        try require(object.count == 16 && object.values.allSatisfy { $0 is NSNumber },
                    "progress JSON retained non-numeric data or unbounded fields")
        try require(MemoryLayout<DNSStreamProgressSnapshot>.stride <= 256, "progress snapshot is no longer fixed and small")
        print("PASS bounded-anonymous-JSON fields=16 numericOnly=true noPayload=true")
        print("PASS memory-summary assertions=\(assertions)")
    }

    private static func upgraded(_ raw: Raw, anchor: SecCertificate, attempt: Attempt?) throws -> any NativeOutboundByteStream {
        let done = DispatchSemaphore(value: 0), lock = NSLock()
        var outcome: Result<any ByteTransport, Error>?
        let cancel = NestedNetworkTLSByteTransport.upgrade(raw: OutboundStreamTransport(raw), serverName: "127.0.0.1",
            skipCertificateVerification: false, alpn: ["http/1.1"], defaultHTTPALPN: false,
            fixtureAnchor: anchor, attemptTrace: attempt?.trace) { result in
                lock.lock(); outcome = result; lock.unlock(); done.signal()
            }
        do { try wait(done, "verified loopback TLS did not finish") } catch { cancel(); throw error }
        lock.lock(); let result = outcome; lock.unlock()
        guard case .success(let value)? = result, let stream = value as? any NativeOutboundByteStream else {
            throw Failure(text: "verified loopback TLS failed")
        }
        return stream
    }
    private static func exchange(_ stream: any NativeOutboundByteStream, payload: Data) throws {
        let done = DispatchSemaphore(value: 0), lock = NSLock()
        var actual = Data(), failure: Error?
        stream.send(payload) { error in
            if let error { lock.lock(); failure = error; lock.unlock(); done.signal(); return }
            func read() {
                stream.receive(maximum: 1024) { data, complete, error in
                    lock.lock()
                    if let data { actual.append(data) }
                    failure = error
                    let ready = actual.count >= payload.count || complete || error != nil
                    lock.unlock()
                    if ready { done.signal() } else { read() }
                }
            }
            read()
        }
        try wait(done, "fixed loopback echo did not complete")
        lock.lock(); let matches = actual == payload && failure == nil; lock.unlock()
        try require(matches, "loopback echo payload/ownership changed")
    }
    private static func loopback(port: UInt16, anchor: SecCertificate, scenario: String) throws {
        let raw = Raw(port), attempt = scenario == "untraced" ? nil : Attempt()
        try raw.start(); defer { raw.cancel() }
        let stream = try upgraded(raw, anchor: anchor, attempt: attempt)
        defer { stream.cancel() }
        if scenario == "untraced" {
            try exchange(stream, payload: Data([65, 66, 67]))
            try require((stream as? any DNSStreamProgressProviding)?.dnsStreamProgressSnapshot() == nil,
                        "untraced real TLS allocated progress evidence")
            print("PASS loopback-untraced realTLS=true payloadUnchanged=true snapshot=nil assertions=\(assertions)")
            return
        }
        let before = try snapshot(stream)
        try require(before.rawWriteCompletedBytes > 0 && before.rawReadCompletedBytes > 0
                    && before.plaintextReadDeliveredBytes == 0, "TLS handshake was confused with application data")
        if scenario == "echo" {
            try exchange(stream, payload: Data([65, 66, 67]))
            let first = try snapshot(stream), delta = first.delta(since: before)!
            try require(delta.plaintextWriteRequestedBytes == 3 && delta.plaintextWriteProcessedBytes == 3
                        && delta.plaintextReadRequests >= 1 && delta.plaintextReadDeliveredBytes == 3,
                        "real TLS plaintext send/read counters differ")
            try require(delta.rawWriteRequestedBytes >= 3 && delta.rawWriteCompletedBytes >= 3
                        && delta.rawReadCompletedBytes >= 3, "real TLS did not report carrier byte callbacks")
            try exchange(stream, payload: Data([68, 69]))
            let reused = try snapshot(stream).delta(since: first)!
            try require(reused.plaintextWriteRequestedBytes == 2 && reused.plaintextWriteProcessedBytes == 2
                        && reused.plaintextReadDeliveredBytes == 2, "second lease inherited first-lease plaintext counters")
            print("PASS loopback-echo realTLS=true firstBytes=3 reusedBytes=2 handshakeExcluded=true assertions=\(assertions)")
            return
        }
        if scenario == "held-write" { raw.holdNextWriteCompletion() }
        let sent = DispatchSemaphore(value: 0), readDone = DispatchSemaphore(value: 0), lock = NSLock()
        var readCount = 0, sendOK = false
        stream.send(Data([83])) { error in lock.lock(); sendOK = error == nil; lock.unlock(); sent.signal() }
        stream.receive(maximum: 1024) { _, _, _ in lock.lock(); readCount += 1; lock.unlock(); readDone.signal() }
        try wait(sent, "local TLS content processing did not finish")
        if scenario == "held-write" { try wait(raw.writeHeld, "controlled carrier write callback was not held") }
        // A bounded wait proves no plaintext response was delivered before
        // this checkpoint. It is not treated as a provider timeout by code.
        try require(readDone.wait(timeout: .now() + .milliseconds(100)) == .timedOut,
                    "silent loopback peer unexpectedly delivered plaintext")
        let waiting = try snapshot(stream).delta(since: before)!
        lock.lock(); let sentSuccessfully = sendOK; lock.unlock()
        try require(sentSuccessfully && waiting.plaintextWriteProcessedBytes == 1
                    && waiting.plaintextReadRequests == 1 && waiting.plaintextReadDeliveredBytes == 0,
                    "silent peer evidence fabricated application receipt")
        if scenario == "held-write" {
            try require(waiting.rawWriteRequestedBytes > waiting.rawWriteCompletedBytes,
                        "local contentProcessed was incorrectly counted as completed carrier write")
            raw.releaseWrite()
        } else {
            try require(waiting.rawWriteRequestedBytes > 0 && waiting.rawWriteCompletedBytes > 0,
                        "successful raw write callback was omitted")
        }
        stream.cancel()
        try wait(readDone, "cancellation did not complete the existing plaintext read")
        lock.lock(); let callbacks = readCount; lock.unlock()
        try require(callbacks == 1, "passive progress changed cancellation callback ownership")
        print("PASS loopback-\(scenario) localProcessingNotRemoteACK=true plaintextBytes=0 cancelCallbacks=1 assertions=\(assertions)")
    }

    static func main() throws {
        let args = CommandLine.arguments
        guard args.contains("--dns-adaptive-loopback-test") else { throw Failure(text: "explicit local fixture mode required") }
        if args.count > 1 && args[1] == "memory" { try memory(); return }
        guard args.count >= 5, let port = UInt16(args[1]),
              let anchor = SecCertificateCreateWithData(nil, try Data(contentsOf: URL(fileURLWithPath: args[2])) as CFData) else {
            throw Failure(text: "fixed loopback arguments missing")
        }
        try loopback(port: port, anchor: anchor, scenario: args[3])
    }
}

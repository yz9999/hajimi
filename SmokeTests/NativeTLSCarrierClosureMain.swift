import Foundation
import Network
import Security

/// Appended to the unchanged extracted production declarations and existing
/// loopback peer. All owner accessors below exist only in this smoke source.
private final class NativeCarrierMemoryPeer: ByteTransport {
    private let lock = NSLock()
    private var reader: ((Data?, Bool, Error?) -> Void)?
    private var closes = 0
    func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock(); precondition(reader == nil); reader = completion; lock.unlock()
    }
    func emit(_ data: Data?, complete: Bool, error: Error? = nil) {
        lock.lock(); let done = reader; reader = nil; lock.unlock()
        precondition(done != nil); done?(data, complete, error)
    }
    func cancel() { lock.lock(); closes += 1; reader = nil; lock.unlock() }
    var cancellations: Int { lock.lock(); defer { lock.unlock() }; return closes }
}

private extension NestedNetworkTLSByteTransport {
    static func fixtureOwner(raw: any ByteTransport, observe: @escaping (Error) -> Void,
                             completion: @escaping (Result<any ByteTransport, Error>) -> Void)
        -> NestedNetworkTLSByteTransport {
        let owner = NestedNetworkTLSByteTransport(raw: raw, serverName: "127.0.0.1",
            skipCertificateVerification: false, alpn: ["http/1.1"], defaultHTTPALPN: false,
            fixtureAnchor: nil, fixtureTrustObserver: nil, failureObserver: observe, attemptTrace: nil)
        owner.queue.sync {
            owner.completion = completion; owner.upgradeKeepAlive = owner
            let local = NWConnection(host: "127.0.0.1", port: 1, using: .tcp)
            owner.localCipherConnection = local
            owner.pumpRemoteCiphertext(local)
        }
        return owner
    }
    func fixtureReady() { queue.async { self.publishReady() } }
    func fixtureOriginalError(_ error: Error) { failures.observe(error) }
    func fixtureDrain() { queue.sync {} }
    var fixtureReleased: Bool {
        queue.sync {
            cancelled && completion == nil && upgradeKeepAlive == nil
                && listener == nil && localCipherConnection == nil && tlsConnection == nil
        }
    }
    func fixtureHold() -> (DispatchSemaphore, DispatchSemaphore) {
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        queue.async { entered.signal(); _ = release.wait(timeout: .now() + 3) }
        return (entered, release)
    }
}

extension NativeTLSLeaseFailureMain {
    private static func carrierMemoryCases() throws {
        let ingress = NativeTLSCarrierIngress()
        let empty = ingress.observe(bytes: 0, complete: false, error: nil)
        try require(empty.peerCiphertextBytes == 0 && !empty.cleanEOF
                    && empty.rejectionError(originalError: nil) == nil,
                    "nonterminal empty read ended the carrier")
        ingress.observe(bytes: 7, complete: false, error: nil)
        let ended = ingress.observe(bytes: 0, complete: true, error: nil)
        try require(ended.peerCiphertextBytes == 7 && !ended.endedWithoutPeerCiphertext,
                    "empty EOF forgot previous peer ciphertext")
        try require(kind(ended.rejectionError(originalError: nil)) == "app.hajimi.nested-tls-carrier:1",
                    "new use of ended carrier was permitted")
        let rawError = NSError(domain: "FixedCarrierFixture", code: 91)
        ingress.observe(bytes: 3, complete: true, error: rawError)
        try require((ingress.snapshot.rejectionError(originalError: nil) as NSError?) === rawError,
                    "ingress lost its exact original raw error")
        let original = NWError.tls(-9807)
        try require(kind(ingress.snapshot.rejectionError(originalError: original)) == kind(original),
                    "carrier EOF displaced an admitted native authentication error")
        let saturated = NativeTLSCarrierIngress()
        for _ in 0..<3 { saturated.observe(bytes: Int.max, complete: false, error: nil) }
        try require(saturated.snapshot.peerCiphertextBytes == UInt64.max,
                    "peer ciphertext counter wrapped")
        for reason in [NativeTLSCarrierClosureError.closedBeforeUse, .closedWithoutPeerCiphertext] {
            try require(EncryptedDNSQueryFailure.classify(reason) == .other
                        && !EncryptedDNSQueryFailure.classify(reason).permitsProxyFallback,
                        "carrier closure allowed plaintext DNS downgrade")
            let captured = DNSAttemptErrorSnapshot.capture(reason)
            try require(captured.codes.first == DNSAttemptErrorCode(domain: NativeTLSCarrierClosureError.errorDomain,
                                                                   code: reason.rawValue),
                        "controlled carrier closure lost its fixed original code")
        }
        print("PASS memory=ingress-count-error-precedence-and-denial")

        for scenario in ["zero-eof", "ready-before-forward", "ready-with-final-bytes", "auth-first", "raw-error-first", "ready-auth"] {
            let peer = NativeCarrierMemoryPeer(), done = DispatchSemaphore(value: 0), lock = NSLock()
            var outcomes: [Result<any ByteTransport, Error>] = [], observed: [String] = []
            let owner = NestedNetworkTLSByteTransport.fixtureOwner(raw: peer, observe: { error in
                lock.lock(); observed.append(kind(error)); lock.unlock()
            }, completion: { result in
                lock.lock(); outcomes.append(result); lock.unlock(); done.signal()
            })
            let nativeError: Error = scenario == "raw-error-first" ? NWError.posix(.ECONNRESET) : NWError.tls(-9807)
            if scenario == "auth-first" || scenario == "ready-auth" { owner.fixtureOriginalError(nativeError) }
            if scenario == "ready-before-forward" || scenario == "ready-with-final-bytes" {
                let (entered, release) = owner.fixtureHold()
                try wait(entered, "could not hold the controlled owner queue")
                owner.fixtureReady()
                peer.emit(scenario == "ready-with-final-bytes" ? Data([1, 2, 3]) : nil, complete: true)
                release.signal()
            } else if scenario == "ready-auth" { owner.fixtureReady() }
            else { peer.emit(nil, complete: true, error: scenario == "raw-error-first" ? nativeError : nil) }
            try wait(done, "pending carrier did not acknowledge exactly one terminal result")
            owner.fixtureReady(); owner.fixtureDrain()
            lock.lock(); let results = outcomes, admissions = observed; lock.unlock()
            try require(results.count == 1, "ready/EOF race duplicated the pending completion")
            guard case .failure(let failure) = results[0] else {
                throw Failure(text: "ended or failed raw carrier became a usable TLS success")
            }
            let expected = ["auth-first", "raw-error-first", "ready-auth"].contains(scenario) ? kind(nativeError)
                : "app.hajimi.nested-tls-carrier:\(scenario == "zero-eof" ? 2 : 1)"
            try require(kind(failure) == expected && admissions.allSatisfy { $0 == expected },
                        "terminal carrier result erased an original native verdict")
            try require(peer.cancellations == 1 && owner.fixtureReleased,
                        "pending closure duplicated raw close or retained native owner resources")
            print("PASS memory=\(scenario) result=\(kind(failure)) callbacks=1 rawCloses=1 released=true")
        }
    }

    private static func carrierFinalRecord(_ stream: any NativeOutboundByteStream, raw: Raw,
                                           attempt: AttemptProbe, rejectNextSend: Bool) throws {
        func read(_ expected: UInt8) throws -> Bool {
            let done = DispatchSemaphore(value: 0), lock = NSLock()
            var value: Data?, ended = false, failure: Error?
            stream.receive(maximum: 1024) { data, eof, error in
                lock.lock(); value = data; ended = eof; failure = error; lock.unlock(); done.signal()
            }
            try wait(done, "final application TLS record did not reach its existing reader")
            lock.lock(); let data = value, eof = ended, error = failure; lock.unlock()
            try require(data == Data([expected]) && error == nil,
                        "last TLS plaintext was discarded: bytes=\(data?.count ?? -1) error=\(kind(error))")
            return eof
        }
        func send(_ byte: UInt8) throws {
            let done = DispatchSemaphore(value: 0), lock = NSLock()
            var result: Error?
            stream.send(Data([byte])) { error in lock.lock(); result = error; lock.unlock(); done.signal() }
            try wait(done, "verified application send did not finish")
            lock.lock(); let error = result; lock.unlock()
            try require(error == nil, "verified application send failed: \(kind(error))")
        }
        try send(65)
        try require(try !read(65), "first verified TLS exchange ended early")
        raw.finishNextReadWithEOF()
        try send(66)
        try wait(raw.finalCiphertextObserved, "peer did not combine a final encrypted record and FIN")
        if rejectNextSend {
            let done = DispatchSemaphore(value: 0), lock = NSLock()
            var failure: Error?, callbacks = 0
            stream.send(Data([67])) { error in
                lock.lock(); failure = error; callbacks += 1; lock.unlock(); done.signal()
            }
            try wait(done, "new application query was not rejected after EOF ingress")
            lock.lock(); let error = failure, count = callbacks; lock.unlock()
            try require(kind(error) == "app.hajimi.nested-tls-carrier:1" && count == 1,
                        "late caller sent a new query on an already ended carrier")
            try require(error.map(EncryptedDNSQueryFailure.classify) == .other,
                        "new-query EOF rejection permitted privacy downgrade")
        }
        let ended = try read(66)
        if !ended {
            let done = DispatchSemaphore(value: 0), lock = NSLock()
            var valid = false, failure: Error?
            stream.receive(maximum: 1024) { data, eof, error in
                lock.lock(); valid = eof && data?.isEmpty != false; failure = error; lock.unlock(); done.signal()
            }
            try wait(done, "final ciphertext FIN did not finish the existing reader")
            lock.lock(); let validEOF = valid, error = failure; lock.unlock()
            try require(validEOF && error == nil, "final plaintext EOF was relabeled: \(kind(error))")
        }
        try require(raw.finalCiphertextByteCount > 1, "last record fixture omitted ciphertext")
        let origin = try attempt.requireOrigin("eof", ready: true)
        try require(attempt.snapshot.observations[origin].peerCiphertextBytes ?? 0 > 1,
                    "raw EOF lost its accumulated numeric ciphertext receipt")
        try require(attempt.snapshot.firstError == nil, "a rejected new send poisoned the existing read")
        print("PASS loopback=final-record rejectNewSend=\(rejectNextSend) finalPlaintext=preserved")
    }

    static func carrierMain() throws {
        let args = CommandLine.arguments
        guard args.count >= 6 else { throw Failure(text: "carrier fixture arguments missing") }
        if args[4] == "memory" { try carrierMemoryCases(); return }
        if ["handshake", "pending", "late", "pool"].contains(args[4]) { try legacyMain(); return }
        guard let port = UInt16(args[1]), let anchor = SecCertificateCreateWithData(nil,
            try Data(contentsOf: URL(fileURLWithPath: args[2])) as CFData) else {
            throw Failure(text: "controlled loopback certificate missing")
        }
        let scenario = args[4], raw = Raw(port)
        let original = Probe(), attempt = AttemptProbe()
        try raw.start(); defer { raw.cancel() }
        if scenario == "handshake-final" || scenario == "wrong-san-final" { raw.finishNextReadWithEOF() }
        if scenario == "wrong-san" || scenario == "wrong-san-final" || scenario == "handshake-final" {
            let done = DispatchSemaphore(value: 0), lock = NSLock()
            var outcome: Result<any ByteTransport, Error>?, callbacks = 0
            let cancel = NestedNetworkTLSByteTransport.upgrade(raw: OutboundStreamTransport(raw),
                serverName: "127.0.0.1", skipCertificateVerification: false, alpn: ["http/1.1"],
                defaultHTTPALPN: false, fixtureAnchor: anchor, failureObserver: original.observe,
                attemptTrace: attempt.trace) { result in
                lock.lock(); outcome = result; callbacks += 1; lock.unlock(); done.signal()
            }
            defer { cancel() }
            try wait(done, "peer certificate/EOF did not finish its platform TLS verdict")
            lock.lock(); let result = outcome, count = callbacks; lock.unlock()
            guard case .failure(let error)? = result else {
                throw Failure(text: "closed or wrong-identity TLS handshake was handed off")
            }
            try require(count == 1, "handshake terminal result was duplicated")
            if scenario != "handshake-final" {
                guard let native = error as? NWError, case .tls = native else {
                    throw Failure(text: "real certificate denial was replaced by \(kind(error))")
                }
                try require(EncryptedDNSQueryFailure.classify(error) == .authentication,
                            "certificate denial no longer blocked downgrade")
            }
            if scenario != "wrong-san" {
                let snapshot = attempt.snapshot
                guard let eof = snapshot.observations.first(where: { $0.event == .rawEOF }) else {
                    throw Failure(text: "final handshake record did not carry EOF")
                }
                try require(eof.peerCiphertextBytes ?? 0 > 0,
                            "final handshake fixture did not deliver real peer ciphertext")
                try require(kind(error) != "app.hajimi.nested-tls-carrier:2",
                            "peer ciphertext was incorrectly treated as an empty first read")
            }
            print("PASS loopback=\(scenario) result=\(kind(error)) callbacks=1")
            return
        }
        let stream = try upgraded(raw, anchor: anchor, original: original, attempt: attempt)
        defer { stream.cancel() }
        try carrierFinalRecord(stream, raw: raw, attempt: attempt, rejectNextSend: scenario == "late-send")
    }

    static func main() {
        do { try carrierMain() }
        catch {
            FileHandle.standardError.write(Data(("CARRIER FIXTURE FAILURE: \(error)\n").utf8))
            exit(1)
        }
    }
}

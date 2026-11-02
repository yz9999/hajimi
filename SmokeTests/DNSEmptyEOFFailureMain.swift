import Foundation
import Network
import Darwin

/// Runs real resolver/request/pool code with memory byte streams. No network
/// listener or external address is used, including for the proxy TCP cases.
@main
private enum DNSEmptyEOFFailureMain {
    private struct Failure: Error { let text: String }
    private enum Kind: String { case doh, dot, proxyTCP }
    private struct Event {
        let data: Data?
        let complete: Bool
        let error: Error?
    }
    private final class Peer: NativeOutboundByteStream {
        typealias Handler = (Peer, Data, Int, @escaping (Error?) -> Void) -> Void
        private let lock = NSLock()
        private var handler: Handler?
        private var pending: ((Data?, Bool, Error?) -> Void)?
        private var events: [Event] = []
        private var stopped = false, writes = 0
        init(_ handler: @escaping Handler) { self.handler = handler }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock()
            guard !stopped, let handler else {
                lock.unlock(); completion(NativeOutboundError.cancelled); return
            }
            writes += 1; let count = writes; lock.unlock()
            handler(self, data, count, completion)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped, pending == nil else {
                lock.unlock(); completion(nil, true, NativeOutboundError.cancelled); return
            }
            pending = completion
            drainLocked()
        }
        func emit(_ data: Data?, complete: Bool = false, error: Error? = nil) {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            events.append(Event(data: data, complete: complete, error: error))
            drainLocked()
        }
        private func drainLocked() {
            guard let pending, !events.isEmpty else { lock.unlock(); return }
            self.pending = nil
            let event = events.removeFirst(); lock.unlock()
            pending(event.data, event.complete, event.error)
        }
        func cancel() {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            stopped = true; handler = nil; events.removeAll()
            let pending = self.pending; self.pending = nil; lock.unlock()
            pending?(nil, true, NativeOutboundError.cancelled)
        }
        var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
        var sendCount: Int { lock.lock(); defer { lock.unlock() }; return writes }
    }
    private final class Probe {
        private let lock = NSLock()
        private let factory: (Int, @escaping (Error) -> Void) -> Peer
        private var peers: [Peer] = []
        init(_ factory: @escaping (Int, @escaping (Error) -> Void) -> Peer) { self.factory = factory }
        var dialer: MetadataAwareEncryptedDNSStreamDialer {
            { [self] _, _, _, _, _, observe, done in
                lock.lock()
                let peer = factory(peers.count, observe); peers.append(peer)
                lock.unlock()
                done(.success(peer))
                return nil
            }
        }
        var streams: [Peer] { lock.lock(); defer { lock.unlock() }; return peers }
    }
    private struct Observation {
        let result: Result<Data, EncryptedDNSQueryFailure>
        let barriers: [EncryptedDNSQueryFailure]
        let evidence: [DNSQueryTransportEvidence]
    }
    private final class Owner {
        let kind: Kind, probe: Probe
        let budget = SOCKSUDPGlobalBudget(resources: 16, packets: 0, bytes: 0)
        private let resolve: (Data, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                              @escaping (DNSProxyFallbackBarrier) -> Void,
                              @escaping (DNSQueryTransportEvidence) -> Void) -> UUID?
        private let cancelAll: () -> Void
        private let cancelOne: (UUID, @escaping () -> Void) -> Void
        init(_ kind: Kind, probe: Probe, timeout: DispatchTimeInterval = .seconds(2)) {
            self.kind = kind; self.probe = probe
            switch kind {
            case .doh:
                let resolver = DoHResolver(endpoint: DoHEndpoint("https://memory.invalid/dns-query#203.0.113.53")!,
                    metadataStreamDialer: probe.dialer, bootstrapTimeout: timeout, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0, completion: $1, downgradeBarrier: $2, transportEvidence: $3) }
                cancelAll = { resolver.cancel() }
                cancelOne = { resolver.cancel($0, completion: $1) }
            case .dot:
                let resolver = DoTResolver(endpoint: DoTEndpoint("tls://memory.invalid#203.0.113.53")!,
                    metadataStreamDialer: probe.dialer, requestTimeout: timeout, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0, completion: $1, downgradeBarrier: $2, transportEvidence: $3) }
                cancelAll = { resolver.cancel() }
                cancelOne = { resolver.cancel($0, completion: $1) }
            case .proxyTCP:
                let resolver = ProxyTCPDNSResolver(server: DNSProxyFallbackServer("203.0.113.53:53")!,
                    metadataStreamDialer: probe.dialer, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0,
                    absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2, permitted: { true },
                    completion: $1, downgradeBarrier: $2, transportEvidence: $3) }
                cancelAll = { resolver.cancel() }
                cancelOne = { resolver.cancel($0, completion: $1) }
            }
        }
        func query(_ query: Data) throws -> Observation {
            let finished = DispatchSemaphore(value: 0), lock = NSLock()
            var result: Result<Data, EncryptedDNSQueryFailure>?
            var barriers: [EncryptedDNSQueryFailure] = [], evidence: [DNSQueryTransportEvidence] = []
            _ = resolve(query, { value in
                lock.lock(); result = value; lock.unlock(); finished.signal()
            }, { barrier in
                guard case .failure(let error) = barrier else { return }
                lock.lock(); barriers.append(EncryptedDNSQueryFailure.classify(error)); lock.unlock()
            }, { value in
                lock.lock(); evidence.append(value); lock.unlock()
            })
            guard finished.wait(timeout: .now() + 3) == .success else {
                throw Failure(text: "memory resolver did not complete")
            }
            lock.lock(); defer { lock.unlock() }
            guard let result else { throw Failure(text: "completion did not preserve its result") }
            return Observation(result: result, barriers: barriers, evidence: evidence)
        }
        func close() -> Bool {
            cancelAll()
            let drained = DispatchSemaphore(value: 0)
            // The absent request's real owner-queue ACK follows pool teardown.
            cancelOne(UUID()) { drained.signal() }
            return drained.wait(timeout: .now() + 1) == .success
                && budget.usage.resources == 0 && probe.streams.allSatisfy(\.cancelled)
        }
        deinit { cancelAll() }
    }

    private static var checks = 0, failed: [String] = []
    private static func require(_ condition: Bool, _ message: String) throws {
        checks += 1
        if !condition { throw Failure(text: message) }
    }
    private static func failure(_ observation: Observation) -> EncryptedDNSQueryFailure? {
        if case .failure(let reason) = observation.result { return reason }
        return nil
    }
    private static func query(_ id: UInt16) -> Data {
        DNSMessageInspection.query(for: "empty-eof.memory.invalid", type: 1, id: id)!
    }
    private static func response(_ wire: Data, kind: Kind) -> Data {
        let query: Data
        if kind == .doh {
            guard let boundary = wire.range(of: Data("\r\n\r\n".utf8)) else { return Data() }
            query = Data(wire[boundary.upperBound...])
        } else { query = Data(wire.dropFirst(2)) }
        var answer = query; answer[2] = 0x81; answer[3] = 0x80
        if kind == .doh {
            return Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(answer.count)\r\n\r\n".utf8) + answer
        }
        return Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer
    }
    private static func check(_ name: String, _ body: () throws -> Void) {
        do { try body(); print("PASS " + name) }
        catch {
            failed.append(name)
            let message = (error as? Failure)?.text ?? String(describing: error)
            print("FAIL " + name + ": " + message)
        }
    }
    private static func single(_ kind: Kind, data: Data?, complete: Bool = true,
                               error: Error? = nil, admitted: Error? = nil) throws -> Observation {
        let probe = Probe { _, observe in Peer { peer, _, _, sent in
            if let admitted { observe(admitted) }
            sent(nil); peer.emit(data, complete: complete, error: error)
        } }
        let owner = Owner(kind, probe: probe)
        let result = try owner.query(query(1))
        try require(owner.close(), "resolver close leaked an active stream or global reservation")
        try require(probe.streams.count == 1 && probe.streams[0].sendCount == 1,
                    "a fresh terminal response redialed or repeated its query")
        return result
    }
    private static func dohFreshEmpty() {
        for emptyData in [false, true] {
            check(emptyData ? "doh-fresh-empty-data-eof" : "doh-fresh-nil-empty-eof") {
                let result = try single(.doh, data: emptyData ? Data() : nil)
                try require(failure(result) == .network,
                            "clean zero-response EOF must be network; observed \(String(describing: failure(result)))")
                try require(result.barriers.isEmpty, "clean no-response EOF invented a malformed/authentication denial")
                try require(result.evidence == [.fresh], "fresh EOF changed transport evidence")
            }
        }
    }
    private static func reusedRetry(kind: Kind, freshEOF: Bool) throws {
        let probe = Probe { dial, _ in Peer { peer, wire, number, sent in
            sent(nil)
            if dial == 0 && number == 1 { peer.emit(response(wire, kind: kind)) }
            else if dial == 0 || freshEOF { peer.emit(nil, complete: true) }
            else { peer.emit(response(wire, kind: kind)) }
        } }
        let owner = Owner(kind, probe: probe)
        let warm = try owner.query(query(2)), next = try owner.query(query(3))
        try require(owner.close(), "retry owner leaked its retained or borrowed stream")
        try require(failure(warm) == nil, "warmup query did not complete")
        try require(probe.streams.count == 2 && probe.streams[0].sendCount == 2
                    && probe.streams[1].sendCount == 1,
                    "empty idle EOF did not use exactly one fresh retry")
        try require(next.evidence == [.reused, .reusedThenFresh], "idle retry lost real reuse evidence")
        if freshEOF {
            try require(failure(next) == .network,
                        "fresh retry's clean zero-response EOF must be network; observed \(String(describing: failure(next)))")
            try require(next.barriers.isEmpty, "spent idle retry invented a deny barrier")
        } else {
            guard case .success(let answer) = next.result else { throw Failure(text: "fresh idle retry failed") }
            try require(DNSMessageInspection.responseMatchesQuery(answer, query: query(3)),
                        "fresh idle retry changed the new caller's DNS identity")
        }
    }
    private static func dohMalformedAndErrors() {
        check("doh-partial-header-body-and-http-status-stay-invalid") {
            let samples = [Data("HTTP/1.1 20".utf8),
                Data("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nabc".utf8),
                Data("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n".utf8),
                Data("HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".utf8)]
            for sample in samples {
                let result = try single(.doh, data: sample)
                try require(failure(result) == .invalidResponse && result.barriers.contains(.invalidResponse),
                            "partial/malformed HTTP bytes lost their terminal invalidResponse fence")
            }
        }
        check("doh-no-progress-without-eof-stays-denied") {
            let result = try single(.doh, data: Data(), complete: false)
            // PooledConnection records invalid metadata before returning its
            // existing opaque stream error. Preserve both existing decisions;
            // this callback is neither EOF nor a recoverable network failure.
            try require(failure(result) == .other && result.barriers.contains(.invalidResponse),
                        "empty nonterminal callback was accepted as a clean EOF or lost its deny fence")
        }
        check("doh-empty-final-callback-after-partial-bytes-stays-invalid") {
            for reused in [false, true] {
                for partial in [Data("HTTP/1.1 20".utf8),
                                Data("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nabc".utf8)] {
                    let probe = Probe { _, _ in Peer { peer, wire, number, sent in
                        sent(nil)
                        if reused && number == 1 { peer.emit(response(wire, kind: .doh)) }
                        else { peer.emit(partial); peer.emit(nil, complete: true) }
                    } }
                    let owner = Owner(.doh, probe: probe)
                    if reused { _ = try owner.query(query(7)) }
                    let result = try owner.query(query(8))
                    try require(owner.close(), "partial-then-empty response leaked a stream or reservation")
                    try require(failure(result) == .invalidResponse && result.barriers.contains(.invalidResponse),
                                "empty final callback hid previously received malformed HTTP bytes")
                    try require(probe.streams.count == 1 && probe.streams[0].sendCount == (reused ? 2 : 1),
                                "partial response bytes permitted another encrypted retry")
                }
            }
        }
        check("doh-original-native-errors-precede-empty-eof") {
            let nativeErrors: [(Error, EncryptedDNSQueryFailure)] = [
                (NWError.tls(-9807), .authentication), (NWError.tls(-9816), .authentication),
                (NWError.posix(.ECONNRESET), .network), (NativeOutboundError.connection("memory unknown error"), .other),
            ]
            for (error, expected) in nativeErrors {
                let result = try single(.doh, data: nil, error: error)
                try require(failure(result) == expected, "clean-EOF handling erased original native error \(error)")
                if expected == .authentication {
                    try require(result.barriers.contains(.authentication), "original TLS error lost its auth barrier")
                }
            }
            let result = try single(.doh, data: Data("HTTP/1.1 20".utf8), error: NWError.tls(-9807))
            try require(failure(result) == .authentication, "partial bytes outranked an admitted TLS authentication error")
        }
        for reason in [EncryptedDNSQueryFailure.authentication, .other] {
            check("doh-admitted-\(reason)-empty-eof") {
                let admitted: Error = reason == .other ? NativeOutboundError.connection("memory unknown failure") : reason
                let result = try single(.doh, data: nil, admitted: admitted)
                try require(failure(result) == reason,
                            "clean EOF erased existing \(reason) denial; observed \(String(describing: failure(result)))")
                try require(result.barriers.contains(reason), "native metadata lost its existing privacy barrier")
            }
        }
    }
    private static func validFinalEOF(kind: Kind) throws {
        let probe = Probe { _, _ in Peer { peer, wire, _, sent in
            sent(nil); peer.emit(response(wire, kind: kind), complete: true)
        } }
        let owner = Owner(kind, probe: probe)
        let result = try owner.query(query(4))
        try require(owner.close(), "valid final response retained a closed stream")
        guard case .success(let answer) = result.result else { throw Failure(text: "valid final DNS response was lost") }
        try require(DNSMessageInspection.responseMatchesQuery(answer, query: query(4)), "valid EOF reply lost its DNS identity")
    }
    private static func otherProtocolBoundaries(kind: Kind) throws {
        let empty = try single(kind, data: nil)
        try require(failure(empty) == .network && empty.barriers.isEmpty, "empty \(kind) EOF behavior changed")
        let partial = try single(kind, data: Data([0]))
        let expected: EncryptedDNSQueryFailure = kind == .proxyTCP ? .invalidResponse : .network
        try require(failure(partial) == expected, "partial \(kind) prefix behavior changed")
        let malformed = try single(kind, data: Data([0, 1, 0]))
        try require(failure(malformed) == .invalidResponse, "malformed \(kind) framing was accepted")
        for reason in [EncryptedDNSQueryFailure.authentication, .other] {
            let denied = try single(kind, data: nil, admitted: reason)
            try require(failure(denied) == reason && denied.barriers.contains(reason),
                        "empty \(kind) EOF erased an admitted \(reason) privacy fence")
        }
        try reusedRetry(kind: kind, freshEOF: false)
        try reusedRetry(kind: kind, freshEOF: true)
        try validFinalEOF(kind: kind)
    }
    private static func retryOriginalDeadline() throws {
        let probe = Probe { dial, _ in Peer { peer, wire, number, sent in
            sent(nil)
            if dial == 0 && number == 1 { peer.emit(response(wire, kind: .doh)) }
            else if dial == 0 { peer.emit(nil, complete: true) }
            // Fresh retry intentionally withholds its response; only the
            // original request timer can finish this actual resolver request.
        } }
        let owner = Owner(.doh, probe: probe, timeout: .milliseconds(80))
        let warm = try owner.query(query(5))
        let started = ProcessInfo.processInfo.systemUptime
        let result = try owner.query(query(6))
        let elapsed = ProcessInfo.processInfo.systemUptime - started
        try require(owner.close(), "timed-out idle retry leaked a stream or reservation")
        try require(failure(warm) == nil && failure(result) == .timeout,
                    "idle retry discarded its original request deadline")
        try require(elapsed >= 0.06 && elapsed < 0.5 && probe.streams.count == 2,
                    "idle retry restarted its timeout or dialed a third stream")
    }
    private static func responseMetadata() throws {
        for sample in 0..<7 {
            let kind: Kind = sample == 5 ? .dot : (sample == 6 ? .proxyTCP : .doh)
            let before = Set(NetworkPerformanceDiagnostics.shared.snapshot().dnsQueryExchanges.map(\.id))
            let lock = NSLock()
            var wireCount = 0
            let probe = Probe { _, _ in Peer { peer, request, _, sent in
                var wire: Data?
                switch sample {
                case 0: wire = nil
                case 1: wire = Data("HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".utf8)
                case 2: wire = Data("HTTP/1.1 20".utf8)
                case 5, 6: wire = Data([0, 1, 0])
                default:
                    var reply = response(request, kind: .doh)
                    let body = reply.range(of: Data("\r\n\r\n".utf8))!.upperBound
                    if sample == 3 { reply[body] ^= 1 }
                    if sample == 4 { reply[body + 3] = 0x85 }
                    wire = reply
                }
                lock.lock(); wireCount = wire?.count ?? 0; lock.unlock()
                sent(nil); peer.emit(wire, complete: true)
            } }
            let owner = Owner(kind, probe: probe)
            _ = try owner.query(query(9))
            try require(owner.close(), "metadata fixture leaked its actual resolver")
            let exchanges = NetworkPerformanceDiagnostics.shared.snapshot().dnsQueryExchanges.filter { !before.contains($0.id) }
            try require(exchanges.count == 1, "response metadata invented or lost a logical exchange")
            guard let exchange = exchanges.first else { throw Failure(text: "missing exchange") }
            lock.lock(); let expectedBytes = wireCount; lock.unlock()
            let status: Int? = sample == 1 ? 503 : ([3, 4].contains(sample) ? 200 : nil)
            let code: UInt8? = sample == 3 ? 0 : (sample == 4 ? 5 : nil)
            let rejection: String? = sample == 0 ? "emptyResponse"
                : ([1, 2].contains(sample) ? "httpFraming"
                    : (sample == 3 ? "dnsIdentity" : ([5, 6].contains(sample) ? "streamFraming" : nil)))
            try require(exchange.httpStatusCode == status, "HTTP numeric status was lost or fabricated")
            try require(exchange.responseBytes == expectedBytes, "response count omitted HTTP headers or stream framing")
            try require(exchange.dnsResponseCode == code, "DNS numeric response code was lost before identity rejection")
            try require(exchange.responseRejection == rejection, "response rejection did not use its fixed source category")
        }
    }
    static func main() {
        dohFreshEmpty()
        check("doh-reused-empty-eof-retries-once-to-success") { try reusedRetry(kind: .doh, freshEOF: false) }
        check("doh-reused-retry-fresh-empty-eof") { try reusedRetry(kind: .doh, freshEOF: true) }
        dohMalformedAndErrors()
        check("doh-valid-final-response-with-eof") { try validFinalEOF(kind: .doh) }
        check("dot-existing-eof-framing-and-denial-boundaries") { try otherProtocolBoundaries(kind: .dot) }
        check("proxy-tcp-existing-eof-framing-and-denial-boundaries") { try otherProtocolBoundaries(kind: .proxyTCP) }
        check("doh-idle-retry-retains-original-deadline") { try retryOriginalDeadline() }
        check("numeric-response-evidence-and-fixed-rejection-categories") { try responseMetadata() }
        let report: [String: Any] = ["checks": checks, "failedGroups": failed,
                                   "realResolvers": ["DoHResolver", "DoTResolver", "ProxyTCPDNSResolver"],
                                   "networkAccess": false]
        print(String(data: try! JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!)
        if !failed.isEmpty { exit(1) }
    }
}

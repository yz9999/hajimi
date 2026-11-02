import Foundation
import Network
import Darwin

/// Production DNS framing and real resolver ownership with memory peers only.
@main
private enum DNSEDEMetadataMain {
    private struct Failure: Error { let text: String }
    private enum Kind: String, CaseIterable { case doh, dot, proxyTCP }
    private struct Event { let data: Data?; let complete: Bool; let error: Error? }
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
            guard !stopped, let handler else { lock.unlock(); completion(NativeOutboundError.cancelled); return }
            writes += 1; let number = writes; lock.unlock()
            handler(self, data, number, completion)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped, pending == nil else { lock.unlock(); completion(nil, true, NativeOutboundError.cancelled); return }
            pending = completion; drainLocked()
        }
        func emit(_ data: Data?, complete: Bool = false, error: Error? = nil) {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            events.append(Event(data: data, complete: complete, error: error)); drainLocked()
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
        private let factory: (Int) -> Result<Peer, Error>
        private var peers: [Peer] = []
        private var dials = 0
        init(_ factory: @escaping (Int) -> Result<Peer, Error>) { self.factory = factory }
        var dialer: MetadataAwareEncryptedDNSStreamDialer {
            { [self] _, _, _, _, _, _, done in
                lock.lock(); let number = dials; dials += 1; lock.unlock()
                switch factory(number) {
                case .failure(let error): done(.failure(error))
                case .success(let peer):
                    lock.lock(); peers.append(peer); lock.unlock(); done(.success(peer))
                }
                return nil
            }
        }
        var streams: [Peer] { lock.lock(); defer { lock.unlock() }; return peers }
        var dialCount: Int { lock.lock(); defer { lock.unlock() }; return dials }
    }
    private final class Completion {
        private let lock = NSLock()
        private let signal = DispatchSemaphore(value: 0)
        private var value: Result<Data, EncryptedDNSQueryFailure>?
        private var calls = 0
        func receive(_ result: Result<Data, EncryptedDNSQueryFailure>) {
            lock.lock(); value = result; calls += 1; lock.unlock(); signal.signal()
        }
        func wait() throws -> Result<Data, EncryptedDNSQueryFailure> {
            guard signal.wait(timeout: .now() + 2) == .success else { throw Failure(text: "memory request did not finish") }
            lock.lock(); defer { lock.unlock() }
            guard let value, calls == 1 else { throw Failure(text: "request did not complete exactly once") }
            return value
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return calls }
    }
    private final class Owner {
        let probe: Probe
        let budget = SOCKSUDPGlobalBudget(resources: 16, packets: 0, bytes: 0)
        private let resolve: (Data, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID?
        private let cancelAll: () -> Void
        private let cancelOne: (UUID, @escaping () -> Void) -> Void
        init(_ kind: Kind, probe: Probe, shortDeadline: Bool = false) {
            self.probe = probe
            let timeout: DispatchTimeInterval = shortDeadline ? .milliseconds(60) : .seconds(1)
            switch kind {
            case .doh:
                let resolver = DoHResolver(endpoint: DoHEndpoint("https://memory.invalid/dns-query#203.0.113.53")!,
                    metadataStreamDialer: probe.dialer, bootstrapTimeout: timeout, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0, completion: $1) }
                cancelAll = { resolver.cancel() }; cancelOne = { resolver.cancel($0, completion: $1) }
            case .dot:
                let resolver = DoTResolver(endpoint: DoTEndpoint("tls://memory.invalid#203.0.113.53")!,
                    metadataStreamDialer: probe.dialer, requestTimeout: timeout, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0, completion: $1) }
                cancelAll = { resolver.cancel() }; cancelOne = { resolver.cancel($0, completion: $1) }
            case .proxyTCP:
                let resolver = ProxyTCPDNSResolver(server: DNSProxyFallbackServer("203.0.113.53:53")!,
                    metadataStreamDialer: probe.dialer, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0,
                    absoluteDeadline: ProcessInfo.processInfo.systemUptime + (shortDeadline ? 0.06 : 1),
                    permitted: { true }, completion: $1) }
                cancelAll = { resolver.cancel() }; cancelOne = { resolver.cancel($0, completion: $1) }
            }
        }
        func begin(_ query: Data, completion: Completion) -> UUID? { resolve(query, completion.receive) }
        func query(_ query: Data) throws -> Result<Data, EncryptedDNSQueryFailure> {
            let completion = Completion(); _ = begin(query, completion: completion); return try completion.wait()
        }
        func cancel(_ id: UUID) throws {
            let signal = DispatchSemaphore(value: 0); cancelOne(id) { signal.signal() }
            try DNSEDEMetadataMain.require(signal.wait(timeout: .now() + 1) == .success, "cancel did not acknowledge ownership")
        }
        func close() throws {
            cancelAll()
            let signal = DispatchSemaphore(value: 0); cancelOne(UUID()) { signal.signal() }
            try DNSEDEMetadataMain.require(signal.wait(timeout: .now() + 1) == .success, "pool close did not drain")
            try DNSEDEMetadataMain.require(budget.usage.resources == 0 && probe.streams.allSatisfy(\.cancelled), "close leaked stream or admission")
        }
        deinit { cancelAll() }
    }

    private static var checks = 0, groups = 0, failed: [String] = []
    private static var boundedScanBenchmark: [String: Any] = [:]
    private static let privateName = "qname-must-not-export.memory.invalid"
    private static let privateText = Data("private-extra-text-SECRET-987654\r\nAuthorization: secret".utf8) + Data([0xff, 0, 0xfe])
    private static func require(_ value: Bool, _ text: String) throws {
        checks += 1; if !value { throw Failure(text: text) }
    }
    private static func check(_ name: String, _ body: () throws -> Void) {
        groups += 1
        do { try body(); print("PASS " + name) }
        catch { failed.append(name); print("FAIL " + name + ": " + ((error as? Failure)?.text ?? String(describing: error))) }
    }
    private static func codes(_ response: Data) -> [UInt16]? {
        #if BUILD19_BASELINE
        return nil
        #else
        return DNSMessageInspection.extendedDNSErrorCodes(in: response)
        #endif
    }
    private static func questionType(_ exchange: DNSQueryExchangeSnapshot) -> UInt16? {
        #if BUILD19_BASELINE
        return nil
        #else
        return exchange.queryType
        #endif
    }
    private static func responseCodes(_ exchange: DNSQueryExchangeSnapshot) -> [UInt16]? {
        #if BUILD19_BASELINE
        return nil
        #else
        return exchange.extendedDNSErrorCodes
        #endif
    }
    private static func append16(_ value: UInt16, _ data: inout Data) {
        data.append(UInt8(value >> 8)); data.append(UInt8(value & 255))
    }
    private static func query(_ id: UInt16, type: UInt16 = 1) -> Data {
        DNSMessageInspection.query(for: privateName, type: type, id: id)!
    }
    private static func option(_ code: UInt16 = 15, body: Data) -> Data {
        var data = Data(); append16(code, &data); append16(UInt16(body.count), &data); data.append(body); return data
    }
    private static func ede(_ code: UInt16, extra: Data = Data()) -> Data {
        var body = Data(); append16(code, &body); body.append(extra); return option(body: body)
    }
    private static func record(owner: Data = Data([0]), type: UInt16 = 41,
                               version: UInt8 = 0, body: Data) -> Data {
        var data = owner; append16(type, &data); append16(1232, &data)
        data.append(contentsOf: [0, version, 0, 0]); append16(UInt16(body.count), &data); data.append(body); return data
    }
    private static func answer(_ query: Data, code: UInt8 = 0, answers: [Data] = [],
                               authorities: [Data] = [], additional: [Data] = []) -> Data {
        var data = query; data[2] = 0x81; data[3] = 0x80 | code
        for (offset, count) in [(6, answers.count), (8, authorities.count), (10, additional.count)] {
            data[offset] = UInt8(count >> 8); data[offset + 1] = UInt8(count & 255)
        }
        for rr in answers + authorities + additional { data.append(rr) }; return data
    }
    private static func requestBody(_ wire: Data, kind: Kind) -> Data {
        if kind == .doh {
            guard let boundary = wire.range(of: Data("\r\n\r\n".utf8)) else { return Data() }
            return Data(wire[boundary.upperBound...])
        }
        return Data(wire.dropFirst(2))
    }
    private static func frame(_ data: Data, kind: Kind) -> Data {
        if kind == .doh {
            return Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(data.count)\r\n\r\n".utf8) + data
        }
        var prefix = Data(); append16(UInt16(data.count), &prefix); return prefix + data
    }
    private static func newExchanges(since before: Set<UUID>) -> [DNSQueryExchangeSnapshot] {
        NetworkPerformanceDiagnostics.shared.snapshot().dnsQueryExchanges.filter { !before.contains($0.id) }
    }
    private static func exchangeIDs() -> Set<UUID> {
        Set(NetworkPerformanceDiagnostics.shared.snapshot().dnsQueryExchanges.map(\.id))
    }
    private static func checkPrivacy(_ exchange: DNSQueryExchangeSnapshot) throws {
        let encoded = try JSONEncoder().encode(exchange)
        let text = String(decoding: encoded, as: UTF8.self)
        try require(!text.contains(privateName) && !text.contains("private-extra-text")
                    && !text.contains("SECRET-987654") && !text.contains("Authorization"), "diagnostics retained question or EDE text")
    }
    private static func requireAnswer(_ result: Result<Data, EncryptedDNSQueryFailure>, query: Data,
                                      code: UInt8) throws {
        guard case .success(let data) = result else { throw Failure(text: "metadata changed response acceptance") }
        try require(DNSMessageInspection.responseMatchesQuery(data, query: query) && data[3] & 15 == code,
                    "metadata changed question identity or RCODE")
    }
    private static func requireFailure(_ result: Result<Data, EncryptedDNSQueryFailure>, _ expected: EncryptedDNSQueryFailure) throws {
        guard case .failure(let actual) = result else { throw Failure(text: "expected terminal failure") }
        try require(actual == expected, "metadata changed existing failure classification")
    }

    private static func parserCases() {
        let question = query(100), validOPT = record(body: ede(6, extra: privateText))
        let valid = answer(question, additional: [validOPT])
        check("parser-numeric-unknown-zero-dedup-and-text") {
            let response = answer(question, code: 2, additional: [record(body:
                ede(6, extra: privateText) + option(65000, body: privateText) + ede(6) + ede(23) + ede(65535) + ede(0))])
            try require(DNSMessageInspection.responseMatchesQuery(response, query: question), "fixture identity mismatch")
            try require(codes(response) == [6, 23, 65535, 0], "numeric EDE values lost, reordered, or text interpreted")
        }
        check("parser-caps-values-and-still-scans-remainder") {
            let many = (0..<12).reduce(Data()) { $0 + ede(UInt16($1)) }
            try require(codes(answer(question, additional: [record(body: many)])) == Array(0..<8).map(UInt16.init), "EDE numeric cap is not eight")
            try require(codes(answer(question, additional: [record(body: many + Data([0, 15, 0]))])) == nil,
                        "EDE cap skipped a later malformed option")
            try require(codes(answer(question, additional: [record(body: many), Data([0xc0])])) == nil,
                        "EDE cap skipped a later malformed record")
        }
        check("parser-no-ede-and-valid-compressed-other-records") {
            let ordinary = record(owner: Data([0xc0, 12]), type: 65000, body: Data([1, 2, 3]))
            try require(codes(answer(question)) == nil, "absent OPT invented EDE")
            try require(codes(answer(question, additional: [record(body: option(3, body: privateText))])) == nil,
                        "non-EDE option invented INFO-CODE")
            try require(codes(answer(question, answers: [ordinary], additional: [validOPT])) == [6],
                        "bounded ordinary RR framing or backward compression was rejected")
        }
        check("parser-malformed-opt-never-changes-identity-acceptance") {
            var badLength = validOPT; badLength[9] = 0xff; badLength[10] = 0xff
            let nonroot = record(owner: Data([0xc0, 12]), body: ede(6))
            let rootPointer = question.count - 5
            let compressedRoot = record(owner: Data([0xc0 | UInt8(rootPointer >> 8), UInt8(rootPointer & 255)]), body: ede(6))
            var truncatedFlag = valid; truncatedFlag[2] |= 2
            var trailing = valid; trailing.append(0)
            var wrongCount = valid; wrongCount[11] = 2
            let fixtures = [
                answer(question, additional: [validOPT, validOPT]),
                answer(question, answers: [validOPT]), answer(question, authorities: [validOPT]),
                answer(question, additional: [nonroot]), answer(question, additional: [compressedRoot]),
                answer(question, additional: [record(version: 1, body: ede(6))]),
                answer(question, additional: [badLength]),
                answer(question, additional: [record(body: option(body: Data()))]),
                answer(question, additional: [record(body: option(body: Data([1])))]),
                answer(question, additional: [record(body: Data([0, 15, 0, 3, 0, 6]))]),
                answer(question, additional: [record(body: Data([0, 15, 0]))]),
                truncatedFlag, trailing, wrongCount,
            ]
            for response in fixtures {
                try require(DNSMessageInspection.responseMatchesQuery(response, query: question), "metadata fixture changed old identity precondition")
                try require(codes(response) == nil, "malformed/unsupported OPT published EDE")
            }
        }
        check("parser-full-frame-name-length-and-truncation-validation") {
            for length in 0..<valid.count {
                try require(codes(Data(valid.prefix(length))) == nil, "truncated DNS framing published EDE")
            }
            let selfPointer = question.count + validOPT.count
            let loop = Data([0xc0 | UInt8(selfPointer >> 8), UInt8(selfPointer & 255)])
            let forwardPointer = selfPointer + 2
            let forward = Data([0xc0 | UInt8(forwardPointer >> 8), UInt8(forwardPointer & 255), 0])
            for owner in [loop, forward, Data([0x40]), Data([0x80]), Data([63, 1])] {
                let response = answer(question, additional: [validOPT, record(owner: owner, type: 65000, body: Data())])
                try require(codes(response) == nil, "invalid later owner name published earlier EDE")
            }
            var loopQuestion = valid; loopQuestion[12] = 0xc0; loopQuestion[13] = 12
            try require(codes(loopQuestion) == nil, "cyclic question compression published EDE")
            var oversizeCount = valid; oversizeCount[6] = 0x10; oversizeCount[7] = 1
            try require(codes(oversizeCount) == nil, "unbounded record count entered EDE scan")
        }
        check("parser-bounded-compressed-owner-work") {
            let longName = Array(repeating: "a", count: 127).joined(separator: ".")
            let question = DNSMessageInspection.query(for: longName, type: 1, id: 101)!
            let ordinary = record(owner: Data([0xc0, 12]), type: 65000, body: Data())
            var records = [record(body: ede(6))] + Array(repeating: ordinary, count: 4094)
            let size = question.count + records.reduce(0) { $0 + $1.count }
            records[1] = record(owner: Data([0xc0, 12]), type: 65000, body: Data(repeating: 0, count: 65_535 - size))
            let response = answer(question, additional: records)
            try require(response.count == 65_535 && DNSMessageInspection.responseMatchesQuery(response, query: question),
                        "compressed-name work fixture is not a complete valid-identity DNS frame")
            let began = ProcessInfo.processInfo.systemUptime
            for _ in 0..<100 {
                try require(codes(response) == nil, "name-work budget published partial EDE")
            }
            boundedScanBenchmark = ["bytes": response.count, "iterations": 100,
                "elapsedMilliseconds": (ProcessInfo.processInfo.systemUptime - began) * 1000]
        }
    }

    private static func resolverCases(_ kind: Kind) {
        for sample in 0..<5 {
            check(kind.rawValue + "-question-and-ede-case-\(sample)") {
                let qtype: UInt16 = [1, 28, 65, 65535, 255][sample]
                let question = query(UInt16(200 + sample), type: qtype)
                let responseCode: UInt8 = [0, 2, 0, 2, 0][sample]
                let extra = sample == 0 ? record(body: ede(6, extra: privateText) + ede(0) + ede(65535) + ede(6))
                    : (sample == 1 ? record(body: ede(9) + ede(23))
                       : (sample == 2 ? Data() : (sample == 3 ? record(body: option(body: Data([1]))) : record(body: ede(6)))))
                let probe = Probe { _ in .success(Peer { peer, wire, _, sent in
                    let original = requestBody(wire, kind: kind)
                    var response = answer(original, code: responseCode, additional: extra.isEmpty ? [] : [extra])
                    if sample == 4 { response[0] ^= 1 }
                    sent(nil); peer.emit(frame(response, kind: kind), complete: true)
                }) }
                let owner = Owner(kind, probe: probe), before = exchangeIDs()
                let result = try owner.query(question); try owner.close()
                if sample == 4 { try requireFailure(result, .invalidResponse) }
                else { try requireAnswer(result, query: question, code: responseCode) }
                let exchanges = newExchanges(since: before)
                try require(exchanges.count == 1, "metadata changed exchange count")
                let exchange = exchanges[0]
                try require(exchange.dnsResponseCode == responseCode, "metadata changed existing numeric RCODE")
                try require(exchange.responseRejection == (sample == 4 ? "dnsIdentity" : nil), "EDE changed existing rejection decision")
                try checkPrivacy(exchange)
                try require(questionType(exchange) == qtype, "QTYPE missing before real exchange")
                let expected: [UInt16]? = sample == 0 ? [6, 0, 65535] : (sample == 1 ? [9, 23] : nil)
                try require(responseCodes(exchange) == expected, "matched response EDE missing or untrusted response published EDE")
            }
        }
        check(kind.rawValue + "-qtype-before-dial-failure") {
            let probe = Probe { _ in .failure(NWError.posix(.ECONNRESET)) }
            let owner = Owner(kind, probe: probe), before = exchangeIDs()
            let result = try owner.query(query(300, type: 28)); try owner.close()
            try requireFailure(result, .network)
            let exchanges = newExchanges(since: before)
            try require(exchanges.count == 1 && probe.dialCount == 1, "dial failure lost exchange identity")
            try require(responseCodes(exchanges[0]) == nil && exchanges[0].dnsResponseCode == nil, "failed dial fabricated response metadata")
            try require(questionType(exchanges[0]) == 28, "dial failure erased initial QTYPE")
        }
        for freshEOF in [false, true] {
            check(kind.rawValue + "-reuse-retry-\(freshEOF ? "eof" : "answer")") {
                let probe = Probe { dial in .success(Peer { peer, wire, number, sent in
                    sent(nil)
                    if dial == 0 && number > 1 || (dial > 0 && freshEOF) { peer.emit(nil, complete: true); return }
                    let code: UInt16 = dial == 0 ? 6 : 23
                    peer.emit(frame(answer(requestBody(wire, kind: kind), additional: [record(body: ede(code, extra: privateText))]), kind: kind))
                }) }
                let owner = Owner(kind, probe: probe)
                let warm = try owner.query(query(310)); try requireAnswer(warm, query: query(310), code: 0)
                let before = exchangeIDs(), nextQuestion = query(311, type: 65)
                let result = try owner.query(nextQuestion); try owner.close()
                if freshEOF { try requireFailure(result, .network) }
                else { try requireAnswer(result, query: nextQuestion, code: 0) }
                let exchanges = newExchanges(since: before)
                try require(exchanges.count == 1 && probe.dialCount == 2, "idle retry changed original exchange or retry cap")
                try require(probe.streams[0].sendCount == 2 && probe.streams[1].sendCount == 1, "idle retry repeated a fresh attempt")
                try require(exchanges[0].reusedConnection && exchanges[0].physicalAttemptIDs.count == 1, "idle retry lost physical lineage")
                try checkPrivacy(exchanges[0])
                try require(questionType(exchanges[0]) == 65, "idle retry lost original QTYPE")
                try require(responseCodes(exchanges[0]) == (freshEOF ? nil : [23]), "idle retry reused the old response EDE")
            }
        }
        check(kind.rawValue + "-cancel-and-late-response") {
            let sent = DispatchSemaphore(value: 0)
            let probe = Probe { _ in .success(Peer { _, _, _, done in done(nil); sent.signal() }) }
            let owner = Owner(kind, probe: probe), before = exchangeIDs(), completion = Completion()
            let question = query(320, type: 65)
            guard let id = owner.begin(question, completion: completion) else { throw Failure(text: "cancel request not admitted") }
            try require(sent.wait(timeout: .now() + 1) == .success, "cancel fixture did not send")
            try owner.cancel(id); let result = try completion.wait()
            probe.streams[0].emit(frame(answer(question, additional: [record(body: ede(6))]), kind: kind))
            try owner.close(); try requireFailure(result, .cancelled)
            let exchanges = newExchanges(since: before)
            try require(exchanges.count == 1 && completion.count == 1, "late response changed cancelled completion")
            try require(responseCodes(exchanges[0]) == nil && exchanges[0].dnsResponseCode == nil, "late response published EDE after cancellation")
            try require(questionType(exchanges[0]) == 65, "cancellation erased QTYPE")
        }
        check(kind.rawValue + "-timeout-retains-question-only") {
            let probe = Probe { _ in .success(Peer { _, _, _, sent in sent(nil) }) }
            let owner = Owner(kind, probe: probe, shortDeadline: true), before = exchangeIDs()
            let result = try owner.query(query(321, type: 28)); try owner.close(); try requireFailure(result, .timeout)
            let exchanges = newExchanges(since: before)
            try require(exchanges.count == 1 && responseCodes(exchanges[0]) == nil, "timeout invented EDE")
            try require(questionType(exchanges[0]) == 28, "timeout erased QTYPE")
        }
    }
    static func main() {
        parserCases()
        for kind in Kind.allCases { resolverCases(kind) }
        let report: [String: Any] = ["groups": groups, "checks": checks, "failedGroups": failed,
            "realResolvers": ["DoHResolver", "DoTResolver", "ProxyTCPDNSResolver"], "networkAccess": false,
            "boundedScanBenchmark": boundedScanBenchmark]
        print(String(data: try! JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!)
        if !failed.isEmpty { exit(1) }
    }
}

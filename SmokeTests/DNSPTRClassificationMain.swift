import Foundation
import Network
import Darwin

/// Real DNS wire inspection, diagnostic encoding and resolver ownership. Every
/// byte stream and dial below is memory-only; native fallback is a fatal error.
@main
private enum DNSPTRClassificationMain {
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
            writes += 1; let count = writes; lock.unlock()
            handler(self, data, count, completion)
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
            let reader = pending; pending = nil; lock.unlock()
            reader?(nil, true, NativeOutboundError.cancelled)
        }
        var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
        var sendCount: Int { lock.lock(); defer { lock.unlock() }; return writes }
    }
    private final class Probe {
        private let lock = NSLock()
        private let factory: (Int) -> Result<Peer, Error>
        private var peers: [Peer] = []
        private var count = 0
        init(_ factory: @escaping (Int) -> Result<Peer, Error>) { self.factory = factory }
        var dialer: MetadataAwareEncryptedDNSStreamDialer {
            { [self] _, _, _, _, _, _, done in
                lock.lock(); let number = count; count += 1; lock.unlock()
                switch factory(number) {
                case .failure(let error): done(.failure(error))
                case .success(let peer):
                    lock.lock(); peers.append(peer); lock.unlock(); done(.success(peer))
                }
                return nil
            }
        }
        var streams: [Peer] { lock.lock(); defer { lock.unlock() }; return peers }
        var dialCount: Int { lock.lock(); defer { lock.unlock() }; return count }
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
            guard signal.wait(timeout: .now() + 2) == .success else { throw Failure(text: "memory resolver did not finish") }
            lock.lock(); defer { lock.unlock() }
            guard let value, calls == 1 else { throw Failure(text: "query did not complete exactly once") }
            return value
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return calls }
    }
    private final class Owner {
        let budget = SOCKSUDPGlobalBudget(resources: 16, packets: 0, bytes: 0)
        let probe: Probe
        private let resolve: (Data, DNSQueryExecutionContext, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID?
        private let cancelOne: (UUID, @escaping () -> Void) -> Void
        private let cancelAll: () -> Void
        init(_ kind: Kind, _ probe: Probe) {
            self.probe = probe
            switch kind {
            case .doh:
                let resolver = DoHResolver(endpoint: DoHEndpoint("https://ptr-private.memory.invalid/dns-query#203.0.113.53")!,
                    metadataStreamDialer: probe.dialer, bootstrapTimeout: .seconds(1), resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0, completion: $2, executionContext: $1) }
                cancelOne = { resolver.cancel($0, completion: $1) }; cancelAll = { resolver.cancel() }
            case .dot:
                let resolver = DoTResolver(endpoint: DoTEndpoint("tls://ptr-private.memory.invalid#203.0.113.53")!,
                    metadataStreamDialer: probe.dialer, requestTimeout: .seconds(1), resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0, completion: $2, executionContext: $1) }
                cancelOne = { resolver.cancel($0, completion: $1) }; cancelAll = { resolver.cancel() }
            case .proxyTCP:
                let resolver = ProxyTCPDNSResolver(server: DNSProxyFallbackServer("203.0.113.53:53")!,
                    metadataStreamDialer: probe.dialer, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0,
                    absoluteDeadline: $1.absoluteDeadline ?? ProcessInfo.processInfo.systemUptime + 1,
                    permitted: { true }, completion: $2, executionContext: $1) }
                cancelOne = { resolver.cancel($0, completion: $1) }; cancelAll = { resolver.cancel() }
            }
        }
        func begin(_ query: Data, context: DNSQueryExecutionContext, _ completion: Completion) -> UUID? {
            resolve(query, context, completion.receive)
        }
        func query(_ query: Data, context: DNSQueryExecutionContext) throws -> Result<Data, EncryptedDNSQueryFailure> {
            let completion = Completion(); _ = begin(query, context: context, completion); return try completion.wait()
        }
        func cancel(_ id: UUID) throws {
            let signal = DispatchSemaphore(value: 0); cancelOne(id) { signal.signal() }
            try require(signal.wait(timeout: .now() + 1) == .success, "cancel did not acknowledge ownership")
        }
        func close() throws {
            cancelAll()
            let signal = DispatchSemaphore(value: 0); cancelOne(UUID()) { signal.signal() }
            try require(signal.wait(timeout: .now() + 1) == .success, "pool close did not drain")
            try require(budget.usage.resources == 0 && probe.streams.allSatisfy(\.cancelled), "stream or resource reservation leaked")
        }
        deinit { cancelAll() }
    }

    private static var checks = 0, groups = 0, failures: [String] = [], metadataGroups: [String] = []
    private static var maximumRoundtripTimingDriftMilliseconds = 0.0
    private static func require(_ value: Bool, _ text: String) throws {
        checks += 1; if !value { throw Failure(text: text) }
    }
    private static func check(_ name: String, metadata: Bool = false, _ body: () throws -> Void) {
        groups += 1; if metadata { metadataGroups.append(name) }
        do { try body(); print("PASS " + name) }
        catch { failures.append(name); print("FAIL " + name + ": " + ((error as? Failure)?.text ?? String(describing: error))) }
    }
    private static func classification(_ data: Data) -> String? {
        guard let question = DNSMessageInspection.singleQuestion(in: data) else { return nil }
        #if HAVE_PTR_CLASSIFICATION
        return DNSMessageInspection.ptrTargetCategory(for: question)?.rawValue
        #else
        return nil
        #endif
    }
    private static func label(_ exchange: DNSQueryExchangeSnapshot) -> String? {
        #if HAVE_PTR_CLASSIFICATION
        return exchange.ptrTargetCategory?.rawValue
        #else
        return nil
        #endif
    }
    private static func record(_ trace: DNSQueryExchangeTrace, type: UInt16, label: String) {
        #if HAVE_PTR_CLASSIFICATION
        trace.recordQuestion(type: type, ptrTargetCategory: DNSPTRTargetCategory(rawValue: label))
        #else
        trace.recordQuestion(type: type)
        #endif
    }
    private static func context(_ remaining: TimeInterval = 1) -> DNSQueryExecutionContext {
        DNSQueryExecutionContext(absoluteDeadline: ProcessInfo.processInfo.systemUptime + remaining)
    }
    private static func query(_ name: String, type: UInt16 = 12, id: UInt16 = 0x3737) -> Data {
        DNSMessageInspection.query(for: name, type: type, id: id)!
    }
    private static func reverse4(_ address: String) -> String {
        address.split(separator: ".").reversed().joined(separator: ".") + ".in-addr.arpa"
    }
    private static func reverse6(_ address: String) -> String {
        var value = in6_addr()
        precondition(address.withCString { inet_pton(AF_INET6, $0, &value) } == 1)
        return withUnsafeBytes(of: &value) { raw in
            raw.map { String(format: "%02x", $0) }.joined().reversed().map(String.init).joined(separator: ".") + ".ip6.arpa"
        }
    }
    private static func reply(_ query: Data) -> Data {
        var data = query; data[2] = 0x81; data[3] = 0x80; return data
    }
    private static func body(_ wire: Data, kind: Kind) -> Data {
        if kind == .doh {
            guard let boundary = wire.range(of: Data("\r\n\r\n".utf8)) else { preconditionFailure("missing DoH framing") }
            return Data(wire[boundary.upperBound...])
        }
        precondition(wire.count >= 2 && Int(wire[wire.startIndex]) << 8 | Int(wire[wire.startIndex + 1]) == wire.count - 2)
        return Data(wire.dropFirst(2))
    }
    private static func frame(_ data: Data, kind: Kind) -> Data {
        if kind == .doh {
            return Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(data.count)\r\n\r\n".utf8) + data
        }
        return Data([UInt8(data.count >> 8), UInt8(data.count & 255)]) + data
    }
    private static func answerProbe(_ kind: Kind, query expected: Data) -> Probe {
        Probe { _ in .success(Peer { peer, wire, _, done in
            let actual = body(wire, kind: kind)
            precondition(actual == expected, "diagnostics changed the original query")
            done(nil); peer.emit(frame(reply(actual), kind: kind))
        }) }
    }
    private static func requireAnswer(_ result: Result<Data, EncryptedDNSQueryFailure>, query: Data) throws {
        guard case .success(let data) = result else { throw Failure(text: "metadata changed query acceptance") }
        try require(data == reply(query) && DNSMessageInspection.responseMatchesQuery(data, query: query), "metadata changed response bytes or identity")
    }
    private static func requireFailure(_ result: Result<Data, EncryptedDNSQueryFailure>, _ expected: EncryptedDNSQueryFailure) throws {
        guard case .failure(let actual) = result else { throw Failure(text: "expected terminal failure") }
        try require(actual == expected, "metadata changed failure classification")
    }
    private static func exchange(for context: DNSQueryExecutionContext) throws -> DNSQueryExchangeSnapshot {
        let values = NetworkPerformanceDiagnostics.shared.snapshot().dnsQueryExchanges.filter {
            $0.rootID == context.rootID && $0.candidateID == context.candidateID
        }
        try require(values.count == 1, "question category lost root/candidate correlation")
        let value = values[0]
        let attempts = NetworkPerformanceDiagnostics.shared.snapshot().dnsConnectionAttempts.filter { $0.requestID == value.requestID }
        try require(attempts.allSatisfy { $0.rootID == value.rootID && $0.candidateID == value.candidateID }
                    && Set(attempts.map(\.id)) == Set(value.physicalAttemptIDs), "physical lineage changed")
        return value
    }
    private static func privacyAndRoundtrip(_ value: DNSQueryExchangeSnapshot, query original: Data) throws {
        let data = try JSONEncoder().encode(value)
        let text = String(decoding: data, as: UTF8.self)
        let name = DNSMessageInspection.singleQuestion(in: original)!.name
        try require(!text.contains(name) && !text.contains("203.0.113.53") && !text.contains("ptr-private")
                    && !text.contains("in-addr.arpa") && !text.contains("ip6.arpa"), "diagnostics retained a target or endpoint")
        let decoded = try JSONDecoder().decode(DNSQueryExchangeSnapshot.self, from: data)
        try require(decoded.id == value.id && decoded.requestID == value.requestID
                    && decoded.rootID == value.rootID && decoded.candidateID == value.candidateID
                    && decoded.upstreamID == value.upstreamID && decoded.transport == value.transport
                    && decoded.physicalAttemptIDs == value.physicalAttemptIDs
                    && decoded.reusedConnection == value.reusedConnection && decoded.outcome == value.outcome
                    && decoded.failureReason == value.failureReason && decoded.httpStatusCode == value.httpStatusCode
                    && decoded.responseBytes == value.responseBytes && decoded.dnsResponseCode == value.dnsResponseCode
                    && decoded.responseRejection == value.responseRejection && decoded.queryType == value.queryType
                    && decoded.extendedDNSErrorCodes == value.extendedDNSErrorCodes && label(decoded) == label(value)
                    && decoded.firstError == value.firstError && decoded.firstErrorBeforeCancellation == value.firstErrorBeforeCancellation
                    && decoded.cancellationReason == value.cancellationReason && decoded.omittedObservations == value.omittedObservations,
                    "optional category changed discrete JSON metadata")
        try require(decoded.observations.count == value.observations.count, "JSON roundtrip changed observation count")
        for (before, after) in zip(value.observations, decoded.observations) {
            let drift = abs(before.milliseconds - after.milliseconds)
            maximumRoundtripTimingDriftMilliseconds = max(maximumRoundtripTimingDriftMilliseconds, drift)
            try require(before.sequence == after.sequence && before.event == after.event && before.error == after.error
                        && before.cancellationReason == after.cancellationReason && before.peerCiphertextBytes == after.peerCiphertextBytes
                        && drift <= 0.000001, "JSON roundtrip changed an observation or exceeded 1ns timing tolerance")
        }
    }

    private static func parserCases() {
        let v4: [(String, String)] = [
            ("8.8.8.8", "ipv4Public"), ("1.1.1.1", "ipv4Public"),
            ("9.255.255.255", "ipv4Public"), ("11.0.0.0", "ipv4Public"),
            ("10.0.0.0", "ipv4Private"), ("10.255.255.255", "ipv4Private"),
            ("172.15.255.255", "ipv4Public"), ("172.16.0.0", "ipv4Private"),
            ("172.31.255.255", "ipv4Private"), ("172.32.0.0", "ipv4Public"),
            ("192.168.0.0", "ipv4Private"), ("192.168.255.255", "ipv4Private"),
            ("127.0.0.0", "ipv4Loopback"), ("127.255.255.255", "ipv4Loopback"),
            ("169.254.0.0", "ipv4LinkLocal"), ("169.254.255.255", "ipv4LinkLocal"),
            ("198.19.0.0", "ipv4FakeIP"), ("198.19.0.2", "ipv4FakeIP"),
            ("198.19.255.254", "ipv4FakeIP"), ("198.19.255.255", "other"),
            ("198.18.0.1", "other"), ("198.18.16.1", "other"), ("198.18.16.2", "other"),
            ("0.0.0.0", "other"), ("0.255.255.255", "other"),
            ("100.64.0.0", "other"), ("100.127.255.255", "other"),
            ("192.0.0.1", "other"), ("192.0.2.1", "other"), ("192.88.99.1", "other"),
            ("198.51.100.1", "other"), ("203.0.113.1", "other"),
            ("224.0.0.1", "other"), ("240.0.0.1", "other"), ("255.255.255.255", "other"),
        ]
        for (address, expected) in v4 {
            check("wire-v4-" + address, metadata: true) {
                let original = query(reverse4(address))
                try require(DNSMessageInspection.singleQuestion(in: original)?.type == 12, "fixture question invalid")
                try require(FakeIPAllocator.isFake(address) == (expected == "ipv4FakeIP"), "diagnostic Fake-IP range differs from actual allocator")
                try require(classification(original) == expected, "wrong IPv4 reverse-target category")
                try require(DNSMessageInspection.responseMatchesQuery(reply(original), query: original), "classification changed DNS identity")
            }
        }
        let v6: [(String, String)] = [
            ("2001:4860:4860::8888", "ipv6Public"), ("2606:4700:4700::1111", "ipv6Public"),
            ("2a00::1", "ipv6Public"), ("fc00::", "ipv6UniqueLocal"), ("fdff:ffff::1", "ipv6UniqueLocal"),
            ("fe80::", "ipv6LinkLocal"), ("febf:ffff::1", "ipv6LinkLocal"), ("::1", "ipv6Loopback"),
            ("::", "other"), ("::ffff:10.0.0.1", "other"), ("fec0::1", "other"),
            ("ff02::1", "other"), ("2001:db8::1", "other"), ("2001::1", "other"),
            ("2002::1", "other"), ("3fff::1", "other"), ("4000::1", "other"),
        ]
        for (index, sample) in v6.enumerated() {
            check("wire-v6-\(index)", metadata: true) {
                let original = query(reverse6(sample.0).uppercased())
                try require(DNSMessageInspection.singleQuestion(in: original)?.type == 12, "fixture IPv6 question invalid")
                try require(classification(original) == sample.1, "wrong IPv6 reverse-target category")
                try require(DNSMessageInspection.responseMatchesQuery(reply(original), query: original), "classification changed IPv6 DNS identity")
            }
        }
        for (index, name) in ["ptr-private.memory.invalid", ".", "in-addr.arpa", "1.2.3.in-addr.arpa",
            "1.2.3.4.5.in-addr.arpa", "256.2.3.4.in-addr.arpa", "01.2.3.4.in-addr.arpa",
            "+1.2.3.4.in-addr.arpa", "１.2.3.4.in-addr.arpa", "1.2.3.4.in-addr.arpa.invalid",
            "1.0.ip6.arpa", "1.2.3.4.ip6.arpa", Array(repeating: "g", count: 32).joined(separator: ".") + ".ip6.arpa",
            Array(repeating: "00", count: 32).joined(separator: ".") + ".ip6.arpa"].enumerated() {
            check("wire-other-\(index)", metadata: true) {
                let original = query(name)
                try require(DNSMessageInspection.singleQuestion(in: original) != nil, "other category rejected a legal question")
                try require(DNSMessageInspection.responseMatchesQuery(reply(original), query: original), "other category changed old response acceptance")
                try require(classification(original) == "other", "incomplete/noncanonical reverse name was classified as an address")
            }
        }
        check("wire-nonptr-and-nonIN-omitted") {
            for type: UInt16 in [1, 28, 65, 255, 65535] {
                try require(classification(query(reverse4("10.0.0.1"), type: type)) == nil, "non-PTR received a reverse label")
            }
            for cls: UInt8 in [0, 3, 4, 255] {
                var data = query(reverse4("10.0.0.1")); data[data.count - 1] = cls
                try require(DNSMessageInspection.singleQuestion(in: data) != nil && classification(data) == nil, "non-IN question received a reverse label")
            }
        }
        check("wire-malformed-metadata-omitted") {
            let original = query(reverse4("10.0.0.1"))
            for length in 0..<original.count {
                let truncated = Data(original.prefix(length))
                try require(DNSMessageInspection.singleQuestion(in: truncated) == nil && classification(truncated) == nil, "truncated wire published PTR metadata")
            }
            var response = original; response[2] |= 0x80
            var multi = original; multi[5] = 2
            var opcode = original; opcode[2] |= 0x08
            var loop = Data(original.prefix(12)); loop.append(contentsOf: [0xc0, 0x0c, 0, 12, 0, 1])
            for malformed in [response, multi, opcode, loop] {
                try require(DNSMessageInspection.singleQuestion(in: malformed) == nil && classification(malformed) == nil, "invalid query framing published PTR metadata")
            }
        }
    }

    private static func diagnosticCases() {
        check("diagnostic-fixed-labels-and-schema2-roundtrip", metadata: true) {
            let diagnostics = NetworkPerformanceDiagnostics(maximumDNSAttempts: 2)
            let trace = diagnostics.beginDNSExchange(requestID: UUID(), context: context(), transport: .doh,
                endpointIdentity: "https://ptr-private.memory.invalid/secret")
            record(trace, type: 12, label: "ipv4FakeIP")
            record(trace, type: 12, label: "ipv4Public")
            let value = diagnostics.snapshot().dnsQueryExchanges[0]
            try require(value.queryType == 12, "adding a label changed QTYPE")
            try privacyAndRoundtrip(value, query: query(reverse4("198.19.0.2")))
            try require(label(value) == "ipv4FakeIP", "initial fixed PTR label absent or overwritten")
            #if HAVE_PTR_CLASSIFICATION
            try require(Set(DNSPTRTargetCategory.allCases.map(\.rawValue)) == Set([
                "ipv4Public", "ipv4Private", "ipv4Loopback", "ipv4LinkLocal", "ipv4FakeIP",
                "ipv6Public", "ipv6UniqueLocal", "ipv6LinkLocal", "ipv6Loopback", "other"]), "unbounded PTR label set")
            #endif
        }
        check("diagnostic-legacy-schema2-omits-optional-label") {
            let diagnostics = NetworkPerformanceDiagnostics(maximumDNSAttempts: 1)
            let trace = diagnostics.beginDNSExchange(requestID: UUID(), context: nil, transport: .dot, endpointIdentity: "private")
            record(trace, type: 12, label: "ipv4Private")
            var legacy = try JSONSerialization.jsonObject(with: JSONEncoder().encode(diagnostics.snapshot().dnsQueryExchanges[0])) as! [String: Any]
            legacy.removeValue(forKey: "ptrTargetCategory")
            let decoded = try JSONDecoder().decode(DNSQueryExchangeSnapshot.self, from: JSONSerialization.data(withJSONObject: legacy))
            try require(decoded.queryType == 12 && label(decoded) == nil, "old schema-2 exchange no longer decodes")
        }
        check("diagnostic-nonptr-and-late-trace-omitted") {
            let diagnostics = NetworkPerformanceDiagnostics(maximumDNSAttempts: 1)
            let trace = diagnostics.beginDNSExchange(requestID: UUID(), context: nil, transport: .doh, endpointIdentity: "private")
            record(trace, type: 1, label: "ipv4Private")
            try require(label(diagnostics.snapshot().dnsQueryExchanges[0]) == nil, "non-PTR accepted a diagnostic label")
            diagnostics.reset(); record(trace, type: 12, label: "ipv4Private")
            try require(diagnostics.snapshot().dnsQueryExchanges.isEmpty, "late label revived an evicted exchange")
        }
    }

    private static func resolverCases(_ kind: Kind) {
        let samples: [(String, String)] = [
            (reverse4("8.8.8.8"), "ipv4Public"), (reverse4("10.1.2.3"), "ipv4Private"),
            (reverse4("127.0.0.1"), "ipv4Loopback"), (reverse4("169.254.1.1"), "ipv4LinkLocal"),
            (reverse4("198.19.0.2"), "ipv4FakeIP"), (reverse6("2001:4860::8888"), "ipv6Public"),
            (reverse6("fd00:6861:6a69::1"), "ipv6UniqueLocal"), (reverse6("fe80::1"), "ipv6LinkLocal"),
            (reverse6("::1"), "ipv6Loopback"), ("1.2.3.in-addr.arpa", "other"),
        ]
        for (index, sample) in samples.enumerated() {
            check(kind.rawValue + "-success-category-\(index)", metadata: true) {
                let original = query(sample.0, id: UInt16(0x3800 + index)), context = context()
                let probe = answerProbe(kind, query: original), owner = Owner(kind, probe)
                let result = try owner.query(original, context: context); try owner.close()
                try requireAnswer(result, query: original)
                let value = try exchange(for: context)
                try require(value.queryType == 12 && value.outcome == .success && value.dnsResponseCode == 0, "category changed existing query metadata")
                try privacyAndRoundtrip(value, query: original)
                try require(label(value) == sample.1, "real resolver omitted the PTR category")
            }
        }
        check(kind.rawValue + "-dialfailure-retains-category", metadata: true) {
            let original = query(reverse4("10.1.2.3")), context = context()
            let probe = Probe { _ in .failure(NWError.posix(.ECONNRESET)) }, owner = Owner(kind, probe)
            let result = try owner.query(original, context: context); try owner.close()
            try requireFailure(result, .network)
            let value = try exchange(for: context)
            try require(value.queryType == 12 && value.failureReason == "network" && value.dnsResponseCode == nil
                        && !value.observations.contains { $0.event == .querySent }, "failed dial changed old phase/result")
            try privacyAndRoundtrip(value, query: original)
            try require(label(value) == "ipv4Private", "dial failure erased PTR category")
        }
        check(kind.rawValue + "-timeout-retains-category", metadata: true) {
            let original = query(reverse6("fd00:6861:6a69::1")), context = context(0.08)
            let probe = Probe { _ in .success(Peer { _, _, _, done in done(nil) }) }, owner = Owner(kind, probe)
            let result = try owner.query(original, context: context); try owner.close()
            try requireFailure(result, .timeout)
            let value = try exchange(for: context)
            try require(value.queryType == 12 && value.failureReason == "timeout" && value.dnsResponseCode == nil
                        && value.observations.contains { $0.event == .querySent }, "timeout changed old query phases")
            try privacyAndRoundtrip(value, query: original)
            try require(label(value) == "ipv6UniqueLocal", "timeout erased PTR category")
        }
        check(kind.rawValue + "-cancel-retains-category-and-fences-late-answer", metadata: true) {
            let original = query(reverse4("198.19.0.2")), context = context(), done = Completion()
            let sent = DispatchSemaphore(value: 0)
            let probe = Probe { _ in .success(Peer { _, _, _, callback in callback(nil); sent.signal() }) }, owner = Owner(kind, probe)
            guard let id = owner.begin(original, context: context, done) else { throw Failure(text: "cancel request not admitted") }
            try require(sent.wait(timeout: .now() + 1) == .success, "cancel fixture did not send")
            try owner.cancel(id); let result = try done.wait()
            probe.streams[0].emit(frame(reply(original), kind: kind)); try owner.close()
            try requireFailure(result, .cancelled)
            let value = try exchange(for: context)
            try require(done.count == 1 && value.queryType == 12 && value.dnsResponseCode == nil, "late answer changed cancelled result")
            try privacyAndRoundtrip(value, query: original)
            try require(label(value) == "ipv4FakeIP", "cancellation erased PTR category")
        }
        check(kind.rawValue + "-idle-retry-preserves-original-category", metadata: true) {
            let original = query(reverse6("fe80::1")), warm = query("warm-private.memory.invalid", type: 1)
            let probe = Probe { dial in .success(Peer { peer, wire, number, done in
                done(nil)
                if dial == 0 && number > 1 { peer.emit(nil, complete: true) }
                else { peer.emit(frame(reply(body(wire, kind: kind)), kind: kind)) }
            }) }, owner = Owner(kind, probe)
            try requireAnswer(owner.query(warm, context: context()), query: warm)
            let context = context(), result = try owner.query(original, context: context); try owner.close()
            try requireAnswer(result, query: original)
            let value = try exchange(for: context)
            try require(probe.dialCount == 2 && value.reusedConnection && value.physicalAttemptIDs.count == 1, "metadata changed the single idle retry")
            try privacyAndRoundtrip(value, query: original)
            try require(label(value) == "ipv6LinkLocal", "idle retry lost original PTR category")
        }
        check(kind.rawValue + "-nonIN-and-nonPTR-remain-omitted") {
            for nonIN in [false, true] {
                var original = query(reverse4("10.0.0.1"), type: nonIN ? 12 : 1)
                if nonIN { original[original.count - 1] = 3 }
                let context = context(), probe = answerProbe(kind, query: original), owner = Owner(kind, probe)
                let result = try owner.query(original, context: context); try owner.close()
                try requireAnswer(result, query: original)
                try require(label(exchange(for: context)) == nil, "non-IN/non-PTR obtained a target label")
            }
        }
        check(kind.rawValue + "-malformed-wire-preserves-configuration-result") {
            let original = Data(query(reverse4("10.0.0.1")).dropLast())
            let probe = Probe { _ in preconditionFailure("Malformed query reached a dial") }, owner = Owner(kind, probe)
            let context = context(), result = try owner.query(original, context: context); try owner.close()
            try requireFailure(result, .configuration)
            try require(probe.dialCount == 0 && !NetworkPerformanceDiagnostics.shared.snapshot().dnsQueryExchanges.contains { $0.rootID == context.rootID }, "metadata admitted malformed wire")
        }
    }

    static func main() {
        parserCases(); diagnosticCases()
        for kind in Kind.allCases { resolverCases(kind) }
        let report: [String: Any] = ["groups": groups, "checks": checks, "failedGroups": failures,
            "metadataGroups": metadataGroups, "realResolvers": ["DoHResolver", "DoTResolver", "ProxyTCPDNSResolver"],
            "networkAccess": false, "systemSettingsChanged": false,
            "maximumRoundtripTimingDriftMilliseconds": maximumRoundtripTimingDriftMilliseconds]
        print(String(data: try! JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!)
        if !failures.isEmpty { exit(1) }
    }
}

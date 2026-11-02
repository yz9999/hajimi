import Foundation
import Network
import Darwin

private extension EncryptedDNSRequest {
    var ioAuditTrace: DNSQueryExchangeTrace? { exchangeTrace }
}
private extension EncryptedDNSRequestPool {
    func ioAuditTrace(_ id: UUID) -> DNSQueryExchangeTrace? {
        queue.sync { registeredRequest(id)?.ioAuditTrace }
    }
}

/// Real request/pool/diagnostic code with independently controlled memory
/// raw/TLS callbacks. This does not claim to test Network.framework itself.
@main private enum DNSQueryIOProgressMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private enum Kind: String, CaseIterable { case doh, dot, proxyTCP }
    private struct Event { let data: Data?; let complete: Bool; let error: Error? }
    private class Peer: NativeOutboundByteStream {
        typealias Send = (Peer, Data, Int, @escaping (Error?) -> Void) -> Void
        let recorder: DNSStreamProgressRecorder?
        private let handler: Send
        private let lock = NSLock()
        private var pending: ((Data?, Bool, Error?) -> Void)?
        private var latestReader: ((Data?, Bool, Error?) -> Void)?
        private var events: [Event] = [], writes: [Data] = []
        private var stopped = false
        var recordTeardown = false
        init(recorder: DNSStreamProgressRecorder? = nil,
             send: @escaping Send = { _, _, _, done in done(nil) }) {
            self.recorder = recorder; handler = send
        }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock()
            guard !stopped else { lock.unlock(); completion(NativeOutboundError.cancelled); return }
            writes.append(data); let ordinal = writes.count; lock.unlock()
            recorder?.record(.plaintextWriteRequested, bytes: data.count)
            handler(self, data, ordinal) { [self] error in
                if error == nil { recorder?.record(.plaintextWriteProcessed, bytes: data.count) }
                completion(error)
            }
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped, pending == nil, maximum > 0 else {
                lock.unlock(); completion(nil, true, NativeOutboundError.cancelled); return
            }
            recorder?.record(.plaintextReadRequested)
            latestReader = completion
            if !events.isEmpty {
                let event = events.removeFirst(); lock.unlock()
                recorder?.record(.plaintextReadDelivered, bytes: event.data?.count ?? 0)
                completion(event.data, event.complete, event.error)
            } else { pending = completion; lock.unlock() }
        }
        func emit(_ data: Data?, complete: Bool = false, error: Error? = nil) {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            let reader = pending; pending = nil
            if reader == nil { events.append(Event(data: data, complete: complete, error: error)) }
            lock.unlock()
            if let reader {
                recorder?.record(.plaintextReadDelivered, bytes: data?.count ?? 0)
                reader(data, complete, error)
            }
        }
        func emitLate(_ data: Data) {
            recorder?.record(.rawWriteCompleted, bytes: 4096)
            recorder?.record(.rawReadCompleted, bytes: 2048)
            recorder?.record(.plaintextReadDelivered, bytes: data.count)
            lock.lock(); let reader = latestReader; lock.unlock()
            reader?(data, false, nil)
        }
        func cancel() {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            stopped = true; let reader = pending; pending = nil; events.removeAll(); lock.unlock()
            if recordTeardown {
                recorder?.record(.rawWriteRequested, bytes: 8192)
                recorder?.record(.rawReadCompleted, bytes: 8192)
            }
            reader?(nil, true, NativeOutboundError.cancelled)
        }
        var sendCount: Int { lock.lock(); defer { lock.unlock() }; return writes.count }
        var lastWire: Data { lock.lock(); defer { lock.unlock() }; return writes.last ?? Data() }
        var readPending: Bool { lock.lock(); defer { lock.unlock() }; return pending != nil }
        var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
    }
    private final class ObservablePeer: Peer, DNSStreamProgressProviding {
        var unavailable = false
        func dnsStreamProgressSnapshot() -> DNSStreamProgressSnapshot? {
            unavailable ? nil : recorder?.snapshot()
        }
    }
    private final class Ticket {
        let context: DNSQueryExecutionContext, query: Data
        var id: UUID!
        private let signal = DispatchSemaphore(value: 0), lock = NSLock()
        private var terminal: [Result<Data, EncryptedDNSQueryFailure>] = []
        init(query: Data, deadline: TimeInterval) {
            self.query = query; context = DNSQueryExecutionContext(absoluteDeadline: deadline)
        }
        func finish(_ result: Result<Data, EncryptedDNSQueryFailure>) {
            lock.lock(); terminal.append(result); lock.unlock(); signal.signal()
        }
        func wait() throws -> Result<Data, EncryptedDNSQueryFailure> {
            guard signal.wait(timeout: .now() + 3) == .success else { throw Failure(text: "Memory DNS request did not finish") }
            lock.lock(); defer { lock.unlock() }
            guard terminal.count == 1 else { throw Failure(text: "Memory DNS completion duplicated") }
            return terminal[0]
        }
        var completionCount: Int { lock.lock(); defer { lock.unlock() }; return terminal.count }
    }
    private final class Owner {
        let kind: Kind, diagnostics: NetworkPerformanceDiagnostics
        let pool: EncryptedDNSRequestPool, peers: [Peer]
        let budget = SOCKSUDPGlobalBudget(resources: 256, packets: 0, bytes: 0)
        init(_ kind: Kind, peers: [Peer], diagnostics: NetworkPerformanceDiagnostics = NetworkPerformanceDiagnostics()) {
            self.kind = kind; self.peers = peers; self.diagnostics = diagnostics
            let transport: EncryptedDNSProtocol
            switch kind {
            case .doh: transport = .https(DoHEndpoint("https://io.private-memory.invalid/dns-query#203.0.113.53")!)
            case .dot: transport = .tls(DoTEndpoint("tls://io.private-memory.invalid#203.0.113.53")!)
            case .proxyTCP: transport = .proxyTCP(DNSProxyFallbackServer("203.0.113.53:53")!)
            }
            var current = 0
            let dialLock = NSLock()
            pool = EncryptedDNSRequestPool(protocol: transport, label: "memory.dns.query-io-progress",
                streamDialer: nil, cancellableStreamDialer: nil,
                metadataStreamDialer: { _, _, _, _, _, _, done in
                    dialLock.lock(); let index = current; current += 1; dialLock.unlock()
                    guard peers.indices.contains(index) else { done(.failure(EncryptedDNSQueryFailure.configuration)); return nil }
                    done(.success(peers[index])); return nil
                }, timeout: .seconds(3), idleTimeout: 15, idleLimit: 4, idleHandoffGrace: 8, activeLimit: 16,
                clock: { Date(timeIntervalSince1970: SOCKSUDPResourceLimits.now) }, resourceBudget: budget, diagnostics: diagnostics)
        }
        deinit { pool.cancel() }
        func drain() { for _ in 0..<8 { pool.drainQueueForSelfTest() } }
        func submit(_ query: Data, milliseconds: Int = 1000, permitted: @escaping () -> Bool = { true }) throws -> Ticket {
            let ticket = Ticket(query: query, deadline: ProcessInfo.processInfo.systemUptime + Double(milliseconds) / 1000)
            guard let id = pool.resolveResult(query: query, completion: ticket.finish,
                absoluteDeadline: ticket.context.absoluteDeadline, permitted: permitted, executionContext: ticket.context) else {
                throw Failure(text: "Production DNS pool rejected valid memory request")
            }
            ticket.id = id; drain(); return ticket
        }
        func cancel(_ ticket: Ticket) throws {
            let ack = DispatchSemaphore(value: 0)
            pool.cancel(ticket.id) { ack.signal() }
            try require(ack.wait(timeout: .now() + 2) == .success, "Logical DNS cancel ACK lost")
            drain()
        }
        func exchange(_ ticket: Ticket) throws -> DNSQueryExchangeSnapshot {
            guard let value = diagnostics.snapshot().dnsQueryExchanges.first(where: { $0.rootID == ticket.context.rootID }) else {
                throw Failure(text: "Real production request did not create exchange metadata")
            }
            return value
        }
        func close() throws {
            pool.cancel(); drain()
            try require(peers.allSatisfy { $0.sendCount == 0 || $0.cancelled } && budget.usage.resources == 0,
                        "Memory query left a stream or idle reservation open")
        }
    }

    private static var groups = 0, assertions = 0
    private static var maxJSONRoundtripMillisecondsError: Double = 0
    private static func require(_ value: @autoclosure () throws -> Bool, _ text: String) throws {
        assertions += 1
        if try !value() { throw Failure(text: text) }
    }
    private static func check(_ name: String, _ work: () throws -> Void) throws {
        try work(); groups += 1; print("PASS", name)
    }
    private static func query(type: UInt16 = 12, name: String = "b._dns-sd._udp.private-fixture.local",
                              dnsClass: UInt16 = 1, flags: UInt16 = 0x0100, additional: Bool = false) -> Data {
        var value = DNSMessageInspection.query(for: name, type: type, id: 0x4160)!
        value[2] = UInt8(flags >> 8); value[3] = UInt8(flags & 255)
        value[value.count - 2] = UInt8(dnsClass >> 8); value[value.count - 1] = UInt8(dnsClass & 255)
        if additional {
            let secret = Data("private-edns-payload".utf8)
            value[11] = 1
            value.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 0, 0, 0, UInt8(secret.count + 4),
                                      0xfd, 0xe9, 0, UInt8(secret.count)])
            value.append(secret)
        }
        return value
    }
    private static func body(_ peer: Peer, kind: Kind) throws -> Data {
        let wire = peer.lastWire
        if kind == .doh {
            guard let marker = wire.range(of: Data("\r\n\r\n".utf8)) else { throw Failure(text: "Missing production DoH header") }
            return Data(wire[marker.upperBound...])
        }
        guard wire.count >= 2 else { throw Failure(text: "Missing DNS stream length") }
        return Data(wire.dropFirst(2))
    }
    private static func answerWire(_ query: Data, kind: Kind) -> Data {
        var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail)!
        answer[3] &= 0xf0
        if kind == .doh {
            return Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(answer.count)\r\n\r\n".utf8) + answer
        }
        return Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer
    }
    private static func reply(_ owner: Owner, _ peer: Peer) throws {
        peer.emit(answerWire(try body(peer, kind: owner.kind), kind: owner.kind)); owner.drain()
    }
    private static func sample(_ exchange: DNSQueryExchangeSnapshot, ordinal: UInt8 = 1) throws -> DNSQueryLeaseIOProgressSnapshot {
        guard let value = exchange.leaseIOProgress?.first(where: { $0.ordinal == ordinal }) else {
            throw Failure(text: "Production request omitted its per-lease I/O sample")
        }
        return value
    }
    private static func stream(_ sample: DNSQueryLeaseIOProgressSnapshot) throws -> DNSStreamProgressSnapshot {
        guard let value = sample.stream else { throw Failure(text: "Observable stream was exported as unavailable") }
        return value
    }
    private static func expectFailure(_ ticket: Ticket, _ reason: EncryptedDNSQueryFailure) throws {
        guard case .failure(let actual) = try ticket.wait(), actual == reason else { throw Failure(text: "Unexpected production failure result") }
    }
    private static func expectSuccess(_ ticket: Ticket) throws {
        guard case .success(let answer) = try ticket.wait(), DNSMessageInspection.responseMatchesQuery(answer, query: ticket.query) else {
            throw Failure(text: "Production pool did not deliver the exact successful question")
        }
    }

    private static func requireJSONRoundtrip(_ decoded: DNSQueryExchangeSnapshot,
                                            _ original: DNSQueryExchangeSnapshot) throws {
        func milliseconds(_ actual: Double?, _ expected: Double?) throws -> Double? {
            try require((actual == nil) == (expected == nil), "JSON changed optional timing availability")
            guard let actual, let expected else { return nil }
            let difference = abs(actual - expected)
            try require(actual.isFinite && expected.isFinite && difference <= 1e-6,
                        "JSON changed a millisecond duration beyond floating-point roundoff")
            maxJSONRoundtripMillisecondsError = max(maxJSONRoundtripMillisecondsError, difference)
            return expected
        }
        func observation(_ actual: DNSConnectionAttemptObservation,
                         _ expected: DNSConnectionAttemptObservation) throws -> DNSConnectionAttemptObservation {
            DNSConnectionAttemptObservation(sequence: actual.sequence, event: actual.event,
                milliseconds: try milliseconds(actual.milliseconds, expected.milliseconds)!, error: actual.error,
                cancellationReason: actual.cancellationReason, peerCiphertextBytes: actual.peerCiphertextBytes)
        }
        var normalized = decoded
        try require(decoded.observations.count == original.observations.count
                    && (decoded.firstCancellationRequest == nil) == (original.firstCancellationRequest == nil)
                    && (decoded.leaseIOProgress == nil) == (original.leaseIOProgress == nil)
                    && decoded.leaseIOProgress?.count == original.leaseIOProgress?.count,
                    "JSON changed observation or lease sample counts/availability")
        normalized.resolverQueueMilliseconds = try milliseconds(decoded.resolverQueueMilliseconds,
                                                                original.resolverQueueMilliseconds)
        normalized.observations = try zip(decoded.observations, original.observations).map { try observation($0, $1) }
        if let actual = decoded.firstCancellationRequest, let expected = original.firstCancellationRequest {
            normalized.firstCancellationRequest = try observation(actual, expected)
        }
        if let actual = decoded.leaseIOProgress, let expected = original.leaseIOProgress {
            normalized.leaseIOProgress = try zip(actual, expected).map { actual, expected in
                DNSQueryLeaseIOProgressSnapshot(ordinal: actual.ordinal, reusedConnection: actual.reusedConnection,
                    sampledBeforeIdleRetry: actual.sampledBeforeIdleRetry,
                    millisecondsSinceSend: try milliseconds(actual.millisecondsSinceSend, expected.millisecondsSinceSend)!,
                    resolverReadRequests: actual.resolverReadRequests,
                    firstResolverReadMilliseconds: try milliseconds(actual.firstResolverReadMilliseconds,
                                                                    expected.firstResolverReadMilliseconds),
                    pooledReadPendingAtSend: actual.pooledReadPendingAtSend,
                    pooledReadPendingAtSample: actual.pooledReadPendingAtSample,
                    plaintextResponseBytes: actual.plaintextResponseBytes, stream: actual.stream)
            }
        }
        // Only Double durations receive a tolerance. IDs, fixed tags, wire
        // metadata, counts, flags and every UInt64 native timestamp stay exact.
        try require(normalized == original, "JSON changed non-timing query, lease or stream metadata")
    }

    private static func stalledPhases(_ kind: Kind) throws {
        try check(kind.rawValue + "-local-TLS-processed-does-not-claim-completed-raw-write") {
            let recorder = DNSStreamProgressRecorder()
            let peer = ObservablePeer(recorder: recorder, send: { peer, _, _, done in
                peer.recorder?.record(.rawWriteRequested, bytes: 173); done(nil)
            })
            let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
            let ticket = try owner.submit(query(), milliseconds: 100)
            try require(peer.readPending, "Real request did not issue its pending response read")
            try expectFailure(ticket, .timeout); owner.drain()
            let exchange = try owner.exchange(ticket), lease = try sample(exchange), progress = try stream(lease)
            try require(exchange.observations.contains { $0.event == .querySent }
                        && !exchange.observations.contains { $0.event == .responseStarted }, "Local send/response observations changed")
            try require(progress.plaintextWriteRequestedBytes == UInt64(peer.lastWire.count)
                        && progress.plaintextWriteProcessedBytes == UInt64(peer.lastWire.count)
                        && progress.rawWriteRequestedBytes == 173 && progress.rawWriteCompletedBytes == 0,
                        "Local processed callback was mistaken for a completed raw write")
            try require(lease.resolverReadRequests == 1 && lease.firstResolverReadMilliseconds != nil
                        && lease.pooledReadPendingAtSample && lease.plaintextResponseBytes == 0
                        && progress.plaintextReadRequests == 1 && progress.plaintextReadDeliveredBytes == 0,
                        "Issued-but-unanswered read was reported as no reader or fabricated data")
        }
        try check(kind.rawValue + "-raw-ciphertext-without-plaintext-remains-distinct") {
            let peer = ObservablePeer(recorder: DNSStreamProgressRecorder())
            let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
            let ticket = try owner.submit(query(), milliseconds: 100)
            peer.recorder?.record(.rawReadRequested)
            peer.recorder?.record(.rawReadCompleted, bytes: 97)
            peer.recorder?.record(.rawReadRequested)
            try expectFailure(ticket, .timeout); owner.drain()
            let lease = try sample(owner.exchange(ticket)), progress = try stream(lease)
            try require(progress.rawReadRequests == 2 && progress.rawReadCompletedBytes == 97
                        && progress.plaintextReadDeliveredBytes == 0 && lease.plaintextResponseBytes == 0,
                        "Raw TLS records were reported as DNS response plaintext")
        }
        try check(kind.rawValue + "-send-not-processed-yet-does-not-fabricate-a-resolver-read") {
            let peer = ObservablePeer(recorder: DNSStreamProgressRecorder(), send: { _, _, _, _ in })
            let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
            let ticket = try owner.submit(query(), milliseconds: 100)
            try expectFailure(ticket, .timeout); owner.drain()
            let lease = try sample(owner.exchange(ticket)), progress = try stream(lease)
            try require(lease.resolverReadRequests == 0 && lease.firstResolverReadMilliseconds == nil
                        && !lease.pooledReadPendingAtSample && progress.plaintextWriteProcessedBytes == 0
                        && progress.plaintextReadRequests == 0 && progress.plaintextWriteRequestedBytes > 0,
                        "Stalled local send invented a completed write or response read")
        }
    }

    private static func reuseAndRetry(_ kind: Kind) throws {
        try check(kind.rawValue + "-idle-read-is-inherited-without-new-native-read-or-old-byte-counts") {
            let recorder = DNSStreamProgressRecorder()
            recorder.record(.rawWriteRequested, bytes: 4000); recorder.record(.rawWriteCompleted, bytes: 4000)
            recorder.record(.rawReadRequested); recorder.record(.rawReadCompleted, bytes: 5000)
            let peer = ObservablePeer(recorder: recorder)
            let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
            let warm = try owner.submit(query(type: 1, name: "warm.private-fixture.invalid"))
            try reply(owner, peer); try expectSuccess(warm); owner.drain()
            try require(peer.readPending, "Completed query did not establish the idle-monitor read")
            let ticket = try owner.submit(query())
            let before = try owner.exchange(ticket)
            try require(before.reusedConnection && peer.sendCount == 2, "Second query did not reuse the concrete idle stream")
            try owner.cancel(ticket); try expectFailure(ticket, .cancelled)
            let lease = try sample(owner.exchange(ticket)), progress = try stream(lease)
            try require(lease.reusedConnection && lease.pooledReadPendingAtSend && lease.pooledReadPendingAtSample
                        && lease.resolverReadRequests == 1 && progress.plaintextReadRequests == 0,
                        "Inherited idle read was mislabeled as missing reader or a new native read")
            try require(progress.rawWriteRequestedBytes == 0 && progress.rawWriteCompletedBytes == 0
                        && progress.rawReadCompletedBytes == 0 && progress.plaintextReadDeliveredBytes == 0,
                        "Handshake/previous query counters leaked into a reused lease")
            try require(progress.lastRawWriteRequestedUptimeNanoseconds == nil
                        && progress.lastRawReadCompletedUptimeNanoseconds == nil
                        && progress.lastPlaintextReadRequestedUptimeNanoseconds == nil,
                        "Unchanged old counters retained pre-lease timestamps")
        }
        try check(kind.rawValue + "-one-fresh-retry-keeps-two-separate-baselines-and-an-original-deadline") {
            let first = ObservablePeer(recorder: DNSStreamProgressRecorder(), send: { peer, _, ordinal, done in
                peer.recorder?.record(.rawWriteRequested, bytes: ordinal == 1 ? 900 : 11)
                if ordinal == 1 { peer.recorder?.record(.rawWriteCompleted, bytes: 900); done(nil) }
                else { done(NWError.posix(.ECONNRESET)) }
            })
            first.recordTeardown = true
            let freshRecorder = DNSStreamProgressRecorder()
            freshRecorder.record(.rawWriteRequested, bytes: 6000); freshRecorder.record(.rawWriteCompleted, bytes: 6000)
            freshRecorder.record(.rawReadCompleted, bytes: 7000)
            let second = ObservablePeer(recorder: freshRecorder, send: { peer, _, _, done in
                peer.recorder?.record(.rawWriteRequested, bytes: 19)
                peer.recorder?.record(.rawWriteCompleted, bytes: 19); done(nil)
            })
            let owner = Owner(kind, peers: [first, second]); defer { try? owner.close() }
            let warm = try owner.submit(query(type: 1, name: "retry-warm.private-fixture.invalid"))
            try reply(owner, first); try expectSuccess(warm); owner.drain()
            let ticket = try owner.submit(query(), milliseconds: 180)
            let trace = owner.pool.ioAuditTrace(ticket.id)
            try require(trace != nil, "Retry bound test did not retain its real live exchange handle")
            try require(first.cancelled && first.sendCount == 2 && second.sendCount == 1,
                        "Dirty reused lease did not take exactly one fresh production retry")
            let deadline = owner.pool.originalDeadlineForSelfTest(ticket.id)
            try expectFailure(ticket, .timeout); owner.drain()
            let exchange = try owner.exchange(ticket), oldLease = try sample(exchange), freshLease = try sample(exchange, ordinal: 2)
            let old = try stream(oldLease), fresh = try stream(freshLease)
            try require(exchange.leaseIOProgress?.count == 2 && oldLease.sampledBeforeIdleRetry && oldLease.reusedConnection
                        && !freshLease.sampledBeforeIdleRetry && !freshLease.reusedConnection,
                        "Idle retry lost or merged its two lease identities")
            try require(old.rawWriteRequestedBytes == 11 && old.rawWriteCompletedBytes == 0
                        && old.plaintextWriteProcessedBytes == 0 && oldLease.resolverReadRequests == 0,
                        "Failed idle send inherited warmup or teardown counters")
            try require(fresh.rawWriteRequestedBytes == 19 && fresh.rawWriteCompletedBytes == 19
                        && fresh.rawReadCompletedBytes == 0 && freshLease.resolverReadRequests == 1,
                        "Fresh retry reused old-stream or handshake counters")
            try require(deadline != nil && ticket.context.inheritedDeadlineReached,
                        "Fresh retry received an extended deadline or lost its inherited timeout")
            if let trace {
                for ordinal: UInt8 in [1, 2, 3, 4] {
                    trace.recordLeaseIOProgress(DNSQueryLeaseIOProgressSnapshot(ordinal: ordinal,
                        reusedConnection: false, sampledBeforeIdleRetry: false, millisecondsSinceSend: 0,
                        resolverReadRequests: 0, firstResolverReadMilliseconds: nil,
                        pooledReadPendingAtSend: false, pooledReadPendingAtSample: false, plaintextResponseBytes: 0,
                        stream: DNSStreamProgressSnapshot()))
                }
            }
            try require(try owner.exchange(ticket).leaseIOProgress == exchange.leaseIOProgress,
                        "Late duplicate/excess records bypassed the two-sample bound")
        }
    }

    private static func frozenTerminalAndAvailability(_ kind: Kind) throws {
        try check(kind.rawValue + "-terminal-lease-sample-precedes-teardown-and-ignores-late-native-events") {
            let peer = ObservablePeer(recorder: DNSStreamProgressRecorder(), send: { peer, _, _, done in
                peer.recorder?.record(.rawWriteRequested, bytes: 23); done(nil)
            })
            peer.recordTeardown = true
            let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
            let ticket = try owner.submit(query())
            try owner.cancel(ticket); try expectFailure(ticket, .cancelled)
            let before = try owner.exchange(ticket), lease = try sample(before), progress = try stream(lease)
            try require(progress.rawWriteRequestedBytes == 23 && progress.rawReadCompletedBytes == 0,
                        "Native teardown traffic polluted the terminal lease sample")
            peer.emitLate(answerWire(ticket.query, kind: kind)); owner.drain()
            try require(try owner.exchange(ticket).leaseIOProgress == before.leaseIOProgress && ticket.completionCount == 1,
                        "Post-cancel native data modified a closed sample or delivered a second result")
        }
        try check(kind.rawValue + "-unsupported-progress-is-nil-and-supported-zero-remains-measured") {
            for visible in [false, true] {
                let peer: Peer = visible ? ObservablePeer(recorder: DNSStreamProgressRecorder(), send: { _, _, _, _ in })
                    : Peer(send: { _, _, _, _ in })
                let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
                let ticket = try owner.submit(query())
                try owner.cancel(ticket); try expectFailure(ticket, .cancelled)
                let lease = try sample(owner.exchange(ticket))
                try require((lease.stream != nil) == visible && lease.resolverReadRequests == 0,
                            "Unavailable stream evidence was fabricated as zero or measured evidence was omitted")
                if let progress = lease.stream {
                    try require(progress.rawWriteRequestedBytes == 0 && progress.rawWriteCompletedBytes == 0
                                && progress.rawReadRequests == 0 && progress.rawReadCompletedBytes == 0,
                                "Supported-but-unadvanced raw counters did not remain measured zero")
                }
            }
        }
        try check(kind.rawValue + "-lost-snapshot-baseline-is-not-reported-as-zero") {
            let peer = ObservablePeer(recorder: DNSStreamProgressRecorder())
            let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
            let ticket = try owner.submit(query())
            peer.unavailable = true
            try owner.cancel(ticket); try expectFailure(ticket, .cancelled)
            try require(try sample(owner.exchange(ticket)).stream == nil, "Unavailable terminal observation invented a zero delta")
        }
    }

    private static func metadataAndResponse(_ kind: Kind) throws {
        try check(kind.rawValue + "-real-request-records-numeric-question-metadata-without-payload") {
            let peer = ObservablePeer(recorder: DNSStreamProgressRecorder())
            let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
            let original = query(dnsClass: 3, flags: 0x0120, additional: true)
            let ticket = try owner.submit(original)
            try require(try body(peer, kind: kind) == original, "Diagnostics changed the forwarded DNS bytes")
            try owner.cancel(ticket); try expectFailure(ticket, .cancelled)
            let exchange = try owner.exchange(ticket)
            try require(exchange.queryType == 12 && exchange.queryClass == 3 && exchange.queryFlags == 0x0120
                        && exchange.queryBytes == original.count && exchange.queryAdditionalRecordCount == 1
                        && exchange.ptrQueryKind == .dnsSDDomainEnumeration && exchange.ptrTargetCategory == nil,
                        "Production request did not wire exact PTR kind/class/flags/length/additional count")
            let bytes = try JSONEncoder().encode(exchange), text = String(decoding: bytes, as: UTF8.self)
            for secret in ["private-fixture", "private-edns-payload", "io.private-memory.invalid", "203.0.113.53", "_dns-sd", "application/dns-message"] {
                try require(!text.contains(secret), "Numeric I/O export retained query, resolver or HTTP payload")
            }
            let decoded = try JSONDecoder().decode(DNSQueryExchangeSnapshot.self, from: bytes)
            try requireJSONRoundtrip(decoded, exchange)
            var old = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
            for key in ["ptrQueryKind", "queryClass", "queryFlags", "queryBytes", "queryAdditionalRecordCount", "leaseIOProgress"] {
                old.removeValue(forKey: key)
            }
            let legacy = try JSONDecoder().decode(DNSQueryExchangeSnapshot.self,
                from: JSONSerialization.data(withJSONObject: old))
            try require(legacy.queryType == 12 && legacy.queryClass == nil && legacy.queryFlags == nil
                        && legacy.queryBytes == nil && legacy.queryAdditionalRecordCount == nil
                        && legacy.ptrQueryKind == nil && legacy.leaseIOProgress == nil,
                        "Old schema-2 exchange JSON now requires the added metadata")
        }
        try check(kind.rawValue + "-received-wire-bytes-and-reader-counts-are-per-lease") {
            let peer = ObservablePeer(recorder: DNSStreamProgressRecorder())
            let owner = Owner(kind, peers: [peer]); defer { try? owner.close() }
            let ticket = try owner.submit(query(type: 65, name: "response.private-fixture.invalid"))
            let wire = answerWire(ticket.query, kind: kind), cut = min(7, wire.count - 1)
            peer.emit(Data(wire.prefix(cut))); owner.drain()
            peer.emit(Data(wire.dropFirst(cut))); owner.drain()
            try expectSuccess(ticket)
            let exchange = try owner.exchange(ticket), lease = try sample(exchange), progress = try stream(lease)
            try require(lease.plaintextResponseBytes == wire.count && progress.plaintextReadDeliveredBytes == UInt64(wire.count)
                        && lease.resolverReadRequests == 2 && progress.plaintextReadRequests == 2
                        && !lease.pooledReadPendingAtSend && !lease.pooledReadPendingAtSample,
                        "Fragmented HTTP/DNS response lost per-lease byte or read counts")
            try require(exchange.ptrQueryKind == nil && exchange.ptrTargetCategory == nil
                        && exchange.queryClass == 1 && exchange.queryFlags == 0x0100
                        && exchange.queryBytes == ticket.query.count && exchange.queryAdditionalRecordCount == 0,
                        "Non-PTR metadata acquired a reverse kind or lost numeric fields")
        }
    }

    private static func boundedExchangeRing() throws {
        try check("real-query-exports-remain-within-128-exchanges-and-two-lease-records") {
            let peer = ObservablePeer(recorder: DNSStreamProgressRecorder())
            let diagnostics = NetworkPerformanceDiagnostics()
            let owner = Owner(.doh, peers: [peer], diagnostics: diagnostics); defer { try? owner.close() }
            var firstTrace: DNSQueryExchangeTrace?
            var firstID: UUID?
            for index in 0..<144 {
                let ticket = try owner.submit(query(type: 1, name: "ring-\(index).private-fixture.invalid"))
                if index == 0 { firstTrace = owner.pool.ioAuditTrace(ticket.id); firstID = try owner.exchange(ticket).id }
                try reply(owner, peer); try expectSuccess(ticket)
                let values = diagnostics.snapshot().dnsQueryExchanges
                try require(values.count <= 128 && values.allSatisfy { ($0.leaseIOProgress?.count ?? 0) <= 2 },
                            "Query I/O snapshots expanded the bounded diagnostic ring")
            }
            let before = diagnostics.snapshot().dnsQueryExchanges
            try require(firstTrace != nil && firstID != nil, "Ring test did not retain its first live exchange handle")
            try require(before.count == 128 && before.allSatisfy { $0.id != firstID }, "Completed old exchanges did not rotate out")
            firstTrace?.recordLeaseIOProgress(DNSQueryLeaseIOProgressSnapshot(ordinal: 2, reusedConnection: false,
                sampledBeforeIdleRetry: false, millisecondsSinceSend: 0, resolverReadRequests: 0,
                firstResolverReadMilliseconds: nil, pooledReadPendingAtSend: false, pooledReadPendingAtSample: false,
                plaintextResponseBytes: 0, stream: nil))
            try require(diagnostics.snapshot().dnsQueryExchanges == before, "Late evicted handle recreated an old query record")
        }
    }

    static func main() {
        do {
            for kind in Kind.allCases {
                try stalledPhases(kind)
                try reuseAndRetry(kind)
                try frozenTerminalAndAvailability(kind)
                try metadataAndResponse(kind)
            }
            try boundedExchangeRing()
            let report: [String: Any] = ["groups": groups, "assertions": assertions, "failedGroups": [],
                                       "memoryOnly": true, "nativeNetworkUsed": false,
                                       "maxJSONRoundtripMillisecondsError": maxJSONRoundtripMillisecondsError,
                                       "realRequestPools": ["DoH", "DoT", "proxyTCP"]]
            print(String(data: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!)
        } catch {
            fputs("FAIL DNS query I/O: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}

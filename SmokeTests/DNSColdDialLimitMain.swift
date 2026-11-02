import Foundation
import Network
import Darwin

/// Exercises the real resolver/request/pool/store with held memory dial
/// callbacks. There are no listeners, external endpoints, app or Helper calls.
@main
private enum DNSColdDialLimitMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private enum Kind: String, CaseIterable { case doh, dot }
    private final class Peer: NativeOutboundByteStream {
        private let lock = NSLock()
        private let kind: Kind
        private var pending: ((Data?, Bool, Error?) -> Void)?
        private var response: Data?
        private var lastWire = Data()
        private var stopped = false, failSend = false, writes = 0
        init(_ kind: Kind) { self.kind = kind }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock()
            guard !stopped else { lock.unlock(); completion(NativeOutboundError.cancelled); return }
            writes += 1; lastWire = data
            let failing = failSend; failSend = false; lock.unlock()
            completion(failing ? NWError.posix(.ECONNRESET) : nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped, pending == nil else {
                lock.unlock(); completion(nil, true, NativeOutboundError.cancelled); return
            }
            if let response { self.response = nil; lock.unlock(); completion(response, false, nil) }
            else { pending = completion; lock.unlock() }
        }
        func reply() throws {
            lock.lock()
            let wire = lastWire, kind = self.kind
            guard !stopped, !wire.isEmpty, response == nil else {
                lock.unlock(); throw Failure(text: "reply had no live request or duplicated buffered bytes")
            }
            lock.unlock()
            let query: Data
            if kind == .doh {
                guard let boundary = wire.range(of: Data("\r\n\r\n".utf8)) else {
                    throw Failure(text: "production DoH request has no header boundary")
                }
                query = Data(wire[boundary.upperBound...])
            } else { query = Data(wire.dropFirst(2)) }
            guard query.count >= 12 else { throw Failure(text: "memory peer received an incomplete DNS query") }
            var answer = query; answer[2] = 0x81; answer[3] = 0x80
            let bytes: Data
            if kind == .doh {
                bytes = Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(answer.count)\r\n\r\n".utf8) + answer
            } else { bytes = Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer }
            lock.lock()
            guard !stopped else { lock.unlock(); throw Failure(text: "memory reply raced teardown") }
            let receive = pending; pending = nil
            if receive == nil { response = bytes }
            lock.unlock()
            receive?(bytes, false, nil)
        }
        func rejectNextSend() { lock.lock(); failSend = true; lock.unlock() }
        func cancel() {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            stopped = true; let receive = pending; pending = nil; response = nil; lock.unlock()
            receive?(nil, true, NativeOutboundError.cancelled)
        }
        var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
        var sendCount: Int { lock.lock(); defer { lock.unlock() }; return writes }
    }
    private final class Probe {
        private struct Dial {
            let complete: (Result<any NativeOutboundByteStream, Error>) -> Void
            var acknowledged = false, cancellations = 0, callbacks = 0
            var peer: Peer?
        }
        struct Snapshot {
            let opens: Int, pending: [Int], peak: Int, cancellations: [Int], callbacks: [Int], peers: [Peer]
        }
        private let lock = NSLock()
        private var dials: [Dial] = []
        private var peakPending = 0
        private var queue: DispatchQueue?
        var dialer: MetadataAwareEncryptedDNSStreamDialer {
            { [self] _, _, _, queue, _, _, done in
                lock.lock()
                self.queue = queue
                let index = dials.count; dials.append(Dial(complete: done))
                peakPending = max(peakPending, dials.filter { !$0.acknowledged }.count)
                lock.unlock()
                // Deliberately withhold the physical ACK. A cancellation
                // action alone must not restore a physical cold-dial slot.
                return { [self] in
                    lock.lock(); dials[index].cancellations += 1; lock.unlock()
                }
            }
        }
        @discardableResult
        func succeed(_ index: Int, _ kind: Kind) throws -> Peer {
            let peer = Peer(kind)
            try deliver(index, .success(peer), peer: peer)
            return peer
        }
        func fail(_ index: Int) throws { try deliver(index, .failure(NWError.posix(.ECONNRESET))) }
        private func deliver(_ index: Int, _ value: Result<any NativeOutboundByteStream, Error>, peer: Peer? = nil) throws {
            lock.lock()
            guard dials.indices.contains(index), !dials[index].acknowledged else {
                lock.unlock(); throw Failure(text: "physical dial callback was missing or duplicated")
            }
            dials[index].acknowledged = true; dials[index].callbacks += 1; dials[index].peer = peer
            let complete = dials[index].complete; lock.unlock()
            complete(value)
        }
        /// Every submission has already enqueued its start before this
        /// barrier. Extra passes also drain coalesced return/availability work.
        func barrier() throws {
            lock.lock(); let queue = self.queue; lock.unlock()
            guard let queue else { throw Failure(text: "no real resolver queue was captured") }
            for _ in 0..<4 { queue.sync {} }
        }
        var snapshot: Snapshot {
            lock.lock(); defer { lock.unlock() }
            return Snapshot(opens: dials.count,
                pending: dials.indices.filter { !dials[$0].acknowledged }, peak: peakPending,
                cancellations: dials.map(\.cancellations), callbacks: dials.map(\.callbacks),
                peers: dials.compactMap(\.peer))
        }
    }
    private final class Book {
        private let lock = NSLock()
        private var results: [Int: [Result<Data, EncryptedDNSQueryFailure>]] = [:]
        private var observations: [Int: [DNSQueryTransportEvidence]] = [:]
        private var denials: [Int: [EncryptedDNSQueryFailure]] = [:]
        func record(_ index: Int, query: Data, result: Result<Data, EncryptedDNSQueryFailure>) {
            var value = result
            if case .success(let answer) = result,
               !DNSMessageInspection.responseMatchesQuery(answer, query: query) { value = .failure(.invalidResponse) }
            lock.lock(); results[index, default: []].append(value); lock.unlock()
        }
        func evidence(_ index: Int, _ value: DNSQueryTransportEvidence) {
            lock.lock(); observations[index, default: []].append(value); lock.unlock()
        }
        func barrier(_ index: Int, _ value: DNSProxyFallbackBarrier) {
            guard case .failure(let error) = value else { return }
            lock.lock(); denials[index, default: []].append(EncryptedDNSQueryFailure.classify(error)); lock.unlock()
        }
        func evidence(_ index: Int) -> [DNSQueryTransportEvidence] {
            lock.lock(); defer { lock.unlock() }; return observations[index] ?? []
        }
        func success(_ index: Int) -> Bool {
            lock.lock(); defer { lock.unlock() }
            guard let first = results[index]?.first, case .success = first else { return false }; return true
        }
        func failure(_ index: Int) -> EncryptedDNSQueryFailure? {
            lock.lock(); defer { lock.unlock() }
            guard let first = results[index]?.first, case .failure(let failure) = first else { return nil }; return failure
        }
        func exactlyOnce(_ indices: Range<Int>) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return Set(results.keys) == Set(indices) && results.values.allSatisfy { $0.count == 1 }
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return results.values.reduce(0) { $0 + $1.count } }
        var hasPrivacyDenial: Bool {
            lock.lock(); defer { lock.unlock() }
            return denials.values.joined().contains { $0 == .authentication || $0 == .invalidResponse || $0 == .other }
        }
    }
    private final class Owner {
        let probe = Probe(), book = Book()
        let budget = SOCKSUDPGlobalBudget(resources: 64, packets: 0, bytes: 0)
        private let resolve: (Data, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                              @escaping (DNSProxyFallbackBarrier) -> Void,
                              @escaping (DNSQueryTransportEvidence) -> Void, DNSQueryExecutionContext) -> UUID?
        private let cancelAll: () -> Void
        private let cancelOne: (UUID, @escaping () -> Void) -> Void
        private var ids: [Int: UUID] = [:]
        private(set) var contexts: [Int: DNSQueryExecutionContext] = [:]
        init(_ kind: Kind, timeout: DispatchTimeInterval = .seconds(5)) {
            switch kind {
            case .doh:
                let resolver = DoHResolver(endpoint: DoHEndpoint("https://cold.memory.invalid/dns-query#203.0.113.53")!,
                    metadataStreamDialer: probe.dialer, bootstrapTimeout: timeout, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0, completion: $1, downgradeBarrier: $2,
                    transportEvidence: $3, executionContext: $4) }
                cancelAll = { resolver.cancel() }; cancelOne = { resolver.cancel($0, completion: $1) }
            case .dot:
                let resolver = DoTResolver(endpoint: DoTEndpoint("tls://cold.memory.invalid#203.0.113.53")!,
                    metadataStreamDialer: probe.dialer, requestTimeout: timeout, resourceBudget: budget)
                resolve = { resolver.resolveResult(query: $0, completion: $1, downgradeBarrier: $2,
                    transportEvidence: $3, executionContext: $4) }
                cancelAll = { resolver.cancel() }; cancelOne = { resolver.cancel($0, completion: $1) }
            }
        }
        func submit(_ index: Int) throws {
            let query = DNSMessageInspection.query(for: "cold-\(index).memory.invalid", type: 1,
                id: UInt16(0x5000 + index))!, context = DNSQueryExecutionContext()
            let book = self.book
            guard let id = resolve(query, { book.record(index, query: query, result: $0) },
                { book.barrier(index, $0) }, { book.evidence(index, $0) }, context) else {
                throw Failure(text: "bounded query was rejected at registration")
            }
            ids[index] = id; contexts[index] = context
        }
        func cancel(_ index: Int) throws {
            guard let id = ids[index] else { throw Failure(text: "cancelled an unknown caller") }
            let ack = DispatchSemaphore(value: 0)
            cancelOne(id) { ack.signal() }
            try require(ack.wait(timeout: .now() + 2) == .success, "logical cancellation ACK was lost")
        }
        func close() throws {
            cancelAll(); try probe.barrier()
            for index in probe.snapshot.pending { try probe.fail(index) }
            try probe.barrier()
            let ack = DispatchSemaphore(value: 0)
            cancelOne(UUID()) { ack.signal() }
            try require(ack.wait(timeout: .now() + 2) == .success, "owner cleanup queue did not drain")
            try until("owner retained a stream or global idle resource") {
                self.budget.usage.resources == 0 && self.probe.snapshot.peers.allSatisfy(\.cancelled)
            }
            try require(probe.snapshot.callbacks.allSatisfy { $0 == 1 }, "physical completion was lost or duplicated")
            try require(probe.snapshot.cancellations.allSatisfy { $0 <= 1 }, "a native cancellation action ran twice")
        }
        deinit { cancelAll() }
    }
    private static var checks = 0, passed: [String] = [], failed: [String] = []
    private static var measurements: [String: [String: Int]] = [:]
    private static func require(_ value: Bool, _ text: String) throws {
        checks += 1; if !value { throw Failure(text: text) }
    }
    private static func until(_ text: String, seconds: TimeInterval = 3, _ body: () -> Bool) throws {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while !body() && ProcessInfo.processInfo.systemUptime < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.005))
        }
        try require(body(), text)
    }
    private static func check(_ name: String, _ body: () throws -> Void) {
        do { try body(); passed.append(name); print("PASS " + name) }
        catch { failed.append(name); print("FAIL " + name + ": " + error.localizedDescription) }
    }
    private static func baseline(_ kind: Kind, expected: Int) throws {
        let owner = Owner(kind)
        defer { try? owner.close() }
        for index in 0..<16 { try owner.submit(index) }
        try until("initial cold wave did not open") { owner.probe.snapshot.opens >= expected }
        try owner.probe.barrier()
        try require(owner.probe.snapshot.opens == expected && owner.probe.snapshot.pending.count == expected,
                    "held initial cold wave exceeded its expected physical opens")
        try require(owner.book.count == 0, "held physical callbacks unexpectedly completed a caller")
        measurements[kind.rawValue + "-baseline"] = ["queries": 16, "opens": owner.probe.snapshot.opens,
            "peakUnacknowledgedDials": owner.probe.snapshot.peak]
        try owner.close()
        try require(owner.book.exactlyOnce(0..<16), "baseline cleanup lost exactly-once callers")
    }
    private static func waves(_ kind: Kind) throws {
        let owner = Owner(kind)
        defer { try? owner.close() }
        for index in 0..<16 { try owner.submit(index) }
        try until("four cold connections did not start") { owner.probe.snapshot.opens >= 4 }
        try owner.probe.barrier()
        try require(owner.probe.snapshot.opens == 4, "16 registered queries opened more than four cold dials")
        var peers: [Peer] = []
        for wave in 0..<4 {
            let expected = Array((wave * 4)..<((wave + 1) * 4))
            try require(owner.probe.snapshot.pending == expected, "cold wave lost FIFO dial admission")
            for index in expected { peers.append(try owner.probe.succeed(index, kind)) }
            try until("acknowledged wave did not send its real DNS queries") {
                peers.allSatisfy { $0.sendCount == 1 }
            }
            try owner.probe.barrier()
            try require(owner.probe.snapshot.opens == min(16, (wave + 2) * 4),
                        "physical callback did not admit exactly the next bounded cold wave")
            try require(owner.probe.snapshot.peak == 4, "physical callback admitted a fifth unfinished cold dial")
        }
        try require(owner.book.count == 0 && peers.count == 16, "the active exchange limit was reduced below 16")
        try owner.submit(16); try owner.probe.barrier()
        try require(owner.probe.snapshot.opens == 16 && owner.book.count == 0, "17th exchange bypassed the 16-active limit")
        try peers[0].reply()
        try until("ready return was not reused for queued exchange 17") {
            peers[0].sendCount == 2 && owner.book.success(0)
        }
        try require(owner.book.success(0) && owner.book.evidence(16) == [.reused], "ready exchange reuse lost caller identity/evidence")
        for peer in peers { try peer.reply() }
        try until("16 live exchanges and queued reuse did not all complete") { owner.book.count == 17 }
        try require((0..<17).allSatisfy { owner.book.success($0) } && owner.book.exactlyOnce(0..<17),
                    "wave/reuse answers mismatched callers or completed more than once")
        try require(owner.probe.snapshot.opens == 16, "queued reuse created an unnecessary seventeenth dial")
        #if HAVE_RESOLVER_QUEUE_DIAGNOSTICS
        let roots = Set(owner.contexts.values.map(\.rootID))
        let exchanges = NetworkPerformanceDiagnostics.shared.snapshot().dnsQueryExchanges.filter {
            $0.rootID.map(roots.contains) ?? false
        }
        try require(exchanges.filter { ($0.resolverQueueReasons ?? []).contains(.coldConnectionLimit)
            && ($0.resolverQueueMilliseconds ?? 0) > 0 }.count >= 12,
            "held cold queue lost its actual duration or fixed coldConnectionLimit reason")
        let lastRoot = owner.contexts[16]!.rootID
        try require(exchanges.contains { $0.rootID == lastRoot && ($0.resolverQueueReasons ?? []).contains(.queryLimit) },
                    "17th ready exchange did not report the distinct active-query queue reason")
        #endif
        measurements[kind.rawValue + "-waves"] = ["successfulQueries": 17, "activeExchanges": 16,
            "coldPeak": owner.probe.snapshot.peak, "physicalDials": owner.probe.snapshot.opens]
        try owner.close()
    }
    private static func idleBypassesColdLimit(_ kind: Kind, dirtyRetry: Bool) throws {
        let owner = Owner(kind)
        defer { try? owner.close() }
        for index in 0..<5 { try owner.submit(index) }
        try until("idle fixture did not saturate four cold dials") { owner.probe.snapshot.opens >= 4 }
        try owner.probe.barrier()
        let ready = try owner.probe.succeed(0, kind)
        try until("ready stream did not send or make room for the fifth cold dial") {
            ready.sendCount == 1 && owner.probe.snapshot.opens == 5
        }
        try ready.reply()
        try until("warm memory exchange did not finish") { owner.book.success(0) }
        try owner.probe.barrier()
        try require(owner.probe.snapshot.pending.count == 4, "idle fixture failed to retain four independent cold dials")
        if dirtyRetry { ready.rejectNextSend() }
        try owner.submit(5)
        try until("cold saturation blocked a ready idle checkout") { ready.sendCount == 2 }
        try owner.probe.barrier()
        try require(owner.probe.snapshot.opens == 5 && owner.book.evidence(5) == [.reused],
                    "ready checkout consumed a cold slot or invented fresh evidence")
        if dirtyRetry {
            try require(!owner.book.success(5) && owner.book.failure(5) == nil,
                        "dirty-idle retry was rejected as capacity instead of remaining queued")
            try owner.probe.fail(1)
            try until("a real cold receipt did not admit the dirty-idle fresh retry") { owner.probe.snapshot.opens == 6 }
            let fresh = try owner.probe.succeed(5, kind)
            try until("dirty idle fresh retry did not send") { fresh.sendCount == 1 }
            try fresh.reply()
            try until("dirty-idle fresh retry did not return its original caller answer") { owner.book.success(5) }
            try require(owner.book.evidence(5) == [.reused, .reusedThenFresh], "queued dirty-idle retry lost actual transport evidence")
        } else {
            try ready.reply()
            try until("ready idle checkout did not complete while four cold dials remained held") { owner.book.success(5) }
            try require(owner.probe.snapshot.pending.count == 4 && owner.probe.snapshot.opens == 5,
                        "idle success secretly required a new cold callback")
        }
        try require(owner.probe.snapshot.peak == 4, "ready idle path exceeded four unfinished cold dials")
        try owner.close()
        try require(owner.book.exactlyOnce(0..<6), "idle/retry cleanup duplicated or lost a caller")
    }
    private static func cancellationRequiresPhysicalACK(_ kind: Kind) throws {
        let owner = Owner(kind)
        defer { try? owner.close() }
        for index in 0..<16 { try owner.submit(index) }
        try until("cancellation fixture did not open its cold wave") { owner.probe.snapshot.opens >= 4 }
        try owner.probe.barrier(); try owner.cancel(0); try owner.probe.barrier()
        try require(owner.book.failure(0) == .cancelled && owner.probe.snapshot.cancellations[0] == 1,
                    "logical cancellation did not reach its pending physical dial")
        try require(owner.probe.snapshot.opens == 4 && owner.probe.snapshot.pending.count == 4,
                    "logical cancellation freed a physical slot before the real dial callback")
        let late = try owner.probe.succeed(0, kind)
        try until("real late dial receipt did not close its revoked stream and admit one waiter") {
            late.cancelled && owner.probe.snapshot.opens == 5
        }
        try owner.probe.barrier()
        try require(late.sendCount == 0 && owner.probe.snapshot.pending.count == 4,
                    "late success sent a cancelled query or admitted excess cold dials")
        try owner.cancel(15); try owner.probe.barrier()
        try require(owner.book.failure(15) == .cancelled && owner.probe.snapshot.opens == 5,
                    "cancelling a queued caller dialed it or completed with capacity")
        try owner.close()
        try require(owner.book.exactlyOnce(0..<16) && owner.probe.snapshot.peak == 4,
                    "cancellation or late callback duplicated a caller or exceeded cold pressure")
    }
    private static func queuedDeadline(_ kind: Kind) throws {
        let owner = Owner(kind, timeout: .milliseconds(350))
        defer { try? owner.close() }
        let started = ProcessInfo.processInfo.systemUptime
        for index in 0..<16 { try owner.submit(index) }
        try until("deadline fixture did not start four dials") { owner.probe.snapshot.opens >= 4 }
        try owner.probe.barrier()
        try until("queued callers did not expire under their original registration deadline") { owner.book.count == 16 }
        let elapsed = ProcessInfo.processInfo.systemUptime - started
        try owner.probe.barrier()
        try require((0..<16).allSatisfy { owner.book.failure($0) == .timeout },
                    "cold wait invented a capacity, provider or authentication failure")
        try require(elapsed >= 0.32 && elapsed < 1.5, "cold queue reset or lost the original 350ms deadline")
        try require(owner.probe.snapshot.opens == 4 && owner.probe.snapshot.pending.count == 4,
                    "queue expiry started extra transports or released unacknowledged physical dials")
        try require((4..<16).allSatisfy { owner.book.evidence($0).isEmpty } && !owner.book.hasPrivacyDenial,
                    "a purely queued timeout invented transport observation or a privacy denial")
        #if HAVE_RESOLVER_QUEUE_DIAGNOSTICS
        let roots = Set((4..<16).map { owner.contexts[$0]!.rootID })
        let exchanges = NetworkPerformanceDiagnostics.shared.snapshot().dnsQueryExchanges.filter {
            $0.rootID.map(roots.contains) ?? false
        }
        try require(exchanges.count == 12 && exchanges.allSatisfy {
            $0.physicalAttemptIDs.isEmpty && ($0.resolverQueueMilliseconds ?? 0) >= 300
            && ($0.resolverQueueReasons ?? []).contains(.coldConnectionLimit)
        }, "queued timeout diagnostics lost local waiting or fabricated a physical attempt")
        #endif
        try owner.close()
        try require(owner.book.exactlyOnce(0..<16), "timeout cleanup completed a waiter twice")
    }
    static func main() {
        let args = CommandLine.arguments
        let position = args.firstIndex(of: "--expect-cold-limit")
        let expected = position.flatMap { $0 + 1 < args.count ? Int(args[$0 + 1]) : nil } ?? 4
        guard expected == 4 || expected == 16 else { fputs("expected cold limit must be 4 or 16\n", stderr); exit(2) }
        for kind in Kind.allCases {
            if expected == 16 { check(kind.rawValue + "-archived-16-cold-characterization") { try baseline(kind, expected: expected) } }
            else {
                check(kind.rawValue + "-four-cold-sixteen-active-queued-reuse") { try waves(kind) }
                check(kind.rawValue + "-ready-idle-bypasses-cold-saturation") { try idleBypassesColdLimit(kind, dirtyRetry: false) }
                check(kind.rawValue + "-dirty-idle-retry-waits-for-real-slot") { try idleBypassesColdLimit(kind, dirtyRetry: true) }
                check(kind.rawValue + "-physical-cancel-acknowledgment") { try cancellationRequiresPhysicalACK(kind) }
                check(kind.rawValue + "-queued-original-deadline") { try queuedDeadline(kind) }
            }
        }
        let report: [String: Any] = ["expectedColdLimit": expected, "checks": checks,
            "passedGroups": passed, "failedGroups": failed, "measurements": measurements]
        let encoded = try! JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        print(String(decoding: encoded, as: UTF8.self))
        if !failed.isEmpty { exit(1) }
    }
}

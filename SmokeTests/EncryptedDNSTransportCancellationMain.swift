import Foundation
import Darwin
import HajimiCore

/// Existing-object regression: raw transports are memory-only black holes;
/// the production nested TLS layer creates only its one-shot loopback bridge.
/// No profile, user settings, public DNS or external endpoint is involved.
@main
enum EncryptedDNSTransportCancellationMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }

    private final class BlackHole: NativeOutboundByteStream {
        private let lock = NSLock()
        private var closed = false
        private var read: ((Data?, Bool, Error?) -> Void)?
        private var writes = 0
        var hasCiphertext: Bool { lock.lock(); defer { lock.unlock() }; return writes > 0 }
        var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return closed }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); let stopped = closed
            if !stopped && !data.isEmpty { writes += 1 }
            lock.unlock()
            completion(stopped ? Failure(text: "Memory raw stream closed") : nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            if closed { lock.unlock(); completion(nil, true, Failure(text: "Memory raw stream closed")); return }
            if read != nil { lock.unlock(); completion(nil, true, Failure(text: "Concurrent memory raw read")); return }
            read = completion; lock.unlock()
        }
        func cancel() {
            lock.lock(); closed = true; let callback = read; read = nil; lock.unlock()
            callback?(nil, true, Failure(text: "Memory raw stream cancelled"))
        }
    }

    private final class Probe {
        private let lock = NSLock()
        private var peers: [BlackHole] = []
        private var dials = 0, dialResults = 0, queryResults = 0, answers = 0
        private var resolverQueue: DispatchQueue?
        private var queryCounts: [Int: Int] = [:], dialCounts: [Int: Int] = [:]
        func dial(_ queue: DispatchQueue, _ completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void)
            -> (() -> Void)? {
            let raw = BlackHole()
            lock.lock(); dials += 1; let index = dials; peers.append(raw)
            if resolverQueue == nil { resolverQueue = queue }
            lock.unlock()
            let result: (Result<any NativeOutboundByteStream, Error>) -> Void = { result in
                self.lock.lock(); self.dialResults += 1; self.dialCounts[index, default: 0] += 1; self.lock.unlock()
                completion(result)
            }
            #if HAJIMI_CANCELLABLE_TLS_TRANSPORT
            return NativeOutboundFactory.beginTLSUpgrade(stream: raw, serverName: "blackhole.fixture.invalid",
                                                         queue: queue, completion: result)
            #else
            NativeOutboundFactory.upgradeTLS(stream: raw, serverName: "blackhole.fixture.invalid",
                                            queue: queue, completion: result)
            return nil
            #endif
        }
        func result(_ index: Int, answer: Data?) {
            lock.lock(); queryResults += 1; queryCounts[index, default: 0] += 1
            if answer != nil { answers += 1 }; lock.unlock()
        }
        /// Revoke the whole registered batch before any cancellation callback
        /// can refill the FIFO. This isolates cancel-after-admission from the
        /// legitimate scheduling of another still-live query during the loop.
        func holdResolverQueue() throws -> () -> Void {
            lock.lock(); let queue = resolverQueue; lock.unlock()
            guard let queue else { throw Failure(text: "No resolver queue was captured by the memory dialer") }
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            queue.async { entered.signal(); _ = release.wait(timeout: .now() + 3) }
            guard entered.wait(timeout: .now() + 3) == .success else {
                release.signal(); throw Failure(text: "Cancellation fixture could not hold its resolver queue")
            }
            return { release.signal() }
        }
        var snapshot: (dials: Int, dialResults: Int, queryResults: Int, answers: Int, peers: [BlackHole],
                       queryCounts: [Int: Int], dialCounts: [Int: Int]) {
            lock.lock(); defer { lock.unlock() }
            return (dials, dialResults, queryResults, answers, peers, queryCounts, dialCounts)
        }
    }

    private static func require(_ condition: Bool, _ text: String) throws {
        if !condition { throw Failure(text: text) }
    }

    private static func until(_ text: @autoclosure () -> String, seconds: TimeInterval = 5,
                              _ condition: () -> Bool) throws {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while !condition() && ProcessInfo.processInfo.systemUptime < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
        }
        try require(condition(), text())
    }

    private static func run(expectCurrentGap: Bool) throws {
        let initialPhysicalDials: Int
        #if HAJIMI_CANCELLABLE_TLS_TRANSPORT
        try require(!expectCurrentGap, "The cancellable after-fixture cannot select the legacy before mode")
        try require(DoHResolver.maximumConcurrentQueries == 16,
                    "Active query limit: expected=16, observed=\(DoHResolver.maximumConcurrentQueries)")
        initialPhysicalDials = DoHResolver.maximumConcurrentConnectionAttempts
        try require(initialPhysicalDials == 4,
                    "Default cold TLS dial limit: expected=4, observed=\(initialPhysicalDials)")
        #else
        try require(expectCurrentGap, "The legacy fixture requires its explicit before-fix flag")
        initialPhysicalDials = 128
        #endif
        let probe = Probe()
        let endpoint = DoHEndpoint("https://blackhole.fixture.invalid/dns-query#203.0.113.53")!
        #if HAJIMI_CANCELLABLE_TLS_TRANSPORT
        let resolver = DoHResolver(endpoint: endpoint, cancellableStreamDialer: { _, _, _, queue, completion in
            probe.dial(queue, completion)
        })
        #else
        let resolver = DoHResolver(endpoint: endpoint, streamDialer: { _, _, _, queue, completion in
            _ = probe.dial(queue, completion)
        })
        #endif
        defer { resolver.cancel(); probe.snapshot.peers.forEach { $0.cancel() } }
        var queries: [UUID] = []
        for index in 0..<128 {
            let query = DNSMessageInspection.query(for: "cancel-\(index).fixture.invalid", type: 1, id: UInt16(0x4000 + index))!
            guard let id = resolver.resolve(query: query, completion: { probe.result(index, answer: $0) }) else {
                throw Failure(text: "A bounded initial query was not admitted")
            }
            queries.append(id)
        }
        try until("Bounded memory TLS concurrency: expected=\(initialPhysicalDials), observed=\(probe.snapshot.dials)") {
            probe.snapshot.dials == initialPhysicalDials
        }
        try until("Memory ClientHello carriers: expected>=1, observed=\(probe.snapshot.peers.filter(\.hasCiphertext).count)") {
            probe.snapshot.peers.contains(where: \.hasCiphertext)
        }
        try require(probe.snapshot.queryResults == 0,
                    "Query results before cancellation: expected=0, observed=\(probe.snapshot.queryResults)")
        do {
            let release = try probe.holdResolverQueue()
            defer { release() }
            queries.forEach { resolver.cancel($0) }
        }
        try until("Cancelled query results: expected=128, observed=\(probe.snapshot.queryResults)") {
            probe.snapshot.queryResults == 128
        }
        let before = probe.snapshot
        try require(before.dials == initialPhysicalDials && before.peers.count == initialPhysicalDials,
                    "Dials/peers after batch cancellation: expected=\(initialPhysicalDials)/\(initialPhysicalDials), observed=\(before.dials)/\(before.peers.count)")
        try require(before.queryCounts.count == 128 && before.queryCounts.values.allSatisfy({ $0 == 1 }),
                    "Initial logical results: expected=128 unique exactly-once callbacks, observed=\(before.queryCounts.count) unique, duplicates=\(before.queryCounts.filter { $0.value != 1 })")
        let extra = DNSMessageInspection.query(for: "cancel-overflow.fixture.invalid", type: 1, id: 0x4100)!
        if expectCurrentGap {
            _ = resolver.resolve(query: extra, completion: { probe.result(128, answer: $0) })
            try until("Overflow query did not return a bounded failure") { probe.snapshot.queryResults == 129 }
            let after = probe.snapshot
            let gap = before.peers.allSatisfy({ !$0.isCancelled }) && before.dialResults == 0
                && after.dials == 128 && after.answers == 0
            try require(gap, "The expected pre-fix cancellation/slot gap was not observed")
            try require(after.queryCounts.count == 129 && after.queryCounts.values.allSatisfy({ $0 == 1 }),
                        "Legacy overflow query did not complete exactly once")
            let forwarded = before.peers.filter(\.hasCiphertext).count
            print("CONFIRMED pre-fix gap: 128 cancelled DNS queries, raw streams cancelled=0, TLS dial callbacks=0, ClientHello carriers=\(forwarded); query 129 failed before a dial")
        } else {
            try until("TLS cancellation ACK/raw close: expected=\(initialPhysicalDials)/\(initialPhysicalDials), observed=\(probe.snapshot.dialResults)/\(probe.snapshot.peers.filter(\.isCancelled).count)") {
                let state = probe.snapshot
                return state.dialResults == initialPhysicalDials && state.peers.allSatisfy(\.isCancelled)
            }
            let acknowledged = probe.snapshot
            try require(acknowledged.dials == initialPhysicalDials
                        && acknowledged.dialCounts.count == initialPhysicalDials
                        && acknowledged.dialCounts.values.allSatisfy({ $0 == 1 }),
                        "Initial physical results: expected=\(initialPhysicalDials) dials/unique exactly-once ACKs, observed=\(acknowledged.dials)/\(acknowledged.dialCounts.count), duplicates=\(acknowledged.dialCounts.filter { $0.value != 1 })")
            guard let extraID = resolver.resolve(query: extra, completion: { probe.result(128, answer: $0) }) else {
                throw Failure(text: "Query 129 was not admitted after actual TLS cancellation acknowledgments")
            }
            try until("Recovered physical dials: expected=\(initialPhysicalDials + 1), observed=\(probe.snapshot.dials)") {
                probe.snapshot.dials == initialPhysicalDials + 1
            }
            resolver.cancel(extraID)
            try until("Query results including recovery: expected=129, observed=\(probe.snapshot.queryResults)") {
                probe.snapshot.queryResults == 129
            }
            try until("Recovered TLS ACK/raw close: expected=\(initialPhysicalDials + 1)/\(initialPhysicalDials + 1), observed=\(probe.snapshot.dialResults)/\(probe.snapshot.peers.filter(\.isCancelled).count)") {
                let state = probe.snapshot
                return state.dialResults == initialPhysicalDials + 1 && state.peers.allSatisfy(\.isCancelled)
            }
            let final = probe.snapshot
            try require(final.answers == 0 && final.dials == initialPhysicalDials + 1
                        && final.peers.count == initialPhysicalDials + 1,
                        "Final answers/dials/peers: expected=0/\(initialPhysicalDials + 1)/\(initialPhysicalDials + 1), observed=\(final.answers)/\(final.dials)/\(final.peers.count)")
            try require(final.queryCounts.count == 129 && Set(final.queryCounts.keys) == Set(0..<129)
                        && final.queryCounts.values.allSatisfy({ $0 == 1 })
                        && final.dialCounts.count == initialPhysicalDials + 1
                        && final.dialCounts.values.allSatisfy({ $0 == 1 }),
                        "Final callbacks: expected logical IDs=0..<129 exactly once and \(initialPhysicalDials + 1) physical ACKs exactly once, observed logical=\(final.queryCounts.count), missing=\(Set(0..<129).subtracting(final.queryCounts.keys).sorted()), logical duplicates=\(final.queryCounts.filter { $0.value != 1 }), physical=\(final.dialCounts.count), physical duplicates=\(final.dialCounts.filter { $0.value != 1 })")
            print("PASS cancellable TLS: active query limit=16, default cold TLS dial limit=\(initialPhysicalDials); 128 registered queries cancelled exactly once, \(initialPhysicalDials) handshakes dialed and acknowledged; query 129 started physical dial \(initialPhysicalDials + 1), no live raw streams or DNS answers")
            return
        }
        before.peers.forEach { $0.cancel() }
        do {
            try until("Closed memory raw streams did not acknowledge all late TLS failures", seconds: 17) {
                probe.snapshot.dialResults == 128
            }
        } catch {
            let state = probe.snapshot
            throw Failure(text: "Closed memory raw streams left TLS callbacks unacknowledged past the 15s timer: callbacks=\(state.dialResults)/128, closed raw=\(state.peers.filter(\.isCancelled).count)/128")
        }
        let recovered = DNSMessageInspection.query(for: "cancel-recovered.fixture.invalid", type: 1, id: 0x4200)!
        let recoveryID = resolver.resolve(query: recovered, completion: { probe.result(129, answer: $0) })
        try until("Acknowledged TLS callbacks did not restore the per-resolver slot") { probe.snapshot.dials == 129 }
        if let recoveryID { resolver.cancel(recoveryID) }
        probe.snapshot.peers.forEach { $0.cancel() }
        try until("Recovery cleanup did not acknowledge its TLS dial") { probe.snapshot.dialResults == 129 }
        try until("Recovery query completed more than once or leaked") { probe.snapshot.queryResults == 130 }
        let legacyFinal = probe.snapshot
        try require(legacyFinal.queryCounts.count == 130 && Set(legacyFinal.queryCounts.keys) == Set(0..<130)
                    && legacyFinal.queryCounts.values.allSatisfy({ $0 == 1 })
                    && legacyFinal.dialCounts.count == 129 && legacyFinal.dialCounts.values.allSatisfy({ $0 == 1 }),
                    "Legacy late-callback cleanup duplicated or lost a logical/physical result")
        print("PASS late-callback cleanup: exactly-once query/dial results, per-resolver capacity recovered; only memory raw and TLS loopback")
    }

    static func main() {
        do {
            try run(expectCurrentGap: CommandLine.arguments.contains("--expect-current-gap"))
        } catch {
            FileHandle.standardError.write(Data("Encrypted DNS transport cancellation fixture failed: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}

// Memory-only regression for batch returns followed by an adaptive hedge.
// The production DoT initializer supplies the after-case handoff default.
private extension EncryptedDNSRequestPool {
    var handoffStore: EncryptedDNSConnectionStore { connections }
    var handoffQueue: DispatchQueue { queue }
}
private extension DoTResolver {
    var handoffStore: EncryptedDNSConnectionStore { requests.handoffStore }
    var handoffQueue: DispatchQueue { requests.handoffQueue }
}

// The real direct-TLS branch is compiled but cannot perform network I/O.
private enum ProxyEngine {
    static var currentOutboundInterface: NWInterface? {
        preconditionFailure("Memory fixture attempted direct transport")
    }
}

@main private enum DNSHandoffWindowMain {
    static func now() -> Double { ProcessInfo.processInfo.systemUptime }
    static func answer(_ query: Data) -> Data {
        var result = query; result[2] = 0x81; result[3] = 0x80; return result
    }
    final class Stream: NativeOutboundByteStream {
        let lock = NSLock(), queue: DispatchQueue
        var reader: ((Data?, Bool, Error?) -> Void)?, closed = false
        init(_ queue: DispatchQueue) { self.queue = queue }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            completion(nil)
            queue.asyncAfter(deadline: .now() + 0.1) { [self] in
                lock.lock(); let callback = reader; reader = nil; let stopped = closed; lock.unlock()
                if !stopped { callback?(answer(data), false, nil) }
            }
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); reader = completion; lock.unlock()
        }
        func cancel() { lock.lock(); closed = true; reader = nil; lock.unlock() }
    }
    final class Pool {
        let budget = SOCKSUDPGlobalBudget(resources: 1024, packets: 0, bytes: 0)
        let resolver: DoTResolver
        let native = DispatchGroup()
        var reused = 0, redial = 0, returned = 0, physicalPeak = 0
        var queue: DispatchQueue { resolver.handoffQueue }
        var store: EncryptedDNSConnectionStore { resolver.handoffStore }
        init(legacy: Bool) {
            let endpoint = DoTEndpoint("tls://handoff.fixture.invalid#203.0.113.70")!
            let neverDial: EncryptedDNSStreamDialer = { _, _, _, _, _ in
                preconditionFailure("Pool-seeding fixture unexpectedly dialed")
            }
            if legacy {
                // The current clamp leaves explicit 250ms unchanged, so this
                // reproduces Build17 without a copied production implementation.
                resolver = DoTResolver(endpoint: endpoint, streamDialer: neverDial,
                    requestTimeout: .seconds(8), idleHandoffGrace: 0.25,
                    coldDialLimit: 16, resourceBudget: budget)
            } else {
                // Omit idleHandoffGrace: exercise the real production default.
                resolver = DoTResolver(endpoint: endpoint, streamDialer: neverDial,
                    requestTimeout: .seconds(8), coldDialLimit: 16, resourceBudget: budget)
            }
            // Isolate the handoff window for this 16-stream batch. Production
            // now admits four cold dials; its independent admission regression
            // covers that limit. Here every missed retained stream must fit a
            // synthetic pending dial so the original exact 4/12 and 16/0
            // window assertions remain independent of cold-dial backpressure.
            queue.sync {
                for _ in 0..<16 {
                    let entry = store.adopt(Stream(queue))!
                    store.returnIdle(entry)
                }
                physicalPeak = store.physicalOccupancyForSelfTest
                precondition(physicalPeak == 16 && budget.usage.resources == 16)
            }
        }
        func samplePhysical() { physicalPeak = max(physicalPeak, store.physicalOccupancyForSelfTest) }
    }
    final class Peer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging {
        let lock = NSLock(), pool: Pool, isReadyProvider: Bool, receive: (Data) -> Void
        var closed = false, entry: EncryptedDNSPooledConnection?
        init(pool: Pool, isReadyProvider: Bool, receive: @escaping (Data) -> Void) {
            self.pool = pool; self.isReadyProvider = isReadyProvider; self.receive = receive
        }
        func send(_ query: Data) {
            guard isReadyProvider else { return }
            pool.queue.async { [self] in
                lock.lock(); let stopped = closed; lock.unlock(); guard !stopped else { return }
                if let ready = pool.store.checkout() { pool.reused += 1; use(ready, query); return }
                guard let token = pool.store.reserveDial() else { return }
                pool.redial += 1; pool.native.enter(); pool.samplePhysical()
                // Cancellation must leave this physical reservation owned until
                // the original injected native callback arrives after deadline.
                pool.queue.asyncAfter(deadline: .now() + 3.9) { [self] in
                    defer { pool.native.leave() }
                    let accepted = pool.store.completeDial(token)
                    lock.lock(); let stopped = closed; lock.unlock()
                    let stream = Stream(pool.queue)
                    guard accepted, !stopped else { stream.cancel(); return }
                    if let ready = pool.store.adopt(stream) { use(ready, query) }
                }
            }
        }
        func use(_ ready: EncryptedDNSPooledConnection, _ query: Data) {
            entry = ready
            ready.send(query, failureObserver: { _ in }, completion: { _ in })
            ready.receive { [self] data, _, error in
                guard let data, error == nil else { return }
                entry = nil; pool.store.returnIdle(ready); pool.returned += 1
                lock.lock(); let stopped = closed; lock.unlock()
                if !stopped { receive(data) }
            }
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); closed = true; lock.unlock()
            pool.queue.async { [self] in entry?.close(); entry = nil; completion() }
        }
    }
    final class CountedPeer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging {
        let peer: Peer, onCancel: () -> Void, lock = NSLock()
        var stopped = false
        init(_ peer: Peer, _ onCancel: @escaping () -> Void) { self.peer = peer; self.onCancel = onCancel }
        func send(_ data: Data) { peer.send(data) }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); let first = !stopped; stopped = true; lock.unlock()
            if first { onCancel() }
            peer.cancel(completion: completion)
        }
    }
    final class Scenario {
        let legacy: Bool, delay: Double, pool: Pool
        let coordinator = DNSQueryCoordinator(), selector = DNSAdaptiveUpstreamSelector()
        let lock = NSLock(), done = DispatchGroup(), callbacks = DispatchQueue(label: "handoff-callback")
        var success = 0, failure = 0, attempts: [Int: Int] = [:], live: [Int: Int] = [:], peak: [Int: Int] = [:]
        let candidates = (0..<3).map { index in
            DNSUpstreamCandidate(upstream: .doh(DoHEndpoint(
                "https://c\(index).fixture.invalid/dns-query#203.0.113.\(70 + index)")!), bootstrap: nil)
        }
        init(legacy: Bool, delay: Double) { self.legacy = legacy; self.delay = delay; pool = Pool(legacy: legacy) }
        func start() {
            let deadline = now() + 3.7
            for index in 0..<16 {
                done.enter()
                DispatchQueue.global().asyncAfter(deadline: .now() + max(0, delay - 0.75)) { [self] in
                    let query = DNSMessageInspection.query(for: "handoff-\(index).fixture.invalid",
                        type: 1, id: UInt16(index + 1))!
                    coordinator.resolve(scope: "approved-query-scope", query: query,
                        callbackQueue: callbacks, absoluteDeadline: deadline, permitted: { true },
                        factory: { [self] queue, receive, failure in
                            DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector,
                                scopeKey: "handoff-health", queue: queue, permitted: { true },
                                factory: { [self] candidate, _, receive, _ in
                                    lock.lock(); attempts[index, default: 0] += 1; live[index, default: 0] += 1
                                    peak[index] = max(peak[index, default: 0], live[index]!); lock.unlock()
                                    let peer = Peer(pool: pool, isReadyProvider: candidate.id == candidates[1].id,
                                        receive: receive)
                                    return CountedPeer(peer) { [self] in
                                        lock.lock(); live[index, default: 0] -= 1; lock.unlock()
                                    }
                                }, receive: receive, failure: failure, timeout: 8, absoluteDeadline: deadline)
                        }, completion: { [self] result in
                            lock.lock()
                            if let result, DNSMessageInspection.responseMatchesQuery(result, query: query) { success += 1 }
                            else { failure += 1 }
                            lock.unlock(); done.leave()
                        })
                }
            }
        }
        func result() -> [String: Any] {
            precondition(done.wait(timeout: .now() + 6) == .success)
            precondition(pool.native.wait(timeout: .now() + 6) == .success)
            pool.queue.sync {
                pool.store.cancel()
                precondition(pool.store.physicalOccupancyForSelfTest == 0 && pool.budget.usage.resources == 0)
            }
            callbacks.sync {}
            let state = coordinator.statistics
            precondition(state.activeUpstreams == 0 && state.pendingQueries == 0)
            lock.lock(); defer { lock.unlock() }
            precondition(live.values.allSatisfy { $0 == 0 } && peak.values.allSatisfy { $0 <= 2 }
                && attempts.values.allSatisfy { $0 <= 3 })
            precondition(pool.physicalPeak <= 128)
            if pool.reused != (legacy ? 4 : 16) || pool.redial != (legacy ? 12 : 0) {
                let evidence: [String: Any] = ["window": legacy ? "explicitLegacy250ms" : "productionDoTDefaultHandoffGrace",
                    "requestedHandoffGapMs": delay * 1000, "reuse": pool.reused, "redial": pool.redial,
                    "returned": pool.returned, "success": success, "failure": failure,
                    "attempts": attempts.values.sorted(), "peaks": peak.values.sorted()]
                let data = try! JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys])
                FileHandle.standardError.write(data + Data([10]))
            }
            precondition(pool.reused == (legacy ? 4 : 16) && pool.redial == (legacy ? 12 : 0))
            precondition(success == (legacy ? 4 : 16) && failure == (legacy ? 12 : 0))
            return ["window": legacy ? "explicitLegacy250ms" : "productionDoTDefaultHandoffGrace",
                "requestedHandoffGapMs": delay * 1000, "readyReturned": 16,
                "reuse": pool.reused, "redial": pool.redial, "success": success, "failure": failure,
                "scenarioDeadlineBudgetMs": 3700, "timeoutDefaultMs": 8000,
                "maximumPerRootAttempts": attempts.values.max() ?? 0, "maximumPerRootLive": peak.values.max() ?? 0,
                "physicalPeak": pool.physicalPeak, "physicalAfterDrain": 0, "resourcesAfterDrain": pool.budget.usage.resources]
        }
    }
    static func main() {
        let scenarios = [Scenario(legacy: true, delay: 0.75), Scenario(legacy: false, delay: 0.75),
            Scenario(legacy: true, delay: 1.5), Scenario(legacy: false, delay: 1.5)]
        scenarios.forEach { $0.start() }
        for scenario in scenarios {
            let result = scenario.result()
            print(String(data: try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), encoding: .utf8)!)
        }
    }
}

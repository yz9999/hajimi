import Foundation
import HajimiDNS

@main
enum DNSModuleMain {
    private struct Failure: Error { let text: String }

    private static func require(_ value: Bool, _ text: String) throws {
        if !value { throw Failure(text: text) }
    }

    private final class Observer: DNSQueryObserver {
        private let lock = NSLock()
        private var failures = Set<DNSQueryFailureReason>()
        func recordDNS(_ event: DNSPerformanceEvent, count: Int) {}
        func recordResolution(milliseconds: Double, outcome: DNSQueryOutcome) {}
        func recordDNSFailure(_ reason: DNSQueryFailureReason) { lock.lock(); failures.insert(reason); lock.unlock() }
        func observed(_ reason: DNSQueryFailureReason) -> Bool {
            lock.lock(); defer { lock.unlock() }; return failures.contains(reason)
        }
        func beginDNSQuery(rootID: UUID, waiterID: UUID, started: UInt64, absoluteDeadline: TimeInterval) {}
        func joinDNSQuery(rootID: UUID, waiterID: UUID, started: UInt64, absoluteDeadline: TimeInterval) {}
        func finishDNSQueryWaiter(rootID: UUID, waiterID: UUID, outcome: DNSQueryOutcome,
                                  failureReason: DNSQueryFailureReason?, milliseconds: Double) {}
        func recordDNSUpstreamStart(rootID: UUID, generationID: UUID, queuedAt: UInt64, started: UInt64) {}
    }

    private final class Permission {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }

    private final class Peer: DNSQueryCancellationAcknowledging {
        private let lock = NSLock()
        private let receive: (Data) -> Void
        private var wire = Data()
        private var cancellations = 0
        init(receive: @escaping (Data) -> Void) { self.receive = receive }
        func send(_ data: Data) { lock.lock(); wire = data; lock.unlock() }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); cancellations += 1; lock.unlock(); completion()
        }
        var cancelCount: Int { lock.lock(); defer { lock.unlock() }; return cancellations }
        func reply() {
            lock.lock(); var answer = wire; lock.unlock()
            guard answer.count >= 12 else { return }
            answer[2] = 0x81; answer[3] = 0x80; answer[6] = 0; answer[7] = 1
            answer.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1])
            receive(answer)
        }
    }

    private final class Peers {
        private let lock = NSLock()
        private var values: [Peer] = []
        func make(receive: @escaping (Data) -> Void) -> Peer {
            let value = Peer(receive: receive)
            lock.lock(); values.append(value); lock.unlock(); return value
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return values.count }
        subscript(_ index: Int) -> Peer { lock.lock(); defer { lock.unlock() }; return values[index] }
    }

    private final class Results {
        private let lock = NSLock()
        private var values: [String: Data] = [:]
        private var nils = Set<String>()
        private var callbacks = 0
        func record(_ name: String, _ answer: Data?) {
            lock.lock(); defer { lock.unlock() }
            callbacks += 1
            if let answer { values[name] = answer } else { nils.insert(name) }
        }
        func answer(_ name: String) -> Data? { lock.lock(); defer { lock.unlock() }; return values[name] }
        func denied(_ name: String) -> Bool { lock.lock(); defer { lock.unlock() }; return nils.contains(name) }
        var count: Int { lock.lock(); defer { lock.unlock() }; return callbacks }
    }

    private final class FencePeer: DNSQueryDeadlineAcknowledging, DNSQueryCancellationAcknowledging {
        let fencing = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var receipt: ((DNSProxyFallbackBarrier?) -> Void)?
        func send(_ data: Data) {}
        func cancel() {}
        func cancel(completion: @escaping () -> Void) { completion() }
        func queryDeadlineReached() { queryDeadlineReached { _ in } }
        func queryDeadlineReached(completion: @escaping (DNSProxyFallbackBarrier?) -> Void) {
            lock.lock(); receipt = completion; lock.unlock(); fencing.signal()
        }
        func acknowledge(_ barrier: DNSProxyFallbackBarrier) {
            lock.lock(); let callback = receipt; receipt = nil; lock.unlock()
            callback?(barrier); callback?(barrier)
        }
    }

    private static func deadlineCapabilityBoundary() throws {
        for authentication in [true, false] {
            let observer = Observer(), peer = FencePeer(), results = Results(), replacements = Peers()
            let denial = NSError(domain: "DNSModuleMemoryAuthentication", code: 77)
            let coordinator = DNSQueryCoordinator(observer: observer, classifyFailure: { error in
                DNSQueryFailureClassification(reason: (error as NSError) === denial ? .authentication : .upstreamOrResponse,
                    isTimeout: error is DNSQueryTimeoutError, permitsProxyFallback: false)
            }, makeInvalidResponseError: { Failure(text: "invalid memory response") })
            let callbacks = DispatchQueue(label: "dns.module.boundary.fence")
            let first = DNSMessageInspection.query(for: "fence.module.fixture.test", type: 1, id: 0x7101)!
            let second = DNSMessageInspection.query(for: "fence.module.fixture.test", type: 1, id: 0x7102)!
            let now = ProcessInfo.processInfo.systemUptime
            coordinator.resolve(scope: "held-fence", query: first, callbackQueue: callbacks,
                absoluteDeadline: now + 0.25, permitted: { true }, factory: { _, _, _ in peer }) {
                results.record("expired", $0)
            }
            coordinator.resolve(scope: "held-fence", query: second, callbackQueue: callbacks,
                absoluteDeadline: now + 3, permitted: { true }, factory: { _, receive, _ in
                    replacements.make(receive: receive)
                }) { results.record("follower", $0) }
            try require(coordinator.statistics.waitingClients == 2, "Missing original deadline followers")
            try require(peer.fencing.wait(timeout: .now() + 2) == .success,
                        "Imported deadline capability was not dynamically discovered")
            let held = coordinator.statistics
            try require(held.pendingQueries == 1 && held.activeUpstreams == 1 && held.waitingClients == 1
                        && replacements.count == 0, "A follower crossed the imported deadline ACK fence")
            if authentication { peer.acknowledge(.failure(denial)) }
            else { peer.acknowledge(.answer(DNSMessageInspection.errorResponse(to: first, code: .refused)!)) }
            try require(coordinator.statistics.pendingQueries == 0 && replacements.count == 0,
                        "A terminal imported barrier created a replacement transport")
            callbacks.sync {}
            try require(results.count == 2 && results.denied("expired"), "Deadline or terminal receipt delivered twice")
            if authentication {
                try require(results.denied("follower") && observer.observed(.authentication),
                            "The imported ACK lost the original authentication error")
            } else {
                try require(results.answer("follower").map {
                    DNSMessageInspection.responseMatchesQuery($0, query: second) && $0[3] & 15 == 5
                } == true, "The imported ACK lost REFUSED or another caller's response ID")
            }
        }
    }

    private static func coordinatorBoundary() throws {
        let coordinator = DNSQueryCoordinator(observer: Observer(), classifyFailure: { _ in
            DNSQueryFailureClassification(reason: .upstreamOrResponse, isTimeout: false, permitsProxyFallback: false)
        }, makeInvalidResponseError: { Failure(text: "invalid memory response") })
        let peers = Peers(), results = Results()
        let callbacks = DispatchQueue(label: "dns.module.boundary.callback")
        let factory: DNSQueryCoordinator.Factory = { _, receive, _ in peers.make(receive: receive) }
        let first = DNSMessageInspection.query(for: "module.fixture.test", type: 1, id: 0x7001)!
        let second = DNSMessageInspection.query(for: "module.fixture.test", type: 1, id: 0x7002)!
        let leader = coordinator.resolve(scope: "memory-scope", query: first, callbackQueue: callbacks,
            permitted: { true }, factory: factory) { results.record("leader", $0) }
        let originalDeadline = coordinator.deadlineForSelfTest(scope: "memory-scope", query: first)
        coordinator.resolve(scope: "memory-scope", query: second, callbackQueue: callbacks,
            permitted: { true }, factory: factory) { results.record("follower", $0) }
        let joined = coordinator.statistics
        try require(peers.count == 1 && joined.upstreamQueries == 1 && joined.mergedQueries == 1
                    && joined.waitingClients == 2, "Imported coordinator did not merge the approved memory scope")
        try require(coordinator.deadlineForSelfTest(scope: "memory-scope", query: first) == originalDeadline,
                    "A merged caller replaced the leader's original deadline")
        coordinator.cancel(leader)
        try require(coordinator.statistics.waitingClients == 1 && peers[0].cancelCount == 0,
                    "Canceling the leader revoked its follower's transport")
        peers[0].reply(); _ = coordinator.statistics; callbacks.sync {}
        try require(results.count == 1 && results.answer("leader") == nil
                    && results.answer("follower").map { DNSMessageInspection.responseMatchesQuery($0, query: second) } == true,
                    "Imported coordinator changed cancellation or each caller's response identity")
        coordinator.resolve(scope: "memory-scope", query: first, callbackQueue: callbacks,
            permitted: { true }, factory: factory) { results.record("cached", $0) }
        try require(coordinator.statistics.cacheHits == 1, "Imported coordinator failed to reuse its answer cache")
        callbacks.sync {}
        try require(peers.count == 1 && results.answer("cached").map {
            DNSMessageInspection.responseMatchesQuery($0, query: first)
        } == true, "A cache hit opened another transport or retained another caller's DNS ID")

        coordinator.resolve(scope: "denied-scope", query: first, callbackQueue: callbacks,
            permitted: { false }, factory: factory) { results.record("denied", $0) }
        _ = coordinator.statistics; callbacks.sync {}
        try require(results.denied("denied") && peers.count == 1,
                    "The imported module admitted transport I/O without permission")

        let permission = Permission(), held = DispatchQueue(label: "dns.module.boundary.held")
        held.suspend()
        coordinator.resolve(scope: "revoked-scope", query: first, callbackQueue: held,
            permitted: permission.permits, factory: factory) { results.record("revoked", $0) }
        _ = coordinator.statistics
        guard peers.count == 2 else { held.resume(); throw Failure(text: "Missing memory transport") }
        peers[1].reply(); _ = coordinator.statistics
        permission.revoke(); held.resume(); held.sync {}
        try require(results.denied("revoked"), "A queued completion bypassed permission revocation")

        let canceled = coordinator.resolve(scope: "canceled-scope", query: first, callbackQueue: callbacks,
            permitted: { true }, factory: factory) { results.record("canceled", $0) }
        _ = coordinator.statistics; let count = results.count
        coordinator.cancel(canceled)
        try require(coordinator.statistics.pendingQueries == 0 && peers[2].cancelCount == 1,
                    "Imported cancellation retained a logical registration or lost its child cleanup")
        peers[2].reply(); _ = coordinator.statistics; callbacks.sync {}
        try require(results.count == count, "A canceled imported-module request delivered a late answer")
    }

    static func main() throws {
        try DNSQueryCacheSelfTest.run()
        try DNSAdaptiveUpstreamSelectorSelfTest.run()
        try coordinatorBoundary()
        try deadlineCapabilityBoundary()
        print("DNS module boundary passed: real import, existing wire/cache/selector vectors, coordinator merge/cache/cancel/deadline/permission, held ACK authentication/REFUSED barriers")
    }
}

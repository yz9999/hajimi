// Appended to verbatim production declarations and the unmodified memory
// support from DNSColdProviderAdmissionMain.swift (only @main is removed).
// Queries go through the real adaptive send, timeout, health and cancel paths.
private extension DNSAdaptiveQueryDatagram {
    var isolationObservedScope: String { queue.sync { scopeKey } }
}

@main private enum DNSQueryHealthIsolationMain {
    typealias Support = DNSColdProviderAdmissionMain
    typealias Clock = Support.Clock
    typealias Slots = Support.Slots
    typealias Capacity = Support.Capacity
    typealias Peer = Support.MemoryPeer

    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    static var assertions = 0, groups = 0
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        assertions += 1
        if !condition() { throw Failure(text: message) }
    }
    static func check(_ name: String, _ body: () throws -> Void) throws {
        try body(); groups += 1; print("PASS", name)
    }
    static func emit(_ value: [String: Any]) {
        print(String(data: try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), encoding: .utf8)!)
    }
    static func slots() -> Slots {
        Slots([Capacity(), Capacity(), Capacity(), Capacity(1, 0)])
    }

    final class Query {
        let clock: Clock, selector: DNSAdaptiveUpstreamSelector, slots: Slots
        let permission = Support.Permission(), base: String, wire: Data, absoluteDeadline: TimeInterval
        let candidates: [DNSUpstreamCandidate]
        private let lock = NSLock()
        private var peers: [Int: Peer] = [:], factories: [Int] = [], sends: [Int] = []
        private var live = Set<Int>(), maximumLive = 0
        private var answers: [Data] = [], errors: [Error] = []
        var flow: DNSAdaptiveQueryDatagram!

        init(type: UInt16 = 1, name: String = "forward.isolation.fixture.invalid", dnsClass: UInt16 = 1,
             base: String, clock: Clock, selector: DNSAdaptiveUpstreamSelector, slots: Slots,
             holdCancellation: Bool = false, autoSend: Bool = true,
             absoluteDeadline: TimeInterval? = nil, raw: Data? = nil,
             candidates: [DNSUpstreamCandidate] = Support.approved,
             beforeFactoryReturn: ((Support.Permission, Clock) -> Void)? = nil) {
            self.base = base; self.clock = clock; self.selector = selector; self.slots = slots
            self.absoluteDeadline = absoluteDeadline ?? (clock.now() + 8)
            self.candidates = candidates
            var wire = raw ?? DNSMessageInspection.query(for: name, type: type, id: 0x4027)!
            if raw == nil {
                wire[wire.count - 2] = UInt8(dnsClass >> 8)
                wire[wire.count - 1] = UInt8(dnsClass & 0xff)
            }
            self.wire = wire
            flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector, scopeKey: base,
                queue: DispatchQueue(label: "dns.query-health-isolation.memory"),
                permitted: permission.permits,
                factory: { [weak self] candidate, _, receive, failure in
                    guard let self, let index = self.candidates.firstIndex(where: { $0.id == candidate.id }) else {
                        throw Failure(text: "Unapproved candidate reached the real factory")
                    }
                    let peer = Peer(clock: self.clock, candidate: candidate, slots: self.slots,
                        hold: holdCancellation, onSend: { [weak self] in
                            guard let self else { return }
                            self.lock.lock(); self.sends.append(index); self.live.insert(index)
                            self.maximumLive = max(self.maximumLive, self.live.count); self.lock.unlock()
                        }, onCancel: { [weak self] in
                            guard let self else { return }
                            self.lock.lock(); self.live.remove(index); self.lock.unlock()
                        }, receive: receive, failure: failure)
                    self.lock.lock(); self.factories.append(index); self.peers[index] = peer; self.lock.unlock()
                    beforeFactoryReturn?(self.permission, self.clock)
                    return peer
                }, receive: { [weak self] answer in
                    guard let self else { return }
                    self.lock.lock(); self.answers.append(answer); self.lock.unlock()
                }, failure: { [weak self] error in
                    guard let self else { return }
                    self.lock.lock(); self.errors.append(error); self.lock.unlock()
                }, availability: slots.availability, timeout: 8, absoluteDeadline: self.absoluteDeadline,
                clock: clock.now)
            if autoSend { send() }
        }

        deinit {
            flow?.cancel(); drain()
            for index in snapshot.factories { peer(index)?.acknowledge() }
            drain()
        }
        func send() { flow.send(wire); drain() }
        func drain() { flow.coldAuditDrain(); flow.coldAuditDrain() }
        func peer(_ index: Int) -> Peer? { lock.lock(); defer { lock.unlock() }; return peers[index] }
        func answer(_ index: Int, rcode: UInt8 = 0) throws {
            guard let peer = peer(index), var answer = DNSMessageInspection.errorResponse(to: wire, code: .servfail) else {
                throw Failure(text: "Answer requires a real admitted peer and complete question")
            }
            answer[3] = (answer[3] & 0xf0) | rcode
            peer.receive(answer); drain()
        }
        func answerFirst() throws {
            guard let index = snapshot.sends.first else { throw Failure(text: "No candidate was sent") }
            try answer(index)
        }
        func querySent() { for index in snapshot.sends { peer(index)?.querySent() } }
        func expire() { flow.coldAuditDeadline(); drain() }
        func acknowledge() {
            for index in snapshot.factories { peer(index)?.acknowledge(duplicate: true) }
            drain()
        }
        var scope: String { flow.isolationObservedScope }
        var snapshot: (factories: [Int], sends: [Int], live: Int, maximumLive: Int, answers: [Data], errors: [Error]) {
            lock.lock(); defer { lock.unlock() }
            return (factories, sends, live.count, maximumLive, answers, errors)
        }
        func integrity() throws {
            let state = flow.coldAuditState, value = snapshot
            try require(value.factories.count <= 3 && state.attempts <= 3, "Three-attempt bound changed")
            try require(value.maximumLive <= 2 && state.active <= 2, "Two-live bound changed")
            try require(Set(value.factories).count == value.factories.count, "Repeated candidate admission")
            try require(state.attempts == value.factories.count, "Attempt bookkeeping lost a factory")
            try require(value.factories.allSatisfy(candidates.indices.contains), "Unapproved candidate selected")
            try require(state.deadline == absoluteDeadline, "Original absolute deadline was extended")
            try require(value.sends.allSatisfy { peer($0)?.inheritedDeadline == absoluteDeadline },
                        "Child inherited a different original deadline")
            try require(value.answers.count + value.errors.count <= 1, "Duplicate completion")
        }
    }

    static func seedForward(base: String, clock: Clock, selector: DNSAdaptiveUpstreamSelector, slots: Slots) throws {
        let query = Query(base: base, clock: clock, selector: selector, slots: slots)
        try require(query.snapshot.sends == [3], "Healthy provider warmup did not use the only reusable approved pool")
        query.querySent(); try query.answer(3); try query.integrity()
        try require(selector.schedulingPriority(scopeKey: base, candidateID: Support.dnspod.id) == 0,
                    "A real forward answer did not establish healthy provider history")
    }

    static func mixedTimeoutReplay(fixed: Bool) throws {
        try check("four PTR original-deadline failures do not remove the working forward provider") {
            let clock = Clock(), pools = slots(), base = "mixed-real-send-timeout-path"
            let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600)
            try seedForward(base: base, clock: clock, selector: selector, slots: pools)
            let reverse = (0..<4).map {
                Query(type: 12, name: "ptr-\($0).reverse.fixture.invalid", base: base,
                      clock: clock, selector: selector, slots: pools)
            }
            for query in reverse {
                try require(query.snapshot.sends == [3], "PTR replay did not send through the same concrete provider")
                query.querySent()
            }
            clock.advance(8)
            for query in reverse {
                query.expire()
                try require(query.snapshot.errors.count == 1 && query.snapshot.errors[0] is DNSQueryTimeoutError
                            && query.snapshot.answers.isEmpty,
                            "PTR no-response did not fail once at its original deadline")
                try query.integrity()
            }
            let forwardStarted = clock.now()
            let next = Query(base: base, clock: clock, selector: selector, slots: pools)
            let priorityAtAdmission = selector.schedulingPriority(scopeKey: base, candidateID: Support.dnspod.id)
            if next.snapshot.sends == [3] {
                clock.advance(8.05)
                next.querySent(); try next.answer(3)
            } else {
                clock.advance(8.75); next.flow.coldAuditHedge()
                clock.advance(13.4); next.flow.coldAuditRotate()
                clock.advance(16); next.expire()
            }
            emit(["case": "PTR-timeouts-then-forward-query", "expectedFixed": fixed,
                  "ptrTimeouts": reverse.reduce(0) { $0 + $1.snapshot.errors.count },
                  "forwardCandidates": next.snapshot.sends,
                  "forwardAnswers": next.snapshot.answers.count, "forwardFailures": next.snapshot.errors.count,
                  "healthScopes": selector.usage.scopes,
                  "ptrOriginalDeadlineUptime": reverse[0].absoluteDeadline,
                  "forwardStartedUptime": forwardStarted,
                  "forwardOriginalDeadlineUptime": next.absoluteDeadline,
                  "forwardCompletedUptime": clock.now(),
                  "forwardElapsedMilliseconds": Int(((clock.now() - forwardStarted) * 1000).rounded()),
                  "forwardProviderPriorityAtAdmission": priorityAtAdmission])
            try require(next.snapshot.answers.count == (fixed ? 1 : 0)
                        && next.snapshot.errors.count == (fixed ? 0 : 1)
                        && (next.snapshot.sends.first == 3) == fixed,
                        "Four PTR timeouts still exclude reusable DNSPod from the next forward query")
            if fixed {
                let reverseScope = reverse[0].scope
                try require(reverseScope != base && reverse.allSatisfy { $0.scope == reverseScope },
                            "PTR flows did not use one independent reverse health scope")
                let health = selector.coldAuditHealth(reverseScope, Support.dnspod.id)
                try require(health.failures == 4 && selector.schedulingPriority(
                    scopeKey: reverseScope, candidateID: Support.dnspod.id) == 2,
                    "PTR-specific failures or exponential cooldown were lost")
                let forward = selector.coldAuditHealth(base, Support.dnspod.id)
                try require(forward.failures == 0 && forward.successes == 2 && selector.usage.scopes == 2,
                            "PTR failures leaked into ordinary query health or created extra domains")
                for type: UInt16 in [1, 28, 65] {
                    let shared = Query(type: type, name: "type-\(type).forward.fixture.invalid", base: base,
                        clock: clock, selector: selector, slots: pools)
                    try require(shared.scope == base && shared.snapshot.sends == [3],
                                "A/AAAA/HTTPS lost the shared verified forward preference")
                    try shared.answer(3); try shared.integrity()
                }
            }
            try next.integrity()
        }
    }

    static func finiteScopeDomains() throws {
        try check("query names, reverse categories and QCLASS create only two health domains") {
            let clock = Clock(), pools = slots(), base = "finite-type-domain"
            let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, maximumScopes: 8)
            var forwardScopes = Set<String>(), reverseScopes = Set<String>()
            let reverseNames = ["8.8.8.8.in-addr.arpa", "1.0.0.127.in-addr.arpa",
                                "1.0.19.198.in-addr.arpa", "0.0.0.10.in-addr.arpa", "nonstandard.reverse.name"]
            for index in 0..<128 {
                let isReverse = index.isMultiple(of: 2)
                let type: UInt16 = isReverse ? 12 : [1, 28, 65, 16, 255][index % 5]
                let name = isReverse ? reverseNames[index % reverseNames.count]
                    : "forward-\(index).finite.fixture.invalid"
                let query = Query(type: type, name: name, dnsClass: index.isMultiple(of: 3) ? 3 : 1,
                    base: base, clock: clock, selector: selector, slots: pools)
                if isReverse { reverseScopes.insert(query.scope) } else { forwardScopes.insert(query.scope) }
                try query.answerFirst(); try query.integrity()
                try require(selector.usage.scopes <= 2, "QNAME or PTR target category fragmented health storage")
            }
            try require(forwardScopes == [base] && reverseScopes.count == 1
                        && !reverseScopes.contains(base) && selector.usage.scopes == 2,
                        "Valid PTR/other type classification did not stay in two fixed domains")
            let reverseScope = reverseScopes.first!
            let repeated = Query(type: 12, name: "second-send.reverse.fixture.invalid", base: base,
                clock: clock, selector: selector, slots: pools)
            repeated.flow.send(DNSMessageInspection.query(for: "ignored.forward.fixture.invalid", type: 1, id: 0x4028)!)
            repeated.drain()
            try require(repeated.scope == reverseScope && repeated.snapshot.factories.count == 1,
                        "Repeated send nested/reclassified the scope or admitted another transport")
            try repeated.answerFirst(); try repeated.integrity()
        }
    }

    static func concurrentAndLateCancellation() throws {
        try check("concurrent PTR deadline receipts cannot poison in-flight or new forward queries") {
            let clock = Clock(), pools = slots(), base = "concurrent-ptr-forward"
            let selector = DNSAdaptiveUpstreamSelector(clock: clock.now, probeInterval: 3600)
            try seedForward(base: base, clock: clock, selector: selector, slots: pools)
            let reverse = (0..<16).map {
                Query(type: 12, name: "concurrent-\($0).reverse.fixture.invalid", base: base,
                    clock: clock, selector: selector, slots: pools, holdCancellation: true, autoSend: false)
            }
            DispatchQueue.concurrentPerform(iterations: reverse.count) { reverse[$0].send(); reverse[$0].querySent() }
            clock.advance(7.5)
            let forward = (0..<16).map {
                Query(type: [UInt16(1), 28, 65][$0 % 3], name: "concurrent-\($0).forward.fixture.invalid", base: base,
                    clock: clock, selector: selector, slots: pools, autoSend: false)
            }
            DispatchQueue.concurrentPerform(iterations: forward.count) { forward[$0].send(); forward[$0].querySent() }
            clock.advance(8)
            DispatchQueue.concurrentPerform(iterations: reverse.count) { reverse[$0].expire() }
            try require(reverse.allSatisfy { $0.snapshot.errors.count == 1 && $0.snapshot.answers.isEmpty },
                        "Held reverse ACKs delayed the callers' original timeout")
            let reverseScope = reverse[0].scope
            try require(selector.coldAuditHealth(reverseScope, Support.dnspod.id).failures == 0,
                        "Reverse failure was recorded before logical cancellation acknowledgement")
            for query in forward {
                try require(query.snapshot.sends == [3], "Concurrent PTR work displaced verified forward provider")
                try query.answer(3); try query.integrity()
            }
            DispatchQueue.concurrentPerform(iterations: reverse.count) { reverse[$0].acknowledge() }
            for query in reverse {
                try query.answer(3); query.peer(3)?.failure(EncryptedDNSQueryFailure.authentication); query.drain()
                try require(query.snapshot.answers.isEmpty && query.snapshot.errors.count == 1,
                            "Late canceled reverse answer/error reopened a finished query")
                try query.integrity()
            }
            try require(selector.coldAuditHealth(reverseScope, Support.dnspod.id).failures == 10
                        && selector.coldAuditHealth(base, Support.dnspod.id).failures == 0,
                        "Concurrent reverse receipts were lost, double-counted or leaked into forward health")
            let next = Query(base: base, clock: clock, selector: selector, slots: pools)
            try require(next.snapshot.sends == [3], "New forward caller inherited concurrent PTR cooldown")
            try next.answer(3); try next.integrity()
            emit(["case": "concurrent-two-health-domains", "ptrTimeouts": reverse.count,
                  "forwardAnswers": forward.count + 1, "healthScopes": selector.usage.scopes])
        }
    }

    static func cancellationAndDeadline() throws {
        try check("client cancellation fences late callbacks and does not create resolver failure") {
            let clock = Clock(), pools = slots(), base = "client-cancel-isolation"
            let selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let query = Query(type: 12, base: base, clock: clock, selector: selector, slots: pools,
                              holdCancellation: true)
            let completion = DispatchSemaphore(value: 0)
            query.flow.cancel { completion.signal() }; query.drain()
            try require(completion.wait(timeout: .now()) == .timedOut, "Client cancel acknowledged before child receipt")
            clock.advance(8); query.expire(); try query.answer(3)
            query.peer(3)?.failure(EncryptedDNSQueryFailure.network); query.drain()
            try require(query.snapshot.answers.isEmpty && query.snapshot.errors.isEmpty,
                        "Canceled PTR delivered timeout, late answer or error")
            query.acknowledge()
            try require(completion.wait(timeout: .now() + 2) == .success
                        && completion.wait(timeout: .now()) == .timedOut,
                        "Client cancellation did not acknowledge exactly once")
            try require(selector.coldAuditHealth(query.scope, Support.dnspod.id).failures == 0
                        && selector.usage.scopes == 1,
                        "Client cancellation penalized DNS health or created a forward domain")
            try query.integrity()
        }
        try check("expired or revoked work cannot use a new query-health domain to gain authorization") {
            let clock = Clock(), pools = slots(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let denied = Query(type: 12, base: "denied", clock: clock, selector: selector, slots: pools, autoSend: false)
            denied.permission.revoke(); denied.send()
            try require(denied.snapshot.factories.isEmpty && denied.snapshot.sends.isEmpty
                        && denied.snapshot.errors.count == 1 && denied.snapshot.answers.isEmpty
                        && selector.usage.scopes == 0,
                        "Initially revoked policy reached a provider or created health state")
            let expired = Query(type: 12, base: "expired", clock: clock, selector: selector, slots: pools,
                                absoluteDeadline: clock.now())
            try require(expired.snapshot.factories.isEmpty && expired.snapshot.errors.count == 1
                        && expired.snapshot.errors[0] is DNSQueryTimeoutError && selector.usage.scopes == 0,
                        "Expired query created a transport, scope or new deadline")
            let changed = Query(type: 12, base: "factory-policy-change", clock: clock,
                selector: selector, slots: pools, beforeFactoryReturn: { permission, _ in permission.revoke() })
            try require(changed.snapshot.factories.count == 1 && changed.snapshot.sends.isEmpty,
                        "Factory policy revocation was bypassed after PTR classification")
            let plain = DNSUpstreamCandidate(upstream: .plain(host: "192.0.2.53", port: 53), bootstrap: nil)
            let plaintext = Query(type: 12, base: "plaintext-denial", clock: clock, selector: selector, slots: pools,
                                  candidates: [Support.google1, plain, Support.dnspod])
            try require(plaintext.snapshot.factories.isEmpty && plaintext.snapshot.errors.count == 1
                        && plaintext.snapshot.answers.isEmpty,
                        "Query-health classification authorized plaintext DNS")
        }
    }

    static func malformedAndScopeBoundaries() throws {
        try check("incomplete questions do not fabricate a reverse domain and path scopes remain separate") {
            let clock = Clock(), pools = slots(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let valid = DNSMessageInspection.query(for: "malformed.reverse.fixture.invalid", type: 12, id: 0x4030)!
            var multiple = valid; multiple[5] = 2
            var nonstandard = valid; nonstandard[2] = 0x09
            for (index, wire) in [Data(), Data(valid.prefix(11)), Data(valid.dropLast()), multiple, nonstandard].enumerated() {
                let base = "malformed-\(index)"
                let query = Query(base: base, clock: clock, selector: selector, slots: pools, raw: wire)
                try require(query.scope == base, "Incomplete/nonstandard question fabricated PTR health identity")
                query.flow.cancel(); query.drain()
            }
            let original = Query(type: 12, base: "epoch-interface-route-A", clock: clock, selector: selector, slots: pools)
            try original.answerFirst()
            let other = Query(type: 12, base: "epoch-interface-route-B", clock: clock, selector: selector, slots: pools)
            try require(other.scope != original.scope && other.scope != "epoch-interface-route-A",
                        "Reverse classification collapsed distinct inherited policy/path scopes")
            try other.answerFirst(); try original.integrity(); try other.integrity()
        }
    }

    static func main() {
        do {
            let fixed = CommandLine.arguments.dropFirst().first != "before"
            try mixedTimeoutReplay(fixed: fixed)
            if fixed {
                try finiteScopeDomains()
                try concurrentAndLateCancellation()
                try cancellationAndDeadline()
                try malformedAndScopeBoundaries()
            }
            print("DNS query health isolation passed: \(groups) groups, \(assertions) assertions; expected=\(fixed ? "after" : "before"); memory only")
        } catch {
            fputs("FAIL DNS query health isolation: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}

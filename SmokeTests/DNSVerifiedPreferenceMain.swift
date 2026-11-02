// Production selector + coordinator + adaptive resolver, memory transports only.
private extension DNSAdaptiveQueryDatagram {
    var verifiedAuditState: (attempts: Int, active: Int, deadline: TimeInterval, parentDeadline: TimeInterval?) {
        queue.sync { (attemptCount, active.count, deadline, executionContext.absoluteDeadline) }
    }
    func verifiedAuditDrain() { queue.sync {} }
}

@main private enum DNSVerifiedPreferenceMain {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    final class Clock {
        var value: TimeInterval = 100
        func now() -> TimeInterval { value }
    }
    static var checks = 0
    static func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
        guard condition() else { throw Failure(text: text) }
    }
    static func check(_ name: String, _ body: () throws -> Void) throws {
        try body(); checks += 1; print("PASS", name)
    }
    static func emit(_ values: [String: Any]) {
        precondition(JSONSerialization.isValidJSONObject(values))
        print(String(data: try! JSONSerialization.data(withJSONObject: values, options: [.sortedKeys]), encoding: .utf8)!)
    }
    static func record(_ selector: DNSAdaptiveUpstreamSelector, _ id: String, _ milliseconds: Double,
                       success: Bool = true, evidence: DNSQueryTransportEvidence = .fresh,
                       scope: String = "health") {
        selector.record(selector.beginObservation(scopeKey: scope, candidateID: id),
            milliseconds: milliseconds, success: success, transport: evidence)
    }
    static func policyCases(fixed: Bool) throws {
        try check("unmeasured backup cannot acquire ordinary primary preference") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let ids = ["known", "backupA", "backupB"]
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            record(selector, ids[0], 3900)
            var primaries: [String: Int] = [:]
            for _ in 0..<64 {
                let first = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)[0]
                primaries[first, default: 0] += 1
                _ = selector.beginObservation(scopeKey: "health", candidateID: first)
            }
            try require(primaries == [fixed ? "known" : "backupA": 64], "Unexpected before/after primary distribution")
            try require(selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "backupA") == nil,
                "Merely choosing an unknown candidate fabricated RTT")
            emit(["case": "ordinary-primary-counterexample", "fixed": fixed, "primaries": primaries,
                  "elapsedProbeClockSeconds": 0, "knownColdMilliseconds": 3900])
        }
        guard fixed else { return }
        try check("new scopes preserve configured cold order and every approved candidate") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            for ids in [["a", "b", "c"], ["c", "a", "b"], ["b", "c", "a"]] {
                try require(selector.orderedCandidates(scopeKey: "cold", candidateIDs: ids) == ids,
                    "All-unknown scope changed configured order")
                for id in ids { _ = selector.beginObservation(scopeKey: "cold", candidateID: id) }
            }
            let ids = (0..<32).map { "approved-\($0)" }
            try require(selector.orderedCandidates(scopeKey: "all-approved", candidateIDs: ids) == ids,
                "Selection removed a fallback candidate")
        }
        try check("cold costs and reused RTT remain candidate-local") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let ids = ["known", "unknown", "otherKnown"]
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            record(selector, "known", 3900); record(selector, "known", 80, evidence: .reused)
            record(selector, "otherKnown", 2600)
            let order = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            try require(order == ["otherKnown", "known", "unknown"], "Known candidates no longer use their own scores")
            try require(selector.estimatedMilliseconds(scopeKey: "health", candidateID: "known", phase: .cold) == 3900
                && selector.estimatedMilliseconds(scopeKey: "health", candidateID: "unknown", phase: .cold) == nil,
                "Reused RTT erased cold setup or leaked it to another IP")
        }
        try check("hysteresis cannot reinsert an unverified preferred candidate") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let ids = ["unknown", "known", "other"]
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            selector.recordPendingLatencyLowerBound(scopeKey: "health", candidateID: "unknown", milliseconds: 1000)
            record(selector, "known", 3900)
            try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "known",
                "Old pending preference bypassed verified priority")
        }
        try check("exploration requires both 16 questions and 30 seconds and lasts one primary") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let ids = ["known", "backupA", "backupB"]
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            record(selector, "known", 3900)
            for query in 2...65 {
                clock.value = query < 17 ? 129.999 : query < 34 ? 130 : query < 49 ? 159.999 : 160
                let first = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)[0]
                let expected = query == 32 ? "backupA" : query == 64 ? "backupB" : "known"
                try require(first == expected, "Probe escaped query/time gates at query \(query): \(first)")
            }
        }
        try check("a failed historical winner yields until real success recovers it") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let ids = ["quickButFailed", "healthySlow", "unknown"]
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            record(selector, ids[0], 20); record(selector, ids[1], 3900)
            record(selector, ids[0], 20, success: false)
            clock.value += 2
            try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == ids[1],
                "An expired cooldown restored failed historical evidence as healthy")
            record(selector, ids[1], 20, success: false)
            try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).contains("unknown"),
                "All unhealthy candidates removed unknown recovery")
            record(selector, ids[0], 20)
            try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == ids[0],
                "Real recovery success did not restore priority")
        }
        try check("unknown recovery is available when all successes are cooling") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let ids = ["knownA", "knownB", "unknown"]
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            for id in ids.prefix(2) { record(selector, id, 3900); record(selector, id, 10, success: false) }
            try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "unknown",
                "Verified priority blocked unknown recovery during cooldown")
        }
        try check("expired success cannot outrank a current success through the verified tier") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let ids = ["expired", "current", "unknown"]
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            record(selector, "expired", 20)
            clock.value += 900.001; record(selector, "current", 3900)
            try require(selector.knownLatencyMilliseconds(scopeKey: "health", candidateID: "expired") == nil
                && selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "current",
                "Expired success kept validated priority")
        }
        try check("clock rollback clears priority without reviving stale receipts") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let ids = ["unknown", "known"]
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            let stale = selector.beginObservation(scopeKey: "health", candidateID: "known")
            record(selector, "known", 3900); clock.value = 1
            try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids) == ids && selector.usage.scopes == 0,
                "Clock rollback retained previous validation")
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ids)
            selector.record(stale, milliseconds: 1, success: true)
            try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids) == ids,
                "Pre-rollback receipt validated a replacement scope")
        }
        try check("approved set updates preserve same-candidate success without crossing scopes") {
            let clock = Clock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            _ = selector.orderedCandidates(scopeKey: "health", candidateIDs: ["known", "old"])
            record(selector, "known", 3900)
            let ids = ["newBackup", "known", "old"]
            try require(selector.orderedCandidates(scopeKey: "health", candidateIDs: ids).first == "known"
                && selector.orderedCandidates(scopeKey: "other-policy", candidateIDs: ids) == ids,
                "Candidate set change lost success or shared it across policy scopes")
            selector.removeAll(); record(selector, "known", 1)
            try require(selector.usage.scopes == 0, "Late success recreated a flushed scope")
        }
    }

    final class MemoryScenario {
        let fixed: Bool
        let selector = DNSAdaptiveUpstreamSelector(), coordinator = DNSQueryCoordinator()
        let callback = DispatchQueue(label: "verified-preference-callback"), lock = NSLock()
        let completed = DispatchSemaphore(value: 0)
        let candidates = (0..<3).map { index in
            DNSUpstreamCandidate(upstream: .doh(DoHEndpoint(
                "https://candidate-\(index).fixture.invalid/dns-query#203.0.113.\(70 + index)")!), bootstrap: nil)
        }
        var ready = false, firstAnswer = false, secondAnswer = false
        var attempts: [[Int]] = [[], []], live = [0, 0], peak = [0, 0]
        var fresh = [0, 0], reused = [0, 0], answers = [0, 0], flows: [DNSAdaptiveQueryDatagram] = []
        init(fixed: Bool) { self.fixed = fixed }
        func query(wave: Int, budget: Double) throws -> TimeInterval {
            let query = DNSMessageInspection.query(for: "wave-\(wave).verified.fixture.invalid",
                type: 1, id: UInt16(wave + 1))!
            let deadline = ProcessInfo.processInfo.systemUptime + budget
            coordinator.resolve(scope: "approved-question-policy", query: query, callbackQueue: callback,
                absoluteDeadline: deadline, permitted: { true }, factory: { [self] queue, receive, failure in
                    let flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector,
                        scopeKey: "same-approved-health", queue: queue, permitted: { true },
                        factory: { [self] candidate, queue, receive, _ in
                            let index = candidates.firstIndex { $0.id == candidate.id }!
                            lock.lock(); let hot = index == 0 && ready
                            attempts[wave].append(index); live[wave] += 1; peak[wave] = max(peak[wave], live[wave])
                            if hot { reused[wave] += 1 } else { fresh[wave] += 1 }; lock.unlock()
                            return Peer(owner: self, wave: wave, index: index, hot: hot, queue: queue, receive: receive)
                        }, receive: receive, failure: failure, timeout: 8, absoluteDeadline: deadline)
                    lock.lock(); flows.append(flow); lock.unlock(); return flow
                }, completion: { [self] answer in
                    lock.lock()
                    answers[wave] += 1
                    let valid = answer.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } ?? false
                    if wave == 0 { firstAnswer = valid } else { secondAnswer = valid }
                    lock.unlock(); completed.signal()
                })
            try require(completed.wait(timeout: .now() + 10) == .success, "Memory wave did not complete")
            lock.lock(); let current = flows.last!; lock.unlock()
            current.verifiedAuditDrain(); callback.sync {}
            let state = current.verifiedAuditState
            var deadlineEvidence: [String: Any] = ["case": "consumer-original-and-inherited-deadline",
                "wave": wave, "callerAbsoluteDeadline": deadline,
                "effectiveAbsoluteDeadline": state.deadline,
                "effectiveMinusCallerMicroseconds": (state.deadline - deadline) * 1_000_000,
                "attempts": state.attempts, "active": state.active]
            if let inherited = state.parentDeadline {
                deadlineEvidence["inheritedContextAbsoluteDeadline"] = inherited
                deadlineEvidence["expectedEffectiveAbsoluteDeadline"] = min(deadline, inherited)
                deadlineEvidence["inheritedMinusCallerMicroseconds"] = (inherited - deadline) * 1_000_000
            }
            emit(deadlineEvidence)
            guard let inherited = state.parentDeadline else {
                throw Failure(text: "Coordinator did not propagate the original deadline through its execution context")
            }
            try require(state.deadline == min(deadline, inherited) && state.deadline <= deadline
                && state.attempts <= 3 && state.active == 0,
                "Selection lost the exact caller/context deadline cap or changed attempt bounds")
            return deadline
        }
        func run() throws {
            _ = try query(wave: 0, budget: 8)
            lock.lock(); let initialPassed = firstAnswer && ready; lock.unlock()
            try require(initialPassed, "Real cold valid-answer wave did not establish health")
            let deadline = try query(wave: 1, budget: 1.5)
            let state = coordinator.statistics
            lock.lock(); defer { lock.unlock() }
            try require(state.activeUpstreams == 0 && state.pendingQueries == 0 && live == [0, 0],
                "Memory consumer did not drain after completion")
            try require(peak.allSatisfy { $0 <= 2 } && attempts.allSatisfy { $0.count <= 3 } && answers == [1, 1],
                "Consumer changed live/attempt/callback limits")
            try require(secondAnswer == fixed, "Expected old deadline failure versus verified reused success")
            try require(attempts[1] == (fixed ? [0] : [2, 1]), "Unexpected consumer candidate order")
            try require(reused[1] == (fixed ? 1 : 0), "After case did not use the ready memory stream")
            emit(["case": "production-coordinator-adaptive-cold-then-ready", "fixed": fixed,
                "firstWaveAttempts": attempts[0], "secondWaveAttempts": attempts[1],
                "secondWaveSuccess": secondAnswer, "secondWaveFreshDials": fresh[1], "secondWaveReuse": reused[1],
                "remainingOriginalBudgetMilliseconds": 1500, "originalAbsoluteDeadline": deadline,
                "maximumPerRootLive": peak.max()!, "logicalAfterDrain": state.activeUpstreams,
                "answersPerWave": answers])
        }
    }
    final class Peer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSQueryExecutionContextAccepting, DNSQueryTransportEvidenceProviding {
        let owner: MemoryScenario, wave: Int, index: Int, hot: Bool, queue: DispatchQueue, receive: (Data) -> Void
        let lock = NSLock()
        var closed = false, context: DNSQueryExecutionContext?
        init(owner: MemoryScenario, wave: Int, index: Int, hot: Bool, queue: DispatchQueue, receive: @escaping (Data) -> Void) {
            self.owner = owner; self.wave = wave; self.index = index; self.hot = hot; self.queue = queue; self.receive = receive
        }
        func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) { lock.lock(); self.context = context; lock.unlock() }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { hot ? .reused : .fresh }
        func send(_ query: Data) {
            lock.lock(); let context = self.context; lock.unlock()
            context?.record(hot ? .connectionReused : .transportStarted)
            guard index == 0 else { return }
            queue.asyncAfter(deadline: .now() + (hot ? 0.08 : 2.6)) { [self] in
                lock.lock(); let stopped = closed, context = self.context; lock.unlock()
                guard !stopped else { return }
                if !hot { context?.record(.transportReady); context?.record(.tlsStarted); context?.record(.tlsReady) }
                context?.record(.querySendStarted); context?.record(.querySent)
                context?.record(.responseStarted); context?.record(.responseComplete)
                owner.lock.lock(); owner.ready = true; owner.lock.unlock()
                var answer = query; answer[2] = 0x81; answer[3] = 0x80
                receive(answer)
            }
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); let first = !closed; closed = true; lock.unlock()
            if first { owner.lock.lock(); owner.live[wave] -= 1; owner.lock.unlock() }
            completion()
        }
    }
    static func main() {
        do {
            let fixed = CommandLine.arguments.dropFirst().first != "before"
            try policyCases(fixed: fixed)
            try check("existing production selector self-tests") { try DNSAdaptiveUpstreamSelectorSelfTest.run() }
            try check("production consumers retain and reuse the successful candidate") { try MemoryScenario(fixed: fixed).run() }
            print("PASS", checks, "checks", fixed ? "after" : "before")
        } catch {
            fputs("FAIL \(error.localizedDescription)\n", stderr); exit(1)
        }
    }
}

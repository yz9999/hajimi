// This file is appended to DNSColdDialLimitMain.swift with only its @main
// attribute removed. Production resolver declarations remain verbatim.
private extension EncryptedDNSRequestPool {
    func holdAvailabilityQueue(entered: DispatchSemaphore, release: DispatchSemaphore) {
        queue.async { entered.signal(); _ = release.wait(timeout: .now() + 3) }
    }
}

private extension DNSColdDialLimitMain {
    private final class AvailabilityOwner {
        let probe = Probe(), book = Book()
        let budget = SOCKSUDPGlobalBudget(resources: 64, packets: 0, bytes: 0)
        let pool: EncryptedDNSRequestPool
        private var ids: [Int: UUID] = [:]
        init(_ kind: Kind) {
            let transport: EncryptedDNSProtocol = kind == .doh
                ? .https(DoHEndpoint("https://cold.memory.invalid/dns-query#203.0.113.53")!)
                : .tls(DoTEndpoint("tls://cold.memory.invalid#203.0.113.53")!)
            pool = EncryptedDNSRequestPool(protocol: transport, label: "fixture.cold-queue-availability",
                streamDialer: nil, cancellableStreamDialer: nil, metadataStreamDialer: probe.dialer,
                timeout: .seconds(5), idleTimeout: 15, idleLimit: 4, idleHandoffGrace: 8,
                activeLimit: 16, clock: { Date(timeIntervalSince1970: SOCKSUDPResourceLimits.now) },
                resourceBudget: budget)
        }
        func submit(_ index: Int) throws {
            let query = DNSMessageInspection.query(for: "availability-\(index).memory.invalid", type: 1,
                id: UInt16(0x6000 + index))!, book = self.book
            guard let id = pool.resolveResult(query: query, completion: { book.record(index, query: query, result: $0) },
                transportEvidence: { book.evidence(index, $0) }) else {
                throw Failure(text: "availability query was rejected at registration")
            }
            ids[index] = id
        }
        func cancel(_ index: Int) throws {
            guard let id = ids[index] else { throw Failure(text: "unknown availability query") }
            let ack = DispatchSemaphore(value: 0)
            pool.cancel(id) { ack.signal() }
            try require(ack.wait(timeout: .now() + 2) == .success, "availability cancel ACK lost")
        }
        func cancelWithoutWaiting(_ index: Int) throws {
            guard let id = ids[index] else { throw Failure(text: "unknown availability query") }
            pool.cancel(id)
        }
        func close() throws {
            pool.cancel(); pool.drainQueueForSelfTest()
            for index in probe.snapshot.pending { try probe.fail(index) }
            try probe.barrier()
            try until("availability fixture retained a stream or global idle resource") {
                self.budget.usage.resources == 0 && self.probe.snapshot.peers.allSatisfy(\.cancelled)
            }
            try require(probe.snapshot.callbacks.allSatisfy { $0 == 1 }, "availability physical callback was lost or duplicated")
        }
        deinit { pool.cancel() }
    }

    private static func registeredDemandIsImmediate(_ kind: Kind) throws {
        let owner = AvailabilityOwner(kind)
        defer { try? owner.close() }
        let initial = owner.pool.schedulingAvailability
        try require(initial.reusable == 0 && initial.cold == 4, "empty real pool did not advertise four cold reservations")
        try owner.submit(0)
        try until("availability preparation did not start") { owner.probe.snapshot.opens == 1 }
        let ready = try owner.probe.succeed(0, kind)
        try until("availability preparation did not send") { ready.sendCount == 1 }
        try ready.reply()
        try until("availability preparation did not return idle") { owner.book.success(0) }
        try owner.probe.barrier()
        let warm = owner.pool.schedulingAvailability
        try require(warm.reusable == 1 && warm.cold == 4, "warm pool did not advertise one reusable stream and four cold starts")
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        owner.pool.holdAvailabilityQueue(entered: entered, release: release)
        try require(entered.wait(timeout: .now() + 2) == .success, "availability queue barrier did not start")
        do {
            try owner.submit(1)
            let one = owner.pool.schedulingAvailability
            try require(one.reusable == 0 && one.cold == 4,
                        "registered request did not deduct reusable demand before queued start")
            for index in 2...6 { try owner.submit(index) }
            let six = owner.pool.schedulingAvailability
            try require(six.reusable == 0 && six.cold == 0,
                        "six registered starts advertised already-promised cold slots")
        } catch { release.signal(); throw error }
        release.signal(); try owner.probe.barrier()
        let pressure = owner.pool.pressureForSelfTest
        try require(ready.sendCount == 2 && owner.probe.snapshot.opens == 5 && owner.probe.snapshot.pending.count == 4
                    && pressure.active == 5 && pressure.waiting == 1,
                    "queued registration bypassed reusable-first/cold4 or lost the last waiter")
        try ready.reply()
        try until("returned idle did not serve a waiter while all four physical dials remained held") {
            ready.sendCount == 3 && owner.book.success(1)
        }
        try owner.probe.barrier()
        try require(owner.book.evidence(6) == [.reused] && owner.probe.snapshot.opens == 5
                    && owner.probe.snapshot.pending.count == 4 && owner.pool.pressureForSelfTest.waiting == 0,
                    "returned idle required an unrelated cold ACK or created another connection")
        try ready.reply()
        try until("last queued caller did not receive its matching reply") { owner.book.success(6) }
        try owner.close()
        try require(owner.book.exactlyOnce(0..<7), "availability cleanup lost or duplicated a caller")
    }

    private static func cancelledDialRemainsUnavailable(_ kind: Kind) throws {
        let owner = AvailabilityOwner(kind)
        defer { try? owner.close() }
        for index in 0..<4 { try owner.submit(index) }
        try until("availability cancellation did not saturate cold4") { owner.probe.snapshot.opens == 4 }
        try owner.probe.barrier(); try owner.cancel(0); try owner.probe.barrier()
        let cancelled = owner.pool.schedulingAvailability
        try require(cancelled.reusable == 0 && cancelled.cold == 0 && owner.probe.snapshot.pending.count == 4,
                    "logical cancel falsely advertised a free cold reservation")
        try owner.submit(4); try owner.probe.barrier()
        try require(owner.probe.snapshot.opens == 4 && owner.pool.pressureForSelfTest.waiting == 1,
                    "logical cancel allowed a fifth unfinished cold start")
        let late = try owner.probe.succeed(0, kind)
        try until("real late completion did not wake the queued request") { owner.probe.snapshot.opens == 5 }
        try owner.probe.barrier()
        try require(late.cancelled && late.sendCount == 0 && owner.probe.snapshot.pending.count == 4
                    && owner.pool.schedulingAvailability.cold == 0,
                    "real callback admitted stale sends or exceeded cold4")
        try owner.close()
        try require(owner.book.exactlyOnce(0..<5), "cancel availability cleanup lost or duplicated a caller")
    }

    private static func freshOnlyWaiterDoesNotClaimIdle(_ kind: Kind, expected: Int) throws {
        let owner = AvailabilityOwner(kind)
        defer { try? owner.close() }
        for index in 0..<6 { try owner.submit(index) }
        try until("fresh-only setup did not saturate cold4") { owner.probe.snapshot.opens == 4 }
        let first = try owner.probe.succeed(0, kind)
        try until("first live connection did not release its real reservation") {
            first.sendCount == 1 && owner.probe.snapshot.opens == 5
        }
        let second = try owner.probe.succeed(1, kind)
        try until("second live connection did not release its real reservation") {
            second.sendCount == 1 && owner.probe.snapshot.opens == 6
        }
        try first.reply()
        try until("fresh-only setup did not return its first idle stream") { owner.book.success(0) }
        try owner.probe.barrier()
        try second.reply()
        try until("fresh-only setup did not return its second idle stream") { owner.book.success(1) }
        try owner.probe.barrier()
        try require(owner.pool.schedulingAvailability.reusable == 2 && owner.probe.snapshot.pending.count == 4,
                    "fresh-only setup did not retain two ready idle streams beside cold4")
        // The first return is drained before the second reply, so checkout
        // must borrow the second (last returned) stream.
        second.rejectNextSend()
        try owner.submit(6)
        try until("dirty reuse did not become a fresh-only queued retry") {
            owner.book.evidence(6) == [.reused] && (first.cancelled || second.cancelled)
        }
        try owner.probe.barrier()
        let retryPressure = owner.pool.pressureForSelfTest
        let advertised = owner.pool.schedulingAvailability
        try require(retryPressure.waiting == 1 && owner.probe.snapshot.pending.count == 4,
                    "dirty retry did not remain queued under real cold pressure")
        try require(advertised.reusable == expected && advertised.cold == 0,
                    "fresh-only retry reusable hint expected=\(expected), actual=\(advertised.reusable)")
        try owner.submit(7)
        try until("fresh-only waiter blocked a later eligible idle borrower") { first.sendCount == 2 }
        try owner.probe.barrier()
        try require(owner.book.evidence(7) == [.reused] && owner.book.failure(6) == nil
                    && owner.probe.snapshot.opens == 6 && owner.probe.snapshot.pending.count == 4
                    && owner.pool.pressureForSelfTest.waiting == 1,
                    "later idle borrower changed the queued retry deadline or opened an excess cold dial")
        try first.reply()
        try until("later idle borrower did not receive its matching answer") { owner.book.success(7) }
        try owner.close()
        try require(owner.book.exactlyOnce(0..<8), "fresh-only availability cleanup lost or duplicated a caller")
    }

    private static func cancelledActiveDoesNotMaskNewDemand(_ kind: Kind) throws {
        let owner = AvailabilityOwner(kind)
        defer { try? owner.close() }
        for index in 0..<3 { try owner.submit(index) }
        try until("registration replacement did not start three physical dials") { owner.probe.snapshot.opens == 3 }
        let first = try owner.probe.succeed(0, kind), second = try owner.probe.succeed(1, kind)
        try until("registration replacement did not send its two warmup requests") {
            first.sendCount == 1 && second.sendCount == 1
        }
        try first.reply(); try second.reply()
        try until("registration replacement did not return its two idle streams") {
            owner.book.success(0) && owner.book.success(1)
        }
        try owner.probe.barrier()
        try require(owner.pool.schedulingAvailability.reusable == 2, "registration replacement lost initial ready availability")
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        owner.pool.holdAvailabilityQueue(entered: entered, release: release)
        try require(entered.wait(timeout: .now() + 2) == .success, "registration replacement queue barrier did not start")
        do {
            // cancel removes registration immediately; native ownership and
            // its published logical-active snapshot still await the queue.
            try owner.cancelWithoutWaiting(2); try owner.submit(3)
            let replaced = owner.pool.schedulingAvailability
            try require(replaced.reusable == 1 && replaced.cold == 3,
                        "cancelled published-active ID masked a new registration: actual=\(replaced)")
        } catch { release.signal(); throw error }
        release.signal(); try owner.probe.barrier()
        try require(owner.book.failure(2) == .cancelled && owner.book.evidence(3) == [.reused]
                    && owner.probe.snapshot.opens == 3 && owner.probe.snapshot.pending == [2],
                    "registration replacement released native cancellation early or missed ready reuse")
        try owner.close()
        try require(owner.book.exactlyOnce(0..<4), "registration replacement cleanup lost or duplicated a caller")
    }

    static func runAvailabilityChecks() {
        let arguments = CommandLine.arguments
        let position = arguments.firstIndex(of: "--expected-fresh-retry-reusable")
        let expected = position.flatMap { $0 + 1 < arguments.count ? Int(arguments[$0 + 1]) : nil } ?? 1
        for kind in Kind.allCases {
            check(kind.rawValue + "-registered-demand-and-idle-handoff") { try registeredDemandIsImmediate(kind) }
            check(kind.rawValue + "-cancelled-dial-advertised-unavailable-until-ack") { try cancelledDialRemainsUnavailable(kind) }
            check(kind.rawValue + "-fresh-only-waiter-does-not-claim-idle") { try freshOnlyWaiterDoesNotClaimIdle(kind, expected: expected) }
            check(kind.rawValue + "-cancelled-published-active-does-not-mask-new-demand") { try cancelledActiveDoesNotMaskNewDemand(kind) }
        }
        let report: [String: Any] = ["checks": checks, "passedGroups": passed, "failedGroups": failed]
        let bytes = try! JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        print(String(decoding: bytes, as: UTF8.self))
        if !failed.isEmpty { exit(1) }
    }
}

@main private enum DNSColdQueueAvailabilityMain {
    static func main() { DNSColdDialLimitMain.runAvailabilityChecks() }
}

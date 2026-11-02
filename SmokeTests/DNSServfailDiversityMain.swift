// Appended to exact production declarations; memory peers, no DNS or TLS I/O.
private extension DNSAdaptiveQueryDatagram {
    func serviceAuditPauseTimers() {
        deadlineTimer?.cancel()
        for attempt in active.values {
            attempt.hedgeTimer?.cancel(); attempt.rotationTimer?.cancel()
        }
    }
    func serviceAuditDrain() { queue.sync { serviceAuditPauseTimers() } }
    func serviceAuditHedge() {
        queue.sync {
            if let token = active.keys.first { startHedge(after: token) }
            serviceAuditPauseTimers()
        }
    }
    func serviceAuditDeadline() {
        queue.sync { overallDeadlineReached(); serviceAuditPauseTimers() }
    }
    var serviceAuditState: (attempts: Int, active: Int, deadline: TimeInterval) {
        queue.sync { (attemptCount, active.count, deadline) }
    }
}

private extension DNSAdaptiveUpstreamSelector {
    func serviceAuditQueryCount(_ scope: String) -> UInt64 {
        lock.lock(); defer { lock.unlock() }; return scopes[scope]?.queries ?? 0
    }
    func serviceAuditHealth(_ scope: String, _ candidate: String) -> (successes: Int, failures: Int) {
        lock.lock(); defer { lock.unlock() }
        let value = scopes[scope]?.health[candidate]
        return (value?.successes ?? 0, value?.failures ?? 0)
    }
}

@main private enum DNSServfailDiversityMain {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    static var checks = 0
    static func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
        if !condition() { throw Failure(text: text) }
    }
    static func check(_ name: String, _ body: () throws -> Void) throws {
        try body(); checks += 1; print("PASS", name)
    }
    static func emit(_ value: [String: Any]) {
        print(String(data: try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), encoding: .utf8)!)
    }
    static func candidate(_ raw: String) -> DNSUpstreamCandidate {
        DNSUpstreamCandidate(upstream: .doh(DoHEndpoint(raw)!), bootstrap: nil)
    }
    static let g1 = candidate("https://dns.google/dns-query#8.8.8.8")
    static let g2 = candidate("https://dns.google/dns-query#8.8.4.4")
    static let dnspod = candidate("https://doh.pub/dns-query#1.12.12.12")
    static let cloudflare = candidate("https://cloudflare-dns.com/dns-query#1.1.1.1")
    static var baseline: [DNSUpstreamCandidate] { [g1, g2, dnspod, cloudflare] }

    final class Clock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ elapsed: TimeInterval) { lock.lock(); value = 100 + elapsed; lock.unlock() }
    }
    final class Permission {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }
    final class MemoryPeer: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSQueryTransportEvidenceProviding {
        let receive: (Data) -> Void, failure: (Error) -> Void
        let onSend: () -> Void, onCancel: () -> Void
        private let lock = NSLock()
        private let holdAcknowledgement: Bool
        private var cancelled = false, acknowledgements: [() -> Void] = []
        init(hold: Bool, onSend: @escaping () -> Void, onCancel: @escaping () -> Void,
             receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            holdAcknowledgement = hold; self.onSend = onSend; self.onCancel = onCancel
            self.receive = receive; self.failure = failure
        }
        func send(_ data: Data) { onSend() }
        func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { .fresh }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); let first = !cancelled; cancelled = true
            if holdAcknowledgement { acknowledgements.append(completion) }
            lock.unlock()
            if first { onCancel() }
            if !holdAcknowledgement { completion() }
        }
        func acknowledgeTwice() {
            lock.lock(); let values = acknowledgements; acknowledgements.removeAll(); lock.unlock()
            for value in values { value(); value() }
        }
    }
    final class Scenario {
        let candidates: [DNSUpstreamCandidate]
        let clock = Clock(), permission = Permission(), selector = DNSAdaptiveUpstreamSelector()
        let lock = NSLock(), scope = "servfail-approved-health"
        let query = DNSMessageInspection.query(for: "servfail.fixture.invalid", type: 1, id: 0x2042)!
        var flow: DNSAdaptiveQueryDatagram!
        var peers: [Int: MemoryPeer] = [:], attempts: [Int] = []
        var live = 0, peak = 0, answers: [Data] = [], errors: [Error] = []
        init(_ candidates: [DNSUpstreamCandidate] = baseline, holdAcknowledgements: Bool = false,
             protectFallback: Bool = false, allowApprovedPlaintext: Bool = false) {
            self.candidates = candidates
            flow = DNSAdaptiveQueryDatagram(candidates: candidates, selector: selector, scopeKey: scope,
                queue: DispatchQueue(label: "servfail-memory-callback"), permitted: permission.permits,
                factory: { [weak self] candidate, _, receive, failure in
                    guard let self else { throw Failure(text: "Memory scenario already released") }
                    let index = self.candidates.firstIndex { $0.id == candidate.id }!
                    let peer = MemoryPeer(hold: holdAcknowledgements, onSend: { [weak self] in
                        guard let self else { return }
                        self.lock.lock(); self.attempts.append(index); self.live += 1
                        self.peak = max(self.peak, self.live); self.lock.unlock()
                    }, onCancel: { [weak self] in
                        guard let self else { return }
                        self.lock.lock(); self.live -= 1; self.lock.unlock()
                    }, receive: receive, failure: failure)
                    self.lock.lock(); self.peers[index] = peer; self.lock.unlock(); return peer
                }, receive: { [weak self] answer in
                    guard let self else { return }
                    self.lock.lock(); self.answers.append(answer); self.lock.unlock()
                }, failure: { [weak self] error in
                    guard let self else { return }
                    self.lock.lock(); self.errors.append(error); self.lock.unlock()
                }, timeout: 8, absoluteDeadline: 108, clock: clock.now, protectProxyFallback: protectFallback,
                allowApprovedProxyPlaintext: allowApprovedPlaintext)
            flow.send(query); flow.serviceAuditDrain()
        }
        deinit { flow.cancel() }
        func peer(_ index: Int) -> MemoryPeer? { lock.lock(); defer { lock.unlock() }; return peers[index] }
        func reply(_ index: Int, _ code: UInt8, matching: Bool = true) throws {
            guard let peer = peer(index) else { throw Failure(text: "Unstarted candidate \(index)") }
            var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail)!
            answer[3] = (answer[3] & 0xf0) | code
            if !matching { answer[0] ^= 1 }
            peer.receive(answer); flow.serviceAuditDrain()
        }
        func fail(_ index: Int, _ error: Error = EncryptedDNSQueryFailure.network) throws {
            guard let peer = peer(index) else { throw Failure(text: "Unstarted candidate \(index)") }
            peer.failure(error); flow.serviceAuditDrain()
        }
        var snapshot: (attempts: [Int], live: Int, peak: Int, answers: [Data], errors: [Error]) {
            lock.lock(); defer { lock.unlock() }; return (attempts, live, peak, answers, errors)
        }
        func integrity() throws {
            let s = snapshot, state = flow.serviceAuditState
            try require(s.attempts.count <= 3 && s.peak <= 2 && state.active <= 2,
                        "Three-attempt/two-live cap changed")
            try require(Set(s.attempts).count == s.attempts.count && state.attempts == s.attempts.count,
                        "An existing or attempted candidate was duplicated")
            try require(s.attempts.allSatisfy { candidates.indices.contains($0) } && state.deadline == 108,
                        "Unapproved candidate or extended deadline")
            try require(selector.serviceAuditQueryCount(scope) == 1, "Reordering queried selector twice")
        }
    }

    static func regression(fixed: Bool) throws {
        try check("SERVFAIL reaches approved provider outside original prefix(3)") {
            let s = Scenario()
            try s.reply(0, 2)
            try require(s.snapshot.attempts == (fixed ? [0, 2] : [0, 1]), "Wrong first SERVFAIL replacement")
            try s.reply(fixed ? 2 : 1, 2)
            try require(s.snapshot.attempts == (fixed ? [0, 2, 3] : [0, 1, 2]), "Wrong third approved slot")
            try s.reply(fixed ? 3 : 2, fixed ? 0 : 2)
            try require(s.snapshot.answers.count == (fixed ? 1 : 0) && s.snapshot.errors.count == (fixed ? 0 : 1),
                        "Before/after regression outcome not reproduced")
            try s.integrity()
            emit(["case": "G1-G2-DNSPod-CF", "fixed": fixed, "attempts": s.snapshot.attempts,
                  "answers": s.snapshot.answers.count, "errors": s.snapshot.errors.count,
                  "selectorCalls": s.selector.serviceAuditQueryCount(s.scope), "maximumLive": s.snapshot.peak,
                  "deadline": s.flow.serviceAuditState.deadline])
        }
        try check("ordinary network errors preserve original ranked prefix") {
            let s = Scenario()
            try s.fail(0); try s.fail(1); try s.fail(2)
            try require(s.snapshot.attempts == [0, 1, 2] && s.snapshot.errors.count == 1,
                        "Network failure changed ordinary ranking")
            try s.integrity()
        }
        try check("a mismatching SERVFAIL cannot activate service diversification") {
            let s = Scenario()
            try s.reply(0, 2, matching: false)
            try require(s.snapshot.attempts == [0, 1], "Mismatching response reordered candidates")
            try s.reply(1, 0); try s.integrity()
        }
        try check("already-started same-provider hedge consumes its slot and remains live") {
            let s = Scenario()
            s.flow.serviceAuditHedge()
            try require(s.snapshot.attempts == [0, 1] && s.snapshot.live == 2, "Hedge was not active")
            try s.reply(0, 2)
            try require(s.snapshot.attempts == [0, 1, 2] && s.snapshot.live == 2,
                        "Active hedge was cancelled or fourth slot invented")
            try s.reply(2, 2)
            try require(s.snapshot.answers.isEmpty && s.snapshot.errors.isEmpty && s.snapshot.live == 1,
                        "Pending Google hedge was discarded after backup SERVFAIL")
            try s.reply(1, 2)
            try require(s.snapshot.attempts == [0, 1, 2] && s.snapshot.errors.count == 1,
                        "Already-spent slot was reclaimed to dial fourth provider")
            try s.integrity()
        }
        try check("two admitted SERVFAIL callbacks cannot duplicate or reopen a consumed candidate") {
            let s = Scenario()
            s.flow.serviceAuditHedge()
            let failed = DNSMessageInspection.errorResponse(to: s.query, code: .servfail)!
            s.peer(0)!.receive(failed); s.peer(1)!.receive(failed); s.flow.serviceAuditDrain()
            try require(s.snapshot.attempts == [0, 1, 2] && s.snapshot.live == 1,
                        "Queued failures duplicated a candidate or exceeded the attempt cap")
            try s.reply(2, 0)
            try s.reply(0, 2)
            try require(s.snapshot.attempts == [0, 1, 2] && s.snapshot.answers.count == 1 && s.snapshot.errors.isEmpty,
                        "Late SERVFAIL changed an already completed winner")
            try s.integrity()
        }
        try check("single approved provider retains backup IP recovery") {
            let third = candidate("https://dns.google/dns-query#203.0.113.80")
            let s = Scenario([g1, g2, third])
            try s.reply(0, 2); try s.reply(1, 2); try s.reply(2, 0)
            try require(s.snapshot.attempts == [0, 1, 2] && s.snapshot.answers.count == 1,
                        "Single-provider alternate IPs were lost")
            try s.integrity()
        }
        try check("unapproved Cloudflare cannot appear and remaining repeated provider is retained") {
            let s = Scenario([g1, g2, dnspod])
            try s.reply(0, 2); try s.reply(fixed ? 2 : 1, 2); try s.reply(fixed ? 1 : 2, 0)
            try require(s.snapshot.attempts == (fixed ? [0, 2, 1] : [0, 1, 2]) && s.snapshot.answers.count == 1,
                        "Unapproved service was added or repeated-provider fallback was lost")
            try s.integrity()
        }
        for code: UInt8 in [0, 3, 5] {
            try check("rcode \(code) remains terminal without shopping for another provider") {
                let s = Scenario()
                try s.reply(0, code)
                try require(s.snapshot.attempts == [0] && s.snapshot.answers.count == 1
                    && s.snapshot.answers[0][3] & 0x0f == code && s.snapshot.errors.isEmpty,
                    "Valid NODATA/NXDOMAIN/REFUSED response triggered retry")
                let health = s.selector.serviceAuditHealth(s.scope, g1.id)
                try require(health.failures == 0 && health.successes == (code == 5 ? 0 : 1),
                            "Terminal refusal changed health evidence")
                try s.integrity()
            }
        }
        try check("authentication barrier survives later SERVFAIL and timeout") {
            let s = Scenario(protectFallback: true)
            try s.fail(0, EncryptedDNSQueryFailure.authentication)
            try require(s.snapshot.attempts == [0, 1], "Authentication was mistaken for SERVFAIL")
            try s.reply(1, 2); try s.fail(2, EncryptedDNSQueryFailure.timeout)
            try require(s.snapshot.attempts == [0, 1, 2] && s.snapshot.answers.isEmpty
                && s.snapshot.errors.count == 1
                && EncryptedDNSQueryFailure.classify(s.snapshot.errors[0]) == .authentication,
                "Later failure erased authentication barrier")
            try s.integrity()
        }
        try check("capacity, policy and local cancellation remain terminal without a new provider dial") {
            for error in [EncryptedDNSQueryFailure.capacity, .policy, .configuration, .cancelled] {
                let s = Scenario()
                try s.fail(0, error)
                try require(s.snapshot.attempts == [0] && s.snapshot.answers.isEmpty && s.snapshot.errors.count == 1,
                            "Local failure fanned out a new provider")
                let health = s.selector.serviceAuditHealth(s.scope, g1.id)
                try require(health.successes == 0 && health.failures == 0, "Local failure penalized provider health")
                try s.integrity()
            }
        }
        try check("permission revocation before SERVFAIL handling prevents replacement") {
            let s = Scenario()
            s.permission.revoke(); try s.reply(0, 2)
            try require(s.snapshot.attempts == [0] && s.snapshot.errors.isEmpty && s.snapshot.answers.count == 1
                && s.snapshot.answers[0][3] & 0x0f == 2,
                        "Policy revocation allowed a replacement")
            try s.integrity()
        }
        try check("deadline remains original after SERVFAIL and active hedging") {
            let s = Scenario()
            s.clock.advance(1); try s.reply(0, 2)
            s.flow.serviceAuditHedge()
            try require(s.snapshot.attempts == (fixed ? [0, 2, 3] : [0, 1, 2]) && s.snapshot.live == 2,
                        "Expected three-attempt/two-active schedule did not occur")
            s.clock.advance(8); s.flow.serviceAuditDeadline(); s.flow.serviceAuditDrain()
            try require(s.snapshot.errors.count == 1 && s.snapshot.errors[0] is DNSQueryTimeoutError
                && s.snapshot.answers.isEmpty && s.snapshot.live == 0, "Original deadline was extended")
            try s.reply(0, 0)
            try require(s.snapshot.answers.isEmpty && s.snapshot.attempts.count == 3, "Late callback reopened deadline")
            try s.integrity()
        }
        try check("client cancel waits for every cancellation receipt and rejects late replies") {
            let s = Scenario(holdAcknowledgements: true), completed = DispatchSemaphore(value: 0)
            try s.reply(0, 2)
            s.flow.cancel { completed.signal() }; s.flow.serviceAuditDrain()
            try require(completed.wait(timeout: .now()) == .timedOut, "Cancellation acknowledged before child receipts")
            try s.reply(0, 0)
            try s.reply(fixed ? 2 : 1, 2)
            try require(s.snapshot.attempts.count == 2 && s.snapshot.answers.isEmpty && s.snapshot.errors.isEmpty,
                        "Cancelled child callback escaped admission fence")
            for index in s.snapshot.attempts { s.peer(index)?.acknowledgeTwice() }
            try require(completed.wait(timeout: .now() + 2) == .success, "Cancellation receipt never arrived")
            try require(completed.wait(timeout: .now()) == .timedOut, "Cancellation receipt delivered twice")
            try s.integrity()
        }
    }

    #if BUILD20_SERVFAIL_SERVICE_GROUPS
    static func identities() throws {
        try check("provider identities ignore dial pins and share only explicit standard built-in aliases") {
            func id(_ raw: String) -> String { candidate(raw).upstream.resolverServiceID }
            let googleTLS = DNSConfiguredUpstream.dot(DoTEndpoint("tls://dns.google#8.8.4.4")!)
            let dnspodTLS = DNSConfiguredUpstream.dot(DoTEndpoint("tls://dot.pub#120.53.53.53")!)
            try require(g1.upstream.resolverServiceID == g2.upstream.resolverServiceID
                && g1.upstream.resolverServiceID == googleTLS.resolverServiceID
                && dnspod.upstream.resolverServiceID == dnspodTLS.resolverServiceID,
                "Known same-provider address/protocol variants were split")
            try require(cloudflare.upstream.resolverServiceID == id("https://one.one.one.one/dns-query#1.0.0.1")
                && cloudflare.upstream.resolverServiceID == id("https://MOZILLA.CLOUDFLARE-DNS.COM./dns-query#1.1.1.1"),
                "Known Cloudflare aliases were split")
            let custom = id("https://custom-a.fixture.invalid/dns-query#203.0.113.1")
            try require(custom == id("https://CUSTOM-A.FIXTURE.INVALID./dns-query#203.0.113.2")
                && custom != id("https://custom-b.fixture.invalid/dns-query#203.0.113.1")
                && custom != id("https://custom-a.fixture.invalid:8443/dns-query#203.0.113.1")
                && custom != id("https://custom-a.fixture.invalid/other#203.0.113.1")
                && custom != id("https://custom-a.fixture.invalid/dns-query?#203.0.113.1")
                && custom != id("https://custom-a.fixture.invalid/dns-query?profile=other#203.0.113.1"),
                "Unrelated custom endpoint services were collapsed")
            try require(g1.upstream.resolverServiceID != id("https://dns.google:8443/dns-query#8.8.8.8")
                && g1.upstream.resolverServiceID != id("https://dns.google/other#8.8.8.8")
                && g1.upstream.resolverServiceID != id("https://dns.google/dns-query?profile=other#8.8.8.8"),
                "Nonstandard built-in service was blindly merged")
        }
        try check("known cross-protocol variants cannot hide a different approved provider") {
            let googleTLS = DNSUpstreamCandidate(upstream: .dot(DoTEndpoint("tls://dns.google#8.8.4.4")!), bootstrap: nil)
            let s = Scenario([g1, googleTLS, dnspod, cloudflare])
            try s.reply(0, 2); try s.reply(2, 2); try s.reply(3, 0)
            try require(s.snapshot.attempts == [0, 2, 3] && s.snapshot.answers.count == 1,
                        "Cross-protocol Google variant consumed provider coverage")
            try s.integrity()
        }
        try check("published literal and explicitly approved plain DNS variants share standard provider identity") {
            let googleLiteral = candidate("https://8.8.8.8/dns-query")
            let googleTLS = DNSUpstreamCandidate(upstream: .dot(DoTEndpoint("tls://8.8.4.4")!), bootstrap: nil)
            let googlePlain = DNSUpstreamCandidate(upstream: .plain(host: "8.8.8.8", port: 53), bootstrap: nil)
            for variant in [googleLiteral, googleTLS, googlePlain] {
                try require(variant.upstream.resolverServiceID == g1.upstream.resolverServiceID,
                            "Known literal or plain DNS split same provider")
                let s = Scenario([g1, variant, dnspod, cloudflare], allowApprovedPlaintext: true)
                try s.reply(0, 2); try s.reply(2, 2); try s.reply(3, 0)
                try require(s.snapshot.attempts == [0, 2, 3] && s.snapshot.answers.count == 1,
                            "Known same-provider literal consumed another service slot")
                try s.integrity()
            }
            let cfLiteral = candidate("https://1.1.1.1/dns-query")
            let cfPlain = DNSConfiguredUpstream.plain(host: "1.0.0.1", port: 53)
            try require(cfLiteral.upstream.resolverServiceID == cloudflare.upstream.resolverServiceID
                && cfPlain.resolverServiceID == cloudflare.upstream.resolverServiceID,
                "Cloudflare published literal aliases were split")
            try require(DNSConfiguredUpstream.plain(host: "8.8.8.8", port: 1053).resolverServiceID != g1.upstream.resolverServiceID
                && candidate("https://8.8.8.8:8443/dns-query").upstream.resolverServiceID != g1.upstream.resolverServiceID
                && candidate("https://1.1.1.1/custom").upstream.resolverServiceID != cloudflare.upstream.resolverServiceID,
                "Published IP merged an unrelated custom port/path")
        }
        try check("different custom endpoints remain independent approved services") {
            let a = candidate("https://custom-a.fixture.invalid/dns-query#203.0.113.1")
            let a2 = candidate("https://custom-a.fixture.invalid/dns-query#203.0.113.2")
            let b = candidate("https://custom-b.fixture.invalid/dns-query#203.0.113.3")
            let s = Scenario([a, a2, b, cloudflare])
            try s.reply(0, 2); try s.reply(2, 2); try s.reply(3, 0)
            try require(s.snapshot.attempts == [0, 2, 3] && s.snapshot.answers.count == 1,
                        "Diagnostic custom label conflated unrelated resolvers")
            try s.integrity()
        }
    }
    #endif

    static func main() {
        do {
            let fixed = CommandLine.arguments.dropFirst().first != "before"
            try regression(fixed: fixed)
            #if BUILD20_SERVFAIL_SERVICE_GROUPS
            try identities()
            #endif
            print("DNS SERVFAIL provider diversity passed: \(checks) cases, fixed=\(fixed), exact production Adaptive, memory only")
        } catch {
            fputs("DNS SERVFAIL provider diversity FAILED: \(error.localizedDescription)\n", stderr); exit(1)
        }
    }
}

import Foundation
import HajimiDNS

enum DNSProxyFallbackTransportPolicy {
    /// Actual resolved nodes, not group names or the global default. Every hop
    /// must protect/authenticate the DNS payload. Unknown composition is denied.
    static func permits(_ route: ResolvedRoute, policies: [String: ProxyPolicy]) -> Bool {
        let selected: ProxyPolicy
        switch route {
        case .native(let node, _), .http(let node, _), .socks5(let node, _): selected = node
        case .direct, .reject: return false
        }
        var node = selected, visited = Set<String>()
        for _ in 0..<16 {
            guard visited.insert(node.name).inserted, nodePermits(node) else { return false }
            let underlying = node.parameters["underlying-proxy"]
            let dialer = node.parameters["dialer-proxy"]
            if let underlying, let dialer, underlying != dialer { return false }
            guard let nextName = underlying ?? dialer else { return true }
            guard !nextName.isEmpty, nextName == nextName.trimmingCharacters(in: .whitespacesAndNewlines) else { return false }
            if let next = policies[nextName] {
                // A physical DIRECT terminator dials the encrypted node; it is
                // not a DIRECT route to the ordinary DNS server.
                if next.kind == .direct { return true }
                if next.kind == .reject { return false }
                node = next
            } else { return nextName.uppercased() == "DIRECT" }
        }
        return false
    }

    private static func flag(_ value: String?, default fallback: Bool = false) -> Bool? {
        guard let value else { return fallback }
        // C++ removes ALL whitespace but prepared Swift carriers do not.
        // Refuse noncanonical values instead of allowing the two to disagree.
        guard !value.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.contains) else { return nil }
        switch value.lowercased() {
        case "true", "yes", "on", "1": return true
        case "false", "no", "off", "0": return false
        default: return nil
        }
    }

    private static func nodePermits(_ node: ProxyPolicy) -> Bool {
        guard [.native, .external, .http, .socks5].contains(node.kind),
              let host = node.host, !host.isEmpty, let port = node.port, port > 0,
              flag(node.parameters["skip-cert-verify"]) == false,
              flag(node.parameters["skip-common-name-verify"]) == false else { return false }
        for key in ["tls", "vmess-aead", "ws"] where node.parameters[key] != nil {
            guard flag(node.parameters[key]) != nil else { return false }
        }
        // A local proxy endpoint cannot prove that the ordinary DNS egress is
        // outside this Mac. Do not mistake encryption on lo0 for leak protection.
        let normalizedHost = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard normalizedHost != "localhost", !normalizedHost.hasSuffix(".localhost") else { return false }
        if DoHEndpoint.isAddressLiteral(host), DNSProxyFallbackServer(DoHEndpoint.unbracketed(host)) == nil { return false }
        // These parsed options are not implemented as pins by the current
        // transport. Never silently weaken a user's requested identity check.
        for key in ["server-cert-fingerprint-sha256", "tls-verification"] {
            if let value = node.parameters[key], !value.isEmpty { return false }
        }
        guard NativeOutboundFactory.supports(node) else { return false }
        // Match the C++ configuration encoder exactly. A stale/malformed
        // adapter hint must not lend VMess/SS encryption to an actual HTTP
        // or SOCKS carrier selected by its policy kind.
        let type: String
        switch node.kind {
        case .http: type = node.adapterType?.lowercased() == "https" ? "https" : "http"
        case .socks5: type = node.adapterType?.lowercased() == "socks5-tls" ? "socks5-tls" : "socks5"
        default: type = node.adapterType?.lowercased() ?? ""
        }
        switch type {
        case "vmess":
            let cipher = (node.parameters["cipher"] ?? node.parameters["encryption"] ?? "auto").lowercased()
            return ["auto", "aes-128-gcm"].contains(cipher)
                && flag(node.parameters["vmess-aead"], default: true) == true
                && (node.parameters["alter-id"] ?? node.parameters["alterid"] ?? "0") == "0"
        case "ss":
            let cipher = (node.parameters["cipher"] ?? node.parameters["encrypt-method"] ?? "").lowercased()
            return ["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                "chacha20-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
                "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"].contains(cipher)
        case "vless", "trojan", "http", "https", "socks5", "socks5-tls":
            let reality = node.parameters["reality-public-key"] != nil
                || (node.parameters["security"] ?? "").lowercased() == "reality"
            if reality { return ["vless", "vmess", "trojan"].contains(type) }
            let defaultTLS = ["trojan", "https", "socks5-tls"].contains(type)
                || (node.parameters["security"] ?? "").lowercased() == "tls"
            return flag(node.parameters["tls"], default: defaultTLS) == true
        case "anytls", "hysteria", "hysteria2", "tuic", "trusttunnel":
            return flag(node.parameters["tls"], default: true) == true
        case "mieru": return true
        case "sudoku":
            let aead = (node.parameters["aead-method"] ?? node.parameters["cipher"] ?? "chacha20-poly1305").lowercased()
            return ["chacha20-poly1305", "aes-128-gcm"].contains(aead)
        case "ssh": return node.parameters["host-key"]?.isEmpty == false
        default: return false // CFB/SSR, unknown/native-unavailable carriers.
        }
    }
}

enum DNSProxyFallbackBudget {
    static func encryptedWindow(remaining: TimeInterval, knownMilliseconds: [Double]) -> TimeInterval {
        guard remaining.isFinite, remaining > 0 else { return 0 }
        let healthy = knownMilliseconds.filter { $0.isFinite && $0 >= 0 }
            .map { $0 / 1_000 * 1.75 + 0.25 }.max() ?? 0
        // Unknown blackholes need not consume the full eight seconds. A known
        // healthy slow path gets its measured headroom, even the whole budget.
        return min(remaining, max(min(3, remaining), healthy))
    }
}

/// Exactly one encrypted phase followed, conditionally, by one bounded serial
/// TCP ordinary-DNS phase through the SAME verified proxy. No racing plaintext,
/// direct/socket/system resolver alternative is expressible in this class.
final class DNSProxyFallbackQueryDatagram: NativeRoutedDatagram, DNSQueryDeadlineAwareDatagram, DNSQueryCancellationAcknowledging,
                                         DNSQueryExecutionContextAccepting {
    typealias Factory = (DispatchQueue, TimeInterval, @escaping (Data) -> Void,
                        @escaping (Error) -> Void) throws -> DNSQueryCancellationAcknowledging
    typealias Schedule = (DispatchQueue, TimeInterval, @escaping () -> Void) -> (() -> Void)
    private enum Phase { case idle, encrypted, cancelling, fallback, finished }
    private let queue: DispatchQueue
    private let permitted: () -> Bool, clock: () -> TimeInterval
    private let encrypted: Factory, fallback: Factory, knownMilliseconds: () -> [Double]
    private let receive: (Data) -> Void, failure: (Error) -> Void
    private let absoluteDeadline: TimeInterval, schedule: Schedule
    private let diagnostics: NetworkPerformanceDiagnostics
    private let admission = NSLock()
    private var closed = false, deadlineSignalled = false, admitted = false
    private var executionContext = DNSQueryExecutionContext()
    private var cancellationReason: DNSAttemptCancellationReason?
    private var phase = Phase.idle, epoch: UInt64 = 0
    private var query: Data?, transport: DNSQueryCancellationAcknowledging?
    private var overallTimer: (() -> Void)?, phaseTimer: (() -> Void)?
    private var started: TimeInterval = 0, phaseStarted: TimeInterval = 0
    private var encryptedObserved = false, fallbackObserved = false

    init(queue: DispatchQueue, absoluteDeadline: TimeInterval, permitted: @escaping () -> Bool,
         knownMilliseconds: @escaping () -> [Double], encrypted: @escaping Factory,
         fallback: @escaping Factory, receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         schedule: @escaping Schedule = DNSProxyFallbackQueryDatagram.scheduleTimer,
         diagnostics: NetworkPerformanceDiagnostics = .shared) {
        self.queue = DispatchQueue(label: "app.hajimi.dns.secure-proxy-fallback", qos: .userInitiated, target: queue)
        self.absoluteDeadline = absoluteDeadline; self.permitted = permitted; self.knownMilliseconds = knownMilliseconds
        self.encrypted = encrypted; self.fallback = fallback; self.receive = receive; self.failure = failure
        self.clock = clock; self.schedule = schedule; self.diagnostics = diagnostics
    }

    private static func scheduleTimer(queue: DispatchQueue, delay: TimeInterval, work: @escaping () -> Void) -> (() -> Void) {
        let item = DispatchWorkItem(block: work)
        queue.asyncAfter(deadline: .now() + max(0, delay), execute: item)
        return { item.cancel() }
    }

    private var stopped: Bool {
        admission.lock(); defer { admission.unlock() }; return closed || deadlineSignalled
    }

    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
        admission.lock(); defer { admission.unlock() }
        guard !admitted, !closed, !deadlineSignalled else { return }
        executionContext = context
    }

    func send(_ data: Data) {
        admission.lock()
        guard !closed, !deadlineSignalled, !admitted else { admission.unlock(); return }
        admitted = true; admission.unlock()
        queue.async {
            guard !self.stopped else { return }
            guard self.permitted() else { self.finishFailure(EncryptedDNSQueryFailure.policy); return }
            let now = self.clock()
            guard now.isFinite, self.absoluteDeadline.isFinite, self.absoluteDeadline > now else {
                self.finishFailure(DNSQueryTimeoutError()); return
            }
            guard DNSMessageInspection.singleQuestion(in: data) != nil else {
                self.finishFailure(EncryptedDNSQueryFailure.configuration); return
            }
            self.query = data; self.started = now
            self.overallTimer = self.schedule(self.queue, self.absoluteDeadline - now) { [weak self] in
                self?.overallDeadlineReached()
            }
            self.begin(.encrypted)
            self.scheduleEncryptedWindow()
        }
    }

    private func begin(_ next: Phase) {
        guard !stopped, let query, phase != .finished, permitted() else {
            if !stopped { finishFailure(EncryptedDNSQueryFailure.policy) }; return
        }
        guard clock().isFinite, clock() < absoluteDeadline else { overallDeadlineReached(); return }
        epoch &+= 1; let token = epoch
        phase = next; phaseStarted = clock()
        if next == .fallback { diagnostics.recordDNS(.proxyFallbackAttempt) }
        do {
            let child = try (next == .encrypted ? encrypted : fallback)(queue, absoluteDeadline, { [weak self] data in
                self?.queue.async { self?.accept(data, token: token) }
            }, { [weak self] error in
                self?.queue.async { self?.failed(error, token: token) }
            })
            guard !stopped, permitted(), epoch == token, clock() < absoluteDeadline else {
                child.cancel(reason: .policyChanged, completion: {})
                if !stopped { finishFailure(EncryptedDNSQueryFailure.policy) }; return
            }
            // Both phases retain the coordinator root and original absolute
            // deadline. Each candidate gets a separate diagnostic timeline;
            // installing it does not admit I/O or weaken the ACK barrier.
            (child as? DNSQueryExecutionContextAccepting)?
                .setDNSQueryExecutionContext(executionContext.child())
            transport = child; child.send(query)
        } catch { failed(error, token: token) }
    }

    private func scheduleEncryptedWindow() {
        guard phase == .encrypted, !stopped else { return }
        let window = DNSProxyFallbackBudget.encryptedWindow(remaining: absoluteDeadline - started,
                                                           knownMilliseconds: knownMilliseconds())
        let cutoff = started + window
        guard cutoff < absoluteDeadline - 0.001 else { return }
        phaseTimer?()
        phaseTimer = schedule(queue, max(0, cutoff - clock())) { [weak self] in self?.encryptedWindowReached() }
    }

    private func encryptedWindowReached() {
        guard phase == .encrypted, !stopped else { return }
        guard permitted() else { finishFailure(EncryptedDNSQueryFailure.policy); return }
        // Another query can learn that this is a healthy slow path while our
        // timer was pending. Never clip it using the old cold-start window.
        let cutoff = started + DNSProxyFallbackBudget.encryptedWindow(remaining: absoluteDeadline - started,
                                                                      knownMilliseconds: knownMilliseconds())
        if cutoff > clock() + 0.001 { scheduleEncryptedWindow(); return }
        if let provider = transport as? DNSProxyFallbackBarrierProviding,
           let barrier = provider.proxyFallbackBarrier() {
            if case .answer(let data) = barrier, let query,
               DNSMessageInspection.responseMatchesQuery(data, query: query),
               [UInt8(0), 3].contains(data[data.startIndex + 3] & 0x0f) {
                accept(data, token: epoch)
            } else { phaseTimer?(); phaseTimer = nil } // keep encrypted-only until its original deadline
            return
        }
        if let scheduler = transport as? DNSQueryEncryptedPhaseScheduling {
            let token = epoch
            scheduler.encryptedPhaseContinuationDeadline { [weak self] continuation in
                self?.queue.async {
                    guard let self, self.phase == .encrypted, self.epoch == token, !self.stopped else { return }
                    guard self.permitted() else { self.finishFailure(EncryptedDNSQueryFailure.policy); return }
                    let now = self.clock()
                    guard now.isFinite, now < self.absoluteDeadline else { self.overallDeadlineReached(); return }
                    if let continuation, continuation.isFinite, continuation > now + 0.001 {
                        let cutoff = min(continuation, self.absoluteDeadline)
                        self.phaseTimer?()
                        // The overall deadline owns the final timeout; do not
                        // race another phase transition at that same instant.
                        if cutoff < self.absoluteDeadline - 0.001 {
                            self.phaseTimer = self.schedule(self.queue, cutoff - now) { [weak self] in
                                self?.encryptedWindowReached()
                            }
                        } else { self.phaseTimer = nil }
                    } else { self.transitionToFallback(deadlineExpired: true) }
                }
            }
            return
        }
        transitionToFallback(deadlineExpired: true)
    }

    private func accept(_ answer: Data, token: UInt64) {
        guard token == epoch, !stopped, phase == .encrypted || phase == .fallback, let query else { return }
        guard permitted() else { finishFailure(EncryptedDNSQueryFailure.policy); return }
        guard clock() < absoluteDeadline else { overallDeadlineReached(); return }
        guard DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
            finishFailure(EncryptedDNSQueryFailure.invalidResponse); return
        }
        let code = answer[answer.startIndex + 3] & 0x0f
        observe(code == 0 || code == 3 ? .success : .failure)
        finish(answer: answer)
    }

    private func failed(_ error: Error, token: UInt64) {
        guard token == epoch, !stopped, phase == .encrypted || phase == .fallback else { return }
        guard permitted() else { finishFailure(EncryptedDNSQueryFailure.policy); return }
        if (error is DNSQueryTimeoutError || EncryptedDNSQueryFailure.classify(error) == .timeout),
           clock() >= absoluteDeadline {
            overallDeadlineReached(); return
        }
        if phase == .encrypted, (error as? EncryptedDNSQueryFailure)?.permitsProxyFallback == true {
            transitionToFallback(); return
        }
        // A phase-local deterministic timeout is retryable; the overall parent
        // timeout never is. No arbitrary Error/NSError/string grants a downgrade.
        if phase == .encrypted, error is DNSQueryTimeoutError, clock() < absoluteDeadline {
            transitionToFallback(); return
        }
        finishFailure(error)
    }

    private func transitionToFallback(deadlineExpired: Bool = false) {
        guard phase == .encrypted, !stopped else { return }
        guard clock() < absoluteDeadline else { overallDeadlineReached(); return }
        let old = transport
        if let provider = old as? DNSProxyFallbackBarrierProviding, let barrier = provider.proxyFallbackBarrier() {
            finish(barrier: barrier); return
        }
        phaseTimer?(); phaseTimer = nil
        phase = .cancelling; epoch &+= 1; let token = epoch
        let acknowledged: () -> Void = { [weak self] in
            self?.queue.async {
                guard let self, self.epoch == token, self.phase == .cancelling, !self.stopped else { return }
                guard self.permitted() else { self.finishFailure(EncryptedDNSQueryFailure.policy); return }
                guard self.clock().isFinite, self.clock() < self.absoluteDeadline else { self.overallDeadlineReached(); return }
                // Inspect again AFTER the child queue's logical cancellation
                // ACK, so a queued auth/negative cannot be erased by timeout.
                if let provider = old as? DNSProxyFallbackBarrierProviding, let barrier = provider.proxyFallbackBarrier() {
                    self.finish(barrier: barrier); return
                }
                self.observe(.failure)
                self.transport = nil
                guard self.clock() < self.absoluteDeadline else { self.overallDeadlineReached(); return }
                self.begin(.fallback)
            }
        }
        if deadlineExpired, let timed = old as? DNSQueryPhaseDeadlineAcknowledging {
            timed.phaseDeadlineReached(completion: acknowledged)
        } else if let old {
            old.cancel(reason: deadlineExpired ? .encryptedPhaseDeadline : .cleanup, completion: acknowledged)
        }
        else { acknowledged() }
    }

    private func finish(barrier: DNSProxyFallbackBarrier) {
        guard !stopped else { return }
        guard permitted() else { finishFailure(EncryptedDNSQueryFailure.policy); return }
        guard clock().isFinite, clock() < absoluteDeadline else { overallDeadlineReached(); return }
        switch barrier {
        case .answer(let answer):
            guard let query, DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
                finishFailure(EncryptedDNSQueryFailure.invalidResponse); return
            }
            let code = answer[answer.startIndex + 3] & 0x0f
            observe(code == 0 || code == 3 ? .success : .failure); finish(answer: answer)
        case .failure(let error): finishFailure(error)
        }
    }

    private func observe(_ outcome: NetworkPerformanceOutcome) {
        let stage: NetworkPerformanceStage
        if phase == .fallback {
            guard !fallbackObserved else { return }; fallbackObserved = true; stage = .dnsProxyFallbackPhase
            if outcome == .success { diagnostics.recordDNS(.proxyFallbackSuccess) }
            else if outcome == .failure { diagnostics.recordDNS(.proxyFallbackFailure) }
        } else {
            guard phase == .encrypted || phase == .cancelling, !encryptedObserved else { return }
            encryptedObserved = true; stage = .dnsEncryptedPhase
        }
        diagnostics.record(stage, milliseconds: max(0, clock() - phaseStarted) * 1_000, outcome: outcome)
    }

    private func finish(answer: Data? = nil, error: Error? = nil, notifyingDeadline: Bool = false) {
        guard phase != .finished else { return }
        phase = .finished; epoch &+= 1
        overallTimer?(); phaseTimer?(); overallTimer = nil; phaseTimer = nil
        let old = transport; transport = nil; query = nil
        if notifyingDeadline, let timed = old as? DNSQueryDeadlineAwareDatagram {
            // The child owns total-timeout cleanup and its health receipt.
            // An immediate ordinary cancel would revoke that admission before
            // its queue can fence an already-observed native error.
            timed.queryDeadlineReached()
        } else {
            let reason: DNSAttemptCancellationReason = notifyingDeadline ? .overallDeadline
                : (answer != nil ? .winnerSelected
                    : ((error as? EncryptedDNSQueryFailure) == .policy ? .policyChanged : .cleanup))
            old?.cancel(reason: reason, completion: {})
        }
        if let answer { receive(answer) } else if let error { failure(error) }
    }

    private func finishFailure(_ error: Error) { observe(.failure); finish(error: error) }

    private func overallDeadlineReached() {
        guard phase != .finished else { return }
        admission.lock(); let cancelled = closed; deadlineSignalled = true; admission.unlock()
        guard !cancelled else { return }
        observe(.failure)
        finish(error: DNSQueryTimeoutError(), notifyingDeadline: true)
    }

    func queryDeadlineReached() {
        admission.lock(); guard !closed, !deadlineSignalled else { admission.unlock(); return }
        deadlineSignalled = true; admission.unlock()
        queue.async { self.overallDeadlineReached() }
    }

    func cancel() { cancel(completion: {}) }

    func cancel(completion: @escaping () -> Void) {
        cancel(reason: .callerCancelled, completion: completion)
    }

    func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        admission.lock()
        if !closed { cancellationReason = reason }
        let reason = cancellationReason ?? reason
        closed = true; admission.unlock()
        queue.async {
            self.observe(.cancelled); self.phase = .finished; self.epoch &+= 1
            self.overallTimer?(); self.phaseTimer?(); self.overallTimer = nil; self.phaseTimer = nil
            let child = self.transport; self.transport = nil; self.query = nil
            if let child { child.cancel(reason: reason, completion: completion) } else { completion() }
        }
    }

    func drainQueueForSelfTest() { queue.sync {} }
}

/// Pure memory/clock/crypto-configuration checks. No socket, resolver, Helper,
/// application state, system proxy or user configuration is used.
public enum DNSProxyFallbackSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "安全代理 DNS 回退自检失败：\(text)" }
    }
    private static func expect(_ condition: Bool, _ text: String) throws {
        if !condition { throw Failure(text: text) }
    }
    private final class Clock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func set(_ value: TimeInterval) { lock.lock(); self.value = value; lock.unlock() }
    }
    private final class Timers {
        private final class Item {
            let time: TimeInterval, queue: DispatchQueue, work: () -> Void
            var cancelled = false
            init(_ time: TimeInterval, _ queue: DispatchQueue, _ work: @escaping () -> Void) {
                self.time = time; self.queue = queue; self.work = work
            }
        }
        private let clock: Clock, lock = NSLock()
        private var items: [Item] = []
        init(_ clock: Clock) { self.clock = clock }
        var schedule: DNSProxyFallbackQueryDatagram.Schedule {
            { queue, delay, work in
                let item = Item(self.clock.now() + delay, queue, work)
                self.lock.lock(); self.items.append(item); self.lock.unlock()
                return { self.lock.lock(); item.cancelled = true; self.lock.unlock() }
            }
        }
        func fire() {
            lock.lock()
            let due = items.filter { !$0.cancelled && $0.time <= clock.now() }
            items.removeAll { $0.cancelled || $0.time <= clock.now() }
            lock.unlock()
            due.forEach { $0.queue.async(execute: $0.work) }
        }
    }
    private final class MemoryTransport: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding {
        private let lock = NSLock()
        private let receive: (Data) -> Void, failure: (Error) -> Void
        private var held = false, callbacks: [() -> Void] = [], barrier: DNSProxyFallbackBarrier?
        private var sent: [Data] = [], cancellations = 0
        init(receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
            self.receive = receive; self.failure = failure
        }
        func send(_ data: Data) { lock.lock(); sent.append(data); lock.unlock() }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); cancellations += 1
            if held { callbacks.append(completion); lock.unlock() }
            else { lock.unlock(); completion() }
        }
        func holdACK() { lock.lock(); held = true; lock.unlock() }
        func acknowledge() {
            lock.lock(); held = false; let values = callbacks; callbacks.removeAll(); lock.unlock()
            values.forEach { $0() }
        }
        func setBarrier(_ value: DNSProxyFallbackBarrier) { lock.lock(); barrier = value; lock.unlock() }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { lock.lock(); defer { lock.unlock() }; return barrier }
        var query: Data? { lock.lock(); defer { lock.unlock() }; return sent.first }
        var cancelCount: Int { lock.lock(); defer { lock.unlock() }; return cancellations }
        func reply(code: UInt8 = 0) {
            if let query, var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail) {
                answer[3] = (answer[3] & 0xf0) | (code & 0x0f); receive(answer)
            }
        }
        func reply(_ data: Data) { receive(data) }
        func fail(_ error: Error) { failure(error) }
    }
    private final class Fixture {
        let clock = Clock(), diagnostics = NetworkPerformanceDiagnostics()
        let query = DNSMessageInspection.query(for: "owned.fallback.example.test", type: 1, id: 0x1234)!
        private let fallbackServers: [DNSProxyFallbackServer]
        private let selector = DNSAdaptiveUpstreamSelector()
        private let lock = NSLock()
        private var allowed = true, encryptedValues: [MemoryTransport] = [], fallbackValues: [MemoryTransport] = []
        private var answers: [Data] = [], errors: [Error] = [], observed: [Double] = []
        private var resolverSequence: DNSProxyFallbackResolverSequence?
        lazy var timers = Timers(clock)
        lazy var flow = DNSProxyFallbackQueryDatagram(queue: .global(qos: .userInitiated), absoluteDeadline: 108,
            permitted: { [weak self] in
                guard let self else { return false }
                self.lock.lock(); defer { self.lock.unlock() }; return self.allowed
            }, knownMilliseconds: { [weak self] in
                guard let self else { return [] }
                self.lock.lock(); defer { self.lock.unlock() }; return self.observed
            }, encrypted: { [weak self] _, _, receive, failure in
                guard let self else { throw EncryptedDNSQueryFailure.configuration }
                let value = MemoryTransport(receive: receive, failure: failure)
                self.lock.lock(); self.encryptedValues.append(value); self.lock.unlock(); return value
            }, fallback: { [weak self] queue, deadline, receive, failure in
                guard let self else { throw EncryptedDNSQueryFailure.configuration }
                guard !self.fallbackServers.isEmpty else {
                    return self.makeFallback(receive: receive, failure: failure)
                }
                let sequence = DNSProxyFallbackResolverSequence(servers: self.fallbackServers,
                    selector: self.selector, scopeKey: "owned-composed-proxy-fallback", queue: queue,
                    absoluteDeadline: deadline, permitted: { [weak self] in
                        guard let self else { return false }
                        self.lock.lock(); defer { self.lock.unlock() }; return self.allowed
                    }, factory: { [weak self] _, _, _, receive, failure in
                        guard let self else { throw EncryptedDNSQueryFailure.configuration }
                        return self.makeFallback(receive: receive, failure: failure)
                    }, receive: receive, failure: failure, clock: self.clock.now,
                    schedule: self.timers.schedule, diagnostics: self.diagnostics)
                self.lock.lock(); self.resolverSequence = sequence; self.lock.unlock(); return sequence
            }, receive: { [weak self] answer in
                guard let self else { return }
                self.lock.lock(); self.answers.append(answer); self.lock.unlock()
            }, failure: { [weak self] error in
                guard let self else { return }
                self.lock.lock(); self.errors.append(error); self.lock.unlock()
            },
            clock: clock.now, schedule: timers.schedule, diagnostics: diagnostics)
        init(fallbackServerCount: Int = 0) {
            fallbackServers = (0..<fallbackServerCount).map { DNSProxyFallbackServer("203.0.113.\(60 + $0)")! }
        }
        private func makeFallback(receive: @escaping (Data) -> Void,
                                  failure: @escaping (Error) -> Void) -> MemoryTransport {
            let value = MemoryTransport(receive: receive, failure: failure)
            lock.lock(); fallbackValues.append(value); lock.unlock()
            return value
        }
        var encrypted: [MemoryTransport] { lock.lock(); defer { lock.unlock() }; return encryptedValues }
        var fallback: [MemoryTransport] { lock.lock(); defer { lock.unlock() }; return fallbackValues }
        var results: (answers: [Data], errors: [Error]) { lock.lock(); defer { lock.unlock() }; return (answers, errors) }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
        func observe(_ milliseconds: Double) { lock.lock(); observed = [milliseconds]; lock.unlock() }
        func settle() {
            for _ in 0..<12 {
                flow.drainQueueForSelfTest()
                lock.lock(); let sequence = resolverSequence; lock.unlock()
                sequence?.drainQueueForSelfTest()
            }
        }
        func start() { flow.send(query); settle() }
        func advance(_ now: TimeInterval) { clock.set(now); timers.fire(); settle() }
        func stop() {
            flow.cancel(); encrypted.forEach { $0.acknowledge() }; fallback.forEach { $0.acknowledge() }; settle()
        }
    }

    private final class SequenceFixture {
        let clock = Clock(), diagnostics = NetworkPerformanceDiagnostics()
        let selector = DNSAdaptiveUpstreamSelector(), scope = "owned-proxy-fallback-sequence"
        let query = DNSMessageInspection.query(for: "owned.sequence.example.test", type: 1, id: 0x5678)!
        let servers: [DNSProxyFallbackServer]
        private let lock = NSLock()
        private var allowed = true, values: [(DNSProxyFallbackServer, TimeInterval, MemoryTransport)] = []
        private var answers: [Data] = [], errors: [Error] = []
        lazy var timers = Timers(clock)
        lazy var flow = DNSProxyFallbackResolverSequence(servers: servers, selector: selector, scopeKey: scope,
            queue: .global(qos: .userInitiated), absoluteDeadline: 108,
            permitted: { [weak self] in
                guard let self else { return false }
                self.lock.lock(); defer { self.lock.unlock() }; return self.allowed
            }, factory: { [weak self] server, _, deadline, receive, failure in
                guard let self else { throw EncryptedDNSQueryFailure.configuration }
                let value = MemoryTransport(receive: receive, failure: failure)
                self.lock.lock(); self.values.append((server, deadline, value)); self.lock.unlock(); return value
            }, receive: { [weak self] answer in
                guard let self else { return }
                self.lock.lock(); self.answers.append(answer); self.lock.unlock()
            }, failure: { [weak self] error in
                guard let self else { return }
                self.lock.lock(); self.errors.append(error); self.lock.unlock()
            }, clock: clock.now, schedule: timers.schedule, diagnostics: diagnostics)
        init(count: Int = 2) {
            servers = (0..<count).map { DNSProxyFallbackServer("203.0.113.\(60 + $0)")! }
        }
        var transports: [MemoryTransport] { lock.lock(); defer { lock.unlock() }; return values.map { $0.2 } }
        var attempts: [(DNSProxyFallbackServer, TimeInterval)] { lock.lock(); defer { lock.unlock() }; return values.map { ($0.0, $0.1) } }
        var results: (answers: [Data], errors: [Error]) { lock.lock(); defer { lock.unlock() }; return (answers, errors) }
        private func id(_ server: DNSProxyFallbackServer) -> String {
            [server.host, String(server.port)].map { "\($0.utf8.count):\($0)" }.joined()
        }
        func observe(_ milliseconds: [Double]) {
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: servers.map(id))
            for (server, value) in zip(servers, milliseconds) {
                selector.record(scopeKey: scope, candidateID: id(server), milliseconds: value, success: true)
            }
        }
        var preferred: DNSProxyFallbackServer? {
            let first = selector.orderedCandidates(scopeKey: scope, candidateIDs: servers.map(id)).first
            return servers.first { id($0) == first }
        }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
        func settle() { for _ in 0..<12 { flow.drainQueueForSelfTest() } }
        func start() { flow.send(query); settle() }
        func advance(_ now: TimeInterval) { clock.set(now); timers.fire(); settle() }
        func stop() { flow.cancel(); transports.forEach { $0.acknowledge() }; settle() }
    }

    public static func run() throws {
        try transportEligibility()
        try phaseSafety()
        try resolverSequenceSafety()
        try DNSFallbackDeadlineHealthSelfTest.run()
        try DNSSecurityRoutingSelfTest.runProxyFallbackTests()
        print("Secure proxy DNS fallback checks passed: verified routes/chains, bounded serial approved-resolver failover, typed failures, shared deadline, cancellation ACK, late replies, negative barriers and no direct/system/UDP fallback")
    }

    private static func transportEligibility() throws {
        let vmess = ProxyPolicy(name: "owned-node", kind: .native, host: "203.0.113.9", port: 443,
            adapterType: "vmess", parameters: ["uuid": "12345678-1234-1234-1234-1234567890ab"])
        func allowed(_ node: ProxyPolicy, _ nodes: [String: ProxyPolicy] = [:]) -> Bool {
            DNSProxyFallbackTransportPolicy.permits(.native(node, node.name), policies: nodes)
        }
        try expect(allowed(vmess), "VMess AEAD 默认安全配置被拒绝")
        try expect(!DNSProxyFallbackTransportPolicy.permits(.direct("DIRECT"), policies: [vmess.name: vmess])
                    && !DNSProxyFallbackTransportPolicy.permits(.reject("REJECT"), policies: [:]), "DIRECT/REJECT 意外准入")
        for (key, value) in [("cipher", "none"), ("cipher", "aes-128-cfb"), ("vmess-aead", "false"),
            ("alter-id", "1"), ("skip-cert-verify", "true"), ("skip-common-name-verify", "YES"),
            ("skip-cert-verify", " true "), ("skip-cert-verify", "t r u e"), ("tls", " false "),
            ("tls", "unknown"), ("server-cert-fingerprint-sha256", "unsupported-pin")] {
            var unsafe = vmess; unsafe.parameters[key] = value
            try expect(!allowed(unsafe), "不安全/模糊节点参数准入：\(key)")
        }
        var strictFalse = vmess; strictFalse.parameters["skip-cert-verify"] = "FALSE"
        try expect(allowed(strictFalse), "规范 false 标记被误拒绝")
        for type in ["http", "socks5", "vless", "trojan"] {
            var unsafe = vmess; unsafe.adapterType = type
            unsafe.parameters["tls"] = "false"; unsafe.parameters["password"] = "owned-secret"
            try expect(!allowed(unsafe), "无 TLS 明文协议意外准入")
        }
        for kind in [ProxyKind.http, .socks5] {
            var misleading = vmess; misleading.kind = kind
            try expect(!allowed(misleading), "HTTP/SOCKS 实际类型借用 adapter hint 授权了明文回退")
        }
        let http = ProxyPolicy(name: "clear-hop", kind: .http, host: "203.0.113.10", port: 8080)
        var chain = vmess; chain.parameters["underlying-proxy"] = http.name
        try expect(!allowed(chain, [http.name: http]), "代理链明文跳点意外准入")
        chain.parameters["underlying-proxy"] = "missing"
        try expect(!allowed(chain), "缺失代理链回落直连")
        chain.parameters["underlying-proxy"] = chain.name
        try expect(!allowed(chain, [chain.name: chain]), "代理链循环意外准入")
        chain.parameters["underlying-proxy"] = "DIRECT"
        try expect(allowed(chain), "加密节点的物理 DIRECT 终端被误当作 DNS 直连")
        try expect(DNSProxyFallbackBudget.encryptedWindow(remaining: 8, knownMilliseconds: []) == 3
                    && DNSProxyFallbackBudget.encryptedWindow(remaining: 8, knownMilliseconds: [5_000]) == 8
                    && DNSProxyFallbackBudget.encryptedWindow(remaining: 8, knownMilliseconds: [2_000]) == 3.75,
                    "回退预算盲截已知健康慢路径或延长总期限")
    }

    private static func phaseSafety() throws {
        for error in [EncryptedDNSQueryFailure.network, .timeout] {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start()
            fixture.encrypted[0].holdACK(); fixture.encrypted[0].fail(error); fixture.settle()
            try expect(fixture.fallback.isEmpty, "旧加密阶段取消 ACK 前启动普通 DNS")
            fixture.encrypted[0].acknowledge(); fixture.settle()
            try expect(fixture.fallback.count == 1 && fixture.fallback[0].query == fixture.query, "合格失败未保持原 DNS 查询")
            fixture.encrypted[0].reply(); fixture.settle()
            try expect(fixture.results.answers.isEmpty, "迟到加密应答越过阶段 token")
            fixture.fallback[0].reply(); fixture.settle()
            try expect(fixture.results.answers.count == 1 && fixture.results.errors.isEmpty,
                        "回退未恰好完成一次查询")
        }
        for error in [EncryptedDNSQueryFailure.cancelled, .capacity, .authentication, .policy,
                      .configuration, .invalidResponse, .other] {
            let fixture = Fixture(); defer { fixture.stop() }
            fixture.start(); fixture.encrypted[0].fail(error); fixture.settle()
            try expect(fixture.fallback.isEmpty && fixture.results.errors.count == 1, "非网络失败触发隐私降级")
        }
        for code in [UInt8(0), 3, 5, 2] {
            let fixture = Fixture(); defer { fixture.stop() }
            fixture.start(); fixture.encrypted[0].reply(code: code); fixture.settle()
            try expect(fixture.fallback.isEmpty && fixture.results.answers.count == 1, "合法 DNS 结果触发普通回退")
        }
        do {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start(); fixture.advance(103)
            try expect(fixture.fallback.count == 1, "确定无应答的阶段截止未启动安全回退")
            fixture.advance(108); fixture.fallback[0].reply(); fixture.settle()
            try expect(fixture.results.answers.isEmpty && fixture.results.errors.count == 1,
                        "回退重启八秒预算或接纳截止后应答")
        }
        do {
            let fixture = Fixture(fallbackServerCount: 3); defer { fixture.stop() }; fixture.start()
            fixture.encrypted[0].holdACK(); fixture.advance(103)
            try expect(fixture.fallback.isEmpty, "冷启动回退绕过加密阶段取消 ACK")
            fixture.encrypted[0].acknowledge(); fixture.settle()
            try expect(fixture.fallback.count == 1, "三秒加密无应答后未启动批准的普通 DNS")
            let first = fixture.fallback[0]
            // The old equal share expired at 104.667, before a realistic
            // 2.7s proxy setup and DNS exchange could complete at 105.7.
            fixture.advance(104.7)
            try expect(fixture.fallback.count == 1 && first.cancelCount == 0,
                        "多个批准服务器把冷启动代理隧道预算切得过短")
            fixture.advance(105.7); first.reply(); fixture.settle()
            let snapshot = fixture.diagnostics.snapshot()
            try expect(fixture.results.answers.count == 1 && fixture.results.errors.isEmpty
                        && fixture.fallback.count == 1 && snapshot.dnsProxyFallbackSuccesses == 1,
                        "三秒加密黑洞后的健康 2.7 秒普通 DNS 未在原八秒期限内成功")
            fixture.advance(108); first.reply(); fixture.settle()
            try expect(fixture.results.answers.count == 1 && fixture.results.errors.isEmpty,
                        "冷启动回退成功后原期限或迟到应答重复完成")
        }
        do {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.observe(5_000); fixture.start(); fixture.advance(103)
            try expect(fixture.fallback.isEmpty, "健康慢加密路径被固定三秒截断")
            fixture.encrypted[0].reply(); fixture.settle()
            try expect(fixture.results.answers.count == 1, "健康加密响应丢失")
        }
        do {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start(); fixture.observe(5_000); fixture.advance(103)
            try expect(fixture.fallback.isEmpty, "在途新健康观测未延长加密阶段")
            fixture.flow.cancel(); fixture.settle()
        }
        for blocked in [EncryptedDNSQueryFailure.authentication, .other, .capacity] {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start(); fixture.encrypted[0].holdACK(); fixture.advance(103)
            fixture.encrypted[0].setBarrier(.failure(blocked)); fixture.encrypted[0].acknowledge(); fixture.settle()
            try expect(fixture.fallback.isEmpty && fixture.results.errors.count == 1, "ACK 后私有 barrier 被阶段超时吞掉")
        }
        do {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start()
            let negative = DNSMessageInspection.errorResponse(to: fixture.query, code: .servfail)!
            fixture.encrypted[0].setBarrier(.answer(negative)); fixture.advance(103)
            try expect(fixture.fallback.isEmpty, "合法 SERVFAIL barrier 被阶段超时吞掉")
            fixture.encrypted[0].fail(EncryptedDNSQueryFailure.timeout); fixture.settle()
            try expect(fixture.results.answers == [negative] && fixture.fallback.isEmpty, "候选 timeout 擦除合法负答 barrier")
        }
        do {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start(); fixture.encrypted[0].holdACK(); fixture.advance(103)
            fixture.revoke(); fixture.encrypted[0].acknowledge(); fixture.settle()
            try expect(fixture.fallback.isEmpty, "配置/接口代际撤销后仍启动回退")
        }
        do {
            let fixture = Fixture(); defer { fixture.stop() }; fixture.start(); fixture.encrypted[0].holdACK(); fixture.advance(103)
            fixture.flow.cancel(); fixture.encrypted[0].acknowledge(); fixture.settle()
            try expect(fixture.fallback.isEmpty && fixture.results.answers.isEmpty, "取消/迟到 ACK 启动回退")
        }
        do {
            let fixture = Fixture(); defer { fixture.stop() }
            fixture.start(); fixture.encrypted[0].fail(EncryptedDNSQueryFailure.network); fixture.settle()
            var wrong = DNSMessageInspection.errorResponse(to: fixture.query, code: .servfail)!
            wrong[3] = wrong[3] & 0xf0
            wrong[0] ^= 1; fixture.fallback[0].reply(wrong); fixture.settle()
            try expect(fixture.results.answers.isEmpty && fixture.results.errors.count == 1,
                        "错误 DNS ID 回退响应被接纳")
        }
    }

    private static func resolverSequenceSafety() throws {
        do {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.start()
            let first = fixture.transports[0]; first.holdACK(); first.fail(EncryptedDNSQueryFailure.network); fixture.settle()
            try expect(fixture.attempts.count == 1, "普通 DNS 未等旧查询取消 ACK 就并行拨号")
            first.acknowledge(); fixture.settle()
            try expect(fixture.attempts.map { $0.0 } == fixture.servers && fixture.transports[1].query == fixture.query
                        && fixture.attempts[1].1 == 108, "普通 DNS 备用没有保持批准列表、原问题或父期限")
            first.reply(); fixture.settle()
            try expect(fixture.results.answers.isEmpty, "已撤销普通 DNS 的迟到答复越过 attempt token")
            fixture.transports[1].reply(); fixture.settle()
            try expect(fixture.results.answers.count == 1 && fixture.results.errors.isEmpty
                        && fixture.diagnostics.snapshot().dnsUpstreamAttempts == 2
                        && fixture.diagnostics.snapshot().dnsFailovers == 1
                        && fixture.preferred == fixture.servers[1], "备用成功未恰好交付一次或未避开失败首选")
        }
        do {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.start()
            fixture.transports[0].holdACK(); fixture.advance(104)
            try expect(fixture.attempts.count == 1 && fixture.attempts[0].1 == 104, "坏首选未预留备用预算或越过取消栅栏")
            fixture.transports[0].acknowledge(); fixture.settle()
            try expect(fixture.attempts.count == 2 && fixture.attempts[1].1 == 108, "首选无应答耗尽所有备用时间")
            fixture.transports[1].reply(); fixture.settle()
            try expect(fixture.results.answers.count == 1, "分段预算备用应答丢失")
        }
        for blocked in [EncryptedDNSQueryFailure.capacity, .authentication, .policy, .configuration,
                        .invalidResponse, .other, .cancelled] {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.start()
            fixture.transports[0].fail(blocked); fixture.settle()
            try expect(fixture.attempts.count == 1 && fixture.results.errors.count == 1
                        && fixture.results.answers.isEmpty && fixture.preferred == fixture.servers[0],
                        "认证/策略/容量/无效或未知错误触发备用或污染健康排序")
        }
        for code in [UInt8(0), 3, 5, 2] {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.start()
            fixture.transports[0].reply(code: code); fixture.settle()
            try expect(fixture.attempts.count == 1 && fixture.results.answers.count == 1,
                        "合法普通 DNS 否定答复被跨解析器重试")
        }
        for negative in [false, true] {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.start()
            let first = fixture.transports[0]; first.holdACK(); first.fail(EncryptedDNSQueryFailure.timeout); fixture.settle()
            if negative { first.setBarrier(.answer(DNSMessageInspection.errorResponse(to: fixture.query, code: .refused)!)) }
            else { first.setBarrier(.failure(EncryptedDNSQueryFailure.authentication)) }
            first.acknowledge(); fixture.settle()
            try expect(fixture.attempts.count == 1
                        && (negative ? fixture.results.answers.count == 1 : fixture.results.errors.count == 1)
                        && fixture.preferred == fixture.servers[0],
                        "取消 ACK 前的晚到认证/否定 barrier 被备用擦除")
        }
        for ending in 0..<3 {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.start()
            let first = fixture.transports[0]; first.holdACK(); fixture.advance(104)
            if ending == 0 { fixture.advance(108) }
            else if ending == 1 { fixture.revoke() }
            else { fixture.flow.cancel(); fixture.settle() }
            first.acknowledge(); fixture.settle()
            try expect(fixture.attempts.count == 1 && fixture.results.answers.isEmpty
                        && (ending == 2 ? fixture.results.errors.isEmpty : fixture.results.errors.count == 1),
                        "截止/策略撤销/取消后晚 ACK 仍启动普通 DNS 备用")
        }
        do {
            let fixture = SequenceFixture(count: 8); defer { fixture.stop() }; fixture.start()
            for index in 0..<3 { fixture.transports[index].fail(EncryptedDNSQueryFailure.network); fixture.settle() }
            try expect(fixture.attempts.count == 3 && fixture.results.errors.count == 1,
                        "普通 DNS failover 超过三个有限尝试或重复失败交付")
        }
        do {
            let fixture = SequenceFixture(count: 3); defer { fixture.stop() }
            fixture.clock.set(106); fixture.start()
            try expect(fixture.attempts.count == 1 && fixture.attempts[0].1 == 108,
                        "冷启动最短拨号窗口延长了剩余不足三秒的父期限")
            fixture.advance(108); fixture.transports[0].reply(); fixture.settle()
            try expect(fixture.attempts.count == 1 && fixture.results.answers.isEmpty
                        && fixture.results.errors.count == 1,
                        "冷启动最短拨号窗口在总截止后继续重试或接纳答复")
        }
        do {
            let fixture = SequenceFixture(count: 3); defer { fixture.stop() }
            fixture.observe([20, 30, 40]); fixture.clock.set(103); fixture.start()
            let first = fixture.transports[0]; first.holdACK(); fixture.advance(104.8)
            try expect(first.cancelCount == 1 && fixture.attempts.count == 1,
                        "已知快速服务器黑洞时沿用冷启动三秒下限或越过取消 ACK")
            first.acknowledge(); fixture.settle()
            try expect(fixture.attempts.count == 2,
                        "已知快速服务器失联后未及时尝试批准的备用")
            fixture.transports[1].reply(); fixture.settle()
            try expect(fixture.results.answers.count == 1 && fixture.results.errors.isEmpty,
                        "已知快速服务器失联后的正常备用应答丢失")
        }
        do {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.observe([5_000, 7_000]); fixture.start()
            fixture.advance(104)
            try expect(fixture.attempts.count == 1 && fixture.attempts[0].1 == 108,
                        "已知健康慢普通 DNS 被固定分段预算截断")
            fixture.transports[0].reply(); fixture.settle()
            try expect(fixture.results.answers.count == 1, "健康慢普通 DNS 答复丢失")
        }
        do {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.observe([1_000, 20]); fixture.start()
            try expect(fixture.attempts[0].0 == fixture.servers[1], "代理内回退始终固定首个服务器")
            var invalid = DNSMessageInspection.errorResponse(to: fixture.query, code: .servfail)!
            invalid[0] ^= 1; fixture.transports[0].reply(invalid); fixture.settle()
            try expect(fixture.results.errors.count == 1 && fixture.results.answers.isEmpty && fixture.attempts.count == 1,
                        "普通 DNS 备用接纳错误 ID 或在无效响应后继续查询")
        }
        do {
            let fixture = SequenceFixture(); defer { fixture.stop() }; fixture.start()
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            fixture.flow.enqueueForSelfTest { entered.signal(); _ = release.wait(timeout: .now() + 2) }
            try expect(entered.wait(timeout: .now() + 1) == .success, "普通 DNS 取消/timer 栅栏未启动")
            fixture.clock.set(108); fixture.timers.fire(); fixture.flow.cancel()
            release.signal(); fixture.settle()
            try expect(fixture.results.answers.isEmpty && fixture.results.errors.isEmpty && fixture.attempts.count == 1,
                        "已排队 overall timer 越过同步取消仍交付失败")
        }
    }
}

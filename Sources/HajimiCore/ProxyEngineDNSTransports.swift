import Foundation
import HajimiDNS
import Network
import Security
import Darwin
import HajimiProxyRuntime
import HajimiCXXProtocolBridge

public enum UDPPrivacyPolicySelfTest {
    public static func failure() -> String? {
        let secureSOCKS = ProxyPolicy(name: "SecureSOCKS", kind: .socks5,
            host: "127.0.0.1", port: 443, parameters: ["tls": "true"])
        let secureHTTP = ProxyPolicy(name: "SecureHTTP", kind: .http,
            host: "127.0.0.1", port: 443, parameters: ["tls": "true"])
        let unsafeFlag = ProxyPolicy(name: "Invalid", kind: .socks5,
            host: "127.0.0.1", port: 443, parameters: ["tls": "unexpected"])
        let secureAlias = ProxyPolicy(name: "SecureAlias", kind: .socks5,
            host: "127.0.0.1", port: 443, adapterType: "socks5-tls")
        let contradictoryAlias = ProxyPolicy(name: "ContradictoryAlias", kind: .http,
            host: "127.0.0.1", port: 443, adapterType: "https", parameters: ["tls": "false"])
        let chainedTLS = ProxyPolicy(name: "ChainedTLS", kind: .native,
            host: "127.0.0.1", port: 443, adapterType: "socks5",
            parameters: ["tls": "true", "underlying-proxy": "Hop"])
        for route in [ResolvedRoute.socks5(secureSOCKS, secureSOCKS.name),
                      .http(secureHTTP, secureHTTP.name),
                      .socks5(unsafeFlag, unsafeFlag.name),
                      .socks5(secureAlias, secureAlias.name),
                      .http(contradictoryAlias, contradictoryAlias.name),
                      .native(chainedTLS, chainedTLS.name)] {
            guard case .reject = safeSOCKSUDPRoute(route, destinationPort: 53) else {
                return "TLS SOCKS/HTTPS UDP DNS must never fall back to DIRECT"
            }
        }
        guard case .direct = safeSOCKSUDPRoute(.direct("DIRECT"), destinationPort: 53) else {
            return "explicit DIRECT DNS route was unexpectedly rejected"
        }
        for port in [UInt16(53), UInt16(443)] {
            guard case .reject("DNS blocked") = safeSOCKSUDPRoute(.reject("DNS blocked"), destinationPort: port),
                  case .reject("DNS blocked") = safeTCPDNSRoute(.reject("DNS blocked"), destinationPort: port) else {
                return "an explicit REJECT must survive TCP and SOCKS UDP DNS compatibility routing"
            }
        }
        guard case .socks5 = safeTCPDNSRoute(.socks5(secureSOCKS, secureSOCKS.name), destinationPort: 53),
              case .direct = safeTCPDNSRoute(.direct("DIRECT"), destinationPort: 53) else {
            return "TCP DNS must preserve its TLS route and explicit DIRECT compatibility"
        }
        guard case .socks5 = safeSOCKSUDPRoute(.socks5(secureSOCKS, secureSOCKS.name),
                                              destinationPort: 443) else {
            return "non-DNS SOCKS route was incorrectly rewritten"
        }
        let plainSOCKS = ProxyPolicy(name: "PlainSOCKS", kind: .socks5,
                                    host: "127.0.0.1", port: 1080)
        let native = ProxyPolicy(name: "Native", kind: .native, host: "127.0.0.1", port: 443,
                                 adapterType: "trojan", parameters: ["password": "test"])
        for selected in [ResolvedRoute.socks5(plainSOCKS, plainSOCKS.name), .native(native, native.name)] {
            guard safeSOCKSUDPRoute(selected, destinationPort: 53) == selected,
                  safeTCPDNSRoute(selected, destinationPort: 53) == selected else {
                return "DNS compatibility routing bypassed the selected proxy"
            }
        }
        return nil
    }
}

/// A socket may carry questions for many unrelated names. Select and validate
/// the policy for each DNS message, never once per DNS server/association.
final class PolicyDNSDatagram: NativeRoutedDatagram {
    struct Transaction {
        let query: Data
        let generation: UInt64
        let reservation: SOCKSUDPReservation
        let connectionReservation: SOCKSUDPReservation
        var transport: NativeRoutedDatagram?
        var timeout: DispatchWorkItem?
    }
    let router: NativePacketRouter
    let original: RequestTarget
    let queue: DispatchQueue
    let queueSpecificKey = DispatchSpecificKey<Bool>()
    let queryTimeout: DispatchTimeInterval
    let upstreamFactory: DNSQueryCoordinator.Factory?
    let synthesizeFakeIP: Bool
    let receiveHandler: (Data) -> Void
    let failureHandler: (Error) -> Void
    let admission = NSLock()
    let resource: SOCKSUDPReservation
    var closed = false
    var admittedPackets = 0, admittedBytes = 0
    var transactions: [UUID: Transaction] = [:]
    var fakeIPSynthesisEnabled: Bool { synthesizeFakeIP }

    // Short deadlines and the factory override are private memory-test inputs;
    // routed application callers keep the eight-second verified defaults.
    init(router: NativePacketRouter, original: RequestTarget, queue: DispatchQueue,
         synthesizeFakeIP: Bool, receive: @escaping (Data) -> Void,
         failure: @escaping (Error) -> Void,
         queryTimeout: DispatchTimeInterval = .seconds(8),
         upstreamFactory: DNSQueryCoordinator.Factory? = nil) throws {
        guard let resource = SOCKSUDPResourceLimits.shared.reserveResource() else {
            throw EngineError("DNS 会话资源已达上限")
        }
        self.router = router; self.original = original; self.synthesizeFakeIP = synthesizeFakeIP
        self.queue = DispatchQueue(label: "app.hajimi.dns.query-policy", target: queue)
        self.queryTimeout = queryTimeout; self.upstreamFactory = upstreamFactory
        self.resource = resource; receiveHandler = receive; failureHandler = failure
        self.queue.setSpecific(key: queueSpecificKey, value: true)
    }

    func send(_ data: Data) {
        admission.lock(); let stopped = closed; admission.unlock()
        guard !stopped else { return }
        let queryDeadline = Self.timeoutSeconds(queryTimeout).map {
            ProcessInfo.processInfo.systemUptime + $0
        }
        let prepared: DNSQueryPreparation
        do {
            prepared = try router.prepareDNSQuery(data, original: original,
                                                  synthesizeFakeIP: synthesizeFakeIP)
        } catch {
            let code = (error as? DNSPolicyFailure)?.responseCode ?? .servfail
            if let answer = DNSMessageInspection.errorResponse(to: data, code: code) { deliver(answer) }
            return
        }
        switch prepared {
        case .answer(let answer, let generation):
            deliverLocalAnswer(answer, query: data, generation: generation)
        case .upstream(let plan):
            admission.lock()
            guard !closed, admittedPackets < 64, data.count <= 256 * 1_024 - admittedBytes,
                  let leases = DNSQueryResourceBudget.reserve(bytes: data.count) else {
                admission.unlock()
                if let answer = DNSMessageInspection.errorResponse(to: data, code: .servfail) { deliver(answer) }
                return
            }
            admittedPackets += 1; admittedBytes += data.count; admission.unlock()
            let id = UUID()
            queue.async {
                self.admission.lock(); let stopped = self.closed; self.admission.unlock()
                guard !stopped else {
                    self.release(data.count); leases.payload.release(); leases.connection.release(); return
                }
                guard self.router.isCurrentDNSGenerationForInternal(plan.generation) else {
                    self.release(data.count); leases.payload.release(); leases.connection.release()
                    if let reply = DNSMessageInspection.errorResponse(to: data, code: .servfail) { self.deliver(reply) }
                    return
                }
                self.transactions[id] = Transaction(query: data, generation: plan.generation,
                                                    reservation: leases.payload,
                                                    connectionReservation: leases.connection)
                // Share one monotonic budget with delayed coordinator/adaptive
                // work; a later child queue must not receive a fresh eight seconds.
                let timeout = DispatchWorkItem { [weak self] in
                    self?.finish(id, answer: nil, deadlineExpired: true)
                }
                self.transactions[id]?.timeout = timeout
                let remaining = queryDeadline.map { max(0, $0 - ProcessInfo.processInfo.systemUptime) }
                self.queue.asyncAfter(deadline: remaining.map { .now() + $0 } ?? .distantFuture, execute: timeout)
                do {
                    let transport = try self.router.makeOptimizedDNSUpstream(plan: plan, queue: self.queue,
                        factory: self.upstreamFactory,
                        queryDeadline: queryDeadline,
                        receive: { [weak self] answer in self?.finishOnQueue(id, answer: answer) },
                        failure: { [weak self] _ in self?.finishOnQueue(id, answer: nil) })
                    self.transactions[id]?.transport = transport
                    let adaptedQuery = DNSProtocolRouterAdapter.adaptOutboundDNSQuery(data, for: plan.route)
                    transport.send(adaptedQuery)
                } catch { self.finish(id, answer: nil) }
            }
        }
    }

    static func timeoutSeconds(_ interval: DispatchTimeInterval) -> TimeInterval? {
        let seconds: TimeInterval
        switch interval {
        case .seconds(let value): seconds = Double(value)
        case .milliseconds(let value): seconds = Double(value) / 1_000
        case .microseconds(let value): seconds = Double(value) / 1_000_000
        case .nanoseconds(let value): seconds = Double(value) / 1_000_000_000
        case .never: return nil // Only the private fixture can disable its parent timer.
        @unknown default: return 0
        }
        return max(0, seconds)
    }

    func finishOnQueue(_ id: UUID, answer: Data?) {
        // A coalesced lease already delivers on a queue targeting this serial
        // policy queue. A second hop can put an earlier queued answer behind
        // an elapsed timer. Foreign-thread callbacks still need dispatch.
        if DispatchQueue.getSpecific(key: queueSpecificKey) == true {
            finish(id, answer: answer)
        } else {
            queue.async { [weak self] in self?.finish(id, answer: answer) }
        }
    }

    func finish(_ id: UUID, answer: Data?, deadlineExpired: Bool = false) {
        guard let transaction = transactions.removeValue(forKey: id) else { return }
        transaction.timeout?.cancel()
        if deadlineExpired, let timed = transaction.transport as? any DNSQueryDeadlineAwareDatagram {
            timed.queryDeadlineReached()
        } else { transaction.transport?.cancel() }
        transaction.reservation.release(); transaction.connectionReservation.release()
        release(transaction.query.count)
        let accepted = answer.flatMap { reply -> Data? in
            guard router.isCurrentDNSGenerationForInternal(transaction.generation),
                  DNSMessageInspection.responseMatchesQuery(reply, query: transaction.query) else { return nil }
            return reply
        }
        if let response = accepted ?? DNSMessageInspection.errorResponse(to: transaction.query, code: .servfail) {
            deliver(response)
        }
    }

    func release(_ count: Int) {
        admission.lock(); admittedPackets -= 1; admittedBytes -= count; admission.unlock()
    }

    func deliver(_ response: Data) {
        admission.lock(); let stopped = closed; admission.unlock()
        if !stopped { receiveHandler(response) }
    }

    func deliverLocalAnswer(_ answer: Data, query: Data, generation: UInt64) {
        let work = { [self] in
            admission.lock(); let stopped = closed; admission.unlock()
            guard !stopped else { return }
            // A synthetic/FORMERR answer has no upstream transaction whose
            // finish path checks the epoch. Check at the actual owner-queue
            // handoff, not before enqueueing: reload/flush may run meanwhile.
            // isCurrentDNSGeneration releases its lock before user callbacks.
            let response = router.isCurrentDNSGenerationForInternal(generation)
                ? answer : DNSMessageInspection.errorResponse(to: query, code: .servfail)
            if let response { deliver(response) }
        }
        if DispatchQueue.getSpecific(key: queueSpecificKey) == true { work() }
        else { queue.async(execute: work) }
    }

    func invalidateForPolicyUpdate() {
        queue.async {
            // The association survives an epoch transition. A new question
            // may already be queued here; only revoke its stale transactions.
            for (id, transaction) in Array(self.transactions)
                where !self.router.isCurrentDNSGenerationForInternal(transaction.generation) {
                self.finish(id, answer: nil)
            }
        }
    }

    func cancel() {
        admission.lock(); closed = true; admission.unlock()
        queue.async {
            for transaction in self.transactions.values {
                transaction.timeout?.cancel(); transaction.transport?.cancel()
                transaction.reservation.release(); transaction.connectionReservation.release()
                self.release(transaction.query.count)
            }
            self.transactions.removeAll(); self.resource.release()
        }
    }

    deinit {
        transactions.values.forEach { $0.timeout?.cancel(); $0.transport?.cancel() }
        resource.release()
    }
}

extension PolicyDNSDatagram {
    func drainQueueForSelfTest() { queue.sync {} }
    func activeTransactionForSelfTest() -> UUID? { queue.sync { transactions.keys.first } }
    func completeFromAnyThreadForSelfTest(_ id: UUID, answer: Data?) { finishOnQueue(id, answer: answer) }
    static func timeoutSecondsForSelfTest(_ interval: DispatchTimeInterval) -> TimeInterval? { timeoutSeconds(interval) }
}

/// Real policy/coordinator/lease callbacks over memory-only transports. The
/// short parent deadline preserves the production eight-second ordering race
/// without occupying a test process for eight seconds per boundary case.
enum PolicyDNSCallbackQueueSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS 回调队列自检失败：\(text)" }
    }
    private static func expect(_ condition: Bool, _ text: String) throws {
        guard condition else { throw Failure(text: text) }
    }
    private static func wait(_ semaphore: DispatchSemaphore, _ text: String) throws {
        try expect(semaphore.wait(timeout: .now() + 2) == .success, text)
    }

    final class MemoryTransport: NativeRoutedDatagram {
        let sent = DispatchSemaphore(value: 0), canceled = DispatchSemaphore(value: 0)
        let processed = DispatchSemaphore(value: 0)
        let queue: DispatchQueue
        let receive: (Data) -> Void
        let lock = NSLock()
        var question: Data?
        var cancels = 0
        init(queue: DispatchQueue, receive: @escaping (Data) -> Void) {
            self.queue = queue; self.receive = receive
        }
        func send(_ data: Data) { lock.lock(); question = data; lock.unlock(); sent.signal() }
        func cancel() {
            lock.lock(); cancels += 1; let first = cancels == 1; lock.unlock()
            if first { canceled.signal() }
        }
        var cancelCount: Int { lock.lock(); defer { lock.unlock() }; return cancels }
        func answer(wrongID: Bool = false) -> Data {
            lock.lock(); var answer = question!; lock.unlock()
            answer[2] = 0x81; answer[3] = 0x80
            for index in 6...11 { answer[index] = 0 }
            if wrongID { answer[1] ^= 1 }
            return answer
        }
        func reply(wrongID: Bool = false) {
            // Deliberately allow late/duplicate callbacks after cancellation.
            receive(answer(wrongID: wrongID))
            // The factory's queue is the real coordinator queue. Its finish
            // is enqueued by receive() before this acknowledgment barrier.
            queue.async { self.processed.signal() }
        }
    }
    final class Broker {
        let offered = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var value: MemoryTransport?
        var transport: MemoryTransport { lock.lock(); defer { lock.unlock() }; return value! }
        var factory: DNSQueryCoordinator.Factory {
            { queue, receive, _ in
                let transport = MemoryTransport(queue: queue, receive: receive)
                self.lock.lock(); self.value = transport; self.lock.unlock()
                self.offered.signal()
                return transport
            }
        }
    }
    final class Responses {
        let received = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var answers: [Data] = []
        var failures = 0
        func receive(_ answer: Data) { lock.lock(); answers.append(answer); lock.unlock(); received.signal() }
        func fail(_ error: Error) { lock.lock(); failures += 1; lock.unlock(); received.signal() }
        var snapshot: (answers: [Data], failures: Int) {
            lock.lock(); defer { lock.unlock() }; return (answers, failures)
        }
    }
    final class Fixture {
        let parent = DispatchQueue(label: "app.hajimi.dns.policy-callback-self-test.parent")
        let broker = Broker(), responses = Responses()
        let profile: Profile
        let router: NativePacketRouter
        let flow: PolicyDNSDatagram
        let query: Data
        init(localAnswers: Bool = false) throws {
            var profile = Profile()
            profile.fakeIPEnabled = localAnswers
            // An omitted test override could only target a closed loopback
            // port; it cannot cause a public resolver/system DNS fallback.
            profile.encryptedDNSServers = ["https://127.0.0.1:1/dns-query"]
            profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
            if localAnswers {
                let node = ProxyPolicy(name: "MemoryNode", kind: .native, host: "127.0.0.1", port: 1,
                    adapterType: "trojan", parameters: ["password": "memory-only"])
                profile.proxies[node.name] = node
                profile.rules[0] = RoutingRule(kind: .final, policy: node.name, sourceLine: 1)
            }
            self.profile = profile
            query = DNSMessageInspection.query(for: "callback-policy.selftest.invalid",
                                               type: localAnswers ? 1 : 28, id: 0x4101)!
            router = NativePacketRouter(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            flow = try PolicyDNSDatagram(router: router,
                original: RequestTarget(host: "127.0.0.1", port: 53, protocolName: "UDP"), queue: parent,
                synthesizeFakeIP: localAnswers, receive: responses.receive, failure: responses.fail,
                queryTimeout: .milliseconds(150), upstreamFactory: broker.factory)
        }
        func start() throws {
            flow.send(query)
            try wait(broker.offered, "未进入内存工厂")
            try wait(broker.transport.sent, "真实 coordinator/lease 未发送查询")
        }
        func stop() { flow.cancel(); flow.drainQueueForSelfTest(); parent.sync {} }
        func requireOneResponse(_ code: UInt8, _ text: String) throws {
            try wait(responses.received, text)
            flow.drainQueueForSelfTest(); parent.sync {}
            let values = responses.snapshot
            try expect(values.failures == 0 && values.answers.count == 1
                       && DNSMessageInspection.responseMatchesQuery(values.answers[0], query: query)
                       && values.answers[0][3] & 0x0f == code, text)
        }
        func requireNoFurtherResponse(_ text: String) throws {
            try expect(responses.received.wait(timeout: .now() + .milliseconds(180)) == .timedOut, text)
        }
    }

    static func run() throws {
        try expect(PolicyDNSDatagram.timeoutSecondsForSelfTest(.seconds(8)) == 8
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.milliseconds(150)) == 0.15
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.microseconds(150_000)) == 0.15
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.nanoseconds(150_000_000)) == 0.15
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.seconds(-1)) == 0
                   && PolicyDNSDatagram.timeoutSecondsForSelfTest(.never) == nil,
                   "绝对预算单位换算、负预算或 private never 语义错误")
        // Local replies have no coordinator transaction. Hold their actual
        // delivery queue while an epoch changes; neither a cached route nor a
        // precomputed FakeIP answer may survive that handoff unchecked.
        for change in 0..<3 {
            let fixture = try Fixture(localAnswers: true)
            let blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal(); fixture.stop() }
            fixture.parent.async { blocked.signal(); _ = release.wait(timeout: .now() + 2) }
            try wait(blocked, "本地合成答复未能阻塞实际交付队列")
            fixture.flow.send(fixture.query)
            try expect(fixture.responses.received.wait(timeout: .now() + .milliseconds(20)) == .timedOut,
                       "本地合成答复绕过 owner 队列提前交付")
            if change == 1 {
                var rejected = fixture.profile
                rejected.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)]
                fixture.router.update(profile: rejected, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            } else if change == 2 { fixture.router.flushDNS() }
            release.signal()
            try fixture.requireOneResponse(change == 0 ? 0 : 2,
                "本地合成答复跨 epoch 交付旧地址或没有返回 SERVFAIL")
            let records = DNSMessageInspection.addressAnswers(in: fixture.responses.snapshot.answers[0])
            if change == 0 {
                try expect(records.count == 1 && IPCIDR.contains(records[0].address, cidr: "198.19.0.0/16"),
                           "未变化 epoch 的合成答复丢失 FakeIP")
            } else { try expect(records.isEmpty, "过期本地答复仍泄露旧合成地址") }
            try expect(fixture.broker.offered.wait(timeout: .now()) == .timedOut,
                       "本地 epoch 检查意外启动了上游工厂")
            try fixture.requireNoFurtherResponse("本地答复重复交付或由计时器复活")
        }
        for shouldFlush in [false, true] {
            let fixture = try Fixture(localAnswers: true)
            let blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal(); fixture.stop() }
            var malformed = fixture.query
            malformed[4] = 0; malformed[5] = 2 // Two questions declared, only one supplied.
            fixture.parent.async { blocked.signal(); _ = release.wait(timeout: .now() + 2) }
            try wait(blocked, "FORMERR 答复未能阻塞实际交付队列")
            fixture.flow.send(malformed)
            try expect(fixture.responses.received.wait(timeout: .now() + .milliseconds(20)) == .timedOut,
                       "FORMERR 答复绕过 owner 队列")
            if shouldFlush { fixture.router.flushDNS() }
            release.signal()
            try wait(fixture.responses.received, "FORMERR/过期 SERVFAIL 未交付，形成静默超时")
            fixture.flow.drainQueueForSelfTest(); fixture.parent.sync {}
            let responses = fixture.responses.snapshot
            let expectedCode: UInt8 = shouldFlush ? 2 : 1
            try expect(responses.failures == 0 && responses.answers.count == 1
                       && responses.answers[0].count >= 12
                       && responses.answers[0][0] == malformed[0] && responses.answers[0][1] == malformed[1]
                       && responses.answers[0][3] & 0x0f == expectedCode,
                       "FORMERR 未保留 epoch/ID 或过期时没有改为 SERVFAIL")
            try expect(fixture.broker.offered.wait(timeout: .now()) == .timedOut,
                       "FORMERR epoch 回归意外启动上游工厂")
            try fixture.requireNoFurtherResponse("FORMERR/过期 SERVFAIL 被重复交付")
        }
        // The reply is accepted before the deadline, then held on the lease's
        // parent/target queue past expiry. The old second hop returned SERVFAIL.
        do {
            let fixture = try Fixture(), blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal(); fixture.stop() }
            try fixture.start()
            fixture.parent.async { blocked.signal(); _ = release.wait(timeout: .now() + 2) }
            try wait(blocked, "target 队列未进入受控排队")
            fixture.broker.transport.reply()
            try wait(fixture.broker.transport.processed, "deadline 前答复未被 coordinator 接受")
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(300)) { release.signal() }
            try fixture.requireOneResponse(0, "target 队列已有答复被第二次 dispatch 的 timeout 越过")
            try fixture.requireNoFurtherResponse("已完成答复被 parent timer 重复完成")
        }
        // Calls from unrelated threads must not mutate policy state off queue.
        do {
            let fixture = try Fixture(), blocked = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal(); fixture.stop() }
            try fixture.start()
            guard let id = fixture.flow.activeTransactionForSelfTest() else { throw Failure(text: "无活动事务") }
            let answer = fixture.broker.transport.answer()
            fixture.parent.async { blocked.signal(); _ = release.wait(timeout: .now() + 2) }
            try wait(blocked, "任意线程负测未阻塞 owner 队列")
            fixture.flow.completeFromAnyThreadForSelfTest(id, answer: answer)
            try expect(fixture.responses.received.wait(timeout: .now() + .milliseconds(20)) == .timedOut,
                       "任意线程绕过了 owner 队列")
            release.signal()
            try fixture.requireOneResponse(0, "任意线程答复没有经串行 owner 交付")
            try fixture.requireNoFurtherResponse("任意线程完成后计时器重复回包")
        }
        // An answer that really arrives after the parent timeout stays rejected.
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start()
            try fixture.requireOneResponse(2, "真正迟到的查询没有按原截止时间返回 SERVFAIL")
            fixture.broker.transport.reply()
            try wait(fixture.broker.transport.processed, "迟到答复未进入 token 校验")
            try fixture.requireNoFurtherResponse("真正超时后迟到答复复活了事务")
        }
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start(); fixture.flow.cancel()
            try wait(fixture.broker.transport.canceled, "普通取消未关闭自己的 transport")
            fixture.broker.transport.reply()
            try wait(fixture.broker.transport.processed, "已取消事务的迟到回调未抵达")
            try fixture.requireNoFurtherResponse("取消后的答复或 timer 仍向客户端回包")
            try expect(fixture.responses.snapshot.answers.isEmpty && fixture.broker.transport.cancelCount == 1,
                       "普通取消被复活或重复取消下层")
        }
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start()
            fixture.router.update(profile: fixture.profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            fixture.flow.invalidateForPolicyUpdate()
            try fixture.requireOneResponse(2, "epoch 更新未撤销旧策略事务")
            fixture.broker.transport.reply()
            try wait(fixture.broker.transport.processed, "旧 epoch 答复未进入 token 校验")
            try fixture.requireNoFurtherResponse("旧 epoch 答复被重新交付")
        }
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start(); fixture.broker.transport.reply(); fixture.broker.transport.reply()
            try fixture.requireOneResponse(0, "重复 callback 丢失合法首答复")
            try fixture.requireNoFurtherResponse("重复 callback 或 timer 产生第二个答复")
            try expect(fixture.broker.transport.cancelCount == 1, "重复 callback 多次取消同一 transport")
        }
        do {
            let fixture = try Fixture(); defer { fixture.stop() }
            try fixture.start(); fixture.broker.transport.reply(wrongID: true)
            try fixture.requireOneResponse(2, "错 ID 答复被 inline 路径接纳")
            try fixture.requireNoFurtherResponse("错 ID 事务被 timer 重复完成")
        }
        print("DNS policy callback queue checks passed: local answer epochs, target handoff, foreign-thread dispatch, genuine timeout, cancellation, epoch, duplicate callbacks and wrong ID")
    }
}

/// An intercepted datagram can now create a TCP/TLS transaction. Reserve a
/// process-wide connection slot as well as wire bytes before dispatching it;
/// the larger packet budget alone must not authorize thousands of sockets.
/// Both leases survive until that logical query completes or is cancelled.
enum DNSQueryResourceBudget {
    static func reserve(bytes: Int, budget: SOCKSUDPGlobalBudget = SOCKSUDPResourceLimits.shared)
        -> (payload: SOCKSUDPReservation, connection: SOCKSUDPReservation)? {
        guard let connection = budget.reserveResource() else { return nil }
        guard let payload = budget.reservePacket(bytes: bytes) else { connection.release(); return nil }
        return (payload, connection)
    }
}

/// The only input to traditional DNS is the configured DoH service hostname.
/// Retain the application query locally until a numeric, policy-approved dial
/// address is available; failures never forward that query to a plain server.
final class DoHBootstrapDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding, DNSConnectionPrewarming, DNSQueryExecutionContextAccepting {
    let endpoint: DoHEndpoint
    let resolver: TraditionalDNSBootstrapResolver
    let queue: DispatchQueue
    let permitted: () -> Bool
    let makeEncrypted: (String) throws -> NativeRoutedDatagram
    let failure: (Error) -> Void
    let admission = NSLock()
    var closed = false, started = false
    var cancellationReason: DNSAttemptCancellationReason?
    var executionContext: DNSQueryExecutionContext?
    var request: UUID?
    var encrypted: NativeRoutedDatagram?
    var preparationTimer: DispatchWorkItem?
    var preparationCompletion: ((Result<Void, EncryptedDNSQueryFailure>) -> Void)?

    init(endpoint: DoHEndpoint, resolver: TraditionalDNSBootstrapResolver, queue: DispatchQueue,
         permitted: @escaping () -> Bool,
         makeEncrypted: @escaping (String) throws -> NativeRoutedDatagram,
         failure: @escaping (Error) -> Void) {
        self.endpoint = endpoint; self.resolver = resolver
        self.queue = DispatchQueue(label: "app.hajimi.dns.doh-bootstrap-gateway", target: queue)
        self.permitted = permitted; self.makeEncrypted = makeEncrypted; self.failure = failure
    }
    var isClosed: Bool { admission.lock(); defer { admission.unlock() }; return closed }

    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
        admission.lock(); defer { admission.unlock() }
        if !started, !closed { executionContext = context }
    }

    func send(_ data: Data) {
        start(data: data, preparationDeadline: nil, prepared: nil)
    }
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Void, EncryptedDNSQueryFailure>) -> Void) {
        start(data: nil, preparationDeadline: absoluteDeadline, prepared: completion)
    }
    func start(data: Data?, preparationDeadline: TimeInterval?,
                       prepared: ((Result<Void, EncryptedDNSQueryFailure>) -> Void)?) {
        admission.lock()
        guard !closed, !started else { admission.unlock(); prepared?(.failure(.cancelled)); return }
        started = true; admission.unlock()
        queue.async {
            guard !self.isClosed else { return }
            self.preparationCompletion = prepared
            if let preparationDeadline {
                let remaining = preparationDeadline - ProcessInfo.processInfo.systemUptime
                guard remaining.isFinite, remaining > 0 else { self.fail(EncryptedDNSQueryFailure.timeout); return }
                let timer = DispatchWorkItem { [weak self] in
                    guard let self, !self.isClosed else { return }
                    self.finishPreparation(.failure(.timeout))
                    self.cancel(reason: .requestDeadline, completion: {})
                }
                self.preparationTimer = timer
                self.queue.asyncAfter(deadline: .now() + remaining, execute: timer)
            }
            guard self.permitted() else { self.fail(EncryptedDNSQueryFailure.policy); return }
            self.request = self.resolver.resolveDoHHost(self.endpoint.host, queue: self.queue) { [weak self] result in
                guard let self else { return }; self.request = nil
                guard !self.isClosed else { return }
                guard self.permitted() else { self.fail(EncryptedDNSQueryFailure.policy); return }
                do {
                    let addresses = try result.get()
                    guard let address = addresses.first else { throw EngineError("DoH 引导未返回 IP") }
                    let transport = try self.makeEncrypted(address)
                    guard !self.isClosed, self.permitted() else {
                        self.admission.lock(); let reason = self.cancellationReason ?? .policyChanged; self.admission.unlock()
                        self.cancelEncrypted(transport, reason: reason, completion: {})
                        if !self.isClosed { self.fail(EncryptedDNSQueryFailure.policy) }
                        return
                    }
                    self.admission.lock(); self.encrypted = transport; self.admission.unlock()
                    if let context = self.executionContext {
                        (transport as? DNSQueryExecutionContextAccepting)?.setDNSQueryExecutionContext(context)
                    }
                    if let preparationDeadline {
                        guard let preparation = transport as? DNSConnectionPrewarming else {
                            transport.cancel(); self.fail(EncryptedDNSQueryFailure.configuration); return
                        }
                        preparation.prewarm(absoluteDeadline: preparationDeadline) { [weak self] result in
                            self?.queue.async {
                                guard let self, !self.isClosed else { return }
                                self.finishPreparation(result)
                            }
                        }
                    } else if let data { transport.send(data) }
                } catch { self.fail(error) }
            }
        }
    }
    func fail(_ error: Error) {
        if preparationCompletion != nil { finishPreparation(.failure(EncryptedDNSQueryFailure.classify(error))) }
        else { failure(error) }
    }
    func finishPreparation(_ result: Result<Void, EncryptedDNSQueryFailure>) {
        preparationTimer?.cancel(); preparationTimer = nil
        let completion = preparationCompletion; preparationCompletion = nil; completion?(result)
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
            self.preparationTimer?.cancel(); self.preparationTimer = nil; self.preparationCompletion = nil
            if let request = self.request { self.resolver.cancel(request); self.request = nil }
            self.admission.lock(); let child = self.encrypted; self.admission.unlock()
            if let child { self.cancelEncrypted(child, reason: reason, completion: completion) }
            else { completion() }
        }
    }
    func cancelEncrypted(_ child: NativeRoutedDatagram, reason: DNSAttemptCancellationReason,
                                  completion: @escaping () -> Void) {
        if let acknowledging = child as? DNSQueryCancellationAcknowledging {
            acknowledging.cancel(reason: reason, completion: completion)
        } else { child.cancel(); completion() }
    }
    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
        admission.lock(); let provider = encrypted as? DNSProxyFallbackBarrierProviding; admission.unlock()
        return provider?.proxyFallbackBarrier()
    }
    func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence {
        admission.lock(); let provider = encrypted as? DNSQueryTransportEvidenceProviding; admission.unlock()
        return provider?.dnsQueryTransportEvidence() ?? .notStarted
    }
    deinit {
        preparationTimer?.cancel(); if let request { resolver.cancel(request) }
        if let encrypted { cancelEncrypted(encrypted, reason: .cleanup, completion: {}) }
    }
}

final class TCPDNSQueryDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSQueryDeadlineAwareDatagram, DNSProxyFallbackBarrierProviding {
    typealias Dialer = (ResolvedRoute, RequestTarget, DispatchQueue,
                       @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) -> (() -> Void)?
    let route: ResolvedRoute, target: RequestTarget
    let queue: DispatchQueue
    let permitted: () -> Bool
    let receiveHandler: (Data) -> Void, failureHandler: (Error) -> Void
    var stream: NativeOutboundByteStream?
    var buffer = Data()
    var started = false, stopped = false
    let admission = NSLock()
    var revoked = false
    var fallbackBarrier: DNSProxyFallbackBarrier?
    var fallbackQuestion: Data?, fallbackIngress = Data()
    let absoluteDeadline: TimeInterval?, dialer: Dialer
    let afterReplyIngressForSelfTest: (() -> Void)?
    var pendingConnect: (() -> Void)?, timer: DispatchWorkItem?, query: Data?

    init(route: ResolvedRoute, target: RequestTarget, queue: DispatchQueue,
         permitted: @escaping () -> Bool = { true },
         receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void,
         absoluteDeadline: TimeInterval? = nil, dialer: Dialer? = nil,
         afterReplyIngressForSelfTest: (() -> Void)? = nil) {
        self.route = route; self.target = target
        self.queue = DispatchQueue(label: "app.hajimi.dns.proxy-tcp-query", target: queue)
        self.permitted = permitted
        receiveHandler = receive; failureHandler = failure
        self.absoluteDeadline = absoluteDeadline
        self.afterReplyIngressForSelfTest = afterReplyIngressForSelfTest
        self.dialer = dialer ?? { route, target, worker, done in
            TunnelConnector.beginConnect(route: route, target: target, plainHTTP: false, queue: worker,
                                         waitForSetupAcknowledgement: true, completion: done)
        }
    }

    var allowed: Bool {
        admission.lock(); let active = !revoked; admission.unlock()
        return active && permitted() && (absoluteDeadline.map { $0.isFinite && ProcessInfo.processInfo.systemUptime < $0 } ?? true)
    }

    func send(_ data: Data) {
        queue.async {
            guard !self.started, !self.stopped, (12...65_535).contains(data.count) else { return }
            guard self.allowed else { self.fail(EncryptedDNSQueryFailure.policy); return }
            self.admission.lock()
            guard !self.revoked else { self.admission.unlock(); self.fail(EncryptedDNSQueryFailure.policy); return }
            self.fallbackQuestion = data
            self.admission.unlock()
            self.started = true; self.query = data
            if let deadline = self.absoluteDeadline {
                let timer = DispatchWorkItem { [weak self] in self?.fail(DNSQueryTimeoutError()) }
                self.timer = timer; self.queue.asyncAfter(deadline: .now() + max(0, deadline - ProcessInfo.processInfo.systemUptime), execute: timer)
            }
            self.pendingConnect = self.dialer(self.route, self.target, self.queue) { result in
                if case .failure(let error) = result { self.observeFallbackFailure(error) }
                self.queue.async {
                    self.pendingConnect = nil
                    guard !self.stopped else { if case .success(let pair) = result { pair.0.cancel() }; return }
                    guard self.allowed else {
                        if case .success(let pair) = result { pair.0.cancel() }
                        self.fail(EncryptedDNSQueryFailure.policy); return
                    }
                    switch result {
                    case .failure(let error): self.fail(error)
                    case .success(let pair):
                        self.stream = pair.0
                        var framed = Data([UInt8(data.count >> 8), UInt8(data.count & 0xff)])
                        framed.append(data)
                        pair.0.send(framed) { [weak self] error in
                            if let error { self?.observeFallbackFailure(error) }
                            self?.queue.async {
                                if let error { self?.fail(error) } else { self?.read() }
                            }
                        }
                    }
                }
            }
        }
    }

    func read() {
        guard !stopped, let stream else { return }
        guard allowed else { fail(EncryptedDNSQueryFailure.policy); return }
        stream.receive(maximum: 65_537 - buffer.count) { [weak self] data, complete, error in
            // Admit DNS metadata before the asynchronous submission gap. A
            // cancel may win after this callback but before its queue block.
            self?.observeFallbackIngress(data, complete: complete, error: error)
            self?.afterReplyIngressForSelfTest?()
            self?.queue.async {
                guard let self, !self.stopped else { return }
                guard self.allowed else {
                    self.fail(EncryptedDNSQueryFailure.policy); return
                }
                if let error { self.fail(error); return }
                if let data {
                    guard data.count <= 65_537 - self.buffer.count else { self.fail(EncryptedDNSQueryFailure.invalidResponse); return }
                    self.buffer.append(data)
                }
                if self.buffer.count >= 2 {
                    let length = Int(self.buffer[self.buffer.startIndex]) << 8
                        | Int(self.buffer[self.buffer.startIndex + 1])
                    guard length >= 12 else { self.fail(EncryptedDNSQueryFailure.invalidResponse); return }
                    if self.buffer.count >= length + 2 {
                        guard self.buffer.count == length + 2 else { self.fail(EncryptedDNSQueryFailure.invalidResponse); return }
                        let answer = Data(self.buffer.dropFirst(2))
                        guard let query = self.query, DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
                            self.fail(EncryptedDNSQueryFailure.invalidResponse); return
                        }
                        self.observeFallbackAnswer(answer)
                        self.stopped = true; self.timer?.cancel(); self.timer = nil
                        self.stream?.cancel(); self.stream = nil; self.query = nil
                        self.receiveHandler(answer); return
                    }
                }
                if complete { self.fail(self.buffer.isEmpty ? EncryptedDNSQueryFailure.network : .invalidResponse) }
                else { self.read() }
            }
        }
    }

    func fail(_ error: Error) {
        guard !stopped else { return }; stopped = true; timer?.cancel(); timer = nil
        observeFallbackFailure(error)
        pendingConnect?(); pendingConnect = nil; stream?.cancel(); stream = nil
        query = nil; buffer.removeAll(); failureHandler(error)
    }
    func observeFallbackFailure(_ error: Error) {
        let reason = EncryptedDNSQueryFailure.classify(error)
        guard !reason.permitsProxyFallback, reason != .cancelled else { return }
        admission.lock(); defer { admission.unlock() }
        guard !revoked, fallbackBarrier == nil else { return }
        fallbackBarrier = .failure(error)
    }
    func observeFallbackAnswer(_ answer: Data) {
        admission.lock()
        if fallbackBarrier == nil { fallbackBarrier = .answer(answer) }
        admission.unlock()
    }
    func observeFallbackIngress(_ data: Data?, complete: Bool, error: Error?) {
        let denial = error.map(EncryptedDNSQueryFailure.classify)
        admission.lock(); defer { admission.unlock() }
        guard !revoked, fallbackBarrier == nil, let query = fallbackQuestion else { return }
        if let error, let denial, !denial.permitsProxyFallback, denial != .cancelled {
            fallbackBarrier = .failure(error); return
        }
        // One bounded metadata-only framer, protected by the same admission
        // lock as cancel(). It neither submits I/O nor publishes a response.
        // This retains pre-cancel auth/negative/invalid results even if the
        // delivery block has not yet reached the child's serial queue.
        let input = data ?? Data()
        guard input.count <= 65_537 - fallbackIngress.count else {
            fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse); return
        }
        fallbackIngress.append(input)
        let received = fallbackIngress
        guard received.count >= 2 else {
            if complete, !received.isEmpty { fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse) }
            return
        }
        let length = Int(received[received.startIndex]) << 8 | Int(received[received.startIndex + 1])
        guard length >= 12, received.count <= length + 2 else {
            fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse); return
        }
        if received.count == length + 2 {
            let answer = Data(received.dropFirst(2))
            guard DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
                fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse); return
            }
            fallbackBarrier = .answer(answer)
        } else if complete {
            fallbackBarrier = .failure(EncryptedDNSQueryFailure.invalidResponse)
        }
    }
    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
        admission.lock(); defer { admission.unlock() }; return fallbackBarrier
    }
    func cancel() { cancel(completion: {}) }
    func cancel(completion: @escaping () -> Void) {
        admission.lock(); revoked = true; admission.unlock()
        queue.async {
            self.stopped = true; self.timer?.cancel(); self.timer = nil
            self.pendingConnect?(); self.pendingConnect = nil; self.stream?.cancel(); self.stream = nil
            self.query = nil; self.buffer.removeAll(); completion()
            self.admission.lock(); self.fallbackQuestion = nil; self.fallbackIngress.removeAll(); self.admission.unlock()
        }
    }
    func queryDeadlineReached() {
        admission.lock(); revoked = true; admission.unlock()
        queue.async { self.fail(DNSQueryTimeoutError()) }
    }
    func drainQueueForSelfTest() { queue.sync {} }
    deinit { timer?.cancel(); pendingConnect?(); stream?.cancel() }
}

/// RFC 1035 TCP framing, with bounded input and no assumptions about read or
/// write boundaries. Multiple queries in one write and split prefixes work.
struct DNSLengthFramer {
    var buffer = Data()
    mutating func append(_ data: Data) throws -> [Data] {
        guard data.count <= 256 * 1_024 - buffer.count else { throw EngineError("DNS TCP 输入缓冲超限") }
        buffer.append(data)
        var offset = 0, frames: [Data] = []
        while buffer.count - offset >= 2 {
            let length = Int(buffer[buffer.startIndex + offset]) << 8
                | Int(buffer[buffer.startIndex + offset + 1])
            guard length >= 12 else { throw EngineError("DNS TCP 查询长度无效") }
            guard buffer.count - offset >= length + 2 else { break }
            guard frames.count < 64 else { throw EngineError("DNS TCP 合并查询数量超限") }
            frames.append(Data(buffer[(buffer.startIndex + offset + 2)..<(buffer.startIndex + offset + 2 + length)]))
            offset += length + 2
        }
        if offset > 0 { buffer = Data(buffer.dropFirst(offset)) }
        guard buffer.count <= 65_537 else { throw EngineError("DNS TCP 未完成帧缓冲超限") }
        return frames
    }
}

final class DNSFramedByteStream: NativeOutboundByteStream {
    let queue: DispatchQueue
    let admission = NSLock()
    var reservedWrites = 0, reservedBytes = 0, admissionClosed = false
    var datagram: NativeRoutedDatagram?
    var framer = DNSLengthFramer()
    var output = Data()
    var outstanding = 0, bufferedResponses = 0
    var outputFrameLengths: [Int] = []
    var receiver: (maximum: Int, callback: (Data?, Bool, Error?) -> Void)?
    var stopped = false
    var terminalError: Error?
    var fakeIPSynthesisEnabled: Bool {
        (datagram as? PolicyDNSDatagram)?.fakeIPSynthesisEnabled ?? false
    }

    init(queue: DispatchQueue) { self.queue = DispatchQueue(label: "app.hajimi.dns.tcp-ingress", target: queue) }
    func attach(_ datagram: NativeRoutedDatagram) { self.datagram = datagram }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        admission.lock()
        guard !admissionClosed, reservedWrites < 64, data.count <= 256 * 1_024 - reservedBytes else {
            admission.unlock(); completion(EngineError("DNS TCP 发送缓冲超限或已关闭")); return
        }
        reservedWrites += 1; reservedBytes += data.count; admission.unlock()
        queue.async {
            self.admission.lock(); self.reservedWrites -= 1; self.reservedBytes -= data.count; self.admission.unlock()
            guard !self.stopped, let datagram = self.datagram else { completion(self.terminalError ?? EngineError("DNS TCP 已关闭")); return }
            do {
                let queries = try self.framer.append(data)
                guard queries.count <= 64 - self.outstanding else { throw EngineError("DNS TCP 未完成查询超限") }
                self.outstanding += queries.count
                queries.forEach(datagram.send)
                completion(nil)
            } catch { self.stop(error); completion(error) }
        }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async {
            guard maximum > 0, self.receiver == nil else { completion(nil, true, EngineError("DNS TCP 读取参数或并发读取无效")); return }
            self.receiver = (min(maximum, 65_536), completion); self.flushReceive()
        }
    }

    func receiveDNSResponse(_ data: Data) {
        queue.async {
            guard !self.stopped else { return }
            guard (12...65_535).contains(data.count), self.outstanding > 0,
                  self.bufferedResponses < 64, data.count + 2 <= 1_024 * 1_024 - self.output.count else {
                self.stop(EngineError("DNS TCP 应答缓冲超限或收到非请求应答")); return
            }
            self.outstanding -= 1; self.bufferedResponses += 1
            self.outputFrameLengths.append(data.count + 2)
            self.output.append(contentsOf: [UInt8(data.count >> 8), UInt8(data.count & 0xff)])
            self.output.append(data); self.flushReceive()
        }
    }

    func flushReceive() {
        guard let receiver else { return }
        if !output.isEmpty {
            let chunk = Data(output.prefix(receiver.maximum))
            output = Data(output.dropFirst(chunk.count))
            var consumed = chunk.count
            while consumed > 0, let length = outputFrameLengths.first {
                if consumed >= length {
                    consumed -= length; outputFrameLengths.removeFirst(); bufferedResponses -= 1
                } else {
                    outputFrameLengths[0] -= consumed; consumed = 0
                }
            }
            self.receiver = nil; receiver.callback(chunk, false, nil)
        } else if stopped {
            self.receiver = nil; receiver.callback(nil, true, terminalError)
        }
    }

    func stop(_ error: Error?) {
        guard !stopped else { return }; stopped = true; terminalError = error
        admission.lock(); admissionClosed = true; admission.unlock()
        datagram?.cancel(); datagram = nil; output.removeAll(); bufferedResponses = 0; outputFrameLengths.removeAll()
        flushReceive()
    }
    func fail(_ error: Error) { queue.async { self.stop(error) } }
    func cancel() { admission.lock(); admissionClosed = true; admission.unlock(); queue.async { self.stop(nil) } }
    deinit { datagram?.cancel() }
}

final class DNSAddressResolution {
    typealias DatagramFactory = (RequestTarget, DispatchQueue, @escaping (Data) -> Void,
                                 @escaping (Error) -> Void) throws -> NativeRoutedDatagram
    let queue: DispatchQueue
    let permitted: () -> Bool
    let totalTimeout: TimeInterval
    // Only this file's memory-only regression supplies a factory or shorter
    // deadline. Production construction keeps the routed wire query path.
    let datagramFactory: DatagramFactory?
    let admission = NSLock()
    var cancelled = false
    var started = false
    var completion: ((Result<[String], Error>) -> Void)?
    var flow: NativeRoutedDatagram?
    var pending: [UInt16: Data] = [:]
    var addresses: [String] = []
    var timeout: DispatchWorkItem?
    var addressGrace: DispatchWorkItem?
    var sawRefusal = false

    init(queue: DispatchQueue, permitted: @escaping () -> Bool = { true },
         totalTimeout: TimeInterval = 10, datagramFactory: DatagramFactory? = nil,
         completion: @escaping (Result<[String], Error>) -> Void) {
        self.queue = DispatchQueue(label: "app.hajimi.dns.direct-address", target: queue)
        self.permitted = permitted; self.datagramFactory = datagramFactory
        self.totalTimeout = totalTimeout.isFinite ? min(10, max(0.001, totalTimeout)) : 10
        self.completion = completion
    }
    var isCancelled: Bool {
        admission.lock(); defer { admission.unlock() }; return cancelled
    }
    func start(router: NativePacketRouter, host: String, sourceTarget: RequestTarget?) {
        let id = UInt16.random(in: UInt16.min...UInt16.max), secondID = id &+ 1
        guard let a = DNSMessageInspection.query(for: host, type: 1, id: id),
              let aaaa = DNSMessageInspection.query(for: host, type: 28, id: secondID) else {
            queue.async { self.finish(.failure(EngineError("目标域名不能编码为 DNS 查询"))) }; return
        }
        let target = RequestTarget(host: protectedSystemDNSGateway, port: 53, protocolName: "UDP",
                                   sourceHost: sourceTarget?.sourceHost, sourcePort: sourceTarget?.sourcePort,
                                   inboundPort: sourceTarget?.inboundPort)
        queue.async {
            guard self.completion != nil, !self.started else { return }
            self.started = true
            guard !self.isCancelled, self.permitted() else {
                self.finish(.failure(EngineError("DNS 地址解析已取消或策略/接口已更新"))); return
            }
            self.pending = [id: a, secondID: aaaa]
            let receive: (Data) -> Void = { [self] answer in self.queue.async { self.accept(answer) } }
            let failure: (Error) -> Void = { [self] error in
                self.queue.async {
                    self.finish(self.addresses.isEmpty ? .failure(error) : .success(self.addresses))
                }
            }
            do {
                // DIRECT destinations need real addresses, even if a DNS-specific
                // rule routes the question through a proxy with fake-IP enabled.
                if let factory = self.datagramFactory {
                    self.flow = try factory(target, self.queue, receive, failure)
                } else {
                    self.flow = try router.makeDNSDatagram(original: target, queue: self.queue,
                        synthesizeFakeIP: false, receive: receive, failure: failure)
                }
            } catch { self.finish(.failure(error)); return }
            guard !self.isCancelled, self.permitted() else {
                self.finish(.failure(EngineError("DNS 地址解析期间策略或接口已更新"))); return
            }
            let deadline = DispatchWorkItem { [weak self] in self?.deadlineReached() }
            self.timeout = deadline
            self.queue.asyncAfter(deadline: .now() + self.totalTimeout, execute: deadline)
            self.flow?.send(a); self.flow?.send(aaaa)
        }
    }
    func accept(_ answer: Data) {
        guard completion != nil, answer.count >= 12 else { return }
        guard !isCancelled, permitted() else {
            finish(.failure(EngineError("DNS 应答期间策略或接口已更新"))); return
        }
        let id = UInt16(answer[answer.startIndex]) << 8 | UInt16(answer[answer.startIndex + 1])
        guard let query = pending[id], DNSMessageInspection.responseMatchesQuery(answer, query: query) else { return }
        pending.removeValue(forKey: id)
        sawRefusal = sawRefusal || answer[answer.startIndex + 3] & 0x0f == 5
        for record in DNSMessageInspection.addressAnswers(in: answer) where !addresses.contains(record.address) {
            if !FakeIPAllocator.isFake(record.address) { addresses.append(record.address) }
        }
        if pending.isEmpty {
            if addresses.isEmpty { finish(.failure(EngineError(sawRefusal ? "域名解析被 DNS 策略拒绝" : "加密/代理 DNS 未返回地址"))) }
            else { finish(.success(addresses)) }
        } else if addressGrace == nil, addresses.contains(where: { !$0.contains(":") }) {
            // This is internal DIRECT address discovery, not an application
            // wire DNS reply. Keep a short DNS resolution delay to collect a
            // prompt AAAA, but a silent/broken AAAA must not hold valid IPv4
            // for the full 8-second routed-query deadline. An IPv6-only first
            // answer still waits for A: this one-shot API cannot append a late
            // IPv4 fallback to an already-running Happy Eyeballs dial.
            let grace = DispatchWorkItem { [weak self] in
                guard let self else { return }; self.finish(.success(self.addresses))
            }
            addressGrace = grace; queue.asyncAfter(deadline: .now() + 0.05, execute: grace)
        }
    }
    func deadlineReached() {
        // Preserve a usable family even if the other query never delivers a
        // response. finish performs the final policy/interface/cancel check.
        if addresses.isEmpty { finish(.failure(EngineError("DNS 地址解析超时"))) }
        else { finish(.success(addresses)) }
    }
    func finish(_ result: Result<[String], Error>) {
        guard let callback = completion else { return }; completion = nil
        timeout?.cancel(); timeout = nil; addressGrace?.cancel(); addressGrace = nil
        flow?.cancel(); flow = nil; pending.removeAll()
        if isCancelled { callback(.failure(EngineError("DNS 地址解析已取消"))) }
        else if !permitted() { callback(.failure(EngineError("DNS 地址解析期间策略或接口已更新"))) }
        else { callback(result) }
        addresses.removeAll()
    }
    func cancel() {
        admission.lock(); cancelled = true; admission.unlock()
        queue.async { self.finish(.failure(EngineError("DNS 地址解析已取消"))) }
    }
    deinit { timeout?.cancel(); addressGrace?.cancel(); flow?.cancel() }
}

// Memory self-tests drive the original callbacks on their owning queue. Stop
// dispatch work items inside the fixture factory, before even a 1ms hedge can
// race the test driver; production exchanges never call these checkpoints.

import Foundation
import HajimiDNS
import HajimiRouting
import Network
import Security
import Darwin
import HajimiProxyRuntime
import HajimiCXXProtocolBridge

@_exported import HajimiDNS
@_exported import HajimiRouting

/// Pure routing/framing regressions plus a fake-IP TCP round trip. No test in
/// this suite starts a listener, opens an outbound socket or changes DNS.
public enum DNSSecurityRoutingSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS 路由安全自检失败：\(text)" }
    }
    private static func expect(_ condition: @autoclosure () throws -> Bool, _ text: String) throws {
        guard try condition() else { throw Failure(text: text) }
    }
    private static func query(_ name: String, _ type: UInt16, id: UInt16 = 0x4545) throws -> Data {
        guard let data = DNSMessageInspection.query(for: name, type: type, id: id) else {
            throw Failure(text: "查询构造失败")
        }
        return data
    }
    private static func plan(_ router: NativePacketRouter, name: String = "allowed.example.test",
                             type: UInt16 = 1, original: RequestTarget? = nil) throws -> DNSQueryPlan {
        let target = original ?? RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")
        guard case .upstream(let plan) = try router.prepareDNSQuery(query(name, type), original: target) else {
            throw Failure(text: "真实查询被意外合成")
        }
        return plan
    }
    private static func router(_ profile: Profile, mode: OutboundMode = .rule,
                               global: String = "Node") -> NativePacketRouter {
        NativePacketRouter(profile: profile, mode: mode, globalPolicy: global, groupSelections: [:])
    }
    private static func refusal(_ router: NativePacketRouter, name: String, type: UInt16,
                                original: RequestTarget? = nil) throws {
        do { _ = try plan(router, name: name, type: type, original: original) }
        catch DNSPolicyFailure.refused { return }
        throw Failure(text: "\(name)/\(type) 的显式拒绝被绕过")
    }

    /// Owned, in-memory regression path for the opt-in proxy DNS downgrade.
    /// None of these checks can invoke a resolver, native dial or listener.
    public static func runProxyFallbackTests() throws {
        try proxyFallbackRoutingPolicy()
        try dnsSelectionModes()
        try dnsPrewarmLifecycle()
        try proxyFallbackTCPFraming()
        try proxyFallbackIngressFence()
        try proxyFallbackPooledTransport()
        try proxyFallbackAdaptiveBarriers()
        try proxyFallbackEncryptedPhaseHealth()
    }

    private final class PrewarmMemoryPeer: NativeOutboundByteStream {
        private let lock = NSLock()
        private var reader: ((Data?, Bool, Error?) -> Void)?
        private var closed = false, sends = 0
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); sends += 1; lock.unlock(); completion(nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); reader = completion; lock.unlock()
        }
        func cancel() {
            lock.lock(); closed = true; let callback = reader; reader = nil; lock.unlock()
            callback?(nil, true, EncryptedDNSQueryFailure.cancelled)
        }
        var snapshot: (closed: Bool, sends: Int) { lock.lock(); defer { lock.unlock() }; return (closed, sends) }
    }
    private static func dnsPrewarmLifecycle() throws {
        var configured = proxyFallbackProfile()
        configured.encryptedDNSServers += ["https://203.0.113.71/dns-query", "tls://203.0.113.72"]
        configured.dnsSelectionMode = .encryptedOnly
        for scenario in 0..<4 {
            var profile = configured
            if scenario == 0 { profile.dnsPrewarmEnabled = false }
            if scenario == 3 { profile.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)] }
            let source = router(profile), started = DispatchSemaphore(value: 0), lock = NSLock()
            var peers: [PrewarmMemoryPeer] = []
            source.memoryFixtureDNSStreamDialer = { _, _, _, _, _, _, done in
                let peer = PrewarmMemoryPeer()
                lock.lock(); peers.append(peer); lock.unlock(); started.signal(); done(.success(peer)); return nil
            }
            source.prewarmDNS()
            if scenario == 1 { source.cancelDNSQueriesForInternal() }
            if scenario == 2 {
                profile.dnsPrewarmEnabled = false
                source.update(profile: profile, mode: .rule, globalPolicy: "Node", groupSelections: [:])
            }
            try expect(started.wait(timeout: .now() + 0.35) == .timedOut,
                       "关闭、停止、旧代际或REJECT仍触发预热连接")
            lock.lock(); let count = peers.count; lock.unlock()
            try expect(count == 0, "预热越过取消或策略边界")
            source.cancelDNSQueriesForInternal()
        }
        let source = router(configured), started = DispatchSemaphore(value: 0), lock = NSLock()
        var peers: [PrewarmMemoryPeer] = []
        source.memoryFixtureDNSStreamDialer = { _, _, _, _, _, _, done in
            let peer = PrewarmMemoryPeer()
            lock.lock(); peers.append(peer); lock.unlock(); started.signal(); done(.success(peer)); return nil
        }
        defer { source.cancelDNSQueriesForInternal() }
        source.prewarmDNS()
        try expect(started.wait(timeout: .now() + 1) == .success && started.wait(timeout: .now() + 1) == .success,
                   "启动预热没有准备两个获准加密候选")
        source.prewarmDNS()
        try expect(started.wait(timeout: .now() + 0.35) == .timedOut, "同一代际重复预热或超过两个候选")
        lock.lock(); let first = peers; lock.unlock()
        try expect(first.count == 2 && first.allSatisfy { $0.snapshot.sends == 0 },
                   "预热发送了DNS消息或无界启动候选")
        var disabled = configured; disabled.dnsPrewarmEnabled = false
        source.update(profile: disabled, mode: .rule, globalPolicy: "Node", groupSelections: [:])
        try expect(started.wait(timeout: .now() + 0.35) == .timedOut && first.allSatisfy { $0.snapshot.closed },
                   "关闭预热未清理旧连接，或重新创建了连接")
        print("DNS prewarm lifecycle: opt-out, stop, epoch revocation, REJECT, two-candidate cap, duplicate suppression and zero DNS payload passed")
    }

    private static func dnsSelectionModes() throws {
        var balanced = proxyFallbackProfile(); balanced.dnsProxyFallbackEnabled = false
        let b = try plan(router(balanced))
        var encrypted = balanced; encrypted.dnsSelectionMode = .encryptedOnly; encrypted.dnsProxyFallbackEnabled = true
        let a = try plan(router(encrypted))
        var mixed = balanced; mixed.dnsSelectionMode = .mixedSpeed
        let source = router(mixed), c = try plan(source)
        try expect(a.fallbackServers.isEmpty && b.fallbackServers.isEmpty && c.fallbackServers.count == 2,
                   "DNS模式未保持加密独用、显式后备与混合批准的不同权限")
        try expect(a.scopeKey != b.scopeKey && b.scopeKey != c.scopeKey && a.healthScopeKey != c.healthScopeKey,
                   "DNS模式切换沿用了不同授权模式的答案或健康作用域")
        let plain = try source.revalidatedProxyFallbackPlan(c, server: c.fallbackServers[0])
        try expect(plain.route == c.route && !plain.upstream.encrypted && !mixed.dnsProxyFallbackEnabled,
                   "混合模式错误依赖后备开关或离开已批准代理")
        for selection: DNSSelectionMode in [.encryptedOnly, .mixedSpeed] {
            var traditional = mixed
            traditional.dnsSelectionMode = selection; traditional.encryptedDNSServers = []
            traditional.dnsLeakProtectionEnabled = false
            try expect(try plan(router(traditional)).upstream.encrypted,
                       "明确加密或混合模式仍降回旧纯传统DNS路径")
        }
        var direct = mixed; direct.dnsLeakProtectionEnabled = false
        direct.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        try expect(try plan(router(direct)).fallbackServers.isEmpty,
                   "混合模式在DIRECT路由或保护关闭时泄露普通DNS")
        var denied = mixed
        denied.rules.insert(RoutingRule(kind: .domainSuffix("example.test"), policy: "REJECT", sourceLine: 0), at: 0)
        try refusal(router(denied), name: "allowed.example.test", type: 1)

        // Exercise the real coordinator, mixed scheduler and health receipts.
        // Both encrypted peers are silent; the explicitly approved ordinary
        // peer answers. The next fresh question should start with that winner.
        for round in 0..<2 {
            let probe = AdaptiveProbe(), message = try query("mixed-\(round).example.test", 1)
            let approved = try plan(source, name: "mixed-\(round).example.test")
            let flow = try source.makeOptimizedDNSUpstream(plan: approved, queue: .global(),
                adaptiveFactory: { candidate, _, _, _ in
                    AdaptiveAcknowledgedMemoryTransport(send: { _ in probe.attempted(candidate) }, cancel: probe.transportCancelled)
                }, proxyTCPFactory: { server, worker, _, receive, _ in
                    let candidate = DNSUpstreamCandidate(upstream: .plain(host: server.host, port: server.port), bootstrap: nil)
                    return AdaptiveAcknowledgedMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        worker.asyncAfter(deadline: .now() + 0.01) { receive(bootstrapAnswer(data)!) }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }
            flow.send(message); try awaitAdaptive(probe, query: message, waitTimeout: 2)
            try expect(probe.snapshot.attempts == (round == 0
                ? [approved.candidates[0].upstream.target.host, approved.fallbackServers[0].host]
                : [approved.fallbackServers[0].host]) && probe.concurrency.peak <= 2,
                "混合模式未使用真实批准普通候选、未学习获胜路径或超出两条在途")
        }
        print("DNS modes: encrypted-only, balanced authorization, mixed proxy-only ranking, scope separation and first/next-query learning passed")
    }

    private static func proxyFallbackProfile() -> Profile {
        var profile = Profile()
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
            adapterType: "vmess", parameters: ["uuid": "12345678-1234-1234-1234-1234567890ab"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        profile.dnsServers = ["203.0.113.61"]
        profile.encryptedDNSServers = ["https://203.0.113.70/dns-query"]
        profile.dnsProxyFallbackEnabled = true
        profile.dnsProxyFallbackServers = ["203.0.113.60", "203.0.113.62:5353"]
        return profile
    }

    private static func proxyFallbackRoutingPolicy() throws {
        let base = proxyFallbackProfile()
        let original = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7263)
        let source = router(base), approved = try plan(source, original: original)
        try expect(approved.fallbackServers.map(\.host) == ["203.0.113.60", "203.0.113.62"]
                   && approved.questionName == "allowed.example.test" && approved.original == original,
                   "显式回退列表混入传统引导 DNS 或丢失应用问题/元数据")
        let fallback = try source.revalidatedProxyFallbackPlan(approved, server: approved.fallbackServers[0])
        try expect(fallback.route == approved.route && fallback.upstream.target.host == "203.0.113.60"
                   && fallback.upstream.target.port == 53 && fallback.upstream.target.protocolName == "TCP"
                   && !fallback.upstream.encrypted, "回退切换了实际代理、使用 UDP 或改变解析器角色")

        var disabled = base; disabled.dnsProxyFallbackEnabled = false
        let disabledPlan = try plan(router(disabled), original: original)
        try expect(disabledPlan.fallbackServers.isEmpty && disabledPlan.scopeKey != approved.scopeKey,
                   "关闭回退仍授权名单或沿用旧查询 scope")
        disabled.dnsProxyFallbackServers = []
        try expect(try plan(router(disabled), original: original).fallbackServers.isEmpty,
                   "传统/bootstrap-only DNS 被自动迁移成应用回退解析器")
        var missing = base; missing.dnsProxyFallbackServers = []
        do { _ = try plan(router(missing), original: original)
            throw Failure(text: "开启回退但没有显式名单仍准入")
        } catch DNSPolicyFailure.configuration {}

        var direct = base; direct.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        try expect(try plan(router(direct, global: "Node"), original: original).fallbackServers.isEmpty,
                   "选定 DIRECT 被安全 global 节点替换并触发回退")
        var clear = base
        clear.proxies["Node"] = ProxyPolicy(name: "Node", kind: .socks5,
            host: "203.0.113.10", port: 1080)
        try expect(try plan(router(clear), original: original).fallbackServers.isEmpty,
                   "未加密实际节点被误当作安全 DNS 代理")
        var invalid = base; invalid.encryptedDNSServers = ["https://dns.google"]
        do { _ = try plan(router(invalid), original: original)
            throw Failure(text: "无效加密配置被普通 DNS 回退掩盖")
        } catch DNSPolicyFailure.configuration {}

        for deny in [RuleKind.domain("allowed.example.test"), .ipCIDR("203.0.113.53/32"),
                     .sourceIPCIDR("192.0.2.1/32"), .sourcePort(41000...41000), .inboundPort(7263...7263)] {
            var denied = base
            denied.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            for mode in [OutboundMode.rule, .proxy] {
                try refusal(router(denied, mode: mode), name: "allowed.example.test", type: 1, original: original)
            }
        }
        for deny in [RuleKind.ipCIDR("203.0.113.60/32"), .domain("203.0.113.60")] {
            var filtered = base
            filtered.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            let selected = try plan(router(filtered, mode: .proxy), original: original)
            try expect(selected.fallbackServers.map(\.host) == ["203.0.113.62"]
                       && selected.scopeKey != approved.scopeKey,
                       "被拒绝的备用解析器仍准入或未隔离完整批准集合")
        }
        var reordered = base; reordered.dnsProxyFallbackServers.reverse()
        try expect(try plan(router(reordered), original: original).scopeKey != approved.scopeKey,
                   "完整回退列表/次序未进入 cache 与 single-flight scope")
        var alternate = original; alternate.sourceHost = "192.0.2.2"
        try expect(try plan(source, original: alternate).scopeKey != approved.scopeKey, "回退 scope 跨来源 IP")
        alternate = original; alternate.inboundPort = 7264
        try expect(try plan(source, original: alternate).scopeKey != approved.scopeKey, "回退 scope 跨入站端口")
        alternate = original; alternate.protocolName = "TCP"
        try expect(try plan(source, original: alternate).scopeKey != approved.scopeKey, "回退 scope 混同 UDP/TCP")
        alternate = original; alternate.host = "203.0.113.54"
        try expect(try plan(source, original: alternate).scopeKey != approved.scopeKey, "回退 scope 丢失原目的地址")

        var nested = base
        let reference = RuleSetReference(location: "memory.proxy-fallback.source-port")
        nested.ruleSetContents[reference.location] = [.logicalNot(.logicalNot(.sourcePort(41001...41001)))]
        nested.rules.insert(RoutingRule(kind: .ruleSet(reference), policy: "REJECT", sourceLine: 0), at: 0)
        let scoped = router(nested), first = try plan(scoped, original: original)
        alternate = original; alternate.sourcePort = 41002
        try expect(try plan(scoped, original: alternate).scopeKey != first.scopeKey,
                   "规则集内 SRC-PORT 未隔离回退查询 scope")
        alternate.sourcePort = 41001
        try refusal(scoped, name: "allowed.example.test", type: 1, original: alternate)

        func revoked(_ decision: DNSQueryPlan) throws {
            do { _ = try source.revalidatedProxyFallbackPlan(decision, server: decision.fallbackServers[0])
                throw Failure(text: "失效策略/接口代际仍授权回退")
            } catch EncryptedDNSQueryFailure.policy {}
        }
        let wrongInterface = DNSQueryPlan(upstream: approved.upstream, candidates: approved.candidates,
            route: approved.route, original: approved.original, generation: approved.generation,
            bootstrap: approved.bootstrap, scopeKey: approved.scopeKey, healthScopeKey: approved.healthScopeKey,
            interfaceName: "owned-nonexistent-fallback-interface", questionName: approved.questionName,
            fallbackServers: approved.fallbackServers)
        try revoked(wrongInterface)
        source.flushDNS(); try revoked(approved)
        let afterFlush = try plan(source, original: original)
        source.update(profile: disabled, mode: .rule, globalPolicy: "Node", groupSelections: [:])
        try revoked(afterFlush)
    }

    private final class ProxyFallbackMemoryStream: NativeOutboundByteStream {
        private let lock = NSLock()
        private var input: [(Data?, Bool, Error?)]
        private var writes: [Data] = [], cancellations = 0
        init(_ chunks: [(Data?, Bool, Error?)]) { input = chunks }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); writes.append(data); lock.unlock(); completion(nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); let chunk = input.isEmpty ? (nil, true, nil) : input.removeFirst(); lock.unlock()
            completion(chunk.0, chunk.1, chunk.2)
        }
        func cancel() { lock.lock(); cancellations += 1; lock.unlock() }
        var snapshot: (writes: [Data], cancellations: Int) {
            lock.lock(); defer { lock.unlock() }; return (writes, cancellations)
        }
    }
    private final class ProxyFallbackDialProbe {
        typealias Completion = (Result<(any OutboundByteStream, Data), Error>) -> Void
        private let lock = NSLock()
        private var callback: Completion?, calls = 0, cancellations = 0
        func begin(_ callback: @escaping Completion) { lock.lock(); calls += 1; self.callback = callback; lock.unlock() }
        func cancel() { lock.lock(); cancellations += 1; lock.unlock() }
        func ready(_ result: Result<(any OutboundByteStream, Data), Error>) {
            lock.lock(); let callback = self.callback; self.callback = nil; lock.unlock(); callback?(result)
        }
        var snapshot: (calls: Int, cancellations: Int) {
            lock.lock(); defer { lock.unlock() }; return (calls, cancellations)
        }
    }

    private final class ProxyFallbackControlledStream: NativeOutboundByteStream {
        let receiving = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var callback: ((Data?, Bool, Error?) -> Void)?
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); callback = completion; lock.unlock(); receiving.signal()
        }
        func emit(_ data: Data?, error: Error? = nil) {
            lock.lock(); let callback = callback; self.callback = nil; lock.unlock()
            callback?(data, true, error)
        }
        func cancel() {}
    }

    private final class ProxyFallbackPooledMemoryStream: NativeOutboundByteStream {
        let closed = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var input: Data?
        private var receiver: ((Data?, Bool, Error?) -> Void)?
        private var stopped = false, sends = 0
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            let query = Data(data.dropFirst(2))
            guard data.count >= 14, Int(data[0]) << 8 | Int(data[1]) == query.count,
                  var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail) else {
                completion(EncryptedDNSQueryFailure.invalidResponse); return
            }
            answer[3] &= 0xf0
            let frame = Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer
            lock.lock()
            guard !stopped, input == nil else { lock.unlock(); completion(EncryptedDNSQueryFailure.cancelled); return }
            sends += 1
            let callback = receiver; receiver = nil
            if callback == nil { input = frame }
            lock.unlock(); completion(nil); callback?(frame, false, nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped, receiver == nil else { lock.unlock(); completion(nil, true, EncryptedDNSQueryFailure.cancelled); return }
            if let input {
                self.input = nil; lock.unlock(); completion(input, false, nil)
            } else { receiver = completion; lock.unlock() }
        }
        func cancel() {
            lock.lock(); guard !stopped else { lock.unlock(); return }
            stopped = true; input = nil; let callback = receiver; receiver = nil; lock.unlock()
            callback?(nil, true, EncryptedDNSQueryFailure.cancelled); closed.signal()
        }
        var sendCount: Int { lock.lock(); defer { lock.unlock() }; return sends }
    }

    private static func proxyFallbackPooledTransport() throws {
        var profile = proxyFallbackProfile()
        profile.rules.insert(RoutingRule(kind: .sourcePort(65_000...65_000), policy: "REJECT", sourceLine: 1), at: 0)
        let source = router(profile), nativeLock = NSLock()
        var streams: [ProxyFallbackPooledMemoryStream] = []
        let dialer: MetadataAwareEncryptedDNSStreamDialer = { host, port, name, _, _, observe, done in
            guard (host == "203.0.113.60" && port == 53) || (host == "203.0.113.62" && port == 5353), host == name else {
                observe(EncryptedDNSQueryFailure.policy); done(.failure(EncryptedDNSQueryFailure.policy)); return nil
            }
            let stream = ProxyFallbackPooledMemoryStream()
            nativeLock.lock(); streams.append(stream); nativeLock.unlock(); done(.success(stream)); return nil
        }
        func peers() -> [ProxyFallbackPooledMemoryStream] { nativeLock.lock(); defer { nativeLock.unlock() }; return streams }
        func exchange(_ decision: DNSQueryPlan, server: Int = 0, id: UInt16) throws {
            let message = try query(decision.questionName!, 1, id: id), result = AdaptiveProbe()
            let flow = try source.makeProxyTCPFallbackUpstream(plan: decision, server: decision.fallbackServers[server],
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 1, dialer: dialer,
                receive: result.received, failure: result.failed)
            flow.send(message); try awaitAdaptive(result, query: message, expectFailure: false)
            let cancelled = DispatchSemaphore(value: 0); flow.cancel { cancelled.signal() }
            try expect(cancelled.wait(timeout: .now() + 1) == .success, "pooled router lease did not ACK its question")
        }
        let one = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 42_001, inboundPort: 7263)
        var two = one; two.sourcePort = 42_002
        let first = try plan(source, name: "first.router-pool.example", original: one)
        let second = try plan(source, name: "second.router-pool.example", original: two)
        try expect(first.scopeKey != second.scopeKey, "pooled router fixture did not partition question source ports")
        let unused = try source.makeProxyTCPFallbackUpstream(plan: first, server: first.fallbackServers[0],
            absoluteDeadline: ProcessInfo.processInfo.systemUptime + 1, dialer: dialer, receive: { _ in }, failure: { _ in })
        try expect(peers().isEmpty, "borrowing a fallback resolver pre-dialed an unrequested stream")
        unused.cancel()
        try exchange(first, id: 0x7501); try exchange(second, id: 0x7502)
        try expect(peers().count == 1 && peers()[0].sendCount == 2,
                   "authorized source-port/QNAME changes fragmented the physical fallback pool")
        try exchange(second, server: 1, id: 0x7503)
        let beforeFlush = peers()
        try expect(beforeFlush.count == 2 && beforeFlush[1].sendCount == 1,
                   "another approved fallback resolver borrowed the first resolver's connection")
        source.flushDNS()
        for stream in beforeFlush {
            try expect(stream.closed.wait(timeout: .now() + 1) == .success, "DNS epoch flush retained an old fallback pool")
        }
        do {
            _ = try source.makeProxyTCPFallbackUpstream(plan: first, server: first.fallbackServers[0],
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 1, dialer: dialer, receive: { _ in }, failure: { _ in })
            throw Failure(text: "old question authority revived a flushed proxy TCP resolver")
        } catch EncryptedDNSQueryFailure.policy {}
        let fresh = try plan(source, name: "fresh.router-pool.example", original: one)
        try exchange(fresh, id: 0x7504)
        try expect(peers().count == 3, "new epoch reused an old authenticated fallback transport")
        source.flushDNS()
    }

    private static func proxyFallbackIngressFence() throws {
        let source = router(proxyFallbackProfile()), approved = try plan(source)
        let decision = try source.revalidatedProxyFallbackPlan(approved, server: approved.fallbackServers[0])
        let query = try self.query("fallback-native-ingress.example.test", 1)
        for mode in 0..<8 {
            let stream = ProxyFallbackControlledStream(), probe = AdaptiveProbe()
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let returned = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
            let flow = TCPDNSQueryDatagram(route: decision.route, target: decision.upstream.target,
                queue: .global(qos: .userInitiated), receive: probe.received, failure: probe.failed,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8,
                dialer: { _, _, _, done in done(.success((stream, Data()))); return {} },
                afterReplyIngressForSelfTest: { entered.signal(); _ = release.wait(timeout: .now() + 2) })
            defer { release.signal(); flow.cancel(); flow.drainQueueForSelfTest() }
            flow.send(query)
            try expect(stream.receiving.wait(timeout: .now() + 1) == .success, "TCP DNS 原生回调尚未登记")
            var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail)!
            let code: UInt8 = mode == 0 ? 0 : mode == 1 ? 3 : mode == 2 ? 5 : 2
            answer[3] = (answer[3] & 0xf0) | code
            if mode == 4 { answer[0] ^= 1 }
            var frame = Data([UInt8(answer.count >> 8), UInt8(answer.count & 0xff)]); frame.append(answer)
            if mode == 6 { frame = Data(frame.prefix(1)) }
            if mode == 7 { frame = Data(frame.dropLast()) }
            let admittedFrame = frame
            DispatchQueue.global(qos: .userInitiated).async {
                stream.emit(mode == 5 ? nil : admittedFrame, error: mode == 5 ? EncryptedDNSQueryFailure.authentication : nil)
                returned.signal()
            }
            try expect(entered.wait(timeout: .now() + 1) == .success, "TCP DNS ingress→queue 窗口未打开")
            flow.cancel { cancelled.signal() }
            try expect(cancelled.wait(timeout: .now() + 1) == .success, "TCP DNS 取消逻辑 ACK 未完成")
            guard let barrier = flow.proxyFallbackBarrier() else { throw Failure(text: "取消擦除了已准入原生 metadata") }
            switch barrier {
            case .answer(let received):
                try expect(mode < 4 && received == answer, "TCP DNS 原生否定/正向答复 barrier 改变 ID 或问题")
            case .failure(let error):
                try expect(EncryptedDNSQueryFailure.classify(error) == (mode == 5 ? .authentication : .invalidResponse),
                           "TCP DNS 认证/错误 ID barrier 被弱化")
            }
            release.signal()
            try expect(returned.wait(timeout: .now() + 1) == .success, "TCP DNS 晚到 native read 未返回")
            flow.drainQueueForSelfTest()
            try expect(probe.snapshot.answers.isEmpty && probe.snapshot.error == nil,
                       "取消的 TCP DNS 原生结果仍交付给客户端")
        }
    }

    private static func proxyFallbackTCPFraming() throws {
        let profile = proxyFallbackProfile(), source = router(profile), decision = try plan(source)
        let fallback = try source.revalidatedProxyFallbackPlan(decision, server: decision.fallbackServers[0])
        let message = try query("allowed.example.test", 1), answer = bootstrapAnswer(message)!
        func framed(_ data: Data) -> Data {
            var frame = Data([UInt8(data.count >> 8), UInt8(data.count & 0xff)]); frame.append(data); return frame
        }
        let frame = framed(answer)
        func exchange(_ chunks: [(Data?, Bool, Error?)], succeeds: Bool) throws {
            let stream = ProxyFallbackMemoryStream(chunks), probe = AdaptiveProbe()
            let transport = TCPDNSQueryDatagram(route: fallback.route, target: fallback.upstream.target,
                queue: .global(), receive: probe.received, failure: probe.failed,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8,
                dialer: { route, target, _, ready in
                    try? expect(route == decision.route && target == fallback.upstream.target
                                && target.protocolName == "TCP" && DoHEndpoint.isAddressLiteral(target.host),
                                "内存 TCP 回退尝试了替代/global/DIRECT/system/UDP 拨号")
                    guard route == decision.route, target == fallback.upstream.target,
                          target.protocolName == "TCP", DoHEndpoint.isAddressLiteral(target.host) else {
                        ready(.failure(EncryptedDNSQueryFailure.policy)); return nil
                    }
                    ready(.success((stream, Data()))); return {}
                })
            defer { transport.cancel(); transport.drainQueueForSelfTest() }
            transport.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: !succeeds)
            for _ in 0..<8 { transport.drainQueueForSelfTest() }
            try expect(stream.snapshot.writes == [framed(message)] && stream.snapshot.cancellations == 1,
                       "回退未恰好发送一份 TCP DNS 帧或未关闭字节流")
        }
        try exchange([(Data(frame.prefix(1)), false, nil), (Data(frame[1..<7]), false, nil),
                      (Data(frame.dropFirst(7)), true, nil)], succeeds: true)
        var wrongID = answer; wrongID[0] ^= 1
        let wrongName = bootstrapAnswer(try query("wrong.example.test", 1))!
        var extra = frame; extra.append(0)
        for invalid in [framed(wrongID), framed(wrongName), extra, Data(frame.dropLast()), Data([0, 1, 0])] {
            try exchange([(invalid, true, nil)], succeeds: false)
        }
        for revoke in [false, true] {
            let pending = ProxyFallbackDialProbe(), probe = AdaptiveProbe(), gate = AdaptivePolicyGate()
            let stream = ProxyFallbackMemoryStream([(frame, true, nil)])
            let transport = TCPDNSQueryDatagram(route: fallback.route, target: fallback.upstream.target,
                queue: .global(), permitted: gate.permits, receive: probe.received, failure: probe.failed,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8,
                dialer: { _, _, _, ready in pending.begin(ready); return pending.cancel })
            defer { transport.cancel(); transport.drainQueueForSelfTest() }
            transport.send(message); transport.drainQueueForSelfTest()
            try expect(pending.snapshot.calls == 1, "内存 pending beginConnect 未建立")
            if revoke { gate.revoke() }
            else {
                let done = DispatchSemaphore(value: 0)
                transport.cancel { done.signal() }
                try expect(done.wait(timeout: .now() + 2) == .success && pending.snapshot.cancellations == 1,
                           "取消没有撤销 pending beginConnect 或 ACK 过早")
            }
            pending.ready(.success((stream, Data())))
            for _ in 0..<8 { transport.drainQueueForSelfTest() }
            try expect(stream.snapshot.writes.isEmpty && stream.snapshot.cancellations == 1
                       && probe.snapshot.answers.isEmpty, "取消/策略撤销后的 late ready 发出了明文查询")
            if revoke { try expect(probe.snapshot.error != nil, "策略撤销没有 fail closed") }
            else { try expect(probe.snapshot.error == nil, "主动取消仍交付错误/应答") }
        }
    }

    private final class ProxyFallbackMemoryDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding {
        private let lock = NSLock()
        private var barrier: DNSProxyFallbackBarrier?
        private let sendHandler: (Data) -> Void, cancellationBarrier: DNSProxyFallbackBarrier?
        init(cancellationBarrier: DNSProxyFallbackBarrier? = nil, send: @escaping (Data) -> Void) {
            self.cancellationBarrier = cancellationBarrier; sendHandler = send
        }
        func send(_ data: Data) { sendHandler(data) }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); if let cancellationBarrier { barrier = cancellationBarrier }; lock.unlock()
            completion(); completion() // malformed duplicate ACK must not over-leave a DispatchGroup
        }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { lock.lock(); defer { lock.unlock() }; return barrier }
    }

    private static func proxyFallbackAdaptiveBarriers() throws {
        let profile = adaptiveProfile(), source = router(profile), approved = try plan(source)
        let message = try query("allowed.example.test", 1)
        for hidden in [EncryptedDNSQueryFailure.authentication, .other, .capacity] {
            let started = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: DNSAdaptiveUpstreamSelector(),
                scopeKey: approved.healthScopeKey, queue: .global(), permitted: { true },
                factory: { _, _, _, _ in
                    ProxyFallbackMemoryDatagram(cancellationBarrier: .failure(hidden), send: { _ in started.signal() })
                }, receive: { _ in }, failure: { _ in }, protectProxyFallback: true)
            flow.send(message)
            try expect(started.wait(timeout: .now() + 2) == .success, "内存加密 phase 未启动")
            flow.cancel { cancelled.signal() }
            try expect(cancelled.wait(timeout: .now() + 2) == .success, "加密子查询取消 ACK 未完成")
            guard case .failure(let error)? = flow.proxyFallbackBarrier() else {
                throw Failure(text: "ACK 后已 retired 子请求的私有 barrier 丢失")
            }
            try expect(error as? EncryptedDNSQueryFailure == hidden, "ACK 后 hidden barrier 被其他候选覆盖")
        }
        for successfulBackup in [false, true] {
            let probe = AdaptiveProbe()
            let negative = DNSMessageInspection.errorResponse(to: message, code: .servfail)!
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: DNSAdaptiveUpstreamSelector(),
                scopeKey: approved.healthScopeKey, queue: .global(), permitted: { true },
                factory: { candidate, _, receive, failure in
                    ProxyFallbackMemoryDatagram(send: { query in
                        if candidate.id == approved.candidates[0].id { receive(negative) }
                        else if successfulBackup { receive(bootstrapAnswer(query)!) }
                        else { failure(EncryptedDNSQueryFailure.timeout) }
                    })
                }, receive: probe.received, failure: probe.failed, protectProxyFallback: true)
            defer { flow.cancel() }
            flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.answers.first?[3] == (successfulBackup ? 0x80 : 0x82),
                       "SERVFAIL 被 timeout 洗掉或阻止合格加密备用成功")
        }
        var phaseProfile = profile
        phaseProfile.encryptedDNSServers.append("https://third.phase-barrier.selftest.invalid/dns-query#203.0.113.72")
        let phaseApproved = try plan(router(phaseProfile)), ids = phaseApproved.candidates.map(\.id)
        let negative = DNSMessageInspection.errorResponse(to: message, code: .servfail)!
        let positive = bootstrapAnswer(message)!
        let barriers: [DNSProxyFallbackBarrier] = [.failure(EncryptedDNSQueryFailure.authentication),
            .failure(EncryptedDNSQueryFailure.capacity), .answer(negative), .answer(positive)]
        for barrier in barriers {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let flow = DNSAdaptiveQueryDatagram(candidates: phaseApproved.candidates, selector: selector,
                scopeKey: phaseApproved.healthScopeKey, queue: .global(), permitted: { true },
                factory: { candidate, _, _, _ in
                    ProxyFallbackMemoryDatagram(cancellationBarrier: barrier, send: { _ in probe.attempted(candidate) })
                }, receive: probe.received, failure: probe.failed, protectProxyFallback: true)
            defer { flow.cancel() }
            flow.send(message)
            try expect(probe.started.wait(timeout: .now() + 2) == .success, "加密阶段 barrier 查询未启动")
            let acknowledged = DispatchSemaphore(value: 0)
            flow.phaseDeadlineReached { acknowledged.signal() }
            try expect(acknowledged.wait(timeout: .now() + 2) == .success
                       && selector.orderedCandidates(scopeKey: phaseApproved.healthScopeKey, candidateIDs: ids) == ids,
                       "加密阶段 ACK 后认证/容量/合法应答 barrier 被误记为提供商网络超时")
            switch barrier {
            case .failure(let error):
                try expect(probe.snapshot.error.map(EncryptedDNSQueryFailure.classify) == EncryptedDNSQueryFailure.classify(error)
                           && probe.snapshot.answers.isEmpty, "阶段截止擦除了认证或容量错误")
            case .answer(let answer):
                try expect(probe.snapshot.answers == [answer] && probe.snapshot.error == nil,
                           "阶段截止擦除了已准入合法正向或否定应答")
            }
        }
    }

    private static func proxyFallbackEncryptedPhaseHealth() throws {
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let approved = try plan(router(profile)), message = try query("phase-health.example.test", 1)
        let ids = approved.candidates.map(\.id), selector = DNSAdaptiveUpstreamSelector()
        let fallbackStarted = DispatchSemaphore(value: 0)
        func exchange(_ probe: AdaptiveProbe, selector: DNSAdaptiveUpstreamSelector) -> DNSProxyFallbackQueryDatagram {
            DNSProxyFallbackQueryDatagram(queue: .global(qos: .userInitiated),
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8, permitted: { true },
                knownMilliseconds: {
                    ids.compactMap { selector.knownLatencyMilliseconds(scopeKey: approved.healthScopeKey, candidateID: $0) }
                }, encrypted: { queue, absolute, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                        scopeKey: approved.healthScopeKey, queue: queue, permitted: { true },
                        factory: { candidate, _, receive, _ in
                            ProxyFallbackMemoryDatagram(send: { data in
                                probe.attempted(candidate)
                                if candidate.id == ids[2] { receive(bootstrapAnswer(data)!) }
                            })
                        }, receive: receive, failure: failure, absoluteDeadline: absolute,
                        protectProxyFallback: true)
                }, fallback: { _, _, receive, _ in
                    ProxyFallbackMemoryDatagram(send: { data in
                        fallbackStarted.signal(); receive(bootstrapAnswer(data)!)
                    })
                }, receive: probe.received, failure: probe.failed)
        }

        // The first wave must reach its third approved encrypted candidate;
        // learning only after an unnecessary ordinary fallback is too late.
        let firstProbe = AdaptiveProbe(), first = exchange(firstProbe, selector: selector)
        defer { first.cancel() }
        first.send(message); try awaitAdaptive(firstProbe, query: message, waitTimeout: 7)
        try expect(firstProbe.snapshot.attempts == approved.candidates.prefix(3).map { $0.upstream.target.host }
                   && fallbackStarted.wait(timeout: .now()) == .timedOut,
                   "首批查询未等到第三个获准加密候选，或错误启动了普通后备")
        let secondProbe = AdaptiveProbe(), second = exchange(secondProbe, selector: selector)
        defer { second.cancel() }
        second.send(message); try awaitAdaptive(secondProbe, query: message)
        try expect(secondProbe.snapshot.attempts == [approved.candidates[2].upstream.target.host]
                   && fallbackStarted.wait(timeout: .now()) == .timedOut,
                   "加密成功后的健康学习未让下一查询优先使用可用候选")

        let cancelledSelector = DNSAdaptiveUpstreamSelector(), cancelledProbe = AdaptiveProbe()
        let cancelled = exchange(cancelledProbe, selector: cancelledSelector)
        cancelled.send(message)
        try expect(cancelledProbe.started.wait(timeout: .now() + 1) == .success, "待取消加密 phase 未启动")
        let acknowledged = DispatchSemaphore(value: 0)
        cancelled.cancel { acknowledged.signal() }
        try expect(acknowledged.wait(timeout: .now() + 2) == .success
                   && cancelledSelector.orderedCandidates(scopeKey: approved.healthScopeKey, candidateIDs: ids) == ids
                   && cancelledProbe.snapshot.answers.isEmpty && cancelledProbe.snapshot.error == nil,
                   "客户端取消被误记为加密提供商超时或仍交付结果")
    }

    public static func run() throws {
        if let text = UDPPrivacyPolicySelfTest.failure() { throw Failure(text: text) }
        try routing()
        try localServiceDiscoveryRouting()
        try routeDecisionCache()
        try dnsPurposeIsolation()
        try DNSAdaptiveUpstreamSelectorSelfTest.run()
        try adaptiveCandidatePolicy()
        try adaptiveBuiltinAddressVariants()
        try adaptiveEncryptedExchanges()
        try adaptiveLocalCapacityIsolation()
        try productionEncryptedCapacityIsolation()
        try adaptiveShortHedgeBudgets()
        try adaptiveHedgedExchanges()
        try adaptiveParentDeadlineHealth()
        try adaptiveHealthScopeIsolationAndBurst()
        try adaptiveHedgeRotation()
        try adaptiveQueuedAbsoluteDeadlines()
        try directHostnameDNSConfiguration()
        try directAddressResolutionGrace()
        try asynchronousBootstrap()
        try queryPerformancePolicyIsolation()
        try DNSResolverLeaseSelfTest.run()
        try transportScopeAndManyClientBurst()
        try PolicyDNSCallbackQueueSelfTest.run()
        try framing()
        try resourceBudget()
        try framedFakeIPRoundTrip()
        if let text = ProxyEngine.localDNSIsolationSelfTest() { throw Failure(text: text) }
    }

    private static func localServiceDiscoveryRouting() throws {
        let name = "lb._dns-sd._udp.1.168.192.in-addr.arpa"
        let message = try query(name, 12)
        let original = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7263)
        var profile = proxyFallbackProfile()
        profile.dnsServers = []
        profile.encryptedDNSServers = ["https://doh.pub/dns-query#1.12.12.12",
            "https://dns.google/dns-query#8.8.8.8", "https://cloudflare-dns.com/dns-query#1.1.1.1"]
        profile.dnsProxyFallbackEnabled = false; profile.dnsProxyFallbackServers = []
        func requireLocal(_ source: NativePacketRouter, wire: Data = message) throws {
            guard case .answer(let answer, let generation) = try source.prepareDNSQuery(wire, original: original) else {
                throw Failure(text: "标准公共加密配置未本地处理保留反向区DNS-SD")
            }
            var expected = wire; expected[2] = 0x81; expected[3] = 0x80
            try expect(answer == expected && source.isCurrentDNSGenerationForInternal(generation)
                       && DNSMessageInspection.responseMatchesQuery(answer, query: wire),
                       "本地DNS-SD空答丢失ID、大小写、NOERROR或当前代际")
        }
        func requireUpstream(_ value: Profile, wire: Data = message) throws {
            guard case .upstream = try router(value).prepareDNSQuery(wire, original: original) else {
                throw Failure(text: "自定义/企业解析器或普通DNS问题被本地DNS-SD分支覆盖")
            }
        }
        for endpoint in ["https://doh.pub/dns-query", "https://dns.google/dns-query#8.8.4.4",
                         "tls://dot.pub", "https://1.1.1.1/dns-query", "tls://1.1.1.1"] {
            var standard = profile; standard.encryptedDNSServers = [endpoint]
            try requireLocal(router(standard))
        }
        for mode: OutboundMode in [.rule, .proxy, .direct] { try requireLocal(router(profile, mode: mode)) }
        var defaults = profile; defaults.encryptedDNSServers = []
        try requireLocal(router(defaults)) // The effective default is a pinned public resolver.
        for endpoint in ["https://doh.pub/dns-query#192.168.1.53", "https://doh.pub/dns-query#127.0.0.1",
                         "https://doh.pub/dns-query#8.8.8.8", "https://doh.pub/enterprise-query",
                         "https://doh.pub:8443/dns-query", "https://doh.pub/dns-query?profile=private",
                         "https://doh.pub/dns-query?", "https://doh.pub/dns%2Dquery",
                         "https://192.168.1.53/dns-query", "https://enterprise.selftest.invalid/dns-query#1.1.1.1",
                         "https://1.1.1.1/dns-query#8.8.8.8", "tls://dot.pub#192.168.1.53", "tls://dot.pub:8853"] {
            var custom = profile; custom.encryptedDNSServers = [endpoint]
            try requireUpstream(custom)
        }
        for deny in [RuleKind.domain("enterprise.selftest.invalid"), .ipCIDR("192.168.1.53/32")] {
            var enterprise = profile
            enterprise.encryptedDNSServers.append("https://enterprise.selftest.invalid/dns-query#192.168.1.53")
            enterprise.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            let chosen = try plan(router(enterprise), name: name, type: 12, original: original)
            try expect(chosen.candidates.allSatisfy { $0.upstream.isStandardPublicEncryptedResolver },
                       "企业解析器过滤样本没有真正只留下公共候选")
            try requireUpstream(enterprise)
        }
        var partialDeny = profile
        partialDeny.rules.insert(RoutingRule(kind: .domain("doh.pub"), policy: "REJECT", sourceLine: 0), at: 0)
        try requireLocal(router(partialDeny)) // Another approved public resolver remains.
        for selection: DNSSelectionMode in [.balanced, .mixedSpeed] {
            var fallback = profile; fallback.dnsSelectionMode = selection
            fallback.dnsProxyFallbackEnabled = selection == .balanced
            fallback.dnsProxyFallbackServers = ["192.168.1.53"]
            try requireUpstream(fallback)
            fallback.dnsProxyFallbackServers = []
            do { _ = try router(fallback).prepareDNSQuery(message, original: original)
                throw Failure(text: "本地DNS-SD分支掩盖了活动普通DNS后备的无效配置")
            } catch DNSPolicyFailure.configuration {}
        }
        var encryptedOnly = profile
        encryptedOnly.dnsSelectionMode = .encryptedOnly; encryptedOnly.dnsProxyFallbackEnabled = true
        encryptedOnly.dnsProxyFallbackServers = ["192.168.1.53"]
        try requireLocal(router(encryptedOnly)) // Inactive stored fallback settings grant no authority.
        var traditional = profile; traditional.encryptedDNSServers = []; traditional.dnsServers = ["192.168.1.53"]
        try requireUpstream(traditional)
        traditional.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        try requireUpstream(traditional) // A DIRECT secureDefault replacement must not change the original resolver view.
        traditional.dnsServers = []; traditional.dnsLeakProtectionEnabled = false
        try requireUpstream(traditional)
        for remote in ["b._dns-sd._udp.example.test", "b._dns-sd._udp.local",
                       "b._dns-sd._udp.8.8.8.8.in-addr.arpa", "1.1.168.192.in-addr.arpa",
                       "_services._dns-sd._udp.1.168.192.in-addr.arpa"] {
            try requireUpstream(profile, wire: query(remote, 12))
        }
        var edns = message; edns[11] = 1
        edns.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0])
        try requireUpstream(profile, wire: edns)
        for deny in [RuleKind.ipCIDR("203.0.113.53/32"), .domain(name), .sourceIPCIDR("192.0.2.1/32"),
                     .sourcePort(41000...41000), .inboundPort(7263...7263)] {
            var rejected = profile
            rejected.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            for mode: OutboundMode in [.rule, .proxy, .direct] {
                try refusal(router(rejected, mode: mode), name: name, type: 12, original: original)
            }
        }
        for deny in [RuleKind.domain("doh.pub"), .ipCIDR("1.12.12.12/32")] {
            var rejected = profile; rejected.encryptedDNSServers = [profile.encryptedDNSServers[0]]
            rejected.rules.insert(RoutingRule(kind: deny, policy: "REJECT", sourceLine: 0), at: 0)
            for mode: OutboundMode in [.rule, .proxy, .direct] {
                try refusal(router(rejected, mode: mode), name: name, type: 12, original: original)
            }
        }
        for values in [["https://dns.google"], profile.encryptedDNSServers + ["not-an-encrypted-resolver"]] {
            var invalid = profile; invalid.encryptedDNSServers = values
            do { _ = try router(invalid).prepareDNSQuery(message, original: original)
                throw Failure(text: "本地DNS-SD分支掩盖了无效加密解析器配置")
            } catch DNSPolicyFailure.configuration {}
        }

        // Real policy associations use a trapping memory factory: an accidental
        // upstream path fails the test and cannot open a public socket. Hold the
        // actual owner queue across flush/update/cancel to exercise delivery.
        for change in 0..<5 {
            let source = router(profile), replies = AdaptiveProbe(), factory = BootstrapProbe()
            let parent = DispatchQueue(label: "app.hajimi.dns.local-discovery-self-test.\(change)")
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let flow = try PolicyDNSDatagram(router: source, original: original, queue: parent,
                synthesizeFakeIP: false, receive: replies.received, failure: replies.failed,
                queryTimeout: .milliseconds(150), upstreamFactory: { _, _, _ in
                    factory.lock.lock(); factory.builds += 1; factory.lock.unlock()
                    throw Failure(text: "本地DNS-SD意外调用上游工厂")
                })
            defer { release.signal(); flow.cancel(); flow.drainQueueForSelfTest(); parent.sync {} }
            parent.async { entered.signal(); _ = release.wait(timeout: .now() + 2) }
            try expect(entered.wait(timeout: .now() + 2) == .success, "DNS-SD交付队列未进入受控排队")
            flow.send(message)
            try expect(replies.done.wait(timeout: .now()) == .timedOut, "本地DNS-SD绕过owner队列提前回包")
            if change == 1 || change == 4 { source.flushDNS() }
            if change == 2 {
                var rejected = profile
                rejected.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)]
                source.update(profile: rejected, mode: .rule, globalPolicy: "Node", groupSelections: [:])
            }
            if change >= 3 { flow.cancel() }
            release.signal(); flow.drainQueueForSelfTest(); parent.sync {}
            if change >= 3 {
                try expect(replies.done.wait(timeout: .now()) == .timedOut
                           && replies.snapshot.answers.isEmpty && replies.snapshot.error == nil,
                           "已取消DNS-SD交付了旧空答或错误回调")
            } else {
                try expect(replies.done.wait(timeout: .now() + 2) == .success, "本地DNS-SD没有完成队列交付")
                let result = replies.snapshot
                let code: UInt8 = change == 0 ? 0 : 2
                try expect(result.error == nil && result.answers.count == 1
                           && DNSMessageInspection.responseMatchesQuery(result.answers[0], query: message)
                           && result.answers[0][3] & 15 == code,
                           "本地DNS-SD跨代际交付旧NOERROR或没有返回一次SERVFAIL")
                if change == 1 {
                    let fresh = try query(name, 12, id: 0x4646)
                    flow.send(fresh)
                    try expect(replies.done.wait(timeout: .now() + 2) == .success, "flush后新DNS-SD问题没有完成")
                    try expect(replies.snapshot.answers.count == 2
                               && DNSMessageInspection.responseMatchesQuery(replies.snapshot.answers[1], query: fresh)
                               && replies.snapshot.answers[1][3] & 15 == 0,
                               "旧代际SERVFAIL影响了新代际DNS-SD本地空答")
                }
            }
            flow.drainQueueForSelfTest()
            factory.lock.lock(); let builds = factory.builds; factory.lock.unlock()
            try expect(builds == 0, "本地DNS-SD创建了上游transport、共享查询或连接")
        }
        // An excluded private/custom view still enters the real coordinator;
        // its only transport is this explicit, immediate memory responder.
        for endpoint in ["https://doh.pub/dns-query#192.168.1.53", "https://doh.pub/enterprise-query"] {
            var custom = profile; custom.encryptedDNSServers = [endpoint]
            let source = router(custom), replies = AdaptiveProbe(), factory = BootstrapProbe()
            let flow = try PolicyDNSDatagram(router: source, original: original, queue: .global(),
                synthesizeFakeIP: false, receive: replies.received, failure: replies.failed,
                queryTimeout: .seconds(2), upstreamFactory: { _, receive, _ in
                    factory.lock.lock(); factory.builds += 1; factory.lock.unlock()
                    return BootstrapMemoryTransport { data in receive(bootstrapAnswer(data)!) }
                })
            defer { flow.cancel(); flow.drainQueueForSelfTest() }
            flow.send(message)
            try expect(replies.done.wait(timeout: .now() + 2) == .success, "自定义DNS视图未进入内存上游")
            flow.drainQueueForSelfTest()
            factory.lock.lock(); let builds = factory.builds; factory.lock.unlock()
            try expect(builds == 1 && replies.snapshot.error == nil && replies.snapshot.answers.count == 1
                       && DNSMessageInspection.responseMatchesQuery(replies.snapshot.answers[0], query: message),
                       "自定义DNS视图被本地空答覆盖或没有经过真实coordinator")
        }
        print("DNS-SD local routing: public-only endpoint gate, enterprise/fallback ownership, full policy/configuration checks, zero upstream calls and epoch/cancel delivery fences passed")
    }

    private static func transportScopeAndManyClientBurst() throws {
        let makeRouter: DNSTransportScopeSelfTest.MakeRouter = { profile, dialer in
            // No wire plaintext fallback, real helper, listener or configurable
            // trust override is allowed in this private memory-only factory.
            precondition(!profile.dnsProxyFallbackEnabled && !profile.fakeIPEnabled)
            let value = router(profile, global: "DIRECT")
            value.memoryFixtureDNSStreamDialer = dialer
            return value
        }
        try DNSTransportScopeSelfTest.run(makeRouter: makeRouter, inspect: { value, query, original, interface in
            guard case .upstream(let decision) = try value.prepareDNSQuery(query, original: original,
                                                                           synthesizeFakeIP: false) else {
                throw Failure(text: "传输复用回归查询被意外合成")
            }
            let snapshot = value.dnsRoutingSnapshotForSelfTest()
            return DNSTransportScopeSelfTest.ScopeSnapshot(queryScope: decision.scopeKey,
                transportScope: snapshot.transportScope(upstream: decision.upstream, route: decision.route,
                    interfaceName: interface ?? decision.interfaceName), generation: decision.generation)
        })
        try DNSEpochTransitionSelfTest.run(makeRouter: makeRouter,
            installAfterFlushGate: { $0.memoryFixtureAfterDNSFlushUnlock = $1 },
            drainFlow: { ($0 as? PolicyDNSDatagram)?.drainQueueForSelfTest() })
    }

    private static func routeDecisionCache() throws {
        let source = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7263)
        func snapshot(_ profile: Profile, mode: OutboundMode = .rule, global: String = "DIRECT",
                      selections: [String: String] = [:], cache: DNSRouteDecisionCache? = nil) -> DNSRoutingSnapshot {
            DNSRoutingSnapshot(profile: profile, mode: mode, globalPolicy: global,
                selections: selections, generation: 7,
                sourcePortSensitive: DNSRoutingSnapshot.usesSourcePortRules(profile), routeCache: cache)
        }
        var basic = Profile()
        basic.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        do {
            let cache = DNSRouteDecisionCache(), cached = snapshot(basic, cache: cache)
            try expect(cached.route(source) == snapshot(basic).route(source), "路由决策缓存改变冷态结果")
            _ = cached.route(source)
            var ephemeral = source; ephemeral.sourcePort = 41001
            _ = cached.route(ephemeral)
            try expect(cache.snapshotForSelfTest.entries == 1 && cache.snapshotForSelfTest.hits == 2,
                       "同一上下文或无 SRC-PORT 规则的临时端口未命中决策缓存")
            var variants: [RequestTarget] = []
            var value = source; value.sourceHost = nil; variants.append(value)
            value = source; value.sourceHost = ""; variants.append(value)
            value = source; value.sourceHost = "192.0.2.2"; variants.append(value)
            value = source; value.host = "203.0.113.54"; variants.append(value)
            value = source; value.port = 5353; variants.append(value)
            value = source; value.protocolName = "TCP"; variants.append(value)
            value = source; value.inboundPort = nil; variants.append(value)
            value = source; value.inboundPort = 0; variants.append(value)
            value = source; value.inboundPort = 7264; variants.append(value)
            for target in variants {
                try expect(cached.route(target) == snapshot(basic).route(target), "元数据决策缓存改变路由")
            }
            _ = cached.route(source, name: "one.example.test")
            _ = cached.route(source, name: "two.example.test")
            _ = cached.route(source, name: "")
            _ = cached.route(source, mode: .proxy)
            _ = cached.route(source, mode: .direct)
            try expect(cache.snapshotForSelfTest.entries == variants.count + 6,
                       "决策缓存混合 nil/空值、原地址/QNAME、协议或模式")
        }
        do {
            var denied = basic
            denied.rules = [
                RoutingRule(kind: .domain("blocked.example.test"), policy: "REJECT", sourceLine: 1),
                RoutingRule(kind: .ipCIDR("203.0.113.54/32"), policy: "REJECT", sourceLine: 2),
                RoutingRule(kind: .sourceIPCIDR("192.0.2.2/32"), policy: "REJECT", sourceLine: 3),
                RoutingRule(kind: .logicalAnd([.sourcePort(41001...41001), .protocolName("UDP")]),
                    policy: "REJECT", sourceLine: 4),
                RoutingRule(kind: .inboundPort(7264...7264), policy: "REJECT", sourceLine: 5),
                RoutingRule(kind: .destinationPort(5353...5353), policy: "REJECT", sourceLine: 6),
                RoutingRule(kind: .protocolName("TCP"), policy: "REJECT", sourceLine: 7),
                RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 8)]
            let cached = snapshot(denied, cache: DNSRouteDecisionCache()), plain = snapshot(denied)
            try expect(cached.route(source) == .direct("DIRECT"), "拒绝样本错误地覆盖允许上下文")
            var targets: [(RequestTarget, String?)] = [(source, "blocked.example.test")]
            var value = source; value.host = "203.0.113.54"; targets.append((value, nil))
            value = source; value.sourceHost = "192.0.2.2"; targets.append((value, nil))
            value = source; value.sourcePort = 41001; targets.append((value, nil))
            value = source; value.inboundPort = 7264; targets.append((value, nil))
            value = source; value.port = 5353; targets.append((value, nil))
            value = source; value.protocolName = "TCP"; targets.append((value, nil))
            for (target, name) in targets {
                for _ in 0..<2 {
                    let decision = cached.route(target, name: name)
                    guard case .reject = decision else { throw Failure(text: "热决策缓存绕过 REJECT") }
                    try expect(decision == plain.route(target, name: name), "缓存和完整拒绝匹配不一致")
                }
            }
            let reference = RuleSetReference(location: "memory.route-cache.source-port")
            denied.ruleSetContents[reference.location] = [.logicalNot(.logicalNot(.sourcePort(41001...41001)))]
            denied.rules = [RoutingRule(kind: .ruleSet(reference), policy: "REJECT", sourceLine: 1),
                            RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2)]
            let nestedCache = DNSRouteDecisionCache(), nested = snapshot(denied, cache: nestedCache)
            try expect(nested.sourcePortSensitive && nested.route(source) == .direct("DIRECT"),
                       "嵌套规则集未检测 SRC-PORT 敏感性")
            value = source; value.sourcePort = 41001
            try expect(nested.route(value) == .reject("REJECT"), "嵌套 SRC-PORT 拒绝继承了允许端口")
            value.sourcePort = nil; _ = nested.route(value)
            value.sourcePort = 0; _ = nested.route(value)
            try expect(nestedCache.snapshotForSelfTest.entries == 4, "敏感源端口的 nil/零值被混同")
        }
        do {
            let kinds: [RuleKind] = [
                .logicalOr([.domain("blocked.example.test"), .sourceIPCIDR("192.0.2.2/32")]),
                .logicalAnd([.logicalNot(.domain("allowed.example.test")), .protocolName("UDP")]),
                .logicalNot(.logicalOr([.domain("allowed.example.test"), .destinationPort(443...443)]))]
            for kind in kinds {
                var logical = basic
                logical.rules.insert(RoutingRule(kind: kind, policy: "REJECT", sourceLine: 0), at: 0)
                let cached = snapshot(logical, cache: DNSRouteDecisionCache()), plain = snapshot(logical)
                for name in ["allowed.example.test", "blocked.example.test"] {
                    for _ in 0..<2 {
                        try expect(cached.route(source, name: name) == plain.route(source, name: name),
                                   "AND/OR/NOT 复合规则的热缓存改变了完整匹配")
                    }
                }
            }
        }
        do {
            var provider = basic
            provider.rules.insert(RoutingRule(kind: .ipCIDR("1.0.0.1/32"), policy: "REJECT", sourceLine: 0), at: 0)
            let first = DNSConfiguredUpstream.doh(DoHEndpoint("https://cloudflare-dns.com/dns-query#1.1.1.1")!)
            let second = DNSConfiguredUpstream.doh(DoHEndpoint("https://cloudflare-dns.com/dns-query#1.0.0.1")!)
            let cached = snapshot(provider, cache: DNSRouteDecisionCache())
            for _ in 0..<2 {
                try cached.requireAllowedResolver(first, original: source)
                do { try cached.requireAllowedResolver(second, original: source)
                    throw Failure(text: "同 provider 的第二个 IP 绕过拒绝")
                } catch DNSPolicyFailure.refused {}
            }
            provider.rules[0] = RoutingRule(kind: .domain("cloudflare-dns.com"), policy: "REJECT", sourceLine: 0)
            let identity = snapshot(provider, cache: DNSRouteDecisionCache())
            for upstream in [first, second] {
                do { try identity.requireAllowedResolver(upstream, original: source)
                    throw Failure(text: "provider 身份拒绝被 IP 决策缓存绕过")
                } catch DNSPolicyFailure.refused {}
            }
        }
        do {
            var grouped = basic
            let one = ProxyPolicy(name: "One", kind: .native, host: "203.0.113.10", port: 443,
                                  adapterType: "trojan", parameters: ["password": "memory-only"])
            let two = ProxyPolicy(name: "Two", kind: .native, host: "203.0.113.11", port: 443,
                                  adapterType: "trojan", parameters: ["password": "memory-only"])
            grouped.proxies[one.name] = one; grouped.proxies[two.name] = two
            grouped.groups["Balanced"] = PolicyGroup(name: "Balanced", kind: .loadBalance, members: [one.name, two.name])
            let cache = DNSRouteDecisionCache()
            let cached = snapshot(grouped, mode: .proxy, global: "Balanced", cache: cache)
            let plain = snapshot(grouped, mode: .proxy, global: "Balanced")
            var variants = [source]
            var value = source; value.host = "203.0.113.54"; variants.append(value)
            value = source; value.port = 443; variants.append(value)
            value = source; value.protocolName = "TCP"; variants.append(value)
            for target in variants {
                try expect(cached.route(target) == plain.route(target) && cached.route(target) == plain.route(target),
                           "load-balance 决策缓存丢失 host/port/protocol 哈希")
            }
            value = source; value.sourcePort = 41001
            try expect(cached.route(value) == plain.route(source) && cache.snapshotForSelfTest.entries == variants.count,
                       "load-balance 意外依赖无规则观察的临时源端口")
            let selected = snapshot(grouped, mode: .proxy, global: "Balanced",
                                    selections: ["Balanced": two.name], cache: DNSRouteDecisionCache())
            try expect(selected.route(source) == .native(two, two.name), "新的策略组选项继承旧快照决策")
            let routed = NativePacketRouter(profile: grouped, mode: .proxy, globalPolicy: "Balanced",
                                             groupSelections: ["Balanced": one.name])
            let before = routed.dnsRoutingSnapshotForSelfTest()
            try expect(before.route(source) == .native(one, one.name), "策略组更新样本未预热旧决策")
            routed.update(profile: grouped, mode: .proxy, globalPolicy: "Balanced",
                          groupSelections: ["Balanced": two.name])
            let after = routed.dnsRoutingSnapshotForSelfTest()
            try expect(after.routeCache !== before.routeCache && after.route(source) == .native(two, two.name),
                       "同一 profile 的策略组选项更新未替换决策 epoch")
            let loop = PolicyGroup(name: "Loop", members: ["Loop"])
            grouped.groups[loop.name] = loop
            let cyclic = snapshot(grouped, mode: .proxy, global: loop.name, cache: DNSRouteDecisionCache())
            try expect(cyclic.route(source) == snapshot(grouped, mode: .proxy, global: loop.name).route(source),
                       "策略组循环被缓存改为直连")
        }
        do {
            var recursive = basic
            let loop = RuleSetReference(location: "memory.route-cache.loop")
            recursive.rules.insert(RoutingRule(kind: .ruleSet(loop), policy: "DIRECT", sourceLine: 0), at: 0)
            recursive.ruleSetContents[loop.location] = [.ruleSet(loop)]
            let cached = snapshot(recursive, cache: DNSRouteDecisionCache())
            for _ in 0..<2 {
                guard case .reject = cached.route(source) else { throw Failure(text: "规则集循环没有 fail closed") }
                try expect(cached.route(source) == snapshot(recursive).route(source), "循环规则缓存改变拒绝原因")
            }
            var deep: RuleKind = .domain("unmatched.example.test")
            for _ in 0..<40 { deep = .logicalNot(deep) }
            recursive.rules[0] = RoutingRule(kind: deep, policy: "DIRECT", sourceLine: 0)
            let depth = snapshot(recursive, cache: DNSRouteDecisionCache())
            guard case .reject = depth.route(source) else { throw Failure(text: "超深逻辑规则缓存没有 fail closed") }
            var finalFirst = recursive
            finalFirst.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1),
                                RoutingRule(kind: .final, policy: "REJECT", sourceLine: 2)]
            try expect(snapshot(finalFirst, cache: DNSRouteDecisionCache()).route(source) == .direct("DIRECT"),
                       "缓存改变了 FINAL 的首条命中语义")
        }
        do {
            let cache = DNSRouteDecisionCache(maximumEntries: 2), cached = snapshot(basic, cache: cache)
            for name in ["one.example.test", "two.example.test", "three.example.test", "one.example.test"] {
                try expect(cached.route(source, name: name) == snapshot(basic).route(source, name: name),
                           "FIFO 淘汰改变了路由结果")
            }
            try expect(cache.snapshotForSelfTest.entries == 2, "决策缓存容量没有上限")
            let before = cache.snapshotForSelfTest
            let longName = String(repeating: "x", count: 2_048)
            _ = cached.route(source, name: longName); _ = cached.route(source, name: longName)
            try expect(cache.snapshotForSelfTest.entries == before.entries && cache.snapshotForSelfTest.hits == before.hits,
                       "超长决策 key 被缓存并延长了生命周期")
            let disabled = DNSRouteDecisionCache(maximumEntries: 0)
            _ = snapshot(basic, cache: disabled).route(source)
            try expect(disabled.snapshotForSelfTest.entries == 0, "零容量缓存仍保留决策")
        }
        do {
            var concurrentProfile = basic
            concurrentProfile.rules.insert(RoutingRule(kind: .domain("blocked.example.test"),
                policy: "REJECT", sourceLine: 0), at: 0)
            let cache = DNSRouteDecisionCache(maximumEntries: 8)
            let cached = snapshot(concurrentProfile, cache: cache), plain = snapshot(concurrentProfile)
            let lock = NSLock(); var matched = true
            DispatchQueue.concurrentPerform(iterations: 64) { index in
                var target = source; target.sourcePort = UInt16(42000 + index)
                let name = index % 2 == 0 ? "allowed.example.test" : "blocked.example.test"
                if cached.route(target, name: name) != plain.route(target, name: name) {
                    lock.lock(); matched = false; lock.unlock()
                }
            }
            try expect(matched && cache.snapshotForSelfTest.entries == 2,
                       "并发 miss 覆盖了拒绝决策或重复预留了缓存容量")
        }
        do {
            let routed = router(basic), old = routed.dnsRoutingSnapshotForSelfTest()
            _ = old.route(source)
            let release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
            defer { release.signal() }
            DispatchQueue.global(qos: .userInitiated).async {
                release.wait()
                _ = old.route(source, name: "late.example.test")
                done.signal()
            }
            routed.flushDNS()
            let fresh = routed.dnsRoutingSnapshotForSelfTest()
            try expect(old.routeCache !== fresh.routeCache && !routed.isCurrentDNSGenerationForInternal(old.generation),
                       "flush 重置了旧对象而非替换决策缓存 epoch")
            release.signal()
            try expect(done.wait(timeout: .now() + 2) == .success && fresh.routeCache?.snapshotForSelfTest.entries == 0,
                       "旧快照迟到计算污染了新 epoch")
            var changed = basic
            changed.rules[0] = RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)
            routed.update(profile: changed, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            let updated = routed.dnsRoutingSnapshotForSelfTest()
            try expect(updated.routeCache !== fresh.routeCache && updated.route(source) == .reject("REJECT"),
                       "profile 更新继承旧允许决策或未替换缓存")
            try refusal(routed, name: "allowed.example.test", type: 1, original: source)
        }
        do {
            var changing = basic
            let reference = RuleSetReference(location: "memory.route-cache.contents")
            changing.rules = [RoutingRule(kind: .ruleSet(reference), policy: "DIRECT", sourceLine: 1),
                              RoutingRule(kind: .final, policy: "REJECT", sourceLine: 2)]
            changing.ruleSetContents[reference.location] = [.domain("allowed.example.test")]
            let routed = router(changing), before = routed.dnsRoutingSnapshotForSelfTest()
            try expect(before.route(source, name: "allowed.example.test") == .direct("DIRECT"),
                       "规则集内容更新样本未预热允许决策")
            changing.ruleSetContents[reference.location] = [.domain("other.example.test")]
            routed.update(profile: changing, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            let after = routed.dnsRoutingSnapshotForSelfTest()
            try expect(before.routeCache !== after.routeCache
                       && after.route(source, name: "allowed.example.test") == .reject("REJECT"),
                       "主规则未变的规则集更新继承旧允许缓存")
        }
        do {
            let before = NetworkPerformanceDiagnostics.shared.snapshot()
            _ = try plan(router(basic), original: source)
            let after = NetworkPerformanceDiagnostics.shared.snapshot()
            try expect(after.dnsQueries == before.dnsQueries && after.dnsFailures == before.dnsFailures
                       && after.stages[.dnsPolicyPreparation]?.count
                            == (before.stages[.dnsPolicyPreparation]?.count ?? 0) + 1,
                       "策略准备计量重复统计逻辑 DNS 或没有覆盖 cache 前工作")
        }
    }

    private static func queryPerformancePolicyIsolation() throws {
        var profile = Profile()
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let routed = router(profile)
        let probe = BootstrapProbe()
        let queue = DispatchQueue(label: "app.hajimi.dns.policy-cache-self-test")
        let message = try query("allowed.example.test", 1)
        let source = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
                                   sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7263)
        func exchange(_ decision: DNSQueryPlan, query: Data? = nil) throws {
            let query = query ?? message
            let complete = DispatchSemaphore(value: 0), lock = NSLock()
            var valid = false
            let transport = try routed.makeOptimizedDNSUpstream(plan: decision, queue: queue,
                factory: { _, receive, _ in
                    probe.lock.lock(); probe.builds += 1; probe.lock.unlock()
                    return BootstrapMemoryTransport { request in
                        if let response = bootstrapAnswer(request) { receive(response) }
                    }
                }, receive: { answer in
                    lock.lock(); valid = DNSMessageInspection.responseMatchesQuery(answer, query: query); lock.unlock()
                    complete.signal()
                }, failure: { _ in complete.signal() })
            defer { transport.cancel() }
            transport.send(query)
            try expect(complete.wait(timeout: .now() + 3) == .success, "策略缓存回包超时")
            lock.lock(); let accepted = valid; lock.unlock()
            try expect(accepted, "策略缓存回包丢失 ID 或问题身份")
        }
        let first = try plan(routed, original: source)
        try exchange(first)
        var other = source; other.sourcePort = 41001
        let ephemeral = try plan(routed, original: other)
        try expect(first.scopeKey == ephemeral.scopeKey, "无源端口规则时临时 UDP 端口破坏缓存命中")
        try exchange(ephemeral, query: try query("allowed.example.test", 1, id: 0x4546))
        probe.lock.lock(); let warmBuilds = probe.builds; probe.lock.unlock()
        try expect(warmBuilds == 1, "缓存命中仍创建第二个上游")
        other.sourceHost = "192.0.2.2"
        try expect(first.scopeKey != (try plan(routed, original: other)).scopeKey, "缓存跨来源 IP 共享")
        other = source; other.inboundPort = 7264
        try expect(first.scopeKey != (try plan(routed, original: other)).scopeKey, "缓存跨入站端口共享")
        other = source; other.host = "203.0.113.54"
        try expect(first.scopeKey != (try plan(routed, original: other)).scopeKey, "缓存丢失原 DNS 目的地址")
        other = source; other.protocolName = "TCP"
        try expect(first.scopeKey != (try plan(routed, original: other)).scopeKey, "缓存丢失 UDP/TCP 身份")

        let nested = RuleSetReference(location: "memory.source-port.selftest")
        profile.ruleSetContents[nested.location] = [.logicalNot(.logicalNot(.sourcePort(41001...41001)))]
        profile.rules = [RoutingRule(kind: .ruleSet(nested), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2)]
        routed.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
        let portScoped = try plan(routed, original: source)
        other = source; other.sourcePort = 41002
        try expect(portScoped.scopeKey != (try plan(routed, original: other)).scopeKey,
                   "嵌套规则集 SRC-PORT 没有隔离缓存")
        other.sourcePort = 41001
        try refusal(routed, name: "allowed.example.test", type: 1, original: other)
        try exchange(portScoped)
        probe.lock.lock(); let changedBuilds = probe.builds; probe.lock.unlock()
        try expect(changedBuilds == 2, "策略更新未撤销旧缓存")

        for deny in [RuleKind.domain("allowed.example.test"), .ipCIDR("203.0.113.53/32"),
                     .domain("cloudflare-dns.com"), .ipCIDR("1.1.1.1/32")] {
            profile.rules = [RoutingRule(kind: deny, policy: "REJECT", sourceLine: 1),
                             RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2)]
            routed.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            try refusal(routed, name: "allowed.example.test", type: 1, original: source)
        }
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        routed.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
        let beforeFlush = try plan(routed, original: source)
        try exchange(beforeFlush)
        routed.flushDNS()
        try expect(!routed.isCurrentDNSGenerationForInternal(beforeFlush.generation), "清空 DNS 未撤销在途查询代次")
        try exchange(try plan(routed, original: source))
        probe.lock.lock(); let flushedBuilds = probe.builds; probe.lock.unlock()
        try expect(flushedBuilds == 4, "清空 DNS 后仍返回旧缓存")
    }

    private static func resourceBudget() throws {
        let budget = SOCKSUDPGlobalBudget(resources: 2, packets: 4, bytes: 8)
        guard let first = DNSQueryResourceBudget.reserve(bytes: 4, budget: budget),
              let second = DNSQueryResourceBudget.reserve(bytes: 4, budget: budget) else {
            throw Failure(text: "DNS 事务资源预算样本无法预留")
        }
        try expect(DNSQueryResourceBudget.reserve(bytes: 0, budget: budget) == nil,
                   "DNS TCP 事务绕过全局连接名额上限")
        try expect(budget.usage.resources == 2 && budget.usage.packets == 2 && budget.usage.bytes == 8,
                   "DNS 拒绝的事务遗留连接/载荷名额")
        first.payload.release(); first.connection.release()
        guard let replacement = DNSQueryResourceBudget.reserve(bytes: 0, budget: budget) else {
            throw Failure(text: "DNS 已释放的连接名额无法复用")
        }
        second.payload.release(); second.connection.release()
        replacement.payload.release(); replacement.connection.release()
        try expect(DNSQueryResourceBudget.reserve(bytes: 9, budget: budget) == nil
                   && DNSQueryResourceBudget.reserve(bytes: -1, budget: budget) == nil,
                   "DNS 无效或超预算载荷被接受")
        try expect(budget.usage.resources == 0 && budget.usage.packets == 0 && budget.usage.bytes == 0,
                   "DNS 拒绝、完成或取消后没有释放全局预算")
    }

    private static func routing() throws {
        var profile = Profile()
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                               adapterType: "trojan", parameters: ["password": "test"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        let target = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")
        let kinds: [UInt16] = [1, 28, 15, 16, 64, 65, 255]
        for mode: OutboundMode in [.proxy, .rule] {
            let routed = router(profile, mode: mode)
            for type in kinds {
                let decision = try plan(routed, type: type)
                try expect(decision.route == .native(node, node.name), "QTYPE \(type) 丢失选定代理")
                try expect(decision.upstream.encrypted, "默认查询不是加密 DNS")
                try expect(DoHEndpoint.isAddressLiteral(decision.upstream.target.host), "解析器使用隐式系统 bootstrap")
            }
        }
        profile.dnsServers = ["udp://203.0.113.60:5353"]
        let plainProxy = try plan(router(profile, mode: .proxy))
        try expect(plainProxy.route == .native(node, node.name) && !plainProxy.upstream.encrypted,
                   "自定义明文 DNS 未保持代理承载")
        let transport = try router(profile).makeDNSUpstream(plan: plainProxy, queue: .global(),
                                                           receive: { _ in }, failure: { _ in })
        try expect(transport is TCPDNSQueryDatagram, "无 UDP 的 DNS 被降级为直接套接字")
        transport.cancel()

        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let direct = try plan(router(profile))
        try expect(direct.upstream.encrypted && direct.upstream.target.host == "1.1.1.1",
                   "DIRECT 规则下明文 DNS 未替换成固定 bootstrap 加密 DNS")
        profile.dnsLeakProtectionEnabled = false
        let optedOut = try plan(router(profile))
        try expect(!optedOut.upstream.encrypted && optedOut.upstream.target.port == 5353,
                   "显式关闭保护未保留明文 DNS 兼容配置")
        profile.dnsLeakProtectionEnabled = true
        profile.dnsServers = []
        profile.fakeIPEnabled = true
        profile.rules = [RoutingRule(kind: .domain("blocked.example.test"), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .final, policy: node.name, sourceLine: 2)]
        let mixed = router(profile)
        for type in kinds { try refusal(mixed, name: "blocked.example.test", type: type) }
        let flow = try mixed.makeDNSDatagram(original: target, queue: .global(),
                                            receive: { _ in }, failure: { _ in })
        flow.cancel()
        for type in [UInt16(15), 16, 64, 65, 255] {
            let decision = try plan(mixed, type: type)
            try expect(decision.route == .native(node, node.name), "fake-IP 非 A/AAAA 查询绕过代理")
        }
        profile.alwaysRealIP = ["*.example.test"]
        let real = try plan(router(profile))
        try expect(real.route == .native(node, node.name), "fake-IP filter 将真实查询降级 DIRECT")

        // Denies are checked even in global-proxy mode, including original
        // address, QNAME, actual bootstrap address and resolver identity.
        profile.fakeIPEnabled = false; profile.alwaysRealIP = []
        for rule in [RuleKind.ipCIDR("203.0.113.53/32"), .domain("blocked.example.test"),
                     .ipCIDR("1.1.1.1/32"), .domain("cloudflare-dns.com")] {
            profile.rules = [RoutingRule(kind: rule, policy: "REJECT", sourceLine: 1),
                             RoutingRule(kind: .final, policy: node.name, sourceLine: 2)]
            let rejected = router(profile, mode: .proxy)
            for type in kinds { try refusal(rejected, name: "blocked.example.test", type: type) }
        }

        profile.rules = [RoutingRule(kind: .logicalAnd([.domain("logical.example.test"),
            .destinationPort(53...53), .protocolName("UDP"), .sourceIPCIDR("127.0.0.0/8"), .inboundPort(7263...7263)]),
            policy: node.name, sourceLine: 1), RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2)]
        let source = RequestTarget(host: target.host, port: 53, protocolName: "UDP",
                                   sourceHost: "127.0.0.1", sourcePort: 12345, inboundPort: 7263)
        let logical = try plan(router(profile), name: "logical.example.test", original: source)
        try expect(logical.route == .native(node, node.name) && logical.original == source,
                   "逻辑 QNAME 规则丢失原目的、协议或入站元数据")
        var tcp = source; tcp.protocolName = "TCP"
        let tcpDecision = try plan(router(profile), name: "logical.example.test", original: tcp)
        try expect(tcpDecision.route == .direct("DIRECT") && tcpDecision.original.protocolName == "TCP",
                   "TCP 查询被错误标记为 UDP")

        for invalid in ["https://unknown.invalid/dns-query", "https://dns.google", "tls://unknown.invalid",
                        "http://1.1.1.1/dns-query", "udp://1.1.1.1:0", "1.1.1.1:garbage"] {
            profile.dnsServers = [invalid]
            do { _ = try plan(router(profile)) }
            catch DNSPolicyFailure.configuration { continue }
            throw Failure(text: "坏 DNS 配置静默回退：\(invalid)")
        }

        profile.dnsServers = []; profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        let changed = router(profile)
        let old = try plan(changed)
        profile.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)]
        changed.update(profile: profile, mode: .rule, globalPolicy: node.name, groupSelections: [:])
        try expect(!changed.isCurrentDNSGenerationForInternal(old.generation), "策略切换没有撤销旧 DNS generation")
        try refusal(changed, name: "allowed.example.test", type: 65)
    }

    private static func dnsPurposeIsolation() throws {
        var profile = Profile()
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                               adapterType: "trojan", parameters: ["password": "test"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        profile.dnsServers = ["malformed-traditional:bad", "system", "198.18.16.2"]
        profile.encryptedDNSServers = ["https://203.0.113.77/dns-query"]
        for protection in [true, false] {
            profile.dnsLeakProtectionEnabled = protection
            for type: UInt16 in [1, 16, 28, 65] {
                let decision = try plan(router(profile), type: type)
                try expect(decision.upstream.encrypted && decision.upstream.target.host == "203.0.113.77"
                           && decision.bootstrap == nil, "已固定加密 DNS 被无关传统配置阻断或降级")
            }
        }
        profile.encryptedDNSServers = []
        profile.dnsServers = ["203.0.113.60", "https://203.0.113.77/dns-query"]
        try expect(try plan(router(profile)).upstream.encrypted, "旧混合 dns-server 中的加密条目被降级传统")
        for invalid in ["not-an-encrypted-url", "http://203.0.113.77/dns-query",
                        "https://dns.google", "https://dns.google/dns-query#hostname.invalid"] {
            profile.encryptedDNSServers = [invalid]
            do { _ = try plan(router(profile)) }
            catch DNSPolicyFailure.configuration { continue }
            throw Failure(text: "无效 encrypted-dns-server 回退旧传统/加密条目")
        }
        profile.encryptedDNSServers = ["https://doh.bootstrap.selftest.invalid/dns-query"]
        profile.dnsServers = []
        do { _ = try plan(router(profile)) }
        catch DNSPolicyFailure.configuration { profile.dnsServers = ["203.0.113.60:5353"] }
        guard !profile.dnsServers.isEmpty else { throw Failure(text: "未固定未知 DoH 无传统引导仍被接受") }
        let deferred = try plan(router(profile))
        guard case .doh(let endpoint) = deferred.upstream else { throw Failure(text: "延后引导丢失 DoH 类型") }
        try expect(endpoint.needsBootstrap && deferred.bootstrap?.allowedHosts == [endpoint.host],
                   "未知 DoH 未进入专用白名单引导路径")
        for invalid in ["system", "hostname.invalid", "198.18.16.2", "198.19.0.1", "[::ffff:198.18.16.2]"] {
            profile.dnsServers = [invalid]
            do { _ = try plan(router(profile)) }
            catch DNSPolicyFailure.configuration { continue }
            throw Failure(text: "DoH 引导接受系统、非数字或递归传统 DNS 地址")
        }
        profile.dnsServers = ["203.0.113.60:5353"]
        for deny in [RuleKind.ipCIDR("203.0.113.60/32"), .domain(endpoint.host)] {
            profile.rules = [RoutingRule(kind: deny, policy: "REJECT", sourceLine: 1),
                             RoutingRule(kind: .final, policy: node.name, sourceLine: 2)]
            try refusal(router(profile, mode: .proxy), name: "private.user.example.test", type: 65)
        }
        profile.rules = [RoutingRule(kind: .ipCIDR("203.0.113.77/32"), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .final, policy: node.name, sourceLine: 2)]
        let deniedIP = router(profile, mode: .proxy), decision = try plan(deniedIP)
        do { _ = try deniedIP.resolvedBootstrapPlan(decision, address: "203.0.113.77") }
        catch DNSPolicyFailure.refused { return }
        throw Failure(text: "DoH 域名被允许后绕过新引导 IP 的 REJECT")
    }

    private static func directHostnameDNSConfiguration() throws {
        var profile = Profile()
        profile.dnsLeakProtectionEnabled = false
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        profile.dnsServers = ["203.0.113.60"]
        try expect(!DNSApplicationResolutionPolicy.usesQueryRouter(profile),
                   "无加密 DNS 的 legacy opt-out 改变应用 DIRECT 解析路径")
        profile.encryptedDNSServers = ["https://203.0.113.77/dns-query"]
        try expect(DNSApplicationResolutionPolicy.usesQueryRouter(profile) && !profile.shouldHijackSystemDNS,
                   "显式加密 DNS 未用于 DIRECT 名称或意外打开系统 DNS 拦截")
        let configured = try plan(router(profile), name: "direct.application.selftest.invalid")
        try expect(configured.route == .direct("DIRECT") && configured.upstream.encrypted
                   && configured.upstream.target.host == "203.0.113.77",
                   "应用 DIRECT 查询丢失指定加密 DNS 或使用默认解析器")
        profile.encryptedDNSServers = []
        profile.dnsServers.append("https://203.0.113.77/dns-query")
        let legacy = try plan(router(profile))
        try expect(DNSApplicationResolutionPolicy.usesQueryRouter(profile)
                   && legacy.upstream.target.host == "203.0.113.77",
                   "旧混合 DNS 中的显式加密选项未用于 DIRECT 名称")
        profile.encryptedDNSServers = ["malformed-encrypted-endpoint"]
        try expect(DNSApplicationResolutionPolicy.usesQueryRouter(profile),
                   "坏加密配置允许 DIRECT 名称绕过自定义查询路由")
        do { _ = try plan(router(profile)) }
        catch DNSPolicyFailure.configuration {
            profile.encryptedDNSServers = []; profile.dnsServers = []
            try expect(!DNSApplicationResolutionPolicy.usesQueryRouter(profile),
                       "空加密配置改变显式关闭保护的应用兼容行为")
            profile.dnsLeakProtectionEnabled = true
            try expect(DNSApplicationResolutionPolicy.usesQueryRouter(profile),
                       "默认保护未通过应用查询路由解析 DIRECT 名称")
            return
        }
        throw Failure(text: "坏加密配置的 DIRECT 查询回退其它 DNS")
    }

    private final class AddressResolutionProbe {
        let lock = NSLock(), done = DispatchSemaphore(value: 0)
        private let started = NetworkPerformanceDiagnostics.now()
        private var queries: [UInt16] = [], callbacks = 0, cancellations = 0
        private var addresses: [String] = []
        private var error: Error?
        private var elapsed: Double = 0
        func sent(_ type: UInt16) { lock.lock(); queries.append(type); lock.unlock() }
        func cancelled() { lock.lock(); cancellations += 1; lock.unlock() }
        func completed(_ result: Result<[String], Error>) {
            lock.lock(); callbacks += 1
            elapsed = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started)
            switch result { case .success(let value): addresses = value; case .failure(let value): error = value }
            lock.unlock(); done.signal()
        }
        var snapshot: (queries: [UInt16], callbacks: Int, cancellations: Int,
                       addresses: [String], error: Error?, elapsed: Double) {
            lock.lock(); defer { lock.unlock() }
            return (queries, callbacks, cancellations, addresses, error, elapsed)
        }
    }

    /// Only internal DIRECT discovery may shorten the wait for the other
    /// family. These fixtures cannot dial: both questions use an injected
    /// memory datagram, with deliberately late replies after cancellation.
    private static func directAddressResolutionGrace() throws {
        enum Reply { case address, nodata, servfail, refused, fake, mismatch }
        typealias Scheduled = (delay: TimeInterval, reply: Reply)
        var initialProfile = Profile()
        initialProfile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let profile = initialProfile
        let deliveries = DispatchGroup()
        var completed: [AddressResolutionProbe] = []
        let ipv4 = "203.0.113.77", ipv6 = "2001:db8::77"
        let sourceTarget = RequestTarget(host: "direct.address.selftest.invalid", port: 443,
            protocolName: "TCP", sourceHost: "192.0.2.1", sourcePort: 41000, inboundPort: 7262)

        func run(_ label: String, replies: [UInt16: Scheduled], timeout: TimeInterval = 0.7,
                 cancelAfter: TimeInterval? = nil, invalidateAfter: TimeInterval? = nil,
                 interfaceChangeAfter: TimeInterval? = nil) throws -> AddressResolutionProbe {
            let source = router(profile), generation = try plan(source).generation
            let interfaceGate = AdaptivePolicyGate(), probe = AddressResolutionProbe()
            let queue = DispatchQueue(label: "app.hajimi.dns.address-grace-self-test." + label)
            let operation = DNSAddressResolution(queue: queue, permitted: {
                source.isCurrentDNSGenerationForInternal(generation) && interfaceGate.permits()
            }, totalTimeout: timeout, datagramFactory: { original, worker, receive, _ in
                try expect(original.host == protectedSystemDNSGateway && original.port == 53
                           && original.protocolName == "UDP" && original.sourceHost == sourceTarget.sourceHost
                           && original.sourcePort == sourceTarget.sourcePort
                           && original.inboundPort == sourceTarget.inboundPort,
                           "DIRECT 解析丢失 DNS 原目的或来源元数据")
                return AdaptiveMemoryTransport(send: { query in
                    guard let question = DNSMessageInspection.singleQuestion(in: query) else { return }
                    probe.sent(question.type)
                    guard let selected = replies[question.type] else { return }
                    var answer = Data(query.prefix(question.questionEnd))
                    answer[2] = 0x81; answer[3] = 0x80
                    switch selected.reply {
                    case .address, .fake:
                        answer[7] = 1
                        let bytes: [UInt8]
                        if question.type == 1 {
                            bytes = selected.reply == .fake ? [198, 19, 0, 77] : [203, 0, 113, 77]
                        } else {
                            bytes = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77]
                        }
                        answer.append(contentsOf: [0xc0, 0x0c, 0, UInt8(question.type), 0, 1,
                            0, 0, 0, 60, 0, UInt8(bytes.count)])
                        answer.append(contentsOf: bytes)
                    case .nodata: break
                    case .servfail: answer[3] = 0x82
                    case .refused: answer[3] = 0x85
                    case .mismatch:
                        if let wrong = DNSMessageInspection.query(for: "wrong.address.selftest.invalid",
                            type: question.type, id: UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1])) {
                            answer = wrong; answer[2] = 0x81; answer[3] = 0x80; answer[7] = 1
                            answer.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1,
                                0, 0, 0, 60, 0, 4, 203, 0, 113, 77])
                        }
                    }
                    let response = answer
                    deliveries.enter()
                    worker.asyncAfter(deadline: .now() + selected.delay) {
                        receive(response); deliveries.leave()
                    }
                }, cancel: probe.cancelled)
            }, completion: probe.completed)
            operation.start(router: source, host: sourceTarget.host, sourceTarget: sourceTarget)
            if let delay = cancelAfter { queue.asyncAfter(deadline: .now() + delay) { operation.cancel() } }
            if let delay = invalidateAfter {
                queue.asyncAfter(deadline: .now() + delay) {
                    var denied = profile
                    denied.rules = [RoutingRule(kind: .final, policy: "REJECT", sourceLine: 1)]
                    source.update(profile: denied, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
                }
            }
            if let delay = interfaceChangeAfter {
                queue.asyncAfter(deadline: .now() + delay) { interfaceGate.revoke() }
            }
            try expect(probe.done.wait(timeout: .now() + 2) == .success, "DIRECT 解析场景没有完成：\(label)")
            queue.sync {}
            let state = probe.snapshot
            try expect(state.queries.sorted() == [1, 28] && state.callbacks == 1 && state.cancellations == 1,
                       "DIRECT 解析没有发送两族、未释放 datagram 或重复完成：\(label)")
            completed.append(probe); withExtendedLifetime(operation) {}
            return probe
        }
        func success(_ probe: AddressResolutionProbe, _ addresses: [String], _ text: String) throws {
            let state = probe.snapshot
            try expect(state.error == nil && Set(state.addresses) == Set(addresses), text)
        }
        let fastA: Scheduled = (0.005, .address)
        let blackhole = try run("A-valid-AAAA-silent", replies: [1: fastA])
        try success(blackhole, [ipv4], "AAAA 沉默使已经有效的 A 超时或丢失")
        try expect(blackhole.snapshot.elapsed < 500, "有效 IPv4 仍等到了完整 DNS 超时")
        for reply: Reply in [.nodata, .servfail, .refused, .address] {
            let late = try run("A-valid-AAAA-late-\(reply)", replies: [1: fastA, 28: (0.4, reply)])
            try success(late, [ipv4], "慢 AAAA 拖住有效 IPv4 或迟到回复改变已完成结果")
            try expect(late.snapshot.elapsed < 300, "DIRECT A 首答未在有限 grace 后完成")
        }
        let both = try run("both-fast", replies: [1: fastA, 28: (0.01, .address)])
        try success(both, [ipv4, ipv6], "grace 丢弃及时到达的另一族地址")
        let v6First = try run("IPv6-first-IPv4-late", replies: [28: fastA, 1: (0.18, .address)])
        try success(v6First, [ipv4, ipv6], "IPv6 首答过早结束导致 IPv4 fallback 丢失")
        try expect(v6First.snapshot.elapsed >= 150, "IPv6-only 首答裁掉仍待返回的 IPv4")
        let v6AtDeadline = try run("IPv6-valid-A-silent", replies: [28: fastA], timeout: 0.12)
        try success(v6AtDeadline, [ipv6], "总截止丢弃已经获得的有效 IPv6")
        try expect(v6AtDeadline.snapshot.elapsed >= 100, "IPv6 首答未等原有 A 截止")
        let aNoData = try run("A-empty-AAAA-valid", replies: [1: (0.005, .nodata), 28: (0.03, .address)])
        try success(aNoData, [ipv6], "A NODATA 误拒绝已有效的 IPv6")
        for (label, replies) in [
            ("both-empty", [UInt16(1): (0.005, Reply.nodata), 28: (0.01, .nodata)]),
            ("both-failed", [UInt16(1): (0.005, Reply.servfail), 28: (0.01, .refused)]),
            ("fake-address", [UInt16(1): (0.005, Reply.fake), 28: (0.01, .nodata)]),
            ("wrong-question", [UInt16(1): (0.005, Reply.mismatch), 28: (0.01, .nodata)])
        ] {
            let result = try run(label, replies: replies, timeout: 0.12).snapshot
            try expect(result.error != nil && result.addresses.isEmpty,
                       "空/失败/伪造 DNS 首答没有 fail closed：\(label)")
        }
        let cancel = try run("cancel-after-A", replies: [1: fastA, 28: (0.1, .address)], cancelAfter: 0.02)
        let revoke = try run("policy-update-after-A", replies: [1: fastA, 28: (0.1, .address)], invalidateAfter: 0.02)
        let rebound = try run("interface-change-after-A", replies: [1: fastA, 28: (0.1, .address)], interfaceChangeAfter: 0.02)
        for result in [cancel.snapshot, revoke.snapshot, rebound.snapshot] {
            try expect(result.error != nil && result.addresses.isEmpty, "取消或策略/接口更新仍送出旧地址")
        }
        try expect(deliveries.wait(timeout: .now() + 1) == .success, "迟到的 DIRECT 回包没有排空")
        try expect(completed.allSatisfy { $0.snapshot.callbacks == 1 }, "取消后的迟到回包触发第二次完成")
    }

    private final class AdaptiveProbe {
        let lock = NSLock(), done = DispatchSemaphore(value: 0)
        let started = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
        let late = DispatchSemaphore(value: 0)
        var attempts: [String] = [], answers: [Data] = []
        var activeAttempts = 0, peakActiveAttempts = 0, cancelledAttempts = 0
        var error: Error?
        func attempted(_ candidate: DNSUpstreamCandidate) {
            lock.lock(); attempts.append(candidate.upstream.target.host)
            activeAttempts += 1; peakActiveAttempts = max(peakActiveAttempts, activeAttempts)
            lock.unlock(); started.signal()
        }
        func transportCancelled() {
            lock.lock(); activeAttempts = max(0, activeAttempts - 1); cancelledAttempts += 1; lock.unlock()
            cancelled.signal()
        }
        func received(_ data: Data) { lock.lock(); answers.append(data); lock.unlock(); done.signal() }
        func failed(_ error: Error) { lock.lock(); self.error = error; lock.unlock(); done.signal() }
        var snapshot: (attempts: [String], answers: [Data], error: Error?) {
            lock.lock(); defer { lock.unlock() }; return (attempts, answers, error)
        }
        var concurrency: (active: Int, peak: Int, cancelled: Int) {
            lock.lock(); defer { lock.unlock() }; return (activeAttempts, peakActiveAttempts, cancelledAttempts)
        }
    }
    private final class AdaptiveManualClock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func advance(to elapsed: TimeInterval) {
            lock.lock(); defer { lock.unlock() }
            precondition(100 + elapsed >= value); value = 100 + elapsed
        }
    }
    private final class AdaptiveManualReply {
        private let lock = NSLock()
        private var reply: (() -> Void)?
        private var cancelled = false
        func prepare(_ reply: @escaping () -> Void) { lock.lock(); self.reply = reply; lock.unlock() }
        func recordCancellation() { lock.lock(); cancelled = true; lock.unlock() }
        var wasCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
        func release() -> Bool {
            lock.lock(); let reply = self.reply; self.reply = nil; lock.unlock()
            guard let reply else { return false }; reply(); return true
        }
    }
    private final class AdaptiveMemoryTransport: NativeRoutedDatagram {
        let onSend: (Data) -> Void, onCancel: () -> Void
        init(send: @escaping (Data) -> Void, cancel: @escaping () -> Void = {}) {
            onSend = send; onCancel = cancel
        }
        func send(_ data: Data) { onSend(data) }
        func cancel() { onCancel() }
    }
    private final class AdaptiveAcknowledgedMemoryTransport: NativeRoutedDatagram, DNSQueryCancellationAcknowledging {
        private let lock = NSLock()
        private var closed = false
        private let onSend: (Data) -> Void, onCancel: () -> Void
        init(send: @escaping (Data) -> Void, cancel: @escaping () -> Void = {}) {
            onSend = send; onCancel = cancel
        }
        func send(_ data: Data) {
            lock.lock(); let stopped = closed; lock.unlock()
            if !stopped { onSend(data) }
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); let first = !closed; closed = true; lock.unlock()
            if first { onCancel() }
            completion()
        }
    }
    private static func adaptiveProfile() -> Profile {
        var profile = Profile()
        profile.dnsServers = ["203.0.113.60"]
        profile.encryptedDNSServers = ["https://primary.adaptive.selftest.invalid/dns-query#203.0.113.70",
                                       "https://secondary.adaptive.selftest.invalid/dns-query#203.0.113.71"]
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        return profile
    }
    private static func adaptiveExchange(_ routed: NativePacketRouter, plan: DNSQueryPlan, message: Data,
        probe: AdaptiveProbe, timeout: TimeInterval = 1, factory: @escaping DNSAdaptiveQueryDatagram.Factory)
        throws -> NativeRoutedDatagram {
        let flow = try routed.makeOptimizedDNSUpstream(plan: plan,
            queue: DispatchQueue(label: "app.hajimi.dns.adaptive-self-test"),
            adaptiveFactory: factory, adaptiveTimeout: timeout,
            receive: probe.received, failure: probe.failed)
        flow.send(message); return flow
    }
    private static func awaitAdaptive(_ probe: AdaptiveProbe, query: Data, expectFailure: Bool = false,
                                      waitTimeout: TimeInterval = 3) throws {
        try expect(probe.done.wait(timeout: .now() + waitTimeout) == .success, "自适应 DNS 内存交换没有完成")
        let result = probe.snapshot
        if expectFailure { try expect(result.error != nil && result.answers.isEmpty, "失效交换仍返回应用答案"); return }
        if let error = result.error {
            let name = DNSMessageInspection.singleQuestion(in: query)?.name ?? "unknown-self-test-question"
            print("DNS adaptive memory self-test failed: question=\(name), error_type=\(String(reflecting: type(of: error))), attempts=\(result.attempts.count)")
            throw error
        }
        try expect(result.answers.count == 1 && DNSMessageInspection.responseMatchesQuery(result.answers[0], query: query),
                   "自适应 DNS 返回错误问题、ID 或重复回包")
    }
    private static func adaptiveCandidatePolicy() throws {
        let base = adaptiveProfile(), source = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")
        let originalSet = try plan(router(base), original: source)
        for (blocked, allowed) in [("203.0.113.71", "203.0.113.70"), ("203.0.113.70", "203.0.113.71")] {
            var profile = base
            profile.rules.insert(RoutingRule(kind: .ipCIDR(blocked + "/32"), policy: "REJECT", sourceLine: 0), at: 0)
            let routed = router(profile), decision = try plan(routed, original: source), probe = AdaptiveProbe()
            try expect(decision.candidates.count == 1 && decision.upstream.target.host == allowed
                       && decision.scopeKey != originalSet.scopeKey, "被拒绝候选未剔除或批准集合没有进入缓存 scope")
            let message = try query("allowed.example.test", 1)
            let flow = try adaptiveExchange(routed, plan: decision, message: message, probe: probe) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    probe.attempted(candidate)
                    if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts == [allowed], "REJECT 解析器仍被拨号或作为网络失败绕过")
        }
        var denied = base
        denied.rules.insert(RoutingRule(kind: .logicalOr([.ipCIDR("203.0.113.70/32"), .ipCIDR("203.0.113.71/32")]),
                                       policy: "REJECT", sourceLine: 0), at: 0)
        try refusal(router(denied), name: "allowed.example.test", type: 1)
        denied = base
        denied.rules.insert(RoutingRule(kind: .domain("blocked.example.test"), policy: "REJECT", sourceLine: 0), at: 0)
        try refusal(router(denied), name: "blocked.example.test", type: 1)
        denied = base
        denied.rules.insert(RoutingRule(kind: .ipCIDR("203.0.113.53/32"), policy: "REJECT", sourceLine: 0), at: 0)
        try refusal(router(denied), name: "allowed.example.test", type: 1, original: source)
    }
    private static func adaptiveBuiltinAddressVariants() throws {
        var profile = Profile()
        profile.dnsServers = ["203.0.113.60"]
        profile.encryptedDNSServers = ["https://doh.pub/dns-query", "https://dns.quad9.net/dns-query"]
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let ips = ["1.12.12.12", "9.9.9.9", "120.53.53.53", "149.112.112.112"]
        let names = ["doh.pub", "dns.quad9.net", "doh.pub", "dns.quad9.net"]
        let full = try plan(router(profile))
        try expect(full.candidates.map { $0.upstream.target.host } == ips
                   && full.candidates.map { $0.upstream.identityHost } == names
                   && full.candidates.allSatisfy({ $0.upstream.encrypted && $0.bootstrap == nil }),
                   "内置备用未按提供商波次排列或改变身份/变成传统 DNS")
        for candidate in full.candidates {
            guard case .doh(let endpoint) = candidate.upstream else { throw Failure(text: "DoH variant 丢失类型") }
            try expect(endpoint.url.absoluteString == "https://\(endpoint.host)/dns-query", "备用 IP 改变配置的 URL")
        }
        for blocked in ips {
            var denied = profile
            denied.rules.insert(RoutingRule(kind: .ipCIDR(blocked + "/32"), policy: "REJECT", sourceLine: 0), at: 0)
            let source = router(denied), approved = try plan(source), probe = AdaptiveProbe()
            try expect(approved.candidates.map { $0.upstream.target.host } == ips.filter { $0 != blocked }
                       && approved.scopeKey != full.scopeKey, "备用 IP 未逐一 REJECT 预检或批准集合未隔离 scope")
            let message = try query("adaptive-variant-policy.example.test", 1)
            let flow = try adaptiveExchange(source, plan: approved, message: message, probe: probe) { candidate, queue, receive, _ in
                try expect(candidate.upstream.target.host != blocked, "REJECT 的备用 IP 仍进入 factory")
                return AdaptiveMemoryTransport(send: { data in
                    probe.attempted(candidate)
                    if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
            defer { flow.cancel() }; try awaitAdaptive(probe, query: message)
        }
        var deniedIdentity = profile
        deniedIdentity.rules.insert(RoutingRule(kind: .domain("doh.pub"), policy: "REJECT", sourceLine: 0), at: 0)
        let allowed = try plan(router(deniedIdentity))
        try expect(allowed.candidates.map { $0.upstream.target.host } == ["9.9.9.9", "149.112.112.112"]
                   && allowed.scopeKey != full.scopeKey, "同 provider 备用绕过 TLS 身份域名拒绝")
        var explicit = profile
        explicit.encryptedDNSServers = ["https://doh.pub/dns-query#1.12.12.12",
                                        "https://dns.quad9.net/dns-query#149.112.112.112"]
        let pinned = try plan(router(explicit))
        try expect(pinned.candidates.map { $0.upstream.target.host } == ["1.12.12.12", "149.112.112.112"]
                   && pinned.scopeKey != full.scopeKey, "显式 #pin 扩展到备用或与自动集合共享 scope")
        var mixed = profile
        mixed.encryptedDNSServers = ["tls://dot.pub", "https://doh.pub/dns-query"]
        try expect((try plan(router(mixed))).candidates.map { $0.upstream.identityHost } == ["doh.pub", "dot.pub", "doh.pub"],
                   "波次扩展改变 DoH-first 顺序或扩展未授权的 DoT 地址")
        var maximum = profile
        maximum.encryptedDNSServers = (0..<16).map { "https://doh.pub/dns-query?slot=\($0)" }
        try expect((try plan(router(maximum))).candidates.count == 32, "16 合法配置的有限 32 地址集合被截断")
        maximum.encryptedDNSServers.append("https://doh.pub/dns-query?slot=16")
        do { _ = try plan(router(maximum)); throw Failure(text: "超过 16 个配置仍获批准") }
        catch DNSPolicyFailure.configuration { }

        // Keep first IP alive while the other provider fails; its approved
        // same-provider backup occupies the newly available second live slot.
        let source = router(profile), probe = AdaptiveProbe()
        let message = try query("adaptive-builtin-backup.example.test", 1)
        let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-builtin-backup.example.test"),
            message: message, probe: probe, timeout: 2) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    probe.attempted(candidate)
                    switch candidate.upstream.target.host {
                    case "1.12.12.12": break
                    case "120.53.53.53":
                        if let reply = bootstrapAnswer(data) { queue.asyncAfter(deadline: .now() + 0.55) { receive(reply) } }
                    default:
                        if let failed = DNSMessageInspection.errorResponse(to: data, code: .servfail) { queue.async { receive(failed) } }
                    }
                }, cancel: probe.transportCancelled)
            }
        defer { flow.cancel() }; try awaitAdaptive(probe, query: message)
        try expect(probe.snapshot.attempts == Array(ips.prefix(3)) && probe.concurrency.peak == 2
                   && probe.concurrency.active == 0 && probe.concurrency.cancelled == 3,
                   "内置备用未补位或突破 2 活跃/3 尝试预算")
        let nextProbe = AdaptiveProbe(), fresh = try query("adaptive-builtin-preferred.example.test", 1)
        let nextFlow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-builtin-preferred.example.test"),
            message: fresh, probe: nextProbe, timeout: 2) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    nextProbe.attempted(candidate)
                    if candidate.upstream.target.host == "120.53.53.53", let reply = bootstrapAnswer(data) {
                        queue.asyncAfter(deadline: .now() + 0.55) { receive(reply) }
                    } else if let failed = DNSMessageInspection.errorResponse(to: data, code: .servfail) { queue.async { receive(failed) } }
                }, cancel: nextProbe.transportCancelled)
            }
        defer { nextFlow.cancel() }; try awaitAdaptive(nextProbe, query: fresh)
        try expect(!nextProbe.snapshot.attempts.contains("1.12.12.12") && nextProbe.snapshot.attempts.last == "120.53.53.53",
                   "winner 取消的慢 primary 仍以未知 500ms 抢过健康备用")
    }

    private static func adaptiveEncryptedExchanges() throws {
        let profile = adaptiveProfile(), routed = router(profile)
        let firstQuery = try query("adaptive-first.example.test", 1), firstPlan = try plan(routed, name: "adaptive-first.example.test")
        let first = AdaptiveProbe()
        let failedPrimary = try adaptiveExchange(routed, plan: firstPlan, message: firstQuery, probe: first) {
            candidate, queue, receive, failure in
            let expectedIdentity = candidate.upstream.target.host == "203.0.113.70"
                ? "primary.adaptive.selftest.invalid" : "secondary.adaptive.selftest.invalid"
            try expect(candidate.upstream.identityHost == expectedIdentity && candidate.upstream.encrypted,
                       "failover 改变原 TLS 身份或候选变成传统 DNS")
            return AdaptiveMemoryTransport(send: { data in
                first.attempted(candidate)
                if candidate.upstream.target.host == "203.0.113.70" { queue.async { failure(EngineError("内存 TLS 失败")) } }
                else if let answer = bootstrapAnswer(data) { queue.async { receive(answer) } }
            })
        }
        defer { failedPrimary.cancel() }
        try awaitAdaptive(first, query: firstQuery)
        try expect(first.snapshot.attempts == ["203.0.113.70", "203.0.113.71"], "网络失败未切换至批准的加密备用")
        let secondQuery = try query("adaptive-next.example.test", 1), second = AdaptiveProbe()
        let secondFlow = try adaptiveExchange(routed, plan: plan(routed, name: "adaptive-next.example.test"),
            message: secondQuery, probe: second) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    second.attempted(candidate)
                    if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
        defer { secondFlow.cancel() }
        try awaitAdaptive(second, query: secondQuery)
        try expect(second.snapshot.attempts == ["203.0.113.71"] && secondFlow is DNSCoalescedQueryDatagram,
                   "故障后择优没有避开失败端点或绕过了 single-flight")

        let throwingSource = router(profile), throwingProbe = AdaptiveProbe()
        let throwingQuery = try query("adaptive-factory-throw.example.test", 1)
        let beforeAttempts = NetworkPerformanceDiagnostics.shared.snapshot()
        let throwingFlow = try adaptiveExchange(throwingSource,
            plan: plan(throwingSource, name: "adaptive-factory-throw.example.test"),
            message: throwingQuery, probe: throwingProbe) { candidate, queue, receive, _ in
                throwingProbe.attempted(candidate)
                if candidate.upstream.target.host == "203.0.113.70" { throw EngineError("内存拨号 factory 立即失败") }
                return AdaptiveMemoryTransport(send: { data in
                    if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
        defer { throwingFlow.cancel() }
        try awaitAdaptive(throwingProbe, query: throwingQuery)
        let afterAttempts = NetworkPerformanceDiagnostics.shared.snapshot()
        try expect(throwingProbe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                   && afterAttempts.dnsUpstreamAttempts == beforeAttempts.dnsUpstreamAttempts + 2
                   && afterAttempts.dnsFailovers == beforeAttempts.dnsFailovers + 1,
                   "立即 factory 网络错误没有进入逻辑尝试/failover 计数")
        let cachedProbe = AdaptiveProbe()
        let cachedFlow = try adaptiveExchange(throwingSource,
            plan: plan(throwingSource, name: "adaptive-factory-throw.example.test"),
            message: throwingQuery, probe: cachedProbe) { _, _, _, _ in
                throw Failure(text: "缓存命中仍启动上游 factory")
            }
        defer { cachedFlow.cancel() }
        try awaitAdaptive(cachedProbe, query: throwingQuery)
        let afterCached = NetworkPerformanceDiagnostics.shared.snapshot()
        try expect(afterCached.dnsUpstreamAttempts == afterAttempts.dnsUpstreamAttempts
                   && afterCached.dnsFailovers == afterAttempts.dnsFailovers,
                   "cache hit 重复增加上游尝试或故障切换计数")

        for code: UInt8 in [3, 5] {
            let source = router(profile), message = try query("adaptive-terminal.example.test", 1), probe = AdaptiveProbe()
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-terminal.example.test"),
                message: message, probe: probe) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if var reply = DNSMessageInspection.errorResponse(to: data, code: .refused) {
                            reply[3] = (reply[3] & 0xf0) | code
                            let answer = reply; queue.async { receive(answer) }
                        }
                    })
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts == ["203.0.113.70"] && probe.snapshot.answers[0][3] & 0x0f == code,
                       "NXDOMAIN/REFUSED 被跨供应商重试")
        }

        // An upstream REFUSED and a late local policy denial are both terminal.
        for localPolicy in [false, true] {
            let source = router(profile), message = try query("adaptive-refused.example.test", 1), probe = AdaptiveProbe()
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-refused.example.test"),
                message: message, probe: probe) { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        queue.async {
                            if localPolicy { failure(DNSPolicyFailure.refused("返回的解析器 IP 被拒绝")) }
                            else if let reply = DNSMessageInspection.errorResponse(to: data, code: .refused) { receive(reply) }
                        }
                    })
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts == ["203.0.113.70"] && probe.snapshot.answers[0][3] & 0x0f == 5,
                       "REFUSED 被当网络失败改走备用解析器")
        }

        var dotProfile = profile
        dotProfile.encryptedDNSServers[1] = "tls://secondary.adaptive.selftest.invalid#203.0.113.71"
        let dotSource = router(dotProfile), dotProbe = AdaptiveProbe(), dotQuery = try query("adaptive-dot.example.test", 1)
        let dotFlow = try adaptiveExchange(dotSource, plan: plan(dotSource, name: "adaptive-dot.example.test"),
            message: dotQuery, probe: dotProbe) { candidate, queue, receive, failure in
                if candidate.upstream.target.host == "203.0.113.71" {
                    guard case .dot = candidate.upstream else { throw Failure(text: "DoH 故障没有保留配置的 DoT 类型") }
                    try expect(candidate.upstream.identityHost == "secondary.adaptive.selftest.invalid", "DoT TLS 身份改变")
                }
                return AdaptiveMemoryTransport(send: { data in
                    dotProbe.attempted(candidate)
                    if candidate.upstream.target.host == "203.0.113.70" { queue.async { failure(EngineError("内存 DoH 失败")) } }
                    else if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                })
            }
        defer { dotFlow.cancel() }
        try awaitAdaptive(dotProbe, query: dotQuery)
        try expect(dotProbe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"], "DoH→已批准 DoT 故障切换失败")

        var exhaustedProfile = profile
        exhaustedProfile.encryptedDNSServers += ["https://third.adaptive.selftest.invalid/dns-query#203.0.113.72",
                                                 "https://fourth.adaptive.selftest.invalid/dns-query#203.0.113.73"]
        let exhaustedSource = router(exhaustedProfile), exhausted = AdaptiveProbe(), exhaustedQuery = try query("adaptive-exhausted.example.test", 1)
        let exhaustedFlow = try adaptiveExchange(exhaustedSource, plan: plan(exhaustedSource, name: "adaptive-exhausted.example.test"),
            message: exhaustedQuery, probe: exhausted) { candidate, queue, _, failure in
                AdaptiveMemoryTransport(send: { _ in
                    exhausted.attempted(candidate); queue.async { failure(EngineError("内存加密端点全失败")) }
                })
            }
        defer { exhaustedFlow.cancel() }
        try awaitAdaptive(exhausted, query: exhaustedQuery, expectFailure: true)
        try expect(exhausted.snapshot.attempts == ["203.0.113.70", "203.0.113.71", "203.0.113.72"],
                   "单问题超过三次尝试或加密失败回退传统 DNS")

        let timedSource = router(profile), timedQuery = try query("adaptive-timeout.example.test", 1), timed = AdaptiveProbe()
        let timedFlow = try adaptiveExchange(timedSource, plan: plan(timedSource, name: "adaptive-timeout.example.test"),
            message: timedQuery, probe: timed, timeout: 0.4) { candidate, queue, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    timed.attempted(candidate)
                    guard let reply = bootstrapAnswer(data) else { return }
                    if candidate.upstream.target.host == "203.0.113.70" {
                        queue.asyncAfter(deadline: .now() + 0.3) { receive(reply); timed.late.signal() }
                    } else { queue.async { receive(reply) } }
                }, cancel: { timed.cancelled.signal() })
            }
        defer { timedFlow.cancel() }
        try awaitAdaptive(timed, query: timedQuery)
        try expect(timed.late.wait(timeout: .now() + 2) == .success
                   && timed.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                   && timed.snapshot.answers.count == 1, "超时/迟到回包复活旧尝试或产生重复应答")

        for flush in [true, false] {
            let source = router(profile), message = try query("adaptive-epoch.example.test", 1), probe = AdaptiveProbe()
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-epoch.example.test"),
                message: message, probe: probe) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if let reply = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 0.1) { receive(reply); probe.late.signal() }
                        }
                    }, cancel: { probe.cancelled.signal() })
                }
            defer { flow.cancel() }
            try expect(probe.started.wait(timeout: .now() + 2) == .success, "待撤销 adaptive 交换未开始")
            if flush { source.flushDNS() }
            else { source.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:]) }
            try awaitAdaptive(probe, query: message, expectFailure: true)
            try expect(probe.cancelled.wait(timeout: .now() + 2) == .success
                       && probe.late.wait(timeout: .now() + 2) == .success
                       && probe.snapshot.attempts == ["203.0.113.70"], "flush/代次更新后旧尝试仍切换或未取消")
        }
        let cancelledSource = router(profile), cancelled = AdaptiveProbe(), message = try query("adaptive-cancel.example.test", 1)
        let flow = try adaptiveExchange(cancelledSource, plan: plan(cancelledSource, name: "adaptive-cancel.example.test"),
            message: message, probe: cancelled) { candidate, _, _, _ in
                AdaptiveMemoryTransport(send: { _ in cancelled.attempted(candidate) }, cancel: { cancelled.cancelled.signal() })
            }
        try expect(cancelled.started.wait(timeout: .now() + 2) == .success, "待取消 adaptive 交换未开始")
        flow.cancel()
        try expect(cancelled.cancelled.wait(timeout: .now() + 2) == .success && cancelled.snapshot.answers.isEmpty,
                   "客户端取消未撤销自己的 adaptive 请求")
    }

    private static func adaptiveHedgedExchanges() throws {
        let profile = adaptiveProfile()

        // Reproduce the real four-second cutoff, not just a fast backup win:
        // the healthy primary replies at 4.5 s, still within the 8 s query
        // deadline, while the approved backup has no response at all.
        do {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-late-primary.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-late-primary.example.test"),
                message: message, probe: probe, timeout: 8) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.upstream.target.host == "203.0.113.70", let reply = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 4.5) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message, waitTimeout: 7)
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            try expect(probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.concurrency.peak == 2 && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 2 && elapsed >= 4 && elapsed < 8,
                       "soft hedge 截断了 4s 后仍健康的 primary 或没有撤销自己的备用")

            // Seed the fresh question independently: the real 4.5s exchange's
            // censored backup sample can fall on either side of the selector's
            // 10% hysteresis when dispatch delivers the primary slightly late.
            // This case tests known-alternate budget, not that ranking boundary.
            let fresh = try query("adaptive-known-slow-alternate.example.test", 1), nextProbe = AdaptiveProbe()
            let approved = try plan(source, name: "adaptive-known-slow-alternate.example.test")
            let ids = approved.candidates.map(\.id), scope = approved.healthScopeKey
            let clock = AdaptiveManualClock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let replyGate = AdaptiveManualReply()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            selector.record(scopeKey: scope, candidateID: ids[0], milliseconds: 4500, success: true)
            selector.record(scopeKey: scope, candidateID: ids[1], milliseconds: 100, success: true)
            try expect(selector.orderedCandidates(scopeKey: scope, candidateIDs: ids) == [ids[1], ids[0]],
                       "两个已有成功记录的候选没有按各自快慢历史排序")
            let hedgeDelay = DNSAdaptiveHedgeBudget.delay(remaining: 0.4, attemptsLeft: 2,
                primaryMilliseconds: selector.planningLatencyMilliseconds(scopeKey: scope, candidateID: ids[1]),
                alternateMilliseconds: selector.planningLatencyMilliseconds(scopeKey: scope, candidateID: ids[0]))
            try expect(hedgeDelay == 0.001, "已知 4.5s alternate 没有在原 400ms 内获最早 hedge 预算")
            let absolute = clock.now() + 0.4
            weak var checkpointFlow: DNSAdaptiveQueryDatagram?
            let nextFlow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, _, receive, _ in
                    checkpointFlow?.pauseAdaptiveTimersForSelfTest()
                    return AdaptiveMemoryTransport(send: { data in
                        nextProbe.attempted(candidate)
                        if candidate.upstream.target.host == "203.0.113.70", let answer = bootstrapAnswer(data) {
                            // The explicit fixture reply is released 300ms
                            // after the known alternate's admitted 1ms start.
                            replyGate.prepare { receive(answer) }
                        }
                    }, cancel: nextProbe.transportCancelled)
                }, receive: nextProbe.received, failure: nextProbe.failed, timeout: 0.4,
                absoluteDeadline: absolute, clock: clock.now)
            checkpointFlow = nextFlow
            defer { nextFlow.cancel() }
            nextFlow.send(fresh); nextFlow.drainAdaptiveQueueForSelfTest()
            try expect(nextProbe.snapshot.attempts == ["203.0.113.71"], "已知较快 primary 没有先按独立历史启动")
            clock.advance(to: hedgeDelay)
            try expect(nextFlow.fireAdaptiveHedgeForSelfTest(), "原生已知 alternate hedge checkpoint 未装载")
            clock.advance(to: hedgeDelay + 0.3)
            try expect(replyGate.release(), "已知慢 alternate 没有获发送和真实答复入口")
            try awaitAdaptive(nextProbe, query: fresh)
            let state = nextFlow.adaptiveStateForSelfTest
            try expect(nextProbe.snapshot.attempts == ["203.0.113.71", "203.0.113.70"]
                       && nextProbe.concurrency.peak == 2 && nextProbe.concurrency.active == 0
                       && nextProbe.concurrency.cancelled == 2 && state.attempts == 2 && state.active == 0
                       && state.started == 100 && state.deadline == absolute && clock.now() < absolute,
                       "fresh question 没给已知慢但健康 alternate 留足 overall 预算")
        }

        // A backup SERVFAIL must not finish an exchange whose primary is
        // still healthy. Its later, otherwise valid answer is a stale token
        // and must be ignored even before the primary eventually succeeds.
        do {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-servfail.example.test", 1)
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-servfail.example.test"),
                message: message, probe: probe, timeout: 0.4) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        guard let reply = bootstrapAnswer(data) else { return }
                        if candidate.upstream.target.host == "203.0.113.70" {
                            queue.asyncAfter(deadline: .now() + 0.3) { receive(reply) }
                        } else {
                            if let failed = DNSMessageInspection.errorResponse(to: data, code: .servfail) {
                                queue.async { receive(failed) }
                            }
                            var stale = reply; stale[stale.count - 1] = 78
                            let late = stale
                            queue.asyncAfter(deadline: .now() + 0.03) { receive(late); probe.late.signal() }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success
                       && DNSMessageInspection.addressAnswers(in: probe.snapshot.answers[0]).map(\.address) == ["203.0.113.77"]
                       && probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 2,
                       "备用 SERVFAIL 终止仍活跃 primary 或迟到 token 被采纳")
        }

        // The third approved candidate may replace a genuinely failed hedge,
        // but neither a fourth attempt nor three simultaneous transports is
        // permitted. Retain and later reject the first primary's late reply.
        do {
            var extended = profile
            extended.encryptedDNSServers += ["https://third.adaptive.selftest.invalid/dns-query#203.0.113.72",
                                             "https://fourth.adaptive.selftest.invalid/dns-query#203.0.113.73"]
            let source = router(extended), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-slots.example.test", 1)
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-slots.example.test"),
                message: message, probe: probe, timeout: 0.6) { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        switch candidate.upstream.target.host {
                        case "203.0.113.70":
                            if let reply = bootstrapAnswer(data) {
                                queue.asyncAfter(deadline: .now() + 0.45) { receive(reply); probe.late.signal() }
                            }
                        case "203.0.113.71": queue.async { failure(EngineError("内存 hedge 网络失败")) }
                        default:
                            if let reply = bootstrapAnswer(data) { queue.async { receive(reply) } }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success
                       && probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71", "203.0.113.72"]
                       && probe.concurrency.peak == 2 && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 3 && probe.snapshot.answers.count == 1,
                       "失败 hedge 补位超过 2 活跃/3 总尝试或迟到 primary 复活")
        }

        // The first primary retains the original deadline. A late unmeasured
        // hedge can rotate once without turning retirement into an outage.
        do {
            var extended = profile
            extended.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
            let source = router(extended), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-deadline.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-deadline.example.test"),
                message: message, probe: probe, timeout: 0.3) { candidate, _, _, _ in
                    AdaptiveMemoryTransport(send: { _ in probe.attempted(candidate) }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message, expectFailure: true)
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            try expect(probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71", "203.0.113.72"]
                       && probe.concurrency.peak == 2 && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 3 && elapsed >= 0.25 && elapsed < 2.5,
                       "unknown hedge 轮替丢失 primary、超过 2 live/3 attempts 或延长总期限")
        }

        // First observed NODATA/NXDOMAIN/REFUSED or local policy denial remains
        // terminal even with a positive primary already awaiting its reply.
        for code: UInt8 in [0, 3, 5, 255] {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-terminal.example.test", 1)
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-terminal.example.test"),
                message: message, probe: probe, timeout: 0.4) { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.upstream.target.host == "203.0.113.70", let reply = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 0.3) { receive(reply); probe.late.signal() }
                        } else {
                            queue.async {
                                if code == 255 { failure(DNSPolicyFailure.refused("内存候选策略拒绝")); return }
                                if var reply = DNSMessageInspection.errorResponse(to: data, code: .refused) {
                                    reply[3] = (reply[3] & 0xf0) | code; receive(reply)
                                }
                            }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success
                       && probe.snapshot.answers.count == 1 && probe.snapshot.answers[0][3] & 0x0f == (code == 255 ? 5 : code)
                       && DNSMessageInspection.addressAnswers(in: probe.snapshot.answers[0]).isEmpty
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 2,
                       "活跃 hedge 的明确否定/策略拒绝被忽略、跨供应商重试或没有取消 primary")
        }

        // Policy invalidation and client cancellation revoke both requests,
        // not only the most recently started hedge. All later replies remain
        // inert and must not start another approved candidate.
        for revoke in 0..<3 {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-hedge-revoke.example.test", 1)
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-hedge-revoke.example.test"),
                message: message, probe: probe, timeout: 0.4) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if let reply = bootstrapAnswer(data) {
                            let delay = candidate.upstream.target.host == "203.0.113.70" ? 0.3 : 0.1
                            queue.asyncAfter(deadline: .now() + delay) { receive(reply); probe.late.signal() }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }
            for _ in 0..<2 {
                try expect(probe.started.wait(timeout: .now() + 1) == .success, "待撤销 hedge 的两个候选未同时开始")
            }
            switch revoke {
            case 0: source.flushDNS()
            case 1: source.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
            default: flow.cancel()
            }
            if revoke < 2 { try awaitAdaptive(probe, query: message, expectFailure: true) }
            for _ in 0..<2 {
                try expect(probe.cancelled.wait(timeout: .now() + 1) == .success
                           && probe.late.wait(timeout: .now() + 1) == .success, "双候选撤销未取消各自请求或缺迟到回调")
            }
            try expect(probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.snapshot.answers.isEmpty && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 2, "撤销后 hedge 接纳旧答案、继续切换或取消范围不完整")
        }
    }

    private final class AdaptivePolicyGate {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }

    private static func adaptiveShortHedgeBudgets() throws {
        let profile = adaptiveProfile()
        // The normal total deadline stays eight seconds. Only the approved
        // backup launch becomes shorter; the blackholed primary remains live.
        do {
            let source = router(profile), probe = AdaptiveProbe()
            let message = try query("adaptive-cold-short-hedge.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let flow = try adaptiveExchange(source, plan: plan(source, name: "adaptive-cold-short-hedge.example.test"),
                message: message, probe: probe, timeout: 8) { candidate, queue, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.upstream.target.host == "203.0.113.71", let reply = bootstrapAnswer(data) {
                            queue.async { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }
            defer { flow.cancel() }; try awaitAdaptive(probe, query: message, waitTimeout: 2)
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            try expect(elapsed >= 0.6 && elapsed <= 1.5
                       && probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 2,
                       "8s 冷查询仍长时间等待坏 primary 或超出 750ms 有界备用启动")
        }
        let approved = try plan(router(profile)), ids = approved.candidates.map(\.id)
        func observedSelector(_ candidates: [DNSUpstreamCandidate], scope: String) -> DNSAdaptiveUpstreamSelector {
            let selector = DNSAdaptiveUpstreamSelector()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: candidates.map(\.id))
            for (index, candidate) in candidates.enumerated() {
                selector.record(scopeKey: scope, candidateID: candidate.id,
                                milliseconds: index == 0 ? 2500 : index == 1 ? 3500 : 6000, success: true)
            }
            return selector
        }
        // A measured slow primary gets a hedge by 1.5s, but a legitimate 2.1s
        // primary reply must still win if that hedge has no response.
        do {
            let selector = observedSelector(approved.candidates, scope: approved.scopeKey), probe = AdaptiveProbe()
            let message = try query("adaptive-known-primary-retained.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let flow = DNSCoalescedQueryDatagram(coordinator: DNSQueryCoordinator(), scope: approved.scopeKey,
                queue: .global(), permitted: { true }, factory: { queue, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                        scopeKey: approved.scopeKey, queue: queue, permitted: { true },
                        factory: { candidate, queue, receive, _ in
                            AdaptiveMemoryTransport(send: { data in
                                probe.attempted(candidate)
                                if candidate.id == ids[0], let reply = bootstrapAnswer(data) {
                                    queue.asyncAfter(deadline: .now() + 2.1) { receive(reply) }
                                }
                            }, cancel: probe.transportCancelled)
                        }, receive: receive, failure: failure, timeout: 8)
                }, receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, waitTimeout: 3.5)
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            try expect(elapsed >= 2 && elapsed < 3.5
                       && probe.snapshot.attempts == ["203.0.113.70", "203.0.113.71"]
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 2,
                       "known RTT 的 1.5s 软预算未启动备用或取消了仍健康 primary")
        }
        var extended = profile
        extended.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let three = try plan(router(extended)), threeIDs = three.candidates.map(\.id)
        // RTT-driven short hedges do not turn ordinary cancellation into an
        // outage, nor make pending candidates escape a parent's total timeout.
        for deadline in [false, true] {
            let selector = observedSelector(three.candidates, scope: three.scopeKey), probe = AdaptiveProbe()
            let healthDrained = DispatchSemaphore(value: 0)
            let coordinator = DNSQueryCoordinator(timeout: .milliseconds(400))
            let message = try query("adaptive-known-budget-finish.example.test", 1)
            let flow = DNSCoalescedQueryDatagram(coordinator: coordinator, scope: three.scopeKey,
                queue: .global(), permitted: { true }, factory: { queue, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: three.candidates, selector: selector,
                        scopeKey: three.scopeKey, queue: queue, permitted: { true },
                        factory: { candidate, ownerQueue, _, _ in
                            AdaptiveMemoryTransport(send: { _ in probe.attempted(candidate) }, cancel: {
                                probe.transportCancelled()
                                // The deadline turn submits health after peer
                                // cancellation. Two passive FIFO hops observe
                                // that submission without an extra cancel/ACK.
                                ownerQueue.async { ownerQueue.async { healthDrained.signal() } }
                            })
                        }, receive: receive, failure: failure, timeout: 0.4)
                }, receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }; flow.send(message)
            for _ in 0..<2 {
                try expect(probe.started.wait(timeout: .now() + 1) == .success, "known RTT 负测的两个候选未同时启动")
            }
            if deadline { try awaitAdaptive(probe, query: message, expectFailure: true) }
            else { flow.cancel() }
            for _ in 0..<2 {
                try expect(probe.cancelled.wait(timeout: .now() + 1) == .success, "known RTT 结束未取消两个自己的请求")
            }
            for _ in 0..<2 {
                try expect(healthDrained.wait(timeout: .now() + 1) == .success, "known RTT 结束未排空真实 owner 队列的健康回执")
            }
            let next = selector.orderedCandidates(scopeKey: three.scopeKey, candidateIDs: threeIDs)
            try expect(next.first == (deadline ? threeIDs[2] : threeIDs[0])
                       && selector.knownLatencyMilliseconds(scopeKey: three.scopeKey, candidateID: threeIDs[0]) == 2500
                       && probe.snapshot.answers.isEmpty && probe.concurrency.active == 0
                       && probe.concurrency.cancelled == 2,
                       "known RTT 下 user cancel 被罚、总 timeout 不罚或 live transport 泄漏")
        }
    }

    private static func adaptiveLocalCapacityIsolation() throws {
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.capacity.selftest.invalid/dns-query#203.0.113.72")
        let approved = try plan(router(profile)), ids = approved.candidates.map(\.id)
        for primaryDenied in [false, true] {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: approved.healthScopeKey, candidateIDs: ids)
            for (index, candidate) in approved.candidates.enumerated() {
                selector.record(scopeKey: approved.healthScopeKey, candidateID: candidate.id,
                                milliseconds: index == 0 ? 20 : index == 1 ? 500 : 900, success: true)
            }
            let message = try query("adaptive-capacity-isolation.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                scopeKey: approved.healthScopeKey, queue: .global(qos: .userInitiated), permitted: { true },
                factory: { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if primaryDenied || candidate.id != ids[0] {
                            queue.async { failure(NodeConnectionAdmissionError.capacityExceeded) }
                        } else if let answer = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 0.3) { receive(answer) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 1)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: primaryDenied)
            let order = selector.orderedCandidates(scopeKey: approved.healthScopeKey, candidateIDs: ids)
            try expect(probe.snapshot.attempts == approved.candidates.prefix(primaryDenied ? 1 : 2).map { $0.upstream.target.host }
                       && order == ids && probe.concurrency.active == 0,
                       "本地满额导致更多拨号、健康 primary 被丢弃或解析器健康排序被污染")
            if primaryDenied {
                try expect(probe.snapshot.error.map(EncryptedDNSQueryFailure.classify) == .capacity,
                           "真实容量失败被误归网络失败或授权降级")
            } else {
                try expect(selector.knownLatencyMilliseconds(scopeKey: approved.healthScopeKey, candidateID: ids[1]) == 500,
                           "被准入拒绝的 hedge 改写 RTT")
            }
        }
        for latePrimaryDenied in [false, true] {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: approved.healthScopeKey, candidateIDs: ids)
            for (index, candidate) in approved.candidates.enumerated() {
                selector.record(scopeKey: approved.healthScopeKey, candidateID: candidate.id,
                                milliseconds: index == 0 ? 20 : index == 1 ? 500 : 900, success: true)
            }
            let message = try query("adaptive-late-capacity-isolation.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                scopeKey: approved.healthScopeKey, queue: .global(qos: .userInitiated), permitted: { true },
                factory: { candidate, queue, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[0] {
                            queue.asyncAfter(deadline: .now() + 0.25) {
                                failure(latePrimaryDenied ? NodeConnectionAdmissionError.capacityExceeded : EncryptedDNSQueryFailure.network)
                            }
                        } else if latePrimaryDenied, candidate.id == ids[1], let answer = bootstrapAnswer(data) {
                            queue.asyncAfter(deadline: .now() + 0.6) { receive(answer) }
                        } else { queue.async { failure(NodeConnectionAdmissionError.capacityExceeded) } }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 1)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: !latePrimaryDenied)
            try expect(probe.snapshot.attempts == approved.candidates.prefix(2).map { $0.upstream.target.host }
                       && probe.concurrency.peak == 2 && probe.concurrency.active == 0,
                       "late primary capacity 的轮替 timer 或后续网络错误继续拨号第三候选")
            if !latePrimaryDenied {
                try expect(probe.snapshot.error.map(EncryptedDNSQueryFailure.classify) == .capacity,
                           "曾有本地容量 deny 的交换最终丢失了容量屏障")
            }
        }
    }

    private final class ProductionCapacityDialProbe {
        private let lock = NSLock()
        private var hosts: [String] = []
        func observed(_ host: String) { lock.lock(); hosts.append(host); lock.unlock() }
        var snapshot: [String] { lock.lock(); defer { lock.unlock() }; return hosts }
    }

    private static func productionEncryptedCapacityIsolation() throws {
        for tls in [false, true] {
            var profile = adaptiveProfile()
            profile.dnsProxyFallbackEnabled = false
            profile.encryptedDNSServers = (0..<3).map { index in
                tls ? "tls://203.0.113.\(70 + index):853"
                    : "https://capacity-\(index).selftest.invalid/dns-query#203.0.113.\(70 + index)"
            }
            let source = router(profile), dials = ProductionCapacityDialProbe()
            source.memoryFixtureDNSStreamDialer = { host, _, _, _, _, observe, done in
                dials.observed(host)
                observe(NodeConnectionAdmissionError.capacityExceeded)
                done(.failure(NodeConnectionAdmissionError.capacityExceeded)); return {}
            }
            defer { source.flushDNS() }
            let worker = DispatchQueue(label: "app.hajimi.dns.production-capacity-self-test")
            let name = "capacity-raw-owned.example.test", rawPlan = try plan(source, name: name)
            try expect(rawPlan.fallbackServers.isEmpty && rawPlan.candidates.count == 3,
                       "容量回归没有进入无普通回退的三个批准候选")
            // Both owner insert and owner-cache acquire must preserve the
            // typed failure. Do not exercise an adaptiveFactory test double.
            for _ in 0..<2 {
                let message = try query(name, 1), probe = AdaptiveProbe()
                let flow = try source.makeDNSUpstream(plan: rawPlan, queue: worker,
                                                      receive: probe.received, failure: probe.failed)
                flow.send(message); try awaitAdaptive(probe, query: message, expectFailure: true)
                try expect(probe.snapshot.error.map(EncryptedDNSQueryFailure.classify) == .capacity
                           && probe.snapshot.answers.isEmpty, "严格 resolver 工厂将容量转换成了上游 SERVFAIL")
                let ack = DispatchSemaphore(value: 0)
                (flow as? DNSQueryCancellationAcknowledging)?.cancel { ack.signal() }
                try expect(ack.wait(timeout: .now() + 1) == .success, "严格 resolver 容量取消 ACK 未完成")
            }
            let before = NetworkPerformanceDiagnostics.shared.snapshot()
            for index in 0..<2 {
                let name = "capacity-optimized-\(index).example.test", message = try query(name, 1), probe = AdaptiveProbe()
                let flow = try source.makeOptimizedDNSUpstream(plan: plan(source, name: name), queue: worker,
                                                               receive: probe.received, failure: probe.failed)
                flow.send(message); try awaitAdaptive(probe, query: message, expectFailure: true)
                // The public coordinator facade intentionally returns a
                // privacy-preserving generic Error. Its aggregate retains
                // the real reason, asserted below; retry policy must have
                // consumed the typed failure before that facade boundary.
                try expect(probe.snapshot.error != nil && probe.snapshot.answers.isEmpty,
                           "无普通回退的容量拒绝仍被当作成功答案")
                flow.cancel()
            }
            let after = NetworkPerformanceDiagnostics.shared.snapshot()
            try expect(dials.snapshot == Array(repeating: "203.0.113.70", count: 4)
                       && after.dnsUpstreamAttempts - before.dnsUpstreamAttempts == 2
                       && after.dnsFailureReasons[.capacity, default: 0] - before.dnsFailureReasons[.capacity, default: 0] == 2,
                       "无普通回退路径在容量拒绝后拨号备用、罚首选或伪报上游失败")
            let message = try query("capacity-client-servfail.example.test", 1, id: 0x5a5a), client = AdaptiveProbe()
            let facade = try source.makeDNSDatagram(original: RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP"),
                queue: worker, synthesizeFakeIP: false, receive: client.received, failure: client.failed)
            facade.send(message); try awaitAdaptive(client, query: message)
            facade.cancel(); worker.sync {}
            try expect(client.snapshot.answers[0][3] & 0x0f == 2 && dials.snapshot.count == 5,
                       "保留 typed 容量破坏客户端单次同 ID SERVFAIL 契约")
        }
        print("DNS production capacity isolation passed: DoH/DoT new/acquired owners, real adaptive factories without fallback, no provider penalty/fanout and exactly one client SERVFAIL")
    }

    private enum ParentDeadlineReason: String { case deadline, caller, policy, other }
    private enum ParentDeadlineMethod: String { case deadline, cancel }
    private static func parentDeadlineReason(_ state: DNSParentDeadlineMemoryState) -> ParentDeadlineReason {
        if !state.permitted { return .policy }
        if state.closed { return .caller }
        return state.deadlineSignalled ? .deadline : .other
    }

    private struct ParentDeadlineOwnerReceipt {
        let token: UUID, candidate: Int, createdAt: UInt64
        var sends = 0, cancels = 0, lates = 0, drains = 0, fences = 0
        var sendAt: UInt64?, cancelAt: UInt64?, lateAt: UInt64?, drainAt: UInt64?, fenceAt: UInt64?
        var cancelState: DNSParentDeadlineMemoryState?, fenceState: DNSParentDeadlineMemoryState?
    }
    private struct ParentDeadlineLedgerState {
        let mode: Int
        var owners: [ParentDeadlineOwnerReceipt] = [] // Never more than three; never remove an owner.
        var faults = 0, peakLive = 0, actions = 0, parentCalls = 0
        var firstForeign: UUID?, actionOwner: UUID?, actionAt: UInt64?
        var parentMethod: ParentDeadlineMethod?, parentAt: UInt64?
        var parentLive = Set<UUID>(), parentRetired = Set<UUID>()
        var terminalState: DNSParentDeadlineMemoryState?, terminalAt: UInt64?
        var terminalCandidates = Set<Int>()
        var terminalFenceState: DNSParentDeadlineMemoryState?, terminalFenceAt: UInt64?
        func diagnostics() -> String {
            let reason = terminalState.map { DNSSecurityRoutingSelfTest.parentDeadlineReason($0).rawValue } ?? "unobserved"
            let childFirst = terminalAt.flatMap { ended in parentAt.map { ended < $0 } }
            let receipts = owners.map {
                "owner=\($0.token.uuidString), candidate=\($0.candidate), created=1, send=\($0.sends), cancel=\($0.cancels), late=\($0.lates), drain=\($0.drains), fence=\($0.fences), createdNs=\($0.createdAt), sendNs=\($0.sendAt.map { String($0) } ?? "none"), cancelNs=\($0.cancelAt.map { String($0) } ?? "none"), lateNs=\($0.lateAt.map { String($0) } ?? "none"), drainNs=\($0.drainAt.map { String($0) } ?? "none"), fenceNs=\($0.fenceAt.map { String($0) } ?? "none")"
            }.joined(separator: " | ")
            return "mode=\(mode), parent=\(parentMethod?.rawValue ?? "unobserved"), child=\(reason), childEndedBeforeParent=\(childFirst.map { String($0) } ?? "unobserved"), owners=\(owners.count), peakLive=\(peakLive), terminalCandidates=\(terminalCandidates.sorted()), actionNs=\(actionAt.map { String($0) } ?? "none"), parentNs=\(parentAt.map { String($0) } ?? "none"), childEndNs=\(terminalAt.map { String($0) } ?? "none"), quiescenceNs=\(terminalFenceAt.map { String($0) } ?? "none"), faults=\(faults), firstForeign=\(firstForeign?.uuidString ?? "none"); \(receipts)"
        }
    }
    private final class ParentDeadlineOwnerLedger {
        private enum Event { case send, cancel(DNSParentDeadlineMemoryState?), late, drain, fence(DNSParentDeadlineMemoryState?) }
        let terminalFence = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var state: ParentDeadlineLedgerState
        init(mode: Int) { state = ParentDeadlineLedgerState(mode: mode) }
        init(forMemoryVector state: ParentDeadlineLedgerState) { self.state = state }
        func fault() { lock.lock(); state.faults += 1; lock.unlock() }
        func create(candidate: Int) -> UUID {
            let token = UUID(), now = DispatchTime.now().uptimeNanoseconds
            lock.lock(); defer { lock.unlock() }
            guard state.owners.count < 3 else { state.faults += 1; state.firstForeign = state.firstForeign ?? token; return token }
            if state.parentCalls != 0 || state.terminalState != nil { state.faults += 1 }
            state.owners.append(ParentDeadlineOwnerReceipt(token: token, candidate: candidate, createdAt: now))
            state.peakLive = max(state.peakLive, state.owners.filter { $0.cancels == 0 }.count)
            return token
        }
        func sent(_ token: UUID) -> Bool { record(.send, token: token) }
        func cancelled(_ token: UUID, child: DNSParentDeadlineMemoryState?) { _ = record(.cancel(child), token: token) }
        func late(_ token: UUID) { _ = record(.late, token: token) }
        func drained(_ token: UUID) { _ = record(.drain, token: token) }
        func fenced(_ token: UUID, child: DNSParentDeadlineMemoryState?) { _ = record(.fence(child), token: token) }
        private func record(_ event: Event, token: UUID) -> Bool {
            let now = DispatchTime.now().uptimeNanoseconds
            var secondSend = false, wakeTerminal = false
            lock.lock()
            guard let index = state.owners.firstIndex(where: { $0.token == token }) else {
                state.faults += 1; state.firstForeign = state.firstForeign ?? token; lock.unlock(); return false
            }
            var owner = state.owners[index]
            switch event {
            case .send:
                owner.sends += 1; owner.sendAt = owner.sendAt ?? now
                if state.parentCalls != 0 || state.terminalState != nil { state.faults += 1 }
                secondSend = owner.sends == 1 && state.owners.filter { $0.sends > 0 }.count == 1
            case .cancel(let child):
                owner.cancels += 1; owner.cancelAt = owner.cancelAt ?? now
                owner.cancelState = owner.cancelState ?? child
                if let child {
                    if child.finished, state.terminalState == nil {
                        state.terminalState = child; state.terminalAt = now
                        state.terminalCandidates = Set(state.owners.map(\.candidate)).subtracting(child.retiredCandidates)
                    }
                } else { state.faults += 1 }
            case .late:
                owner.lates += 1; owner.lateAt = owner.lateAt ?? now
                if owner.sends != 1 || owner.cancels != 1 || state.terminalState == nil { state.faults += 1 }
            case .drain:
                owner.drains += 1; owner.drainAt = owner.drainAt ?? now
                if owner.lates != 1 { state.faults += 1 }
            case .fence(let child):
                owner.fences += 1; owner.fenceAt = owner.fenceAt ?? now
                owner.fenceState = owner.fenceState ?? child
                if let child {
                    if child.finished, child.activeCandidates.isEmpty, state.terminalFenceState == nil {
                        state.terminalFenceState = child; state.terminalFenceAt = now; wakeTerminal = true
                    }
                } else { state.faults += 1 }
            }
            state.owners[index] = owner
            lock.unlock()
            if wakeTerminal { terminalFence.signal() } // Passive owner-queue observation, never a native/kernel ACK.
            return secondSend
        }
        func action(_ token: UUID) {
            let now = DispatchTime.now().uptimeNanoseconds
            lock.lock(); state.actions += 1; state.actionOwner = state.actionOwner ?? token
            state.actionAt = state.actionAt ?? now; lock.unlock()
        }
        func parentEnded(_ method: ParentDeadlineMethod) {
            let now = DispatchTime.now().uptimeNanoseconds
            lock.lock(); defer { lock.unlock() }
            state.parentCalls += 1
            guard state.parentAt == nil else { return }
            state.parentAt = now; state.parentMethod = method
            state.parentLive = Set(state.owners.filter { $0.cancels == 0 }.map(\.token))
            state.parentRetired = Set(state.owners.filter {
                $0.cancelState?.finished == false && $0.cancelState?.retiredCandidates.contains($0.candidate) == true
            }.map(\.token))
        }
        var snapshot: ParentDeadlineLedgerState { lock.lock(); defer { lock.unlock() }; return state }
    }
    private final class ParentDeadlineReferences {
        private let lock = NSLock()
        private weak var child: DNSAdaptiveQueryDatagram?
        private weak var lease: DNSCoalescedQueryDatagram?
        func setChild(_ child: DNSAdaptiveQueryDatagram) { lock.lock(); self.child = child; lock.unlock() }
        func setLease(_ lease: DNSCoalescedQueryDatagram) { lock.lock(); self.lease = lease; lock.unlock() }
        var currentChild: DNSAdaptiveQueryDatagram? { lock.lock(); defer { lock.unlock() }; return child }
        var currentLease: DNSCoalescedQueryDatagram? { lock.lock(); defer { lock.unlock() }; return lease }
    }
    /// Transparent fixture metadata only; every operation reaches the real
    /// adaptive child, without extra cancel calls or manufactured acknowledgements.
    private final class ParentDeadlineObservedChild: NativeRoutedDatagram, DNSQueryDeadlineAwareDatagram {
        let child: DNSAdaptiveQueryDatagram, ledger: ParentDeadlineOwnerLedger
        init(_ child: DNSAdaptiveQueryDatagram, ledger: ParentDeadlineOwnerLedger) { self.child = child; self.ledger = ledger }
        func send(_ data: Data) { child.send(data) }
        func queryDeadlineReached() { ledger.parentEnded(.deadline); child.queryDeadlineReached() }
        func cancel() { ledger.parentEnded(.cancel); child.cancel() }
    }
    private struct ParentDeadlineOutcome {
        var ledger: ParentDeadlineLedgerState
        var orders: [[Int]], rtts: [Double?]
        var sent: Int, cancelled: Int, active: Int, peak: Int, answers: Int, pending: Int
    }
    private static let parentDeadlinePermutations = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]
    private static func parentDeadlineOracle(_ result: ParentDeadlineOutcome) -> String? {
        let state = result.ledger, owners = state.owners
        guard state.faults == 0, state.firstForeign == nil, (0..<4).contains(state.mode), (2...3).contains(owners.count),
              Set(owners.map(\.token)).count == owners.count,
              owners.map(\.candidate) == Array(0..<owners.count), state.peakLive == 2, result.peak == 2 else {
            return "foreign/duplicate/post-terminal owner or invalid admission bound"
        }
        guard state.parentCalls == 1, let method = state.parentMethod, let parentAt = state.parentAt,
              let terminal = state.terminalState, let terminalAt = state.terminalAt,
              let fence = state.terminalFenceState, let fenceAt = state.terminalFenceAt,
              terminal.finished, terminal.activeCandidates.isEmpty, fence.finished, fence.activeCandidates.isEmpty,
              fence.retiredCandidates.isEmpty,
              terminal.attempts == owners.count, fence.attempts == owners.count, terminalAt <= fenceAt else {
            return "missing actual parent/child terminal or passive quiescence receipt"
        }
        guard state.actions == (state.mode == 0 ? 0 : 1),
              state.actionOwner == (state.mode == 0 ? nil : owners[1].token) else { return "incorrect second-send action receipt" }
        if state.mode == 0 {
            guard state.actionAt == nil else { return "unrequested caller action" }
        } else {
            guard let actionAt = state.actionAt, let secondSendAt = owners[1].sendAt,
                  secondSendAt <= actionAt, actionAt <= parentAt, actionAt <= terminalAt else { return "second-send action lost its actual event ordering" }
        }
        let retired = Set(owners.filter {
            $0.cancelState?.finished == false && $0.cancelState?.retiredCandidates.contains($0.candidate) == true
        }.map(\.candidate))
        guard retired.isSubset(of: [1]), terminal.retiredCandidates == retired,
              state.terminalCandidates == Set(owners.map(\.candidate)).subtracting(retired),
              (1...2).contains(state.terminalCandidates.count) else { return "terminal/retired owner identity mismatch" }
        let liveAtParent = Set(owners.filter {
            $0.createdAt <= parentAt && ($0.cancelAt.map { $0 > parentAt } ?? true)
        }.map(\.token))
        let retiredAtParent = Set(owners.filter {
            retired.contains($0.candidate) && ($0.cancelAt.map { $0 <= parentAt } ?? false)
        }.map(\.token))
        guard state.parentLive == liveAtParent, state.parentRetired == retiredAtParent else { return "parent event owner-set mismatch" }
        let reason = parentDeadlineReason(terminal)
        let requiredReason: ParentDeadlineReason = state.mode < 2 ? .deadline : state.mode == 2 ? .caller : .policy
        let requiredMethod: ParentDeadlineMethod = state.mode < 2 ? .deadline : .cancel
        // A truthful deadline winning a caller-cancel race is still a failed
        // caller scenario, never permission to change this oracle's purpose.
        guard reason == requiredReason, method == requiredMethod else { return "actual termination does not belong to this requested scenario" }
        for owner in owners {
            guard (0...1).contains(owner.sends), owner.cancels == 1, owner.fences == 1,
                  let cancelAt = owner.cancelAt, let ownerFenceAt = owner.fenceAt,
                  let cancellation = owner.cancelState, let observation = owner.fenceState,
                  owner.createdAt <= parentAt, owner.createdAt <= terminalAt,
                  owner.createdAt <= cancelAt, cancelAt <= ownerFenceAt,
                  (1...owners.count).contains(cancellation.attempts), cancellation.activeCandidates.count <= 2,
                  (1...owners.count).contains(observation.attempts), observation.activeCandidates.count <= 2,
                  cancellation.activeCandidates.isSubset(of: Set(0..<cancellation.attempts)),
                  cancellation.retiredCandidates.isSubset(of: [1]),
                  observation.activeCandidates.isSubset(of: Set(0..<observation.attempts)),
                  observation.retiredCandidates.isSubset(of: [1]) else { return "missing/duplicate/foreign owner cancellation or observation" }
            if cancellation.finished {
                guard cancellation.activeCandidates.isEmpty, parentDeadlineReason(cancellation) == reason,
                      !retired.contains(owner.candidate) else { return "owner cleanup has inconsistent terminal identity" }
            } else if retired.contains(owner.candidate) {
                guard owner.sends == 1, !cancellation.closed, !cancellation.deadlineSignalled, cancellation.permitted,
                      !cancellation.activeCandidates.contains(owner.candidate) else { return "retirement is not an actual nonterminal owner event" }
            } else {
                // A returned factory owner may lose its remaining budget
                // before send. It still needs its own real cancellation.
                guard owner.sends == 0, cancellation.activeCandidates.contains(owner.candidate) else { return "unclassified preterminal cancellation" }
            }
            if owner.sends == 1 {
                guard owner.lates == 1, owner.drains == 1, let sendAt = owner.sendAt,
                      let lateAt = owner.lateAt, let drainAt = owner.drainAt,
                      owner.createdAt <= sendAt, sendAt <= parentAt, sendAt <= terminalAt,
                      sendAt <= cancelAt, cancelAt <= lateAt,
                      terminalAt <= lateAt, lateAt <= drainAt else { return "missing/duplicate/early late-owner callback or drain" }
            } else if owner.lates != 0 || owner.drains != 0 || owner.sendAt != nil || owner.lateAt != nil || owner.drainAt != nil {
                return "unsent owner fabricated a late callback"
            }
        }
        let sent = owners.filter { $0.sends == 1 }.count
        guard (2...3).contains(sent), result.sent == sent, result.cancelled == owners.count,
              result.active == 0, result.answers == 0, result.pending == 0,
              result.rtts.count == 3, result.rtts.allSatisfy({ $0 == nil }), result.orders.count == 6 else {
            return "late answer/RTT revival, leaked work, or receipt aggregate mismatch"
        }
        let penalized = reason == .deadline ? state.terminalCandidates : Set<Int>()
        for (input, order) in zip(parentDeadlinePermutations, result.orders) {
            let untouched = input.filter { !penalized.contains($0) }
            // The actual failure calls can have distinct cooldown instants.
            // Verify exact membership, not a timer-sensitive tie inside the
            // failed partition; neutral/untouched candidates keep input order.
            guard order.count == 3, Set(order) == Set(input),
                  Array(order.prefix(untouched.count)) == untouched,
                  Set(order.dropFirst(untouched.count)) == penalized else {
                return "deadline-active health partition or caller/policy neutrality mismatch"
            }
        }
        return nil
    }

    private static func parentDeadlineVector(owners count: Int, reason: ParentDeadlineReason = .deadline,
        mode: Int = 0, retireSecond: Bool = false, unsentThird: Bool = false) -> ParentDeadlineOutcome {
        let retires = retireSecond || count == 3
        let retired: Set<Int> = retires ? [1] : []
        let ended = DNSParentDeadlineMemoryState(finished: true, closed: reason == .caller,
            deadlineSignalled: reason == .deadline, permitted: reason != .policy,
            attempts: count, activeCandidates: [], retiredCandidates: retired)
        let quiet = DNSParentDeadlineMemoryState(finished: true, closed: ended.closed,
            deadlineSignalled: ended.deadlineSignalled, permitted: ended.permitted,
            attempts: count, activeCandidates: [], retiredCandidates: [])
        var state = ParentDeadlineLedgerState(mode: mode)
        state.peakLive = 2; state.parentCalls = 1
        state.parentMethod = reason == .deadline ? .deadline : .cancel
        state.parentAt = unsentThird ? 1_000 : 800
        state.terminalState = ended; state.terminalAt = 900
        state.terminalFenceState = quiet; state.terminalFenceAt = unsentThird ? 1_049 : 1_050
        for index in 0..<count {
            var owner = ParentDeadlineOwnerReceipt(token: UUID(), candidate: index,
                createdAt: index == 0 ? 100 : index == 1 ? 300 : 700)
            owner.sends = unsentThird && index == 2 ? 0 : 1
            if owner.sends == 1 { owner.sendAt = owner.createdAt + 10 }
            owner.cancels = 1; owner.fences = 1
            owner.cancelAt = UInt64(900 + index); owner.cancelState = ended
            owner.fenceAt = UInt64(1_050 + index); owner.fenceState = quiet
            if retires && index == 1 {
                owner.cancelAt = 600
                owner.cancelState = DNSParentDeadlineMemoryState(finished: false, closed: false,
                    deadlineSignalled: false, permitted: true, attempts: 2,
                    activeCandidates: [0], retiredCandidates: [1])
                if unsentThird { owner.fenceAt = 1_049 }
                else {
                    owner.fenceAt = 760
                    owner.fenceState = DNSParentDeadlineMemoryState(finished: false, closed: false,
                        deadlineSignalled: false, permitted: true, attempts: count,
                        activeCandidates: count == 3 ? [0, 2] : [0], retiredCandidates: [1])
                }
            } else if unsentThird && index == 2 {
                owner.cancelAt = 850
                owner.cancelState = DNSParentDeadlineMemoryState(finished: false, closed: false,
                    deadlineSignalled: false, permitted: true, attempts: 3,
                    activeCandidates: [0, 2], retiredCandidates: [1])
            }
            if owner.sends == 1 {
                owner.lates = 1; owner.drains = 1
                owner.lateAt = UInt64(1_200 + index); owner.drainAt = UInt64(1_300 + index)
            }
            state.owners.append(owner)
        }
        state.terminalCandidates = Set(state.owners.map(\.candidate)).subtracting(retired)
        state.parentLive = Set(state.owners.filter { $0.cancelAt! > state.parentAt! }.map(\.token))
        state.parentRetired = Set(state.owners.filter { retired.contains($0.candidate) }.map(\.token))
        if mode != 0 { state.actions = 1; state.actionOwner = state.owners[1].token; state.actionAt = 311 }
        let penalized = reason == .deadline ? state.terminalCandidates : Set<Int>()
        return ParentDeadlineOutcome(ledger: state,
            orders: parentDeadlinePermutations.map { input in
                input.filter { !penalized.contains($0) } + input.filter { penalized.contains($0) }
            }, rtts: [nil, nil, nil], sent: state.owners.filter { $0.sends == 1 }.count,
            cancelled: count, active: 0, peak: 2, answers: 0, pending: 0)
    }
    private static func parentDeadlineOwnerOracleVectors() throws {
        let two = parentDeadlineVector(owners: 2), three = parentDeadlineVector(owners: 3)
        let caller = parentDeadlineVector(owners: 2, reason: .caller, mode: 2)
        let policy = parentDeadlineVector(owners: 2, reason: .policy, mode: 3)
        var reorderedFailures = two
        reorderedFailures.orders = two.orders.map { [$0[0]] + Array($0.dropFirst().reversed()) }
        let positives = [two, three, caller, policy, reorderedFailures,
            parentDeadlineVector(owners: 2, mode: 1),
            parentDeadlineVector(owners: 2, retireSecond: true),
            parentDeadlineVector(owners: 3, unsentThird: true)]
        for vector in positives {
            try expect(parentDeadlineOracle(vector) == nil, "合法 2/3 owner、退役或未发送 owner 被拒绝")
        }
        let negatives: [(String, ParentDeadlineOutcome, (inout ParentDeadlineOutcome) -> Void)] = [
            ("missing cancel", three, { $0.ledger.owners[2].cancels = 0 }),
            ("duplicate hides missing", three, { $0.ledger.owners[0].cancels = 2; $0.ledger.owners[2].cancels = 0 }),
            ("foreign cancel", two, { $0.ledger.faults = 1; $0.ledger.firstForeign = UUID() }),
            ("duplicate owner", two, { value in
                let old = value.ledger.owners[1]
                value.ledger.owners[1] = ParentDeadlineOwnerReceipt(token: value.ledger.owners[0].token,
                    candidate: old.candidate, createdAt: old.createdAt)
            }),
            ("foreign candidate", three, { value in
                let old = value.ledger.owners[2]
                value.ledger.owners[2] = ParentDeadlineOwnerReceipt(token: old.token, candidate: 3, createdAt: old.createdAt)
            }),
            ("fourth owner", three, { $0.ledger.owners.append(ParentDeadlineOwnerReceipt(token: UUID(), candidate: 3, createdAt: 800)) }),
            ("missing late", three, { $0.ledger.owners[2].lates = 0 }),
            ("duplicate hides missing late", three, { $0.ledger.owners[0].lates = 2; $0.ledger.owners[2].lates = 0 }),
            ("missing drain", two, { $0.ledger.owners[0].drains = 0 }),
            ("missing fence", two, { $0.ledger.owners[0].fences = 0 }),
            ("duplicate fence", two, { $0.ledger.owners[0].fences = 2 }),
            ("missing terminal", two, { $0.ledger.terminalState = nil }),
            ("missing quiescence", two, { $0.ledger.terminalFenceState = nil }),
            ("unbound foreign metadata", two, { $0.ledger.firstForeign = UUID() }),
            ("wrong live identity", three, { $0.ledger.parentLive = [UUID()] }),
            ("wrong retired identity", three, { $0.ledger.parentRetired = [] }),
            ("wrong terminal participant", three, { $0.ledger.terminalCandidates = [0, 1] }),
            ("late before cancel", two, { $0.ledger.owners[0].lateAt = 500 }),
            ("post-terminal send", two, { $0.ledger.owners[0].sendAt = 1_000 }),
            ("caller health penalty", caller, { $0.orders = three.orders }),
            ("policy health penalty", policy, { $0.orders = two.orders }),
            ("deadline not penalized", two, { $0.orders = parentDeadlinePermutations }),
            ("retired health penalty", three, { $0.orders = two.orders }),
            ("late RTT revival", two, { $0.rtts[0] = 500 }),
            ("late application answer", two, { $0.answers = 1 }),
            ("pending leaked", two, { $0.pending = 1 }),
            ("three live", three, { $0.ledger.peakLive = 3 }),
            ("mode0 caller with matching neutral health", parentDeadlineVector(owners: 2, reason: .caller), { _ in }),
            ("mode1 caller with matching neutral health", parentDeadlineVector(owners: 2, reason: .caller, mode: 1), { _ in }),
            ("mode2 deadline with matching penalized health", parentDeadlineVector(owners: 2, mode: 2), { _ in }),
            ("mode3 deadline with matching penalized health", parentDeadlineVector(owners: 2, mode: 3), { _ in }),
            ("mode3 caller with matching neutral health", parentDeadlineVector(owners: 2, reason: .caller, mode: 3), { _ in }),
            ("mode0 child-first deadline wrong parent method", parentDeadlineVector(owners: 3, unsentThird: true), { $0.ledger.parentMethod = .cancel }),
            ("mode1 child-first deadline wrong parent method", parentDeadlineVector(owners: 3, mode: 1, unsentThird: true), { $0.ledger.parentMethod = .cancel }),
            ("mode2 caller wrong parent method", caller, { $0.ledger.parentMethod = .deadline }),
            ("mode3 policy wrong parent method", policy, { $0.ledger.parentMethod = .deadline }),
            ("unsent fabricated late", parentDeadlineVector(owners: 3, unsentThird: true), { value in
                value.ledger.owners[2].lates = 1; value.ledger.owners[2].drains = 1
                value.ledger.owners[2].lateAt = 1_202; value.ledger.owners[2].drainAt = 1_302
            })
        ]
        for (name, original, alter) in negatives {
            var broken = original; alter(&broken)
            try expect(parentDeadlineOracle(broken) != nil, "owner oracle 接受负向量：\(name)")
        }
        // Exercise actual ledger admission rather than relying only on a
        // synthetic fault flag: no foreign or duplicate callback is deduped.
        let foreign = ParentDeadlineOwnerLedger(forMemoryVector: two.ledger)
        foreign.cancelled(UUID(), child: two.ledger.terminalState)
        var foreignResult = two; foreignResult.ledger = foreign.snapshot
        try expect(parentDeadlineOracle(foreignResult) != nil, "实际 ledger 接受 foreign cancel")
        let duplicate = ParentDeadlineOwnerLedger(forMemoryVector: three.ledger)
        duplicate.cancelled(three.ledger.owners[0].token, child: three.ledger.terminalState)
        var duplicateResult = three; duplicateResult.ledger = duplicate.snapshot
        try expect(parentDeadlineOracle(duplicateResult) != nil, "实际 ledger 去重并接受 duplicate cancel")
        print("DNS parent-deadline owner oracle vectors passed: \(positives.count) positive / \(negatives.count + 2) negative, exact identities and truthful termination health")
    }

    private static func adaptiveParentDeadlineHealth() throws {
        try parentDeadlineOwnerOracleVectors()
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let approved = try plan(router(profile)), ids = approved.candidates.map(\.id)
        // Actual coordinator + actual adaptive child, with equal 350ms timers.
        // The 30ms factory setup normally places the parent first, but actual
        // receipts, not wall-clock assumptions, determine cleanup and health.
        for mode in 0..<4 {
            let coordinator = DNSQueryCoordinator(timeout: .milliseconds(350))
            let selector = DNSAdaptiveUpstreamSelector(), gate = AdaptivePolicyGate(), probe = AdaptiveProbe()
            let ledger = ParentDeadlineOwnerLedger(mode: mode), references = ParentDeadlineReferences()
            defer { print("DNS parent-deadline memory receipts: \(ledger.snapshot.diagnostics())") }
            let message = try query("adaptive-parent-deadline.example.test", 1)
            let flow = DNSCoalescedQueryDatagram(coordinator: coordinator, scope: approved.scopeKey,
                queue: DispatchQueue(label: "app.hajimi.dns.parent-deadline-self-test"),
                permitted: gate.permits, factory: { queue, receive, failure in
                    Thread.sleep(forTimeInterval: 0.03)
                    let child = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                        scopeKey: approved.scopeKey, queue: queue, permitted: gate.permits,
                        factory: { candidate, queue, receive, _ in
                            let owner = ledger.create(candidate: ids.firstIndex(of: candidate.id) ?? -1)
                            return AdaptiveMemoryTransport(send: { data in
                                if data != message { ledger.fault() }
                                let secondSend = ledger.sent(owner)
                                probe.attempted(candidate)
                                // Perform the original action at the actual
                                // second send, not after a main-thread wakeup.
                                if secondSend, mode != 0 {
                                    ledger.action(owner)
                                    switch mode {
                                    case 1:
                                        if let lease = references.currentLease { lease.queryDeadlineReached() }
                                        else { ledger.fault() }
                                    case 2:
                                        if let lease = references.currentLease { lease.cancel() }
                                        else { ledger.fault() }
                                    case 3: gate.revoke()
                                    default: ledger.fault()
                                    }
                                }
                                if let reply = bootstrapAnswer(data) {
                                    queue.asyncAfter(deadline: .now() + 0.5) {
                                        ledger.late(owner)
                                        if !DNSMessageInspection.responseMatchesQuery(reply, query: message) { ledger.fault() }
                                        receive(reply)
                                        // receive() queues accept() on this
                                        // same child queue. This FIFO marker
                                        // observes that handoff; it is no ACK.
                                        queue.async { ledger.drained(owner); probe.late.signal() }
                                    }
                                } else { ledger.fault() }
                            }, cancel: {
                                let actualChild = references.currentChild
                                ledger.cancelled(owner, child: actualChild?.parentDeadlineStateForMemorySelfTest())
                                probe.transportCancelled()
                                // Retain only an already observed cancel's
                                // child until this bounded passive inspection.
                                // No cancel/finish call can create the receipt.
                                queue.async {
                                    ledger.fenced(owner, child: actualChild?.parentDeadlineStateForMemorySelfTest())
                                }
                            })
                        }, receive: receive, failure: failure, timeout: 0.35)
                    references.setChild(child)
                    return ParentDeadlineObservedChild(child, ledger: ledger)
                }, receive: probe.received, failure: probe.failed)
            references.setLease(flow)
            defer { flow.cancel() }
            let began = ProcessInfo.processInfo.systemUptime; flow.send(message)
            for _ in 0..<2 {
                try expect(probe.started.wait(timeout: .now() + 1) == .success,
                           "父期限 mode \(mode) 未形成两个真实 send owner")
            }
            if mode == 0 || mode == 3 {
                try awaitAdaptive(probe, query: message, expectFailure: true)
                try expect(ProcessInfo.processInfo.systemUptime - began < 0.8,
                           "父期限等待子 timer 或延长了等待者的总预算")
            }
            let cancellationDeadline = DispatchTime.now() + 1
            try expect(ledger.terminalFence.wait(timeout: cancellationDeadline) == .success,
                       "父期限 mode \(mode) 缺少实际 finished/active0 被动观察；\(ledger.snapshot.diagnostics())")
            let ended = ledger.snapshot
            for _ in ended.owners {
                try expect(probe.cancelled.wait(timeout: cancellationDeadline) == .success,
                           "父期限 mode \(mode) 缺少 factory owner 的真实取消调用；\(ledger.snapshot.diagnostics())")
            }
            for _ in ended.owners.filter({ $0.sends == 1 }) {
                try expect(probe.late.wait(timeout: .now() + 1) == .success,
                           "父期限 mode \(mode) 缺少已发送 owner 的 late/drain；\(ledger.snapshot.diagnostics())")
            }
            // Keep all three approved IDs for each observation: querying a
            // subset would remove the omitted candidates' health records.
            // Seven total order reads remain below the exploration cadence.
            let orders = parentDeadlinePermutations.map { permutation in
                selector.orderedCandidates(scopeKey: approved.scopeKey, candidateIDs: permutation.map { ids[$0] })
                    .map { ids.firstIndex(of: $0) ?? -1 }
            }
            let rtts = ids.map { selector.knownLatencyMilliseconds(scopeKey: approved.scopeKey, candidateID: $0) }
            let callbacks = probe.snapshot, concurrency = probe.concurrency
            let outcome = ParentDeadlineOutcome(ledger: ledger.snapshot, orders: orders, rtts: rtts,
                sent: callbacks.attempts.count, cancelled: concurrency.cancelled, active: concurrency.active,
                peak: concurrency.peak, answers: callbacks.answers.count, pending: coordinator.statistics.pendingQueries)
            if let failure = parentDeadlineOracle(outcome) {
                throw Failure(text: "parent deadline owner oracle: \(failure); \(outcome.ledger.diagnostics())")
            }
        }

        // One expired ingress lease cannot expire single-flight followers.
        let coordinator = DNSQueryCoordinator(timeout: .milliseconds(600))
        let selector = DNSAdaptiveUpstreamSelector(), lifecycle = AdaptiveProbe()
        let leader = AdaptiveProbe(), follower = AdaptiveProbe()
        let first = try query("adaptive-expired-leader.example.test", 1, id: 0x7101)
        let second = try query("adaptive-expired-leader.example.test", 1, id: 0x7102)
        let leaderFlow = DNSCoalescedQueryDatagram(coordinator: coordinator, scope: approved.scopeKey,
            queue: .global(), permitted: { true }, factory: { queue, receive, failure in
                DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector,
                    scopeKey: approved.scopeKey, queue: queue, permitted: { true },
                    factory: { candidate, queue, receive, _ in
                        AdaptiveMemoryTransport(send: { data in
                            lifecycle.attempted(candidate)
                            if candidate.id == ids[0], let reply = bootstrapAnswer(data) {
                                queue.asyncAfter(deadline: .now() + 0.3) { receive(reply) }
                            }
                        }, cancel: lifecycle.transportCancelled)
                    }, receive: receive, failure: failure, timeout: 0.6)
            }, receive: leader.received, failure: leader.failed)
        defer { leaderFlow.cancel() }; leaderFlow.send(first)
        try expect(lifecycle.started.wait(timeout: .now() + 1) == .success, "single-flight leader 未开始")
        let followerFlow = DNSCoalescedQueryDatagram(coordinator: coordinator, scope: approved.scopeKey,
            queue: .global(), permitted: { true }, factory: { _, _, _ in
                throw Failure(text: "同问题 follower 启动第二个 adaptive")
            }, receive: follower.received, failure: follower.failed)
        defer { followerFlow.cancel() }; followerFlow.send(second)
        let joinDeadline = ProcessInfo.processInfo.systemUptime + 1
        while coordinator.statistics.waitingClients < 2 && ProcessInfo.processInfo.systemUptime < joinDeadline {
            Thread.sleep(forTimeInterval: 0.001)
        }
        try expect(coordinator.statistics.waitingClients == 2, "single-flight follower 未加入")
        try expect(lifecycle.started.wait(timeout: .now() + 1) == .success, "single-flight hedge 未开始")
        leaderFlow.queryDeadlineReached()
        try awaitAdaptive(follower, query: second)
        try expect(leader.snapshot.answers.isEmpty && leader.snapshot.error == nil
                   && lifecycle.concurrency.cancelled == 2
                   && selector.knownLatencyMilliseconds(scopeKey: approved.scopeKey, candidateID: ids[0]) != nil,
                   "单个过期 lease 取消 follower 或误记仍有所有者的健康交换为 timeout")
    }

    private final class AdaptiveBurstProbe {
        let lock = NSLock(), done = DispatchGroup()
        private var expected: [UInt16: Data] = [:], responses: [UInt16: Data] = [:]
        private var callbacks: [UInt16: Int] = [:], active: [UInt16: Int] = [:]
        private var attempts: [String: Int] = [:]
        private var failed = 0, invalid = 0, peak = 0
        func expectQuery(_ query: Data) -> UInt16 {
            let id = UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1])
            lock.lock(); expected[id] = query; lock.unlock(); done.enter(); return id
        }
        func attempted(_ candidate: DNSUpstreamCandidate, id: UInt16) {
            lock.lock(); attempts[candidate.upstream.target.host, default: 0] += 1
            active[id, default: 0] += 1; peak = max(peak, active[id]!); lock.unlock()
        }
        func cancelled(_ id: UInt16) {
            lock.lock(); active[id, default: 0] -= 1
            if active[id]! < 0 { invalid += 1 }; lock.unlock()
        }
        func completed(_ answer: Data?, id: UInt16) {
            lock.lock(); callbacks[id, default: 0] += 1
            let first = callbacks[id] == 1
            if !first { invalid += 1 }
            if let answer, let query = expected[id], DNSMessageInspection.responseMatchesQuery(answer, query: query) {
                responses[id] = answer
            } else { failed += 1 }
            lock.unlock(); if first { done.leave() }
        }
        var snapshot: (responses: Int, failed: Int, invalid: Int, peak: Int, active: Int, attempts: [String: Int]) {
            lock.lock(); defer { lock.unlock() }
            return (responses.count, failed, invalid, peak, active.values.reduce(0, +), attempts)
        }
    }

    private static func adaptiveHealthScopeIsolationAndBurst() throws {
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        // Force the original cache/pool scope to observe every source port.
        profile.rules.insert(RoutingRule(kind: .sourcePort(41001...41001), policy: "REJECT", sourceLine: 0), at: 0)
        profile.rules.insert(RoutingRule(kind: .logicalAnd([.sourcePort(52000...52000),
            .ipCIDR("203.0.113.71/32")]), policy: "REJECT", sourceLine: 0), at: 0)
        let source = router(profile)
        let original = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP",
            sourceHost: "192.0.2.1", sourcePort: 50000, inboundPort: 7263)
        let first = try plan(source, original: original)
        for change in 0..<5 {
            var other = original
            switch change {
            case 0: other.sourcePort = 50001
            case 1: other.sourceHost = "192.0.2.2"
            case 2: other.inboundPort = 7264
            case 3: other.protocolName = "TCP"
            default: other.host = "203.0.113.54"
            }
            let next = try plan(source, original: other)
            try expect(next.scopeKey != first.scopeKey && next.healthScopeKey == first.healthScopeKey,
                       "共享健康状态放宽了 cache/单飞 scope 或同出站路径仍被来源碎片化")
        }
        var deniedPort = original; deniedPort.sourcePort = 41001
        try refusal(source, name: "allowed.example.test", type: 1, original: deniedPort)
        var filtered = original; filtered.sourcePort = 52000
        let filteredPlan = try plan(source, original: filtered)
        try expect(filteredPlan.candidates.count == 2 && filteredPlan.healthScopeKey != first.healthScopeKey,
                   "健康状态跨不同 source 策略批准集合共享")
        let snapshot = DNSRoutingSnapshot(profile: profile, mode: .rule, globalPolicy: "DIRECT", selections: [:],
            generation: first.generation, sourcePortSensitive: true)
        let providers = first.candidates.map(\.upstream)
        let otherNode = ProxyPolicy(name: "HealthOtherNode", kind: .http, host: "127.0.0.1", port: 1)
        try expect(snapshot.healthScope(upstreams: providers, route: .http(otherNode, otherNode.name),
                   interfaceName: first.interfaceName) != first.healthScopeKey,
                   "健康状态跨不同选定 node/route 共享")
        try expect(snapshot.healthScope(upstreams: providers, route: first.route,
                   interfaceName: "en-health-fixture") != first.healthScopeKey,
                   "健康状态跨物理接口共享")

        let trace = AdaptiveBurstProbe(), queue = DispatchQueue(label: "app.hajimi.dns.health-scope-burst-self-test")
        var fullScopes = Set<String>(), healthScopes = Set<String>(), flows: [NativeRoutedDatagram] = []
        for index in 0..<64 {
            var target = original; target.sourcePort = UInt16(50000 + index)
            let message = try query("adaptive-burst-\(index).example.test", 1, id: UInt16(0x8100 + index))
            guard case .upstream(let decision) = try source.prepareDNSQuery(message, original: target) else {
                throw Failure(text: "共享健康 burst 被意外合成")
            }
            fullScopes.insert(decision.scopeKey); healthScopes.insert(decision.healthScopeKey)
            let id = trace.expectQuery(message)
            let flow = try source.makeOptimizedDNSUpstream(plan: decision, queue: queue,
                adaptiveFactory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        trace.attempted(candidate, id: id)
                        if candidate.upstream.target.host == "203.0.113.72", let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.01) { receive(reply) }
                        }
                    }, cancel: { trace.cancelled(id) })
                }, adaptiveTimeout: 0.45, receive: { trace.completed($0, id: id) },
                failure: { _ in trace.completed(nil, id: id) })
            flows.append(flow); flow.send(message)
        }
        try expect(fullScopes.count == 64 && healthScopes.count == 1,
                   "64 来源端口没有保持独立缓存 scope/单一健康 path")
        try expect(trace.done.wait(timeout: .now() + 2) == .success, "64 跨来源健康 burst 未完成")
        let result = trace.snapshot
        try expect(result.responses == 64 && result.failed == 0 && result.invalid == 0
                   && result.peak <= 2 && result.active == 0
                   && result.attempts["203.0.113.72"] == 64
                   && result.attempts.values.reduce(0, +) <= 192,
                   "前两个 provider 沉默仍饿死第三候选、超过 2 live/3 attempts 或跨 ID 回包")
        flows.forEach { $0.cancel() }

        // New client tuples get the learned preference, not another client's
        // answer or transport: strict source scopes still require an exchange.
        for index in 0..<4 {
            var target = original
            target.host = "203.0.113.54"; target.protocolName = "TCP"; target.sourcePort = UInt16(52100 + index)
            target.sourceHost = "192.0.2.\(index + 2)"; target.inboundPort = 7264
            let message = try query("adaptive-burst-0.example.test", 1, id: UInt16(0x8200 + index))
            let decision = try plan(source, name: "adaptive-burst-0.example.test", original: target)
            try expect(!fullScopes.contains(decision.scopeKey) && decision.healthScopeKey == first.healthScopeKey,
                       "新的来源直接复用了旧 cache/单飞 scope")
            let probe = AdaptiveProbe()
            let flow = try adaptiveExchange(source, plan: decision, message: message, probe: probe) { candidate, worker, receive, _ in
                AdaptiveMemoryTransport(send: { data in
                    probe.attempted(candidate)
                    if let reply = bootstrapAnswer(data) { worker.async { receive(reply) } }
                }, cancel: probe.transportCancelled)
            }
            defer { flow.cancel() }; try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts == ["203.0.113.72"],
                       "新来源丢失同出站健康择优或借健康状态跳过真实交换")
        }
        profile.rules.insert(RoutingRule(kind: .domain("blocked.health.example.test"), policy: "REJECT", sourceLine: 0), at: 0)
        source.update(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
        try expect(try plan(source, original: original).healthScopeKey != first.healthScopeKey,
                   "健康状态跨配置代次共享")
        try refusal(source, name: "blocked.health.example.test", type: 1, original: original)
        withExtendedLifetime(flows) {}
        print("DNS health-scope burst passed: 64 strict source scopes / 1 health path, 64 replies, at most 2 live / 3 attempts")
    }

    private static func adaptiveHedgeRotation() throws {
        var profile = adaptiveProfile()
        profile.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let approved = try plan(router(profile)), ids = approved.candidates.map(\.id)
        let scope = approved.healthScopeKey
        // The primary survives a rotated hedge and may still win late.
        do {
            let clock = AdaptiveManualClock(), selector = DNSAdaptiveUpstreamSelector(clock: clock.now)
            let probe = AdaptiveProbe(), reply = AdaptiveManualReply(), absolute = clock.now() + 0.45
            let message = try query("rotation-primary-retained.example.test", 1)
            weak var checkpointFlow: DNSAdaptiveQueryDatagram?
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, _, receive, _ in
                    checkpointFlow?.pauseAdaptiveTimersForSelfTest()
                    return AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[0], let answer = bootstrapAnswer(data) {
                            reply.prepare { receive(answer) }
                        }
                    }, cancel: {
                        if candidate.id == ids[0] { reply.recordCancellation() }
                        probe.transportCancelled()
                    })
                }, receive: probe.received, failure: probe.failed, timeout: 0.45,
                absoluteDeadline: absolute, clock: clock.now)
            checkpointFlow = flow
            defer { flow.cancel() }; flow.send(message); flow.drainAdaptiveQueueForSelfTest()
            clock.advance(to: 0.15)
            try expect(flow.fireAdaptiveHedgeForSelfTest(), "primary 保留夹具没有装载原生 hedge callback")
            clock.advance(to: 0.3)
            try expect(flow.fireAdaptiveRotationForSelfTest(), "primary 保留夹具没有装载原生 rotation callback")
            try expect(probe.snapshot.attempts.count == 3 && probe.concurrency.active == 2
                       && probe.concurrency.cancelled == 1 && !reply.wasCancelled,
                       "轮替时未只退役 hedge，或提前取消仍可成功的 primary")
            clock.advance(to: 0.39)
            try expect(reply.release(), "轮替保留的 primary 没有可交付答复")
            try awaitAdaptive(probe, query: message)
            let state = flow.adaptiveStateForSelfTest
            try expect(probe.snapshot.attempts.count == 3 && probe.concurrency.peak == 2
                       && probe.concurrency.cancelled == 3 && probe.concurrency.active == 0
                       && state.attempts == 3 && state.active == 0 && state.started == 100
                       && state.deadline == absolute && clock.now() < absolute,
                       "轮替取消了仍可成功的慢 primary")
        }
        // Retirement is not a network error. Both an error delivered from
        // cancel() and a later valid old-hedge answer are obsolete tokens.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let message = try query("rotation-late-token.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, failure in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        guard var reply = bootstrapAnswer(data) else { return }
                        reply[reply.count - 1] = candidate.id == ids[2] ? 79 : 78
                        let response = reply
                        if candidate.id == ids[1] {
                            worker.asyncAfter(deadline: .now() + 0.23) { receive(response); probe.late.signal() }
                        } else if candidate.id == ids[2] {
                            worker.asyncAfter(deadline: .now() + 0.01) { receive(response) }
                        }
                    }, cancel: {
                        probe.transportCancelled()
                        if candidate.id == ids[1] { failure(EngineError("退役 hedge 的同步取消回调")) }
                    })
                }, receive: probe.received, failure: probe.failed, timeout: 0.45)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success
                       && DNSMessageInspection.addressAnswers(in: probe.snapshot.answers[0]).map(\.address) == ["203.0.113.79"]
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 3,
                       "late retired reply/error 复活或覆盖第三候选答案")
            // The two never-successful losers still tie at their prior score:
            // a cancellation error would have incorrectly cooled the hedge.
            try expect(selector.orderedCandidates(scopeKey: scope, candidateIDs: [ids[1], ids[0]]).first == ids[1],
                       "退役 hedge 被伪记网络失败或 cooldown")
        }
        for knownMilliseconds: Double in [10, 300] {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            selector.record(scopeKey: scope, candidateID: ids[0], milliseconds: 1, success: true)
            selector.record(scopeKey: scope, candidateID: ids[1], milliseconds: knownMilliseconds, success: true)
            selector.record(scopeKey: scope, candidateID: ids[2], milliseconds: 1000, success: true)
            let slowWorking = knownMilliseconds == 300
            let message = try query("rotation-known-\(Int(knownMilliseconds)).example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        guard let reply = bootstrapAnswer(data) else { return }
                        if slowWorking, candidate.id == ids[1] {
                            worker.asyncAfter(deadline: .now() + 0.24) { receive(reply) }
                        } else if !slowWorking, candidate.id == ids[2] { worker.async { receive(reply) } }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 0.45)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts.count == (slowWorking ? 2 : 3)
                       && probe.concurrency.peak == 2,
                       "已知慢 hedge 被剪掉或曾经快但现沉默的 hedge 仍饿死第三候选")
        }
        // A new concurrent RTT observation must extend the pending hedge's
        // headroom even after its short rotation timer was already scheduled.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let message = try query("rotation-new-slow-rtt.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[1], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.02) {
                                selector.record(scopeKey: scope, candidateID: candidate.id, milliseconds: 300, success: true)
                            }
                            worker.asyncAfter(deadline: .now() + 0.24) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 0.45)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts.count == 2, "旧 rotation timer 剪掉刚测得慢 RTT 的健康 hedge")
        }
        // A refusal delivered by the third approved provider is terminal;
        // rotating the slot cannot turn it into provider-shopping.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let message = try query("rotation-terminal-refused.example.test", 1)
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[0], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.4) { receive(reply); probe.late.signal() }
                        } else if candidate.id == ids[2], let refusal = DNSMessageInspection.errorResponse(to: data, code: .refused) {
                            worker.async { receive(refusal) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 0.45)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.late.wait(timeout: .now() + 1) == .success && probe.snapshot.answers.count == 1
                       && probe.snapshot.answers[0][3] & 0x0f == 5 && probe.snapshot.attempts.count == 3,
                       "第三 provider REFUSED 后继续接受旧 positive 或多开候选")
        }
        // A third provider's warm RTT must not turn into a cold-connection
        // timeout for the live hedge. Both known and unknown third providers
        // retain the conservative 8s * 2/3 rotation boundary.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            for (index, milliseconds) in [1.0, 10.0, 100.0].enumerated() {
                selector.record(scopeKey: scope, candidateID: ids[index], milliseconds: milliseconds, success: true)
            }
            let message = try query("rotation-measured-third-eight-second.example.test", 1)
            let started = ProcessInfo.processInfo.systemUptime
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[2], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.1) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 8,
                absoluteDeadline: started + 8)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message, waitTimeout: 7)
            let elapsed = ProcessInfo.processInfo.systemUptime - started
            try expect(elapsed >= 8.0 * (2.0 / 3.0) && elapsed < 8
                       && probe.snapshot.attempts.count == 3 && probe.snapshot.answers.count == 1
                       && probe.concurrency.peak == 2 && probe.concurrency.cancelled == 3,
                       "第三候选成功 RTT 仍提前取消冷 hedge，或突破原期限/2 live/3 attempt")
            print("DNS measured-third conservative rotation: parent=8000ms, rotation=5333ms, elapsed=\(Int(elapsed * 1000))ms, attempts=3, live-peak=2")
        }
        // A measured slow-but-working hedge keeps RTT headroom even though a
        // measured third path is available. Warm history cannot replace that
        // currently working path before its conservative rotation boundary.
        do {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            for (index, milliseconds) in [1.0, 500.0, 1000.0].enumerated() {
                selector.record(scopeKey: scope, candidateID: ids[index], milliseconds: milliseconds, success: true)
            }
            let message = try query("rotation-slow-measured-hedge-eight-second.example.test", 1)
            let started = ProcessInfo.processInfo.systemUptime
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[1], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.6) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 8,
                absoluteDeadline: started + 8)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts.count == 2 && probe.snapshot.answers.count == 1
                       && probe.concurrency.peak == 2,
                       "加速第三候选剪掉仍在测得 RTT 裕量内的合法慢 hedge")
        }
        // Warm RTT must not act as a cold TCP/TLS setup timeout. A backup
        // previously measured at 10ms may need 400/800ms for a fresh carrier;
        // replacing it with the known 1000ms third path would only add work.
        for setupSeconds in [0.4, 0.8] {
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
            for (index, milliseconds) in [1.0, 10.0, 1000.0].enumerated() {
                selector.record(scopeKey: scope, candidateID: ids[index], milliseconds: milliseconds, success: true)
            }
            let message = try query("rotation-warm-to-cold-\(Int(setupSeconds * 1000)).example.test", 1)
            let started = ProcessInfo.processInfo.systemUptime
            let flow = DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                queue: .global(), permitted: { true }, factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[1], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + setupSeconds) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 8,
                absoluteDeadline: started + 8)
            defer { flow.cancel() }; flow.send(message); try awaitAdaptive(probe, query: message)
            try expect(probe.snapshot.attempts.count == 2 && probe.snapshot.answers.count == 1
                       && probe.concurrency.peak == 2,
                       "暖 RTT 被当作冷握手超时，剪掉 \(Int(setupSeconds * 1000))ms 合法 backup")
        }
        try adaptiveWarmHistoryColdPhase(approved: approved)
    }

    private static func adaptiveWarmHistoryColdPhase(approved: DNSQueryPlan) throws {
        let ids = approved.candidates.map(\.id), scope = approved.healthScopeKey
        // These are synthetic historical successes and a memory response
        // delay, not measured TLS. The production parent/child state machines
        // retain the real 8s deadline and default 3s encrypted phase window.
        let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe(), gate = AdaptivePolicyGate()
        _ = selector.orderedCandidates(scopeKey: scope, candidateIDs: ids)
        for (index, milliseconds) in [1.0, 10.0, 100.0].enumerated() {
            selector.record(scopeKey: scope, candidateID: ids[index], milliseconds: milliseconds, success: true)
        }
        try expect(selector.orderedCandidates(scopeKey: scope, candidateIDs: ids) == ids,
                   "冷连接回归改变了候选顺序")
        let message = try query("rotation-warm-history-cold-phase.example.test", 1)
        let lock = NSLock(), worker = DispatchQueue(label: "app.hajimi.dns.cold-phase-self-test", qos: .userInitiated)
        var fallbackCalls = 0, hedgeReady = false, cancelledHedgeBeforeReady = false
        let started = ProcessInfo.processInfo.systemUptime
        let flow = DNSProxyFallbackQueryDatagram(queue: worker, absoluteDeadline: started + 8,
            permitted: gate.permits, knownMilliseconds: {
                ids.compactMap { selector.knownLatencyMilliseconds(scopeKey: scope, candidateID: $0) }
            }, encrypted: { queue, absolute, receive, failure in
                DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: selector, scopeKey: scope,
                    queue: queue, permitted: gate.permits, factory: { candidate, queue, receive, _ in
                        AdaptiveAcknowledgedMemoryTransport(send: { data in
                            probe.attempted(candidate)
                            guard candidate.id == ids[1], let answer = bootstrapAnswer(data) else { return }
                            queue.asyncAfter(deadline: .now() + 2.3) {
                                lock.lock(); hedgeReady = true; lock.unlock()
                                receive(answer)
                            }
                        }, cancel: {
                            lock.lock()
                            if candidate.id == ids[1] && !hedgeReady { cancelledHedgeBeforeReady = true }
                            lock.unlock(); probe.transportCancelled()
                        })
                    }, receive: receive, failure: failure, timeout: 8,
                    absoluteDeadline: absolute, protectProxyFallback: true)
            }, fallback: { _, absolute, _, failure in
                lock.lock(); fallbackCalls += 1; lock.unlock()
                return AdaptiveAcknowledgedMemoryTransport(send: { _ in
                    failure(absolute > ProcessInfo.processInfo.systemUptime
                        ? EncryptedDNSQueryFailure.network : DNSQueryTimeoutError())
                })
            }, receive: probe.received, failure: probe.failed)
        defer { flow.cancel() }
        flow.send(message); try awaitAdaptive(probe, query: message, waitTimeout: 4)
        let elapsed = ProcessInfo.processInfo.systemUptime - started
        let acknowledged = DispatchSemaphore(value: 0)
        flow.cancel { acknowledged.signal() }
        try expect(acknowledged.wait(timeout: .now() + 1) == .success, "冷连接回归未完成取消 ACK")
        lock.lock(); let fallbackCount = fallbackCalls, clipped = cancelledHedgeBeforeReady; lock.unlock()
        try expect(elapsed >= 2.3 && elapsed < 3 && !clipped && fallbackCount == 0
                   && probe.snapshot.attempts == approved.candidates.prefix(2).map { $0.upstream.target.host }
                   && probe.snapshot.answers.count == 1 && probe.concurrency.peak == 2
                   && probe.concurrency.active == 0 && probe.concurrency.cancelled == 2,
                   "快历史剪掉 2.3s 冷 hedge、触发不必要回退或突破并发/取消约束")
        // Client cancellation and permission revocation still reject an old
        // answer before it can revive history, deliver data or start fallback.
        for revoke in [false, true] {
            let stopped = AdaptiveProbe(), permission = AdaptivePolicyGate()
            let callbackLock = NSLock(); var late: (() -> Void)?
            let forbiddenFallback = DispatchSemaphore(value: 0)
            let pending = DNSProxyFallbackQueryDatagram(queue: worker,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 8,
                permitted: permission.permits, knownMilliseconds: { [1, 10, 100] }, encrypted: { queue, absolute, receive, failure in
                    DNSAdaptiveQueryDatagram(candidates: approved.candidates, selector: DNSAdaptiveUpstreamSelector(),
                        scopeKey: scope, queue: queue, permitted: permission.permits,
                        factory: { candidate, queue, receive, _ in
                            AdaptiveAcknowledgedMemoryTransport(send: { data in
                                callbackLock.lock()
                                late = { queue.async { receive(bootstrapAnswer(data)!) } }
                                callbackLock.unlock(); stopped.attempted(candidate)
                            }, cancel: stopped.transportCancelled)
                        }, receive: receive, failure: failure, absoluteDeadline: absolute, protectProxyFallback: true)
                }, fallback: { _, _, _, _ in
                    forbiddenFallback.signal(); return AdaptiveAcknowledgedMemoryTransport(send: { _ in })
                }, receive: stopped.received, failure: stopped.failed)
            defer { pending.cancel() }
            pending.send(message)
            try expect(stopped.started.wait(timeout: .now() + 1) == .success, "待撤销加密阶段未启动")
            if revoke { permission.revoke() }
            else {
                let cancelled = DispatchSemaphore(value: 0); pending.cancel { cancelled.signal() }
                try expect(cancelled.wait(timeout: .now() + 1) == .success, "客户端取消缺少 ACK")
            }
            callbackLock.lock(); let deliverLate = late; callbackLock.unlock(); deliverLate?()
            if revoke { try awaitAdaptive(stopped, query: message, expectFailure: true) }
            else { try expect(stopped.done.wait(timeout: .now() + 0.05) == .timedOut, "取消后仍交付结果") }
            try expect(stopped.snapshot.answers.isEmpty && forbiddenFallback.wait(timeout: .now()) == .timedOut,
                       "撤销后旧答案恢复或启动了未授权回退")
        }
        print("DNS warm-history cold-phase regression: memory-delay=2300ms, elapsed=\(Int(elapsed * 1000))ms, fallback=0, attempts=2, live-peak=2, cancel/policy fenced")
    }

    private static func adaptiveQueuedAbsoluteDeadlines() throws {
        let profile = adaptiveProfile(), source = router(profile), approved = try plan(source)
        let queue = DispatchQueue(label: "app.hajimi.dns.absolute-deadline-self-test")
        // The real coordinator must not even enter a queued/expired factory,
        // and the typed failure must be recorded once as a timeout.
        do {
            let message = try query("adaptive-expired-before-factory.example.test", 1)
            let probe = AdaptiveProbe(), construction = BootstrapProbe()
            let before = NetworkPerformanceDiagnostics.shared.snapshot().dnsFailureReasons[.timeout, default: 0]
            let flow = try source.makeOptimizedDNSUpstream(plan: approved, queue: queue, factory: { _, _, _ in
                construction.lock.lock(); construction.builds += 1; construction.lock.unlock()
                return BootstrapMemoryTransport { _ in }
            }, queryDeadline: ProcessInfo.processInfo.systemUptime - 0.01,
                receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: true)
            construction.lock.lock(); let builds = construction.builds; construction.lock.unlock()
            let after = NetworkPerformanceDiagnostics.shared.snapshot().dnsFailureReasons[.timeout, default: 0]
            try expect(builds == 0 && after == before + 1, "已过期的 queued factory 仍建连或误记通用失败")
        }
        // Setup work may consume the remaining budget after the entry guard.
        // Its returned transport is canceled without sending the DNS query.
        do {
            let message = try query("adaptive-expired-in-factory.example.test", 1)
            let probe = AdaptiveProbe(), construction = BootstrapProbe()
            let lock = NSLock(); var sends = 0, cancels = 0
            let flow = try source.makeOptimizedDNSUpstream(plan: approved, queue: queue, factory: { _, _, _ in
                construction.lock.lock(); construction.builds += 1; construction.lock.unlock()
                Thread.sleep(forTimeInterval: 0.25)
                return AdaptiveMemoryTransport(send: { _ in lock.lock(); sends += 1; lock.unlock() },
                    cancel: { lock.lock(); cancels += 1; lock.unlock() })
            }, queryDeadline: ProcessInfo.processInfo.systemUptime + 0.2,
                receive: probe.received, failure: probe.failed)
            defer { flow.cancel() }; flow.send(message)
            try awaitAdaptive(probe, query: message, expectFailure: true)
            lock.lock(); let sent = sends, closed = cancels; lock.unlock()
            construction.lock.lock(); let builds = construction.builds; construction.lock.unlock()
            try expect(builds == 1 && sent == 0 && closed == 1,
                       "factory 消耗完 absolute budget 后仍发送查询或未释放 transport")
        }
        var three = profile
        three.encryptedDNSServers.append("https://third.adaptive.selftest.invalid/dns-query#203.0.113.72")
        let decision = try plan(router(three)), ids = decision.candidates.map(\.id)
        for expired in [true, false] {
            let blocked = DispatchQueue(label: "app.hajimi.dns.blocked-deadline-self-test")
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            blocked.async { entered.signal(); _ = release.wait(timeout: .now() + 2) }
            try expect(entered.wait(timeout: .now() + 1) == .success, "absolute deadline fixture 未阻塞其队列")
            let selector = DNSAdaptiveUpstreamSelector(), probe = AdaptiveProbe()
            let message = try query(expired ? "adaptive-expired-on-send.example.test" : "adaptive-remaining-rotation.example.test", 1)
            let began = ProcessInfo.processInfo.systemUptime
            let deadline = began + (expired ? 0.05 : 0.9)
            let flow = DNSAdaptiveQueryDatagram(candidates: decision.candidates, selector: selector,
                scopeKey: decision.healthScopeKey, queue: blocked, permitted: { true },
                factory: { candidate, worker, receive, _ in
                    AdaptiveMemoryTransport(send: { data in
                        probe.attempted(candidate)
                        if candidate.id == ids[2], let reply = bootstrapAnswer(data) {
                            worker.asyncAfter(deadline: .now() + 0.01) { receive(reply) }
                        }
                    }, cancel: probe.transportCancelled)
                }, receive: probe.received, failure: probe.failed, timeout: 8, absoluteDeadline: deadline)
            defer { flow.cancel() }; flow.send(message)
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) { release.signal() }
            try awaitAdaptive(probe, query: message, expectFailure: expired)
            if expired {
                try expect(probe.snapshot.attempts.isEmpty && selector.usage.scopes == 0
                           && probe.snapshot.error is DNSQueryTimeoutError,
                           "send 队列延误后重新给了 8s 或仍拨号/写入健康状态")
            } else {
                try expect(probe.snapshot.attempts.count == 3 && probe.concurrency.peak == 2
                           && ProcessInfo.processInfo.systemUptime - began < 0.85,
                           "排队后 rotation 未按真实剩余预算运行或超过 parent absolute deadline")
            }
        }
    }

    private final class BootstrapProbe {
        let lock = NSLock(), done = DispatchSemaphore(value: 0)
        let started = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
        var names: [String] = [], payloads: [Data] = [], builds = 0
        var error: Error?
        func record(_ name: String) { lock.lock(); names.append(name); lock.unlock() }
        func fail(_ error: Error) { lock.lock(); self.error = error; lock.unlock(); done.signal() }
    }
    private final class BootstrapMemoryTransport: NativeRoutedDatagram {
        let onSend: (Data) -> Void
        init(_ onSend: @escaping (Data) -> Void) { self.onSend = onSend }
        func send(_ data: Data) { onSend(data) }
        func cancel() {}
    }
    private static func bootstrapAnswer(_ query: Data) -> Data? {
        guard let question = DNSMessageInspection.singleQuestion(in: query) else { return nil }
        var answer = Data(query.prefix(question.questionEnd))
        answer[2] = 0x81; answer[3] = 0x80
        for offset in 6...11 { answer[offset] = 0 }
        if question.type == 1 {
            answer[7] = 1
            answer.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 77])
        }
        return answer
    }

    private static func asynchronousBootstrap() throws {
        var profile = Profile()
        let node = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                               adapterType: "trojan", parameters: ["password": "test"])
        profile.proxies[node.name] = node
        profile.rules = [RoutingRule(kind: .final, policy: node.name, sourceLine: 1)]
        profile.dnsServers = ["203.0.113.60:5353"]
        profile.encryptedDNSServers = ["https://doh.bootstrap.selftest.invalid/dns-query"]
        let source = router(profile), decision = try plan(source, name: "private.user.example.test", type: 65)
        guard case .doh(let endpoint) = decision.upstream else { throw Failure(text: "引导测试端点不是 DoH") }
        let probe = BootstrapProbe(), queue = DispatchQueue(label: "app.hajimi.dns.bootstrap-routing-test")
        let wire: TraditionalDNSWireExchange = { _, query, queue, completion in
            guard let question = DNSMessageInspection.singleQuestion(in: query), let reply = bootstrapAnswer(query) else {
                queue.async { completion(.failure(Failure(text: "传统引导问题无效"))) }; return {}
            }
            probe.record(question.name)
            queue.async { completion(.success(reply)) }
            return {}
        }
        let resolver = try source.bootstrapResolver(for: decision, exchange: wire)
        try expect(try source.bootstrapResolver(for: decision, exchange: wire) === resolver,
                   "同用途/代次/接口的 DoH 引导解析器未复用")
        let original = try query("private.user.example.test", 65)
        let gateway = DoHBootstrapDatagram(endpoint: endpoint, resolver: resolver, queue: queue,
            permitted: { source.isCurrentDNSGenerationForInternal(decision.generation) }, makeEncrypted: { address in
                let resolved = try source.resolvedBootstrapPlan(decision, address: address)
                try expect(resolved.route == decision.route && resolved.upstream.identityHost == endpoint.host
                           && resolved.upstream.target.host == "203.0.113.77" && resolved.bootstrap == nil,
                           "引导改变 TLS 身份、所选代理或仍使用主机名拨号")
                probe.lock.lock(); probe.builds += 1; probe.lock.unlock()
                return BootstrapMemoryTransport { data in
                    probe.lock.lock(); probe.payloads.append(data); probe.lock.unlock(); probe.done.signal()
                }
            }, failure: probe.fail)
        gateway.send(original)
        guard probe.done.wait(timeout: .now() + 2) == .success else { throw Failure(text: "内存 DoH 引导未完成") }
        probe.lock.lock(); let error = probe.error, names = probe.names, payloads = probe.payloads; probe.lock.unlock()
        if let error { throw error }
        try expect(!names.isEmpty && names.allSatisfy { $0 == endpoint.host } && payloads == [original],
                   "普通应用 QNAME 泄入传统 DNS 或原查询未只交加密传输")
        gateway.cancel()

        let denied = DispatchSemaphore(value: 0)
        let id = resolver.resolveDoHHost("private.user.example.test", queue: queue) { result in
            if case .failure = result { denied.signal() }
        }
        try expect(id == nil && denied.wait(timeout: .now() + 2) == .success,
                   "引导解析器允许调用任意应用域名")
        probe.lock.lock(); let namesAfterDenied = probe.names; probe.lock.unlock()
        try expect(namesAfterDenied == names, "白名单拒绝仍产生传统 DNS 交换")

        // Hold a memory wire transaction so update must cancel the actual
        // cached resolver, not merely ignore a late application response.
        let pendingSource = router(profile), pendingPlan = try plan(pendingSource)
        let pending = BootstrapProbe()
        let heldWire: TraditionalDNSWireExchange = { _, query, _, _ in
            if let question = DNSMessageInspection.singleQuestion(in: query) { pending.record(question.name) }
            pending.started.signal(); return { pending.cancelled.signal() }
        }
        let old = try pendingSource.bootstrapResolver(for: pendingPlan, exchange: heldWire)
        let waiting = DoHBootstrapDatagram(endpoint: endpoint, resolver: old, queue: queue,
            permitted: { pendingSource.isCurrentDNSGenerationForInternal(pendingPlan.generation) },
            makeEncrypted: { _ in
                pending.lock.lock(); pending.builds += 1; pending.lock.unlock()
                return BootstrapMemoryTransport { _ in pending.done.signal() }
            }, failure: pending.fail)
        waiting.send(original)
        guard pending.started.wait(timeout: .now() + 2) == .success else { throw Failure(text: "待取消引导未启动") }
        pendingSource.update(profile: profile, mode: .rule, globalPolicy: node.name, groupSelections: [:])
        try expect(pending.cancelled.wait(timeout: .now() + 2) == .success
                   && pending.done.wait(timeout: .now() + 2) == .success,
                   "策略更新没有撤销旧引导请求")
        pending.lock.lock(); let builds = pending.builds; pending.lock.unlock()
        try expect(builds == 0, "旧引导完成后仍构建应用加密查询")
        let replacement = try pendingSource.bootstrapResolver(for: plan(pendingSource), exchange: heldWire)
        try expect(replacement !== old, "配置更新复用已失效引导解析器")
        waiting.cancel(); replacement.cancel(); resolver.cancel()

        let cancelled = BootstrapProbe()
        let cancelResolver = TraditionalDNSBootstrapResolver(servers: profile.traditionalDNSServers,
            allowedDoHHosts: [endpoint.host], timeout: 4, exchange: { _, _, _, _ in
                cancelled.started.signal(); return { cancelled.cancelled.signal() }
            })
        let cancelGateway = DoHBootstrapDatagram(endpoint: endpoint, resolver: cancelResolver, queue: queue,
            permitted: { true }, makeEncrypted: { _ in
                cancelled.lock.lock(); cancelled.builds += 1; cancelled.lock.unlock()
                return BootstrapMemoryTransport { _ in }
            }, failure: cancelled.fail)
        cancelGateway.send(original)
        guard cancelled.started.wait(timeout: .now() + 2) == .success else { throw Failure(text: "可取消引导未启动") }
        cancelGateway.cancel()
        try expect(cancelled.cancelled.wait(timeout: .now() + 2) == .success, "单 flow 取消未撤销自己的引导事务")
        cancelled.lock.lock(); let cancelBuilds = cancelled.builds; cancelled.lock.unlock()
        try expect(cancelBuilds == 0, "已取消引导仍送出普通 QNAME")
        cancelResolver.cancel()
    }

    private static func frame(_ query: Data) -> Data {
        var framed = Data([UInt8(query.count >> 8), UInt8(query.count & 0xff)])
        framed.append(query); return framed
    }
    private static func framing() throws {
        let first = try query("first.example.test", 1), second = try query("second.example.test", 65)
        let bytes = frame(first) + frame(second)
        var framer = DNSLengthFramer(), decoded: [Data] = []
        for byte in bytes { decoded += try framer.append(Data([byte])) }
        try expect(decoded == [first, second], "DNS TCP 单字节拆包/前缀未正确复原")
        var merged = DNSLengthFramer()
        try expect(try merged.append(bytes) == [first, second], "DNS TCP 合包未解析多个查询")
        for invalid in [Data([0, 0]), Data([0, 11]), Data(repeating: 0, count: 256 * 1_024 + 1)] {
            var bounded = DNSLengthFramer()
            do { _ = try bounded.append(invalid) }
            catch { continue }
            throw Failure(text: "DNS TCP 无效长度/超大输入未拒绝")
        }
        let maximum = Data(repeating: 0x41, count: 65_535)
        var maxFramer = DNSLengthFramer()
        try expect(try maxFramer.append(Data([0xff])).isEmpty, "DNS TCP 半前缀被当成整帧")
        try expect(try maxFramer.append(Data([0xff]) + maximum) == [maximum], "DNS TCP 最大帧长度边界错误")
    }

    private static func framedFakeIPRoundTrip() throws {
        var profile = Profile(); profile.fakeIPEnabled = true
        profile.proxies["Node"] = ProxyPolicy(name: "Node", kind: .native, host: "203.0.113.10", port: 443,
                                             adapterType: "trojan", parameters: ["password": "test"])
        profile.rules = [RoutingRule(kind: .domain("blocked.example.test"), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .final, policy: "Node", sourceLine: 2)]
        let router = self.router(profile), queue = DispatchQueue(label: "app.hajimi.dns.framed-selftest")
        var stream: NativeOutboundByteStream?
        router.connectTCP(host: "203.0.113.53", port: 53, queue: queue) { result in
            if case .success(let value) = result { stream = value }
        }
        guard let stream else { throw Failure(text: "DNS TCP gateway 未建立") }
        defer { stream.cancel() }
        let a = try query("fake.example.test", 1, id: 1), aaaa = try query("fake.example.test", 28, id: 2)
        let denied = try query("blocked.example.test", 16, id: 3)
        let all = frame(a) + frame(aaaa) + frame(denied)
        let writes = DispatchGroup(), lock = NSLock()
        var failure: Error?
        for chunk in [Data(all.prefix(1)), Data(all.dropFirst(1).prefix(7)), Data(all.dropFirst(8))] {
            writes.enter(); stream.send(chunk) { error in
                if let error { lock.lock(); failure = error; lock.unlock() }; writes.leave()
            }
        }
        guard writes.wait(timeout: .now() + 2) == .success else { throw Failure(text: "DNS TCP 发送未完成") }
        lock.lock(); let writeError = failure; lock.unlock()
        if let writeError { throw writeError }
        let done = DispatchSemaphore(value: 0)
        var responses: [Data] = [], decoder = DNSLengthFramer(), receivedBytes = 0
        func read() {
            stream.receive(maximum: 3) { data, complete, error in
                if let error { failure = error; done.signal(); return }
                if let data {
                    receivedBytes += data.count
                    do { responses += try decoder.append(data) }
                    catch { failure = error; done.signal(); return }
                }
                if responses.count == 3 { done.signal(); return }
                if complete || receivedBytes > 1_024 { failure = Failure(text: "DNS TCP 回包截断或超限"); done.signal(); return }
                read()
            }
        }
        read()
        guard done.wait(timeout: .now() + 2) == .success else { throw Failure(text: "DNS TCP fake-IP 回包超时") }
        if let failure { throw failure }
        // DNS-over-TCP permits pipelined answers out of order. Refusals may
        // finish before queued local synthesis; correlate every payload with
        // its question rather than assuming a callback scheduling order.
        guard let aReply = responses.first(where: { DNSMessageInspection.responseMatchesQuery($0, query: a) }),
              let aaaaReply = responses.first(where: { DNSMessageInspection.responseMatchesQuery($0, query: aaaa) }),
              let deniedReply = responses.first(where: { DNSMessageInspection.responseMatchesQuery($0, query: denied) }) else {
            throw Failure(text: "DNS TCP 回包丢失或混淆查询 ID/身份")
        }
        let records = DNSMessageInspection.addressAnswers(in: aReply)
        try expect(records.count == 1 && FakeIPAllocator.isFake(records[0].address), "TCP A 查询没有 fake-IP")
        try expect(aaaaReply[aaaaReply.startIndex + 7] == 0 && aaaaReply[aaaaReply.startIndex + 3] & 0x0f == 0,
                   "TCP AAAA 查询未保持空 NOERROR")
        try expect(deniedReply[deniedReply.startIndex + 3] & 0x0f == 5, "TCP 非 A 查询绕过域名 REJECT")
    }
}


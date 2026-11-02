import Foundation
import HajimiDNS

/// Production policy/coordinator/resolver pressure checks over memory-only
/// byte streams. The caller's file-local fixture factory is the only route
/// to the private injection point; this type exposes no production override,
/// listener, TLS trust change, system resolver or plaintext fallback.
enum DNSTransportScopeSelfTest {
    struct ScopeSnapshot {
        let queryScope: String
        /// The complete key used to own one current encrypted endpoint pool.
        let transportScope: String
        let generation: UInt64
    }

    typealias MakeRouter = (Profile, @escaping MetadataAwareEncryptedDNSStreamDialer) -> NativePacketRouter
    typealias Inspect = (NativePacketRouter, Data, RequestTarget, String?) throws -> ScopeSnapshot

    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS transport scope 自检失败：\(text)" }
    }

    private static func require(_ condition: @autoclosure () throws -> Bool, _ text: String) throws {
        guard try condition() else { throw Failure(text: text) }
    }

    private enum Kind: String, CaseIterable {
        case doh = "DoH", dot = "DoT"
        var port: UInt16 { self == .doh ? 5443 : 5853 }
        func endpoint(identity: String = "scope.fixture.invalid", address: String = "203.0.113.70",
                      port: UInt16? = nil, path: String = "/dns-query") -> String {
            let servicePort = port ?? self.port
            return self == .doh ? "https://\(identity):\(servicePort)\(path)#\(address)"
                : "tls://\(identity):\(servicePort)#\(address)"
        }
        func question(in wire: Data) -> Data? {
            if self == .dot {
                guard wire.count >= 14 else { return nil }
                let size = Int(wire[wire.startIndex]) << 8 | Int(wire[wire.startIndex + 1])
                guard size == wire.count - 2 else { return nil }
                return Data(wire.dropFirst(2))
            }
            guard let separator = wire.range(of: Data("\r\n\r\n".utf8)),
                  wire.starts(with: Data("POST /dns-query HTTP/1.1\r\n".utf8)) else { return nil }
            return Data(wire[separator.upperBound...])
        }
        func frame(_ response: Data) -> Data {
            if self == .dot {
                return Data([UInt8(response.count >> 8), UInt8(response.count & 255)]) + response
            }
            return Data(("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                + "Connection: keep-alive\r\nContent-Length: \(response.count)\r\n\r\n").utf8) + response
        }
    }

    private static func profile(_ kind: Kind) -> Profile {
        var profile = Profile()
        profile.fakeIPEnabled = false
        profile.dnsLeakProtectionEnabled = true
        profile.dnsProxyFallbackEnabled = false
        profile.dnsProxyFallbackServers = []
        profile.dnsServers = []
        profile.encryptedDNSServers = [kind.endpoint()]
        // Make source-port identity observable without rejecting test traffic.
        profile.rules = [RoutingRule(kind: .sourcePort(65535...65535), policy: "REJECT", sourceLine: 1),
                         RoutingRule(kind: .domain("blocked.scope.fixture.test"), policy: "REJECT", sourceLine: 2)]
        for index in 0..<8 {
            let name = "ScopeNode\(index)"
            profile.proxies[name] = ProxyPolicy(name: name, kind: .http,
                host: "192.0.2.\(100 + index)", port: UInt16(8100 + index))
            profile.rules.append(RoutingRule(kind: .domainSuffix("path-\(index).scope.fixture.test"),
                policy: name, sourceLine: index + 3))
        }
        profile.rules.append(RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 20))
        return profile
    }

    private static func target(_ index: Int) -> RequestTarget {
        RequestTarget(host: index % 2 == 0 ? "203.0.113.53" : "203.0.113.54", port: 53,
            protocolName: "UDP", sourceHost: "192.0.2.\(1 + index % 200)",
            sourcePort: UInt16(43000 + index), inboundPort: UInt16(7263 + index % 2))
    }

    private static func query(_ name: String, id: UInt16) throws -> Data {
        guard let result = DNSMessageInspection.query(for: name, type: 1, id: id) else {
            throw Failure(text: "无法编码固定 fixture 问题")
        }
        return result
    }

    private final class Replies {
        private struct Expected {
            let query: Data, code: UInt8, address: String?
        }
        private let lock = NSLock()
        private let done = DispatchGroup()
        private var expected: [UInt16: Expected] = [:]
        private var answers: [UInt16: Data] = [:]
        private var callbacks: [UInt16: Int] = [:]
        private var failure: String?

        private func identifier(_ data: Data) -> UInt16 {
            UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1])
        }

        func register(_ query: Data, code: UInt8 = 0, address: String? = "203.0.113.80") throws {
            let id = identifier(query)
            lock.lock()
            guard expected[id] == nil else { lock.unlock(); throw Failure(text: "fixture 重复使用客户端 ID") }
            expected[id] = Expected(query: query, code: code, address: address)
            done.enter(); lock.unlock()
        }

        func received(_ response: Data) {
            lock.lock()
            guard response.count >= 12 else {
                failure = failure ?? "生产路径回包短于 DNS 头"; lock.unlock(); return
            }
            let id = identifier(response)
            guard let item = expected[id] else {
                failure = failure ?? "生产路径把回包交给了其他客户端 ID"; lock.unlock(); return
            }
            callbacks[id, default: 0] += 1
            let first = callbacks[id] == 1
            if !first { failure = failure ?? "同一 DNS 查询完成超过一次" }
            if !DNSMessageInspection.responseMatchesQuery(response, query: item.query) {
                failure = failure ?? "物理连接复用破坏了原始问题或事务 ID"
            } else if response[response.startIndex + 3] & 15 != item.code {
                failure = failure ?? "有查询返回 SERVFAIL/错误码或绕过 REJECT（期望 \(item.code)）"
            } else if let address = item.address, item.code == 0,
                      DNSMessageInspection.addressAnswers(in: response).map(\.address) != [address] {
                failure = failure ?? "查询收到另一代/另一来源的缓存地址"
            }
            answers[id] = response
            lock.unlock()
            if first { done.leave() }
        }

        func failed(_ id: UInt16, _ error: Error) {
            lock.lock()
            guard expected[id] != nil else { lock.unlock(); return }
            callbacks[id, default: 0] += 1
            let first = callbacks[id] == 1
            failure = failure ?? "DNS flow 失败：\(String(error.localizedDescription.prefix(160)))"
            lock.unlock()
            if first { done.leave() }
        }

        func wait(_ label: String) throws {
            guard done.wait(timeout: .now() + 10) == .success else {
                throw Failure(text: "\(label) 超过原始 8 秒查询预算/回包未交付")
            }
            try validate(label)
        }

        func validate(_ label: String) throws {
            lock.lock(); let error = failure
            let complete = answers.count == expected.count && callbacks.values.allSatisfy { $0 == 1 }
            lock.unlock()
            if let error { throw Failure(text: "\(label)：\(error)") }
            try DNSTransportScopeSelfTest.require(complete, "\(label) 丢失或重复回包")
        }
    }

    /// The read broker deliberately permits a held native read to complete
    /// once *after* cancel, matching a real already-admitted callback race.
    /// Normal reusable streams never emit unsolicited bytes or overlap reads.
    private final class Peer: NativeOutboundByteStream {
        typealias Writer = (Peer, Data, UUID, @escaping (Error?) -> Void) -> Void
        private struct Reader {
            let maximum: Int
            let completion: (Data?, Bool, Error?) -> Void
        }
        let closed = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private let kind: Kind
        private let keepLateRead: Bool
        private let retired: (UUID) -> Void
        private let readerInstalled: () -> Void
        private var writer: Writer?
        private var reader: Reader?, lateReader: Reader?
        private var buffered: [Data] = []
        private var active: UUID?
        private var stopped = false, writes = 0

        init(kind: Kind, keepLateRead: Bool, writer: @escaping Writer,
             retired: @escaping (UUID) -> Void, readerInstalled: @escaping () -> Void) {
            self.kind = kind; self.keepLateRead = keepLateRead; self.writer = writer
            self.retired = retired; self.readerInstalled = readerInstalled
        }

        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            guard let query = kind.question(in: data),
                  let question = DNSMessageInspection.singleQuestion(in: query),
                  question.name.hasSuffix(".scope.fixture.test"), question.type == 1 else {
                completion(Failure(text: "memory stream 收到 fixture 之外的请求")); return
            }
            lock.lock()
            guard !stopped, active == nil, let writer else {
                lock.unlock(); completion(Failure(text: "memory stream 关闭或两个事务重叠")); return
            }
            let token = UUID(); active = token; writes += 1; lock.unlock()
            writer(self, query, token, completion)
        }

        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped, maximum > 0, reader == nil else {
                lock.unlock(); completion(nil, true, Failure(text: "memory stream 重叠/关闭的 read")); return
            }
            reader = Reader(maximum: maximum, completion: completion)
            let notify = keepLateRead
            lock.unlock()
            if notify { readerInstalled() }
            drain()
        }

        func reply(_ data: Data, token: UUID) {
            lock.lock()
            guard !stopped, active == token else { lock.unlock(); return }
            active = nil; buffered.append(data); lock.unlock()
            retired(token); drain()
        }

        private func drain() {
            lock.lock()
            guard !stopped, let reader, !buffered.isEmpty else { lock.unlock(); return }
            self.reader = nil
            let data = buffered.removeFirst()
            let delivered = Data(data.prefix(reader.maximum))
            if data.count > reader.maximum { buffered.insert(Data(data.dropFirst(reader.maximum)), at: 0) }
            lock.unlock(); reader.completion(delivered, false, nil)
        }

        func cancel() {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            stopped = true; writer = nil; buffered.removeAll()
            let token = active; active = nil
            let pending = reader; reader = nil
            if keepLateRead { lateReader = pending }
            lock.unlock()
            if let token { retired(token) }
            if !keepLateRead { pending?.completion(nil, true, Failure(text: "cancelled memory stream")) }
            closed.signal()
        }

        func deliverLate(_ data: Data) -> Bool {
            lock.lock(); let saved = lateReader; lateReader = nil; lock.unlock()
            guard let saved, data.count <= saved.maximum else { return false }
            saved.completion(data, false, nil); return true
        }

        var sendCount: Int { lock.lock(); defer { lock.unlock() }; return writes }
    }

    private final class Harness {
        private struct HeldWire {
            let peer: Peer, token: UUID, response: Data, queue: DispatchQueue
        }
        private struct HeldDial {
            let token: UUID
            let queue: DispatchQueue
            let completion: (Result<any NativeOutboundByteStream, Error>) -> Void
        }
        struct Statistics {
            let dials: Int, exchanges: Int, peak: Int, active: Int, invalid: Int
            let failedPrimaryDials: Int, pendingNativeDials: Int, peakNativeDials: Int
        }
        let wireArrived = DispatchSemaphore(value: 0)
        let readInstalled = DispatchSemaphore(value: 0)
        let dialArrived = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private let kind: Kind
        private let failingPrimary: Bool
        private var streams: [Peer] = []
        private var heldWires: [HeldWire] = [], heldDials: [HeldDial] = []
        private var active = Set<UUID>()
        private var nativeDials = Set<UUID>()
        private var dialCount = 0, exchangeCount = 0, peak = 0, invalid = 0
        private var failedPrimaryDials = 0, peakNativeDials = 0
        private var holdWire = false, holdDial = false
        private var responseAddress = "203.0.113.80"
        private var responseDelay: TimeInterval = 0.035
        private var nextReplyUptime: TimeInterval = 0

        init(_ kind: Kind, failingPrimary: Bool = false) {
            self.kind = kind; self.failingPrimary = failingPrimary
        }

        func holdNextWire() { lock.lock(); holdWire = true; lock.unlock() }
        func holdNextDial() { lock.lock(); holdDial = true; lock.unlock() }
        func makeAutomatic(address: String = "203.0.113.80", delay: TimeInterval = 0.035) {
            lock.lock(); holdWire = false; holdDial = false
            responseAddress = address; responseDelay = delay; lock.unlock()
        }

        var dialer: MetadataAwareEncryptedDNSStreamDialer {
            { [self] host, port, name, worker, _, note, done in
                let primary = host == "203.0.113.70" && name == "scope.fixture.invalid"
                let backup = failingPrimary && host == "203.0.113.71" && name == "backup-scope.fixture.invalid"
                guard port == kind.port, primary || backup else {
                    let error = Failure(text: "fixture dial 逃逸至未批准的 IP/端口/TLS 身份")
                    lock.lock(); invalid += 1; lock.unlock(); note(error); done(.failure(error)); return nil
                }
                let nativeToken = UUID()
                lock.lock(); dialCount += 1; nativeDials.insert(nativeToken)
                peakNativeDials = max(peakNativeDials, nativeDials.count)
                let fails = failingPrimary && primary
                if fails { failedPrimaryDials += 1 }
                let held = holdDial
                if held { heldDials.append(HeldDial(token: nativeToken, queue: worker, completion: done)) }
                lock.unlock(); dialArrived.signal()
                if !held, fails {
                    // A failed channel consumes real native admission for its
                    // full delay. The same approved backup must carry queued
                    // clients without 256 new cold primary handshakes.
                    worker.asyncAfter(deadline: .now() + 0.25) {
                        self.completeNativeDial(nativeToken)
                        note(EncryptedDNSQueryFailure.network)
                        done(.failure(EncryptedDNSQueryFailure.network))
                    }
                } else if !held {
                    let peer = newPeer()
                    worker.asyncAfter(deadline: .now() + 0.002) {
                        self.completeNativeDial(nativeToken); done(.success(peer))
                    }
                }
                // A deliberately uncancellable native dial retains its real
                // reservation until releaseDials() delivers the callback.
                return nil
            }
        }

        private func newPeer() -> Peer {
            lock.lock(); let late = holdWire; lock.unlock()
            let peer = Peer(kind: kind, keepLateRead: late, writer: { [weak self] peer, query, token, ack in
                guard let self else { ack(Failure(text: "fixture 已释放")); return }
                self.sent(peer, query: query, token: token, ack: ack)
            }, retired: { [weak self] token in self?.retire(token) }, readerInstalled: { [weak self] in
                self?.readInstalled.signal()
            })
            lock.lock(); streams.append(peer); lock.unlock(); return peer
        }

        private func sent(_ peer: Peer, query: Data, token: UUID, ack: @escaping (Error?) -> Void) {
            lock.lock()
            exchangeCount += 1
            active.insert(token); peak = max(peak, active.count)
            let address = responseAddress, held = holdWire, delay = responseDelay
            let now = ProcessInfo.processInfo.systemUptime
            let replyAt = max(now + delay, nextReplyUptime + 0.003)
            if !held { nextReplyUptime = replyAt }
            lock.unlock()
            guard let question = FakeIPResponder.question(in: query),
                  let answer = FakeIPResponder.reply(to: query, question: question, address: address, ttl: 120) else {
                lock.lock(); invalid += 1; lock.unlock(); retire(token)
                ack(Failure(text: "无法编码 memory 上游答复")); return
            }
            let response = kind.frame(answer)
            // Reply timers use their own queue. A production request/pool
            // queue must remain available to process admission and cancel.
            let delivery = DispatchQueue.global(qos: .userInitiated)
            if held {
                lock.lock(); heldWires.append(HeldWire(peer: peer, token: token, response: response, queue: delivery))
                lock.unlock()
            }
            ack(nil); wireArrived.signal()
            if !held {
                // Stagger otherwise identical in-memory completion stamps;
                // a synchronized fixture burst is not a real idle-cap test.
                delivery.asyncAfter(deadline: .now() + max(0, replyAt - now)) { peer.reply(response, token: token) }
            }
        }

        private func retire(_ token: UUID) {
            lock.lock(); active.remove(token); lock.unlock()
        }

        private func completeNativeDial(_ token: UUID) {
            lock.lock(); nativeDials.remove(token); lock.unlock()
        }

        var statistics: Statistics {
            lock.lock(); defer { lock.unlock() }
            return Statistics(dials: dialCount, exchanges: exchangeCount, peak: peak,
                active: active.count, invalid: invalid, failedPrimaryDials: failedPrimaryDials,
                pendingNativeDials: nativeDials.count, peakNativeDials: peakNativeDials)
        }

        var lastPeer: Peer? { lock.lock(); defer { lock.unlock() }; return streams.last }

        func releaseWiresLate() throws {
            lock.lock(); let held = heldWires; heldWires.removeAll(); lock.unlock()
            try DNSTransportScopeSelfTest.require(!held.isEmpty, "flush fixture 没有保存旧 native read")
            for wire in held {
                try DNSTransportScopeSelfTest.require(wire.peer.closed.wait(timeout: .now() + 2) == .success,
                            "flush 未关闭旧 encrypted stream")
                let delivered = DispatchSemaphore(value: 0), resultLock = NSLock()
                var accepted = false
                wire.queue.async {
                    let value = wire.peer.deliverLate(wire.response)
                    resultLock.lock(); accepted = value; resultLock.unlock(); delivered.signal()
                }
                try DNSTransportScopeSelfTest.require(delivered.wait(timeout: .now() + 2) == .success, "旧 native read 没有完成")
                resultLock.lock(); let value = accepted; resultLock.unlock()
                try DNSTransportScopeSelfTest.require(value, "flush fixture 没有实际交付取消后的旧 read")
            }
        }

        func releaseDials() -> [Peer] {
            lock.lock(); let held = heldDials; heldDials.removeAll(); lock.unlock()
            return held.map { dial in
                let peer = newPeer()
                dial.queue.async { self.completeNativeDial(dial.token); dial.completion(.success(peer)) }
                return peer
            }
        }
    }

    private final class Workload {
        let router: NativePacketRouter
        let replies = Replies()
        let queue = DispatchQueue(label: "app.hajimi.dns.transport-scope-self-test", qos: .userInitiated)
        private var flows: [any NativeRoutedDatagram] = []

        init(_ router: NativePacketRouter) { self.router = router }

        func send(_ message: Data, original: RequestTarget, code: UInt8 = 0,
                  address: String? = "203.0.113.80") throws {
            let id = UInt16(message[message.startIndex]) << 8 | UInt16(message[message.startIndex + 1])
            let flow = try router.makeUDPFlow(host: original.host, port: original.port, queue: queue,
                sourceHost: original.sourceHost, sourcePort: original.sourcePort, inboundPort: original.inboundPort,
                receive: { [replies] in replies.received($0) },
                failure: { [replies] in replies.failed(id, $0) })
            try replies.register(message, code: code, address: address)
            flows.append(flow); flow.send(message)
        }

        func cleanup() {
            flows.forEach { $0.cancel() }; flows.removeAll(); router.flushDNS()
        }

        deinit { cleanup() }
    }

    static func run(makeRouter: MakeRouter, inspect: Inspect) throws {
        for kind in Kind.allCases {
            try scopeIsolation(kind, makeRouter: makeRouter, inspect: inspect)
            try sourceBurstAndReuse(kind, makeRouter: makeRouter, inspect: inspect)
            try globalPhysicalAdmission(kind, makeRouter: makeRouter, inspect: inspect)
            try saturatedFailureSwitch(kind, makeRouter: makeRouter, inspect: inspect)
            try flushLateCallbacks(kind, makeRouter: makeRouter, inspect: inspect)
        }
        print("DNS transport-scope pressure passed: DoH/DoT, 96 isolated source scopes with same-scope merge, "
            + "256-query healthy/failing-provider bursts, 8 physical proxy paths, bounded 16 active, "
            + ">64-scope reuse, REJECT, flush/late native callbacks")
    }

    private static func scopeIsolation(_ kind: Kind, makeRouter: MakeRouter, inspect: Inspect) throws {
        let base = profile(kind), harness = Harness(kind), router = makeRouter(base, harness.dialer)
        defer { router.flushDNS() }
        let original = target(0), message = try query("isolation.scope.fixture.test", id: 0x9100)
        let first = try inspect(router, message, original, nil)
        for change in 0..<5 {
            var other = original
            switch change {
            case 0: other.host = "203.0.113.54"
            case 1: other.sourceHost = "192.0.2.2"
            case 2: other.sourcePort = 44001
            case 3: other.inboundPort = 7264
            default: other.protocolName = "TCP"
            }
            let value = try inspect(router, message, other, nil)
            try require(value.queryScope != first.queryScope && value.transportScope == first.transportScope,
                        "\(kind.rawValue)：来源元数据合并了缓存，或把同物理路径拆成新 pool")
        }
        let routedA = try inspect(router, query("one.path-0.scope.fixture.test", id: 0x9101), original, nil)
        let routedB = try inspect(router, query("one.path-1.scope.fixture.test", id: 0x9102), original, nil)
        try require(Set([first.transportScope, routedA.transportScope, routedB.transportScope]).count == 3,
                    "\(kind.rawValue)：transport pool 跨 DIRECT/不同 resolved node 共享")
        let otherInterface = try inspect(router, message, original, "en-scope-fixture")
        try require(otherInterface.transportScope != first.transportScope,
                    "\(kind.rawValue)：transport pool 跨物理接口共享")

        var endpoints = [kind.endpoint(address: "203.0.113.71"),
                         kind.endpoint(identity: "other-scope.fixture.invalid"),
                         kind.endpoint(port: kind.port + 1)]
        if kind == .doh { endpoints.append(kind.endpoint(path: "/other-dns-query")) }
        endpoints.append((kind == .doh ? Kind.dot : Kind.doh).endpoint())
        for endpoint in endpoints {
            var changed = base; changed.encryptedDNSServers = [endpoint]
            let isolated = makeRouter(changed, harness.dialer)
            let value = try inspect(isolated, message, original, nil)
            try require(value.transportScope != first.transportScope,
                        "\(kind.rawValue)：不同 IP/端口/TLS 身份/协议/路径混用 transport pool")
            isolated.flushDNS()
        }
        var expanded = base
        expanded.encryptedDNSServers.append(kind.endpoint(address: "203.0.113.71"))
        let expandedRouter = makeRouter(expanded, harness.dialer)
        let expandedScope = try inspect(expandedRouter, message, original, nil)
        try require(expandedScope.queryScope != first.queryScope
                    && expandedScope.transportScope == first.transportScope,
                    "\(kind.rawValue)：批准集合改变放宽了 answer scope 或拆碎首个同路径 pool")
        expandedRouter.flushDNS()
        router.flushDNS()
        let next = try inspect(router, message, original, nil)
        try require(next.generation != first.generation && next.queryScope != first.queryScope
                    && next.transportScope != first.transportScope,
                    "\(kind.rawValue)：flush 后 answer/transport scope 沿用了旧代次")
        try require(harness.statistics.dials == 0, "纯 scope/REJECT 检查意外创建了 native dial")
    }

    private static func sourceBurstAndReuse(_ kind: Kind, makeRouter: MakeRouter, inspect: Inspect) throws {
        let harness = Harness(kind), router = makeRouter(profile(kind), harness.dialer)
        let work = Workload(router); defer { work.cleanup() }
        var queryScopes = Set<String>(), transportScopes = Set<String>()
        for index in 0..<96 {
            let original = target(index)
            let first = try query("same-name.scope.fixture.test", id: UInt16(0x9200 + index * 2))
            let second = try query("same-name.scope.fixture.test", id: UInt16(0x9201 + index * 2))
            let scope = try inspect(router, first, original, nil)
            queryScopes.insert(scope.queryScope); transportScopes.insert(scope.transportScope)
            try work.send(first, original: original)
            try work.send(second, original: original)
        }
        try work.replies.wait("\(kind.rawValue) 96 来源/192 客户端")
        var before = harness.statistics
        try require(queryScopes.count == 96 && transportScopes.count == 1,
                    "\(kind.rawValue)：96 来源没有保持独立缓存/单一实际 transport")
        try require(before.exchanges == 96 && before.peak <= 16 && before.invalid == 0,
                    "\(kind.rawValue)：来源间错误合并、同来源未单飞或连接突破 16")
        try require(before.dials <= 32, "\(kind.rawValue)：96 来源仍各自创建冷 transport")

        try work.send(query("same-name.scope.fixture.test", id: 0x9300), original: target(0))
        try work.replies.wait("\(kind.rawValue) 同来源缓存")
        try require(harness.statistics.exchanges == before.exchanges,
                    "\(kind.rawValue)：共享 transport 后同来源缓存失效")
        try work.send(query("same-name.scope.fixture.test", id: 0x9301), original: target(300))
        try work.replies.wait("\(kind.rawValue) 新来源缓存隔离")
        try require(harness.statistics.exchanges == before.exchanges + 1,
                    "\(kind.rawValue)：新来源继承了其他来源 answer cache")

        before = harness.statistics
        for index in 0..<256 {
            try work.send(query("burst-\(index).scope.fixture.test", id: UInt16(0x9400 + index)),
                          original: target(400 + index))
        }
        try work.replies.wait("\(kind.rawValue) 256 unique 查询 burst")
        let burst = harness.statistics
        try require(burst.exchanges == before.exchanges + 256 && burst.active == 0
                    && burst.peak <= 16 && burst.invalid == 0,
                    "\(kind.rawValue)：256 查询容量拒绝/丢失回包或无全局背压")
        try require(burst.dials <= 64, "\(kind.rawValue)：256 来源仍放大为数百次冷 dial")

        // This crosses the old 64-owner dictionary reset repeatedly, using
        // never-cached names and new original/source tuples every time.
        let warmDials = burst.dials
        harness.makeAutomatic(delay: 0.001)
        for index in 0..<80 {
            try work.send(query("sequential-\(index).scope.fixture.test", id: UInt16(0x9500 + index)),
                          original: target(800 + index))
            try work.replies.wait("\(kind.rawValue) >64 来源连续复用")
        }
        try require(harness.statistics.dials == warmDials
                    && harness.statistics.exchanges == burst.exchanges + 80,
                    "\(kind.rawValue)：跨 64 来源触发 pool removeAll/连接不能复用")

        let accepted = harness.statistics
        try work.send(query("blocked.scope.fixture.test", id: 0x9600), original: target(0), code: 5, address: nil)
        try work.replies.wait("\(kind.rawValue) QNAME REJECT")
        var denied = target(0); denied.sourcePort = 65535
        do {
            let forbidden = try router.makeUDPFlow(host: denied.host, port: denied.port, queue: work.queue,
                sourceHost: denied.sourceHost, sourcePort: denied.sourcePort, inboundPort: denied.inboundPort,
                receive: { _ in }, failure: { _ in })
            forbidden.cancel()
            throw Failure(text: "\(kind.rawValue)：source-port REJECT 被 transport reuse 绕过")
        } catch let error as Failure { throw error }
        catch {
            try require(error.localizedDescription.contains("拒绝"),
                        "\(kind.rawValue)：source REJECT fixture 遇到其他异常，不能证明拒绝生效")
        }
        try require(harness.statistics.dials == accepted.dials
                    && harness.statistics.exchanges == accepted.exchanges,
                    "\(kind.rawValue)：REJECT 创建/借用了 encrypted transport")
        print("DNS \(kind.rawValue) many-source production flow passed: 96 strict scopes/192 replies, "
            + "256 unique burst, 80 sequential scopes, dials=\(harness.statistics.dials), peak=\(harness.statistics.peak)")
    }

    private static func globalPhysicalAdmission(_ kind: Kind, makeRouter: MakeRouter, inspect: Inspect) throws {
        let harness = Harness(kind), router = makeRouter(profile(kind), harness.dialer)
        let work = Workload(router); defer { work.cleanup() }
        var transportScopes = Set<String>()
        for index in 0..<256 {
            let original = target(index)
            let message = try query("multiple-\(index).path-\(index % 8).scope.fixture.test", id: UInt16(0x9700 + index))
            transportScopes.insert(try inspect(router, message, original, nil).transportScope)
            try work.send(message, original: original)
        }
        try work.replies.wait("\(kind.rawValue) 8 路径全局 DNS 背压")
        let result = harness.statistics
        try require(transportScopes.count == 8 && result.exchanges == 256 && result.active == 0
                    && result.peak <= 16 && result.invalid == 0,
                    "\(kind.rawValue)：每 resolver 的 16 并发跨 8 路径相乘/队列容量拒绝")
        print("DNS \(kind.rawValue) global production admission passed: 256 replies / 8 paths / peak \(result.peak)")
    }

    private static func saturatedFailureSwitch(_ kind: Kind, makeRouter: MakeRouter, inspect: Inspect) throws {
        var configured = profile(kind)
        configured.encryptedDNSServers.append(kind.endpoint(identity: "backup-scope.fixture.invalid",
                                                            address: "203.0.113.71"))
        let harness = Harness(kind, failingPrimary: true), router = makeRouter(configured, harness.dialer)
        let work = Workload(router); defer { work.cleanup() }
        var queryScopes = Set<String>(), transportScopes = Set<String>()
        for index in 0..<256 {
            let original = target(index)
            let message = try query("fault-burst-\(index).scope.fixture.test", id: UInt16(0x9800 + index))
            let snapshot = try inspect(router, message, original, nil)
            queryScopes.insert(snapshot.queryScope); transportScopes.insert(snapshot.transportScope)
            try work.send(message, original: original)
        }
        try work.replies.wait("\(kind.rawValue) 256 来源/首选 TLS channel 失败")
        let observed = harness.statistics
        try require(queryScopes.count == 256 && transportScopes.count == 1
                    && observed.exchanges == 256 && observed.active == 0 && observed.invalid == 0,
                    "\(kind.rawValue)：慢坏上游使高并发真实策略路径 SERVFAIL 或丢失客户端")
        try require(observed.failedPrimaryDials > 0 && observed.failedPrimaryDials <= 32
                    && observed.dials <= 96 && observed.peak <= 16 && observed.peakNativeDials <= 32
                    && observed.pendingNativeDials == 0,
                    "\(kind.rawValue)：失败路径的准入/健康状态仍按来源相乘或泄漏 native reservation")
        let previous = harness.statistics
        harness.makeAutomatic(delay: 0.001)
        for index in 0..<16 {
            try work.send(query("fault-warm-\(index).scope.fixture.test", id: UInt16(0x9a00 + index)),
                          original: target(1000 + index))
            try work.replies.wait("\(kind.rawValue) 故障切换后新来源 warm path")
        }
        let warm = harness.statistics
        try require(warm.exchanges == previous.exchanges + 16 && warm.dials == previous.dials
                    && warm.failedPrimaryDials == previous.failedPrimaryDials,
                    "\(kind.rawValue)：新来源丢失健康选优/复用，重新尝试已坏首选")
        print("DNS \(kind.rawValue) failing-provider production burst passed: 256 replies, "
            + "failed primary dials=\(warm.failedPrimaryDials), total dials=\(warm.dials), native peak=\(warm.peakNativeDials)")
    }

    private static func flushLateCallbacks(_ kind: Kind, makeRouter: MakeRouter, inspect: Inspect) throws {
        // A completed read that was already admitted by a native stream must
        // not repopulate a fresh epoch or be delivered twice after flush.
        do {
            let harness = Harness(kind); harness.holdNextWire()
            let router = makeRouter(profile(kind), harness.dialer), original = target(0)
            let work = Workload(router); defer { work.cleanup() }
            let old = try query("flush-read.scope.fixture.test", id: 0x9900)
            let first = try inspect(router, old, original, nil)
            try work.send(old, original: original, code: 2, address: nil)
            try require(harness.wireArrived.wait(timeout: .now() + 2) == .success
                        && harness.readInstalled.wait(timeout: .now() + 2) == .success,
                        "\(kind.rawValue)：无法挂起已发送的旧 native read")
            router.flushDNS()
            try work.replies.wait("\(kind.rawValue) flush 终止旧 read")
            harness.makeAutomatic(address: "203.0.113.81")
            try harness.releaseWiresLate()
            let fresh = try query("flush-read.scope.fixture.test", id: 0x9901)
            let second = try inspect(router, fresh, original, nil)
            try require(second.generation != first.generation && second.transportScope != first.transportScope,
                        "\(kind.rawValue)：flush 未替换 transport epoch")
            try work.send(fresh, original: original, address: "203.0.113.81")
            try work.replies.wait("\(kind.rawValue) late read 不能回填新 cache")
            try require(harness.statistics.exchanges == 2 && harness.statistics.dials == 2,
                        "\(kind.rawValue)：取消后的旧答复被 cache/reuse 接受")
            try work.send(query("flush-read.scope.fixture.test", id: 0x9902), original: original,
                          address: "203.0.113.81")
            try work.replies.wait("\(kind.rawValue) 新 epoch cache")
            try require(harness.statistics.exchanges == 2, "\(kind.rawValue)：新 epoch 缓存没有正常工作")
        }
        // Logical cancel is not physical dial completion. The old callback
        // arrives only after a different epoch has completed its own query.
        do {
            let harness = Harness(kind); harness.holdNextDial()
            let router = makeRouter(profile(kind), harness.dialer), original = target(0)
            let work = Workload(router); defer { work.cleanup() }
            try work.send(query("flush-dial.scope.fixture.test", id: 0x9910), original: original, code: 2, address: nil)
            try require(harness.dialArrived.wait(timeout: .now() + 2) == .success,
                        "\(kind.rawValue)：无法挂起旧 native dial")
            router.flushDNS()
            try work.replies.wait("\(kind.rawValue) flush 终止旧 dial")
            harness.makeAutomatic(address: "203.0.113.81")
            try work.send(query("flush-dial.scope.fixture.test", id: 0x9911), original: original,
                          address: "203.0.113.81")
            try work.replies.wait("\(kind.rawValue) 新 epoch 未被旧 dial 饿死")
            let late = harness.releaseDials()
            try require(late.count == 1, "\(kind.rawValue)：旧物理 dial callback 丢失")
            for peer in late {
                try require(peer.closed.wait(timeout: .now() + 2) == .success && peer.sendCount == 0,
                            "\(kind.rawValue)：取消后的 native 成功 stream 未关闭或发生旧查询 IO")
            }
            try work.send(query("flush-dial.scope.fixture.test", id: 0x9912), original: original,
                          address: "203.0.113.81")
            try work.replies.wait("\(kind.rawValue) late dial 不破坏新 cache")
            try require(harness.statistics.exchanges == 1 && harness.statistics.dials == 2,
                        "\(kind.rawValue)：旧 dial 复活/回填缓存或影响新连接所有者")
        }
    }
}

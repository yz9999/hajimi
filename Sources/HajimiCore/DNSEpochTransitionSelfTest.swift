import Foundation
import HajimiDNS

/// Replays the actual router/association/DoT-pool epoch boundary with memory
/// streams. The private caller installs a gate only for this fixture instance;
/// no socket, helper, trust override or user/system configuration is involved.
enum DNSEpochTransitionSelfTest {
    typealias InstallGate = (NativePacketRouter, (() -> Void)?) -> Void
    typealias DrainFlow = (any NativeRoutedDatagram) -> Void

    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS epoch transition 自检失败：\(text)" }
    }
    private static func require(_ condition: Bool, _ text: String) throws {
        guard condition else { throw Failure(text: text) }
    }
    private static func wait(_ semaphore: DispatchSemaphore, _ text: String) throws {
        try require(semaphore.wait(timeout: .now() + 3) == .success, text)
    }
    private static func query(_ name: String, id: UInt16) throws -> Data {
        guard let query = DNSMessageInspection.query(for: name, type: 1, id: id) else {
            throw Failure(text: "无法编码固定 epoch fixture 问题")
        }
        return query
    }
    private static func answer(_ query: Data, lastOctet: UInt8) -> Data {
        let question = DNSMessageInspection.singleQuestion(in: query)!
        var response = Data(query.prefix(question.questionEnd))
        response[2] = 0x81; response[3] = 0x80
        for index in 6...11 { response[index] = 0 }
        response[7] = 1
        response.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, lastOctet])
        return response
    }
    private static func framed(_ response: Data) -> Data {
        Data([UInt8(response.count >> 8), UInt8(truncatingIfNeeded: response.count)]) + response
    }

    private final class GateState {
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var timedOut = false, completed = false
        func suspend() {
            entered.signal()
            let failed = resume.wait(timeout: .now() + 3) != .success
            lock.lock(); timedOut = failed; lock.unlock()
        }
        func complete() { lock.lock(); completed = true; lock.unlock(); finished.signal() }
        var snapshot: (timedOut: Bool, completed: Bool) {
            lock.lock(); defer { lock.unlock() }; return (timedOut, completed)
        }
    }

    private final class Replies {
        private struct Expected {
            let query: Data, address: String, done: DispatchSemaphore
        }
        private let lock = NSLock()
        private var expected: [UInt16: Expected] = [:]
        private var received: [UInt16: Int] = [:]
        private var failure: String?

        func register(_ query: Data, address: String) -> UInt16 {
            let id = UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1])
            lock.lock()
            expected[id] = Expected(query: query, address: address, done: DispatchSemaphore(value: 0))
            lock.unlock(); return id
        }
        func receive(_ response: Data) {
            guard response.count >= 12 else { fail(); return }
            let id = UInt16(response[response.startIndex]) << 8 | UInt16(response[response.startIndex + 1])
            lock.lock()
            guard let item = expected[id] else {
                failure = failure ?? "epoch fixture 收到非预期客户端 ID"
                let signals = expected.values.map(\.done); lock.unlock(); signals.forEach { $0.signal() }; return
            }
            received[id, default: 0] += 1
            if received[id] != 1 {
                failure = failure ?? "epoch fixture 重复完成同一个问题"
            } else if !DNSMessageInspection.responseMatchesQuery(response, query: item.query)
                || response[response.startIndex + 3] & 15 != 0
                || DNSMessageInspection.addressAnswers(in: response).map(\.address) != [item.address] {
                failure = failure ?? "新 epoch 问题被旧清理取消、串答或返回错误地址"
            }
            lock.unlock(); item.done.signal()
        }
        func fail() {
            lock.lock(); failure = failure ?? "epoch fixture association 发生失败"
            let signals = expected.values.map(\.done); lock.unlock(); signals.forEach { $0.signal() }
        }
        func waitFor(_ id: UInt16) throws {
            lock.lock(); let item = expected[id]; lock.unlock()
            guard let item else { throw Failure(text: "epoch fixture 没有注册预期问题") }
            try DNSEpochTransitionSelfTest.wait(item.done, "epoch fixture 问题未完成")
            try validate()
        }
        func contains(_ id: UInt16) -> Bool {
            lock.lock(); defer { lock.unlock() }; return received[id] != nil
        }
        func validate() throws {
            lock.lock(); let error = failure; lock.unlock()
            if let error { throw Failure(text: error) }
        }
    }

    private final class Peer: NativeOutboundByteStream {
        private struct Reader {
            let maximum: Int, completion: (Data?, Bool, Error?) -> Void
        }
        private let lock = NSLock()
        private let worker: DispatchQueue
        private let sent: () -> Void, heldRead: () -> Void
        private var receiver: Reader?
        private var buffered = Data(), heldResponse: Data?
        private var stopped = false, notifiedHeldRead = false
        private var cancellations = 0, sends = 0

        init(worker: DispatchQueue, sent: @escaping () -> Void, heldRead: @escaping () -> Void) {
            self.worker = worker; self.sent = sent; self.heldRead = heldRead
        }
        func send(_ wire: Data, completion: @escaping (Error?) -> Void) {
            guard wire.count >= 14,
                  (Int(wire[wire.startIndex]) << 8 | Int(wire[wire.startIndex + 1])) == wire.count - 2,
                  let question = DNSMessageInspection.singleQuestion(in: Data(wire.dropFirst(2))),
                  question.type == 1, question.name.hasSuffix(".epoch.fixture.test") else {
                completion(Failure(text: "memory DoT peer 收到 fixture 之外的数据")); return
            }
            let query = Data(wire.dropFirst(2)), hold = question.name.hasPrefix("fresh.")
            lock.lock()
            guard !stopped, buffered.isEmpty, heldResponse == nil else {
                lock.unlock(); completion(Failure(text: "memory DoT peer 关闭或事务重叠")); return
            }
            sends += 1
            let response = DNSEpochTransitionSelfTest.framed(DNSEpochTransitionSelfTest.answer(query, lastOctet: hold ? 81 : 80))
            if hold { heldResponse = response } else { buffered = response }
            let notify = hold && receiver != nil && !notifiedHeldRead
            if notify { notifiedHeldRead = true }
            lock.unlock()
            sent(); completion(nil)
            if notify { heldRead() }
            drain()
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped, maximum > 0, receiver == nil else {
                lock.unlock(); completion(nil, true, Failure(text: "memory DoT peer read 重叠或已关闭")); return
            }
            receiver = Reader(maximum: maximum, completion: completion)
            let notify = heldResponse != nil && !notifiedHeldRead
            if notify { notifiedHeldRead = true }
            lock.unlock()
            if notify { heldRead() }
            drain()
        }
        private func drain() {
            lock.lock()
            guard !stopped, let receiver, !buffered.isEmpty else { lock.unlock(); return }
            self.receiver = nil
            let data = Data(buffered.prefix(receiver.maximum))
            buffered.removeFirst(data.count)
            lock.unlock(); receiver.completion(data, false, nil)
        }
        func releaseHeldResponse() {
            worker.async {
                self.lock.lock()
                guard !self.stopped, let response = self.heldResponse else { self.lock.unlock(); return }
                self.heldResponse = nil; self.buffered = response; self.lock.unlock(); self.drain()
            }
        }
        func cancel() {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            stopped = true; cancellations += 1; heldResponse = nil; buffered.removeAll()
            let pending = receiver; receiver = nil; lock.unlock()
            pending?.completion(nil, true, EncryptedDNSQueryFailure.cancelled)
        }
        var snapshot: (cancellations: Int, sends: Int, held: Bool, reading: Bool) {
            lock.lock(); defer { lock.unlock() }
            return (cancellations, sends, heldResponse != nil, receiver != nil)
        }
    }

    private final class Harness {
        let heldRead = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var peers: [Peer] = []
        private var exchanges = 0
        var dialer: MetadataAwareEncryptedDNSStreamDialer {
            { [self] host, port, name, worker, _, note, ready in
                guard host == "203.0.113.73", port == 5853, name == "epoch.fixture.invalid" else {
                    let error = Failure(text: "memory epoch dial 逃逸已批准 endpoint")
                    note(error); ready(.failure(error)); return nil
                }
                let peer = Peer(worker: worker, sent: { [weak self] in
                    guard let self else { return }
                    self.lock.lock(); self.exchanges += 1; self.lock.unlock()
                }, heldRead: { [weak self] in self?.heldRead.signal() })
                lock.lock(); peers.append(peer); lock.unlock()
                worker.async { ready(.success(peer)) }
                return { peer.cancel() }
            }
        }
        var snapshot: (peers: [Peer], exchanges: Int) {
            lock.lock(); defer { lock.unlock() }; return (peers, exchanges)
        }
    }

    static func run(makeRouter: DNSTransportScopeSelfTest.MakeRouter,
                    installAfterFlushGate: InstallGate, drainFlow: DrainFlow) throws {
        var profile = Profile()
        profile.fakeIPEnabled = false; profile.dnsLeakProtectionEnabled = true
        profile.dnsProxyFallbackEnabled = false; profile.dnsProxyFallbackServers = []
        profile.dnsServers = []; profile.encryptedDNSServers = ["tls://epoch.fixture.invalid:5853#203.0.113.73"]
        profile.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let harness = Harness(), replies = Replies(), gate = GateState()
        let router = makeRouter(profile, harness.dialer)
        let queue = DispatchQueue(label: "app.hajimi.dns.epoch-transition-self-test", qos: .userInitiated)
        let flow = try router.makeUDPFlow(host: "203.0.113.53", port: 53, queue: queue,
            sourceHost: "192.0.2.2", sourcePort: 44000, inboundPort: 7263,
            receive: { replies.receive($0) }, failure: { _ in replies.fail() })
        var flushStarted = false
        defer {
            installAfterFlushGate(router, nil)
            gate.resume.signal()
            if flushStarted && !gate.snapshot.completed { _ = gate.finished.wait(timeout: .now() + 3) }
            flow.cancel(); router.flushDNS()
        }
        let warm = try query("warm.epoch.fixture.test", id: 0xb001)
        let warmID = replies.register(warm, address: "203.0.113.80")
        flow.send(warm); try replies.waitFor(warmID)
        try require(harness.snapshot.peers.count == 1 && harness.snapshot.exchanges == 1,
                    "无法在已有 association 上建立旧代 idle pool")

        installAfterFlushGate(router) { gate.suspend() }
        flushStarted = true
        DispatchQueue.global(qos: .userInitiated).async { router.flushDNS(); gate.complete() }
        try wait(gate.entered, "flush 未在新代公布、旧清理前进入 deterministic gate")
        let fresh = try query("fresh.epoch.fixture.test", id: 0xb002)
        let freshID = replies.register(fresh, address: "203.0.113.81")
        flow.send(fresh)
        try wait(harness.heldRead, "同一旧 association 的新代问题没有真正进入 held read")
        let duringGate = harness.snapshot
        try require(duringGate.peers.count == 2 && duringGate.exchanges == 2,
                    "新代问题未提交独立新 pool 或继续使用已 detach 旧池")
        let newPeer = duringGate.peers[1]
        try require(newPeer.snapshot.held && newPeer.snapshot.reading && newPeer.snapshot.cancellations == 0
                    && !replies.contains(freshID), "gate 中的新查询已被旧清理取消或没有在途")

        gate.resume.signal(); try wait(gate.finished, "旧代资源/association 清理没有结束")
        installAfterFlushGate(router, nil)
        drainFlow(flow) // Ensures the old association cleanup has run, not just been enqueued.
        try require(!gate.snapshot.timedOut && newPeer.snapshot.cancellations == 0
                    && newPeer.snapshot.held && !replies.contains(freshID),
                    "flush 清理误杀了已提交的新代 pool、coordinator 或同 association 事务")
        newPeer.releaseHeldResponse(); try replies.waitFor(freshID)
        let cached = try query("fresh.epoch.fixture.test", id: 0xb003)
        let cachedID = replies.register(cached, address: "203.0.113.81")
        flow.send(cached); try replies.waitFor(cachedID)
        try require(harness.snapshot.peers.count == 2 && harness.snapshot.exchanges == 2,
                    "新代完成后的暖查询未命中缓存，或旧 epoch 回填了新答案")
        try replies.validate()
        print("DNS atomic epoch transition passed: old association warms a pool, new epoch commits held IO before old cleanup, current query survives and new cache works")
    }
}

import Foundation
import HajimiDNS
import Network

/// Memory-only coverage of the production Attempt -> Request -> Flow boundary.
/// No listener, TLS bridge, native socket, system DNS, Helper or profile is used.
/// The fallback factory is a spy returning a memory datagram, never plaintext I/O.
enum DNSNativeFailureAdmissionSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS 原生失败接纳自检失败：\(text)" }
    }
    private static func require(_ value: Bool, _ text: String) throws {
        if !value { throw Failure(text: text) }
    }
    private static func wait(_ value: DispatchSemaphore, _ text: String) throws {
        try require(value.wait(timeout: .now() + 2) == .success, text)
    }

    private enum WireProtocol: CaseIterable { case doh, dot }
    private enum NativeStage: CaseIterable { case connect, upgrade }
    private enum AdmissionBoundary: CaseIterable { case operationCallback, beforeCallerHop }

    private final class Clock {
        private let lock = NSLock()
        private var time: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return time }
        func cutoff() { lock.lock(); time = 103; lock.unlock() }
    }
    private final class Timers {
        private final class Item {
            let deadline: TimeInterval, queue: DispatchQueue, work: () -> Void
            var cancelled = false
            init(deadline: TimeInterval, queue: DispatchQueue, work: @escaping () -> Void) {
                self.deadline = deadline; self.queue = queue; self.work = work
            }
        }
        let phaseArmed = DispatchSemaphore(value: 0)
        private let lock = NSLock(), clock: Clock
        private var items: [Item] = []
        init(clock: Clock) { self.clock = clock }
        var schedule: DNSProxyFallbackQueryDatagram.Schedule {
            { queue, delay, work in
                let item = Item(deadline: self.clock.now() + delay, queue: queue, work: work)
                self.lock.lock(); self.items.append(item); self.lock.unlock()
                if abs(delay - 3) < 0.001 { self.phaseArmed.signal() }
                return { self.lock.lock(); item.cancelled = true; self.lock.unlock() }
            }
        }
        func fire() {
            lock.lock()
            let now = clock.now(), due = items.filter { !$0.cancelled && $0.deadline <= now }
            items.removeAll { $0.cancelled || $0.deadline <= now }
            lock.unlock()
            due.forEach { $0.queue.async(execute: $0.work) }
        }
    }

    private final class MemoryStream: NativeOutboundByteStream {
        private let lock = NSLock()
        private var response: Data?, reader: ((Data?, Bool, Error?) -> Void)?
        private var closed = false, sent: [Data] = [], closes = 0
        init(response: Data? = nil) { self.response = response }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); let stopped = closed
            if !stopped { sent.append(data) }
            lock.unlock(); completion(stopped ? EncryptedDNSQueryFailure.cancelled : nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            if closed { lock.unlock(); completion(nil, true, EncryptedDNSQueryFailure.cancelled); return }
            if reader != nil { lock.unlock(); completion(nil, true, EncryptedDNSQueryFailure.invalidResponse); return }
            if let response, !response.isEmpty {
                let chunk = Data(response.prefix(maximum)), remaining = Data(response.dropFirst(maximum))
                self.response = remaining.isEmpty ? nil : remaining
                lock.unlock(); completion(chunk, false, nil)
            } else { reader = completion; lock.unlock() }
        }
        func cancel() {
            lock.lock(); closes += 1; closed = true; let callback = reader; reader = nil; lock.unlock()
            callback?(nil, true, EncryptedDNSQueryFailure.cancelled)
        }
        var snapshot: (writes: [Data], closes: Int) { lock.lock(); defer { lock.unlock() }; return (sent, closes) }
    }

    /// The real synchronous state dispatcher/admission drives a memory owner.
    /// cancelLocked alone supplies the receipt; the observer never completes it.
    private final class TLSStateOwner {
        let raw = MemoryStream()
        private let injectCleanupUnknown: Bool, note: ((Error) -> Void)?, complete: ((Error?) -> Void)?
        private(set) var live = true, pending = true
        private(set) var events: [String] = [], observations: [Error] = []
        private(set) var resultError: Error?, firstDenial: EncryptedDNSQueryFailure?
        private(set) var denialAtRawCancel: EncryptedDNSQueryFailure?
        private(set) var failures = 0, successes = 0
        init(injectCleanupUnknown: Bool = true, note: ((Error) -> Void)? = nil,
             complete: ((Error?) -> Void)? = nil) {
            self.injectCleanupUnknown = injectCleanupUnknown; self.note = note; self.complete = complete
        }
        func handle(_ state: NWConnection.State) {
            nativeOutboundTLSStateHandler(state, isLive: live, hasPendingUpgrade: pending, ready: {
                guard pending else { return }; pending = false; successes += 1
                events.append("ready"); complete?(nil)
            }, fail: { error in
                nativeOutboundTLSFailureAdmission(error, isLive: live, failureObserver: observe) {
                    cancelLocked($0)
                }
            })
        }
        private func observe(_ error: Error) {
            observations.append(error)
            let reason = EncryptedDNSQueryFailure.classify(error)
            events.append("observe-\(reason)")
            if firstDenial == nil, !reason.permitsProxyFallback, reason != .cancelled { firstDenial = reason }
            note?(error)
        }
        private func cancelLocked(_ error: Error) {
            guard live else { return }
            let receiptPending = pending; live = false; pending = false
            denialAtRawCancel = firstDenial; events.append("raw.cancel"); raw.cancel()
            if injectCleanupUnknown { observe(NativeOutboundError.connection("memory raw cancellation cleanup")) }
            guard receiptPending else { return }
            // The unchanged outer factory can observe this exact error again.
            observe(error); resultError = error; failures += 1; events.append("completion")
            complete?(error)
        }
        func cancelUpgrade() {
            guard live, pending else { return }
            cancelLocked(NativeOutboundError.cancelled)
        }
    }
    private final class FallbackSpy: NativeRoutedDatagram, DNSQueryCancellationAcknowledging {
        private let receive: (Data) -> Void
        init(receive: @escaping (Data) -> Void) { self.receive = receive }
        func send(_ data: Data) {
            if let answer = DNSNativeFailureAdmissionSelfTest.makeAnswer(data, code: 0) { receive(answer) }
        }
        func cancel() {}
        func cancel(completion: @escaping () -> Void) { completion() }
    }
    private final class CancelProbe: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding {
        private let child: DNSQueryCancellationAcknowledging & DNSProxyFallbackBarrierProviding
        let cancellationQueued = DispatchSemaphore(value: 0)
        init(_ child: DNSQueryCancellationAcknowledging & DNSProxyFallbackBarrierProviding) { self.child = child }
        func send(_ data: Data) { child.send(data) }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            child.cancel(completion: completion)
            // Flow.cancel has synchronously revoked registration and queued
            // Request C before this signal. It has NOT acknowledged C yet.
            cancellationQueued.signal()
        }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { child.proxyFallbackBarrier() }
    }

    private final class Fixture {
        typealias NativeReady = (Result<any NativeOutboundByteStream, Error>) -> Void
        let query = DNSMessageInspection.query(for: "owned.native-admission.example.test", type: 1, id: 0x6a01)!
        let nativeArmed = DispatchSemaphore(value: 0), nativeCompleted = DispatchSemaphore(value: 0)
        let completed = DispatchSemaphore(value: 0), clock = Clock()
        let diagnostics = NetworkPerformanceDiagnostics(), raw = MemoryStream()
        private let wire: WireProtocol, stage: NativeStage, cancelGeneratesUnknown: Bool
        private let lock = NSLock()
        private var worker: DispatchQueue?, ready: NativeReady?, note: ((Error) -> Void)?
        private var child: CancelProbe?, stopResolver: (() -> Void)?
        private var answers: [Data] = [], errors: [Error] = [], fallbackFactories = 0
        private var nativeResults = 0, nativeCancellations = 0
        private var secured: MemoryStream?
        lazy var timers = Timers(clock: clock)
        lazy var parent = DNSProxyFallbackQueryDatagram(queue: .global(qos: .userInitiated), absoluteDeadline: 108,
            permitted: { [weak self] in self != nil }, knownMilliseconds: { [] },
            encrypted: { [weak self] _, _, receive, failure in
                guard let self else { throw EncryptedDNSQueryFailure.configuration }
                let dialer: MetadataAwareEncryptedDNSStreamDialer = { [weak self] host, port, name, worker, trace, note, done in
                    guard let self else { done(.failure(EncryptedDNSQueryFailure.cancelled)); return nil }
                    guard host == "203.0.113.53", port > 0, name == "dns.native.fixture.invalid" else {
                        done(.failure(EncryptedDNSQueryFailure.configuration)); return nil
                    }
                    self.lock.lock(); self.worker = worker; self.note = note; self.lock.unlock()
                    let attempt = DNSRoutedTLSConnectionAttempt(queue: worker, permitted: { true },
                        connect: { [weak self] ready in
                            guard let self else { ready(.failure(EncryptedDNSQueryFailure.cancelled)); return nil }
                            if self.stage == .connect { self.arm(ready); return { [weak self] in self?.cancelNative() } }
                            ready(.success(self.raw)); return nil
                        }, upgrade: { [weak self] _, _, ready in
                            guard let self else { ready(.failure(EncryptedDNSQueryFailure.cancelled)); return nil }
                            self.arm(ready); return { [weak self] in self?.cancelNative() }
                        }, diagnostics: self.diagnostics, failureObserver: note, attemptTrace: trace, completion: { [weak self] result in
                            done(result)
                            if let self {
                                self.lock.lock(); self.nativeResults += 1; self.lock.unlock()
                                self.nativeCompleted.signal()
                            }
                        })
                    attempt.start(); return { attempt.cancel() }
                }
                let wrapped: CancelProbe
                switch self.wire {
                case .doh:
                    let resolver = DoHResolver(endpoint: DoHEndpoint("https://dns.native.fixture.invalid/dns-query#203.0.113.53")!,
                                               metadataStreamDialer: dialer)
                    wrapped = CancelProbe(DoHRoutedDatagram(resolver: resolver, receive: receive, failure: failure))
                    self.lock.lock(); self.stopResolver = resolver.cancel; self.lock.unlock()
                case .dot:
                    let resolver = DoTResolver(endpoint: DoTEndpoint("tls://dns.native.fixture.invalid#203.0.113.53")!,
                                               metadataStreamDialer: dialer)
                    wrapped = CancelProbe(DoTRoutedDatagram(resolver: resolver, receive: receive, failure: failure))
                    self.lock.lock(); self.stopResolver = resolver.cancel; self.lock.unlock()
                }
                self.lock.lock(); self.child = wrapped; self.lock.unlock(); return wrapped
            }, fallback: { [weak self] _, deadline, receive, _ in
                guard let self else { throw EncryptedDNSQueryFailure.configuration }
                guard deadline == 108 else { throw Failure(text: "回退重置了绝对八秒期限") }
                self.lock.lock(); self.fallbackFactories += 1; self.lock.unlock()
                return FallbackSpy(receive: receive)
            }, receive: { [weak self] answer in
                guard let self else { return }
                self.lock.lock(); self.answers.append(answer); self.lock.unlock(); self.completed.signal()
            }, failure: { [weak self] error in
                guard let self else { return }
                self.lock.lock(); self.errors.append(error); self.lock.unlock(); self.completed.signal()
            }, clock: clock.now, schedule: timers.schedule, diagnostics: diagnostics)

        init(wire: WireProtocol, stage: NativeStage = .upgrade, cancelGeneratesUnknown: Bool = false) {
            self.wire = wire; self.stage = stage; self.cancelGeneratesUnknown = cancelGeneratesUnknown
        }
        private func arm(_ ready: @escaping NativeReady) {
            lock.lock(); self.ready = ready; lock.unlock(); nativeArmed.signal()
        }
        private func cancelNative() {
            lock.lock(); nativeCancellations += 1
            let callback = cancelGeneratesUnknown ? ready : nil
            if callback != nil { ready = nil }
            lock.unlock()
            // Deliberately unclassified cancellation noise AFTER Request.seal.
            // It must not become a deny barrier for an unrelated live phase.
            callback?(.failure(NSError(domain: "OwnedNativeCancellationFixture", code: 1)))
        }
        func start() throws {
            parent.send(query)
            try DNSNativeFailureAdmissionSelfTest.wait(nativeArmed, "原生内存阶段未启动")
            try DNSNativeFailureAdmissionSelfTest.wait(timers.phaseArmed, "加密阶段截止未装载或查询注册未返回")
        }
        private func owner() throws -> DispatchQueue {
            lock.lock(); let worker = worker; lock.unlock()
            guard let worker else { throw Failure(text: "缺少 Request 所属 pool 队列") }; return worker
        }
        func holdPool() throws -> () -> Void {
            let worker = try owner(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            worker.async { entered.signal(); _ = release.wait(timeout: .now() + 3) }
            try DNSNativeFailureAdmissionSelfTest.wait(entered, "无法封锁 pool 队列以构造 FIFO N/C/A/B")
            return { release.signal() }
        }
        func enqueueNative(_ result: Result<any NativeOutboundByteStream, Error>, noteBeforeHop: Bool = false) throws {
            let worker = try owner()
            lock.lock(); let callback = ready, note = note; ready = nil; lock.unlock()
            guard let callback else { throw Failure(text: "原生完成回调已被消费") }
            if noteBeforeHop, case .failure(let error) = result { note?(error) }
            // N runs on the caller queue and admits to Operation before A.
            // Operation must synchronously note its native failure before it
            // queues A, even though Flow has already revoked registration.
            worker.async { callback(result) }
        }
        func enqueueNativeTLSState(_ state: NWConnection.State) throws -> TLSStateOwner {
            let worker = try owner()
            lock.lock(); let callback = ready, note = note; ready = nil; lock.unlock()
            guard let callback, let note else { throw Failure(text: "原生 TLS 状态缺少真实 callback/observer") }
            let owner = TLSStateOwner(note: note, complete: { error in
                if let error { callback(.failure(error)) }
                else { callback(.success(self.raw)) }
            })
            worker.async {
                owner.handle(state)
                // Duplicate and late state deliveries cannot supply receipts.
                owner.handle(.failed(.tls(-9843))); owner.handle(.ready)
            }
            return owner
        }
        func noteBeforeCallerHop(_ error: Error) throws {
            lock.lock(); let note = note; lock.unlock()
            guard let note else { throw Failure(text: "缺少 immutable native deny recorder") }
            note(error)
        }
        func phaseCutoff() throws {
            clock.cutoff(); timers.fire()
            lock.lock(); let child = child; lock.unlock()
            guard let child else { throw Failure(text: "缺少生产加密 Flow") }
            try DNSNativeFailureAdmissionSelfTest.wait(child.cancellationQueued, "阶段截止没有排入 Request C")
        }
        func cancelParent() throws {
            parent.cancel()
            lock.lock(); let child = child; lock.unlock()
            guard let child else { throw Failure(text: "缺少生产加密 Flow") }
            try DNSNativeFailureAdmissionSelfTest.wait(child.cancellationQueued, "显式取消没有排入 Request C")
        }
        func awaitPhysicalCallback() throws {
            try DNSNativeFailureAdmissionSelfTest.wait(nativeCompleted, "原生完成没有交给 Request 的实际 callback")
            try owner().sync {} // B has already been appended by done(result).
        }
        func secureStream(code: UInt8 = 0) -> MemoryStream {
            let answer = DNSNativeFailureAdmissionSelfTest.makeAnswer(query, code: code)!
            let response: Data
            switch wire {
            case .doh:
                response = Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(answer.count)\r\n\r\n".utf8) + answer
            case .dot: response = Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer
            }
            let stream = MemoryStream(response: response)
            lock.lock(); secured = stream; lock.unlock(); return stream
        }
        var barrier: DNSProxyFallbackBarrier? { lock.lock(); let child = child; lock.unlock(); return child?.proxyFallbackBarrier() }
        var snapshot: (answers: [Data], errors: [Error], fallbackFactories: Int, nativeResults: Int, cancellations: Int) {
            lock.lock(); defer { lock.unlock() }; return (answers, errors, fallbackFactories, nativeResults, nativeCancellations)
        }
        func stop() {
            parent.cancel()
            lock.lock(); let cancel = stopResolver, ready = ready, secure = secured
            self.ready = nil; stopResolver = nil; note = nil; lock.unlock()
            cancel?(); ready?(.failure(EncryptedDNSQueryFailure.cancelled)); secure?.cancel(); raw.cancel()
        }
    }

    private static func makeAnswer(_ query: Data, code: UInt8) -> Data? {
        guard var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail) else { return nil }
        answer[3] = (answer[3] & 0xf0) | (code & 0x0f); return answer
    }

    private static func tlsStateFailureAdmission() throws {
        let states: [(NWConnection.State, Int32)] = [(.failed(.tls(-9807)), -9807), (.waiting(.tls(-9843)), -9843)]
        func matches(_ error: Error?, _ code: Int32) -> Bool {
            guard let value = error as? NWError, case .tls(let actual) = value else { return false }
            return actual == code
        }
        for (state, code) in states {
            let owner = TLSStateOwner()
            owner.handle(.waiting(.posix(.ECONNREFUSED)))
            try require(owner.events.isEmpty && owner.live && owner.pending && owner.raw.snapshot.closes == 0,
                        "非 TLS waiting 被当作终止或提供了假 setup 回执")
            owner.handle(state)
            let events = owner.events
            try require(events == ["observe-authentication", "raw.cancel", "observe-other",
                                   "observe-authentication", "completion"]
                        && matches(owner.observations.first, code) && matches(owner.resultError, code)
                        && owner.denialAtRawCancel == .authentication && owner.firstDenial == .authentication
                        && owner.raw.snapshot.closes == 1 && owner.failures == 1 && owner.successes == 0,
                        "真实 typed TLS 错误未先于 raw.cancel/完成入场，或 cleanup unknown 覆盖了认证")
            owner.handle(state); owner.handle(.failed(.posix(.ECONNRESET))); owner.handle(.ready)
            owner.handle(.cancelled); owner.cancelUpgrade()
            try require(owner.events == events && owner.raw.snapshot.closes == 1 && owner.failures == 1,
                        "重复/迟到 TLS 状态或 own cancel 重复完成、关闭或改写了认证")

            for wire in WireProtocol.allCases {
                let fixture = Fixture(wire: wire); defer { fixture.stop() }
                try fixture.start()
                let actual = try fixture.enqueueNativeTLSState(state)
                try wait(fixture.completed, "生产 TLS state -> Request/Flow 认证拒绝未完成")
                try fixture.awaitPhysicalCallback()
                guard case .failure(let denial)? = fixture.barrier else {
                    throw Failure(text: "原生 TLS teardown 擦除了真实 Request/Flow 认证屏障")
                }
                let result = fixture.snapshot
                try require(denial as? EncryptedDNSQueryFailure == .authentication
                            && result.errors.first as? EncryptedDNSQueryFailure == .authentication
                            && result.errors.count == 1 && result.answers.isEmpty && result.fallbackFactories == 0
                            && result.nativeResults == 1 && actual.failures == 1
                            && actual.raw.snapshot.closes == 1 && matches(actual.resultError, code),
                            "实际 typed TLS 入场被 raw cleanup unknown 洗掉、重复完成或授权普通 DNS")
            }
        }
        let own = TLSStateOwner(injectCleanupUnknown: false)
        own.cancelUpgrade(); let ownEvents = own.events
        own.handle(.failed(.tls(-9807))); own.handle(.waiting(.tls(-9843))); own.handle(.ready); own.cancelUpgrade()
        try require(ownEvents == ["raw.cancel", "observe-cancelled", "completion"] && own.events == ownEvents
                    && own.resultError.map(EncryptedDNSQueryFailure.classify) == .cancelled
                    && own.firstDenial == nil && own.failures == 1 && own.raw.snapshot.closes == 1,
                    "own cancel 伪造了 TLS 认证、允许降级或重复完成")
        let unexpected = TLSStateOwner(injectCleanupUnknown: false)
        unexpected.handle(.cancelled)
        try require(unexpected.resultError.map(EncryptedDNSQueryFailure.classify) == .other && unexpected.failures == 1,
                    "未请求的 TLS cancelled 被误改为 typed own cancellation")
        let ready = TLSStateOwner(injectCleanupUnknown: false)
        ready.handle(.ready); ready.handle(.ready); ready.cancelUpgrade(); ready.handle(.cancelled)
        try require(ready.successes == 1 && ready.failures == 0 && ready.raw.snapshot.closes == 0,
                    "已交付 TLS 的重复 ready/upgrade cancel 关闭了 caller 的 stream 或重复完成")
        ready.handle(.failed(.tls(-9807)))
        try require(ready.successes == 1 && ready.failures == 0 && ready.raw.snapshot.closes == 1
                    && ready.firstDenial == .authentication,
                    "已交付 stream 的真实后续错误未清理或重复提供 setup 回执")
        print("TLS state failure admission passed: actual typed failed/waiting before raw close, cleanup unknown barriers, nonterminal waiting, own/duplicate/late cancellation and exactly-once receipts")
    }

    static func run() throws {
        try tlsStateFailureAdmission()
        let denied: [(Error, EncryptedDNSQueryFailure)] = [
            (NWError.tls(-9807), .authentication),
            (NSError(domain: "OwnedNativeUnknownFixture", code: 73), .other),
            (NativeOutboundError.unsupported("owned fixture"), .configuration),
            (NativeOutboundError.protocolError("owned fixture"), .invalidResponse),
            (NodeConnectionAdmissionError.capacityExceeded, .capacity)
        ]
        for wire in WireProtocol.allCases {
            for stage in NativeStage.allCases {
                for boundary in AdmissionBoundary.allCases {
                    for (error, expected) in denied {
                        let fixture = Fixture(wire: wire, stage: stage); defer { fixture.stop() }
                        try fixture.start()
                        let release = try fixture.holdPool(); defer { release() }
                        if boundary == .operationCallback {
                            // N entered the pool FIFO before C; N queues A
                            // behind C, and A later queues Request B.
                            try fixture.enqueueNative(.failure(error))
                            try fixture.phaseCutoff()
                        } else {
                            // The raw failure is already admitted before the
                            // caller hop, but completion N is queued AFTER C.
                            // Only the immutable pre-hop recorder can save it.
                            try fixture.noteBeforeCallerHop(error)
                            try fixture.phaseCutoff()
                            try fixture.enqueueNative(.failure(error))
                        }
                        release()
                        try wait(fixture.completed, "认证/未知屏障没有完成安全拒绝")
                        try fixture.awaitPhysicalCallback()
                        guard case .failure(let preserved)? = fixture.barrier else {
                            throw Failure(text: "取消 ACK 擦除了 native 已接纳的拒绝元数据")
                        }
                        let result = fixture.snapshot
                        try require(preserved as? EncryptedDNSQueryFailure == expected
                                    && result.errors.first as? EncryptedDNSQueryFailure == expected
                                    && result.errors.count == 1 && result.answers.isEmpty
                                    && result.fallbackFactories == 0 && result.nativeResults == 1,
                                    "N/C/A/B 原生拒绝被改写、重复完成或授权了普通 DNS")
                    }
                }
            }
            for error in [EncryptedDNSQueryFailure.network, .timeout, .cancelled] {
                let fixture = Fixture(wire: wire); defer { fixture.stop() }
                try fixture.start()
                let release = try fixture.holdPool(); defer { release() }
                try fixture.enqueueNative(.failure(error)); try fixture.phaseCutoff(); release()
                try wait(fixture.completed, "无拒绝屏障的阶段截止未完成")
                try fixture.awaitPhysicalCallback()
                let result = fixture.snapshot
                try require(fixture.barrier == nil && result.fallbackFactories == 1 && result.errors.isEmpty
                            && result.answers.count == 1
                            && DNSMessageInspection.responseMatchesQuery(result.answers[0], query: fixture.query),
                            "network/timeout/phase-selfcancel 被错误录为 deny 或重置了查询身份")
            }
            do {
                let fixture = Fixture(wire: wire, cancelGeneratesUnknown: true); defer { fixture.stop() }
                try fixture.start(); try fixture.phaseCutoff()
                try wait(fixture.completed, "取消产生 unknown 的阶段截止未完成")
                try fixture.awaitPhysicalCallback()
                let result = fixture.snapshot
                try require(fixture.barrier == nil && result.cancellations == 1
                            && result.fallbackFactories == 1 && result.errors.isEmpty && result.answers.count == 1,
                            "seal 后取消动作自产 unknown 污染了安全回退屏障")
            }
            do {
                let fixture = Fixture(wire: wire, cancelGeneratesUnknown: true); defer { fixture.stop() }
                try fixture.start(); try fixture.cancelParent(); try fixture.awaitPhysicalCallback()
                let result = fixture.snapshot
                try require(fixture.barrier == nil && result.fallbackFactories == 0
                            && result.answers.isEmpty && result.errors.isEmpty,
                            "用户主动取消触发回退或送出迟到结果")
            }
            do {
                let fixture = Fixture(wire: wire); defer { fixture.stop() }
                try fixture.start()
                let stream = fixture.secureStream(), release = try fixture.holdPool(); defer { release() }
                try fixture.enqueueNative(.success(stream)); try fixture.phaseCutoff(); release()
                try wait(fixture.completed, "迟到 TLS success 阶段未完成")
                try fixture.awaitPhysicalCallback()
                try require(fixture.barrier == nil && stream.snapshot.writes.isEmpty && stream.snapshot.closes == 1
                            && fixture.snapshot.fallbackFactories == 1,
                            "取消后的 TLS success 发出了旧 DNS 请求或变成假拒绝屏障")
            }
            for code in [UInt8(0), 3, 5, 2] {
                let fixture = Fixture(wire: wire); defer { fixture.stop() }
                try fixture.start()
                let stream = fixture.secureStream(code: code)
                try fixture.enqueueNative(.success(stream))
                try wait(fixture.completed, "有效加密 DNS 正答/否定未完成")
                try fixture.awaitPhysicalCallback()
                let result = fixture.snapshot
                try require(result.fallbackFactories == 0 && result.errors.isEmpty && result.answers.count == 1
                            && result.answers.first == makeAnswer(fixture.query, code: code)
                            && stream.snapshot.writes.count == 1,
                            "有效 NODATA/NXDOMAIN/REFUSED/SERVFAIL 触发普通 DNS 或被原生元数据吞掉")
            }
        }
        print("DNS native failure admission checks passed: DoH/DoT Attempt -> Request -> Flow N/C/A/B, pre-hop auth/unknown barriers, typed exclusions, sealed cancellation, late TLS success, DNS negatives and zero unauthorized fallback factories")
    }
}

import Foundation
import HajimiDNS
import Network
import Security
import Darwin

// MARK: - Routed Proxy-to-Inner-TLS Connection Attempt & Self-Test

/// Request-local ownership from proxy establishment through authenticated
/// inner TLS. Cancellation never releases a pool slot speculatively: its
/// callback follows the transport's own cancellation completion. In
/// particular a shared mux carrier cannot be canceled for one DNS caller.
final class DNSRoutedTLSConnectionAttempt {
    typealias ResultType = Result<any NativeOutboundByteStream, Error>
    typealias Connect = (@escaping (ResultType) -> Void) -> (() -> Void)?
    typealias Upgrade = (any NativeOutboundByteStream, @escaping (Error) -> Void,
                        @escaping (ResultType) -> Void) -> (() -> Void)?
    /// Callback admission and explicit cancellation share one receipt. Queue
    /// congestion must not relabel an already observed failure as a cancel.
    private final class Receipt {
        private enum Terminal { case success, failure(Error) }
        private let lock = NSLock()
        private var cancelled = false
        private var terminals: [NetworkPerformanceStage: Terminal] = [:]
        func failure(_ error: Error, stage: NetworkPerformanceStage) {
            lock.lock(); defer { lock.unlock() }
            // Retaining the original value does not bridge to NSError. This
            // receipt must never delay the pre-existing security error sink.
            if !cancelled, terminals[stage] == nil { terminals[stage] = .failure(error) }
        }
        func success(_ stage: NetworkPerformanceStage) {
            lock.lock(); defer { lock.unlock() }
            if terminals[stage] == nil { terminals[stage] = .success }
        }
        func cancel() { lock.lock(); cancelled = true; lock.unlock() }
        var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
        func failed(_ stage: NetworkPerformanceStage) -> Bool {
            lock.lock(); let terminal = terminals[stage]; lock.unlock()
            guard case .failure(let error) = terminal else { return false }
            let reason = EncryptedDNSQueryFailure.classify(error)
            return reason != .cancelled && reason != .policy
        }
    }
    private enum Phase { case waiting, connecting, upgrading, finished }
    private let queue: DispatchQueue
    private let permitted: () -> Bool
    private let connect: Connect
    private let upgrade: Upgrade
    private let diagnostics: NetworkPerformanceDiagnostics
    private let failureObserver: ((Error) -> Void)?
    private let attemptTrace: DNSConnectionAttemptTrace?
    private let receipt = Receipt()
    private var completion: ((ResultType) -> Void)?
    private var phase = Phase.waiting
    private var cancelled = false
    private var cancellation: (() -> Void)?
    private var raw: (any NativeOutboundByteStream)?
    private var connectionStarted: UInt64?
    private var tlsStarted: UInt64?

    init(queue: DispatchQueue, permitted: @escaping () -> Bool,
         connect: @escaping Connect, upgrade: @escaping Upgrade,
         diagnostics: NetworkPerformanceDiagnostics = .shared,
         failureObserver: ((Error) -> Void)? = nil,
         attemptTrace: DNSConnectionAttemptTrace? = nil,
         completion: @escaping (ResultType) -> Void) {
        self.queue = DispatchQueue(label: "app.hajimi.dns.routed-tls-dial", target: queue)
        self.permitted = permitted; self.connect = connect; self.upgrade = upgrade
        self.diagnostics = diagnostics; self.completion = completion
        self.failureObserver = failureObserver
        self.attemptTrace = attemptTrace
    }

    func start() {
        queue.async {
            guard self.phase == .waiting else { return }
            if self.receipt.isCancelled { self.cancelled = true }
            guard !self.cancelled, self.permitted() else { self.finish(.failure(self.unavailable)); return }
            self.phase = .connecting
            self.connectionStarted = NetworkPerformanceDiagnostics.now()
            self.attemptTrace?.record(.transportStarted)
            self.cancellation = self.connect { result in
                if case .failure(let error) = result {
                    self.observeFailure(error, stage: .dnsUpstreamConnection, event: .transportFailure)
                } else {
                    self.receipt.success(.dnsUpstreamConnection)
                    self.attemptTrace?.record(.transportReady)
                }
                self.queue.async { self.connected(result) }
            }
        }
    }

    func cancel() {
        receipt.cancel()
        queue.async {
            guard self.phase != .finished, !self.cancelled else { return }
            self.cancelled = true
            self.cancellation?()
            if self.phase == .waiting {
                self.finish(.failure(self.unavailable))
                return
            }
            // If a legacy/mux establishment cannot be canceled immediately, wait
            // briefly for its callback, then force-finish after 2.5s so pendingDials
            // in EncryptedDNSConnectionStore can never be permanently wedged.
            self.queue.asyncAfter(deadline: .now() + 2.5) { [weak self] in
                guard let self, self.phase != .finished else { return }
                if let started = self.connectionStarted {
                    self.connectionStarted = nil
                    self.record(.dnsUpstreamConnection, started: started, result: .failure(self.unavailable), allowed: false)
                }
                if let started = self.tlsStarted {
                    self.tlsStarted = nil
                    self.record(.dnsTLSHandshake, started: started, result: .failure(self.unavailable), allowed: false)
                }
                self.finish(.failure(self.unavailable))
            }
        }
    }

    private var unavailable: Error {
        cancelled ? EncryptedDNSQueryFailure.cancelled : EncryptedDNSQueryFailure.policy
    }

    private func connected(_ result: ResultType) {
        guard phase == .connecting else {
            if case .success(let stream) = result { stream.cancel() }
            return
        }
        cancellation = nil
        let allowed = !cancelled && permitted()
        if let started = connectionStarted {
            connectionStarted = nil
            record(.dnsUpstreamConnection, started: started, result: result, allowed: allowed)
        }
        guard allowed else {
            if case .success(let stream) = result { stream.cancel() }
            finish(.failure(unavailable)); return
        }
        switch result {
        case .failure(let error): finish(.failure(error))
        case .success(let stream):
            raw = stream; phase = .upgrading
            tlsStarted = NetworkPerformanceDiagnostics.now()
            attemptTrace?.record(.tlsStarted)
            cancellation = upgrade(stream, { error in
                self.receipt.failure(error, stage: .dnsTLSHandshake)
                self.failureObserver?(error)
            }) { result in
                if case .failure(let error) = result {
                    self.observeFailure(error, stage: .dnsTLSHandshake, event: .tlsFailure)
                } else { self.receipt.success(.dnsTLSHandshake) }
                self.queue.async { self.upgraded(result) }
            }
        }
    }

    private func upgraded(_ result: ResultType) {
        guard phase == .upgrading else {
            if case .success(let stream) = result { stream.cancel() }
            return
        }
        cancellation = nil
        let allowed = !cancelled && permitted()
        if let started = tlsStarted {
            tlsStarted = nil
            record(.dnsTLSHandshake, started: started, result: result, allowed: allowed)
        }
        guard allowed else {
            if case .success(let stream) = result { stream.cancel() }
            finish(.failure(unavailable)); return
        }
        finish(result)
    }

    private func record(_ stage: NetworkPerformanceStage, started: UInt64,
                        result: ResultType, allowed: Bool) {
        let outcome: NetworkPerformanceOutcome
        if receipt.failed(stage) { outcome = .failure }
        else if !allowed { outcome = .cancelled }
        else if case .success = result { outcome = .success }
        else if case .failure(let error) = result,
                [.cancelled, .policy].contains(EncryptedDNSQueryFailure.classify(error)) { outcome = .cancelled }
        else { outcome = .failure }
        // Only the real phase callback acknowledges completion. A cancel
        // request must not invent a completed handshake, release admission or
        // count another logical DNS question. No endpoint/error text is kept.
        diagnostics.record(stage,
            milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started), outcome: outcome)
        attemptTrace?.complete(stage, outcome: outcome)
    }

    private func observeFailure(_ error: Error, stage: NetworkPerformanceStage,
                                event: DNSConnectionAttemptEvent) {
        let admit = {
            self.receipt.failure(error, stage: stage)
            self.failureObserver?(error)
        }
        if let attemptTrace { attemptTrace.record(event, error: error, admitting: admit) }
        else { admit() }
    }

    private func finish(_ result: ResultType) {
        guard let done = completion else {
            if case .success(let stream) = result { stream.cancel() }
            return
        }
        completion = nil; phase = .finished; cancellation = nil
        if case .failure = result { raw?.cancel() }
        raw = nil
        done(result)
    }
}

private extension DNSRoutedTLSConnectionAttempt {
    /// A test barrier only: it does not start or cancel a transport.
    func drainQueueForSelfTest() { queue.sync {} }
}

/// In-memory ownership checks for the proxy-to-inner-TLS handoff. Every fake
/// transport calls its completion once, matching the native API contract.
enum DNSRoutedTLSConnectionAttemptSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS 路由 TLS 建连自检失败：\(text)" }
    }
    private final class Stream: NativeOutboundByteStream {
        private let lock = NSLock()
        private var closes = 0
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            completion(nil, false, nil)
        }
        func cancel() { lock.lock(); closes += 1; lock.unlock() }
        var cancellations: Int { lock.lock(); defer { lock.unlock() }; return closes }
    }
    private final class Gate {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }
    private final class SlowBridgeError: CustomNSError {
        let conversionEntered = DispatchSemaphore(value: 0)
        let releaseConversion = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var observed = false, converting = false, observerWasFirst = false
        static var errorDomain: String { NSOSStatusErrorDomain }
        var errorCode: Int { -9807 }
        var errorUserInfo: [String: Any] {
            lock.lock()
            let first = !converting
            if first { converting = true; observerWasFirst = observed }
            lock.unlock()
            if first {
                conversionEntered.signal()
                _ = releaseConversion.wait(timeout: .now() + 5)
            }
            return [NSLocalizedDescriptionKey: "memory-only private routed error"]
        }
        func failureObserved() { lock.lock(); observed = true; lock.unlock() }
        var observerPrecededConversion: Bool {
            lock.lock(); defer { lock.unlock() }; return observerWasFirst
        }
    }
    private final class Probe {
        typealias ResultType = DNSRoutedTLSConnectionAttempt.ResultType
        let diagnostics = NetworkPerformanceDiagnostics(maximumSamples: 4)
        let connected = DispatchSemaphore(value: 0), upgrading = DispatchSemaphore(value: 0)
        let cancelled = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private let uncancelable: Bool
        private var connectCallback: ((ResultType) -> Void)?
        private var upgradeCallback: ((ResultType) -> Void)?
        private var upgradeFailureObserver: ((Error) -> Void)?
        private var connects = 0, upgrades = 0, connectCancels = 0, upgradeCancels = 0
        private var values: [ResultType] = []
        init(uncancelable: Bool = false) { self.uncancelable = uncancelable }
        func connect(_ callback: @escaping (ResultType) -> Void) -> (() -> Void)? {
            lock.lock(); connects += 1; connectCallback = callback; lock.unlock()
            connected.signal()
            if uncancelable { return nil }
            return {
                self.lock.lock(); self.connectCancels += 1; self.lock.unlock()
                // Teardown has been requested, but this fixture deliberately
                // withholds its callback acknowledgement until the test does.
                self.cancelled.signal()
            }
        }
        func upgrade(_ stream: any NativeOutboundByteStream,
                     _ callback: @escaping (ResultType) -> Void,
                     failureObserver: ((Error) -> Void)? = nil) -> (() -> Void)? {
            lock.lock(); upgrades += 1; upgradeCallback = callback
            upgradeFailureObserver = failureObserver; lock.unlock()
            upgrading.signal()
            return {
                self.lock.lock(); self.upgradeCancels += 1; self.lock.unlock()
                self.cancelled.signal()
            }
        }
        func completed(_ value: ResultType) {
            lock.lock(); values.append(value); lock.unlock(); done.signal()
        }
        func deliverConnect(_ value: ResultType) {
            lock.lock(); let callback = connectCallback; connectCallback = nil; lock.unlock()
            callback?(value)
        }
        func deliverUpgrade(_ value: ResultType) {
            lock.lock(); let callback = upgradeCallback; upgradeCallback = nil
            upgradeFailureObserver = nil; lock.unlock()
            callback?(value)
        }
        func observeUpgradeFailure(_ error: Error) {
            lock.lock(); let observer = upgradeFailureObserver; lock.unlock()
            observer?(error)
        }
        var connectCallbackForSelfTest: ((ResultType) -> Void)? {
            lock.lock(); defer { lock.unlock() }; return connectCallback
        }
        var upgradeCallbackForSelfTest: ((ResultType) -> Void)? {
            lock.lock(); defer { lock.unlock() }; return upgradeCallback
        }
        var snapshot: (connects: Int, upgrades: Int, connectCancels: Int,
                       upgradeCancels: Int, values: [ResultType]) {
            lock.lock(); defer { lock.unlock() }
            return (connects, upgrades, connectCancels, upgradeCancels, values)
        }
    }
    private static func expect(_ condition: Bool, _ text: String) throws {
        guard condition else { throw Failure(text: text) }
    }
    private static func wait(_ semaphore: DispatchSemaphore, _ text: String) throws {
        try expect(semaphore.wait(timeout: .now() + 2) == .success, text)
    }
    private static func failedOnce(_ probe: Probe) -> Bool {
        let values = probe.snapshot.values
        guard values.count == 1 else { return false }
        if case .failure = values[0] { return true }; return false
    }
    private static func stage(_ probe: Probe, _ stage: NetworkPerformanceStage) -> NetworkStageSnapshot {
        probe.diagnostics.snapshot().stages[stage] ?? NetworkStageSnapshot()
    }

    /// Hold a native failure after its receipt and before its operation-queue
    /// callback. A later cancel/epoch revoke must still reject delivery, while
    /// retaining the failure that actually arrived first for diagnostics.
    private static func terminalFailureReceipts() throws {
        let queue = DispatchQueue(label: "app.hajimi.dns.routed-tls-receipt-self-test")
        for rawStage in [true, false] {
            for epochRevocation in [false, true] {
                let probe = Probe(), gate = Gate()
                let observed = DispatchSemaphore(value: 0), releaseObserver = DispatchSemaphore(value: 0)
                let operation = DNSRoutedTLSConnectionAttempt(queue: queue, permitted: gate.permits,
                    connect: probe.connect, upgrade: { stream, _, ready in probe.upgrade(stream, ready) },
                    diagnostics: probe.diagnostics, failureObserver: { _ in
                        observed.signal()
                        _ = releaseObserver.wait(timeout: .now() + 2)
                    }, completion: probe.completed)
                operation.start()
                try wait(probe.connected, "receipt 场景未开始 raw 建连")
                if !rawStage {
                    probe.deliverConnect(.success(Stream()))
                    try wait(probe.upgrading, "receipt 场景未开始 inner TLS")
                }
                DispatchQueue.global().async {
                    let error: Error = rawStage ? NWError.posix(.ECONNRESET) : NWError.tls(-9807)
                    if rawStage { probe.deliverConnect(.failure(error)) }
                    else { probe.deliverUpgrade(.failure(error)) }
                }
                defer { releaseObserver.signal() }
                try wait(observed, "receipt 场景未收到原生失败")
                if epochRevocation { gate.revoke() }
                else {
                    operation.cancel()
                    try wait(probe.cancelled, "receipt 后取消未交给原生 transport")
                }
                releaseObserver.signal()
                try wait(probe.done, "receipt 后终止未完成")
                operation.drainQueueForSelfTest()
                let measured = stage(probe, rawStage ? .dnsUpstreamConnection : .dnsTLSHandshake)
                try expect(measured.count == 1 && measured.failureCount == 1
                           && measured.cancellationCount == 0 && measured.sampleCount == 0,
                           "已接收的真实 raw/TLS 失败被迟到取消或 epoch 撤销掩盖")
                let values = probe.snapshot.values
                var refusedDelivery = false
                if values.count == 1, case .failure(let error) = values[0] {
                    refusedDelivery = EncryptedDNSQueryFailure.classify(error)
                        == (epochRevocation ? .policy : .cancelled)
                }
                try expect(refusedDelivery, "诊断保留真实失败时放行了已取消或旧 epoch 的结果")
                if rawStage {
                    try expect(probe.snapshot.upgrades == 0 && stage(probe, .dnsTLSHandshake).count == 0,
                               "raw 失败后仍执行 TLS 或产生伪阶段")
                } else {
                    try expect(stage(probe, .dnsUpstreamConnection).sampleCount == 1,
                               "TLS receipt 覆盖了已完成 raw 阶段")
                }
            }
            do {
                let probe = Probe(), operation = DNSRoutedTLSConnectionAttempt(queue: queue,
                    permitted: { true }, connect: probe.connect,
                    upgrade: { stream, _, ready in probe.upgrade(stream, ready) },
                    diagnostics: probe.diagnostics, completion: probe.completed)
                operation.start()
                try wait(probe.connected, "取消优先 receipt 场景未开始")
                if !rawStage {
                    probe.deliverConnect(.success(Stream()))
                    try wait(probe.upgrading, "取消优先 receipt 场景未开始 TLS")
                }
                operation.cancel()
                try wait(probe.cancelled, "取消优先 receipt 未先取消原生 transport")
                let error: Error = rawStage ? NWError.posix(.ECONNRESET) : NWError.tls(-9807)
                if rawStage { probe.deliverConnect(.failure(error)) }
                else { probe.deliverUpgrade(.failure(error)) }
                try wait(probe.done, "取消优先 receipt 未等待回调结束")
                operation.drainQueueForSelfTest()
                let measured = stage(probe, rawStage ? .dnsUpstreamConnection : .dnsTLSHandshake)
                try expect(failedOnce(probe) && measured.count == 1 && measured.failureCount == 0
                           && measured.cancellationCount == 1 && measured.sampleCount == 0,
                           "取消后的 raw/TLS teardown 失败被误罚为网络故障")
            }
        }
        // Native TLS can admit failure metadata before its eventual callback
        // reports cancellation. Exercise that separate three-argument API.
        for epochRevocation in [false, true] {
            let probe = Probe(), gate = Gate()
            let operation = DNSRoutedTLSConnectionAttempt(queue: queue, permitted: gate.permits,
                connect: probe.connect, upgrade: { stream, observer, ready in
                    probe.upgrade(stream, ready, failureObserver: observer)
                }, diagnostics: probe.diagnostics, completion: probe.completed)
            operation.start()
            try wait(probe.connected, "TLS metadata receipt 场景未开始 raw")
            probe.deliverConnect(.success(Stream()))
            try wait(probe.upgrading, "TLS metadata receipt 场景未开始 TLS")
            probe.observeUpgradeFailure(NWError.tls(-9807))
            if epochRevocation { gate.revoke() }
            else {
                operation.cancel()
                try wait(probe.cancelled, "TLS metadata receipt 后未取消 transport")
            }
            probe.deliverUpgrade(.failure(EncryptedDNSQueryFailure.cancelled))
            try wait(probe.done, "TLS metadata receipt 未等到最终 ACK")
            operation.drainQueueForSelfTest()
            let measured = stage(probe, .dnsTLSHandshake)
            try expect(failedOnce(probe) && measured.count == 1 && measured.failureCount == 1
                       && measured.cancellationCount == 0 && measured.sampleCount == 0,
                       "已接收的 TLS metadata 失败被最终 cancellation ACK 覆盖")
        }
        print("DNS routed-TLS receipt checks passed: raw/TLS failure before cancel or epoch revoke, cancellation before failure, native TLS metadata before cancellation ACK, exact-once termination and revoked-result refusal")
    }

    /// Run the complete routed wrapper, including its real diagnostic trace.
    /// An Error -> NSError bridge may execute arbitrary userInfo code; it must
    /// follow security admission and hold neither receipt nor diagnostics lock.
    private static func slowFailureBridging() throws {
        let queue = DispatchQueue(label: "app.hajimi.dns.routed-tls-slow-error-self-test")
        for rawStage in [true, false] {
            let probe = Probe(), error = SlowBridgeError()
            let trace = probe.diagnostics.beginDNSAttempt(requestID: UUID(), transport: .doh, purpose: .query,
                serverName: "routed-receipt.selftest.invalid",
                endpointIdentity: "https://routed-receipt.selftest.invalid/dns-query", address: "203.0.113.53")
            let operation = DNSRoutedTLSConnectionAttempt(queue: queue, permitted: { true },
                connect: probe.connect, upgrade: { stream, _, ready in probe.upgrade(stream, ready) },
                diagnostics: probe.diagnostics, failureObserver: { _ in error.failureObserved() },
                attemptTrace: trace, completion: probe.completed)
            operation.start()
            try wait(probe.connected, "慢桥接场景未开始 raw 建连")
            if !rawStage {
                probe.deliverConnect(.success(Stream()))
                try wait(probe.upgrading, "慢桥接场景未进入 inner TLS")
            }
            DispatchQueue.global().async {
                if rawStage { probe.deliverConnect(.failure(error)) }
                else { probe.deliverUpgrade(.failure(error)) }
            }
            defer { error.releaseConversion.signal() }
            try wait(error.conversionEntered, "慢桥接场景未进入真实 Error→NSError 转换")
            let cancelReturned = DispatchSemaphore(value: 0)
            DispatchQueue.global().async {
                trace.cancel(.callerCancelled)
                operation.cancel()
                cancelReturned.signal()
            }
            let returnedWhileBlocked = cancelReturned.wait(timeout: .now() + 1) == .success
            let pendingBeforeRelease = probe.snapshot.values.isEmpty
            error.releaseConversion.signal()
            if !returnedWhileBlocked { try wait(cancelReturned, "慢桥接释放后取消仍无法返回") }
            try wait(probe.cancelled, "慢桥接期间取消未交给原生 transport")
            try wait(probe.done, "慢桥接释放后未完成真实回调")
            operation.drainQueueForSelfTest()
            try expect(error.observerPrecededConversion,
                       "诊断转换 Error→NSError 早于原安全 failureObserver")
            try expect(returnedWhileBlocked && pendingBeforeRelease,
                       "慢桥接持有 receipt/诊断锁阻塞 cancel，或提前释放真实回调所有权")
            let measured = stage(probe, rawStage ? .dnsUpstreamConnection : .dnsTLSHandshake)
            try expect(measured.count == 1 && measured.failureCount == 1
                       && measured.cancellationCount == 0 && measured.sampleCount == 0,
                       "先到的慢桥接原生失败被取消覆盖或重复计量")
            let values = probe.snapshot.values
            var refusedDelivery = false
            if values.count == 1, case .failure(let resultError) = values[0] {
                refusedDelivery = EncryptedDNSQueryFailure.classify(resultError) == .cancelled
            }
            try expect(refusedDelivery, "慢桥接诊断保留失败时交付了已取消的结果")
            guard let attempt = probe.diagnostics.snapshot().dnsConnectionAttempts.first,
                  let failed = attempt.observations.first(where: {
                      $0.event == (rawStage ? .transportFailure : .tlsFailure)
                  }), let cancelled = attempt.firstCancellationRequest else {
                throw Failure(text: "慢桥接场景缺少真实 trace 失败/取消记录")
            }
            try expect(failed.sequence < cancelled.sequence
                       && (rawStage ? attempt.transportOutcome : attempt.tlsOutcome) == .failure,
                       "慢桥接改变了原生失败与取消的 trace 先后或阶段结果")
        }
        print("DNS routed-TLS slow error bridging checks passed: security observer first, cancel returns during blocked NSError conversion, real failure retained and canceled delivery refused")
    }

    static func run() throws {
        try terminalFailureReceipts()
        try slowFailureBridging()
        let queue = DispatchQueue(label: "app.hajimi.dns.routed-tls-ownership-self-test")
        func make(_ probe: Probe, _ gate: Gate = Gate()) -> DNSRoutedTLSConnectionAttempt {
            DNSRoutedTLSConnectionAttempt(queue: queue, permitted: gate.permits,
                connect: probe.connect, upgrade: { stream, _, ready in probe.upgrade(stream, ready) },
                diagnostics: probe.diagnostics, completion: probe.completed)
        }
        do {
            let probe = Probe(), operation = make(probe)
            operation.cancel(); operation.start()
            try wait(probe.done, "尚未开始的建连取消没有完成")
            operation.drainQueueForSelfTest()
            try expect(probe.snapshot.connects == 0 && probe.snapshot.upgrades == 0 && failedOnce(probe),
                       "尚未开始的取消仍拨号或重复完成")
            try expect(probe.diagnostics.snapshot().stages.isEmpty, "未开始的建连取消产生伪阶段样本")
        }
        do {
            let probe = Probe(), operation = make(probe), lateRaw = Stream()
            operation.start(); try wait(probe.connected, "可取消 proxy 建连未开始")
            operation.cancel(); try wait(probe.cancelled, "proxy 建连取消未交给 transport")
            operation.drainQueueForSelfTest()
            try expect(probe.snapshot.values.isEmpty && probe.snapshot.connectCancels == 1,
                       "proxy transport 未回调 ACK 前释放了 DNS 建连")
            try expect(probe.diagnostics.snapshot().stages.isEmpty, "raw 取消 ACK 前提前结束阶段计量")
            probe.deliverConnect(.success(lateRaw)); try wait(probe.done, "迟到 proxy 回调未完成取消")
            operation.cancel(); operation.drainQueueForSelfTest()
            try expect(lateRaw.cancellations == 1 && probe.snapshot.upgrades == 0
                       && probe.snapshot.connectCancels == 1 && failedOnce(probe),
                       "已取消的 proxy 流泄漏、继续升级或重复关闭")
            let value = stage(probe, .dnsUpstreamConnection)
            try expect(value.count == 1 && value.cancellationCount == 1 && value.failureCount == 0
                       && value.sampleCount == 0 && stage(probe, .dnsTLSHandshake).count == 0,
                       "raw 取消被计为网络失败或不存在的 TLS 阶段")
        }
        do {
            let probe = Probe(uncancelable: true), operation = make(probe), lateLogical = Stream()
            operation.start(); try wait(probe.connected, "不可独立取消的 mux/open 未开始")
            operation.cancel(); operation.drainQueueForSelfTest()
            try expect(probe.snapshot.values.isEmpty && probe.snapshot.connectCancels == 0,
                       "单 DNS 取消触碰共享 carrier 或提前释放不可取消建连")
            probe.deliverConnect(.success(lateLogical)); try wait(probe.done, "迟到 mux/open 未完成取消")
            operation.drainQueueForSelfTest()
            try expect(lateLogical.cancellations == 1 && probe.snapshot.upgrades == 0 && failedOnce(probe),
                       "迟到 mux 逻辑流未关闭或继续做 TLS")
            try expect(stage(probe, .dnsUpstreamConnection).cancellationCount == 1
                       && stage(probe, .dnsTLSHandshake).count == 0,
                       "不可取消 mux 的真实迟到回调缺失取消计量")
        }
        do {
            let probe = Probe(), operation = make(probe), raw = Stream(), lateTLS = Stream()
            operation.start(); try wait(probe.connected, "proxy-to-TLS 建连未开始")
            probe.deliverConnect(.success(raw)); try wait(probe.upgrading, "proxy 流未交给 TLS")
            operation.cancel(); try wait(probe.cancelled, "TLS 取消未交给 upgrader")
            operation.drainQueueForSelfTest()
            try expect(probe.snapshot.values.isEmpty && probe.snapshot.upgradeCancels == 1
                       && probe.snapshot.connectCancels == 0,
                       "TLS ACK 前提前完成或取消到已交付的 proxy 流")
            try expect(stage(probe, .dnsUpstreamConnection).sampleCount == 1
                       && stage(probe, .dnsTLSHandshake).count == 0,
                       "TLS 尚未 ACK 就产生完成或失败样本")
            probe.deliverUpgrade(.success(lateTLS)); try wait(probe.done, "迟到 TLS 回调未完成取消")
            operation.cancel(); operation.drainQueueForSelfTest()
            try expect(lateTLS.cancellations == 1 && raw.cancellations == 1
                       && probe.snapshot.upgradeCancels == 1 && failedOnce(probe),
                       "迟到 TLS 流泄漏、重复关闭或完成多次")
            let value = stage(probe, .dnsTLSHandshake)
            try expect(value.count == 1 && value.cancellationCount == 1 && value.failureCount == 0
                       && value.sampleCount == 0, "TLS 取消 ACK 被当作握手失败或成功样本")
        }
        do {
            let probe = Probe(), operation = make(probe), raw = Stream(), winner = Stream()
            operation.start(); try wait(probe.connected, "成功场景的 proxy 未开始")
            probe.deliverConnect(.success(raw)); try wait(probe.upgrading, "成功场景未升级 TLS")
            probe.deliverUpgrade(.success(winner)); try wait(probe.done, "TLS 成功没有交付")
            operation.cancel(); operation.drainQueueForSelfTest()
            let state = probe.snapshot
            var correctWinner = false
            if state.values.count == 1, case .success(let delivered) = state.values[0] {
                correctWinner = (delivered as AnyObject) === winner
            }
            try expect(correctWinner && raw.cancellations == 0 && winner.cancellations == 0
                       && state.connectCancels == 0 && state.upgradeCancels == 0,
                       "交付后的旧取消 action 撤销了 winner 或其已完成下层")
            for measured in [NetworkPerformanceStage.dnsUpstreamConnection, .dnsTLSHandshake] {
                let value = stage(probe, measured)
                try expect(value.count == 1 && value.sampleCount == 1 && value.failureCount == 0
                           && value.cancellationCount == 0, "成功阶段缺少样本或被旧 cancel 重复结束")
            }
            try expect(probe.diagnostics.snapshot().dnsQueries == 0 && probe.diagnostics.snapshot().dnsFailures == 0,
                       "阶段计量重复统计了逻辑 DNS 问题")
        }
        do {
            let probe = Probe(), gate = Gate(), operation = make(probe, gate), raw = Stream()
            operation.start(); try wait(probe.connected, "handoff 撤销场景未开始")
            gate.revoke(); probe.deliverConnect(.success(raw)); try wait(probe.done, "handoff 撤销未完成")
            operation.drainQueueForSelfTest()
            try expect(raw.cancellations == 1 && probe.snapshot.upgrades == 0 && failedOnce(probe),
                       "策略/接口撤销后的 proxy 流仍升级或未关闭")
            try expect(stage(probe, .dnsUpstreamConnection).cancellationCount == 1
                       && stage(probe, .dnsTLSHandshake).count == 0,
                       "raw handoff 策略撤销被计成成功或网络失败")
        }
        do {
            let probe = Probe(), gate = Gate(), operation = make(probe, gate)
            let raw = Stream(), secured = Stream()
            operation.start(); try wait(probe.connected, "TLS 中撤销场景未开始")
            probe.deliverConnect(.success(raw)); try wait(probe.upgrading, "撤销场景没有进入 TLS")
            gate.revoke(); probe.deliverUpgrade(.success(secured)); try wait(probe.done, "TLS 中撤销未完成")
            operation.drainQueueForSelfTest()
            try expect(raw.cancellations == 1 && secured.cancellations == 1 && failedOnce(probe),
                       "TLS 完成时旧策略/接口仍交付流或漏关下层")
            try expect(stage(probe, .dnsUpstreamConnection).sampleCount == 1
                       && stage(probe, .dnsTLSHandshake).cancellationCount == 1,
                       "TLS 策略撤销丢失已完成 raw 阶段或被计为握手成功")
        }
        do {
            let probe = Probe(), operation = make(probe), raw = Stream()
            operation.start(); try wait(probe.connected, "证书失败场景未开始")
            probe.deliverConnect(.success(raw)); try wait(probe.upgrading, "证书失败场景未升级")
            probe.deliverUpgrade(.failure(Failure(text: "injected certificate rejection")))
            try wait(probe.done, "TLS 身份拒绝未完成")
            operation.cancel(); operation.drainQueueForSelfTest()
            try expect(raw.cancellations == 1 && probe.snapshot.upgradeCancels == 0 && failedOnce(probe),
                       "证书拒绝后泄漏 proxy 流或重复操作已完成 handshake")
            let value = stage(probe, .dnsTLSHandshake)
            try expect(stage(probe, .dnsUpstreamConnection).sampleCount == 1 && value.count == 1
                       && value.failureCount == 1 && value.cancellationCount == 0 && value.sampleCount == 0,
                       "TLS 身份拒绝未单独计为失败或污染成功延迟分位数")
        }
        do {
            let probe = Probe(), operation = make(probe)
            operation.start(); try wait(probe.connected, "raw 失败场景未开始")
            probe.deliverConnect(.failure(Failure(text: "memory raw failure")))
            try wait(probe.done, "raw 失败场景未完成")
            operation.drainQueueForSelfTest()
            let value = stage(probe, .dnsUpstreamConnection)
            try expect(failedOnce(probe) && value.count == 1 && value.failureCount == 1
                       && value.cancellationCount == 0 && stage(probe, .dnsTLSHandshake).count == 0,
                       "raw 失败被错误归为 TLS 或产生重复阶段")
        }
        do {
            let probe = Probe(), operation = make(probe), raw = Stream(), secured = Stream()
            operation.start(); try wait(probe.connected, "重复回调场景未开始")
            let duplicateRaw = probe.connectCallbackForSelfTest
            probe.deliverConnect(.success(raw)); try wait(probe.upgrading, "重复回调场景未升级")
            duplicateRaw?(.failure(Failure(text: "duplicate raw callback")))
            operation.drainQueueForSelfTest()
            let duplicateTLS = probe.upgradeCallbackForSelfTest
            probe.deliverUpgrade(.success(secured)); try wait(probe.done, "重复回调场景未完成")
            duplicateTLS?(.failure(Failure(text: "duplicate TLS callback")))
            operation.drainQueueForSelfTest()
            try expect(probe.snapshot.values.count == 1 && raw.cancellations == 0 && secured.cancellations == 0,
                       "迟到失败回调撤销了已交付流")
            for measured in [NetworkPerformanceStage.dnsUpstreamConnection, .dnsTLSHandshake] {
                let value = stage(probe, measured)
                try expect(value.count == 1 && value.sampleCount == 1 && value.failureCount == 0,
                           "重复 phase 回调被计量多次或覆盖成功")
            }
        }
    }
}

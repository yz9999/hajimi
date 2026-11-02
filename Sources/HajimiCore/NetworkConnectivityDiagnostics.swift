import Foundation
import HajimiDNS

public enum NetworkConnectivityDiagnosticKind: String, Codable, Equatable {
    case localLatency, proxyLatency, traditionalDNS, encryptedDNS, proxyDNS
}

public enum NetworkConnectivityDiagnosticStatus: String, Codable, Equatable {
    case queued, running, success, failure, skipped, cancelled
}

/// One explicit, bounded connectivity check. Endpoint labels contain no URL
/// path/query, credentials, resolved answer addresses or arbitrary error text.
public struct NetworkConnectivityDiagnosticResult: Codable, Equatable {
    public let id: String
    public let kind: NetworkConnectivityDiagnosticKind
    public let title: String
    public let endpoint: String
    public let route: String
    public var status: NetworkConnectivityDiagnosticStatus
    public var milliseconds: Double?
    public var responseCode: Int?
    public var extendedDNSErrorCodes: [UInt16]?
    public var errorDomain: String?
    public var errorCode: Int?
    public var detail: String

    init(id: String, kind: NetworkConnectivityDiagnosticKind, title: String,
         endpoint: String, route: String, status: NetworkConnectivityDiagnosticStatus = .queued,
         detail: String = "等待本轮测试") {
        self.id = id; self.kind = kind; self.title = title
        self.endpoint = endpoint; self.route = route; self.status = status; self.detail = detail
    }
}

public struct NetworkConnectivityDiagnosticsSnapshot: Codable, Equatable {
    public let id: UUID
    public let startedAt: Date
    public let updatedAt: Date
    public let isRunning: Bool
    public let rows: [NetworkConnectivityDiagnosticResult]
    public let omittedEndpointCount: Int
}

struct NetworkConnectivityDiagnosticMeasurement {
    var status: NetworkConnectivityDiagnosticStatus
    var responseCode: Int?
    var extendedDNSErrorCodes: [UInt16]?
    var errorDomain: String?
    var errorCode: Int?
    var detail: String

    init(status: NetworkConnectivityDiagnosticStatus, detail: String,
         responseCode: Int? = nil, extendedDNSErrorCodes: [UInt16]? = nil,
         error: Error? = nil) {
        self.status = status; self.detail = detail; self.responseCode = responseCode
        self.extendedDNSErrorCodes = extendedDNSErrorCodes
        if let error, let first = DNSAttemptErrorSnapshot.capture(error).codes.first {
            errorDomain = first.domain; errorCode = first.code
        }
    }
}

/// The operation must install cancellation before owning resources and close
/// late streams itself. A cancellation callback is never a second result.
struct NetworkConnectivityDiagnosticTask {
    typealias Operation = (DispatchQueue, TimeInterval,
        @escaping (NetworkConnectivityDiagnosticMeasurement) -> Void) -> (() -> Void)?
    let row: NetworkConnectivityDiagnosticResult
    let timeout: TimeInterval
    /// Only an admitted request's original deadline may read this evidence.
    /// Queue expiry and cancellation must not inherit an unrelated path error.
    let deadlineMeasurement: (() -> NetworkConnectivityDiagnosticMeasurement)?
    let operation: Operation?

    init(row: NetworkConnectivityDiagnosticResult, timeout: TimeInterval = 5,
         deadlineMeasurement: (() -> NetworkConnectivityDiagnosticMeasurement)? = nil,
         operation: Operation? = nil) {
        self.row = row; self.timeout = timeout
        self.deadlineMeasurement = deadlineMeasurement; self.operation = operation
    }
}

/// A manual round has at most two admitted jobs, in addition to the existing
/// process-wide scheduler limits. There is no automatic public-network timer.
/// The local timer only revokes work when the router or interface changes.
public final class NetworkConnectivityDiagnosticsSession {
    public let id = UUID()
    private let queue = DispatchQueue(label: "app.hajimi.network-diagnostics", qos: .utility)
    private let callbackQueue: DispatchQueue
    private let scheduler: ProbeScheduler
    private let tasks: [NetworkConnectivityDiagnosticTask]
    private let isCurrent: () -> Bool
    private let onUpdate: (NetworkConnectivityDiagnosticsSnapshot) -> Void
    private let startedAt = Date()
    private let omittedEndpointCount: Int
    private let delivery = DeliveryGate()
    private var rows: [NetworkConnectivityDiagnosticResult]
    private var next = 0
    private var tickets: [Int: ProbeScheduler.Ticket] = [:]
    private var monitor: DispatchSourceTimer?
    private var ended = false

    private final class DeliveryGate {
        private let lock = NSLock()
        private var cancellationRequested = false
        private var sequence: UInt64 = 0
        var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancellationRequested }
        func cancel() { lock.lock(); cancellationRequested = true; sequence &+= 1; lock.unlock() }
        func advance() -> UInt64 { lock.lock(); defer { lock.unlock() }; sequence &+= 1; return sequence }
        func permits(_ value: UInt64, terminal: Bool) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return sequence == value && (!cancellationRequested || terminal)
        }
    }

    init(tasks: [NetworkConnectivityDiagnosticTask], omittedEndpointCount: Int = 0,
         scheduler: ProbeScheduler = .shared, callbackQueue: DispatchQueue,
         isCurrent: @escaping () -> Bool,
         onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) {
        self.tasks = tasks; rows = tasks.map(\.row); self.scheduler = scheduler
        self.callbackQueue = callbackQueue; self.isCurrent = isCurrent; self.onUpdate = onUpdate
        self.omittedEndpointCount = max(0, omittedEndpointCount)
        queue.async { [weak self] in self?.begin() }
    }

    deinit {
        delivery.cancel(); monitor?.cancel()
        tickets.values.forEach { $0.cancel() }
    }

    /// Synchronously revokes already-enqueued UI deliveries, then cancels all
    /// scheduler tickets and owned I/O on their original serial lanes.
    public func cancel() {
        delivery.cancel()
        queue.async { [weak self] in self?.cancelRound(detail: "本轮网络诊断已取消") }
    }

    private func begin() {
        guard !delivery.isCancelled else { cancelRound(detail: "本轮网络诊断已取消"); return }
        guard tasks.contains(where: { $0.operation != nil }) else { ended = true; publish(); return }
        guard isCurrent() else { cancelRound(detail: "配置或网络接口已变化，请重新测试"); return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250),
                       leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in
            guard let self, !self.ended else { return }
            if !self.isCurrent() {
                self.delivery.cancel()
                self.cancelRound(detail: "配置或网络接口已变化，请重新测试")
            }
        }
        monitor = timer; timer.resume()
        publish(); pump()
    }

    private func pump() {
        guard !ended, !delivery.isCancelled else { return }
        while tickets.count < 2, next < tasks.count {
            let index = next; next += 1
            let task = tasks[index]
            guard let operation = task.operation else { continue }
            let cleanup = NetworkConnectivityProbeCleanup()
            let ticket = scheduler.submit(timeout: task.timeout, queueWait: 3,
                callbackQueue: queue, start: { [weak self] lease in
                    guard lease.setCancellationHandler({ cleanup.cancel() }) else { return }
                    guard let self, self.isCurrent(), !self.delivery.isCancelled else {
                        if lease.complete() {
                            self?.queue.async { [weak self] in self?.finish(index,
                                measurement: .init(status: .cancelled, detail: "配置或网络接口已变化"),
                                started: nil) }
                        }
                        return
                    }
                    let started = cleanup.markStarted()
                    self.queue.async { [weak self] in
                        guard let self, !self.ended, self.rows[index].status == .queued else { return }
                        self.rows[index].status = .running; self.rows[index].detail = "正在测试"; self.publish()
                    }
                    let deadline = min(ProcessInfo.processInfo.systemUptime + task.timeout,
                        Double(lease.deadline.uptimeNanoseconds) / 1_000_000_000)
                    cleanup.install(operation(lease.queue, deadline) { [weak self] measurement in
                        guard lease.complete() else { return }
                        self?.queue.async { [weak self] in
                            guard let self, !self.ended else { return }
                            guard self.isCurrent(), !self.delivery.isCancelled else {
                                self.delivery.cancel(); self.cancelRound(detail: "配置或网络接口已变化，请重新测试"); return
                            }
                            self.finish(index, measurement: measurement, started: started)
                        }
                    })
                }, failure: { [weak self] failure in
                    guard let self, !self.ended else { return }
                    guard self.isCurrent(), !self.delivery.isCancelled else {
                        self.delivery.cancel()
                        self.cancelRound(detail: "配置或网络接口已变化，请重新测试")
                        return
                    }
                    let expired = failure == .requestExpired
                    let measurement = expired ? task.deadlineMeasurement?() : nil
                    self.finish(index, measurement: measurement ?? Self.schedulerFailure(failure),
                        started: expired ? cleanup.startedAt : nil)
                })
            tickets[index] = ticket
        }
        if tickets.isEmpty, next == tasks.count {
            ended = true; monitor?.cancel(); monitor = nil
        }
        publish()
    }

    private func finish(_ index: Int, measurement: NetworkConnectivityDiagnosticMeasurement, started: UInt64?) {
        if delivery.isCancelled { cancelRound(detail: "本轮网络诊断已取消"); return }
        guard !ended, tickets.removeValue(forKey: index) != nil else { return }
        rows[index].status = measurement.status; rows[index].detail = measurement.detail
        rows[index].responseCode = measurement.responseCode
        rows[index].extendedDNSErrorCodes = measurement.extendedDNSErrorCodes
        rows[index].errorDomain = measurement.errorDomain; rows[index].errorCode = measurement.errorCode
        rows[index].milliseconds = started.map { NetworkPerformanceDiagnostics.elapsedMilliseconds(since: $0) }
        pump()
    }

    private func cancelRound(detail: String) {
        guard !ended else { return }
        ended = true; monitor?.cancel(); monitor = nil
        let active = Array(tickets.values); tickets.removeAll()
        for index in rows.indices where rows[index].status == .queued || rows[index].status == .running {
            rows[index].status = .cancelled; rows[index].detail = detail
        }
        active.forEach { $0.cancel() }
        publish()
    }

    private func publish() {
        let snapshot = NetworkConnectivityDiagnosticsSnapshot(id: id, startedAt: startedAt,
            updatedAt: Date(), isRunning: !ended, rows: rows, omittedEndpointCount: omittedEndpointCount)
        let sequence = delivery.advance(), gate = delivery, callback = onUpdate
        callbackQueue.async {
            guard gate.permits(sequence, terminal: !snapshot.isRunning) else { return }
            callback(snapshot)
        }
    }

    private static func schedulerFailure(_ failure: ProbeScheduler.Failure) -> NetworkConnectivityDiagnosticMeasurement {
        let status: NetworkConnectivityDiagnosticStatus
        let detail: String
        switch failure {
        case .cancelled: status = .cancelled; detail = "网络诊断已取消"
        case .requestExpired: status = .failure; detail = "本项测试超时"
        case .capacityExceeded: status = .skipped; detail = "共享测试队列已满"
        case .connectionBudgetExceeded: status = .skipped; detail = "共享测试连接达到上限"
        case .queueWaitExpired: status = .skipped; detail = "共享测试排队超时"
        }
        return .init(status: status, detail: detail)
    }
}

/// Cancelling before an operation returns its handle must still cancel that
/// handle exactly once. No socket or resolver is released by dropping a ticket.
final class NetworkConnectivityProbeCleanup {
    private let lock = NSLock()
    private var ended = false
    private var handler: (() -> Void)?
    private var start: UInt64?
    func markStarted() -> UInt64 {
        let now = NetworkPerformanceDiagnostics.now()
        lock.lock(); start = now; lock.unlock()
        return now
    }
    var startedAt: UInt64? { lock.lock(); defer { lock.unlock() }; return start }
    func install(_ value: (() -> Void)?) {
        lock.lock()
        let cancelNow = ended
        if !cancelNow { handler = value }
        lock.unlock()
        if cancelNow { value?() }
    }
    func cancel() {
        lock.lock(); ended = true; let value = handler; handler = nil; lock.unlock()
        value?()
    }
}

/// A bounded numeric snapshot survives the scheduler/probe deadline race.
/// No raw error or userInfo is retained, and a recovered path clears evidence.
final class NetworkConnectivityDNSProbeEvidence {
    private let lock = NSLock()
    private let ipv6: Bool
    private var path: DNSAttemptErrorCode?

    init(ipv6: Bool) { self.ipv6 = ipv6 }

    func observePathError(_ error: Error?) {
        let code = error.flatMap { DNSAttemptErrorSnapshot.capture($0).codes.first }
        lock.lock(); path = code; lock.unlock()
    }

    func deadlineMeasurement() -> NetworkConnectivityDiagnosticMeasurement {
        lock.lock(); let code = path; lock.unlock()
        return NetworkConnectivityDNSProbeFailure.deadline(ipv6: ipv6, cause: code)
    }
}

enum NetworkConnectivityDNSProbeFailure {
    static func inspect(_ error: Error, ipv6: Bool) -> NetworkConnectivityDiagnosticMeasurement {
        if let deadline = error as? TraditionalDNSProbeDeadlineError {
            return self.deadline(ipv6: ipv6,
                cause: deadline.cause.flatMap { DNSAttemptErrorSnapshot.capture($0).codes.first })
        }
        let cause = DNSAttemptErrorSnapshot.capture(error).codes.first
        return measurement(ipv6: ipv6, timedOut: false, cause: cause)
    }

    static func deadline(ipv6: Bool, cause: DNSAttemptErrorCode?) -> NetworkConnectivityDiagnosticMeasurement {
        measurement(ipv6: ipv6, timedOut: true, cause: cause)
    }

    private static func measurement(ipv6: Bool, timedOut: Bool, cause: DNSAttemptErrorCode?)
        -> NetworkConnectivityDiagnosticMeasurement {
        let family = ipv6 ? "IPv6" : "IPv4"
        let prefix = timedOut ? "\(family) 直连 DNS 检测已到原截止时间" : "\(family) 直连 DNS 传输失败"
        var detail = prefix
        if cause?.domain == NSPOSIXErrorDomain, let code = cause?.code {
            switch code {
            case Int(POSIXErrorCode.EHOSTUNREACH.rawValue), Int(POSIXErrorCode.ENETUNREACH.rawValue):
                detail += "；当前直连网络路径不可达，不能据此判定 DNS 服务商故障"
            case Int(POSIXErrorCode.EADDRNOTAVAIL.rawValue):
                detail += "；当前直连路径没有可用的源地址"
            case Int(POSIXErrorCode.ENETDOWN.rawValue):
                detail += "；当前所选 \(family) 出口路径不可用，不代表物理网卡未启用"
            default: break
            }
        } else if cause == nil {
            detail += "；未取得匹配应答，不能仅凭超时区分本地路径与上游故障"
        }
        var result = NetworkConnectivityDiagnosticMeasurement(status: .failure, detail: detail)
        result.errorDomain = cause?.domain; result.errorCode = cause?.code
        return result
    }
}

/// Stream ownership is shared by logical cancellation and late dial replies.
/// HTTP status is validated, and only the fixed numeric response code escapes.
final class NetworkConnectivityHTTPExchange {
    private let queue: DispatchQueue
    private let host: String
    private let path: String
    private let completion: (NetworkConnectivityDiagnosticMeasurement) -> Void
    private let lock = NSLock()
    private var closed = false
    private var stream: (any NativeOutboundByteStream)?
    private var cancelConnect: (() -> Void)?
    private var pendingReservation: ProbeScheduler.ConnectionReservation?
    private var buffer = Data()
    private var reads = 0

    init(host: String, path: String, queue: DispatchQueue,
         completion: @escaping (NetworkConnectivityDiagnosticMeasurement) -> Void) {
        self.host = host; self.path = path; self.queue = queue; self.completion = completion
    }

    func installCancellation(_ cancel: (() -> Void)?) {
        lock.lock(); let cancelNow = closed
        if !cancelNow { cancelConnect = cancel }
        lock.unlock()
        if cancelNow { cancel?() }
    }

    func reserve(_ scheduler: ProbeScheduler) -> Bool {
        guard let reservation = scheduler.reservePendingConnection() else { return false }
        lock.lock(); let accepted = !closed
        if accepted { pendingReservation = reservation }
        lock.unlock()
        if !accepted { reservation.release() }
        return accepted
    }

    func connected(_ result: Result<(any NativeOutboundByteStream, Data), Error>) {
        lock.lock(); let reservation = pendingReservation; pendingReservation = nil
        let accepted = !closed
        if accepted, case .success(let pair) = result { stream = pair.0 }
        lock.unlock()
        reservation?.release()
        guard accepted else { if case .success(let pair) = result { pair.0.cancel() }; return }
        switch result {
        case .failure(let error): finish(.init(status: .failure, detail: "连接或代理握手失败", error: error))
        case .success(let (stream, initial)):
            let request = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: Hajimi\r\nConnection: close\r\n\r\n"
            stream.send(Data(request.utf8)) { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    if let error { self.finish(.init(status: .failure, detail: "HTTP 请求发送失败", error: error)) }
                    else { self.read(initial) }
                }
            }
        }
    }

    func fail(_ measurement: NetworkConnectivityDiagnosticMeasurement) { finish(measurement) }

    func cancel() {
        lock.lock(); closed = true
        let live = stream; stream = nil; let cancel = cancelConnect; cancelConnect = nil
        // Physical admission is held until the real connector callback.
        lock.unlock(); cancel?(); live?.cancel()
    }

    private func finish(_ measurement: NetworkConnectivityDiagnosticMeasurement) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let live = stream; stream = nil; let cancel = cancelConnect; cancelConnect = nil
        lock.unlock()
        cancel?(); live?.cancel(); completion(measurement)
    }

    private func read(_ data: Data) {
        lock.lock(); let live = closed ? nil : stream; lock.unlock()
        guard let live else { return }
        guard data.count <= 8_192 - buffer.count else {
            finish(.init(status: .failure, detail: "HTTP 响应头超过诊断上限")); return
        }
        buffer.append(data)
        if let end = buffer.range(of: Data([13, 10])) {
            let prefix = buffer[buffer.startIndex..<end.lowerBound]
            guard let line = String(data: prefix, encoding: .ascii) else {
                finish(.init(status: .failure, detail: "HTTP 状态行格式无效")); return
            }
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count >= 2, fields[0] == "HTTP/1.0" || fields[0] == "HTTP/1.1",
                  fields[1].count == 3, let code = Int(fields[1]), (100...599).contains(code) else {
                finish(.init(status: .failure, detail: "未收到有效 HTTP 状态行")); return
            }
            let healthy = (200...299).contains(code)
            finish(.init(status: healthy ? .success : .failure,
                detail: healthy ? "收到 HTTP 成功状态；耗时包含解析、建连与代理握手，非 ICMP ping"
                    : "已收到 HTTP 响应，但状态非成功；可能存在重定向、认证或目标服务异常",
                responseCode: code))
            return
        }
        guard buffer.count < 8_192, reads < 32 else {
            finish(.init(status: .failure, detail: "未收到完整 HTTP 状态行")); return
        }
        reads += 1
        live.receive(maximum: min(4_096, 8_192 - buffer.count)) { [weak self] data, eof, error in
            guard let self else { return }
            self.queue.async {
                if let error { self.finish(.init(status: .failure, detail: "HTTP 响应接收失败", error: error)) }
                else if let data, !data.isEmpty { self.read(data) }
                else { self.finish(.init(status: .failure, detail: eof ? "连接在 HTTP 响应前关闭" : "HTTP 响应为空")) }
            }
        }
    }
}

enum NetworkConnectivityDNSResponse {
    static func inspect(_ response: Data, query: Data) -> NetworkConnectivityDiagnosticMeasurement {
        guard DNSMessageInspection.responseMatchesQuery(response, query: query), response.count >= 12 else {
            return .init(status: .failure, detail: "DNS 应答事务或问题不匹配")
        }
        let code = Int(response[response.startIndex + 3] & 0x0f)
        let ede = DNSMessageInspection.extendedDNSErrorCodes(in: response)
        guard response[response.startIndex + 2] & 0x02 == 0 else {
            return .init(status: .failure, detail: "DNS 应答被截断", responseCode: code, extendedDNSErrorCodes: ede)
        }
        guard code == 0 else {
            return .init(status: .failure, detail: "DNS 服务已响应，但固定 A 查询返回错误；EDE 缺失不代表没有上游错误",
                         responseCode: code, extendedDNSErrorCodes: ede)
        }
        guard DNSMessageInspection.addressAnswers(in: response).contains(where: { !$0.address.contains(":") }) else {
            return .init(status: .failure, detail: "固定 A 查询未返回可用地址记录", responseCode: code,
                         extendedDNSErrorCodes: ede)
        }
        return .init(status: .success, detail: "固定 captive.apple.com 的 A 查询收到匹配 DNS 应答；不代表所有域名均可解析",
                     responseCode: code, extendedDNSErrorCodes: ede)
    }
}

/// In-memory protocol and cancellation checks; no name lookup or socket is
/// performed. The final application runs these in its existing self-test mode.
public enum NetworkConnectivityDiagnosticsSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "网络连通性诊断自检失败：\(text)" }
    }
    private final class Stream: NativeOutboundByteStream {
        private let lock = NSLock()
        private var cancelled = 0
        private let response: Data
        init(_ response: String = "") { self.response = Data(response.utf8) }
        var cancellationCount: Int { lock.lock(); defer { lock.unlock() }; return cancelled }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            completion(response.isEmpty ? nil : response, true, nil)
        }
        func cancel() { lock.lock(); cancelled += 1; lock.unlock() }
    }
    private final class Jobs {
        let started = DispatchSemaphore(value: 0)
        let cleaned = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var callbacks: [Int: (NetworkConnectivityDiagnosticMeasurement) -> Void] = [:]
        var starts: [Int] = []
        func add(_ index: Int, _ callback: @escaping (NetworkConnectivityDiagnosticMeasurement) -> Void) {
            lock.lock(); starts.append(index); callbacks[index] = callback; lock.unlock(); started.signal()
        }
        func answer(_ index: Int) {
            lock.lock(); let callback = callbacks[index]; lock.unlock()
            callback?(.init(status: .success, detail: "内存应答", responseCode: 200))
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return starts.count }
    }
    private final class SnapshotBox {
        let done = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var snapshots: [NetworkConnectivityDiagnosticsSnapshot] = []
        func add(_ value: NetworkConnectivityDiagnosticsSnapshot) {
            lock.lock(); snapshots.append(value); lock.unlock()
            if !value.isRunning { done.signal() }
        }
        var last: NetworkConnectivityDiagnosticsSnapshot? {
            lock.lock(); defer { lock.unlock() }; return snapshots.last
        }
    }

    public static func run() throws {
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            if !condition() { throw Failure(text: text) }
        }
        let query = DNSMessageInspection.query(for: "captive.apple.com", type: 1, id: 0x5051)!
        func answer(type: UInt16 = 1, code: UInt8 = 0, ede: UInt16? = nil) -> Data {
            var data = query; data[2] = 0x81; data[3] = 0x80 | code
            if code == 0 {
                data[7] = 1
                data.append(contentsOf: [0xc0, 0x0c, UInt8(type >> 8), UInt8(truncatingIfNeeded: type),
                    0, 1, 0, 0, 0, 60, 0, type == 1 ? 4 : 16])
                data.append(type == 1 ? Data([192, 0, 2, 80]) : Data(repeating: 1, count: 16))
            }
            if let ede {
                data[11] = 1
                data.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 6,
                    0, 15, 0, 2, UInt8(ede >> 8), UInt8(truncatingIfNeeded: ede)])
            }
            return data
        }
        let good = NetworkConnectivityDNSResponse.inspect(answer(), query: query)
        try require(good.status == .success && good.responseCode == 0, "匹配的固定 A 应答未判成功")
        let wrongType = NetworkConnectivityDNSResponse.inspect(answer(type: 28), query: query)
        try require(wrongType.status == .failure, "A 查询仅返回 AAAA 却显示成功")
        let servfail = NetworkConnectivityDNSResponse.inspect(answer(code: 2, ede: 6), query: query)
        try require(servfail.status == .failure && servfail.responseCode == 2
                    && servfail.extendedDNSErrorCodes == [6], "SERVFAIL 或 EDE 数值丢失")
        let unknown = NetworkConnectivityDNSResponse.inspect(answer(code: 2, ede: 65_535), query: query)
        try require(unknown.extendedDNSErrorCodes == [65_535], "未知 EDE 被丢弃")
        var mismatch = answer(); mismatch[0] ^= 1
        try require(NetworkConnectivityDNSResponse.inspect(mismatch, query: query).status == .failure,
                    "错误 DNS 事务显示成功")
        var truncated = answer(); truncated[2] |= 2
        try require(NetworkConnectivityDNSResponse.inspect(truncated, query: query).status == .failure,
                    "截断 DNS 应答显示成功")
        let secret = "userinfo-secret-token.invalid/path?credential=secret"
        let error = NetworkConnectivityDiagnosticMeasurement(status: .failure, detail: "连接失败",
            error: NSError(domain: secret, code: -9, userInfo: [NSLocalizedDescriptionKey: secret]))
        try require(error.errorCode == -9 && error.errorDomain?.contains(secret) == false
                    && !error.detail.contains(secret), "错误元数据暴露原始错误文本或丢数值")

        let lane = DispatchQueue(label: "app.hajimi.network-diagnostics.http-selftest")
        for (statusLine, expected, code) in [
            ("HTTP/1.1 200 OK\r\n", NetworkConnectivityDiagnosticStatus.success, 200),
            ("HTTP/1.1 302 Portal\r\n", .failure, 302),
            ("HTTP/1.1 403 Forbidden\r\n", .failure, 403),
            ("HTTP/1.1 999 Bad\r\n", .failure, -1),
            ("not-http\r\n", .failure, -1)
        ] {
            let done = DispatchSemaphore(value: 0), stream = Stream()
            let lock = NSLock(); var received: NetworkConnectivityDiagnosticMeasurement?
            let exchange = NetworkConnectivityHTTPExchange(host: "fixed.invalid", path: "/", queue: lane) { value in
                lock.lock(); received = value; lock.unlock(); done.signal()
            }
            lane.async { exchange.connected(.success((stream, Data(statusLine.utf8)))) }
            try require(done.wait(timeout: .now() + 2) == .success, "HTTP 内存应答未完成")
            lock.lock(); let result = received; lock.unlock()
            try require(result?.status == expected && (result?.responseCode ?? -1) == code,
                        "HTTP 失败/门户状态被标为可用")
            try require(stream.cancellationCount == 1, "HTTP 已完成流未恰好关闭一次")
        }
        let cancelled = NetworkConnectivityHTTPExchange(host: "fixed.invalid", path: "/", queue: lane) { _ in }
        let reservationScheduler = ProbeScheduler(maximumActive: 1, maximumQueued: 0)
        try require(cancelled.reserve(reservationScheduler), "测试连接准入失败")
        cancelled.cancel()
        try require(reservationScheduler.snapshot().pendingConnections == 1,
                    "取消在真实 setup 回执前错误返还物理连接名额")
        var lateHandleCancellations = 0
        cancelled.installCancellation { lateHandleCancellations += 1 }
        let late = Stream(); cancelled.connected(.success((late, Data())))
        try require(lateHandleCancellations == 1 && late.cancellationCount == 1
                    && reservationScheduler.snapshot().pendingConnections == 0,
                    "迟到取消句柄/成功流未关闭或真实回执未返还名额")
        let cleanup = NetworkConnectivityProbeCleanup()
        cleanup.cancel(); var cleanupCalls = 0
        cleanup.install { cleanupCalls += 1 }; cleanup.cancel()
        try require(cleanupCalls == 1, "取消先于句柄返回时丢失或重复清理")

        let jobs = Jobs(), box = SnapshotBox(), callbacks = DispatchQueue(label: "app.hajimi.network-diagnostics.results-selftest")
        let scheduler = ProbeScheduler(maximumActive: 8, maximumQueued: 8)
        let tasks = (0..<5).map { index in
            NetworkConnectivityDiagnosticTask(row: .init(id: "job-\(index)", kind: .traditionalDNS,
                title: "内存固定查询", endpoint: "192.0.2.53:53", route: "内存"),
                timeout: 2, operation: { _, _, done in
                    jobs.add(index, done)
                    return { jobs.cleaned.signal() }
                })
        }
        let session = NetworkConnectivityDiagnosticsSession(tasks: tasks, scheduler: scheduler,
            callbackQueue: callbacks, isCurrent: { true }, onUpdate: box.add)
        try require(jobs.started.wait(timeout: .now() + 2) == .success
                    && jobs.started.wait(timeout: .now() + 2) == .success && jobs.count == 2,
                    "一轮超过两个活跃测试或首批未启动")
        jobs.answer(0)
        try require(jobs.started.wait(timeout: .now() + 2) == .success && jobs.count == 3,
                    "一个完成后未仅补一个新任务")
        session.cancel()
        try require(box.done.wait(timeout: .now() + 2) == .success, "取消未发送终态快照")
        jobs.answer(1); callbacks.sync {}
        try require(box.last?.isRunning == false && box.last?.rows.filter({ $0.status == .success }).count == 1
                    && box.last?.rows.filter({ $0.status == .cancelled }).count == 4 && jobs.count == 3,
                    "取消后迟到回调篡改结果或启动后续工作")
        let encoded = try JSONEncoder().encode(box.last!)
        let decoded = try JSONDecoder().decode(NetworkConnectivityDiagnosticsSnapshot.self, from: encoded)
        try require(decoded == box.last,
                    "可复制网络诊断快照不能往返编码")
        try dnsProbeDeadlineEvidence()
        print("Network connectivity diagnostics self-test passed: fixed DNS identity/A-only/SERVFAIL/EDE, HTTP status, bounded admission, late setup receipts, cancellation, IPv6 path/deadline evidence, numeric errors and Codable")
        withExtendedLifetime(session) {}
    }

    private static func dnsProbeDeadlineEvidence() throws {
        func require(_ value: Bool, _ message: String) throws {
            if !value { throw Failure(text: message) }
        }
        let native = NSError(domain: NSPOSIXErrorDomain, code: Int(POSIXErrorCode.EHOSTUNREACH.rawValue),
            userInfo: [NSLocalizedDescriptionKey: "private-error.invalid/secret?token=hidden"])
        let evidence = NetworkConnectivityDNSProbeEvidence(ipv6: true)
        evidence.observePathError(native)
        let recorded = evidence.deadlineMeasurement()
        try require(recorded.status == .failure && recorded.errorDomain == NSPOSIXErrorDomain
            && recorded.errorCode == 65 && recorded.detail.contains("IPv6")
            && recorded.detail.contains("路径不可达") && recorded.detail.contains("原截止时间")
            && !recorded.detail.contains("private-error"), "IPv6 原生路径错误丢失或暴露错误描述")
        evidence.observePathError(nil)
        try require(evidence.deadlineMeasurement().errorCode == nil,
            "路径恢复后仍沿用之前的不可达错误")
        let terminal = NetworkConnectivityDNSProbeFailure.inspect(native, ipv6: true)
        let timed = NetworkConnectivityDNSProbeFailure.inspect(
            TraditionalDNSProbeDeadlineError(cause: native), ipv6: true)
        try require(terminal.errorCode == 65 && !terminal.detail.contains("原截止时间")
            && timed.errorCode == 65 && timed.detail.contains("原截止时间")
            && terminal.responseCode == nil && timed.responseCode == nil,
            "传输失败与原期限超时混淆，或伪造 DNS 应答码")

        // Build25's ENETDOWN waiting result coexisted with an UP/RUNNING
        // physical link. This reports the selected address-family path;
        // it must not diagnose the interface's administrative state.
        let downPath = NSError(domain: NSPOSIXErrorDomain,
            code: Int(POSIXErrorCode.ENETDOWN.rawValue),
            userInfo: [NSLocalizedDescriptionKey: "private-path.invalid/secret"])
        evidence.observePathError(downPath)
        let downDeadline = evidence.deadlineMeasurement()
        let downFailure = NetworkConnectivityDNSProbeFailure.inspect(downPath, ipv6: true)
        try require(downDeadline.errorDomain == NSPOSIXErrorDomain && downDeadline.errorCode == 50
            && downDeadline.detail.contains("IPv6") && downDeadline.detail.contains("出口路径不可用")
            && !downDeadline.detail.contains("接口尚未就绪") && !downDeadline.detail.contains("private-path")
            && downFailure.errorCode == 50 && downFailure.responseCode == nil
            && !downFailure.detail.contains("原截止时间"),
            "ENETDOWN 被误解为物理网卡未启用，丢失原始错误或伪造 DNS 应答")
        evidence.observePathError(nil)

        // Keep the actual transport lane blocked beyond the scheduler deadline.
        // This forces the scheduler to win; no close/timer callback can supply
        // the path evidence afterward or turn its expiry into a second result.
        let gateEntered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let late = DispatchSemaphore(value: 0), cleaned = DispatchSemaphore(value: 0)
        let callbacks = DispatchQueue(label: "app.hajimi.network-diagnostics.deadline-evidence-selftest")
        let box = SnapshotBox(), scheduler = ProbeScheduler(maximumActive: 1, maximumQueued: 0)
        let task = NetworkConnectivityDiagnosticTask(row: .init(id: "ipv6-deadline", kind: .traditionalDNS,
            title: "IPv6 固定测试", endpoint: "[2001:db8::53]:53", route: "内存"), timeout: 0.2,
            deadlineMeasurement: evidence.deadlineMeasurement, operation: { lane, _, done in
                evidence.observePathError(native)
                lane.async {
                    gateEntered.signal()
                    _ = release.wait(timeout: .now() + 3)
                    done(.init(status: .success, detail: "过期后应答")); late.signal()
                }
                return { cleaned.signal() }
            })
        let session = NetworkConnectivityDiagnosticsSession(tasks: [task], scheduler: scheduler,
            callbackQueue: callbacks, isCurrent: { true }, onUpdate: box.add)
        defer { release.signal() }
        try require(gateEntered.wait(timeout: .now() + 2) == .success,
            "真实探测队列未进入受控阻塞")
        try require(box.done.wait(timeout: .now() + 2) == .success,
            "调度器先超时未交付终态")
        let terminalSnapshot = box.last
        try require(terminalSnapshot?.rows.first?.status == .failure
            && terminalSnapshot?.rows.first?.errorDomain == NSPOSIXErrorDomain
            && terminalSnapshot?.rows.first?.errorCode == 65
            && (terminalSnapshot?.rows.first?.milliseconds ?? 0) > 0,
            "调度器先到时丢失原生 IPv6 错误或实际检测耗时")
        release.signal()
        try require(late.wait(timeout: .now() + 2) == .success
            && cleaned.wait(timeout: .now() + 2) == .success,
            "迟到应答或清理未完成")
        callbacks.sync {}
        try require(box.last == terminalSnapshot && scheduler.snapshot().active == 0,
            "迟到成功覆盖超时证据或遗留调度名额")

        // Cancellation must not read deadline evidence or publish a path failure.
        let jobs = Jobs(), cancelledBox = SnapshotBox()
        let cancelledTask = NetworkConnectivityDiagnosticTask(row: .init(id: "ipv6-cancel", kind: .traditionalDNS,
            title: "IPv6 固定测试", endpoint: "[2001:db8::53]:53", route: "内存"), timeout: 2,
            deadlineMeasurement: { fatalError("cancellation read deadline-only evidence") },
            operation: { _, _, done in jobs.add(0, done); return { jobs.cleaned.signal() } })
        let cancelled = NetworkConnectivityDiagnosticsSession(tasks: [cancelledTask], scheduler: scheduler,
            callbackQueue: callbacks, isCurrent: { true }, onUpdate: cancelledBox.add)
        try require(jobs.started.wait(timeout: .now() + 2) == .success, "取消夹具未启动")
        cancelled.cancel()
        try require(cancelledBox.done.wait(timeout: .now() + 2) == .success
            && cancelledBox.last?.rows.first?.status == .cancelled
            && cancelledBox.last?.rows.first?.errorCode == nil, "取消被改报为 IPv6 路径故障")
        withExtendedLifetime((session, cancelled)) {}
    }
}

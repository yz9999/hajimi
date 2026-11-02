import Foundation
import HajimiDNS
import Network
import Darwin

/// A literal traditional DNS server, used only for explicit DoH bootstrap and
/// the fixed connectivity probe. Names and TUN/fake-IP sinks cannot bootstrap
/// themselves and are rejected before any Network.framework connection exists.
public struct TraditionalDNSServer: Equatable {
    public let host: String
    public let port: UInt16

    public init?(_ raw: String) {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.lowercased().hasPrefix("udp://") { value.removeFirst(6) }
        guard !value.isEmpty, value.lowercased() != "system", !value.contains("://") else { return nil }
        var port: UInt16 = 53
        var host = value
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]") else { return nil }
            host = String(value[value.index(after: value.startIndex)..<close])
            guard host.contains(":") else { return nil }
            let suffix = value[value.index(after: close)...]
            if !suffix.isEmpty {
                guard suffix.first == ":", let parsed = UInt16(suffix.dropFirst()), parsed > 0 else { return nil }
                port = parsed
            }
        } else if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":") {
            host = String(value[..<colon])
            guard let parsed = UInt16(value[value.index(after: colon)...]), parsed > 0 else { return nil }
            port = parsed
        }
        // Darwin can embed a %scope index into the IPv6 address bytes and
        // inet_ntop then prints a different unscoped address. This endpoint
        // has no separate scope field, so do not silently rewrite it.
        guard !host.contains("%"), let normalized = Self.usableAddress(host) else { return nil }
        self.host = normalized
        self.port = port
    }

    /// IPv4-mapped literals use an IPv4 path despite their textual colons.
    /// This label describes the DNS endpoint, never the requested RR type.
    var usesIPv6Transport: Bool {
        var address = in6_addr()
        guard host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &address) { Array($0) }
        return !(bytes.prefix(10).allSatisfy({ $0 == 0 })
            && bytes[10] == 255 && bytes[11] == 255)
    }

    var isLoopback: Bool {
        if host.hasPrefix("127.") || host == "::1" { return true }
        var address = in6_addr()
        guard host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &address) { Array($0) }
        return bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 255
            && bytes[11] == 255 && bytes[12] == 127
    }

    fileprivate static func usableAddress(_ raw: String) -> String? {
        var ipv4 = in_addr()
        if raw.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            let bytes = withUnsafeBytes(of: &ipv4) { Array($0) }
            guard usableIPv4(bytes) else { return nil }
            var output = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &ipv4, &output, socklen_t(output.count)) != nil else { return nil }
            return String(cString: output)
        }
        var ipv6 = in6_addr()
        guard raw.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
        guard !bytes.allSatisfy({ $0 == 0 }), bytes[0] != 255,
              !bytes.starts(with: [0xfd, 0, 0x68, 0x61, 0x6a, 0x69, 0, 0]) else { return nil }
        if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 255, bytes[11] == 255 {
            guard usableIPv4(Array(bytes.suffix(4))) else { return nil }
        }
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &ipv6, &output, socklen_t(output.count)) != nil else { return nil }
        return String(cString: output)
    }

    private static func usableIPv4(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 4, bytes[0] != 0, bytes[0] < 224 else { return false }
        if bytes[0] == 198 && bytes[1] == 19 { return false }
        if bytes[0] == 198 && bytes[1] == 18 && bytes[2] == 16 { return false }
        return true
    }
}

enum TraditionalDNSBootstrapError: LocalizedError {
    case configuration(String)
    case notAllowed
    case unavailable
    case timeout
    case cancelled
    case capacity
    var errorDescription: String? {
        switch self {
        case .configuration(let message): return message
        case .notAllowed: return "传统 DNS 仅允许解析配置中的 DoH 主机名"
        case .unavailable: return "传统 DNS 未返回经过事务验证的可用地址"
        case .timeout: return "传统 DNS 引导或连通性检查超时"
        case .cancelled: return "传统 DNS 请求已取消"
        case .capacity: return "传统 DNS 请求已达容量上限"
        }
    }
}

/// Internal wire injection for offline tests, not a public arbitrary-name API.
typealias TraditionalDNSWireExchange = (
    _ server: TraditionalDNSServer, _ query: Data, _ queue: DispatchQueue,
    _ completion: @escaping (Result<Data, Error>) -> Void
) -> () -> Void

/// This is deliberately not an application DNS resolver. Its two public
/// entrypoints are a configured DoH-host allowlist and one fixed probe name.
public final class TraditionalDNSBootstrapResolver {
    private struct Waiter {
        let queue: DispatchQueue
        let completion: (Result<[String], Error>) -> Void
    }
    private struct CacheEntry {
        let addresses: [String]
        let expires: Date
    }
    private final class Job {
        let id = UUID()
        let operation: TraditionalDNSLookup
        let cacheable: Bool
        var waiters: Set<UUID>
        init(operation: TraditionalDNSLookup, cacheable: Bool, waiter: UUID) {
            self.operation = operation; self.cacheable = cacheable; waiters = [waiter]
        }
    }

    private let servers: [TraditionalDNSServer]
    private let allowedHosts: Set<String>
    private let configurationError: Error?
    private let timeout: TimeInterval
    private let clock: () -> Date
    private let exchange: TraditionalDNSWireExchange?
    private let permitted: () -> Bool
    private let queue = DispatchQueue(label: "app.hajimi.dns.traditional-purpose", qos: .utility)
    private let admission = NSLock()
    private var closed = false
    private var waiters: [UUID: Waiter] = [:]
    // The following fields are confined to queue.
    private var jobs: [String: Job] = [:]
    private var waiterJobs: [UUID: String] = [:]
    private var cache: [String: CacheEntry] = [:]

    public convenience init(servers: [String], allowedDoHHosts: [String]) {
        self.init(servers: servers, allowedDoHHosts: allowedDoHHosts, timeout: 4)
    }

    init(servers rawServers: [String], allowedDoHHosts: [String], timeout: TimeInterval,
         clock: @escaping () -> Date = Date.init, exchange: TraditionalDNSWireExchange? = nil,
         permitted: @escaping () -> Bool = { true }) {
        var servers: [TraditionalDNSServer] = []
        var hosts = Set<String>()
        var error: Error?
        if rawServers.isEmpty || rawServers.count > 32 {
            error = TraditionalDNSBootstrapError.configuration("传统 DNS 必须配置 1 至 32 个固定 IP 上游")
        }
        for raw in rawServers.prefix(32) {
            guard let server = TraditionalDNSServer(raw) else {
                error = TraditionalDNSBootstrapError.configuration("传统 DNS 含无效地址、主机名或 TUN/fake-IP 回环")
                continue
            }
            if !servers.contains(server) { servers.append(server) }
        }
        if allowedDoHHosts.count > 128 {
            error = TraditionalDNSBootstrapError.configuration("DoH 引导主机白名单超过上限")
        }
        for raw in allowedDoHHosts.prefix(128) {
            guard let host = Self.normalizedHost(raw) else {
                error = TraditionalDNSBootstrapError.configuration("DoH 引导白名单必须是合法的非 IP 主机名")
                continue
            }
            hosts.insert(host)
        }
        if !timeout.isFinite || timeout <= 0 || timeout > 60 {
            error = TraditionalDNSBootstrapError.configuration("传统 DNS 截止时间无效")
        }
        self.servers = servers
        allowedHosts = hosts
        configurationError = error
        self.timeout = timeout
        self.clock = clock
        self.exchange = exchange
        self.permitted = permitted
    }

    @discardableResult
    public func resolveDoHHost(_ host: String, queue callbackQueue: DispatchQueue,
                              completion: @escaping (Result<[String], Error>) -> Void) -> UUID? {
        guard let normalized = Self.normalizedHost(host), allowedHosts.contains(normalized) else {
            callbackQueue.async { completion(.failure(TraditionalDNSBootstrapError.notAllowed)) }
            return nil
        }
        return request(host: normalized, cacheable: true, callbackQueue: callbackQueue, completion: completion)
    }

    @discardableResult
    public func testConnectivity(queue callbackQueue: DispatchQueue,
                                 completion: @escaping (Result<[String], Error>) -> Void) -> UUID? {
        request(host: "captive.apple.com", cacheable: false,
                callbackQueue: callbackQueue, completion: completion)
    }

    private func request(host: String, cacheable: Bool, callbackQueue: DispatchQueue,
                         completion: @escaping (Result<[String], Error>) -> Void) -> UUID? {
        if let configurationError {
            callbackQueue.async { completion(.failure(configurationError)) }
            return nil
        }
        guard permitted() else {
            callbackQueue.async { completion(.failure(TraditionalDNSBootstrapError.cancelled)) }
            return nil
        }
        let id = UUID()
        admission.lock()
        guard !closed, waiters.count < 128 else {
            let error: Error = closed ? TraditionalDNSBootstrapError.cancelled : TraditionalDNSBootstrapError.capacity
            admission.unlock()
            callbackQueue.async { completion(.failure(error)) }
            return nil
        }
        waiters[id] = Waiter(queue: callbackQueue, completion: completion)
        admission.unlock()
        queue.async {
            guard self.hasWaiter(id) else { return }
            guard self.permitted() else {
                self.complete(id, result: .failure(TraditionalDNSBootstrapError.cancelled)); return
            }
            let interface = ProxyEngine.currentOutboundInterface
            let key = "\(cacheable ? "bootstrap" : "connectivity")|\(host)|\(interface?.name ?? "")"
            let now = self.clock()
            self.cache = self.cache.filter { $0.value.expires > now }
            if cacheable, let entry = self.cache[key] {
                self.complete(id, result: .success(entry.addresses))
                return
            }
            if let job = self.jobs[key] {
                job.waiters.insert(id); self.waiterJobs[id] = key
                return
            }
            guard self.jobs.count < 16 else {
                self.complete(id, result: .failure(TraditionalDNSBootstrapError.capacity))
                return
            }
            let wire: TraditionalDNSWireExchange
            if let injected = self.exchange {
                wire = { [permitted = self.permitted] server, query, queue, completion in
                    guard permitted() else {
                        completion(.failure(TraditionalDNSBootstrapError.cancelled)); return {}
                    }
                    return injected(server, query, queue, completion)
                }
            }
            else {
                let wireTimeout = self.timeout
                wire = { [permitted = self.permitted] server, query, queue, completion in
                    guard permitted() else {
                        completion(.failure(TraditionalDNSBootstrapError.cancelled)); return {}
                    }
                    let transaction = TraditionalDNSNetworkExchange(
                        server: server, query: query, interface: interface,
                        queue: queue, timeout: wireTimeout, permitted: permitted, completion: completion)
                    transaction.start()
                    return { transaction.cancel() }
                }
            }
            let operation = TraditionalDNSLookup(host: host, servers: self.servers,
                queue: self.queue, timeout: self.timeout, exchange: wire, permitted: self.permitted)
            let job = Job(operation: operation, cacheable: cacheable, waiter: id)
            self.jobs[key] = job; self.waiterJobs[id] = key
            let jobID = job.id
            operation.start { [weak self] result in self?.completeJob(key: key, jobID: jobID, result: result) }
        }
        return id
    }

    private func hasWaiter(_ id: UUID) -> Bool {
        admission.lock(); defer { admission.unlock() }
        return waiters[id] != nil
    }

    private func complete(_ id: UUID, result: Result<[String], Error>) {
        admission.lock()
        let waiter = waiters.removeValue(forKey: id)
        admission.unlock()
        waiterJobs.removeValue(forKey: id)
        if let waiter { waiter.queue.async { waiter.completion(result) } }
    }

    private func completeJob(key: String, jobID: UUID,
                             result: Result<(addresses: [String], ttl: UInt32), Error>) {
        guard let job = jobs[key], job.id == jobID else { return }
        jobs.removeValue(forKey: key)
        if job.cacheable, case .success(let answer) = result, answer.ttl > 0 {
            if cache.count >= 128, let oldest = cache.min(by: { $0.value.expires < $1.value.expires })?.key {
                cache.removeValue(forKey: oldest)
            }
            cache[key] = CacheEntry(addresses: answer.addresses,
                                    expires: clock().addingTimeInterval(min(3_600, TimeInterval(answer.ttl))))
        }
        let answer = result.map(\.addresses)
        for id in job.waiters { complete(id, result: answer) }
    }

    public func cancel(_ id: UUID) {
        admission.lock()
        let waiter = waiters.removeValue(forKey: id)
        admission.unlock()
        if let waiter { waiter.queue.async { waiter.completion(.failure(TraditionalDNSBootstrapError.cancelled)) } }
        queue.async {
            guard let key = self.waiterJobs.removeValue(forKey: id), let job = self.jobs[key] else { return }
            job.waiters.remove(id)
            if job.waiters.isEmpty { self.jobs.removeValue(forKey: key); job.operation.cancel() }
        }
    }

    public func cancel() {
        admission.lock()
        closed = true
        let active = Array(waiters.values)
        waiters.removeAll()
        admission.unlock()
        active.forEach { waiter in
            waiter.queue.async { waiter.completion(.failure(TraditionalDNSBootstrapError.cancelled)) }
        }
        queue.async {
            let active = self.jobs.values.map(\.operation)
            self.jobs.removeAll(); self.waiterJobs.removeAll(); self.cache.removeAll()
            active.forEach { $0.cancel() }
        }
    }

    deinit {
        let pending = Array(waiters.values)
        let active = jobs.values.map(\.operation)
        pending.forEach { waiter in
            waiter.queue.async { waiter.completion(.failure(TraditionalDNSBootstrapError.cancelled)) }
        }
        queue.async { active.forEach { $0.cancel() } }
    }

    private static func normalizedHost(_ raw: String) -> String? {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.hasSuffix(".") { host.removeLast() }
        guard DoHEndpoint.isValidServerName(host), !DoHEndpoint.isAddressLiteral(host),
              DNSMessageInspection.query(for: host, type: 1) != nil else { return nil }
        return host
    }
}

/// One coalesced, bounded A/AAAA lookup, with configured-server failover only.
private final class TraditionalDNSLookup {
    private let host: String
    private let servers: [TraditionalDNSServer]
    private let queue: DispatchQueue
    private let timeout: TimeInterval
    private let exchange: TraditionalDNSWireExchange
    private let permitted: () -> Bool
    private var completion: ((Result<(addresses: [String], ttl: UInt32), Error>) -> Void)?
    private var serverIndex = 0
    private var attempt = UUID()
    private var cancellations: [UInt16: () -> Void] = [:]
    private var addresses: [String] = []
    private var minimumTTL = UInt32.max
    private var sawTimeout = false
    private var deadline: DispatchSourceTimer?
    private var attemptDeadline: DispatchSourceTimer?

    init(host: String, servers: [TraditionalDNSServer], queue: DispatchQueue,
         timeout: TimeInterval, exchange: @escaping TraditionalDNSWireExchange,
         permitted: @escaping () -> Bool = { true }) {
        self.host = host; self.servers = servers; self.queue = queue
        self.timeout = timeout; self.exchange = exchange
        self.permitted = permitted
    }

    func start(completion: @escaping (Result<(addresses: [String], ttl: UInt32), Error>) -> Void) {
        self.completion = completion
        let timer = DispatchSource.makeTimerSource(queue: queue)
        deadline = timer
        timer.schedule(deadline: .now() + timeout)
        timer.setEventHandler { [weak self] in self?.finish(.failure(TraditionalDNSBootstrapError.timeout)) }
        timer.resume()
        nextServer()
    }

    private func nextServer() {
        guard completion != nil else { return }
        guard permitted() else { finish(.failure(TraditionalDNSBootstrapError.cancelled)); return }
        guard serverIndex < servers.count else {
            finish(.failure(sawTimeout ? TraditionalDNSBootstrapError.timeout : .unavailable)); return
        }
        let server = servers[serverIndex]; serverIndex += 1
        let token = UUID(); attempt = token
        addresses.removeAll(); minimumTTL = .max
        let timer = DispatchSource.makeTimerSource(queue: queue)
        attemptDeadline = timer
        timer.schedule(deadline: .now() + min(1.5, max(0.02, timeout / Double(servers.count))))
        timer.setEventHandler { [weak self] in self?.endAttempt(token, timedOut: true) }
        timer.resume()
        let firstID = UInt16.random(in: .min ... .max)
        for (id, type) in [(firstID, UInt16(1)), (firstID &+ 1, UInt16(28))] {
            guard permitted() else { finish(.failure(TraditionalDNSBootstrapError.cancelled)); return }
            guard let query = DNSMessageInspection.query(for: host, type: type, id: id) else {
                finish(.failure(TraditionalDNSBootstrapError.notAllowed)); return
            }
            let cancel = exchange(server, query, queue) { [weak self] result in
                guard let self else { return }
                self.queue.async { self.accept(result, query: query, id: id, attempt: token) }
            }
            cancellations[id] = cancel
        }
    }

    private func accept(_ result: Result<Data, Error>, query: Data, id: UInt16, attempt token: UUID) {
        guard completion != nil, attempt == token, let cancel = cancellations.removeValue(forKey: id) else { return }
        cancel()
        guard permitted() else { finish(.failure(TraditionalDNSBootstrapError.cancelled)); return }
        if case .success(let response) = result,
           DNSMessageInspection.responseMatchesQuery(response, query: query) {
            for record in DNSMessageInspection.addressAnswers(in: response) {
                guard let address = TraditionalDNSServer.usableAddress(record.address) else { continue }
                minimumTTL = min(minimumTTL, record.ttl)
                if addresses.count < 16, !addresses.contains(address) { addresses.append(address) }
            }
        }
        if cancellations.isEmpty { endAttempt(token) }
    }

    private func endAttempt(_ token: UUID, timedOut: Bool = false) {
        guard completion != nil, attempt == token else { return }
        sawTimeout = sawTimeout || timedOut
        attempt = UUID()
        attemptDeadline?.setEventHandler {}; attemptDeadline?.cancel(); attemptDeadline = nil
        let active = Array(cancellations.values); cancellations.removeAll()
        active.forEach { $0() }
        if !addresses.isEmpty { finish(.success((addresses, minimumTTL))) }
        else { nextServer() }
    }

    func cancel() { finish(.failure(TraditionalDNSBootstrapError.cancelled)) }

    private func finish(_ result: Result<(addresses: [String], ttl: UInt32), Error>) {
        guard let callback = completion else { return }
        completion = nil
        deadline?.setEventHandler {}; deadline?.cancel(); deadline = nil
        attemptDeadline?.setEventHandler {}; attemptDeadline?.cancel(); attemptDeadline = nil
        let active = Array(cancellations.values); cancellations.removeAll()
        active.forEach { $0() }
        callback(result)
    }
}

/// A deadline is a local observation, not a replacement for the last native
/// path error. Diagnostics expose its fixed reason and its numeric cause
/// separately; merely waiting never declares a recoverable path terminal.
struct TraditionalDNSProbeDeadlineError: Error, CustomNSError {
    let cause: Error?
    static var errorDomain: String { "app.hajimi.traditional-dns-probe" }
    var errorCode: Int { 1 }
    var errorUserInfo: [String: Any] {
        var info: [String: Any] = [NSLocalizedDescriptionKey: "普通 DNS 固定查询已到原截止时间"]
        if let cause { info[NSUnderlyingErrorKey] = cause }
        return info
    }
}

/// One explicit fixed A question, independent of the DoH-bootstrap lookup's
/// A/AAAA aggregation, cache and per-server failover slice. Query type is not
/// the transport family: an IPv6 DNS endpoint still receives this A question.
final class TraditionalDNSConnectivityProbe {
    let query: Data
    private let queue: DispatchQueue
    private let exchange: TraditionalDNSNetworkExchange
    private let permission: Permission

    private final class Permission {
        private let lock = NSLock()
        private var cancelled = false
        func cancel() { lock.lock(); cancelled = true; lock.unlock() }
        var isAllowed: Bool { lock.lock(); defer { lock.unlock() }; return !cancelled }
    }

    init(server: TraditionalDNSServer, interface: NWInterface?, queue: DispatchQueue,
         deadline: TimeInterval, queryID: UInt16 = .random(in: .min ... .max),
         permitted: @escaping () -> Bool = { true },
         onWaitingError: ((Error?) -> Void)? = nil,
         completion: @escaping (Result<Data, Error>) -> Void) {
        query = DNSMessageInspection.query(for: "captive.apple.com", type: 1, id: queryID)!
        self.queue = queue
        let permission = Permission()
        self.permission = permission
        exchange = TraditionalDNSNetworkExchange(server: server, query: query,
            interface: interface, queue: queue, timeout: 0, absoluteDeadline: deadline,
            permitted: { permission.isAllowed && permitted() },
            onWaitingError: onWaitingError, completion: completion)
    }

    func start() { queue.async { [exchange] in exchange.start() } }
    func cancel() { permission.cancel(); exchange.cancel() }
}

/// Literal-IP UDP first, with one TCP retry only for a validated TC response.
/// Every connection is physically bound except the deliberate loopback fixture.
private final class TraditionalDNSNetworkExchange {
    private let server: TraditionalDNSServer
    private let query: Data
    private let interface: NWInterface?
    private let queue: DispatchQueue
    private let timeout: TimeInterval
    private let absoluteDeadline: TimeInterval?
    private let permitted: () -> Bool
    private let startConnection: (NWConnection, DispatchQueue) -> Void
    private let onWaitingError: ((Error?) -> Void)?
    private var completion: ((Result<Data, Error>) -> Void)?
    private var connection: NWConnection?
    private var tcp = false
    private var sent = false
    private var invalidResponses = 0
    private var buffer = Data()
    private var timer: DispatchSourceTimer?
    private var keepAlive: TraditionalDNSNetworkExchange?
    private var started = false
    private var waitingError: NWError?

    init(server: TraditionalDNSServer, query: Data, interface: NWInterface?,
         queue: DispatchQueue, timeout: TimeInterval, absoluteDeadline: TimeInterval? = nil,
         permitted: @escaping () -> Bool = { true },
         startConnection: @escaping (NWConnection, DispatchQueue) -> Void = { $0.start(queue: $1) },
         onWaitingError: ((Error?) -> Void)? = nil,
         completion: @escaping (Result<Data, Error>) -> Void) {
        self.server = server; self.query = query; self.interface = interface
        self.queue = queue; self.timeout = timeout; self.completion = completion
        self.absoluteDeadline = absoluteDeadline
        self.permitted = permitted
        self.startConnection = startConnection
        self.onWaitingError = onWaitingError
    }

    func start() {
        guard completion != nil, !started else { return }
        started = true
        guard permitted() else { finish(.failure(TraditionalDNSBootstrapError.cancelled)); return }
        let timerDeadline: DispatchTime
        if let absoluteDeadline {
            let nanos = absoluteDeadline * 1_000_000_000
            guard absoluteDeadline.isFinite, absoluteDeadline > ProcessInfo.processInfo.systemUptime,
                  nanos > 0, nanos < Double(UInt64.max) else {
                finish(.failure(TraditionalDNSProbeDeadlineError(cause: nil))); return
            }
            timerDeadline = DispatchTime(uptimeNanoseconds: UInt64(nanos))
        } else {
            // Preserve the existing DoH-bootstrap duration and failover policy.
            timerDeadline = .now() + timeout
        }
        keepAlive = self
        let timer = DispatchSource.makeTimerSource(queue: queue)
        self.timer = timer
        timer.schedule(deadline: timerDeadline)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let error: Error = self.absoluteDeadline == nil
                ? TraditionalDNSBootstrapError.timeout
                : TraditionalDNSProbeDeadlineError(cause: self.waitingError)
            self.finish(.failure(error))
        }
        timer.resume()
        connect(tcp: false)
    }

    private func connect(tcp: Bool) {
        guard completion != nil, let port = NWEndpoint.Port(rawValue: server.port) else { return }
        guard checkProbeDeadline() else { return }
        guard permitted() else { finish(.failure(TraditionalDNSBootstrapError.cancelled)); return }
        connection?.stateUpdateHandler = nil; connection?.cancel()
        self.tcp = tcp; sent = false; buffer.removeAll()
        let parameters = tcp ? NWParameters.tcp : NWParameters.udp
        if !server.isLoopback { parameters.requiredInterface = interface }
        let connection = NWConnection(host: NWEndpoint.Host(server.host), port: port, using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection, self.connection === connection, self.completion != nil else { return }
            guard self.checkProbeDeadline() else { return }
            switch state {
            case .ready:
                self.waitingError = nil
                self.onWaitingError?(nil)
                guard !self.sent else { return }
                self.sent = true; self.send(connection, tcp: tcp)
            case .waiting(let error):
                if self.absoluteDeadline != nil {
                    self.waitingError = error
                    self.onWaitingError?(error)
                }
            case .failed(let error):
                self.failNative(error)
            case .cancelled: self.finish(.failure(TraditionalDNSBootstrapError.cancelled))
            default: break
            }
        }
        guard checkProbeDeadline() else { return }
        startConnection(connection, queue)
    }

    private func send(_ connection: NWConnection, tcp: Bool) {
        guard checkProbeDeadline() else { return }
        guard permitted() else { finish(.failure(TraditionalDNSBootstrapError.cancelled)); return }
        var request = query
        if tcp {
            request = Data([UInt8(truncatingIfNeeded: query.count >> 8), UInt8(truncatingIfNeeded: query.count)])
            request.append(query)
        }
        connection.send(content: request, completion: .contentProcessed { [weak self, weak connection] error in
            guard let self, let connection, self.connection === connection, self.completion != nil else { return }
            guard self.checkProbeDeadline() else { return }
            if let error { self.failNative(error) }
            else if tcp { self.readTCP(connection) }
            else { self.readUDP(connection) }
        })
    }

    private func readUDP(_ connection: NWConnection) {
        guard checkProbeDeadline() else { return }
        connection.receiveMessage { [weak self, weak connection] data, _, _, error in
            guard let self, let connection, self.connection === connection, self.completion != nil else { return }
            guard self.checkProbeDeadline() else { return }
            if let error { self.failNative(error); return }
            guard let data, DNSMessageInspection.responseMatchesQuery(data, query: self.query) else {
                self.invalidResponses += 1
                if self.invalidResponses >= 16 {
                    self.finish(.failure(TraditionalDNSBootstrapError.unavailable)); return
                }
                self.readUDP(connection); return
            }
            if data[data.startIndex + 2] & 0x02 != 0 { self.connect(tcp: true) }
            else { self.finish(.success(data)) }
        }
    }

    private func readTCP(_ connection: NWConnection) {
        guard checkProbeDeadline() else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_537 - buffer.count) {
            [weak self, weak connection] data, _, complete, error in
            guard let self, let connection, self.connection === connection, self.completion != nil else { return }
            guard self.checkProbeDeadline() else { return }
            if let error { self.failNative(error); return }
            if let data {
                guard data.count <= 65_537 - self.buffer.count else {
                    self.finish(.failure(TraditionalDNSBootstrapError.unavailable)); return
                }
                self.buffer.append(data)
            }
            if self.buffer.count >= 2 {
                let length = Int(self.buffer[self.buffer.startIndex]) << 8 | Int(self.buffer[self.buffer.startIndex + 1])
                guard length >= 12, self.buffer.count <= length + 2 else {
                    self.finish(.failure(TraditionalDNSBootstrapError.unavailable)); return
                }
                if self.buffer.count == length + 2 {
                    let response = Data(self.buffer.dropFirst(2))
                    guard DNSMessageInspection.responseMatchesQuery(response, query: self.query),
                          response[response.startIndex + 2] & 0x02 == 0 else {
                        self.finish(.failure(TraditionalDNSBootstrapError.unavailable)); return
                    }
                    self.finish(.success(response)); return
                }
            }
            if complete { self.finish(.failure(TraditionalDNSBootstrapError.unavailable)) }
            else { self.readTCP(connection) }
        }
    }

    func cancel() { queue.async { self.finish(.failure(TraditionalDNSBootstrapError.cancelled)) } }

    private func failNative(_ error: Error) {
        onWaitingError?(error)
        finish(.failure(error))
    }

    /// The timer and native callbacks share a serial lane but need not be
    /// delivered in deadline order. Do not begin IO, admit evidence or deliver
    /// success after the original deadline merely because its timer is queued.
    private func checkProbeDeadline() -> Bool {
        guard let absoluteDeadline else { return true }
        guard permitted() else { finish(.failure(TraditionalDNSBootstrapError.cancelled)); return false }
        guard ProcessInfo.processInfo.systemUptime < absoluteDeadline else {
            finish(.failure(TraditionalDNSProbeDeadlineError(cause: waitingError))); return false
        }
        return true
    }

    private func finish(_ result: Result<Data, Error>) {
        if case .success = result, !checkProbeDeadline() { return }
        guard let callback = completion else { return }; completion = nil
        timer?.setEventHandler {}; timer?.cancel(); timer = nil
        connection?.stateUpdateHandler = nil; connection?.cancel(); connection = nil
        callback(result)
        keepAlive = nil
    }
}

/// Purpose, cache and cancellation vectors use injected memory exchanges.
/// The only real sockets are a private 127.0.0.1 UDP/TCP truncation fixture.
public enum TraditionalDNSBootstrapSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "传统 DNS 用途隔离自检失败：\(text)" }
    }
    private static func expect(_ condition: Bool, _ text: String) throws {
        guard condition else { throw Failure(text: text) }
    }
    private static func checked(_ name: String, _ body: () throws -> Void) throws {
        do { try body() }
        catch { throw Failure(text: "\(name): \(error.localizedDescription)") }
    }

    public static func run() throws {
        try runOffline()
        try loopbackTruncation()
    }

    public static func runOffline() throws {
        try checked("serverParsing", serverParsing)
        try checked("listenerPortCandidates", listenerPortCandidates)
        try checked("purposeAndCache", purposeAndCache)
        try checked("coalescingAndCancellation", coalescingAndCancellation)
        try checked("failuresAndCapacity", failuresAndCapacity)
        try checked("permissionRevocation", permissionRevocation)
    }

    /// Test-only, fixed-size planning. A fresh OS-assigned TCP port is not
    /// guaranteed to differ from a UDP port that the fixture still occupies.
    private struct ListenerPortCandidates {
        static let range: ClosedRange<UInt16> = 49_152...65_535
        static let maximumAttempts = 4
        private(set) var requested: [UInt16] = []
        private(set) var actual: [UInt16] = []
        private var lastActualRequest = 0

        private static func successor(after port: UInt16) -> UInt16 {
            if range.contains(port), port < range.upperBound { return port + 1 }
            return range.lowerBound
        }

        mutating func next(blockedPort: UInt16? = nil) -> UInt16? {
            guard requested.count < Self.maximumAttempts else { return nil }
            guard let lastActual = actual.last else {
                requested.append(0) // The first allocation remains OS .any.
                return 0
            }
            var excluded = Set(requested)
            excluded.formUnion(actual)
            if let blockedPort { excluded.insert(blockedPort) }
            var candidate = Self.successor(after: lastActual)
            // At most four requested, four actual and one blocked port can
            // be excluded. Ten probes suffice without scanning the range.
            for _ in 0..<(2 * Self.maximumAttempts + 2) {
                if !excluded.contains(candidate) {
                    requested.append(candidate)
                    return candidate
                }
                candidate = Self.successor(after: candidate)
            }
            return nil
        }

        mutating func recordActual(_ port: UInt16) throws {
            guard port > 0, requested.count > lastActualRequest,
                  actual.count < Self.maximumAttempts else {
                throw Failure(text: "invalid or duplicate fixture TCP port receipt")
            }
            actual.append(port)
            lastActualRequest = requested.count
        }
    }

    private static func listenerPortCandidates() throws {
        var ordinary = ListenerPortCandidates()
        try expect(ordinary.next() == 0, "首个 TCP 端口不再由系统分配")
        try ordinary.recordActual(60_000)
        try expect(ordinary.next(blockedPort: 60_000) == 60_001,
                   "显式重试未排除已占用的实际端口")
        try ordinary.recordActual(60_001)
        try expect(ordinary.next(blockedPort: 60_000) == 60_002
                   && ordinary.next(blockedPort: 60_000) == 60_003,
                   "TCP 绑定失败后的重试重复使用了 requested 端口")
        try expect(ordinary.requested.count == 4 && ordinary.next() == nil
                   && ordinary.requested.count == 4,
                   "端口候选超过四次尝试上限")

        var blockedSuccessor = ListenerPortCandidates()
        _ = blockedSuccessor.next()
        try blockedSuccessor.recordActual(60_000)
        try expect(blockedSuccessor.next(blockedPort: 60_001) == 60_002,
                   "小序列未跳过额外的已知 blocked 端口")

        var wrap = ListenerPortCandidates()
        _ = wrap.next()
        try wrap.recordActual(49_152)
        try expect(wrap.next() == 49_153, "固定范围内的候选顺序错误")
        // Distinct actual/requested receipts exercise both exclusion sets;
        // the socket fixture separately rejects an explicit-port mismatch.
        try wrap.recordActual(65_535)
        try expect(wrap.next(blockedPort: 49_154) == 49_155,
                   "回绕后未同时排除 actual、requested 和 blocked 端口")

        for seed in [UInt16(1), 1_024, 49_151, 49_152, 65_535] {
            var bounded = ListenerPortCandidates()
            _ = bounded.next()
            try bounded.recordActual(seed)
            guard let candidate = bounded.next() else {
                throw Failure(text: "bounded fixture port candidate missing")
            }
            try expect(ListenerPortCandidates.range.contains(candidate) && candidate > 1_023,
                       "显式 TCP 重试端口越界或使用特权端口")
            if seed == 65_535 {
                try expect(candidate == 49_152, "上边界未在固定范围内回绕")
            }
        }

        var noActual = ListenerPortCandidates()
        for _ in 0..<4 {
            try expect(noActual.next() == 0, "尚无实际端口时擅自改用显式端口")
        }
        try expect(noActual.next() == nil, "OS .any 分配超过四次尝试上限")
    }

    private static func serverParsing() throws {
        try expect(TraditionalDNSServer("udp://1.1.1.1:5353")?.host == "1.1.1.1"
                   && TraditionalDNSServer("udp://1.1.1.1:5353")?.port == 5353,
                   "传统 DNS UDP 地址/端口解析错误")
        try expect(TraditionalDNSServer("127.0.0.1")?.port == 53
                   && TraditionalDNSServer("udp://[::1]:5353")?.host == "::1",
                   "隔离测试的 loopback 地址不应被拒绝")
        for raw in ["system", "dns.google", "udp://dns.google:53", "https://1.1.1.1/dns-query",
                    "tls://1.1.1.1", "1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1:bad", "127.1",
                    "[1.1.1.1]:53", "0.0.0.0", "224.0.0.1", "::", "ff02::1",
                    "198.18.16.1", "198.18.16.2", "198.19.0.2",
                    "[fd00:6861:6a69::1]", "[::ffff:198.18.16.2]", "[::ffff:198.19.0.2]"] {
            try expect(TraditionalDNSServer(raw) == nil, "传统 DNS 非法/循环上游未被拒绝：\(raw)")
        }
    }

    private final class Clock {
        private let lock = NSLock()
        private var now = Date(timeIntervalSince1970: 1_000)
        func read() -> Date { lock.lock(); defer { lock.unlock() }; return now }
        func advance(_ seconds: TimeInterval) { lock.lock(); now.addTimeInterval(seconds); lock.unlock() }
    }

    private final class MemoryProvider {
        let issued = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private let hold: Bool, wrongID: Bool
        private let ttl: UInt32
        private var queries: [Data] = []
        private var callbacks: [(Data, (Result<Data, Error>) -> Void)] = []
        private var cancelledCount = 0
        init(hold: Bool = false, wrongID: Bool = false, ttl: UInt32 = 60) {
            self.hold = hold; self.wrongID = wrongID; self.ttl = ttl
        }
        var exchange: TraditionalDNSWireExchange {
            { [self] _, query, _, completion in
                lock.lock()
                queries.append(query)
                if hold { callbacks.append((query, completion)) }
                lock.unlock()
                if !hold { completion(result(query)) }
                issued.signal()
                return {
                    self.lock.lock(); self.cancelledCount += 1; self.lock.unlock()
                }
            }
        }
        private func result(_ query: Data) -> Result<Data, Error> {
            guard var response = TraditionalDNSBootstrapSelfTest.response(to: query, ttl: ttl) else {
                return .failure(TraditionalDNSBootstrapError.unavailable)
            }
            if wrongID { response[0] ^= 1 }
            return .success(response)
        }
        func releaseAll() {
            lock.lock(); let pending = callbacks; callbacks.removeAll(); lock.unlock()
            for (query, callback) in pending { callback(result(query)) }
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return queries.count }
        var cancellations: Int { lock.lock(); defer { lock.unlock() }; return cancelledCount }
        var names: [String] {
            lock.lock(); let snapshot = queries; lock.unlock()
            return snapshot.compactMap { DNSMessageInspection.singleQuestion(in: $0)?.name }
        }
    }

    private static func wait(
        _ issue: (@escaping (Result<[String], Error>) -> Void) -> UUID?
    ) throws -> Result<[String], Error> {
        let semaphore = DispatchSemaphore(value: 0), lock = NSLock()
        var result: Result<[String], Error>?
        _ = issue { lock.lock(); result = $0; lock.unlock(); semaphore.signal() }
        guard semaphore.wait(timeout: .now() + 3) == .success else {
            throw Failure(text: "DNS 内存/回环事务未在截止时间内完成")
        }
        lock.lock(); let answer = result; lock.unlock()
        guard let answer else { throw Failure(text: "DNS 请求缺少结果") }
        return answer
    }

    private static func failed(_ result: Result<[String], Error>) -> Bool {
        if case .failure = result { return true }
        return false
    }

    private static func purposeAndCache() throws {
        let provider = MemoryProvider(ttl: 2), clock = Clock()
        let resolver = TraditionalDNSBootstrapResolver(
            servers: ["127.0.0.1"], allowedDoHHosts: ["Bootstrap.Example."], timeout: 1,
            clock: clock.read, exchange: provider.exchange)
        defer { resolver.cancel() }
        let denied = try wait { resolver.resolveDoHHost("ordinary.application.example", queue: .global(), completion: $0) }
        try expect(failed(denied) && provider.count == 0, "传统 DNS 解析了非 DoH 白名单域名")
        let first = try wait { resolver.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }.get()
        try expect(first.contains("192.0.2.10") && first.contains("2001:db8::10") && provider.count == 2,
                   "DoH 专用 A/AAAA 引导未取得经过校验的地址")
        _ = try wait { resolver.resolveDoHHost("BOOTSTRAP.EXAMPLE.", queue: .global(), completion: $0) }.get()
        try expect(provider.count == 2, "DoH 引导 TTL 缓存未生效")
        clock.advance(3)
        _ = try wait { resolver.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }.get()
        try expect(provider.count == 4, "已过期的 DoH 引导 TTL 缓存仍被复用")
        _ = try wait { resolver.testConnectivity(queue: .global(), completion: $0) }.get()
        try expect(provider.names.suffix(2).allSatisfy({ $0 == "captive.apple.com" }),
                   "传统 DNS 连通性检查未使用固定域名")
        let before = provider.count
        _ = try wait { resolver.testConnectivity(queue: .global(), completion: $0) }.get()
        try expect(provider.count == before + 2, "连通性检查不应把历史缓存当成当前网络状态")

        let invalid = TraditionalDNSBootstrapResolver(
            servers: ["127.0.0.1", "system"], allowedDoHHosts: ["bootstrap.example"],
            timeout: 1, exchange: provider.exchange)
        let previous = provider.count
        let failure = try wait { invalid.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }
        try expect(failed(failure) && provider.count == previous,
                   "无效传统 DNS 项被静默丢弃后继续发起网络查询")
        invalid.cancel()
        let badAllowlist = TraditionalDNSBootstrapResolver(
            servers: ["127.0.0.1"], allowedDoHHosts: ["bootstrap.example", "not/a/host"],
            timeout: 1, exchange: provider.exchange)
        let invalidHost = try wait { badAllowlist.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }
        try expect(failed(invalidHost) && provider.count == previous, "非法 DoH 白名单被静默忽略")
        badAllowlist.cancel()
    }

    private final class PermissionGate {
        private let lock = NSLock()
        private var allowed = true
        func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
        func revoke() { lock.lock(); allowed = false; lock.unlock() }
    }

    private static func permissionRevocation() throws {
        let deniedGate = PermissionGate(); deniedGate.revoke()
        let neverIssued = MemoryProvider()
        let denied = TraditionalDNSBootstrapResolver(servers: ["127.0.0.1"], allowedDoHHosts: [],
            timeout: 1, exchange: neverIssued.exchange, permitted: deniedGate.permits)
        defer { denied.cancel() }
        let first = try wait { denied.testConnectivity(queue: .global(), completion: $0) }
        try expect(failed(first) && neverIssued.count == 0, "撤销许可后仍调用固定测试 wire")

        let gate = PermissionGate(), provider = MemoryProvider()
        let cached = TraditionalDNSBootstrapResolver(servers: ["127.0.0.1"], allowedDoHHosts: ["bootstrap.example"],
            timeout: 1, exchange: provider.exchange, permitted: gate.permits)
        defer { cached.cancel() }
        _ = try wait { cached.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }.get()
        gate.revoke()
        let stale = try wait { cached.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }
        try expect(failed(stale) && provider.count == 2, "撤销许可后交付旧缓存或发起新交换")

        let during = PermissionGate(), held = MemoryProvider(hold: true)
        let resolver = TraditionalDNSBootstrapResolver(servers: ["127.0.0.1", "127.0.0.2"], allowedDoHHosts: [],
            timeout: 1, exchange: held.exchange, permitted: during.permits)
        defer { resolver.cancel() }
        let completed = DispatchSemaphore(value: 0), lock = NSLock()
        var result: Result<[String], Error>?
        _ = resolver.testConnectivity(queue: .global()) {
            lock.lock(); result = $0; lock.unlock(); completed.signal()
        }
        try expect(held.issued.wait(timeout: .now() + 2) == .success
                   && held.issued.wait(timeout: .now() + 2) == .success, "内存撤销向量未启动 A/AAAA")
        during.revoke(); held.releaseAll()
        try expect(completed.wait(timeout: .now() + 2) == .success, "在途许可撤销未完成")
        lock.lock(); let failedAfterRevocation = result.map(failed) ?? false; lock.unlock()
        try expect(failedAfterRevocation && held.count == 2,
                   "撤销后接收成功结果或跨服务器继续发包")

        let lane = DispatchQueue(label: "app.hajimi.traditional-dns.revocation-selftest")
        let noSocket = DispatchSemaphore(value: 0)
        let transaction = TraditionalDNSNetworkExchange(server: TraditionalDNSServer("127.0.0.1")!,
            query: DNSMessageInspection.query(for: "captive.apple.com", type: 1)!, interface: nil,
            queue: lane, timeout: 1, permitted: { false }) { value in
                if failed(value.map { _ in [String]() }) { noSocket.signal() }
            }
        lane.async { transaction.start() }
        try expect(noSocket.wait(timeout: .now() + 2) == .success,
                   "实际 network exchange 未在建socket前拒绝已撤销许可")
    }

    private static func coalescingAndCancellation() throws {
        let provider = MemoryProvider(hold: true)
        let resolver = TraditionalDNSBootstrapResolver(
            servers: ["127.0.0.1"], allowedDoHHosts: ["bootstrap.example"],
            timeout: 1, exchange: provider.exchange)
        defer { resolver.cancel() }
        let firstDone = DispatchSemaphore(value: 0), secondDone = DispatchSemaphore(value: 0), lock = NSLock()
        var first: Result<[String], Error>?, second: Result<[String], Error>?
        guard let firstID = resolver.resolveDoHHost("bootstrap.example", queue: .global(), completion: {
            lock.lock(); first = $0; lock.unlock(); firstDone.signal()
        }), resolver.resolveDoHHost("bootstrap.example", queue: .global(), completion: {
            lock.lock(); second = $0; lock.unlock(); secondDone.signal()
        }) != nil else { throw Failure(text: "DNS 合并请求未被接收") }
        try expect(provider.issued.wait(timeout: .now() + 2) == .success
                   && provider.issued.wait(timeout: .now() + 2) == .success && provider.count == 2,
                   "相同 DoH 主机名未合并为一组 A/AAAA 查询")
        resolver.cancel(firstID)
        try expect(firstDone.wait(timeout: .now() + 2) == .success && provider.cancellations == 0,
                   "取消单个等待者误取消共用 DNS 传输")
        provider.releaseAll()
        try expect(secondDone.wait(timeout: .now() + 2) == .success, "剩余共用 DNS 等待者未收到应答")
        lock.lock(); let rejected = first.map(failed) ?? false; let kept = second; lock.unlock()
        try expect(rejected && (try? kept?.get().contains("192.0.2.10")) == true,
                   "DNS 合并请求取消隔离失败")
    }

    private static func failuresAndCapacity() throws {
        let wrong = MemoryProvider(wrongID: true)
        let mismatch = TraditionalDNSBootstrapResolver(
            servers: ["127.0.0.1"], allowedDoHHosts: ["bootstrap.example"],
            timeout: 1, exchange: wrong.exchange)
        let invalid = try wait { mismatch.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }
        try expect(failed(invalid) && wrong.count == 2, "错误 DNS 事务 ID 被用于 DoH 引导")
        mismatch.cancel()

        let silent = MemoryProvider(hold: true)
        let timeout = TraditionalDNSBootstrapResolver(
            servers: ["127.0.0.1"], allowedDoHHosts: ["bootstrap.example"],
            timeout: 0.025, exchange: silent.exchange)
        let timedOut = try wait { timeout.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }
        try expect(failed(timedOut) && silent.cancellations == 2, "传统 DNS 超时未取消全部传输")
        timeout.cancel()

        let provider = MemoryProvider(hold: true), pending = DispatchGroup()
        let bounded = TraditionalDNSBootstrapResolver(
            servers: ["127.0.0.1"], allowedDoHHosts: ["bootstrap.example"],
            timeout: 1, exchange: provider.exchange)
        for _ in 0..<128 {
            pending.enter()
            guard bounded.resolveDoHHost("bootstrap.example", queue: .global(), completion: { _ in pending.leave() }) != nil else {
                throw Failure(text: "传统 DNS 有界等待者未被接收")
            }
        }
        let extra = try wait { bounded.resolveDoHHost("bootstrap.example", queue: .global(), completion: $0) }
        try expect(failed(extra), "传统 DNS 第 129 个未完成请求未被拒绝")
        bounded.cancel()
        try expect(pending.wait(timeout: .now() + 2) == .success, "传统 DNS cancel 未结束所有等待者")
    }

    private static func response(to query: Data, ttl: UInt32 = 60, truncated: Bool = false) -> Data? {
        guard let question = DNSMessageInspection.singleQuestion(in: query),
              question.type == 1 || question.type == 28 else { return nil }
        var reply = Data(query.prefix(question.questionEnd))
        reply[2] = 0x80 | (query[query.startIndex + 2] & 1) | (truncated ? 2 : 0)
        reply[3] = 0x80
        for index in 6..<12 { reply[index] = 0 }
        if truncated { return reply }
        reply[7] = 1
        let address: [UInt8] = question.type == 1 ? [192, 0, 2, 10]
            : [0x20, 0x01, 0x0d, 0xb8] + Array(repeating: 0, count: 11) + [0x10]
        reply.append(contentsOf: [0xC0, 12, 0, UInt8(question.type), 0, 1,
                                  UInt8(truncatingIfNeeded: ttl >> 24),
                                  UInt8(truncatingIfNeeded: ttl >> 16),
                                  UInt8(truncatingIfNeeded: ttl >> 8), UInt8(truncatingIfNeeded: ttl),
                                  0, UInt8(address.count)])
        reply.append(contentsOf: address)
        return reply
    }

    private static func loopbackTruncation() throws {
        final class ListenerProbe {
            let terminal = DispatchSemaphore(value: 0)
            private let lock = NSLock()
            private var state: NWListener.State = .setup
            private var cancelCalls = 0, cancelledCallbacks = 0
            private var firstCancelCallAt: UInt64?, firstCancelledCallbackAt: UInt64?
            func record(_ value: NWListener.State) {
                let now = DispatchTime.now().uptimeNanoseconds
                lock.lock()
                state = value
                if case .cancelled = value {
                    cancelledCallbacks += 1
                    if firstCancelledCallbackAt == nil { firstCancelledCallbackAt = now }
                }
                lock.unlock()
                switch value {
                case .ready, .failed, .cancelled: terminal.signal()
                case .waiting(let error):
                    if case .posix(.EADDRINUSE) = error { terminal.signal() }
                default: break
                }
            }
            func cancel(_ listener: NWListener) {
                let now = DispatchTime.now().uptimeNanoseconds
                lock.lock()
                cancelCalls += 1
                if firstCancelCallAt == nil { firstCancelCallAt = now }
                lock.unlock()
                listener.cancel()
            }
            func snapshot() -> NWListener.State {
                lock.lock(); defer { lock.unlock() }; return state
            }
            func diagnostics() -> String {
                lock.lock(); defer { lock.unlock() }
                // These are API-call and actual NWListener state-callback
                // receipts, not acknowledgements of kernel or peer closure.
                return "state=\(state), cancelCalls=\(cancelCalls), cancelledCallbacks=\(cancelledCallbacks), firstCancelCallNs=\(firstCancelCallAt.map { String($0) } ?? "none"), firstCancelledCallbackNs=\(firstCancelledCallbackAt.map { String($0) } ?? "none")"
            }
        }
        final class ListenerAttempt {
            let index: Int, requestedTCP: UInt16, tcp: ListenerProbe
            var actualTCP: UInt16?, requestedUDP: UInt16?, actualUDP: UInt16?, blockedPort: UInt16?
            var udp: ListenerProbe?, blocker: ListenerProbe?
            var stage = "TCP", errorText: String?, tcpStateAtError: String?, udpStateAtError: String?
            init(index: Int, requestedTCP: UInt16, tcp: ListenerProbe) {
                self.index = index; self.requestedTCP = requestedTCP; self.tcp = tcp
            }
            private static func port(_ value: UInt16?) -> String {
                value.map { String($0) } ?? "none"
            }
            func diagnostics() -> String {
                let requested = requestedTCP == 0 ? "any(0)" : String(requestedTCP)
                return "attempt \(index) [\(stage)]: \(errorText ?? "ready pair"); TCP requested=\(requested), actual=\(Self.port(actualTCP)); UDP requested=\(Self.port(requestedUDP)), actual=\(Self.port(actualUDP)); blockedUDP=\(Self.port(blockedPort)); TCP-at-error=\(tcpStateAtError ?? "none"), UDP-at-error=\(udpStateAtError ?? "none"); TCP(\(tcp.diagnostics())); UDP(\(udp?.diagnostics() ?? "not-created")); blocker(\(blocker?.diagnostics() ?? "not-created"))"
            }
        }
        let queue = DispatchQueue(label: "app.hajimi.traditional-dns.loopback-selftest")
        let lock = NSLock()
        var connections: [NWConnection] = []
        var udpQuestions = 0, tcpQuestions = 0
        var tcpProbe: ListenerProbe?, udpProbe: ListenerProbe?, blockerProbe: ListenerProbe?
        var attempts: [ListenerAttempt] = [], phase = "listener setup"
        var blockers: [(listener: NWListener, probe: ListenerProbe)] = [], blockedPort: NWEndpoint.Port?
        var failedUDPAfterReadyTCP = false
        // Registered before cleanup, so at most four passive diagnostic lines
        // include the original cancel calls without adding any wait for callbacks.
        defer {
            lock.lock(); let udpCount = udpQuestions, tcpCount = tcpQuestions; lock.unlock()
            for attempt in attempts {
                print("Traditional DNS loopback fixture: \(attempt.diagnostics()); queries UDP=\(udpCount), TCP=\(tcpCount)")
            }
        }
        defer { lock.lock(); let active = connections; lock.unlock(); active.forEach { $0.cancel() } }
        defer { blockers.forEach { $0.probe.cancel($0.listener) } }

        func waitReady(_ listener: NWListener, probe: ListenerProbe, name: String) throws -> NWEndpoint.Port {
            listener.stateUpdateHandler = probe.record
            listener.start(queue: queue)
            guard probe.terminal.wait(timeout: .now() + 2) == .success else {
                throw Failure(text: "\(name) listener readiness timeout: \(probe.snapshot())")
            }
            switch probe.snapshot() {
            case .ready:
                guard let port = listener.port, port.rawValue > 0 else {
                    throw Failure(text: "\(name) ready listener has no bound port")
                }
                return port
            case .failed(let error): throw error
            case .waiting(let error): throw error
            default: throw Failure(text: "\(name) listener is not ready: \(probe.snapshot())")
            }
        }

        func read(_ connection: NWConnection, buffer: Data) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_537 - buffer.count) {
                data, _, complete, error in
                guard error == nil else { connection.cancel(); return }
                var next = buffer
                if let data { next.append(data) }
                if next.count >= 2 {
                    let length = Int(next[next.startIndex]) << 8 | Int(next[next.startIndex + 1])
                    if next.count == length + 2, let reply = response(to: Data(next.dropFirst(2))) {
                        lock.lock(); tcpQuestions += 1; lock.unlock()
                        var wire = Data([UInt8(reply.count >> 8), UInt8(reply.count & 255)])
                        wire.append(reply)
                        connection.send(content: Data(wire.prefix(1)), completion: .contentProcessed { error in
                            if error != nil { connection.cancel(); return }
                            connection.send(content: Data(wire.dropFirst()), completion: .contentProcessed { _ in
                                connection.cancel()
                            })
                        })
                        return
                    }
                    if length < 12 || next.count > length + 2 { connection.cancel(); return }
                }
                if complete { connection.cancel() }
                else { read(connection, buffer: next) }
            }
        }

        func makePair(maxAttempts: Int, afterTCPReady: ((NWEndpoint.Port) throws -> Void)? = nil) throws
            -> (tcp: NWListener, udp: NWListener, port: NWEndpoint.Port, attempt: Int,
                tcpProbe: ListenerProbe, udpProbe: ListenerProbe) {
            guard (1...4).contains(maxAttempts) else { throw Failure(text: "invalid fixture retry bound") }
            var lastError: Error = Failure(text: "no listener pair")
            var candidates = ListenerPortCandidates()
            for attempt in 1...maxAttempts {
                guard let requestedTCP = candidates.next(blockedPort: blockedPort?.rawValue) else {
                    throw Failure(text: "bounded fixture TCP candidate missing")
                }
                let requestedPort: NWEndpoint.Port
                if requestedTCP == 0 { requestedPort = .any }
                else if let port = NWEndpoint.Port(rawValue: requestedTCP) { requestedPort = port }
                else { throw Failure(text: "invalid explicit fixture TCP candidate") }
                let currentTCP = ListenerProbe()
                let receipt = ListenerAttempt(index: attempt, requestedTCP: requestedTCP, tcp: currentTCP)
                receipt.blockedPort = blockedPort?.rawValue; receipt.blocker = blockerProbe
                attempts.append(receipt)
                tcpProbe = currentTCP; udpProbe = nil
                var tcp: NWListener?, udp: NWListener?, keep = false
                var currentUDP: ListenerProbe?
                var candidatePort: NWEndpoint.Port?, stage = "TCP"
                defer {
                    if !keep {
                        if let udp, let currentUDP { currentUDP.cancel(udp) }
                        if let tcp { currentTCP.cancel(tcp) }
                    }
                }
                do {
                    let tcpParameters = NWParameters.tcp
                    tcpParameters.allowLocalEndpointReuse = false
                    tcpParameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: requestedPort)
                    let candidateTCP = try NWListener(using: tcpParameters); tcp = candidateTCP
                    candidateTCP.newConnectionHandler = { connection in
                        lock.lock(); connections.append(connection); lock.unlock()
                        connection.start(queue: queue); read(connection, buffer: Data())
                    }
                    // Reserve the actual TCP port first. An independently
                    // occupied UDP port must reject this pair, never count as ready.
                    let port = try waitReady(candidateTCP, probe: currentTCP, name: "TCP")
                    candidatePort = port; receipt.actualTCP = port.rawValue
                    try candidates.recordActual(port.rawValue)
                    try expect(requestedTCP == 0 || port.rawValue == requestedTCP,
                               "ready TCP listener did not bind its explicit requested port")
                    stage = "UDP blocker hook"
                    try afterTCPReady?(port)
                    receipt.blockedPort = blockedPort?.rawValue; receipt.blocker = blockerProbe
                    stage = "UDP"
                    let candidateUDPProbe = ListenerProbe()
                    currentUDP = candidateUDPProbe; udpProbe = candidateUDPProbe; receipt.udp = candidateUDPProbe
                    receipt.requestedUDP = port.rawValue
                    let udpParameters = NWParameters.udp
                    udpParameters.allowLocalEndpointReuse = false
                    udpParameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: port)
                    let candidateUDP = try NWListener(using: udpParameters); udp = candidateUDP
                    candidateUDP.newConnectionHandler = { connection in
                        lock.lock(); connections.append(connection); lock.unlock()
                        connection.start(queue: queue)
                        connection.receiveMessage { data, _, _, _ in
                            guard let data, let reply = response(to: data, truncated: true) else {
                                connection.cancel(); return
                            }
                            lock.lock(); udpQuestions += 1; lock.unlock()
                            connection.send(content: reply, contentContext: .defaultMessage, isComplete: true,
                                            completion: .contentProcessed { _ in connection.cancel() })
                        }
                    }
                    let udpPort = try waitReady(candidateUDP, probe: candidateUDPProbe, name: "UDP")
                    receipt.actualUDP = udpPort.rawValue
                    try expect(udpPort == port, "TCP/UDP listener pair did not bind the same port")
                    receipt.stage = "paired"
                    keep = true
                    return (candidateTCP, candidateUDP, port, attempt, currentTCP, candidateUDPProbe)
                } catch {
                    receipt.stage = stage; receipt.errorText = String(describing: error)
                    receipt.blockedPort = blockedPort?.rawValue; receipt.blocker = blockerProbe
                    receipt.tcpStateAtError = String(describing: tcpProbe?.snapshot())
                    receipt.udpStateAtError = String(describing: udpProbe?.snapshot())
                    lastError = error
                    // Retry only a genuine bind collision. Once an actual TCP
                    // port is known, explicitly exclude previous requests,
                    // actual ports and the still-live UDP blocker.
                    guard let networkError = error as? NWError,
                          case .posix(.EADDRINUSE) = networkError else { throw error }
                    if stage == "UDP", let candidatePort, candidatePort == blockedPort,
                       let currentTCP = tcpProbe, case .ready = currentTCP.snapshot(),
                       let currentUDP = udpProbe {
                        switch currentUDP.snapshot() {
                        case .failed(let error), .waiting(let error):
                            if case .posix(.EADDRINUSE) = error { failedUDPAfterReadyTCP = true }
                        default: break
                        }
                    }
                }
            }
            throw lastError
        }

        do {
            phase = "forced UDP collision and bounded listener-pair retry"
            let pair = try makePair(maxAttempts: 4, afterTCPReady: { port in
                guard blockedPort == nil else { return }
                let blockedParameters = NWParameters.udp
                blockedParameters.allowLocalEndpointReuse = false
                blockedParameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: port)
                let currentBlocker = ListenerProbe(); blockerProbe = currentBlocker
                let blocker = try NWListener(using: blockedParameters)
                var keep = false
                defer { if !keep { currentBlocker.cancel(blocker) } }
                blocker.newConnectionHandler = { $0.cancel() }
                let bound = try waitReady(blocker, probe: currentBlocker, name: "UDP blocker")
                try expect(bound == port, "UDP conflict blocker did not bind the ready TCP port")
                blockers.append((blocker, currentBlocker)); blockedPort = port; keep = true
            })
            defer { pair.udpProbe.cancel(pair.udp); pair.tcpProbe.cancel(pair.tcp) }
            try expect(failedUDPAfterReadyTCP && blockedPort != nil
                       && pair.attempt > 1 && pair.port != blockedPort,
                       "forced UDP failure after ready TCP was not observed or was accepted as ready")
            phase = "validated TC to TCP exchange"
            let resolver = TraditionalDNSBootstrapResolver(
                servers: ["udp://127.0.0.1:\(pair.port.rawValue)"], allowedDoHHosts: ["bootstrap.selftest.invalid"])
            defer { resolver.cancel() }
            let addresses = try wait {
                resolver.resolveDoHHost("bootstrap.selftest.invalid", queue: .global(), completion: $0)
            }.get()
            lock.lock(); let udpCount = udpQuestions, tcpCount = tcpQuestions; lock.unlock()
            try expect(addresses.contains("192.0.2.10") && addresses.contains("2001:db8::10")
                       && udpCount == 2 && tcpCount == 2, "有效 TC 应答未仅向同一 loopback 上游回退 TCP")
        } catch {
            lock.lock(); let udpCount = udpQuestions, tcpCount = tcpQuestions; lock.unlock()
            throw Failure(text: "loopbackTruncation [\(phase)]: \(error.localizedDescription); UDP=\(udpCount), TCP=\(tcpCount); TCP-state=\(String(describing: tcpProbe?.snapshot())), UDP-state=\(String(describing: udpProbe?.snapshot())), blocker-state=\(String(describing: blockerProbe?.snapshot())); listener-attempts=\(attempts.count) (bounded port/callback diagnostics emitted separately)")
        }
    }
}

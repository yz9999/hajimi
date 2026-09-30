import Foundation
import HajimiProtocolsCXX
import HajimiCXXProtocolBridge

/// Configuration and ownership only. All supported proxy handshakes, payload
/// authentication/encryption, framing and protocol sessions live in C++.
enum NativeCXXOutbound {
    private struct Configuration: Encodable {
        let type: String
        let name: String
        let host: String
        let port: UInt16
        let parameters: [String: String]
    }
    private struct Entry {
        let policy: ProxyPolicy
        let interfaceName: String?
        let client: HJCppProtocolClient
    }
    private struct ValidationResult {
        let error: String?
    }
    private struct ValidationEntry {
        let policy: ProxyPolicy
        var retainedBytes: Int
        var tcp: ValidationResult?
        var udp: ValidationResult?
    }
    private static let lock = NSLock()
    private static var clients: [String: Entry] = [:]
    private static var validations: [String: ValidationEntry] = [:]
    private static var validationBytes = 0
    private static let maximumValidationEntryBytes = 64 * 1_024
    private static let maximumValidationBytes = 8 * 1_024 * 1_024

    private static func validationCacheCost(_ policy: ProxyPolicy) -> Int? {
        // Count all retained fields, including credentials overridden by
        // parameters and adapterType omitted from a protocol's encoded form.
        // Per-entry/string allowances also bound many tiny parameter objects.
        var bytes = 256
        func retain(_ text: String?) -> Bool {
            guard let text else { return true }
            let count = text.utf8.count
            guard count <= maximumValidationEntryBytes - bytes - 32 else { return false }
            bytes += count + 32; return true
        }
        for text in [policy.name, policy.host, policy.username, policy.password, policy.adapterType] {
            guard retain(text) else { return nil }
        }
        for (key, value) in policy.parameters {
            guard bytes <= maximumValidationEntryBytes - 64 else { return nil }
            bytes += 64
            guard retain(key), retain(value) else { return nil }
        }
        return bytes
    }

    private static func configuration(_ policy: ProxyPolicy) throws -> Data {
        guard let host = policy.host, let port = policy.port else {
            throw NativeOutboundError.unsupported("C++ 协议节点缺少服务器或端口")
        }
        let type: String
        switch policy.kind {
        case .http: type = policy.adapterType?.lowercased() == "https" ? "https" : "http"
        case .socks5: type = policy.adapterType?.lowercased() == "socks5-tls" ? "socks5-tls" : "socks5"
        default: type = policy.adapterType?.lowercased() ?? ""
        }
        var parameters = policy.parameters
        if parameters["username"] == nil { parameters["username"] = policy.username }
        if parameters["password"] == nil { parameters["password"] = policy.password }
        if ["1", "true", "yes", "on"].contains(parameters["ws"]?.lowercased() ?? "") {
            parameters["network"] = "ws"
        }
        return try JSONEncoder().encode(Configuration(type: type, name: policy.name, host: host,
                                                       port: port, parameters: parameters))
    }

    static func validationError(for policy: ProxyPolicy, udp: Bool = false) -> String? {
        lock.lock()
        if let cached = validations[policy.name], cached.policy == policy,
           let result = udp ? cached.udp : cached.tcp {
            lock.unlock(); return result.error
        }
        lock.unlock()
        let result: ValidationResult
        do {
            result = ValidationResult(error: HJCppProtocolClient.validationError(
                configuration: try configuration(policy), udp: udp)?.localizedDescription)
        } catch { result = ValidationResult(error: error.localizedDescription) }
        // These checks inspect configuration only, not mutable files or network
        // state. Large inline keys/configurations are validated normally but do
        // not extend their lifetime via the UI cache.
        guard let policyBytes = validationCacheCost(policy) else { return result.error }
        lock.lock()
        var cached = validations[policy.name].flatMap { $0.policy == policy ? $0 : nil }
            ?? ValidationEntry(policy: policy, retainedBytes: policyBytes)
        if udp { cached.udp = result } else { cached.tcp = result }
        cached.retainedBytes = policyBytes + (cached.tcp?.error?.utf8.count ?? 0)
            + (cached.udp?.error?.utf8.count ?? 0)
        guard cached.retainedBytes <= maximumValidationEntryBytes else {
            lock.unlock(); return result.error
        }
        let previousBytes = validations[policy.name]?.retainedBytes ?? 0
        if (validations.count >= 1_024 && validations[policy.name] == nil)
            || cached.retainedBytes > maximumValidationBytes - (validationBytes - previousBytes) {
            validations.removeAll(); validationBytes = 0
        }
        let stale = validations.updateValue(cached, forKey: policy.name)
        validationBytes += cached.retainedBytes - (stale?.retainedBytes ?? 0)
        lock.unlock()
        return result.error
    }

    static func selfTest() throws {
        guard hajimi_cpp_protocol_self_test() == 0 else {
            throw NativeOutboundError.protocolError("C++ 协议与加密已知答案自检失败")
        }
    }

    static func configure(policies: [String: ProxyPolicy]) {
        lock.lock()
        let stale = clients.filter { policies[$0.key] != $0.value.policy }
        for (name, _) in stale { clients.removeValue(forKey: name) }
        validations = validations.filter { policies[$0.key] == $0.value.policy }
        validationBytes = validations.values.reduce(0) { $0 + $1.retainedBytes }
        lock.unlock()
        stale.values.forEach { $0.client.cancel() }
    }

    private static func client(for policy: ProxyPolicy, queue: DispatchQueue,
                               preparedDialer: HJCppTransportDialer?) throws -> HJCppProtocolClient {
        let interface = ProxyEngine.currentOutboundInterface?.name
        lock.lock()
        if let existing = clients[policy.name], existing.policy == policy,
           existing.interfaceName == interface {
            lock.unlock(); return existing.client
        }
        lock.unlock()
        let client = try HJCppProtocolClient(configuration: configuration(policy), interfaceName: interface,
                                             queue: queue, preparedTransportDialer: preparedDialer)
        lock.lock()
        if let existing = clients[policy.name], existing.policy == policy,
           existing.interfaceName == interface {
            lock.unlock(); client.cancel(); return existing.client
        }
        let stale = clients.updateValue(Entry(policy: policy, interfaceName: interface, client: client),
                                         forKey: policy.name)
        lock.unlock(); stale?.client.cancel()
        return client
    }

    static func connect(policy: ProxyPolicy, target: RequestTarget, plainHTTP: Bool = false,
                        queue: DispatchQueue, preparedDialer: HJCppTransportDialer? = nil,
                        completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        do {
            let owner = try client(for: policy, queue: queue, preparedDialer: preparedDialer)
            owner.connect(host: target.host, port: target.port, udp: target.protocolName.uppercased() == "UDP",
                          plainHTTP: plainHTTP) { stream, error in
                queue.async {
                    if let error { completion(.failure(error)) }
                    else if let stream { completion(.success(NativeCXXByteStream(stream, owner: owner))) }
                    else { completion(.failure(NativeOutboundError.connection("C++ 引擎未返回连接"))) }
                }
            }
        } catch { completion(.failure(error)) }
    }

    static func makeDatagramSession(policy: ProxyPolicy, queue: DispatchQueue,
                                    preparedDialer: HJCppTransportDialer? = nil,
                                    receive: @escaping (RequestTarget, Data) -> Void,
                                    failure: @escaping (Error) -> Void) throws -> NativeOutboundDatagramSession {
        if let error = validationError(for: policy, udp: true) {
            throw NativeOutboundError.unsupported(error)
        }
        return try NativeCXXDatagramSession(owner: client(for: policy, queue: queue,
                                                          preparedDialer: preparedDialer),
                                            queue: queue, receive: receive, failure: failure)
    }
}

final class NativeCXXByteStream: NativeOutboundByteStream {
    let native: HJCppByteStream
    private let owner: HJCppProtocolClient
    init(_ native: HJCppByteStream, owner: HJCppProtocolClient) { self.native = native; self.owner = owner }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) { native.sendData(data, completion: completion) }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        native.receiveData(maximum: UInt(clamping: maximum), completion: completion)
    }
    func cancel() { native.cancel() }
}

private final class NativeCXXDatagramSession: NativeOutboundDatagramSession {
    private let owner: HJCppProtocolClient
    private let queue: DispatchQueue
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private let admission = NSLock()
    private var reservedBytes = 0
    private var reservedRequests = 0
    private var admissionClosed = false
    private var handle: HJCppDatagramSession?
    private var pending: [(Data, RequestTarget)] = []
    private var head = 0
    private var sending = false
    private var cancelled = false

    init(owner: HJCppProtocolClient, queue: DispatchQueue,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) throws {
        self.owner = owner
        self.queue = DispatchQueue(label: "app.hajimi.cpp-datagram.adapter", target: queue)
        receiveHandler = receive; failureHandler = failure
        owner.createDatagramSession(receive: { [weak self] host, port, payload in
            self?.queue.async { [weak self] in
                guard let self, !self.cancelled else { return }
                self.receiveHandler(RequestTarget(host: host, port: port, protocolName: "UDP"), payload)
            }
        }, failure: { [weak self] error in
            if let error { self?.queue.async { [weak self] in self?.fail(error) } }
        }, completion: { [weak self] handle, error in
            guard let self else { handle?.cancel(); return }
            self.queue.async {
                if self.cancelled { handle?.cancel(); return }
                if let error { self.fail(error) }
                else if let handle { self.handle = handle; self.flush() }
                else { self.fail(NativeOutboundError.connection("C++ 引擎未返回 UDP 会话")) }
            }
        })
    }

    func send(_ payload: Data, to target: RequestTarget) {
        admission.lock()
        guard !admissionClosed, reservedRequests < 512,
              payload.count <= 65_535, payload.count <= 2 * 1_024 * 1_024 - reservedBytes else {
            admission.unlock(); return // Bounded UDP admission: drop under pressure.
        }
        reservedBytes += payload.count; reservedRequests += 1; admission.unlock()
        queue.async {
            guard !self.cancelled else { self.release(payload.count); return }
            self.pending.append((payload, target)); self.flush()
        }
    }
    private func release(_ bytes: Int) {
        admission.lock(); reservedBytes -= bytes; reservedRequests -= 1; admission.unlock()
    }
    private func flush() {
        guard !cancelled, !sending, let handle, head < pending.count else { return }
        let item = pending[head]; sending = true
        handle.send(item.0, host: item.1.host, port: item.1.port) { [weak self] error in
            self?.queue.async { [weak self] in
                guard let self, !self.cancelled else { return }
                self.sending = false; self.release(item.0.count)
                self.head += 1
                if self.head == self.pending.count { self.pending.removeAll(keepingCapacity: true); self.head = 0 }
                else if self.head >= 64 { self.pending.removeFirst(self.head); self.head = 0 }
                if let error { self.fail(error) } else { self.flush() }
            }
        }
    }
    private func stop() {
        guard !cancelled else { return }
        cancelled = true; admission.lock(); admissionClosed = true; admission.unlock()
        for item in pending.dropFirst(head) { release(item.0.count) }
        pending.removeAll(); head = 0; handle?.cancel(); handle = nil
    }
    private func fail(_ error: Error) {
        guard !cancelled else { return }; stop(); failureHandler(error)
    }
    func cancel() { queue.async { self.stop() } }
    deinit { handle?.cancel() }
}

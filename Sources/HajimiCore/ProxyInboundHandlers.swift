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

enum OutboundInterfaceBinding {
    private static let lock = NSLock()
    private static var value: NWInterface?
    private static var knownInterfaces: [String: NWInterface] = [:]

    static var current: NWInterface? {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    static func set(_ interface: NWInterface?) {
        lock.lock()
        value = interface
        if let interface { knownInterfaces[interface.name] = interface }
        lock.unlock()
        NativeOutboundFactory.invalidateForNetworkChange()
    }

    static func flushKnownInterfaces() {
        lock.lock()
        knownInterfaces = knownInterfaces.filter { name, iface in
            let currentIdx = Int(name.withCString { if_nametoindex($0) })
            return currentIdx > 0 && currentIdx == iface.index
        }
        lock.unlock()
    }

    private static func cachedInterface(named name: String, index: Int) -> NWInterface? {
        guard index > 0 else { return nil }
        lock.lock(); defer { lock.unlock() }
        if let existing = value, existing.name == name, existing.index == index {
            return existing
        }
        if let known = knownInterfaces[name], known.index == index {
            return known
        }
        return nil
    }

    static func resolve(name: String, completion: @escaping (Result<Void, Error>) -> Void) {
        let kernelIndex = Int(name.withCString { if_nametoindex($0) })
        if let cached = cachedInterface(named: name, index: kernelIndex) {
            set(cached)
            completion(.success(()))
            return
        }
        let physicalMonitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        let fallbackMonitor = NWPathMonitor()
        let queue = DispatchQueue(label: "app.hajimi.interface-resolver", qos: .userInitiated)
        var completed = false
        let handlePath: (NWPath) -> Void = { path in
            guard !completed else { return }
            lock.lock()
            for iface in path.availableInterfaces {
                knownInterfaces[iface.name] = iface
            }
            lock.unlock()
            if let interface = path.availableInterfaces.first(where: { $0.name == name }) {
                completed = true
                physicalMonitor.cancel()
                fallbackMonitor.cancel()
                set(interface)
                completion(.success(()))
                return
            }
            let currentIdx = Int(name.withCString { if_nametoindex($0) })
            if let cached = cachedInterface(named: name, index: currentIdx) {
                completed = true
                physicalMonitor.cancel()
                fallbackMonitor.cancel()
                set(cached)
                completion(.success(()))
            }
        }
        physicalMonitor.pathUpdateHandler = handlePath
        fallbackMonitor.pathUpdateHandler = handlePath
        physicalMonitor.start(queue: queue)
        fallbackMonitor.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 1.2) {
            guard !completed else { return }
            completed = true
            physicalMonitor.cancel()
            fallbackMonitor.cancel()
            let currentIdx = Int(name.withCString { if_nametoindex($0) })
            if let cached = cachedInterface(named: name, index: currentIdx) {
                set(cached)
                completion(.success(()))
                return
            }
            completion(.failure(EngineError("找不到物理网络接口 \(name)")))
        }
    }
}

protocol CancellableConnectionHandler: AnyObject {
    func cancel()
}

final class ConnectionReader {
    private let connection: any OutboundByteStream
    private var buffer = Data()
    private var ended = false

    init(_ connection: NWConnection) { self.connection = NetworkOutboundByteStream(connection) }
    init(_ connection: any OutboundByteStream) { self.connection = connection }

    static func headerBoundarySelfTest() -> String? {
        final class Fixture: NativeOutboundByteStream {
            var chunks: [Data]
            init(_ chunks: [Data]) { self.chunks = chunks }
            func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
            func cancel() {}
            func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
                guard !chunks.isEmpty else { completion(nil, true, nil); return }
                let chunk = chunks.removeFirst()
                guard chunk.count <= maximum else { completion(nil, true, EngineError("fixture exceeded raw read limit")); return }
                completion(chunk, false, nil)
            }
        }
        let marker = Data("\r\n\r\n".utf8)
        var oversized: Result<(Data, Data), Error>?
        let bad = ConnectionReader(Fixture([Data(repeating: 97, count: 65_520),
                                           Data(repeating: 97, count: 20) + marker]))
        bad.readUntil(marker, maximum: 65_536) { oversized = $0 }
        guard case .failure(let error)? = oversized,
              error.localizedDescription.contains("65536") else {
            return "split oversized complete header escaped its 64 KiB bound"
        }
        let body = Data(repeating: 98, count: 60_000)
        var valid: Result<(Data, Data), Error>?
        let good = ConnectionReader(Fixture([Data(repeating: 97, count: 40_000), marker + body]))
        good.readUntil(marker, maximum: 65_536) { valid = $0 }
        guard case .success(let pair)? = valid, pair.0.count == 40_004, pair.1 == body else {
            return "legal body remainder was counted as oversized header"
        }
        return nil
    }

    func takeBufferedData() -> Data {
        let data = buffer
        buffer.removeAll(keepingCapacity: false)
        return data
    }

    func readExactly(_ count: Int, completion: @escaping (Result<Data, Error>) -> Void) {
        guard count >= 0 else { completion(.failure(EngineError("读取长度无效"))); return }
        if buffer.count >= count {
            let result = Data(buffer.prefix(count))
            buffer.removeFirst(count)
            completion(.success(result))
            return
        }
        receive { [weak self] result in
            switch result {
            case .success:
                self?.readExactly(count, completion: completion)
            case .failure(let error): completion(.failure(error))
            }
        }
    }

    func readUntil(_ marker: Data, maximum: Int,
                   completion: @escaping (Result<(Data, Data), Error>) -> Void) {
        if let range = buffer.range(of: marker) {
            let end = range.upperBound
            guard end <= maximum else {
                completion(.failure(EngineError("请求头超过 \(maximum) 字节")))
                return
            }
            let head = Data(buffer[..<end])
            let remainder = Data(buffer[end...])
            buffer.removeAll(keepingCapacity: false)
            completion(.success((head, remainder)))
            return
        }
        if buffer.count >= maximum {
            completion(.failure(EngineError("请求头超过 \(maximum) 字节")))
            return
        }
        receive { [weak self] result in
            switch result {
            case .success: self?.readUntil(marker, maximum: maximum, completion: completion)
            case .failure(let error): completion(.failure(error))
            }
        }
    }

    private func receive(completion: @escaping (Result<Void, Error>) -> Void) {
        guard !ended else { completion(.failure(EngineError("连接已关闭"))); return }
        connection.receive(maximum: 65_536) { [weak self] data, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.buffer.append(data) }
            if let error {
                self.ended = true
                completion(.failure(error))
            } else if complete && (data == nil || data!.isEmpty) {
                self.ended = true
                completion(.failure(EngineError("连接已关闭")))
            } else {
                completion(.success(()))
            }
        }
    }
}

func send(_ data: Data, to connection: NWConnection,
                  completion: @escaping (Error?) -> Void) {
    connection.send(content: data, completion: .contentProcessed { error in completion(error) })
}

func send(_ data: Data, to connection: any OutboundByteStream,
                  completion: @escaping (Error?) -> Void) {
    connection.send(data, completion: completion)
}

/// Retain an in-flight connection until it becomes ready, then release the
/// callback and state handler immediately. TLS timeout closures capture this
/// attempt weakly so busy proxy workloads do not retain every finished socket
/// until the 12-second deadline expires.
final class TCPConnectionAttempt {
    private var connection: NWConnection?
    private var completion: ((Result<NWConnection, Error>) -> Void)?

    init(connection: NWConnection,
         completion: @escaping (Result<NWConnection, Error>) -> Void) {
        self.connection = connection
        self.completion = completion
    }

    func finish(_ result: Result<NWConnection, Error>, cancel: Bool = false) {
        guard let callback = completion else { return }
        completion = nil
        let value = connection
        connection = nil
        value?.stateUpdateHandler = nil
        if cancel { value?.cancel() }
        callback(result)
    }
}

func connectTCP(host: String, port: UInt16,
                        tls: Bool = false, serverName: String? = nil,
                        skipCertificateVerification: Bool = false, alpn: [String] = [],
                        queue: DispatchQueue,
                        completion: @escaping (Result<NWConnection, Error>) -> Void) {
    guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
        completion(.failure(EngineError("端口无效")))
        return
    }
    let parameters: NWParameters
    if tls {
        let options = NWProtocolTLS.Options()
        // Without a custom verify block, Network.framework validates the
        // certificate chain and hostname using the server name below.
        let rawSNI = serverName?.isEmpty == false ? serverName! : host
        var cleanSNI = DoHEndpoint.unbracketed(rawSNI)
        if cleanSNI.contains(":"), let pct = cleanSNI.firstIndex(of: "%") { cleanSNI = String(cleanSNI[..<pct]) }
        sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, cleanSNI)
        alpn.forEach {
            sec_protocol_options_add_tls_application_protocol(options.securityProtocolOptions, $0)
        }
        if skipCertificateVerification {
            sec_protocol_options_set_verify_block(options.securityProtocolOptions,
                                                   { _, _, complete in complete(true) }, queue)
        }
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        tcpOptions.disableAckStretching = true
        parameters = NWParameters(tls: options, tcp: tcpOptions)
    } else {
        parameters = .tcp
        if let tcpOptions = parameters.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
            tcpOptions.noDelay = true
            tcpOptions.disableAckStretching = true
        }
    }
    if !isLoopbackHost(host) { parameters.requiredInterface = OutboundInterfaceBinding.current }
    let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: parameters)
    let attempt = TCPConnectionAttempt(connection: connection, completion: completion)
    connection.stateUpdateHandler = { [attempt] state in
        switch state {
        case .ready:
            attempt.finish(.success(connection))
        case .failed(let error):
            attempt.finish(.failure(error), cancel: true)
        case .waiting(let error):
            if case .tls = error { attempt.finish(.failure(error), cancel: true) }
        case .cancelled:
            attempt.finish(.failure(EngineError("出站连接已取消")))
        default: break
        }
    }
    connection.start(queue: queue)
    if tls {
        queue.asyncAfter(deadline: .now() + 12) { [weak attempt] in
            attempt?.finish(.failure(EngineError("出站 TLS 握手超时")), cancel: true)
        }
    }
}

/// Internal rather than private so the policy health monitor can dial a
/// candidate through the exact same path a real request would take. Probing a
/// member any other way would measure something the user never experiences.
enum TunnelConnector {
    static func connect(route: ResolvedRoute, target: RequestTarget, plainHTTP: Bool,
                        queue: DispatchQueue,
                        recordSetup: Bool = true,
                        completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        _ = beginConnect(route: route, target: target, plainHTTP: plainHTTP,
                         queue: queue, recordSetup: recordSetup, completion: completion)
    }

    @discardableResult
    static func beginConnect(route: ResolvedRoute, target: RequestTarget, plainHTTP: Bool,
                             queue: DispatchQueue,
                             waitForSetupAcknowledgement: Bool = false,
                             recordSetup: Bool = true,
                             completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void)
        -> (() -> Void)? {
        switch route {
        case .direct:
            let attempt = ObjCNetworkByteStream.connect(host: target.host, port: target.port,
                interfaceName: isLoopbackHost(target.host) ? nil : OutboundInterfaceBinding.current?.name,
                queue: queue, recordSetup: recordSetup) {
                completion($0.map { ($0, Data()) })
            }
            return { attempt.cancel() }
        case .reject(let reason):
            completion(.failure(EngineError("策略拒绝：\(reason)")))
            return nil
        case .http(let proxy, _):
            return NativeOutboundFactory.beginConnection(policy: proxy, target: target, plainHTTP: plainHTTP, queue: queue,
                                                         waitForSetupAcknowledgement: waitForSetupAcknowledgement,
                                                         recordSetup: recordSetup) {
                completion($0.map { ($0, Data()) })
            }
        case .socks5(let proxy, _):
            return NativeOutboundFactory.beginConnection(policy: proxy, target: target, queue: queue,
                                                         waitForSetupAcknowledgement: waitForSetupAcknowledgement,
                                                         recordSetup: recordSetup) {
                completion($0.map { ($0, Data()) })
            }
        case .native(let proxy, _):
            return NativeOutboundFactory.beginConnection(policy: proxy, target: target, queue: queue,
                                                         waitForSetupAcknowledgement: waitForSetupAcknowledgement,
                                                         recordSetup: recordSetup) {
                completion($0.map { ($0, Data()) })
            }
        }
    }

    /// HTTPS and SOCKS5-TLS use the same HTTP/SOCKS wire format after TLS.
    /// Reject unknown TLS flags and HTTP/2 ALPN rather than sending the clear
    /// protocol to a port the user expected to be protected by TLS.
    private static func connectUpstream(_ proxy: ProxyPolicy, queue: DispatchQueue,
                                        completion: @escaping (Result<any OutboundByteStream, Error>) -> Void) {
        guard let host = proxy.host, let port = proxy.port else {
            completion(.failure(EngineError("HTTP/SOCKS5 上游代理配置不完整")))
            return
        }
        let tls: Bool
        switch (proxy.parameters["tls"] ?? "false")
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "true", "yes", "on", "1": tls = true
        case "false", "no", "off", "0": tls = false
        default:
            completion(.failure(EngineError("HTTP/SOCKS5 上游 tls 参数无效，已拒绝明文连接")))
            return
        }
        let configuredALPN = proxy.parameters["alpn"].map { value in
            value.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) }
                .filter { !$0.isEmpty }
        } ?? []
        if !tls && !configuredALPN.isEmpty {
            completion(.failure(EngineError("明文 HTTP/SOCKS5 上游不能配置 TLS ALPN")))
            return
        }
        if tls && proxy.kind == .http &&
            !configuredALPN.allSatisfy({ $0 == "http/1.1" }) {
            completion(.failure(EngineError("HTTPS 上游只支持 HTTP/1.1 ALPN，不支持 h2")))
            return
        }
        let alpn = tls && proxy.kind == .http && configuredALPN.isEmpty
            ? ["http/1.1"] : configuredALPN
        ObjCNetworkByteStream.connect(host: host, port: port, tls: tls,
                   serverName: proxy.parameters["sni"] ?? proxy.parameters["servername"] ?? host,
                   skipCertificateVerification: proxy.skipsCertificateVerification,
                   alpn: alpn, interfaceName: isLoopbackHost(host) ? nil : OutboundInterfaceBinding.current?.name,
                   queue: queue) { completion($0.map { $0 as any OutboundByteStream }) }
    }

    private static func httpConnect(connection: any OutboundByteStream, proxy: ProxyPolicy,
                                    target: RequestTarget,
                                    completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        guard !target.host.isEmpty,
              target.port > 0,
              !target.host.utf8.contains(where: { $0 <= 0x20 || $0 == 0x7F }) else {
            connection.cancel()
            completion(.failure(EngineError("上游 HTTP CONNECT 目标主机或端口包含非法控制字符")))
            return
        }
        let authority = hostPort(target.host, target.port)
        var request = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\nProxy-Connection: Keep-Alive\r\n"
        if let username = proxy.username, let password = proxy.password {
            guard !username.contains("\r"), !username.contains("\n"), !username.contains("\0"),
                  !password.contains("\r"), !password.contains("\n"), !password.contains("\0") else {
                connection.cancel()
                completion(.failure(EngineError("上游 HTTP 代理凭据包含非法控制字符")))
                return
            }
            let token = Data("\(username):\(password)".utf8).base64EncodedString()
            request += "Proxy-Authorization: Basic \(token)\r\n"
        }
        request += "\r\n"
        send(Data(request.utf8), to: connection) { error in
            if let error { completion(.failure(error)); return }
            let reader = ConnectionReader(connection)
            reader.readUntil(Data("\r\n\r\n".utf8), maximum: 65_536) { result in
                // `ConnectionReader.receive` intentionally captures self weakly.
                // Keep this local reader alive across the asynchronous header
                // read or a valid CONNECT 200 can hang without invoking us.
                withExtendedLifetime(reader) {
                    switch result {
                    case .failure(let error): completion(.failure(error))
                    case .success(let pair):
                        let line = String(data: pair.0, encoding: .utf8)?.components(separatedBy: "\r\n").first ?? ""
                        let fields = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
                        guard fields.count >= 2,
                              fields[0].hasPrefix("HTTP/1."),
                              fields[1].count == 3,
                              let code = Int(fields[1]),
                              (200...299).contains(code) else {
                            completion(.failure(EngineError("上游 HTTP 代理拒绝连接：\(line)")))
                            return
                        }
                        completion(.success((connection, pair.1)))
                    }
                }
            }
        }
    }

    private static func socksConnect(connection: any OutboundByteStream, proxy: ProxyPolicy,
                                     target: RequestTarget,
                                     completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        let reader = ConnectionReader(connection)
        let authenticated = proxy.username != nil
        send(Data([0x05, 0x01, authenticated ? 0x02 : 0x00]), to: connection) { error in
            if let error { completion(.failure(error)); return }
            reader.readExactly(2) { result in
                guard case .success(let response) = result, response.count == 2, response[0] == 0x05 else {
                    completion(.failure(result.error ?? EngineError("SOCKS5 握手失败"))); return
                }
                if response[1] == 0x02 {
                    authenticateSOCKS(connection: connection, reader: reader, proxy: proxy) { authResult in
                        switch authResult {
                        case .failure(let error): completion(.failure(error))
                        case .success: requestSOCKS(connection: connection, reader: reader, target: target, completion: completion)
                        }
                    }
                } else if response[1] == 0x00 {
                    requestSOCKS(connection: connection, reader: reader, target: target, completion: completion)
                } else {
                    completion(.failure(EngineError("SOCKS5 不接受鉴权方式")))
                }
            }
        }
    }

    private static func authenticateSOCKS(connection: any OutboundByteStream, reader: ConnectionReader,
                                          proxy: ProxyPolicy,
                                          completion: @escaping (Result<Void, Error>) -> Void) {
        let user = Data((proxy.username ?? "").utf8)
        let pass = Data((proxy.password ?? "").utf8)
        guard user.count <= 255, pass.count <= 255 else {
            completion(.failure(EngineError("SOCKS5 用户名或密码过长"))); return
        }
        var data = Data([0x01, UInt8(user.count)])
        data.append(user); data.append(UInt8(pass.count)); data.append(pass)
        send(data, to: connection) { error in
            if let error { completion(.failure(error)); return }
            reader.readExactly(2) { result in
                guard case .success(let response) = result, response.count == 2, response[1] == 0 else {
                    completion(.failure(result.error ?? EngineError("SOCKS5 鉴权失败"))); return
                }
                completion(.success(()))
            }
        }
    }

    private static func requestSOCKS(connection: any OutboundByteStream, reader: ConnectionReader,
                                     target: RequestTarget,
                                     completion: @escaping (Result<(any OutboundByteStream, Data), Error>) -> Void) {
        var data = Data([0x05, 0x01, 0x00])
        data.append(socksAddress(host: target.host, port: target.port))
        send(data, to: connection) { error in
            if let error { completion(.failure(error)); return }
            reader.readExactly(4) { headerResult in
                guard case .success(let header) = headerResult, header.count == 4,
                      header[0] == 0x05, header[1] == 0 else {
                    completion(.failure(headerResult.error ?? EngineError("SOCKS5 连接被拒绝"))); return
                }
                let remaining: Int
                switch header[3] {
                case 0x01: remaining = 4 + 2
                case 0x04: remaining = 16 + 2
                case 0x03:
                    reader.readExactly(1) { lengthResult in
                        guard case .success(let length) = lengthResult, let count = length.first else {
                            completion(.failure(lengthResult.error ?? EngineError("SOCKS5 响应无效"))); return
                        }
                        reader.readExactly(Int(count) + 2) { tailResult in
                            switch tailResult {
                            case .failure(let error): completion(.failure(error))
                            case .success:
                                completion(.success((connection,
                                                     reader.takeBufferedData())))
                            }
                        }
                    }
                    return
                default: completion(.failure(EngineError("SOCKS5 地址类型无效"))); return
                }
                reader.readExactly(remaining) { tailResult in
                    switch tailResult {
                    case .failure(let error): completion(.failure(error))
                    case .success:
                        completion(.success((connection,
                                             reader.takeBufferedData())))
                    }
                }
            }
        }
    }
}

final class NetworkOutboundByteStream: OutboundByteStream {
    private let connection: NWConnection
    init(_ connection: NWConnection) { self.connection = connection }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed(completion))
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) {
            data, _, complete, error in completion(data, complete, error)
        }
    }

    func cancel() { connection.cancel() }
}

final class ConnectionBridge {
    private let client: NWConnection
    private let remote: any OutboundByteStream
    private let id: UUID
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private var finished = false
    private var nativePump: HJStreamPump?

    init(client: NWConnection, remote: any OutboundByteStream, id: UUID, engine: ProxyEngine,
         queue: DispatchQueue) {
        self.client = client
        self.remote = remote
        self.id = id
        self.engine = engine
        self.queue = queue
    }

    func start(clientInitial: Data = Data(), remoteInitial: Data = Data()) {
        let client = self.client
        let nativeClient = HJCallbackStream(queue: queue, supportsHalfClose: true,
            receiveHandler: { maximum, done in
                client.receive(minimumIncompleteLength: 1, maximumLength: Int(clamping: maximum)) {
                    data, _, complete, error in done(data, complete, error)
                }
            }, sendHandler: { data, complete, done in
                client.send(content: data, contentContext: .defaultStream,
                            isComplete: complete, completion: .contentProcessed { done($0) })
            }, cancelHandler: { client.cancel() })
        let nativeRemote: any HJByteStream
        if let stream = remote as? ObjCNetworkByteStream { nativeRemote = stream.native }
        else if let stream = remote as? NativeCXXByteStream { nativeRemote = stream.native }
        else {
            let remote = self.remote
            nativeRemote = HJCallbackStream(queue: queue, supportsHalfClose: false,
                receiveHandler: { maximum, done in remote.receive(maximum: Int(clamping: maximum), completion: done) },
                sendHandler: { data, _, done in remote.send(data ?? Data(), completion: done) },
                cancelHandler: { remote.cancel() })
        }
        let pump = HJStreamPump(client: nativeClient, remote: nativeRemote, queue: queue,
            chunkSize: 64 * 1_024, idleTimeout: 300, trafficInterval: 0.1,
            trafficHandler: { [weak self] uploaded, downloaded in
                guard let self else { return }
                self.engine?.emit(.traffic(id: self.id, uploaded: Int(clamping: uploaded), downloaded: Int(clamping: downloaded)))
            }, completion: { [weak self] error in self?.finish(error) })
        pump.firstByteHandler = { elapsed, success in
            NetworkPerformanceDiagnostics.shared.record(.firstByte, milliseconds: elapsed, success: success)
        }
        nativePump = pump
        pump.start(clientInitial: clientInitial, remoteInitial: remoteInitial)
    }

    func cancel() { finish(nil) }

    private func finish(_ error: Error?) {
        queue.async {
            guard !self.finished else { return }
            self.finished = true
            self.nativePump?.cancel(); self.nativePump = nil
            self.client.cancel(); self.remote.cancel()
            self.engine?.emit(.closed(id: self.id, error: error?.localizedDescription))
            self.engine?.handlerFinished(id: self.id)
        }
    }
}

struct HTTPRequestHead {
    let method: String
    let rawTarget: String
    let version: String
    let host: String
    let port: UInt16
    let header: Data
    let remainder: Data

    var isConnect: Bool { method.uppercased() == "CONNECT" }

    static func parse(header: Data, remainder: Data) throws -> HTTPRequestHead {
        let native = try NativeProtocolCodec.parseHTTP(header)
        func field(_ offset: Int, _ count: Int) -> String {
            let start = header.startIndex + offset
            return String(decoding: header[start..<(start + count)], as: UTF8.self)
        }
        let method = field(native.method_offset, native.method_length)
        let rawTarget = field(native.target_offset, native.target_length)
        let version = field(native.version_offset, native.version_length)
        return HTTPRequestHead(method: method, rawTarget: rawTarget, version: version,
                               host: NativeProtocolCodec.host(native.target), port: native.target.port,
                               header: header, remainder: remainder)
    }

    func requestData(httpProxy: ProxyPolicy?) throws -> Data {
        try NativeProtocolCodec.rewriteHTTP(header + remainder, upstream: httpProxy)
    }
}

final class HTTPConnectionHandler: CancellableConnectionHandler {
    let id = UUID()
    private let connection: NWConnection
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private var bridge: ConnectionBridge?
    private lazy var reader = ConnectionReader(connection)
    private var finished = false
    private var handshakeDeadline: DispatchWorkItem?

    init(connection: NWConnection, engine: ProxyEngine, queue: DispatchQueue) {
        self.connection = connection
        self.engine = engine
        self.queue = queue
    }

    func start() {
        guard !finished else { return }
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, !self.finished, self.bridge == nil else { return }
            self.fail(EngineError("HTTP 代理握手超时"), sendResponse: false)
        }
        handshakeDeadline = deadline
        queue.asyncAfter(deadline: .now() + (engine?.httpHandshakeTimeout ?? 15), execute: deadline)
        reader.readUntil(Data("\r\n\r\n".utf8), maximum: 65_536) { [weak self] result in
            guard let self, !self.finished else { return }
            switch result {
            case .failure(let error): self.fail(error, sendResponse: true)
            case .success(let pair):
                do { self.handle(try HTTPRequestHead.parse(header: pair.0, remainder: pair.1)) }
                catch { self.fail(error, sendResponse: true) }
            }
        }
    }

    func cancel() {
        queue.async { self.finish(nil) }
    }

    private func handle(_ request: HTTPRequestHead) {
        guard !finished, let engine else { return }
        let protocolName = request.isConnect ? "HTTPS" : "HTTP"
        let peer = peerAddress(connection.endpoint)
        let target = RequestTarget(host: request.host, port: request.port,
                                   protocolName: protocolName,
                                   sourceHost: peer.host, sourcePort: peer.port,
                                   inboundPort: engine.activeHTTPListen.port)
        let route = engine.route(for: target)
        let snapshot = ConnectionSnapshot(id: id, openedAt: Date(), client: endpointDescription(connection.endpoint),
                                          method: protocolName, host: target.host, port: target.port,
                                          policy: route.policyName)
        engine.emit(.opened(snapshot))
        if case .reject = route {
            fail(EngineError("请求被策略拒绝"), sendResponse: true)
            return
        }
        engine.connect(route: route, target: target, plainHTTP: !request.isConnect,
                                queue: queue) { [weak self] result in
            guard let self, !self.finished else {
                if case .success(let pair) = result { pair.0.cancel() }
                return
            }
            switch result {
            case .failure(let error): self.fail(error, sendResponse: true)
            case .success(let pair):
                let remote = pair.0
                if request.isConnect {
                    let established = Data("HTTP/1.1 200 Connection Established\r\nProxy-Agent: Hajimi/1.0\r\n\r\n".utf8)
                    send(established, to: self.connection) { [weak self] error in
                        guard let self, !self.finished else { remote.cancel(); return }
                        if let error { remote.cancel(); self.fail(error, sendResponse: false); return }
                        self.beginBridge(remote: remote, clientInitial: request.remainder, remoteInitial: pair.1)
                    }
                } else {
                    let httpProxy: ProxyPolicy?
                    if case .http(let proxy, _) = route { httpProxy = proxy } else { httpProxy = nil }
                    do {
                        self.beginBridge(remote: remote, clientInitial: try request.requestData(httpProxy: httpProxy),
                                         remoteInitial: pair.1)
                    } catch { remote.cancel(); self.fail(error, sendResponse: true) }
                }
            }
        }
    }

    private func beginBridge(remote: any OutboundByteStream,
                             clientInitial: Data, remoteInitial: Data) {
        guard !finished, let engine else { remote.cancel(); return }
        handshakeDeadline?.cancel(); handshakeDeadline = nil
        let bridge = ConnectionBridge(client: connection, remote: remote, id: id, engine: engine,
                                      queue: queue)
        self.bridge = bridge
        bridge.start(clientInitial: clientInitial, remoteInitial: remoteInitial)
    }

    private func fail(_ error: Error, sendResponse: Bool) {
        guard !finished else { return }
        if sendResponse {
            let body = "Hajimi: \(error.localizedDescription)\n"
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            send(Data(response.utf8), to: connection) { [weak self] _ in self?.finish(error) }
        } else { finish(error) }
    }

    private func finish(_ error: Error?) {
        guard !finished else { return }
        finished = true
        handshakeDeadline?.cancel(); handshakeDeadline = nil
        connection.cancel()
        if let bridge { self.bridge = nil; bridge.cancel(); return }
        engine?.emit(.closed(id: id, error: error?.localizedDescription))
        engine?.handlerFinished(id: id)
    }
}

final class SOCKSConnectionHandler: CancellableConnectionHandler {
    let id = UUID()
    private let connection: NWConnection
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private var bridge: ConnectionBridge?
    private var udpAssociation: SOCKSUDPAssociation?
    private lazy var reader = ConnectionReader(connection)
    private var finished = false
    private var handshakeCarrier: HJCallbackStream?
    private var handshakeInitial = Data()

    init(connection: NWConnection, engine: ProxyEngine, queue: DispatchQueue) {
        self.connection = connection
        self.engine = engine
        self.queue = queue
    }

    func start() {
        guard !finished else { return }
        let connection = self.connection
        let carrier = HJCallbackStream(queue: queue, supportsHalfClose: true,
            receiveHandler: { maximum, done in
                connection.receive(minimumIncompleteLength: 1, maximumLength: Int(clamping: maximum)) {
                    content, _, eof, error in done(content, eof, error)
                }
            }, sendHandler: { content, eof, done in
                connection.send(content: content, contentContext: eof ? .finalMessage : .defaultMessage,
                    isComplete: true, completion: .contentProcessed { done($0) })
            }, cancelHandler: { connection.cancel() })
        // The C++ parser borrows this carrier. Retain it until routing/pumping
        // or the UDP association ends, not merely until negotiation completes.
        handshakeCarrier = carrier
        HJCppServerProtocols.acceptSOCKS5(stream: carrier, queue: queue) { [weak self] host, port, command, initial, error in
            guard let self, !self.finished else { return }
            if let error { self.finish(error); return } // C++ already sent the rejection and closed its source.
            guard let host else { self.fail(EngineError("C++ SOCKS5 未返回目标地址")); return }
            self.handshakeInitial = initial ?? Data()
            if command == 1 { self.connect(RequestTarget(host: host, port: port, protocolName: "TCP")) }
            else if command == 3 { self.handshakeInitial.removeAll(); self.startUDPAssociation() }
            else { self.fail(EngineError("C++ SOCKS5 返回未知命令")) }
        }
    }

    func cancel() {
        queue.async { self.finish(nil) }
    }

    private func readRequest() {
        reader.readExactly(4) { [weak self] result in
            guard let self else { return }
            guard case .success(let head) = result, head.count == 4, head[0] == 0x05, head[2] == 0x00 else {
                self.fail(result.error ?? EngineError("SOCKS5 请求无效")); return
            }
            self.readAddress(type: head[3]) { addressResult in
                switch addressResult {
                case .failure(let error): self.fail(error)
                case .success(let target):
                    switch head[1] {
                    case 0x01: self.connect(target)
                    case 0x03: self.startUDPAssociation()
                    default: self.fail(EngineError("SOCKS5 命令暂不支持"))
                    }
                }
            }
        }
    }

    private func readAddress(type: UInt8, completion: @escaping (Result<RequestTarget, Error>) -> Void) {
        switch type {
        case 0x01:
            reader.readExactly(6) { result in completion(result.flatMap { parseSOCKSAddress($0, type: type) }) }
        case 0x04:
            reader.readExactly(18) { result in completion(result.flatMap { parseSOCKSAddress($0, type: type) }) }
        case 0x03:
            reader.readExactly(1) { [weak self] result in
                guard let self else { return }
                guard case .success(let data) = result, let length = data.first else {
                    completion(.failure(result.error ?? EngineError("SOCKS5 域名长度无效"))); return
                }
                self.reader.readExactly(Int(length) + 2) { body in
                    completion(body.flatMap { parseSOCKSAddress($0, type: type) })
                }
            }
        default: completion(.failure(EngineError("SOCKS5 地址类型不支持")))
        }
    }

    private func connect(_ target: RequestTarget) {
        guard !finished, let engine else { return }
        let peer = peerAddress(connection.endpoint)
        let routed = RequestTarget(host: target.host, port: target.port,
                                   protocolName: target.protocolName,
                                   sourceHost: peer.host, sourcePort: peer.port,
                                   inboundPort: engine.activeSOCKSListen.port)
        let route = engine.route(for: routed)
        engine.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(),
                                               client: endpointDescription(connection.endpoint), method: "SOCKS",
                                               host: engine.displayHost(for: routed.host), port: routed.port,
                                               policy: route.policyName)))
        if case .reject = route { fail(EngineError("请求被策略拒绝")); return }
        engine.connect(route: route, target: routed, plainHTTP: false, queue: queue) { [weak self] result in
            guard let self, !self.finished else {
                if case .success(let pair) = result { pair.0.cancel() }
                return
            }
            switch result {
            case .failure(let error): self.fail(error)
            case .success(let pair):
                let response: Data
                do { response = try NativeProtocolCodec.socksReply() }
                catch { pair.0.cancel(); self.fail(error); return }
                send(response, to: self.connection) { error in
                    if let error { pair.0.cancel(); self.fail(error); return }
                    guard !self.finished, let engine = self.engine else { pair.0.cancel(); return }
                    let bridge = ConnectionBridge(client: self.connection, remote: pair.0, id: self.id,
                                                  engine: engine, queue: self.queue)
                    self.bridge = bridge
                    bridge.start(clientInitial: self.handshakeInitial, remoteInitial: pair.1)
                    self.handshakeInitial.removeAll()
                }
            }
        }
    }

    private func startUDPAssociation() {
        guard !finished, let engine else { return }
        do {
            let association = try SOCKSUDPAssociation(engine: engine, queue: queue)
            udpAssociation = association
            association.start { [weak self] result in
                guard let self, !self.finished else { association.cancel(); return }
                switch result {
                case .failure(let error): self.fail(error)
                case .success(let port):
                    let response: Data
                    do { response = try NativeProtocolCodec.socksReply(host: "127.0.0.1", port: port) }
                    catch { self.finish(error); return }
                    send(response, to: self.connection) { error in
                        if let error { self.finish(error) }
                        else { self.monitorUDPControlConnection() }
                    }
                }
            }
        } catch { fail(error) }
    }

    private func monitorUDPControlConnection() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] _, _, complete, error in
            guard let self, !self.finished else { return }
            if let error { self.finish(error) }
            else if complete { self.finish(nil) }
            else { self.monitorUDPControlConnection() }
        }
    }

    private func fail(_ error: Error) {
        guard !finished else { return }
        guard let response = try? NativeProtocolCodec.socksReply(code: 1) else { finish(error); return }
        send(response, to: connection) { [weak self] _ in self?.finish(error) }
    }

    private func finish(_ error: Error?) {
        guard !finished else { return }
        finished = true
        udpAssociation?.cancel()
        handshakeCarrier?.cancel(); handshakeCarrier = nil
        handshakeInitial.removeAll()
        connection.cancel()
        if let bridge { self.bridge = nil; bridge.cancel(); return }
        engine?.emit(.closed(id: id, error: error?.localizedDescription))
        engine?.handlerFinished(id: id)
    }
}

final class SOCKSUDPClient {
    private struct Reply {
        let data: Data
        let completion: (Error?) -> Void
    }
    let id = UUID()
    let connection: NWConnection
    private let reservation: SOCKSUDPReservation
    private var replies = SOCKSUDPWriteQueue<Reply>()
    private(set) var closed = false
    var hasValidPacket = false

    init(connection: NWConnection, reservation: SOCKSUDPReservation) {
        self.connection = connection; self.reservation = reservation
    }

    func reply(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !closed else { completion(EngineError("SOCKS5 UDP 客户端已关闭")); return }
        guard replies.append(Reply(data: data, completion: completion), bytes: data.count) else {
            completion(EngineError("SOCKS5 UDP 客户端发送队列已达上限")); return
        }
        pumpReplies()
    }

    private func pumpReplies() {
        guard !closed, let packet = replies.beginNext() else { return }
        let packetID = packet.id, completion = packet.value.completion
        let reservation = packet.reservation
        connection.send(content: packet.value.data, completion: .contentProcessed { [weak self, reservation] error in
            reservation.release()
            if let self { _ = self.replies.complete(packetID) }
            completion(error)
            self?.pumpReplies()
        })
    }

    func close() {
        guard !closed else { return }
        closed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        let pending = replies.discard()
        reservation.release()
        for reply in pending { reply.completion(EngineError("SOCKS5 UDP 客户端已关闭")) }
    }
}

final class SOCKSUDPAssociation {
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private let listener: NWListener
    private var clients = SOCKSUDPResourceRegistry<ObjectIdentifier, SOCKSUDPClient>(
        maximumCount: SOCKSUDPResourceLimits.clientsPerAssociation)
    private var flows = SOCKSUDPResourceRegistry<String, SOCKSUDPFlow>(
        maximumCount: SOCKSUDPResourceLimits.directFlowsPerAssociation)
    private var routedFlows = SOCKSUDPResourceRegistry<String, SOCKSRoutedUDPFlow>(
        maximumCount: SOCKSUDPResourceLimits.directFlowsPerAssociation)
    private var upstreamRelays = SOCKSUDPResourceRegistry<String, NativeUDPRelay>(
        maximumCount: SOCKSUDPResourceLimits.relaysPerAssociation)
    private var nativeRelays = SOCKSUDPResourceRegistry<String, NativeUDPRelay>(
        maximumCount: SOCKSUDPResourceLimits.relaysPerAssociation)
    private var routeCache: [String: ResolvedRoute] = [:]
    private var reportedUnsupportedTargets = Set<String>()
    private var lastRoutingRevision: UInt64 = 0
    private var cancelled = false
    private var idleReaper: DispatchWorkItem?

    init(engine: ProxyEngine, queue: DispatchQueue) throws {
        self.engine = engine
        self.queue = queue
        let parameters = NWParameters.udp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }

    func start(completion: @escaping (Result<UInt16, Error>) -> Void) {
        guard !cancelled else { completion(.failure(EngineError("SOCKS5 UDP 会话已关闭"))); return }
        var completed = false
        listener.stateUpdateHandler = { [weak self] state in
            guard let self, !self.cancelled else { return }
            guard !completed else { return }
            switch state {
            case .ready:
                guard let rawPort = self.listener.port?.rawValue else {
                    completed = true
                    completion(.failure(EngineError("无法获得 SOCKS5 UDP 端口")))
                    return
                }
                completed = true
                completion(.success(rawPort))
            case .failed(let error):
                completed = true
                completion(.failure(error))
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.accept(connection)
        }
        listener.start(queue: queue)
        scheduleIdleReaper()
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        idleReaper?.cancel(); idleReaper = nil
        listener.stateUpdateHandler = nil
        listener.cancel()
        let activeClients = clients.removeAll()
        dropRoutedState()
        activeClients.forEach { $0.close() }
    }

    /// Route caches AND already-connected UDP sockets belong to one policy
    /// generation. An old DIRECT socket must never outlive a switch to TLS.
    private func dropRoutedState() {
        let activeFlows = flows.removeAll()
        let activeRoutedFlows = routedFlows.removeAll()
        let activeRelays = upstreamRelays.removeAll()
        let activeNativeRelays = nativeRelays.removeAll()
        routeCache.removeAll(keepingCapacity: false)
        reportedUnsupportedTargets.removeAll(keepingCapacity: false)
        activeFlows.forEach { $0.cancel() }
        activeRoutedFlows.forEach { $0.cancel() }
        activeRelays.forEach { $0.cancel() }
        activeNativeRelays.forEach { $0.cancel() }
    }

    private func refreshRoutingIfNeeded(engine: ProxyEngine) {
        let current = engine.routingRevision()
        guard current != lastRoutingRevision else { return }
        lastRoutingRevision = current
        dropRoutedState()
    }

    private func accept(_ connection: NWConnection) {
        guard !cancelled, clients.hasCapacity,
              let reservation = SOCKSUDPResourceLimits.shared.reserveResource() else {
            connection.cancel(); return
        }
        let client = SOCKSUDPClient(connection: connection, reservation: reservation)
        let key = ObjectIdentifier(connection), token = client.id
        guard clients.insert(client, forKey: key, token: token) else { client.close(); return }
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection else { return }
            switch state {
            case .failed, .cancelled: self.removeClient(connection, token: token)
            default: break
            }
        }
        connection.start(queue: queue)
        receive(on: connection)
    }

    private func receive(on client: NWConnection) {
        client.receiveMessage { [weak self, weak client] data, _, _, error in
            guard let self, let client, !self.cancelled else { return }
            guard self.consume(data, client: client, error: error) else { return }
            self.receive(on: client)
        }
    }

    private func consume(_ data: Data?, client: NWConnection, error: Error?) -> Bool {
        let key = ObjectIdentifier(client)
        guard !cancelled, let record = clients.value(forKey: key), !record.closed else {
            client.cancel(); return false
        }
        if error != nil { removeClient(client, token: record.id); return false }
        if let data {
            switch parseSOCKSUDPDatagram(data) {
            case .failure:
                // Invalid traffic never refreshes an established client.
                if !record.hasValidPacket { removeClient(client, token: record.id); return false }
            case .success(let datagram):
                record.hasValidPacket = true
                clients.touch(key, token: record.id)
                handle(datagram, client: record)
            }
        }
        return true
    }

    static func resourceStateSelfTest() -> String? {
        do {
            let engine = ProxyEngine()
            let association = try SOCKSUDPAssociation(engine: engine, queue: DispatchQueue(label: "app.hajimi.udp-state-test"))
            defer { association.cancel() }
            let budget = SOCKSUDPGlobalBudget(resources: 2, packets: 1, bytes: 1)
            let connection = NWConnection(host: "127.0.0.1", port: .any, using: .udp)
            guard let oldLease = budget.reserveResource() else { return "UDP test slot unavailable" }
            let old = SOCKSUDPClient(connection: connection, reservation: oldLease)
            let key = ObjectIdentifier(connection)
            association.clients = SOCKSUDPResourceRegistry(maximumCount: 1)
            guard association.clients.insert(old, forKey: key, token: old.id),
                  !association.consume(Data([255]), client: connection, error: nil),
                  association.clients.count == 0, old.closed, budget.usage.resources == 0 else {
                return "invalid first UDP packet retained a client or resource slot"
            }
            guard let newLease = budget.reserveResource() else { return "UDP invalid-client slot was not reusable" }
            let current = SOCKSUDPClient(connection: connection, reservation: newLease)
            guard association.clients.insert(current, forKey: key, token: current.id) else {
                return "UDP replacement client was not admitted"
            }
            association.removeClient(connection, token: old.id)
            guard association.clients.count == 1, !current.closed, budget.usage.resources == 1 else {
                return "late UDP client cancellation deleted its replacement"
            }
            association.cancel()
            association.accept(NWConnection(host: "127.0.0.1", port: .any, using: .udp))
            guard association.clients.count == 0, current.closed, budget.usage.resources == 0 else {
                return "UDP association cancellation leaked or admitted late clients"
            }
            guard case .success(let empty) = parseSOCKSUDPDatagram(Data([0, 0, 0, 1, 127, 0, 0, 1, 0, 53])),
                  empty.payload.isEmpty else { return "valid empty SOCKS UDP payload was rejected" }
            return nil
        } catch { return "UDP resource state fixture: \(error.localizedDescription)" }
    }

    private func removeClient(_ connection: NWConnection, token: UUID) {
        guard let client = clients.removeValue(forKey: ObjectIdentifier(connection), token: token) else { return }
        let direct = flows.remove { $0.belongs(to: client) }
        let routed = routedFlows.remove { $0.belongs(to: client) }
        let upstream = upstreamRelays.remove { $0.belongs(to: client) }
        let native = nativeRelays.remove { $0.belongs(to: client) }
        client.close()
        direct.forEach { $0.cancel() }; routed.forEach { $0.cancel() }
        upstream.forEach { $0.cancel() }; native.forEach { $0.cancel() }
    }

    private func scheduleIdleReaper() {
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.cancelled else { return }
            let now = SOCKSUDPResourceLimits.now
            for client in self.clients.expiredValues(now: now) {
                self.removeClient(client.connection, token: client.id)
            }
            self.flows.removeExpired(now: now).forEach { $0.cancel() }
            self.routedFlows.removeExpired(now: now).forEach { $0.cancel() }
            self.upstreamRelays.removeExpired(now: now).forEach { $0.cancel() }
            self.nativeRelays.removeExpired(now: now).forEach { $0.cancel() }
            self.scheduleIdleReaper()
        }
        idleReaper = work
        queue.asyncAfter(deadline: .now() + SOCKSUDPResourceLimits.reapInterval, execute: work)
    }

    private func handle(_ datagram: SOCKSUDPDatagram, client: SOCKSUDPClient) {
        guard let engine else { return }
        refreshRoutingIfNeeded(engine: engine)
        let peer = peerAddress(client.connection.endpoint)
        let target = RequestTarget(host: datagram.target.host, port: datagram.target.port, protocolName: "UDP",
                                   sourceHost: peer.host, sourcePort: peer.port,
                                   inboundPort: engine.activeSOCKSListen.port)
        // Source ownership is part of the identity: clients using the same
        // destination/policy must not receive each other's UDP replies.
        let destinationKey = "\(target.host.lowercased())|\(target.port)|\(target.sourceHost ?? ""):\(target.sourcePort ?? 0)|\(target.inboundPort ?? 0)"
        let targetKey = SOCKSUDPResourceLimits.ownedKey(client: client.id, target: destinationKey)
        let clientKey = ObjectIdentifier(client.connection), clientToken = client.id
        if isLoopbackHost(target.host), let localUDPPort = listener.port?.rawValue, localUDPPort != 0, target.port == localUDPPort {
            reportUnsupported(targetKey: targetKey, target: target, client: client, engine: engine,
                route: .reject("Self-loopback UDP"),
                message: "已阻止指向当前 SOCKS5 UDP 关联端口的回环数据报 (\(target.host):\(target.port))")
            return
        }
        if FakeIPAllocator.isFake(target.host) {
            reportUnsupported(targetKey: targetKey, target: target, client: client, engine: engine,
                route: .reject("Unmapped local fake-IP"),
                message: "本地 SOCKS UDP 不支持跨数据面的 fake-IP；请使用域名或对应 TUN 数据面")
            return
        }
        if let existing = routedFlows.value(forKey: targetKey) {
            routedFlows.touch(targetKey, token: existing.id)
            existing.send(datagram.payload); return
        }
        if target.port == 53 {
            handleRouted(datagram.payload, target: target, key: targetKey, client: client, engine: engine)
            return
        }
        if let existing = flows.value(forKey: targetKey) {
            flows.touch(targetKey, token: existing.id)
            existing.send(datagram.payload); return
        }
        let route: ResolvedRoute
        if let cached = routeCache[destinationKey] { route = cached }
        else {
            route = safeSOCKSUDPRoute(engine.route(for: target), destinationPort: target.port)
            if routeCache.count >= 2_048 { routeCache.removeAll(keepingCapacity: true) }
            routeCache[destinationKey] = route
        }
        switch route {
        case .direct:
            if engine.routesDirectHostnamesViaDNS, !DoHEndpoint.isAddressLiteral(target.host) {
                handleRouted(datagram.payload, target: target, key: targetKey, client: client, engine: engine)
                return
            }
            guard flows.hasCapacity,
                  let reservation = SOCKSUDPResourceLimits.shared.reserveResource() else { return }
            let id = UUID()
            let flow = SOCKSUDPFlow(id: id, target: target, client: client, engine: engine, queue: queue,
                reservation: reservation, onActivity: { [weak self] in
                    self?.flows.touch(targetKey, token: id)
                    self?.clients.touch(clientKey, token: clientToken)
                }, onClose: { [weak self] in self?.flows.removeValue(forKey: targetKey, token: id) })
            guard flows.insert(flow, forKey: targetKey, token: id) else { flow.cancel(); return }
            flow.send(datagram.payload)
        case .socks5(let proxy, let policyName), .native(let proxy, let policyName):
            let upstream: Bool
            if case .socks5 = route { upstream = true } else { upstream = false }
            if upstream, isTLSOnlyUpstream(route) {
                reportUnsupported(targetKey: targetKey, target: target, client: client,
                    engine: engine, route: route, message: "SOCKS5-TLS 上游不支持安全的 UDP Relay")
                return
            }
            let key = SOCKSUDPResourceLimits.ownedKey(client: client.id, target: proxy.name)
            if let relay = upstream ? upstreamRelays.value(forKey: key) : nativeRelays.value(forKey: key) {
                if upstream { upstreamRelays.touch(key, token: relay.id) }
                else { nativeRelays.touch(key, token: relay.id) }
                relay.sendDatagram(target: target, payload: datagram.payload); return
            }
            guard upstream ? upstreamRelays.hasCapacity : nativeRelays.hasCapacity,
                  let reservation = SOCKSUDPResourceLimits.shared.reserveResource() else { return }
            let id = UUID()
            do {
                let relay = try NativeUDPRelay(id: id, proxy: proxy, policyName: policyName,
                    client: client, engine: engine, queue: queue, reservation: reservation,
                    onActivity: { [weak self] in
                        guard let self else { return }
                        if upstream { self.upstreamRelays.touch(key, token: id) }
                        else { self.nativeRelays.touch(key, token: id) }
                        self.clients.touch(clientKey, token: clientToken)
                    }, onClose: { [weak self] in
                        guard let self else { return }
                        if upstream { self.upstreamRelays.removeValue(forKey: key, token: id) }
                        else { self.nativeRelays.removeValue(forKey: key, token: id) }
                    })
                let admitted: Bool
                if upstream { admitted = upstreamRelays.insert(relay, forKey: key, token: id) }
                else { admitted = nativeRelays.insert(relay, forKey: key, token: id) }
                guard admitted else { relay.cancel(); return }
                relay.sendDatagram(target: target, payload: datagram.payload)
            } catch {
                reservation.release()
                reportUnsupported(targetKey: targetKey, target: target, client: client,
                                  engine: engine, route: route, message: error.localizedDescription)
            }
        case .reject(let reason):
            reportUnsupported(targetKey: targetKey, target: target, client: client,
                              engine: engine, route: route, message: reason)
        case .http:
            reportUnsupported(targetKey: targetKey, target: target, client: client,
                              engine: engine, route: route, message: "该代理策略不支持 UDP Relay")
        }
    }

    private func handleRouted(_ payload: Data, target: RequestTarget, key: String,
                              client: SOCKSUDPClient, engine: ProxyEngine) {
        guard routedFlows.hasCapacity,
              let reservation = SOCKSUDPResourceLimits.shared.reserveResource() else { return }
        let id = UUID(), clientKey = ObjectIdentifier(client.connection), clientToken = client.id
        do {
            let flow = try SOCKSRoutedUDPFlow(id: id, target: target, client: client, engine: engine,
                queue: queue, reservation: reservation, onActivity: { [weak self] in
                    self?.routedFlows.touch(key, token: id)
                    self?.clients.touch(clientKey, token: clientToken)
                }, onClose: { [weak self] in self?.routedFlows.removeValue(forKey: key, token: id) })
            guard routedFlows.insert(flow, forKey: key, token: id) else { flow.cancel(); return }
            flow.send(payload)
        } catch {
            reservation.release()
            reportUnsupported(targetKey: key, target: target, client: client, engine: engine,
                               route: engine.route(for: target), message: error.localizedDescription)
        }
    }

    private func reportUnsupported(targetKey: String, target: RequestTarget,
                                   client: SOCKSUDPClient, engine: ProxyEngine,
                                   route: ResolvedRoute, message: String) {
                if reportedUnsupportedTargets.count >= 2_048 {
                    reportedUnsupportedTargets.removeAll(keepingCapacity: true)
                }
                guard reportedUnsupportedTargets.insert(targetKey).inserted else { return }
                let eventID = UUID()
                engine.emit(.opened(ConnectionSnapshot(id: eventID, openedAt: Date(),
                                                       client: endpointDescription(client.connection.endpoint), method: "UDP",
                                                       host: target.host, port: target.port,
                                                       policy: route.policyName)))
                engine.emit(.closed(id: eventID, error: message))
    }
}

public extension ProxyEngine {
    /// Includes pure resource-budget checks and canceled/malformed-client
    /// state replay. Constructed listeners/connections are never started.
    static func socksUDPResourceSelfTest() -> String? {
        SOCKSUDPResourcePolicySelfTest.run() ?? SOCKSUDPAssociation.resourceStateSelfTest()
    }
}

/// The shared packet router handles DNS and protected DIRECT name resolution
/// without changing source ownership or the SOCKS response address.
final class SOCKSRoutedUDPFlow {
    let id: UUID
    private let target: RequestTarget
    private let client: SOCKSUDPClient
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private let reservation: SOCKSUDPReservation
    private let onActivity: () -> Void, onClose: () -> Void
    private var session: NativeRoutedDatagram?
    private var closed = false

    init(id: UUID, target: RequestTarget, client: SOCKSUDPClient, engine: ProxyEngine,
         queue: DispatchQueue, reservation: SOCKSUDPReservation,
         onActivity: @escaping () -> Void, onClose: @escaping () -> Void) throws {
        self.id = id; self.target = target; self.client = client; self.engine = engine
        self.queue = queue; self.reservation = reservation
        self.onActivity = onActivity; self.onClose = onClose
        session = try engine.makeRoutedUDP(target: target, queue: queue,
            receive: { [weak self] answer in self?.queue.async { self?.receive(answer) } },
            failure: { [weak self] error in self?.queue.async { self?.finish(error) } })
        engine.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(), client: endpointDescription(client.connection.endpoint),
            method: "UDP", host: target.host, port: target.port, policy: target.port == 53 ? "DNS" : "DIRECT")))
    }
    func send(_ data: Data) {
        guard !closed else { return }; onActivity(); session?.send(data)
        engine?.emit(.traffic(id: id, uploaded: data.count, downloaded: 0))
    }
    private func receive(_ data: Data) {
        guard !closed else { return }; onActivity()
        if target.port == 53 { engine?.recordDNSResponse(data) }
        do {
            let packet = try NativeProtocolCodec.encodeSOCKSUDP(target: target, payload: data)
            client.reply(packet) { [weak self] error in
                guard let self, !self.closed else { return }
                if let error { self.finish(error) }
                else { self.engine?.emit(.traffic(id: self.id, uploaded: 0, downloaded: data.count)) }
            }
        } catch { finish(error) }
    }
    func belongs(to client: SOCKSUDPClient) -> Bool { self.client === client }
    func cancel() { finish(nil) }
    private func finish(_ error: Error?) {
        guard !closed else { return }; closed = true; session?.cancel(); session = nil
        reservation.release(); onClose(); engine?.emit(.closed(id: id, error: error?.localizedDescription))
    }
    deinit { session?.cancel(); reservation.release() }
}

final class NativeUDPRelay {
    let id: UUID
    private weak var engine: ProxyEngine?
    private let client: SOCKSUDPClient
    private let policyName: String
    private let reservation: SOCKSUDPReservation
    private let onActivity: () -> Void
    private let onClose: () -> Void
    private var session: NativeOutboundDatagramSession!
    private var closed = false
    // Stream-based UDP implementations may open a socket per target. Count
    // those logical targets globally as well as the relay itself. They retain
    // their leases until this session closes, never ahead of the C++ session.
    private var targets = SOCKSUDPResourceRegistry<String, SOCKSUDPReservation>(
        maximumCount: SOCKSUDPResourceLimits.targetsPerRelay)

    init(id: UUID, proxy: ProxyPolicy, policyName: String, client: SOCKSUDPClient,
         engine: ProxyEngine, queue: DispatchQueue, reservation: SOCKSUDPReservation,
         onActivity: @escaping () -> Void, onClose: @escaping () -> Void) throws {
        self.id = id; self.reservation = reservation; self.onActivity = onActivity
        self.client = client; self.engine = engine; self.policyName = policyName
        self.onClose = onClose
        if proxy.kind == .socks5 {
            session = try NativeCXXOutbound.makeDatagramSession(policy: proxy, queue: queue,
                receive: { [weak self] target, payload in self?.receive(target: target, payload: payload) },
                failure: { [weak self] error in self?.finish(error) })
        } else {
            session = try NativeOutboundFactory.makeDatagramSession(
                policy: proxy, queue: queue,
                receive: { [weak self] target, payload in self?.receive(target: target, payload: payload) },
                failure: { [weak self] error in self?.finish(error) })
        }
    }

    func sendDatagram(target: RequestTarget, payload: Data) {
        guard !closed else { return }
        let key = "\(target.host.lowercased())|\(target.port)"
        let isNewTarget = (targets.value(forKey: key) == nil)
        if isNewTarget {
            guard targets.hasCapacity, let lease = SOCKSUDPResourceLimits.shared.reserveResource() else { return }
            guard targets.insert(lease, forKey: key, token: UUID()) else { lease.release(); return }
        }
        onActivity()
        if isNewTarget {
            engine?.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(), client: endpointDescription(client.connection.endpoint),
                                                    method: "UDP", host: target.host, port: target.port,
                                                    policy: policyName)))
        }
        // NativeCXXDatagramSession already bounds its pre-ready AND in-flight
        // queue to 512 packets/2 MiB and submits one datagram write at a time.
        session.send(payload, to: target)
        engine?.emit(.traffic(id: id, uploaded: payload.count, downloaded: 0))
    }

    func cancel() { finish(nil) }
    func belongs(to client: SOCKSUDPClient) -> Bool { self.client === client }

    private func receive(target: RequestTarget, payload: Data) {
        guard !closed else { return }
        onActivity()
        let response: Data
        do { response = try NativeProtocolCodec.encodeSOCKSUDP(target: target, payload: payload) }
        catch { finish(error); return }
        let byteCount = payload.count
        client.reply(response) { [weak self] error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error) }
            else { self.engine?.emit(.traffic(id: self.id, uploaded: 0, downloaded: byteCount)) }
        }
    }

    private func finish(_ error: Error?) {
        guard !closed else { return }
        closed = true; session?.cancel()
        targets.removeAll().forEach { $0.release() }
        reservation.release()
        engine?.emit(.closed(id: id, error: error?.localizedDescription))
        onClose()
    }
}

final class SOCKSUDPFlow {
    let id: UUID
    private let target: RequestTarget
    private let client: SOCKSUDPClient
    private weak var engine: ProxyEngine?
    private let remote: NWConnection
    private let reservation: SOCKSUDPReservation
    private let onActivity: () -> Void
    private let onClose: () -> Void
    private var pending = SOCKSUDPWriteQueue<Data>()
    private var ready = false
    private var closed = false

    init(id: UUID, target: RequestTarget, client: SOCKSUDPClient, engine: ProxyEngine,
         queue: DispatchQueue, reservation: SOCKSUDPReservation,
         onActivity: @escaping () -> Void, onClose: @escaping () -> Void) {
        self.id = id; self.reservation = reservation; self.onActivity = onActivity
        self.target = target
        self.client = client
        self.engine = engine
        self.onClose = onClose
        let parameters = NWParameters.udp
        if !isLoopbackHost(target.host) { parameters.requiredInterface = OutboundInterfaceBinding.current }
        remote = NWConnection(host: NWEndpoint.Host(target.host),
                              port: NWEndpoint.Port(rawValue: target.port)!, using: parameters)
        engine.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(),
                                               client: endpointDescription(client.connection.endpoint), method: "UDP",
                                               host: engine.displayHost(for: target.host), port: target.port,
                                               policy: target.port == 53 ? "DNS" : "DIRECT")))
        remote.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready:
                self.ready = true
                self.pumpWrites()
                self.receive()
            case .failed(let error): self.finish(error)
            case .cancelled: self.finish(nil)
            default: break
            }
        }
        remote.start(queue: queue)
    }

    func send(_ payload: Data) {
        guard !closed else { return }
        guard pending.append(payload, bytes: payload.count) else {
            finish(EngineError("SOCKS5 UDP 发送缓冲达到包数或内存上限")); return
        }
        pumpWrites()
    }

    private func pumpWrites() {
        guard !closed, ready, let packet = pending.beginNext() else { return }
        let packetID = packet.id, byteCount = packet.byteCount, lease = packet.reservation
        remote.send(content: packet.value, completion: .contentProcessed { [weak self, lease] error in
            lease.release()
            guard let self, !self.closed else { return }
            _ = self.pending.complete(packetID)
            if let error { self.finish(error); return }
            self.onActivity()
            self.engine?.emit(.traffic(id: self.id, uploaded: byteCount, downloaded: 0))
            self.pumpWrites()
        })
    }

    func cancel() { finish(nil) }
    func belongs(to client: SOCKSUDPClient) -> Bool { self.client === client }

    private func receive() {
        remote.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error); return }
            if let data {
                self.onActivity()
                if self.target.port == 53 { self.engine?.recordDNSResponse(data) }
                var response = Data([0x00, 0x00, 0x00])
                response.append(socksAddress(host: self.target.host, port: self.target.port))
                response.append(data)
                let byteCount = data.count
                self.client.reply(response) { [weak self] sendError in
                    guard let self, !self.closed else { return }
                    if let sendError { self.finish(sendError); return }
                    self.engine?.emit(.traffic(id: self.id, uploaded: 0, downloaded: byteCount))
                    self.receive()
                }
                return
            }
            self.receive()
        }
    }

    private func finish(_ error: Error?) {
        guard !closed else { return }
        closed = true
        _ = pending.discard()
        remote.stateUpdateHandler = nil
        remote.cancel()
        reservation.release()
        engine?.emit(.closed(id: id, error: error?.localizedDescription))
        onClose()
    }
}

/// One RFC 1928 UDP ASSOCIATE session to an upstream SOCKS5 proxy. All UDP
/// destinations selected by the same policy share the control TCP connection
/// and UDP relay socket.
final class UpstreamSOCKSUDPRelay {
    private struct PendingDatagram {
        let target: RequestTarget
        let payload: Data
    }

    private let proxy: ProxyPolicy
    private let policyName: String
    private let client: NWConnection
    private weak var engine: ProxyEngine?
    private let queue: DispatchQueue
    private let onClose: () -> Void
    private var control: NWConnection?
    private var controlReader: ConnectionReader?
    private var relay: NWConnection?
    private var pending: [PendingDatagram] = []
    private var eventIDs: [String: UUID] = [:]
    private var ready = false
    private var closed = false

    init(proxy: ProxyPolicy, policyName: String, client: NWConnection,
         engine: ProxyEngine, queue: DispatchQueue, onClose: @escaping () -> Void) {
        self.proxy = proxy
        self.policyName = policyName
        self.client = client
        self.engine = engine
        self.queue = queue
        self.onClose = onClose
        establishControlConnection()
    }

    func sendDatagram(target: RequestTarget, payload: Data) {
        guard !closed else { return }
        ensureEvent(for: target)
        guard ready else {
            if pending.count < 512 { pending.append(PendingDatagram(target: target, payload: payload)) }
            return
        }
        sendNow(target: target, payload: payload)
    }

    func cancel() { finish(nil) }

    private func establishControlConnection() {
        let tls = (proxy.parameters["tls"] ?? "false").lowercased()
        guard ["false", "no", "off", "0"].contains(tls) else {
            finish(EngineError("SOCKS5-TLS 上游不支持安全的 UDP Relay"))
            return
        }
        guard let host = proxy.host, let port = proxy.port else {
            finish(EngineError("SOCKS5 UDP 上游配置不完整"))
            return
        }
        connectTCP(host: host, port: port, queue: queue) { [weak self] result in
            guard let self, !self.closed else { return }
            switch result {
            case .failure(let error): self.finish(error)
            case .success(let connection):
                self.control = connection
                let reader = ConnectionReader(connection)
                self.controlReader = reader
                self.negotiateAuthentication(connection: connection, reader: reader)
            }
        }
    }

    private func negotiateAuthentication(connection: NWConnection, reader: ConnectionReader) {
        let hasCredentials = proxy.username != nil
        let greeting = Data(hasCredentials ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00])
        send(greeting, to: connection) { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            reader.readExactly(2) { result in
                guard case .success(let response) = result, response.count == 2, response[0] == 0x05 else {
                    self.finish(result.error ?? EngineError("SOCKS5 UDP 上游握手失败")); return
                }
                switch response[1] {
                case 0x00: self.requestAssociation(connection: connection, reader: reader)
                case 0x02: self.authenticate(connection: connection, reader: reader)
                default: self.finish(EngineError("SOCKS5 UDP 上游拒绝鉴权方式"))
                }
            }
        }
    }

    private func authenticate(connection: NWConnection, reader: ConnectionReader) {
        let username = Data((proxy.username ?? "").utf8)
        let password = Data((proxy.password ?? "").utf8)
        guard username.count <= 255, password.count <= 255 else {
            finish(EngineError("SOCKS5 UDP 上游用户名或密码过长")); return
        }
        var request = Data([0x01, UInt8(username.count)])
        request.append(username)
        request.append(UInt8(password.count))
        request.append(password)
        send(request, to: connection) { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            reader.readExactly(2) { result in
                guard case .success(let response) = result, response.count == 2, response[1] == 0 else {
                    self.finish(result.error ?? EngineError("SOCKS5 UDP 上游鉴权失败")); return
                }
                self.requestAssociation(connection: connection, reader: reader)
            }
        }
    }

    private func requestAssociation(connection: NWConnection, reader: ConnectionReader) {
        let request = Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        send(request, to: connection) { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            reader.readExactly(4) { result in
                guard case .success(let header) = result, header.count == 4,
                      header[0] == 0x05, header[1] == 0 else {
                    self.finish(result.error ?? EngineError("SOCKS5 上游不支持 UDP ASSOCIATE")); return
                }
                self.readBoundAddress(type: header[3], reader: reader) { addressResult in
                    switch addressResult {
                    case .failure(let error): self.finish(error)
                    case .success(let target): self.openRelay(target)
                    }
                }
            }
        }
    }

    private func readBoundAddress(type: UInt8, reader: ConnectionReader,
                                  completion: @escaping (Result<RequestTarget, Error>) -> Void) {
        switch type {
        case 0x01:
            reader.readExactly(6) { completion($0.flatMap { parseSOCKSAddress($0, type: type) }) }
        case 0x04:
            reader.readExactly(18) { completion($0.flatMap { parseSOCKSAddress($0, type: type) }) }
        case 0x03:
            reader.readExactly(1) { result in
                guard case .success(let lengthData) = result, let length = lengthData.first else {
                    completion(.failure(result.error ?? EngineError("SOCKS5 UDP Relay 地址无效"))); return
                }
                reader.readExactly(Int(length) + 2) { body in
                    completion(body.flatMap { parseSOCKSAddress($0, type: type) })
                }
            }
        default: completion(.failure(EngineError("SOCKS5 UDP Relay 地址类型无效")))
        }
    }

    private func openRelay(_ boundTarget: RequestTarget) {
        guard let proxyHost = proxy.host else { finish(EngineError("SOCKS5 上游地址为空")); return }
        let wildcard = boundTarget.host == "0.0.0.0" || boundTarget.host == "::" || boundTarget.host == "::0"
        let host = wildcard ? proxyHost : boundTarget.host
        guard boundTarget.port != 0, let port = NWEndpoint.Port(rawValue: boundTarget.port) else {
            finish(EngineError("SOCKS5 上游返回了无效 UDP Relay 端口")); return
        }
        let parameters = NWParameters.udp
        if !isLoopbackHost(host) { parameters.requiredInterface = OutboundInterfaceBinding.current }
        let relay = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
        self.relay = relay
        relay.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready:
                self.ready = true
                let buffered = self.pending
                self.pending.removeAll()
                buffered.forEach { self.sendNow(target: $0.target, payload: $0.payload) }
                self.receiveRelayDatagram()
                self.monitorControlConnection()
            case .failed(let error): self.finish(error)
            case .cancelled: self.finish(nil)
            default: break
            }
        }
        relay.start(queue: queue)
    }

    private func sendNow(target: RequestTarget, payload: Data) {
        guard let relay, !closed else { return }
        var packet = Data([0x00, 0x00, 0x00])
        packet.append(socksAddress(host: target.host, port: target.port))
        packet.append(payload)
        relay.send(content: packet, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            if let id = self.eventIDs[self.eventKey(target)] {
                self.engine?.emit(.traffic(id: id, uploaded: payload.count, downloaded: 0))
            }
        })
    }

    private func receiveRelayDatagram() {
        relay?.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error); return }
            if let data, !data.isEmpty {
                switch parseSOCKSUDPDatagram(data) {
                case .failure(let error): self.finish(error)
                case .success(let datagram):
                    self.client.send(content: data, completion: .contentProcessed { [weak self] sendError in
                        guard let self else { return }
                        if let sendError { self.finish(sendError); return }
                        if let id = self.eventIDs[self.eventKey(datagram.target)] {
                            self.engine?.emit(.traffic(id: id, uploaded: 0,
                                                       downloaded: datagram.payload.count))
                        }
                    })
                }
            }
            self.receiveRelayDatagram()
        }
    }

    private func monitorControlConnection() {
        control?.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] _, _, complete, error in
            guard let self, !self.closed else { return }
            if let error { self.finish(error) }
            else if complete { self.finish(EngineError("SOCKS5 UDP 上游控制连接已关闭")) }
            else { self.monitorControlConnection() }
        }
    }

    private func ensureEvent(for target: RequestTarget) {
        let key = eventKey(target)
        guard eventIDs[key] == nil, let engine else { return }
        let id = UUID()
        eventIDs[key] = id
        engine.emit(.opened(ConnectionSnapshot(id: id, openedAt: Date(),
                                               client: endpointDescription(client.endpoint), method: "UDP",
                                               host: engine.displayHost(for: target.host), port: target.port,
                                               policy: policyName)))
    }

    private func eventKey(_ target: RequestTarget) -> String { "\(target.host)|\(target.port)" }

    private func finish(_ error: Error?) {
        guard !closed else { return }
        closed = true
        control?.cancel()
        relay?.cancel()
        for id in eventIDs.values { engine?.emit(.closed(id: id, error: error?.localizedDescription)) }
        eventIDs.removeAll()
        pending.removeAll()
        onClose()
    }
}

struct SOCKSUDPDatagram {
    let target: RequestTarget
    let payload: Data
}

func parseSOCKSUDPDatagram(_ data: Data) -> Result<SOCKSUDPDatagram, Error> {
    Result { let parsed = try NativeProtocolCodec.parseSOCKSUDP(data)
        return SOCKSUDPDatagram(target: parsed.0, payload: parsed.1) }
}

func parseSOCKSAddress(_ data: Data, type: UInt8) -> Result<RequestTarget, Error> {
    guard data.count >= 3 else { return .failure(EngineError("SOCKS5 地址过短")) }
    let host: String
    let portBytes: Data
    switch type {
    case 0x01:
        guard data.count == 6 else { return .failure(EngineError("SOCKS5 IPv4 地址无效")) }
        host = data.prefix(4).map(String.init).joined(separator: ".")
        portBytes = data.suffix(2)
    case 0x04:
        guard data.count == 18 else { return .failure(EngineError("SOCKS5 IPv6 地址无效")) }
        var address = in6_addr()
        _ = withUnsafeMutableBytes(of: &address) { data.prefix(16).copyBytes(to: $0) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
            return .failure(EngineError("SOCKS5 IPv6 转换失败"))
        }
        host = String(cString: buffer)
        portBytes = data.suffix(2)
    case 0x03:
        guard data.count >= 3, let value = String(data: data.dropLast(2), encoding: .utf8) else {
            return .failure(EngineError("SOCKS5 域名无效"))
        }
        host = value
        portBytes = data.suffix(2)
    default: return .failure(EngineError("SOCKS5 地址类型无效"))
    }
    let port = UInt16(portBytes[portBytes.startIndex]) << 8 | UInt16(portBytes[portBytes.index(after: portBytes.startIndex)])
    return .success(RequestTarget(host: host, port: port, protocolName: "TCP"))
}

func socksAddress(host rawHost: String, port: UInt16) -> Data {
    var host = DoHEndpoint.unbracketed(rawHost)
    if host.contains(":"), let pct = host.firstIndex(of: "%") { host = String(host[..<pct]) }
    var ipv4 = in_addr()
    var ipv6 = in6_addr()
    var data = Data()
    if inet_pton(AF_INET, host, &ipv4) == 1 {
        data.append(0x01)
        withUnsafeBytes(of: &ipv4) { data.append(contentsOf: $0) }
    } else if inet_pton(AF_INET6, host, &ipv6) == 1 {
        data.append(0x04)
        withUnsafeBytes(of: &ipv6) { data.append(contentsOf: $0) }
    } else {
        let bytes = Data(host.utf8.prefix(255))
        data.append(0x03); data.append(UInt8(bytes.count)); data.append(bytes)
    }
    data.append(UInt8(port >> 8)); data.append(UInt8(port & 0xff))
    return data
}

/// Loopback traffic must stay on the loopback interface even while enhanced
/// mode pins ordinary outbound sockets to the physical interface. Advanced
/// protocol adapters are exposed to the engine through 127.0.0.1 listeners.
func isLoopbackHost(_ rawHost: String) -> Bool {
    var host = rawHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    if let zone = host.firstIndex(of: "%") { host = String(host[..<zone]) }
    if host == "localhost" || host == "::1" || host.hasPrefix("127.") { return true }

    var address = in_addr()
    guard inet_pton(AF_INET, host, &address) == 1 else { return false }
    return UInt32(bigEndian: address.s_addr) >> 24 == 127
}

func parseHostPort(_ value: String, defaultPort: UInt16) -> (String, UInt16)? {
    if value.hasPrefix("["), let bracket = value.firstIndex(of: "]") {
        let host = String(value[value.index(after: value.startIndex)..<bracket])
        let rest = value[value.index(after: bracket)...]
        if rest.first == ":", let port = UInt16(rest.dropFirst()) { return (host, port) }
        return (host, defaultPort)
    }
    if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":"),
       let port = UInt16(value[value.index(after: colon)...]) {
        return (String(value[..<colon]), port)
    }
    return value.isEmpty ? nil : (value, defaultPort)
}

func hostPort(_ host: String, _ port: UInt16) -> String {
    (host.contains(":") && !host.hasPrefix("[")) ? "[\(host)]:\(port)" : "\(host):\(port)"
}

func endpointDescription(_ endpoint: NWEndpoint) -> String {
    switch endpoint {
    case .hostPort(let host, let port): return "\(host):\(port)"
    default: return String(describing: endpoint)
    }
}

func peerAddress(_ endpoint: NWEndpoint) -> (host: String?, port: UInt16?) {
    switch endpoint {
    case .hostPort(let host, let port):
        return (String(describing: host), port.rawValue)
    default:
        return (nil, nil)
    }
}

/// Picks a free local TCP port for HTTP/SOCKS listeners.
///
/// Prefer the profile port; if it is taken, walk nearby ports then a random
/// high range so engine start never fails solely because another proxy owns
/// 7162/7163.
enum ListenPortAllocator {
    static func availableAddress(preferred: ListenAddress, kind: String,
                                 excluding: Set<UInt16>,
                                 forceAlternate: Bool = false) throws -> ListenAddress {
        let host = preferred.host.isEmpty ? "127.0.0.1" : preferred.host
        var blocked = excluding
        if !forceAlternate, preferred.port > 0, !blocked.contains(preferred.port),
           canBind(host: host, port: preferred.port) {
            return ListenAddress(host: preferred.host, port: preferred.port)
        }
        blocked.insert(preferred.port)

        // Nearby first so the UI stays close to the configured values.
        if preferred.port > 0 {
            for delta in 1...64 {
                for candidate in [preferred.port &+ UInt16(delta),
                                  preferred.port &- UInt16(delta)] where candidate >= 1024 {
                    if blocked.contains(candidate) { continue }
                    blocked.insert(candidate)
                    if canBind(host: host, port: candidate) {
                        return ListenAddress(host: preferred.host, port: candidate)
                    }
                }
            }
        }

        // Random high ports as a last resort.
        let base = UInt16.random(in: 20_000...55_000)
        for offset in 0..<2_000 {
            let candidate = base &+ UInt16(offset)
            if candidate < 1024 || blocked.contains(candidate) { continue }
            blocked.insert(candidate)
            if canBind(host: host, port: candidate) {
                return ListenAddress(host: preferred.host, port: candidate)
            }
        }
        throw EngineError("无法为 \(kind) 找到可用监听端口")
    }

    /// True when nothing is accepting TCP on the address.
    ///
    /// This must not bind-and-close the candidate. A probe bind without
    /// `SO_REUSEADDR` leaves the port reserved; `NWListener` then either
    /// fails with EADDRINUSE or sits in `.waiting` until start times out.
    private static func canBind(host: String, port: UInt16) -> Bool {
        if host.contains(":") {
            return !isListeningIPv6(host: host, port: port)
        }
        return !isListeningIPv4(host: host, port: port)
    }

    private static func isListeningIPv4(host: String, port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { Darwin.close(fd) }
        setNonBlocking(fd)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        if host == "0.0.0.0" || host.isEmpty {
            address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        } else {
            var addr = in_addr()
            guard host.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return true }
            address.sin_addr = addr
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return connectReachedListener(fd: fd, result: result)
    }

    private static func isListeningIPv6(host: String, port: UInt16) -> Bool {
        let fd = socket(AF_INET6, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { Darwin.close(fd) }
        setNonBlocking(fd)
        var address = sockaddr_in6()
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        var clean = DoHEndpoint.unbracketed(host)
        if clean.contains(":"), let pct = clean.firstIndex(of: "%") { clean = String(clean[..<pct]) }
        if clean == "::" || clean.isEmpty {
            address.sin6_addr = in6addr_loopback
        } else {
            var addr = in6_addr()
            guard clean.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return true }
            address.sin6_addr = addr
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        return connectReachedListener(fd: fd, result: result)
    }

    private static func setNonBlocking(_ fd: Int32) {
        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
    }

    /// `connect` succeeded or is in progress toward an accepting socket.
    /// `ECONNREFUSED` (and friends) means the port is free.
    private static func connectReachedListener(fd: Int32, result: Int32) -> Bool {
        if result == 0 { return true }
        let code = errno
        if code == ECONNREFUSED || code == EHOSTUNREACH || code == ENETUNREACH {
            return false
        }
        if code == EINPROGRESS || code == EWOULDBLOCK {
            var pollFD = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&pollFD, 1, 40)
            if ready > 0, pollFD.revents & Int16(POLLOUT) != 0 {
                var error: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                _ = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length)
                return error == 0
            }
            return false
        }
        return false
    }
}

final class DNSMappingCache {
    private struct Entry {
        let domain: String
        let expiresAt: CFAbsoluteTime
    }
    private let lock = NSLock()
    private var entries: [String: Entry] = [:]

    func set(domain: String, for address: String, ttl: UInt32) {
        let lifetime = max(1, min(TimeInterval(ttl), 86_400))
        let expiration = CFAbsoluteTimeGetCurrent() + lifetime
        lock.lock()
        if entries.count >= 16_384 { entries.removeAll(keepingCapacity: true) }
        entries[address.lowercased()] = Entry(domain: domain.lowercased(),
                                               expiresAt: expiration)
        lock.unlock()
    }

    func domain(for address: String) -> String? {
        guard let first = address.utf8.first,
              (first >= 48 && first <= 57) || address.utf8.contains(58) else {
            return nil
        }
        lock.lock(); defer { lock.unlock() }
        guard !entries.isEmpty else { return nil }
        let key = address.lowercased()
        guard let entry = entries[key] else { return nil }
        if entry.expiresAt <= CFAbsoluteTimeGetCurrent() {
            entries.removeValue(forKey: key)
            return nil
        }
        return entry.domain
    }

    func removeAll() {
        lock.lock(); entries.removeAll(); lock.unlock()
    }
}

struct DNSAddressRecord {
    let domain: String
    let address: String
    let ttl: UInt32
}

/// Test seam over `DNSMessage`, which is private to this file.
enum DNSMessageProbe {
    static func addressRecords(in data: Data) -> [(domain: String, address: String, ttl: UInt32)] {
        DNSMessageInspection.addressAnswers(in: data)
    }
}

enum DNSMessage {
    static func addressRecords(in data: Data) -> [DNSAddressRecord] {
        guard data.count >= 12 else { return [] }
        let questionCount = Int(readUInt16(data, 4) ?? 0)
        let answerCount = Int(readUInt16(data, 6) ?? 0)
        guard questionCount > 0 else { return [] }
        var offset = 12
        guard let queryName = readName(data, offset: &offset) else { return [] }
        guard offset + 4 <= data.count else { return [] }
        offset += 4
        if questionCount > 1 {
            for _ in 1..<questionCount {
                guard readName(data, offset: &offset) != nil, offset + 4 <= data.count else { return [] }
                offset += 4
            }
        }

        var result: [DNSAddressRecord] = []
        for _ in 0..<answerCount {
            guard readName(data, offset: &offset) != nil, offset + 10 <= data.count,
                  let type = readUInt16(data, offset),
                  let ttl = readUInt32(data, offset + 4),
                  let length = readUInt16(data, offset + 8) else { break }
            offset += 10
            let count = Int(length)
            guard offset + count <= data.count else { break }
            if type == 1, count == 4 {
                let bytes = data[offset..<(offset + 4)]
                result.append(DNSAddressRecord(domain: queryName,
                                               address: bytes.map(String.init).joined(separator: "."), ttl: ttl))
            } else if type == 28, count == 16 {
                var address = in6_addr()
                _ = withUnsafeMutableBytes(of: &address) { data[offset..<(offset + 16)].copyBytes(to: $0) }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    result.append(DNSAddressRecord(domain: queryName, address: String(cString: buffer), ttl: ttl))
                }
            }
            offset += count
        }
        return result
    }

    private static func readName(_ data: Data, offset: inout Int, depth: Int = 0) -> String? {
        guard depth < 16 else { return nil }
        var labels: [String] = []
        var cursor = offset
        var consumed = 0
        var jumped = false
        while cursor < data.count {
            let length = Int(data[cursor])
            if length == 0 {
                if !jumped { consumed += 1 }
                offset += consumed
                return labels.joined(separator: ".")
            }
            if length & 0xC0 == 0xC0 {
                guard cursor + 1 < data.count else { return nil }
                let pointer = ((length & 0x3F) << 8) | Int(data[cursor + 1])
                if !jumped { consumed += 2 }
                jumped = true
                var pointerOffset = pointer
                guard let suffix = readName(data, offset: &pointerOffset, depth: depth + 1) else { return nil }
                if !suffix.isEmpty { labels.append(suffix) }
                offset += consumed
                return labels.joined(separator: ".")
            }
            guard length <= 63, cursor + 1 + length <= data.count,
                  let label = String(data: data[(cursor + 1)..<(cursor + 1 + length)], encoding: .utf8) else {
                return nil
            }
            labels.append(label)
            cursor += 1 + length
            if !jumped { consumed += 1 + length }
        }
        return nil
    }

    private static func readUInt16(_ data: Data, _ offset: Int) -> UInt16? {
        guard offset + 2 <= data.count else { return nil }
        return UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    private static func readUInt32(_ data: Data, _ offset: Int) -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        return UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 |
            UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
    }
}

extension Result {
    var error: Failure? {
        if case .failure(let error) = self { return error }
        return nil
    }
}


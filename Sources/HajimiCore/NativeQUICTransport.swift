import Foundation
import Network
import Security

enum NativeQUICError: LocalizedError {
    case unavailable
    case invalidEndpoint
    case connection(String)
    case protocolError(String)
    case exporter

    var errorDescription: String? {
        switch self {
        case .unavailable: return "当前 macOS 不支持原生 QUIC Datagram"
        case .invalidEndpoint: return "QUIC 服务端地址无效"
        case .connection(let value): return "原生 QUIC 连接失败：\(value)"
        case .protocolError(let value): return "原生 QUIC 协议错误：\(value)"
        case .exporter: return "无法从 QUIC TLS 会话导出 TUIC 认证密钥"
        }
    }
}

/// A physical QUIC connection shared by independent streams and RFC 9221
/// datagrams. Hysteria, Hysteria2 and TUIC own their wire formats; this type
/// deliberately owns only TLS, multiplexing, interface binding and lifecycle.
@available(macOS 13.0, *)
final class NativeQUICSession {
    private let endpoint: NWEndpoint
    private let group: NWConnectionGroup
    private let queue: DispatchQueue
    private var datagramConnection: NWConnection?
    private var children: [ObjectIdentifier: NWConnection] = [:]
    private var cancelled = false

    var incomingStreamHandler: ((NWConnection) -> Void)?

    init(host: String, port: UInt16, alpn: [String], serverName: String,
         skipCertificateVerification: Bool, interface: NWInterface?,
         maximumDatagramSize: Int = 1_200, queue: DispatchQueue) throws {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw NativeQUICError.invalidEndpoint
        }
        endpoint = .hostPort(host: NWEndpoint.Host(host), port: endpointPort)
        self.queue = queue

        let options = NWProtocolQUIC.Options(alpn: alpn)
        options.direction = .bidirectional
        options.idleTimeout = 60_000
        options.maxUDPPayloadSize = 1_350
        options.initialMaxData = 64 * 1_024 * 1_024
        options.initialMaxStreamDataBidirectionalRemote = 16 * 1_024 * 1_024
        options.initialMaxStreamDataBidirectionalLocal = 16 * 1_024 * 1_024
        options.initialMaxStreamDataUnidirectional = 4 * 1_024 * 1_024
        options.initialMaxStreamsBidirectional = 1_024
        options.initialMaxStreamsUnidirectional = 1_024
        options.maxDatagramFrameSize = max(1_200, maximumDatagramSize)
        if !serverName.isEmpty {
            sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, serverName)
        }
        if skipCertificateVerification {
            sec_protocol_options_set_verify_block(options.securityProtocolOptions,
                                                   { _, _, complete in complete(true) }, queue)
        }

        let parameters = NWParameters(quic: options)
        parameters.requiredInterface = interface
        group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: parameters)
        group.newConnectionHandler = { [weak self] connection in
            guard let self, !self.cancelled else { connection.cancel(); return }
            self.track(connection)
            if let handler = self.incomingStreamHandler { handler(connection) }
            else { self.drainIncoming(connection) }
        }
    }

    func start(timeout: TimeInterval = 12,
               completion: @escaping (Result<Void, Error>) -> Void) {
        var finished = false
        func finish(_ result: Result<Void, Error>) {
            guard !finished else { return }
            finished = true
            completion(result)
        }
        group.stateUpdateHandler = { state in
            quicTransportTrace("group \(self.endpoint): \(state)")
            switch state {
            case .ready: finish(.success(()))
            case .failed(let error):
                finish(.failure(NativeQUICError.connection(error.debugDescription)))
            case .cancelled:
                finish(.failure(NativeQUICError.connection("连接已取消")))
            default: break
            }
        }
        group.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard !finished else { return }
            self?.cancel()
            finish(.failure(NativeQUICError.connection("握手超时")))
        }
    }

    func openStream(direction: NWProtocolQUIC.Options.Direction = .bidirectional) throws -> NWConnection {
        guard !cancelled else { throw NativeQUICError.connection("连接已关闭") }
        let connection: NWConnection?
        if direction == .bidirectional {
            // Ventura 13 rejects a child QUIC options object with ENETDOWN;
            // the inherited bidirectional stream initializer is the working
            // API on that release.
            connection = NWConnection(from: group)
        } else {
            let options = NWProtocolQUIC.Options()
            options.direction = direction
            connection = NWConnection(from: group, to: nil, using: options)
        }
        guard let connection else {
            throw NativeQUICError.connection("无法创建 QUIC 子流")
        }
        track(connection)
        connection.start(queue: queue)
        return connection
    }

    func openDatagramFlow() throws -> NWConnection {
        if let datagramConnection { return datagramConnection }
        guard !cancelled else { throw NativeQUICError.connection("连接已关闭") }
        let options = NWProtocolQUIC.Options()
        options.isDatagram = true
        guard let connection = NWConnection(from: group, to: nil, using: options) else {
            throw NativeQUICError.connection("无法创建 QUIC Datagram 流")
        }
        track(connection)
        connection.start(queue: queue)
        datagramConnection = connection
        return connection
    }

    func negotiatedALPN() -> String? {
        (group.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata)?.negotiatedALPN
    }

    /// RFC 5705 / RFC 8446 exporter used by TUIC v5. The TUIC label is the
    /// UUID's 16 raw bytes (not its printable form) and the context is the raw
    /// password bytes.
    func exportKeyingMaterial(label: Data, context: Data, length: Int) throws -> Data {
        guard length > 0, !label.isEmpty, !context.isEmpty,
              let metadata = group.metadata(definition: NWProtocolQUIC.definition)
                as? NWProtocolQUIC.Metadata else { throw NativeQUICError.exporter }
        let secret = label.withUnsafeBytes { labelRaw in
            context.withUnsafeBytes { contextRaw in
                return sec_protocol_metadata_create_secret_with_context(
                    metadata.securityProtocolMetadata,
                    label.count, labelRaw.baseAddress!.assumingMemoryBound(to: CChar.self),
                    context.count, contextRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    length)
            }
        }
        guard let secret else { throw NativeQUICError.exporter }
        return Data(secret as DispatchData)
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        let values = Array(children.values)
        children.removeAll()
        datagramConnection = nil
        values.forEach { $0.cancel() }
        group.cancel()
    }

    private func track(_ connection: NWConnection) {
        children[ObjectIdentifier(connection)] = connection
    }

    private func drainIncoming(_ connection: NWConnection) {
        connection.start(queue: queue)
        func read() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1_024) {
                _, _, complete, error in
                if error != nil || complete { connection.cancel(); return }
                read()
            }
        }
        read()
    }
}

@available(macOS 13.0, *)
final class NativeQUICByteStream: NativeOutboundByteStream {
    private let connection: NWConnection
    private var prefix: Data
    private var cancelled = false

    init(_ connection: NWConnection, prefix: Data = Data()) {
        self.connection = connection
        self.prefix = prefix
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !cancelled else {
            completion(NativeQUICError.connection("子流已关闭")); return
        }
        connection.send(content: data, completion: .contentProcessed(completion))
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        guard !cancelled else { completion(nil, true, nil); return }
        if !prefix.isEmpty {
            let count = min(maximum, prefix.count)
            let value = Data(prefix.prefix(count))
            prefix.removeFirst(count)
            completion(value, false, nil)
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) {
            data, _, complete, error in completion(data, complete, error)
        }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        connection.cancel()
    }
}

@available(macOS 13.0, *)
final class NativeQUICBufferedReader {
    private let connection: NWConnection
    private var buffer = Data()
    private var ended = false
    private var pending = false

    init(_ connection: NWConnection) { self.connection = connection }

    func readExactly(_ count: Int, completion: @escaping (Result<Data, Error>) -> Void) {
        guard count >= 0 else {
            completion(.failure(NativeQUICError.protocolError("读取长度无效"))); return
        }
        if buffer.count >= count {
            let value = Data(buffer.prefix(count)); buffer.removeFirst(count)
            completion(.success(value)); return
        }
        guard !ended else {
            completion(.failure(NativeQUICError.protocolError("QUIC 子流提前结束"))); return
        }
        guard !pending else {
            completion(.failure(NativeQUICError.protocolError("QUIC 子流发生并发读取"))); return
        }
        pending = true
        connection.receive(minimumIncompleteLength: 1, maximumLength: 262_144) {
            [weak self] data, _, complete, error in
            guard let self else { return }
            self.pending = false
            if let data { self.buffer.append(data) }
            if complete { self.ended = true }
            if let error { completion(.failure(error)); return }
            self.readExactly(count, completion: completion)
        }
    }

    func readQUICVarint(completion: @escaping (Result<UInt64, Error>) -> Void) {
        readExactly(1) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let firstData):
                let first = firstData[0]
                let count = 1 << Int(first >> 6)
                if count == 1 { completion(.success(UInt64(first & 0x3f))); return }
                self.readExactly(count - 1) { rest in
                    completion(rest.map { bytes in
                        var value = UInt64(first & 0x3f)
                        for byte in bytes { value = (value << 8) | UInt64(byte) }
                        return value
                    })
                }
            }
        }
    }

    func takeBufferedData() -> Data {
        let value = buffer; buffer.removeAll(keepingCapacity: false); return value
    }
}

@available(macOS 13.0, *)
func waitForQUICStreamReady(_ connection: NWConnection, queue: DispatchQueue,
                            timeout: TimeInterval = 10,
                            completion: @escaping (Result<Void, Error>) -> Void) {
    var finished = false
    func finish(_ result: Result<Void, Error>) {
        guard !finished else { return }
        finished = true
        connection.stateUpdateHandler = nil
        completion(result)
    }
    connection.stateUpdateHandler = { state in
        quicTransportTrace("stream: \(state)")
        switch state {
        case .ready: finish(.success(()))
        case .failed(let error): finish(.failure(error))
        case .cancelled: finish(.failure(NativeQUICError.connection("子流已取消")))
        default: break
        }
    }
    queue.asyncAfter(deadline: .now() + timeout) {
        guard !finished else { return }
        connection.cancel()
        finish(.failure(NativeQUICError.connection("子流打开超时")))
    }
}

private func quicTransportTrace(_ value: String) {
    guard ProcessInfo.processInfo.environment["HAJIMI_NATIVE_DEBUG"] == "1" else { return }
    FileHandle.standardError.write(Data("[LurgeQUIC] \(value)\n".utf8))
}

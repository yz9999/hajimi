import Foundation
import Network
import Security
import Darwin

/// Native QUIC protocol entry point. Capability is deliberately reported only
/// for wire options implemented below; unsupported UDP obfuscation and port
/// hopping are rejected instead of being silently ignored.
enum NativeQUICOutbound {
    static func selfTest() throws {
        try NativeCXXOutbound.selfTest()
        for value: UInt64 in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let encoded = quicVarint(value)
            guard parseQUICVarint(encoded, offset: 0)?.value == value else {
                throw NativeQUICError.protocolError("QUIC varint 自检失败")
            }
        }
        let fields = [(":method", "POST"), (":scheme", "https"),
                      (":authority", "hysteria"), (":path", "/auth"),
                      ("hysteria-auth", "secret"), ("hysteria-cc-rx", "0")]
        let decoded = try QPACKCodec.decode(QPACKCodec.encode(fields))
        guard decoded.count == fields.count,
              zip(decoded, fields).allSatisfy({ $0.0.0 == $0.1.0 && $0.0.1 == $0.1.1 }) else {
            throw NativeQUICError.protocolError("QPACK 往返自检失败")
        }
        let huffman = Data([0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff])
        guard try HPACKHuffman.decode(huffman) == "www.example.com" else {
            throw NativeQUICError.protocolError("HPACK Huffman 自检失败")
        }
        let targets = [RequestTarget(host: "example.com", port: 443, protocolName: "UDP"),
                       RequestTarget(host: "127.0.0.1", port: 53, protocolName: "UDP"),
                       RequestTarget(host: "2001:db8::1", port: 853, protocolName: "UDP")]
        for target in targets {
            let encoded = try tuicAddress(target)
            guard let parsed = parseTUICAddress(encoded, offset: 0)?.target,
                  parsed == target else { throw NativeQUICError.protocolError("TUIC 地址自检失败") }
        }
    }

    static func supports(_ policy: ProxyPolicy) -> Bool {
        validationError(for: policy) == nil
    }

    static func supportsUDP(_ policy: ProxyPolicy) -> Bool {
        supports(policy)
    }

    static func validationError(for policy: ProxyPolicy) -> String? {
        guard policy.kind == .external || policy.kind == .native,
              let type = policy.adapterType?.lowercased(),
              ["hysteria", "hysteria2", "tuic"].contains(type),
              policy.host?.isEmpty == false, policy.port != nil else {
            return "QUIC 节点缺少有效服务器或端口"
        }
        return NativeCXXOutbound.validationError(for: policy)
    }

    static func configure(policies: [String: ProxyPolicy]) {
        NativeStaticQUICOutbound.configure(policies: policies)
    }

    static func connect(policy: ProxyPolicy, target: RequestTarget,
                        queue: DispatchQueue,
                        completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        NativeCXXOutbound.connect(policy: policy, target: target, queue: queue, completion: completion)
    }

    static func makeDatagramSession(policy: ProxyPolicy,
                                    receive: @escaping (RequestTarget, Data) -> Void,
                                    failure: @escaping (Error) -> Void)
        throws -> NativeOutboundDatagramSession {
        try NativeStaticQUICOutbound.makeDatagramSession(policy: policy,
                                                         receive: receive, failure: failure)
    }
}

@available(macOS 13.0, *)
private protocol NativeQUICProxyClient: AnyObject {
    func connectTCP(_ target: RequestTarget,
                    completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void)
    func makeDatagramSession(receive: @escaping (RequestTarget, Data) -> Void,
                             failure: @escaping (Error) -> Void) throws
        -> NativeOutboundDatagramSession
    func cancel()
}

@available(macOS 13.0, *)
private final class NativeQUICClientPool {
    static let shared = NativeQUICClientPool()
    private struct Entry { let policy: ProxyPolicy; let client: any NativeQUICProxyClient }
    private let lock = NSLock()
    private var entries: [String: Entry] = [:]

    func configure(policies: [String: ProxyPolicy]) {
        lock.lock()
        let stale = entries.compactMap { name, entry -> (String, any NativeQUICProxyClient)? in
            guard policies[name] != entry.policy else { return nil }
            return (name, entry.client)
        }
        stale.forEach { entries.removeValue(forKey: $0.0) }
        lock.unlock()
        stale.forEach { $0.1.cancel() }
    }

    func client(for policy: ProxyPolicy) throws -> any NativeQUICProxyClient {
        if let error = NativeQUICOutbound.validationError(for: policy) {
            throw NativeOutboundError.unsupported(error)
        }
        lock.lock()
        if let entry = entries[policy.name], entry.policy == policy {
            lock.unlock(); return entry.client
        }
        lock.unlock()

        let value: any NativeQUICProxyClient
        switch policy.adapterType?.lowercased() {
        case "hysteria": value = try Hysteria1Client(policy: policy)
        case "hysteria2": value = try Hysteria2Client(policy: policy)
        case "tuic": value = try TUICv5Client(policy: policy)
        default: throw NativeOutboundError.unsupported("未知 QUIC 协议")
        }
        lock.lock()
        if let existing = entries[policy.name], existing.policy == policy {
            lock.unlock(); value.cancel(); return existing.client
        }
        let old = entries.updateValue(Entry(policy: policy, client: value), forKey: policy.name)
        lock.unlock()
        old?.client.cancel()
        return value
    }
}

@available(macOS 13.0, *)
private final class QUICReadyGate {
    private enum State { case idle, starting, ready, failed(Error), cancelled }
    private var state: State = .idle
    private var waiters: [(Result<Void, Error>) -> Void] = []

    func ensure(start: () -> Void, completion: @escaping (Result<Void, Error>) -> Void) {
        switch state {
        case .ready: completion(.success(()))
        case .failed(let error): completion(.failure(error))
        case .cancelled: completion(.failure(NativeQUICError.connection("连接已关闭")))
        case .starting: waiters.append(completion)
        case .idle:
            waiters.append(completion); state = .starting; start()
        }
    }

    func succeed() { finish(.success(()), state: .ready) }
    func fail(_ error: Error) { finish(.failure(error), state: .failed(error)) }
    func cancel() {
        finish(.failure(NativeQUICError.connection("连接已关闭")), state: .cancelled)
    }

    private func finish(_ result: Result<Void, Error>, state newState: State) {
        state = newState
        let values = waiters; waiters.removeAll()
        values.forEach { $0(result) }
    }
}

// MARK: - Hysteria v1

@available(macOS 13.0, *)
private final class Hysteria1Client: NativeQUICProxyClient {
    private let policy: ProxyPolicy
    fileprivate let queue: DispatchQueue
    private let gate = QUICReadyGate()
    private var session: NativeQUICSession?
    private var controlStream: NWConnection?
    private var datagramFlow: NWConnection?
    private var udpSessions: [UInt32: Hysteria1DatagramSession] = [:]
    private var cancelled = false

    init(policy: ProxyPolicy) throws {
        self.policy = policy
        queue = DispatchQueue(label: "app.hajimi.quic.hy1.\(safeQueueLabel(policy.name))",
                              qos: .userInitiated, autoreleaseFrequency: .workItem)
    }

    func connectTCP(_ target: RequestTarget,
                    completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureReady { result in
                switch result {
                case .failure(let error): completion(.failure(error))
                case .success: self.openRequest(target: target, udp: false) { response in
                    completion(response.map { NativeQUICByteStream($0.0, prefix: $0.1)
                        as any NativeOutboundByteStream })
                }
                }
            }
        }
    }

    func makeDatagramSession(receive: @escaping (RequestTarget, Data) -> Void,
                             failure: @escaping (Error) -> Void) throws
        -> NativeOutboundDatagramSession {
        Hysteria1DatagramSession(client: self, receive: receive, failure: failure)
    }

    func cancel() {
        queue.async { [weak self] in
            guard let self, !self.cancelled else { return }
            self.cancelled = true; self.gate.cancel()
            self.udpSessions.values.forEach { $0.fail(NativeQUICError.connection("连接已关闭")) }
            self.udpSessions.removeAll(); self.session?.cancel(); self.session = nil
        }
    }

    fileprivate func send(_ payload: Data, to target: RequestTarget,
                          through wrapper: Hysteria1DatagramSession) {
        queue.async { [weak self, weak wrapper] in
            guard let self, let wrapper, !wrapper.isCancelled else { return }
            wrapper.pending.append((payload, target))
            if wrapper.sessionID != nil { self.flush(wrapper); return }
            guard !wrapper.opening else { return }
            wrapper.opening = true
            self.ensureReady { result in
                switch result {
                case .failure(let error): wrapper.fail(error)
                case .success:
                    self.openRequest(target: RequestTarget(host: "", port: 0, protocolName: "UDP"),
                                     udp: true) { response in
                        switch response {
                        case .failure(let error): wrapper.fail(error)
                        case .success(let value):
                            guard value.2 != 0 else {
                                wrapper.fail(NativeQUICError.protocolError("Hysteria UDP 会话 ID 无效")); return
                            }
                            wrapper.opening = false; wrapper.sessionID = value.2
                            wrapper.holdStream = value.0; self.udpSessions[value.2] = wrapper
                            self.flush(wrapper)
                        }
                    }
                }
            }
        }
    }

    fileprivate func remove(_ wrapper: Hysteria1DatagramSession) {
        queue.async { [weak self, weak wrapper] in
            guard let self, let wrapper else { return }
            if let id = wrapper.sessionID { self.udpSessions.removeValue(forKey: id) }
            wrapper.holdStream?.cancel(); wrapper.holdStream = nil
        }
    }

    private func ensureReady(_ completion: @escaping (Result<Void, Error>) -> Void) {
        gate.ensure(start: { self.establish() }, completion: completion)
    }

    private func establish() {
        guard !cancelled, let host = policy.host, let port = policy.port,
              let auth = hysteria1Auth(policy) else {
            gate.fail(NativeQUICError.connection("Hysteria 配置无效")); return
        }
        do {
            let alpn = protocolValues(policy.parameters["alpn"])
            let value = try NativeQUICSession(
                host: host, port: port, alpn: alpn.isEmpty ? ["hysteria"] : alpn,
                serverName: quicServerName(policy),
                skipCertificateVerification: quicSkipVerify(policy),
                interface: quicInterface(host), queue: queue)
            session = value
            value.start { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error): self.gate.fail(error)
                case .success:
                    do {
                        let stream = try value.openStream(); self.controlStream = stream
                        waitForQUICStreamReady(stream, queue: self.queue) { ready in
                            switch ready {
                            case .failure(let error): self.gate.fail(error)
                            case .success: self.sendClientHello(stream: stream, auth: auth)
                            }
                        }
                    } catch { self.gate.fail(error) }
                }
            }
        } catch { gate.fail(error) }
    }

    private func sendClientHello(stream: NWConnection, auth: String) {
        var hello = Data([0x03])
        appendBE(parseBandwidth(policy.parameters["up"] ?? policy.parameters["up-speed"] ??
                                policy.parameters["upload-bandwidth"]), to: &hello)
        appendBE(parseBandwidth(policy.parameters["down"] ?? policy.parameters["down-speed"] ??
                                policy.parameters["download-bandwidth"]), to: &hello)
        let authData = Data(auth.utf8)
        guard authData.count <= Int(UInt16.max) else {
            gate.fail(NativeQUICError.protocolError("Hysteria auth 过长")); return
        }
        appendBE(UInt16(authData.count), to: &hello); hello.append(authData)
        stream.send(content: hello, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error { self.gate.fail(error); return }
            let reader = NativeQUICBufferedReader(stream)
            reader.readExactly(19) { result in
                switch result {
                case .failure(let error): self.gate.fail(error)
                case .success(let header):
                    let ok = header[0] != 0
                    let messageLength = Int(readBE16(header, 17))
                    reader.readExactly(messageLength) { messageResult in
                        switch messageResult {
                        case .failure(let error): self.gate.fail(error)
                        case .success(let message):
                            guard ok else {
                                self.gate.fail(NativeQUICError.protocolError(
                                    "Hysteria 认证失败：\(String(data: message, encoding: .utf8) ?? "未知原因")"))
                                return
                            }
                            self.startDatagramReceiver(); self.gate.succeed()
                        }
                    }
                }
            }
        })
    }

    /// Returns stream, any coalesced target bytes, and UDP session ID.
    private func openRequest(target: RequestTarget, udp: Bool,
                             completion: @escaping (Result<(NWConnection, Data, UInt32), Error>) -> Void) {
        guard let session else {
            completion(.failure(NativeQUICError.connection("Hysteria 会话未建立"))); return
        }
        do {
            let stream = try session.openStream()
            waitForQUICStreamReady(stream, queue: queue) { ready in
                if case .failure(let error) = ready { completion(.failure(error)); return }
                let hostData = Data((udp ? "" : target.host).utf8)
                guard hostData.count <= Int(UInt16.max) else {
                    stream.cancel(); completion(.failure(NativeQUICError.protocolError("目标域名过长"))); return
                }
                var request = Data([udp ? 1 : 0]); appendBE(UInt16(hostData.count), to: &request)
                request.append(hostData); appendBE(udp ? UInt16(0) : target.port, to: &request)
                stream.send(content: request, completion: .contentProcessed { error in
                    if let error { stream.cancel(); completion(.failure(error)); return }
                    let reader = NativeQUICBufferedReader(stream)
                    reader.readExactly(7) { headerResult in
                        switch headerResult {
                        case .failure(let error): stream.cancel(); completion(.failure(error))
                        case .success(let header):
                            let ok = header[0] != 0
                            let sessionID = readBE32(header, 1)
                            let messageLength = Int(readBE16(header, 5))
                            reader.readExactly(messageLength) { messageResult in
                                switch messageResult {
                                case .failure(let error): stream.cancel(); completion(.failure(error))
                                case .success(let message):
                                    guard ok else {
                                        stream.cancel()
                                        completion(.failure(NativeQUICError.protocolError(
                                            "Hysteria 连接被拒绝：\(String(data: message, encoding: .utf8) ?? "未知原因")")))
                                        return
                                    }
                                    completion(.success((stream, reader.takeBufferedData(), sessionID)))
                                }
                            }
                        }
                    }
                })
            }
        } catch { completion(.failure(error)) }
    }

    private func startDatagramReceiver() {
        guard datagramFlow == nil, let session else { return }
        do {
            let flow = try session.openDatagramFlow(); datagramFlow = flow
            func read() {
                flow.receiveMessage { [weak self] data, _, _, error in
                    guard let self, !self.cancelled else { return }
                    if let error { self.failAllUDP(error); return }
                    if let data { self.handleDatagram(data) }
                    read()
                }
            }
            read()
        } catch { failAllUDP(error) }
    }

    private func flush(_ wrapper: Hysteria1DatagramSession) {
        guard let id = wrapper.sessionID, let flow = datagramFlow else { return }
        let values = wrapper.pending; wrapper.pending.removeAll()
        for (payload, target) in values {
            let host = Data(target.host.utf8)
            guard host.count <= Int(UInt16.max) else {
                wrapper.fail(NativeQUICError.protocolError("UDP 目标域名过长")); return
            }
            let headerSize = 4 + 2 + host.count + 2 + 2 + 1 + 1 + 2
            let maxPayload = max(1, 1_200 - headerSize)
            let count = max(1, (payload.count + maxPayload - 1) / maxPayload)
            guard count <= 255 else {
                wrapper.fail(NativeQUICError.protocolError("Hysteria UDP 数据报过大")); return
            }
            let messageID = count > 1 ? randomUInt16Nonzero() : 0
            for index in 0..<count {
                let start = index * maxPayload, end = min(payload.count, start + maxPayload)
                let part = Data(payload[start..<end])
                var value = Data(); appendBE(id, to: &value)
                appendBE(UInt16(host.count), to: &value); value.append(host); appendBE(target.port, to: &value)
                appendBE(messageID, to: &value); value.append(UInt8(index)); value.append(UInt8(count))
                appendBE(UInt16(part.count), to: &value); value.append(part)
                flow.send(content: value, completion: .contentProcessed { [weak wrapper] error in
                    if let error { wrapper?.fail(error) }
                })
            }
        }
    }

    private func handleDatagram(_ data: Data) {
        guard data.count >= 14 else { return }
        let id = readBE32(data, 0), hostLength = Int(readBE16(data, 4))
        let fixed = 6 + hostLength + 2 + 2 + 1 + 1 + 2
        guard hostLength > 0, data.count >= fixed else { return }
        let hostStart = 6, hostEnd = hostStart + hostLength
        guard let host = String(data: data[hostStart..<hostEnd], encoding: .utf8) else { return }
        let port = readBE16(data, hostEnd), messageID = readBE16(data, hostEnd + 2)
        let fragmentID = data[hostEnd + 4], fragmentCount = data[hostEnd + 5]
        let payloadLength = Int(readBE16(data, hostEnd + 6)), payloadStart = hostEnd + 8
        guard fragmentCount > 0, fragmentID < fragmentCount,
              data.count == payloadStart + payloadLength,
              let wrapper = udpSessions[id] else { return }
        let payload = Data(data[payloadStart...])
        let target = RequestTarget(host: host, port: port, protocolName: "UDP")
        wrapper.receiveFragment(packetID: messageID, index: fragmentID, count: fragmentCount,
                                target: target, payload: payload)
    }

    private func failAllUDP(_ error: Error) {
        let values = Array(udpSessions.values); udpSessions.removeAll()
        values.forEach { $0.fail(error) }
    }
}

@available(macOS 13.0, *)
private final class Hysteria1DatagramSession: NativeOutboundDatagramSession {
    fileprivate weak var client: Hysteria1Client?
    fileprivate var sessionID: UInt32?
    fileprivate var holdStream: NWConnection?
    fileprivate var opening = false
    fileprivate var pending: [(Data, RequestTarget)] = []
    fileprivate var isCancelled = false
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private var fragments: [UInt16: UDPFragments] = [:]

    init(client: Hysteria1Client, receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) {
        self.client = client; receiveHandler = receive; failureHandler = failure
    }

    func send(_ payload: Data, to target: RequestTarget) {
        guard !isCancelled else { return }
        client?.send(payload, to: target, through: self)
    }

    func cancel() {
        guard !isCancelled else { return }
        isCancelled = true; pending.removeAll(); client?.remove(self); client = nil
    }

    fileprivate func fail(_ error: Error) {
        guard !isCancelled else { return }
        isCancelled = true; pending.removeAll(); holdStream?.cancel(); failureHandler(error)
    }

    fileprivate func receiveFragment(packetID: UInt16, index: UInt8, count: UInt8,
                                     target: RequestTarget, payload: Data) {
        guard !isCancelled else { return }
        if count == 1 { receiveHandler(target, payload); return }
        var value = fragments[packetID] ?? UDPFragments(count: Int(count), target: target)
        guard value.parts.count == Int(count), Int(index) < value.parts.count else { return }
        value.parts[Int(index)] = payload; fragments[packetID] = value
        if value.parts.allSatisfy({ $0 != nil }) {
            fragments.removeValue(forKey: packetID)
            receiveHandler(value.target, value.parts.compactMap { $0 }.reduce(into: Data(), { $0.append($1) }))
        }
        if fragments.count > 64 { fragments.removeAll(keepingCapacity: true) }
    }
}

// MARK: - Hysteria 2 (HTTP/3 authentication + native QUIC streams/datagrams)

@available(macOS 13.0, *)
private final class Hysteria2Client: NativeQUICProxyClient {
    private let policy: ProxyPolicy
    fileprivate let queue: DispatchQueue
    private let gate = QUICReadyGate()
    private let idLock = NSLock()
    private var nextSessionID: UInt32 = randomUInt32Nonzero()
    private var session: NativeQUICSession?
    private var infrastructureStreams: [NWConnection] = []
    private var datagramFlow: NWConnection?
    private var udpSessions: [UInt32: Hysteria2DatagramSession] = [:]
    private var udpEnabled = false
    private var cancelled = false

    init(policy: ProxyPolicy) throws {
        self.policy = policy
        queue = DispatchQueue(label: "app.hajimi.quic.hy2.\(safeQueueLabel(policy.name))",
                              qos: .userInitiated, autoreleaseFrequency: .workItem)
    }

    func connectTCP(_ target: RequestTarget,
                    completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureReady { result in
                switch result {
                case .failure(let error): completion(.failure(error))
                case .success: self.openTCP(target, completion: completion)
                }
            }
        }
    }

    func makeDatagramSession(receive: @escaping (RequestTarget, Data) -> Void,
                             failure: @escaping (Error) -> Void) throws
        -> NativeOutboundDatagramSession {
        idLock.lock()
        let id = nextSessionID
        nextSessionID &+= 1
        if nextSessionID == 0 { nextSessionID = 1 }
        idLock.unlock()
        let wrapper = Hysteria2DatagramSession(client: self, id: id,
                                               receive: receive, failure: failure)
        queue.async { [weak self, weak wrapper] in
            guard let self, let wrapper, !wrapper.isCancelled else { return }
            self.udpSessions[id] = wrapper
        }
        return wrapper
    }

    func cancel() {
        queue.async { [weak self] in
            guard let self, !self.cancelled else { return }
            self.cancelled = true; self.gate.cancel()
            let values = Array(self.udpSessions.values); self.udpSessions.removeAll()
            values.forEach { $0.fail(NativeQUICError.connection("连接已关闭")) }
            self.session?.cancel(); self.session = nil
        }
    }

    fileprivate func send(_ payload: Data, to target: RequestTarget,
                          through wrapper: Hysteria2DatagramSession) {
        queue.async { [weak self, weak wrapper] in
            guard let self, let wrapper, !wrapper.isCancelled else { return }
            self.ensureReady { result in
                switch result {
                case .failure(let error): wrapper.fail(error)
                case .success:
                    guard self.udpEnabled, let flow = self.datagramFlow else {
                        wrapper.fail(NativeQUICError.protocolError("Hysteria2 服务端未启用 UDP")); return
                    }
                    self.sendDatagram(payload, target: target, sessionID: wrapper.id,
                                      flow: flow, failure: wrapper.fail)
                }
            }
        }
    }

    fileprivate func remove(_ wrapper: Hysteria2DatagramSession) {
        queue.async { [weak self] in self?.udpSessions.removeValue(forKey: wrapper.id) }
    }

    private func ensureReady(_ completion: @escaping (Result<Void, Error>) -> Void) {
        gate.ensure(start: { self.establish() }, completion: completion)
    }

    private func establish() {
        guard !cancelled, let host = policy.host, let port = policy.port,
              let auth = hysteria2Auth(policy) else {
            gate.fail(NativeQUICError.connection("Hysteria2 配置无效")); return
        }
        do {
            let value = try NativeQUICSession(
                host: host, port: port, alpn: ["h3"], serverName: quicServerName(policy),
                skipCertificateVerification: quicSkipVerify(policy),
                interface: quicInterface(host), queue: queue)
            session = value
            value.incomingStreamHandler = { [weak self] in self?.drainHTTP3PeerStream($0) }
            value.start { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error): self.gate.fail(error)
                case .success:
                    guard value.negotiatedALPN() == "h3" else {
                        self.gate.fail(NativeQUICError.protocolError(
                            "Hysteria2 服务端未协商 HTTP/3（ALPN=\(value.negotiatedALPN() ?? "空")）"))
                        return
                    }
                    self.openHTTP3Infrastructure(auth: auth)
                }
            }
        } catch { gate.fail(error) }
    }

    private func openHTTP3Infrastructure(auth: String) {
        guard let session else { gate.fail(NativeQUICError.connection("QUIC 会话不存在")); return }
        // Control stream: stream type 0, SETTINGS with QPACK capacity=0 and
        // blocked-streams=0. The two QPACK streams keep the connection fully
        // conformant while all header blocks intentionally remain static.
        let payloads = [Data([0x00, 0x04, 0x04, 0x01, 0x00, 0x07, 0x00]),
                        Data([0x02]), Data([0x03])]
        var remaining = payloads.count
        var failed = false
        for payload in payloads {
            do {
                let stream = try session.openStream(direction: .unidirectional)
                infrastructureStreams.append(stream)
                waitForQUICStreamReady(stream, queue: queue) { [weak self] result in
                    guard let self, !failed else { return }
                    switch result {
                    case .failure(let error): failed = true; self.gate.fail(error)
                    case .success:
                        stream.send(content: payload, completion: .contentProcessed { error in
                            guard !failed else { return }
                            if let error { failed = true; self.gate.fail(error); return }
                            remaining -= 1
                            if remaining == 0 { self.sendHTTP3Auth(auth: auth) }
                        })
                    }
                }
            } catch { failed = true; gate.fail(error); return }
        }
    }

    private func sendHTTP3Auth(auth: String) {
        guard let session else { gate.fail(NativeQUICError.connection("QUIC 会话不存在")); return }
        do {
            let stream = try session.openStream()
            waitForQUICStreamReady(stream, queue: queue) { [weak self] result in
                guard let self else { return }
                if case .failure(let error) = result { self.gate.fail(error); return }
                do {
                    let fields = [
                        (":method", "POST"), (":scheme", "https"),
                        (":authority", "hysteria"), (":path", "/auth"),
                        ("hysteria-auth", auth), ("hysteria-cc-rx", "0"),
                        ("content-length", "0")
                    ]
                    let block = try QPACKCodec.encode(fields)
                    var frame = quicVarint(0x01); frame.append(quicVarint(UInt64(block.count)))
                    frame.append(block)
                    stream.send(content: frame, contentContext: .finalMessage,
                                isComplete: true, completion: .contentProcessed { error in
                        if let error { self.gate.fail(error); return }
                        self.readHTTP3AuthResponse(stream: stream, buffer: Data())
                    })
                } catch { self.gate.fail(error) }
            }
        } catch { gate.fail(error) }
    }

    private func readHTTP3AuthResponse(stream: NWConnection, buffer: Data) {
        var value = buffer
        while let typePair = parseQUICVarint(value, offset: 0),
              let lengthPair = parseQUICVarint(value, offset: typePair.length) {
            let start = typePair.length + lengthPair.length
            guard lengthPair.value <= UInt64(Int.max),
                  value.count >= start + Int(lengthPair.value) else { break }
            let payload = Data(value[start..<(start + Int(lengthPair.value))])
            value.removeFirst(start + Int(lengthPair.value))
            if typePair.value == 0x01 {
                do {
                    let headers = try QPACKCodec.decode(payload)
                    let status = headers.first(where: { $0.0 == ":status" })?.1
                    guard status == "233" else {
                        gate.fail(NativeQUICError.protocolError(
                            "Hysteria2 认证失败，HTTP/3 状态码 \(status ?? "缺失")")); return
                    }
                    udpEnabled = parseBooleanHeader(headers.first(where: {
                        $0.0.lowercased() == "hysteria-udp"
                    })?.1)
                    stream.cancel()
                    if udpEnabled { startDatagramReceiver() }
                    gate.succeed(); return
                } catch { gate.fail(error); return }
            }
        }
        stream.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1_024) {
            [weak self] data, _, complete, error in
            guard let self else { return }
            if let error { self.gate.fail(error); return }
            var next = value; if let data { next.append(data) }
            if complete {
                self.gate.fail(NativeQUICError.protocolError("Hysteria2 HTTP/3 认证响应提前结束")); return
            }
            self.readHTTP3AuthResponse(stream: stream, buffer: next)
        }
    }

    private func drainHTTP3PeerStream(_ stream: NWConnection) {
        stream.start(queue: queue)
        func read() {
            stream.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1_024) {
                _, _, complete, error in
                if complete || error != nil { stream.cancel(); return }
                read()
            }
        }
        read()
    }

    private func openTCP(_ target: RequestTarget,
                         completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        guard let session else {
            completion(.failure(NativeQUICError.connection("Hysteria2 会话未建立"))); return
        }
        do {
            let stream = try session.openStream()
            waitForQUICStreamReady(stream, queue: queue) { ready in
                if case .failure(let error) = ready { completion(.failure(error)); return }
                let address = Data(hostPortString(target.host, target.port).utf8)
                guard address.count <= 2_048 else {
                    stream.cancel(); completion(.failure(NativeQUICError.protocolError("目标地址过长"))); return
                }
                var request = quicVarint(0x401); request.append(quicVarint(UInt64(address.count)))
                request.append(address); request.append(quicVarint(0))
                stream.send(content: request, completion: .contentProcessed { error in
                    if let error { stream.cancel(); completion(.failure(error)); return }
                    let reader = NativeQUICBufferedReader(stream)
                    reader.readExactly(1) { statusResult in
                        switch statusResult {
                        case .failure(let error): stream.cancel(); completion(.failure(error))
                        case .success(let status):
                            reader.readQUICVarint { lengthResult in
                                switch lengthResult {
                                case .failure(let error): stream.cancel(); completion(.failure(error))
                                case .success(let length):
                                    guard length <= 2_048 else {
                                        stream.cancel(); completion(.failure(
                                            NativeQUICError.protocolError("Hysteria2 响应消息过长"))); return
                                    }
                                    reader.readExactly(Int(length)) { messageResult in
                                        switch messageResult {
                                        case .failure(let error): stream.cancel(); completion(.failure(error))
                                        case .success(let message):
                                            reader.readQUICVarint { paddingResult in
                                                switch paddingResult {
                                                case .failure(let error): stream.cancel(); completion(.failure(error))
                                                case .success(let padding):
                                                    guard padding <= 4_096 else {
                                                        stream.cancel(); completion(.failure(
                                                            NativeQUICError.protocolError("Hysteria2 响应填充过长"))); return
                                                    }
                                                    reader.readExactly(Int(padding)) { finalResult in
                                                        switch finalResult {
                                                        case .failure(let error): stream.cancel(); completion(.failure(error))
                                                        case .success:
                                                            guard status[0] == 0 else {
                                                                stream.cancel(); completion(.failure(
                                                                    NativeQUICError.protocolError(
                                                                        "Hysteria2 连接被拒绝：\(String(data: message, encoding: .utf8) ?? "未知原因")")))
                                                                return
                                                            }
                                                            completion(.success(NativeQUICByteStream(
                                                                stream, prefix: reader.takeBufferedData())))
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                })
            }
        } catch { completion(.failure(error)) }
    }

    private func startDatagramReceiver() {
        guard datagramFlow == nil, let session else { return }
        do {
            let flow = try session.openDatagramFlow(); datagramFlow = flow
            func read() {
                flow.receiveMessage { [weak self] data, _, _, error in
                    guard let self, !self.cancelled else { return }
                    if let error { self.failAllUDP(error); return }
                    if let data { self.handleDatagram(data) }
                    read()
                }
            }
            read()
        } catch { failAllUDP(error) }
    }

    private func sendDatagram(_ payload: Data, target: RequestTarget, sessionID: UInt32,
                              flow: NWConnection, failure: @escaping (Error) -> Void) {
        let address = Data(hostPortString(target.host, target.port).utf8)
        guard !address.isEmpty, address.count <= 2_048 else {
            failure(NativeQUICError.protocolError("Hysteria2 UDP 目标地址过长")); return
        }
        let headerSize = 8 + quicVarint(UInt64(address.count)).count + address.count
        let maxPayload = max(1, 1_200 - headerSize)
        let count = max(1, (payload.count + maxPayload - 1) / maxPayload)
        guard count <= 255 else { failure(NativeQUICError.protocolError("Hysteria2 UDP 数据报过大")); return }
        let packetID = count > 1 ? randomUInt16Nonzero() : 0
        for index in 0..<count {
            let start = index * maxPayload, end = min(payload.count, start + maxPayload)
            var value = Data(); appendBE(sessionID, to: &value); appendBE(packetID, to: &value)
            value.append(UInt8(index)); value.append(UInt8(count))
            value.append(quicVarint(UInt64(address.count))); value.append(address)
            value.append(payload[start..<end])
            flow.send(content: value, completion: .contentProcessed { error in
                if let error { failure(error) }
            })
        }
    }

    private func handleDatagram(_ data: Data) {
        guard data.count >= 10 else { return }
        let sessionID = readBE32(data, 0), packetID = readBE16(data, 4)
        let fragmentID = data[6], fragmentCount = data[7]
        guard let addressLength = parseQUICVarint(data, offset: 8),
              addressLength.value > 0, addressLength.value <= 2_048 else { return }
        let addressStart = 8 + addressLength.length
        guard data.count > addressStart + Int(addressLength.value),
              let address = String(data: data[addressStart..<(addressStart + Int(addressLength.value))],
                                   encoding: .utf8),
              let target = parseHostPortString(address, protocolName: "UDP"),
              fragmentCount > 0, fragmentID < fragmentCount,
              let wrapper = udpSessions[sessionID] else { return }
        let payload = Data(data[(addressStart + Int(addressLength.value))...])
        wrapper.receiveFragment(packetID: packetID, index: fragmentID, count: fragmentCount,
                                target: target, payload: payload)
    }

    private func failAllUDP(_ error: Error) {
        let values = Array(udpSessions.values); udpSessions.removeAll()
        values.forEach { $0.fail(error) }
    }
}

@available(macOS 13.0, *)
private final class Hysteria2DatagramSession: NativeOutboundDatagramSession {
    fileprivate weak var client: Hysteria2Client?
    fileprivate let id: UInt32
    fileprivate var isCancelled = false
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private var fragments: [UInt16: UDPFragments] = [:]

    init(client: Hysteria2Client, id: UInt32,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) {
        self.client = client; self.id = id
        receiveHandler = receive; failureHandler = failure
    }

    func send(_ payload: Data, to target: RequestTarget) {
        guard !isCancelled else { return }
        client?.send(payload, to: target, through: self)
    }

    func cancel() {
        guard !isCancelled else { return }
        isCancelled = true; client?.remove(self); client = nil
    }

    fileprivate func fail(_ error: Error) {
        guard !isCancelled else { return }
        isCancelled = true; failureHandler(error)
    }

    fileprivate func receiveFragment(packetID: UInt16, index: UInt8, count: UInt8,
                                     target: RequestTarget, payload: Data) {
        guard !isCancelled else { return }
        if count == 1 { receiveHandler(target, payload); return }
        var value = fragments[packetID] ?? UDPFragments(count: Int(count), target: target)
        guard value.parts.count == Int(count), Int(index) < value.parts.count else { return }
        value.parts[Int(index)] = payload; fragments[packetID] = value
        if value.parts.allSatisfy({ $0 != nil }) {
            fragments.removeValue(forKey: packetID)
            receiveHandler(value.target, value.parts.compactMap { $0 }.reduce(into: Data(), { $0.append($1) }))
        }
        if fragments.count > 64 { fragments.removeAll(keepingCapacity: true) }
    }
}

// MARK: - TUIC v5

@available(macOS 13.0, *)
private final class TUICv5Client: NativeQUICProxyClient {
    private let policy: ProxyPolicy
    private let uuid: UUID
    private let password: String
    private let udpMode: String
    fileprivate let queue: DispatchQueue
    private let gate = QUICReadyGate()
    private let idLock = NSLock()
    private var nextAssociationID: UInt16 = randomUInt16Nonzero()
    private var nextPacketID: UInt16 = randomUInt16Nonzero()
    private var session: NativeQUICSession?
    private var datagramFlow: NWConnection?
    private var udpSessions: [UInt16: TUICDatagramSession] = [:]
    private var cancelled = false

    init(policy: ProxyPolicy) throws {
        guard let credentials = tuicCredentials(policy) else {
            throw NativeOutboundError.unsupported("TUIC v5 凭据无效")
        }
        self.policy = policy; uuid = credentials.0; password = credentials.1
        udpMode = (policy.parameters["udp-relay-mode"] ?? "native").lowercased()
        queue = DispatchQueue(label: "app.hajimi.quic.tuic.\(safeQueueLabel(policy.name))",
                              qos: .userInitiated, autoreleaseFrequency: .workItem)
    }

    func connectTCP(_ target: RequestTarget,
                    completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.ensureReady { result in
                switch result {
                case .failure(let error): completion(.failure(error))
                case .success: self.openTCP(target, completion: completion)
                }
            }
        }
    }

    func makeDatagramSession(receive: @escaping (RequestTarget, Data) -> Void,
                             failure: @escaping (Error) -> Void) throws
        -> NativeOutboundDatagramSession {
        idLock.lock()
        let id = nextAssociationID
        nextAssociationID &+= 1
        if nextAssociationID == 0 { nextAssociationID = 1 }
        idLock.unlock()
        let wrapper = TUICDatagramSession(client: self, id: id,
                                          receive: receive, failure: failure)
        queue.async { [weak self, weak wrapper] in
            guard let self, let wrapper, !wrapper.isCancelled else { return }
            self.udpSessions[id] = wrapper
        }
        return wrapper
    }

    func cancel() {
        queue.async { [weak self] in
            guard let self, !self.cancelled else { return }
            self.cancelled = true; self.gate.cancel()
            let values = Array(self.udpSessions.values); self.udpSessions.removeAll()
            values.forEach { $0.fail(NativeQUICError.connection("连接已关闭")) }
            self.session?.cancel(); self.session = nil
        }
    }

    fileprivate func send(_ payload: Data, to target: RequestTarget,
                          through wrapper: TUICDatagramSession) {
        queue.async { [weak self, weak wrapper] in
            guard let self, let wrapper, !wrapper.isCancelled else { return }
            self.ensureReady { result in
                switch result {
                case .failure(let error): wrapper.fail(error)
                case .success: self.sendPacket(payload, target: target, associationID: wrapper.id,
                                               failure: wrapper.fail)
                }
            }
        }
    }

    fileprivate func remove(_ wrapper: TUICDatagramSession) {
        queue.async { [weak self] in
            guard let self else { return }
            self.udpSessions.removeValue(forKey: wrapper.id)
            guard !self.cancelled, let session = self.session else { return }
            do {
                let stream = try session.openStream(direction: .unidirectional)
                waitForQUICStreamReady(stream, queue: self.queue) { result in
                    guard case .success = result else { stream.cancel(); return }
                    var command = Data([0x05, 0x03]); appendBE(wrapper.id, to: &command)
                    stream.send(content: command, contentContext: .finalMessage,
                                isComplete: true, completion: .contentProcessed { _ in })
                }
            } catch { /* Dissociate is best effort during local flow teardown. */ }
        }
    }

    private func ensureReady(_ completion: @escaping (Result<Void, Error>) -> Void) {
        gate.ensure(start: { self.establish() }, completion: completion)
    }

    private func establish() {
        guard !cancelled, let host = policy.host, let port = policy.port else {
            gate.fail(NativeQUICError.connection("TUIC 配置无效")); return
        }
        do {
            let configuredALPN = protocolValues(policy.parameters["alpn"])
            let value = try NativeQUICSession(
                host: host, port: port,
                alpn: configuredALPN.isEmpty ? ["h3"] : configuredALPN,
                serverName: quicServerName(policy),
                skipCertificateVerification: quicSkipVerify(policy),
                interface: quicInterface(host), queue: queue)
            session = value
            value.incomingStreamHandler = { [weak self] in self?.handleIncomingStream($0) }
            value.start { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error): self.gate.fail(error)
                case .success: self.authenticate()
                }
            }
        } catch { gate.fail(error) }
    }

    private func authenticate() {
        guard let session else { gate.fail(NativeQUICError.connection("TUIC 会话不存在")); return }
        do {
            let uuidData = rawUUIDData(uuid)
            let token = try session.exportKeyingMaterial(label: uuidData,
                                                         context: Data(password.utf8), length: 32)
            guard token.count == 32 else { throw NativeQUICError.exporter }
            var command = Data([0x05, 0x00]); command.append(uuidData); command.append(token)
            let stream = try session.openStream(direction: .unidirectional)
            waitForQUICStreamReady(stream, queue: queue) { [weak self] result in
                guard let self else { return }
                if case .failure(let error) = result { self.gate.fail(error); return }
                stream.send(content: command, contentContext: .finalMessage,
                            isComplete: true, completion: .contentProcessed { error in
                    if let error { self.gate.fail(error); return }
                    self.startDatagramReceiver()
                    self.gate.succeed(); self.scheduleHeartbeat()
                })
            }
        } catch { gate.fail(error) }
    }

    private func openTCP(_ target: RequestTarget,
                         completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        guard let session else {
            completion(.failure(NativeQUICError.connection("TUIC 会话未建立"))); return
        }
        do {
            let stream = try session.openStream()
            waitForQUICStreamReady(stream, queue: queue) { result in
                if case .failure(let error) = result { completion(.failure(error)); return }
                do {
                    var command = Data([0x05, 0x01])
                    command.append(try tuicAddress(target))
                    stream.send(content: command, completion: .contentProcessed { error in
                        if let error { stream.cancel(); completion(.failure(error)); return }
                        completion(.success(NativeQUICByteStream(stream)))
                    })
                } catch { stream.cancel(); completion(.failure(error)) }
            }
        } catch { completion(.failure(error)) }
    }

    private func startDatagramReceiver() {
        guard datagramFlow == nil, let session else { return }
        do {
            let flow = try session.openDatagramFlow(); datagramFlow = flow
            func read() {
                flow.receiveMessage { [weak self] data, _, _, error in
                    guard let self, !self.cancelled else { return }
                    if let error { self.failAllUDP(error); return }
                    if let data, data.count >= 2, data[0] == 0x05, data[1] == 0x02 {
                        self.handlePacket(data)
                    }
                    read()
                }
            }
            read()
        } catch { failAllUDP(error) }
    }

    private func handleIncomingStream(_ stream: NWConnection) {
        stream.start(queue: queue)
        func read(_ buffer: Data) {
            stream.receive(minimumIncompleteLength: 1, maximumLength: 65_535) {
                [weak self] data, _, complete, error in
                guard let self else { return }
                if let error { stream.cancel(); self.failAllUDP(error); return }
                var next = buffer; if let data { next.append(data) }
                if complete {
                    stream.cancel()
                    if next.count >= 2, next[0] == 0x05, next[1] == 0x02 {
                        self.handlePacket(next)
                    }
                    return
                }
                read(next)
            }
        }
        read(Data())
    }

    private func sendPacket(_ payload: Data, target: RequestTarget, associationID: UInt16,
                            failure: @escaping (Error) -> Void) {
        do {
            let address = try tuicAddress(target)
            let firstCapacity = 1_200 - 10 - address.count
            let laterCapacity = 1_200 - 10 - 1
            guard firstCapacity > 0, laterCapacity > 0 else {
                throw NativeQUICError.protocolError("TUIC UDP 地址过长")
            }
            var ranges: [Range<Int>] = []
            var offset = 0
            if payload.isEmpty { ranges.append(0..<0) }
            while offset < payload.count {
                let capacity = ranges.isEmpty ? firstCapacity : laterCapacity
                let end = min(payload.count, offset + capacity)
                ranges.append(offset..<end); offset = end
            }
            guard ranges.count <= 255 else { throw NativeQUICError.protocolError("TUIC UDP 数据报过大") }
            let packetID = allocatePacketID()
            for (index, range) in ranges.enumerated() {
                let part = Data(payload[range])
                var command = Data([0x05, 0x02]); appendBE(associationID, to: &command)
                appendBE(packetID, to: &command); command.append(UInt8(ranges.count)); command.append(UInt8(index))
                appendBE(UInt16(part.count), to: &command)
                command.append(index == 0 ? address : Data([0xff])); command.append(part)
                sendTUICPacketCommand(command, failure: failure)
            }
        } catch { failure(error) }
    }

    private func sendTUICPacketCommand(_ command: Data, failure: @escaping (Error) -> Void) {
        guard let session else { failure(NativeQUICError.connection("TUIC 会话未建立")); return }
        if udpMode == "native" {
            guard let flow = datagramFlow else {
                failure(NativeQUICError.connection("TUIC Datagram 尚未就绪")); return
            }
            flow.send(content: command, completion: .contentProcessed { error in
                if let error { failure(error) }
            })
            return
        }
        do {
            let stream = try session.openStream(direction: .unidirectional)
            waitForQUICStreamReady(stream, queue: queue) { result in
                switch result {
                case .failure(let error): failure(error)
                case .success:
                    stream.send(content: command, contentContext: .finalMessage,
                                isComplete: true, completion: .contentProcessed { error in
                        if let error { failure(error) }
                    })
                }
            }
        } catch { failure(error) }
    }

    private func handlePacket(_ data: Data) {
        guard data.count >= 11, data[0] == 0x05, data[1] == 0x02 else { return }
        let associationID = readBE16(data, 2), packetID = readBE16(data, 4)
        let fragmentCount = data[6], fragmentID = data[7], size = Int(readBE16(data, 8))
        guard fragmentCount > 0, fragmentID < fragmentCount,
              let address = parseTUICAddress(data, offset: 10),
              data.count == address.nextOffset + size,
              let wrapper = udpSessions[associationID] else { return }
        let payload = Data(data[address.nextOffset...])
        wrapper.receiveFragment(packetID: packetID, index: fragmentID, count: fragmentCount,
                                target: address.target, payload: payload)
    }

    private func scheduleHeartbeat() {
        let interval = max(3, TimeInterval(policy.parameters["heartbeat-interval"] ?? "10") ?? 10)
        queue.asyncAfter(deadline: .now() + interval) { [weak self] in
            guard let self, !self.cancelled else { return }
            if let flow = self.datagramFlow {
                flow.send(content: Data([0x05, 0x04]), completion: .contentProcessed { _ in })
            }
            self.scheduleHeartbeat()
        }
    }

    private func allocatePacketID() -> UInt16 {
        let value = nextPacketID; nextPacketID &+= 1
        if nextPacketID == 0 { nextPacketID = 1 }
        return value
    }

    private func failAllUDP(_ error: Error) {
        let values = Array(udpSessions.values); udpSessions.removeAll()
        values.forEach { $0.fail(error) }
    }
}

@available(macOS 13.0, *)
private final class TUICDatagramSession: NativeOutboundDatagramSession {
    fileprivate weak var client: TUICv5Client?
    fileprivate let id: UInt16
    fileprivate var isCancelled = false
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private struct Fragments {
        var parts: [Data?]
        var target: RequestTarget?
    }
    private var fragments: [UInt16: Fragments] = [:]

    init(client: TUICv5Client, id: UInt16,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) {
        self.client = client; self.id = id
        receiveHandler = receive; failureHandler = failure
    }

    func send(_ payload: Data, to target: RequestTarget) {
        guard !isCancelled else { return }
        client?.send(payload, to: target, through: self)
    }

    func cancel() {
        guard !isCancelled else { return }
        isCancelled = true; client?.remove(self); client = nil
    }

    fileprivate func fail(_ error: Error) {
        guard !isCancelled else { return }
        isCancelled = true; failureHandler(error)
    }

    fileprivate func receiveFragment(packetID: UInt16, index: UInt8, count: UInt8,
                                     target: RequestTarget?, payload: Data) {
        guard !isCancelled else { return }
        if count == 1 {
            if let target { receiveHandler(target, payload) }
            return
        }
        var value = fragments[packetID] ?? Fragments(parts: [Data?](repeating: nil, count: Int(count)),
                                                     target: nil)
        guard value.parts.count == Int(count), Int(index) < value.parts.count else { return }
        value.parts[Int(index)] = payload
        if index == 0, let target { value.target = target }
        fragments[packetID] = value
        if let target = value.target, value.parts.allSatisfy({ $0 != nil }) {
            fragments.removeValue(forKey: packetID)
            receiveHandler(target, value.parts.compactMap { $0 }.reduce(into: Data(), { $0.append($1) }))
        }
        if fragments.count > 64 { fragments.removeAll(keepingCapacity: true) }
    }
}

// MARK: - HTTP/3 QPACK (static table only, as advertised in SETTINGS)

private enum QPACKCodec {
    static func encode(_ fields: [(String, String)]) throws -> Data {
        var output = Data([0x00, 0x00]) // Required Insert Count = 0, Delta Base = 0
        for (rawName, value) in fields {
            let name = rawName.lowercased()
            if let index = exactStaticIndex(name: name, value: value) {
                appendPrefixedInteger(UInt64(index), prefix: 6, marker: 0xc0, to: &output)
            } else if let index = staticNameIndex[name] {
                appendPrefixedInteger(UInt64(index), prefix: 4, marker: 0x50, to: &output)
                try appendString(value, prefix: 7, marker: 0x00, to: &output)
            } else {
                try appendString(name, prefix: 3, marker: 0x20, to: &output)
                try appendString(value, prefix: 7, marker: 0x00, to: &output)
            }
        }
        return output
    }

    static func decode(_ data: Data) throws -> [(String, String)] {
        var offset = 0
        let required = try readPrefixedInteger(data, offset: &offset, prefix: 8)
        guard required == 0 else { throw NativeQUICError.protocolError("QPACK 动态表未关闭") }
        guard offset < data.count else { throw NativeQUICError.protocolError("QPACK Header Block 截断") }
        let deltaSign = data[offset] & 0x80
        let delta = try readPrefixedInteger(data, offset: &offset, prefix: 7)
        guard deltaSign == 0, delta == 0 else {
            throw NativeQUICError.protocolError("QPACK Delta Base 无效")
        }
        var fields: [(String, String)] = []
        while offset < data.count {
            let byte = data[offset]
            if byte & 0x80 != 0 {
                guard byte & 0x40 != 0 else {
                    throw NativeQUICError.protocolError("QPACK 动态索引不受支持")
                }
                let index = try readPrefixedInteger(data, offset: &offset, prefix: 6)
                guard index < UInt64(staticTable.count) else {
                    throw NativeQUICError.protocolError("QPACK 静态索引越界")
                }
                fields.append(staticTable[Int(index)])
            } else if byte & 0xc0 == 0x40 {
                guard byte & 0x10 != 0 else {
                    throw NativeQUICError.protocolError("QPACK 动态名称不受支持")
                }
                let index = try readPrefixedInteger(data, offset: &offset, prefix: 4)
                guard index < UInt64(staticTable.count) else {
                    throw NativeQUICError.protocolError("QPACK 名称索引越界")
                }
                let value = try readString(data, offset: &offset, prefix: 7)
                fields.append((staticTable[Int(index)].0, value))
            } else if byte & 0xe0 == 0x20 {
                let name = try readString(data, offset: &offset, prefix: 3)
                let value = try readString(data, offset: &offset, prefix: 7)
                fields.append((name.lowercased(), value))
            } else {
                throw NativeQUICError.protocolError(
                    String(format: "QPACK 字段表示 0x%02x 不受支持", byte))
            }
        }
        return fields
    }

    private static func appendString(_ value: String, prefix: Int, marker: UInt8,
                                     to data: inout Data) throws {
        let bytes = Data(value.utf8)
        guard bytes.count <= 65_535 else { throw NativeQUICError.protocolError("QPACK 字符串过长") }
        appendPrefixedInteger(UInt64(bytes.count), prefix: prefix, marker: marker, to: &data)
        data.append(bytes)
    }

    private static func readString(_ data: Data, offset: inout Int, prefix: Int) throws -> String {
        guard offset < data.count else { throw NativeQUICError.protocolError("QPACK 字符串截断") }
        let huffman = data[offset] & (prefix == 7 ? 0x80 : 0x08) != 0
        let length = try readPrefixedInteger(data, offset: &offset, prefix: prefix)
        guard length <= UInt64(Int.max), data.count >= offset + Int(length) else {
            throw NativeQUICError.protocolError("QPACK 字符串长度无效")
        }
        let bytes = Data(data[offset..<(offset + Int(length))]); offset += Int(length)
        if huffman { return try HPACKHuffman.decode(bytes) }
        guard let value = String(data: bytes, encoding: .utf8) else {
            throw NativeQUICError.protocolError("QPACK 字符串不是 UTF-8")
        }
        return value
    }

    private static func exactStaticIndex(name: String, value: String) -> Int? {
        switch (name, value) {
        case (":method", "POST"): return 20
        case (":scheme", "https"): return 23
        case ("content-length", "0"): return 4
        case (":path", "/"): return 1
        default: return nil
        }
    }

    private static let staticNameIndex: [String: Int] = [
        ":authority": 0, ":path": 1, "content-length": 4, ":method": 15,
        ":scheme": 22, ":status": 24, "date": 6, "server": 92
    ]

    private static let staticTable: [(String, String)] = [
        (":authority", ""), (":path", "/"), ("age", "0"), ("content-disposition", ""),
        ("content-length", "0"), ("cookie", ""), ("date", ""), ("etag", ""),
        ("if-modified-since", ""), ("if-none-match", ""), ("last-modified", ""),
        ("link", ""), ("location", ""), ("referer", ""), ("set-cookie", ""),
        (":method", "CONNECT"), (":method", "DELETE"), (":method", "GET"),
        (":method", "HEAD"), (":method", "OPTIONS"), (":method", "POST"),
        (":method", "PUT"), (":scheme", "http"), (":scheme", "https"),
        (":status", "103"), (":status", "200"), (":status", "304"),
        (":status", "404"), (":status", "503"), ("accept", "*/*"),
        ("accept", "application/dns-message"), ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"), ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"), ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"), ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"), ("cache-control", "no-cache"),
        ("cache-control", "no-store"), ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"), ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"), ("content-type", "application/javascript"),
        ("content-type", "application/json"), ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"), ("content-type", "image/jpeg"),
        ("content-type", "image/png"), ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"), ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"), ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        ("strict-transport-security", "max-age=31536000; includesubdomains"),
        ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        ("vary", "accept-encoding"), ("vary", "origin"),
        ("x-content-type-options", "nosniff"), ("x-xss-protection", "1; mode=block"),
        (":status", "100"), (":status", "204"), (":status", "206"),
        (":status", "302"), (":status", "400"), (":status", "403"),
        (":status", "421"), (":status", "425"), (":status", "500"),
        ("accept-language", ""), ("access-control-allow-credentials", "FALSE"),
        ("access-control-allow-credentials", "TRUE"), ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"), ("access-control-request-method", "post"),
        ("alt-svc", "clear"), ("authorization", ""),
        ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        ("early-data", "1"), ("expect-ct", ""), ("forwarded", ""), ("if-range", ""),
        ("origin", ""), ("purpose", "prefetch"), ("server", ""),
        ("timing-allow-origin", "*"), ("upgrade-insecure-requests", "1"),
        ("user-agent", ""), ("x-forwarded-for", ""), ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin")
    ]
}

private enum HPACKHuffman {
    static func decode(_ data: Data) throws -> String {
        var output = Data(), current: UInt32 = 0, length = 0
        for byte in data {
            for shift in stride(from: 7, through: 0, by: -1) {
                current = (current << 1) | UInt32((byte >> UInt8(shift)) & 1)
                length += 1
                var match: Int?
                if length <= 30 {
                    for symbol in 0..<256 where Int(codeLengths[symbol]) == length && codes[symbol] == current {
                        match = symbol; break
                    }
                }
                if let match {
                    output.append(UInt8(match)); current = 0; length = 0
                } else if length > 30 {
                    throw NativeQUICError.protocolError("HPACK Huffman 编码无效")
                }
            }
        }
        guard length <= 7,
              length == 0 || current == (UInt32(1) << UInt32(length)) - 1,
              let value = String(data: output, encoding: .utf8) else {
            throw NativeQUICError.protocolError("HPACK Huffman 填充或 UTF-8 无效")
        }
        return value
    }

    private static let codes: [UInt32] = [
        0x1ff8,0x7fffd8,0xfffffe2,0xfffffe3,0xfffffe4,0xfffffe5,0xfffffe6,0xfffffe7,
        0xfffffe8,0xffffea,0x3ffffffc,0xfffffe9,0xfffffea,0x3ffffffd,0xfffffeb,0xfffffec,
        0xfffffed,0xfffffee,0xfffffef,0xffffff0,0xffffff1,0xffffff2,0x3ffffffe,0xffffff3,
        0xffffff4,0xffffff5,0xffffff6,0xffffff7,0xffffff8,0xffffff9,0xffffffa,0xffffffb,
        0x14,0x3f8,0x3f9,0xffa,0x1ff9,0x15,0xf8,0x7fa,0x3fa,0x3fb,0xf9,0x7fb,0xfa,0x16,0x17,
        0x18,0x0,0x1,0x2,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x5c,0xfb,0x7ffc,0x20,0xffb,0x3fc,
        0x1ffa,0x21,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,
        0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0xfc,0x73,0xfd,0x1ffb,0x7fff0,0x1ffc,0x3ffc,
        0x22,0x7ffd,0x3,0x23,0x4,0x24,0x5,0x25,0x26,0x27,0x6,0x74,0x75,0x28,0x29,0x2a,
        0x7,0x2b,0x76,0x2c,0x8,0x9,0x2d,0x77,0x78,0x79,0x7a,0x7b,0x7ffe,0x7fc,0x3ffd,0x1ffd,
        0xffffffc,0xfffe6,0x3fffd2,0xfffe7,0xfffe8,0x3fffd3,0x3fffd4,0x3fffd5,
        0x7fffd9,0x3fffd6,0x7fffda,0x7fffdb,0x7fffdc,0x7fffdd,0x7fffde,0xffffeb,
        0x7fffdf,0xffffec,0xffffed,0x3fffd7,0x7fffe0,0xffffee,0x7fffe1,0x7fffe2,
        0x7fffe3,0x7fffe4,0x1fffdc,0x3fffd8,0x7fffe5,0x3fffd9,0x7fffe6,0x7fffe7,
        0xffffef,0x3fffda,0x1fffdd,0xfffe9,0x3fffdb,0x3fffdc,0x7fffe8,0x7fffe9,
        0x1fffde,0x7fffea,0x3fffdd,0x3fffde,0xfffff0,0x1fffdf,0x3fffdf,0x7fffeb,
        0x7fffec,0x1fffe0,0x1fffe1,0x3fffe0,0x1fffe2,0x7fffed,0x3fffe1,0x7fffee,
        0x7fffef,0xfffea,0x3fffe2,0x3fffe3,0x3fffe4,0x7ffff0,0x3fffe5,0x3fffe6,
        0x7ffff1,0x3ffffe0,0x3ffffe1,0xfffeb,0x7fff1,0x3fffe7,0x7ffff2,0x3fffe8,
        0x1ffffec,0x3ffffe2,0x3ffffe3,0x3ffffe4,0x7ffffde,0x7ffffdf,0x3ffffe5,
        0xfffff1,0x1ffffed,0x7fff2,0x1fffe3,0x3ffffe6,0x7ffffe0,0x7ffffe1,
        0x3ffffe7,0x7ffffe2,0xfffff2,0x1fffe4,0x1fffe5,0x3ffffe8,0x3ffffe9,
        0xffffffd,0x7ffffe3,0x7ffffe4,0x7ffffe5,0xfffec,0xfffff3,0xfffed,0x1fffe6,
        0x3fffe9,0x1fffe7,0x1fffe8,0x7ffff3,0x3fffea,0x3fffeb,0x1ffffee,
        0x1ffffef,0xfffff4,0xfffff5,0x3ffffea,0x7ffff4,0x3ffffeb,0x7ffffe6,
        0x3ffffec,0x3ffffed,0x7ffffe7,0x7ffffe8,0x7ffffe9,0x7ffffea,0x7ffffeb,
        0xffffffe,0x7ffffec,0x7ffffed,0x7ffffee,0x7ffffef,0x7fffff0,0x3ffffee
    ]

    private static let codeLengths: [UInt8] = [
        13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,
        28,28,28,28,28,28,30,28,28,28,28,28,28,28,28,28,
        6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,
        5,5,5,6,6,6,6,6,6,6,7,8,15,6,12,10,
        13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
        7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,
        15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,
        6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,
        20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,
        24,24,22,23,24,23,23,23,23,21,22,23,22,23,23,24,
        22,21,20,22,22,23,23,21,23,22,22,24,21,22,23,23,
        21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,
        26,26,20,19,22,23,22,25,26,26,26,27,27,26,24,25,
        19,21,26,27,27,26,27,24,21,21,26,26,28,27,27,27,
        20,24,20,21,22,21,21,23,22,22,25,25,24,24,26,23,
        26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26
    ]
}

// MARK: - Wire helpers

private struct UDPFragments {
    var parts: [Data?]
    var target: RequestTarget
    init(count: Int, target: RequestTarget) {
        parts = [Data?](repeating: nil, count: count); self.target = target
    }
}

private struct ParsedQUICVarint { let value: UInt64; let length: Int }

private func quicVarint(_ value: UInt64) -> Data {
    precondition(value <= 4_611_686_018_427_387_903)
    if value <= 63 { return Data([UInt8(value)]) }
    if value <= 16_383 {
        return Data([0x40 | UInt8(value >> 8), UInt8(value & 0xff)])
    }
    if value <= 1_073_741_823 {
        return Data([0x80 | UInt8(value >> 24), UInt8((value >> 16) & 0xff),
                     UInt8((value >> 8) & 0xff), UInt8(value & 0xff)])
    }
    return Data([0xc0 | UInt8(value >> 56), UInt8((value >> 48) & 0xff),
                 UInt8((value >> 40) & 0xff), UInt8((value >> 32) & 0xff),
                 UInt8((value >> 24) & 0xff), UInt8((value >> 16) & 0xff),
                 UInt8((value >> 8) & 0xff), UInt8(value & 0xff)])
}

private func parseQUICVarint(_ data: Data, offset: Int) -> ParsedQUICVarint? {
    guard offset >= 0, offset < data.count else { return nil }
    let count = 1 << Int(data[offset] >> 6)
    guard data.count >= offset + count else { return nil }
    var value = UInt64(data[offset] & 0x3f)
    if count > 1 {
        for index in (offset + 1)..<(offset + count) { value = (value << 8) | UInt64(data[index]) }
    }
    return ParsedQUICVarint(value: value, length: count)
}

private func appendPrefixedInteger(_ value: UInt64, prefix: Int, marker: UInt8,
                                   to data: inout Data) {
    let maximum = UInt64((1 << prefix) - 1)
    if value < maximum { data.append(marker | UInt8(value)); return }
    data.append(marker | UInt8(maximum))
    var remaining = value - maximum
    while remaining >= 128 { data.append(0x80 | UInt8(remaining & 0x7f)); remaining >>= 7 }
    data.append(UInt8(remaining))
}

private func readPrefixedInteger(_ data: Data, offset: inout Int, prefix: Int) throws -> UInt64 {
    guard (1...8).contains(prefix), offset < data.count else {
        throw NativeQUICError.protocolError("QPACK 整数截断")
    }
    let maximum = UInt64((1 << prefix) - 1)
    var value = UInt64(data[offset] & UInt8(maximum)); offset += 1
    guard value == maximum else { return value }
    var shift = 0
    while offset < data.count {
        let byte = data[offset]; offset += 1
        guard shift < 63 else { throw NativeQUICError.protocolError("QPACK 整数溢出") }
        value += UInt64(byte & 0x7f) << UInt64(shift)
        if byte & 0x80 == 0 { return value }
        shift += 7
    }
    throw NativeQUICError.protocolError("QPACK 整数截断")
}

private func appendBE(_ value: UInt16, to data: inout Data) {
    data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
}

private func appendBE(_ value: UInt32, to data: inout Data) {
    data.append(UInt8(value >> 24)); data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff)); data.append(UInt8(value & 0xff))
}

private func appendBE(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private func readBE16(_ data: Data, _ offset: Int) -> UInt16 {
    UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
}

private func readBE32(_ data: Data, _ offset: Int) -> UInt32 {
    UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 |
        UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
}

private func randomUInt16Nonzero() -> UInt16 {
    var value: UInt16 = 0
    repeat { _ = withUnsafeMutableBytes(of: &value) { SecRandomCopyBytes(kSecRandomDefault, 2, $0.baseAddress!) } }
    while value == 0
    return value
}

private func randomUInt32Nonzero() -> UInt32 {
    var value: UInt32 = 0
    repeat { _ = withUnsafeMutableBytes(of: &value) { SecRandomCopyBytes(kSecRandomDefault, 4, $0.baseAddress!) } }
    while value == 0
    return value
}

private func nonempty(_ value: String?) -> String? {
    guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return nil }
    return value
}

private func hysteria1Auth(_ policy: ProxyPolicy) -> String? {
    nonempty(policy.parameters["auth-str"]) ?? nonempty(policy.parameters["auth"]) ??
        nonempty(policy.parameters["password"])
}

private func hysteria2Auth(_ policy: ProxyPolicy) -> String? {
    nonempty(policy.parameters["password"]) ?? nonempty(policy.parameters["auth"]) ??
        nonempty(policy.parameters["auth-str"])
}

private func tuicCredentials(_ policy: ProxyPolicy) -> (UUID, String)? {
    if let raw = nonempty(policy.parameters["uuid"]), let uuid = UUID(uuidString: raw),
       let password = nonempty(policy.parameters["password"]) { return (uuid, password) }
    guard let token = nonempty(policy.parameters["token"]),
          let colon = token.firstIndex(of: ":"),
          let uuid = UUID(uuidString: String(token[..<colon])) else { return nil }
    let password = String(token[token.index(after: colon)...])
    return password.isEmpty ? nil : (uuid, password)
}

private func parseBandwidth(_ raw: String?) -> UInt64 {
    guard var value = nonempty(raw) else { return 0 }
    value = value.replacingOccurrences(of: " ", with: "")
    let pattern = #"^([0-9]+(?:\.[0-9]+)?)([KMGTkmgt]?)([bB])(?:ps)?$"#
    if let regex = try? NSRegularExpression(pattern: pattern),
       let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
       let numberRange = Range(match.range(at: 1), in: value),
       let number = Double(value[numberRange]), number > 0,
       let unitRange = Range(match.range(at: 2), in: value),
       let bitRange = Range(match.range(at: 3), in: value) {
        let unit = value[unitRange].uppercased()
        let powers = ["": 1.0, "K": 1_024.0, "M": 1_048_576.0,
                      "G": 1_073_741_824.0, "T": 1_099_511_627_776.0]
        let bytes = number * (powers[unit] ?? 1) / (value[bitRange] == "b" ? 8 : 1)
        return bytes.isFinite && bytes < Double(UInt64.max) ? UInt64(bytes) : 0
    }
    // Surge also accepts a bare Mbps number.
    if let number = Double(value), number > 0 { return UInt64(number * 125_000) }
    return 0
}

private func protocolValues(_ raw: String?) -> [String] {
    guard let raw else { return [] }
    return raw.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        .split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        }.filter { !$0.isEmpty }
}

private func quicServerName(_ policy: ProxyPolicy) -> String {
    if ["true", "yes", "1", "on"].contains(policy.parameters["disable-sni"]?.lowercased() ?? "") {
        return ""
    }
    return nonempty(policy.parameters["sni"]) ?? nonempty(policy.parameters["servername"]) ??
        policy.host ?? ""
}

private func quicSkipVerify(_ policy: ProxyPolicy) -> Bool {
    let value = policy.parameters["skip-cert-verify"] ?? policy.parameters["skip-common-name-verify"]
    return ["true", "yes", "1", "on"].contains(value?.lowercased() ?? "")
}

private func quicInterface(_ host: String) -> NWInterface? {
    let lowered = host.lowercased()
    if lowered == "localhost" || lowered == "127.0.0.1" || lowered == "::1" { return nil }
    return ProxyEngine.currentOutboundInterface
}

private func safeQueueLabel(_ value: String) -> String {
    String(value.unicodeScalars.map { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-")
        ? Character($0) : "_" })
}

private func hostPortString(_ host: String, _ port: UInt16) -> String {
    let value = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
    return value.contains(":") ? "[\(value)]:\(port)" : "\(value):\(port)"
}

private func parseHostPortString(_ value: String, protocolName: String) -> RequestTarget? {
    if value.hasPrefix("["), let closing = value.firstIndex(of: "]") {
        let after = value.index(after: closing)
        guard after < value.endIndex, value[after] == ":",
              let port = UInt16(value[value.index(after: after)...]) else { return nil }
        return RequestTarget(host: String(value[value.index(after: value.startIndex)..<closing]),
                             port: port, protocolName: protocolName)
    }
    guard let colon = value.lastIndex(of: ":"), let port = UInt16(value[value.index(after: colon)...]) else { return nil }
    return RequestTarget(host: String(value[..<colon]), port: port, protocolName: protocolName)
}

private func parseBooleanHeader(_ value: String?) -> Bool {
    ["true", "yes", "1", "on"].contains(value?.lowercased() ?? "")
}

private func rawUUIDData(_ uuid: UUID) -> Data {
    var raw = uuid.uuid
    return withUnsafeBytes(of: &raw) { Data($0) }
}

private func tuicAddress(_ target: RequestTarget) throws -> Data {
    var host = target.host
    if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    var ipv4 = in_addr()
    if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
        var data = Data([0x01]); withUnsafeBytes(of: &ipv4) { data.append(contentsOf: $0) }
        appendBE(target.port, to: &data); return data
    }
    var ipv6 = in6_addr()
    if host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
        var data = Data([0x02]); withUnsafeBytes(of: &ipv6) { data.append(contentsOf: $0) }
        appendBE(target.port, to: &data); return data
    }
    let domain = Data(host.utf8)
    guard !domain.isEmpty, domain.count <= 255 else {
        throw NativeQUICError.protocolError("TUIC 目标域名长度无效")
    }
    var data = Data([0x00, UInt8(domain.count)]); data.append(domain); appendBE(target.port, to: &data)
    return data
}

private struct TUICParsedAddress { let target: RequestTarget?; let nextOffset: Int }

private func parseTUICAddress(_ data: Data, offset: Int) -> TUICParsedAddress? {
    guard offset < data.count else { return nil }
    switch data[offset] {
    case 0xff: return TUICParsedAddress(target: nil, nextOffset: offset + 1)
    case 0x00:
        guard data.count >= offset + 2 else { return nil }
        let length = Int(data[offset + 1]), start = offset + 2, end = start + length
        guard length > 0, data.count >= end + 2,
              let host = String(data: data[start..<end], encoding: .utf8) else { return nil }
        return TUICParsedAddress(target: RequestTarget(host: host, port: readBE16(data, end),
                                                       protocolName: "UDP"), nextOffset: end + 2)
    case 0x01:
        guard data.count >= offset + 7 else { return nil }
        var address = in_addr()
        withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: data[(offset + 1)..<(offset + 5)]) }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return TUICParsedAddress(target: RequestTarget(host: String(cString: buffer),
                                                       port: readBE16(data, offset + 5), protocolName: "UDP"),
                                 nextOffset: offset + 7)
    case 0x02:
        guard data.count >= offset + 19 else { return nil }
        var address = in6_addr()
        withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: data[(offset + 1)..<(offset + 17)]) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return TUICParsedAddress(target: RequestTarget(host: String(cString: buffer),
                                                       port: readBE16(data, offset + 17), protocolName: "UDP"),
                                 nextOffset: offset + 19)
    default: return nil
    }
}

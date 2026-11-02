import Foundation

enum XHTTPMode: String {
    case packetUp = "packet-up"
    case streamUp = "stream-up"
    case streamOne = "stream-one"

    init?(_ raw: String?) {
        switch raw?.lowercased() ?? "auto" {
        case "", "auto", "packet-up": self = .packetUp
        case "stream-up": self = .streamUp
        case "stream-one": self = .streamOne
        default: return nil
        }
    }
}

enum XHTTPTransport {
    static func connect(raw: any ByteTransport, dial: @escaping XHTTPByteTransport.Dialer,
                        mode: XHTTPMode, path: String, hostHeader: String, scheme: String,
                        paddingRange: ClosedRange<Int> = XHTTP.defaultPaddingRange,
                        queue: DispatchQueue,
                        completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        switch mode {
        case .packetUp:
            XHTTPByteTransport.connect(raw: raw, dial: dial, path: path,
                                       hostHeader: hostHeader, scheme: scheme,
                                       paddingRange: paddingRange, queue: queue) {
                completion($0.map { $0 as any ByteTransport })
            }
        case .streamUp, .streamOne:
            XHTTPStreamingByteTransport.connect(raw: raw, dial: dial, mode: mode,
                                                 path: path, hostHeader: hostHeader,
                                                 scheme: scheme, paddingRange: paddingRange,
                                                 queue: queue, completion: completion)
        }
    }
}

/// Xray labels stream-up/one as application/grpc for camouflage, but the body
/// is a raw byte stream. HTTP/1.1 chunk framing belongs to HTTP, not gRPC.
final class XHTTPStreamingByteTransport: ByteTransport {
    typealias Dialer = XHTTPByteTransport.Dialer

    private struct PendingWrite {
        let data: Data
        let completion: (Error?) -> Void
    }

    private let mode: XHTTPMode
    private let downlink: any ByteTransport
    private let dial: Dialer
    private let path: String
    private let hostHeader: String
    private let scheme: String
    private let paddingRange: ClosedRange<Int>
    private let session: String
    private let lock = NSLock()
    private var uplink: (any ByteTransport)?
    private var inbound = Data()
    private var waitingReceive: ((Data?, Bool, Error?) -> Void)?
    private var writes: [PendingWrite] = []
    private var writeInFlight = false
    private var downlinkEnded = false
    private var cancelled = false
    private var failure: Error?
    private var readyCompletion: ((Result<any ByteTransport, Error>) -> Void)?

    private init(raw: any ByteTransport, dial: @escaping Dialer, mode: XHTTPMode,
                 path: String, hostHeader: String, scheme: String,
                 paddingRange: ClosedRange<Int>,
                 completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        self.mode = mode
        downlink = raw
        self.dial = dial
        self.path = path
        self.hostHeader = hostHeader
        self.scheme = scheme
        self.paddingRange = paddingRange
        session = mode == .streamOne ? "" : XHTTP.sessionIdentifier()
        readyCompletion = completion
    }

    static func connect(raw: any ByteTransport, dial: @escaping Dialer, mode: XHTTPMode,
                        path: String, hostHeader: String, scheme: String,
                        paddingRange: ClosedRange<Int>, queue: DispatchQueue,
                        completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        precondition(mode != .packetUp)
        let value = XHTTPStreamingByteTransport(raw: raw, dial: dial, mode: mode,
                                                path: path, hostHeader: hostHeader,
                                                scheme: scheme, paddingRange: paddingRange,
                                                completion: completion)
        value.start()
    }

    private func start() {
        switch mode {
        case .streamUp:
            let request = XHTTP.downlinkRequest(path: path, session: session,
                                                host: hostHeader, scheme: scheme,
                                                padding: XHTTP.padding(in: paddingRange))
            downlink.send(request) { [weak self] error in
                guard let self else { return }
                if let error { self.failBeforeReady(error); return }
                self.readDownlinkHead { [weak self] in self?.openStreamingUplink() }
            }
        case .streamOne:
            uplink = downlink
            downlink.send(streamRequest(session: "")) { [weak self] error in
                guard let self else { return }
                if let error { self.failBeforeReady(error); return }
                self.readDownlinkHead { [weak self] in self?.finishReady() }
            }
        case .packetUp:
            preconditionFailure("packet-up must use XHTTPByteTransport")
        }
    }

    private func openStreamingUplink() {
        dial { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): self.failBeforeReady(error)
            case .success(let connection):
                self.lock.lock()
                let stale = self.cancelled || self.failure != nil
                if !stale { self.uplink = connection }
                self.lock.unlock()
                guard !stale else { connection.cancel(); return }
                connection.send(self.streamRequest(session: self.session)) { [weak self] error in
                    guard let self else { return }
                    if let error { self.failBeforeReady(error); return }
                    self.drainUplinkResponse(connection)
                    self.finishReady()
                }
            }
        }
    }

    private func streamRequest(session: String) -> Data {
        let padding = XHTTP.padding(in: paddingRange)
        let requestPath = path + session
        let lines = [
            "POST \(requestPath)?x_padding=\(padding) HTTP/1.1",
            "Host: \(hostHeader)",
            "Referer: \(scheme)://\(hostHeader)\(path)?x_padding=\(padding)",
            "Content-Type: application/grpc",
            "Transfer-Encoding: chunked",
            "Accept: */*",
            "Accept-Encoding: identity",
            "Cache-Control: no-cache",
            "Pragma: no-cache",
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        ]
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    private func readDownlinkHead(ready: @escaping () -> Void) {
        let parser = HTTP1ResponseParser()
        func step() {
            downlink.receive { [weak self] data, complete, error in
                guard let self else { return }
                if let error { self.failBeforeReady(error); return }
                if let data, !data.isEmpty {
                    do {
                        let result = try parser.ingest(data)
                        if parser.headComplete {
                            guard parser.statusCode == 200 else {
                                self.failBeforeReady(NativeOutboundError.protocolError(
                                    "XHTTP \(self.mode.rawValue) 返回 " +
                                    (parser.statusCode.map(String.init) ?? "无状态")))
                                return
                            }
                            if !result.payload.isEmpty { self.deliver(result.payload) }
                            ready()
                            self.pumpDownlink(parser)
                            return
                        }
                    } catch { self.failBeforeReady(error); return }
                }
                if complete {
                    self.failBeforeReady(NativeOutboundError.connection(
                        "XHTTP \(self.mode.rawValue) 在响应头前断开"))
                    return
                }
                step()
            }
        }
        step()
    }

    private func pumpDownlink(_ parser: HTTP1ResponseParser) {
        downlink.receive { [weak self] data, complete, error in
            guard let self else { return }
            if let error { self.fail(error); return }
            if let data, !data.isEmpty {
                do {
                    let result = try parser.ingest(data)
                    if !result.payload.isEmpty { self.deliver(result.payload) }
                    if result.complete { self.finishDownlink(); return }
                } catch { self.fail(error); return }
            }
            if complete { self.finishDownlink(); return }
            self.pumpDownlink(parser)
        }
    }

    /// Consume stream-up's response padding so TCP flow control cannot stall
    /// the upload. The server may intentionally delay this response head.
    private func drainUplinkResponse(_ connection: any ByteTransport) {
        let parser = HTTP1ResponseParser()
        func step() {
            connection.receive { [weak self] data, complete, error in
                guard let self else { return }
                if let error { self.fail(error); return }
                if let data, !data.isEmpty {
                    do {
                        _ = try parser.ingest(data)
                        if parser.headComplete, parser.statusCode != 200 {
                            self.fail(NativeOutboundError.protocolError(
                                "XHTTP stream-up 上行返回 " +
                                (parser.statusCode.map(String.init) ?? "无状态")))
                            return
                        }
                    } catch { self.fail(error); return }
                }
                if complete {
                    self.fail(NativeOutboundError.connection("XHTTP stream-up 上行已断开"))
                    return
                }
                step()
            }
        }
        step()
    }

    private func finishReady() {
        lock.lock()
        let completion = readyCompletion
        readyCompletion = nil
        lock.unlock()
        completion?(.success(self as any ByteTransport))
    }

    private func failBeforeReady(_ error: Error) {
        lock.lock()
        let completion = readyCompletion
        readyCompletion = nil
        lock.unlock()
        completion?(.failure(error))
        fail(error)
    }

    private func deliver(_ data: Data) {
        lock.lock()
        guard !cancelled, failure == nil else { lock.unlock(); return }
        if let waiting = waitingReceive {
            waitingReceive = nil
            let value = inbound + data
            inbound.removeAll(keepingCapacity: true)
            lock.unlock()
            waiting(value, false, nil)
        } else {
            inbound.append(data)
            lock.unlock()
        }
    }

    private func finishDownlink() {
        lock.lock()
        guard !downlinkEnded, !cancelled else { lock.unlock(); return }
        downlinkEnded = true
        guard let waiting = waitingReceive else { lock.unlock(); return }
        waitingReceive = nil
        let value = inbound
        inbound.removeAll(keepingCapacity: true)
        lock.unlock()
        waiting(value.isEmpty ? nil : value, true, nil)
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock()
        if let failure { lock.unlock(); completion(nil, true, failure); return }
        if !inbound.isEmpty {
            let value = inbound
            inbound.removeAll(keepingCapacity: true)
            let complete = downlinkEnded
            lock.unlock()
            completion(value, complete, nil)
            return
        }
        if downlinkEnded || cancelled {
            lock.unlock(); completion(nil, true, nil); return
        }
        waitingReceive = completion
        lock.unlock()
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !data.isEmpty else { completion(nil); return }
        lock.lock()
        if let failure { lock.unlock(); completion(failure); return }
        guard !cancelled else {
            lock.unlock(); completion(NativeOutboundError.connection("XHTTP 会话已关闭")); return
        }
        writes.append(PendingWrite(data: data, completion: completion))
        lock.unlock()
        flushWrites()
    }

    private func flushWrites() {
        lock.lock()
        guard !writeInFlight, !writes.isEmpty, !cancelled, failure == nil,
              let connection = uplink else { lock.unlock(); return }
        writeInFlight = true
        let item = writes.removeFirst()
        lock.unlock()

        var chunk = Data(String(item.data.count, radix: 16).utf8)
        chunk.append(contentsOf: [0x0d, 0x0a])
        chunk.append(item.data)
        chunk.append(contentsOf: [0x0d, 0x0a])
        connection.send(chunk) { [weak self] error in
            guard let self else { return }
            self.lock.lock(); self.writeInFlight = false; self.lock.unlock()
            item.completion(error)
            if let error { self.fail(error) } else { self.flushWrites() }
        }
    }

    func cancel() {
        lock.lock()
        guard !cancelled else { lock.unlock(); return }
        cancelled = true
        let waiting = waitingReceive
        waitingReceive = nil
        let pending = writes
        writes.removeAll()
        let upstream = uplink
        uplink = nil
        let completion = readyCompletion
        readyCompletion = nil
        lock.unlock()
        if let upstream, mode == .streamUp {
            upstream.send(Data("0\r\n\r\n".utf8)) { _ in upstream.cancel() }
        }
        downlink.cancel()
        waiting?(nil, true, nil)
        let error = NativeOutboundError.connection("XHTTP 会话已关闭")
        pending.forEach { $0.completion(error) }
        completion?(.failure(error))
    }

    private func fail(_ error: Error) {
        lock.lock()
        guard failure == nil, !cancelled else { lock.unlock(); return }
        failure = error
        let waiting = waitingReceive
        waitingReceive = nil
        let pending = writes
        writes.removeAll()
        let upstream = uplink
        uplink = nil
        lock.unlock()
        if mode == .streamUp { upstream?.cancel() }
        downlink.cancel()
        waiting?(nil, true, error)
        pending.forEach { $0.completion(error) }
    }
}

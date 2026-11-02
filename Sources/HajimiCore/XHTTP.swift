import Foundation

/// XHTTP — Xray's successor to SplitHTTP — in `packet-up` mode.
///
/// A session is two independent HTTP/1.1 conversations tied together by a
/// session id that travels in the URL path:
///
///     downlink   GET  {path}{session}         one request, body streams forever
///     uplink     POST {path}{session}/{seq}   one request per chunk, seq from 0
///
/// The downlink response never ends, so its socket can carry nothing else; the
/// uploads need their own connection. That asymmetry is why this transport
/// dials for itself instead of upgrading a single connection the way WebSocket
/// and gRPC do.
///
/// Every request must carry a padding string whose length lands inside the
/// server's configured range. A request without one is answered `400`, which
/// looks exactly like a wrong path or a wrong host — the single easiest way to
/// end up with an implementation that is silently and undiagnosably broken.
enum XHTTP {
    /// The server's own default when `xPaddingBytes` is unset. A value outside
    /// the range is rejected just as hard as a missing one.
    static let defaultPaddingRange: ClosedRange<Int> = 100...1000

    /// The server's default cap is 1 MB, but it is not observable from the
    /// client and exceeding a lowered cap surfaces as `413` mid-session, so
    /// stay well under it.
    static let maximumPostBytes = 65_536

    /// Xray paces its uploads. Matching it keeps the request cadence from
    /// standing out against the browser traffic this transport imitates.
    static let minimumPostInterval: TimeInterval = 0.03

    /// Padding is `X` repeated. HPACK assigns `X` an 8-bit Huffman code, so
    /// over HTTP/2 and HTTP/3 the length on the wire survives header
    /// compression unchanged — which is the whole point of the padding.
    static func padding(in range: ClosedRange<Int> = defaultPaddingRange) -> String {
        String(repeating: "X", count: Int.random(in: range))
    }

    static func sessionIdentifier() -> String {
        UUID().uuidString.lowercased()
    }

    /// Xray appends a trailing slash whenever the session id lives in the path,
    /// and the server matches with a plain prefix test. Without the slash
    /// `/tunnel` is a literal `404` while `/tunnel/<session>` is not, so
    /// omitting it fails in a way that reads as "wrong path".
    static func normalizedPath(_ raw: String?) -> String {
        var path = raw ?? "/"
        if let mark = path.firstIndex(of: "?") { path = String(path[path.startIndex..<mark]) }
        if path.isEmpty || !path.hasPrefix("/") { path = "/" + path }
        if !path.hasSuffix("/") { path += "/" }
        return path
    }

    /// Headers that carry no protocol meaning and exist only so a request looks
    /// like a browser's `fetch()`. The server reads none of them.
    private static let camouflage = [
        "Accept: */*",
        "Accept-Encoding: identity",
        "Accept-Language: en-US,en;q=0.9",
        "Cache-Control: no-cache",
        "Pragma: no-cache",
        "Sec-Fetch-Dest: empty",
        "Sec-Fetch-Mode: cors",
        "Sec-Fetch-Site: same-origin",
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    ]

    /// The padding rides in two places on purpose.
    ///
    /// Current Xray puts it in a `Referer` whose query is rewritten to
    /// `x_padding=…`, and the current server reads `Referer` *exclusively* when
    /// it is present. Older servers only ever look at the request URL's own
    /// query. Sending both satisfies either one; sending only what today's
    /// client sends would 400 against an older server, and only what today's
    /// server prefers would 400 against an older one.
    ///
    /// The `Referer` names the *base* path, carrying neither the session id nor
    /// the seq, because Xray captures the URL before it appends either of them.
    /// It is a distinct value from the request path, not something to recover
    /// from it.
    private static func paddedHead(method: String, requestPath: String, basePath: String,
                                   host: String, scheme: String, padding: String) -> [String] {
        [
            "\(method) \(requestPath)?x_padding=\(padding) HTTP/1.1",
            "Host: \(host)",
            "Referer: \(scheme)://\(host)\(basePath)?x_padding=\(padding)",
        ]
    }

    static func downlinkRequest(path: String, session: String, host: String,
                                scheme: String, padding: String) -> Data {
        var lines = paddedHead(method: "GET", requestPath: path + session, basePath: path,
                               host: host, scheme: scheme, padding: padding)
        lines.append(contentsOf: camouflage)
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    static func uplinkRequest(path: String, session: String, seq: UInt64, host: String,
                              scheme: String, padding: String, bodyLength: Int) -> Data {
        var lines = paddedHead(method: "POST", requestPath: "\(path)\(session)/\(seq)",
                               basePath: path, host: host, scheme: scheme, padding: padding)
        // Exact and mandatory: Xray never chunks its uploads.
        lines.append("Content-Length: \(bodyLength)")
        lines.append(contentsOf: camouflage)
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }
}

// MARK: - HTTP/1.1 response parsing

/// Incremental HTTP/1.1 response parser: head first, then a chunked, counted or
/// read-until-close body.
///
/// The downlink body is unbounded, so this has to hand back payload as it
/// arrives rather than buffering a whole message.
final class HTTP1ResponseParser {
    private enum BodyState {
        case chunkHeader
        case chunkPayload(remaining: Int)
        case chunkTerminator
        case trailers
        case counted(remaining: Int)
        case untilClose
        case complete
    }

    private(set) var statusCode: Int?
    private(set) var headers: [String: String] = [:]
    private(set) var headComplete = false
    /// True once the message body has ended on its own terms. A
    /// read-until-close body only ends when the socket does.
    var complete: Bool { if case .complete = body { return true }; return false }
    var wantsClose: Bool {
        if case .untilClose = body { return true }
        return headers["connection"]?.lowercased().contains("close") ?? false
    }

    private var buffer = Data()
    private var body: BodyState = .untilClose

    /// The head of a response has no business being large; a peer that never
    /// sends the terminator would otherwise grow this without bound.
    private static let maximumHeadBytes = 64 * 1024

    func ingest(_ data: Data) throws -> (payload: Data, complete: Bool) {
        buffer.append(data)
        var payload = Data()
        var cursor = 0

        loop: while true {
            if !headComplete {
                guard let terminator = range(of: "\r\n\r\n", from: cursor) else {
                    if buffer.count - cursor > Self.maximumHeadBytes {
                        throw NativeOutboundError.protocolError("XHTTP 响应头过长")
                    }
                    break loop
                }
                try parseHead(buffer.subdata(in: cursor..<terminator.lowerBound))
                cursor = terminator.upperBound
                headComplete = true
                continue
            }

            switch body {
            case .complete:
                break loop

            case .untilClose:
                if cursor < buffer.count {
                    payload.append(buffer.subdata(in: cursor..<buffer.count))
                    cursor = buffer.count
                }
                break loop

            case .counted(let remaining):
                let available = min(remaining, buffer.count - cursor)
                if available > 0 {
                    payload.append(buffer.subdata(in: cursor..<(cursor + available)))
                    cursor += available
                }
                let left = remaining - available
                body = left == 0 ? .complete : .counted(remaining: left)
                if left > 0 { break loop }

            case .chunkHeader:
                guard let line = range(of: "\r\n", from: cursor) else { break loop }
                let text = String(decoding: buffer.subdata(in: cursor..<line.lowerBound), as: UTF8.self)
                // A chunk size may carry extensions after a semicolon.
                let sizeText = text.split(separator: ";", maxSplits: 1).first
                    .map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
                guard let size = Int(sizeText, radix: 16), size >= 0 else {
                    throw NativeOutboundError.protocolError("XHTTP 分块长度无效：\(text)")
                }
                cursor = line.upperBound
                body = size == 0 ? .trailers : .chunkPayload(remaining: size)

            case .chunkPayload(let remaining):
                let available = min(remaining, buffer.count - cursor)
                if available > 0 {
                    payload.append(buffer.subdata(in: cursor..<(cursor + available)))
                    cursor += available
                }
                let left = remaining - available
                body = left == 0 ? .chunkTerminator : .chunkPayload(remaining: left)
                if left > 0 { break loop }

            case .chunkTerminator:
                guard buffer.count - cursor >= 2 else { break loop }
                guard buffer[cursor] == 0x0D, buffer[cursor + 1] == 0x0A else {
                    throw NativeOutboundError.protocolError("XHTTP 分块缺少结尾 CRLF")
                }
                cursor += 2
                body = .chunkHeader

            case .trailers:
                // Either an immediate CRLF, or trailer lines then CRLFCRLF.
                if buffer.count - cursor >= 2, buffer[cursor] == 0x0D, buffer[cursor + 1] == 0x0A {
                    cursor += 2
                    body = .complete
                    break loop
                }
                guard let terminator = range(of: "\r\n\r\n", from: cursor) else { break loop }
                cursor = terminator.upperBound
                body = .complete
                break loop
            }
        }

        if cursor > 0 { buffer.removeSubrange(0..<cursor) }
        return (payload, complete)
    }

    private func range(of token: String, from cursor: Int) -> Range<Int>? {
        guard cursor <= buffer.count else { return nil }
        return buffer.range(of: Data(token.utf8), in: cursor..<buffer.count)
    }

    private func parseHead(_ head: Data) throws {
        let text = String(decoding: head, as: UTF8.self)
        var lines = text.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { throw NativeOutboundError.protocolError("XHTTP 响应为空") }
        let statusLine = lines.removeFirst()
        let fields = statusLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard fields.count >= 2, fields[0].hasPrefix("HTTP/"), let code = Int(fields[1]) else {
            throw NativeOutboundError.protocolError("XHTTP 状态行无效：\(statusLine)")
        }
        statusCode = code
        for line in lines where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }

        // 204 and 304 never carry a body regardless of what the headers claim.
        if code == 204 || code == 304 {
            body = .complete
        } else if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
            body = .chunkHeader
        } else if let length = headers["content-length"].flatMap({ Int($0) }) {
            body = length == 0 ? .complete : .counted(remaining: length)
        } else {
            body = .untilClose
        }
    }
}

// MARK: - Transport

/// One XHTTP session presented as a plain byte pipe.
final class XHTTPByteTransport: ByteTransport {
    /// Dials a fresh connection to the same server, with the same TLS settings
    /// as the downlink. Uploads need one of their own.
    typealias Dialer = (@escaping (Result<any ByteTransport, Error>) -> Void) -> Void

    private struct PendingWrite {
        var data: Data
        let done: ((Error?) -> Void)?
    }

    private let downlink: any ByteTransport
    private let dial: Dialer
    private let queue: DispatchQueue
    private let path: String
    private let hostHeader: String
    private let scheme: String
    private let session: String
    private let paddingRange: ClosedRange<Int>

    private let lock = NSLock()
    private var inbound = Data()
    private var pendingReceive: ((Data?, Bool, Error?) -> Void)?
    private var downlinkEnded = false
    /// Diagnostics only, but still guarded: an unsynchronised counter read from
    /// the receive loop while the deliver path writes it is a data race whether
    /// or not anyone is reading the log.
    private var downlinkBytes = 0

    private var failure: Error?
    private var cancelled = false

    private var writeQueue: [PendingWrite] = []
    private var postInFlight = false
    private var nextSeq: UInt64 = 0
    private var uplink: (any ByteTransport)?
    private var uplinkParser: HTTP1ResponseParser?
    private var uplinkResidue = Data()
    private var lastPostStart: DispatchTime?

    private init(downlink: any ByteTransport, dial: @escaping Dialer, queue: DispatchQueue,
                 path: String, hostHeader: String, scheme: String,
                 session: String, paddingRange: ClosedRange<Int>) {
        self.downlink = downlink
        self.dial = dial
        self.queue = queue
        self.path = path
        self.hostHeader = hostHeader
        self.scheme = scheme
        self.session = session
        self.paddingRange = paddingRange
    }

    /// Opens the downlink and reports ready once the server has answered 200.
    ///
    /// Xray returns from its dial as soon as the TCP connection is up, without
    /// waiting for the status. Waiting costs one round trip and buys a real
    /// error message instead of a session that fails later for reasons the
    /// caller can no longer see.
    static func connect(raw: any ByteTransport, dial: @escaping Dialer,
                        path: String, hostHeader: String, scheme: String,
                        paddingRange: ClosedRange<Int> = XHTTP.defaultPaddingRange,
                        queue: DispatchQueue,
                        completion: @escaping (Result<XHTTPByteTransport, Error>) -> Void) {
        let session = XHTTP.sessionIdentifier()
        let transport = XHTTPByteTransport(downlink: raw, dial: dial, queue: queue,
                                           path: path, hostHeader: hostHeader,
                                           scheme: scheme, session: session,
                                           paddingRange: paddingRange)
        let request = XHTTP.downlinkRequest(path: path, session: session, host: hostHeader,
                                            scheme: scheme,
                                            padding: XHTTP.padding(in: paddingRange))
        raw.send(request) { error in
            if let error {
                raw.cancel()
                completion(.failure(error))
                return
            }
            transport.readDownlinkHead(completion: completion)
        }
    }

    // MARK: Downlink

    private func readDownlinkHead(completion: @escaping (Result<XHTTPByteTransport, Error>) -> Void) {
        let parser = HTTP1ResponseParser()
        var settled = false
        func finish(_ result: Result<XHTTPByteTransport, Error>) {
            guard !settled else { return }
            settled = true
            if case .failure = result { downlink.cancel() }
            completion(result)
        }

        func step() {
            downlink.receive { [weak self] data, isComplete, error in
                guard let self else { return }
                if let error { finish(.failure(error)); return }
                if let data, !data.isEmpty {
                    do {
                        let (payload, _) = try parser.ingest(data)
                        if parser.headComplete {
                            guard parser.statusCode == 200 else {
                                finish(.failure(NativeOutboundError.protocolError(
                                    "XHTTP 下行返回 \(parser.statusCode.map(String.init) ?? "无状态")"
                                        + (parser.statusCode == 400
                                            ? "（padding 长度或路径不符合服务端配置）" : ""))))
                                return
                            }
                            if !payload.isEmpty { self.deliver(payload) }
                            finish(.success(self))
                            self.pumpDownlink(parser: parser)
                            return
                        }
                    } catch {
                        finish(.failure(error))
                        return
                    }
                }
                if isComplete {
                    finish(.failure(NativeOutboundError.connection("XHTTP 下行在响应头前断开")))
                    return
                }
                step()
            }
        }
        step()
    }

    private func pumpDownlink(parser: HTTP1ResponseParser) {
        downlink.receive { [weak self] data, isComplete, error in
            guard let self else { return }
            if let error {
                nativeDebug("xhttp downlink error after \(self.deliveredBytes) bytes: \(error)")
                self.fail(error)
                return
            }
            if let data, !data.isEmpty {
                do {
                    let (payload, done) = try parser.ingest(data)
                    if !payload.isEmpty { self.deliver(payload) }
                    if done {
                        nativeDebug("xhttp downlink ended by terminating chunk "
                                    + "after \(self.deliveredBytes) bytes")
                        self.finishDownlink()
                        return
                    }
                } catch {
                    nativeDebug("xhttp downlink parse failure after \(self.deliveredBytes) bytes: \(error)")
                    self.fail(error)
                    return
                }
            }
            if isComplete {
                nativeDebug("xhttp downlink socket closed after \(self.deliveredBytes) bytes")
                self.finishDownlink()
                return
            }
            self.pumpDownlink(parser: parser)
        }
    }

    private func deliver(_ payload: Data) {
        lock.lock()
        guard !cancelled else { lock.unlock(); return }
        downlinkBytes += payload.count
        if let waiting = pendingReceive {
            pendingReceive = nil
            let pending = inbound + payload
            inbound.removeAll(keepingCapacity: true)
            lock.unlock()
            waiting(pending, false, nil)
        } else {
            inbound.append(payload)
            lock.unlock()
        }
    }

    private func finishDownlink() {
        lock.lock()
        guard !downlinkEnded, !cancelled else { lock.unlock(); return }
        downlinkEnded = true
        // Anything already buffered has to survive the end of the stream. Only
        // drain it when someone is waiting for it — with no reader parked here,
        // clearing the buffer would silently drop whatever arrived in the last
        // moment before EOF, and `receive` would then report a clean end of
        // stream with the tail missing.
        guard let waiting = pendingReceive else { lock.unlock(); return }
        pendingReceive = nil
        let pending = inbound
        inbound.removeAll(keepingCapacity: true)
        lock.unlock()
        waiting(pending.isEmpty ? nil : pending, true, nil)
    }

    private var deliveredBytes: Int {
        lock.lock(); defer { lock.unlock() }
        return downlinkBytes
    }

    private func fail(_ error: Error) {
        lock.lock()
        guard failure == nil, !cancelled else { lock.unlock(); return }
        failure = error
        let waiting = pendingReceive
        pendingReceive = nil
        let pendingWrites = writeQueue
        writeQueue.removeAll()
        let upstream = uplink
        uplink = nil
        lock.unlock()
        upstream?.cancel()
        downlink.cancel()
        waiting?(nil, true, error)
        pendingWrites.forEach { $0.done?(error) }
    }

    // MARK: ByteTransport

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock()
        if let failure {
            lock.unlock(); completion(nil, true, failure); return
        }
        if !inbound.isEmpty {
            let pending = inbound
            inbound.removeAll(keepingCapacity: true)
            let ended = downlinkEnded
            lock.unlock()
            completion(pending, ended, nil)
            return
        }
        if downlinkEnded || cancelled {
            lock.unlock(); completion(nil, true, nil); return
        }
        pendingReceive = completion
        lock.unlock()
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !data.isEmpty else { completion(nil); return }
        lock.lock()
        if let failure { lock.unlock(); completion(failure); return }
        if cancelled {
            lock.unlock(); completion(NativeOutboundError.connection("XHTTP 会话已关闭")); return
        }
        writeQueue.append(PendingWrite(data: data, done: completion))
        lock.unlock()
        pumpUplink()
    }

    func cancel() {
        lock.lock()
        guard !cancelled else { lock.unlock(); return }
        cancelled = true
        let waiting = pendingReceive
        pendingReceive = nil
        let pendingWrites = writeQueue
        writeQueue.removeAll()
        let upstream = uplink
        uplink = nil
        lock.unlock()
        upstream?.cancel()
        downlink.cancel()
        waiting?(nil, true, nil)
        pendingWrites.forEach { $0.done?(NativeOutboundError.connection("XHTTP 会话已关闭")) }
    }

    // MARK: Uplink

    /// Batches whatever is queued into one POST and keeps exactly one in flight.
    ///
    /// Batching is not an optimisation: a POST per `send` puts a full round trip
    /// between every write, which collapses throughput to a trickle.
    private func pumpUplink() {
        lock.lock()
        guard !postInFlight, !cancelled, failure == nil, !writeQueue.isEmpty else {
            lock.unlock(); return
        }
        postInFlight = true

        var body = Data()
        var finished: [(Error?) -> Void] = []
        while !writeQueue.isEmpty, body.count < XHTTP.maximumPostBytes {
            var item = writeQueue.removeFirst()
            let room = XHTTP.maximumPostBytes - body.count
            if item.data.count > room {
                body.append(item.data.prefix(room))
                item.data = Data(item.data.dropFirst(room))
                // The completion travels with the tail, so the caller hears
                // back only once every byte it handed over has gone out.
                writeQueue.insert(item, at: 0)
                break
            }
            body.append(item.data)
            if let done = item.done { finished.append(done) }
        }
        let seq = nextSeq
        nextSeq += 1
        nativeDebug("xhttp uplink POST seq \(seq) body=\(body.count) queued=\(writeQueue.count)")
        let last = lastPostStart
        lock.unlock()

        let delay: TimeInterval
        if let last {
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds &- last.uptimeNanoseconds) / 1e9
            delay = max(0, XHTTP.minimumPostInterval - elapsed)
        } else {
            delay = 0
        }

        let start = { [weak self] in
            guard let self else { return }
            self.lock.lock(); self.lastPostStart = .now(); self.lock.unlock()
            self.post(body: body, seq: seq) { [weak self] error in
                guard let self else { return }
                if let error {
                    finished.forEach { $0(error) }
                    self.fail(error)
                    return
                }
                self.lock.lock(); self.postInFlight = false; self.lock.unlock()
                finished.forEach { $0(nil) }
                self.pumpUplink()
            }
        }
        if delay > 0 { queue.asyncAfter(deadline: .now() + delay, execute: start) } else { start() }
    }

    private func post(body: Data, seq: UInt64, completion: @escaping (Error?) -> Void) {
        withUplink { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): completion(error)
            case .success(let connection):
                var request = XHTTP.uplinkRequest(path: self.path, session: self.session, seq: seq,
                                                  host: self.hostHeader, scheme: self.scheme,
                                                  padding: XHTTP.padding(in: self.paddingRange),
                                                  bodyLength: body.count)
                request.append(body)
                connection.send(request) { error in
                    if let error { completion(error); return }
                    self.readUplinkResponse(connection: connection, seq: seq, completion: completion)
                }
            }
        }
    }

    private func readUplinkResponse(connection: any ByteTransport, seq: UInt64,
                                    completion: @escaping (Error?) -> Void) {
        let parser = HTTP1ResponseParser()
        lock.lock()
        var residue = uplinkResidue
        uplinkResidue.removeAll(keepingCapacity: true)
        lock.unlock()

        func consume(_ data: Data) -> Bool {
            do {
                _ = try parser.ingest(data)
            } catch {
                completion(error)
                return true
            }
            guard parser.complete else { return false }
            let status = parser.statusCode ?? 0
            guard status == 200 else {
                connection.cancel()
                self.lock.lock(); self.uplink = nil; self.lock.unlock()
                completion(NativeOutboundError.protocolError(uplinkDiagnosis(status: status, seq: seq)))
                return true
            }
            nativeDebug("xhttp uplink seq \(seq) -> 200")
            if parser.wantsClose {
                connection.cancel()
                self.lock.lock(); self.uplink = nil; self.lock.unlock()
            }
            completion(nil)
            return true
        }

        if !residue.isEmpty {
            let pending = residue
            residue.removeAll()
            if consume(pending) { return }
        }

        func step() {
            connection.receive { [weak self] data, isComplete, error in
                guard let self else { return }
                if let error { completion(error); return }
                if let data, !data.isEmpty, consume(data) { return }
                if isComplete {
                    self.lock.lock(); self.uplink = nil; self.lock.unlock()
                    connection.cancel()
                    completion(NativeOutboundError.connection("XHTTP 上行在响应完成前断开"))
                    return
                }
                step()
            }
        }
        step()
    }

    private func uplinkDiagnosis(status: Int, seq: UInt64) -> String {
        switch status {
        case 400: return "XHTTP 上行返回 400（padding 长度或路径不符合服务端配置）"
        case 404: return "XHTTP 上行返回 404（路径或 Host 与服务端不符）"
        case 409: return "XHTTP 上行返回 409（seq \(seq) 已被使用）"
        case 413: return "XHTTP 上行返回 413（分块超过服务端 scMaxEachPostBytes）"
        default: return "XHTTP 上行返回 \(status)"
        }
    }

    /// Reuses the upload connection while the server keeps it alive, redialling
    /// when it does not.
    private func withUplink(_ completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        lock.lock()
        if let failure { lock.unlock(); completion(.failure(failure)); return }
        if cancelled {
            lock.unlock()
            completion(.failure(NativeOutboundError.connection("XHTTP 会话已关闭")))
            return
        }
        if let existing = uplink { lock.unlock(); completion(.success(existing)); return }
        lock.unlock()

        dial { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let connection):
                self.lock.lock()
                let stale = self.cancelled || self.failure != nil
                if !stale { self.uplink = connection }
                self.lock.unlock()
                if stale {
                    connection.cancel()
                    completion(.failure(NativeOutboundError.connection("XHTTP 会话已关闭")))
                } else {
                    completion(.success(connection))
                }
            }
        }
    }
}

// MARK: - Self-test

public enum XHTTPSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "XHTTP 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try pathNormalization()
        try paddingShape()
        try requestShape()
        try chunkedParsing()
        try countedParsing()
        try rejectsMalformed()
        try sessionHandshake()
        try tailSurvivesEndOfStream()
        try rejectsBadDownlinkStatus()
    }

    /// A `ByteTransport` that replays a canned script, so the session logic can
    /// be exercised without a server.
    private final class ScriptedTransport: ByteTransport {
        private let lock = NSLock()
        private var script: [Data]
        private var closeAtEnd: Bool
        private(set) var written = Data()
        private var parked: ((Data?, Bool, Error?) -> Void)?
        private(set) var cancelled = false

        init(script: [Data], closeAtEnd: Bool = false) {
            self.script = script
            self.closeAtEnd = closeAtEnd
        }

        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); written.append(data); lock.unlock()
            completion(nil)
        }

        func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            if script.isEmpty {
                if closeAtEnd {
                    closeAtEnd = false; lock.unlock(); completion(nil, true, nil); return
                }
                parked = completion
                lock.unlock()
                return
            }
            let next = script.removeFirst()
            lock.unlock()
            completion(next, false, nil)
        }

        func cancel() { lock.lock(); cancelled = true; lock.unlock() }

        /// Pushes one more chunk, or an end of stream, to a parked reader.
        func push(_ data: Data?) {
            lock.lock()
            guard let waiting = parked else {
                if let data { script.append(data) } else { closeAtEnd = true }
                lock.unlock()
                return
            }
            parked = nil
            lock.unlock()
            if let data { waiting(data, false, nil) } else { waiting(nil, true, nil) }
        }
    }

    private static func okHead(chunked: Bool = true) -> Data {
        Data(("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
            + (chunked ? "Transfer-Encoding: chunked\r\n" : "Content-Length: 0\r\n")
            + "\r\n").utf8)
    }

    private static func chunk(_ text: String) -> Data {
        Data((String(text.utf8.count, radix: 16) + "\r\n" + text + "\r\n").utf8)
    }

    private static func open(downlink: ScriptedTransport,
                             uplink: ScriptedTransport?) throws -> XHTTPByteTransport {
        var opened: Result<XHTTPByteTransport, Error>?
        XHTTPByteTransport.connect(
            raw: downlink,
            dial: { done in
                if let uplink { done(.success(uplink)) }
                else { done(.failure(NativeOutboundError.connection("测试未提供上行连接"))) }
            },
            path: "/tunnel/", hostHeader: "example.org", scheme: "http",
            queue: DispatchQueue(label: "app.hajimi.xhttp-selftest")) { opened = $0 }
        guard let opened else { throw Failure(text: "连接未同步完成") }
        return try opened.get()
    }

    /// The downlink request must go out before anything is read back, and the
    /// session must not be reported ready until the server has answered 200.
    private static func sessionHandshake() throws {
        let downlink = ScriptedTransport(script: [okHead() + chunk("hi")])
        let uplink = ScriptedTransport(script: [Data("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8)])
        let session = try open(downlink: downlink, uplink: uplink)

        let request = String(decoding: downlink.written, as: UTF8.self)
        try expect(request.hasPrefix("GET /tunnel/"), "下行请求未先发出：\(request.prefix(40))")
        try expect(request.contains("x_padding="), "下行请求缺少 padding")

        var first: Data?
        session.receive { data, _, _ in first = data }
        try expect(String(decoding: first ?? Data(), as: UTF8.self) == "hi",
                   "握手后未取到首段载荷")

        var sendError: Error?
        var sendDone = false
        session.send(Data("payload".utf8)) { sendError = $0; sendDone = true }
        try expect(sendDone && sendError == nil, "上行写入未完成：\(String(describing: sendError))")
        let post = String(decoding: uplink.written, as: UTF8.self)
        try expect(post.hasPrefix("POST /tunnel/"), "上行请求行错误：\(post.prefix(40))")
        try expect(post.contains("/0?x_padding="), "首个 POST 的 seq 应为 0")
        try expect(post.hasSuffix("payload"), "上行请求体未附上载荷")
        session.cancel()
    }

    /// Data that lands while no reader is parked must still be handed over
    /// after the stream ends. Dropping it produces a truncated download that
    /// only shows up when the consumer happens to be busy at the wrong moment.
    private static func tailSurvivesEndOfStream() throws {
        let downlink = ScriptedTransport(script: [okHead()])
        let session = try open(downlink: downlink, uplink: nil)

        // Arrives with nobody waiting, then the stream ends.
        downlink.push(chunk("tail"))
        downlink.push(nil)

        var payload: Data?
        var ended = false
        session.receive { data, complete, _ in payload = data; ended = complete }
        try expect(String(decoding: payload ?? Data(), as: UTF8.self) == "tail",
                   "流结束后尾部数据丢失：\(String(decoding: payload ?? Data(), as: UTF8.self))")
        try expect(ended, "尾部数据未携带结束标记")

        var afterEnd: Data?
        var afterComplete = false
        session.receive { data, complete, _ in afterEnd = data; afterComplete = complete }
        try expect(afterEnd == nil && afterComplete, "尾部取走后未报告流结束")
        session.cancel()
    }

    /// 400 is what the server answers when the padding or path is wrong, and it
    /// must surface as a failed dial rather than an empty session.
    private static func rejectsBadDownlinkStatus() throws {
        let downlink = ScriptedTransport(
            script: [Data("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".utf8)])
        do {
            _ = try open(downlink: downlink, uplink: nil)
            throw Failure(text: "下行 400 未被拒绝")
        } catch is NativeOutboundError {}
        try expect(downlink.cancelled, "握手失败后未关闭下行连接")
    }

    /// The trailing slash is load-bearing: the server matches the configured
    /// path by prefix, so `/tunnel` without it is a 404 while the same path
    /// with it is not.
    private static func pathNormalization() throws {
        try expect(XHTTP.normalizedPath("/tunnel") == "/tunnel/", "未补尾部斜杠")
        try expect(XHTTP.normalizedPath("tunnel") == "/tunnel/", "未补前导斜杠")
        try expect(XHTTP.normalizedPath("/a/b/") == "/a/b/", "已规范化的路径被改动")
        try expect(XHTTP.normalizedPath(nil) == "/", "缺省路径错误")
        try expect(XHTTP.normalizedPath("/p?x=1") == "/p/", "未剥离 query")
    }

    private static func paddingShape() throws {
        for _ in 0..<64 {
            let value = XHTTP.padding()
            try expect(XHTTP.defaultPaddingRange.contains(value.count),
                       "padding 长度 \(value.count) 越界")
            try expect(value.allSatisfy { $0 == "X" }, "padding 含非 X 字符")
        }
        let narrow = XHTTP.padding(in: 7...7)
        try expect(narrow.count == 7, "自定义区间未生效")
    }

    /// Pins the three things the server actually reads. A request that gets any
    /// of them wrong is answered 400 or 404 — failures that look identical to
    /// a misconfigured node, so nothing downstream would point here.
    private static func requestShape() throws {
        let get = String(decoding: XHTTP.downlinkRequest(path: "/tunnel/", session: "SID",
                                                         host: "example.org", scheme: "http",
                                                         padding: "XXX"), as: UTF8.self)
        try expect(get.hasPrefix("GET /tunnel/SID?x_padding=XXX HTTP/1.1\r\n"),
                   "下行请求行错误：\(get.prefix(64))")
        try expect(get.contains("\r\nHost: example.org\r\n"), "下行缺少 Host")
        try expect(get.contains("\r\nReferer: http://example.org/tunnel/?x_padding=XXX\r\n"),
                   "下行 Referer 形态错误")
        try expect(!get.contains("Content-Length"), "下行不应带 Content-Length")

        let post = String(decoding: XHTTP.uplinkRequest(path: "/tunnel/", session: "SID", seq: 0,
                                                        host: "example.org", scheme: "https",
                                                        padding: "XX", bodyLength: 12), as: UTF8.self)
        try expect(post.hasPrefix("POST /tunnel/SID/0?x_padding=XX HTTP/1.1\r\n"),
                   "上行请求行错误：\(post.prefix(64))")
        try expect(post.contains("\r\nContent-Length: 12\r\n"), "上行 Content-Length 错误")
        try expect(post.contains("\r\nReferer: https://example.org/tunnel/?x_padding=XX\r\n"),
                   "上行 Referer 未剥离会话与 seq")
        // application/grpc belongs to stream-up and stream-one only.
        try expect(!post.contains("Content-Type"), "packet-up 上行不应带 Content-Type")
    }

    /// Feeds a chunked response one byte at a time. Real reads split wherever
    /// the network decides, and a parser that only works on whole responses
    /// fails intermittently under load rather than in a test.
    private static func chunkedParsing() throws {
        let raw = Data(("HTTP/1.1 200 OK\r\n"
            + "Content-Type: text/event-stream\r\n"
            + "Transfer-Encoding: chunked\r\n\r\n"
            + "5\r\nhello\r\n"
            + "6\r\n world\r\n"
            + "0\r\n\r\n").utf8)

        for stride in [1, 3, 7, 64, raw.count] {
            let parser = HTTP1ResponseParser()
            var payload = Data()
            var done = false
            var offset = 0
            while offset < raw.count {
                let end = min(offset + stride, raw.count)
                let (chunk, complete) = try parser.ingest(raw.subdata(in: offset..<end))
                payload.append(chunk)
                done = done || complete
                offset = end
            }
            try expect(parser.statusCode == 200, "分片 \(stride)：状态码错误")
            try expect(String(decoding: payload, as: UTF8.self) == "hello world",
                       "分片 \(stride)：载荷为 \(String(decoding: payload, as: UTF8.self))")
            try expect(done, "分片 \(stride)：未识别终止块")
        }

        // A chunk size may carry extensions.
        let parser = HTTP1ResponseParser()
        let (payload, complete) = try parser.ingest(Data(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;name=v\r\nabc\r\n0\r\n\r\n".utf8))
        try expect(String(decoding: payload, as: UTF8.self) == "abc", "分块扩展未被忽略")
        try expect(complete, "带扩展的分块未终止")
    }

    private static func countedParsing() throws {
        let parser = HTTP1ResponseParser()
        let (payload, complete) = try parser.ingest(Data(
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".utf8))
        try expect(parser.statusCode == 200, "计数体状态码错误")
        try expect(String(decoding: payload, as: UTF8.self) == "body", "计数体载荷错误")
        try expect(complete, "计数体未完成")

        // Xray answers uploads with an empty 200; treating that as "still
        // reading" would stall every POST after the first.
        let empty = HTTP1ResponseParser()
        let (_, emptyComplete) = try empty.ingest(Data("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8))
        try expect(emptyComplete, "空响应体未判定为完成")

        let noBody = HTTP1ResponseParser()
        let (_, noBodyComplete) = try noBody.ingest(Data("HTTP/1.1 204 No Content\r\n\r\n".utf8))
        try expect(noBodyComplete, "204 未判定为完成")
    }

    private static func rejectsMalformed() throws {
        let badStatus = HTTP1ResponseParser()
        do {
            _ = try badStatus.ingest(Data("NOT HTTP\r\n\r\n".utf8))
            throw Failure(text: "非法状态行未被拒绝")
        } catch is NativeOutboundError {}

        let badChunk = HTTP1ResponseParser()
        do {
            _ = try badChunk.ingest(Data(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n".utf8))
            throw Failure(text: "非法分块长度未被拒绝")
        } catch is NativeOutboundError {}

        let badTerminator = HTTP1ResponseParser()
        do {
            _ = try badTerminator.ingest(Data(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXX".utf8))
            throw Failure(text: "分块缺少 CRLF 未被拒绝")
        } catch is NativeOutboundError {}
    }
}

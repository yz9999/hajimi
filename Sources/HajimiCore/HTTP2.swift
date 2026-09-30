import Foundation

// MARK: - HTTP/2 frames (RFC 7540)

/// A minimal HTTP/2 client, sized for what a proxy transport needs: one
/// bidirectional stream over one connection.
///
/// Network.framework exposes HTTP/2 only through URLSession, which cannot carry
/// an arbitrary bidirectional stream, so the framing is written here. Nothing
/// beyond a single long-lived stream is implemented — no server push, no
/// priority, no stream multiplexing — because a transport never needs it and
/// every unused feature is a place for a bug to hide.
enum HTTP2 {
    static let preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    static let defaultMaxFrameSize = 16_384
    static let defaultWindowSize = 65_535

    enum FrameType: UInt8 {
        case data = 0x0
        case headers = 0x1
        case rstStream = 0x3
        case settings = 0x4
        case pushPromise = 0x5
        case ping = 0x6
        case goAway = 0x7
        case windowUpdate = 0x8
        case continuation = 0x9
    }

    struct Flags: OptionSet {
        let rawValue: UInt8
        static let endStream = Flags(rawValue: 0x1)
        static let ack = Flags(rawValue: 0x1)
        static let endHeaders = Flags(rawValue: 0x4)
        static let padded = Flags(rawValue: 0x8)
        static let priority = Flags(rawValue: 0x20)
    }

    struct Frame {
        var type: UInt8
        var flags: Flags
        var streamID: UInt32
        var payload: Data
    }

    enum FrameError: LocalizedError, Equatable {
        case oversized(Int)
        case badPadding
        case goAway(UInt32)

        var errorDescription: String? {
            switch self {
            case .oversized(let size): return "HTTP/2 帧长度 \(size) 超出上限"
            case .badPadding: return "HTTP/2 帧填充无效"
            case .goAway(let code): return "HTTP/2 服务端发送 GOAWAY，错误码 \(code)"
            }
        }
    }

    static func encode(_ frame: Frame) -> Data {
        var out = Data()
        let length = frame.payload.count
        out.append(UInt8(truncatingIfNeeded: length >> 16))
        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(frame.type)
        out.append(frame.flags.rawValue)
        // The reserved high bit is always zero.
        out.append(UInt8(truncatingIfNeeded: (frame.streamID >> 24) & 0x7F))
        out.append(UInt8(truncatingIfNeeded: frame.streamID >> 16))
        out.append(UInt8(truncatingIfNeeded: frame.streamID >> 8))
        out.append(UInt8(truncatingIfNeeded: frame.streamID))
        out.append(frame.payload)
        return out
    }

    /// Pulls one frame off the front of `buffer`, or nil when it is incomplete.
    static func decode(from buffer: inout Data, maxFrameSize: Int) throws -> Frame? {
        guard buffer.count >= 9 else { return nil }
        let base = buffer.startIndex
        let length = Int(buffer[base]) << 16 | Int(buffer[base + 1]) << 8 | Int(buffer[base + 2])
        guard length <= maxFrameSize else { throw FrameError.oversized(length) }
        guard buffer.count >= 9 + length else { return nil }
        let type = buffer[base + 3]
        let flags = Flags(rawValue: buffer[base + 4])
        let streamID = (UInt32(buffer[base + 5] & 0x7F) << 24)
            | (UInt32(buffer[base + 6]) << 16)
            | (UInt32(buffer[base + 7]) << 8)
            | UInt32(buffer[base + 8])
        var payload = Data(buffer[(base + 9)..<(base + 9 + length)])
        buffer.removeSubrange(base..<(base + 9 + length))

        // Padding is stripped here so every caller sees only real content.
        if flags.contains(.padded), type == FrameType.data.rawValue
            || type == FrameType.headers.rawValue {
            guard let padLength = payload.first.map(Int.init),
                  payload.count >= padLength + 1 else { throw FrameError.badPadding }
            payload = Data(payload.dropFirst().dropLast(padLength))
        }
        if flags.contains(.priority), type == FrameType.headers.rawValue {
            guard payload.count >= 5 else { throw FrameError.badPadding }
            payload = Data(payload.dropFirst(5))
        }
        return Frame(type: type, flags: flags, streamID: streamID, payload: payload)
    }

    static func settingsFrame(ack: Bool = false, values: [(UInt16, UInt32)] = []) -> Data {
        var payload = Data()
        for (identifier, value) in values {
            payload.append(UInt8(truncatingIfNeeded: identifier >> 8))
            payload.append(UInt8(truncatingIfNeeded: identifier))
            payload.append(UInt8(truncatingIfNeeded: value >> 24))
            payload.append(UInt8(truncatingIfNeeded: value >> 16))
            payload.append(UInt8(truncatingIfNeeded: value >> 8))
            payload.append(UInt8(truncatingIfNeeded: value))
        }
        return encode(Frame(type: FrameType.settings.rawValue,
                            flags: ack ? .ack : [], streamID: 0, payload: payload))
    }

    static func windowUpdate(streamID: UInt32, increment: UInt32) -> Data {
        var payload = Data()
        payload.append(UInt8(truncatingIfNeeded: (increment >> 24) & 0x7F))
        payload.append(UInt8(truncatingIfNeeded: increment >> 16))
        payload.append(UInt8(truncatingIfNeeded: increment >> 8))
        payload.append(UInt8(truncatingIfNeeded: increment))
        return encode(Frame(type: FrameType.windowUpdate.rawValue, flags: [],
                            streamID: streamID, payload: payload))
    }
}

// MARK: - gRPC message framing

/// Xray's gRPC transport carries each chunk as a protobuf `Hunk { bytes data = 1 }`
/// inside a gRPC length-prefixed message.
enum GRPCFraming {
    /// `[1 byte compressed flag][4 byte big-endian length][protobuf Hunk]`
    static func encode(_ payload: Data) -> Data {
        var hunk = Data([0x0A])          // field 1, wire type 2
        appendVarint(payload.count, to: &hunk)
        hunk.append(payload)

        var out = Data([0x00])           // not compressed
        out.append(UInt8(truncatingIfNeeded: hunk.count >> 24))
        out.append(UInt8(truncatingIfNeeded: hunk.count >> 16))
        out.append(UInt8(truncatingIfNeeded: hunk.count >> 8))
        out.append(UInt8(truncatingIfNeeded: hunk.count))
        out.append(hunk)
        return out
    }

    /// Extracts complete messages, leaving any partial one in `buffer`.
    static func decode(from buffer: inout Data) throws -> [Data] {
        var out: [Data] = []
        while buffer.count >= 5 {
            let base = buffer.startIndex
            let compressed = buffer[base]
            let length = Int(buffer[base + 1]) << 24 | Int(buffer[base + 2]) << 16
                | Int(buffer[base + 3]) << 8 | Int(buffer[base + 4])
            guard length >= 0, length <= 16 * 1_024 * 1_024 else {
                throw NativeOutboundError.protocolError("gRPC 消息长度 \(length) 不合理")
            }
            guard buffer.count >= 5 + length else { break }
            let message = Data(buffer[(base + 5)..<(base + 5 + length)])
            buffer.removeSubrange(base..<(base + 5 + length))
            guard compressed == 0 else {
                throw NativeOutboundError.protocolError("gRPC 压缩消息尚未支持")
            }
            out.append(try unwrapHunk(message))
        }
        return out
    }

    private static func unwrapHunk(_ message: Data) throws -> Data {
        guard let first = message.first else { return Data() }
        guard first == 0x0A else {
            throw NativeOutboundError.protocolError(
                "gRPC Hunk 首字节为 0x\(String(first, radix: 16))，应为 0x0a")
        }
        var index = message.index(after: message.startIndex)
        let length = try readVarint(message, &index)
        guard message.distance(from: index, to: message.endIndex) >= length else {
            throw NativeOutboundError.protocolError("gRPC Hunk 长度越界")
        }
        return Data(message[index..<message.index(index, offsetBy: length)])
    }

    static func appendVarint(_ value: Int, to data: inout Data) {
        var remaining = UInt64(value)
        while remaining >= 0x80 {
            data.append(UInt8(truncatingIfNeeded: remaining) | 0x80)
            remaining >>= 7
        }
        data.append(UInt8(truncatingIfNeeded: remaining))
    }

    static func readVarint(_ data: Data, _ index: inout Data.Index) throws -> Int {
        var value = 0
        var shift = 0
        while index < data.endIndex {
            let byte = data[index]
            index = data.index(after: index)
            value |= Int(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return value }
            shift += 7
            guard shift <= 35 else {
                throw NativeOutboundError.protocolError("gRPC varint 溢出")
            }
        }
        throw NativeOutboundError.protocolError("gRPC varint 截断")
    }
}

// MARK: - Transport

/// A gRPC bidirectional stream presented as a plain byte transport.
///
/// Everything above this — VMess, VLESS, Trojan — sees an ordinary stream and
/// needs no knowledge of HTTP/2.
final class GRPCByteTransport: ByteTransport {
    private let raw: any ByteTransport
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var frameBuffer = Data()
    private var messageBuffer = Data()
    private var inbound = Data()
    private var pendingReceive: ((Data?, Bool, Error?) -> Void)?
    private var cancelled = false
    private var failure: Error?
    /// Bytes the peer may still send us before it must wait for a window
    /// update. Left unattended the server stalls after 64 KiB, which looks
    /// exactly like a hung connection on a large download.
    private var localWindow = HTTP2.defaultWindowSize
    private var localConnectionWindow = HTTP2.defaultWindowSize
    private var peerMaxFrameSize = HTTP2.defaultMaxFrameSize
    private var writeInFlight = false
    private var writeBacklog: [(Data, (Error?) -> Void)] = []

    private static let streamID: UInt32 = 1

    private init(raw: any ByteTransport, queue: DispatchQueue) {
        self.raw = raw
        self.queue = queue
    }

    /// Performs the h2c preface, opens the stream and reports ready.
    static func connect(raw: any ByteTransport, serviceName: String, authority: String,
                        scheme: String, queue: DispatchQueue,
                        completion: @escaping (Result<GRPCByteTransport, Error>) -> Void) {
        let transport = GRPCByteTransport(raw: raw, queue: queue)
        var opening = HTTP2.preface
        // A larger initial window than the 64 KiB default keeps a bulk transfer
        // from stopping every window's worth of data.
        opening.append(HTTP2.settingsFrame(values: [(0x4, 1 << 21), (0x3, 128)]))
        opening.append(HTTP2.windowUpdate(streamID: 0, increment: UInt32(1 << 21)))

        let path = "/" + serviceName.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/Tun"
        let headers: [HPACK.HeaderField] = [
            .init(name: ":method", value: "POST"),
            .init(name: ":scheme", value: scheme),
            .init(name: ":path", value: path),
            .init(name: ":authority", value: authority),
            .init(name: "content-type", value: "application/grpc"),
            .init(name: "user-agent", value: "grpc-go/1.60.0"),
            .init(name: "te", value: "trailers"),
            .init(name: "grpc-accept-encoding", value: "identity"),
        ]
        opening.append(HTTP2.encode(HTTP2.Frame(
            type: HTTP2.FrameType.headers.rawValue,
            flags: [.endHeaders], streamID: streamID,
            payload: HPACK.encode(headers))))
        // The local window was just raised; tell the peer about the stream's
        // share too.
        opening.append(HTTP2.windowUpdate(streamID: streamID, increment: UInt32(1 << 21)))
        transport.localWindow = 1 << 21
        transport.localConnectionWindow = 1 << 21

        raw.send(opening) { error in
            if let error { raw.cancel(); completion(.failure(error)); return }
            transport.pump()
            // The stream is open; the server's own HEADERS arrive with the
            // first response and are handled by the read pump.
            completion(.success(transport))
        }
    }

    // MARK: ByteTransport

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        if let failure { lock.unlock(); completion(failure); return }
        if cancelled { lock.unlock(); completion(NativeOutboundError.connection("gRPC 流已关闭")); return }
        let limit = peerMaxFrameSize
        lock.unlock()

        var out = Data()
        var remaining = GRPCFraming.encode(data)[...]
        while !remaining.isEmpty {
            let chunk = remaining.prefix(limit)
            remaining = remaining.dropFirst(chunk.count)
            out.append(HTTP2.encode(HTTP2.Frame(type: HTTP2.FrameType.data.rawValue,
                                                flags: [], streamID: Self.streamID,
                                                payload: Data(chunk))))
        }
        enqueue(out, completion: completion)
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock()
        if let failure { lock.unlock(); completion(nil, true, failure); return }
        if !inbound.isEmpty {
            let data = inbound
            inbound.removeAll(keepingCapacity: true)
            lock.unlock()
            completion(data, false, nil)
            return
        }
        if cancelled { lock.unlock(); completion(nil, true, nil); return }
        pendingReceive = completion
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        if cancelled { lock.unlock(); return }
        cancelled = true
        let waiter = pendingReceive
        pendingReceive = nil
        lock.unlock()
        waiter?(nil, true, nil)
        raw.cancel()
    }

    // MARK: Writer

    private func enqueue(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        writeBacklog.append((data, completion))
        lock.unlock()
        drain()
    }

    /// Writes are serialised: two concurrent sends would interleave frames and
    /// corrupt the stream.
    private func drain() {
        lock.lock()
        guard !writeInFlight, !writeBacklog.isEmpty, !cancelled else { lock.unlock(); return }
        writeInFlight = true
        let (data, completion) = writeBacklog.removeFirst()
        lock.unlock()
        raw.send(data) { [weak self] error in
            guard let self else { completion(error); return }
            self.lock.lock(); self.writeInFlight = false; self.lock.unlock()
            completion(error)
            if error == nil { self.drain() }
        }
    }

    private func sendControl(_ data: Data) {
        enqueue(data) { _ in }
    }

    // MARK: Reader

    private func pump() {
        raw.receive { [weak self] data, isComplete, error in
            guard let self else { return }
            if let error { self.fail(error); return }
            if let data, !data.isEmpty {
                do { try self.consume(data) } catch { self.fail(error); return }
            }
            if isComplete { self.finish(); return }
            self.lock.lock(); let stopped = self.cancelled; self.lock.unlock()
            guard !stopped else { return }
            self.pump()
        }
    }

    private func consume(_ data: Data) throws {
        lock.lock()
        frameBuffer.append(data)
        var deliver = Data()
        var control = Data()
        while let frame = try HTTP2.decode(from: &frameBuffer, maxFrameSize: 1 << 22) {
            switch frame.type {
            case HTTP2.FrameType.data.rawValue:
                localWindow -= frame.payload.count
                localConnectionWindow -= frame.payload.count
                messageBuffer.append(frame.payload)
                for payload in try GRPCFraming.decode(from: &messageBuffer) {
                    deliver.append(payload)
                }
                // Replenish well before the window runs out; waiting until it
                // is empty costs a full round trip of idle time per window.
                if localWindow < (1 << 20) {
                    let increment = UInt32((1 << 21) - localWindow)
                    control.append(HTTP2.windowUpdate(streamID: Self.streamID,
                                                      increment: increment))
                    localWindow = 1 << 21
                }
                if localConnectionWindow < (1 << 20) {
                    let increment = UInt32((1 << 21) - localConnectionWindow)
                    control.append(HTTP2.windowUpdate(streamID: 0, increment: increment))
                    localConnectionWindow = 1 << 21
                }
            case HTTP2.FrameType.settings.rawValue:
                if !frame.flags.contains(.ack) {
                    applySettings(frame.payload)
                    control.append(HTTP2.settingsFrame(ack: true))
                }
            case HTTP2.FrameType.ping.rawValue:
                if !frame.flags.contains(.ack) {
                    control.append(HTTP2.encode(HTTP2.Frame(
                        type: HTTP2.FrameType.ping.rawValue, flags: .ack,
                        streamID: 0, payload: frame.payload)))
                }
            case HTTP2.FrameType.goAway.rawValue:
                let code = frame.payload.count >= 8
                    ? (UInt32(frame.payload[frame.payload.startIndex + 4]) << 24
                       | UInt32(frame.payload[frame.payload.startIndex + 5]) << 16
                       | UInt32(frame.payload[frame.payload.startIndex + 6]) << 8
                       | UInt32(frame.payload[frame.payload.startIndex + 7]))
                    : 0
                lock.unlock()
                fail(HTTP2.FrameError.goAway(code))
                return
            case HTTP2.FrameType.rstStream.rawValue:
                lock.unlock()
                finish()
                return
            default:
                break   // HEADERS, WINDOW_UPDATE and the rest need no action here
            }
            if frame.flags.contains(.endStream),
               frame.type == HTTP2.FrameType.data.rawValue
                || frame.type == HTTP2.FrameType.headers.rawValue {
                lock.unlock()
                if !deliver.isEmpty { publish(deliver) }
                if !control.isEmpty { sendControl(control) }
                finish()
                return
            }
        }
        lock.unlock()
        if !control.isEmpty { sendControl(control) }
        if !deliver.isEmpty { publish(deliver) }
    }

    private func applySettings(_ payload: Data) {
        var index = payload.startIndex
        while payload.distance(from: index, to: payload.endIndex) >= 6 {
            let identifier = UInt16(payload[index]) << 8 | UInt16(payload[index + 1])
            let value = UInt32(payload[index + 2]) << 24 | UInt32(payload[index + 3]) << 16
                | UInt32(payload[index + 4]) << 8 | UInt32(payload[index + 5])
            if identifier == 0x5, value >= 16_384, value <= (1 << 24) - 1 {
                peerMaxFrameSize = Int(value)
            }
            index = payload.index(index, offsetBy: 6)
        }
    }

    private func publish(_ data: Data) {
        lock.lock()
        if let waiter = pendingReceive {
            pendingReceive = nil
            lock.unlock()
            waiter(data, false, nil)
            return
        }
        inbound.append(data)
        lock.unlock()
    }

    private func fail(_ error: Error) {
        lock.lock()
        if failure == nil { failure = error }
        let waiter = pendingReceive
        pendingReceive = nil
        lock.unlock()
        waiter?(nil, true, error)
        raw.cancel()
    }

    private func finish() {
        lock.lock()
        cancelled = true
        let waiter = pendingReceive
        pendingReceive = nil
        lock.unlock()
        waiter?(nil, true, nil)
        raw.cancel()
    }
}


// MARK: - Self-test

public enum HTTP2SelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "HTTP/2 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try frameRoundTrip()
        try framePadding()
        try grpcFraming()
        try rejectsMalformedInput()
    }

    private static func frameRoundTrip() throws {
        let payload = Data((0..<1000).map { UInt8($0 % 251) })
        let frame = HTTP2.Frame(type: HTTP2.FrameType.data.rawValue,
                                flags: [.endStream], streamID: 1, payload: payload)
        var buffer = HTTP2.encode(frame)
        try expect(buffer.count == 9 + payload.count, "帧长度错误：\(buffer.count)")
        guard let decoded = try HTTP2.decode(from: &buffer, maxFrameSize: 1 << 22) else {
            throw Failure(text: "完整帧未能解码")
        }
        try expect(decoded.streamID == 1 && decoded.payload == payload, "帧往返内容不符")
        try expect(decoded.flags.contains(.endStream), "END_STREAM 标志丢失")
        try expect(buffer.isEmpty, "帧解码后有残留")

        // The reserved high bit of the stream ID must never leak into the value.
        var wide = HTTP2.encode(HTTP2.Frame(type: 0, flags: [], streamID: 0x7FFF_FFFF,
                                            payload: Data()))
        guard let big = try HTTP2.decode(from: &wide, maxFrameSize: 1 << 22) else {
            throw Failure(text: "大流 ID 帧未能解码")
        }
        try expect(big.streamID == 0x7FFF_FFFF, "31 位流 ID 解析错误：\(big.streamID)")

        // A partial frame must leave the buffer untouched for the next read.
        var partial = HTTP2.encode(frame).prefix(20)
        let snapshot = partial
        try expect(try HTTP2.decode(from: &partial, maxFrameSize: 1 << 22) == nil,
                   "不完整帧被错误解码")
        try expect(partial == snapshot, "不完整帧解析后缓冲区被破坏")
    }

    /// Padding and priority prefixes must be stripped, or the payload handed
    /// upwards contains bytes that were never sent by the peer.
    private static func framePadding() throws {
        var payload = Data([4])                    // pad length
        payload.append(Data("hello".utf8))
        payload.append(Data(repeating: 0, count: 4))
        var buffer = HTTP2.encode(HTTP2.Frame(type: HTTP2.FrameType.data.rawValue,
                                              flags: [.padded], streamID: 1,
                                              payload: payload))
        guard let decoded = try HTTP2.decode(from: &buffer, maxFrameSize: 1 << 22) else {
            throw Failure(text: "带填充的帧未能解码")
        }
        try expect(decoded.payload == Data("hello".utf8),
                   "填充未被剥离：\(decoded.payload.count) 字节")

        var priority = Data([0, 0, 0, 1, 16])      // stream dependency + weight
        priority.append(Data("hdr".utf8))
        var pbuf = HTTP2.encode(HTTP2.Frame(type: HTTP2.FrameType.headers.rawValue,
                                            flags: [.priority], streamID: 1,
                                            payload: priority))
        guard let ph = try HTTP2.decode(from: &pbuf, maxFrameSize: 1 << 22) else {
            throw Failure(text: "带优先级的 HEADERS 未能解码")
        }
        try expect(ph.payload == Data("hdr".utf8), "优先级前缀未被剥离")
    }

    /// Xray wraps each chunk in a protobuf Hunk inside a gRPC message; getting
    /// either layer wrong yields a stream the server discards silently.
    private static func grpcFraming() throws {
        for length in [0, 1, 127, 128, 16_383, 16_384, 100_000] {
            let payload = Data((0..<length).map { UInt8($0 % 251) })
            let encoded = GRPCFraming.encode(payload)
            try expect(encoded[encoded.startIndex] == 0, "压缩标志应为 0")
            var buffer = encoded
            let messages = try GRPCFraming.decode(from: &buffer)
            try expect(messages.count == 1, "长度 \(length) 应解出 1 条消息")
            try expect(messages[0] == payload, "长度 \(length) 的载荷往返不符")
            try expect(buffer.isEmpty, "长度 \(length) 解码后有残留")
        }

        // Several messages arriving in one read, with the last one split.
        var stream = Data()
        for text in ["one", "two", "three"] { stream.append(GRPCFraming.encode(Data(text.utf8))) }
        let split = stream.count - 3
        var head = Data(stream.prefix(split))
        let first = try GRPCFraming.decode(from: &head)
        try expect(first.count == 2, "应先解出 2 条完整消息，实际 \(first.count)")
        head.append(Data(stream.suffix(from: split)))
        let rest = try GRPCFraming.decode(from: &head)
        try expect(rest.count == 1 && rest[0] == Data("three".utf8), "拼接后未解出末条消息")
        try expect(head.isEmpty, "全部解码后仍有残留")
    }

    private static func rejectsMalformedInput() throws {
        var oversized = Data([0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 1])
        do {
            _ = try HTTP2.decode(from: &oversized, maxFrameSize: 16_384)
            throw Failure(text: "超长帧未被拒绝")
        } catch is HTTP2.FrameError {}

        // Pad length larger than the payload.
        var badPad = HTTP2.encode(HTTP2.Frame(type: HTTP2.FrameType.data.rawValue,
                                              flags: [.padded], streamID: 1,
                                              payload: Data([200, 1, 2])))
        do {
            _ = try HTTP2.decode(from: &badPad, maxFrameSize: 1 << 22)
            throw Failure(text: "越界填充长度未被拒绝")
        } catch is HTTP2.FrameError {}

        // A Hunk that does not start with field 1.
        var wrongTag = Data([0x00, 0x00, 0x00, 0x00, 0x03, 0x12, 0x01, 0x41])
        do {
            _ = try GRPCFraming.decode(from: &wrongTag)
            throw Failure(text: "错误的 Hunk 字段号未被拒绝")
        } catch is NativeOutboundError {}

        // A compressed message, which is not supported and must not be
        // mistaken for plaintext.
        var compressed = Data([0x01, 0x00, 0x00, 0x00, 0x01, 0x41])
        do {
            _ = try GRPCFraming.decode(from: &compressed)
            throw Failure(text: "压缩消息未被拒绝")
        } catch is NativeOutboundError {}
    }
}

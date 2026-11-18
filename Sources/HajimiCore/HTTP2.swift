import Foundation

// MARK: - HTTP/2 frames (RFC 9113) & Extended CONNECT (RFC 8441 / RFC 9298)

/// Minimal, strictly RFC 9113-compliant HTTP/2 client framing and single-stream
/// bidirectional transports (`GRPCByteTransport` and `HTTP2ConnectByteTransport`).
enum HTTP2 {
    static let preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    static let defaultMaxFrameSize = 16_384
    static let defaultWindowSize = 65_535
    static let maxFlowControlWindow = 0x7FFF_FFFF
    static let maxConsecutiveControlFrames = 64

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
        /// RFC 9113 §6.9.1: Entire wire payload length before stripping Pad Length / Padding.
        var rawLength: Int

        init(type: UInt8, flags: Flags, streamID: UInt32, payload: Data, rawLength: Int? = nil) {
            self.type = type
            self.flags = flags
            self.streamID = streamID
            self.payload = payload
            self.rawLength = rawLength ?? payload.count
        }
    }

    enum FrameError: LocalizedError, Equatable {
        case oversized(Int)
        case badPadding
        case goAway(UInt32)
        case protocolViolation(String)

        var errorDescription: String? {
            switch self {
            case .oversized(let size): return "HTTP/2 帧长度 \(size) 超出上限"
            case .badPadding: return "HTTP/2 帧填充无效"
            case .goAway(let code): return "HTTP/2 服务端发送 GOAWAY，错误码 \(code)"
            case .protocolViolation(let detail): return "HTTP/2 协议违规：\(detail)"
            }
        }
    }

    static func encode(_ frame: Frame) -> Data {
        let length = frame.payload.count
        var out = Data(capacity: 9 + length)
        appendFrameHeader(length: length, type: frame.type, flags: frame.flags, streamID: frame.streamID, to: &out)
        out.append(frame.payload)
        return out
    }

    @inline(__always)
    static func appendFrameHeader(length: Int, type: UInt8, flags: Flags, streamID: UInt32, to out: inout Data) {
        out.append(UInt8(truncatingIfNeeded: length >> 16))
        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(type)
        out.append(flags.rawValue)
        // RFC 9113 §4.1: Reserved high bit MUST remain unset when sending.
        out.append(UInt8(truncatingIfNeeded: (streamID >> 24) & 0x7F))
        out.append(UInt8(truncatingIfNeeded: streamID >> 16))
        out.append(UInt8(truncatingIfNeeded: streamID >> 8))
        out.append(UInt8(truncatingIfNeeded: streamID))
    }

    /// Zero-shift cursor decoder: advances `offset` without mutating `buffer`.
    static func decode(from buffer: Data, offset: inout Int, maxFrameSize: Int) throws -> Frame? {
        let base = buffer.startIndex + offset
        let available = buffer.endIndex - base
        guard available >= 9 else { return nil }
        let length = Int(buffer[base]) << 16 | Int(buffer[base + 1]) << 8 | Int(buffer[base + 2])
        guard length <= maxFrameSize else { throw FrameError.oversized(length) }
        guard available >= 9 + length else { return nil }
        let type = buffer[base + 3]
        let flags = Flags(rawValue: buffer[base + 4])
        let streamID = (UInt32(buffer[base + 5] & 0x7F) << 24)
            | (UInt32(buffer[base + 6]) << 16)
            | (UInt32(buffer[base + 7]) << 8)
            | UInt32(buffer[base + 8])
        var payloadStart = base + 9
        var payloadEnd = payloadStart + length
        offset += 9 + length

        if flags.contains(.padded),
           type == FrameType.data.rawValue || type == FrameType.headers.rawValue {
            guard payloadEnd > payloadStart else { throw FrameError.badPadding }
            let padLength = Int(buffer[payloadStart])
            payloadStart += 1
            guard payloadEnd - payloadStart >= padLength else { throw FrameError.badPadding }
            payloadEnd -= padLength
        }
        if flags.contains(.priority), type == FrameType.headers.rawValue {
            guard payloadEnd - payloadStart >= 5 else { throw FrameError.badPadding }
            payloadStart += 5
        }
        return Frame(type: type, flags: flags, streamID: streamID,
                     payload: Data(buffer[payloadStart..<payloadEnd]),
                     rawLength: length)
    }

    /// Pulls one frame off the front of `buffer`, or nil when it is incomplete.
    static func decode(from buffer: inout Data, maxFrameSize: Int) throws -> Frame? {
        var offset = 0
        guard let frame = try decode(from: buffer, offset: &offset, maxFrameSize: maxFrameSize) else {
            return nil
        }
        if offset == buffer.count {
            buffer.removeAll(keepingCapacity: true)
        } else {
            buffer.removeSubrange(buffer.startIndex..<(buffer.startIndex + offset))
        }
        return frame
    }

    static func settingsFrame(ack: Bool = false, values: [(UInt16, UInt32)] = []) -> Data {
        var payload = Data(capacity: values.count * 6)
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
        var payload = Data(capacity: 4)
        payload.append(UInt8(truncatingIfNeeded: (increment >> 24) & 0x7F))
        payload.append(UInt8(truncatingIfNeeded: increment >> 16))
        payload.append(UInt8(truncatingIfNeeded: increment >> 8))
        payload.append(UInt8(truncatingIfNeeded: increment))
        return encode(Frame(type: FrameType.windowUpdate.rawValue, flags: [],
                            streamID: streamID, payload: payload))
    }

    static func parseWindowUpdate(_ frame: Frame) throws -> Int {
        guard frame.payload.count == 4 else {
            throw FrameError.protocolViolation("WINDOW_UPDATE 帧长度必须为 4 字节")
        }
        let b = frame.payload.startIndex
        let inc = Int(UInt32(frame.payload[b] & 0x7F) << 24
            | UInt32(frame.payload[b + 1]) << 16
            | UInt32(frame.payload[b + 2]) << 8
            | UInt32(frame.payload[b + 3]))
        guard inc > 0 else {
            throw FrameError.protocolViolation("RFC 9113 §6.9 WINDOW_UPDATE 增量不能为 0")
        }
        return inc
    }
}

// MARK: - gRPC message framing

/// Xray's gRPC transport carries each chunk as a protobuf `Hunk { bytes data = 1 }`
/// inside a gRPC length-prefixed message.
enum GRPCFraming {
    /// `[1 byte compressed flag][4 byte big-endian length][protobuf Hunk]`
    static func encode(_ payload: Data) -> Data {
        let payloadLen = payload.count
        var varintBytes: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        var varintLen = 0
        withUnsafeMutableBytes(of: &varintBytes) { buf in
            var remaining = UInt64(payloadLen)
            while remaining >= 0x80 {
                buf[varintLen] = UInt8(truncatingIfNeeded: remaining) | 0x80
                varintLen += 1
                remaining >>= 7
            }
            buf[varintLen] = UInt8(truncatingIfNeeded: remaining)
            varintLen += 1
        }
        let hunkCount = 1 + varintLen + payloadLen
        var out = Data(capacity: 5 + hunkCount)
        out.append(0x00) // not compressed
        out.append(UInt8(truncatingIfNeeded: hunkCount >> 24))
        out.append(UInt8(truncatingIfNeeded: hunkCount >> 16))
        out.append(UInt8(truncatingIfNeeded: hunkCount >> 8))
        out.append(UInt8(truncatingIfNeeded: hunkCount))
        out.append(0x0A) // field 1, wire type 2
        withUnsafeBytes(of: &varintBytes) { buf in
            out.append(buf.bindMemory(to: UInt8.self).baseAddress!, count: varintLen)
        }
        out.append(payload)
        return out
    }

    /// Extracts complete messages using a single cursor pass (O(N)), leaving any partial tail in `buffer`.
    static func decode(from buffer: inout Data) throws -> [Data] {
        var out: [Data] = []
        var offset = 0
        let total = buffer.count
        while total - offset >= 5 {
            let base = buffer.startIndex + offset
            let compressed = buffer[base]
            let length = Int(buffer[base + 1]) << 24 | Int(buffer[base + 2]) << 16
                | Int(buffer[base + 3]) << 8 | Int(buffer[base + 4])
            guard length >= 0, length <= 16 * 1_024 * 1_024 else {
                throw NativeOutboundError.protocolError("gRPC 消息长度 \(length) 不合理")
            }
            guard total - offset >= 5 + length else { break }
            let message = Data(buffer[(base + 5)..<(base + 5 + length)])
            offset += 5 + length
            guard compressed == 0 else {
                throw NativeOutboundError.protocolError("gRPC 压缩消息尚未支持")
            }
            out.append(try unwrapHunk(message))
        }
        if offset > 0 {
            if offset == total {
                buffer.removeAll(keepingCapacity: true)
            } else {
                buffer.removeSubrange(buffer.startIndex..<(buffer.startIndex + offset))
            }
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

// MARK: - gRPC Transport

/// A gRPC bidirectional stream presented as a plain byte transport with full
/// RFC 9113 inbound & outbound flow-control window accounting and control-frame flood bounds.
final class GRPCByteTransport: ByteTransport {
    private static let initialTargetWindow = 4_194_304       // 4 MiB (SETTINGS_INITIAL_WINDOW_SIZE)
    private static let maxTargetWindow = 16 * 1_024 * 1_024  // 16 MiB max auto-tuned BDP window
    private static let advertisedMaxFrameSize = 65_536       // 64 KiB (SETTINGS_MAX_FRAME_SIZE)
    private static let maxCoalescedWriteBytes = 65_536       // 64 KiB outbound coalescing cap
    private static let streamID: UInt32 = 1
    private static let maxPendingOutboundBytes = 8 * 1_024 * 1_024

    private let raw: any ByteTransport
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var frameBuffer = Data()
    private var messageBuffer = Data()
    private var inbound = Data()
    private var pendingReceive: ((Data?, Bool, Error?) -> Void)?
    private var cancelled = false
    private var failure: Error?
    private var currentTargetWindow = GRPCByteTransport.initialTargetWindow
    private var localWindow = GRPCByteTransport.initialTargetWindow
    private var localConnectionWindow = GRPCByteTransport.initialTargetWindow
    private var peerSettingsReceived = false
    private var peerInitialWindowSize = GRPCByteTransport.initialTargetWindow
    private var peerStreamWindow = GRPCByteTransport.initialTargetWindow
    private var peerConnectionWindow = GRPCByteTransport.initialTargetWindow
    private var peerMaxFrameSize = HTTP2.defaultMaxFrameSize
    private var consecutiveControlFrames = 0
    private var awaitingContinuationStream: UInt32?
    private var pendingDataPayloads: [(Data, Int, (Error?) -> Void)] = []
    private var pendingDataBytes = 0
    private var writeInFlight = false
    private var writeBacklog: [(Data, (Error?) -> Void)] = []

    // RFC 9113 §6.7 PING-based BDP estimator state
    private var bdpBytesSinceSample = 0
    private var bdpBytesDuringRTT = 0
    private var bdpSampleStartNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    private var bdpLastDataNs: UInt64 = 0
    private var bdpPingInFlight = false
    private var bdpPingSentNs: UInt64 = 0
    private var bdpPingSeq: UInt32 = 0
    private var bdpPingPayload = Data()

    private init(raw: any ByteTransport, queue: DispatchQueue) {
        self.raw = raw
        self.queue = queue
    }

    static func connect(raw: any ByteTransport, serviceName: String, authority: String,
                        scheme: String, queue: DispatchQueue,
                        completion: @escaping (Result<GRPCByteTransport, Error>) -> Void) {
        let transport = GRPCByteTransport(raw: raw, queue: queue)
        var opening = HTTP2.preface
        opening.append(HTTP2.settingsFrame(values: [
            (0x4, UInt32(initialTargetWindow)),
            (0x5, UInt32(advertisedMaxFrameSize)),
            (0x3, 128),
        ]))
        opening.append(HTTP2.windowUpdate(streamID: 0,
                                          increment: UInt32(initialTargetWindow - HTTP2.defaultWindowSize)))

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
        transport.currentTargetWindow = initialTargetWindow
        transport.localWindow = initialTargetWindow
        transport.localConnectionWindow = initialTargetWindow

        raw.send(opening) { error in
            if let error { raw.cancel(); completion(.failure(error)); return }
            transport.pump()
            completion(.success(transport))
        }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        let framed = GRPCFraming.encode(data)
        lock.lock()
        if let failure { lock.unlock(); completion(failure); return }
        if cancelled { lock.unlock(); completion(NativeOutboundError.connection("gRPC 流已关闭")); return }
        if pendingDataBytes + framed.count > Self.maxPendingOutboundBytes {
            lock.unlock()
            completion(NativeOutboundError.connection("gRPC 发送缓冲超出上限"))
            return
        }
        pendingDataPayloads.append((framed, 0, completion))
        pendingDataBytes += framed.count
        let batch = buildFlowControlledBatchLocked()
        if !batch.isEmpty {
            writeBacklog.append(contentsOf: batch)
        }
        lock.unlock()
        if !batch.isEmpty {
            drain()
        }
    }

    /// Coalesces adjacent small `pendingDataPayloads` into larger `DATA` frames
    /// (up to `min(peerMaxFrameSize, 65_536)`) and batches frames up to 64 KiB.
    private func buildFlowControlledBatchLocked() -> [(Data, (Error?) -> Void)] {
        var ready: [(Data, (Error?) -> Void)] = []
        let maxFramePayloadCap = min(peerMaxFrameSize, Self.maxCoalescedWriteBytes)
        guard maxFramePayloadCap > 0 else { return ready }

        while !pendingDataPayloads.isEmpty {
            let budget = min(peerStreamWindow, peerConnectionWindow)
            guard budget > 0 else { break }

            var wire = Data(capacity: min(Self.maxCoalescedWriteBytes + 36, 9 + min(pendingDataBytes, budget)))
            var callbacks: [(Error?) -> Void] = []

            while !pendingDataPayloads.isEmpty, wire.count < Self.maxCoalescedWriteBytes {
                let avail = min(peerStreamWindow, peerConnectionWindow)
                guard avail > 0 else { break }
                let maxFrameLen = min(maxFramePayloadCap, avail)

                // Compute total payload length we will pack into this single DATA frame.
                var frameLen = 0
                var probeIdx = 0
                while probeIdx < pendingDataPayloads.count, frameLen < maxFrameLen {
                    let (msg, off, _) = pendingDataPayloads[probeIdx]
                    let rem = msg.count - off
                    let take = min(rem, maxFrameLen - frameLen)
                    frameLen += take
                    if take < rem { break }
                    probeIdx += 1
                }
                guard frameLen > 0 else { break }

                HTTP2.appendFrameHeader(
                    length: frameLen,
                    type: HTTP2.FrameType.data.rawValue,
                    flags: [],
                    streamID: Self.streamID,
                    to: &wire
                )

                var remainingInFrame = frameLen
                while remainingInFrame > 0, !pendingDataPayloads.isEmpty {
                    let (msg, off, cb) = pendingDataPayloads[0]
                    let rem = msg.count - off
                    if rem <= remainingInFrame {
                        wire.append(msg[(msg.startIndex + off)..<msg.endIndex])
                        remainingInFrame -= rem
                        peerStreamWindow -= rem
                        peerConnectionWindow -= rem
                        pendingDataBytes -= rem
                        callbacks.append(cb)
                        pendingDataPayloads.removeFirst()
                    } else {
                        wire.append(msg[(msg.startIndex + off)..<(msg.startIndex + off + remainingInFrame)])
                        pendingDataPayloads[0].1 = off + remainingInFrame
                        peerStreamWindow -= remainingInFrame
                        peerConnectionWindow -= remainingInFrame
                        pendingDataBytes -= remainingInFrame
                        remainingInFrame = 0
                    }
                }
            }

            if !wire.isEmpty {
                if callbacks.isEmpty {
                    ready.append((wire, { _ in }))
                } else if callbacks.count == 1 {
                    ready.append((wire, callbacks[0]))
                } else {
                    let batchedCallbacks = callbacks
                    ready.append((wire, { err in
                        for cb in batchedCallbacks { cb(err) }
                    }))
                }
            } else {
                break
            }
        }
        return ready
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
        let stalled = pendingDataPayloads
        pendingDataPayloads.removeAll()
        pendingDataBytes = 0
        let queuedWrites = writeBacklog
        writeBacklog.removeAll()
        lock.unlock()
        waiter?(nil, true, nil)
        let cancelErr = NativeOutboundError.connection("gRPC 流已取消")
        for (_, _, cb) in stalled { cb(cancelErr) }
        for (_, cb) in queuedWrites { cb(cancelErr) }
        raw.cancel()
    }

    private func enqueue(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        if cancelled {
            let err = failure ?? NativeOutboundError.connection("gRPC 流已取消")
            lock.unlock()
            completion(err)
            return
        }
        writeBacklog.append((data, completion))
        lock.unlock()
        drain()
    }

    /// Coalesces consecutive `writeBacklog` wire buffers up to `65_536` bytes
    /// into a single `raw.send`, completing all batched callbacks together.
    private func drain() {
        lock.lock()
        guard !writeInFlight, !writeBacklog.isEmpty, !cancelled else { lock.unlock(); return }
        writeInFlight = true

        var takeCount = 1
        var totalBytes = writeBacklog[0].0.count
        while takeCount < writeBacklog.count {
            let nextCount = writeBacklog[takeCount].0.count
            guard totalBytes + nextCount <= Self.maxCoalescedWriteBytes else { break }
            totalBytes += nextCount
            takeCount += 1
        }

        let wireData: Data
        let completion: (Error?) -> Void
        if takeCount == 1 {
            let item = writeBacklog.removeFirst()
            wireData = item.0
            completion = item.1
        } else {
            var combined = Data(capacity: totalBytes)
            var callbacks: [(Error?) -> Void] = []
            callbacks.reserveCapacity(takeCount)
            for idx in 0..<takeCount {
                combined.append(writeBacklog[idx].0)
                callbacks.append(writeBacklog[idx].1)
            }
            writeBacklog.removeFirst(takeCount)
            wireData = combined
            completion = { err in
                for cb in callbacks { cb(err) }
            }
        }
        lock.unlock()

        raw.send(wireData) { [weak self] error in
            guard let self else { completion(error); return }
            self.lock.lock(); self.writeInFlight = false; self.lock.unlock()
            completion(error)
            if error == nil { self.drain() }
        }
    }

    private func sendControl(_ data: Data) {
        enqueue(data) { _ in }
    }

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
        var unblockedWrites: [(Data, (Error?) -> Void)] = []
        var offset = 0
        do {
            while let frame = try HTTP2.decode(from: frameBuffer, offset: &offset, maxFrameSize: 1 << 22) {
                if let contStream = awaitingContinuationStream {
                    guard frame.type == HTTP2.FrameType.continuation.rawValue, frame.streamID == contStream else {
                        throw HTTP2.FrameError.protocolViolation("期待 CONTINUATION 帧但收到类型 \(frame.type)")
                    }
                    consecutiveControlFrames += 1
                    if consecutiveControlFrames > HTTP2.maxConsecutiveControlFrames {
                        throw HTTP2.FrameError.protocolViolation("CONTINUATION 帧数量超出安全上限")
                    }
                    if frame.flags.contains(.endHeaders) { awaitingContinuationStream = nil }
                    continue
                }
                switch frame.type {
                case HTTP2.FrameType.data.rawValue:
                    consecutiveControlFrames = 0
                    localWindow -= frame.rawLength
                    localConnectionWindow -= frame.rawLength
                    if frame.streamID == Self.streamID {
                        messageBuffer.append(frame.payload)
                        for payload in try GRPCFraming.decode(from: &messageBuffer) {
                            deliver.append(payload)
                        }
                    }
                    recordBDPDataSampleLocked(bytes: frame.rawLength, control: &control)
                    let replenishThreshold = currentTargetWindow / 2
                    if localWindow < replenishThreshold {
                        let increment = UInt32(currentTargetWindow - localWindow)
                        control.append(HTTP2.windowUpdate(streamID: Self.streamID, increment: increment))
                        localWindow = currentTargetWindow
                    }
                    if localConnectionWindow < replenishThreshold {
                        let increment = UInt32(currentTargetWindow - localConnectionWindow)
                        control.append(HTTP2.windowUpdate(streamID: 0, increment: increment))
                        localConnectionWindow = currentTargetWindow
                    }
                case HTTP2.FrameType.headers.rawValue:
                    consecutiveControlFrames += 1
                    if !frame.flags.contains(.endHeaders) {
                        awaitingContinuationStream = frame.streamID
                    }
                case HTTP2.FrameType.settings.rawValue:
                    consecutiveControlFrames += 1
                    guard frame.streamID == 0 else {
                        throw HTTP2.FrameError.protocolViolation("SETTINGS 帧 streamID 必须为 0")
                    }
                    if frame.flags.contains(.ack) {
                        guard frame.payload.isEmpty else {
                            throw HTTP2.FrameError.protocolViolation("SETTINGS ACK 载荷必须为空")
                        }
                    } else {
                        guard frame.payload.count % 6 == 0 else {
                            throw HTTP2.FrameError.protocolViolation("SETTINGS 帧长度不是 6 的倍数")
                        }
                        try applySettingsLocked(frame.payload)
                        control.append(HTTP2.settingsFrame(ack: true))
                        unblockedWrites.append(contentsOf: buildFlowControlledBatchLocked())
                    }
                case HTTP2.FrameType.windowUpdate.rawValue:
                    consecutiveControlFrames += 1
                    let inc = try HTTP2.parseWindowUpdate(frame)
                    if frame.streamID == 0 {
                        guard peerConnectionWindow <= HTTP2.maxFlowControlWindow - inc else {
                            throw HTTP2.FrameError.protocolViolation("连接流控窗口溢出 2^31-1")
                        }
                        peerConnectionWindow += inc
                    } else if frame.streamID == Self.streamID {
                        guard peerStreamWindow <= HTTP2.maxFlowControlWindow - inc else {
                            throw HTTP2.FrameError.protocolViolation("流级流控窗口溢出 2^31-1")
                        }
                        peerStreamWindow += inc
                    }
                    unblockedWrites.append(contentsOf: buildFlowControlledBatchLocked())
                case HTTP2.FrameType.ping.rawValue:
                    consecutiveControlFrames += 1
                    guard frame.streamID == 0, frame.payload.count == 8 else {
                        throw HTTP2.FrameError.protocolViolation("RFC 9113 §6.7 PING 帧必须位于流 0 且长度为 8 字节")
                    }
                    if frame.flags.contains(.ack) {
                        handleBDPPingAckLocked(payload: frame.payload, control: &control)
                    } else {
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
                    compactFrameBufferLocked(consumed: offset)
                    lock.unlock()
                    fail(HTTP2.FrameError.goAway(code))
                    return
                case HTTP2.FrameType.rstStream.rawValue:
                    if frame.streamID == Self.streamID {
                        compactFrameBufferLocked(consumed: offset)
                        lock.unlock()
                        finish()
                        return
                    }
                case HTTP2.FrameType.continuation.rawValue:
                    throw HTTP2.FrameError.protocolViolation("未处于 HEADERS 延续状态却收到孤立 CONTINUATION 帧")
                default:
                    consecutiveControlFrames += 1
                }
                if consecutiveControlFrames > HTTP2.maxConsecutiveControlFrames {
                    throw HTTP2.FrameError.protocolViolation("连续控制帧超过安全上限，已阻断疑似 Rapid-Reset/PING 洪泛")
                }
                if frame.streamID == Self.streamID,
                   frame.flags.contains(.endStream),
                   frame.type == HTTP2.FrameType.data.rawValue || frame.type == HTTP2.FrameType.headers.rawValue {
                    compactFrameBufferLocked(consumed: offset)
                    if !control.isEmpty { writeBacklog.append((control, { _ in })) }
                    if !unblockedWrites.isEmpty { writeBacklog.append(contentsOf: unblockedWrites) }
                    let needDrain = !control.isEmpty || !unblockedWrites.isEmpty
                    lock.unlock()
                    if !deliver.isEmpty { publish(deliver) }
                    if needDrain { drain() }
                    finish()
                    return
                }
            }
            compactFrameBufferLocked(consumed: offset)
        } catch {
            lock.unlock()
            throw error
        }
        if !control.isEmpty { writeBacklog.append((control, { _ in })) }
        if !unblockedWrites.isEmpty { writeBacklog.append(contentsOf: unblockedWrites) }
        let needDrain = !control.isEmpty || !unblockedWrites.isEmpty
        lock.unlock()
        if needDrain { drain() }
        if !deliver.isEmpty { publish(deliver) }
    }

    /// RFC 9113 PING-based BDP estimator: emits an 8-byte PING probe once
    /// downlink bytes since the last sample reach `>= currentTargetWindow / 2`.
    private func recordBDPDataSampleLocked(bytes: Int, control: inout Data) {
        guard bytes > 0, currentTargetWindow < Self.maxTargetWindow else { return }
        let now = DispatchTime.now().uptimeNanoseconds
        if !bdpPingInFlight {
            if bdpBytesSinceSample == 0 || (bdpLastDataNs > 0 && now &- bdpLastDataNs > 1_000_000_000) {
                bdpBytesSinceSample = 0
                bdpSampleStartNs = now
            }
            bdpLastDataNs = now
            bdpBytesSinceSample += bytes
            if bdpBytesSinceSample >= currentTargetWindow / 2 {
                bdpPingInFlight = true
                bdpBytesDuringRTT = bytes
                bdpPingSeq &+= 1
                bdpPingSentNs = now
                var payload = Data(capacity: 8)
                payload.append(contentsOf: [0x48, 0x4A, 0x42, 0x44]) // "HJBD"
                payload.append(UInt8(truncatingIfNeeded: bdpPingSeq >> 24))
                payload.append(UInt8(truncatingIfNeeded: bdpPingSeq >> 16))
                payload.append(UInt8(truncatingIfNeeded: bdpPingSeq >> 8))
                payload.append(UInt8(truncatingIfNeeded: bdpPingSeq))
                bdpPingPayload = payload
                control.append(HTTP2.encode(HTTP2.Frame(
                    type: HTTP2.FrameType.ping.rawValue,
                    flags: [], streamID: 0, payload: payload)))
            }
        } else {
            bdpLastDataNs = now
            bdpBytesSinceSample += bytes
            bdpBytesDuringRTT += bytes
        }
    }

    private func handleBDPPingAckLocked(payload: Data, control: inout Data) {
        guard bdpPingInFlight, payload == bdpPingPayload else { return }
        bdpPingInFlight = false
        let now = DispatchTime.now().uptimeNanoseconds
        let rttNs = max(1, now &- bdpPingSentNs)
        let sampleNs = max(rttNs, now &- bdpSampleStartNs)
        let sampledBytes = bdpBytesSinceSample
        let rttBytes = bdpBytesDuringRTT
        bdpBytesSinceSample = 0
        bdpBytesDuringRTT = 0
        bdpSampleStartNs = now

        let rateEstimate = Int((Double(sampledBytes) * Double(rttNs)) / Double(sampleNs))
        let bdpEstimate = max(rttBytes, rateEstimate)
        if bdpEstimate * 2 > currentTargetWindow, currentTargetWindow < Self.maxTargetWindow {
            let newTarget = min(Self.maxTargetWindow, max(currentTargetWindow * 2, bdpEstimate * 2))
            let growDelta = newTarget - currentTargetWindow
            if growDelta > 0 {
                currentTargetWindow = newTarget
                let inc = UInt32(growDelta)
                control.append(HTTP2.windowUpdate(streamID: Self.streamID, increment: inc))
                localWindow += growDelta
                control.append(HTTP2.windowUpdate(streamID: 0, increment: inc))
                localConnectionWindow += growDelta
            }
        }
    }

    private func compactFrameBufferLocked(consumed: Int) {
        guard consumed > 0 else { return }
        if consumed >= frameBuffer.count {
            frameBuffer.removeAll(keepingCapacity: true)
        } else {
            frameBuffer.removeSubrange(frameBuffer.startIndex..<(frameBuffer.startIndex + consumed))
        }
    }

    private func applySettingsLocked(_ payload: Data) throws {
        if !peerSettingsReceived {
            peerSettingsReceived = true
            let baseDelta = HTTP2.defaultWindowSize - peerInitialWindowSize
            peerInitialWindowSize = HTTP2.defaultWindowSize
            peerStreamWindow += baseDelta
            peerConnectionWindow += baseDelta
        }
        var index = payload.startIndex
        while payload.distance(from: index, to: payload.endIndex) >= 6 {
            let identifier = UInt16(payload[index]) << 8 | UInt16(payload[index + 1])
            let value = UInt32(payload[index + 2]) << 24 | UInt32(payload[index + 3]) << 16
                | UInt32(payload[index + 4]) << 8 | UInt32(payload[index + 5])
            switch identifier {
            case 0x4: // SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113 §6.5.2 & §6.9.2)
                guard value <= UInt32(HTTP2.maxFlowControlWindow) else {
                    throw HTTP2.FrameError.protocolViolation("SETTINGS_INITIAL_WINDOW_SIZE 超出 2^31-1")
                }
                let delta = Int(value) - peerInitialWindowSize
                guard peerStreamWindow + delta <= HTTP2.maxFlowControlWindow else {
                    throw HTTP2.FrameError.protocolViolation("SETTINGS 窗口调整导致流窗口溢出")
                }
                peerInitialWindowSize = Int(value)
                peerStreamWindow += delta
            case 0x5: // SETTINGS_MAX_FRAME_SIZE (RFC 9113 §6.5.2)
                guard value >= 16_384, value <= (1 << 24) - 1 else {
                    throw HTTP2.FrameError.protocolViolation("SETTINGS_MAX_FRAME_SIZE 超出 [16384, 16777215]")
                }
                peerMaxFrameSize = Int(value)
            default:
                break
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
        cancelled = true
        let waiter = pendingReceive
        pendingReceive = nil
        let stalled = pendingDataPayloads
        pendingDataPayloads.removeAll()
        pendingDataBytes = 0
        let queuedWrites = writeBacklog
        writeBacklog.removeAll()
        lock.unlock()
        waiter?(nil, true, error)
        for (_, _, cb) in stalled { cb(error) }
        for (_, cb) in queuedWrites { cb(error) }
        raw.cancel()
    }

    private func finish() {
        lock.lock()
        cancelled = true
        let waiter = pendingReceive
        pendingReceive = nil
        let stalled = pendingDataPayloads
        pendingDataPayloads.removeAll()
        pendingDataBytes = 0
        let queuedWrites = writeBacklog
        writeBacklog.removeAll()
        lock.unlock()
        waiter?(nil, true, nil)
        let endErr = NativeOutboundError.connection("gRPC 流已结束")
        for (_, _, cb) in stalled { cb(endErr) }
        for (_, cb) in queuedWrites { cb(endErr) }
        raw.cancel()
    }
}

// MARK: - Standard HTTP/2 CONNECT & Extended CONNECT (RFC 9113 §8.5 / RFC 8441 / RFC 9298)

/// Standard HTTP/2 `CONNECT` and Extended `CONNECT` (`:protocol = connect-udp` / `connect-ip`)
/// stream framing over a raw TLS/TCP byte carrier.

/// RFC 9218 Extensible Prioritization Scheme for HTTP (`Priority` header field).
public struct HTTPExtensiblePriority: Equatable, Sendable {
    public let urgency: UInt8
    public let incremental: Bool

    public static let interactiveDNS = HTTPExtensiblePriority(urgency: 0, incremental: true)
    public static let interactiveStream = HTTPExtensiblePriority(urgency: 3, incremental: true)
    public static let defaultPriority = HTTPExtensiblePriority(urgency: 3, incremental: false)

    public init(urgency: UInt8 = 3, incremental: Bool = false) {
        self.urgency = min(urgency, 7)
        self.incremental = incremental
    }

    public var headerValue: String {
        incremental ? "u=\(urgency), i" : "u=\(urgency)"
    }
}

enum HTTP2ConnectHeaders {
    private static func containsForbiddenHeaderOctet(_ text: String) -> Bool {
        for b in text.utf8 where b == 0x0D || b == 0x0A || b == 0x00 {
            return true
        }
        return false
    }

    static func buildRequestHeaders(authority: String,
                                    extendedProtocol: String? = nil,
                                    scheme: String = "https",
                                    path: String? = nil,
                                    proxyAuthorization: String? = nil,
                                    priority: HTTPExtensiblePriority? = nil) throws -> [HPACK.HeaderField] {
        guard !authority.isEmpty, !containsForbiddenHeaderOctet(authority) else {
            throw HTTP2.FrameError.protocolViolation("HTTP/2 CONNECT :authority 非法")
        }
        var fields: [HPACK.HeaderField] = [.init(name: ":method", value: "CONNECT")]
        if let proto = extendedProtocol, !proto.isEmpty {
            // RFC 8441 §4: Extended CONNECT requires :protocol, :scheme, :path, and :authority.
            let resolvedPath = path ?? "/.well-known/masque/udp/"
            fields.append(.init(name: ":protocol", value: proto))
            fields.append(.init(name: ":scheme", value: scheme))
            fields.append(.init(name: ":path", value: resolvedPath))
            fields.append(.init(name: ":authority", value: authority))
            if proto == "connect-udp" || proto == "connect-ip" {
                fields.append(.init(name: "capsule-protocol", value: "?1"))
            }
        } else {
            // RFC 9113 §8.5: Classic HTTP/2 CONNECT omits :scheme and :path.
            fields.append(.init(name: ":authority", value: authority))
        }
        if let auth = proxyAuthorization, !auth.isEmpty,
           !containsForbiddenHeaderOctet(auth) {
            fields.append(.init(name: "proxy-authorization", value: auth))
        }
        if let priority {
            fields.append(.init(name: "priority", value: priority.headerValue))
        }
        return fields
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
        try HPACKSelfTest.run()
        try frameRoundTrip()
        try framePadding()
        try grpcFraming()
        try rejectsMalformedInput()
        try extendedConnectAndWindowValidation()
        try bdpAutoTuningAndCoalescing()
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
        try expect(decoded.rawLength == payload.count, "rawLength 不符")
        try expect(decoded.flags.contains(.endStream), "END_STREAM 标志丢失")
        try expect(buffer.isEmpty, "帧解码后有残留")

        var wide = HTTP2.encode(HTTP2.Frame(type: 0, flags: [], streamID: 0x7FFF_FFFF,
                                            payload: Data()))
        guard let big = try HTTP2.decode(from: &wide, maxFrameSize: 1 << 22) else {
            throw Failure(text: "大流 ID 帧未能解码")
        }
        try expect(big.streamID == 0x7FFF_FFFF, "31 位流 ID 解析错误：\(big.streamID)")

        var partial = HTTP2.encode(frame).prefix(20)
        let snapshot = partial
        try expect(try HTTP2.decode(from: &partial, maxFrameSize: 1 << 22) == nil,
                   "不完整帧被错误解码")
        try expect(partial == snapshot, "不完整帧解析后缓冲区被破坏")
    }

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
        try expect(decoded.rawLength == 10,
                   "RFC 9113 §6.9.1 流控计费必须保留原始含填充长度 10，实际 \(decoded.rawLength)")

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

        var badPad = HTTP2.encode(HTTP2.Frame(type: HTTP2.FrameType.data.rawValue,
                                              flags: [.padded], streamID: 1,
                                              payload: Data([200, 1, 2])))
        do {
            _ = try HTTP2.decode(from: &badPad, maxFrameSize: 1 << 22)
            throw Failure(text: "越界填充长度未被拒绝")
        } catch is HTTP2.FrameError {}

        var wrongTag = Data([0x00, 0x00, 0x00, 0x00, 0x03, 0x12, 0x01, 0x41])
        do {
            _ = try GRPCFraming.decode(from: &wrongTag)
            throw Failure(text: "错误的 Hunk 字段号未被拒绝")
        } catch is NativeOutboundError {}

        var compressed = Data([0x01, 0x00, 0x00, 0x00, 0x01, 0x41])
        do {
            _ = try GRPCFraming.decode(from: &compressed)
            throw Failure(text: "压缩消息未被拒绝")
        } catch is NativeOutboundError {}
    }

    private static func extendedConnectAndWindowValidation() throws {
        // RFC 9113 §6.9 zero-increment WINDOW_UPDATE MUST be rejected.
        let zeroWU = HTTP2.Frame(type: HTTP2.FrameType.windowUpdate.rawValue, flags: [],
                                 streamID: 0, payload: Data([0, 0, 0, 0]))
        try expect((try? HTTP2.parseWindowUpdate(zeroWU)) == nil,
                   "RFC 9113 §6.9 增量为 0 的 WINDOW_UPDATE 必须被拒绝")
        var validWUBuf = HTTP2.windowUpdate(streamID: 1, increment: 65_536)
        guard let parsedWU = try HTTP2.decode(from: &validWUBuf, maxFrameSize: 16_384) else {
            throw Failure(text: "合法 WINDOW_UPDATE 解码失败")
        }
        try expect(try HTTP2.parseWindowUpdate(parsedWU) == 65_536, "WINDOW_UPDATE 增量解析错误")

        // RFC 8441 + RFC 9298 MASQUE connect-udp header construction & CRLF injection defense.
        let masqueHeaders = try HTTP2ConnectHeaders.buildRequestHeaders(
            authority: "proxy.example.com:443",
            extendedProtocol: "connect-udp",
            path: "/.well-known/masque/udp/192.0.2.1/53/",
            priority: .interactiveStream
        )
        try expect(masqueHeaders.contains(where: { $0.name == ":protocol" && $0.value == "connect-udp" })
                   && masqueHeaders.contains(where: { $0.name == "capsule-protocol" && $0.value == "?1" })
                   && masqueHeaders.contains(where: { $0.name == "priority" && $0.value == "u=3, i" }),
                   "RFC 8441 / RFC 9298 Extended CONNECT 伪首部或 Capsule-Protocol 缺失")
        try expect((try? HTTP2ConnectHeaders.buildRequestHeaders(authority: "bad.example\r\nx:1")) == nil,
                   "含 CRLF 的 HTTP/2 CONNECT :authority 必须被拒绝")
    }

    private static func bdpAutoTuningAndCoalescing() throws {
        final class LoopbackPeer: ByteTransport {
            private let lock = NSLock()
            var sentChunks: [Data] = []
            var receiver: ((Data?, Bool, Error?) -> Void)?
            var holdWrites = false
            var heldCompletions: [(Error?) -> Void] = []

            func send(_ data: Data, completion: @escaping (Error?) -> Void) {
                lock.lock()
                sentChunks.append(data)
                if holdWrites {
                    heldCompletions.append(completion)
                    lock.unlock()
                    return
                }
                lock.unlock()
                completion(nil)
            }

            func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
                lock.lock()
                receiver = completion
                lock.unlock()
            }

            func cancel() {}

            func releaseHeld() {
                while true {
                    lock.lock()
                    guard !heldCompletions.isEmpty else {
                        holdWrites = false
                        lock.unlock()
                        return
                    }
                    let next = heldCompletions.removeFirst()
                    lock.unlock()
                    next(nil)
                }
            }
        }

        let peer = LoopbackPeer()
        let queue = DispatchQueue(label: "app.hajimi.http2.bdp-selftest")
        var opened: Result<GRPCByteTransport, Error>?
        GRPCByteTransport.connect(raw: peer, serviceName: "GunService", authority: "example.com",
                                  scheme: "https", queue: queue) { opened = $0 }
        guard let transport = try opened?.get() else {
            throw Failure(text: "GRPCByteTransport 连接未完成")
        }

        // 1. Verify 4 MiB SETTINGS_INITIAL_WINDOW_SIZE (0x4) and 64 KiB SETTINGS_MAX_FRAME_SIZE (0x5)
        try expect(!peer.sentChunks.isEmpty, "未发送 HTTP/2 握手前导")
        var opening = peer.sentChunks[0]
        try expect(opening.starts(with: HTTP2.preface), "缺少 HTTP/2 连接前导")
        opening.removeFirst(HTTP2.preface.count)
        guard let settings = try HTTP2.decode(from: &opening, maxFrameSize: 16_384),
              settings.type == HTTP2.FrameType.settings.rawValue else {
            throw Failure(text: "首帧不是客户端 SETTINGS")
        }
        var saw4MiB = false
        var saw64KiB = false
        var sIdx = settings.payload.startIndex
        while settings.payload.distance(from: sIdx, to: settings.payload.endIndex) >= 6 {
            let id = UInt16(settings.payload[sIdx]) << 8 | UInt16(settings.payload[sIdx + 1])
            let val = UInt32(settings.payload[sIdx + 2]) << 24 | UInt32(settings.payload[sIdx + 3]) << 16
                | UInt32(settings.payload[sIdx + 4]) << 8 | UInt32(settings.payload[sIdx + 5])
            if id == 0x4 && val == 4_194_304 { saw4MiB = true }
            if id == 0x5 && val == 65_536 { saw64KiB = true }
            sIdx = settings.payload.index(sIdx, offsetBy: 6)
        }
        try expect(saw4MiB && saw64KiB, "客户端 SETTINGS 未通告 4 MiB 窗口与 64 KiB 最大帧长")

        // 2. Verify BDP PING probe after >= 2 MiB downlink DATA and auto-tuned WINDOW_UPDATE upon PING ACK
        peer.sentChunks.removeAll()
        let chunkPayload = GRPCFraming.encode(Data(repeating: 0x42, count: 65_531))
        var downlinkBurst = Data()
        for _ in 0..<40 { // 40 * 64 KiB = 2.5 MiB (> 4 MiB / 2)
            downlinkBurst.append(HTTP2.encode(HTTP2.Frame(
                type: HTTP2.FrameType.data.rawValue, flags: [], streamID: 1, payload: chunkPayload)))
        }
        guard let deliverIn = peer.receiver else { throw Failure(text: "gRPC 未注册下行读取回调") }
        deliverIn(downlinkBurst, false, nil)

        var controlWire = peer.sentChunks.reduce(Data(), +)
        var bdpPingToken: Data?
        while let ctlFrame = try HTTP2.decode(from: &controlWire, maxFrameSize: 65_536) {
            if ctlFrame.type == HTTP2.FrameType.ping.rawValue && !ctlFrame.flags.contains(.ack) {
                bdpPingToken = ctlFrame.payload
            }
        }
        guard let pingToken = bdpPingToken else {
            throw Failure(text: "接收超过半窗流量后未发出 BDP PING 探测帧")
        }

        // Feed 2.5 MiB during the PING RTT + PING ACK so bdp * 2 > 4 MiB triggers window auto-tuning
        peer.sentChunks.removeAll()
        var ackBurst = Data()
        for _ in 0..<40 {
            ackBurst.append(HTTP2.encode(HTTP2.Frame(
                type: HTTP2.FrameType.data.rawValue, flags: [], streamID: 1, payload: chunkPayload)))
        }
        ackBurst.append(HTTP2.encode(HTTP2.Frame(
            type: HTTP2.FrameType.ping.rawValue, flags: .ack, streamID: 0, payload: pingToken)))
        peer.receiver?(ackBurst, false, nil)

        var postAckWire = peer.sentChunks.reduce(Data(), +)
        var grewWindow = false
        while let ctlFrame = try HTTP2.decode(from: &postAckWire, maxFrameSize: 65_536) {
            if ctlFrame.type == HTTP2.FrameType.windowUpdate.rawValue {
                let inc = try HTTP2.parseWindowUpdate(ctlFrame)
                if inc >= 4_194_304 { grewWindow = true }
            }
        }
        try expect(grewWindow, "收到 BDP PING ACK 后未自动调大接收流控窗口")

        // 3. Verify multi-frame outbound DATA & writeBacklog coalescing
        peer.sentChunks.removeAll()
        peer.holdWrites = true
        var doneCount = 0
        for _ in 0..<16 {
            transport.send(Data(repeating: 0x33, count: 512)) { if $0 == nil { doneCount += 1 } }
        }
        peer.releaseHeld()
        try expect(doneCount == 16, "合并发送回调未全部完成：\(doneCount)")
        try expect(peer.sentChunks.count < 16, "多笔小负载写入未触发合并发送：\(peer.sentChunks.count)")
        transport.cancel()
    }
}

import Foundation
import Network

// MARK: - Mux.Cool wire format
//
// Mux.Cool carries many logical streams over one already-established outbound
// connection. It is chosen over sing-mux for one decisive reason: a Mux.Cool
// server adapts automatically when the client opts in, whereas sing-mux
// requires the server inbound to enable multiplexing explicitly. Only the
// former lets an existing, unmodified node keep working.
//
// Frame layout, all integers big-endian:
//
//     [2 bytes metadata length L][L bytes metadata][2 bytes data length D][D bytes data]
//
// The trailing length-prefixed data section is present only when the metadata
// option byte has bit D (0x01) set.
//
// Metadata, common prefix:
//
//     [2 bytes stream ID][1 byte status][1 byte option]
//
// A `new` frame appends the destination:
//
//     [1 byte network][2 bytes port][1 byte address type][address]
//
// Address encoding: IPv4 is 4 raw bytes, IPv6 is 16 raw bytes, and a domain is
// a single length byte followed by that many UTF-8 bytes.

enum MuxStatus: UInt8 {
    case new = 0x01
    case keep = 0x02
    case end = 0x03
    case keepAlive = 0x04
}

enum MuxNetwork: UInt8 {
    case tcp = 0x01
    case udp = 0x02
}

enum MuxAddressType: UInt8 {
    case ipv4 = 0x01
    case domain = 0x02
    case ipv6 = 0x03
}

struct MuxFrame: Equatable {
    var id: UInt16
    var status: MuxStatus
    var network: MuxNetwork = .tcp
    /// Present on `new`, and on `keep` when the network is UDP.
    var target: RequestTarget?
    var payload: Data = Data()

    /// The option byte only ever carries the "extra data follows" bit, so it is
    /// derived rather than stored: an inconsistent pair is not representable.
    var hasPayload: Bool { !payload.isEmpty }
}

enum MuxCodecError: LocalizedError {
    case malformed(String)
    case addressTooLong(String)
    case payloadTooLarge(Int)

    var errorDescription: String? {
        switch self {
        case .malformed(let detail): return "Mux 帧格式无效：\(detail)"
        case .addressTooLong(let host): return "Mux 目标域名超过 255 字节：\(host)"
        case .payloadTooLarge(let size): return "Mux 分片超过 65535 字节：\(size)"
        }
    }
}

/// A bounds-checked, copy-free view over a `Data` starting at an offset.
private struct ContiguousBytes {
    private let data: Data
    private let base: Int
    let count: Int

    init(_ data: Data, offset: Int) {
        self.data = data
        base = data.startIndex + offset
        count = max(0, data.count - offset)
    }

    subscript(index: Int) -> UInt8 { data[base + index] }

    func slice(_ start: Int, _ length: Int) -> Data {
        Data(data[(base + start)..<(base + start + length)])
    }
}

enum MuxCodec {
    static let maximumPayload = 65_535
    /// Smaller chunks interleave better across logical streams. Multiplexing
    /// exists to avoid one stream monopolising the carrier, so the chunk size
    /// is deliberately well below the 64 KiB the length field allows.
    static let preferredChunk = 8 * 1024

    // MARK: Encoding

    static func encode(_ frame: MuxFrame) throws -> Data {
        guard frame.payload.count <= maximumPayload else {
            throw MuxCodecError.payloadTooLarge(frame.payload.count)
        }
        var metadata = Data()
        appendUInt16(frame.id, to: &metadata)
        metadata.append(frame.status.rawValue)
        metadata.append(frame.hasPayload ? 0x01 : 0x00)

        let needsTarget = frame.status == .new || (frame.status == .keep && frame.network == .udp)
        if needsTarget {
            guard let target = frame.target else {
                throw MuxCodecError.malformed("\(frame.status) 帧缺少目标地址")
            }
            metadata.append(frame.network.rawValue)
            appendUInt16(target.port, to: &metadata)
            try appendAddress(host: target.host, to: &metadata)
        }

        guard metadata.count <= maximumPayload else {
            throw MuxCodecError.malformed("元数据超过 65535 字节")
        }
        var out = Data()
        appendUInt16(UInt16(metadata.count), to: &out)
        out.append(metadata)
        if frame.hasPayload {
            appendUInt16(UInt16(frame.payload.count), to: &out)
            out.append(frame.payload)
        }
        return out
    }

    private static func appendUInt16(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    private static func appendAddress(host: String, to data: inout Data) throws {
        if let v4 = IPv4Address(host) {
            data.append(MuxAddressType.ipv4.rawValue)
            data.append(contentsOf: v4.rawValue)
            return
        }
        // Network's IPv6Address accepts a scope suffix; the wire format has no
        // room for one, so it is dropped rather than smuggled into the domain
        // branch as a bogus hostname.
        if let v6 = IPv6Address(String(host.split(separator: "%").first ?? "")) {
            data.append(MuxAddressType.ipv6.rawValue)
            data.append(contentsOf: v6.rawValue)
            return
        }
        let bytes = Array(host.utf8)
        guard bytes.count <= 255, !bytes.isEmpty else { throw MuxCodecError.addressTooLong(host) }
        data.append(MuxAddressType.domain.rawValue)
        data.append(UInt8(bytes.count))
        data.append(contentsOf: bytes)
    }

    // MARK: Decoding

    /// Decodes one frame from the front of `buffer`.
    ///
    /// Returns nil when the buffer holds only part of a frame, in which case
    /// `buffer` is left untouched so the caller can retry after more bytes
    /// arrive. On success the consumed bytes are removed.
    ///
    /// Every read is bounds-checked against the declared lengths: this parses
    /// bytes straight off the network and must never trust them.
    static func decode(from buffer: inout Data) throws -> MuxFrame? {
        var consumed = 0
        let frame = try decode(buffer, from: 0, consumed: &consumed)
        if consumed > 0 {
            buffer.removeSubrange(buffer.startIndex..<(buffer.startIndex + consumed))
        }
        return frame
    }

    /// Decodes one frame starting at `offset` without copying the buffer.
    ///
    /// `decode(from:)` used to materialise the entire receive buffer as an
    /// array for every frame, which turns a full 64 KiB read into thousands of
    /// full-buffer copies.
    static func decode(_ buffer: Data, from offset: Int,
                       consumed: inout Int) throws -> MuxFrame? {
        let bytes = ContiguousBytes(buffer, offset: offset)
        guard bytes.count >= 2 else { return nil }
        let metadataLength = Int(bytes[0]) << 8 | Int(bytes[1])
        guard metadataLength >= 4 else {
            throw MuxCodecError.malformed("元数据长度 \(metadataLength) 小于最小值 4")
        }
        guard bytes.count >= 2 + metadataLength else { return nil }

        var cursor = 2
        let metadataEnd = 2 + metadataLength
        func take(_ count: Int, _ what: String) throws -> [UInt8] {
            guard cursor + count <= metadataEnd else {
                throw MuxCodecError.malformed("元数据在读取\(what)时越界")
            }
            defer { cursor += count }
            return (0..<count).map { bytes[cursor + $0] }
        }

        let idBytes = try take(2, "流 ID")
        let id = UInt16(idBytes[0]) << 8 | UInt16(idBytes[1])
        let rawStatus = try take(1, "状态").first!
        guard let status = MuxStatus(rawValue: rawStatus) else {
            throw MuxCodecError.malformed("未知状态 0x\(String(rawStatus, radix: 16))")
        }
        let option = try take(1, "选项").first!
        let hasPayload = option & 0x01 != 0

        var network = MuxNetwork.tcp
        var target: RequestTarget?
        // `new` always carries a destination; `keep` carries one only for UDP.
        // Distinguishing them by remaining metadata length keeps the decoder
        // tolerant of the TCP `keep` frame, which stops right here.
        if status == .new || (status == .keep && cursor < metadataEnd) {
            let rawNetwork = try take(1, "网络类型").first!
            guard let parsed = MuxNetwork(rawValue: rawNetwork) else {
                throw MuxCodecError.malformed("未知网络类型 0x\(String(rawNetwork, radix: 16))")
            }
            network = parsed
            let portBytes = try take(2, "端口")
            let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
            let rawAddressType = try take(1, "地址类型").first!
            guard let addressType = MuxAddressType(rawValue: rawAddressType) else {
                throw MuxCodecError.malformed("未知地址类型 0x\(String(rawAddressType, radix: 16))")
            }
            let host: String
            switch addressType {
            case .ipv4:
                let raw = try take(4, "IPv4 地址")
                guard let address = IPv4Address(Data(raw)) else {
                    throw MuxCodecError.malformed("IPv4 地址无效")
                }
                host = "\(address)"
            case .ipv6:
                let raw = try take(16, "IPv6 地址")
                guard let address = IPv6Address(Data(raw)) else {
                    throw MuxCodecError.malformed("IPv6 地址无效")
                }
                host = "\(address)"
            case .domain:
                let length = Int(try take(1, "域名长度").first!)
                guard length > 0 else { throw MuxCodecError.malformed("域名长度为 0") }
                let raw = try take(length, "域名")
                guard let decoded = String(bytes: raw, encoding: .utf8) else {
                    throw MuxCodecError.malformed("域名不是合法 UTF-8")
                }
                host = decoded
            }
            target = RequestTarget(host: host, port: port,
                                   protocolName: network == .udp ? "UDP" : "TCP")
        }

        var payload = Data()
        var consumedHere = metadataEnd
        if hasPayload {
            guard bytes.count >= consumedHere + 2 else { return nil }
            let payloadLength = Int(bytes[consumedHere]) << 8 | Int(bytes[consumedHere + 1])
            guard bytes.count >= consumedHere + 2 + payloadLength else { return nil }
            payload = bytes.slice(consumedHere + 2, payloadLength)
            consumedHere += 2 + payloadLength
        }

        consumed = consumedHere
        return MuxFrame(id: id, status: status, network: network,
                        target: target, payload: payload)
    }
}

// MARK: - Applicability

enum MuxApplicability {
    /// The carrier connection's destination. A Mux.Cool server switches into
    /// multiplexed mode when the request it decodes names this host, which is
    /// why no server-side configuration change is needed.
    ///
    /// VMess and VLESS do not put this address on the wire: they signal
    /// multiplexing with request command 0x03 and omit the address entirely.
    /// The destination still acts as the internal marker that selects that
    /// path, exactly as it does upstream.
    static let carrierTarget = RequestTarget(host: "v1.mux.cool", port: 9527,
                                             protocolName: "TCP")

    /// True when a dial is establishing a mux carrier rather than reaching a
    /// real destination.
    static func isCarrierTarget(_ target: RequestTarget) -> Bool {
        target.host == carrierTarget.host && target.port == carrierTarget.port
    }

    private static let capableTypes: Set<String> = ["trojan", "ss", "vmess", "vless"]

    /// Multiplexing is not universally beneficial, and for several outbounds it
    /// is actively harmful. Refusing loudly beats silently degrading someone's
    /// connection.
    static func rejectionReason(for policy: ProxyPolicy) -> String? {
        let type = policy.adapterType?.lowercased() ?? ""
        switch type {
        case "hysteria", "hysteria2", "tuic":
            return "QUIC 出站已在传输层原生多路复用，叠加 Mux.Cool 只会增加一层队头阻塞"
        case "anytls":
            return "AnyTLS 自带会话复用与填充，不应再叠加 Mux.Cool"
        case "ssh":
            return "SSH 出站已使用 channel 复用"
        case "snell":
            return "Snell 未定义 Mux.Cool 承载"
        case "ssr":
            return "SSR 原生路径不支持 Mux.Cool"
        default: break
        }
        guard capableTypes.contains(type) else {
            return "\(type.uppercased()) 未定义 Mux.Cool 承载"
        }
        // Xray rejects both of these combinations server-side; enabling them
        // produces a connection that handshakes and then silently fails.
        let flow = (policy.parameters["flow"] ?? "").lowercased()
        if flow.contains("vision") {
            return "VLESS Vision 流控与 Mux.Cool 不兼容，Xray 服务端会拒绝"
        }
        let network = (policy.parameters["network"] ?? "").lowercased()
        if network.hasPrefix("xhttp") || network == "splithttp" {
            return "XHTTP 承载不得启用 Mux.Cool"
        }
        return nil
    }

    /// Mux is opt-in per node. It trades fate-sharing and head-of-line blocking
    /// for far fewer handshakes, so it must never be turned on behind the
    /// user's back.
    static func isEnabled(for policy: ProxyPolicy) -> Bool {
        guard let raw = policy.parameters["mux"]?.lowercased() else { return false }
        guard ["1", "true", "yes", "on"].contains(raw) else { return false }
        return rejectionReason(for: policy) == nil
    }

    static func concurrency(for policy: ProxyPolicy) -> Int {
        let requested = Int(policy.parameters["mux-concurrency"] ?? "") ?? 8
        return min(max(requested, 1), 128)
    }
}

// MARK: - Logical stream

/// One logical stream over a shared carrier. It is indistinguishable from a
/// real outbound to everything above it, which is what lets multiplexing be
/// introduced without touching the engine or the utun data plane.
final class MuxLogicalStream: NativeOutboundByteStream {
    private let id: UInt16
    private let target: RequestTarget
    private weak var session: MuxSession?
    /// Callbacks are delivered here, not on the session's queue. The forwarding
    /// pumps above assume single-queue ownership of their own state, and
    /// multiplexing would otherwise deliver N streams' callbacks on one shared
    /// queue.
    private let callbackQueue: DispatchQueue

    private let lock = NSLock()
    private var inbound = Data()
    private var remoteClosed = false
    private var cancelled = false
    private var failure: Error?
    private var openSent = false
    private var pendingReceive: ((Data?, Bool, Error?) -> Void)?

    init(id: UInt16, target: RequestTarget, session: MuxSession, callbackQueue: DispatchQueue) {
        self.id = id
        self.target = target
        self.session = session
        self.callbackQueue = callbackQueue
    }

    // MARK: NativeOutboundByteStream

    /// Emits the stream-open frame with no payload when nothing has been
    /// written yet, so a read-first destination still gets opened.
    private func openIfNeeded() {
        lock.lock()
        guard !openSent, !cancelled, failure == nil else { lock.unlock(); return }
        openSent = true
        lock.unlock()
        session?.sendPayload(id: id, target: target, isOpen: true, payload: Data()) { _ in }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        if let failure { lock.unlock(); callbackQueue.async { completion(failure) }; return }
        if cancelled {
            lock.unlock()
            callbackQueue.async { completion(NativeOutboundError.connection("Mux 逻辑流已关闭")) }
            return
        }
        // The first payload rides along with the stream-open frame, saving a
        // round trip exactly the way a fresh connection's initial write does.
        let isOpen = !openSent
        openSent = true
        lock.unlock()


        guard let session else {
            callbackQueue.async { completion(NativeOutboundError.connection("Mux 会话已结束")) }
            return
        }
        session.sendPayload(id: id, target: target, isOpen: isOpen, payload: data) { [weak self] error in
            guard let self else { return }
            self.callbackQueue.async { completion(error) }
        }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        // A server-speaks-first destination (SMTP, IMAP, SSH, MySQL) is read
        // before it is written to. Without this the `new` frame would never
        // reach the peer and both sides would wait on each other forever.
        openIfNeeded()
        lock.lock()
        if let failure {
            lock.unlock(); callbackQueue.async { completion(nil, true, failure) }; return
        }
        if !inbound.isEmpty {
            let count = max(1, maximum)
            let chunk = inbound.prefix(count)
            inbound.removeFirst(chunk.count)
            let complete = inbound.isEmpty && remoteClosed
            let buffered = inbound.count
            lock.unlock()
            // Draining is what lets the session resume reading the carrier.
            session?.streamBufferChanged(id: id, buffered: buffered)
            callbackQueue.async { completion(Data(chunk), complete, nil) }
            return
        }
        if remoteClosed || cancelled {
            lock.unlock(); callbackQueue.async { completion(nil, true, nil) }; return
        }
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
        if let waiter { callbackQueue.async { waiter(nil, true, nil) } }
        session?.closeStream(id: id, notifyPeer: true)
    }

    // MARK: Session callbacks

    func deliver(_ data: Data) {
        lock.lock()
        guard !cancelled else { lock.unlock(); return }
        if let waiter = pendingReceive {
            pendingReceive = nil
            let complete = remoteClosed
            lock.unlock()
            callbackQueue.async { waiter(data, complete, nil) }
            return
        }
        inbound.append(data)
        let buffered = inbound.count
        lock.unlock()
        session?.streamBufferChanged(id: id, buffered: buffered)
    }

    func deliverRemoteClose() {
        lock.lock()
        remoteClosed = true
        guard let waiter = pendingReceive, inbound.isEmpty else { lock.unlock(); return }
        pendingReceive = nil
        lock.unlock()
        callbackQueue.async { waiter(nil, true, nil) }
    }

    func deliverFailure(_ error: Error) {
        lock.lock()
        if failure == nil { failure = error }
        let waiter = pendingReceive
        pendingReceive = nil
        lock.unlock()
        if let waiter { callbackQueue.async { waiter(nil, true, error) } }
    }
}

// MARK: - Session

/// Owns one carrier connection and demultiplexes the logical streams riding on
/// it. All mutable session state is confined to `queue`.
final class MuxSession {
    private let carrier: any NativeOutboundByteStream
    private let queue: DispatchQueue
    private let concurrency: Int

    private var streams: [UInt16: MuxLogicalStream] = [:]
    private var nextID: UInt16 = 0
    private var buffer = Data()
    private var closed = false

    /// Writes are strictly serialized. The carrier is a single byte stream, so
    /// two concurrent sends would interleave and corrupt the framing.
    private var writing = false
    private var writeBacklog: [(Data, (Error?) -> Void)] = []

    private(set) var openedStreams = 0

    /// Bytes buffered across all logical streams, and whether the carrier read
    /// loop is parked because of them.
    ///
    /// This is the only backpressure mux has. The utun data plane refuses to
    /// read from an outbound while the client's receive window is full, but
    /// that demand signal cannot reach the carrier: a logical stream is fed by
    /// the session's read loop rather than by its own reads. Without a cap the
    /// session keeps pulling from the server at line rate and the whole
    /// remaining transfer accumulates in memory.
    private var bufferedByStream: [UInt16: Int] = [:]
    private var totalBuffered = 0
    private var readSuspended = false
    private static let bufferHighWater = 4 * 1024 * 1024
    private static let bufferLowWater = 1 * 1024 * 1024

    init(carrier: any NativeOutboundByteStream, concurrency: Int, label: String) {
        self.carrier = carrier
        self.concurrency = concurrency
        self.queue = DispatchQueue(label: "app.hajimi.mux.session.\(label)", qos: .userInitiated,
                                   autoreleaseFrequency: .workItem)
        pump()
    }

    var activeStreamCount: Int { queue.sync { streams.count } }
    var isClosed: Bool { queue.sync { closed } }
    var hasCapacity: Bool { queue.sync { !closed && streams.count < concurrency } }

    func openStream(target: RequestTarget, callbackQueue: DispatchQueue) -> MuxLogicalStream? {
        queue.sync {
            guard !closed, streams.count < concurrency else { return nil }
            // ID 0 is reserved for KeepAlive, and wrapping must not collide with
            // a stream that is still live.
            var candidate = nextID
            var probes = 0
            repeat {
                candidate = candidate &+ 1
                if candidate == 0 { candidate = 1 }
                probes += 1
                if probes > Int(UInt16.max) { return nil }
            } while streams[candidate] != nil
            nextID = candidate
            let stream = MuxLogicalStream(id: candidate, target: target, session: self,
                                          callbackQueue: callbackQueue)
            streams[candidate] = stream
            openedStreams += 1
            return stream
        }
    }

    /// Called by a logical stream whenever its buffered byte count changes.
    func streamBufferChanged(id: UInt16, buffered: Int) {
        queue.async {
            guard !self.closed else { return }
            let previous = self.bufferedByStream[id] ?? 0
            self.totalBuffered += buffered - previous
            if buffered == 0 { self.bufferedByStream.removeValue(forKey: id) }
            else { self.bufferedByStream[id] = buffered }
            if self.readSuspended, self.totalBuffered <= Self.bufferLowWater {
                self.readSuspended = false
                self.pump()
            }
        }
    }

    func sendPayload(id: UInt16, target: RequestTarget, isOpen: Bool, payload: Data,
                     completion: @escaping (Error?) -> Void) {
        queue.async {
            guard !self.closed else {
                completion(NativeOutboundError.connection("Mux 会话已关闭")); return
            }
            var remaining = payload
            var first = true
            var frames: [Data] = []
            repeat {
                let chunk = remaining.prefix(MuxCodec.preferredChunk)
                remaining = remaining.dropFirst(chunk.count)
                let frame = MuxFrame(id: id,
                                     status: (isOpen && first) ? .new : .keep,
                                     network: .tcp,
                                     target: (isOpen && first) ? target : nil,
                                     payload: Data(chunk))
                do { frames.append(try MuxCodec.encode(frame)) }
                catch { completion(error); return }
                first = false
            } while !remaining.isEmpty
            // An open with no payload still has to reach the peer.
            if frames.isEmpty && isOpen {
                let frame = MuxFrame(id: id, status: .new, network: .tcp, target: target)
                do { frames.append(try MuxCodec.encode(frame)) }
                catch { completion(error); return }
            }
            var combined = Data()
            frames.forEach { combined.append($0) }
            self.enqueueWrite(combined, completion: completion)
        }
    }

    func closeStream(id: UInt16, notifyPeer: Bool) {
        queue.async {
            self.totalBuffered -= self.bufferedByStream.removeValue(forKey: id) ?? 0
            if self.readSuspended, self.totalBuffered <= Self.bufferLowWater {
                self.readSuspended = false
                self.pump()
            }
            guard self.streams.removeValue(forKey: id) != nil, !self.closed else { return }
            guard notifyPeer else { return }
            guard let encoded = try? MuxCodec.encode(MuxFrame(id: id, status: .end)) else { return }
            self.enqueueWrite(encoded) { _ in }
        }
    }

    func shutdown(_ error: Error?) {
        queue.async { self.shutdownLocked(error) }
    }

    // MARK: Writer

    private func enqueueWrite(_ data: Data, completion: @escaping (Error?) -> Void) {
        writeBacklog.append((data, completion))
        drainWrites()
    }

    private func drainWrites() {
        guard !writing, !writeBacklog.isEmpty, !closed else { return }
        writing = true
        let (data, completion) = writeBacklog.removeFirst()
        carrier.send(data) { [weak self] error in
            guard let self else { completion(error); return }
            self.queue.async {
                self.writing = false
                completion(error)
                if let error { self.shutdownLocked(error) } else { self.drainWrites() }
            }
        }
    }

    // MARK: Reader

    private func pump() {
        carrier.receive(maximum: 64 * 1024) { [weak self] data, isComplete, error in
            guard let self else { return }
            self.queue.async {
                if let error { self.shutdownLocked(error); return }
                if let data, !data.isEmpty {
                    self.buffer.append(data)
                    do { try self.drainFrames() }
                    catch { self.shutdownLocked(error); return }
                }
                if isComplete { self.shutdownLocked(nil); return }
                guard !self.closed else { return }
                guard self.totalBuffered < Self.bufferHighWater else {
                    self.readSuspended = true
                    return
                }
                self.pump()
            }
        }
    }

    private func drainFrames() throws {
        var offset = 0
        defer {
            if offset > 0 {
                buffer.removeSubrange(buffer.startIndex..<(buffer.startIndex + offset))
            }
        }
        while true {
            var consumed = 0
            guard let frame = try MuxCodec.decode(buffer, from: offset, consumed: &consumed),
                  consumed > 0 else { return }
            offset += consumed
            switch frame.status {
            case .keepAlive:
                continue
            case .new, .keep:
                // A server never opens streams towards the client, so an
                // unknown ID is a stream we already closed; its residual data
                // is dropped rather than resurrecting the stream.
                guard let stream = streams[frame.id] else { continue }
                if !frame.payload.isEmpty { stream.deliver(frame.payload) }
            case .end:
                totalBuffered -= bufferedByStream.removeValue(forKey: frame.id) ?? 0
                guard let stream = streams.removeValue(forKey: frame.id) else { continue }
                if !frame.payload.isEmpty { stream.deliver(frame.payload) }
                stream.deliverRemoteClose()
            }
        }
    }

    private func shutdownLocked(_ error: Error?) {
        guard !closed else { return }
        closed = true
        let victims = streams
        streams.removeAll()
        let backlog = writeBacklog
        writeBacklog.removeAll()
        carrier.cancel()
        let reported = error ?? NativeOutboundError.connection("Mux 载体连接已关闭")
        for (_, stream) in victims {
            if error != nil { stream.deliverFailure(reported) } else { stream.deliverRemoteClose() }
        }
        backlog.forEach { $0.1(reported) }
    }
}

// MARK: - Pool

/// Per-policy pool of carrier sessions. Sessions are opened on demand, reused
/// while they have spare stream slots, and reaped once idle.
final class MuxSessionPool {
    static let shared = MuxSessionPool()

    private let lock = NSLock()
    private var sessions: [String: [MuxSession]] = [:]
    /// Bumped by `removeAll`. A carrier whose dial started before a profile
    /// reload was previously inserted after the flush and then reused
    /// indefinitely, so traffic kept flowing to the old server and credentials.
    private var generation = 0

    private init() {}

    /// Hands back a logical stream, dialling a new carrier only when every
    /// existing session for this policy is full.
    func openStream(policy: ProxyPolicy, target: RequestTarget, queue: DispatchQueue,
                    dial: @escaping (@escaping (Result<any OutboundByteStream, Error>) -> Void) -> Void,
                    completion: @escaping (Result<any OutboundByteStream, Error>) -> Void) {
        let concurrency = MuxApplicability.concurrency(for: policy)
        if let stream = takeExistingStream(policy: policy, target: target, queue: queue) {
            completion(.success(stream))
            return
        }
        let dialedGeneration = lock.withLock { generation }
        dial { result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let carrier):
                let session = MuxSession(carrier: carrier, concurrency: concurrency,
                                         label: policy.name)
                guard let stream = session.openStream(target: target, callbackQueue: queue) else {
                    session.shutdown(nil)
                    completion(.failure(NativeOutboundError.connection("无法在新建 Mux 会话上开流")))
                    return
                }
                self.lock.lock()
                let stale = self.generation != dialedGeneration
                if !stale { self.sessions[policy.name, default: []].append(session) }
                self.lock.unlock()
                guard !stale else {
                    session.shutdown(nil)
                    completion(.failure(NativeOutboundError.connection(
                        "配置已在拨号期间重载，请重试")))
                    return
                }
                completion(.success(stream))
            }
        }
    }

    private func takeExistingStream(policy: ProxyPolicy, target: RequestTarget,
                                    queue: DispatchQueue) -> MuxLogicalStream? {
        lock.lock()
        var pool = sessions[policy.name] ?? []
        pool.removeAll { $0.isClosed }
        // Least-loaded placement keeps one session from absorbing every stream
        // and becoming a head-of-line bottleneck.
        let candidates = pool.filter { $0.hasCapacity }
            .sorted { $0.activeStreamCount < $1.activeStreamCount }
        sessions[policy.name] = pool
        lock.unlock()
        for session in candidates {
            if let stream = session.openStream(target: target, callbackQueue: queue) {
                return stream
            }
        }
        return nil
    }

    /// Drops sessions that are closed or idle. Sessions with live streams are
    /// never reaped, which is what makes `MuxLogicalStream`'s weak session
    /// reference safe.
    func reap() {
        lock.lock()
        for (name, pool) in sessions {
            let kept = pool.filter { !$0.isClosed && $0.activeStreamCount > 0 }
            let dropped = pool.filter { !$0.isClosed && $0.activeStreamCount == 0 }
            sessions[name] = kept
            lock.unlock()
            dropped.forEach { $0.shutdown(nil) }
            lock.lock()
        }
        sessions = sessions.filter { !$0.value.isEmpty }
        lock.unlock()
    }

    func removeAll() {
        lock.lock()
        let all = sessions.values.flatMap { $0 }
        sessions.removeAll()
        generation &+= 1
        lock.unlock()
        all.forEach { $0.shutdown(nil) }
    }
}

// MARK: - Self-test

/// An in-memory stand-in for a carrier connection. It records what the session
/// wrote and lets a test push bytes back, so multiplexing can be verified
/// without a socket or a server.
private final class MuxLoopbackCarrier: NativeOutboundByteStream {
    private let lock = NSLock()
    private var written = Data()
    private var readable = Data()
    private var pending: ((Data?, Bool, Error?) -> Void)?
    private var cancelled = false

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock(); written.append(data); lock.unlock()
        completion(nil)
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock()
        if !readable.isEmpty {
            let chunk = readable.prefix(max(1, maximum))
            readable.removeFirst(chunk.count)
            lock.unlock()
            completion(Data(chunk), false, nil)
            return
        }
        if cancelled { lock.unlock(); completion(nil, true, nil); return }
        pending = completion
        lock.unlock()
    }

    func cancel() {
        lock.lock(); cancelled = true; let waiter = pending; pending = nil; lock.unlock()
        waiter?(nil, true, nil)
    }

    func takeWritten() -> Data {
        lock.lock(); defer { written = Data(); lock.unlock() }
        return written
    }

    /// Delivers server-to-client bytes.
    func inject(_ data: Data) {
        lock.lock()
        if let waiter = pending {
            pending = nil
            lock.unlock()
            waiter(data, false, nil)
            return
        }
        readable.append(data)
        lock.unlock()
    }
}

public enum MuxSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "Mux 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try codecRoundTrip()
        try codecRejectsMalformedInput()
        try codecHandlesPartialBuffers()
        try sessionMultiplexes()
        try applicabilityRefusals()
        try carrierRequestHeaders()
        try opensOnReadFirst()
    }

    /// Regression test: a destination whose server speaks first (SMTP, IMAP,
    /// SSH, MySQL) is read before it is written to. The open frame used to be
    /// emitted only from `send`, so the peer never learned the stream existed
    /// and both ends waited on each other.
    private static func opensOnReadFirst() throws {
        let carrier = MuxLoopbackCarrier()
        let session = MuxSession(carrier: carrier, concurrency: 4, label: "readfirst")
        let target = RequestTarget(host: "mail.example", port: 25, protocolName: "TCP")
        guard let stream = session.openStream(target: target,
                                              callbackQueue: DispatchQueue(label: "rf")) else {
            throw Failure(text: "无法开流")
        }
        // Read without ever writing.
        stream.receive(maximum: 4096) { _, _, _ in }
        // Give the session queue a moment to serialize the frame.
        let settle = DispatchSemaphore(value: 0)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { settle.signal() }
        _ = settle.wait(timeout: .now() + 2)

        var written = carrier.takeWritten()
        guard let frame = try MuxCodec.decode(from: &written) else {
            throw Failure(text: "只读取不写入时没有发出任何帧 —— 服务端先发协议会死锁")
        }
        try expect(frame.status == .new, "首帧应为 new，实际 \(frame.status)")
        try expect(frame.target?.host == "mail.example", "new 帧目标错误")
        try expect(frame.payload.isEmpty, "空开流帧不应携带载荷")
        session.shutdown(nil)
    }

    /// Pins the one detail that fails silently when wrong: VMess and VLESS omit
    /// the address and port when the command is Mux. A placeholder address
    /// there desyncs the server's parser (and VMess's FNV1a checksum), and the
    /// symptom is a connection that handshakes and then stalls.
    private static func carrierRequestHeaders() throws {
        let uuid = UUID(uuidString: "b831381d-6324-4d53-ad4f-8cda48b30811")!
        let carrier = MuxApplicability.carrierTarget
        let real = RequestTarget(host: "example.com", port: 443, protocolName: "TCP")

        try expect(MuxApplicability.isCarrierTarget(carrier), "载体目标未被识别")
        try expect(!MuxApplicability.isCarrierTarget(real), "普通目标被误判为载体")

        // VLESS: version(1) + uuid(16) + addons length(1) + command(1) = 19 bytes,
        // and nothing more.
        let muxHeader = try vlessRequestHeader(uuid: uuid, target: carrier, command: .mux)
        try expect(muxHeader.count == 19,
                   "VLESS mux 请求头应为 19 字节，实际 \(muxHeader.count)")
        try expect(muxHeader.last == 0x03, "VLESS mux 命令字节应为 0x03")
        let tcpHeader = try vlessRequestHeader(uuid: uuid, target: real, command: .tcp)
        try expect(tcpHeader.count > muxHeader.count,
                   "VLESS 普通请求头应携带地址与端口")
        try expect(tcpHeader[18] == 0x01, "VLESS TCP 命令字节应为 0x01")

        // VMess: the mux block must be shorter than the TCP block by exactly
        // the address and port it omits, with padding held constant.
        let iv = Data(repeating: 0xa1, count: 16)
        let key = Data(repeating: 0xb2, count: 16)
        let muxBlock = try vmessCommandBlock(requestBodyIV: iv, requestBodyKey: key,
                                             responseVerification: 0x5a, paddingLength: 0,
                                             target: carrier, command: .mux)
        let tcpBlock = try vmessCommandBlock(requestBodyIV: iv, requestBodyKey: key,
                                             responseVerification: 0x5a, paddingLength: 0,
                                             target: real, command: .tcp)
        try expect(muxBlock.count == 42,
                   "VMess mux 命令块应为 42 字节，实际 \(muxBlock.count)")
        // 1 version + 16 iv + 16 key + 1 verify + 1 option + 1 security
        // + 1 reserved = 37, so the command byte lands at index 37.
        try expect(muxBlock[37] == 0x03, "VMess mux 命令字节应为 0x03")
        try expect(tcpBlock[37] == 0x01, "VMess TCP 命令字节应为 0x01")
        // 2 port + 1 address type + 1 length + 11 for "example.com"
        try expect(tcpBlock.count == muxBlock.count + 15,
                   "VMess 普通命令块长度差应为地址与端口的 15 字节，实际差 \(tcpBlock.count - muxBlock.count)")
    }

    // MARK: Codec

    private static func codecRoundTrip() throws {
        let cases: [MuxFrame] = [
            MuxFrame(id: 1, status: .new, network: .tcp,
                     target: RequestTarget(host: "example.com", port: 443, protocolName: "TCP"),
                     payload: Data("hello".utf8)),
            MuxFrame(id: 2, status: .new, network: .tcp,
                     target: RequestTarget(host: "192.0.2.10", port: 80, protocolName: "TCP")),
            MuxFrame(id: 3, status: .new, network: .udp,
                     target: RequestTarget(host: "2001:db8::1", port: 53, protocolName: "UDP"),
                     payload: Data([0x00, 0xff])),
            MuxFrame(id: 4, status: .keep, network: .tcp, payload: Data(repeating: 0x41, count: 1000)),
            MuxFrame(id: 5, status: .end),
            MuxFrame(id: 0, status: .keepAlive),
        ]
        for original in cases {
            var buffer = try MuxCodec.encode(original)
            let expectedBytes = buffer.count
            guard let decoded = try MuxCodec.decode(from: &buffer) else {
                throw Failure(text: "\(original.status) 帧无法解码")
            }
            try expect(buffer.isEmpty, "\(original.status) 帧解码后残留 \(buffer.count) 字节")
            try expect(decoded.id == original.id, "流 ID 不一致：\(decoded.id) != \(original.id)")
            try expect(decoded.status == original.status, "状态不一致")
            try expect(decoded.payload == original.payload, "载荷不一致")
            if let target = original.target {
                guard let round = decoded.target else { throw Failure(text: "目标地址丢失") }
                try expect(round.host == target.host,
                           "目标主机不一致：\(round.host) != \(target.host)")
                try expect(round.port == target.port, "目标端口不一致")
                try expect(decoded.network == original.network, "网络类型不一致")
            }
            try expect(expectedBytes > 0, "编码结果为空")
        }
    }

    /// The decoder reads attacker-controlled bytes, so every truncated or
    /// self-inconsistent frame must be rejected rather than over-read.
    private static func codecRejectsMalformedInput() throws {
        // Metadata length below the 4-byte minimum.
        var tooShort = Data([0x00, 0x02, 0x00, 0x01])
        try expectThrows(&tooShort, "元数据长度过小未被拒绝")
        // Metadata claims a domain longer than the metadata section.
        var overrun = Data([0x00, 0x09,
                            0x00, 0x01, 0x01, 0x00,
                            0x01, 0x01, 0xbb, 0x02, 0xff])
        try expectThrows(&overrun, "越界域名长度未被拒绝")
        // Unknown status byte.
        var badStatus = Data([0x00, 0x04, 0x00, 0x01, 0x7f, 0x00])
        try expectThrows(&badStatus, "未知状态未被拒绝")
        // Unknown address type.
        var badAddress = Data([0x00, 0x09,
                               0x00, 0x01, 0x01, 0x00,
                               0x01, 0x01, 0xbb, 0x7f, 0x00])
        try expectThrows(&badAddress, "未知地址类型未被拒绝")
    }

    private static func expectThrows(_ buffer: inout Data, _ message: String) throws {
        do {
            _ = try MuxCodec.decode(from: &buffer)
            throw Failure(text: message)
        } catch is MuxCodecError {
            return
        }
    }

    /// A partially received frame must leave the buffer untouched so the
    /// session can retry once the rest arrives.
    private static func codecHandlesPartialBuffers() throws {
        let frame = MuxFrame(id: 7, status: .new, network: .tcp,
                             target: RequestTarget(host: "example.org", port: 8443,
                                                   protocolName: "TCP"),
                             payload: Data("partial".utf8))
        let encoded = try MuxCodec.encode(frame)
        for prefixLength in 1..<encoded.count {
            var partial = encoded.prefix(prefixLength)
            let snapshot = partial
            let decoded = try MuxCodec.decode(from: &partial)
            try expect(decoded == nil, "在 \(prefixLength)/\(encoded.count) 字节时错误地解出了帧")
            try expect(partial == snapshot, "不完整帧解析后缓冲区被破坏")
        }
        var whole = encoded
        try expect(try MuxCodec.decode(from: &whole) != nil, "完整帧未能解码")

        // Two frames concatenated must decode one at a time.
        var pair = try MuxCodec.encode(MuxFrame(id: 1, status: .keep, payload: Data("a".utf8)))
        pair.append(try MuxCodec.encode(MuxFrame(id: 2, status: .keep, payload: Data("b".utf8))))
        let first = try MuxCodec.decode(from: &pair)
        let second = try MuxCodec.decode(from: &pair)
        try expect(first?.id == 1 && second?.id == 2, "连续帧未按顺序解码")
        try expect(pair.isEmpty, "连续帧解码后有残留")
    }

    // MARK: Session

    /// Drives three logical streams over one carrier and checks that each one
    /// sees only its own bytes, including when the server interleaves them out
    /// of order.
    private static func sessionMultiplexes() throws {
        let carrier = MuxLoopbackCarrier()
        let session = MuxSession(carrier: carrier, concurrency: 4, label: "selftest")
        let callbackQueue = DispatchQueue(label: "app.hajimi.mux.selftest.callbacks")

        let targets = [
            RequestTarget(host: "alpha.example", port: 443, protocolName: "TCP"),
            RequestTarget(host: "beta.example", port: 80, protocolName: "TCP"),
            RequestTarget(host: "gamma.example", port: 8080, protocolName: "TCP"),
        ]
        var streams: [MuxLogicalStream] = []
        for target in targets {
            guard let stream = session.openStream(target: target, callbackQueue: callbackQueue) else {
                throw Failure(text: "无法在会话上开流")
            }
            streams.append(stream)
        }
        try expect(session.activeStreamCount == 3, "活动流数量错误")
        try expect(!session.hasCapacity == false, "并发上限计算错误")

        // Each stream's first write must produce a `new` frame naming its own
        // destination — that is the property that proves demultiplexing is
        // keyed correctly.
        for (index, stream) in streams.enumerated() {
            let semaphore = DispatchSemaphore(value: 0)
            var sendError: Error?
            stream.send(Data("req-\(index)".utf8)) { sendError = $0; semaphore.signal() }
            guard semaphore.wait(timeout: .now() + 5) == .success else {
                throw Failure(text: "第 \(index) 流写入超时")
            }
            if let sendError { throw Failure(text: "第 \(index) 流写入失败：\(sendError)") }
        }

        var written = carrier.takeWritten()
        var openFrames: [MuxFrame] = []
        while let frame = try MuxCodec.decode(from: &written) { openFrames.append(frame) }
        try expect(openFrames.count == 3, "期望 3 个 new 帧，实际 \(openFrames.count)")
        for (index, frame) in openFrames.enumerated() {
            try expect(frame.status == .new, "第 \(index) 帧不是 new")
            try expect(frame.target?.host == targets[index].host,
                       "第 \(index) 帧目标错误：\(frame.target?.host ?? "nil")")
            try expect(frame.payload == Data("req-\(index)".utf8), "第 \(index) 帧载荷错误")
        }
        let ids = openFrames.map(\.id)
        try expect(Set(ids).count == 3, "流 ID 发生碰撞")

        // Park a read on every stream, then answer them in reverse order.
        var received = [Int: Data]()
        let receivedLock = NSLock()
        let group = DispatchGroup()
        for (index, stream) in streams.enumerated() {
            group.enter()
            stream.receive(maximum: 4096) { data, _, error in
                if let error { print("mux selftest receive error: \(error)") }
                receivedLock.lock(); received[index] = data ?? Data(); receivedLock.unlock()
                group.leave()
            }
        }
        var serverToClient = Data()
        for index in stride(from: ids.count - 1, through: 0, by: -1) {
            serverToClient.append(try MuxCodec.encode(
                MuxFrame(id: ids[index], status: .keep,
                         payload: Data("resp-\(index)".utf8))))
        }
        carrier.inject(serverToClient)
        guard group.wait(timeout: .now() + 5) == .success else {
            throw Failure(text: "逻辑流读取超时")
        }
        for index in 0..<streams.count {
            receivedLock.lock(); let value = received[index]; receivedLock.unlock()
            try expect(value == Data("resp-\(index)".utf8),
                       "第 \(index) 流收到了错误的数据：\(String(data: value ?? Data(), encoding: .utf8) ?? "nil")")
        }

        // An `end` for one stream must close exactly that stream.
        let closing = DispatchSemaphore(value: 0)
        var closedComplete = false
        streams[0].receive(maximum: 4096) { _, isComplete, _ in
            closedComplete = isComplete; closing.signal()
        }
        carrier.inject(try MuxCodec.encode(MuxFrame(id: ids[0], status: .end)))
        guard closing.wait(timeout: .now() + 5) == .success else {
            throw Failure(text: "end 帧未唤醒等待中的读取")
        }
        try expect(closedComplete, "end 帧未将读取标记为完成")
        try expect(session.activeStreamCount == 2, "end 帧后活动流数量错误")

        // The surviving streams must be untouched by their sibling's closure.
        let survivor = DispatchSemaphore(value: 0)
        var survivorData: Data?
        streams[2].receive(maximum: 4096) { data, _, _ in survivorData = data; survivor.signal() }
        carrier.inject(try MuxCodec.encode(
            MuxFrame(id: ids[2], status: .keep, payload: Data("still-alive".utf8))))
        guard survivor.wait(timeout: .now() + 5) == .success else {
            throw Failure(text: "兄弟流在同伴关闭后无法继续读取")
        }
        try expect(survivorData == Data("still-alive".utf8), "兄弟流数据错误")

        session.shutdown(nil)
        try expect(session.isClosed, "会话未关闭")
    }

    // MARK: Applicability

    private static func applicabilityRefusals() throws {
        func policy(_ type: String, _ parameters: [String: String] = [:]) -> ProxyPolicy {
            var value = ProxyPolicy(name: "probe", kind: .native)
            value.adapterType = type
            value.host = "example.com"
            value.port = 443
            value.parameters = parameters
            return value
        }
        // Stacking mux on transports that already multiplex must be refused.
        for type in ["hysteria2", "tuic", "anytls", "ssh", "snell", "ssr"] {
            try expect(MuxApplicability.rejectionReason(for: policy(type)) != nil,
                       "\(type) 未被拒绝叠加 Mux")
            try expect(!MuxApplicability.isEnabled(for: policy(type, ["mux": "true"])),
                       "\(type) 在显式开启时未被拒绝")
        }
        // VMess/VLESS signal mux with request command 0x03 and are drivable.
        for type in ["vmess", "vless"] {
            try expect(MuxApplicability.rejectionReason(for: policy(type)) == nil,
                       "\(type) 应支持 Mux.Cool")
            try expect(MuxApplicability.isEnabled(for: policy(type, ["mux": "true"])),
                       "\(type) 显式开启 Mux 未生效")
        }
        // Trojan is drivable, but only when opted in.
        try expect(MuxApplicability.rejectionReason(for: policy("trojan")) == nil,
                   "Trojan 应支持 Mux.Cool")
        try expect(!MuxApplicability.isEnabled(for: policy("trojan")),
                   "Mux 必须默认关闭")
        try expect(MuxApplicability.isEnabled(for: policy("trojan", ["mux": "true"])),
                   "Trojan 显式开启 Mux 未生效")
        // Combinations Xray rejects server-side must not be dialled at all.
        try expect(!MuxApplicability.isEnabled(for: policy("trojan", ["mux": "true",
                                                                     "flow": "xtls-rprx-vision"])),
                   "Vision 流控未被拒绝")
        try expect(!MuxApplicability.isEnabled(for: policy("trojan", ["mux": "true",
                                                                     "network": "xhttp"])),
                   "XHTTP 承载未被拒绝")
        try expect(MuxApplicability.concurrency(for: policy("trojan", ["mux-concurrency": "0"])) == 1,
                   "并发下限未被钳制")
        try expect(MuxApplicability.concurrency(for: policy("trojan", ["mux-concurrency": "9999"])) == 128,
                   "并发上限未被钳制")
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }
        return try body()
    }
}

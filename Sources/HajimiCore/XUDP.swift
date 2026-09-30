import Foundation
import Network

/// Xray XUDP packet stream carried directly inside a protocol-level Mux connection.
enum XUDPCodec {
    struct Packet: Equatable {
        let target: RequestTarget
        let payload: Data
    }

    static func encode(target: RequestTarget, payload: Data, first: Bool,
                       globalID: Data) throws -> Data {
        guard payload.count <= Int(UInt16.max) else {
            throw MuxCodecError.payloadTooLarge(payload.count)
        }
        guard globalID.count == 8, globalID.contains(where: { $0 != 0 }) else {
            throw MuxCodecError.malformed("XUDP Global ID 必须为非零 8 字节")
        }
        // The first pair is the outer metadata length. The second pair is the
        // XUDP/Mux session ID, fixed to zero for Xray-compatible XUDP.
        var metadata = Data([0, 0, 0, 0,
                             first ? MuxStatus.new.rawValue : MuxStatus.keep.rawValue,
                             1, MuxNetwork.udp.rawValue])
        append16(target.port, to: &metadata)
        try appendAddress(target.host, to: &metadata)
        if first { metadata.append(globalID) }
        let length = metadata.count - 2
        metadata[0] = UInt8(length >> 8)
        metadata[1] = UInt8(length & 0xff)
        append16(UInt16(payload.count), to: &metadata)
        metadata.append(payload)
        return metadata
    }

    static func decode(from buffer: inout Data) throws -> Packet? {
        guard let frame = try MuxCodec.decode(from: &buffer) else { return nil }
        switch frame.status {
        case .new, .keep:
            guard frame.network == .udp, let target = frame.target else {
                throw MuxCodecError.malformed("XUDP 数据帧缺少 UDP 目标")
            }
            return Packet(target: target, payload: frame.payload)
        case .end, .keepAlive:
            return nil
        }
    }

    private static func append16(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
    }

    private static func appendAddress(_ host: String, to data: inout Data) throws {
        if let value = IPv4Address(host) {
            data.append(MuxAddressType.ipv4.rawValue)
            data.append(contentsOf: value.rawValue)
        } else if let value = IPv6Address(String(host.split(separator: "%").first ?? "")) {
            data.append(MuxAddressType.ipv6.rawValue)
            data.append(contentsOf: value.rawValue)
        } else {
            let bytes = Data(host.utf8)
            guard !bytes.isEmpty, bytes.count <= 255 else {
                throw MuxCodecError.addressTooLong(host)
            }
            data.append(MuxAddressType.domain.rawValue)
            data.append(UInt8(bytes.count))
            data.append(bytes)
        }
    }
}

final class XUDPDatagramSession: NativeOutboundDatagramSession {
    typealias Dialer = (@escaping (Result<any NativeOutboundByteStream, Error>) -> Void) -> Void

    private let queue: DispatchQueue
    private let dial: Dialer
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private let globalID: Data
    private var carrier: (any NativeOutboundByteStream)?
    private var pending: [(Data, RequestTarget)] = []
    private var writing = false
    private var firstPacket = true
    private var receiveBuffer = Data()
    private var dialling = false
    private var cancelled = false
    private var failed = false

    init(queue: DispatchQueue, dial: @escaping Dialer,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) {
        self.queue = queue
        self.dial = dial
        receiveHandler = receive
        failureHandler = failure
        var id = secureRandom(count: 8)
        if !id.contains(where: { $0 != 0 }) { id[7] = 1 }
        globalID = id
    }

    func send(_ payload: Data, to target: RequestTarget) {
        queue.async {
            guard !self.cancelled, !self.failed else { return }
            guard payload.count <= Int(UInt16.max) else {
                self.fail(MuxCodecError.payloadTooLarge(payload.count))
                return
            }
            self.pending.append((payload, target))
            self.ensureCarrier()
            self.flush()
        }
    }

    func cancel() {
        queue.async {
            guard !self.cancelled else { return }
            self.cancelled = true
            self.pending.removeAll()
            self.carrier?.cancel()
            self.carrier = nil
        }
    }

    private func ensureCarrier() {
        guard carrier == nil, !dialling, !cancelled, !failed else { return }
        dialling = true
        dial { [weak self] result in
            guard let self else { return }
            self.queue.async {
                self.dialling = false
                guard !self.cancelled, !self.failed else {
                    if case .success(let stream) = result { stream.cancel() }
                    return
                }
                switch result {
                case .failure(let error): self.fail(error)
                case .success(let stream):
                    self.carrier = stream
                    self.pump()
                    self.flush()
                }
            }
        }
    }

    private func flush() {
        guard !writing, let carrier, !pending.isEmpty, !cancelled, !failed else { return }
        let item = pending.removeFirst()
        let wire: Data
        do {
            wire = try XUDPCodec.encode(target: item.1, payload: item.0,
                                        first: firstPacket, globalID: globalID)
            firstPacket = false
        } catch { fail(error); return }
        writing = true
        carrier.send(wire) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.writing = false
                if let error { self.fail(error) } else { self.flush() }
            }
        }
    }

    private func pump() {
        guard let carrier, !cancelled, !failed else { return }
        carrier.receive(maximum: 65_535) { [weak self] data, complete, error in
            guard let self else { return }
            self.queue.async {
                if let error { self.fail(error); return }
                if let data, !data.isEmpty {
                    self.receiveBuffer.append(data)
                    do {
                        while true {
                            let before = self.receiveBuffer.count
                            guard let packet = try XUDPCodec.decode(from: &self.receiveBuffer) else {
                                if self.receiveBuffer.count < before { continue }
                                break
                            }
                            self.receiveHandler(packet.target, packet.payload)
                        }
                    } catch { self.fail(error); return }
                }
                if complete {
                    self.fail(NativeOutboundError.connection("XUDP 载体已关闭"))
                } else {
                    self.pump()
                }
            }
        }
    }

    private func fail(_ error: Error) {
        guard !failed, !cancelled else { return }
        failed = true
        pending.removeAll()
        carrier?.cancel()
        carrier = nil
        failureHandler(error)
    }
}

public enum XUDPSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "XUDP 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        let id = Data([1, 2, 3, 4, 5, 6, 7, 8])
        let firstTarget = RequestTarget(host: "example.com", port: 53, protocolName: "UDP")
        let nextTarget = RequestTarget(host: "2001:db8::1", port: 443, protocolName: "UDP")
        var first = try XUDPCodec.encode(target: firstTarget, payload: Data("dns".utf8),
                                         first: true, globalID: id)
        try expect(first[2] == 0 && first[3] == 0, "XUDP session ID 不是 0")
        try expect(first[4] == MuxStatus.new.rawValue, "首包不是 new")
        try expect(first[6] == MuxNetwork.udp.rawValue, "首包网络类型不是 UDP")
        let metaLength = Int(first[0]) << 8 | Int(first[1])
        try expect(Data(first[2 + metaLength - 8..<2 + metaLength]) == id,
                   "首包 Global ID 位置错误")
        let decodedFirst = try XUDPCodec.decode(from: &first)
        try expect(decodedFirst?.target.host == firstTarget.host &&
                   decodedFirst?.payload == Data("dns".utf8), "首包往返失败")
        try expect(first.isEmpty, "首包解码后有残留")

        var next = try XUDPCodec.encode(target: nextTarget, payload: Data([0, 255]),
                                        first: false, globalID: id)
        try expect(next[4] == MuxStatus.keep.rawValue, "后续包不是 keep")
        let decodedNext = try XUDPCodec.decode(from: &next)
        try expect(decodedNext?.target.host == nextTarget.host &&
                   decodedNext?.target.port == nextTarget.port &&
                   decodedNext?.payload == Data([0, 255]), "后续包往返失败")
        try expect(next.isEmpty, "后续包解码后有残留")

        do {
            _ = try XUDPCodec.encode(target: firstTarget, payload: Data([1]),
                                     first: true, globalID: Data(repeating: 0, count: 8))
            throw Failure(text: "全零 Global ID 未被拒绝")
        } catch is MuxCodecError {}
    }
}

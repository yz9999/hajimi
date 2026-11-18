import Foundation
import Darwin
import HajimiCore
import HajimiFlowCXX
import HajimiDataPlaneC


final class UDPFlow {
    let id = UUID()
    var unreportedUploadBytes: Int = 0
    var unreportedDownloadBytes: Int = 0
    let key: FlowKey
    let routingGeneration: UInt64
    let upstreamQueue: DispatchQueue
    private weak var owner: NativeTunnel?
    private var session: NativeRoutedDatagram?
    private var pending: [Data] = []
    private var pendingBytes = 0
    private var ready = false
    private var closed = false
    private var lastActivity = Date()

    var lastActivityDate: Date { lastActivity }

    init(key: FlowKey, routingGeneration: UInt64 = 0, owner: NativeTunnel) {
        self.key = key
        self.routingGeneration = routingGeneration
        self.owner = owner
        self.upstreamQueue = owner.upstreamQueue(for: key)
    }

    func start() { owner?.connectUDPFlow(self) }

    func send(_ payload: Data) {
        guard !closed else { return }
        lastActivity = Date()
        guard ready else {
            if pending.count < 128 && pendingBytes + payload.count <= 512 * 1024 {
                pending.append(payload); pendingBytes += payload.count
            }
            return
        }
        sendNow(payload)
    }

    func connected(_ result: Result<NativeRoutedDatagram, Error>) {
        guard !closed else {
            if case .success(let session) = result { session.cancel() }
            return
        }
        switch result {
        case .failure: close()
        case .success(let session):
            self.session = session
            ready = true
            let buffered = pending
            pending.removeAll(keepingCapacity: false); pendingBytes = 0
            for payload in buffered { sendNow(payload) }
        }
    }

    func tick(now: Date) {
        if now.timeIntervalSince(lastActivity) > 90 { close() }
    }

    func close(removeFromOwner: Bool = true) {
        guard !closed else { return }
        closed = true
        session?.cancel(); session = nil
        let remUp = unreportedUploadBytes
        let remDown = unreportedDownloadBytes
        unreportedUploadBytes = 0
        unreportedDownloadBytes = 0
        owner?.recordFlowClosed(id: id, remainingUp: remUp, remainingDown: remDown)
        if removeFromOwner { owner?.removeUDP(self) }
    }

    private func sendNow(_ payload: Data) {
        session?.send(payload)
    }

    func received(_ payload: Data) {
        guard !closed else { return }
        lastActivity = Date()
        unreportedDownloadBytes &+= payload.count
        owner?.writeUDP(key: key, remoteAddress: key.remoteAddress,
                        remotePort: key.remotePort, payload: payload)
    }
}

/* Legacy local SOCKS bridge removed. NativeTunnel now connects through
   NativePacketRouter directly; no loopback proxy listener participates in
   enhanced-mode traffic. */
/*enum SOCKSLocalConnector {
    static func connectTCP(port: UInt16, destination: IPAddress,
                           destinationPort: UInt16) throws -> Int32 {
        let descriptor = try connectLoopback(port: port, socketType: SOCK_STREAM)
        do {
            try negotiate(descriptor)
            var request = Data([5, 1, 0])
            request.append(destination.socksAddress)
            append16(destinationPort, to: &request)
            try writeAll(descriptor, request)
            _ = try readReply(descriptor)
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    static func associateUDP(port: UInt16) throws -> SOCKSUDPDescriptors {
        let control = try connectLoopback(port: port, socketType: SOCK_STREAM)
        do {
            try negotiate(control)
            try writeAll(control, Data([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]))
            let relay = try readReply(control)
            guard relay.port > 0 else { throw NativeTunnelError.socks("UDP Relay 端口无效") }
            let datagram = try connectUDP(address: relay.address, port: relay.port)
            return SOCKSUDPDescriptors(controlDescriptor: control, datagramDescriptor: datagram)
        } catch {
            Darwin.close(control)
            throw error
        }
    }

    private static func negotiate(_ descriptor: Int32) throws {
        try writeAll(descriptor, Data([5, 1, 0]))
        let response = try readExactly(descriptor, count: 2)
        guard response == Data([5, 0]) else { throw NativeTunnelError.socks("本地握手被拒绝") }
    }

    private static func readReply(_ descriptor: Int32) throws -> (address: IPAddress, port: UInt16) {
        let head = [UInt8](try readExactly(descriptor, count: 4))
        guard head.count == 4, head[0] == 5, head[1] == 0 else {
            throw NativeTunnelError.socks("本地代理拒绝请求（代码 \(head.count > 1 ? head[1] : 255)）")
        }
        let address: IPAddress
        switch head[3] {
        case 1: address = .v4([UInt8](try readExactly(descriptor, count: 4)))
        case 4: address = .v6([UInt8](try readExactly(descriptor, count: 16)))
        case 3:
            let length = Int(try readExactly(descriptor, count: 1).first!)
            let domain = String(data: try readExactly(descriptor, count: length), encoding: .utf8) ?? ""
            address = try resolveAddress(domain)
        default: throw NativeTunnelError.socks("SOCKS5 返回未知地址类型")
        }
        let portData = [UInt8](try readExactly(descriptor, count: 2))
        return (normalizedRelayAddress(address), read16(portData, 0))
    }

    private static func normalizedRelayAddress(_ address: IPAddress) -> IPAddress {
        switch address {
        case .v4(let bytes) where bytes == [0, 0, 0, 0]: return .v4([127, 0, 0, 1])
        case .v6(let bytes) where bytes.allSatisfy({ $0 == 0 }): return .v4([127, 0, 0, 1])
        default: return address
        }
    }

    private static func connectLoopback(port: UInt16, socketType: Int32) throws -> Int32 {
        let descriptor = socket(AF_INET, socketType, 0)
        guard descriptor >= 0 else { throw NativeTunnelError.socks(String(cString: strerror(errno))) }
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            let message = String(cString: strerror(errno)); Darwin.close(descriptor)
            throw NativeTunnelError.socks("无法连接 127.0.0.1:\(port)：\(message)")
        }
        return descriptor
    }

    private static func connectUDP(address: IPAddress, port: UInt16) throws -> Int32 {
        switch address {
        case .v4(let bytes):
            let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
            guard descriptor >= 0 else { throw NativeTunnelError.socks(String(cString: strerror(errno))) }
            var target = sockaddr_in()
            target.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            target.sin_family = sa_family_t(AF_INET)
            target.sin_port = port.bigEndian
            let raw = read32(bytes, 0)
            target.sin_addr = in_addr(s_addr: raw.bigEndian)
            let result = withUnsafePointer(to: &target) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard result == 0 else { let e = errno; Darwin.close(descriptor); throw NativeTunnelError.socks(String(cString: strerror(e))) }
            return descriptor
        case .v6(let bytes):
            let descriptor = socket(AF_INET6, SOCK_DGRAM, 0)
            guard descriptor >= 0 else { throw NativeTunnelError.socks(String(cString: strerror(errno))) }
            var target = sockaddr_in6()
            target.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            target.sin6_family = sa_family_t(AF_INET6)
            target.sin6_port = port.bigEndian
            withUnsafeMutableBytes(of: &target.sin6_addr) { $0.copyBytes(from: bytes) }
            let result = withUnsafePointer(to: &target) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
            guard result == 0 else { let e = errno; Darwin.close(descriptor); throw NativeTunnelError.socks(String(cString: strerror(e))) }
            return descriptor
        }
    }

    private static func resolveAddress(_ host: String) throws -> IPAddress {
        var hints = addrinfo(ai_flags: AI_NUMERICSERV, ai_family: AF_UNSPEC,
                             ai_socktype: SOCK_DGRAM, ai_protocol: IPPROTO_UDP,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "0", &hints, &result) == 0, let first = result else {
            throw NativeTunnelError.socks("无法解析 UDP Relay 地址")
        }
        defer { freeaddrinfo(result) }
        if first.pointee.ai_family == AF_INET {
            let value = first.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            return withUnsafeBytes(of: value.s_addr) { .v4(Array($0)) }
        }
        let value = first.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
        return withUnsafeBytes(of: value) { .v6(Array($0)) }
    }

    private static func writeAll(_ descriptor: Int32, _ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { raw -> Int in
                Darwin.send(descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset, 0)
            }
            guard count > 0 else { throw NativeTunnelError.socks(String(cString: strerror(errno))) }
            offset += count
        }
    }

    private static func readExactly(_ descriptor: Int32, count: Int) throws -> Data {
        var result = Data(count: count)
        var offset = 0
        while offset < count {
            let value = result.withUnsafeMutableBytes { raw -> Int in
                Darwin.recv(descriptor, raw.baseAddress!.advanced(by: offset), count - offset, 0)
            }
            guard value > 0 else { throw NativeTunnelError.socks(value == 0 ? "连接提前关闭" : String(cString: strerror(errno))) }
            offset += value
        }
        return result
    }
}*/

/*struct SOCKSUDPResponse {
    let address: IPAddress
    let port: UInt16
    let payload: Data
}*/

/*func parseSOCKSUDPResponse(_ bytes: [UInt8]) -> SOCKSUDPResponse? {
    guard bytes.count >= 10, bytes[0] == 0, bytes[1] == 0, bytes[2] == 0 else { return nil }
    var offset = 4
    let address: IPAddress
    switch bytes[3] {
    case 1:
        guard offset + 4 + 2 <= bytes.count else { return nil }
        address = .v4(Array(bytes[offset..<(offset + 4)])); offset += 4
    case 4:
        guard offset + 16 + 2 <= bytes.count else { return nil }
        address = .v6(Array(bytes[offset..<(offset + 16)])); offset += 16
    default: return nil
    }
    let port = read16(bytes, offset); offset += 2
    return SOCKSUDPResponse(address: address, port: port, payload: Data(bytes[offset...]))
}*/

enum PacketBuilder {
    static func tcp(version: IPVersion, source: IPAddress, sourcePort: UInt16,
                    destination: IPAddress, destinationPort: UInt16,
                    sequence: UInt32, acknowledgment: UInt32, flags: TCPFlags,
                    window: UInt16, payload: Data,
                    maximumSegmentSize: UInt16?, windowScale: UInt8?,
                    sackPermitted: Bool,
                    sackBlocks: [SACKBlock] = [],
                    identifier: UInt16) -> Data {
        var transport = Data()
        // Growing from empty through a dozen small appends meant every append
        // that crossed a malloc size class reallocated and copied the whole
        // segment -- on every packet, in the hottest loop in the process.
        transport.reserveCapacity(60 + payload.count)
        append16(sourcePort, to: &transport); append16(destinationPort, to: &transport)
        append32(sequence, to: &transport); append32(acknowledgment, to: &transport)
        var options: [UInt8] = []
        if let maximumSegmentSize {
            options.append(contentsOf: [2, 4, UInt8(maximumSegmentSize >> 8),
                                        UInt8(maximumSegmentSize & 0xff)])
        }
        if sackPermitted { options.append(contentsOf: [4, 2]) }
        if let windowScale {
            // NOP aligns the three-byte Window Scale option.  Only SYN
            // packets call this path.
            options.append(contentsOf: [1, 3, 3, min(windowScale, 14)])
        }
        if !sackBlocks.isEmpty {
            // The TCP header caps options at 40 bytes, and two NOPs align the
            // block list, so at most four blocks fit — which is also the most
            // RFC 2018 allows.
            let capacity = max(0, (40 - options.count - 4) / 8)
            let emitted = sackBlocks.prefix(min(4, capacity))
            if !emitted.isEmpty {
                options.reserveCapacity(options.count + 4 + emitted.count * 8)
                options.append(contentsOf: [1, 1, 5, UInt8(2 + emitted.count * 8)])
                for block in emitted {
                    options.append(UInt8(block.start >> 24))
                    options.append(UInt8((block.start >> 16) & 0xff))
                    options.append(UInt8((block.start >> 8) & 0xff))
                    options.append(UInt8(block.start & 0xff))
                    options.append(UInt8(block.end >> 24))
                    options.append(UInt8((block.end >> 16) & 0xff))
                    options.append(UInt8((block.end >> 8) & 0xff))
                    options.append(UInt8(block.end & 0xff))
                }
            }
        }
        while options.count % 4 != 0 { options.append(1) }
        transport.append(UInt8((20 + options.count) / 4) << 4)
        transport.append(flags.rawValue)
        append16(window, to: &transport)
        append16(0, to: &transport); append16(0, to: &transport)
        transport.append(contentsOf: options); transport.append(payload)
        let checksum = transportChecksum(version: version, source: source, destination: destination,
                                         nextHeader: 6, transport: transport)
        // Two stores instead of replaceSubrange: the old form built a throwaway
        // array and took the generic collection replacement path on every
        // packet, which showed up as allocation and release traffic.
        transport[16] = UInt8(checksum >> 8)
        transport[17] = UInt8(checksum & 0xff)
        // Segments produced here stay under the local MSS, so the length field
        // always fits. A nil result would mean the caller asked for an illegal size.
        return ipPacket(version: version, source: source, destination: destination,
                        nextHeader: 6, transport: transport, identifier: identifier)!
    }

    static func icmpPortUnreachable(original: ParsedIPPacket,
                                    identifier: UInt16) -> Data {
        var message: Data
        let nextHeader: UInt8
        switch original.version {
        case .v4:
            // Destination Unreachable / Port Unreachable.  The quoted IP
            // header and first eight transport bytes identify the socket.
            message = Data([3, 3, 0, 0, 0, 0, 0, 0])
            let quotedEnd = min(original.payloadEnd, original.transportOffset + 8)
            message.append(contentsOf: original.bytes[0..<quotedEnd])
            let checksum = internetChecksum(message)
            message.replaceSubrange(2..<4,
                                    with: [UInt8(checksum >> 8), UInt8(checksum & 0xff)])
            nextHeader = 1
        case .v6:
            // ICMPv6 Destination Unreachable / Port Unreachable.  Keep the
            // generated packet below the IPv6 minimum MTU while quoting as
            // much of the invoking packet as possible.
            message = Data([1, 4, 0, 0, 0, 0, 0, 0])
            message.append(contentsOf: original.bytes.prefix(min(original.payloadEnd, 1_232)))
            let checksum = transportChecksum(version: .v6,
                                              source: original.destination,
                                              destination: original.source,
                                              nextHeader: 58,
                                              transport: message)
            message.replaceSubrange(2..<4,
                                    with: [UInt8(checksum >> 8), UInt8(checksum & 0xff)])
            nextHeader = 58
        }
        return ipPacket(version: original.version,
                        source: original.destination, destination: original.source,
                        nextHeader: nextHeader, transport: message,
                        identifier: identifier)!
    }

    /// Wraps an already-formed ICMP echo reply in an IPv4 header.
    ///
    /// The checksum inside the ICMP message is left as the responder computed
    /// it: ICMP covers only its own bytes, so recomputing would be redundant
    /// and would mask a corrupted reply.
    static func icmpEchoReply(source: IPAddress, destination: IPAddress,
                              message: Data, identifier: UInt16) -> Data {
        ipPacket(version: .v4, source: source, destination: destination,
                 nextHeader: 1, transport: message, identifier: identifier)!
    }

    /// Largest UDP payload that still fits the 16-bit length field (8-byte header + payload).
    static let maximumUDPPayloadLength = Int(UInt16.max) - 8

    /// Builds a UDP/IP packet, or `nil` when the payload cannot be framed without
    /// truncating a length field (which would trap on `UInt16(...)` and take down
    /// the root helper).
    static func udp(version: IPVersion, source: IPAddress, sourcePort: UInt16,
                    destination: IPAddress, destinationPort: UInt16,
                    payload: Data, identifier: UInt16) -> Data? {
        guard payload.count <= maximumUDPPayloadLength else { return nil }
        var transport = Data()
        transport.reserveCapacity(8 + payload.count)
        append16(sourcePort, to: &transport); append16(destinationPort, to: &transport)
        append16(UInt16(8 + payload.count), to: &transport); append16(0, to: &transport)
        transport.append(payload)
        var checksum = transportChecksum(version: version, source: source, destination: destination,
                                          nextHeader: 17, transport: transport)
        if checksum == 0 { checksum = 0xffff }
        transport[6] = UInt8(checksum >> 8)
        transport[7] = UInt8(checksum & 0xff)
        return ipPacket(version: version, source: source, destination: destination,
                        nextHeader: 17, transport: transport, identifier: identifier)
    }

    private static func ipPacket(version: IPVersion, source: IPAddress, destination: IPAddress,
                                 nextHeader: UInt8, transport: Data, identifier: UInt16) -> Data? {
        // IPv4 total-length and IPv6 payload-length are both 16-bit. Refuse
        // oversized transports instead of trapping inside UInt16(...).
        switch version {
        case .v4:
            let total = 20 + transport.count
            guard total <= Int(UInt16.max) else { return nil }
            var packet = Data([0x45, 0])
            packet.reserveCapacity(total)
            append16(UInt16(total), to: &packet)
            append16(identifier, to: &packet); append16(0x4000, to: &packet)
            packet.append(64); packet.append(nextHeader); append16(0, to: &packet)
            packet.append(contentsOf: source.bytes); packet.append(contentsOf: destination.bytes)
            let checksum = internetChecksum(packet)
            packet[10] = UInt8(checksum >> 8)
            packet[11] = UInt8(checksum & 0xff)
            packet.append(transport)
            return packet
        case .v6:
            guard transport.count <= Int(UInt16.max) else { return nil }
            var packet = Data([0x60, 0, 0, 0])
            packet.reserveCapacity(40 + transport.count)
            append16(UInt16(transport.count), to: &packet)
            packet.append(nextHeader); packet.append(64)
            packet.append(contentsOf: source.bytes); packet.append(contentsOf: destination.bytes)
            packet.append(transport)
            return packet
        }
    }

    private static func transportChecksum(version: IPVersion, source: IPAddress,
                                          destination: IPAddress, nextHeader: UInt8,
                                          transport: Data) -> UInt16 {
        // C sums the two addresses and the transport in place. Building a
        // temporary pseudo-header Data here used to copy both addresses on
        // every TCP/UDP segment.
        _ = version
        return CDataPlane.transportChecksum(sourceBytes: source.bytes,
                                            destinationBytes: destination.bytes,
                                            protocolNumber: nextHeader,
                                            transport: transport)
    }
}

func internetChecksum(_ data: Data) -> UInt16 {
    foldChecksum(checksumSum(data))
}

/// The unfolded one's-complement 16-bit sum of a region.
///
/// The arithmetic itself lives in C, where there is no bounds checking on
/// every byte and the compiler is free to vectorise the loop. Leaving the sum
/// unfolded is what lets callers combine several regions and fold once.
func checksumSum(_ data: Data) -> UInt64 {
    CDataPlane.checksumSum(data)
}

func foldChecksum(_ value: UInt64) -> UInt16 {
    CDataPlane.fold(value)
}

func read16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
    UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
}

func read16(_ bytes: UnsafePointer<UInt8>, _ offset: Int) -> UInt16 {
    UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
}

func read32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 |
        UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
}

func read32(_ bytes: UnsafePointer<UInt8>, _ offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 |
        UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
}

func append16(_ value: UInt16, to data: inout Data) {
    data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
}

func append32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8(value >> 24)); data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff)); data.append(UInt8(value & 0xff))
}

func sequenceGreaterOrEqual(_ lhs: UInt32, _ rhs: UInt32) -> Bool {
    hajimi_sequence_after_equal(lhs, rhs) != 0
}

func sequenceGreater(_ lhs: UInt32, _ rhs: UInt32) -> Bool {
    hajimi_sequence_after(lhs, rhs) != 0
}



/// Relays ICMP echo out of the physical interface and writes the reply back
/// into utun.
///
/// The tunnel captures every address through its split default routes, but the
/// data plane only terminates TCP and UDP — an echo request entering utun had
/// nowhere to go, so `ping` and `traceroute` failed for every destination and
/// every node while ordinary traffic worked. That is a poor diagnostic story:
/// the tools people reach for first are exactly the ones that stop working.
///
/// Echo is sent directly rather than through the proxy. No mainstream outbound
/// protocol carries ICMP, and answering locally would report reachability the
/// packet never tested. The cost is that a ping reveals the real egress address
/// while other traffic does not, which is why this is a deliberate choice
/// rather than a default.
final class ICMPEchoRelay {
    private struct PendingKey: Hashable {
        let identifier: UInt16
        let sequence: UInt16
    }

    private struct Pending {
        let clientAddress: IPAddress
        let remoteAddress: IPAddress
        let createdAt: Date
    }

    private let queue: DispatchQueue
    private weak var owner: NativeTunnel?
    private var descriptor: Int32 = -1
    private var boundInterfaceName: String?
    private var readSource: DispatchSourceRead?
    private var pending: [PendingKey: Pending] = [:]

    init(queue: DispatchQueue, owner: NativeTunnel) {
        self.queue = queue
        self.owner = owner
    }

    /// Opens the socket lazily: a session that never pings should not hold one.
    private func ensureSocket() -> Bool {
        let currentInterface = NativeTunnel.physicalInterfaceName
        if descriptor >= 0 {
            if boundInterfaceName == currentInterface { return true }
            if let source = readSource {
                readSource = nil
                descriptor = -1
                source.cancel()
            } else {
                Darwin.close(descriptor)
                descriptor = -1
            }
        }
        // SOCK_DGRAM/IPPROTO_ICMP sends echo without the raw-socket privileges,
        // and the kernel handles the outer IP header for us.
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return false }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        // The reply must not come back through the tunnel that produced the
        // request, or the relay would feed itself.
        if let name = currentInterface {
            var index = UInt32(if_nametoindex(name))
            if index > 0 {
                _ = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index,
                               socklen_t(MemoryLayout<UInt32>.size))
            }
        }
        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
        descriptor = fd
        boundInterfaceName = currentInterface
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.drainReplies() }
        source.setCancelHandler { Darwin.close(fd) }
        readSource = source
        source.resume()
        return true
    }

    func handle(_ packet: ParsedIPPacket) {
        // IPv4 echo request only. ICMPv6 carries neighbour discovery and path
        // MTU signalling that must not be forwarded blindly.
        guard packet.version == .v4, packet.transportProtocol == 1,
              packet.payloadEnd - packet.transportOffset >= 8 else { return }
        let type = packet.bytes[packet.transportOffset]
        guard type == 8 else { return }
        let identifier = read16(packet.bytes, packet.transportOffset + 4)
        let sequence = read16(packet.bytes, packet.transportOffset + 6)
        guard ensureSocket(), packet.destination.version == .v4 else { return }

        expireStale()
        pending[PendingKey(identifier: identifier, sequence: sequence)] =
            Pending(clientAddress: packet.source, remoteAddress: packet.destination,
                    createdAt: Date())

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        let remote = packet.destination.bytes
        address.sin_addr = in_addr(s_addr: remote.withUnsafeBufferPointer {
            $0.baseAddress!.withMemoryRebound(to: in_addr_t.self, capacity: 1) { $0.pointee }
        })
        let body = Array(packet.bytes[packet.transportOffset..<packet.payloadEnd])
        _ = body.withUnsafeBytes { raw in
            withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(descriptor, raw.baseAddress, raw.count, 0, $0,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    private func drainReplies() {
        var buffer = [UInt8](repeating: 0, count: 2048)
        while true {
            let count = buffer.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, 0) }
            guard count > 0 else { return }
            // A SOCK_DGRAM ICMP socket delivers the payload without the outer
            // IP header, but macOS includes it — handle both.
            var offset = 0
            if count >= 20, buffer[0] >> 4 == 4 {
                offset = Int(buffer[0] & 0x0F) * 4
            }
            guard count - offset >= 8 else { continue }
            let type = buffer[offset]
            guard type == 0 else { continue }        // echo reply
            let identifier = read16(buffer, offset + 4)
            let sequence = read16(buffer, offset + 6)
            let key = PendingKey(identifier: identifier, sequence: sequence)
            guard let entry = pending.removeValue(forKey: key) else { continue }
            let body = Array(buffer[offset..<count])
            owner?.writeICMPEchoReply(to: entry.clientAddress, from: entry.remoteAddress,
                                      body: body)
        }
    }

    private func expireStale() {
        guard pending.count > 256 else { return }
        let cutoff = Date().addingTimeInterval(-10)
        pending = pending.filter { $0.value.createdAt > cutoff }
    }

    func stop() {
        if let source = readSource {
            readSource = nil
            descriptor = -1
            source.cancel()
        } else if descriptor >= 0 {
            Darwin.close(descriptor)
            descriptor = -1
        }
        boundInterfaceName = nil
        pending.removeAll()
    }

    deinit {
        stop()
    }
}

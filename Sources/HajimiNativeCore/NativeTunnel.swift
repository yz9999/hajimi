import Foundation
import Darwin
import HajimiCore
import HajimiFlowCXX
import HajimiDataPlaneC

public struct NativeTunnelStatistics: Equatable {
    public let activeFlows: Int
    public let totalFlows: Int
    public let uploadedBytes: UInt64
    public let downloadedBytes: UInt64
}

public enum NativeTunnelError: LocalizedError {
    case permissionDenied
    case utun(String)
    case socks(String)
    case invalidPort

    public var errorDescription: String? {
        switch self {
        case .permissionDenied: return "创建 utun 需要 root Helper 权限"
        case .utun(let value): return "HajimiNativeCore utun 错误：\(value)"
        case .socks(let value): return "HajimiNativeCore SOCKS5 错误：\(value)"
        case .invalidPort: return "SOCKS5 监听端口无效"
        }
    }
}

/// First-party userspace data plane for Hajimi's enhanced mode.
///
/// The implementation terminates local TCP flows at the utun boundary and
/// routes their byte streams and datagrams directly through NativePacketRouter.
/// No local proxy listener or third-party packet engine participates.
public final class NativeTunnel {
    private let router: NativePacketRouter
    public private(set) var interfaceName: String?

    fileprivate static let queueSpecificKey = DispatchSpecificKey<Bool>()
    private let queue = DispatchQueue(label: "app.hajimi.native-tunnel", qos: .userInitiated,
                                      autoreleaseFrequency: .workItem)
    /// Shared outbound lanes. A private DispatchQueue per TCP/UDP flow used to
    /// create thousands of queues under a YouTube 4K burst and jetsam the App.
    fileprivate static let upstreamQueueCount = 8
    private static let sharedUpstreamQueues: [DispatchQueue] = (0..<upstreamQueueCount).map { index in
        DispatchQueue(label: "app.hajimi.native-tunnel.upstream.\(index)",
                      qos: .userInitiated, autoreleaseFrequency: .workItem)
    }
    private var descriptor: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var writeSource: DispatchSourceWrite?
    private lazy var icmpRelay = ICMPEchoRelay(queue: queue, owner: self)
    /// The physical interface outbound sockets are pinned to, so the ICMP relay
    /// can bind there too and not feed its own tunnel.
    public static var physicalInterfaceName: String?
    /// Set from any thread the instant a stop is requested.
    private let stopRequested = AtomicFlag()
    private var pendingFrames: [PendingFrame] = []
    private var pendingFrameHead = 0
    private var pendingFrameBytes = 0
    private var maintenanceTimer: DispatchSourceTimer?
    private var tcpFlows: [FlowKey: TCPFlow] = [:]
    private var udpFlows: [FlowKey: UDPFlow] = [:]
    private var ipv4Identifier: UInt16 = UInt16.random(in: 1...UInt16.max)
    /// Reused across read-source firings. Allocating and zeroing 64 KiB on
    /// every event was itself a measurable share of the data plane's cost.
    /// Only ever touched from `queue`, which is serial.
    private var readBuffer = [UInt8](repeating: 0, count: 65_540)
    /// Scratch for C-built download/UDP packets. Reused so the hot path
    /// does not allocate a Data per segment.
    private var buildBuffer = [UInt8](repeating: 0, count: 9_216)
    private var stopped = true
    private var totalFlowCount = 0
    private var uploadedByteCount: UInt64 = 0
    private var downloadedByteCount: UInt64 = 0

    public init(router: NativePacketRouter) throws {
        self.router = router
        queue.setSpecific(key: Self.queueSpecificKey, value: true)
    }

    deinit { stop() }

    /// Starts packet processing on a utun already opened by the privileged
    /// helper. Addresses and routes stay with the helper; this process only
    /// reads and writes packets.
    @discardableResult
    public func start(fileDescriptor: Int32, interfaceName: String) throws -> String {
        if self.interfaceName == interfaceName, descriptor >= 0 { return interfaceName }
        stop()
        stopRequested.value = false
        guard fileDescriptor >= 0 else { throw NativeTunnelError.utun("无效的 utun 描述符") }
        let flags = fcntl(fileDescriptor, F_GETFL, 0)
        if flags >= 0 { _ = fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK) }
        descriptor = fileDescriptor
        self.interfaceName = interfaceName
        stopped = false

        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self, !self.stopRequested.value else { return }
            self.drainPackets()
        }
        source.setCancelHandler {}
        readSource = source
        source.resume()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(250),
                       repeating: .milliseconds(250), leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in self?.performMaintenance() }
        maintenanceTimer = timer
        timer.resume()
        return interfaceName
    }

    /// Opens an automatically numbered utun in-process. Prefer
    /// `start(fileDescriptor:interfaceName:)` when a root helper supplies the
    /// tunnel; this path remains for self-tests that do not need routes.
    @discardableResult
    public func start() throws -> String {
        if let interfaceName, descriptor >= 0 { return interfaceName }
        let opened = try Self.openUTUN()
        return try start(fileDescriptor: opened.descriptor, interfaceName: opened.name)
    }

    public func stop() {
        // Set before the barrier: handlers already running on `queue` check
        // this and bail out, so a busy or misbehaving data plane cannot keep
        // stop() waiting for a queue it will never yield.
        stopRequested.value = true
        queue.sync {
            guard !stopped else { return }
            stopped = true
            maintenanceTimer?.cancel()
            maintenanceTimer = nil
            readSource?.cancel()
            readSource = nil
            icmpRelay.stop()
            writeSource?.cancel()
            writeSource = nil
            pendingFrames.removeAll(keepingCapacity: false)
            pendingFrameHead = 0
            pendingFrameBytes = 0
            let tcp = Array(tcpFlows.values)
            let udp = Array(udpFlows.values)
            tcpFlows.removeAll(keepingCapacity: false)
            udpFlows.removeAll(keepingCapacity: false)
            tcp.forEach { $0.close(sendReset: false, removeFromOwner: false) }
            udp.forEach { $0.close(removeFromOwner: false) }
            if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
            interfaceName = nil
        }
    }

    public func statistics() -> NativeTunnelStatistics {
        queue.sync {
            NativeTunnelStatistics(activeFlows: tcpFlows.count + udpFlows.count,
                                   totalFlows: totalFlowCount,
                                   uploadedBytes: uploadedByteCount,
                                   downloadedBytes: downloadedByteCount)
        }
    }

    /// Drops transport sessions after an atomic policy reload. The utun and
    /// routes remain active; applications reconnect immediately and the new
    /// flows are resolved against the new routing snapshot.
    public func resetFlows() {
        queue.sync {
            let tcp = Array(tcpFlows.values), udp = Array(udpFlows.values)
            tcpFlows.removeAll(keepingCapacity: true)
            udpFlows.removeAll(keepingCapacity: true)
            tcp.forEach { $0.close(sendReset: true, removeFromOwner: false) }
            udp.forEach { $0.close(removeFromOwner: false) }
        }
    }

    private func drainPackets() {
        guard descriptor >= 0, !stopped else { return }
        // A full-route utun can remain readable continuously. Bound each
        // dispatch-source turn so stop/configuration work is never starved by
        // an input flood after routes become active.
        var processed = 0
        readBuffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            while processed < 1_024 {
                let count = Darwin.read(descriptor, base, raw.count)
                if count > 0 { processed += 1 }
                if count > 4 {
                    handleIPPacket(UnsafeRawBufferPointer(start: base.advanced(by: 4),
                                                          count: count - 4))
                    continue
                }
                if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { break }
                if count <= 0 { break }
            }
        }
    }

    private func handleIPPacket(_ bytes: UnsafeRawBufferPointer) {
        guard let packet = ParsedIPPacket(bytes) else { return }
        switch packet.transportProtocol {
        case 6:
            guard let segment = ParsedTCPSegment(bytes: bytes, packet: packet) else { return }
            handleTCP(packet, segment: segment)
        case 17:
            guard let datagram = ParsedUDPDatagram(bytes: bytes, packet: packet) else { return }
            handleUDP(packet, datagram: datagram, originalBytes: bytes)
        case 1: icmpRelay.handle(packet)
        default: break
        }
    }

    private func handleTCP(_ packet: ParsedIPPacket, segment: ParsedTCPSegment) {
        let key = FlowKey(version: packet.version, transportProtocol: 6,
                          clientAddress: packet.source, clientPort: segment.sourcePort,
                          remoteAddress: packet.destination, remotePort: segment.destinationPort)
        if let flow = tcpFlows[key] {
            flow.handle(segment)
            return
        }
        guard segment.flags.contains(.syn), !segment.flags.contains(.ack) else { return }
        if tcpFlows.count >= FlowAdmission.maximumTCPFlows {
            if !evictIdleTCP() {
                _ = writeTCP(key: key, sequence: 0,
                             acknowledgment: segment.sequence &+ 1,
                             flags: [.rst, .ack])
                return
            }
        }
        totalFlowCount += 1
        let flow = TCPFlow(key: key, initial: segment, owner: self)
        tcpFlows[key] = flow
        flow.start()
    }

    private func handleUDP(_ packet: ParsedIPPacket, datagram: ParsedUDPDatagram,
                           originalBytes: UnsafeRawBufferPointer) {
        func rejectWithICMP() {
            guard let quoted = ParsedIPPacket(copying: originalBytes) else { return }
            writeICMPPortUnreachable(for: quoted)
        }
        // QUIC loses its loss-recovery advantage when a stream-only proxy
        // (VMess/VLESS/Trojan/Snell/AnyTLS) carries every UDP packet over a
        // reliable TCP byte stream.  One lost outer TCP segment then blocks
        // all later QUIC packets.  Tell the local stack that UDP/443 is
        // unavailable so browsers immediately retry the same origin over
        // HTTPS/TCP.  Native UDP transports (DIRECT, SS/SSR, HY/TUIC) keep
        // QUIC enabled.
        if datagram.destinationPort == 443,
           router.prefersTCPFallbackForQUIC(host: packet.destination.hostString) {
            rejectWithICMP()
            return
        }
        // The outbound cannot carry this datagram. Saying so costs one packet;
        // staying silent costs the application its full timeout on every
        // attempt, which is indistinguishable from a dead network.
        if router.rejectsUDP(host: packet.destination.hostString,
                             port: datagram.destinationPort) {
            rejectWithICMP()
            return
        }
        let key = FlowKey(version: packet.version, transportProtocol: 17,
                          clientAddress: packet.source, clientPort: datagram.sourcePort,
                          remoteAddress: packet.destination, remotePort: datagram.destinationPort)
        let flow: UDPFlow
        if let existing = udpFlows[key] {
            flow = existing
        } else {
            if udpFlows.count >= FlowAdmission.maximumUDPFlows {
                if !evictIdleUDP() {
                    rejectWithICMP()
                    return
                }
            }
            totalFlowCount += 1
            flow = UDPFlow(key: key, owner: self)
            udpFlows[key] = flow
            flow.start()
        }
        flow.send(datagram.payload)
        uploadedByteCount &+= UInt64(datagram.payload.count)
    }

    fileprivate func connectTCPFlow(_ flow: TCPFlow) {
        router.connectTCP(host: flow.key.remoteAddress.hostString,
                          port: flow.key.remotePort, queue: flow.upstreamQueue,
                          sourceHost: flow.key.clientAddress.hostString,
                          sourcePort: flow.key.clientPort) { [weak self, weak flow] result in
            guard let self, let flow else {
                if case .success(let stream) = result { stream.cancel() }; return
            }
            self.queue.async {
                guard self.tcpFlows[flow.key] === flow else {
                    if case .success(let stream) = result { stream.cancel() }; return
                }
                flow.connected(result)
            }
        }
    }

    fileprivate func connectUDPFlow(_ flow: UDPFlow) {
        do {
            let session = try router.makeUDPFlow(host: flow.key.remoteAddress.hostString,
                                                 port: flow.key.remotePort, queue: flow.upstreamQueue,
                                                 sourceHost: flow.key.clientAddress.hostString,
                                                 sourcePort: flow.key.clientPort,
                                                 receive: { [weak self, weak flow] data in self?.queue.async { flow?.received(data) } },
                                                 failure: { [weak self, weak flow] _ in self?.queue.async { flow?.close() } })
            flow.connected(.success(session))
        } catch { flow.connected(.failure(error)) }
    }

    fileprivate func removeTCP(_ flow: TCPFlow) {
        if tcpFlows[flow.key] === flow { tcpFlows.removeValue(forKey: flow.key) }
    }

    fileprivate func removeUDP(_ flow: UDPFlow) {
        if udpFlows[flow.key] === flow { udpFlows.removeValue(forKey: flow.key) }
    }

    /// Maximum TCP payload this stack will put on the wire toward the client.
    /// utun is configured at 9000, so 8 KiB stays well under that MTU while
    /// cutting per-segment Swift/C overhead by about 5× versus Ethernet MSS.
    fileprivate static let tcpSegmentPayloadLimit = 8_192

    @discardableResult
    fileprivate func writeTCP(key: FlowKey, sequence: UInt32, acknowledgment: UInt32,
                               flags: TCPFlags, window: UInt16 = 65_535,
                               payload: Data = Data(), includeMSS: Bool = false,
                               windowScale: UInt8? = nil,
                               sackPermitted: Bool = false) -> Data? {
        if !includeMSS, windowScale == nil, !sackPermitted,
           let packet = buildSimpleTCP(key: key, sequence: sequence,
                                       acknowledgment: acknowledgment,
                                       flags: flags, window: window, payload: payload) {
            guard writeReturningOK(packet, version: key.version) else { return nil }
            return packet
        }
        let packet = PacketBuilder.tcp(version: key.version,
                                       source: key.remoteAddress, sourcePort: key.remotePort,
                                       destination: key.clientAddress, destinationPort: key.clientPort,
                                       sequence: sequence, acknowledgment: acknowledgment,
                                       flags: flags, window: window, payload: payload,
                                       maximumSegmentSize: includeMSS
                                           ? UInt16(Self.tcpSegmentPayloadLimit
                                                        - (key.version == .v4 ? 0 : 20)) : nil,
                                       windowScale: windowScale,
                                       sackPermitted: sackPermitted,
                                       identifier: nextIPv4Identifier())
        guard writeReturningOK(packet, version: key.version) else { return nil }
        return packet
    }

    /// No-option data/ACK segments — the download hot path. Built in C into a
    /// reused scratch buffer so Swift does not allocate per MSS.
    private func buildSimpleTCP(key: FlowKey, sequence: UInt32, acknowledgment: UInt32,
                                flags: TCPFlags, window: UInt16, payload: Data) -> Data? {
        var sourceBytes = (UInt64(0), UInt64(0))
        var destinationBytes = (UInt64(0), UInt64(0))
        let identifier = nextIPv4Identifier()
        return withUnsafeMutableBytes(of: &sourceBytes) { sourceRaw in
            withUnsafeMutableBytes(of: &destinationBytes) { destinationRaw in
                key.remoteAddress.copyBytes(to: sourceRaw.baseAddress!.assumingMemoryBound(to: UInt8.self))
                key.clientAddress.copyBytes(to: destinationRaw.baseAddress!.assumingMemoryBound(to: UInt8.self))
                return buildBuffer.withUnsafeMutableBytes { out in
                    payload.withUnsafeBytes { payloadRaw in
                        let written = CDataPlane.buildTCP(
                            into: out,
                            version: key.version.rawValue,
                            source: sourceRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            sourceLength: key.remoteAddress.addressLength,
                            sourcePort: key.remotePort,
                            destinationAddress: destinationRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            destinationPort: key.clientPort,
                            sequence: sequence,
                            acknowledgment: acknowledgment,
                            flags: flags.rawValue,
                            window: window,
                            payload: payloadRaw,
                            identifier: identifier)
                        guard written > 0 else { return nil }
                        return Data(bytes: out.baseAddress!, count: written)
                    }
                }
            }
        }
    }

    fileprivate func writeICMPEchoReply(to client: IPAddress, from remote: IPAddress,
                                        body: [UInt8]) {
        let packet = PacketBuilder.icmpEchoReply(source: remote, destination: client,
                                                 message: Data(body),
                                                 identifier: nextIPv4Identifier())
        write(packet, version: .v4)
    }

    private func writeICMPPortUnreachable(for original: ParsedIPPacket) {
        let packet = PacketBuilder.icmpPortUnreachable(original: original,
                                                       identifier: nextIPv4Identifier())
        write(packet, version: original.version)
    }

    fileprivate func rewrite(_ packet: Data, version: IPVersion) {
        _ = writeReturningOK(packet, version: version)
    }

    fileprivate func recordTCPUpload(_ count: Int) { uploadedByteCount &+= UInt64(count) }
    fileprivate func recordTCPDownload(_ count: Int) { downloadedByteCount &+= UInt64(count) }

    fileprivate func writeUDP(key: FlowKey, remoteAddress: IPAddress, remotePort: UInt16,
                              payload: Data) {
        let identifier = nextIPv4Identifier()
        var sourceBytes = (UInt64(0), UInt64(0))
        var destinationBytes = (UInt64(0), UInt64(0))
        let packet = withUnsafeMutableBytes(of: &sourceBytes) { sourceRaw -> Data? in
            withUnsafeMutableBytes(of: &destinationBytes) { destinationRaw in
                remoteAddress.copyBytes(to: sourceRaw.baseAddress!.assumingMemoryBound(to: UInt8.self))
                key.clientAddress.copyBytes(to: destinationRaw.baseAddress!.assumingMemoryBound(to: UInt8.self))
                return buildBuffer.withUnsafeMutableBytes { out in
                    payload.withUnsafeBytes { payloadRaw in
                        let written = CDataPlane.buildUDP(
                            into: out,
                            version: key.version.rawValue,
                            source: sourceRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            sourceLength: remoteAddress.addressLength,
                            sourcePort: remotePort,
                            destinationAddress: destinationRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            destinationPort: key.clientPort,
                            payload: payloadRaw,
                            identifier: identifier)
                        guard written > 0 else { return nil }
                        return Data(bytes: out.baseAddress!, count: written)
                    }
                }
            }
        }
        guard let packet else { return }
        downloadedByteCount &+= UInt64(payload.count)
        write(packet, version: key.version)
    }

    /// A frame waiting for the descriptor to become writable again. The
    /// address family prefix is generated at write time, so queueing a frame
    /// copies nothing.
    fileprivate struct PendingFrame {
        let packet: Data
        let version: IPVersion
    }

    /// Writes a packet to utun. Returns `false` only when the frame was dropped
    /// (descriptor down or a hard error). Enqueued-on-backpressure still counts
    /// as success so TCP outstanding accounting stays honest.
    @discardableResult
    private func writeReturningOK(_ packet: Data, version: IPVersion) -> Bool {
        guard descriptor >= 0, !stopped else { return false }
        if pendingFrameHead < pendingFrames.count {
            enqueue(packet, version: version); flushPendingFrames(); return true
        }
        switch writePacket(packet, version: version) {
        case .written:
            return true
        case .wouldBlock:
            enqueue(packet, version: version); ensureWriteSource()
            return true
        case .failed:
            // Unwritable for a reason retrying cannot fix; drop it rather than
            // arming a level-triggered source that would spin.
            return false
        }
    }

    private func write(_ packet: Data, version: IPVersion) {
        _ = writeReturningOK(packet, version: version)
    }

    private enum FrameWriteOutcome {
        case written
        /// The descriptor is not ready; retry when it signals writable again.
        case wouldBlock
        /// The write can never succeed for this frame — a downed interface, a
        /// closed descriptor, an oversized datagram.
        case failed
    }

    /// Writes the 4-byte address family and the packet in a single `writev`.
    ///
    /// The previous form concatenated both into a fresh `Data` for every
    /// packet, which allocated a buffer and then copied up to nine kilobytes
    /// on the hottest path in the process. A two-element gather list lives on
    /// the stack and copies nothing.
    private func writePacket(_ packet: Data, version: IPVersion) -> FrameWriteOutcome {
        var family = UInt32(version == .v4 ? AF_INET : AF_INET6).bigEndian
        return withUnsafeMutableBytes(of: &family) { familyRaw -> FrameWriteOutcome in
            packet.withUnsafeBytes { raw -> FrameWriteOutcome in
                guard let familyBase = familyRaw.baseAddress else { return .failed }
                // Empty IP packets are never produced; a nil base with a positive
                // length would mean we claimed success without writing anything.
                guard raw.count == 0 || raw.baseAddress != nil else { return .failed }
                let expected = 4 + raw.count
                var vectors = (
                    iovec(iov_base: familyBase, iov_len: 4),
                    iovec(iov_base: UnsafeMutableRawPointer(mutating: raw.baseAddress),
                          iov_len: raw.count)
                )
                let count = withUnsafeMutablePointer(to: &vectors) { pointer in
                    pointer.withMemoryRebound(to: iovec.self, capacity: 2) {
                        Darwin.writev(descriptor, $0, 2)
                    }
                }
                if count == expected { return .written }
                if count < 0, errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                    return .wouldBlock
                }
                return .failed
            }
        }
    }

    private func enqueue(_ packet: Data, version: IPVersion) {
        // A bounded queue prevents a stalled kernel consumer from turning a
        // local packet flood into unbounded root-helper memory. TCP will
        // retransmit a dropped oldest frame; interactive/UDP traffic keeps its
        // opportunity to progress.
        let frameBytes = 4 + packet.count
        while pendingFrameBytes + frameBytes > 8 * 1024 * 1024,
              pendingFrameHead < pendingFrames.count {
            let oldest = pendingFrames[pendingFrameHead]
            pendingFrameBytes -= 4 + oldest.packet.count
            pendingFrameHead += 1
        }
        pendingFrames.append(PendingFrame(packet: packet, version: version))
        pendingFrameBytes += frameBytes
        compactPendingFramesIfNeeded()
        ensureWriteSource()
    }

    private func ensureWriteSource() {
        guard writeSource == nil, descriptor >= 0 else { return }
        let source = DispatchSource.makeWriteSource(fileDescriptor: descriptor, queue: queue)
        source.setEventHandler { [weak self] in self?.flushPendingFrames() }
        source.setCancelHandler {}
        writeSource = source
        source.resume()
    }

    private func flushPendingFrames() {
        guard descriptor >= 0, !stopRequested.value else {
            writeSource?.cancel(); writeSource = nil
            return
        }
        var consecutiveFailures = 0
        while pendingFrameHead < pendingFrames.count {
            let frame = pendingFrames[pendingFrameHead]
            switch writePacket(frame.packet, version: frame.version) {
            case .written:
                pendingFrameBytes -= 4 + frame.packet.count
                pendingFrameHead += 1
                consecutiveFailures = 0
            case .wouldBlock:
                // Genuinely not ready: keep the source armed and wait for the
                // next writability signal.
                return
            case .failed:
                // Drop the frame — TCP will retransmit — but stop entirely once
                // the descriptor is clearly unusable. A downed utun reports
                // writable while rejecting every write, and a level-triggered
                // source would otherwise re-fire immediately and spin the queue
                // at 100%, starving stop() of the queue it needs.
                pendingFrameBytes -= 4 + frame.packet.count
                pendingFrameHead += 1
                consecutiveFailures += 1
                if consecutiveFailures >= 16 {
                    pendingFrames.removeAll(keepingCapacity: true)
                    pendingFrameBytes = 0
                    pendingFrameHead = 0
                    writeSource?.cancel(); writeSource = nil
                    return
                }
            }
        }
        pendingFrames.removeAll(keepingCapacity: true)
        pendingFrameBytes = 0
        pendingFrameHead = 0
        writeSource?.cancel(); writeSource = nil
    }

    private func compactPendingFramesIfNeeded() {
        guard pendingFrameHead >= 512,
              pendingFrameHead * 2 >= pendingFrames.count else { return }
        pendingFrames.removeFirst(pendingFrameHead)
        pendingFrameHead = 0
    }

    private func nextIPv4Identifier() -> UInt16 {
        ipv4Identifier &+= 1
        return ipv4Identifier
    }

    private func performMaintenance() {
        let now = Date()
        // Snapshot first: tick() may close a flow and remove it from the
        // live table. Mutating the dictionary while iterating it is illegal.
        for flow in Array(tcpFlows.values) { flow.tick(now: now) }
        for flow in Array(udpFlows.values) { flow.tick(now: now) }
    }

    fileprivate func upstreamQueue(for key: FlowKey) -> DispatchQueue {
        let bucket = Int(UInt(bitPattern: key.hashValue) % UInt(Self.upstreamQueueCount))
        return Self.sharedUpstreamQueues[bucket]
    }

    /// Drops the least-recently-used idle TCP flow so a new handshake can
    /// proceed. Returns false when every occupant is still active.
    private func evictIdleTCP(now: Date = Date()) -> Bool {
        var candidate: TCPFlow?
        var oldest = now
        for flow in tcpFlows.values {
            guard FlowAdmission.isIdle(lastActivity: flow.lastActivityDate, now: now,
                                       limit: FlowAdmission.tcpIdleEviction) else { continue }
            if flow.lastActivityDate < oldest {
                candidate = flow
                oldest = flow.lastActivityDate
            }
        }
        guard let candidate else { return false }
        candidate.close(sendReset: true)
        return true
    }

    private func evictIdleUDP(now: Date = Date()) -> Bool {
        var candidate: UDPFlow?
        var oldest = now
        for flow in udpFlows.values {
            guard FlowAdmission.isIdle(lastActivity: flow.lastActivityDate, now: now,
                                       limit: FlowAdmission.udpIdleEviction) else { continue }
            if flow.lastActivityDate < oldest {
                candidate = flow
                oldest = flow.lastActivityDate
            }
        }
        guard let candidate else { return false }
        candidate.close()
        return true
    }

    private static func openUTUN() throws -> (descriptor: Int32, name: String) {
        let descriptor = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        guard descriptor >= 0 else {
            if errno == EPERM || errno == EACCES { throw NativeTunnelError.permissionDenied }
            throw NativeTunnelError.utun(String(cString: strerror(errno)))
        }
        do {
            var info = ctl_info()
            withUnsafeMutableBytes(of: &info.ctl_name) { raw in
                let name = Array("com.apple.net.utun_control".utf8) + [0]
                raw.copyBytes(from: name)
            }
            // CTLIOCGINFO = _IOWR('N', 3, struct ctl_info). Clang cannot
            // expose this structure-valued macro to Swift, so use its stable
            // Darwin ABI value for the 100-byte ctl_info structure.
            guard ioctl(descriptor, UInt(0xC0644E03), &info) == 0 else {
                throw NativeTunnelError.utun(String(cString: strerror(errno)))
            }
            var address = sockaddr_ctl()
            address.sc_len = UInt8(MemoryLayout<sockaddr_ctl>.size)
            address.sc_family = UInt8(AF_SYSTEM)
            address.ss_sysaddr = UInt16(AF_SYS_CONTROL)
            address.sc_id = info.ctl_id
            address.sc_unit = 0
            let connected = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_ctl>.size))
                }
            }
            guard connected == 0 else {
                if errno == EPERM || errno == EACCES { throw NativeTunnelError.permissionDenied }
                throw NativeTunnelError.utun(String(cString: strerror(errno)))
            }
            var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            var length = socklen_t(name.count)
            guard getsockopt(descriptor, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &name, &length) == 0 else {
                throw NativeTunnelError.utun("无法读取接口名称：\(String(cString: strerror(errno)))")
            }
            let flags = fcntl(descriptor, F_GETFL, 0)
            if flags >= 0 { _ = fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) }
            return (descriptor, String(cString: name))
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }
}

fileprivate enum IPVersion: UInt8, Hashable { case v4 = 4, v6 = 6 }

fileprivate struct IPAddress: Hashable {
    let version: IPVersion
    /// Network-order address. IPv4 occupies the first four bytes.
    let storage: (UInt8, UInt8, UInt8, UInt8,
                  UInt8, UInt8, UInt8, UInt8,
                  UInt8, UInt8, UInt8, UInt8,
                  UInt8, UInt8, UInt8, UInt8)

    static func v4(_ bytes: [UInt8]) -> IPAddress {
        precondition(bytes.count == 4)
        return IPAddress(version: .v4, storage: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    }

    static func v6(_ bytes: [UInt8]) -> IPAddress {
        precondition(bytes.count == 16)
        return IPAddress(version: .v6, storage: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]))
    }

    var bytes: [UInt8] {
        switch version {
        case .v4: return [storage.0, storage.1, storage.2, storage.3]
        case .v6:
            return [storage.0, storage.1, storage.2, storage.3,
                    storage.4, storage.5, storage.6, storage.7,
                    storage.8, storage.9, storage.10, storage.11,
                    storage.12, storage.13, storage.14, storage.15]
        }
    }

    var addressLength: Int { version == .v4 ? 4 : 16 }

    var socksAddress: Data {
        var result = Data([version == .v4 ? 0x01 : 0x04])
        result.append(contentsOf: bytes)
        return result
    }

    var hostString: String {
        switch version {
        case .v4:
            return "\(storage.0).\(storage.1).\(storage.2).\(storage.3)"
        case .v6:
            var address = in6_addr()
            withUnsafeMutableBytes(of: &address) { raw in
                raw[0] = storage.0; raw[1] = storage.1; raw[2] = storage.2; raw[3] = storage.3
                raw[4] = storage.4; raw[5] = storage.5; raw[6] = storage.6; raw[7] = storage.7
                raw[8] = storage.8; raw[9] = storage.9; raw[10] = storage.10; raw[11] = storage.11
                raw[12] = storage.12; raw[13] = storage.13; raw[14] = storage.14; raw[15] = storage.15
            }
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &address, &output, socklen_t(output.count)) != nil else { return "::" }
            return String(cString: output)
        }
    }

    func copyBytes(to pointer: UnsafeMutablePointer<UInt8>) {
        pointer[0] = storage.0; pointer[1] = storage.1; pointer[2] = storage.2; pointer[3] = storage.3
        guard version == .v6 else { return }
        pointer[4] = storage.4; pointer[5] = storage.5; pointer[6] = storage.6; pointer[7] = storage.7
        pointer[8] = storage.8; pointer[9] = storage.9; pointer[10] = storage.10; pointer[11] = storage.11
        pointer[12] = storage.12; pointer[13] = storage.13; pointer[14] = storage.14; pointer[15] = storage.15
    }

    static func == (lhs: IPAddress, rhs: IPAddress) -> Bool {
        lhs.version == rhs.version
            && lhs.storage.0 == rhs.storage.0 && lhs.storage.1 == rhs.storage.1
            && lhs.storage.2 == rhs.storage.2 && lhs.storage.3 == rhs.storage.3
            && lhs.storage.4 == rhs.storage.4 && lhs.storage.5 == rhs.storage.5
            && lhs.storage.6 == rhs.storage.6 && lhs.storage.7 == rhs.storage.7
            && lhs.storage.8 == rhs.storage.8 && lhs.storage.9 == rhs.storage.9
            && lhs.storage.10 == rhs.storage.10 && lhs.storage.11 == rhs.storage.11
            && lhs.storage.12 == rhs.storage.12 && lhs.storage.13 == rhs.storage.13
            && lhs.storage.14 == rhs.storage.14 && lhs.storage.15 == rhs.storage.15
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(version)
        hasher.combine(storage.0); hasher.combine(storage.1)
        hasher.combine(storage.2); hasher.combine(storage.3)
        if version == .v6 {
            hasher.combine(storage.4); hasher.combine(storage.5)
            hasher.combine(storage.6); hasher.combine(storage.7)
            hasher.combine(storage.8); hasher.combine(storage.9)
            hasher.combine(storage.10); hasher.combine(storage.11)
            hasher.combine(storage.12); hasher.combine(storage.13)
            hasher.combine(storage.14); hasher.combine(storage.15)
        }
    }
}

fileprivate struct FlowKey: Hashable {
    let version: IPVersion
    let transportProtocol: UInt8
    let clientAddress: IPAddress
    let clientPort: UInt16
    let remoteAddress: IPAddress
    let remotePort: UInt16
}

fileprivate struct ParsedIPPacket {
    let version: IPVersion
    let source: IPAddress
    let destination: IPAddress
    let transportProtocol: UInt8
    let transportOffset: Int
    let payloadEnd: Int
    /// Copied only when ICMP needs to quote the original header. TCP/UDP
    /// never look at this after parsing.
    let bytes: [UInt8]

    init?(_ bytes: [UInt8]) {
        let parsed: ParsedIPPacket? = bytes.withUnsafeBytes { raw in
            ParsedIPPacket(raw, owned: bytes)
        }
        guard let parsed else { return nil }
        self = parsed
    }

    init?(_ raw: UnsafeRawBufferPointer) {
        self.init(raw, owned: nil)
    }

    private init?(_ raw: UnsafeRawBufferPointer, owned: [UInt8]?) {
        guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
              raw.count > 0 else { return nil }
        switch base[0] >> 4 {
        case 4:
            guard raw.count >= 20 else { return nil }
            let totalLength = Int(read16(base, 2))
            let fragment = read16(base, 6)
            // The flow engine has no IP fragment reassembly. Never treat the
            // first fragment (MF=1) as a complete TCP/UDP packet either.
            guard totalLength <= raw.count, fragment & 0x3fff == 0 else { return nil }
        case 6:
            guard raw.count >= 40 else { return nil }
            let totalLength = 40 + Int(read16(base, 4))
            guard totalLength <= raw.count, [UInt8(6), 17, 58].contains(base[6]) else { return nil }
        default: return nil
        }
        var parsed = hajimi_ip_packet()
        guard hajimi_parse_ip(base, raw.count, &parsed) == 0,
              let version = IPVersion(rawValue: parsed.version) else { return nil }
        self.version = version
        source = IPAddress(version: version, storage: parsed.source)
        destination = IPAddress(version: version, storage: parsed.destination)
        transportProtocol = parsed.protocol
        transportOffset = Int(parsed.payload_offset)
        payloadEnd = transportOffset + Int(parsed.payload_length)
        // The hot TCP/UDP path borrows the input frame. Materialize a complete
        // packet only for ICMP handling/quotes and explicitly owned fixtures.
        bytes = owned ?? ((parsed.protocol == 6 || parsed.protocol == 17)
            ? [] : Array(UnsafeBufferPointer(start: base, count: payloadEnd)))
    }

    init?(copying raw: UnsafeRawBufferPointer) {
        self.init(Array(raw))
    }
}

fileprivate struct TCPFlags: OptionSet {
    let rawValue: UInt8
    static let fin = TCPFlags(rawValue: 0x01)
    static let syn = TCPFlags(rawValue: 0x02)
    static let rst = TCPFlags(rawValue: 0x04)
    static let psh = TCPFlags(rawValue: 0x08)
    static let ack = TCPFlags(rawValue: 0x10)
}

fileprivate struct ParsedTCPSegment {
    let sourcePort: UInt16
    let destinationPort: UInt16
    let sequence: UInt32
    let acknowledgment: UInt32
    let flags: TCPFlags
    let window: UInt16
    let windowScale: UInt8?
    let sackPermitted: Bool
    let sackBlocks: [SACKBlock]
    let payload: Data

    init?(_ packet: ParsedIPPacket) {
        guard !packet.bytes.isEmpty else { return nil }
        let parsed: ParsedTCPSegment? = packet.bytes.withUnsafeBytes { raw in
            ParsedTCPSegment(bytes: raw, packet: packet)
        }
        guard let parsed else { return nil }
        self = parsed
    }

    init?(bytes: UnsafeRawBufferPointer, packet: ParsedIPPacket) {
        guard let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
        let offset = packet.transportOffset
        guard packet.transportProtocol == 6, offset + 20 <= packet.payloadEnd,
              packet.payloadEnd <= bytes.count else { return nil }
        var parsed = hajimi_tcp_segment()
        guard hajimi_parse_tcp(base.advanced(by: offset), packet.payloadEnd - offset, &parsed) == 0 else { return nil }
        var options = hajimi_tcp_options()
        guard hajimi_parse_tcp_options(base.advanced(by: offset + Int(parsed.options_offset)),
                                      Int(parsed.options_length), &options) == 0 else { return nil }
        sourcePort = parsed.source_port
        destinationPort = parsed.destination_port
        sequence = parsed.sequence
        acknowledgment = parsed.acknowledgment
        flags = TCPFlags(rawValue: parsed.flags)
        window = parsed.window
        windowScale = options.has_window_scale == 0 ? nil : options.window_scale
        sackPermitted = options.sack_permitted != 0
        sackBlocks = withUnsafeBytes(of: &options.sacks) { raw in
            raw.bindMemory(to: hajimi_sack_block.self).prefix(Int(options.sack_count)).map {
                SACKBlock(start: $0.start, end: $0.end)
            }
        }
        let payloadStart = offset + Int(parsed.payload_offset)
        payload = Data(bytes: base.advanced(by: payloadStart),
                       count: packet.payloadEnd - payloadStart)
    }
}

/// A boolean readable and writable from any thread.
fileprivate final class AtomicFlag {
    private let lock = NSLock()
    private var storage = false
    var value: Bool {
        get { lock.lock(); defer { lock.unlock() }; return storage }
        set { lock.lock(); storage = newValue; lock.unlock() }
    }
}

fileprivate struct SACKBlock {
    let start: UInt32
    let end: UInt32
}

fileprivate struct OutstandingSegment {
    var packet: Data
    var endSequence: UInt32
    var payloadBytes: Int
    var sentAt: Date
    var retries: Int
    /// Set once the peer selectively acknowledged this exact range, so
    /// retransmission can skip it.
    var sacked: Bool = false
    /// Karn's algorithm: a retransmitted segment's ACK is ambiguous — it may
    /// acknowledge either transmission — so it must not feed the RTT estimator.
    var retransmitted: Bool = false

    var startSequence: UInt32 { endSequence &- UInt32(payloadBytes) }
}

/// In-order release of client-to-server payload that arrived early.
///
/// Pure state machine so a missing middle segment can be unit-tested without
/// standing up a full `TCPFlow` and utun.
fileprivate enum TCPReceiveReassembly {
    struct State: Equatable {
        var expected: UInt32
        var buffered: [UInt32: Data] = [:]
        var bufferedBytes: Int = 0
        var pendingFin: UInt32? = nil
        var finished = false
    }

    /// Payload chunks that became contiguous and should be written upstream,
    /// in order.
    static func ingest(payload: Data, sequence: UInt32, into state: inout State,
                       limitBytes: Int, limitSegments: Int) -> [Data] {
        var released: [Data] = []
        if sequence == state.expected {
            released.append(payload)
            state.expected &+= UInt32(payload.count)
            released.append(contentsOf: drain(&state))
            return released
        }
        guard sequenceGreater(sequence, state.expected) else { return [] }
        guard state.buffered[sequence] == nil else { return [] }
        guard state.bufferedBytes + payload.count <= limitBytes,
              state.buffered.count < limitSegments else { return [] }
        state.buffered[sequence] = payload
        state.bufferedBytes += payload.count
        return []
    }

    static func noteFin(sequence: UInt32, into state: inout State) {
        if sequence == state.expected {
            state.expected &+= 1
            state.finished = true
            state.pendingFin = nil
        } else if sequenceGreater(sequence, state.expected) {
            state.pendingFin = sequence
        }
    }

    private static func drain(_ state: inout State) -> [Data] {
        var released: [Data] = []
        while let payload = state.buffered[state.expected] {
            state.buffered.removeValue(forKey: state.expected)
            state.bufferedBytes = max(0, state.bufferedBytes - payload.count)
            state.expected &+= UInt32(payload.count)
            released.append(payload)
        }
        if let fin = state.pendingFin, fin == state.expected {
            state.expected &+= 1
            state.finished = true
            state.pendingFin = nil
        }
        return released
    }
}

/// Tracks which outstanding segments the peer has selectively acknowledged.
///
/// Kept free of connection state so the retransmission choice — the part that
/// actually changes behaviour under loss — can be exercised directly.
fileprivate enum SACKScoreboard {
    static func apply(_ blocks: [SACKBlock], to segments: inout [OutstandingSegment],
                      from head: Int) {
        guard !blocks.isEmpty, head < segments.count else { return }
        for index in head..<segments.count
        where !segments[index].sacked && segments[index].payloadBytes > 0 {
            let start = segments[index].startSequence
            let end = segments[index].endSequence
            // Only a block that fully covers the segment proves it arrived; a
            // partial overlap says nothing about the remaining bytes.
            if blocks.contains(where: { sequenceGreaterOrEqual(start, $0.start)
                && sequenceGreaterOrEqual($0.end, end) }) {
                segments[index].sacked = true
            }
        }
    }

    /// The oldest segment the peer has not selectively acknowledged.
    ///
    /// Without SACK this is always the head, which is what made a single loss
    /// resend the whole window. With SACK the ranges the peer already holds are
    /// skipped, so only genuinely missing data goes back on the wire.
    static func firstRetransmittable(in segments: [OutstandingSegment], from head: Int) -> Int? {
        var index = head
        while index < segments.count {
            if !segments[index].sacked { return index }
            index += 1
        }
        return nil
    }
}

/// RFC 6298 retransmission timer.
///
/// The previous fixed `0.75 * 2^retries` schedule was calibrated for a wide
/// area link, but this TCP endpoint talks to an application on the same machine
/// over utun, where the round trip is sub-millisecond. A single dropped segment
/// therefore stalled the flow for 750 ms before the first retransmission —
/// visible as a periodic hitch rather than a slowdown.
fileprivate struct RetransmissionTimer {
    /// Loss on utun comes from our own queue overflowing, not from a congested
    /// path, so the floor sits far below the 1 s RFC 6298 suggests for the
    /// internet. The ceiling keeps the previous value so a genuinely dead peer
    /// is still torn down on the same schedule.
    static let minimum: TimeInterval = 0.02
    static let maximum: TimeInterval = 12.0
    static let clockGranularity: TimeInterval = 0.001

    private var native: hajimi_rto = {
        var value = hajimi_rto()
        hajimi_rto_init(&value)
        return value
    }()
    var smoothedRTT: TimeInterval? { native.sampled == 0 ? nil : native.smoothed_rtt }
    var variation: TimeInterval { native.variation }
    var timeout: TimeInterval { native.timeout }

    mutating func update(sample: TimeInterval) {
        hajimi_rto_update(&native, sample)
    }

    /// The estimator sets the base timeout; the exponential backoff on top is
    /// the separate RFC 6298 response to repeated loss.
    func timeout(retries: Int) -> TimeInterval {
        var value = native
        return hajimi_rto_timeout(&value, UInt32(clamping: retries))
    }
}

fileprivate struct ParsedUDPDatagram {
    let sourcePort: UInt16
    let destinationPort: UInt16
    let payload: Data

    init?(_ packet: ParsedIPPacket) {
        guard !packet.bytes.isEmpty else { return nil }
        let parsed: ParsedUDPDatagram? = packet.bytes.withUnsafeBytes { raw in
            ParsedUDPDatagram(bytes: raw, packet: packet)
        }
        guard let parsed else { return nil }
        self = parsed
    }

    init?(bytes: UnsafeRawBufferPointer, packet: ParsedIPPacket) {
        guard let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
        let offset = packet.transportOffset
        guard packet.transportProtocol == 17, offset + 8 <= packet.payloadEnd,
              packet.payloadEnd <= bytes.count else { return nil }
        let length = Int(read16(base, offset + 4))
        guard length >= 8, offset + length <= packet.payloadEnd else { return nil }
        var parsed = hajimi_udp_datagram()
        guard hajimi_parse_udp(base.advanced(by: offset), length, &parsed) == 0 else { return nil }
        sourcePort = parsed.source_port
        destinationPort = parsed.destination_port
        payload = Data(bytes: base.advanced(by: offset + 8), count: length - 8)
    }
}

/// Passing the flags and QoS explicitly keeps DispatchQueue.async away from
/// the generic SetAlgebra initialiser it otherwise uses to build its default
/// empty option set. That default cost generic metadata instantiation on
/// every hop, which is measurable when the hop happens per packet burst.
fileprivate let dispatchNoFlags = DispatchWorkItemFlags(rawValue: 0)

/// Joins queued upload chunks into one outbound write. Isolated so the
/// coalesce budget can be unit-tested without standing up a TCPFlow.
fileprivate enum TCPWriteCoalesce {
    static func merge(_ chunks: [Data], from head: Int, limit: Int)
        -> (payload: Data, chunkCount: Int, byteCount: Int) {
        guard head < chunks.count else { return (Data(), 0, 0) }
        let first = chunks[head]
        var chunkCount = 1
        var byteCount = first.count
        var index = head + 1
        while index < chunks.count, byteCount < limit {
            let next = chunks[index]
            if byteCount + next.count > limit { break }
            byteCount += next.count
            chunkCount += 1
            index += 1
        }
        if chunkCount == 1 { return (first, 1, first.count) }
        var combined = Data()
        combined.reserveCapacity(byteCount)
        for offset in 0..<chunkCount {
            combined.append(chunks[head + offset])
        }
        return (combined, chunkCount, byteCount)
    }
}

/// Byte-offset slice of a `Data` that may not start at index 0.
///
/// `Network.framework` receive callbacks frequently hand back a window into a
/// larger buffer (`startIndex != 0`). `Data.subdata(in:)` takes absolute
/// indices, so treating a logical offset as `0..<n` traps inside Foundation
/// (`Data._Representation.subscript.getter` → SIGILL).
fileprivate enum TCPDeliverySlice {
    static func payload(from buffer: Data, offset: Int, count: Int) -> Data {
        let start = buffer.startIndex + offset
        return buffer.subdata(in: start..<(start + count))
    }
}

/// Caps concurrent userspace flows so a YouTube 4K (or similar) burst of
/// TCP + QUIC sockets cannot allocate unbounded per-flow state.
fileprivate enum FlowAdmission {
    static let maximumTCPFlows = 768
    static let maximumUDPFlows = 512
    static let tcpIdleEviction: TimeInterval = 15
    static let udpIdleEviction: TimeInterval = 8

    static func shouldAdmit(current: Int, maximum: Int) -> Bool {
        current < maximum
    }

    static func isIdle(lastActivity: Date, now: Date, limit: TimeInterval) -> Bool {
        now.timeIntervalSince(lastActivity) >= limit
    }
}

fileprivate final class TCPFlow {
    fileprivate let key: FlowKey
    fileprivate let upstreamQueue: DispatchQueue
    private weak var owner: NativeTunnel?
    private let initial: ParsedTCPSegment
    private let receiveState: OpaquePointer?
    private var expectedClientSequence: UInt32 { hajimi_tcp_reassembly_expected(receiveState) }
    private let initialServerSequence = UInt32.random(in: 1...UInt32.max - 1_000_000)
    private var nextServerSequence: UInt32
    private let clientWindowScale: UInt8
    private let serverWindowScale: UInt8?
    private var clientAdvertisedWindow: Int
    private var lastClientAcknowledgment: UInt32
    private var duplicateAcknowledgments = 0
    private var remoteStream: NativeOutboundByteStream?
    private var remoteReadSuspended = false
    private var remoteReadInFlight = false
    private var remoteWriteInFlight = false
    private let remoteWrites: NativeByteQueue
    private var pendingRemoteWriteBytes: Int { remoteWrites.count }
    private var remoteDeliveryBuffer = Data()
    private var remoteDeliveryOffset = 0
    private var remoteEOFPending = false
    private var outstanding: [OutstandingSegment] = []
    private var outstandingHead = 0
    private var outstandingPayloadByteCount = 0
    private var remoteConnected = false
    private var clientFinished: Bool { hajimi_tcp_reassembly_finished(receiveState) != 0 }
    private var remoteFinished = false
    private var closed = false
    private var lastActivity = Date()
    private var lastAdvertisedReceiveWindow = UInt16.max

    private let maximumOutstandingPayloadBytes = 8 * 1_024 * 1_024
    /// Extra bytes we are willing to pull from the outbound while earlier
    /// download segments are still sitting in the client window. Without this
    /// the flow waits for a full receive to drain onto utun before asking the
    /// proxy for more, which serialises high-BDP downloads.
    private let maximumPrefetchBytes = 512 * 1_024

    /// Set when the peer offered SACK in its SYN. Only then may it send us
    /// selective acknowledgements, and only then is skipping segments safe.
    private var sackEnabled = false

    private var retransmissionTimer = RetransmissionTimer()

    /// Segments that arrived ahead of `expectedClientSequence`. Keyed by the
    /// starting sequence so a later in-order arrival can release the chain
    /// without asking the peer to retransmit data we already hold.
    private static let consumeUpload: hajimi_tcp_consume = { context, bytes, count in
        guard let context, let bytes else { return 0 }
        let flow = Unmanaged<TCPFlow>.fromOpaque(context).takeUnretainedValue()
        guard flow.remoteWrites.append(UnsafeRawBufferPointer(start: bytes, count: count)) else { return 0 }
        flow.owner?.recordTCPUpload(count)
        return 1
    }

    fileprivate var lastActivityDate: Date { lastActivity }

    init(key: FlowKey, initial: ParsedTCPSegment, owner: NativeTunnel) {
        self.key = key
        self.initial = initial
        self.owner = owner
        self.upstreamQueue = owner.upstreamQueue(for: key)
        receiveState = hajimi_tcp_reassembly_create(initial.sequence &+ 1, 256 * 1_024, 64)
        remoteWrites = NativeByteQueue(limit: initial.windowScale == nil ? Int(UInt16.max) : Int(UInt16.max) << 6)
        nextServerSequence = initialServerSequence &+ 1
        clientWindowScale = initial.windowScale ?? 0
        // Four MiB is large enough to keep local delivery continuously fed,
        // while still bounding uploads when the selected proxy is slower than
        // the application.  Window scaling is only legal when the peer
        // offered it in SYN.
        serverWindowScale = initial.windowScale == nil ? nil : 6
        clientAdvertisedWindow = Int(initial.window)
        lastClientAcknowledgment = initialServerSequence
        // SACK is bidirectional and only legal once both SYNs offered it.
        sackEnabled = initial.sackPermitted
    }

    func start() {
        guard let owner, receiveState != nil, remoteWrites.isValid else { close(sendReset: false); return }
        guard let packet = owner.writeTCP(key: key, sequence: initialServerSequence,
                                          acknowledgment: expectedClientSequence,
                                          flags: [.syn, .ack], window: advertisedReceiveWindow,
                                          includeMSS: true,
                                          windowScale: serverWindowScale,
                                          sackPermitted: sackEnabled) else {
            close(sendReset: false)
            return
        }
        outstanding.append(OutstandingSegment(packet: packet, endSequence: nextServerSequence,
                                              payloadBytes: 0,
                                              sentAt: Date(), retries: 0))
        owner.connectTCPFlow(self)
    }

    func handle(_ segment: ParsedTCPSegment) {
        guard !closed else { return }
        lastActivity = Date()
        if segment.flags.contains(.rst) { close(sendReset: false); return }
        if segment.flags.contains(.ack) {
            // A peer cannot acknowledge bytes we have not sent. Reject before
            // applying its window/SACK or releasing retransmission storage.
            if sequenceGreater(segment.acknowledgment, nextServerSequence) {
                sendAcknowledgment()
                return
            }
            let previousWindow = clientAdvertisedWindow
            clientAdvertisedWindow = Int(segment.window) << Int(clientWindowScale)
            applySelectiveAcknowledgements(segment.sackBlocks)
            acknowledge(segment.acknowledgment,
                        duplicateCandidate: segment.payload.isEmpty &&
                            clientAdvertisedWindow == previousWindow,
                        now: lastActivity)
            if closed { return }
        }

        var shouldAcknowledge = false
        if !segment.payload.isEmpty {
            ingestClientPayload(segment.payload, sequence: segment.sequence)
            shouldAcknowledge = true
        }
        if segment.flags.contains(.fin) {
            let finSequence = segment.sequence &+ UInt32(segment.payload.count)
            hajimi_tcp_reassembly_fin(receiveState, finSequence)
            shouldAcknowledge = true
        }
        if shouldAcknowledge {
            sendAcknowledgment()
            if clientFinished && remoteFinished && outstandingHead == outstanding.count { close(sendReset: false) }
        }
    }

    /// Accepts in-order bytes immediately and parks later segments until the gap
    /// fills, then drains any contiguous run that is already buffered.
    private func ingestClientPayload(_ payload: Data, sequence: UInt32) {
        payload.withUnsafeBytes { bytes in
            _ = hajimi_tcp_reassembly_ingest(receiveState, sequence,
                bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count,
                Unmanaged.passUnretained(self).toOpaque(), Self.consumeUpload)
        }
        flushRemoteWrites()
    }

    private func flushContiguousOutOfOrder() {
        _ = hajimi_tcp_reassembly_drain(receiveState,
            Unmanaged.passUnretained(self).toOpaque(), Self.consumeUpload)
    }

    func connected(_ result: Result<NativeOutboundByteStream, Error>) {
        guard !closed else {
            if case .success(let stream) = result { stream.cancel() }
            return
        }
        switch result {
        case .failure:
            close(sendReset: true)
        case .success(let stream):
            remoteStream = stream
            remoteConnected = true
            flushRemoteWrites()
            readRemote()
        }
    }

    func tick(now: Date) {
        guard !closed else { return }
        if now.timeIntervalSince(lastActivity) > 300 { close(sendReset: true); return }
        guard let index = firstRetransmittableIndex() else { return }
        let retries = outstanding[index].retries
        let timeout = retransmissionTimer.timeout(retries: retries)
        guard now.timeIntervalSince(outstanding[index].sentAt) >= timeout else { return }
        if retries >= 8 { close(sendReset: true); return }
        retransmit(at: index, now: now)
    }

    func close(sendReset: Bool, removeFromOwner: Bool = true) {
        guard !closed else { return }
        closed = true
        if sendReset {
            _ = owner?.writeTCP(key: key, sequence: nextServerSequence,
                                acknowledgment: expectedClientSequence,
                                flags: [.rst, .ack], window: advertisedReceiveWindow)
        }
        remoteStream?.cancel(); remoteStream = nil
        remoteWrites.clear()
        remoteDeliveryBuffer.removeAll(keepingCapacity: false)
        outstanding.removeAll(keepingCapacity: false)
        if removeFromOwner { owner?.removeTCP(self) }
    }

    deinit { hajimi_tcp_reassembly_destroy(receiveState) }

    private var ownerQueue: DispatchQueue {
        // Dispatch sources are created while executing NativeTunnel's serial
        // queue; a private serial queue would race packet state. This accessor
        // is filled by NativeTunnel through this internal bridge.
        owner!.queueForFlows
    }

    private func acknowledge(_ sequence: UInt32, duplicateCandidate: Bool, now: Date) {
        let advanced = sequenceGreater(sequence, lastClientAcknowledgment)
        if advanced {
            lastClientAcknowledgment = sequence
            duplicateAcknowledgments = 0
        } else if duplicateCandidate, sequence == lastClientAcknowledgment,
                  outstandingHead < outstanding.count,
                  outstanding[outstandingHead].payloadBytes > 0 {
            duplicateAcknowledgments += 1
        }

        while outstandingHead < outstanding.count,
              sequenceGreaterOrEqual(sequence, outstanding[outstandingHead].endSequence) {
            let segment = outstanding[outstandingHead]
            if !segment.retransmitted {
                retransmissionTimer.update(sample: now.timeIntervalSince(segment.sentAt))
            }
            outstandingPayloadByteCount -= segment.payloadBytes
            outstandingHead += 1
        }
        compactOutstandingIfNeeded()

        if duplicateAcknowledgments >= 3, let index = firstRetransmittableIndex() {
            duplicateAcknowledgments = 0
            retransmit(at: index, now: now)
        }

        flushRemoteDelivery()
        if remoteReadSuspended, remoteDeliveryBytes == 0,
           availableClientDeliveryBytes > 0 {
            remoteReadSuspended = false
        }
        readRemote()
        if remoteFinished && sequenceGreaterOrEqual(sequence, nextServerSequence) {
            close(sendReset: false)
        }
    }

    private func flushRemoteWrites() {
        guard remoteConnected, let stream = remoteStream, !closed, !remoteWriteInFlight,
              remoteWrites.count > 0 else { return }
        // One send() per small TCP segment spent more time in the outbound
        // framing than on the wire. Coalesce up to 64 KiB so a burst of
        // 1460-byte uploads becomes a handful of writes.
        let payload = remoteWrites.prefix(maximum: 64 * 1_024)
        remoteWriteInFlight = true
        stream.send(payload) { [weak self] error in
            guard let self else { return }
            let apply: () -> Void = {
                guard !self.closed else { return }
                self.remoteWriteInFlight = false
                if error != nil { self.close(sendReset: true); return }
                self.remoteWrites.consume(payload.count)
                // A full receive window may have blocked both the in-order
                // head and a chain parked in the out-of-order map. Try the
                // map before advertising the larger window.
                self.flushContiguousOutOfOrder()
                if self.lastAdvertisedReceiveWindow < UInt16.max {
                    self.sendAcknowledgment()
                }
                self.flushRemoteWrites()
            }
            if DispatchQueue.getSpecific(key: NativeTunnel.queueSpecificKey) != nil {
                apply()
            } else {
                self.owner?.queueForFlows.async(qos: .unspecified,
                                                flags: dispatchNoFlags, execute: apply)
            }
        }
    }

    private func readRemote() {
        guard let stream = remoteStream, !closed, !remoteFinished,
              !remoteEOFPending, !remoteReadInFlight else { return }
        let room = availableClientDeliveryBytes + maximumPrefetchBytes - remoteDeliveryBytes
        let maximum = min(512 * 1_024, room)
        guard maximum > 0 else { remoteReadSuspended = true; return }
        remoteReadSuspended = false
        remoteReadInFlight = true
        stream.receive(maximum: maximum) { [weak self] data, complete, error in
            guard let self else { return }
            let apply: () -> Void = {
                guard !self.closed else { return }
                self.remoteReadInFlight = false
                if let data, !data.isEmpty {
                    self.lastActivity = Date()
                    self.appendRemoteDelivery(data)
                    self.flushRemoteDelivery()
                }
                if error != nil { self.close(sendReset: true); return }
                if complete {
                    self.remoteEOFPending = true
                    self.finishRemoteEOFIfPossible()
                    return
                }
                self.readRemote()
            }
            if DispatchQueue.getSpecific(key: NativeTunnel.queueSpecificKey) != nil {
                apply()
            } else {
                self.owner?.queueForFlows.async(qos: .unspecified,
                                                flags: dispatchNoFlags, execute: apply)
            }
        }
    }

    private func appendRemoteDelivery(_ data: Data) {
        if remoteDeliveryOffset >= remoteDeliveryBuffer.count {
            // Copy non-zero-origin slices so later offset math cannot see a
            // window into the original receive buffer.
            remoteDeliveryBuffer = data.startIndex == 0 ? data : Data(data)
            remoteDeliveryOffset = 0
            return
        }
        if remoteDeliveryOffset > 0 {
            remoteDeliveryBuffer.removeFirst(remoteDeliveryOffset)
            remoteDeliveryOffset = 0
        }
        remoteDeliveryBuffer.append(data)
    }

    private func flushRemoteDelivery() {
        guard !closed else { return }
        let maximumSegment = NativeTunnel.tcpSegmentPayloadLimit
        var available = availableClientDeliveryBytes
        while remoteDeliveryOffset < remoteDeliveryBuffer.count, available > 0 {
            let count = min(maximumSegment,
                            remoteDeliveryBuffer.count - remoteDeliveryOffset,
                            available)
            let payload = TCPDeliverySlice.payload(
                from: remoteDeliveryBuffer, offset: remoteDeliveryOffset, count: count)
            let sequence = nextServerSequence
            guard let packet = owner?.writeTCP(key: key, sequence: sequence,
                                               acknowledgment: expectedClientSequence,
                                               flags: [.ack, .psh],
                                               window: advertisedReceiveWindow,
                                               payload: payload) else {
                // Hard write failure: stop draining so we do not advance the
                // sequence number over bytes the client will never see.
                remoteReadSuspended = true
                return
            }
            nextServerSequence &+= UInt32(count)
            outstanding.append(OutstandingSegment(packet: packet,
                                                  endSequence: nextServerSequence,
                                                  payloadBytes: count,
                                                  sentAt: Date(), retries: 0))
            outstandingPayloadByteCount += count
            owner?.recordTCPDownload(count)
            remoteDeliveryOffset += count
            available -= count
        }
        if remoteDeliveryOffset >= remoteDeliveryBuffer.count {
            remoteDeliveryBuffer.removeAll(keepingCapacity: true)
            remoteDeliveryOffset = 0
            finishRemoteEOFIfPossible()
        } else {
            remoteReadSuspended = true
        }
    }

    private func sendAcknowledgment() {
        let window = advertisedReceiveWindow
        lastAdvertisedReceiveWindow = window
        _ = owner?.writeTCP(key: key, sequence: nextServerSequence,
                            acknowledgment: expectedClientSequence, flags: [.ack],
                            window: window)
    }

    private func finishRemoteEOFIfPossible() {
        guard remoteEOFPending, remoteDeliveryBytes == 0, !remoteFinished else { return }
        let sequence = nextServerSequence
        guard let packet = owner?.writeTCP(key: key, sequence: sequence,
                                           acknowledgment: expectedClientSequence,
                                           flags: [.fin, .ack],
                                           window: advertisedReceiveWindow) else {
            return
        }
        remoteFinished = true
        nextServerSequence &+= 1
        outstanding.append(OutstandingSegment(packet: packet, endSequence: nextServerSequence,
                                              payloadBytes: 0,
                                              sentAt: Date(), retries: 0))
        remoteStream?.cancel(); remoteStream = nil
        if clientFinished && outstandingHead == outstanding.count {
            close(sendReset: false)
        }
    }

    private var receiveBufferCapacity: Int {
        guard let serverWindowScale else { return Int(UInt16.max) }
        return Int(UInt16.max) << Int(serverWindowScale)
    }

    private var advertisedReceiveWindow: UInt16 {
        let buffered = hajimi_tcp_reassembly_buffered(receiveState)
        let available = max(0, min(receiveBufferCapacity - pendingRemoteWriteBytes,
                                   remoteWrites.availableRoom) - buffered)
        let shift = Int(serverWindowScale ?? 0)
        return UInt16(min(Int(UInt16.max), available >> shift))
    }

    private var remoteDeliveryBytes: Int {
        max(0, remoteDeliveryBuffer.count - remoteDeliveryOffset)
    }

    private var availableClientDeliveryBytes: Int {
        max(0, min(maximumOutstandingPayloadBytes - outstandingPayloadByteCount,
                   clientAdvertisedWindow - outstandingPayloadByteCount))
    }

    private func firstRetransmittableIndex() -> Int? {
        SACKScoreboard.firstRetransmittable(in: outstanding, from: outstandingHead)
    }

    private func applySelectiveAcknowledgements(_ blocks: [SACKBlock]) {
        guard sackEnabled else { return }
        SACKScoreboard.apply(blocks, to: &outstanding, from: outstandingHead)
    }

    private func retransmit(at index: Int, now: Date) {
        guard index < outstanding.count else { return }
        outstanding[index].retries += 1
        outstanding[index].sentAt = now
        outstanding[index].retransmitted = true
        owner?.rewrite(outstanding[index].packet, version: key.version)
    }

    private func compactOutstandingIfNeeded() {
        guard outstandingHead >= 256,
              outstandingHead * 2 >= outstanding.count else { return }
        outstanding.removeFirst(outstandingHead)
        outstandingHead = 0
    }

}

// Kept internal to the module while allowing flow objects to attach their
// descriptor sources to the same serialization lane as packet processing.
extension NativeTunnel {
    fileprivate var queueForFlows: DispatchQueue { queue }
}

fileprivate final class UDPFlow {
    fileprivate let key: FlowKey
    fileprivate let upstreamQueue: DispatchQueue
    private weak var owner: NativeTunnel?
    private var session: NativeRoutedDatagram?
    private var pending: [Data] = []
    private var pendingBytes = 0
    private var ready = false
    private var closed = false
    private var lastActivity = Date()

    fileprivate var lastActivityDate: Date { lastActivity }

    init(key: FlowKey, owner: NativeTunnel) {
        self.key = key
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
        if removeFromOwner { owner?.removeUDP(self) }
    }

    private func sendNow(_ payload: Data) {
        session?.send(payload)
    }

    func received(_ payload: Data) {
        guard !closed else { return }
        lastActivity = Date()
        owner?.writeUDP(key: key, remoteAddress: key.remoteAddress,
                        remotePort: key.remotePort, payload: payload)
    }
}

/* Legacy local SOCKS bridge removed. NativeTunnel now connects through
   NativePacketRouter directly; no loopback proxy listener participates in
   enhanced-mode traffic. */
/*fileprivate enum SOCKSLocalConnector {
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

/*fileprivate struct SOCKSUDPResponse {
    let address: IPAddress
    let port: UInt16
    let payload: Data
}*/

/*fileprivate func parseSOCKSUDPResponse(_ bytes: [UInt8]) -> SOCKSUDPResponse? {
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

fileprivate enum PacketBuilder {
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
                options.append(contentsOf: [1, 1, 5, UInt8(2 + emitted.count * 8)])
                for block in emitted {
                    var encoded = Data()
                    append32(block.start, to: &encoded); append32(block.end, to: &encoded)
                    options.append(contentsOf: encoded)
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

private func internetChecksum(_ data: Data) -> UInt16 {
    foldChecksum(checksumSum(data))
}

/// The unfolded one's-complement 16-bit sum of a region.
///
/// The arithmetic itself lives in C, where there is no bounds checking on
/// every byte and the compiler is free to vectorise the loop. Leaving the sum
/// unfolded is what lets callers combine several regions and fold once.
private func checksumSum(_ data: Data) -> UInt64 {
    CDataPlane.checksumSum(data)
}

private func foldChecksum(_ value: UInt64) -> UInt16 {
    CDataPlane.fold(value)
}

private func read16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
    UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
}

private func read16(_ bytes: UnsafePointer<UInt8>, _ offset: Int) -> UInt16 {
    UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
}

private func read32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 |
        UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
}

private func read32(_ bytes: UnsafePointer<UInt8>, _ offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 |
        UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
}

private func append16(_ value: UInt16, to data: inout Data) {
    data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
}

private func append32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8(value >> 24)); data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff)); data.append(UInt8(value & 0xff))
}

private func sequenceGreaterOrEqual(_ lhs: UInt32, _ rhs: UInt32) -> Bool {
    hajimi_sequence_after_equal(lhs, rhs) != 0
}

private func sequenceGreater(_ lhs: UInt32, _ rhs: UInt32) -> Bool {
    hajimi_sequence_after(lhs, rhs) != 0
}

public enum NativeCoreSelfTest {
    public static func run() -> String? {
        let nativeFlowCode = hajimi_flow_self_test()
        if nativeFlowCode != 0 { return "C++ flow self-test failed: \(nativeFlowCode)" }
        let source = IPAddress.v4([1, 1, 1, 1])
        let destination = IPAddress.v4([198, 18, 0, 2])
        guard let packet = PacketBuilder.udp(version: .v4, source: source, sourcePort: 53,
                                             destination: destination, destinationPort: 50_000,
                                             payload: Data("hajimi".utf8), identifier: 7) else {
            return "IPv4/UDP packet codec self-test failed to build"
        }
        guard let parsed = ParsedIPPacket([UInt8](packet)),
              let udp = ParsedUDPDatagram(parsed), udp.sourcePort == 53,
              udp.destinationPort == 50_000, udp.payload == Data("hajimi".utf8),
              internetChecksum(packet.prefix(20)) == 0 else {
            return "IPv4/UDP packet codec self-test failed"
        }
        // Transport checksum must verify to 0 over the pseudo header + segment.
        // A bad checksum is dropped silently by the local stack and shows up as
        // "upload only" traffic in the dashboard.
        if !tcpTransportChecksumValid(packet: packet, version: .v4,
                                      source: source, destination: destination) {
            return "UDP transport checksum self-test failed"
        }
        let bulk = PacketBuilder.tcp(version: .v4, source: source, sourcePort: 443,
                                     destination: destination, destinationPort: 51_000,
                                     sequence: 1, acknowledgment: 2, flags: [.ack, .psh],
                                     window: 65_535,
                                     payload: Data(repeating: 0x5a, count: 1_460),
                                     maximumSegmentSize: nil, windowScale: nil,
                                     sackPermitted: false, identifier: 12)
        if !tcpTransportChecksumValid(packet: bulk, version: .v4,
                                      source: source, destination: destination) {
            return "TCP data-segment checksum self-test failed"
        }
        if let failure = CDataPlane.selfTestFailure() { return failure }
        if let failure = cBuiltPacketSelfTest(source: source, destination: destination) {
            return failure
        }
        // Oversized payloads must be refused: forcing them into UInt16 used to
        // trap inside the root helper.
        let oversized = Data(count: PacketBuilder.maximumUDPPayloadLength + 1)
        if PacketBuilder.udp(version: .v4, source: source, sourcePort: 53,
                             destination: destination, destinationPort: 50_000,
                             payload: oversized, identifier: 7) != nil {
            return "oversized UDP payload was framed instead of rejected"
        }
        if let failure = tcpReassemblySelfTest() { return failure }
        let v6Source = IPAddress.v6(Array(repeating: 0, count: 15) + [1])
        let v6Destination = IPAddress.v6([0xfd, 0, 0x71, 0x62] + Array(repeating: 0, count: 11) + [2])
        let tcp = PacketBuilder.tcp(version: .v6, source: v6Source, sourcePort: 443,
                                    destination: v6Destination, destinationPort: 51_000,
                                    sequence: 10, acknowledgment: 20, flags: [.ack, .psh],
                                    window: 65_535, payload: Data([1, 2, 3]),
                                    maximumSegmentSize: nil, windowScale: nil,
                                    sackPermitted: false, identifier: 0)
        guard let parsed6 = ParsedIPPacket([UInt8](tcp)),
              let segment = ParsedTCPSegment(parsed6), segment.sequence == 10,
              segment.acknowledgment == 20, segment.payload == Data([1, 2, 3]) else {
            return "IPv6/TCP packet codec self-test failed"
        }
        let syn = PacketBuilder.tcp(version: .v4, source: source, sourcePort: 443,
                                    destination: destination, destinationPort: 51_001,
                                    sequence: 30, acknowledgment: 40, flags: [.syn, .ack],
                                    window: .max, payload: Data(),
                                    maximumSegmentSize: 1_460, windowScale: 6,
                                    sackPermitted: true, identifier: 8)
        guard let parsedSYN = ParsedIPPacket([UInt8](syn)),
              let synSegment = ParsedTCPSegment(parsedSYN),
              synSegment.windowScale == 6, synSegment.sackPermitted,
              internetChecksum(syn.prefix(20)) == 0 else {
            return "TCP window-scale option self-test failed"
        }
        if let failure = sackOptionSelfTest(source: source, destination: destination) {
            return failure
        }
        if let failure = retransmissionTimerSelfTest() { return failure }
        if let failure = sackScoreboardSelfTest() { return failure }
        if let failure = tcpCoalesceSelfTest() { return failure }
        if let failure = tcpDeliverySliceSelfTest() { return failure }
        if let failure = flowAdmissionSelfTest() { return failure }
        if let failure = icmpEchoReplySelfTest(source: source, destination: destination) {
            return failure
        }
        let unreachable = PacketBuilder.icmpPortUnreachable(original: parsed,
                                                             identifier: 9)
        guard let parsedICMP = ParsedIPPacket([UInt8](unreachable)),
              parsedICMP.transportProtocol == 1,
              parsedICMP.bytes[parsedICMP.transportOffset] == 3,
              parsedICMP.bytes[parsedICMP.transportOffset + 1] == 3,
              internetChecksum(Data(parsedICMP.bytes[
                parsedICMP.transportOffset..<parsedICMP.payloadEnd])) == 0 else {
            return "ICMP UDP fallback self-test failed"
        }
        return nil
    }

    private static func tcpTransportChecksumValid(packet: Data, version: IPVersion,
                                                  source: IPAddress,
                                                  destination: IPAddress) -> Bool {
        let headerLength: Int
        let nextHeader: UInt8
        switch version {
        case .v4:
            guard packet.count >= 20 else { return false }
            headerLength = Int(packet[0] & 0x0f) * 4
            nextHeader = packet[9]
        case .v6:
            guard packet.count >= 40 else { return false }
            headerLength = 40
            nextHeader = packet[6]
        }
        guard packet.count >= headerLength else { return false }
        let transport = Data(packet[headerLength..<packet.count])
        var pseudo = Data()
        pseudo.append(contentsOf: source.bytes)
        pseudo.append(contentsOf: destination.bytes)
        switch version {
        case .v4:
            pseudo.append(0); pseudo.append(nextHeader)
            append16(UInt16(transport.count), to: &pseudo)
        case .v6:
            append32(UInt32(transport.count), to: &pseudo)
            pseudo.append(contentsOf: [0, 0, 0, nextHeader])
        }
        // Valid on-wire checksum folds to 0 when the field is included.
        return foldChecksum(checksumSum(pseudo) &+ checksumSum(transport)) == 0
    }

    /// A missing middle segment must not drop the bytes that already arrived
    /// after the hole; once the hole fills, the whole run is released in order.
    private static func tcpReassemblySelfTest() -> String? {
        var state = TCPReceiveReassembly.State(expected: 1_000)
        let first = Data([1, 2, 3])
        let second = Data([4, 5])
        let third = Data([6, 7, 8, 9])
        // Second and third arrive first.
        let early = TCPReceiveReassembly.ingest(payload: second, sequence: 1_003, into: &state,
                                                limitBytes: 64 * 1_024, limitSegments: 64)
        guard early.isEmpty, state.buffered.count == 1 else {
            return "out-of-order segment was not parked"
        }
        _ = TCPReceiveReassembly.ingest(payload: third, sequence: 1_005, into: &state,
                                        limitBytes: 64 * 1_024, limitSegments: 64)
        TCPReceiveReassembly.noteFin(sequence: 1_009, into: &state)
        guard !state.finished, state.pendingFin == 1_009 else {
            return "FIN ahead of the gap was not deferred"
        }
        let released = TCPReceiveReassembly.ingest(payload: first, sequence: 1_000, into: &state,
                                                   limitBytes: 64 * 1_024, limitSegments: 64)
        guard released == [first, second, third] else {
            return "reassembly did not release contiguous payload in order"
        }
        guard state.finished, state.expected == 1_010, state.buffered.isEmpty else {
            return "reassembly did not consume the deferred FIN"
        }
        // Retransmissions of already-accepted bytes must be ignored.
        let dup = TCPReceiveReassembly.ingest(payload: first, sequence: 1_000, into: &state,
                                              limitBytes: 64 * 1_024, limitSegments: 64)
        guard dup.isEmpty else { return "duplicate payload was accepted again" }
        return nil
    }

    /// Round-trips SACK blocks through the builder and the parser, and checks
    /// that a truncated block list is rejected rather than over-read — this
    /// parser consumes bytes straight off utun.
    private static func sackOptionSelfTest(source: IPAddress,
                                           destination: IPAddress) -> String? {
        let blocks = [SACKBlock(start: 1_000, end: 2_000),
                      SACKBlock(start: 3_000, end: 4_500),
                      SACKBlock(start: 9_000, end: 9_100)]
        let packet = PacketBuilder.tcp(version: .v4, source: source, sourcePort: 443,
                                       destination: destination, destinationPort: 51_002,
                                       sequence: 100, acknowledgment: 200, flags: [.ack],
                                       window: 65_535, payload: Data(),
                                       maximumSegmentSize: nil, windowScale: nil,
                                       sackPermitted: false, sackBlocks: blocks,
                                       identifier: 11)
        guard let parsedPacket = ParsedIPPacket([UInt8](packet)),
              let segment = ParsedTCPSegment(parsedPacket),
              internetChecksum(packet.prefix(20)) == 0 else {
            return "SACK packet failed to parse"
        }
        guard segment.sackBlocks.count == blocks.count else {
            return "SACK block count mismatch: \(segment.sackBlocks.count) != \(blocks.count)"
        }
        for (index, block) in blocks.enumerated() {
            guard segment.sackBlocks[index].start == block.start,
                  segment.sackBlocks[index].end == block.end else {
                return "SACK block \(index) round-trip mismatch"
            }
        }
        guard segment.acknowledgment == 200, segment.payload.isEmpty else {
            return "SACK packet corrupted the surrounding header"
        }
        // A block list whose declared length is not a whole number of blocks
        // must be ignored, not partially consumed.
        var malformed = [UInt8](packet)
        let optionOffset = parsedPacket.transportOffset + 20
        malformed[optionOffset + 3] = 9 // length 9 is not 2 + 8n
        if let reparsed = ParsedIPPacket(malformed),
           let segment = ParsedTCPSegment(reparsed), !segment.sackBlocks.isEmpty {
            return "malformed SACK option length was accepted"
        }
        return nil
    }

    /// The echo reply is handed back to the client's own stack, so a malformed
    /// header means ping stays broken in a way that looks like packet loss.
    private static func icmpEchoReplySelfTest(source: IPAddress,
                                              destination: IPAddress) -> String? {
        // A real echo reply: type 0, code 0, checksum, id, sequence, payload.
        var message = Data([0, 0, 0, 0, 0x12, 0x34, 0x00, 0x01])
        message.append(contentsOf: Array(0..<32).map { UInt8($0) })
        let checksum = internetChecksum(message)
        message.replaceSubrange(2..<4, with: [UInt8(checksum >> 8), UInt8(checksum & 0xff)])

        let packet = PacketBuilder.icmpEchoReply(source: source, destination: destination,
                                                 message: message, identifier: 77)
        guard let parsed = ParsedIPPacket([UInt8](packet)) else {
            return "ICMP echo reply failed to parse"
        }
        guard parsed.transportProtocol == 1 else { return "ICMP echo reply has wrong protocol" }
        guard internetChecksum(packet.prefix(20)) == 0 else {
            return "ICMP echo reply IPv4 header checksum invalid"
        }
        let body = Data(parsed.bytes[parsed.transportOffset..<parsed.payloadEnd])
        guard body == message else { return "ICMP echo reply body was altered" }
        guard internetChecksum(body) == 0 else {
            return "ICMP echo reply message checksum invalid"
        }
        // Addresses are swapped relative to the request: the reply appears to
        // come from the host that was pinged.
        guard parsed.source == source, parsed.destination == destination else {
            return "ICMP echo reply addresses are not the pinged host and the client"
        }
        return nil
    }

    /// Pins the behaviour SACK exists for: when a single segment in the middle
    /// of the window is lost, retransmission must resend only that segment
    /// rather than restarting from the cumulative acknowledgement.
    private static func sackScoreboardSelfTest() -> String? {
        // Ten 100-byte segments starting at sequence 1000.
        var segments: [OutstandingSegment] = (0..<10).map { index in
            let end = UInt32(1_000 + (index + 1) * 100)
            return OutstandingSegment(packet: Data([UInt8(index)]), endSequence: end,
                                      payloadBytes: 100, sentAt: Date(), retries: 0)
        }
        guard SACKScoreboard.firstRetransmittable(in: segments, from: 0) == 0 else {
            return "with no SACK the head segment must be retransmitted"
        }

        // The peer holds everything except segment index 2 ([1200, 1300)).
        let blocks = [SACKBlock(start: 1_000, end: 1_200),
                      SACKBlock(start: 1_300, end: 2_000)]
        SACKScoreboard.apply(blocks, to: &segments, from: 0)
        for (index, segment) in segments.enumerated() {
            let expected = index != 2
            guard segment.sacked == expected else {
                return "segment \(index) sacked=\(segment.sacked), expected \(expected)"
            }
        }
        guard SACKScoreboard.firstRetransmittable(in: segments, from: 0) == 2 else {
            return "retransmission did not skip the selectively acknowledged segments"
        }

        // Once the hole is filled there is nothing left to resend.
        SACKScoreboard.apply([SACKBlock(start: 1_200, end: 1_300)], to: &segments, from: 0)
        guard SACKScoreboard.firstRetransmittable(in: segments, from: 0) == nil else {
            return "fully acknowledged window still reported a retransmission"
        }

        // A block that only partially covers a segment proves nothing.
        var partial: [OutstandingSegment] = [
            OutstandingSegment(packet: Data(), endSequence: 1_100, payloadBytes: 100,
                               sentAt: Date(), retries: 0)
        ]
        SACKScoreboard.apply([SACKBlock(start: 1_000, end: 1_050)], to: &partial, from: 0)
        guard partial[0].sacked == false else {
            return "a partially covered segment was treated as acknowledged"
        }

        // Sequence numbers wrapping past 2^32 must still compare correctly.
        var wrapped: [OutstandingSegment] = [
            OutstandingSegment(packet: Data(), endSequence: 50, payloadBytes: 100,
                               sentAt: Date(), retries: 0)
        ]
        SACKScoreboard.apply([SACKBlock(start: UInt32.max &- 49, end: 50)],
                             to: &wrapped, from: 0)
        guard wrapped[0].sacked else { return "SACK failed across a sequence wrap" }
        return nil
    }

    /// C-built no-option packets must parse and checksum identically to the
    /// Swift PacketBuilder path they replace on the download hot path.
    private static func cBuiltPacketSelfTest(source: IPAddress,
                                             destination: IPAddress) -> String? {
        let payload = Data("hajimi".utf8)
        let sourceBytes = source.bytes
        let destinationBytes = destination.bytes
        var buffer = [UInt8](repeating: 0, count: 128)
        let tcpLength = buffer.withUnsafeMutableBytes { out -> Int in
            sourceBytes.withUnsafeBufferPointer { src in
                destinationBytes.withUnsafeBufferPointer { dst in
                    payload.withUnsafeBytes { body in
                        CDataPlane.buildTCP(into: out, version: 4,
                                            source: src.baseAddress!,
                                            sourceLength: 4, sourcePort: 443,
                                            destinationAddress: dst.baseAddress!,
                                            destinationPort: 51_000,
                                            sequence: 1, acknowledgment: 2,
                                            flags: TCPFlags([.ack, .psh]).rawValue,
                                            window: 65_535, payload: body,
                                            identifier: 12)
                    }
                }
            }
        }
        guard tcpLength == 40 + payload.count else {
            return "C IPv4/TCP builder wrote \(tcpLength) bytes"
        }
        let tcpPacket = Data(buffer.prefix(tcpLength))
        guard let parsed = ParsedIPPacket([UInt8](tcpPacket)),
              let segment = ParsedTCPSegment(parsed),
              segment.sequence == 1, segment.acknowledgment == 2,
              segment.payload == payload,
              internetChecksum(tcpPacket.prefix(20)) == 0,
              tcpTransportChecksumValid(packet: tcpPacket, version: .v4,
                                        source: source, destination: destination) else {
            return "C IPv4/TCP builder produced an invalid packet"
        }
        let udpLength = buffer.withUnsafeMutableBytes { out -> Int in
            sourceBytes.withUnsafeBufferPointer { src in
                destinationBytes.withUnsafeBufferPointer { dst in
                    payload.withUnsafeBytes { body in
                        CDataPlane.buildUDP(into: out, version: 4,
                                            source: src.baseAddress!,
                                            sourceLength: 4, sourcePort: 53,
                                            destinationAddress: dst.baseAddress!,
                                            destinationPort: 50_000,
                                            payload: body, identifier: 7)
                    }
                }
            }
        }
        guard udpLength == 28 + payload.count else {
            return "C IPv4/UDP builder wrote \(udpLength) bytes"
        }
        let udpPacket = Data(buffer.prefix(udpLength))
        guard let parsedUDP = ParsedIPPacket([UInt8](udpPacket)),
              let datagram = ParsedUDPDatagram(parsedUDP),
              datagram.sourcePort == 53, datagram.destinationPort == 50_000,
              datagram.payload == payload,
              internetChecksum(udpPacket.prefix(20)) == 0,
              tcpTransportChecksumValid(packet: udpPacket, version: .v4,
                                        source: source, destination: destination) else {
            return "C IPv4/UDP builder produced an invalid packet"
        }
        return nil
    }

    /// A full table must refuse new work; only flows past the idle window
    /// are eligible for eviction so a live YouTube playback is not reset.
    private static func flowAdmissionSelfTest() -> String? {
        guard FlowAdmission.shouldAdmit(current: 0, maximum: FlowAdmission.maximumTCPFlows) else {
            return "empty TCP table was not admitted"
        }
        guard !FlowAdmission.shouldAdmit(current: FlowAdmission.maximumTCPFlows,
                                         maximum: FlowAdmission.maximumTCPFlows) else {
            return "full TCP table was still admitted"
        }
        guard !FlowAdmission.shouldAdmit(current: FlowAdmission.maximumUDPFlows,
                                         maximum: FlowAdmission.maximumUDPFlows) else {
            return "full UDP table was still admitted"
        }
        let now = Date()
        guard FlowAdmission.isIdle(lastActivity: now.addingTimeInterval(-20), now: now,
                                   limit: FlowAdmission.tcpIdleEviction) else {
            return "idle TCP flow was not eligible for eviction"
        }
        guard !FlowAdmission.isIdle(lastActivity: now.addingTimeInterval(-1), now: now,
                                    limit: FlowAdmission.tcpIdleEviction) else {
            return "active TCP flow was treated as idle"
        }
        guard FlowAdmission.isIdle(lastActivity: now.addingTimeInterval(-10), now: now,
                                   limit: FlowAdmission.udpIdleEviction) else {
            return "idle UDP flow was not eligible for eviction"
        }
        guard FlowAdmission.maximumTCPFlows >= 256, FlowAdmission.maximumUDPFlows >= 128 else {
            return "flow caps are too small for ordinary browsing"
        }
        return nil
    }

    /// Small consecutive uploads must become one write; a single large chunk
    /// must stay a single write; the 64 KiB budget must not swallow the next
    /// chunk that would overflow it.
    private static func tcpCoalesceSelfTest() -> String? {
        let small = (0..<8).map { Data(repeating: UInt8($0), count: 1_460) }
        let merged = TCPWriteCoalesce.merge(small, from: 0, limit: 64 * 1_024)
        guard merged.chunkCount == 8, merged.byteCount == 8 * 1_460,
              merged.payload.count == merged.byteCount else {
            return "small upload burst was not coalesced"
        }
        let leftover = TCPWriteCoalesce.merge(small, from: 7, limit: 64 * 1_024)
        guard leftover.chunkCount == 1, leftover.payload == small[7] else {
            return "tail chunk coalesce lost the original Data"
        }
        let oversized = [Data(count: 70_000), Data(count: 100)]
        let firstOnly = TCPWriteCoalesce.merge(oversized, from: 0, limit: 64 * 1_024)
        guard firstOnly.chunkCount == 1, firstOnly.byteCount == 70_000 else {
            return "over-budget first chunk was not sent alone"
        }
        let mixed = [Data(count: 30_000), Data(count: 30_000), Data(count: 10_000)]
        let two = TCPWriteCoalesce.merge(mixed, from: 0, limit: 64 * 1_024)
        guard two.chunkCount == 2, two.byteCount == 60_000 else {
            return "coalesce crossed the 64 KiB budget"
        }
        let empty = TCPWriteCoalesce.merge([], from: 0, limit: 64 * 1_024)
        guard empty.chunkCount == 0, empty.payload.isEmpty else {
            return "empty write queue produced a payload"
        }
        return nil
    }

    /// A sliced `Data` (the shape Network.framework returns) must be addressed
    /// by `startIndex + offset`, not by a 0-based range. The old path trapped
    /// in Foundation the first time a download ACK flushed such a buffer.
    private static func tcpDeliverySliceSelfTest() -> String? {
        let backing = Data((0..<64).map { UInt8($0) })
        let window = backing[16..<48]
        guard window.count == 32 else { return "sliced delivery window has wrong count" }
        let head = TCPDeliverySlice.payload(from: window, offset: 0, count: 8)
        guard Array(head) == Array(16..<24) else {
            return "offset 0 into a non-zero startIndex window was wrong"
        }
        let mid = TCPDeliverySlice.payload(from: window, offset: 8, count: 8)
        guard Array(mid) == Array(24..<32) else {
            return "offset 8 into a non-zero startIndex window was wrong"
        }
        // The assignment used on the first receive must also rebase.
        let copied = window.startIndex == 0 ? window : Data(window)
        guard copied.startIndex == 0, Array(copied) == Array(16..<48) else {
            return "rebasing a sliced receive buffer lost bytes"
        }
        return nil
    }

    /// Pins the RFC 6298 estimator: it must converge near the observed round
    /// trip on a local link instead of sitting at the old fixed 750 ms, and it
    /// must stay inside its clamps.
    private static func retransmissionTimerSelfTest() -> String? {
        var timer = RetransmissionTimer()
        guard timer.timeout == 0.2 else { return "initial RTO should be 200 ms" }

        // First sample seeds SRTT directly: RTO = R + max(G, 4 * R/2).
        timer.update(sample: 0.010)
        guard let seeded = timer.smoothedRTT, abs(seeded - 0.010) < 1e-9 else {
            return "first RTT sample did not seed SRTT"
        }
        guard abs(timer.timeout - 0.030) < 1e-6 else {
            return "seeded RTO should be 30 ms, got \(timer.timeout)"
        }

        // A stable link drives the estimate down towards the floor.
        for _ in 0..<200 { timer.update(sample: 0.002) }
        guard timer.timeout <= 0.05 else {
            return "RTO failed to converge on a fast link: \(timer.timeout)"
        }
        guard timer.timeout >= RetransmissionTimer.minimum else {
            return "RTO fell below its floor: \(timer.timeout)"
        }

        // Backoff is bounded, and non-positive or non-finite samples are ignored.
        guard timer.timeout(retries: 0) == timer.timeout,
              timer.timeout(retries: 1) > timer.timeout(retries: 0),
              timer.timeout(retries: 30) == RetransmissionTimer.maximum else {
            return "RTO backoff is not monotonic and bounded"
        }
        let stable = timer.timeout
        timer.update(sample: 0)
        timer.update(sample: -1)
        timer.update(sample: .infinity)
        guard timer.timeout == stable else { return "invalid RTT samples perturbed the estimate" }

        // A slow link must not exceed the ceiling.
        var slow = RetransmissionTimer()
        for _ in 0..<50 { slow.update(sample: 30) }
        guard slow.timeout == RetransmissionTimer.maximum else {
            return "RTO exceeded its ceiling on a slow link: \(slow.timeout)"
        }
        return nil
    }
}

// MARK: - ICMP

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
fileprivate final class ICMPEchoRelay {
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
    private var readSource: DispatchSourceRead?
    private var pending: [PendingKey: Pending] = [:]

    init(queue: DispatchQueue, owner: NativeTunnel) {
        self.queue = queue
        self.owner = owner
    }

    /// Opens the socket lazily: a session that never pings should not hold one.
    private func ensureSocket() -> Bool {
        if descriptor >= 0 { return true }
        // SOCK_DGRAM/IPPROTO_ICMP sends echo without the raw-socket privileges,
        // and the kernel handles the outer IP header for us.
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return false }
        // The reply must not come back through the tunnel that produced the
        // request, or the relay would feed itself.
        if let name = NativeTunnel.physicalInterfaceName {
            var index = UInt32(if_nametoindex(name))
            if index > 0 {
                _ = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index,
                               socklen_t(MemoryLayout<UInt32>.size))
            }
        }
        let flags = fcntl(fd, F_GETFL, 0)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
        descriptor = fd
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.drainReplies() }
        source.setCancelHandler {}
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
        readSource?.cancel(); readSource = nil
        if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
        pending.removeAll()
    }
}

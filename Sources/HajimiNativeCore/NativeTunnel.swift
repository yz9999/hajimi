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

/// Yield at a packet boundary: even fewer than 1024 DNS packets can take a
/// long time to prepare. A continuously readable utun must leave time for
/// downstream delivery, ACKs, maintenance and stop work on the same queue.
/// This is a scheduling budget, not preemption of an individual packet.
struct PacketDrainBudget {
    static let maximumPackets = 1_024
    static let maximumNanoseconds: UInt64 = 2_000_000
    let started: UInt64

    func shouldContinue(processed: Int, at now: UInt64) -> Bool {
        guard processed >= 0, processed < Self.maximumPackets, now >= started else { return false }
        return now - started < Self.maximumNanoseconds
    }
}

/// Present only in the explicitly admitted AF_UNIX packet-load fixture. These
/// are operation counts, not allocator/RSS or kernel packet-tap measurements.
final class NativeTunnelPacketLoadCounters {
    var packets = 0, acknowledgmentPackets = 0, selectiveAcknowledgmentPackets = 0
    var sackSegmentVisits = 0, sackApplications = 0, sackCacheHits = 0
    var outstandingCreated = 0, outstandingAcknowledged = 0, outstandingPeak = 0
    var outstandingCompactions = 0, outstandingSlotsMoved = 0, outstandingStoredPeak = 0
    var downloadAppends = 0, downloadRebases = 0, downloadRebasedTailBytes = 0
    var downloadBufferedPeak = 0, downloadStoredPeak = 0, downloadRetainedPrefixPeak = 0
    var downloadStorageBoundViolations = 0, maintenanceTicks = 0, maintenanceSnapshotReferences = 0
    var drainTurns = 0, drainPacketsPeak = 0
    var drainNanosecondsPeak: UInt64 = 0
    var queueProbeNanoseconds: [UInt64] = []

    func report() -> [String: Any] {
        let probes = queueProbeNanoseconds.sorted()
        return ["packets": packets, "acknowledgmentPackets": acknowledgmentPackets,
                "selectiveAcknowledgmentPackets": selectiveAcknowledgmentPackets,
                "sackApplications": sackApplications, "sackSegmentVisits": sackSegmentVisits,
                "sackCacheHits": sackCacheHits,
                "outstandingCreated": outstandingCreated, "outstandingAcknowledged": outstandingAcknowledged,
                "outstandingPeak": outstandingPeak, "outstandingStoredPeak": outstandingStoredPeak,
                "outstandingCompactions": outstandingCompactions, "outstandingSlotsMoved": outstandingSlotsMoved,
                "downloadAppends": downloadAppends, "downloadRebases": downloadRebases,
                "downloadRebasedTailBytes": downloadRebasedTailBytes, "downloadBufferedPeak": downloadBufferedPeak,
                "downloadStoredPeak": downloadStoredPeak, "downloadRetainedPrefixPeak": downloadRetainedPrefixPeak,
                "downloadStorageBoundViolations": downloadStorageBoundViolations,
                "maintenanceTicks": maintenanceTicks, "maintenanceSnapshotReferences": maintenanceSnapshotReferences,
                "drainTurns": drainTurns, "drainPacketsPeak": drainPacketsPeak,
                "drainMaximumMilliseconds": Double(drainNanosecondsPeak) / 1_000_000,
                "queueProbeCount": probes.count,
                "queueProbeP95Milliseconds": probes.isEmpty ? 0 : Double(probes[min(probes.count - 1, Int(Double(probes.count) * 0.95))]) / 1_000_000,
                "queueProbeMaximumMilliseconds": Double(probes.last ?? 0) / 1_000_000]
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

    static let queueSpecificKey = DispatchSpecificKey<Bool>()
    private let queue = DispatchQueue(label: "app.hajimi.native-tunnel", qos: .userInitiated,
                                      autoreleaseFrequency: .workItem)
    /// Shared outbound lanes. A private DispatchQueue per TCP/UDP flow used to
    /// create thousands of queues under a YouTube 4K burst and jetsam the App.
    static let upstreamQueueCount = 8
    private static let sharedUpstreamQueues: [DispatchQueue] = (0..<upstreamQueueCount).map { index in
        DispatchQueue(label: "app.hajimi.native-tunnel.upstream.\(index)",
                      qos: .userInitiated, autoreleaseFrequency: .workItem)
    }
    private var descriptor: Int32 = -1
    private var readSource: DispatchSourceRead?
    private let readerReadiness = NativeTunnelReaderReadiness()
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
    private var maintenanceTickParity: UInt8 = 0
    private var pendingFlowEvents: [ProxyEngineEvent] = []
    private var pendingFlowCloses: [UUID] = []
    /// Explicit CLI-only memory regression hook. Ordinary initializers never
    /// install a connector or override transport sequence numbers.
    private var streamRegressionConnector: (() -> NativeOutboundByteStream)?
    var streamRegressionInitialSequence: UInt32?
    var packetLoadCounters: NativeTunnelPacketLoadCounters?

    public init(router: NativePacketRouter) throws {
        self.router = router
        queue.setSpecific(key: Self.queueSpecificKey, value: true)
    }

    static func makeStreamRegressionFixture(stream: NativeOutboundByteStream,
                                            initialSequence: UInt32,
                                            packetLoadCounters: NativeTunnelPacketLoadCounters? = nil) throws -> NativeTunnel {
        guard (CommandLine.arguments.contains("--native-tunnel-stream-self-test") ||
               CommandLine.arguments.contains("--native-tunnel-packet-load-self-test")),
              ProxyEngine.currentOutboundInterface == nil else {
            throw NativeTunnelError.utun("Native stream memory fixture requires its isolated CLI flag")
        }
        // An accidentally unhandled target fails closed; the fixture must
        // never construct a physical TCP/UDP/DNS connection.
        let profile = try ProfileParser.parse("[Rule]\nFINAL,REJECT\n")
        let router = NativePacketRouter(profile: profile, mode: .rule, globalPolicy: "REJECT", groupSelections: [:])
        let tunnel = try NativeTunnel(router: router)
        tunnel.streamRegressionConnector = { stream }
        tunnel.streamRegressionInitialSequence = initialSequence
        tunnel.packetLoadCounters = packetLoadCounters
        return tunnel
    }

    /// The probe is serialized with the actual descriptor source. A busy
    /// packet reader must yield before this queue work can complete.
    func packetLoadProbe() -> Int {
        let started = DispatchTime.now().uptimeNanoseconds
        return queue.sync {
            packetLoadCounters?.queueProbeNanoseconds.append(DispatchTime.now().uptimeNanoseconds - started)
            return packetLoadCounters?.acknowledgmentPackets ?? 0
        }
    }

    deinit { stop() }

    /// Starts packet processing on a utun already opened by the privileged
    /// helper. Addresses and routes stay with the helper; this process only
    /// reads and writes packets.
    @discardableResult
    public func start(fileDescriptor: Int32, interfaceName: String) throws -> String {
        if self.interfaceName == interfaceName, descriptor == fileDescriptor, descriptor >= 0 { return interfaceName }
        stop()
        stopRequested.value = false
        guard fileDescriptor >= 0 else { throw NativeTunnelError.utun("无效的 utun 描述符") }
        let flags = fcntl(fileDescriptor, F_GETFL, 0)
        guard flags >= 0, fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            // This method takes ownership of a handed-off descriptor. The
            // time budget cannot protect a blocking read; fail closed and
            // release the handoff rather than attaching an unsafe reader.
            Darwin.close(fileDescriptor)
            throw NativeTunnelError.utun("无法配置 utun 非阻塞描述符")
        }
        for candidate in [Int32(4 * 1024 * 1024), Int32(2 * 1024 * 1024), Int32(1 * 1024 * 1024)] {
            var bufSize = candidate
            if setsockopt(fileDescriptor, SOL_SOCKET, SO_RCVBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size)) == 0 { break }
        }
        for candidate in [Int32(4 * 1024 * 1024), Int32(2 * 1024 * 1024), Int32(1 * 1024 * 1024)] {
            var bufSize = candidate
            if setsockopt(fileDescriptor, SOL_SOCKET, SO_SNDBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size)) == 0 { break }
        }
        descriptor = fileDescriptor
        self.interfaceName = interfaceName
        stopped = false
        let readerEpoch = readerReadiness.begin()

        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        source.setRegistrationHandler { [weak self] in
            guard let self, !self.stopRequested.value, !self.stopped,
                  self.descriptor == fileDescriptor else { return }
            self.readerReadiness.confirm(readerEpoch)
        }
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

    /// Call before asking the Helper to capture system traffic. `resume()`
    /// alone is insufficient: libdispatch must acknowledge source registration
    /// on the actual packet queue. No public network probe is required.
    public func waitUntilReaderReady(timeout: TimeInterval = 2) throws {
        guard DispatchQueue.getSpecific(key: Self.queueSpecificKey) == nil else {
            throw NativeTunnelError.utun("不能在收包队列内等待收包就绪")
        }
        try readerReadiness.wait(timeout: timeout)
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
        readerReadiness.invalidate()
        let cleanup = {
            guard !self.stopped else { return }
            self.stopped = true
            self.maintenanceTimer?.cancel()
            self.maintenanceTimer = nil
            self.readSource?.cancel()
            self.readSource = nil
            self.icmpRelay.stop()
            self.writeSource?.cancel()
            self.writeSource = nil
            self.pendingFrames.removeAll(keepingCapacity: false)
            self.pendingFrameHead = 0
            self.pendingFrameBytes = 0
            let tcp = Array(self.tcpFlows.values)
            let udp = Array(self.udpFlows.values)
            self.tcpFlows.removeAll(keepingCapacity: false)
            self.udpFlows.removeAll(keepingCapacity: false)
            tcp.forEach { $0.close(sendReset: false, removeFromOwner: false) }
            udp.forEach { $0.close(removeFromOwner: false) }
            self.flushFlowEventsIfNeeded()
            if self.descriptor >= 0 { Darwin.close(self.descriptor); self.descriptor = -1 }
            self.interfaceName = nil
        }
        if DispatchQueue.getSpecific(key: Self.queueSpecificKey) != nil { cleanup() }
        else { queue.sync(execute: cleanup) }
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
            icmpRelay.stop()
            tcp.forEach { $0.close(sendReset: true, removeFromOwner: false) }
            udp.forEach { $0.close(removeFromOwner: false) }
            flushFlowEventsIfNeeded()
        }
    }

    private func drainPackets() {
        guard descriptor >= 0, !stopped else { return }
        // A full-route utun can remain readable continuously. Bound each
        // dispatch-source turn by both count and elapsed work. Returning
        // leaves unread packets on the read source; they are not discarded.
        let budget = PacketDrainBudget(started: DispatchTime.now().uptimeNanoseconds)
        var processed = 0
        readBuffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            while !stopRequested.value,
                  budget.shouldContinue(processed: processed, at: DispatchTime.now().uptimeNanoseconds) {
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
        if let counters = packetLoadCounters {
            counters.drainTurns += 1
            counters.drainPacketsPeak = max(counters.drainPacketsPeak, processed)
            counters.drainNanosecondsPeak = max(counters.drainNanosecondsPeak,
                DispatchTime.now().uptimeNanoseconds - budget.started)
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
        if let counters = packetLoadCounters {
            counters.packets += 1
            if segment.flags.contains(.ack) { counters.acknowledgmentPackets += 1 }
            if !segment.sackBlocks.isEmpty { counters.selectiveAcknowledgmentPackets += 1 }
        }
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
        recordFlowOpened(id: flow.id, key: key, isTCP: true)
        flow.start()
    }

    private func handleUDP(_ packet: ParsedIPPacket, datagram: ParsedUDPDatagram,
                           originalBytes: UnsafeRawBufferPointer) {
        let key = FlowKey(version: packet.version, transportProtocol: 17,
                          clientAddress: packet.source, clientPort: datagram.sourcePort,
                          remoteAddress: packet.destination, remotePort: datagram.destinationPort)
        let currentGen = router.currentConfigurationGeneration
        if let existing = udpFlows[key], existing.routingGeneration == currentGen {
            existing.send(datagram.payload)
            uploadedByteCount &+= UInt64(datagram.payload.count)
            existing.unreportedUploadBytes &+= datagram.payload.count
            return
        }
        func rejectWithICMP() {
            guard let quoted = ParsedIPPacket(copying: originalBytes) else { return }
            writeICMPPortUnreachable(for: quoted)
        }
        let destHost = packet.destination.hostString
        let srcHost = packet.source.hostString
        // QUIC loses its loss-recovery advantage when a stream-only proxy
        // (VMess/VLESS/Trojan/Snell/AnyTLS) carries every UDP packet over a
        // reliable TCP byte stream.  One lost outer TCP segment then blocks
        // all later QUIC packets.  Tell the local stack that UDP/443 is
        // unavailable so browsers immediately retry the same origin over
        // HTTPS/TCP.  Native UDP transports (DIRECT, SS/SSR, HY/TUIC) keep
        // QUIC enabled.
        if datagram.destinationPort == 443,
           router.prefersTCPFallbackForQUIC(host: destHost,
               sourceHost: srcHost, sourcePort: datagram.sourcePort) {
            if let stale = udpFlows.removeValue(forKey: key) { stale.close(removeFromOwner: false) }
            rejectWithICMP()
            return
        }
        // The outbound cannot carry this datagram. Saying so costs one packet;
        // staying silent costs the application its full timeout on every
        // attempt, which is indistinguishable from a dead network.
        if router.rejectsUDP(host: destHost,
                             port: datagram.destinationPort,
                             sourceHost: srcHost, sourcePort: datagram.sourcePort) {
            if let stale = udpFlows.removeValue(forKey: key) { stale.close(removeFromOwner: false) }
            rejectWithICMP()
            return
        }
        if let stale = udpFlows.removeValue(forKey: key) {
            stale.close(removeFromOwner: false)
        }
        if udpFlows.count >= FlowAdmission.maximumUDPFlows {
            if !evictIdleUDP() {
                rejectWithICMP()
                return
            }
        }
        totalFlowCount += 1
        let flow = UDPFlow(key: key, routingGeneration: currentGen, owner: self)
        udpFlows[key] = flow
        recordFlowOpened(id: flow.id, key: key, isTCP: false)
        flow.start()
        flow.send(datagram.payload)
        uploadedByteCount &+= UInt64(datagram.payload.count)
        flow.unreportedUploadBytes &+= datagram.payload.count
    }

    func connectTCPFlow(_ flow: TCPFlow) {
        if let streamRegressionConnector {
            guard flow.key.remoteAddress.hostString == "203.0.113.7", flow.key.remotePort == 9443 else {
                flow.connected(.failure(NativeTunnelError.utun("Unexpected memory fixture target")))
                return
            }
            flow.connected(.success(streamRegressionConnector()))
            return
        }
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

    func connectUDPFlow(_ flow: UDPFlow) {
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

    func removeTCP(_ flow: TCPFlow) {
        if tcpFlows[flow.key] === flow { tcpFlows.removeValue(forKey: flow.key) }
    }

    func removeUDP(_ flow: UDPFlow) {
        if udpFlows[flow.key] === flow { udpFlows.removeValue(forKey: flow.key) }
    }

    /// Maximum TCP payload this stack will put on the wire toward the client.
    /// utun is configured at 9000, so 8 KiB stays well under that MTU while
    /// cutting per-segment Swift/C overhead by about 5× versus Ethernet MSS.
    static let tcpSegmentPayloadLimit = 8_192

    @discardableResult
    func writeTCP(key: FlowKey, sequence: UInt32, acknowledgment: UInt32,
                               flags: TCPFlags, window: UInt16 = 65_535,
                               payload: Data = Data(), payloadOffset: Int = 0,
                               payloadCount: Int? = nil, includeMSS: Bool = false,
                               windowScale: UInt8? = nil,
                               sackPermitted: Bool = false) -> Data? {
        guard payloadOffset >= 0, payloadOffset <= payload.count else { return nil }
        let count = payloadCount ?? (payload.count - payloadOffset)
        guard count >= 0, count <= payload.count - payloadOffset else { return nil }
        if !includeMSS, windowScale == nil, !sackPermitted {
            let built: Data?? = CDataPlane.withBorrowedPayload(payload, offset: payloadOffset, count: count) { body in
                buildSimpleTCP(key: key, sequence: sequence, acknowledgment: acknowledgment,
                               flags: flags, window: window, payload: body)
            }
            if let packet = built ?? nil {
                guard writeReturningOK(packet, version: key.version) else { return nil }
                return packet
            }
        }
        let framedPayload = payloadOffset == 0 && count == payload.count ? payload
            : TCPDeliverySlice.payload(from: payload, offset: payloadOffset, count: count)
        let packet = PacketBuilder.tcp(version: key.version,
                                       source: key.remoteAddress, sourcePort: key.remotePort,
                                       destination: key.clientAddress, destinationPort: key.clientPort,
                                       sequence: sequence, acknowledgment: acknowledgment,
                                       flags: flags, window: window, payload: framedPayload,
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
    /// reused scratch buffer. The caller borrows the original receive range;
    /// only the resulting owned retransmission packet is materialized.
    private func buildSimpleTCP(key: FlowKey, sequence: UInt32, acknowledgment: UInt32,
                                flags: TCPFlags, window: UInt16, payload: UnsafeRawBufferPointer) -> Data? {
        var sourceBytes = (UInt64(0), UInt64(0))
        var destinationBytes = (UInt64(0), UInt64(0))
        let identifier = nextIPv4Identifier()
        return withUnsafeMutableBytes(of: &sourceBytes) { sourceRaw in
            withUnsafeMutableBytes(of: &destinationBytes) { destinationRaw in
                key.remoteAddress.copyBytes(to: sourceRaw.baseAddress!.assumingMemoryBound(to: UInt8.self))
                key.clientAddress.copyBytes(to: destinationRaw.baseAddress!.assumingMemoryBound(to: UInt8.self))
                return buildBuffer.withUnsafeMutableBytes { out in
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
                        payload: payload,
                        identifier: identifier)
                    guard written > 0 else { return nil }
                    return Data(bytes: out.baseAddress!, count: written)
                }
            }
        }
    }

    func writeICMPEchoReply(to client: IPAddress, from remote: IPAddress,
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

    func rewrite(_ packet: Data, version: IPVersion) {
        _ = writeReturningOK(packet, version: version)
    }

    private func recordFlowOpened(id: UUID, key: FlowKey, isTCP: Bool) {
        guard NativePacketRouter.onTunnelFlowEvents != nil else { return }
        let destHost = router.displayDestinationHost(key.remoteAddress.hostString)
        let policy = key.remotePort == 53 ? "DNS" : "TUN"
        let client = "198.18.0.1:\(key.clientPort)"
        let snapshot = ConnectionSnapshot(id: id, openedAt: Date(), client: client,
                                          method: isTCP ? "TCP" : "UDP",
                                          host: destHost, port: key.remotePort,
                                          policy: policy)
        if pendingFlowEvents.count < 2048 {
            pendingFlowEvents.append(.opened(snapshot))
        }
    }

    func recordFlowClosed(id: UUID, remainingUp: Int, remainingDown: Int) {
        guard NativePacketRouter.onTunnelFlowEvents != nil else { return }
        if (remainingUp > 0 || remainingDown > 0), pendingFlowEvents.count < 4096 {
            pendingFlowEvents.append(.traffic(id: id, uploaded: remainingUp, downloaded: remainingDown))
        }
        if pendingFlowCloses.count < 2048 {
            pendingFlowCloses.append(id)
        }
    }

    private func flushFlowEventsIfNeeded() {
        guard let handler = NativePacketRouter.onTunnelFlowEvents else {
            if !pendingFlowEvents.isEmpty { pendingFlowEvents.removeAll() }
            if !pendingFlowCloses.isEmpty { pendingFlowCloses.removeAll() }
            return
        }
        var batch = pendingFlowEvents
        pendingFlowEvents.removeAll(keepingCapacity: true)
        for flow in tcpFlows.values {
            let up = flow.unreportedUploadBytes
            let down = flow.unreportedDownloadBytes
            if up > 0 || down > 0 {
                flow.unreportedUploadBytes = 0
                flow.unreportedDownloadBytes = 0
                batch.append(.traffic(id: flow.id, uploaded: up, downloaded: down))
            }
        }
        for flow in udpFlows.values {
            let up = flow.unreportedUploadBytes
            let down = flow.unreportedDownloadBytes
            if up > 0 || down > 0 {
                flow.unreportedUploadBytes = 0
                flow.unreportedDownloadBytes = 0
                batch.append(.traffic(id: flow.id, uploaded: up, downloaded: down))
            }
        }
        for id in pendingFlowCloses {
            batch.append(.closed(id: id, error: nil))
        }
        pendingFlowCloses.removeAll(keepingCapacity: true)
        if !batch.isEmpty {
            handler(batch)
        }
    }

    func recordTCPUpload(_ count: Int) { uploadedByteCount &+= UInt64(count) }
    func recordTCPDownload(_ count: Int) { downloadedByteCount &+= UInt64(count) }

    func writeUDP(key: FlowKey, remoteAddress: IPAddress, remotePort: UInt16,
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
    struct PendingFrame {
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
        if let counters = packetLoadCounters {
            counters.maintenanceTicks += 1
            counters.maintenanceSnapshotReferences += tcpFlows.count + udpFlows.count
        }
        // Snapshot first: tick() may close a flow and remove it from the
        // live table. Mutating the dictionary while iterating it is illegal.
        for flow in Array(tcpFlows.values) { flow.tick(now: now) }
        for flow in Array(udpFlows.values) { flow.tick(now: now) }
        maintenanceTickParity &+= 1
        if (maintenanceTickParity & 3) == 0 {
            flushFlowEventsIfNeeded()
        }
        if tcpFlows.count > (FlowAdmission.maximumTCPFlows * 3) / 4 {
            for flow in Array(tcpFlows.values) {
                let elapsed = now.timeIntervalSince(flow.lastActivityDate)
                if (!flow.isFullyConnected && elapsed >= 10)
                    || (flow.isHalfClosed && elapsed >= 15)
                    || elapsed >= 90 {
                    flow.close(sendReset: true)
                }
            }
        }
    }

    func upstreamQueue(for key: FlowKey) -> DispatchQueue {
        let bucket = Int(UInt(bitPattern: key.hashValue) % UInt(Self.upstreamQueueCount))
        return Self.sharedUpstreamQueues[bucket]
    }

    /// Drops the least-recently-used idle TCP flow so a new handshake can
    /// proceed. Returns false when every occupant is still active.
    private func evictIdleTCP(now: Date = Date()) -> Bool {
        var transientCandidate: TCPFlow?
        var transientOldest = now
        for flow in tcpFlows.values where !flow.isFullyConnected || flow.isHalfClosed {
            guard FlowAdmission.isIdle(lastActivity: flow.lastActivityDate, now: now, limit: 8) else { continue }
            if flow.lastActivityDate < transientOldest {
                transientCandidate = flow
                transientOldest = flow.lastActivityDate
            }
        }
        if let transientCandidate {
            transientCandidate.close(sendReset: true)
            return true
        }
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

enum IPVersion: UInt8, Hashable { case v4 = 4, v6 = 6 }

struct IPAddress: Hashable {
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

struct FlowKey: Hashable {
    let version: IPVersion
    let transportProtocol: UInt8
    let clientAddress: IPAddress
    let clientPort: UInt16
    let remoteAddress: IPAddress
    let remotePort: UInt16
}

struct ParsedIPPacket {
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
            guard totalLength <= raw.count else { return nil }
        default: return nil
        }
        var parsed = hajimi_ip_packet()
        guard hajimi_parse_ip(base, raw.count, &parsed) == 0,
              let version = IPVersion(rawValue: parsed.version),
              version == .v4 || [UInt8(6), 17, 58].contains(parsed.protocol) else { return nil }
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

struct TCPFlags: OptionSet {
    let rawValue: UInt8
    static let fin = TCPFlags(rawValue: 0x01)
    static let syn = TCPFlags(rawValue: 0x02)
    static let rst = TCPFlags(rawValue: 0x04)
    static let psh = TCPFlags(rawValue: 0x08)
    static let ack = TCPFlags(rawValue: 0x10)
}

struct ParsedTCPSegment {
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
final class AtomicFlag {
    private let lock = NSLock()
    private var storage = false
    var value: Bool {
        get { lock.lock(); defer { lock.unlock() }; return storage }
        set { lock.lock(); storage = newValue; lock.unlock() }
    }
}

struct SACKBlock: Equatable {
    let start: UInt32
    let end: UInt32
}

struct OutstandingSegment {
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
enum TCPReceiveReassembly {
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
enum SACKScoreboard {
    static func apply(_ blocks: [SACKBlock], to segments: inout [OutstandingSegment],
                      from head: Int) {
        guard !blocks.isEmpty, head < segments.count else { return }
        let cRanges = blocks.map { hajimi_sack_range(start: $0.start, end: $0.end) }
        cRanges.withUnsafeBufferPointer { ptr in
            guard let base = ptr.baseAddress else { return }
            for index in head..<segments.count
            where !segments[index].sacked && segments[index].payloadBytes > 0 {
                let start = segments[index].startSequence
                let len = UInt32(segments[index].payloadBytes)
                if hajimi_sack_covers(base, ptr.count, start, len) != 0 {
                    segments[index].sacked = true
                }
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

/// ACKs may repeat the same four SACK blocks thousands of times while one
/// cumulative-ACK hole remains. Their previous marks remain valid until a
/// segment is appended or RTO deliberately revokes a mark. Removing fully
/// ACKed entries (including array compaction) does not change any remaining
/// entry's sequence range or mark. Empty options never revoke advisory SACK.
struct SACKApplicationState {
    private var previous: [SACKBlock] = []
    private var invalidated = true

    mutating func invalidate() { invalidated = true }

    mutating func shouldApply(_ blocks: [SACKBlock]) -> Bool {
        guard !blocks.isEmpty else { return false }
        guard invalidated || blocks != previous else { return false }
        previous = blocks
        invalidated = false
        return true
    }
}

/// RFC 6298 retransmission timer.
///
/// The previous fixed `0.75 * 2^retries` schedule was calibrated for a wide
/// area link, but this TCP endpoint talks to an application on the same machine
/// over utun, where the round trip is sub-millisecond. A single dropped segment
/// therefore stalled the flow for 750 ms before the first retransmission —
/// visible as a periodic hitch rather than a slowdown.
struct RetransmissionTimer {
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

struct ParsedUDPDatagram {
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
let dispatchNoFlags = DispatchWorkItemFlags(rawValue: 0)

/// Joins queued upload chunks into one outbound write. Isolated so the
/// coalesce budget can be unit-tested without standing up a TCPFlow.
enum TCPWriteCoalesce {
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
enum TCPDeliverySlice {
    static func payload(from buffer: Data, offset: Int, count: Int) -> Data {
        let start = buffer.startIndex + offset
        return buffer.subdata(in: start..<(start + count))
    }
}

/// Caps concurrent userspace flows so a YouTube 4K (or similar) burst of
/// TCP + QUIC sockets cannot allocate unbounded per-flow state.
enum FlowAdmission {
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

/// Establishment is a historical event, not equality with a 32-bit sequence.
/// Long streams can legitimately bring the cumulative ACK back to ISN after
/// a complete 4 GiB turn. Call only after checking ACK <= SND.NXT.
struct TCPHandshakeAcknowledgmentState {
    private(set) var isEstablished = false
    mutating func acknowledge(_ sequence: UInt32, synSequence: UInt32) {
        guard !isEstablished else { return }
        isEstablished = Int32(bitPattern: sequence &- (synSequence &+ 1)) >= 0
    }
}

final class TCPFlow {
    let id = UUID()
    var unreportedUploadBytes: Int = 0
    var unreportedDownloadBytes: Int = 0
    let key: FlowKey
    let upstreamQueue: DispatchQueue
    private weak var owner: NativeTunnel?
    private let initial: ParsedTCPSegment
    private let receiveState: OpaquePointer?
    private var expectedClientSequence: UInt32 { hajimi_tcp_reassembly_expected(receiveState) }
    private let initialServerSequence: UInt32
    private var nextServerSequence: UInt32
    private let clientWindowScale: UInt8
    private let serverWindowScale: UInt8?
    private var clientAdvertisedWindow: Int
    private var lastClientAcknowledgment: UInt32
    private var duplicateAcknowledgments = 0
    private var handshake = TCPHandshakeAcknowledgmentState()
    private var lastPayloadByte: UInt8?
    private var lastPayloadSequence: UInt32?
    private var persistStartedAt: Date?
    private var persistSentAt: Date?
    private var persistAttempts: UInt32 = 0
    private var remoteStream: NativeOutboundByteStream?
    private var remoteReadSuspended = false
    private var remoteReadInFlight = false
    private var remoteWriteInFlight = false
    private let remoteWrites: NativeByteQueue
    private var pendingRemoteWriteBytes: Int { remoteWrites.count }
    private var remoteDeliveryBuffer = Data()
    private var remoteDeliveryOffset = 0
    private var firstPayloadSentAt: UInt64?
    private var firstPayloadResponseRecorded = false
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
    private var sackApplicationState = SACKApplicationState()

    private var retransmissionTimer = RetransmissionTimer()

    /// Segments that arrived ahead of `expectedClientSequence`. Keyed by the
    /// starting sequence so a later in-order arrival can release the chain
    /// without asking the peer to retransmit data we already hold.
    private static let consumeUpload: hajimi_tcp_consume = { context, bytes, count in
        guard let context, let bytes else { return 0 }
        let flow = Unmanaged<TCPFlow>.fromOpaque(context).takeUnretainedValue()
        guard flow.remoteWrites.append(UnsafeRawBufferPointer(start: bytes, count: count)) else { return 0 }
        flow.unreportedUploadBytes &+= count
        flow.owner?.recordTCPUpload(count)
        return 1
    }

    var lastActivityDate: Date { lastActivity }
    var isFullyConnected: Bool { handshake.isEstablished && remoteConnected }
    var isHalfClosed: Bool { clientFinished || remoteFinished }

    init(key: FlowKey, initial: ParsedTCPSegment, owner: NativeTunnel) {
        self.key = key
        self.initial = initial
        self.owner = owner
        self.upstreamQueue = owner.upstreamQueue(for: key)
        initialServerSequence = owner.streamRegressionInitialSequence
            ?? UInt32.random(in: 1...UInt32.max - 1_000_000)
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
        recordOutstandingAppend()
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
            handshake.acknowledge(segment.acknowledgment, synSequence: initialServerSequence)
            let previousWindow = clientAdvertisedWindow
            clientAdvertisedWindow = Int(segment.window) << Int(clientWindowScale)
            if clientAdvertisedWindow > 0 { resetPersist() }
            else if previousWindow > 0 {
                persistStartedAt = lastActivity; persistSentAt = nil; persistAttempts = 0
                duplicateAcknowledgments = 0
            }
            applySelectiveAcknowledgements(segment.sackBlocks)
            acknowledge(segment.acknowledgment,
                        duplicateCandidate: segment.payload.isEmpty &&
                            clientAdvertisedWindow > 0 &&
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
        let idleLimit: TimeInterval
        if !handshake.isEstablished || !remoteConnected {
            idleLimit = 18
        } else if clientFinished || remoteFinished {
            idleLimit = 30
        } else {
            idleLimit = 300
        }
        if now.timeIntervalSince(lastActivity) > idleLimit { close(sendReset: true); return }
        if clientAdvertisedWindow == 0, handshake.isEstablished,
           remoteDeliveryBytes > 0 || outstandingHead < outstanding.count || remoteEOFPending {
            // A lost window-update ACK otherwise leaves a completely ACKed
            // download suspended forever. Use the existing maintenance tick,
            // not an extra timer or repeated full-sized data retransmissions.
            if persistStartedAt == nil { persistStartedAt = now }
            guard let started = persistStartedAt else { return }
            if now.timeIntervalSince(started) > 300 { close(sendReset: true); return }
            let base = max(0.25, min(1, retransmissionTimer.timeout))
            let interval = min(5, base * pow(2, Double(min(persistAttempts, 8))))
            guard now.timeIntervalSince(persistSentAt ?? started) >= interval else { return }
            sendPersistProbe(now: now)
            return
        }
        resetPersist()
        // SACK is advisory: a receiver may discard previously SACKed bytes.
        // RTO must always be able to retry the cumulative-ACK head, including
        // when later unsacked data exists. Fast retransmit still uses holes.
        guard outstandingHead < outstanding.count else { return }
        let index = outstandingHead
        let retries = outstanding[index].retries
        let timeout = retransmissionTimer.timeout(retries: retries)
        guard now.timeIntervalSince(outstanding[index].sentAt) >= timeout else { return }
        if retries >= 8 { close(sendReset: true); return }
        outstanding[index].sacked = false
        sackApplicationState.invalidate()
        retransmit(at: index, now: now)
    }

    private func resetPersist() {
        persistStartedAt = nil; persistSentAt = nil; persistAttempts = 0
    }

    private func sendPersistProbe(now: Date) {
        var sequence = nextServerSequence &- 1
        var payload = Data()
        if lastPayloadSequence == sequence, let lastPayloadByte {
            payload = Data([lastPayloadByte])
        } else {
            // Before the first payload, or after FIN consumed SND.NXT, an
            // empty keepalive below SND.UNA solicits the current window. Never
            // put a remembered data byte at FIN's sequence position.
            sequence = lastClientAcknowledgment &- 1
        }
        _ = owner?.writeTCP(key: key, sequence: sequence, acknowledgment: expectedClientSequence,
                            flags: [.ack], window: advertisedReceiveWindow, payload: payload)
        persistSentAt = now; persistAttempts = min(persistAttempts + 1, 16)
        // No SND.NXT advance, new outstanding range, retry-budget consumption
        // or downloaded-byte accounting: this cannot acknowledge unsent data.
    }

    func close(sendReset: Bool, removeFromOwner: Bool = true) {
        guard !closed else { return }
        closed = true
        // A reset/idle failure after a payload send is an observed failed
        // stream response. Normal EOF and explicit teardown are not counted
        // as failed network samples merely because there was no response.
        if sendReset, let started = firstPayloadSentAt, !firstPayloadResponseRecorded {
            firstPayloadResponseRecorded = true
            NetworkPerformanceDiagnostics.shared.record(.firstByte,
                milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started), success: false)
        }
        if sendReset {
            _ = owner?.writeTCP(key: key, sequence: nextServerSequence,
                                acknowledgment: expectedClientSequence,
                                flags: [.rst, .ack], window: advertisedReceiveWindow)
        }
        remoteStream?.cancel(); remoteStream = nil
        remoteWrites.clear()
        remoteDeliveryBuffer.removeAll(keepingCapacity: false)
        outstanding.removeAll(keepingCapacity: false)
        let remUp = unreportedUploadBytes
        let remDown = unreportedDownloadBytes
        unreportedUploadBytes = 0
        unreportedDownloadBytes = 0
        owner?.recordFlowClosed(id: id, remainingUp: remUp, remainingDown: remDown)
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

        let previousHead = outstandingHead
        while outstandingHead < outstanding.count,
              sequenceGreaterOrEqual(sequence, outstanding[outstandingHead].endSequence) {
            let segment = outstanding[outstandingHead]
            if !segment.retransmitted {
                retransmissionTimer.update(sample: now.timeIntervalSince(segment.sentAt))
            }
            outstandingPayloadByteCount -= segment.payloadBytes
            outstandingHead += 1
        }
        owner?.packetLoadCounters?.outstandingAcknowledged += outstandingHead - previousHead
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
        if firstPayloadSentAt == nil, !payload.isEmpty, key.remotePort != 53 {
            firstPayloadSentAt = NetworkPerformanceDiagnostics.now()
        }
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
                    if let started = self.firstPayloadSentAt, !self.firstPayloadResponseRecorded {
                        self.firstPayloadResponseRecorded = true
                        NetworkPerformanceDiagnostics.shared.record(.firstByte,
                            milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started))
                    }
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
        let counters = owner?.packetLoadCounters
        defer {
            if let counters {
                // Logical Data bytes, not allocation capacity, RSS or copied
                // bytes. Observe the real buffer after each append.
                counters.downloadStoredPeak = max(counters.downloadStoredPeak, remoteDeliveryBuffer.count)
                counters.downloadRetainedPrefixPeak = max(counters.downloadRetainedPrefixPeak, remoteDeliveryOffset)
                if remoteDeliveryBuffer.count >= 2 * remoteDeliveryBytes + 64 * 1_024 ||
                   remoteDeliveryOffset >= max(64 * 1_024, remoteDeliveryBytes) {
                    counters.downloadStorageBoundViolations += 1
                }
            }
        }
        if let counters {
            counters.downloadAppends += 1
            counters.downloadBufferedPeak = max(counters.downloadBufferedPeak, remoteDeliveryBytes + data.count)
        }
        if remoteDeliveryOffset >= remoteDeliveryBuffer.count {
            // Copy non-zero-origin slices so later offset math cannot see a
            // window into the original receive buffer.
            remoteDeliveryBuffer = data.startIndex == 0 ? data : Data(data)
            remoteDeliveryOffset = 0
            return
        }
        // A small client window otherwise removes a few KiB and appends a
        // few KiB against the same large tail on every ACK. Amortize that
        // work: retain the consumed prefix until it is both at least 64 KiB
        // and at least as large as the live tail. After appending, logical
        // storage stays below twice the live bytes plus 64 KiB. The existing
        // receive/prefetch limits still count only undelivered bytes.
        if remoteDeliveryOffset >= 64 * 1_024,
           remoteDeliveryOffset >= remoteDeliveryBytes {
            if let counters {
                counters.downloadRebases += 1
                counters.downloadRebasedTailBytes += remoteDeliveryBytes
            }
            remoteDeliveryBuffer.removeFirst(remoteDeliveryOffset)
            remoteDeliveryOffset = 0
        }
        remoteDeliveryBuffer.append(data)
    }

    private func flushRemoteDelivery() {
        guard !closed else { return }
        defer {
            // EOF can leave a partly drained buffer with no later append.
            // Observe the prefix retained at that boundary as well.
            if let counters = owner?.packetLoadCounters {
                counters.downloadRetainedPrefixPeak = max(counters.downloadRetainedPrefixPeak, remoteDeliveryOffset)
            }
        }
        let maximumSegment = NativeTunnel.tcpSegmentPayloadLimit
        var available = availableClientDeliveryBytes
        while remoteDeliveryOffset < remoteDeliveryBuffer.count, available > 0 {
            let count = min(maximumSegment,
                            remoteDeliveryBuffer.count - remoteDeliveryOffset,
                            available)
            let sequence = nextServerSequence
            guard let packet = owner?.writeTCP(key: key, sequence: sequence,
                                               acknowledgment: expectedClientSequence,
                                               flags: [.ack, .psh],
                                               window: advertisedReceiveWindow,
                                               payload: remoteDeliveryBuffer,
                                               payloadOffset: remoteDeliveryOffset,
                                               payloadCount: count) else {
                // Hard write failure: stop draining so we do not advance the
                // sequence number over bytes the client will never see.
                remoteReadSuspended = true
                return
            }
            nextServerSequence &+= UInt32(count)
            lastPayloadSequence = nextServerSequence &- 1
            lastPayloadByte = remoteDeliveryBuffer.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                raw[remoteDeliveryOffset + count - 1]
            }
            outstanding.append(OutstandingSegment(packet: packet,
                                                  endSequence: nextServerSequence,
                                                  payloadBytes: count,
                                                  sentAt: Date(), retries: 0))
            recordOutstandingAppend()
            outstandingPayloadByteCount += count
            unreportedDownloadBytes &+= count
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
        guard remoteEOFPending, remoteDeliveryBytes == 0, !remoteFinished,
              availableClientDeliveryBytes > 0 else { return }
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
        recordOutstandingAppend()
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
        guard sackEnabled, !blocks.isEmpty else { return }
        guard sackApplicationState.shouldApply(blocks) else {
            owner?.packetLoadCounters?.sackCacheHits += 1
            return
        }
        if let counters = owner?.packetLoadCounters {
            counters.sackApplications += 1
            counters.sackSegmentVisits += max(0, outstanding.count - outstandingHead)
        }
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
        if let counters = owner?.packetLoadCounters {
            counters.outstandingCompactions += 1
            counters.outstandingSlotsMoved += outstanding.count - outstandingHead
        }
        outstanding.removeFirst(outstandingHead)
        outstandingHead = 0
    }

    private func recordOutstandingAppend() {
        sackApplicationState.invalidate()
        if let counters = owner?.packetLoadCounters {
            counters.outstandingCreated += 1
            counters.outstandingPeak = max(counters.outstandingPeak, outstanding.count - outstandingHead)
            counters.outstandingStoredPeak = max(counters.outstandingStoredPeak, outstanding.count)
        }
    }

}

// Kept internal to the module while allowing flow objects to attach their
// descriptor sources to the same serialization lane as packet processing.
extension NativeTunnel {
    var queueForFlows: DispatchQueue { queue }
}


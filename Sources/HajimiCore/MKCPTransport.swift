import Foundation

// mKCP's ARQ, congestion control and connection state machine, plus the
// ByteTransport it presents upward.
//
// Segment encoding lives in MKCPSegment.swift; this file only consumes it.
// Until the two are wired together `MKCPWireStub` stands in so the ARQ compiles
// and self-tests on its own. Integration means deleting the section marked
// `MARK: - Segment coding (placeholder)` and swapping these types for the ones
// MKCPSegment.swift exports. The interface assumed here is:
//
//     struct DataSegment {
//         var conv: UInt16; var option: UInt8
//         var timestamp: UInt32; var number: UInt32; var sendingNext: UInt32
//         var payload: Data
//         func encoded() -> Data
//     }
//     struct AckSegment {
//         var conv: UInt16; var option: UInt8
//         var receivingWindow: UInt32; var receivingNext: UInt32; var timestamp: UInt32
//         var numbers: [UInt32]
//         func encoded() -> Data
//     }
//     struct CmdSegment {
//         var conv: UInt16; var command: UInt8; var option: UInt8
//         var sendingNext: UInt32; var receivingNext: UInt32; var peerRTO: UInt32
//         func encoded() -> Data
//     }
//     enum Segment { case data(DataSegment), ack(AckSegment), cmd(CmdSegment) }
//     static func decode(_ datagram: Data) -> [Segment]   // chained, stops at a bad segment
//
// The datagram wrapper (SimpleAuthenticator's fnv1a+xorfwd, AES-128-GCM, the
// camouflage headers) belongs there too; this file reaches it only through
// `MKCPDatagramCodec`, which defaults to the identity.

/// Connection parameters.
///
/// Defaults follow Xray's kcp/config.go — Mtu 1350, 5 MB/s up, 20 MB/s down,
/// 2 MB send buffer — except for `tti`, which follows the value real nodes ship
/// (20ms) rather than the kernel default of 50ms. tti is both the flush period
/// and the floor the RTO converges to; the two ends need not agree on it.
struct MKCPConfiguration {
    /// Xray's client seeds a global counter with a random uint16 and increments
    /// it per dial. There is no negotiation: the server keys its session on
    /// (source address, source port, conv) taken from the first segment it can
    /// parse, so a fresh value per connection is all that is required.
    var conversation: UInt16 = MKCPTransport.allocateConversation()

    var mtu: UInt32 = 1350
    var tti: UInt32 = 20
    /// MB/s. These only size the windows; nothing here rate-limits.
    var uplinkCapacity: UInt32 = 5
    var downlinkCapacity: UInt32 = 20
    var maxSendingWindow: UInt32 = 2 * 1024 * 1024

    /// Multiplier applied to the per-flush send quota.
    ///
    /// v1.8.24 and earlier hard-code `cwnd *= 20 // magic`; since 2026-04 it is
    /// a config field defaulting to 1. Neither violates the protocol — the
    /// difference is purely how aggressive this end is, and it is invisible in
    /// every log on both sides. Sending with 1 against an old server can cost a
    /// factor of twenty in uplink throughput, and old servers are still the
    /// overwhelming majority, so 20 is the safer default.
    var cwndMultiplier: UInt32 = 20

    /// Loss-driven AIMD. v1.8.24's `Config.Congestion` defaults to false; current
    /// main deleted the switch and applies it unconditionally. It governs only
    /// this end's send rate, so either choice interoperates.
    var congestion: Bool = false

    /// Datagram wrapper. The identity matches current main, where the
    /// obfuscation layer moved out to finalmask and the server must opt back in.
    var datagram: MKCPDatagramCodec = .identity

    /// How long after `cancel()` the state machine still gets to run.
    ///
    /// Xray's own teardown takes 8 to 23 seconds (Terminating caps at 8000ms,
    /// ReadyToClose at 15000ms). A proxy client opens and closes connections by
    /// the thousand, so this is cut down to a window that still fits two or
    /// three Terminates.
    var closeGrace: UInt32 = 1000

    /// Payload bytes per data segment.
    ///
    /// Current main computes `Mtu - 18` and no longer subtracts the wrapper's
    /// overhead, which pushes the wire datagram past the configured MTU when
    /// mkcp-legacy is in use. v1.8.24 subtracts it; that is what is done here so
    /// datagrams stay inside the MTU that was asked for.
    var mss: UInt32 { mtu &- datagram.overhead &- UInt32(MKCPWireStub.dataOverhead) }

    /// Integer division throughout, including the inner `1000 / tti`. Computing
    /// these in floating point yields different windows, which shows up as a
    /// throughput difference and never as an error.
    var sendingInFlightSize: UInt32 { Self.inFlightSize(uplinkCapacity, mtu, tti) }
    var receivingInFlightSize: UInt32 { Self.inFlightSize(downlinkCapacity, mtu, tti) }
    /// Backpressure threshold for pushing into the sending window, in segments.
    var sendingBufferSize: UInt32 { maxSendingWindow / mtu }

    /// SACK numbers per AckSegment. Xray passes `kcp.mss + DataSegmentOverhead`
    /// into the ack list and clamps `(that - 17) / 4` into 1...128.
    var ackNumberLimit: Int {
        let room = (Int(mss) + MKCPWireStub.dataOverhead - MKCPWireStub.ackOverhead) / 4
        return min(max(room, 1), MKCPWireStub.ackNumberLimit)
    }

    private static func inFlightSize(_ capacity: UInt32, _ mtu: UInt32, _ tti: UInt32) -> UInt32 {
        let ticksPerSecond = max(1000 / max(tti, 1), 1)
        let size = capacity * 1024 * 1024 / max(mtu, 1) / ticksPerSecond
        return max(size, 8)
    }
}

/// The outermost datagram wrapper. `open` returning nil means the datagram is
/// not ours and is dropped without a word — the layer has no feedback channel,
/// and Xray drops it just as silently.
struct MKCPDatagramCodec {
    let overhead: UInt32
    let seal: (Data) -> Data
    let open: (Data) -> Data?

    /// Bare segments, matching current main. Servers running v1.8.24 or earlier
    /// expect SimpleAuthenticator (overhead 6) and will drop everything else.
    static let identity = MKCPDatagramCodec(overhead: 0, seal: { $0 }, open: { $0 })
}

// MARK: - Segment coding (placeholder)

/// Stand-in until MKCPSegment.swift lands; the layout follows the Serialize and
/// parse routines in kcp/segment.go.
enum MKCPWireStub {
    static let dataOverhead = 18
    static let ackOverhead = 17
    static let cmdSize = 16
    static let ackNumberLimit = 128

    enum Command: UInt8 {
        case ack = 0
        case data = 1
        case terminate = 2
        case ping = 3
    }

    /// The option byte has exactly one bit. Any segment that sets it drives the
    /// peer through OnPeerClosed, which discards everything it had queued to
    /// send; on a healthy connection this byte is always zero.
    static let optionClose: UInt8 = 1

    struct DataSegment {
        var conv: UInt16 = 0
        var option: UInt8 = 0
        var timestamp: UInt32 = 0
        var number: UInt32 = 0
        /// Xray names this field SendingNext, but what goes on the wire is the
        /// sender's firstUnacknowledged (una), not its next number.
        var sendingNext: UInt32 = 0
        var payload: Data = Data()

        func encoded() -> Data {
            var out = Data(capacity: dataOverhead + payload.count)
            out.appendBigEndian(conv)
            out.append(Command.data.rawValue)
            out.append(option)
            out.appendBigEndian(timestamp)
            out.appendBigEndian(number)
            out.appendBigEndian(sendingNext)
            out.appendBigEndian(UInt16(truncatingIfNeeded: payload.count))
            out.append(payload)
            return out
        }
    }

    struct AckSegment {
        var conv: UInt16 = 0
        var option: UInt8 = 0
        /// An absolute right edge — receiver's nextNumber plus its window — not
        /// a window size.
        var receivingWindow: UInt32 = 0
        var receivingNext: UInt32 = 0
        var timestamp: UInt32 = 0
        var numbers: [UInt32] = []

        func encoded() -> Data {
            var out = Data(capacity: ackOverhead + numbers.count * 4)
            out.appendBigEndian(conv)
            out.append(Command.ack.rawValue)
            out.append(option)
            out.appendBigEndian(receivingWindow)
            out.appendBigEndian(receivingNext)
            out.appendBigEndian(timestamp)
            // One byte. Written as a big-endian uint16 the peer reads the high
            // byte, decodes zero SACK numbers, and keeps working off cumulative
            // acknowledgement alone — ordered traffic looks fine and every loss
            // costs a full retransmission timeout.
            out.append(UInt8(truncatingIfNeeded: numbers.count))
            for number in numbers { out.appendBigEndian(number) }
            return out
        }
    }

    struct CmdSegment {
        var conv: UInt16 = 0
        var command: UInt8 = Command.ping.rawValue
        var option: UInt8 = 0
        var sendingNext: UInt32 = 0
        var receivingNext: UInt32 = 0
        var peerRTO: UInt32 = 0

        func encoded() -> Data {
            var out = Data(capacity: cmdSize)
            out.appendBigEndian(conv)
            out.append(command)
            out.append(option)
            out.appendBigEndian(sendingNext)
            out.appendBigEndian(receivingNext)
            out.appendBigEndian(peerRTO)
            return out
        }
    }

    enum Segment {
        case data(DataSegment)
        case ack(AckSegment)
        case cmd(CmdSegment)

        var conv: UInt16 {
            switch self {
            case .data(let segment): return segment.conv
            case .ack(let segment): return segment.conv
            case .cmd(let segment): return segment.conv
            }
        }

        var option: UInt8 {
            switch self {
            case .data(let segment): return segment.option
            case .ack(let segment): return segment.option
            case .cmd(let segment): return segment.option
            }
        }
    }

    /// One datagram may chain several segments. A parse failure stops the walk
    /// but keeps what came before it, which is what Xray's reader does.
    static func decode(_ datagram: Data) -> [Segment] {
        let bytes = [UInt8](datagram)
        var segments: [Segment] = []
        var offset = 0
        while bytes.count - offset >= 4 {
            let conv = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            let command = bytes[offset + 2]
            let option = bytes[offset + 3]
            var cursor = offset + 4
            let remaining = bytes.count - cursor
            switch command {
            case Command.data.rawValue:
                // The source demands 15 bytes but consumes 14, so a zero-length
                // data segment at the end of a datagram is rejected. Copying the
                // off-by-one keeps us from accepting datagrams Xray would drop.
                guard remaining >= 15 else { return segments }
                var segment = DataSegment(conv: conv, option: option)
                segment.timestamp = readBigEndian32(bytes, cursor); cursor += 4
                segment.number = readBigEndian32(bytes, cursor); cursor += 4
                segment.sendingNext = readBigEndian32(bytes, cursor); cursor += 4
                let length = Int(UInt16(bytes[cursor]) << 8 | UInt16(bytes[cursor + 1]))
                cursor += 2
                guard bytes.count - cursor >= length else { return segments }
                segment.payload = Data(bytes[cursor..<(cursor + length)])
                cursor += length
                segments.append(.data(segment))
            case Command.ack.rawValue:
                guard remaining >= 13 else { return segments }
                var segment = AckSegment(conv: conv, option: option)
                segment.receivingWindow = readBigEndian32(bytes, cursor); cursor += 4
                segment.receivingNext = readBigEndian32(bytes, cursor); cursor += 4
                segment.timestamp = readBigEndian32(bytes, cursor); cursor += 4
                let count = Int(bytes[cursor]); cursor += 1
                guard bytes.count - cursor >= count * 4 else { return segments }
                // The 128 cap binds the sender only; up to 255 are accepted here.
                segment.numbers.reserveCapacity(count)
                for _ in 0..<count {
                    segment.numbers.append(readBigEndian32(bytes, cursor)); cursor += 4
                }
                segments.append(.ack(segment))
            default:
                // Terminate, Ping and every unknown command parse as CmdOnly.
                guard remaining >= 12 else { return segments }
                var segment = CmdSegment(conv: conv, command: command, option: option)
                segment.sendingNext = readBigEndian32(bytes, cursor); cursor += 4
                segment.receivingNext = readBigEndian32(bytes, cursor); cursor += 4
                segment.peerRTO = readBigEndian32(bytes, cursor); cursor += 4
                segments.append(.cmd(segment))
            }
            offset = cursor
        }
        return segments
    }

    private static func readBigEndian32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
    }
}

private extension Data {
    mutating func appendBigEndian(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    mutating func appendBigEndian(_ value: UInt32) {
        append(UInt8(truncatingIfNeeded: value >> 24))
        append(UInt8(truncatingIfNeeded: value >> 16))
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }
}

// MARK: - Round trip

/// The RFC6298 variant from kcp/connection.go:73-107.
///
/// Two differences from stock ikcp matter: there is no RTO backoff anywhere — a
/// timeout retransmission neither doubles nor multiplies the value — and there
/// is no explicit RTO floor, only the one implied by clamping srtt to minRtt.
struct MKCPRoundTrip {
    private(set) var srtt: UInt32 = 0
    private(set) var variation: UInt32 = 0
    /// The 100ms seed is written at connection setup. This value is also
    /// broadcast to the peer inside every Ping; sending zero makes the peer zero
    /// its own RTO and retransmit its entire window every tick.
    private(set) var timeout: UInt32 = 100
    let minRtt: UInt32
    private var updatedTimestamp: UInt32 = 0

    init(minRtt: UInt32) { self.minRtt = minRtt }

    mutating func update(rtt: UInt32, current: UInt32) {
        // A wrapped subtraction that came out "negative".
        if rtt > 0x7FFF_FFFF { return }
        if srtt == 0 {
            srtt = rtt
            variation = rtt / 2
        } else {
            let delta = srtt > rtt ? srtt &- rtt : rtt &- srtt
            variation = (3 &* variation &+ delta) / 4
            srtt = (7 &* srtt &+ rtt) / 8
            if srtt < minRtt { srtt = minRtt }
        }
        // Anything but a low-jitter steady state takes the srtt+4*variation
        // branch. Hard-coding the other one yields an RTO that is too small,
        // which retransmits early, inflates the measured loss rate, and gets the
        // congestion window beaten down for it.
        var raw = minRtt < 4 &* variation ? srtt &+ 4 &* variation : srtt &+ variation
        if raw > 10000 { raw = 10000 }
        timeout = raw * 5 / 4
        updatedTimestamp = current
    }

    /// Adopts the RTO the peer advertises. The assignment is unconditional; the
    /// only brake is the three-second gate, and because `update` refreshes the
    /// same timestamp a fresh local measurement shadows the peer for that long.
    mutating func adoptPeer(rto: UInt32, current: UInt32) {
        if current &- updatedTimestamp < 3000 { return }
        updatedTimestamp = current
        timeout = rto
    }
}

// MARK: - State machine

/// mKCP's ARQ and connection state machine.
///
/// Nothing here locks; every method must be called with MKCPTransport's lock
/// held. Nor does it read a clock — `current` always arrives from the caller.
/// Both concessions exist so the self-test can drive two instances against each
/// other on a virtual timeline: almost every defect in this layer presents as
/// "connects but is slow", which is unobservable without a deterministic clock.
///
/// `current` must be milliseconds since this connection was created. A truncated
/// Unix millisecond clock spends about half its time in [0x80000000, 0xFFFFFFFF],
/// where the expiry test `current - timeout < 0x7FFFFFFF` never holds for a
/// freshly pushed segment (whose timeout is zero) and not one data segment ever
/// leaves — with a healthy socket and a silent log.
final class MKCPSession {
    enum State: Int32 {
        case active = 0
        case readyToClose = 1
        case peerClosed = 2
        case terminating = 3
        case peerTerminating = 4
        case terminated = 5
    }

    /// One segment in the sending window. The window has to stay sorted by
    /// number and be drained from the front: removal, cumulative clearing and
    /// the fast-ack walk all rely on an ordered scan with an early exit. Backed
    /// by a dictionary or a heap, SACK removal silently no-ops for most numbers,
    /// which kills fast retransmit and RTT sampling together.
    private struct SendingSegment {
        let number: UInt32
        let payload: Data
        var timeout: UInt32 = 0
        var timestamp: UInt32 = 0
        var transmit: UInt32 = 0
    }

    let configuration: MKCPConfiguration
    private(set) var state: State = .active
    private var stateBeginTime: UInt32 = 0
    private var lastIncomingTime: UInt32 = 0
    private var lastPingTime: UInt32 = 0
    private(set) var roundTrip: MKCPRoundTrip

    private var sendingWindow: [SendingSegment] = []
    private var totalInFlightSize: UInt32 = 0
    private var firstUnacknowledged: UInt32 = 0
    private var nextNumber: UInt32 = 0
    /// The peer's advertised absolute right edge. The seed of 32 is the sending
    /// window before any ACK arrives; seeding it with zero makes the first
    /// flush compute a quota of 0 - 0. It only ever grows.
    private var remoteNextNumber: UInt32 = 32
    private var controlWindow: UInt32
    private var firstUnacknowledgedUpdated = false

    private var receivingWindow: [UInt32: Data] = [:]
    private var receivingNext: UInt32 = 0
    private var ackNumbers: [UInt32] = []
    private var ackTimestamps: [UInt32] = []
    private var ackNextFlush: [UInt32] = []
    private var ackDirty = false
    private var flushCandidates: [UInt32] = []

    /// Datagrams waiting to go out, one serialized segment each. Xray puts a
    /// single segment in every UDP packet; batching would exceed the MTU when
    /// full and would change the traffic shape, even though a peer can parse it.
    private var outbox: [Data] = []

    init(configuration: MKCPConfiguration) {
        self.configuration = configuration
        self.controlWindow = configuration.sendingInFlightSize
        self.roundTrip = MKCPRoundTrip(minRtt: configuration.tti)
    }

    // MARK: Observable state

    var mss: UInt32 { configuration.mss }
    var acceptsWrites: Bool { state == .active }
    var isDataAvailable: Bool { receivingWindow[receivingNext] != nil }
    /// Only a non-empty sending window or a pending acknowledgement justifies
    /// running at tti; otherwise the connection falls back to the ping cadence.
    var updateNecessary: Bool { !sendingWindow.isEmpty || !ackNumbers.isEmpty }
    /// Xray drops its ping updater to one second while tearing down.
    var pingInterval: UInt32 {
        switch state {
        case .terminating, .peerTerminating, .terminated: return 1000
        default: return 5000
        }
    }

    /// When the reader should see end of stream.
    ///
    /// Xray's `Read` reports EOF only in {ReadyToClose, Terminating, Terminated}
    /// and spins in PeerTerminating until a timer moves the state on four
    /// seconds later; `ReadMultiBuffer` is the one with the PeerTerminating
    /// branch, and that is the one followed here.
    ///
    /// PeerClosed is deliberately not an end. The peer stamps the close bit on
    /// every data segment it writes while in ReadyToClose (sending.go:282-285),
    /// so the segment that moves this end into PeerClosed usually has the rest
    /// of the response queued behind it; ending the stream once the receive
    /// window happens to drain truncates that tail without a word. Such a
    /// connection still finishes — the peer follows with a Terminate once its
    /// own window empties, and the PeerClosed idle backstop in `flush` catches
    /// the case where it never does.
    var readsAreFinished: Bool {
        switch state {
        case .readyToClose, .terminating, .terminated: return true
        case .peerTerminating: return !isDataAvailable
        case .active, .peerClosed: return false
        }
    }

    func takeOutbox() -> [Data] {
        defer { outbox.removeAll(keepingCapacity: true) }
        return outbox
    }

    // MARK: Sending

    /// Queues one payload. False means the window is full and the caller has to
    /// wait for acknowledgements to make room.
    @discardableResult
    func push(_ payload: Data) -> Bool {
        if state != .active { return false }
        // An empty data segment makes the peer reject the whole datagram.
        if payload.isEmpty { return true }
        // Strictly greater, so the window actually holds sendingBufferSize + 1.
        if UInt32(sendingWindow.count) > configuration.sendingBufferSize { return false }
        sendingWindow.append(SendingSegment(number: nextNumber, payload: payload))
        nextNumber &+= 1
        return true
    }

    private func findFirstUnacknowledged() {
        let previous = firstUnacknowledged
        firstUnacknowledged = sendingWindow.first?.number ?? nextNumber
        if previous != firstUnacknowledged { firstUnacknowledgedUpdated = true }
    }

    /// Cumulative acknowledgement. The comparison is deliberately not wraparound
    /// safe: closing the write side clears the window by passing 0xFFFFFFFF, and
    /// a wraparound-safe test would clear only half of it and leave the rest
    /// retransmitting.
    private func clearSendingWindow(before una: UInt32) {
        var count = 0
        while count < sendingWindow.count && sendingWindow[count].number < una { count += 1 }
        if count > 0 { sendingWindow.removeFirst(count) }
    }

    private func removeSendingSegment(_ number: UInt32) -> Bool {
        for index in sendingWindow.indices {
            if sendingWindow[index].number > number { return false }
            if sendingWindow[index].number == number {
                if totalInFlightSize > 0 { totalInFlightSize -= 1 }
                sendingWindow.remove(at: index)
                return true
            }
        }
        return false
    }

    private func processAck(_ number: UInt32) -> Bool {
        // Ignore anything below una or at or above nextNumber, wraparound safe.
        if number &- firstUnacknowledged > 0x7FFF_FFFF { return false }
        if number &- nextNumber < 0x7FFF_FFFF { return false }
        let removed = removeSendingSegment(number)
        if removed { findFirstUnacknowledged() }
        return removed
    }

    /// mKCP has no duplicate-ACK counter. Fast retransmission is a timer cut:
    /// every batch of acknowledgements that actually removed a segment pulls the
    /// deadline of everything older than maxack forward by rto/3, so three
    /// crossing events bring a full RTO forward and the next tick resends. The
    /// unit of counting is the ACK batch, not the number of segments skipped.
    private func handleFastAck(maxack: UInt32, rto: UInt32) {
        let step = rto / 3
        for index in sendingWindow.indices {
            let number = sendingWindow[index].number
            if number == maxack || maxack &- number > 0x7FFF_FFFF { return }
            if sendingWindow[index].transmit > 0 && sendingWindow[index].timeout > step {
                sendingWindow[index].timeout &-= step
            }
        }
    }

    /// `current - timeout >= 0x7FFFFFFF` means the deadline is still in the
    /// future. Such a segment is skipped and the walk continues; breaking out
    /// instead wedges the stream permanently after a single loss.
    static func isDue(current: UInt32, timeout: UInt32) -> Bool {
        (current &- timeout) < 0x7FFF_FFFF
    }

    private func flushSendingWindow(current: UInt32, maxInFlightSize: UInt32) {
        var lost: UInt32 = 0
        var inFlight: UInt32 = 0
        let rto = roundTrip.timeout
        for index in sendingWindow.indices {
            guard Self.isDue(current: current, timeout: sendingWindow[index].timeout) else { continue }
            if sendingWindow[index].transmit == 0 {
                totalInFlightSize &+= 1
            } else {
                lost &+= 1
            }
            sendingWindow[index].timeout = current &+ rto
            // Every retransmission restamps the segment; leaving the original
            // timestamp makes the peer's echo inflate the RTT sample forever.
            sendingWindow[index].timestamp = current
            sendingWindow[index].transmit &+= 1

            var segment = MKCPWireStub.DataSegment()
            segment.conv = configuration.conversation
            segment.option = state == .readyToClose ? MKCPWireStub.optionClose : 0
            segment.timestamp = current
            segment.number = sendingWindow[index].number
            segment.sendingNext = firstUnacknowledged
            segment.payload = sendingWindow[index].payload
            outbox.append(segment.encoded())

            inFlight &+= 1
            // The quota is checked after the write, so even a quota of zero
            // still emits one segment.
            if inFlight >= maxInFlightSize { break }
        }
        if configuration.congestion && inFlight > 0 && totalInFlightSize != 0 {
            onPacketLoss(rate: lost * 100 / totalInFlightSize)
        }
    }

    /// A loss-rate AIMD approximation, not ikcp's slow start: there is no
    /// ssthresh, no collapse to one segment, no dead-link teardown. Copying
    /// ikcp's controller here makes the two ends behave differently on a lossy
    /// path, and nothing reports it.
    private func onPacketLoss(rate: UInt32) {
        if roundTrip.timeout == 0 { return }
        if rate >= 15 { controlWindow = 3 * controlWindow / 4 }
        if rate <= 5 { controlWindow &+= controlWindow / 4 }
        if controlWindow < 16 { controlWindow = 16 }
        // Current main caps at SendingInFlightSize; v1.8.24 caps at twice that.
        let ceiling = configuration.sendingInFlightSize
        if controlWindow > ceiling { controlWindow = ceiling }
    }

    private func flushData(current: UInt32) {
        var cwnd = configuration.sendingInFlightSize
        // Unsigned: once the peer's right edge runs ahead the subtraction
        // underflows to a huge value, which simply stops constraining us.
        let remoteRoom = remoteNextNumber &- firstUnacknowledged
        if cwnd > remoteRoom { cwnd = remoteRoom }
        if configuration.congestion && cwnd > controlWindow { cwnd = controlWindow }
        cwnd = cwnd &* configuration.cwndMultiplier

        if !sendingWindow.isEmpty {
            flushSendingWindow(current: current, maxInFlightSize: cwnd)
            firstUnacknowledgedUpdated = false
        }
        let updated = firstUnacknowledgedUpdated
        firstUnacknowledgedUpdated = false
        // Cleared just above whenever the window is non-empty, so this ping only
        // ever fires on the flush that empties the window.
        if updated { ping(current: current, command: .ping) }
    }

    // MARK: Receiving

    private func ackListAdd(number: UInt32, timestamp: UInt32) {
        ackNumbers.append(number)
        ackTimestamps.append(timestamp)
        ackNextFlush.append(0)
        ackDirty = true
    }

    /// Drops entries the peer's una says it no longer needs. Plain comparison,
    /// no wraparound handling — same as the source.
    private func ackListClear(una: UInt32) {
        var count = 0
        for index in 0..<ackNumbers.count {
            if ackNumbers[index] < una { continue }
            if index != count {
                ackNumbers[count] = ackNumbers[index]
                ackTimestamps[count] = ackTimestamps[index]
                ackNextFlush[count] = ackNextFlush[index]
            }
            count += 1
        }
        if count < ackNumbers.count {
            ackNumbers.removeLast(ackNumbers.count - count)
            ackTimestamps.removeLast(ackTimestamps.count - count)
            ackNextFlush.removeLast(ackNextFlush.count - count)
            ackDirty = true
        }
    }

    private struct AckBuilder {
        let limit: Int
        var numbers: [UInt32] = []
        var timestamp: UInt32 = 0
        var isFull: Bool { numbers.count == limit }
        var isEmpty: Bool { numbers.isEmpty }
        mutating func put(number: UInt32) { numbers.append(number) }
        /// Wraparound-safe maximum: the newest data segment in this batch.
        mutating func put(timestamp value: UInt32) {
            if value &- timestamp < 0x7FFF_FFFF { timestamp = value }
        }
    }

    private func writeAck(_ builder: AckBuilder) {
        var segment = MKCPWireStub.AckSegment()
        // The window fields are computed at serialization time. Packing acks
        // ahead of the send would leave receivingNext stale, and the peer's
        // cumulative clearing would then always run a step behind.
        segment.conv = configuration.conversation
        segment.option = state == .readyToClose ? MKCPWireStub.optionClose : 0
        segment.receivingWindow = receivingNext &+ configuration.receivingInFlightSize
        segment.receivingNext = receivingNext
        segment.timestamp = builder.timestamp
        segment.numbers = builder.numbers
        outbox.append(segment.encoded())
    }

    private func flushAcks(current: UInt32) {
        flushCandidates.removeAll(keepingCapacity: true)
        var builder = AckBuilder(limit: configuration.ackNumberLimit)
        for index in 0..<ackNumbers.count {
            if ackNextFlush[index] > current {
                // Numbers that are not due yet are not skipped, they become
                // candidates: the tail of this routine packs them into the
                // outgoing segment without a timestamp. What the interval
                // throttles is the guaranteed repeat, not the number itself.
                if flushCandidates.count < MKCPWireStub.ackNumberLimit {
                    flushCandidates.append(ackNumbers[index])
                }
                continue
            }
            builder.put(number: ackNumbers[index])
            builder.put(timestamp: ackTimestamps[index])
            var timeout = roundTrip.timeout / 2
            if timeout < 20 { timeout = 20 }
            ackNextFlush[index] = current &+ timeout
            if builder.isFull {
                writeAck(builder)
                builder = AckBuilder(limit: configuration.ackNumberLimit)
                ackDirty = false
            }
        }
        // While dirty, an ack goes out even with no numbers in it at all: it is
        // the only channel for the window edge and the cumulative point.
        if ackDirty || !builder.isEmpty {
            for number in flushCandidates {
                if builder.isFull { break }
                builder.put(number: number)
            }
            writeAck(builder)
            ackDirty = false
        }
    }

    /// Takes the contiguous run starting at receivingNext; out-of-order segments
    /// stay put until the gap is filled. receivingNext advances only here, which
    /// means the window edge this end advertises moves only when the caller
    /// actually reads — that is mKCP's receive-side flow control.
    func readAvailable() -> Data {
        var payload = Data()
        while let segment = receivingWindow.removeValue(forKey: receivingNext) {
            payload.append(segment)
            receivingNext &+= 1
        }
        return payload
    }

    private func receive(_ segment: MKCPWireStub.DataSegment) {
        // Unsigned: a retransmission of something already delivered underflows
        // into a huge index and is dropped without producing an acknowledgement.
        let index = segment.number &- receivingNext
        if index >= configuration.receivingInFlightSize { return }
        ackListClear(una: segment.sendingNext)
        ackListAdd(number: segment.number, timestamp: segment.timestamp)
        if receivingWindow[segment.number] == nil {
            receivingWindow[segment.number] = segment.payload
        }
    }

    // MARK: Input

    func input(_ segments: [MKCPWireStub.Segment], current: UInt32) {
        lastIncomingTime = current
        for segment in segments {
            // A conv mismatch discards the rest of the datagram, not just this
            // one segment.
            guard segment.conv == configuration.conversation else { break }
            handleOption(segment.option, current: current)
            switch segment {
            case .data(let data):
                receive(data)
            case .ack(let ack):
                // Read per segment, as connection.go:581 does. A datagram may
                // chain several acks, and an earlier one can already have moved
                // the RTO that the fast-ack cut is a third of.
                process(ack, current: current, rto: roundTrip.timeout)
            case .cmd(let cmd):
                if cmd.command == MKCPWireStub.Command.terminate.rawValue {
                    switch state {
                    case .active, .peerClosed: setState(.peerTerminating, current: current)
                    case .readyToClose: setState(.terminating, current: current)
                    case .terminating: setState(.terminated, current: current)
                    default: break
                    }
                }
                clearSendingWindow(before: cmd.receivingNext)
                findFirstUnacknowledged()
                ackListClear(una: cmd.sendingNext)
                roundTrip.adoptPeer(rto: cmd.peerRTO, current: current)
            }
        }
    }

    private func handleOption(_ option: UInt8, current: UInt32) {
        guard option & MKCPWireStub.optionClose == MKCPWireStub.optionClose else { return }
        switch state {
        case .readyToClose: setState(.terminating, current: current)
        case .active: setState(.peerClosed, current: current)
        default: break
        }
    }

    private func process(_ ack: MKCPWireStub.AckSegment, current: UInt32, rto: UInt32) {
        // Absolute right edge, monotonic.
        if remoteNextNumber < ack.receivingWindow { remoteNextNumber = ack.receivingWindow }
        clearSendingWindow(before: ack.receivingNext)
        findFirstUnacknowledged()
        if ack.numbers.isEmpty { return }

        var maxack: UInt32 = 0
        var maxackRemoved = false
        for number in ack.numbers {
            let removed = processAck(number)
            // Plain comparison against a zero-initialised maxack: a batch whose
            // largest number is 0 leaves maxackRemoved false and triggers
            // neither fast retransmit nor RTT sampling. The first data segment
            // of a connection is numbered 0, so Xray genuinely takes no sample
            // from the opening exchange. Copied verbatim — "fixing" it makes
            // this end's RTO converge faster than the peer's and the two
            // implementations diverge.
            if maxack < number {
                maxack = number
                maxackRemoved = removed
            }
        }
        guard maxackRemoved else { return }
        handleFastAck(maxack: maxack, rto: rto)
        // The sample comes from the timestamp echoed in the ack, never from a
        // local record. Xray fills spare room in an ack with candidate numbers
        // and no timestamp, so acks carrying numbers but a zero timestamp are
        // routine; accepting one yields a bogus sample of "the current elapsed
        // time" and poisons srtt.
        if ack.timestamp != 0 && current &- ack.timestamp < 10000 {
            roundTrip.update(rtt: current &- ack.timestamp, current: current)
        }
    }

    // MARK: Transitions

    private func setState(_ next: State, current: UInt32) {
        state = next
        stateBeginTime = current
        switch next {
        case .peerClosed, .terminating, .peerTerminating, .terminated:
            // Closing the write side throws away everything still queued.
            clearSendingWindow(before: 0xFFFF_FFFF)
        case .active, .readyToClose:
            break
        }
    }

    func closeLocally(current: UInt32) {
        switch state {
        case .readyToClose, .terminating, .terminated: return
        case .active: setState(.readyToClose, current: current)
        case .peerClosed: setState(.terminating, current: current)
        case .peerTerminating: setState(.terminated, current: current)
        }
    }

    private func ping(current: UInt32, command: MKCPWireStub.Command) {
        var segment = MKCPWireStub.CmdSegment()
        segment.conv = configuration.conversation
        segment.command = command.rawValue
        segment.option = state == .readyToClose ? MKCPWireStub.optionClose : 0
        segment.sendingNext = firstUnacknowledged
        segment.receivingNext = receivingNext
        segment.peerRTO = roundTrip.timeout
        outbox.append(segment.encoded())
        lastPingTime = current
    }

    func flush(current: UInt32) {
        if state == .terminated { return }
        if state == .active && current &- lastIncomingTime >= 30000 {
            closeLocally(current: current)
        }
        // Xray's idle check is guarded on StateActive, so a connection whose
        // peer closed first never times out on its own and pings every five
        // seconds forever. This is the backstop for that.
        if state == .peerClosed && current &- lastIncomingTime >= 30000 {
            closeLocally(current: current)
        }
        if state == .readyToClose && sendingWindow.isEmpty {
            setState(.terminating, current: current)
        }
        if state == .terminating {
            ping(current: current, command: .terminate)
            if current &- stateBeginTime > 8000 { setState(.terminated, current: current) }
            return
        }
        if state == .peerTerminating && current &- stateBeginTime > 4000 {
            setState(.terminating, current: current)
        }
        if state == .readyToClose && current &- stateBeginTime > 15000 {
            setState(.terminating, current: current)
        }

        // The order is fixed: acknowledgements leave ahead of data.
        flushAcks(current: current)
        flushData(current: current)

        if current &- lastPingTime >= 3000 {
            ping(current: current, command: .ping)
        }
    }

    // MARK: Self-test hooks

    /// How far the fast-ack cut has moved each deadline has no external effect
    /// whatsoever, so pinning it is the only way to test it.
    var pendingTimeouts: [UInt32] { sendingWindow.map(\.timeout) }
    var pendingNumbers: [UInt32] { sendingWindow.map(\.number) }
}

// MARK: - ByteTransport

/// mKCP as a byte stream.
///
/// State is guarded by an NSLock and no callback is ever invoked while it is
/// held — a callback that turns around and calls `send` or `receive` would
/// deadlock against it. The timer is a chain of one-shot `asyncAfter` closures
/// tagged with a generation number rather than a DispatchSourceTimer: bumping
/// the generation invalidates every closure already in flight, so a cancelled
/// connection stops retransmitting instead of burning a core.
final class MKCPTransport: ByteTransport {
    private struct PendingWrite {
        let data: Data
        /// Bytes already handed to the sending window. An offset rather than a
        /// `removeFirst`, which would make one large write quadratic — and Data
        /// indices are not zero-based, so slicing it is easy to get wrong.
        var offset: Int = 0
        let done: (Error?) -> Void
    }

    /// The datagram substrate. The self-test injects a sink instead and never
    /// touches the network.
    private enum Substrate {
        case datagram(KCPDatagramChannel)
        case injected((Data) -> Void)
    }

    private let queue: DispatchQueue
    private let configuration: MKCPConfiguration
    private let session: MKCPSession
    private let substrate: Substrate
    private let clock: () -> UInt32
    /// The self-test turns this off and ticks the state machine by hand.
    private let selfDriving: Bool

    private let lock = NSLock()
    private var pendingReceive: ((Data?, Bool, Error?) -> Void)?
    private var pendingWrites: [PendingWrite] = []
    private var closing = false
    private var closeBeganAt: UInt32 = 0
    private var cancelled = false
    private var failure: Error?
    private var tickGeneration: UInt64 = 0
    private var tickPending = false
    private var tickDeadline: UInt32 = 0

    private init(configuration: MKCPConfiguration, queue: DispatchQueue,
                 substrate: Substrate, clock: (() -> UInt32)?, selfDriving: Bool) {
        self.configuration = configuration
        self.queue = queue
        self.substrate = substrate
        self.selfDriving = selfDriving
        self.session = MKCPSession(configuration: configuration)
        if let clock {
            self.clock = clock
        } else {
            // Monotonic and starting at zero. Never a truncated Unix clock.
            let epoch = DispatchTime.now().uptimeNanoseconds
            self.clock = {
                UInt32(truncatingIfNeeded: (DispatchTime.now().uptimeNanoseconds &- epoch) / 1_000_000)
            }
        }
    }

    deinit { closeSubstrate() }

    /// Xray seeds a global counter with a random uint16 and adds one per dial,
    /// so one client's connections carry adjacent conversation numbers. No
    /// server checks this, but the traffic should look the same.
    private static let conversationLock = NSLock()
    private static var conversationCounter = UInt16.random(in: 0...UInt16.max)

    static func allocateConversation() -> UInt16 {
        conversationLock.lock()
        defer { conversationLock.unlock() }
        conversationCounter &+= 1
        return conversationCounter
    }

    static func connect(host: String, port: UInt16,
                        configuration: MKCPConfiguration = MKCPConfiguration(),
                        queue: DispatchQueue, timeout: TimeInterval = 10,
                        completion: @escaping (Result<MKCPTransport, Error>) -> Void) {
        KCPDatagramChannel.connect(host: host, port: port, queue: queue, timeout: timeout) { result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let channel):
                let transport = MKCPTransport(configuration: configuration, queue: queue,
                                              substrate: .datagram(channel), clock: nil,
                                              selfDriving: true)
                // mKCP has no handshake. The server's session springs into
                // existence when the first parseable segment arrives, and until
                // then there is nothing to wait for and nothing to hear back,
                // so the transport is reported ready immediately.
                transport.readDatagrams(from: channel)
                transport.drive(tick: false)
                completion(.success(transport))
            }
        }
    }

    /// Self-test entry point: no network, caller owns the clock and the ticks.
    static func inMemory(configuration: MKCPConfiguration, queue: DispatchQueue,
                         clock: @escaping () -> UInt32,
                         sink: @escaping (Data) -> Void) -> MKCPTransport {
        MKCPTransport(configuration: configuration, queue: queue,
                      substrate: .injected(sink), clock: clock, selfDriving: false)
    }

    // MARK: Substrate

    /// Wraps everything the session has queued. Called with the lock held: the
    /// wrapper is allowed to be stateful — the camouflage headers carry a
    /// per-packet counter — and sealing after the unlock would let two drives
    /// race on it. `open` already runs inside the lock, so this keeps the codec
    /// single-threaded in both directions.
    private func sealOutbox() -> [Data] {
        session.takeOutbox().map { configuration.datagram.seal($0) }
    }

    private func emit(_ datagram: Data) {
        switch substrate {
        case .datagram(let channel): channel.send(datagram)
        case .injected(let sink): sink(datagram)
        }
    }

    private func closeSubstrate() {
        if case .datagram(let channel) = substrate { channel.cancel() }
    }

    private func readDatagrams(from channel: KCPDatagramChannel) {
        channel.receive { [weak self] data, error in
            guard let self else { return }
            self.lock.lock()
            let dead = self.cancelled
            self.lock.unlock()
            if dead { return }
            if error != nil {
                // A failed datagram read is not fatal to the session — the ARQ
                // retransmits — but NWConnection delivers nothing more after an
                // error, so treat it as the end of the connection.
                self.teardown(NativeOutboundError.connection("mKCP 数据报通道中断"))
                return
            }
            if let data, !data.isEmpty { self.input(datagram: data) }
            self.readDatagrams(from: channel)
        }
    }

    /// Feeds one wire datagram, still wrapped.
    func input(datagram: Data) {
        drive(tick: false) { session, current in
            // A datagram that will not unwrap is dropped in silence; the
            // obfuscation layer has no way to report anything, and Xray drops it
            // just the same.
            guard let plain = self.configuration.datagram.open(datagram) else { return }
            session.input(MKCPWireStub.decode(plain), current: current)
        }
    }

    /// Self-test only: run one flush by hand.
    func tick() { drive(tick: true) }

    // MARK: Driving

    /// The one place the state machine moves.
    ///
    /// Everything that has to happen under the lock — advancing the machine,
    /// collecting outbound datagrams, deciding which callbacks are owed — is
    /// done first; the socket writes and the callbacks happen after unlocking.
    private func drive(tick: Bool, generation: UInt64? = nil,
                       _ body: ((MKCPSession, UInt32) -> Void)? = nil) {
        lock.lock()
        if cancelled {
            lock.unlock(); return
        }
        if let generation {
            guard generation == tickGeneration else { lock.unlock(); return }
            tickPending = false
        }
        let current = clock()
        body?(session, current)

        var completions: [() -> Void] = []
        if session.acceptsWrites {
            // Whatever does not fit stays queued until acknowledgements free
            // room in the window.
            while var head = pendingWrites.first {
                while head.offset < head.data.count {
                    let start = head.data.startIndex + head.offset
                    let end = min(start + Int(session.mss), head.data.endIndex)
                    guard session.push(Data(head.data[start..<end])) else { break }
                    head.offset += end - start
                }
                if head.offset == head.data.count {
                    pendingWrites.removeFirst()
                    let done = head.done
                    completions.append { done(nil) }
                } else {
                    pendingWrites[0] = head
                    break
                }
            }
        } else if !pendingWrites.isEmpty {
            for write in pendingWrites {
                let done = write.done
                completions.append { done(NativeOutboundError.connection("mKCP 连接已关闭")) }
            }
            pendingWrites.removeAll()
        }

        if tick { session.flush(current: current) }

        var readCallback: ((Data?, Bool, Error?) -> Void)?
        var readPayload: Data?
        var readEnded = false
        if let waiting = pendingReceive {
            if session.isDataAvailable {
                readPayload = session.readAvailable()
                readEnded = session.readsAreFinished
                readCallback = waiting
                pendingReceive = nil
            } else if session.readsAreFinished {
                readEnded = true
                readCallback = waiting
                pendingReceive = nil
            }
        }

        let datagrams = sealOutbox()
        // The grace period is measured on the same clock the state machine uses,
        // so it holds on the self-test's virtual timeline too.
        let graceExpired = closing && current &- closeBeganAt >= configuration.closeGrace
        let dead = session.state == .terminated || graceExpired
        if !dead { scheduleNext(tick: tick, current: current) }
        lock.unlock()

        for datagram in datagrams { emit(datagram) }
        for done in completions { done() }
        readCallback?(readPayload, readEnded, nil)
        if dead { teardown(nil) }
    }

    /// Schedules the next tick. Called with the lock held.
    ///
    /// Runs at tti while there is data or an acknowledgement outstanding and
    /// falls back to the heartbeat cadence otherwise, so an idle connection does
    /// not wake up every 20ms. This is Xray's data updater and ping updater
    /// collapsed into one loop.
    private func scheduleNext(tick: Bool, current: UInt32) {
        guard selfDriving, !cancelled else { return }
        let necessary = session.updateNecessary
        if tick {
            schedule(after: necessary ? configuration.tti : session.pingInterval, current: current)
        } else if !tickPending {
            schedule(after: necessary ? 0 : session.pingInterval, current: current)
        } else if necessary && tickDeadline &- current > configuration.tti {
            // Parked on a distant heartbeat tick with work to do.
            schedule(after: 0, current: current)
        }
    }

    private func schedule(after delay: UInt32, current: UInt32) {
        tickGeneration &+= 1
        tickPending = true
        tickDeadline = current &+ delay
        let generation = tickGeneration
        queue.asyncAfter(deadline: .now() + .milliseconds(Int(delay))) { [weak self] in
            self?.drive(tick: true, generation: generation)
        }
    }

    /// Tears everything down: invalidates scheduled ticks, closes the socket,
    /// settles whoever was waiting.
    private func teardown(_ error: Error?) {
        lock.lock()
        guard !cancelled else { lock.unlock(); return }
        cancelled = true
        failure = error
        // One bump retires every asyncAfter closure already queued. Without it a
        // closed connection keeps retransmitting, which reads as a spinning CPU.
        tickGeneration &+= 1
        tickPending = false
        let waiting = pendingReceive
        pendingReceive = nil
        let writes = pendingWrites
        pendingWrites.removeAll()
        lock.unlock()

        closeSubstrate()
        waiting?(nil, true, error)
        let reason = error ?? NativeOutboundError.connection("mKCP 连接已关闭")
        for write in writes { write.done(reason) }
    }

    // MARK: ByteTransport

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !data.isEmpty else { completion(nil); return }
        lock.lock()
        if let failure { lock.unlock(); completion(failure); return }
        if cancelled || closing || !session.acceptsWrites {
            lock.unlock()
            completion(NativeOutboundError.connection("mKCP 连接已关闭"))
            return
        }
        pendingWrites.append(PendingWrite(data: data, done: completion))
        lock.unlock()
        drive(tick: false)
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock()
        if let failure { lock.unlock(); completion(nil, true, failure); return }
        if cancelled { lock.unlock(); completion(nil, true, nil); return }
        if session.isDataAvailable {
            let payload = session.readAvailable()
            let ended = session.readsAreFinished
            lock.unlock()
            completion(payload, ended, nil)
            // Reading is what advances receivingNext, and therefore what moves
            // the window edge this end advertises, so an ack should follow.
            drive(tick: false)
            return
        }
        if session.readsAreFinished {
            lock.unlock(); completion(nil, true, nil); return
        }
        pendingReceive = completion
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        guard !cancelled, !closing else { lock.unlock(); return }
        closing = true
        let current = clock()
        closeBeganAt = current
        // Go through the graceful close so the Terminate actually goes out;
        // dropping the socket instead leaves the server holding the session
        // until its 30-second idle timeout.
        session.closeLocally(current: current)
        session.flush(current: current)
        let datagrams = sealOutbox()
        let waiting = pendingReceive
        pendingReceive = nil
        let writes = pendingWrites
        pendingWrites.removeAll()
        // Restart the tick chain on the teardown cadence. Without this the
        // connection stays parked on whatever tick it had — up to the five
        // second heartbeat — and the single Terminate written just above is the
        // only one that ever goes out, so losing it costs the server its full
        // 30-second idle timeout.
        scheduleNext(tick: true, current: current)
        lock.unlock()

        for datagram in datagrams { emit(datagram) }
        waiting?(nil, true, nil)
        for write in writes { write.done(NativeOutboundError.connection("mKCP 连接已关闭")) }

        guard selfDriving else { return }
        // Deliberately strong for the length of the grace period, so the state
        // machine can repeat the Terminate even if the caller drops its
        // reference the moment it cancels.
        queue.asyncAfter(deadline: .now() + .milliseconds(Int(configuration.closeGrace))) {
            self.teardown(nil)
        }
    }
}

// Hooks for the self-test. None of the ARQ's internal state is observable from
// the outside, and "connects but is slow" is exactly how this layer fails.
extension MKCPTransport {
    var mssForSelfTest: UInt32 { configuration.mss }

    var pendingSegmentsForSelfTest: Int {
        lock.lock(); defer { lock.unlock() }
        return session.pendingNumbers.count
    }

    func timeoutForSelfTest(number: UInt32) -> UInt32? {
        lock.lock(); defer { lock.unlock() }
        guard let index = session.pendingNumbers.firstIndex(of: number) else { return nil }
        return session.pendingTimeouts[index]
    }
}

// MARK: - Self-test

public enum MKCPTransportSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "mKCP 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try windowDerivation()
        try expiryPredicate()
        try roundTripKnownAnswers()
        try peerRTOAdoption()
        try dataSegmentKnownAnswer()
        try ackSegmentKnownAnswer()
        try pingKnownAnswer()
        try closeSegmentKnownAnswers()
        try sendingWindowLimit()
        try maxAckZeroQuirk()
        try fastAckTimerMath()
        try receiveWindowAdmission()
        try stateMachineTimeouts()
        try orderedTransfer()
        try reorderedDelivery()
        try lossRecovery()
        try fastRetransmit()
        try writeBackpressure()
        try closeHandshake()
        try closeWithPendingData()
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// One conversation number throughout, so the pinned bytes stay readable.
    private static let conv: UInt16 = 0x1234

    private static func configuration(tti: UInt32 = 20, mtu: UInt32 = 1350,
                                      maxSendingWindow: UInt32 = 2 * 1024 * 1024) -> MKCPConfiguration {
        var config = MKCPConfiguration()
        config.conversation = conv
        config.tti = tti
        config.mtu = mtu
        config.maxSendingWindow = maxSendingWindow
        return config
    }

    // MARK: Known answers

    /// Window and mss arithmetic.
    ///
    /// Every division is integral, including the inner 1000/tti; done in
    /// floating point the windows come out different, which shows up as a
    /// throughput difference and never as an error. For mtu 1350, tti 20,
    /// 5 MB/s up and 20 MB/s down:
    ///   sending in flight   = 5 * 1048576 / 1350 / (1000/20)  = 3883 / 50  = 77
    ///   receiving in flight = 20 * 1048576 / 1350 / (1000/20) = 15534 / 50 = 310
    ///   sending buffer      = 2097152 / 1350                               = 1553
    ///   mss with a 6-byte wrapper = 1350 - 6 - 18                          = 1326
    private static func windowDerivation() throws {
        var config = configuration()
        config.datagram = MKCPDatagramCodec(overhead: 6, seal: { $0 }, open: { $0 })
        try expect(config.sendingInFlightSize == 77, "上行在途窗口应为 77，实际 \(config.sendingInFlightSize)")
        try expect(config.receivingInFlightSize == 310, "下行在途窗口应为 310，实际 \(config.receivingInFlightSize)")
        try expect(config.sendingBufferSize == 1553, "发送缓冲应为 1553 段，实际 \(config.sendingBufferSize)")
        try expect(config.mss == 1326, "mss 应为 1326，实际 \(config.mss)")
        try expect(config.ackNumberLimit == 128, "SACK 上限应钳到 128，实际 \(config.ackNumberLimit)")

        // The kernel default of tti 50: 5*1048576/1350/20 = 194, 20*.../20 = 776.
        let slow = configuration(tti: 50)
        try expect(slow.sendingInFlightSize == 194, "tti=50 时上行窗口应为 194，实际 \(slow.sendingInFlightSize)")
        try expect(slow.receivingInFlightSize == 776, "tti=50 时下行窗口应为 776，实际 \(slow.receivingInFlightSize)")

        // The floor of 8 exists so a small capacity cannot compute a zero window.
        var tiny = configuration()
        tiny.uplinkCapacity = 1
        tiny.mtu = 1460
        tiny.tti = 10
        try expect(tiny.sendingInFlightSize == 8, "窗口下限应为 8，实际 \(tiny.sendingInFlightSize)")

        // Bare segments, as current main computes them: mss = Mtu - 18.
        let bare = configuration()
        try expect(bare.mss == 1332, "裸段 mss 应为 1332，实际 \(bare.mss)")
    }

    /// The expiry test is a wraparound comparison, and the clock has to start at
    /// zero for it to work.
    ///
    /// A freshly pushed segment carries a timeout of zero. With a truncated Unix
    /// clock, `current` spends about half its time above 0x7FFFFFFF, where
    /// current - 0 makes every new segment look like it is not due yet — no data
    /// leaves at all, and the fault comes and goes on a 49.7-day cycle.
    private static func expiryPredicate() throws {
        try expect(MKCPSession.isDue(current: 0, timeout: 0), "current==timeout 应判为到期")
        try expect(MKCPSession.isDue(current: 100, timeout: 0), "新段应立刻到期")
        try expect(!MKCPSession.isDue(current: 100, timeout: 200), "未到期的段不应被发出")
        try expect(MKCPSession.isDue(current: 0x7FFF_FFFE, timeout: 0), "边界内应仍判到期")
        try expect(!MKCPSession.isDue(current: 0x8000_0000, timeout: 0),
                   "Unix 毫秒截断做时钟会让新段永远发不出去，这里必须复现该判据")
        try expect(MKCPSession.isDue(current: 10, timeout: 0xFFFF_FFF0), "回绕后应判为到期")
    }

    /// Pinned RTO values.
    ///
    /// Getting this wrong only ever presents as "connects but is slow", which a
    /// round-trip test cannot see. The numbers below were computed here from the
    /// algorithm in kcp/connection.go:73-107, not copied:
    ///   first sample  srtt = rtt, variation = rtt/2
    ///   afterwards    variation = (3*variation + |rtt-srtt|)/4,
    ///                 srtt = (7*srtt + rtt)/8 clamped up to minRtt
    ///   raw = (minRtt < 4*variation) ? srtt + 4*variation : srtt + variation
    ///   rto = min(raw, 10000) * 5 / 4
    /// With minRtt 20 and a constant rtt of 100 the variation decays by 3/4 each
    /// time — 50, 37, 27, 20, 15, 11, 8, 6, 4, 3, 2, 1, 0 — so from the ninth
    /// sample 4*variation drops below minRtt, the branch flips, the RTO falls
    /// from 155 to 130 and converges on 100 * 5/4 = 125.
    private static func roundTripKnownAnswers() throws {
        var info = MKCPRoundTrip(minRtt: 20)
        try expect(info.timeout == 100, "RTO 初值应为 100，实际 \(info.timeout)")

        let expected: [UInt32] = [375, 310, 260, 225, 200, 180, 165, 155, 130, 128, 127, 126, 125, 125]
        var produced: [UInt32] = []
        for step in 0..<expected.count {
            info.update(rtt: 100, current: UInt32(step) * 4000)
            produced.append(info.timeout)
        }
        try expect(produced == expected, "RTO 序列应为 \(expected)，实际 \(produced)")
        try expect(info.srtt == 100, "srtt 应收敛到 100，实际 \(info.srtt)")
        try expect(info.variation == 0, "variation 应收敛到 0，实际 \(info.variation)")

        // raw is clamped to 10000 before the 5/4, so the ceiling is 12500.
        var slow = MKCPRoundTrip(minRtt: 20)
        slow.update(rtt: 8000, current: 0)
        try expect(slow.timeout == 12500, "RTO 上限应为 12500，实际 \(slow.timeout)")

        // srtt has a floor of minRtt, but only from the second sample on.
        var floored = MKCPRoundTrip(minRtt: 50)
        var flooredOut: [UInt32] = []
        for (step, rtt) in [UInt32(100), 10, 10, 10, 10, 10].enumerated() {
            floored.update(rtt: rtt, current: UInt32(step) * 4000)
            flooredOut.append(floored.timeout)
        }
        try expect(flooredOut == [375, 410, 417, 411, 391, 367],
                   "srtt 截到 minRtt 后的 RTO 序列不符：\(flooredOut)")
        try expect(floored.srtt >= 50, "srtt 不应低于 minRtt，实际 \(floored.srtt)")

        // A wrapped, "negative" sample must not reach srtt.
        var guarded = MKCPRoundTrip(minRtt: 20)
        guarded.update(rtt: 0x8000_0000, current: 1000)
        try expect(guarded.timeout == 100 && guarded.srtt == 0, "非法 RTT 应被丢弃")
    }

    /// The peer's advertised RTO overwrites ours outright, gated only by three
    /// seconds.
    private static func peerRTOAdoption() throws {
        var info = MKCPRoundTrip(minRtt: 20)
        info.adoptPeer(rto: 555, current: 5000)
        try expect(info.timeout == 555, "应采纳对端 RTO，实际 \(info.timeout)")
        info.adoptPeer(rto: 999, current: 7000)
        try expect(info.timeout == 555, "3 秒内的第二次广播应被节流，实际 \(info.timeout)")
        info.adoptPeer(rto: 999, current: 8001)
        try expect(info.timeout == 999, "超过节流窗口应采纳，实际 \(info.timeout)")

        // A local measurement refreshes the same timestamp and shadows the peer.
        var mixed = MKCPRoundTrip(minRtt: 20)
        mixed.update(rtt: 100, current: 10000)
        let measured = mixed.timeout
        mixed.adoptPeer(rto: 12500, current: 11000)
        try expect(mixed.timeout == measured, "新鲜的本地测量应屏蔽对端广播")
    }

    /// DataSegment on the wire.
    ///
    /// Layout per kcp/segment.go:107-116 — conv(BE16) | 0x01 | opt | ts(BE32) |
    /// sn(BE32) | una(BE32) | len(BE16) | payload. With conv 0x1234, ts 1000
    /// (0x3e8), sn 0, una 0 and "hello" (68 65 6c 6c 6f) that is 18 + 5 bytes.
    private static func dataSegmentKnownAnswer() throws {
        let session = MKCPSession(configuration: configuration())
        try expect(session.push(Data("hello".utf8)), "首个段应能进窗口")
        session.flush(current: 1000)
        let out = session.takeOutbox()
        try expect(out.count == 1, "应恰好发出 1 个数据报，实际 \(out.count)")
        try expect(hex(out[0]) == "12340100000003e80000000000000000000568656c6c6f",
                   "DataSegment 字节不符：\(hex(out[0]))")

        // Numbers start at 0 and count up per push; una stays 0 until an ack.
        // The first segment is not due again, so only the new one goes out.
        try expect(session.push(Data("x".utf8)), "第二个段应能进窗口")
        session.flush(current: 1001)
        let second = session.takeOutbox()
        try expect(second.count == 1, "第二轮应只发新段（首段尚未到期）")
        try expect(hex(second[0]) == "12340100000003e90000000100000000000178",
                   "第二个 DataSegment 字节不符：\(hex(second[0]))")
    }

    /// AckSegment on the wire.
    ///
    /// Layout per kcp/segment.go:212-225 — conv(BE16) | 0x00 | opt |
    /// recvWindow(BE32) | recvNext(BE32) | ts(BE32) | count(u8) | count * BE32.
    /// Three data segments numbered 0..2 with timestamps 100, 200, 300 arrive
    /// and nothing is read, so recvNext stays 0, recvWindow is 0 + 310 = 0x136,
    /// the echoed timestamp is the batch maximum 300 = 0x12c and count is 3.
    private static func ackSegmentKnownAnswer() throws {
        let session = MKCPSession(configuration: configuration())
        for (number, timestamp) in [(UInt32(0), UInt32(100)), (1, 200), (2, 300)] {
            var segment = MKCPWireStub.DataSegment()
            segment.conv = conv
            segment.timestamp = timestamp
            segment.number = number
            segment.payload = Data([UInt8(0x61 + number)])
            session.input([.data(segment)], current: 900)
        }
        session.flush(current: 1000)
        let out = session.takeOutbox()
        try expect(out.count == 1, "应恰好发出 1 个 ACK，实际 \(out.count)")
        try expect(hex(out[0]) == "1234000000000136000000000000012c03000000000000000100000002",
                   "AckSegment 字节不符：\(hex(out[0]))")

        // Reading is what moves the edge: recvNext 3, recvWindow 3 + 310 = 0x139.
        let payload = session.readAvailable()
        try expect(payload == Data("abc".utf8), "应读出连续的三段载荷")
        session.flush(current: 1100)
        let after = session.takeOutbox()
        try expect(after.count == 1, "第二轮应只发一个 ACK，实际 \(after.count)")
        try expect(hex(after[0]) == "1234000000000139000000030000012c03000000000000000100000002",
                   "读走数据后的 AckSegment 字节不符：\(hex(after[0]))")

        // What is advertised is an absolute edge, not a window size. A constant
        // there pins the peer's remoteNextNumber and, past that many segments,
        // removes flow control entirely.
        let decoded = MKCPWireStub.decode(after[0])
        guard case .ack(let ack)? = decoded.first else {
            throw Failure(text: "ACK 未能解析回来")
        }
        try expect(ack.receivingWindow == ack.receivingNext + 310,
                   "receivingWindow 必须是 recvNext + 接收窗口，实际 \(ack.receivingWindow)")
    }

    /// Ping on the wire: conv | 0x03 | opt | una(BE32) | recvNext(BE32) |
    /// peerRTO(BE32). An idle connection sends one once current - lastPingTime
    /// reaches 3000; peerRTO is this end's current RTO, still the seed 100 =
    /// 0x64. Sending zero there makes the peer zero its own RTO and retransmit
    /// its whole window every tick.
    private static func pingKnownAnswer() throws {
        let session = MKCPSession(configuration: configuration())
        session.flush(current: 2999)
        try expect(session.takeOutbox().isEmpty, "未到 3000ms 不应发 Ping")
        session.flush(current: 3000)
        let out = session.takeOutbox()
        try expect(out.count == 1, "应恰好发出 1 个 Ping，实际 \(out.count)")
        try expect(hex(out[0]) == "12340300000000000000000000000064",
                   "Ping 字节不符：\(hex(out[0]))")
    }

    /// Closing segments.
    ///
    /// The close bit is set only while in ReadyToClose. On a healthy connection
    /// it is zero; a stray one makes the peer throw away everything it had
    /// queued, and the connection then stays up but silent in that direction.
    private static func closeSegmentKnownAnswers() throws {
        // Closing with data still queued: the data keeps flowing with the close
        // bit set, and the state only advances once the window empties.
        let pending = MKCPSession(configuration: configuration())
        pending.push(Data("hi".utf8))
        pending.closeLocally(current: 500)
        pending.flush(current: 1000)
        let out = pending.takeOutbox()
        try expect(out.count == 1, "应只发出待重传的数据段，实际 \(out.count)")
        try expect(hex(out[0]) == "12340101000003e8000000000000000000026869",
                   "关闭中的 DataSegment 字节不符：\(hex(out[0]))")
        try expect(pending.state == .readyToClose, "窗口非空时应停在 ReadyToClose")

        // Closing with an empty window goes straight to Terminating and sends a
        // Terminate — by which point the state is no longer ReadyToClose, so the
        // option byte is zero.
        let idle = MKCPSession(configuration: configuration())
        idle.closeLocally(current: 500)
        idle.flush(current: 1000)
        let terminate = idle.takeOutbox()
        try expect(terminate.count == 1, "应恰好发出 1 个 Terminate，实际 \(terminate.count)")
        try expect(hex(terminate[0]) == "12340200000000000000000000000064",
                   "Terminate 字节不符：\(hex(terminate[0]))")
        try expect(idle.state == .terminating, "空窗口关闭后应进入 Terminating")
    }

    // MARK: State machine and windows

    /// The backpressure test is a strict greater-than, so the window really
    /// holds sendingBufferSize + 1 segments.
    private static func sendingWindowLimit() throws {
        // 5400 / 1350 = 4.
        let session = MKCPSession(configuration: configuration(maxSendingWindow: 5400))
        try expect(session.configuration.sendingBufferSize == 4,
                   "本例的背压阈值应为 4，实际 \(session.configuration.sendingBufferSize)")
        for index in 0..<5 {
            try expect(session.push(Data([UInt8(index)])), "第 \(index + 1) 个段应能进窗口")
        }
        try expect(!session.push(Data([9])), "第 6 个段应被背压挡住")
        try expect(session.pendingNumbers == [0, 1, 2, 3, 4], "窗口内容不符：\(session.pendingNumbers)")
    }

    /// A batch whose largest acknowledged number is 0 triggers neither fast
    /// retransmit nor RTT sampling, because maxack starts at zero and the
    /// comparison is a plain one. The first data segment of a connection is
    /// numbered 0, so this is the common opening exchange; copying it keeps our
    /// RTO from converging faster than the peer's.
    private static func maxAckZeroQuirk() throws {
        let session = MKCPSession(configuration: configuration())
        session.push(Data("a".utf8))
        session.push(Data("b".utf8))
        session.flush(current: 100)
        _ = session.takeOutbox()

        var onlyZero = MKCPWireStub.AckSegment()
        onlyZero.conv = conv
        onlyZero.receivingWindow = 310
        onlyZero.receivingNext = 0
        onlyZero.timestamp = 100
        onlyZero.numbers = [0]
        session.input([.ack(onlyZero)], current: 200)
        try expect(session.roundTrip.timeout == 100, "只确认 0 号段不应产生 RTT 样本")

        var withOne = MKCPWireStub.AckSegment()
        withOne.conv = conv
        withOne.receivingWindow = 310
        withOne.receivingNext = 0
        withOne.timestamp = 100
        withOne.numbers = [1]
        session.input([.ack(withOne)], current: 200)
        // rtt = 200 - 100 = 100, first sample, so srtt 100 and variation 50;
        // 20 < 200 takes the wide branch: raw = 100 + 200, rto = 300 * 5/4.
        try expect(session.roundTrip.timeout == 375,
                   "确认 1 号段应产生 RTT 样本并把 RTO 推到 375，实际 \(session.roundTrip.timeout)")
    }

    /// Pinned fast-retransmit arithmetic. Every batch that removed a segment
    /// pulls the deadline of everything older than maxack forward by rto/3; with
    /// the seed RTO of 100 that is 33 a time, and after three batches the
    /// deadline has moved from current+100 to current+1 — a whole RTO earlier.
    private static func fastAckTimerMath() throws {
        let session = MKCPSession(configuration: configuration())
        for index in 0..<5 { session.push(Data([UInt8(index)])) }
        session.flush(current: 1000)
        _ = session.takeOutbox()
        try expect(session.pendingTimeouts == [1100, 1100, 1100, 1100, 1100],
                   "首发后各段的到期时刻应为 current+rto：\(session.pendingTimeouts)")

        // Segments at or beyond maxack must not move at all — the walk stops
        // there.
        let expected: [[UInt32]] = [[1067, 1067, 1100, 1100],
                                    [1034, 1034, 1100],
                                    [1001, 1001]]
        for round in 1...3 {
            var ack = MKCPWireStub.AckSegment()
            ack.conv = conv
            ack.receivingWindow = 310
            ack.receivingNext = 0
            // Timestamp left at zero: this measures the timer, and a sample here
            // would move the RTO out from under it.
            ack.timestamp = 0
            ack.numbers = [UInt32(round + 1)]
            session.input([.ack(ack)], current: 1000)
            try expect(session.roundTrip.timeout == 100, "本例中 RTO 应保持 100")
            try expect(session.pendingTimeouts == expected[round - 1],
                       "第 \(round) 次跨越后各段到期时刻应为 \(expected[round - 1])，实际 \(session.pendingTimeouts)")
        }
        session.flush(current: 1001)
        try expect(!session.takeOutbox().isEmpty, "到期后应立刻重发")
    }

    /// Admission into the receiving window is an unsigned subtraction: anything
    /// already delivered underflows into a huge index and is dropped without an
    /// acknowledgement, which is also why a random initial sequence number makes
    /// every segment disappear.
    private static func receiveWindowAdmission() throws {
        let session = MKCPSession(configuration: configuration())
        var far = MKCPWireStub.DataSegment()
        far.conv = conv
        far.number = 310                 // exactly the window size, so out
        far.timestamp = 10
        far.payload = Data("x".utf8)
        session.input([.data(far)], current: 100)
        session.flush(current: 100)
        try expect(session.takeOutbox().isEmpty, "越界的数据段不应产生 ACK")

        var edge = far
        edge.number = 309                // the last one inside
        session.input([.data(edge)], current: 100)
        session.flush(current: 100)
        try expect(session.takeOutbox().count == 1, "窗口内的数据段应产生 ACK")
        try expect(session.readAvailable().isEmpty, "有空洞时不应交付任何数据")

        // A conv mismatch discards the rest of the datagram, not just one
        // segment.
        let strict = MKCPSession(configuration: configuration())
        var alien = MKCPWireStub.DataSegment()
        alien.conv = conv &+ 1
        alien.number = 0
        alien.payload = Data("a".utf8)
        var mine = MKCPWireStub.DataSegment()
        mine.conv = conv
        mine.number = 0
        mine.payload = Data("b".utf8)
        strict.input([.data(alien), .data(mine)], current: 100)
        try expect(strict.readAvailable().isEmpty, "conv 不匹配之后的段应一并丢弃")
    }

    private static func stateMachineTimeouts() throws {
        // Thirty idle seconds — measured on inbound traffic only — close it.
        let idle = MKCPSession(configuration: configuration())
        idle.flush(current: 29999)
        try expect(idle.state == .active, "未到 30 秒不应关闭")
        idle.flush(current: 30000)
        try expect(idle.state != .active, "空闲 30 秒应触发关闭，实际 \(idle.state)")

        // Terminate: Active to PeerTerminating, 4s to Terminating, 8s to
        // Terminated.
        let peer = MKCPSession(configuration: configuration())
        var terminate = MKCPWireStub.CmdSegment()
        terminate.conv = conv
        terminate.command = MKCPWireStub.Command.terminate.rawValue
        peer.input([.cmd(terminate)], current: 1000)
        try expect(peer.state == .peerTerminating, "收到 Terminate 应进 PeerTerminating")
        peer.flush(current: 5000)
        try expect(peer.state == .peerTerminating, "4000ms 内不应推进")
        peer.flush(current: 5001)
        try expect(peer.state == .terminating, "超过 4000ms 应进 Terminating")
        peer.flush(current: 13001)
        try expect(peer.state == .terminating, "8000ms 内应停在 Terminating")
        peer.flush(current: 13002)
        try expect(peer.state == .terminated, "超过 8000ms 应进 Terminated")

        // A segment carrying the close bit: Active to PeerClosed, and everything
        // queued to send is discarded — but its own payload still counts, since
        // the option is handled before the segment is taken in.
        let closed = MKCPSession(configuration: configuration())
        closed.push(Data("pending".utf8))
        var flagged = MKCPWireStub.DataSegment()
        flagged.conv = conv
        flagged.option = MKCPWireStub.optionClose
        flagged.number = 0
        flagged.timestamp = 1
        flagged.payload = Data("z".utf8)
        closed.input([.data(flagged)], current: 1000)
        try expect(closed.state == .peerClosed, "Close 位应把状态推到 PeerClosed")
        try expect(closed.pendingNumbers.isEmpty, "PeerClosed 应丢弃待发数据")
        try expect(closed.readAvailable() == Data("z".utf8), "带 Close 位的段其载荷仍要交付")
        // PeerClosed has no idle timeout upstream; the backstop must fire.
        closed.flush(current: 31001)
        try expect(closed.state != .peerClosed, "PeerClosed 也应有空闲兜底，实际 \(closed.state)")
    }

    // MARK: Two ends over an in-memory link

    /// A link that can drop and reorder, with a transport on each end and a
    /// virtual clock stepped by tti.
    private final class Wire {
        struct Packet {
            let at: UInt32
            let destination: Int
            let data: Data
        }

        private(set) var now: UInt32 = 0
        var latency: UInt32 = 10
        var reverseBatches = false
        /// Returning false drops the datagram in flight.
        var deliver: (Int, Data) -> Bool = { _, _ in true }
        private(set) var sent: [[Data]] = [[], []]
        var endpoints: [MKCPTransport] = []
        private var queue: [Packet] = []

        func send(from index: Int, _ data: Data) {
            sent[index].append(data)
            guard deliver(index, data) else { return }
            queue.append(Packet(at: now &+ latency, destination: 1 - index, data: data))
        }

        func advance(by milliseconds: UInt32, step: UInt32 = 20) {
            let target = now &+ milliseconds
            while now < target {
                now = min(now &+ step, target)
                var due = queue.filter { $0.at <= now }
                queue.removeAll { $0.at <= now }
                if reverseBatches { due.reverse() }
                for packet in due { endpoints[packet.destination].input(datagram: packet.data) }
                for endpoint in endpoints { endpoint.tick() }
            }
        }

        /// How many times one end put a given number on the wire, first
        /// transmission and retransmissions alike.
        func transmissions(from index: Int, number: UInt32) -> Int {
            sent[index].reduce(0) { total, datagram in
                total + MKCPWireStub.decode(datagram).filter {
                    if case .data(let segment) = $0 { return segment.number == number }
                    return false
                }.count
            }
        }

        func commands(from index: Int, command: MKCPWireStub.Command) -> Int {
            sent[index].reduce(0) { total, datagram in
                total + MKCPWireStub.decode(datagram).filter {
                    if case .cmd(let segment) = $0 { return segment.command == command.rawValue }
                    return false
                }.count
            }
        }
    }

    /// A reader that re-arms itself and accumulates whatever arrives.
    private final class Collector {
        private(set) var data = Data()
        private(set) var ended = false
        private(set) var failure: Error?

        func attach(to transport: MKCPTransport) {
            transport.receive { [weak self] payload, ended, error in
                guard let self else { return }
                if let payload { self.data.append(payload) }
                if let error { self.failure = error }
                if ended { self.ended = true; return }
                self.attach(to: transport)
            }
        }
    }

    private static func pair(configure: (inout MKCPConfiguration) -> Void = { _ in })
        -> (wire: Wire, client: MKCPTransport, server: MKCPTransport) {
        let wire = Wire()
        let queue = DispatchQueue(label: "app.hajimi.mkcp-selftest")
        var config = configuration()
        configure(&config)
        let client = MKCPTransport.inMemory(configuration: config, queue: queue,
                                            clock: { wire.now }, sink: { wire.send(from: 0, $0) })
        let server = MKCPTransport.inMemory(configuration: config, queue: queue,
                                            clock: { wire.now }, sink: { wire.send(from: 1, $0) })
        wire.endpoints = [client, server]
        return (wire, client, server)
    }

    /// Deterministic content, so any misordering shows up in the comparison.
    private static func payload(_ count: Int) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
    }

    private static func orderedTransfer() throws {
        let (wire, client, server) = pair()
        let collector = Collector()
        collector.attach(to: server)

        let body = payload(20_000)
        var sendError: Error?
        var sendDone = false
        client.send(body) { error in sendError = error; sendDone = true }
        wire.advance(by: 2000)

        try expect(sendDone, "写入应在窗口足够时完成")
        try expect(sendError == nil, "写入不应报错：\(String(describing: sendError))")
        try expect(collector.data == body,
                   "收到 \(collector.data.count) 字节，应为 \(body.count) 字节且逐字节相同")
        try expect(!collector.ended, "传输过程中不应报结束")
    }

    /// Every batch is delivered back to front; reassembly still has to match.
    private static func reorderedDelivery() throws {
        let (wire, client, server) = pair()
        wire.reverseBatches = true
        let collector = Collector()
        collector.attach(to: server)

        let body = payload(12_000)
        client.send(body) { _ in }
        wire.advance(by: 2000)
        try expect(collector.data == body, "乱序到达后重组结果不符：\(collector.data.count) 字节")
    }

    /// One segment's first transmission is dropped and the ARQ has to fill it in.
    private static func lossRecovery() throws {
        let (wire, client, server) = pair()
        var dropped = false
        wire.deliver = { index, datagram in
            guard index == 0, !dropped else { return true }
            let carriesTarget = MKCPWireStub.decode(datagram).contains {
                if case .data(let segment) = $0 { return segment.number == 3 }
                return false
            }
            if carriesTarget { dropped = true; return false }
            return true
        }
        let collector = Collector()
        collector.attach(to: server)

        let body = payload(9_000)
        client.send(body) { _ in }
        wire.advance(by: 3000)

        try expect(dropped, "自检信道应确实丢掉过 3 号段")
        try expect(collector.data == body, "丢包后应完整恢复，实际 \(collector.data.count) 字节")
        try expect(wire.transmissions(from: 0, number: 3) >= 2, "3 号段应被重传过")
    }

    /// A dropped segment while later ones keep being acknowledged: each batch of
    /// acknowledgements has to pull its deadline forward by rto/3.
    ///
    /// Asserting only that the transfer completes proves nothing — a timeout
    /// retransmission completes it too. What has to be visible is the deadline
    /// moving ahead of the original RTO: with a duplicate-ACK counter (which
    /// mKCP does not have) or with no fast path at all, it would sit at the
    /// current+rto written when the segment was first sent.
    private static func fastRetransmit() throws {
        let (wire, client, server) = pair()
        var dropped = false
        wire.deliver = { index, datagram in
            guard index == 0, !dropped else { return true }
            let carriesTarget = MKCPWireStub.decode(datagram).contains {
                if case .data(let segment) = $0 { return segment.number == 1 }
                return false
            }
            if carriesTarget { dropped = true; return false }
            return true
        }
        let collector = Collector()
        collector.attach(to: server)

        let body = payload(9_000)
        client.send(body) { _ in }

        wire.advance(by: 20)
        try expect(dropped, "自检信道应确实丢掉过 1 号段")
        guard let scheduled = client.timeoutForSelfTest(number: 1) else {
            throw Failure(text: "1 号段首发后应留在发送窗口里")
        }

        var cutAt: UInt32 = 0
        while wire.now < scheduled && cutAt == 0 {
            wire.advance(by: 20)
            if let now = client.timeoutForSelfTest(number: 1), now < scheduled { cutAt = wire.now }
        }
        try expect(cutAt != 0,
                   "到期时刻应在原定的 \(scheduled)ms 之前被 ACK 削掉，实际一直没削")
        wire.advance(by: 2000)
        try expect(wire.transmissions(from: 0, number: 1) >= 2, "1 号段应被重传")
        try expect(collector.data == body, "快重传之后数据应完整")
    }

    /// With the window full, the write's completion must wait for room, and the
    /// number of segments in flight must never exceed the limit.
    private static func writeBackpressure() throws {
        // A 5400-byte buffer over a 1350 MTU is four segments, so twenty is far
        // more than one window.
        let (wire, client, server) = pair { $0.maxSendingWindow = 5400 }
        let collector = Collector()
        collector.attach(to: server)

        var completed = false
        let body = payload(Int(client.mssForSelfTest) * 20)
        client.send(body) { _ in completed = true }
        try expect(client.pendingSegmentsForSelfTest == 5,
                   "窗口应恰好被填到 5 段，实际 \(client.pendingSegmentsForSelfTest)")
        try expect(!completed, "窗口只有 5 段时不可能一次写完 20 段")

        var peak = 0
        while wire.now < 4000 && !completed {
            wire.advance(by: 20)
            peak = max(peak, client.pendingSegmentsForSelfTest)
        }
        try expect(completed, "ACK 腾出窗口后写入应完成")
        try expect(peak <= 5, "在途段数不应超过 5，实际峰值 \(peak)")
        wire.advance(by: 500)
        try expect(collector.data == body, "背压恢复后数据应完整")
    }

    /// Cancelling has to reach the peer as an end of stream, and the timers have
    /// to stop dead afterwards.
    private static func closeHandshake() throws {
        let (wire, client, server) = pair()
        let collector = Collector()
        collector.attach(to: server)

        let body = payload(3_000)
        client.send(body) { _ in }
        wire.advance(by: 500)
        try expect(collector.data == body, "关闭前的数据应先送达")

        client.cancel()
        // Terminates repeat during the grace period and must stop after it.
        wire.advance(by: 1500)
        try expect(wire.commands(from: 0, command: .terminate) >= 1, "关闭应发出 Terminate")
        try expect(collector.ended, "对端应看到 EOF")

        let before = wire.sent[0].count
        wire.advance(by: 2000)
        try expect(wire.sent[0].count == before,
                   "cancel 之后不应再发包，实际又发了 \(wire.sent[0].count - before) 个")

        var writeError: Error?
        client.send(Data([1])) { writeError = $0 }
        try expect(writeError != nil, "关闭之后的写入应报错")
    }

    /// A peer that closes while it still has data queued keeps flushing that
    /// data, and every segment written while it sits in ReadyToClose carries the
    /// close bit (kcp/sending.go:282-285). So the segment that first puts this
    /// end into PeerClosed normally has the whole tail of the response behind
    /// it, and reporting end of stream as soon as the receive window drains
    /// truncates it in silence.
    ///
    /// `closeHandshake` closes an already-drained connection, which reaches the
    /// peer as a Terminate and never exercises this path — the reason a
    /// round-trip test on its own is not enough here.
    private static func closeWithPendingData() throws {
        let (wire, client, server) = pair()
        let collector = Collector()
        collector.attach(to: client)

        let body = payload(9_000)
        server.send(body) { _ in }
        // No tick in between, so the close lands while all seven segments are
        // still in the window and every one of them goes out flagged.
        server.cancel()
        wire.advance(by: 2000)

        try expect(collector.data == body,
                   "对端带着待发数据关闭时应交付全部载荷，实际 \(collector.data.count)/\(body.count) 字节")
        try expect(collector.ended, "全部数据交付后应报结束")
    }
}

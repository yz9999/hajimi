import Foundation
import Darwin
import HajimiCore
import HajimiFlowCXX
import HajimiDataPlaneC


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
              synSegment.maximumSegmentSize == 1_460,
              synSegment.windowScale == 6, synSegment.sackPermitted,
              internetChecksum(syn.prefix(20)) == 0 else {
            return "TCP MSS / window-scale option self-test failed"
        }
        if let failure = sackOptionSelfTest(source: source, destination: destination) {
            return failure
        }
        if let failure = retransmissionTimerSelfTest() { return failure }
        if let failure = bdpAndShrinkSelfTest() { return failure }
        if let failure = sackScoreboardSelfTest() { return failure }
        if let failure = sackApplicationCacheSelfTest() { return failure }
        if let failure = tcpCoalesceSelfTest() { return failure }
        if let failure = tcpDeliverySliceSelfTest() { return failure }
        if let failure = flowAdmissionSelfTest() { return failure }
        if let failure = packetDrainBudgetSelfTest() { return failure }
        if let failure = nonblockingDescriptorSelfTest() { return failure }
        if let failure = batchAckSackAndMSSSelfTest() { return failure }
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

    private static func packetDrainBudgetSelfTest() -> String? {
        let started: UInt64 = 10_000_000
        let budget = PacketDrainBudget(started: started)
        guard budget.shouldContinue(processed: 0, at: started),
              budget.shouldContinue(processed: 1_023, at: started + 1_999_999),
              !budget.shouldContinue(processed: 1_024, at: started),
              !budget.shouldContinue(processed: 0, at: started + 2_000_000),
              !budget.shouldContinue(processed: 1, at: started - 1),
              !budget.shouldContinue(processed: -1, at: started) else {
            return "packet-drain count/time/clock budget self-test failed"
        }
        // An injected clock makes the expensive-DNS case deterministic: two
        // 1.1ms packets yield well before the old 1024-packet-only bound.
        var now = started, processed = 0
        while budget.shouldContinue(processed: processed, at: now) {
            processed += 1; now += 1_100_000
        }
        guard processed == 2 else { return "expensive packets did not yield at a packet boundary" }
        return nil
    }

    private static func nonblockingDescriptorSelfTest() -> String? {
        do {
            let profile = try ProfileParser.parse("[Rule]\nFINAL,REJECT\n")
            let router = NativePacketRouter(profile: profile, mode: .rule,
                                            globalPolicy: "REJECT", groupSelections: [:])
            let tunnel = try NativeTunnel(router: router)
            do {
                // No real descriptor, interface, route, packet or socket is
                // created. A failed F_GETFL must never install a read source.
                _ = try tunnel.start(fileDescriptor: Int32.max, interfaceName: "invalid-memory-fixture")
                return "invalid descriptor installed a tunnel read source"
            } catch NativeTunnelError.utun {
                guard tunnel.interfaceName == nil, tunnel.statistics().activeFlows == 0 else {
                    return "failed nonblocking setup left an attached data plane"
                }
            }
        } catch { return "nonblocking descriptor fail-closed self-test failed" }
        return nil
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

    /// Compare complete operation sequences with the original unconditional
    /// scoreboard. This covers reuse after head movement, future-covering
    /// blocks followed by payload/SYN/FIN growth, and explicit RTO reneging.
    private static func sackApplicationCacheSelfTest() -> String? {
        var applied = 0, skipped = 0, seed: UInt64 = 0x5ac0_1287
        func random(_ maximum: Int) -> Int {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1
            return Int((seed >> 32) % UInt64(max(1, maximum)))
        }
        for base: UInt32 in [0, 1_000, .max - 31, .max - 65_535, .max / 2] {
            var naive: [OutstandingSegment] = [], cached: [OutstandingSegment] = []
            var state = SACKApplicationState(), head = 0, next = base
            var previous: [SACKBlock] = []
            func append(_ count: Int) {
                next &+= UInt32(max(1, count))
                let segment = OutstandingSegment(packet: Data(), endSequence: next,
                    payloadBytes: count, sentAt: Date(timeIntervalSince1970: 0), retries: 0)
                naive.append(segment); cached.append(segment); state.invalidate()
            }
            func apply(_ blocks: [SACKBlock]) -> Bool {
                SACKScoreboard.apply(blocks, to: &naive, from: head)
                if state.shouldApply(blocks) {
                    applied += 1
                    SACKScoreboard.apply(blocks, to: &cached, from: head)
                } else if !blocks.isEmpty { skipped += 1 }
                if !blocks.isEmpty { previous = blocks }
                return naive.count == cached.count && naive.indices.allSatisfy { naive[$0].sacked == cached[$0].sacked }
                    && SACKScoreboard.firstRetransmittable(in: naive, from: head)
                        == SACKScoreboard.firstRetransmittable(in: cached, from: head)
            }
            append(0) // SYN consumes sequence space, but cannot be SACKed.
            for _ in 0..<600 { append(100) }
            let broad = [SACKBlock(start: base, end: next &+ 32_768)]
            guard apply(broad), apply(broad), apply([]), apply(broad) else {
                return "SACK cache repeated/empty/wrapped block equivalence failed"
            }
            for count in [100, 0, 0] { // New payload, SYN-like and FIN-like entries.
                append(count)
                guard apply(broad) else { return "SACK cache skipped a newly appended range" }
            }
            naive[1].sacked = false; cached[1].sacked = false; state.invalidate()
            guard apply(broad), cached[1].sacked else { return "SACK cache hid RTO mark revocation" }
            head = 256
            guard apply(broad) else { return "SACK cache changed after cumulative ACK" }
            naive.removeFirst(head); cached.removeFirst(head); head = 0
            guard apply(broad) else { return "SACK cache changed after outstanding compaction" }

            for step in 0..<2_048 {
                var blocks = previous
                switch random(7) {
                case 0: break // Exact repeats, including after unrelated ACKs.
                case 1: blocks = []
                case 2, 6:
                    if head < naive.count {
                        let first = head + random(naive.count - head)
                        let last = first + random(naive.count - first)
                        let start = naive[first].startSequence
                        let end = naive[last].endSequence
                        blocks = [SACKBlock(start: start, end: end)]
                        if step & 1 == 0 {
                            blocks.append(SACKBlock(start: start &+ 1, end: end &+ 1))
                        }
                        if step & 3 == 0 {
                            blocks.append(SACKBlock(start: end, end: end &+ 65_536))
                        }
                    }
                case 3:
                    append(step % 17 == 0 ? 0 : random(1_460) + 1)
                case 4:
                    if head < naive.count {
                        naive[head].sacked = false; cached[head].sacked = false; state.invalidate()
                    }
                default:
                    head = min(naive.count, head + random(8) + 1)
                    if head >= 256, head * 2 >= naive.count {
                        naive.removeFirst(head); cached.removeFirst(head); head = 0
                    }
                }
                guard apply(blocks) else {
                    return "SACK cache/naive operation-sequence mismatch at base=\(base), step=\(step)"
                }
            }
        }
        return applied > 500 && skipped > 500 ? nil : "SACK cache oracle did not exercise both apply/reuse paths"
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
        let borrowed = CDataPlane.withBorrowedPayload(window, offset: 8, count: 8) { Array($0) }
        guard borrowed == Array(24..<32) else { return "borrowed non-zero-origin delivery lost bytes" }
        for (offset, count) in [(-1, 1), (0, -1), (Int.max, 1), (1, Int.max), (33, 0)] {
            let invalid = CDataPlane.withBorrowedPayload(window, offset: offset, count: count) { $0.count }
            guard invalid == nil else { return "borrowed delivery accepted an invalid relative range" }
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

        // RFC 8985 RACK-TLP probe timeout (PTO) bounds.
        var tlpTimer = RetransmissionTimer()
        tlpTimer.update(sample: 0.040)
        let singlePTO = tlpTimer.probeTimeout(flightSize: 1_460, mss: 1_460)
        let multiPTO = tlpTimer.probeTimeout(flightSize: 8 * 1_460, mss: 1_460)
        guard singlePTO >= 0.010, singlePTO <= tlpTimer.timeout,
              multiPTO >= 0.010, multiPTO <= tlpTimer.timeout else {
            return "RFC 8985 PTO fell outside [10ms, RTO]: single=\(singlePTO), multi=\(multiPTO)"
        }
        return nil
    }

    private static func bdpAndShrinkSelfTest() -> String? {
        let beforeBudget = hajimi_flow_buffer_budget_used()
        do {
            let queue = NativeByteQueue(limit: 512 * 1_024)
            guard queue.isValid, queue.isEmpty else { return "NativeByteQueue failed to initialize" }
            let chunk = Data(repeating: 0x42, count: 300 * 1_024)
            guard queue.append(chunk), queue.residentCapacity >= 256 * 1_024 else {
                return "NativeByteQueue failed to grow for 300 KiB burst"
            }
            queue.consume(chunk.count)
            guard queue.isEmpty, queue.residentCapacity >= 256 * 1_024 else {
                return "NativeByteQueue lost empty state before shrinkToFit"
            }
            queue.shrinkToFit()
            guard queue.residentCapacity == 0 else {
                return "NativeByteQueue.shrinkToFit did not release empty backing buffer"
            }
        }
        guard hajimi_flow_buffer_budget_used() == beforeBudget else {
            return "NativeByteQueue.shrinkToFit leaked shared flow buffer budget"
        }

        var bdp = NativeBDPEstimator(windowSeconds: 10.0)
        guard !bdp.isInitialized else { return "fresh BDP estimator reported initialized" }
        bdp.observe(deliveredBytes: 131_072, rtt: 0.010, timestamp: 1.0)
        guard bdp.isInitialized, bdp.maxBandwidth >= 13_000_000 else {
            return "BDP estimator failed to record delivery bandwidth"
        }
        let steady = bdp.recommendedWindow(mss: 1_460, minWindow: TCPFlow.minimumBDPWindowBytes, maxWindow: 8 * 1_024 * 1_024)
        guard steady >= TCPFlow.minimumBDPWindowBytes else {
            return "BDP recommended window violated minimum floor: \(steady)"
        }
        bdp.observe(deliveredBytes: 1_048_576, rtt: 0.005, timestamp: 1.5)
        let highBDP = bdp.recommendedWindow(mss: 1_460, minWindow: TCPFlow.minimumBDPWindowBytes, maxWindow: 8 * 1_024 * 1_024)
        bdp.observe(deliveredBytes: 65_536, rtt: 0.030, timestamp: 1.7)
        bdp.observe(deliveredBytes: 65_536, rtt: 0.032, timestamp: 1.9)
        bdp.observe(deliveredBytes: 65_536, rtt: 0.035, timestamp: 2.1)
        let drained = bdp.recommendedWindow(mss: 1_460, minWindow: TCPFlow.minimumBDPWindowBytes, maxWindow: 8 * 1_024 * 1_024)
        guard bdp.standingQueueRounds >= 3, drained < highBDP else {
            return "CoDel standing-queue inflation did not drain BDP window"
        }
        bdp.observeLoss(inflightBytes: 600_000, lostBytes: 30_000, deliveredBytes: 100_000)
        let lossClamped = bdp.recommendedWindow(mss: 1_460, minWindow: 256 * 1_024, maxWindow: 8 * 1_024 * 1_024)
        guard bdp.lossEvents >= 1, lossClamped <= 600_000 else {
            return "BBRv3 loss headroom failed to clamp window"
        }
        return nil
    }

    private final class SelfTestCaptureStream: NativeOutboundByteStream {
        private let lock = NSLock()
        private(set) var sendCallCount = 0
        private(set) var receivedUpload = Data()
        private var pendingReceive: ((Int, (Data?, Bool, Error?) -> Void))?
        private var queuedDownload = Data()
        private var eofQueued = false
        private var cancelled = false

        func enqueueDownload(_ data: Data, eof: Bool = false) {
            var callback: ((Data?, Bool, Error?) -> Void)?
            var slice: Data?
            var doneEOF = false
            lock.lock()
            queuedDownload.append(data)
            if eof { eofQueued = true }
            if let (maximum, completion) = pendingReceive, (!queuedDownload.isEmpty || eofQueued) {
                pendingReceive = nil
                let count = min(maximum, queuedDownload.count)
                if count > 0 {
                    slice = Data(queuedDownload.prefix(count))
                    queuedDownload.removeFirst(count)
                }
                doneEOF = queuedDownload.isEmpty && eofQueued
                callback = completion
            }
            lock.unlock()
            callback?(slice, doneEOF, nil)
        }

        var snapshot: (sends: Int, uploaded: Data) {
            lock.lock(); defer { lock.unlock() }
            return (sendCallCount, receivedUpload)
        }

        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock()
            let isCancelled = cancelled
            if !isCancelled {
                sendCallCount += 1
                receivedUpload.append(data)
            }
            lock.unlock()
            completion(isCancelled ? NativeTunnelError.utun("cancelled") : nil)
        }

        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            var immediate: (Data?, Bool)?
            lock.lock()
            if !queuedDownload.isEmpty || eofQueued {
                let count = min(maximum, queuedDownload.count)
                let chunk = count > 0 ? Data(queuedDownload.prefix(count)) : nil
                if count > 0 { queuedDownload.removeFirst(count) }
                let doneEOF = queuedDownload.isEmpty && eofQueued
                immediate = (chunk, doneEOF)
            } else if !cancelled {
                pendingReceive = (maximum, completion)
            }
            lock.unlock()
            if let (chunk, doneEOF) = immediate {
                completion(chunk, doneEOF, nil)
            }
        }

        func cancel() {
            var pending: ((Data?, Bool, Error?) -> Void)?
            lock.lock()
            cancelled = true
            pending = pendingReceive?.1
            pendingReceive = nil
            lock.unlock()
            pending?(nil, true, NativeTunnelError.utun("cancelled"))
        }
    }

    private static func readAvailableFrames(from descriptor: Int32) -> [Data] {
        var frames: [Data] = []
        var buffer = [UInt8](repeating: 0, count: 65_540)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.recv(descriptor, $0.baseAddress!, $0.count, 0) }
            guard count > 4 else { break }
            frames.append(Data(buffer[4..<count]))
        }
        return frames
    }

    /// Verifies batch ACK + upload coalescing, symmetric RFC 2018 outbound SACK,
    /// RFC 9293 client MSS negotiation / IPv6 8172 clamping, and on-demand 20ms
    /// active retransmit timer suspend/resume safety.
    private static func batchAckSackAndMSSSelfTest() -> String? {
        do {
            // 1. IPv4 flow: MSS=1380 negotiation, active timer suspend/resume, batch coalescing, and outbound SACK.
            let stream = SelfTestCaptureStream()
            let tunnel = try NativeTunnel.makeIsolatedSelfTestTunnel(stream: stream, initialSequence: 50_000)
            var fds = [Int32](repeating: -1, count: 2)
            guard fds.withUnsafeMutableBufferPointer({ socketpair(AF_UNIX, SOCK_DGRAM, 0, $0.baseAddress!) }) == 0 else {
                return "batch self-test socketpair failed"
            }
            let peer = fds[1]
            _ = fcntl(peer, F_SETFL, fcntl(peer, F_GETFL, 0) | O_NONBLOCK)
            var sockBuf: Int32 = 1_024 * 1_024
            _ = setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sockBuf, socklen_t(MemoryLayout<Int32>.size))
            _ = setsockopt(peer, SOL_SOCKET, SO_RCVBUF, &sockBuf, socklen_t(MemoryLayout<Int32>.size))
            defer { tunnel.stop(); Darwin.close(peer) }

            _ = try tunnel.start(fileDescriptor: fds[0], interfaceName: "batch-selftest0")
            guard !tunnel.isActiveRetransmitTimerRunningForSelfTest else {
                return "activeRetransmitTimer was running with zero outstanding TCP flows"
            }

            let client = IPAddress.v4([198, 18, 0, 9])
            let remote = IPAddress.v4([203, 0, 113, 7])
            var clientSeq: UInt32 = 10_000
            let synPacket = PacketBuilder.tcp(version: .v4, source: client, sourcePort: 54_321,
                                              destination: remote, destinationPort: 9443,
                                              sequence: clientSeq, acknowledgment: 0, flags: [.syn],
                                              window: 65_535, payload: Data(),
                                              maximumSegmentSize: 1_380, windowScale: 6,
                                              sackPermitted: true, identifier: 1)
            tunnel.processIPPacketForSelfTest(synPacket)
            clientSeq &+= 1

            // While SYN+ACK is unacknowledged, the 20 ms timer must be resumed.
            guard tunnel.isActiveRetransmitTimerRunningForSelfTest else {
                return "activeRetransmitTimer did not resume for unacknowledged SYN+ACK"
            }
            let synAckFrames = readAvailableFrames(from: peer)
            guard synAckFrames.count == 1,
                  let parsedSynAckIP = ParsedIPPacket([UInt8](synAckFrames[0])),
                  let synAck = ParsedTCPSegment(parsedSynAckIP),
                  synAck.flags.contains([.syn, .ack]) else {
                return "SYN+ACK was not emitted"
            }
            var serverSeq = synAck.sequence &+ 1
            let handshakeAck = PacketBuilder.tcp(version: .v4, source: client, sourcePort: 54_321,
                                                 destination: remote, destinationPort: 9443,
                                                 sequence: clientSeq, acknowledgment: serverSeq,
                                                 flags: [.ack], window: 65_535, payload: Data(),
                                                 maximumSegmentSize: nil, windowScale: nil,
                                                 sackPermitted: false, identifier: 2)
            tunnel.processIPPacketForSelfTest(handshakeAck)
            // Once SYN+ACK is acknowledged and zero segments remain in flight, timer must suspend immediately.
            guard !tunnel.isActiveRetransmitTimerRunningForSelfTest else {
                return "activeRetransmitTimer remained active after flight drained to zero"
            }

            // Coalesce 16 in-order 1,000-byte upload segments in a single batch -> 1 cumulative ACK & 1 stream.send!
            var expectedUpload = Data()
            var uploadBatch: [Data] = []
            for idx in 0..<16 {
                let chunk = Data((0..<1_000).map { UInt8(($0 + idx * 13) & 0xff) })
                expectedUpload.append(chunk)
                let seg = PacketBuilder.tcp(version: .v4, source: client, sourcePort: 54_321,
                                            destination: remote, destinationPort: 9443,
                                            sequence: clientSeq, acknowledgment: serverSeq,
                                            flags: [.ack, .psh], window: 65_535, payload: chunk,
                                            maximumSegmentSize: nil, windowScale: nil,
                                            sackPermitted: false, identifier: UInt16(10 + idx))
                uploadBatch.append(seg)
                clientSeq &+= UInt32(chunk.count)
            }
            tunnel.processIPPacketBatchForSelfTest(uploadBatch)
            let batchAckFrames = readAvailableFrames(from: peer)
            guard batchAckFrames.count == 1,
                  let batchAckIP = ParsedIPPacket([UInt8](batchAckFrames[0])),
                  let batchAck = ParsedTCPSegment(batchAckIP),
                  batchAck.acknowledgment == clientSeq,
                  batchAck.sackBlocks.isEmpty else {
                return "batch upload did not coalesce into 1 cumulative ACK (got \(batchAckFrames.count))"
            }
            let snap1 = stream.snapshot
            guard snap1.sends == 1, snap1.uploaded == expectedUpload else {
                return "batch upload did not coalesce into 1 exact stream.send (sends=\(snap1.sends), bytes=\(snap1.uploaded.count))"
            }

            // Out-of-order upload segment during batch must emit immediate RFC 2018 outbound SACK!
            let missingChunk = Data(repeating: 0xaa, count: 500)
            let oooChunk1 = Data(repeating: 0xbb, count: 600)
            let oooChunk2 = Data(repeating: 0xcc, count: 400)
            let oooSeg1 = PacketBuilder.tcp(version: .v4, source: client, sourcePort: 54_321,
                                            destination: remote, destinationPort: 9443,
                                            sequence: clientSeq &+ 500, acknowledgment: serverSeq,
                                            flags: [.ack, .psh], window: 65_535, payload: oooChunk1,
                                            maximumSegmentSize: nil, windowScale: nil,
                                            sackPermitted: false, identifier: 40)
            let oooSeg2 = PacketBuilder.tcp(version: .v4, source: client, sourcePort: 54_321,
                                            destination: remote, destinationPort: 9443,
                                            sequence: clientSeq &+ 1_100, acknowledgment: serverSeq,
                                            flags: [.ack, .psh], window: 65_535, payload: oooChunk2,
                                            maximumSegmentSize: nil, windowScale: nil,
                                            sackPermitted: false, identifier: 41)
            tunnel.processIPPacketBatchForSelfTest([oooSeg1, oooSeg2])
            let sackFrames = readAvailableFrames(from: peer)
            guard sackFrames.count == 2,
                  let lastSackIP = ParsedIPPacket([UInt8](sackFrames[1])),
                  let lastSack = ParsedTCPSegment(lastSackIP),
                  lastSack.acknowledgment == clientSeq,
                  lastSack.sackBlocks == [SACKBlock(start: clientSeq &+ 500, end: clientSeq &+ 1_500)] else {
                return "outbound RFC 2018 SACK option was not attached or coalesced for OOO upload"
            }

            // Filling the OOO gap clears SACK blocks and delivers contiguous upload bytes.
            let fillSeg = PacketBuilder.tcp(version: .v4, source: client, sourcePort: 54_321,
                                            destination: remote, destinationPort: 9443,
                                            sequence: clientSeq, acknowledgment: serverSeq,
                                            flags: [.ack, .psh], window: 65_535, payload: missingChunk,
                                            maximumSegmentSize: nil, windowScale: nil,
                                            sackPermitted: false, identifier: 42)
            tunnel.processIPPacketBatchForSelfTest([fillSeg])
            clientSeq &+= 1_500
            let fillFrames = readAvailableFrames(from: peer)
            guard !fillFrames.isEmpty,
                  let fillIP = ParsedIPPacket([UInt8](fillFrames.last!)),
                  let fillAck = ParsedTCPSegment(fillIP),
                  fillAck.acknowledgment == clientSeq,
                  fillAck.sackBlocks.isEmpty else {
                return "gap-filling segment did not advance cumulative ACK and clear SACK"
            }
            expectedUpload.append(missingChunk)
            expectedUpload.append(oooChunk1)
            expectedUpload.append(oooChunk2)
            guard stream.snapshot.uploaded == expectedUpload else {
                return "reordered upload bytes differed after gap fill"
            }

            // Verify peerEffectiveMSS = 1380 caps outbound download segments to <= 1380 bytes!
            stream.enqueueDownload(Data(repeating: 0x7e, count: 3_000))
            // Serialize with tunnel queue so async receive callback has flushed onto peer.
            _ = tunnel.statistics()
            let dlFrames = readAvailableFrames(from: peer)
            guard dlFrames.count == 3 else {
                return "MSS=1380 3000B download expected 3 segments (1380+1380+240), got \(dlFrames.count)"
            }
            var dlSizes: [Int] = []
            for frame in dlFrames {
                guard let ip = ParsedIPPacket([UInt8](frame)),
                      let seg = ParsedTCPSegment(ip),
                      tcpTransportChecksumValid(packet: frame, version: .v4, source: remote, destination: client) else {
                    return "invalid IPv4 download segment checksum"
                }
                dlSizes.append(seg.payload.count)
                serverSeq &+= UInt32(seg.payload.count)
            }
            guard dlSizes == [1_380, 1_380, 240] else {
                return "unexpected MSS=1380 segment sizes: \(dlSizes)"
            }
            // Note: leave these 3 segments unacknowledged when `tunnel.stop()` runs via defer/explicit call
            // so we ALSO test cancelling `activeRetransmitTimer` while actively running!
            guard tunnel.isActiveRetransmitTimerRunningForSelfTest else {
                return "activeRetransmitTimer was not running for unacknowledged download flight"
            }
            tunnel.stop()

            // 2. IPv6 flow: verify oversized client MSS=8940 is clamped to 8172 (IPv6 utun max payload)!
            let stream6 = SelfTestCaptureStream()
            let tunnel6 = try NativeTunnel.makeIsolatedSelfTestTunnel(stream: stream6, initialSequence: 90_000)
            var fds6 = [Int32](repeating: -1, count: 2)
            guard fds6.withUnsafeMutableBufferPointer({ socketpair(AF_UNIX, SOCK_DGRAM, 0, $0.baseAddress!) }) == 0 else {
                return "IPv6 MSS self-test socketpair failed"
            }
            let peer6 = fds6[1]
            _ = fcntl(peer6, F_SETFL, fcntl(peer6, F_GETFL, 0) | O_NONBLOCK)
            _ = setsockopt(fds6[0], SOL_SOCKET, SO_SNDBUF, &sockBuf, socklen_t(MemoryLayout<Int32>.size))
            _ = setsockopt(peer6, SOL_SOCKET, SO_RCVBUF, &sockBuf, socklen_t(MemoryLayout<Int32>.size))
            defer { tunnel6.stop(); Darwin.close(peer6) }
            _ = try tunnel6.start(fileDescriptor: fds6[0], interfaceName: "ipv6-mss-selftest0")

            let client6 = IPAddress.v6([0x20, 0x01, 0x0d, 0xb8] + Array(repeating: 0, count: 11) + [1])
            let remote6 = IPAddress.v6([0x20, 0x01, 0x0d, 0xb8] + Array(repeating: 0, count: 11) + [7])
            let syn6 = PacketBuilder.tcp(version: .v6, source: client6, sourcePort: 55_000,
                                         destination: remote6, destinationPort: 9443,
                                         sequence: 1_000, acknowledgment: 0, flags: [.syn],
                                         window: 65_535, payload: Data(),
                                         maximumSegmentSize: 8_940, windowScale: 6,
                                         sackPermitted: true, identifier: 0)
            tunnel6.processIPPacketForSelfTest(syn6)
            let synAck6Frames = readAvailableFrames(from: peer6)
            guard synAck6Frames.count == 1,
                  let ip6 = ParsedIPPacket([UInt8](synAck6Frames[0])),
                  let synAck6 = ParsedTCPSegment(ip6),
                  synAck6.maximumSegmentSize == 8_172 else {
                return "IPv6 SYN+ACK did not advertise 8172 MSS"
            }
            let ack6 = PacketBuilder.tcp(version: .v6, source: client6, sourcePort: 55_000,
                                         destination: remote6, destinationPort: 9443,
                                         sequence: 1_001, acknowledgment: synAck6.sequence &+ 1,
                                         flags: [.ack], window: 65_535, payload: Data(),
                                         maximumSegmentSize: nil, windowScale: nil,
                                         sackPermitted: false, identifier: 0)
            tunnel6.processIPPacketForSelfTest(ack6)
            stream6.enqueueDownload(Data(repeating: 0x33, count: 9_000))
            _ = tunnel6.statistics()
            let dl6Frames = readAvailableFrames(from: peer6)
            guard dl6Frames.count == 2,
                  let firstIP6 = ParsedIPPacket([UInt8](dl6Frames[0])),
                  let firstSeg6 = ParsedTCPSegment(firstIP6),
                  firstSeg6.payload.count == 8_172,
                  tcpTransportChecksumValid(packet: dl6Frames[0], version: .v6, source: remote6, destination: client6) else {
                return "IPv6 download segment was not clamped to 8172 bytes"
            }
        } catch {
            return "batchAckSackAndMSSSelfTest threw: \(error.localizedDescription)"
        }
        return nil
    }
}

// MARK: - ICMP

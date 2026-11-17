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
              synSegment.windowScale == 6, synSegment.sackPermitted,
              internetChecksum(syn.prefix(20)) == 0 else {
            return "TCP window-scale option self-test failed"
        }
        if let failure = sackOptionSelfTest(source: source, destination: destination) {
            return failure
        }
        if let failure = retransmissionTimerSelfTest() { return failure }
        if let failure = sackScoreboardSelfTest() { return failure }
        if let failure = sackApplicationCacheSelfTest() { return failure }
        if let failure = tcpCoalesceSelfTest() { return failure }
        if let failure = tcpDeliverySliceSelfTest() { return failure }
        if let failure = flowAdmissionSelfTest() { return failure }
        if let failure = packetDrainBudgetSelfTest() { return failure }
        if let failure = nonblockingDescriptorSelfTest() { return failure }
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
        return nil
    }
}

// MARK: - ICMP

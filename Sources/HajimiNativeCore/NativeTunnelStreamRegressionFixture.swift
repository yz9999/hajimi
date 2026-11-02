import Foundation
import Darwin
import HajimiCore
import HajimiFlowCXX

/// Exercises the real TCPFlow, C packet codec and utun read/writev path using
/// only AF_UNIX datagrams and an in-memory byte stream. No IP socket, resolver,
/// proxy listener, Helper, interface or system setting is created.
public enum NativeTunnelStreamRegressionFixture {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private enum Behavior { case ordinary, zeroAcknowledged, zeroOutstanding, zeroHeld, zeroInitial, sackNormal, sackAll, sackPartial }
    private struct Step { let request: Data; let response: Data; let eof: Bool }
    private struct Plan {
        let name: String
        let behavior: Behavior
        let steps: [Step]
        let fragmented: Bool
        let dropFIN: Bool
        var expected: Data { steps.reduce(into: Data()) { $0.append($1.response) } }
    }

    /// Returns a bounded, credential-free report. Ordinary app paths cannot
    /// enable this fixture through a profile or by passing a custom dialer.
    public static func run(scenario: String = "all") throws -> String {
        guard CommandLine.arguments.contains("--native-tunnel-stream-self-test"),
              ProxyEngine.currentOutboundInterface == nil else {
            throw Failure(text: "Native stream regression requires its isolated CLI flag")
        }
        let plans = makePlans()
        guard scenario == "all" || plans.contains(where: { $0.name == scenario }) else {
            throw Failure(text: "Unknown native stream regression scenario")
        }
        // Same state object used by TCPFlow; model a full sequence turn with
        // scalar ACKs, not by allocating or transferring four GiB.
        var handshake = TCPHandshakeAcknowledgmentState()
        handshake.acknowledge(101, synSequence: 101)
        guard !handshake.isEstablished else { throw Failure(text: "SYN acknowledged too early") }
        handshake.acknowledge(102, synSequence: 101)
        handshake.acknowledge(101, synSequence: 101)
        guard handshake.isEstablished else { throw Failure(text: "Full sequence turn lost establishment") }
        var wrappedHandshake = TCPHandshakeAcknowledgmentState()
        wrappedHandshake.acknowledge(0, synSequence: .max)
        wrappedHandshake.acknowledge(.max, synSequence: .max)
        guard wrappedHandshake.isEstablished else { throw Failure(text: "SYN sequence wrap lost establishment") }
        var reports = ["PASS handshake-sequence-full-turn: sticky SYN ACK across zero and full 4GiB turn"]
        var failed = false
        for plan in plans where scenario == "all" || plan.name == scenario {
            do { reports.append(try exercise(plan)) }
            catch {
                failed = true
                reports.append("FAIL " + plan.name + ": " + error.localizedDescription)
            }
        }
        let report = reports.joined(separator: "\n")
        if failed { throw Failure(text: report) }
        return report
    }

    /// Real production read-source/parser/TCPFlow/C-codec/writev scheduling,
    /// with AF_UNIX datagrams standing in for the utun descriptor. Process CPU
    /// includes the independent packet peer and checksum/byte validation.
    public static func runPacketLoad() throws -> String {
        guard CommandLine.arguments.contains("--native-tunnel-packet-load-self-test"),
              ProxyEngine.currentOutboundInterface == nil else {
            throw Failure(text: "Native packet load requires its isolated CLI flag")
        }
        let budgetBefore = hajimi_flow_buffer_budget_used()
        let reports = try [exercisePacketLoad(ackFlood: true), exercisePacketLoad(ackFlood: false)]
        guard hajimi_flow_buffer_budget_used() == budgetBefore else {
            throw Failure(text: "Packet load leaked native queue/reassembly budget")
        }
        return reports.joined(separator: "\n") + "\nPASS native packet load: production parser/scheduler/native bridges, exact bytes/checksums, bounded drain/stop, no system TUN or IP sockets"
    }

    private static func cpuMilliseconds() -> Double {
        var usage = rusage()
        guard getrusage(RUSAGE_SELF, &usage) == 0 else { return -1 }
        return Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000 +
            Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000
    }

    private static func exercisePacketLoad(ackFlood: Bool) throws -> String {
        let responseBytes = ackFlood ? 4 * 1024 * 1024 - 64 : 32 * 1024 * 1024 + 113
        let golden = response(responseBytes, seed: 17)
        let command = request(0, length: responseBytes)
        let plan = Plan(name: ackFlood ? "ack-sack-packet-load" : "download-packet-load", behavior: .ordinary,
                        steps: [Step(request: command, response: golden, eof: false)],
                        fragmented: false, dropFIN: false)
        let origin = MemoryOrigin(plan)
        let counters = NativeTunnelPacketLoadCounters()
        let tunnel = try NativeTunnel.makeStreamRegressionFixture(stream: origin,
            initialSequence: UInt32.max - 4097, packetLoadCounters: counters)
        var descriptors = [Int32](repeating: -1, count: 2)
        guard descriptors.withUnsafeMutableBufferPointer({ socketpair(AF_UNIX, SOCK_DGRAM, 0, $0.baseAddress!) }) == 0 else {
            throw Failure(text: "Packet-load socketpair failed")
        }
        let peer = descriptors[1]
        defer { tunnel.stop(); Darwin.close(peer) }
        for descriptor in descriptors {
            guard fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL, 0) | O_NONBLOCK) == 0 else {
                Darwin.close(descriptors[0]); throw Failure(text: "Packet-load descriptor could not be nonblocking")
            }
            var size: Int32 = 512 * 1024
            _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
            _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        }
        _ = try tunnel.start(fileDescriptor: descriptors[0], interfaceName: "packet-load-memory0")
        var clientSequence: UInt32 = UInt32.max - 63
        var expectedSequence: UInt32 = 0, firstSequence: UInt32 = 0
        var received = Data(), handshake = false, finished = false
        var duplicatePackets = 0, dataPackets = 0, floodPackets = 0
        var floodMilliseconds = 0.0, floodCPU = 0.0
        var scratch = [UInt8](repeating: 0, count: 65_540)
        let started = clock(), cpuStarted = cpuMilliseconds(), deadline = started + 25
        let receiveWindow: UInt16 = ackFlood ? .max : 64

        func send(_ acknowledgment: UInt32, flags: UInt8 = 0x10,
                  payload: Data = Data(), sacks: [(UInt32, UInt32)] = [], window: UInt16? = nil) throws {
            try sendFrame(packet(sequence: clientSequence, acknowledgment: acknowledgment,
                flags: flags, window: window ?? receiveWindow, payload: payload, sacks: sacks), to: peer)
            clientSequence &+= UInt32(payload.count)
        }
        func runFlood() throws {
            // A stable cumulative-ACK hole plus repeated valid SACK ranges.
            // Window updates alternate, so these are not fast-retransmit
            // duplicate candidates. RTO/reneging remains enabled throughout.
            let blocks = [(firstSequence &+ 8192, expectedSequence)]
            let frames = [UInt16.max, UInt16.max - 1].map {
                packet(sequence: clientSequence, acknowledgment: firstSequence, flags: 0x10,
                       window: $0, payload: Data(), sacks: blocks)
            }
            let before = tunnel.packetLoadProbe()
            let floodStarted = clock(), cpuBefore = cpuMilliseconds()
            for index in 0..<131_072 {
                do { try sendFrame(frames[index & 1], to: peer) }
                catch { throw Failure(text: "ACK flood at \(index): \(error.localizedDescription)") }
                if index & 1023 == 1023 { _ = tunnel.packetLoadProbe() }
            }
            while tunnel.packetLoadProbe() < before + 131_072 {
                guard clock() < deadline else { throw Failure(text: "Packet ACK flood did not drain") }
                usleep(100)
            }
            floodPackets = 131_072
            floodMilliseconds = (clock() - floodStarted) * 1000
            floodCPU = cpuMilliseconds() - cpuBefore
        }

        try send(0, flags: 2)
        clientSequence &+= 1
        while clock() < deadline, !finished {
            var ready = pollfd(fd: peer, events: Int16(POLLIN), revents: 0)
            _ = Darwin.poll(&ready, 1, 10)
            let count = scratch.withUnsafeMutableBytes { Darwin.recv(peer, $0.baseAddress!, $0.count, 0) }
            if count < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { continue }
                throw Failure(text: "Packet-load receive failed")
            }
            let incoming = try Packet(Data(scratch.prefix(count)))
            guard incoming.flags & 4 == 0 else { throw Failure(text: "Packet-load unexpected reset") }
            if incoming.flags & 2 != 0 {
                guard !handshake else { try send(expectedSequence); continue }
                handshake = true
                expectedSequence = incoming.sequence &+ 1; firstSequence = expectedSequence
                try send(expectedSequence)
                try send(expectedSequence, flags: 0x18, payload: command)
                continue
            }
            if !incoming.payload.isEmpty {
                dataPackets += 1
                let delta = distance(incoming.sequence, expectedSequence)
                guard delta <= 0 else { throw Failure(text: "Packet load reordered or dropped a local datagram") }
                let skip = Int(-Int64(delta))
                if skip < incoming.payload.count {
                    received.append(incoming.payload.dropFirst(skip))
                    expectedSequence &+= UInt32(incoming.payload.count - skip)
                } else { duplicatePackets += 1 }
                if ackFlood {
                    if received.count == golden.count, floodPackets == 0 { try runFlood(); try send(expectedSequence) }
                } else {
                    try send(expectedSequence)
                    if dataPackets & 255 == 0 { _ = tunnel.packetLoadProbe() }
                }
                if received.count == golden.count { origin.finish() }
            }
            if incoming.flags & 1 != 0, incoming.sequence == expectedSequence {
                guard received == golden else { throw Failure(text: "Packet load changed download bytes or FIN boundary") }
                expectedSequence &+= 1; try send(expectedSequence); finished = true
            }
        }
        guard finished, received == golden, !ackFlood || floodPackets == 131_072 else {
            throw Failure(text: "Packet load deadline: bytes=\(received.count)/\(golden.count), flood=\(floodPackets)")
        }
        while tunnel.statistics().activeFlows != 0 {
            guard clock() < deadline else { throw Failure(text: "Final packet-load FIN acknowledgment did not retire its flow") }
            usleep(100)
        }
        let statistics = tunnel.statistics()
        guard statistics.downloadedBytes == UInt64(golden.count), statistics.uploadedBytes == UInt64(command.count) else {
            throw Failure(text: "Packet load corrupted traffic accounting")
        }
        // Continue valid packet ingress while stop requests the same serial
        // queue. This tests cancellation fairness while the descriptor is
        // readable, after exact stream retirement has already been verified.
        let pressureStarted = DispatchSemaphore(value: 0), pressureEnded = DispatchSemaphore(value: 0)
        let pressureFrame = packet(sequence: clientSequence, acknowledgment: expectedSequence,
            flags: 0x10, window: receiveWindow, payload: Data(), sacks: [])
        DispatchQueue.global(qos: .userInitiated).async {
            var sent = 0
            let pressureDeadline = clock() + 2
            defer { pressureEnded.signal() }
            while clock() < pressureDeadline {
                let count = pressureFrame.withUnsafeBytes { Darwin.send(peer, $0.baseAddress!, $0.count, 0) }
                if count == pressureFrame.count {
                    sent += 1
                    if sent == 64 { pressureStarted.signal() }
                } else if count < 0, errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOBUFS {
                    usleep(100)
                } else { return }
            }
        }
        guard pressureStarted.wait(timeout: .now() + 1) == .success else {
            throw Failure(text: "Packet pressure sender did not start")
        }
        let stopStarted = clock()
        tunnel.stop()
        let stopMilliseconds = (clock() - stopStarted) * 1000
        guard pressureEnded.wait(timeout: .now() + 1) == .success else {
            throw Failure(text: "Packet pressure sender did not observe stopped descriptor")
        }
        let report = counters.report()
        guard counters.downloadStorageBoundViolations == 0,
              counters.downloadStoredPeak >= counters.downloadBufferedPeak,
              counters.downloadStoredPeak < 2 * counters.downloadBufferedPeak + 64 * 1024,
              counters.downloadRetainedPrefixPeak <= counters.downloadStoredPeak else {
            throw Failure(text: "Packet load exceeded the logical download storage/prefix bound")
        }
        guard (report["drainPacketsPeak"] as? Int ?? .max) <= 1024, stopMilliseconds < 1000 else {
            throw Failure(text: "Packet load violated count fairness or bounded stop")
        }
        var result = report
        result["scenario"] = plan.name
        result["scope"] = "AF_UNIX production TCPFlow/codec/descriptor scheduling; not kernel utun takeover or Internet throughput"
        result["processCPUMillisecondsIncludingPeer"] = cpuMilliseconds() - cpuStarted
        result["elapsedMilliseconds"] = (clock() - started) * 1000
        result["downloadBytes"] = golden.count
        result["dataPackets"] = dataPackets
        result["duplicateDataPackets"] = duplicatePackets
        result["floodPackets"] = floodPackets
        result["floodMilliseconds"] = floodMilliseconds
        result["floodProcessCPUMillisecondsIncludingPeer"] = floodCPU
        result["floodPacketsPerSecond"] = floodMilliseconds > 0 ? Double(floodPackets) * 1000 / floodMilliseconds : 0
        result["stopMilliseconds"] = stopMilliseconds
        result["stopDuringContinuousIngress"] = true
        result["exactBytesAndChecksums"] = true
        let json = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        return "TUN-PACKET-LOAD " + String(decoding: json, as: UTF8.self)
    }

    private static func bytes(_ count: Int, seed: Int = 0) -> Data {
        var result = Data(count: count)
        result.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            for index in 0..<count { raw[index] = UInt8((index + seed) % 251) }
        }
        return result
    }
    private static func request(_ index: Int, start: Int = 0, length: Int = 256 * 1024) -> Data {
        Data("GET /videoplayback/segment-\(index) HTTP/1.1\r\nHost: video.fixture.test\r\nRange: bytes=\(start)-\(start + length - 1)\r\nConnection: keep-alive\r\n\r\n".utf8)
    }
    private static func response(_ count: Int, seed: Int = 0) -> Data {
        var size = max(0, count - 160), result = Data()
        for _ in 0..<3 {
            result = Data("HTTP/1.1 206 Partial Content\r\nContent-Type: video/mp4\r\nContent-Length: \(size)\r\nContent-Range: bytes 0-\(size - 1)/\(size)\r\nConnection: keep-alive\r\n\r\n".utf8)
            size = count - result.count
        }
        result.append(bytes(size, seed: seed))
        return result
    }
    private static func h2Frame(_ type: UInt8, flags: UInt8, stream: UInt32, payload: Data) -> Data {
        let count = payload.count
        var result = Data([UInt8(count >> 16), UInt8((count >> 8) & 255), UInt8(count & 255), type, flags])
        append32(stream, to: &result); result.append(payload)
        return result
    }
    private static func makePlans() -> [Plan] {
        var ranges: [Step] = []
        for index in 0..<48 {
            ranges.append(Step(request: request(index, start: index * 256 * 1024),
                               response: response(256 * 1024, seed: index), eof: index == 47))
        }
        var frames = h2Frame(4, flags: 0, stream: 0, payload: Data())
        frames.append(h2Frame(1, flags: 4, stream: 1, payload: Data([0x8a])))
        frames.append(h2Frame(1, flags: 4, stream: 3, payload: Data([0x8a])))
        for index in 0..<256 {
            frames.append(h2Frame(0, flags: index >= 254 ? 1 : 0, stream: index % 2 == 0 ? 1 : 3,
                                  payload: bytes(16_384, seed: index)))
        }
        let preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
        let ordinary = Plan(name: "range-keepalive", behavior: .ordinary, steps: ranges,
                            fragmented: true, dropFIN: true)
        let h2 = Plan(name: "h2-interleaved-tail-eof", behavior: .ordinary,
                      steps: [Step(request: preface, response: frames, eof: true)], fragmented: true, dropFIN: true)
        func one(_ name: String, _ behavior: Behavior, _ count: Int, eof: Bool = true) -> Plan {
            Plan(name: name, behavior: behavior,
                 steps: [Step(request: request(0), response: response(count), eof: eof)],
                 fragmented: false, dropFIN: false)
        }
        return [ordinary, h2,
                one("zero-window-update-loss", .zeroAcknowledged, 1024 * 1024 + 17),
                one("zero-window-outstanding-wrap", .zeroOutstanding, 1024 * 1024 + 37),
                one("zero-window-held-no-spin", .zeroHeld, 1024 * 1024 + 17),
                one("zero-window-before-first-byte", .zeroInitial, 32_768 + 17),
                one("zero-window-tail-eof", .zeroAcknowledged, 8192 + 513),
                one("zero-window-drained-tail-fin", .zeroAcknowledged, 4096, eof: false),
                Plan(name: "zero-window-empty-response-eof", behavior: .zeroInitial,
                     steps: [Step(request: request(0), response: Data(), eof: true)], fragmented: false, dropFIN: false),
                one("sack-normal-hole-only", .sackNormal, 4 * 8192, eof: false),
                one("sack-all-reneging", .sackAll, 3 * 8192, eof: false),
                one("sack-partial-reneging", .sackPartial, 4 * 8192, eof: false)]
    }

    private final class MemoryOrigin: NativeOutboundByteStream {
        private let queue = DispatchQueue(label: "app.hajimi.native-stream.memory-origin")
        private let steps: [Step]
        private let fragmented: Bool
        private var input = Data(), step = 0, responses: [Data] = [], head = 0, offset = 0, reads = 0
        private var closed = false, finalEOF = false, forcedEOF = false
        private var pending: (Int, (Data?, Bool, Error?) -> Void)?
        init(_ plan: Plan) { steps = plan.steps; fragmented = plan.fragmented }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            queue.async {
                guard !self.closed, data.count <= 64 * 1024, self.input.count + data.count <= 64 * 1024 else {
                    completion(Failure(text: "Memory origin rejected its bounded input")); return
                }
                self.input.append(data)
                while self.step < self.steps.count {
                    let expected = self.steps[self.step].request
                    guard self.input.count >= expected.count else { break }
                    guard self.input.prefix(expected.count) == expected else {
                        completion(Failure(text: "Range/H2 request bytes changed")); return
                    }
                    self.input.removeFirst(expected.count)
                    self.responses.append(self.steps[self.step].response)
                    self.finalEOF = self.steps[self.step].eof
                    self.step += 1
                }
                completion(nil); self.deliver()
            }
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            queue.async {
                guard !self.closed, self.pending == nil, maximum > 0 else {
                    completion(nil, false, Failure(text: "Invalid memory origin receive")); return
                }
                self.pending = (maximum, completion); self.deliver()
            }
        }
        func finish(delay: Double = 0) {
            queue.asyncAfter(deadline: .now() + delay) { self.forcedEOF = true; self.deliver() }
        }
        func cancel() {
            queue.async {
                self.closed = true; self.responses.removeAll(); self.input.removeAll()
                let done = self.pending?.1; self.pending = nil
                done?(nil, true, Failure(text: "Memory origin cancelled"))
            }
        }
        private func deliver() {
            guard let (maximum, done) = pending else { return }
            if head >= responses.count {
                if forcedEOF || (finalEOF && step == steps.count) {
                    pending = nil; done(nil, true, nil)
                }
                return
            }
            let source = responses[head]
            let fragments = [1, 2, 17, 4093, 16_381, 65_536, 1461, 8191]
            let limit = fragmented ? fragments[reads % fragments.count] : 16_384
            let count = min(maximum, source.count - offset, limit)
            let data = source[offset..<(offset + count)] // Deliberate non-zero Data origin.
            offset += count; reads += 1
            if offset == source.count { head += 1; offset = 0 }
            let eof = head == responses.count && step == steps.count && (finalEOF || forcedEOF)
            pending = nil
            if fragmented, reads % 13 == 0 {
                // Real asynchronous idle gaps, not only varying byte slices.
                queue.asyncAfter(deadline: .now() + .milliseconds(6)) { done(data, eof, nil) }
            } else { done(data, eof, nil) }
        }
    }

    private struct Packet {
        let sequence: UInt32, acknowledgment: UInt32
        let flags: UInt8
        let payload: Data
        init(_ frame: Data) throws {
            guard frame.count >= 44, read32(frame, 0) == UInt32(AF_INET), frame[4] == 0x45,
                  frame[13] == 6, CDataPlane.checksum(frame.subdata(in: 4..<24)) == 0 else {
                throw Failure(text: "Invalid memory TCP/IP frame")
            }
            let tcp = frame.subdata(in: 24..<frame.count)
            let header = Int(tcp[12] >> 4) * 4
            guard header >= 20, header <= tcp.count,
                  CDataPlane.transportChecksum(sourceBytes: [203, 0, 113, 7],
                    destinationBytes: [198, 18, 16, 10], protocolNumber: 6, transport: tcp) == 0 else {
                throw Failure(text: "TCP stream bytes/checksum changed")
            }
            sequence = read32(tcp, 4); acknowledgment = read32(tcp, 8); flags = tcp[13]
            payload = tcp.subdata(in: header..<tcp.count)
        }
    }

    private static func exercise(_ plan: Plan) throws -> String {
        let origin = MemoryOrigin(plan)
        let tunnel = try NativeTunnel.makeStreamRegressionFixture(stream: origin,
                                                                  initialSequence: UInt32.max - 4097)
        var descriptors = [Int32](repeating: -1, count: 2)
        guard descriptors.withUnsafeMutableBufferPointer({ socketpair(AF_UNIX, SOCK_DGRAM, 0, $0.baseAddress!) }) == 0 else {
            throw Failure(text: "Memory socketpair failed")
        }
        let peer = descriptors[1]
        defer { tunnel.stop(); Darwin.close(peer) }
        for descriptor in descriptors {
            _ = fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL, 0) | O_NONBLOCK)
            var size: Int32 = 512 * 1024
            _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
            _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        }
        _ = try tunnel.start(fileDescriptor: descriptors[0], interfaceName: "memory-fixture0")
        var clientSequence: UInt32 = UInt32.max - 63
        var expectedSequence: UInt32 = 0, initialSequence: UInt32 = 0, handshake = false
        var received = Data(), parked: [UInt32: Data] = [:], requests = 0, responseBoundary = 0
        var packets = 0, probes = 0, retransmissions: [Int: Int] = [:], droppedFIN = false
        var pendingFIN: UInt32?, finished = false, forcedFinish = false
        var zeroSince: Double? = plan.behavior == .zeroInitial ? clock() : nil
        var zeroActive = plan.behavior == .zeroInitial, reneged = false, sackMarked = Set<UInt32>()
        let started = clock(), deadline = started + 8
        let golden = plan.expected
        var scratch = [UInt8](repeating: 0, count: 65_540)

        func advertisedWindow() -> UInt16 {
            switch plan.behavior {
            case .zeroAcknowledged, .zeroHeld, .zeroInitial: return zeroActive ? 0 : 64
            case .zeroOutstanding: return zeroActive ? 0 : 4096
            case .sackAll: return reneged ? 256 : 384
            case .sackPartial: return reneged ? 384 : 512
            default: return 4096
            }
        }
        func send(flags: UInt8 = 0x10, payload: Data = Data(), sacks: [(UInt32, UInt32)] = []) throws {
            let frame = packet(sequence: clientSequence, acknowledgment: expectedSequence,
                               flags: flags, window: advertisedWindow(), payload: payload, sacks: sacks)
            try sendFrame(frame, to: peer)
            if !payload.isEmpty { clientSequence &+= UInt32(payload.count) }
        }
        func ack() throws {
            let blocks = parked.keys.sorted { distance($0, expectedSequence) < distance($1, expectedSequence) }
                .prefix(4).compactMap { key -> (UInt32, UInt32)? in
                    guard let data = parked[key] else { return nil }
                    return (key, key &+ UInt32(data.count))
                }
            try send(sacks: blocks)
        }
        func consume(_ data: Data, at sequence: UInt32) {
            let delta = distance(sequence, expectedSequence)
            if delta <= 0 {
                let skip = Int(-Int64(delta))
                if skip < data.count {
                    let tail = data.dropFirst(skip)
                    received.append(tail); expectedSequence &+= UInt32(tail.count)
                }
                while let next = parked.removeValue(forKey: expectedSequence) {
                    received.append(next); expectedSequence &+= UInt32(next.count)
                }
            } else if parked.count < 64, parked[sequence] == nil { parked[sequence] = data }
        }
        try sendFrame(packet(sequence: clientSequence, acknowledgment: 0, flags: 2,
                             window: .max, payload: Data(), sacks: []), to: peer)
        clientSequence &+= 1

        while clock() < deadline, !finished {
            var ready = pollfd(fd: peer, events: Int16(POLLIN), revents: 0)
            _ = Darwin.poll(&ready, 1, 20)
            let count = scratch.withUnsafeMutableBytes { Darwin.recv(peer, $0.baseAddress!, $0.count, 0) }
            if count < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    if plan.behavior == .zeroHeld, let zeroSince, clock() - zeroSince > 1.7 {
                        guard probes > 0, probes <= 4, received.count == 4096,
                              tunnel.statistics().downloadedBytes == UInt64(received.count) else {
                            throw Failure(text: "zero-window hold: bytes=\(received.count), probes=\(probes)")
                        }
                        return "PASS \(plan.name): held=1700ms, bytes=\(received.count), probes=\(probes), no duplicate delivery"
                    }
                    if let zeroSince, plan.behavior != .zeroHeld, clock() - zeroSince > 2.3, zeroActive {
                        throw Failure(text: "persist stalled: bytes=\(received.count)/\(golden.count), probes=\(probes), outstanding=\(plan.behavior == .zeroOutstanding)")
                    }
                    if reneged, (plan.behavior == .sackAll || plan.behavior == .sackPartial),
                       clock() - started > 2.5, received.count < golden.count {
                        throw Failure(text: "SACK reneging stalled: bytes=\(received.count)/\(golden.count), retransmitted=\(retransmissions.values.reduce(0, +))")
                    }
                    continue
                }
                throw Failure(text: "Memory frame receive failed")
            }
            let incoming = try Packet(Data(scratch.prefix(count)))
            packets += 1
            if incoming.flags & 4 != 0 { throw Failure(text: "Unexpected reset: bytes=\(received.count)/\(golden.count)") }
            if incoming.flags & 2 != 0 {
                guard !handshake else { try ack(); continue }
                handshake = true; expectedSequence = incoming.sequence &+ 1; initialSequence = expectedSequence
                try ack()
                try send(flags: 0x18, payload: plan.steps[0].request)
                requests = 1; responseBoundary = plan.steps[0].response.count
                continue
            }
            guard handshake else { throw Failure(text: "Payload preceded handshake") }
            if incoming.flags & 1 != 0 {
                guard !zeroActive else { throw Failure(text: "FIN bypassed the peer's zero window") }
                if plan.dropFIN, !droppedFIN { droppedFIN = true; continue }
                pendingFIN = incoming.sequence
            }
            if !incoming.payload.isEmpty {
                let relative = Int(distance(incoming.sequence, initialSequence))
                let isProbe = zeroActive && incoming.payload.count <= 1 && incoming.flags & 8 == 0
                if isProbe {
                    probes += 1
                    if plan.behavior != .zeroHeld, let zeroSince, clock() - zeroSince >= 0.7 { zeroActive = false }
                    try ack(); continue
                }
                retransmissions[relative, default: 0] += 1
                switch plan.behavior {
                case .zeroOutstanding:
                    if zeroSince == nil {
                        zeroSince = clock(); zeroActive = true
                        try ack(); continue // Original permitted bytes are deliberately lost.
                    }
                    if zeroActive { try ack(); continue }
                    consume(incoming.payload, at: incoming.sequence)
                case .sackNormal, .sackAll, .sackPartial:
                    if relative == 0, retransmissions[relative] == 1 { continue }
                    if !reneged, relative > 0 {
                        if relative <= 16_384 || plan.behavior == .sackNormal {
                            parked[incoming.sequence] = incoming.payload; sackMarked.insert(incoming.sequence)
                            try ack()
                        }
                        continue
                    }
                    if relative == 0, !reneged {
                        if plan.behavior != .sackNormal { parked.removeAll() }
                        reneged = true
                    }
                    // Partial reneging retains an unsacked tail, exposing a
                    // sender that keeps retrying that tail but never its head.
                    if plan.behavior == .sackPartial, received.count < 24_576, relative >= 24_576 {
                        try send(); continue
                    }
                    consume(incoming.payload, at: incoming.sequence)
                default:
                    consume(incoming.payload, at: incoming.sequence)
                }
                if (plan.behavior == .zeroAcknowledged || plan.behavior == .zeroHeld),
                   zeroSince == nil, received.count >= 4096 {
                    zeroSince = clock(); zeroActive = true
                }
                try ack()
            } else if zeroActive, incoming.flags & 1 == 0,
                      incoming.sequence == expectedSequence &- 1 {
                probes += 1
                if plan.behavior != .zeroHeld, let zeroSince, clock() - zeroSince >= 0.7 { zeroActive = false }
                try ack()
            }
            if requests < plan.steps.count, received.count >= responseBoundary {
                try send(flags: 0x18, payload: plan.steps[requests].request)
                responseBoundary += plan.steps[requests].response.count; requests += 1
            }
            if received.count == golden.count, !forcedFinish {
                forcedFinish = true
                origin.finish(delay: plan.name == "zero-window-drained-tail-fin" ? 0.06 : 0)
            }
            if pendingFIN == expectedSequence {
                guard received == golden else { throw Failure(text: "EOF lost or changed range/frame bytes") }
                expectedSequence &+= 1; try send(); finished = true
            }
        }
        guard finished, received == golden else {
            throw Failure(text: "stream deadline: bytes=\(received.count)/\(golden.count), probes=\(probes), fin=\(finished)")
        }
        if plan.behavior == .sackNormal {
            guard retransmissions.filter({ $0.key > 0 }).allSatisfy({ $0.value == 1 }), sackMarked.count >= 2 else {
                throw Failure(text: "Normal SACK retransmitted bytes already held by the receiver")
            }
        }
        let statistics = tunnel.statistics()
        guard statistics.downloadedBytes == UInt64(golden.count) else {
            throw Failure(text: "Probes/retransmissions changed downloaded-byte accounting")
        }
        return "PASS \(plan.name): bytes=\(golden.count), requests=\(requests), packets=\(packets), probes=\(probes), exact bytes/checksums/FIN"
    }

    private static func clock() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }
    private static func distance(_ lhs: UInt32, _ rhs: UInt32) -> Int32 { Int32(bitPattern: lhs &- rhs) }
    private static func sendFrame(_ frame: Data, to descriptor: Int32) throws {
        let deadline = clock() + 1
        repeat {
            let count = frame.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress!, $0.count, 0) }
            if count == frame.count { return }
            if count < 0, errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOBUFS {
                var ready = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
                _ = Darwin.poll(&ready, 1, 5); continue
            }
            break
        } while clock() < deadline
        throw Failure(text: "Memory frame send failed: errno=\(errno), bytes=\(frame.count)")
    }
    private static func packet(sequence: UInt32, acknowledgment: UInt32, flags: UInt8,
                               window: UInt16, payload: Data, sacks: [(UInt32, UInt32)]) -> Data {
        var options = Data()
        if flags & 2 != 0 { options = Data([2, 4, 32, 0, 1, 3, 3, 6, 4, 2, 1, 1]) }
        else if !sacks.isEmpty {
            options = Data([1, 1, 5, UInt8(2 + 8 * min(4, sacks.count))])
            for block in sacks.prefix(4) { append32(block.0, to: &options); append32(block.1, to: &options) }
        }
        var tcp = Data(); append16(49152, to: &tcp); append16(9443, to: &tcp)
        append32(sequence, to: &tcp); append32(acknowledgment, to: &tcp)
        tcp.append(UInt8((20 + options.count) / 4) << 4); tcp.append(flags)
        append16(window, to: &tcp); append16(0, to: &tcp); append16(0, to: &tcp)
        tcp.append(options); tcp.append(payload)
        let checksum = CDataPlane.transportChecksum(sourceBytes: [198, 18, 16, 10],
            destinationBytes: [203, 0, 113, 7], protocolNumber: 6, transport: tcp)
        tcp[16] = UInt8(checksum >> 8); tcp[17] = UInt8(checksum & 255)
        var ip = Data([0x45, 0]); append16(UInt16(20 + tcp.count), to: &ip)
        append16(1, to: &ip); append16(0x4000, to: &ip)
        ip.append(64); ip.append(6); append16(0, to: &ip)
        ip.append(contentsOf: [198, 18, 16, 10, 203, 0, 113, 7])
        let header = CDataPlane.checksum(ip); ip[10] = UInt8(header >> 8); ip[11] = UInt8(header & 255)
        ip.append(tcp)
        var result = Data(); append32(UInt32(AF_INET), to: &result); result.append(ip)
        return result
    }
    private static func read32(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
    }
    private static func append16(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8)); data.append(UInt8(value & 255))
    }
    private static func append32(_ value: UInt32, to data: inout Data) {
        data.append(UInt8(value >> 24)); data.append(UInt8((value >> 16) & 255))
        data.append(UInt8((value >> 8) & 255)); data.append(UInt8(value & 255))
    }
}

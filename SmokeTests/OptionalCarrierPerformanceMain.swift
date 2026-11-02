import Foundation

// Compile with OptionalCarrierMemorySupport.swift and the unmodified production
// NativeMux.swift, XUDP.swift, MKCPSegment.swift, MKCPTransport.swift and
// MKCPOutbound.swift. Use -O -whole-module-optimization -parse-as-library.
// All payloads, clocks and peers stay inside this process.
@main
enum OptionalCarrierPerformanceMain {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    static func require(_ condition: @autoclosure () throws -> Bool, _ text: String) throws {
        guard try condition() else { throw Failure(text: text) }
    }
    static func awaitGroup(_ group: DispatchGroup) throws {
        try require(group.wait(timeout: .now() + 30) == .success, "memory carrier completion timed out")
    }
    static func elapsed(_ start: UInt64) -> Double {
        Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    }

    final class Carrier: NativeOutboundByteStream {
        private let lock = NSLock()
        private var reader: ((Data?, Bool, Error?) -> Void)?
        private var held: ((Error?) -> Void)?
        private var holdFirst: Bool
        private var stopped = false
        private var writes = 0, bytes = 0
        let reading = DispatchSemaphore(value: 0)
        var inspect: ((Data) -> Void)?
        var onWrite: ((Int) -> Void)?
        init(holdFirst: Bool = false) { self.holdFirst = holdFirst }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock()
            guard !stopped else { lock.unlock(); completion(Failure(text: "closed carrier")); return }
            writes += 1; bytes += data.count
            let hold = holdFirst; holdFirst = false
            let number = writes
            if hold { held = completion }
            lock.unlock()
            inspect?(data)
            onWrite?(number)
            if !hold { completion(nil) }
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped else { lock.unlock(); completion(nil, true, nil); return }
            precondition(reader == nil)
            reader = completion; lock.unlock(); reading.signal()
        }
        func release() { lock.lock(); let done = held; held = nil; lock.unlock(); done?(nil) }
        func emit(_ data: Data?, complete: Bool = false) {
            lock.lock(); let done = reader; reader = nil; lock.unlock()
            precondition(done != nil); done?(data, complete, nil)
        }
        func cancel() {
            lock.lock(); stopped = true; let done = reader; reader = nil; lock.unlock()
            done?(nil, true, nil)
        }
        var counts: (Int, Int) { lock.lock(); defer { lock.unlock() }; return (writes, bytes) }
        var isStopped: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
        var nativeRead: ((Data?, Bool, Error?) -> Void)? { lock.lock(); defer { lock.unlock() }; return reader }
    }

    static let tcp = RequestTarget(host: "benchmark.fixture.invalid", port: 443, protocolName: "TCP")
    static let udp = RequestTarget(host: "203.0.113.53", port: 53, protocolName: "UDP")

    static func muxFrames(count: Int = 768) throws -> Double {
        let carrier = Carrier(), group = DispatchGroup()
        let session = MuxSession(carrier: carrier, concurrency: 1, label: "performance-frames")
        let payload = Data(repeating: 0x5a, count: 256 * 1024)
        let start = DispatchTime.now().uptimeNanoseconds
        for index in 0..<count {
            group.enter()
            session.sendPayload(id: 1, target: tcp, isOpen: index == 0, payload: payload) { error in
                precondition(error == nil); group.leave()
            }
        }
        try awaitGroup(group)
        let duration = elapsed(start)
        try require(carrier.counts.0 == count && carrier.counts.1 > count * payload.count, "Mux framing lost a write")
        session.shutdown(nil)
        return duration
    }

    static func muxBacklog(count: Int = 16_384) throws -> Double {
        let carrier = Carrier(holdFirst: true), group = DispatchGroup()
        let session = MuxSession(carrier: carrier, concurrency: 1, label: "performance-backlog")
        let payload = Data(repeating: 0x5a, count: 64)
        for index in 0..<count {
            group.enter()
            session.sendPayload(id: 1, target: tcp, isOpen: index == 0, payload: payload) { error in
                precondition(error == nil); group.leave()
            }
        }
        _ = session.activeStreamCount // all writes have entered the real queue
        let start = DispatchTime.now().uptimeNanoseconds
        carrier.release(); try awaitGroup(group)
        let duration = elapsed(start)
        try require(carrier.counts.0 == count, "Mux queue dropped a write")
        session.shutdown(nil)
        return duration
    }

    static func xudpBacklog(count: Int = 16_384) throws -> Double {
        let queue = DispatchQueue(label: "fixture.xudp.performance"), carrier = Carrier()
        let completed = DispatchSemaphore(value: 0)
        carrier.onWrite = { if $0 == count { completed.signal() } }
        var dial: ((Result<any NativeOutboundByteStream, Error>) -> Void)?
        let session = XUDPDatagramSession(queue: queue, dial: { dial = $0 }, receive: { _, _ in }, failure: { _ in
            preconditionFailure("XUDP fixture unexpectedly failed")
        })
        let payload = Data(repeating: 0xa5, count: 64)
        for _ in 0..<count { session.send(payload, to: udp) }
        queue.sync {}
        let start = DispatchTime.now().uptimeNanoseconds
        dial?(.success(carrier))
        try require(completed.wait(timeout: .now() + 30) == .success, "XUDP backlog did not drain")
        queue.sync {}
        let duration = elapsed(start)
        session.cancel(); queue.sync {}
        try require(carrier.counts.0 == count, "XUDP queue dropped a datagram")
        return duration
    }

    static func mkcpDecode(iterations: Int = 100_000) throws -> Double {
        let payload = Data(repeating: 0x9b, count: 1200)
        var segment = MKCPWireStub.DataSegment(conv: 7, option: 0)
        segment.payload = payload
        let encoded = segment.encoded()
        var checksum = 0
        let start = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<iterations {
            let decoded = MKCPWireStub.decode(encoded)
            guard case .data(let frame)? = decoded.first else { throw Failure(text: "mKCP decoder lost its data segment") }
            checksum &+= frame.payload.count
        }
        let duration = elapsed(start)
        try require(checksum == iterations * payload.count, "mKCP decode checksum changed")
        return duration
    }

    static func correct() throws {
        try XUDPSelfTest.run()
        try MKCPSegmentSelfTest.run()
        try MKCPTransportSelfTest.run()
        try MKCPOutboundSelfTest.run()
        try queueAndLifecycleChecks()
        try datagramDecodeBoundaries()
        let payload = Data((0..<65_535).map { UInt8(truncatingIfNeeded: $0) })
        let frame = MuxFrame(id: 31, status: .new, target: tcp, payload: payload)
        let wire = try MuxCodec.encode(frame)
        for length in [0, 1, 2, 5, 17, wire.count - 1] {
            var partial = Data(wire.prefix(length))
            let before = partial
            try require(try MuxCodec.decode(from: &partial) == nil && partial == before, "partial Mux frame was consumed")
        }
        var prefixed = Data([9, 9, 9]) + wire
        prefixed.removeFirst(3)
        try require(try MuxCodec.decode(from: &prefixed) == frame && prefixed.isEmpty, "nonzero-based Mux frame changed")
        let carrier = Carrier(), session = MuxSession(carrier: carrier, concurrency: 2, label: "fixture-correctness")
        guard let first = session.openStream(target: tcp, callbackQueue: .global()),
              let second = session.openStream(target: tcp, callbackQueue: .global()) else { throw Failure(text: "Mux slots unavailable") }
        try require(session.openStream(target: tcp, callbackQueue: .global()) == nil, "Mux concurrency limit was bypassed")
        let sent = DispatchGroup(), inspectLock = NSLock()
        var encoded = Data()
        carrier.inspect = { data in inspectLock.lock(); encoded.append(data); inspectLock.unlock() }
        sent.enter(); first.send(payload) { error in precondition(error == nil); sent.leave() }
        sent.enter(); second.send(Data([0xbb])) { error in precondition(error == nil); sent.leave() }
        try awaitGroup(sent)
        inspectLock.lock(); var bytes = encoded; inspectLock.unlock()
        var firstID: UInt16?, recovered = Data(), frames = 0
        while let decoded = try MuxCodec.decode(from: &bytes) {
            if firstID == nil { firstID = decoded.id }
            if decoded.id == firstID { recovered.append(decoded.payload) }
            frames += 1
        }
        try require(recovered == payload && frames == 9 && bytes.isEmpty, "Mux split/serialized data changed")
        first.cancel()
        let done = DispatchGroup(); done.enter()
        second.receive(maximum: 32) { data, complete, error in
            precondition(data == Data([0xcc]) && !complete && error == nil); done.leave()
        }
        try require(carrier.reading.wait(timeout: .now() + 2) == .success, "Mux did not register a carrier read")
        carrier.emit(try MuxCodec.encode(MuxFrame(id: 2, status: .keep, payload: Data([0xcc]))))
        try awaitGroup(done)
        second.cancel(); session.shutdown(nil)
        print("PASS optional carrier memory checks: production Mux splitting/serialization/concurrency/cancel isolation, XUDP wire vectors, mKCP segments/windows/loss/retransmission/EOF/close")
    }

    static func queueAndLifecycleChecks() throws {
        let carrier = Carrier(holdFirst: true), group = DispatchGroup(), lock = NSLock()
        let session = MuxSession(carrier: carrier, concurrency: 1, label: "fixture-fifo")
        var seen: [Int] = []
        carrier.inspect = { wire in
            var input = wire
            guard let frame = try? MuxCodec.decode(from: &input), frame.payload.count == 2 else {
                preconditionFailure("Mux backlog framing changed")
            }
            lock.lock(); seen.append(Int(frame.payload[0]) << 8 | Int(frame.payload[1])); lock.unlock()
        }
        for index in 0..<513 {
            group.enter()
            session.sendPayload(id: 1, target: tcp, isOpen: index == 0,
                payload: Data([UInt8(index >> 8), UInt8(index & 255)])) { error in precondition(error == nil); group.leave() }
        }
        _ = session.activeStreamCount
        carrier.release(); try awaitGroup(group)
        lock.lock(); let order = seen; lock.unlock()
        try require(order == Array(0..<513), "Mux backlog reordered/dropped/duplicated an acknowledged write")
        session.shutdown(nil)

        let blocked = Carrier(holdFirst: true), closing = MuxSession(carrier: blocked, concurrency: 1, label: "fixture-close")
        let done = DispatchGroup()
        var calls = [Int](repeating: 0, count: 257), failures = 0
        for index in 0..<257 {
            done.enter()
            closing.sendPayload(id: 1, target: tcp, isOpen: index == 0, payload: Data([1])) { error in
                lock.lock(); calls[index] += 1; if error != nil { failures += 1 }; lock.unlock(); done.leave()
            }
        }
        _ = closing.activeStreamCount
        closing.shutdown(nil)
        try require(closing.isClosed && blocked.counts.0 == 1, "Mux shutdown continued queued carrier sends")
        blocked.release(); try awaitGroup(done)
        lock.lock(); let counts = calls, failed = failures; lock.unlock()
        try require(counts.allSatisfy { $0 == 1 } && failed == 256, "Mux shutdown failed pending writes more than once")

        let queue = DispatchQueue(label: "fixture.xudp.lifecycle")
        var dial: ((Result<any NativeOutboundByteStream, Error>) -> Void)?
        let xudp = XUDPDatagramSession(queue: queue, dial: { dial = $0 }, receive: { _, _ in
            preconditionFailure("cancelled XUDP delivered a packet")
        }, failure: { _ in preconditionFailure("cancelled XUDP delivered an error") })
        for _ in 0..<513 { xudp.send(Data([7]), to: udp) }
        queue.sync {}; xudp.cancel(); queue.sync {}
        let late = Carrier(); dial?(.success(late)); queue.sync {}
        try require(late.isStopped && late.counts.0 == 0, "XUDP cancellation sent queued packets over a late carrier")

        let inbound = Carrier(), packets = DispatchGroup()
        var replies: [Data] = [], eofFailures = 0
        let receiver = XUDPDatagramSession(queue: queue, dial: { $0(.success(inbound)) }, receive: { target, payload in
            precondition(target == udp); replies.append(payload); packets.leave()
        }, failure: { _ in eofFailures += 1 })
        receiver.send(Data([1]), to: udp); queue.sync {}; queue.sync {}
        let globalID = Data([1, 2, 3, 4, 5, 6, 7, 8])
        var wire = try XUDPCodec.encode(target: udp, payload: Data([3]), first: true, globalID: globalID)
        wire.append(try MuxCodec.encode(MuxFrame(id: 0, status: .keepAlive)))
        wire.append(try MuxCodec.encode(MuxFrame(id: 0, status: .end)))
        wire.append(try XUDPCodec.encode(target: udp, payload: Data([4, 5]), first: false, globalID: globalID))
        packets.enter(); packets.enter()
        var offset = 0
        for length in [1, 2, 7, wire.count - 10] {
            try require(inbound.reading.wait(timeout: .now() + 2) == .success, "fragmented XUDP did not request its next read")
            inbound.emit(Data(wire[offset..<(offset + length)]), complete: offset + length == wire.count)
            offset += length
        }
        try awaitGroup(packets); queue.sync {}
        try require(replies == [Data([3]), Data([4, 5])] && eofFailures == 1 && inbound.isStopped,
                    "XUDP fragmented/coalesced/control/EOF handling changed")
        receiver.cancel(); queue.sync {}

        let cancelledPeer = Carrier()
        var cancelledDeliveries = 0
        let cancelledReceiver = XUDPDatagramSession(queue: queue, dial: { $0(.success(cancelledPeer)) },
            receive: { _, _ in cancelledDeliveries += 1 }, failure: { _ in cancelledDeliveries += 1 })
        cancelledReceiver.send(Data([1]), to: udp)
        try require(cancelledPeer.reading.wait(timeout: .now() + 2) == .success, "XUDP cancellation fixture never registered a native read")
        let oldNativeRead = cancelledPeer.nativeRead
        cancelledReceiver.cancel(); queue.sync {}
        oldNativeRead?(try XUDPCodec.encode(target: udp, payload: Data([9]), first: false, globalID: globalID), false, nil)
        queue.sync {}
        try require(cancelledDeliveries == 0, "a native XUDP read arriving after cancellation reached its old client")

        var oversizeFailures = 0, dials = 0
        let limited = XUDPDatagramSession(queue: queue, dial: { _ in dials += 1 }, receive: { _, _ in }, failure: { _ in oversizeFailures += 1 })
        limited.send(Data(repeating: 1, count: 65_536), to: udp); queue.sync {}
        try require(oversizeFailures == 1 && dials == 0, "oversized XUDP payload bypassed the wire limit or dialed")
        limited.cancel(); queue.sync {}
    }

    static func datagramDecodeBoundaries() throws {
        var data = MKCPWireStub.DataSegment(conv: 7, option: 1)
        data.timestamp = UInt32.max; data.number = 0x12345678; data.sendingNext = 17
        data.payload = Data((0..<128).map { UInt8($0) })
        var ack = MKCPWireStub.AckSegment(conv: 7, option: 0)
        ack.receivingNext = 19; ack.receivingWindow = 207; ack.timestamp = 0x89abcdef
        ack.numbers = (0..<128).map { UInt32($0) &* 65537 }
        var command = MKCPWireStub.CmdSegment(conv: 7, command: 91, option: 0)
        command.receivingNext = 23; command.sendingNext = 41; command.peerRTO = 200
        let wire = data.encoded() + ack.encoded() + command.encoded()
        for length in 0...wire.count {
            var input = Data([0xff, 0xee, 0xdd]) + Data(wire.prefix(length))
            input.removeFirst(3)
            let actual = MKCPWireStub.decode(input).map { segment -> Data in
                switch segment {
                case .data(let value): return value.encoded()
                case .ack(let value): return value.encoded()
                case .cmd(let value): return value.encoded()
                }
            }
            let expected = try MKCPSegment.decodeAll(input).map { try $0.encoded() }
            try require(actual == expected, "mKCP production decoder changed a truncated/chained/nonzero-index datagram")
        }
        let memory = UnsafeMutableRawPointer.allocate(byteCount: wire.count, alignment: 8)
        defer { memory.deallocate() }
        wire.withUnsafeBytes { memory.copyMemory(from: $0.baseAddress!, byteCount: wire.count) }
        let borrowed = Data(bytesNoCopy: memory, count: wire.count, deallocator: .none)
        let snapshots = MKCPWireStub.decode(borrowed)
        memory.initializeMemory(as: UInt8.self, repeating: 0, count: wire.count)
        try require(borrowed[borrowed.startIndex + 1] == 0 && wire[1] != 0,
                    "mKCP ownership fixture did not mutate the no-copy datagram backing")
        let owned = snapshots.map { segment -> Data in
            switch segment {
            case .data(let value): return value.encoded()
            case .ack(let value): return value.encoded()
            case .cmd(let value): return value.encoded()
            }
        }
        try require(owned == [data.encoded(), ack.encoded(), command.encoded()],
                    "mKCP retained externally mutable no-copy datagram storage instead of owning a payload snapshot")
        withExtendedLifetime(borrowed) {}
        print("PASS carrier queue/lifecycle and mKCP decoder boundary vectors")
    }

    static func main() {
        do {
            if !CommandLine.arguments.contains("--bench-only") { try correct() }
            let rounds = CommandLine.arguments.contains("--sample") ? 15 : 3
            for round in 0..<rounds {
                print(String(format: "CARRIER-PERF round=%d mux-frames-192MiB=%.3fms mux-backlog-16384=%.3fms xudp-backlog-16384=%.3fms mkcp-decode-120MB=%.3fms", round,
                    try muxFrames(), try muxBacklog(), try xudpBacklog(), try mkcpDecode()))
                fflush(stdout)
            }
        } catch {
            FileHandle.standardError.write(Data("Optional carrier fixture failed: \(error.localizedDescription)\n".utf8)); exit(1)
        }
    }
}

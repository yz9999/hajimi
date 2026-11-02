import Foundation
import CryptoKit

/// The server side is an independent memory peer. The client is the verbatim
/// production ByteTransport, including its handshake, queues and receive pump.
enum WebSocketCarrierFixture {
    final class Peer: ByteTransport {
        private let lock = NSLock()
        private var incoming: [Data] = []
        private var head = 0
        private var receiver: ((Data?, Bool, Error?) -> Void)?
        private var writes: [Data] = []
        private var holdWrites = false
        private var heldWrites: [(Error?) -> Void] = []
        private var stopped = false
        private var delivered = 0
        var badAccept = false

        var frames: [Data] { lock.lock(); defer { lock.unlock() }; return writes }
        var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
        var deliveredBytes: Int { lock.lock(); defer { lock.unlock() }; return delivered }

        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            if data.starts(with: Data("GET ".utf8)) {
                let lines = String(decoding: data, as: UTF8.self).components(separatedBy: "\r\n")
                guard let line = lines.first(where: { $0.hasPrefix("Sec-WebSocket-Key:") }) else {
                    completion(CarrierFramingMain.Failure(message: "WS handshake omitted secure key")); return
                }
                let key = line.dropFirst("Sec-WebSocket-Key:".count).trimmingCharacters(in: .whitespaces)
                let value = Data((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8)
                let accept = badAccept ? "invalid" : Data(Insecure.SHA1.hash(data: value)).base64EncodedString()
                let reply = Data(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    + "Connection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n").utf8)
                feed([reply]); completion(nil); return
            }
            lock.lock(); writes.append(data); let closed = stopped
            if holdWrites, !closed { heldWrites.append(completion); lock.unlock(); return }
            lock.unlock()
            completion(closed ? CarrierFramingMain.Failure(message: "WS memory peer closed") : nil)
        }

        func pauseWrites() { lock.lock(); holdWrites = true; lock.unlock() }
        func releaseWrites() {
            lock.lock(); let callbacks = heldWrites; heldWrites.removeAll(); holdWrites = false; lock.unlock()
            callbacks.forEach { $0(nil) }
        }

        func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            if head < incoming.count {
                let next = incoming[head]; head += 1; delivered += next.count
                if head == incoming.count { incoming.removeAll(keepingCapacity: true); head = 0 }
                lock.unlock(); completion(next, false, nil)
            } else if stopped { lock.unlock(); completion(nil, true, nil) }
            else { receiver = completion; lock.unlock() }
        }

        func feed(_ fragments: [Data]) {
            lock.lock()
            incoming.append(contentsOf: fragments)
            if let callback = receiver, head < incoming.count {
                receiver = nil
                let next = incoming[head]; head += 1; delivered += next.count
                if head == incoming.count { incoming.removeAll(keepingCapacity: true); head = 0 }
                lock.unlock(); callback(next, false, nil)
            } else { lock.unlock() }
        }

        func cancel() {
            lock.lock(); stopped = true; let callback = receiver; receiver = nil; lock.unlock()
            callback?(nil, true, nil)
        }
    }

    static func open(_ peer: Peer) throws -> any ByteTransport {
        let ready = DispatchSemaphore(value: 0)
        var result: Result<any ByteTransport, Error>?
        WebSocketProductionFixture.connect(raw: peer) { result = $0; ready.signal() }
        try CarrierFramingMain.require(ready.wait(timeout: .now() + 3) == .success, "WS production handshake timed out")
        return try result!.get()
    }

    static func benchmarkSend(_ payload: Data, count: Int) throws -> (Double, Int) {
        let peer = Peer(), stream = try open(peer)
        defer { stream.cancel() }
        let complete = DispatchGroup(), lock = NSLock()
        var failures = 0
        let started = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<count {
            complete.enter()
            stream.send(payload) { error in
                if error != nil { lock.lock(); failures += 1; lock.unlock() }
                complete.leave()
            }
        }
        try CarrierFramingMain.require(complete.wait(timeout: .now() + 10) == .success, "WS production sends stalled")
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        let frames = peer.frames
        try CarrierFramingMain.require(failures == 0 && frames.count == count, "WS send completion/frame count changed")
        // Full independent wire verification is outside the measured region.
        for frame in frames { try CarrierFramingMain.require(try decodeClientFrame(frame) == payload, "WS production send changed bytes") }
        return (elapsed, frames.reduce(0) { $0 &+ $1.count })
    }

    static func benchmarkReceive(_ payload: Data, count: Int, fragmentSize: Int) throws -> (Double, Int) {
        var wire = Data()
        let frame = serverFrame(payload)
        for _ in 0..<count { wire.append(frame) }
        let fragments = stride(from: 0, to: wire.count, by: fragmentSize).map {
            Data(wire[$0..<min($0 + fragmentSize, wire.count)])
        }
        let peer = Peer(), stream = try open(peer)
        defer { stream.cancel() }
        let complete = DispatchGroup(), lock = NSLock()
        var bytes = 0, failures = 0
        let started = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<count {
            complete.enter()
            stream.receive { data, ended, error in
                lock.lock()
                if error != nil || ended || data != payload { failures += 1 }
                bytes += data?.count ?? 0
                lock.unlock(); complete.leave()
            }
        }
        peer.feed(fragments)
        try CarrierFramingMain.require(complete.wait(timeout: .now() + 10) == .success, "WS production receive pump stalled")
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        try CarrierFramingMain.require(failures == 0 && bytes == payload.count * count, "WS fragmented receive lost bytes")
        return (elapsed, bytes)
    }

    static func run() throws {
        try WebSocketProductionFixture.runExistingSelfTest()
        try framingOwnership()
        for size in [0, 1, 7, 8, 9, 125, 126, 127, 65_535, 65_536] {
            let payload = Data((0..<size).map { UInt8(truncatingIfNeeded: $0) })
            let peer = Peer(), stream = try open(peer), done = DispatchSemaphore(value: 0)
            var error: Error?
            stream.send(payload) { error = $0; done.signal() }
            try CarrierFramingMain.require(done.wait(timeout: .now() + 3) == .success && error == nil, "WS length boundary send failed")
            try CarrierFramingMain.require(peer.frames.count == 1 && (try decodeClientFrame(peer.frames[0])) == payload,
                                            "WS 7/16/64-bit length boundary changed")
            stream.cancel()
        }
        try receiveBoundaries()
        try cancelBacklog()
        let invalid = Peer(); invalid.badAccept = true
        do { _ = try open(invalid); throw CarrierFramingMain.Failure(message: "WS accepted invalid handshake proof") }
        catch is NativeOutboundError {}
        try CarrierFramingMain.require(invalid.isCancelled, "WS rejected handshake retained its peer")

        let peer = Peer(), stream = try open(peer), cancelled = DispatchSemaphore(value: 0)
        var callbacks = 0, terminal = false
        stream.receive { data, ended, _ in callbacks += 1; terminal = data == nil && ended; cancelled.signal() }
        stream.cancel()
        try CarrierFramingMain.require(cancelled.wait(timeout: .now() + 3) == .success && terminal && callbacks == 1,
                                        "WS cancellation did not terminate the pending read exactly once")
    }

    private static func framingOwnership() throws {
        let maskStorage = Data([0xff, 0x13, 0x57, 0x9b, 0xdf, 0xff])
        let mask = maskStorage[1..<5]
        for size in [0, 1, 2, 7, 8, 9, 15, 16, 17, 125, 126, 127, 65_535, 65_536] {
            let storage = Data([0xff]) + Data((0..<size).map { UInt8(truncatingIfNeeded: $0) }) + Data([0xff])
            let input = storage[1..<(size + 1)]
            let expected = Data(input)
            let encoded = WebSocketFraming.encode(input, mask: mask)
            try CarrierFramingMain.require(try decodeClientFrame(encoded) == expected,
                                            "WS unaligned/sliced framing changed bytes")
            let maskOffset = size < 126 ? 2 : (size <= 65_535 ? 4 : 10)
            let masked = encoded[maskOffset...]
            try CarrierFramingMain.require(WebSocketFraming.payload(masked, masked: true) == expected,
                                            "WS unaligned/sliced masked decoding changed bytes")
            try CarrierFramingMain.require(WebSocketFraming.payload(input, masked: false) == expected,
                                            "WS sliced unmasked decoding changed bytes")
        }
        let storage = UnsafeMutableRawPointer.allocate(byteCount: 65, alignment: 8)
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0x5a, count: 65)
        let borrowed = Data(bytesNoCopy: storage.advanced(by: 1), count: 64, deallocator: .none)
        let owned = WebSocketFraming.payload(borrowed, masked: false)
        let ownedMasked = WebSocketFraming.payload(borrowed, masked: true)
        let encoded = WebSocketFraming.encode(borrowed, mask: mask)
        storage.initializeMemory(as: UInt8.self, repeating: 0xff, count: 65)
        try CarrierFramingMain.require(owned == Data(repeating: 0x5a, count: 64)
            && ownedMasked == Data(repeating: 0, count: 60)
            && (try decodeClientFrame(encoded)) == owned, "WS retained mutable no-copy input storage")
    }

    private static func receiveBoundaries() throws {
        for size in [1, 7, 8, 9, 125, 126, 127, 65_535, 65_536] {
            let payload = Data((0..<size).map { UInt8(truncatingIfNeeded: $0) })
            for masked in [false, true] {
                let peer = Peer(), stream = try open(peer), done = DispatchSemaphore(value: 0)
                var received: Data?, failed = false
                stream.receive { data, ended, error in received = data; failed = ended || error != nil; done.signal() }
                let wire = serverFrame(payload, mask: masked ? [0x13, 0x57, 0x9b, 0xdf] : nil)
                // Include split 7/16/64-bit length fields and mask words.
                let fragments = stride(from: 0, to: wire.count, by: 31).map { Data(wire[$0..<min($0 + 31, wire.count)]) }
                peer.feed(fragments)
                try CarrierFramingMain.require(done.wait(timeout: .now() + 3) == .success && !failed && received == payload,
                                                "WS actual receive changed a fragmented length/mask boundary")
                stream.cancel()
            }
        }
        // Pin the existing reader's clean EOF classification while reading a
        // base header. EOF after a length prefix or payload is an error.
        for (wire, expectsError) in [(Data(), false), (Data([0x82]), false),
                                     (Data([0x82, 126, 0]), true),
                                     (Data([0x82, 2, 0x41]), true),
                                     (Data([0x82, 127, 0, 0, 0, 0, 1, 0, 0, 1]), true)] {
            let peer = Peer(), stream = try open(peer), done = DispatchSemaphore(value: 0)
            var terminal = false
            stream.receive { data, ended, error in
                terminal = data == nil && ended && ((error != nil) == expectsError); done.signal()
            }
            if !wire.isEmpty { peer.feed([wire]) }
            peer.cancel()
            try CarrierFramingMain.require(done.wait(timeout: .now() + 3) == .success && terminal,
                "WS EOF/truncation/oversized length outcome changed for \(wire.map { String(format: "%02x", $0) }.joined())")
            stream.cancel()
        }
    }

    private static func cancelBacklog() throws {
        let peer = Peer(), stream = try open(peer), done = DispatchGroup(), lock = NSLock()
        peer.pauseWrites()
        var callbacks = [Int](repeating: 0, count: 256), failures = 0
        for index in callbacks.indices {
            done.enter()
            stream.send(Data(repeating: UInt8(truncatingIfNeeded: index), count: 32)) { error in
                lock.lock(); callbacks[index] += 1; if error != nil { failures += 1 }; lock.unlock()
                done.leave()
            }
        }
        stream.cancel()
        try CarrierFramingMain.require(done.wait(timeout: .now() + 3) == .success,
                                        "WS cancellation stalled a backpressured write backlog")
        try CarrierFramingMain.require(peer.frames.count == 1 && peer.isCancelled,
                                        "WS writer did not retain one native send in flight")
        peer.releaseWrites()
        let barrier = DispatchSemaphore(value: 0)
        stream.receive { _, _, _ in barrier.signal() }
        try CarrierFramingMain.require(barrier.wait(timeout: .now() + 3) == .success
            && failures == callbacks.count && callbacks.allSatisfy { $0 == 1 },
            "WS late native completion repeated a cancelled application write")
    }

    private static func serverFrame(_ payload: Data, mask: [UInt8]? = nil) -> Data {
        var frame = Data([0x82])
        let flag: UInt8 = mask == nil ? 0 : 0x80
        if payload.count < 126 { frame.append(flag | UInt8(payload.count)) }
        else if payload.count <= 65_535 {
            frame.append(contentsOf: [flag | 126, UInt8(payload.count >> 8), UInt8(payload.count & 255)])
        } else {
            frame.append(flag | 127)
            for shift in stride(from: 56, through: 0, by: -8) { frame.append(UInt8(truncatingIfNeeded: payload.count >> shift)) }
        }
        if let mask {
            frame.append(contentsOf: mask)
            for (index, byte) in payload.enumerated() { frame.append(byte ^ mask[index & 3]) }
            return frame
        }
        frame.append(payload); return frame
    }

    private static func decodeClientFrame(_ frame: Data) throws -> Data {
        try CarrierFramingMain.require(frame.count >= 6 && frame[0] == 0x82 && frame[1] & 0x80 != 0,
                                        "WS client frame is unmasked or has wrong opcode")
        let short = Int(frame[1] & 0x7f)
        var offset = 2, length = short
        if short == 126 { length = Int(frame[2]) << 8 | Int(frame[3]); offset = 4 }
        else if short == 127 {
            length = 0
            for byte in frame[2..<10] { length = length << 8 | Int(byte) }
            offset = 10
        }
        try CarrierFramingMain.require(frame.count == offset + 4 + length, "WS frame length does not match its payload")
        var payload = Data(count: length)
        for index in 0..<length { payload[index] = frame[offset + 4 + index] ^ frame[offset + (index & 3)] }
        return payload
    }
}

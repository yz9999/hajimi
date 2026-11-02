import Foundation

/// Compile the real HTTP2/HPACK/XHTTP/streaming/WebSocketFraming sources with
/// CarrierFramingSupport.swift. Peers are memory-only; no profile or socket.
@main
enum CarrierFramingMain {
    struct Failure: Error { let message: String }
    private static var sink = 0

    static func require(_ value: Bool, _ message: String) throws {
        if !value { throw Failure(message: message) }
    }

    private final class Peer: ByteTransport {
        var initial: Data?
        var receiver: ((Data?, Bool, Error?) -> Void)?
        var holdWrites = false
        var pendingWrite: ((Error?) -> Void)?
        var sentBytes = 0, sends = 0, cancelled = false
        var digest: UInt64 = 0
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            sentBytes += data.count; sends += 1
            digest &+= UInt64(data.count) &+ UInt64(data.first ?? 0) &+ UInt64(data.last ?? 0)
            if holdWrites { pendingWrite = completion } else { completion(nil) }
        }
        func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
            if let data = initial { initial = nil; completion(data, false, nil) }
            else { receiver = completion }
        }
        func cancel() { cancelled = true }
        func releaseWrites() {
            // Deliver one native completion at a time without manufacturing a
            // recursive call stack for a real asynchronously drained writer.
            while let callback = pendingWrite { pendingWrite = nil; callback(nil) }
            holdWrites = false
        }
    }

    static func main() throws {
        if CommandLine.arguments.contains("--grpc-malformed") {
            do { try grpcMalformedRegression(); print("PASS gRPC malformed production-pump regression") }
            catch {
                FileHandle.standardError.write(Data("FAIL gRPC malformed production-pump: \(error)\n".utf8))
                exit(1)
            }
            return
        }
        if !CommandLine.arguments.contains("--bench-only") {
            try HTTP2SelfTest.run()
            try XHTTPSelfTest.run()
            try WebSocketCarrierFixture.run()
            try grpcMalformedRegression()
            print("PASS production WS framing/lifecycle and gRPC malformed-pump regressions")
        }
        if !CommandLine.arguments.contains("--checks-only") { try benchmarks() }
        print("Carrier production framing checks passed; checksum=\(sink)")
    }

    private static func grpcMalformedRegression() throws {
        let compressed = HTTP2.encode(HTTP2.Frame(type: 0, flags: [], streamID: 1,
                                                  payload: Data([1, 0, 0, 0, 0])))
        let badHunk = HTTP2.encode(HTTP2.Frame(type: 0, flags: [], streamID: 1,
                                              payload: Data([0, 0, 0, 0, 1, 0xff])))
        let badPadding = HTTP2.encode(HTTP2.Frame(type: 0, flags: .padded, streamID: 1,
                                                 payload: Data([2])))
        let oversized = Data([0x40, 0, 1, 0, 0, 0, 0, 0, 1])
        for (name, wire) in [("compressed message", compressed), ("invalid protobuf Hunk", badHunk),
                             ("invalid HTTP2 padding", badPadding), ("oversized HTTP2 frame", oversized)] {
            let raw = Peer(), queue = DispatchQueue(label: "carrier.grpc.malformed.fixture")
            var opened: Result<GRPCByteTransport, Error>?
            GRPCByteTransport.connect(raw: raw, serviceName: "fixture", authority: "fixture.invalid",
                                      scheme: "https", queue: queue) { opened = $0 }
            let transport = try opened!.get()
            var callbacks = 0, terminalError = false
            transport.receive { data, ended, error in
                callbacks += 1; terminalError = data == nil && ended && error != nil
            }
            let processed = DispatchSemaphore(value: 0), receive = raw.receiver!
            queue.async { receive(wire, false, nil); processed.signal() }
            try require(processed.wait(timeout: .now() + 2) == .success,
                        "gRPC malformed \(name) left consume's NSLock held")
            try require(callbacks == 1 && terminalError && raw.cancelled,
                        "gRPC malformed \(name) did not fail its pending read exactly once")
            var subsequentError = false
            transport.receive { _, ended, error in subsequentError = ended && error != nil }
            try require(subsequentError, "gRPC malformed \(name) did not retain its terminal error")
            transport.cancel()
        }
    }

    private static func measure(_ name: String, bytes: Int, _ body: () throws -> Int) rethrows {
        var samples: [Double] = []
        for _ in 0..<5 {
            let started = DispatchTime.now().uptimeNanoseconds
            sink &+= try body()
            samples.append(Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000)
        }
        let median = samples.sorted()[samples.count / 2]
        let value: [String: Any] = ["name": name, "bytes": bytes, "samplesMilliseconds": samples,
                                   "medianMilliseconds": median]
        let json = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        print("CARRIER-MEASUREMENT " + String(decoding: json, as: UTF8.self))
    }

    private static func benchmarks() throws {
        let block = Data((0..<16_384).map { UInt8(truncatingIfNeeded: $0) })
        let mask = Data([0x13, 0x57, 0x9b, 0xdf]), iterations = 4096
        try measureTransport("websocket-transport-send-16k", bytes: block.count * iterations) {
            try WebSocketCarrierFixture.benchmarkSend(block, count: iterations)
        }
        try measureTransport("websocket-transport-receive-1460byte-fragments", bytes: block.count * 512) {
            try WebSocketCarrierFixture.benchmarkReceive(block, count: 512, fragmentSize: 1460)
        }
        measure("websocket-send-16k", bytes: block.count * iterations) {
            var count = 0
            for _ in 0..<iterations {
                let frame = WebSocketFraming.encode(block, mask: mask)
                count &+= frame.count &+ Int(frame.last ?? 0)
            }
            return count
        }
        measure("websocket-receive-unmasked-16k", bytes: block.count * iterations) {
            var count = 0
            for _ in 0..<iterations {
                let payload = WebSocketFraming.payload(block, masked: false)
                count &+= payload.count &+ Int(payload.last ?? 0)
            }
            return count
        }
        measure("grpc-encode-16k", bytes: block.count * iterations) {
            var count = 0
            for _ in 0..<iterations {
                let frame = GRPCFraming.encode(block)
                count &+= frame.count &+ Int(frame.last ?? 0)
            }
            return count
        }

        var frameWire = Data(), grpcWire = Data()
        for _ in 0..<512 {
            let grpc = GRPCFraming.encode(block)
            grpcWire.append(grpc)
            for start in stride(from: 0, to: grpc.count, by: HTTP2.defaultMaxFrameSize) {
                frameWire.append(HTTP2.encode(HTTP2.Frame(type: 0, flags: [], streamID: 1,
                    payload: Data(grpc[start..<min(start + HTTP2.defaultMaxFrameSize, grpc.count)]))))
            }
        }
        let frameChunks = chunks(frameWire, size: 65_536), grpcChunks = chunks(grpcWire, size: 65_536)
        try measure("http2-decode-64k-reads", bytes: frameWire.count) {
            var buffer = Data(), count = 0
            for chunk in frameChunks {
                buffer.append(chunk)
                while let frame = try HTTP2.decode(from: &buffer, maxFrameSize: 1 << 22) { count += frame.payload.count }
            }
            try require(buffer.isEmpty, "HTTP2 benchmark left a partial frame")
            return count
        }
        try measure("grpc-decode-64k-reads", bytes: grpcWire.count) {
            var buffer = Data(), count = 0
            for chunk in grpcChunks {
                buffer.append(chunk)
                for payload in try GRPCFraming.decode(from: &buffer) { count += payload.count }
            }
            try require(buffer.isEmpty, "gRPC benchmark left a partial message")
            return count
        }
        let count = 4096, small = Data(repeating: 0x51, count: 256)
        try measure("grpc-transport-write-backlog", bytes: small.count * count) {
            let raw = Peer(), queue = DispatchQueue(label: "carrier.grpc.fixture")
            var opened: Result<GRPCByteTransport, Error>?
            GRPCByteTransport.connect(raw: raw, serviceName: "fixture", authority: "fixture.invalid",
                                      scheme: "https", queue: queue) { opened = $0 }
            let transport = try opened!.get()
            raw.holdWrites = true
            var completed = 0
            for _ in 0..<count { transport.send(small) { if $0 == nil { completed += 1 } } }
            raw.releaseWrites()
            try require(completed == count, "gRPC write backlog did not drain")
            transport.cancel()
            return Int(truncatingIfNeeded: raw.digest)
        }
        try measure("xhttp-stream-one-write-backlog", bytes: small.count * count) {
            let raw = Peer()
            raw.initial = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".utf8)
            var opened: Result<any ByteTransport, Error>?
            XHTTPTransport.connect(raw: raw, dial: { _ in }, mode: .streamOne,
                                   path: "/fixture/", hostHeader: "fixture.invalid", scheme: "https",
                                   paddingRange: 0...0, queue: .global()) { opened = $0 }
            let transport = try opened!.get()
            raw.holdWrites = true
            var completed = 0
            for _ in 0..<count { transport.send(small) { if $0 == nil { completed += 1 } } }
            raw.releaseWrites()
            try require(completed == count, "XHTTP stream-one write backlog did not drain")
            transport.cancel()
            return Int(truncatingIfNeeded: raw.digest)
        }
        let head = Data(("HTTP/1.1 200 OK\r\nX-Padding: " + String(repeating: "x", count: 32_768)
                         + "\r\nTransfer-Encoding: chunked\r\n\r\n").utf8)
        let headChunks = chunks(head, size: 32)
        try measure("xhttp-response-head-32byte-fragments", bytes: head.count * 16) {
            var count = 0
            for _ in 0..<16 {
                let parser = HTTP1ResponseParser()
                for chunk in headChunks { count += try parser.ingest(chunk).payload.count }
                try require(parser.headComplete && parser.statusCode == 200, "fragmented XHTTP head failed")
            }
            return count + head.count
        }
        var body = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".utf8)
        for _ in 0..<8192 { body.append(Data("100\r\n".utf8)); body.append(small); body.append(Data("\r\n".utf8)) }
        body.append(Data("0\r\n\r\n".utf8))
        for size in [31, 1460, 16_384] {
            let fragments = chunks(body, size: size)
            try measure("xhttp-chunks-\(size)byte-reads", bytes: small.count * 8192) {
                let parser = HTTP1ResponseParser()
                var count = 0
                for fragment in fragments { count += try parser.ingest(fragment).payload.count }
                try require(parser.complete && count == small.count * 8192, "chunked XHTTP payload changed")
                return count
            }
        }
    }

    private static func chunks(_ data: Data, size: Int) -> [Data] {
        stride(from: 0, to: data.count, by: size).map { Data(data[$0..<min($0 + size, data.count)]) }
    }

    private static func measureTransport(_ name: String, bytes: Int,
                                         _ body: () throws -> (Double, Int)) rethrows {
        var samples: [Double] = []
        for _ in 0..<5 {
            let (milliseconds, checksum) = try body()
            samples.append(milliseconds); sink &+= checksum
        }
        let value: [String: Any] = ["name": name, "bytes": bytes, "samplesMilliseconds": samples,
                                   "medianMilliseconds": samples.sorted()[samples.count / 2]]
        let json = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        print("CARRIER-MEASUREMENT " + String(decoding: json, as: UTF8.self))
    }
}

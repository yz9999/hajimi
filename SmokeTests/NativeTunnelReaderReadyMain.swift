import Foundation
import Dispatch
import Darwin
import HajimiCore

/// Compiled with the unchanged NativeCore sources and the completed Core
/// objects. AF_UNIX datagrams replace utun; FINAL,REJECT prevents any outbound
/// socket, resolver, listener, Helper or system-network change.
@main
struct NativeTunnelReaderReadyMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private static var checks = 0
    private final class WaitProbe {
        private let lock = NSLock()
        private var rejected = false
        private var successes = 0
        func record(rejected: Bool) {
            lock.lock(); defer { lock.unlock() }
            self.rejected = rejected
            if !rejected { successes += 1 }
        }
        var result: (rejected: Bool, successes: Int) {
            lock.lock(); defer { lock.unlock() }
            return (rejected, successes)
        }
    }

    private static func expect(_ condition: Bool, _ text: String) throws {
        checks += 1
        if !condition { throw Failure(text: text) }
    }

    private static func rejects(_ text: String, _ body: () throws -> Void) throws {
        var rejected = false
        do { try body() } catch { rejected = true }
        try expect(rejected, text)
    }

    static func main() {
        signal(SIGPIPE, SIG_IGN)
        do { try run() }
        catch {
            FileHandle.standardError.write(Data(("FAIL reader-ready: " + error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    private static func run() throws {
        try readinessStateChecks()
        let profile = try ProfileParser.parse("[General]\ndns-prewarm = false\n[Rule]\nFINAL,REJECT\n")
        let router = NativePacketRouter(profile: profile, mode: .rule,
                                        globalPolicy: "REJECT", groupSelections: [:])
        let tunnel = try NativeTunnel(router: router)
        try rejects("an unstarted tunnel acknowledged its reader") {
            try tunnel.waitUntilReaderReady(timeout: 0.05)
        }

        // A datagram is queued before source registration. Acknowledgment is
        // followed by a real parser/router/C-codec/writev round trip, rather
        // than inferring readiness from source.resume() returning.
        let started = DispatchTime.now().uptimeNanoseconds
        for epoch in 0..<16 {
            var descriptors = [Int32](repeating: -1, count: 2)
            try expect(descriptors.withUnsafeMutableBufferPointer {
                socketpair(AF_UNIX, SOCK_DGRAM, 0, $0.baseAddress!)
            } == 0, "socketpair failed")
            let peer = descriptors[1]
            var handedOff = false
            defer {
                tunnel.stop()
                if !handedOff { Darwin.close(descriptors[0]) }
                Darwin.close(peer)
            }
            let first = try frame(identifier: UInt16(epoch * 8))
            try send(first, on: peer)
            let name = "reader-ready-memory\(epoch)"
            _ = try tunnel.start(fileDescriptor: descriptors[0], interfaceName: name)
            handedOff = true
            try tunnel.waitUntilReaderReady(timeout: 2)
            try expect(tunnel.interfaceName == name, "reader acknowledged a different epoch")
            try validateICMP(try receive(on: peer), original: first)

            // Verify the acknowledged source keeps processing subsequent
            // ingress, including after the first dispatch-source event.
            for offset in 1..<8 {
                let packet = try frame(identifier: UInt16(epoch * 8 + offset))
                try send(packet, on: peer)
                try validateICMP(try receive(on: peer), original: packet)
            }
            try tunnel.waitUntilReaderReady(timeout: 0.1)
            tunnel.stop()
            try rejects("stopped epoch \(epoch) retained a reader-ready ACK") {
                try tunnel.waitUntilReaderReady(timeout: 0.05)
            }
        }
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        print("PASS reader-ready: \(checks) checks, 16 descriptor generations, 128 real IPv4/ICMP round trips, queued-before-start ingress, stopped-generation rejection; \(String(format: "%.2f", elapsed))ms; AF_UNIX only")
    }

    private static func readinessStateChecks() throws {
        let readiness = NativeTunnelReaderReadiness()
        try rejects("inactive reader state acknowledged readiness") { try readiness.wait(timeout: 0) }
        let old = readiness.begin()
        try rejects("begin implied registration readiness") { try readiness.wait(timeout: 0) }
        readiness.confirm(old)
        try readiness.wait(timeout: 0)
        readiness.invalidate()
        readiness.confirm(old)
        try rejects("late ACK revived an invalidated reader") { try readiness.wait(timeout: 0) }
        let current = readiness.begin()
        readiness.confirm(old)
        try rejects("old-generation ACK made its replacement ready") { try readiness.wait(timeout: 0) }
        readiness.confirm(current)
        try readiness.wait(timeout: 0)
        for invalid in [-1.0, .infinity, -.infinity, .nan] {
            try rejects("invalid timeout was accepted") { try readiness.wait(timeout: invalid) }
        }

        _ = readiness.begin()
        let entered = DispatchSemaphore(value: 0), ended = DispatchSemaphore(value: 0)
        let cancellation = WaitProbe()
        DispatchQueue.global(qos: .userInitiated).async {
            entered.signal()
            do { try readiness.wait(timeout: 3); cancellation.record(rejected: false) }
            catch { cancellation.record(rejected: true) }
            ended.signal()
        }
        try expect(entered.wait(timeout: .now() + 1) == .success, "readiness waiter did not start")
        try expect(ended.wait(timeout: .now() + 0.04) == .timedOut,
                   "unregistered reader acknowledged a blocked waiter")
        readiness.invalidate()
        try expect(ended.wait(timeout: .now() + 0.5) == .success && cancellation.result.rejected,
                   "reader invalidation did not wake and reject the waiter")

        let broadcast = readiness.begin()
        let group = DispatchGroup(), results = WaitProbe()
        for _ in 0..<32 {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { group.leave() }
                do { try readiness.wait(timeout: 2); results.record(rejected: false) }
                catch { results.record(rejected: true) }
            }
        }
        readiness.confirm(broadcast)
        try expect(group.wait(timeout: .now() + 3) == .success && results.result.successes == 32,
                   "registration ACK failed to release all reader waiters")
        readiness.invalidate()
        print("PASS readiness state: registration required, timeout validation, cancel wakes waiter, old ACK rejection, 32 waiter broadcast")
    }

    private static func frame(identifier: UInt16) throws -> Data {
        let source: [UInt8] = [198, 18, 16, 9]
        let destination: [UInt8] = [203, 0, 113, 7]
        let payload = Data([0x68, 0x61, 0x6a, 0x69, UInt8(identifier >> 8), UInt8(identifier & 0xff)])
        var output = [UInt8](repeating: 0, count: 256)
        let count = output.withUnsafeMutableBytes { raw in
            source.withUnsafeBufferPointer { sourceBytes in
                destination.withUnsafeBufferPointer { destinationBytes in
                    payload.withUnsafeBytes { body in
                        CDataPlane.buildUDP(into: raw, version: 4,
                            source: sourceBytes.baseAddress!, sourceLength: 4,
                            sourcePort: 50_000 + identifier,
                            destinationAddress: destinationBytes.baseAddress!,
                            destinationPort: 3478, payload: body, identifier: identifier)
                    }
                }
            }
        }
        try expect(count == 28 + payload.count, "production UDP codec refused a valid frame")
        var packet = Data([0, 0, 0, UInt8(AF_INET)])
        packet.append(contentsOf: output.prefix(count))
        return packet
    }

    private static func send(_ data: Data, on descriptor: Int32) throws {
        let count = data.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress!, $0.count, 0) }
        try expect(count == data.count, "AF_UNIX packet send failed")
    }

    private static func receive(on descriptor: Int32) throws -> Data {
        var state = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        try expect(Darwin.poll(&state, 1, 2_000) == 1 && state.revents & Int16(POLLIN) != 0,
                   "reader-ready ACK did not lead to a live packet response")
        var bytes = [UInt8](repeating: 0, count: 65_540)
        let count = bytes.withUnsafeMutableBytes { Darwin.recv(descriptor, $0.baseAddress!, $0.count, 0) }
        try expect(count > 4, "AF_UNIX packet receive failed")
        return Data(bytes.prefix(count))
    }

    private static func validateICMP(_ frame: Data, original: Data) throws {
        let bytes = [UInt8](frame)
        try expect(bytes.count >= 4 + 20 + 8 + 28 && Array(bytes.prefix(4)) == [0, 0, 0, UInt8(AF_INET)],
                   "reader response has no complete IPv4 ICMP frame")
        let packet = Data(bytes.dropFirst(4))
        let headerLength = Int(packet[0] & 15) * 4
        try expect(packet[0] >> 4 == 4 && headerLength == 20 && packet[9] == 1 &&
                   ((Int(packet[2]) << 8) | Int(packet[3])) == packet.count,
                   "reader response has an invalid IPv4 envelope")
        try expect(CDataPlane.checksum(Data(packet.prefix(headerLength))) == 0,
                   "reader response has a bad IPv4 checksum")
        try expect(Array(packet[12..<16]) == [203, 0, 113, 7] &&
                   Array(packet[16..<20]) == [198, 18, 16, 9],
                   "reader response has the wrong source/destination")
        let icmp = Data(packet.dropFirst(headerLength))
        try expect(icmp[0] == 3 && icmp[1] == 3 && CDataPlane.checksum(icmp) == 0,
                   "REJECT did not produce a valid ICMP port-unreachable response")
        try expect(Data(icmp.dropFirst(8)) == Data(original.dropFirst(4).prefix(28)),
                   "reader response changed the quoted request or used a stale descriptor")
    }
}

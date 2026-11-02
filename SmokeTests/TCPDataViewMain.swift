import Foundation

private final class PacketFixture {
    let version: UInt8
    let source: [UInt8], destination: [UInt8]
    var scratch = [UInt8](repeating: 0, count: 65_600)

    init(version: UInt8) {
        self.version = version
        if version == 4 {
            source = [203, 0, 113, 7]; destination = [198, 51, 100, 9]
        } else {
            source = [0x20, 1, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [7]
            destination = [0x20, 1, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [9]
        }
    }

    func build(_ payload: Data, offset: Int, count: Int, borrowed: Bool) -> Data {
        func packet(_ body: UnsafeRawBufferPointer) -> Data {
            source.withUnsafeBufferPointer { sourceBytes in
                destination.withUnsafeBufferPointer { destinationBytes in
                    scratch.withUnsafeMutableBytes { output in
                        let size = CDataPlane.buildTCP(into: output, version: version,
                            source: sourceBytes.baseAddress!, sourceLength: source.count, sourcePort: 443,
                            destinationAddress: destinationBytes.baseAddress!, destinationPort: 49151,
                            sequence: 17, acknowledgment: 29, flags: 0x18, window: 65535,
                            payload: body, identifier: 99)
                        precondition(size > 0, "Packet codec rejected controlled fixture")
                        return Data(bytes: output.baseAddress!, count: size)
                    }
                }
            }
        }
        if borrowed {
            return CDataPlane.withBorrowedPayload(payload, offset: offset, count: count, packet)!
        }
        let start = payload.startIndex + offset
        return payload.subdata(in: start..<(start + count)).withUnsafeBytes(packet)
    }
}

@main struct TCPDataViewMain {
    static func main() {
        let backing = Data((0..<32_800).map { UInt8($0 % 251) })
        let payload = backing[16..<32_784]
        precondition(payload.startIndex != 0)
        for version: UInt8 in [4, 6] {
            let fixture = PacketFixture(version: version)
            for offset in [0, 1, 8191, 16_384] {
                for count in [0, 1, 64, 1460, 8192] {
                    let old = fixture.build(payload, offset: offset, count: count, borrowed: false)
                    let new = fixture.build(payload, offset: offset, count: count, borrowed: true)
                    precondition(old == new, "Borrowed payload changed packet bytes/checksum")
                }
            }
            for (offset, count) in [(-1, 1), (0, -1), (Int.max, 1), (1, Int.max), (payload.count + 1, 0)] {
                let result = CDataPlane.withBorrowedPayload(payload, offset: offset, count: count) { $0.count }
                precondition(result == nil, "Invalid payload range was admitted")
            }
            for count in [64, 1460, 8192] {
                for borrowed in [false, true] {
                    let started = DispatchTime.now().uptimeNanoseconds
                    var checksum: UInt64 = 0
                    for index in 0..<20_000 {
                        let offset = index % (payload.count - count)
                        let packet = fixture.build(payload, offset: offset, count: count, borrowed: borrowed)
                        checksum &+= UInt64(packet.count) + UInt64(packet.last!)
                    }
                    let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
                    precondition(checksum > 0)
                    print(String(format: "TCP payload fixture IPv%d/%d: %@, 20000 packets, %.2f ms, checksum=%llu (memory-only; not tunnel/Internet throughput)",
                                 version, count, borrowed ? "borrowed view" : "Data.subdata copy", elapsed, checksum))
                }
            }
        }
        print("Borrowed TCP payload checks passed: IPv4/IPv6, nonzero origin, relative ranges, immutable packet bytes/checksums")
    }
}

import Foundation
import HajimiDataPlaneC

/// Swift-facing wrappers over the C packet codec.
///
/// These exist so call sites read naturally while the arithmetic itself stays
/// in C, where there is no ARC, no `Data` value semantics and no bounds
/// checking on every byte.
public enum CDataPlane {
    /// The unfolded one's-complement sum of a region.
    ///
    /// Exposed separately from `checksum` so callers can add the sums of
    /// several regions and fold once, instead of concatenating the regions
    /// into a scratch buffer.
    public static func checksumSum(_ data: Data) -> UInt64 {
        data.withUnsafeBytes { raw in
            hajimi_checksum_sum(raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                               raw.count)
        }
    }

    public static func fold(_ value: UInt64) -> UInt16 {
        hajimi_checksum_fold(value)
    }

    public static func checksum(_ data: Data) -> UInt16 {
        hajimi_checksum_fold(checksumSum(data))
    }

    /// Header checksum of an IPv4 header. The checksum field does not need to
    /// be zeroed first.
    public static func ipv4HeaderChecksum(_ header: Data) -> UInt16 {
        header.withUnsafeBytes { raw in
            hajimi_ipv4_header_checksum(raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                       raw.count)
        }
    }

    /// TCP or UDP checksum, without materialising a pseudo header.
    ///
    /// - Parameters:
    ///   - source: The source address in network order, 4 or 16 bytes.
    ///   - destination: The destination address, the same length as `source`.
    ///   - protocolNumber: 6 for TCP, 17 for UDP.
    ///   - transport: The transport header and payload, with its own checksum
    ///     field already zeroed.
    public static func transportChecksum(source: Data,
                                         destination: Data,
                                         protocolNumber: UInt8,
                                         transport: Data) -> UInt16 {
        precondition(source.count == destination.count,
                     "pseudo header addresses must be the same length")
        return source.withUnsafeBytes { sourceRaw in
            destination.withUnsafeBytes { destinationRaw in
                transport.withUnsafeBytes { transportRaw in
                    hajimi_transport_checksum(
                        sourceRaw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        destinationRaw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        sourceRaw.count,
                        protocolNumber,
                        transportRaw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        transportRaw.count)
                }
            }
        }
    }

    /// Same as `transportChecksum(source:destination:protocolNumber:transport:)`
    /// but takes already-materialised address bytes so the packet builder can
    /// skip wrapping `[UInt8]` into two temporary `Data` values per segment.
    public static func transportChecksum(sourceBytes: [UInt8],
                                         destinationBytes: [UInt8],
                                         protocolNumber: UInt8,
                                         transport: Data) -> UInt16 {
        precondition(sourceBytes.count == destinationBytes.count,
                     "pseudo header addresses must be the same length")
        return sourceBytes.withUnsafeBufferPointer { sourceRaw in
            destinationBytes.withUnsafeBufferPointer { destinationRaw in
                transport.withUnsafeBytes { transportRaw in
                    hajimi_transport_checksum(
                        sourceRaw.baseAddress,
                        destinationRaw.baseAddress,
                        sourceRaw.count,
                        protocolNumber,
                        transportRaw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        transportRaw.count)
                }
            }
        }
    }

    /// Runs the C layer's own vectors.
    ///
    /// - Returns: `nil` on success, or a description of the first failing
    ///   check.
    public static func selfTestFailure() -> String? {
        let code = hajimi_dataplane_self_test()
        return code == 0 ? nil : "C data plane self test failed at check \(code)"
    }

    /// Writes a no-option TCP segment into `destination`. Returns the number
    /// of bytes written, or 0 when the packet would not fit.
    @discardableResult
    public static func buildTCP(into destination: UnsafeMutableRawBufferPointer,
                                version: UInt8,
                                source: UnsafePointer<UInt8>,
                                sourceLength: Int,
                                sourcePort: UInt16,
                                destinationAddress: UnsafePointer<UInt8>,
                                destinationPort: UInt16,
                                sequence: UInt32,
                                acknowledgment: UInt32,
                                flags: UInt8,
                                window: UInt16,
                                payload: UnsafeRawBufferPointer,
                                identifier: UInt16) -> Int {
        guard let out = destination.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return 0
        }
        let payloadBase = payload.baseAddress?.assumingMemoryBound(to: UInt8.self)
        if version == 6 {
            guard sourceLength == 16 else { return 0 }
            return Int(hajimi_build_ipv6_tcp(out, destination.count,
                                            source, sourcePort,
                                            destinationAddress, destinationPort,
                                            sequence, acknowledgment, flags, window,
                                            payloadBase, payload.count))
        }
        guard sourceLength == 4 else { return 0 }
        return Int(hajimi_build_ipv4_tcp(out, destination.count,
                                        source, sourcePort,
                                        destinationAddress, destinationPort,
                                        sequence, acknowledgment, flags, window,
                                        payloadBase, payload.count, identifier))
    }

    @discardableResult
    public static func buildUDP(into destination: UnsafeMutableRawBufferPointer,
                                version: UInt8,
                                source: UnsafePointer<UInt8>,
                                sourceLength: Int,
                                sourcePort: UInt16,
                                destinationAddress: UnsafePointer<UInt8>,
                                destinationPort: UInt16,
                                payload: UnsafeRawBufferPointer,
                                identifier: UInt16) -> Int {
        guard let out = destination.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return 0
        }
        let payloadBase = payload.baseAddress?.assumingMemoryBound(to: UInt8.self)
        if version == 6 {
            guard sourceLength == 16 else { return 0 }
            return Int(hajimi_build_ipv6_udp(out, destination.count,
                                            source, sourcePort,
                                            destinationAddress, destinationPort,
                                            payloadBase, payload.count))
        }
        guard sourceLength == 4 else { return 0 }
        return Int(hajimi_build_ipv4_udp(out, destination.count,
                                        source, sourcePort,
                                        destinationAddress, destinationPort,
                                        payloadBase, payload.count, identifier))
    }
}

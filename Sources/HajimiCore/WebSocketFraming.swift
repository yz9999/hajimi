import Foundation
#if canImport(HajimiProtocolCXX)
import HajimiProtocolCXX
#endif

/// Wire framing shared by the production WebSocket transport and its isolated
/// memory fixtures. Random masks are supplied by the transport's secure RNG.
enum WebSocketFraming {
    static func encode(_ data: Data, opcode: UInt8 = 0x2, mask: Data) -> Data {
        precondition(mask.count == 4)
        let maskOffset = data.count < 126 ? 2 : (data.count <= Int(UInt16.max) ? 4 : 10)
        let payloadOffset = maskOffset + 4
        var frame = Data(count: payloadOffset + data.count)
        #if canImport(HajimiProtocolCXX)
        let written = frame.withUnsafeMutableBytes { output -> Int in
            guard let outBase = output.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return mask.withUnsafeBytes { maskRaw -> Int in
                guard let maskBase = maskRaw.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return data.withUnsafeBytes { payloadRaw -> Int in
                    let payloadBase = payloadRaw.bindMemory(to: UInt8.self).baseAddress
                    let res = hajimi_ws_encode_frame(
                        1, opcode, 1, maskBase,
                        payloadBase, payloadRaw.count,
                        outBase, output.count
                    )
                    return res.status == HAJIMI_CODEC_OK ? res.written : 0
                }
            }
        }
        if written == frame.count {
            return frame
        }
        #endif
        frame.withUnsafeMutableBytes { (output: UnsafeMutableRawBufferPointer) in
            output[0] = 0x80 | opcode
            if maskOffset == 2 {
                output[1] = 0x80 | UInt8(data.count)
            } else if maskOffset == 4 {
                output[1] = 0xfe
                output[2] = UInt8(data.count >> 8)
                output[3] = UInt8(truncatingIfNeeded: data.count)
            } else {
                output[1] = 0xff
                for index in 0..<8 {
                    output[index + 2] = UInt8(truncatingIfNeeded: UInt64(data.count) >> UInt64(56 - index * 8))
                }
            }
            mask.withUnsafeBytes { key in
                for index in 0..<4 { output[maskOffset + index] = key[index] }
                data.withUnsafeBytes { input in
                    xor(input, into: UnsafeMutableRawBufferPointer(rebasing: output[payloadOffset...]), mask: key)
                }
            }
        }
        return frame
    }

    static func payload(_ value: Data, masked: Bool) -> Data {
        // Explicitly copy even unmasked input: callers may supply Data backed
        // by mutable, externally owned memory. The returned frame owns bytes.
        if !masked {
            return value.withUnsafeBytes { input in
                guard let base = input.baseAddress else { return Data() }
                return Data(bytes: base, count: input.count)
            }
        }
        precondition(value.count >= 4)
        var payload = Data(count: value.count - 4)
        #if canImport(HajimiProtocolCXX)
        value.withUnsafeBytes { input in
            guard let inBase = input.bindMemory(to: UInt8.self).baseAddress else { return }
            payload.withUnsafeMutableBytes { output in
                guard let outBase = output.bindMemory(to: UInt8.self).baseAddress else { return }
                let count = input.count - 4
                if count > 0 {
                    outBase.initialize(from: inBase.advanced(by: 4), count: count)
                    hajimi_ws_xor_mask(outBase, count, inBase)
                }
            }
        }
        return payload
        #else
        value.withUnsafeBytes { input in
            payload.withUnsafeMutableBytes { output in
                xor(UnsafeRawBufferPointer(rebasing: input[4...]), into: output,
                    mask: UnsafeRawBufferPointer(rebasing: input[..<4]))
            }
        }
        return payload
        #endif
    }

    private static func xor(_ input: UnsafeRawBufferPointer, into output: UnsafeMutableRawBufferPointer,
                            mask: UnsafeRawBufferPointer) {
        guard !input.isEmpty else { return }
        let key = UInt64(mask.loadUnaligned(as: UInt32.self))
        let repeated = key | (key << 32)
        var index = 0
        while input.count - index >= 8 {
            var word = input.loadUnaligned(fromByteOffset: index, as: UInt64.self) ^ repeated
            withUnsafeBytes(of: &word) { bytes in
                output.baseAddress!.advanced(by: index).copyMemory(from: bytes.baseAddress!, byteCount: 8)
            }
            index += 8
        }
        while index < input.count {
            output[index] = input[index] ^ mask[index & 3]
            index += 1
        }
    }
}

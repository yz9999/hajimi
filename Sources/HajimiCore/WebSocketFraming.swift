import Foundation
#if canImport(HajimiProtocolCXX)
import HajimiProtocolCXX
#endif

/// Wire framing shared by the production WebSocket transport and its isolated
/// memory fixtures. Random client masks are generated in userspace without syscalls.
enum WebSocketFraming {
    static func encode(_ data: Data, opcode: UInt8 = 0x2) -> Data {
        var rng = SystemRandomNumberGenerator()
        let maskKey = UInt32(truncatingIfNeeded: rng.next() as UInt64)
        return encode(data, opcode: opcode, maskKey: maskKey)
    }

    static func encode(_ data: Data, opcode: UInt8 = 0x2, mask: Data) -> Data {
        precondition(mask.count == 4)
        let maskKey = mask.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        return encode(data, opcode: opcode, maskKey: maskKey)
    }

    static func encode(_ data: Data, opcode: UInt8 = 0x2, maskKey: UInt32) -> Data {
        let dataCount = data.count
        let maskOffset = dataCount < 126 ? 2 : (dataCount <= Int(UInt16.max) ? 4 : 10)
        let payloadOffset = maskOffset + 4
        var frame = Data(count: payloadOffset + dataCount)
        #if canImport(HajimiProtocolCXX)
        var rawKey = maskKey
        let written = frame.withUnsafeMutableBytes { output -> Int in
            guard let outBase = output.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return withUnsafeBytes(of: &rawKey) { maskRaw -> Int in
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
                output[1] = 0x80 | UInt8(dataCount)
            } else if maskOffset == 4 {
                output[1] = 0xfe
                output[2] = UInt8(dataCount >> 8)
                output[3] = UInt8(truncatingIfNeeded: dataCount)
            } else {
                output[1] = 0xff
                let bigLen = UInt64(dataCount).bigEndian
                output.storeBytes(of: bigLen, toByteOffset: 2, as: UInt64.self)
            }
            output.storeBytes(of: maskKey, toByteOffset: maskOffset, as: UInt32.self)
            if dataCount > 0 {
                data.withUnsafeBytes { input in
                    xor(input,
                        into: UnsafeMutableRawBufferPointer(rebasing: output[payloadOffset...]),
                        maskKey: maskKey)
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
            let key = input.loadUnaligned(as: UInt32.self)
            payload.withUnsafeMutableBytes { output in
                xor(UnsafeRawBufferPointer(rebasing: input[4...]), into: output, maskKey: key)
            }
        }
        return payload
        #endif
    }

    @inline(__always)
    private static func xor(_ input: UnsafeRawBufferPointer, into output: UnsafeMutableRawBufferPointer,
                            maskKey: UInt32) {
        let count = input.count
        guard count > 0 else { return }
        let key64 = UInt64(maskKey)
        let repeated = key64 | (key64 << 32)
        var index = 0
        while count - index >= 32 {
            let w0 = input.loadUnaligned(fromByteOffset: index, as: UInt64.self) ^ repeated
            let w1 = input.loadUnaligned(fromByteOffset: index + 8, as: UInt64.self) ^ repeated
            let w2 = input.loadUnaligned(fromByteOffset: index + 16, as: UInt64.self) ^ repeated
            let w3 = input.loadUnaligned(fromByteOffset: index + 24, as: UInt64.self) ^ repeated
            output.storeBytes(of: w0, toByteOffset: index, as: UInt64.self)
            output.storeBytes(of: w1, toByteOffset: index + 8, as: UInt64.self)
            output.storeBytes(of: w2, toByteOffset: index + 16, as: UInt64.self)
            output.storeBytes(of: w3, toByteOffset: index + 24, as: UInt64.self)
            index += 32
        }
        while count - index >= 8 {
            let word = input.loadUnaligned(fromByteOffset: index, as: UInt64.self) ^ repeated
            output.storeBytes(of: word, toByteOffset: index, as: UInt64.self)
            index += 8
        }
        if index < count {
            var rawKey = maskKey
            withUnsafeBytes(of: &rawKey) { maskBytes in
                while index < count {
                    output[index] = input[index] ^ maskBytes[index & 3]
                    index += 1
                }
            }
        }
    }
}

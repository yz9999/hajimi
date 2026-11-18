import Foundation

// Generated from RFC 7541 Appendix B: the canonical HPACK Huffman code.
// 256 symbols plus EOS; EOS may only appear as trailing padding.
let hpackHuffmanCodes: [(code: UInt32, bits: Int)] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
]

/// The canonical Huffman code HPACK uses for string literals (RFC 7541 Appendix B & §5.2).
enum Huffman {
    /// Packed `(bits << 32) | code` lookup table for fast register-only encoding.
    private static let encodeTable: ContiguousArray<UInt64> = {
        var table = ContiguousArray<UInt64>()
        table.reserveCapacity(256)
        for index in 0..<256 {
            let entry = hpackHuffmanCodes[index]
            table.append((UInt64(entry.bits) << 32) | UInt64(entry.code))
        }
        return table
    }()

    /// Static 4-bit nibble DFA transition table (`256 internal states * 16 nibbles = 4,096 UInt32s`).
    ///
    /// Because the shortest codeword in RFC 7541 Appendix B is 5 bits, stepping 4 bits
    /// from any internal trie state can emit at most one octet.
    ///
    /// Bit layout of each `UInt32` entry:
    /// - Bit 31 (`0x8000_0000`): `FAIL` (invalid prefix or EOS symbol 256 decoded)
    /// - Bit 30 (`0x4000_0000`): `EMIT` (symbol in bits 16..23 was decoded)
    /// - Bit 29 (`0x2000_0000`): `ACCEPT` (target state is valid end-of-stream padding: `< 8` all-1 bits)
    /// - Bits 16..23: emitted `UInt8` symbol
    /// - Bits 0..15: next internal state index (`0..<256`)
    private static let dfaTable: ContiguousArray<UInt32> = {
        struct TrieNode {
            var child0: Int = -1
            var child1: Int = -1
            var symbol: Int = -1
            var code: UInt32 = 0
            var bits: Int = 0
        }

        var nodes: [TrieNode] = [TrieNode()]
        nodes.reserveCapacity(513)

        for (symbol, entry) in hpackHuffmanCodes.enumerated() {
            var cur = 0
            for shift in stride(from: entry.bits - 1, through: 0, by: -1) {
                let bit = Int((entry.code >> UInt32(shift)) & 1)
                var next = (bit == 0) ? nodes[cur].child0 : nodes[cur].child1
                if next < 0 {
                    next = nodes.count
                    var child = TrieNode()
                    child.code = (nodes[cur].code << 1) | UInt32(bit)
                    child.bits = nodes[cur].bits + 1
                    nodes.append(child)
                    if bit == 0 {
                        nodes[cur].child0 = next
                    } else {
                        nodes[cur].child1 = next
                    }
                }
                cur = next
            }
            nodes[cur].symbol = symbol
        }

        var stateToTrie: [Int] = []
        stateToTrie.reserveCapacity(256)
        var trieToState = [Int](repeating: -1, count: nodes.count)
        for (idx, node) in nodes.enumerated() where node.symbol < 0 {
            trieToState[idx] = stateToTrie.count
            stateToTrie.append(idx)
        }

        var table = ContiguousArray<UInt32>(repeating: 0x8000_0000, count: stateToTrie.count * 16)
        for state in 0..<stateToTrie.count {
            for nibble in 0..<16 {
                var curTrie = stateToTrie[state]
                var failed = false
                var emitted = false
                var emittedSymbol: UInt32 = 0

                for shift in stride(from: 3, through: 0, by: -1) {
                    let bit = (nibble >> shift) & 1
                    let nextTrie = (bit == 0) ? nodes[curTrie].child0 : nodes[curTrie].child1
                    if nextTrie < 0 {
                        failed = true
                        break
                    }
                    let sym = nodes[nextTrie].symbol
                    if sym >= 0 {
                        // RFC 7541 §5.2: EOS (256) MUST NOT appear as a literal symbol.
                        if sym >= 256 {
                            failed = true
                            break
                        }
                        emitted = true
                        emittedSymbol = UInt32(sym)
                        curTrie = 0
                    } else {
                        curTrie = nextTrie
                    }
                }

                if !failed {
                    let nextState = trieToState[curTrie]
                    let endNode = nodes[curTrie]
                    // RFC 7541 §5.2: Trailing padding MUST be <= 7 bits and all-ones (EOS prefix).
                    let accept = endNode.bits < 8 && endNode.code == ((UInt32(1) << UInt32(endNode.bits)) - 1)
                    var packed = UInt32(nextState)
                    if emitted {
                        packed |= 0x4000_0000 | (emittedSymbol << 16)
                    }
                    if accept {
                        packed |= 0x2000_0000
                    }
                    table[(state << 4) | nibble] = packed
                }
            }
        }
        return table
    }()

    /// Computes the exact Huffman-encoded byte length without allocating output storage.
    @inline(__always)
    static func encodedByteLength<S: Sequence>(_ bytes: S) -> Int where S.Element == UInt8 {
        var totalBits = 0
        encodeTable.withUnsafeBufferPointer { tbl in
            let base = tbl.baseAddress!
            for byte in bytes {
                totalBits &+= Int(base[Int(byte)] >> 32)
            }
        }
        return (totalBits &+ 7) >> 3
    }

    static func encode(_ data: Data) -> Data {
        guard !data.isEmpty else { return Data() }
        return data.withUnsafeBytes { raw in
            encode(raw)
        }
    }

    static func encode(_ raw: UnsafeRawBufferPointer) -> Data {
        let inCount = raw.count
        guard inCount > 0, let inPtr = raw.bindMemory(to: UInt8.self).baseAddress else {
            return Data()
        }
        let outLen = encodedByteLength(UnsafeBufferPointer(start: inPtr, count: inCount))
        var out = Data(count: outLen)
        encodeTable.withUnsafeBufferPointer { tbl in
            let codeTbl = tbl.baseAddress!
            out.withUnsafeMutableBytes { outRaw in
                guard let outPtr = outRaw.bindMemory(to: UInt8.self).baseAddress else { return }
                var accumulator: UInt64 = 0
                var bits = 0
                var outPos = 0
                for i in 0..<inCount {
                    let packed = codeTbl[Int(inPtr[i])]
                    let entryBits = Int(packed >> 32)
                    let entryCode = packed & 0xFFFF_FFFF
                    accumulator = (accumulator << UInt64(entryBits)) | entryCode
                    bits += entryBits
                    while bits >= 8 {
                        bits -= 8
                        outPtr[outPos] = UInt8(truncatingIfNeeded: accumulator >> UInt64(bits))
                        outPos += 1
                    }
                }
                if bits > 0 {
                    // RFC 7541 §5.2: pad trailing bits with all-ones EOS MSBs.
                    let pad = 8 - bits
                    accumulator = (accumulator << UInt64(pad)) | ((UInt64(1) << UInt64(pad)) - 1)
                    outPtr[outPos] = UInt8(truncatingIfNeeded: accumulator)
                }
            }
        }
        return out
    }

    static func encode(_ string: String) -> Data {
        var s = string
        return s.withUTF8 { utf8 in
            encode(UnsafeRawBufferPointer(utf8))
        }
    }

    static func decode(_ data: Data) throws -> Data {
        guard !data.isEmpty else { return Data() }
        return try data.withUnsafeBytes { raw in
            try decode(raw)
        }
    }

    static func decode(_ raw: UnsafeRawBufferPointer) throws -> Data {
        let inCount = raw.count
        guard inCount > 0, let inPtr = raw.bindMemory(to: UInt8.self).baseAddress else {
            return Data()
        }
        let maxOut = (inCount * 8) / 5 + 1
        var out = Data(count: maxOut)
        let decodedCount: Int = dfaTable.withUnsafeBufferPointer { tablePtr in
            let tbl = tablePtr.baseAddress!
            return out.withUnsafeMutableBytes { outRaw -> Int in
                let outPtr = outRaw.bindMemory(to: UInt8.self).baseAddress!
                var state = 0
                var outPos = 0
                var lastEntry: UInt32 = 0x2000_0000
                for i in 0..<inCount {
                    let byte = inPtr[i]
                    let e1 = tbl[(state << 4) | Int(byte >> 4)]
                    if (e1 & 0x8000_0000) != 0 { return -1 }
                    if (e1 & 0x4000_0000) != 0 {
                        outPtr[outPos] = UInt8(truncatingIfNeeded: e1 >> 16)
                        outPos += 1
                    }
                    state = Int(e1 & 0xFFFF)

                    let e2 = tbl[(state << 4) | Int(byte & 0x0F)]
                    if (e2 & 0x8000_0000) != 0 { return -1 }
                    if (e2 & 0x4000_0000) != 0 {
                        outPtr[outPos] = UInt8(truncatingIfNeeded: e2 >> 16)
                        outPos += 1
                    }
                    state = Int(e2 & 0xFFFF)
                    lastEntry = e2
                }
                if (lastEntry & 0x2000_0000) == 0 { return -1 }
                return outPos
            }
        }
        guard decodedCount >= 0 else {
            throw HPACK.DecodeError.invalidHuffman
        }
        if decodedCount < maxOut {
            out.removeSubrange(decodedCount..<maxOut)
        }
        return out
    }
}

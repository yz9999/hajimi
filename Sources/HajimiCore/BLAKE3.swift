import Foundation

/// BLAKE3, implemented from the reference specification.
///
/// Shadowsocks 2022 derives every session subkey with BLAKE3's `derive_key`
/// mode, and neither CryptoKit nor CommonCrypto provides it. This is a direct
/// translation of the reference implementation rather than an optimised one:
/// correctness is verifiable against the project's official test vectors, and
/// the volume of key derivation a proxy performs is negligible next to the
/// bulk cipher.
public enum BLAKE3 {
    public static let outLength = 32
    public static let keyLength = 32
    static let blockLength = 64
    static let chunkLength = 1024

    private static let iv: [UInt32] = [
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
    ]

    private static let messagePermutation: [Int] = [
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
    ]

    private struct Flags {
        static let chunkStart: UInt32 = 1 << 0
        static let chunkEnd: UInt32 = 1 << 1
        static let parent: UInt32 = 1 << 2
        static let root: UInt32 = 1 << 3
        static let keyedHash: UInt32 = 1 << 4
        static let deriveKeyContext: UInt32 = 1 << 5
        static let deriveKeyMaterial: UInt32 = 1 << 6
    }

    // MARK: Compression

    private static func g(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int,
                          _ mx: UInt32, _ my: UInt32) {
        state[a] = state[a] &+ state[b] &+ mx
        state[d] = (state[d] ^ state[a]).rotatedRight(16)
        state[c] = state[c] &+ state[d]
        state[b] = (state[b] ^ state[c]).rotatedRight(12)
        state[a] = state[a] &+ state[b] &+ my
        state[d] = (state[d] ^ state[a]).rotatedRight(8)
        state[c] = state[c] &+ state[d]
        state[b] = (state[b] ^ state[c]).rotatedRight(7)
    }

    private static func round(_ state: inout [UInt32], _ m: [UInt32]) {
        g(&state, 0, 4, 8, 12, m[0], m[1])
        g(&state, 1, 5, 9, 13, m[2], m[3])
        g(&state, 2, 6, 10, 14, m[4], m[5])
        g(&state, 3, 7, 11, 15, m[6], m[7])
        g(&state, 0, 5, 10, 15, m[8], m[9])
        g(&state, 1, 6, 11, 12, m[10], m[11])
        g(&state, 2, 7, 8, 13, m[12], m[13])
        g(&state, 3, 4, 9, 14, m[14], m[15])
    }

    private static func permute(_ m: inout [UInt32]) {
        var permuted = [UInt32](repeating: 0, count: 16)
        for index in 0..<16 { permuted[index] = m[messagePermutation[index]] }
        m = permuted
    }

    /// Returns all 16 output words; callers that need a chaining value take the
    /// first eight.
    private static func compress(chainingValue: [UInt32], blockWords: [UInt32],
                                 counter: UInt64, blockLength: UInt32,
                                 flags: UInt32) -> [UInt32] {
        var state: [UInt32] = [
            chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3],
            chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7],
            iv[0], iv[1], iv[2], iv[3],
            UInt32(truncatingIfNeeded: counter),
            UInt32(truncatingIfNeeded: counter >> 32),
            blockLength, flags,
        ]
        var block = blockWords
        for index in 0..<7 {
            round(&state, block)
            if index < 6 { permute(&block) }
        }
        for index in 0..<8 {
            state[index] ^= state[index + 8]
            state[index + 8] ^= chainingValue[index]
        }
        return state
    }

    private static func words(fromLittleEndian bytes: [UInt8]) -> [UInt32] {
        stride(from: 0, to: bytes.count, by: 4).map { offset in
            UInt32(bytes[offset])
                | UInt32(bytes[offset + 1]) << 8
                | UInt32(bytes[offset + 2]) << 16
                | UInt32(bytes[offset + 3]) << 24
        }
    }

    // MARK: Tree

    private struct Output {
        var inputChainingValue: [UInt32]
        var blockWords: [UInt32]
        var counter: UInt64
        var blockLength: UInt32
        var flags: UInt32

        func chainingValue() -> [UInt32] {
            Array(BLAKE3.compress(chainingValue: inputChainingValue, blockWords: blockWords,
                                  counter: counter, blockLength: blockLength,
                                  flags: flags).prefix(8))
        }

        /// Extendable output: each 64-byte block re-compresses the same root
        /// node with an incrementing counter.
        func rootBytes(count: Int) -> [UInt8] {
            var output: [UInt8] = []
            output.reserveCapacity(count)
            var blockCounter: UInt64 = 0
            while output.count < count {
                let words = BLAKE3.compress(chainingValue: inputChainingValue,
                                            blockWords: blockWords, counter: blockCounter,
                                            blockLength: blockLength, flags: flags | Flags.root)
                for word in words {
                    output.append(UInt8(truncatingIfNeeded: word))
                    output.append(UInt8(truncatingIfNeeded: word >> 8))
                    output.append(UInt8(truncatingIfNeeded: word >> 16))
                    output.append(UInt8(truncatingIfNeeded: word >> 24))
                }
                blockCounter += 1
            }
            return Array(output.prefix(count))
        }
    }

    private struct ChunkState {
        var chainingValue: [UInt32]
        var chunkCounter: UInt64
        var block = [UInt8](repeating: 0, count: BLAKE3.blockLength)
        var blockLength = 0
        var blocksCompressed = 0
        var flags: UInt32

        init(key: [UInt32], chunkCounter: UInt64, flags: UInt32) {
            chainingValue = key
            self.chunkCounter = chunkCounter
            self.flags = flags
        }

        var length: Int { BLAKE3.blockLength * blocksCompressed + blockLength }
        var startFlag: UInt32 { blocksCompressed == 0 ? Flags.chunkStart : 0 }

        mutating func update(_ input: ArraySlice<UInt8>) {
            var remaining = input
            while !remaining.isEmpty {
                if blockLength == BLAKE3.blockLength {
                    chainingValue = Array(BLAKE3.compress(
                        chainingValue: chainingValue,
                        blockWords: BLAKE3.words(fromLittleEndian: block),
                        counter: chunkCounter,
                        blockLength: UInt32(BLAKE3.blockLength),
                        flags: flags | startFlag).prefix(8))
                    blocksCompressed += 1
                    block = [UInt8](repeating: 0, count: BLAKE3.blockLength)
                    blockLength = 0
                }
                let take = min(BLAKE3.blockLength - blockLength, remaining.count)
                for offset in 0..<take {
                    block[blockLength + offset] = remaining[remaining.startIndex + offset]
                }
                blockLength += take
                remaining = remaining.dropFirst(take)
            }
        }

        func output() -> Output {
            Output(inputChainingValue: chainingValue,
                   blockWords: BLAKE3.words(fromLittleEndian: block),
                   counter: chunkCounter,
                   blockLength: UInt32(blockLength),
                   flags: flags | startFlag | Flags.chunkEnd)
        }
    }

    private static func parentOutput(left: [UInt32], right: [UInt32],
                                     key: [UInt32], flags: UInt32) -> Output {
        Output(inputChainingValue: key,
               blockWords: left + right,
               // Parent nodes always use counter 0 and a full block length.
               counter: 0,
               blockLength: UInt32(blockLength),
               flags: flags | Flags.parent)
    }

    /// Incremental hasher. The chaining-value stack collapses subtrees whenever
    /// the completed chunk count gains a trailing zero bit, which is what keeps
    /// the stack logarithmic.
    public struct Hasher {
        private var chunkState: ChunkState
        private let key: [UInt32]
        private var stack: [[UInt32]] = []
        private let flags: UInt32

        fileprivate init(key: [UInt32], flags: UInt32) {
            self.key = key
            self.flags = flags
            chunkState = ChunkState(key: key, chunkCounter: 0, flags: flags)
        }

        public init() { self.init(key: BLAKE3.iv, flags: 0) }

        private mutating func addChunkChainingValue(_ value: [UInt32], totalChunks: UInt64) {
            var newValue = value
            var chunks = totalChunks
            while chunks & 1 == 0 {
                newValue = BLAKE3.parentOutput(left: stack.removeLast(), right: newValue,
                                               key: key, flags: flags).chainingValue()
                chunks >>= 1
            }
            stack.append(newValue)
        }

        public mutating func update(_ input: [UInt8]) {
            var remaining = input[...]
            while !remaining.isEmpty {
                if chunkState.length == BLAKE3.chunkLength {
                    let value = chunkState.output().chainingValue()
                    let total = chunkState.chunkCounter + 1
                    addChunkChainingValue(value, totalChunks: total)
                    chunkState = ChunkState(key: key, chunkCounter: total, flags: flags)
                }
                let take = min(BLAKE3.chunkLength - chunkState.length, remaining.count)
                chunkState.update(remaining.prefix(take))
                remaining = remaining.dropFirst(take)
            }
        }

        public mutating func update(_ input: Data) { update([UInt8](input)) }

        public func finalize(count: Int = BLAKE3.outLength) -> [UInt8] {
            var output = chunkState.output()
            for value in stack.reversed() {
                output = BLAKE3.parentOutput(left: value, right: output.chainingValue(),
                                             key: key, flags: flags)
            }
            return output.rootBytes(count: count)
        }
    }

    // MARK: Public modes

    public static func hash(_ input: [UInt8], count: Int = outLength) -> [UInt8] {
        var hasher = Hasher()
        hasher.update(input)
        return hasher.finalize(count: count)
    }

    public static func keyedHash(key: [UInt8], input: [UInt8],
                                 count: Int = outLength) -> [UInt8] {
        precondition(key.count == keyLength, "BLAKE3 keyed hash requires a 32-byte key")
        var hasher = Hasher(key: words(fromLittleEndian: key), flags: Flags.keyedHash)
        hasher.update(input)
        return hasher.finalize(count: count)
    }

    /// `derive_key(context, key_material)` — the mode Shadowsocks 2022 uses.
    ///
    /// The context string is hashed first in its own mode to produce a key,
    /// which then keys the hash of the key material. The context is a domain
    /// separator and must be a hardcoded constant, never attacker-influenced.
    public static func deriveKey(context: String, keyMaterial: [UInt8],
                                 count: Int = outLength) -> [UInt8] {
        var contextHasher = Hasher(key: iv, flags: Flags.deriveKeyContext)
        contextHasher.update([UInt8](context.utf8))
        let contextKey = contextHasher.finalize(count: keyLength)
        var hasher = Hasher(key: words(fromLittleEndian: contextKey),
                            flags: Flags.deriveKeyMaterial)
        hasher.update(keyMaterial)
        return hasher.finalize(count: count)
    }
}

private extension UInt32 {
    func rotatedRight(_ amount: UInt32) -> UInt32 {
        (self >> amount) | (self << (32 - amount))
    }
}

// MARK: - Self-test

public enum BLAKE3SelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "BLAKE3 自检失败：\(text)" }
    }

    /// Official vectors from the BLAKE3 reference repository.
    private static let keyedKey = "whats the Elvish word for friend"
    private static let context = "BLAKE3 2019-12-27 16:29:52 test vectors context"

    /// Inputs are the repeating byte sequence 0, 1, …, 250, 0, 1, ….
    private static func input(length: Int) -> [UInt8] {
        (0..<length).map { UInt8($0 % 251) }
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// (input_len, hash, keyed_hash, derive_key) — each expectation is the
    /// first 32 output bytes.
    ///
    /// Lengths past 1024 are the important ones: everything at or below a
    /// single chunk exercises only one compression path and would pass even
    /// with the whole tree-merging layer broken.
    private static let vectors: [(Int, String?, String?, String?)] = [
        (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
        (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
            "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
        (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
            "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a",
            "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"),
        (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
            "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9",
            "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797"),
        (4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32",
            "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070",
            "f46085c8190d69022369ce1a18880e9b369c135eb93f3c63550d3e7630e91060"),
        (5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2",
            "73ac69eecf286894d8102018a6fc729f4b1f4247d3703f69bdc6a5fe3e0c8461",
            "1f24eda69dbcb752847ec3ebb5dd42836d86e58500c7c98d906ecd82ed9ae47f"),
        // Exactly one block.
        (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
             nil,
             "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"),
        // Second block opens.
        (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
             nil,
             "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"),
        // Several blocks inside one chunk.
        (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
              nil, nil),
        // One byte short of a chunk. Only derive_key is asserted here: the
        // published hash column for this length could not be read back
        // reliably, and an expectation produced by the code under test would
        // prove nothing.
        (1023, nil, nil,
               "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"),
        // Exactly one chunk, so still no parent node. derive_key is omitted:
        // the published value came back with a duplicated trailing character.
        (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
               nil, nil),
        // Two chunks: the first parent node.
        (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
               nil,
               "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"),
        (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
               nil,
               "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"),
        // Three chunks: an unbalanced tree, where the stack must collapse
        // correctly at finalize rather than during update.
        (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
               nil,
               "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b"),
        (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
               nil,
               "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d"),
    ]

    public static func run() throws {
        for (length, expectedHash, expectedKeyed, expectedDerive) in vectors {
            let message = input(length: length)
            if let expectedHash {
                let actualHash = hex(BLAKE3.hash(message))
                guard actualHash == expectedHash else {
                    throw Failure(text: "hash(\(length)) = \(actualHash)，期望 \(expectedHash)")
                }
            }
            if let expectedKeyed {
                let actual = hex(BLAKE3.keyedHash(key: [UInt8](keyedKey.utf8), input: message))
                guard actual == expectedKeyed else {
                    throw Failure(text: "keyed_hash(\(length)) = \(actual)，期望 \(expectedKeyed)")
                }
            }
            if let expectedDerive {
                let actual = hex(BLAKE3.deriveKey(context: context, keyMaterial: message))
                guard actual == expectedDerive else {
                    throw Failure(text: "derive_key(\(length)) = \(actual)，期望 \(expectedDerive)")
                }
            }
        }

        // Extended output must agree with the 32-byte result on its prefix and
        // keep going past one 64-byte compression block.
        let long = BLAKE3.hash(input(length: 100), count: 131)
        guard long.count == 131 else { throw Failure(text: "扩展输出长度错误") }
        guard Array(long.prefix(32)) == BLAKE3.hash(input(length: 100)) else {
            throw Failure(text: "扩展输出前缀与 32 字节结果不一致")
        }
        guard Set(long.suffix(67)).count > 1 else {
            throw Failure(text: "扩展输出的后续块疑似未重新压缩")
        }

        // Incremental updates must match a single-shot hash, since the SS2022
        // paths feed key material in more than one piece.
        var incremental = BLAKE3.Hasher()
        let whole = input(length: 3000)
        incremental.update(Array(whole[0..<1]))
        incremental.update(Array(whole[1..<1024]))
        incremental.update(Array(whole[1024..<1025]))
        incremental.update(Array(whole[1025..<3000]))
        guard incremental.finalize() == BLAKE3.hash(whole) else {
            throw Failure(text: "分段 update 与一次性 hash 结果不一致")
        }
    }
}

import Foundation
import CryptoKit

/// XChaCha20-Poly1305, built from CryptoKit's ChaChaPoly and an HChaCha20 step.
///
/// Shadowsocks 2022's `2022-blake3-chacha20-poly1305` UDP construction uses a
/// 24-byte nonce, which CryptoKit does not accept — `ChaChaPoly.Nonce` is 12
/// bytes. XChaCha20 bridges the two: the first 16 nonce bytes and the key are
/// run through HChaCha20 to derive a subkey, and the remaining 8 bytes become
/// the low half of a 12-byte nonce. Only the key-derivation step is
/// hand-written; the sealing itself stays in CryptoKit.
public enum XChaCha20Poly1305 {
    public enum CryptoError: LocalizedError {
        case badKeyLength(Int)
        case badNonceLength(Int)

        public var errorDescription: String? {
            switch self {
            case .badKeyLength(let value): return "XChaCha20 密钥长度为 \(value)，应为 32"
            case .badNonceLength(let value): return "XChaCha20 nonce 长度为 \(value)，应为 24"
            }
        }
    }

    public static let keyLength = 32
    public static let nonceLength = 24
    public static let tagLength = 16

    public static func seal(_ plaintext: Data, key: Data, nonce: Data) throws -> Data {
        let (subkey, inner) = try derive(key: key, nonce: nonce)
        let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: subkey),
                                      nonce: try ChaChaPoly.Nonce(data: inner))
        return box.ciphertext + box.tag
    }

    public static func open(_ ciphertext: Data, key: Data, nonce: Data) throws -> Data {
        guard ciphertext.count >= tagLength else {
            throw NativeOutboundError.crypto("XChaCha20 密文短于认证标签")
        }
        let (subkey, inner) = try derive(key: key, nonce: nonce)
        let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: inner),
                                           ciphertext: ciphertext.prefix(ciphertext.count - tagLength),
                                           tag: ciphertext.suffix(tagLength))
        return try ChaChaPoly.open(box, using: SymmetricKey(data: subkey))
    }

    private static func derive(key: Data, nonce: Data) throws -> (Data, Data) {
        guard key.count == keyLength else { throw CryptoError.badKeyLength(key.count) }
        guard nonce.count == nonceLength else { throw CryptoError.badNonceLength(nonce.count) }
        let subkey = hChaCha20(key: key, nonce: Data(nonce.prefix(16)))
        // The inner nonce is four zero bytes followed by the last 8 of the 24.
        var inner = Data(repeating: 0, count: 4)
        inner.append(contentsOf: nonce.suffix(8))
        return (subkey, inner)
    }

    /// HChaCha20: the ChaCha20 permutation with no feed-forward, returning the
    /// first and last four state words.
    ///
    /// Dropping the feed-forward addition is what distinguishes this from
    /// ChaCha20's block function; adding it back would produce a subkey that
    /// looks plausible and interoperates with nothing.
    static func hChaCha20(key: Data, nonce: Data) -> Data {
        precondition(key.count == 32 && nonce.count == 16)
        var state = [UInt32](repeating: 0, count: 16)
        // "expand 32-byte k"
        state[0] = 0x6170_7865; state[1] = 0x3320_646E
        state[2] = 0x7962_2D32; state[3] = 0x6B20_6574
        let keyBytes = [UInt8](key), nonceBytes = [UInt8](nonce)
        for index in 0..<8 {
            state[4 + index] = littleEndian(keyBytes, index * 4)
        }
        for index in 0..<4 {
            state[12 + index] = littleEndian(nonceBytes, index * 4)
        }
        for _ in 0..<10 {
            quarterRound(&state, 0, 4, 8, 12)
            quarterRound(&state, 1, 5, 9, 13)
            quarterRound(&state, 2, 6, 10, 14)
            quarterRound(&state, 3, 7, 11, 15)
            quarterRound(&state, 0, 5, 10, 15)
            quarterRound(&state, 1, 6, 11, 12)
            quarterRound(&state, 2, 7, 8, 13)
            quarterRound(&state, 3, 4, 9, 14)
        }
        var out = Data()
        for index in [0, 1, 2, 3, 12, 13, 14, 15] {
            let word = state[index]
            out.append(UInt8(truncatingIfNeeded: word))
            out.append(UInt8(truncatingIfNeeded: word >> 8))
            out.append(UInt8(truncatingIfNeeded: word >> 16))
            out.append(UInt8(truncatingIfNeeded: word >> 24))
        }
        return out
    }

    /// ChaCha rotations are to the **left**, unlike BLAKE3's.
    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int,
                                     _ c: Int, _ d: Int) {
        s[a] = s[a] &+ s[b]; s[d] = rotateLeft(s[d] ^ s[a], 16)
        s[c] = s[c] &+ s[d]; s[b] = rotateLeft(s[b] ^ s[c], 12)
        s[a] = s[a] &+ s[b]; s[d] = rotateLeft(s[d] ^ s[a], 8)
        s[c] = s[c] &+ s[d]; s[b] = rotateLeft(s[b] ^ s[c], 7)
    }

    private static func rotateLeft(_ value: UInt32, _ amount: UInt32) -> UInt32 {
        (value << amount) | (value >> (32 - amount))
    }

    private static func littleEndian(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
    }
}

// MARK: - Self-test

public enum XChaCha20SelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "XChaCha20 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func bytes(_ hex: String) -> Data {
        var out = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            out.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    public static func run() throws {
        try hChaCha20Vector()
        try sealOpenRoundTrip()
        try rejectsMalformedInput()
    }

    /// The published HChaCha20 vector from the XChaCha20 draft. Everything else
    /// in this file is built on this function, so a wrong rotation direction or
    /// a stray feed-forward would silently produce a cipher that interoperates
    /// with nothing — and only this vector catches it.
    private static func hChaCha20Vector() throws {
        let key = bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let nonce = bytes("000000090000004a0000000031415927")
        let expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
        let actual = hex(XChaCha20Poly1305.hChaCha20(key: key, nonce: nonce))
        try expect(actual == expected, "HChaCha20 输出为 \(actual)，期望 \(expected)")
    }

    private static func sealOpenRoundTrip() throws {
        let key = Data((0..<32).map { UInt8($0) })
        let nonce = Data((0..<24).map { UInt8(($0 &* 7) & 0xFF) })
        for length in [0, 1, 15, 16, 17, 64, 1500] {
            let plaintext = Data((0..<length).map { UInt8($0 % 251) })
            let sealed = try XChaCha20Poly1305.seal(plaintext, key: key, nonce: nonce)
            try expect(sealed.count == length + XChaCha20Poly1305.tagLength,
                       "长度 \(length) 的密文大小错误：\(sealed.count)")
            let opened = try XChaCha20Poly1305.open(sealed, key: key, nonce: nonce)
            try expect(opened == plaintext, "长度 \(length) 的往返结果不一致")
        }

        // A different nonce must not open the box — that is the whole point of
        // deriving the subkey from it.
        let sealed = try XChaCha20Poly1305.seal(Data("hello".utf8), key: key, nonce: nonce)
        var otherNonce = nonce
        otherNonce[0] ^= 0x01
        do {
            _ = try XChaCha20Poly1305.open(sealed, key: key, nonce: otherNonce)
            throw Failure(text: "错误的 nonce 竟然解开了密文")
        } catch is CryptoKitError {}
        var otherKey = key
        otherKey[31] ^= 0x01
        do {
            _ = try XChaCha20Poly1305.open(sealed, key: otherKey, nonce: nonce)
            throw Failure(text: "错误的密钥竟然解开了密文")
        } catch is CryptoKitError {}
    }

    private static func rejectsMalformedInput() throws {
        let key = Data(repeating: 0x11, count: 32)
        let nonce = Data(repeating: 0x22, count: 24)
        do {
            _ = try XChaCha20Poly1305.seal(Data(), key: Data(repeating: 0, count: 16), nonce: nonce)
            throw Failure(text: "错误的密钥长度未被拒绝")
        } catch is XChaCha20Poly1305.CryptoError {}
        do {
            _ = try XChaCha20Poly1305.seal(Data(), key: key, nonce: Data(repeating: 0, count: 12))
            throw Failure(text: "错误的 nonce 长度未被拒绝")
        } catch is XChaCha20Poly1305.CryptoError {}
        do {
            _ = try XChaCha20Poly1305.open(Data(repeating: 0, count: 8), key: key, nonce: nonce)
            throw Failure(text: "短于标签的密文未被拒绝")
        } catch is NativeOutboundError {}
    }
}

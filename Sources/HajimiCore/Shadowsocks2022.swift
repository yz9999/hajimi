import Foundation
import Network
import CryptoKit

/// Shadowsocks 2022 (SIP022).
///
/// A different protocol from classic Shadowsocks AEAD despite the shared name:
/// keys come from BLAKE3 rather than HKDF, the password is a base64 PSK rather
/// than a passphrase, the request carries a timestamp and a padded header, and
/// the response echoes the request salt so the client can detect a replayed or
/// substituted server.
///
/// Byte-order trap, and the easiest way to get this silently wrong: every
/// length, port and timestamp on the wire is big-endian, but the AEAD nonce
/// counter is little-endian.
public enum Shadowsocks2022 {
    /// ASCII, no NUL terminator.
    static let sessionSubkeyContext = "shadowsocks 2022 session subkey"
    static let maximumPadding = 900
    static let maximumTimestampSkew: Int64 = 30
    static let tagLength = 16
    /// SIP022 raises the classic 0x3FFF payload cap to a full 16-bit length.
    static let maximumChunkPayload = 0xFFFF

    public enum Method: String, CaseIterable {
        case aes128GCM = "2022-blake3-aes-128-gcm"
        case aes256GCM = "2022-blake3-aes-256-gcm"
        case chacha20Poly1305 = "2022-blake3-chacha20-poly1305"

        /// The salt is always the same length as the key.
        var keyLength: Int {
            switch self {
            case .aes128GCM: return 16
            case .aes256GCM, .chacha20Poly1305: return 32
            }
        }
        var saltLength: Int { keyLength }
    }

    public static func method(named raw: String) -> Method? {
        Method(rawValue: raw.lowercased())
    }

    // MARK: Keys

    public enum KeyError: LocalizedError, Equatable {
        case notBase64(String)
        case wrongLength(expected: Int, actual: Int)
        case emptySegment
        case identityHeadersNeedAES

        public var errorDescription: String? {
            switch self {
            case .notBase64:
                return "Shadowsocks 2022 的密码必须是 base64 编码的 PSK，不是普通口令"
            case .wrongLength(let expected, let actual):
                return "Shadowsocks 2022 PSK 长度为 \(actual) 字节，该加密方式要求 \(expected) 字节"
            case .emptySegment:
                return "Shadowsocks 2022 的多用户密码中存在空的 PSK 段"
            case .identityHeadersNeedAES:
                return "2022-blake3-chacha20-poly1305 不支持多用户身份头（EIH），"
                    + "请改用 aes-128-gcm 或 aes-256-gcm"
            }
        }
    }

    /// The chain of pre-shared keys behind a `psk1:psk2:…:pskN` password.
    ///
    /// A single PSK — by far the common case — yields an empty `identity` list,
    /// which turns every identity-header path below into a no-op instead of a
    /// branch. That is deliberate: a special case here would be exercised only
    /// by multi-user setups nobody tests locally.
    public struct KeyChain: Equatable {
        /// One per relay hop the request passes through, outermost first.
        public let identity: [Data]
        /// The last key in the chain: the one the destination server holds, and
        /// the only one any session subkey is ever derived from. Deriving from
        /// the first instead produces a request the relay forwards happily and
        /// the destination cannot open.
        public let session: Data

        /// The full chain, identity keys first. Header `k` is built from key `k`
        /// and names key `k+1`.
        var all: [Data] { identity + [session] }

        /// A chain with no relays in it — the ordinary single-PSK node.
        init(single key: Data) { self.identity = []; self.session = key }

        init(identity: [Data], session: Data) {
            self.identity = identity
            self.session = session
        }
    }

    /// Decodes the configured password into its PSK chain.
    ///
    /// This is deliberately strict. Classic Shadowsocks stretches an arbitrary
    /// passphrase into a key, and falling back to that here would produce a
    /// client that connects to nothing while looking correctly configured.
    public static func keyChain(password: String, method: Method) throws -> KeyChain {
        let segments = password.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard !segments.contains(where: { $0.isEmpty }) else { throw KeyError.emptySegment }
        // Each segment carries its own base64 padding. Stripping the colons and
        // decoding the whole string would silently produce one key of the wrong
        // length — or, worse, a plausible one.
        let keys = try segments.map { try decodeKey($0, method: method) }
        guard keys.count == 1 || method != .chacha20Poly1305 else {
            // The chacha UDP construction has no room for identity headers, and
            // the reference implementation panics rather than emit one. Failing
            // at configuration time is the only way the user sees a reason.
            throw KeyError.identityHeadersNeedAES
        }
        return KeyChain(identity: Array(keys.dropLast()), session: keys[keys.count - 1])
    }

    private static func decodeKey(_ segment: String, method: Method) throws -> Data {
        var normalized = segment
        while normalized.count % 4 != 0 { normalized.append("=") }
        guard let key = Data(base64Encoded: normalized) else {
            throw KeyError.notBase64(segment)
        }
        guard key.count == method.keyLength else {
            throw KeyError.wrongLength(expected: method.keyLength, actual: key.count)
        }
        return key
    }

    static func sessionSubkey(preSharedKey: Data, salt: Data, method: Method) -> Data {
        let material = [UInt8](preSharedKey) + [UInt8](salt)
        return Data(BLAKE3.deriveKey(context: sessionSubkeyContext, keyMaterial: material,
                                     count: method.keyLength))
    }

    // MARK: Extensible identity headers (SIP023)

    /// ASCII, no NUL terminator. A single wrong character changes the derived
    /// key completely and nothing downstream validates it.
    static let identitySubkeyContext = "shadowsocks 2022 identity subkey"

    /// The block size of the identity header — always 16, independent of the
    /// method's key length, because it is one AES block.
    static let identityHeaderLength = 16

    /// Each hop is named by the first 16 bytes of the BLAKE3 hash of the key it
    /// is expected to hold.
    private static func identityHash(_ key: Data) -> Data {
        Data(BLAKE3.hash([UInt8](key), count: identityHeaderLength))
    }

    /// TCP identity headers, sitting between the salt and the first AEAD chunk.
    ///
    /// Header `k` is `AES(derive_key(identity, psk[k] ‖ salt))` applied to the
    /// hash of `psk[k+1]`; each relay strips one and forwards the rest. The
    /// headers are outside the AEAD, so nothing ever authenticates them — a
    /// mistake here surfaces only as a server that closes the connection.
    static func tcpIdentityHeaders(chain: KeyChain, salt: Data, method: Method) throws -> Data {
        guard !chain.identity.isEmpty else { return Data() }
        let keys = chain.all
        var out = Data()
        for index in 0..<chain.identity.count {
            let material = [UInt8](keys[index]) + [UInt8](salt)
            let subkey = Data(BLAKE3.deriveKey(context: identitySubkeyContext,
                                               keyMaterial: material,
                                               count: method.keyLength))
            out.append(try aesECBBlock(identityHash(keys[index + 1]), key: subkey, encrypt: true))
        }
        return out
    }

    /// UDP identity headers, sitting between the separate header and the body.
    ///
    /// Two differences from the TCP form, and getting either wrong fails
    /// silently because UDP gives the client no feedback at all:
    ///   - the key is the raw PSK, with no `derive_key` step;
    ///   - the hash is XORed with the separate header **in the clear**, not with
    ///     the encrypted bytes that occupy the same offsets on the wire.
    static func udpIdentityHeaders(chain: KeyChain, plainSeparateHeader: Data) throws -> Data {
        guard !chain.identity.isEmpty else { return Data() }
        precondition(plainSeparateHeader.count == identityHeaderLength)
        let keys = chain.all
        var out = Data()
        for index in 0..<chain.identity.count {
            let masked = Data(zip(identityHash(keys[index + 1]), plainSeparateHeader).map { $0 ^ $1 })
            out.append(try aesECBBlock(masked, key: keys[index], encrypt: true))
        }
        return out
    }

    // MARK: AEAD

    /// A one-directional AEAD stream. The counter is per-direction and never
    /// resets, so send and receive are separate instances.
    struct Cipher {
        let key: Data
        let method: Method
        private(set) var counter: UInt64 = 0

        init(key: Data, method: Method) {
            self.key = key
            self.method = method
        }

        /// 12 bytes, little-endian, unlike every other integer in the protocol.
        static func nonce(counter: UInt64) -> Data {
            var bytes = Data(count: 12)
            for index in 0..<8 {
                bytes[index] = UInt8(truncatingIfNeeded: counter >> (8 * UInt64(index)))
            }
            return bytes
        }

        mutating func seal(_ plaintext: Data) throws -> Data {
            let result = try Self.seal(plaintext, key: key, method: method,
                                       nonce: Self.nonce(counter: counter))
            counter &+= 1
            return result
        }

        mutating func open(_ ciphertext: Data) throws -> Data {
            let result = try Self.open(ciphertext, key: key, method: method,
                                       nonce: Self.nonce(counter: counter))
            counter &+= 1
            return result
        }

        static func seal(_ plaintext: Data, key: Data, method: Method, nonce: Data) throws -> Data {
            let symmetric = SymmetricKey(data: key)
            switch method {
            case .aes128GCM, .aes256GCM:
                let box = try AES.GCM.seal(plaintext, using: symmetric,
                                           nonce: try AES.GCM.Nonce(data: nonce))
                return box.ciphertext + box.tag
            case .chacha20Poly1305:
                let box = try ChaChaPoly.seal(plaintext, using: symmetric,
                                              nonce: try ChaChaPoly.Nonce(data: nonce))
                return box.ciphertext + box.tag
            }
        }

        static func open(_ ciphertext: Data, key: Data, method: Method, nonce: Data) throws -> Data {
            guard ciphertext.count >= tagLength else {
                throw NativeOutboundError.crypto("Shadowsocks 2022 密文短于认证标签")
            }
            let body = ciphertext.prefix(ciphertext.count - tagLength)
            let tag = ciphertext.suffix(tagLength)
            let symmetric = SymmetricKey(data: key)
            switch method {
            case .aes128GCM, .aes256GCM:
                let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce),
                                                ciphertext: body, tag: tag)
                return try AES.GCM.open(box, using: symmetric)
            case .chacha20Poly1305:
                let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce),
                                                   ciphertext: body, tag: tag)
                return try ChaChaPoly.open(box, using: symmetric)
            }
        }
    }

    // MARK: Header construction

    static func addressBytes(host: String, port: UInt16) throws -> Data {
        var out = Data()
        if let v4 = IPv4Address(host) {
            out.append(0x01)
            out.append(contentsOf: v4.rawValue)
        } else if let v6 = IPv6Address(String(host.split(separator: "%").first ?? "")) {
            out.append(0x04)
            out.append(contentsOf: v6.rawValue)
        } else {
            let bytes = Array(host.utf8)
            guard !bytes.isEmpty, bytes.count <= 255 else {
                throw NativeOutboundError.protocolError("Shadowsocks 2022 目标域名长度非法")
            }
            out.append(0x03)
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(UInt8(truncatingIfNeeded: port >> 8))
        out.append(UInt8(truncatingIfNeeded: port))
        return out
    }

    /// Builds the entire first write.
    ///
    /// The result must reach the socket in a single `write`: servers issue one
    /// read of exactly `saltLength + 11 + 16` and treat a short read as a fatal
    /// protocol error with nothing sent back. Splitting this produces a client
    /// that works on loopback and fails intermittently on a real network.
    static func requestPrologue(chain: KeyChain, method: Method, salt: Data,
                                timestamp: UInt64, host: String, port: UInt16,
                                padding: Int, initialPayload: Data,
                                cipher: inout Cipher) throws -> Data {
        var variable = try addressBytes(host: host, port: port)
        let clampedPadding = max(0, min(padding, maximumPadding))
        variable.append(UInt8(truncatingIfNeeded: clampedPadding >> 8))
        variable.append(UInt8(truncatingIfNeeded: clampedPadding))
        variable.append(Data(repeating: 0, count: clampedPadding))
        variable.append(initialPayload)
        guard variable.count <= maximumChunkPayload else {
            throw NativeOutboundError.protocolError("Shadowsocks 2022 变长头超出 65535 字节")
        }
        // A server rejects a header carrying neither payload nor padding.
        guard clampedPadding > 0 || !initialPayload.isEmpty else {
            throw NativeOutboundError.protocolError("Shadowsocks 2022 请求头必须携带载荷或填充")
        }

        var fixed = Data([0x00])
        for shift in stride(from: 56, through: 0, by: -8) {
            fixed.append(UInt8(truncatingIfNeeded: timestamp >> UInt64(shift)))
        }
        fixed.append(UInt8(truncatingIfNeeded: variable.count >> 8))
        fixed.append(UInt8(truncatingIfNeeded: variable.count))

        var out = salt
        // Identity headers sit between the salt and the first chunk, and are
        // *not* counted by the AEAD nonce counter — the fixed-length chunk is
        // still sealed with counter 0.
        out.append(try tcpIdentityHeaders(chain: chain, salt: salt, method: method))
        out.append(try cipher.seal(fixed))
        out.append(try cipher.seal(variable))
        return out
    }

    struct ResponseHeader: Equatable {
        var timestamp: UInt64
        var echoedSalt: Data
        var firstChunkLength: Int
    }

    static func parseResponseHeader(_ plaintext: Data, method: Method) throws -> ResponseHeader {
        let expected = 11 + method.saltLength
        guard plaintext.count == expected else {
            throw NativeOutboundError.protocolError(
                "Shadowsocks 2022 响应头长度为 \(plaintext.count)，应为 \(expected)")
        }
        let bytes = [UInt8](plaintext)
        guard bytes[0] == 0x01 else {
            throw NativeOutboundError.protocolError(
                "Shadowsocks 2022 响应类型为 0x\(String(bytes[0], radix: 16))，应为 0x01")
        }
        var timestamp: UInt64 = 0
        for index in 1..<9 { timestamp = timestamp << 8 | UInt64(bytes[index]) }
        let salt = Data(bytes[9..<(9 + method.saltLength)])
        let lengthOffset = 9 + method.saltLength
        let length = Int(bytes[lengthOffset]) << 8 | Int(bytes[lengthOffset + 1])
        return ResponseHeader(timestamp: timestamp, echoedSalt: salt, firstChunkLength: length)
    }

    static func validate(_ header: ResponseHeader, requestSalt: Data, now: UInt64) throws {
        // A hostile server can send any 64-bit timestamp, so the difference is
        // computed in a width that cannot overflow. `Int64 - Int64` traps on a
        // top-bit-set value, which would crash the whole app on a single bad
        // response.
        let skew = header.timestamp > now
            ? header.timestamp - now
            : now - header.timestamp
        guard skew <= UInt64(maximumTimestampSkew) else {
            throw NativeOutboundError.protocolError(
                "Shadowsocks 2022 响应时间戳相差 \(skew) 秒，超过 ±30 秒；请检查本机时钟")
        }
        // Constant-time: this echo is the client's only replay defence, and a
        // short-circuiting comparison leaks how much of the salt matched.
        guard constantTimeEquals(header.echoedSalt, requestSalt) else {
            throw NativeOutboundError.protocolError("Shadowsocks 2022 响应未正确回显请求 salt")
        }
    }

    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(lhs, rhs) { difference |= a ^ b }
        return difference == 0
    }
}

// MARK: - Self-test

public enum Shadowsocks2022SelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "Shadowsocks 2022 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    /// Synthetic key material. Never put a real PSK in the repository — this
    /// file is committed and pushed.
    private static let psk32 = Data((0..<32).map { UInt8($0) })
    private static let psk16 = Data((0..<16).map { UInt8($0) })

    private static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func hexBytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            out.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    public static func run() throws {
        try keyParsing()
        try nonceEncoding()
        try addressEncoding()
        try requestLayout()
        try responseValidation()
        try prologueRoundTrip()
        try hostileServerResponses()
        try udpDatagramRoundTrip()
        try blockCipherKnownAnswers()
        try datagramKnownAnswers()
        try identityHeaderKnownAnswers()
        try datagramPaddingPolicy()
    }

    /// Padding is applied to DNS and nothing else, and never past the cap.
    ///
    /// Padding everything would be a louder signal than padding nothing, and a
    /// range computed without subtracting the payload can exceed the 900-byte
    /// limit — which a server rejects as a malformed header.
    private static func datagramPaddingPolicy() throws {
        for _ in 0..<64 {
            let dns = Shadowsocks2022.datagramPadding(port: 53, payloadLength: 40)
            try expect((1...860).contains(dns), "DNS 填充 \(dns) 越界")
        }
        try expect(Shadowsocks2022.datagramPadding(port: 443, payloadLength: 40) == 0,
                   "非 53 端口不应填充")
        try expect(Shadowsocks2022.datagramPadding(port: 53, payloadLength: 900) == 0,
                   "载荷已达上限时不应填充")
        try expect(Shadowsocks2022.datagramPadding(port: 53, payloadLength: 1200) == 0,
                   "载荷超过上限时不应填充")
        let edge = Shadowsocks2022.datagramPadding(port: 53, payloadLength: 899)
        try expect(edge == 1, "边界处填充应恰为 1，实际 \(edge)")
    }

    /// Identity headers pinned against externally computed values.
    ///
    /// Nothing on the wire authenticates these bytes — they sit outside the
    /// AEAD, and a server that cannot match them simply closes the connection
    /// or, on UDP, says nothing at all. There is no round trip to check them
    /// against and no error to read, so known answers are the only feedback
    /// this code will ever get.
    private static func identityHeaderKnownAnswers() throws {
        let iPSK = psk32                                   // 00 01 … 1f
        let uPSK = Data((0x64...0x83).map { UInt8($0) })
        let chain = Shadowsocks2022.KeyChain(identity: [iPSK], session: uPSK)
        let salt = Data(repeating: 0xAA, count: 32)

        let tcp = try Shadowsocks2022.tcpIdentityHeaders(chain: chain, salt: salt,
                                                         method: .aes256GCM)
        try expect(hexString(tcp) == "ee76f0b2b44e0cb0dab66a3ee2f612c9",
                   "TCP 身份头为 \(hexString(tcp))")

        // The UDP form keys off the raw PSK and masks with the separate header
        // *before* it is encrypted — two departures from the TCP form, each
        // silent when wrong.
        let separate = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            + Data(repeating: 0, count: 8)
        let udp = try Shadowsocks2022.udpIdentityHeaders(chain: chain,
                                                         plainSeparateHeader: separate)
        try expect(hexString(udp) == "e4069992ecde45339addce9a8299d109",
                   "UDP 身份头为 \(hexString(udp))")

        // A single-key chain must emit nothing at all: one stray block shifts
        // every following offset by 16 bytes.
        try expect(try Shadowsocks2022.tcpIdentityHeaders(
            chain: .init(single: uPSK), salt: salt, method: .aes256GCM).isEmpty,
                   "单 PSK 不应产生身份头")
        try expect(try Shadowsocks2022.udpIdentityHeaders(
            chain: .init(single: uPSK), plainSeparateHeader: separate).isEmpty,
                   "单 PSK 不应产生 UDP 身份头")

        // Count is exactly one per hop, and a header names the *next* key, so a
        // three-key chain emits two blocks whose first one is unchanged.
        let deeper = Shadowsocks2022.KeyChain(identity: [iPSK, uPSK],
                                              session: Data(repeating: 0x5A, count: 32))
        let stacked = try Shadowsocks2022.tcpIdentityHeaders(chain: deeper, salt: salt,
                                                             method: .aes256GCM)
        try expect(stacked.count == 32, "三段密钥链应产生 2 个身份头，实际 \(stacked.count / 16) 个")
        try expect(hexString(Data(stacked.prefix(16))) == "ee76f0b2b44e0cb0dab66a3ee2f612c9",
                   "多跳时首个身份头应与两段链一致")

        // The prologue places them between the salt and the first sealed chunk,
        // and must not let them advance the AEAD counter.
        var cipher = Shadowsocks2022.Cipher(
            key: Shadowsocks2022.sessionSubkey(preSharedKey: uPSK, salt: salt, method: .aes256GCM),
            method: .aes256GCM)
        let prologue = try Shadowsocks2022.requestPrologue(
            chain: chain, method: .aes256GCM, salt: salt, timestamp: 1_700_000_000,
            host: "example.com", port: 443, padding: 0,
            initialPayload: Data("x".utf8), cipher: &cipher)
        try expect(prologue.prefix(32) == salt, "前奏首段应为 salt")
        try expect(hexString(Data(prologue.dropFirst(32).prefix(16))) == hexString(tcp),
                   "身份头未紧跟在 salt 之后")

        var plainCipher = Shadowsocks2022.Cipher(
            key: Shadowsocks2022.sessionSubkey(preSharedKey: uPSK, salt: salt, method: .aes256GCM),
            method: .aes256GCM)
        let plain = try Shadowsocks2022.requestPrologue(
            chain: .init(single: uPSK), method: .aes256GCM, salt: salt,
            timestamp: 1_700_000_000, host: "example.com", port: 443, padding: 0,
            initialPayload: Data("x".utf8), cipher: &plainCipher)
        try expect(prologue.count == plain.count + 16,
                   "带身份头的前奏应恰好长 16 字节")
        try expect(Data(prologue.dropFirst(48)) == Data(plain.dropFirst(32)),
                   "身份头之后的密文应与无身份头时逐字节相同（计数器不得被身份头推进）")
    }

    /// FIPS-197 Appendix C known answers for the raw block cipher.
    ///
    /// Everything in the AES datagram construction is built on this one call,
    /// and a wrong mode or accidental PKCS#7 padding still yields something that
    /// looks like ciphertext.
    private static func blockCipherKnownAnswers() throws {
        let plaintext = Data([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        let cases: [(Data, String)] = [
            (psk16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (psk32, "8ea2b7ca516745bfeafc49904b496089"),
        ]
        for (key, expected) in cases {
            let sealed = try Shadowsocks2022.aesECBBlock(plaintext, key: key, encrypt: true)
            try expect(hexString(sealed) == expected,
                       "AES-\(key.count * 8)-ECB 输出为 \(hexString(sealed))，期望 \(expected)")
            let opened = try Shadowsocks2022.aesECBBlock(sealed, key: key, encrypt: false)
            try expect(opened == plaintext, "AES-\(key.count * 8)-ECB 解密未还原明文")
        }
    }

    /// A complete client datagram pinned against a value computed outside this
    /// codebase, from the reference construction.
    ///
    /// The round-trip test cannot catch a symmetric mistake: encoding and
    /// decoding with the same wrong value agree with each other and disagree
    /// with every real server. That is exactly how the body nonce came to be
    /// taken from the *encrypted* separate header rather than the plaintext
    /// one — self-consistent, and rejected by every deployment.
    private static func datagramKnownAnswers() throws {
        // These plaintext bytes are part of independently computed reference
        // vectors. They are historical test data, not application branding:
        // renaming them without independently regenerating the ciphertext
        // invalidates the known-answer test instead of changing the protocol.
        let sessionID = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let expected = "65627bd127f455618ff9d0f081df2db4"
            + "7e41c363d48a26c057fcafd4eb348dd067cf7fcb35c0e4744094af381f896528"
            + "d5722b043577b66754447146f69467334c2412b32e1e1e6ca4f843462ff8f9a5449b3b"
        let datagram = try Shadowsocks2022.encodeDatagram(
            chain: .init(single: psk32), method: .aes256GCM,
            sessionID: sessionID, packetID: 0, timestamp: 1_700_000_000,
            target: RequestTarget(host: "example.com", port: 443, protocolName: "UDP"),
            payload: Data("lurge-sip022-known-answer".utf8))
        try expect(hexString(datagram) == expected,
                   "SIP022 数据报与参考实现不一致\n实际：\(hexString(datagram))\n期望：\(expected)")

        // The chacha construction is a different shape entirely — one XChaCha20
        // nonce prefix, the raw PSK as the key, and the session and packet ids
        // moved *inside* the sealed body — so it needs its own external answer.
        // This is the layout most deployed 2022 nodes use.
        let merged = Data(hexBytes(
            "000102030405060708090a0b0c0d0e0f10111213141516"
            + "17bfe02c5bb5f4aa86334426cecb52a8eb4a4728a5fdb34e1a7f0b2da529b8e34e"
            + "4606b6e74a027105b8e5c23ce1423c0f70018e2c35139e3474f2e30dbdd56999d7"
            + "5298d66cb40feb432848ec3a0b7ad53c728b559ec9d7ce8167e9df21fd0a2af839"))
        let decoded = try Shadowsocks2022.decodeDatagram(
            merged, chain: .init(single: psk32), method: .chacha20Poly1305,
            clientSessionID: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]),
            now: 1_700_000_000)
        try expect(decoded.payload == Data("lurge-sip022-merged-known-answer".utf8),
                   "chacha 数据报载荷解出为 \(String(decoding: decoded.payload, as: UTF8.self))")

        // The session subkey and the separate header are pinned separately so a
        // failure above points at which half went wrong.
        try expect(hexString(Shadowsocks2022.udpSessionSubkey(
            preSharedKey: Data((0x64...0x83).map { UInt8($0) }),
            sessionID: sessionID, method: .aes256GCM))
            == "150557261c48edaafa98fc2992ee8ecd606c52a867798a6bf7f7ecbe94e06aa9",
                   "UDP 会话子密钥与参考实现不一致")
        try expect(hexString(Shadowsocks2022.sessionSubkey(
            preSharedKey: Data((0x64...0x83).map { UInt8($0) }),
            salt: Data(repeating: 0xAA, count: 32), method: .aes256GCM))
            == "471dc6fd0dc74138d6865e559927db33f7e0fe603f3bb2d982da59fc0162c85b",
                   "TCP 会话子密钥与参考实现不一致")
    }

    /// SIP022 has two structurally different datagram constructions and no
    /// published test vectors, so the codec is checked against itself: a client
    /// packet is built, then decoded as the server would, then a server reply is
    /// built and decoded as the client does.
    private static func udpDatagramRoundTrip() throws {
        for method in Shadowsocks2022.Method.allCases {
            let psk = method.keyLength == 16 ? psk16 : psk32
            let session = Data((0..<8).map { UInt8($0 &+ 1) })
            let target = RequestTarget(host: "1.2.3.4", port: 53, protocolName: "UDP")
            let payload = Data("query".utf8)
            let datagram = try Shadowsocks2022.encodeDatagram(
                chain: .init(single: psk), method: method, sessionID: session, packetID: 7,
                timestamp: 1_700_000_000, target: target, payload: payload, padding: 3)

            switch Shadowsocks2022.layout(for: method) {
            case .merged:
                // Nonce in the clear, everything else sealed.
                try expect(datagram.count > XChaCha20Poly1305.nonceLength,
                           "\(method.rawValue) 数据报过短")
            case .separateHeader:
                // The 16-byte header must decrypt to exactly what was put in.
                let header = try Shadowsocks2022.aesECBBlock(
                    Data(datagram.prefix(16)), key: psk, encrypt: false)
                try expect(Data(header.prefix(8)) == session,
                           "\(method.rawValue) 独立头中的会话 ID 不符")
                try expect(Shadowsocks2022.readBigEndian(Data(header.dropFirst(8))) == 7,
                           "\(method.rawValue) 独立头中的包 ID 不符")
            }

            // Build the answer a server would send and read it back.
            let reply = try serverDatagram(preSharedKey: psk, method: method,
                                           clientSession: session,
                                           timestamp: 1_700_000_000,
                                           target: target, payload: Data("answer".utf8))
            let decoded = try Shadowsocks2022.decodeDatagram(
                reply, chain: .init(single: psk), method: method,
                clientSessionID: session, now: 1_700_000_000)
            try expect(decoded.payload == Data("answer".utf8),
                       "\(method.rawValue) 应答载荷不符")
            try expect(decoded.target.host == "1.2.3.4" && decoded.target.port == 53,
                       "\(method.rawValue) 应答目标不符")

            // A reply naming someone else's session must be refused: on UDP any
            // host can send one, and accepting it would let an off-path party
            // answer for the server.
            let foreign = Data(repeating: 0xEE, count: 8)
            let wrongSession = try serverDatagram(preSharedKey: psk, method: method,
                                                  clientSession: foreign,
                                                  timestamp: 1_700_000_000,
                                                  target: target, payload: Data())
            do {
                _ = try Shadowsocks2022.decodeDatagram(
                    wrongSession, chain: .init(single: psk), method: method,
                    clientSessionID: session, now: 1_700_000_000)
                throw Failure(text: "\(method.rawValue) 接受了回显他人会话 ID 的数据报")
            } catch is NativeOutboundError {}

            // And one outside the timestamp window.
            do {
                _ = try Shadowsocks2022.decodeDatagram(
                    reply, chain: .init(single: psk), method: method,
                    clientSessionID: session, now: 1_700_000_031)
                throw Failure(text: "\(method.rawValue) 接受了超窗时间戳的数据报")
            } catch is NativeOutboundError {}
        }
    }

    /// Mirrors the server side of the layout so the client decoder has
    /// something real to read.
    private static func serverDatagram(preSharedKey psk: Data,
                                       method: Shadowsocks2022.Method,
                                       clientSession: Data, timestamp: UInt64,
                                       target: RequestTarget, payload: Data) throws -> Data {
        let serverSession = Data(repeating: 0xA5, count: 8)
        var body = Data()
        if Shadowsocks2022.layout(for: method) == .merged {
            body.append(serverSession)
            Shadowsocks2022.appendBigEndian(1, to: &body)
        }
        body.append(0x01)                                   // server packet
        Shadowsocks2022.appendBigEndian(timestamp, to: &body)
        body.append(clientSession)                          // echo
        body.append(contentsOf: [0x00, 0x00])               // no padding
        body.append(try Shadowsocks2022.addressBytes(host: target.host, port: target.port))
        body.append(payload)

        switch Shadowsocks2022.layout(for: method) {
        case .merged:
            let nonce = Data((0..<24).map { UInt8($0) })
            var out = nonce
            out.append(try XChaCha20Poly1305.seal(body, key: psk, nonce: nonce))
            return out
        case .separateHeader:
            var header = serverSession
            Shadowsocks2022.appendBigEndian(1, to: &header)
            let subkey = Shadowsocks2022.udpSessionSubkey(preSharedKey: psk,
                                                          sessionID: serverSession,
                                                          method: method)
            // Bytes 4..<16 of the header while it is still plaintext, matching
            // the reference server. This fixture previously mirrored the client's
            // mistake of using the ciphertext, which is precisely why the two
            // agreed with each other and with nothing else.
            var out = try Shadowsocks2022.aesECBBlock(header, key: psk, encrypt: true)
            out.append(try Shadowsocks2022.Cipher.seal(body, key: subkey, method: method,
                                                       nonce: Data(header.dropFirst(4))))
            return out
        }
    }

    /// SIP022 defines a UDP construction this implementation does not have.
    /// Claiming support would route those datagrams through the classic
    /// Shadowsocks codec, whose key derivation and packet layout are both
    /// different — the server drops every packet and the user sees a node that
    /// carries web pages but breaks anything using QUIC or plain UDP.
    private static func udpIsRefusedNotApproximated() throws {
        func node(_ cipher: String, _ password: String) -> ProxyPolicy {
            var value = ProxyPolicy(name: "probe", kind: .external)
            value.adapterType = "ss"
            value.host = "example.com"
            value.port = 8388
            value.parameters = ["cipher": cipher, "password": password]
            return value
        }
        let sip022 = node("2022-blake3-chacha20-poly1305", psk32.base64EncodedString())
        try expect(NativeOutboundFactory.supports(sip022), "SIP022 节点应被 TCP 路径接受")
        // Off unless the node opts in: the datagram layout has never been
        // confirmed against a live server, and enabling it silently would put
        // UDP back on a path that may drop every packet.
        try expect(!NativeOutboundFactory.supportsUDP(sip022),
                   "SIP022 的 UDP 默认应关闭")
        try expect(NativeOutboundFactory.carriesUDPOverReliableStream(sip022),
                   "UDP 关闭时应触发 UDP/443 回退到 TCP")
        do {
            _ = try NativeOutboundFactory.makeDatagramSession(
                policy: sip022, queue: .global(), receive: { _, _ in }, failure: { _ in })
            throw Failure(text: "关闭 UDP 时的会话未被拒绝")
        } catch is NativeOutboundError {}

        var opted = sip022
        opted.parameters["udp"] = "true"
        try expect(NativeOutboundFactory.supportsUDP(opted), "显式开启后 UDP 未生效")
        try expect(!NativeOutboundFactory.carriesUDPOverReliableStream(opted),
                   "UDP 可用时不应再把 QUIC 降级到 TCP")

        // The classic ciphers keep their UDP support untouched.
        let classic = node("aes-128-gcm", "pw")
        try expect(NativeOutboundFactory.supportsUDP(classic),
                   "经典 Shadowsocks 的 UDP 支持被误伤")
        try expect(!NativeOutboundFactory.carriesUDPOverReliableStream(classic),
                   "经典 Shadowsocks 不应触发 QUIC 回退")
    }

    /// Regression tests for defects an adversarial review found. The response
    /// header is attacker-controlled: a malicious or compromised server can put
    /// any 64-bit value in the timestamp field.
    private static func hostileServerResponses() throws {
        func header(timestamp: UInt64) -> Data {
            var out = Data([0x01])
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: timestamp >> UInt64(shift)))
            }
            out.append(Data(repeating: 0x11, count: 32))
            out.append(contentsOf: [0x00, 0x05])
            return out
        }
        let salt = Data(repeating: 0x11, count: 32)
        // Any of these used to trap on Int64 overflow and take down the process.
        for timestamp in [UInt64.max, UInt64(Int64.max), UInt64(Int64.max) + 1, 0] {
            let parsed = try Shadowsocks2022.parseResponseHeader(header(timestamp: timestamp),
                                                                 method: .chacha20Poly1305)
            do {
                try Shadowsocks2022.validate(parsed, requestSalt: salt, now: 1_700_000_000)
                throw Failure(text: "越界时间戳 \(timestamp) 未被拒绝")
            } catch is NativeOutboundError {}
        }
        // Near the 64-bit boundary the check must still compute the real skew
        // instead of trapping: 5 seconds apart is inside the window and has to
        // be accepted, which is only possible without a signed subtraction.
        let big = try Shadowsocks2022.parseResponseHeader(header(timestamp: UInt64.max - 5),
                                                          method: .chacha20Poly1305)
        try Shadowsocks2022.validate(big, requestSalt: salt, now: UInt64.max)

        // A first write larger than one chunk must be split, not rejected.
        var cipher = Shadowsocks2022.Cipher(
            key: Shadowsocks2022.sessionSubkey(preSharedKey: psk32, salt: salt,
                                               method: .chacha20Poly1305),
            method: .chacha20Poly1305)
        let inline = Data(repeating: 0x41, count: Shadowsocks2022.maximumChunkPayload - 512)
        _ = try Shadowsocks2022.requestPrologue(
            chain: .init(single: psk32), method: .chacha20Poly1305, salt: salt,
            timestamp: 1_700_000_000, host: "example.com", port: 80,
            padding: 0, initialPayload: inline, cipher: &cipher)
    }

    private static func keyParsing() throws {
        let encoded32 = psk32.base64EncodedString()
        let single = try Shadowsocks2022.keyChain(password: encoded32, method: .chacha20Poly1305)
        try expect(single.session == psk32 && single.identity.isEmpty, "32 字节 PSK 解析错误")
        try expect((try? Shadowsocks2022.keyChain(password: psk16.base64EncodedString(),
                                                  method: .aes128GCM))?.session == psk16,
                   "16 字节 PSK 解析错误")

        // A classic Shadowsocks passphrase must be refused, not stretched into
        // a key: that would look configured and connect to nothing.
        do {
            _ = try Shadowsocks2022.keyChain(password: "hunter2", method: .aes128GCM)
            throw Failure(text: "普通口令未被拒绝")
        } catch let error as Shadowsocks2022.KeyError {
            guard error == .wrongLength(expected: 16, actual: 5) || error == .notBase64("hunter2") else {
                throw Failure(text: "普通口令的错误类型不对：\(error)")
            }
        }
        // Right base64, wrong length for the method.
        do {
            _ = try Shadowsocks2022.keyChain(password: encoded32, method: .aes128GCM)
            throw Failure(text: "长度不符的 PSK 未被拒绝")
        } catch let error as Shadowsocks2022.KeyError {
            try expect(error == .wrongLength(expected: 16, actual: 32), "长度错误信息不对")
        }

        // A multi-user password splits into a chain whose *last* key is the one
        // sessions are keyed from. Getting that order backwards yields a request
        // every relay forwards and the destination cannot open.
        let encoded16 = psk16.base64EncodedString()
        let other16 = Data((0..<16).map { UInt8(0xF0 &- $0) })
        let chain = try Shadowsocks2022.keyChain(
            password: "\(encoded16):\(other16.base64EncodedString())", method: .aes128GCM)
        try expect(chain.identity == [psk16], "身份密钥应为链上除末位外的全部")
        try expect(chain.session == other16, "会话密钥应取链上最后一个 PSK")
        try expect(chain.all.count == 2, "密钥链长度错误")

        // Each segment is padded and decoded on its own. Joining them first
        // would decode to a single key of the wrong length — or a plausible one.
        let unpadded = Data((0..<16).map { UInt8($0) }).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        try expect((try? Shadowsocks2022.keyChain(password: "\(unpadded):\(encoded16)",
                                                  method: .aes128GCM))?.identity.count == 1,
                   "分段 base64 填充未独立处理")
        do {
            _ = try Shadowsocks2022.keyChain(password: "\(encoded16):", method: .aes128GCM)
            throw Failure(text: "空 PSK 段未被拒绝")
        } catch let error as Shadowsocks2022.KeyError {
            try expect(error == .emptySegment, "空段拒绝原因不对")
        }

        // The chacha datagram construction has nowhere to put identity headers,
        // so this combination must fail while it is still a configuration error
        // rather than an unexplained connection failure.
        do {
            _ = try Shadowsocks2022.keyChain(password: "\(encoded32):\(encoded32)",
                                             method: .chacha20Poly1305)
            throw Failure(text: "chacha20 + EIH 未被拒绝")
        } catch let error as Shadowsocks2022.KeyError {
            try expect(error == .identityHeadersNeedAES, "chacha20 + EIH 拒绝原因不对")
        }

        try expect(Shadowsocks2022.Method.aes128GCM.keyLength == 16
                   && Shadowsocks2022.Method.aes256GCM.keyLength == 32
                   && Shadowsocks2022.Method.chacha20Poly1305.keyLength == 32,
                   "密钥长度表错误")
        try expect(Shadowsocks2022.Method.allCases.allSatisfy { $0.saltLength == $0.keyLength },
                   "salt 长度应与密钥长度相同")
    }

    /// The nonce counter is the one little-endian integer in a protocol whose
    /// every other field is big-endian.
    private static func nonceEncoding() throws {
        func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        try expect(hex(Shadowsocks2022.Cipher.nonce(counter: 0)) == "000000000000000000000000",
                   "counter 0 的 nonce 错误")
        try expect(hex(Shadowsocks2022.Cipher.nonce(counter: 1)) == "010000000000000000000000",
                   "counter 1 的 nonce 应为小端")
        try expect(hex(Shadowsocks2022.Cipher.nonce(counter: 256)) == "000100000000000000000000",
                   "counter 256 的 nonce 应为小端")
        try expect(Shadowsocks2022.Cipher.nonce(counter: 0).count == 12, "nonce 长度应为 12")
    }

    private static func addressEncoding() throws {
        let v4 = try Shadowsocks2022.addressBytes(host: "1.2.3.4", port: 443)
        try expect([UInt8](v4) == [0x01, 1, 2, 3, 4, 0x01, 0xbb], "IPv4 地址编码错误")
        let domain = try Shadowsocks2022.addressBytes(host: "example.com", port: 80)
        try expect(domain.first == 0x03 && domain[domain.startIndex + 1] == 11,
                   "域名地址编码错误")
        try expect([UInt8](domain.suffix(2)) == [0x00, 0x50], "端口应为大端")
        let v6 = try Shadowsocks2022.addressBytes(host: "2001:db8::1", port: 443)
        try expect(v6.first == 0x04 && v6.count == 1 + 16 + 2, "IPv6 地址编码错误")
    }

    private static func requestLayout() throws {
        let salt = Data(repeating: 0xAA, count: 32)
        let subkey = Shadowsocks2022.sessionSubkey(preSharedKey: psk32, salt: salt,
                                                   method: .chacha20Poly1305)
        var cipher = Shadowsocks2022.Cipher(key: subkey, method: .chacha20Poly1305)
        let payload = Data("GET / HTTP/1.1\r\n\r\n".utf8)
        let prologue = try Shadowsocks2022.requestPrologue(
            chain: .init(single: psk32), method: .chacha20Poly1305, salt: salt,
            timestamp: 1_700_000_000, host: "example.com", port: 80,
            padding: 0, initialPayload: payload, cipher: &cipher)

        // V = ATYP(1) + len(1) + 11 domain + port(2) + padLen(2) + payload
        let variableLength = 1 + 1 + 11 + 2 + 2 + payload.count
        let expectedTotal = 32 + (11 + 16) + (variableLength + 16)
        try expect(prologue.count == expectedTotal,
                   "首包长度为 \(prologue.count)，应为 \(expectedTotal)")
        try expect(prologue.prefix(32) == salt, "首包开头应为明文 salt")
        try expect(cipher.counter == 2, "首包应消耗 nonce 0 与 1，实际计数 \(cipher.counter)")

        // The fixed header must decrypt at nonce 0 and declare V.
        let fixed = try Shadowsocks2022.Cipher.open(
            prologue[prologue.startIndex + 32..<prologue.startIndex + 32 + 27],
            key: subkey, method: .chacha20Poly1305,
            nonce: Shadowsocks2022.Cipher.nonce(counter: 0))
        try expect(fixed.count == 11, "定长头明文应为 11 字节")
        try expect(fixed[fixed.startIndex] == 0x00, "客户端类型字节应为 0x00")
        let declared = Int(fixed[fixed.startIndex + 9]) << 8 | Int(fixed[fixed.startIndex + 10])
        try expect(declared == variableLength,
                   "定长头声明的变长头长度为 \(declared)，应为 \(variableLength)")
        var timestamp: UInt64 = 0
        for index in 1..<9 { timestamp = timestamp << 8 | UInt64(fixed[fixed.startIndex + index]) }
        try expect(timestamp == 1_700_000_000, "时间戳应为 8 字节大端")

        // A header with neither payload nor padding is rejected by servers.
        var reject = Shadowsocks2022.Cipher(key: subkey, method: .chacha20Poly1305)
        do {
            _ = try Shadowsocks2022.requestPrologue(
                chain: .init(single: psk32), method: .chacha20Poly1305, salt: salt,
                timestamp: 1_700_000_000, host: "example.com", port: 80,
                padding: 0, initialPayload: Data(), cipher: &reject)
            throw Failure(text: "无载荷且无填充的请求头未被拒绝")
        } catch is NativeOutboundError {}
    }

    private static func responseValidation() throws {
        let requestSalt = Data(repeating: 0x11, count: 32)
        func header(type: UInt8 = 0x01, timestamp: UInt64 = 1_700_000_000,
                    salt: Data = Data(repeating: 0x11, count: 32),
                    length: Int = 5) -> Data {
            var out = Data([type])
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: timestamp >> UInt64(shift)))
            }
            out.append(salt)
            out.append(UInt8(truncatingIfNeeded: length >> 8))
            out.append(UInt8(truncatingIfNeeded: length))
            return out
        }

        let parsed = try Shadowsocks2022.parseResponseHeader(header(), method: .chacha20Poly1305)
        try expect(parsed.timestamp == 1_700_000_000, "响应时间戳解析错误")
        try expect(parsed.firstChunkLength == 5, "首块长度解析错误")
        try Shadowsocks2022.validate(parsed, requestSalt: requestSalt, now: 1_700_000_000)

        // Wrong type.
        do {
            _ = try Shadowsocks2022.parseResponseHeader(header(type: 0x00),
                                                        method: .chacha20Poly1305)
            throw Failure(text: "错误的响应类型未被拒绝")
        } catch is NativeOutboundError {}

        // Clock skew past the window, in both directions.
        for now in [UInt64(1_700_000_031), UInt64(1_699_999_969)] {
            do {
                try Shadowsocks2022.validate(parsed, requestSalt: requestSalt, now: now)
                throw Failure(text: "超窗时间戳未被拒绝：now=\(now)")
            } catch is NativeOutboundError {}
        }
        // Exactly at the boundary is accepted.
        try Shadowsocks2022.validate(parsed, requestSalt: requestSalt, now: 1_700_000_030)

        // A mismatched salt echo is the client's only replay defence.
        var tampered = requestSalt
        tampered[tampered.startIndex] ^= 0x01
        do {
            try Shadowsocks2022.validate(parsed, requestSalt: tampered, now: 1_700_000_000)
            throw Failure(text: "回显 salt 不匹配未被拒绝")
        } catch is NativeOutboundError {}
        try expect(!Shadowsocks2022.constantTimeEquals(requestSalt, tampered),
                   "恒定时间比较对不同输入返回了相等")
        try expect(Shadowsocks2022.constantTimeEquals(requestSalt, requestSalt),
                   "恒定时间比较对相同输入返回了不等")
        try expect(!Shadowsocks2022.constantTimeEquals(requestSalt, requestSalt.prefix(31)),
                   "长度不同应判定为不等")
    }

    /// Seals a prologue and opens it back with an independently derived key,
    /// proving the subkey derivation and nonce schedule agree with themselves.
    private static func prologueRoundTrip() throws {
        for method in Shadowsocks2022.Method.allCases {
            let psk = method.keyLength == 16 ? psk16 : psk32
            let salt = Data(repeating: 0x5A, count: method.saltLength)
            let subkey = Shadowsocks2022.sessionSubkey(preSharedKey: psk, salt: salt,
                                                       method: method)
            var cipher = Shadowsocks2022.Cipher(key: subkey, method: method)
            let payload = Data("hello".utf8)
            let prologue = try Shadowsocks2022.requestPrologue(
                chain: .init(single: psk), method: method, salt: salt, timestamp: 1_700_000_000,
                host: "example.com", port: 443, padding: 7, initialPayload: payload,
                cipher: &cipher)

            let recovered = Shadowsocks2022.sessionSubkey(
                preSharedKey: psk, salt: Data(prologue.prefix(method.saltLength)), method: method)
            try expect(recovered == subkey, "\(method.rawValue) 子密钥派生不可复现")

            var opener = Shadowsocks2022.Cipher(key: recovered, method: method)
            let start = prologue.startIndex + method.saltLength
            let fixed = try opener.open(prologue[start..<(start + 27)])
            let declared = Int(fixed[fixed.startIndex + 9]) << 8 | Int(fixed[fixed.startIndex + 10])
            let variable = try opener.open(
                prologue[(start + 27)..<(start + 27 + declared + Shadowsocks2022.tagLength)])
            try expect(variable.count == declared, "\(method.rawValue) 变长头长度不符")
            try expect(variable.suffix(payload.count) == payload,
                       "\(method.rawValue) 初始载荷未正确还原")
            // padding length field sits just before the padding itself
            let padOffset = variable.startIndex + 1 + 1 + 11 + 2
            let padding = Int(variable[padOffset]) << 8 | Int(variable[padOffset + 1])
            try expect(padding == 7, "\(method.rawValue) 填充长度未正确还原")
        }
    }
}

// MARK: - Stream

/// Client stream for SIP022 over TCP.
final class Shadowsocks2022Stream: OutboundByteStream {
    private let transport: any ByteTransport
    private let reader: BufferedByteReader
    private let method: Shadowsocks2022.Method
    private let chain: Shadowsocks2022.KeyChain
    private let requestSalt: Data
    private let target: RequestTarget
    private var sendCipher: Shadowsocks2022.Cipher
    private var receiveCipher: Shadowsocks2022.Cipher?
    private var pendingChunkLength: Int?
    private var inbound = Data()
    private var prologueSent = false
    private var emptyChunkRun = 0
    private var cancelled = false

    init(policy: ProxyPolicy, target: RequestTarget, transport: any ByteTransport) throws {
        guard let raw = policy.parameters["cipher"] ?? policy.parameters["encrypt-method"],
              let method = Shadowsocks2022.method(named: raw) else {
            throw NativeOutboundError.unsupported("不是 Shadowsocks 2022 加密方式")
        }
        guard let password = policy.parameters["password"], !password.isEmpty else {
            throw NativeOutboundError.protocolError("Shadowsocks 2022 缺少 PSK")
        }
        self.method = method
        self.target = target
        self.transport = transport
        chain = try Shadowsocks2022.keyChain(password: password, method: method)
        requestSalt = secureRandom(count: method.saltLength)
        let subkey = Shadowsocks2022.sessionSubkey(preSharedKey: chain.session,
                                                   salt: requestSalt, method: method)
        sendCipher = Shadowsocks2022.Cipher(key: subkey, method: method)
        reader = BufferedByteReader(transport)
    }

    /// Sending the prologue is deferred so the caller's first write can ride
    /// along with it, saving a round trip. A read before any write must still
    /// flush it: SMTP, IMAP, SSH and MySQL all have the server speak first, and
    /// waiting for a write that never comes deadlocks both ends.
    func start(completion: @escaping (Result<Shadowsocks2022Stream, Error>) -> Void) {
        completion(.success(self))
    }

    private func flushPrologueIfNeeded(completion: @escaping (Error?) -> Void) {
        guard !prologueSent else { completion(nil); return }
        sendPrologue(initialPayload: Data(), completion: completion)
    }

    private func sendPrologue(initialPayload: Data,
                              completion: @escaping (Error?) -> Void) {
        do {
            let padding = initialPayload.isEmpty ? Int.random(in: 1...Shadowsocks2022.maximumPadding) : 0
            let prologue = try Shadowsocks2022.requestPrologue(
                chain: chain, method: method, salt: requestSalt,
                timestamp: UInt64(max(0, Int64(Date().timeIntervalSince1970))),
                host: target.host, port: target.port,
                padding: padding, initialPayload: initialPayload,
                cipher: &sendCipher)
            prologueSent = true
            transport.send(prologue, completion: completion)
        } catch {
            completion(error)
        }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !cancelled else {
            completion(NativeOutboundError.connection("连接已关闭")); return
        }
        guard prologueSent else {
            // The variable header is a single length-prefixed chunk, so only
            // what fits goes inline; the remainder follows as ordinary chunks
            // rather than failing the connection.
            let headroom = Shadowsocks2022.maximumChunkPayload - 512
            let inline = data.prefix(headroom)
            let rest = data.dropFirst(inline.count)
            sendPrologue(initialPayload: Data(inline)) { [weak self] error in
                guard let self else { return }
                if let error { completion(error); return }
                guard !rest.isEmpty else { completion(nil); return }
                self.send(Data(rest), completion: completion)
            }
            return
        }
        do {
            var out = Data()
            var offset = 0
            while offset < data.count {
                let count = min(Shadowsocks2022.maximumChunkPayload, data.count - offset)
                var lengthField = Data()
                lengthField.append(UInt8(truncatingIfNeeded: count >> 8))
                lengthField.append(UInt8(truncatingIfNeeded: count))
                out.append(try sendCipher.seal(lengthField))
                out.append(try sendCipher.seal(data[(data.startIndex + offset)..<(data.startIndex + offset + count)]))
                offset += count
            }
            transport.send(out, completion: completion)
        } catch { completion(error) }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        guard !cancelled else { completion(nil, true, nil); return }
        if !inbound.isEmpty {
            let chunk = inbound.prefix(max(1, maximum))
            inbound.removeFirst(chunk.count)
            completion(Data(chunk), false, nil)
            return
        }
        guard receiveCipher != nil else {
            flushPrologueIfNeeded { [weak self] error in
                guard let self else { return }
                if let error { completion(nil, true, error); return }
                self.readPrologue { error in
                    if let error { completion(nil, true, error); return }
                    self.receive(maximum: maximum, completion: completion)
                }
            }
            return
        }
        readChunk { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                completion(nil, true, isCleanByteStreamEOF(error) ? nil : error)
            case .success(let payload):
                guard let payload else { completion(nil, true, nil); return }
                guard !payload.isEmpty else {
                    // A server that streams empty chunks would otherwise drive
                    // receive/readChunk into unbounded synchronous recursion
                    // and overflow the worker's stack.
                    self.emptyChunkRun += 1
                    guard self.emptyChunkRun <= 64 else {
                        completion(nil, true, NativeOutboundError.protocolError(
                            "Shadowsocks 2022 服务端持续发送空分块"))
                        return
                    }
                    self.receive(maximum: maximum, completion: completion)
                    return
                }
                self.emptyChunkRun = 0
                self.inbound.append(payload)
                self.receive(maximum: maximum, completion: completion)
            }
        }
    }

    /// Reads salt + response header + the first payload chunk.
    ///
    /// The response is not symmetric with the request: its header doubles as
    /// the first length chunk, so a payload chunk follows it directly and the
    /// length/payload alternation only begins with the second payload.
    private func readPrologue(completion: @escaping (Error?) -> Void) {
        let saltLength = method.saltLength
        let headerCipherLength = 11 + saltLength + Shadowsocks2022.tagLength
        reader.readExactly(saltLength + headerCipherLength) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): completion(error)
            case .success(let prologue):
                do {
                    let salt = prologue.prefix(saltLength)
                    let sealed = prologue.suffix(headerCipherLength)
                    let subkey = Shadowsocks2022.sessionSubkey(preSharedKey: self.chain.session,
                                                               salt: Data(salt),
                                                               method: self.method)
                    var cipher = Shadowsocks2022.Cipher(key: subkey, method: self.method)
                    let plaintext = try cipher.open(Data(sealed))
                    let header = try Shadowsocks2022.parseResponseHeader(plaintext,
                                                                         method: self.method)
                    try Shadowsocks2022.validate(
                        header, requestSalt: self.requestSalt,
                        now: UInt64(max(0, Int64(Date().timeIntervalSince1970))))
                    self.receiveCipher = cipher
                    self.pendingChunkLength = header.firstChunkLength
                    completion(nil)
                } catch { completion(error) }
            }
        }
    }

    /// Returns nil on a clean end of stream.
    private func readChunk(completion: @escaping (Result<Data?, Error>) -> Void) {
        guard receiveCipher != nil else {
            completion(.failure(NativeOutboundError.protocolError("接收方向尚未初始化"))); return
        }
        if let length = pendingChunkLength {
            pendingChunkLength = nil
            guard length > 0 else { completion(.success(Data())); return }
            reader.readExactly(length + Shadowsocks2022.tagLength) { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error): completion(.failure(error))
                case .success(let sealed):
                    do { completion(.success(try self.receiveCipher!.open(sealed))) }
                    catch { completion(.failure(error)) }
                }
            }
            return
        }
        reader.readExactly(2 + Shadowsocks2022.tagLength) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let sealed):
                do {
                    let lengthBytes = try self.receiveCipher!.open(sealed)
                    let length = Int(lengthBytes[lengthBytes.startIndex]) << 8
                        | Int(lengthBytes[lengthBytes.startIndex + 1])
                    self.pendingChunkLength = length
                    self.readChunk(completion: completion)
                } catch { completion(.failure(error)) }
            }
        }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        transport.cancel()
    }
}

// MARK: - UDP (SIP022 datagrams)

import CommonCrypto

extension Shadowsocks2022 {
    /// SIP022 defines two structurally different datagram constructions.
    ///
    /// The AES methods put an unauthenticated 16-byte "separate header" —
    /// session ID and packet ID — at offset 0, encrypted as a single AES-ECB
    /// block with the PSK, and derive a per-session subkey for the body. The
    /// chacha method has no separate header at all: a 24-byte nonce travels in
    /// the clear and the whole body, session ID included, is sealed with
    /// XChaCha20-Poly1305 under the PSK directly.
    enum DatagramLayout {
        case separateHeader     // 2022-blake3-aes-*-gcm
        case merged             // 2022-blake3-chacha20-poly1305
    }

    static func layout(for method: Method) -> DatagramLayout {
        method == .chacha20Poly1305 ? .merged : .separateHeader
    }

    /// Everything a client needs to read back from a server datagram.
    struct DatagramPacket: Equatable {
        var sessionID: Data
        var packetID: UInt64
        var type: UInt8
        var timestamp: UInt64
        /// Present only on server packets: the client session ID being answered.
        var echoedClientSession: Data?
        var target: RequestTarget
        var payload: Data
    }

    /// Builds a client datagram for `target`.
    static func encodeDatagram(chain: KeyChain, method: Method,
                               sessionID: Data, packetID: UInt64,
                               timestamp: UInt64, target: RequestTarget,
                               payload: Data, padding: Int = 0) throws -> Data {
        precondition(sessionID.count == 8)
        var body = Data()
        if layout(for: method) == .merged {
            // The chacha construction authenticates the session and packet IDs
            // as part of the body; the AES one carries them outside it.
            body.append(sessionID)
            appendBigEndian(packetID, to: &body)
        }
        body.append(0x00)                       // client packet
        appendBigEndian(timestamp, to: &body)
        let clamped = max(0, min(padding, maximumPadding))
        body.append(UInt8(truncatingIfNeeded: clamped >> 8))
        body.append(UInt8(truncatingIfNeeded: clamped))
        body.append(Data(repeating: 0, count: clamped))
        body.append(try addressBytes(host: target.host, port: target.port))
        body.append(payload)

        switch layout(for: method) {
        case .merged:
            let nonce = secureRandom(count: XChaCha20Poly1305.nonceLength)
            var out = nonce
            // The chacha layout keys straight off the PSK with no derivation,
            // and rejects identity headers outright, so the chain is a single
            // key here by construction.
            out.append(try XChaCha20Poly1305.seal(body, key: chain.session, nonce: nonce))
            return out
        case .separateHeader:
            var header = sessionID
            appendBigEndian(packetID, to: &header)
            let subkey = udpSessionSubkey(preSharedKey: chain.session,
                                          sessionID: sessionID, method: method)
            // The nonce is bytes 4..<16 of the separate header while it is still
            // in the clear; the header is encrypted last, after the body has
            // been sealed. Taking these bytes from the ciphertext instead still
            // round-trips against ourselves, so only a known-answer test can
            // catch it — and every real server rejects the result.
            let nonce = Data(header.dropFirst(4))
            // Outbound, the separate header is encrypted with the *first* key in
            // the chain — the one the nearest relay holds. Inbound it is
            // decrypted with the last. Using one key for both directions works
            // for a single PSK and silently breaks the moment a relay appears.
            var out = try aesECBBlock(header, key: chain.all[0], encrypt: true)
            out.append(try udpIdentityHeaders(chain: chain, plainSeparateHeader: header))
            out.append(try Cipher.seal(body, key: subkey, method: method, nonce: nonce))
            return out
        }
    }

    /// Parses a server datagram, verifying everything the spec requires of a
    /// client: packet type, timestamp window, and — for the AES layout — that
    /// the answer belongs to this client's session.
    static func decodeDatagram(_ data: Data, chain: KeyChain, method: Method,
                               clientSessionID: Data, now: UInt64) throws -> DatagramPacket {
        let body: Data
        var sessionID = Data()
        var packetID: UInt64 = 0
        switch layout(for: method) {
        case .merged:
            guard data.count > XChaCha20Poly1305.nonceLength else {
                throw NativeOutboundError.protocolError("SIP022 数据报短于 nonce")
            }
            let nonce = Data(data.prefix(XChaCha20Poly1305.nonceLength))
            let sealed = Data(data.dropFirst(XChaCha20Poly1305.nonceLength))
            body = try XChaCha20Poly1305.open(sealed, key: chain.session, nonce: nonce)
        case .separateHeader:
            guard data.count > 16 else {
                throw NativeOutboundError.protocolError("SIP022 数据报短于独立头")
            }
            // Replies carry no identity headers and are always addressed to
            // the last key in the chain; relays pass them through untouched.
            let header = try aesECBBlock(Data(data.prefix(16)), key: chain.session, encrypt: false)
            sessionID = Data(header.prefix(8))
            packetID = readBigEndian(Data(header.dropFirst(8)))
            let subkey = udpSessionSubkey(preSharedKey: chain.session,
                                          sessionID: sessionID, method: method)
            // Bytes 4..<16 of the *decrypted* header, matching the sender.
            let nonce = Data(header.dropFirst(4))
            body = try Cipher.open(Data(data.dropFirst(16)), key: subkey,
                                   method: method, nonce: nonce)
        }

        var cursor = 0
        func take(_ count: Int, _ what: String) throws -> Data {
            guard cursor + count <= body.count else {
                throw NativeOutboundError.protocolError("SIP022 数据报在读取\(what)时越界")
            }
            defer { cursor += count }
            return Data(body[(body.startIndex + cursor)..<(body.startIndex + cursor + count)])
        }
        if layout(for: method) == .merged {
            sessionID = try take(8, "会话 ID")
            packetID = readBigEndian(try take(8, "包 ID"))
        }
        let type = try take(1, "类型").first!
        guard type == 0x01 else {
            throw NativeOutboundError.protocolError(
                "SIP022 数据报类型为 0x\(String(type, radix: 16))，应为 0x01")
        }
        let timestamp = readBigEndian(try take(8, "时间戳"))
        let skew = timestamp > now ? timestamp - now : now - timestamp
        guard skew <= UInt64(maximumTimestampSkew) else {
            throw NativeOutboundError.protocolError("SIP022 数据报时间戳相差 \(skew) 秒")
        }
        // The echoed client session is the datagram analogue of the TCP
        // request-salt echo: without checking it, a datagram from any other
        // session would be accepted as an answer to this one.
        let echoed = try take(8, "回显的客户端会话 ID")
        guard constantTimeEquals(echoed, clientSessionID) else {
            throw NativeOutboundError.protocolError("SIP022 数据报未回显本会话 ID")
        }
        let paddingLength = Int(readBigEndian16(try take(2, "填充长度")))
        _ = try take(paddingLength, "填充")

        let atyp = try take(1, "地址类型").first!
        let host: String
        switch atyp {
        case 0x01:
            let raw = try take(4, "IPv4 地址")
            host = raw.map(String.init).joined(separator: ".")
        case 0x03:
            let length = Int(try take(1, "域名长度").first!)
            guard let name = String(data: try take(length, "域名"), encoding: .utf8) else {
                throw NativeOutboundError.protocolError("SIP022 数据报域名不是合法 UTF-8")
            }
            host = name
        case 0x04:
            let raw = try take(16, "IPv6 地址")
            var address = in6_addr()
            _ = withUnsafeMutableBytes(of: &address) { raw.copyBytes(to: $0) }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                throw NativeOutboundError.protocolError("SIP022 数据报 IPv6 地址无效")
            }
            host = String(cString: buffer)
        default:
            throw NativeOutboundError.protocolError("SIP022 数据报地址类型 0x\(String(atyp, radix: 16)) 无效")
        }
        let port = readBigEndian16(try take(2, "端口"))
        let payload = Data(body[(body.startIndex + cursor)...])
        return DatagramPacket(sessionID: sessionID, packetID: packetID, type: type,
                              timestamp: timestamp, echoedClientSession: echoed,
                              target: RequestTarget(host: host, port: port,
                                                    protocolName: "UDP"),
                              payload: payload)
    }

    /// Random padding for a datagram, applied only to DNS.
    ///
    /// A DNS query has a very distinctive length, and on UDP the ciphertext is
    /// the same size as the plaintext, so an observer can pick queries out of a
    /// stream by size alone. The reference client pads only port 53, and only
    /// while the packet is still short enough for padding to fit under the
    /// 900-byte cap — padding everything would be a far louder signal than
    /// padding nothing.
    static func datagramPadding(port: UInt16, payloadLength: Int) -> Int {
        guard port == 53, payloadLength < maximumPadding else { return 0 }
        return Int.random(in: 1...(maximumPadding - payloadLength))
    }

    static func udpSessionSubkey(preSharedKey psk: Data, sessionID: Data,
                                 method: Method) -> Data {
        let material = [UInt8](psk) + [UInt8](sessionID)
        return Data(BLAKE3.deriveKey(context: sessionSubkeyContext, keyMaterial: material,
                                     count: method.keyLength))
    }

    /// One raw AES block. CryptoKit exposes no unauthenticated block cipher, and
    /// PKCS#7 padding must stay off — it would emit 32 bytes and corrupt every
    /// datagram.
    static func aesECBBlock(_ block: Data, key: Data, encrypt: Bool) throws -> Data {
        guard block.count == 16 else {
            throw NativeOutboundError.crypto("AES-ECB 输入必须为 16 字节")
        }
        var output = Data(count: 16)
        var moved = 0
        let status = output.withUnsafeMutableBytes { outBytes in
            block.withUnsafeBytes { inBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                            keyBytes.baseAddress, key.count, nil,
                            inBytes.baseAddress, 16,
                            outBytes.baseAddress, 16, &moved)
                }
            }
        }
        guard status == kCCSuccess, moved == 16 else {
            throw NativeOutboundError.crypto("AES-ECB 处理失败（状态 \(status)）")
        }
        return output
    }

    static func appendBigEndian(_ value: UInt64, to data: inout Data) {
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    static func readBigEndian(_ data: Data) -> UInt64 {
        data.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    }

    static func readBigEndian16(_ data: Data) -> UInt16 {
        UInt16(truncatingIfNeeded: readBigEndian(data))
    }
}

/// Client UDP session for SIP022.
///
/// One socket to the server carries every destination, which is why the target
/// travels inside each datagram rather than being fixed at connect time.
final class Shadowsocks2022DatagramSession: NativeOutboundDatagramSession {
    private let method: Shadowsocks2022.Method
    private let chain: Shadowsocks2022.KeyChain
    private let sessionID: Data
    private let connection: NWConnection
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private let lock = NSLock()
    private var packetID: UInt64 = 0
    private var cancelled = false

    init(policy: ProxyPolicy, queue: DispatchQueue,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) throws {
        guard let raw = policy.parameters["cipher"] ?? policy.parameters["encrypt-method"],
              let method = Shadowsocks2022.method(named: raw) else {
            throw NativeOutboundError.unsupported("不是 Shadowsocks 2022 加密方式")
        }
        guard let password = policy.parameters["password"], !password.isEmpty else {
            throw NativeOutboundError.protocolError("Shadowsocks 2022 缺少 PSK")
        }
        guard let host = policy.host, let port = policy.port,
              let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw NativeOutboundError.protocolError("Shadowsocks 2022 服务器地址无效")
        }
        self.method = method
        chain = try Shadowsocks2022.keyChain(password: password, method: method)
        // Fresh per session and never reused: the server tracks it to bind
        // answers to this client.
        sessionID = secureRandom(count: 8)
        receiveHandler = receive
        failureHandler = failure

        let parameters = NWParameters.udp
        if let interface = ProxyEngine.currentOutboundInterface {
            parameters.requiredInterface = interface
        }
        connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort,
                                  using: parameters)
        connection.start(queue: queue)
        receiveLoop()
    }

    func send(_ payload: Data, to target: RequestTarget) {
        lock.lock()
        if cancelled { lock.unlock(); return }
        let identifier = packetID
        packetID &+= 1
        lock.unlock()
        do {
            let datagram = try Shadowsocks2022.encodeDatagram(
                chain: chain, method: method, sessionID: sessionID,
                packetID: identifier,
                timestamp: UInt64(max(0, Int64(Date().timeIntervalSince1970))),
                target: target, payload: payload,
                padding: Shadowsocks2022.datagramPadding(port: target.port,
                                                         payloadLength: payload.count))
            connection.send(content: datagram, completion: .contentProcessed { [weak self] error in
                if let error { self?.failureHandler(error) }
            })
        } catch {
            failureHandler(error)
        }
    }

    private func receiveLoop() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            self.lock.lock(); let stopped = self.cancelled; self.lock.unlock()
            guard !stopped else { return }
            if let error { self.failureHandler(error); return }
            if let data, !data.isEmpty {
                do {
                    let packet = try Shadowsocks2022.decodeDatagram(
                        data, chain: self.chain, method: self.method,
                        clientSessionID: self.sessionID,
                        now: UInt64(max(0, Int64(Date().timeIntervalSince1970))))
                    self.receiveHandler(packet.target, packet.payload)
                } catch {
                    // A datagram that fails to authenticate is dropped, not
                    // reported: on a UDP socket anyone can send one, and
                    // tearing down the session would hand any host on the path
                    // a way to kill it.
                    nativeDebug("SIP022 UDP 丢弃无效数据报：\(error.localizedDescription)")
                }
            }
            self.receiveLoop()
        }
    }

    func cancel() {
        lock.lock()
        if cancelled { lock.unlock(); return }
        cancelled = true
        lock.unlock()
        connection.cancel()
    }
}

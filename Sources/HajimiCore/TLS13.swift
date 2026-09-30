import CryptoKit
import Foundation

// MARK: - Overview

/// TLS 1.3 client core (RFC 8446): the record layer, the key schedule, handshake
/// message decoding, transcript maintenance, and just enough DER to read a leaf
/// certificate.
///
/// Why any of this is hand-written: macOS exposes no API that can place bytes
/// into a ClientHello, and none that hands back the ephemeral `key_share`
/// private key. REALITY needs both — its authentication payload lives inside
/// `legacy_session_id`, and the key that seals it comes from ECDH between *that*
/// ephemeral private key and the server's static public key. `tls_options.h`
/// exports three functions and `SecProtocolOptions` can set ALPN, versions,
/// ciphersuites and SNI; there is no hook for either requirement, so the
/// handshake is written here instead.
///
/// Deliberately absent, and each omission is a decision rather than a gap:
/// PSK / 0-RTT / session resumption (REALITY servers set
/// `SessionTicketsDisabled`, and a PSK binder is computed over a *truncated*
/// ClientHello, which is unsatisfiable when REALITY's AEAD covers the whole
/// finished message), HelloRetryRequest (a REALITY server cannot forward one —
/// it requires a `server_share` and falls back to the real site otherwise),
/// client certificates, certificate compression, renegotiation, RSA/ECDSA
/// signature verification, and certificate chain building. An unused branch is
/// a branch that is never exercised and therefore always wrong.
///
/// # Interface expected from the fingerprint layer
///
/// This file never builds a ClientHello. It takes bytes that are already final.
/// That is not a style preference: REALITY seals the complete ClientHello as
/// AEAD associated data, so appending padding, re-randomising GREASE or adding
/// an extension *after* the seal produces an authentication failure whose only
/// symptom is that the server silently proxies the connection to the real
/// website. The two values this file needs are:
///
///     // Produced by TLS13Fingerprint.chromeClientHello(_:) -> Data
///     let material = TLS13.ClientHelloMaterial(
///         message: <complete client_hello handshake message, 4-byte header included,
///                   byte-for-byte what goes on the wire>,
///         ephemeralPrivateKey: <Curve25519.KeyAgreement.PrivateKey whose public key is
///                               the X25519 entry inside that message's key_share>)
///
/// The transport above is responsible for framing that message itself, because
/// the record header of the first flight is part of the fingerprint:
///
///     transport.send(try TLS13.plaintextRecord(contentType: .handshake,
///                                              legacyVersion: TLS13.legacyRecordVersionInitial,
///                                              fragment: material.message))
///
/// `legacyRecordVersionInitial` is 0x0301, not 0x0303. Both handshake fine; only
/// one matches a browser.
///
/// `changeCipherSpecRecord` is deliberately *not* part of that first send. uTLS
/// calls `sendDummyChangeCipherSpec` only after the ServerHello has been
/// processed (`handshake_client_tls13.go`), so the record belongs to the
/// client's second flight, immediately ahead of the encrypted Finished. Gluing
/// it behind the ClientHello handshakes perfectly well and buys a distinguisher
/// for nothing: no browser puts those six bytes in the first packet.
/// `TLS13Fingerprint` documents the same rule for the same six bytes.
///
/// # Notes that only show up as a Finished mismatch
///
///   * The transcript is fed the **wire bytes**. For the ClientHello that means
///     the version whose `legacy_session_id` holds REALITY's *ciphertext*, not
///     the zeroed copy used as AEAD associated data. For the ServerHello it
///     means the bytes as received, whose `key_share` the REALITY server has
///     already rewritten in place. Reusing the zeroed AAD buffer here fails at
///     Finished with no other signal.
///   * A record may carry several handshake messages, and one message may span
///     several records. REALITY merges EncryptedExtensions + Certificate +
///     CertificateVerify + Finished into one record whenever the upstream site's
///     EncryptedExtensions record exceeds 512 bytes.
///   * The server sends a dummy `change_cipher_spec` record of its own right
///     after the ServerHello, unconditionally. It contributes nothing to the
///     transcript, is not encrypted, and is not a handshake message:
///     `RecordReader` hands it back with `contentType == 20` and the caller
///     must drop it without advancing any state. Feeding it to the protector or
///     to the transcript breaks Finished.
///   * Zero-length `application_data` records are legal and REALITY emits them
///     on purpose: its forged NewSessionTicket is an inner plaintext of
///     `[0x17, 0x00...]`, and it pads the post-handshake stream with more of the
///     same to match the real site's record lengths. Treating an empty record as
///     end-of-stream drops the connection the instant the handshake completes.
enum TLS13 {

    // MARK: - Wire constants

    static let recordHeaderLength = 5
    /// RFC 8446 §5.1: TLSPlaintext.length must not exceed 2^14.
    static let maximumPlaintextLength = 1 << 14
    /// §5.2: TLSCiphertext.length may add 255 bytes of padding plus the tag.
    static let maximumCiphertextLength = (1 << 14) + 256
    /// A single handshake message. The wire format allows 2^24-1; nothing this
    /// client accepts is anywhere near that, and an unbounded value lets a peer
    /// make us buffer 16 MB before we notice.
    static let maximumHandshakeMessageLength = 1 << 18

    /// uTLS writes 0x0301 for the first record because `c.vers` is still zero at
    /// that point; every later record uses 0x0303. Servers ignore the field, so
    /// getting it wrong costs nothing except the fingerprint.
    static let legacyRecordVersionInitial: UInt16 = 0x0301
    static let legacyRecordVersion: UInt16 = 0x0303
    static let versionTLS12: UInt16 = 0x0303
    static let versionTLS13: UInt16 = 0x0304

    /// The dummy record a middlebox-compatibility handshake sends. It goes out
    /// with the client's *second* flight — after the ServerHello has been
    /// processed, immediately before the encrypted Finished — because that is
    /// where uTLS puts it. Not sending it at all still handshakes; it also makes
    /// the flow stop looking like a browser, and the REALITY server only pads
    /// its records when the upstream site answered with a CCS of its own.
    static let changeCipherSpecRecord = Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])

    enum ContentType: UInt8 {
        case changeCipherSpec = 20
        case alert = 21
        case handshake = 22
        case applicationData = 23
    }

    enum HandshakeType: UInt8 {
        case clientHello = 1
        case serverHello = 2
        case newSessionTicket = 4
        case endOfEarlyData = 5
        case encryptedExtensions = 8
        case certificate = 11
        case certificateRequest = 13
        case certificateVerify = 15
        case finished = 20
        case keyUpdate = 24
        case messageHash = 254
    }

    enum ExtensionType {
        static let serverName: UInt16 = 0x0000
        static let supportedGroups: UInt16 = 0x000A
        static let alpn: UInt16 = 0x0010
        static let supportedVersions: UInt16 = 0x002B
        static let keyShare: UInt16 = 0x0033
        static let preSharedKey: UInt16 = 0x0029
        static let earlyData: UInt16 = 0x002A
        static let cookie: UInt16 = 0x002C
    }

    enum NamedGroup {
        static let x25519: UInt16 = 0x001D
        static let x25519MLKEM768: UInt16 = 0x11EC
    }

    enum SignatureScheme {
        static let ed25519: UInt16 = 0x0807
    }

    /// RFC 8446 §4.1.3: a ServerHello carrying this exact `random` is a
    /// HelloRetryRequest wearing a ServerHello's message type. It is
    /// SHA-256("HelloRetryRequest"). Detecting it matters because a REALITY
    /// server cannot produce one — if the upstream site answers with HRR the
    /// server abandons authentication and forwards the connection verbatim, so
    /// an HRR arriving here means we are already talking to the real website.
    static let helloRetryRequestRandom = Data([
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ])

    /// What the caller hands over from the fingerprint layer. Keeping the two
    /// values in one type is the whole point: a private key that does not match
    /// the `key_share` inside `message` produces a working TLS session and a
    /// failed REALITY authentication, which is invisible from the client side.
    struct ClientHelloMaterial {
        let message: Data
        let ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey

        init(message: Data, ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey) {
            self.message = message
            self.ephemeralPrivateKey = ephemeralPrivateKey
        }
    }

    // MARK: - Hashes

    /// TLS 1.3 parameterises everything on the cipher suite's hash. The two
    /// CryptoKit types are unrelated, so the switch lives here once instead of
    /// at every call site — and every length below is derived from
    /// `byteCount` rather than written as 32, which is the mistake that makes
    /// SHA-384 suites fail only at Finished.
    enum HashFunction {
        case sha256
        case sha384

        var length: Int {
            switch self {
            case .sha256: return SHA256.byteCount
            case .sha384: return SHA384.byteCount
            }
        }

        func hash(_ data: Data) -> Data {
            switch self {
            case .sha256: return Data(SHA256.hash(data: data))
            case .sha384: return Data(SHA384.hash(data: data))
            }
        }

        func hmac(key: Data, message: Data) -> Data {
            let symmetric = SymmetricKey(data: key.isEmpty ? Data(repeating: 0, count: length) : key)
            switch self {
            case .sha256:
                return Data(HMAC<SHA256>.authenticationCode(for: message, using: symmetric))
            case .sha384:
                return Data(HMAC<SHA384>.authenticationCode(for: message, using: symmetric))
            }
        }

        var emptyHash: Data { hash(Data()) }
    }

    /// The running hash over every handshake message, in the order they appear
    /// on the wire, header bytes included and record boundaries ignored.
    ///
    /// `value` deliberately does not finalise the live state: TLS needs the hash
    /// of a *prefix* at four different points (before EncryptedExtensions for
    /// the handshake secrets, through CertificateVerify for the server's
    /// Finished, through the server's Finished for the application secrets,
    /// through the client's Finished for the resumption secret) and the stream
    /// keeps growing afterwards. CryptoKit's hashers are value types, so a copy
    /// is a snapshot.
    struct Transcript {
        let hashFunction: HashFunction
        private var sha256 = SHA256()
        private var sha384 = SHA384()

        init(_ hashFunction: HashFunction) {
            self.hashFunction = hashFunction
        }

        mutating func update(_ data: Data) {
            switch hashFunction {
            case .sha256: sha256.update(data: data)
            case .sha384: sha384.update(data: data)
            }
        }

        var value: Data {
            switch hashFunction {
            case .sha256:
                let copy = sha256
                return Data(copy.finalize())
            case .sha384:
                let copy = sha384
                return Data(copy.finalize())
            }
        }
    }

    // MARK: - AEAD

    enum AEAD {
        case aes128GCM
        case aes256GCM
        case chaCha20Poly1305

        var keyLength: Int {
            switch self {
            case .aes128GCM: return 16
            case .aes256GCM, .chaCha20Poly1305: return 32
            }
        }

        /// Fixed by RFC 8446 §5.3 for every suite defined there, which is why
        /// the sequence number can be XORed into the low 8 bytes unconditionally.
        var nonceLength: Int { 12 }
        var tagLength: Int { 16 }

        func seal(key: Data, nonce: Data, additionalData: Data, plaintext: Data) throws -> Data {
            try validate(key: key, nonce: nonce)
            let symmetric = SymmetricKey(data: key)
            do {
                switch self {
                case .aes128GCM, .aes256GCM:
                    let box = try AES.GCM.seal(plaintext, using: symmetric,
                                               nonce: AES.GCM.Nonce(data: nonce),
                                               authenticating: additionalData)
                    return box.ciphertext + box.tag
                case .chaCha20Poly1305:
                    let box = try ChaChaPoly.seal(plaintext, using: symmetric,
                                                  nonce: ChaChaPoly.Nonce(data: nonce),
                                                  authenticating: additionalData)
                    return box.ciphertext + box.tag
                }
            } catch {
                throw NativeOutboundError.crypto("TLS 1.3 记录加密失败：\(error.localizedDescription)")
            }
        }

        func open(key: Data, nonce: Data, additionalData: Data, ciphertext: Data) throws -> Data {
            try validate(key: key, nonce: nonce)
            guard ciphertext.count >= tagLength else {
                throw NativeOutboundError.protocolError(
                    "TLS 1.3 密文长度 \(ciphertext.count) 小于认证标签长度 \(tagLength)")
            }
            let symmetric = SymmetricKey(data: key)
            let body = ciphertext.prefix(ciphertext.count - tagLength)
            let tag = ciphertext.suffix(tagLength)
            do {
                switch self {
                case .aes128GCM, .aes256GCM:
                    let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                                                    ciphertext: body, tag: tag)
                    return try AES.GCM.open(box, using: symmetric, authenticating: additionalData)
                case .chaCha20Poly1305:
                    let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce),
                                                       ciphertext: body, tag: tag)
                    return try ChaChaPoly.open(box, using: symmetric, authenticating: additionalData)
                }
            } catch {
                throw NativeOutboundError.crypto("TLS 1.3 记录解密失败（认证标签不匹配或密钥错误）")
            }
        }

        private func validate(key: Data, nonce: Data) throws {
            guard key.count == keyLength else {
                throw NativeOutboundError.crypto(
                    "TLS 1.3 AEAD 密钥必须是 \(keyLength) 字节，实际 \(key.count) 字节")
            }
            guard nonce.count == nonceLength else {
                throw NativeOutboundError.crypto(
                    "TLS 1.3 AEAD nonce 必须是 \(nonceLength) 字节，实际 \(nonce.count) 字节")
            }
        }
    }

    // MARK: - Cipher suites

    /// The three suites RFC 8446 defines. Offering only 0x1301 would be enough
    /// for any compliant server (§9.1 makes it mandatory) and enough for
    /// REALITY, which only checks that the suite the *upstream site* picked is a
    /// known TLS 1.3 one — but a ClientHello listing a single TLS 1.3 suite is a
    /// glaring fingerprint anomaly, so all three are supported here.
    enum CipherSuite: UInt16, CaseIterable {
        case aes128GCMSHA256 = 0x1301
        case aes256GCMSHA384 = 0x1302
        case chaCha20Poly1305SHA256 = 0x1303

        var hashFunction: HashFunction {
            switch self {
            case .aes128GCMSHA256, .chaCha20Poly1305SHA256: return .sha256
            case .aes256GCMSHA384: return .sha384
            }
        }

        var aead: AEAD {
            switch self {
            case .aes128GCMSHA256: return .aes128GCM
            case .aes256GCMSHA384: return .aes256GCM
            case .chaCha20Poly1305SHA256: return .chaCha20Poly1305
            }
        }

        static func named(_ identifier: UInt16) throws -> CipherSuite {
            guard let suite = CipherSuite(rawValue: identifier) else {
                throw NativeOutboundError.protocolError(
                    String(format: "TLS 1.3 服务端选择了不支持的 cipher suite 0x%04X", identifier))
            }
            return suite
        }
    }

    // MARK: - HKDF

    /// RFC 5869 plus RFC 8446 §7.1's label wrapper.
    ///
    /// Note for anyone reading this next to the REALITY code: REALITY's AuthKey
    /// uses *bare* RFC 5869 HKDF with `info = "REALITY"`, not `expandLabel`.
    /// Feeding it through here adds the `tls13 ` prefix and the HkdfLabel
    /// structure and fails authentication silently.
    enum HKDF {
        static func extract(_ hashFunction: HashFunction, salt: Data, inputKeyMaterial: Data) -> Data {
            // RFC 5869 §2.2: an absent salt is HashLen zero bytes. TLS always
            // passes an explicit one, but the substitution keeps callers honest.
            let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: hashFunction.length) : salt
            return hashFunction.hmac(key: effectiveSalt, message: inputKeyMaterial)
        }

        static func expand(_ hashFunction: HashFunction, pseudoRandomKey: Data,
                           info: Data, count: Int) throws -> Data {
            guard count > 0 else { return Data() }
            guard count <= 255 * hashFunction.length else {
                throw NativeOutboundError.crypto("TLS 1.3 HKDF-Expand 输出长度 \(count) 超出上限")
            }
            var output = Data()
            var block = Data()
            var counter: UInt8 = 1
            while output.count < count {
                var message = block
                message.append(info)
                message.append(counter)
                block = hashFunction.hmac(key: pseudoRandomKey, message: message)
                output.append(block)
                // The counter is a single octet and 255 is the last legal value;
                // the length guard above means the loop is already done by then.
                if counter == 255 { break }
                counter += 1
            }
            return Data(output.prefix(count))
        }

        /// The `HkdfLabel` structure of RFC 8446 §7.1, verbatim:
        ///
        ///     uint16 length;
        ///     opaque label<7..255>  = "tls13 " + Label;
        ///     opaque context<0..255>;
        static func hkdfLabel(count: Int, label: String, context: Data) throws -> Data {
            let full = Data("tls13 ".utf8) + Data(label.utf8)
            guard full.count <= 255, context.count <= 255, count <= 0xFFFF else {
                throw NativeOutboundError.crypto("TLS 1.3 HkdfLabel 字段超长：label=\(label)")
            }
            var out = Data()
            out.append(UInt8(truncatingIfNeeded: count >> 8))
            out.append(UInt8(truncatingIfNeeded: count))
            out.append(UInt8(full.count))
            out.append(full)
            out.append(UInt8(context.count))
            out.append(context)
            return out
        }

        static func expandLabel(_ hashFunction: HashFunction, secret: Data, label: String,
                                context: Data, count: Int) throws -> Data {
            try expand(hashFunction, pseudoRandomKey: secret,
                       info: hkdfLabel(count: count, label: label, context: context), count: count)
        }

        /// `Derive-Secret(Secret, Label, Messages)` — the output is always one
        /// full hash length, and the context is the transcript hash rather than
        /// the messages themselves.
        static func deriveSecret(_ hashFunction: HashFunction, secret: Data, label: String,
                                 transcriptHash: Data) throws -> Data {
            try expandLabel(hashFunction, secret: secret, label: label,
                            context: transcriptHash, count: hashFunction.length)
        }
    }

    // MARK: - Key schedule

    struct TrafficKeys {
        let key: Data
        let iv: Data
    }

    /// Traffic keys depend on the suite and one secret, nothing else, so the
    /// record layer can build them without owning a whole key schedule.
    static func trafficKeys(suite: CipherSuite, from secret: Data) throws -> TrafficKeys {
        TrafficKeys(
            key: try HKDF.expandLabel(suite.hashFunction, secret: secret, label: "key",
                                      context: Data(), count: suite.aead.keyLength),
            iv: try HKDF.expandLabel(suite.hashFunction, secret: secret, label: "iv",
                                     context: Data(), count: suite.aead.nonceLength))
    }

    /// RFC 8446 §7.2, used when either side sends KeyUpdate.
    static func updatedTrafficSecret(suite: CipherSuite, from secret: Data) throws -> Data {
        try HKDF.expandLabel(suite.hashFunction, secret: secret, label: "traffic upd",
                             context: Data(), count: suite.hashFunction.length)
    }

    /// Which secret a traffic label hangs off. Getting this wrong (deriving
    /// `c ap traffic` from the handshake secret, say) yields keys that look
    /// perfectly well-formed and decrypt nothing.
    enum TrafficSecretLabel {
        case clientHandshake
        case serverHandshake
        case clientApplication
        case serverApplication
        case exporterMaster
        case resumptionMaster

        var label: String {
            switch self {
            case .clientHandshake: return "c hs traffic"
            case .serverHandshake: return "s hs traffic"
            case .clientApplication: return "c ap traffic"
            case .serverApplication: return "s ap traffic"
            case .exporterMaster: return "exp master"
            case .resumptionMaster: return "res master"
            }
        }

        var derivesFromMasterSecret: Bool {
            switch self {
            case .clientHandshake, .serverHandshake: return false
            case .clientApplication, .serverApplication, .exporterMaster, .resumptionMaster: return true
            }
        }
    }

    /// The three-stage ladder of RFC 8446 §7.1. Each `HKDF-Extract` is separated
    /// from the previous stage by a `Derive-Secret(..., "derived", "")`; skipping
    /// that step is the single most common way to produce a key schedule that is
    /// internally consistent and interoperates with nothing.
    struct KeySchedule {
        let suite: CipherSuite
        private(set) var earlySecret: Data
        private(set) var handshakeSecret: Data?
        private(set) var masterSecret: Data?

        var hashFunction: HashFunction { suite.hashFunction }

        /// Without a PSK the IKM is HashLen zero bytes, not an empty string.
        init(suite: CipherSuite, preSharedKey: Data? = nil) {
            self.suite = suite
            let zeros = Data(repeating: 0, count: suite.hashFunction.length)
            earlySecret = HKDF.extract(suite.hashFunction, salt: zeros,
                                       inputKeyMaterial: preSharedKey ?? zeros)
        }

        /// Feeds in the (EC)DHE output and derives both the handshake and the
        /// master secret. The master secret depends on nothing else, so there is
        /// no reason to make the caller remember a second step.
        mutating func advance(sharedSecret: Data) throws {
            let hash = suite.hashFunction
            let zeros = Data(repeating: 0, count: hash.length)
            let derivedForHandshake = try HKDF.deriveSecret(hash, secret: earlySecret,
                                                            label: "derived",
                                                            transcriptHash: hash.emptyHash)
            let handshake = HKDF.extract(hash, salt: derivedForHandshake,
                                         inputKeyMaterial: sharedSecret)
            let derivedForMaster = try HKDF.deriveSecret(hash, secret: handshake,
                                                         label: "derived",
                                                         transcriptHash: hash.emptyHash)
            handshakeSecret = handshake
            masterSecret = HKDF.extract(hash, salt: derivedForMaster, inputKeyMaterial: zeros)
        }

        func trafficSecret(_ which: TrafficSecretLabel, transcriptHash: Data) throws -> Data {
            let base: Data?
            if which.derivesFromMasterSecret {
                base = masterSecret
            } else {
                base = handshakeSecret
            }
            guard let secret = base else {
                throw NativeOutboundError.crypto(
                    "TLS 1.3 密钥调度尚未推进到可以推导 \(which.label) 的阶段")
            }
            return try HKDF.deriveSecret(suite.hashFunction, secret: secret,
                                         label: which.label, transcriptHash: transcriptHash)
        }

        func trafficKeys(from secret: Data) throws -> TrafficKeys {
            try TLS13.trafficKeys(suite: suite, from: secret)
        }

        func finishedKey(from secret: Data) throws -> Data {
            try HKDF.expandLabel(suite.hashFunction, secret: secret, label: "finished",
                                 context: Data(), count: suite.hashFunction.length)
        }

        /// `verify_data = HMAC(finished_key, Transcript-Hash(...))`. The hash is
        /// fed as a *message*, already digested — hashing it again produces a
        /// value both ends could agree on only if both made the same mistake.
        func verifyData(secret: Data, transcriptHash: Data) throws -> Data {
            suite.hashFunction.hmac(key: try finishedKey(from: secret), message: transcriptHash)
        }

        func updatedTrafficSecret(from secret: Data) throws -> Data {
            try TLS13.updatedTrafficSecret(suite: suite, from: secret)
        }

        /// §4.6.1. Present for completeness; this client never resumes.
        func resumptionPreSharedKey(resumptionMaster: Data, ticketNonce: Data) throws -> Data {
            try HKDF.expandLabel(suite.hashFunction, secret: resumptionMaster, label: "resumption",
                                 context: ticketNonce, count: suite.hashFunction.length)
        }
    }

    // MARK: - Records

    struct Record {
        let contentType: UInt8
        let legacyVersion: UInt16
        /// The five header bytes exactly as they arrived. They are the AEAD
        /// associated data, so they are kept rather than rebuilt — a rebuilt
        /// header that disagrees with the wire by one byte fails the tag check
        /// and looks like a key derivation bug.
        let header: Data
        let fragment: Data
    }

    static func plaintextRecord(contentType: ContentType, legacyVersion: UInt16,
                                fragment: Data) throws -> Data {
        guard fragment.count <= maximumPlaintextLength else {
            throw NativeOutboundError.protocolError(
                "TLS 1.3 明文记录长度 \(fragment.count) 超出 \(maximumPlaintextLength)")
        }
        var out = Data()
        out.append(contentType.rawValue)
        out.append(UInt8(truncatingIfNeeded: legacyVersion >> 8))
        out.append(UInt8(truncatingIfNeeded: legacyVersion))
        out.append(UInt8(truncatingIfNeeded: fragment.count >> 8))
        out.append(UInt8(truncatingIfNeeded: fragment.count))
        out.append(fragment)
        return out
    }

    /// Splits `TLSInnerPlaintext` = `content || content_type || zeros`.
    ///
    /// The scan must run from the end and skip *every* trailing zero, not just
    /// look at the last byte. REALITY pads each of its handshake records with
    /// zeros up to the byte length of the corresponding record from the real
    /// site, so the last byte is almost never the content type.
    static func splitInnerPlaintext(_ plaintext: Data) throws -> (contentType: UInt8, content: Data) {
        var index = plaintext.endIndex - 1
        while index >= plaintext.startIndex, plaintext[index] == 0 {
            index -= 1
        }
        guard index >= plaintext.startIndex else {
            throw NativeOutboundError.protocolError(
                "TLS 1.3 内层明文全为零填充，无法确定 content_type")
        }
        return (plaintext[index], Data(plaintext[plaintext.startIndex..<index]))
    }

    /// Pulls whole records off a byte stream. Incomplete input is left alone for
    /// the next read; nothing here interprets the payload.
    struct RecordReader {
        private var buffer: [UInt8] = []
        private var offset = 0

        init() {}

        mutating func append(_ data: Data) {
            buffer.append(contentsOf: data)
        }

        var pendingByteCount: Int { buffer.count - offset }

        /// Returns bytes not yet framed as records. XTLS Vision uses this at
        /// the exact record boundary where the peer starts writing inner TLS
        /// bytes directly onto the carrier.
        mutating func takePendingBytes() -> Data {
            guard offset < buffer.count else {
                buffer.removeAll(keepingCapacity: true); offset = 0; return Data()
            }
            let value = Data(buffer[offset...])
            buffer.removeAll(keepingCapacity: true); offset = 0
            return value
        }

        mutating func next() throws -> Record? {
            guard buffer.count - offset >= recordHeaderLength else {
                compact()
                return nil
            }
            let length = Int(buffer[offset + 3]) << 8 | Int(buffer[offset + 4])
            guard length <= maximumCiphertextLength else {
                throw NativeOutboundError.protocolError(
                    "TLS 1.3 记录长度 \(length) 超出上限 \(maximumCiphertextLength)")
            }
            guard buffer.count - offset >= recordHeaderLength + length else {
                compact()
                return nil
            }
            let header = Data(buffer[offset..<(offset + recordHeaderLength)])
            let start = offset + recordHeaderLength
            let record = Record(contentType: buffer[offset],
                                legacyVersion: UInt16(buffer[offset + 1]) << 8 | UInt16(buffer[offset + 2]),
                                header: header,
                                fragment: Data(buffer[start..<(start + length)]))
            offset = start + length
            if offset == buffer.count {
                buffer.removeAll(keepingCapacity: true)
                offset = 0
            }
            return record
        }

        private mutating func compact() {
            guard offset > 0 else { return }
            buffer.removeFirst(offset)
            offset = 0
        }
    }

    /// One direction's AEAD state: key, IV and sequence number.
    ///
    /// Sequence numbers are per direction and reset to zero on every key change,
    /// which is why this is an object per direction rather than a shared counter.
    final class RecordProtector {
        let suite: CipherSuite
        private var trafficSecret: Data
        private var key: Data
        private var iv: Data
        private(set) var sequenceNumber: UInt64 = 0

        init(suite: CipherSuite, trafficSecret: Data) throws {
            self.suite = suite
            self.trafficSecret = trafficSecret
            let keys = try TLS13.trafficKeys(suite: suite, from: trafficSecret)
            key = keys.key
            iv = keys.iv
        }

        /// `nonce = static_iv XOR seq`, the sequence number right-aligned in the
        /// IV as a big-endian 64-bit value. The IV itself never changes.
        func nonce(for sequence: UInt64) -> Data {
            var nonce = iv
            let base = nonce.endIndex - 8
            for byte in 0..<8 {
                nonce[base + byte] ^= UInt8(truncatingIfNeeded: sequence >> (8 * (7 - UInt64(byte))))
            }
            return nonce
        }

        private func advanceSequence() throws {
            guard sequenceNumber != UInt64.max else {
                // RFC 8446 §5.3 requires termination rather than wrapping; a
                // repeated nonce destroys the AEAD outright.
                throw NativeOutboundError.crypto("TLS 1.3 记录序号耗尽，必须重新协商密钥")
            }
            sequenceNumber += 1
        }

        func protect(contentType: ContentType, content: Data, paddingLength: Int = 0) throws -> Data {
            var inner = content
            inner.append(contentType.rawValue)
            if paddingLength > 0 { inner.append(Data(repeating: 0, count: paddingLength)) }
            // RFC 8446 §5.4: the limit is on the *encoded TLSInnerPlaintext* —
            // content plus the content-type byte plus the padding — and it is
            // 2^14 + 1. Bounding the ciphertext by 2^14 + 256 instead would wave
            // through 239 extra bytes of content, and the peer answers that with
            // record_overflow (§5.2) rather than with anything diagnosable.
            guard inner.count <= maximumPlaintextLength + 1 else {
                throw NativeOutboundError.protocolError(
                    "TLS 1.3 内层明文长度 \(inner.count)（含 content_type 与填充）超出上限 \(maximumPlaintextLength + 1)")
            }
            let length = inner.count + suite.aead.tagLength
            var header = Data([ContentType.applicationData.rawValue,
                               UInt8(truncatingIfNeeded: legacyRecordVersion >> 8),
                               UInt8(truncatingIfNeeded: legacyRecordVersion)])
            header.append(UInt8(truncatingIfNeeded: length >> 8))
            header.append(UInt8(truncatingIfNeeded: length))
            let sealed = try suite.aead.seal(key: key, nonce: nonce(for: sequenceNumber),
                                             additionalData: header, plaintext: inner)
            try advanceSequence()
            return header + sealed
        }

        /// Returns the inner content type and content. A zero-length
        /// `application_data` result is normal and must not be read as EOF.
        func unprotect(_ record: Record) throws -> (contentType: UInt8, content: Data) {
            guard record.contentType == ContentType.applicationData.rawValue else {
                throw NativeOutboundError.protocolError(
                    "TLS 1.3 密文记录的外层 content_type 应为 23，实际 \(record.contentType)")
            }
            let plaintext = try suite.aead.open(key: key, nonce: nonce(for: sequenceNumber),
                                                additionalData: record.header,
                                                ciphertext: record.fragment)
            try advanceSequence()
            return try splitInnerPlaintext(plaintext)
        }

        /// KeyUpdate: derive the next secret, rebuild key and IV, restart the
        /// sequence at zero.
        func updateKeys() throws {
            trafficSecret = try TLS13.updatedTrafficSecret(suite: suite, from: trafficSecret)
            let keys = try TLS13.trafficKeys(suite: suite, from: trafficSecret)
            key = keys.key
            iv = keys.iv
            sequenceNumber = 0
        }
    }

    // MARK: - Handshake reassembly

    struct HandshakeMessage {
        let type: UInt8
        let body: Data
        /// The complete message including its 4-byte header. This — not `body` —
        /// is what the transcript hash consumes.
        let raw: Data

        var handshakeType: HandshakeType? { HandshakeType(rawValue: type) }
    }

    /// Reassembles handshake messages from record fragments. Both directions of
    /// the mismatch are real: one record may hold several messages (REALITY
    /// merges the whole server flight into one when the upstream site's
    /// EncryptedExtensions record is larger than 512 bytes) and one message may
    /// span several records (a large certificate chain always does).
    struct HandshakeReader {
        private var buffer: [UInt8] = []
        private var offset = 0

        init() {}

        mutating func append(_ fragment: Data) {
            buffer.append(contentsOf: fragment)
        }

        var pendingByteCount: Int { buffer.count - offset }

        mutating func next() throws -> HandshakeMessage? {
            guard buffer.count - offset >= 4 else {
                compact()
                return nil
            }
            let length = Int(buffer[offset + 1]) << 16 | Int(buffer[offset + 2]) << 8 | Int(buffer[offset + 3])
            guard length <= maximumHandshakeMessageLength else {
                throw NativeOutboundError.protocolError(
                    "TLS 1.3 握手消息长度 \(length) 超出上限 \(maximumHandshakeMessageLength)")
            }
            guard buffer.count - offset >= 4 + length else {
                compact()
                return nil
            }
            let raw = Data(buffer[offset..<(offset + 4 + length)])
            let message = HandshakeMessage(type: buffer[offset],
                                           body: Data(raw.dropFirst(4)),
                                           raw: raw)
            offset += 4 + length
            if offset == buffer.count {
                buffer.removeAll(keepingCapacity: true)
                offset = 0
            }
            return message
        }

        private mutating func compact() {
            guard offset > 0 else { return }
            buffer.removeFirst(offset)
            offset = 0
        }
    }

    // MARK: - Byte reader

    /// A bounds-checked cursor. Every parser below runs through it so that a
    /// truncated message is an error rather than a trap.
    struct ByteReader {
        private let bytes: [UInt8]
        private var index = 0
        private let what: String

        init(_ data: Data, describing what: String) {
            bytes = Array(data)
            self.what = what
        }

        var remaining: Int { bytes.count - index }
        var isEmpty: Bool { remaining == 0 }

        private func need(_ count: Int) throws {
            guard remaining >= count else {
                throw NativeOutboundError.protocolError(
                    "TLS 1.3 \(what) 被截断：还需要 \(count) 字节，只剩 \(remaining) 字节")
            }
        }

        mutating func uint8() throws -> UInt8 {
            try need(1)
            defer { index += 1 }
            return bytes[index]
        }

        mutating func uint16() throws -> UInt16 {
            try need(2)
            defer { index += 2 }
            return UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
        }

        mutating func uint24() throws -> Int {
            try need(3)
            defer { index += 3 }
            return Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
        }

        mutating func uint32() throws -> UInt32 {
            try need(4)
            defer { index += 4 }
            return UInt32(bytes[index]) << 24 | UInt32(bytes[index + 1]) << 16
                | UInt32(bytes[index + 2]) << 8 | UInt32(bytes[index + 3])
        }

        mutating func take(_ count: Int) throws -> Data {
            guard count >= 0 else {
                throw NativeOutboundError.protocolError("TLS 1.3 \(what) 长度为负")
            }
            try need(count)
            defer { index += count }
            return Data(bytes[index..<(index + count)])
        }

        mutating func vector8() throws -> Data { try take(Int(try uint8())) }
        mutating func vector16() throws -> Data { try take(Int(try uint16())) }
        mutating func vector24() throws -> Data { try take(try uint24()) }

        mutating func rest() throws -> Data { try take(remaining) }
    }

    // MARK: - Extensions

    struct Extension {
        let type: UInt16
        let data: Data
    }

    /// Parses an `Extension extensions<..>` body — the caller has already
    /// stripped the uint16 total length.
    static func parseExtensions(_ data: Data, describing what: String) throws -> [Extension] {
        var reader = ByteReader(data, describing: what)
        var result: [Extension] = []
        while !reader.isEmpty {
            let type = try reader.uint16()
            let body = try reader.vector16()
            result.append(Extension(type: type, data: body))
        }
        return result
    }

    static func firstExtension(_ extensions: [Extension], type: UInt16) -> Data? {
        extensions.first { $0.type == type }?.data
    }

    // MARK: - Handshake messages

    struct ServerHello {
        /// RFC 8446 §4.2.1: once `supported_versions` is present a client MUST
        /// ignore this field, so nothing here checks it. It is exposed only
        /// because a value other than 0x0303 says the peer is not the TLS 1.3
        /// stack it claims to be.
        let legacyVersion: UInt16
        let random: Data
        /// §4.1.3 makes comparing this against the ClientHello's
        /// `legacy_session_id` a MUST, and this file never sees the ClientHello,
        /// so the caller has to do it. Under REALITY the echoed value is our own
        /// authentication ciphertext coming back through the upstream site; a
        /// mismatch means the bytes were rewritten in flight.
        let legacySessionIDEcho: Data
        let cipherSuite: CipherSuite
        let legacyCompressionMethod: UInt8
        let extensions: [Extension]
        /// From `supported_versions`; a TLS 1.3 server must send 0x0304 there
        /// and leave `legacyVersion` at 0x0303.
        let selectedVersion: UInt16
        let keyShareGroup: UInt16
        /// The server's `key_exchange`. For X25519 this is the 32-byte public
        /// key that a REALITY server has substituted for the real site's.
        let keyShareData: Data
        let isHelloRetryRequest: Bool

        init(_ body: Data) throws {
            var reader = ByteReader(body, describing: "ServerHello")
            legacyVersion = try reader.uint16()
            random = try reader.take(32)
            legacySessionIDEcho = try reader.vector8()
            cipherSuite = try CipherSuite.named(try reader.uint16())
            legacyCompressionMethod = try reader.uint8()
            guard legacyCompressionMethod == 0 else {
                throw NativeOutboundError.protocolError(
                    "TLS 1.3 ServerHello 的 legacy_compression_method 必须为 0，实际 \(legacyCompressionMethod)")
            }
            let extensionBytes = try reader.vector16()
            extensions = try TLS13.parseExtensions(extensionBytes, describing: "ServerHello 扩展")
            isHelloRetryRequest = random == TLS13.helloRetryRequestRandom
            guard !isHelloRetryRequest else {
                // Not a recoverable condition here: this client sends one
                // key_share and REALITY servers cannot relay a retry at all.
                throw NativeOutboundError.protocolError(
                    "TLS 1.3 收到 HelloRetryRequest；本实现只发送单个 X25519 key_share，且 REALITY 服务端无法处理 HRR")
            }
            guard let versionBytes = TLS13.firstExtension(extensions, type: ExtensionType.supportedVersions) else {
                throw NativeOutboundError.protocolError("TLS 1.3 ServerHello 缺少 supported_versions 扩展")
            }
            var versionReader = ByteReader(versionBytes, describing: "ServerHello supported_versions")
            selectedVersion = try versionReader.uint16()
            guard selectedVersion == TLS13.versionTLS13 else {
                throw NativeOutboundError.protocolError(
                    String(format: "TLS 1.3 服务端协商出的版本是 0x%04X，不是 0x0304", selectedVersion))
            }
            guard let keyShareBytes = TLS13.firstExtension(extensions, type: ExtensionType.keyShare) else {
                throw NativeOutboundError.protocolError("TLS 1.3 ServerHello 缺少 key_share 扩展")
            }
            var keyShareReader = ByteReader(keyShareBytes, describing: "ServerHello key_share")
            keyShareGroup = try keyShareReader.uint16()
            keyShareData = try keyShareReader.vector16()
        }
    }

    struct EncryptedExtensions {
        let extensions: [Extension]
        /// nil is the normal case against REALITY: the server runs with
        /// `NextProtos == nil`, so no ALPN extension comes back even though the
        /// ClientHello offered h2 and http/1.1. Requiring a negotiated protocol
        /// here rejects every working connection.
        let alpn: String?

        init(_ body: Data) throws {
            var reader = ByteReader(body, describing: "EncryptedExtensions")
            let extensionBytes = try reader.vector16()
            extensions = try TLS13.parseExtensions(extensionBytes, describing: "EncryptedExtensions 扩展")
            guard let alpnBytes = TLS13.firstExtension(extensions, type: ExtensionType.alpn) else {
                alpn = nil
                return
            }
            var alpnReader = ByteReader(alpnBytes, describing: "ALPN")
            let list = try alpnReader.vector16()
            var listReader = ByteReader(list, describing: "ALPN 协议列表")
            let first = try listReader.vector8()
            alpn = String(data: first, encoding: .utf8)
        }
    }

    struct CertificateMessage {
        struct Entry {
            let certificate: Data
            let extensions: [Extension]
        }

        let requestContext: Data
        let entries: [Entry]

        var leaf: Data? { entries.first?.certificate }

        init(_ body: Data) throws {
            var reader = ByteReader(body, describing: "Certificate")
            requestContext = try reader.vector8()
            let listBytes = try reader.vector24()
            var listReader = ByteReader(listBytes, describing: "Certificate 列表")
            var parsed: [Entry] = []
            while !listReader.isEmpty {
                let certificate = try listReader.vector24()
                let extensionBytes = try listReader.vector16()
                parsed.append(Entry(certificate: certificate,
                                    extensions: try TLS13.parseExtensions(extensionBytes,
                                                                          describing: "Certificate 条目扩展")))
            }
            guard !parsed.isEmpty else {
                throw NativeOutboundError.protocolError("TLS 1.3 Certificate 消息里没有任何证书")
            }
            entries = parsed
        }
    }

    struct CertificateVerify {
        let algorithm: UInt16
        let signature: Data

        init(_ body: Data) throws {
            var reader = ByteReader(body, describing: "CertificateVerify")
            algorithm = try reader.uint16()
            signature = try reader.vector16()
        }
    }

    struct NewSessionTicket {
        let lifetime: UInt32
        let ageAdd: UInt32
        let ticketNonce: Data
        let ticket: Data
        let extensions: [Extension]

        init(_ body: Data) throws {
            var reader = ByteReader(body, describing: "NewSessionTicket")
            lifetime = try reader.uint32()
            ageAdd = try reader.uint32()
            ticketNonce = try reader.vector8()
            ticket = try reader.vector16()
            let extensionBytes = try reader.vector16()
            extensions = try TLS13.parseExtensions(extensionBytes, describing: "NewSessionTicket 扩展")
        }
    }

    enum KeyUpdateRequest: UInt8 {
        case notRequested = 0
        case requested = 1

        init(_ body: Data) throws {
            var reader = ByteReader(body, describing: "KeyUpdate")
            let value = try reader.uint8()
            guard reader.isEmpty, let request = KeyUpdateRequest(rawValue: value) else {
                throw NativeOutboundError.protocolError("TLS 1.3 KeyUpdate 请求字段无效：\(value)")
            }
            self = request
        }
    }

    /// A Finished message is nothing but `verify_data`; its length is the hash
    /// length of the negotiated suite.
    static func parseFinished(_ body: Data, suite: CipherSuite) throws -> Data {
        guard body.count == suite.hashFunction.length else {
            throw NativeOutboundError.protocolError(
                "TLS 1.3 Finished 的 verify_data 应为 \(suite.hashFunction.length) 字节，实际 \(body.count) 字节")
        }
        return body
    }

    struct Alert {
        let level: UInt8
        let description: UInt8

        init(_ fragment: Data) throws {
            var reader = ByteReader(fragment, describing: "Alert")
            level = try reader.uint8()
            description = try reader.uint8()
        }

        var isCloseNotify: Bool { description == 0 }

        var text: String {
            let name: String
            switch description {
            case 0: name = "close_notify"
            case 10: name = "unexpected_message"
            case 20: name = "bad_record_mac"
            case 40: name = "handshake_failure"
            case 42: name = "bad_certificate"
            case 47: name = "illegal_parameter"
            case 48: name = "unknown_ca"
            case 50: name = "decode_error"
            case 51: name = "decrypt_error"
            case 70: name = "protocol_version"
            case 80: name = "internal_error"
            case 109: name = "missing_extension"
            case 112: name = "unrecognized_name"
            case 120: name = "no_application_protocol"
            default: name = "描述码 \(description)"
            }
            return "TLS 告警（level \(level)）：\(name)"
        }
    }

    // MARK: - CertificateVerify content

    /// RFC 8446 §4.4.3: 64 spaces, the context string, a zero byte, then the
    /// transcript hash. REALITY signs exactly this with the ephemeral Ed25519
    /// key inside its forged certificate, so the signature is genuine even
    /// though the certificate is not.
    static func certificateVerifyContent(transcriptHash: Data,
                                         context: String = "TLS 1.3, server CertificateVerify") -> Data {
        var out = Data(repeating: 0x20, count: 64)
        out.append(Data(context.utf8))
        out.append(0x00)
        out.append(transcriptHash)
        return out
    }

    /// Only Ed25519 (0x0807) is implemented, which is the only scheme a REALITY
    /// server ever uses. Anything else is rejected loudly rather than skipped —
    /// an unverified CertificateVerify means the peer never proved possession of
    /// the certificate's private key.
    static func verifyCertificateVerify(algorithm: UInt16, signature: Data,
                                        publicKey: Data, transcriptHash: Data) throws {
        guard algorithm == SignatureScheme.ed25519 else {
            throw NativeOutboundError.protocolError(
                String(format: "TLS 1.3 CertificateVerify 使用了未实现的签名算法 0x%04X（只支持 Ed25519 0x0807）",
                       algorithm))
        }
        let content = certificateVerifyContent(transcriptHash: transcriptHash)
        guard verifyEd25519(publicKey: publicKey, message: content, signature: signature) else {
            throw NativeOutboundError.crypto("TLS 1.3 CertificateVerify 的 Ed25519 签名校验失败")
        }
    }

    static func verifyEd25519(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard publicKey.count == 32, signature.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else {
            return false
        }
        return key.isValidSignature(signature, for: message)
    }

    /// Comparison that does not leak where two byte strings first differ. Used
    /// for `verify_data`; the length is public so an early length check is fine.
    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
        return difference == 0
    }

    /// X25519 with raw byte inputs, the form every TLS field uses.
    static func x25519(privateKey: Curve25519.KeyAgreement.PrivateKey, peerPublicKey: Data) throws -> Data {
        guard peerPublicKey.count == 32 else {
            throw NativeOutboundError.protocolError(
                "TLS 1.3 X25519 对端公钥必须是 32 字节，实际 \(peerPublicKey.count) 字节")
        }
        do {
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            let shared = try privateKey.sharedSecretFromKeyAgreement(with: peer)
            return shared.withUnsafeBytes { Data($0) }
        } catch {
            throw NativeOutboundError.crypto("TLS 1.3 X25519 密钥协商失败：\(error.localizedDescription)")
        }
    }

    // MARK: - Minimal DER

    /// Just enough ASN.1 to walk a certificate. This is not a validator: it does
    /// not check dates, names, key usage, chains or signatures. REALITY replaces
    /// the signature of a self-signed throwaway certificate with an HMAC, so a
    /// real X.509 verifier would reject every honest connection; the trust
    /// decision belongs to the REALITY layer above.
    enum DER {
        struct Element {
            let tag: UInt8
            /// Offset of the tag byte.
            let start: Int
            let contentStart: Int
            let contentEnd: Int

            var end: Int { contentEnd }
        }

        static let sequence: UInt8 = 0x30
        static let objectIdentifier: UInt8 = 0x06
        static let bitString: UInt8 = 0x03
        static let contextConstructed0: UInt8 = 0xA0

        static func element(_ bytes: [UInt8], at offset: Int) throws -> Element {
            guard offset + 1 < bytes.count else {
                throw NativeOutboundError.protocolError("DER 解析越界：偏移 \(offset) 处没有完整的标签与长度")
            }
            let tag = bytes[offset]
            guard tag & 0x1F != 0x1F else {
                throw NativeOutboundError.protocolError("DER 解析不支持多字节标签")
            }
            let first = bytes[offset + 1]
            var contentStart = offset + 2
            var length = Int(first)
            if first & 0x80 != 0 {
                let count = Int(first & 0x7F)
                guard count >= 1, count <= 4 else {
                    throw NativeOutboundError.protocolError("DER 长度字节数 \(count) 不受支持（不定长或超过 4 字节）")
                }
                guard contentStart + count <= bytes.count else {
                    throw NativeOutboundError.protocolError("DER 长度字段越界")
                }
                length = 0
                for index in 0..<count { length = length << 8 | Int(bytes[contentStart + index]) }
                contentStart += count
            }
            guard length >= 0, contentStart + length <= bytes.count else {
                throw NativeOutboundError.protocolError("DER 元素长度 \(length) 超出缓冲区")
            }
            return Element(tag: tag, start: offset, contentStart: contentStart,
                           contentEnd: contentStart + length)
        }

        /// A hard cap keeps a malformed certificate from turning into an
        /// unbounded loop; no real certificate has anywhere near this many
        /// direct children.
        static let maximumChildren = 64

        static func children(_ bytes: [UInt8], of parent: Element) throws -> [Element] {
            var result: [Element] = []
            var cursor = parent.contentStart
            while cursor < parent.contentEnd {
                guard result.count < maximumChildren else {
                    throw NativeOutboundError.protocolError("DER 子元素数量超过 \(maximumChildren)")
                }
                let child = try element(bytes, at: cursor)
                guard child.contentEnd <= parent.contentEnd else {
                    throw NativeOutboundError.protocolError("DER 子元素越出父元素范围")
                }
                result.append(child)
                cursor = child.contentEnd
            }
            return result
        }

        /// BIT STRING content starts with an "unused bits" octet, which is
        /// always zero for keys and signatures and is not part of the value.
        static func bitStringBytes(_ bytes: [UInt8], of element: Element) throws -> Data {
            guard element.tag == bitString, element.contentEnd > element.contentStart,
                  bytes[element.contentStart] == 0 else {
                throw NativeOutboundError.protocolError("DER BIT STRING 格式异常（非零的 unused bits）")
            }
            return Data(bytes[(element.contentStart + 1)..<element.contentEnd])
        }
    }

    /// The three fields a REALITY client needs out of the leaf certificate: the
    /// SPKI algorithm, the raw public key, and the signature value.
    struct LeafCertificate {
        /// OID content octets of `SubjectPublicKeyInfo.algorithm.algorithm`.
        let publicKeyAlgorithm: Data
        /// The raw key bytes, i.e. the BIT STRING without its unused-bits octet
        /// and without any SPKI wrapping. For Ed25519 that is 32 bytes, and it
        /// is exactly what REALITY runs HMAC-SHA512 over.
        let publicKey: Data
        let signatureAlgorithm: Data
        /// `signatureValue`. For an Ed25519 self-signed certificate this is the
        /// last 64 bytes of the DER, which is the slot REALITY overwrites with
        /// HMAC-SHA512(AuthKey, ed25519_public_key).
        let signature: Data

        /// 1.3.101.112 encoded as OID content octets.
        static let ed25519OID = Data([0x2B, 0x65, 0x70])

        var isEd25519: Bool { publicKeyAlgorithm == LeafCertificate.ed25519OID && publicKey.count == 32 }

        init(der: Data) throws {
            let bytes = Array(der)
            let certificate = try DER.element(bytes, at: 0)
            guard certificate.tag == DER.sequence else {
                throw NativeOutboundError.protocolError("X.509 证书最外层不是 SEQUENCE")
            }
            let top = try DER.children(bytes, of: certificate)
            guard top.count >= 3 else {
                throw NativeOutboundError.protocolError("X.509 证书顶层元素不足 3 个")
            }
            let tbs = top[0]
            guard tbs.tag == DER.sequence else {
                throw NativeOutboundError.protocolError("X.509 tbsCertificate 不是 SEQUENCE")
            }
            signatureAlgorithm = try LeafCertificate.algorithmOID(bytes, of: top[1])
            signature = try DER.bitStringBytes(bytes, of: top[2])

            var fields = try DER.children(bytes, of: tbs)
            // The explicit [0] version tag is optional; v1 certificates omit it.
            if let first = fields.first, first.tag == DER.contextConstructed0 {
                fields.removeFirst()
            }
            // serialNumber, signature, issuer, validity, subject, then SPKI.
            guard fields.count >= 6 else {
                throw NativeOutboundError.protocolError("X.509 tbsCertificate 字段不足，找不到 subjectPublicKeyInfo")
            }
            let spki = fields[5]
            guard spki.tag == DER.sequence else {
                throw NativeOutboundError.protocolError("X.509 subjectPublicKeyInfo 不是 SEQUENCE")
            }
            let spkiFields = try DER.children(bytes, of: spki)
            guard spkiFields.count >= 2 else {
                throw NativeOutboundError.protocolError("X.509 subjectPublicKeyInfo 字段不足")
            }
            publicKeyAlgorithm = try LeafCertificate.algorithmOID(bytes, of: spkiFields[0])
            publicKey = try DER.bitStringBytes(bytes, of: spkiFields[1])
        }

        private static func algorithmOID(_ bytes: [UInt8], of element: DER.Element) throws -> Data {
            guard element.tag == DER.sequence else {
                throw NativeOutboundError.protocolError("X.509 AlgorithmIdentifier 不是 SEQUENCE")
            }
            let fields = try DER.children(bytes, of: element)
            guard let oid = fields.first, oid.tag == DER.objectIdentifier else {
                throw NativeOutboundError.protocolError("X.509 AlgorithmIdentifier 缺少 OID")
            }
            return Data(bytes[oid.contentStart..<oid.contentEnd])
        }
    }
}

// MARK: - Self-test

/// Known-answer tests. Every expected value below comes from outside this file:
/// RFC 8448's complete TLS 1.3 trace, RFC 8439's AEAD vector, RFC 8032's Ed25519
/// vectors, and draft-mcgrew-gcm-test-01's AES-256-GCM case.
///
/// The reason none of this is a round trip: a key schedule that derives the
/// wrong secret, a transcript that hashes the wrong bytes and a nonce built from
/// the wrong sequence number all round-trip perfectly against themselves. The
/// only observable symptom against a real server is a Finished mismatch, and
/// against a REALITY server not even that — the connection succeeds and proxies
/// to the wrong place.
public enum TLS13SelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "TLS 1.3 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    private static func expect(_ actual: Data, _ expected: Data, _ what: String) throws {
        guard actual == expected else {
            throw Failure(text: "\(what) 不符：期望 \(hexString(expected))，实际 \(hexString(actual))")
        }
    }

    public static func run() throws {
        try hkdfLabelEncoding()
        try keyScheduleRFC8448()
        try transcriptAndFinishedRFC8448()
        try recordDecryptionRFC8448()
        try recordEncryptionRFC8448()
        try innerPlaintextHandling()
        try recordFraming()
        try handshakeReassembly()
        try handshakeMessageParsing()
        try certificateParsing()
        try cipherSuiteShape()
        try sha384KeySchedule()
        try aeadKnownAnswers()
        try ed25519AndCertificateVerify()
        try rejectsMalformedInput()
    }

    // MARK: RFC 8448 §3 — Simple 1-RTT Handshake

    /// The HkdfLabel encoding, pinned against the `info` blocks RFC 8448 prints
    /// for every derivation. A wrong prefix or a missing length byte changes
    /// every secret downstream and nothing else.
    private static func hkdfLabelEncoding() throws {
        let hash = TLS13.HashFunction.sha256
        try expect(try TLS13.HKDF.hkdfLabel(count: 32, label: "derived", context: hash.emptyHash),
                   derivedInfo, "\"tls13 derived\" 的 HkdfLabel")
        try expect(try TLS13.HKDF.hkdfLabel(count: 32, label: "c hs traffic",
                                            context: transcriptClientServerHello),
                   clientHandshakeTrafficInfo, "\"tls13 c hs traffic\" 的 HkdfLabel")
        try expect(try TLS13.HKDF.hkdfLabel(count: 16, label: "key", context: Data()),
                   keyInfo, "\"tls13 key\" 的 HkdfLabel")
        try expect(try TLS13.HKDF.hkdfLabel(count: 12, label: "iv", context: Data()),
                   ivInfo, "\"tls13 iv\" 的 HkdfLabel")
        try expect(try TLS13.HKDF.hkdfLabel(count: 32, label: "finished", context: Data()),
                   finishedInfo, "\"tls13 finished\" 的 HkdfLabel")
    }

    private static func keyScheduleRFC8448() throws {
        let suite = TLS13.CipherSuite.aes128GCMSHA256
        let hash = suite.hashFunction

        // The ECDH input itself is a known answer: RFC 8448 prints the X25519
        // output as the IKM of the handshake extract.
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: clientEphemeralPrivateKey)
        let shared = try TLS13.x25519(privateKey: privateKey, peerPublicKey: serverEphemeralPublicKey)
        try expect(shared, ecdheSharedSecret, "X25519 共享密钥")

        var schedule = TLS13.KeySchedule(suite: suite)
        try expect(schedule.earlySecret, earlySecret, "early secret")
        try expect(try TLS13.HKDF.deriveSecret(hash, secret: schedule.earlySecret,
                                               label: "derived", transcriptHash: hash.emptyHash),
                   derivedForHandshake, "Derive-Secret(early, \"derived\", \"\")")

        try schedule.advance(sharedSecret: shared)
        try expect(schedule.handshakeSecret ?? Data(), handshakeSecret, "handshake secret")
        try expect(try TLS13.HKDF.deriveSecret(hash, secret: handshakeSecret,
                                               label: "derived", transcriptHash: hash.emptyHash),
                   derivedForMaster, "Derive-Secret(handshake, \"derived\", \"\")")
        try expect(schedule.masterSecret ?? Data(), masterSecret, "master secret")

        let clientHS = try schedule.trafficSecret(.clientHandshake,
                                                  transcriptHash: transcriptClientServerHello)
        let serverHS = try schedule.trafficSecret(.serverHandshake,
                                                  transcriptHash: transcriptClientServerHello)
        try expect(clientHS, clientHandshakeTraffic, "client handshake traffic secret")
        try expect(serverHS, serverHandshakeTraffic, "server handshake traffic secret")

        let clientHSKeys = try schedule.trafficKeys(from: clientHS)
        let serverHSKeys = try schedule.trafficKeys(from: serverHS)
        try expect(clientHSKeys.key, clientHandshakeKey, "client handshake write key")
        try expect(clientHSKeys.iv, clientHandshakeIV, "client handshake write IV")
        try expect(serverHSKeys.key, serverHandshakeKey, "server handshake write key")
        try expect(serverHSKeys.iv, serverHandshakeIV, "server handshake write IV")

        let clientAP = try schedule.trafficSecret(.clientApplication,
                                                  transcriptHash: transcriptThroughServerFinished)
        let serverAP = try schedule.trafficSecret(.serverApplication,
                                                  transcriptHash: transcriptThroughServerFinished)
        try expect(clientAP, clientApplicationTraffic, "client application traffic secret")
        try expect(serverAP, serverApplicationTraffic, "server application traffic secret")
        try expect(try schedule.trafficSecret(.exporterMaster,
                                              transcriptHash: transcriptThroughServerFinished),
                   exporterMaster, "exporter master secret")
        try expect(try schedule.trafficSecret(.resumptionMaster,
                                              transcriptHash: transcriptThroughClientFinished),
                   resumptionMaster, "resumption master secret")

        try expect(try schedule.trafficKeys(from: clientAP).key, clientApplicationKey,
                   "client application write key")
        try expect(try schedule.trafficKeys(from: clientAP).iv, clientApplicationIV,
                   "client application write IV")
        try expect(try schedule.trafficKeys(from: serverAP).key, serverApplicationKey,
                   "server application write key")
        try expect(try schedule.trafficKeys(from: serverAP).iv, serverApplicationIV,
                   "server application write IV")

        // A 2-byte context, which is the only place the context length prefix is
        // exercised with something other than 0 or a full hash.
        try expect(try schedule.resumptionPreSharedKey(resumptionMaster: resumptionMaster,
                                                       ticketNonce: Data([0x00, 0x00])),
                   resumptionPSK, "resumption PSK")
    }

    /// The transcript is where a correct implementation usually goes wrong: the
    /// hash covers raw handshake messages in wire order, with their 4-byte
    /// headers, and record framing plays no part. This walks the real flight
    /// through the real reader and checks both Finished values.
    private static func transcriptAndFinishedRFC8448() throws {
        let suite = TLS13.CipherSuite.aes128GCMSHA256
        var transcript = TLS13.Transcript(suite.hashFunction)

        // ClientHello and ServerHello arrive as plaintext records.
        var reader = TLS13.RecordReader()
        reader.append(clientHelloRecord)
        reader.append(serverHelloRecord)
        var handshake = TLS13.HandshakeReader()
        var seen: [TLS13.HandshakeMessage] = []
        while let record = try reader.next() {
            try expect(record.contentType == TLS13.ContentType.handshake.rawValue,
                       "明文记录的 content_type 应为 22，实际 \(record.contentType)")
            handshake.append(record.fragment)
            while let message = try handshake.next() { seen.append(message) }
        }
        try expect(seen.count == 2, "应从两条明文记录里解出 2 条握手消息，实际 \(seen.count)")
        try expect(seen[0].raw, clientHello, "ClientHello 原始字节")
        try expect(seen[1].raw, serverHello, "ServerHello 原始字节")
        transcript.update(seen[0].raw)
        transcript.update(seen[1].raw)
        try expect(transcript.value, transcriptClientServerHello, "ClientHello‖ServerHello 的 transcript hash")

        // The rest of the server flight arrives as one encrypted record holding
        // four messages; the reader must split them without help.
        var flight = TLS13.HandshakeReader()
        flight.append(serverFlightPayload)
        var flightMessages: [TLS13.HandshakeMessage] = []
        while let message = try flight.next() { flightMessages.append(message) }
        try expect(flightMessages.count == 4,
                   "一条 record 里应解出 4 条握手消息，实际 \(flightMessages.count)")
        try expect(flightMessages[0].raw, encryptedExtensions, "EncryptedExtensions 原始字节")
        try expect(flightMessages[1].raw, certificateMessage, "Certificate 原始字节")
        try expect(flightMessages[2].raw, certificateVerify, "CertificateVerify 原始字节")
        try expect(flightMessages[3].raw, serverFinished, "Finished 原始字节")

        transcript.update(flightMessages[0].raw)
        transcript.update(flightMessages[1].raw)
        transcript.update(flightMessages[2].raw)
        let throughCertificateVerify = transcript.value
        try expect(throughCertificateVerify, transcriptThroughCertificateVerify,
                   "至 CertificateVerify 的 transcript hash")

        let schedule = try makeSchedule(suite: suite)
        try expect(try schedule.finishedKey(from: serverHandshakeTraffic), serverFinishedKey,
                   "服务端 finished key")
        let serverVerify = try schedule.verifyData(secret: serverHandshakeTraffic,
                                                   transcriptHash: throughCertificateVerify)
        try expect(serverVerify, serverVerifyData, "服务端 verify_data")
        try expect(TLS13.constantTimeEquals(
            try TLS13.parseFinished(flightMessages[3].body, suite: suite), serverVerify),
            "服务端 Finished 与本地计算的 verify_data 不一致")

        transcript.update(flightMessages[3].raw)
        try expect(transcript.value, transcriptThroughServerFinished, "至服务端 Finished 的 transcript hash")

        try expect(try schedule.finishedKey(from: clientHandshakeTraffic), clientFinishedKey,
                   "客户端 finished key")
        let clientVerify = try schedule.verifyData(secret: clientHandshakeTraffic,
                                                   transcriptHash: transcript.value)
        try expect(clientVerify, clientVerifyData, "客户端 verify_data")

        transcript.update(clientFinished)
        try expect(transcript.value, transcriptThroughClientFinished, "至客户端 Finished 的 transcript hash")
    }

    private static func makeSchedule(suite: TLS13.CipherSuite) throws -> TLS13.KeySchedule {
        var schedule = TLS13.KeySchedule(suite: suite)
        try schedule.advance(sharedSecret: ecdheSharedSecret)
        return schedule
    }

    /// Decrypting real bytes pins the AAD (the five header bytes as sent), the
    /// nonce construction, and the per-direction sequence counter all at once.
    private static func recordDecryptionRFC8448() throws {
        let suite = TLS13.CipherSuite.aes128GCMSHA256

        let handshakeProtector = try TLS13.RecordProtector(suite: suite,
                                                           trafficSecret: serverHandshakeTraffic)
        var reader = TLS13.RecordReader()
        reader.append(serverFlightRecord)
        guard let record = try reader.next() else { throw Failure(text: "服务端握手记录未能成帧") }
        let opened = try handshakeProtector.unprotect(record)
        try expect(opened.contentType == TLS13.ContentType.handshake.rawValue,
                   "解密后的 content_type 应为 22，实际 \(opened.contentType)")
        try expect(opened.content, serverFlightPayload, "服务端握手记录明文")

        // Three consecutive records under the application keys. Sequence numbers
        // are per direction and start at zero after every key change; reusing the
        // handshake counter here decrypts nothing.
        let applicationProtector = try TLS13.RecordProtector(suite: suite,
                                                             trafficSecret: serverApplicationTraffic)
        var stream = TLS13.RecordReader()
        stream.append(newSessionTicketRecord)
        stream.append(serverApplicationRecord)
        stream.append(serverAlertRecord)

        guard let ticketRecord = try stream.next() else { throw Failure(text: "NewSessionTicket 记录未能成帧") }
        let ticket = try applicationProtector.unprotect(ticketRecord)
        try expect(ticket.contentType == TLS13.ContentType.handshake.rawValue,
                   "NewSessionTicket 的内层 content_type 应为 22")
        try expect(ticket.content, newSessionTicket, "NewSessionTicket 明文（序号 0）")

        guard let dataRecord = try stream.next() else { throw Failure(text: "应用数据记录未能成帧") }
        let payload = try applicationProtector.unprotect(dataRecord)
        try expect(payload.contentType == TLS13.ContentType.applicationData.rawValue,
                   "应用数据的内层 content_type 应为 23")
        try expect(payload.content, applicationPayload, "应用数据明文（序号 1）")

        guard let alertRecord = try stream.next() else { throw Failure(text: "告警记录未能成帧") }
        let alert = try applicationProtector.unprotect(alertRecord)
        try expect(alert.contentType == TLS13.ContentType.alert.rawValue,
                   "告警的内层 content_type 应为 21")
        try expect(try TLS13.Alert(alert.content).isCloseNotify, "序号 2 的告警应为 close_notify")
    }

    /// The strongest single check in this file: encrypting known plaintext with
    /// a known traffic secret must reproduce the exact bytes RFC 8448 puts on
    /// the wire, header included.
    private static func recordEncryptionRFC8448() throws {
        let suite = TLS13.CipherSuite.aes128GCMSHA256

        let handshakeProtector = try TLS13.RecordProtector(suite: suite,
                                                           trafficSecret: clientHandshakeTraffic)
        try expect(try handshakeProtector.protect(contentType: .handshake, content: clientFinished),
                   clientFinishedRecord, "客户端 Finished 记录密文")

        let applicationProtector = try TLS13.RecordProtector(suite: suite,
                                                             trafficSecret: clientApplicationTraffic)
        try expect(try applicationProtector.protect(contentType: .applicationData,
                                                    content: applicationPayload),
                   clientApplicationRecord, "客户端应用数据记录密文（序号 0）")
        try expect(try applicationProtector.protect(contentType: .alert, content: Data([0x01, 0x00])),
                   clientAlertRecord, "客户端告警记录密文（序号 1）")

        // The padded branch, which RFC 8448 never exercises because nothing in
        // its trace pads. Without a vector here, writing the content type
        // *after* the zeros instead of before them round-trips against this
        // file's own reader and fails against everyone else — and REALITY makes
        // the branch mandatory rather than optional, because it pads every
        // record to the byte length of the corresponding one from the real site.
        let paddedProtector = try TLS13.RecordProtector(suite: suite,
                                                        trafficSecret: clientHandshakeTraffic)
        let padded = try paddedProtector.protect(contentType: .handshake,
                                                 content: clientFinished,
                                                 paddingLength: 26)
        try expect(padded, clientFinishedPaddedRecord, "带 26 字节填充的客户端 Finished 记录密文")

        // And it must come back out of the reader with the padding gone.
        let paddedReader = try TLS13.RecordProtector(suite: suite,
                                                     trafficSecret: clientHandshakeTraffic)
        var framing = TLS13.RecordReader()
        framing.append(padded)
        guard let paddedRecord = try framing.next() else {
            throw Failure(text: "带填充的记录未能成帧")
        }
        let unpadded = try paddedReader.unprotect(paddedRecord)
        try expect(unpadded.contentType == TLS13.ContentType.handshake.rawValue,
                   "带填充的记录解出的 content_type 应为 22，实际 \(unpadded.contentType)")
        try expect(unpadded.content, clientFinished, "带填充的记录解出的内容")
    }

    // MARK: Record layer edge cases

    private static func innerPlaintextHandling() throws {
        // REALITY pads every handshake record with zeros up to the byte length
        // of the corresponding record from the real site.
        var padded = serverFinished
        padded.append(TLS13.ContentType.handshake.rawValue)
        padded.append(Data(repeating: 0, count: 137))
        let split = try TLS13.splitInnerPlaintext(padded)
        try expect(split.contentType == TLS13.ContentType.handshake.rawValue,
                   "跳过尾部零后应读出 content_type 22，实际 \(split.contentType)")
        try expect(split.content, serverFinished, "剥离填充后的内容")

        // REALITY's forged NewSessionTicket is literally this.
        let empty = try TLS13.splitInnerPlaintext(Data([0x17, 0x00, 0x00, 0x00, 0x00]))
        try expect(empty.contentType == TLS13.ContentType.applicationData.rawValue,
                   "零长度 application_data 的 content_type 应为 23")
        try expect(empty.content.isEmpty, "零长度 application_data 不应带出内容")

        // No content type at all: taking the last byte blindly would return 0x00
        // and be reported as an unknown record type instead of an error.
        do {
            _ = try TLS13.splitInnerPlaintext(Data(repeating: 0, count: 8))
            throw Failure(text: "全零内层明文未被拒绝")
        } catch is NativeOutboundError {}
        do {
            _ = try TLS13.splitInnerPlaintext(Data())
            throw Failure(text: "空内层明文未被拒绝")
        } catch is NativeOutboundError {}
    }

    private static func recordFraming() throws {
        // A record split across two reads must survive, and the leftover bytes
        // of the next record must not be lost.
        var reader = TLS13.RecordReader()
        let split = 40
        reader.append(serverFlightRecord.prefix(split))
        try expect(try reader.next() == nil, "不完整的记录被错误地成帧")
        reader.append(serverFlightRecord.dropFirst(split))
        reader.append(newSessionTicketRecord)
        var lengths: [Int] = []
        while let record = try reader.next() { lengths.append(record.fragment.count) }
        try expect(lengths == [serverFlightRecord.count - 5, newSessionTicketRecord.count - 5],
                   "跨读取重组的记录长度不符：\(lengths)")

        // A zero-length application_data record is legal on the wire and must be
        // returned as a record, not treated as end of stream.
        var emptyReader = TLS13.RecordReader()
        emptyReader.append(Data([0x17, 0x03, 0x03, 0x00, 0x00]))
        guard let emptyRecord = try emptyReader.next() else {
            throw Failure(text: "零长度 application_data 记录未被成帧")
        }
        try expect(emptyRecord.fragment.isEmpty, "零长度记录不应带出内容")
        try expect(emptyRecord.header == Data([0x17, 0x03, 0x03, 0x00, 0x00]),
                   "记录头未按原样保留（AEAD 的 AAD 依赖它）")
        try expect(try emptyReader.next() == nil, "空缓冲区应返回 nil")

        // The header bytes handed back must be the ones from the wire.
        var headerReader = TLS13.RecordReader()
        headerReader.append(clientHelloRecord)
        guard let helloRecord = try headerReader.next() else {
            throw Failure(text: "ClientHello 记录未能成帧")
        }
        try expect(helloRecord.header, clientHelloRecord.prefix(5), "ClientHello 记录头")
        try expect(helloRecord.legacyVersion == TLS13.legacyRecordVersionInitial,
                   String(format: "首个 ClientHello 的 record 版本应为 0x0301，实际 0x%04X",
                          helloRecord.legacyVersion))

        // Framing the ClientHello has to reproduce the wire bytes exactly,
        // 0x0301 record version included — the transport calls this, and a
        // 0x0303 there handshakes perfectly while failing every fingerprint.
        try expect(try TLS13.plaintextRecord(contentType: .handshake,
                                             legacyVersion: TLS13.legacyRecordVersionInitial,
                                             fragment: clientHello),
                   clientHelloRecord, "ClientHello 明文记录的封装")
    }

    private static func handshakeReassembly() throws {
        // One message spread over three fragments, each cut at an awkward place.
        var reader = TLS13.HandshakeReader()
        reader.append(certificateMessage.prefix(2))
        try expect(try reader.next() == nil, "只有 2 字节时不应解出消息")
        reader.append(certificateMessage.dropFirst(2).prefix(300))
        try expect(try reader.next() == nil, "消息未收全时不应解出消息")
        reader.append(certificateMessage.dropFirst(302))
        guard let message = try reader.next() else { throw Failure(text: "跨片段的握手消息未能重组") }
        try expect(message.raw, certificateMessage, "重组后的 Certificate 原始字节")
        try expect(message.type == TLS13.HandshakeType.certificate.rawValue,
                   "重组后的消息类型应为 11，实际 \(message.type)")
        try expect(try reader.next() == nil, "重组后不应有残留消息")

        // Two messages arriving in one fragment, the second one short by a byte.
        var mixed = TLS13.HandshakeReader()
        mixed.append(encryptedExtensions + certificateVerify.dropLast())
        guard let first = try mixed.next() else { throw Failure(text: "同一片段里的第一条消息未解出") }
        try expect(first.raw, encryptedExtensions, "同一片段里的第一条消息")
        try expect(try mixed.next() == nil, "残缺的第二条消息被错误解出")
        mixed.append(certificateVerify.suffix(1))
        guard let second = try mixed.next() else { throw Failure(text: "补齐后的第二条消息未解出") }
        try expect(second.raw, certificateVerify, "补齐后的第二条消息")
    }

    // MARK: Message parsing

    private static func handshakeMessageParsing() throws {
        let hello = try TLS13.ServerHello(Data(serverHello.dropFirst(4)))
        try expect(hello.legacyVersion == TLS13.versionTLS12,
                   String(format: "ServerHello legacy_version 应为 0x0303，实际 0x%04X", hello.legacyVersion))
        try expect(hello.selectedVersion == TLS13.versionTLS13,
                   String(format: "协商版本应为 0x0304，实际 0x%04X", hello.selectedVersion))
        try expect(hello.cipherSuite == .aes128GCMSHA256,
                   "ServerHello 选中的 suite 应为 0x1301，实际 \(hello.cipherSuite.rawValue)")
        try expect(hello.keyShareGroup == TLS13.NamedGroup.x25519,
                   "key_share group 应为 X25519(0x001d)，实际 \(hello.keyShareGroup)")
        try expect(hello.keyShareData, serverEphemeralPublicKey, "ServerHello 的 key_share 公钥")
        try expect(!hello.isHelloRetryRequest, "普通 ServerHello 被误判为 HelloRetryRequest")
        try expect(hello.legacySessionIDEcho.isEmpty,
                   "RFC 8448 的 ServerHello 没有回显 session_id，解析结果却非空")

        // RFC 8448's EncryptedExtensions carries supported_groups and
        // record_size_limit and no ALPN — the same shape a REALITY server sends,
        // because it runs with NextProtos == nil.
        let encrypted = try TLS13.EncryptedExtensions(Data(encryptedExtensions.dropFirst(4)))
        try expect(encrypted.alpn == nil, "缺少 ALPN 时应得到 nil，而不是报错")
        try expect(encrypted.extensions.count == 3,
                   "EncryptedExtensions 应解出 3 个扩展，实际 \(encrypted.extensions.count)")
        try expect(encrypted.extensions[0].type == TLS13.ExtensionType.supportedGroups,
                   "第一个扩展应为 supported_groups")

        // And the same parser must still find ALPN when it is present.
        var withALPN = Data([0x00, 0x0C])                      // extensions total length
        withALPN.append(Data([0x00, 0x10, 0x00, 0x08]))        // ALPN, extension_data length 8
        withALPN.append(Data([0x00, 0x06]))                    // protocol name list length
        withALPN.append(Data([0x02]))
        withALPN.append(Data("h2".utf8))
        withALPN.append(Data([0x02]))
        withALPN.append(Data("h3".utf8))
        try expect(try TLS13.EncryptedExtensions(withALPN).alpn == "h2",
                   "应取 ALPN 列表里的第一项")

        let certificates = try TLS13.CertificateMessage(Data(certificateMessage.dropFirst(4)))
        try expect(certificates.requestContext.isEmpty, "服务端 Certificate 的 request_context 应为空")
        try expect(certificates.entries.count == 1,
                   "Certificate 应含 1 张证书，实际 \(certificates.entries.count)")
        try expect(certificates.entries[0].extensions.isEmpty, "证书条目扩展应为空")
        try expect(certificates.leaf?.count == 432,
                   "叶证书 DER 长度应为 432，实际 \(certificates.leaf?.count ?? -1)")

        let verify = try TLS13.CertificateVerify(Data(certificateVerify.dropFirst(4)))
        try expect(verify.algorithm == 0x0804,
                   String(format: "CertificateVerify 算法应为 0x0804，实际 0x%04X", verify.algorithm))
        try expect(verify.signature.count == 128,
                   "CertificateVerify 签名长度应为 128，实际 \(verify.signature.count)")

        try expect(try TLS13.parseFinished(Data(serverFinished.dropFirst(4)), suite: .aes128GCMSHA256),
                   serverVerifyData, "Finished 的 verify_data")

        let ticket = try TLS13.NewSessionTicket(Data(newSessionTicket.dropFirst(4)))
        try expect(ticket.lifetime == 30, "ticket_lifetime 应为 30，实际 \(ticket.lifetime)")
        try expect(ticket.ticketNonce, Data([0x00, 0x00]), "ticket_nonce")
        try expect(ticket.ticket.count == 178, "ticket 长度应为 178，实际 \(ticket.ticket.count)")
        try expect(ticket.extensions.count == 1,
                   "NewSessionTicket 应含 1 个扩展，实际 \(ticket.extensions.count)")
        try expect(ticket.extensions[0].type == TLS13.ExtensionType.earlyData,
                   "NewSessionTicket 的扩展应为 early_data")

        try expect(try TLS13.KeyUpdateRequest(Data([0x00])) == .notRequested, "KeyUpdate 0 应为 not_requested")
        try expect(try TLS13.KeyUpdateRequest(Data([0x01])) == .requested, "KeyUpdate 1 应为 requested")

        // KeyUpdate rekeying, pinned against the same expand-label path.
        let schedule = TLS13.KeySchedule(suite: .aes128GCMSHA256)
        try expect(try schedule.updatedTrafficSecret(from: serverApplicationTraffic),
                   try TLS13.HKDF.expandLabel(.sha256, secret: serverApplicationTraffic,
                                              label: "traffic upd", context: Data(), count: 32),
                   "traffic upd 派生")
        let protector = try TLS13.RecordProtector(suite: .aes128GCMSHA256,
                                                  trafficSecret: serverApplicationTraffic)
        _ = try protector.protect(contentType: .applicationData, content: Data([0x00]))
        try expect(protector.sequenceNumber == 1, "写入一条记录后序号应为 1")
        try protector.updateKeys()
        try expect(protector.sequenceNumber == 0, "KeyUpdate 之后序号必须归零")
    }

    private static func certificateParsing() throws {
        // The RSA leaf from RFC 8448: the public key is not Ed25519, and the
        // signature must come out of the DER rather than being assumed.
        guard let leafDER = try TLS13.CertificateMessage(Data(certificateMessage.dropFirst(4))).leaf else {
            throw Failure(text: "取不到叶证书")
        }
        let rsa = try TLS13.LeafCertificate(der: leafDER)
        try expect(!rsa.isEd25519, "RSA 叶证书被误判为 Ed25519")
        try expect(rsa.publicKeyAlgorithm, Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]),
                   "rsaEncryption 的 OID")
        try expect(rsa.signature, rsaLeafSignature, "RSA 叶证书的 signatureValue")
        try expect(rsa.publicKey.count == 140,
                   "RSA SPKI 的 BIT STRING 内容长度应为 140，实际 \(rsa.publicKey.count)")

        // An Ed25519 self-signed certificate, the shape REALITY forges.
        let ed = try TLS13.LeafCertificate(der: ed25519Certificate)
        try expect(ed.isEd25519, "Ed25519 叶证书未被识别")
        try expect(ed.publicKeyAlgorithm, TLS13.LeafCertificate.ed25519OID, "Ed25519 的 OID")
        try expect(ed.publicKey, ed25519PublicKey, "Ed25519 裸公钥")
        try expect(ed.signatureAlgorithm, TLS13.LeafCertificate.ed25519OID, "证书签名算法 OID")
        // REALITY overwrites the last 64 bytes of the DER with
        // HMAC-SHA512(AuthKey, ed25519_public_key); this is the assumption that
        // makes that trick work, so it is pinned rather than assumed.
        try expect(ed.signature, Data(ed25519Certificate.suffix(64)),
                   "Ed25519 自签证书的 signatureValue 必须正好是 DER 末尾 64 字节")
    }

    private static func cipherSuiteShape() throws {
        try expect(TLS13.CipherSuite.aes128GCMSHA256.hashFunction.length == 32, "0x1301 应使用 SHA-256")
        try expect(TLS13.CipherSuite.aes128GCMSHA256.aead.keyLength == 16, "0x1301 的密钥应为 16 字节")
        try expect(TLS13.CipherSuite.aes256GCMSHA384.hashFunction.length == 48, "0x1302 应使用 SHA-384")
        try expect(TLS13.CipherSuite.aes256GCMSHA384.aead.keyLength == 32, "0x1302 的密钥应为 32 字节")
        try expect(TLS13.CipherSuite.chaCha20Poly1305SHA256.hashFunction.length == 32,
                   "0x1303 应使用 SHA-256")
        try expect(TLS13.CipherSuite.chaCha20Poly1305SHA256.aead.keyLength == 32,
                   "0x1303 的密钥应为 32 字节")
        for suite in TLS13.CipherSuite.allCases {
            try expect(suite.aead.nonceLength == 12, "所有 suite 的 nonce 长度都应为 12")
            try expect(suite.aead.tagLength == 16, "所有 suite 的 tag 长度都应为 16")
        }

        // The nonce is the IV XOR the sequence number, right-aligned, big-endian.
        let protector = try TLS13.RecordProtector(suite: .aes128GCMSHA256,
                                                  trafficSecret: serverHandshakeTraffic)
        try expect(protector.nonce(for: 0), serverHandshakeIV, "序号 0 的 nonce 应等于 static_iv")
        var expectedOne = serverHandshakeIV
        expectedOne[expectedOne.endIndex - 1] ^= 0x01
        try expect(protector.nonce(for: 1), expectedOne, "序号 1 的 nonce")
        var expectedWide = serverHandshakeIV
        expectedWide[expectedWide.endIndex - 8] ^= 0x01
        expectedWide[expectedWide.endIndex - 1] ^= 0x02
        try expect(protector.nonce(for: (1 << 56) | 2), expectedWide, "跨字节序号的 nonce")
    }

    /// RFC 8448 only ever negotiates TLS_AES_128_GCM_SHA256, so the SHA-384
    /// ladder is pinned against values computed separately from the RFC 5869 and
    /// RFC 8446 definitions (see /tmp workings; the inputs are RFC 8448's own
    /// ClientHello, ServerHello and ECDHE output so they are reproducible).
    /// The structure of every step is already pinned by the SHA-256 vectors
    /// above; what this adds is that no length is hard-coded to 32.
    private static func sha384KeySchedule() throws {
        let suite = TLS13.CipherSuite.aes256GCMSHA384
        let hash = suite.hashFunction

        var schedule = TLS13.KeySchedule(suite: suite)
        try expect(schedule.earlySecret, sha384EarlySecret, "SHA-384 early secret")
        try expect(try TLS13.HKDF.hkdfLabel(count: 48, label: "derived", context: hash.emptyHash),
                   sha384DerivedInfo, "SHA-384 的 \"tls13 derived\" HkdfLabel")
        try expect(try TLS13.HKDF.deriveSecret(hash, secret: schedule.earlySecret,
                                               label: "derived", transcriptHash: hash.emptyHash),
                   sha384Derived, "SHA-384 Derive-Secret(early, \"derived\", \"\")")

        try schedule.advance(sharedSecret: ecdheSharedSecret)
        try expect(schedule.handshakeSecret ?? Data(), sha384HandshakeSecret, "SHA-384 handshake secret")
        try expect(schedule.masterSecret ?? Data(), sha384MasterSecret, "SHA-384 master secret")

        var transcript = TLS13.Transcript(hash)
        transcript.update(clientHello)
        transcript.update(serverHello)
        try expect(transcript.value, sha384Transcript, "SHA-384 transcript hash")

        let clientHS = try schedule.trafficSecret(.clientHandshake, transcriptHash: transcript.value)
        let serverHS = try schedule.trafficSecret(.serverHandshake, transcriptHash: transcript.value)
        try expect(clientHS, sha384ClientHandshakeTraffic, "SHA-384 client handshake traffic secret")
        try expect(serverHS, sha384ServerHandshakeTraffic, "SHA-384 server handshake traffic secret")

        let keys = try schedule.trafficKeys(from: serverHS)
        try expect(keys.key, sha384ServerHandshakeKey, "SHA-384 / AES-256 写密钥（必须是 32 字节）")
        try expect(keys.iv, sha384ServerHandshakeIV, "SHA-384 写 IV（仍是 12 字节）")
        try expect(try schedule.finishedKey(from: serverHS), sha384ServerFinishedKey,
                   "SHA-384 finished key（必须是 48 字节）")
        try expect(try schedule.verifyData(secret: serverHS, transcriptHash: transcript.value),
                   sha384ServerVerifyData, "SHA-384 verify_data")
    }

    private static func aeadKnownAnswers() throws {
        // RFC 8439 §2.8.2.
        let chacha = try TLS13.AEAD.chaCha20Poly1305.seal(key: chachaKey, nonce: chachaNonce,
                                                          additionalData: chachaAAD,
                                                          plaintext: chachaPlaintext)
        try expect(chacha, chachaCiphertext, "ChaCha20-Poly1305 密文与标签")
        try expect(try TLS13.AEAD.chaCha20Poly1305.open(key: chachaKey, nonce: chachaNonce,
                                                        additionalData: chachaAAD,
                                                        ciphertext: chachaCiphertext),
                   chachaPlaintext, "ChaCha20-Poly1305 解密")

        // draft-mcgrew-gcm-test-01, the 32-octet key case.
        let gcm = try TLS13.AEAD.aes256GCM.seal(key: gcm256Key, nonce: gcm256Nonce,
                                                additionalData: gcm256AAD,
                                                plaintext: gcm256Plaintext)
        try expect(gcm, gcm256Ciphertext, "AES-256-GCM 密文与标签")
        try expect(try TLS13.AEAD.aes256GCM.open(key: gcm256Key, nonce: gcm256Nonce,
                                                 additionalData: gcm256AAD,
                                                 ciphertext: gcm256Ciphertext),
                   gcm256Plaintext, "AES-256-GCM 解密")

        // A tampered tag must fail rather than return plaintext.
        var tampered = gcm256Ciphertext
        tampered[tampered.endIndex - 1] ^= 0x01
        do {
            _ = try TLS13.AEAD.aes256GCM.open(key: gcm256Key, nonce: gcm256Nonce,
                                              additionalData: gcm256AAD, ciphertext: tampered)
            throw Failure(text: "被篡改的认证标签未被拒绝")
        } catch is NativeOutboundError {}

        // Wrong associated data must fail too — this is the check that catches a
        // record header rebuilt with the wrong length.
        do {
            _ = try TLS13.AEAD.aes256GCM.open(key: gcm256Key, nonce: gcm256Nonce,
                                              additionalData: gcm256AAD + Data([0x00]),
                                              ciphertext: gcm256Ciphertext)
            throw Failure(text: "错误的 AAD 未被拒绝")
        } catch is NativeOutboundError {}
    }

    private static func ed25519AndCertificateVerify() throws {
        // RFC 8032 §7.1 TEST 2.
        try expect(TLS13.verifyEd25519(publicKey: ed25519TestPublicKey,
                                       message: Data([0x72]),
                                       signature: ed25519TestSignature),
                   "RFC 8032 的 Ed25519 向量未通过验签")
        var badSignature = ed25519TestSignature
        badSignature[badSignature.startIndex] ^= 0x01
        try expect(!TLS13.verifyEd25519(publicKey: ed25519TestPublicKey,
                                        message: Data([0x72]),
                                        signature: badSignature),
                   "被篡改的 Ed25519 签名通过了验签")

        // The signed content of CertificateVerify: 64 spaces, the context
        // string, one zero byte, then the transcript hash.
        let content = TLS13.certificateVerifyContent(transcriptHash: transcriptThroughCertificateVerify)
        try expect(content.count == 64 + 33 + 1 + 32,
                   "CertificateVerify 待签名内容长度应为 130，实际 \(content.count)")
        try expect(Data(content.prefix(64)), Data(repeating: 0x20, count: 64),
                   "CertificateVerify 待签名内容的前 64 字节应为空格")
        try expect(Data(content.dropFirst(64).prefix(33)),
                   Data("TLS 1.3, server CertificateVerify".utf8),
                   "CertificateVerify 的上下文串")
        try expect(content[content.startIndex + 97] == 0x00, "上下文串之后必须是一个 0x00 分隔符")
        try expect(Data(content.suffix(32)), transcriptThroughCertificateVerify,
                   "CertificateVerify 待签名内容尾部应为 transcript hash")

        // The whole CertificateVerify path end to end, against a signature made
        // outside this file over RFC 8448's own transcript hash. Checking only
        // that a non-Ed25519 algorithm is rejected would leave the one code path
        // REALITY actually depends on — a genuine Ed25519 signature over the
        // prefixed content — never executed.
        try TLS13.verifyCertificateVerify(algorithm: TLS13.SignatureScheme.ed25519,
                                          signature: certificateVerifySignature,
                                          publicKey: certificateVerifyPublicKey,
                                          transcriptHash: transcriptThroughCertificateVerify)

        // The same signature against a transcript hash that differs in one bit
        // must fail, or the check above would pass for a replayed handshake.
        var alteredHash = transcriptThroughCertificateVerify
        alteredHash[alteredHash.startIndex] ^= 0x01
        do {
            try TLS13.verifyCertificateVerify(algorithm: TLS13.SignatureScheme.ed25519,
                                              signature: certificateVerifySignature,
                                              publicKey: certificateVerifyPublicKey,
                                              transcriptHash: alteredHash)
            throw Failure(text: "CertificateVerify 签名对错误的 transcript hash 也通过了")
        } catch is NativeOutboundError {}

        do {
            try TLS13.verifyCertificateVerify(algorithm: 0x0804, signature: Data(repeating: 0, count: 64),
                                              publicKey: ed25519TestPublicKey,
                                              transcriptHash: transcriptThroughCertificateVerify)
            throw Failure(text: "非 Ed25519 的签名算法未被拒绝")
        } catch is NativeOutboundError {}
    }

    private static func rejectsMalformedInput() throws {
        // A ServerHello wearing the HelloRetryRequest random. REALITY servers
        // cannot relay one, so seeing it means the connection already fell back.
        var retry = Data(serverHello.dropFirst(4))
        retry.replaceSubrange(retry.startIndex.advanced(by: 2)..<retry.startIndex.advanced(by: 34),
                              with: TLS13.helloRetryRequestRandom)
        do {
            _ = try TLS13.ServerHello(retry)
            throw Failure(text: "HelloRetryRequest 未被拒绝")
        } catch is NativeOutboundError {}

        // An unknown cipher suite must not be silently mapped onto a known one.
        var badSuite = Data(serverHello.dropFirst(4))
        let suiteOffset = badSuite.startIndex.advanced(by: 2 + 32 + 1)
        badSuite.replaceSubrange(suiteOffset..<suiteOffset.advanced(by: 2), with: Data([0x13, 0x04]))
        do {
            _ = try TLS13.ServerHello(badSuite)
            throw Failure(text: "未知 cipher suite 未被拒绝")
        } catch is NativeOutboundError {}

        // supported_versions saying TLS 1.2.
        var badVersion = Data(serverHello.dropFirst(4))
        badVersion.replaceSubrange(badVersion.endIndex.advanced(by: -2)..<badVersion.endIndex,
                                   with: Data([0x03, 0x03]))
        do {
            _ = try TLS13.ServerHello(badVersion)
            throw Failure(text: "非 TLS 1.3 的协商版本未被拒绝")
        } catch is NativeOutboundError {}

        // A truncated ServerHello must not read past the end of the buffer.
        do {
            _ = try TLS13.ServerHello(Data(serverHello.dropFirst(4).dropLast(10)))
            throw Failure(text: "被截断的 ServerHello 未被拒绝")
        } catch is NativeOutboundError {}

        // An oversized record length.
        var oversized = TLS13.RecordReader()
        oversized.append(Data([0x17, 0x03, 0x03, 0xFF, 0xFF]))
        do {
            _ = try oversized.next()
            throw Failure(text: "超长记录未被拒绝")
        } catch is NativeOutboundError {}

        // An oversized handshake message length.
        var hugeMessage = TLS13.HandshakeReader()
        hugeMessage.append(Data([0x0B, 0xFF, 0xFF, 0xFF]))
        do {
            _ = try hugeMessage.next()
            throw Failure(text: "超长握手消息未被拒绝")
        } catch is NativeOutboundError {}

        // A plaintext record fed to the protector: the outer type of a
        // TLSCiphertext is always 23, and accepting anything else means the AAD
        // no longer matches what the peer computed.
        let protector = try TLS13.RecordProtector(suite: .aes128GCMSHA256,
                                                  trafficSecret: serverHandshakeTraffic)
        do {
            _ = try protector.unprotect(TLS13.Record(contentType: 22, legacyVersion: 0x0303,
                                                     header: Data([0x16, 0x03, 0x03, 0x00, 0x01]),
                                                     fragment: Data([0x00])))
            throw Failure(text: "外层 content_type 非 23 的记录未被拒绝")
        } catch is NativeOutboundError {}

        // The record-size boundary. RFC 8446 §5.4 caps the encoded
        // TLSInnerPlaintext — content, content type and padding together — at
        // 2^14 + 1, so 2^14 bytes of content is the largest legal record and one
        // more byte must be refused here rather than by the peer's
        // record_overflow alert. Bounding the *ciphertext* by 2^14 + 256 instead
        // silently admits 239 bytes too many.
        let sizing = try TLS13.RecordProtector(suite: .aes128GCMSHA256,
                                               trafficSecret: clientApplicationTraffic)
        let full = Data(repeating: 0x5A, count: TLS13.maximumPlaintextLength)
        try expect(try sizing.protect(contentType: .applicationData, content: full).count
                    == TLS13.recordHeaderLength + TLS13.maximumPlaintextLength + 1 + 16,
                   "2^14 字节内容应恰好构成上限记录")
        do {
            _ = try sizing.protect(contentType: .applicationData, content: full + Data([0x00]))
            throw Failure(text: "超过 2^14 字节的内容未被拒绝")
        } catch is NativeOutboundError {}
        do {
            _ = try sizing.protect(contentType: .applicationData, content: full, paddingLength: 1)
            throw Failure(text: "内容加填充超过 2^14 未被拒绝")
        } catch is NativeOutboundError {}
        do {
            _ = try TLS13.plaintextRecord(contentType: .handshake,
                                          legacyVersion: TLS13.legacyRecordVersionInitial,
                                          fragment: full + Data([0x00]))
            throw Failure(text: "超长明文记录未被拒绝")
        } catch is NativeOutboundError {}

        // Certificate parsing must reject garbage instead of trapping.
        do {
            _ = try TLS13.LeafCertificate(der: Data([0x30, 0x82, 0xFF, 0xFF]))
            throw Failure(text: "长度越界的 DER 未被拒绝")
        } catch is NativeOutboundError {}
        do {
            _ = try TLS13.LeafCertificate(der: Data(ed25519Certificate.dropLast(20)))
            throw Failure(text: "被截断的证书未被拒绝")
        } catch is NativeOutboundError {}
        do {
            _ = try TLS13.LeafCertificate(der: Data([0x02, 0x01, 0x00]))
            throw Failure(text: "非 SEQUENCE 的证书未被拒绝")
        } catch is NativeOutboundError {}
    }

    // MARK: - Helpers

    private static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func hex(_ parts: [String]) -> Data {
        var out = Data()
        var high: UInt8?
        for part in parts {
            for character in part.utf8 {
                let value: UInt8
                switch character {
                case 0x30...0x39: value = character - 0x30
                case 0x61...0x66: value = character - 0x61 + 10
                case 0x41...0x46: value = character - 0x41 + 10
                default: continue
                }
                if let pending = high {
                    out.append(pending << 4 | value)
                    high = nil
                } else {
                    high = value
                }
            }
        }
        return out
    }

    // MARK: - Vectors

    // RFC 8448 §3 "Simple 1-RTT Handshake": every handshake message, every
    // record, every intermediate secret and every traffic key of one complete
    // trace. Extracted mechanically from the RFC text rather than typed in.
    private static let clientHello = hex([
        "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b000900000673657276",
        "6572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e",
        "51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c",
        "00024001",
    ])
    private static let clientHelloRecord = hex([
        "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b00090000",
        "06736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7d",
        "bafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00",
        "020101001c00024001",
    ])
    private static let serverHello = hex([
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb",
        "f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
    ])
    private static let serverHelloRecord = hex([
        "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095",
        "fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
    ])
    private static let encryptedExtensions = hex(["080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000"])
    private static let certificateMessage = hex([
        "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136",
        "303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d00",
        "30818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312",
        "0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a",
        "8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5",
        "b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102",
        "702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000",
    ])
    private static let certificateVerify = hex([
        "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248ee",
        "aaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea2",
        "0d53dfacd42f74f3",
    ])
    private static let serverFinished = hex(["140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"])
    private static let clientFinished = hex(["14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"])
    private static let newSessionTicket = hex([
        "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785a",
        "bc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529",
        "513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934a",
        "e4d3570008002a000400000400",
    ])
    private static let serverFlightPayload = hex([
        "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102",
        "020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335",
        "395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c",
        "0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e2",
        "2a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304",
        "023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594",
        "365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb",
        "2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f82",
        "4cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671",
        "459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4de",
        "da4ab42c309572cb7fffee5454b78f0718",
    ])
    private static let serverFlightRecord = hex([
        "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78",
        "b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9",
        "d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092",
        "8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b368",
        "4596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26",
        "f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e",
        "1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d4",
        "61e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb",
        "992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038",
        "ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5",
        "d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b",
    ])
    private static let clientFinishedRecord = hex(["170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546"])
    // Same key, same sequence number, same message as `clientFinishedRecord`,
    // with 26 zero octets of TLS 1.3 record padding. RFC 8448's trace never
    // pads, so this one was produced by a different AEAD implementation from the
    // RFC's own client handshake traffic secret; it is reproducible from
    // published numbers and it is not this file's output copied back.
    private static let clientFinishedPaddedRecord = hex([
        "170303004f75ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc690bb753a03d000c5efac53c619face25ad234dffb63",
        "e6114619c8728bbdcafa5174603d6c1023ff287c",
    ])
    private static let newSessionTicketRecord = hex([
        "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d41d6af8f6b580dcf3d11d63c758db289a015940252f55713e061dc13e078891a3",
        "8efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e09c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406",
        "f16e3fc181a77ca475840025db2f0a77f81b5ab05b94c01346755f69232c86519d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74",
        "bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf15985684f",
    ])
    private static let applicationPayload = hex(["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"])
    private static let clientApplicationRecord = hex([
        "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae6",
        "3aeebb21694915e4",
    ])
    private static let serverApplicationRecord = hex([
        "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf33254",
        "0dd032e167c2955d",
    ])
    private static let clientAlertRecord = hex(["1703030013c9872760655666b74d7ff1153efd6db6d0b0e3"])
    private static let serverAlertRecord = hex(["1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9"])

    private static let clientEphemeralPrivateKey = hex(["49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"])
    private static let serverEphemeralPublicKey = hex(["c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"])
    private static let ecdheSharedSecret = hex(["8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"])
    private static let earlySecret = hex(["33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"])
    private static let derivedForHandshake = hex(["6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"])
    private static let derivedInfo = hex(["00200d746c733133206465726976656420e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"])
    private static let handshakeSecret = hex(["1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"])
    private static let clientHandshakeTraffic = hex(["b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"])
    private static let clientHandshakeTrafficInfo = hex(["002012746c7331332063206873207472616666696320860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"])
    private static let serverHandshakeTraffic = hex(["b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"])
    private static let derivedForMaster = hex(["43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"])
    private static let masterSecret = hex(["18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"])
    private static let clientApplicationTraffic = hex(["9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"])
    private static let serverApplicationTraffic = hex(["a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"])
    private static let exporterMaster = hex(["fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"])
    private static let resumptionMaster = hex(["7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"])
    private static let serverHandshakeKey = hex(["3fce516009c21727d0f2e4e86ee403bc"])
    private static let serverHandshakeIV = hex(["5d313eb2671276ee13000b30"])
    private static let keyInfo = hex(["001009746c733133206b657900"])
    private static let ivInfo = hex(["000c08746c73313320697600"])
    private static let clientHandshakeKey = hex(["dbfaa693d1762c5b666af5d950258d01"])
    private static let clientHandshakeIV = hex(["5bd3c71b836e0b76bb73265f"])
    private static let serverApplicationKey = hex(["9f02283b6c9c07efc26bb9f2ac92e356"])
    private static let serverApplicationIV = hex(["cf782b88dd83549aadf1e984"])
    private static let clientApplicationKey = hex(["17422dda596ed5d9acd890e3c63f5051"])
    private static let clientApplicationIV = hex(["5b78923dee08579033e523d9"])
    private static let serverFinishedKey = hex(["008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"])
    private static let serverVerifyData = hex(["9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"])
    private static let finishedInfo = hex(["00200e746c7331332066696e697368656400"])
    private static let clientFinishedKey = hex(["b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"])
    private static let clientVerifyData = hex(["a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"])
    private static let transcriptClientServerHello = hex(["860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"])
    private static let transcriptThroughCertificateVerify = hex(["edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed"])
    private static let transcriptThroughServerFinished = hex(["9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"])
    private static let transcriptThroughClientFinished = hex(["209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"])

    // TLS_AES_256_GCM_SHA384. RFC 8448 never negotiates a SHA-384 suite, so these
    // were computed separately straight from the RFC 5869 / RFC 8446 definitions,
    // using RFC 8448's own ClientHello, ServerHello and ECDHE output as inputs so
    // that the whole ladder is reproducible from published numbers. The *shape* of
    // every step is already pinned by the SHA-256 vectors above; what these add is
    // that no length is wired to 32.
    private static let sha384EarlySecret = hex(["7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5"])
    private static let sha384DerivedInfo = hex([
        "00300d746c73313320646572697665643038b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b9",
        "5b",
    ])
    private static let sha384Derived = hex(["1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b"])
    private static let sha384HandshakeSecret = hex(["984e65f4ea6ac0dece14762ac3752b71867a045c60d3fe7808b31949d2ce27d3142e6da6d92a68437f77c26509ce0b2b"])
    private static let sha384Transcript = hex(["53585189fd526863cc1afbe3eecb2ba95ac94ba13e94d41603ce79f074ee1c0ae3879807076c5273a1a880d310208c54"])
    private static let sha384ClientHandshakeTraffic = hex(["29577dc122959b0e087c1eedb7a81bf2bf2cafb97c8bccc06536230567a8d85e734a0fb1da5926e4d83a58989fdab7c6"])
    private static let sha384ServerHandshakeTraffic = hex(["25351eb01a5c05cb096c6810d72fedf4735d48c878ee62ed44187b3fb6b57feba5c7f3b2fb622c28acb964ac70dba494"])
    private static let sha384ServerHandshakeKey = hex(["116a31a195f8551eebb463ca280d9282ad25156966d01c742c17a822a2950e16"])
    private static let sha384ServerHandshakeIV = hex(["040a4d7734ac0a8ccc445e2d"])
    private static let sha384MasterSecret = hex(["2915f95014de3957dad1c2764430fa490ffbe027a09be69e4da30a27969b40081308dbd17cb65a35332215cfc8cf4a2f"])
    private static let sha384ServerFinishedKey = hex(["e34bf12a86de504fd9d03c159098947d1e551edd788bb71796319df2b5698418b4b777626e44c407d889907ad69ee330"])
    private static let sha384ServerVerifyData = hex(["49b1ee4859b5462655a5af0e37f614227c5f786206a0a5813830c9be0a0a07469250e8b60d510534ef7e5919c6f7e911"])
    // RFC 8439 §2.8.2 — the AEAD_CHACHA20_POLY1305 example.
    private static let chachaKey = hex(["808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"])
    private static let chachaNonce = hex(["070000004041424344454647"])
    private static let chachaAAD = hex(["50515253c0c1c2c3c4c5c6c7"])
    private static let chachaPlaintext = hex([
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f",
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    ])
    private static let chachaCiphertext = hex([
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060",
        "0691",
    ])
    // draft-mcgrew-gcm-test-01 §4, the 32-octet-key case. Pins that a 32-byte key
    // selects AES-256 rather than being truncated to AES-128.
    private static let gcm256Key = hex(["abbccddef00112233445566778899aababbccddef00112233445566778899aab"])
    private static let gcm256Nonce = hex(["112233440102030405060708"])
    private static let gcm256AAD = hex(["4a2cbfe300000002"])
    private static let gcm256Plaintext = hex(["4500003069a6400080062690c0a801029389155e0a9e008b2dc57ee0000000007002400020bf0000020405b40101040201020201"])
    private static let gcm256Ciphertext = hex([
        "ff425c9b724599df7a3bcd510194e00d6a78107f1b0b1cbf06efae9d65a5d763748a637985771d347f0545659f14e99def842d8eb335f4eecfdbf831824b4c49",
        "15956c96",
    ])
    // A throwaway self-signed Ed25519 certificate (fixed serial and validity, so
    // the bytes are stable) standing in for the one a REALITY server forges. It
    // carries no secret: the private key was discarded after generation.
    private static let ed25519Certificate = hex([
        "308201333081e6a003020102020101300506032b657030193117301506035504030c0e746c7331332d73656c6674657374301e170d3230303130313030303030",
        "305a170d3430303130313030303030305a30193117301506035504030c0e746c7331332d73656c6674657374302a300506032b657003210084edb022ddb7c84b",
        "7b5136d6cf80376e5e0da40539e5061fcf1545e4640538d9a3533051301d0603551d0e04160414df7e5d59b6600c764a651581ed8be986551482a0301f060355",
        "1d23041830168014df7e5d59b6600c764a651581ed8be986551482a0300f0603551d130101ff040530030101ff300506032b6570034100ff83a7879796f0f0ae",
        "394d364ef7e90e56277d99253ce64c4f761f2b921982e0f72b0db7cbf680f665211e284b869cb83bdc7d7f2dc8217ed43afb3fc4bba90e",
    ])
    private static let ed25519PublicKey = hex(["84edb022ddb7c84b7b5136d6cf80376e5e0da40539e5061fcf1545e4640538d9"])
    // signatureValue of the RSA leaf inside RFC 8448's Certificate message.
    private static let rsaLeafSignature = hex([
        "85aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e",
        "67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de1",
    ])

    // RFC 8448 prints the resumption PSK for ticket_nonce 00 00. It is the only
    // derivation here whose context is neither empty nor a full hash, so it is
    // what pins the one-byte context length prefix.
    private static let resumptionPSK = hex(["4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"])

    // A throwaway Ed25519 key pair whose signature covers exactly what
    // `certificateVerifyContent` builds over RFC 8448's transcript hash through
    // CertificateVerify: 64 spaces, "TLS 1.3, server CertificateVerify", one
    // 0x00, then the hash. Signed outside this file; the private half was never
    // written down, so the vector can only be satisfied by producing the same
    // 130 bytes this file produces.
    private static let certificateVerifyPublicKey = hex(["79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"])
    private static let certificateVerifySignature = hex([
        "1028419efecde43a06887352aab7cc53ab7ce52f94821eaf7d9429d4b5991cc42c5f3cabc88654cc4834a0e0ccf9cca7fbe757925a59132ea14b0ff47d30890c",
    ])

    // RFC 8032 §7.1 TEST 2 — Ed25519 over the one-byte message 0x72.
    private static let ed25519TestPublicKey = hex(["3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"])
    private static let ed25519TestSignature = hex(["92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"])
}

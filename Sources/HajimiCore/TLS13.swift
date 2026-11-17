import Compression
import CryptoKit
import Foundation
import HajimiProtocolsCXX

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
        case compressedCertificate = 25
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
        let mlkem768PrivateKey: Data?

        init(message: Data,
             ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey,
             mlkem768PrivateKey: Data? = nil) {
            self.message = message
            self.ephemeralPrivateKey = ephemeralPrivateKey
            self.mlkem768PrivateKey = mlkem768PrivateKey
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

    /// RFC 10024 §3 Post-Quantum Traditional Hybrid Key Exchange (`X25519MLKEM768`, 0x11EC):
    /// Server key_share is `mlkem768_ciphertext (1088 bytes) || x25519_public_key (32 bytes)` = 1120 bytes.
    /// Combined shared secret is `mlkem768_shared_secret (32 bytes) || x25519_shared_secret (32 bytes)` = 64 bytes.
    static func hybridX25519MLKEM768SharedSecret(
        mlkemSharedSecret: Data,
        x25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        serverKeyShareData: Data
    ) throws -> (combinedSharedSecret: Data, mlkemCiphertext: Data) {
        guard mlkemSharedSecret.count == 32 else {
            throw NativeOutboundError.protocolError("ML-KEM-768 共享密钥必须是 32 字节，实际 \(mlkemSharedSecret.count) 字节")
        }
        guard serverKeyShareData.count == 1088 + 32 else {
            throw NativeOutboundError.protocolError("X25519MLKEM768 服务端 key_share 必须是 1120 字节，实际 \(serverKeyShareData.count) 字节")
        }
        let start = serverKeyShareData.startIndex
        let mlkemCiphertext = Data(serverKeyShareData[start..<(start + 1088)])
        let peerX25519 = Data(serverKeyShareData[(start + 1088)..<(start + 1120)])
        let ecdhe = try x25519(privateKey: x25519PrivateKey, peerPublicKey: peerX25519)
        var combined = Data(capacity: 64)
        combined.append(mlkemSharedSecret)
        combined.append(ecdhe)
        return (combined, mlkemCiphertext)
    }

    /// Runtime availability of NIST FIPS 203 `ML-KEM-768` in the linked OpenSSL 3.5+ provider.
    static var isMLKEM768Available: Bool {
        hajimi_cpp_mlkem768_available() != 0
    }

    /// Generates an ephemeral NIST FIPS 203 `ML-KEM-768` keypair (1184B public, 2400B private)
    /// backed by OpenSSL 3.5+ `EVP_PKEY`. Returns `nil` if linked against OpenSSL < 3.5.
    static func generateMLKEM768KeyPair() -> (publicKey: Data, privateKey: Data)? {
        guard isMLKEM768Available else { return nil }
        var pub = [UInt8](repeating: 0, count: 1184)
        var priv = [UInt8](repeating: 0, count: 2400)
        let ok = hajimi_cpp_mlkem768_keygen(&pub, pub.count, &priv, priv.count)
        guard ok == 1 else {
            for i in priv.indices { priv[i] = 0 }
            return nil
        }
        let privData = Data(priv)
        for i in priv.indices { priv[i] = 0 }
        return (Data(pub), privData)
    }

    /// Decapsulates a 1088-byte `ML-KEM-768` ciphertext into a 32-byte shared secret via OpenSSL 3.5+.
    static func mlkem768Decapsulate(privateKey: Data, ciphertext: Data) throws -> Data {
        guard privateKey.count == 2400, ciphertext.count == 1088 else {
            throw NativeOutboundError.protocolError("ML-KEM-768 私钥或密文长度不符合 FIPS 203 规范")
        }
        var secret = [UInt8](repeating: 0, count: 32)
        let ok = privateKey.withUnsafeBytes { skRaw -> Int32 in
            ciphertext.withUnsafeBytes { ctRaw -> Int32 in
                guard let skPtr = skRaw.bindMemory(to: UInt8.self).baseAddress,
                      let ctPtr = ctRaw.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return hajimi_cpp_mlkem768_decaps(skPtr, privateKey.count, ctPtr, ciphertext.count, &secret, secret.count)
            }
        }
        defer { for i in secret.indices { secret[i] = 0 } }
        guard ok == 1 else {
            throw NativeOutboundError.crypto("ML-KEM-768 解封装失败或当前 OpenSSL 运行时未启用 FIPS 203")
        }
        return Data(secret)
    }

    // MARK: - Minimal DER
}

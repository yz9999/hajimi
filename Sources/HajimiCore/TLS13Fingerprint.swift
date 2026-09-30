import CryptoKit
import Foundation

/// ClientHello fingerprint layer: a byte-exact transcription of uTLS's
/// `HelloChrome_133` preset (refraction-networking/utls `u_parrots.go:894-966`).
///
/// This file is pure data plus serialisation. It owns no handshake state, no
/// keys and no sockets — it turns a handful of caller-supplied values into the
/// exact bytes of one `client_hello` handshake message, including the 4-byte
/// handshake header, and nothing else.
///
/// Why the caller has to supply so much:
///
///   * `sessionID` is REALITY's authentication payload. It lives at a hard-coded
///     offset (39) inside the finished message and is AES-256-GCM sealed with
///     the *entire* message as associated data, so it can never be generated
///     here — see `sessionIDOffset`.
///   * `x25519PublicKey` must pair with a private key the caller keeps, because
///     REALITY derives its AuthKey from ECDH(that private key, server static
///     public key). A key generated inside this layer would be unusable.
///   * `random` is split by REALITY into an HKDF salt (`[0..<20]`) and a GCM
///     nonce (`[20..<32]`), so the caller needs the same bytes we emit.
///
/// Three things this layer deliberately does *not* do, and which the transport
/// above it must get right:
///
///   1. The record header. The first ClientHello goes out as
///      `16 03 01 <uint16 length>` — record version 0x0301, not 0x0303. uTLS
///      writes 0x0301 because `c.vers == 0` at that point
///      (`conn.go` `writeRecordLocked`); every fingerprinting library keys off
///      this and a wrong value still handshakes fine.
///   2. Nothing may be appended, padded or re-randomised after the bytes leave
///      here. REALITY seals with AAD = the final wire bytes; any later edit is a
///      silent authentication failure that surfaces as "connected to the real
///      website instead of the proxy".
///   3. The dummy `change_cipher_spec` record (`14 03 03 00 01 01`), and in
///      particular *when* it goes out. uTLS calls `sendDummyChangeCipherSpec`
///      only after the ServerHello has been processed
///      (`handshake_client_tls13.go:140`; `:93` on a HelloRetryRequest), so the
///      record belongs to the client's second flight, alongside Finished. It is
///      never glued behind the ClientHello in the first packet — no browser
///      does that, and doing it costs a distinguisher for nothing, because
///      nothing about the first flight depends on it. It is also not optional:
///      the REALITY server only pads its handshake records when the *upstream*
///      site answered with a CCS of its own, and the upstream only enters
///      middlebox-compatibility mode — and therefore only sends that CCS —
///      because our session_id is non-empty.
///
/// Known limitation, stated plainly: uTLS's newest Chrome preset is 133 and
/// real Chrome is far past that by now. Everything below therefore reproduces a
/// *stale* Chrome. The fingerprint is internally consistent and lands in the
/// "Chrome" bucket for JA3/JA4-style classifiers, but a censor that tracks
/// current Chrome releases can see that the claimed browser is several versions
/// behind — for instance by the post-quantum group selection, which Chrome has
/// kept changing. This cannot be fixed here; it needs a fresh capture of a real
/// Chrome ClientHello and a new preset.
enum TLS13Fingerprint {
    /// REALITY overwrites `hello.Raw[39..<71]`. 39 = 1 (msg_type) + 3 (uint24
    /// length) + 2 (legacy_version) + 32 (random) + 1 (session_id length byte).
    /// The self-test asserts this offset against the produced bytes, because a
    /// session_id of any other length silently relocates the payload onto the
    /// cipher_suites length field.
    static let sessionIDOffset = 39

    // MARK: - GREASE

    /// BoringSSL's five GREASE categories. uTLS mirrors the enum verbatim
    /// (`u_tls_extensions.go:962-970`); a sixth, `ssl_grease_ticket_extension`,
    /// doubles as the array bound and is therefore never usable.
    ///
    /// The categories matter because values are *shared within* a category and
    /// independent *across* categories: supported_groups and key_share both draw
    /// from `.group` and so must carry the identical value, while cipher_suites
    /// and supported_versions each draw their own. Filling every slot with the
    /// same constant handshakes perfectly and is a known early-uTLS signature.
    enum GREASECategory: Int {
        case cipher = 0
        case group = 1
        case extension1 = 2
        case extension2 = 3
        case version = 4
    }

    /// The 5 × uint16 seed BoringSSL keeps per connection.
    struct GREASESeed {
        private var words: [UInt16]

        /// `u_parrots.go:3050-3061`: read `2 * ssl_grease_last_index` = 10 bytes
        /// from the CSPRNG, parse them **little-endian** into five uint16, then
        /// apply the collision fixup once, before any value is read.
        init(seedBytes: Data) throws {
            let bytes = Array(seedBytes)
            guard bytes.count == 10 else {
                throw NativeOutboundError.protocolError("GREASE 种子必须是 10 字节，实际 \(bytes.count)")
            }
            var parsed = [UInt16]()
            parsed.reserveCapacity(5)
            for index in 0..<5 {
                parsed.append(UInt16(bytes[2 * index]) | (UInt16(bytes[2 * index + 1]) << 8))
            }
            words = parsed
            // The two GREASE *extensions* must not collide, or the ClientHello
            // carries a duplicate extension type and is illegal. BoringSSL
            // resolves it by perturbing the second seed, not the second value,
            // which flips exactly the nibble that survives into the value.
            if Self.value(of: words[GREASECategory.extension1.rawValue])
                == Self.value(of: words[GREASECategory.extension2.rawValue]) {
                words[GREASECategory.extension2.rawValue] ^= 0x1010
            }
        }

        init() throws {
            try self.init(seedBytes: secureRandom(count: 10))
        }

        /// `GetBoringGREASEValue`, `u_tls_extensions.go:983-991`. The result is
        /// always one of the 16 legal 0xωaωa values.
        func value(_ category: GREASECategory) -> UInt16 {
            Self.value(of: words[category.rawValue])
        }

        private static func value(of seed: UInt16) -> UInt16 {
            var result = (seed & 0x00f0) | 0x000a
            result |= result << 8
            return result
        }
    }

    // MARK: - GREASE ECH

    /// The `encrypted_client_hello` decoy Chrome sends when it has no real ECH
    /// config (`BoringGREASEECH()`, `u_ech.go:296-306`).
    ///
    /// Chrome offers exactly one candidate cipher suite — HKDF-SHA256 (0x0001)
    /// with AES-128-GCM (0x0001) — so those two are hard-coded below rather than
    /// being fields here.
    struct ECHGrease {
        /// One random byte. It must be re-rolled for every new ClientHello and
        /// only reused across a HelloRetryRequest.
        var configID: UInt8
        /// HPKE `enc`: for DHKEM(X25519, HKDF-SHA256) this is nothing but the
        /// sender's ephemeral X25519 public key, 32 bytes.
        var encapsulatedKey: Data
        /// `CandidatePayloadLens` = [128, 160, 192, 224] picked at random, then
        /// `cipherLen()` adds the 16-byte AEAD tag — so the wire lengths are
        /// 144/176/208/240, never the four listed numbers themselves.
        var payload: Data

        static let candidatePayloadLengths = [128, 160, 192, 224]

        static func random() -> ECHGrease {
            // Deliberately a real X25519 public key rather than 32 random bytes.
            // A serialised X25519 u-coordinate is < 2^255-19, so the top bit of
            // its last byte is always clear; random bytes would set it half the
            // time, which is a free distinguisher against every browser.
            let ephemeral = Curve25519.KeyAgreement.PrivateKey()
            let length = candidatePayloadLengths.randomElement()! + 16
            return ECHGrease(configID: secureRandom(count: 1)[0],
                             encapsulatedKey: ephemeral.publicKey.rawRepresentation,
                             payload: secureRandom(count: length))
        }
    }

    // MARK: - Inputs

    struct ChromeClientHelloInputs {
        /// Goes into server_name. An IP literal makes the whole extension
        /// disappear (uTLS `hostnameInSNI`), it does not produce an empty one.
        var serverName: String
        /// Exactly 32 bytes. REALITY's authentication payload.
        var sessionID: Data
        /// Exactly 32 bytes; the caller keeps the matching private key.
        var x25519PublicKey: Data
        /// Chrome always sends both, in this order. An empty array drops the
        /// extension entirely, which is a fingerprint deviation — Xray's
        /// WebSocket path does exactly that and it is a known leak, not a model
        /// to copy.
        var alpnProtocols: [String] = ["h2", "http/1.1"]
        /// Exactly 32 bytes when set; generated here otherwise. REALITY needs
        /// the same bytes for its HKDF salt and GCM nonce.
        var random: Data?
        /// Optional `X25519MLKEM768` share, 1216 bytes laid out as
        /// ML-KEM-768 encapsulation key (1184) ‖ X25519 public key (32) — the
        /// ML-KEM half comes *first*; the reversed layout belongs to the retired
        /// `X25519Kyber768Draft00`. Supplying it restores the exact Chrome 133
        /// group list; see the HRR discussion on `supportedGroups`.
        var hybridKeyShare: Data?
        /// Chrome 106+ reshuffles its extensions on every connection, so a fixed
        /// order is itself a fingerprint. Only the self-test turns this off.
        var shuffleExtensions: Bool = true
        /// Test hook: the 10 raw CSPRNG bytes behind the GREASE seed.
        var greaseSeedBytes: Data?
        /// Test hook: fixed GREASE ECH material.
        var echGrease: ECHGrease?
        /// Test hook: seed for the extension shuffle.
        var shuffleSeed: UInt64?

        init(serverName: String,
             sessionID: Data,
             x25519PublicKey: Data,
             alpnProtocols: [String] = ["h2", "http/1.1"],
             random: Data? = nil,
             hybridKeyShare: Data? = nil,
             shuffleExtensions: Bool = true,
             greaseSeedBytes: Data? = nil,
             echGrease: ECHGrease? = nil,
             shuffleSeed: UInt64? = nil) {
            self.serverName = serverName
            self.sessionID = sessionID
            self.x25519PublicKey = x25519PublicKey
            self.alpnProtocols = alpnProtocols
            self.random = random
            self.hybridKeyShare = hybridKeyShare
            self.shuffleExtensions = shuffleExtensions
            self.greaseSeedBytes = greaseSeedBytes
            self.echGrease = echGrease
            self.shuffleSeed = shuffleSeed
        }
    }

    // MARK: - Constants transcribed from u_parrots.go

    /// `u_parrots.go:896-913`. Index 0 is the GREASE placeholder, replaced with
    /// the `.cipher` value. Order is load-bearing: JA4's cipher hash sorts the
    /// list, but JA3's does not.
    private static let cipherSuites: [UInt16] = [
        0x0000,  // GREASE placeholder, overwritten below
        0x1301,  // TLS_AES_128_GCM_SHA256
        0x1302,  // TLS_AES_256_GCM_SHA384
        0x1303,  // TLS_CHACHA20_POLY1305_SHA256
        0xc02b,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc02f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc02c,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xcca9,  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xcca8,  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xc013,  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xc014,  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0x009c,  // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009d,  // TLS_RSA_WITH_AES_256_GCM_SHA384
        0x002f,  // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035,  // TLS_RSA_WITH_AES_256_CBC_SHA
    ]

    /// `u_parrots.go:935-944`. JA4 hashes this list **unsorted**, so the order
    /// is part of the fingerprint even though TLS itself treats it as a set.
    private static let signatureAlgorithms: [UInt16] = [
        0x0403,  // ecdsa_secp256r1_sha256
        0x0804,  // rsa_pss_rsae_sha256
        0x0401,  // rsa_pkcs1_sha256
        0x0503,  // ecdsa_secp384r1_sha384
        0x0805,  // rsa_pss_rsae_sha384
        0x0501,  // rsa_pkcs1_sha384
        0x0806,  // rsa_pss_rsae_sha512
        0x0601,  // rsa_pkcs1_sha512
    ]

    private enum Group {
        static let x25519MLKEM768: UInt16 = 0x11ec  // 4588
        static let x25519: UInt16 = 0x001d          // 29
        static let secp256r1: UInt16 = 0x0017       // 23
        static let secp384r1: UInt16 = 0x0018       // 24
    }

    private enum ExtensionType {
        static let serverName: UInt16 = 0x0000
        static let statusRequest: UInt16 = 0x0005
        static let supportedGroups: UInt16 = 0x000a
        static let ecPointFormats: UInt16 = 0x000b
        static let signatureAlgorithms: UInt16 = 0x000d
        static let alpn: UInt16 = 0x0010
        static let signedCertificateTimestamp: UInt16 = 0x0012
        static let extendedMasterSecret: UInt16 = 0x0017
        static let compressCertificate: UInt16 = 0x001b
        static let sessionTicket: UInt16 = 0x0023
        static let supportedVersions: UInt16 = 0x002b
        static let pskKeyExchangeModes: UInt16 = 0x002d
        static let keyShare: UInt16 = 0x0033
        /// ALPS. Chrome 131 used the old 0x4469; 133 moved to 0x44cd. Same wire
        /// format, different codepoint — copying the wrong one is invisible
        /// because servers just ignore what they do not recognise.
        static let applicationSettings: UInt16 = 0x44cd
        static let encryptedClientHello: UInt16 = 0xfe0d
        static let renegotiationInfo: UInt16 = 0xff01
    }

    // MARK: - Builder

    /// Builds one complete `client_hello` handshake message, header included.
    static func chromeClientHello(_ inputs: ChromeClientHelloInputs) throws -> Data {
        guard inputs.sessionID.count == 32 else {
            throw NativeOutboundError.protocolError(
                "session_id 必须是 32 字节，实际 \(inputs.sessionID.count) 字节；REALITY 的鉴权载荷依赖偏移 39 起的固定 32 字节")
        }
        guard inputs.x25519PublicKey.count == 32 else {
            throw NativeOutboundError.protocolError(
                "X25519 公钥必须是 32 字节，实际 \(inputs.x25519PublicKey.count) 字节")
        }
        let random = try resolvedRandom(inputs.random)
        if let hybrid = inputs.hybridKeyShare, hybrid.count != 1184 + 32 {
            throw NativeOutboundError.protocolError(
                "X25519MLKEM768 key_share 必须是 1216 字节（ML-KEM 封装密钥 1184 在前、X25519 公钥 32 在后），实际 \(hybrid.count) 字节")
        }
        for proto in inputs.alpnProtocols {
            let bytes = Data(proto.utf8)
            guard !bytes.isEmpty, bytes.count <= 255 else {
                throw NativeOutboundError.protocolError("ALPN 协议名长度必须在 1..255 字节之间：\"\(proto)\"")
            }
        }

        let seed = try inputs.greaseSeedBytes.map { try GREASESeed(seedBytes: $0) } ?? GREASESeed()
        let ech = inputs.echGrease ?? ECHGrease.random()
        guard ech.encapsulatedKey.count == 32 else {
            throw NativeOutboundError.protocolError(
                "GREASE ECH 的封装密钥必须是 32 字节，实际 \(ech.encapsulatedKey.count) 字节")
        }

        var extensions = try chromeExtensions(inputs: inputs, seed: seed, ech: ech)
        if inputs.shuffleExtensions {
            var rng = SplitMix64(seed: inputs.shuffleSeed ?? Self.randomSeed())
            shuffleChromeExtensions(&extensions, using: &rng)
        }

        var extensionBlock = Data()
        for item in extensions { extensionBlock.append(item.bytes) }
        guard extensionBlock.count <= 0xffff else {
            throw NativeOutboundError.protocolError("扩展总长度 \(extensionBlock.count) 超出 uint16 上限")
        }

        // Body layout, uTLS MarshalClientHelloNoECH (u_conn.go:636-661).
        var body = Data()
        body.append(uint16(0x0303))  // legacy_version is pinned to TLS 1.2 even
                                     // though we offer 1.3 in supported_versions.
        body.append(random)
        body.append(UInt8(inputs.sessionID.count))
        body.append(inputs.sessionID)
        body.append(uint16(UInt16(cipherSuites.count * 2)))
        var suites = cipherSuites
        suites[0] = seed.value(.cipher)
        for suite in suites { body.append(uint16(suite)) }
        body.append(contentsOf: [0x01, 0x00])  // compression_methods = { null }
        body.append(uint16(UInt16(extensionBlock.count)))
        body.append(extensionBlock)

        guard body.count <= 0xff_ffff else {
            throw NativeOutboundError.protocolError("ClientHello 长度 \(body.count) 超出 uint24 上限")
        }
        var message = Data([0x01,
                            UInt8(truncatingIfNeeded: body.count >> 16),
                            UInt8(truncatingIfNeeded: body.count >> 8),
                            UInt8(truncatingIfNeeded: body.count)])
        message.append(body)
        return message
    }

    private static func resolvedRandom(_ provided: Data?) throws -> Data {
        guard let provided else { return secureRandom(count: 32) }
        guard provided.count == 32 else {
            throw NativeOutboundError.protocolError("random 必须是 32 字节，实际 \(provided.count) 字节")
        }
        return provided
    }

    private static func randomSeed() -> UInt64 {
        secureRandom(count: 8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    // MARK: - Extension table

    private struct EncodedExtension {
        let bytes: Data
        /// GREASE, padding and pre_shared_key are pinned: uTLS's shuffle turns
        /// any swap touching them into a no-op, so GREASE #1 stays at index 0
        /// and GREASE #2 stays last.
        let positionInvariant: Bool
    }

    /// Chrome 133's extension table in declaration order
    /// (`u_parrots.go:917-965`), before the shuffle.
    private static func chromeExtensions(inputs: ChromeClientHelloInputs,
                                         seed: GREASESeed,
                                         ech: ECHGrease) throws -> [EncodedExtension] {
        var list = [EncodedExtension]()

        // [0] GREASE #1 — empty body. The order matters: the *first* GREASE
        // extension encountered takes `extension1` and an empty body, the second
        // takes `extension2` and exactly one 0x00 byte. Swapping the bodies
        // still handshakes and still looks wrong.
        list.append(EncodedExtension(bytes: extensionBytes(seed.value(.extension1), Data()),
                                     positionInvariant: true))

        // [1] server_name. When the name is an IP literal uTLS's SNIExtension
        // reports `Len() == 0` and writes nothing, but the extension *object*
        // stays in the array that gets shuffled — so the permutation is still
        // drawn over 18 slots. Keeping a zero-byte entry here reproduces that;
        // removing the slot outright would quietly shrink the shuffle's domain
        // to 17 and change the order distribution of everything else.
        var serverNameBytes = Data()
        if let host = sniHostName(inputs.serverName) {
            var body = Data([0x00])                 // name_type = host_name
            body.append(vector16(Data(host.utf8)))  // HostName
            serverNameBytes = extensionBytes(ExtensionType.serverName, vector16(body))
        }
        list.append(EncodedExtension(bytes: serverNameBytes, positionInvariant: false))

        // [2] extended_master_secret, zero-length body
        list.append(EncodedExtension(bytes: extensionBytes(ExtensionType.extendedMasterSecret, Data()),
                                     positionInvariant: false))

        // [3] renegotiation_info: a single zero length byte on a first handshake
        list.append(EncodedExtension(bytes: extensionBytes(ExtensionType.renegotiationInfo, vector8(Data())),
                                     positionInvariant: false))

        // [4] supported_groups
        //
        // Chrome 133 lists [GREASE, X25519MLKEM768, X25519, P-256, P-384] and
        // key-shares [GREASE, X25519MLKEM768, X25519]. We drop X25519MLKEM768
        // from *both* lists unless the caller hands us a hybrid share, and the
        // reason is REALITY, not fingerprinting:
        //
        //   * The REALITY server cannot answer a HelloRetryRequest — its
        //     ServerHello check demands a concrete `serverShare` and otherwise
        //     bails out into transparent fallback (REALITY `tls.go:353-361`).
        //     Advertising a group we have no share for is precisely how a
        //     HelloRetryRequest gets provoked, and the failure is silent: TCP
        //     connects, the certificate is the real site's, the proxy is dead.
        //   * Offering X25519MLKEM768 with a share means the upstream may select
        //     it, and then the *session* keys need ML-KEM decapsulation. Getting
        //     authenticated but failing at Finished is the worst of both worlds.
        //
        // Advertising only groups we can actually complete makes a
        // HelloRetryRequest impossible for any server that supports X25519,
        // which is every TLS 1.3 stack in practice. P-256/P-384 remain listed
        // because Chrome lists them and we never key-share them anyway.
        //
        // Honest accounting of what this costs. It is an unconfirmed risk on two
        // counts. First, a server that somehow refuses X25519 would send a
        // HelloRetryRequest for P-256 and REALITY would fall back silently —
        // untested, because no such public dest is known to us. Second, the
        // omission is observable: the ClientHello loses ~1.2 kB and ends up near
        // 500 bytes where a real Chrome 133 hello is around 1.7 kB, and the
        // group list no longer matches Chrome. JA4 is unaffected (it hashes
        // ciphers, extension types and signature algorithms — not groups), JA3
        // and raw length are. Passing `hybridKeyShare` restores byte-exact
        // Chrome once the core implements ML-KEM-768.
        //
        // Third, and this one is a trap that uTLS's preset table hides rather
        // than states: BoringSSL pads any ClientHello whose total length falls
        // in the open interval (0xff, 0x200) out to exactly 0x200 using
        // extension 0x0015 (`BoringPaddingStyle`,
        // `u_tls_extensions.go:1115-1126`). Chrome 133's preset carries no
        // padding extension purely because the ML-KEM share puts every hello
        // far past 0x200; Chrome 120's preset does carry one, as the very last
        // entry after GREASE #2 (`u_parrots.go:744`). Without the hybrid share
        // our message length is 339 + len(SNI) + ECH payload, so it lands
        // inside that interval whenever the ECH GREASE draws its 144-byte
        // payload — one time in four — and the SNI is shorter than 29 bytes.
        // That is a Chrome-shaped hello sitting at a length where a real
        // BoringSSL client would have padded and we did not.
        //
        // We still do not emit the padding extension, and the reason is a
        // deliberate trade rather than an oversight: extension 0x0015 changes
        // both the extension count and the sorted extension list, which is
        // exactly what JA4 hashes. As emitted, JA4 matches real Chrome 133
        // character for character (15 ciphers, 16 extensions, h2 first, and
        // identical JA4_b/JA4_c inputs) — dropping the group buys that for
        // free, since JA4 never looks at groups. Giving up an exact JA4 match
        // to satisfy a length heuristic that almost no deployed classifier
        // implements is the wrong way round. Supplying `hybridKeyShare`
        // removes the question entirely.
        var groups: [UInt16] = [seed.value(.group)]
        if inputs.hybridKeyShare != nil { groups.append(Group.x25519MLKEM768) }
        groups.append(contentsOf: [Group.x25519, Group.secp256r1, Group.secp384r1])
        var groupList = Data()
        for group in groups { groupList.append(uint16(group)) }
        list.append(EncodedExtension(bytes: extensionBytes(ExtensionType.supportedGroups, vector16(groupList)),
                                     positionInvariant: false))

        // [5] ec_point_formats = { uncompressed }
        list.append(EncodedExtension(bytes: extensionBytes(ExtensionType.ecPointFormats, vector8(Data([0x00]))),
                                     positionInvariant: false))

        // [6] session_ticket, empty. REALITY disables tickets server-side, and a
        // pre_shared_key is structurally incompatible with it anyway: the PSK
        // binder is computed over a truncated ClientHello while REALITY's AAD is
        // the complete one.
        list.append(EncodedExtension(bytes: extensionBytes(ExtensionType.sessionTicket, Data()),
                                     positionInvariant: false))

        // [7] ALPN. uTLS would write a 6-byte extension with an empty
        // ProtocolNameList for an empty protocol set, which RFC 7301 forbids;
        // we write nothing instead but keep the slot, for the same reason as
        // server_name above — the shuffle has to see 18 entries either way.
        var alpnBytes = Data()
        if !inputs.alpnProtocols.isEmpty {
            var protocolList = Data()
            for proto in inputs.alpnProtocols { protocolList.append(vector8(Data(proto.utf8))) }
            alpnBytes = extensionBytes(ExtensionType.alpn, vector16(protocolList))
        }
        list.append(EncodedExtension(bytes: alpnBytes, positionInvariant: false))

        // [8] status_request: OCSP, with two empty uint16 lists after it
        list.append(EncodedExtension(
            bytes: extensionBytes(ExtensionType.statusRequest, Data([0x01, 0x00, 0x00, 0x00, 0x00])),
            positionInvariant: false))

        // [9] signature_algorithms
        var algorithmList = Data()
        for algorithm in signatureAlgorithms { algorithmList.append(uint16(algorithm)) }
        list.append(EncodedExtension(
            bytes: extensionBytes(ExtensionType.signatureAlgorithms, vector16(algorithmList)),
            positionInvariant: false))

        // [10] signed_certificate_timestamp, zero-length body
        list.append(EncodedExtension(
            bytes: extensionBytes(ExtensionType.signedCertificateTimestamp, Data()),
            positionInvariant: false))

        // [11] key_share. The GREASE entry carries exactly one 0x00 byte — not a
        // zero-length share and not 32 random bytes; uTLS never generates a key
        // for it (`u_parrots.go:3121-3126`). Its group id is the *same*
        // `.group` value that supported_groups used.
        var shares = Data()
        shares.append(uint16(seed.value(.group)))
        shares.append(vector16(Data([0x00])))
        if let hybrid = inputs.hybridKeyShare {
            shares.append(uint16(Group.x25519MLKEM768))
            shares.append(vector16(hybrid))
        }
        shares.append(uint16(Group.x25519))
        shares.append(vector16(inputs.x25519PublicKey))
        list.append(EncodedExtension(bytes: extensionBytes(ExtensionType.keyShare, vector16(shares)),
                                     positionInvariant: false))

        // [12] psk_key_exchange_modes = { psk_dhe_ke }
        list.append(EncodedExtension(
            bytes: extensionBytes(ExtensionType.pskKeyExchangeModes, vector8(Data([0x01]))),
            positionInvariant: false))

        // [13] supported_versions = { GREASE, TLS 1.3, TLS 1.2 }
        var versionList = Data()
        versionList.append(uint16(seed.value(.version)))
        versionList.append(uint16(0x0304))
        versionList.append(uint16(0x0303))
        list.append(EncodedExtension(
            bytes: extensionBytes(ExtensionType.supportedVersions, vector8(versionList)),
            positionInvariant: false))

        // [14] compress_certificate = { brotli }. Declaring it obliges us to
        // decompress a CompressedCertificate(25) if the peer sends one — one of
        // the few mistakes in this file that would fail loudly rather than
        // silently.
        list.append(EncodedExtension(
            bytes: extensionBytes(ExtensionType.compressCertificate, vector8(uint16(0x0002))),
            positionInvariant: false))

        // [15] application_settings (ALPS), new codepoint, = { "h2" }
        list.append(EncodedExtension(
            bytes: extensionBytes(ExtensionType.applicationSettings, vector16(vector8(Data("h2".utf8)))),
            positionInvariant: false))

        // [16] GREASE encrypted_client_hello. Note this one is *not* pinned:
        // uTLS's skip list covers GREASE/padding/PSK extensions only, so the ECH
        // decoy takes part in the shuffle like any ordinary extension.
        var echBody = Data([0x00])       // ECHClientHelloType.outer
        echBody.append(uint16(0x0001))   // HPKE KDF  = HKDF-SHA256
        echBody.append(uint16(0x0001))   // HPKE AEAD = AES-128-GCM
        echBody.append(ech.configID)
        echBody.append(vector16(ech.encapsulatedKey))
        echBody.append(vector16(ech.payload))
        list.append(EncodedExtension(bytes: extensionBytes(ExtensionType.encryptedClientHello, echBody),
                                     positionInvariant: false))

        // [17] GREASE #2 — body is one 0x00 byte
        list.append(EncodedExtension(bytes: extensionBytes(seed.value(.extension2), Data([0x00])),
                                     positionInvariant: true))

        return list
    }

    /// uTLS `hostnameInSNI` (`handshake_client.go:1345-1360`): an IP literal —
    /// including one wrapped in brackets or carrying a `%zone` — yields no
    /// extension at all rather than an empty one, and trailing dots are stripped.
    private static func sniHostName(_ raw: String) -> String? {
        var host = raw
        if host.count >= 2, host.hasPrefix("["), host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        if let zone = host.lastIndex(of: "%"), zone != host.startIndex {
            host = String(host[host.startIndex..<zone])
        }
        if isIPLiteral(host) { return nil }
        var name = raw
        while name.hasSuffix(".") { name = String(name.dropLast()) }
        return name.isEmpty ? nil : name
    }

    private static func isIPLiteral(_ text: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 { return true }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 { return true }
        return false
    }

    // MARK: - Shuffle

    /// `ShuffleChromeTLSExtensions` (`u_parrots.go:2944-2977`).
    ///
    /// This is Fisher-Yates walking downwards, but a swap whose *either* index
    /// lands on a pinned extension is dropped on the floor instead of being
    /// retried. That makes the permutation non-uniform, and reproducing the bias
    /// matters: a textbook uniform shuffle of the 16 middle extensions has a
    /// different distribution from what uTLS and Chrome actually emit. The
    /// random draw happens before the skip test, exactly as in Go, so the
    /// consumption of randomness matches too.
    private static func shuffleChromeExtensions(_ extensions: inout [EncodedExtension],
                                                using rng: inout SplitMix64) {
        guard extensions.count > 1 else { return }
        var index = extensions.count - 1
        while index > 0 {
            let target = rng.index(upperBound: index + 1)
            if !extensions[index].positionInvariant && !extensions[target].positionInvariant {
                extensions.swapAt(index, target)
            }
            index -= 1
        }
    }

    /// Deterministic PRNG for the shuffle. Go seeds `math/rand` from
    /// `crypto/rand`; bit-compatibility with Go's generator buys nothing, but a
    /// seedable generator lets the self-test pin a permutation.
    struct SplitMix64 {
        private var state: UInt64

        init(seed: UInt64) { state = seed }

        mutating func next() -> UInt64 {
            state = state &+ 0x9e37_79b9_7f4a_7c15
            var z = state
            z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
            z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
            return z ^ (z >> 31)
        }

        /// Rejection-sampled so small bounds stay unbiased.
        mutating func index(upperBound: Int) -> Int {
            precondition(upperBound > 0)
            let bound = UInt64(upperBound)
            let limit = UInt64.max - (UInt64.max % bound) - 1
            while true {
                let draw = next()
                if draw <= limit { return Int(draw % bound) }
            }
        }
    }

    // MARK: - Encoding helpers

    private static func uint16(_ value: UInt16) -> Data {
        Data([UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
    }

    /// `uint16 length ‖ payload`
    private static func vector16(_ payload: Data) -> Data {
        var out = uint16(UInt16(truncatingIfNeeded: payload.count))
        out.append(payload)
        return out
    }

    /// `uint8 length ‖ payload`
    private static func vector8(_ payload: Data) -> Data {
        var out = Data([UInt8(truncatingIfNeeded: payload.count)])
        out.append(payload)
        return out
    }

    private static func extensionBytes(_ type: UInt16, _ body: Data) -> Data {
        var out = uint16(type)
        out.append(uint16(UInt16(truncatingIfNeeded: body.count)))
        out.append(body)
        return out
    }
}

// MARK: - Self-test

public enum TLS13FingerprintSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "TLS 指纹自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try greaseValues()
        try fixedVector()
        try structuralInvariants()
        try shuffleKeepsGREASEPinned()
        try defaultsAreWellFormed()
        try hybridKeyShareLayout()
        try ipLiteralDropsSNI()
        try rejectsBadInput()
    }

    // MARK: Fixed inputs shared by several checks

    private static let serverName = "www.example.com"
    private static let random = Data((0x00...0x1f).map { UInt8($0) })
    private static let sessionID = Data((0x20...0x3f).map { UInt8($0) })
    private static let publicKey = Data((0x40...0x5f).map { UInt8($0) })
    private static let echEncapsulatedKey = Data((0x60...0x7f).map { UInt8($0) })
    private static let seedBytes = Data([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa])

    private static var echGrease: TLS13Fingerprint.ECHGrease {
        TLS13Fingerprint.ECHGrease(
            configID: 0x5a,
            encapsulatedKey: echEncapsulatedKey,
            payload: Data((0..<144).map { UInt8(truncatingIfNeeded: $0 * 7 + 3) }))
    }

    private static func inputs(shuffle: Bool = false,
                               hybrid: Data? = nil,
                               serverName: String = serverName)
        -> TLS13Fingerprint.ChromeClientHelloInputs {
        TLS13Fingerprint.ChromeClientHelloInputs(
            serverName: serverName,
            sessionID: sessionID,
            x25519PublicKey: publicKey,
            random: random,
            hybridKeyShare: hybrid,
            shuffleExtensions: shuffle,
            greaseSeedBytes: seedBytes,
            echGrease: echGrease,
            shuffleSeed: 0x0123_4567_89ab_cdef)
    }

    /// Known answers for `GetBoringGREASEValue`, including the collision fixup.
    /// The seed words below are the little-endian reading of `seedBytes`.
    private static func greaseValues() throws {
        let seed = try TLS13Fingerprint.GREASESeed(seedBytes: seedBytes)
        // 0x2211 & 0xf0 = 0x10 -> 0x1a -> 0x1a1a, and so on up the list.
        try expect(seed.value(.cipher) == 0x1a1a, "cipher GREASE 应为 0x1a1a")
        try expect(seed.value(.group) == 0x3a3a, "group GREASE 应为 0x3a3a")
        try expect(seed.value(.extension1) == 0x5a5a, "extension1 GREASE 应为 0x5a5a")
        try expect(seed.value(.extension2) == 0x7a7a, "extension2 GREASE 应为 0x7a7a")
        try expect(seed.value(.version) == 0x9a9a, "version GREASE 应为 0x9a9a")

        // Every legal value is 0xωaωa.
        for nibble in 0..<16 {
            let raw = UInt16(nibble << 4)
            let bytes = Data([UInt8(truncatingIfNeeded: raw), UInt8(truncatingIfNeeded: raw >> 8),
                              0, 0, 0, 0, 0, 0, 0, 0])
            let value = try TLS13Fingerprint.GREASESeed(seedBytes: bytes).value(.cipher)
            let expected = UInt16(nibble << 4 | 0x0a)
            try expect(value == expected << 8 | expected,
                       "GREASE 生成规则错误：nibble \(nibble) 得到 \(String(value, radix: 16))")
        }

        // Collision fixup: both extension seeds pick nibble 5, so extension2's
        // seed is XORed with 0x1010 and lands on nibble 4.
        let colliding = Data([0, 0, 0, 0, 0x50, 0x00, 0x50, 0x00, 0, 0])
        let fixed = try TLS13Fingerprint.GREASESeed(seedBytes: colliding)
        try expect(fixed.value(.extension1) == 0x5a5a, "冲突消解不应改动 extension1")
        try expect(fixed.value(.extension2) == 0x4a4a,
                   "冲突消解后 extension2 应为 0x4a4a，实际 \(String(fixed.value(.extension2), radix: 16))")
    }

    /// The byte-for-byte vector. The expected value was assembled by hand from
    /// uTLS's field lists — not captured from this implementation — so a shared
    /// mistake between builder and test is not possible.
    private static func fixedVector() throws {
        let expected = try decodeHex(
            "010001ee0303000102030405060708090a0b0c0d0e0f10111213141516171819" +
            "1a1b1c1d1e1f20202122232425262728292a2b2c2d2e2f303132333435363738" +
            "393a3b3c3d3e3f00201a1a130113021303c02bc02fc02cc030cca9cca8c013c0" +
            "14009c009d002f0035010001855a5a000000000014001200000f7777772e6578" +
            "616d706c652e636f6d00170000ff01000100000a000a00083a3a001d00170018" +
            "000b00020100002300000010000e000c02683208687474702f312e3100050005" +
            "0100000000000d00120010040308040401050308050501080606010012000000" +
            "33002b00293a3a000100001d0020404142434445464748494a4b4c4d4e4f5051" +
            "52535455565758595a5b5c5d5e5f002d00020101002b0007069a9a0304030300" +
            "1b000302000244cd00050003026832fe0d00ba00000100015a00206061626364" +
            "65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0090030a11" +
            "181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1" +
            "f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1" +
            "d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1" +
            "b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91" +
            "989fa6adb4bbc2c9d0d7dee5ec7a7a000100")
        let actual = try TLS13Fingerprint.chromeClientHello(inputs())
        try expect(actual.count == expected.count,
                   "ClientHello 长度应为 \(expected.count) 字节，实际 \(actual.count) 字节")
        if actual != expected {
            let bytes = Array(actual)
            let reference = Array(expected)
            var offset = 0
            while offset < bytes.count && bytes[offset] == reference[offset] { offset += 1 }
            throw Failure(text: "定值向量在偏移 \(offset) 处不符：期望 " +
                          String(format: "%02x", reference[offset]) + "，实际 " +
                          String(format: "%02x", bytes[offset]))
        }
    }

    /// Everything REALITY and the record layer depend on structurally.
    private static func structuralInvariants() throws {
        let hello = try TLS13Fingerprint.chromeClientHello(inputs())
        let bytes = Array(hello)

        try expect(bytes[0] == 0x01, "handshake type 应为 0x01")
        let declared = Int(bytes[1]) << 16 | Int(bytes[2]) << 8 | Int(bytes[3])
        try expect(declared == bytes.count - 4,
                   "handshake 长度字段 \(declared) 与实际 \(bytes.count - 4) 不符")
        try expect(bytes[4] == 0x03 && bytes[5] == 0x03, "legacy_version 应为 0x0303")
        try expect(bytes[38] == 32, "session_id 长度字节应为 0x20，实际 \(bytes[38])")
        try expect(Data(bytes[39..<71]) == sessionID,
                   "session_id 未落在偏移 \(TLS13Fingerprint.sessionIDOffset) 起的 32 字节")

        let parsed = try parse(hello)
        try expect(parsed.cipherSuites.count == 16, "cipher_suites 应有 16 项")
        try expect(parsed.cipherSuites[0] == 0x1a1a, "cipher_suites 首项应为 cipher GREASE")
        try expect(parsed.compressionMethods == [0x00], "compression_methods 应为 { 0x00 }")
        try expect(parsed.extensions.count == 18, "扩展应有 18 项，实际 \(parsed.extensions.count)")

        // The extension length field is self-consistent: walking the list lands
        // exactly on the end of the message, which `parse` already enforced.
        let sum = parsed.extensions.reduce(0) { $0 + 4 + $1.body.count }
        try expect(sum == parsed.extensionsLength,
                   "扩展总长度字段 \(parsed.extensionsLength) 与逐项累加 \(sum) 不符")

        // Same-category GREASE must be identical, cross-category must not be.
        guard let groups = parsed.extensions.first(where: { $0.type == 0x000a })?.body,
              let keyShare = parsed.extensions.first(where: { $0.type == 0x0033 })?.body,
              let versions = parsed.extensions.first(where: { $0.type == 0x002b })?.body else {
            throw Failure(text: "缺少 supported_groups / key_share / supported_versions")
        }
        let groupGREASE = UInt16(groups[2]) << 8 | UInt16(groups[3])
        let shareGREASE = UInt16(keyShare[2]) << 8 | UInt16(keyShare[3])
        try expect(groupGREASE == shareGREASE,
                   "supported_groups 与 key_share 的 GREASE 必须同值：\(String(groupGREASE, radix: 16)) vs \(String(shareGREASE, radix: 16))")
        let versionGREASE = UInt16(versions[1]) << 8 | UInt16(versions[2])
        try expect(versionGREASE == 0x9a9a, "supported_versions 的 GREASE 取值错误")
        try expect(parsed.extensions[0].type == 0x5a5a && parsed.extensions[0].body.isEmpty,
                   "首个 GREASE 扩展必须取 extension1 且体长为 0")
        let last = parsed.extensions[parsed.extensions.count - 1]
        try expect(last.type == 0x7a7a && last.body == Data([0x00]),
                   "末个 GREASE 扩展必须取 extension2 且体为单个 0x00")
        try expect(parsed.extensions[0].type != last.type, "两个 GREASE 扩展不得同值")

        // The GREASE key_share entry is one 0x00 byte, never an empty or real one.
        try expect(keyShare[4] == 0x00 && keyShare[5] == 0x01 && keyShare[6] == 0x00,
                   "GREASE key_share 的 data 必须是单字节 0x00")

        // No duplicate extension types — a duplicate is an illegal ClientHello.
        var seen = Set<UInt16>()
        for item in parsed.extensions {
            try expect(seen.insert(item.type).inserted,
                       "扩展类型重复：\(String(item.type, radix: 16))")
        }

        // The groups we advertise must be exactly the ones we can complete, or
        // the REALITY server may face a HelloRetryRequest it cannot answer.
        let advertised = stride(from: 2, to: groups.count, by: 2).map {
            UInt16(groups[$0]) << 8 | UInt16(groups[$0 + 1])
        }
        try expect(!advertised.contains(0x11ec),
                   "未提供 hybrid key_share 时不得声明 X25519MLKEM768，否则可能触发 HelloRetryRequest")
        try expect(advertised.contains(0x001d), "supported_groups 必须包含 X25519")
    }

    /// The shuffle may move anything except the two GREASE extensions, and it
    /// must never lose, duplicate or resize one.
    private static func shuffleKeepsGREASEPinned() throws {
        let reference = try parse(TLS13Fingerprint.chromeClientHello(inputs()))
        let referenceTypes = Set(reference.extensions.map { $0.type })
        var sawReorder = false

        for seed in UInt64(1)...64 {
            var configuration = inputs(shuffle: true)
            configuration.shuffleSeed = seed
            let shuffled = try parse(TLS13Fingerprint.chromeClientHello(configuration))

            try expect(shuffled.extensions.count == reference.extensions.count,
                       "洗牌改变了扩展数量（seed \(seed)）")
            try expect(Set(shuffled.extensions.map { $0.type }) == referenceTypes,
                       "洗牌改变了扩展集合（seed \(seed)）")
            try expect(shuffled.extensions[0].type == 0x5a5a,
                       "洗牌后首位不再是 GREASE #1（seed \(seed)）")
            try expect(shuffled.extensions[shuffled.extensions.count - 1].type == 0x7a7a,
                       "洗牌后末位不再是 GREASE #2（seed \(seed)）")
            try expect(shuffled.extensionsLength == reference.extensionsLength,
                       "洗牌改变了扩展总长度（seed \(seed)）")
            if shuffled.extensions.map({ $0.type }) != reference.extensions.map({ $0.type }) {
                sawReorder = true
            }
        }
        try expect(sawReorder, "洗牌在 64 个种子上从未改变过顺序，说明洗牌未生效")
    }

    /// Every other check pins the GREASE seed, the ECH material and the shuffle
    /// seed, so none of them ever executes the production paths that draw from
    /// the CSPRNG. This one does, and checks the parts that are still fixed.
    private static func defaultsAreWellFormed() throws {
        for _ in 0..<32 {
            let configuration = TLS13Fingerprint.ChromeClientHelloInputs(
                serverName: serverName,
                sessionID: sessionID,
                x25519PublicKey: publicKey)
            let hello = try TLS13Fingerprint.chromeClientHello(configuration)
            let bytes = Array(hello)
            try expect(bytes[38] == 32 && Data(bytes[39..<71]) == sessionID,
                       "随机化构造下 session_id 偏移被破坏")
            let parsed = try parse(hello)
            try expect(parsed.extensions.count == 18, "随机化构造下扩展数量错误")

            let leading = parsed.extensions[0].type
            let trailing = parsed.extensions[parsed.extensions.count - 1].type
            for value in [leading, trailing, parsed.cipherSuites[0]] {
                try expect(value >> 8 == value & 0xff && value & 0x0f == 0x0a,
                           "非法的 GREASE 值 \(String(value, radix: 16))")
            }
            try expect(leading != trailing, "两个 GREASE 扩展撞值，冲突消解未生效")
            try expect(parsed.extensions[0].body.isEmpty, "首个 GREASE 扩展体应为空")
            try expect(parsed.extensions[parsed.extensions.count - 1].body == Data([0x00]),
                       "末个 GREASE 扩展体应为单个 0x00")

            guard let ech = parsed.extensions.first(where: { $0.type == 0xfe0d })?.body else {
                throw Failure(text: "缺少 GREASE ECH 扩展")
            }
            // 1 type + 4 cipher suite + 1 config_id + 2 + 32 enc + 2 + payload
            let encLength = Int(ech[6]) << 8 | Int(ech[7])
            try expect(encLength == 32, "GREASE ECH 的 enc 长度应为 32，实际 \(encLength)")
            let payloadLength = Int(ech[40]) << 8 | Int(ech[41])
            try expect([144, 176, 208, 240].contains(payloadLength),
                       "GREASE ECH 的 payload 长度应为 128/160/192/224 加 16 字节 tag，实际 \(payloadLength)")
            try expect(ech.count == 42 + payloadLength, "GREASE ECH 扩展体长度不自洽")
            // A real X25519 public key never has the top bit of its last byte set.
            try expect(ech[8 + 31] & 0x80 == 0, "GREASE ECH 的 enc 不像 X25519 公钥")
        }
    }

    /// If the caller can do ML-KEM, the hybrid share must land between the
    /// GREASE entry and the classical X25519 entry, ML-KEM half first.
    private static func hybridKeyShareLayout() throws {
        let hybrid = Data((0..<1216).map { UInt8(truncatingIfNeeded: $0) })
        let parsed = try parse(TLS13Fingerprint.chromeClientHello(inputs(hybrid: hybrid)))
        guard let keyShare = parsed.extensions.first(where: { $0.type == 0x0033 })?.body,
              let groups = parsed.extensions.first(where: { $0.type == 0x000a })?.body else {
            throw Failure(text: "缺少 key_share / supported_groups")
        }
        // client_shares length + GREASE(5) + hybrid(4+1216) + X25519(4+32)
        try expect(keyShare.count == 2 + 5 + 1220 + 36,
                   "带 hybrid 的 key_share 长度错误：\(keyShare.count)")
        let hybridGroup = UInt16(keyShare[7]) << 8 | UInt16(keyShare[8])
        let hybridLength = Int(keyShare[9]) << 8 | Int(keyShare[10])
        try expect(hybridGroup == 0x11ec, "第二个 key_share 应为 X25519MLKEM768")
        try expect(hybridLength == 1216, "X25519MLKEM768 的 key_exchange 长度应为 1216")
        try expect(Data(keyShare[11..<(11 + 1216)]) == hybrid, "hybrid key_share 内容被改动")
        let classicalGroup = UInt16(keyShare[11 + 1216]) << 8 | UInt16(keyShare[12 + 1216])
        try expect(classicalGroup == 0x001d, "最后一个 key_share 应为 X25519")
        let advertised = stride(from: 2, to: groups.count, by: 2).map {
            UInt16(groups[$0]) << 8 | UInt16(groups[$0 + 1])
        }
        try expect(advertised == [0x3a3a, 0x11ec, 0x001d, 0x0017, 0x0018],
                   "带 hybrid 时 supported_groups 应与 Chrome 133 一致")
    }

    /// An IP literal removes the whole server_name extension; it does not emit
    /// an empty one. JA4's SNI flag flips from 'd' to 'i' as a result.
    private static func ipLiteralDropsSNI() throws {
        for literal in ["203.0.113.7", "[2001:db8::1]", "fe80::1%en0"] {
            let parsed = try parse(TLS13Fingerprint.chromeClientHello(inputs(serverName: literal)))
            try expect(!parsed.extensions.contains { $0.type == 0x0000 },
                       "IP 字面量 \(literal) 仍写出了 server_name 扩展")
            try expect(parsed.extensions.count == 17, "IP 字面量下扩展应剩 17 项")
        }
        // The dropped extension leaves a zero-byte slot behind so the shuffle
        // still runs over 18 entries; make sure that slot never reaches the
        // wire and never displaces a pinned GREASE.
        for seed in UInt64(1)...16 {
            var configuration = inputs(shuffle: true, serverName: "203.0.113.7")
            configuration.shuffleSeed = seed
            let parsed = try parse(TLS13Fingerprint.chromeClientHello(configuration))
            try expect(parsed.extensions.count == 17,
                       "IP 字面量洗牌后扩展应剩 17 项（seed \(seed)），实际 \(parsed.extensions.count)")
            try expect(parsed.extensions[0].type == 0x5a5a
                       && parsed.extensions[parsed.extensions.count - 1].type == 0x7a7a,
                       "IP 字面量洗牌后两端不再是 GREASE（seed \(seed)）")
            try expect(!parsed.extensions.contains { $0.type == 0x0000 },
                       "IP 字面量洗牌后仍写出了 server_name 扩展（seed \(seed)）")
        }

        // A trailing dot is stripped, the extension stays.
        let dotted = try parse(TLS13Fingerprint.chromeClientHello(inputs(serverName: "example.com.")))
        guard let sni = dotted.extensions.first(where: { $0.type == 0x0000 })?.body else {
            throw Failure(text: "绝对域名下 server_name 扩展丢失")
        }
        try expect(Data(sni[5...]) == Data("example.com".utf8), "末尾的点未被剥掉")
    }

    private static func rejectsBadInput() throws {
        var short = inputs()
        short.sessionID = Data(repeating: 0, count: 16)
        try expectThrows(short, "16 字节 session_id 未被拒绝")

        var badKey = inputs()
        badKey.x25519PublicKey = Data(repeating: 0, count: 31)
        try expectThrows(badKey, "31 字节公钥未被拒绝")

        var badRandom = inputs()
        badRandom.random = Data(repeating: 0, count: 31)
        try expectThrows(badRandom, "31 字节 random 未被拒绝")

        var badHybrid = inputs()
        badHybrid.hybridKeyShare = Data(repeating: 0, count: 1184)
        try expectThrows(badHybrid, "长度错误的 hybrid key_share 未被拒绝")

        var badALPN = inputs()
        badALPN.alpnProtocols = ["h2", ""]
        try expectThrows(badALPN, "空 ALPN 协议名未被拒绝")

        // 9 bytes is the seed length of a GREASE implementation that forgot
        // ssl_grease_last_index is 5 and read 2*4+1 bytes.
        var badSeed = inputs()
        badSeed.greaseSeedBytes = Data(repeating: 0, count: 9)
        try expectThrows(badSeed, "9 字节 GREASE 种子未被拒绝")

        var badECH = inputs()
        badECH.echGrease = TLS13Fingerprint.ECHGrease(configID: 0,
                                                     encapsulatedKey: Data(repeating: 0, count: 31),
                                                     payload: Data(repeating: 0, count: 144))
        try expectThrows(badECH, "31 字节 GREASE ECH 封装密钥未被拒绝")
    }

    private static func expectThrows(_ configuration: TLS13Fingerprint.ChromeClientHelloInputs,
                                     _ message: String) throws {
        do {
            _ = try TLS13Fingerprint.chromeClientHello(configuration)
            throw Failure(text: message)
        } catch is NativeOutboundError {}
    }

    // MARK: Minimal ClientHello reader, used only by the assertions above

    private struct ParsedExtension {
        let type: UInt16
        let body: Data
    }

    private struct ParsedHello {
        let cipherSuites: [UInt16]
        let compressionMethods: [UInt8]
        let extensionsLength: Int
        let extensions: [ParsedExtension]
    }

    private static func parse(_ message: Data) throws -> ParsedHello {
        let bytes = Array(message)
        var cursor = 4 + 2 + 32
        guard bytes.count > cursor else { throw Failure(text: "ClientHello 过短") }
        let sessionLength = Int(bytes[cursor])
        cursor += 1 + sessionLength

        guard bytes.count >= cursor + 2 else { throw Failure(text: "cipher_suites 长度字段越界") }
        let suitesLength = Int(bytes[cursor]) << 8 | Int(bytes[cursor + 1])
        cursor += 2
        guard suitesLength % 2 == 0, bytes.count >= cursor + suitesLength else {
            throw Failure(text: "cipher_suites 长度 \(suitesLength) 非法")
        }
        var suites = [UInt16]()
        for offset in stride(from: cursor, to: cursor + suitesLength, by: 2) {
            suites.append(UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1]))
        }
        cursor += suitesLength

        guard bytes.count > cursor else { throw Failure(text: "compression_methods 越界") }
        let compressionLength = Int(bytes[cursor])
        cursor += 1
        guard bytes.count >= cursor + compressionLength else {
            throw Failure(text: "compression_methods 长度 \(compressionLength) 越界")
        }
        let compression = Array(bytes[cursor..<(cursor + compressionLength)])
        cursor += compressionLength

        guard bytes.count >= cursor + 2 else { throw Failure(text: "扩展长度字段越界") }
        let extensionsLength = Int(bytes[cursor]) << 8 | Int(bytes[cursor + 1])
        cursor += 2
        guard bytes.count == cursor + extensionsLength else {
            throw Failure(text: "扩展总长度 \(extensionsLength) 与消息尾部不符")
        }

        var extensions = [ParsedExtension]()
        let end = cursor + extensionsLength
        while cursor < end {
            guard cursor + 4 <= end else { throw Failure(text: "扩展头越界") }
            let type = UInt16(bytes[cursor]) << 8 | UInt16(bytes[cursor + 1])
            let length = Int(bytes[cursor + 2]) << 8 | Int(bytes[cursor + 3])
            cursor += 4
            guard cursor + length <= end else {
                throw Failure(text: "扩展 \(String(type, radix: 16)) 的长度 \(length) 越界")
            }
            extensions.append(ParsedExtension(type: type,
                                              body: Data(bytes[cursor..<(cursor + length)])))
            cursor += length
        }
        return ParsedHello(cipherSuites: suites, compressionMethods: compression,
                           extensionsLength: extensionsLength, extensions: extensions)
    }

    private static func decodeHex(_ text: String) throws -> Data {
        let characters = Array(text)
        guard characters.count % 2 == 0 else { throw Failure(text: "十六进制向量长度为奇数") }
        var out = Data(capacity: characters.count / 2)
        for index in stride(from: 0, to: characters.count, by: 2) {
            guard let value = UInt8(String(characters[index...(index + 1)]), radix: 16) else {
                throw Failure(text: "十六进制向量含非法字符")
            }
            out.append(value)
        }
        return out
    }
}

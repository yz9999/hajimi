import Foundation
import CryptoKit

// mKCP's wire format: segment encoding, datagram framing and header camouflage.
// The ARQ state machine sits on top of these types.
//
// mKCP shares a name and an idea with ikcp and nothing else. ikcp's header is
// 24 bytes, little-endian, with a 32-bit conv and commands 81..84; mKCP's is a
// 4-byte common prefix, big-endian throughout, with a 16-bit conv, commands
// 0..3 and no fragment field. Porting any ikcp implementation produces a client
// that never connects, and the only symptom is silence: the server logs one
// "discarding invalid payload" line and drops the datagram.
//
// Everything here either drops or throws where Xray drops. There is no error
// channel on the wire — a rejected datagram is indistinguishable from a lost
// one — so every guard exists to keep a malformed packet from being mistaken
// for a good one, never to report anything to the peer.
//
// Verified against XTLS/Xray-core v1.8.24 transport/internet/kcp/* (the format
// every deployed server before v26.1.31 speaks) and against the byte-identical
// relocation in transport/internet/finalmask/mkcp/* on main.

// MARK: - Segment types

/// The four commands. Any other value is still parsed — as a command-only
/// segment — which is why an ikcp port using 81..84 fails silently instead of
/// loudly: the far side accepts every packet and finds no data in any of them.
enum MKCPCommand: UInt8 {
    case ack = 0
    case data = 1
    case terminate = 2
    case ping = 3
}

/// The option byte. Only bit 0 is defined.
///
/// Setting `close` on a segment that is not closing anything makes the peer
/// discard its entire pending send queue and stop transmitting, while the
/// connection itself stays up. It presents as "the server went quiet", so this
/// bit must be zero on every ordinary segment.
struct MKCPSegmentOption: OptionSet {
    let rawValue: UInt8
    init(rawValue: UInt8) { self.rawValue = rawValue }

    static let close = MKCPSegmentOption(rawValue: 1)
}

/// cmd = 1. Header is 18 bytes; `payload` follows it.
struct MKCPDataSegment {
    /// `DataSegmentOverhead` upstream. The split point for application data is
    /// derived from it, so it is load-bearing far beyond parsing.
    static let overhead = 18

    var conversation: UInt16
    var option: MKCPSegmentOption
    /// Milliseconds since *this connection* was created, truncated to 32 bits —
    /// not a Unix timestamp. The peer echoes it back in an ACK and subtracts,
    /// so a wall-clock value yields an astronomical RTT, pins the peer's RTO at
    /// its 12500 ms ceiling and all but stops its retransmissions.
    ///
    /// Rewritten on every retransmission, not fixed at first send.
    var timestamp: UInt32
    /// Sequence number, from 0, +1 per segment. A random ISN puts every segment
    /// outside the receiver's window, where it is dropped without an ACK.
    var number: UInt32
    /// Upstream calls this field `SendingNext`, but the sender writes its
    /// `firstUnacknowledged` (una) into it — the receiver uses it to retire ACK
    /// list entries. Writing the true "next" number retires them early and
    /// costs a great deal of needless retransmission.
    var sendingNext: UInt32
    var payload: Data

    init(conversation: UInt16, option: MKCPSegmentOption = [], timestamp: UInt32,
         number: UInt32, sendingNext: UInt32, payload: Data) {
        self.conversation = conversation
        self.option = option
        self.timestamp = timestamp
        self.number = number
        self.sendingNext = sendingNext
        self.payload = payload
    }

    var byteSize: Int { MKCPDataSegment.overhead + payload.count }
}

/// cmd = 0. Header is 17 bytes, then `numbers.count` big-endian sequence
/// numbers.
struct MKCPAckSegment {
    /// The sender-side cap: `count` is a single byte at offset 16 and upstream
    /// never emits more than this. The parser accepts up to 255, so this is not
    /// a receive-side limit.
    static let numberLimit = 128

    /// How many acknowledgements one segment may carry at a given MTU.
    ///
    /// v1.8.24 ignores the MTU and stops at the flat 128 above; current main
    /// clamps to `(mtu - 17) / 4` first. The two agree at mtu 1350, and the
    /// smaller value is always safe to send, so take the clamp.
    static func numberLimit(forMTU mtu: Int) -> Int {
        max(1, min(numberLimit, (mtu - 17) / 4))
    }

    var conversation: UInt16
    var option: MKCPSegmentOption
    /// An absolute right edge — the receiver's `nextNumber + windowSize` — not
    /// a window *size*. The peer computes its send quota as
    /// `receivingWindow - firstUnacknowledged`, so a plain count here collapses
    /// that to roughly zero and the connection goes idle without any error.
    var receivingWindow: UInt32
    /// Cumulative acknowledgement point: the receiver's `nextNumber`.
    var receivingNext: UInt32
    /// Echo of the largest `timestamp` among the data segments being
    /// acknowledged. It must be the peer's clock, never ours — the peer
    /// subtracts it from its own clock to sample RTT.
    var timestamp: UInt32
    /// Selective acknowledgements.
    var numbers: [UInt32]

    init(conversation: UInt16, option: MKCPSegmentOption = [], receivingWindow: UInt32,
         receivingNext: UInt32, timestamp: UInt32, numbers: [UInt32]) {
        self.conversation = conversation
        self.option = option
        self.receivingWindow = receivingWindow
        self.receivingNext = receivingNext
        self.timestamp = timestamp
        self.numbers = numbers
    }

    var byteSize: Int { 17 + numbers.count * 4 }
}

/// cmd = 2 (terminate), 3 (ping), or anything unrecognised. Always 16 bytes.
struct MKCPCommandSegment {
    var conversation: UInt16
    /// Kept as a raw byte because upstream routes *every* unrecognised command
    /// through this segment shape and still applies its una/next/RTO fields.
    /// Folding unknown values onto `.ping` would silently rewrite them on the
    /// way back out.
    var rawCommand: UInt8
    var option: MKCPSegmentOption
    /// The sender's `firstUnacknowledged` (una), same as `MKCPDataSegment`.
    var sendingNext: UInt32
    /// The sender's receive-side `nextNumber`.
    var receivingNext: UInt32
    /// Our current RTO in milliseconds. The peer adopts this value outright
    /// (throttled to once per 3000 ms), so sending 0 makes every segment in its
    /// window instantly overdue and it retransmits its whole window every tick.
    var peerRTO: UInt32

    var command: MKCPCommand? { MKCPCommand(rawValue: rawCommand) }
    var byteSize: Int { 16 }

    init(conversation: UInt16, rawCommand: UInt8, option: MKCPSegmentOption = [],
         sendingNext: UInt32, receivingNext: UInt32, peerRTO: UInt32) {
        self.conversation = conversation
        self.rawCommand = rawCommand
        self.option = option
        self.sendingNext = sendingNext
        self.receivingNext = receivingNext
        self.peerRTO = peerRTO
    }

    init(conversation: UInt16, command: MKCPCommand, option: MKCPSegmentOption = [],
         sendingNext: UInt32, receivingNext: UInt32, peerRTO: UInt32) {
        self.init(conversation: conversation, rawCommand: command.rawValue, option: option,
                  sendingNext: sendingNext, receivingNext: receivingNext, peerRTO: peerRTO)
    }
}

enum MKCPSegment {
    case data(MKCPDataSegment)
    case ack(MKCPAckSegment)
    case command(MKCPCommandSegment)

    var conversation: UInt16 {
        switch self {
        case .data(let segment): return segment.conversation
        case .ack(let segment): return segment.conversation
        case .command(let segment): return segment.conversation
        }
    }

    var rawCommand: UInt8 {
        switch self {
        case .data: return MKCPCommand.data.rawValue
        case .ack: return MKCPCommand.ack.rawValue
        case .command(let segment): return segment.rawCommand
        }
    }

    var command: MKCPCommand? { MKCPCommand(rawValue: rawCommand) }

    var option: MKCPSegmentOption {
        switch self {
        case .data(let segment): return segment.option
        case .ack(let segment): return segment.option
        case .command(let segment): return segment.option
        }
    }

    var byteSize: Int {
        switch self {
        case .data(let segment): return segment.byteSize
        case .ack(let segment): return segment.byteSize
        case .command(let segment): return segment.byteSize
        }
    }
}

// MARK: - Segment encoding

private func bigEndian16(_ bytes: [UInt8], _ index: Int) -> UInt16 {
    UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
}

private func bigEndian32(_ bytes: [UInt8], _ index: Int) -> UInt32 {
    UInt32(bytes[index]) << 24 | UInt32(bytes[index + 1]) << 16
        | UInt32(bytes[index + 2]) << 8 | UInt32(bytes[index + 3])
}

private extension Array where Element == UInt8 {
    mutating func appendBigEndian(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    mutating func appendBigEndian(_ value: UInt32) {
        append(UInt8(truncatingIfNeeded: value >> 24))
        append(UInt8(truncatingIfNeeded: value >> 16))
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }
}

extension MKCPSegment {
    /// Appends the wire form. Every multi-byte field is big-endian, including
    /// `conv` — ikcp writes it little-endian, and a little-endian conv makes
    /// the server open a second session under the wrong number and answer into
    /// it, which reads as "connected, no traffic".
    func encode(into out: inout [UInt8]) throws {
        switch self {
        case .data(let segment):
            guard segment.payload.count <= Int(UInt16.max) else {
                throw NativeOutboundError.protocolError(
                    "mKCP 数据段载荷 \(segment.payload.count) 字节超出 16 位长度字段")
            }
            out.appendBigEndian(segment.conversation)
            out.append(MKCPCommand.data.rawValue)
            out.append(segment.option.rawValue)
            out.appendBigEndian(segment.timestamp)
            out.appendBigEndian(segment.number)
            out.appendBigEndian(segment.sendingNext)
            out.appendBigEndian(UInt16(segment.payload.count))
            out.append(contentsOf: segment.payload)
        case .ack(let segment):
            guard segment.numbers.count <= Int(UInt8.max) else {
                throw NativeOutboundError.protocolError(
                    "mKCP 确认段序号个数 \(segment.numbers.count) 超出单字节计数")
            }
            out.appendBigEndian(segment.conversation)
            out.append(MKCPCommand.ack.rawValue)
            out.append(segment.option.rawValue)
            out.appendBigEndian(segment.receivingWindow)
            out.appendBigEndian(segment.receivingNext)
            out.appendBigEndian(segment.timestamp)
            out.append(UInt8(segment.numbers.count))
            for number in segment.numbers { out.appendBigEndian(number) }
        case .command(let segment):
            // 0 and 1 belong to the ACK and data shapes. A 16-byte segment
            // carrying either is one byte short of the ACK minimum, so the peer
            // rejects it *and* everything chained behind it in the datagram.
            // Refuse to put one on the wire rather than let a caller build it.
            guard segment.rawCommand != MKCPCommand.ack.rawValue,
                  segment.rawCommand != MKCPCommand.data.rawValue else {
                throw NativeOutboundError.protocolError(
                    "mKCP 命令段不能使用命令字 \(segment.rawCommand)")
            }
            out.appendBigEndian(segment.conversation)
            out.append(segment.rawCommand)
            out.append(segment.option.rawValue)
            out.appendBigEndian(segment.sendingNext)
            out.appendBigEndian(segment.receivingNext)
            out.appendBigEndian(segment.peerRTO)
        }
    }

    func encoded() throws -> Data {
        var out: [UInt8] = []
        out.reserveCapacity(byteSize)
        try encode(into: &out)
        return Data(out)
    }

    /// Decodes one segment starting at `offset`, returning it with the offset
    /// just past it. `nil` means "stop here" — upstream returns a nil segment
    /// and the reader abandons the rest of the datagram, so a partial parse is
    /// not an error to report, it is a boundary.
    static func decode(_ bytes: [UInt8], at offset: Int) -> (segment: MKCPSegment, next: Int)? {
        guard bytes.count - offset >= 4 else { return nil }
        let conversation = bigEndian16(bytes, offset)
        let rawCommand = bytes[offset + 2]
        let option = MKCPSegmentOption(rawValue: bytes[offset + 3])
        var cursor = offset + 4
        let available = bytes.count - cursor

        switch rawCommand {
        case MKCPCommand.data.rawValue:
            // 15, not 14, although only 14 bytes of header are consumed. The
            // off-by-one is upstream's (segment.go:61) and it is observable: a
            // zero-length data segment at the end of a datagram is rejected,
            // and rejecting it takes the rest of the datagram with it. Relaxing
            // this to 14 would accept packets Xray refuses.
            guard available >= 15 else { return nil }
            let timestamp = bigEndian32(bytes, cursor); cursor += 4
            let number = bigEndian32(bytes, cursor); cursor += 4
            let sendingNext = bigEndian32(bytes, cursor); cursor += 4
            let length = Int(bigEndian16(bytes, cursor)); cursor += 2
            guard bytes.count - cursor >= length else { return nil }
            let payload = Data(bytes[cursor..<(cursor + length)])
            cursor += length
            return (.data(MKCPDataSegment(conversation: conversation, option: option,
                                          timestamp: timestamp, number: number,
                                          sendingNext: sendingNext, payload: payload)), cursor)
        case MKCPCommand.ack.rawValue:
            guard available >= 13 else { return nil }
            let receivingWindow = bigEndian32(bytes, cursor); cursor += 4
            let receivingNext = bigEndian32(bytes, cursor); cursor += 4
            let timestamp = bigEndian32(bytes, cursor); cursor += 4
            let count = Int(bytes[cursor]); cursor += 1
            guard bytes.count - cursor >= count * 4 else { return nil }
            var numbers: [UInt32] = []
            numbers.reserveCapacity(count)
            for _ in 0..<count {
                numbers.append(bigEndian32(bytes, cursor)); cursor += 4
            }
            return (.ack(MKCPAckSegment(conversation: conversation, option: option,
                                        receivingWindow: receivingWindow,
                                        receivingNext: receivingNext, timestamp: timestamp,
                                        numbers: numbers)), cursor)
        default:
            guard available >= 12 else { return nil }
            let sendingNext = bigEndian32(bytes, cursor); cursor += 4
            let receivingNext = bigEndian32(bytes, cursor); cursor += 4
            let peerRTO = bigEndian32(bytes, cursor); cursor += 4
            return (.command(MKCPCommandSegment(conversation: conversation, rawCommand: rawCommand,
                                                option: option, sendingNext: sendingNext,
                                                receivingNext: receivingNext,
                                                peerRTO: peerRTO)), cursor)
        }
    }

    /// Decodes the chain of segments in one datagram.
    ///
    /// Xray's writer emits exactly one segment per datagram, but its reader
    /// loops, and so must ours: a peer that batches is legal and would
    /// otherwise cost us every segment after the first.
    ///
    /// `conversation` reproduces `Connection.Input`: a segment for another
    /// conversation ends the loop rather than being skipped, so the remainder of
    /// the datagram is discarded with it.
    static func decodeAll(_ frame: Data, conversation: UInt16? = nil) -> [MKCPSegment] {
        let bytes = [UInt8](frame)
        var offset = 0
        var result: [MKCPSegment] = []
        while offset < bytes.count {
            guard let (segment, next) = decode(bytes, at: offset) else { break }
            if let conversation, segment.conversation != conversation { break }
            result.append(segment)
            offset = next
        }
        return result
    }
}

// MARK: - FNV-1a

/// FNV-1a, 32-bit. Go's `hash/fnv` emits the digest big-endian, and mKCP's
/// checksum field is that digest verbatim; writing it little-endian fails every
/// check with no diagnostic anywhere.
enum MKCPFNV1a {
    static let offsetBasis: UInt32 = 0x811C_9DC5
    static let prime: UInt32 = 0x0100_0193

    static func hash<S: Sequence>(_ bytes: S) -> UInt32 where S.Element == UInt8 {
        var hash = offsetBasis
        for byte in bytes {
            hash ^= UInt32(byte)
            hash = hash &* prime
        }
        return hash
    }
}

// MARK: - Datagram security

/// The outer envelope of every mKCP datagram.
///
/// There is no "plain mKCP" in any deployed version: with no `seed` configured
/// the 6-byte SimpleAuthenticator shell is still mandatory. Sending bare
/// segments makes the server drop every packet, and the client only notices
/// 30 seconds later when its own idle timer fires.
///
/// 未确认：which of the two shapes a given server speaks. Xray v26.1.31 moved
/// this layer out to `streamSettings.finalmask.udp`, where it applies only if
/// the operator lists `mkcp-legacy` — and the mask array is wrapped
/// innermost-first, so the auth layer has to sit at index 0 and the camouflage
/// header last, or the checksum ends up covering the header too. The bytes are
/// otherwise identical to the ones below. Nothing observable from the client
/// distinguishes the versions, so `.simpleAuthenticator` is the default here on
/// the grounds that it matches every build before that split; the reliable probe
/// is server-side (`transport/internet/kcp/crypt.go` exists ⇒ old shape).
enum MKCPPacketSecurity {
    /// FNV-1a checksum, length prefix and a forward XOR. No key, no nonce.
    case simpleAuthenticator
    /// AES-128-GCM, used only when a `seed` is configured.
    case aes128GCM(key: SymmetricKey)

    /// The key is the *first 16 bytes* of SHA-256(seed) — AES-128, not AES-256.
    /// Using all 32 bytes produces a valid AES-256 key that decrypts nothing.
    ///
    /// The seed is an independent `kcpSettings` string. It is not derived from
    /// the VMess id, and the VMess id never participates in mKCP keying — the
    /// two protocols share nothing but the connection.
    ///
    /// 未确认：which share-link field, if any, third-party clients map onto this
    /// seed. The two paths are mutually unintelligible, so a profile that omits
    /// the seed and a server that expects one fail exactly like a wrong address.
    static func aes128GCM(seed: String) -> MKCPPacketSecurity {
        let digest = Data(SHA256.hash(data: Data(seed.utf8)))
        return .aes128GCM(key: SymmetricKey(data: digest.prefix(16)))
    }

    var nonceSize: Int {
        switch self {
        case .simpleAuthenticator: return 0
        case .aes128GCM: return 12
        }
    }

    /// What upstream's `Overhead()` reports. For the AES-GCM path that is the
    /// tag only — the 12-byte nonce is prepended by the writer but never
    /// counted, so Xray's own datagrams overrun its configured MTU by 12 bytes.
    /// Reproduced rather than fixed: this number feeds the segment size, and a
    /// different one changes where we split application data.
    var overhead: Int {
        switch self {
        case .simpleAuthenticator: return 6
        case .aes128GCM: return 16
        }
    }

    /// `nonce` exists for the self-test; production always randomises.
    func seal(_ plain: Data, nonce: Data? = nil) throws -> Data {
        switch self {
        case .simpleAuthenticator:
            // Upstream writes `uint16(len(plain))` and lets Go truncate, which
            // ships a datagram whose length field disagrees with its body and
            // is dropped in silence. Refusing outright is the only difference
            // from upstream here, and it is the difference between a diagnosed
            // caller bug and an unexplained dead connection. A frame can reach
            // this size legitimately — one data segment may carry a 65535-byte
            // payload — so the check is not theoretical.
            guard plain.count <= Int(UInt16.max) else {
                throw NativeOutboundError.protocolError(
                    "mKCP 外层封装的明文 \(plain.count) 字节超出 16 位长度字段")
            }
            // Order is the whole trick. Lay out [4 bytes reserved][BE16
            // length][plaintext], hash bytes 4.. into the reserved prefix, and
            // only then run the XOR over the finished buffer. Hashing after the
            // XOR, or hashing from offset 0 or 6 instead of 4, all produce a
            // checksum the server can never reproduce.
            var out = [UInt8](repeating: 0, count: 4)
            out.appendBigEndian(UInt16(plain.count))
            out.append(contentsOf: plain)
            let checksum = MKCPFNV1a.hash(out[4...])
            out[0] = UInt8(truncatingIfNeeded: checksum >> 24)
            out[1] = UInt8(truncatingIfNeeded: checksum >> 16)
            out[2] = UInt8(truncatingIfNeeded: checksum >> 8)
            out[3] = UInt8(truncatingIfNeeded: checksum)
            // Upstream zero-pads to a multiple of 4 here, XORs, then truncates
            // back. Since the forward pass only ever reads x[i-4], padding
            // cannot influence any byte that survives the truncation, so it is
            // a no-op and is omitted. Keeping the padding *without* truncating
            // would add 1..3 bytes and fail the length check on the far side.
            for index in 4..<out.count { out[index] ^= out[index - 4] }
            return Data(out)
        case .aes128GCM(let key):
            let raw = nonce ?? Data((0..<12).map { _ in UInt8.random(in: 0...255) })
            guard let box = try? AES.GCM.Nonce(data: raw) else {
                throw NativeOutboundError.crypto("mKCP AES-GCM 的 nonce 必须是 12 字节")
            }
            guard let sealed = try? AES.GCM.seal(plain, using: key, nonce: box),
                  let combined = sealed.combined else {
                throw NativeOutboundError.crypto("mKCP AES-GCM 封装失败")
            }
            // `combined` is nonce ‖ ciphertext ‖ tag, which is exactly the
            // layout the reader expects. AAD is empty.
            return combined
        }
    }

    /// Structural minimum only. Upstream's reader additionally refuses a
    /// datagram that is *exactly* the envelope; that guard lives in
    /// `MKCPPacketCodec.openDatagram`, where its counterpart lives upstream.
    func open(_ datagram: Data) throws -> Data {
        guard datagram.count >= nonceSize + overhead else {
            throw NativeOutboundError.protocolError("mKCP 报文长度 \(datagram.count) 不足以承载外层封装")
        }
        switch self {
        case .simpleAuthenticator:
            var bytes = [UInt8](datagram)
            var index = bytes.count - 1
            while index >= 4 {
                bytes[index] ^= bytes[index - 4]
                index -= 1
            }
            let expected = bigEndian32(bytes, 0)
            guard MKCPFNV1a.hash(bytes[4...]) == expected else {
                throw NativeOutboundError.crypto("mKCP 报文校验和不匹配")
            }
            let declared = Int(bigEndian16(bytes, 4))
            guard bytes.count - 6 == declared else {
                throw NativeOutboundError.crypto("mKCP 报文长度字段 \(declared) 与实际 \(bytes.count - 6) 不符")
            }
            return Data(bytes[6...])
        case .aes128GCM(let key):
            guard let box = try? AES.GCM.SealedBox(combined: datagram),
                  let plain = try? AES.GCM.open(box, using: key) else {
                throw NativeOutboundError.crypto("mKCP AES-GCM 校验失败")
            }
            return plain
        }
    }
}

// MARK: - Header camouflage

/// The fake protocol header prepended to every datagram.
///
/// The receiver strips it by length and never inspects a byte of it, which
/// splits the failure modes cleanly: wrong *content* is harmless, wrong
/// *length* shifts the entire envelope and every packet is dropped in silence.
/// Content still matters for traffic analysis — the counters below advance per
/// packet in Xray, and a constant where Xray increments is a fingerprint.
struct MKCPHeaderCamouflage {
    enum Kind: Equatable {
        case none
        case srtp
        case utp
        case wechatVideo
        case dtls
        case wireguard
        /// The only variable-length header: 12 + encoded(domain + ".") + 4.
        /// Both ends must agree on the domain, because the receiver only skips
        /// `Size()` bytes — a different domain is a different length and every
        /// packet dies.
        case dns
    }

    static let defaultDNSDomain = "www.baidu.com"

    let kind: Kind
    private var dnsHeader: [UInt8]
    private var srtpNumber: UInt16
    private var utpConnectionID: UInt16
    private var wechatSN: UInt32
    private var dtlsEpoch: UInt16
    private var dtlsSequence: UInt32
    private var dtlsLength: UInt16
    /// Non-nil only in the self-test, where reproducible bytes are the point.
    private let fixedRandom: UInt16?

    /// `pinnedRandom` fixes every field Xray randomises, for the self-test only;
    /// production must leave it nil. It has nothing to do with the mKCP `seed`,
    /// which keys the AES-GCM envelope.
    ///
    /// Initial values follow v1.8.24. The finalmask rewrite zero-initialises all
    /// of them, so a capture from a current server shows a constant srtp magic
    /// of 0 and a dtls length starting at 0 — different bytes, identical lengths,
    /// and the receiver reads neither.
    init(kind: Kind, domain: String = MKCPHeaderCamouflage.defaultDNSDomain,
         pinnedRandom: UInt16? = nil) throws {
        let base = pinnedRandom ?? UInt16.random(in: 0...UInt16.max)
        self.kind = kind
        self.fixedRandom = pinnedRandom
        self.srtpNumber = base
        self.utpConnectionID = base
        self.wechatSN = UInt32(base)
        self.dtlsEpoch = base
        self.dtlsSequence = 0
        self.dtlsLength = 17
        self.dnsHeader = kind == .dns ? try MKCPHeaderCamouflage.dnsQuery(domain: domain) : []
    }

    var size: Int {
        switch kind {
        case .none: return 0
        case .srtp, .utp, .wireguard: return 4
        case .wechatVideo, .dtls: return 13
        case .dns: return dnsHeader.count
        }
    }

    /// Accepts both spellings of the WeChat header: the classic `kcpSettings`
    /// name is `wechat-video`, the finalmask replacement calls it `wechat`.
    static func kind(named raw: String) -> Kind? {
        switch raw.lowercased() {
        case "", "none": return Kind.none
        case "srtp": return .srtp
        case "utp": return .utp
        case "wechat-video", "wechat": return .wechatVideo
        case "dtls": return .dtls
        case "wireguard": return .wireguard
        case "dns": return .dns
        default: return nil
        }
    }

    /// Produces the next header. Stateful by design — srtp's counter, wechat's
    /// serial and dtls's sequence and length all advance per packet.
    mutating func next() -> [UInt8] {
        switch kind {
        case .none:
            // Zero bytes, confirmed: NoOpHeader.Size() is 0 and its Serialize
            // is empty, and an absent header config takes the same path. The
            // payload MTU below depends on this being exactly zero.
            return []
        case .srtp:
            srtpNumber &+= 1                     // incremented before the write
            var out: [UInt8] = []
            out.appendBigEndian(UInt16(0xB5E8))
            out.appendBigEndian(srtpNumber)
            return out
        case .utp:
            var out: [UInt8] = []
            out.appendBigEndian(utpConnectionID) // constant for the connection
            out.append(0x01)
            out.append(0x00)
            return out
        case .wechatVideo:
            wechatSN &+= 1
            var out: [UInt8] = [0xA1, 0x08]
            out.appendBigEndian(wechatSN)
            out.append(contentsOf: [0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30])
            return out
        case .dtls:
            var out: [UInt8] = [0x17, 0xFE, 0xFD]
            out.appendBigEndian(dtlsEpoch)
            out.append(contentsOf: [0x00, 0x00])
            out.appendBigEndian(dtlsSequence)
            dtlsSequence &+= 1                   // incremented after the write
            out.appendBigEndian(dtlsLength)
            dtlsLength &+= 17
            if dtlsLength > 100 { dtlsLength -= 50 }
            return out
        case .wireguard:
            return [0x04, 0x00, 0x00, 0x00]
        case .dns:
            var out = dnsHeader
            guard out.count >= 2 else { return out }
            // A fresh transaction id per packet, mirroring dns.go:23.
            let transaction = fixedRandom ?? UInt16.random(in: 0...UInt16.max)
            out[0] = UInt8(truncatingIfNeeded: transaction >> 8)
            out[1] = UInt8(truncatingIfNeeded: transaction)
            return out
        }
    }

    /// A standard-query DNS header plus one question for `domain`, type A,
    /// class IN.
    ///
    /// The name follows `packDomainName`, which upstream feeds `domain + "."`
    /// and which emits one length-prefixed label per dot — *including* empty
    /// ones. Dropping empty labels would be the natural thing to write and is
    /// wrong: `"www.baidu.com."` encodes to 16 bytes upstream and 15 without
    /// them, and since the receiver skips a fixed `Size()` without looking, a
    /// one-byte disagreement loses every packet in both directions with nothing
    /// logged anywhere. Only the trailing dot upstream appends is implicit, so
    /// the split runs over `domain` itself with empty subsequences kept.
    private static func dnsQuery(domain: String) throws -> [UInt8] {
        var name: [UInt8] = []
        for label in domain.split(separator: ".", omittingEmptySubsequences: false) {
            let bytes = Array(label.utf8)
            guard bytes.count < 64 else {
                throw NativeOutboundError.protocolError("mKCP dns 伪装域名的标签过长：\(label)")
            }
            name.append(UInt8(bytes.count))
            name.append(contentsOf: bytes)
        }
        name.append(0x00)
        // packDomainName packs into a fixed 256-byte scratch buffer and fails
        // past it; a longer domain is rejected by Xray at config time, so
        // accepting one here would only produce a header no server can match.
        guard name.count <= 0x100 else {
            throw NativeOutboundError.protocolError("mKCP dns 伪装域名过长：\(domain)")
        }

        var out: [UInt8] = []
        out.appendBigEndian(UInt16(0x0000))      // transaction id, replaced per packet
        out.appendBigEndian(UInt16(0x0100))      // standard query, recursion desired
        out.appendBigEndian(UInt16(0x0001))      // one question
        out.appendBigEndian(UInt16(0x0000))      // no answers
        out.appendBigEndian(UInt16(0x0000))      // no authority records
        out.appendBigEndian(UInt16(0x0000))      // no additional records
        out.append(contentsOf: name)
        out.appendBigEndian(UInt16(0x0001))      // type A
        out.appendBigEndian(UInt16(0x0001))      // class IN
        return out
    }
}

// MARK: - Datagram codec

/// Assembles and takes apart whole UDP datagrams:
/// `[camouflage header][security envelope[ one or more segments ]]`.
struct MKCPPacketCodec {
    var camouflage: MKCPHeaderCamouflage
    var security: MKCPPacketSecurity

    init(camouflage: MKCPHeaderCamouflage, security: MKCPPacketSecurity = .simpleAuthenticator) {
        self.camouflage = camouflage
        self.security = security
    }

    /// Xray's own accounting of what the writer adds, and the number that
    /// determines the segment size. It undercounts the AES-GCM nonce; see
    /// `MKCPPacketSecurity.overhead`.
    var writerOverhead: Int { camouflage.size + security.overhead }

    /// What a datagram actually costs on the wire.
    var datagramOverhead: Int { camouflage.size + security.nonceSize + security.overhead }

    /// Payload bytes one data segment may carry.
    ///
    /// Derivation for the node in hand (mtu 1350, header none, no seed):
    ///
    ///     writerOverhead = camouflage 0 + security 6           =    6
    ///     mss            = 1350 - 6 - 18                       = 1326
    ///     full datagram  = 6 + 18 + 1326                       = 1350  (== mtu)
    ///
    /// Xray's main branch dropped the `writerOverhead` term, making mss
    /// 1350 - 18 = 1332 and its datagrams 1356 bytes — six over the configured
    /// MTU. Neither side validates MTU, so the two interoperate; they just
    /// fragment at different sizes. The conservative figure is used here.
    func maximumPayload(mtu: Int = MKCPFraming.defaultMTU) -> Int {
        mtu - writerOverhead - MKCPDataSegment.overhead
    }

    mutating func encode(segment: MKCPSegment) throws -> Data {
        try encode(segments: [segment])
    }

    /// Batching several segments into one datagram is legal — Xray's reader
    /// loops — but its writer never does it, and a full batch overruns the MTU.
    /// Send one segment per datagram unless there is a reason not to.
    mutating func encode(segments: [MKCPSegment]) throws -> Data {
        // An empty batch would seal into a bare 6-byte envelope, which every
        // reader discards on its `len(b) <= overhead` guard — a packet sent
        // purely to be thrown away, and one that also burns a camouflage
        // counter and so desynchronises the sequence the peer never checks.
        guard !segments.isEmpty else {
            throw NativeOutboundError.protocolError("mKCP 报文中没有任何段")
        }
        var frame: [UInt8] = []
        for segment in segments { try segment.encode(into: &frame) }
        var out = Data(camouflage.next())
        out.append(try security.seal(Data(frame)))
        return out
    }

    /// Strips the camouflage header and the security envelope.
    ///
    /// Both guards are `>`, matching upstream: a datagram consisting of nothing
    /// but framing carries no segment and is dropped before the checksum is
    /// even computed.
    func openDatagram(_ datagram: Data) throws -> Data {
        guard datagram.count > camouflage.size else {
            throw NativeOutboundError.protocolError("mKCP 报文长度 \(datagram.count) 不足以剥离伪装头")
        }
        let body = datagram.dropFirst(camouflage.size)
        guard body.count > security.nonceSize + security.overhead else {
            throw NativeOutboundError.protocolError("mKCP 报文长度 \(datagram.count) 不足以承载外层封装")
        }
        return try security.open(body)
    }

    /// The full receive path. Errors here are for logging only — the peer gets
    /// no feedback either way, and the ARQ above simply waits for a
    /// retransmission.
    func decodeDatagram(_ datagram: Data, conversation: UInt16? = nil) throws -> [MKCPSegment] {
        let frame = try openDatagram(datagram)
        let segments = MKCPSegment.decodeAll(frame, conversation: conversation)
        guard !segments.isEmpty else {
            throw NativeOutboundError.protocolError("mKCP 报文中没有可解析的段")
        }
        return segments
    }
}

/// Framing-level constants. Timing, windows and congestion live with the ARQ.
enum MKCPFraming {
    static let defaultMTU = 1350
    /// The configuration parser's bounds, inclusive.
    static let mtuRange = 576...1460
    /// One UDP read upstream, and the point past which a datagram is truncated.
    static let maximumDatagram = 8192

    /// The conversation id is chosen unilaterally: there is no handshake, and
    /// the server keys its session on (source address, source port, conv). Xray
    /// seeds a process-wide counter randomly and increments it per dial; a fresh
    /// random value per dial is equivalent on the wire and does not leak how many
    /// connections this process has opened. It
    /// is 16 bits, unlike ikcp's 32.
    static func randomConversation() -> UInt16 { UInt16.random(in: 0...UInt16.max) }
}

// MARK: - Self-test

public enum MKCPSegmentSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "mKCP 分帧自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    private static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func hexBytes(_ hex: String) -> Data {
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
        try fnvKnownAnswers()
        try authenticatorKnownAnswers()
        try paddingIsANoOp()
        try segmentKnownAnswers()
        try camouflageKnownAnswers()
        try datagramKnownAnswers()
        try aesGCMKnownAnswers()
        try segmentRoundTrip()
        try chainedSegments()
        try rejectsMalformed()
        try payloadSizeDerivation()
    }

    /// FNV-1a's own published test vectors.
    ///
    /// The empty input must return the offset basis unchanged, which pins both
    /// constants at once, and the remaining three pin the multiply-after-xor
    /// order — FNV-1 (multiply first) gives different digests for all of them.
    private static func fnvKnownAnswers() throws {
        try expect(MKCPFNV1a.hash([UInt8]()) == 0x811C_9DC5, "FNV 空输入未返回 offset basis")
        try expect(MKCPFNV1a.hash(Array("a".utf8)) == 0xE40C_292C, "FNV(\"a\") 不匹配")
        try expect(MKCPFNV1a.hash(Array("foobar".utf8)) == 0xBF9C_F968, "FNV(\"foobar\") 不匹配")
        try expect(MKCPFNV1a.hash(Array("hello".utf8)) == 0x4F9F_2CAB, "FNV(\"hello\") 不匹配")
    }

    /// The SimpleAuthenticator envelope, pinned byte for byte.
    ///
    /// Nothing about this layer round-trips against a server: a wrong checksum,
    /// a wrong XOR direction or a wrong hash range all look identical from
    /// here — the packet just never arrives. Only fixed answers can catch them,
    /// and a round-trip test catches none of them, because both directions
    /// would be wrong in the same way.
    ///
    /// Each expectation below is `[BE32 fnv1a(rest)][BE16 len][plain]` with
    /// `x[i] ^= x[i-4]` applied from offset 4 on. Worked example for the empty
    /// payload: the hashed range is just `00 00`, giving
    /// fnv1a32 = ((0x811c9dc5 ^ 0) * p ^ 0) * p = 0x117697cd; the buffer is
    /// `11 76 97 cd 00 00`, and the XOR turns the two length bytes into
    /// `00^11 = 11`, `00^76 = 76`.
    private static func authenticatorKnownAnswers() throws {
        let vectors: [(String, String)] = [
            ("", "117697cd1176"),
            ("6162", "861590708617f112"),
            ("61626364656667", "d1972ba8d1904acab2f42facd5"),
            ("00000000", "64da689164de689164de"),
            ("000102030405060708090a0b0c0d0e0f",
             "32500fad32400fac30430ba9364403a03c4f0fad3240"),
        ]
        for (plainHex, expected) in vectors {
            let plain = hexBytes(plainHex)
            let sealed = try MKCPPacketSecurity.simpleAuthenticator.seal(plain)
            try expect(hexString(sealed) == expected,
                       "封装 \(plainHex) 得到 \(hexString(sealed))，应为 \(expected)")
            let opened = try MKCPPacketSecurity.simpleAuthenticator.open(hexBytes(expected))
            try expect(opened == plain, "解封 \(expected) 未还原原文")
        }

        // The checksum covers the length field as well as the payload — a hash
        // taken from offset 6 is the single most common way to get this wrong.
        // Two payloads of different length can therefore never share a prefix.
        let a = try MKCPPacketSecurity.simpleAuthenticator.seal(Data([0x00]))
        let b = try MKCPPacketSecurity.simpleAuthenticator.seal(Data([0x00, 0x00]))
        try expect(a.prefix(4) != b.prefix(4), "长度字段未参与校验和计算")
    }

    /// Upstream pads the buffer to a multiple of four before the XOR pass and
    /// truncates afterwards. Skipping that is only safe if it changes nothing,
    /// so prove it over every length that can be padded rather than assuming.
    private static func paddingIsANoOp() throws {
        for length in 0...40 {
            let plain = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) })
            let sealed = try MKCPPacketSecurity.simpleAuthenticator.seal(plain)
            try expect(sealed.count == length + 6, "长度 \(length) 的封装多出了填充字节")

            // Upstream's version, transcribed with the padding left in.
            var padded = [UInt8](repeating: 0, count: 4)
            padded.appendBigEndian(UInt16(length))
            padded.append(contentsOf: plain)
            let checksum = MKCPFNV1a.hash(padded[4...])
            padded[0] = UInt8(truncatingIfNeeded: checksum >> 24)
            padded[1] = UInt8(truncatingIfNeeded: checksum >> 16)
            padded[2] = UInt8(truncatingIfNeeded: checksum >> 8)
            padded[3] = UInt8(truncatingIfNeeded: checksum)
            let unpaddedCount = padded.count
            let extra = 4 - unpaddedCount % 4
            if extra != 4 { padded.append(contentsOf: [UInt8](repeating: 0, count: extra)) }
            for index in 4..<padded.count { padded[index] ^= padded[index - 4] }
            try expect(Data(padded.prefix(unpaddedCount)) == sealed,
                       "长度 \(length) 上省略补齐改变了结果，填充并非无操作")
        }
    }

    /// Segment layouts, pinned field by field.
    private static func segmentKnownAnswers() throws {
        // conv 1234 │ cmd 01 │ opt 00 │ ts 000003e8 = 1000 │ sn 00000000 │
        // una 00000000 │ len 0005 │ "hello" = 68656c6c6f. 18 + 5 = 23 bytes.
        let data = try MKCPSegment.data(MKCPDataSegment(conversation: 0x1234, timestamp: 1000,
                                                        number: 0, sendingNext: 0,
                                                        payload: Data("hello".utf8))).encoded()
        try expect(hexString(data) == "12340100000003e80000000000000000000568656c6c6f",
                   "数据段编码为 \(hexString(data))")

        // Every field distinct, so a swapped pair cannot pass: conv beef │
        // cmd 01 │ opt 01 (close) │ ts 01020304 │ sn 0a0b0c0d │ una 00ff00ff │
        // len 0002 │ dead. 18 + 2 = 20 bytes.
        let flagged = try MKCPSegment.data(MKCPDataSegment(
            conversation: 0xBEEF, option: .close, timestamp: 0x0102_0304, number: 0x0A0B_0C0D,
            sendingNext: 0x00FF_00FF, payload: Data([0xDE, 0xAD]))).encoded()
        try expect(hexString(flagged) == "beef0101010203040a0b0c0d00ff00ff0002dead",
                   "带 close 位的数据段编码为 \(hexString(flagged))")

        // conv 1234 │ cmd 00 │ opt 00 │ wnd 00000136 = 310 │ una 00000005 │
        // ts 000003e8 = 1000 │ count 03 │ 00000005 00000006 00000007.
        // 17 + 3*4 = 29 bytes.
        let ack = try MKCPSegment.ack(MKCPAckSegment(conversation: 0x1234, receivingWindow: 310,
                                                     receivingNext: 5, timestamp: 1000,
                                                     numbers: [5, 6, 7])).encoded()
        try expect(hexString(ack) == "123400000000013600000005000003e803000000050000000600000007",
                   "确认段编码为 \(hexString(ack))")

        // count is one byte at offset 16, so an empty ACK is exactly 17 bytes.
        // A two-byte count would make this 18 and shift every number by one.
        let emptyAck = try MKCPSegment.ack(MKCPAckSegment(
            conversation: 0x0001, receivingWindow: 32, receivingNext: 0, timestamp: 0,
            numbers: [])).encoded()
        try expect(hexString(emptyAck) == "0001000000000020000000000000000000",
                   "空确认段编码为 \(hexString(emptyAck))")

        // conv 1234 │ cmd 03 (ping) │ opt 00 │ una 00000000 │ next 00000000 │
        // rto 00000064 = 100. Fixed 16 bytes.
        let ping = try MKCPSegment.command(MKCPCommandSegment(
            conversation: 0x1234, command: .ping, sendingNext: 0, receivingNext: 0,
            peerRTO: 100)).encoded()
        try expect(hexString(ping) == "12340300000000000000000000000064",
                   "Ping 段编码为 \(hexString(ping))")

        // conv 1234 │ cmd 02 (terminate) │ opt 01 │ una 00000007 │
        // next 00000009 │ rto 000000fa = 250.
        let terminate = try MKCPSegment.command(MKCPCommandSegment(
            conversation: 0x1234, command: .terminate, option: .close, sendingNext: 7,
            receivingNext: 9, peerRTO: 250)).encoded()
        try expect(hexString(terminate) == "123402010000000700000009000000fa",
                   "终止段编码为 \(hexString(terminate))")
    }

    /// Complete datagrams, header plus envelope plus segments.
    private static func datagramKnownAnswers() throws {
        var codec = MKCPPacketCodec(camouflage: try MKCPHeaderCamouflage(kind: .none))
        let data = MKCPSegment.data(MKCPDataSegment(conversation: 0x1234, timestamp: 1000,
                                                    number: 0, sendingNext: 0,
                                                    payload: Data("hello".utf8)))

        // header none contributes nothing, so the datagram is the 23-byte frame
        // above wrapped in the 6-byte envelope. The first four bytes survive the
        // XOR untouched and are fnv1a32(0017 ‖ frame) = 0x359f0819; everything
        // from offset 4 on is then chained with x[i] ^= x[i-4].
        let datagram = try codec.encode(segment: data)
        try expect(datagram.count == 29, "报文长度 \(datagram.count)，应为 6 + 23")
        try expect(hexString(datagram)
                    == "359f081935881a2d34881a2d37601a2d37601a2d37601a285f05764430",
                   "完整报文为 \(hexString(datagram))")

        let frame = try data.encoded()
        try expect(MKCPFNV1a.hash([UInt8](hexBytes("0017") + frame)) == 0x359F_0819,
                   "报文校验和的覆盖范围不是长度字段加帧")

        let ack = MKCPSegment.ack(MKCPAckSegment(conversation: 0x1234, receivingWindow: 310,
                                                 receivingNext: 5, timestamp: 1000,
                                                 numbers: [5, 6, 7]))
        let ackDatagram = try codec.encode(segment: ack)
        try expect(hexString(ackDatagram)
                    == "1596b5b4158ba780158ba78014bda78014b8a7801750a4801750a1801750a7801750a0",
                   "确认段报文为 \(hexString(ackDatagram))")

        // Several segments in one datagram: legal to send, mandatory to parse.
        let ping = MKCPSegment.command(MKCPCommandSegment(conversation: 0x1234, command: .ping,
                                                          sendingNext: 0, receivingNext: 0,
                                                          peerRTO: 100))
        let batch = try codec.encode(segments: [data, ack, ping])
        try expect(batch.count == 6 + 23 + 29 + 16, "聚合报文长度 \(batch.count) 不等于三段之和加封装")
        try expect(hexString(batch).hasPrefix("61eaaf6d"), "聚合报文校验和为 \(hexString(batch.prefix(4)))")
        let parsed = try codec.decodeDatagram(batch, conversation: 0x1234)
        try expect(parsed.count == 3, "聚合报文只解析出 \(parsed.count) 个段")
        try expect(parsed[0].command == .data && parsed[1].command == .ack
                    && parsed[2].command == .ping, "聚合报文的段顺序被打乱")
    }

    /// Header lengths decide whether the peer can parse anything at all, and
    /// the contents decide whether the flow looks like Xray's.
    private static func camouflageKnownAnswers() throws {
        // The one that matters for the node in hand: none adds nothing. Any
        // other answer silently changes the payload MTU.
        var none = try MKCPHeaderCamouflage(kind: .none, pinnedRandom: 0x1234)
        try expect(none.size == 0 && none.next().isEmpty, "none 伪装头不应产生字节")

        var wireguard = try MKCPHeaderCamouflage(kind: .wireguard, pinnedRandom: 0x1234)
        try expect(hexString(Data(wireguard.next())) == "04000000", "wireguard 伪装头错误")

        // srtp increments before writing, so the first packet carries seed + 1.
        var srtp = try MKCPHeaderCamouflage(kind: .srtp, pinnedRandom: 0x0000)
        try expect(hexString(Data(srtp.next())) == "b5e80001", "srtp 首包应为魔数加序号 1")
        try expect(hexString(Data(srtp.next())) == "b5e80002", "srtp 序号未逐包递增")

        // utp holds its connection id constant for the whole connection.
        var utp = try MKCPHeaderCamouflage(kind: .utp, pinnedRandom: 0x1234)
        try expect(hexString(Data(utp.next())) == "12340100", "utp 伪装头错误")
        try expect(hexString(Data(utp.next())) == "12340100", "utp connectionID 不应递增")

        var wechat = try MKCPHeaderCamouflage(kind: .wechatVideo, pinnedRandom: 0x0000)
        try expect(wechat.size == 13, "wechat-video 伪装头应为 13 字节")
        try expect(hexString(Data(wechat.next())) == "a1080000000100101118302230",
                   "wechat-video 伪装头错误")

        // dtls: 17 fe fd │ epoch │ 00 00 │ sequence │ length. The sequence starts
        // at 0 and advances after each write; the length starts at 17, gains 17
        // per packet and loses 50 whenever it passes 100.
        var dtls = try MKCPHeaderCamouflage(kind: .dtls, pinnedRandom: 0x1234)
        try expect(dtls.size == 13, "dtls 伪装头应为 13 字节")
        try expect(hexString(Data(dtls.next())) == "17fefd12340000000000000011", "dtls 首包错误")
        try expect(hexString(Data(dtls.next())) == "17fefd12340000000000010022", "dtls 第二包错误")
        var lengths: [String] = []
        for _ in 0..<6 { lengths.append(hexString(Data(dtls.next().suffix(2)))) }
        try expect(lengths == ["0033", "0044", "0055", "0034", "0045", "0056"],
                   "dtls 长度字段的递增/回卷序列为 \(lengths)")

        // dns is the only variable-length header: 12 byte fixed part, the
        // encoded name, then type and class. www.baidu.com encodes as
        // 03 www 05 baidu 03 com 00 = 15 bytes, so 12 + 15 + 4 = 31.
        var dns = try MKCPHeaderCamouflage(kind: .dns, pinnedRandom: 0xABCD)
        try expect(dns.size == 31, "dns 伪装头长度为 \(dns.size)，应为 31")
        let query = hexString(Data(dns.next()))
        try expect(query == "abcd01000001000000000000"
                    + "0377777705626169647503636f6d00" + "00010001",
                   "dns 伪装头为 \(query)")

        // packDomainName counts a zero-length label for every consecutive dot,
        // and upstream hands it `domain + "."`. Transcribing that routine by
        // hand for these three gives names of 4, 2 and 6 bytes; a version that
        // skips empty labels gives 3, 1 and 5, and the peer then strips one
        // byte too few from every datagram forever.
        let awkward: [(String, Int, String)] = [
            ("a.", 20, "01610000"),
            ("", 18, "0000"),
            ("a..b", 22, "016100016200"),
        ]
        for (domain, size, name) in awkward {
            var header = try MKCPHeaderCamouflage(kind: .dns, domain: domain, pinnedRandom: 0)
            try expect(header.size == size,
                       "dns 域名 \"\(domain)\" 的伪装头长度为 \(header.size)，应为 \(size)")
            try expect(hexString(Data(header.next())) == "000001000001000000000000" + name + "00010001",
                       "dns 域名 \"\(domain)\" 的问题段编码错误")
        }

        var overlongLabel = false
        do { _ = try MKCPHeaderCamouflage(kind: .dns, domain: String(repeating: "a", count: 64)) }
        catch { overlongLabel = true }
        try expect(overlongLabel, "超过 63 字节的 dns 标签应被拒绝")

        var overlongName = false
        do {
            _ = try MKCPHeaderCamouflage(
                kind: .dns,
                domain: (0..<64).map { _ in "abcd" }.joined(separator: "."))
        } catch { overlongName = true }
        try expect(overlongName, "超过 256 字节的 dns 域名应被拒绝")

        try expect(MKCPHeaderCamouflage.kind(named: "") == MKCPHeaderCamouflage.Kind.none,
                   "空 header 字段应等同于 none")
        try expect(MKCPHeaderCamouflage.kind(named: "WeChat-Video") == .wechatVideo,
                   "wechat-video 名称解析失败")
        try expect(MKCPHeaderCamouflage.kind(named: "wechat") == .wechatVideo,
                   "新版 wechat 名称解析失败")
        try expect(MKCPHeaderCamouflage.kind(named: "quic") == nil, "未知伪装头应被拒绝")
    }

    /// The seed path: key derivation and envelope layout.
    private static func aesGCMKnownAnswers() throws {
        // Test case 2 of the GCM specification (McGrew & Viega): an all-zero
        // AES-128 key and an all-zero 96-bit nonce over an all-zero block give
        // ciphertext 0388dace60b6a392f328c2b971b2fe78 and tag
        // ab6e47d42cec13bdf53a67b21257bddf. Pinning it here fixes the wire
        // layout — nonce, then ciphertext, then tag, with no AAD.
        let zeroKey = MKCPPacketSecurity.aes128GCM(key: SymmetricKey(data: Data(repeating: 0, count: 16)))
        let sealed = try zeroKey.seal(Data(repeating: 0, count: 16),
                                      nonce: Data(repeating: 0, count: 12))
        try expect(hexString(sealed) == "000000000000000000000000"
                    + "0388dace60b6a392f328c2b971b2fe78"
                    + "ab6e47d42cec13bdf53a67b21257bddf",
                   "AES-128-GCM 报文布局为 \(hexString(sealed))")

        // The key is SHA-256(seed) truncated to 16 bytes. The full digest of
        // The inherited fixed digest below was generated for the literal
        // "lurge-mkcp-self-test". Keep cryptographic test-vector input stable
        // when rebranding so the check still detects real KDF regressions.
        // e8e4efb705ef2c1bb79d6bd397932a75badb876e9dd4566e696a3442c4da7ce8,
        // so AES-128 uses only its first half; taking all 32 bytes yields a
        // perfectly valid AES-256 key that decrypts nothing.
        let derived = MKCPPacketSecurity.aes128GCM(seed: "lurge-mkcp-self-test")
        guard case .aes128GCM(let key) = derived else {
            throw Failure(text: "seed 未派生出 AES-128-GCM")
        }
        try expect(key.bitCount == 128, "seed 派生出的密钥为 \(key.bitCount) 位，应为 128 位")
        let expectedKey = MKCPPacketSecurity.aes128GCM(
            key: SymmetricKey(data: hexBytes("e8e4efb705ef2c1bb79d6bd397932a75")))
        let probe = try derived.seal(Data("mkcp".utf8), nonce: Data(repeating: 7, count: 12))
        let mirror = try expectedKey.seal(Data("mkcp".utf8), nonce: Data(repeating: 7, count: 12))
        try expect(probe == mirror, "seed 派生的密钥不是 SHA256(seed) 的前 16 字节")

        // Overheads differ from the SimpleAuthenticator path, and Xray's own
        // accounting omits the nonce, so the two numbers disagree by 12.
        let codec = MKCPPacketCodec(camouflage: try MKCPHeaderCamouflage(kind: .none),
                                    security: derived)
        try expect(codec.writerOverhead == 16 && codec.datagramOverhead == 28,
                   "AES-GCM 的开销计算为 \(codec.writerOverhead)/\(codec.datagramOverhead)")
        try expect(codec.maximumPayload(mtu: 1350) == 1316,
                   "AES-GCM 下的分片长度为 \(codec.maximumPayload(mtu: 1350))")

        let round = try derived.open(try derived.seal(Data("payload".utf8)))
        try expect(round == Data("payload".utf8), "AES-GCM 往返失败")
    }

    private static func segmentRoundTrip() throws {
        var segments: [MKCPSegment] = []
        for index in 0..<32 {
            let conv = UInt16(0x4000 + index)
            // At least one payload byte: a zero-length data segment is not a
            // valid thing to emit, see `rejectsMalformed`.
            segments.append(.data(MKCPDataSegment(
                conversation: conv, option: MKCPSegmentOption(rawValue: UInt8(index % 2)),
                timestamp: UInt32(index) &* 977, number: UInt32(index),
                sendingNext: UInt32(index / 2),
                payload: Data((0...index).map { UInt8(truncatingIfNeeded: $0) }))))
            segments.append(.ack(MKCPAckSegment(
                conversation: conv, receivingWindow: UInt32(index) &+ 310,
                receivingNext: UInt32(index), timestamp: UInt32(index) &* 31,
                numbers: (0..<index).map { UInt32($0) })))
            segments.append(.command(MKCPCommandSegment(
                conversation: conv, rawCommand: UInt8(2 + index % 2),
                sendingNext: UInt32(index), receivingNext: UInt32(index) &* 3,
                peerRTO: 100)))
        }

        for segment in segments {
            let encoded = try segment.encoded()
            try expect(encoded.count == segment.byteSize,
                       "段长度自述 \(segment.byteSize) 与实际 \(encoded.count) 不符")
            let decoded = MKCPSegment.decodeAll(encoded)
            try expect(decoded.count == 1, "单段解析出 \(decoded.count) 个结果")
            try expect(try decoded[0].encoded() == encoded, "段往返后字节不一致")
        }

        // An unrecognised command must survive the round trip as itself: the
        // peer still reads its una, next and RTO fields.
        let unknown = MKCPSegment.command(MKCPCommandSegment(conversation: 9, rawCommand: 0x51,
                                                             sendingNext: 1, receivingNext: 2,
                                                             peerRTO: 3))
        let recovered = MKCPSegment.decodeAll(try unknown.encoded())
        try expect(recovered.count == 1 && recovered[0].rawCommand == 0x51 && recovered[0].command == nil,
                   "未知命令未按命令段原样保留")
    }

    private static func chainedSegments() throws {
        let data = MKCPSegment.data(MKCPDataSegment(conversation: 7, timestamp: 5, number: 1,
                                                    sendingNext: 0, payload: Data([0x01])))
        let ack = MKCPSegment.ack(MKCPAckSegment(conversation: 7, receivingWindow: 40,
                                                 receivingNext: 2, timestamp: 5, numbers: [1]))
        var frame = Data()
        frame.append(try data.encoded())
        frame.append(try ack.encoded())
        try expect(MKCPSegment.decodeAll(frame, conversation: 7).count == 2,
                   "同一报文内的两个段未全部解析")

        // A segment for another conversation ends the loop, and everything
        // after it is lost with it — the same as upstream's `break`.
        var mixed = Data()
        mixed.append(try data.encoded())
        mixed.append(try MKCPSegment.ack(MKCPAckSegment(conversation: 8, receivingWindow: 40,
                                                        receivingNext: 2, timestamp: 5,
                                                        numbers: [1])).encoded())
        mixed.append(try ack.encoded())
        let filtered = MKCPSegment.decodeAll(mixed, conversation: 7)
        try expect(filtered.count == 1, "conv 不匹配后应停止解析，实际得到 \(filtered.count) 个段")

        // Trailing garbage keeps whatever parsed cleanly before it.
        var trailing = Data()
        trailing.append(try data.encoded())
        trailing.append(Data([0x00, 0x07]))
        try expect(MKCPSegment.decodeAll(trailing, conversation: 7).count == 1,
                   "尾部残字节不应作废已解析的段")
    }

    private static func rejectsMalformed() throws {
        let codec = MKCPPacketCodec(camouflage: try MKCPHeaderCamouflage(kind: .none))

        // A data segment whose declared length runs past the buffer.
        let truncatedPayload = hexBytes("12340100000003e800000000000000000005616263")
        try expect(MKCPSegment.decodeAll(truncatedPayload).isEmpty, "载荷不足的数据段应被拒绝")

        // 4-byte prefix plus 14 bytes is one short of the 15 upstream demands,
        // so an empty data segment at the end of a datagram is invalid. Accepting
        // it would make us take packets Xray refuses.
        let emptyTail = hexBytes("123401000000000000000000000000000000")
        try expect(emptyTail.count == 18, "空数据段用例构造错误")
        try expect(MKCPSegment.decodeAll(emptyTail).isEmpty, "报尾的空数据段应被拒绝")

        // An ACK whose number list is shorter than its count claims.
        let shortAck = hexBytes("1234000000000136000000050000000003000000050000")
        try expect(MKCPSegment.decodeAll(shortAck).isEmpty, "序号列表不足的确认段应被拒绝")

        // A command segment one byte short of its fixed 16.
        try expect(MKCPSegment.decodeAll(hexBytes("123403000000000000000000000000")).isEmpty,
                   "长度不足的命令段应被拒绝")
        try expect(MKCPSegment.decodeAll(hexBytes("1234")).isEmpty, "不足 4 字节的公共头应被拒绝")

        // A datagram carrying only the envelope is dropped before any check,
        // matching the reader's `len(b) <= overhead` guard.
        for length in 0...6 {
            let short = Data(repeating: 0, count: length)
            var thrown = false
            do { _ = try codec.openDatagram(short) } catch { thrown = true }
            try expect(thrown, "长度 \(length) 的报文应被拒绝")
        }

        let good = try MKCPPacketSecurity.simpleAuthenticator.seal(Data("hello".utf8))

        // One flipped payload byte must fail the checksum.
        var corrupt = [UInt8](good)
        corrupt[corrupt.count - 1] ^= 0x01
        var checksumRejected = false
        do { _ = try MKCPPacketSecurity.simpleAuthenticator.open(Data(corrupt)) }
        catch { checksumRejected = true }
        try expect(checksumRejected, "载荷被篡改后应校验失败")

        // A flipped checksum byte must fail too — the prefix is not XORed, so
        // it is the one region an implementation might forget to check.
        var badChecksum = [UInt8](good)
        badChecksum[0] ^= 0xFF
        var prefixRejected = false
        do { _ = try MKCPPacketSecurity.simpleAuthenticator.open(Data(badChecksum)) }
        catch { prefixRejected = true }
        try expect(prefixRejected, "校验和被篡改后应校验失败")

        // A length field that disagrees with the datagram must be rejected even
        // when the checksum agrees with it, so build the mismatch before sealing.
        var forged = [UInt8](repeating: 0, count: 4)
        forged.append(contentsOf: [0x00, 0x63])              // claims 99 bytes
        forged.append(contentsOf: Array("hello".utf8))       // carries 5
        let forgedChecksum = MKCPFNV1a.hash(forged[4...])
        forged[0] = UInt8(truncatingIfNeeded: forgedChecksum >> 24)
        forged[1] = UInt8(truncatingIfNeeded: forgedChecksum >> 16)
        forged[2] = UInt8(truncatingIfNeeded: forgedChecksum >> 8)
        forged[3] = UInt8(truncatingIfNeeded: forgedChecksum)
        for index in 4..<forged.count { forged[index] ^= forged[index - 4] }
        var lengthRejected = false
        do { _ = try MKCPPacketSecurity.simpleAuthenticator.open(Data(forged)) }
        catch { lengthRejected = true }
        try expect(lengthRejected, "长度字段不符的报文应被拒绝")

        // The single most tempting way to get this layer wrong: hash the buffer
        // after the XOR pass instead of before it. Both ends would agree with
        // each other and neither would agree with Xray, so only a fixed answer
        // catches it — build such a datagram and confirm it is refused.
        var wrongOrder = [UInt8](repeating: 0, count: 4)
        wrongOrder.appendBigEndian(UInt16(5))
        wrongOrder.append(contentsOf: Array("hello".utf8))
        for index in 4..<wrongOrder.count { wrongOrder[index] ^= wrongOrder[index - 4] }
        let lateChecksum = MKCPFNV1a.hash(wrongOrder[4...])
        wrongOrder[0] = UInt8(truncatingIfNeeded: lateChecksum >> 24)
        wrongOrder[1] = UInt8(truncatingIfNeeded: lateChecksum >> 16)
        wrongOrder[2] = UInt8(truncatingIfNeeded: lateChecksum >> 8)
        wrongOrder[3] = UInt8(truncatingIfNeeded: lateChecksum)
        var orderRejected = false
        do { _ = try MKCPPacketSecurity.simpleAuthenticator.open(Data(wrongOrder)) }
        catch { orderRejected = true }
        try expect(orderRejected, "先异或后计算校验和的报文不应通过校验")

        // A camouflage header of the wrong length shifts the envelope and must
        // fail rather than decode into something plausible.
        var srtpCodec = MKCPPacketCodec(camouflage: try MKCPHeaderCamouflage(kind: .srtp, pinnedRandom: 1))
        let wrapped = try srtpCodec.encode(segment: .command(
            MKCPCommandSegment(conversation: 3, command: .ping, sendingNext: 0,
                               receivingNext: 0, peerRTO: 100)))
        try expect(try srtpCodec.decodeDatagram(wrapped, conversation: 3).count == 1,
                   "srtp 伪装下的报文应能解出一个段")
        var mismatchRejected = false
        do { _ = try codec.decodeDatagram(wrapped, conversation: 3) } catch { mismatchRejected = true }
        try expect(mismatchRejected, "伪装头长度不符的报文应被拒绝")

        // Field overflow: the wire has one byte for the ACK count and two for
        // the payload length.
        var tooManyNumbers = false
        do {
            _ = try MKCPSegment.ack(MKCPAckSegment(conversation: 1, receivingWindow: 1,
                                                   receivingNext: 1, timestamp: 1,
                                                   numbers: (0..<256).map { UInt32($0) })).encoded()
        } catch { tooManyNumbers = true }
        try expect(tooManyNumbers, "超过 255 个序号的确认段应被拒绝编码")

        var tooLongPayload = false
        do {
            _ = try MKCPSegment.data(MKCPDataSegment(conversation: 1, timestamp: 0, number: 0,
                                                     sendingNext: 0,
                                                     payload: Data(count: 0x1_0000))).encoded()
        } catch { tooLongPayload = true }
        try expect(tooLongPayload, "超过 65535 字节的数据段应被拒绝编码")

        // The envelope's length field is 16 bits too, and a frame can exceed it
        // while every segment in it is legal: 18 + 65535 = 65553. Upstream
        // truncates and ships a datagram the peer silently drops.
        var tooLongFrame = false
        do {
            _ = try MKCPPacketSecurity.simpleAuthenticator.seal(Data(count: 0x1_0000))
        } catch { tooLongFrame = true }
        try expect(tooLongFrame, "超过 65535 字节的外层明文应被拒绝封装")

        var emptyBatch = false
        var emptyCodec = MKCPPacketCodec(camouflage: try MKCPHeaderCamouflage(kind: .none))
        do { _ = try emptyCodec.encode(segments: []) } catch { emptyBatch = true }
        try expect(emptyBatch, "空段列表应被拒绝编码")

        // A command segment claiming cmd 0 or 1 serialises to 16 bytes, one
        // short of the ACK minimum, so the peer drops the datagram from that
        // point on.
        for raw in [MKCPCommand.ack.rawValue, MKCPCommand.data.rawValue] {
            var rejected = false
            do {
                _ = try MKCPSegment.command(MKCPCommandSegment(
                    conversation: 1, rawCommand: raw, sendingNext: 0, receivingNext: 0,
                    peerRTO: 100)).encoded()
            } catch { rejected = true }
            try expect(rejected, "命令段不应允许命令字 \(raw)")
        }
    }

    /// The split point for application data, and the datagram size it implies.
    private static func payloadSizeDerivation() throws {
        let codec = MKCPPacketCodec(camouflage: try MKCPHeaderCamouflage(kind: .none))
        try expect(codec.writerOverhead == 6, "none + SimpleAuthenticator 的开销应为 6")
        try expect(codec.maximumPayload(mtu: 1350) == 1326,
                   "mtu=1350 时的分片长度为 \(codec.maximumPayload(mtu: 1350))，应为 1326")
        try expect(6 + MKCPDataSegment.overhead + codec.maximumPayload(mtu: 1350) == 1350,
                   "满载报文长度不等于 mtu")

        // A full-size datagram must survive the round trip intact — the length
        // field is 16 bits, so nothing here can wrap.
        var full = MKCPPacketCodec(camouflage: try MKCPHeaderCamouflage(kind: .none))
        let payload = Data((0..<1326).map { UInt8(truncatingIfNeeded: $0) })
        let datagram = try full.encode(segment: .data(MKCPDataSegment(
            conversation: 0x2222, timestamp: 1, number: 0, sendingNext: 0, payload: payload)))
        try expect(datagram.count == 1350, "满载报文实际 \(datagram.count) 字节")
        let segments = try full.decodeDatagram(datagram, conversation: 0x2222)
        guard case .data(let recovered) = segments.first else {
            throw Failure(text: "满载报文未解析出数据段")
        }
        try expect(recovered.payload == payload, "满载报文的载荷在往返后不一致")

        // The camouflage header comes out of the same budget.
        let dtls = MKCPPacketCodec(camouflage: try MKCPHeaderCamouflage(kind: .dtls))
        try expect(dtls.maximumPayload(mtu: 1350) == 1313,
                   "dtls 伪装下的分片长度为 \(dtls.maximumPayload(mtu: 1350))，应为 1350-13-6-18")

        // (1350 - 17) / 4 = 333, above the flat cap, so the node in hand still
        // gets 128; a small MTU is what makes the clamp bite.
        try expect(MKCPAckSegment.numberLimit(forMTU: 1350) == 128,
                   "mtu=1350 时的单段确认上限为 \(MKCPAckSegment.numberLimit(forMTU: 1350))")
        try expect(MKCPAckSegment.numberLimit(forMTU: 217) == 50,
                   "mtu=217 时的单段确认上限为 \(MKCPAckSegment.numberLimit(forMTU: 217))")
        try expect(MKCPAckSegment.numberLimit(forMTU: 18) == 1, "确认上限的下界应为 1")
    }
}

import CryptoKit
import Foundation

/// Joins mKCP's framing layer to its transport.
///
/// The two are deliberately separate: the ARQ never needs to know whether a
/// datagram is wrapped in a checksum, an AEAD, or nothing at all, and the
/// framing layer never needs to know what a window is. This file is the only
/// place that has to agree with both.
enum MKCPOutbound {
    /// Wraps the camouflage header and the packet authenticator into the
    /// transport's datagram hook.
    ///
    /// The camouflage is stateful — srtp's counter, dtls's sequence and length,
    /// wechat's serial all advance per packet — so it lives in a locked box
    /// rather than being captured by value. Capturing a struct here would give
    /// every datagram the same header, which no receiver validates and which
    /// therefore fails only as a fingerprint, never as an error.
    final class DatagramMask {
        private let lock = NSLock()
        private var camouflage: MKCPHeaderCamouflage
        /// Absent means bare segments behind the camouflage. Current upstream
        /// moved the checksum-and-XOR wrapper out of the transport and into an
        /// opt-in mask, so a server that does not list one speaks segments
        /// directly — verified on the wire, where its replies are exactly the
        /// camouflage plus a 16-byte command segment with no six-byte envelope
        /// between them.
        private let security: MKCPPacketSecurity?

        init(camouflage: MKCPHeaderCamouflage, security: MKCPPacketSecurity?) {
            self.camouflage = camouflage
            self.security = security
        }

        /// Matches Xray's own accounting, which counts the AEAD tag but not the
        /// nonce. The number is wrong by 12 bytes on the AES path and its own
        /// datagrams overrun the configured MTU because of it — but it decides
        /// where application data is split, so a "corrected" value would simply
        /// fragment differently from the peer.
        var overhead: UInt32 {
            lock.lock(); defer { lock.unlock() }
            return UInt32(camouflage.size + (security?.overhead ?? 0))
        }

        func codec() -> MKCPDatagramCodec {
            MKCPDatagramCodec(
                overhead: overhead,
                seal: { [self] frame in
                    lock.lock()
                    let header = camouflage.next()
                    lock.unlock()
                    var out = Data(header)
                    guard let security else { out.append(frame); return out }
                    guard let sealed = try? security.seal(frame) else { return Data() }
                    out.append(sealed)
                    return out
                },
                open: { [self] datagram in
                    lock.lock()
                    let prefix = camouflage.size
                    lock.unlock()
                    // The receiver strips the camouflage by length alone and
                    // never inspects it, exactly as upstream does. A datagram
                    // shorter than the header is not ours; dropping it silently
                    // is the only defined behaviour at this layer.
                    guard datagram.count > prefix else { return nil }
                    let body = Data(datagram.dropFirst(prefix))
                    guard let security else { return body }
                    return try? security.open(body)
                })
        }
    }

    /// Builds the transport configuration from a node's parameters.
    ///
    /// Every field here is a number both ends have to agree on before a single
    /// byte can be parsed, and none of them is negotiated: a mismatch in the
    /// camouflage length or the seed makes every datagram fail its checksum and
    /// be dropped without a word, which is indistinguishable from an unreachable
    /// server.
    static func configuration(for policy: ProxyPolicy) throws -> (MKCPConfiguration, DatagramMask) {
        var config = MKCPConfiguration()
        if let mtu = unsigned(policy.parameters["kcp-mtu"] ?? policy.parameters["mtu"]) {
            config.mtu = mtu
        }
        if let tti = unsigned(policy.parameters["kcp-tti"] ?? policy.parameters["tti"]) {
            config.tti = tti
        }
        if let value = unsigned(policy.parameters["kcp-uplink-capacity"]) {
            config.uplinkCapacity = value
        }
        if let value = unsigned(policy.parameters["kcp-downlink-capacity"]) {
            config.downlinkCapacity = value
        }
        if let raw = policy.parameters["kcp-congestion"] {
            config.congestion = (raw as NSString).boolValue
        }

        let headerName = policy.parameters["kcp-header"]
            ?? policy.parameters["header-type"] ?? "none"
        guard let kind = MKCPHeaderCamouflage.kind(named: headerName) else {
            throw NativeOutboundError.unsupported("mKCP 伪装头类型无效：\(headerName)")
        }
        let camouflage = try MKCPHeaderCamouflage(
            kind: kind,
            domain: policy.parameters["kcp-header-domain"]
                ?? MKCPHeaderCamouflage.defaultDNSDomain)

        // Which wrapper sits between the camouflage and the segments is not
        // negotiated and cannot be probed: a mismatch makes every datagram fail
        // its checksum and vanish, which looks exactly like an unreachable
        // server. It therefore has to be stated.
        //
        // The default is none, matching current upstream, where the wrapper
        // became an opt-in mask rather than part of the transport. Servers from
        // before that split always apply the checksum-and-XOR envelope and need
        // `kcp-authenticator=simple`.
        let security: MKCPPacketSecurity?
        let seed = policy.parameters["kcp-seed"] ?? policy.parameters["seed"]
        switch (policy.parameters["kcp-authenticator"] ?? (seed?.isEmpty == false ? "seed" : "none"))
            .lowercased() {
        case "none", "": security = nil
        case "simple", "simple-authenticator": security = .simpleAuthenticator
        case "seed", "aes", "aes-128-gcm":
            guard let seed, !seed.isEmpty else {
                throw NativeOutboundError.unsupported("mKCP 选择了 seed 认证但未提供 kcp-seed")
            }
            security = try MKCPPacketSecurity.aes128GCM(seed: seed)
        case let other:
            throw NativeOutboundError.unsupported("mKCP 认证层类型无效：\(other)")
        }

        let mask = DatagramMask(camouflage: camouflage, security: security)
        config.datagram = mask.codec()
        return (config, mask)
    }

    private static func unsigned(_ raw: String?) -> UInt32? {
        guard let raw, let value = UInt32(raw.trimmingCharacters(in: .whitespaces)) else {
            return nil
        }
        return value
    }
}

// MARK: - Self-test

public enum MKCPOutboundSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "mKCP 出站自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    private static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func policy(_ parameters: [String: String]) -> ProxyPolicy {
        ProxyPolicy(name: "kcp", kind: .native, host: "example.org", port: 443,
                    adapterType: "vmess", parameters: parameters)
    }

    public static func run() throws {
        try maskProducesTheFramedDatagram()
        try camouflageAdvancesPerPacket()
        try segmentSizeMatchesUpstreamAccounting()
        try rejectsUnknownCamouflage()
    }

    /// The mask must produce exactly what the framing layer's own codec does.
    ///
    /// These are two independent paths to the same bytes — the transport goes
    /// through the datagram hook, the framing self-test goes through
    /// `MKCPPacketCodec` — and nothing else would notice them drifting apart.
    /// The expected value is the one independently recomputed from the wire
    /// spec, not one captured from this implementation.
    private static func maskProducesTheFramedDatagram() throws {
        let mask = MKCPOutbound.DatagramMask(
            camouflage: try MKCPHeaderCamouflage(kind: .none), security: .simpleAuthenticator)
        let codec = mask.codec()

        // conv 0x1234, cmd data, opt 0, ts 1000, sn 0, una 0, len 5, "hello"
        let frame = Data([0x12, 0x34, 0x01, 0x00,
                          0x00, 0x00, 0x03, 0xE8,
                          0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00,
                          0x00, 0x05] + Array("hello".utf8))
        let sealed = codec.seal(frame)
        try expect(hexString(sealed)
                    == "359f081935881a2d34881a2d37601a2d37601a2d37601a285f05764430",
                   "封装结果为 \(hexString(sealed))")
        try expect(codec.open(sealed) == frame, "解封未还原原帧")

        // A corrupted checksum must vanish rather than raise: this layer has no
        // feedback channel, and upstream drops it just as silently.
        var damaged = sealed
        damaged[damaged.startIndex] ^= 0x01
        try expect(codec.open(damaged) == nil, "校验和损坏的报文未被丢弃")
        try expect(codec.open(Data([0x01, 0x02])) == nil, "过短的报文未被丢弃")
    }

    /// dtls carries a sequence number and a length that both advance per packet.
    /// Capturing the camouflage by value would freeze them, which no receiver
    /// checks — it would fail only as a fingerprint, never as an error.
    private static func camouflageAdvancesPerPacket() throws {
        let mask = MKCPOutbound.DatagramMask(
            camouflage: try MKCPHeaderCamouflage(kind: .dtls), security: .simpleAuthenticator)
        let codec = mask.codec()
        let frame = Data(repeating: 0x41, count: 20)
        let first = codec.seal(frame)
        let second = codec.seal(frame)
        try expect(first.count == 13 + 6 + 20 && second.count == first.count,
                   "dtls 报文长度为 \(first.count)，应为 39")
        try expect(first.prefix(3) == Data([0x17, 0xFE, 0xFD]),
                   "dtls 头未以 17 fe fd 开头")
        try expect(first != second, "dtls 头未逐包推进")
        // The body is identical either way — only the header moved.
        try expect(first.dropFirst(13) == second.dropFirst(13), "推进的不应是载荷")
        try expect(codec.open(first) == frame && codec.open(second) == frame,
                   "dtls 报文解封失败")
    }

    /// The node in hand: mtu 1350, dtls camouflage, no seed.
    ///
    ///     mss = 1350 - (13 + 6) - 18 = 1313
    ///
    /// This number decides where application data is split. Both ends compute it
    /// independently and never exchange it, so a disagreement shows up as a
    /// connection that establishes and then stalls.
    private static func segmentSizeMatchesUpstreamAccounting() throws {
        let (config, _) = try MKCPOutbound.configuration(for: policy([
            "kcp-header": "dtls", "kcp-mtu": "1350", "kcp-tti": "20",
        ]))
        try expect(config.mtu == 1350 && config.tti == 20, "mtu/tti 未取自参数")
        // dtls only: the live server replies with camouflage plus a bare
        // segment and nothing in between, so nothing is added here either.
        try expect(config.datagram.overhead == 13,
                   "dtls 裸段的开销为 \(config.datagram.overhead)，应为 13")
        try expect(config.mss == 1319, "mss 为 \(config.mss)，应为 1319")

        let (legacy, _) = try MKCPOutbound.configuration(for: policy([
            "kcp-header": "dtls", "kcp-authenticator": "simple",
        ]))
        try expect(legacy.datagram.overhead == 19,
                   "dtls + SimpleAuthenticator 的开销为 \(legacy.datagram.overhead)，应为 19")
        try expect(legacy.mss == 1313, "经典口径的 mss 为 \(legacy.mss)，应为 1313")

        // With a seed the wrapper becomes AES-128-GCM, whose declared overhead
        // is the tag only — upstream omits the 12-byte nonce, and matching that
        // omission is what keeps both ends splitting at the same offset.
        let (sealedConfig, _) = try MKCPOutbound.configuration(for: policy([
            "kcp-header": "none", "kcp-seed": "example",
        ]))
        try expect(sealedConfig.datagram.overhead == 16,
                   "AES-GCM 的开销为 \(sealedConfig.datagram.overhead)，应为 16")
        try expect(sealedConfig.mss == 1350 - 16 - 18, "AES-GCM 下的 mss 错误")

        let (plain, _) = try MKCPOutbound.configuration(for: policy([:]))
        try expect(plain.datagram.overhead == 0, "缺省应为无伪装头、无认证层")

        do {
            _ = try MKCPOutbound.configuration(for: policy(["kcp-authenticator": "seed"]))
            throw Failure(text: "选择 seed 认证却未给 kcp-seed，未被拒绝")
        } catch is NativeOutboundError {}
    }

    /// A misspelled camouflage must fail at configuration time. Silently falling
    /// back to `none` would strip the wrong number of bytes off every datagram,
    /// and the only symptom is a server that never answers.
    private static func rejectsUnknownCamouflage() throws {
        do {
            _ = try MKCPOutbound.configuration(for: policy(["kcp-header": "srtp2"]))
            throw Failure(text: "未知伪装头类型未被拒绝")
        } catch is NativeOutboundError {}
    }
}

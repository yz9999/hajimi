import Foundation

// MARK: - Per-Protocol DNS & Encrypted DNS Rule Policy Engine

/// Normalized outbound protocol family across Hajimi's 14 supported protocol families.
public enum DNSOutboundProtocolFamily: String, CaseIterable, Equatable, Sendable {
    case direct = "direct"
    case reject = "reject"
    case mieru = "mieru"
    case sudoku = "sudoku"
    case vless = "vless"
    case vmess = "vmess"
    case trojan = "trojan"
    case shadowsocks = "ss"
    case shadowsocksR = "ssr"
    case anytls = "anytls"
    case snell = "snell"
    case trusttunnel = "trusttunnel"
    case hysteria = "hysteria"
    case hysteria2 = "hysteria2"
    case tuic = "tuic"
    case ssh = "ssh"
    case http = "http"
    case https = "https"
    case socks5 = "socks5"
    case socks5TLS = "socks5-tls"
    case wireguard = "wireguard"

    public static func classify(_ rawType: String?) -> DNSOutboundProtocolFamily {
        guard let normalized = rawType?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
              !normalized.isEmpty else {
            return .direct
        }
        switch normalized {
        case "direct": return .direct
        case "reject", " reject-drop": return .reject
        case "mieru": return .mieru
        case "sudoku": return .sudoku
        case "vless": return .vless
        case "vmess": return .vmess
        case "trojan": return .trojan
        case "ss", "shadowsocks": return .shadowsocks
        case "ssr", "shadowsocksr": return .shadowsocksR
        case "anytls": return .anytls
        case "snell": return .snell
        case "trusttunnel": return .trusttunnel
        case "hysteria": return .hysteria
        case "hysteria2", "hy2": return .hysteria2
        case "tuic": return .tuic
        case "ssh": return .ssh
        case "http": return .http
        case "https": return .https
        case "socks5", "socks": return .socks5
        case "socks5-tls": return .socks5TLS
        case "wireguard", "wg": return .wireguard
        default: return .direct
        }
    }
}

/// Physical and logical framing underlay used by the outbound protocol.
public enum DNSProtocolUnderlayKind: String, Equatable, Sendable {
    /// Direct socket on the local interface.
    case directSocket
    /// Policy reject.
    case rejected
    /// Reliable TCP/TLS stream only (e.g. HTTP CONNECT, HTTPS, SSH, or SIP022 with UDP disabled).
    case tcpStreamOnly
    /// Reliable stream carrying framed UDP packets (VMess/VLESS/Trojan/Snell/AnyTLS/Sudoku UoT/Mieru-TCP/Mux/XUDP).
    case reliableStreamFramedUDP
    /// Mieru UDP session underlay (`PacketUnderlay` with 24B nonce + 48B AEAD metadata + `1332B` max segment payload).
    case mieruUDPSession
    /// Native UDP datagram relay (Shadowsocks AEAD UDP, SOCKS5 UDP ASSOCIATE).
    case nativeUDPDatagram
    /// QUIC / HTTP/3 native datagram relay (Hysteria v1/v2, TUIC v5, TrustTunnel H3).
    case quicDatagram
}

/// Handling rule for RFC 9460 `SVCB` (`qtype=64`) and `HTTPS` (`qtype=65`) records.
public enum DNSHTTPSRecordPolicy: String, Equatable, Sendable {
    /// Preserve `SVCB`/`HTTPS` answers unchanged.
    case passthrough
    /// Prefer TCP fallback for QUIC (`UDP/443`) while allowing HTTPS record resolution.
    case preferTCPForQUIC
    /// Synthesize empty `NOERROR` (`NODATA`) for `HTTPS`/`SVCB` when explicit QUIC suppression is requested.
    case synthesizeNoData
}

/// Computed DNS and Encrypted DNS transport/rule requirements for a specific outbound protocol and node configuration.
public struct DNSProtocolRuleRequirements: Equatable, Sendable {
    public let family: DNSOutboundProtocolFamily
    public let underlay: DNSProtocolUnderlayKind
    /// Whether the outbound can carry raw UDP-53 datagrams or UDP ASSOCIATE frames.
    public let supportsUDP53Relay: Bool
    /// Whether proxy-routed DNS MUST use TCP framing (`ProxyTCPDNSResolver`) or Encrypted DNS (`DoH`/`DoT`) instead of UDP-53.
    public let requiresTCPOrEncryptedDNSOverProxy: Bool
    /// Whether pooled Encrypted DNS (`DoH`/`DoT`) or `ProxyTCPDNSResolver` is preferred over one-shot UDP-53.
    public let prefersStreamMultiplexedDNS: Bool
    /// Whether application `UDP/443` (QUIC / HTTP/3) should trigger immediate TCP fallback so browsers use HTTP/2 over TCP/TLS.
    public let prefersTCPFallbackForQUIC: Bool
    /// Policy for RFC 9460 `SVCB`/`HTTPS` (`qtype=64/65`) records.
    public let httpsRecordPolicy: DNSHTTPSRecordPolicy
    /// Whether `AAAA` (`qtype=28`) queries should be short-circuited with an empty `NOERROR` (`NODATA`) response.
    public let suppressesAAAARecords: Bool
    /// Recommended maximum EDNS(0) UDP payload size (`1232` for `mieru-udp` and `quicDatagram` to prevent 2-packet fragmentation).
    public let recommendedEDNSPayloadSize: UInt16
    /// Recommended `EncryptedDNSConnectionStore` idle retention timeout (in seconds).
    public let recommendedEncryptedDNSIdleTimeout: TimeInterval
    /// Recommended `EncryptedDNSConnectionStore` burst handoff grace window (in seconds).
    public let recommendedEncryptedDNSHandoffGrace: TimeInterval
    /// Whether a transient timeout/reset on a borrowed idle stream must immediately trigger `recoverIdle` without poisoning fallback barriers.
    public let permitsFastIdleRecovery: Bool

    public init(
        family: DNSOutboundProtocolFamily,
        underlay: DNSProtocolUnderlayKind,
        supportsUDP53Relay: Bool,
        requiresTCPOrEncryptedDNSOverProxy: Bool,
        prefersStreamMultiplexedDNS: Bool,
        prefersTCPFallbackForQUIC: Bool,
        httpsRecordPolicy: DNSHTTPSRecordPolicy,
        suppressesAAAARecords: Bool,
        recommendedEDNSPayloadSize: UInt16,
        recommendedEncryptedDNSIdleTimeout: TimeInterval,
        recommendedEncryptedDNSHandoffGrace: TimeInterval,
        permitsFastIdleRecovery: Bool
    ) {
        self.family = family
        self.underlay = underlay
        self.supportsUDP53Relay = supportsUDP53Relay
        self.requiresTCPOrEncryptedDNSOverProxy = requiresTCPOrEncryptedDNSOverProxy
        self.prefersStreamMultiplexedDNS = prefersStreamMultiplexedDNS
        self.prefersTCPFallbackForQUIC = prefersTCPFallbackForQUIC
        self.httpsRecordPolicy = httpsRecordPolicy
        self.suppressesAAAARecords = suppressesAAAARecords
        self.recommendedEDNSPayloadSize = recommendedEDNSPayloadSize
        self.recommendedEncryptedDNSIdleTimeout = recommendedEncryptedDNSIdleTimeout
        self.recommendedEncryptedDNSHandoffGrace = recommendedEncryptedDNSHandoffGrace
        self.permitsFastIdleRecovery = permitsFastIdleRecovery
    }
}

/// Action returned by `DNSProtocolRulePolicy.evaluateQuery` before upstream transmission.
public enum DNSProtocolQueryDecision: Equatable, Sendable {
    /// Proceed with upstream resolution using the protocol-adapted EDNS(0) payload cap.
    case forwardUpstream(ednsMaxPayload: UInt16, preferTCPOrEncrypted: Bool)
    /// Synthesize a Fake-IP (`198.18.0.0/15`) answer locally for an eligible proxied `A` query.
    case synthesizeFakeIP
    /// Synthesize an RFC 2308 empty `NOERROR` (`NODATA`) response locally (e.g., `AAAA` on IPv4-only node).
    case synthesizeNoData(reason: String)
    /// Reject the query with `REFUSED`.
    case refuse(reason: String)
}

/// Stateless rule engine that derives DNS / Encrypted DNS behavior for each protocol and node configuration.
public enum DNSProtocolRulePolicy {
    /// RFC 6891 / DNS Flag Day 2020 & Mieru-UDP safe payload ceiling (`1232B` fits inside Mieru's `1332B` segment limit with HTTP/TLS headers).
    public static let mieruUDPSafeEDNSPayloadSize: UInt16 = 1_232
    /// Default EDNS(0) payload ceiling for TCP/TLS streams.
    public static let defaultStreamEDNSPayloadSize: UInt16 = 4_096

    public static func requirements(
        protocolType: String?,
        transport: String? = nil,
        udpSupported: Bool = true,
        carriesUDPOverStream: Bool = false,
        muxEnabled: Bool = false,
        ipv6Disabled: Bool = false,
        suppressQUICHTTPSRecords: Bool = false
    ) -> DNSProtocolRuleRequirements {
        let family = DNSOutboundProtocolFamily.classify(protocolType)
        let normalizedTransport = transport?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() ?? ""

        switch family {
        case .direct:
            return DNSProtocolRuleRequirements(
                family: .direct,
                underlay: .directSocket,
                supportsUDP53Relay: true,
                requiresTCPOrEncryptedDNSOverProxy: false,
                prefersStreamMultiplexedDNS: false,
                prefersTCPFallbackForQUIC: false,
                httpsRecordPolicy: .passthrough,
                suppressesAAAARecords: ipv6Disabled,
                recommendedEDNSPayloadSize: defaultStreamEDNSPayloadSize,
                recommendedEncryptedDNSIdleTimeout: 15.0,
                recommendedEncryptedDNSHandoffGrace: 8.0,
                permitsFastIdleRecovery: true
            )

        case .reject:
            return DNSProtocolRuleRequirements(
                family: .reject,
                underlay: .rejected,
                supportsUDP53Relay: false,
                requiresTCPOrEncryptedDNSOverProxy: true,
                prefersStreamMultiplexedDNS: false,
                prefersTCPFallbackForQUIC: true,
                httpsRecordPolicy: .synthesizeNoData,
                suppressesAAAARecords: true,
                recommendedEDNSPayloadSize: mieruUDPSafeEDNSPayloadSize,
                recommendedEncryptedDNSIdleTimeout: 0,
                recommendedEncryptedDNSHandoffGrace: 0,
                permitsFastIdleRecovery: false
            )

        case .mieru:
            let isMieruUDP = normalizedTransport == "UDP"
            return DNSProtocolRuleRequirements(
                family: .mieru,
                underlay: isMieruUDP ? .mieruUDPSession : .reliableStreamFramedUDP,
                supportsUDP53Relay: udpSupported,
                requiresTCPOrEncryptedDNSOverProxy: !udpSupported,
                prefersStreamMultiplexedDNS: true,
                // Mieru carries UDP over its session protocol; QUIC (UDP/443) over Mieru-UDP
                // causes double congestion control and 1332B segment fragmentation.
                prefersTCPFallbackForQUIC: true,
                httpsRecordPolicy: suppressQUICHTTPSRecords ? .synthesizeNoData : .preferTCPForQUIC,
                suppressesAAAARecords: ipv6Disabled,
                recommendedEDNSPayloadSize: isMieruUDP ? mieruUDPSafeEDNSPayloadSize : defaultStreamEDNSPayloadSize,
                // Align pooled DoH/DoT idle retention on Mieru-UDP with Mieru's 10s keepalive
                // so CGNAT UDP mappings do not silently expire before pool checkout.
                recommendedEncryptedDNSIdleTimeout: isMieruUDP ? 10.0 : 15.0,
                recommendedEncryptedDNSHandoffGrace: isMieruUDP ? 5.0 : 8.0,
                permitsFastIdleRecovery: true
            )

        case .http, .https, .ssh:
            return DNSProtocolRuleRequirements(
                family: family,
                underlay: .tcpStreamOnly,
                supportsUDP53Relay: false,
                requiresTCPOrEncryptedDNSOverProxy: true,
                prefersStreamMultiplexedDNS: true,
                prefersTCPFallbackForQUIC: true,
                httpsRecordPolicy: suppressQUICHTTPSRecords ? .synthesizeNoData : .preferTCPForQUIC,
                suppressesAAAARecords: ipv6Disabled,
                recommendedEDNSPayloadSize: defaultStreamEDNSPayloadSize,
                recommendedEncryptedDNSIdleTimeout: 15.0,
                recommendedEncryptedDNSHandoffGrace: 8.0,
                permitsFastIdleRecovery: true
            )

        case .hysteria, .hysteria2, .tuic:
            let canUDP = udpSupported && !muxEnabled
            return DNSProtocolRuleRequirements(
                family: family,
                underlay: canUDP ? .quicDatagram : .reliableStreamFramedUDP,
                supportsUDP53Relay: udpSupported,
                requiresTCPOrEncryptedDNSOverProxy: !udpSupported,
                prefersStreamMultiplexedDNS: true,
                prefersTCPFallbackForQUIC: !canUDP || carriesUDPOverStream,
                httpsRecordPolicy: (!canUDP && suppressQUICHTTPSRecords) ? .synthesizeNoData : .passthrough,
                suppressesAAAARecords: ipv6Disabled,
                recommendedEDNSPayloadSize: mieruUDPSafeEDNSPayloadSize,
                recommendedEncryptedDNSIdleTimeout: 12.0,
                recommendedEncryptedDNSHandoffGrace: 6.0,
                permitsFastIdleRecovery: true
            )

        case .sudoku, .anytls, .vmess, .vless, .trojan, .snell, .trusttunnel:
            return DNSProtocolRuleRequirements(
                family: family,
                underlay: udpSupported ? .reliableStreamFramedUDP : .tcpStreamOnly,
                supportsUDP53Relay: udpSupported,
                requiresTCPOrEncryptedDNSOverProxy: !udpSupported,
                prefersStreamMultiplexedDNS: true,
                prefersTCPFallbackForQUIC: true,
                httpsRecordPolicy: suppressQUICHTTPSRecords ? .synthesizeNoData : .preferTCPForQUIC,
                suppressesAAAARecords: ipv6Disabled,
                recommendedEDNSPayloadSize: defaultStreamEDNSPayloadSize,
                recommendedEncryptedDNSIdleTimeout: 15.0,
                recommendedEncryptedDNSHandoffGrace: 8.0,
                permitsFastIdleRecovery: true
            )

        case .shadowsocks, .shadowsocksR, .socks5, .socks5TLS, .wireguard:
            let streamOnlyOrFramed = !udpSupported || carriesUDPOverStream || muxEnabled
            return DNSProtocolRuleRequirements(
                family: family,
                underlay: !udpSupported ? .tcpStreamOnly : (streamOnlyOrFramed ? .reliableStreamFramedUDP : .nativeUDPDatagram),
                supportsUDP53Relay: udpSupported,
                requiresTCPOrEncryptedDNSOverProxy: !udpSupported,
                prefersStreamMultiplexedDNS: streamOnlyOrFramed,
                prefersTCPFallbackForQUIC: streamOnlyOrFramed,
                httpsRecordPolicy: (streamOnlyOrFramed && suppressQUICHTTPSRecords) ? .synthesizeNoData : .passthrough,
                suppressesAAAARecords: ipv6Disabled,
                recommendedEDNSPayloadSize: streamOnlyOrFramed ? defaultStreamEDNSPayloadSize : mieruUDPSafeEDNSPayloadSize,
                recommendedEncryptedDNSIdleTimeout: 15.0,
                recommendedEncryptedDNSHandoffGrace: 8.0,
                permitsFastIdleRecovery: true
            )
        }
    }

    /// Evaluates how a DNS query should be handled given the selected outbound protocol's rule requirements.
    public static func evaluateQuery(
        question: DNSQueryQuestion,
        routedViaProxy: Bool,
        fakeIPEnabled: Bool,
        skipsFakeIP: Bool,
        requirements: DNSProtocolRuleRequirements
    ) -> DNSProtocolQueryDecision {
        if requirements.family == .reject {
            return .refuse(reason: "Outbound protocol policy is REJECT")
        }
        if routedViaProxy, question.`class` == 1 {
            if question.type == 28, requirements.suppressesAAAARecords {
                return .synthesizeNoData(reason: "Outbound node disables IPv6 (AAAA suppressed)")
            }
            if (question.type == 64 || question.type == 65),
               requirements.httpsRecordPolicy == .synthesizeNoData {
                return .synthesizeNoData(reason: "Outbound protocol suppresses SVCB/HTTPS QUIC hints")
            }
            if fakeIPEnabled, !skipsFakeIP, (question.type == 1 || question.type == 28) {
                if question.type == 1 {
                    return .synthesizeFakeIP
                } else {
                    return .synthesizeNoData(reason: "Fake-IP mode suppresses AAAA to bind IPv4 synthetic address")
                }
            }
        }
        return .forwardUpstream(
            ednsMaxPayload: requirements.recommendedEDNSPayloadSize,
            preferTCPOrEncrypted: requirements.requiresTCPOrEncryptedDNSOverProxy || requirements.prefersStreamMultiplexedDNS
        )
    }

    /// Clamps the advertised EDNS(0) OPT UDP payload size (RFC 6891) in a raw DNS query if it exceeds `maxPayloadSize`.
    /// Prevents oversized (>1232B) DNS responses from fragmenting across multiple Mieru-UDP segments.
    public static func clampEDNSPayloadSize(in query: Data, maxPayloadSize: UInt16) -> Data {
        let bytes = Array(query)
        guard bytes.count >= 12, maxPayloadSize >= 512 else { return query }
        let qdCount = (Int(bytes[4]) << 8) | Int(bytes[5])
        let anCount = (Int(bytes[6]) << 8) | Int(bytes[7])
        let nsCount = (Int(bytes[8]) << 8) | Int(bytes[9])
        let arCount = (Int(bytes[10]) << 8) | Int(bytes[11])
        guard arCount > 0 else { return query }

        var offset = 12
        for _ in 0..<qdCount {
            guard let next = skipDNSName(bytes, from: offset), next + 4 <= bytes.count else { return query }
            offset = next + 4
        }
        for _ in 0..<(anCount + nsCount) {
            guard let next = skipDNSName(bytes, from: offset), next + 10 <= bytes.count else { return query }
            let rdLen = (Int(bytes[next + 8]) << 8) | Int(bytes[next + 9])
            guard next + 10 + rdLen <= bytes.count else { return query }
            offset = next + 10 + rdLen
        }
        var modified = bytes
        var changed = false
        for _ in 0..<arCount {
            guard let nameEnd = skipDNSName(modified, from: offset), nameEnd + 10 <= modified.count else { return query }
            let rrType = (UInt16(modified[nameEnd]) << 8) | UInt16(modified[nameEnd + 1])
            let rdLen = (Int(modified[nameEnd + 8]) << 8) | Int(modified[nameEnd + 9])
            guard nameEnd + 10 + rdLen <= modified.count else { return query }
            if rrType == 41 { // EDNS(0) OPT record: CLASS field holds requestor's UDP payload size
                let advertised = (UInt16(modified[nameEnd + 2]) << 8) | UInt16(modified[nameEnd + 3])
                if advertised > maxPayloadSize {
                    modified[nameEnd + 2] = UInt8((maxPayloadSize >> 8) & 0xff)
                    modified[nameEnd + 3] = UInt8(maxPayloadSize & 0xff)
                    changed = true
                }
            }
            offset = nameEnd + 10 + rdLen
        }
        return changed ? Data(modified) : query
    }

    private static func skipDNSName(_ bytes: [UInt8], from start: Int) -> Int? {
        var idx = start
        var steps = 0
        while idx < bytes.count && steps < 128 {
            steps += 1
            let len = Int(bytes[idx])
            if len == 0 {
                return idx + 1
            }
            if (len & 0xC0) == 0xC0 {
                guard idx + 1 < bytes.count else { return nil }
                return idx + 2
            }
            if (len & 0xC0) != 0 || len > 63 || idx + 1 + len > bytes.count {
                return nil
            }
            idx += 1 + len
        }
        return nil
    }
}

// MARK: - Self-Test

public enum DNSProtocolRulePolicySelfTest {
    public struct Failure: LocalizedError {
        public let text: String
        public init(text: String) {
            self.text = text
        }
        public var errorDescription: String? { "DNS 协议规则策略自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        // 1. Mieru-UDP vs Mieru-TCP rule requirements
        let mieruUDP = DNSProtocolRulePolicy.requirements(
            protocolType: "mieru", transport: "UDP", udpSupported: true, carriesUDPOverStream: true)
        let mieruTCP = DNSProtocolRulePolicy.requirements(
            protocolType: "mieru", transport: "TCP", udpSupported: true, carriesUDPOverStream: true)
        try expect(mieruUDP.family == .mieru && mieruUDP.underlay == .mieruUDPSession,
                   "mieru-udp underlay 分类错误")
        try expect(mieruUDP.prefersTCPFallbackForQUIC && mieruUDP.recommendedEDNSPayloadSize == 1232
                   && mieruUDP.recommendedEncryptedDNSIdleTimeout == 10.0
                   && mieruUDP.recommendedEncryptedDNSHandoffGrace == 5.0
                   && mieruUDP.permitsFastIdleRecovery,
                   "mieru-udp 未启用 1232B EDNS0 上限、10s 加密连接池保活窗口或 QUIC TCP 回退")
        try expect(mieruTCP.underlay == .reliableStreamFramedUDP
                   && mieruTCP.recommendedEDNSPayloadSize == 4096
                   && mieruTCP.recommendedEncryptedDNSIdleTimeout == 15.0,
                   "mieru-tcp 默认参数错误")

        // 2. Stream-only protocols (HTTP/HTTPS/SSH) vs QUIC protocols (Hysteria2/TUIC)
        for proto in ["http", "https", "ssh"] {
            let req = DNSProtocolRulePolicy.requirements(
                protocolType: proto, udpSupported: false, carriesUDPOverStream: false)
            try expect(!req.supportsUDP53Relay && req.requiresTCPOrEncryptedDNSOverProxy
                       && req.prefersTCPFallbackForQUIC && req.underlay == .tcpStreamOnly,
                       "\(proto) 未强制要求代理 TCP/加密 DNS 或未禁用裸 UDP-53")
        }
        for proto in ["hysteria2", "tuic"] {
            let req = DNSProtocolRulePolicy.requirements(
                protocolType: proto, udpSupported: true, carriesUDPOverStream: false)
            try expect(req.supportsUDP53Relay && !req.prefersTCPFallbackForQUIC
                       && req.underlay == .quicDatagram && req.recommendedEDNSPayloadSize == 1232,
                       "\(proto) 原生 QUIC 数据报特征分类错误")
        }

        // 3. Query evaluation (Fake-IP, IPv4-only AAAA NODATA, HTTPS record suppression)
        guard let rawQA = DNSMessageInspection.query(for: "api.spotify.com", type: 1),
              let qA = DNSMessageInspection.singleQuestion(in: rawQA),
              let rawQAAAA = DNSMessageInspection.query(for: "api.spotify.com", type: 28),
              let qAAAA = DNSMessageInspection.singleQuestion(in: rawQAAAA),
              let rawQHTTPS = DNSMessageInspection.query(for: "video.googlevideo.com", type: 65),
              let qHTTPS = DNSMessageInspection.singleQuestion(in: rawQHTTPS) else {
            throw Failure(text: "无法构造协议规则测试问题")
        }
        let ipv4OnlyMieru = DNSProtocolRulePolicy.requirements(
            protocolType: "mieru", transport: "UDP", udpSupported: true,
            carriesUDPOverStream: true, ipv6Disabled: true, suppressQUICHTTPSRecords: true)
        try expect(DNSProtocolRulePolicy.evaluateQuery(
            question: qAAAA, routedViaProxy: true, fakeIPEnabled: false,
            skipsFakeIP: false, requirements: ipv4OnlyMieru) == .synthesizeNoData(reason: "Outbound node disables IPv6 (AAAA suppressed)"),
            "IPv4-only 节点未对 AAAA 合成 NODATA")
        try expect(DNSProtocolRulePolicy.evaluateQuery(
            question: qHTTPS, routedViaProxy: true, fakeIPEnabled: false,
            skipsFakeIP: false, requirements: ipv4OnlyMieru) == .synthesizeNoData(reason: "Outbound protocol suppresses SVCB/HTTPS QUIC hints"),
            "启用 QUIC 抑制时未对 HTTPS(65) 记录合成 NODATA")
        try expect(DNSProtocolRulePolicy.evaluateQuery(
            question: qA, routedViaProxy: true, fakeIPEnabled: true,
            skipsFakeIP: false, requirements: mieruUDP) == .synthesizeFakeIP,
            "代理 A 查询未命中 Fake-IP 合成")

        // 4. EDNS(0) UDP payload size clamping (4096 -> 1232 for mieru-udp)
        guard var rawQuery = DNSMessageInspection.query(for: "mieru-edns.example", type: 1, id: 0x3141) else {
            throw Failure(text: "无法构造 EDNS 测试查询")
        }
        rawQuery[11] = 1 // ARCOUNT = 1
        // Append OPT RR with UDP payload size = 4096 (0x1000)
        rawQuery.append(contentsOf: [0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let clamped = DNSProtocolRulePolicy.clampEDNSPayloadSize(
            in: rawQuery, maxPayloadSize: DNSProtocolRulePolicy.mieruUDPSafeEDNSPayloadSize)
        let optClassOffset = clamped.count - 8
        let clampedSize = (UInt16(clamped[optClassOffset]) << 8) | UInt16(clamped[optClassOffset + 1])
        try expect(clampedSize == 1232 && DNSMessageInspection.singleQuestion(in: clamped)?.name == "mieru-edns.example",
                   "Mieru-UDP EDNS0 负载上限未能从 4096 钳制到 1232")
    }
}

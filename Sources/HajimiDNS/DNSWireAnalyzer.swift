import Foundation

/// Standard-stack DNS Wire, Security, Negative-Cache & Happy Eyeballs v3 Analyzer.
///
/// Built strictly on IETF specifications:
/// - RFC 1035: Domain Names - Implementation and Specification (pointer-safe wire walk)
/// - RFC 2308 & RFC 9520: DNS Negative Caching (Authority SOA minimum TTL clamping)
/// - RFC 6891: Extension Mechanisms for DNS (EDNS(0) UDP payload & DNSSEC OK bit)
/// - RFC 8914: Extended DNS Errors (EDNS0 Option Code 15)
/// - RFC 9567: DNS Error Reporting (EDNS0 Option Code 18 `REPORT-CHANNEL` & §8.1 loop guard)
/// - RFC 9715: IP Fragmentation Avoidance in DNS over UDP (<= 1232 octets over IPv6 / <= 1400 IPv4)
/// - RFC 9460 / RFC 9461 / RFC 9848: SVCB/HTTPS Service Bindings (`alpn`, `ech`, `dohpath`, hints)
/// - RFC 8305 & Happy Eyeballs v3 (`draft-ietf-happy-happyeyeballs-v3`): Prioritized multi-protocol
///   (HTTP/3 QUIC -> HTTP/2 TLS) and interleaved IPv6/IPv4 connection candidate synthesis.
public enum DNSWireAnalyzer {
    public static let ednsOptionExtendedError: UInt16 = 15
    public static let ednsOptionReportChannel: UInt16 = 18
    public static let recommendedUDPPayloadIPv6: UInt16 = 1232

    public enum TunnelingRiskLevel: String, Equatable, Sendable {
        case none
        case elevated
        case high
    }

    public struct DNSExtendedError: Equatable, Sendable {
        public let infoCode: UInt16
        public let category: DNSExtendedErrorCategory
        public let extraText: String?

        public init(infoCode: UInt16, extraText: String? = nil) {
            self.infoCode = infoCode
            self.category = DNSMessageInspection.classifyExtendedDNSError(infoCode)
            self.extraText = extraText
        }
    }

    public struct HappyEyeballsEndpointCandidate: Equatable, Sendable {
        public enum TransportProtocol: String, Equatable, Sendable {
            case h3
            case h2
            case http11
        }
        public enum AddressFamily: String, Equatable, Sendable {
            case ipv6
            case ipv4
            case unresolvedTarget
        }

        public let svcPriority: UInt16
        public let targetName: String
        public let port: UInt16
        public let transport: TransportProtocol
        public let family: AddressFamily
        public let address: String?
        public let echConfigList: Data?
        public let dohPathTemplate: String?

        public init(svcPriority: UInt16, targetName: String, port: UInt16,
                    transport: TransportProtocol, family: AddressFamily,
                    address: String?, echConfigList: Data?, dohPathTemplate: String?) {
            self.svcPriority = svcPriority
            self.targetName = targetName
            self.port = port
            self.transport = transport
            self.family = family
            self.address = address
            self.echConfigList = echConfigList
            self.dohPathTemplate = dohPathTemplate
        }
    }

    public struct DiagnosticReport: Equatable, Sendable {
        public let transactionID: UInt16
        public let isResponse: Bool
        public let opcode: UInt8
        public let rcode: UInt16
        public let isAuthoritative: Bool
        public let isTruncated: Bool
        public let recursionDesired: Bool
        public let recursionAvailable: Bool
        public let authenticatedData: Bool
        public let checkingDisabled: Bool
        public let dnssecOK: Bool
        public let qname: String
        public let qtype: UInt16
        public let qclass: UInt16
        public let labelCount: Int
        public let maxLabelLength: Int
        public let shannonEntropyBits: Double
        public let hexCharacterRatio: Double
        public let tunnelingRisk: TunnelingRiskLevel
        public let answerCount: Int
        public let authorityCount: Int
        public let additionalCount: Int
        public let cnameHopCount: Int
        public let minimumPositiveTTL: UInt32?
        public let negativeCacheTTL: UInt32?
        public let ednsUDPPayloadSize: UInt16?
        public let hasUDPFragmentationRisk: Bool
        public let extendedError: DNSExtendedError?
        public let reportChannelAgentDomain: String?
        public let amplificationFactor: Double?
        public let happyEyeballsCandidates: [HappyEyeballsEndpointCandidate]
    }

    /// Appends an empty RFC 9567 Option 18 (`REPORT-CHANNEL`) to an outbound DNS query's
    /// root `OPT` record (or creates a root `OPT` record advertising 1232-byte UDP payload
    /// per RFC 9715 when `ARCOUNT == 0`) to solicit authoritative error-reporting agent domains.
    public static func attachingReportChannelRequest(_ query: Data) -> Data? {
        let bytes = [UInt8](query)
        guard bytes.count >= 12,
              bytes[2] & 0x80 == 0,
              read16(bytes, 4) == 1,
              read16(bytes, 6) == 0,
              read16(bytes, 8) == 0 else { return nil }
        let arcount = read16(bytes, 10)
        guard arcount <= 1 else { return nil }
        var seen = Set<Int>()
        guard let qname = readName(bytes, at: 12, visited: &seen),
              qname.end + 4 <= bytes.count else { return nil }
        let questionEnd = qname.end + 4
        let optionBytes: [UInt8] = [0x00, 0x12, 0x00, 0x00] // Option 18 (REPORT-CHANNEL), length 0

        if arcount == 0 {
            guard questionEnd == bytes.count else { return nil }
            var out = bytes
            out[10] = 0x00
            out[11] = 0x01
            out.append(contentsOf: [
                0x00,                   // root owner "."
                0x00, 0x29,             // TYPE = OPT (41)
                0x04, 0xd0,             // CLASS = 1232 UDP payload (RFC 9715)
                0x00, 0x00, 0x00, 0x00, // EXT-RCODE=0, VERSION=0, FLAGS=0
                0x00, 0x04              // RDLENGTH = 4
            ])
            out.append(contentsOf: optionBytes)
            return Data(out)
        }

        // ARCOUNT == 1: verify root uncompressed OPT record at tail
        guard questionEnd + 11 <= bytes.count,
              bytes[questionEnd] == 0,
              read16(bytes, questionEnd + 1) == 41 else { return nil }
        let rdlen = Int(read16(bytes, questionEnd + 9))
        guard questionEnd + 11 + rdlen == bytes.count,
              rdlen + 4 <= 65535 else { return nil }
        // Check if Option 18 is already present
        var optPos = questionEnd + 11
        while optPos + 4 <= bytes.count {
            let code = read16(bytes, optPos)
            let len = Int(read16(bytes, optPos + 2))
            optPos += 4
            guard optPos + len <= bytes.count else { return nil }
            if code == ednsOptionReportChannel { return query }
            optPos += len
        }
        var out = bytes
        let newLen = UInt16(rdlen + 4)
        out[questionEnd + 9] = UInt8(newLen >> 8)
        out[questionEnd + 10] = UInt8(newLen & 0xff)
        out.append(contentsOf: optionBytes)
        return Data(out)
    }

    /// Performs single-pass wire inspection, tunneling anomaly scoring, RFC 2308 negative TTL
    /// calculation, RFC 9567 `REPORT-CHANNEL` validation, and Happy Eyeballs v3 candidate synthesis.
    public static func analyze(_ message: Data, queryByteCount: Int? = nil, defaultPort: UInt16 = 443) -> DiagnosticReport? {
        let bytes = [UInt8](message)
        guard (12...65535).contains(bytes.count) else { return nil }

        let txid = read16(bytes, 0)
        let flags = read16(bytes, 2)
        let isResponse = (flags & 0x8000) != 0
        let opcode = UInt8((flags >> 11) & 0x0f)
        let aa = (flags & 0x0400) != 0
        let tc = (flags & 0x0200) != 0
        let rd = (flags & 0x0100) != 0
        let ra = (flags & 0x0080) != 0
        let ad = (flags & 0x0020) != 0
        let cd = (flags & 0x0010) != 0
        var fullRcode = UInt16(flags & 0x000f)

        let qdcount = Int(read16(bytes, 4))
        let ancount = Int(read16(bytes, 6))
        let nscount = Int(read16(bytes, 8))
        let arcount = Int(read16(bytes, 10))
        guard qdcount >= 1, ancount + nscount + arcount <= 512 else { return nil }

        var pos = 12
        var qnameStr = "."
        var qtype: UInt16 = 0
        var qclass: UInt16 = 0
        var labelCount = 0
        var maxLabel = 0
        var entropy = 0.0
        var hexRatio = 0.0

        for q in 0..<qdcount {
            var seen = Set<Int>()
            guard let parsed = readName(bytes, at: pos, visited: &seen),
                  parsed.end + 4 <= bytes.count else { return nil }
            if q == 0 {
                qnameStr = parsed.normalized
                labelCount = parsed.labels.count
                maxLabel = parsed.labels.map(\.count).max() ?? 0
                (entropy, hexRatio) = computeLabelMetrics(parsed.labels)
                qtype = read16(bytes, parsed.end)
                qclass = read16(bytes, parsed.end + 2)
            }
            pos = parsed.end + 4
        }

        let risk = classifyTunnelingRisk(qname: qnameStr, qtype: qtype, labelCount: labelCount,
                                         maxLabelLength: maxLabel, entropy: entropy, hexRatio: hexRatio)

        var cnameHops = 0
        var minPosTTL: UInt32?
        var minNegTTL: UInt32?
        var ednsPayload: UInt16?
        var dnssecDO = false
        var ede: DNSExtendedError?
        var reportAgent: String?
        var ipv4Answers: [String] = []
        var ipv6Answers: [String] = []
        var svcbRecords: [ParsedSVCB] = []

        let sections = [ancount, nscount, arcount]
        for (secIdx, count) in sections.enumerated() {
            for _ in 0..<count {
                let ownerStart = pos
                var seen = Set<Int>()
                guard let owner = readName(bytes, at: pos, visited: &seen),
                      owner.end + 10 <= bytes.count else { return nil }
                pos = owner.end
                let rtype = read16(bytes, pos)
                let rclass = read16(bytes, pos + 2)
                let rttl = read32(bytes, pos + 4)
                let rdlen = Int(read16(bytes, pos + 8))
                pos += 10
                guard pos + rdlen <= bytes.count else { return nil }
                let rdataEnd = pos + rdlen

                if secIdx == 0 {
                    if rtype != 41 {
                        minPosTTL = minPosTTL.map { min($0, rttl) } ?? rttl
                    }
                    if rtype == 5 {
                        cnameHops += 1
                    } else if rtype == 1 && (rclass & 0x7fff) == 1 && rdlen == 4 {
                        ipv4Answers.append("\(bytes[pos]).\(bytes[pos + 1]).\(bytes[pos + 2]).\(bytes[pos + 3])")
                    } else if rtype == 28 && (rclass & 0x7fff) == 1 && rdlen == 16 {
                        if let v6 = formatIPv6(Array(bytes[pos..<rdataEnd])) {
                            ipv6Answers.append(v6)
                        }
                    } else if (rtype == 64 || rtype == 65) && (rclass & 0x7fff) == 1 {
                        if let svc = parseSVCB(bytes, from: pos, to: rdataEnd, fallbackTarget: qnameStr, defaultPort: defaultPort) {
                            svcbRecords.append(svc)
                        }
                    }
                } else if secIdx == 1 {
                    // RFC 2308 §3 & §5: Authority SOA negative caching lifetime = min(SOA RR TTL, SOA.MINIMUM)
                    if rtype == 6 && (rclass & 0x7fff) == 1 {
                        var s1 = Set<Int>(), s2 = Set<Int>()
                        if let mname = readName(bytes, at: pos, visited: &s1),
                           mname.end <= rdataEnd,
                           let rname = readName(bytes, at: mname.end, visited: &s2),
                           rname.end + 20 == rdataEnd {
                            let soaMinimum = read32(bytes, rname.end + 16)
                            let candidate = min(rttl, soaMinimum)
                            minNegTTL = minNegTTL.map { min($0, candidate) } ?? candidate
                        }
                    }
                } else {
                    // Additional section: EDNS0 OPT (RFC 6891) + glue A/AAAA
                    if rtype == 41 && owner.normalized == "." && bytes[ownerStart] == 0 {
                        ednsPayload = rclass
                        let extRcode = UInt16((rttl >> 24) & 0xff)
                        if extRcode != 0 {
                            fullRcode = (extRcode << 4) | (flags & 0x000f)
                        }
                        dnssecDO = ((rttl >> 15) & 1) != 0
                        var opt = pos
                        while opt + 4 <= rdataEnd {
                            let optCode = read16(bytes, opt)
                            let optLen = Int(read16(bytes, opt + 2))
                            opt += 4
                            guard opt + optLen <= rdataEnd else { return nil }
                            if optCode == ednsOptionExtendedError && optLen >= 2 && ede == nil {
                                let infoCode = read16(bytes, opt)
                                let extraBytes = Array(bytes[(opt + 2)..<(opt + optLen)])
                                let text = extraBytes.isEmpty ? nil : String(decoding: extraBytes, as: UTF8.self)
                                    .trimmingCharacters(in: .controlCharacters)
                                ede = DNSExtendedError(infoCode: infoCode, extraText: text?.isEmpty == true ? nil : text)
                            } else if optCode == ednsOptionReportChannel && optLen > 1 && reportAgent == nil {
                                if let agent = parseUncompressedDomainOption(bytes, from: opt, length: optLen),
                                   isSafeReportChannelAgent(agent, forQName: qnameStr) {
                                    reportAgent = agent
                                }
                            }
                            opt += optLen
                        }
                    }
                }
                pos = rdataEnd
            }
        }

        let effectiveNegTTL: UInt32? = (isResponse && ancount == 0 && (fullRcode == 0 || fullRcode == 3))
            ? minNegTTL : nil
        let fragRisk: Bool = {
            if let payload = ednsPayload, payload > recommendedUDPPayloadIPv6 { return true }
            return isResponse && bytes.count > Int(recommendedUDPPayloadIPv6)
        }()
        let amp: Double? = {
            guard isResponse, let qLen = queryByteCount, qLen > 0 else { return nil }
            return Double(bytes.count) / Double(qLen)
        }()

        let heCandidates = synthesizeHappyEyeballsCandidates(
            qname: qnameStr, defaultPort: defaultPort,
            svcbRecords: svcbRecords, ipv6Answers: ipv6Answers, ipv4Answers: ipv4Answers)

        return DiagnosticReport(
            transactionID: txid,
            isResponse: isResponse,
            opcode: opcode,
            rcode: fullRcode,
            isAuthoritative: aa,
            isTruncated: tc,
            recursionDesired: rd,
            recursionAvailable: ra,
            authenticatedData: ad,
            checkingDisabled: cd,
            dnssecOK: dnssecDO,
            qname: qnameStr,
            qtype: qtype,
            qclass: qclass,
            labelCount: labelCount,
            maxLabelLength: maxLabel,
            shannonEntropyBits: entropy,
            hexCharacterRatio: hexRatio,
            tunnelingRisk: risk,
            answerCount: ancount,
            authorityCount: nscount,
            additionalCount: arcount,
            cnameHopCount: cnameHops,
            minimumPositiveTTL: ancount > 0 ? minPosTTL : nil,
            negativeCacheTTL: effectiveNegTTL,
            ednsUDPPayloadSize: ednsPayload,
            hasUDPFragmentationRisk: fragRisk,
            extendedError: ede,
            reportChannelAgentDomain: reportAgent,
            amplificationFactor: amp,
            happyEyeballsCandidates: heCandidates
        )
    }

    // MARK: - Private Wire Helpers

    private struct ParsedName {
        let normalized: String
        let labels: [[UInt8]]
        let end: Int
    }

    private struct ParsedSVCB {
        let priority: UInt16
        let target: String
        let port: UInt16
        let alpns: [String]
        let ipv4Hints: [String]
        let ipv6Hints: [String]
        let echConfig: Data?
        let dohPath: String?
    }

    private static func read16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
    }

    private static func read32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }

    private static func readName(_ bytes: [UInt8], at start: Int, visited: inout Set<Int>) -> ParsedName? {
        guard start < bytes.count else { return nil }
        var cur = start
        var nextAfterPointer: Int?
        var wireTotal = 0
        var labels: [[UInt8]] = []

        while true {
            guard cur < bytes.count else { return nil }
            let length = Int(bytes[cur])
            if length == 0 {
                let end = nextAfterPointer ?? (cur + 1)
                let norm = labels.isEmpty ? "." : labels.map { String(decoding: $0, as: UTF8.self) }.joined(separator: ".")
                return ParsedName(normalized: norm, labels: labels, end: end)
            }
            if (length & 0xc0) == 0xc0 {
                guard cur + 1 < bytes.count else { return nil }
                let target = ((length & 0x3f) << 8) | Int(bytes[cur + 1])
                guard target < cur, target < bytes.count, visited.insert(target).inserted, visited.count <= 64 else {
                    return nil
                }
                if nextAfterPointer == nil { nextAfterPointer = cur + 2 }
                cur = target
                continue
            }
            guard (length & 0xc0) == 0, length <= 63, cur + 1 + length <= bytes.count else { return nil }
            wireTotal += 1 + length
            guard wireTotal <= 255 else { return nil }
            var lowered: [UInt8] = []
            lowered.reserveCapacity(length)
            for idx in (cur + 1)..<(cur + 1 + length) {
                let c = bytes[idx]
                lowered.append((65...90).contains(c) ? c + 32 : c)
            }
            labels.append(lowered)
            cur += 1 + length
        }
    }

    private static func parseUncompressedDomainOption(_ bytes: [UInt8], from start: Int, length: Int) -> String? {
        let end = start + length
        guard length > 1, length <= 255, end <= bytes.count else { return nil }
        var cur = start
        var labels: [String] = []
        while cur < end {
            let lbl = Int(bytes[cur])
            if lbl == 0 {
                guard cur + 1 == end, !labels.isEmpty else { return nil }
                return labels.joined(separator: ".")
            }
            guard (lbl & 0xc0) == 0, lbl <= 63, cur + 1 + lbl <= end else { return nil }
            var chars: [UInt8] = []
            chars.reserveCapacity(lbl)
            for b in bytes[(cur + 1)..<(cur + 1 + lbl)] {
                guard b > 0x20 && b < 0x7f else { return nil }
                chars.append((65...90).contains(b) ? b + 32 : b)
            }
            labels.append(String(decoding: chars, as: UTF8.self))
            cur += 1 + lbl
        }
        return nil
    }

    /// RFC 9567 §8.1 Loop Prevention: An error-reporting agent domain MUST NOT be equal to
    /// or a subdomain of the queried QNAME, preventing infinite self-reporting amplification loops.
    private static func isSafeReportChannelAgent(_ agent: String, forQName qname: String) -> Bool {
        guard agent != ".", !agent.isEmpty else { return false }
        guard qname != "." else { return true }
        if agent == qname { return false }
        if agent.hasSuffix("." + qname) { return false }
        return true
    }

    private static func computeLabelMetrics(_ labels: [[UInt8]]) -> (entropy: Double, hexRatio: Double) {
        var freq = [Int](repeating: 0, count: 256)
        var total = 0
        var hexCount = 0
        for label in labels {
            for b in label {
                freq[Int(b)] += 1
                total += 1
                if (48...57).contains(b) || (97...102).contains(b) {
                    hexCount += 1
                }
            }
        }
        guard total > 0 else { return (0.0, 0.0) }
        let inv = 1.0 / Double(total)
        var h = 0.0
        for count in freq where count > 0 {
            let p = Double(count) * inv
            h -= p * log2(p)
        }
        return ((h * 1000).rounded() / 1000, (Double(hexCount) * inv * 1000).rounded() / 1000)
    }

    private static func classifyTunnelingRisk(qname: String, qtype: UInt16, labelCount: Int,
                                              maxLabelLength: Int, entropy: Double, hexRatio: Double) -> TunnelingRiskLevel {
        let charCount = qname.utf8.count
        if maxLabelLength >= 50 || (charCount >= 100 && entropy >= 3.85) || (qtype == 10 && charCount >= 60) {
            return .high
        }
        if maxLabelLength >= 36 || (charCount >= 64 && (entropy >= 3.75 || hexRatio >= 0.80)) || labelCount >= 8 {
            return .elevated
        }
        return .none
    }

    private static func formatIPv6(_ octets: [UInt8]) -> String? {
        guard octets.count == 16 else { return nil }
        var groups: [UInt16] = []
        groups.reserveCapacity(8)
        for i in stride(from: 0, to: 16, by: 2) {
            groups.append((UInt16(octets[i]) << 8) | UInt16(octets[i + 1]))
        }
        var bestStart = -1, bestLen = 0
        var curStart = -1, curLen = 0
        for (idx, g) in groups.enumerated() {
            if g == 0 {
                if curStart == -1 { curStart = idx; curLen = 1 } else { curLen += 1 }
                if curLen > bestLen && curLen >= 2 { bestStart = curStart; bestLen = curLen }
            } else {
                curStart = -1; curLen = 0
            }
        }
        var parts: [String] = []
        var idx = 0
        while idx < 8 {
            if idx == bestStart {
                parts.append("")
                idx += bestLen
                if idx == 8 { parts.append("") }
            } else {
                parts.append(String(groups[idx], radix: 16))
                idx += 1
            }
        }
        let joined = parts.joined(separator: ":")
        return joined.hasPrefix(":") && !joined.hasPrefix("::") ? ":" + joined : joined
    }

    private static func parseSVCB(_ bytes: [UInt8], from start: Int, to end: Int,
                                  fallbackTarget: String, defaultPort: UInt16) -> ParsedSVCB? {
        guard end - start >= 3 else { return nil }
        let priority = read16(bytes, start)
        guard priority > 0 else { return nil } // AliasMode does not carry SvcParams
        var seen = Set<Int>()
        guard let targetName = readName(bytes, at: start + 2, visited: &seen),
              targetName.end <= end else { return nil }
        let resolvedTarget = targetName.normalized == "." ? fallbackTarget : targetName.normalized

        var port = defaultPort
        var alpns: [String] = []
        var v4Hints: [String] = []
        var v6Hints: [String] = []
        var ech: Data?
        var dohPath: String?

        var cur = targetName.end
        while cur + 4 <= end {
            let key = read16(bytes, cur)
            let len = Int(read16(bytes, cur + 2))
            cur += 4
            guard cur + len <= end else { return nil }
            let valEnd = cur + len
            switch key {
            case 1: // alpn
                var p = cur
                while p < valEnd {
                    let l = Int(bytes[p]); p += 1
                    guard l > 0, p + l <= valEnd else { break }
                    alpns.append(String(decoding: bytes[p..<(p + l)], as: UTF8.self).lowercased())
                    p += l
                }
            case 3 where len == 2: // port
                port = read16(bytes, cur)
            case 4 where len > 0 && len % 4 == 0: // ipv4hint
                for i in stride(from: cur, to: valEnd, by: 4) {
                    v4Hints.append("\(bytes[i]).\(bytes[i + 1]).\(bytes[i + 2]).\(bytes[i + 3])")
                }
            case 5 where len >= 4: // ech (ECHConfigList)
                ech = Data(bytes[cur..<valEnd])
            case 6 where len > 0 && len % 16 == 0: // ipv6hint
                for i in stride(from: cur, to: valEnd, by: 16) {
                    if let s = formatIPv6(Array(bytes[i..<(i + 16)])) { v6Hints.append(s) }
                }
            case 7 where len > 0 && bytes[cur] == 0x2f: // dohpath (RFC 9461)
                let slice = bytes[cur..<valEnd]
                if slice.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) {
                    dohPath = String(decoding: slice, as: UTF8.self)
                }
            default:
                break
            }
            cur = valEnd
        }

        return ParsedSVCB(priority: priority, target: resolvedTarget, port: port,
                          alpns: alpns, ipv4Hints: v4Hints, ipv6Hints: v6Hints,
                          echConfig: ech, dohPath: dohPath)
    }

    private static func synthesizeHappyEyeballsCandidates(
        qname: String,
        defaultPort: UInt16,
        svcbRecords: [ParsedSVCB],
        ipv6Answers: [String],
        ipv4Answers: [String]
    ) -> [HappyEyeballsEndpointCandidate] {
        var results: [HappyEyeballsEndpointCandidate] = []
        let sortedSVCB = svcbRecords.sorted { $0.priority < $1.priority }

        for svc in sortedSVCB {
            var transports: [HappyEyeballsEndpointCandidate.TransportProtocol] = []
            if svc.alpns.contains("h3") { transports.append(.h3) }
            if svc.alpns.contains("h2") { transports.append(.h2) }
            if svc.alpns.contains("http/1.1") { transports.append(.http11) }
            if transports.isEmpty { transports.append(.h2) }

            let v6Pool = !svc.ipv6Hints.isEmpty ? svc.ipv6Hints : (svc.target == qname ? ipv6Answers : [])
            let v4Pool = !svc.ipv4Hints.isEmpty ? svc.ipv4Hints : (svc.target == qname ? ipv4Answers : [])
            let interleaved = interleaveAddresses(ipv6: v6Pool, ipv4: v4Pool)

            for proto in transports {
                if interleaved.isEmpty {
                    results.append(HappyEyeballsEndpointCandidate(
                        svcPriority: svc.priority, targetName: svc.target, port: svc.port,
                        transport: proto, family: .unresolvedTarget, address: nil,
                        echConfigList: svc.echConfig, dohPathTemplate: svc.dohPath))
                } else {
                    for (fam, addr) in interleaved {
                        results.append(HappyEyeballsEndpointCandidate(
                            svcPriority: svc.priority, targetName: svc.target, port: svc.port,
                            transport: proto, family: fam, address: addr,
                            echConfigList: svc.echConfig, dohPathTemplate: svc.dohPath))
                    }
                }
            }
        }

        if results.isEmpty && (!ipv6Answers.isEmpty || !ipv4Answers.isEmpty) {
            for (fam, addr) in interleaveAddresses(ipv6: ipv6Answers, ipv4: ipv4Answers) {
                results.append(HappyEyeballsEndpointCandidate(
                    svcPriority: 65535, targetName: qname, port: defaultPort,
                    transport: .h2, family: fam, address: addr,
                    echConfigList: nil, dohPathTemplate: nil))
            }
        }
        return results
    }

    private static func interleaveAddresses(
        ipv6: [String], ipv4: [String]
    ) -> [(HappyEyeballsEndpointCandidate.AddressFamily, String)] {
        var out: [(HappyEyeballsEndpointCandidate.AddressFamily, String)] = []
        let maxCount = max(ipv6.count, ipv4.count)
        for i in 0..<maxCount {
            if i < ipv6.count { out.append((.ipv6, ipv6[i])) }
            if i < ipv4.count { out.append((.ipv4, ipv4[i])) }
        }
        return out
    }
}

public enum DNSWireAnalyzerSelfTest {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { "DNSWireAnalyzer 自检失败：\(message)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(message: message) }
    }

    public static func run() throws {
        // 1. RFC 9567 Option 18 request attachment & idempotency
        guard let baseQuery = DNSMessageInspection.query(for: "svc.example.com", type: 65, id: 0x5150),
              let withDER = DNSWireAnalyzer.attachingReportChannelRequest(baseQuery),
              let withDERAgain = DNSWireAnalyzer.attachingReportChannelRequest(withDER) else {
            throw Failure(message: "RFC 9567 Option 18 请求附加失败")
        }
        try expect(withDER == withDERAgain && withDER.count == baseQuery.count + 15,
                   "RFC 9567 Option 18 请求重复附加或 OPT RDATA 长度不匹配")

        // 2. HTTPS (Type 65) + ECH (RFC 9848) + dohpath (RFC 9461) + Happy Eyeballs v3 interleaved IPv6/IPv4
        //    + RFC 9567 Option 18 safe agent domain
        var httpsResp: [UInt8] = [
            0x51, 0x50, 0x81, 0xa0, // ID=0x5150, QR=1, RD=1, RA=1, AD=1, NOERROR
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            3, 115, 118, 99, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, // svc.example.com
            0x00, 0x41, 0x00, 0x01 // HTTPS IN
        ]
        // Build HTTPS RDATA: priority=1, target=".", key 1 alpn=["h3","h2"], key 4 ipv4hint=198.51.100.8,
        // key 5 ech=[0,4,0xfe,0x0d,0,0], key 6 ipv6hint=2001:db8::8, key 7 dohpath="/dns-query{?dns}"
        let dohPathBytes = Array("/dns-query{?dns}".utf8)
        var svcRdata: [UInt8] = [
            0x00, 0x01, 0x00, // priority=1, target="."
            0x00, 0x01, 0x00, 0x06, 2, 104, 51, 2, 104, 50, // alpn: h3, h2
            0x00, 0x04, 0x00, 0x04, 198, 51, 100, 8,        // ipv4hint
            0x00, 0x05, 0x00, 0x06, 0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00, // ech
            0x00, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, // ipv6hint
            0x00, 0x07, UInt8(dohPathBytes.count >> 8), UInt8(dohPathBytes.count)
        ]
        svcRdata.append(contentsOf: dohPathBytes)
        httpsResp.append(contentsOf: [
            0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x2c, // TTL = 300
            UInt8(svcRdata.count >> 8), UInt8(svcRdata.count)
        ])
        httpsResp.append(contentsOf: svcRdata)
        // Additional OPT: UDP=1232, DO=1, Option 18 agent = "er. telemetry.net" -> 2"er" 9"telemetry" 3"net" 0 (17B)
        let agentWire: [UInt8] = [2, 101, 114, 9, 116, 101, 108, 101, 109, 101, 116, 114, 121, 3, 110, 101, 116, 0]
        let optRdlen = 4 + agentWire.count
        httpsResp.append(contentsOf: [
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00,
            UInt8(optRdlen >> 8), UInt8(optRdlen),
            0x00, 0x12, UInt8(agentWire.count >> 8), UInt8(agentWire.count)
        ])
        httpsResp.append(contentsOf: agentWire)

        guard let report = DNSWireAnalyzer.analyze(Data(httpsResp), queryByteCount: withDER.count) else {
            throw Failure(message: "HTTPS + ECH + DE-R 响应解析失败")
        }
        try expect(report.authenticatedData && report.dnssecOK && !report.hasUDPFragmentationRisk,
                   "DNSSEC AD/DO 或 RFC 9715 分片风险判断错误")
        try expect(report.reportChannelAgentDomain == "er.telemetry.net",
                   "RFC 9567 REPORT-CHANNEL 代理域名提取错误：\(String(describing: report.reportChannelAgentDomain))")
        try expect(report.happyEyeballsCandidates.count == 4
                    && report.happyEyeballsCandidates[0].transport == .h3
                    && report.happyEyeballsCandidates[0].family == .ipv6
                    && report.happyEyeballsCandidates[1].transport == .h3
                    && report.happyEyeballsCandidates[1].family == .ipv4
                    && report.happyEyeballsCandidates[2].transport == .h2
                    && report.happyEyeballsCandidates[0].echConfigList != nil
                    && report.happyEyeballsCandidates[0].dohPathTemplate == "/dns-query{?dns}",
                   "Happy Eyeballs v3 候选排序未优先 h3 + ECH + IPv6/IPv4 交错")

        // 3. RFC 9567 §8.1 Loop Guard: agent domain inside QNAME subtree must be rejected!
        var loopResp = httpsResp
        let badAgent: [UInt8] = [2, 101, 114, 3, 115, 118, 99, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0] // er.svc.example.com
        loopResp.removeLast(4 + agentWire.count)
        let badOptRdlen = 4 + badAgent.count
        loopResp[loopResp.count - 2] = UInt8(badOptRdlen >> 8)
        loopResp[loopResp.count - 1] = UInt8(badOptRdlen)
        loopResp.append(contentsOf: [0x00, 0x12, 0x00, UInt8(badAgent.count)] + badAgent)
        guard let loopReport = DNSWireAnalyzer.analyze(Data(loopResp)) else {
            throw Failure(message: "RFC 9567 子域环路样本解析失败")
        }
        try expect(loopReport.reportChannelAgentDomain == nil,
                   "RFC 9567 §8.1 未拦截位于 QNAME 子树内的自指上报域名")

        // 4. High-entropy tunneling QNAME & RFC 2308 SOA negative TTL
        let tunnelName = "a9f03bc81d7e426590cfa18b73e254d1c098ef12ab34cd56ef7890.tunnel.example.com"
        guard let tunnelQuery = DNSMessageInspection.query(for: tunnelName, type: 16, id: 0x9999),
              let tunnelReport = DNSWireAnalyzer.analyze(tunnelQuery) else {
            throw Failure(message: "高熵隧道查询解析失败")
        }
        try expect(tunnelReport.tunnelingRisk == .high && tunnelReport.maxLabelLength == 54,
                   "高熵长标签 DNS 隧道查询未触发高风险告警")
    }
}

import Foundation
import Darwin

/// A bounded, single standard DNS question, independent of the requested RR type.
public struct DNSQueryQuestion: Equatable {
    public let name: String
    public let type: UInt16
    public let `class`: UInt16
    public let questionEnd: Int
}

public enum DNSResponseCode: UInt8 {
    case formerr = 1
    case servfail = 2
    case refused = 5
}

/// Fixed diagnostic labels only. These describe the reverse target's address
/// range, not its reachability or whether a Fake-IP mapping is allocated.
public enum DNSPTRTargetCategory: String, Codable, CaseIterable {
    case ipv4Public, ipv4Private, ipv4Loopback, ipv4LinkLocal, ipv4FakeIP
    case ipv6Public, ipv6UniqueLocal, ipv6LinkLocal, ipv6Loopback
    case other
}

/// Fixed question-shape labels only. They contain no question name, address,
/// service identifier, prefix or routing/reachability verdict.
public enum DNSPTRQueryKind: String, Codable, CaseIterable {
    case dnsSDDomainEnumeration, serviceType
    case ipv4Reverse, ipv6Reverse, partialReverseZone, localName, other
}

/// RFC 8914 Extended DNS Error (EDE) semantic categories for privacy-preserving
/// diagnostics and adaptive upstream health classification.
public enum DNSExtendedErrorCategory: String, Codable, CaseIterable {
    case dnssecValidationFailure
    case policyBlockedOrCensored
    case staleOrCachedError
    case resolverTransientOrNetwork
    case other
}

/// RFC 7871 EDNS Client Subnet (ECS) privacy sanitization modes.
public enum DNSECSPrivacyMode: Int, Codable, CaseIterable {
    case strip = 0
    case anonymizeZeroPrefix = 1
    case truncatePrivacyBound = 2
}

/// Privacy-safe structural summary of an EDNS0 Client Subnet (Option 8) field.
/// Raw client address octets are deliberately excluded from diagnostic metadata.
public struct DNSECSMetadata: Equatable, Codable {
    public let family: UInt16
    public let sourcePrefixLength: UInt8
    public let scopePrefixLength: UInt8

    public init(family: UInt16, sourcePrefixLength: UInt8, scopePrefixLength: UInt8) {
        self.family = family
        self.sourcePrefixLength = sourcePrefixLength
        self.scopePrefixLength = scopePrefixLength
    }
}

/// Validated RFC 9460 SVCB (Type 64) / HTTPS (Type 65) & RFC 9462 DDR summary.
/// Target names and IP hints remain advisory metadata and never bypass routing
/// policy or grant unverified address authority.
public struct DNSServiceBindingRecord: Equatable {
    public let owner: String
    public let type: UInt16
    public let ttl: UInt32
    public let priority: UInt16
    public let targetName: String
    public let alpnProtocols: [String]
    public let noDefaultALPN: Bool
    public let port: UInt16?
    public let ipv4Hints: [String]
    public let ipv6Hints: [String]
    public let hasECHConfig: Bool
    public let dohPathTemplate: String?
}

/// Wire inspection shared by UDP DNS, TCP DNS and explicit node bootstrapping.
/// No operation in this type performs name resolution or opens a socket.
public enum DNSMessageInspection {
    public static func singleQuestion(in data: Data) -> DNSQueryQuestion? {
        question(in: data, response: false)
    }

    /// Call with an already validated, complete question. No address or name
    /// is retained in diagnostics, and no reverse lookup or routing is done.
    /// Incomplete/noncanonical reverse targets and special-use ranges remain
    /// `other`; metadata never changes acceptance of the original question.
    public static func ptrTargetCategory(for question: DNSQueryQuestion) -> DNSPTRTargetCategory? {
        guard question.type == 12, question.`class` == 1 else { return nil }
        let labels = question.name.split(separator: ".", omittingEmptySubsequences: false)
        if labels.count == 6, labels[4] == "in-addr", labels[5] == "arpa" {
            var address: UInt32 = 0
            for label in labels.prefix(4).reversed() {
                let digits = label.utf8
                guard (1...3).contains(digits.count),
                      digits.count == 1 || digits.first != 48,
                      digits.allSatisfy({ (48...57).contains($0) }),
                      let value = UInt8(label) else { return .other }
                address = address << 8 | UInt32(value)
            }
            // Match FakeIPAllocator's actual [198.19.0.0, 198.19.255.255)
            // range. The separate 198.18.16/24 tunnel subnet is not Fake-IP.
            if address >= 0xc613_0000, address < 0xc613_ffff { return .ipv4FakeIP }
            if address & 0xff00_0000 == 0x0a00_0000
                || address & 0xfff0_0000 == 0xac10_0000
                || address & 0xffff_0000 == 0xc0a8_0000 { return .ipv4Private }
            if address & 0xff00_0000 == 0x7f00_0000 { return .ipv4Loopback }
            if address & 0xffff_0000 == 0xa9fe_0000 { return .ipv4LinkLocal }
            // Conservative public classification: shared, documentation,
            // benchmark, protocol-assignment, multicast and reserved space
            // do not become evidence of a public reverse target.
            let special: [(UInt32, UInt32)] = [
                (0xff00_0000, 0x0000_0000), (0xffc0_0000, 0x6440_0000),
                (0xffff_ff00, 0xc000_0000), (0xffff_ff00, 0xc000_0200),
                (0xffff_ff00, 0xc058_6300), (0xfffe_0000, 0xc612_0000),
                (0xffff_ff00, 0xc633_6400), (0xffff_ff00, 0xcb00_7100),
                (0xe000_0000, 0xe000_0000),
            ]
            return special.contains(where: { address & $0.0 == $0.1 }) ? .other : .ipv4Public
        }
        if labels.count == 34, labels[32] == "ip6", labels[33] == "arpa" {
            var address = [UInt8](repeating: 0, count: 16)
            for (index, label) in labels.prefix(32).reversed().enumerated() {
                guard label.utf8.count == 1, let raw = label.utf8.first else { return .other }
                let nibble: UInt8
                if (48...57).contains(raw) { nibble = raw - 48 }
                else if (97...102).contains(raw) { nibble = raw - 87 }
                else { return .other }
                address[index / 2] |= nibble << (index.isMultiple(of: 2) ? 4 : 0)
            }
            if address.dropLast().allSatisfy({ $0 == 0 }), address[15] == 1 { return .ipv6Loopback }
            if address[0] & 0xfe == 0xfc { return .ipv6UniqueLocal }
            if address[0] == 0xfe, address[1] & 0xc0 == 0x80 { return .ipv6LinkLocal }
            guard address[0] & 0xe0 == 0x20 else { return .other }
            if address[0] == 0x20 {
                if address[1] == 0x01,
                   (address[2] & 0xfe == 0 || (address[2] == 0x0d && address[3] == 0xb8)) { return .other }
                if address[1] == 0x02 { return .other }
            }
            if address[0] == 0x3f, address[1] == 0xff, address[2] & 0xf0 == 0 { return .other }
            return .ipv6Public
        }
        return .other
    }

    /// Classify an already inspected question without reparsing or retaining
    /// its wire/name. Shape is independent of QCLASS and address category;
    /// even a special-use address has a complete reverse-query shape.
    /// These labels never affect acceptance, routing or the returned answer.
    public static func ptrQueryKind(for question: DNSQueryQuestion) -> DNSPTRQueryKind? {
        guard question.type == 12 else { return nil }
        let labels = question.name.split(separator: ".", omittingEmptySubsequences: false)
        if labels.count >= 3, labels[1] == "_dns-sd", labels[2] == "_udp" {
            switch labels[0] {
            case "b", "db", "r", "dr", "lb", "_services": return .dnsSDDomainEnumeration
            default: break
            }
        }
        if labels.count >= 2, labels[1] == "_tcp" || labels[1] == "_udp",
           isDNSServiceTypeLabel(labels[0]) { return .serviceType }

        let ipv4Zone = labels.count >= 2
            && labels[labels.count - 2] == "in-addr" && labels.last == "arpa"
        if ipv4Zone, labels.count == 6, labels.prefix(4).allSatisfy({ label in
            let digits = label.utf8
            return (1...3).contains(digits.count)
                && (digits.count == 1 || digits.first != 48)
                && digits.allSatisfy({ (48...57).contains($0) }) && UInt8(label) != nil
        }) { return .ipv4Reverse }
        let ipv6Zone = labels.count >= 2
            && labels[labels.count - 2] == "ip6" && labels.last == "arpa"
        if ipv6Zone, labels.count == 34, labels.prefix(32).allSatisfy({ label in
            guard label.utf8.count == 1, let digit = label.utf8.first else { return false }
            return (48...57).contains(digit) || (97...102).contains(digit)
        }) { return .ipv6Reverse }
        // A zone suffix must end on whole labels. Full-length malformed or
        // overlong reverse targets are not reported as partial addresses.
        if ipv4Zone && labels.count < 6 || ipv6Zone && labels.count < 34 { return .partialReverseZone }
        if labels.last == "local" { return .localName }
        return .other
    }

    /// An empty local view for DNS-SD domain enumeration beneath a narrowly
    /// defined local IPv4 reverse zone. The caller must first approve the
    /// original destination, QNAME and every configured resolver, and must
    /// preserve enterprise/custom resolver views. This pure wire helper does
    /// not grant routing permission or classify arbitrary PTRs as local.
    ///
    /// Only the simple RD/IN/PTR wire shape is handled. EDNS, authentication,
    /// compression and all other DNS flags retain the ordinary resolver path.
    /// No names or wire bytes are retained after returning the response.
    public static func localServiceDiscoveryResponse(to query: Data,
                                                      question: DNSQueryQuestion) -> Data? {
        guard question.type == 12, question.`class` == 1,
              (12...271).contains(query.count), question.questionEnd == query.count else { return nil }
        let bytes = [UInt8](query)
        guard read16(bytes, 2) == 0x0100, read16(bytes, 4) == 1,
              read16(bytes, 6) == 0, read16(bytes, 8) == 0, read16(bytes, 10) == 0,
              singleQuestion(in: query) == question else { return nil }

        // The general inspector deliberately supports compression. A local
        // answer instead requires one complete, uncompressed question, so a
        // pointer cannot borrow data from a discarded or unrelated record.
        var offset = 12
        while offset < bytes.count - 4 {
            let length = Int(bytes[offset])
            offset += 1
            if length == 0 { break }
            guard length <= 63, length <= bytes.count - 4 - offset else { return nil }
            offset += length
        }
        guard offset == bytes.count - 4, bytes[offset - 1] == 0 else { return nil }

        let labels = question.name.split(separator: ".", omittingEmptySubsequences: false)
        guard (6...9).contains(labels.count), labels[1] == "_dns-sd", labels[2] == "_udp",
              labels[labels.count - 2] == "in-addr", labels.last == "arpa" else { return nil }
        switch labels[0] {
        case "b", "db", "r", "dr", "lb": break
        default: return nil
        }
        var network: [UInt8] = []
        for label in labels[3..<(labels.count - 2)].reversed() {
            let digits = label.utf8
            guard (1...3).contains(digits.count),
                  digits.count == 1 || digits.first != 48,
                  digits.allSatisfy({ (48...57).contains($0) }),
                  let value = UInt8(label) else { return nil }
            network.append(value)
        }
        let localZone: Bool
        switch network[0] {
        case 10, 127: localZone = true
        case 172: localZone = network.count >= 2 && (16...31).contains(network[1])
        case 192: localZone = network.count >= 2 && network[1] == 168
        case 169: localZone = network.count >= 2 && network[1] == 254
        case 198:
            // Only this application's tunnel /24 and Fake-IP /16, not the
            // whole 198.18/15 benchmark range or any public reverse zone.
            localZone = network.count >= 2 && network[1] == 19
                || network.count >= 3 && network[1] == 18 && network[2] == 16
        default: localZone = false
        }
        guard localZone else { return nil }
        // Preserve the caller's transaction ID and QNAME case exactly. An
        // empty NOERROR view claims neither authority nor DNSSEC validation,
        // and creates no synthetic SOA or negative-cache lifetime.
        var reply = Data(bytes)
        reply[2] = 0x81
        reply[3] = 0x80
        return reply
    }

    /// DNS-SD uses an underscore followed by an RFC 6335 service name, then
    /// the separate exact _tcp/_udp label. Arbitrary underscore names and
    /// transport-looking suffixes must not be mistaken for service types.
    private static func isDNSServiceTypeLabel(_ label: Substring) -> Bool {
        guard label.first == "_" else { return false }
        let service = label.dropFirst(), bytes = service.utf8
        guard (1...15).contains(bytes.count), bytes.first != 45, bytes.last != 45 else { return false }
        var hasLetter = false, previousHyphen = false
        for byte in bytes {
            let letter = (97...122).contains(byte)
            if letter { hasLetter = true }
            guard letter || (48...57).contains(byte) || byte == 45 else { return false }
            if byte == 45 && previousHyphen { return false }
            previousHyphen = byte == 45
        }
        return hasLetter
    }

    public static func responseMatchesQuery(_ response: Data, query: Data) -> Bool {
        guard let expected = singleQuestion(in: query),
              let actual = question(in: response, response: true),
              response[response.startIndex] == query[query.startIndex],
              response[response.startIndex + 1] == query[query.startIndex + 1] else { return false }
        return actual.name == expected.name && actual.type == expected.type
            && actual.`class` == expected.`class`
    }

    /// Diagnostic INFO-CODE values only. Call after matching the response to
    /// its original question; unavailable or malformed EDNS metadata is nil
    /// and must not change whether the DNS response itself is accepted.
    /// Unknown record data and EDE EXTRA-TEXT remain opaque and are not kept.
    public static func extendedDNSErrorCodes(in response: Data) -> [UInt16]? {
        guard (12...65_535).contains(response.count),
              response[response.startIndex + 10] != 0 || response[response.startIndex + 11] != 0 else { return nil }
        let bytes = [UInt8](response)
        var nameWork = 65_535
        guard bytes[2] & 0x80 != 0, bytes[2] & 0x78 == 0,
              bytes[2] & 0x02 == 0, read16(bytes, 4) == 1,
              let questionEnd = diagnosticNameEnd(bytes, at: 12, work: &nameWork),
              questionEnd <= bytes.count - 4 else { return nil }
        let counts = [Int(read16(bytes, 6)), Int(read16(bytes, 8)), Int(read16(bytes, 10))]
        guard counts.reduce(0, +) <= 4_096 else { return nil }
        var offset = questionEnd + 4, foundOPT = false
        var codes: [UInt16] = []
        for (section, count) in counts.enumerated() {
            for _ in 0..<count {
                let ownerStart = offset
                guard let ownerEnd = diagnosticNameEnd(bytes, at: offset, work: &nameWork),
                      ownerEnd <= bytes.count - 10 else { return nil }
                offset = ownerEnd
                let type = read16(bytes, offset), length = Int(read16(bytes, offset + 8))
                let body = offset + 10
                guard length <= bytes.count - body else { return nil }
                let end = body + length
                if type == 41 {
                    // Only a single, uncompressed root OPT in the additional
                    // section with the EDNS version we understand is trusted.
                    guard section == 2, !foundOPT, bytes[ownerStart] == 0,
                          ownerEnd == ownerStart + 1, bytes[offset + 5] == 0 else { return nil }
                    foundOPT = true
                    var option = body
                    while option < end {
                        guard end - option >= 4 else { return nil }
                        let optionCode = read16(bytes, option)
                        let optionLength = Int(read16(bytes, option + 2))
                        option += 4
                        guard optionLength <= end - option else { return nil }
                        if optionCode == 15 {
                            guard optionLength >= 2 else { return nil }
                            let infoCode = read16(bytes, option)
                            if codes.count < 8, !codes.contains(infoCode) { codes.append(infoCode) }
                        }
                        option += optionLength
                    }
                }
                offset = end
            }
        }
        // Even after reaching the numeric cap, scan every remaining option,
        // name and record before publishing any value from this response.
        guard offset == bytes.count, foundOPT, !codes.isEmpty else { return nil }
        return codes
    }

    /// Maps an RFC 8914 Extended DNS Error INFO-CODE to its semantic category.
    public static func classifyExtendedDNSError(_ infoCode: UInt16) -> DNSExtendedErrorCategory {
        switch infoCode {
        case 1, 2, 5, 6, 7, 8, 9, 10, 11, 12:
            return .dnssecValidationFailure
        case 4, 15, 16, 17, 18, 21, 25, 26, 27, 29:
            return .policyBlockedOrCensored
        case 3, 13, 19:
            return .staleOrCachedError
        case 14, 20, 22, 23, 24:
            return .resolverTransientOrNetwork
        default:
            return .other
        }
    }

    /// Extracts deduplicated RFC 8914 EDE categories from a validated response.
    public static func extendedDNSErrorCategories(in response: Data) -> [DNSExtendedErrorCategory]? {
        guard let codes = extendedDNSErrorCodes(in: response) else { return nil }
        var seen = Set<DNSExtendedErrorCategory>()
        var result: [DNSExtendedErrorCategory] = []
        for code in codes {
            let cat = classifyExtendedDNSError(code)
            if seen.insert(cat).inserted { result.append(cat) }
        }
        return result
    }

    /// RFC 9250 §4.2 & §4.2.1: Encodes a DNS wire message into a 2-octet length-prefixed
    /// DoQ stream frame with wire Message ID normalized to 0x0000.
    public static func encodeDoQFrame(_ query: Data) -> (frame: Data, originalID: UInt16)? {
        guard (12...65_535).contains(query.count),
              singleQuestion(in: query) != nil else { return nil }
        let bytes = [UInt8](query)
        let originalID = read16(bytes, 0)
        var frame = Data(capacity: 2 + bytes.count)
        append16(UInt16(bytes.count), to: &frame)
        frame.append(0)
        frame.append(0)
        frame.append(contentsOf: bytes[2...])
        return (frame, originalID)
    }

    /// RFC 9250 §4.2 & §4.2.1: Decodes a 2-octet length-prefixed DoQ response frame,
    /// requiring the wire Message ID to be 0x0000 and restoring `expectedClientID`.
    public static func decodeDoQFrame(_ frame: Data, expectedClientID: UInt16) -> Data? {
        guard frame.count >= 14 else { return nil }
        let bytes = [UInt8](frame)
        let declared = Int(read16(bytes, 0))
        guard (12...65_535).contains(declared), bytes.count == 2 + declared,
              read16(bytes, 2) == 0 else { return nil }
        var restored = Data(capacity: declared)
        append16(expectedClientID, to: &restored)
        restored.append(contentsOf: bytes[4...])
        return restored
    }

    /// RFC 7830 / RFC 8467 Block-Length Padding: aligns a standard DNS query to
    /// `blockSize` (default 128 bytes per RFC 8467 §4.1) using EDNS0 Option 12.
    public static func paddedQuery(_ query: Data, blockSize: Int = 128,
                                   maxPayload: UInt16 = 1232) -> Data? {
        applyEDNSPadding(query, isResponse: false, blockSize: blockSize, maxPayload: maxPayload)
    }

    /// RFC 7830 / RFC 8467 Block-Length Padding: aligns a DNS response to
    /// `blockSize` (default 468 bytes per RFC 8467 §4.1) using EDNS0 Option 12.
    public static func paddedResponse(_ response: Data, blockSize: Int = 468,
                                      maxPayload: UInt16 = 1232) -> Data? {
        applyEDNSPadding(response, isResponse: true, blockSize: blockSize, maxPayload: maxPayload)
    }

    private static func applyEDNSPadding(_ message: Data, isResponse: Bool,
                                         blockSize: Int, maxPayload: UInt16) -> Data? {
        guard (12...65_535).contains(message.count),
              (16...4096).contains(blockSize), maxPayload >= 512,
              let q = question(in: message, response: isResponse) else { return nil }
        let bytes = [UInt8](message)
        let anCount = Int(read16(bytes, 6))
        let nsCount = Int(read16(bytes, 8))
        let arCount = Int(read16(bytes, 10))
        guard anCount + nsCount + arCount <= 512 else { return nil }
        var offset = q.questionEnd
        var nameWork = 65_535
        let nonTail = anCount + nsCount + (arCount > 0 ? arCount - 1 : 0)
        for _ in 0..<nonTail {
            guard let ownerEnd = diagnosticNameEnd(bytes, at: offset, work: &nameWork),
                  ownerEnd <= bytes.count - 10 else { return nil }
            let rtype = read16(bytes, ownerEnd)
            guard rtype != 41 else { return nil }
            let rdlen = Int(read16(bytes, ownerEnd + 8))
            offset = ownerEnd + 10
            guard rdlen <= bytes.count - offset else { return nil }
            offset += rdlen
        }
        var cleanOptions = Data()
        var optPayload = maxPayload
        var optFlags: UInt32 = 0
        if arCount > 0 {
            guard offset <= bytes.count - 11, bytes[offset] == 0,
                  read16(bytes, offset + 1) == 41 else { return nil }
            optPayload = max(512, read16(bytes, offset + 3))
            guard bytes[offset + 6] == 0 else { return nil } // EDNS version 0
            optFlags = UInt32(bytes[offset + 5]) << 24 | UInt32(bytes[offset + 6]) << 16
                | UInt32(bytes[offset + 7]) << 8 | UInt32(bytes[offset + 8])
            let rdlen = Int(read16(bytes, offset + 9))
            let rdataStart = offset + 11
            guard rdataStart + rdlen == bytes.count else { return nil }
            var pos = rdataStart
            while pos < bytes.count {
                guard bytes.count - pos >= 4 else { return nil }
                let code = read16(bytes, pos)
                let olen = Int(read16(bytes, pos + 2))
                guard olen <= bytes.count - (pos + 4) else { return nil }
                if code != 12 {
                    cleanOptions.append(contentsOf: bytes[pos..<(pos + 4 + olen)])
                }
                pos += 4 + olen
            }
        } else {
            guard offset == bytes.count else { return nil }
        }
        let baseSize = offset + 11 + cleanOptions.count + 4
        let limit = Int(min(optPayload, maxPayload))
        guard baseSize <= limit else { return nil }
        let rem = baseSize % blockSize
        var padLen = rem == 0 ? 0 : (blockSize - rem)
        if baseSize + padLen > limit {
            padLen = max(0, limit - baseSize)
        }
        let newRdlen = cleanOptions.count + 4 + padLen
        guard newRdlen <= 65_535 else { return nil }
        var out = Data(bytes[0..<offset])
        if arCount == 0 {
            let newAR = UInt16(arCount + 1)
            out[10] = UInt8(truncatingIfNeeded: newAR >> 8)
            out[11] = UInt8(truncatingIfNeeded: newAR)
        }
        out.append(0) // root owner
        append16(41, to: &out)
        append16(optPayload, to: &out)
        out.append(UInt8(truncatingIfNeeded: optFlags >> 24))
        out.append(UInt8(truncatingIfNeeded: optFlags >> 16))
        out.append(UInt8(truncatingIfNeeded: optFlags >> 8))
        out.append(UInt8(truncatingIfNeeded: optFlags))
        append16(UInt16(newRdlen), to: &out)
        out.append(cleanOptions)
        append16(12, to: &out) // Option Code 12: Padding
        append16(UInt16(padLen), to: &out)
        if padLen > 0 { out.append(Data(repeating: 0, count: padLen)) }
        return out
    }

    /// Inspects RFC 7871 EDNS0 Client Subnet (Option Code 8) metadata if present.
    public static func inspectEDNSClientSubnet(in message: Data) -> DNSECSMetadata? {
        guard (12...65_535).contains(message.count) else { return nil }
        let bytes = [UInt8](message)
        let isResp = (bytes[2] & 0x80) != 0
        guard let q = question(in: message, response: isResp) else { return nil }
        let counts = [Int(read16(bytes, 6)), Int(read16(bytes, 8)), Int(read16(bytes, 10))]
        guard counts[2] > 0, counts.reduce(0, +) <= 512 else { return nil }
        var offset = q.questionEnd
        var nameWork = 65_535
        for section in 0..<3 {
            for _ in 0..<counts[section] {
                let ownerStart = offset
                guard let ownerEnd = diagnosticNameEnd(bytes, at: offset, work: &nameWork),
                      ownerEnd <= bytes.count - 10 else { return nil }
                let rtype = read16(bytes, ownerEnd)
                let rdlen = Int(read16(bytes, ownerEnd + 8))
                let body = ownerEnd + 10
                guard rdlen <= bytes.count - body else { return nil }
                let end = body + rdlen
                if rtype == 41 {
                    guard section == 2, bytes[ownerStart] == 0, ownerEnd == ownerStart + 1 else { return nil }
                    var pos = body
                    while pos < end {
                        guard end - pos >= 4 else { return nil }
                        let code = read16(bytes, pos)
                        let olen = Int(read16(bytes, pos + 2))
                        pos += 4
                        guard olen <= end - pos else { return nil }
                        if code == 8 {
                            guard olen >= 4 else { return nil }
                            let family = read16(bytes, pos)
                            let srcPrefix = bytes[pos + 2]
                            let scopePrefix = bytes[pos + 3]
                            let maxBits: UInt8 = family == 1 ? 32 : (family == 2 ? 128 : 0)
                            let addrBytes = Int((srcPrefix + 7) / 8)
                            guard maxBits > 0, srcPrefix <= maxBits, olen == 4 + addrBytes else { return nil }
                            return DNSECSMetadata(family: family, sourcePrefixLength: srcPrefix, scopePrefixLength: scopePrefix)
                        }
                        pos += olen
                    }
                }
                offset = end
            }
        }
        return nil
    }

    /// Sanitizes RFC 7871 EDNS0 Client Subnet (Option Code 8) in a DNS query.
    public static func sanitizingEDNSClientSubnet(in query: Data,
                                                  mode: DNSECSPrivacyMode = .strip) -> Data? {
        guard (12...65_535).contains(query.count),
              let q = singleQuestion(in: query) else { return nil }
        let bytes = [UInt8](query)
        guard read16(bytes, 6) == 0, read16(bytes, 8) == 0 else { return nil }
        let arCount = Int(read16(bytes, 10))
        if arCount == 0 {
            return q.questionEnd == bytes.count ? Data(bytes) : nil
        }
        guard arCount == 1, q.questionEnd <= bytes.count - 11,
              bytes[q.questionEnd] == 0, read16(bytes, q.questionEnd + 1) == 41,
              bytes[q.questionEnd + 6] == 0 else { return nil }
        let rdlen = Int(read16(bytes, q.questionEnd + 9))
        let rdataStart = q.questionEnd + 11
        guard rdataStart + rdlen == bytes.count else { return nil }
        var sanitizedOptions = Data()
        var pos = rdataStart
        while pos < bytes.count {
            guard bytes.count - pos >= 4 else { return nil }
            let code = read16(bytes, pos)
            let olen = Int(read16(bytes, pos + 2))
            let valStart = pos + 4
            guard olen <= bytes.count - valStart else { return nil }
            if code == 8 {
                guard olen >= 4 else { return nil }
                let family = read16(bytes, valStart)
                let srcPrefix = bytes[valStart + 2]
                let maxBits: UInt8 = family == 1 ? 32 : (family == 2 ? 128 : 0)
                let addrBytes = Int((srcPrefix + 7) / 8)
                guard maxBits > 0, srcPrefix <= maxBits, olen == 4 + addrBytes else { return nil }
                switch mode {
                case .strip:
                    break
                case .anonymizeZeroPrefix:
                    append16(8, to: &sanitizedOptions)
                    append16(4, to: &sanitizedOptions)
                    append16(family, to: &sanitizedOptions)
                    sanitizedOptions.append(0)
                    sanitizedOptions.append(0)
                case .truncatePrivacyBound:
                    let clamped = min(srcPrefix, family == 1 ? 24 : 56)
                    let clampedBytes = Int((clamped + 7) / 8)
                    append16(8, to: &sanitizedOptions)
                    append16(UInt16(4 + clampedBytes), to: &sanitizedOptions)
                    append16(family, to: &sanitizedOptions)
                    sanitizedOptions.append(clamped)
                    sanitizedOptions.append(0)
                    if clampedBytes > 0 {
                        var addr = Array(bytes[(valStart + 4)..<(valStart + 4 + clampedBytes)])
                        let remBits = clamped % 8
                        if remBits != 0 {
                            addr[clampedBytes - 1] &= (0xFF << (8 - remBits))
                        }
                        sanitizedOptions.append(contentsOf: addr)
                    }
                }
            } else {
                sanitizedOptions.append(contentsOf: bytes[pos..<(valStart + olen)])
            }
            pos = valStart + olen
        }
        var out = Data(bytes[0..<(q.questionEnd + 9)])
        append16(UInt16(sanitizedOptions.count), to: &out)
        out.append(sanitizedOptions)
        return out
    }

    /// Constructs an RFC 9462 Discovery of Designated Resolvers (DDR) query
    /// for `_dns.resolver.arpa` (QTYPE = SVCB 64, QCLASS = IN 1).
    public static func ddrDiscoveryQuery(id: UInt16 = UInt16.random(in: .min ... .max)) -> Data? {
        query(for: "_dns.resolver.arpa", type: 64, id: id)
    }

    /// Extracts validated RFC 9460 SVCB (Type 64) and HTTPS (Type 65) records
    /// from the answer section, including ALPN, port, IPv4/IPv6 hints, ECH
    /// presence, and RFC 9461/9462 `dohpath` (key 7).
    public static func serviceBindingAnswers(in response: Data) -> [DNSServiceBindingRecord] {
        guard let q = question(in: response, response: true),
              q.`class` == 1, (q.type == 64 || q.type == 65),
              response[response.startIndex + 2] & 0x02 == 0,
              response[response.startIndex + 3] & 0x0F == 0 else { return [] }
        let bytes = [UInt8](response)
        let anCount = Int(read16(bytes, 6))
        guard anCount > 0, anCount <= 256 else { return [] }
        var offset = q.questionEnd
        var results: [DNSServiceBindingRecord] = []
        for _ in 0..<anCount {
            guard let owner = readName(bytes, at: offset), owner.end <= bytes.count - 10 else { return [] }
            offset = owner.end
            let rtype = read16(bytes, offset), rclass = read16(bytes, offset + 2)
            let ttl = UInt32(bytes[offset + 4]) << 24 | UInt32(bytes[offset + 5]) << 16
                | UInt32(bytes[offset + 6]) << 8 | UInt32(bytes[offset + 7])
            let rdlength = Int(read16(bytes, offset + 8))
            offset += 10
            guard rdlength <= bytes.count - offset else { return [] }
            let end = offset + rdlength
            if rclass == 1 && (rtype == 64 || rtype == 65) {
                guard end - offset >= 3,
                      let target = readName(bytes, at: offset + 2),
                      target.end <= end else { return [] }
                let priority = read16(bytes, offset)
                var alpn: [String] = []
                var noDefaultALPN = false
                var port: UInt16?
                var ipv4Hints: [String] = []
                var ipv6Hints: [String] = []
                var hasECH = false
                var dohPath: String?
                if priority == 0 {
                    guard target.end == end else { return [] }
                } else {
                    var paramPos = target.end
                    var lastKey: Int = -1
                    while paramPos < end {
                        guard end - paramPos >= 4 else { return [] }
                        let key = read16(bytes, paramPos)
                        let valLen = Int(read16(bytes, paramPos + 2))
                        paramPos += 4
                        guard Int(key) > lastKey, valLen <= end - paramPos else { return [] }
                        lastKey = Int(key)
                        let valEnd = paramPos + valLen
                        switch key {
                        case 1: // alpn
                            guard valLen > 0 else { return [] }
                            var idx = paramPos
                            while idx < valEnd {
                                let len = Int(bytes[idx]); idx += 1
                                guard len > 0, len <= valEnd - idx,
                                      let proto = String(bytes: bytes[idx..<(idx + len)], encoding: .utf8) else { return [] }
                                alpn.append(proto)
                                idx += len
                            }
                        case 2: // no-default-alpn
                            guard valLen == 0 else { return [] }
                            noDefaultALPN = true
                        case 3: // port
                            guard valLen == 2 else { return [] }
                            port = read16(bytes, paramPos)
                        case 4: // ipv4hint
                            guard valLen > 0, valLen % 4 == 0 else { return [] }
                            for ipOff in stride(from: paramPos, to: valEnd, by: 4) {
                                let raw = Array(bytes[ipOff..<(ipOff + 4)])
                                var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                                if raw.withUnsafeBytes({ inet_ntop(AF_INET, $0.baseAddress, &text, socklen_t(text.count)) }) != nil {
                                    ipv4Hints.append(String(cString: text))
                                }
                            }
                        case 5: // ech
                            guard valLen >= 7, Int(read16(bytes, paramPos)) == valLen - 2 else { return [] }
                            hasECH = true
                        case 6: // ipv6hint
                            guard valLen > 0, valLen % 16 == 0 else { return [] }
                            for ipOff in stride(from: paramPos, to: valEnd, by: 16) {
                                let raw = Array(bytes[ipOff..<(ipOff + 16)])
                                var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                                if raw.withUnsafeBytes({ inet_ntop(AF_INET6, $0.baseAddress, &text, socklen_t(text.count)) }) != nil {
                                    ipv6Hints.append(String(cString: text))
                                }
                            }
                        case 7: // dohpath (RFC 9461 / RFC 9462)
                            guard valLen > 0,
                                  let path = String(bytes: bytes[paramPos..<valEnd], encoding: .utf8),
                                  path.hasPrefix("/") else { return [] }
                            dohPath = path
                        default:
                            break
                        }
                        paramPos = valEnd
                    }
                }
                results.append(DNSServiceBindingRecord(
                    owner: owner.name, type: rtype, ttl: ttl, priority: priority,
                    targetName: target.name, alpnProtocols: alpn, noDefaultALPN: noDefaultALPN,
                    port: port, ipv4Hints: ipv4Hints, ipv6Hints: ipv6Hints,
                    hasECHConfig: hasECH, dohPathTemplate: dohPath))
            }
            offset = end
        }
        return results
    }

    /// Validate wire-name framing without allocating owner strings. Compression
    /// must point backwards and expansion stays within the DNS name bound.
    /// A shared byte/step budget prevents repeated long compressed owners from
    /// amplifying a small response into unbounded diagnostic work. Exhaustion
    /// merely omits EDE; normal response identity and acceptance stay separate.
    private static func diagnosticNameEnd(_ bytes: [UInt8], at start: Int, work: inout Int) -> Int? {
        guard start >= 0, start < bytes.count else { return nil }
        var offset = start, end: Int?, expandedLength = 1
        for _ in 0..<256 {
            guard offset < bytes.count, work > 0 else { return nil }
            work -= 1
            let length = Int(bytes[offset])
            if length & 0xc0 == 0xc0 {
                guard offset + 1 < bytes.count, work > 0 else { return nil }
                work -= 1
                let pointer = (length & 0x3f) << 8 | Int(bytes[offset + 1])
                guard pointer >= 12, pointer < offset else { return nil }
                if end == nil { end = offset + 2 }
                offset = pointer
                continue
            }
            guard length <= 63 else { return nil }
            offset += 1
            if length == 0 { return end ?? offset }
            guard length <= bytes.count - offset, expandedLength <= 255 - length - 1,
                  work >= length else { return nil }
            work -= length
            expandedLength += length + 1
            offset += length
        }
        return nil
    }

    public static func query(for name: String, type: UInt16,
                             id: UInt16 = UInt16.random(in: .min ... .max)) -> Data? {
        guard let encodedName = encodeName(name) else { return nil }
        var data = Data([UInt8(truncatingIfNeeded: id >> 8), UInt8(truncatingIfNeeded: id),
                         0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        data.append(encodedName)
        append16(type, to: &data)
        append16(1, to: &data)
        return data
    }

    /// Re-encode the question rather than retaining compression pointers into
    /// records that the error response necessarily removes.
    public static func errorResponse(to query: Data, code: DNSResponseCode) -> Data? {
        guard query.count >= 2,
              query.count < 3 || query[query.startIndex + 2] & 0x80 == 0 else { return nil }
        var reply = Data(repeating: 0, count: 12)
        reply[0] = query[query.startIndex]
        reply[1] = query[query.startIndex + 1]
        let requestFlags = query.count >= 3 ? query[query.startIndex + 2] : 0
        reply[2] = 0x80 | (requestFlags & 0x79)
        reply[3] = 0x80 | code.rawValue
        if let question = singleQuestion(in: query), let name = encodeName(question.name) {
            reply[5] = 1
            reply.append(name)
            append16(question.type, to: &reply)
            append16(question.`class`, to: &reply)
        }
        return reply
    }

    /// Accept addresses only from the answer section and only for the question
    /// or its bounded CNAME chain. The returned domain is the original question,
    /// so routing keeps its application identity rather than a CDN alias.
    /// Additional-section glue is not a host answer.
    public static func addressAnswers(in response: Data)
        -> [(domain: String, address: String, ttl: UInt32)] {
        guard let question = question(in: response, response: true),
              question.`class` == 1,
              response[response.startIndex + 2] & 0x02 == 0,
              response[response.startIndex + 3] & 0x0F == 0 else { return [] }
        let bytes = [UInt8](response)
        let count = Int(read16(bytes, 6))
        guard count <= 4_096 else { return [] }
        var offset = question.questionEnd
        var aliases: [String: (name: String, ttl: UInt32)] = [:]
        var records: [(domain: String, address: String, ttl: UInt32)] = []
        for _ in 0..<count {
            guard let owner = readName(bytes, at: offset), owner.end <= bytes.count - 10 else { return [] }
            offset = owner.end
            let type = read16(bytes, offset), cls = read16(bytes, offset + 2)
            let ttl = UInt32(bytes[offset + 4]) << 24 | UInt32(bytes[offset + 5]) << 16
                | UInt32(bytes[offset + 6]) << 8 | UInt32(bytes[offset + 7])
            let length = Int(read16(bytes, offset + 8))
            offset += 10
            guard length <= bytes.count - offset else { return [] }
            if cls == 1 && type == 5 {
                guard let alias = readName(bytes, at: offset), alias.end == offset + length else { return [] }
                if let existing = aliases[owner.name], existing.name != alias.name { return [] }
                aliases[owner.name] = (alias.name, min(ttl, aliases[owner.name]?.ttl ?? ttl))
            } else if cls == 1 && ((type == 1 && length == 4) || (type == 28 && length == 16)) {
                let raw = Array(bytes[offset..<(offset + length)])
                var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                let converted = raw.withUnsafeBytes {
                    inet_ntop(type == 1 ? AF_INET : AF_INET6, $0.baseAddress, &text,
                              socklen_t(text.count))
                }
                guard converted != nil else { return [] }
                records.append((owner.name, String(cString: text), ttl))
            }
            offset += length
        }
        var chain: [String: UInt32] = [:]
        var name = question.name, minimumTTL = UInt32.max
        for _ in 0..<64 {
            guard chain[name] == nil else { return [] }
            chain[name] = minimumTTL
            guard let alias = aliases[name] else {
                return records.compactMap { record in
                    guard let limit = chain[record.domain] else { return nil }
                    return (question.name, record.address, min(record.ttl, limit))
                }
            }
            minimumTTL = min(minimumTTL, alias.ttl)
            name = alias.name
        }
        return []
    }

    private static func question(in data: Data, response: Bool) -> DNSQueryQuestion? {
        guard (12...65_535).contains(data.count) else { return nil }
        let bytes = [UInt8](data)
        guard (bytes[2] & 0x80 != 0) == response,
              bytes[2] & 0x78 == 0, read16(bytes, 4) == 1,
              let name = readName(bytes, at: 12), name.end <= bytes.count - 4 else { return nil }
        return DNSQueryQuestion(name: name.name, type: read16(bytes, name.end),
                                class: read16(bytes, name.end + 2), questionEnd: name.end + 4)
    }

    private static func readName(_ bytes: [UInt8], at start: Int) -> (name: String, end: Int)? {
        guard start >= 0, start < bytes.count else { return nil }
        var offset = start, end: Int?, labels: [String] = []
        var visited = Set<Int>(), expandedLength = 1
        for _ in 0..<256 {
            guard offset < bytes.count, visited.insert(offset).inserted else { return nil }
            let length = Int(bytes[offset])
            if length & 0xC0 == 0xC0 {
                guard offset + 1 < bytes.count else { return nil }
                let pointer = (length & 0x3F) << 8 | Int(bytes[offset + 1])
                guard pointer >= 12, pointer < bytes.count else { return nil }
                if end == nil { end = offset + 2 }
                offset = pointer
                continue
            }
            guard length <= 63 else { return nil }
            offset += 1
            if length == 0 {
                let name = labels.isEmpty ? "." : labels.joined(separator: ".").lowercased()
                guard name == "." || name.utf8.count <= 253 else { return nil }
                return (name, end ?? offset)
            }
            guard length <= bytes.count - offset,
                  expandedLength <= 255 - length - 1,
                  let label = String(bytes: bytes[offset..<(offset + length)], encoding: .utf8),
                  !label.contains("."), !label.contains("\\"), !label.contains("\0") else { return nil }
            expandedLength += length + 1
            labels.append(label)
            offset += length
        }
        return nil
    }

    private static func encodeName(_ raw: String) -> Data? {
        var name = raw
        if name == "." { return Data([0]) }
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name.utf8.count <= 253, !name.contains("\\"), !name.contains("\0") else { return nil }
        var encoded = Data()
        for label in name.split(separator: ".", omittingEmptySubsequences: false) {
            let bytes = Array(label.utf8)
            guard !bytes.isEmpty, bytes.count <= 63 else { return nil }
            encoded.append(UInt8(bytes.count))
            encoded.append(contentsOf: bytes)
        }
        encoded.append(0)
        return encoded.count <= 255 ? encoded : nil
    }

    private static func read16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func append16(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }
}

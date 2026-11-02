import Foundation
import Darwin

/// The ordinary rule interpreter. DNS's recursive QNAME substitutions and
/// authority barriers deliberately remain in its Core owner.
public enum RoutingRuleMatcher {
    public static func matches(_ kind: RuleKind, target: RequestTarget) -> Bool {
        matches(kind, target: target, domainMatcher: nil)
    }

    package static func matches(_ kind: RuleKind, target: RequestTarget,
                                domainMatcher: RoutingDomainMatcher?) -> Bool {
        var cachedNormalizedHost: String?
        func normalizedHost() -> String {
            if let existing = cachedNormalizedHost { return existing }
            let computed = DomainPattern.trimDotsAndLowercase(target.host)
            cachedNormalizedHost = computed
            return computed
        }
        switch kind {
        case .domain(let value):
            if let match = domainMatcher?(target.host, value, .exact) { return match }
            return normalizedHost() == value.lowercased()
        case .domainSuffix(let value):
            if let match = domainMatcher?(target.host, value, .suffix) { return match }
            let host = normalizedHost()
            let suffix = DomainPattern.trimDotsAndLowercase(value)
            return host == suffix || host.hasSuffix("." + suffix)
        case .domainKeyword(let value):
            if let match = domainMatcher?(target.host, value, .keyword) { return match }
            return normalizedHost().contains(value.lowercased())
        case .domainWildcard(let value):
            return DomainPattern.wildcard(value, matches: normalizedHost())
        case .ipCIDR(let cidr):
            return IPCIDR.contains(normalizedHost(), cidr: cidr)
        case .destinationPort(let range):
            return range.contains(target.port)
        case .sourceIPCIDR(let cidr):
            guard let source = target.sourceHost else { return false }
            return IPCIDR.contains(source, cidr: cidr)
        case .sourcePort(let range):
            guard let port = target.sourcePort else { return false }
            return range.contains(port)
        case .inboundPort(let range):
            guard let port = target.inboundPort else { return false }
            return range.contains(port)
        case .protocolName(let value):
            return target.protocolName.caseInsensitiveCompare(value) == .orderedSame
        case .processName(let expected):
            guard let actual = target.processName?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !actual.isEmpty else { return false }
            let needle = expected.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !needle.isEmpty else { return false }
            if actual.caseInsensitiveCompare(needle) == .orderedSame { return true }
            let actualBase = (actual as NSString).lastPathComponent
            let needleBase = (needle as NSString).lastPathComponent
            if !actualBase.isEmpty && actualBase.caseInsensitiveCompare(needleBase) == .orderedSame {
                return true
            }
            for component in actual.split(separator: "/") where component.lowercased().hasSuffix(".app") {
                if component.caseInsensitiveCompare(needleBase) == .orderedSame {
                    return true
                }
            }
            return false
        case .geoIP, .ipASN:
            // Need MaxMind database lookup that Hajimi does not ship.
            return false
        case .logicalAnd(let children):
            return !children.isEmpty && children.allSatisfy {
                matches($0, target: target, domainMatcher: domainMatcher)
            }
        case .logicalOr(let children):
            return children.contains { matches($0, target: target, domainMatcher: domainMatcher) }
        case .logicalNot(let child):
            return !matches(child, target: target, domainMatcher: domainMatcher)
        case .ruleSet:
            return false
        case .final:
            return true
        }
    }

    package static func matches(_ rule: RoutingRule, target: RequestTarget,
                                alternateHost: String?, ruleSetContents: [String: [RuleKind]],
                                domainMatcher: RoutingDomainMatcher?) -> Bool {
        if case .ruleSet(let reference) = rule.kind {
            guard let contents = ruleSetContents[reference.location] else { return false }
            return contents.contains { kind in
                guard let candidate = matchTarget(for: kind, target: target,
                                                  alternateHost: alternateHost) else { return false }
                return matches(kind, target: candidate, domainMatcher: domainMatcher)
            }
        }
        guard let candidate = matchTarget(for: rule.kind, target: target,
                                          alternateHost: alternateHost) else { return false }
        return matches(rule.kind, target: candidate, domainMatcher: domainMatcher)
    }

    private static func matchTarget(for kind: RuleKind, target: RequestTarget,
                                    alternateHost: String?) -> RequestTarget? {
        switch kind {
        case .domain, .domainSuffix, .domainKeyword, .domainWildcard:
            guard let alternateHost else { return target }
            return RequestTarget(host: alternateHost, port: target.port,
                                 protocolName: target.protocolName,
                                 sourceHost: target.sourceHost,
                                 sourcePort: target.sourcePort,
                                 inboundPort: target.inboundPort,
                                 processName: target.processName)
        case .logicalAnd, .logicalOr, .logicalNot:
            return target
        case .ruleSet:
            return nil
        default:
            return target
        }
    }
}

/// Surge-style domain patterns used by `always-real-ip` and DOMAIN-WILDCARD.
package enum DomainPattern {
    private static let dotCharacterSet = CharacterSet(charactersIn: ".")

    package static func trimDotsAndLowercase(_ raw: String) -> String {
        raw.lowercased().trimmingCharacters(in: dotCharacterSet)
    }

    package static func any(_ patterns: [String], matches host: String) -> Bool {
        patterns.contains { matches($0, host: host) }
    }

    package static func matches(_ pattern: String, host: String) -> Bool {
        let needle = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return false }
        let name = trimDotsAndLowercase(host)
        if needle.contains("*") || needle.contains("?") {
            return wildcard(needle, matches: name)
        }
        let suffix = trimDotsAndLowercase(needle)
        return name == suffix || name.hasSuffix("." + suffix)
    }

    package static func wildcard(_ pattern: String, matches host: String) -> Bool {
        let name = trimDotsAndLowercase(host)
        let raw = trimDotsAndLowercase(pattern)
        return glob(raw, matches: name)
    }

    private static func glob(_ pattern: String, matches value: String) -> Bool {
        func walk(_ p: String.Index, _ v: String.Index) -> Bool {
            var patternIndex = p
            var valueIndex = v
            while patternIndex < pattern.endIndex {
                let character = pattern[patternIndex]
                if character == "*" {
                    let next = pattern.index(after: patternIndex)
                    if next == pattern.endIndex { return true }
                    var probe = valueIndex
                    while probe <= value.endIndex {
                        if walk(next, probe) { return true }
                        if probe == value.endIndex { break }
                        probe = value.index(after: probe)
                    }
                    return false
                }
                if valueIndex == value.endIndex { return false }
                if character != "?" && character != value[valueIndex] { return false }
                patternIndex = pattern.index(after: patternIndex)
                valueIndex = value.index(after: valueIndex)
            }
            return valueIndex == value.endIndex
        }
        return walk(pattern.startIndex, value.startIndex)
    }
}

package enum IPCIDR {
    package static func contains(_ address: String, cidr: String) -> Bool {
        let pieces = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard pieces.count == 2, let bits = Int(pieces[1]) else { return false }
        if pieces[0].contains(":"), (0...128).contains(bits) {
            return containsIPv6(address, network: pieces[0], bits: bits)
        }
        guard (0...32).contains(bits), let ip = ipv4Value(address),
              let network = ipv4Value(pieces[0]) else { return false }
        let mask: UInt32 = bits == 0 ? 0 : UInt32.max << UInt32(32 - bits)
        return (ip & mask) == (network & mask)
    }

    private static func ipv4Value(_ string: String) -> UInt32? {
        var address = in_addr()
        guard inet_pton(AF_INET, string, &address) == 1 else { return nil }
        return UInt32(bigEndian: address.s_addr)
    }

    private static func containsIPv6(_ rawAddress: String, network: String, bits: Int) -> Bool {
        let addressString = rawAddress.split(separator: "%", maxSplits: 1).first.map(String.init) ?? rawAddress
        var address = in6_addr()
        var networkAddress = in6_addr()
        guard inet_pton(AF_INET6, addressString, &address) == 1,
              inet_pton(AF_INET6, network, &networkAddress) == 1 else { return false }
        return withUnsafeBytes(of: &address) { addressBytes in
            withUnsafeBytes(of: &networkAddress) { networkBytes in
                let fullBytes = bits / 8
                for i in 0..<fullBytes where addressBytes[i] != networkBytes[i] {
                    return false
                }
                let remaining = bits % 8
                guard remaining > 0 else { return true }
                let mask = UInt8.max << UInt8(8 - remaining)
                return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask)
            }
        }
    }
}

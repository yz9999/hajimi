import Foundation

public enum SubscriptionFormat: String, Equatable, Codable {
    case clash
    case surge
    case shareLinks
}

public struct SubscriptionContents: Equatable {
    public var format: SubscriptionFormat
    /// Fully-formed `[Proxy]` lines, ready to splice into a profile.
    public var proxyLines: [String]
    public var groupLines: [String]
    public var proxyNames: [String]
    public var groupNames: [String]
    public var warnings: [String]

    public init(format: SubscriptionFormat, proxyLines: [String] = [], groupLines: [String] = [],
                proxyNames: [String] = [], groupNames: [String] = [], warnings: [String] = []) {
        self.format = format
        self.proxyLines = proxyLines
        self.groupLines = groupLines
        self.proxyNames = proxyNames
        self.groupNames = groupNames
        self.warnings = warnings
    }
}

public enum SubscriptionError: LocalizedError, Equatable {
    case unrecognizedFormat
    case empty

    public var errorDescription: String? {
        switch self {
        case .unrecognizedFormat:
            return "无法识别订阅格式，仅支持 Clash YAML、Surge .conf 与分享链接列表"
        case .empty:
            return "订阅内容为空"
        }
    }
}

public enum SubscriptionDocument {
    public static func parse(_ raw: String) throws -> SubscriptionContents {
        let text = decodeBase64Envelope(raw)
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SubscriptionError.empty
        }
        if ClashSubscription.looksLikeClash(text) { return try parseClash(text) }
        if looksLikeSurge(text) { return try parseSurge(text) }
        if ShareLinkSubscription.looksLikeShareLinks(text) { return try parseShareLinks(text) }
        throw SubscriptionError.unrecognizedFormat
    }

    /// Many providers base64 the whole body. Decoding is attempted only when the
    /// payload is plausibly base64 *and* the result looks like a config, so a
    /// config that merely happens to be base64-shaped is never mangled.
    static func decodeBase64Envelope(_ raw: String) -> String {
        let condensed = raw.components(separatedBy: .whitespacesAndNewlines).joined()
        guard condensed.count >= 32 else { return raw }
        let allowed = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
        guard condensed.unicodeScalars.allSatisfy(allowed.contains) else { return raw }
        // Tolerate URL-safe alphabets and missing padding.
        var normalized = condensed.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while normalized.count % 4 != 0 { normalized.append("=") }
        guard let data = Data(base64Encoded: normalized),
              let decoded = String(data: data, encoding: .utf8) else { return raw }
        // Share-link lists are almost always delivered wrapped this way, so
        // they have to count as "looks like a config" here; otherwise the
        // decoded body is thrown away and the format is never recognised.
        guard ClashSubscription.looksLikeClash(decoded) || looksLikeSurge(decoded)
                || ShareLinkSubscription.looksLikeShareLinks(decoded) else {
            return raw
        }
        return decoded
    }

    static func looksLikeSurge(_ text: String) -> Bool {
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.lowercased() == "[proxy]" || line.lowercased() == "[proxy group]" {
                return true
            }
        }
        return false
    }

    /// Renders converted policies as `[Proxy]` lines.
    ///
    /// Shared by both converting formats, so a node arriving through Clash and
    /// one arriving through a share link are held to exactly the same standard.
    private static func render(_ policies: [ProxyPolicy],
                               warnings: inout [String])
        -> (lines: [String], names: [String], nameMap: [String: String]) {
        var lines: [String] = []
        var names: [String] = []
        var nameMap: [String: String] = [:]
        var usedNames = Set<String>()
        for var policy in policies {
            let originalName = policy.name
            let baseName = sanitizeIdentifier(originalName, fallback: "节点")
            var uniqueName = baseName
            var suffix = 2
            while usedNames.contains(uniqueName) {
                uniqueName = "\(baseName) \(suffix)"
                suffix += 1
            }
            policy.name = uniqueName
            do {
                let definition = try SurgeProfileDocument.definition(for: SurgeProxyDraft(policy: policy))
                lines.append("\(policy.name) = \(definition)")
                names.append(policy.name)
                usedNames.insert(policy.name)
                nameMap[originalName] = policy.name
                nameMap[policy.name] = policy.name
            } catch {
                warnings.append("跳过节点 \(policy.name)：\(error.localizedDescription)")
            }
        }
        return (lines, names, nameMap)
    }

    private static func parseClash(_ text: String) throws -> SubscriptionContents {
        let parsed = try ClashSubscription.parse(text)
        var warnings = parsed.warnings
        let rendered = render(parsed.proxies, warnings: &warnings)
        let proxyLines = rendered.lines
        let proxyNames = rendered.names
        let proxyNameMap = rendered.nameMap
        let usable = Set(proxyNames)
        var groupNameMap: [String: String] = [:]
        var usedGroupNames = usable
        for group in parsed.groups {
            let base = sanitizeIdentifier(group.name, fallback: "策略组")
            var unique = base
            var suffix = 2
            while usedGroupNames.contains(unique) {
                unique = "\(base) \(suffix)"
                suffix += 1
            }
            usedGroupNames.insert(unique)
            groupNameMap[group.name] = unique
            groupNameMap[unique] = unique
        }
        let usableGroups = Set(groupNameMap.values)
        var groupLines: [String] = []
        var groupNames: [String] = []
        for group in parsed.groups {
            let mappedGroupName = groupNameMap[group.name] ?? sanitizeIdentifier(group.name, fallback: "策略组")
            var trimmed = group
            trimmed.name = mappedGroupName
            trimmed.members = group.members.compactMap { rawMember -> String? in
                if let mappedProxy = proxyNameMap[rawMember], usable.contains(mappedProxy) {
                    return mappedProxy
                }
                if let mappedGroup = groupNameMap[rawMember], usableGroups.contains(mappedGroup),
                   mappedGroup != mappedGroupName {
                    return mappedGroup
                }
                let sanitizedMember = sanitizeIdentifier(rawMember, fallback: "")
                if usable.contains(sanitizedMember) { return sanitizedMember }
                if usableGroups.contains(sanitizedMember), sanitizedMember != mappedGroupName {
                    return sanitizedMember
                }
                if isBuiltIn(rawMember) { return rawMember.uppercased() }
                return nil
            }
            if let rawOther = trimmed.parameters["include-other-group"], !rawOther.isEmpty {
                let mappedOthers = rawOther.split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .compactMap { other -> String? in
                        if let mapped = groupNameMap[other], mapped != mappedGroupName { return mapped }
                        let sanitizedOther = sanitizeIdentifier(other, fallback: "")
                        if usableGroups.contains(sanitizedOther), sanitizedOther != mappedGroupName {
                            return sanitizedOther
                        }
                        return nil
                    }
                if mappedOthers.isEmpty {
                    trimmed.parameters.removeValue(forKey: "include-other-group")
                } else {
                    trimmed.parameters["include-other-group"] = mappedOthers.joined(separator: ", ")
                }
            }
            let expands = trimmed.parameters["include-all-proxies"] == "true"
                || !(trimmed.parameters["include-other-group"] ?? "").isEmpty
            guard !trimmed.members.isEmpty || expands else {
                warnings.append("跳过策略组 \(trimmed.name)：成员均不可用")
                continue
            }
            do {
                let definition = try SurgeProfileDocument.definition(
                    for: SurgePolicyGroupDraft(group: trimmed))
                groupLines.append("\(trimmed.name) = \(definition)")
                groupNames.append(trimmed.name)
            } catch {
                warnings.append("跳过策略组 \(trimmed.name)：\(error.localizedDescription)")
            }
        }
        SkipCertificateWarning.append(
            names: parsed.proxies.filter(\.skipsCertificateVerification)
                .compactMap { proxyNameMap[$0.name] }
                .filter(usable.contains),
            into: &warnings)
        return SubscriptionContents(format: .clash, proxyLines: proxyLines,
                                    groupLines: groupLines, proxyNames: proxyNames,
                                    groupNames: groupNames, warnings: warnings)
    }

    /// Share-link lists carry nodes and nothing else: there is no place in the
    /// format for policy groups, so none are produced.
    private static func parseShareLinks(_ text: String) throws -> SubscriptionContents {
        let parsed = try ShareLinkSubscription.parse(text)
        var warnings = parsed.warnings
        let rendered = render(parsed.proxies, warnings: &warnings)
        let usable = Set(rendered.names)
        let proxyNameMap = rendered.nameMap
        SkipCertificateWarning.append(
            names: parsed.proxies.filter(\.skipsCertificateVerification)
                .compactMap { proxyNameMap[$0.name] }
                .filter(usable.contains),
            into: &warnings)
        return SubscriptionContents(format: .shareLinks, proxyLines: rendered.lines,
                                    proxyNames: rendered.names, warnings: warnings)
    }

    /// Surge subscriptions already speak the target syntax, so the sections are
    /// taken verbatim rather than parsed and re-rendered. That preserves every
    /// option, including ones Hajimi does not model yet.
    private static func parseSurge(_ text: String) throws -> SubscriptionContents {
        var wireGuardSections: [String: [String: String]] = [:]
        do {
            var wgSec = ""
            for raw in text.components(separatedBy: .newlines) {
                let line = raw.replacingOccurrences(of: "\r", with: "")
                    .trimmingCharacters(in: .whitespaces)
                if line.hasPrefix("[") && line.hasSuffix("]") && !line.contains("=") {
                    let inner = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                    if inner.lowercased().hasPrefix("wireguard ") {
                        wgSec = String(inner.dropFirst("wireguard ".count))
                            .trimmingCharacters(in: .whitespaces).lowercased()
                        if wireGuardSections[wgSec] == nil { wireGuardSections[wgSec] = [:] }
                    } else {
                        wgSec = ""
                    }
                    continue
                }
                guard !wgSec.isEmpty, !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";"),
                      let equal = line.firstIndex(of: "=") else { continue }
                let k = String(line[..<equal]).trimmingCharacters(in: .whitespaces).lowercased()
                let v = String(line[line.index(after: equal)...]).trimmingCharacters(in: .whitespaces)
                if !k.isEmpty, !v.isEmpty { wireGuardSections[wgSec]?[k] = v }
            }
        }
        var proxyLines: [String] = []
        var rawGroupEntries: [(name: String, rhs: String)] = []
        var usedNames = Set<String>()
        var nameMap: [String: String] = [:]
        var section = ""
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.replacingOccurrences(of: "\r", with: "")
                .trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && line.hasSuffix("]") && !line.contains("=") {
                section = line.lowercased()
                continue
            }
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";"),
                  let equal = line.firstIndex(of: "=") else { continue }
            let rawName = String(line[..<equal]).trimmingCharacters(in: .whitespaces)
            let rhs = String(line[line.index(after: equal)...]).trimmingCharacters(in: .whitespaces)
            guard !rawName.isEmpty, !rhs.isEmpty else { continue }
            let baseName = isSafeIdentifier(rawName)
                ? rawName
                : sanitizeIdentifier(rawName, fallback: section == "[proxy]" ? "节点" : "策略组")
            var uniqueName = baseName
            var suffix = 2
            while usedNames.contains(uniqueName) {
                uniqueName = "\(baseName) \(suffix)"
                suffix += 1
            }
            if section == "[proxy]" {
                usedNames.insert(uniqueName)
                if nameMap[rawName] == nil { nameMap[rawName] = uniqueName }
                nameMap[uniqueName] = uniqueName
                let normalizedRHS = normalizeSurgeProxyRHS(rhs, proxyName: rawName, wireGuardSections: wireGuardSections)
                proxyLines.append("\(uniqueName) = \(normalizedRHS)")
            } else if section == "[proxy group]" {
                usedNames.insert(uniqueName)
                if nameMap[rawName] == nil { nameMap[rawName] = uniqueName }
                nameMap[uniqueName] = uniqueName
                rawGroupEntries.append((name: uniqueName, rhs: rhs))
            }
        }
        let groupLines = rawGroupEntries.map { entry -> String in
            let parts = entry.rhs.split(separator: ",", omittingEmptySubsequences: false)
                .map { String($0).trimmingCharacters(in: .whitespaces) }
            guard parts.count > 1 else { return "\(entry.name) = \(entry.rhs)" }
            var remapped = [parts[0]]
            for token in parts.dropFirst() {
                if token.contains("=") {
                    remapped.append(token)
                } else if let mapped = nameMap[token] {
                    remapped.append(mapped)
                } else {
                    remapped.append(token)
                }
            }
            return "\(entry.name) = \(remapped.joined(separator: ", "))"
        }
        guard !proxyLines.isEmpty || !groupLines.isEmpty else {
            throw SubscriptionError.unrecognizedFormat
        }
        let proxyNames = proxyLines.compactMap(name(ofDefinition:))
        var warnings: [String] = []
        SkipCertificateWarning.append(
            names: proxyLines.compactMap { line in
                guard SkipCertificateWarning.lineDisablesVerification(line) else { return nil }
                return name(ofDefinition: line)
            },
            into: &warnings)
        return SubscriptionContents(format: .surge, proxyLines: proxyLines,
                                    groupLines: groupLines,
                                    proxyNames: proxyNames,
                                    groupNames: groupLines.compactMap(name(ofDefinition:)),
                                    warnings: warnings)
    }

    /// Normalizes imported Surge `[Proxy]` definitions so legacy SSH lines such
    /// as `ssh, host, user, port, password=...` or SSH lines without explicit
    /// `host-key` / `skip-cert-verify` can be imported and activated cleanly.
    private static func splitRespectingQuotes(_ text: String) -> [String] {
        var result: [String] = []
        var current = ""
        var inQuotes = false
        var parenDepth = 0
        for ch in text {
            if ch == "\"" {
                inQuotes.toggle()
                current.append(ch)
            } else if !inQuotes && ch == "(" {
                parenDepth += 1
                current.append(ch)
            } else if !inQuotes && ch == ")" && parenDepth > 0 {
                parenDepth -= 1
                current.append(ch)
            } else if !inQuotes && parenDepth == 0 && ch == "," {
                result.append(current.trimmingCharacters(in: .whitespaces))
                current = ""
            } else {
                current.append(ch)
            }
        }
        let tail = current.trimmingCharacters(in: .whitespaces)
        if !tail.isEmpty || text.hasSuffix(",") {
            result.append(tail)
        }
        return result
    }

    private static func normalizeSurgeProxyRHS(
        _ rhs: String,
        proxyName: String = "",
        wireGuardSections: [String: [String: String]] = [:]
    ) -> String {
        let parts = splitRespectingQuotes(rhs)
        guard let first = parts.first?.lowercased() else { return rhs }
        if first == "wireguard" {
            let hasHostPort = parts.count >= 3 && !parts[1].contains("=") && UInt16(parts[2]) != nil
            if !hasHostPort {
                var inlineParams: [String: String] = [:]
                var inlineOrder: [String] = []
                for token in parts.dropFirst() {
                    guard let eq = token.firstIndex(of: "=") else { continue }
                    let k = String(token[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                    let v = String(token[token.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                    if !k.isEmpty {
                        if inlineParams[k] == nil { inlineOrder.append(k) }
                        inlineParams[k] = v
                    }
                }
                let secKey = (inlineParams["section-name"] ?? proxyName)
                    .trimmingCharacters(in: .whitespaces).lowercased()
                let wgSec = wireGuardSections[secKey] ?? [:]
                var peerValues: [String: String] = [:]
                if var rawPeer = wgSec["peer"] ?? inlineParams["peer"] {
                    rawPeer = rawPeer.trimmingCharacters(in: .whitespaces)
                    if rawPeer.hasPrefix("("), rawPeer.hasSuffix(")") {
                        rawPeer = String(rawPeer.dropFirst().dropLast())
                    }
                    for field in splitRespectingQuotes(rawPeer) {
                        guard let eq = field.firstIndex(of: "=") else { continue }
                        let pk = String(field[..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
                        var pv = String(field[field.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                        if pv.count >= 2, pv.hasPrefix("\""), pv.hasSuffix("\"") {
                            pv = String(pv.dropFirst().dropLast())
                        }
                        peerValues[pk] = pv
                    }
                }
                let endpoint = peerValues["endpoint"] ?? inlineParams["endpoint"] ?? ""
                if let colon = endpoint.lastIndex(of: ":"),
                   let port = UInt16(endpoint[endpoint.index(after: colon)...].trimmingCharacters(in: .whitespaces)),
                   port > 0 {
                    var host = String(endpoint[..<colon]).trimmingCharacters(in: .whitespaces)
                    if host.hasPrefix("["), host.hasSuffix("]") {
                        host = String(host.dropFirst().dropLast())
                    }
                    var outFields = ["wireguard", host, String(port)]
                    if let priv = inlineParams["private-key"] ?? wgSec["private-key"], !priv.isEmpty {
                        outFields.append("private-key=\(priv)")
                    }
                    if let ip = inlineParams["ip"] ?? inlineParams["self-ip"] ?? wgSec["self-ip"] ?? wgSec["ip"], !ip.isEmpty {
                        outFields.append("ip=\(ip)")
                    }
                    if let ipv6 = inlineParams["ipv6"] ?? inlineParams["self-ip-v6"] ?? wgSec["self-ip-v6"], !ipv6.isEmpty {
                        outFields.append("ipv6=\(ipv6)")
                    }
                    if let pub = inlineParams["public-key"] ?? peerValues["public-key"], !pub.isEmpty {
                        outFields.append("public-key=\(pub)")
                    }
                    if let psk = inlineParams["pre-shared-key"] ?? inlineParams["preshared-key"]
                        ?? peerValues["pre-shared-key"] ?? peerValues["preshared-key"], !psk.isEmpty {
                        outFields.append("pre-shared-key=\(psk)")
                    }
                    if let allowed = inlineParams["allowed-ips"] ?? peerValues["allowed-ips"], !allowed.isEmpty {
                        let normalizedAllowed = allowed
                            .replacingOccurrences(of: "\"", with: "")
                            .split(separator: ",")
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                            .filter { !$0.isEmpty }
                            .joined(separator: ";")
                        if !normalizedAllowed.isEmpty {
                            outFields.append("allowed-ips=\(normalizedAllowed)")
                        }
                    }
                    if let mtu = inlineParams["mtu"] ?? wgSec["mtu"], !mtu.isEmpty {
                        outFields.append("mtu=\(mtu)")
                    }
                    if let ka = inlineParams["keepalive"] ?? inlineParams["persistent-keepalive"] ?? peerValues["keepalive"], !ka.isEmpty {
                        outFields.append("persistent-keepalive=\(ka)")
                    }
                    if let res = inlineParams["reserved"] ?? peerValues["reserved"], !res.isEmpty {
                        outFields.append("reserved=\(res)")
                    }
                    let handled: Set<String> = [
                        "section-name", "peer", "endpoint", "private-key", "ip", "self-ip",
                        "ipv6", "self-ip-v6", "public-key", "pre-shared-key", "preshared-key",
                        "allowed-ips", "mtu", "keepalive", "persistent-keepalive", "reserved"
                    ]
                    for k in inlineOrder where !handled.contains(k) {
                        if let v = inlineParams[k], !v.isEmpty {
                            outFields.append("\(k)=\(v)")
                        }
                    }
                    if inlineParams["udp"] == nil {
                        outFields.append("udp=true")
                    }
                    return outFields.joined(separator: ", ")
                }
            }
            return rhs
        }
        guard first == "ssh", parts.count >= 3 else {
            return rhs
        }
        var fields = parts
        if fields.count >= 4, UInt16(fields[2]) == nil, !fields[2].contains("="),
           let port = UInt16(fields[3]), port > 0 {
            let user = fields[2]
            fields[2] = String(port)
            fields[3] = "username=\(user)"
        }
        return fields.joined(separator: ", ")
    }

    static func name(ofDefinition line: String) -> String? {
        guard let equal = line.firstIndex(of: "=") else { return nil }
        let name = line[..<equal].trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? nil : name
    }

    /// Sanitizes any node or policy group name so that special characters
    /// (such as `[92ms]`, `(HK)`, emoji, `|`, `:`, `/`, `-`, `+`, `&`, etc.)
    /// are preserved, while characters that would break out of a Surge INI
    /// assignment or section header (`\n`, `\r`, `\0`, `=`, `#`, `;`, or an
    /// entire `[...]` wrapper) are safely converted instead of dropping the node.
    static func sanitizeIdentifier(_ raw: String, fallback: String) -> String {
        var output = ""
        for character in raw {
            switch character {
            case "\n", "\r", "\0":
                output.append(" ")
            case "=":
                output.append("＝")
            case "#":
                output.append("＃")
            case ";":
                output.append("；")
            case ",":
                output.append("，")
            case "\"":
                output.append("＂")
            case "'":
                output.append("＇")
            case "\\":
                output.append("＼")
            default:
                if character.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) {
                    continue
                }
                output.append(character)
            }
        }
        let hadLineBreak = raw.contains("\n") || raw.contains("\r")
        var trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        if hadLineBreak {
            trimmed = trimmed.replacingOccurrences(of: "[", with: "【")
                .replacingOccurrences(of: "]", with: "】")
        }
        while trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
            let inner = String(trimmed.dropFirst().dropLast())
            if !inner.contains("[") && !inner.contains("]") {
                trimmed = "【" + inner + "】"
            } else {
                trimmed = trimmed.replacingOccurrences(of: "[", with: "【")
                    .replacingOccurrences(of: "]", with: "】")
            }
        }
        if trimmed.isEmpty { trimmed = fallback }
        if trimmed.count > 255 {
            trimmed = String(trimmed.prefix(255)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return trimmed.isEmpty ? fallback : trimmed
    }

    /// Rejects identifiers that could break out of the line or the section
    /// they are written into.
    ///
    /// Subscription content is attacker-controlled, and YAML's `\n` escape
    /// turns into a real newline during unquoting, so a proxy or group name is
    /// a line-injection vector into the user's profile.
    static func isSafeIdentifier(_ name: String) -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 255 else { return false }
        guard !(trimmed.hasPrefix("[") && trimmed.hasSuffix("]")) else { return false }
        return !trimmed.contains(where: {
            $0 == "\n" || $0 == "\r" || $0 == "\0"
                || $0 == "=" || $0 == "#" || $0 == ";"
                || $0 == "," || $0 == "\"" || $0 == "'" || $0 == "\\"
        })
    }

    private static func isBuiltIn(_ name: String) -> Bool {
        guard isSafeIdentifier(name) else { return false }
        let upper = name.uppercased()
        return ["DIRECT", "REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"].contains(upper)
    }
}

// MARK: - Merging into a profile

/// Splices subscription output into a profile between marker comments.
///
/// The markers are what make updating non-destructive: a refresh replaces
/// exactly the region it wrote last time, so hand-written nodes, rules,
/// comments and unknown sections in the same file are never touched. Surge
/// treats `#` lines as comments, so a profile carrying them stays valid
/// everywhere else.
public enum SubscriptionMerge {
    static let beginPrefix = "#!hajimi-subscription-begin "
    static let endPrefix = "#!hajimi-subscription-end "

    public static func sanitize(name: String) -> String {
        name.components(separatedBy: .newlines).joined(separator: " ")
            .trimmingCharacters(in: .whitespaces)
    }

    public static func apply(_ contents: SubscriptionContents, name rawName: String,
                             to profileText: String) -> String {
        let name = sanitize(name: rawName)
        guard !name.isEmpty else { return profileText }
        var lines = remove(name: name, from: profileText)
            .components(separatedBy: .newlines)
        if !contents.proxyLines.isEmpty {
            insert(block(name: name, lines: contents.proxyLines),
                   intoSection: "[proxy]", of: &lines)
        }
        if !contents.groupLines.isEmpty {
            insert(block(name: name, lines: contents.groupLines),
                   intoSection: "[proxy group]", of: &lines)
        }
        return lines.joined(separator: "\n")
    }

    public static func remove(name rawName: String, from profileText: String) -> String {
        let name = sanitize(name: rawName)
        var output: [String] = []
        var skipping = false
        for line in profileText.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == beginPrefix + name { skipping = true; continue }
            if trimmed == endPrefix + name { skipping = false; continue }
            if !skipping { output.append(line) }
        }
        return output.joined(separator: "\n")
    }

    public static func managedNames(in profileText: String) -> [String] {
        guard profileText.contains(beginPrefix) else { return [] }
        var names: [String] = []
        var searchRange = profileText.startIndex..<profileText.endIndex
        while let match = profileText.range(of: beginPrefix, range: searchRange) {
            let after = match.upperBound
            let lineEnd = profileText[after...].firstIndex(where: { $0 == "\n" || $0 == "\r" }) ?? profileText.endIndex
            let name = profileText[after..<lineEnd].trimmingCharacters(in: .whitespaces)
            if !name.isEmpty, !names.contains(name) { names.append(name) }
            searchRange = lineEnd..<profileText.endIndex
        }
        return names
    }

    public static func renameManagedBlock(from rawOldName: String, to rawNewName: String,
                                          in profileText: String) -> String {
        let oldName = sanitize(name: rawOldName)
        let newName = sanitize(name: rawNewName)
        guard !oldName.isEmpty, !newName.isEmpty, oldName != newName else { return profileText }
        return profileText.components(separatedBy: .newlines).map { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == beginPrefix + oldName { return beginPrefix + newName }
            if trimmed == endPrefix + oldName { return endPrefix + newName }
            return line
        }.joined(separator: "\n")
    }

    /// Replaces `[Proxy]` and `[Proxy Group]` exclusively with the selected
    /// subscription's definitions so nodes and policy groups from previous
    /// subscriptions or leftover unbracketed imports never mix together.
    public static func replaceExclusively(_ contents: SubscriptionContents, name rawName: String,
                                          in profileText: String) -> String {
        let name = sanitize(name: rawName)
        guard !name.isEmpty else { return profileText }
        var effectiveContents = contents
        if effectiveContents.groupLines.isEmpty, !effectiveContents.proxyLines.isEmpty {
            effectiveContents.groupLines = ["Proxy = select, DIRECT, include-all-proxies=true"]
            effectiveContents.groupNames = ["Proxy"]
        }
        let cleaned = stripAllProxiesAndGroups(from: profileText)
        let merged = apply(effectiveContents, name: name, to: cleaned)
        return reconcileDanglingRulePolicies(in: merged, contents: effectiveContents)
    }

    private static func stripAllProxiesAndGroups(from profileText: String) -> String {
        var output: [String] = []
        var section = ""
        var skippingManaged = false
        for line in profileText.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix(beginPrefix) {
                skippingManaged = true
                continue
            }
            if trimmed.hasPrefix(endPrefix) {
                skippingManaged = false
                continue
            }
            if skippingManaged { continue }
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]"), !trimmed.contains("=") {
                section = String(trimmed.dropFirst().dropLast())
                    .trimmingCharacters(in: .whitespaces).lowercased()
                if section.hasPrefix("wireguard ") { continue }
                output.append(line)
                continue
            }
            if section.hasPrefix("wireguard ") { continue }
            if section == "proxy" || section == "proxy group" {
                if !trimmed.isEmpty, !trimmed.hasPrefix("#"), !trimmed.hasPrefix(";"),
                   trimmed.contains("=") {
                    continue
                }
            }
            output.append(line)
        }
        return output.joined(separator: "\n")
    }

    public static func reconcileDanglingRulePolicies(
        in profileText: String,
        contents: SubscriptionContents = SubscriptionContents(format: .surge)
    ) -> String {
        guard let parsed = try? ProfileParser.parse(profileText) else { return profileText }
        let availableGroups = Set(contents.groupNames)
        let availableProxies = Set(contents.proxyNames)
        let fallbackPolicy = contents.groupNames.first
            ?? parsed.groupOrder.first
            ?? contents.proxyNames.first
            ?? parsed.proxyOrder.first
            ?? "DIRECT"
        let validPolicies = availableGroups.union(availableProxies)
            .union(parsed.groups.keys).union(parsed.proxies.keys)
            .union(["DIRECT", "REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"])
        let danglingPolicies = Set(parsed.rules.map(\.policy).filter { policy in
            !validPolicies.contains(policy) && !policy.uppercased().hasPrefix("REJECT")
                && policy.uppercased() != "DIRECT"
        })
        guard !danglingPolicies.isEmpty else { return profileText }
        var document = SurgeProfileDocument(profileText)
        document.replaceRulePolicies(from: danglingPolicies, to: fallbackPolicy)
        return document.text
    }

    private static func block(name: String, lines: [String]) -> [String] {
        [beginPrefix + name] + lines + [endPrefix + name]
    }

    /// Appends to an existing section, creating it at the end of the file when
    /// the profile does not have one yet.
    private static func insert(_ block: [String], intoSection header: String,
                               of lines: inout [String]) {
        var sectionStart: Int?
        var sectionEnd = lines.count
        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("["), trimmed.hasSuffix("]"), !trimmed.contains("=") else { continue }
            if trimmed.lowercased() == header {
                sectionStart = index
                sectionEnd = lines.count
            } else if sectionStart != nil, index > sectionStart! {
                sectionEnd = index
                break
            }
        }
        guard let start = sectionStart else {
            if let last = lines.last, !last.trimmingCharacters(in: .whitespaces).isEmpty {
                lines.append("")
            }
            lines.append(header == "[proxy]" ? "[Proxy]" : "[Proxy Group]")
            lines.append(contentsOf: block)
            return
        }
        // Insert after the section's last non-blank line so trailing blank
        // separators stay between sections rather than inside one.
        var insertion = sectionEnd
        while insertion > start + 1,
              lines[insertion - 1].trimmingCharacters(in: .whitespaces).isEmpty {
            insertion -= 1
        }
        lines.insert(contentsOf: block, at: insertion)
    }
}

// MARK: - Self-test

public enum SubscriptionSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "订阅自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try yamlParsing()
        try clashConversion()
        try surgeExtraction()
        try base64Envelope()
        try renderedProfileReparses()
        try shareLinks()
        try merging()
        try rejectsHostileContent()
    }

    /// Regression tests for defects an adversarial review found in this code.
    /// Each one was reachable from a subscription body, which is entirely
    /// attacker-controlled.
    private static func rejectsHostileContent() throws {
        // A member name carrying a real newline used to be written verbatim
        // into the profile, closing [Proxy Group] and letting the attacker open
        // [General] to expose the listener on the LAN.
        let injection = """
        proxies:
          - name: A
            type: ss
            server: a.example.com
            port: 8388
            cipher: aes-128-gcm
            password: pw
        proxy-groups:
          - name: G
            type: select
            proxies: ["A", "REJECT\\n[General]\\nhttp-listen = 0.0.0.0:7162"]
        """
        let contents = try SubscriptionDocument.parse(injection)
        let rendered = (contents.proxyLines + contents.groupLines).joined(separator: "\n")
        try expect(!rendered.contains("[General]"), "订阅内容注入了新的配置段落")
        try expect(!rendered.contains("http-listen"), "订阅内容注入了监听地址")
        for line in contents.proxyLines + contents.groupLines {
            try expect(!line.contains("\n") && !line.contains("\r"),
                       "渲染出的行含换行：\(line)")
        }
        // Applying it must not change where the engine listens.
        let merged = SubscriptionMerge.apply(contents, name: "hostile",
                                             to: "[Proxy]\n[Proxy Group]\n[Rule]\nFINAL,DIRECT\n")
        let profile = try ProfileParser.parse(merged)
        try expect(profile.httpListen.host == "127.0.0.1",
                   "恶意订阅改写了 HTTP 监听地址：\(profile.httpListen)")

        // Each layer is pinned on its own, because with all three in place a
        // whole-file mutation of any single one still gets caught by the next.
        // Layer 2: the serializer must refuse a member carrying a line break
        // even if such a name somehow reaches it.
        do {
            _ = try SurgeProfileDocument.definition(for: SurgePolicyGroupDraft(
                name: "G", kind: .select, members: ["A", "REJECT\n[General]"]))
            throw Failure(text: "序列化器接受了含换行的成员名")
        } catch is SurgeProfileDocumentError {}
        // Layer 3: a parameter value carrying a line break is rejected outright
        // — stricter than quoting, and already the behaviour before this fix.
        do {
            _ = try SurgeProfileDocument.definition(for: SurgeProxyDraft(
                name: "N", type: "ss", host: "a.example.com", port: 8388,
                parameters: ["cipher": "aes-128-gcm", "password": "a\nb"]))
            throw Failure(text: "序列化器接受了含换行的参数值")
        } catch is SurgeProfileDocumentError {}
        // Nothing the serializer does emit may contain a bare line break.
        let emitted = try SurgeProfileDocument.definition(for: SurgeProxyDraft(
            name: "N", type: "ss", host: "a.example.com", port: 8388,
            parameters: ["cipher": "aes-128-gcm", "password": "p,w#d"]))
        try expect(!emitted.contains("\n"), "序列化输出含裸换行：\(emitted)")

        try expect(!SubscriptionDocument.isSafeIdentifier("a\nb"), "含换行的名称未被拒绝")
        try expect(!SubscriptionDocument.isSafeIdentifier("a=b"), "含等号的名称未被拒绝")
        try expect(!SubscriptionDocument.isSafeIdentifier("[General]"), "整段方括号包裹的名称未被拒绝")
        try expect(SubscriptionDocument.isSafeIdentifier("🇯🇵 JP 官方优选[92ms 45.69Mbps]"), "含方括号标签的名称被误拒")
        try expect(SubscriptionDocument.isSafeIdentifier("[VIP] HK 01"), "前缀方括号的名称被误拒")
        try expect(SubscriptionDocument.isSafeIdentifier("HK 01"), "正常名称被误拒")
        try expect(SubscriptionDocument.sanitizeIdentifier("[General]", fallback: "节点") == "【General】",
                   "整段方括号名称未转换为全角方括号")
        try expect(SubscriptionDocument.sanitizeIdentifier("[VIP] 🇭🇰 HK [92ms]", fallback: "节点") == "【VIP】 🇭🇰 HK 【92ms】",
                   "首尾多段方括号名称未成对转换为全角方括号")
        try expect(SubscriptionDocument.sanitizeIdentifier("A=1#2;3,4\"5'6\\7", fallback: "节点") == "A＝1＃2；3，4＂5＇6＼7",
                   "特殊分隔字符未安全转换")

        // Deep nesting must produce an error rather than overflowing the stack.
        let deepFlow = "proxies:\na: " + String(repeating: "[", count: 5000)
        do {
            _ = try YAMLSubset.parse(deepFlow)
            throw Failure(text: "超深流式嵌套未被拒绝")
        } catch let error as YAMLError {
            try expect(error == .tooDeep, "超深嵌套的错误类型不对：\(error)")
        }
        var deepBlock = "proxies:\n"
        for level in 0..<5000 { deepBlock += String(repeating: " ", count: level) + "- \n" }
        do {
            _ = try YAMLSubset.parse(deepBlock)
            throw Failure(text: "超深块序列未被拒绝")
        } catch let error as YAMLError {
            try expect(error == .tooDeep, "超深块序列的错误类型不对：\(error)")
        }
        // Ordinary nesting depth must still parse.
        try expect(try YAMLSubset.parse(clashSample)["proxies"]?.array.count == 4,
                   "正常嵌套被深度限制误伤")
    }

    /// Updating must replace only what a previous update wrote. Everything else
    /// in the profile — hand-written nodes, rules, comments, unknown sections —
    /// has to survive untouched, including across repeated refreshes.
    private static func merging() throws {
        let original = """
        [General]
        loglevel = notify

        [Proxy]
        # my own node
        Home = ss, home.example.com, 8388, encrypt-method=aes-128-gcm, password=pw

        [Proxy Group]
        Manual = select, Home, DIRECT

        [Rule]
        DOMAIN-SUFFIX,example.com,Manual
        FINAL,DIRECT
        """
        let first = SubscriptionContents(
            format: .clash,
            proxyLines: ["S1 = ss, s1.example.com, 8388, encrypt-method=aes-128-gcm, password=a"],
            groupLines: ["Sub = select, S1, DIRECT"],
            proxyNames: ["S1"], groupNames: ["Sub"])
        let merged = SubscriptionMerge.apply(first, name: "provider", to: original)

        try expect(SubscriptionMerge.managedNames(in: merged) == ["provider"],
                   "托管块名称记录错误")
        var profile = try ProfileParser.parse(merged)
        try expect(profile.proxies["Home"] != nil, "合并后丢失了手写节点")
        try expect(profile.proxies["S1"] != nil, "合并后没有订阅节点")
        try expect(profile.groups["Manual"] != nil, "合并后丢失了手写策略组")
        try expect(profile.groups["Sub"] != nil, "合并后没有订阅策略组")
        try expect(profile.rules.count == 2, "合并破坏了规则段")
        try expect(merged.contains("# my own node"), "合并丢失了用户注释")
        try expect(merged.contains("loglevel = notify"), "合并破坏了 General 段")

        // A refresh must replace the previous block, not stack a second copy.
        let second = SubscriptionContents(
            format: .clash,
            proxyLines: ["S2 = ss, s2.example.com, 8388, encrypt-method=aes-128-gcm, password=b"],
            groupLines: ["Sub = select, S2, DIRECT"],
            proxyNames: ["S2"], groupNames: ["Sub"])
        let refreshed = SubscriptionMerge.apply(second, name: "provider", to: merged)
        profile = try ProfileParser.parse(refreshed)
        try expect(profile.proxies["S1"] == nil, "刷新后旧节点未被移除")
        try expect(profile.proxies["S2"] != nil, "刷新后新节点缺失")
        try expect(profile.proxies["Home"] != nil, "刷新破坏了手写节点")
        try expect(SubscriptionMerge.managedNames(in: refreshed) == ["provider"],
                   "刷新后产生了重复托管块")

        // Two providers coexist and are removed independently.
        let other = SubscriptionContents(
            format: .surge,
            proxyLines: ["T1 = trojan, t1.example.com, 443, password=c"],
            proxyNames: ["T1"])
        let both = SubscriptionMerge.apply(other, name: "second", to: refreshed)
        try expect(SubscriptionMerge.managedNames(in: both).sorted() == ["provider", "second"],
                   "多订阅托管块记录错误")
        let removed = SubscriptionMerge.remove(name: "provider", from: both)
        profile = try ProfileParser.parse(removed)
        try expect(profile.proxies["S2"] == nil, "移除订阅后节点仍在")
        try expect(profile.proxies["T1"] != nil, "移除一个订阅影响了另一个")
        try expect(profile.proxies["Home"] != nil, "移除订阅破坏了手写节点")

        // A profile with no [Proxy Group] section yet must gain one.
        let bare = "[Proxy]\nHome = ss, home.example.com, 8388, "
            + "encrypt-method=aes-128-gcm, password=pw\n"
        let grown = SubscriptionMerge.apply(first, name: "provider", to: bare)
        profile = try ProfileParser.parse(grown)
        try expect(profile.groups["Sub"] != nil, "缺失的 [Proxy Group] 段未被创建")

        // Exclusive replacement must remove any other subscription's blocks and
        // any leftover unmarked proxies/groups so subscriptions never mix.
        let mixedBase = """
        [General]
        loglevel = notify

        [Proxy]
        Leftover = ss, leftover.example.com, 8388, encrypt-method=aes-128-gcm, password=pw
        #!hajimi-subscription-begin OldSub
        OldNode = ss, old.example.com, 8388, encrypt-method=aes-128-gcm, password=pw
        #!hajimi-subscription-end OldSub

        [Proxy Group]
        LeftoverGroup = select, Leftover, DIRECT
        #!hajimi-subscription-begin OldSub
        OldGroup = select, OldNode, DIRECT
        #!hajimi-subscription-end OldSub

        [Rule]
        DOMAIN-SUFFIX,example.com,OldGroup
        FINAL,LeftoverGroup
        """
        let exclusive = SubscriptionMerge.replaceExclusively(first, name: "NewSub", in: mixedBase)
        try expect(SubscriptionMerge.managedNames(in: exclusive) == ["NewSub"],
                   "独占切换后仍残留其他订阅块")
        profile = try ProfileParser.parse(exclusive)
        try expect(profile.proxyOrder == ["S1"], "独占切换后节点列表混入了其他节点：\(profile.proxyOrder)")
        try expect(profile.groupOrder == ["Sub"], "独占切换后策略组混入了其他策略组：\(profile.groupOrder)")
        try expect(profile.rules.allSatisfy { $0.policy == "Sub" }, "悬空规则策略未自动迁移到新订阅策略组")
    }

    private static let clashSample = """
    # a comment that must not be parsed
    port: 7890
    proxies:
      - name: "HK Node"
        type: ss
        server: hk.example.com
        port: 8388
        cipher: aes-128-gcm
        password: "p#ss:word"
        udp: true
      - name: JP
        type: vmess
        server: jp.example.com
        port: 443
        uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
        cipher: auto
        tls: true
        servername: jp.example.com
        network: ws
        ws-opts:
          path: /ray
          headers:
            Host: jp.example.com
      - {name: SG, type: trojan, server: sg.example.com, port: 443, password: tj, sni: sg.example.com, skip-cert-verify: true}
      - name: Broken
        type: wireguard-not-supported
        server: x.example.com
        port: 1
    proxy-groups:
      - name: Proxy
        type: select
        proxies:
          - HK Node
          - JP
          - DIRECT
      - name: Auto
        type: url-test
        proxies: [HK Node, JP, SG]
        url: http://www.gstatic.com/generate_204
        interval: 300
    """

    private static func yamlParsing() throws {
        let root = try YAMLSubset.parse(clashSample)
        try expect(root["port"]?.string == "7890", "顶层标量解析错误")
        let proxies = root["proxies"]?.array ?? []
        try expect(proxies.count == 4, "节点数量错误：\(proxies.count)")
        try expect(proxies[0]["name"]?.string == "HK Node", "带引号的名称解析错误")
        // A '#' inside a quoted value must survive comment stripping.
        try expect(proxies[0]["password"]?.string == "p#ss:word",
                   "引号内的 # 与 : 被破坏：\(proxies[0]["password"]?.string ?? "nil")")
        try expect(proxies[1]["ws-opts"]?["path"]?.string == "/ray", "嵌套映射解析错误")
        try expect(proxies[1]["ws-opts"]?["headers"]?["Host"]?.string == "jp.example.com",
                   "二级嵌套映射解析错误")
        try expect(proxies[2]["name"]?.string == "SG", "流式映射解析错误")
        try expect(proxies[2]["port"]?.string == "443", "流式映射数值解析错误")
        let groups = root["proxy-groups"]?.array ?? []
        try expect(groups.count == 2, "策略组数量错误")
        try expect(groups[0]["proxies"]?.array.compactMap(\.string) == ["HK Node", "JP", "DIRECT"],
                   "块序列成员解析错误")
        try expect(groups[1]["proxies"]?.array.compactMap(\.string) == ["HK Node", "JP", "SG"],
                   "流式序列成员解析错误")

        // A sequence sitting at the same column as its key is equally valid.
        let flush = try YAMLSubset.parse("""
        proxies:
        - name: A
          type: ss
        - name: B
          type: ss
        """)
        try expect(flush["proxies"]?.array.count == 2, "同列块序列解析错误")

        // Tabs are illegal YAML indentation and must be reported, not guessed at.
        do {
            _ = try YAMLSubset.parse("proxies:\n\t- name: A")
            throw Failure(text: "制表符缩进未被拒绝")
        } catch let error as YAMLError {
            guard case .tabIndentation = error else { throw Failure(text: "制表符错误类型不对") }
        }
    }

    private static func clashConversion() throws {
        let contents = try ClashSubscription.parse(clashSample)
        try expect(contents.proxies.count == 3,
                   "可转换节点数量错误：\(contents.proxies.count)")
        try expect(contents.warnings.contains { $0.contains("Broken") },
                   "不支持的协议未产生警告")

        let ss = contents.proxies[0]
        try expect(ss.adapterType == "ss" && ss.host == "hk.example.com" && ss.port == 8388,
                   "Shadowsocks 字段映射错误")
        try expect(ss.parameters["cipher"] == "aes-128-gcm", "cipher 映射错误")
        try expect(ss.parameters["password"] == "p#ss:word", "password 映射错误")

        let vmess = contents.proxies[1]
        try expect(vmess.adapterType == "vmess", "VMess 类型映射错误")
        try expect(vmess.parameters["alter-id"] == "0", "alterId 未映射为 alter-id")
        try expect(vmess.parameters["network"] == "ws", "network 映射错误")
        try expect(vmess.parameters["ws-path"] == "/ray", "ws-opts.path 未展平为 ws-path")
        try expect(vmess.parameters["ws-host"] == "jp.example.com",
                   "ws-opts.headers.Host 未展平为 ws-host")
        try expect(vmess.parameters["tls"] == "true", "tls 布尔映射错误")

        let trojan = contents.proxies[2]
        try expect(trojan.adapterType == "trojan" && trojan.parameters["sni"] == "sg.example.com",
                   "Trojan 字段映射错误")
        try expect(trojan.skipsCertificateVerification,
                   "Clash skip-cert-verify 未映射")

        try expect(contents.groups.count == 2, "策略组数量错误")
        try expect(contents.groups[0].kind == .select, "select 组类型错误")
        try expect(contents.groups[1].kind == .urlTest, "url-test 组类型错误")
        try expect(contents.groups[1].parameters["interval"] == "300", "组 interval 未保留")
        try expect(contents.groups[1].parameters["url"]?.isEmpty == false, "组 url 未保留")

        let includeAll = """
        proxies:
          - {name: HK, type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: pw}
          - {name: JP, type: ss, server: jp.example.com, port: 8388, cipher: aes-128-gcm, password: pw}
        proxy-groups:
          - name: All
            type: select
            include-all: true
          - name: Combined
            type: select
            include-other-group: [All]
        """
        let expanded = try ClashSubscription.parse(includeAll)
        try expect(expanded.groups.count == 2, "include-all 空成员组被丢掉")
        try expect(expanded.groups[0].parameters["include-all-proxies"] == "true",
                   "Clash include-all 未映射")
        try expect(expanded.groups[1].parameters["include-other-group"] == "All",
                   "Clash include-other-group 未映射")
        let rendered = try SubscriptionDocument.parse(includeAll)
        try expect(rendered.groupNames == ["All", "Combined"],
                   "订阅渲染丢掉了展开组：\(rendered.groupNames)")
        let merged = SubscriptionMerge.apply(rendered, name: "provider",
                                             to: "[Proxy]\n[Proxy Group]\n[Rule]\nFINAL,DIRECT\n")
        let profile = try ProfileParser.parse(merged)
        try expect(profile.groups["All"]?.members.contains("HK") == true,
                   "include-all 未展开订阅节点")
        try expect(profile.groups["Combined"]?.members.contains("JP") == true,
                   "include-other-group 未展开订阅节点")
    }

    private static func surgeExtraction() throws {
        let surge = """
        [General]
        loglevel = notify

        [Proxy]
        # comment
        A = ss, a.example.com, 8388, encrypt-method=aes-128-gcm, password=pw
        B = trojan, b.example.com, 443, password=pw, sni=b.example.com, skip-cert-verify=true

        [Proxy Group]
        G = select, A, B, DIRECT

        [Rule]
        FINAL,DIRECT
        """
        let contents = try SubscriptionDocument.parse(surge)
        try expect(contents.format == .surge, "格式识别错误")
        try expect(contents.proxyNames == ["A", "B"], "节点名提取错误：\(contents.proxyNames)")
        try expect(contents.groupNames == ["G"], "策略组名提取错误")
        // Rules and General must not leak into the proxy sections.
        try expect(contents.proxyLines.allSatisfy { !$0.contains("FINAL") },
                   "规则行混入了节点段")
        try expect(contents.proxyLines.allSatisfy { !$0.contains("loglevel") },
                   "General 行混入了节点段")
        try expect(contents.warnings.contains { $0.contains("跳过服务器证书验证") },
                   "Surge 订阅未提示 skip-cert-verify")
    }

    private static func base64Envelope() throws {
        let surge = """
        [Proxy]
        A = ss, a.example.com, 8388, encrypt-method=aes-128-gcm, password=pw
        """
        let encoded = Data(surge.utf8).base64EncodedString()
        let contents = try SubscriptionDocument.parse(encoded)
        try expect(contents.proxyNames == ["A"], "base64 包装未被解开")

        // Content that merely looks base64-ish must be left alone.
        let plain = "[Proxy]\nAAAABBBBCCCCDDDDEEEEFFFFGGGG = ss, a.example.com, 8388, "
            + "encrypt-method=aes-128-gcm, password=pw"
        try expect(SubscriptionDocument.decodeBase64Envelope(plain) == plain,
                   "非 base64 内容被错误解码")

        // Random base64 that does not decode to a config must not be accepted.
        let noise = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 7) }).base64EncodedString()
        try expect(SubscriptionDocument.decodeBase64Envelope(noise) == noise,
                   "无意义 base64 被当作配置解码")
    }

    /// Share links are what providers actually hand out, and the format with the
    /// least agreement between clients. Every case here is a layout seen in the
    /// wild rather than one this parser invented.
    private static func shareLinks() throws {
        let ss = "ss://" + Data("aes-128-gcm:p#ss:word".utf8).base64EncodedString()
            + "@hk.example.com:8388#HK%20Node"
        let vmessJSON = """
        {"v":"2","ps":"JP","add":"jp.example.com","port":443,
         "id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"scy":"auto",
         "net":"ws","type":"none","host":"jp.example.com","path":"/ray","tls":"tls"}
        """
        let vmess = "vmess://" + Data(vmessJSON.utf8).base64EncodedString()
        let trojan = "trojan://tj@sg.example.com:443?sni=sg.example.com&type=grpc"
            + "&serviceName=youtube.com&allowInsecure=1#SG"
        let vless = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@kcp.example.com:443"
            + "?encryption=none&security=tls&sni=kcp.example.com&type=kcp"
            + "&headerType=dtls&seed=s3cret#KCP"
        let list = [ss, vmess, trojan, vless].joined(separator: "\n")

        // Providers almost always base64 the whole body.
        let contents = try SubscriptionDocument.parse(Data(list.utf8).base64EncodedString())
        try expect(contents.format == .shareLinks, "分享链接格式识别错误")
        try expect(contents.proxyNames == ["HK Node", "JP", "SG", "KCP"],
                   "节点名提取错误：\(contents.proxyNames)")
        try expect(contents.groupLines.isEmpty, "分享链接列表不应产生策略组")
        // The plain form must work too; only the wrapping differs.
        try expect(try SubscriptionDocument.parse(list).proxyNames.count == 4,
                   "未经 base64 包装的列表解析失败")

        let text = "[Proxy]\n" + contents.proxyLines.joined(separator: "\n")
            + "\n\n[Rule]\nFINAL,DIRECT\n"
        let profile = try ProfileParser.parse(text)

        guard let hk = profile.proxies["HK Node"] else { throw Failure(text: "HK Node 缺失") }
        try expect(hk.adapterType == "ss" && hk.parameters["cipher"] == "aes-128-gcm",
                   "ss 链接字段映射错误")
        // The password contains a colon; only the first one separates it from
        // the method.
        try expect(hk.parameters["password"] == "p#ss:word",
                   "ss 密码切分错误：\(hk.parameters["password"] ?? "nil")")

        guard let jp = profile.proxies["JP"] else { throw Failure(text: "JP 缺失") }
        try expect(jp.adapterType == "vmess" && jp.port == 443, "vmess 基本字段映射错误")
        try expect(jp.parameters["ws-path"] == "/ray", "vmess ws-path 映射错误")
        try expect(jp.parameters["ws-host"] == "jp.example.com", "vmess ws-host 映射错误")
        // `host` doubles as the certificate name when `sni` is absent.
        try expect(jp.parameters["servername"] == "jp.example.com", "vmess SNI 回退错误")
        try expect(jp.parameters["tls"] == "true", "vmess tls 映射错误")

        guard let sg = profile.proxies["SG"] else { throw Failure(text: "SG 缺失") }
        try expect(sg.parameters["network"] == "grpc"
                    && sg.parameters["grpc-service-name"] == "youtube.com",
                   "trojan gRPC 参数映射错误")
        try expect(sg.skipsCertificateVerification, "分享链接 allowInsecure 未映射")
        try expect(contents.warnings.contains { $0.contains("跳过服务器证书验证") },
                   "分享链接订阅未提示 skip-cert-verify")

        guard let kcp = profile.proxies["KCP"] else { throw Failure(text: "KCP 缺失") }
        try expect(kcp.parameters["network"] == "kcp"
                    && kcp.parameters["kcp-header"] == "dtls"
                    && kcp.parameters["kcp-seed"] == "s3cret",
                   "vless mKCP 参数映射错误")

        let sudokuLink = "sudoku://eyJoIjoiMjAzLjAuMTEzLjEwIiwicCI6NTg3OTcsImsiOiJlNzFkYzk2MjI4ZmQwZGI4ZWRiY2Y1YTM0YTM2Mjc1NjZlZGM1NjdkZWQ0YTJhNWExMGNhOTNlNTI2MGE1ODAzMzVlMDRiZDMxYThjZDg4MWY4NjQ5NjBmM2M4ZjE0N2Q0MzBlMzQ2ODUzMWQwMTkxNTMwYWM2MGM2ZjJmZWIwOCIsImEiOiJ1cF9hc2NpaV9kb3duX2VudHJvcHkiLCJlIjoiY2hhY2hhMjAtcG9seTEzMDUiLCJtIjoxMDIzMywieCI6dHJ1ZSwidCI6Inh2eHZwcHZ2IiwiaGQiOnRydWUsImhtIjoiYXV0byIsImh4Ijoib24iLCJoeSI6ImhhamltaXBhdGgifQ#AWS-Sudoku"
        let sudokuParsed = try ShareLinkSubscription.parse(sudokuLink)
        guard let sudokuPolicy = sudokuParsed.proxies.first else {
            throw Failure(text: "sudoku Base64 JSON 链接解析失败")
        }
        try expect(sudokuPolicy.host == "203.0.113.10" && sudokuPolicy.port == 58797,
                   "sudoku 链接地址或端口映射错误")
        try expect(sudokuPolicy.parameters["table-type"] == "up_ascii_down_entropy"
                    && sudokuPolicy.parameters["aead-method"] == "chacha20-poly1305"
                    && sudokuPolicy.parameters["custom-table"] == "xvxvppvv"
                    && sudokuPolicy.parameters["enable-pure-downlink"] == "false"
                    && sudokuPolicy.parameters["disable-http-mask"] == "true"
                    && sudokuPolicy.parameters["http-mask-mode"] == "auto"
                    && sudokuPolicy.parameters["multiplex"] == "on"
                    && sudokuPolicy.parameters["path-root"] == "hajimipath",
                   "sudoku 链接参数映射错误：\(sudokuPolicy.parameters)")

        // A carrier that is not implemented must be skipped with a reason
        // rather than silently downgraded to plain TCP.
        let h2JSON = """
        {"v":"2","ps":"H2","add":"h2.example.com","port":443,
         "id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"h2","tls":"tls"}
        """
        let mixed = ss + "\nvmess://" + Data(h2JSON.utf8).base64EncodedString() + "\nnot-a-link"
        let partial = try SubscriptionDocument.parse(mixed)
        try expect(partial.proxyNames == ["HK Node"], "不可转换的链接未被跳过")
        try expect(partial.warnings.count == 2, "被跳过的链接未逐条给出原因")

        // Duplicate labels are the norm in provider lists and must not collapse
        // into one node. The fragment is attacker-controlled, so a name that
        // carries a separator must not break the line it is written into.
        let hostile = ss + "\n" + ss
            + "\ntrojan://tj@x.example.com:443#A%3DB%0A%5BGeneral%5D%0Ahttp-listen%20%3D%200.0.0.0%3A7162"
        let merged = try SubscriptionDocument.parse(hostile)
        try expect(merged.proxyNames.count == 3, "重名节点被合并或丢弃")
        try expect(Set(merged.proxyNames).count == 3, "重名节点未被区分")
        for line in merged.proxyLines {
            try expect(!line.contains("\n") && !line.contains("\r"),
                       "渲染出的行含换行：\(line)")
            try expect(!line.contains("[General]"), "分享链接名称注入了配置段落")
        }
        let appliedProfile = try ProfileParser.parse(SubscriptionMerge.apply(
            merged, name: "links", to: "[Proxy]\n[Rule]\nFINAL,DIRECT\n"))
        try expect(appliedProfile.httpListen.host == "127.0.0.1",
                   "恶意分享链接改写了 HTTP 监听地址：\(appliedProfile.httpListen)")
    }

    /// The strongest check available without a server: render the converted
    /// Clash nodes as Surge lines, feed them back through the real profile
    /// parser, and confirm the policies survive the round trip.
    private static func renderedProfileReparses() throws {
        let contents = try SubscriptionDocument.parse(clashSample)
        try expect(contents.format == .clash, "格式识别错误")
        try expect(contents.proxyLines.count == 3, "渲染出的节点行数错误")
        try expect(contents.warnings.contains { $0.contains("跳过服务器证书验证") },
                   "Clash 订阅未提示 skip-cert-verify")

        var text = "[Proxy]\n" + contents.proxyLines.joined(separator: "\n") + "\n"
        text += "\n[Proxy Group]\n" + contents.groupLines.joined(separator: "\n") + "\n"
        text += "\n[Rule]\nFINAL,DIRECT\n"

        let profile = try ProfileParser.parse(text)
        try expect(profile.proxies["HK Node"] != nil, "重解析后丢失了 HK Node")
        try expect(profile.proxies["JP"] != nil, "重解析后丢失了 JP")
        try expect(profile.proxies["SG"] != nil, "重解析后丢失了 SG")

        guard let jp = profile.proxies["JP"] else { throw Failure(text: "JP 缺失") }
        try expect(jp.adapterType == "vmess", "重解析后 VMess 类型错误")
        try expect(jp.parameters["ws-path"] == "/ray", "重解析后 ws-path 丢失")
        try expect(jp.parameters["ws-host"] == "jp.example.com", "重解析后 ws-host 丢失")

        guard let hk = profile.proxies["HK Node"] else { throw Failure(text: "HK Node 缺失") }
        // A password containing '#' and ':' must survive quoting through the
        // renderer and the parser.
        try expect(hk.parameters["password"] == "p#ss:word",
                   "含特殊字符的密码未经完整往返：\(hk.parameters["password"] ?? "nil")")

        guard let auto = profile.groups["Auto"] else { throw Failure(text: "Auto 组缺失") }
        try expect(auto.kind == .urlTest, "重解析后 url-test 类型错误")
        try expect(auto.members == ["HK Node", "JP", "SG"], "重解析后组成员错误：\(auto.members)")
        try expect(auto.parameters["interval"] == "300", "重解析后组 interval 丢失")

        guard let select = profile.groups["Proxy"] else { throw Failure(text: "Proxy 组缺失") }
        try expect(select.members.contains("DIRECT"), "内建成员 DIRECT 被误删")

        let specialClash = """
        proxies:
          - {name: "🇯🇵 JP 官方优选[92ms 45.69Mbps]", server: 108.165.152.53, port: 8443, type: trojan, password: pw, sni: example.com}
          - {name: "[VIP] 🇭🇰 HK (IPLC) | x1.5 = #1;2,3\\"4'5\\\\6", server: 108.165.152.54, port: 8443, type: trojan, password: pw, sni: example.com}
          - {name: "[General]", server: 108.165.152.55, port: 8443, type: trojan, password: pw, sni: example.com}
        proxy-groups:
          - name: 🚀 手动切换[优选]
            type: select
            proxies:
              - 🇯🇵 JP 官方优选[92ms 45.69Mbps]
              - "[VIP] 🇭🇰 HK (IPLC) | x1.5 = #1;2,3\\"4'5\\\\6"
              - "[General]"
              - DIRECT
        """
        let specialContents = try SubscriptionDocument.parse(specialClash)
        try expect(specialContents.proxyNames.count == 3,
                   "特殊字符节点被误跳过：\(specialContents.proxyNames) warnings=\(specialContents.warnings)")
        try expect(specialContents.warnings.allSatisfy { !$0.contains("非法字符") },
                   "特殊字符节点仍产生非法字符警告：\(specialContents.warnings)")
        let specialMerged = SubscriptionMerge.replaceExclusively(
            specialContents, name: "CF订阅", in: defaultProfileText)
        let specialProfile = try ProfileParser.parse(specialMerged)
        try expect(specialProfile.proxies["🇯🇵 JP 官方优选[92ms 45.69Mbps]"] != nil,
                   "带 [92ms 45.69Mbps] 的节点重解析失败")
        try expect(specialProfile.proxies["【General】"] != nil,
                   "整段 [...] 包裹的节点未安全重命名为【General】")
        try expect(specialProfile.groups["🚀 手动切换[优选]"]?.members.count == 4,
                   "特殊字符节点未完整加入策略组：\(specialProfile.groups["🚀 手动切换[优选]"]?.members ?? [])")
    }
}

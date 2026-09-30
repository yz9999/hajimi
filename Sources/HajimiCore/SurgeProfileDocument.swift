import Foundation
import Darwin

/// An editable representation of one entry in Surge's `[Proxy]` section.
/// Values are emitted as named options so credentials containing `,`, `#`
/// or `=` can be round-tripped without changing the rest of the profile.
public struct SurgeProxyDraft: Equatable {
    public static let supportedTypes = [
        "http", "https", "socks5", "socks5-tls", "ss", "ssr", "snell",
        "vmess", "vless", "trojan", "anytls", "hysteria", "hysteria2",
        "tuic", "ssh", "wireguard"
    ]

    public var name: String
    public var type: String
    public var host: String
    public var port: UInt16
    public var parameters: [String: String]

    public init(name: String, type: String, host: String, port: UInt16,
                parameters: [String: String] = [:]) {
        self.name = name
        self.type = type
        self.host = host
        self.port = port
        self.parameters = parameters
    }

    public init(policy: ProxyPolicy) {
        name = policy.name
        host = policy.host ?? ""
        port = policy.port ?? 0
        parameters = policy.parameters
        if let username = policy.username, parameters["username"] == nil {
            parameters["username"] = username
        }
        if let password = policy.password, parameters["password"] == nil {
            parameters["password"] = password
        }
        switch policy.kind {
        case .http:
            type = Self.isTrue(parameters["tls"]) ? "https" : "http"
            if type == "https" { parameters.removeValue(forKey: "tls") }
        case .socks5:
            type = Self.isTrue(parameters["tls"]) ? "socks5-tls" : "socks5"
            if type == "socks5-tls" { parameters.removeValue(forKey: "tls") }
        case .external, .native:
            let adapter = policy.adapterType ?? "socks5"
            if adapter == "http", Self.isTrue(parameters["tls"]) {
                type = "https"
                parameters.removeValue(forKey: "tls")
            } else if adapter == "socks5", Self.isTrue(parameters["tls"]) {
                type = "socks5-tls"
                parameters.removeValue(forKey: "tls")
            } else {
                type = adapter
            }
        case .direct: type = "direct"
        case .reject: type = "reject"
        }
    }

    private static func isTrue(_ value: String?) -> Bool {
        guard let value else { return false }
        return ["true", "yes", "on", "1"].contains(value.lowercased())
    }
}

public struct SurgePolicyGroupDraft: Equatable {
    public var name: String
    public var kind: PolicyGroupKind
    public var members: [String]
    public var parameters: [String: String]

    public init(name: String, kind: PolicyGroupKind, members: [String],
                parameters: [String: String] = [:]) {
        self.name = name
        self.kind = kind
        self.members = members
        self.parameters = parameters
    }

    public init(group: PolicyGroup) {
        name = group.name
        kind = group.kind
        members = group.members
        parameters = group.parameters
    }
}

/// A single `[Rule]` entry. Match values and policy names are decoded scalars;
/// logical match values retain their parenthesized expression. Options are
/// individual, original Surge parameter fragments (for example `no-resolve`
/// or `custom="a,b"`) so unknown options and their order can be preserved.
public struct SurgeRuleDraft: Equatable {
    public static let supportedTypes = [
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
        "IP-CIDR", "IP-CIDR6", "SRC-IP", "SRC-IP-CIDR", "SOURCE-IP-CIDR",
        "SRC-PORT", "SOURCE-PORT", "IN-PORT", "DEST-PORT", "PROTOCOL",
        "GEOIP", "IP-ASN", "PROCESS-NAME", "RULE-SET", "AND", "OR", "NOT",
        "FINAL", "MATCH"
    ]

    public var type: String
    public var value: String
    public var policy: String
    public var options: [String]

    public init(type: String, value: String, policy: String, options: [String] = []) {
        self.type = type
        self.value = value
        self.policy = policy
        self.options = options
    }
}

public enum SurgeProfileDocumentError: LocalizedError, Equatable {
    case invalidName(String)
    case invalidType(String)
    case invalidHost
    case invalidPort
    case invalidParameter(String)
    case duplicateProxy(String)
    case proxyNotFound(String)
    case duplicateGroup(String)
    case groupNotFound(String)
    case invalidGroup(String)
    case invalidRule(String)
    case ruleNotFound(Int)
    case duplicateFinalRule

    public var errorDescription: String? {
        switch self {
        case .invalidName(let reason): return "节点名称无效：\(reason)"
        case .invalidType(let value): return "不支持的节点协议：\(value)"
        case .invalidHost: return "服务器地址不能为空，且不能包含换行"
        case .invalidPort: return "服务器端口必须为 1…65535"
        case .invalidParameter(let value): return "无效的节点参数：\(value)"
        case .duplicateProxy(let name): return "已经存在名为“\(name)”的节点"
        case .proxyNotFound(let name): return "在 [Proxy] 中找不到节点“\(name)”"
        case .duplicateGroup(let name): return "已经存在名为“\(name)”的策略组"
        case .groupNotFound(let name): return "在 [Proxy Group] 中找不到策略组“\(name)”"
        case .invalidGroup(let reason): return "策略组无效：\(reason)"
        case .invalidRule(let reason): return "规则无效：\(reason)"
        case .ruleNotFound(let line): return "第 \(line) 行不是 [Rule] 中可编辑的规则，请刷新后重试"
        case .duplicateFinalRule: return "已经存在 FINAL / MATCH 兜底规则，请更新原有规则，或先删除它"
        }
    }
}

/// Makes targeted edits to a Surge profile instead of serializing `Profile`
/// wholesale. Comments, unknown sections, WireGuard sections and original
/// ordering therefore remain intact.
public struct SurgeProfileDocument: Equatable {
    public private(set) var text: String

    public init(_ text: String) { self.text = text }

    public func containsProxy(named name: String) -> Bool {
        var buffer = LineBuffer(text)
        return buffer.proxyLine(named: name) != nil
    }

    public func containsGroup(named name: String) -> Bool {
        var buffer = LineBuffer(text)
        return buffer.groupLine(named: name) != nil
    }

    /// Reads an actual rule by its one-based physical source line. Headers,
    /// comments, unsupported rules and entries in other sections are rejected.
    public func ruleDraft(atSourceLine sourceLine: Int) throws -> SurgeRuleDraft {
        try RuleTextBuffer(text).rule(atSourceLine: sourceLine).draft
    }

    /// New ordinary rules precede the first catch-all by default. A catch-all
    /// is always appended to the last rule section, and cannot be duplicated.
    /// The returned line is the new rule's one-based physical source line.
    @discardableResult
    public mutating func insertRule(_ draft: SurgeRuleDraft,
                                    beforeSourceLine: Int? = nil) throws -> Int {
        let rule = try validatedSurgeRule(draft)
        var buffer = RuleTextBuffer(text)
        let finals = buffer.finalRuleIndices
        if rule.isFinal, !finals.isEmpty { throw SurgeProfileDocumentError.duplicateFinalRule }

        let insertion: Int
        if let beforeSourceLine {
            let target = try buffer.rule(atSourceLine: beforeSourceLine)
            guard !rule.isFinal else {
                throw SurgeProfileDocumentError.invalidRule("FINAL / MATCH 兜底规则只能添加到规则末尾")
            }
            guard finals.first.map({ target.index <= $0 }) ?? true else {
                throw SurgeProfileDocumentError.invalidRule("不能插入到 FINAL / MATCH 之后；该规则将无法命中")
            }
            insertion = target.index
        } else if !rule.isFinal, let final = finals.first {
            insertion = final
        } else if let tail = buffer.ruleSectionTail {
            insertion = tail
        } else {
            buffer.appendRuleSection()
            insertion = buffer.lines.count
        }
        buffer.insert(rule.definition, at: insertion)
        text = buffer.rendered
        return insertion + 1
    }

    /// Replaces only the selected rule. Unchanged fields, all untouched
    /// options, indentation, inline comments and line endings stay intact.
    public mutating func updateRule(atSourceLine sourceLine: Int,
                                    draft: SurgeRuleDraft) throws {
        var buffer = RuleTextBuffer(text)
        let original = try buffer.rule(atSourceLine: sourceLine)
        let replacement = try validatedSurgeRule(draft)
        if replacement.isFinal,
           buffer.finalRuleIndices.contains(where: { $0 != original.index }) {
            throw SurgeProfileDocumentError.duplicateFinalRule
        }
        let updated = try original.replacing(with: replacement)
        let needsMove = replacement.isFinal && buffer.ruleIndices.contains(where: { $0 > original.index })
        if needsMove {
            buffer.remove(at: original.index)
            buffer.insert(updated, at: buffer.ruleSectionTail ?? buffer.lines.count)
        } else {
            buffer.lines[original.index].body = updated
        }
        text = buffer.rendered
    }

    /// Validates every selected line before removing any of them. Only rule
    /// definitions are removed; section headers and comment lines are safe.
    public mutating func deleteRules(atSourceLines sourceLines: Set<Int>) throws {
        guard !sourceLines.isEmpty else { return }
        var buffer = RuleTextBuffer(text)
        let indices = try sourceLines.sorted().map { try buffer.rule(atSourceLine: $0).index }
        for index in indices.reversed() { buffer.remove(at: index) }
        text = buffer.rendered
    }

    /// Changes only the policy token of all selected rules, atomically.
    public mutating func setRulePolicies(atSourceLines sourceLines: Set<Int>,
                                         policy: String) throws {
        guard !sourceLines.isEmpty else { return }
        var buffer = RuleTextBuffer(text)
        var replacements: [(Int, String)] = []
        for sourceLine in sourceLines.sorted() {
            let original = try buffer.rule(atSourceLine: sourceLine)
            var draft = original.draft
            draft.policy = policy
            let validated = try validatedSurgeRule(draft)
            replacements.append((original.index, try original.replacing(with: validated)))
        }
        for (index, line) in replacements { buffer.lines[index].body = line }
        text = buffer.rendered
    }

    /// Returns a complete, validated Surge rule definition (without comment).
    public static func definition(for draft: SurgeRuleDraft) throws -> String {
        try validatedSurgeRule(draft).definition
    }

    /// Adds a new proxy or replaces an existing `[Proxy]` entry. When the
    /// name changes, group members, rule policies and dialer references are
    /// updated at the same time.
    public mutating func upsertProxy(originalName: String?, draft: SurgeProxyDraft) throws {
        let definition = try Self.definition(for: draft)
        var buffer = LineBuffer(text)

        if let originalName {
            guard let index = buffer.proxyLine(named: originalName) else {
                throw SurgeProfileDocumentError.proxyNotFound(originalName)
            }
            if originalName != draft.name, buffer.proxyLine(named: draft.name) != nil {
                throw SurgeProfileDocumentError.duplicateProxy(draft.name)
            }
            buffer.replaceDefinition(at: index, name: draft.name, definition: definition)
            if originalName != draft.name {
                buffer.replacePolicyReferences(from: originalName, to: draft.name)
            }
        } else {
            guard buffer.proxyLine(named: draft.name) == nil else {
                throw SurgeProfileDocumentError.duplicateProxy(draft.name)
            }
            buffer.insertProxy(name: draft.name, definition: definition)
        }
        text = buffer.rendered
    }

    /// Removes a proxy, removes it from policy groups, and redirects rules
    /// and `underlying-proxy` references to `replacement`.
    public mutating func deleteProxy(named name: String, replacement: String = "DIRECT") throws {
        var buffer = LineBuffer(text)
        guard let index = buffer.proxyLine(named: name) else {
            throw SurgeProfileDocumentError.proxyNotFound(name)
        }
        buffer.lines.remove(at: index)
        buffer.removeGroupMember(name)
        buffer.replaceRulePolicies(from: name, to: replacement)
        buffer.replaceDialerReferences(from: name, to: replacement)
        text = buffer.rendered
    }

    public mutating func upsertGroup(originalName: String?, draft: SurgePolicyGroupDraft) throws {
        let definition = try Self.definition(for: draft)
        var buffer = LineBuffer(text)
        if let originalName {
            guard let index = buffer.groupLine(named: originalName) else {
                throw SurgeProfileDocumentError.groupNotFound(originalName)
            }
            if originalName != draft.name, buffer.groupLine(named: draft.name) != nil {
                throw SurgeProfileDocumentError.duplicateGroup(draft.name)
            }
            buffer.replaceDefinition(at: index, name: draft.name, definition: definition)
            if originalName != draft.name {
                buffer.replaceGroupMembers(from: originalName, to: draft.name)
                buffer.replaceRulePolicies(from: originalName, to: draft.name)
            }
        } else {
            guard buffer.groupLine(named: draft.name) == nil else {
                throw SurgeProfileDocumentError.duplicateGroup(draft.name)
            }
            buffer.insertGroup(name: draft.name, definition: definition)
        }
        text = buffer.rendered
    }

    public mutating func deleteGroup(named name: String, replacement: String = "DIRECT") throws {
        var buffer = LineBuffer(text)
        guard let index = buffer.groupLine(named: name) else {
            throw SurgeProfileDocumentError.groupNotFound(name)
        }
        buffer.lines.remove(at: index)
        buffer.removeGroupMember(name)
        buffer.replaceRulePolicies(from: name, to: replacement)
        text = buffer.rendered
    }

    /// Updates one `[General]` assignment without reserializing the profile.
    /// A nil/empty value removes the option. Comments and unrelated settings
    /// remain byte-for-byte intact.
    public mutating func setGeneralOption(_ rawName: String, value: String?) throws {
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !name.isEmpty,
              name.unicodeScalars.allSatisfy({
                  CharacterSet.alphanumerics.contains($0) || "-_".unicodeScalars.contains($0)
              }), value?.contains("\n") != true, value?.contains("\r") != true else {
            throw SurgeProfileDocumentError.invalidParameter(rawName)
        }
        var buffer = LineBuffer(text)
        buffer.setGeneralOption(name, value: value?.trimmingCharacters(in: .whitespacesAndNewlines))
        text = buffer.rendered
    }

    /// Returns a complete Surge proxy definition (without `name =`).
    public static func definition(for draft: SurgeProxyDraft) throws -> String {
        let name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw SurgeProfileDocumentError.invalidName("不能为空") }
        guard !name.contains("="), !name.contains("#"), !name.contains("\n"), !name.contains("\r") else {
            throw SurgeProfileDocumentError.invalidName("不能包含 =、# 或换行")
        }
        let type = canonicalType(draft.type)
        guard SurgeProxyDraft.supportedTypes.contains(type) else {
            throw SurgeProfileDocumentError.invalidType(draft.type)
        }
        let host = draft.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, !host.contains("\n"), !host.contains("\r") else {
            throw SurgeProfileDocumentError.invalidHost
        }
        guard draft.port > 0 else { throw SurgeProfileDocumentError.invalidPort }

        var parameters: [String: String] = [:]
        for (rawKey, value) in draft.parameters {
            let key = rawKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !key.isEmpty,
                  key.unicodeScalars.allSatisfy({
                      CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0)
                  }),
                  !value.contains("\n"), !value.contains("\r") else {
                throw SurgeProfileDocumentError.invalidParameter(rawKey)
            }
            parameters[key] = value
        }

        var fields = [csvScalar(type), csvScalar(host), String(draft.port)]
        let order = orderedParameterKeys(type: type, keys: Set(parameters.keys))
        for key in order {
            guard let value = parameters[key] else { continue }
            fields.append("\(key)=\(csvScalar(value, forceQuoteWhenEmpty: true))")
        }
        return fields.joined(separator: ", ")
    }

    public static func definition(for draft: SurgePolicyGroupDraft) throws -> String {
        let name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !name.contains("="), !name.contains("#"),
              !name.contains("\n"), !name.contains("\r") else {
            throw SurgeProfileDocumentError.invalidGroup("名称不能为空，且不能包含 =、# 或换行")
        }
        let type: String
        switch draft.kind {
        case .select: type = "select"
        case .loadBalance: type = "load-balance"
        case .urlTest: type = "url-test"
        case .fallback: type = "fallback"
        case .smart: type = "smart"
        case .subnet: type = "subnet"
        }
        let members = draft.members.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        // Member names were the one identifier that reached the profile
        // unchecked. A name carrying a newline closes the [Proxy Group] section
        // and lets whatever follows become a new section — a subscription could
        // append [General] and expose the listener on the LAN.
        for member in members {
            guard !member.contains("\n"), !member.contains("\r"),
                  !member.contains("="), !member.contains("#") else {
                throw SurgeProfileDocumentError.invalidGroup("成员名 \(member) 含非法字符")
            }
        }
        var fields = [type]
        let expands = ["true", "yes", "on", "1"]
            .contains((draft.parameters["include-all-proxies"] ?? "").lowercased())
            || !(draft.parameters["include-other-group"] ?? "").isEmpty
        if members.isEmpty && !expands {
            fields.append("DIRECT")
        } else {
            fields.append(contentsOf: members.map { csvScalar($0) })
        }
        for key in draft.parameters.keys.sorted() {
            let normalized = key.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !normalized.isEmpty,
                  normalized.unicodeScalars.allSatisfy({
                      CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0)
                  }), let value = draft.parameters[key], !value.contains("\n"), !value.contains("\r") else {
                throw SurgeProfileDocumentError.invalidGroup("参数 \(key) 无效")
            }
            fields.append("\(normalized)=\(csvScalar(value, forceQuoteWhenEmpty: true))")
        }
        return fields.joined(separator: ", ")
    }

    private static func canonicalType(_ raw: String) -> String {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch value.replacingOccurrences(of: "-", with: "") {
        case "shadowsocks": return "ss"
        case "shadowsocksr": return "ssr"
        case "hy", "hysteria1": return "hysteria"
        case "hy2": return "hysteria2"
        case "socks5tls": return "socks5-tls"
        default: return value
        }
    }

    private static func orderedParameterKeys(type: String, keys: Set<String>) -> [String] {
        let required: [String]
        switch type {
        case "http", "https", "socks5", "socks5-tls": required = ["username", "password"]
        case "ss": required = ["cipher", "password"]
        case "ssr": required = ["cipher", "password", "protocol", "obfs"]
        case "snell": required = ["psk", "version"]
        case "vmess", "vless": required = ["uuid"]
        case "trojan", "anytls", "hysteria2": required = ["password"]
        case "hysteria": required = ["auth", "auth-str", "up", "up-speed", "down", "down-speed"]
        case "tuic": required = ["token", "uuid", "password"]
        case "ssh": required = ["username", "password", "private-key"]
        case "wireguard": required = ["private-key", "ip", "ipv6", "public-key"]
        default: required = []
        }
        let common = [
            "tls", "sni", "servername", "skip-cert-verify", "udp", "udp-relay",
            "network", "ws", "ws-path", "ws-host", "ws-headers", "grpc-service-name",
            "xhttp-path", "xhttp-host", "xhttp-mode", "xhttp-padding-bytes",
            "kcp-header", "kcp-header-domain", "kcp-seed", "kcp-mtu", "kcp-tti",
            "kcp-congestion", "kcp-uplink-capacity", "kcp-downlink-capacity",
            "flow", "security", "client-fingerprint", "reality-public-key", "reality-short-id",
            "underlying-proxy", "dialer-proxy"
        ]
        var result: [String] = []
        for key in required + common where keys.contains(key) && !result.contains(key) {
            result.append(key)
        }
        result.append(contentsOf: keys.subtracting(result).sorted())
        return result
    }

    private static func csvScalar(_ value: String, forceQuoteWhenEmpty: Bool = false) -> String {
        let needsQuotes = (forceQuoteWhenEmpty && value.isEmpty) ||
            value.isEmpty || value != value.trimmingCharacters(in: .whitespaces) ||
            value.contains(",") || value.contains("#") || value.contains("\"") ||
            // `.whitespaces` excludes newlines, so they have to be named
            // explicitly or a value carrying one escapes its own line.
            value.contains("\n") || value.contains("\r") ||
            value.contains("'") || value.contains("\\")
        guard needsQuotes else { return value }
        var escaped = ""
        for character in value {
            if character == "\\" || character == "\"" { escaped.append("\\") }
            escaped.append(character)
        }
        return "\"\(escaped)\""
    }
}

private struct ValidatedSurgeRule {
    var draft: SurgeRuleDraft
    var kind: RuleKind
    var definition: String
    var isFinal: Bool { draft.type == "FINAL" || draft.type == "MATCH" }
}

private func validatedSurgeRule(_ input: SurgeRuleDraft) throws -> ValidatedSurgeRule {
    let fields = [input.type, input.value, input.policy] + input.options
    guard input.options.count <= 256,
          fields.allSatisfy({ $0.utf8.count <= 65_536 && safeRuleField($0) }) else {
        throw SurgeProfileDocumentError.invalidRule("不能包含换行、控制字符，或过长的字段")
    }
    let type = input.type.trimmingCharacters(in: .whitespaces).uppercased()
    guard SurgeRuleDraft.supportedTypes.contains(type) else {
        throw SurgeProfileDocumentError.invalidRule("不支持的规则类型 \(input.type)")
    }
    let value = input.value.trimmingCharacters(in: .whitespaces)
    let policy = input.policy.trimmingCharacters(in: .whitespaces)
    guard !policy.isEmpty else { throw SurgeProfileDocumentError.invalidRule("策略不能为空") }
    let options = try input.options.map(validatedRuleOption)
    let isFinal = type == "FINAL" || type == "MATCH"
    let kind: RuleKind
    if isFinal {
        guard value.isEmpty else {
            throw SurgeProfileDocumentError.invalidRule("FINAL / MATCH 不需要匹配值")
        }
        kind = .final
    } else if isLogicalRuleType(type) {
        kind = try validatedLogicalCondition(type: type, payload: value, depth: 0)
    } else {
        kind = try validatedRuleCondition(type: type, value: value, options: options)
    }
    var tokens = [type]
    if !isFinal { tokens.append(isLogicalRuleType(type) ? value : ruleCSVScalar(value)) }
    tokens.append(ruleCSVScalar(policy))
    tokens.append(contentsOf: options)
    let definition = tokens.joined(separator: ", ")
    guard definition.utf8.count <= 65_536 else {
        throw SurgeProfileDocumentError.invalidRule("单条规则过长")
    }
    try validateParsedRule(definition, kind: kind, policy: policy)
    return ValidatedSurgeRule(draft: SurgeRuleDraft(type: type, value: value, policy: policy,
                                                  options: options),
                              kind: kind, definition: definition)
}

private func safeRuleField(_ value: String) -> Bool {
    !value.unicodeScalars.contains {
        CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0)
    }
}

private func isLogicalRuleType(_ type: String) -> Bool {
    type == "AND" || type == "OR" || type == "NOT"
}

private func validatedRuleOption(_ raw: String) throws -> String {
    let value = raw.trimmingCharacters(in: .whitespaces)
    // An empty legacy field is harmless and must remain round-trippable.
    if value.isEmpty { return value }
    guard ruleLineParts(value).suffix.trimmingCharacters(in: .whitespaces).isEmpty,
          try strictRuleTokens(value, nested: false).count == 1 else {
        throw SurgeProfileDocumentError.invalidRule("每个附加参数只能包含一个字段；含逗号或 # 的值请加引号")
    }
    let scalar = decodedRuleScalar(value)
    let key = scalar.firstIndex(of: "=").map { String(scalar[..<$0]) } ?? scalar
    let normalizedKey = key.trimmingCharacters(in: .whitespaces)
    guard !normalizedKey.isEmpty,
          normalizedKey.unicodeScalars.allSatisfy({
              CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0)
          }) else {
        throw SurgeProfileDocumentError.invalidRule("附加参数名无效：\(key)")
    }
    return value
}

private func validatedRuleCondition(type: String, value: String,
                                    options: [String] = []) throws -> RuleKind {
    guard !value.isEmpty else { throw SurgeProfileDocumentError.invalidRule("\(type) 的匹配值不能为空") }
    switch type {
    case "DOMAIN": return .domain(value)
    case "DOMAIN-SUFFIX": return .domainSuffix(value)
    case "DOMAIN-KEYWORD": return .domainKeyword(value)
    case "DOMAIN-WILDCARD": return .domainWildcard(value)
    case "IP-CIDR", "IP-CIDR6":
        try validateRuleCIDR(value, family: type == "IP-CIDR6" ? AF_INET6 : AF_INET)
        return .ipCIDR(value)
    case "SRC-IP", "SRC-IP-CIDR", "SOURCE-IP-CIDR":
        try validateRuleCIDR(value, family: nil)
        return .sourceIPCIDR(value)
    case "SRC-PORT", "SOURCE-PORT": return .sourcePort(try validatedRulePort(value))
    case "IN-PORT": return .inboundPort(try validatedRulePort(value))
    case "DEST-PORT": return .destinationPort(try validatedRulePort(value))
    case "PROTOCOL": return .protocolName(value)
    case "GEOIP": return .geoIP(value)
    case "IP-ASN": return .ipASN(value)
    case "PROCESS-NAME": return .processName(value)
    case "RULE-SET":
        var interval: TimeInterval = 86_400
        for raw in options {
            let scalar = decodedRuleScalar(raw)
            guard let equal = scalar.firstIndex(of: "="),
                  scalar[..<equal].trimmingCharacters(in: .whitespaces).lowercased() == "update-interval"
            else { continue }
            let rawInterval = decodedRuleScalar(String(scalar[scalar.index(after: equal)...]))
            guard let seconds = TimeInterval(rawInterval), seconds.isFinite, seconds > 0 else {
                throw SurgeProfileDocumentError.invalidRule("update-interval 必须为大于零的秒数")
            }
            interval = max(60, seconds)
        }
        return .ruleSet(RuleSetReference(location: value, updateInterval: interval))
    default: throw SurgeProfileDocumentError.invalidRule("不支持的匹配类型 \(type)")
    }
}

private func validateRuleCIDR(_ value: String, family: Int32?) throws {
    let parts = value.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 2, isASCIIDigits(String(parts[1])), let bits = Int(parts[1]) else {
        throw SurgeProfileDocumentError.invalidRule("CIDR 应为 IP 地址/前缀长度")
    }
    let address = String(parts[0])
    var ipv4 = in_addr()
    if family != AF_INET6, bits <= 32,
       address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return }
    var ipv6 = in6_addr()
    if family != AF_INET, bits <= 128,
       address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 { return }
    throw SurgeProfileDocumentError.invalidRule("CIDR 地址或前缀长度无效：\(value)")
}

private func validatedRulePort(_ value: String) throws -> ClosedRange<UInt16> {
    let bounds = value.split(separator: "-", omittingEmptySubsequences: false).map(String.init)
    guard (1...2).contains(bounds.count), bounds.allSatisfy(isASCIIDigits),
          let first = UInt16(bounds[0]), first > 0,
          let last = UInt16(bounds.last ?? ""), last >= first else {
        throw SurgeProfileDocumentError.invalidRule("端口应为 1…65535，或按升序填写范围（如 80-443）")
    }
    return first...last
}

private func isASCIIDigits(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
}

private func validatedLogicalCondition(type: String, payload: String, depth: Int) throws -> RuleKind {
    guard depth < 32, let inner = logicalRuleInner(payload) else {
        throw SurgeProfileDocumentError.invalidRule("逻辑条件应使用 ((类型,值),…) 格式，且不能嵌套过深")
    }
    let operands = try strictRuleTokens(inner, nested: true)
    guard !operands.isEmpty, operands.count <= 256 else {
        throw SurgeProfileDocumentError.invalidRule("逻辑条件数量无效")
    }
    var children: [RuleKind] = []
    for operand in operands {
        guard let child = logicalRuleInner(operand) else {
            throw SurgeProfileDocumentError.invalidRule("每个逻辑子条件必须用括号包裹")
        }
        let fields = try strictRuleTokens(child, nested: true)
        guard fields.count == 2 else {
            throw SurgeProfileDocumentError.invalidRule("逻辑子条件只能包含类型和匹配值，不得带策略")
        }
        let childType = decodedRuleScalar(fields[0]).uppercased()
        if isLogicalRuleType(childType) {
            children.append(try validatedLogicalCondition(type: childType,
                                                           payload: fields[1].trimmingCharacters(in: .whitespaces),
                                                           depth: depth + 1))
        } else {
            guard childType != "FINAL", childType != "MATCH", childType != "RULE-SET" else {
                throw SurgeProfileDocumentError.invalidRule("\(childType) 不能作为逻辑子条件")
            }
            children.append(try validatedRuleCondition(type: childType,
                                                        value: decodedRuleScalar(fields[1])))
        }
    }
    switch type {
    case "AND": return .logicalAnd(children)
    case "OR": return .logicalOr(children)
    case "NOT":
        guard children.count == 1, let first = children.first else {
            throw SurgeProfileDocumentError.invalidRule("NOT 必须且只能包含一个子条件")
        }
        return .logicalNot(first)
    default: throw SurgeProfileDocumentError.invalidRule("不支持的逻辑类型 \(type)")
    }
}

private func logicalRuleInner(_ raw: String) -> String? {
    let value = raw.trimmingCharacters(in: .whitespaces)
    guard value.first == "(", value.last == ")" else { return nil }
    var depth = 0
    var quote: Character?
    var escaped = false
    var mayStartQuote = true
    for index in value.indices {
        let character = value[index]
        if let active = quote {
            if escaped { escaped = false }
            else if character == "\\" { escaped = true }
            else if character == active { quote = nil; mayStartQuote = false }
            continue
        }
        if (character == "\"" || character == "'") && mayStartQuote {
            quote = character
        } else if character == "(" {
            depth += 1; mayStartQuote = true
        } else if character == ")" {
            depth -= 1; mayStartQuote = false
            if depth < 0 || (depth == 0 && value.index(after: index) != value.endIndex) { return nil }
        } else if character == "," || character == "=" {
            mayStartQuote = true
        } else if !character.isWhitespace {
            mayStartQuote = false
        }
    }
    guard depth == 0, quote == nil, !escaped else { return nil }
    return String(value.dropFirst().dropLast())
}

private func parsedSingleRule(_ definition: String) throws -> RoutingRule {
    let profile: Profile
    do { profile = try ProfileParser.parse("[Rule]\n" + definition + "\n") }
    catch { throw SurgeProfileDocumentError.invalidRule(error.localizedDescription) }
    guard profile.rules.count == 1, let rule = profile.rules.first, rule.sourceLine == 2 else {
        throw SurgeProfileDocumentError.invalidRule("规则未被引擎完整识别，请检查类型和字段")
    }
    return rule
}

private func validateParsedRule(_ definition: String, kind: RuleKind, policy: String) throws {
    let rule = try parsedSingleRule(definition)
    guard rule.kind == kind, rule.policy == policy else {
        throw SurgeProfileDocumentError.invalidRule("规则解析结果与输入不一致，请检查引号、匹配条件和附加参数")
    }
}

private func decodedRuleScalar(_ raw: String) -> String {
    decodedScalar(raw).trimmingCharacters(in: .whitespaces)
}

private func ruleCSVScalar(_ value: String) -> String {
    // Logical scanners use parentheses structurally. Quote them in scalar
    // policy names as well as commas, rather than changing their meaning.
    if value.contains("(") || value.contains(")") {
        var escaped = ""
        for character in value {
            if character == "\\" || character == "\"" { escaped.append("\\") }
            escaped.append(character)
        }
        return "\"\(escaped)\""
    }
    return profileCSVScalar(value)
}

private func strictRuleTokens(_ value: String, nested: Bool) throws -> [String] {
    var result: [String] = []
    var start = value.startIndex
    var quote: Character?
    var escaped = false
    var mayStartQuote = true
    var depth = 0
    for index in value.indices {
        let character = value[index]
        if let active = quote {
            if escaped { escaped = false }
            else if character == "\\" { escaped = true }
            else if character == active { quote = nil; mayStartQuote = false }
        } else if (character == "\"" || character == "'") && mayStartQuote {
            quote = character
        } else if character == "(", nested {
            depth += 1; mayStartQuote = true
            guard depth <= 64 else { throw SurgeProfileDocumentError.invalidRule("逻辑条件嵌套过深") }
        } else if character == ")", nested {
            depth -= 1; mayStartQuote = false
            guard depth >= 0 else { throw SurgeProfileDocumentError.invalidRule("逻辑条件括号不匹配") }
        } else if character == "," {
            if depth == 0 {
                result.append(String(value[start..<index]))
                start = value.index(after: index)
            }
            // Nested operands also introduce quoted match values after commas.
            mayStartQuote = true
        } else if character == "=" {
            mayStartQuote = true
        } else if !character.isWhitespace {
            mayStartQuote = false
        }
    }
    guard quote == nil, !escaped, depth == 0 else {
        throw SurgeProfileDocumentError.invalidRule("引号或逻辑括号不匹配")
    }
    result.append(String(value[start...]))
    return result
}

/// Unlike `splitComment`, retains the exact whitespace preceding a comment.
private func ruleLineParts(_ line: String) -> (body: String, suffix: String) {
    var quote: Character?
    var escaped = false
    var mayStartQuote = true
    var commentStart = line.endIndex
    for index in line.indices {
        let character = line[index]
        if let active = quote {
            if escaped { escaped = false }
            else if character == "\\" { escaped = true }
            else if character == active { quote = nil; mayStartQuote = false }
        } else if (character == "\"" || character == "'") && mayStartQuote {
            quote = character
        } else if character == "#" {
            commentStart = index; break
        } else if character == "," || character == "=" || character == "(" {
            mayStartQuote = true
        } else if !character.isWhitespace {
            mayStartQuote = false
        }
    }
    let prefix = String(line[..<commentStart])
    let trailing = String(prefix.reversed().prefix { $0.isWhitespace }.reversed())
    return (String(prefix.dropLast(trailing.count)), trailing + String(line[commentStart...]))
}

private func ruleSectionHeader(_ line: String) -> String? {
    let trim = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "\u{feff}"))
    let body = ruleLineParts(line).body.trimmingCharacters(in: trim)
    guard body.hasPrefix("["), body.hasSuffix("]") else { return nil }
    return body.dropFirst().dropLast().trimmingCharacters(in: .whitespaces).lowercased()
}

private struct ReadSurgeRuleLine {
    var index: Int
    var draft: SurgeRuleDraft
    var tokens: [String]
    var suffix: String
    var policyIndex: Int { draft.type == "FINAL" || draft.type == "MATCH" ? 1 : 2 }

    init(_ line: String, index: Int) throws {
        let parts = ruleLineParts(line)
        let type = csvTokens(parts.body).first.map { decodedRuleScalar($0).uppercased() } ?? ""
        guard SurgeRuleDraft.supportedTypes.contains(type) else {
            throw SurgeProfileDocumentError.ruleNotFound(index + 1)
        }
        tokens = try strictRuleTokens(parts.body, nested: isLogicalRuleType(type))
        let policyIndex = type == "FINAL" || type == "MATCH" ? 1 : 2
        guard tokens.indices.contains(policyIndex) else {
            throw SurgeProfileDocumentError.invalidRule("第 \(index + 1) 行缺少匹配值或策略")
        }
        let value = policyIndex == 1 ? "" : (isLogicalRuleType(type)
            ? tokens[1].trimmingCharacters(in: .whitespaces) : decodedRuleScalar(tokens[1]))
        draft = SurgeRuleDraft(type: type, value: value, policy: decodedRuleScalar(tokens[policyIndex]),
                               options: tokens.dropFirst(policyIndex + 1).map {
                                   $0.trimmingCharacters(in: .whitespaces)
                               })
        let parsed = try parsedSingleRule(parts.body)
        guard parsed.policy == draft.policy else {
            throw SurgeProfileDocumentError.invalidRule("第 \(index + 1) 行的策略无法完整识别")
        }
        self.index = index
        suffix = parts.suffix
    }

    func replacing(with replacement: ValidatedSurgeRule) throws -> String {
        let new = replacement.draft
        var fields = [new.type == draft.type ? tokens[0] : replaceRuleToken(tokens[0], with: ruleCSVScalar(new.type))]
        if !replacement.isFinal {
            let value = isLogicalRuleType(new.type) ? new.value : ruleCSVScalar(new.value)
            if policyIndex != 1, new.value == draft.value,
               isLogicalRuleType(new.type) == isLogicalRuleType(draft.type) {
                fields.append(tokens[1])
            } else {
                fields.append(policyIndex == 1 ? " " + value : replaceRuleToken(tokens[1], with: value))
            }
        }
        fields.append(new.policy == draft.policy ? tokens[policyIndex]
            : replaceRuleToken(tokens[policyIndex], with: ruleCSVScalar(new.policy)))
        for (offset, value) in new.options.enumerated() {
            let oldIndex = policyIndex + 1 + offset
            if draft.options.indices.contains(offset), draft.options[offset] == value {
                fields.append(tokens[oldIndex])
            } else if tokens.indices.contains(oldIndex) {
                fields.append(replaceRuleToken(tokens[oldIndex], with: value))
            } else {
                fields.append(" " + value)
            }
        }
        let body = fields.joined(separator: ",")
        try validateParsedRule(body, kind: replacement.kind, policy: new.policy)
        return body + suffix
    }
}

private func replaceRuleToken(_ raw: String, with value: String) -> String {
    let leading = String(raw.prefix { $0.isWhitespace })
    let trailing = String(raw.reversed().prefix { $0.isWhitespace }.reversed())
    return leading + value + trailing
}

/// Rule-only buffer: preserve each physical line's terminator and the original
/// end-of-file convention, without changing proxy/group editor behavior.
private struct RuleTextBuffer {
    struct Line { var body: String; var ending: String }
    var lines: [Line]
    let newline: String
    let endsWithNewline: Bool

    init(_ text: String) {
        var records: [Line] = []
        var body = ""
        for character in text {
            if character.unicodeScalars.allSatisfy({ CharacterSet.newlines.contains($0) }) {
                records.append(Line(body: body, ending: String(character)))
                body = ""
            } else {
                body.append(character)
            }
        }
        if !body.isEmpty { records.append(Line(body: body, ending: "")) }
        lines = records
        newline = records.first(where: { !$0.ending.isEmpty })?.ending ?? "\n"
        endsWithNewline = records.last.map { !$0.ending.isEmpty } ?? false
    }

    var rendered: String { lines.map { $0.body + $0.ending }.joined() }

    func rule(atSourceLine sourceLine: Int) throws -> ReadSurgeRuleLine {
        // Check before subtracting: Int.min must be an ordinary error, not a trap.
        guard sourceLine > 0, sourceLine <= lines.count else {
            throw SurgeProfileDocumentError.ruleNotFound(sourceLine)
        }
        let index = sourceLine - 1
        var section = ""
        for current in 0...index {
            if let header = ruleSectionHeader(lines[current].body) { section = header }
        }
        guard section == "rule", ruleSectionHeader(lines[index].body) == nil else {
            throw SurgeProfileDocumentError.ruleNotFound(sourceLine)
        }
        return try ReadSurgeRuleLine(lines[index].body, index: index)
    }

    var ruleIndices: [Int] {
        var section = ""
        return lines.indices.filter { index in
            if let header = ruleSectionHeader(lines[index].body) { section = header; return false }
            guard section == "rule" else { return false }
            let body = ruleLineParts(lines[index].body).body
            let type = csvTokens(body).first.map { decodedRuleScalar($0).uppercased() } ?? ""
            return SurgeRuleDraft.supportedTypes.contains(type)
        }
    }

    var finalRuleIndices: [Int] {
        ruleIndices.filter { index in
            let body = ruleLineParts(lines[index].body).body
            let type = csvTokens(body).first.map { decodedRuleScalar($0).uppercased() } ?? ""
            return type == "FINAL" || type == "MATCH"
        }
    }

    var ruleSectionTail: Int? {
        var header: Int?
        var end = lines.count
        for index in lines.indices {
            guard let section = ruleSectionHeader(lines[index].body) else { continue }
            if section == "rule" { header = index; end = lines.count }
            else if header != nil, end == lines.count { end = index }
        }
        guard let header else { return nil }
        while end > header + 1, lines[end - 1].body.trimmingCharacters(in: .whitespaces).isEmpty {
            end -= 1
        }
        return end
    }

    mutating func appendRuleSection() {
        if let last = lines.last, !last.body.trimmingCharacters(in: .whitespaces).isEmpty {
            insert("", at: lines.count)
        }
        insert("[Rule]", at: lines.count)
    }

    mutating func insert(_ body: String, at index: Int) {
        if index < lines.count {
            lines.insert(Line(body: body, ending: newline), at: index)
        } else {
            if !lines.isEmpty, lines[lines.count - 1].ending.isEmpty {
                lines[lines.count - 1].ending = newline
            }
            lines.append(Line(body: body, ending: endsWithNewline ? newline : ""))
        }
    }

    mutating func remove(at index: Int) {
        let wasLast = index == lines.count - 1
        lines.remove(at: index)
        if wasLast, !endsWithNewline, !lines.isEmpty { lines[lines.count - 1].ending = "" }
    }
}

private struct LineBuffer {
    var lines: [String]
    let newline: String
    let endsWithNewline: Bool

    init(_ text: String) {
        newline = text.contains("\r\n") ? "\r\n" : "\n"
        endsWithNewline = text.hasSuffix(newline)
        lines = text.components(separatedBy: newline)
        if endsWithNewline, lines.last == "" { lines.removeLast() }
        if lines.count == 1, lines[0].isEmpty, text.isEmpty { lines.removeAll() }
    }

    var rendered: String {
        let result = lines.joined(separator: newline)
        return result + (endsWithNewline || !lines.isEmpty ? newline : "")
    }

    mutating func proxyLine(named name: String) -> Int? {
        var section = ""
        var result: Int?
        for index in lines.indices {
            if let header = sectionHeader(lines[index]) { section = header; continue }
            guard section == "proxy", let pair = assignment(lines[index]), pair.key == name else { continue }
            result = index
        }
        return result
    }

    mutating func groupLine(named name: String) -> Int? {
        var section = ""
        var result: Int?
        for index in lines.indices {
            if let header = sectionHeader(lines[index]) { section = header; continue }
            guard section == "proxy group", let pair = assignment(lines[index]), pair.key == name else { continue }
            result = index
        }
        return result
    }

    mutating func replaceDefinition(at index: Int, name: String, definition: String) {
        let line = lines[index]
        let indent = String(line.prefix { $0 == " " || $0 == "\t" })
        let comment = splitComment(line).comment
        lines[index] = indent + name + " = " + definition + (comment.map { "  " + $0 } ?? "")
    }

    mutating func insertProxy(name: String, definition: String) {
        let newLine = "\(name) = \(definition)"
        var proxyHeader: Int?
        var end: Int?
        for index in lines.indices {
            guard let header = sectionHeader(lines[index]) else { continue }
            if header == "proxy" { proxyHeader = index; end = lines.count; continue }
            if proxyHeader != nil, end == lines.count { end = index; break }
        }
        if let header = proxyHeader {
            var insertion = end ?? lines.count
            while insertion > header + 1,
                  lines[insertion - 1].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                insertion -= 1
            }
            lines.insert(newLine, at: insertion)
            return
        }

        var insertion = lines.firstIndex { line in
            guard let header = sectionHeader(line) else { return false }
            return header == "proxy group" || header == "rule"
        } ?? lines.count
        if insertion > 0,
           !lines[insertion - 1].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            lines.insert("", at: insertion)
            insertion += 1
        }
        lines.insert(contentsOf: ["[Proxy]", newLine, ""], at: insertion)
    }

    mutating func insertGroup(name: String, definition: String) {
        insertAssignment(section: "proxy group", displayName: "Proxy Group",
                         name: name, definition: definition, beforeSections: ["rule"])
    }

    mutating func setGeneralOption(_ name: String, value: String?) {
        var section = ""
        var matches: [Int] = []
        var generalHeader: Int?
        var generalEnd = lines.count
        for index in lines.indices {
            if let header = sectionHeader(lines[index]) {
                if section == "general", generalEnd == lines.count { generalEnd = index }
                section = header
                if header == "general" { generalHeader = index }
                continue
            }
            guard section == "general", let pair = assignment(lines[index]),
                  pair.key.lowercased() == name else { continue }
            matches.append(index)
        }

        guard let value, !value.isEmpty else {
            for index in matches.reversed() { lines.remove(at: index) }
            return
        }
        if let index = matches.last, let pair = assignment(lines[index]) {
            lines[index] = pair.prefix + value + (pair.comment.map { "  " + $0 } ?? "")
            for duplicate in matches.dropLast().reversed() { lines.remove(at: duplicate) }
            return
        }

        let newLine = "\(name) = \(value)"
        if let header = generalHeader {
            var insertion = generalEnd
            while insertion > header + 1,
                  lines[insertion - 1].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                insertion -= 1
            }
            lines.insert(newLine, at: insertion)
        } else {
            let prefix = lines.isEmpty ? [] : [""]
            lines.insert(contentsOf: ["[General]", newLine] + prefix, at: 0)
        }
    }

    private mutating func insertAssignment(section target: String, displayName: String,
                                           name: String, definition: String,
                                           beforeSections: Set<String>) {
        let newLine = "\(name) = \(definition)"
        var headerIndex: Int?
        var endIndex = lines.count
        for index in lines.indices {
            guard let header = sectionHeader(lines[index]) else { continue }
            if header == target { headerIndex = index; continue }
            if headerIndex != nil { endIndex = index; break }
        }
        if let headerIndex {
            var insertion = endIndex
            while insertion > headerIndex + 1,
                  lines[insertion - 1].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                insertion -= 1
            }
            lines.insert(newLine, at: insertion)
            return
        }
        var insertion = lines.firstIndex { line in
            guard let header = sectionHeader(line) else { return false }
            return beforeSections.contains(header)
        } ?? lines.count
        if insertion > 0, !lines[insertion - 1].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            lines.insert("", at: insertion); insertion += 1
        }
        lines.insert(contentsOf: ["[\(displayName)]", newLine, ""], at: insertion)
    }

    mutating func replacePolicyReferences(from old: String, to new: String) {
        replaceGroupMembers(from: old, to: new)
        replaceRulePolicies(from: old, to: new)
        replaceDialerReferences(from: old, to: new)
    }

    mutating func replaceGroupMembers(from old: String, to new: String) {
        transformSection("proxy group") { _, value in
            var tokens = csvTokens(value)
            guard tokens.count > 1 else { return nil }
            var changed = false
            for index in 1..<tokens.count where option(tokens[index]) == nil {
                if decodedScalar(tokens[index]) == old {
                    tokens[index] = replacingScalar(in: tokens[index], with: new)
                    changed = true
                }
            }
            return changed ? tokens.joined(separator: ",") : nil
        }
    }

    mutating func removeGroupMember(_ name: String) {
        transformSection("proxy group") { _, value in
            var tokens = csvTokens(value)
            guard tokens.count > 1 else { return nil }
            let originalCount = tokens.count
            tokens = tokens.enumerated().filter { index, token in
                index == 0 || option(token) != nil || decodedScalar(token) != name
            }.map(\.element)
            guard tokens.count != originalCount else { return nil }
            let memberCount = tokens.dropFirst().filter { option($0) == nil }.count
            if memberCount == 0 { tokens.insert(" DIRECT", at: 1) }
            return tokens.joined(separator: ",")
        }
    }

    mutating func replaceRulePolicies(from old: String, to new: String) {
        var section = ""
        for index in lines.indices {
            if let header = sectionHeader(lines[index]) { section = header; continue }
            guard section == "rule" else { continue }
            let parts = splitComment(lines[index])
            var tokens = csvTokens(parts.body)
            guard let type = tokens.first.map({ decodedScalar($0).uppercased() }) else { continue }
            let policyIndex = (type == "FINAL" || type == "MATCH") ? 1 : 2
            guard tokens.indices.contains(policyIndex), decodedScalar(tokens[policyIndex]) == old else { continue }
            tokens[policyIndex] = replacingScalar(in: tokens[policyIndex], with: new)
            lines[index] = tokens.joined(separator: ",") + (parts.comment.map { "  " + $0 } ?? "")
        }
    }

    mutating func replaceDialerReferences(from old: String, to new: String) {
        transformSection("proxy") { _, value in
            var tokens = csvTokens(value)
            guard tokens.count >= 4 else { return nil }
            var changed = false
            for index in 3..<tokens.count {
                guard let pair = option(tokens[index]),
                      pair.key == "underlying-proxy" || pair.key == "dialer-proxy",
                      pair.value == old else { continue }
                tokens[index] = replacingOptionValue(in: tokens[index], with: new)
                changed = true
            }
            return changed ? tokens.joined(separator: ",") : nil
        }
    }

    /// The transform receives the assignment key and RHS without an inline
    /// comment. Returning nil leaves the line byte-for-byte unchanged.
    private mutating func transformSection(_ target: String,
                                           _ transform: (String, String) -> String?) {
        var section = ""
        for index in lines.indices {
            if let header = sectionHeader(lines[index]) { section = header; continue }
            guard section == target, let pair = assignment(lines[index]),
                  let replacement = transform(pair.key, pair.value) else { continue }
            lines[index] = pair.prefix + replacement + (pair.comment.map { "  " + $0 } ?? "")
        }
    }
}

private func sectionHeader(_ line: String) -> String? {
    let body = splitComment(line).body.trimmingCharacters(in: .whitespacesAndNewlines)
    guard body.hasPrefix("["), body.hasSuffix("]") else { return nil }
    return body.dropFirst().dropLast().trimmingCharacters(in: .whitespaces).lowercased()
}

private struct Assignment {
    var key: String
    var value: String
    var prefix: String
    var comment: String?
}

private func assignment(_ line: String) -> Assignment? {
    let parts = splitComment(line)
    guard let equal = parts.body.firstIndex(of: "=") else { return nil }
    let key = parts.body[..<equal].trimmingCharacters(in: .whitespaces)
    guard !key.isEmpty else { return nil }
    let valueStart = parts.body.index(after: equal)
    let leadingValueWhitespace = parts.body[valueStart...].prefix { $0 == " " || $0 == "\t" }
    let prefix = String(parts.body[...equal]) + leadingValueWhitespace
    let actualStart = parts.body.index(valueStart, offsetBy: leadingValueWhitespace.count)
    return Assignment(key: key, value: String(parts.body[actualStart...]),
                      prefix: prefix, comment: parts.comment)
}

private func splitComment(_ line: String) -> (body: String, comment: String?) {
    var quote: Character?
    var escaped = false
    var mayStartQuote = true
    for index in line.indices {
        let character = line[index]
        if let active = quote {
            if escaped { escaped = false; continue }
            if character == "\\" { escaped = true; continue }
            if character == active { quote = nil; mayStartQuote = false }
            continue
        }
        if (character == "\"" || character == "'") && mayStartQuote {
            quote = character
        } else if character == "#" {
            return (String(line[..<index]).trimmingCharacters(in: .whitespaces), String(line[index...]))
        } else if character == "," || character == "=" {
            mayStartQuote = true
        } else if !character.isWhitespace {
            mayStartQuote = false
        }
    }
    return (line, nil)
}

private func csvTokens(_ value: String) -> [String] {
    var result: [String] = []
    var start = value.startIndex
    var quote: Character?
    var escaped = false
    var mayStartQuote = true
    var index = value.startIndex
    while index < value.endIndex {
        let character = value[index]
        if let active = quote {
            if escaped { escaped = false }
            else if character == "\\" { escaped = true }
            else if character == active { quote = nil; mayStartQuote = false }
        } else if (character == "\"" || character == "'") && mayStartQuote {
            quote = character
        } else if character == "," {
            result.append(String(value[start..<index]))
            start = value.index(after: index)
            mayStartQuote = true
        } else if character == "=" {
            mayStartQuote = true
        } else if !character.isWhitespace {
            mayStartQuote = false
        }
        index = value.index(after: index)
    }
    result.append(String(value[start...]))
    return result
}

private func decodedScalar(_ raw: String) -> String {
    var value = raw.trimmingCharacters(in: .whitespaces)
    guard value.count >= 2, let first = value.first, first == "\"" || first == "'",
          value.last == first else { return value }
    value.removeFirst(); value.removeLast()
    var result = ""
    var escaped = false
    for character in value {
        if escaped { result.append(character); escaped = false }
        else if character == "\\" { escaped = true }
        else { result.append(character) }
    }
    if escaped { result.append("\\") }
    return result
}

private func replacingScalar(in raw: String, with value: String) -> String {
    let leading = raw.prefix { $0 == " " || $0 == "\t" }
    let trailing = raw.reversed().prefix { $0 == " " || $0 == "\t" }.reversed()
    return String(leading) + profileCSVScalar(value) + String(trailing)
}

private func option(_ raw: String) -> (key: String, value: String)? {
    let trimmed = raw.trimmingCharacters(in: .whitespaces)
    guard let equal = trimmed.firstIndex(of: "=") else { return nil }
    let key = trimmed[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
    let value = decodedScalar(String(trimmed[trimmed.index(after: equal)...]))
    guard !key.isEmpty else { return nil }
    return (key, value)
}

private func replacingOptionValue(in raw: String, with value: String) -> String {
    guard let equal = raw.firstIndex(of: "=") else { return raw }
    let after = raw.index(after: equal)
    let suffix = raw[after...]
    let leading = suffix.prefix { $0 == " " || $0 == "\t" }
    let trailing = suffix.reversed().prefix { $0 == " " || $0 == "\t" }.reversed()
    return String(raw[...equal]) + String(leading) + profileCSVScalar(value) + String(trailing)
}

private func profileCSVScalar(_ value: String) -> String {
    let needsQuotes = value.isEmpty || value != value.trimmingCharacters(in: .whitespaces) ||
        value.contains(",") || value.contains("#") || value.contains("\"") ||
        value.contains("'") || value.contains("\\")
    guard needsQuotes else { return value }
    var escaped = ""
    for character in value {
        if character == "\\" || character == "\"" { escaped.append("\\") }
        escaped.append(character)
    }
    return "\"\(escaped)\""
}

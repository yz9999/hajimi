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
                               warnings: inout [String]) -> (lines: [String], names: [String]) {
        var lines: [String] = []
        var names: [String] = []
        for policy in policies {
            guard isSafeIdentifier(policy.name) else {
                warnings.append("跳过节点：名称含非法字符")
                continue
            }
            do {
                let definition = try SurgeProfileDocument.definition(for: SurgeProxyDraft(policy: policy))
                lines.append("\(policy.name) = \(definition)")
                names.append(policy.name)
            } catch {
                warnings.append("跳过节点 \(policy.name)：\(error.localizedDescription)")
            }
        }
        return (lines, names)
    }

    private static func parseClash(_ text: String) throws -> SubscriptionContents {
        let parsed = try ClashSubscription.parse(text)
        var warnings = parsed.warnings
        let rendered = render(parsed.proxies, warnings: &warnings)
        let proxyLines = rendered.lines
        let proxyNames = rendered.names
        let usable = Set(proxyNames)
        var groupLines: [String] = []
        var groupNames: [String] = []
        for group in parsed.groups {
            // A group referring to a node that failed conversion would make the
            // profile unloadable, so the dead members are dropped first.
            guard isSafeIdentifier(group.name) else {
                warnings.append("跳过策略组：名称含非法字符")
                continue
            }
            var trimmed = group
            trimmed.members = group.members.filter {
                isSafeIdentifier($0) && (usable.contains($0) || isBuiltIn($0))
            }
            let expands = trimmed.parameters["include-all-proxies"] == "true"
                || !(trimmed.parameters["include-other-group"] ?? "").isEmpty
            guard !trimmed.members.isEmpty || expands else {
                warnings.append("跳过策略组 \(group.name)：成员均不可用")
                continue
            }
            if trimmed.members.count != group.members.count {
                warnings.append("策略组 \(group.name) 已移除不可用成员")
            }
            do {
                let definition = try SurgeProfileDocument.definition(
                    for: SurgePolicyGroupDraft(group: trimmed))
                groupLines.append("\(trimmed.name) = \(definition)")
                groupNames.append(trimmed.name)
            } catch {
                warnings.append("跳过策略组 \(group.name)：\(error.localizedDescription)")
            }
        }
        SkipCertificateWarning.append(
            names: parsed.proxies.filter(\.skipsCertificateVerification).map(\.name)
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
        SkipCertificateWarning.append(
            names: parsed.proxies.filter(\.skipsCertificateVerification).map(\.name)
                .filter(usable.contains),
            into: &warnings)
        return SubscriptionContents(format: .shareLinks, proxyLines: rendered.lines,
                                    proxyNames: rendered.names, warnings: warnings)
    }

    /// Surge subscriptions already speak the target syntax, so the sections are
    /// taken verbatim rather than parsed and re-rendered. That preserves every
    /// option, including ones Hajimi does not model yet.
    private static func parseSurge(_ text: String) throws -> SubscriptionContents {
        var proxyLines: [String] = []
        var groupLines: [String] = []
        var section = ""
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && line.hasSuffix("]") {
                section = line.lowercased()
                continue
            }
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";"),
                  line.contains("="), !line.contains("\r"),
                  // A verbatim line is copied into the profile untouched, so a
                  // name that opens a bracket could start a new section.
                  SubscriptionDocument.name(ofDefinition: line)
                      .map(isSafeIdentifier) == true else { continue }
            if section == "[proxy]" { proxyLines.append(line) }
            else if section == "[proxy group]" { groupLines.append(line) }
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

    static func name(ofDefinition line: String) -> String? {
        guard let equal = line.firstIndex(of: "=") else { return nil }
        let name = line[..<equal].trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? nil : name
    }

    /// Rejects identifiers that could break out of the line or the section
    /// they are written into.
    ///
    /// Subscription content is attacker-controlled, and YAML's `\n` escape
    /// turns into a real newline during unquoting, so a proxy or group name is
    /// a line-injection vector into the user's profile.
    static func isSafeIdentifier(_ name: String) -> Bool {
        guard !name.isEmpty, name.count <= 255 else { return false }
        return !name.contains(where: { $0 == "\n" || $0 == "\r" || $0 == "\0" })
            && !name.contains("=") && !name.contains("#") && !name.contains("[")
    }

    private static func isBuiltIn(_ name: String) -> Bool {
        let upper = name.uppercased()
        return upper == "DIRECT" || upper.hasPrefix("REJECT")
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
        var names: [String] = []
        for line in profileText.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix(beginPrefix) else { continue }
            let name = String(trimmed.dropFirst(beginPrefix.count))
            if !name.isEmpty, !names.contains(name) { names.append(name) }
        }
        return names
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
            guard trimmed.hasPrefix("["), trimmed.hasSuffix("]") else { continue }
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
        try expect(!SubscriptionDocument.isSafeIdentifier("[General]"), "含方括号的名称未被拒绝")
        try expect(SubscriptionDocument.isSafeIdentifier("HK 01"), "正常名称被误拒")

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
    }
}

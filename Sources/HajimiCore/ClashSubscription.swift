import Foundation

// MARK: - Minimal YAML

/// A YAML value restricted to what Clash configurations actually contain.
///
/// Mappings keep their declared order because proxy-group membership order is
/// meaningful — `fallback` treats it as a preference list.
public indirect enum YAMLValue: Equatable {
    case scalar(String)
    case mapping([(key: String, value: YAMLValue)])
    case sequence([YAMLValue])

    public subscript(key: String) -> YAMLValue? {
        guard case .mapping(let entries) = self else { return nil }
        return entries.first { $0.key == key }?.value
    }

    public var string: String? {
        switch self {
        case .scalar(let value):
            return value
        case .sequence(let values) where values.count == 1:
            if case .scalar(let inner) = values[0] {
                return "[\(inner)]"
            }
            return nil
        default:
            return nil
        }
    }

    public var array: [YAMLValue] {
        switch self {
        case .sequence(let values): return values
        case .scalar(let value) where value.isEmpty: return []
        default: return [self]
        }
    }

    public var isEmpty: Bool {
        switch self {
        case .scalar(let value): return value.isEmpty
        case .mapping(let entries): return entries.isEmpty
        case .sequence(let values): return values.isEmpty
        }
    }

    public static func == (lhs: YAMLValue, rhs: YAMLValue) -> Bool {
        switch (lhs, rhs) {
        case (.scalar(let a), .scalar(let b)): return a == b
        case (.sequence(let a), .sequence(let b)): return a == b
        case (.mapping(let a), .mapping(let b)):
            return a.count == b.count
                && zip(a, b).allSatisfy { $0.key == $1.key && $0.value == $1.value }
        default: return false
        }
    }
}

public enum YAMLError: LocalizedError, Equatable {
    case tabIndentation(Int)
    case malformed(String)
    case tooDeep

    public var errorDescription: String? {
        switch self {
        case .tabIndentation(let line): return "第 \(line) 行使用了制表符缩进，YAML 不允许"
        case .malformed(let detail): return "YAML 结构无效：\(detail)"
        case .tooDeep: return "YAML 嵌套层级过深，疑似构造的畸形订阅内容"
        }
    }
}

/// Indentation-driven parser for the block and flow constructs Clash uses.
///
/// This is deliberately not a general YAML implementation: anchors, aliases,
/// multi-document streams, block scalars and tags are all absent from
/// subscription output, and supporting them would add far more surface than a
/// config reader needs.
public enum YAMLSubset {
    /// Both the block and the flow parsers recurse once per nesting level and
    /// run on a dispatch worker with a 512 KiB stack, so a few thousand levels
    /// overflow it. A subscription body is attacker-controlled and the overflow
    /// is a signal rather than a catchable error, so depth is bounded up front.
    static let maximumDepth = 64

    private struct Line {
        var indent: Int
        var text: String
    }

    public static func parse(_ text: String) throws -> YAMLValue {
        var lines = try tokenize(text)
        guard !lines.isEmpty else { return .mapping([]) }
        var index = 0
        let value = try parseValue(&lines, &index, minIndent: lines[0].indent, depth: 0)
        return value
    }

    private static func tokenize(_ text: String) throws -> [Line] {
        var result: [Line] = []
        for (offset, raw) in text.components(separatedBy: .newlines).enumerated() {
            let line = raw.hasSuffix("\r") ? String(raw.dropLast()) : raw
            let stripped = stripComment(line)
            let trimmed = stripped.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed == "---" || trimmed == "..." { continue }
            var indent = 0
            for character in stripped {
                if character == " " { indent += 1 }
                else if character == "\t" { throw YAMLError.tabIndentation(offset + 1) }
                else { break }
            }
            result.append(Line(indent: indent, text: trimmed))
        }
        return result
    }

    /// Removes a trailing comment while respecting quoting, so a `#` inside a
    /// password or a URL survives.
    private static func stripComment(_ line: String) -> String {
        var quote: Character?
        var escaped = false
        var previousWasSpace = true
        var output = ""
        for character in line {
            if let active = quote {
                output.append(character)
                if escaped { escaped = false }
                else if character == "\\" && active == "\"" { escaped = true }
                else if character == active { quote = nil }
                previousWasSpace = false
                continue
            }
            if character == "\"" || character == "'" {
                quote = character; output.append(character); previousWasSpace = false; continue
            }
            if character == "#" && previousWasSpace { break }
            previousWasSpace = character == " "
            output.append(character)
        }
        return output
    }

    private static func isSequenceEntry(_ text: String) -> Bool {
        text == "-" || text.hasPrefix("- ")
    }

    private static func parseValue(_ lines: inout [Line], _ index: inout Int,
                                   minIndent: Int, depth: Int) throws -> YAMLValue {
        guard depth <= maximumDepth else { throw YAMLError.tooDeep }
        guard index < lines.count, lines[index].indent >= minIndent else { return .scalar("") }
        if isSequenceEntry(lines[index].text) {
            return try parseSequence(&lines, &index, indent: lines[index].indent, depth: depth)
        }
        return try parseMapping(&lines, &index, indent: lines[index].indent, depth: depth)
    }

    /// Distinguishes a YAML flow collection (`{...}` or `[a, b]`) from an
    /// unquoted scalar that merely begins with a bracketed tag such as
    /// `[VIP] 🇭🇰 HK 01` or `[VIP] 🇭🇰 HK [92ms]`, while still routing deeply
    /// nested/unclosed `[` sequences to `parseFlow` so `maximumDepth` is enforced.
    private static func isFlowCollection(_ text: String) -> Bool {
        if text.hasPrefix("{") { return true }
        guard text.hasPrefix("[") else { return false }
        let characters = Array(text)
        return isFlowSequenceStart(characters, at: 0, requireFullSpan: true)
    }

    private static func isFlowSequenceStart(_ characters: [Character], at start: Int,
                                            requireFullSpan: Bool) -> Bool {
        guard start < characters.count, characters[start] == "[" else { return false }
        var index = start + 1
        var quote: Character?
        var escaped = false
        var depth = 1
        var sawTopLevelComma = false
        while index < characters.count {
            let character = characters[index]
            if let active = quote {
                index += 1
                if escaped { escaped = false }
                else if character == "\\" && active == "\"" { escaped = true }
                else if character == active { quote = nil }
                continue
            }
            if character == "\"" || character == "'" {
                quote = character
                index += 1
                continue
            }
            if character == "[" {
                depth += 1
                index += 1
                continue
            }
            if character == "]" {
                depth -= 1
                index += 1
                if depth == 0 {
                    while index < characters.count, characters[index] == " " { index += 1 }
                    if requireFullSpan {
                        return index == characters.count
                    }
                    guard index < characters.count else { return true }
                    let next = characters[index]
                    return next == "," || next == "]" || next == "}"
                }
                continue
            }
            if character == "," && depth == 1 {
                sawTopLevelComma = true
            }
            index += 1
        }
        return depth > 1 || sawTopLevelComma
    }

    private static func isBlockSequenceMapping(_ rest: String, lines: [Line],
                                               index: Int, indent: Int) -> Bool {
        guard let (key, value) = splitKey(rest) else { return false }
        if value.isEmpty { return true }
        if index + 1 < lines.count, lines[index + 1].indent > indent { return true }
        return key.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }
    }

    private static func parseSequence(_ lines: inout [Line], _ index: inout Int,
                                      indent: Int, depth: Int) throws -> YAMLValue {
        guard depth <= maximumDepth else { throw YAMLError.tooDeep }
        var items: [YAMLValue] = []
        while index < lines.count, lines[index].indent == indent,
              isSequenceEntry(lines[index].text) {
            let rest = lines[index].text == "-"
                ? ""
                : String(lines[index].text.dropFirst(2)).trimmingCharacters(in: .whitespaces)
            if rest.isEmpty {
                index += 1
                items.append(try parseValue(&lines, &index, minIndent: indent + 1, depth: depth + 1))
            } else if isFlowCollection(rest) {
                index += 1
                items.append(try parseFlow(rest))
            } else if isBlockSequenceMapping(rest, lines: lines, index: index, indent: indent) {
                // `- key: value` opens a mapping whose remaining keys are
                // indented to where the value started. Rewriting the line lets
                // the ordinary mapping parser take over.
                lines[index] = Line(indent: indent + 2, text: rest)
                items.append(try parseMapping(&lines, &index, indent: indent + 2, depth: depth + 1))
            } else {
                index += 1
                items.append(.scalar(unquote(rest)))
            }
        }
        return .sequence(items)
    }

    private static func parseMapping(_ lines: inout [Line], _ index: inout Int,
                                     indent: Int, depth: Int) throws -> YAMLValue {
        guard depth <= maximumDepth else { throw YAMLError.tooDeep }
        var entries: [(key: String, value: YAMLValue)] = []
        while index < lines.count, lines[index].indent == indent {
            guard let (key, rest) = splitKey(lines[index].text) else { break }
            index += 1
            if isFlowCollection(rest) {
                entries.append((key, try parseFlow(rest)))
            } else if !rest.isEmpty {
                entries.append((key, .scalar(unquote(rest))))
            } else if index < lines.count, lines[index].indent > indent {
                entries.append((key, try parseValue(&lines, &index, minIndent: lines[index].indent, depth: depth + 1)))
            } else if index < lines.count, lines[index].indent == indent,
                      isSequenceEntry(lines[index].text) {
                // A block sequence may sit at the same column as its key.
                entries.append((key, try parseSequence(&lines, &index, indent: indent, depth: depth + 1)))
            } else {
                entries.append((key, .scalar("")))
            }
        }
        return .mapping(entries)
    }

    /// Splits `key: value`, ignoring colons inside quotes and the `://` of a URL.
    private static func splitKey(_ text: String) -> (String, String)? {
        var quote: Character?
        var escaped = false
        let characters = Array(text)
        for position in characters.indices {
            let character = characters[position]
            if let active = quote {
                if escaped { escaped = false; continue }
                if character == "\\" && active == "\"" { escaped = true; continue }
                if character == active { quote = nil }
                continue
            }
            if character == "\"" || character == "'" {
                // A quote may only open a key at the very start.
                if position == 0 { quote = character; continue }
                quote = character
                continue
            }
            guard character == ":" else { continue }
            let isLast = position == characters.count - 1
            guard isLast || characters[position + 1] == " " else { continue }
            let key = String(characters[0..<position]).trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { return nil }
            let value = isLast
                ? ""
                : String(characters[(position + 1)...]).trimmingCharacters(in: .whitespaces)
            return (unquote(key), value)
        }
        return nil
    }

    private static func parseFlow(_ text: String) throws -> YAMLValue {
        var characters = Array(text)
        var position = 0
        return try parseFlowValue(&characters, &position, depth: 0)
    }

    private static func parseFlowValue(_ characters: inout [Character],
                                       _ position: inout Int, depth: Int) throws -> YAMLValue {
        guard depth <= maximumDepth else { throw YAMLError.tooDeep }
        skipSpaces(&characters, &position)
        guard position < characters.count else { return .scalar("") }
        if characters[position] == "[",
           isFlowSequenceStart(characters, at: position, requireFullSpan: false) {
            position += 1
            var items: [YAMLValue] = []
            while position < characters.count {
                skipSpaces(&characters, &position)
                if position < characters.count, characters[position] == "]" { position += 1; break }
                items.append(try parseFlowValue(&characters, &position, depth: depth + 1))
                skipSpaces(&characters, &position)
                if position < characters.count, characters[position] == "," { position += 1 }
            }
            return .sequence(items)
        }
        if characters[position] == "{" {
            position += 1
            var entries: [(key: String, value: YAMLValue)] = []
            while position < characters.count {
                skipSpaces(&characters, &position)
                if position < characters.count, characters[position] == "}" { position += 1; break }
                let key = readFlowToken(&characters, &position, terminators: [":", ",", "}"])
                skipSpaces(&characters, &position)
                if position < characters.count, characters[position] == ":" { position += 1 }
                let value = try parseFlowValue(&characters, &position, depth: depth + 1)
                entries.append((unquote(key), value))
                skipSpaces(&characters, &position)
                if position < characters.count, characters[position] == "," { position += 1 }
            }
            return .mapping(entries)
        }
        let token = readFlowToken(&characters, &position, terminators: [",", "]", "}"])
        return .scalar(unquote(token))
    }

    private static func skipSpaces(_ characters: inout [Character], _ position: inout Int) {
        while position < characters.count, characters[position] == " " { position += 1 }
    }

    private static func readFlowToken(_ characters: inout [Character], _ position: inout Int,
                                      terminators: Set<Character>) -> String {
        skipSpaces(&characters, &position)
        var output = ""
        var quote: Character?
        var escaped = false
        var bracketDepth = 0
        while position < characters.count {
            let character = characters[position]
            if let active = quote {
                output.append(character)
                position += 1
                if escaped { escaped = false }
                else if character == "\\" && active == "\"" { escaped = true }
                else if character == active { quote = nil }
                continue
            }
            if character == "\"" || character == "'" {
                quote = character; output.append(character); position += 1; continue
            }
            if character == "[" {
                bracketDepth += 1
                output.append(character)
                position += 1
                continue
            }
            if character == "]" && bracketDepth > 0 {
                bracketDepth -= 1
                output.append(character)
                position += 1
                continue
            }
            if bracketDepth == 0 && terminators.contains(character) { break }
            output.append(character)
            position += 1
        }
        return output.trimmingCharacters(in: .whitespaces)
    }

    static func unquote(_ value: String) -> String {
        guard value.count >= 2 else { return value }
        let first = value.first!, last = value.last!
        guard first == last, first == "\"" || first == "'" else { return value }
        let inner = String(value.dropFirst().dropLast())
        guard first == "\"" else { return inner.replacingOccurrences(of: "''", with: "'") }
        var output = ""
        var escaped = false
        for character in inner {
            if escaped {
                switch character {
                case "n": output.append("\n")
                case "t": output.append("\t")
                case "r": output.append("\r")
                default: output.append(character)
                }
                escaped = false
                continue
            }
            if character == "\\" { escaped = true; continue }
            output.append(character)
        }
        return output
    }
}

// MARK: - Clash conversion

public enum ClashSubscriptionError: LocalizedError, Equatable {
    case notClash
    case noProxies

    public var errorDescription: String? {
        switch self {
        case .notClash: return "该内容不是 Clash 配置（缺少 proxies 段）"
        case .noProxies: return "Clash 配置中没有可用节点"
        }
    }
}

public enum ClashSubscription {
    public struct Contents: Equatable {
        public var proxies: [ProxyPolicy]
        public var groups: [PolicyGroup]
        public var warnings: [String]
    }

    public static func looksLikeClash(_ text: String) -> Bool {
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("proxies:") || line.hasPrefix("proxy-groups:") { return true }
        }
        return false
    }

    public static func parse(_ text: String) throws -> Contents {
        let root = try YAMLSubset.parse(text)
        guard let rawProxies = root["proxies"] else { throw ClashSubscriptionError.notClash }
        var proxies: [ProxyPolicy] = []
        var warnings: [String] = []
        var seen = Set<String>()
        for entry in rawProxies.array {
            guard let name = entry["name"]?.string, !name.isEmpty else { continue }
            guard !seen.contains(name) else {
                warnings.append("节点名重复，已跳过：\(name)")
                continue
            }
            switch convert(entry, name: name) {
            case .success(let policy):
                seen.insert(name)
                proxies.append(policy)
            case .failure(let reason):
                warnings.append("跳过节点 \(name)：\(reason)")
            }
        }
        guard !proxies.isEmpty else { throw ClashSubscriptionError.noProxies }

        var groups: [PolicyGroup] = []
        for entry in (root["proxy-groups"]?.array ?? []) {
            guard let name = entry["name"]?.string, !name.isEmpty else { continue }
            guard let rawType = entry["type"]?.string else { continue }
            let kind: PolicyGroupKind
            switch rawType {
            case "select": kind = .select
            case "url-test": kind = .urlTest
            case "fallback": kind = .fallback
            case "load-balance": kind = .loadBalance
            case "smart": kind = .smart
            case "subnet": kind = .subnet
            default:
                warnings.append("跳过策略组 \(name)：暂不支持的类型 \(rawType)")
                continue
            }
            let members = (entry["proxies"]?.array ?? []).compactMap(\.string)
                .filter { !$0.isEmpty }
            var parameters: [String: String] = [:]
            if let url = entry["url"]?.string, !url.isEmpty { parameters["url"] = url }
            if let interval = entry["interval"]?.string, !interval.isEmpty {
                parameters["interval"] = interval
            }
            if let tolerance = entry["tolerance"]?.string, !tolerance.isEmpty {
                parameters["tolerance"] = tolerance
            }
            if boolean(entry["include-all"]?.string ?? "")
                || boolean(entry["include-all-proxies"]?.string ?? "")
                || boolean(entry["use-all-proxies"]?.string ?? "") {
                parameters["include-all-proxies"] = "true"
            }
            let otherGroups = (entry["include-other-group"]?.array ?? [])
                .compactMap(\.string).filter { !$0.isEmpty }
            if !otherGroups.isEmpty {
                parameters["include-other-group"] = otherGroups.joined(separator: ", ")
            }
            let expands = parameters["include-all-proxies"] == "true"
                || parameters["include-other-group"] != nil
            guard !members.isEmpty || expands else {
                warnings.append("跳过策略组 \(name)：没有成员")
                continue
            }
            groups.append(PolicyGroup(name: name, kind: kind, members: members,
                                      parameters: parameters))
        }
        return Contents(proxies: proxies, groups: groups, warnings: warnings)
    }

    private enum Conversion {
        case success(ProxyPolicy)
        case failure(String)
    }

    private static func convert(_ entry: YAMLValue, name: String) -> Conversion {
        guard let type = entry["type"]?.string?.lowercased() else {
            return .failure("缺少 type")
        }
        guard let server = entry["server"]?.string, !server.isEmpty else {
            return .failure("缺少 server")
        }
        let parsedPort: UInt16? = {
            if let rawPort = entry["port"]?.string, let p = UInt16(rawPort), p > 0 { return p }
            if let range = entry["port-range"]?.string ?? entry["ports"]?.string {
                let first = range.split(separator: ",").first.map(String.init) ?? range
                let start = first.split(separator: "-").first.map(String.init) ?? first
                if let p = UInt16(start.trimmingCharacters(in: .whitespacesAndNewlines)), p > 0 { return p }
            }
            return nil
        }()
        guard let port = parsedPort else {
            return .failure("端口无效")
        }

        var parameters: [String: String] = [:]
        func copy(_ clashKey: String, to surgeKey: String? = nil) {
            guard let value = entry[clashKey]?.string, !value.isEmpty else { return }
            parameters[surgeKey ?? clashKey] = value
        }
        func copyBool(_ clashKey: String, to surgeKey: String? = nil) {
            guard let value = entry[clashKey]?.string, !value.isEmpty else { return }
            parameters[surgeKey ?? clashKey] = boolean(value) ? "true" : "false"
        }
        /// Clash nests transport settings; Surge keeps them flat.
        func copyTransport() {
            let network = entry["network"]?.string?.lowercased() ?? "tcp"
            guard network != "tcp" else { return }
            parameters["network"] = network
            switch network {
            case "ws":
                let options = entry["ws-opts"]
                if let path = options?["path"]?.string ?? entry["ws-path"]?.string, !path.isEmpty {
                    parameters["ws-path"] = path
                }
                if let host = options?["headers"]?["Host"]?.string
                    ?? options?["headers"]?["host"]?.string, !host.isEmpty {
                    parameters["ws-host"] = host
                }
            case "grpc":
                if let name = entry["grpc-opts"]?["grpc-service-name"]?.string
                    ?? entry["grpc-opts"]?["serviceName"]?.string, !name.isEmpty {
                    parameters["grpc-service-name"] = name
                }
            case "xhttp", "splithttp":
                let options = entry["xhttp-opts"] ?? entry["splithttp-opts"]
                if let path = options?["path"]?.string, !path.isEmpty {
                    parameters["xhttp-path"] = path
                }
                if let host = options?["host"]?.string
                    ?? options?["headers"]?["Host"]?.string
                    ?? options?["headers"]?["host"]?.string, !host.isEmpty {
                    parameters["xhttp-host"] = host
                }
                // The server rejects any padding length outside this range, so
                // a node that narrows it must be carried through verbatim.
                if let padding = options?["x-padding-bytes"]?.string
                    ?? options?["xPaddingBytes"]?.string, !padding.isEmpty {
                    parameters["xhttp-padding-bytes"] = padding
                }
                if let mode = options?["mode"]?.string, !mode.isEmpty {
                    parameters["xhttp-mode"] = mode.lowercased()
                }
            default:
                break
            }
        }
        func copyReality() {
            guard let options = entry["reality-opts"] ?? entry["realityOpts"] else { return }
            if let key = options["public-key"]?.string ?? options["publicKey"]?.string,
               !key.isEmpty {
                parameters["security"] = "reality"
                parameters["tls"] = "true"
                parameters["reality-public-key"] = key
                parameters["reality-short-id"] = options["short-id"]?.string
                    ?? options["shortId"]?.string ?? ""
            }
        }

        func copyALPN() {
            guard let raw = entry["alpn"] else { return }
            let items = raw.array.compactMap { item -> String? in
                if case .scalar(let text) = item {
                    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                    return trimmed.isEmpty ? nil : trimmed
                }
                return nil
            }
            if !items.isEmpty {
                parameters["alpn"] = items.joined(separator: ",")
            }
        }

        switch type {
        case "ss", "shadowsocks":
            copy("cipher"); copy("password")
            guard parameters["cipher"] != nil, parameters["password"] != nil else {
                return .failure("Shadowsocks 缺少 cipher 或 password")
            }
            if entry["plugin"]?.string?.isEmpty == false {
                return .failure("暂不支持 plugin=\(entry["plugin"]?.string ?? "")")
            }
            copyBool("udp")
        case "ssr", "shadowsocksr":
            copy("cipher"); copy("password"); copy("protocol"); copy("obfs")
            copy("protocol-param"); copy("obfs-param")
            copyBool("udp"); copyBool("udp-relay")
        case "vmess":
            copy("uuid"); copy("alterId", to: "alter-id"); copy("cipher")
            copyBool("tls"); copy("servername")
            if parameters["servername"] == nil { copy("sni", to: "servername") }
            copy("sni"); copyALPN()
            copyBool("skip-cert-verify")
            copy("client-fingerprint"); copyReality()
            copyTransport()
        case "vless":
            copy("uuid"); copy("flow"); copyBool("tls"); copy("servername")
            if parameters["servername"] == nil { copy("sni", to: "servername") }
            copy("sni"); copyALPN()
            copyBool("skip-cert-verify"); copy("client-fingerprint")
            copyReality()
            copyTransport()
        case "trojan":
            copy("password"); copy("sni")
            if parameters["sni"] == nil { copy("servername", to: "sni") }
            copyALPN(); copyBool("skip-cert-verify")
            copy("client-fingerprint"); copyReality()
            copyTransport()
            guard parameters["password"] != nil else { return .failure("Trojan 缺少 password") }
        case "hysteria", "hysteria1":
            copy("auth-str"); copy("auth_str", to: "auth-str"); copy("auth-string", to: "auth-str")
            copy("up"); copy("down"); copy("sni"); copy("obfs"); copyALPN()
            copyBool("skip-cert-verify")
        case "hysteria2", "hy2":
            copy("password"); copy("obfs"); copy("obfs-password")
            copy("sni"); copyALPN(); copyBool("skip-cert-verify")
        case "tuic":
            copy("uuid"); copy("password"); copy("token")
            copy("congestion-controller"); copy("sni"); copyALPN(); copyBool("skip-cert-verify")
        case "snell":
            copy("psk"); copy("version")
            if let obfs = entry["obfs-opts"]?["mode"]?.string, !obfs.isEmpty {
                parameters["obfs"] = obfs
            }
        case "anytls":
            copy("password"); copy("sni"); copyBool("skip-cert-verify")
        case "sudoku":
            copy("key"); copy("password", to: "key")
            copy("aead-method"); copy("cipher", to: "aead-method")
            copy("padding-min"); copy("padding-max")
            copy("table-type"); copy("ascii", to: "table-type")
            copy("custom-table"); copyBool("enable-pure-downlink")
            copyBool("http-mask"); copyBool("disable-http-mask")
            copy("http-mask-mode"); copyBool("http-mask-tls")
            copy("http-mask-host"); copy("multiplex"); copy("http-mask-multiplex", to: "multiplex")
            copy("path-root")
            if let mask = entry["httpmask"] {
                if let dis = mask["disable"]?.string, !dis.isEmpty {
                    parameters["disable-http-mask"] = boolean(dis) ? "true" : "false"
                }
                if let mode = mask["mode"]?.string, !mode.isEmpty { parameters["http-mask-mode"] = mode }
                if let tls = mask["tls"]?.string, !tls.isEmpty {
                    parameters["http-mask-tls"] = boolean(tls) ? "true" : "false"
                }
                if let host = mask["host"]?.string, !host.isEmpty { parameters["http-mask-host"] = host }
                if let root = mask["path-root"]?.string, !root.isEmpty { parameters["path-root"] = root }
                if let mux = mask["multiplex"]?.string, !mux.isEmpty { parameters["multiplex"] = mux }
            }
            guard parameters["key"] != nil else { return .failure("Sudoku 缺少 key") }
        case "mieru":
            copy("username"); copy("password")
            copy("transport"); copy("multiplexing"); copy("handshake-mode")
            copy("port-range"); copy("mtu"); copy("traffic-pattern")
            guard parameters["username"] != nil, parameters["password"] != nil else {
                return .failure("Mieru 缺少 username 或 password")
            }
        case "trusttunnel", "trust-tunnel":
            copy("username"); copy("password")
            copy("sni"); copy("servername", to: "sni"); copy("alpn")
            copyBool("quic"); copyBool("skip-cert-verify"); copyBool("tls")
            guard parameters["username"] != nil, parameters["password"] != nil else {
                return .failure("TrustTunnel 缺少 username 或 password")
            }
        case "ssh":
            copy("username")
            if parameters["username"] == nil { copy("user", to: "username") }
            copy("password"); copy("private-key"); copy("private-key-passphrase")
            if let hkArray = entry["host-key"]?.array, !hkArray.isEmpty {
                let items = hkArray.compactMap { item -> String? in
                    if case .scalar(let s) = item {
                        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
                        return t.isEmpty ? nil : t
                    }
                    return item.string
                }.filter { !$0.isEmpty }
                if !items.isEmpty { parameters["host-key"] = items.joined(separator: "|") }
            } else {
                copy("host-key")
            }
            if let algArray = entry["host-key-algorithms"]?.array, !algArray.isEmpty {
                let items = algArray.compactMap { item -> String? in
                    if case .scalar(let s) = item {
                        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
                        return t.isEmpty ? nil : t
                    }
                    return item.string
                }.filter { !$0.isEmpty }
                if !items.isEmpty { parameters["host-key-algorithms"] = items.joined(separator: ",") }
            } else {
                copy("host-key-algorithms")
            }
            copyBool("skip-cert-verify")
            if parameters["host-key"] == nil && parameters["skip-cert-verify"] == nil {
                parameters["skip-cert-verify"] = "true"
            }
        case "socks5", "socks5-tls":
            copy("username"); copy("password")
            if type == "socks5-tls" { parameters["tls"] = "true" } else { copyBool("tls") }
            copy("sni")
            if parameters["sni"] == nil { copy("servername", to: "sni") }
            copy("servername"); copyALPN()
            copyBool("skip-cert-verify"); copyBool("skip-common-name-verify")
            copy("client-fingerprint"); copy("fingerprint")
            copyBool("udp"); copyBool("udp-relay")
            copy("underlying-proxy"); copy("dialer-proxy")
            if parameters["underlying-proxy"] != nil || parameters["dialer-proxy"] != nil {
                return .success(ProxyPolicy(name: name, kind: .external, host: server, port: port,
                                            username: entry["username"]?.string,
                                            password: entry["password"]?.string,
                                            adapterType: "socks5", parameters: parameters))
            }
            return .success(ProxyPolicy(name: name, kind: .socks5, host: server, port: port,
                                        username: entry["username"]?.string,
                                        password: entry["password"]?.string,
                                        adapterType: "socks5", parameters: parameters))
        case "http", "https":
            copy("username"); copy("password")
            if type == "https" { parameters["tls"] = "true" } else { copyBool("tls") }
            copy("sni")
            if parameters["sni"] == nil { copy("servername", to: "sni") }
            copy("servername"); copyALPN()
            copyBool("skip-cert-verify"); copyBool("skip-common-name-verify")
            copy("client-fingerprint"); copy("fingerprint")
            copy("underlying-proxy"); copy("dialer-proxy")
            if parameters["underlying-proxy"] != nil || parameters["dialer-proxy"] != nil {
                return .success(ProxyPolicy(name: name, kind: .external, host: server, port: port,
                                            username: entry["username"]?.string,
                                            password: entry["password"]?.string,
                                            adapterType: "http", parameters: parameters))
            }
            return .success(ProxyPolicy(name: name, kind: .http, host: server, port: port,
                                        username: entry["username"]?.string,
                                        password: entry["password"]?.string,
                                        adapterType: "http", parameters: parameters))
        case "wireguard":
            copy("private-key")
            copy("ip"); copy("self-ip", to: "ip")
            copy("ipv6"); copy("self-ip-v6", to: "ipv6")
            copy("public-key")
            copy("pre-shared-key"); copy("preshared-key", to: "pre-shared-key")
            copy("mtu"); copy("reserved"); copy("allowed-ips")
            copyBool("udp")
            if parameters["udp"] == nil { parameters["udp"] = "true" }
            guard parameters["private-key"] != nil,
                  parameters["ip"] != nil,
                  parameters["public-key"] != nil else {
                return .failure("WireGuard 缺少 private-key、ip 或 public-key")
            }
        default:
            return .failure("暂不支持的协议类型 \(type)")
        }
        copy("underlying-proxy")
        copy("dialer-proxy")
        copyBool("tfo")
        copyBool("fast-open", to: "tfo")
        copy("ip-version")
        copy("interface-name")
        let normalizedType: String
        switch type {
        case "shadowsocks": normalizedType = "ss"
        case "shadowsocksr": normalizedType = "ssr"
        case "hysteria1": normalizedType = "hysteria"
        case "hy2": normalizedType = "hysteria2"
        case "trust-tunnel": normalizedType = "trusttunnel"
        default: normalizedType = type
        }
        // Advanced protocols enter as `.external`; the adapter manager promotes
        // only the ones the native implementation fully covers, exactly as a
        // hand-written profile would.
        return .success(ProxyPolicy(name: name, kind: .external, host: server, port: port,
                                    adapterType: normalizedType,
                                    parameters: parameters))
    }

    private static func boolean(_ value: String) -> Bool {
        ["true", "yes", "on", "1"].contains(value.lowercased())
    }
}

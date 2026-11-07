import Foundation

public enum ShareLinkSubscriptionError: LocalizedError, Equatable {
    case notShareLinks
    case noProxies

    public var errorDescription: String? {
        switch self {
        case .notShareLinks: return "该内容不是分享链接列表"
        case .noProxies: return "分享链接列表中没有可用节点"
        }
    }
}

/// Converts the `vmess://` / `ss://` style lists most providers hand out into
/// the same `ProxyPolicy` values the Clash converter produces.
///
/// These links are not a specification. Every client invented its own encoding
/// and they disagree on nearly everything: `ss://` has two incompatible
/// layouts, `vmess://` wraps a JSON object whose numeric fields are sometimes
/// written as strings, and the VLESS/Trojan query keys were only retrofitted
/// into a common shape years later. The rule here is the one the rest of the
/// codebase follows: recognise what is actually deployed, and refuse whatever
/// cannot be recovered instead of guessing at it.
///
/// Parameter names deliberately match the Clash converter's, because a profile
/// carrying two spellings of the same setting is worse than either spelling.
public enum ShareLinkSubscription {
    public struct Contents: Equatable {
        public var proxies: [ProxyPolicy]
        public var warnings: [String]
    }

    /// Schemes this parser claims. A body made only of unknown schemes is
    /// reported as unrecognised rather than quietly producing nothing.
    static let schemes: Set<String> = [
        "ss", "ssr", "vmess", "vless", "trojan",
        "hysteria", "hysteria2", "hy2", "tuic", "anytls",
        "sudoku", "mieru", "mierus", "trusttunnel", "trust-tunnel",
    ]

    private static func extractEmbeddedMieruLinks(_ text: String) -> [String] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("{"),
              let data = trimmed.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return []
        }
        if let profiles = obj["profiles"] as? [[String: Any]], !profiles.isEmpty {
            return profiles.compactMap { prof in
                guard let profData = try? JSONSerialization.data(withJSONObject: prof) else { return nil }
                return "mieru://" + profData.base64EncodedString()
            }
        }
        if obj["profileName"] != nil || obj["ipAddress"] != nil || obj["portBindings"] != nil {
            return ["mieru://" + data.base64EncodedString()]
        }
        return []
    }

    public static func looksLikeShareLinks(_ text: String) -> Bool {
        if !extractEmbeddedMieruLinks(text).isEmpty { return true }
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard let scheme = scheme(of: line), schemes.contains(scheme) else { continue }
            return true
        }
        return false
    }

    // MARK: - Parsing

    public static func parse(_ text: String) throws -> Contents {
        guard looksLikeShareLinks(text) else { throw ShareLinkSubscriptionError.notShareLinks }
        var proxies: [ProxyPolicy] = []
        var warnings: [String] = []
        var used = Set<String>()

        let embedded = extractEmbeddedMieruLinks(text)
        let linesToParse = embedded.isEmpty ? text.components(separatedBy: .newlines) : embedded
        for (offset, raw) in linesToParse.enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix("//") else { continue }
            guard let link = split(line), schemes.contains(link.scheme) else {
                warnings.append("跳过第 \(offset + 1) 行：不是可识别的分享链接")
                continue
            }
            switch convert(link) {
            case .failure(let reason):
                warnings.append("跳过第 \(offset + 1) 行的 \(link.scheme) 节点：\(reason)")
            case .success(let node):
                let cleaned = sanitized(node.name)
                // Duplicate labels are the norm in provider lists. Dropping the
                // later ones would silently halve a subscription, so they are
                // numbered instead.
                var unique = cleaned
                var suffix = 2
                while used.contains(unique) {
                    unique = "\(cleaned) \(suffix)"
                    suffix += 1
                }
                if unique != node.name {
                    warnings.append("节点名已调整：\(node.name) → \(unique)")
                }
                used.insert(unique)
                // Advanced protocols enter as `.external`; the adapter manager
                // promotes only what the native implementation fully covers,
                // exactly as a hand-written profile would.
                proxies.append(ProxyPolicy(name: unique, kind: .external, host: node.host,
                                           port: node.port, adapterType: node.type,
                                           parameters: node.parameters))
            }
        }

        guard !proxies.isEmpty else { throw ShareLinkSubscriptionError.noProxies }
        return Contents(proxies: proxies, warnings: warnings)
    }

    /// Replaces the characters that would break out of the line or the section
    /// a name is written into.
    ///
    /// The label comes from the link's fragment and is attacker-controlled, so
    /// this is a security boundary rather than cosmetics. Replacing keeps the
    /// node usable; rejecting would lose a node over a decorative character.
    static func sanitized(_ name: String) -> String {
        var output = ""
        for character in name {
            switch character {
            case "\n", "\r", "\0":
                continue
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
        let hadLineBreak = name.contains("\n") || name.contains("\r")
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
        return trimmed.isEmpty ? "未命名节点" : String(trimmed.prefix(200))
    }

    // MARK: - Link structure

    struct Link: Equatable {
        var scheme: String
        /// Everything between `://` and the query or fragment.
        var body: String
        /// Query keys are lowercased: clients disagree on `serviceName` versus
        /// `servicename` and the difference never carries meaning.
        var query: [String: String]
        var fragment: String
    }

    static func scheme(of line: String) -> String? {
        guard let marker = line.range(of: "://") else { return nil }
        let scheme = String(line[line.startIndex..<marker.lowerBound]).lowercased()
        guard !scheme.isEmpty else { return nil }
        let allowed = scheme.allSatisfy {
            $0.isLetter || $0.isNumber || $0 == "+" || $0 == "-" || $0 == "."
        }
        return allowed ? scheme : nil
    }

    /// Splits a link by hand rather than through `URLComponents`.
    ///
    /// Fragments routinely carry emoji and raw spaces, and `URLComponents`
    /// rejects the whole string when they do, losing a node over a flag emoji
    /// in its name.
    static func split(_ line: String) -> Link? {
        guard let scheme = scheme(of: line), let marker = line.range(of: "://") else { return nil }
        var rest = String(line[marker.upperBound...])

        var fragment = ""
        if let hash = rest.firstIndex(of: "#") {
            fragment = decodedPercent(String(rest[rest.index(after: hash)...]))
            rest = String(rest[..<hash])
        }

        var query: [String: String] = [:]
        if let mark = rest.firstIndex(of: "?") {
            let rawQuery = String(rest[rest.index(after: mark)...])
            rest = String(rest[..<mark])
            for pair in rawQuery.components(separatedBy: "&") where !pair.isEmpty {
                let parts = pair.split(separator: "=", maxSplits: 1,
                                       omittingEmptySubsequences: false)
                let key = decodedPercent(String(parts[0])).lowercased()
                guard !key.isEmpty else { continue }
                // `+` is only a space in form submissions. Translating it here
                // would corrupt every password and seed that contains one.
                query[key] = parts.count > 1 ? decodedPercent(String(parts[1])) : ""
            }
        }
        return Link(scheme: scheme, body: rest, query: query, fragment: fragment)
    }

    static func decodedPercent(_ value: String) -> String {
        value.removingPercentEncoding ?? value
    }

    /// Decodes base64 that may use the URL-safe alphabet and may omit padding.
    /// Both are common in share links and neither is signalled anywhere.
    static func base64Decoded(_ value: String) -> String? {
        var normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        while normalized.hasSuffix("/") && normalized.count % 4 == 1 {
            normalized.removeLast()
        }
        normalized = normalized
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard !normalized.isEmpty else { return nil }
        while normalized.count % 4 != 0 { normalized.append("=") }
        guard let data = Data(base64Encoded: normalized) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// The last `@` separates userinfo from the address: a percent-decoded
    /// password may contain one, the host never does.
    static func splitUserinfo(_ body: String) -> (userinfo: String?, address: String) {
        guard let at = body.lastIndex(of: "@") else { return (nil, body) }
        return (String(body[..<at]), String(body[body.index(after: at)...]))
    }

    static func splitHostPort(_ text: String) -> (host: String, port: UInt16)? {
        var host = ""
        var portText = ""
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]") else { return nil }
            host = String(text[text.index(after: text.startIndex)..<close])
            let remainder = text[text.index(after: close)...]
            guard remainder.hasPrefix(":") else { return nil }
            portText = String(remainder.dropFirst())
        } else {
            guard let colon = text.lastIndex(of: ":") else { return nil }
            host = String(text[..<colon])
            portText = String(text[text.index(after: colon)...])
        }
        // Some clients append a trailing path that carries nothing.
        if let slash = portText.firstIndex(of: "/") { portText = String(portText[..<slash]) }
        guard !host.isEmpty, let port = UInt16(portText), port > 0 else { return nil }
        return (host, port)
    }

    static func truthy(_ value: String?) -> Bool {
        guard let value else { return false }
        return ["1", "true", "yes", "on"].contains(value.lowercased())
    }

    // MARK: - Conversion

    struct Node: Equatable {
        var name: String
        var type: String
        var host: String
        var port: UInt16
        var parameters: [String: String]
    }

    private enum Conversion {
        case success(Node)
        case failure(String)
    }

    private static func convert(_ link: Link) -> Conversion {
        switch link.scheme {
        case "ss": return convertShadowsocks(link)
        case "ssr": return convertShadowsocksR(link)
        case "vmess": return convertVMess(link)
        case "vless": return convertVLESS(link)
        case "trojan": return convertTrojan(link)
        case "hysteria": return convertHysteria(link)
        case "hysteria2", "hy2": return convertHysteria2(link)
        case "tuic": return convertTUIC(link)
        case "anytls": return convertAnyTLS(link)
        case "sudoku": return convertSudoku(link)
        case "mieru", "mierus": return convertMieru(link)
        case "trusttunnel", "trust-tunnel": return convertTrustTunnel(link)
        default: return .failure("暂不支持的协议 \(link.scheme)")
        }
    }

    private static func label(_ link: Link, host: String, port: UInt16) -> String {
        let raw = link.fragment.trimmingCharacters(in: .whitespaces)
        return raw.isEmpty ? "\(host):\(port)" : raw
    }

    /// Applies the security-related query keys shared by the URI-shaped links.
    ///
    /// `sniKey` differs by protocol only because the Clash converter already
    /// established that split: `servername` for VMess/VLESS, `sni` elsewhere.
    private static func applySecurity(_ link: Link, sniKey: String, impliesTLS: Bool,
                                      fingerprint: Bool,
                                      into parameters: inout [String: String]) -> String? {
        let explicitTLS = truthy(link.query["tls"])
        let rawSecurity = link.query["security"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let security = (rawSecurity.isEmpty ? ((impliesTLS || explicitTLS) ? "tls" : "none") : rawSecurity).lowercased()
        switch security {
        case "tls":
            // Protocols that are always TLS do not carry the flag; writing it
            // would differ from what the profile editor produces.
            if !impliesTLS { parameters["tls"] = "true" }
        case "none", "":
            if explicitTLS, !impliesTLS { parameters["tls"] = "true" }
        case "reality":
            guard let publicKey = link.query["pbk"] ?? link.query["publickey"]
                    ?? link.query["public-key"], !publicKey.isEmpty else {
                return "REALITY 缺少 pbk/public-key"
            }
            parameters["tls"] = "true"
            parameters["security"] = "reality"
            parameters["reality-public-key"] = publicKey
            if let shortID = link.query["sid"] ?? link.query["shortid"]
                ?? link.query["short-id"], !shortID.isEmpty {
                parameters["reality-short-id"] = shortID
            }
        default:
            return "暂不支持 security=\(security)"
        }

        if let sni = link.query["sni"] ?? link.query["servername"] ?? link.query["peer"], !sni.isEmpty {
            parameters[sniKey] = sni
        }
        if truthy(link.query["allowinsecure"]) || truthy(link.query["insecure"])
            || truthy(link.query["skip-cert-verify"]) {
            parameters["skip-cert-verify"] = "true"
        }
        if fingerprint, let fp = link.query["fp"] ?? link.query["fingerprint"]
            ?? link.query["client-fingerprint"], !fp.isEmpty {
            parameters["client-fingerprint"] = fp
        }
        if let alpn = link.query["alpn"], !alpn.isEmpty {
            parameters["alpn"] = alpn
        }
        return nil
    }

    private static func applyTransport(_ link: Link,
                                       into parameters: inout [String: String]) -> String? {
        // `mkcp` and `splithttp` are the same carriers under older names. The
        // rest of the codebase already accepts both, but emitting the canonical
        // spelling keeps the profile editor's transport popup in sync.
        var network = (link.query["type"] ?? link.query["network"] ?? "tcp").lowercased()
        if network == "mkcp" { network = "kcp" }
        if network == "splithttp" { network = "xhttp" }
        switch network {
        case "tcp", "":
            if let header = link.query["headerType"] ?? link.query["headertype"],
               !header.isEmpty, header.lowercased() != "none" {
                return "暂不支持 headerType=\(header)"
            }
            return nil
        case "ws", "websocket":
            parameters["network"] = "ws"
            if let path = link.query["path"], !path.isEmpty { parameters["ws-path"] = path }
            if let host = link.query["host"], !host.isEmpty { parameters["ws-host"] = host }
            return nil
        case "grpc":
            parameters["network"] = "grpc"
            if let service = link.query["servicename"] ?? link.query["service-name"]
                ?? link.query["path"], !service.isEmpty {
                parameters["grpc-service-name"] = service
            }
            return nil
        case "xhttp":
            parameters["network"] = "xhttp"
            if let path = link.query["path"], !path.isEmpty { parameters["xhttp-path"] = path }
            if let host = link.query["host"], !host.isEmpty { parameters["xhttp-host"] = host }
            if let mode = link.query["mode"], !mode.isEmpty {
                parameters["xhttp-mode"] = mode.lowercased()
            }
            if let extra = link.query["extra"], !extra.isEmpty,
               let data = extra.data(using: .utf8),
               let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
               let padding = (json["xPaddingBytes"] ?? json["x-padding-bytes"]) as? String,
               !padding.isEmpty {
                parameters["xhttp-padding-bytes"] = padding
            }
            return nil
        case "kcp":
            parameters["network"] = "kcp"
            if let header = link.query["headertype"] ?? link.query["header"], !header.isEmpty {
                parameters["kcp-header"] = header.lowercased()
            }
            if let seed = link.query["seed"], !seed.isEmpty { parameters["kcp-seed"] = seed }
            return nil
        default:
            return "暂不支持的传输方式 \(network)"
        }
    }

    // MARK: - Shadowsocks / ShadowsocksR

    private static func convertShadowsocks(_ link: Link) -> Conversion {
        if let plugin = link.query["plugin"], !plugin.isEmpty {
            return .failure("暂不支持 plugin=\(plugin)")
        }
        // SIP002 puts base64(method:password) in userinfo; the legacy layout
        // base64-encodes the entire `method:password@host:port` body.
        let decodedBody: String
        if link.body.contains("@") {
            decodedBody = link.body
        } else if let whole = base64Decoded(link.body), whole.contains("@") {
            decodedBody = whole
        } else {
            return .failure("Shadowsocks 链接无法解析")
        }

        let (rawUserinfo, address) = splitUserinfo(decodedBody)
        guard let rawUserinfo, !rawUserinfo.isEmpty else {
            return .failure("Shadowsocks 链接缺少加密方式和密码")
        }
        guard let (host, port) = splitHostPort(address) else {
            return .failure("Shadowsocks 链接的地址或端口无效")
        }

        let credentials: String
        if rawUserinfo.contains(":") {
            credentials = decodedPercent(rawUserinfo)
        } else if let decoded = base64Decoded(decodedPercent(rawUserinfo)), decoded.contains(":") {
            credentials = decoded
        } else {
            return .failure("Shadowsocks 认证信息无法解码")
        }

        guard let colon = credentials.firstIndex(of: ":") else {
            return .failure("Shadowsocks 认证信息缺少 :")
        }
        let cipher = String(credentials[..<colon]).trimmingCharacters(in: .whitespaces)
        let password = String(credentials[credentials.index(after: colon)...])
        guard !cipher.isEmpty, !password.isEmpty else {
            return .failure("Shadowsocks 加密方式或密码为空")
        }
        return .success(Node(name: label(link, host: host, port: port), type: "ss",
                             host: host, port: port,
                             parameters: ["cipher": cipher, "password": password]))
    }

    private static func convertShadowsocksR(_ link: Link) -> Conversion {
        guard let decoded = base64Decoded(link.body) else {
            return .failure("SSR 链接不是合法的 base64")
        }
        let parts = decoded.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let main = String(parts[0])
        var query: [String: String] = [:]
        if parts.count > 1 {
            var tail = String(parts[1])
            if tail.hasPrefix("?") { tail.removeFirst() }
            for item in tail.components(separatedBy: "&") where !item.isEmpty {
                let kv = item.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let key = String(kv[0]).lowercased()
                let value = kv.count > 1 ? (base64Decoded(String(kv[1])) ?? "") : ""
                query[key] = value
            }
        }
        // Fixed layout `host:port:protocol:method:obfs:base64(password)`, read
        // from the right so an IPv6 literal in the host does not shift it.
        let fields = main.components(separatedBy: ":")
        guard fields.count >= 6 else { return .failure("SSR 链接字段不足") }
        let count = fields.count
        let host = fields[0..<(count - 5)].joined(separator: ":").trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard let port = UInt16(fields[count - 5]), !host.isEmpty else {
            return .failure("SSR 链接的地址或端口无效")
        }
        guard let password = base64Decoded(fields[count - 1]) else {
            return .failure("SSR 密码不是合法的 base64")
        }
        var parameters: [String: String] = [
            "protocol": fields[count - 4],
            "cipher": fields[count - 3],
            "obfs": fields[count - 2],
            "password": password,
        ]
        if let value = query["protoparam"], !value.isEmpty { parameters["protocol-param"] = value }
        if let value = query["obfsparam"], !value.isEmpty { parameters["obfs-param"] = value }
        let remarks = query["remarks"]?.trimmingCharacters(in: .whitespaces) ?? ""
        let name = remarks.isEmpty ? label(link, host: host, port: port) : remarks
        return .success(Node(name: name, type: "ssr", host: host, port: port,
                             parameters: parameters))
    }

    // MARK: - VMess

    private static func convertVMess(_ link: Link) -> Conversion {
        if let json = base64Decoded(link.body),
           json.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            return convertVMessJSON(json, link: link)
        }
        // VMessAEAD sharing reuses the VLESS URI shape.
        guard link.body.contains("@") else {
            return .failure("VMess 链接既不是 base64 JSON 也不是 uuid@host:port")
        }
        let (userinfo, address) = splitUserinfo(link.body)
        guard let uuid = userinfo, !uuid.isEmpty else { return .failure("VMess 链接缺少 uuid") }
        guard let (host, port) = splitHostPort(address) else {
            return .failure("VMess 链接的地址或端口无效")
        }
        var parameters: [String: String] = ["uuid": decodedPercent(uuid)]
        if let cipher = link.query["encryption"], !cipher.isEmpty { parameters["cipher"] = cipher }
        if let reason = applySecurity(link, sniKey: "servername", impliesTLS: false,
                                      fingerprint: true, into: &parameters) {
            return .failure(reason)
        }
        if let reason = applyTransport(link, into: &parameters) { return .failure(reason) }
        return .success(Node(name: label(link, host: host, port: port), type: "vmess",
                             host: host, port: port, parameters: parameters))
    }

    private static func convertVMessJSON(_ json: String, link: Link) -> Conversion {
        guard let data = json.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return .failure("VMess 链接内不是合法的 JSON")
        }
        // Numeric fields are written as numbers by some clients and as strings
        // by others, with no way to tell which produced a given link.
        func field(_ key: String) -> String {
            guard let value = object[key] else { return "" }
            if let text = value as? String { return text.trimmingCharacters(in: .whitespaces) }
            if let number = value as? NSNumber { return number.stringValue }
            return ""
        }

        let host = field("add")
        guard !host.isEmpty else { return .failure("VMess 链接缺少 add") }
        guard let port = UInt16(field("port")) else { return .failure("VMess 链接的端口无效") }
        let uuid = field("id")
        guard !uuid.isEmpty else { return .failure("VMess 链接缺少 id") }

        var parameters: [String: String] = ["uuid": uuid]
        let alterID = field("aid")
        if !alterID.isEmpty { parameters["alter-id"] = alterID }
        let cipher = field("scy")
        if !cipher.isEmpty { parameters["cipher"] = cipher }

        let security = field("tls").lowercased()
        let secure = security == "tls" || security == "reality"
        if secure { parameters["tls"] = "true" }
        if security == "reality" {
            let publicKey = field("pbk")
            guard !publicKey.isEmpty else { return .failure("REALITY 缺少 pbk/public-key") }
            parameters["security"] = "reality"
            parameters["reality-public-key"] = publicKey
            parameters["reality-short-id"] = field("sid")
        }

        var network = field("net").lowercased()
        if network.isEmpty { network = "tcp" }
        if network == "mkcp" { network = "kcp" }
        if network == "splithttp" { network = "xhttp" }
        let header = field("type").lowercased()
        let path = field("path")
        let hostHeader = field("host")

        switch network {
        case "tcp":
            if !header.isEmpty, header != "none" { return .failure("暂不支持 type=\(header)") }
        case "ws":
            if !path.isEmpty { parameters["ws-path"] = path }
            if !hostHeader.isEmpty { parameters["ws-host"] = hostHeader }
        case "grpc":
            if !path.isEmpty { parameters["grpc-service-name"] = path }
        case "xhttp":
            if !path.isEmpty { parameters["xhttp-path"] = path }
            if !hostHeader.isEmpty { parameters["xhttp-host"] = hostHeader }
        case "kcp":
            if !header.isEmpty { parameters["kcp-header"] = header }
            // There is no separate seed field; v2rayN stores it in `path`.
            if !path.isEmpty { parameters["kcp-seed"] = path }
        default:
            return .failure("暂不支持的传输方式 \(network)")
        }
        if network != "tcp" { parameters["network"] = network }

        // `host` is the HTTP header, but with TLS on and no explicit `sni` it is
        // also the name the certificate is checked against: that is what every
        // client writing these links does. Using the connect address instead
        // would fail verification on exactly the nodes that rely on this.
        if secure {
            let sni = field("sni")
            let servername = sni.isEmpty ? hostHeader : sni
            if !servername.isEmpty { parameters["servername"] = servername }
        }
        if truthy(field("allowInsecure")) || truthy(field("allowinsecure")) {
            parameters["skip-cert-verify"] = "true"
        }
        if let alpn = object["alpn"] as? String, !alpn.isEmpty { parameters["alpn"] = alpn }

        let remark = field("ps")
        let name = remark.isEmpty ? label(link, host: host, port: port) : remark
        return .success(Node(name: name, type: "vmess", host: host, port: port,
                             parameters: parameters))
    }

    // MARK: - VLESS / Trojan / AnyTLS

    private static func convertVLESS(_ link: Link) -> Conversion {
        let (userinfo, address) = splitUserinfo(link.body)
        guard let uuid = userinfo, !uuid.isEmpty else { return .failure("VLESS 链接缺少 uuid") }
        guard let (host, port) = splitHostPort(address) else {
            return .failure("VLESS 链接的地址或端口无效")
        }
        if let encryption = link.query["encryption"], !encryption.isEmpty,
           encryption.lowercased() != "none" {
            return .failure("暂不支持 encryption=\(encryption)")
        }
        var parameters: [String: String] = ["uuid": decodedPercent(uuid)]
        if let flow = link.query["flow"], !flow.isEmpty { parameters["flow"] = flow }
        if let reason = applySecurity(link, sniKey: "servername", impliesTLS: false,
                                      fingerprint: true, into: &parameters) {
            return .failure(reason)
        }
        if let reason = applyTransport(link, into: &parameters) { return .failure(reason) }
        return .success(Node(name: label(link, host: host, port: port), type: "vless",
                             host: host, port: port, parameters: parameters))
    }

    private static func convertTrojan(_ link: Link) -> Conversion {
        let (userinfo, address) = splitUserinfo(link.body)
        guard let password = userinfo, !password.isEmpty else {
            return .failure("Trojan 链接缺少 password")
        }
        guard let (host, port) = splitHostPort(address) else {
            return .failure("Trojan 链接的地址或端口无效")
        }
        var parameters: [String: String] = ["password": decodedPercent(password)]
        if let reason = applySecurity(link, sniKey: "sni", impliesTLS: true,
                                      fingerprint: false, into: &parameters) {
            return .failure(reason)
        }
        if let reason = applyTransport(link, into: &parameters) { return .failure(reason) }
        return .success(Node(name: label(link, host: host, port: port), type: "trojan",
                             host: host, port: port, parameters: parameters))
    }

    private static func convertAnyTLS(_ link: Link) -> Conversion {
        let (userinfo, address) = splitUserinfo(link.body)
        guard let password = userinfo, !password.isEmpty else {
            return .failure("AnyTLS 链接缺少 password")
        }
        guard let (host, port) = splitHostPort(address) else {
            return .failure("AnyTLS 链接的地址或端口无效")
        }
        var parameters: [String: String] = ["password": decodedPercent(password)]
        if let reason = applySecurity(link, sniKey: "sni", impliesTLS: true,
                                      fingerprint: false, into: &parameters) {
            return .failure(reason)
        }
        return .success(Node(name: label(link, host: host, port: port), type: "anytls",
                             host: host, port: port, parameters: parameters))
    }

    // MARK: - Hysteria / TUIC

    private static func convertHysteria(_ link: Link) -> Conversion {
        let (_, address) = splitUserinfo(link.body)
        guard let (host, port) = splitHostPort(address) else {
            return .failure("Hysteria 链接的地址或端口无效")
        }
        var parameters: [String: String] = [:]
        if let auth = link.query["auth"] ?? link.query["auth-str"] ?? link.query["auth_str"],
           !auth.isEmpty {
            parameters["auth-str"] = auth
        }
        // The profile carries bandwidth with its unit; the link states megabits
        // per second and nothing else, so the unit is restored here rather than
        // guessed at load time.
        if let up = link.query["upmbps"], !up.isEmpty {
            parameters["up"] = "\(up) Mbps"
        } else if let up = link.query["up"], !up.isEmpty {
            parameters["up"] = up
        }
        if let down = link.query["downmbps"], !down.isEmpty {
            parameters["down"] = "\(down) Mbps"
        } else if let down = link.query["down"], !down.isEmpty {
            parameters["down"] = down
        }
        if let obfs = link.query["obfs"], !obfs.isEmpty { parameters["obfs"] = obfs }
        if let reason = applySecurity(link, sniKey: "sni", impliesTLS: true,
                                      fingerprint: false, into: &parameters) {
            return .failure(reason)
        }
        return .success(Node(name: label(link, host: host, port: port), type: "hysteria",
                             host: host, port: port, parameters: parameters))
    }

    private static func convertHysteria2(_ link: Link) -> Conversion {
        let (userinfo, address) = splitUserinfo(link.body)
        guard let password = userinfo, !password.isEmpty else {
            return .failure("Hysteria2 链接缺少 password")
        }
        guard let (host, port) = splitHostPort(address) else {
            return .failure("Hysteria2 链接的地址或端无效")
        }
        var parameters: [String: String] = ["password": decodedPercent(password)]
        if let obfs = link.query["obfs"], !obfs.isEmpty { parameters["obfs"] = obfs }
        if let value = link.query["obfs-password"] ?? link.query["obfs_password"],
           !value.isEmpty {
            parameters["obfs-password"] = value
        }
        if let reason = applySecurity(link, sniKey: "sni", impliesTLS: true,
                                      fingerprint: false, into: &parameters) {
            return .failure(reason)
        }
        return .success(Node(name: label(link, host: host, port: port), type: "hysteria2",
                             host: host, port: port, parameters: parameters))
    }

    private static func convertTUIC(_ link: Link) -> Conversion {
        let (userinfo, address) = splitUserinfo(link.body)
        guard let (host, port) = splitHostPort(address) else {
            return .failure("TUIC 链接的地址或端口无效")
        }
        var parameters: [String: String] = [:]
        if let userinfo, !userinfo.isEmpty {
            // v5 carries `uuid:password`; v4 carries a single token.
            if let separator = userinfo.firstIndex(of: ":") {
                parameters["uuid"] = decodedPercent(String(userinfo[..<separator]))
                parameters["password"] =
                    decodedPercent(String(userinfo[userinfo.index(after: separator)...]))
            } else {
                parameters["token"] = decodedPercent(userinfo)
            }
        }
        guard !parameters.isEmpty else { return .failure("TUIC 链接缺少认证信息") }
        if let value = link.query["congestion_control"]
            ?? link.query["congestion-controller"], !value.isEmpty {
            parameters["congestion-controller"] = value
        }
        if let reason = applySecurity(link, sniKey: "sni", impliesTLS: true,
                                      fingerprint: false, into: &parameters) {
            return .failure(reason)
        }
        return .success(Node(name: label(link, host: host, port: port), type: "tuic",
                             host: host, port: port, parameters: parameters))
    }

    // MARK: - Sudoku / Mieru / TrustTunnel

    private static func normalizeSudokuTableType(_ raw: String) -> String {
        let lower = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch lower {
        case "ascii": return "prefer_ascii"
        case "entropy": return "prefer_entropy"
        default: return lower
        }
    }

    private static func convertSudoku(_ link: Link) -> Conversion {
        if let json = base64Decoded(link.body) ?? base64Decoded(decodedPercent(link.body)),
           json.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            return convertSudokuJSON(json, link: link)
        }
        let (userinfo, address) = splitUserinfo(link.body)
        guard let (host, port) = splitHostPort(address) else {
            return .failure("Sudoku 链接的地址或端口无效")
        }
        let key = (userinfo.map(decodedPercent) ?? link.query["key"] ?? link.query["k"] ?? link.query["password"] ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else { return .failure("Sudoku 链接缺少 key") }
        var parameters: [String: String] = ["key": key]
        if let aead = link.query["aead-method"] ?? link.query["aead"] ?? link.query["e"] ?? link.query["cipher"],
           !aead.isEmpty {
            parameters["aead-method"] = aead.lowercased()
        }
        if let table = link.query["table-type"] ?? link.query["ascii"] ?? link.query["a"], !table.isEmpty {
            parameters["table-type"] = normalizeSudokuTableType(table)
        }
        if let custom = link.query["custom-table"] ?? link.query["t"], !custom.isEmpty {
            parameters["custom-table"] = custom.lowercased()
        }
        if let pmin = link.query["padding-min"] ?? link.query["pmin"], !pmin.isEmpty {
            parameters["padding-min"] = pmin
        }
        if let pmax = link.query["padding-max"] ?? link.query["pmax"], !pmax.isEmpty {
            parameters["padding-max"] = pmax
        }
        if let pure = link.query["enable-pure-downlink"] ?? link.query["enable_pure_downlink"], !pure.isEmpty {
            parameters["enable-pure-downlink"] = truthy(pure) ? "true" : "false"
        } else if let packed = link.query["x"] ?? link.query["packed-downlink"] ?? link.query["packed_downlink"], !packed.isEmpty {
            parameters["enable-pure-downlink"] = truthy(packed) ? "false" : "true"
        }
        if let mask = link.query["http-mask"], !mask.isEmpty {
            parameters["http-mask"] = truthy(mask) ? "true" : "false"
        }
        if let dmask = link.query["disable-http-mask"] ?? link.query["hd"], !dmask.isEmpty {
            parameters["disable-http-mask"] = truthy(dmask) ? "true" : "false"
        }
        if let mode = link.query["http-mask-mode"] ?? link.query["hm"], !mode.isEmpty {
            parameters["http-mask-mode"] = mode.lowercased()
        }
        if let mTLS = link.query["http-mask-tls"] ?? link.query["ht"], !mTLS.isEmpty {
            parameters["http-mask-tls"] = truthy(mTLS) ? "true" : "false"
        }
        if let mhost = link.query["http-mask-host"] ?? link.query["hh"] ?? link.query["host"], !mhost.isEmpty {
            parameters["http-mask-host"] = mhost
        }
        if let mux = link.query["multiplex"] ?? link.query["http-mask-multiplex"] ?? link.query["hx"], !mux.isEmpty {
            parameters["multiplex"] = mux.lowercased()
        }
        if let root = link.query["path-root"] ?? link.query["hy"] ?? link.query["path"], !root.isEmpty {
            parameters["path-root"] = root
        }
        return .success(Node(name: label(link, host: host, port: port), type: "sudoku",
                             host: host, port: port, parameters: parameters))
    }

    private static func convertSudokuJSON(_ json: String, link: Link) -> Conversion {
        guard let data = json.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return .failure("Sudoku 链接内不是合法的 JSON")
        }
        func stringField(_ keys: [String]) -> String {
            for key in keys {
                guard let value = object[key] else { continue }
                if let text = value as? String {
                    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty { return trimmed }
                } else if let number = value as? NSNumber {
                    return number.stringValue
                }
            }
            return ""
        }
        func boolField(_ keys: [String]) -> Bool? {
            for key in keys {
                guard let value = object[key] else { continue }
                if let b = value as? Bool { return b }
                if let n = value as? NSNumber { return n.boolValue }
                if let s = value as? String {
                    let lower = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    if ["true", "1", "yes", "on"].contains(lower) { return true }
                    if ["false", "0", "no", "off"].contains(lower) { return false }
                }
            }
            return nil
        }

        let host = stringField(["h", "host", "server", "add"])
        guard !host.isEmpty else { return .failure("Sudoku 链接缺少服务器地址 (h)") }
        guard let port = UInt16(stringField(["p", "port"])), port > 0 else {
            return .failure("Sudoku 链接的端口 (p) 无效")
        }
        let key = stringField(["k", "key", "password", "uuid"])
        guard !key.isEmpty else { return .failure("Sudoku 链接缺少密钥 (k)") }

        var parameters: [String: String] = ["key": key]
        let aead = stringField(["e", "aead", "aead-method", "aead_method", "cipher"])
        if !aead.isEmpty { parameters["aead-method"] = aead.lowercased() }

        let table = stringField(["a", "ascii", "table-type", "table_type"])
        if !table.isEmpty { parameters["table-type"] = normalizeSudokuTableType(table) }

        var customTable = stringField(["t", "custom-table", "custom_table"])
        if let tables = object["ts"] as? [String] ?? object["custom_tables"] as? [String] ?? object["custom-tables"] as? [String] {
            let valid = tables.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }.filter { !$0.isEmpty }
            if customTable.isEmpty, let first = valid.first { customTable = first }
            if !valid.isEmpty { parameters["custom-tables"] = valid.joined(separator: ";") }
        }
        if !customTable.isEmpty { parameters["custom-table"] = customTable.lowercased() }

        let pmin = stringField(["pmin", "padding-min", "padding_min"])
        if !pmin.isEmpty { parameters["padding-min"] = pmin }
        let pmax = stringField(["pmax", "padding-max", "padding_max"])
        if !pmax.isEmpty { parameters["padding-max"] = pmax }

        if let pure = boolField(["enable-pure-downlink", "enable_pure_downlink"]) {
            parameters["enable-pure-downlink"] = pure ? "true" : "false"
        } else if let packed = boolField(["x", "packed-downlink", "packed_downlink"]) {
            parameters["enable-pure-downlink"] = packed ? "false" : "true"
        }
        if let disableMask = boolField(["hd", "disable-http-mask", "disable_http_mask"]) {
            parameters["disable-http-mask"] = disableMask ? "true" : "false"
        } else if let httpMask = boolField(["http-mask", "http_mask"]) {
            parameters["disable-http-mask"] = httpMask ? "false" : "true"
        }
        let maskMode = stringField(["hm", "http-mask-mode", "http_mask_mode"])
        if !maskMode.isEmpty { parameters["http-mask-mode"] = maskMode.lowercased() }
        if let maskTLS = boolField(["ht", "http-mask-tls", "http_mask_tls", "tls"]) {
            parameters["http-mask-tls"] = maskTLS ? "true" : "false"
        }
        let maskHost = stringField(["hh", "http-mask-host", "http_mask_host"])
        if !maskHost.isEmpty { parameters["http-mask-host"] = maskHost }
        let mux = stringField(["hx", "multiplex", "http-mask-multiplex", "http_mask_multiplex"])
        if !mux.isEmpty { parameters["multiplex"] = mux.lowercased() }
        let pathRoot = stringField(["hy", "path-root", "path_root", "path"])
        if !pathRoot.isEmpty { parameters["path-root"] = pathRoot }

        let remark = stringField(["n", "name", "ps", "remark", "remarks"])
        let name = remark.isEmpty ? label(link, host: host, port: port) : remark
        return .success(Node(name: name, type: "sudoku", host: host, port: port, parameters: parameters))
    }

    private static func firstPortFromRange(_ rangeText: String) -> UInt16? {
        let trimmed = rangeText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let firstPart = trimmed.split(separator: ",").first.map(String.init) ?? trimmed
        let startPart = firstPart.split(separator: "-").first.map(String.init) ?? firstPart
        if let port = UInt16(startPart.trimmingCharacters(in: .whitespaces)), port > 0 {
            return port
        }
        return nil
    }

    private static func convertMieru(_ link: Link) -> Conversion {
        if let json = base64Decoded(link.body) ?? base64Decoded(decodedPercent(link.body)),
           json.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") {
            return convertMieruJSON(json, link: link)
        }
        let (userinfo, address) = splitUserinfo(link.body)
        var host = ""
        var port: UInt16 = 0
        if let parsed = splitHostPort(address) {
            host = parsed.host
            port = parsed.port
        } else {
            var candidateHost = address
            if let slash = candidateHost.firstIndex(of: "/") {
                candidateHost = String(candidateHost[..<slash])
            }
            host = candidateHost.trimmingCharacters(in: .whitespacesAndNewlines)
            if let pr = link.query["port-range"] ?? link.query["port"],
               let extracted = firstPortFromRange(pr) {
                port = extracted
            }
        }
        guard !host.isEmpty, port > 0 else {
            return .failure("Mieru 链接的地址或端口无效")
        }
        var username = link.query["username"] ?? link.query["user"] ?? ""
        var password = link.query["password"] ?? ""
        if let userinfo, !userinfo.isEmpty {
            let decodedUser = decodedPercent(userinfo)
            if let colon = decodedUser.firstIndex(of: ":") {
                username = String(decodedUser[..<colon])
                password = String(decodedUser[decodedUser.index(after: colon)...])
            } else if let b64 = base64Decoded(decodedUser), let colon = b64.firstIndex(of: ":") {
                username = String(b64[..<colon])
                password = String(b64[b64.index(after: colon)...])
            } else if username.isEmpty {
                username = decodedUser
            }
        }
        guard !username.isEmpty, !password.isEmpty else {
            return .failure("Mieru 链接缺少 username 或 password")
        }
        var parameters: [String: String] = ["username": username, "password": password]
        if let transport = link.query["transport"] ?? link.query["protocol"] ?? link.query["network"],
           !transport.isEmpty {
            parameters["transport"] = transport.uppercased()
        }
        if let mux = link.query["multiplexing"] ?? link.query["mux"], !mux.isEmpty {
            parameters["multiplexing"] = mux.uppercased()
        }
        if let hs = link.query["handshake-mode"], !hs.isEmpty {
            parameters["handshake-mode"] = hs.uppercased()
        }
        if let pr = link.query["port-range"] ?? (link.query["port"]?.contains("-") == true ? link.query["port"] : nil),
           !pr.isEmpty {
            parameters["port-range"] = pr
        }
        if let mtu = link.query["mtu"], !mtu.isEmpty {
            parameters["mtu"] = mtu
        }
        if let pattern = link.query["traffic-pattern"], !pattern.isEmpty {
            parameters["traffic-pattern"] = pattern
        }
        let name = link.query["profile"]?.trimmingCharacters(in: .whitespaces).isEmpty == false
            ? link.query["profile"]! : label(link, host: host, port: port)
        return .success(Node(name: name, type: "mieru",
                             host: host, port: port, parameters: parameters))
    }

    private static func convertMieruJSON(_ json: String, link: Link) -> Conversion {
        guard let data = json.data(using: .utf8),
              var object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return .failure("Mieru 链接内不是合法的 JSON")
        }
        if let profiles = object["profiles"] as? [[String: Any]], let firstProfile = profiles.first {
            let active = (object["activeProfile"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
            let chosen = profiles.first(where: { ($0["profileName"] as? String) == active }) ?? firstProfile
            object = chosen
        }
        func stringField(_ keys: [String], in dict: [String: Any] = object) -> String {
            for key in keys {
                guard let value = dict[key] else { continue }
                if let text = value as? String {
                    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty { return trimmed }
                } else if let number = value as? NSNumber {
                    return number.stringValue
                }
            }
            return ""
        }
        let firstServer = (object["servers"] as? [[String: Any]])?.first ?? [:]
        let firstBinding = (firstServer["portBindings"] as? [[String: Any]])?.first ?? [:]
        let userDict = (object["user"] as? [String: Any]) ?? [:]
        let muxDict = (object["multiplexing"] as? [String: Any]) ?? [:]

        var host = stringField(["server", "host", "h", "ipAddress", "domainName"])
        if host.isEmpty {
            host = stringField(["ipAddress", "domainName", "server", "host"], in: firstServer)
        }
        guard !host.isEmpty else { return .failure("Mieru 链接缺少服务器地址") }

        var portRange = stringField(["port-range", "portRange"])
        if portRange.isEmpty {
            portRange = stringField(["portRange", "port-range"], in: firstBinding)
        }
        let portStr = !stringField(["port", "p"]).isEmpty
            ? stringField(["port", "p"])
            : stringField(["port", "p"], in: firstBinding)
        let port = UInt16(portStr) ?? firstPortFromRange(portRange) ?? 0
        guard port > 0 else { return .failure("Mieru 链接缺少有效端口") }

        var username = stringField(["username", "user", "u"])
        if username.isEmpty { username = stringField(["name", "username"], in: userDict) }
        var password = stringField(["password", "pass", "k"])
        if password.isEmpty { password = stringField(["password", "pass"], in: userDict) }
        guard !username.isEmpty, !password.isEmpty else {
            return .failure("Mieru 链接缺少 username 或 password")
        }
        var parameters: [String: String] = ["username": username, "password": password]
        var transport = stringField(["transport", "protocol", "network"])
        if transport.isEmpty { transport = stringField(["protocol", "transport"], in: firstBinding) }
        if !transport.isEmpty { parameters["transport"] = transport.uppercased() }
        var mux = stringField(["multiplexing", "mux"])
        if mux.isEmpty { mux = stringField(["level"], in: muxDict) }
        if !mux.isEmpty { parameters["multiplexing"] = mux.uppercased() }
        let hs = stringField(["handshake-mode", "handshakeMode"])
        if !hs.isEmpty { parameters["handshake-mode"] = hs.uppercased() }
        if !portRange.isEmpty { parameters["port-range"] = portRange }
        let mtu = stringField(["mtu"])
        if !mtu.isEmpty { parameters["mtu"] = mtu }
        let name = stringField(["name", "profileName", "ps", "n"])
        return .success(Node(name: name.isEmpty ? label(link, host: host, port: port) : name,
                             type: "mieru", host: host, port: port, parameters: parameters))
    }

    private static func convertTrustTunnel(_ link: Link) -> Conversion {
        let (userinfo, address) = splitUserinfo(link.body)
        guard let (host, port) = splitHostPort(address) else {
            return .failure("TrustTunnel 链接的地址或端口无效")
        }
        var username = link.query["username"] ?? link.query["user"] ?? ""
        var password = link.query["password"] ?? ""
        if let userinfo, !userinfo.isEmpty {
            if let colon = userinfo.firstIndex(of: ":") {
                username = decodedPercent(String(userinfo[..<colon]))
                password = decodedPercent(String(userinfo[userinfo.index(after: colon)...]))
            }
        }
        guard !username.isEmpty, !password.isEmpty else {
            return .failure("TrustTunnel 链接缺少 username 或 password")
        }
        var parameters: [String: String] = ["username": username, "password": password]
        if let quic = link.query["quic"], !quic.isEmpty {
            parameters["quic"] = truthy(quic) ? "true" : "false"
        }
        if let reason = applySecurity(link, sniKey: "sni", impliesTLS: true,
                                      fingerprint: false, into: &parameters) {
            return .failure(reason)
        }
        return .success(Node(name: label(link, host: host, port: port), type: "trusttunnel",
                             host: host, port: port, parameters: parameters))
    }
}

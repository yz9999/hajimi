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
    ]

    public static func looksLikeShareLinks(_ text: String) -> Bool {
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

        for (offset, raw) in text.components(separatedBy: .newlines).enumerated() {
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
            case "\n", "\r", "\0", "=", "#", "[", "]", ",", ";", "\"":
                output.append("_")
            default:
                output.append(character)
            }
        }
        let trimmed = output.trimmingCharacters(in: .whitespaces)
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
        let security = (link.query["security"] ?? (impliesTLS ? "tls" : "none")).lowercased()
        switch security {
        case "tls":
            // Protocols that are always TLS do not carry the flag; writing it
            // would differ from what the profile editor produces.
            if !impliesTLS { parameters["tls"] = "true" }
        case "none", "":
            break
        case "reality":
            guard let publicKey = link.query["pbk"] ?? link.query["publickey"]
                    ?? link.query["public-key"], !publicKey.isEmpty else {
                return "REALITY 缺少 pbk/public-key"
            }
            parameters["tls"] = "true"
            parameters["security"] = "reality"
            parameters["reality-public-key"] = publicKey
            parameters["reality-short-id"] = link.query["sid"] ?? link.query["shortid"] ?? ""
        default:
            return "暂不支持 security=\(security)"
        }
        if let sni = link.query["sni"] ?? link.query["peer"], !sni.isEmpty {
            parameters[sniKey] = sni
        }
        if fingerprint, let value = link.query["fp"], !value.isEmpty {
            parameters["client-fingerprint"] = value
        }
        if let alpn = link.query["alpn"], !alpn.isEmpty { parameters["alpn"] = alpn }
        if truthy(link.query["allowinsecure"]) || truthy(link.query["insecure"])
            || truthy(link.query["skip-cert-verify"]) {
            parameters["skip-cert-verify"] = "true"
        }
        return nil
    }

    /// Applies the transport query keys, returning a reason when the carrier is
    /// one the native outbound does not implement.
    private static func applyTransport(_ link: Link,
                                       into parameters: inout [String: String]) -> String? {
        let raw = (link.query["type"] ?? link.query["network"] ?? "tcp").lowercased()
        // `mkcp` and `splithttp` are the same carriers under older names. The
        // outbound factory accepts both, but the profile is written with one
        // spelling so the editor round-trips it unchanged.
        var network = raw
        if network == "mkcp" { network = "kcp" }
        if network == "splithttp" { network = "xhttp" }

        switch network {
        case "tcp":
            // `headerType=http` is TCP-with-HTTP-obfuscation, a separate carrier
            // that is not implemented. Ignoring it yields a node that connects
            // and is then closed by the server with nothing to explain it.
            if let header = link.query["headertype"], !header.isEmpty,
               header.lowercased() != "none" {
                return "暂不支持 headerType=\(header)"
            }
            return nil
        case "ws":
            if let path = link.query["path"], !path.isEmpty { parameters["ws-path"] = path }
            if let host = link.query["host"], !host.isEmpty { parameters["ws-host"] = host }
        case "grpc":
            if let service = link.query["servicename"] ?? link.query["path"], !service.isEmpty {
                parameters["grpc-service-name"] = service
            }
        case "xhttp":
            if let path = link.query["path"], !path.isEmpty { parameters["xhttp-path"] = path }
            if let host = link.query["host"], !host.isEmpty { parameters["xhttp-host"] = host }
            if let mode = link.query["mode"], !mode.isEmpty {
                parameters["xhttp-mode"] = mode.lowercased()
            }
        case "kcp":
            if let header = link.query["headertype"], !header.isEmpty {
                parameters["kcp-header"] = header.lowercased()
            }
            if let seed = link.query["seed"], !seed.isEmpty { parameters["kcp-seed"] = seed }
        default:
            return "暂不支持的传输方式 \(raw)"
        }
        parameters["network"] = network
        return nil
    }

    // MARK: - Shadowsocks

    private static func convertShadowsocks(_ link: Link) -> Conversion {
        if let plugin = link.query["plugin"], !plugin.isEmpty {
            return .failure("暂不支持 plugin=\(plugin)")
        }
        var body = link.body
        // Legacy form: `method:password@host:port` is one base64 blob.
        if !body.contains("@"), let decoded = base64Decoded(body) { body = decoded }

        let (userinfo, address) = splitUserinfo(body)
        guard let userinfo, !userinfo.isEmpty else { return .failure("ss 链接缺少认证信息") }
        guard let (host, port) = splitHostPort(address) else {
            return .failure("ss 链接的地址或端口无效")
        }
        // SIP002 base64s the userinfo; older links percent-encode it in place.
        // The decoded value is accepted only when it actually looks like a
        // credential pair, so a percent-encoded userinfo that happens to be
        // valid base64 is not mangled.
        let decoded = base64Decoded(userinfo)
        let credentials = decoded?.contains(":") == true ? decoded! : decodedPercent(userinfo)
        guard let separator = credentials.firstIndex(of: ":") else {
            return .failure("ss 链接的认证信息不是 method:password")
        }
        let method = String(credentials[..<separator])
        // The password may itself contain colons; only the first one separates.
        let password = String(credentials[credentials.index(after: separator)...])
        guard !method.isEmpty, !password.isEmpty else {
            return .failure("ss 链接缺少 method 或 password")
        }
        return .success(Node(name: label(link, host: host, port: port), type: "ss",
                             host: host, port: port,
                             parameters: ["cipher": method, "password": password]))
    }

    private static func convertShadowsocksR(_ link: Link) -> Conversion {
        guard let decoded = base64Decoded(link.body) else {
            return .failure("SSR 链接不是合法的 base64")
        }
        var main = decoded
        var query: [String: String] = [:]
        if let mark = decoded.range(of: "/?") {
            main = String(decoded[..<mark.lowerBound])
            for pair in decoded[mark.upperBound...].components(separatedBy: "&") {
                let parts = pair.split(separator: "=", maxSplits: 1,
                                       omittingEmptySubsequences: false)
                guard parts.count == 2 else { continue }
                query[String(parts[0]).lowercased()] = base64Decoded(String(parts[1])) ?? ""
            }
        }
        // Fixed layout `host:port:protocol:method:obfs:base64(password)`, read
        // from the right so an IPv6 literal in the host does not shift it.
        let fields = main.components(separatedBy: ":")
        guard fields.count >= 6 else { return .failure("SSR 链接字段不足") }
        let count = fields.count
        let host = fields[0..<(count - 5)].joined(separator: ":")
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
            parameters["auth-string"] = auth
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
}

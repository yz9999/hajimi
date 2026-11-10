import Foundation
import Network
import Security
import Darwin

/// Native QUIC protocol entry point. Capability is deliberately reported only
/// for wire options implemented below; unsupported UDP obfuscation and port
/// hopping are rejected instead of being silently ignored.
enum NativeQUICOutbound {
    static func selfTest() throws {
        try NativeCXXOutbound.selfTest()
        for value: UInt64 in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let encoded = quicVarint(value)
            guard parseQUICVarint(encoded, offset: 0)?.value == value else {
                throw NativeQUICError.protocolError("QUIC varint 自检失败")
            }
        }
        let fields = [(":method", "POST"), (":scheme", "https"),
                      (":authority", "hysteria"), (":path", "/auth"),
                      ("hysteria-auth", "secret"), ("hysteria-cc-rx", "0")]
        let decoded = try QPACKCodec.decode(QPACKCodec.encode(fields))
        guard decoded.count == fields.count,
              zip(decoded, fields).allSatisfy({ $0.0.0 == $0.1.0 && $0.0.1 == $0.1.1 }) else {
            throw NativeQUICError.protocolError("QPACK 往返自检失败")
        }
        let huffman = Data([0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff])
        guard try HPACKHuffman.decode(huffman) == "www.example.com" else {
            throw NativeQUICError.protocolError("HPACK Huffman 自检失败")
        }
        let targets = [RequestTarget(host: "example.com", port: 443, protocolName: "UDP"),
                       RequestTarget(host: "127.0.0.1", port: 53, protocolName: "UDP"),
                       RequestTarget(host: "2001:db8::1", port: 853, protocolName: "UDP")]
        for target in targets {
            let encoded = try tuicAddress(target)
            guard let parsed = parseTUICAddress(encoded, offset: 0)?.target,
                  parsed == target else { throw NativeQUICError.protocolError("TUIC 地址自检失败") }
        }
    }

    static func supports(_ policy: ProxyPolicy) -> Bool {
        validationError(for: policy) == nil
    }

    static func supportsUDP(_ policy: ProxyPolicy) -> Bool {
        supports(policy)
    }

    static func validationError(for policy: ProxyPolicy) -> String? {
        guard policy.kind == .external || policy.kind == .native,
              let type = policy.adapterType?.lowercased(),
              ["hysteria", "hysteria2", "tuic"].contains(type),
              policy.host?.isEmpty == false, policy.port != nil else {
            return "QUIC 节点缺少有效服务器或端口"
        }
        return NativeCXXOutbound.validationError(for: policy)
    }

    static func configure(policies: [String: ProxyPolicy]) {
        NativeStaticQUICOutbound.configure(policies: policies)
    }

    static func invalidateForNetworkChange() {
        NativeCXXOutbound.invalidateForNetworkChange()
    }

    static func connect(policy: ProxyPolicy, target: RequestTarget,
                        queue: DispatchQueue,
                        completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        NativeCXXOutbound.connect(policy: policy, target: target, queue: queue, completion: completion)
    }

    static func makeDatagramSession(policy: ProxyPolicy,
                                    receive: @escaping (RequestTarget, Data) -> Void,
                                    failure: @escaping (Error) -> Void)
        throws -> NativeOutboundDatagramSession {
        try NativeStaticQUICOutbound.makeDatagramSession(policy: policy,
                                                         receive: receive, failure: failure)
    }
}


enum NativeQUICError: LocalizedError {
    case invalidEndpoint
    case connection(String)
    case protocolError(String)
    case exporter

    var errorDescription: String? {
        switch self {
        case .invalidEndpoint: return "QUIC 节点地址或端口无效"
        case .connection(let text): return "QUIC 连接失败：\(text)"
        case .protocolError(let text): return "QUIC 协议错误：\(text)"
        case .exporter: return "无法导出 TUIC TLS 会话密钥"
        }
    }
}

// MARK: - HTTP/3 QPACK (static table only, as advertised in SETTINGS)

private enum QPACKCodec {
    static func encode(_ fields: [(String, String)]) throws -> Data {
        var output = Data([0x00, 0x00]) // Required Insert Count = 0, Delta Base = 0
        for (rawName, value) in fields {
            let name = rawName.lowercased()
            if let index = exactStaticIndex(name: name, value: value) {
                appendPrefixedInteger(UInt64(index), prefix: 6, marker: 0xc0, to: &output)
            } else if let index = staticNameIndex[name] {
                appendPrefixedInteger(UInt64(index), prefix: 4, marker: 0x50, to: &output)
                try appendString(value, prefix: 7, marker: 0x00, to: &output)
            } else {
                try appendString(name, prefix: 3, marker: 0x20, to: &output)
                try appendString(value, prefix: 7, marker: 0x00, to: &output)
            }
        }
        return output
    }

    static func decode(_ data: Data) throws -> [(String, String)] {
        var offset = 0
        let required = try readPrefixedInteger(data, offset: &offset, prefix: 8)
        guard required == 0 else { throw NativeQUICError.protocolError("QPACK 动态表未关闭") }
        guard offset < data.count else { throw NativeQUICError.protocolError("QPACK Header Block 截断") }
        let deltaSign = data[offset] & 0x80
        let delta = try readPrefixedInteger(data, offset: &offset, prefix: 7)
        guard deltaSign == 0, delta == 0 else {
            throw NativeQUICError.protocolError("QPACK Delta Base 无效")
        }
        var fields: [(String, String)] = []
        while offset < data.count {
            let byte = data[offset]
            if byte & 0x80 != 0 {
                guard byte & 0x40 != 0 else {
                    throw NativeQUICError.protocolError("QPACK 动态索引不受支持")
                }
                let index = try readPrefixedInteger(data, offset: &offset, prefix: 6)
                guard index < UInt64(staticTable.count) else {
                    throw NativeQUICError.protocolError("QPACK 静态索引越界")
                }
                fields.append(staticTable[Int(index)])
            } else if byte & 0xc0 == 0x40 {
                guard byte & 0x10 != 0 else {
                    throw NativeQUICError.protocolError("QPACK 动态名称不受支持")
                }
                let index = try readPrefixedInteger(data, offset: &offset, prefix: 4)
                guard index < UInt64(staticTable.count) else {
                    throw NativeQUICError.protocolError("QPACK 名称索引越界")
                }
                let value = try readString(data, offset: &offset, prefix: 7)
                fields.append((staticTable[Int(index)].0, value))
            } else if byte & 0xe0 == 0x20 {
                let name = try readString(data, offset: &offset, prefix: 3)
                let value = try readString(data, offset: &offset, prefix: 7)
                fields.append((name.lowercased(), value))
            } else {
                throw NativeQUICError.protocolError(
                    String(format: "QPACK 字段表示 0x%02x 不受支持", byte))
            }
        }
        return fields
    }

    private static func appendString(_ value: String, prefix: Int, marker: UInt8,
                                     to data: inout Data) throws {
        let bytes = Data(value.utf8)
        guard bytes.count <= 65_535 else { throw NativeQUICError.protocolError("QPACK 字符串过长") }
        appendPrefixedInteger(UInt64(bytes.count), prefix: prefix, marker: marker, to: &data)
        data.append(bytes)
    }

    private static func readString(_ data: Data, offset: inout Int, prefix: Int) throws -> String {
        guard offset < data.count else { throw NativeQUICError.protocolError("QPACK 字符串截断") }
        let huffman = data[offset] & (prefix == 7 ? 0x80 : 0x08) != 0
        let length = try readPrefixedInteger(data, offset: &offset, prefix: prefix)
        guard length <= UInt64(Int.max), data.count >= offset + Int(length) else {
            throw NativeQUICError.protocolError("QPACK 字符串长度无效")
        }
        let bytes = Data(data[offset..<(offset + Int(length))]); offset += Int(length)
        if huffman { return try HPACKHuffman.decode(bytes) }
        guard let value = String(data: bytes, encoding: .utf8) else {
            throw NativeQUICError.protocolError("QPACK 字符串不是 UTF-8")
        }
        return value
    }

    private static func exactStaticIndex(name: String, value: String) -> Int? {
        switch (name, value) {
        case (":method", "POST"): return 20
        case (":scheme", "https"): return 23
        case ("content-length", "0"): return 4
        case (":path", "/"): return 1
        default: return nil
        }
    }

    private static let staticNameIndex: [String: Int] = [
        ":authority": 0, ":path": 1, "content-length": 4, ":method": 15,
        ":scheme": 22, ":status": 24, "date": 6, "server": 92
    ]

    private static let staticTable: [(String, String)] = [
        (":authority", ""), (":path", "/"), ("age", "0"), ("content-disposition", ""),
        ("content-length", "0"), ("cookie", ""), ("date", ""), ("etag", ""),
        ("if-modified-since", ""), ("if-none-match", ""), ("last-modified", ""),
        ("link", ""), ("location", ""), ("referer", ""), ("set-cookie", ""),
        (":method", "CONNECT"), (":method", "DELETE"), (":method", "GET"),
        (":method", "HEAD"), (":method", "OPTIONS"), (":method", "POST"),
        (":method", "PUT"), (":scheme", "http"), (":scheme", "https"),
        (":status", "103"), (":status", "200"), (":status", "304"),
        (":status", "404"), (":status", "503"), ("accept", "*/*"),
        ("accept", "application/dns-message"), ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"), ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"), ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"), ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"), ("cache-control", "no-cache"),
        ("cache-control", "no-store"), ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"), ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"), ("content-type", "application/javascript"),
        ("content-type", "application/json"), ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"), ("content-type", "image/jpeg"),
        ("content-type", "image/png"), ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"), ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"), ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        ("strict-transport-security", "max-age=31536000; includesubdomains"),
        ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        ("vary", "accept-encoding"), ("vary", "origin"),
        ("x-content-type-options", "nosniff"), ("x-xss-protection", "1; mode=block"),
        (":status", "100"), (":status", "204"), (":status", "206"),
        (":status", "302"), (":status", "400"), (":status", "403"),
        (":status", "421"), (":status", "425"), (":status", "500"),
        ("accept-language", ""), ("access-control-allow-credentials", "FALSE"),
        ("access-control-allow-credentials", "TRUE"), ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"), ("access-control-request-method", "post"),
        ("alt-svc", "clear"), ("authorization", ""),
        ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        ("early-data", "1"), ("expect-ct", ""), ("forwarded", ""), ("if-range", ""),
        ("origin", ""), ("purpose", "prefetch"), ("server", ""),
        ("timing-allow-origin", "*"), ("upgrade-insecure-requests", "1"),
        ("user-agent", ""), ("x-forwarded-for", ""), ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin")
    ]
}


private enum HPACKHuffman {
    static func decode(_ data: Data) throws -> String {
        guard let bytes = try? Huffman.decode(data),
              let value = String(data: bytes, encoding: .utf8) else {
            throw NativeQUICError.protocolError("HPACK Huffman 填充或 UTF-8 无效")
        }
        return value
    }
}

private struct ParsedQUICVarint { let value: UInt64; let length: Int }

private func quicVarint(_ value: UInt64) -> Data {
    precondition(value <= 4_611_686_018_427_387_903)
    if value <= 63 { return Data([UInt8(value)]) }
    if value <= 16_383 {
        return Data([0x40 | UInt8(value >> 8), UInt8(value & 0xff)])
    }
    if value <= 1_073_741_823 {
        return Data([0x80 | UInt8(value >> 24), UInt8((value >> 16) & 0xff),
                     UInt8((value >> 8) & 0xff), UInt8(value & 0xff)])
    }
    return Data([0xc0 | UInt8(value >> 56), UInt8((value >> 48) & 0xff),
                 UInt8((value >> 40) & 0xff), UInt8((value >> 32) & 0xff),
                 UInt8((value >> 24) & 0xff), UInt8((value >> 16) & 0xff),
                 UInt8((value >> 8) & 0xff), UInt8(value & 0xff)])
}

private func parseQUICVarint(_ data: Data, offset: Int) -> ParsedQUICVarint? {
    guard offset >= 0, offset < data.count else { return nil }
    let count = 1 << Int(data[offset] >> 6)
    guard data.count >= offset + count else { return nil }
    var value = UInt64(data[offset] & 0x3f)
    if count > 1 {
        for index in (offset + 1)..<(offset + count) { value = (value << 8) | UInt64(data[index]) }
    }
    return ParsedQUICVarint(value: value, length: count)
}

private func appendPrefixedInteger(_ value: UInt64, prefix: Int, marker: UInt8,
                                   to data: inout Data) {
    let maximum = UInt64((1 << prefix) - 1)
    if value < maximum { data.append(marker | UInt8(value)); return }
    data.append(marker | UInt8(maximum))
    var remaining = value - maximum
    while remaining >= 128 { data.append(0x80 | UInt8(remaining & 0x7f)); remaining >>= 7 }
    data.append(UInt8(remaining))
}

private func readPrefixedInteger(_ data: Data, offset: inout Int, prefix: Int) throws -> UInt64 {
    guard (1...8).contains(prefix), offset < data.count else {
        throw NativeQUICError.protocolError("QPACK 整数截断")
    }
    let maximum = UInt64((1 << prefix) - 1)
    var value = UInt64(data[offset] & UInt8(maximum)); offset += 1
    guard value == maximum else { return value }
    var shift = 0
    while offset < data.count {
        let byte = data[offset]; offset += 1
        guard shift < 63 else { throw NativeQUICError.protocolError("QPACK 整数溢出") }
        value += UInt64(byte & 0x7f) << UInt64(shift)
        if byte & 0x80 == 0 { return value }
        shift += 7
    }
    throw NativeQUICError.protocolError("QPACK 整数截断")
}

private func appendBE(_ value: UInt16, to data: inout Data) {
    data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
}

private func appendBE(_ value: UInt32, to data: inout Data) {
    data.append(UInt8(value >> 24)); data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff)); data.append(UInt8(value & 0xff))
}

private func appendBE(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private func readBE16(_ data: Data, _ offset: Int) -> UInt16 {
    UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
}


private func tuicAddress(_ target: RequestTarget) throws -> Data {
    var host = target.host
    if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    if host.contains(":"), let pct = host.firstIndex(of: "%") { host = String(host[..<pct]) }
    var ipv4 = in_addr()
    if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
        var data = Data([0x01]); withUnsafeBytes(of: &ipv4) { data.append(contentsOf: $0) }
        appendBE(target.port, to: &data); return data
    }
    var ipv6 = in6_addr()
    if host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
        var data = Data([0x02]); withUnsafeBytes(of: &ipv6) { data.append(contentsOf: $0) }
        appendBE(target.port, to: &data); return data
    }
    let domain = Data(host.utf8)
    guard !domain.isEmpty, domain.count <= 255 else {
        throw NativeQUICError.protocolError("TUIC 目标域名长度无效")
    }
    var data = Data([0x00, UInt8(domain.count)]); data.append(domain); appendBE(target.port, to: &data)
    return data
}

private struct TUICParsedAddress { let target: RequestTarget?; let nextOffset: Int }

private func parseTUICAddress(_ data: Data, offset: Int) -> TUICParsedAddress? {
    guard offset < data.count else { return nil }
    switch data[offset] {
    case 0xff: return TUICParsedAddress(target: nil, nextOffset: offset + 1)
    case 0x00:
        guard data.count >= offset + 2 else { return nil }
        let length = Int(data[offset + 1]), start = offset + 2, end = start + length
        guard length > 0, data.count >= end + 2,
              let host = String(data: data[start..<end], encoding: .utf8) else { return nil }
        return TUICParsedAddress(target: RequestTarget(host: host, port: readBE16(data, end),
                                                       protocolName: "UDP"), nextOffset: end + 2)
    case 0x01:
        guard data.count >= offset + 7 else { return nil }
        var address = in_addr()
        withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: data[(offset + 1)..<(offset + 5)]) }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return TUICParsedAddress(target: RequestTarget(host: String(cString: buffer),
                                                       port: readBE16(data, offset + 5), protocolName: "UDP"),
                                 nextOffset: offset + 7)
    case 0x02:
        guard data.count >= offset + 19 else { return nil }
        var address = in6_addr()
        withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: data[(offset + 1)..<(offset + 17)]) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return TUICParsedAddress(target: RequestTarget(host: String(cString: buffer),
                                                       port: readBE16(data, offset + 17), protocolName: "UDP"),
                                 nextOffset: offset + 19)
    default: return nil
    }
}

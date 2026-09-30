import Foundation
import HajimiProtocolCXX
import HajimiProtocolsCXX

/// Swift control-plane adapters around caller-buffer C++ wire codecs.
/// Transport, routing policy, and cryptographic authentication are separate.
enum NativeProtocolCodec {
    static func failure(_ status: Int32) -> Error {
        NativeOutboundError.protocolError(String(cString: hajimi_codec_status_string(status)))
    }
    static func host(_ address: hajimi_address) -> String {
        var address = address
        let count = address.host_length
        return withUnsafeBytes(of: &address.host) {
            String(decoding: $0.prefix(count), as: UTF8.self)
        }
    }
    static func address(host: String, port: UInt16) throws -> hajimi_address {
        var address = hajimi_address()
        let status = Data(host.utf8).withUnsafeBytes { bytes in
            hajimi_address_from_host(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                     bytes.count, port, &address).status
        }
        guard status == HAJIMI_CODEC_OK else { throw failure(status) }
        return address
    }
    static func encode(_ body: (UnsafeMutablePointer<UInt8>?, Int) -> hajimi_codec_result) throws -> Data {
        let sizing = body(nil, 0)
        guard sizing.status == HAJIMI_CODEC_OUTPUT_TOO_SMALL, sizing.needed > 0,
              sizing.needed <= 16 * 1_024 * 1_024 else { throw failure(sizing.status) }
        var output = Data(count: sizing.needed)
        let result = output.withUnsafeMutableBytes { bytes in
            body(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count)
        }
        guard result.status == HAJIMI_CODEC_OK, result.written <= output.count else { throw failure(result.status) }
        if result.written < output.count { output.removeLast(output.count - result.written) }
        return output
    }
    static func parseHTTP(_ input: Data) throws -> hajimi_http_request {
        var request = hajimi_http_request()
        let result = input.withUnsafeBytes { bytes in
            hajimi_http_parse_request(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                     bytes.count, 0, &request)
        }
        guard result.status == HAJIMI_CODEC_OK else { throw failure(result.status) }
        return request
    }
    static func rewriteHTTP(_ input: Data, upstream: ProxyPolicy?) throws -> Data {
        let authorization: Data
        if let username = upstream?.parameters["username"] ?? upstream?.username {
            let password = upstream?.parameters["password"] ?? upstream?.password ?? ""
            authorization = try Data(username.utf8).withUnsafeBytes { user in
                try Data(password.utf8).withUnsafeBytes { pass in
                    let u = user.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    let p = pass.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    let count = hajimi_cpp_http_basic_authorization(u, user.count, p, pass.count, nil, 0)
                    guard count > 0 else { throw NativeOutboundError.protocolError("HTTP 上游凭据过长或无效") }
                    var result = Data(count: count)
                    result.withUnsafeMutableBytes { output in
                        _ = hajimi_cpp_http_basic_authorization(u, user.count, p, pass.count,
                            output.baseAddress?.assumingMemoryBound(to: UInt8.self), output.count)
                    }
                    return result
                }
            }
        } else { authorization = Data() }
        return try input.withUnsafeBytes { bytes in
            try authorization.withUnsafeBytes { auth in
                try encode { out, capacity in
                    hajimi_http_rewrite_request(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        bytes.count, 0, upstream == nil ? 0 : 1,
                        auth.baseAddress?.assumingMemoryBound(to: UInt8.self), auth.count,
                        out, capacity, nil)
                }
            }
        }
    }
    static func vless(uuid: UUID, target: RequestTarget, command: UInt8, addons: Data) throws -> Data {
        var uuid = uuid.uuid
        var destination = try address(host: target.host, port: target.port)
        return try withUnsafeBytes(of: &uuid) { identifier in
            try addons.withUnsafeBytes { extra in
                try withUnsafePointer(to: &destination) { pointer in
                    try encode { out, capacity in
                        hajimi_vless_encode_request(identifier.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            extra.baseAddress?.assumingMemoryBound(to: UInt8.self), extra.count,
                            command, command == 3 ? nil : pointer, out, capacity)
                    }
                }
            }
        }
    }
    static func trojan(digest: String, target: RequestTarget, udp: Bool) throws -> Data {
        var destination = try address(host: target.host, port: target.port)
        return try Data(digest.utf8).withUnsafeBytes { hash in
            guard hash.count == 56 else { throw failure(Int32(HAJIMI_CODEC_INVALID)) }
            return try encode { out, capacity in
                hajimi_trojan_encode_request(hash.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                            udp ? 3 : 1, &destination, out, capacity)
            }
        }
    }
    static func parseSOCKSUDP(_ input: Data) throws -> (RequestTarget, Data) {
        var frame = hajimi_udp_frame()
        let result = input.withUnsafeBytes { bytes in
            hajimi_socks5_parse_udp(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count, &frame)
        }
        guard result.status == HAJIMI_CODEC_OK else { throw failure(result.status) }
        let start = input.startIndex + frame.payload_offset
        return (RequestTarget(host: host(frame.target), port: frame.target.port, protocolName: "UDP"),
                Data(input[start..<(start + frame.payload_length)]))
    }
    static func encodeSOCKSUDP(target: RequestTarget, payload: Data) throws -> Data {
        var destination = try address(host: target.host, port: target.port)
        return try payload.withUnsafeBytes { value in
            try encode { output, capacity in
                hajimi_socks5_encode_udp(&destination,
                    value.baseAddress?.assumingMemoryBound(to: UInt8.self), value.count, output, capacity)
            }
        }
    }
    static func socksReply(code: UInt8 = 0, host: String = "0.0.0.0", port: UInt16 = 0) throws -> Data {
        try Data(host.utf8).withUnsafeBytes { name in
            let pointer = name.baseAddress?.assumingMemoryBound(to: UInt8.self)
            let count = hajimi_cpp_socks5_reply(code, pointer, name.count, port, nil, 0)
            guard count > 0 else { throw NativeOutboundError.protocolError("SOCKS5 回复地址无效") }
            var result = Data(count: count)
            result.withUnsafeMutableBytes { output in
                _ = hajimi_cpp_socks5_reply(code, pointer, name.count, port,
                    output.baseAddress?.assumingMemoryBound(to: UInt8.self), output.count)
            }
            return result
        }
    }
}

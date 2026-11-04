import Foundation
import HajimiDNS

// MARK: - Frontier Encrypted DNS Endpoints (RFC 9250 DoQ & RFC 9230 ODoH)

public enum ProxyTCPDNSResolverSelfTest {
    public static func run() throws { try EncryptedDNSSelfTest.proxyTCPConnectionPool() }
}

/// RFC 9250 DNS over Dedicated QUIC Connections (DoQ) endpoint.
/// Uses `quic://host[:port][#bootstrap-ip]` with default UDP port 853 and ALPN `"doq"`.
/// All DoQ queries normalize the wire DNS Message ID to 0x0000 per RFC 9250 §4.2.1
/// and frame each message with a 2-octet big-endian length prefix per RFC 9250 §4.2.
public struct DoQEndpoint: Equatable {
    public var host: String
    public var port: UInt16
    public var bootstrapAddress: String?
    public var alpn: [String] { ["doq"] }

    public init?(_ raw: String) {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              value.lowercased().hasPrefix("quic://") else { return nil }
        value.removeFirst(7)
        var bootstrap: String?
        if let hash = value.lastIndex(of: "#") {
            bootstrap = String(value[value.index(after: hash)...])
            value = String(value[..<hash])
        }
        var parsedPort: UInt16 = 853
        if value.hasPrefix("["), let close = value.firstIndex(of: "]") {
            let inner = String(value[value.index(after: value.startIndex)..<close])
            let suffix = value[value.index(after: close)...]
            if !suffix.isEmpty {
                guard suffix.first == ":", let p = UInt16(suffix.dropFirst()), p > 0 else { return nil }
                parsedPort = p
            }
            value = inner
        } else if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":") {
            guard let p = UInt16(value[value.index(after: colon)...]), p > 0 else { return nil }
            parsedPort = p
            value = String(value[..<colon])
        }
        guard DoHEndpoint.isValidServerName(value) else { return nil }
        if let bootstrap, !DoHEndpoint.isAddressLiteral(bootstrap) { return nil }
        if bootstrap == nil, !DoHEndpoint.isAddressLiteral(value) {
            guard let known = EncryptedDNSBootstrap.address(for: value) else { return nil }
            bootstrap = known
        }
        host = value
        port = parsedPort
        bootstrapAddress = bootstrap.map(DoHEndpoint.unbracketed)
    }

    public var connectHost: String { DoHEndpoint.unbracketed(bootstrapAddress ?? host) }

    public func encodeFrame(_ query: Data) -> (frame: Data, originalID: UInt16)? {
        DNSMessageInspection.encodeDoQFrame(query)
    }

    public static func decodeFrame(_ frame: Data, expectedClientID: UInt16) -> Data? {
        DNSMessageInspection.decodeDoQFrame(frame, expectedClientID: expectedClientID)
    }
}

/// RFC 9230 Oblivious DNS over HTTPS (ODoH) endpoint pair.
/// Enforces strict separation between the Oblivious Proxy (which sees the client IP
/// but only HPKE-encrypted ciphertext) and the Oblivious Target (which decrypts the
/// DNS query without seeing the client IP). Co-locating proxy and target on the
/// same host identity or dial IP is rejected to prevent trivial correlation.
public struct ODoHEndpoint: Equatable {
    public static let contentType = "application/oblivious-dns-message"
    public let proxy: DoHEndpoint
    public let target: DoHEndpoint

    public init?(proxy: DoHEndpoint, target: DoHEndpoint) {
        let proxyHost = proxy.host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let targetHost = target.host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard proxyHost != targetHost,
              proxy.connectHost.lowercased() != target.connectHost.lowercased() else { return nil }
        self.proxy = proxy
        self.target = target
    }

    /// Builds the RFC 9230 §4.1 Oblivious Proxy request path with `targethost` and `targetpath` query parameters.
    public var proxyRequestPathWithTarget: String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&+=?")
        let encodedHost = target.host.addingPercentEncoding(withAllowedCharacters: allowed) ?? target.host
        let targetPath = target.url.path.isEmpty ? "/dns-query" : target.url.path
        let encodedPath = targetPath.addingPercentEncoding(withAllowedCharacters: allowed) ?? targetPath
        let basePath = proxy.url.path.isEmpty ? "/dns-query" : proxy.url.path
        let sep = proxy.url.query == nil ? "?" : "&"
        let existingQuery = proxy.url.query.map { "?\($0)" } ?? ""
        return "\(basePath)\(existingQuery)\(sep)targethost=\(encodedHost)&targetpath=\(encodedPath)"
    }

    /// RFC 9230 §6 `ObliviousDoHMessagePlaintext` wire encoding:
    /// `uint16 dns_message_len || dns_message || uint16 padding_len || zeros`.
    public static func encodePlaintext(dnsMessage: Data, paddingLength: Int = 0) -> Data? {
        guard dnsMessage.count >= 12, dnsMessage.count <= 65535,
              paddingLength >= 0, paddingLength <= 65535 else { return nil }
        var out = Data(capacity: 4 + dnsMessage.count + paddingLength)
        out.append(UInt8((dnsMessage.count >> 8) & 0xff))
        out.append(UInt8(dnsMessage.count & 0xff))
        out.append(dnsMessage)
        out.append(UInt8((paddingLength >> 8) & 0xff))
        out.append(UInt8(paddingLength & 0xff))
        if paddingLength > 0 { out.append(Data(repeating: 0, count: paddingLength)) }
        return out
    }

    /// Decodes an RFC 9230 §6 `ObliviousDoHMessagePlaintext` and validates zero padding.
    public static func decodePlaintext(_ data: Data) -> Data? {
        let bytes = Array(data)
        guard bytes.count >= 4 else { return nil }
        let msgLen = (Int(bytes[0]) << 8) | Int(bytes[1])
        guard msgLen >= 12, 2 + msgLen + 2 <= bytes.count else { return nil }
        let padOffset = 2 + msgLen
        let padLen = (Int(bytes[padOffset]) << 8) | Int(bytes[padOffset + 1])
        guard padOffset + 2 + padLen == bytes.count else { return nil }
        for i in (padOffset + 2)..<bytes.count where bytes[i] != 0 { return nil }
        return Data(bytes[2..<(2 + msgLen)])
    }

    /// RFC 9230 §6 `ObliviousDoHMessage` binary framing (`message_type` 0x01 = query, 0x02 = response).
    public static func encodeWireMessage(messageType: UInt8, keyIDOrNonce: Data, encryptedMessage: Data) -> Data? {
        guard (messageType == 0x01 || messageType == 0x02),
              keyIDOrNonce.count <= 65535,
              !encryptedMessage.isEmpty, encryptedMessage.count <= 65535 else { return nil }
        var out = Data(capacity: 5 + keyIDOrNonce.count + encryptedMessage.count)
        out.append(messageType)
        out.append(UInt8((keyIDOrNonce.count >> 8) & 0xff))
        out.append(UInt8(keyIDOrNonce.count & 0xff))
        out.append(keyIDOrNonce)
        out.append(UInt8((encryptedMessage.count >> 8) & 0xff))
        out.append(UInt8(encryptedMessage.count & 0xff))
        out.append(encryptedMessage)
        return out
    }

    public static func decodeWireMessage(_ data: Data) -> (messageType: UInt8, keyIDOrNonce: Data, encryptedMessage: Data)? {
        let bytes = Array(data)
        guard bytes.count >= 5 else { return nil }
        let msgType = bytes[0]
        guard msgType == 0x01 || msgType == 0x02 else { return nil }
        let idLen = (Int(bytes[1]) << 8) | Int(bytes[2])
        guard 3 + idLen + 2 <= bytes.count else { return nil }
        let encOffset = 3 + idLen
        let encLen = (Int(bytes[encOffset]) << 8) | Int(bytes[encOffset + 1])
        guard encLen > 0, encOffset + 2 + encLen == bytes.count else { return nil }
        return (
            msgType,
            Data(bytes[3..<(3 + idLen)]),
            Data(bytes[(encOffset + 2)..<bytes.count])
        )
    }
}

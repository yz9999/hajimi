import Foundation
import Network
import Security
import Darwin

/// DNS over HTTPS (RFC 8484).
///
/// Plain UDP DNS is the weakest link left in the data plane: fake-IP keeps
/// proxied names off the local resolver, but anything routed direct still asks
/// an upstream in the clear, and an on-path answer is accepted as readily as a
/// genuine one. DoH removes that: the query travels inside TLS to a named
/// Bootstrap addresses for endpoints whose provider publishes stable ones.
///
/// A DoH or DoT endpoint named by hostname cannot be reached without first
/// resolving that hostname, and the only resolver available to do it is the one
/// being replaced. On this platform the circularity is worse than theoretical:
/// with the tunnel up the system resolver answers with a fake-IP, so the
/// bootstrap query would be routed into the very tunnel that depends on it and
/// fail with nothing to diagnose.
///
/// Requiring the user to type an address for `dns.google` is technically
/// correct and practically useless, so the well-known ones are built in. Each
/// address below was checked the way it will actually be used: open TLS to the
/// address with the endpoint's hostname as SNI, then complete an RFC 8484
/// query. Reachability alone is not enough — the certificate has to match the
/// name, or the connection this bootstrap enables would be refused.
public enum EncryptedDNSBootstrap {
    static let table: [String: [String]] = [
        "dns.google": ["8.8.8.8", "8.8.4.4"],
        "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"],
        "one.one.one.one": ["1.1.1.1", "1.0.0.1"],
        "mozilla.cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"],
        "doh.pub": ["1.12.12.12", "120.53.53.53"],
        "dot.pub": ["1.12.12.12", "120.53.53.53"],
        "dns.alidns.com": ["223.5.5.5", "223.6.6.6"],
        "dns.quad9.net": ["9.9.9.9", "149.112.112.112"],
        "dns.adguard-dns.com": ["94.140.14.14", "94.140.15.15"],
        "dns.sb": ["185.222.222.222", "45.11.45.11"],
        "doh.dns.sb": ["185.222.222.222", "45.11.45.11"],
    ]

    /// The address to dial for `host`, or nil if the user must supply one.
    public static func address(for host: String) -> String? {
        table[host.lowercased()]?.first
    }

    /// Provider names carrying a built-in address, for error messages that
    /// would otherwise send the user looking for something they cannot guess.
    public static var knownHosts: [String] { table.keys.sorted() }
}

/// endpoint, and a forged reply cannot be produced without the endpoint's key.
public struct DoHEndpoint: Equatable {
    public var url: URL
    /// Host to connect to when the URL's host is a name rather than a literal.
    ///
    /// Resolving the endpoint through the resolver it is meant to replace would
    /// hand an attacker the same control, so a named endpoint must come with an
    /// address to reach it at.
    public var bootstrapAddress: String?

    public var host: String { url.host ?? "" }
    public var port: UInt16 { UInt16(url.port ?? 443) }

    /// Accepts `https://host/path`, optionally suffixed with `#bootstrap-ip`.
    public init?(_ raw: String) {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        var bootstrap: String?
        if let hash = value.lastIndex(of: "#") {
            bootstrap = String(value[value.index(after: hash)...])
                .trimmingCharacters(in: .whitespaces)
            value = String(value[..<hash])
        }
        guard let parsed = URL(string: value), parsed.scheme?.lowercased() == "https",
              let host = parsed.host, !host.isEmpty, !parsed.path.isEmpty,
              (1...65_535).contains(parsed.port ?? 443) else { return nil }
        // A hostname here would reintroduce the bootstrap DNS dependency.
        if let bootstrap, !Self.isAddressLiteral(bootstrap) { return nil }
        // A literal address needs no bootstrap and is the safest form. A named
        // one falls back to the built-in table before being rejected.
        if bootstrap == nil, !DoHEndpoint.isAddressLiteral(host) {
            guard let known = EncryptedDNSBootstrap.address(for: host) else { return nil }
            bootstrap = known
        }
        url = parsed
        bootstrapAddress = bootstrap
    }

    static func isAddressLiteral(_ host: String) -> Bool {
        var ipv4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return true }
        var ipv6 = in6_addr()
        return host.withCString { inet_pton(AF_INET6, $0, &ipv6) } == 1
    }

    /// The address a connection should actually be opened to.
    public var connectHost: String { bootstrapAddress ?? host }
}

/// DoH over HTTPS. URLSession retains its connection pooling for literal-IP
/// endpoints outside Enhanced Mode. With a physical interface bound, even
/// literal addresses need a direct socket; URLSession would follow the utun
/// default route and re-enter the proxy. Named endpoints always use a direct,
/// certificate-checked connection to their bootstrap IP.
public final class DoHResolver {
    private let endpoint: DoHEndpoint
    private let session: URLSession?
    private let bootstrapTimeout: DispatchTimeInterval
    private let bootstrapQueue = DispatchQueue(label: "app.hajimi.dns.doh-bootstrap",
                                               qos: .utility)
    private let lock = NSLock()
    private var bootstrapRequests: [UUID: DoHBootstrapRequest] = [:]

    public convenience init(endpoint: DoHEndpoint) {
        self.init(endpoint: endpoint, bootstrapTimeout: .seconds(8))
    }

    /// A shorter deadline makes the loopback TLS-failure test deterministic:
    /// Network.framework may wait for its own handshake timer after the plain
    /// TCP test server closes, while production retains the normal 8 s limit.
    fileprivate init(endpoint: DoHEndpoint, bootstrapTimeout: DispatchTimeInterval) {
        self.endpoint = endpoint
        self.bootstrapTimeout = bootstrapTimeout
        guard endpoint.bootstrapAddress == nil else {
            session = nil
            return
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 6
        configuration.timeoutIntervalForResource = 8
        configuration.httpAdditionalHeaders = [
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message",
        ]
        // The system proxy must not be consulted: this runs inside the data
        // plane that would be answering for it.
        configuration.connectionProxyDictionary = [:]
        session = URLSession(configuration: configuration)
    }

    deinit {
        session?.invalidateAndCancel()
        lock.lock()
        let active = Array(bootstrapRequests.values)
        bootstrapRequests.removeAll()
        lock.unlock()
        active.forEach { $0.cancel() }
    }

    /// `query` and the result are both raw DNS wire messages, so this drops
    /// straight into the UDP path.
    public func resolve(query: Data, completion: @escaping (Data?) -> Void) {
        guard (12...65_535).contains(query.count) else { completion(nil); return }
        let physicalInterface = ProxyEngine.currentOutboundInterface
        if Self.needsDirectTLS(endpoint: endpoint, physicalInterfaceBound: physicalInterface != nil) {
            // Keep the URL hostname as SNI/certificate identity and HTTP Host,
            // but never look it up or follow an enhanced-mode route into utun.
            guard DoHEndpoint.isAddressLiteral(endpoint.connectHost) else {
                completion(nil); return
            }
            let id = UUID()
            guard let request = DoHBootstrapRequest(endpoint: endpoint, query: query,
                                                    physicalInterface: physicalInterface,
                                                    queue: bootstrapQueue, timeout: bootstrapTimeout,
                                                    completion: { [weak self] answer in
                if let self {
                    self.lock.lock()
                    self.bootstrapRequests.removeValue(forKey: id)
                    self.lock.unlock()
                }
                completion(answer)
            }) else { completion(nil); return }
            lock.lock()
            // A broken upstream must not grow an unbounded number of TLS
            // handshakes or retain an unbounded number of DNS queries.
            guard bootstrapRequests.count < 128 else {
                lock.unlock()
                completion(nil)
                return
            }
            bootstrapRequests[id] = request
            lock.unlock()
            request.start()
            return
        }
        guard let session else { completion(nil); return }
        var request = URLRequest(url: endpoint.url)
        request.httpMethod = "POST"
        request.httpBody = query
        session.dataTask(with: request) { data, response, _ in
            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode),
                  let data, (12...65_535).contains(data.count) else {
                completion(nil); return
            }
            completion(data)
        }.resume()
    }

    fileprivate static func needsDirectTLS(endpoint: DoHEndpoint,
                                            physicalInterfaceBound: Bool) -> Bool {
        endpoint.bootstrapAddress != nil || physicalInterfaceBound
    }
}

/// One bounded HTTP/1.1 transaction over TLS to the literal endpoint IP (or
/// the IP supplied as bootstrap). Network.framework's TLS server-name option sets the hostname
/// used for the default system certificate/trust evaluation (macOS 13 SDK).
private final class DoHBootstrapRequest {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let timeout: DispatchTimeInterval
    private let requestBytes: Data
    private var response = DoHHTTPResponseParser()
    private var completion: ((Data?) -> Void)?
    private var sent = false

    init?(endpoint: DoHEndpoint, query: Data, physicalInterface: NWInterface?,
          queue: DispatchQueue, timeout: DispatchTimeInterval,
          completion: @escaping (Data?) -> Void) {
        guard let port = NWEndpoint.Port(rawValue: endpoint.port),
              let bytes = DoHHTTPWire.request(endpoint: endpoint, query: query) else { return nil }
        self.queue = queue
        self.timeout = timeout
        self.completion = completion
        requestBytes = bytes

        let tls = NWProtocolTLS.Options()
        // When the URL itself contains an IP, Network.framework already uses
        // that endpoint for certificate verification and need not put an IP
        // literal into the TLS SNI extension. For a named URL dialled by IP,
        // explicitly override the bootstrap IP with the original DNS name.
        if endpoint.bootstrapAddress != nil || !DoHEndpoint.isAddressLiteral(endpoint.host) {
            endpoint.host.withCString {
                sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, $0)
            }
        }
        "http/1.1".withCString {
            sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, $0)
        }
        let parameters = NWParameters(tls: tls, tcp: .init())
        // The system default route may point back into this tunnel. Pin the
        // bootstrap socket to the physical link when Enhanced Mode is active.
        parameters.requiredInterface = physicalInterface
        connection = NWConnection(host: NWEndpoint.Host(endpoint.connectHost),
                                  port: port, using: parameters)
    }

    func start() {
        queue.async { [self] in
            connection.stateUpdateHandler = { [weak self] state in
                guard let self, self.completion != nil else { return }
                switch state {
                case .ready:
                    guard !self.sent else { return }
                    self.sent = true
                    self.connection.send(content: self.requestBytes,
                                         completion: .contentProcessed { [weak self] error in
                        guard let self else { return }
                        if error != nil { self.finish(nil) }
                        else { self.read() }
                    })
                case .failed, .cancelled:
                    self.finish(nil)
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                self?.finish(nil)
            }
        }
    }

    func cancel() { queue.async { [self] in finish(nil) } }

    private func read() {
        guard completion != nil else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 32_768) {
            [weak self] data, _, complete, error in
            guard let self, self.completion != nil else { return }
            guard error == nil else { self.finish(nil); return }
            switch self.response.ingest(data ?? Data(), endOfStream: complete) {
            case .pending:
                if complete { self.finish(nil) }
                else { self.read() }
            case .answer(let answer): self.finish(answer)
            case .invalid: self.finish(nil)
            }
        }
    }

    private func finish(_ answer: Data?) {
        guard let done = completion else { return }
        completion = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        done(answer)
    }
}

private enum DoHHTTPWire {
    static func request(endpoint: DoHEndpoint, query: Data) -> Data? {
        guard let components = URLComponents(url: endpoint.url, resolvingAgainstBaseURL: false),
              let host = endpoint.url.host, !host.isEmpty else { return nil }
        var target = components.percentEncodedPath
        guard target.hasPrefix("/") else { return nil }
        if let query = components.percentEncodedQuery { target += "?" + query }
        let authority = (host.contains(":") ? "[\(host)]" : host)
            + (endpoint.url.port.map { ":\($0)" } ?? "")
        let headers = "POST \(target) HTTP/1.1\r\n"
            + "Host: \(authority)\r\n"
            + "Accept: application/dns-message\r\n"
            + "Content-Type: application/dns-message\r\n"
            + "Content-Length: \(query.count)\r\n"
            + "Connection: close\r\n\r\n"
        var bytes = Data(headers.utf8)
        bytes.append(query)
        return bytes
    }
}

/// DNS wire responses are at most 65535 bytes. Bound both response headers
/// and the total wire stream, including chunk framing, before buffering it.
private struct DoHHTTPResponseParser {
    enum Result {
        case pending
        case answer(Data)
        case invalid
    }

    private enum Framing {
        case header
        case fixed(Int)
        case chunkSize
        case chunkBody(Int)
        case chunkCRLF
        case trailers
        case untilClose
    }

    private static let maxBody = 65_535
    private static let maxHeader = 16_384
    private static let maxWire = 196_608
    private let crlf = Data([13, 10])
    private let headerEnd = Data([13, 10, 13, 10])
    private var buffer = Data()
    private var body = Data()
    private var framing: Framing = .header
    private var wireBytes = 0

    mutating func ingest(_ input: Data, endOfStream: Bool) -> Result {
        guard input.count <= Self.maxWire - wireBytes else { return .invalid }
        wireBytes += input.count
        buffer.append(input)
        while true {
            switch framing {
            case .header:
                guard let end = buffer.range(of: headerEnd) else {
                    return buffer.count > Self.maxHeader || endOfStream ? .invalid : .pending
                }
                guard end.lowerBound - buffer.startIndex <= Self.maxHeader,
                      let head = String(data: buffer[buffer.startIndex..<end.lowerBound],
                                        encoding: .utf8) else { return .invalid }
                discardBytes(end.upperBound - buffer.startIndex)
                let lines = head.components(separatedBy: "\r\n")
                guard let statusLine = lines.first,
                      statusLine.hasPrefix("HTTP/1."),
                      let status = Int(statusLine.split(separator: " ", maxSplits: 2)
                        .dropFirst().first ?? ""), (200...299).contains(status) else { return .invalid }
                var headers: [String: String] = [:]
                for line in lines.dropFirst() {
                    guard let colon = line.firstIndex(of: ":") else { return .invalid }
                    headers[String(line[..<colon]).lowercased()] =
                        line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                }
                if let encoding = headers["transfer-encoding"] {
                    guard encoding.lowercased() == "chunked" else { return .invalid }
                    framing = .chunkSize
                } else if let raw = headers["content-length"] {
                    guard !raw.isEmpty, raw.utf8.allSatisfy({ (48...57).contains($0) }),
                          let count = Int(raw), count <= Self.maxBody else { return .invalid }
                    framing = .fixed(count)
                } else {
                    framing = .untilClose
                }

            case .fixed(let remaining):
                let count = min(buffer.count, remaining)
                let part = consume(count)
                guard appendBody(part) else { return .invalid }
                let left = remaining - count
                if left == 0 { return answer() }
                framing = .fixed(left)
                return endOfStream ? .invalid : .pending

            case .chunkSize:
                guard let end = buffer.range(of: crlf) else {
                    return buffer.count > Self.maxHeader || endOfStream ? .invalid : .pending
                }
                guard end.lowerBound - buffer.startIndex <= Self.maxHeader else { return .invalid }
                let raw = String(decoding: buffer[buffer.startIndex..<end.lowerBound], as: UTF8.self)
                let size = raw.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
                    .first.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
                guard !size.isEmpty, let count = Int(size, radix: 16),
                      count <= Self.maxBody - body.count else { return .invalid }
                discardBytes(end.upperBound - buffer.startIndex)
                framing = count == 0 ? .trailers : .chunkBody(count)

            case .chunkBody(let remaining):
                let count = min(buffer.count, remaining)
                let part = consume(count)
                guard appendBody(part) else { return .invalid }
                let left = remaining - count
                framing = left == 0 ? .chunkCRLF : .chunkBody(left)
                if left > 0 { return endOfStream ? .invalid : .pending }

            case .chunkCRLF:
                guard buffer.count >= 2 else { return endOfStream ? .invalid : .pending }
                guard buffer[buffer.startIndex] == 13,
                      buffer[buffer.startIndex + 1] == 10 else { return .invalid }
                discardBytes(2)
                framing = .chunkSize

            case .trailers:
                if buffer.count >= 2, buffer[buffer.startIndex] == 13,
                   buffer[buffer.startIndex + 1] == 10 {
                    discardBytes(2)
                    return answer()
                }
                guard let end = buffer.range(of: headerEnd) else {
                    return buffer.count > Self.maxHeader || endOfStream ? .invalid : .pending
                }
                guard end.lowerBound - buffer.startIndex <= Self.maxHeader else { return .invalid }
                discardBytes(end.upperBound - buffer.startIndex)
                return answer()

            case .untilClose:
                let part = consume(buffer.count)
                guard appendBody(part) else { return .invalid }
                return endOfStream ? answer() : .pending
            }
        }
    }

    private mutating func appendBody(_ data: Data) -> Bool {
        guard data.count <= Self.maxBody - body.count else { return false }
        body.append(data)
        return true
    }

    private mutating func consume(_ count: Int) -> Data {
        let start = buffer.startIndex
        let end = start + count
        let prefix = Data(buffer[start..<end])
        buffer = Data(buffer[end...])
        return prefix
    }

    private mutating func discardBytes(_ count: Int) {
        buffer = Data(buffer[(buffer.startIndex + count)...])
    }

    private func answer() -> Result { body.count >= 12 ? .answer(body) : .invalid }
}

/// Adapts a `DoHResolver` to the datagram interface the tunnel already speaks.
public final class DoHRoutedDatagram: NativeRoutedDatagram {
    private let resolver: DoHResolver
    private let receiveHandler: (Data) -> Void
    private let lock = NSLock()
    private var cancelled = false

    public init(resolver: DoHResolver, receive: @escaping (Data) -> Void) {
        self.resolver = resolver
        receiveHandler = receive
    }

    public func send(_ data: Data) {
        resolver.resolve(query: data) { [weak self] answer in
            guard let self, let reply = answer ?? DoHFailureResponse.reply(to: data) else { return }
            self.lock.lock(); let stopped = self.cancelled; self.lock.unlock()
            guard !stopped else { return }
            self.receiveHandler(reply)
        }
    }

    public func cancel() {
        lock.lock(); cancelled = true; lock.unlock()
    }
}

/// Report an authenticated resolver outage as SERVFAIL, rather than leaving
/// the local DNS client waiting for an answer that cannot arrive.
private enum DoHFailureResponse {
    static func reply(to query: Data) -> Data? {
        guard query.count >= 17,
              query[query.startIndex + 2] & 0xF8 == 0,
              query[query.startIndex + 4] == 0, query[query.startIndex + 5] == 1 else {
            return nil
        }
        var end = query.startIndex + 12
        var foundEnd = false
        while end < query.endIndex {
            let count = Int(query[end])
            guard count <= 63, end + 1 + count <= query.endIndex,
                  end - query.startIndex <= 255 else { return nil }
            end += 1 + count
            if count == 0 { foundEnd = true; break }
        }
        guard foundEnd, end + 4 <= query.endIndex else { return nil }
        var reply = Data(query[query.startIndex..<(end + 4)])
        // QR=1, RA=1, RCODE=SERVFAIL; keep the client's RD bit.
        reply[reply.startIndex + 2] = 0x80 | (query[query.startIndex + 2] & 0x01)
        reply[reply.startIndex + 3] = 0x82
        // Preserve the single question; clear answer/authority/EDNS counts.
        for index in 6..<12 { reply[reply.startIndex + index] = 0 }
        return reply
    }
}

// MARK: - Self-test

public enum EncryptedDNSSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "加密 DNS 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try endpointParsing()
        try dotEndpointParsing()
        try wireFormatCompatibility()
        try bootstrapHTTPWire()
        try bootstrapHTTPResponseParsing()
        try bootstrapLoopbackDialAndSNI()
    }

    private static func endpointParsing() throws {
        // An address literal is self-sufficient.
        guard let literal = DoHEndpoint("https://1.1.1.1/dns-query") else {
            throw Failure(text: "字面地址端点解析失败")
        }
        try expect(literal.host == "1.1.1.1" && literal.port == 443, "主机/端口解析错误")
        try expect(literal.connectHost == "1.1.1.1", "连接目标错误")
        try expect(literal.bootstrapAddress == nil, "字面地址不应需要 bootstrap")

        // A named endpoint is only accepted with an address to reach it at:
        // resolving it through the resolver it replaces would hand an attacker
        // the same control the feature exists to remove.
        try expect(DoHEndpoint("https://doh.example.org/dns-query") == nil,
                   "表外域名端点在无 bootstrap 时未被拒绝")
        guard let named = DoHEndpoint("https://doh.example.org/dns-query#8.8.8.8") else {
            throw Failure(text: "带 bootstrap 的端点解析失败")
        }
        try expect(named.host == "doh.example.org", "域名端点主机解析错误")
        try expect(named.connectHost == "8.8.8.8", "bootstrap 未生效")

        // Well-known providers carry their own address. Requiring the user to
        // type one for dns.google is correct and useless in equal measure.
        guard let builtIn = DoHEndpoint("https://dns.google/dns-query") else {
            throw Failure(text: "内置 bootstrap 的提供商未被接受")
        }
        try expect(builtIn.host == "dns.google", "内置端点主机错误")
        try expect(builtIn.connectHost == "8.8.8.8",
                   "内置 bootstrap 为 \(builtIn.connectHost)，应为 8.8.8.8")
        // The certificate is checked against the name, not the address, so the
        // host must survive; losing it would silently disable that check.
        try expect(builtIn.url.host == "dns.google", "内置 bootstrap 覆盖了 SNI 名称")

        // An explicit address always wins: a user pinning their own resolver
        // must not be quietly redirected to ours.
        guard let overridden = DoHEndpoint("https://dns.google/dns-query#1.1.1.1") else {
            throw Failure(text: "显式 bootstrap 覆盖失败")
        }
        try expect(overridden.connectHost == "1.1.1.1", "显式 bootstrap 未覆盖内置值")

        try expect(DoHEndpoint("https://DNS.GOOGLE/dns-query")?.connectHost == "8.8.8.8",
                   "内置表未做大小写归一")
        for host in EncryptedDNSBootstrap.knownHosts {
            try expect(DoHEndpoint("https://\(host)/dns-query") != nil,
                       "内置提供商 \(host) 未被接受")
        }

        try expect(DoHEndpoint("http://1.1.1.1/dns-query") == nil, "明文 HTTP 端点未被拒绝")
        try expect(DoHEndpoint("1.1.1.1") == nil, "普通 UDP 地址不应被当作 DoH")
        try expect(DoHEndpoint("https://1.1.1.1") == nil, "缺少路径的端点未被拒绝")
        try expect(DoHEndpoint("") == nil, "空字符串未被拒绝")
        try expect(DoHEndpoint("https://dns.google/dns-query#other.example") == nil,
                   "bootstrap 只能是 IP 地址，否则仍会递归解析")
        try expect(DoHEndpoint("https://dns.google:65536/dns-query") == nil,
                   "超出范围的 DoH 端口未被拒绝")

        guard let ported = DoHEndpoint("https://1.1.1.1:8443/dns-query") else {
            throw Failure(text: "带端口的端点解析失败")
        }
        try expect(ported.port == 8443, "自定义端口解析错误")
    }

    private static func dotEndpointParsing() throws {
        guard let literal = DoTEndpoint("tls://1.1.1.1") else {
            throw Failure(text: "字面地址 DoT 端点解析失败")
        }
        try expect(literal.host == "1.1.1.1" && literal.port == 853, "默认端口应为 853")
        guard let ported = DoTEndpoint("tls://1.1.1.1:8853") else {
            throw Failure(text: "带端口的 DoT 端点解析失败")
        }
        try expect(ported.port == 8853, "自定义端口解析错误")
        guard let v6 = DoTEndpoint("tls://[2606:4700:4700::1111]:853") else {
            throw Failure(text: "IPv6 字面地址端点解析失败")
        }
        try expect(v6.host == "2606:4700:4700::1111" && v6.port == 853,
                   "IPv6 端点解析错误：\(v6.host):\(v6.port)")

        // Same rule as DoH: a name must come with an address, or resolving the
        // resolver hands the attacker the same control.
        try expect(DoTEndpoint("tls://dot.example.org") == nil,
                   "表外域名端点在无 bootstrap 时未被拒绝")
        try expect(DoTEndpoint("tls://dns.google")?.connectHost == "8.8.8.8",
                   "DoT 未使用内置 bootstrap")
        guard let named = DoTEndpoint("tls://dns.google#8.8.8.8") else {
            throw Failure(text: "带 bootstrap 的 DoT 端点解析失败")
        }
        try expect(named.connectHost == "8.8.8.8" && named.host == "dns.google",
                   "bootstrap 未生效，或证书校验会失去正确的名称")
        try expect(DoTEndpoint("https://1.1.1.1/dns-query") == nil, "DoH 地址不应被当作 DoT")
        try expect(DoTEndpoint("1.1.1.1") == nil, "普通地址不应被当作 DoT")
    }

    /// A DoH answer is an ordinary DNS message, so the parser that already
    /// populates the IP→domain map must read it unchanged.
    private static func wireFormatCompatibility() throws {
        let request = FakeIPSelfTest.query("example.com", type: 1)
        guard let question = FakeIPResponder.question(in: request),
              let answer = FakeIPResponder.reply(to: request, question: question,
                                                 address: "93.184.216.34") else {
            throw Failure(text: "无法构造样本应答")
        }
        let records = DNSMessageProbe.addressRecords(in: answer)
        try expect(records.count == 1 && records[0].address == "93.184.216.34",
                   "DoH 线格式与既有解析器不兼容")
    }

    private static func bootstrapHTTPWire() throws {
        guard let endpoint = DoHEndpoint(
            "https://doh.selftest.invalid:18443/dns%2Dquery?key=a%20b#127.0.0.1") else {
            throw Failure(text: "无法构造 bootstrap 请求")
        }
        let query = FakeIPSelfTest.query("example.com", type: 1)
        guard let wire = DoHHTTPWire.request(endpoint: endpoint, query: query),
              let end = wire.range(of: Data("\r\n\r\n".utf8)) else {
            throw Failure(text: "DoH POST 请求未生成")
        }
        let headers = String(decoding: wire[..<end.upperBound], as: UTF8.self)
        try expect(headers.hasPrefix("POST /dns%2Dquery?key=a%20b HTTP/1.1\r\n"),
                   "DoH 原始路径/参数丢失")
        try expect(headers.contains("\r\nHost: doh.selftest.invalid:18443\r\n"),
                   "DoH HTTP Host 被 bootstrap 地址替换")
        try expect(headers.contains("\r\nContent-Length: \(query.count)\r\n"),
                   "DoH DNS 请求长度错误")
        try expect(Data(wire[end.upperBound...]) == query, "DoH 请求体不匹配")
        guard let literal = DoHEndpoint("https://1.1.1.1/dns-query") else {
            throw Failure(text: "字面地址 DoH 端点解析失败")
        }
        try expect(!DoHResolver.needsDirectTLS(endpoint: literal, physicalInterfaceBound: false),
                   "普通模式字面地址应继续复用 URLSession 连接")
        try expect(DoHResolver.needsDirectTLS(endpoint: literal, physicalInterfaceBound: true),
                   "增强模式字面地址必须绑定物理接口，避免自经 utun")
        try expect(DoHResolver.needsDirectTLS(endpoint: endpoint, physicalInterfaceBound: false),
                   "具名端点即使不在增强模式，也必须直连 bootstrap IP")
    }

    private static func bootstrapHTTPResponseParsing() throws {
        let query = FakeIPSelfTest.query("example.com", type: 1)
        guard let failure = DoHFailureResponse.reply(to: query) else {
            throw Failure(text: "DoH 超时未生成 DNS SERVFAIL")
        }
        try expect(failure.prefix(2) == query.prefix(2) && failure[3] & 0x0f == 2,
                   "DoH SERVFAIL 未保留原事务 ID 或状态码")
        guard let question = FakeIPResponder.question(in: query),
              let answer = FakeIPResponder.reply(to: query, question: question,
                                                 address: "93.184.216.34") else {
            throw Failure(text: "无法生成 DoH 回环应答")
        }
        var parser = DoHHTTPResponseParser()
        var response = Data(("HTTP/1.1 200 OK\r\nContent-Length: \(answer.count)\r\n\r\n").utf8)
        response.append(answer)
        var parsed: Data?
        for byte in response {
            switch parser.ingest(Data([byte]), endOfStream: false) {
            case .pending: break
            case .answer(let bytes): parsed = bytes
            case .invalid: throw Failure(text: "分段 Content-Length 应答被拒绝")
            }
        }
        try expect(parsed == answer, "分段 Content-Length 应答未完成")

        parser = DoHHTTPResponseParser()
        response = Data(("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "\(String(answer.count, radix: 16))\r\n").utf8)
        response.append(answer)
        response.append(Data("\r\n0\r\n\r\n".utf8))
        parsed = nil
        for byte in response {
            switch parser.ingest(Data([byte]), endOfStream: false) {
            case .pending: break
            case .answer(let bytes): parsed = bytes
            case .invalid: throw Failure(text: "分段 chunked 应答被拒绝")
            }
        }
        try expect(parsed == answer, "分段 chunked 应答未完成")

        for header in ["Content-Length: -1", "Content-Length: 65536",
                       "Transfer-Encoding: gzip"] {
            var rejected = DoHHTTPResponseParser()
            let result = rejected.ingest(Data("HTTP/1.1 200 OK\r\n\(header)\r\n\r\n".utf8),
                                         endOfStream: false)
            guard case .invalid = result else {
                throw Failure(text: "DoH 非法响应头未被拒绝：\(header)")
            }
        }
    }

    /// Only opens a TCP socket bound to loopback; it does not install a
    /// certificate or change DNS. The TLS ClientHello is enough to prove the
    /// resolver connects to the bootstrap IP and carries the URL host as SNI.
    private static func bootstrapLoopbackDialAndSNI() throws {
        let queue = DispatchQueue(label: "app.hajimi.dns.bootstrap-selftest")
        let parameters = NWParameters.tcp
        parameters.requiredInterfaceType = .loopback
        let listener = try NWListener(using: parameters, on: .any)
        defer { listener.cancel() }
        let ready = DispatchSemaphore(value: 0)
        let accepted = DispatchSemaphore(value: 0)
        let lock = NSLock()
        let serverName = "doh.selftest.invalid"
        var clientHello = Data()

        func capture(_ connection: NWConnection, _ partial: Data) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) {
                data, _, complete, error in
                var next = partial
                if let data { next.append(data) }
                if next.range(of: Data(serverName.utf8)) != nil || next.count >= 4096
                    || complete || error != nil {
                    lock.lock(); clientHello = next; lock.unlock()
                    accepted.signal()
                    connection.cancel()
                } else {
                    capture(connection, next)
                }
            }
        }

        listener.newConnectionHandler = { connection in
            connection.start(queue: queue)
            capture(connection, Data())
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready, .failed: ready.signal()
            default: break
            }
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 3) == .success,
              let port = listener.port else { throw Failure(text: "回环 DNS 监听器未启动") }
        guard let endpoint = DoHEndpoint(
            "https://\(serverName):\(port.rawValue)/dns-query#127.0.0.1") else {
            throw Failure(text: "回环 bootstrap 端点解析失败")
        }
        let resolver = DoHResolver(endpoint: endpoint, bootstrapTimeout: .seconds(2))
        let completed = DispatchSemaphore(value: 0)
        var result: Data?
        resolver.resolve(query: FakeIPSelfTest.query("example.com", type: 1)) {
            result = $0
            completed.signal()
        }
        guard accepted.wait(timeout: .now() + 5) == .success else {
            throw Failure(text: "具名 DoH 端点未连接 127.0.0.1 bootstrap")
        }
        lock.lock(); let hello = clientHello; lock.unlock()
        try expect(hello.range(of: Data(serverName.utf8)) != nil,
                   "DoH TLS ClientHello 缺少原 URL 域名 SNI")
        try expect(completed.wait(timeout: .now() + 5) == .success && result == nil,
                   "无证书的回环服务未被 TLS 拒绝或 DoH 查询未及时结束")
    }
}

// MARK: - DNS over TLS (RFC 7858)

/// A DoT endpoint: `tls://host[:port][#bootstrap]`.
///
/// DoT differs from DoH in what it hides. Both authenticate the answer, but a
/// DoH query is indistinguishable from ordinary HTTPS, while DoT's dedicated
/// port 853 announces what it is. It is offered because some networks permit
/// 853 and interfere with the HTTPS the DoH endpoint would need.
public struct DoTEndpoint: Equatable {
    public var host: String
    public var port: UInt16
    public var bootstrapAddress: String?

    public init?(_ raw: String) {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.lowercased().hasPrefix("tls://") else { return nil }
        value.removeFirst(6)
        var bootstrap: String?
        if let hash = value.lastIndex(of: "#") {
            bootstrap = String(value[value.index(after: hash)...])
                .trimmingCharacters(in: .whitespaces)
            value = String(value[..<hash])
        }
        var parsedPort: UInt16 = 853
        // A bracketed IPv6 literal keeps its own colons out of the port split.
        if value.hasPrefix("["), let close = value.firstIndex(of: "]") {
            let inner = String(value[value.index(after: value.startIndex)..<close])
            let suffix = value[value.index(after: close)...]
            if !suffix.isEmpty {
                guard suffix.first == ":", let p = UInt16(suffix.dropFirst()), p > 0 else {
                    return nil
                }
                parsedPort = p
            }
            value = inner
        } else if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":"),
                  let p = UInt16(value[value.index(after: colon)...]), p > 0 {
            parsedPort = p
            value = String(value[..<colon])
        }
        guard !value.isEmpty else { return nil }
        // The certificate is validated against the name, so a named endpoint
        // still needs an address to reach it at — resolving it through the
        // resolver it replaces would defeat the point.
        if bootstrap == nil, !DoHEndpoint.isAddressLiteral(value) {
            guard let known = EncryptedDNSBootstrap.address(for: value) else { return nil }
            bootstrap = known
        }
        host = value
        port = parsedPort
        bootstrapAddress = bootstrap
    }

    public var connectHost: String { bootstrapAddress ?? host }
}

/// Resolves over a TLS connection, reconnecting as needed.
///
/// The connection is kept for reuse — RFC 7858 expects it — but a DoT server
/// may close an idle one at any time, so a query that fails on a stale
/// connection is retried once on a fresh one rather than surfaced as a
/// resolution failure.
public final class DoTResolver {
    private let endpoint: DoTEndpoint
    private let queue = DispatchQueue(label: "app.hajimi.dns.dot")
    private let lock = NSLock()
    private var connection: NWConnection?
    private var buffer = Data()
    private var pending: [(Data?) -> Void] = []

    public init(endpoint: DoTEndpoint) {
        self.endpoint = endpoint
    }

    deinit { connection?.cancel() }

    public func resolve(query: Data, completion: @escaping (Data?) -> Void) {
        send(query: query, allowRetry: true, completion: completion)
    }

    private func send(query: Data, allowRetry: Bool,
                      completion: @escaping (Data?) -> Void) {
        let connection = ensureConnection()
        lock.lock(); pending.append(completion); lock.unlock()
        // DNS over a stream is length-prefixed; the datagram form is not.
        var framed = Data()
        framed.append(UInt8(truncatingIfNeeded: query.count >> 8))
        framed.append(UInt8(truncatingIfNeeded: query.count))
        framed.append(query)
        connection.send(content: framed, completion: .contentProcessed { [weak self] error in
            guard let self, error != nil else { return }
            self.reset()
            guard allowRetry else { self.failAll(); return }
            self.lock.lock()
            let waiter = self.pending.popLast()
            self.lock.unlock()
            guard let waiter else { return }
            self.send(query: query, allowRetry: false, completion: waiter)
        })
    }

    private func ensureConnection() -> NWConnection {
        lock.lock()
        if let existing = connection { lock.unlock(); return existing }
        let parameters = NWParameters(tls: tlsOptions(), tcp: .init())
        if let interface = ProxyEngine.currentOutboundInterface {
            parameters.requiredInterface = interface
        }
        let created = NWConnection(host: NWEndpoint.Host(endpoint.connectHost),
                                   port: NWEndpoint.Port(rawValue: endpoint.port) ?? 853,
                                   using: parameters)
        connection = created
        lock.unlock()
        created.stateUpdateHandler = { [weak self] state in
            if case .failed = state { self?.reset(); self?.failAll() }
            if case .cancelled = state { self?.reset() }
        }
        created.start(queue: queue)
        receiveLoop(created)
        return created
    }

    /// The certificate is checked against the endpoint's name even when the
    /// connection is opened to a bootstrap address — otherwise the bootstrap
    /// would become an unauthenticated redirect.
    private func tlsOptions() -> NWProtocolTLS.Options {
        let options = NWProtocolTLS.Options()
        if endpoint.bootstrapAddress != nil {
            endpoint.host.withCString { pointer in
                sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, pointer)
            }
        }
        return options
    }

    private func receiveLoop(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_535) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.lock.lock()
                self.buffer.append(data)
                var answers: [Data] = []
                while self.buffer.count >= 2 {
                    let length = Int(self.buffer[self.buffer.startIndex]) << 8
                        | Int(self.buffer[self.buffer.startIndex + 1])
                    guard self.buffer.count >= 2 + length else { break }
                    let start = self.buffer.startIndex + 2
                    answers.append(Data(self.buffer[start..<(start + length)]))
                    self.buffer.removeFirst(2 + length)
                }
                var waiters: [(Data?) -> Void] = []
                for _ in answers where !self.pending.isEmpty {
                    waiters.append(self.pending.removeFirst())
                }
                self.lock.unlock()
                for (waiter, answer) in zip(waiters, answers) { waiter(answer) }
            }
            if error != nil || isComplete { self.reset(); self.failAll(); return }
            self.receiveLoop(connection)
        }
    }

    private func reset() {
        lock.lock()
        connection?.cancel()
        connection = nil
        buffer.removeAll()
        lock.unlock()
    }

    private func failAll() {
        lock.lock()
        let waiters = pending
        pending.removeAll()
        lock.unlock()
        // nil is the caller's signal to fall through to the next configured
        // resolver rather than to treat the name as nonexistent.
        waiters.forEach { $0(nil) }
    }
}

/// Adapts a `DoTResolver` to the tunnel's datagram interface.
public final class DoTRoutedDatagram: NativeRoutedDatagram {
    private let resolver: DoTResolver
    private let receiveHandler: (Data) -> Void
    private let lock = NSLock()
    private var cancelled = false

    public init(resolver: DoTResolver, receive: @escaping (Data) -> Void) {
        self.resolver = resolver
        receiveHandler = receive
    }

    public func send(_ data: Data) {
        resolver.resolve(query: data) { [weak self] answer in
            guard let self, let answer else { return }
            self.lock.lock(); let stopped = self.cancelled; self.lock.unlock()
            guard !stopped else { return }
            self.receiveHandler(answer)
        }
    }

    public func cancel() { lock.lock(); cancelled = true; lock.unlock() }
}

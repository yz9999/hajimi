import Foundation
import HajimiDNS
import Network
import Security
import Darwin

/// A failed encrypted exchange is not blanket permission to disclose its
/// question to a plaintext resolver. Keep network/deadline failures distinct
/// from authentication, policy, admission and malformed-response failures.
/// Unknown errors remain terminal; never infer a downgrade from error text.
enum EncryptedDNSQueryFailure: Error, Equatable, LocalizedError {
    case network, timeout, cancelled, capacity, authentication
    case policy, configuration, invalidResponse, other

    var permitsProxyFallback: Bool {
        self == .network || self == .timeout
    }

    var errorDescription: String? {
        switch self {
        case .network: return "加密 DNS 网络连接失败"
        case .timeout: return "加密 DNS 查询超时"
        case .cancelled: return "加密 DNS 查询已取消"
        case .capacity: return "加密 DNS 连接容量已满"
        case .authentication: return "加密 DNS 或代理身份验证失败"
        case .policy: return "加密 DNS 策略或网络接口已更新"
        case .configuration: return "加密 DNS 配置无效"
        case .invalidResponse: return "加密 DNS 应答无效"
        case .other: return "加密 DNS 查询失败，已禁止隐私降级"
        }
    }

    static func classify(_ error: Error) -> EncryptedDNSQueryFailure {
        if let known = error as? EncryptedDNSQueryFailure { return known }
        if error is DNSQueryTimeoutError { return .timeout }
        if error is NodeConnectionAdmissionError { return .capacity }
        if let bootstrap = error as? TraditionalDNSBootstrapError {
            switch bootstrap {
            case .timeout: return .timeout
            case .cancelled: return .cancelled
            case .capacity: return .capacity
            case .configuration: return .configuration
            case .notAllowed: return .policy
            case .unavailable: return .invalidResponse
            }
        }
        let native = error as NSError
        if native.domain == NodeConnectionAdmissionError.errorDomain,
           native.code == NodeConnectionAdmissionError.capacityExceeded.errorCode { return .capacity }
        if let native = error as? NativeOutboundError {
            switch native {
            case .unsupported: return .configuration
            case .crypto: return .authentication
            case .protocolError: return .invalidResponse
            case .cancelled: return .cancelled
            // These legacy errors also contain authentication and stale
            // route failures. A string match is not a security boundary.
            case .connection: return .other
            }
        }
        if let network = error as? NWError {
            switch network {
            case .tls: return .authentication
            case .dns: return .configuration
            case .posix(let code):
                if code == .ECANCELED { return .cancelled }
                if code == .ETIMEDOUT { return .timeout }
                if [POSIXErrorCode.ECONNREFUSED, .ECONNRESET, .ECONNABORTED,
                    .ENETDOWN, .ENETUNREACH, .EHOSTDOWN, .EHOSTUNREACH,
                    .ENOTCONN, .EPIPE].contains(code) { return .network }
                return .other
            @unknown default: return .other
            }
        }
        if native.domain == NSPOSIXErrorDomain,
           let value = Int32(exactly: native.code), let code = POSIXErrorCode(rawValue: value) {
            return classify(NWError.posix(code))
        }
        if native.domain == "app.hajimi.cpp-protocol" {
            let desc = (native.userInfo[NSLocalizedDescriptionKey] as? String) ?? ""
            if desc == "Mieru UDP session handshake timed out" ||
               desc == "Mieru UDP retransmission limit exceeded" ||
               desc == "C++ protocol connection timed out" ||
               desc == "Sudoku KIP handshake timed out" ||
               desc == "TrustTunnel CONNECT handshake timed out" {
                return .timeout
            }
            if desc == "Mieru UDP socket error" ||
               desc == "Mieru UDP target connection closed by server" ||
               desc == "Mieru UDP dial failed" ||
               desc == "UDP transport send failed" ||
               desc == "UDP transport receive failed" ||
               desc == "Native UDP connection failed" ||
               desc == "UDP transport closed" {
                return .network
            }
            return .other
        }
        if native.domain == NSURLErrorDomain {
            switch native.code {
            case NSURLErrorTimedOut: return .timeout
            case NSURLErrorCancelled: return .cancelled
            case NSURLErrorCannotConnectToHost, NSURLErrorNetworkConnectionLost,
                 NSURLErrorNotConnectedToInternet: return .network
            case NSURLErrorSecureConnectionFailed, NSURLErrorServerCertificateHasBadDate,
                 NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
                 NSURLErrorServerCertificateNotYetValid, NSURLErrorClientCertificateRejected,
                 NSURLErrorClientCertificateRequired: return .authentication
            default: return .other
            }
        }
        return .other
    }
}

/// Bootstrap addresses for endpoints whose provider publishes stable ones.
///
/// An encrypted endpoint must have a literal dial address before transport I/O.
/// The system resolver or application DNS path cannot bootstrap itself through
/// that endpoint: with the tunnel up it may return a fake-IP and create a loop.
/// Known providers carry built-in pins; explicit #IP pins take precedence.
/// Unknown DoH hosts may instead be held deferred during configuration and
/// resolved by TraditionalDNSBootstrapResolver's explicit, host-only allowlist.
/// That does not authorize traditional DNS for ordinary application QNAMEs.
///
/// Requiring the user to type an address for `dns.google` is technically
/// correct and practically useless, so the well-known ones are built in. Each
/// connection still authenticates the endpoint's hostname, not its dial IP.
/// Reachability alone is not enough: the certificate must match that identity.
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

    /// Stable addresses of this same provider; never a different resolver.
    static func addresses(for host: String) -> [String] {
        var normalized = host.lowercased()
        if normalized.hasSuffix(".") { normalized.removeLast() }
        return table[normalized] ?? []
    }

    /// The first address to dial for `host`, or nil if one must be supplied.
    public static func address(for host: String) -> String? { addresses(for: host).first }

    /// Provider names carrying a built-in address, for error messages that
    /// would otherwise send the user looking for something they cannot guess.
    public static var knownHosts: [String] { table.keys.sorted() }
}

/// A DNS-over-HTTPS endpoint. Unknown names can be held unresolved while a
/// caller obtains a purpose-limited bootstrap IP; resolver I/O still requires
/// a literal dial address.
public struct DoHEndpoint: Equatable {
    public var url: URL { didSet { usesAutomaticBootstrapAddress = false } }
    /// Host to connect to when the URL's host is a name rather than a literal.
    ///
    /// Populated by an explicit/built-in pin or purpose-limited traditional
    /// bootstrap. Deferred configuration may leave this nil for an unknown
    /// hostname; DoHResolver still refuses that hostname before any dial.
    public var bootstrapAddress: String? { didSet { usesAutomaticBootstrapAddress = false } }
    /// Only an unpinned named endpoint can inherit its provider's built-in
    /// addresses. Explicit pins and later programmatic overrides stay single.
    public private(set) var usesAutomaticBootstrapAddress = false

    public var host: String { Self.unbracketed(url.host ?? "") }
    public var port: UInt16 { UInt16(exactly: url.port ?? 443) ?? 0 }

    /// Accepts `https://host/path`, optionally suffixed with `#bootstrap-ip`.
    public init?(_ raw: String) {
        self.init(raw, allowUnresolvedHost: false)
    }

    public init?(_ raw: String, allowUnresolvedHost: Bool = false) {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // Keep inline pins unambiguous to profile parsers. URL whitespace must
        // be percent-encoded instead of silently normalized by Foundation.
        guard value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else { return nil }
        var bootstrap: String?
        var automaticBootstrap = false
        if let hash = value.lastIndex(of: "#") {
            bootstrap = String(value[value.index(after: hash)...])
            value = String(value[..<hash])
        }
        guard let parsed = URL(string: value), parsed.scheme?.lowercased() == "https",
              let rawHost = parsed.host, !rawHost.isEmpty, !parsed.path.isEmpty,
              parsed.user == nil, parsed.password == nil,
              (1...65_535).contains(parsed.port ?? 443) else { return nil }
        let host = Self.unbracketed(rawHost)
        guard Self.isValidServerName(host) else { return nil }
        // A hostname here would reintroduce the bootstrap DNS dependency.
        if let bootstrap, !Self.isAddressLiteral(bootstrap) { return nil }
        // A literal address needs no bootstrap and is the safest form. A named
        // one falls back to the built-in table before being rejected.
        if bootstrap == nil, !DoHEndpoint.isAddressLiteral(host) {
            if let known = EncryptedDNSBootstrap.address(for: host) {
                bootstrap = known; automaticBootstrap = true
            } else if !allowUnresolvedHost {
                return nil
            }
        }
        url = parsed
        bootstrapAddress = bootstrap.map(Self.unbracketed)
        usesAutomaticBootstrapAddress = automaticBootstrap
    }

    static func isAddressLiteral(_ host: String) -> Bool {
        let host = unbracketed(host)
        var ipv4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return true }
        var ipv6 = in6_addr()
        return host.withCString { inet_pton(AF_INET6, $0, &ipv6) } == 1
    }

    static func unbracketed(_ host: String) -> String {
        guard host.hasPrefix("["), host.hasSuffix("]") else { return host }
        return String(host.dropFirst().dropLast())
    }

    static func isValidServerName(_ host: String) -> Bool {
        if isAddressLiteral(host) { return true }
        let name = host.hasSuffix(".") ? String(host.dropLast()) : host
        guard !name.isEmpty, name.utf8.count <= 253,
              name.split(separator: ".", omittingEmptySubsequences: false)
                .allSatisfy({ !$0.isEmpty && $0.utf8.count <= 63 }) else { return false }
        return host.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                || $0 == 45 || $0 == 46 || $0 == 95
        }
    }

    /// The address a connection should actually be opened to.
    public var connectHost: String { Self.unbracketed(bootstrapAddress ?? host) }

    public var needsBootstrap: Bool {
        bootstrapAddress == nil && !Self.isAddressLiteral(host)
    }

    /// Keep the URL, HTTP authority and TLS identity exactly unchanged while
    /// varying only a built-in dial IP. These still require individual policy
    /// preflight before becoming approved candidates. No explicit/custom pin,
    /// literal host or traditionally bootstrapped endpoint is expanded.
    var builtinAddressVariants: [DoHEndpoint] {
        guard usesAutomaticBootstrapAddress, !Self.isAddressLiteral(host) else { return [self] }
        let addresses = EncryptedDNSBootstrap.addresses(for: host)
        guard !addresses.isEmpty else { return [self] }
        return addresses.map { address in
            var variant = self
            variant.bootstrapAddress = Self.unbracketed(address)
            variant.usesAutomaticBootstrapAddress = true
            return variant
        }
    }

    /// Preserve the URL, HTTP Host and authenticated TLS identity, replacing
    /// only the address used for the actual connection.
    public func resolvingBootstrap(to address: String) -> DoHEndpoint? {
        guard Self.isAddressLiteral(address) else { return nil }
        guard needsBootstrap else { return self }
        var resolved = self
        resolved.bootstrapAddress = Self.unbracketed(address)
        return resolved
    }
}

/// Opens an already verified TLS stream through the caller-selected outbound.
/// The dial address is always literal; serverName remains the endpoint identity.
public typealias EncryptedDNSStreamDialer = (
    _ connectHost: String, _ port: UInt16, _ serverName: String, _ queue: DispatchQueue,
    _ completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void
) -> Void

/// The cancellation action owns only this pending dial/handshake. It must
/// close its transport and complete the dial once; the pool keeps admission
/// reserved until that completion acknowledges cancellation. A nil action
/// preserves the bounded, late-callback behavior of a legacy dialer.
public typealias CancellableEncryptedDNSStreamDialer = (
    _ connectHost: String, _ port: UInt16, _ serverName: String, _ queue: DispatchQueue,
    _ completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void
) -> (() -> Void)?

/// Production routed dials report a failure when the native stage first
/// admits it, before any caller/operation queue hops can hide it behind cancel.
/// The observer is a thread-safe metadata sink, never permission for I/O.
typealias MetadataAwareEncryptedDNSStreamDialer = (
    _ connectHost: String, _ port: UInt16, _ serverName: String, _ queue: DispatchQueue,
    _ attemptTrace: DNSConnectionAttemptTrace,
    _ failureObserver: @escaping (Error) -> Void,
    _ completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void
) -> (() -> Void)?

/// Native metadata admission and logical termination share this lock. A deny
/// admitted before seal survives token/completion cleanup; a later cancellation
/// error belongs to the closed lease and cannot manufacture a new deny.
private final class EncryptedDNSFailureAdmission {
    private let lock = NSLock()
    private var sealed = false
    private var denial: EncryptedDNSQueryFailure?
    private let proxyTCPQuery: Data?
    private var proxyTCPIngress = Data(), proxyTCPAnswer: Data?

    init(proxyTCPQuery: Data? = nil) { self.proxyTCPQuery = proxyTCPQuery }

    func observe(_ error: Error) {
        let reason = EncryptedDNSQueryFailure.classify(error)
        guard !reason.permitsProxyFallback, reason != .cancelled else { return }
        lock.lock()
        if !sealed, denial == nil { denial = reason }
        lock.unlock()
    }

    func seal() -> EncryptedDNSQueryFailure? {
        lock.lock(); defer { lock.unlock() }
        sealed = true
        return denial
    }

    /// The old TCP DNS flow admitted reply metadata on the native callback,
    /// before queue submission and cancel(). Preserve that fence when the
    /// stream is pooled: this bounded framer neither publishes nor starts I/O.
    func observeProxyTCPIngress(_ data: Data?, complete: Bool, error: Error?) {
        lock.lock(); defer { lock.unlock() }
        guard !sealed, let query = proxyTCPQuery, denial == nil, proxyTCPAnswer == nil else { return }
        if let error {
            let reason = EncryptedDNSQueryFailure.classify(error)
            if !reason.permitsProxyFallback, reason != .cancelled { denial = reason; return }
        }
        let input = data ?? Data()
        guard input.count <= 65_537 - proxyTCPIngress.count else { denial = .invalidResponse; return }
        proxyTCPIngress.append(input)
        guard proxyTCPIngress.count >= 2 else {
            if complete, !proxyTCPIngress.isEmpty { denial = .invalidResponse }
            return
        }
        let length = Int(proxyTCPIngress[proxyTCPIngress.startIndex]) << 8
            | Int(proxyTCPIngress[proxyTCPIngress.startIndex + 1])
        guard length >= 12, proxyTCPIngress.count <= length + 2 else { denial = .invalidResponse; return }
        if proxyTCPIngress.count == length + 2 {
            let answer = Data(proxyTCPIngress.dropFirst(2))
            guard DNSMessageInspection.responseMatchesQuery(answer, query: query) else { denial = .invalidResponse; return }
            proxyTCPAnswer = answer
        } else if complete { denial = .invalidResponse }
    }

    var admittedProxyTCPAnswer: Data? {
        lock.lock(); defer { lock.unlock() }; return denial == nil ? proxyTCPAnswer : nil
    }
}

/// Request-local ownership from proxy establishment through authenticated
/// inner TLS. Cancellation never releases a pool slot speculatively: its
/// callback follows the transport's own cancellation completion. In
/// particular a shared mux carrier cannot be canceled for one DNS caller.

/// One bounded HTTP/1.1 exchange at a time per reusable TLS stream. Redirects and system DNS are never
/// consulted. An injected dialer is the sole transport; the default transport
/// exists only for explicitly direct, encrypted node bootstrapping.
public final class DoHResolver {
    /// More simultaneous HTTP/1.1 exchanges create new TLS handshakes rather
    /// than multiplexing an existing connection. Queue bursts and reuse the
    /// first ready streams instead of building a cold connection per query.
    public static let maximumConcurrentQueries = 16
    /// Cold TCP/proxy/TLS setup is bounded separately from ready exchanges.
    public static let maximumConcurrentConnectionAttempts = 4
    private let endpoint: DoHEndpoint
    private let requests: EncryptedDNSRequestPool

    /// A scheduling hint only; the pool still owns admission and all leases.
    var schedulingAvailability: (reusable: Int, cold: Int) { requests.schedulingAvailability }

    public convenience init(endpoint: DoHEndpoint, streamDialer: EncryptedDNSStreamDialer? = nil) {
        self.init(endpoint: endpoint, streamDialer: streamDialer, bootstrapTimeout: .seconds(8))
    }

    public convenience init(endpoint: DoHEndpoint, timeout: TimeInterval,
                            streamDialer: EncryptedDNSStreamDialer? = nil) {
        let milliseconds = max(10, Int((timeout.isFinite ? timeout : 8.0) * 1_000))
        self.init(endpoint: endpoint, streamDialer: streamDialer, bootstrapTimeout: .milliseconds(milliseconds))
    }

    public convenience init(endpoint: DoHEndpoint,
                            cancellableStreamDialer: @escaping CancellableEncryptedDNSStreamDialer) {
        self.init(endpoint: endpoint, cancellableStreamDialer: cancellableStreamDialer,
                  bootstrapTimeout: .seconds(8))
    }

    convenience init(endpoint: DoHEndpoint,
                     metadataStreamDialer: @escaping MetadataAwareEncryptedDNSStreamDialer,
                     idleTimeout: TimeInterval = 15,
                     idleHandoffGrace: TimeInterval = 8) {
        self.init(endpoint: endpoint, metadataStreamDialer: metadataStreamDialer,
                  bootstrapTimeout: .seconds(8), idleTimeout: idleTimeout,
                  idleHandoffGrace: idleHandoffGrace)
    }

    /// A shorter deadline makes the loopback TLS-failure test deterministic:
    /// Network.framework may wait for its own handshake timer after the plain
    /// TCP test server closes, while production retains the normal 8 s limit.
    init(endpoint: DoHEndpoint, streamDialer: EncryptedDNSStreamDialer? = nil,
                     cancellableStreamDialer: CancellableEncryptedDNSStreamDialer? = nil,
                     metadataStreamDialer: MetadataAwareEncryptedDNSStreamDialer? = nil,
                     bootstrapTimeout: DispatchTimeInterval,
                     idleTimeout: TimeInterval = 15, idleLimit: Int = 4,
                     idleHandoffGrace: TimeInterval = 8,
                     activeLimit: Int = DoHResolver.maximumConcurrentQueries,
                     coldDialLimit: Int = DoHResolver.maximumConcurrentConnectionAttempts,
                     clock: @escaping () -> Date = { Date(timeIntervalSince1970: SOCKSUDPResourceLimits.now) },
                     resourceBudget: SOCKSUDPGlobalBudget = SOCKSUDPResourceLimits.shared) {
        self.endpoint = endpoint
        requests = EncryptedDNSRequestPool(protocol: .https(endpoint), label: "app.hajimi.dns.doh",
            streamDialer: streamDialer, cancellableStreamDialer: cancellableStreamDialer,
            metadataStreamDialer: metadataStreamDialer,
            timeout: bootstrapTimeout, idleTimeout: idleTimeout,
            idleLimit: idleLimit, idleHandoffGrace: idleHandoffGrace,
            activeLimit: activeLimit, coldDialLimit: coldDialLimit,
            clock: clock, resourceBudget: resourceBudget)
    }

    /// `query` and the result are both raw DNS wire messages, so this drops
    /// straight into the UDP path.
    @discardableResult
    public func resolve(query: Data, completion: @escaping (Data?) -> Void) -> UUID? {
        requests.resolve(query: query, completion: completion)
    }

    @discardableResult
    func resolveResult(query: Data,
                       completion: @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                       downgradeBarrier: ((DNSProxyFallbackBarrier) -> Void)? = nil,
                       transportEvidence: ((DNSQueryTransportEvidence) -> Void)? = nil,
                       executionContext: DNSQueryExecutionContext? = nil) -> UUID? {
        requests.resolveResult(query: query, completion: completion, downgradeBarrier: downgradeBarrier,
                               absoluteDeadline: executionContext?.absoluteDeadline,
                               transportEvidence: transportEvidence, executionContext: executionContext)
    }

    public func cancel(_ requestID: UUID) { requests.cancel(requestID) }
    func cancel(_ requestID: UUID, reason: DNSAttemptCancellationReason = .callerCancelled,
                completion: @escaping () -> Void) {
        requests.cancel(requestID, reason: reason, completion: completion)
    }
    public func cancel() { requests.cancel() }
    func cancel(reason: DNSAttemptCancellationReason) { requests.cancel(reason: reason) }

    @discardableResult
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID? {
        requests.resolveResult(query: Data(), completion: completion,
                               absoluteDeadline: absoluteDeadline, connectionOnly: true)
    }
}

private enum EncryptedDNSProtocol {
    case https(DoHEndpoint)
    case tls(DoTEndpoint)
    /// Ordinary DNS inside a separately authorized, authenticated proxy.
    /// This variant has no direct transport or implicit TLS upgrade.
    case proxyTCP(DNSProxyFallbackServer)

    var diagnosticTransport: DNSAttemptTransport {
        switch self {
        case .https: return .doh
        case .tls: return .dot
        case .proxyTCP: return .proxyTCP
        }
    }
    var diagnosticIdentity: String {
        switch self {
        case .https(let endpoint): return endpoint.url.absoluteString
        case .tls, .proxyTCP: return diagnosticTransport.rawValue + "|" + serverName + "|" + String(port)
        }
    }

    var connectHost: String {
        switch self {
        case .https(let endpoint): return endpoint.connectHost
        case .tls(let endpoint): return endpoint.connectHost
        case .proxyTCP(let server): return server.host
        }
    }
    var serverName: String {
        switch self {
        case .https(let endpoint): return endpoint.host
        case .tls(let endpoint): return endpoint.host
        case .proxyTCP(let server): return server.host
        }
    }
    var port: UInt16 {
        switch self {
        case .https(let endpoint): return endpoint.port
        case .tls(let endpoint): return endpoint.port
        case .proxyTCP(let server): return server.port
        }
    }
    var alpn: [String] {
        if case .https = self { return ["http/1.1"] }
        return []
    }
    func request(query: Data) -> Data? {
        switch self {
        case .https(let endpoint): return DoHHTTPWire.request(endpoint: endpoint, query: query)
        case .tls, .proxyTCP:
            var framed = Data([UInt8(truncatingIfNeeded: query.count >> 8),
                               UInt8(truncatingIfNeeded: query.count)])
            framed.append(query)
            return framed
        }
    }
}

/// Queue-confined transport ownership. Pending injected dials keep their slot
/// until their callback arrives, even if the query has already been cancelled.
private final class EncryptedDNSConnectionStore {
    private let queue: DispatchQueue
    private let clock: () -> Date
    private let idleTimeout: TimeInterval
    private let idleLimit: Int
    private let handoffLimit: Int
    private let handoffGrace: TimeInterval
    private let coldDialLimit: Int
    private let resourceBudget: SOCKSUDPGlobalBudget
    private let diagnostics: NetworkPerformanceDiagnostics, reuseEvent: DNSPerformanceEvent
    private let afterReplyIngressForSelfTest: (() -> Void)?
    private var entries: [UUID: EncryptedDNSPooledConnection] = [:]
    private var idle: [UUID] = []
    private var pendingDials = Set<UUID>()
    private var expiration: DispatchSourceTimer?
    private var closed = false
    private var lastClock: Date?
    // Queue-confined notification only. The pool defers/coalesces its drain,
    // so completing a dial cannot let a waiter take the released reservation
    // between this callback's completeDial() and adopt().
    var availabilityChanged: (() -> Void)?

    init(queue: DispatchQueue, idleTimeout: TimeInterval, idleLimit: Int,
         idleHandoffGrace: TimeInterval, activeLimit: Int,
         coldDialLimit: Int = DoHResolver.maximumConcurrentConnectionAttempts,
         clock: @escaping () -> Date, resourceBudget: SOCKSUDPGlobalBudget,
         diagnostics: NetworkPerformanceDiagnostics = .shared, reuseEvent: DNSPerformanceEvent = .connectionReuse,
         afterReplyIngressForSelfTest: (() -> Void)? = nil) {
        self.queue = queue; self.clock = clock; self.resourceBudget = resourceBudget
        self.coldDialLimit = min(128, max(1, coldDialLimit))
        self.diagnostics = diagnostics; self.reuseEvent = reuseEvent
        self.afterReplyIngressForSelfTest = afterReplyIngressForSelfTest
        self.idleLimit = min(4, max(0, idleLimit))
        self.idleTimeout = idleTimeout.isFinite ? min(15, max(0, idleTimeout)) : 0
        handoffGrace = idleHandoffGrace.isFinite ? min(8, max(0, idleHandoffGrace)) : 0
        // A queued question may try another approved provider before coming
        // back here as a hedge or third candidate. A 250ms handoff expires
        // healthy batch returns before those existing timers can borrow them.
        // Keep burst excess for at most one original 8s query budget, separately
        // from the four steady 15s idle streams. No query deadline is extended;
        // every idle stream still owns a global resource reservation, and an
        // explicit idleLimit=0 disables all retention.
        handoffLimit = self.idleLimit > 0 && handoffGrace > 0
            ? max(self.idleLimit, min(DoHResolver.maximumConcurrentQueries, max(1, activeLimit)))
            : self.idleLimit
    }

    func reserveDial() -> UUID? {
        expire()
        guard !closed, pendingDials.count < coldDialLimit,
              entries.count + pendingDials.count < 128 else { return nil }
        let token = UUID(); pendingDials.insert(token)
        availabilityChanged?()
        return token
    }

    func completeDial(_ token: UUID) -> Bool {
        let retired = pendingDials.remove(token) != nil
        if retired, !closed { availabilityChanged?() }
        return retired && !closed
    }

    /// Logical admission is not physical admission. A canceled native dial
    /// still owns its reservation until the real callback arrives. A FIFO
    /// waiter may meanwhile use a returned idle stream without another dial.
    /// A dirty idle stream is also safe to admit: checkout() closes it and
    /// thereby frees its entry before reserving the replacement transport.
    var canStartTransport: Bool {
        transportQueueReasons(allowIdleReuse: true).isEmpty
    }

    func transportQueueReasons(allowIdleReuse: Bool) -> [DNSResolverQueueReason] {
        expire()
        guard !closed else { return [.physicalConnectionLimit] }
        // Checkout rechecks native ingress. An idle FIN may still invalidate
        // this hint before checkout, in which case the request queues again.
        if allowIdleReuse, idle.contains(where: { entries[$0] != nil }) { return [] }
        var reasons: [DNSResolverQueueReason] = []
        if entries.count + pendingDials.count >= 128 { reasons.append(.physicalConnectionLimit) }
        if pendingDials.count >= coldDialLimit { reasons.append(.coldConnectionLimit) }
        return reasons
    }

    /// Pure queue-confined observation. This neither expires/closes an entry
    /// nor reserves a connection; the pool publishes only these scalar values.
    var schedulingSnapshot: (reusable: Int, cold: Int, reusableUntil: TimeInterval?) {
        guard !closed else { return (0, 0, nil) }
        let now = clock(), uptime = SOCKSUDPResourceLimits.now
        let backwards = lastClock.map { now < $0 } ?? false
        let ready = backwards ? [] : idle.compactMap { id -> EncryptedDNSPooledConnection? in
            guard let entry = entries[id], entry.canScheduleReuse(at: now, uptime: uptime) else { return nil }
            return entry
        }
        let cold = max(0, min(coldDialLimit - pendingDials.count, 128 - entries.count - pendingDials.count))
        return (ready.count, cold, ready.compactMap(\.idleUptime).min())
    }

    var hasConnectionOrPendingDial: Bool {
        expire()
        return !closed && (!entries.isEmpty || !pendingDials.isEmpty)
    }

    fileprivate var physicalOccupancyForSelfTest: Int { entries.count + pendingDials.count }

    func adopt(_ stream: any NativeOutboundByteStream) -> EncryptedDNSPooledConnection? {
        guard !closed, entries.count + pendingDials.count < 128 else { stream.cancel(); return nil }
        let entry = EncryptedDNSPooledConnection(stream: stream, queue: queue,
            afterReplyIngressForSelfTest: afterReplyIngressForSelfTest) { [weak self] id in
            guard let self else { return }
            self.entries.removeValue(forKey: id); self.idle.removeAll { $0 == id }
            self.scheduleExpiration()
            if !self.closed { self.availabilityChanged?() }
        }
        entries[entry.id] = entry
        availabilityChanged?()
        return entry
    }

    func checkout() -> EncryptedDNSPooledConnection? {
        expire()
        guard !closed else { return nil }
        while let id = idle.popLast() {
            guard let entry = entries[id] else { continue }
            if entry.beginLease() {
                diagnostics.recordDNS(reuseEvent)
                scheduleExpiration(); availabilityChanged?(); return entry
            }
            entry.close()
        }
        scheduleExpiration(); return nil
    }

    func returnIdle(_ entry: EncryptedDNSPooledConnection) {
        expire()
        guard !closed, entries[entry.id] === entry, entry.canReturnIdle,
              idleTimeout > 0, idle.count < handoffLimit,
              let reservation = resourceBudget.reserveResource() else { entry.close(); return }
        let duration = idle.count < idleLimit ? idleTimeout : min(idleTimeout, handoffGrace)
        idle.append(entry.id)
        entry.beginIdle(until: clock().addingTimeInterval(duration), duration: duration,
                        reservation: reservation)
        scheduleExpiration()
        availabilityChanged?()
    }

    func discard(_ entry: EncryptedDNSPooledConnection) { entry.close() }

    func discardIdle() {
        let stale = idle.compactMap { entries[$0] }
        idle.removeAll()
        stale.forEach { $0.close() }
    }

    private func expire() {
        let now = clock()
        let uptime = SOCKSUDPResourceLimits.now
        let backwards = lastClock.map { now < $0 } ?? false
        lastClock = now
        for id in idle {
            if let entry = entries[id],
               backwards || (entry.idleUntil.map { $0 <= now } ?? false)
                || (entry.idleUptime.map { $0 <= uptime } ?? false) { entry.close() }
        }
    }

    private func scheduleExpiration() {
        guard !closed else { return }
        let now = clock(), uptime = SOCKSUDPResourceLimits.now
        let delay = idle.compactMap { id -> TimeInterval? in
            guard let entry = entries[id], let until = entry.idleUntil, let end = entry.idleUptime else { return nil }
            return min(until.timeIntervalSince(now), end - uptime)
        }.min()
        guard let delay else { expiration?.schedule(deadline: .distantFuture); return }
        if expiration == nil {
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.setEventHandler { [weak self] in
                self?.expire(); self?.scheduleExpiration()
            }
            expiration = timer; timer.resume()
        }
        expiration?.schedule(deadline: .now() + max(0.001, delay))
    }

    func cancel() {
        guard !closed else { return }
        closed = true
        availabilityChanged = nil
        expiration?.setEventHandler {}; expiration?.cancel(); expiration = nil
        let active = Array(entries.values)
        entries.removeAll(); idle.removeAll()
        active.forEach { $0.close() }
        // Do not release un-cancellable injected dial slots before delivery.
    }

    deinit { expiration?.cancel(); entries.values.forEach { $0.close() } }
}

/// Queue-confined direct TLS receipt. Logical cancellation is not a native
/// terminal event: a late ready is closed and its dial slot remains occupied
/// until failed/cancelled arrives. The same handler is exercised by memory
/// tests, rather than simulating cancellation with an unrelated budget gate.
private func encryptedDNSDirectTLSStateHandler(
    completeDial: @escaping () -> Bool,
    canPublish: @escaping () -> Bool,
    cancel: @escaping () -> Void,
    detach: @escaping () -> Void,
    ready: @escaping () -> Void,
    failure: @escaping (EncryptedDNSQueryFailure) -> Void,
    observe: @escaping (Error) -> Void
) -> (NWConnection.State) -> Void {
    var retired = false
    return { state in
        guard !retired else { return }
        switch state {
        case .failed(let error), .waiting(let error): observe(error)
        default: break
        }
        switch state {
        case .failed(let error):
            retired = true
            _ = completeDial(); detach()
            cancel()
            failure(EncryptedDNSQueryFailure.classify(error))
        case .cancelled:
            retired = true
            _ = completeDial(); detach()
            failure(.cancelled)
        case .ready:
            guard canPublish() else { cancel(); return }
            retired = true
            let accepted = completeDial(); detach()
            guard accepted else { cancel(); failure(.cancelled); return }
            ready()
        case .waiting(let error):
            guard canPublish() else { cancel(); return }
            let reason = EncryptedDNSQueryFailure.classify(error)
            // A deny must reach logical completion before any downgrade,
            // but the waiting transport is not yet physically retired.
            if !reason.permitsProxyFallback { failure(reason) }
        default:
            if !canPublish() { cancel() }
        }
    }
}

/// A single read broker owns both idle EOF monitoring and the active receive.
/// It never issues two receives on the same stream, nor buffers idle data for
/// the next client. One bounded event can wait for an active client's reader.
private final class EncryptedDNSPooledConnection {
    private enum State: Equatable { case leased, idle, closed }
    private enum ObservationPhase { case preparing, sent, idle, closed }
    let id = UUID()
    private let stream: any NativeOutboundByteStream
    private let queue: DispatchQueue
    private let onClosed: (UUID) -> Void
    private let afterReplyIngressForSelfTest: (() -> Void)?
    private var state = State.leased
    private var sent = false, eof = false, readPending = false
    private var readToken = UUID()
    private var buffered: (Data?, Bool, Error?)?
    private var receiver: ((Data?, Bool, Error?) -> Void)?
    private var idleReservation: SOCKSUDPReservation?
    // Native callbacks need not run on queue. Record arrival before enqueueing
    // it so an already-observed idle FIN/data cannot race a new checkout, and
    // a received prefix cannot be hidden behind a queued send-error callback.
    private let observationLock = NSLock()
    private var observationPhase = ObservationPhase.preparing
    private var observationToken: UUID?
    private var observedBytes = 0
    private var observedDirty = false, observedTerminal = false
    private var observedTransportError: Error?
    private var observationFailureObserver: ((Error) -> Void)?
    private var observationIngressObserver: ((Data?, Bool, Error?) -> Void)?
    private(set) var idleUntil: Date?
    private(set) var idleUptime: TimeInterval?
    private static let maximumRead = 32_768
    private static var unavailable: Error { NSError(domain: "EncryptedDNSStream", code: 1) }

    init(stream: any NativeOutboundByteStream, queue: DispatchQueue,
         afterReplyIngressForSelfTest: (() -> Void)? = nil, onClosed: @escaping (UUID) -> Void) {
        self.stream = stream; self.queue = queue; self.onClosed = onClosed
        self.afterReplyIngressForSelfTest = afterReplyIngressForSelfTest
        (stream as? any NativeOutboundFailureObservingByteStream)?.setStreamFailureObserver { [weak self] error in
            self?.observeTransportFailure(error)
        }
    }

    private func observeTransportFailure(_ error: Error) {
        observationLock.lock()
        guard observationPhase != .closed else { observationLock.unlock(); return }
        if observedTransportError == nil { observedTransportError = error }
        observedTerminal = true
        if observationPhase != .sent { observedDirty = true }
        let observer = observationPhase == .sent ? observationFailureObserver : nil
        observationLock.unlock()
        // Raw TLS bridge errors belong to the current lease, even when its
        // application read has not completed or cancellation is already queued.
        observer?(error)
    }

    var canReturnIdle: Bool {
        observationLock.lock()
        let clean = !observedDirty && !observedTerminal
        observationLock.unlock()
        return clean && state == .leased && !eof && receiver == nil && buffered == nil && !readPending
    }

    var receivedBytes: Int {
        observationLock.lock(); defer { observationLock.unlock() }; return observedBytes
    }

    /// Passive evidence only. Pending-read state belongs to this owner queue;
    /// an idle receive may remain in flight when beginLease() transfers it.
    var diagnosticReadPending: Bool { readPending }
    func dnsStreamProgressSnapshot() -> DNSStreamProgressSnapshot? {
        (stream as? any DNSStreamProgressProviding)?.dnsStreamProgressSnapshot()
    }

    /// Same clean-idle predicate as beginLease(), without changing ownership.
    func canScheduleReuse(at now: Date, uptime: TimeInterval) -> Bool {
        guard state == .idle, !eof, buffered == nil, receiver == nil,
              let idleUntil, idleUntil > now, let idleUptime, idleUptime > uptime else { return false }
        observationLock.lock(); defer { observationLock.unlock() }
        return !observedDirty && !observedTerminal
    }

    func beginLease() -> Bool {
        guard state == .idle, !eof, buffered == nil, receiver == nil else { return false }
        observationLock.lock()
        guard !observedDirty, !observedTerminal else { observationLock.unlock(); return false }
        observationPhase = .preparing; observedBytes = 0
        observationFailureObserver = nil
        observationIngressObserver = nil
        observationLock.unlock()
        state = .leased; sent = false; idleUntil = nil; idleUptime = nil
        idleReservation?.release(); idleReservation = nil
        return true
    }

    func beginIdle(until: Date, duration: TimeInterval, reservation: SOCKSUDPReservation) {
        observationLock.lock()
        observationPhase = .idle; observationFailureObserver = nil; observationIngressObserver = nil
        observationLock.unlock()
        state = .idle; idleUntil = until; idleReservation = reservation
        idleUptime = SOCKSUDPResourceLimits.now + duration
        startRead()
    }

    func send(_ data: Data, failureObserver: @escaping (Error) -> Void,
              ingressObserver: ((Data?, Bool, Error?) -> Void)? = nil,
              completion: @escaping (Error?) -> Void) {
        guard state == .leased, !sent else { completion(Self.unavailable); return }
        observationLock.lock()
        guard !observedDirty, !observedTerminal else {
            let error = observedTransportError ?? Self.unavailable
            observationLock.unlock()
            failureObserver(error); completion(error); return
        }
        observationPhase = .sent
        observationFailureObserver = failureObserver
        observationIngressObserver = ingressObserver
        observationLock.unlock()
        sent = true
        stream.send(data) { [weak self] error in
            if let error { failureObserver(error) }
            guard let self else { return }
            self.observationLock.lock(); let original = self.observedTransportError; self.observationLock.unlock()
            if let original { failureObserver(original) }
            self.queue.async { completion(original ?? error ?? (self.state == .closed ? Self.unavailable : nil)) }
        }
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        guard state == .leased, receiver == nil else { completion(nil, true, Self.unavailable); return }
        if let event = buffered { buffered = nil; completion(event.0, event.1, event.2); return }
        guard !eof else { completion(nil, true, nil); return }
        receiver = completion
        startRead()
    }

    private func startRead() {
        guard state != .closed, !readPending, !eof,
              state == .idle || receiver != nil else { return }
        readPending = true
        let token = UUID(); readToken = token
        observationLock.lock(); observationToken = token; observationLock.unlock()
        stream.receive(maximum: Self.maximumRead) { [weak self] data, complete, error in
            guard let self else { return }
            let count = data?.count ?? 0
            self.observationLock.lock()
            guard self.observationPhase != .closed, self.observationToken == token else {
                self.observationLock.unlock(); return
            }
            self.observationToken = nil
            let originalError = self.observedTransportError ?? error
            self.observedBytes += count
            if self.observationPhase != .sent { self.observedDirty = true }
            self.observedTerminal = self.observedTerminal || complete || originalError != nil
            let observer = self.observationPhase == .sent ? self.observationFailureObserver : nil
            let ingress = self.observationPhase == .sent ? self.observationIngressObserver : nil
            self.observationLock.unlock()
            // Save deny metadata at native admission, not only when A later
            // invokes Request. C may already be queued before A is scheduled.
            if let originalError { observer?(originalError) }
            ingress?(data, complete, originalError)
            if count > Self.maximumRead || (count == 0 && !complete && originalError == nil) {
                observer?(EncryptedDNSQueryFailure.invalidResponse)
            }
            self.afterReplyIngressForSelfTest?()
            self.queue.async {
                guard self.state != .closed, self.readPending, self.readToken == token else { return }
                self.readPending = false
                if self.state == .idle { self.close(); return }
                let noProgress = count == 0 && !complete && originalError == nil
                let failure = originalError ?? (count > Self.maximumRead || noProgress ? Self.unavailable : nil)
                self.eof = complete || failure != nil
                let event = (data, complete, failure)
                if let callback = self.receiver {
                    self.receiver = nil
                    callback(event.0, event.1, event.2)
                } else { self.buffered = event }
            }
        }
    }

    func close() {
        guard state != .closed else { return }
        observationLock.lock()
        observationPhase = .closed; observationToken = nil
        observationFailureObserver = nil
        observationIngressObserver = nil
        observationLock.unlock()
        state = .closed; readToken = UUID(); readPending = false; buffered = nil
        idleUntil = nil; idleUptime = nil; idleReservation?.release(); idleReservation = nil
        (stream as? any NativeOutboundFailureObservingByteStream)?.setStreamFailureObserver(nil)
        stream.cancel()
        let callback = receiver; receiver = nil
        onClosed(id)
        callback?(nil, true, Self.unavailable)
    }

    deinit {
        idleReservation?.release()
        (stream as? any NativeOutboundFailureObservingByteStream)?.setStreamFailureObserver(nil)
        if state != .closed {
            stream.cancel()
        }
    }
}

private final class EncryptedDNSRequestPool {
    private let queue: DispatchQueue
    private let streamDialer: MetadataAwareEncryptedDNSStreamDialer?
    private let timeout: DispatchTimeInterval
    private let dnsProtocol: EncryptedDNSProtocol
    private let connections: EncryptedDNSConnectionStore
    private let diagnostics: NetworkPerformanceDiagnostics
    private let lock = NSLock()
    private var requests: [UUID: EncryptedDNSRequest] = [:]
    private var cancelled = false
    // Published on queue, read under lock. Native/request state is never
    // inspected by the cross-queue getter. ID snapshots prevent a canceled
    // old active registration from masking a newly registered queued start.
    private var publishedReusable = 0, publishedCold = 0
    private var publishedActiveRequestIDs = Set<UUID>()
    private var publishedFreshOnlyWaitingRequestIDs = Set<UUID>()
    private var publishedReusableUntil: TimeInterval?
    // Queue-confined logical admission. This is separate from the connection
    // store's physical dial reservations, which only real callbacks release.
    private let activeLimit: Int
    private var activeRequests = Set<UUID>()
    private var waitingOrder: [UUID] = []
    private var waitingStarts: [UUID: () -> Void] = [:]
    private var drainingStarts = false
    private var scheduledDrainStarts = false

    init(protocol dnsProtocol: EncryptedDNSProtocol, label: String, streamDialer: EncryptedDNSStreamDialer?,
         cancellableStreamDialer: CancellableEncryptedDNSStreamDialer?,
         metadataStreamDialer: MetadataAwareEncryptedDNSStreamDialer?,
         timeout: DispatchTimeInterval, idleTimeout: TimeInterval, idleLimit: Int,
         idleHandoffGrace: TimeInterval,
         activeLimit: Int,
         coldDialLimit: Int = DoHResolver.maximumConcurrentConnectionAttempts,
         clock: @escaping () -> Date, resourceBudget: SOCKSUDPGlobalBudget,
         diagnostics: NetworkPerformanceDiagnostics = .shared, afterReplyIngressForSelfTest: (() -> Void)? = nil) {
        // DNS gates foreground navigation. Keeping this queue at utility
        // priority lets bulk traffic delay cold handshakes and their ACKs.
        let queue = DispatchQueue(label: label, qos: .userInitiated)
        self.queue = queue; self.dnsProtocol = dnsProtocol; self.diagnostics = diagnostics
        self.activeLimit = min(128, max(1, activeLimit))
        let reuseEvent: DNSPerformanceEvent
        if case .proxyTCP = dnsProtocol { reuseEvent = .proxyFallbackConnectionReuse }
        else { reuseEvent = .connectionReuse }
        connections = EncryptedDNSConnectionStore(queue: queue, idleTimeout: idleTimeout,
            idleLimit: idleLimit, idleHandoffGrace: idleHandoffGrace,
            activeLimit: self.activeLimit, coldDialLimit: coldDialLimit,
            clock: clock, resourceBudget: resourceBudget,
            diagnostics: diagnostics, reuseEvent: reuseEvent,
            afterReplyIngressForSelfTest: afterReplyIngressForSelfTest)
        if let metadataStreamDialer { self.streamDialer = metadataStreamDialer }
        else if let cancellableStreamDialer {
            self.streamDialer = { host, port, name, queue, _, _, done in
                cancellableStreamDialer(host, port, name, queue, done)
            }
        } else if let streamDialer {
            self.streamDialer = { host, port, name, queue, _, _, done in
                streamDialer(host, port, name, queue, done)
                return nil
            }
        } else { self.streamDialer = nil }
        self.timeout = timeout
        connections.availabilityChanged = { [weak self] in self?.scheduleDrainStarts() }
        publishSchedulingAvailability()
    }

    deinit { cancel() }

    private func isRegistered(_ id: UUID) -> Bool {
        lock.lock(); defer { lock.unlock() }; return !cancelled && requests[id] != nil
    }

    private func registeredRequest(_ id: UUID) -> EncryptedDNSRequest? {
        lock.lock(); defer { lock.unlock() }; return cancelled ? nil : requests[id]
    }

    var schedulingAvailability: (reusable: Int, cold: Int) {
        let now = SOCKSUDPResourceLimits.now
        lock.lock(); defer { lock.unlock() }
        guard !cancelled else { return (0, 0) }
        // A delayed expiry callback must not advertise a past idle deadline.
        let reusable = publishedReusableUntil.map { $0 > now } == true ? publishedReusable : 0
        var demand = 0, reusableDemand = 0
        for id in requests.keys where !publishedActiveRequestIDs.contains(id) {
            demand += 1
            // An idle retry needs a fresh transport and cannot claim a
            // healthy idle stream that another query can already borrow.
            if !publishedFreshOnlyWaitingRequestIDs.contains(id) { reusableDemand += 1 }
        }
        let reuseDemand = min(reusable, reusableDemand)
        return (reusable - reuseDemand, max(0, publishedCold - (demand - reuseDemand)))
    }

    /// Called only from queue, or synchronously before this pool is published.
    /// Do not hold lock while touching the store or a stream observation lock.
    private func publishSchedulingAvailability() {
        let snapshot = connections.schedulingSnapshot
        let active = activeRequests.count
        let available = max(0, activeLimit - active)
        let reusable = min(snapshot.reusable, available)
        let cold = min(snapshot.cold, max(0, available - reusable))
        let freshOnlyWaiting = Set(waitingOrder.filter {
            registeredRequest($0)?.requiresFreshTransport == true
        })
        lock.lock()
        publishedReusable = reusable; publishedCold = cold
        publishedActiveRequestIDs = activeRequests
        publishedFreshOnlyWaitingRequestIDs = freshOnlyWaiting
        publishedReusableUntil = snapshot.reusableUntil
        lock.unlock()
    }

    func resolve(query: Data,
                 completion: @escaping (Data?) -> Void) -> UUID? {
        resolveResult(query: query, completion: { result in
            if case .success(let answer) = result { completion(answer) }
            else { completion(nil) }
        })
    }

    func resolveResult(query: Data,
                       completion: @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                       downgradeBarrier: ((DNSProxyFallbackBarrier) -> Void)? = nil,
                       absoluteDeadline: TimeInterval? = nil,
                       permitted: @escaping () -> Bool = { true },
                       transportEvidence: ((DNSQueryTransportEvidence) -> Void)? = nil,
                       connectionOnly: Bool = false,
                       executionContext: DNSQueryExecutionContext? = nil) -> UUID? {
        if let absoluteDeadline {
            guard absoluteDeadline.isFinite else { completion(.failure(.configuration)); return nil }
            guard absoluteDeadline > ProcessInfo.processInfo.systemUptime else { completion(.failure(.timeout)); return nil }
        }
        guard permitted() else { completion(.failure(.policy)); return nil }
        lock.lock()
        let preflightCancelled = cancelled
        let preflightFull = requests.count >= 128
        lock.unlock()
        if preflightCancelled || preflightFull {
            completion(.failure(preflightCancelled ? .cancelled : .capacity))
            return nil
        }
        let id = UUID()
        guard let request = EncryptedDNSRequest(
            protocol: dnsProtocol, query: query, streamDialer: streamDialer,
            queue: queue, timeout: timeout, connections: connections,
            permitted: { [weak self] in (self?.isRegistered(id) ?? false) && permitted() },
            downgradeBarrier: downgradeBarrier,
            diagnostics: diagnostics, absoluteDeadline: absoluteDeadline,
            transportEvidence: transportEvidence,
            connectionOnly: connectionOnly,
            executionContext: executionContext,
            completion: { [weak self] result, entry, reusable in
                guard let self else { entry?.close(); completion(.failure(.cancelled)); return }
                self.lock.lock()
                let registered = self.requests.removeValue(forKey: id) != nil
                let allowed = registered && !self.cancelled
                self.lock.unlock()
                if let entry {
                    if allowed, reusable { self.connections.returnIdle(entry) }
                    else { self.connections.discard(entry) }
                }
                // Make the just-completed stream available before starting
                // another queued exchange, including on a foreign cancel.
                self.retire(id)
                completion(allowed ? result : .failure(.cancelled))
            }) else { completion(.failure(.configuration)); return nil }
        lock.lock()
        guard !cancelled, requests.count < 128 else {
            let reason: EncryptedDNSQueryFailure = cancelled ? .cancelled : .capacity
            lock.unlock()
            completion(.failure(reason))
            return nil
        }
        requests[id] = request
        lock.unlock()
        request.start { [weak self] begin in
            guard let self else { begin(); return }
            // The same admission path owns a stale-idle fresh retry. Release
            // only its logical exchange slot; physical dial receipts remain
            // in the store until their real callback acknowledges teardown.
            self.activeRequests.remove(id)
            if self.waitingStarts.updateValue(begin, forKey: id) == nil {
                self.waitingOrder.append(id)
            }
            self.drainStarts()
        }
        return id
    }

    private func retire(_ id: UUID) {
        activeRequests.remove(id)
        waitingStarts.removeValue(forKey: id)
        waitingOrder.removeAll { $0 == id }
        drainStarts()
    }

    private func scheduleDrainStarts() {
        guard !scheduledDrainStarts else { return }
        scheduledDrainStarts = true
        queue.async { [weak self] in
            guard let self else { return }
            self.scheduledDrainStarts = false
            self.drainStarts()
        }
    }

    private func drainStarts() {
        guard !drainingStarts else { return }
        drainingStarts = true
        defer { drainingStarts = false; publishSchedulingAvailability() }
        while activeRequests.count < activeLimit, !waitingOrder.isEmpty {
            // An old query's late hedge retains its earlier deadline. Prefer
            // that deadline among eligible work, with FIFO for exact ties. A
            // retry needing a fresh dial still cannot take a returned idle
            // stream away from a later request that can actually use it.
            var selected: (position: Int, deadline: TimeInterval)?
            for (position, id) in waitingOrder.enumerated() {
                guard let request = registeredRequest(id) else {
                    selected = (position, 0); break
                }
                guard request.deadlineExpired || request.transportQueueReasons.isEmpty else { continue }
                if selected == nil || request.originalDeadline < selected!.deadline {
                    selected = (position, request.originalDeadline)
                }
            }
            guard let position = selected?.position else { break }
            let id = waitingOrder[position]
            guard let begin = waitingStarts[id] else { waitingOrder.remove(at: position); continue }
            // Do not turn transient physical saturation into a new capacity
            // failure. Wait for a real dial receipt or a reusable return, with
            // the already-running original timer and registration budget.
            // Revoked/expired heads must still finish when no socket is free.
            waitingOrder.remove(at: position); waitingStarts.removeValue(forKey: id)
            // begin() also rechecks registration and its original deadline.
            // A revoked queued request finishes without creating a socket.
            if isRegistered(id) { activeRequests.insert(id) }
            begin()
        }
        for id in waitingOrder {
            guard let request = registeredRequest(id) else { continue }
            var reasons = request.transportQueueReasons
            if activeRequests.count >= activeLimit { reasons.insert(.queryLimit, at: 0) }
            request.recordResolverQueueWait(reasons: reasons)
        }
    }

    func cancel(_ requestID: UUID) {
        cancel(requestID, completion: {})
    }

    func cancel(_ requestID: UUID, reason: DNSAttemptCancellationReason = .callerCancelled,
                completion: @escaping () -> Void) {
        lock.lock()
        let request = requests.removeValue(forKey: requestID)
        lock.unlock()
        if let request { request.cancel(reason: reason, completion: completion) }
        else { queue.async { completion() } }
    }

    func cancel(reason: DNSAttemptCancellationReason = .poolShutdown) {
        lock.lock()
        cancelled = true
        let active = Array(requests.values)
        requests.removeAll()
        lock.unlock()
        let connections = self.connections
        queue.async { connections.cancel() }
        active.forEach { $0.cancel(reason: reason) }
    }

    fileprivate func drainQueueForSelfTest() { queue.sync {} }

    func originalDeadlineForSelfTest(_ requestID: UUID) -> DispatchTime? {
        registeredRequest(requestID)?.originalDeadlineForSelfTest
    }

    fileprivate var pressureForSelfTest: (registered: Int, active: Int, waiting: Int, physical: Int) {
        queue.sync {
            lock.lock(); let registered = requests.count; lock.unlock()
            return (registered, activeRequests.count, waitingStarts.count,
                    connections.physicalOccupancyForSelfTest)
        }
    }
}

/// Exactly one active query per leased stream. Old-attempt callbacks cannot
/// mutate its replacement, and the original deadline also covers one retry.
private final class EncryptedDNSRequest {
    private let dnsProtocol: EncryptedDNSProtocol
    private let query: Data
    private let streamDialer: MetadataAwareEncryptedDNSStreamDialer?
    private let queue: DispatchQueue
    private let deadline: DispatchTime
    private let schedulingDeadline: TimeInterval
    private let inheritedOwnsDeadline: Bool
    private let requestBytes: Data
    private let connectionOnly: Bool
    private let connections: EncryptedDNSConnectionStore
    private let permitted: () -> Bool
    private var httpResponse = DoHHTTPResponseParser()
    private var tlsResponse = Data()
    private var completion: ((Result<Data, EncryptedDNSQueryFailure>, EncryptedDNSPooledConnection?, Bool) -> Void)?
    private var stream: EncryptedDNSPooledConnection?
    private var directConnection: NWConnection?
    private var timer: DispatchSourceTimer?
    private var pendingDial: UUID?
    private var pendingDialCancellation: (() -> Void)?
    private let diagnosticRequestID = UUID()
    private var attemptTrace: DNSConnectionAttemptTrace?
    private let executionContext: DNSQueryExecutionContext?
    private var exchangeTrace: DNSQueryExchangeTrace?
    private var responseStarted = false
    private var transportAdmission: ((@escaping () -> Void) -> Void)?
    private var resolverQueueStarted: UInt64?
    private var resolverQueueReasons: [DNSResolverQueueReason] = []
    private var cancellationReason: DNSAttemptCancellationReason?
    private var attempt = UUID()
    private var borrowedIdle = false, retried = false
    private let evidenceObserver: ((DNSQueryTransportEvidence) -> Void)?
    private var downgradeBarrier: EncryptedDNSQueryFailure?
    private let barrierObserver: ((DNSProxyFallbackBarrier) -> Void)?
    private let failureAdmission: EncryptedDNSFailureAdmission
    private let diagnostics: NetworkPerformanceDiagnostics
    private var proxyExchangeStarted: UInt64?
    private var ioSendStarted: UInt64?
    private var ioStreamBaseline: DNSStreamProgressSnapshot?
    private var ioReadPendingAtSend = false
    private var ioResolverReadRequests: UInt64 = 0
    private var ioFirstResolverRead: UInt64?

    init?(protocol dnsProtocol: EncryptedDNSProtocol, query: Data,
          streamDialer: MetadataAwareEncryptedDNSStreamDialer?,
          queue: DispatchQueue, timeout: DispatchTimeInterval,
          connections: EncryptedDNSConnectionStore, permitted: @escaping () -> Bool,
          downgradeBarrier: ((DNSProxyFallbackBarrier) -> Void)?,
          diagnostics: NetworkPerformanceDiagnostics = .shared, absoluteDeadline: TimeInterval? = nil,
          transportEvidence: ((DNSQueryTransportEvidence) -> Void)? = nil,
          connectionOnly: Bool = false,
          executionContext: DNSQueryExecutionContext? = nil,
          completion: @escaping (Result<Data, EncryptedDNSQueryFailure>, EncryptedDNSPooledConnection?, Bool) -> Void) {
        guard DoHEndpoint.isAddressLiteral(dnsProtocol.connectHost), dnsProtocol.port > 0,
              DoHEndpoint.isValidServerName(dnsProtocol.serverName) else { return nil }
        let bytes: Data, inspectedQuestion: DNSQueryQuestion?
        if connectionOnly {
            // Ordinary DNS has no prewarm entry, even through a proxy.
            if case .proxyTCP = dnsProtocol { return nil }
            bytes = Data()
            inspectedQuestion = nil
        } else {
            guard (12...65_535).contains(query.count),
                  let question = DNSMessageInspection.singleQuestion(in: query),
                  let request = dnsProtocol.request(query: query) else { return nil }
            bytes = request
            inspectedQuestion = question
        }
        self.connectionOnly = connectionOnly
        self.dnsProtocol = dnsProtocol
        self.query = query
        if case .proxyTCP = dnsProtocol { failureAdmission = EncryptedDNSFailureAdmission(proxyTCPQuery: query) }
        else { failureAdmission = EncryptedDNSFailureAdmission() }
        self.streamDialer = streamDialer
        self.queue = queue
        // Queue admission, TLS setup, one idle retry and response parsing all
        // consume one deadline, measured from registration, never from dial.
        let original = DispatchTime.now() + timeout
        let uptime = ProcessInfo.processInfo.systemUptime
        let now = DispatchTime.now().uptimeNanoseconds
        let localRemaining = original.uptimeNanoseconds > now
            ? Double(original.uptimeNanoseconds - now) / 1_000_000_000 : 0
        let localDeadline = uptime + localRemaining
        if let absoluteDeadline {
            guard absoluteDeadline.isFinite else { return nil }
            let inherited = DispatchTime.now() + max(0, absoluteDeadline - ProcessInfo.processInfo.systemUptime)
            deadline = min(original, inherited)
            inheritedOwnsDeadline = executionContext?.absoluteDeadline == absoluteDeadline && inherited <= original
            // Keep equal caller deadlines exactly equal for stable EDF ties;
            // a shorter local timeout still takes precedence in scheduling.
            schedulingDeadline = min(localDeadline, absoluteDeadline)
        } else {
            deadline = original
            schedulingDeadline = localDeadline
            inheritedOwnsDeadline = false
        }
        self.connections = connections; self.permitted = permitted
        self.diagnostics = diagnostics
        self.evidenceObserver = transportEvidence
        self.executionContext = executionContext
        if !connectionOnly {
            exchangeTrace = diagnostics.beginDNSExchange(requestID: diagnosticRequestID,
                context: executionContext, transport: dnsProtocol.diagnosticTransport,
                endpointIdentity: dnsProtocol.diagnosticIdentity)
            if let question = inspectedQuestion {
                let flags = UInt16(query[query.startIndex + 2]) << 8 | UInt16(query[query.startIndex + 3])
                let additional = UInt16(query[query.startIndex + 10]) << 8 | UInt16(query[query.startIndex + 11])
                exchangeTrace?.recordQuestion(type: question.type,
                    ptrTargetCategory: DNSMessageInspection.ptrTargetCategory(for: question),
                    ptrQueryKind: DNSMessageInspection.ptrQueryKind(for: question), queryClass: question.class,
                    flags: flags, bytes: query.count, additionalRecordCount: additional)
            }
        }
        barrierObserver = downgradeBarrier
        self.completion = completion
        requestBytes = bytes
    }

    func start(admit: @escaping (@escaping () -> Void) -> Void) {
        queue.async { [self] in
            guard completion != nil else { return }
            guard permitted() else { finish(.failure(.cancelled)); return }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            self.timer = timer
            timer.schedule(deadline: deadline)
            timer.setEventHandler { [weak self] in self?.finish(.failure(.timeout)) }
            timer.resume()
            transportAdmission = admit
            enqueueTransport()
        }
    }

    var transportQueueReasons: [DNSResolverQueueReason] {
        if connectionOnly, connections.hasConnectionOrPendingDial { return [] }
        return connections.transportQueueReasons(allowIdleReuse: !retried)
    }

    /// Queue-confined only; external selectors consume the pool's published
    /// ID snapshot instead of observing this mutable request field.
    var requiresFreshTransport: Bool { retried }

    func recordResolverQueueWait(reasons: [DNSResolverQueueReason]) {
        guard completion != nil, !reasons.isEmpty else { return }
        if resolverQueueStarted == nil {
            resolverQueueStarted = NetworkPerformanceDiagnostics.now()
            exchangeTrace?.record(.resolverQueued)
        }
        for reason in reasons where !resolverQueueReasons.contains(reason) {
            resolverQueueReasons.append(reason)
        }
    }

    private func finishResolverQueueWait(outcome: NetworkPerformanceOutcome, admitted: Bool = false) {
        guard let started = resolverQueueStarted else { return }
        let milliseconds = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started)
        resolverQueueStarted = nil
        if admitted { exchangeTrace?.record(.resolverAdmitted) }
        exchangeTrace?.recordResolverQueue(milliseconds: milliseconds, reasons: resolverQueueReasons)
        resolverQueueReasons.removeAll(keepingCapacity: true)
        diagnostics.record(.dnsResolverQueue, milliseconds: milliseconds, outcome: outcome)
    }

    private func enqueueTransport() {
        guard completion != nil else { return }
        guard let transportAdmission else { finish(.failure(.configuration)); return }
        transportAdmission { [self] in beginTransport() }
    }

    private func beginTransport() {
        guard completion != nil else { return }
        guard permitted() else { finish(.failure(.cancelled)); return }
        guard DispatchTime.now() < deadline else { finish(.failure(.timeout)); return }
        if connectionOnly, connections.hasConnectionOrPendingDial {
            // A foreground query may already be preparing this path. Do not
            // take its live/idle stream merely to report another warmup.
            finishResolverQueueWait(outcome: .success, admitted: true)
            finish(.success(Data())); return
        }
        if !retried, let idle = connections.checkout() {
            finishResolverQueueWait(outcome: .success, admitted: true)
            evidenceObserver?(.reused)
            exchangeTrace?.record(.connectionReused)
            borrowedIdle = true; stream = idle; send(attempt)
        } else { dial(attempt) }
    }

    func cancel(reason: DNSAttemptCancellationReason = .callerCancelled, completion: (() -> Void)? = nil) {
        queue.async { [self] in
            if self.completion != nil { self.cancellationReason = reason }
            finish(.failure(.cancelled))
            // This ACK fences logical sends and invalidates the request,
            // not the lifetime of a pending native dial. Its reservation is
            // retained until the real transport callback acknowledges it.
            completion?()
        }
    }

    private func isLive(_ token: UUID) -> Bool {
        completion != nil && attempt == token && permitted()
    }

    private func mayPerformIO(_ token: UUID) -> Bool {
        guard completion != nil, attempt == token else { return false }
        guard permitted() else { finish(.failure(.cancelled)); return false }
        guard DispatchTime.now() < deadline else { finish(.failure(.timeout)); return false }
        return true
    }

    var deadlineExpired: Bool { DispatchTime.now() >= deadline }
    var originalDeadline: TimeInterval { schedulingDeadline }
    fileprivate var originalDeadlineForSelfTest: DispatchTime { deadline }

    private func dial(_ token: UUID) {
        guard mayPerformIO(token) else { return }
        guard let reservation = connections.reserveDial() else {
            // Native ingress may revoke an idle checkout after the pool's
            // availability hint. Transient setup pressure queues this request
            // again without a capacity failure or a new deadline.
            enqueueTransport(); return
        }
        finishResolverQueueWait(outcome: .success, admitted: true)
        evidenceObserver?(retried ? .reusedThenFresh : .fresh)
        pendingDial = reservation
        let trace = diagnostics.beginDNSAttempt(requestID: diagnosticRequestID,
            transport: dnsProtocol.diagnosticTransport, purpose: connectionOnly ? .prewarm : .query,
            serverName: dnsProtocol.serverName, endpointIdentity: dnsProtocol.diagnosticIdentity,
            address: dnsProtocol.connectHost + "|" + String(dnsProtocol.port), context: executionContext)
        attemptTrace = trace
        exchangeTrace?.attachPhysicalAttempt(trace.id)
        guard let streamDialer else {
            if case .proxyTCP = dnsProtocol {
                _ = connections.completeDial(reservation); pendingDial = nil
                finish(.failure(.configuration)); return
            }
            startDirectTLS(token, reservation: reservation); return
        }
        let connections = self.connections, queue = self.queue, admission = failureAdmission
        pendingDialCancellation = streamDialer(dnsProtocol.connectHost, dnsProtocol.port, dnsProtocol.serverName, queue, trace,
                                               admission.observe) {
            [weak self] result in
            if case .failure(let error) = result { admission.observe(error) }
            queue.async {
                let accepted = connections.completeDial(reservation)
                if let self, self.completion != nil, self.attempt == token, case .failure(let error) = result {
                    self.observeBarrier(EncryptedDNSQueryFailure.classify(error))
                }
                guard accepted, let self, self.isLive(token) else {
                    if case .success(let stream) = result { stream.cancel() }
                    return
                }
                self.pendingDial = nil
                self.pendingDialCancellation = nil
                switch result {
                case .success(let stream):
                    guard let leased = connections.adopt(stream) else { self.finish(.failure(.capacity)); return }
                    self.stream = leased; self.send(token)
                case .failure(let error): self.finish(.failure(EncryptedDNSQueryFailure.classify(error)))
                }
            }
        }
    }

    private func startDirectTLS(_ token: UUID, reservation: UUID) {
        let trace = attemptTrace
        trace?.setRoute(.direct, identity: "direct|" + (ProxyEngine.currentOutboundInterface?.name ?? "default"))
        trace?.record(.tlsStarted)
        guard let port = NWEndpoint.Port(rawValue: dnsProtocol.port) else {
            _ = connections.completeDial(reservation); pendingDial = nil; finish(.failure(.configuration)); return
        }
        let tls = NWProtocolTLS.Options()
        // Do not replace the authenticated identity with a bootstrap address.
        // The default platform verification checks both chain and identity.
        var cleanSNI = DoHEndpoint.unbracketed(dnsProtocol.serverName)
        if cleanSNI.contains(":"), let pct = cleanSNI.firstIndex(of: "%") { cleanSNI = String(cleanSNI[..<pct]) }
        cleanSNI.withCString {
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, $0)
        }
        for protocolName in dnsProtocol.alpn {
            protocolName.withCString {
                sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, $0)
            }
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let parameters = NWParameters(tls: tls, tcp: tcp)
        if dnsProtocol.connectHost != "::1" && !dnsProtocol.connectHost.hasPrefix("127.") {
            if let outbound = ProxyEngine.currentOutboundInterface {
                parameters.requiredInterface = outbound
            } else {
                parameters.prohibitedInterfaceTypes = [.other]
            }
        }
        let connection = NWConnection(host: NWEndpoint.Host(dnsProtocol.connectHost),
                                      port: port, using: parameters)
        directConnection = connection
        let admission = failureAdmission, connections = self.connections
        // NWConnection.cancel() is asynchronous. These closures retain the
        // native handle and store until its actual terminal callback, even
        // when the request itself has already been released. Every terminal
        // or successfully published ready detaches the handler to break the
        // deliberate handshaking keep-alive cycle.
        connection.stateUpdateHandler = encryptedDNSDirectTLSStateHandler(
            completeDial: { connections.completeDial(reservation) },
            canPublish: { [weak self] in self?.mayPerformIO(token) ?? false },
            cancel: { connection.cancel() },
            detach: { connection.stateUpdateHandler = nil },
            ready: { [weak self] in
                guard let self else { connection.cancel(); return }
                trace?.record(.tlsReady)
                trace?.complete(.dnsTLSHandshake, outcome: .success)
                self.pendingDial = nil; self.directConnection = nil
                guard let leased = connections.adopt(EncryptedDNSNetworkStream(connection)) else {
                    self.finish(.failure(.capacity)); return
                }
                self.stream = leased; self.send(token)
            },
            failure: { [weak self] reason in
                guard let self, self.completion != nil, self.attempt == token else { return }
                trace?.complete(.dnsTLSHandshake, outcome: reason == .cancelled ? .cancelled : .failure)
                self.finish(.failure(reason))
            },
            observe: { error in
                if let trace { trace.record(.tlsFailure, error: error, admitting: { admission.observe(error) }) }
                else { admission.observe(error) }
            })
        connection.start(queue: queue)
    }

    private func recoverIdle(_ token: UUID) -> Bool {
        guard mayPerformIO(token), borrowedIdle, !retried, let old = stream, old.receivedBytes == 0 else { return false }
        // The peer has supplied no response bytes. DNS is read-only, so a
        // single fresh encrypted transport may repeat this query safely.
        recordLeaseIOProgress(beforeIdleRetry: true)
        retried = true; borrowedIdle = false; stream = nil
        attempt = UUID()
        observeProxyExchange(.failure)
        connections.discard(old)
        httpResponse = DoHHTTPResponseParser(); tlsResponse.removeAll()
        responseStarted = false
        enqueueTransport()
        return true
    }

    private func observeBarrier(_ reason: EncryptedDNSQueryFailure) {
        guard !reason.permitsProxyFallback, reason != .cancelled else { return }
        failureAdmission.observe(reason)
        if downgradeBarrier == nil { downgradeBarrier = reason }
        // Synchronous observer, before an encrypted-only retry can queue a
        // new dial. A shorter parent cutoff must not erase this deny reason.
        barrierObserver?(.failure(reason))
    }

    private func send(_ token: UUID) {
        guard mayPerformIO(token) else { return }
        guard let stream else { finish(.failure(.cancelled)); return }
        if connectionOnly { finish(.success(Data()), reusable: true); return }
        ioSendStarted = DispatchTime.now().uptimeNanoseconds
        ioStreamBaseline = stream.dnsStreamProgressSnapshot()
        ioReadPendingAtSend = stream.diagnosticReadPending
        ioResolverReadRequests = 0
        ioFirstResolverRead = nil
        recordQuery(.querySendStarted)
        if case .proxyTCP = dnsProtocol { proxyExchangeStarted = NetworkPerformanceDiagnostics.now() }
        let ingress: ((Data?, Bool, Error?) -> Void)?
        if case .proxyTCP = dnsProtocol { ingress = failureAdmission.observeProxyTCPIngress }
        else { ingress = nil }
        stream.send(requestBytes, failureObserver: failureAdmission.observe, ingressObserver: ingress) { [weak self] error in
            guard let self else { return }
            // Pooled callbacks already run on this queue. Register a deny
            // before adding another async hop: cancellation may have revoked
            // pool registration but its logical finish is still behind this
            // event. Metadata is not permission to send or deliver anything.
            if self.completion != nil, self.attempt == token {
                if let error {
                    self.observeBarrier(EncryptedDNSQueryFailure.classify(error))
                    self.recordQuery(.querySendFailure, error: error)
                } else { self.recordQuery(.querySent) }
            }
            self.queue.async { [self] in
                guard self.isLive(token) else {
                    if self.completion != nil, self.attempt == token { self.finish(.failure(.cancelled)) }
                    return
                }
                if let error {
                    let reason = EncryptedDNSQueryFailure.classify(error)
                    if reason == .other { self.observeBarrier(reason) }
                    let canRetryEncrypted = self.permitsIdleRetry(reason)
                    if !canRetryEncrypted || !self.recoverIdle(token) { self.finish(.failure(reason)) }
                } else { self.read(token) }
            }
        }
    }

    private func read(_ token: UUID) {
        guard mayPerformIO(token) else { return }
        if stream != nil {
            if ioResolverReadRequests < UInt64.max { ioResolverReadRequests += 1 }
            if ioFirstResolverRead == nil { ioFirstResolverRead = DispatchTime.now().uptimeNanoseconds }
        }
        stream?.receive { [weak self] data, complete, error in
            guard let self else { return }
            // PooledConnection guarantees this callback's owner queue. Parse
            // here, without a second async hop that cancellation could outrun.
            guard self.completion != nil, self.attempt == token else { return }
            if data?.isEmpty == false, !self.responseStarted {
                self.responseStarted = true
                self.recordQuery(.responseStarted)
            }
            if let error {
                self.observeBarrier(EncryptedDNSQueryFailure.classify(error))
                self.recordQuery(.responseFailure, error: error)
            }
            guard self.permitted() else {
                // This event entered the pool queue before its cancellation
                // finish. Observe a complete/invalid reply as metadata only;
                // never send another read or deliver to the revoked request.
                self.inspectCancelledReply(data, complete: complete, error: error)
                return
            }
            if let error {
                let reason = EncryptedDNSQueryFailure.classify(error)
                let canRetryEncrypted = self.permitsIdleRetry(reason)
                if !canRetryEncrypted || !self.recoverIdle(token) { self.finish(.failure(reason)) }
                return
            }
            if complete, (data?.isEmpty ?? true), self.stream?.receivedBytes == 0 {
                if self.recoverIdle(token) { return }
                // A clean close before any response bytes is a transport
                // failure. Preserve the bounded idle retry and let finish()
                // retain any native denial admitted before this empty EOF.
                self.recordResponseMetadata(rejection: "emptyResponse")
                self.finish(.failure(.network)); return
            }
            switch self.dnsProtocol {
            case .https:
                switch self.httpResponse.ingest(data ?? Data(), endOfStream: complete) {
                case .pending:
                    if complete { self.finish(.failure(.network)) }
                    else { self.read(token) }
                case .answer(let answer): self.finishValidated(answer, reusable: self.httpResponse.reusable)
                case .invalid:
                    self.recordResponseMetadata(rejection: "httpFraming")
                    if self.httpResponse.statusCode == 429 {
                        self.retried = true
                        self.connections.discardIdle()
                        self.finish(.failure(.network))
                    } else {
                        self.finish(.failure(.invalidResponse))
                    }
                }
            case .tls, .proxyTCP:
                let input = data ?? Data()
                guard input.count <= 65_537 - self.tlsResponse.count else {
                    self.recordResponseMetadata(rejection: "streamFraming")
                    self.finish(.failure(.invalidResponse)); return
                }
                self.tlsResponse.append(input)
                if self.tlsResponse.count >= 2 {
                    let length = Int(self.tlsResponse[self.tlsResponse.startIndex]) << 8
                        | Int(self.tlsResponse[self.tlsResponse.startIndex + 1])
                    guard (12...65_535).contains(length),
                          self.tlsResponse.count <= length + 2 else {
                        self.recordResponseMetadata(rejection: "streamFraming")
                        self.finish(.failure(.invalidResponse)); return
                    }
                    if self.tlsResponse.count == length + 2 {
                        self.finishValidated(Data(self.tlsResponse.dropFirst(2)), reusable: !complete)
                        return
                    }
                }
                if complete {
                    if case .proxyTCP = self.dnsProtocol, !self.tlsResponse.isEmpty {
                        self.recordResponseMetadata(rejection: "streamFraming")
                        self.finish(.failure(.invalidResponse))
                    } else { self.finish(.failure(.network)) }
                }
                else { self.read(token) }
            }
        }
    }

    private func inspectCancelledReply(_ data: Data?, complete: Bool, error: Error?) {
        guard barrierObserver != nil, error == nil else { return }
        switch dnsProtocol {
        case .https:
            // Copy only on the rare cancellation boundary, not the hot path.
            var parser = httpResponse
            switch parser.ingest(data ?? Data(), endOfStream: complete) {
            case .answer(let answer): publishAnswerBarrier(answer)
            case .invalid: observeBarrier(.invalidResponse)
            case .pending: break
            }
        case .tls, .proxyTCP:
            let input = data ?? Data()
            guard input.count <= 65_537 - tlsResponse.count else { observeBarrier(.invalidResponse); return }
            var response = tlsResponse; response.append(input)
            guard response.count >= 2 else { return }
            let length = Int(response[response.startIndex]) << 8 | Int(response[response.startIndex + 1])
            guard (12...65_535).contains(length), response.count <= length + 2 else {
                observeBarrier(.invalidResponse); return
            }
            if response.count == length + 2 { publishAnswerBarrier(Data(response.dropFirst(2))) }
        }
    }

    private func publishAnswerBarrier(_ answer: Data) {
        guard let barrierObserver else { return }
        guard DNSMessageInspection.responseMatchesQuery(answer, query: query) else {
            observeBarrier(.invalidResponse); return
        }
        barrierObserver(.answer(answer))
    }

    private func finishValidated(_ answer: Data, reusable: Bool) {
        let matches = DNSMessageInspection.responseMatchesQuery(answer, query: query)
        let responseCode = answer.count >= 4 ? answer[answer.startIndex + 3] & 0x0f : nil
        recordResponseMetadata(dnsResponseCode: responseCode, rejection: matches ? nil : "dnsIdentity")
        guard matches else {
            finish(.failure(.invalidResponse)); return
        }
        recordQuery(.responseComplete)
        barrierObserver?(.answer(answer))
        guard DispatchTime.now() < deadline else { finish(.failure(.timeout)); return }
        if let codes = DNSMessageInspection.extendedDNSErrorCodes(in: answer) {
            exchangeTrace?.recordResponse(extendedDNSErrorCodes: codes)
        }
        finish(.success(answer), reusable: reusable)
    }

    private func recordResponseMetadata(dnsResponseCode: UInt8? = nil, rejection: String? = nil) {
        exchangeTrace?.recordResponse(httpStatusCode: httpResponse.statusCode,
            responseBytes: stream?.receivedBytes, dnsResponseCode: dnsResponseCode, rejection: rejection)
    }

    /// Snapshot before native close/cancel callbacks can add teardown traffic.
    /// A retry starts a new baseline even if its prior stream was observable.
    private func recordLeaseIOProgress(beforeIdleRetry: Bool = false) {
        guard let started = ioSendStarted, let stream else { return }
        let delta = ioStreamBaseline.flatMap { baseline in
            stream.dnsStreamProgressSnapshot()?.delta(since: baseline)
        }
        let received = stream.receivedBytes
        let pending = stream.diagnosticReadPending
        func elapsed(_ end: UInt64) -> Double {
            Double(end >= started ? end - started : 0) / 1_000_000
        }
        exchangeTrace?.recordLeaseIOProgress(DNSQueryLeaseIOProgressSnapshot(
            ordinal: retried ? 2 : 1, reusedConnection: borrowedIdle,
            sampledBeforeIdleRetry: beforeIdleRetry,
            millisecondsSinceSend: elapsed(DispatchTime.now().uptimeNanoseconds),
            resolverReadRequests: ioResolverReadRequests,
            firstResolverReadMilliseconds: ioFirstResolverRead.map(elapsed),
            pooledReadPendingAtSend: ioReadPendingAtSend, pooledReadPendingAtSample: pending,
            plaintextResponseBytes: min(1_048_576, max(0, received)), stream: delta))
        ioSendStarted = nil; ioStreamBaseline = nil
    }

    private func finish(_ input: Result<Data, EncryptedDNSQueryFailure>, reusable: Bool = false) {
        guard let done = completion else { return }
        let queueOutcome: NetworkPerformanceOutcome
        switch input {
        case .success: queueOutcome = .success
        case .failure(.cancelled), .failure(.policy): queueOutcome = .cancelled
        case .failure: queueOutcome = .failure
        }
        finishResolverQueueWait(outcome: queueOutcome)
        recordLeaseIOProgress()
        if case .failure(let reason) = input {
            let cancellation: DNSAttemptCancellationReason?
            switch reason {
            case .timeout: cancellation = .requestDeadline
            case .policy: cancellation = .policyChanged
            case .cancelled: cancellation = cancellationReason ?? (permitted() ? .callerCancelled : .policyChanged)
            default: cancellation = nil
            }
            if let cancellation {
                attemptTrace?.cancel(cancellation); exchangeTrace?.cancel(cancellation)
            }
        }
        // This is the linearization point for logical cancel/termination.
        // Publish all previously admitted denies before clearing the token,
        // invoking native cancellation or letting the caller ACK its phase.
        let admittedDenial = failureAdmission.seal()
        if let admittedDenial { observeBarrier(admittedDenial) }
        if let answer = failureAdmission.admittedProxyTCPAnswer { barrierObserver?(.answer(answer)) }
        let result: Result<Data, EncryptedDNSQueryFailure>
        if case .proxyTCP = dnsProtocol, let denial = admittedDenial ?? downgradeBarrier {
            result = .failure(denial)
        } else if case .failure(let reason) = input, reason.permitsProxyFallback,
           let denial = admittedDenial ?? downgradeBarrier {
            // An unknown failure may still retry the same authenticated
            // encrypted provider once, but a later timeout must not erase it
            // and turn it into permission for plaintext disclosure.
            result = .failure(denial)
        } else { result = input }
        if case .failure(.timeout) = result, inheritedOwnsDeadline, DispatchTime.now() >= deadline {
            // Only the winning inherited timer may identify this boundary.
            // A shorter local timeout or an early native timeout cannot make
            // the adaptive owner claim that its caller's deadline has elapsed.
            executionContext?.recordInheritedDeadlineReached()
        }
        if case .failure(let reason) = result { observeBarrier(reason) }
        if case .failure(let reason) = result {
            exchangeTrace?.finish(reason == .cancelled ? .cancelled : .failure, failureReason: String(describing: reason))
        } else { exchangeTrace?.finish(.success, failureReason: nil) }
        attemptTrace?.record(.requestFinished)
        switch result {
        case .success: observeProxyExchange(.success)
        case .failure(.cancelled): observeProxyExchange(.cancelled)
        case .failure: observeProxyExchange(.failure)
        }
        completion = nil
        transportAdmission = nil
        attempt = UUID()
        timer?.setEventHandler {}
        timer?.cancel()
        timer = nil
        // Keep the direct dial's state receipt until its native terminal ACK;
        // neither logical finish nor cancel() itself releases that slot.
        directConnection?.cancel()
        directConnection = nil
        pendingDial = nil
        let cancelDial = pendingDialCancellation
        pendingDialCancellation = nil
        // Do not release the reserved slot here. The dial callback closes
        // late successes and acknowledges actual cancellation to the store.
        cancelDial?()
        let leased = stream
        stream = nil
        let succeeded: Bool
        if case .success = result { succeeded = true } else { succeeded = false }
        done(result, leased, reusable && succeeded)
    }

    private func observeProxyExchange(_ outcome: NetworkPerformanceOutcome) {
        guard let started = proxyExchangeStarted else { return }
        proxyExchangeStarted = nil
        diagnostics.record(.dnsProxyFallbackExchange,
            milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started), outcome: outcome)
    }

    private func recordQuery(_ event: DNSConnectionAttemptEvent, error: Error? = nil) {
        if let attemptTrace {
            // Reserve both event orders before either diagnostic bridge can
            // invoke arbitrary CustomNSError conversion code.
            attemptTrace.record(event, error: error, admitting: { self.exchangeTrace?.record(event, error: error) })
        } else { exchangeTrace?.record(event, error: error) }
    }

    private func permitsIdleRetry(_ reason: EncryptedDNSQueryFailure) -> Bool {
        if case .proxyTCP = dnsProtocol { return reason.permitsProxyFallback }
        return reason.permitsProxyFallback || reason == .other
    }
}

private final class EncryptedDNSNetworkStream: NativeOutboundByteStream {
    private let connection: NWConnection
    init(_ connection: NWConnection) { self.connection = connection }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed(completion))
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) {
            data, _, complete, error in completion(data, complete, error)
        }
    }
    func cancel() { connection.cancel() }
}

private enum DoHHTTPWire {
    static func request(endpoint: DoHEndpoint, query: Data) -> Data? {
        guard let components = URLComponents(url: endpoint.url, resolvingAgainstBaseURL: false),
              !endpoint.host.isEmpty else { return nil }
        let host = endpoint.host
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
            + "Connection: keep-alive\r\n\r\n"
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
    private var permitsPersistence = false
    private var sawEOF = false, completed = false
    private(set) var reusable = false
    private(set) var statusCode: Int?

    mutating func ingest(_ input: Data, endOfStream: Bool) -> Result {
        guard !completed else { return .invalid }
        sawEOF = sawEOF || endOfStream
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
                      let version = statusLine.split(separator: " ", maxSplits: 2).first,
                      version == "HTTP/1.1" || version == "HTTP/1.0",
                      let status = Int(statusLine.split(separator: " ", maxSplits: 2)
                        .dropFirst().first ?? "") else { return .invalid }
                if (100...599).contains(status) { statusCode = status }
                guard (200...299).contains(status) else { return .invalid }
                var headers: [String: String] = [:]
                var connectionTokens = Set<String>()
                for line in lines.dropFirst() {
                    guard let colon = line.firstIndex(of: ":") else { return .invalid }
                    let key = String(line[..<colon]).lowercased()
                    guard Self.isHeaderToken(key),
                          headers[key] == nil || !["content-length", "transfer-encoding"].contains(key) else {
                        return .invalid
                    }
                    let value =
                        line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                    guard !value.unicodeScalars.contains(where: {
                        ($0.value < 32 && $0.value != 9) || $0.value == 127
                    }) else { return .invalid }
                    if key == "connection" {
                        for raw in value.split(separator: ",", omittingEmptySubsequences: false) {
                            let token = raw.trimmingCharacters(in: .whitespaces).lowercased()
                            guard Self.isHeaderToken(token) else { return .invalid }
                            connectionTokens.insert(token)
                        }
                    }
                    headers[key] = value
                }
                guard headers["transfer-encoding"] == nil || headers["content-length"] == nil else {
                    return .invalid
                }
                if let raw = headers["content-type"] {
                    let mediaType = raw.split(separator: ";", maxSplits: 1).first
                        .map(String.init)?.trimmingCharacters(in: .whitespaces).lowercased()
                    guard mediaType == "application/dns-message" else { return .invalid }
                }
                if let encoding = headers["transfer-encoding"] {
                    guard encoding.lowercased() == "chunked" else { return .invalid }
                    framing = .chunkSize
                    permitsPersistence = version == "HTTP/1.1" && !connectionTokens.contains("close")
                } else if let raw = headers["content-length"] {
                    guard !raw.isEmpty, raw.utf8.allSatisfy({ (48...57).contains($0) }),
                          let count = Int(raw), count <= Self.maxBody else { return .invalid }
                    framing = .fixed(count)
                    permitsPersistence = version == "HTTP/1.1" && !connectionTokens.contains("close")
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
                      size.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
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
                guard let text = String(data: buffer[buffer.startIndex..<end.lowerBound], encoding: .utf8) else {
                    return .invalid
                }
                for line in text.components(separatedBy: "\r\n") {
                    guard let colon = line.firstIndex(of: ":") else { return .invalid }
                    let name = String(line[..<colon]).lowercased()
                    guard Self.isHeaderToken(name),
                          !["content-length", "transfer-encoding", "connection", "host"].contains(name) else {
                        return .invalid
                    }
                    let value = line[line.index(after: colon)...]
                    guard !value.unicodeScalars.contains(where: {
                        ($0.value < 32 && $0.value != 9) || $0.value == 127
                    }) else { return .invalid }
                }
                // Non-empty trailers are accepted only for this transaction.
                permitsPersistence = false
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

    private static func isHeaderToken(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                || [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains($0)
        }
    }

    private mutating func answer() -> Result {
        guard body.count >= 12, buffer.isEmpty else { return .invalid }
        completed = true
        reusable = permitsPersistence && !sawEOF
        return .answer(body)
    }
}

/// Adapts a `DoHResolver` to the datagram interface the tunnel already speaks.
public final class DoHRoutedDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding, DNSConnectionPrewarming, DNSQueryExecutionContextAccepting {
    private let flow: EncryptedDNSDatagramFlow

    public init(resolver: DoHResolver, receive: @escaping (Data) -> Void,
                failure: ((Error) -> Void)? = nil) {
        flow = EncryptedDNSDatagramFlow(
            contextualResolve: { resolver.resolveResult(query: $0, completion: $1, downgradeBarrier: $2, transportEvidence: $3, executionContext: $4) },
            cancelRequest: { resolver.cancel($0, reason: $1, completion: $2) },
            prepare: { resolver.prewarm(absoluteDeadline: $0, completion: $1) }, receive: receive, failure: failure)
    }

    public func send(_ data: Data) { flow.send(data) }
    package func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) { flow.setDNSQueryExecutionContext(context) }
    public func cancel() { flow.cancel() }
    package func cancel(completion: @escaping () -> Void) { flow.cancel(completion: completion) }
    package func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        flow.cancel(reason: reason, completion: completion)
    }
    package func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { flow.proxyFallbackBarrier() }
    package func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { flow.dnsQueryTransportEvidence() }
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Void, EncryptedDNSQueryFailure>) -> Void) {
        flow.prewarm(absoluteDeadline: absoluteDeadline, completion: completion)
    }
}

/// Report an authenticated resolver outage as SERVFAIL, rather than leaving
/// the local DNS client waiting for an answer that cannot arrive.
private enum DoHFailureResponse {
    static func reply(to query: Data) -> Data? {
        DNSMessageInspection.errorResponse(to: query, code: .servfail)
    }
}

/// Track only this flow's request IDs. A flow must not cancel every request
/// owned by a resolver that is shared with other local DNS clients.
private final class EncryptedDNSDatagramFlow {
    private let resolve: (Data, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                          @escaping (DNSProxyFallbackBarrier) -> Void,
                          @escaping (DNSQueryTransportEvidence) -> Void, DNSQueryExecutionContext?) -> UUID?
    private let cancelRequest: (UUID, DNSAttemptCancellationReason, @escaping () -> Void) -> Void
    private let prepare: ((TimeInterval, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID?)?
    private let receive: (Data) -> Void
    private let failure: ((Error) -> Void)?
    private let lock = NSLock()
    private var liveTokens = Set<UUID>()
    private var requestIDs: [UUID: UUID] = [:]
    private var cancelled = false
    private var cancellationReason: DNSAttemptCancellationReason?
    private let cancellationFence = DispatchGroup()
    private var barrier: DNSProxyFallbackBarrier?
    private var evidence = DNSQueryTransportEvidence.notStarted
    private var executionContext: DNSQueryExecutionContext?

    convenience init(resolve: @escaping (Data, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                             @escaping (DNSProxyFallbackBarrier) -> Void,
                             @escaping (DNSQueryTransportEvidence) -> Void) -> UUID?,
         cancelRequest: @escaping (UUID, DNSAttemptCancellationReason, @escaping () -> Void) -> Void,
         prepare: ((TimeInterval, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID?)? = nil,
         receive: @escaping (Data) -> Void,
         failure: ((Error) -> Void)? = nil) {
        self.init(contextualResolve: { query, done, barrier, evidence, _ in resolve(query, done, barrier, evidence) },
                  cancelRequest: cancelRequest, prepare: prepare, receive: receive, failure: failure)
    }

    init(contextualResolve: @escaping (Data, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                             @escaping (DNSProxyFallbackBarrier) -> Void,
                             @escaping (DNSQueryTransportEvidence) -> Void, DNSQueryExecutionContext?) -> UUID?,
         cancelRequest: @escaping (UUID, DNSAttemptCancellationReason, @escaping () -> Void) -> Void,
         prepare: ((TimeInterval, @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID?)? = nil,
         receive: @escaping (Data) -> Void,
         failure: ((Error) -> Void)? = nil) {
        self.resolve = contextualResolve
        self.cancelRequest = cancelRequest
        self.prepare = prepare
        self.receive = receive
        self.failure = failure
    }

    deinit { cancel(reason: .cleanup, completion: {}) }

    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
        lock.lock(); defer { lock.unlock() }
        // A caller installs once, before send. Never retarget an in-flight
        // registration or revive a cancelled flow through diagnostic metadata.
        guard !cancelled, liveTokens.isEmpty, requestIDs.isEmpty else { return }
        executionContext = context
    }

    func send(_ query: Data) {
        perform(query, preparationDeadline: nil, prepared: nil)
    }

    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Void, EncryptedDNSQueryFailure>) -> Void) {
        perform(Data(), preparationDeadline: absoluteDeadline, prepared: completion)
    }

    private func perform(_ query: Data, preparationDeadline: TimeInterval?,
                         prepared: ((Result<Void, EncryptedDNSQueryFailure>) -> Void)?) {
        let token = UUID()
        lock.lock()
        guard !cancelled else { lock.unlock(); prepared?(.failure(.cancelled)); return }
        let context = executionContext
        liveTokens.insert(token)
        // Keep cancellation ACK behind even an in-progress registration. A
        // synchronous resolver callback can finish before its ID is returned.
        cancellationFence.enter()
        lock.unlock()
        let complete: (Result<Data, EncryptedDNSQueryFailure>) -> Void = { [weak self] result in
            guard let self else { return }
            let code: DNSResponseCode = DNSMessageInspection.singleQuestion(in: query) == nil
                ? .formerr : .servfail
            self.lock.lock()
            self.liveTokens.remove(token)
            self.requestIDs.removeValue(forKey: token)
            let stopped = self.cancelled
            if !stopped {
                self.cancellationFence.enter()
                if preparationDeadline == nil { switch result {
                case .success(let answer): self.barrier = .answer(answer)
                case .failure(let reason) where !reason.permitsProxyFallback && reason != .cancelled:
                    if self.barrier == nil { self.barrier = .failure(reason) }
                default: break
                } }
            }
            self.lock.unlock()
            guard !stopped else { return }
            defer { self.cancellationFence.leave() }
            if let prepared { prepared(result.map { _ in () }); return }
            switch result {
            case .success(let answer): self.receive(answer)
            case .failure(let reason):
                if let failure = self.failure { failure(reason) }
                else if let reply = DNSMessageInspection.errorResponse(to: query, code: code) { self.receive(reply) }
            }
        }
        let observeBarrier: (DNSProxyFallbackBarrier) -> Void = { [weak self] observation in
            guard let self else { return }
            self.lock.lock()
            switch observation {
            case .answer(let answer): self.barrier = .answer(answer)
            case .failure(let error):
                if self.barrier == nil { self.barrier = .failure(error) }
            }
            self.lock.unlock()
        }
        let observeEvidence: (DNSQueryTransportEvidence) -> Void = { [weak self] observation in
            guard let self else { return }
            self.lock.lock(); self.evidence = observation; self.lock.unlock()
        }
        let id: UUID?
        if let preparationDeadline {
            if let prepare { id = prepare(preparationDeadline, complete) }
            else { complete(.failure(.configuration)); id = nil }
        } else { id = resolve(query, complete, observeBarrier, observeEvidence, context) }
        guard let id else { cancellationFence.leave(); return }
        lock.lock()
        let stopped = cancelled || !liveTokens.contains(token)
        let reason = cancellationReason ?? .cleanup
        if !stopped { requestIDs[token] = id }
        lock.unlock()
        let fence = cancellationFence
        if stopped { cancelRequest(id, reason) { fence.leave() } }
        else { cancellationFence.leave() }
    }

    func cancel() { cancel(completion: {}) }

    func cancel(reason: DNSAttemptCancellationReason = .callerCancelled,
                completion: @escaping () -> Void) {
        lock.lock()
        if !cancelled { cancellationReason = reason }
        cancelled = true
        let reason = cancellationReason ?? reason
        let active = Array(requestIDs.values)
        active.forEach { _ in cancellationFence.enter() }
        requestIDs.removeAll()
        liveTokens.removeAll()
        lock.unlock()
        let fence = cancellationFence
        active.forEach { id in cancelRequest(id, reason) { fence.leave() } }
        cancellationFence.notify(queue: .global(qos: .userInitiated), execute: completion)
    }

    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
        lock.lock(); defer { lock.unlock() }; return barrier
    }
    func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence {
        lock.lock(); defer { lock.unlock() }; return evidence
    }
}

// MARK: - Self-test

public enum EncryptedDNSSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "加密 DNS 自检失败：\(text)" }
    }

    static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try runOffline()
        try bootstrapLoopbackDialAndSNI()
    }

    /// Transport and wire privacy vectors with no listeners, system DNS or
    /// external connections. Fake streams exercise the injected transport only.
    public static func runOffline() throws {
        try endpointParsing()
        try dotEndpointParsing()
        try wireFormatCompatibility()
        try bootstrapHTTPWire()
        try bootstrapHTTPResponseParsing()
        try questionInspection()
        try injectedTransportTransactions()
        try cancellationAndAdmission()
        try connectionReuse()
        try queryTransportEvidence()
        try encryptedConnectionPrewarming()
        try pooledTransportFailureAdmission()
        try proxyTCPConnectionPool()
        try boundedQueryScheduling()
        try cancellableDialCleanup()
        try physicalPressureQueueRecovery()
        try directDialCancellationReceipts()
        try DNSRoutedTLSConnectionAttemptSelfTest.run()
        try DNSNativeFailureAdmissionSelfTest.run()
        try typedFailureReasons()
        try routedFailureCallbackPreservesCapacity()
        try frontierProtocolsAndWireExtensions()
        try protocolRulesAndMieruUDPRecovery()
    }

    private static func queryTransportEvidence() throws {
        let endpoint = DoTEndpoint("tls://evidence.selftest.invalid#203.0.113.53")!
        let query = FakeIPSelfTest.query("evidence.example", type: 1, id: 0x7281)
        let probe = ReuseProbe { index in
            if index > 0 { return reuseAuto(2) }
            return ReuseMemoryStream { stream, wire, number, done in
                if number == 1 { done(nil); stream.emit(reuseWireReply(wire, mode: 2)) }
                else { done(NWError.posix(.ECONNRESET)) }
            }
        }
        let resolver = DoTResolver(endpoint: endpoint, streamDialer: probe.dialer)
        defer { resolver.cancel() }
        let lock = NSLock()
        for expected: [DNSQueryTransportEvidence] in [[.fresh], [.reused, .reusedThenFresh], [.reused]] {
            let done = DispatchSemaphore(value: 0)
            var observations: [DNSQueryTransportEvidence] = [], answer: Data?
            resolver.resolveResult(query: query, completion: { result in
                lock.lock(); answer = try? result.get(); lock.unlock(); done.signal()
            }, transportEvidence: { value in lock.lock(); observations.append(value); lock.unlock() })
            try expect(done.wait(timeout: .now() + 2) == .success, "冷热证据事务未结束")
            lock.lock(); let valid = observations == expected && answer != nil; lock.unlock()
            try expect(valid, "新建、复用或复用后重连证据与真实pool路径不符")
        }
        let flowDone = DispatchSemaphore(value: 0)
        let flow = DoTRoutedDatagram(resolver: resolver, receive: { _ in flowDone.signal() })
        flow.send(query)
        try expect(flowDone.wait(timeout: .now() + 2) == .success && flow.dnsQueryTransportEvidence() == .reused,
                   "datagram未向调度器透传实际复用证据")
        flow.cancel()

        let queueDone = DispatchSemaphore(value: 0), active = DispatchSemaphore(value: 0)
        let pool = EncryptedDNSRequestPool(protocol: .tls(endpoint), label: "app.hajimi.dns.evidence.queue",
            streamDialer: { _, _, _, _, done in active.signal(); done(.success(MemoryStream(response: nil))) },
            cancellableStreamDialer: nil, metadataStreamDialer: nil, timeout: .seconds(2), idleTimeout: 0,
            idleLimit: 0, idleHandoffGrace: 0, activeLimit: 1, clock: Date.init,
            resourceBudget: SOCKSUDPResourceLimits.shared)
        defer { pool.cancel() }
        _ = pool.resolve(query: query) { _ in }
        try expect(active.wait(timeout: .now() + 1) == .success, "排队证据样本未占据活动槽")
        var queuedEvidence: [DNSQueryTransportEvidence] = [], queuedResult: EncryptedDNSQueryFailure?
        _ = pool.resolveResult(query: query, completion: { result in
            lock.lock(); if case .failure(let failure) = result { queuedResult = failure }; lock.unlock()
            queueDone.signal()
        }, absoluteDeadline: ProcessInfo.processInfo.systemUptime + 0.04,
           transportEvidence: { value in lock.lock(); queuedEvidence.append(value); lock.unlock() })
        try expect(queueDone.wait(timeout: .now() + 1) == .success, "纯排队事务未按原期限结束")
        lock.lock(); let stayedQueued = queuedEvidence.isEmpty && queuedResult == .timeout; lock.unlock()
        try expect(stayedQueued && active.wait(timeout: .now()) == .timedOut,
                   "纯排队超时被误报为解析器连接或额外拨号")
    }

    private static func encryptedConnectionPrewarming() throws {
        let endpoint = DoTEndpoint("tls://prewarm.selftest.invalid#203.0.113.53")!
        let query = FakeIPSelfTest.query("first-page.example", type: 1, id: 0x7282)
        let probe = ReuseProbe { _ in reuseAuto(2) }
        let resolver = DoTResolver(endpoint: endpoint, streamDialer: probe.dialer)
        defer { resolver.cancel() }
        let lock = NSLock()
        for _ in 0..<2 {
            let done = DispatchSemaphore(value: 0)
            var prepared = false
            resolver.prewarm(absoluteDeadline: ProcessInfo.processInfo.systemUptime + 1) { result in
                lock.lock(); prepared = (try? result.get()) == Data(); lock.unlock(); done.signal()
            }
            try expect(done.wait(timeout: .now() + 2) == .success, "后台加密连接准备未完成")
            lock.lock(); let valid = prepared; lock.unlock()
            try expect(valid && probe.count == 1 && probe.streams.allSatisfy { $0.sendCount == 0 },
                       "预热重复拨号、发送了DNS消息或未保留连接")
        }
        let completed = DispatchSemaphore(value: 0)
        var evidence: [DNSQueryTransportEvidence] = [], answered = false
        resolver.resolveResult(query: query, completion: { result in
            lock.lock(); answered = (try? result.get()) != nil; lock.unlock(); completed.signal()
        }, transportEvidence: { value in lock.lock(); evidence.append(value); lock.unlock() })
        try expect(completed.wait(timeout: .now() + 2) == .success, "预热后的首个真实查询未完成")
        lock.lock(); let reused = answered && evidence == [.reused]; lock.unlock()
        try expect(reused && probe.count == 1 && probe.streams[0].sendCount == 1,
                   "真实首问没有复用预热连接，或预热被记成真实查询")

        let started = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
        var nativeCompletion: ((Result<any NativeOutboundByteStream, Error>) -> Void)?
        var nativeCancelCount = 0, unexpectedCompletion = false
        let pending = DoTResolver(endpoint: endpoint, cancellableStreamDialer: { _, _, _, _, done in
            lock.lock(); nativeCompletion = done; lock.unlock(); started.signal()
            return { lock.lock(); nativeCancelCount += 1; lock.unlock() }
        })
        defer { pending.cancel() }
        let flow = DoTRoutedDatagram(resolver: pending, receive: { _ in })
        flow.prewarm(absoluteDeadline: ProcessInfo.processInfo.systemUptime + 1) { _ in
            lock.lock(); unexpectedCompletion = true; lock.unlock()
        }
        try expect(started.wait(timeout: .now() + 1) == .success, "待取消预热没有开始连接")
        flow.cancel { cancelled.signal() }
        try expect(cancelled.wait(timeout: .now() + 1) == .success, "预热取消未完成逻辑ACK")
        let late = reuseAuto(2)
        lock.lock(); let callback = nativeCompletion; lock.unlock(); callback?(.success(late))
        pending.drainQueueForSelfTest()
        lock.lock(); let clean = nativeCancelCount == 1 && !unexpectedCompletion; lock.unlock()
        try expect(clean && late.cancelled && late.sendCount == 0,
                   "取消后晚到预热连接被发布、发送或泄漏")

        let expiredDone = DispatchSemaphore(value: 0)
        var expired: EncryptedDNSQueryFailure?
        resolver.prewarm(absoluteDeadline: ProcessInfo.processInfo.systemUptime - 1) { result in
            if case .failure(let reason) = result { expired = reason }; expiredDone.signal()
        }
        try expect(expiredDone.wait(timeout: .now()) == .success && expired == .timeout && probe.count == 1,
                   "过期预热仍建立了新连接")
        print("Encrypted DNS prewarm: no DNS payload, one retained connection, first-query reuse, duplicate suppression, cancellation ACK and late-dial cleanup passed")
    }

    private static func directDialCancellationReceipts() throws {
        let queue = DispatchQueue(label: "app.hajimi.dns.direct-receipt.selftest")
        let budget = SOCKSUDPGlobalBudget(resources: 0, packets: 0, bytes: 0)
        let store = EncryptedDNSConnectionStore(queue: queue, idleTimeout: 0, idleLimit: 0,
            idleHandoffGrace: 0, activeLimit: 16, coldDialLimit: 128,
            clock: Date.init, resourceBudget: budget)
        defer { queue.sync { store.cancel() } }
        try queue.sync {
            var logicalLive = false, receipts = 0, detaches = 0, cancels = 0, published = 0
            var failures: [EncryptedDNSQueryFailure] = []
            func handler(_ reservation: UUID,
                         admission: EncryptedDNSFailureAdmission = EncryptedDNSFailureAdmission())
                -> (NWConnection.State) -> Void {
                encryptedDNSDirectTLSStateHandler(
                    completeDial: { receipts += 1; return store.completeDial(reservation) },
                    canPublish: { logicalLive }, cancel: { cancels += 1 },
                    detach: { detaches += 1 }, ready: { published += 1 },
                    failure: { reason in
                        failures.append(reason)
                        if logicalLive {
                            // The production request finishes logically and
                            // sends native cancel; that is not a terminal ACK.
                            logicalLive = false; cancels += 1
                        }
                    }, observe: admission.observe)
            }
            var old: [(NWConnection.State) -> Void] = []
            for _ in 0..<128 {
                guard let reservation = store.reserveDial() else {
                    throw Failure(text: "direct receipt fixture could not reserve its physical dial")
                }
                old.append(handler(reservation))
            }
            try expect(store.reserveDial() == nil, "direct pending dials exceeded their physical admission bound")
            old.forEach { $0(.ready) }
            try expect(cancels == 128 && receipts == 0 && detaches == 0 && published == 0
                       && store.reserveDial() == nil,
                       "logical cancel/late-ready speculatively released a direct dial or published its stream")
            for (index, callback) in old.enumerated() {
                if index.isMultiple(of: 2) { callback(.cancelled) }
                else { callback(.failed(.posix(.ECONNRESET))) }
            }
            try expect(receipts == 128 && detaches == 128 && published == 0,
                       "direct terminal ACK did not retire the dial after its logical owner was released")
            var replacements: [UUID] = []
            for _ in 0..<128 {
                guard let token = store.reserveDial() else {
                    throw Failure(text: "real direct terminal receipts did not make admission reusable")
                }
                replacements.append(token)
            }
            old.forEach { $0(.cancelled); $0(.ready) }
            try expect(receipts == 128 && detaches == 128 && published == 0 && store.reserveDial() == nil,
                       "duplicate old direct callbacks released a replacement's slot or published twice")
            replacements.forEach { _ = store.completeDial($0) }

            logicalLive = true
            guard let denied = store.reserveDial() else { throw Failure(text: "direct deny receipt was not admitted") }
            let admission = EncryptedDNSFailureAdmission(), denyHandler = handler(denied, admission: admission)
            denyHandler(.waiting(.tls(-9807)))
            try expect(failures.last == .authentication && admission.seal() == .authentication
                       && receipts == 128 && detaches == 128 && !logicalLive,
                       "waiting authentication denial lost its barrier or fabricated a terminal receipt")
            var held: [UUID] = []
            for _ in 0..<127 {
                guard let token = store.reserveDial() else { throw Failure(text: "direct waiting receipt lost admission") }
                held.append(token)
            }
            try expect(store.reserveDial() == nil, "waiting denial released its native dial before cancellation ACK")
            denyHandler(.cancelled)
            held.forEach { _ = store.completeDial($0) }

            logicalLive = true
            guard let healthy = store.reserveDial() else { throw Failure(text: "healthy direct receipt was not admitted") }
            let healthyHandler = handler(healthy), beforeCancel = cancels
            healthyHandler(.ready)
            logicalLive = false
            healthyHandler(.ready); healthyHandler(.cancelled)
            try expect(published == 1 && receipts == 130 && detaches == 130 && cancels == beforeCancel,
                       "published direct stream was closed or adopted/refunded again by an old handler")
        }
        print("DNS direct dial receipts passed: 128 canceled/late-ready reservations await native terminal ACK, deny barrier and replacement/published ownership preserved")
    }

    /// The downgrade boundary must survive the entire pool/flow path, not
    /// merely an error enum tested in isolation. All peers here are memory.
    private static func typedFailureReasons() throws {
        let endpoint = DoTEndpoint("tls://typed.selftest.invalid#203.0.113.53")!
        let query = FakeIPSelfTest.query("typed.example.test", type: 1, id: 0x6801)
        func awaitResult(_ issue: (@escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID?) throws
            -> Result<Data, EncryptedDNSQueryFailure> {
            let done = DispatchSemaphore(value: 0), lock = NSLock()
            var value: Result<Data, EncryptedDNSQueryFailure>?
            _ = issue { result in lock.lock(); value = result; lock.unlock(); done.signal() }
            try expect(done.wait(timeout: .now() + 2) == .success, "typed failure callback was lost")
            lock.lock(); let result = value; lock.unlock()
            guard let result else { throw Failure(text: "typed failure result missing") }
            return result
        }
        func isFailure(_ result: Result<Data, EncryptedDNSQueryFailure>, _ expected: EncryptedDNSQueryFailure) -> Bool {
            if case .failure(let reason) = result { return reason == expected }
            return false
        }
        let vectors: [(Error, EncryptedDNSQueryFailure)] = [
            (NWError.posix(.ECONNREFUSED), .network), (NWError.posix(.ETIMEDOUT), .timeout),
            (NWError.tls(-9807), .authentication), (NWError.posix(.ECANCELED), .cancelled),
            (NodeConnectionAdmissionError.capacityExceeded, .capacity),
            (NodeConnectionAdmissionError.capacityExceeded as NSError, .capacity),
            (NativeOutboundError.crypto("memory crypto rejection"), .authentication),
            (NativeOutboundError.unsupported("memory configuration rejection"), .configuration),
            (NativeOutboundError.protocolError("memory framing rejection"), .invalidResponse),
            (NativeOutboundError.cancelled, .cancelled),
            (EncryptedDNSQueryFailure.policy, .policy),
            (NativeOutboundError.connection("unclassified memory failure"), .other),
            (NativeOutboundError.connection("嵌套 TLS 已取消"), .other),
            (NativeOutboundError.connection("cancelled"), .other),
            (NSError(domain: NSPOSIXErrorDomain, code: Int.max), .other),
        ]
        for (error, expected) in vectors {
            let resolver = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in done(.failure(error)) })
            let result = try awaitResult { resolver.resolveResult(query: query, completion: $0) }
            resolver.cancel()
            try expect(isFailure(result, expected), "pool erased a typed failure reason")
            try expect(expected.permitsProxyFallback == (expected == .network || expected == .timeout),
                       "non-network failure authorized a plaintext downgrade")
        }
        let nativeCancellation = NativeOutboundError.cancelled
        let cancellationReason = EncryptedDNSQueryFailure.classify(nativeCancellation)
        try expect(cancellationReason == .cancelled && !cancellationReason.permitsProxyFallback,
                   "typed native cancellation independently authorized plaintext fallback")
        let cancellationAdmission = EncryptedDNSFailureAdmission()
        cancellationAdmission.observe(nativeCancellation)
        try expect(cancellationAdmission.seal() == nil,
                   "own typed cancellation manufactured an unknown downgrade barrier")
        for denial in [EncryptedDNSQueryFailure.authentication, .other] {
            let admission = EncryptedDNSFailureAdmission()
            admission.observe(denial)
            admission.observe(nativeCancellation)
            try expect(admission.seal() == denial,
                       "typed cancellation erased admitted authentication or unknown metadata")
        }
        let silent = ReuseMemoryStream { _, _, _, done in done(nil) }
        let timeout = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in done(.success(silent)) },
                                  requestTimeout: .milliseconds(30))
        let timed = try awaitResult { timeout.resolveResult(query: query, completion: $0) }
        try expect(isFailure(timed, .timeout) && silent.cancelled, "deadline lost its type or did not close its lease")
        timeout.cancel()

        let invalid = ReuseMemoryStream { stream, wire, _, done in
            done(nil); var reply = reuseWireReply(wire, mode: 2); reply[2] ^= 1; stream.emit(reply)
        }
        let malformed = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in done(.success(invalid)) })
        let bad = try awaitResult { malformed.resolveResult(query: query, completion: $0) }
        try expect(isFailure(bad, .invalidResponse) && !EncryptedDNSQueryFailure.invalidResponse.permitsProxyFallback,
                   "wrong transaction identity became a retriable network outage")
        malformed.cancel()

        let sent = DispatchSemaphore(value: 0), fenced = DispatchSemaphore(value: 0), delivered = DispatchSemaphore(value: 0)
        let blackhole = ReuseMemoryStream { _, _, _, done in done(nil); sent.signal() }
        let cancelResolver = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in done(.success(blackhole)) })
        let flow = DoTRoutedDatagram(resolver: cancelResolver, receive: { _ in delivered.signal() },
                                    failure: { _ in delivered.signal() })
        flow.send(query)
        try expect(sent.wait(timeout: .now() + 2) == .success, "cancel fence fixture did not send")
        flow.cancel { fenced.signal() }
        try expect(fenced.wait(timeout: .now() + 2) == .success && blackhole.cancelled,
                   "flow cancel ACK preceded logical lease teardown")
        try expect(delivered.wait(timeout: .now() + .milliseconds(20)) == .timedOut,
                   "cancelled flow delivered a result after its fence")
        cancelResolver.cancel()

        // A result already admitted by Flow may still be inside its external
        // callback. Cancellation cannot ACK ahead of it or erase a valid
        // negative/authentication barrier while a parent cuts its phase short.
        for kind in 0..<3 {
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let acknowledged = DispatchSemaphore(value: 0)
            let peer = ReuseMemoryStream { stream, wire, _, done in
                done(nil)
                if kind == 2 {
                    let original = Data(wire.dropFirst(2))
                    let answer = DNSMessageInspection.errorResponse(to: original, code: .servfail)!
                    stream.emit(Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer)
                } else { stream.emit(reuseWireReply(wire, mode: 2)) }
            }
            let resolver = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in
                if kind == 1 { done(.failure(NWError.tls(-9807))) }
                else { done(.success(peer)) }
            })
            let block: () -> Void = { entered.signal(); _ = release.wait(timeout: .now() + 2) }
            let held = DoTRoutedDatagram(resolver: resolver, receive: { _ in block() }, failure: { _ in block() })
            held.send(query)
            try expect(entered.wait(timeout: .now() + 2) == .success, "admitted result fence fixture did not start")
            held.cancel { acknowledged.signal() }
            let barrier = held.proxyFallbackBarrier()
            if kind == 1 {
                guard case .failure(let error)? = barrier else { throw Failure(text: "authentication barrier not retained") }
                try expect((error as? EncryptedDNSQueryFailure) == .authentication,
                           "admitted authentication callback lost its synchronous barrier")
            } else {
                guard case .answer(let answer)? = barrier else { throw Failure(text: "authenticated answer barrier not retained") }
                try expect(DNSMessageInspection.responseMatchesQuery(answer, query: query),
                           "admitted answer/negative lost its transaction barrier")
            }
            try expect(acknowledged.wait(timeout: .now() + .milliseconds(20)) == .timedOut,
                       "cancel ACK ran ahead of an already admitted callback")
            release.signal()
            try expect(acknowledged.wait(timeout: .now() + 2) == .success, "admitted callback never released its cancel fence")
            resolver.cancel()
        }

        // Deterministic FIFO: native callback queues A and holds the pool
        // queue; cancellation revokes registration and queues C; A must save
        // its deny metadata before scheduling Request B behind C. Checking
        // permitted() at A would lose the error and incorrectly allow fallback.
        final class HeldCallbackStream: NativeOutboundByteStream {
            let holdSend: Bool, error: Error
            let arrived: DispatchSemaphore, release: DispatchSemaphore
            init(holdSend: Bool, error: Error, arrived: DispatchSemaphore, release: DispatchSemaphore) {
                self.holdSend = holdSend; self.error = error; self.arrived = arrived; self.release = release
            }
            func send(_ data: Data, completion: @escaping (Error?) -> Void) {
                completion(holdSend ? error : nil)
                if holdSend { hold() }
            }
            func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
                completion(nil, true, error); hold()
            }
            private func hold() { arrived.signal(); _ = release.wait(timeout: .now() + 2) }
            func cancel() {}
        }
        for mode in 0..<3 {
            for reason in [EncryptedDNSQueryFailure.authentication, .other] {
                let arrived = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
                let acknowledged = DispatchSemaphore(value: 0)
                let peer = HeldCallbackStream(holdSend: mode == 0, error: reason, arrived: arrived, release: release)
                let resolver = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in
                    if mode == 2 {
                        done(.failure(reason)); arrived.signal(); _ = release.wait(timeout: .now() + 2)
                    } else { done(.success(peer)) }
                })
                let raced = DoTRoutedDatagram(resolver: resolver, receive: { _ in }, failure: { _ in })
                raced.send(query)
                try expect(arrived.wait(timeout: .now() + 2) == .success, "queued deny fixture did not admit its native event")
                raced.cancel { acknowledged.signal() }
                try expect(acknowledged.wait(timeout: .now() + .milliseconds(10)) == .timedOut,
                           "queued native event was not behind the cancellation fence")
                release.signal()
                try expect(acknowledged.wait(timeout: .now() + 2) == .success, "queued deny fixture never acknowledged cancellation")
                guard case .failure(let preserved)? = raced.proxyFallbackBarrier(),
                      (preserved as? EncryptedDNSQueryFailure) == reason else {
                    throw Failure(text: "A/C/B cancellation race erased native send/read/dial deny metadata")
                }
                resolver.cancel()
            }
        }

        final class HeldReplyStream: NativeOutboundByteStream {
            let wire: Data, arrived: DispatchSemaphore, release: DispatchSemaphore
            init(wire: Data, arrived: DispatchSemaphore, release: DispatchSemaphore) {
                self.wire = wire; self.arrived = arrived; self.release = release
            }
            func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
            func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
                completion(wire, true, nil)
                arrived.signal(); _ = release.wait(timeout: .now() + 2)
            }
            func cancel() {}
        }
        for https in [false, true] {
            for variant in 0..<5 {
                let arrived = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
                let acknowledged = DispatchSemaphore(value: 0)
                var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail)!
                answer[3] = (answer[3] & 0xf0) | [UInt8(0), 3, 5, 2, 0][variant]
                if variant == 4 { answer[0] ^= 1 }
                let wire = https
                    ? Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: \(answer.count)\r\n\r\n".utf8) + answer
                    : Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer
                let peer = HeldReplyStream(wire: wire, arrived: arrived, release: release)
                let dialer: EncryptedDNSStreamDialer = { _, _, _, _, done in done(.success(peer)) }
                let flow: NativeRoutedDatagram & DNSQueryCancellationAcknowledging & DNSProxyFallbackBarrierProviding
                let cleanup: () -> Void
                if https {
                    let resolver = DoHResolver(endpoint: DoHEndpoint("https://203.0.113.53/dns-query")!, streamDialer: dialer)
                    flow = DoHRoutedDatagram(resolver: resolver, receive: { _ in }, failure: { _ in })
                    cleanup = { resolver.cancel() }
                } else {
                    let resolver = DoTResolver(endpoint: endpoint, streamDialer: dialer)
                    flow = DoTRoutedDatagram(resolver: resolver, receive: { _ in }, failure: { _ in })
                    cleanup = { resolver.cancel() }
                }
                flow.send(query)
                try expect(arrived.wait(timeout: .now() + 2) == .success, "queued reply fixture did not admit its native event")
                flow.cancel { acknowledged.signal() }
                release.signal()
                try expect(acknowledged.wait(timeout: .now() + 2) == .success, "queued reply fixture did not acknowledge cancellation")
                if variant == 4 {
                    guard case .failure(let blocked)? = flow.proxyFallbackBarrier(),
                          (blocked as? EncryptedDNSQueryFailure) == .invalidResponse else {
                        throw Failure(text: "queued malformed DNS reply lost its downgrade barrier")
                    }
                } else {
                    guard case .answer(let preserved)? = flow.proxyFallbackBarrier(), preserved == answer else {
                        throw Failure(text: "queued NODATA/NXDOMAIN/REFUSED/SERVFAIL was erased by cancellation")
                    }
                }
                cleanup()
            }
        }

        // A successful send ACK is not a policy failure merely because its
        // pool registration was revoked at the phase cutoff.
        let ackArrived = DispatchSemaphore(value: 0), ackRelease = DispatchSemaphore(value: 0)
        let ackFence = DispatchSemaphore(value: 0)
        let ackPeer = ReuseMemoryStream { _, _, _, done in
            done(nil); ackArrived.signal(); _ = ackRelease.wait(timeout: .now() + 2)
        }
        let ackResolver = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in done(.success(ackPeer)) })
        let ackFlow = DoTRoutedDatagram(resolver: ackResolver, receive: { _ in }, failure: { _ in })
        ackFlow.send(query)
        try expect(ackArrived.wait(timeout: .now() + 2) == .success, "queued send ACK fixture did not start")
        ackFlow.cancel { ackFence.signal() }; ackRelease.signal()
        try expect(ackFence.wait(timeout: .now() + 2) == .success && ackFlow.proxyFallbackBarrier() == nil,
                   "self-induced registration revocation became a false policy barrier")
        ackResolver.cancel()

        // An unclassified stale-idle error can retry the *same encrypted*
        // provider, but a timeout on that retry cannot erase the deny barrier.
        let stale = ReuseProbe { index in
            ReuseMemoryStream { stream, wire, number, done in
                if index == 0 && number == 1 { done(nil); stream.emit(reuseWireReply(wire, mode: 2)) }
                else if index == 0 { done(Failure(text: "unclassified stale idle failure")) }
                else { done(nil) }
            }
        }
        let retry = DoTResolver(endpoint: endpoint, streamDialer: stale.dialer, requestTimeout: .milliseconds(50))
        _ = try awaitResult { retry.resolveResult(query: query, completion: $0) }
        let result = try awaitResult { retry.resolveResult(query: query, completion: $0) }
        try expect(isFailure(result, .other) && stale.count == 2,
                   "stale retry timeout erased an unknown downgrade barrier")
        retry.cancel()
        let observerStarted = DispatchSemaphore(value: 0)
        let observation = ReuseProbe { index in
            ReuseMemoryStream { stream, wire, number, done in
                if index == 0 && number == 1 { done(nil); stream.emit(reuseWireReply(wire, mode: 2)) }
                else if index == 0 { done(Failure(text: "observed stale idle failure")) }
                else { done(nil); observerStarted.signal() }
            }
        }
        let observedResolver = DoTResolver(endpoint: endpoint, streamDialer: observation.dialer, requestTimeout: .seconds(1))
        _ = try awaitResult { observedResolver.resolveResult(query: query, completion: $0) }
        let observedFlow = DoTRoutedDatagram(resolver: observedResolver, receive: { _ in }, failure: { _ in })
        observedFlow.send(query)
        try expect(observerStarted.wait(timeout: .now() + 2) == .success, "stale barrier observer fixture did not retry")
        guard case .failure(let early)? = observedFlow.proxyFallbackBarrier(),
              (early as? EncryptedDNSQueryFailure) == .other else {
            throw Failure(text: "parent phase cutoff could erase an encrypted-only retry barrier")
        }
        let observedFence = DispatchSemaphore(value: 0)
        observedFlow.cancel { observedFence.signal() }
        try expect(observedFence.wait(timeout: .now() + 2) == .success, "observed stale retry cancellation did not ACK")
        observedResolver.cancel()
        print("Encrypted DNS typed failure check passed: network/deadline, authentication, cancellation fence, capacity, policy and invalid response")
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
        guard let literal = DoHEndpoint("https://[::1]:8443/dns-query"),
              let literalWire = DoHHTTPWire.request(endpoint: literal, query: query) else {
            throw Failure(text: "IPv6 字面地址 DoH 请求生成失败")
        }
        try expect(String(decoding: literalWire, as: UTF8.self).contains("Host: [::1]:8443\r\n"),
                   "DoH IPv6 Host 头必须只有一层方括号")
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
                       "Transfer-Encoding: gzip", "Content-Type: text/html",
                       "Content-Length: 12\r\nContent-Length: 12",
                       "Content-Length: 12\r\nTransfer-Encoding: chunked"] {
            var rejected = DoHHTTPResponseParser()
            let result = rejected.ingest(Data("HTTP/1.1 200 OK\r\n\(header)\r\n\r\n".utf8),
                                         endOfStream: false)
            guard case .invalid = result else {
                throw Failure(text: "DoH 非法响应头未被拒绝：\(header)")
            }
        }
        var redirected = DoHHTTPResponseParser()
        let redirect = redirected.ingest(
            Data("HTTP/1.1 302 Found\r\nLocation: https://unresolved.invalid/dns-query\r\n\r\n".utf8),
            endOfStream: true)
        guard case .invalid = redirect else { throw Failure(text: "DoH 不应跟随具名重定向") }
    }

    final class MemoryStream: NativeOutboundByteStream {
        private let lock = NSLock()
        private var response: Data?
        private var offset = 0
        private var written = Data()
        private var stopped = false
        init(response: Data?) { self.response = response }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock(); written.append(data); lock.unlock()
            completion(nil)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard let response else { lock.unlock(); return }
            let count = min(maximum, min(3, response.count - offset))
            let next = Data(response[(response.startIndex + offset)..<(response.startIndex + offset + count)])
            offset += count
            let complete = offset == response.count
            lock.unlock()
            completion(next, complete, nil)
        }
        func cancel() { lock.lock(); stopped = true; lock.unlock() }
        var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
        var sent: Data { lock.lock(); defer { lock.unlock() }; return written }
    }

    final class ReuseMemoryStream: NativeOutboundFailureObservingByteStream {
        typealias Handler = (ReuseMemoryStream, Data, Int, @escaping (Error?) -> Void) -> Void
        let closedSignal = DispatchSemaphore(value: 0)
        let receiving = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var handler: Handler?
        private var events: [(Data?, Bool, Error?)] = []
        private var pending: (Int, (Data?, Bool, Error?) -> Void)?
        private var failureObserver: ((Error) -> Void)?
        private var stopped = false, writes = 0
        init(_ handler: @escaping Handler) { self.handler = handler }
        func setStreamFailureObserver(_ observer: ((Error) -> Void)?) {
            lock.lock(); failureObserver = observer; lock.unlock()
        }
        func emitTransportFailure(_ error: Error) {
            lock.lock(); let observer = failureObserver; lock.unlock(); observer?(error)
        }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            lock.lock()
            guard !stopped, let handler else { lock.unlock(); completion(Failure(text: "closed memory peer")); return }
            writes += 1; let number = writes; lock.unlock()
            handler(self, data, number, completion)
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            guard !stopped else { lock.unlock(); completion(nil, true, Failure(text: "closed memory peer")); return }
            guard pending == nil else { lock.unlock(); completion(nil, true, Failure(text: "concurrent receive")); return }
            pending = (maximum, completion)
            receiving.signal()
            drainLocked()
        }
        func emit(_ data: Data?, complete: Bool = false, error: Error? = nil) {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            events.append((data, complete, error)); drainLocked()
        }
        // Called with lock held; always unlocks before invoking a callback.
        private func drainLocked() {
            guard let pending, !events.isEmpty else { lock.unlock(); return }
            self.pending = nil
            var event = events.removeFirst()
            if let data = event.0, data.count > pending.0 {
                events.insert((Data(data.dropFirst(pending.0)), event.1, event.2), at: 0)
                event = (Data(data.prefix(pending.0)), false, nil)
            }
            lock.unlock(); pending.1(event.0, event.1, event.2)
        }
        func cancel() {
            lock.lock()
            guard !stopped else { lock.unlock(); return }
            stopped = true; handler = nil; events.removeAll()
            let reader = pending; pending = nil; lock.unlock()
            reader?.1(nil, true, Failure(text: "cancelled memory peer"))
            closedSignal.signal()
        }
        var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
        var sendCount: Int { lock.lock(); defer { lock.unlock() }; return writes }
    }

    final class ReuseProbe {
        private let lock = NSLock()
        private let factory: (Int) -> ReuseMemoryStream
        private var all: [ReuseMemoryStream] = []
        init(_ factory: @escaping (Int) -> ReuseMemoryStream) { self.factory = factory }
        var dialer: EncryptedDNSStreamDialer {
            { [self] _, _, _, _, done in
                lock.lock(); let stream = factory(all.count); all.append(stream); lock.unlock()
                done(.success(stream))
            }
        }
        var streams: [ReuseMemoryStream] { lock.lock(); defer { lock.unlock() }; return all }
        var count: Int { streams.count }
    }

    final class ReuseClock {
        private let lock = NSLock()
        private var value = Date(timeIntervalSince1970: 100)
        func read() -> Date { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ seconds: TimeInterval) { lock.lock(); value.addTimeInterval(seconds); lock.unlock() }
    }

    static func reuseAwait(_ issue: (@escaping (Data?) -> Void) -> UUID?) throws -> Data? {
        let done = DispatchSemaphore(value: 0), lock = NSLock()
        var result: Data?
        _ = issue { lock.lock(); result = $0; lock.unlock(); done.signal() }
        guard done.wait(timeout: .now() + 3) == .success else { throw Failure(text: "reuse request did not complete") }
        lock.lock(); defer { lock.unlock() }; return result
    }

    // mode 0: Content-Length, 1: chunked, 2: DoT, 3: close-delimited.
    static func reuseWireReply(_ request: Data, mode: Int, header: String = "",
                                       version: String = "HTTP/1.1", extra: Data = Data()) -> Data {
        let query: Data
        if mode == 2 { query = Data(request.dropFirst(2)) }
        else if let boundary = request.range(of: Data("\r\n\r\n".utf8)) {
            query = Data(request[boundary.upperBound...])
        } else { return Data() }
        guard let question = FakeIPResponder.question(in: query),
              let answer = FakeIPResponder.reply(to: query, question: question, address: "93.184.216.34") else { return Data() }
        var result: Data
        switch mode {
        case 2:
            result = Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)])
            result.append(answer)
        case 1:
            result = Data("\(version) 200 OK\r\n\(header)Transfer-Encoding: chunked\r\n\r\n\(String(answer.count, radix: 16))\r\n".utf8)
            result.append(answer); result.append(Data("\r\n0\r\n\r\n".utf8))
        case 3:
            result = Data("\(version) 200 OK\r\n\(header)\r\n".utf8); result.append(answer)
        default:
            result = Data("\(version) 200 OK\r\n\(header)Content-Length: \(answer.count)\r\n\r\n".utf8); result.append(answer)
        }
        result.append(extra); return result
    }

    static func reuseAuto(_ mode: Int, header: String = "", version: String = "HTTP/1.1",
                                  extra: Data = Data(), eof: Bool = false) -> ReuseMemoryStream {
        ReuseMemoryStream { stream, data, _, done in
            done(nil)
            stream.emit(reuseWireReply(data, mode: mode, header: header, version: version, extra: extra),
                        complete: eof)
        }
    }

    static func proxyTCPConnectionPool() throws {
        let server = DNSProxyFallbackServer("203.0.113.53")!
        let first = FakeIPSelfTest.query("first.proxy-pool.example", type: 1, id: 0x7301)
        let second = FakeIPSelfTest.query("second.proxy-pool.example", type: 1, id: 0x7302)
        func result(_ issue: (@escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID?) throws
            -> Result<Data, EncryptedDNSQueryFailure> {
            let signal = DispatchSemaphore(value: 0), lock = NSLock()
            var value: Result<Data, EncryptedDNSQueryFailure>?
            _ = issue { lock.lock(); value = $0; lock.unlock(); signal.signal() }
            try expect(signal.wait(timeout: .now() + 2) == .success, "proxy TCP pool callback missing")
            lock.lock(); defer { lock.unlock() }; return value!
        }
        func failure(_ value: Result<Data, EncryptedDNSQueryFailure>, _ reason: EncryptedDNSQueryFailure) -> Bool {
            if case .failure(let found) = value { return found == reason }; return false
        }
        func make(_ probe: ReuseProbe, diagnostics: NetworkPerformanceDiagnostics = NetworkPerformanceDiagnostics(),
                  resources: SOCKSUDPGlobalBudget = SOCKSUDPGlobalBudget(resources: 8, packets: 0, bytes: 0),
                  activeLimit: Int = 16, hook: (() -> Void)? = nil) -> ProxyTCPDNSResolver {
            ProxyTCPDNSResolver(server: server, metadataStreamDialer: { host, port, name, queue, _, _, done in
                probe.dialer(host, port, name, queue, done); return nil
            }, activeLimit: activeLimit, resourceBudget: resources, diagnostics: diagnostics,
               afterReplyIngressForSelfTest: hook)
        }
        func resolve(_ resolver: ProxyTCPDNSResolver, _ query: Data, after seconds: TimeInterval = 1,
                     permitted: @escaping () -> Bool = { true },
                     barrier: ((DNSProxyFallbackBarrier) -> Void)? = nil) throws -> Result<Data, EncryptedDNSQueryFailure> {
            try result { resolver.resolveResult(query: query, absoluteDeadline: ProcessInfo.processInfo.systemUptime + seconds,
                permitted: permitted, completion: $0, downgradeBarrier: barrier) }
        }

        let metrics = NetworkPerformanceDiagnostics(), budget = SOCKSUDPGlobalBudget(resources: 1, packets: 0, bytes: 0)
        let probe = ReuseProbe { _ in reuseAuto(2) }, pooled = make(probe, diagnostics: metrics, resources: budget)
        for index in 0..<8 {
            let query = FakeIPSelfTest.query("serial-\(index).proxy-pool.example", type: 1, id: UInt16(0x7310 + index))
            let answer = try resolve(pooled, query).get()
            try expect(DNSMessageInspection.responseMatchesQuery(answer, query: query), "proxy pool changed query identity")
        }
        let summary = metrics.snapshot()
        try expect(probe.count == 1 && probe.streams[0].sendCount == 8 && budget.usage.resources == 1
                   && summary.dnsProxyFallbackConnectionsReused == 7 && summary.dnsConnectionsReused == 0
                   && summary.stages[.dnsProxyFallbackConnection]?.count == 1
                   && summary.stages[.dnsProxyFallbackExchange]?.count == 8
                   && summary.stages[.dnsTLSHandshake] == nil,
                   "proxy TCP queries repeated dial/TLS, escaped resource limits, or mixed reuse/phase counters")
        try expect(summary.dnsConnectionAttempts.count == 1
                   && summary.dnsConnectionAttempts[0].transport == .proxyTCP
                   && summary.dnsConnectionAttempts[0].transportOutcome == .success
                   && summary.dnsConnectionAttempts[0].tlsOutcome == nil
                   && summary.dnsConnectionAttempts[0].observations.contains(where: { $0.event == .transportReady }),
                   "successful proxy TCP dial has no physical result or invented an inner TLS handshake")
        do {
            let failures = NetworkPerformanceDiagnostics()
            let denied = ProxyTCPDNSResolver(server: server, metadataStreamDialer: { _, _, _, _, _, observe, ready in
                let error = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET))
                observe(error); ready(.failure(error)); return nil
            }, diagnostics: failures)
            defer { denied.cancel() }
            try expect(failure(try resolve(denied, first), .network), "typed proxy dial failure changed query classification")
            let attempt = failures.snapshot().dnsConnectionAttempts.first
            try expect(attempt?.transportOutcome == .failure && attempt?.tlsOutcome == nil
                       && attempt?.firstError?.codes == [DNSAttemptErrorCode(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET))],
                       "proxy TCP physical failure lost its original error code or remained pending")
        }
        try expect(failure(try resolve(pooled, second, permitted: { false }), .policy)
                   && probe.count == 1 && probe.streams[0].sendCount == 8,
                   "a reusable connection lent a revoked question permission to send")
        probe.streams[0].emit(Data([0x7f]))
        _ = try resolve(pooled, second).get()
        try expect(probe.count == 2 && probe.streams[0].cancelled, "unsolicited idle data survived pool checkout")
        pooled.cancel(); pooled.drainQueueForSelfTest()
        try expect(budget.usage.resources == 0, "proxy pool cancellation leaked an idle resource reservation")

        // An old idle stream may retry once only for a typed network outage.
        // Unknown/authentication send and read failures must not send a second
        // ordinary DNS query, even to the same approved resolver.
        for onRead in [false, true] {
            for reason in [EncryptedDNSQueryFailure.other, .authentication] {
                let error: Error = reason == .other ? Failure(text: "unknown proxy idle failure") : reason
                let denied = ReuseProbe { _ in ReuseMemoryStream { stream, wire, number, done in
                    if number == 1 { done(nil); stream.emit(reuseWireReply(wire, mode: 2)) }
                    else if onRead { done(nil); stream.emit(nil, error: error) }
                    else { done(error) }
                } }
                let resolver = make(denied); defer { resolver.cancel() }
                _ = try resolve(resolver, first).get()
                var barrier: DNSProxyFallbackBarrier?
                let rejected = try resolve(resolver, second, barrier: { barrier = $0 })
                guard case .failure(let observed)? = barrier else { throw Failure(text: "idle deny barrier disappeared") }
                try expect(failure(rejected, reason) && EncryptedDNSQueryFailure.classify(observed) == reason
                           && denied.count == 1 && denied.streams[0].sendCount == 2,
                           "unknown/authenticated idle failure redialed ordinary DNS or lost its barrier")
            }
        }
        let stale = ReuseProbe { index in ReuseMemoryStream { stream, wire, number, done in
            if index == 0, number > 1 { done(NWError.posix(.ECONNRESET)) }
            else { done(nil); stream.emit(reuseWireReply(wire, mode: 2)) }
        } }
        let recovered = make(stale); defer { recovered.cancel() }
        _ = try resolve(recovered, first).get(); _ = try resolve(recovered, second).get()
        try expect(stale.count == 2 && stale.streams[0].cancelled,
                   "zero-response typed network failure did not use its single original-deadline idle retry")

        let reference = reuseWireReply(Data([UInt8(first.count >> 8), UInt8(first.count & 255)]) + first, mode: 2)
        var wrongID = reference; wrongID[2] ^= 1
        for invalid in [Data(reference.prefix(1)), Data(reference.dropLast()), wrongID, reference + Data([0])] {
            let malformed = ReuseProbe { _ in ReuseMemoryStream { stream, _, _, done in done(nil); stream.emit(invalid, complete: true) } }
            let resolver = make(malformed); defer { resolver.cancel() }
            try expect(failure(try resolve(resolver, first), .invalidResponse)
                       && malformed.count == 1 && malformed.streams[0].cancelled,
                       "partial/mismatched/extra proxy TCP bytes were retried or reused")
        }

        // A waiting request's short deadline begins at registration. It must
        // expire without dialing while the only live exchange remains owned.
        let sent = DispatchSemaphore(value: 0)
        let held = ReuseProbe { _ in ReuseMemoryStream { _, _, _, done in done(nil); sent.signal() } }
        let serial = make(held, activeLimit: 1); defer { serial.cancel() }
        let firstDone = DispatchSemaphore(value: 0)
        let active = serial.resolveResult(query: first, absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2,
            permitted: { true }, completion: { _ in firstDone.signal() })!
        try expect(sent.wait(timeout: .now() + 1) == .success, "proxy TCP queue fixture did not send its first query")
        try expect(failure(try resolve(serial, second, after: 0.04), .timeout)
                   && held.count == 1 && held.streams[0].sendCount == 1,
                   "queued fallback received a fresh deadline or pre-dialed another transport")
        let cancelled = DispatchSemaphore(value: 0)
        serial.cancel(active) { cancelled.signal() }
        try expect(cancelled.wait(timeout: .now() + 1) == .success && firstDone.wait(timeout: .now() + 1) == .success,
                   "queued fallback cancellation ACK did not retire only its live request")

        try proxyTCPPendingDialFence(server: server, query: first)
        try proxyTCPIngressFence(server: server, query: first)
        print("Proxy TCP DNS pool checks passed: bounded reuse, independent transport/exchange timing, per-question authority, original deadlines, typed idle retries, native metadata and cancellation fences")
    }

    private static func proxyTCPPendingDialFence(server: DNSProxyFallbackServer, query: Data) throws {
        let lock = NSLock(), entered = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        let metrics = NetworkPerformanceDiagnostics()
        var callback: ((Result<any NativeOutboundByteStream, Error>) -> Void)?
        var observer: ((Error) -> Void)?, cancelCalls = 0
        var barrier: DNSProxyFallbackBarrier?
        let resolver = ProxyTCPDNSResolver(server: server, metadataStreamDialer: { _, _, _, _, _, observe, complete in
            lock.lock(); callback = complete; observer = observe; lock.unlock(); entered.signal()
            return { lock.lock(); cancelCalls += 1; lock.unlock() }
        }, diagnostics: metrics)
        defer { resolver.cancel() }
        let id = resolver.resolveResult(query: query, absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2,
            permitted: { true }, completion: { _ in done.signal() }, downgradeBarrier: { barrier = $0 })!
        try expect(entered.wait(timeout: .now() + 1) == .success, "proxy TCP pending dial did not start")
        lock.lock(); let admit = observer; lock.unlock(); admit?(EncryptedDNSQueryFailure.authentication)
        let acknowledged = DispatchSemaphore(value: 0)
        resolver.cancel(id) { acknowledged.signal() }
        try expect(acknowledged.wait(timeout: .now() + 1) == .success && done.wait(timeout: .now() + 1) == .success,
                   "proxy TCP logical cancellation did not ACK")
        guard case .failure(let denied)? = barrier else { throw Failure(text: "native pending authentication metadata was erased") }
        lock.lock(); let cancels = cancelCalls, complete = callback; callback = nil; lock.unlock()
        try expect(cancels == 1 && EncryptedDNSQueryFailure.classify(denied) == .authentication
                   && resolver.pressureForSelfTest.physical == 1
                   && metrics.snapshot().stages[.dnsProxyFallbackConnection] == nil,
                   "logical cancellation refunded a physical dial or invented a native timing receipt")
        let late = reuseAuto(2); complete?(.success(late)); resolver.drainQueueForSelfTest()
        try expect(late.cancelled && late.sendCount == 0 && resolver.pressureForSelfTest.physical == 0
                   && metrics.snapshot().stages[.dnsProxyFallbackConnection]?.failureCount == 1
                   && metrics.snapshot().stages[.dnsProxyFallbackConnection]?.cancellationCount == 0,
                   "late native success was sent/reused, leaked its receipt or erased an earlier real failure")
        let attempt = metrics.snapshot().dnsConnectionAttempts.first
        try expect(attempt?.transportOutcome == .failure && attempt?.firstError != nil
                   && attempt?.cancellationReason == .callerCancelled,
                   "native proxy failure and later logical cancellation were not retained together")
    }

    private static func proxyTCPIngressFence(server: DNSProxyFallbackServer, query: Data) throws {
        for mode in 0..<8 {
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let returned = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
            let sent = DispatchSemaphore(value: 0), lock = NSLock()
            var delivered = 0
            let peer = ReuseMemoryStream { _, _, _, done in done(nil); sent.signal() }
            let resolver = ProxyTCPDNSResolver(server: server, metadataStreamDialer: { _, _, _, _, _, _, done in
                done(.success(peer)); return nil
            }, afterReplyIngressForSelfTest: { entered.signal(); _ = release.wait(timeout: .now() + 2) })
            let flow = ProxyTCPDNSRoutedDatagram(resolver: resolver,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2, permitted: { true },
                receive: { _ in lock.lock(); delivered += 1; lock.unlock() },
                failure: { _ in lock.lock(); delivered += 1; lock.unlock() })
            defer { release.signal(); flow.cancel(); resolver.cancel() }
            flow.send(query)
            try expect(sent.wait(timeout: .now() + 1) == .success, "pooled native ingress fixture never sent")
            try expect(peer.receiving.wait(timeout: .now() + 1) == .success, "pooled native ingress callback was not registered")
            var answer = DNSMessageInspection.errorResponse(to: query, code: .servfail)!
            answer[3] = (answer[3] & 0xf0) | (mode == 0 ? 0 : mode == 1 ? 3 : 5)
            if mode == 4 { answer[0] ^= 1 }
            var frame = Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)]) + answer
            if mode == 5 { frame.append(0) }
            if mode == 6 { frame = Data(frame.prefix(1)) }
            if mode == 7 { frame = Data(frame.dropLast()) }
            let packet = frame
            DispatchQueue.global(qos: .userInitiated).async {
                peer.emit(mode == 3 ? nil : packet, complete: true,
                          error: mode == 3 ? EncryptedDNSQueryFailure.authentication : nil)
                returned.signal()
            }
            try expect(entered.wait(timeout: .now() + 1) == .success, "pooled native ingress fence did not open")
            flow.cancel { cancelled.signal() }
            try expect(cancelled.wait(timeout: .now() + 1) == .success, "pooled native ingress cancellation did not ACK")
            guard let barrier = flow.proxyFallbackBarrier() else { throw Failure(text: "pool cancel erased admitted native DNS metadata") }
            switch barrier {
            case .answer(let received):
                try expect(mode < 3 && received == answer, "pooled native negative/positive barrier changed identity")
            case .failure(let error):
                try expect(mode >= 3 && EncryptedDNSQueryFailure.classify(error) == (mode == 3 ? .authentication : .invalidResponse),
                           "pooled native authentication/partial/malformed barrier changed type")
            }
            release.signal()
            try expect(returned.wait(timeout: .now() + 1) == .success, "pooled native ingress callback never returned")
            resolver.drainQueueForSelfTest()
            lock.lock(); let count = delivered; lock.unlock()
            try expect(count == 0, "pooled canceled native reply reached its old logical client")
        }
    }

    private static func connectionReuse() throws {
        let dohEndpoint = DoHEndpoint("https://reuse.selftest.invalid/dns-query#203.0.113.53")!
        let dotEndpoint = DoTEndpoint("tls://reuse.selftest.invalid#203.0.113.53")!
        let first = FakeIPSelfTest.query("first.reuse.example", type: 1, id: 0x1001)
        let second = FakeIPSelfTest.query("second.reuse.example", type: 1, id: 0x2002)
        for mode in [0, 1, 2] {
            let probe = ReuseProbe { _ in reuseAuto(mode) }
            let cancel: () -> Void
            let resolve: (Data, @escaping (Data?) -> Void) -> UUID?
            if mode == 2 {
                let resolver = DoTResolver(endpoint: dotEndpoint, streamDialer: probe.dialer)
                resolve = { resolver.resolve(query: $0, completion: $1) }; cancel = { resolver.cancel() }
            } else {
                let resolver = DoHResolver(endpoint: dohEndpoint, streamDialer: probe.dialer)
                resolve = { resolver.resolve(query: $0, completion: $1) }; cancel = { resolver.cancel() }
            }
            defer { cancel() }
            for query in [first, second, first] {
                let result = try reuseAwait { resolve(query, $0) }
                try expect(result.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true,
                           "reused stream changed DNS ID/question")
            }
            try expect(probe.count == 1 && probe.streams[0].sendCount == 3,
                       "sequential CL/chunked/DoT queries did not reuse exactly one stream")
        }
        for (mode, header, version, eof, extra, valid) in [
            (0, "Connection: close\r\nConnection: keep-alive\r\n", "HTTP/1.1", false, Data(), true),
            (0, "Connection: keep-alive, CLOSE\r\n", "HTTP/1.1", false, Data(), true),
            (0, "", "HTTP/1.0", false, Data(), true),
            (0, "", "HTTP/1.1", true, Data(), true),
            (3, "", "HTTP/1.1", true, Data(), true),
            (0, "", "HTTP/1.1", false, Data([0]), false),
            (2, "", "HTTP/1.1", false, Data([0]), false)
        ] {
            let probe = ReuseProbe { _ in reuseAuto(mode, header: header, version: version, extra: extra, eof: eof) }
            if mode == 2 {
                let resolver = DoTResolver(endpoint: dotEndpoint, streamDialer: probe.dialer)
                defer { resolver.cancel() }
                for query in [first, second] {
                    let result = try reuseAwait { resolver.resolve(query: query, completion: $0) }
                    try expect((result != nil) == valid, "DoT extra bytes were accepted")
                }
            } else {
                let resolver = DoHResolver(endpoint: dohEndpoint, streamDialer: probe.dialer)
                defer { resolver.cancel() }
                for query in [first, second] {
                    let result = try reuseAwait { resolver.resolve(query: query, completion: $0) }
                    try expect((result != nil) == valid, "HTTP framing/close response result changed")
                }
            }
            try expect(probe.count == 2 && probe.streams.allSatisfy(\.cancelled),
                       "close/EOF/HTTP1.0/unframed/extra response was pooled")
        }
        for fragment in ["-1\r\n", "+1\r\n", "g\r\n"] {
            var parser = DoHHTTPResponseParser()
            let result = parser.ingest(Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\(fragment)".utf8),
                                       endOfStream: false)
            guard case .invalid = result else { throw Failure(text: "signed/non-hex HTTP chunk was accepted") }
        }
        for trailer in ["X-Trace: test", "Connection: keep-alive"] {
            let probe = ReuseProbe { _ in
                ReuseMemoryStream { stream, wire, _, done in
                    done(nil)
                    var reply = reuseWireReply(wire, mode: 1)
                    reply.removeLast(2); reply.append(Data("\(trailer)\r\n\r\n".utf8))
                    stream.emit(reply)
                }
            }
            let resolver = DoHResolver(endpoint: dohEndpoint, streamDialer: probe.dialer)
            defer { resolver.cancel() }
            for query in [first, second] {
                let answer = try reuseAwait { resolver.resolve(query: query, completion: $0) }
                try expect((answer != nil) == trailer.hasPrefix("X-Trace"),
                           "chunk trailers changed framing/connection semantics")
            }
            try expect(probe.count == 2 && probe.streams.allSatisfy(\.cancelled),
                       "nonempty/forbidden trailer stream was reused")
        }
        for unsolicited in [false, true] {
            let probe = ReuseProbe { _ in reuseAuto(2) }
            let resolver = DoTResolver(endpoint: dotEndpoint, streamDialer: probe.dialer)
            defer { resolver.cancel() }
            _ = try reuseAwait { resolver.resolve(query: first, completion: $0) }
            if unsolicited { probe.streams[0].emit(Data([0])) }
            else { probe.streams[0].emit(nil, complete: true) }
            let answer = try reuseAwait { resolver.resolve(query: second, completion: $0) }
            try expect(answer.map { DNSMessageInspection.responseMatchesQuery($0, query: second) } == true
                       && probe.count == 2 && probe.streams[0].cancelled,
                       "idle bytes/FIN leaked into the next query instead of invalidating the stream")
        }
        // Per-request cancellation after completion must not reach a stream
        // that now belongs to a different query.
        let borrowed = DispatchSemaphore(value: 0)
        let peer = ReuseMemoryStream { stream, data, number, done in
            done(nil)
            if number == 1 { stream.emit(reuseWireReply(data, mode: 2)) }
            else { borrowed.signal() }
        }
        let resolver = DoTResolver(endpoint: dotEndpoint, streamDialer: { _, _, _, _, done in done(.success(peer)) })
        defer { resolver.cancel() }
        let oldDone = DispatchSemaphore(value: 0)
        let oldID = resolver.resolve(query: first) { _ in oldDone.signal() }!
        try expect(oldDone.wait(timeout: .now() + 2) == .success, "completed lease not returned")
        let newDone = DispatchSemaphore(value: 0), lock = NSLock()
        var remaining: Data?
        let newID = resolver.resolve(query: second) { lock.lock(); remaining = $0; lock.unlock(); newDone.signal() }!
        try expect(borrowed.wait(timeout: .now() + 2) == .success, "next query did not borrow returned stream")
        resolver.cancel(oldID)
        peer.emit(reuseWireReply(Data([UInt8(second.count >> 8), UInt8(second.count & 255)]) + second, mode: 2))
        try expect(newDone.wait(timeout: .now() + 2) == .success, "old UUID cancelled the new lease")
        lock.lock(); let kept = remaining; lock.unlock()
        try expect(kept.map { DNSMessageInspection.responseMatchesQuery($0, query: second) } == true && !peer.cancelled,
                   "cancel-after-return affected new stream owner")
        resolver.cancel(newID)
        try reuseResourceBounds()
        try reuseHandoffBounds()
        try reuseRetryAndCancellation()
    }

    /// A reused TLS owner can admit a raw error before its application receive
    /// wakes with nil-error EOF. That first native error must reach the current
    /// request before a queued cancel/deadline can seal its downgrade barrier.
    private static func reuseHandoffBounds() throws {
        for capacity in [16, 6, 0] {
            let queue = DispatchQueue(label: "app.hajimi.dns.handoff.selftest")
            let clock = ReuseClock()
            let budget = SOCKSUDPGlobalBudget(resources: capacity, packets: 0, bytes: 0)
            let store = EncryptedDNSConnectionStore(queue: queue, idleTimeout: 15, idleLimit: 4,
                idleHandoffGrace: 0.25, activeLimit: 16, clock: clock.read, resourceBudget: budget)
            defer { queue.sync { store.cancel() } }
            var peers: [ReuseMemoryStream] = []
            let exchanged = DispatchGroup()
            var invalid = false
            let retained = min(capacity, 16)
            try queue.sync {
                for _ in 0..<17 {
                    let peer = reuseAuto(2); peers.append(peer)
                    guard let entry = store.adopt(peer) else {
                        throw Failure(text: "handoff fixture could not adopt its memory peer")
                    }
                    store.returnIdle(entry)
                }
                try expect(budget.usage.resources == retained
                           && peers.filter(\.cancelled).count == 17 - retained,
                           "handoff exceeded active/global bounds or prematurely closed its healthy batch")

                var borrowed: [EncryptedDNSPooledConnection] = []
                for _ in 0..<retained {
                    guard let entry = store.checkout() else {
                        throw Failure(text: "completed batch could not hand a stream to its next owner")
                    }
                    borrowed.append(entry)
                }
                try expect(store.checkout() == nil && budget.usage.resources == 0,
                           "handoff checkout kept an idle reservation or duplicated stream ownership")
                for (index, entry) in borrowed.enumerated() {
                    let query = FakeIPSelfTest.query("handoff-\(index).reuse.example", type: 1,
                                                    id: UInt16(0x3400 + index))
                    let wire = Data([UInt8(query.count >> 8), UInt8(query.count & 255)]) + query
                    let expected = reuseWireReply(wire, mode: 2)
                    exchanged.enter()
                    entry.send(wire, failureObserver: { _ in }, completion: { error in
                        if error != nil { invalid = true }
                    })
                    // The old idle monitor remains the one read broker for
                    // the next exchange. Let its genuine memory callback run
                    // before returning the new lease, just as production does.
                    entry.receive { data, eof, error in
                        if data != expected || eof || error != nil { invalid = true }
                        store.returnIdle(entry)
                        exchanged.leave()
                    }
                }
            }
            try expect(exchanged.wait(timeout: .now() + 3) == .success,
                       "handoff memory exchanges failed to deliver their next owner's reply")
            try queue.sync {
                try expect(!invalid && budget.usage.resources == retained,
                           "a reused handoff stream was not charged to the shared resource budget")

                // The short window must not become sixteen long-lived idle
                // carriers after a burst. Advancing the injected wall clock
                // exercises expiry even when no real timer has fired yet.
                clock.advance(1)
                guard let expiryProbe = store.reserveDial() else {
                    throw Failure(text: "handoff fixture could not recheck expired idle entries")
                }
                _ = store.completeDial(expiryProbe)
                let steady = min(retained, 4)
                try expect(budget.usage.resources == steady
                           && peers.filter(\.cancelled).count == 17 - steady,
                           "excess handoff streams survived their grace window")
                let next = store.checkout()
                try expect((next != nil) == (steady > 0)
                           && budget.usage.resources == max(0, steady - 1)
                           && peers.filter(\.cancelled).count == 17 - steady,
                           "excess handoff streams survived their grace window or lost a steady stream")
                if let next { store.discard(next) }
                store.cancel()
                try expect(budget.usage.resources == 0 && peers.allSatisfy(\.cancelled),
                           "flush/cancellation leaked transient or steady handoff reservations")
            }
        }
    }

    private static func physicalPressureQueueRecovery() throws {
        for mode in [0, 2] {
            for expires in [false, true] {
                let lock = NSLock(), issued = DispatchSemaphore(value: 0)
                let budget = SOCKSUDPGlobalBudget(resources: 4, packets: 0, bytes: 0)
                var callbacks: [(Result<any NativeOutboundByteStream, Error>) -> Void] = []
                var healthy = false, invalid = false, dialCount = 0, cancelCount = 0
                var sentIDs: [UInt16] = [], resultCounts: [UInt16: Int] = [:]
                let peer = ReuseMemoryStream { stream, wire, _, done in
                    let query: Data
                    if mode == 2 { query = Data(wire.dropFirst(2)) }
                    else if let boundary = wire.range(of: Data("\r\n\r\n".utf8)) {
                        query = Data(wire[boundary.upperBound...])
                    } else { query = Data() }
                    lock.lock()
                    if query.count >= 2 {
                        sentIDs.append(UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1]))
                    } else { invalid = true }
                    lock.unlock()
                    done(nil); stream.emit(reuseWireReply(wire, mode: mode))
                }
                let dialer: CancellableEncryptedDNSStreamDialer = { _, _, _, _, done in
                    lock.lock()
                    dialCount += 1
                    let ready = healthy
                    if !ready { callbacks.append(done) }
                    lock.unlock(); issued.signal()
                    if ready { done(.success(peer)); return nil }
                    return { lock.lock(); cancelCount += 1; lock.unlock() }
                }
                let protocolValue: EncryptedDNSProtocol = mode == 2
                    ? .tls(DoTEndpoint("tls://pressure.selftest.invalid#203.0.113.53")!)
                    : .https(DoHEndpoint("https://pressure.selftest.invalid/dns-query#203.0.113.53")!)
                let pool = EncryptedDNSRequestPool(protocol: protocolValue,
                    label: "app.hajimi.dns.physical-pressure-self-test", streamDialer: nil,
                    cancellableStreamDialer: dialer, metadataStreamDialer: nil,
                    timeout: expires ? .seconds(1) : .seconds(8), idleTimeout: 15,
                    idleLimit: 4, idleHandoffGrace: 0.25, activeLimit: DoHResolver.maximumConcurrentQueries,
                    coldDialLimit: 128,
                    clock: { Date(timeIntervalSince1970: SOCKSUDPResourceLimits.now) }, resourceBudget: budget)
                defer { pool.cancel() }
                func question(_ id: UInt16) -> Data {
                    FakeIPSelfTest.query("pressure-\(id).reuse.example", type: 1, id: id)
                }
                func record(_ id: UInt16, result: Result<Data, EncryptedDNSQueryFailure>,
                            expected: EncryptedDNSQueryFailure?) {
                    lock.lock()
                    resultCounts[id, default: 0] += 1
                    switch result {
                    case .failure(let reason): invalid = invalid || reason != expected
                    case .success(let answer):
                        invalid = invalid || expected != nil
                            || !DNSMessageInspection.responseMatchesQuery(answer, query: question(id))
                    }
                    lock.unlock()
                }
                for wave in 0..<8 {
                    let completed = DispatchGroup()
                    var ids: [UUID] = []
                    for index in 0..<16 {
                        let wireID = UInt16(0x7200 + wave * 16 + index)
                        completed.enter()
                        guard let id = pool.resolveResult(query: question(wireID), completion: { result in
                            record(wireID, result: result, expected: .cancelled); completed.leave()
                        }) else { throw Failure(text: "production physical-pressure wave rejected registration") }
                        ids.append(id)
                    }
                    for _ in 0..<16 {
                        try expect(issued.wait(timeout: .now() + 2) == .success,
                                   "production physical-pressure wave did not start its 16 dials")
                    }
                    let active = pool.pressureForSelfTest
                    try expect(active.registered == 16 && active.active == 16 && active.waiting == 0
                               && active.physical == (wave + 1) * 16,
                               "physical-pressure wave changed the production active limit or physical receipts")
                    ids.forEach { pool.cancel($0) }
                    try expect(completed.wait(timeout: .now() + 2) == .success,
                               "physical-pressure wave did not finish logical cancellation")
                }
                let held = pool.pressureForSelfTest
                lock.lock(); let saturated = dialCount == 128 && cancelCount == 128 && callbacks.count == 128; lock.unlock()
                try expect(saturated && held.registered == 0 && held.active == 0 && held.waiting == 0
                           && held.physical == 128 && budget.usage.resources == 0,
                           "logical cancellation refunded a production physical reservation before its receipt")

                if expires {
                    let finished = DispatchSemaphore(value: 0), started = NetworkPerformanceDiagnostics.now()
                    let wireID: UInt16 = 0x7300
                    try expect(pool.resolveResult(query: question(wireID), completion: { result in
                        record(wireID, result: result, expected: .timeout); finished.signal()
                    }) != nil, "physically queued timeout was rejected as capacity")
                    pool.drainQueueForSelfTest()
                    let queued = pool.pressureForSelfTest
                    try expect(queued.registered == 1 && queued.active == 0 && queued.waiting == 1
                               && queued.physical == 128,
                               "physical-pressure timeout acquired an early dial or lost its registration")
                    try expect(finished.wait(timeout: .now() + 2) == .success,
                               "a physically queued client restarted or lost its original deadline")
                    let elapsed = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started)
                    lock.lock(); let timedOutWithoutIO = dialCount == 128 && resultCounts[wireID] == 1 && !invalid; lock.unlock()
                    let retired = pool.pressureForSelfTest
                    try expect(timedOutWithoutIO && elapsed >= 900 && elapsed < 1_500
                               && retired.registered == 0 && retired.waiting == 0 && retired.physical == 128,
                               "physical-pressure timeout performed I/O, changed its deadline or released an unacknowledged dial")
                } else {
                    let resumed = DispatchGroup(), cancelled = DispatchGroup()
                    var canceledIDs: [UUID] = []
                    for index in 0..<128 {
                        let wireID = UInt16(0x7300 + index), keep = index == 0 || index == 2
                        if keep { resumed.enter() } else { cancelled.enter() }
                        guard let id = pool.resolveResult(query: question(wireID), completion: { result in
                            record(wireID, result: result, expected: keep ? nil : .cancelled)
                            if keep { resumed.leave() } else { cancelled.leave() }
                        }) else { throw Failure(text: "bounded physical-pressure waiter was rejected") }
                        if !keep { canceledIDs.append(id) }
                    }
                    pool.drainQueueForSelfTest()
                    let queued = pool.pressureForSelfTest
                    try expect(queued.registered == 128 && queued.active == 0 && queued.waiting == 128
                               && queued.physical == 128,
                               "physical pressure widened registration/admission or immediately failed its FIFO")
                    let overflowID: UInt16 = 0x7380
                    let rejected = pool.resolveResult(query: question(overflowID), completion: {
                        record(overflowID, result: $0, expected: .capacity)
                    })
                    lock.lock(); let overflowOnce = resultCounts[overflowID] == 1 && dialCount == 128; lock.unlock()
                    try expect(rejected == nil && overflowOnce,
                               "registration 129 was not rejected while 128 bounded waiters were retained")
                    canceledIDs.forEach { pool.cancel($0) }
                    try expect(cancelled.wait(timeout: .now() + 2) == .success,
                               "physical-pressure waiters did not acknowledge logical cancellation")
                    let remaining = pool.pressureForSelfTest
                    lock.lock()
                    let noEarlyWork = dialCount == 128 && cancelCount == 128
                        && resultCounts[0x7300] == nil && resultCounts[0x7302] == nil
                    healthy = true
                    let firstReceipt = callbacks.removeFirst()
                    lock.unlock()
                    try expect(noEarlyWork && remaining.registered == 2 && remaining.active == 0
                               && remaining.waiting == 2 && remaining.physical == 128,
                               "canceling queued clients freed physical capacity or delivered another client's answer")
                    // Only this genuine receipt makes one physical place
                    // reusable. The second FIFO client must use its idle return.
                    firstReceipt(.failure(EncryptedDNSQueryFailure.cancelled))
                    try expect(resumed.wait(timeout: .now() + 2) == .success,
                               "a real physical receipt/idle return did not resume the FIFO")
                    let recovered = pool.pressureForSelfTest
                    lock.lock(); let fifo = dialCount == 129 && sentIDs == [0x7300, 0x7302] && !invalid; lock.unlock()
                    try expect(fifo && peer.sendCount == 2 && recovered.registered == 0 && recovered.active == 0
                               && recovered.waiting == 0 && recovered.physical == 128,
                               "physical-pressure recovery lost FIFO, made excess dials or counted a cancel as a terminal receipt")
                }

                lock.lock(); healthy = true; let delayed = callbacks; callbacks.removeAll(); lock.unlock()
                var late: [ReuseMemoryStream] = []
                for callback in delayed {
                    let stream = reuseAuto(mode); late.append(stream); callback(.success(stream))
                }
                pool.drainQueueForSelfTest()
                try expect(late.allSatisfy({ $0.cancelled && $0.sendCount == 0 }),
                           "a late canceled pressure dial was used or pooled")
                if expires {
                    let fresh = DispatchSemaphore(value: 0), wireID: UInt16 = 0x7400
                    try expect(pool.resolveResult(query: question(wireID), completion: {
                        record(wireID, result: $0, expected: nil); fresh.signal()
                    }) != nil, "expired physical-pressure pool did not recover after real receipts")
                    try expect(fresh.wait(timeout: .now() + 2) == .success,
                               "fresh pressure query did not recover after old receipts")
                    lock.lock(); let freshOnly = dialCount == 129 && sentIDs == [wireID] && !invalid; lock.unlock()
                    try expect(freshOnly, "an expired waiter was dialed by a late receipt or completed more than once")
                }
                lock.lock(); let once = resultCounts.values.allSatisfy({ $0 == 1 }) && !invalid; lock.unlock()
                try expect(once, "a physical-pressure client completed twice or lost its failure classification")
                pool.cancel(); pool.drainQueueForSelfTest()
                try expect(budget.usage.resources == 0 && peer.cancelled,
                           "physical-pressure shutdown leaked its reusable transport reservation")
            }
        }
        print("DNS physical backpressure passed: DoH/DoT production-16 eight-wave delayed receipts, physical128/registration128, FIFO/idle recovery, queued cancel/timeout and late-stream disposal")
    }

    /// A strict router supplies the failure channel even when plaintext DNS
    /// fallback is disabled. A local admission refusal must retain its typed
    /// reason; converting it to a DNS SERVFAIL would look like a failed remote
    /// provider and bypass adaptive local-capacity backpressure.
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
        guard value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              value.lowercased().hasPrefix("tls://") else { return nil }
        value.removeFirst(6)
        var bootstrap: String?
        if let hash = value.lastIndex(of: "#") {
            bootstrap = String(value[value.index(after: hash)...])
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
        } else if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":") {
            guard let p = UInt16(value[value.index(after: colon)...]), p > 0 else { return nil }
            parsedPort = p
            value = String(value[..<colon])
        }
        guard DoHEndpoint.isValidServerName(value) else { return nil }
        if let bootstrap, !DoHEndpoint.isAddressLiteral(bootstrap) { return nil }
        // The certificate is validated against the name, so a named endpoint
        // still needs an address to reach it at — resolving it through the
        // resolver it replaces would defeat the point.
        if bootstrap == nil, !DoHEndpoint.isAddressLiteral(value) {
            guard let known = EncryptedDNSBootstrap.address(for: value) else { return nil }
            bootstrap = known
        }
        host = value
        port = parsedPort
        bootstrapAddress = bootstrap.map(DoHEndpoint.unbracketed)
    }

    public var connectHost: String { DoHEndpoint.unbracketed(bootstrapAddress ?? host) }
}

/// Bounded DNS-over-TLS transactions. One query leases each stream, so response
/// order and client ID reuse cannot associate an answer with the wrong client.
public final class DoTResolver {
    public static let maximumConcurrentQueries = DoHResolver.maximumConcurrentQueries
    public static let maximumConcurrentConnectionAttempts = DoHResolver.maximumConcurrentConnectionAttempts
    private let endpoint: DoTEndpoint
    private let requests: EncryptedDNSRequestPool

    /// A scheduling hint only; the pool still owns admission and all leases.
    var schedulingAvailability: (reusable: Int, cold: Int) { requests.schedulingAvailability }

    public convenience init(endpoint: DoTEndpoint, streamDialer: EncryptedDNSStreamDialer? = nil) {
        self.init(endpoint: endpoint, streamDialer: streamDialer, requestTimeout: .seconds(8))
    }

    public convenience init(endpoint: DoTEndpoint,
                            cancellableStreamDialer: @escaping CancellableEncryptedDNSStreamDialer) {
        self.init(endpoint: endpoint, cancellableStreamDialer: cancellableStreamDialer,
                  requestTimeout: .seconds(8))
    }

    convenience init(endpoint: DoTEndpoint,
                     metadataStreamDialer: @escaping MetadataAwareEncryptedDNSStreamDialer,
                     idleTimeout: TimeInterval = 15,
                     idleHandoffGrace: TimeInterval = 8) {
        self.init(endpoint: endpoint, metadataStreamDialer: metadataStreamDialer,
                  requestTimeout: .seconds(8), idleTimeout: idleTimeout,
                  idleHandoffGrace: idleHandoffGrace)
    }

    init(endpoint: DoTEndpoint, streamDialer: EncryptedDNSStreamDialer? = nil,
                     cancellableStreamDialer: CancellableEncryptedDNSStreamDialer? = nil,
                     metadataStreamDialer: MetadataAwareEncryptedDNSStreamDialer? = nil,
                     requestTimeout: DispatchTimeInterval,
                     idleTimeout: TimeInterval = 15, idleLimit: Int = 4,
                     idleHandoffGrace: TimeInterval = 8,
                     activeLimit: Int = DoTResolver.maximumConcurrentQueries,
                     coldDialLimit: Int = DoTResolver.maximumConcurrentConnectionAttempts,
                     clock: @escaping () -> Date = { Date(timeIntervalSince1970: SOCKSUDPResourceLimits.now) },
                     resourceBudget: SOCKSUDPGlobalBudget = SOCKSUDPResourceLimits.shared) {
        self.endpoint = endpoint
        requests = EncryptedDNSRequestPool(protocol: .tls(endpoint), label: "app.hajimi.dns.dot",
            streamDialer: streamDialer, cancellableStreamDialer: cancellableStreamDialer,
            metadataStreamDialer: metadataStreamDialer,
            timeout: requestTimeout, idleTimeout: idleTimeout,
            idleLimit: idleLimit, idleHandoffGrace: idleHandoffGrace,
            activeLimit: activeLimit, coldDialLimit: coldDialLimit,
            clock: clock, resourceBudget: resourceBudget)
    }

    @discardableResult
    public func resolve(query: Data, completion: @escaping (Data?) -> Void) -> UUID? {
        requests.resolve(query: query, completion: completion)
    }

    @discardableResult
    func resolveResult(query: Data,
                       completion: @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                       downgradeBarrier: ((DNSProxyFallbackBarrier) -> Void)? = nil,
                       transportEvidence: ((DNSQueryTransportEvidence) -> Void)? = nil,
                       executionContext: DNSQueryExecutionContext? = nil) -> UUID? {
        requests.resolveResult(query: query, completion: completion, downgradeBarrier: downgradeBarrier,
                               absoluteDeadline: executionContext?.absoluteDeadline,
                               transportEvidence: transportEvidence, executionContext: executionContext)
    }

    public func cancel(_ requestID: UUID) { requests.cancel(requestID) }
    func cancel(_ requestID: UUID, reason: DNSAttemptCancellationReason = .callerCancelled,
                completion: @escaping () -> Void) {
        requests.cancel(requestID, reason: reason, completion: completion)
    }
    public func cancel() { requests.cancel() }
    func cancel(reason: DNSAttemptCancellationReason) { requests.cancel(reason: reason) }
    @discardableResult
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void) -> UUID? {
        requests.resolveResult(query: Data(), completion: completion,
                               absoluteDeadline: absoluteDeadline, connectionOnly: true)
    }
    func drainQueueForSelfTest() { requests.drainQueueForSelfTest() }
    func originalDeadlineForSelfTest(_ requestID: UUID) -> DispatchTime? {
        requests.originalDeadlineForSelfTest(requestID)
    }
}

/// Adapts a `DoTResolver` to the tunnel's datagram interface.
public final class DoTRoutedDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding, DNSConnectionPrewarming, DNSQueryExecutionContextAccepting {
    private let flow: EncryptedDNSDatagramFlow

    public init(resolver: DoTResolver, receive: @escaping (Data) -> Void,
                failure: ((Error) -> Void)? = nil) {
        flow = EncryptedDNSDatagramFlow(
            contextualResolve: { resolver.resolveResult(query: $0, completion: $1, downgradeBarrier: $2, transportEvidence: $3, executionContext: $4) },
            cancelRequest: { resolver.cancel($0, reason: $1, completion: $2) },
            prepare: { resolver.prewarm(absoluteDeadline: $0, completion: $1) }, receive: receive, failure: failure)
    }

    public func send(_ data: Data) { flow.send(data) }
    package func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) { flow.setDNSQueryExecutionContext(context) }
    public func cancel() { flow.cancel() }
    package func cancel(completion: @escaping () -> Void) { flow.cancel(completion: completion) }
    package func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        flow.cancel(reason: reason, completion: completion)
    }
    package func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { flow.proxyFallbackBarrier() }
    package func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { flow.dnsQueryTransportEvidence() }
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Void, EncryptedDNSQueryFailure>) -> Void) {
        flow.prewarm(absoluteDeadline: absoluteDeadline, completion: completion)
    }
}

/// RFC 1035 TCP exchanges inside a caller-authorized encrypted proxy tunnel.
/// The mandatory dialer is the only transport: neither direct TCP/UDP nor an
/// implicit TLS endpoint can be selected here. Authorization remains per query;
/// this bounded owner shares only an already authenticated physical path.
final class ProxyTCPDNSResolver {
    private let requests: EncryptedDNSRequestPool

    private final class ConnectionObservation {
        private let lock = NSLock()
        private let started = NetworkPerformanceDiagnostics.now()
        private let diagnostics: NetworkPerformanceDiagnostics
        private let trace: DNSConnectionAttemptTrace
        private var cancelled = false, finished = false
        private var failureBeforeCancellation: Error?
        init(_ diagnostics: NetworkPerformanceDiagnostics, trace: DNSConnectionAttemptTrace) {
            self.diagnostics = diagnostics; self.trace = trace
        }
        func observeFailure(_ error: Error) {
            lock.lock(); defer { lock.unlock() }
            if !cancelled, !finished, failureBeforeCancellation == nil { failureBeforeCancellation = error }
        }
        func cancel() { lock.lock(); cancelled = true; lock.unlock() }
        func complete(_ result: Result<any NativeOutboundByteStream, Error>) {
            lock.lock()
            guard !finished else { lock.unlock(); return }
            finished = true
            let cancelled = self.cancelled, failure = failureBeforeCancellation
            lock.unlock()
            let admittedFailure = failure.map(EncryptedDNSQueryFailure.classify)
            let outcome: NetworkPerformanceOutcome
            if let admittedFailure, admittedFailure != .cancelled, admittedFailure != .policy { outcome = .failure }
            else if cancelled { outcome = .cancelled }
            else if case .success = result { outcome = .success }
            else if case .failure(let error) = result, EncryptedDNSQueryFailure.classify(error) == .cancelled {
                outcome = .cancelled
            } else { outcome = .failure }
            diagnostics.record(.dnsProxyFallbackConnection,
                milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started), outcome: outcome)
            trace.complete(.dnsProxyFallbackConnection, outcome: outcome)
        }
    }

    init(server: DNSProxyFallbackServer, metadataStreamDialer: @escaping MetadataAwareEncryptedDNSStreamDialer,
         idleTimeout: TimeInterval = 15, idleLimit: Int = 4, idleHandoffGrace: TimeInterval = 8,
         activeLimit: Int = DoHResolver.maximumConcurrentQueries,
         clock: @escaping () -> Date = { Date(timeIntervalSince1970: SOCKSUDPResourceLimits.now) },
         resourceBudget: SOCKSUDPGlobalBudget = SOCKSUDPResourceLimits.shared,
         diagnostics: NetworkPerformanceDiagnostics = .shared, afterReplyIngressForSelfTest: (() -> Void)? = nil) {
        let observed: MetadataAwareEncryptedDNSStreamDialer = { host, port, name, queue, trace, observeFailure, done in
            let observation = ConnectionObservation(diagnostics, trace: trace)
            trace.record(.transportStarted)
            let observedFailure: (Error) -> Void = { error in
                trace.record(.transportFailure, error: error, admitting: {
                    observation.observeFailure(error)
                    observeFailure(error)
                })
            }
            let cancel = metadataStreamDialer(host, port, name, queue, trace, observedFailure) { result in
                if case .failure(let error) = result { observedFailure(error) }
                else { trace.record(.transportReady) }
                observation.complete(result); done(result)
            }
            // Mark only the request here. The real native callback records the
            // outcome and retires its pending-dial reservation in the pool.
            return { observation.cancel(); cancel?() }
        }
        requests = EncryptedDNSRequestPool(protocol: .proxyTCP(server), label: "app.hajimi.dns.proxy-tcp-pool",
            streamDialer: nil, cancellableStreamDialer: nil, metadataStreamDialer: observed,
            timeout: .seconds(8), idleTimeout: idleTimeout, idleLimit: idleLimit,
            idleHandoffGrace: idleHandoffGrace,
            activeLimit: min(DoHResolver.maximumConcurrentQueries, max(1, activeLimit)),
            coldDialLimit: 128,
            clock: clock, resourceBudget: resourceBudget, diagnostics: diagnostics,
            afterReplyIngressForSelfTest: afterReplyIngressForSelfTest)
    }

    @discardableResult
    func resolveResult(query: Data, absoluteDeadline: TimeInterval, permitted: @escaping () -> Bool,
                       completion: @escaping (Result<Data, EncryptedDNSQueryFailure>) -> Void,
                       downgradeBarrier: ((DNSProxyFallbackBarrier) -> Void)? = nil,
                       transportEvidence: ((DNSQueryTransportEvidence) -> Void)? = nil,
                       executionContext: DNSQueryExecutionContext? = nil) -> UUID? {
        requests.resolveResult(query: query, completion: completion, downgradeBarrier: downgradeBarrier,
                               absoluteDeadline: absoluteDeadline, permitted: permitted, transportEvidence: transportEvidence,
                               executionContext: executionContext)
    }
    func cancel(_ requestID: UUID, reason: DNSAttemptCancellationReason = .callerCancelled,
                completion: @escaping () -> Void) { requests.cancel(requestID, reason: reason, completion: completion) }
    func cancel() { requests.cancel() }
    func cancel(reason: DNSAttemptCancellationReason) { requests.cancel(reason: reason) }
    func drainQueueForSelfTest() { requests.drainQueueForSelfTest() }
    var pressureForSelfTest: (registered: Int, active: Int, waiting: Int, physical: Int) { requests.pressureForSelfTest }
}

/// A separate per-question flow owns registration, deny/negative barriers and
/// cancellation. A reusable resolver lease never lends its first caller's
/// routing authority to a later question or survives that question's deadline.
final class ProxyTCPDNSRoutedDatagram: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding, DNSQueryExecutionContextAccepting {
    private let flow: EncryptedDNSDatagramFlow
    init(resolver: ProxyTCPDNSResolver, absoluteDeadline: TimeInterval, permitted: @escaping () -> Bool,
         receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
        flow = EncryptedDNSDatagramFlow(contextualResolve: { query, done, barrier, evidence, context in
            resolver.resolveResult(query: query, absoluteDeadline: absoluteDeadline, permitted: permitted,
                                   completion: done, downgradeBarrier: barrier, transportEvidence: evidence, executionContext: context)
        }, cancelRequest: { resolver.cancel($0, reason: $1, completion: $2) }, receive: receive, failure: failure)
    }
    func send(_ data: Data) { flow.send(data) }
    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) { flow.setDNSQueryExecutionContext(context) }
    func cancel() { flow.cancel() }
    func cancel(completion: @escaping () -> Void) { flow.cancel(completion: completion) }
    func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        flow.cancel(reason: reason, completion: completion)
    }
    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? { flow.proxyFallbackBarrier() }
    func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence { flow.dnsQueryTransportEvidence() }
}


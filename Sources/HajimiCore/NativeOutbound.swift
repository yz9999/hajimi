import Foundation
import Network
import Security
import CryptoKit
import CommonCrypto
import HajimiCXXProtocolBridge
import HajimiProxyRuntime

public protocol NativeOutboundByteStream: AnyObject {
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}
typealias OutboundByteStream = NativeOutboundByteStream

public protocol NativeOutboundDatagramSession: AnyObject {
    func send(_ payload: Data, to target: RequestTarget)
    func cancel()
}

public enum NativeOutboundFactory {
    private static let staticStreamTypes: Set<String> = ["snell", "anytls", "ssh"]
    private static let policyLock = NSLock()
    private static var configuredPolicies: [String: ProxyPolicy] = [:]

    public static func configure(policies: [String: ProxyPolicy]) {
        policyLock.lock(); configuredPolicies = policies; policyLock.unlock()
        NativeQUICOutbound.configure(policies: policies)
        // Carrier sessions are bound to the server and credentials they were
        // dialled with, so a profile reload must not let a stream ride an
        // outdated one.
        MuxSessionPool.shared.removeAll()
    }

    public static func runQUICProtocolSelfTest() throws {
        try NativeQUICOutbound.selfTest()
    }

    public static func runWebSocketTransportSelfTest() throws {
        try WebSocketByteTransport.runSelfTest()
        try BufferedByteReaderSelfTest.run()
    }

    public static func runMuxSelfTest() throws {
        try MuxSelfTest.run()
        try XUDPSelfTest.run()
    }

    /// Offline regression checks: invalid chains must be rejected before any
    /// carrier can dial, while HTTP/SOCKS and explicit DIRECT remain usable.
    public static func runProxyChainSelfTest() throws {
        let http = ProxyPolicy(name: "HTTP", kind: .http, host: "127.0.0.1", port: 1)
        let socks = ProxyPolicy(name: "SOCKS", kind: .socks5, host: "127.0.0.1", port: 1)
        let tls = ProxyPolicy(name: "TLS", kind: .external, host: "127.0.0.1", port: 1,
                              adapterType: "socks5-tls")
        let direct = ProxyPolicy(name: "DirectAlias", kind: .direct)
        let reject = ProxyPolicy(name: "Rejected", kind: .reject)
        let policies = [http.name: http, socks.name: socks, tls.name: tls,
                        direct.name: direct, reject.name: reject]
        func top(_ name: String, key: String = "underlying-proxy") -> ProxyPolicy {
            ProxyPolicy(name: "Top", kind: .native, host: "127.0.0.1", port: 1,
                        adapterType: "trojan", parameters: ["password": "test", key: name])
        }
        func check(_ condition: Bool, _ message: String) throws {
            guard condition else { throw NativeOutboundError.protocolError(message) }
        }
        try check([http, socks, tls].allSatisfy(supports), "HTTP/SOCKS 代理链跳点未进入 C++ 路径")
        var promotedHTTP = http, promotedSOCKS = socks
        promotedHTTP.kind = .native; promotedHTTP.adapterType = "http"
        promotedSOCKS.kind = .native; promotedSOCKS.adapterType = "socks5"
        var routing = Profile()
        routing.proxies[http.name] = promotedHTTP; routing.proxies[socks.name] = promotedSOCKS
        let destination = RequestTarget(host: "127.0.0.1", port: 1, protocolName: "HTTP")
        guard case .http = routing.route(for: destination, mode: .proxy, globalPolicy: http.name),
              case .socks5 = routing.route(for: destination, mode: .proxy, globalPolicy: socks.name) else {
            throw NativeOutboundError.protocolError("C++ HTTP/SOCKS 节点丢失转发或 TLS UDP 语义")
        }
        for name in ["HTTP", "SOCKS", "TLS", "DIRECT", "direct", "DirectAlias"] {
            try check(chainValidationError(for: top(name), in: policies) == nil,
                      "有效代理链被拒绝：\(name)")
        }
        try check(chainValidationError(for: top("SOCKS", key: "dialer-proxy"), in: policies) == nil,
                  "dialer-proxy 未遵循代理链验证")
        for name in ["Missing", "", "Rejected"] {
            try check(chainValidationError(for: top(name), in: policies) != nil,
                      "无效代理链可能退回直连：\(name)")
        }
        var namedDirect = policies
        namedDirect["direct"] = ProxyPolicy(name: "direct", kind: .socks5,
            host: "127.0.0.1", port: 1, parameters: ["underlying-proxy": "Missing"])
        namedDirect["Direct"] = ProxyPolicy(name: "Direct", kind: .reject)
        for name in ["direct", "Direct"] {
            try check(chainValidationError(for: top(name), in: namedDirect) != nil,
                      "同名用户节点被错误解释为内建 DIRECT：\(name)")
        }
        var cyclic = policies
        cyclic["Top"] = top("Top")
        try check(chainValidationError(for: top("Top"), in: cyclic) != nil, "代理链自环未被拒绝")
        cyclic["HTTP"] = ProxyPolicy(name: "HTTP", kind: .http, host: "127.0.0.1", port: 1,
                                     parameters: ["underlying-proxy": "Top"])
        cyclic["Top"] = top("HTTP")
        try check(chainValidationError(for: top("HTTP"), in: cyclic) != nil, "代理链互环未被拒绝")
        var deep: [String: ProxyPolicy] = [:]
        for index in 0..<16 {
            deep["Hop\(index)"] = ProxyPolicy(name: "Hop\(index)", kind: .http,
                host: "127.0.0.1", port: 1,
                parameters: index == 15 ? [:] : ["underlying-proxy": "Hop\(index + 1)"])
        }
        try check(chainValidationError(for: top("Hop1"), in: deep) == nil, "16 层代理链边界错误")
        try check(chainValidationError(for: top("Hop0"), in: deep) != nil, "过深代理链未被拒绝")
        let chainedSS = ProxyPolicy(name: "SS", kind: .native, host: "127.0.0.1", port: 1,
            adapterType: "ss", parameters: ["cipher": "aes-128-gcm", "password": "test",
                                            "underlying-proxy": "HTTP"])
        var chainedSOCKS = socks
        chainedSOCKS.parameters["underlying-proxy"] = "HTTP"
        try check(NativeCXXOutbound.validationError(for: chainedSS, udp: true) != nil
                  && NativeCXXOutbound.validationError(for: chainedSOCKS, udp: true) != nil,
                  "原生 UDP 可能绕过声明的 TCP 代理链")
    }

    public static func supportsUDP(_ policy: ProxyPolicy) -> Bool {
        guard supports(policy) else { return false }
        if MuxApplicability.isEnabled(for: policy) { return true }
        if usesVisionXUDP(policy) { return true }
        guard NativeCXXOutbound.validationError(for: policy, udp: true) == nil else { return false }
        let type = policy.adapterType?.lowercased() ?? ""
        if ["hysteria", "hysteria2", "tuic"].contains(type) {
            return NativeQUICOutbound.supportsUDP(policy)
        }
        if type == "snell" {
            let version = Int(policy.parameters["version"] ?? "4") ?? 4
            return supports(policy) && version >= 3
        }
        if type == "anytls" { return supports(policy) }
        // SIP022's datagram path is verified against a live server and pinned
        // to externally computed vectors, but it still follows the node's own
        // declaration rather than being assumed: a server with no UDP relay
        // configured silently drops datagrams, and UDP gives the client no way
        // to tell that apart from a working relay with nothing to say. Nodes
        // that do not opt in get UDP carried over the TCP stream instead.
        if isShadowsocks2022(policy) {
            return boolean(policy.parameters["udp"], default: false)
                || boolean(policy.parameters["udp-relay"], default: false)
        }
        return ["ss", "ssr", "vmess", "vless", "trojan"].contains(type)
    }

    /// Vision converts each UDP association to a dedicated command=mux
    /// carrier containing XUDP packets. This is protocol-mandated and remains
    /// separate from the optional shared Mux.Cool pool used by TCP streams.
    static func usesVisionXUDP(_ policy: ProxyPolicy) -> Bool {
        policy.adapterType?.lowercased() == "vless"
            && VLESSVisionAddons.recognizes(policy.parameters["flow"] ?? "")
    }

    /// These protocols preserve UDP packet boundaries on top of a reliable
    /// byte stream.  That is useful for ordinary datagrams, but QUIC over such
    /// a carrier suffers TCP head-of-line blocking and should let the local
    /// application fall back to HTTPS/TCP instead.
    public static func carriesUDPOverReliableStream(_ policy: ProxyPolicy) -> Bool {
        // With its datagram path off, a SIP022 node carries no UDP at all, and
        // a browser would retry QUIC until it declared the network down. Steer
        // UDP/443 to TCP instead, as for the stream-only outbounds.
        if isShadowsocks2022(policy) { return !supportsUDP(policy) && supports(policy) }
        guard supportsUDP(policy) else { return false }
        if MuxApplicability.isEnabled(for: policy) { return true }
        let type = policy.adapterType?.lowercased() ?? ""
        return ["vmess", "vless", "trojan", "snell", "anytls"].contains(type)
    }

    public static func makeDatagramSession(policy: ProxyPolicy, queue: DispatchQueue,
                                           receive: @escaping (RequestTarget, Data) -> Void,
                                           failure: @escaping (Error) -> Void) throws
        -> NativeOutboundDatagramSession {
        guard supportsUDP(policy) else {
            throw NativeOutboundError.unsupported("该原生协议尚未实现 UDP 数据报封装")
        }
        if usesVisionXUDP(policy) || MuxApplicability.isEnabled(for: policy) {
            return XUDPDatagramSession(
                queue: queue,
                dial: { completion in
                    connectDirect(policy: policy, target: MuxApplicability.carrierTarget,
                                  queue: queue, completion: completion)
                },
                receive: receive, failure: failure)
        }
        return try NativeCXXOutbound.makeDatagramSession(policy: policy, queue: queue,
            preparedDialer: cppPreparedDialer(for: policy, queue: queue), receive: receive, failure: failure)
    }

    /// Accept only configurations implemented by an in-process outbound.
    /// Protocol authentication, encryption, framing and sessions run in C++.
    /// Unsupported options are rejected instead of approximated.
    public static func supports(_ policy: ProxyPolicy) -> Bool {
        guard NativeCXXOutbound.validationError(for: policy) == nil else { return false }
        let adapterType = policy.adapterType?.lowercased() ?? ""
        if policy.kind == .http || policy.kind == .socks5 || ["http", "https", "socks5", "socks5-tls"].contains(adapterType) {
            return [.http, .socks5, .external, .native].contains(policy.kind)
                && normalizedNetwork(policy.parameters) == "tcp" && supportsTLSIdentity(policy)
        }
        if ["hysteria", "hysteria2", "tuic"].contains(adapterType) {
            return NativeQUICOutbound.supports(policy)
        }
        if staticStreamTypes.contains(adapterType) {
            return staticStreamValidationError(for: policy) == nil
        }
        guard policy.kind == .external || policy.kind == .native,
              let type = policy.adapterType?.lowercased(),
              ["ss", "ssr", "vmess", "vless", "trojan"].contains(type),
              policy.host?.isEmpty == false, policy.port != nil else { return false }
        let network = normalizedNetwork(policy.parameters)
        let carriers = ["ss", "ssr"].contains(type)
            ? ["tcp"] : ["tcp", "ws", "grpc", "xhttp", "splithttp", "kcp", "mkcp"]
        guard carriers.contains(network) else { return false }
        // `auto` resolves to packet-up in the current XHTTP implementation.
        // Explicit stream modes keep their wire semantics; unknown values are
        // rejected instead of silently falling back to another mode.
        if ["xhttp", "splithttp"].contains(network),
           XHTTPMode(policy.parameters["xhttp-mode"]) == nil { return false }
        guard !boolean(policy.parameters["ws-v2ray-http-upgrade"], default: false),
              Int(policy.parameters["ws-max-early-data"] ?? "0") == 0,
              !boolean(policy.parameters["global-padding"], default: false),
              !boolean(policy.parameters["authenticated-length"], default: false),
              policy.parameters["certificate"] == nil,
              policy.parameters["private-key"] == nil,
              supportsTLSIdentity(policy) else { return false }
        // Cipher/authentication/version/flow checks are authoritative in C++.
        // Swift only validates composition with the optional legacy carriers.
        return true
    }

    static func shadowsocksCipher(_ policy: ProxyPolicy) -> String {
        (policy.parameters["cipher"] ?? policy.parameters["encrypt-method"] ?? "").lowercased()
    }

    /// A custom ClientHello is currently used by REALITY, whose certificate
    /// authentication is part of that protocol. Ordinary TLS stays on the
    /// system stack so its X.509 chain and hostname validation are preserved.
    private static func supportsTLSIdentity(_ policy: ProxyPolicy) -> Bool {
        let fingerprint = (policy.parameters["client-fingerprint"]
            ?? policy.parameters["fingerprint"] ?? "").lowercased()
        let reality = policy.parameters["reality-public-key"] != nil
            || (policy.parameters["security"] ?? "").lowercased() == "reality"
        if reality {
            return ["", "chrome", "chrome133", "random", "randomized"].contains(fingerprint)
                && (try? RealityTLSByteTransport.Configuration(
                    policy: policy, fallbackServerName: policy.host ?? "")) != nil
        }
        return fingerprint.isEmpty
    }

    /// SIP022 reuses the `ss` type name but is a distinct protocol, so the
    /// cipher is what selects the code path.
    static func isShadowsocks2022(_ policy: ProxyPolicy) -> Bool {
        Shadowsocks2022.method(named: shadowsocksCipher(policy)) != nil
    }

    /// Xray takes the gRPC service name from `path`/`serviceName`; the method
    /// is always `Tun` for the bidirectional stream.
    static func grpcServiceName(_ policy: ProxyPolicy) -> String {
        let raw = policy.parameters["grpc-service-name"]
            ?? policy.parameters["servicename"]
            ?? policy.parameters["service-name"]
            ?? policy.parameters["ws-path"]
            ?? policy.parameters["path"] ?? ""
        let trimmed = raw.trimmingCharacters(in: CharacterSet(charactersIn: "/ "))
        return trimmed.isEmpty ? "GunService" : trimmed
    }

    static func grpcAuthority(_ policy: ProxyPolicy, host: String) -> String {
        policy.parameters["host"] ?? policy.parameters["ws-host"]
            ?? policy.parameters["sni"] ?? policy.parameters["servername"] ?? host
    }

    static func xhttpPath(_ policy: ProxyPolicy) -> String? {
        policy.parameters["xhttp-path"] ?? policy.parameters["path"]
            ?? policy.parameters["ws-path"]
    }

    /// Xray sends the configured `host` verbatim, with no port, and the server
    /// strips any port before comparing — so a bare hostname is both correct
    /// and byte-identical to the reference client.
    static func xhttpHost(_ policy: ProxyPolicy, host: String) -> String {
        policy.parameters["xhttp-host"] ?? policy.parameters["host"]
            ?? policy.parameters["ws-host"] ?? policy.parameters["sni"]
            ?? policy.parameters["servername"] ?? host
    }

    /// `xPaddingBytes` is a `from-to` range the server checks the padding
    /// length against. Mismatched bounds are answered 400 on every request, so
    /// an unparseable value falls back to the server's own default rather than
    /// to something narrower.
    static func xhttpPaddingRange(_ policy: ProxyPolicy) -> ClosedRange<Int> {
        guard let raw = policy.parameters["xhttp-padding-bytes"]
            ?? policy.parameters["x-padding-bytes"]
            ?? policy.parameters["xpaddingbytes"] else { return XHTTP.defaultPaddingRange }
        let bounds = raw.split(separator: "-").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
        guard bounds.count == 2, bounds[0] >= 0, bounds[0] <= bounds[1], bounds[1] > 0 else {
            if bounds.count == 1, bounds[0] > 0 { return bounds[0]...bounds[0] }
            return XHTTP.defaultPaddingRange
        }
        return max(1, bounds[0])...bounds[1]
    }

    public static func validationError(for policy: ProxyPolicy) -> String? {
        if let error = NativeCXXOutbound.validationError(for: policy) { return error }
        let type = policy.adapterType?.lowercased() ?? ""
        if ["hysteria", "hysteria2", "tuic"].contains(type) {
            return NativeQUICOutbound.validationError(for: policy)
        }
        if staticStreamTypes.contains(type) {
            return staticStreamValidationError(for: policy)
        }
        if type == "ssr" {
            let cipher = policy.parameters["cipher"] ?? "(空)"
            let proto = policy.parameters["protocol"] ?? "origin"
            let obfs = policy.parameters["obfs"] ?? "plain"
            if !["aes-128-cfb", "aes-192-cfb", "aes-256-cfb"].contains(cipher.lowercased()) {
                return "SSR 原生路径暂不支持 cipher=\(cipher)"
            }
            if proto.lowercased() != "origin" { return "SSR 原生路径暂不支持 protocol=\(proto)" }
            if obfs.lowercased() != "plain" { return "SSR 原生路径暂不支持 obfs=\(obfs)" }
        }
        if type == "vmess" || type == "vless" {
            guard let rawUUID = policy.parameters["uuid"] ?? policy.parameters["username"],
                  UUID(uuidString: rawUUID) != nil else { return "\(type.uppercased()) UUID 无效" }
        }
        if type == "vmess", !boolean(policy.parameters["vmess-aead"], default: true) {
            return "第一方内核只启用 VMess AEAD"
        }
        if type == "vless" {
            let flow = (policy.parameters["flow"] ?? "").lowercased()
            if !flow.isEmpty, !VLESSVisionAddons.recognizes(flow) {
                return "VLESS 暂不支持 flow=\(flow)"
            }
            if VLESSVisionAddons.recognizes(flow) {
                if normalizedNetwork(policy.parameters) != "tcp" {
                    return "VLESS Vision 只支持原始 TCP + REALITY，不支持 WS/gRPC/XHTTP/mKCP"
                }
                let reality = policy.parameters["reality-public-key"] != nil
                    || (policy.parameters["security"] ?? "").lowercased() == "reality"
                if !reality { return "VLESS Vision 当前需要可切换 raw 载体的 REALITY TLS" }
                if boolean(policy.parameters["mux"], default: false) {
                    return "VLESS Vision TCP 与 Mux.Cool 不兼容"
                }
            }
        }
        return supports(policy) ? nil : "配置包含尚未进入第一方 \(type.uppercased()) 路径的传输、流控或代理链选项"
    }

    static func connect(policy: ProxyPolicy, target: RequestTarget, plainHTTP: Bool = false,
                        queue: DispatchQueue,
                        completion: @escaping (Result<any OutboundByteStream, Error>) -> Void) {
        // Multiplexing is transparent to every caller: it hands back the same
        // `OutboundByteStream`, so neither the engine nor the utun data plane
        // can tell a logical stream from a dedicated connection.
        guard MuxApplicability.isEnabled(for: policy),
              target.protocolName.uppercased() != "UDP" else {
            connectDirect(policy: policy, target: target, plainHTTP: plainHTTP, queue: queue, completion: completion)
            return
        }
        MuxSessionPool.shared.openStream(
            policy: policy, target: target, queue: queue,
            dial: { carrierCompletion in
                // The carrier is an ordinary connection to the mux destination;
                // reusing connectDirect keeps TLS, WebSocket and proxy chaining
                // identical to the non-multiplexed path.
                connectDirect(policy: policy, target: MuxApplicability.carrierTarget,
                              queue: queue, completion: carrierCompletion)
            },
            completion: completion)
    }

    private static func connectDirect(policy: ProxyPolicy, target: RequestTarget, plainHTTP: Bool = false,
                                      queue: DispatchQueue,
                                      completion: @escaping (Result<any OutboundByteStream, Error>) -> Void) {
        guard supports(policy) else {
            completion(.failure(NativeOutboundError.unsupported(validationError(for: policy) ?? "C++ 协议配置无效")))
            return
        }
        if let error = chainValidationError(for: policy) {
            completion(.failure(NativeOutboundError.unsupported(error))); return
        }
        NativeCXXOutbound.connect(policy: policy, target: target, plainHTTP: plainHTTP, queue: queue,
            preparedDialer: cppPreparedDialer(for: policy, queue: queue), completion: completion)
    }

    private static func cppPreparedDialer(for policy: ProxyPolicy, queue: DispatchQueue) -> HJCppTransportDialer? {
        if ["hysteria", "hysteria2", "tuic"].contains(policy.adapterType?.lowercased() ?? "") { return nil }
        let reality = policy.parameters["reality-public-key"] != nil
            || (policy.parameters["security"] ?? "").lowercased() == "reality"
        guard normalizedNetwork(policy.parameters) != "tcp" || reality || underlyingName(policy) != nil else {
            return nil
        }
        return { done in
            let server = RequestTarget(host: policy.host ?? "", port: policy.port ?? 0, protocolName: "TCP")
            dialCXXCarrier(policy: policy, target: server, queue: queue) { result in
                switch result {
                case .failure(let error): done(nil, error)
                case .success(let transport):
                    let adapter: any HJByteStream = transport is any VisionDirectByteTransport
                        ? CXXVisionCarrierAdapter(transport: transport, queue: queue)
                        : CXXCarrierAdapter(transport: transport, queue: queue)
                    done(adapter, nil)
                }
            }
        }
    }

    /// Composes optional carriers. No proxy protocol headers, authentication,
    /// crypto or payload framing are performed here; those are C++ engines.
    private static func dialCXXCarrier(policy: ProxyPolicy, target: RequestTarget,
                                      queue: DispatchQueue,
                                      completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        guard supports(policy), let host = policy.host, let port = policy.port else {
            completion(.failure(NativeOutboundError.unsupported("高级协议配置不在原生支持范围")))
            return
        }
        let type = policy.adapterType?.lowercased() ?? ""
        let realityEnabled = policy.parameters["reality-public-key"] != nil
            || (policy.parameters["security"] ?? "").lowercased() == "reality"
        let tlsDefault = ["trojan", "https", "socks5-tls"].contains(type)
            || (policy.parameters["security"] ?? "").lowercased() == "tls"
        let tlsEnabled = realityEnabled || boolean(policy.parameters["tls"], default: tlsDefault)
        if let error = chainValidationError(for: policy) {
            completion(.failure(NativeOutboundError.unsupported(error))); return
        }
        let underlying = underlyingPolicy(for: policy)
        if underlyingName(policy) != nil && underlying == nil {
            // A profile reload may remove the hop after the validation snapshot.
            completion(.failure(NativeOutboundError.unsupported("底层代理已变更，已拒绝绕过代理链直连")))
            return
        }
        if let underlying, underlying.kind != .direct {
            let carrierTarget = RequestTarget(host: host, port: port, protocolName: "TCP")
            let redial: XHTTPByteTransport.Dialer = { done in
                connect(policy: underlying, target: carrierTarget, queue: queue) { result in
                    done(result.map { OutboundStreamTransport($0) as any ByteTransport })
                }
            }
            connect(policy: underlying, target: carrierTarget, queue: queue) { result in
                switch result {
                case .failure(let error): completion(.failure(error))
                case .success(let stream):
                    prepareNestedCarrier(OutboundStreamTransport(stream),
                                         policy: policy, tlsEnabled: tlsEnabled,
                                         host: host, redial: redial,
                                         queue: queue) { carrier in
                        finishProtocolCarrier(carrier, policy: policy,
                                              target: target, type: type,
                                              queue: queue, completion: completion)
                    }
                }
            }
            return
        }
        // mKCP runs on UDP and brings its own reliability, so it cannot be
        // layered on the TCP dial below — it has to replace it.
        if ["kcp", "mkcp"].contains(normalizedNetwork(policy.parameters)) {
            do {
                let (configuration, _) = try MKCPOutbound.configuration(for: policy)
                MKCPTransport.connect(host: host, port: port, configuration: configuration,
                                      queue: queue) { result in
                    switch result {
                    case .failure(let error): completion(.failure(error))
                    case .success(let transport):
                        guard tlsEnabled else {
                            finishProtocolCarrier(.success(transport), policy: policy,
                                                  target: target, type: type,
                                                  queue: queue, completion: completion)
                            return
                        }
                        let finishTLS: (Result<any ByteTransport, Error>) -> Void = { secured in
                            finishProtocolCarrier(secured, policy: policy, target: target,
                                                  type: type, queue: queue,
                                                  completion: completion)
                        }
                        if realityEnabled {
                            RealityTLSByteTransport.upgrade(raw: transport, policy: policy,
                                                           fallbackServerName: host,
                                                           queue: queue, completion: finishTLS)
                        } else {
                            NestedNetworkTLSByteTransport.upgrade(
                                raw: transport,
                                serverName: policy.parameters["sni"]
                                    ?? policy.parameters["servername"] ?? host,
                                skipCertificateVerification:
                                    boolean(policy.parameters["skip-cert-verify"], default: false),
                                alpn: protocolList(policy.parameters["alpn"]),
                                completion: finishTLS)
                        }
                    }
                }
            } catch { completion(.failure(error)) }
            return
        }
        NetworkByteTransport.connect(host: host, port: port,
                                     tls: tlsEnabled && !realityEnabled,
                                     serverName: policy.parameters["sni"] ?? policy.parameters["servername"] ??
                                         policy.parameters["ws-host"],
                                     skipCertificateVerification: boolean(policy.parameters["skip-cert-verify"], default: false),
                                     webSocket: normalizedNetwork(policy.parameters) == "ws",
                                     alpn: protocolList(policy.parameters["alpn"]),
                                     queue: queue) { result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let raw):
                nativeDebug("transport ready for \(policy.name)")
                let finishTransport: (Result<any ByteTransport, Error>) -> Void = { transportResult in
                    completion(transportResult)
                }
                let prepareCarrier: (any ByteTransport) -> Void = { raw in
                switch normalizedNetwork(policy.parameters) {
                case "ws":
                    WebSocketByteTransport.upgrade(raw: raw, policy: policy, queue: queue,
                                                   completion: finishTransport)
                case "grpc":
                    GRPCByteTransport.connect(
                        raw: raw, serviceName: grpcServiceName(policy),
                        authority: grpcAuthority(policy, host: host),
                        scheme: tlsEnabled ? "https" : "http", queue: queue) { result in
                        finishTransport(result.map { $0 as any ByteTransport })
                    }
                case "xhttp", "splithttp":
                    // Uploads cannot share the downlink socket — its response
                    // body never ends — so this carrier dials for itself.
                    XHTTPTransport.connect(
                        raw: raw,
                        dial: { done in
                            NetworkByteTransport.connect(
                                host: host, port: port, tls: tlsEnabled && !realityEnabled,
                                serverName: policy.parameters["sni"] ?? policy.parameters["servername"],
                                skipCertificateVerification:
                                    boolean(policy.parameters["skip-cert-verify"], default: false),
                                webSocket: false, alpn: protocolList(policy.parameters["alpn"]),
                                queue: queue) { result in
                                    switch result {
                                    case .failure(let error): done(.failure(error))
                                    case .success(let redialled) where realityEnabled:
                                        RealityTLSByteTransport.upgrade(
                                            raw: redialled, policy: policy,
                                            fallbackServerName: host, queue: queue,
                                            completion: done)
                                    case .success(let redialled): done(.success(redialled))
                                    }
                                }
                        },
                        mode: XHTTPMode(policy.parameters["xhttp-mode"])!,
                        path: XHTTP.normalizedPath(xhttpPath(policy)),
                        hostHeader: xhttpHost(policy, host: host),
                        scheme: tlsEnabled ? "https" : "http",
                        paddingRange: xhttpPaddingRange(policy),
                        queue: queue) { result in
                        finishTransport(result.map { $0 as any ByteTransport })
                    }
                default:
                    finishTransport(.success(raw))
                }
                }
                if realityEnabled {
                    RealityTLSByteTransport.upgrade(raw: raw, policy: policy,
                                                    fallbackServerName: host,
                                                    queue: queue) { result in
                        switch result {
                        case .failure(let error): finishTransport(.failure(error))
                        case .success(let secured): prepareCarrier(secured)
                        }
                    }
                } else {
                    prepareCarrier(raw)
                }
            }
        }
    }

    private static func finishProtocolCarrier(_ result: Result<any ByteTransport, Error>,
                                               policy: ProxyPolicy, target: RequestTarget,
                                               type: String, queue: DispatchQueue,
                                               completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        completion(result)
    }

    /// Applies TLS and the configured carrier on top of a connection that was
    /// dialled through another proxy.
    ///
    /// `redial` opens a second connection over the same underlying proxy, which
    /// only XHTTP needs — its uploads cannot share the downlink socket.
    private static func prepareNestedCarrier(_ base: any ByteTransport,
                                             policy: ProxyPolicy,
                                             tlsEnabled: Bool,
                                             host: String,
                                             redial: @escaping XHTTPByteTransport.Dialer,
                                             queue: DispatchQueue,
                                             completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        let network = normalizedNetwork(policy.parameters)
        nativeDebug("preparing nested carrier \(policy.name) tls=\(tlsEnabled) network=\(network)")

        /// Every connection in the session has to get the same TLS treatment,
        /// so this is shared between the primary one and XHTTP's redials.
        let withTLS: (any ByteTransport, @escaping (Result<any ByteTransport, Error>) -> Void) -> Void = { raw, done in
            guard tlsEnabled else { done(.success(raw)); return }
            let reality = policy.parameters["reality-public-key"] != nil
                || (policy.parameters["security"] ?? "").lowercased() == "reality"
            if reality {
                RealityTLSByteTransport.upgrade(raw: raw, policy: policy,
                                                fallbackServerName: host,
                                                queue: queue, completion: done)
                return
            }
            var nestedALPN = protocolList(policy.parameters["alpn"])
            if nestedALPN.isEmpty, network == "ws" { nestedALPN = ["http/1.1"] }
            NestedNetworkTLSByteTransport.upgrade(
                raw: raw,
                serverName: policy.parameters["sni"] ??
                    policy.parameters["servername"] ??
                    policy.parameters["ws-host"] ?? policy.host ?? "",
                skipCertificateVerification:
                    boolean(policy.parameters["skip-cert-verify"], default: false),
                alpn: nestedALPN,
                completion: done)
        }

        withTLS(base) { result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let transport):
                switch network {
                case "ws":
                    WebSocketByteTransport.upgrade(raw: transport, policy: policy,
                                                   queue: queue, completion: completion)
                case "grpc":
                    GRPCByteTransport.connect(
                        raw: transport, serviceName: grpcServiceName(policy),
                        authority: grpcAuthority(policy, host: host),
                        scheme: tlsEnabled ? "https" : "http", queue: queue) {
                        completion($0.map { $0 as any ByteTransport })
                    }
                case "xhttp", "splithttp":
                    XHTTPTransport.connect(
                        raw: transport,
                        dial: { done in
                            redial { dialled in
                                switch dialled {
                                case .failure(let error): done(.failure(error))
                                case .success(let raw): withTLS(raw, done)
                                }
                            }
                        },
                        mode: XHTTPMode(policy.parameters["xhttp-mode"])!,
                        path: XHTTP.normalizedPath(xhttpPath(policy)),
                        hostHeader: xhttpHost(policy, host: host),
                        scheme: tlsEnabled ? "https" : "http",
                        paddingRange: xhttpPaddingRange(policy),
                        queue: queue) {
                        completion($0.map { $0 as any ByteTransport })
                    }
                default:
                    completion(.success(transport))
                }
            }
        }
    }

    private static func underlyingName(_ policy: ProxyPolicy) -> String? {
        policy.parameters["underlying-proxy"] ?? policy.parameters["dialer-proxy"]
    }

    private static func underlyingPolicy(for policy: ProxyPolicy) -> ProxyPolicy? {
        guard let name = underlyingName(policy) else { return nil }
        policyLock.lock(); defer { policyLock.unlock() }
        if let configured = configuredPolicies[name] { return configured }
        return name.uppercased() == "DIRECT" ? ProxyPolicy(name: name, kind: .direct) : nil
    }

    private static func chainValidationError(for policy: ProxyPolicy) -> String? {
        policyLock.lock(); let snapshot = configuredPolicies; policyLock.unlock()
        return chainValidationError(for: policy, in: snapshot)
    }

    private static func chainValidationError(for policy: ProxyPolicy,
                                             in snapshot: [String: ProxyPolicy]) -> String? {
        var current = policy
        var visited: Set<String> = [policy.name]
        for _ in 0..<16 {
            guard let name = underlyingName(current) else { return nil }
            guard let next = snapshot[name] else {
                return name.uppercased() == "DIRECT" ? nil : "底层代理未找到，已拒绝绕过代理链直连"
            }
            if next.kind == .direct { return nil }
            if next.kind == .reject { return "底层代理为 REJECT，已拒绝建立代理链" }
            if !visited.insert(next.name).inserted { return "代理链存在循环，已拒绝连接" }
            current = next
        }
        return "代理链超过 16 层，已拒绝连接"
    }

    private static func normalizedNetwork(_ parameters: [String: String]) -> String {
        if boolean(parameters["ws"], default: false) { return "ws" }
        return (parameters["network"] ?? "tcp").lowercased()
    }

    private static func protocolList(_ raw: String?) -> [String] {
        guard let raw else { return [] }
        let trimmed = raw.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return trimmed.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        }.filter { !$0.isEmpty }
    }

    private static func staticStreamValidationError(for policy: ProxyPolicy) -> String? {
        guard policy.kind == .external || policy.kind == .native,
              let type = policy.adapterType?.lowercased(), staticStreamTypes.contains(type),
              policy.host?.isEmpty == false, policy.port != nil else {
            return "原生静态协议节点缺少有效服务器或端口"
        }
        guard underlyingName(policy) == nil else {
            return "\(type.uppercased()) 原生静态路径暂不支持 underlying-proxy/dialer-proxy"
        }
        let network = normalizedNetwork(policy.parameters)
        guard network == "tcp" else { return "\(type.uppercased()) 只支持 TCP 承载" }
        switch type {
        case "snell":
            guard policy.parameters["psk"]?.isEmpty == false else { return "Snell 缺少 psk" }
            let version = Int(policy.parameters["version"] ?? "4") ?? -1
            guard (1...5).contains(version) else { return "Snell version 必须为 1…5" }
            let obfs = (policy.parameters["obfs-mode"] ?? policy.parameters["obfs"] ?? "").lowercased()
            guard obfs.isEmpty || obfs == "plain" || obfs == "none" else {
                return "Snell 原生路径当前只支持无 obfs"
            }
            return nil
        case "anytls":
            guard (policy.parameters["password"] ?? policy.password)?.isEmpty == false else {
                return "AnyTLS 缺少 password"
            }
            return nil
        case "ssh":
            guard (policy.parameters["username"] ?? policy.username)?.isEmpty == false else {
                return "SSH 缺少 username"
            }
            guard (policy.parameters["password"] ?? policy.password)?.isEmpty == false ||
                    policy.parameters["private-key"]?.isEmpty == false else {
                return "SSH 需要 password 或 private-key"
            }
            return nil
        default:
            return "未知原生静态协议"
        }
    }
}

enum NativeOutboundError: LocalizedError {
    case unsupported(String)
    case connection(String)
    case protocolError(String)
    case crypto(String)

    var errorDescription: String? {
        switch self {
        case .unsupported(let value): return value
        case .connection(let value): return "原生出站连接失败：\(value)"
        case .protocolError(let value): return "原生协议错误：\(value)"
        case .crypto(let value): return "原生加密错误：\(value)"
        }
    }
}

/// Internal rather than private so protocol codecs can live in their own
/// files instead of accreting into this one.
protocol ByteTransport: AnyObject {
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func receive(completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}

/// Optional transport compatibility boundary. The retained legacy carrier
/// does not see or construct the C++ proxy protocol's framing or credentials.
private class CXXCarrierAdapter: NSObject, HJByteStream {
    let transport: any ByteTransport
    private let native: HJCallbackStream
    init(transport: any ByteTransport, queue: DispatchQueue) {
        self.transport = transport
        let reader = BufferedByteReader(transport)
        native = HJCallbackStream(queue: queue, supportsHalfClose: false,
            receiveHandler: { maximum, completion in
                reader.readAvailable(maximum: Int(clamping: maximum), completion: completion)
            }, sendHandler: { content, isComplete, completion in
                if isComplete { completion(NativeOutboundError.unsupported("该可选载体不支持半关闭")) }
                else { transport.send(content ?? Data(), completion: completion) }
            }, cancelHandler: { transport.cancel() })
        super.init()
    }
    var supportsHalfClose: Bool { false }
    func receive(maximum: UInt, completion: @escaping HJStreamReadCompletion) {
        native.receive(maximum: maximum, completion: completion)
    }
    func send(content: dispatch_data_t?, isComplete: Bool, completion: @escaping HJStreamWriteCompletion) {
        native.send(content: content, isComplete: isComplete, completion: completion)
    }
    func cancel() { native.cancel() }
}
private final class CXXVisionCarrierAdapter: CXXCarrierAdapter, HJCppVisionCarrier {
    func enableVisionDirectWrite() { (transport as? any VisionDirectByteTransport)?.enableVisionDirectWrite() }
    func enableVisionDirectRead() { (transport as? any VisionDirectByteTransport)?.enableVisionDirectRead() }
}

private final class OutboundStreamTransport: ByteTransport {
    private let stream: any OutboundByteStream
    init(_ stream: any OutboundByteStream) { self.stream = stream }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        stream.send(data, completion: completion)
    }
    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        stream.receive(maximum: 262_144, completion: completion)
    }
    func cancel() { stream.cancel() }
}

private final class NetworkByteTransport: ByteTransport {
    private let stream: ObjCNetworkByteStream

    private init(stream: ObjCNetworkByteStream) { self.stream = stream }

    static func connect(host: String, port: UInt16, tls: Bool, serverName: String?,
                        skipCertificateVerification: Bool, webSocket: Bool,
                        alpn: [String],
                        queue: DispatchQueue,
                        completion: @escaping (Result<NetworkByteTransport, Error>) -> Void) {
        ObjCNetworkByteStream.connect(host: host, port: port, tls: tls, serverName: serverName,
            skipCertificateVerification: skipCertificateVerification,
            alpn: alpn.isEmpty && webSocket ? ["http/1.1"] : alpn,
            interfaceName: loopback(host) ? nil : ProxyEngine.currentOutboundInterface?.name,
            queue: queue) { completion($0.map { NetworkByteTransport(stream: $0) }) }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        stream.send(data, completion: completion)
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        stream.receive(maximum: 262_144, completion: completion)
    }

    func cancel() { stream.cancel() }
}

/// Network.framework cannot attach TLS to an arbitrary existing byte stream.
/// A one-shot loopback connection lets its modern TLS stack provide the record
/// layer while this object forwards only encrypted records to the selected
/// underlying proxy. The listener is bound to 127.0.0.1, accepts one client,
/// then closes; it is not an HTTP/SOCKS proxy or a user-facing data path.
private final class NestedNetworkTLSByteTransport: ByteTransport {
    private let raw: any ByteTransport
    private let serverName: String
    private let skipCertificateVerification: Bool
    private let alpn: [String]
    private let queue = DispatchQueue(label: "app.hajimi.nested-network-tls",
                                      qos: .userInitiated,
                                      autoreleaseFrequency: .workItem)
    private var listener: NWListener?
    private var localCipherConnection: NWConnection?
    private var tlsConnection: NWConnection?
    private var localCipherReady = false
    private var bridgeStarted = false
    private var cancelled = false
    private var completion: ((Result<any ByteTransport, Error>) -> Void)?
    private var upgradeKeepAlive: NestedNetworkTLSByteTransport?

    static func upgrade(raw: any ByteTransport, serverName: String,
                        skipCertificateVerification: Bool, alpn: [String],
                        completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        let value = NestedNetworkTLSByteTransport(raw: raw, serverName: serverName,
                                                  skipCertificateVerification: skipCertificateVerification,
                                                  alpn: alpn)
        value.queue.async {
            nativeDebug("starting nested Network TLS for \(serverName)")
            value.upgradeKeepAlive = value
            value.completion = completion
            value.startListener()
        }
    }

    private init(raw: any ByteTransport, serverName: String,
                 skipCertificateVerification: Bool, alpn: [String]) {
        self.raw = raw
        self.serverName = serverName
        self.skipCertificateVerification = skipCertificateVerification
        self.alpn = alpn
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard let connection = tlsConnection, !cancelled else {
            completion(NativeOutboundError.connection("嵌套 TLS 尚未就绪")); return
        }
        connection.send(content: data, completion: .contentProcessed(completion))
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        guard let connection = tlsConnection, !cancelled else {
            completion(nil, true, NativeOutboundError.connection("嵌套 TLS 尚未就绪")); return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 262_144) {
            data, _, complete, error in completion(data, complete, error)
        }
    }

    func cancel() {
        raw.cancel()
        queue.async { self.cancelLocked() }
    }

    private func startListener() {
        do {
            nativeDebug("nested Network TLS creating listener parameters")
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
            nativeDebug("nested Network TLS creating listener")
            let listener = try NWListener(using: parameters)
            nativeDebug("nested Network TLS listener created")
            self.listener = listener
            listener.newConnectionHandler = { [weak self] connection in
                self?.queue.async { self?.accept(connection) }
            }
            listener.stateUpdateHandler = { [weak self] state in
                self?.queue.async {
                    guard let self, !self.cancelled else { return }
                    nativeDebug("nested Network TLS listener state=\(state)")
                    switch state {
                    case .ready:
                        guard let port = listener.port else {
                            self.fail(NativeOutboundError.connection("嵌套 TLS 本地端口无效")); return
                        }
                        self.startTLSClient(port: port)
                    case .failed(let error): self.fail(error)
                    default: break
                    }
                }
            }
            nativeDebug("nested Network TLS starting listener")
            listener.start(queue: queue)
            nativeDebug("nested Network TLS listener start returned")
            queue.asyncAfter(deadline: .now() + 15) { [weak self] in
                guard let self, !self.cancelled, self.completion != nil else { return }
                self.fail(NativeOutboundError.connection("嵌套 TLS 握手超时"))
            }
        } catch { fail(error) }
    }

    private func startTLSClient(port: NWEndpoint.Port) {
        guard tlsConnection == nil else { return }
        let tlsOptions = NWProtocolTLS.Options()
        let options = tlsOptions.securityProtocolOptions
        if !serverName.isEmpty { sec_protocol_options_set_tls_server_name(options, serverName) }
        if alpn.isEmpty {
            sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
        } else {
            alpn.forEach { sec_protocol_options_add_tls_application_protocol(options, $0) }
        }
        if skipCertificateVerification {
            sec_protocol_options_set_verify_block(options, { _, _, verify in verify(true) }, queue)
        }
        let parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        let connection = NWConnection(host: "127.0.0.1", port: port, using: parameters)
        tlsConnection = connection
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                guard let self, !self.cancelled else { return }
                nativeDebug("nested Network TLS client state=\(state)")
                switch state {
                case .ready:
                    let completion = self.completion
                    self.completion = nil
                    completion?(.success(self))
                    self.upgradeKeepAlive = nil
                case .failed(let error): self.fail(error)
                case .cancelled where self.completion != nil:
                    self.fail(NativeOutboundError.connection("嵌套 TLS 已取消"))
                default: break
                }
            }
        }
        connection.start(queue: queue)
    }

    private func accept(_ connection: NWConnection) {
        guard localCipherConnection == nil, !cancelled else { connection.cancel(); return }
        nativeDebug("nested Network TLS accepted loopback client")
        localCipherConnection = connection
        listener?.cancel(); listener = nil
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            self?.queue.async {
                guard let self, let connection, !self.cancelled,
                      self.localCipherConnection === connection else { return }
                nativeDebug("nested Network TLS cipher endpoint state=\(state)")
                switch state {
                case .ready:
                    self.localCipherReady = true
                    self.startBridgeIfReady()
                case .failed(let error): self.fail(error)
                default: break
                }
            }
        }
        connection.start(queue: queue)
    }

    private func startBridgeIfReady() {
        guard localCipherReady, !bridgeStarted,
              let local = localCipherConnection else { return }
        bridgeStarted = true
        pumpLocalCiphertext(local)
        pumpRemoteCiphertext(local)
    }

    private func pumpLocalCiphertext(_ local: NWConnection) {
        guard !cancelled else { return }
        local.receive(minimumIncompleteLength: 1, maximumLength: 262_144) {
            [weak self, weak local] data, _, complete, error in
            guard let self, let local else { return }
            self.queue.async {
                guard !self.cancelled, self.localCipherConnection === local else { return }
                if let error { self.fail(error); return }
                guard let data, !data.isEmpty else {
                    if complete { self.fail(NativeOutboundError.connection("嵌套 TLS 本地流已关闭")) }
                    else { self.pumpLocalCiphertext(local) }
                    return
                }
                nativeDebug("nested Network TLS local ciphertext bytes=\(data.count)")
                self.raw.send(data) { [weak self, weak local] sendError in
                    self?.queue.async {
                        guard let self, let local, !self.cancelled else { return }
                        if let sendError { self.fail(sendError); return }
                        nativeDebug("nested Network TLS forwarded local ciphertext")
                        if complete { self.raw.cancel(); self.cancelLocked() }
                        else { self.pumpLocalCiphertext(local) }
                    }
                }
            }
        }
    }

    private func pumpRemoteCiphertext(_ local: NWConnection) {
        guard !cancelled else { return }
        raw.receive { [weak self, weak local] data, complete, error in
            self?.queue.async {
                guard let self, let local, !self.cancelled else { return }
                if let error { self.fail(error); return }
                if let data { nativeDebug("nested Network TLS remote ciphertext bytes=\(data.count)") }
                if data?.isEmpty != false, !complete {
                    self.pumpRemoteCiphertext(local); return
                }
                local.send(content: data, contentContext: .defaultMessage,
                           isComplete: complete, completion: .contentProcessed { [weak self, weak local] sendError in
                    self?.queue.async {
                        guard let self, let local, !self.cancelled else { return }
                        if let sendError { self.fail(sendError); return }
                        if !complete { self.pumpRemoteCiphertext(local) }
                    }
                })
            }
        }
    }

    private func fail(_ error: Error) {
        guard !cancelled else { return }
        let completion = self.completion
        self.completion = nil
        cancelLocked()
        completion?(.failure(error))
        upgradeKeepAlive = nil
    }

    private func cancelLocked() {
        guard !cancelled else { return }
        cancelled = true
        listener?.cancel(); listener = nil
        localCipherConnection?.cancel(); localCipherConnection = nil
        tlsConnection?.cancel(); tlsConnection = nil
        raw.cancel()
    }
}

final class BufferedByteReader {
    private let transport: any ByteTransport
    private var buffer = Data()
    private var readOffset = 0
    private var ended = false

    init(_ transport: any ByteTransport) { self.transport = transport }

    func readExactly(_ count: Int, completion: @escaping (Result<Data, Error>) -> Void) {
        guard count >= 0 else {
            completion(.failure(NativeOutboundError.protocolError("读取长度无效"))); return
        }
        if bufferedCount >= count {
            completion(.success(consume(count))); return
        }
        if ended {
            completion(.failure(bufferedCount == 0 ? BufferedByteReaderError.endOfStream
                                                   : BufferedByteReaderError.truncatedRecord))
            return
        }
        receiveMore { [weak self] result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success: self?.readExactly(count, completion: completion)
            }
        }
    }

    func readUntil(_ marker: Data, maximum: Int,
                   completion: @escaping (Result<Data, Error>) -> Void) {
        if let range = buffer.range(of: marker, options: [],
                                    in: readOffset..<buffer.endIndex) {
            completion(.success(consume(range.upperBound - readOffset))); return
        }
        guard bufferedCount < maximum else {
            completion(.failure(NativeOutboundError.protocolError("响应头过长"))); return
        }
        receiveMore { [weak self] result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success: self?.readUntil(marker, maximum: maximum, completion: completion)
            }
        }
    }

    func readAvailable(maximum: Int,
                       completion: @escaping (Data?, Bool, Error?) -> Void) {
        if bufferedCount > 0 {
            let count = min(maximum, bufferedCount)
            completion(consume(count), false, nil)
            return
        }
        guard !ended else { completion(nil, true, nil); return }
        transport.receive { [weak self] data, complete, error in
            guard let self else { return }
            if let error { self.ended = true; completion(nil, true, error); return }
            if complete { self.ended = true }
            guard let data, data.count > maximum else {
                completion(data, complete, nil); return
            }
            let value = Data(data.prefix(maximum))
            self.appendToBuffer(data.dropFirst(maximum))
            completion(value, false, nil)
        }
    }

    private func receiveMore(completion: @escaping (Result<Void, Error>) -> Void) {
        guard !ended else {
            completion(.failure(BufferedByteReaderError.endOfStream)); return
        }
        transport.receive { [weak self] data, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.appendToBuffer(data) }
            if let error { self.ended = true; completion(.failure(error)); return }
            if complete && (data?.isEmpty != false) {
                self.ended = true
                completion(.failure(BufferedByteReaderError.endOfStream))
                return
            }
            if complete { self.ended = true }
            completion(.success(()))
        }
    }

    private var bufferedCount: Int { buffer.count - readOffset }

    private func consume(_ count: Int) -> Data {
        let end = readOffset + count
        // Handing the whole buffer over costs nothing; copying it costs a
        // memcpy of every received byte. This is the common case for a framed
        // protocol reading a fully buffered record.
        if readOffset == 0, end == buffer.count {
            let value = buffer
            buffer = Data()
            return value
        }
        let value = Data(buffer[readOffset..<end])
        readOffset = end
        compactBufferIfNeeded()
        return value
    }

    private func appendToBuffer<S: DataProtocol>(_ data: S) {
        // Foundation Data may retain all bytes removed from its front and
        // keep extending the allocation on every append.  A long VMess video
        // stream then grows RSS in proportion to total downloaded bytes.
        // Reclaim the consumed prefix before appending so storage follows the
        // currently buffered record size instead of lifetime traffic.
        compactBufferIfNeeded(beforeAppend: true)
        buffer.append(contentsOf: data)
    }

    private func compactBufferIfNeeded(beforeAppend: Bool = false) {
        guard readOffset > 0 else { return }
        if readOffset == buffer.count {
            buffer.removeAll(keepingCapacity: buffer.count <= 1_048_576)
            readOffset = 0
        // Compacting on every append copied the unread remainder thousands of
        // times a second at line rate. Only reclaim when the consumed prefix is
        // already large, or when the unread tail is a small fraction of storage.
        } else if (beforeAppend && readOffset >= 64 * 1_024) ||
                    (readOffset >= 256 * 1_024 && readOffset * 2 >= buffer.count) {
            buffer = Data(buffer[readOffset...])
            readOffset = 0
        }
    }
}

private enum BufferedByteReaderError: LocalizedError {
    case endOfStream
    case truncatedRecord

    var errorDescription: String? {
        switch self {
        case .endOfStream: return "字节流已结束"
        case .truncatedRecord: return "字节流记录被截断"
        }
    }
}

/// Pins the receive-buffer compaction policy: small consumed prefixes must not
/// force a full copy on every append, while a fully consumed record can still
/// be handed out without memcpy.
private enum BufferedByteReaderSelfTest {
    private final class ScriptedTransport: ByteTransport {
        private var chunks: [Data]
        init(chunks: [Data]) { self.chunks = chunks }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
        func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
            if chunks.isEmpty {
                completion(nil, true, nil)
            } else {
                completion(chunks.removeFirst(), false, nil)
            }
        }
        func cancel() {}
    }

    static func run() throws {
        // Feed one byte more than 64 KiB after a 1-byte consume so a naive
        // "compact on every append" policy would copy ~64 KiB, while the
        // thresholded policy keeps the original storage and still returns the
        // right bytes.
        let head = Data([0xAA])
        let body = Data(repeating: 0xBB, count: 64 * 1_024)
        let transport = ScriptedTransport(chunks: [head + body, Data([0xCC])])
        let reader = BufferedByteReader(transport)
        let first = try readExactly(reader, count: 1)
        guard first == head else {
            throw NativeOutboundError.protocolError("BufferedByteReader 首字节读取错误")
        }
        let rest = try readExactly(reader, count: body.count)
        guard rest == body else {
            throw NativeOutboundError.protocolError("BufferedByteReader 在延迟压缩后读数错误")
        }
        let tail = try readExactly(reader, count: 1)
        guard tail == Data([0xCC]) else {
            throw NativeOutboundError.protocolError("BufferedByteReader 跨块读取错误")
        }

        // Whole-buffer consume must return the identical storage without
        // requiring a second copy of a complete record.
        let whole = Data(repeating: 0xDD, count: 1_024)
        let wholeReader = BufferedByteReader(ScriptedTransport(chunks: [whole]))
        let got = try readExactly(wholeReader, count: whole.count)
        guard got == whole else {
            throw NativeOutboundError.protocolError("BufferedByteReader 整段 consume 内容错误")
        }
    }

    private static func readExactly(_ reader: BufferedByteReader, count: Int) throws -> Data {
        let lock = DispatchSemaphore(value: 0)
        var result: Result<Data, Error>?
        reader.readExactly(count) {
            result = $0
            lock.signal()
        }
        guard lock.wait(timeout: .now() + 2) == .success, let result else {
            throw NativeOutboundError.protocolError("BufferedByteReader 读取超时")
        }
        return try result.get()
    }
}

func isCleanByteStreamEOF(_ error: Error) -> Bool {
    guard let value = error as? BufferedByteReaderError else { return false }
    if case .endOfStream = value { return true }
    return false
}

private final class WebSocketByteTransport: ByteTransport {
    private typealias ReceiveCompletion = (Data?, Bool, Error?) -> Void

    private let raw: any ByteTransport
    private let reader: BufferedByteReader
    private let sendQueue = DispatchQueue(label: "app.hajimi.websocket.send",
                                          qos: .userInitiated,
                                          autoreleaseFrequency: .workItem)
    private var pendingWrites: [(Data, (Error?) -> Void)] = []
    private var pendingWriteHead = 0
    private var writeInFlight = false
    private var cancelled = false
    private var keepaliveTimer: DispatchSourceTimer?
    private var lastActivity = Date()
    private var receiveInFlight = false
    private var receiveEnded = false
    private var receiveError: Error?
    private var receivedFrames: [Data] = []
    private var receivedFrameHead = 0
    private var bufferedReceiveBytes = 0
    private var pendingReceives: [ReceiveCompletion] = []
    private var pendingReceiveHead = 0
    private let receiveHighWaterMark = 4 * 1_024 * 1_024

    private init(raw: any ByteTransport) {
        self.raw = raw
        reader = BufferedByteReader(raw)
    }

    fileprivate static func runSelfTest() throws {
        let pong = DispatchSemaphore(value: 0)
        let pingPayload = Data("hajimi-ws-ping".utf8)
        let raw = WebSocketSelfTestRawTransport { opcode, payload in
            if opcode == 0xA, payload == pingPayload { pong.signal() }
        }
        let upgraded = DispatchSemaphore(value: 0)
        var upgradeResult: Result<any ByteTransport, Error>?
        let policy = ProxyPolicy(name: "WS self-test", kind: .native,
                                 host: "example.test", port: 80,
                                 adapterType: "vmess",
                                 parameters: ["network": "ws", "ws-path": "/native"])
        upgrade(raw: raw, policy: policy,
                queue: DispatchQueue(label: "app.hajimi.websocket.self-test")) {
            upgradeResult = $0
            upgraded.signal()
        }
        guard upgraded.wait(timeout: .now() + 2) == .success,
              let upgradeResult else {
            throw NativeOutboundError.protocolError("WebSocket 自检升级超时")
        }
        let transport = try upgradeResult.get()
        defer { transport.cancel() }

        // No application receive is pending here.  The background control
        // pump must still consume the server Ping and send Pong.
        raw.sendServerFrame(opcode: 0x9, payload: pingPayload)
        guard pong.wait(timeout: .now() + 2) == .success else {
            throw NativeOutboundError.protocolError("WebSocket 空闲 Ping/Pong 自检失败")
        }

        let expected = Data("native websocket payload".utf8)
        let received = DispatchSemaphore(value: 0)
        var receivedData: Data?
        var receivedError: Error?
        transport.receive { data, _, error in
            receivedData = data
            receivedError = error
            received.signal()
        }
        raw.sendServerFrame(opcode: 0x2, payload: expected)
        guard received.wait(timeout: .now() + 2) == .success,
              receivedError == nil, receivedData == expected else {
            throw receivedError ?? NativeOutboundError.protocolError("WebSocket 后台接收自检失败")
        }
    }

    static func upgrade(raw: any ByteTransport, policy: ProxyPolicy,
                        queue: DispatchQueue,
                        completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        let value = WebSocketByteTransport(raw: raw)
        let keyData = secureRandom(count: 16)
        let key = keyData.base64EncodedString()
        let host = policy.parameters["ws-host"] ?? policy.host ?? "localhost"
        var path = policy.parameters["ws-path"] ?? "/"
        if !path.hasPrefix("/") { path = "/" + path }
        var headers: [String: String] = [
            "Host": host,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13"
        ]
        for (name, headerValue) in parseHeaders(policy.parameters["ws-headers"]) {
            headers[name] = headerValue
        }
        var request = "GET \(path) HTTP/1.1\r\n"
        for name in headers.keys.sorted() { request += "\(name): \(headers[name]!)\r\n" }
        request += "\r\n"
        raw.send(Data(request.utf8)) { error in
            if let error { raw.cancel(); completion(.failure(error)); return }
            value.reader.readUntil(Data("\r\n\r\n".utf8), maximum: 65_536) { result in
                switch result {
                case .failure(let error): raw.cancel(); completion(.failure(error))
                case .success(let response):
                    let text = String(data: response, encoding: .utf8) ?? ""
                    let lines = text.components(separatedBy: "\r\n")
                    guard let status = lines.first, status.contains(" 101 ") else {
                        raw.cancel()
                        completion(.failure(NativeOutboundError.protocolError("WebSocket 升级失败：\(lines.first ?? "空响应")")))
                        return
                    }
                    var responseHeaders: [String: String] = [:]
                    for line in lines.dropFirst() {
                        guard let colon = line.firstIndex(of: ":") else { continue }
                        responseHeaders[String(line[..<colon]).lowercased()] =
                            line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                    }
                    let acceptSource = Data((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8)
                    let expected = Data(Insecure.SHA1.hash(data: acceptSource)).base64EncodedString()
                    guard responseHeaders["sec-websocket-accept"] == expected else {
                        raw.cancel()
                        completion(.failure(NativeOutboundError.protocolError("WebSocket Accept 校验失败")))
                        return
                    }
                    // Read control frames independently of application data.
                    // A server/CDN may send Ping while the proxied stream is
                    // idle and close peers that do not answer Pong promptly.
                    value.startReceivePump()
                    value.startKeepalive()
                    completion(.success(value))
                }
            }
        }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        let mask = [UInt8](secureRandom(count: 4))
        var frame = Data([0x82])
        if data.count < 126 {
            frame.append(0x80 | UInt8(data.count))
        } else if data.count <= Int(UInt16.max) {
            frame.append(0x80 | 126); append16(UInt16(data.count), to: &frame)
        } else {
            frame.append(0x80 | 127); append64(UInt64(data.count), to: &frame)
        }
        frame.append(contentsOf: mask)
        var payload = [UInt8](data)
        for index in payload.indices { payload[index] ^= mask[index & 3] }
        frame.append(contentsOf: payload)
        enqueue(frame, completion: completion)
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        sendQueue.async {
            self.pendingReceives.append(completion)
            self.drainReceivesLocked()
            self.pumpReceiveLocked()
        }
    }

    func cancel() {
        sendQueue.async {
            let error = NativeOutboundError.connection("WebSocket 已关闭")
            self.terminateLocked(receiveError: error, cancelRaw: true)
        }
    }

    private func startReceivePump() {
        sendQueue.async { self.pumpReceiveLocked() }
    }

    private func pumpReceiveLocked() {
        guard !cancelled, !receiveEnded, !receiveInFlight,
              bufferedReceiveBytes < receiveHighWaterMark else { return }
        receiveInFlight = true
        readFrame { [weak self] data, complete, error in
            self?.sendQueue.async {
                guard let self else { return }
                self.receiveInFlight = false
                guard !self.receiveEnded else { return }
                if let data, !data.isEmpty {
                    self.receivedFrames.append(data)
                    self.bufferedReceiveBytes += data.count
                }
                if complete || error != nil {
                    self.terminateLocked(receiveError: error, cancelRaw: true)
                    return
                }
                self.drainReceivesLocked()
                self.pumpReceiveLocked()
            }
        }
    }

    private func drainReceivesLocked() {
        while pendingReceiveHead < pendingReceives.count {
            let completion = pendingReceives[pendingReceiveHead]
            if receivedFrameHead < receivedFrames.count {
                let data = receivedFrames[receivedFrameHead]
                receivedFrameHead += 1
                bufferedReceiveBytes -= data.count
                pendingReceiveHead += 1
                let noMoreFrames = receivedFrameHead == receivedFrames.count
                completion(data, receiveEnded && noMoreFrames && receiveError == nil, nil)
                compactReceiveQueuesLocked()
                continue
            }
            guard receiveEnded else { break }
            pendingReceiveHead += 1
            completion(nil, true, receiveError)
            compactReceiveQueuesLocked()
        }
    }

    private func compactReceiveQueuesLocked() {
        if receivedFrameHead == receivedFrames.count {
            receivedFrames.removeAll(keepingCapacity: true)
            receivedFrameHead = 0
        } else if receivedFrameHead >= 128,
                  receivedFrameHead * 2 >= receivedFrames.count {
            receivedFrames.removeFirst(receivedFrameHead)
            receivedFrameHead = 0
        }
        if pendingReceiveHead == pendingReceives.count {
            pendingReceives.removeAll(keepingCapacity: true)
            pendingReceiveHead = 0
        } else if pendingReceiveHead >= 128,
                  pendingReceiveHead * 2 >= pendingReceives.count {
            pendingReceives.removeFirst(pendingReceiveHead)
            pendingReceiveHead = 0
        }
    }

    private func readFrame(completion: @escaping (Data?, Bool, Error?) -> Void) {
        reader.readExactly(2) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                completion(nil, true, isCleanByteStreamEOF(error) ? nil : error)
            case .success(let header):
                let opcode = header[0] & 0x0f
                let masked = header[1] & 0x80 != 0
                let shortLength = Int(header[1] & 0x7f)
                self.readLength(shortLength) { lengthResult in
                    switch lengthResult {
                    case .failure(let error): completion(nil, true, error)
                    case .success(let length): self.readPayload(length: length, masked: masked,
                                                                 opcode: opcode, completion: completion)
                    }
                }
            }
        }
    }

    private func readLength(_ value: Int, completion: @escaping (Result<Int, Error>) -> Void) {
        if value < 126 { completion(.success(value)); return }
        let count = value == 126 ? 2 : 8
        reader.readExactly(count) { result in
            completion(result.flatMap { data in
                let length = data.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
                guard length <= 16 * 1024 * 1024 else {
                    return .failure(NativeOutboundError.protocolError("WebSocket 帧过大"))
                }
                return .success(Int(length))
            })
        }
    }

    private func readPayload(length: Int, masked: Bool, opcode: UInt8,
                             completion: @escaping (Data?, Bool, Error?) -> Void) {
        let maskLength = masked ? 4 : 0
        reader.readExactly(maskLength + length) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): completion(nil, true, error)
            case .success(let value):
                self.sendQueue.async { self.lastActivity = Date() }
                var payload = [UInt8](value.dropFirst(maskLength))
                if masked {
                    let mask = [UInt8](value.prefix(4))
                    for index in payload.indices { payload[index] ^= mask[index & 3] }
                }
                switch opcode {
                case 0x8: completion(nil, true, nil)
                case 0x9:
                    self.sendControl(opcode: 0xA, payload: Data(payload)) { _ in
                        self.readFrame(completion: completion)
                    }
                case 0xA: self.readFrame(completion: completion)
                default: completion(Data(payload), false, nil)
                }
            }
        }
    }

    private func sendControl(opcode: UInt8, payload: Data, completion: @escaping (Error?) -> Void) {
        let mask = [UInt8](secureRandom(count: 4))
        var frame = Data([0x80 | opcode, 0x80 | UInt8(min(payload.count, 125))])
        frame.append(contentsOf: mask)
        var bytes = [UInt8](payload.prefix(125))
        for index in bytes.indices { bytes[index] ^= mask[index & 3] }
        frame.append(contentsOf: bytes)
        enqueue(frame, completion: completion)
    }

    private func enqueue(_ frame: Data, completion: @escaping (Error?) -> Void) {
        sendQueue.async {
            guard !self.cancelled else {
                completion(NativeOutboundError.connection("WebSocket 已关闭")); return
            }
            self.pendingWrites.append((frame, completion))
            self.lastActivity = Date()
            nativeDebug("WebSocket queued frame bytes=\(frame.count) pending=\(self.pendingWrites.count - self.pendingWriteHead)")
            self.flushWrites()
        }
    }

    private func flushWrites() {
        guard !cancelled, !writeInFlight,
              pendingWriteHead < pendingWrites.count else { return }
        let item = pendingWrites[pendingWriteHead]
        writeInFlight = true
        nativeDebug("WebSocket sending frame bytes=\(item.0.count)")
        raw.send(item.0) { [weak self] error in
            self?.sendQueue.async {
                guard let self, !self.cancelled else { return }
                self.writeInFlight = false
                nativeDebug("WebSocket frame completion error=\(error?.localizedDescription ?? "none")")
                item.1(error)
                self.pendingWriteHead += 1
                if let error {
                    self.terminateLocked(receiveError: error, cancelRaw: true)
                    return
                }
                if self.pendingWriteHead == self.pendingWrites.count {
                    self.pendingWrites.removeAll(keepingCapacity: true)
                    self.pendingWriteHead = 0
                } else if self.pendingWriteHead >= 128,
                          self.pendingWriteHead * 2 >= self.pendingWrites.count {
                    self.pendingWrites.removeFirst(self.pendingWriteHead)
                    self.pendingWriteHead = 0
                }
                self.flushWrites()
            }
        }
    }

    private func startKeepalive() {
        sendQueue.async {
            guard self.keepaliveTimer == nil, !self.cancelled else { return }
            let timer = DispatchSource.makeTimerSource(queue: self.sendQueue)
            timer.schedule(deadline: .now() + 20, repeating: 20,
                           leeway: .seconds(2))
            timer.setEventHandler { [weak self] in
                guard let self, !self.cancelled,
                      Date().timeIntervalSince(self.lastActivity) >= 18 else { return }
                var timestamp = UInt64(Date().timeIntervalSince1970).bigEndian
                let payload = withUnsafeBytes(of: &timestamp) { Data($0) }
                self.sendControl(opcode: 0x9, payload: payload) { _ in }
            }
            self.keepaliveTimer = timer
            timer.resume()
        }
    }

    private func terminateLocked(receiveError: Error?, cancelRaw: Bool) {
        guard !receiveEnded else { return }
        receiveEnded = true
        self.receiveError = receiveError
        cancelled = true
        keepaliveTimer?.cancel(); keepaliveTimer = nil
        if cancelRaw { raw.cancel() }

        let writeError = receiveError ?? NativeOutboundError.connection("WebSocket 已关闭")
        for index in pendingWriteHead..<pendingWrites.count {
            pendingWrites[index].1(writeError)
        }
        pendingWrites.removeAll(keepingCapacity: false)
        pendingWriteHead = 0
        writeInFlight = false
        drainReceivesLocked()
    }
}

private final class WebSocketSelfTestRawTransport: ByteTransport {
    private typealias ReceiveCompletion = (Data?, Bool, Error?) -> Void

    private let queue = DispatchQueue(label: "app.hajimi.websocket.self-test.raw")
    private let onClientFrame: (UInt8, Data) -> Void
    private var upgraded = false
    private var cancelled = false
    private var incoming: [Data] = []
    private var pendingReceive: ReceiveCompletion?

    init(onClientFrame: @escaping (UInt8, Data) -> Void) {
        self.onClientFrame = onClientFrame
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async {
            guard !self.cancelled else {
                completion(NativeOutboundError.connection("WebSocket 自检流已关闭"))
                return
            }
            if !self.upgraded {
                guard let request = String(data: data, encoding: .utf8),
                      let keyLine = request.components(separatedBy: "\r\n").first(where: {
                          $0.lowercased().hasPrefix("sec-websocket-key:")
                      }),
                      let colon = keyLine.firstIndex(of: ":") else {
                    completion(NativeOutboundError.protocolError("WebSocket 自检请求无效"))
                    return
                }
                let key = keyLine[keyLine.index(after: colon)...]
                    .trimmingCharacters(in: .whitespaces)
                let source = Data((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8)
                let accept = Data(Insecure.SHA1.hash(data: source)).base64EncodedString()
                let response = Data(("HTTP/1.1 101 Switching Protocols\r\n" +
                    "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
                    "Sec-WebSocket-Accept: \(accept)\r\n\r\n").utf8)
                self.upgraded = true
                self.enqueueIncomingLocked(response)
                completion(nil)
                return
            }
            do {
                let frame = try self.decodeClientFrame(data)
                self.onClientFrame(frame.0, frame.1)
                completion(nil)
            } catch { completion(error) }
        }
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async {
            guard !self.cancelled else { completion(nil, true, nil); return }
            if !self.incoming.isEmpty {
                completion(self.incoming.removeFirst(), false, nil)
            } else {
                self.pendingReceive = completion
            }
        }
    }

    func cancel() {
        queue.async {
            guard !self.cancelled else { return }
            self.cancelled = true
            let receive = self.pendingReceive
            self.pendingReceive = nil
            receive?(nil, true, nil)
        }
    }

    func sendServerFrame(opcode: UInt8, payload: Data) {
        queue.async {
            guard !self.cancelled else { return }
            var frame = Data([0x80 | opcode])
            if payload.count < 126 {
                frame.append(UInt8(payload.count))
            } else if payload.count <= Int(UInt16.max) {
                frame.append(126); append16(UInt16(payload.count), to: &frame)
            } else {
                frame.append(127); append64(UInt64(payload.count), to: &frame)
            }
            frame.append(payload)
            self.enqueueIncomingLocked(frame)
        }
    }

    private func enqueueIncomingLocked(_ data: Data) {
        if let receive = pendingReceive {
            pendingReceive = nil
            receive(data, false, nil)
        } else {
            incoming.append(data)
        }
    }

    private func decodeClientFrame(_ data: Data) throws -> (UInt8, Data) {
        guard data.count >= 6 else {
            throw NativeOutboundError.protocolError("WebSocket 自检帧被截断")
        }
        let opcode = data[0] & 0x0f
        guard data[1] & 0x80 != 0 else {
            throw NativeOutboundError.protocolError("WebSocket 客户端帧未掩码")
        }
        var offset = 2
        let shortLength = Int(data[1] & 0x7f)
        let length: Int
        if shortLength < 126 {
            length = shortLength
        } else if shortLength == 126 {
            guard data.count >= offset + 2 else {
                throw NativeOutboundError.protocolError("WebSocket 自检长度被截断")
            }
            length = Int(data[offset]) << 8 | Int(data[offset + 1])
            offset += 2
        } else {
            guard data.count >= offset + 8 else {
                throw NativeOutboundError.protocolError("WebSocket 自检长度被截断")
            }
            let value = data[offset..<(offset + 8)].reduce(UInt64(0)) {
                ($0 << 8) | UInt64($1)
            }
            guard value <= UInt64(Int.max) else {
                throw NativeOutboundError.protocolError("WebSocket 自检帧过大")
            }
            length = Int(value)
            offset += 8
        }
        guard data.count >= offset + 4 + length else {
            throw NativeOutboundError.protocolError("WebSocket 自检负载被截断")
        }
        let mask = [UInt8](data[offset..<(offset + 4)])
        offset += 4
        var payload = [UInt8](data[offset..<(offset + length)])
        for index in payload.indices { payload[index] ^= mask[index & 3] }
        return (opcode, Data(payload))
    }
}

private enum ShadowsocksCipher {
    case aes128GCM
    case aes256GCM
    case chacha20Poly1305

    init?(name: String) {
        switch name.lowercased() {
        case "aes-128-gcm": self = .aes128GCM
        case "aes-256-gcm": self = .aes256GCM
        case "chacha20-ietf-poly1305", "chacha20-poly1305": self = .chacha20Poly1305
        default: return nil
        }
    }

    var keyLength: Int {
        switch self { case .aes128GCM: return 16; case .aes256GCM, .chacha20Poly1305: return 32 }
    }

    func seal(_ plaintext: Data, key: Data, nonce: Data) throws -> Data {
        switch self {
        case .aes128GCM, .aes256GCM:
            return try aesGCMSeal(plaintext, key: key, nonce: nonce)
        case .chacha20Poly1305:
            do {
                let value = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key),
                                                nonce: try ChaChaPoly.Nonce(data: nonce))
                var output = value.ciphertext; output.append(value.tag); return output
            } catch { throw NativeOutboundError.crypto(error.localizedDescription) }
        }
    }

    func open(_ sealed: Data, key: Data, nonce: Data) throws -> Data {
        switch self {
        case .aes128GCM, .aes256GCM:
            return try aesGCMOpen(sealed, key: key, nonce: nonce)
        case .chacha20Poly1305:
            guard sealed.count >= 16 else { throw NativeOutboundError.crypto("Shadowsocks AEAD 数据截断") }
            do {
                let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce),
                                                   ciphertext: sealed.dropLast(16),
                                                   tag: sealed.suffix(16))
                return try ChaChaPoly.open(box, using: SymmetricKey(data: key))
            } catch { throw NativeOutboundError.crypto(error.localizedDescription) }
        }
    }
}

private struct ShadowsocksRCipherSpec {
    let keyLength: Int
    let ivLength = kCCBlockSizeAES128

    init?(name: String) {
        switch name.lowercased() {
        case "aes-128-cfb": keyLength = kCCKeySizeAES128
        case "aes-192-cfb": keyLength = kCCKeySizeAES192
        case "aes-256-cfb": keyLength = kCCKeySizeAES256
        default: return nil
        }
    }
}

private final class AESCFBState {
    private var cryptor: CCCryptorRef?

    init(operation: CCOperation, key: Data, iv: Data) throws {
        var value: CCCryptorRef?
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreateWithMode(operation, CCMode(kCCModeCFB), CCAlgorithm(kCCAlgorithmAES),
                                        CCPadding(ccNoPadding), ivBytes.baseAddress,
                                        keyBytes.baseAddress, key.count, nil, 0, 0,
                                        CCModeOptions(0), &value)
            }
        }
        guard status == kCCSuccess, let value else {
            throw NativeOutboundError.crypto("AES-CFB 初始化失败（\(status)）")
        }
        cryptor = value
    }

    deinit { if let cryptor { CCCryptorRelease(cryptor) } }

    func update(_ data: Data) throws -> Data {
        guard let cryptor else { throw NativeOutboundError.crypto("AES-CFB 状态已关闭") }
        var output = Data(count: data.count + kCCBlockSizeAES128)
        var written = 0
        let status = output.withUnsafeMutableBytes { out in
            data.withUnsafeBytes { input in
                CCCryptorUpdate(cryptor, input.baseAddress, data.count,
                                out.baseAddress, out.count, &written)
            }
        }
        guard status == kCCSuccess else {
            throw NativeOutboundError.crypto("AES-CFB 处理失败（\(status)）")
        }
        output.count = written
        return output
    }
}

private final class ShadowsocksRStream: OutboundByteStream {
    private let transport: any ByteTransport
    private let reader: BufferedByteReader
    private let spec: ShadowsocksRCipherSpec
    private let key: Data
    private let requestIV: Data
    private let encryptor: AESCFBState
    private let targetAddress: Data
    private var decryptor: AESCFBState?
    private var cancelled = false

    init(policy: ProxyPolicy, target: RequestTarget, transport: any ByteTransport) throws {
        guard let cipherName = policy.parameters["cipher"],
              let spec = ShadowsocksRCipherSpec(name: cipherName),
              let password = policy.parameters["password"], !password.isEmpty else {
            throw NativeOutboundError.protocolError("SSR cipher/password 无效")
        }
        guard (policy.parameters["protocol"] ?? "origin").lowercased() == "origin",
              (policy.parameters["obfs"] ?? "plain").lowercased() == "plain" else {
            throw NativeOutboundError.unsupported("SSR 当前只支持 protocol=origin, obfs=plain")
        }
        self.transport = transport; reader = BufferedByteReader(transport); self.spec = spec
        key = shadowsocksMasterKey(password: password, length: spec.keyLength)
        requestIV = secureRandom(count: spec.ivLength)
        encryptor = try AESCFBState(operation: CCOperation(kCCEncrypt), key: key, iv: requestIV)
        targetAddress = try socksProtocolAddress(target.host, port: target.port)
    }

    func start(completion: @escaping (Result<ShadowsocksRStream, Error>) -> Void) {
        do {
            var packet = requestIV; packet.append(try encryptor.update(targetAddress))
            transport.send(packet) { error in
                if let error { self.cancel(); completion(.failure(error)) }
                else { completion(.success(self)) }
            }
        } catch { cancel(); completion(.failure(error)) }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        do { transport.send(try encryptor.update(data), completion: completion) }
        catch { completion(error) }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        if decryptor == nil {
            reader.readExactly(spec.ivLength) { [weak self] result in
                guard let self else { return }
                do {
                    self.decryptor = try AESCFBState(operation: CCOperation(kCCDecrypt),
                                                     key: self.key, iv: result.get())
                    self.receive(maximum: maximum, completion: completion)
                } catch { completion(nil, true, error) }
            }
            return
        }
        reader.readAvailable(maximum: maximum) { [weak self] data, complete, error in
            guard let self else { return }
            do { completion(try data.map { try self.decryptor!.update($0) }, complete, error) }
            catch { completion(nil, true, error) }
        }
    }

    func cancel() { guard !cancelled else { return }; cancelled = true; transport.cancel() }
}

private final class ShadowsocksRDatagramSession: NativeOutboundDatagramSession {
    private let connection: NWConnection
    private let spec: ShadowsocksRCipherSpec
    private let key: Data
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private var ready = false, cancelled = false
    private var pending: [(Data, RequestTarget)] = []

    init(policy: ProxyPolicy, queue: DispatchQueue,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) throws {
        guard let cipherName = policy.parameters["cipher"],
              let spec = ShadowsocksRCipherSpec(name: cipherName),
              let password = policy.parameters["password"],
              let host = policy.host, let port = policy.port,
              (policy.parameters["protocol"] ?? "origin").lowercased() == "origin",
              (policy.parameters["obfs"] ?? "plain").lowercased() == "plain" else {
            throw NativeOutboundError.unsupported("SSR UDP 仅支持 AES-CFB + origin + plain")
        }
        self.spec = spec; key = shadowsocksMasterKey(password: password, length: spec.keyLength)
        receiveHandler = receive; failureHandler = failure
        let parameters = NWParameters.udp
        if !isNativeLoopbackHost(host) { parameters.requiredInterface = OutboundInterfaceBinding.current }
        connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: parameters)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state { self.ready = true; let p = self.pending; self.pending.removeAll(); p.forEach { self.send($0.0, to: $0.1) }; self.receiveNext() }
            if case .failed(let error) = state { self.fail(error) }
        }
        connection.start(queue: queue)
    }

    func send(_ payload: Data, to target: RequestTarget) {
        guard !cancelled else { return }; guard ready else { pending.append((payload, target)); return }
        do {
            let iv = secureRandom(count: spec.ivLength)
            let cryptor = try AESCFBState(operation: CCOperation(kCCEncrypt), key: key, iv: iv)
            var plain = try socksProtocolAddress(target.host, port: target.port); plain.append(payload)
            var packet = iv; packet.append(try cryptor.update(plain))
            connection.send(content: packet, completion: .contentProcessed { [weak self] error in
                if let error { self?.fail(error) }
            })
        } catch { fail(error) }
    }

    func cancel() { cancelled = true; connection.cancel(); pending.removeAll() }

    private func receiveNext() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            do {
                if let error { throw error }
                if let data, data.count > self.spec.ivLength {
                    let iv = Data(data.prefix(self.spec.ivLength))
                    let cryptor = try AESCFBState(operation: CCOperation(kCCDecrypt), key: self.key, iv: iv)
                    let plain = try cryptor.update(Data(data.dropFirst(self.spec.ivLength)))
                    let parsed = try parseNativeSOCKSAddress(plain)
                    self.receiveHandler(parsed.target, parsed.payload)
                }
                self.receiveNext()
            } catch { self.fail(error) }
        }
    }
    private func fail(_ error: Error) { guard !cancelled else { return }; cancelled = true; connection.cancel(); failureHandler(error) }
}

/// VMess/VLESS/Trojan carry UDP packets in authenticated streams. One stream
/// is retained per destination so packet order and protocol framing remain
/// independent between UDP flows.
private final class StreamDatagramSession: NativeOutboundDatagramSession {
    private final class Flow {
        let target: RequestTarget
        var stream: (any OutboundByteStream)?
        var pending: [Data] = []
        var pendingHead = 0
        var pendingBytes = 0
        var connecting = false
        var sending = false
        var retryScheduled = false
        var failures = 0

        init(target: RequestTarget) { self.target = target }

        var pendingCount: Int { pending.count - pendingHead }
    }

    private let policy: ProxyPolicy
    private let queue: DispatchQueue
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private var flows: [String: Flow] = [:]
    private var cancelled = false

    init(policy: ProxyPolicy, queue: DispatchQueue,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) {
        self.policy = policy; self.queue = queue
        receiveHandler = receive; failureHandler = failure
    }

    func send(_ payload: Data, to target: RequestTarget) {
        guard !cancelled else { return }
        let key = "\(target.host.lowercased()):\(target.port)"
        let flow: Flow
        if let current = flows[key] {
            flow = current
        } else {
            flow = Flow(target: target)
            flows[key] = flow
        }
        // A stalled stream must not let a UDP flood grow the Helper without
        // bound.  Datagram traffic may drop under pressure and recover on the
        // next packet, just like a real UDP socket.
        guard flow.pendingCount < 512,
              flow.pendingBytes + payload.count <= 2 * 1_024 * 1_024 else { return }
        flow.pending.append(payload)
        flow.pendingBytes += payload.count
        if flow.stream != nil { flush(flow, key: key) }
        else { connect(flow, key: key) }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        flows.values.forEach { $0.stream?.cancel() }
        flows.removeAll()
    }

    private func connect(_ flow: Flow, key: String) {
        guard !cancelled, flows[key] === flow, flow.stream == nil,
              !flow.connecting, !flow.retryScheduled else { return }
        flow.connecting = true
        NativeOutboundFactory.connect(policy: policy,
            target: RequestTarget(host: flow.target.host, port: flow.target.port,
                                  protocolName: "UDP"),
            queue: queue) { [weak self] result in
                self?.queue.async {
                    guard let self else {
                        if case .success(let stream) = result { stream.cancel() }
                        return
                    }
                    guard !self.cancelled, self.flows[key] === flow else {
                        if case .success(let stream) = result { stream.cancel() }
                        return
                    }
                    flow.connecting = false
                    switch result {
                    case .failure(let error): self.connectionFailed(flow, key: key, error: error)
                    case .success(let stream):
                        flow.failures = 0
                        flow.stream = stream
                        self.flush(flow, key: key)
                        self.receive(flow, stream: stream, key: key)
                    }
                }
            }
    }

    private func flush(_ flow: Flow, key: String) {
        guard !cancelled, flows[key] === flow, let stream = flow.stream,
              !flow.sending, flow.pendingHead < flow.pending.count else { return }
        let payload = flow.pending[flow.pendingHead]
        flow.sending = true
        stream.send(payload) { [weak self, weak stream] error in
            self?.queue.async {
                guard let self, let stream, !self.cancelled,
                      self.flows[key] === flow, flow.stream === stream else { return }
                flow.sending = false
                if let error {
                    self.streamFailed(flow, stream: stream, key: key, error: error)
                    return
                }
                flow.failures = 0
                flow.pendingBytes -= payload.count
                flow.pendingHead += 1
                self.compactPending(flow)
                self.flush(flow, key: key)
            }
        }
    }

    private func receive(_ flow: Flow, stream: any OutboundByteStream, key: String) {
        stream.receive(maximum: 65_535) { [weak self, weak stream] data, complete, error in
            self?.queue.async {
                guard let self, let stream, !self.cancelled,
                      self.flows[key] === flow, flow.stream === stream else { return }
                if let error {
                    self.streamFailed(flow, stream: stream, key: key, error: error)
                    return
                }
                if let data, !data.isEmpty { self.receiveHandler(flow.target, data) }
                if complete { self.streamEnded(flow, stream: stream, key: key) }
                else { self.receive(flow, stream: stream, key: key) }
            }
        }
    }

    private func streamFailed(_ flow: Flow, stream: any OutboundByteStream,
                              key: String, error: Error) {
        guard flows[key] === flow, flow.stream === stream else { return }
        stream.cancel()
        flow.stream = nil
        flow.sending = false
        flow.failures += 1
        if flow.pendingCount > 0 { scheduleReconnect(flow, key: key, error: error) }
        else { flows.removeValue(forKey: key) }
    }

    private func streamEnded(_ flow: Flow, stream: any OutboundByteStream, key: String) {
        guard flows[key] === flow, flow.stream === stream else { return }
        stream.cancel()
        flow.stream = nil
        flow.sending = false
        if flow.pendingCount > 0 {
            scheduleReconnect(flow, key: key,
                              error: NativeOutboundError.connection("UDP 承载流已关闭"))
        } else {
            flows.removeValue(forKey: key)
        }
    }

    private func connectionFailed(_ flow: Flow, key: String, error: Error) {
        flow.failures += 1
        scheduleReconnect(flow, key: key, error: error)
    }

    private func scheduleReconnect(_ flow: Flow, key: String, error: Error) {
        guard !cancelled, flows[key] === flow else { return }
        guard flow.failures < 6 else {
            flows.removeValue(forKey: key)
            flow.stream?.cancel()
            failureHandler(error)
            return
        }
        guard flow.pendingCount > 0, !flow.retryScheduled else {
            if flow.pendingCount == 0 { flows.removeValue(forKey: key) }
            return
        }
        flow.retryScheduled = true
        let delay = min(2.0, 0.15 * pow(2.0, Double(max(0, flow.failures - 1))))
        queue.asyncAfter(deadline: .now() + delay) { [weak self, weak flow] in
            guard let self, let flow, !self.cancelled,
                  self.flows[key] === flow else { return }
            flow.retryScheduled = false
            self.connect(flow, key: key)
        }
    }

    private func compactPending(_ flow: Flow) {
        guard flow.pendingHead > 0 else { return }
        if flow.pendingHead == flow.pending.count {
            flow.pending.removeAll(keepingCapacity: true)
            flow.pendingHead = 0
        } else if flow.pendingHead >= 128,
                  flow.pendingHead * 2 >= flow.pending.count {
            flow.pending.removeFirst(flow.pendingHead)
            flow.pendingHead = 0
        }
    }
}

/// SIP003 Shadowsocks AEAD UDP. Each UDP packet has an independent random
/// salt and subkey, followed by one authenticated address+payload record.
private final class ShadowsocksAEADDatagramSession: NativeOutboundDatagramSession {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let cipher: ShadowsocksCipher
    private let masterKey: Data
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private var ready = false
    private var cancelled = false
    private var pending: [(Data, RequestTarget)] = []

    init(policy: ProxyPolicy, queue: DispatchQueue,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void) throws {
        guard let cipherName = policy.parameters["cipher"],
              let cipher = ShadowsocksCipher(name: cipherName),
              let password = policy.parameters["password"], !password.isEmpty,
              let host = policy.host, let port = policy.port,
              let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw NativeOutboundError.protocolError("Shadowsocks UDP 参数无效")
        }
        self.queue = queue
        self.cipher = cipher
        masterKey = shadowsocksMasterKey(password: password, length: cipher.keyLength)
        receiveHandler = receive
        failureHandler = failure
        let parameters = NWParameters.udp
        if !isNativeLoopbackHost(host) { parameters.requiredInterface = OutboundInterfaceBinding.current }
        connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: parameters)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !self.cancelled else { return }
            switch state {
            case .ready:
                self.ready = true
                let values = self.pending; self.pending.removeAll()
                values.forEach { self.send($0.0, to: $0.1) }
                self.receiveNext()
            case .failed(let error): self.fail(error)
            default: break
            }
        }
        connection.start(queue: queue)
    }

    func send(_ payload: Data, to target: RequestTarget) {
        guard !cancelled else { return }
        guard ready else { pending.append((payload, target)); return }
        do {
            var plaintext = try socksProtocolAddress(target.host, port: target.port)
            plaintext.append(payload)
            let salt = secureRandom(count: cipher.keyLength)
            let key = shadowsocksSubkey(masterKey: masterKey, salt: salt, length: cipher.keyLength)
            var packet = salt
            packet.append(try cipher.seal(plaintext, key: key,
                                          nonce: Data(repeating: 0, count: 12)))
            connection.send(content: packet, completion: .contentProcessed { [weak self] error in
                if let error { self?.fail(error) }
            })
        } catch { fail(error) }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true; pending.removeAll(); connection.cancel()
    }

    private func receiveNext() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let error { self.fail(error); return }
            if let data, !data.isEmpty {
                do {
                    guard data.count >= self.cipher.keyLength + 16 else {
                        throw NativeOutboundError.protocolError("Shadowsocks UDP 响应截断")
                    }
                    let salt = Data(data.prefix(self.cipher.keyLength))
                    let key = shadowsocksSubkey(masterKey: self.masterKey, salt: salt,
                                                length: self.cipher.keyLength)
                    let plaintext = try self.cipher.open(Data(data.dropFirst(self.cipher.keyLength)),
                                                         key: key,
                                                         nonce: Data(repeating: 0, count: 12))
                    let parsed = try parseNativeSOCKSAddress(plaintext)
                    self.receiveHandler(parsed.target, parsed.payload)
                } catch { self.fail(error); return }
            }
            self.receiveNext()
        }
    }

    private func fail(_ error: Error) {
        guard !cancelled else { return }
        cancelled = true; connection.cancel(); failureHandler(error)
    }
}

private final class ShadowsocksAEADStream: OutboundByteStream {
    private let transport: any ByteTransport
    private let reader: BufferedByteReader
    private let cipher: ShadowsocksCipher
    private let masterKey: Data
    private let requestSalt: Data
    private let requestKey: Data
    private let targetAddress: Data
    private var responseKey: Data?
    private var requestCounter: UInt64 = 0
    private var responseCounter: UInt64 = 0
    private var receiveBuffer = Data()
    private var cancelled = false

    init(policy: ProxyPolicy, target: RequestTarget, transport: any ByteTransport) throws {
        guard let name = policy.parameters["cipher"], let cipher = ShadowsocksCipher(name: name),
              let password = policy.parameters["password"], !password.isEmpty else {
            throw NativeOutboundError.protocolError("Shadowsocks AEAD 参数无效")
        }
        self.transport = transport
        reader = BufferedByteReader(transport)
        self.cipher = cipher
        masterKey = shadowsocksMasterKey(password: password, length: cipher.keyLength)
        requestSalt = secureRandom(count: cipher.keyLength)
        requestKey = shadowsocksSubkey(masterKey: masterKey, salt: requestSalt,
                                       length: cipher.keyLength)
        targetAddress = try socksProtocolAddress(target.host, port: target.port)
    }

    func start(completion: @escaping (Result<ShadowsocksAEADStream, Error>) -> Void) {
        do {
            var output = requestSalt
            output.append(try encrypt(targetAddress))
            transport.send(output) { error in
                if let error { self.cancel(); completion(.failure(error)) }
                else { nativeDebug("Shadowsocks AEAD target sent"); completion(.success(self)) }
            }
        } catch { cancel(); completion(.failure(error)) }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !cancelled else {
            completion(NativeOutboundError.connection("连接已关闭")); return
        }
        guard !data.isEmpty else { completion(nil); return }
        do {
            var output = Data(); var offset = 0
            while offset < data.count {
                let count = min(0x3fff, data.count - offset)
                output.append(try encrypt(Data(data[offset..<(offset + count)])))
                offset += count
            }
            transport.send(output, completion: completion)
        } catch { completion(error) }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        if !receiveBuffer.isEmpty {
            let count = min(maximum, receiveBuffer.count)
            let value = Data(receiveBuffer.prefix(count)); receiveBuffer.removeFirst(count)
            completion(value, false, nil); return
        }
        if responseKey == nil {
            reader.readExactly(cipher.keyLength) { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error): completion(nil, true, error)
                case .success(let salt):
                    self.responseKey = shadowsocksSubkey(masterKey: self.masterKey, salt: salt,
                                                         length: self.cipher.keyLength)
                    self.receive(maximum: maximum, completion: completion)
                }
            }
            return
        }
        reader.readExactly(18) { [weak self] lengthResult in
            guard let self else { return }
            switch lengthResult {
            case .failure(let error):
                completion(nil, true, isCleanByteStreamEOF(error) ? nil : error)
            case .success(let encryptedLength):
                do {
                    let lengthData = try self.decrypt(encryptedLength)
                    guard lengthData.count == 2 else {
                        throw NativeOutboundError.protocolError("Shadowsocks 长度块无效")
                    }
                    let length = Int(read16(lengthData))
                    guard length <= 0x3fff else {
                        throw NativeOutboundError.protocolError("Shadowsocks 数据块过大")
                    }
                    self.reader.readExactly(length + 16) { payloadResult in
                        switch payloadResult {
                        case .failure(let error): completion(nil, true, error)
                        case .success(let encrypted):
                            do {
                                self.receiveBuffer = try self.decrypt(encrypted)
                                self.receive(maximum: maximum, completion: completion)
                            } catch { completion(nil, true, error) }
                        }
                    }
                } catch { completion(nil, true, error) }
            }
        }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true; transport.cancel()
    }

    private func encrypt(_ payload: Data) throws -> Data {
        var length = Data(); append16(UInt16(payload.count), to: &length)
        let encryptedLength = try cipher.seal(length, key: requestKey,
                                              nonce: ssNonce(requestCounter))
        requestCounter &+= 1
        let encryptedPayload = try cipher.seal(payload, key: requestKey,
                                               nonce: ssNonce(requestCounter))
        requestCounter &+= 1
        return encryptedLength + encryptedPayload
    }

    private func decrypt(_ sealed: Data) throws -> Data {
        guard let responseKey else { throw NativeOutboundError.crypto("Shadowsocks 响应密钥未初始化") }
        let value = try cipher.open(sealed, key: responseKey, nonce: ssNonce(responseCounter))
        responseCounter &+= 1
        return value
    }
}

/// VMess and VLESS request commands. Mux is signalled here rather than by
/// naming the carrier destination, which is why these two protocols need a
/// dedicated code path to carry Mux.Cool.
enum VMessRequestCommand: UInt8 {
    case tcp = 0x01
    case udp = 0x02
    case mux = 0x03
}

/// Builds a VLESS request header.
///
/// Both Xray's VLESS and VMess encoders skip the address and port entirely when
/// the command is Mux — the carrier has no single destination, the logical
/// streams inside it do. Emitting a placeholder address instead would desync
/// the server's parser.
func vlessRequestHeader(uuid: UUID, target: RequestTarget,
                        command: VMessRequestCommand,
                        flow: String? = nil) throws -> Data {
    return try NativeProtocolCodec.vless(uuid: uuid, target: target, command: command.rawValue,
        addons: flow.map(VLESSVisionAddons.recognizes) == true ? VLESSVisionAddons.requestBytes : Data())
}

private final class VLESSStream: OutboundByteStream {
    private let transport: any ByteTransport
    private let reader: BufferedByteReader
    private let requestHeader: Data
    private var responseHeaderRead = false
    private var cancelled = false
    private let isUDP: Bool
    private let visionEncoder: VLESSVisionEncoder?
    private let visionDecoder: VLESSVisionDecoder?
    private var visionReceiveBuffer = Data()

    init(policy: ProxyPolicy, target: RequestTarget, transport: any ByteTransport) throws {
        guard let rawUUID = policy.parameters["uuid"] ?? policy.parameters["username"],
              let uuid = UUID(uuidString: rawUUID) else {
            throw NativeOutboundError.protocolError("VLESS UUID 无效")
        }
        self.transport = transport
        isUDP = target.protocolName == "UDP"
        let flow = (policy.parameters["flow"] ?? "").lowercased()
        if VLESSVisionAddons.recognizes(flow) {
            guard !isUDP else {
                throw NativeOutboundError.unsupported("VLESS Vision 不直接承载 UDP；请使用 XUDP 或普通 VLESS UDP")
            }
            guard transport is any VisionDirectByteTransport else {
                throw NativeOutboundError.unsupported("VLESS Vision direct-copy 需要 REALITY 原始 TCP 承载")
            }
            var tuple = uuid.uuid
            let uuidBytes = withUnsafeBytes(of: &tuple) { Data($0) }
            let traffic = VLESSVisionTrafficState()
            // XUDP uses command=mux but its contents are datagrams rather than
            // an inner TLS stream, so it must stay in the framed Vision body.
            visionEncoder = VLESSVisionEncoder(
                uuid: uuidBytes, traffic: traffic,
                canDirect: !MuxApplicability.isCarrierTarget(target))
            visionDecoder = VLESSVisionDecoder(uuid: uuidBytes, traffic: traffic)
        } else {
            visionEncoder = nil; visionDecoder = nil
        }
        reader = BufferedByteReader(transport)
        let command: VMessRequestCommand = MuxApplicability.isCarrierTarget(target)
            ? .mux : (isUDP ? .udp : .tcp)
        requestHeader = try vlessRequestHeader(uuid: uuid, target: target,
                                               command: command, flow: flow)
    }

    func start(completion: @escaping (Result<VLESSStream, Error>) -> Void) {
        var firstFlight = requestHeader
        if let visionEncoder { firstFlight.append(visionEncoder.initialPaddingFrame()) }
        transport.send(firstFlight) { error in
            if let error { self.cancel(); completion(.failure(error)) }
            else { nativeDebug("VLESS request header sent"); completion(.success(self)) }
        }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !cancelled else {
            completion(NativeOutboundError.connection("连接已关闭")); return
        }
        if let visionEncoder {
            let encoded = visionEncoder.encode(data)
            transport.send(encoded.bytes) { error in
                if error == nil, encoded.switchesToDirectAfterWrite {
                    (self.transport as? any VisionDirectByteTransport)?.enableVisionDirectWrite()
                }
                completion(error)
            }
        } else if isUDP {
            guard data.count <= Int(UInt16.max) else { completion(NativeOutboundError.protocolError("VLESS UDP 数据报过大")); return }
            var framed = Data(); append16(UInt16(data.count), to: &framed); framed.append(data)
            transport.send(framed, completion: completion)
        } else { transport.send(data, completion: completion) }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        guard responseHeaderRead else {
            reader.readExactly(2) { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error): completion(nil, true, error)
                case .success(let header):
                    guard header[0] == 0 else {
                        completion(nil, true,
                                   NativeOutboundError.protocolError("VLESS 响应版本无效"))
                        return
                    }
                    self.reader.readExactly(Int(header[1])) { addonResult in
                        switch addonResult {
                        case .failure(let error): completion(nil, true, error)
                        case .success:
                            self.responseHeaderRead = true
                            self.receive(maximum: maximum, completion: completion)
                        }
                    }
                }
            }
            return
        }
        if let visionDecoder {
            if !visionReceiveBuffer.isEmpty {
                let count = min(maximum, visionReceiveBuffer.count)
                let value = Data(visionReceiveBuffer.prefix(count))
                visionReceiveBuffer.removeFirst(count)
                completion(value, false, nil); return
            }
            reader.readAvailable(maximum: max(maximum, 65_536)) { [weak self] data, complete, error in
                guard let self else { return }
                if let error { completion(nil, true, error); return }
                guard let data, !data.isEmpty else { completion(nil, complete, nil); return }
                do {
                    let decoded = try visionDecoder.feed(data)
                    if decoded.switchesToDirect {
                        (self.transport as? any VisionDirectByteTransport)?.enableVisionDirectRead()
                    }
                    for chunk in decoded.chunks { self.visionReceiveBuffer.append(chunk) }
                    self.receive(maximum: maximum, completion: completion)
                } catch { completion(nil, true, error) }
            }
        } else if isUDP {
            reader.readExactly(2) { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error):
                    completion(nil, true, isCleanByteStreamEOF(error) ? nil : error)
                case .success(let length): self.reader.readExactly(Int(read16(length))) {
                    switch $0 { case .success(let data): completion(data, false, nil)
                    case .failure(let error): completion(nil, true, error) }
                }
                }
            }
        } else { reader.readAvailable(maximum: maximum, completion: completion) }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true; transport.cancel()
    }
}

private final class TrojanStream: OutboundByteStream {
    private let transport: any ByteTransport
    private let reader: BufferedByteReader
    private let requestHeader: Data
    private var cancelled = false
    private let isUDP: Bool
    private let udpAddress: Data

    init(policy: ProxyPolicy, target: RequestTarget, transport: any ByteTransport) throws {
        guard let password = policy.parameters["password"], !password.isEmpty else {
            throw NativeOutboundError.protocolError("Trojan 密码为空")
        }
        self.transport = transport
        isUDP = target.protocolName == "UDP"
        udpAddress = try socksProtocolAddress(target.host, port: target.port)
        reader = BufferedByteReader(transport)
        requestHeader = try NativeProtocolCodec.trojan(digest: sha224Hex(password), target: target, udp: isUDP)
    }

    func start(completion: @escaping (Result<TrojanStream, Error>) -> Void) {
        transport.send(requestHeader) { error in
            if let error { self.cancel(); completion(.failure(error)) }
            else { nativeDebug("Trojan request header sent"); completion(.success(self)) }
        }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !cancelled else {
            completion(NativeOutboundError.connection("连接已关闭")); return
        }
        if isUDP {
            guard data.count <= Int(UInt16.max) else { completion(NativeOutboundError.protocolError("Trojan UDP 数据报过大")); return }
            var framed = udpAddress; append16(UInt16(data.count), to: &framed)
            framed.append(contentsOf: [0x0d, 0x0a]); framed.append(data)
            transport.send(framed, completion: completion)
        } else { transport.send(data, completion: completion) }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        // Trojan UDP responses are address + length + CRLF + payload. The
        // destination is fixed for this retained stream, so its address size
        // is known and can be authenticated then discarded.
        if isUDP {
            reader.readExactly(udpAddress.count + 4) { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error):
                    completion(nil, true, isCleanByteStreamEOF(error) ? nil : error)
                case .success(let header):
                    let lengthOffset = self.udpAddress.count
                    let count = Int(UInt16(header[lengthOffset]) << 8 | UInt16(header[lengthOffset + 1]))
                    guard header.suffix(2) == Data([0x0d, 0x0a]) else { completion(nil, true, NativeOutboundError.protocolError("Trojan UDP 帧无效")); return }
                    self.reader.readExactly(count) { switch $0 {
                    case .success(let data): completion(data, false, nil)
                    case .failure(let error): completion(nil, true, error) } }
                }
            }
        } else { reader.readAvailable(maximum: maximum, completion: completion) }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true; transport.cancel()
    }
}

/// Builds the plaintext VMess command block that is later AEAD-sealed.
///
/// The FNV1a checksum covers everything up to and including the padding, so the
/// layout has to match Xray byte for byte — a misplaced field does not fail
/// loudly, it just fails the server's checksum.
func vmessCommandBlock(requestBodyIV: Data, requestBodyKey: Data,
                       responseVerification: UInt8, paddingLength: Int,
                       target: RequestTarget, command: VMessRequestCommand) throws -> Data {
    var block = Data([1])
    block.append(requestBodyIV); block.append(requestBodyKey)
    block.append(responseVerification)
    block.append(0x01) // chunk stream
    block.append(UInt8(paddingLength << 4) | 0x03) // AES-128-GCM
    block.append(0) // reserved
    block.append(command.rawValue)
    if command != .mux {
        append16(target.port, to: &block)
        block.append(try vmessAddress(target.host))
    }
    block.append(secureRandom(count: paddingLength))
    append32(fnv1a(block), to: &block)
    return block
}

private final class VMessAEADStream: OutboundByteStream {
    private let transport: any ByteTransport
    private let reader: BufferedByteReader
    private let requestBodyIV: Data
    private let requestBodyKey: Data
    private let responseBodyIV: Data
    private let responseBodyKey: Data
    private let responseVerification: UInt8
    private let requestHeader: Data
    private var requestCounter: UInt16 = 0
    private var responseCounter: UInt16 = 0
    private var responseHeaderRead = false
    private var receiveBuffer = Data()
    private var cancelled = false

    init(policy: ProxyPolicy, target: RequestTarget, transport: any ByteTransport) throws {
        self.transport = transport
        reader = BufferedByteReader(transport)
        guard let rawUUID = policy.parameters["uuid"] ?? policy.parameters["username"],
              let uuid = UUID(uuidString: rawUUID) else {
            throw NativeOutboundError.protocolError("VMess UUID 无效")
        }
        requestBodyIV = secureRandom(count: 16)
        requestBodyKey = secureRandom(count: 16)
        responseVerification = secureRandom(count: 1).first!
        responseBodyKey = Data(SHA256.hash(data: requestBodyKey).prefix(16))
        responseBodyIV = Data(SHA256.hash(data: requestBodyIV).prefix(16))

        let requestCommand: VMessRequestCommand = MuxApplicability.isCarrierTarget(target)
            ? .mux : (target.protocolName == "UDP" ? .udp : .tcp)
        let command = try vmessCommandBlock(requestBodyIV: requestBodyIV,
                                            requestBodyKey: requestBodyKey,
                                            responseVerification: responseVerification,
                                            paddingLength: Int.random(in: 0..<16),
                                            target: target, command: requestCommand)

        var uuidTuple = uuid.uuid
        let uuidData = withUnsafeBytes(of: &uuidTuple) { Data($0) }
        var commandKeyInput = uuidData
        commandKeyInput.append(Data("c48619fe-8f02-49e0-b9e9-edf763e17e21".utf8))
        let commandKey = Data(Insecure.MD5.hash(data: commandKeyInput))
        requestHeader = try sealHeader(command, commandKey: commandKey)
    }

    func start(completion: @escaping (Result<VMessAEADStream, Error>) -> Void) {
        nativeDebug("sending VMess request header bytes=\(requestHeader.count)")
        transport.send(requestHeader) { error in
            if let error { self.cancel(); completion(.failure(error)) }
            else { nativeDebug("VMess request header sent"); completion(.success(self)) }
        }
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !cancelled else {
            completion(NativeOutboundError.connection("连接已关闭")); return
        }
        do {
            var output = Data(); var offset = 0
            while offset < data.count {
                let count = min(16_368, data.count - offset)
                let chunk = Data(data[offset..<(offset + count)])
                let nonce = bodyNonce(counter: requestCounter, iv: requestBodyIV)
                let sealed = try aesGCMSeal(chunk, key: requestBodyKey, nonce: nonce)
                append16(UInt16(sealed.count), to: &output)
                output.append(sealed)
                requestCounter &+= 1; offset += count
            }
            nativeDebug("VMess body send plain=\(data.count) wire=\(output.count)")
            transport.send(output, completion: completion)
        } catch { completion(error) }
    }

    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        if !receiveBuffer.isEmpty {
            let count = min(maximum, receiveBuffer.count)
            let value = Data(receiveBuffer.prefix(count)); receiveBuffer.removeFirst(count)
            completion(value, false, nil); return
        }
        guard responseHeaderRead else {
            readResponseHeader { [weak self] result in
                switch result {
                case .failure(let error): completion(nil, true, error)
                case .success: self?.receive(maximum: maximum, completion: completion)
                }
            }
            return
        }
        reader.readExactly(2) { [weak self] lengthResult in
            guard let self else { return }
            switch lengthResult {
            case .failure(let error):
                completion(nil, true, isCleanByteStreamEOF(error) ? nil : error)
            case .success(let lengthData):
                let size = Int(read16(lengthData))
                guard size >= 16, size <= 17 * 1024 else {
                    completion(nil, true, NativeOutboundError.protocolError("VMess 数据块长度无效")); return
                }
                self.reader.readExactly(size) { encryptedResult in
                    switch encryptedResult {
                    case .failure(let error): completion(nil, true, error)
                    case .success(let encrypted):
                        do {
                            let nonce = bodyNonce(counter: self.responseCounter, iv: self.responseBodyIV)
                            self.responseCounter &+= 1
                            self.receiveBuffer = try aesGCMOpen(encrypted,
                                                               key: self.responseBodyKey, nonce: nonce)
                            self.receive(maximum: maximum, completion: completion)
                        } catch { completion(nil, true, error) }
                    }
                }
            }
        }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true; transport.cancel()
    }

    private func readResponseHeader(completion: @escaping (Result<Void, Error>) -> Void) {
        nativeDebug("VMess waiting response header")
        reader.readExactly(18) { [weak self] lengthResult in
            guard let self else { return }
            switch lengthResult {
            case .failure(let error): completion(.failure(error))
            case .success(let encryptedLength):
                do {
                    let lengthKey = Data(vmessKDF(key: self.responseBodyKey,
                                                  path: [Data("AEAD Resp Header Len Key".utf8)]).prefix(16))
                    let lengthIV = Data(vmessKDF(key: self.responseBodyIV,
                                                 path: [Data("AEAD Resp Header Len IV".utf8)]).prefix(12))
                    let plainLength = try aesGCMOpen(encryptedLength, key: lengthKey, nonce: lengthIV)
                    guard plainLength.count == 2 else {
                        throw NativeOutboundError.protocolError("VMess 响应头长度无效")
                    }
                    let size = Int(read16(plainLength))
                    guard size >= 4, size <= 4_096 else {
                        throw NativeOutboundError.protocolError("VMess 响应头过大")
                    }
                    self.reader.readExactly(size + 16) { payloadResult in
                        switch payloadResult {
                        case .failure(let error): completion(.failure(error))
                        case .success(let encryptedPayload):
                            do {
                                let key = Data(vmessKDF(key: self.responseBodyKey,
                                                       path: [Data("AEAD Resp Header Key".utf8)]).prefix(16))
                                let iv = Data(vmessKDF(key: self.responseBodyIV,
                                                      path: [Data("AEAD Resp Header IV".utf8)]).prefix(12))
                                let payload = try aesGCMOpen(encryptedPayload, key: key, nonce: iv)
                                guard payload.count >= 4, payload[0] == self.responseVerification,
                                      payload[2] == 0 else {
                                    throw NativeOutboundError.protocolError("VMess 响应校验失败")
                                }
                                self.responseHeaderRead = true
                                completion(.success(()))
                            } catch { completion(.failure(error)) }
                        }
                    }
                } catch { completion(.failure(error)) }
            }
        }
    }
}

func nativeDebug(_ value: @autoclosure () -> String) {
    guard ProcessInfo.processInfo.environment["HAJIMI_NATIVE_DEBUG"] == "1" else { return }
    FileHandle.standardError.write(Data(("[HajimiNative] " + value() + "\n").utf8))
}

private func sealHeader(_ command: Data, commandKey: Data) throws -> Data {
    var authPlain = Data(); append64(UInt64(Date().timeIntervalSince1970), to: &authPlain)
    authPlain.append(secureRandom(count: 4)); append32(crc32(authPlain), to: &authPlain)
    let authKey = Data(vmessKDF(key: commandKey,
                                path: [Data("AES Auth ID Encryption".utf8)]).prefix(16))
    let authID = try aesECBEncryptBlock(authPlain, key: authKey)
    let connectionNonce = secureRandom(count: 8)
    let lengthKey = Data(vmessKDF(key: commandKey, path: [
        Data("VMess Header AEAD Key_Length".utf8), authID, connectionNonce
    ]).prefix(16))
    let lengthIV = Data(vmessKDF(key: commandKey, path: [
        Data("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce
    ]).prefix(12))
    var serializedLength = Data(); append16(UInt16(command.count), to: &serializedLength)
    let encryptedLength = try aesGCMSeal(serializedLength, key: lengthKey,
                                         nonce: lengthIV, authenticatedData: authID)
    let payloadKey = Data(vmessKDF(key: commandKey, path: [
        Data("VMess Header AEAD Key".utf8), authID, connectionNonce
    ]).prefix(16))
    let payloadIV = Data(vmessKDF(key: commandKey, path: [
        Data("VMess Header AEAD Nonce".utf8), authID, connectionNonce
    ]).prefix(12))
    let encryptedPayload = try aesGCMSeal(command, key: payloadKey, nonce: payloadIV,
                                          authenticatedData: authID)
    var output = authID; output.append(encryptedLength); output.append(connectionNonce)
    output.append(encryptedPayload)
    return output
}

private func vmessAddress(_ host: String) throws -> Data {
    var v4 = in_addr()
    if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
        var output = Data([1]); withUnsafeBytes(of: &v4) { output.append(contentsOf: $0) }
        return output
    }
    var v6 = in6_addr()
    if host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
        var output = Data([3]); withUnsafeBytes(of: &v6) { output.append(contentsOf: $0) }
        return output
    }
    let domain = Data(host.utf8)
    guard !domain.isEmpty, domain.count <= 255 else {
        throw NativeOutboundError.protocolError("VMess 目标域名长度无效")
    }
    var output = Data([2, UInt8(domain.count)]); output.append(domain)
    return output
}

private func socksProtocolAddress(_ host: String, port: UInt16) throws -> Data {
    var v4 = in_addr()
    var output = Data()
    if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
        output.append(1); withUnsafeBytes(of: &v4) { output.append(contentsOf: $0) }
    } else {
        var v6 = in6_addr()
        if host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            output.append(4); withUnsafeBytes(of: &v6) { output.append(contentsOf: $0) }
        } else {
            let domain = Data(host.utf8)
            guard !domain.isEmpty, domain.count <= 255 else {
                throw NativeOutboundError.protocolError("目标域名长度无效")
            }
            output.append(3); output.append(UInt8(domain.count)); output.append(domain)
        }
    }
    append16(port, to: &output)
    return output
}

private func isNativeLoopbackHost(_ host: String) -> Bool {
    let value = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
    return value == "localhost" || value == "::1" || value.hasPrefix("127.")
}

private func parseNativeSOCKSAddress(_ data: Data) throws
    -> (target: RequestTarget, payload: Data) {
    guard let type = data.first else {
        throw NativeOutboundError.protocolError("Shadowsocks UDP 地址为空")
    }
    let host: String
    let addressEnd: Int
    switch type {
    case 1:
        guard data.count >= 7 else { throw NativeOutboundError.protocolError("IPv4 地址截断") }
        host = data[1..<5].map(String.init).joined(separator: ".")
        addressEnd = 5
    case 3:
        guard data.count >= 2 else { throw NativeOutboundError.protocolError("域名地址截断") }
        let count = Int(data[1])
        guard data.count >= 2 + count + 2,
              let value = String(data: data[2..<(2 + count)], encoding: .utf8) else {
            throw NativeOutboundError.protocolError("域名地址无效")
        }
        host = value; addressEnd = 2 + count
    case 4:
        guard data.count >= 19 else { throw NativeOutboundError.protocolError("IPv6 地址截断") }
        var address = in6_addr()
        withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: data[1..<17]) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else {
            throw NativeOutboundError.protocolError("IPv6 地址无效")
        }
        host = String(cString: buffer); addressEnd = 17
    default:
        throw NativeOutboundError.protocolError("Shadowsocks UDP 地址类型无效")
    }
    guard data.count >= addressEnd + 2 else {
        throw NativeOutboundError.protocolError("Shadowsocks UDP 端口截断")
    }
    let port = UInt16(data[addressEnd]) << 8 | UInt16(data[addressEnd + 1])
    return (RequestTarget(host: host, port: port, protocolName: "UDP"),
            Data(data.dropFirst(addressEnd + 2)))
}

private func sha224Hex(_ value: String) -> String {
    let input = Data(value.utf8)
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
    input.withUnsafeBytes { raw in
        _ = CC_SHA224(raw.baseAddress, CC_LONG(input.count), &digest)
    }
    return digest.map { String(format: "%02x", $0) }.joined()
}

private func shadowsocksMasterKey(password: String, length: Int) -> Data {
    let passwordData = Data(password.utf8)
    var output = Data(); var previous = Data()
    while output.count < length {
        previous = Data(Insecure.MD5.hash(data: previous + passwordData))
        output.append(previous)
    }
    return Data(output.prefix(length))
}

private func shadowsocksSubkey(masterKey: Data, salt: Data, length: Int) -> Data {
    let prk = Data(HMAC<Insecure.SHA1>.authenticationCode(for: masterKey,
                                                          using: SymmetricKey(data: salt)))
    var input = Data("ss-subkey".utf8); input.append(1)
    let block = Data(HMAC<Insecure.SHA1>.authenticationCode(for: input,
                                                             using: SymmetricKey(data: prk)))
    return Data(block.prefix(length))
}

private func ssNonce(_ counter: UInt64) -> Data {
    var nonce = Data(repeating: 0, count: 12)
    for index in 0..<8 { nonce[index] = UInt8((counter >> UInt64(index * 8)) & 0xff) }
    return nonce
}

private func bodyNonce(counter: UInt16, iv: Data) -> Data {
    var result = Data(); append16(counter, to: &result); result.append(iv[2..<12])
    return result
}

private func aesGCMSeal(_ plaintext: Data, key: Data, nonce: Data,
                        authenticatedData: Data = Data()) throws -> Data {
    do {
        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key),
                                      nonce: try AES.GCM.Nonce(data: nonce),
                                      authenticating: authenticatedData)
        var output = sealed.ciphertext; output.append(sealed.tag); return output
    } catch { throw NativeOutboundError.crypto(error.localizedDescription) }
}

private func aesGCMOpen(_ sealed: Data, key: Data, nonce: Data,
                        authenticatedData: Data = Data()) throws -> Data {
    guard sealed.count >= 16 else { throw NativeOutboundError.crypto("AEAD 数据被截断") }
    do {
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                                        ciphertext: sealed.dropLast(16), tag: sealed.suffix(16))
        return try AES.GCM.open(box, using: SymmetricKey(data: key),
                                authenticating: authenticatedData)
    } catch { throw NativeOutboundError.crypto(error.localizedDescription) }
}

private func aesECBEncryptBlock(_ input: Data, key: Data) throws -> Data {
    guard input.count == kCCBlockSizeAES128, key.count == kCCKeySizeAES128 else {
        throw NativeOutboundError.crypto("AES-ECB 长度无效")
    }
    let outputCapacity = kCCBlockSizeAES128
    var output = Data(count: outputCapacity); var moved = 0
    let status = output.withUnsafeMutableBytes { outRaw in
        input.withUnsafeBytes { inRaw in
            key.withUnsafeBytes { keyRaw in
                CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode), keyRaw.baseAddress, key.count,
                        nil, inRaw.baseAddress, input.count, outRaw.baseAddress,
                        outputCapacity, &moved)
            }
        }
    }
    guard status == kCCSuccess, moved == kCCBlockSizeAES128 else {
        throw NativeOutboundError.crypto("AES-ECB 状态 \(status)")
    }
    return output
}

private typealias NativeHash = (Data) -> Data

private func vmessKDF(key: Data, path: [Data]) -> Data {
    var creator: NativeHash = { message in
        Data(HMAC<SHA256>.authenticationCode(for: message,
                                              using: SymmetricKey(data: Data("VMess AEAD KDF".utf8))))
    }
    for salt in path {
        let parent = creator
        creator = { message in genericHMAC(key: salt, message: message, hash: parent) }
    }
    return creator(key)
}

private func genericHMAC(key: Data, message: Data, hash: NativeHash) -> Data {
    let blockSize = 64
    var normalized = key.count > blockSize ? hash(key) : key
    if normalized.count < blockSize { normalized.append(Data(repeating: 0, count: blockSize - normalized.count)) }
    if normalized.count > blockSize { normalized = normalized.prefix(blockSize) }
    let innerKey = Data(normalized.map { $0 ^ 0x36 })
    let outerKey = Data(normalized.map { $0 ^ 0x5c })
    return hash(outerKey + hash(innerKey + message))
}

func secureRandom(count: Int) -> Data {
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    precondition(status == errSecSuccess)
    return data
}

private func fnv1a(_ data: Data) -> UInt32 {
    var value: UInt32 = 2_166_136_261
    for byte in data { value ^= UInt32(byte); value = value &* 16_777_619 }
    return value
}

private func crc32(_ data: Data) -> UInt32 {
    var crc: UInt32 = 0xffff_ffff
    for byte in data {
        crc ^= UInt32(byte)
        for _ in 0..<8 { crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0 : 0xedb8_8320) }
    }
    return ~crc
}

private func parseHeaders(_ value: String?) -> [String: String] {
    guard let value else { return [:] }
    var result: [String: String] = [:]
    for component in value.split(whereSeparator: { $0 == "|" || $0 == ";" }) {
        guard let separator = component.firstIndex(where: { $0 == ":" || $0 == "=" }) else { continue }
        let name = component[..<separator].trimmingCharacters(in: .whitespaces)
        var headerValue = component[component.index(after: separator)...]
            .trimmingCharacters(in: .whitespaces)
        if headerValue.count >= 2,
           (headerValue.hasPrefix("\"") && headerValue.hasSuffix("\"") ||
            headerValue.hasPrefix("'") && headerValue.hasSuffix("'")) {
            headerValue.removeFirst(); headerValue.removeLast()
        }
        if !name.isEmpty { result[name] = headerValue }
    }
    return result
}

private func boolean(_ value: String?, default fallback: Bool) -> Bool {
    guard let value else { return fallback }
    return ["true", "yes", "on", "1"].contains(value.lowercased())
}

private func loopback(_ host: String) -> Bool {
    let value = host.lowercased()
    return value == "localhost" || value == "127.0.0.1" || value == "::1"
}

private func read16(_ data: Data) -> UInt16 {
    UInt16(data[data.startIndex]) << 8 | UInt16(data[data.index(after: data.startIndex)])
}

private func append16(_ value: UInt16, to data: inout Data) {
    data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
}

private func append32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8(value >> 24)); data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff)); data.append(UInt8(value & 0xff))
}

private func append64(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) { data.append(UInt8((value >> UInt64(shift)) & 0xff)) }
}

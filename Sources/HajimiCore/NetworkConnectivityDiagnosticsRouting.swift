import Foundation
import Network
import Security
import Darwin
import HajimiProxyRuntime
import HajimiCXXProtocolBridge
@_exported import HajimiDNS
@_exported import HajimiRouting

// Explicit diagnostics use the existing live routing core. Constructing a
// temporary router here would reconfigure the process-wide outbound factory.
public extension ProxyEngine {
    /// An explicit terminal result for a missing or revoked App-owned data
    /// plane. Callers supply fixed UI text, never raw errors or profile values.
    static func unavailableNetworkDiagnostics(
        detail: String = "请先开启增强模式或启动代理引擎后再测试",
        callbackQueue: DispatchQueue = .main,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        let tasks = NetworkConnectivityDiagnosticKind.networkDiagnosticOrder.map { kind in
            NetworkConnectivityDiagnosticTask(row: .init(id: kind.rawValue, kind: kind,
                title: kind.networkDiagnosticTitle, endpoint: "", route: "未启动",
                status: .skipped, detail: detail))
        }
        return NetworkConnectivityDiagnosticsSession(tasks: tasks, callbackQueue: callbackQueue,
            isCurrent: { true }, onUpdate: onUpdate)
    }

    @discardableResult
    func startNetworkDiagnostics(callbackQueue: DispatchQueue = .main,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        let context = stateQueue.sync { (status, dnsPacketRouter, routingGeneration) }
        guard context.0 == .running, let router = context.1 else {
            return Self.unavailableNetworkDiagnostics(detail: "代理核心未就绪；请启动后再测试",
                callbackQueue: callbackQueue, onUpdate: onUpdate)
        }
        let capturedRoutingGeneration = context.2
        return router.startNetworkDiagnostics(callbackQueue: callbackQueue, ownerIsCurrent: { [weak self, weak router] in
            guard let self, let router else { return false }
            return self.stateQueue.sync {
                self.status == .running && self.routingGeneration == capturedRoutingGeneration && self.dnsPacketRouter === router
            }
        }, onUpdate: onUpdate)
    }
}

/// Enhanced mode owns a router independently of the optional HTTP/SOCKS
/// listeners. Diagnose that existing data plane without starting listeners or
/// constructing another router. Owner permission never replaces the router's
/// own policy generation and physical-interface checks.
public extension NativePacketRouter {
    @discardableResult
    func startNetworkDiagnostics(callbackQueue: DispatchQueue = .main,
        ownerIsCurrent: @escaping () -> Bool = { true },
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
        -> NetworkConnectivityDiagnosticsSession {
        let round = networkDiagnosticRound(ownerIsCurrent: ownerIsCurrent)
        return NetworkConnectivityDiagnosticsSession(tasks: round.tasks,
            omittedEndpointCount: round.omitted, callbackQueue: callbackQueue,
            isCurrent: round.isCurrent, onUpdate: onUpdate)
    }
}

private extension NetworkConnectivityDiagnosticKind {
    static let networkDiagnosticOrder: [Self] = [.localLatency, .proxyLatency, .traditionalDNS, .encryptedDNS]
    var networkDiagnosticTitle: String {
        switch self {
        case .localLatency: return "本地直连 HTTP 首响应"
        case .proxyLatency: return "所选代理 HTTP 首响应"
        case .traditionalDNS: return "普通 DNS 固定连通性测试"
        case .encryptedDNS: return "加密 DNS 固定 A 查询"
        case .proxyDNS: return "代理内普通 DNS 固定 A 查询"
        }
    }
}

private extension NativePacketRouter {
    static let networkDiagnosticHost = "captive.apple.com"
    static let networkDiagnosticPath = "/hotspot-detect.html"

    func networkDiagnosticSnapshot() -> DNSRoutingSnapshot { dnsSnapshot() }

    func networkDiagnosticRound(ownerIsCurrent: @escaping () -> Bool)
        -> (tasks: [NetworkConnectivityDiagnosticTask], omitted: Int, isCurrent: () -> Bool) {
        let snapshot = networkDiagnosticSnapshot()
        let generation = snapshot.generation
        let interface = ProxyEngine.currentOutboundInterface?.name
        let current: () -> Bool = { [weak self] in
            guard let self else { return false }
            return ownerIsCurrent() && self.isCurrentDNSGenerationForInternal(generation)
                && ProxyEngine.currentOutboundInterface?.name == interface
        }
        let plan = networkDiagnosticTasks(snapshot: snapshot, current: current)
        return (plan.tasks, plan.omitted, current)
    }

    func networkDiagnosticTasks(snapshot: DNSRoutingSnapshot, current: @escaping () -> Bool)
        -> (tasks: [NetworkConnectivityDiagnosticTask], omitted: Int) {
        var tasks: [NetworkConnectivityDiagnosticTask] = []
        var omitted = 0
        let boundInterface = ProxyEngine.currentOutboundInterface
        let httpTarget = RequestTarget(host: Self.networkDiagnosticHost, port: 80, protocolName: "TCP")
        let targetAllowed: Bool
        if case .reject = snapshot.route(httpTarget, mode: .rule) { targetAllowed = false }
        else { targetAllowed = true }
        let direct = ResolvedRoute.direct("DIRECT")
        let selected = snapshot.profile.route(for: httpTarget, mode: .proxy,
            globalPolicy: snapshot.globalPolicy, groupSelections: snapshot.selections)
        for (kind, route) in [(NetworkConnectivityDiagnosticKind.localLatency, direct), (.proxyLatency, selected)] {
            var row = NetworkConnectivityDiagnosticResult(id: kind.rawValue, kind: kind,
                title: kind.networkDiagnosticTitle,
                endpoint: "http://captive.apple.com:80", route: networkDiagnosticRouteLabel(route))
            if !targetAllowed {
                row.status = .skipped; row.detail = "固定 HTTP 测试目标被当前规则拒绝"
                tasks.append(.init(row: row)); continue
            }
            if kind == .proxyLatency {
                if snapshot.mode == .direct {
                    row.status = .skipped; row.detail = "当前处于直连模式，未测试代理路径"
                    tasks.append(.init(row: row)); continue
                }
                switch route {
                case .direct:
                    row.status = .skipped; row.detail = "所选策略最终为 DIRECT，没有可测代理路径"
                    tasks.append(.init(row: row)); continue
                case .reject:
                    row.status = .skipped; row.detail = "所选策略拒绝连接"
                    tasks.append(.init(row: row)); continue
                case .http(let node, _), .socks5(let node, _), .native(let node, _):
                    if let host = node.host, let port = node.port,
                       case .reject = snapshot.route(RequestTarget(host: host, port: port, protocolName: "TCP"), mode: .rule) {
                        row.status = .skipped; row.detail = "所选代理端点被当前规则拒绝"
                        tasks.append(.init(row: row)); continue
                    }
                }
            }
            tasks.append(.init(row: row, timeout: 8, operation: { [weak self] lane, _, done in
                guard let self, current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return nil }
                return self.beginNetworkDiagnosticHTTP(route: route, snapshot: snapshot,
                    queue: lane, current: current, completion: done)
            }))
        }

        let ordinary = snapshot.profile.traditionalDNSServers
        omitted += max(0, ordinary.count - 8)
        if ordinary.isEmpty {
            tasks.append(.init(row: .init(id: "traditionalDNS", kind: .traditionalDNS,
                title: NetworkConnectivityDiagnosticKind.traditionalDNS.networkDiagnosticTitle,
                endpoint: "", route: "本地固定测试", status: .skipped, detail: "未配置固定 IP 的普通 DNS")))
        }
        for (index, raw) in ordinary.prefix(8).enumerated() {
            var row = NetworkConnectivityDiagnosticResult(id: "traditionalDNS-\(index)", kind: .traditionalDNS,
                title: "普通 DNS \(index + 1) · 固定连通性测试", endpoint: "配置项 \(index + 1)", route: "本地固定测试")
            guard let server = TraditionalDNSServer(raw) else {
                row.status = .skipped; row.detail = "此配置不是可测试的固定 IP 普通 DNS；未调用系统解析器"
                tasks.append(.init(row: row)); continue
            }
            let ipv6 = server.usesIPv6Transport
            let family = ipv6 ? "IPv6" : "IPv4"
            let directRoute = server.isLoopback ? "本机回环 · 固定测试"
                : boundInterface.map { "物理接口 \($0.name) 直连 · 固定测试" }
                    ?? "本地默认路径 · 固定测试（未绑定物理接口）"
            row = .init(id: row.id, kind: row.kind,
                title: "普通 DNS \(index + 1) · \(family) 传输 / A 查询",
                endpoint: networkDiagnosticAuthority(server.host, server.port),
                route: directRoute)
            var allowed = true
            for proto in ["UDP", "TCP"] {
                let target = RequestTarget(host: server.host, port: server.port, protocolName: proto)
                for choice in [snapshot.route(target, mode: .rule),
                               snapshot.route(target, name: Self.networkDiagnosticHost, mode: .rule)] {
                    if case .reject = choice { allowed = false }
                }
            }
            guard allowed else {
                row.status = .skipped; row.detail = "普通 DNS 端点或固定测试域名被当前规则拒绝"
                tasks.append(.init(row: row)); continue
            }
            let evidence = NetworkConnectivityDNSProbeEvidence(ipv6: ipv6)
            tasks.append(.init(row: row, timeout: 4, deadlineMeasurement: evidence.deadlineMeasurement,
                operation: { lane, deadline, done in
                guard current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return nil }
                let queryID = UInt16.random(in: .min ... .max)
                let query = DNSMessageInspection.query(for: Self.networkDiagnosticHost, type: 1, id: queryID)!
                let probe = TraditionalDNSConnectivityProbe(server: server,
                    interface: boundInterface, queue: lane, deadline: deadline,
                    queryID: queryID, permitted: current, onWaitingError: evidence.observePathError) { result in
                    guard current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return }
                    switch result {
                    case .success(let response):
                        var measurement = NetworkConnectivityDNSResponse.inspect(response, query: query)
                        measurement.detail += "；本地 \(family) 传输固定测试，不授权应用明文 DNS 降级"
                        done(measurement)
                    case .failure(let error):
                        done(NetworkConnectivityDNSProbeFailure.inspect(error, ipv6: ipv6))
                    }
                }
                probe.start()
                return { probe.cancel() }
            }))
        }

        let encrypted = snapshot.profile.effectiveEncryptedDNSServers
        omitted += max(0, encrypted.count - 8)
        guard !encrypted.isEmpty else {
            tasks.append(.init(row: .init(id: "encryptedDNS", kind: .encryptedDNS,
                title: NetworkConnectivityDiagnosticKind.encryptedDNS.networkDiagnosticTitle,
                endpoint: "", route: "当前 DNS 路径", status: .skipped, detail: "当前配置未使用加密 DNS")))
            return (tasks, omitted)
        }
        let query = DNSMessageInspection.query(for: Self.networkDiagnosticHost, type: 1)!
        let original = RequestTarget(host: protectedSystemDNSGateway, port: 53, protocolName: "UDP")
        let approvedPlan: DNSQueryPlan?
        if case .upstream(let plan)? = try? prepareDNSQuery(query, original: original, synthesizeFakeIP: false) {
            approvedPlan = plan
        } else { approvedPlan = nil }
        for (index, raw) in encrypted.prefix(8).enumerated() {
            var row = NetworkConnectivityDiagnosticResult(id: "encryptedDNS-\(index)", kind: .encryptedDNS,
                title: "加密 DNS \(index + 1) · 固定 A 查询", endpoint: "配置项 \(index + 1)", route: "当前 DNS 路径")
            let upstream: DNSConfiguredUpstream?
            if raw.lowercased().hasPrefix("https://"), let endpoint = DoHEndpoint(raw, allowUnresolvedHost: true) {
                upstream = .doh(endpoint)
                row = .init(id: row.id, kind: row.kind, title: row.title,
                    endpoint: "DoH " + networkDiagnosticAuthority(endpoint.host, endpoint.port), route: row.route)
            } else if raw.lowercased().hasPrefix("tls://"), let endpoint = DoTEndpoint(raw) {
                upstream = .dot(endpoint)
                row = .init(id: row.id, kind: row.kind, title: row.title,
                    endpoint: "DoT " + networkDiagnosticAuthority(endpoint.host, endpoint.port), route: row.route)
            } else { upstream = nil }
            guard let upstream else {
                row.status = .skipped; row.detail = "加密 DNS 配置无效；未降级或替换上游"
                tasks.append(.init(row: row)); continue
            }
            guard let plan = approvedPlan,
                  let candidate = plan.candidates.first(where: { candidate in
                      upstream.builtinAddressVariants.contains(where: { $0.candidateID == candidate.id })
                  }), let chosen = try? revalidatedCandidatePlan(plan, candidate: candidate) else {
                row.status = .skipped; row.detail = "固定查询或该加密 DNS 端点未获当前规则许可"
                tasks.append(.init(row: row)); continue
            }
            row = .init(id: row.id, kind: row.kind, title: row.title,
                endpoint: row.endpoint, route: networkDiagnosticRouteLabel(chosen.route))
            tasks.append(.init(row: row, timeout: 8, operation: { [weak self] lane, _, done in
                guard let self, current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return nil }
                do {
                    // Revalidate one approved endpoint without altering its
                    // authority, answer cache, adaptive selection or fallback.
                    let fresh = try self.revalidatedCandidatePlan(plan, candidate: candidate)
                    let flow = try self.makeDNSUpstream(plan: fresh, queue: lane,
                        receive: { answer in
                            guard current() else { done(.init(status: .cancelled, detail: "配置或接口已变化")); return }
                            done(NetworkConnectivityDNSResponse.inspect(answer, query: query))
                        }, failure: { error in
                            done(.init(status: .failure, detail: "加密 DNS 连接、认证或查询失败", error: error))
                        })
                    flow.send(query)
                    return {
                        if let acknowledging = flow as? DNSQueryCancellationAcknowledging {
                            acknowledging.cancel(reason: .callerCancelled, completion: {})
                        } else { flow.cancel() }
                    }
                } catch {
                    done(.init(status: .failure, detail: "当前加密 DNS 计划已失效或未获许可", error: error)); return nil
                }
            }))
        }
        return (tasks, omitted)
    }

    func beginNetworkDiagnosticHTTP(route: ResolvedRoute, snapshot: DNSRoutingSnapshot,
        queue: DispatchQueue, current: @escaping () -> Bool,
        completion: @escaping (NetworkConnectivityDiagnosticMeasurement) -> Void) -> (() -> Void)? {
        let exchange = NetworkConnectivityHTTPExchange(host: Self.networkDiagnosticHost,
            path: Self.networkDiagnosticPath, queue: queue, completion: completion)
        let target = RequestTarget(host: Self.networkDiagnosticHost, port: 80, protocolName: "TCP")
        let connect: (RequestTarget) -> Void = { addressTarget in
            guard current(), exchange.reserve(.shared) else {
                exchange.fail(.init(status: .skipped, detail: "配置已变化或共享测试连接达到上限")); return
            }
            exchange.installCancellation(TunnelConnector.beginConnect(route: route, target: addressTarget,
                plainHTTP: false, queue: queue, waitForSetupAcknowledgement: true) { result in
                    guard current() else {
                        if case .success(let pair) = result { pair.0.cancel() }
                        exchange.connected(.failure(EncryptedDNSQueryFailure.policy)); return
                    }
                    exchange.connected(result)
                })
        }
        guard case .direct = route else {
            connect(target)
            return { exchange.cancel() }
        }
        // Resolve DIRECT through the existing protected query router. Its
        // flow is individually cancellable; no system-resolver shortcut or
        // non-cancellable resolveAddresses helper is introduced for the test.
        let resolving = NetworkConnectivityProbeCleanup()
        exchange.installCancellation { resolving.cancel() }
        let query = DNSMessageInspection.query(for: Self.networkDiagnosticHost, type: 1)!
        let original = RequestTarget(host: protectedSystemDNSGateway, port: 53, protocolName: "UDP")
        do {
            let flow = try makeDNSDatagram(original: original, queue: queue, synthesizeFakeIP: false,
                receive: { answer in
                    queue.async {
                        guard current() else {
                            exchange.fail(.init(status: .cancelled, detail: "配置或接口已变化")); return
                        }
                        let inspection = NetworkConnectivityDNSResponse.inspect(answer, query: query)
                        guard inspection.status == .success else {
                            exchange.fail(.init(status: .failure,
                                detail: "本地直连测试的受保护 DNS 解析失败"
                                    + (inspection.responseCode.map { "（DNS RCODE \($0)）" } ?? ""),
                                extendedDNSErrorCodes: inspection.extendedDNSErrorCodes)); return
                        }
                        let addresses = DNSMessageInspection.addressAnswers(in: answer)
                            .map(\.address).filter { !$0.contains(":") }
                        let approved = addresses.first { address in
                            var destination = target; destination.host = address
                            if case .reject = snapshot.route(destination, mode: .rule) { return false }
                            return true
                        }
                        guard let approved else {
                            exchange.fail(.init(status: .skipped, detail: "固定 HTTP 目标的解析地址被当前规则拒绝")); return
                        }
                        resolving.cancel()
                        var literal = target; literal.host = approved
                        connect(literal)
                    }
                }, failure: { error in
                    exchange.fail(.init(status: .failure, detail: "本地直连测试的受保护 DNS 查询失败", error: error))
                })
            resolving.install {
                flow.cancel()
            }
            flow.send(query)
        } catch { exchange.fail(.init(status: .failure, detail: "本地直连测试的 DNS 计划未获许可", error: error)) }
        return { exchange.cancel() }
    }
}

private func networkDiagnosticAuthority(_ host: String, _ port: UInt16) -> String {
    (host.contains(":") ? "[\(host)]" : host) + ":\(port)"
}

private func networkDiagnosticRouteLabel(_ route: ResolvedRoute) -> String {
    switch route {
    case .direct: return "DIRECT"
    case .reject: return "REJECT"
    case .http(let node, _): return "HTTP 代理 · " + NetworkPerformanceDiagnostics.dnsOpaqueID(node.name, prefix: "node")
    case .socks5(let node, _): return "SOCKS5 代理 · " + NetworkPerformanceDiagnostics.dnsOpaqueID(node.name, prefix: "node")
    case .native(let node, _): return "原生代理 · " + NetworkPerformanceDiagnostics.dnsOpaqueID(node.name, prefix: "node")
    }
}

/// Planning-only vectors. These instantiate no resolver/stream and execute no
/// network operation; the same private authorization bridge plans production.
public enum NetworkConnectivityDiagnosticsRoutingSelfTest {
    private struct Failure: Error { let text: String }
    public static func run() throws {
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            if !condition() { throw Failure(text: text) }
        }
        func planned(_ profile: Profile, mode: OutboundMode = .rule, policy: String = "DIRECT")
            -> (tasks: [NetworkConnectivityDiagnosticTask], omitted: Int) {
            let router = NativePacketRouter(profile: profile, mode: mode, globalPolicy: policy, groupSelections: [:])
            return router.networkDiagnosticTasks(snapshot: router.networkDiagnosticSnapshot(), current: { true })
        }
        var profile = Profile()
        profile.dnsServers = ["192.0.2.53"]
        profile.encryptedDNSServers = ["https://dns.selftest.invalid/private/path?querytoken=private-credential#192.0.2.54"]
        let ordinary = NetworkConnectivityDiagnosticKind.traditionalDNS
        let encrypted = NetworkConnectivityDiagnosticKind.encryptedDNS
        let initial = planned(profile)
        try require(initial.tasks.first(where: { $0.row.kind == .proxyLatency })?.row.status == .skipped,
                    "最终 DIRECT 被规划为代理测试")
        try require(initial.tasks.first(where: { $0.row.kind == encrypted })?.operation != nil,
                    "获准加密配置未规划真实查询")
        let encoded = String(decoding: try JSONEncoder().encode(initial.tasks.map(\.row)), as: UTF8.self)
        try require(!encoded.contains("querytoken") && !encoded.contains("private-credential")
                    && !encoded.contains("/private/path") && !encoded.contains("#192.0.2.54"),
                    "端点标签回显路径、query token 或 fragment")
        var ipv6Profile = Profile()
        ipv6Profile.dnsServers = ["udp://[2001:db8::53]:5353"]
        let ipv6Task = planned(ipv6Profile).tasks.first(where: { $0.row.kind == ordinary })!
        try require(ipv6Task.operation != nil && ipv6Task.timeout == 4
                    && ipv6Task.deadlineMeasurement != nil
                    && ipv6Task.row.endpoint == "[2001:db8::53]:5353"
                    && ipv6Task.row.title.contains("IPv6 传输 / A 查询")
                    && ipv6Task.row.route.contains("固定测试"),
                    "IPv6 固定检测未保留真实传输族、端口、原期限或 deadline 证据入口")
        if ProxyEngine.currentOutboundInterface == nil {
            try require(ipv6Task.row.route.contains("未绑定物理接口"),
                        "自动出口误标为已绑定物理接口")
        }
        ipv6Profile.dnsServers = ["[::1]:5353"]
        try require(planned(ipv6Profile).tasks.first(where: { $0.row.kind == ordinary })?.row.route
                    == "本机回环 · 固定测试", "IPv6 回环被误标为物理接口直连")
        for proto in ["UDP", "TCP"] {
            var denied = profile
            denied.rules = [.init(kind: .logicalAnd([.ipCIDR("192.0.2.53/32"), .protocolName(proto)]),
                                  policy: "REJECT", sourceLine: 1)]
            let result = planned(denied).tasks.first(where: { $0.row.kind == ordinary })!
            try require(result.row.status == .skipped && result.operation == nil,
                        "普通 DNS \(proto) REJECT 仍获测试操作")
        }
        var deniedName = profile
        deniedName.rules = [.init(kind: .domain("captive.apple.com"), policy: "REJECT", sourceLine: 1)]
        try require(planned(deniedName).tasks.allSatisfy { $0.operation == nil },
                    "固定测试域名 REJECT 仍规划网络操作")
        for deniedHost in ["192.0.2.54/32", "dns.selftest.invalid"] {
            var denied = profile
            denied.rules = [.init(kind: deniedHost.contains("/") ? .ipCIDR(deniedHost) : .domain(deniedHost),
                                  policy: "REJECT", sourceLine: 1)]
            let result = planned(denied).tasks.first(where: { $0.row.kind == encrypted })!
            try require(result.row.status == .skipped && result.operation == nil,
                        "加密 DNS 身份或固定拨号 IP REJECT 仍获测试操作")
        }
        let node = ProxyPolicy(name: "private-selected-node", kind: .socks5, host: "192.0.2.90", port: 1080)
        profile.proxies[node.name] = node
        let forcedDirect = planned(profile, mode: .direct, policy: node.name)
        try require(forcedDirect.tasks.first(where: { $0.row.kind == .proxyLatency })?.operation == nil,
                    "直连模式仍执行所选代理测试")
        let rejected = planned(profile, mode: .proxy, policy: "REJECT")
        try require(rejected.tasks.first(where: { $0.row.kind == .proxyLatency })?.row.status == .skipped,
                    "最终 REJECT 被规划为代理测试")
        let selected = planned(profile, policy: node.name).tasks.first(where: { $0.row.kind == .proxyLatency })!
        try require(selected.operation != nil && selected.row.route.hasPrefix("SOCKS5 代理")
                    && !selected.row.route.contains(node.name), "所选真实代理路径未区分或暴露原始节点标签")
        var invalid = profile
        invalid.encryptedDNSServers = ["https://user:private-password@dns.selftest.invalid/private?querytoken=secret#192.0.2.54"]
        let bad = planned(invalid).tasks.first(where: { $0.row.kind == encrypted })!
        try require(bad.operation == nil && bad.row.endpoint == "配置项 1", "无效 URI 泄露凭据或仍执行查询")
        var many = Profile()
        many.dnsServers = (1...9).map { "192.0.2.\($0)" }
        many.encryptedDNSServers = (1...9).map { "https://203.0.113.\($0)/dns-query" }
        let bounded = planned(many)
        try require(bounded.tasks.filter({ $0.row.kind == ordinary }).count == 8
                    && bounded.tasks.filter({ $0.row.kind == encrypted }).count == 8 && bounded.omitted == 2,
                    "单类端点未限制八项或遗漏数错误")
        try independentRouterAndListenerOwnership()
        print("Network diagnostics route planning self-test passed: DIRECT/REJECT, UDP/TCP/QNAME/TLS-identity/pin policy, approved endpoints, URI privacy and endpoint caps")
    }

    /// Production entrypoints are exercised with permission already revoked,
    /// so their session can never start a resolver or connector. Separate plan
    /// inspection verifies that an otherwise-live TUN router has real jobs.
    private static func independentRouterAndListenerOwnership() throws {
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            if !condition() { throw Failure(text: text) }
        }
        final class SnapshotBox {
            private let lock = NSLock()
            private var value: NetworkConnectivityDiagnosticsSnapshot?
            let done = DispatchSemaphore(value: 0)
            func receive(_ snapshot: NetworkConnectivityDiagnosticsSnapshot) {
                guard !snapshot.isRunning else { return }
                lock.lock(); value = snapshot; lock.unlock(); done.signal()
            }
            var final: NetworkConnectivityDiagnosticsSnapshot? {
                lock.lock(); defer { lock.unlock() }; return value
            }
        }
        final class OwnerGate {
            private let lock = NSLock()
            private var allowed = true
            func permits() -> Bool { lock.lock(); defer { lock.unlock() }; return allowed }
            func revoke() { lock.lock(); allowed = false; lock.unlock() }
        }
        var profile = Profile()
        profile.dnsServers = ["192.0.2.53"]
        profile.encryptedDNSServers = ["https://dns.router-selftest.invalid/dns-query#192.0.2.54"]
        let router = NativePacketRouter(profile: profile, mode: .rule, globalPolicy: "DIRECT", groupSelections: [:])
        let engine = ProxyEngine()
        try require(engine.runtimeSnapshot().status == .stopped, "监听引擎夹具意外启动")
        let owner = OwnerGate()
        let live = router.networkDiagnosticRound(ownerIsCurrent: owner.permits)
        try require(live.isCurrent() && live.tasks.contains(where: { $0.row.kind == .localLatency && $0.operation != nil })
                    && live.tasks.contains(where: { $0.row.kind == .encryptedDNS && $0.operation != nil })
                    && live.tasks.contains(where: { $0.row.kind == .traditionalDNS && $0.operation != nil }),
                    "独立 TUN router 被未启动的监听引擎错误阻止")
        owner.revoke()
        try require(!live.isCurrent(), "所属增强会话撤销后仍保留诊断权限")
        let fresh = router.networkDiagnosticRound(ownerIsCurrent: { true })
        try require(fresh.isCurrent(), "有效 router 代次未获诊断权限")
        router.flushDNS(prewarm: false)
        try require(!fresh.isCurrent(), "router DNS 代次变化后旧诊断仍有效")
        let callbackQueue = DispatchQueue(label: "app.hajimi.network-diagnostics.ownership-selftest")
        let routerBox = SnapshotBox()
        let routerSession = router.startNetworkDiagnostics(callbackQueue: callbackQueue,
            ownerIsCurrent: { false }, onUpdate: routerBox.receive)
        try require(routerBox.done.wait(timeout: .now() + 2) == .success,
                    "独立 router 的公开诊断入口未交付终态")
        try require(routerBox.final?.rows.contains(where: { $0.status == .cancelled }) == true
                    && routerBox.final?.rows.allSatisfy({ !$0.detail.contains("代理核心未就绪") }) == true,
                    "router 入口仍沿用监听引擎未启动检查或忽略所属会话许可")
        let engineBox = SnapshotBox()
        let engineSession = engine.startNetworkDiagnostics(callbackQueue: callbackQueue, onUpdate: engineBox.receive)
        try require(engineBox.done.wait(timeout: .now() + 2) == .success,
                    "未启动的监听引擎未交付明确跳过结果")
        try require(engineBox.final?.rows.count == 4
                    && engineBox.final?.rows.allSatisfy({ $0.status == .skipped && $0.detail.contains("代理核心未就绪") }) == true,
                    "旧监听入口在未启动时错误规划真实网络操作")
        let unavailableBox = SnapshotBox()
        let unavailableSession = ProxyEngine.unavailableNetworkDiagnostics(detail: "增强会话已停止或正在清理，请稍后重试",
            callbackQueue: callbackQueue, onUpdate: unavailableBox.receive)
        try require(unavailableBox.done.wait(timeout: .now() + 2) == .success
                    && unavailableBox.final?.rows.count == 4
                    && unavailableBox.final?.rows.allSatisfy({ $0.status == .skipped
                        && $0.detail == "增强会话已停止或正在清理，请稍后重试" }) == true,
                    "缺失数据面的静态入口未提供明确、无网络操作的终态")
        print("Network diagnostics ownership self-test passed: TUN router independent of stopped listeners, owner revocation, DNS generation and both public entrypoints; no network operations")
        withExtendedLifetime((routerSession, engineSession, unavailableSession, router)) {}
    }
}


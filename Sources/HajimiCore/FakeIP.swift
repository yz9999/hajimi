import Foundation

/// Synthetic addresses that keep a destination's hostname inside the tunnel.
///
/// Enhanced mode otherwise depends on the local resolver being honest: the
/// application resolves a name itself, and the tunnel can only forward whatever
/// address came back. Where DNS answers are tampered with, that address is
/// wrong and every rule, every proxy and every server-side resolution downstream
/// is applied to the wrong destination — while the same node reached through the
/// SOCKS listener works, because there the hostname travels to the server
/// untouched.
///
/// Fake-IP removes the dependency. A query for a proxied name is answered
/// locally with an address from a reserved range, and the connection that
/// follows is mapped back to the name before it is routed, so the hostname
/// reaches the outbound exactly as it does in proxy mode.
public final class FakeIPAllocator {
    /// RFC 2544 benchmarking space, the same range Clash reserves for this.
    /// `198.18.16.0/24` is Hajimi's own point-to-point tunnel subnet, so allocation
    /// starts one /16 above it and can never collide with the gateway.
    public static let subnet = "198.19.0.0/16"
    private static let base: UInt32 = 0xC613_0000 // 198.19.0.0
    private static let count: UInt32 = 0xFFFF

    private let lock = NSLock()
    private var domainToAddress: [String: UInt32] = [:]
    private var addressToDomain: [UInt32: String] = [:]
    private var order: [UInt32] = []
    private var next: UInt32 = 2
    private var storeURL: URL?

    public init() {}

    /// Restores a previous mapping so Enhanced Mode can keep answering the
    /// same names after a reload. Corrupt files are ignored, not fatal.
    public convenience init(persistingAt url: URL) {
        self.init()
        storeURL = url
        restore(from: url)
    }

    public static func isFake(_ address: String) -> Bool {
        guard let value = ipv4Value(address) else { return false }
        return value >= base && value < base &+ count
    }

    /// Stable per domain: the same name always yields the same address until it
    /// is evicted, so a connection opened long after the lookup still resolves.
    public func address(for domain: String) -> String {
        let key = domain.lowercased()
        lock.lock(); defer { lock.unlock() }
        if let existing = domainToAddress[key] { return Self.string(existing) }
        // The range is finite; recycling the oldest entry keeps a long-running
        // session from failing to allocate rather than growing without bound.
        if order.count >= Int(Self.count) - 16, let oldest = order.first {
            order.removeFirst()
            if let stale = addressToDomain.removeValue(forKey: oldest) {
                domainToAddress.removeValue(forKey: stale)
            }
        }
        var candidate = Self.base &+ next
        var probes: UInt32 = 0
        while addressToDomain[candidate] != nil, probes < Self.count {
            next = (next &+ 1) % Self.count
            if next < 2 { next = 2 }
            candidate = Self.base &+ next
            probes &+= 1
        }
        next = (next &+ 1) % Self.count
        if next < 2 { next = 2 }
        domainToAddress[key] = candidate
        addressToDomain[candidate] = key
        order.append(candidate)
        persistLocked()
        return Self.string(candidate)
    }

    public func domain(for address: String) -> String? {
        guard let value = Self.ipv4Value(address) else { return nil }
        lock.lock(); defer { lock.unlock() }
        return addressToDomain[value]
    }

    public func removeAll() {
        lock.lock()
        domainToAddress.removeAll(); addressToDomain.removeAll()
        order.removeAll(); next = 2
        persistLocked()
        lock.unlock()
    }

    public var mappingCount: Int {
        lock.lock(); defer { lock.unlock() }
        return domainToAddress.count
    }

    public func snapshot() -> [(domain: String, address: String)] {
        lock.lock(); defer { lock.unlock() }
        return order.compactMap { value in
            guard let domain = addressToDomain[value] else { return nil }
            return (domain, Self.string(value))
        }
    }

    private func persistLocked() {
        guard let storeURL else { return }
        let payload = Snapshot(next: next, entries: order.compactMap { value in
            guard let domain = addressToDomain[value] else { return nil }
            return Snapshot.Entry(domain: domain, address: value)
        })
        guard let data = try? JSONEncoder().encode(payload) else { return }
        try? data.write(to: storeURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                               ofItemAtPath: storeURL.path)
    }

    private func restore(from url: URL) {
        guard let data = try? Data(contentsOf: url),
              let snapshot = try? JSONDecoder().decode(Snapshot.self, from: data) else { return }
        lock.lock()
        domainToAddress.removeAll(); addressToDomain.removeAll(); order.removeAll()
        for entry in snapshot.entries {
            guard entry.address >= Self.base, entry.address < Self.base &+ Self.count,
                  !entry.domain.isEmpty else { continue }
            domainToAddress[entry.domain] = entry.address
            addressToDomain[entry.address] = entry.domain
            order.append(entry.address)
        }
        next = snapshot.next < 2 ? 2 : snapshot.next % Self.count
        lock.unlock()
    }

    private struct Snapshot: Codable {
        struct Entry: Codable {
            var domain: String
            var address: UInt32
        }
        var next: UInt32
        var entries: [Entry]
    }

    static func ipv4Value(_ address: String) -> UInt32? {
        let parts = address.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part) else { return nil }
            value = value << 8 | UInt32(octet)
        }
        return value
    }

    static func string(_ value: UInt32) -> String {
        "\((value >> 24) & 0xFF).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).\(value & 0xFF)"
    }
}

// MARK: - DNS query handling

/// The parts of a DNS query fake-IP needs.
public struct FakeIPQuestion: Equatable {
    public enum Kind: UInt16 {
        case a = 1
        case aaaa = 28
    }
    public var name: String
    public var kind: Kind
    /// Byte offset just past the question section, where answers are appended.
    public var questionEnd: Int
}

public enum FakeIPResponder {
    /// Reads the single question from a query, or nil when the message is not a
    /// plain one-question A/AAAA lookup that fake-IP can answer.
    public static func question(in data: Data) -> FakeIPQuestion? {
        guard data.count >= 12 else { return nil }
        let flags = UInt16(data[data.startIndex + 2]) << 8 | UInt16(data[data.startIndex + 3])
        // QR must be 0 (a query) and OPCODE 0 (standard).
        guard flags & 0x8000 == 0, (flags >> 11) & 0x0F == 0 else { return nil }
        let questionCount = UInt16(data[data.startIndex + 4]) << 8 | UInt16(data[data.startIndex + 5])
        guard questionCount == 1 else { return nil }

        var offset = 12
        var labels: [String] = []
        while offset < data.count {
            let length = Int(data[data.startIndex + offset])
            // A query never contains compression pointers.
            guard length & 0xC0 == 0 else { return nil }
            offset += 1
            if length == 0 { break }
            guard offset + length <= data.count else { return nil }
            let raw = data[(data.startIndex + offset)..<(data.startIndex + offset + length)]
            guard let label = String(data: Data(raw), encoding: .utf8) else { return nil }
            labels.append(label)
            offset += length
        }
        guard !labels.isEmpty, offset + 4 <= data.count else { return nil }
        let type = UInt16(data[data.startIndex + offset]) << 8
            | UInt16(data[data.startIndex + offset + 1])
        let cls = UInt16(data[data.startIndex + offset + 2]) << 8
            | UInt16(data[data.startIndex + offset + 3])
        guard cls == 1, let kind = FakeIPQuestion.Kind(rawValue: type) else { return nil }
        return FakeIPQuestion(name: labels.joined(separator: "."), kind: kind,
                              questionEnd: offset + 4)
    }

    /// Builds an answer echoing the query's question section.
    ///
    /// `address` nil produces NOERROR with no answers, which is how an AAAA
    /// lookup is refused: returning NXDOMAIN would make some resolvers treat
    /// the name as nonexistent for A as well.
    public static func reply(to query: Data, question: FakeIPQuestion,
                             address: String?, ttl: UInt32 = 60) -> Data? {
        guard query.count >= question.questionEnd else { return nil }
        var out = Data(query[query.startIndex..<(query.startIndex + question.questionEnd)])
        // QR=1, RD copied from the query, RA=1.
        let requestFlags = UInt16(out[out.startIndex + 2]) << 8 | UInt16(out[out.startIndex + 3])
        let responseFlags: UInt16 = 0x8080 | (requestFlags & 0x0100)
        out[out.startIndex + 2] = UInt8(truncatingIfNeeded: responseFlags >> 8)
        out[out.startIndex + 3] = UInt8(truncatingIfNeeded: responseFlags)
        let answers: UInt16 = address == nil ? 0 : 1
        out[out.startIndex + 6] = UInt8(truncatingIfNeeded: answers >> 8)
        out[out.startIndex + 7] = UInt8(truncatingIfNeeded: answers)
        // Authority and additional counts are cleared: an EDNS OPT record in
        // the query is not echoed, and claiming records that are not present
        // makes the answer unparseable.
        out[out.startIndex + 8] = 0; out[out.startIndex + 9] = 0
        out[out.startIndex + 10] = 0; out[out.startIndex + 11] = 0
        guard let address, let value = FakeIPAllocator.ipv4Value(address) else { return out }

        // Name compression pointer back to the question's name at offset 12.
        out.append(contentsOf: [0xC0, 0x0C])
        out.append(contentsOf: [0x00, 0x01])            // type A
        out.append(contentsOf: [0x00, 0x01])            // class IN
        out.append(UInt8(truncatingIfNeeded: ttl >> 24))
        out.append(UInt8(truncatingIfNeeded: ttl >> 16))
        out.append(UInt8(truncatingIfNeeded: ttl >> 8))
        out.append(UInt8(truncatingIfNeeded: ttl))
        out.append(contentsOf: [0x00, 0x04])            // RDLENGTH
        out.append(UInt8(truncatingIfNeeded: value >> 24))
        out.append(UInt8(truncatingIfNeeded: value >> 16))
        out.append(UInt8(truncatingIfNeeded: value >> 8))
        out.append(UInt8(truncatingIfNeeded: value))
        return out
    }
}

// MARK: - Self-test

public enum FakeIPSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "fake-IP 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    /// Builds a minimal query for `name`, mirroring what a resolver emits.
    static func query(_ name: String, type: UInt16, id: UInt16 = 0x1234) -> Data {
        var out = Data()
        out.append(UInt8(truncatingIfNeeded: id >> 8)); out.append(UInt8(truncatingIfNeeded: id))
        out.append(contentsOf: [0x01, 0x00])            // RD
        out.append(contentsOf: [0x00, 0x01])            // QDCOUNT
        out.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in name.split(separator: ".") {
            out.append(UInt8(label.utf8.count))
            out.append(contentsOf: Array(label.utf8))
        }
        out.append(0)
        out.append(UInt8(truncatingIfNeeded: type >> 8)); out.append(UInt8(truncatingIfNeeded: type))
        out.append(contentsOf: [0x00, 0x01])            // class IN
        return out
    }

    public static func run() throws {
        try allocation()
        try questionParsing()
        try replyShape()
        try roundTripThroughExistingParser()
        try endToEndThroughRouter()
        try udpRejectionSignalling()
        try udpFakeIPDestinationResolution()
    }

    /// UDP/QUIC must reverse-map fake-IP addresses the same way TCP does.
    /// Without that, domain rules miss and the outbound is asked to reach
    /// 198.19.x.x — an address no remote server owns.
    private static func udpFakeIPDestinationResolution() throws {
        var profile = Profile()
        profile.fakeIPEnabled = true
        var node = ProxyPolicy(name: "Node", kind: .native)
        node.adapterType = "vmess"
        node.host = "server.example.com"
        node.port = 443
        node.parameters = [
            "uuid": "123e4567-e89b-12d3-a456-426614174000",
            "cipher": "auto",
        ]
        profile.proxies["Node"] = node
        profile.rules = [
            RoutingRule(kind: .domainSuffix("youtube.com"), policy: "Node", sourceLine: 1),
            RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2),
        ]
        let router = NativePacketRouter(profile: profile, mode: .rule,
                                        globalPolicy: "DIRECT", groupSelections: [:])

        let semaphore = DispatchSemaphore(value: 0)
        var answer: Data?
        let flow = try router.makeUDPFlow(host: "8.8.8.8", port: 53,
                                          queue: .global(),
                                          receive: { answer = $0; semaphore.signal() },
                                          failure: { _ in semaphore.signal() })
        flow.send(query("www.youtube.com", type: 1))
        defer { flow.cancel() }
        guard semaphore.wait(timeout: .now() + 5) == .success, let answer else {
            throw Failure(text: "fake-IP 查询没有应答")
        }
        guard let address = DNSMessageProbe.addressRecords(in: answer).first?.address else {
            throw Failure(text: "fake-IP 应答没有 A 记录")
        }

        try expect(router.resolvedDestinationHost(address) == "www.youtube.com",
                   "UDP 路径未能从 fake-IP 还原域名：\(router.resolvedDestinationHost(address))")
        try expect(router.resolvedDestinationHost("1.2.3.4") == "1.2.3.4",
                   "真实地址不应被改写")

        // Domain rule selects the stream-based VMess node: QUIC must fall back.
        try expect(router.prefersTCPFallbackForQUIC(host: address),
                   "对 fake-IP 的 UDP/443 未按域名规则触发 TCP 回退")
        // An unrelated address still hits FINAL DIRECT and must not fall back.
        try expect(!router.prefersTCPFallbackForQUIC(host: "203.0.113.50"),
                   "非 fake-IP 直连地址被错误禁用了 QUIC")

        // A node without UDP support must reject datagrams aimed at the fake-IP
        // of a proxied name, not silently black-hole them as if they were DIRECT.
        var noUDP = profile
        noUDP.proxies["Node"]?.adapterType = "ssh"
        noUDP.proxies["Node"]?.parameters = ["username": "u", "password": "p"]
        let sshRouter = NativePacketRouter(profile: noUDP, mode: .rule,
                                           globalPolicy: "DIRECT", groupSelections: [:])
        // Re-mint the same mapping on the new router.
        let sem2 = DispatchSemaphore(value: 0)
        var answer2: Data?
        let dns = try sshRouter.makeUDPFlow(host: "8.8.8.8", port: 53, queue: .global(),
                                            receive: { answer2 = $0; sem2.signal() },
                                            failure: { _ in sem2.signal() })
        dns.send(query("www.youtube.com", type: 1))
        defer { dns.cancel() }
        guard sem2.wait(timeout: .now() + 5) == .success, let answer2,
              let address2 = DNSMessageProbe.addressRecords(in: answer2).first?.address else {
            throw Failure(text: "SSH 场景下 fake-IP 查询失败")
        }
        try expect(sshRouter.rejectsUDP(host: address2, port: 53_000),
                   "fake-IP 目标在无 UDP 出站上未被拒绝")
        try expect(!sshRouter.rejectsUDP(host: "203.0.113.50", port: 53_000),
                   "直连地址被无 UDP 逻辑误伤")
    }

    /// A node that cannot carry UDP must say so per datagram rather than drop
    /// it: silence costs the application its full timeout every attempt, which
    /// looks exactly like a dead network.
    private static func udpRejectionSignalling() throws {
        func router(udp: Bool) -> NativePacketRouter {
            var profile = Profile()
            var node = ProxyPolicy(name: "Node", kind: .native)
            node.adapterType = "ss"
            node.host = "server.example.com"
            node.port = 8388
            node.parameters = ["cipher": "2022-blake3-chacha20-poly1305",
                               "password": Data((0..<32).map { UInt8($0) }).base64EncodedString()]
            if udp { node.parameters["udp"] = "true" }
            profile.proxies["Node"] = node
            profile.rules = [RoutingRule(kind: .final, policy: "Node", sourceLine: 1)]
            return NativePacketRouter(profile: profile, mode: .rule,
                                      globalPolicy: "DIRECT", groupSelections: [:])
        }

        let without = router(udp: false)
        try expect(without.rejectsUDP(host: "1.2.3.4", port: 443),
                   "未开启 UDP 的节点应拒绝 QUIC 数据报")
        try expect(without.rejectsUDP(host: "1.2.3.4", port: 19_302),
                   "未开启 UDP 的节点应拒绝任意端口的数据报，而不只是 443")
        // Ordinary DNS can use fake-IP, DoH/DoT or a direct query; this SS
        // node does not impose the TLS-only upstream privacy constraint.
        try expect(!without.rejectsUDP(host: "8.8.8.8", port: 53),
                   "普通 SS 节点不应误拒绝 DNS")

        let with = router(udp: true)
        try expect(!with.rejectsUDP(host: "1.2.3.4", port: 443),
                   "开启 UDP 后不应再拒绝数据报")
        try expect(!with.rejectsUDP(host: "1.2.3.4", port: 19_302),
                   "开启 UDP 后任意端口都应放行")

        // A direct route always carries UDP itself.
        var direct = Profile()
        direct.rules = [RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 1)]
        let plain = NativePacketRouter(profile: direct, mode: .rule,
                                       globalPolicy: "DIRECT", groupSelections: [:])
        try expect(!plain.rejectsUDP(host: "1.2.3.4", port: 443), "直连不应被拒绝")
        try expect(!plain.rejectsUDP(host: "8.8.8.8", port: 53), "显式直连 DNS 不应被拒绝")

        // TLS-wrapped HTTP/SOCKS5 cannot carry UDP/53. A DNS exception must
        // not accidentally open a plaintext DirectRoutedDatagram before it
        // reports the missing encrypted resolver.
        for kind: ProxyKind in [.http, .socks5] {
            let name = kind == .http ? "SecureHTTP" : "SecureSOCKS"
            var protected = Profile()
            protected.proxies[name] = ProxyPolicy(
                name: name, kind: kind, host: "203.0.113.10", port: 443,
                parameters: ["tls": "true"])
            protected.rules = [RoutingRule(kind: .final, policy: name, sourceLine: 1)]
            func makeRouter(_ profile: Profile) -> NativePacketRouter {
                NativePacketRouter(profile: profile, mode: .rule,
                                   globalPolicy: "DIRECT", groupSelections: [:])
            }
            let secure = makeRouter(protected)
            try expect(secure.rejectsUDP(host: "8.8.8.8", port: 53),
                       "\(name) 无加密解析器时必须拒绝明文 UDP DNS")
            var callbacks = 0
            do {
                let unexpected = try secure.makeUDPFlow(
                    host: "8.8.8.8", port: 53, queue: .global(),
                    receive: { _ in callbacks += 1 }, failure: { _ in callbacks += 1 })
                unexpected.cancel()
                throw Failure(text: "\(name) 无加密解析器时竟创建了 UDP DNS 会话")
            } catch let failure as Failure {
                throw failure
            } catch {
                try expect(error.localizedDescription.contains("UDP DNS") &&
                           error.localizedDescription.contains("DoH/DoT"),
                           "\(name) 应在创建套接字前同步提示需要加密 DNS：\(error)")
            }
            try expect(callbacks == 0, "\(name) 被拒绝的 DNS 不应产生异步会话事件")

            // Valid encrypted endpoints are selected without sending a query
            // or opening a socket in this offline self-test.
            for (server, expectedType) in [
                ("https://203.0.113.53/dns-query", "DoH"),
                ("tls://203.0.113.53:853", "DoT")
            ] {
                protected.dnsServers = [server]
                let encrypted = makeRouter(protected)
                try expect(!encrypted.rejectsUDP(host: "8.8.8.8", port: 53),
                           "\(name) 配置 \(expectedType) 后不应拒绝 DNS")
                let flow = try encrypted.makeUDPFlow(
                    host: "8.8.8.8", port: 53, queue: .global(),
                    receive: { _ in }, failure: { _ in })
                defer { flow.cancel() }
                try expect(expectedType == "DoH" ? flow is DoHRoutedDatagram
                                               : flow is DoTRoutedDatagram,
                           "\(name) 的 DNS 应使用 \(expectedType) 而非明文 UDP")
            }

            // Fake-IP answers proxied A queries locally; the synthetic path
            // needs no UDP-capable upstream or DNS network connection.
            protected.dnsServers = []
            protected.fakeIPEnabled = true
            let synthetic = makeRouter(protected)
            try expect(!synthetic.rejectsUDP(host: "8.8.8.8", port: 53),
                       "\(name) 的 fake-IP 查询应由本地响应")
            var answer: Data?
            let fakeFlow = try synthetic.makeUDPFlow(
                host: "8.8.8.8", port: 53, queue: .global(),
                receive: { answer = $0 }, failure: { _ in })
            defer { fakeFlow.cancel() }
            fakeFlow.send(query("www.example.test", type: 1))
            guard let answer,
                  let address = DNSMessageProbe.addressRecords(in: answer).first?.address else {
                throw Failure(text: "\(name) 的 fake-IP DNS 查询未得到本地 A 响应")
            }
            try expect(FakeIPAllocator.isFake(address),
                       "\(name) 的 fake-IP DNS 查询返回了真实网络地址")
        }
    }

    /// Drives the real router: a lookup for a proxied name must come back as a
    /// synthetic address, and connecting to that address must recover the name.
    /// This is the whole point of the feature — without the reverse mapping the
    /// outbound would receive an address instead of a hostname.
    private static func endToEndThroughRouter() throws {
        var profile = Profile()
        profile.fakeIPEnabled = true
        var node = ProxyPolicy(name: "Node", kind: .native)
        node.adapterType = "trojan"
        node.host = "server.example.com"
        node.port = 443
        node.parameters = ["password": "pw"]
        profile.proxies["Node"] = node
        profile.rules = [
            RoutingRule(kind: .domainSuffix("youtube.com"), policy: "Node", sourceLine: 1),
            RoutingRule(kind: .final, policy: "DIRECT", sourceLine: 2),
        ]
        let router = NativePacketRouter(profile: profile, mode: .rule,
                                        globalPolicy: "DIRECT", groupSelections: [:])

        func lookup(_ name: String, type: UInt16) throws -> Data {
            let semaphore = DispatchSemaphore(value: 0)
            var answer: Data?
            let flow = try router.makeUDPFlow(host: "8.8.8.8", port: 53,
                                              queue: .global(),
                                              receive: { answer = $0; semaphore.signal() },
                                              failure: { _ in semaphore.signal() })
            flow.send(query(name, type: type))
            defer { flow.cancel() }
            guard semaphore.wait(timeout: .now() + 5) == .success, let answer else {
                throw Failure(text: "\(name) 的查询没有得到应答")
            }
            return answer
        }

        // A proxied name is answered locally, without touching the network.
        let proxied = try lookup("www.youtube.com", type: 1)
        let records = DNSMessageProbe.addressRecords(in: proxied)
        try expect(records.count == 1, "代理域名应得到 1 条 A 记录")
        let address = records[0].address
        try expect(FakeIPAllocator.isFake(address),
                   "代理域名未得到 fake-IP，实际 \(address)")
        try expect(router.hostname(forFakeAddress: address) == "www.youtube.com",
                   "无法从 fake-IP 反查出域名")

        // Stability: the same name must keep its address, or a connection made
        // after the lookup would resolve to nothing.
        let again = try lookup("www.youtube.com", type: 1)
        try expect(DNSMessageProbe.addressRecords(in: again).first?.address == address,
                   "同一域名两次查询得到不同的 fake-IP")

        // AAAA is answered empty so the client uses the A record.
        let v6 = try lookup("www.youtube.com", type: 28)
        try expect(v6[6] == 0 && v6[7] == 0, "AAAA 应答不应携带记录")
        try expect(v6[3] & 0x0F == 0, "AAAA 应答不应是错误码")

        // always-real-ip keeps a proxied name off the synthetic pool so the
        // client still sees the real A record.
        var filtered = profile
        filtered.alwaysRealIP = ["*.apple.com"]
        filtered.rules.insert(RoutingRule(kind: .domainSuffix("apple.com"),
                                          policy: "Node", sourceLine: 0), at: 0)
        let filteredRouter = NativePacketRouter(profile: filtered, mode: .rule,
                                                globalPolicy: "DIRECT", groupSelections: [:])
        try expect(!filteredRouter.shouldSynthesizeFakeIP(for: "gsp64-ssl.ls.apple.com"),
                   "always-real-ip 通配符未生效")
        try expect(filteredRouter.shouldSynthesizeFakeIP(for: "www.youtube.com"),
                   "未列入 always-real-ip 的代理域名应继续合成")

        // A name that routes DIRECT keeps real resolution: fake-IP must not
        // capture LAN hosts or split-tunnelled destinations.
        try expect(router.hostname(forFakeAddress: "198.19.0.1") == nil,
                   "未分配的地址不应有映射")

        // A routing update must keep the reverse map: live sockets still
        // target the address minted before the reload.
        router.update(profile: profile, mode: .rule, globalPolicy: "DIRECT",
                      groupSelections: [:])
        try expect(router.hostname(forFakeAddress: address) == "www.youtube.com",
                   "配置重载后 fake-IP 反查丢失")
        router.flushFakeIP()
        try expect(router.hostname(forFakeAddress: address) == nil,
                   "flush 后 fake-IP 映射未被清除")
    }

    private static func allocation() throws {
        let allocator = FakeIPAllocator()
        let first = allocator.address(for: "youtube.com")
        try expect(FakeIPAllocator.isFake(first), "分配的地址不在 fake-IP 段内：\(first)")
        try expect(allocator.address(for: "YouTube.com") == first,
                   "同一域名（大小写不同）应得到同一地址")
        try expect(allocator.domain(for: first) == "youtube.com", "反查域名失败")
        let second = allocator.address(for: "example.com")
        try expect(second != first, "不同域名分配到了同一地址")

        // The tunnel's own gateway must never be handed out.
        try expect(!FakeIPAllocator.isFake("198.18.16.1") &&
                   !FakeIPAllocator.isFake("198.18.16.2"),
                   "哈基米隧道网关或 DNS 地址被当作 fake-IP")
        try expect(!FakeIPAllocator.isFake("198.18.0.1"),
                   "Lurge 隧道网关被当作 fake-IP")
        try expect(!FakeIPAllocator.isFake("142.250.1.1"), "真实地址被误判为 fake-IP")
        try expect(allocator.domain(for: "142.250.1.1") == nil, "真实地址不应有域名映射")
        try expect(FakeIPAllocator.ipv4Value("1.2.3.4") == 0x0102_0304, "IPv4 解析错误")
        try expect(FakeIPAllocator.ipv4Value("1.2.3") == nil, "残缺地址未被拒绝")
        try expect(FakeIPAllocator.ipv4Value("1.2.3.999") == nil, "越界八位组未被拒绝")

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hajimi-fakeip-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = directory.appendingPathComponent("virtual-ip.json")
        let firstStore = FakeIPAllocator(persistingAt: store)
        let persisted = firstStore.address(for: "persist.example")
        let restored = FakeIPAllocator(persistingAt: store)
        try expect(restored.domain(for: persisted) == "persist.example",
                   "持久化后未能恢复 fake-IP 映射")
        try expect(restored.address(for: "persist.example") == persisted,
                   "持久化后同一域名得到了不同地址")
    }

    private static func questionParsing() throws {
        guard let a = FakeIPResponder.question(in: query("www.youtube.com", type: 1)) else {
            throw Failure(text: "A 查询未能解析")
        }
        try expect(a.name == "www.youtube.com", "查询名解析错误：\(a.name)")
        try expect(a.kind == .a, "查询类型错误")

        guard let aaaa = FakeIPResponder.question(in: query("example.com", type: 28)) else {
            throw Failure(text: "AAAA 查询未能解析")
        }
        try expect(aaaa.kind == .aaaa, "AAAA 类型识别错误")

        // Anything fake-IP cannot answer must be passed through, not guessed at.
        try expect(FakeIPResponder.question(in: query("example.com", type: 15)) == nil,
                   "MX 查询不应被 fake-IP 接管")
        try expect(FakeIPResponder.question(in: Data([0x12])) == nil, "残缺报文未被拒绝")
        var response = query("example.com", type: 1)
        response[2] = 0x81                       // QR=1 — a response, not a query
        try expect(FakeIPResponder.question(in: response) == nil, "响应报文被当成查询")
        // A compression pointer in a question is malformed; refuse it rather
        // than following it.
        var pointer = query("example.com", type: 1)
        pointer[12] = 0xC0
        try expect(FakeIPResponder.question(in: pointer) == nil, "查询中的压缩指针未被拒绝")
    }

    private static func replyShape() throws {
        let request = query("www.youtube.com", type: 1)
        guard let question = FakeIPResponder.question(in: request),
              let answer = FakeIPResponder.reply(to: request, question: question,
                                                 address: "198.19.0.7") else {
            throw Failure(text: "无法构造应答")
        }
        try expect(answer.count == question.questionEnd + 16,
                   "应答长度错误：\(answer.count)")
        try expect(answer[0] == request[0] && answer[1] == request[1], "事务 ID 未回显")
        try expect(answer[2] & 0x80 != 0, "QR 位未置位")
        try expect(answer[6] == 0 && answer[7] == 1, "ANCOUNT 应为 1")
        try expect(answer[10] == 0 && answer[11] == 0, "ARCOUNT 未清零")
        try expect(Array(answer.suffix(4)) == [198, 19, 0, 7], "应答中的地址错误")

        // AAAA for a proxied name answers NOERROR with no records, so the
        // client falls back to the A answer instead of treating the name as
        // nonexistent.
        let v6Request = query("www.youtube.com", type: 28)
        guard let v6Question = FakeIPResponder.question(in: v6Request),
              let empty = FakeIPResponder.reply(to: v6Request, question: v6Question,
                                                address: nil) else {
            throw Failure(text: "无法构造空 AAAA 应答")
        }
        try expect(empty[6] == 0 && empty[7] == 0, "空应答的 ANCOUNT 应为 0")
        try expect(empty[3] & 0x0F == 0, "空应答不应返回错误码（NXDOMAIN 会连 A 一起否定）")
    }

    /// The answer must be readable by the same parser that already populates
    /// the IP→domain map, since that is what consumes real responses.
    private static func roundTripThroughExistingParser() throws {
        let allocator = FakeIPAllocator()
        let address = allocator.address(for: "www.youtube.com")
        let request = query("www.youtube.com", type: 1)
        guard let question = FakeIPResponder.question(in: request),
              let answer = FakeIPResponder.reply(to: request, question: question,
                                                 address: address) else {
            throw Failure(text: "无法构造应答")
        }
        let records = DNSMessageProbe.addressRecords(in: answer)
        try expect(records.count == 1, "既有解析器读出 \(records.count) 条记录，应为 1")
        try expect(records[0].domain == "www.youtube.com",
                   "既有解析器读出的域名错误：\(records[0].domain)")
        try expect(records[0].address == address,
                   "既有解析器读出的地址错误：\(records[0].address)")
    }
}

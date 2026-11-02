import Foundation
import HajimiCore

/// Guarded test entry, never a GUI/Helper launch. All peers must be literals
/// on loopback; ordinary application DNS is carried through fixture proxies.
func runDNSPerformanceLoopbackSmokeCheck() -> Int32 {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    func require(_ value: Bool, _ text: String) throws {
        if !value { throw Failure(text: text) }
    }
    func query(_ id: UInt16, name: String = "cached.example.test", type: UInt16 = 1) -> Data {
        DNSMessageInspection.query(for: name, type: type, id: id)!
    }
    func ednsQuery(_ id: UInt16, aware: Bool = false) -> Data {
        var message = query(id, name: "edns.example.test")
        if aware { message[3] |= 0x20 }
        message[11] = 1
        message.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0])
        return message
    }
    func id(_ message: Data) -> UInt16 {
        UInt16(message[message.startIndex]) << 8 | UInt16(message[message.startIndex + 1])
    }
    func frame(_ message: Data) -> Data {
        Data([UInt8(message.count >> 8), UInt8(message.count & 0xff)]) + message
    }
    do {
        guard let path = ProcessInfo.processInfo.environment["HAJIMI_TEST_PROFILE"] else {
            throw Failure(text: "DNS performance fixture requires HAJIMI_TEST_PROFILE")
        }
        let profile = try ProfileParser.parse(String(contentsOfFile: path, encoding: .utf8))
        try require(profile.dnsLeakProtectionEnabled && !profile.fakeIPEnabled
                    && profile.effectiveEncryptedDNSServers.isEmpty,
                    "Performance fixture requires protected traditional DNS through loopback proxies")
        try require(profile.dnsServers.count == 1 && profile.dnsServers[0].hasPrefix("127.0.0.1:")
                    && UInt16(profile.dnsServers[0].dropFirst("127.0.0.1:".count)).map({ $0 > 0 }) == true,
                    "Performance resolver must be an explicit loopback IP/port")
        try require(profile.proxies["DIRECT"]?.kind == .direct && profile.proxies["REJECT"]?.kind == .reject
                    && Set(profile.proxies.keys).isSubset(of: ["DIRECT", "REJECT", "NodeHTTP", "NodeSOCKS"])
                    && profile.proxyOrder.allSatisfy({ profile.proxies[$0]?.host == "127.0.0.1" })
                    && ["NodeHTTP", "NodeSOCKS"].allSatisfy({ name in
                        guard let node = profile.proxies[name], node.port.map({ $0 > 0 }) == true,
                              node.parameters.isEmpty, node.username == nil, node.password == nil else { return false }
                        let kind: ProxyKind = name == "NodeHTTP" ? .http : .socks5
                        return node.kind == kind
                    }),
                    "Performance fixture must not override reserved policies or configure external peers")
        try require(profile.groups.isEmpty && profile.ruleSetContents.isEmpty
                    && profile.rules.allSatisfy({
                        if case .ruleSet = $0.kind { return false }
                        return true
                    }), "Performance fixture cannot load policy groups or rule sets")
        let rules: [(RuleKind, String)] = [(.domain("blocked.example.test"), "REJECT"),
                                          (.protocolName("UDP"), "NodeHTTP"), (.final, "NodeSOCKS")]
        try require(profile.rules.count == rules.count && zip(profile.rules, rules).allSatisfy({
            $0.0.kind == $0.1.0 && $0.0.policy == $0.1.1
        }), "Performance fixture must use the fixed REJECT/UDP-HTTP/TCP-SOCKS rules")
        for proto in ["UDP", "TCP"] {
            let route = profile.route(for: RequestTarget(host: "127.0.0.1", port: 53, protocolName: proto),
                                      mode: .rule, globalPolicy: "NodeHTTP")
            let expected = proto == "UDP" ? "NodeHTTP" : "NodeSOCKS"
            switch route {
            case .http(let node, _), .socks5(let node, _), .native(let node, _):
                try require(node.name == expected && node.host == "127.0.0.1",
                            "Performance questions must retain their selected fixture proxy")
            default: throw Failure(text: "Performance fixture permits direct DNS instead of its selected proxy")
            }
        }
        let ingress = ProcessInfo.processInfo.environment["HAJIMI_TEST_DNS_INGRESS"] ?? "router"
        try require(["router", "listener"].contains(ingress), "Unknown performance ingress")
        let listener = ingress == "listener" ? try DNSLocalIngressFixture(profile: profile) : nil
        defer { listener?.stop() }
        let router = ingress == "router" ? NativePacketRouter(profile: profile, mode: .rule,
            globalPolicy: "NodeHTTP", groupSelections: [:]) : nil
        let queue = DispatchQueue(label: "app.hajimi.dns.performance-fixture")
        let lock = NSLock(), ready = DispatchSemaphore(value: 0)
        var expected: [UInt16: Data] = [:], replies = Set<UInt16>(), failure: Error?
        let receive: (Data) -> Void = { response in
            lock.lock(); defer { lock.unlock(); ready.signal() }
            guard response.count >= 12, let request = expected[id(response)],
                  DNSMessageInspection.responseMatchesQuery(response, query: request),
                  replies.insert(id(response)).inserted else {
                failure = Failure(text: "Performance UDP reply lost/duplicated its question or client ID"); return
            }
            let question = DNSMessageInspection.singleQuestion(in: request)!
            let expectedCode: UInt8 = question.name == "blocked.example.test" ? 5 : 0
            if response[response.startIndex + 3] & 0x0f != expectedCode {
                failure = Failure(text: "Performance UDP response bypassed REJECT or failed upstream")
            } else if request[request.startIndex + 3] & 0x20 != 0
                        && response[response.startIndex + 3] & 0x20 == 0 {
                failure = Failure(text: "Performance cache lost the selected upstream's AD result")
            } else if question.type == 1 && expectedCode == 0
                        && DNSMessageInspection.addressAnswers(in: response).first?.address != "203.0.113.7" {
                failure = Failure(text: "Performance UDP reply returned the wrong fixture address")
            } else if question.type == 28
                        && DNSMessageInspection.addressAnswers(in: response).first?.address != "2001:db8::7" {
                failure = Failure(text: "Performance IPv6 reply lost the AAAA identity")
            }
        }
        let onFailure: (Error) -> Void = { error in lock.lock(); failure = error; lock.unlock(); ready.signal() }
        func makeFlow(_ sourcePort: UInt16) throws -> NativeRoutedDatagram {
            if let listener { return try listener.makeUDPFlow(queue: queue, receive: receive, failure: onFailure) }
            return try router!.makeUDPFlow(host: "127.0.0.1", port: 53, queue: queue,
                sourceHost: "127.0.0.1", sourcePort: sourcePort, receive: receive, failure: onFailure)
        }
        func batch(_ flow: NativeRoutedDatagram, _ messages: [Data]) throws -> Double {
            lock.lock(); messages.forEach { expected[id($0)] = $0 }; lock.unlock()
            let start = DispatchTime.now().uptimeNanoseconds
            messages.forEach(flow.send)
            for _ in messages {
                try require(ready.wait(timeout: .now() + 8) == .success, "Performance UDP replies timed out")
                lock.lock(); let error = failure; lock.unlock()
                if let error { throw error }
            }
            lock.lock(); let complete = messages.allSatisfy { replies.contains(id($0)) }; lock.unlock()
            try require(complete, "Performance UDP batch did not return every client ID")
            return Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
        }
        let udp = try makeFlow(41000), another = try makeFlow(41001)
        defer { udp.cancel(); another.cancel() }
        let cold = try batch(udp, (0..<32).map { query(UInt16(1000 + $0)) })
        let warm = try batch(udp, (0..<32).map { query(UInt16(2000 + $0)) })
        let crossClient = try batch(another, (0..<32).map { query(UInt16(3000 + $0)) })
        _ = try batch(udp, [query(4000, type: 28), query(4001, type: 28)])
        for identifier: UInt16 in [4100, 4101] {
            _ = try batch(udp, [query(identifier, name: "txt.example.test", type: 16)])
        }
        for identifier: UInt16 in [4200, 4201] {
            _ = try batch(udp, [query(identifier, name: "zero.example.test")])
        }
        _ = try batch(udp, [query(4300, name: "blocked.example.test")])
        _ = try batch(udp, [ednsQuery(4400)])
        _ = try batch(udp, [ednsQuery(4401)])
        _ = try batch(udp, [ednsQuery(4500, aware: true)])
        _ = try batch(udp, [ednsQuery(4501, aware: true)])

        let attached = DispatchSemaphore(value: 0)
        var connection: Result<NativeOutboundByteStream, Error>?
        let connected: (Result<NativeOutboundByteStream, Error>) -> Void = { connection = $0; attached.signal() }
        if let listener { listener.connectTCP(queue: queue, completion: connected) }
        else { router!.connectTCP(host: "127.0.0.1", port: 53, queue: queue, completion: connected) }
        try require(attached.wait(timeout: .now() + 3) == .success, "Performance TCP DNS gateway did not attach")
        let stream = try connection!.get(); defer { stream.cancel() }
        let messages = (0..<32).map { query(UInt16(5000 + $0)) }
        let wire = messages.reduce(into: Data()) { $0.append(frame($1)) }
        let sent = DispatchSemaphore(value: 0); var sendError: Error?
        stream.send(wire) { sendError = $0; sent.signal() }
        try require(sent.wait(timeout: .now() + 3) == .success, "Performance TCP writes timed out")
        if let sendError { throw sendError }
        var buffer = Data(), tcpReplies = Set<UInt16>()
        while tcpReplies.count < messages.count {
            let read = DispatchSemaphore(value: 0)
            var bytes: Data?, ended = false, error: Error?
            stream.receive(maximum: 4096) { bytes = $0; ended = $1; error = $2; read.signal() }
            try require(read.wait(timeout: .now() + 8) == .success, "Performance TCP replies timed out")
            if let error { throw error }
            if let bytes { buffer.append(bytes) }
            try require(buffer.count <= 256 * 1024, "Performance TCP response buffer exceeded its bound")
            while buffer.count >= 2 {
                let length = Int(buffer[buffer.startIndex]) << 8 | Int(buffer[buffer.startIndex + 1])
                try require(length >= 12, "Performance TCP response frame was malformed")
                if buffer.count < length + 2 { break }
                let response = Data(buffer.dropFirst(2).prefix(length)); buffer = Data(buffer.dropFirst(length + 2))
                guard let request = messages.first(where: { id($0) == id(response) }) else {
                    throw Failure(text: "Performance TCP reply belonged to another client")
                }
                try require(tcpReplies.insert(id(response)).inserted
                            && DNSMessageInspection.responseMatchesQuery(response, query: request)
                            && response[response.startIndex + 3] & 0x0f == 0
                            && DNSMessageInspection.addressAnswers(in: response).first?.address == "203.0.113.7",
                            "Performance TCP client received a duplicate/invalid/failed response")
            }
            try require(!ended || tcpReplies.count == messages.count, "Performance TCP stream ended early")
        }
        try require(buffer.isEmpty, "Performance TCP stream contained trailing responses")
        print(String(format: "DNS performance loopback passed: ingress=%@, 32-query cold %.2f ms, warm %.2f ms, cross-client warm %.2f ms; UDP=107, TCP=32, strict REJECT/TTL-zero/non-A/EDNS/AD checks",
            ingress, cold, warm, crossClient))
        return 0
    } catch {
        FileHandle.standardError.write(Data("DNS performance loopback failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

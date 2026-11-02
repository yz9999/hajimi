import Foundation
import Darwin
import HajimiCore

/// Real UDP/TCP ingress with a deliberately broken loopback TLS resolver.
/// The Python peer observes every traditional DNS question: application names
/// must not reach it even when DoH fails and leak protection is opted out.
func runDNSSplitLoopbackSmokeCheck() -> Int32 {
    struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }
    func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(message: message) }
    }
    func query(_ name: String, type: UInt16) throws -> Data {
        guard let bytes = DNSMessageInspection.query(for: name, type: type, id: 4242) else {
            throw Failure(message: "Cannot encode split DNS fixture question")
        }
        return bytes
    }
    func frame(_ bytes: Data) -> Data {
        var framed = Data([UInt8(bytes.count >> 8), UInt8(bytes.count & 255)])
        framed.append(bytes); return framed
    }
    do {
        let environment = ProcessInfo.processInfo.environment
        guard let path = environment["HAJIMI_TEST_PROFILE"] else {
            throw Failure(message: "Split loopback fixture requires HAJIMI_TEST_PROFILE")
        }
        var profile = try ProfileParser.parse(String(contentsOfFile: path, encoding: .utf8))
        let bootstrapHost = "doh.bootstrap.selftest.invalid"
        try require(!profile.fakeIPEnabled && profile.dnsServers.count == 1
                    && profile.dnsServers[0].hasPrefix("127.0.0.1:"), "Split fixture needs literal loopback traditional DNS")
        guard let traditional = TraditionalDNSServer(profile.dnsServers[0]),
              traditional.host == "127.0.0.1", profile.encryptedDNSServers.count == 1,
              let endpoint = DoHEndpoint(profile.encryptedDNSServers[0], allowUnresolvedHost: true) else {
            throw Failure(message: "Invalid split DNS fixture configuration")
        }
        try require(endpoint.host == bootstrapHost && endpoint.needsBootstrap
                    && endpoint.url.path == "/dns-query", "Split fixture requires the fixed, unpinned DoH test hostname")
        try require(profile.proxyOrder.isEmpty && profile.groups.isEmpty
                    && profile.proxies["DIRECT"]?.kind == .direct && profile.proxies["REJECT"]?.kind == .reject
                    && profile.proxies.values.allSatisfy({ [.direct, .reject].contains($0.kind) }),
                    "Split fixture must not configure external proxies or override DIRECT/REJECT semantics")
        // Do not let a broken implementation open the pinned public default,
        // or connect to a non-loopback address returned by the test peer.
        profile.rules.insert(RoutingRule(kind: .logicalAnd([
            .logicalNot(.ipCIDR("127.0.0.0/8")), .logicalNot(.domain(bootstrapHost))
        ]), policy: "REJECT", sourceLine: 0), at: 0)
        try require(profile.rules.contains {
            $0.kind == .domain("blocked.example.test") && $0.policy == "REJECT"
        }, "Split fixture requires an explicit QNAME REJECT rule")
        let ingress = environment["HAJIMI_TEST_DNS_INGRESS"] ?? "router"
        try require(["router", "listener"].contains(ingress), "Unknown split DNS fixture ingress")
        let listener = ingress == "listener" ? try DNSLocalIngressFixture(profile: profile, encryptedSplit: true) : nil
        defer { listener?.stop() }
        let router = ingress == "router" ? NativePacketRouter(profile: profile, mode: .rule,
                                                             globalPolicy: "DIRECT", groupSelections: [:]) : nil
        let queue = DispatchQueue(label: "app.hajimi.dns.split-loopback")
        let udpQueries = try [query("split-udp-a.example.test", type: 1),
                              query("split-udp-txt.example.test", type: 16),
                              query("blocked.example.test", type: 65)]
        let tcpQueries = try [query("split-tcp-a.example.test", type: 1),
                              query("split-tcp-txt.example.test", type: 16)]
        let lock = NSLock(), received = DispatchSemaphore(value: 0)
        var udpAnswers: [String: Data] = [:], udpError: Error?
        let receive: (Data) -> Void = { answer in
            lock.lock(); defer { lock.unlock(); received.signal() }
            guard let request = udpQueries.first(where: {
                DNSMessageInspection.responseMatchesQuery(answer, query: $0)
            }), let question = DNSMessageInspection.singleQuestion(in: request),
                  udpAnswers[question.name] == nil else {
                udpError = Failure(message: "Mismatched or duplicate split UDP answer"); return
            }
            udpAnswers[question.name] = answer
        }
        let failure: (Error) -> Void = { error in
            lock.lock(); udpError = error; lock.unlock(); received.signal()
        }
        let flow: any NativeRoutedDatagram
        if let listener { flow = try listener.makeUDPFlow(queue: queue, receive: receive, failure: failure) }
        else {
            flow = try router!.makeUDPFlow(host: "127.0.0.1", port: 53, queue: queue,
                                          receive: receive, failure: failure)
        }
        defer { flow.cancel() }
        udpQueries.forEach(flow.send)
        for _ in udpQueries {
            try require(received.wait(timeout: .now() + 12) == .success, "Split UDP queries exceeded their deadline")
            lock.lock(); let error = udpError; lock.unlock()
            if let error { throw error }
        }
        lock.lock(); let answers = udpAnswers; lock.unlock()
        for request in udpQueries {
            let question = DNSMessageInspection.singleQuestion(in: request)!
            guard let answer = answers[question.name] else { throw Failure(message: "Missing split UDP answer") }
            try require(answer[answer.startIndex + 3] & 15 == (question.name == "blocked.example.test" ? 5 : 2),
                        "Split UDP must return REFUSED for REJECT and SERVFAIL for failed DoH, never plaintext success")
            try require(DNSMessageInspection.addressAnswers(in: answer).isEmpty, "Failed DoH returned an application address")
        }

        let connected = DispatchSemaphore(value: 0)
        var connection: Result<any NativeOutboundByteStream, Error>?
        let completion: (Result<any NativeOutboundByteStream, Error>) -> Void = { result in
            lock.lock(); connection = result; lock.unlock(); connected.signal()
        }
        if let listener { listener.connectTCP(queue: queue, completion: completion) }
        else { router!.connectTCP(host: "127.0.0.1", port: 53, queue: queue, completion: completion) }
        try require(connected.wait(timeout: .now() + 3) == .success, "Split TCP ingress did not connect")
        lock.lock(); let result = connection; lock.unlock()
        let stream = try result!.get()
        defer { stream.cancel() }
        let wire = tcpQueries.reduce(into: Data()) { $0.append(frame($1)) }
        let written = DispatchSemaphore(value: 0)
        var writeError: Error?
        stream.send(wire) { error in
            lock.lock(); writeError = error; lock.unlock(); written.signal()
        }
        try require(written.wait(timeout: .now() + 3) == .success, "Split TCP ingress write did not complete")
        lock.lock(); let sendError = writeError; lock.unlock()
        if let sendError { throw sendError }
        var buffer = Data(), answered = Set<String>(), receivedBytes = 0
        let deadline = Date().addingTimeInterval(12)
        while answered.count < tcpQueries.count && Date() < deadline {
            let read = DispatchSemaphore(value: 0)
            var chunk: Data?, ended = false, readError: Error?
            stream.receive(maximum: 3) { bytes, complete, error in
                lock.lock(); chunk = bytes; ended = complete; readError = error; lock.unlock(); read.signal()
            }
            try require(read.wait(timeout: .now() + 12) == .success, "Split TCP reply timed out")
            lock.lock(); let bytes = chunk, complete = ended, error = readError; lock.unlock()
            if let error { throw error }
            if let bytes { buffer.append(bytes); receivedBytes += bytes.count }
            try require(receivedBytes <= 2 * 65_537, "Split TCP response exceeded its wire budget")
            while buffer.count >= 2 {
                let length = Int(buffer[buffer.startIndex]) << 8 | Int(buffer[buffer.startIndex + 1])
                try require(length >= 12, "Split TCP response frame was undersized")
                guard buffer.count >= length + 2 else { break }
                let answer = Data(buffer.dropFirst(2).prefix(length))
                buffer = Data(buffer.dropFirst(length + 2))
                guard let request = tcpQueries.first(where: {
                    DNSMessageInspection.responseMatchesQuery(answer, query: $0)
                }), let question = DNSMessageInspection.singleQuestion(in: request) else {
                    throw Failure(message: "Split TCP response ID/QNAME mismatch")
                }
                try require(answer[answer.startIndex + 3] & 15 == 2 && answered.insert(question.name).inserted,
                            "Failed DoH did not return one SERVFAIL per TCP query")
                try require(DNSMessageInspection.addressAnswers(in: answer).isEmpty, "Failed DoH returned a TCP application address")
            }
            if complete && answered.count < tcpQueries.count { throw Failure(message: "Split TCP ingress closed early") }
        }
        try require(answered.count == tcpQueries.count && buffer.isEmpty, "Split TCP responses were missing or truncated")

        // This is the only other authorized plaintext purpose. Its hostname
        // is fixed inside the resolver, not accepted from any application.
        let connectivity = TraditionalDNSBootstrapResolver(servers: profile.traditionalDNSServers, allowedDoHHosts: [])
        defer { connectivity.cancel() }
        let tested = DispatchSemaphore(value: 0)
        var connectivityResult: Result<[String], Error>?
        connectivity.testConnectivity(queue: queue) { result in
            lock.lock(); connectivityResult = result; lock.unlock(); tested.signal()
        }
        try require(tested.wait(timeout: .now() + 8) == .success, "Fixed traditional DNS connectivity test timed out")
        lock.lock(); let testResult = connectivityResult; lock.unlock()
        try require(try testResult!.get() == ["127.0.0.1"], "Traditional DNS did not return the fixed connectivity fixture address")
        print("DNS split loopback checks passed: ingress=\(ingress), protection=\(profile.dnsLeakProtectionEnabled), UDP=3, TCP=2, encrypted failure without plaintext fallback")
        return 0
    } catch {
        FileHandle.standardError.write(Data("DNS split loopback fixture failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

import Foundation
import Darwin
import HajimiCore

/// Explicit loopback-only fixture entry. No helper, system proxy or tunnel is
/// involved, and a malformed fixture is rejected before any DNS traffic.
func runDNSLoopbackSmokeCheck() -> Int32 {
    struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }
    func require(_ value: Bool, _ text: String) throws {
        if !value { throw Failure(message: text) }
    }
    func query(_ name: String, _ type: UInt16) throws -> Data {
        guard let query = DNSMessageInspection.query(for: name, type: type, id: 4242) else {
            throw Failure(message: "DNS fixture query encoding failed")
        }
        return query
    }
    func frame(_ query: Data) -> Data {
        var bytes = Data([UInt8(query.count >> 8), UInt8(query.count & 0xff)])
        bytes.append(query); return bytes
    }
    do {
        guard let path = ProcessInfo.processInfo.environment["HAJIMI_TEST_PROFILE"] else {
            throw Failure(message: "Loopback DNS fixture requires HAJIMI_TEST_PROFILE")
        }
        let profile = try ProfileParser.parse(String(contentsOfFile: path, encoding: .utf8))
        try require(profile.dnsLeakProtectionEnabled && !profile.fakeIPEnabled,
                    "Fixture must enable DNS protection without fake-IP")
        try require(profile.dnsServers.count == 1 && profile.dnsServers[0].hasPrefix("127.0.0.1:"),
                    "Fixture resolver must be an explicit loopback address")
        let rawPort = profile.dnsServers[0].dropFirst("127.0.0.1:".count)
        try require(UInt16(rawPort).map { $0 > 0 } == true, "Invalid fixture DNS port")
        try require(profile.proxyOrder.allSatisfy {
            profile.proxies[$0]?.host == "127.0.0.1"
        }, "Fixture proxies must all be loopback literals")
        let udpQueries = try [query("udp-a.example.test", 1), query("udp-txt.example.test", 16),
                              query("udp-https.example.test", 65), query("blocked.example.test", 65)]
        let tcpQueries = try [query("tcp-a.example.test", 1), query("tcp-txt.example.test", 16)]
        for message in Array(udpQueries.prefix(3)) + tcpQueries {
            let question = DNSMessageInspection.singleQuestion(in: message)!
            let selected = profile.route(for: RequestTarget(host: question.name, port: 53, protocolName: "UDP"),
                                         mode: .rule, globalPolicy: "NodeHTTP")
            switch selected {
            case .http, .socks5, .native: break
            default: throw Failure(message: "Fixture must proxy every allowed query; no direct bootstrap permitted")
            }
        }
        let ingress = ProcessInfo.processInfo.environment["HAJIMI_TEST_DNS_INGRESS"] ?? "router"
        try require(["router", "listener"].contains(ingress), "Unknown fixture ingress")
        let listenerFixture = ingress == "listener" ? try DNSLocalIngressFixture(profile: profile) : nil
        defer { listenerFixture?.stop() }
        let router = ingress == "router" ? NativePacketRouter(profile: profile, mode: .rule,
                                        globalPolicy: "NodeHTTP", groupSelections: [:]) : nil
        let queue = DispatchQueue(label: "app.hajimi.dns.loopback-fixture")
        let lock = NSLock(), received = DispatchSemaphore(value: 0)
        var udpReplies: [String: Data] = [:], udpError: Error?
        let receive: (Data) -> Void = { answer in
                let matched = udpQueries.first { DNSMessageInspection.responseMatchesQuery(answer, query: $0) }
                lock.lock()
                if let matched, let question = DNSMessageInspection.singleQuestion(in: matched) {
                    if udpReplies[question.name] != nil { udpError = Failure(message: "Duplicate UDP DNS reply") }
                    else { udpReplies[question.name] = answer }
                } else { udpError = Failure(message: "UDP DNS ID/QNAME/QTYPE mismatch") }
                lock.unlock(); received.signal()
            }
        let failure: (Error) -> Void = { error in
            lock.lock(); udpError = error; lock.unlock(); received.signal()
        }
        let flow: any NativeRoutedDatagram
        if let listenerFixture {
            flow = try listenerFixture.makeUDPFlow(queue: queue, receive: receive, failure: failure)
        } else {
            flow = try router!.makeUDPFlow(host: "127.0.0.1", port: 53, queue: queue,
                                          receive: receive, failure: failure)
        }
        defer { flow.cancel() }
        udpQueries.forEach(flow.send)
        for _ in udpQueries {
            try require(received.wait(timeout: .now() + 8) == .success, "Proxied UDP DNS fixture timed out")
            lock.lock(); let error = udpError; lock.unlock()
            if let error { throw error }
        }
        lock.lock(); let replies = udpReplies; lock.unlock()
        for message in udpQueries {
            let question = DNSMessageInspection.singleQuestion(in: message)!
            guard let answer = replies[question.name] else { throw Failure(message: "Missing UDP DNS reply") }
            let expectedCode: UInt8 = question.name == "blocked.example.test" ? 5 : 0
            try require(answer[answer.startIndex + 3] & 0x0f == expectedCode, "UDP DNS response code mismatch")
            if question.type == 1 {
                try require(DNSMessageInspection.addressAnswers(in: answer).first?.address == "203.0.113.7",
                            "UDP DNS did not return the fixture's real A record")
            }
        }

        let connected = DispatchSemaphore(value: 0)
        var connection: Result<NativeOutboundByteStream, Error>?
        let connectCompletion: (Result<NativeOutboundByteStream, Error>) -> Void = {
            connection = $0; connected.signal()
        }
        if let listenerFixture { listenerFixture.connectTCP(queue: queue, completion: connectCompletion) }
        else { router!.connectTCP(host: "127.0.0.1", port: 53, queue: queue, completion: connectCompletion) }
        try require(connected.wait(timeout: .now() + 2) == .success, "TCP DNS gateway did not attach")
        let stream = try connection!.get()
        defer { stream.cancel() }
        let wire = tcpQueries.reduce(into: Data()) { $0.append(frame($1)) }
        let writes = DispatchGroup()
        var writeError: Error?
        for chunk in [Data(wire.prefix(1)), Data(wire.dropFirst(1).prefix(7)), Data(wire.dropFirst(8))] {
            writes.enter()
            stream.send(chunk) { error in
                if let error { lock.lock(); writeError = error; lock.unlock() }
                writes.leave()
            }
        }
        try require(writes.wait(timeout: .now() + 2) == .success, "TCP DNS fragmented writes timed out")
        lock.lock(); let error = writeError; lock.unlock()
        if let error { throw error }
        var buffer = Data(), tcpReplies: [String: Data] = [:], totalBytes = 0
        let deadline = Date().addingTimeInterval(8)
        while tcpReplies.count < tcpQueries.count && Date() < deadline {
            let read = DispatchSemaphore(value: 0)
            var data: Data?, ended = false, readError: Error?
            stream.receive(maximum: 3) { data = $0; ended = $1; readError = $2; read.signal() }
            try require(read.wait(timeout: .now() + 8) == .success, "TCP DNS reply timed out")
            if let readError { throw readError }
            if let data { buffer.append(data); totalBytes += data.count }
            try require(totalBytes <= 256 * 1_024, "TCP DNS fixture reply budget exceeded")
            while buffer.count >= 2 {
                let length = Int(buffer[buffer.startIndex]) << 8 | Int(buffer[buffer.startIndex + 1])
                try require(length >= 12, "Malformed TCP DNS reply frame")
                if buffer.count < length + 2 { break }
                let answer = Data(buffer.dropFirst(2).prefix(length))
                buffer = Data(buffer.dropFirst(length + 2))
                guard let request = tcpQueries.first(where: {
                    DNSMessageInspection.responseMatchesQuery(answer, query: $0)
                }), let question = DNSMessageInspection.singleQuestion(in: request) else {
                    throw Failure(message: "TCP DNS ID/QNAME/QTYPE mismatch")
                }
                try require(tcpReplies[question.name] == nil && answer[answer.startIndex + 3] & 0x0f == 0,
                            "Duplicate or failed TCP DNS reply")
                tcpReplies[question.name] = answer
            }
            if ended && tcpReplies.count < tcpQueries.count { throw Failure(message: "TCP DNS stream ended early") }
        }
        try require(tcpReplies.count == tcpQueries.count && buffer.isEmpty, "TCP DNS framing did not complete")
        print("DNS loopback checks passed: ingress=\(ingress), UDP=4, TCP=2, repeated IDs, A/TXT/HTTPS, strict REJECT")
        return 0
    } catch {
        FileHandle.standardError.write(Data("DNS loopback fixture failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

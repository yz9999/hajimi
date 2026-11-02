import Foundation
import Darwin
import HajimiCore

private struct DNSIngressFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

private func dnsIngressAddress(_ port: UInt16) -> sockaddr_in {
    var value = sockaddr_in()
    value.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); value.sin_family = sa_family_t(AF_INET)
    value.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1")); value.sin_port = port.bigEndian
    return value
}

/// Shutdown wakes an outstanding read; close waits for its fd borrow to end,
/// so a canceled syscall never operates on a subsequently reused descriptor.
private final class DNSIngressSocket {
    private let lock = NSLock()
    private var fd: Int32, borrowers = 0, closing = false
    var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closing }
    init(_ type: Int32) throws {
        fd = Darwin.socket(AF_INET, type, 0)
        guard fd >= 0 else { throw DNSIngressFailure("Cannot allocate loopback fixture socket") }
        var readTimeout = timeval(tv_sec: 12, tv_usec: 0), writeTimeout = timeval(tv_sec: 3, tv_usec: 0)
        var noSignal: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &readTimeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &writeTimeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(fd); fd = -1; closing = true; throw DNSIngressFailure("Cannot bound fixture socket I/O")
        }
    }
    func withFD<T>(_ operation: (Int32) throws -> T) throws -> T {
        lock.lock()
        guard !closing, fd >= 0 else { lock.unlock(); throw DNSIngressFailure("Fixture socket closed") }
        let descriptor = fd; borrowers += 1; lock.unlock()
        defer {
            lock.lock(); borrowers -= 1
            if closing && borrowers == 0 && fd >= 0 { Darwin.close(fd); fd = -1 }
            lock.unlock()
        }
        return try operation(descriptor)
    }
    func connect(_ port: UInt16, bindFirst: Bool = false) throws {
        try withFD { descriptor in
            var address = dnsIngressAddress(bindFirst ? 0 : port)
            if bindFirst {
                let result = withUnsafePointer(to: &address) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                guard result == 0 else { throw DNSIngressFailure("Cannot bind dynamic loopback UDP source") }
                address = dnsIngressAddress(port)
            }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard result == 0 else { throw DNSIngressFailure("Cannot connect loopback fixture peer") }
        }
    }
    func write(_ data: Data, datagram: Bool = false) throws {
        try withFD { descriptor in
            var offset = 0
            while offset < data.count {
                let count = data.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress!.advanced(by: offset), data.count - offset, 0) }
                if count < 0 && errno == EINTR { continue }
                guard count > 0, !datagram || count == data.count else { throw DNSIngressFailure("Fixture send failed") }
                offset += count
            }
        }
    }
    func read(_ maximum: Int, exactly: Bool = false) throws -> Data {
        try withFD { descriptor in
            var bytes = [UInt8](repeating: 0, count: maximum), offset = 0
            repeat {
                let count = bytes.withUnsafeMutableBytes { Darwin.recv(descriptor, $0.baseAddress!.advanced(by: offset), maximum - offset, 0) }
                if count < 0 && errno == EINTR { continue }
                guard count >= 0 else { throw DNSIngressFailure("Fixture receive failed or exceeded its 12-second deadline") }
                if count == 0 { break }; offset += count
            } while exactly && offset < maximum
            if exactly && offset != maximum { throw DNSIngressFailure("Truncated fixture SOCKS handshake") }
            return Data(bytes.prefix(offset))
        }
    }
    func socks(_ port: UInt16, command: UInt8) throws -> Data {
        try connect(port); try write(Data([5, 1, 0]))
        guard try read(2, exactly: true) == Data([5, 0]) else { throw DNSIngressFailure("SOCKS fixture rejected no-auth") }
        try write(command == 3 ? Data([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]) : Data([5, 1, 0, 1, 127, 0, 0, 1, 0, 53]))
        let reply = try read(10, exactly: true)
        guard reply.prefix(4) == Data([5, 0, 0, 1]) else { throw DNSIngressFailure("SOCKS fixture command failed") }
        return reply
    }
    func cancel() {
        lock.lock(); defer { lock.unlock() }
        guard !closing else { return }; closing = true
        if fd >= 0 { _ = Darwin.shutdown(fd, SHUT_RDWR); if borrowers == 0 { Darwin.close(fd); fd = -1 } }
    }
    deinit { cancel() }
}

/// Guarded CLI fixture only: actual HTTP/SOCKS listeners and BSD clients, all
/// on loopback. This never creates a helper, changes DNS or starts an App UI.
internal final class DNSLocalIngressFixture {
    private let engine = ProxyEngine(), lock = NSLock()
    private let setupQueue = DispatchQueue(label: "app.hajimi.dns.fixture-setup")
    private var cancelActions: [() -> Void] = [], stopped = false
    init(profile: Profile, encryptedSplit: Bool = false) throws {
        guard (profile.dnsLeakProtectionEnabled || encryptedSplit), profile.dnsServers.count == 1,
              profile.dnsServers[0].hasPrefix("127.0.0.1:"),
              UInt16(profile.dnsServers[0].dropFirst("127.0.0.1:".count)).map({ $0 > 0 }) == true,
              profile.proxies["DIRECT"]?.kind == .direct, profile.proxies["REJECT"]?.kind == .reject,
              profile.proxies.values.allSatisfy({ [.direct, .reject].contains($0.kind) || $0.host == "127.0.0.1" }) else {
            throw DNSIngressFailure("Listener fixture requires protected literal-loopback DNS and proxy peers")
        }
        let splitHost = "doh.bootstrap.selftest.invalid"
        if encryptedSplit {
            guard !profile.fakeIPEnabled, profile.encryptedDNSServers.count == 1,
                  let endpoint = DoHEndpoint(profile.encryptedDNSServers[0], allowUnresolvedHost: true),
                  endpoint.host == splitHost, endpoint.needsBootstrap else {
                throw DNSIngressFailure("Split fixture requires the fixed test DoH hostname with deferred bootstrap")
            }
        } else if !profile.effectiveEncryptedDNSServers.isEmpty {
            throw DNSIngressFailure("Traditional listener fixture cannot contact an encrypted endpoint")
        }
        var local = profile
        local.httpListen = ListenAddress(host: "127.0.0.1", port: 0); local.socksListen = ListenAddress(host: "127.0.0.1", port: 0)
        let deny = "DNSFixtureDeny-\(UUID().uuidString)"
        local.proxies[deny] = ProxyPolicy(name: deny, kind: .reject)
        let denyNonLoopback: RuleKind = encryptedSplit
            ? .logicalAnd([.logicalNot(.ipCIDR("127.0.0.0/8")), .logicalNot(.domain(splitHost))])
            : .logicalNot(.ipCIDR("127.0.0.0/8"))
        local.rules.insert(RoutingRule(kind: denyNonLoopback, policy: deny, sourceLine: 0), at: 0)
        let ready = DispatchSemaphore(value: 0), statusLock = NSLock()
        var failure: String?
        engine.onStatus = { status in
            switch status {
            case .running: ready.signal()
            case .failed(let text): statusLock.lock(); failure = text; statusLock.unlock(); ready.signal()
            default: break
            }
        }
        do {
            try engine.start(profile: local, mode: .rule, globalPolicy: "NodeHTTP")
            guard ready.wait(timeout: .now() + 3) == .success else { throw DNSIngressFailure("Local SOCKS listener startup exceeded 3 seconds") }
            statusLock.lock(); let error = failure; statusLock.unlock()
            if let error { throw DNSIngressFailure(error) }
        } catch { engine.stop(); throw error }
    }
    private func retain(_ action: @escaping () -> Void) throws {
        lock.lock()
        guard !stopped, cancelActions.count < 8 else { lock.unlock(); action(); throw DNSIngressFailure("Fixture closed or flow limit reached") }
        cancelActions.append(action); lock.unlock()
    }
    func makeUDPFlow(queue: DispatchQueue, receive: @escaping (Data) -> Void,
                     failure: @escaping (Error) -> Void) throws -> any NativeRoutedDatagram {
        let flow = try DNSIngressDatagram(port: engine.activeSOCKSListen.port, queue: queue, receive: receive, failure: failure)
        try retain(flow.cancel); flow.start(); return flow
    }
    func connectTCP(queue: DispatchQueue, completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        setupQueue.async {
            do {
                let socket = try DNSIngressSocket(SOCK_STREAM)
                _ = try socket.socks(self.engine.activeSOCKSListen.port, command: 1)
                let stream = DNSIngressStream(socket: socket, queue: queue)
                try self.retain(stream.cancel); queue.async { completion(.success(stream)) }
            } catch { queue.async { completion(.failure(error)) } }
        }
    }
    func stop() {
        lock.lock(); guard !stopped else { lock.unlock(); return }; stopped = true
        let actions = cancelActions; cancelActions.removeAll(); lock.unlock()
        actions.forEach { $0() }; engine.stop()
    }
    deinit { stop() }
}

private final class DNSIngressDatagram: NativeRoutedDatagram {
    private let control: DNSIngressSocket, socket: DNSIngressSocket, queue: DispatchQueue
    private let readQueue = DispatchQueue(label: "app.hajimi.dns.fixture-udp-read")
    private let writeQueue = DispatchQueue(label: "app.hajimi.dns.fixture-udp-write"), lock = NSLock()
    private let receive: (Data) -> Void, failure: (Error) -> Void
    private let header = Data([0, 0, 0, 1, 127, 0, 0, 1, 0, 53])
    private var writes = 0, bytes = 0
    init(port: UInt16, queue: DispatchQueue, receive: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) throws {
        control = try DNSIngressSocket(SOCK_STREAM); socket = try DNSIngressSocket(SOCK_DGRAM)
        self.queue = queue; self.receive = receive; self.failure = failure
        let reply = try control.socks(port, command: 3)
        guard reply.prefix(8) == Data([5, 0, 0, 1, 127, 0, 0, 1]) else { throw DNSIngressFailure("UDP relay is not literal loopback") }
        let relay = UInt16(reply[8]) << 8 | UInt16(reply[9])
        guard relay > 0 else { throw DNSIngressFailure("UDP relay returned port zero") }
        try socket.connect(relay, bindFirst: true)
    }
    func start() {
        readQueue.async {
            while !self.socket.isClosed {
                do {
                    let packet = try self.socket.read(65_535)
                    guard packet.count >= 10, packet.prefix(10) == self.header else { throw DNSIngressFailure("Malformed SOCKS UDP DNS reply") }
                    let answer = Data(packet.dropFirst(10))
                    self.queue.async { if !self.socket.isClosed { self.receive(answer) } }
                } catch {
                    if !self.socket.isClosed { self.queue.async { self.failure(error) } }
                    self.cancel(); return
                }
            }
        }
    }
    func send(_ data: Data) {
        lock.lock()
        guard !socket.isClosed, writes < 64, data.count <= 65_497, data.count <= 256 * 1_024 - bytes else { lock.unlock(); return }
        writes += 1; bytes += data.count; lock.unlock()
        writeQueue.async {
            defer { self.lock.lock(); self.writes -= 1; self.bytes -= data.count; self.lock.unlock() }
            do { try self.socket.write(self.header + data, datagram: true) }
            catch { if !self.socket.isClosed { self.queue.async { self.failure(error) }; self.cancel() } }
        }
    }
    func cancel() { socket.cancel(); control.cancel() }
    deinit { cancel() }
}

private final class DNSIngressStream: NativeOutboundByteStream {
    private let socket: DNSIngressSocket, queue: DispatchQueue, lock = NSLock()
    private let readQueue = DispatchQueue(label: "app.hajimi.dns.fixture-tcp-read")
    private let writeQueue = DispatchQueue(label: "app.hajimi.dns.fixture-tcp-write")
    private var writes = 0, bytes = 0, reading = false
    init(socket: DNSIngressSocket, queue: DispatchQueue) { self.socket = socket; self.queue = queue }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        guard !socket.isClosed, writes < 64, data.count <= 256 * 1_024 - bytes else {
            lock.unlock(); completion(DNSIngressFailure("TCP fixture write queue closed or full")); return
        }
        writes += 1; bytes += data.count; lock.unlock()
        writeQueue.async {
            let result = Result { try self.socket.write(data) }
            self.lock.lock(); self.writes -= 1; self.bytes -= data.count; self.lock.unlock()
            self.queue.async {
                if case .failure(let error) = result { completion(error) } else { completion(nil) }
            }
        }
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock()
        guard maximum > 0, !reading else { lock.unlock(); completion(nil, true, DNSIngressFailure("Invalid concurrent fixture read")); return }
        reading = true; lock.unlock()
        readQueue.async {
            let result = Result { try self.socket.read(min(maximum, 65_536)) }
            self.lock.lock(); self.reading = false; self.lock.unlock()
            self.queue.async {
                switch result {
                case .success(let data): completion(data, data.isEmpty, nil)
                case .failure(let error): completion(nil, true, error)
                }
            }
        }
    }
    func cancel() { socket.cancel() }
    deinit { cancel() }
}

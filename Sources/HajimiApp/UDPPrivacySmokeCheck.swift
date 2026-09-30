import Foundation
import Darwin
import HajimiCore

/// One SOCKS UDP association survives three routing changes. A stale DIRECT
/// socket must not send a packet after a TLS-only policy takes over.
func runLocalUDPPolicySwitchSelfTest() throws {
    let echo = try UDPSwitchEcho()
    echo.start()
    let engine = ProxyEngine()
    defer { engine.stop(); echo.stop() }

    let httpPort = try unusedUDPSwitchTCPPort()
    let socksPort = try unusedUDPSwitchTCPPort(excluding: [httpPort])
    let fixture = """
    [General]
    http-listen = 127.0.0.1:\(httpPort)
    socks5-listen = 127.0.0.1:\(socksPort)
    [Proxy]
    SecureSOCKS = socks5-tls, 127.0.0.1, 65534, sni=localhost
    SecureHTTP = https, 127.0.0.1, 65534, sni=localhost
    [Rule]
    FINAL,DIRECT
    """
    let profile = try ProfileParser.parse(fixture)
    guard profile.proxies["SecureSOCKS"]?.parameters["tls"] == "true",
          profile.proxies["SecureHTTP"]?.parameters["tls"] == "true" else {
        throw UDPSwitchError("TLS-only fixture was not parsed as TLS")
    }

    let ready = DispatchSemaphore(value: 0)
    let statusLock = NSLock()
    var result: ProxyEngineStatus?
    engine.onStatus = { status in
        switch status {
        case .running, .failed:
            statusLock.lock()
            result = status
            statusLock.unlock()
            ready.signal()
        default: break
        }
    }
    try engine.start(profile: profile, mode: .direct, globalPolicy: "DIRECT")
    guard ready.wait(timeout: .now() + 8) == .success else {
        throw UDPSwitchError("HTTP/SOCKS listeners did not become ready")
    }
    statusLock.lock()
    let startResult = result
    statusLock.unlock()
    guard case .running? = startResult else {
        throw UDPSwitchError("HTTP/SOCKS listener failed: \(String(describing: startResult))")
    }

    // The five privacy-switch probes use the same UDP socket, target, payload
    // and SOCKS ASSOCIATE. The independent ownership check adds a second source
    // to this association without weakening the stale-flow regression.
    let client = try UDPSwitchClient(socksPort: engine.activeSOCKSListen.port)
    defer { client.close() }
    let payload = Data("hajimi-udp-private-route".utf8)
    var packet = Data([0, 0, 0, 1, 127, 0, 0, 1,
                       UInt8(echo.port >> 8), UInt8(echo.port & 0xff)])
    packet.append(payload)

    try expectDirectUDPEcho(packet: packet, client: client, echo: echo,
                            phase: "initial DIRECT")
    try expectOwnedUDPReplies(primary: client, echo: echo)
    try expectBlockedUDP(packet: packet, client: client, echo: echo, engine: engine,
                         policy: "SecureSOCKS")
    engine.updateRouting(mode: .direct, globalPolicy: "DIRECT")
    try expectDirectUDPEcho(packet: packet, client: client, echo: echo,
                            phase: "DIRECT after SOCKS5-TLS")
    try expectBlockedUDP(packet: packet, client: client, echo: echo, engine: engine,
                         policy: "SecureHTTP")
    engine.updateRouting(mode: .direct, globalPolicy: "DIRECT")
    try expectDirectUDPEcho(packet: packet, client: client, echo: echo,
                            phase: "DIRECT after HTTPS")
    print("Local UDP policy-switch privacy self-test passed: DIRECT/SOCKS5-TLS/HTTPS, source-owned replies")
}

private func expectOwnedUDPReplies(primary: UDPSwitchClient, echo: UDPSwitchEcho) throws {
    // This must share the UDP ASSOCIATE endpoint, not open a second control
    // connection: the original bug reused the first client's flow by target.
    let secondary = try UDPSwitchClient(sharingAssociation: primary)
    defer { secondary.close() }
    func packet(_ payload: String) -> Data {
        var frame = Data([0, 0, 0, 1, 127, 0, 0, 1,
                          UInt8(echo.port >> 8), UInt8(echo.port & 0xff)])
        frame.append(Data(payload.utf8)); return frame
    }
    let first = packet("hajimi-udp-source-A"), second = packet("hajimi-udp-source-B")
    let before = echo.receivedCount
    try primary.send(first)
    try secondary.send(second)
    guard try primary.receive(timeoutMilliseconds: 2_000) == first,
          try secondary.receive(timeoutMilliseconds: 2_000) == second else {
        throw UDPSwitchError("DIRECT: UDP sources sharing one target received missing or crossed replies")
    }
    guard echo.receivedCount == before + 2,
          try primary.receive(timeoutMilliseconds: 100) == nil,
          try secondary.receive(timeoutMilliseconds: 100) == nil else {
        throw UDPSwitchError("DIRECT: UDP ownership produced duplicated or misdelivered packets")
    }
    // Only the secondary source socket closes. The original association and
    // primary source must remain usable; closing the shared TCP would be a
    // different lifecycle event that legitimately cancels both UDP clients.
    secondary.close()
    try expectDirectUDPEcho(packet: packet("hajimi-udp-source-A-after-B-close"),
                            client: primary, echo: echo, phase: "DIRECT after secondary source close")
    guard try primary.receive(timeoutMilliseconds: 100) == nil else {
        throw UDPSwitchError("DIRECT: closed secondary source left a reply on the surviving client")
    }
}

private func expectDirectUDPEcho(packet: Data, client: UDPSwitchClient,
                                 echo: UDPSwitchEcho, phase: String) throws {
    let before = echo.receivedCount
    try client.send(packet)
    guard let response = try client.receive(timeoutMilliseconds: 2_000), response == packet else {
        throw UDPSwitchError("\(phase): missing or malformed SOCKS5 UDP echo")
    }
    guard echo.receivedCount == before + 1 else {
        throw UDPSwitchError("\(phase): loopback origin saw an unexpected number of packets")
    }
}

private func expectBlockedUDP(packet: Data, client: UDPSwitchClient,
                              echo: UDPSwitchEcho, engine: ProxyEngine,
                              policy: String) throws {
    engine.updateRouting(mode: .proxy, globalPolicy: policy)
    let before = echo.receivedCount
    try client.send(packet)
    let response = try client.receive(timeoutMilliseconds: 450)
    guard response == nil else {
        throw UDPSwitchError("\(policy): a TLS-only upstream leaked a UDP response")
    }
    // An incorrectly retained DIRECT flow can enqueue packets asynchronously.
    Thread.sleep(forTimeInterval: 0.05)
    guard echo.receivedCount == before else {
        throw UDPSwitchError("\(policy): plaintext UDP reached the origin after policy switch")
    }
}

private struct UDPSwitchError: LocalizedError {
    let text: String
    init(_ text: String) { self.text = text }
    var errorDescription: String? { text }
}

private func udpSwitchLoopback(_ port: UInt16) -> sockaddr_in {
    var result = sockaddr_in()
    result.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    result.sin_family = sa_family_t(AF_INET)
    result.sin_port = port.bigEndian
    result.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    return result
}

/// Bound and immediately released; ProxyEngine uses its actual active port if
/// macOS assigns a different one because another listener wins the race.
private func unusedUDPSwitchTCPPort(excluding: Set<UInt16> = []) throws -> UInt16 {
    for _ in 0..<8 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw UDPSwitchError("cannot allocate TCP test port") }
        defer { Darwin.close(fd) }
        var address = udpSwitchLoopback(0)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw UDPSwitchError("cannot bind TCP test port") }
        var actual = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let found = withUnsafeMutablePointer(to: &actual) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &length)
            }
        }
        let port = UInt16(bigEndian: actual.sin_port)
        guard found == 0, port != 0 else { throw UDPSwitchError("cannot read TCP test port") }
        if !excluding.contains(port) { return port }
    }
    throw UDPSwitchError("cannot find two distinct TCP listener ports")
}

private final class UDPSwitchEcho {
    private let lock = NSLock()
    private let finished = DispatchSemaphore(value: 0)
    private var fd: Int32 = -1
    private var running = false
    private var started = false
    private var count = 0
    private(set) var port: UInt16 = 0

    var receivedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return count
    }

    init() throws {
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { throw UDPSwitchError("cannot open UDP echo socket") }
        fd = descriptor
        do {
            var address = udpSwitchLoopback(0)
            let bound = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bound == 0 else { throw UDPSwitchError("cannot bind UDP echo socket") }
            var timeout = timeval(tv_sec: 0, tv_usec: 200_000)
            guard setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                             socklen_t(MemoryLayout<timeval>.size)) == 0 else {
                throw UDPSwitchError("cannot set UDP echo receive timeout")
            }
            var actual = sockaddr_in()
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let found = withUnsafeMutablePointer(to: &actual) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(descriptor, $0, &length)
                }
            }
            guard found == 0 else { throw UDPSwitchError("cannot read UDP echo port") }
            port = UInt16(bigEndian: actual.sin_port)
        } catch {
            Darwin.close(descriptor)
            fd = -1
            throw error
        }
    }

    func start() {
        lock.lock()
        running = true
        started = true
        lock.unlock()
        Thread.detachNewThread { [self] in
            defer { finished.signal() }
            receiveLoop()
        }
    }

    func stop() {
        lock.lock()
        let wasStarted = started
        started = false
        running = false
        lock.unlock()
        if wasStarted { _ = finished.wait(timeout: .now() + 1) }
        if fd >= 0 { Darwin.close(fd); fd = -1 }
    }

    private func receiveLoop() {
        while true {
            lock.lock()
            let active = running
            lock.unlock()
            guard active else { return }
            var buffer = [UInt8](repeating: 0, count: 4_096)
            var sender = sockaddr_in()
            var senderLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let received = withUnsafeMutablePointer(to: &sender) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.recvfrom(fd, &buffer, buffer.count, 0, $0, &senderLength)
                }
            }
            if received < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { continue }
                return
            }
            let payload = Data(buffer.prefix(received))
            lock.lock()
            count += 1
            lock.unlock()
            payload.withUnsafeBytes { bytes in
                withUnsafePointer(to: &sender) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        _ = Darwin.sendto(fd, bytes.baseAddress, bytes.count, 0, $0, senderLength)
                    }
                }
            }
        }
    }
}

private final class UDPSwitchClient {
    private var controlFD: Int32 = -1
    private var udpFD: Int32 = -1
    private var relay = udpSwitchLoopback(0)

    init(socksPort: UInt16) throws {
        var succeeded = false
        defer { if !succeeded { close() } }
        controlFD = socket(AF_INET, SOCK_STREAM, 0)
        guard controlFD >= 0 else { throw UDPSwitchError("cannot open SOCKS control socket") }
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        guard setsockopt(controlFD, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                         socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            throw UDPSwitchError("cannot set SOCKS control receive timeout")
        }
        var remote = udpSwitchLoopback(socksPort)
        let connected = withUnsafePointer(to: &remote) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(controlFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { throw UDPSwitchError("cannot connect SOCKS listener") }
        try writeControl(Data([0x05, 0x01, 0x00]))
        guard try readControl(2) == Data([0x05, 0x00]) else {
            throw UDPSwitchError("SOCKS listener rejected no-auth handshake")
        }
        try writeControl(Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        let association = try readControl(10)
        guard association.prefix(8) == Data([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1]) else {
            throw UDPSwitchError("SOCKS UDP ASSOCIATE returned an invalid loopback address")
        }
        let relayPort = UInt16(association[8]) << 8 | UInt16(association[9])
        guard relayPort != 0 else { throw UDPSwitchError("SOCKS UDP relay port is zero") }
        relay = udpSwitchLoopback(relayPort)

        udpFD = try Self.openUDPSocket()
        succeeded = true
    }

    init(sharingAssociation source: UDPSwitchClient) throws {
        guard source.controlFD >= 0, source.udpFD >= 0 else {
            throw UDPSwitchError("cannot share a closed SOCKS UDP association")
        }
        relay = source.relay
        // controlFD stays -1: this source neither owns nor closes the shared
        // association's TCP lifetime.
        udpFD = try Self.openUDPSocket()
    }

    private static func openUDPSocket() throws -> Int32 {
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { throw UDPSwitchError("cannot open UDP client socket") }
        var local = udpSwitchLoopback(0)
        let bound = withUnsafePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            Darwin.close(descriptor); throw UDPSwitchError("cannot bind UDP client socket")
        }
        return descriptor
    }

    func close() {
        if udpFD >= 0 { Darwin.close(udpFD); udpFD = -1 }
        if controlFD >= 0 { Darwin.close(controlFD); controlFD = -1 }
    }

    deinit { close() }

    func send(_ packet: Data) throws {
        let sent = packet.withUnsafeBytes { bytes in
            withUnsafePointer(to: &relay) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.sendto(udpFD, bytes.baseAddress, bytes.count, 0, $0,
                                  socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == packet.count else { throw UDPSwitchError("SOCKS UDP send failed") }
    }

    func receive(timeoutMilliseconds: Int32) throws -> Data? {
        var descriptor = pollfd(fd: udpFD, events: Int16(POLLIN), revents: 0)
        let ready = Darwin.poll(&descriptor, 1, timeoutMilliseconds)
        if ready == 0 { return nil }
        guard ready > 0 else { throw UDPSwitchError("SOCKS UDP receive poll failed") }
        guard descriptor.revents & Int16(POLLIN) != 0 else { return nil }
        var bytes = [UInt8](repeating: 0, count: 4_096)
        let count = Darwin.recv(udpFD, &bytes, bytes.count, 0)
        guard count > 0 else { throw UDPSwitchError("SOCKS UDP response was unreadable") }
        return Data(bytes.prefix(count))
    }

    private func writeControl(_ bytes: Data) throws {
        var position = 0
        while position < bytes.count {
            let written = bytes.withUnsafeBytes {
                Darwin.send(controlFD, $0.baseAddress!.advanced(by: position),
                            bytes.count - position, 0)
            }
            guard written > 0 else { throw UDPSwitchError("SOCKS control write failed") }
            position += written
        }
    }

    private func readControl(_ length: Int) throws -> Data {
        var result = [UInt8](repeating: 0, count: length)
        var position = 0
        while position < length {
            let count = result.withUnsafeMutableBytes {
                Darwin.recv(controlFD, $0.baseAddress!.advanced(by: position),
                            length - position, 0)
            }
            guard count > 0 else { throw UDPSwitchError("SOCKS control read failed") }
            position += count
        }
        return Data(result)
    }
}

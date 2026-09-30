import Foundation
import Darwin
import Network
import HajimiCore

/// Isolated, small loopback fixtures. Never calls the installed Helper,
/// modifies system preferences, or loads the user's profile.
func runIngressSecuritySelfTest() throws {
    try checkRejectedDNS()
    if let failure = ProxyEngine.listenerLifecycleSelfTest() { throw IngressSecurityError(failure) }
    if let failure = ProxyEngine.requestHeaderBoundarySelfTest() { throw IngressSecurityError(failure) }
    if let failure = ProxyEngine.socksUDPResourceSelfTest() { throw IngressSecurityError(failure) }
    for http in [false, true] {
        do {
            try checkControllerGeneration(http: http)
            try checkControllerAdmission(http: http)
            try checkBlockedControllerDeadline(http: http)
        } catch {
            throw IngressSecurityError("\(http ? "HTTP" : "command") controller: \(error.localizedDescription)")
        }
    }
    try checkHTTPAdmission()
    print("Ingress security regression passed: DNS REJECT, listener epochs/header bounds, UDP resource/peer isolation, controller epochs/admission/deadlines, HTTP admission/deadline")
}

private func checkRejectedDNS() throws {
    let upstream = try SecurityTCPReservation()
    let queue = DispatchQueue(label: "app.hajimi.security-test.dns")
    let plain = "127.0.0.1:\(upstream.port)"
    for (servers, fakeIP) in [(plain, false), (plain, true),
                             ("https://127.0.0.1:\(upstream.port)/dns-query, " + plain, false),
                             ("tls://127.0.0.1:\(upstream.port), " + plain, false)] {
        let profile = try ProfileParser.parse("""
        [General]
        dns-server = \(servers)
        fake-ip = \(fakeIP)
        [Rule]
        FINAL,REJECT
        """)
        let router = NativePacketRouter(profile: profile, mode: .rule,
                                         globalPolicy: "DIRECT", groupSelections: [:])
        try securityExpect(profile.fakeIPEnabled == fakeIP && profile.dnsServers.count == (servers == plain ? 1 : 2),
                           "DNS fixture was not parsed with its requested resolver/fake-IP options")
        try securityExpect(router.rejectsUDP(host: "127.0.0.1", port: 53),
                           "UDP DNS REJECT was not advertised, including resolver/fake-IP exceptions")
        var rejectedUDP = false
        do {
            let flow = try router.makeUDPFlow(host: "127.0.0.1", port: 53, queue: queue,
                                              receive: { _ in }, failure: { _ in })
            flow.cancel()
        } catch {
            rejectedUDP = error.localizedDescription.contains("策略拒绝")
        }
        try securityExpect(rejectedUDP, "UDP DNS REJECT created a resolver or direct flow")
        let completed = DispatchSemaphore(value: 0)
        var rejectedTCP = false
        router.connectTCP(host: "127.0.0.1", port: 53, queue: queue) { result in
            switch result {
            case .success(let stream): stream.cancel()
            case .failure(let error): rejectedTCP = error.localizedDescription.contains("策略拒绝")
            }
            completed.signal()
        }
        try securityExpect(completed.wait(timeout: .now() + 3) == .success && rejectedTCP,
                           "TCP DNS REJECT connected to the remapped loopback upstream")
    }
}

private func controllerTestProfile(port: UInt16, key: String, http: Bool) -> Profile {
    var profile = Profile()
    let address = ListenAddress(host: "127.0.0.1", port: port)
    if http { profile.httpAPI = address; profile.httpAPIKey = key }
    else { profile.externalController = address; profile.externalControllerKey = key }
    return profile
}

private func controllerTestRequest(http: Bool, key: String = "") throws -> Data {
    if http {
        let body = "{\"mode\":\"direct\"}"
        let auth = key.isEmpty ? "" : "X-Key: \(key)\r\n"
        return Data("POST /v1/outbound HTTP/1.1\r\n\(auth)Content-Length: \(body.utf8.count)\r\n\r\n\(body)".utf8)
    }
    guard let frame = ExternalController.encodeFrame([
        "command": "set", "key": key, "args": ["outbound-mode=direct"]
    ]) else { throw IngressSecurityError("cannot encode fixture command") }
    return frame
}

private func checkControllerGeneration(http: Bool) throws {
    let controller = ExternalController(requestTimeout: 5)
    let backend = SecurityRecordingBackend()
    controller.attach(backend: backend)
    defer { controller.stop() }
    let oldPort = try securityUnusedPort()
    controller.start(profile: controllerTestProfile(port: oldPort, key: "fixture-key", http: http))
    try securityAwait("controller did not publish its ready endpoint") {
        (http ? controller.httpListen : controller.commandListen)?.port == oldPort
    }
    let old = try securityConnect(port: oldPort)
    defer { Darwin.close(old) }
    // A keyless mutation remains incomplete under the old, keyed listener.
    let request = try controllerTestRequest(http: http)
    let prefix = http ? 10 : 2
    try securitySend(old, data: Data(request.prefix(prefix)))
    try securityAwait("old controller client was not registered") { controller.activeClientCount == 1 }

    let newPort = try securityUnusedPort(excluding: [oldPort])
    controller.start(profile: controllerTestProfile(port: newPort, key: "", http: http))
    try securityExpect(controller.activeClientCount == 0, "reload did not revoke accepted clients synchronously")
    // Cancellation can race a send at the OS boundary; either send result is
    // legitimate, but the old connection must never mutate the new backend.
    try? securitySend(old, data: Data(request.dropFirst(prefix)))
    try securityPeerClosed(old, description: "old controller connection survived reload")
    try securityExpect(backend.mutationCount == 0, "old keyed epoch inherited a new empty key")

    let fresh = try securityConnect(port: newPort)
    defer { Darwin.close(fresh) }
    try securityExpect((http ? controller.httpListen : controller.commandListen)?.port == newPort,
                       "old listener state replaced the new ready endpoint")
    try securitySend(fresh, data: request)
    try securityAwait("new loopback controller did not retain keyless compatibility") { backend.mutationCount == 1 }
    _ = try securityReadReply(fresh)
    try securityAwait("finished controller client retained admission slot") { controller.activeClientCount == 0 }
    controller.stop()
    try securityExpect(controller.httpListen == nil && controller.commandListen == nil,
                       "stopped controller still advertised a ready endpoint")
}

private func checkControllerAdmission(http: Bool) throws {
    let controller = ExternalController(maximumClients: 2, requestTimeout: 0.5)
    let backend = SecurityRecordingBackend()
    controller.attach(backend: backend)
    defer { controller.stop() }
    let port = try securityUnusedPort()
    controller.start(profile: controllerTestProfile(port: port, key: "fixture-key", http: http))
    let first = try securityConnect(port: port)
    defer { Darwin.close(first) }
    try securityAwait("first controller slot was not admitted") { controller.activeClientCount == 1 }
    let second = try securityConnect(port: port)
    defer { Darwin.close(second) }
    try securityAwait("second controller slot was not admitted") { controller.activeClientCount == 2 }
    let overflow = try securityConnect(port: port)
    defer { Darwin.close(overflow) }
    try securityPeerClosed(overflow, description: "controller exceeded its active-client limit")
    try securityExpect(controller.activeClientCount <= 2, "controller admission counter exceeded bound")
    // No authentication or EOF is supplied. Both idle requests must expire.
    try securityAwait("controller idle clients did not expire") { controller.activeClientCount == 0 }
    try securityPeerClosed(first, description: "controller idle socket did not close")
    try securityPeerClosed(second, description: "controller idle socket did not close")

    let fresh = try securityConnect(port: port)
    defer { Darwin.close(fresh) }
    try securitySend(fresh, data: controllerTestRequest(http: http, key: "fixture-key"))
    try securityAwait("controller admission was not released after timeout") { backend.mutationCount == 1 }
    _ = try securityReadReply(fresh)

    if !http {
        let malformed = try securityConnect(port: port)
        defer { Darwin.close(malformed) }
        try securitySend(malformed, data: Data([255, 255, 255, 255]))
        try securityPeerClosed(malformed, description: "oversized command prefix was not rejected")
    }
}

private func checkHTTPAdmission() throws {
    let engine = ProxyEngine(maximumInboundConnections: 2, httpHandshakeTimeout: 0.5)
    defer { engine.stop() }
    let ready = DispatchSemaphore(value: 0)
    let statusLock = NSLock()
    var status: ProxyEngineStatus?
    engine.onStatus = { value in
        if value == .running || { if case .failed = value { return true }; return false }() {
            statusLock.lock(); status = value; statusLock.unlock(); ready.signal()
        }
    }
    var profile = Profile()
    let httpPort = try securityUnusedPort()
    profile.httpListen = ListenAddress(host: "127.0.0.1", port: httpPort)
    profile.socksListen = ListenAddress(host: "127.0.0.1", port: try securityUnusedPort(excluding: [httpPort]))
    try engine.start(profile: profile, mode: .direct, globalPolicy: "DIRECT")
    try securityExpect(ready.wait(timeout: .now() + 5) == .success, "HTTP fixture listener startup timed out")
    statusLock.lock(); let startup = status; statusLock.unlock()
    try securityExpect(startup == .running, "HTTP fixture listener failed: \(String(describing: startup))")

    let first = try securityConnect(port: engine.activeHTTPListen.port)
    defer { Darwin.close(first) }
    try securityAwait("first HTTP slot not admitted") { engine.inboundConnectionCount == 1 }
    let second = try securityConnect(port: engine.activeHTTPListen.port)
    defer { Darwin.close(second) }
    try securitySend(second, data: Data("GET http://127.0.0.1:9/ HTTP/1.1\r\n".utf8))
    try securityAwait("partial HTTP header was not retained for bounded handshake") { engine.inboundConnectionCount == 2 }
    let overflow = try securityConnect(port: engine.activeHTTPListen.port)
    defer { Darwin.close(overflow) }
    try securityPeerClosed(overflow, description: "HTTP exceeded its active-connection limit")
    try securityAwait("partial/idle HTTP handshakes did not expire") { engine.inboundConnectionCount == 0 }
    try securityPeerClosed(first, description: "idle HTTP socket retained after deadline")
    try securityPeerClosed(second, description: "partial HTTP socket retained after deadline")
}

private func checkBlockedControllerDeadline(http: Bool) throws {
    let controller = ExternalController(maximumClients: 2, requestTimeout: 0.2)
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let backend = SecurityRecordingBackend(blockSnapshot: {
        entered.signal()
        _ = release.wait(timeout: .now() + 10)
    })
    controller.attach(backend: backend)
    defer { release.signal(); controller.stop() }
    let port = try securityUnusedPort()
    controller.start(profile: controllerTestProfile(port: port, key: "fixture-key", http: http))
    let blocked = try securityConnect(port: port)
    defer { Darwin.close(blocked) }
    let request = http
        ? Data("GET /v1/outbound HTTP/1.1\r\nX-Key: fixture-key\r\n\r\n".utf8)
        : ExternalController.encodeFrame(["command": "environment", "key": "fixture-key"])!
    try securitySend(blocked, data: request)
    try securityExpect(entered.wait(timeout: .now() + 2) == .success, "blocking backend fixture was not reached")
    try securityPeerClosed(blocked, description: "blocked backend postponed the controller deadline", timeout: 1.5)
    // Expiration closes the socket independently, but must retain the slot
    // while the serial callback is blocked, bounding pending canceled work.
    try securityExpect(controller.activeClientCount == 1, "blocked cleanup released its admission slot too early")
    let second = try securityConnect(port: port)
    defer { Darwin.close(second) }
    try securityAwait("accept queue stalled behind backend") { controller.activeClientCount == 2 }
    let overflow = try securityConnect(port: port)
    defer { Darwin.close(overflow) }
    try securityPeerClosed(overflow, description: "blocked backend bypassed admission cap", timeout: 1.5)
    try securityExpect(controller.activeClientCount == 2, "expired callbacks accumulated beyond the admission bound")

    // Socket cancellation is not callback cleanup. Repeated reloads while a
    // backend is blocked must not admit another full batch in each epoch.
    var usedPorts: Set<UInt16> = [port]
    var currentPort = port
    for _ in 0..<3 {
        currentPort = try securityUnusedPort(excluding: usedPorts)
        usedPorts.insert(currentPort)
        controller.start(profile: controllerTestProfile(port: currentPort, key: "fixture-key", http: http))
        try securityExpect(controller.activeClientCount == 0
                            && controller.pendingCleanupClientCount == 2
                            && controller.admittedClientCount == 2,
                           "reload released blocked cleanup slots or exceeded the cross-generation cap")
        let denied = try securityConnect(port: currentPort)
        do {
            defer { Darwin.close(denied) }
            try securityPeerClosed(denied, description: "reload bypassed pending-cleanup admission", timeout: 1.5)
        }
        try securityExpect(controller.activeClientCount == 0 && controller.admittedClientCount == 2,
                           "a revoked epoch admitted unbounded callback work")
    }
    release.signal()
    try securityAwait("controller failed to reclaim expired/retired callback slots") {
        controller.admittedClientCount == 0
    }
    let fresh = try securityConnect(port: currentPort)
    defer { Darwin.close(fresh) }
    try securitySend(fresh, data: controllerTestRequest(http: http, key: "fixture-key"))
    try securityAwait("retired callback cleanup did not restore admission") { backend.mutationCount == 1 }
    _ = try securityReadReply(fresh)
}

private struct IngressSecurityError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { "Ingress security check: " + message }
}

private func securityExpect(_ condition: Bool, _ message: String) throws {
    guard condition else { throw IngressSecurityError(message) }
}

private func securityAwait(_ message: String, _ condition: () -> Bool) throws {
    let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
    repeat {
        if condition() { return }
        usleep(10_000)
    } while DispatchTime.now().uptimeNanoseconds < deadline
    throw IngressSecurityError(message)
}

private final class SecurityTCPReservation {
    let descriptor: Int32
    let port: UInt16
    init() throws {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw IngressSecurityError("socket failed") }
        descriptor = fd
        // Network.framework may retain a canceled endpoint briefly. Match its
        // reuse policy, rather than making a bind-and-close probe monopolize
        // the test port until the framework's namespace catches up.
        var reuse: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, Darwin.listen(fd, 4) == 0 else {
            Darwin.close(fd); throw IngressSecurityError("loopback bind/listen failed")
        }
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) }
        }
        guard result == 0 else { Darwin.close(fd); throw IngressSecurityError("getsockname failed") }
        port = UInt16(bigEndian: address.sin_port)
    }
    deinit { Darwin.close(descriptor) }
}

private func securityUnusedPort(excluding: Set<UInt16> = []) throws -> UInt16 {
    for _ in 0..<20 {
        // A raw BSD bind/close can leave the port unavailable to
        // Network.framework even when there is no listening descriptor.
        // Allocate in the same framework as the fixture and wait for actual
        // cancellation before handing the port to its next listener.
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let ready = DispatchSemaphore(value: 0)
        let cancelled = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var boundPort: UInt16?
        var failure: Error?
        listener.newConnectionHandler = { $0.cancel() }
        listener.stateUpdateHandler = { [weak listener] state in
            switch state {
            case .ready:
                lock.lock(); boundPort = listener?.port?.rawValue; lock.unlock()
                ready.signal()
            case .failed(let error):
                lock.lock(); failure = error; lock.unlock()
                ready.signal()
            case .cancelled: cancelled.signal()
            default: break
            }
        }
        listener.start(queue: DispatchQueue(label: "app.hajimi.security-test.allocate-port"))
        let readyResult = ready.wait(timeout: .now() + 3)
        listener.cancel()
        let cancelResult = cancelled.wait(timeout: .now() + 3)
        lock.lock(); let port = boundPort, error = failure; lock.unlock()
        try securityExpect(readyResult == .success && cancelResult == .success && error == nil,
                           "loopback fixture port allocation failed: \(error?.localizedDescription ?? "timeout")")
        guard let port, port != 0 else { throw IngressSecurityError("fixture port was not assigned") }
        if !excluding.contains(port) { return port }
    }
    throw IngressSecurityError("could not allocate distinct loopback ports")
}

private func securityConnect(port: UInt16) throws -> Int32 {
    let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
    repeat {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw IngressSecurityError("client socket failed") }
        var noSignal: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: 0, tv_usec: 200_000)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result == 0 { return fd }
        Darwin.close(fd); usleep(10_000)
    } while DispatchTime.now().uptimeNanoseconds < deadline
    throw IngressSecurityError("loopback client connect failed on \(port)")
}

private func securitySend(_ fd: Int32, data: Data) throws {
    try data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let count = Darwin.send(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw IngressSecurityError("fixture send failed") }
            offset += count
        }
    }
}

private func securityReadReply(_ fd: Int32) throws -> Data {
    var output = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
    repeat {
        let count = buffer.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress!, $0.count, 0) }
        if count > 0 { output.append(contentsOf: buffer.prefix(count)); continue }
        if count == 0 { break }
        if errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { break }
    } while DispatchTime.now().uptimeNanoseconds < deadline
    try securityExpect(!output.isEmpty, "expected controller reply was empty")
    return output
}

private func securityPeerClosed(_ fd: Int32, description: String, timeout: TimeInterval = 3) throws {
    var byte: UInt8 = 0
    let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeout * 1_000_000_000)
    repeat {
        let count = Darwin.recv(fd, &byte, 1, 0)
        if count == 0 { return }
        if count < 0 && [ECONNRESET, ENOTCONN, EPIPE, EBADF].contains(errno) { return }
        if count > 0 { throw IngressSecurityError(description + " (unexpected reply)") }
    } while DispatchTime.now().uptimeNanoseconds < deadline
    throw IngressSecurityError(description)
}

private final class SecurityRecordingBackend: ExternalControllerBackend {
    private let lock = NSLock()
    private var mutations = 0
    private let blockSnapshot: (() -> Void)?
    init(blockSnapshot: (() -> Void)? = nil) { self.blockSnapshot = blockSnapshot }
    var mutationCount: Int { lock.lock(); defer { lock.unlock() }; return mutations }
    private func record() { lock.lock(); mutations += 1; lock.unlock() }
    func controllerSnapshot() -> ExternalControllerSnapshot {
        blockSnapshot?()
        return ExternalControllerSnapshot(mode: .rule, globalPolicy: "DIRECT", groupSelections: [:],
            profile: Profile(), engineStatus: .stopped,
            httpListen: ListenAddress(host: "127.0.0.1", port: 0),
            socksListen: ListenAddress(host: "127.0.0.1", port: 0), uploaded: 0, downloaded: 0,
            startedAt: nil, active: [], recent: [], systemProxyEnabled: false, enhancedModeEnabled: false)
    }
    func controllerSetOutboundMode(_ mode: OutboundMode) { record() }
    func controllerSetGlobalPolicy(_ name: String) -> Bool { record(); return true }
    func controllerSetGroupSelection(group: String, policy: String) -> Bool { record(); return true }
    func controllerSetSystemProxy(_ enabled: Bool) { record() }
    func controllerSetEnhancedMode(_ enabled: Bool) { record() }
    func controllerReloadProfile() { record() }
    func controllerFlushDNS() { record() }
    func controllerFlushFakeIP() { record() }
    func controllerKillRequest(id: String) -> Bool { record(); return true }
    func controllerTestGroup(_ name: String) { record() }
}

import Foundation
import Darwin
import HajimiCore

/// Loopback high-concurrency regression check for the forwarding data plane.
/// It verifies correctness and that traffic notifications remain coalesced.
func runProxyPerformanceSmokeCheck() -> Int32 {
    let echo = LoopbackEchoServer()
    // This explicit stress fixture permits the advertised 1,024 test clients;
    // ordinary application instances retain their smaller admission default.
    let engine = ProxyEngine(maximumInboundConnections: 1_024)
    do {
        try echo.start()
        var profile = Profile()
        let eventLock = NSLock()
        var trafficEvents = 0
        engine.onEvent = { event in
            if case .traffic = event {
                eventLock.lock(); trafficEvents += 1; eventLock.unlock()
            }
        }

        // Picking a free port is inherently racy: a probe only proves the port
        // was unused a moment ago, and anything on the machine may take it
        // before the listener binds. Rather than pretend the probe is
        // authoritative, treat a bind collision as expected and retry with
        // fresh ports — otherwise this check fails spuriously on a busy
        // machine or in CI.
        var httpPort: UInt16 = 0
        var socksPort: UInt16 = 0
        var lastFailure: String?
        var listening = false
        for attempt in 0..<5 {
            httpPort = try unusedLoopbackPort()
            socksPort = try unusedLoopbackPort(excluding: [httpPort, echo.port])
            profile.httpListen = ListenAddress(host: "127.0.0.1", port: httpPort)
            profile.socksListen = ListenAddress(host: "127.0.0.1", port: socksPort)
            if attempt == 0 {
                try verifyListenerFreeRouter(profile: profile, echoPort: echo.port)
            }
            let ready = DispatchSemaphore(value: 0)
            let failureLock = NSLock()
            var startupFailure: String?
            engine.onStatus = { status in
                if status == .running { ready.signal() }
                if case .failed(let message) = status {
                    failureLock.lock(); startupFailure = message; failureLock.unlock()
                    ready.signal()
                }
            }
            try engine.start(profile: profile, mode: .direct, globalPolicy: "DIRECT")
            guard ready.wait(timeout: .now() + 10) == .success else {
                throw PerformanceCheckError("代理监听器启动超时")
            }
            failureLock.lock(); let failure = startupFailure; failureLock.unlock()
            guard let failure else {
                httpPort = engine.activeHTTPListen.port
                socksPort = engine.activeSOCKSListen.port
                listening = true
                break
            }
            lastFailure = "\(failure) (HTTP \(httpPort), SOCKS \(socksPort), Echo \(echo.port))"
            engine.stop()
        }
        guard listening else {
            throw PerformanceCheckError(lastFailure ?? "代理监听器启动失败")
        }

        let clients = ProcessInfo.processInfo.environment["HAJIMI_PERF_CLIENTS"].flatMap(Int.init) ?? 64
        guard (1...1_024).contains(clients) else { throw PerformanceCheckError("HAJIMI_PERF_CLIENTS 必须为 1…1024") }
        let iterations = 16
        let chunkSize = 32 * 1024
        let totalBytes = clients * iterations * chunkSize * 2
        let group = DispatchGroup()
        let failures = LockedFailures()
        let roundTrips = LockedRoundTrips()
        let residentBefore = performanceResidentBytes()
        let started = DispatchTime.now().uptimeNanoseconds
        for index in 0..<clients {
            group.enter()
            Thread.detachNewThread {
                autoreleasepool {
                    defer { group.leave() }
                    do {
                        try runSOCKSEchoClient(socksPort: socksPort, targetPort: echo.port,
                                               iterations: iterations, chunkSize: chunkSize,
                                               seed: UInt8(truncatingIfNeeded: index), samples: roundTrips)
                    } catch {
                        failures.append(error.localizedDescription)
                    }
                }
            }
        }
        guard group.wait(timeout: .now() + 25) == .success else {
            throw PerformanceCheckError("高并发转发测试超时")
        }
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000
        if let first = failures.first { throw PerformanceCheckError(first) }
        usleep(400_000)
        eventLock.lock(); let finalTrafficEvents = trafficEvents; eventLock.unlock()
        guard finalTrafficEvents <= clients * 8 else {
            throw PerformanceCheckError("流量事件未有效合并：\(finalTrafficEvents) 次")
        }
        let throughput = Double(totalBytes) / max(0.001, elapsed) / 1_048_576
        print(String(format: "Proxy concurrency smoke test passed: %d clients, %.1f MiB/s, %d traffic events",
                     clients, throughput, finalTrafficEvents))
        let percentiles = roundTrips.percentiles()
        print(String(format: "Loopback 32 KiB echo RTT: p50 %.3f ms, p99 %.3f ms; process RSS %.1f -> %.1f MiB (includes test clients/server, not peak)",
                     percentiles.0, percentiles.1,
                     Double(residentBefore) / 1_048_576, Double(performanceResidentBytes()) / 1_048_576))
        engine.stop()
        echo.stop()
        return 0
    } catch {
        engine.stop()
        echo.stop()
        FileHandle.standardError.write(Data("Proxy performance smoke test failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

private func verifyListenerFreeRouter(profile: Profile, echoPort: UInt16) throws {
    let router = NativePacketRouter(profile: profile, mode: .direct,
                                    globalPolicy: "DIRECT", groupSelections: [:])
    let queue = DispatchQueue(label: "app.hajimi.smoke.listener-free")
    let connected = DispatchSemaphore(value: 0)
    var result: Result<NativeOutboundByteStream, Error>?
    router.connectTCP(host: "127.0.0.1", port: echoPort, queue: queue) {
        result = $0; connected.signal()
    }
    guard connected.wait(timeout: .now() + 5) == .success, let result else {
        throw PerformanceCheckError("无 listener 路由核心连接超时")
    }
    let stream = try result.get(); defer { stream.cancel() }
    let payload = Data("listener-free-native-router".utf8)
    let sent = DispatchSemaphore(value: 0); var sendError: Error?
    stream.send(payload) { sendError = $0; sent.signal() }
    guard sent.wait(timeout: .now() + 5) == .success, sendError == nil else {
        throw sendError ?? PerformanceCheckError("无 listener 路由核心发送超时")
    }
    let received = DispatchSemaphore(value: 0); var response: Data?; var receiveError: Error?
    stream.receive(maximum: 4096) { data, _, error in
        response = data; receiveError = error; received.signal()
    }
    guard received.wait(timeout: .now() + 5) == .success,
          receiveError == nil, response == payload else {
        throw receiveError ?? PerformanceCheckError("无 listener 路由核心回显不匹配")
    }
    router.update(profile: profile, mode: .proxy, globalPolicy: "REJECT",
                  groupSelections: [:])
    let rejected = DispatchSemaphore(value: 0); var rejectResult: Result<NativeOutboundByteStream, Error>?
    router.connectTCP(host: "127.0.0.1", port: echoPort, queue: queue) {
        rejectResult = $0; rejected.signal()
    }
    guard rejected.wait(timeout: .now() + 5) == .success,
          rejectResult?.failure != nil else {
        throw PerformanceCheckError("无 listener 路由核心热重载未生效")
    }
    print("Listener-free native router smoke test passed")
}

private extension Result {
    var failure: Failure? { if case .failure(let error) = self { return error }; return nil }
}

private final class LockedFailures {
    private let lock = NSLock()
    private var values: [String] = []
    func append(_ value: String) { lock.lock(); values.append(value); lock.unlock() }
    var first: String? { lock.lock(); defer { lock.unlock() }; return values.first }
}

private final class LockedRoundTrips {
    private let lock = NSLock()
    private var samples: [UInt64] = []
    func append(_ nanoseconds: UInt64) {
        lock.lock(); samples.append(nanoseconds); lock.unlock()
    }
    func percentiles() -> (Double, Double) {
        lock.lock(); let sorted = samples.sorted(); lock.unlock()
        guard !sorted.isEmpty else { return (0, 0) }
        func value(_ percentile: Double) -> Double {
            let index = min(sorted.count - 1, max(0, Int(ceil(Double(sorted.count) * percentile)) - 1))
            return Double(sorted[index]) / 1_000_000
        }
        return (value(0.5), value(0.99))
    }
}

private func performanceResidentBytes() -> UInt64 {
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<integer_t>.size)
    let result = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
        }
    }
    return result == KERN_SUCCESS ? UInt64(info.resident_size) : 0
}

private struct PerformanceCheckError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

private final class LoopbackEchoServer {
    private var listener: Int32 = -1
    private var running = false
    private let lock = NSLock()
    private var clients = Set<Int32>()
    private(set) var port: UInt16 = 0

    func start() throws {
        listener = socket(AF_INET, SOCK_STREAM, 0)
        guard listener >= 0 else { throw PerformanceCheckError("无法创建 Echo 监听器") }
        var reuse: Int32 = 1
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout.size(ofValue: reuse)))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, Darwin.listen(listener, 256) == 0 else {
            throw PerformanceCheckError("无法启动 Echo 监听器")
        }
        var actual = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &actual) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(listener, $0, &length) }
        }
        port = UInt16(bigEndian: actual.sin_port)
        running = true
        Thread.detachNewThread { [weak self] in self?.acceptLoop() }
    }

    func stop() {
        lock.lock()
        running = false
        let descriptors = clients
        clients.removeAll()
        let listener = self.listener
        self.listener = -1
        lock.unlock()
        if listener >= 0 { Darwin.shutdown(listener, SHUT_RDWR); Darwin.close(listener) }
        for descriptor in descriptors { Darwin.shutdown(descriptor, SHUT_RDWR); Darwin.close(descriptor) }
    }

    private func acceptLoop() {
        while true {
            lock.lock(); let active = running; let descriptor = listener; lock.unlock()
            guard active, descriptor >= 0 else { return }
            let client = Darwin.accept(descriptor, nil, nil)
            guard client >= 0 else { continue }
            lock.lock(); clients.insert(client); lock.unlock()
            Thread.detachNewThread { [weak self] in self?.echo(client) }
        }
    }

    private func echo(_ descriptor: Int32) {
        var noSignal: Int32 = 1
        setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                   socklen_t(MemoryLayout.size(ofValue: noSignal)))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.recv(descriptor, &buffer, buffer.count, 0)
            guard count > 0 else { break }
            var offset = 0
            while offset < count {
                let sent = buffer.withUnsafeBytes {
                    Darwin.send(descriptor, $0.baseAddress!.advanced(by: offset), count - offset, 0)
                }
                guard sent > 0 else { offset = count; break }
                offset += sent
            }
        }
        lock.lock(); clients.remove(descriptor); lock.unlock()
        Darwin.close(descriptor)
    }
}

private func unusedLoopbackPort(excluding: Set<UInt16> = []) throws -> UInt16 {
    let start = Int(arc4random_uniform(12_000)) + 40_000
    for offset in 0..<1_000 {
        let port = UInt16(start + offset)
        if excluding.contains(port) { continue }
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { continue }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        Darwin.close(descriptor)
        if connected != 0 { return port }
    }
    throw PerformanceCheckError("无法分配测试端口")
}

private func runSOCKSEchoClient(socksPort: UInt16, targetPort: UInt16,
                                iterations: Int, chunkSize: Int, seed: UInt8,
                                samples: LockedRoundTrips) throws {
    let descriptor = socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw PerformanceCheckError("无法创建测试连接") }
    defer { Darwin.close(descriptor) }
    var noSignal: Int32 = 1
    setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
               socklen_t(MemoryLayout.size(ofValue: noSignal)))
    var timeout = timeval(tv_sec: 10, tv_usec: 0)
    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
               socklen_t(MemoryLayout.size(ofValue: timeout)))
    setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
               socklen_t(MemoryLayout.size(ofValue: timeout)))
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = socksPort.bigEndian
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else { throw PerformanceCheckError("无法连接 SOCKS5 测试端口") }
    try writeAll(Data([0x05, 0x01, 0x00]), to: descriptor)
    guard try readExactly(2, from: descriptor) == Data([0x05, 0x00]) else {
        throw PerformanceCheckError("SOCKS5 测试握手失败")
    }
    let request = Data([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
                        UInt8(targetPort >> 8), UInt8(targetPort & 0xff)])
    try writeAll(request, to: descriptor)
    let response = try readExactly(10, from: descriptor)
    guard response.count == 10, response[1] == 0 else {
        throw PerformanceCheckError("SOCKS5 测试连接目标失败")
    }
    let payload = Data((0..<chunkSize).map { seed &+ UInt8(truncatingIfNeeded: $0) })
    for _ in 0..<iterations {
        let began = DispatchTime.now().uptimeNanoseconds
        try writeAll(payload, to: descriptor)
        guard try readExactly(payload.count, from: descriptor) == payload else {
            throw PerformanceCheckError("并发转发内容不一致")
        }
        samples.append(DispatchTime.now().uptimeNanoseconds - began)
    }
}

private func writeAll(_ data: Data, to descriptor: Int32) throws {
    try data.withUnsafeBytes { raw in
        var offset = 0
        while offset < raw.count {
            let count = Darwin.send(descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset, 0)
            guard count > 0 else { throw PerformanceCheckError("测试连接写入失败") }
            offset += count
        }
    }
}

private func readExactly(_ count: Int, from descriptor: Int32) throws -> Data {
    var result = Data(count: count)
    try result.withUnsafeMutableBytes { raw in
        var offset = 0
        while offset < count {
            let received = Darwin.recv(descriptor, raw.baseAddress!.advanced(by: offset), count - offset, 0)
            guard received > 0 else { throw PerformanceCheckError("测试连接读取失败") }
            offset += received
        }
    }
    return result
}

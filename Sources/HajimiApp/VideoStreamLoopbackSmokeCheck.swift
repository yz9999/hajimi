import Foundation
import HajimiCore

/// Explicit, bounded CLI fixture. It never reads the user's profile or changes
/// the system proxy, DNS, routes, Helper, or tunnel. Both the next hop and the
/// only permitted destination are literal loopback addresses.
func runVideoStreamLoopbackSmokeCheck() -> Int32 {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    let engine = ProxyEngine()
    defer { engine.stop() }
    do {
        guard CommandLine.arguments.contains("--video-stream-loopback-test") else {
            throw Failure(text: "Video fixture requires its explicit CLI flag")
        }
        let environment = ProcessInfo.processInfo.environment
        guard let origin = environment["HAJIMI_TEST_VIDEO_ORIGIN_PORT"].flatMap(UInt16.init), origin > 0,
              let kind = environment["HAJIMI_TEST_VIDEO_OUTBOUND"],
              ["direct", "http", "socks5"].contains(kind) else {
            throw Failure(text: "Video fixture requires a loopback origin port and supported outbound")
        }
        var profile = Profile()
        profile.httpListen = ListenAddress(host: "127.0.0.1", port: 0)
        profile.socksListen = ListenAddress(host: "127.0.0.1", port: 0)
        var policy = "DIRECT"
        if kind != "direct" {
            guard let upstream = environment["HAJIMI_TEST_VIDEO_UPSTREAM_PORT"].flatMap(UInt16.init),
                  upstream > 0, upstream != origin else {
                throw Failure(text: "Video fixture requires a separate literal-loopback upstream")
            }
            policy = "VideoLoopbackNode"
            profile.proxies[policy] = ProxyPolicy(name: policy, kind: kind == "http" ? .http : .socks5,
                host: "127.0.0.1", port: upstream)
            profile.proxyOrder = [policy]
        }
        profile.rules = [
            RoutingRule(kind: .logicalAnd([.ipCIDR("127.0.0.1/32"), .destinationPort(origin...origin),
                                           .logicalNot(.protocolName("UDP"))]),
                        policy: policy, sourceLine: 1),
            RoutingRule(kind: .final, policy: "REJECT", sourceLine: 2)
        ]
        let lock = NSLock(), ready = DispatchSemaphore(value: 0)
        var failure: String?
        engine.onStatus = { status in
            switch status {
            case .running: ready.signal()
            case .failed(let text): lock.lock(); failure = text; lock.unlock(); ready.signal()
            default: break
            }
        }
        try engine.start(profile: profile, mode: .rule, globalPolicy: policy)
        guard ready.wait(timeout: .now() + 5) == .success else {
            throw Failure(text: "Video loopback listener startup exceeded five seconds")
        }
        lock.lock(); let startFailure = failure; lock.unlock()
        if let startFailure { throw Failure(text: startFailure) }
        let ports: [String: Any] = ["http": Int(engine.activeHTTPListen.port),
                                   "socks": Int(engine.activeSOCKSListen.port), "outbound": kind]
        let encoded = try JSONSerialization.data(withJSONObject: ports, options: [.sortedKeys])
        FileHandle.standardOutput.write(Data("VIDEO_LOOPBACK_READY ".utf8) + encoded + Data([10]))
        let stop = DispatchSemaphore(value: 0)
        var validStop = false
        Thread.detachNewThread {
            let command = readLine()
            lock.lock(); validStop = command == "STOP"; lock.unlock()
            stop.signal()
        }
        guard stop.wait(timeout: .now() + 30) == .success else {
            throw Failure(text: "Video loopback fixture exceeded its thirty-second lifetime")
        }
        lock.lock(); let requested = validStop; lock.unlock()
        guard requested else { throw Failure(text: "Video loopback fixture requires STOP after verified clients") }
        print("Video loopback listener check passed: \(kind)")
        return 0
    } catch {
        FileHandle.standardError.write(Data("Video loopback listener check failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

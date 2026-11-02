import Foundation
import Darwin
import HajimiCore

/// Temporary files and literal-loopback HTTP proxy fixtures only; never the
/// user's live rule-set/configuration directory or a public origin server.
@main
struct RuleSetRefreshSmokeTest {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(message: message) }
    }

    private final class LoopbackHTTPFixture {
        let address: ListenAddress
        let requestStarted = DispatchSemaphore(value: 0)
        private let queue = DispatchQueue(label: "app.hajimi.rule-refresh.http-fixture")
        private let lock = NSLock()
        private var source: DispatchSourceRead?
        private var received: [String] = []
        private let body: String
        private let responseGate: DispatchSemaphore?

        init(body: String, responseGate: DispatchSemaphore? = nil) throws {
            self.body = body
            self.responseGate = responseGate
            let (descriptor, port) = try Self.listen()
            address = ListenAddress(host: "127.0.0.1", port: port)
            let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
            self.source = source
            source.setEventHandler { [weak self] in
                while true {
                    let client = Darwin.accept(descriptor, nil, nil)
                    guard client >= 0 else { return }
                    self?.serve(client)
                    Darwin.close(client)
                }
            }
            source.setCancelHandler { Darwin.close(descriptor) }
            source.resume()
        }

        private static func listen() throws -> (Int32, UInt16) {
            let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
            guard descriptor >= 0 else { throw Failure(message: "Cannot create loopback fixture socket") }
            var completed = false
            defer { if !completed { Darwin.close(descriptor) } }
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let bound = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bound == 0, Darwin.listen(descriptor, 8) == 0 else {
                throw Failure(message: "Cannot bind loopback fixture socket")
            }
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let inspected = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.getsockname(descriptor, $0, &length)
                }
            }
            guard inspected == 0,
                  Darwin.fcntl(descriptor, F_SETFL, Darwin.fcntl(descriptor, F_GETFL) | O_NONBLOCK) == 0 else {
                throw Failure(message: "Cannot inspect loopback fixture socket")
            }
            completed = true
            return (descriptor, UInt16(bigEndian: address.sin_port))
        }

        private func serve(_ descriptor: Int32) {
            _ = Darwin.fcntl(descriptor, F_SETFL, 0)
            var enabled: Int32 = 1
            _ = withUnsafePointer(to: &enabled) {
                Darwin.setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, $0, socklen_t(MemoryLayout<Int32>.size))
            }
            var timeout = timeval(tv_sec: 2, tv_usec: 0)
            _ = withUnsafePointer(to: &timeout) {
                Darwin.setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
            }
            var request = Data(), bytes = [UInt8](repeating: 0, count: 2_048)
            while request.count < 16_384 {
                let count = Darwin.recv(descriptor, &bytes, bytes.count, 0)
                guard count > 0 else { return }
                request.append(contentsOf: bytes.prefix(count))
                if request.range(of: Data("\r\n\r\n".utf8)) != nil { break }
            }
            let text = String(decoding: request, as: UTF8.self)
            lock.lock(); received.append(text); lock.unlock()
            requestStarted.signal()
            if let responseGate, responseGate.wait(timeout: .now() + 5) != .success { return }
            // HTTPS only needs to prove CONNECT used the selected proxy.
            // Reject it before TLS rather than installing a test CA.
            let connect = text.hasPrefix("CONNECT ")
            let payload = connect ? Data() : Data(body.utf8)
            let status = connect ? "502 Bad Gateway" : "200 OK"
            var response = Data("HTTP/1.1 \(status)\r\nContent-Length: \(payload.count)\r\nConnection: close\r\n\r\n".utf8)
            response.append(payload)
            response.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.send(descriptor, buffer.baseAddress!.advanced(by: offset), buffer.count - offset, 0)
                    guard count > 0 else { return }
                    offset += count
                }
            }
        }

        var requests: [String] { lock.lock(); defer { lock.unlock() }; return received }
        deinit { source?.cancel() }
    }

    private static func cacheStartupAndProxyRefresh(root: URL) throws {
        let directory = root.appendingPathComponent("remote-cache", isDirectory: true)
        let manager = SurgeRuleSetManager(applicationSupportDirectory: directory)
        let proxy = try LoopbackHTTPFixture(body: "DOMAIN-SUFFIX,cached-remote.test\n")
        let location = "http://rules.hajimi.invalid/remote.rules"
        let missingLocation = "http://rules.hajimi.invalid/missing.rules"
        let source = try ProfileParser.parse("""
        [Rule]
        RULE-SET,\(location),REJECT,update-interval=86400
        RULE-SET,\(location),DIRECT,update-interval=3600
        FINAL,DIRECT
        """)
        do {
            _ = try manager.prepare(profile: source, mode: .cacheOnly, httpProxy: proxy.address)
            throw Failure(message: "Uncached remote startup must fail closed")
        } catch let error as SurgeRuleSetManager.RuleSetError {
            try require(error.isMissingCache, "Missing cache must have its own error category")
        }
        try require(proxy.requests.isEmpty && manager.expiredLocations(profile: source) == [location],
                    "Cache-only miss downloaded a remote resource or was omitted from refresh needs")

        let first = try manager.prepare(profile: source, mode: .refresh,
            httpProxy: ListenAddress(host: "0.0.0.0", port: proxy.address.port))
        try require(first.ruleSetContents[location] == [.domainSuffix("cached-remote.test")]
                    && proxy.requests.count == 1
                    && proxy.requests[0].hasPrefix("GET \(location) HTTP/1.1\r\n"),
                    "HTTP rule refresh did not use the selected loopback proxy for its unresolved origin")
        try require(manager.expiredLocations(profile: source).isEmpty,
                    "Fresh remote cache unnecessarily requested startup network refresh")
        try require(manager.expiredLocations(profile: source, at: Date().addingTimeInterval(7_200)) == [location],
                    "Duplicate references did not use their shortest update interval")

        let cacheFiles = try FileManager.default.contentsOfDirectory(
            at: directory.appendingPathComponent("rule-sets"), includingPropertiesForKeys: nil)
        for cache in cacheFiles {
            try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1)],
                                                 ofItemAtPath: cache.path)
        }
        let cached = try manager.prepare(profile: source, mode: .cacheOnly,
            forceRefreshLocations: [location], httpProxy: proxy.address)
        try require(cached.ruleSetContents == first.ruleSetContents && cached.rules == source.rules
                    && proxy.requests.count == 1 && manager.expiredLocations(profile: source) == [location],
                    "Expired cache startup fetched a resource, lost rules, or hid background refresh needs")
        try require(cached.route(for: .init(host: "www.cached-remote.test", port: 443, protocolName: "TCP"),
                                 mode: .rule, globalPolicy: "DIRECT").policyName == "REJECT",
                    "Expired cached rules did not protect routing during startup")
        print("PASS: stale cached startup keeps all rules, downloads nothing and reports refresh needs")

        let incomplete = try ProfileParser.parse("""
        [Rule]
        RULE-SET,\(location),REJECT
        RULE-SET,\(missingLocation),REJECT
        FINAL,DIRECT
        """)
        do {
            _ = try manager.prepare(profile: incomplete, mode: .cacheOnly, httpProxy: proxy.address)
            throw Failure(message: "A partial cached ruleset must not allow startup")
        } catch let error as SurgeRuleSetManager.RuleSetError {
            guard case .missingCaches(let locations) = error else { throw error }
            try require(locations == [missingLocation], "Missing-cache error lost the required reference")
        }
        try require(proxy.requests.count == 1 && incomplete.ruleSetContents.isEmpty,
                    "A missing required cache caused a download or mutated the source profile")
        print("PASS: missing required remote cache fails closed without downloading")

        let nextProxy = try LoopbackHTTPFixture(body: "DOMAIN-SUFFIX,refreshed-remote.test\n")
        let refreshed = try manager.prepare(profile: source, mode: .refresh,
            forceRefreshLocations: [location], httpProxy: nextProxy.address)
        try require(refreshed.ruleSetContents[location] == [.domainSuffix("refreshed-remote.test")]
                    && proxy.requests.count == 1 && nextProxy.requests.count == 1
                    && nextProxy.requests[0].lowercased().contains("cache-control: no-cache\r\n")
                    && manager.expiredLocations(profile: source).isEmpty,
                    "Forced refresh reused an old proxy session, ignored no-cache, or left an expired cache")
        print("PASS: each forced refresh uses its current HTTP proxy and renews the cache")

        let responseGate = DispatchSemaphore(value: 0)
        let parkedProxy = try LoopbackHTTPFixture(body: "DOMAIN-SUFFIX,after-parked-refresh.test\n",
                                                  responseGate: responseGate)
        let refreshDone = DispatchSemaphore(value: 0), startupDone = DispatchSemaphore(value: 0)
        let resultLock = NSLock()
        var refreshResult: Result<Profile, Error>?, startupResult: Result<Profile, Error>?
        DispatchQueue.global(qos: .utility).async {
            let result = Result { try manager.prepare(profile: source, mode: .refresh,
                forceRefreshLocations: [location], httpProxy: parkedProxy.address) }
            resultLock.lock(); refreshResult = result; resultLock.unlock(); refreshDone.signal()
        }
        defer { responseGate.signal() }
        try require(parkedProxy.requestStarted.wait(timeout: .now() + 2) == .success,
                    "Background refresh did not reach its parked proxy request")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result {
                let cached = try manager.prepare(profile: source, mode: .cacheOnly)
                try require(manager.expiredLocations(profile: source).isEmpty,
                            "A pending refresh changed a previously fresh cache's expiry")
                return cached
            }
            resultLock.lock(); startupResult = result; resultLock.unlock(); startupDone.signal()
        }
        let startupCompleted = startupDone.wait(timeout: .now() + 1) == .success
        responseGate.signal()
        try require(refreshDone.wait(timeout: .now() + 3) == .success,
                    "Background refresh did not finish after its response was released")
        try require(startupCompleted, "Cache startup or expiry inspection waited behind a parked network refresh")
        resultLock.lock(); let startup = startupResult, refresh = refreshResult; resultLock.unlock()
        try require(try startup?.get().ruleSetContents[location] == [.domainSuffix("refreshed-remote.test")]
                    && refresh?.get().ruleSetContents[location] == [.domainSuffix("after-parked-refresh.test")],
                    "Concurrent startup did not retain the last complete cache while refresh installed the next one")
        print("PASS: cache startup and expiry inspection never wait behind an in-flight refresh")

        let secureLocation = "https://rules.hajimi.invalid/secure.rules"
        let secureSource = try ProfileParser.parse("[Rule]\nRULE-SET,\(secureLocation),REJECT\nFINAL,DIRECT\n")
        do {
            _ = try manager.prepare(profile: secureSource, mode: .refresh, httpProxy: nextProxy.address)
            throw Failure(message: "Rejected HTTPS CONNECT must fail rather than bypass the proxy")
        } catch is SurgeRuleSetManager.RuleSetError {}
        try require(nextProxy.requests.contains { $0.hasPrefix("CONNECT rules.hajimi.invalid:443 HTTP/1.1\r\n") },
                    "HTTPS refresh bypassed the selected HTTP proxy instead of sending CONNECT")
        print("PASS: HTTPS refresh sends CONNECT to the selected proxy and rejects failed tunnels")
    }

    static func main() {
        do {
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("hajimi-rule-refresh-" + UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let a = root.appendingPathComponent("a.rules")
            let b = root.appendingPathComponent("b.rules")
            try "DOMAIN-SUFFIX,old-a.test\n".write(to: a, atomically: true, encoding: .utf8)
            try "DOMAIN-SUFFIX,old-b.test\n".write(to: b, atomically: true, encoding: .utf8)
            let manager = SurgeRuleSetManager(applicationSupportDirectory: root)
            let source = try ProfileParser.parse("""
            [Rule]
            RULE-SET,\(a.absoluteString),REJECT,update-interval=86400
            RULE-SET,\(b.absoluteString),DIRECT,update-interval=86400
            FINAL,DIRECT
            """)
            let localStartup = try manager.prepare(profile: source, mode: .cacheOnly)
            try require(localStartup.ruleSetContents[a.absoluteString] == [.domainSuffix("old-a.test")]
                        && localStartup.ruleSetContents[b.absoluteString] == [.domainSuffix("old-b.test")]
                        && manager.expiredLocations(profile: source).isEmpty,
                        "First local-file configuration must work without remote I/O or background refresh")
            print("PASS: first local-file configuration works during cache-only startup")
            let first = try manager.prepare(profile: source)
            try require(first.ruleSetContents[a.absoluteString] == [.domainSuffix("old-a.test")],
                        "Initial resource A load")
            try require(first.ruleSetContents[b.absoluteString] == [.domainSuffix("old-b.test")],
                        "Initial resource B load")
            print("PASS: initial local rule-set load and cache")

            try "DOMAIN-SUFFIX,new-a.test\n".write(to: a, atomically: true, encoding: .utf8)
            try "DOMAIN-SUFFIX,new-b.test\n".write(to: b, atomically: true, encoding: .utf8)
            let cached = try manager.prepare(profile: source)
            try require(cached.ruleSetContents == first.ruleSetContents,
                        "Fresh automatic cache should be retained")
            print("PASS: automatic preparation honors fresh cache")

            let selected = try manager.prepare(profile: source, forceRefreshLocations: [a.absoluteString])
            try require(selected.ruleSetContents[a.absoluteString] == [.domainSuffix("new-a.test")],
                        "Selected refresh must bypass a fresh cache")
            try require(selected.ruleSetContents[b.absoluteString] == [.domainSuffix("old-b.test")],
                        "Selected refresh must not force other fresh resources")
            try require(selected.rules == source.rules, "Refresh must preserve rule order and source lines")
            try require(selected.route(for: .init(host: "www.new-a.test", port: 443, protocolName: "TCP"),
                                       mode: .rule, globalPolicy: "DIRECT").policyName == "REJECT",
                        "Updated rule-set must become effective for routing")
            print("PASS: selected manual refresh bypasses cache and updates routing")

            let all = try manager.prepare(profile: source,
                                          forceRefreshLocations: [a.absoluteString, b.absoluteString])
            try require(all.ruleSetContents[b.absoluteString] == [.domainSuffix("new-b.test")],
                        "Refresh all must fetch every requested resource")
            print("PASS: refresh-all updates both resources")

            try FileManager.default.removeItem(at: a)
            let fallback = try manager.prepare(profile: source, forceRefreshLocations: [a.absoluteString])
            try require(fallback.ruleSetContents[a.absoluteString] == [.domainSuffix("new-a.test")],
                        "Failed manual refresh must retain the last usable cache")
            try require(fallback.warnings.contains { $0.contains("RULE-SET 更新失败") },
                        "Stale fallback must be visible as a warning")
            print("PASS: failed refresh retains cache and reports a warning")

            let missing = root.appendingPathComponent("uncached.rules")
            let invalid = try ProfileParser.parse("[Rule]\nRULE-SET,\(missing.absoluteString),REJECT\nFINAL,DIRECT\n")
            do {
                _ = try manager.prepare(profile: invalid, forceRefreshLocations: [missing.absoluteString])
                throw Failure(message: "Missing uncached resource must fail, not silently route DIRECT")
            } catch is SurgeRuleSetManager.RuleSetError {
                print("PASS: uncached resource failure does not silently bypass rules")
            }
            try require(source.ruleSetContents.isEmpty, "Preparation must not mutate the input profile")
            try cacheStartupAndProxyRefresh(root: root)
            print("PASS: rule-set refresh smoke tests")
        } catch {
            FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}

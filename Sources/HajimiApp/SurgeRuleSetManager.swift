import Foundation
import CryptoKit
import Darwin
import HajimiCore

/// Resolves Surge RULE-SET references into Hajimi's in-memory matcher while
/// retaining the original rule order and policy assignment. Remote files are
/// cached according to each rule's `update-interval` value.
final class SurgeRuleSetManager {
    enum PreparationMode {
        case cacheOnly
        case refresh
    }

    enum RuleSetError: LocalizedError {
        case failures([String])
        case missingCaches([String])

        var isMissingCache: Bool {
            if case .missingCaches = self { return true }
            return false
        }

        var errorDescription: String? {
            switch self {
            case .failures(let values):
                return "无法加载 Surge RULE-SET：\n" + values.joined(separator: "\n")
            case .missingCaches(let locations):
                return "以下远程 RULE-SET 尚无本地缓存：\n"
                    + locations.map { "• " + SurgeRuleSetManager.displayName($0) }.joined(separator: "\n")
            }
        }
    }

    private struct Loaded {
        let location: String
        let text: String
        let staleFallback: Bool
    }

    private let directoryURL: URL
    private let prepareLock = NSLock()

    init(applicationSupportDirectory: URL) {
        directoryURL = applicationSupportDirectory.appendingPathComponent("rule-sets", isDirectory: true)
        try? FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700],
                                               ofItemAtPath: directoryURL.path)
    }

    private func makeSession(httpProxy: ListenAddress?) throws -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 30
        configuration.httpAdditionalHeaders = ["User-Agent": "Hajimi/0.5 Surge-RuleSet"]
        configuration.connectionProxyDictionary = [:]
        if let httpProxy {
            let host = httpProxy.host == "0.0.0.0" ? "127.0.0.1" : (httpProxy.host == "::" ? "::1" : httpProxy.host)
            guard !host.isEmpty, httpProxy.port > 0,
                  host.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
                throw URLError(.badURL)
            }
            configuration.connectionProxyDictionary = [
                "HTTPEnable": 1, "HTTPProxy": host, "HTTPPort": Int(httpProxy.port),
                "HTTPSEnable": 1, "HTTPSProxy": host, "HTTPSPort": Int(httpProxy.port),
                "SOCKSEnable": 0, "ProxyAutoConfigEnable": 0, "ProxyAutoDiscoveryEnable": 0,
                "ExceptionsList": [], "ExcludeSimpleHostnames": 0
            ]
        }
        return URLSession(configuration: configuration)
    }

    func prepare(profile: Profile, mode: PreparationMode = .refresh,
                 forceRefreshLocations: Set<String> = [], httpProxy: ListenAddress? = nil) throws -> Profile {
        // A parked refresh must never hold startup behind its network wait.
        // Atomic cache replacement allows readers to use the last complete
        // file while only refresh batches serialize their downloads/writes.
        let refreshing = mode == .refresh
        if refreshing { prepareLock.lock() }
        defer { if refreshing { prepareLock.unlock() } }
        var runtime = profile
        let references = uniqueReferences(profile.ruleSetReferences)
        guard !references.isEmpty else {
            runtime.prepareCompiledRoutingRules()
            return runtime
        }

        let lock = NSLock()
        var loaded: [String: Loaded] = [:]
        var failures: [String] = []
        var missingCaches: [String] = []
        let cacheOnly = mode == .cacheOnly
        let session: URLSession?
        if cacheOnly { session = nil } else { session = try makeSession(httpProxy: httpProxy) }
        defer { session?.invalidateAndCancel() }
        let queue = OperationQueue()
        queue.name = "app.hajimi.surge-rule-sets"
        queue.qualityOfService = .userInitiated
        queue.maxConcurrentOperationCount = 8

        for reference in references {
            if cacheOnly {
                // Local files are safe to read before networking starts. A
                // remote resource must already exist in our disk cache; even
                // an explicit force-refresh request cannot authorize I/O here.
                let url: URL
                do { url = try resourceURL(for: reference.location) }
                catch {
                    lock.lock()
                    failures.append("• \(Self.displayName(reference.location))：\(error.localizedDescription)")
                    lock.unlock(); continue
                }
                if !url.isFileURL {
                    if let cached = anyCache(for: reference.location) {
                        lock.lock()
                        loaded[reference.location] = Loaded(location: reference.location,
                                                            text: cached, staleFallback: false)
                        lock.unlock()
                    } else { missingCaches.append(reference.location) }
                    continue
                }
            }
            if !forceRefreshLocations.contains(reference.location),
               !cacheOnly,
               let cached = freshCache(for: reference) {
                lock.lock()
                loaded[reference.location] = Loaded(location: reference.location,
                                                    text: cached, staleFallback: false)
                lock.unlock()
                continue
            }
            queue.addOperation { [self] in
                do {
                    let text = try download(reference.location,
                                            forceRefresh: forceRefreshLocations.contains(reference.location),
                                            session: session)
                    try save(text: text, for: reference.location)
                    lock.lock()
                    loaded[reference.location] = Loaded(location: reference.location,
                                                        text: text, staleFallback: false)
                    lock.unlock()
                } catch {
                    if let stale = anyCache(for: reference.location) {
                        lock.lock()
                        loaded[reference.location] = Loaded(location: reference.location,
                                                            text: stale, staleFallback: true)
                        lock.unlock()
                    } else {
                        lock.lock()
                        failures.append("• \(Self.displayName(reference.location))：\(error.localizedDescription)")
                        lock.unlock()
                    }
                }
            }
        }
        queue.waitUntilAllOperationsAreFinished()
        guard missingCaches.isEmpty else { throw RuleSetError.missingCaches(missingCaches.sorted()) }
        guard failures.isEmpty else { throw RuleSetError.failures(failures.sorted()) }

        var ignoredTypes: [String: Int] = [:]
        var staleNames: [String] = []
        for reference in references {
            guard let item = loaded[reference.location] else {
                throw RuleSetError.failures(["• \(Self.displayName(reference.location))：规则集未加载"])
            }
            let parsed = SurgeRuleSetParser.parse(item.text)
            runtime.ruleSetContents[reference.location] = parsed.rules
            for (type, count) in parsed.ignoredTypes { ignoredTypes[type, default: 0] += count }
            if item.staleFallback { staleNames.append(Self.displayName(item.location)) }
        }
        if !ignoredTypes.isEmpty {
            let summary = ignoredTypes.keys.sorted().map { "\($0) \(ignoredTypes[$0]!) 条" }
                .joined(separator: "、")
            runtime.warnings.append("RULE-SET 中有当前代理入口无法识别的匹配类型：\(summary)")
        }
        if !staleNames.isEmpty {
            runtime.warnings.append("以下 RULE-SET 更新失败，已使用缓存：\(staleNames.sorted().joined(separator: "、"))")
        }
        // GUI callers prepare on their worker queue, so large rule indexes
        // are ready before the main queue publishes a listener or tunnel.
        runtime.prepareCompiledRoutingRules()
        return runtime
    }

    /// Only remote resources need background network refresh. Local files are
    /// read directly by cache-only preparation, including on their first use.
    func expiredLocations(profile: Profile, at date: Date = Date()) -> Set<String> {
        return Set(uniqueReferences(profile.ruleSetReferences).compactMap { reference in
            guard let url = try? resourceURL(for: reference.location), !url.isFileURL,
                  !cacheIsFresh(for: reference, at: date) else { return nil }
            return reference.location
        })
    }

    private func uniqueReferences(_ references: [RuleSetReference]) -> [RuleSetReference] {
        var order: [String] = []
        var values: [String: RuleSetReference] = [:]
        for reference in references {
            if values[reference.location] == nil { order.append(reference.location) }
            if let existing = values[reference.location] {
                values[reference.location] = RuleSetReference(
                    location: reference.location,
                    updateInterval: min(existing.updateInterval, reference.updateInterval)
                )
            } else {
                values[reference.location] = reference
            }
        }
        return order.compactMap { values[$0] }
    }

    private func cacheIsFresh(for reference: RuleSetReference, at date: Date) -> Bool {
        let url = cacheURL(for: reference.location)
        guard FileManager.default.isReadableFile(atPath: url.path),
              let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              let modified = attributes[.modificationDate] as? Date,
              date.timeIntervalSince(modified) < reference.updateInterval else { return false }
        return true
    }

    private func freshCache(for reference: RuleSetReference, at date: Date = Date()) -> String? {
        // Periodic expiry checks inspect metadata only. A real preparation
        // still validates the complete cached body as UTF-8 before using it.
        guard cacheIsFresh(for: reference, at: date) else { return nil }
        return try? String(contentsOf: cacheURL(for: reference.location), encoding: .utf8)
    }

    private func anyCache(for location: String) -> String? {
        try? String(contentsOf: cacheURL(for: location), encoding: .utf8)
    }

    private func save(text: String, for location: String) throws {
        let url = cacheURL(for: location)
        try text.write(to: url, atomically: true, encoding: .utf8)
        _ = Darwin.chmod(url.path, S_IRUSR | S_IWUSR)
    }

    private func cacheURL(for location: String) -> URL {
        let digest = SHA256.hash(data: Data(location.utf8)).map { String(format: "%02x", $0) }.joined()
        return directoryURL.appendingPathComponent(digest + ".rules")
    }

    private func resourceURL(for location: String) throws -> URL {
        if let parsed = URL(string: location), let scheme = parsed.scheme,
           ["http", "https", "file"].contains(scheme.lowercased()) {
            return parsed
        } else if location.hasPrefix("/") || location.hasPrefix("~") {
            return URL(fileURLWithPath: (location as NSString).expandingTildeInPath)
        } else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }
    }

    private func download(_ location: String, forceRefresh: Bool = false, session: URLSession?) throws -> String {
        let url = try resourceURL(for: location)
        if url.isFileURL { return try String(contentsOf: url, encoding: .utf8) }
        guard let session else { throw CocoaError(.fileReadNoPermission) }

        let semaphore = DispatchSemaphore(value: 0)
        let resultLock = NSLock()
        var result: Result<Data, Error>?
        var request = URLRequest(url: url)
        if forceRefresh {
            request.cachePolicy = .reloadIgnoringLocalCacheData
            request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        }
        let task = session.dataTask(with: request) { data, response, error in
            resultLock.lock()
            defer { resultLock.unlock(); semaphore.signal() }
            if let error { result = .failure(error); return }
            if let response = response as? HTTPURLResponse,
               !(200...299).contains(response.statusCode) {
                result = .failure(URLError(.badServerResponse)); return
            }
            result = .success(data ?? Data())
        }
        task.resume()
        guard semaphore.wait(timeout: .now() + 35) == .success else {
            task.cancel()
            throw URLError(.timedOut)
        }
        resultLock.lock()
        let completed = result
        resultLock.unlock()
        let data = try completed?.get() ?? { throw URLError(.unknown) }()
        return String(decoding: data, as: UTF8.self)
    }

    private static func displayName(_ location: String) -> String {
        guard let url = URL(string: location), let host = url.host else {
            return URL(fileURLWithPath: location).lastPathComponent
        }
        return host + "/" + url.lastPathComponent
    }
}

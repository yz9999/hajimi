import Foundation
import CryptoKit
import Darwin
import HajimiCore

/// Resolves Surge RULE-SET references into Hajimi's in-memory matcher while
/// retaining the original rule order and policy assignment. Remote files are
/// cached according to each rule's `update-interval` value.
final class SurgeRuleSetManager {
    enum RuleSetError: LocalizedError {
        case failures([String])

        var errorDescription: String? {
            switch self {
            case .failures(let values):
                return "无法加载 Surge RULE-SET：\n" + values.joined(separator: "\n")
            }
        }
    }

    private struct Loaded {
        let location: String
        let text: String
        let staleFallback: Bool
    }

    private let directoryURL: URL
    private let session: URLSession
    private let prepareLock = NSLock()

    init(applicationSupportDirectory: URL) {
        directoryURL = applicationSupportDirectory.appendingPathComponent("rule-sets", isDirectory: true)
        try? FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700],
                                               ofItemAtPath: directoryURL.path)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 30
        configuration.httpAdditionalHeaders = ["User-Agent": "Hajimi/0.5 Surge-RuleSet"]
        configuration.connectionProxyDictionary = [:]
        session = URLSession(configuration: configuration)
    }

    deinit { session.invalidateAndCancel() }

    func prepare(profile: Profile, forceRefreshLocations: Set<String> = []) throws -> Profile {
        prepareLock.lock()
        defer { prepareLock.unlock() }
        var runtime = profile
        let references = uniqueReferences(profile.ruleSetReferences)
        guard !references.isEmpty else { return runtime }

        let lock = NSLock()
        var loaded: [String: Loaded] = [:]
        var failures: [String] = []
        let queue = OperationQueue()
        queue.name = "app.hajimi.surge-rule-sets"
        queue.qualityOfService = .userInitiated
        queue.maxConcurrentOperationCount = 8

        for reference in references {
            if !forceRefreshLocations.contains(reference.location),
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
                                            forceRefresh: forceRefreshLocations.contains(reference.location))
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
                        failures.append("• \(displayName(reference.location))：\(error.localizedDescription)")
                        lock.unlock()
                    }
                }
            }
        }
        queue.waitUntilAllOperationsAreFinished()
        guard failures.isEmpty else { throw RuleSetError.failures(failures.sorted()) }

        var ignoredTypes: [String: Int] = [:]
        var staleNames: [String] = []
        for reference in references {
            guard let item = loaded[reference.location] else { continue }
            let parsed = SurgeRuleSetParser.parse(item.text)
            runtime.ruleSetContents[reference.location] = parsed.rules
            for (type, count) in parsed.ignoredTypes { ignoredTypes[type, default: 0] += count }
            if item.staleFallback { staleNames.append(displayName(item.location)) }
        }
        if !ignoredTypes.isEmpty {
            let summary = ignoredTypes.keys.sorted().map { "\($0) \(ignoredTypes[$0]!) 条" }
                .joined(separator: "、")
            runtime.warnings.append("RULE-SET 中有当前代理入口无法识别的匹配类型：\(summary)")
        }
        if !staleNames.isEmpty {
            runtime.warnings.append("以下 RULE-SET 更新失败，已使用缓存：\(staleNames.sorted().joined(separator: "、"))")
        }
        return runtime
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

    private func freshCache(for reference: RuleSetReference) -> String? {
        let url = cacheURL(for: reference.location)
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let modified = attributes[.modificationDate] as? Date,
              Date().timeIntervalSince(modified) < reference.updateInterval else { return nil }
        return try? String(contentsOf: url, encoding: .utf8)
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

    private func download(_ location: String, forceRefresh: Bool = false) throws -> String {
        let url: URL
        if let parsed = URL(string: location), let scheme = parsed.scheme,
           ["http", "https", "file"].contains(scheme.lowercased()) {
            url = parsed
        } else if location.hasPrefix("/") || location.hasPrefix("~") {
            url = URL(fileURLWithPath: (location as NSString).expandingTildeInPath)
        } else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }
        if url.isFileURL { return try String(contentsOf: url, encoding: .utf8) }

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

    private func displayName(_ location: String) -> String {
        guard let url = URL(string: location), let host = url.host else {
            return URL(fileURLWithPath: location).lastPathComponent
        }
        return host + "/" + url.lastPathComponent
    }
}

import Foundation
import CryptoKit
import Darwin
import HajimiCore

/// A configured subscription source.
struct Subscription: Codable, Equatable {
    var name: String
    var url: String
    /// Seconds between automatic refreshes. Zero disables them.
    var updateInterval: TimeInterval
    var lastUpdated: Date?
    var lastFormat: SubscriptionFormat?
    var lastError: String?
    var lastProxyCount: Int
    var originalFilePath: String?

    init(name: String, url: String, updateInterval: TimeInterval = 86_400, originalFilePath: String? = nil) {
        self.name = name
        self.url = url
        self.updateInterval = updateInterval
        self.originalFilePath = originalFilePath
        lastProxyCount = 0
    }
}

/// Fetches and converts Clash and Surge subscriptions. The caller merges the
/// prepared contents into the current editor text only after downloads finish.
///
/// Downloads deliberately bypass the system proxy: a subscription is often
/// fetched while the very proxy it configures is broken or not yet running.
final class SubscriptionManager {
    enum ManagerError: LocalizedError {
        case invalidURL(String)
        case duplicateName(String)
        case unknownName(String)
        case http(Int)

        var errorDescription: String? {
            switch self {
            case .invalidURL(let value): return "订阅地址无效：\(value)"
            case .duplicateName(let value): return "已存在同名订阅：\(value)"
            case .unknownName(let value): return "找不到订阅：\(value)"
            case .http(let code): return "订阅服务器返回 HTTP \(code)"
            }
        }
    }

    struct UpdateResult {
        var name: String
        var format: SubscriptionFormat
        var proxyCount: Int
        var groupCount: Int
        var warnings: [String]
        var usedCache: Bool
    }

    struct PreparedUpdate {
        let name: String
        let sourceURL: String
        let contents: SubscriptionContents
        let result: UpdateResult
        let downloadedBody: String?
    }

    private let storeURL: URL
    private let selectedStoreURL: URL
    private let cacheDirectory: URL
    private let session: URLSession
    private let lock = NSLock()
    private let cacheQueue = DispatchQueue(label: "app.hajimi.subscription-cache", qos: .utility)
    private var subscriptions: [Subscription] = []
    private var activeName: String?

    init(applicationSupportDirectory: URL) {
        storeURL = applicationSupportDirectory.appendingPathComponent("subscriptions.json")
        selectedStoreURL = applicationSupportDirectory.appendingPathComponent("selected-subscription.txt")
        cacheDirectory = applicationSupportDirectory
            .appendingPathComponent("subscriptions", isDirectory: true)
        try? FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700],
                                               ofItemAtPath: cacheDirectory.path)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 25
        configuration.timeoutIntervalForResource = 40
        // Providers commonly gate on the client identifier to pick a format.
        configuration.httpAdditionalHeaders = ["User-Agent": "Hajimi/0.8 Clash"]
        configuration.connectionProxyDictionary = [:]
        session = URLSession(configuration: configuration)
        load()
    }

    deinit { session.invalidateAndCancel() }

    var all: [Subscription] { lock.withLock { subscriptions } }

    var selectedName: String? {
        lock.withLock {
            if let activeName, subscriptions.contains(where: { $0.name == activeName }) {
                return activeName
            }
            return subscriptions.first?.name
        }
    }

    var activeSubscription: Subscription? {
        lock.withLock {
            let target = activeName.flatMap { name in
                subscriptions.contains(where: { $0.name == name }) ? name : nil
            } ?? subscriptions.first?.name
            guard let target else { return nil }
            return subscriptions.first(where: { $0.name == target })
        }
    }

    /// True only when the active configuration comes from a remote HTTP/HTTPS URL subscription.
    /// Locally imported configuration files (`file://`) and standalone local profiles return false.
    var isActiveSubscriptionRemoteURL: Bool {
        guard let sub = activeSubscription,
              let parsed = URL(string: sub.url),
              let scheme = parsed.scheme?.lowercased() else { return false }
        return scheme == "http" || scheme == "https"
    }

    func select(name: String?) {
        let sanitized = name.map(SubscriptionMerge.sanitize)
        lock.withLock {
            if let sanitized, subscriptions.contains(where: { $0.name == sanitized }) {
                activeName = sanitized
            } else {
                activeName = subscriptions.first?.name
            }
        }
        saveSelection()
    }

    func uniqueName(basedOn rawName: String) -> String {
        let base = SubscriptionMerge.sanitize(name: rawName)
        let stem = base.isEmpty ? "订阅" : base
        return lock.withLock {
            let existing = Set(subscriptions.map(\.name))
            guard existing.contains(stem) else { return stem }
            var index = 2
            while existing.contains("\(stem) \(index)") { index += 1 }
            return "\(stem) \(index)"
        }
    }

    // MARK: Definitions

    func add(name rawName: String, url: String, updateInterval: TimeInterval) throws {
        let name = SubscriptionMerge.sanitize(name: rawName)
        guard !name.isEmpty else { throw ManagerError.unknownName(rawName) }
        guard let parsed = URL(string: url),
              let scheme = parsed.scheme?.lowercased(),
              ["http", "https", "file"].contains(scheme) else {
            throw ManagerError.invalidURL(url)
        }
        try lock.withLock {
            guard !subscriptions.contains(where: { $0.name == name }) else {
                throw ManagerError.duplicateName(name)
            }
            subscriptions.append(Subscription(name: name, url: url,
                                              updateInterval: updateInterval))
            if activeName == nil || !subscriptions.contains(where: { $0.name == activeName }) {
                activeName = name
            }
        }
        save()
        saveSelection()
    }

    struct EditOutcome {
        let subscription: Subscription
        let urlChanged: Bool
        let nameChanged: Bool
    }

    func updateSubscription(originalName: String, newName rawNewName: String,
                            url rawURL: String, updateInterval: TimeInterval) throws -> EditOutcome {
        let newName = SubscriptionMerge.sanitize(name: rawNewName)
        guard !newName.isEmpty else { throw ManagerError.unknownName(rawNewName) }
        let url = rawURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let parsed = URL(string: url),
              let scheme = parsed.scheme?.lowercased(),
              ["http", "https", "file"].contains(scheme) else {
            throw ManagerError.invalidURL(url)
        }
        var oldURLToRemove: String?
        let outcome = try lock.withLock { () -> EditOutcome in
            guard let index = subscriptions.firstIndex(where: { $0.name == originalName }) else {
                throw ManagerError.unknownName(originalName)
            }
            if newName != originalName, subscriptions.contains(where: { $0.name == newName }) {
                throw ManagerError.duplicateName(newName)
            }
            let old = subscriptions[index]
            let urlChanged = old.url != url
            let nameChanged = old.name != newName
            subscriptions[index].name = newName
            subscriptions[index].url = url
            subscriptions[index].updateInterval = max(0, updateInterval)
            if urlChanged {
                subscriptions[index].lastError = nil
                subscriptions[index].lastUpdated = nil
                subscriptions[index].lastFormat = nil
                subscriptions[index].lastProxyCount = 0
                if !subscriptions.enumerated().contains(where: { $0.offset != index && $0.element.url == old.url }) {
                    oldURLToRemove = old.url
                }
            }
            if activeName == originalName {
                activeName = newName
            }
            return EditOutcome(subscription: subscriptions[index],
                               urlChanged: urlChanged,
                               nameChanged: nameChanged)
        }
        if let oldURLToRemove {
            try? FileManager.default.removeItem(at: cacheURL(for: oldURLToRemove))
            if let fileURL = URL(string: oldURLToRemove), fileURL.isFileURL,
               fileURL.deletingLastPathComponent().standardizedFileURL == cacheDirectory.standardizedFileURL {
                try? FileManager.default.removeItem(at: fileURL)
            }
        }
        save()
        saveSelection()
        return outcome
    }

    func importFile(name rawName: String, sourceURL: URL) throws -> PreparedUpdate {
        let fallbackName = sourceURL.deletingPathExtension().lastPathComponent
        let requested = SubscriptionMerge.sanitize(name: rawName)
        let name = uniqueName(basedOn: requested.isEmpty ? fallbackName : requested)
        let raw = try String(contentsOf: sourceURL, encoding: .utf8)
        let contents = try SubscriptionDocument.parse(raw)
        let digest = SHA256.hash(data: Data(name.utf8)).map { String(format: "%02x", $0) }.joined()
        let managedFileURL = cacheDirectory.appendingPathComponent("imported-\(digest).conf")
        try raw.write(to: managedFileURL, atomically: true, encoding: .utf8)
        _ = Darwin.chmod(managedFileURL.path, S_IRUSR | S_IWUSR)
        let location = managedFileURL.absoluteString
        try? save(raw: raw, for: location)
        let origPath = sourceURL.isFileURL ? sourceURL.path : nil
        lock.withLock {
            if let index = subscriptions.firstIndex(where: { $0.name == name }) {
                subscriptions[index].url = location
                subscriptions[index].updateInterval = 0
                subscriptions[index].originalFilePath = origPath
            } else {
                subscriptions.append(Subscription(name: name, url: location, updateInterval: 0, originalFilePath: origPath))
            }
            activeName = name
        }
        save()
        saveSelection()
        return PreparedUpdate(
            name: name, sourceURL: location, contents: contents,
            result: UpdateResult(name: name, format: contents.format,
                                 proxyCount: contents.proxyNames.count,
                                 groupCount: contents.groupNames.count,
                                 warnings: contents.warnings, usedCache: false),
            downloadedBody: raw)
    }

    func remove(name: String) {
        let removedURL: String? = lock.withLock {
            let url = subscriptions.first(where: { $0.name == name })?.url
            subscriptions.removeAll { $0.name == name }
            if activeName == name {
                activeName = subscriptions.first?.name
            }
            return url
        }
        if let removedURL {
            try? FileManager.default.removeItem(at: cacheURL(for: removedURL))
            if let fileURL = URL(string: removedURL), fileURL.isFileURL,
               fileURL.deletingLastPathComponent().standardizedFileURL == cacheDirectory.standardizedFileURL {
                try? FileManager.default.removeItem(at: fileURL)
            }
        }
        save()
        saveSelection()
    }

    /// Subscriptions whose interval has elapsed.
    func dueForRefresh(now: Date = Date()) -> [Subscription] {
        lock.withLock {
            let currentSelected = activeName ?? subscriptions.first?.name
            return subscriptions.filter { subscription in
                guard subscription.name == currentSelected else { return false }
                guard URL(string: subscription.url)?.isFileURL != true else { return false }
                guard subscription.updateInterval > 0 else { return false }
                guard let last = subscription.lastUpdated else { return true }
                return now.timeIntervalSince(last) >= subscription.updateInterval
            }
        }
    }

    // MARK: Updating

    /// Downloads without taking a snapshot of the editor. No update is marked
    /// successful until the caller has applied and persisted its merged text.
    func prepareUpdate(name: String) throws -> PreparedUpdate {
        guard let subscription = lock.withLock({ subscriptions.first { $0.name == name } }) else {
            throw ManagerError.unknownName(name)
        }
        var usedCache = false
        var raw: String
        do {
            raw = try download(subscription.url)
        } catch {
            // A stale copy keeps the profile loadable when the provider is
            // unreachable; failing outright would strand the user offline.
            guard let cached = cachedBody(for: subscription.url) else { throw error }
            raw = cached
            usedCache = true
        }
        // Parse before caching. Overwriting the cache with the raw body first
        // destroyed the last known-good copy, so one bad response left the user
        // with nothing to fall back on — and, since the cache is the offline
        // fallback, a body that crashes the parser would be replayed on every
        // subsequent launch.
        let contents = try SubscriptionDocument.parse(raw)
        var warnings = contents.warnings
        if usedCache { warnings.append("无法访问订阅地址，已使用上次缓存内容") }
        return PreparedUpdate(
            name: subscription.name, sourceURL: subscription.url, contents: contents,
            result: UpdateResult(name: subscription.name, format: contents.format,
                                 proxyCount: contents.proxyNames.count,
                                 groupCount: contents.groupNames.count,
                                 warnings: warnings, usedCache: usedCache),
            downloadedBody: usedCache ? nil : raw)
    }

    /// Loads cached subscription contents immediately when switching
    /// subscriptions, falling back to a live fetch only if no cache exists yet.
    func prepareSelection(name: String) throws -> PreparedUpdate {
        guard let subscription = lock.withLock({ subscriptions.first { $0.name == name } }) else {
            throw ManagerError.unknownName(name)
        }
        if let cached = cachedBody(for: subscription.url),
           let contents = try? SubscriptionDocument.parse(cached) {
            return PreparedUpdate(
                name: subscription.name, sourceURL: subscription.url, contents: contents,
                result: UpdateResult(name: subscription.name, format: contents.format,
                                     proxyCount: contents.proxyNames.count,
                                     groupCount: contents.groupNames.count,
                                     warnings: contents.warnings, usedCache: true),
                downloadedBody: nil)
        }
        return try prepareUpdate(name: name)
    }

    func isCurrent(_ update: PreparedUpdate) -> Bool {
        lock.withLock {
            subscriptions.contains { $0.name == update.name && $0.url == update.sourceURL }
        }
    }

    func recordApplied(_ update: PreparedUpdate) {
        record(name: update.name, sourceURL: update.sourceURL) {
            $0.lastUpdated = Date()
            $0.lastFormat = update.contents.format
            $0.lastError = update.result.usedCache ? "更新失败，已使用缓存" : nil
            $0.lastProxyCount = update.contents.proxyNames.count
        }
        // A syntactically valid subscription can still fail when merged with
        // the full profile or when a live adapter reloads. Keep the previous
        // known-good offline copy until the caller commits the new profile.
        if let raw = update.downloadedBody {
            cacheQueue.async { [weak self] in
                guard let self, self.isCurrent(update) else { return }
                try? self.save(raw: raw, for: update.sourceURL)
            }
        }
    }

    func recordFailure(name: String, error: Error) {
        record(name: name) { $0.lastError = error.localizedDescription }
    }

    /// Persists edits made in the Policies/Rules UI directly back into the active
    /// subscription's cached configuration file (and managed/imported file on disk)
    /// so reopening the app or switching subscriptions never loses added/edited nodes.
    func syncEditedProfileText(_ text: String, proxyCount: Int) {
        guard let sub = activeSubscription else { return }
        record(name: sub.name, sourceURL: sub.url) {
            $0.lastProxyCount = proxyCount
        }
        cacheQueue.async { [weak self] in
            guard let self else { return }
            try? self.save(raw: text, for: sub.url)
            if let fileURL = URL(string: sub.url), fileURL.isFileURL {
                try? text.write(to: fileURL, atomically: true, encoding: .utf8)
                _ = Darwin.chmod(fileURL.path, S_IRUSR | S_IWUSR)
            }
            if let origPath = sub.originalFilePath, !origPath.isEmpty,
               (origPath.lowercased().hasSuffix(".conf") || sub.lastFormat == .surge),
               FileManager.default.isWritableFile(atPath: origPath) {
                try? text.write(to: URL(fileURLWithPath: origPath), atomically: true, encoding: .utf8)
            }
        }
    }

    private func record(name: String, sourceURL: String? = nil,
                        _ body: (inout Subscription) -> Void) {
        lock.withLock {
            guard let index = subscriptions.firstIndex(where: { $0.name == name }),
                  sourceURL == nil || subscriptions[index].url == sourceURL else { return }
            body(&subscriptions[index])
        }
        save()
    }

    // MARK: Persistence

    private func load() {
        let savedSelected = (try? String(contentsOf: selectedStoreURL, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = try? Data(contentsOf: storeURL),
              let decoded = try? JSONDecoder().decode([Subscription].self, from: data) else {
            return
        }
        lock.withLock {
            subscriptions = decoded
            if let savedSelected, !savedSelected.isEmpty,
               decoded.contains(where: { $0.name == savedSelected }) {
                activeName = savedSelected
            } else {
                activeName = decoded.first?.name
            }
        }
    }

    private func saveSelection() {
        let current = lock.withLock { activeName } ?? ""
        let url = selectedStoreURL
        cacheQueue.async {
            if current.isEmpty {
                try? FileManager.default.removeItem(at: url)
            } else {
                try? current.write(to: url, atomically: true, encoding: .utf8)
                _ = Darwin.chmod(url.path, S_IRUSR | S_IWUSR)
            }
        }
    }

    private func save() {
        let snapshot = lock.withLock { subscriptions }
        let url = storeURL
        cacheQueue.async {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            guard let data = try? encoder.encode(snapshot) else { return }
            try? data.write(to: url, options: .atomic)
            _ = Darwin.chmod(url.path, S_IRUSR | S_IWUSR)
        }
    }

    private func cacheURL(for location: String) -> URL {
        let digest = SHA256.hash(data: Data(location.utf8)).map { String(format: "%02x", $0) }.joined()
        return cacheDirectory.appendingPathComponent(digest + ".txt")
    }

    private func save(raw: String, for location: String) throws {
        let url = cacheURL(for: location)
        try raw.write(to: url, atomically: true, encoding: .utf8)
        _ = Darwin.chmod(url.path, S_IRUSR | S_IWUSR)
    }

    private func cachedBody(for location: String) -> String? {
        try? String(contentsOf: cacheURL(for: location), encoding: .utf8)
    }

    private func download(_ location: String) throws -> String {
        guard let url = URL(string: location) else { throw ManagerError.invalidURL(location) }
        if url.isFileURL { return try String(contentsOf: url, encoding: .utf8) }
        let semaphore = DispatchSemaphore(value: 0)
        let resultLock = NSLock()
        var result: Result<Data, Error>?
        let task = session.dataTask(with: url) { data, response, error in
            resultLock.lock()
            defer { resultLock.unlock(); semaphore.signal() }
            if let error { result = .failure(error); return }
            if let response = response as? HTTPURLResponse,
               !(200...299).contains(response.statusCode) {
                result = .failure(ManagerError.http(response.statusCode)); return
            }
            result = .success(data ?? Data())
        }
        task.resume()
        guard semaphore.wait(timeout: .now() + 45) == .success else {
            task.cancel()
            throw URLError(.timedOut)
        }
        resultLock.lock()
        let completed = result
        resultLock.unlock()
        guard let completed else { throw URLError(.unknown) }
        return String(decoding: try completed.get(), as: UTF8.self)
    }
}

/// The editor is read when the prepared downloads are applied, not before the
/// network calls. In particular, concurrent refreshes may replace their own
/// blocks without discarding edits or another subscription's completed block.
enum SubscriptionRefreshMerge {
    static func apply(_ updates: [(name: String, contents: SubscriptionContents)],
                      toCurrentText currentText: () -> String) -> String {
        updates.reduce(currentText()) { text, update in
            SubscriptionMerge.apply(update.contents, name: update.name, to: text)
        }
    }

    static func activate(_ update: (name: String, contents: SubscriptionContents)?,
                         toCurrentText currentText: () -> String) -> String {
        let text = currentText()
        guard let update else {
            var cleaned = text
            for existing in SubscriptionMerge.managedNames(in: cleaned) {
                cleaned = SubscriptionMerge.remove(name: existing, from: cleaned)
            }
            return SubscriptionMerge.reconcileDanglingRulePolicies(in: cleaned)
        }
        return SubscriptionMerge.replaceExclusively(update.contents, name: update.name, in: text)
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }
        return try body()
    }
}

import Foundation
import Darwin
import HajimiCore

final class ConfigurationStore {
    let directoryURL: URL
    let profileURL: URL
    private let lock = NSLock()
    private let ioQueue = DispatchQueue(label: "app.hajimi.config-store.io", qos: .utility)
    private var cachedText: String?
    private var cachedMtime: Date?
    private var pendingWrites = 0

    init(fileManager: FileManager = .default) {
        let base = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        directoryURL = base.appendingPathComponent("Hajimi", isDirectory: true)
        profileURL = directoryURL.appendingPathComponent("profile.conf")
        try? fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directoryURL.path)
        if !fileManager.fileExists(atPath: profileURL.path) {
            try? defaultProfileText.write(to: profileURL, atomically: true, encoding: .utf8)
        }
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: profileURL.path)
    }

    private static func fileMtime(at path: String) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
    }

    func loadText() -> String {
        (try? loadTextThrowing()) ?? defaultProfileText
    }

    /// Startup must distinguish an unreadable profile from a fresh default.
    /// Otherwise a failed read can silently start with DIRECT routing.
    func loadTextThrowing() throws -> String {
        let path = profileURL.path
        let currentMtime = Self.fileMtime(at: path)
        lock.lock()
        if pendingWrites > 0, let cachedText {
            lock.unlock()
            return cachedText
        }
        if let cachedText, let cachedMtime, let currentMtime, cachedMtime == currentMtime {
            lock.unlock()
            return cachedText
        }
        lock.unlock()
        let text = try String(contentsOf: profileURL, encoding: .utf8)
        let afterMtime = Self.fileMtime(at: path)
        lock.lock()
        if pendingWrites == 0 {
            cachedText = text
            cachedMtime = afterMtime
        }
        lock.unlock()
        return text
    }

    func save(_ text: String) throws {
        let url = profileURL
        let path = url.path
        if Thread.isMainThread, FileManager.default.isWritableFile(atPath: directoryURL.path) {
            lock.lock()
            cachedText = text
            pendingWrites += 1
            lock.unlock()
            ioQueue.async { [weak self] in
                try? text.write(to: url, atomically: true, encoding: .utf8)
                _ = Darwin.chmod(path, S_IRUSR | S_IWUSR)
                let mtime = Self.fileMtime(at: path)
                guard let self else { return }
                self.lock.lock()
                self.pendingWrites = max(0, self.pendingWrites - 1)
                if self.pendingWrites == 0 {
                    self.cachedMtime = mtime
                }
                self.lock.unlock()
            }
            return
        }
        try text.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: path)
        let mtime = Self.fileMtime(at: path)
        lock.lock()
        cachedText = text
        cachedMtime = mtime
        lock.unlock()
    }
}

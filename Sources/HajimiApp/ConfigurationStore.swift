import Foundation
import HajimiCore

final class ConfigurationStore {
    let directoryURL: URL
    let profileURL: URL

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

    func loadText() -> String {
        (try? loadTextThrowing()) ?? defaultProfileText
    }

    /// Startup must distinguish an unreadable profile from a fresh default.
    /// Otherwise a failed read can silently start with DIRECT routing.
    func loadTextThrowing() throws -> String {
        try String(contentsOf: profileURL, encoding: .utf8)
    }

    func save(_ text: String) throws {
        try text.write(to: profileURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: profileURL.path)
    }
}

import Foundation
import HajimiCore

final class SystemProxyManager {
    struct ProxyState: Codable {
        var enabled: Bool
        var server: String
        var port: Int
    }

    struct ServiceSnapshot: Codable {
        var service: String
        var web: ProxyState
        var secureWeb: ProxyState
        var bypassDomains: [String]?
    }

    /// The original settings are only safe to restore while the current
    /// settings still belong to this app. Another proxy may take over while
    /// Hajimi is running; restoring our old snapshot would overwrite it.
    private struct ManagedSnapshot: Codable {
        var original: [ServiceSnapshot]
        /// Saved before each attempted rebind. Either port may be active if a
        /// privileged command partially succeeded or rolled back.
        var acceptedAddresses: [ListenAddress]
        var bypassDomains: [String: [String]]
    }

    enum ManagerError: LocalizedError {
        case command(String)
        case noServices
        case noSnapshot
        case ownershipLost(String)
        case authorizationCancelled
        case scriptTooLong

        var errorDescription: String? {
            switch self {
            case .command(let value): return value
            case .noServices: return "没有找到可用的网络服务"
            case .noSnapshot: return "找不到系统代理快照"
            case .ownershipLost(let service):
                return "网络服务“\(service)”的系统代理已被其他程序修改，哈基米不会覆盖它；请先检查系统网络设置"
            case .authorizationCancelled: return "已取消管理员授权，系统代理未更改"
            case .scriptTooLong: return "系统代理命令过长（网络服务或绕过域名过多），未执行修改"
            }
        }
    }

    private let queue = DispatchQueue(label: "app.hajimi.system-proxy", qos: .userInitiated)
    private let queueKey = DispatchSpecificKey<Bool>()
    private let snapshotURL: URL

    var isEnabledByHajimi: Bool { FileManager.default.fileExists(atPath: snapshotURL.path) }

    init(applicationSupportDirectory: URL) {
        snapshotURL = applicationSupportDirectory.appendingPathComponent("system-proxy-snapshot.json")
        queue.setSpecific(key: queueKey, value: true)
    }

    func enable(address: ListenAddress, bypassDomains: [String] = [],
                completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            do {
                var previousSnapshot: ManagedSnapshot?
                if self.isEnabledByHajimi {
                    let managed = try self.readSnapshot()
                    // Re-enabling is not the same as stopping: it would
                    // overwrite every service. Refuse it if another program
                    // now owns even one component of our previous snapshot.
                    _ = try self.checkOwnership(managed)
                    try self.disableSynchronously()
                    previousSnapshot = managed
                }
                let services = try self.networkServices()
                guard !services.isEmpty else { throw ManagerError.noServices }
                let snapshots = try services.map {
                    ServiceSnapshot(service: $0,
                                    web: try self.proxyState(argument: "-getwebproxy", service: $0),
                                    secureWeb: try self.proxyState(argument: "-getsecurewebproxy", service: $0),
                                    bypassDomains: try self.proxyBypassDomains(service: $0))
                }
                if let previousSnapshot {
                    // An external change between our first ownership check
                    // and the restore must not be mistaken for the new
                    // baseline and overwritten by this full re-enable.
                    guard snapshots.count == previousSnapshot.original.count else {
                        throw ManagerError.ownershipLost("网络服务列表")
                    }
                    let originals = Dictionary(
                        previousSnapshot.original.map { ($0.service, $0) },
                        uniquingKeysWith: { first, _ in first })
                    guard originals.count == snapshots.count else {
                        throw ManagerError.noSnapshot
                    }
                    for snapshot in snapshots {
                        guard let original = originals[snapshot.service],
                              Self.matchesStrictBaseline(snapshot.web, original: original.web,
                                                         snapshot: previousSnapshot),
                              Self.matchesStrictBaseline(snapshot.secureWeb,
                                                         original: original.secureWeb,
                                                         snapshot: previousSnapshot),
                              Self.sameDomains(snapshot.bypassDomains ?? [],
                                               original.bypassDomains ?? []) else {
                            throw ManagerError.ownershipLost(snapshot.service)
                        }
                    }
                }
                var commands: [String] = []
                var expectedBypass: [String: [String]] = [:]
                let server = self.proxyServer(address.host)
                for snapshot in snapshots {
                    let service = snapshot.service
                    commands.append(self.networksetup("-setwebproxy", service, server, String(address.port)))
                    commands.append(self.networksetup("-setwebproxystate", service, "on"))
                    commands.append(self.networksetup("-setsecurewebproxy", service, server, String(address.port)))
                    commands.append(self.networksetup("-setsecurewebproxystate", service, "on"))
                    let combined = self.unique((snapshot.bypassDomains ?? []) + bypassDomains)
                    expectedBypass[service] = combined
                    commands.append(self.proxyBypassCommand(service: service, domains: combined))
                }
                let rollbackCommands = snapshots.flatMap { self.restoreCommands(for: $0) }
                let script = self.enableScript(commands: commands, rollbackCommands: rollbackCommands)
                // Reject an oversized AppleScript argument before saving the
                // snapshot, since no privileged command can be attempted.
                try self.validateScriptLength(script)
                let managed = ManagedSnapshot(
                    original: snapshots,
                    acceptedAddresses: [ListenAddress(host: server, port: address.port)],
                    bypassDomains: expectedBypass)
                try self.saveSnapshot(managed)

                do { try self.runPrivileged(script) }
                catch ManagerError.authorizationCancelled {
                    // A cancelled *single* authorization cannot have applied
                    // any commands; avoid a spurious restore prompt on exit.
                    try? FileManager.default.removeItem(at: self.snapshotURL)
                    throw ManagerError.authorizationCancelled
                }
                // Any other error may have occurred after some services were
                // changed. The in-shell rollback has been attempted, but keep
                // this snapshot so a later disable can retry incomplete work.
                DispatchQueue.main.async { completion(.success(())) }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    /// Move an already enabled system proxy to a newly bound HTTP listener
    /// without restoring the original (often DIRECT) settings in between.
    /// Keep the original snapshot intact so a later disable still restores
    /// exactly the user's pre-Hajimi configuration.
    func repoint(from previous: ListenAddress, to address: ListenAddress,
                 completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            do {
                guard self.isEnabledByHajimi else { throw ManagerError.noSnapshot }
                var managed = try self.readSnapshot()
                guard !managed.original.isEmpty else { throw ManagerError.noServices }
                guard try self.checkOwnership(managed) else {
                    throw ManagerError.ownershipLost("所有网络服务")
                }
                let active = ListenAddress(host: self.proxyServer(previous.host),
                                           port: previous.port)
                for item in managed.original {
                    let web = try self.proxyState(argument: "-getwebproxy", service: item.service)
                    let secure = try self.proxyState(argument: "-getsecurewebproxy", service: item.service)
                    guard Self.matches(web, address: active),
                          Self.matches(secure, address: active) else {
                        throw ManagerError.ownershipLost(item.service)
                    }
                }
                let update = self.repointCommands(snapshots: managed.original, address: address)
                let rollback = self.repointCommands(snapshots: managed.original, address: previous)
                let normalized = ListenAddress(host: self.proxyServer(address.host), port: address.port)
                if !managed.acceptedAddresses.contains(normalized) {
                    managed.acceptedAddresses.append(normalized)
                    // This is written before invoking the admin command: a
                    // timeout must not leave a newly selected port untracked.
                    try self.saveSnapshot(managed)
                }
                try self.runPrivileged(self.enableScript(commands: update,
                                                         rollbackCommands: rollback))
                // A successful rebind has a single current owner. Keep both
                // endpoints only while an admin operation is uncertain.
                managed.acceptedAddresses = [normalized]
                try self.saveSnapshot(managed)
                DispatchQueue.main.async { completion(.success(())) }
            } catch {
                // The original snapshot remains available for a full restore
                // even if the in-script rollback also encountered an error.
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    func disable(completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            do {
                try self.disableSynchronously()
                DispatchQueue.main.async { completion(.success(())) }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    func disableSynchronously() throws {
        // Quit also calls this from the main thread. It must wait for any
        // in-flight administrator authorization/enable to finish first;
        // otherwise the restore can run before the proxy is actually enabled.
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            try performDisableSynchronously()
        } else {
            try queue.sync { try performDisableSynchronously() }
        }
    }

    private func performDisableSynchronously() throws {
        guard isEnabledByHajimi else { return }
        let managed = try readSnapshot()
        guard !managed.original.isEmpty, !managed.acceptedAddresses.isEmpty else {
            throw ManagerError.noSnapshot
        }

        var commands: [String] = []
        var uncheckedSettings: [String] = []
        for item in managed.original {
            do {
                let web = try proxyState(argument: "-getwebproxy", service: item.service)
                // A different app may have changed one component (or another
                // network service) while ours remains pointed at Hajimi. Only
                // restore components that *still* match the address/bypass
                // settings we installed; leave foreign and already-original
                // values untouched.
                if Self.shouldRestore(web, original: item.web, snapshot: managed) {
                    commands.append(checkedProxyRestoreCommand(
                        kind: "webproxy", state: item.web, service: item.service))
                }
            } catch {
                uncheckedSettings.append("\(item.service) HTTP")
            }
            do {
                let secure = try proxyState(argument: "-getsecurewebproxy", service: item.service)
                if Self.shouldRestore(secure, original: item.secureWeb, snapshot: managed) {
                    commands.append(checkedProxyRestoreCommand(
                        kind: "securewebproxy", state: item.secureWeb, service: item.service))
                }
            } catch {
                uncheckedSettings.append("\(item.service) HTTPS")
            }
            do {
                let bypass = try proxyBypassDomains(service: item.service)
                if Self.shouldRestoreBypass(bypass, original: item.bypassDomains,
                                           service: item.service, snapshot: managed),
                   let originalBypass = item.bypassDomains {
                    commands.append(checkedBypassRestoreCommand(service: item.service,
                        original: originalBypass,
                        installed: managed.bypassDomains[item.service] ?? originalBypass))
                }
            } catch {
                // Even a failed bypass lookup must not prevent restoring the
                // same service's separately readable HTTP/HTTPS components.
                uncheckedSettings.append("\(item.service) 绕过域名")
            }
        }
        if !commands.isEmpty {
            // Run all restorable changes even if one networksetup call fails.
            // `restoreScript` reports failure, leaving the snapshot for retry.
            // The preflight only avoids needless authorization prompts. Each
            // command rechecks ownership after authorization, immediately
            // before writing; a long-open prompt must not authorize stale data.
            try runPrivileged(restoreScript(commands: commands, snapshot: managed))
        }
        guard uncheckedSettings.isEmpty else {
            throw ManagerError.command("已恢复可确认归哈基米管理的系统代理，但无法检查这些网络服务设置："
                + uncheckedSettings.joined(separator: "、") + "；快照已保留以便重试")
        }
        // Everything still owned by Hajimi has been restored. Foreign values
        // belong to their new owner, so keeping our snapshot would risk
        // misidentifying them on a future enable/repoint.
        try FileManager.default.removeItem(at: snapshotURL)
    }

    func discardSnapshot() { try? FileManager.default.removeItem(at: snapshotURL) }

    private func readSnapshot() throws -> ManagedSnapshot {
        let data = try Data(contentsOf: snapshotURL)
        return try JSONDecoder().decode(ManagedSnapshot.self, from: data)
    }

    private func saveSnapshot(_ snapshot: ManagedSnapshot) throws {
        try JSONEncoder().encode(snapshot).write(to: snapshotURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: snapshotURL.path)
    }

    private func proxyServer(_ host: String) -> String {
        ["0.0.0.0", "::", ""].contains(host) ? "127.0.0.1" : host
    }

    private struct OwnershipDecision {
        var authorized: Bool
        var restoreWeb: Bool
        var restoreSecureWeb: Bool
        var restoreBypass: Bool

        var needsRestore: Bool { restoreWeb || restoreSecureWeb || restoreBypass }
    }

    private static func shouldRestore(_ current: ProxyState, original: ProxyState,
                                      snapshot: ManagedSnapshot) -> Bool {
        !matches(current, original: original)
            && snapshot.acceptedAddresses.contains { matches(current, address: $0) }
    }

    private static func shouldRestoreBypass(_ current: [String], original: [String]?,
                                            service: String, snapshot: ManagedSnapshot) -> Bool {
        guard let original else { return false }
        return !sameDomains(current, original)
            && sameDomains(current, snapshot.bypassDomains[service] ?? original)
    }

    /// For enable/repoint, a disabled proxy is not automatically "original":
    /// networksetup retains its last server/port while disabled. A third party
    /// can change those values without enabling the proxy, and re-enabling
    /// Hajimi must not silently overwrite them. The endpoint we installed is
    /// also allowed because disabling our own proxy leaves it behind.
    private static func matchesStrictBaseline(_ current: ProxyState, original: ProxyState,
                                              snapshot: ManagedSnapshot) -> Bool {
        guard current.enabled == original.enabled else { return false }
        if current.enabled { return matches(current, original: original) }
        let storedOriginal = current.port == original.port
            && current.server.caseInsensitiveCompare(original.server) == .orderedSame
        let storedOurs = snapshot.acceptedAddresses.contains { address in
            current.port == Int(address.port)
                && current.server.caseInsensitiveCompare(address.host) == .orderedSame
        }
        return storedOriginal || storedOurs
    }

    private static func ownershipDecision(_ item: ServiceSnapshot,
                                          currentWeb: ProxyState,
                                          currentSecureWeb: ProxyState,
                                          currentBypass: [String],
                                          snapshot: ManagedSnapshot) -> OwnershipDecision {
        let webOwned = snapshot.acceptedAddresses.contains {
            matches(currentWeb, address: $0)
        }
        let secureOwned = snapshot.acceptedAddresses.contains {
            matches(currentSecureWeb, address: $0)
        }
        let webOriginal = matchesStrictBaseline(currentWeb, original: item.web,
                                                snapshot: snapshot)
        let secureOriginal = matchesStrictBaseline(currentSecureWeb,
                                                   original: item.secureWeb,
                                                   snapshot: snapshot)
        let bypassOriginal = sameDomains(currentBypass, item.bypassDomains ?? [])
        let bypassOwned = sameDomains(currentBypass,
            snapshot.bypassDomains[item.service] ?? (item.bypassDomains ?? []))
        return OwnershipDecision(
            authorized: (webOwned || webOriginal) && (secureOwned || secureOriginal)
                && (bypassOwned || bypassOriginal),
            restoreWeb: shouldRestore(currentWeb, original: item.web, snapshot: snapshot),
            restoreSecureWeb: shouldRestore(currentSecureWeb, original: item.secureWeb,
                                           snapshot: snapshot),
            restoreBypass: shouldRestoreBypass(currentBypass, original: item.bypassDomains,
                                              service: item.service, snapshot: snapshot))
    }

    /// Reads the live network settings before changing a saved snapshot.
    /// A stale snapshot is not proof of ownership: Lurge, VPN software or the
    /// user may have changed a network service after our last update.
    private func checkOwnership(_ snapshot: ManagedSnapshot) throws -> Bool {
        guard !snapshot.original.isEmpty, !snapshot.acceptedAddresses.isEmpty else {
            throw ManagerError.noSnapshot
        }
        var needsRestore = false
        for item in snapshot.original {
            let web = try proxyState(argument: "-getwebproxy", service: item.service)
            let secureWeb = try proxyState(argument: "-getsecurewebproxy", service: item.service)
            let bypass = try proxyBypassDomains(service: item.service)
            let decision = Self.ownershipDecision(
                item, currentWeb: web, currentSecureWeb: secureWeb,
                currentBypass: bypass, snapshot: snapshot)
            guard decision.authorized else {
                throw ManagerError.ownershipLost(item.service)
            }
            needsRestore = needsRestore || decision.needsRestore
        }
        return needsRestore
    }

    private static func matches(_ current: ProxyState, address: ListenAddress) -> Bool {
        current.enabled && current.port == Int(address.port)
            && current.server.caseInsensitiveCompare(address.host) == .orderedSame
    }

    private static func matches(_ current: ProxyState, original: ProxyState) -> Bool {
        guard current.enabled == original.enabled else { return false }
        // Disabled proxies do not affect traffic, and networksetup may retain
        // the last host and port even after toggling their state off.
        return !current.enabled ||
            (current.port == original.port
             && current.server.caseInsensitiveCompare(original.server) == .orderedSame)
    }

    private static func sameDomains(_ lhs: [String], _ rhs: [String]) -> Bool {
        Set(lhs.map { $0.lowercased() }) == Set(rhs.map { $0.lowercased() })
    }

    /// Regression checks use only value fixtures and an in-memory shell mock;
    /// never invokes real networksetup, administrator authorization or routes.
    static func ownershipSelfTest() -> Bool {
        let old = ProxyState(enabled: true, server: "127.0.0.1", port: 7162)
        let own = ProxyState(enabled: true, server: "127.0.0.1", port: 7262)
        let foreign = ProxyState(enabled: true, server: "127.0.0.1", port: 9000)
        let original = ServiceSnapshot(service: "Wi-Fi", web: old,
                                       secureWeb: old, bypassDomains: ["localhost"])
        let snapshot = ManagedSnapshot(
            original: [original],
            acceptedAddresses: [ListenAddress(host: "127.0.0.1", port: 7262)],
            bypassDomains: ["Wi-Fi": ["localhost", "internal.example"]])
        let owned = ownershipDecision(original, currentWeb: own,
            currentSecureWeb: own, currentBypass: ["internal.example", "localhost"],
            snapshot: snapshot)
        let restored = ownershipDecision(original, currentWeb: old,
            currentSecureWeb: old, currentBypass: ["localhost"], snapshot: snapshot)
        let stolen = ownershipDecision(original, currentWeb: foreign,
            currentSecureWeb: foreign, currentBypass: ["localhost"], snapshot: snapshot)
        let mixed = ownershipDecision(original, currentWeb: own,
            currentSecureWeb: foreign, currentBypass: ["localhost"], snapshot: snapshot)
        let changedBypass = ownershipDecision(original, currentWeb: own,
            currentSecureWeb: own, currentBypass: ["somebody-else.example"], snapshot: snapshot)
        let foreignServiceWithOwnedComponent = ownershipDecision(
            original, currentWeb: foreign, currentSecureWeb: own,
            currentBypass: ["localhost", "internal.example"], snapshot: snapshot)
        let foreignBypassWithOwnedComponents = ownershipDecision(
            original, currentWeb: own, currentSecureWeb: own,
            currentBypass: ["somebody-else.example"], snapshot: snapshot)
        let disabledOriginal = ProxyState(enabled: false, server: "old.example", port: 8080)
        let disabledRetained = ProxyState(enabled: false, server: "127.0.0.1", port: 7262)
        let disabledForeign = ProxyState(enabled: false, server: "foreign.example", port: 9000)
        let originalDisabled = ServiceSnapshot(service: "Wi-Fi", web: disabledOriginal,
                                               secureWeb: disabledOriginal,
                                               bypassDomains: ["localhost"])
        let disabledOwnedDecision = ownershipDecision(
            originalDisabled, currentWeb: disabledRetained,
            currentSecureWeb: disabledOriginal, currentBypass: ["localhost"], snapshot: snapshot)
        let disabledForeignDecision = ownershipDecision(
            originalDisabled, currentWeb: disabledForeign,
            currentSecureWeb: disabledRetained, currentBypass: ["localhost"], snapshot: snapshot)
        let decisionsMatch = owned.authorized && owned.needsRestore
            && restored.authorized && !restored.needsRestore
            && !stolen.authorized && !mixed.authorized && !changedBypass.authorized
            && mixed.restoreWeb && !mixed.restoreSecureWeb && !mixed.restoreBypass
            && foreignServiceWithOwnedComponent.restoreSecureWeb
            && foreignServiceWithOwnedComponent.restoreBypass
            && !foreignServiceWithOwnedComponent.restoreWeb
            && foreignBypassWithOwnedComponents.restoreWeb
            && foreignBypassWithOwnedComponents.restoreSecureWeb
            && !foreignBypassWithOwnedComponents.restoreBypass
            && disabledOwnedDecision.authorized && !disabledOwnedDecision.needsRestore
            && !disabledForeignDecision.authorized && !disabledForeignDecision.needsRestore
        return decisionsMatch && executionTimeRestoreSelfTest()
    }

    /// Exercise the actual generated restore script, substituting only its
    /// networksetup executable with a shell function. No files/network change.
    private static func executionTimeRestoreSelfTest() -> Bool {
        let manager = SystemProxyManager(applicationSupportDirectory: URL(fileURLWithPath: "/dev/null"))
        let service = "Wi'Fi $(printf injected) \"quoted\""
        let originalBypass = ["localhost", "quote'example"]
        let installedBypass = originalBypass + ["internal.example"]
        let old = ProxyState(enabled: true, server: "127.0.0.1", port: 7162)
        let item = ServiceSnapshot(service: service, web: old, secureWeb: old,
                                   bypassDomains: originalBypass)
        let snapshot = ManagedSnapshot(original: [item],
            acceptedAddresses: [ListenAddress(host: "127.0.0.1", port: 7262)],
            bypassDomains: [service: installedBypass])
        let quote = manager.shellQuote
        let mock = """
        expected_service=\(quote(service))
        original_bypass=\(quote(originalBypass.joined(separator: "\n")))
        web_enabled=yes; web_server=127.0.0.1; web_port=7262
        secure_enabled=yes; secure_server=127.0.0.1; secure_port=7262
        bypass=\(quote(installedBypass.joined(separator: "\n")))
        web_read_error=no; web_malformed=no; web_write_error=no; writes=0
        mock_networksetup() {
            [ "$2" = "$expected_service" ] || return 96
            case "$1" in
            -getwebproxy)
                [ "$web_read_error" = 'no' ] || return 1
                enabled=$web_enabled
                [ "$web_malformed" = 'no' ] || enabled=unknown
                printf 'Enabled: %s\\nServer: %s\\nPort: %s\\n' "$enabled" "$web_server" "$web_port"
                ;;
            -getsecurewebproxy)
                printf 'Enabled: %s\\nServer: %s\\nPort: %s\\n' "$secure_enabled" "$secure_server" "$secure_port"
                ;;
            -getproxybypassdomains)
                if [ -n "$bypass" ]; then printf '%s\\n' "$bypass"
                else printf '%s\\n' "There aren't any bypass domains set on this service."
                fi
                ;;
            -setwebproxy)
                if [ "$web_write_error" = 'yes' ]; then printf '%s\\n' 'write:web-failed'; return 1; fi
                web_enabled=yes; web_server=$3; web_port=$4
                writes=$((writes + 1)); printf '%s\\n' 'write:web'
                ;;
            -setsecurewebproxy)
                secure_enabled=yes; secure_server=$3; secure_port=$4
                writes=$((writes + 1)); printf '%s\\n' 'write:secure'
                ;;
            -setwebproxystate)
                [ "$3" = 'off' ] || return 97
                web_enabled=no; writes=$((writes + 1)); printf '%s\\n' 'write:web-off'
                ;;
            -setsecurewebproxystate)
                [ "$3" = 'off' ] || return 97
                secure_enabled=no; writes=$((writes + 1)); printf '%s\\n' 'write:secure-off'
                ;;
            -setproxybypassdomains)
                shift 2
                if [ "$#" -eq 1 ] && [ "$1" = 'Empty' ]; then bypass=''
                else bypass=$(printf '%s\\n' "$@")
                fi
                writes=$((writes + 1)); printf '%s\\n' 'write:bypass'
                ;;
            *) return 98 ;;
            esac
        }
        """
        func script(_ managed: ManagedSnapshot) -> String {
            let commands = managed.original.flatMap { value -> [String] in
                var result = [manager.checkedProxyRestoreCommand(kind: "webproxy",
                    state: value.web, service: value.service),
                    manager.checkedProxyRestoreCommand(kind: "securewebproxy",
                    state: value.secureWeb, service: value.service)]
                if let original = value.bypassDomains {
                    result.append(manager.checkedBypassRestoreCommand(service: value.service,
                        original: original, installed: managed.bypassDomains[value.service] ?? original))
                }
                return result
            }
            return manager.restoreScript(commands: commands, snapshot: managed,
                                         networksetupExecutable: "mock_networksetup")
        }
        func fixture(_ name: String, setup: String = "", managed: ManagedSnapshot? = nil,
                     assertions: String = ":", status: Int32 = 0, writes: [String]) -> Bool {
            let body = mock + "\n" + setup + "\n" + script(managed ?? snapshot)
                + "\n" + assertions + " || exit 91\nprintf '%s\\n' fixture-ok\n"
            let process = Process()
            let output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", body]
            process.standardOutput = output; process.standardError = output
            do { try process.run() } catch { return false }
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let result = String(data: data, encoding: .utf8) ?? ""
            let actualWrites = result.components(separatedBy: .newlines).filter { $0.hasPrefix("write:") }
            let passed = process.terminationStatus == status && actualWrites == writes
                && (status != 0 || result.contains("fixture-ok")) && !result.contains("injected")
            if !passed {
                FileHandle.standardError.write(Data(
                    "System proxy mock fixture failed (\(name)): \(result)\n".utf8))
            }
            return passed
        }
        let bothRestored = "[ \"$web_port\" = 7162 ] && [ \"$secure_port\" = 7162 ] && [ \"$bypass\" = \"$original_bypass\" ]"
        guard fixture("owned, quoting and bypass set comparison",
            setup: "bypass=\(quote("INTERNAL.EXAMPLE\nquote'example\nLOCALHOST\nlocalhost"))",
            assertions: bothRestored, writes: ["write:web", "write:secure", "write:bypass"]),
            fixture("changed during authorization: all foreign",
                setup: "web_port=9000; secure_port=9001; bypass=foreign.example",
                assertions: "[ \"$web_port\" = 9000 ] && [ \"$secure_port\" = 9001 ] && [ \"$bypass\" = foreign.example ]",
                writes: []),
            fixture("mixed original, owned and foreign components",
                setup: "web_port=7162; bypass=foreign.example",
                assertions: "[ \"$web_port\" = 7162 ] && [ \"$secure_port\" = 7162 ] && [ \"$bypass\" = foreign.example ]",
                writes: ["write:secure"]),
            fixture("failed live read preserves failure and restores other components",
                setup: "web_read_error=yes", status: 1, writes: ["write:secure", "write:bypass"]),
            fixture("malformed live state must not authorize writes",
                setup: "web_malformed=yes", status: 1, writes: ["write:secure", "write:bypass"]),
            fixture("partial write failure remains retryable",
                setup: "web_write_error=yes", status: 1,
                writes: ["write:web-failed", "write:secure", "write:bypass"]),
            fixture("retry only remaining owned component",
                setup: "secure_port=7162; bypass=$original_bypass", assertions: bothRestored,
                writes: ["write:web"]),
            fixture("user disabled component must be preserved",
                setup: "web_enabled=no; bypass=foreign.example",
                assertions: "[ \"$web_enabled\" = no ] && [ \"$web_port\" = 7262 ] && [ \"$secure_port\" = 7162 ]",
                writes: ["write:secure"]) else { return false }
        var disabled = snapshot
        disabled.original[0].web.enabled = false
        disabled.original[0].secureWeb.enabled = false
        var rebound = snapshot
        rebound.acceptedAddresses.append(ListenAddress(host: "127.0.0.1", port: 7362))
        var emptyBypass = snapshot
        emptyBypass.original[0].bypassDomains = []
        emptyBypass.bypassDomains[service] = ["internal.example"]
        return fixture("originally disabled endpoints are never briefly re-enabled",
            setup: "bypass=foreign.example", managed: disabled,
            assertions: "[ \"$web_enabled\" = no ] && [ \"$secure_enabled\" = no ] && [ \"$web_port\" = 7262 ] && [ \"$secure_port\" = 7262 ]",
            writes: ["write:web-off", "write:secure-off"])
            && fixture("uncertain rebind accepts both owned endpoints",
                setup: "secure_port=7362", managed: rebound, assertions: bothRestored,
                writes: ["write:web", "write:secure", "write:bypass"])
            && fixture("empty bypass is restored with the Empty sentinel",
                setup: "web_port=7162; secure_port=7162; bypass=internal.example", managed: emptyBypass,
                assertions: "[ -z \"$bypass\" ]", writes: ["write:bypass"])
    }

    private func restoreCommands(for item: ServiceSnapshot) -> [String] {
        var commands = restoreCommands(kind: "webproxy", state: item.web, service: item.service)
        commands.append(contentsOf: restoreCommands(kind: "securewebproxy", state: item.secureWeb,
                                                   service: item.service))
        if let bypass = item.bypassDomains {
            commands.append(proxyBypassCommand(service: item.service, domains: bypass))
        }
        return commands
    }

    private func restoreCommands(kind: String, state: ProxyState, service: String) -> [String] {
        var result: [String] = []
        if !state.server.isEmpty && state.port > 0 {
            result.append(networksetup("-set\(kind)", service, state.server, String(state.port)))
        }
        result.append(networksetup("-set\(kind)state", service, state.enabled ? "on" : "off"))
        return result
    }

    private func networkServices() throws -> [String] {
        let output = try run("/usr/sbin/networksetup", ["-listallnetworkservices"])
        return output.components(separatedBy: .newlines)
            .dropFirst()
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && !$0.hasPrefix("*") }
    }

    private func proxyState(argument: String, service: String) throws -> ProxyState {
        let output = try run("/usr/sbin/networksetup", [argument, service])
        var values: [String: String] = [:]
        for line in output.components(separatedBy: .newlines) {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            values[key] = value
        }
        return ProxyState(enabled: values["Enabled"]?.lowercased() == "yes",
                          server: values["Server"] ?? "",
                          port: Int(values["Port"] ?? "0") ?? 0)
    }

    private func proxyBypassDomains(service: String) throws -> [String] {
        let output = try run("/usr/sbin/networksetup", ["-getproxybypassdomains", service])
        if output.lowercased().contains("there aren't any bypass domains") { return [] }
        return output.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private func proxyBypassCommand(service: String, domains: [String]) -> String {
        networksetup(["-setproxybypassdomains", service] + (domains.isEmpty ? ["Empty"] : domains))
    }

    private func repointCommands(snapshots: [ServiceSnapshot],
                                 address: ListenAddress) -> [String] {
        let server = ["0.0.0.0", "::", ""].contains(address.host) ? "127.0.0.1" : address.host
        return snapshots.flatMap { item in
            let service = item.service
            return [
                networksetup("-setwebproxy", service, server, String(address.port)),
                networksetup("-setwebproxystate", service, "on"),
                networksetup("-setsecurewebproxy", service, server, String(address.port)),
                networksetup("-setsecurewebproxystate", service, "on")
            ]
        }
    }

    private func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0.lowercased()).inserted }
    }

    private func networksetup(_ arguments: String...) -> String {
        networksetup(arguments)
    }

    private func networksetup(_ arguments: [String]) -> String {
        (["/usr/sbin/networksetup"] + arguments).map(shellQuote).joined(separator: " ")
    }

    private func enableScript(commands: [String], rollbackCommands: [String]) -> String {
        let rollback = rollbackCommands.map { "    \($0) || rollbackFailed=1" }.joined(separator: "\n")
        let apply = commands.map { "\($0) || { rollback; exit 1; }" }.joined(separator: "\n")
        return """
        rollback() {
            rollbackFailed=0
        \(rollback)
            if [ "$rollbackFailed" -ne 0 ]; then
                printf '%s\\n' '部分系统代理自动恢复失败；快照已保留，可重试恢复。' >&2
            fi
        }
        \(apply)
        """
    }

    private func checkedProxyRestoreCommand(kind: String, state: ProxyState,
                                             service: String) -> String {
        ["hajimi_restore_proxy", kind, service, state.enabled ? "yes" : "no",
         state.server, String(state.port)].map(shellQuote).joined(separator: " ")
    }

    private func checkedBypassRestoreCommand(service: String, original: [String],
                                              installed: [String]) -> String {
        (["hajimi_restore_bypass", service, original.joined(separator: "\n"),
          installed.joined(separator: "\n")] + (original.isEmpty ? ["Empty"] : original))
            .map(shellQuote).joined(separator: " ")
    }

    /// Rechecks live components in the elevated process, not before its prompt.
    /// `networksetup` owns its own SCPreferences transaction; taking a lock here
    /// and then spawning it would deadlock that writer. These checks close the
    /// authorization-window race but cannot make a separate get/set atomic.
    /// The executable override is private and used only by in-memory shell mocks.
    private func restoreScript(commands: [String], snapshot: ManagedSnapshot,
                               networksetupExecutable: String = "/usr/sbin/networksetup") -> String {
        let restore = commands.map { "\($0) || restoreFailed=1" }.joined(separator: "\n")
        let executable = shellQuote(networksetupExecutable)
        let ownedEnvironment = (["HAJIMI_OWNED_COUNT=\(snapshot.acceptedAddresses.count)"]
            + snapshot.acceptedAddresses.enumerated().flatMap { index, address in
                ["HAJIMI_OWNED_HOST_\(index)=\(shellQuote(address.host))",
                 "HAJIMI_OWNED_PORT_\(index)=\(address.port)"]
            }).joined(separator: " ")
        let proxyPredicate = """
        function trim(value) { sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); return value }
        /^Enabled:/ { enabled = tolower(trim(substr($0, index($0, ":") + 1))); enabledCount++ }
        /^Server:/ { server = tolower(trim(substr($0, index($0, ":") + 1))); serverCount++ }
        /^Port:/ { port = trim(substr($0, index($0, ":") + 1)); portCount++ }
        END {
            if (enabledCount != 1 || serverCount != 1 || portCount != 1 ||
                (enabled != "yes" && enabled != "no") || port !~ /^[0-9]+$/) exit 2
            if (enabled == ENVIRON["HAJIMI_ORIGINAL_ENABLED"] &&
                (enabled == "no" || (server == tolower(ENVIRON["HAJIMI_ORIGINAL_HOST"]) &&
                 port + 0 == ENVIRON["HAJIMI_ORIGINAL_PORT"] + 0))) exit 1
            if (enabled == "yes") {
                for (i = 0; i < ENVIRON["HAJIMI_OWNED_COUNT"] + 0; i++) {
                    if (server == tolower(ENVIRON["HAJIMI_OWNED_HOST_" i]) &&
                        port + 0 == ENVIRON["HAJIMI_OWNED_PORT_" i] + 0) exit 0
                }
            }
            exit 1
        }
        """
        let bypassPredicate = """
        function trim(value) { sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); return value }
        function same(left, right, key) {
            for (key in left) if (!(key in right)) return 0
            for (key in right) if (!(key in left)) return 0
            return 1
        }
        BEGIN {
            count = split(ENVIRON["HAJIMI_ORIGINAL_BYPASS"], values, "\\n")
            for (i = 1; i <= count; i++) if (length(values[i])) original[tolower(values[i])] = 1
            count = split(ENVIRON["HAJIMI_INSTALLED_BYPASS"], values, "\\n")
            for (i = 1; i <= count; i++) if (length(values[i])) installed[tolower(values[i])] = 1
        }
        {
            value = trim($0)
            if (tolower(value) ~ /there aren.t any bypass domains/) next
            if (length(value)) current[tolower(value)] = 1
        }
        END {
            if (same(current, original)) exit 1
            if (same(current, installed)) exit 0
            exit 1
        }
        """
        let proxyCheck = "printf '%s\\n' \"$current\" | "
            + "HAJIMI_ORIGINAL_ENABLED=\"$3\" HAJIMI_ORIGINAL_HOST=\"$4\" HAJIMI_ORIGINAL_PORT=\"$5\" "
            + ownedEnvironment + " /usr/bin/awk " + shellQuote(proxyPredicate)
        let bypassCheck = "printf '%s\\n' \"$current\" | "
            + "HAJIMI_ORIGINAL_BYPASS=\"$2\" HAJIMI_INSTALLED_BYPASS=\"$3\" /usr/bin/awk "
            + shellQuote(bypassPredicate)
        return """
        hajimi_restore_proxy() {
            current=$(\(executable) "-get$1" "$2") || return 1
            if \(proxyCheck); then
                if [ "$3" = 'yes' ]; then
                    [ -n "$4" ] && [ "$5" -gt 0 ] || return 1
                    # -setwebproxy/-setsecurewebproxy also enable the proxy:
                    # a second state-on write is redundant and adds a race.
                    \(executable) "-set$1" "$2" "$4" "$5" || return 1
                else
                    # Disabled endpoints do not affect traffic. Retaining the
                    # last server/port already satisfies matchesStrictBaseline;
                    # do not briefly re-enable them just to rewrite metadata.
                    \(executable) "-set${1}state" "$2" off || return 1
                fi
            else
                checkStatus=$?
                [ "$checkStatus" -eq 1 ] || return 1
            fi
            return 0
        }
        hajimi_restore_bypass() {
            current=$(\(executable) -getproxybypassdomains "$1") || return 1
            if \(bypassCheck); then
                service=$1
                shift 3
                \(executable) -setproxybypassdomains "$service" "$@" || return 1
            else
                checkStatus=$?
                [ "$checkStatus" -eq 1 ] || return 1
            fi
            return 0
        }
        restoreFailed=0
        \(restore)
        if [ "$restoreFailed" -ne 0 ]; then
            printf '%s\\n' '部分系统代理恢复失败；快照已保留，可重试恢复。' >&2
            exit 1
        fi
        """
    }

    private func validateScriptLength(_ script: String) throws {
        // Both osascript -e and /bin/sh -c receive a single argument. Stay
        // well below macOS's per-argument limit, including escaped characters.
        let command = "/bin/sh -c " + shellQuote(script)
        guard appleScriptEscape(command).utf8.count <= 64 * 1024 else {
            throw ManagerError.scriptTooLong
        }
    }

    private func runPrivileged(_ script: String) throws {
        try validateScriptLength(script)
        // Supply the fixed script itself to Authorization Services. No
        // user-writable file is read after the administrator grants access.
        let command = "/bin/sh -c " + shellQuote(script)
        let appleScript = """
        try
            do shell script "\(appleScriptEscape(command))" with administrator privileges
            return "success"
        on error errorMessage number errorNumber
            if errorNumber is -128 then return "cancelled"
            error errorMessage number errorNumber
        end try
        """
        let result = try run("/usr/bin/osascript", ["-e", appleScript])
        switch result.trimmingCharacters(in: .whitespacesAndNewlines) {
        case "success": break
        case "cancelled":
            throw ManagerError.authorizationCancelled
        default:
            throw ManagerError.command("管理员命令返回了未知结果；快照已保留，可重试恢复")
        }
    }

    private func appleScriptEscape(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = output
        try process.run()
        // Read while the child is running. A long existing bypass list can
        // otherwise fill the pipe and deadlock waitUntilExit() before we have
        // saved the snapshot needed to restore the network settings.
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let result = String(data: data, encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            let error = result.trimmingCharacters(in: .whitespacesAndNewlines)
            throw ManagerError.command(error.isEmpty ? "命令执行失败" : error)
        }
        return result
    }

    private func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

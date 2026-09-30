import Foundation
import Darwin
import CryptoKit
import Security
import HajimiIPC
import HajimiCore

/// Code identity the helper image must prove before it is installed as a root
/// launch daemon.
///
/// The App derives this from its *own* signature at runtime rather than from a
/// build-time constant, so a Developer ID build automatically demands that the
/// helper carry the same Team ID. `codesign --verify` alone is not sufficient:
/// on an ad-hoc signature it only proves internal consistency, which any
/// attacker-supplied binary can also produce after re-signing it ad-hoc.
enum HelperCodeIdentity {
    case team(String)
    case adHoc

    /// Designated requirement text, or nil when the App itself is ad-hoc signed
    /// and therefore has no identity to pin the helper against.
    var requirement: String? {
        switch self {
        case .team(let identifier):
            return "anchor apple generic and certificate leaf[subject.OU] = \"\(identifier)\""
        case .adHoc:
            return nil
        }
    }

    /// Reads the Team ID out of the running App's signature.
    static func current() -> HelperCodeIdentity {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return .adHoc }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else { return .adHoc }
        var information: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticCode, flags, &information) == errSecSuccess,
              let details = information as? [String: Any],
              let team = details[kSecCodeInfoTeamIdentifier as String] as? String,
              !team.isEmpty else { return .adHoc }
        return .team(team)
    }
}

final class PrivilegedHelperClient {
    enum InstallationStatus: Equatable {
        case notInstalled
        case needsUpdate
        case installed(running: Bool, revision: Int)

        var displayText: String {
            switch self {
            case .notInstalled: return "未安装"
            case .needsUpdate: return "已安装旧版本，需要更新"
            case .installed(let running, let revision):
                return running ? "已安装 · v\(HajimiHelperProtocol.version).\(revision) · 增强模式运行中"
                               : "已安装 · v\(HajimiHelperProtocol.version).\(revision)"
            }
        }
    }

    enum ClientError: LocalizedError {
        case helperUnavailable
        case bundledHelperMissing
        case incompatibleVersion(Int)
        case invalidResponse
        case installationFailed(String)
        case unverifiedHelperImage(String)
        case adHocInstallNotPermitted
        case helper(String)
        case command(String)

        var errorDescription: String? {
            switch self {
            case .helperUnavailable: return "root Helper 尚未安装或未运行"
            case .bundledHelperMissing: return "应用包中缺少 HajimiHelper"
            case .incompatibleVersion(let version):
                return "已安装 Helper 协议版本为 \(version)，需要更新到 \(HajimiHelperProtocol.version)"
            case .invalidResponse: return "root Helper 返回了无效响应"
            case .installationFailed(let value): return "安装 root Helper 失败：\(value)"
            case .unverifiedHelperImage(let value):
                return "拒绝以 root 安装未通过代码签名校验的 HajimiHelper：\(value)"
            case .adHocInstallNotPermitted:
                return """
                当前 Hajimi 使用 ad-hoc 签名，无法验证 HajimiHelper 的代码身份，已拒绝以 root 安装。
                正式分发请使用 Developer ID 签名（构建时设置 HAJIMI_SIGN_IDENTITY）。
                如果这是你自己构建的开发版本，可创建以下文件以明确接受该风险：
                \(PrivilegedHelperClient.adHocOptInPath)
                """
            case .helper(let value): return value
            case .command(let value): return value
            }
        }
    }

    /// Ad-hoc opt-in marker. An environment variable alone is not usable here
    /// because a Finder-launched App does not inherit a login shell's
    /// environment.
    static var adHocOptInPath: String {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("Hajimi/allow-adhoc-helper").path
    }

    private let ioQueue = DispatchQueue(label: "app.hajimi.helper-client", qos: .userInitiated)

    func status() throws -> HajimiHelperTunnelState {
        let state = try uncheckedStatus()
        guard state.helperProtocolVersion == HajimiHelperProtocol.version else {
            throw ClientError.incompatibleVersion(state.helperProtocolVersion)
        }
        guard state.helperBuildRevision == HajimiHelperProtocol.buildRevision else {
            throw ClientError.incompatibleVersion(state.helperProtocolVersion)
        }
        return state
    }

    func uncheckedStatus() throws -> HajimiHelperTunnelState {
        let response = try request(HajimiHelperRequest(action: .status))
        guard let state = response.response.state else { throw ClientError.invalidResponse }
        return state
    }

    func isCompatible(_ state: HajimiHelperTunnelState) -> Bool {
        state.helperProtocolVersion == HajimiHelperProtocol.version &&
            state.helperBuildRevision == HajimiHelperProtocol.buildRevision
    }

    struct TunnelSession {
        let state: HajimiHelperTunnelState
        /// Caller owns this descriptor and must close it (NativeTunnel.stop does).
        let fileDescriptor: Int32
    }

    /// Asks the helper to open utun / install routes and return the tunnel FD.
    func start(fakeIPEnabled: Bool, bypassAddresses: [String],
               excludedRoutes: [String] = [],
               includedRoutes: [String] = []) throws -> TunnelSession {
        let decoded = try request(HajimiHelperRequest(action: .start,
                                                      fakeIPEnabled: fakeIPEnabled,
                                                      bypassAddresses: bypassAddresses,
                                                      excludedRoutes: excludedRoutes,
                                                      includedRoutes: includedRoutes),
                                  expectFileDescriptor: true)
        guard let state = decoded.response.state, state.running,
              let fd = decoded.fileDescriptor, fd >= 0 else {
            if let fd = decoded.fileDescriptor, fd >= 0 { Darwin.close(fd) }
            throw ClientError.invalidResponse
        }
        return TunnelSession(state: state, fileDescriptor: fd)
    }

    /// Updates DNS redirection and proxy-host bypass routes only.
    func reload(fakeIPEnabled: Bool, bypassAddresses: [String],
                excludedRoutes: [String] = [],
                includedRoutes: [String] = []) throws -> HajimiHelperTunnelState {
        let decoded = try request(HajimiHelperRequest(action: .reload,
                                                      fakeIPEnabled: fakeIPEnabled,
                                                      bypassAddresses: bypassAddresses,
                                                      excludedRoutes: excludedRoutes,
                                                      includedRoutes: includedRoutes))
        guard let state = decoded.response.state, state.running else {
            throw ClientError.invalidResponse
        }
        return state
    }

    func stop() throws -> HajimiHelperTunnelState {
        let decoded = try request(HajimiHelperRequest(action: .stop))
        guard let state = decoded.response.state else { throw ClientError.invalidResponse }
        return state
    }

    /// Prompts only when the fixed root-owned launch daemon is absent or uses
    /// an incompatible protocol. Normal enhanced-mode start/stop requests use
    /// the Unix socket and never invoke Authorization Services/AppleScript.
    func ensureInstalled(completion: @escaping (Result<Void, Error>) -> Void) {
        ioQueue.async {
            do {
                try self.ensureInstalledSynchronously()
                DispatchQueue.main.async { completion(.success(())) }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    /// Used by the bundled maintenance command during an atomic App/Helper
    /// upgrade.  It runs the same verified installer as the Settings page.
    /// True when the installed binary differs from the one in this bundle.
    ///
    /// The helper binary is small, but a forgotten protocol bump still leaves
    /// an old launchd image answering on the socket. Comparing digests forces
    /// a reinstall whenever the bundled helper changes.
    private func installedBinaryDiffers() -> Bool {
        guard let source = bundledHelperURL,
              let bundled = try? Data(contentsOf: source) else { return false }
        guard let installed = try? Data(contentsOf:
                URL(fileURLWithPath: HajimiHelperProtocol.toolPath)) else { return true }
        return SHA256.hash(data: bundled) != SHA256.hash(data: installed)
    }

    func ensureInstalledSynchronously() throws {
        if let state = try? status(), isCompatible(state), !installedBinaryDiffers() { return }
        try install()
        let deadline = Date().addingTimeInterval(8)
        var lastError: Error = ClientError.helperUnavailable
        while Date() < deadline {
            do {
                let state = try status()
                guard isCompatible(state) else {
                    throw ClientError.incompatibleVersion(state.helperProtocolVersion)
                }
                return
            } catch {
                lastError = error
                usleep(100_000)
            }
        }
        throw lastError
    }

    func installationStatus(completion: @escaping (InstallationStatus) -> Void) {
        ioQueue.async {
            let value: InstallationStatus
            do {
                let state = try self.status()
                value = self.installedBinaryDiffers()
                    ? .needsUpdate
                    : .installed(running: state.running,
                                 revision: state.helperBuildRevision)
            } catch {
                value = FileManager.default.fileExists(atPath: HajimiHelperProtocol.toolPath)
                    ? .needsUpdate : .notInstalled
            }
            DispatchQueue.main.async { completion(value) }
        }
    }

    /// Explicit Settings-page install/update entry point.  It shares the
    /// exact verified installer used by enhanced mode and never starts an
    /// unprivileged compatibility process.
    func installOrUpdate(completion: @escaping (Result<Void, Error>) -> Void) {
        ensureInstalled(completion: completion)
    }

    func uninstall(completion: @escaping (Result<Void, Error>) -> Void) {
        ioQueue.async {
            do {
                // Ask a responsive Helper to remove its routes first.  The
                // launchd SIGTERM handler repeats cleanup before exiting.
                _ = try? self.stop()
                let label = self.shellQuote("system/\(HajimiHelperProtocol.label)")
                let tool = self.shellQuote(HajimiHelperProtocol.toolPath)
                let daemon = self.shellQuote(HajimiHelperProtocol.launchDaemonPath)
                let socket = self.shellQuote(HajimiHelperProtocol.socketPath)
                let script = """
                set -eu
                /bin/launchctl bootout \(label) >/dev/null 2>&1 || true
                /bin/rm -f \(socket) \(tool) \(daemon)
                """
                _ = try self.runPrivileged(script)
                DispatchQueue.main.async { completion(.success(())) }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    /// Carries an optional SCM_RIGHTS descriptor alongside the decoded JSON.
    private struct DecodedHelperResponse {
        let response: HajimiHelperResponse
        let fileDescriptor: Int32?
    }

    private func request(_ request: HajimiHelperRequest,
                         expectFileDescriptor: Bool = false) throws -> DecodedHelperResponse {
        var lastError: Error = ClientError.helperUnavailable
        for attempt in 0..<2 {
            do { return try requestOnce(request, expectFileDescriptor: expectFileDescriptor) }
            catch {
                lastError = error
                guard attempt == 0, isTransientIPCError(error),
                      !isTimeout(error) else { throw error }
                usleep(80_000)
            }
        }
        throw lastError
    }

    private func isTimeout(_ error: Error) -> Bool {
        if case ClientError.command(let message) = error {
            return message.contains("timed out") || message.contains("Operation timed out")
        }
        return false
    }

    private func requestOnce(_ request: HajimiHelperRequest,
                             expectFileDescriptor: Bool) throws -> DecodedHelperResponse {
        guard var encoded = try? JSONEncoder().encode(request) else {
            throw ClientError.invalidResponse
        }
        encoded.append(0x0a)
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ClientError.command(String(cString: strerror(errno))) }
        defer { Darwin.close(descriptor) }
        var noSigPipe: Int32 = 1
        _ = setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                       socklen_t(MemoryLayout.size(ofValue: noSigPipe)))
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(HajimiHelperProtocol.socketPath.utf8) + [0]
        guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw ClientError.command("Helper socket 路径过长")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: path) }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { throw ClientError.helperUnavailable }
        // Start/reload/stop may run several bounded route, ifconfig and DNS
        // commands in series. A 12-second socket timeout could fire after the
        // helper changed system routes but before it returned the utun FD.
        // Keep status/ping short; mutations need enough time to finish or roll
        // back and tell the App what happened.
        let timeoutSeconds = request.action == .status || request.action == .ping ? 3 : 45
        var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        try writeAll(encoded, to: descriptor)
        // Keep the write side open until after an optional SCM_RIGHTS receive:
        // some kernels deliver the control message more reliably before EOF.
        let responseData = try readLine(from: descriptor)
        guard let response = try? JSONDecoder().decode(HajimiHelperResponse.self, from: responseData) else {
            throw ClientError.invalidResponse
        }
        guard response.ok else { throw ClientError.helper(response.message ?? "root Helper 请求失败") }
        var fileDescriptor: Int32?
        if expectFileDescriptor || response.sendsTunnelFileDescriptor == true {
            do {
                fileDescriptor = try UnixFileDescriptorPassing.receive(on: descriptor)
            } catch {
                throw ClientError.command("接收 utun 描述符失败：\(error.localizedDescription)")
            }
        }
        _ = Darwin.shutdown(descriptor, SHUT_WR)
        return DecodedHelperResponse(response: response, fileDescriptor: fileDescriptor)
    }

    private func isTransientIPCError(_ error: Error) -> Bool {
        switch error {
        case ClientError.helperUnavailable, ClientError.invalidResponse: return true
        case ClientError.helper(let message):
            return message.contains("请求格式无效") || message.contains("请求为空")
        case ClientError.command(let message):
            return message.contains("Interrupted system call") || message.contains("Broken pipe")
        default: return false
        }
    }

    /// Validates the helper image against the App's own code identity before it
    /// is ever handed to an elevated process.
    ///
    /// This is the check that makes the installer safe. The App bundle lives in
    /// a user-writable location, so any process running as this user can swap
    /// `Contents/Resources/HajimiHelper`. Without an identity requirement that
    /// substituted binary would be installed as a root launch daemon.
    private func verifyHelperImage(at url: URL, identity: HelperCodeIdentity) throws {
        guard let requirement = identity.requirement else {
            let optIn = ProcessInfo.processInfo.environment["HAJIMI_ALLOW_ADHOC_HELPER"] == "1"
                || FileManager.default.fileExists(atPath: Self.adHocOptInPath)
            guard optIn else { throw ClientError.adHocInstallNotPermitted }
            return
        }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else {
            throw ClientError.unverifiedHelperImage("无法读取 \(url.lastPathComponent) 的代码签名")
        }
        var secRequirement: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, SecCSFlags(),
                                             &secRequirement) == errSecSuccess,
              let secRequirement else {
            throw ClientError.unverifiedHelperImage("无法构造代码签名要求")
        }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate
                               | kSecCSCheckAllArchitectures
                               | kSecCSCheckNestedCode)
        var failure: Unmanaged<CFError>?
        let status = SecStaticCodeCheckValidityWithErrors(staticCode, flags, secRequirement, &failure)
        guard status == errSecSuccess else {
            let detail = failure?.takeRetainedValue().localizedDescription
                ?? "OSStatus \(status)"
            throw ClientError.unverifiedHelperImage(detail)
        }
    }

    private func install() throws {
        guard let source = bundledHelperURL else { throw ClientError.bundledHelperMissing }
        let identity = HelperCodeIdentity.current()
        try verifyHelperImage(at: source, identity: identity)
        // Refuse to elevate a broken/stale helper image.
        let test = Process()
        test.executableURL = source
        test.arguments = ["--self-test"]
        test.standardOutput = FileHandle.nullDevice
        let testError = Pipe()
        test.standardError = testError
        try test.run(); test.waitUntilExit()
        guard test.terminationStatus == 0 else {
            let detail = String(data: testError.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw ClientError.installationFailed(detail.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        let uid = getuid()
        let sourceDigest = SHA256.hash(data: try Data(contentsOf: source))
            .map { String(format: "%02x", $0) }.joined()
        let plist: [String: Any] = [
            "Label": HajimiHelperProtocol.label,
            "ProgramArguments": [HajimiHelperProtocol.toolPath, "--uid", String(uid)],
            "RunAtLoad": true,
            "KeepAlive": true,
            "ProcessType": "Interactive",
            "ThrottleInterval": 2,
            "StandardOutPath": "/var/log/app.hajimi.helper.log",
            "StandardErrorPath": "/var/log/app.hajimi.helper.log"
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: plist,
                                                           format: .xml, options: 0)
        let encodedPlist = plistData.base64EncodedString()
        let sourcePath = shellQuote(source.path)
        let destination = shellQuote(HajimiHelperProtocol.toolPath)
        let daemonPath = shellQuote(HajimiHelperProtocol.launchDaemonPath)
        let label = shellQuote("system/\(HajimiHelperProtocol.label)")
        let plainLabel = shellQuote(HajimiHelperProtocol.label)
        // The unprivileged check above happens before the authorization prompt,
        // which the user may leave open for a long time. Re-verify the copied
        // image from the elevated context so a swap during that window cannot
        // get a different binary installed: the digest pins the exact bytes and
        // the requirement pins the signing identity. Failing either leaves no
        // helper behind.
        let requirementCheck = identity.requirement.map {
            "/usr/bin/codesign --verify --strict -R=\(shellQuote($0)) \(destination)"
        } ?? "/usr/bin/codesign --verify --strict \(destination)"
        let script = """
        set -eu
        /bin/launchctl bootout \(label) >/dev/null 2>&1 || true
        # launchd unregisters a job asynchronously. Bootstrapping while the
        # previous instance is still registered fails with
        # "Bootstrap failed: 5: Input/output error", so wait for it to go away
        # instead of racing it.
        bootout_waited=0
        while /bin/launchctl print \(label) >/dev/null 2>&1; do
            bootout_waited=$((bootout_waited + 1))
            if [ "$bootout_waited" -ge 40 ]; then break; fi
            /bin/sleep 0.25
        done
        /usr/bin/install -d -o root -g wheel -m 0755 /Library/PrivilegedHelperTools
        /usr/bin/install -o root -g wheel -m 0755 \(sourcePath) \(destination)
        # A helper copied out of a quarantined App bundle keeps the quarantine
        # attribute, which launchd refuses to load.
        /usr/bin/xattr -d -r com.apple.quarantine \(destination) >/dev/null 2>&1 || true
        # `set -e` is suspended inside a function used as an `if` condition, so
        # every step returns explicitly. Otherwise a failing digest check would
        # be masked by a succeeding signature check.
        verify_installed_image() {
            /bin/echo \(shellQuote(sourceDigest + "  " + HajimiHelperProtocol.toolPath)) | /usr/bin/shasum -a 256 -c - || return 1
            \(requirementCheck) || return 1
            return 0
        }
        if ! verify_installed_image; then
            /bin/rm -f \(destination)
            /bin/echo 'HajimiHelper 校验失败，已删除未验证的副本' >&2
            exit 1
        fi
        # Staged inside /Library/LaunchDaemons, not /var/tmp: the latter is
        # world-writable and sticky, so any local user could pre-create the
        # name as a symlink and have root's redirect follow it.
        staging=\(daemonPath).staging
        /bin/rm -f "$staging"
        /usr/bin/install -o root -g wheel -m 0644 /dev/null "$staging"
        /bin/echo \(shellQuote(encodedPlist)) | /usr/bin/base64 -D > "$staging"
        /bin/mv -f "$staging" \(daemonPath)
        # `enable` has to precede `bootstrap`. A label left in launchd's
        # disabled database — by an old `launchctl unload -w`, a manual
        # `launchctl disable`, or an interrupted install — makes every later
        # bootstrap fail with "Bootstrap failed: 5: Input/output error", and an
        # `enable` placed after the failing bootstrap never runs.
        /bin/launchctl enable \(label) >/dev/null 2>&1 || true
        if ! bootstrap_output=$(/bin/launchctl bootstrap system \(daemonPath) 2>&1); then
            # One retry after a full teardown: the disabled flag can only be
            # cleared for a job that is not currently loaded.
            /bin/launchctl bootout \(label) >/dev/null 2>&1 || true
            /bin/launchctl enable \(label) >/dev/null 2>&1 || true
            /bin/sleep 1
            if ! bootstrap_output=$(/bin/launchctl bootstrap system \(daemonPath) 2>&1); then
                /bin/echo "launchctl bootstrap 失败：$bootstrap_output" >&2
                /bin/launchctl print-disabled system 2>/dev/null | /usr/bin/grep \(plainLabel) >&2 || true
                exit 1
            fi
        fi
        /bin/launchctl kickstart -k \(label)
        """
        _ = try runPrivileged(script)
    }

    private var bundledHelperURL: URL? {
        if let bundled = Bundle.main.url(forResource: "HajimiHelper", withExtension: nil),
           FileManager.default.isExecutableFile(atPath: bundled.path) { return bundled }
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        // Universal (multi `--arch`) builds land under .build/apple/Products;
        // single-architecture builds keep the target-triple layout.
        let candidates = [
            ".build/apple/Products/Release/HajimiHelper",
            ".build/apple/Products/Debug/HajimiHelper",
            ".build/arm64-apple-macosx/release/HajimiHelper",
            ".build/arm64-apple-macosx/debug/HajimiHelper",
            ".build/x86_64-apple-macosx/release/HajimiHelper",
            ".build/x86_64-apple-macosx/debug/HajimiHelper",
            ".build/release/HajimiHelper",
            ".build/debug/HajimiHelper"
        ].map(root.appendingPathComponent)
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    private func runPrivileged(_ script: String) throws -> String {
        // Pass the fixed installer body directly to Authorization Services.
        // A user-writable temporary root script would introduce a TOCTOU
        // replacement window between authorization and execution.
        let command = "/bin/sh -c " + shellQuote(script)
        let appleScript = "do shell script \"\(appleScriptEscape(command))\" with administrator privileges"
        return try run("/usr/bin/osascript", ["-e", appleScript])
    }

    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        let output = Pipe(); let errors = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = output; process.standardError = errors
        try process.run(); process.waitUntilExit()
        let stdout = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            let value = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw ClientError.installationFailed(value.isEmpty ? "管理员授权被取消或命令失败" : value)
        }
        return stdout
    }

    private func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), raw.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else {
                    throw ClientError.command("IPC 写入 \(offset)/\(raw.count) 字节后失败：\(String(cString: strerror(errno)))")
                }
                offset += count
            }
        }
    }

    private func readLine(from descriptor: Int32) throws -> Data {
        var result = Data(); var byte: UInt8 = 0
        while result.count < 65_536 {
            let count = Darwin.read(descriptor, &byte, 1)
            if count == 1 {
                if byte == 0x0a { return result }
                result.append(byte)
                continue
            }
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
                throw ClientError.command(
                    result.isEmpty
                    ? "root Helper 响应超时（可能正忙于安装路由或已卡死，请重试或重新安装 Helper）"
                    : "root Helper 响应被截断（超时）")
            }
            if count == 0 {
                throw ClientError.command(
                    result.isEmpty
                    ? "root Helper 关闭了连接且未返回数据"
                    : "root Helper 响应不完整")
            }
            throw ClientError.command("读取 Helper 响应失败：\(String(cString: strerror(errno)))")
        }
        throw ClientError.command("root Helper 响应过长")
    }

    private func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func appleScriptEscape(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}

import Foundation
import Darwin
import Security
import HajimiIPC

enum HelperServiceError: LocalizedError {
    case defaultInterfaceMissing
    /// Only physical readiness checks before capture may produce this retryable condition.
    case physicalNetworkNotReady(String)
    case conflictingTunnel(String)
    case command(String)
    case timeout(String)

    var operationMayHaveSucceeded: Bool {
        if case .timeout = self { return true }
        return false
    }

    var errorDescription: String? {
        switch self {
        case .defaultInterfaceMissing: return "无法确定物理默认网络接口"
        case .physicalNetworkNotReady(let value): return value
        case .conflictingTunnel(let name): return "检测到 \(name) 正在接管网络，请先关闭其他 VPN/增强模式"
        case .command(let value): return value
        case .timeout(let value): return value
        }
    }
}

final class HelperSocketServer {
    private let allowedUID: uid_t
    private let service: EnhancedTunnelService
    private let acceptQueue = DispatchQueue(label: "app.hajimi.helper.socket")
    /// Cap concurrent handlers so a flood of stuck clients cannot exhaust threads.
    private let clientQueue = DispatchQueue(label: "app.hajimi.helper.clients",
                                            attributes: .concurrent)
    private let clientLimiter = DispatchSemaphore(value: 8)
    private var descriptor: Int32 = -1
    private var source: DispatchSourceRead?

    init(allowedUID: uid_t, service: EnhancedTunnelService) {
        self.allowedUID = allowedUID
        self.service = service
    }

    deinit { stop() }

    func start() throws {
        guard descriptor < 0 else { return }
        unlink(HajimiHelperProtocol.socketPath)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw HelperServiceError.command(String(cString: strerror(errno))) }
        do {
            var address = sockaddr_un()
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            address.sun_family = sa_family_t(AF_UNIX)
            let pathBytes = Array(HajimiHelperProtocol.socketPath.utf8) + [0]
            guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
                throw HelperServiceError.command("Helper socket 路径过长")
            }
            withUnsafeMutableBytes(of: &address.sun_path) { raw in raw.copyBytes(from: pathBytes) }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard result == 0 else { throw HelperServiceError.command(String(cString: strerror(errno))) }
            guard chown(HajimiHelperProtocol.socketPath, allowedUID, gid_t.max) == 0,
                  chmod(HajimiHelperProtocol.socketPath, S_IRUSR | S_IWUSR) == 0 else {
                throw HelperServiceError.command("无法设置 Helper socket 所有者")
            }
            guard listen(fd, 32) == 0 else { throw HelperServiceError.command(String(cString: strerror(errno))) }
            let flags = fcntl(fd, F_GETFL, 0)
            if flags >= 0 { _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
            descriptor = fd
            let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: acceptQueue)
            source.setEventHandler { [weak self] in self?.acceptClients() }
            source.setCancelHandler {}
            self.source = source
            source.resume()
        } catch {
            Darwin.close(fd)
            unlink(HajimiHelperProtocol.socketPath)
            throw error
        }
    }

    func stop() {
        source?.cancel(); source = nil
        if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
        unlink(HajimiHelperProtocol.socketPath)
    }

    private func acceptClients() {
        while true {
            let client = accept(descriptor, nil, nil)
            if client >= 0 {
                var noSigPipe: Int32 = 1
                _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                               socklen_t(MemoryLayout.size(ofValue: noSigPipe)))
                // Bound wait so accept loop is never stuck behind a full limiter.
                if clientLimiter.wait(timeout: .now() + .milliseconds(50)) == .timedOut {
                    Darwin.close(client)
                    continue
                }
                clientQueue.async { [weak self] in
                    defer { self?.clientLimiter.signal() }
                    self?.handle(client)
                }
                continue
            }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            return
        }
    }

    /// Pure response construction, shared with the memory-only reconnect
    /// fixture. A retryable reply retains only its authenticated owner's token;
    /// all other failures keep the existing redacted error snapshot.
    static func errorResponse(_ error: Error, service: EnhancedTunnelService, peerPID: pid_t) -> HajimiHelperResponse {
        let errorCode: HajimiHelperErrorCode?
        let snapshotClientPID: pid_t
        if case .physicalNetworkNotReady = error as? HelperServiceError {
            errorCode = .physicalNetworkNotReady
            snapshotClientPID = peerPID
        } else { errorCode = nil; snapshotClientPID = 0 }
        return HajimiHelperResponse(ok: false, message: error.localizedDescription, errorCode: errorCode,
                                   state: service.state(clientPID: snapshotClientPID, renewLiveness: false))
    }

    private func handle(_ descriptor: Int32) {
        defer { Darwin.close(descriptor) }
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        let peerPID = Self.peerProcessID(of: descriptor)
        guard getpeereid(descriptor, &peerUID, &peerGID) == 0,
              peerUID == allowedUID || peerUID == 0,
              Self.isAuthorizedPeerProcess(pid: peerPID, uid: peerUID) else {
            writeResponse(HajimiHelperResponse(ok: false, message: "未授权的本地客户端"), to: descriptor)
            return
        }
        // Keep request reads short. Mutations themselves may take longer, but
        // the App should not sit blocked on a dead connection.
        var timeout = timeval(tv_sec: 8, tv_usec: 0)
        _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        guard let data = readRequest(from: descriptor) else {
            writeResponse(HajimiHelperResponse(ok: false, message: "Helper 请求为空或读取中断"), to: descriptor)
            return
        }
        guard let request = try? JSONDecoder().decode(HajimiHelperRequest.self, from: data) else {
            writeResponse(HajimiHelperResponse(ok: false, message: "Helper 请求 JSON 格式无效"), to: descriptor)
            return
        }
        var fileDescriptorToSend: Int32?
        var handoffGeneration: UInt64?
        let response: HajimiHelperResponse
        let caller = EnhancedTunnelService.MutationCaller.authenticatedPeer(
            uid: peerUID, pid: peerPID, allowedUID: allowedUID)
        do {
            switch request.action {
            case .ping, .status:
                // Fast path: never waits on route installation.
                response = HajimiHelperResponse(ok: true, state: service.state(
                    clientPID: peerPID, renewLiveness: request.action == .status))
            case .start:
                throw HelperServiceError.command("Helper 协议已升级，请使用 prepare / commit 收包就绪流程")
            case .prepare:
                let result = try service.prepare(
                    fakeIPEnabled: request.fakeIPEnabled ?? false,
                    bypassAddresses: request.bypassAddresses ?? [],
                    excludedRoutes: request.excludedRoutes ?? [],
                    includedRoutes: request.includedRoutes ?? [],
                    clientPID: peerPID)
                fileDescriptorToSend = result.fileDescriptorToSend
                handoffGeneration = result.sessionGeneration
                response = HajimiHelperResponse(ok: true, state: result.state,
                                               sendsTunnelFileDescriptor: true)
            case .commit:
                response = HajimiHelperResponse(ok: true, state: try service.commit(
                    sessionToken: request.sessionToken, clientPID: peerPID))
            case .reload:
                response = HajimiHelperResponse(ok: true, state: try service.reload(
                    fakeIPEnabled: request.fakeIPEnabled ?? false,
                    bypassAddresses: request.bypassAddresses ?? [],
                    excludedRoutes: request.excludedRoutes ?? [],
                    includedRoutes: request.includedRoutes ?? [], caller: caller,
                    sessionToken: request.sessionToken))
            case .stop:
                response = HajimiHelperResponse(ok: true, state: try service.stop(
                    caller: caller, sessionToken: request.sessionToken))
            }
        } catch {
            response = Self.errorResponse(error, service: service, peerPID: peerPID)
        }
        let responseWritten = writeResponse(response, to: descriptor)
        if let fd = fileDescriptorToSend {
            defer { Darwin.close(fd) }
            var delivered = false
            if responseWritten {
                do {
                    try UnixFileDescriptorPassing.send(fileDescriptor: fd, on: descriptor)
                    delivered = true
                } catch {
                    fputs("send utun fd failed: \(error)\n", stderr)
                }
            }
            if let handoffGeneration {
                service.finishHandoff(generation: handoffGeneration, delivered: delivered)
            }
        }
    }

    /// Enforces a fail-closed whitelist on peer executable paths so untrusted
    /// binaries or world-writable /tmp drops running under the user's UID cannot
    /// invoke root Helper mutations.
    static func isAuthorizedPeerExecutablePath(_ rawPath: String) -> Bool {
        let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("/"), !trimmed.contains("/../"), !trimmed.hasSuffix("/..") else {
            return false
        }
        let standardized = (trimmed as NSString).standardizingPath
        let lower = standardized.lowercased()
        let base = (lower as NSString).lastPathComponent

        // Dedicated CI self-test harness directory is the sole permitted temporary fixture location.
        if lower == "/tmp/hajimi-test-support/hajimihelperselftest" ||
           lower == "/private/tmp/hajimi-test-support/hajimihelperselftest" {
            return true
        }

        // Block all temporary, device, and removable/mounted volume locations BEFORE checking binary names.
        let forbiddenPrefixes = [
            "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/dev/", "/volumes/"
        ]
        if forbiddenPrefixes.contains(where: { lower.hasPrefix($0) }) {
            return false
        }

        let allowedBinaries: Set<String> = [
            "hajimi", "hajimiapp", "hajimihelperselftest", "hajimitestsupport", "enhancedreconnecthelper"
        ]
        guard allowedBinaries.contains(base) else {
            return false
        }

        // Require canonical macOS app bundle or local Xcode/SwiftPM build product directory.
        let inAppBundle = lower.contains(".app/contents/macos/")
        let inBuildOutput = lower.contains("/build/products/") || lower.contains("/.build/")
        return inAppBundle || inBuildOutput
    }

    /// Verifies in-memory dynamic code signature integrity of the peer process (fail-closed).
    static func hasValidDynamicCodeSignature(pid: pid_t) -> Bool {
        guard pid > 0 else { return false }
        var guest: SecCode?
        let attrs = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &guest) == errSecSuccess,
              let code = guest else {
            return false
        }
        let flags = SecCSFlags(rawValue: UInt32(kSecCSStrictValidate))
        return SecCodeCheckValidity(code, flags, nil) == errSecSuccess
    }

    private static func isAuthorizedPeerProcess(pid: pid_t, uid: uid_t) -> Bool {
        if uid == 0 { return true }
        guard pid > 0 else { return false }
        var buffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return false }
        let path = String(cString: buffer)
        guard isAuthorizedPeerExecutablePath(path) else { return false }
        return hasValidDynamicCodeSignature(pid: pid)
    }

    /// Darwin `LOCAL_PEERPID` — the pid of the connected peer.
    private static func peerProcessID(of socket: Int32) -> pid_t {
        var pid: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        // SOL_LOCAL = 0, LOCAL_PEERPID = 0x002
        if getsockopt(socket, 0, 0x002, &pid, &length) == 0, pid > 0 {
            return pid
        }
        return 0
    }

    private func readRequest(from descriptor: Int32) -> Data? {
        let maxBytes = 256 * 1024
        var result = Data()
        result.reserveCapacity(512)
        var chunk = [UInt8](repeating: 0, count: 4096)
        while result.count < maxBytes {
            let toRead = min(chunk.count, maxBytes - result.count)
            let count = chunk.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.read(descriptor, base, toRead)
            }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { return nil }
            if let newlineIdx = chunk[0..<count].firstIndex(of: 0x0a) {
                if newlineIdx > 0 {
                    result.append(contentsOf: chunk[0..<newlineIdx])
                }
                return result
            }
            result.append(contentsOf: chunk[0..<count])
        }
        return nil
    }

    @discardableResult
    private func writeResponse(_ response: HajimiHelperResponse, to descriptor: Int32) -> Bool {
        guard var data = try? JSONEncoder().encode(response) else { return false }
        data.append(0x0a)
        return data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), raw.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
    }
}

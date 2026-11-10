import Foundation
import HajimiDNS
import HajimiRouting
import Network
import Security
import Darwin
import HajimiProxyRuntime
import HajimiCXXProtocolBridge

@_exported import HajimiDNS
@_exported import HajimiRouting

/// Bounded, short-TTL (2.0s) source-port-to-process cache for PROCESS-NAME rules.
/// Avoids repeated kernel proc_pidinfo/proc_pidpath syscalls on bursty traffic
/// from the same local client port.
public final class LocalProcessSocketCache {
    public static let shared = LocalProcessSocketCache()
    private struct Key: Hashable {
        let port: UInt16
        let isTCP: Bool
    }
    private struct Entry {
        let processPath: String
        let expiresAt: TimeInterval
    }
    private let lock = NSLock()
    private var entries: [Key: Entry] = [:]
    private var portIndex: [UInt16: Entry] = [:]
    private var negativePorts: [UInt16: TimeInterval] = [:]
    private var recentPIDs: [pid_t] = []
    private var pidPaths: [pid_t: String] = [:]
    private var lastFullScanAt: TimeInterval = 0
    private let ttl: TimeInterval

    public init(ttl: TimeInterval = 8.0) {
        self.ttl = max(0.1, ttl)
    }

    public func lookup(port: UInt16, isTCP: Bool, now: TimeInterval? = nil) -> String? {
        guard port > 0 else { return nil }
        let currentNow = now ?? SOCKSUDPResourceLimits.now
        let key = Key(port: port, isTCP: isTCP)
        lock.lock()
        defer { lock.unlock() }
        if let existing = entries[key], existing.expiresAt > currentNow {
            return existing.processPath
        }
        entries.removeValue(forKey: key)
        if now == nil, let anyEntry = portIndex[port], anyEntry.expiresAt > currentNow {
            return anyEntry.processPath
        }
        return nil
    }

    public func record(processPath: String, port: UInt16, isTCP: Bool,
                       now: TimeInterval? = nil) {
        let trimmed = processPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard port > 0, !trimmed.isEmpty else { return }
        let currentNow = now ?? SOCKSUDPResourceLimits.now
        let key = Key(port: port, isTCP: isTCP)
        let entry = Entry(processPath: trimmed, expiresAt: currentNow + ttl)
        lock.lock()
        if entries.count >= 2048 {
            entries = entries.filter { $0.value.expiresAt > currentNow }
            portIndex = portIndex.filter { $0.value.expiresAt > currentNow }
            if entries.count >= 2048 {
                entries.removeAll(keepingCapacity: true)
                portIndex.removeAll(keepingCapacity: true)
            }
        }
        entries[key] = entry
        portIndex[port] = entry
        negativePorts.removeValue(forKey: port)
        lock.unlock()
    }

    public func flush() {
        lock.lock()
        entries.removeAll()
        portIndex.removeAll()
        negativePorts.removeAll()
        recentPIDs.removeAll()
        pidPaths.removeAll()
        lastFullScanAt = 0
        lock.unlock()
    }

    public func resolveProcessPath(port: UInt16, isTCP: Bool,
                                   now: TimeInterval? = nil) -> String? {
        guard port > 0 else { return nil }
        let currentNow = now ?? SOCKSUDPResourceLimits.now
        if let cached = lookup(port: port, isTCP: isTCP, now: currentNow) {
            return cached
        }
        #if canImport(Darwin)
        let batch = resolveBatch(ports: [port], now: currentNow)
        return batch[port]
        #else
        return nil
        #endif
    }

    /// Resolves a batch of local client ports in a single rate-limited pass.
    /// Uses recentPIDs fast-path first, negative caching for system/unresolvable ports,
    /// and throttles full user-UID process scans to at most once every 2.0 seconds.
    public func resolveBatch(ports: [UInt16], now: TimeInterval? = nil) -> [UInt16: String] {
        let currentNow = now ?? SOCKSUDPResourceLimits.now
        var resolved: [UInt16: String] = [:]
        var unresolved = Set<UInt16>()

        lock.lock()
        for port in ports where port > 0 {
            if let existing = portIndex[port], existing.expiresAt > currentNow {
                resolved[port] = existing.processPath
            } else if let negUntil = negativePorts[port], negUntil > currentNow {
                continue
            } else {
                unresolved.insert(port)
            }
        }
        let recentSnapshot = recentPIDs
        let canRunFullScan = (currentNow - lastFullScanAt) >= 2.0
        if !unresolved.isEmpty && canRunFullScan {
            lastFullScanAt = currentNow
        }
        lock.unlock()

        #if canImport(Darwin)
        guard !unresolved.isEmpty else { return resolved }
        let selfPID = getpid()
        var fdBuffer = [proc_fdinfo](repeating: proc_fdinfo(), count: 2048)

        // Step 1: Fast scan of the top 8 recently active network PIDs (at most 48 newest sockets each)
        for pid in recentSnapshot.prefix(8) where pid > 0 && pid != selfPID {
            scanPIDForBatch(pid, wanted: &unresolved, resolved: &resolved,
                            fdBuffer: &fdBuffer, maxSocketsToInspect: 48, now: currentNow)
            if unresolved.isEmpty { break }
        }

        // Step 2: Throttled scan of processes (at most once every 2.0s; non-user PIDs fail proc_pidinfo in <1us)
        if !unresolved.isEmpty && canRunFullScan {
            let maxPIDs = 2048
            var pids = [pid_t](repeating: 0, count: maxPIDs)
            let bytesReturned = proc_listallpids(&pids, Int32(maxPIDs * MemoryLayout<pid_t>.stride))
            if bytesReturned > 0 {
                let pidCount = min(maxPIDs, Int(bytesReturned))
                let recentSet = Set(recentSnapshot.prefix(8))
                for idx in 0..<pidCount {
                    let pid = pids[idx]
                    guard pid > 0, pid != selfPID, !recentSet.contains(pid) else { continue }
                    scanPIDForBatch(pid, wanted: &unresolved, resolved: &resolved,
                                    fdBuffer: &fdBuffer, maxSocketsToInspect: 32, now: currentNow)
                    if unresolved.isEmpty { break }
                }
            }
        }

        // Step 3: Negative-cache any remaining unresolved ports so they never trigger repeated scans
        if !unresolved.isEmpty {
            lock.lock()
            if negativePorts.count >= 2048 {
                negativePorts = negativePorts.filter { $0.value > currentNow }
                if negativePorts.count >= 2048 { negativePorts.removeAll(keepingCapacity: true) }
            }
            let negExpiry = currentNow + 20.0
            for port in unresolved {
                negativePorts[port] = negExpiry
            }
            lock.unlock()
        }
        #endif

        return resolved
    }

    #if canImport(Darwin)
    private func promoteRecentPID(_ pid: pid_t) {
        lock.lock()
        recentPIDs.removeAll { $0 == pid }
        recentPIDs.insert(pid, at: 0)
        if recentPIDs.count > 12 {
            recentPIDs.removeLast(recentPIDs.count - 12)
        }
        lock.unlock()
    }

    private func cachedOrResolvedPath(for pid: pid_t) -> String? {
        lock.lock()
        if let existing = pidPaths[pid] {
            lock.unlock()
            return existing
        }
        lock.unlock()

        var pathBuf = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count)) > 0 else {
            return nil
        }
        let rawPath = String(cString: pathBuf)
        var resolvedPath = rawPath

        if !rawPath.lowercased().contains(".app/") {
            var curPID = pid
            for _ in 0..<4 {
                var info = kinfo_proc()
                var size = MemoryLayout<kinfo_proc>.size
                var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, curPID]
                guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { break }
                let ppid = info.kp_eproc.e_ppid
                guard ppid > 1, ppid != curPID else { break }
                var parentBuf = [CChar](repeating: 0, count: 4096)
                if proc_pidpath(ppid, &parentBuf, UInt32(parentBuf.count)) > 0 {
                    let parentPath = String(cString: parentBuf)
                    let lowerParent = parentPath.lowercased()
                    if lowerParent.contains(".app/") {
                        let isTerminal = lowerParent.contains("terminal.app/")
                            || lowerParent.contains("iterm.app/")
                            || lowerParent.contains("warp.app/")
                            || lowerParent.contains("alacritty.app/")
                            || lowerParent.contains("kitty.app/")
                        if !isTerminal {
                            resolvedPath = parentPath
                        }
                        break
                    }
                }
                curPID = ppid
            }
        }

        lock.lock()
        if pidPaths.count >= 1024 {
            pidPaths.removeAll(keepingCapacity: true)
        }
        pidPaths[pid] = resolvedPath
        lock.unlock()
        return resolvedPath
    }

    private func scanPIDForBatch(_ pid: pid_t,
                                 wanted: inout Set<UInt16>,
                                 resolved: inout [UInt16: String],
                                 fdBuffer: inout [proc_fdinfo],
                                 maxSocketsToInspect: Int,
                                 now: TimeInterval) {
        let fdStride = MemoryLayout<proc_fdinfo>.stride
        let fdBytes = fdBuffer.withUnsafeMutableBytes { raw in
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, raw.baseAddress, Int32(raw.count))
        }
        guard fdBytes > 0 else { return }
        let fdCount = min(fdBuffer.count, Int(fdBytes) / fdStride)
        var matchedPorts: [(port: UInt16, isTCP: Bool)] = []
        var socketsChecked = 0

        // Inspect only the newest socket FDs (highest FD numbers)
        for fIdx in stride(from: fdCount - 1, through: 0, by: -1) {
            let fdInfo = fdBuffer[fIdx]
            guard fdInfo.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) else { continue }
            socketsChecked += 1
            if socketsChecked > maxSocketsToInspect { break }

            var sockInfo = socket_fdinfo()
            let sockBytes = proc_pidfdinfo(
                pid, fdInfo.proc_fd, PROC_PIDFDSOCKETINFO,
                &sockInfo, Int32(MemoryLayout<socket_fdinfo>.stride)
            )
            guard sockBytes == Int32(MemoryLayout<socket_fdinfo>.stride) else { continue }
            let kind = sockInfo.psi.soi_kind
            let sockIsTCP: Bool
            if kind == Int32(SOCKINFO_TCP) {
                sockIsTCP = true
            } else if kind == Int32(SOCKINFO_IN) {
                sockIsTCP = false
            } else {
                continue
            }
            let rawPort = UInt16(truncatingIfNeeded: sockInfo.psi.soi_proto.pri_in.insi_lport)
            let localPort = UInt16(bigEndian: rawPort)
            guard localPort > 0 else { continue }
            if wanted.contains(localPort) {
                matchedPorts.append((localPort, sockIsTCP))
                wanted.remove(localPort)
                if wanted.isEmpty { break }
            }
        }

        guard !matchedPorts.isEmpty, let path = cachedOrResolvedPath(for: pid) else {
            return
        }
        promoteRecentPID(pid)
        let expiry = now + ttl
        let entry = Entry(processPath: path, expiresAt: expiry)
        lock.lock()
        if entries.count >= 2048 {
            entries = entries.filter { $0.value.expiresAt > now }
            portIndex = portIndex.filter { $0.value.expiresAt > now }
            if entries.count >= 2048 {
                entries.removeAll(keepingCapacity: true)
                portIndex.removeAll(keepingCapacity: true)
            }
        }
        for item in matchedPorts {
            entries[Key(port: item.port, isTCP: item.isTCP)] = entry
            portIndex[item.port] = entry
            negativePorts.removeValue(forKey: item.port)
            resolved[item.port] = path
        }
        lock.unlock()
    }
    #endif
}

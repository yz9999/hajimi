import AppKit
import Foundation
import HajimiCore
import HajimiUIComponents

/// Aggregates real-time and cumulative traffic usage per local macOS application/process
/// and per outbound policy/node without blocking the main thread or proxy data plane.
final class AppTrafficTelemetryCenter {
    static let shared = AppTrafficTelemetryCenter()

    var onNeedsRefresh: (() -> Void)?

    struct Bucket {
        let id: String
        var title: String
        var subtitle: String
        var symbolName: String
        var tintColor: NSColor
        var iconPath: String?
        var uploadedBytes: UInt64 = 0
        var downloadedBytes: UInt64 = 0
        var activeConnections: Int = 0
        var totalConnections: Int = 0

        var totalBytes: UInt64 {
            uploadedBytes &+ downloadedBytes
        }
    }

    private struct TrackedConnection {
        let id: UUID
        var appKey: String
        let policyKey: String
        let splitKind: SplitKind
        let clientPort: UInt16?
        let isTCP: Bool
        var isResolved: Bool
        var isOpen: Bool = true
        var uploadedBytes: UInt64 = 0
        var downloadedBytes: UInt64 = 0
    }

    private enum SplitKind {
        case proxy
        case direct
        case dnsAndSystem
    }

    private struct AppDescriptor {
        let key: String
        let title: String
        let subtitle: String
        let symbolName: String
        let tintColor: NSColor
        let iconPath: String?
    }

    private var activeConnections: [UUID: TrackedConnection] = [:]
    private var appBuckets: [String: Bucket] = [:]
    private var policyBuckets: [String: Bucket] = [:]

    private var proxySplitBytes: UInt64 = 0
    private var directSplitBytes: UInt64 = 0
    private var dnsSplitBytes: UInt64 = 0

    private var pendingPortConnections: [UInt16: [UUID]] = [:]
    private var resolutionTimerScheduled = false
    private var resolutionInFlight = false
    private let resolveQueue = DispatchQueue(label: "app.hajimi.traffic-telemetry.proc-resolver", qos: .utility)

    private static var descriptorCache: [String: AppDescriptor] = [:]
    private static var displayNameCache: [String: String] = [:]
    private static var iconCache: [String: NSImage] = [:]

    func reset() {
        activeConnections.removeAll(keepingCapacity: true)
        appBuckets.removeAll(keepingCapacity: true)
        policyBuckets.removeAll(keepingCapacity: true)
        pendingPortConnections.removeAll(keepingCapacity: true)
        proxySplitBytes = 0
        directSplitBytes = 0
        dnsSplitBytes = 0
    }

    func observe(event: ProxyEngineEvent) {
        switch event {
        case .opened(let snapshot):
            handleOpened(snapshot)
        case .traffic(let id, let up, let down):
            handleTraffic(id: id, up: max(0, up), down: max(0, down))
        case .closed(let id, _):
            handleClosed(id: id)
        case .message:
            break
        }
    }

    private func handleOpened(_ snapshot: ConnectionSnapshot) {
        guard activeConnections[snapshot.id] == nil else { return }

        let clientPort = Self.extractPort(from: snapshot.client)
        let isTCP = snapshot.method.uppercased() != "UDP"
        let isDNS = (snapshot.port == 53 || snapshot.port == 853)

        // O(1) pure-memory cache lookup on main thread — NEVER invoke kernel syscalls on main thread.
        let cachedProcessPath: String? = (!isDNS && clientPort != nil)
            ? LocalProcessSocketCache.shared.lookup(port: clientPort!, isTCP: isTCP)
            : nil

        let appDesc: AppDescriptor
        let isResolved: Bool
        if let path = cachedProcessPath {
            appDesc = Self.descriptor(forProcessPath: path)
            isResolved = true
        } else if isDNS {
            // Port 53/853 DNS traffic is handled by mDNSResponder / encrypted DNS engine;
            // never waste kernel PID scans on mDNSResponder sockets.
            appDesc = Self.dnsServiceDescriptor()
            isResolved = true
        } else {
            appDesc = Self.pendingOrSystemDescriptor(port: snapshot.port)
            isResolved = (clientPort == nil)
        }

        let policyDesc = Self.policyDescriptor(for: snapshot.policy, port: snapshot.port, method: snapshot.method)
        let splitKind = Self.classifySplit(policy: snapshot.policy, port: snapshot.port, host: snapshot.host)

        if activeConnections.count >= 4096 {
            activeConnections = activeConnections.filter { $0.value.isOpen }
            if activeConnections.count >= 4096 {
                activeConnections.removeAll(keepingCapacity: true)
            }
        }

        activeConnections[snapshot.id] = TrackedConnection(
            id: snapshot.id,
            appKey: appDesc.key,
            policyKey: policyDesc.key,
            splitKind: splitKind,
            clientPort: clientPort,
            isTCP: isTCP,
            isResolved: isResolved,
            isOpen: true
        )

        var appBucket = appBuckets[appDesc.key] ?? Bucket(
            id: appDesc.key,
            title: appDesc.title,
            subtitle: appDesc.subtitle,
            symbolName: appDesc.symbolName,
            tintColor: appDesc.tintColor,
            iconPath: appDesc.iconPath
        )
        appBucket.activeConnections += 1
        appBucket.totalConnections += 1
        appBuckets[appDesc.key] = appBucket

        var polBucket = policyBuckets[policyDesc.key] ?? Bucket(
            id: policyDesc.key,
            title: policyDesc.title,
            subtitle: policyDesc.subtitle,
            symbolName: policyDesc.symbolName,
            tintColor: policyDesc.tintColor,
            iconPath: nil
        )
        polBucket.activeConnections += 1
        polBucket.totalConnections += 1
        policyBuckets[policyDesc.key] = polBucket

        if !isResolved, let port = clientPort, port > 0 {
            if pendingPortConnections.count < 512 {
                pendingPortConnections[port, default: []].append(snapshot.id)
            }
            scheduleBatchResolutionIfNeeded()
        }
    }

    private func scheduleBatchResolutionIfNeeded() {
        guard !resolutionTimerScheduled, !resolutionInFlight, !pendingPortConnections.isEmpty else { return }
        resolutionTimerScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(450)) { [weak self] in
            guard let self else { return }
            self.resolutionTimerScheduled = false
            self.runBatchResolution()
        }
    }

    private func runBatchResolution() {
        guard !resolutionInFlight, !pendingPortConnections.isEmpty else { return }
        resolutionInFlight = true
        let portMap = pendingPortConnections
        pendingPortConnections.removeAll(keepingCapacity: true)
        let ports = Array(portMap.keys)

        resolveQueue.async { [weak self] in
            let resolvedByPort = LocalProcessSocketCache.shared.resolveBatch(ports: ports)
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                var anyPromoted = false
                for (port, connIDs) in portMap {
                    if let path = resolvedByPort[port] {
                        for id in connIDs {
                            if self.promoteConnection(id: id, resolvedProcessPath: path) {
                                anyPromoted = true
                            }
                        }
                    } else {
                        // Mark unresolved closed connections as finished so they don't linger
                        for id in connIDs {
                            if var conn = self.activeConnections[id] {
                                conn.isResolved = true
                                if !conn.isOpen {
                                    self.activeConnections.removeValue(forKey: id)
                                } else {
                                    self.activeConnections[id] = conn
                                }
                            }
                        }
                    }
                }
                self.resolutionInFlight = false
                if anyPromoted {
                    self.onNeedsRefresh?()
                }
                if !self.pendingPortConnections.isEmpty {
                    self.scheduleBatchResolutionIfNeeded()
                }
            }
        }
    }

    @discardableResult
    private func promoteConnection(id: UUID, resolvedProcessPath: String) -> Bool {
        guard var conn = activeConnections[id] else { return false }
        let newDesc = Self.descriptor(forProcessPath: resolvedProcessPath)
        conn.isResolved = true
        let oldKey = conn.appKey

        if newDesc.key != oldKey {
            if var oldBucket = appBuckets[oldKey] {
                if conn.isOpen {
                    oldBucket.activeConnections = max(0, oldBucket.activeConnections - 1)
                }
                oldBucket.totalConnections = max(0, oldBucket.totalConnections - 1)
                oldBucket.uploadedBytes = oldBucket.uploadedBytes >= conn.uploadedBytes
                    ? (oldBucket.uploadedBytes - conn.uploadedBytes) : 0
                oldBucket.downloadedBytes = oldBucket.downloadedBytes >= conn.downloadedBytes
                    ? (oldBucket.downloadedBytes - conn.downloadedBytes) : 0
                if oldBucket.totalConnections == 0 && oldBucket.totalBytes == 0 && oldBucket.activeConnections == 0 {
                    appBuckets.removeValue(forKey: oldKey)
                } else {
                    appBuckets[oldKey] = oldBucket
                }
            }

            conn.appKey = newDesc.key
            var newBucket = appBuckets[newDesc.key] ?? Bucket(
                id: newDesc.key,
                title: newDesc.title,
                subtitle: newDesc.subtitle,
                symbolName: newDesc.symbolName,
                tintColor: newDesc.tintColor,
                iconPath: newDesc.iconPath
            )
            if conn.isOpen {
                newBucket.activeConnections += 1
            }
            newBucket.totalConnections += 1
            newBucket.uploadedBytes &+= conn.uploadedBytes
            newBucket.downloadedBytes &+= conn.downloadedBytes
            appBuckets[newDesc.key] = newBucket
        }

        if conn.isOpen {
            activeConnections[id] = conn
        } else {
            activeConnections.removeValue(forKey: id)
        }
        return true
    }

    private func handleTraffic(id: UUID, up: Int, down: Int) {
        let upU64 = UInt64(up)
        let downU64 = UInt64(down)
        guard upU64 > 0 || downU64 > 0 else { return }

        guard var conn = activeConnections[id] else { return }
        conn.uploadedBytes &+= upU64
        conn.downloadedBytes &+= downU64

        activeConnections[id] = conn
        if var appBucket = appBuckets[conn.appKey] {
            appBucket.uploadedBytes &+= upU64
            appBucket.downloadedBytes &+= downU64
            appBuckets[conn.appKey] = appBucket
        }

        if var polBucket = policyBuckets[conn.policyKey] {
            polBucket.uploadedBytes &+= upU64
            polBucket.downloadedBytes &+= downU64
            policyBuckets[conn.policyKey] = polBucket
        }
        let totalDelta = upU64 &+ downU64
        switch conn.splitKind {
        case .proxy: proxySplitBytes &+= totalDelta
        case .direct: directSplitBytes &+= totalDelta
        case .dnsAndSystem: dnsSplitBytes &+= totalDelta
        }
    }

    private func handleClosed(id: UUID) {
        guard var conn = activeConnections[id] else { return }
        if conn.isOpen {
            conn.isOpen = false
            if var appBucket = appBuckets[conn.appKey] {
                appBucket.activeConnections = max(0, appBucket.activeConnections - 1)
                if appBucket.id == "proc.pending", appBucket.totalBytes == 0, appBucket.activeConnections == 0 {
                    appBuckets.removeValue(forKey: conn.appKey)
                } else {
                    appBuckets[conn.appKey] = appBucket
                }
            }
            if var polBucket = policyBuckets[conn.policyKey] {
                polBucket.activeConnections = max(0, polBucket.activeConnections - 1)
                policyBuckets[conn.policyKey] = polBucket
            }
        }
        if conn.isResolved {
            activeConnections.removeValue(forKey: id)
        } else {
            // Keep closed connection briefly until pending async resolution promotes its bytes.
            activeConnections[id] = conn
        }
    }

    func buildPresentation(enhancedActive: Int,
                           enhancedTotal: Int,
                           enhancedUploaded: UInt64,
                           enhancedDownloaded: UInt64,
                           selectedModeName: String,
                           selectedPolicyName: String) -> (appEntries: [HajimiTrafficUsageEntry],
                                                           policyEntries: [HajimiTrafficUsageEntry],
                                                           split: HajimiTrafficSplitSnapshot) {
        let sortedApps = appBuckets.values
            .filter { bucket in
                if bucket.id == "proc.pending" && bucket.totalBytes == 0 {
                    return false
                }
                return bucket.totalBytes > 0 || bucket.activeConnections > 0
            }
            .sorted {
                if $0.totalBytes != $1.totalBytes { return $0.totalBytes > $1.totalBytes }
                if $0.activeConnections != $1.activeConnections { return $0.activeConnections > $1.activeConnections }
                return $0.totalConnections > $1.totalConnections
            }

        let sortedPolicies = policyBuckets.values
            .filter { $0.totalBytes > 0 || $0.activeConnections > 0 }
            .sorted {
                if $0.totalBytes != $1.totalBytes { return $0.totalBytes > $1.totalBytes }
                if $0.activeConnections != $1.activeConnections { return $0.activeConnections > $1.activeConnections }
                return $0.totalConnections > $1.totalConnections
            }

        let topAppEntries = sortedApps.prefix(40).map(Self.makeEntry)
        let topPolicyEntries = sortedPolicies.prefix(40).map(Self.makeEntry)

        let split = HajimiTrafficSplitSnapshot(
            proxyBytes: proxySplitBytes,
            directBytes: directSplitBytes,
            dnsAndSystemBytes: dnsSplitBytes,
            trackedAppCount: sortedApps.count,
            trackedPolicyCount: sortedPolicies.count
        )
        return (topAppEntries, topPolicyEntries, split)
    }

    private static func makeEntry(_ bucket: Bucket) -> HajimiTrafficUsageEntry {
        let connInfo = bucket.activeConnections > 0
            ? "\(bucket.activeConnections) 活跃 · 累计 \(bucket.totalConnections) 连接"
            : "累计 \(bucket.totalConnections) 连接"
        let fullSubtitle = bucket.subtitle.isEmpty ? connInfo : "\(bucket.subtitle) · \(connInfo)"
        let icon = bucket.iconPath.flatMap { loadCachedIcon(forPath: $0) }
        return HajimiTrafficUsageEntry(
            id: bucket.id,
            title: bucket.title,
            subtitle: fullSubtitle,
            symbolName: bucket.symbolName,
            tintColor: bucket.tintColor,
            uploadedBytes: bucket.uploadedBytes,
            downloadedBytes: bucket.downloadedBytes,
            activeConnections: bucket.activeConnections,
            totalConnections: bucket.totalConnections,
            appIcon: icon
        )
    }

    private static func loadCachedIcon(forPath path: String) -> NSImage? {
        if let cached = iconCache[path] {
            return cached
        }
        guard FileManager.default.fileExists(atPath: path) else {
            return nil
        }
        let img = NSWorkspace.shared.icon(forFile: path)
        if iconCache.count >= 256 {
            iconCache.removeAll(keepingCapacity: true)
        }
        iconCache[path] = img
        return img
    }

    // MARK: - macOS Application & Process Identity Resolution

    private static func extractPort(from client: String) -> UInt16? {
        guard let colon = client.lastIndex(of: ":") else { return nil }
        let portSlice = client[client.index(after: colon)...]
        return UInt16(portSlice)
    }

    /// Extracts the outermost `.app` bundle path (e.g. `/Applications/Google Chrome.app`
    /// from `/Applications/Google Chrome.app/Contents/Frameworks/.../Google Chrome Helper (Networking).app/...`).
    private static func extractOuterAppBundlePath(from path: String) -> String? {
        let components = (path as NSString).pathComponents
        var current = ""
        for comp in components {
            if comp == "/" {
                current = "/"
            } else if current.isEmpty || current == "/" {
                current += comp
            } else {
                current += "/" + comp
            }
            if comp.lowercased().hasSuffix(".app") {
                return current
            }
        }
        return nil
    }

    private static func appDisplayName(forBundlePath bundlePath: String) -> String {
        if let cached = displayNameCache[bundlePath] {
            return cached
        }
        let rawBundleName = ((bundlePath as NSString).lastPathComponent as NSString).deletingPathExtension
        var resolvedName: String?
        if let bundle = Bundle(path: bundlePath) {
            if let display = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String,
               !display.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                resolvedName = display
            } else if let name = bundle.object(forInfoDictionaryKey: "CFBundleName") as? String,
                      !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                resolvedName = name
            }
        }
        if resolvedName == nil {
            let fmName = FileManager.default.displayName(atPath: bundlePath)
            if fmName.lowercased().hasSuffix(".app") {
                resolvedName = String(fmName.dropLast(4))
            } else if !fmName.isEmpty {
                resolvedName = fmName
            }
        }
        let finalName = resolvedName ?? rawBundleName
        if displayNameCache.count >= 512 {
            displayNameCache.removeAll(keepingCapacity: true)
        }
        displayNameCache[bundlePath] = finalName
        return finalName
    }

    private static func descriptor(forProcessPath path: String) -> AppDescriptor {
        if let cached = descriptorCache[path] {
            return cached
        }
        let built = buildDescriptor(forProcessPath: path)
        if descriptorCache.count >= 512 {
            descriptorCache.removeAll(keepingCapacity: true)
        }
        descriptorCache[path] = built
        return built
    }

    private static func buildDescriptor(forProcessPath path: String) -> AppDescriptor {
        let cleanPath = path.trimmingCharacters(in: .whitespacesAndNewlines)
        let lowerPath = cleanPath.lowercased()
        let binaryName = (cleanPath as NSString).lastPathComponent
        let lowerBinary = binaryName.lowercased()

        // 1. Outermost macOS .app bundle (e.g. Google Chrome.app, WeChat.app, Telegram.app, Cursor.app, etc.)
        if let outerBundlePath = extractOuterAppBundlePath(from: cleanPath) {
            let appTitle = appDisplayName(forBundlePath: outerBundlePath)
            let bundleFilename = (outerBundlePath as NSString).lastPathComponent
            return AppDescriptor(
                key: "app.bundle.\(outerBundlePath.lowercased())",
                title: appTitle,
                subtitle: bundleFilename,
                symbolName: "app.fill",
                tintColor: HajimiAppearance.accent,
                iconPath: outerBundlePath
            )
        }

        // 2. Safari / WebKit XPC Networking process (runs outside Safari.app inside WebKit.framework)
        if lowerPath.contains("webkit.networking") || lowerPath.contains("safari") {
            let safariPath = "/System/Applications/Safari.app"
            return AppDescriptor(
                key: "app.bundle./system/applications/safari.app",
                title: "Safari",
                subtitle: "Safari.app (WebKit)",
                symbolName: "safari",
                tintColor: HajimiAppearance.uploadAccent,
                iconPath: safariPath
            )
        }

        // 3. System App Store & Apple Media daemons
        if lowerBinary == "appstoreagent" || lowerBinary == "storedownloadd" || lowerBinary == "commerce" {
            let storePath = "/System/Applications/App Store.app"
            return AppDescriptor(
                key: "app.bundle./system/applications/app store.app",
                title: "App Store",
                subtitle: "App Store.app",
                symbolName: "bag.fill",
                tintColor: HajimiAppearance.uploadAccent,
                iconPath: storePath
            )
        }
        if lowerBinary == "maild" || lowerPath.contains("/mail.app/") {
            let mailPath = "/System/Applications/Mail.app"
            return AppDescriptor(
                key: "app.bundle./system/applications/mail.app",
                title: "邮件 (Mail)",
                subtitle: "Mail.app",
                symbolName: "envelope.fill",
                tintColor: HajimiAppearance.uploadAccent,
                iconPath: mailPath
            )
        }
        if lowerBinary == "ampartworkagent" || lowerBinary == "amplibraryd" {
            let musicPath = "/System/Applications/Music.app"
            return AppDescriptor(
                key: "app.bundle./system/applications/music.app",
                title: "音乐 (Music)",
                subtitle: "Music.app",
                symbolName: "music.note",
                tintColor: .systemPink,
                iconPath: musicPath
            )
        }

        // 4. Git helper binaries (git-remote-https / git-remote-http)
        if lowerBinary.hasPrefix("git-remote-") || lowerBinary == "git" {
            return AppDescriptor(
                key: "proc.git",
                title: "git",
                subtitle: cleanPath,
                symbolName: "terminal",
                tintColor: HajimiAppearance.accent,
                iconPath: cleanPath
            )
        }

        // 5. Well-known macOS background daemons
        if lowerBinary == "nsurlsessiond" {
            return AppDescriptor(
                key: "proc.nsurlsessiond",
                title: "nsurlsessiond",
                subtitle: "macOS 系统后台下载与传输",
                symbolName: "arrow.down.circle.fill",
                tintColor: HajimiAppearance.uploadAccent,
                iconPath: cleanPath
            )
        }
        if lowerBinary == "cloudd" || lowerBinary == "bird" {
            return AppDescriptor(
                key: "proc.icloud",
                title: "iCloud 云同步 (\(binaryName))",
                subtitle: "macOS iCloud 同步守护进程",
                symbolName: "icloud.fill",
                tintColor: HajimiAppearance.uploadAccent,
                iconPath: cleanPath
            )
        }
        if lowerBinary == "apsd" {
            return AppDescriptor(
                key: "proc.apsd",
                title: "Apple 推送服务 (apsd)",
                subtitle: "macOS 系统消息推送守护进程",
                symbolName: "bell.badge.fill",
                tintColor: HajimiAppearance.indigoAccent,
                iconPath: cleanPath
            )
        }
        if lowerBinary == "trustd" || lowerBinary == "ocspd" {
            return AppDescriptor(
                key: "proc.trustd",
                title: "系统证书服务 (\(binaryName))",
                subtitle: "macOS TLS 证书校验守护进程",
                symbolName: "checkmark.shield.fill",
                tintColor: HajimiAppearance.indigoAccent,
                iconPath: cleanPath
            )
        }
        if lowerBinary == "mdnsresponder" {
            return dnsServiceDescriptor()
        }

        // 6. Any other command-line process or standalone executable (curl, node, python3, ssh, clash, etc.)
        let displayTitle = binaryName.isEmpty ? "macOS 进程" : binaryName
        return AppDescriptor(
            key: "proc.\(lowerBinary.isEmpty ? cleanPath.lowercased() : lowerBinary)",
            title: displayTitle,
            subtitle: cleanPath,
            symbolName: "terminal",
            tintColor: HajimiAppearance.accent,
            iconPath: cleanPath
        )
    }

    private static func dnsServiceDescriptor() -> AppDescriptor {
        AppDescriptor(
            key: "proc.mdnsresponder",
            title: "mDNSResponder (系统 DNS)",
            subtitle: "macOS 系统域名解析守护进程",
            symbolName: "lock.shield.fill",
            tintColor: HajimiAppearance.indigoAccent,
            iconPath: nil
        )
    }

    private static func pendingOrSystemDescriptor(port: UInt16) -> AppDescriptor {
        if port == 53 || port == 853 {
            return dnsServiceDescriptor()
        }
        return AppDescriptor(
            key: "proc.pending",
            title: "macOS 系统服务",
            subtitle: "系统底层或守护进程会话",
            symbolName: "cpu",
            tintColor: HajimiAppearance.indigoAccent,
            iconPath: nil
        )
    }

    private static func policyDescriptor(for policy: String, port: UInt16, method: String) -> AppDescriptor {
        let trimmed = policy.trimmingCharacters(in: .whitespacesAndNewlines)
        let upper = trimmed.uppercased()
        if upper == "DIRECT" {
            return AppDescriptor(
                key: "pol.DIRECT",
                title: "DIRECT (直连出站)",
                subtitle: "绕过代理直接访问目标主机",
                symbolName: "arrow.up.right.circle.fill",
                tintColor: HajimiAppearance.uploadAccent,
                iconPath: nil
            )
        }
        if upper == "DNS" || port == 53 || port == 853 {
            return AppDescriptor(
                key: "pol.DNS",
                title: "DNS 安全解析路由",
                subtitle: "加密 DoH / DoT 与防泄漏通道",
                symbolName: "lock.shield.fill",
                tintColor: HajimiAppearance.indigoAccent,
                iconPath: nil
            )
        }
        if upper.hasPrefix("REJECT") {
            return AppDescriptor(
                key: "pol.REJECT",
                title: "REJECT (策略拦截)",
                subtitle: "已阻断的广告或风险请求",
                symbolName: "xmark.shield.fill",
                tintColor: HajimiAppearance.statusDanger,
                iconPath: nil
            )
        }
        let name = trimmed.isEmpty ? "默认代理节点" : trimmed
        return AppDescriptor(
            key: "pol.\(name)",
            title: name,
            subtitle: "加密代理节点出站 (\(method))",
            symbolName: "server.rack",
            tintColor: HajimiAppearance.accent,
            iconPath: nil
        )
    }

    private static func classifySplit(policy: String, port: UInt16, host: String) -> SplitKind {
        let upper = policy.uppercased()
        if upper == "DNS" || port == 53 || port == 853 || host.lowercased().contains("dns.") {
            return .dnsAndSystem
        }
        if upper == "DIRECT" {
            return .direct
        }
        return .proxy
    }
}

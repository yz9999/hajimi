import Foundation
import HajimiCore
import HajimiRuntime

/// UI identity only. Credentials, profile text and user-named policies are
/// deliberately excluded from the copyable report below.
public struct NetworkDiagnosticsRuntimeContext: Equatable {
    public var engineState: String
    public var engineRunning: Bool
    public var mode: String
    public var selectedPolicy: String
    public var groupSelections: [String: String]
    public var profileRevision: Int
    public var enhancedMode: Bool
    public var systemProxy: Bool
    public var boundInterfaceName: String?
    public var runtimeRevision: UInt64 = 0
    public var runtimeBackend: NetworkRuntimeBackend? = nil
    public var runtimeSessionID: UUID? = nil

    public init(engineState: String, engineRunning: Bool, mode: String, selectedPolicy: String,
                groupSelections: [String: String], profileRevision: Int, enhancedMode: Bool,
                systemProxy: Bool, boundInterfaceName: String?, runtimeRevision: UInt64 = 0,
                runtimeBackend: NetworkRuntimeBackend? = nil, runtimeSessionID: UUID? = nil) {
        self.engineState = engineState; self.engineRunning = engineRunning
        self.mode = mode; self.selectedPolicy = selectedPolicy; self.groupSelections = groupSelections
        self.profileRevision = profileRevision; self.enhancedMode = enhancedMode
        self.systemProxy = systemProxy; self.boundInterfaceName = boundInterfaceName
        self.runtimeRevision = runtimeRevision; self.runtimeBackend = runtimeBackend
        self.runtimeSessionID = runtimeSessionID
    }

    public var backend: NetworkRuntimeBackend {
        runtimeBackend ?? .select(enhancedModeActive: enhancedMode, listenerRunning: engineRunning)
    }

    public static let unavailable = Self(engineState: "未连接应用", engineRunning: false,
        mode: "--", selectedPolicy: "--", groupSelections: [:], profileRevision: 0,
        enhancedMode: false, systemProxy: false, boundInterfaceName: nil)
}

/// A round belongs to one visible window and one configuration. Queued or
/// already-dispatched callbacks cannot overwrite a newer round after cancel.
package struct NetworkDiagnosticsRoundGuard {
    private(set) var id: UUID?
    private(set) var context: NetworkDiagnosticsRuntimeContext?

    package init() {}

    package mutating func begin(context: NetworkDiagnosticsRuntimeContext) -> UUID {
        let id = UUID()
        self.id = id; self.context = context
        return id
    }

    package mutating func invalidate() { id = nil; context = nil }

    package func accepts(_ id: UUID, context: NetworkDiagnosticsRuntimeContext, visible: Bool) -> Bool {
        visible && self.id == id && self.context == context
    }
}

public enum NetworkDiagnosticsSummary {
    public static let detectionScope = "点击“开始网络检测”后运行一轮；本地直连与所选代理使用同一 HTTP 目标，"
        + "延迟包含所需解析、建连和首响应，不是 ICMP Ping。DNS 检测使用固定测试域名，验证真实应答，"
        + "仅代表本次测试；普通 DNS 的 IPv4／IPv6 指连接 DNS 服务器的传输，固定 A 查询不测试 IPv6 网页访问。"
        + "普通 DNS 连通性检测不改变应用的加密 DNS 策略。"
    public static let reportScope = "网络诊断报告包含本地 IP、网关和 DNS 地址；下方 DNS 详细记录仍使用匿名格式。"

    public static func runtime(_ context: NetworkDiagnosticsRuntimeContext) -> String {
        "引擎：\(context.engineState) · 模式：\(context.mode)"
            + " · 所选策略：\(display(context.selectedPolicy))\n"
            + "检测通道：\(context.backend.displayName) · "
            + "增强模式：\(context.enhancedMode ? "已开启" : "未开启")"
            + " · 系统代理：\(context.systemProxy ? "已开启" : "未开启")"
            + " · 绑定物理接口：\(context.boundInterfaceName ?? "自动")"
    }

    public static func local(_ snapshot: LocalNetworkDiagnosticsSnapshot) -> String {
        let status: String
        switch snapshot.localLinkStatus {
        case .available: status = "本地链路已配置（公网可达性见下方检测）"
        case .unavailable: status = "未检测到可用本地链路"
        case .unknown: status = "本地链路状态待确认"
        }
        let physical = snapshot.interfaces.first { $0.name == snapshot.physicalInterfaceName }
        let source: String
        switch snapshot.physicalInterfaceSelection {
        case .boundInterface: source = "当前出口绑定"
        case .systemPrimary: source = "系统主服务"
        case .singleActiveInterface: source = "唯一活动物理接口"
        case .undetermined: source = "尚未确定"
        }
        var lines = ["\(status) · 采集 \(time(snapshot.capturedAt))",
            "物理接口：\(snapshot.physicalInterfaceName ?? "--")（\(source)）",
            "本地 IPv4：\(addresses(physical?.ipv4Addresses ?? []))",
            "本地 IPv6：\(addresses(physical?.ipv6Addresses ?? []))",
            "物理网关：\(addresses(snapshot.gateways))",
            "系统 DNS：\(addresses(snapshot.systemDNSServers))",
            "物理服务 DNS：\(addresses(snapshot.physicalDNSServers))"]
        let primary = [snapshot.systemPrimaryIPv4Interface, snapshot.systemPrimaryIPv6Interface]
            .compactMap { $0 }.reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
        lines.append("系统主接口：\(primary.isEmpty ? "--" : primary.joined(separator: " / "))（不代表所有目的的实际路由）")
        let extra = snapshot.interfaces.filter {
            $0.isUp && $0.kind != .loopback && $0.name != snapshot.physicalInterfaceName
                && (!$0.ipv4Addresses.isEmpty || !$0.ipv6Addresses.isEmpty)
        }
        for interface in extra.prefix(8) {
            let kind = interface.kind == .tunnel ? "隧道" : "其他接口"
            lines.append("\(kind) \(interface.name)：\(addresses(interface.ipv4Addresses + interface.ipv6Addresses))")
        }
        if extra.count > 8 { lines.append("其余 \(extra.count - 8) 个接口见网络诊断报告") }
        if !snapshot.collectionIssues.isEmpty {
            let issues = snapshot.collectionIssues.map { issue -> String in
                switch issue {
                case .interfaceEnumerationFailed: return "接口读取失败"
                case .configurationUnavailable: return "系统网络配置暂不可读"
                case .resultsTruncated: return "过多记录已截断"
                case .boundInterfaceUnavailable: return "绑定物理接口当前不可用"
                }
            }
            lines.append("采集提示：" + issues.joined(separator: "；"))
        }
        return lines.joined(separator: "\n")
    }

    public static func sameLocalNetwork(_ lhs: LocalNetworkDiagnosticsSnapshot,
                                 _ rhs: LocalNetworkDiagnosticsSnapshot) -> Bool {
        lhs.interfaces == rhs.interfaces && lhs.localLinkStatus == rhs.localLinkStatus
            && lhs.physicalInterfaceName == rhs.physicalInterfaceName
            && lhs.physicalInterfaceSelection == rhs.physicalInterfaceSelection
            && lhs.systemPrimaryIPv4Interface == rhs.systemPrimaryIPv4Interface
            && lhs.systemPrimaryIPv6Interface == rhs.systemPrimaryIPv6Interface
            && lhs.gateways == rhs.gateways && lhs.systemDNSServers == rhs.systemDNSServers
            && lhs.physicalDNSServers == rhs.physicalDNSServers
    }

    public static func progress(_ snapshot: NetworkConnectivityDiagnosticsSnapshot) -> String {
        let finished = snapshot.rows.filter { ![.queued, .running].contains($0.status) }.count
        var text = snapshot.isRunning ? "正在检测 \(finished) / \(snapshot.rows.count)"
            : "本轮已结束 · \(finished) / \(snapshot.rows.count) · \(time(snapshot.updatedAt))"
        if snapshot.omittedEndpointCount > 0 {
            text += " · 另有 \(snapshot.omittedEndpointCount) 个端点未测试（每类最多八个）"
        }
        return text
    }

    public static func status(_ value: NetworkConnectivityDiagnosticResult) -> String {
        switch value.status {
        case .queued: return "等待"
        case .running: return "检测中…"
        case .success: return "可达 · " + NetworkDiagnosticsFormatting.milliseconds(value.milliseconds)
        case .failure: return "失败"
        case .skipped: return "未测试"
        case .cancelled: return "已取消"
        }
    }

    public static func detail(_ value: NetworkConnectivityDiagnosticResult) -> String {
        var lines = ["\(value.endpoint) · \(value.route)"]
        if !value.detail.isEmpty { lines.append(value.detail) }
        var metadata: [String] = []
        if let code = value.responseCode {
            let isHTTP = value.kind == .localLatency || value.kind == .proxyLatency
            metadata.append("\(isHTTP ? "HTTP" : "DNS RCODE") \(code)")
        }
        if let codes = value.extendedDNSErrorCodes, !codes.isEmpty {
            metadata.append("EDE " + codes.map(String.init).joined(separator: ", "))
        }
        if let domain = value.errorDomain, let code = value.errorCode { metadata.append("\(domain):\(code)") }
        if !metadata.isEmpty { lines.append(metadata.joined(separator: " · ")) }
        return lines.joined(separator: "\n")
    }

    public static func report(context: NetworkDiagnosticsRuntimeContext,
                       local: LocalNetworkDiagnosticsSnapshot?,
                       connectivity: NetworkConnectivityDiagnosticsSnapshot?,
                       performance: NetworkPerformanceSnapshot,
                       applicationVersion: String = NetworkDiagnosticsFormatting.applicationVersion,
                       capturedUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds) -> String? {
        struct Runtime: Encodable {
            let engineState: String
            let engineRunning: Bool
            let mode: String
            let enhancedMode: Bool
            let systemProxy: Bool
            let boundInterfaceName: String?
            let diagnosticsBackend: String
        }
        struct Report: Encodable {
            let schemaVersion: Int
            let applicationVersion: String
            let capturedAt: Date
            let containsLocalAddresses: Bool
            let runtime: Runtime
            let localNetwork: LocalNetworkDiagnosticsSnapshot?
            let connectivity: NetworkConnectivityDiagnosticsSnapshot?
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let report = Report(schemaVersion: 1, applicationVersion: applicationVersion,
            capturedAt: Date(), containsLocalAddresses: true,
            runtime: Runtime(engineState: context.engineState, engineRunning: context.engineRunning,
                mode: context.mode, enhancedMode: context.enhancedMode, systemProxy: context.systemProxy,
                boundInterfaceName: context.boundInterfaceName, diagnosticsBackend: context.backend.rawValue),
            localNetwork: local, connectivity: connectivity)
        guard let encoded = try? encoder.encode(report),
              var object = (try? JSONSerialization.jsonObject(with: encoded)) as? [String: Any],
              let dns = NetworkDiagnosticsFormatting.dnsAttemptReport(performance, applicationVersion: applicationVersion,
                  capturedUptimeNanoseconds: capturedUptimeNanoseconds),
              let dnsObject = try? JSONSerialization.jsonObject(with: Data(dns.utf8)) else { return nil }
        object["dnsDiagnostics"] = dnsObject
        object["stages"] = NetworkDiagnosticsFormatting.stages.map { stage, title -> [String: Any] in
            let value = performance.stages[stage] ?? NetworkStageSnapshot()
            var row: [String: Any] = ["stage": stage.rawValue, "title": title,
                "count": value.count, "failureCount": value.failureCount,
                "cancellationCount": value.cancellationCount, "sampleCount": value.sampleCount]
            for (key, number) in [("medianMilliseconds", value.medianMilliseconds),
                                  ("p95Milliseconds", value.p95Milliseconds),
                                  ("latestMilliseconds", value.latestMilliseconds)] {
                if let number, number.isFinite, number >= 0 { row[key] = number }
            }
            return row
        }
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func addresses(_ values: [String]) -> String {
        guard !values.isEmpty else { return "--" }
        let suffix = values.count > 4 ? "（另有 \(values.count - 4) 个，见报告）" : ""
        return values.prefix(4).joined(separator: " / ") + suffix
    }

    private static func display(_ value: String) -> String {
        String(value.prefix(256).filter { character in
            !character.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
        }.prefix(128))
    }

    private static func time(_ date: Date) -> String {
        date.formatted(date: .omitted, time: .standard)
    }
}

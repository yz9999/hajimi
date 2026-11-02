import Foundation
import HajimiCore

/// Prepared away from AppKit. Retains the complete snapshot for explicit
/// report copies while keeping periodic main-thread work to changed strings.
struct NetworkDiagnosticsPreparedStatistics {
    let snapshot: NetworkPerformanceSnapshot
    let rows: [NetworkDiagnosticsFormatting.Row]
    let dns: String
    let scheduler: String
    let attempts: String
}

public enum NetworkDiagnosticsFormatting {
    public struct Row: Equatable {
        public let stage: NetworkPerformanceStage
        public let title: String
        public let counts: String
        public let samples: String
        public let median: String
        public let p95: String
        public let latest: String
    }

    public static let stages: [(NetworkPerformanceStage, String)] = [
        (.dnsPolicyPreparation, "DNS 规则准备"), (.dnsResolution, "应用 DNS"),
        (.dnsResolverQueue, "DNS 连接排队"),
        (.dnsUpstreamConnection, "DNS 通道建连"), (.dnsTLSHandshake, "DNS 内层 TLS"),
        (.dnsConnectionPrewarm, "DNS 后台连接准备"),
        (.dnsEncryptedPhase, "加密 DNS 阶段"), (.dnsProxyFallbackPhase, "代理内 DNS 回退"),
        (.dnsProxyFallbackConnection, "普通 DNS 代理建连"), (.dnsProxyFallbackExchange, "代理内普通 DNS 交换"),
        (.nodeResolution, "节点 DNS 引导"),
        (.connectionSetup, "建立连接（合计）"), (.firstByte, "流首字节"),
        (.probeFirstByte, "健康探测首响应")
    ]

    public static let scope = "建立连接 = TCP / TLS / 代理握手合计；DNS 分段不等于应用 HTTPS 握手。\n"
        + "DNS 规则准备 = 同步规则计算（包括拒绝）；应用 DNS 从准备后提交解析时计时。\n"
        + "DNS 连接排队 = 本机连接池实际等待，计入原查询期限；成功仅表示获得连接准入，不表示 DNS 应答成功。\n"
        + "DNS 通道建连 / 内层 TLS = 新建连接分段；复用连接不重复计握手，失败可含本地准入。\n"
        + "DNS 后台连接准备不发送应用查询；必要时仅解析已配置 DoH 的端点域名，不计作应用 DNS 成功。\n"
        + "代理内 DNS 回退 = 明确启用后的普通 DNS 经加密代理查询；禁止本机直连，总查询期限不延长。\n"
        + "普通 DNS 代理建连 / 交换包含获准后备与速度优先模式；复用连接不重复计建连。\n"
        + "缓存资格统计已通过许可和期限检查的查询；已存/未存仅统计符合查询资格的应答。\n"
        + "缓存命中率以全部 DNS 查询为分母；合并与排队后缓存命中可重叠。\n"
        + "追加尝试包含择优备用和失败后重试，次数不等于查询失败数。\n"
        + "流首字节 = 首次应用发送到首次非空接收，不是 HTTPS 页面 HTTP TTFB。\n"
        + "健康探测 = 实际启动到 HTTP 状态行；排队不计入网络时延。\n"
        + "p50 / p95 只取最近最多 128 个成功样本（非累计成功数）；中止不算成功或网络失败。\n"
        + "匿名 DNS 明细仅在进程内保存统计与最近 128 次建连记录，每次最多 24 条事件；不记录应用查询域名、地址、URL、凭据或错误文本。\n"
        + "上游与路径编号仅本次运行有效；连接复用不产生新握手记录；窗口可见时最多每秒刷新。"

    public static func milliseconds(_ value: Double?) -> String {
        guard let value, value.isFinite, value >= 0 else { return "--" }
        return String(format: "%.1f ms", locale: Locale(identifier: "en_US_POSIX"), value)
    }

    public static func hitRate(_ value: Double?) -> String {
        guard let value, value.isFinite, (0...1).contains(value) else { return "--" }
        return String(format: "%.1f%%", locale: Locale(identifier: "en_US_POSIX"), value * 100)
    }

    public static func version(_ version: String?, build: String?) -> String {
        let version = version.flatMap { $0.isEmpty ? nil : $0 } ?? "--"
        let build = build.flatMap { $0.isEmpty ? nil : $0 } ?? "--"
        return "版本 \(version) · Build \(build)"
    }

    public static var applicationVersion: String {
        version(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
                build: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String)
    }

    public static func rows(_ snapshot: NetworkPerformanceSnapshot) -> [Row] {
        stages.map { stage, title in
            let value = snapshot.stages[stage] ?? NetworkStageSnapshot()
            return Row(stage: stage, title: title,
                       counts: "\(value.count) / \(value.failureCount) / \(value.cancellationCount)",
                       samples: String(value.sampleCount), median: milliseconds(value.medianMilliseconds),
                       p95: milliseconds(value.p95Milliseconds), latest: milliseconds(value.latestMilliseconds))
        }
    }

    static func prepare(_ statistics: NetworkDiagnosticsStatistics) -> NetworkDiagnosticsPreparedStatistics {
        NetworkDiagnosticsPreparedStatistics(snapshot: statistics.performance,
            rows: rows(statistics.performance), dns: dns(statistics.performance),
            scheduler: scheduler(statistics.scheduler), attempts: dnsAttempts(statistics.performance))
    }

    public static func dns(_ snapshot: NetworkPerformanceSnapshot) -> String {
        "DNS 查询 \(snapshot.dnsQueries) · 缓存命中 \(snapshot.dnsCacheHits)（\(hitRate(snapshot.cacheHitRate))）"
            + " · 合并 \(snapshot.dnsMergedQueries)\n"
            + "缓存资格 \(snapshot.dnsCacheEligibleQueries) · 不适用 \(snapshot.dnsCacheBypassedQueries)"
            + " · 已存应答 \(snapshot.dnsCacheStoredResponses) · 未存应答 \(snapshot.dnsCacheRejectedResponses)\n"
            + "上游尝试 \(snapshot.dnsUpstreamAttempts) · 查询失败 \(snapshot.dnsFailures)"
            + " · 中止 \(snapshot.dnsCancelledQueries)"
            + " · 追加尝试 \(snapshot.dnsFailovers) · 加密 DNS 连接复用 \(snapshot.dnsConnectionsReused)"
            + "\n查询失败分类：上游/响应 \(snapshot.dnsFailureReasons[.upstreamOrResponse, default: 0])"
            + " · 总超时 \(snapshot.dnsFailureReasons[.timeout, default: 0])"
            + " · 容量拒绝 \(snapshot.dnsFailureReasons[.capacity, default: 0])"
            + " · 身份验证 \(snapshot.dnsFailureReasons[.authentication, default: 0])"
            + "\n配置/策略 \(snapshot.dnsFailureReasons[.configurationOrPolicy, default: 0])"
            + " · 无效应答 \(snapshot.dnsFailureReasons[.invalidResponse, default: 0])"
            + "\n代理内回退：尝试 \(snapshot.dnsProxyFallbackAttempts)"
            + " · 成功 \(snapshot.dnsProxyFallbackSuccesses) · 失败 \(snapshot.dnsProxyFallbackFailures)"
            + " · 连接复用 \(snapshot.dnsProxyFallbackConnectionsReused)"
    }

    public static func scheduler(_ snapshot: ProbeScheduler.Snapshot) -> String {
        "测速运行 \(snapshot.active) / \(snapshot.maximumActive) · 排队 \(snapshot.queued) / \(snapshot.maximumQueued)"
            + " · 健康建连待回调 \(snapshot.pendingConnections) / \(snapshot.maximumActive)\n"
            + "队列拒绝 \(snapshot.rejected) · 连接限额 \(snapshot.rejectedConnections) · 排队超时 \(snapshot.queueTimeouts)"
            + " · 请求超时 \(snapshot.requestTimeouts) · 最近排队 \(milliseconds(snapshot.latestQueueWaitMilliseconds))"
    }

    public static func dnsAttempts(_ snapshot: NetworkPerformanceSnapshot) -> String {
        guard !snapshot.dnsConnectionAttempts.isEmpty else { return "DNS 建连明细：暂无新建连接记录" }
        return "最近 DNS 建连（显示最近 8 次，复制可取完整记录）：\n" + snapshot.dnsConnectionAttempts.suffix(8).reversed().map { attempt in
            let outcome: String
            if let measured = attempt.tlsOutcome {
                outcome = measured == .success ? "TLS 成功" : (measured == .failure ? "TLS 失败" : "TLS 中止")
            } else if attempt.observations.contains(where: { $0.event == .tlsStarted }) {
                outcome = attempt.requestFinished ? "等待 TLS 结束回执" : "TLS 进行中"
            } else if let measured = attempt.transportOutcome {
                outcome = measured == .success ? "通道已就绪" : (measured == .failure ? "通道失败" : "通道中止")
            } else {
                outcome = attempt.requestFinished ? "已结束／未建立" : "建连中"
            }
            let cancellation = attempt.cancellationReason.map { cancellationName($0) } ?? "--"
            let first = attempt.firstErrorBeforeCancellation.map { error in
                error.category + " " + error.codes.map { "\($0.domain):\($0.code)" }.joined(separator: " → ")
            } ?? (attempt.firstError == nil ? "--" : "仅关闭／取消后的回调，详见完整记录")
            let close = attempt.firstCarrierClosure.map {
                "\($0.event.rawValue) @ \(milliseconds($0.milliseconds))"
            } ?? "--"
            return "\(attempt.id.uuidString.prefix(8)) · \(attempt.provider) · \(attempt.transport.rawValue) · \(attempt.purpose == .prewarm ? "预热" : "查询") · \(outcome)\n"
                + "\(attempt.upstreamID) / \(attempt.addressID) · \(attempt.route.rawValue) · \(attempt.routeID ?? "--")\n"
                + "主动取消前错误 \(first) · 取消 \(cancellation) · 首次关闭事件 \(close)"
        }.joined(separator: "\n\n")
    }

    public static func cancellationName(_ reason: DNSAttemptCancellationReason) -> String {
        switch reason {
        case .callerCancelled: return "调用方取消"
        case .winnerSelected: return "其他候选已返回"
        case .hedgeRotation: return "备用轮换"
        case .overallDeadline: return "查询总期限"
        case .requestDeadline: return "连接请求期限"
        case .encryptedPhaseDeadline: return "加密阶段期限"
        case .policyChanged: return "策略或接口更新"
        case .poolShutdown: return "连接池关闭"
        case .prewarmSuperseded: return "预热任务撤销"
        case .cleanup: return "完成后清理"
        }
    }

    public static func dnsAttemptReport(_ snapshot: NetworkPerformanceSnapshot,
        applicationVersion: String = NetworkDiagnosticsFormatting.applicationVersion,
        capturedUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds) -> String? {
        struct Report: Encodable {
            let schemaVersion: Int
            let applicationVersion: String
            let capturedUptimeNanoseconds: UInt64
            let totals: [String: UInt64]
            let failureReasons: [String: UInt64]
            let attempts: [DNSConnectionAttemptSnapshot]
            let logicalQueries: [DNSLogicalQuerySnapshot]
            let exchanges: [DNSQueryExchangeSnapshot]
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(Report(schemaVersion: 2, applicationVersion: applicationVersion,
            capturedUptimeNanoseconds: capturedUptimeNanoseconds,
            totals: ["queries": snapshot.dnsQueries, "failedQueries": snapshot.dnsFailures,
                "cancelledQueries": snapshot.dnsCancelledQueries, "mergedQueries": snapshot.dnsMergedQueries,
                "cacheHits": snapshot.dnsCacheHits, "upstreamAttempts": snapshot.dnsUpstreamAttempts,
                "additionalAttempts": snapshot.dnsFailovers, "connectionsReused": snapshot.dnsConnectionsReused],
            failureReasons: Dictionary(uniqueKeysWithValues: snapshot.dnsFailureReasons.map { ($0.key.rawValue, $0.value) }),
            attempts: snapshot.dnsConnectionAttempts, logicalQueries: snapshot.dnsLogicalQueries,
            exchanges: snapshot.dnsQueryExchanges)) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

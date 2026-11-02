import AppKit
import HajimiCore
import HajimiDiagnosticsUI
import HajimiUIComponents

enum NetworkDiagnosticsPresentationSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "网络诊断 UI 自检失败：\(text)" }
    }

    static func run() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        let empty = NetworkDiagnosticsFormatting.rows(NetworkPerformanceSnapshot())
        try require(empty.count == NetworkPerformanceStage.allCases.count
                    && Set(empty.map(\.stage)) == Set(NetworkPerformanceStage.allCases)
                    && empty.allSatisfy { $0.median == "--" && $0.p95 == "--" && $0.latest == "--" },
                    "无样本显示了伪造延迟")
        try require(NetworkDiagnosticsFormatting.hitRate(nil) == "--"
                    && NetworkDiagnosticsFormatting.hitRate(0.6) == "60.0%"
                    && NetworkDiagnosticsFormatting.milliseconds(.nan) == "--", "命中率或非法延迟格式错误")
        try require(NetworkDiagnosticsFormatting.version("0.1.0", build: "5") == "版本 0.1.0 · Build 5"
                    && NetworkDiagnosticsFormatting.version(nil, build: "") == "版本 -- · Build --",
                    "诊断窗口不能识别当前包版本或把缺失版本冒充已验证构建")
        let snapshot = NetworkPerformanceSnapshot(dnsCacheEligibleQueries: 8, dnsCacheBypassedQueries: 2,
            dnsCacheStoredResponses: 3, dnsCacheRejectedResponses: 1, dnsFailures: 2, dnsCancelledQueries: 3,
            dnsFailureReasons: [.upstreamOrResponse: 1, .timeout: 1],
            dnsProxyFallbackConnectionsReused: 4,
            stages: [.connectionSetup: NetworkStageSnapshot(count: 4, failureCount: 1,
                cancellationCount: 1, sampleCount: 2, medianMilliseconds: 12, p95Milliseconds: 24)])
        let measured = NetworkDiagnosticsFormatting.rows(snapshot).first { $0.stage == .connectionSetup }!
        try require(measured.counts == "4 / 1 / 1" && measured.median == "12.0 ms" && measured.p95 == "24.0 ms"
                    && measured.latest == "--", "聚合阶段或最近失败样本展示错误")
        try require(NetworkDiagnosticsFormatting.scope.contains("不是 HTTPS 页面 HTTP TTFB")
                    && NetworkDiagnosticsFormatting.scope.contains("TCP / TLS / 代理握手合计")
                    && NetworkDiagnosticsFormatting.scope.contains("同步规则计算（包括拒绝）")
                    && NetworkDiagnosticsFormatting.scope.contains("复用连接不重复计握手")
                    && NetworkDiagnosticsFormatting.scope.contains("非累计成功数")
                    && NetworkDiagnosticsFormatting.scope.contains("中止不算成功或网络失败"), "诊断口径说明缺失")
        try require(empty.contains { $0.stage == .dnsResolverQueue && $0.title == "DNS 连接排队" }
                    && NetworkDiagnosticsFormatting.scope.contains("计入原查询期限"),
                    "本地连接等待未显示或被当成上游连接时延")
        let dns = NetworkDiagnosticsFormatting.dns(snapshot)
        try require(dns.contains("上游尝试 0 · 查询失败 2 · 中止 3")
                    && dns.contains("查询失败分类：上游/响应 1 · 总超时 1 · 容量拒绝 0")
                    && dns.contains("缓存资格 8 · 不适用 2 · 已存应答 3 · 未存应答 1")
                    && dns.contains("追加尝试 0") && dns.contains("失败 0 · 连接复用 4"),
                    "逻辑查询失败被冒充候选失败或真实失败分类被隐藏")
        let reportText = NetworkDiagnosticsFormatting.dnsAttemptReport(snapshot) ?? ""
        let report = try JSONSerialization.jsonObject(with: Data(reportText.utf8)) as? [String: Any]
        let totals = report?["totals"] as? [String: Int]
        let reasons = report?["failureReasons"] as? [String: Int]
        try require(report?["schemaVersion"] as? Int == 2 && totals?["failedQueries"] == 2
                    && reasons?["timeout"] == 1 && report?["logicalQueries"] is [Any]
                    && report?["exchanges"] is [Any] && report?["attempts"] is [Any],
                    "复制诊断缺失父请求、复用交换、物理连接或全局失败口径")
        let context = NetworkDiagnosticsRuntimeContext(engineState: "运行中", engineRunning: true,
            mode: "规则", selectedPolicy: "private-policy-marker", groupSelections: ["private-group": "private-node"],
            profileRevision: 21, enhancedMode: true, systemProxy: false, boundInterfaceName: "en0")
        let local = LocalNetworkDiagnosticsSnapshot(capturedAt: Date(timeIntervalSince1970: 1),
            localLinkStatus: .available,
            interfaces: [.init(name: "en0", index: 4, kind: .physical, isUp: true, isRunning: true,
                ipv4Addresses: ["192.0.2.20"], ipv6Addresses: ["2001:db8::20"]),
                .init(name: "utun7", index: 8, kind: .tunnel, isUp: true, isRunning: true,
                    ipv4Addresses: ["198.19.0.1"], ipv6Addresses: [])],
            systemPrimaryIPv4Interface: "en0", systemPrimaryIPv6Interface: nil,
            physicalInterfaceName: "en0", physicalInterfaceSelection: .boundInterface,
            gateways: ["192.0.2.1"], systemDNSServers: ["127.0.0.1"],
            physicalDNSServers: [], collectionIssues: [])
        let localText = NetworkDiagnosticsSummary.local(local)
        try require(localText.contains("本地 IPv4：192.0.2.20") && localText.contains("本地 IPv6：2001:db8::20")
                    && localText.contains("物理网关：192.0.2.1") && localText.contains("系统 DNS：127.0.0.1")
                    && localText.contains("隧道 utun7") && localText.contains("不代表所有目的的实际路由")
                    && localText.contains("公网可达性见下方检测"), "本地信息混淆了物理/TUN接口或把链路当公网可达")
        func localCopy(capturedAt: Date, gateways: [String]) -> LocalNetworkDiagnosticsSnapshot {
            LocalNetworkDiagnosticsSnapshot(capturedAt: capturedAt, localLinkStatus: local.localLinkStatus,
                interfaces: local.interfaces, systemPrimaryIPv4Interface: local.systemPrimaryIPv4Interface,
                systemPrimaryIPv6Interface: local.systemPrimaryIPv6Interface,
                physicalInterfaceName: local.physicalInterfaceName,
                physicalInterfaceSelection: local.physicalInterfaceSelection,
                gateways: gateways, systemDNSServers: local.systemDNSServers,
                physicalDNSServers: local.physicalDNSServers, collectionIssues: local.collectionIssues)
        }
        let laterLocal = localCopy(capturedAt: Date(timeIntervalSince1970: 20), gateways: local.gateways)
        let changedLocal = localCopy(capturedAt: laterLocal.capturedAt, gateways: ["192.0.2.254"])
        try require(NetworkDiagnosticsSummary.sameLocalNetwork(local, laterLocal)
                    && !NetworkDiagnosticsSummary.sameLocalNetwork(local, changedLocal), "采集时间引起假网络变更或网关变化未被识别")
        let connectivity = try JSONDecoder().decode(NetworkConnectivityDiagnosticsSnapshot.self, from: Data("""
            {"id":"11111111-2222-3333-4444-555555555555","startedAt":0,"updatedAt":1,
             "isRunning":false,"omittedEndpointCount":2,"rows":[
              {"id":"local","kind":"localLatency","title":"本地网络 HTTP 首响应",
               "endpoint":"http://captive.apple.com:80","route":"DIRECT","status":"success",
               "milliseconds":12.5,"responseCode":200,"detail":"固定 HTTP 目标"},
              {"id":"proxy","kind":"proxyLatency","title":"所选代理 HTTP 首响应",
               "endpoint":"http://captive.apple.com:80","route":"DIRECT","status":"skipped",
               "detail":"所选策略为 DIRECT，不记录代理延迟"},
              {"id":"dns","kind":"encryptedDNS","title":"加密 DNS 1",
               "endpoint":"DoH resolver.example:443","route":"代理","status":"failure",
               "responseCode":2,"extendedDNSErrorCodes":[6,22],
               "errorDomain":"app.hajimi.dns","errorCode":2,"detail":"上游返回 SERVFAIL"},
              {"id":"ipv6","kind":"traditionalDNS","title":"普通 DNS 2 · IPv6 传输 / A 查询",
               "endpoint":"[2001:db8::53]:53","route":"物理出口直连 · 固定测试","status":"failure",
               "milliseconds":4000,"errorDomain":"NSPOSIXErrorDomain","errorCode":65,
               "detail":"IPv6 直连 DNS 检测已到原截止时间；绑定物理出口的网络路径不可达"}]}
            """.utf8))
        var activeConnectivityObject = (try JSONSerialization.jsonObject(with: JSONEncoder().encode(connectivity))) as? [String: Any] ?? [:]
        activeConnectivityObject["isRunning"] = true
        let activeConnectivity = try JSONDecoder().decode(NetworkConnectivityDiagnosticsSnapshot.self,
            from: JSONSerialization.data(withJSONObject: activeConnectivityObject))
        try require(NetworkDiagnosticsSummary.status(connectivity.rows[0]) == "可达 · 12.5 ms"
                    && NetworkDiagnosticsSummary.status(connectivity.rows[1]) == "未测试"
                    && NetworkDiagnosticsSummary.status(connectivity.rows[2]) == "失败"
                    && NetworkDiagnosticsSummary.detail(connectivity.rows[0]).contains("HTTP 200")
                    && NetworkDiagnosticsSummary.detail(connectivity.rows[2]).contains("DNS RCODE 2 · EDE 6, 22")
                    && NetworkDiagnosticsSummary.progress(connectivity).contains("另有 2 个端点未测试"),
                    "直连/代理跳过、RCODE/EDE或遗漏端点展示错误")
        try require(NetworkDiagnosticsSummary.status(connectivity.rows[3]) == "失败"
                    && NetworkDiagnosticsSummary.detail(connectivity.rows[3]).contains("NSPOSIXErrorDomain:65")
                    && NetworkDiagnosticsSummary.detail(connectivity.rows[3]).contains("物理出口")
                    && NetworkDiagnosticsSummary.detectionScope.contains("固定 A 查询不测试 IPv6 网页访问"),
                    "IPv6 物理路径失败被隐藏，或将 A/AAAA 查询类型与传输能力混淆")
        let networkText = NetworkDiagnosticsSummary.report(context: context, local: local,
            connectivity: connectivity, performance: snapshot) ?? ""
        let networkReport = try JSONSerialization.jsonObject(with: Data(networkText.utf8)) as? [String: Any]
        let networkDNS = networkReport?["dnsDiagnostics"] as? [String: Any]
        let networkRuntime = networkReport?["runtime"] as? [String: Any]
        try require(networkReport?["schemaVersion"] as? Int == 1
                    && networkReport?["containsLocalAddresses"] as? Bool == true
                    && networkReport?["localNetwork"] is [String: Any]
                    && networkReport?["connectivity"] is [String: Any]
                    && networkReport?["stages"] is [[String: Any]]
                    && networkRuntime?["engineRunning"] as? Bool == true
                    && networkRuntime?["diagnosticsBackend"] as? String == "enhanced"
                    && networkDNS?["schemaVersion"] as? Int == 2
                    && networkText.contains("192.0.2.20") && networkText.contains("extendedDNSErrorCodes")
                    && !networkText.contains("private-policy-marker") && !networkText.contains("private-group")
                    && !networkText.contains("private-node") && !networkText.contains("runtimeRevision"),
                    "网络报告丢失当前核心来源、破坏匿名DNS schema或导出策略名/内部会话身份")
        var round = NetworkDiagnosticsRoundGuard()
        let firstRound = round.begin(context: context)
        try require(round.accepts(firstRound, context: context, visible: true)
                    && !round.accepts(firstRound, context: context, visible: false), "隐藏窗口仍接收旧轮次")
        var newContext = context; newContext.profileRevision += 1
        try require(!round.accepts(firstRound, context: newContext, visible: true), "配置变化后回填旧检测")
        var restartedContext = context; restartedContext.runtimeRevision &+= 1
        try require(!round.accepts(firstRound, context: restartedContext, visible: true), "同配置重启后回填旧检测")
        var listenerContext = context; listenerContext.enhancedMode = false
        try require(!round.accepts(firstRound, context: listenerContext, visible: true), "更换检测通道后回填旧检测")
        round.invalidate()
        try require(!round.accepts(firstRound, context: context, visible: true), "取消后回填旧检测")
        let secondRound = round.begin(context: newContext)
        try require(!round.accepts(firstRound, context: newContext, visible: true)
                    && round.accepts(secondRound, context: newContext, visible: true), "新一轮接收了旧回调")
        var gate = NetworkDiagnosticsRefreshGate()
        try require(!gate.shouldRefresh(visible: false, now: 0) && gate.shouldRefresh(visible: true, now: 0)
                    && !gate.shouldRefresh(visible: true, now: 0.5)
                    && !gate.shouldRefresh(visible: false, now: 2)
                    && gate.shouldRefresh(visible: true, now: 2), "隐藏/低频诊断刷新门控失效")
        // Offscreen view only: do not order a window, activate NSApp or read
        // user configuration merely to check the presentation.
        // The complete table/notes may outgrow the viewport. Verify the real
        // scroll wrapper at the minimum panel size and a shorter viewport,
        // rather than squeezing away the new safety/phase diagnostics.
        for size in [NSSize(width: 880, height: 680), NSSize(width: 850, height: 652),
                     NSSize(width: 850, height: 400)] {
            let view = NetworkDiagnosticsView(frame: .zero,
                applicationVersion: "版本 memory · Build 30", now: { 0 }, copyReport: { _ in })
            let wrapper = WidthFittingScrollContentView(content: view)
            let host = NSView(frame: NSRect(origin: .zero, size: size))
            wrapper.frame = host.bounds
            host.addSubview(wrapper)
            view.apply(snapshot, scheduler: ProbeScheduler(maximumActive: 8, maximumQueued: 512).snapshot())
            view.applyContext(context, detectionAvailable: true)
            view.applyLocalNetwork(local)
            view.onStartDetection = {}
            var stoppedContext = context; stoppedContext.engineRunning = false
            view.applyContext(stoppedContext, detectionAvailable: true)
            try require(!view.canStartDetection, "未就绪核心仍允许开始检测")
            view.applyContext(context, detectionAvailable: true)
            try require(view.canStartDetection, "增强模式就绪但监听引擎未运行时不能检测")
            view.prepareDetection()
            try require(view.isDetectionRunning && !view.canStartDetection, "准备中的面板允许重复开始检测")
            view.applyConnectivity(activeConnectivity)
            try require(view.isDetectionRunning && !view.canStartDetection, "运行中的面板允许重复开始检测")
            view.clearConnectivity(reason: "本轮检测已停止")
            try require(!view.isDetectionRunning && view.canStartDetection,
                        "终态尚未送达时停止检测，面板未同步恢复开始按钮")
            view.applyConnectivity(connectivity)
            wrapper.layoutSubtreeIfNeeded()
            try require(view.displayedRows == NetworkDiagnosticsFormatting.rows(snapshot), "离屏面板没有显示注入的聚合值")
            guard let stack = view.subviews.first as? NSStackView,
                  let note = stack.arrangedSubviews.last as? NSTextField else {
                throw Failure(text: "诊断布局缺失")
            }
            guard let document = wrapper.scrollView.documentView else { throw Failure(text: "诊断滚动文档缺失") }
            let clip = wrapper.scrollView.contentView
            try require(view.fittingSize.width <= clip.bounds.width && document.frame.width <= clip.bounds.width + 1
                        && document.frame.height >= view.fittingSize.height,
                        "最小面板尺寸无法容纳可滚动诊断内容")
            for child in stack.arrangedSubviews {
                let frame = view.convert(child.bounds, from: child)
                try require(view.bounds.insetBy(dx: -0.5, dy: -0.5).contains(frame), "表格或说明被面板边界裁切")
            }
            let noteFrame = view.convert(note.bounds, from: note)
            try require(noteFrame.minY >= 24 && noteFrame.height >= note.fittingSize.height
                        && noteFrame.height >= 98, "底部说明被挤压或裁切")
            let noteInDocument = note.convert(note.bounds, to: document)
            let origin = max(0, min(document.frame.height - clip.bounds.height, noteInDocument.maxY - clip.bounds.height))
            clip.scroll(to: NSPoint(x: 0, y: origin))
            wrapper.scrollView.reflectScrolledClipView(clip)
            try require(clip.bounds.insetBy(dx: -0.5, dy: -0.5).contains(noteInDocument),
                        "诊断说明无法滚入视口")
        }
        // BEGIN Build 31 shared-scroll regression additions.
        try verifyScrollerTransitions()
        // END Build 31 shared-scroll regression additions.
    }

    // BEGIN Build 31 shared-scroll regression additions.
    private static func verifyScrollerTransitions() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        func nextMainDelivery() throws {
            var delivered = false
            DispatchQueue.main.async { delivered = true }
            let deadline = Date().addingTimeInterval(0.5)
            while !delivered && Date() < deadline {
                RunLoop.current.run(until: Date().addingTimeInterval(0.001))
            }
            try require(delivered, "滚动布局回归未收到下一次主队列交付")
        }
        let note = NSTextField(wrappingLabelWithString: Array(repeating:
            "物理出口与 DNS 检测说明：滚动条切换后仍应按当前视口宽度换行。", count: 36).joined(separator: " "))
        note.font = .systemFont(ofSize: 11)
        note.setContentCompressionResistancePriority(.required, for: .vertical)
        let footer = NSButton(title: "保存并应用", target: nil, action: nil)
        let stack = NSStackView(views: [note, footer])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        note.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        let wrapper = WidthFittingScrollContentView(content: stack)
        let host = NSView(frame: NSRect(x: 0, y: 0, width: 700, height: 260))
        wrapper.frame = host.bounds
        host.addSubview(wrapper)

        func verifyLayout(_ phase: String) throws {
            // Deliberately do not mark needsLayout. Clip-frame changes must
            // invalidate the wrapper, including after a main-queue delivery.
            wrapper.layoutSubtreeIfNeeded()
            guard let document = wrapper.scrollView.documentView else {
                throw Failure(text: "\(phase)：缺少滚动文档")
            }
            let clip = wrapper.scrollView.contentView
            try require(abs(document.frame.width - clip.bounds.width) < 1
                        && stack.frame.width <= clip.bounds.width
                        && document.frame.height >= stack.fittingSize.height,
                        "\(phase)：滚动条变化后文档未匹配真实视口")
            try require(note.frame.height >= note.fittingSize.height && note.frame.height > 100,
                        "\(phase)：窄视口换行说明被挤压")
            let bottom = footer.convert(footer.bounds, to: document)
            clip.scroll(to: NSPoint(x: 0, y: max(0, document.frame.height - clip.bounds.height)))
            wrapper.scrollView.reflectScrolledClipView(clip)
            try require(clip.bounds.insetBy(dx: -0.5, dy: -0.5).contains(bottom),
                        "\(phase)：底部按钮无法滚入视口")
        }

        func applyScrollerStyle(_ style: NSScroller.Style, phase: String) throws {
            // AppKit's first preferred-style delivery can override a style that
            // this offscreen fixture already accepted. See the fresh-process
            // matrix in .build/build32-release-checks/scroller-style-matrix/.
            // Reapply only after an actual style override, and still require
            // correct geometry after every delivery without forcing layout.
            wrapper.scrollView.scrollerStyle = style
            for attempt in 0..<3 {
                try nextMainDelivery()
                try verifyLayout(phase)
                if wrapper.scrollView.scrollerStyle == style { break }
                if attempt < 2 { wrapper.scrollView.scrollerStyle = style }
            }
            try require(wrapper.scrollView.scrollerStyle == style,
                        "\(phase)：AppKit 未保留夹具指定的滚动条样式")
        }

        try applyScrollerStyle(.legacy, phase: "初始 legacy")
        for (index, style) in [NSScroller.Style.overlay, .legacy, .overlay, .legacy].enumerated() {
            try applyScrollerStyle(style, phase: "滚动条切换 \(index + 1)")
            let clipWidth = wrapper.scrollView.contentView.bounds.width
            try require(wrapper.scrollView.scrollerStyle == style
                        && (style == .legacy ? clipWidth < wrapper.bounds.width - 1
                            : abs(clipWidth - wrapper.bounds.width) < 1),
                        "滚动条切换 \(index + 1)：未实际覆盖指定的滚动条样式")
        }

        wrapper.setFrameSize(NSSize(width: 700, height: 2400))
        try nextMainDelivery()
        try verifyLayout("高视口隐藏 legacy")
        try require(abs(wrapper.scrollView.contentView.bounds.width - wrapper.bounds.width) < 1,
                    "高视口没有覆盖 legacy 滚动条隐藏")
        wrapper.setFrameSize(NSSize(width: 650, height: 260))
        try nextMainDelivery()
        try verifyLayout("短视口恢复 legacy")
        try require(wrapper.scrollView.contentView.bounds.width < wrapper.bounds.width - 1,
                    "短视口没有覆盖 legacy 滚动条恢复")
        withExtendedLifetime(host) {}
    }
    // END Build 31 shared-scroll regression additions.
}

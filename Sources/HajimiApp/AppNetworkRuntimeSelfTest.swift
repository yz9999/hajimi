import Foundation
import HajimiCore
import HajimiRuntime
import HajimiDiagnosticsUI

/// Exercises the real App adapter with capability-only owners. No listener,
/// router, tunnel, Helper, profile store, interface lookup or socket is made.
enum AppNetworkRuntimeSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "App 运行时归属自检失败：\(text)" }
    }

    private final class CancellationCounter {
        var value = 0
    }

    private final class Owner: AppRuntimeDiagnosticsOwner {
        var value: AppRuntimeOwnerSnapshot
        var beforeReturn: (() -> Void)?
        var inlineSnapshot: NetworkConnectivityDiagnosticsSnapshot?
        private(set) var starts = 0
        private(set) var cancellations: [CancellationCounter] = []
        private var callbacks: [(NetworkConnectivityDiagnosticsSnapshot) -> Void] = []

        init(_ value: AppRuntimeOwnerSnapshot) { self.value = value }

        func snapshot() -> AppRuntimeOwnerSnapshot { value }

        func startDiagnostics(onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void)
            -> RuntimeOperation {
            starts += 1
            callbacks.append(onUpdate)
            let counter = CancellationCounter()
            cancellations.append(counter)
            let operation = RuntimeOperation()
            operation.installCancellation { counter.value += 1 }
            if let inlineSnapshot { onUpdate(inlineSnapshot) }
            beforeReturn?()
            return operation
        }

        func deliver(_ snapshot: NetworkConnectivityDiagnosticsSnapshot, at index: Int = 0) {
            callbacks[index](snapshot)
        }
    }

    static func run() throws {
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw Failure(text: text) }
        }
        try require(Thread.isMainThread, "App 适配层必须在主线程检查")
        func owner(_ present: Bool, phase: RuntimePhase? = nil, interface: String = "en-fixture",
                   startedAt: Date? = nil) -> Owner {
            Owner(AppRuntimeOwnerSnapshot(endpoint: RuntimeEndpointState(
                phase: phase ?? (present ? .running : .stopped), isPresent: present,
                boundInterfaceName: present ? interface : nil), lifecycleRevision: 0,
                startedAt: startedAt))
        }
        let configuration = NetworkDiagnosticsConfiguration(mode: "规则",
            selectedPolicy: "private-runtime-policy", groupSelections: ["private-group": "private-node"],
            profileRevision: 22, systemProxy: false)
        let sample = try snapshot(isRunning: true)
        let terminal = try snapshot(isRunning: false)

        for (listenerPresent, enhancedPresent, expected) in [
            (false, false, NetworkRuntimeBackend.unavailable),
            (true, false, .listener),
            (false, true, .enhanced),
            (true, true, .enhanced)
        ] {
            let listener = owner(listenerPresent), enhanced = owner(enhancedPresent)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let context = runtime.context(configuration: configuration)
            try require(context.backend == expected, "四种归属组合选择了错误核心")
            try require(context.engineRunning == (expected != .unavailable)
                && context.enhancedMode == enhancedPresent, "就绪或增强存在状态错误")
            try require(context.runtimeSessionID != nil
                && runtime.context(configuration: configuration) == context, "相同快照改变了会话身份")
            var deliveries = 0
            let operation = runtime.startDiagnostics(configuration: configuration) { _ in deliveries += 1 }
            try require(listener.starts == (expected == .listener ? 1 : 0)
                && enhanced.starts == (expected == .enhanced ? 1 : 0), "启动未准确调用唯一已有核心")
            if expected != .unavailable {
                let selected = expected == .listener ? listener : enhanced
                selected.deliver(sample)
                try require(deliveries == 1, "当前核心有效回调未交付")
                operation.cancel()
                selected.deliver(terminal)
                try require(deliveries == 1 && selected.cancellations[0].value == 1,
                    "停止未同步清理子请求或仍接受迟到回调")
            } else {
                // This creates only the operation-free unavailable snapshot,
                // then revokes it before its queued main callback can run.
                operation.cancel()
                try require(deliveries == 0, "无核心时产生了伪造检测结果")
            }
        }

        for phase in [RuntimePhase.stopped, .starting, .stopping, .failed] {
            let listener = owner(true), enhanced = owner(true, phase: phase)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let context = runtime.context(configuration: configuration)
            try require(context.backend == .enhanced && !context.engineRunning
                && context.enhancedMode, "未就绪的保留增强会话回退到 listener")
            let operation = runtime.startDiagnostics(configuration: configuration) { _ in }
            try require(listener.starts == 0 && enhanced.starts == 0,
                "未就绪时仍启动检测或使用另一核心")
            enhanced.value.endpoint.phase = .running
            enhanced.value.lifecycleRevision &+= 1
            let ready = runtime.context(configuration: configuration)
            try require(ready.backend == .enhanced && ready.engineRunning
                && ready.runtimeSessionID != context.runtimeSessionID && operation.isCancelled,
                "增强就绪后未换代并撤销旧请求")
        }

        let changes: [(String, (inout NetworkDiagnosticsConfiguration) -> Void)] = [
            ("mode", { $0.mode = "全局代理" }),
            ("policy", { $0.selectedPolicy = "another-private-policy" }),
            ("groups", { $0.groupSelections["private-group"] = "another-private-node" }),
            ("profile", { $0.profileRevision &+= 1 }),
            ("systemProxy", { $0.systemProxy.toggle() })
        ]
        for (name, change) in changes {
            let listener = owner(true), enhanced = owner(true)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let original = runtime.context(configuration: configuration)
            var oldDeliveries = 0, newDeliveries = 0
            let old = runtime.startDiagnostics(configuration: configuration) { _ in oldDeliveries += 1 }
            enhanced.deliver(sample)
            try require(oldDeliveries == 1, "\(name) 前的有效回调未交付")
            var updated = configuration
            change(&updated)
            let changed = runtime.context(configuration: updated)
            try require(changed.runtimeSessionID != original.runtimeSessionID
                && changed.runtimeRevision != original.runtimeRevision, "\(name) 变化未生成新上下文")
            try require(old.isCancelled && enhanced.cancellations[0].value == 1,
                "\(name) 变化未同步撤销旧子请求")
            enhanced.deliver(terminal)
            try require(oldDeliveries == 1, "\(name) 变化后回填旧结果")
            let current = runtime.startDiagnostics(configuration: updated) { _ in newDeliveries += 1 }
            enhanced.deliver(sample, at: 1)
            try require(newDeliveries == 1 && !current.isCancelled && listener.starts == 0,
                "\(name) 后新会话未使用增强核心")
            try require(runtime.context(configuration: updated) == changed
                && !current.isCancelled, "\(name) 相同配置刷新错误换代")
            old.cancel()
            try require(enhanced.cancellations[0].value == 1, "\(name) 重复取消重复清理")
            current.cancel()
        }

        do {
            let listener = owner(false), enhanced = owner(true)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let before = runtime.context(configuration: configuration)
            var deliveries = 0
            let operation = runtime.startDiagnostics(configuration: configuration) { _ in deliveries += 1 }
            enhanced.value.endpoint.boundInterfaceName = "en-rebound-fixture"
            let after = runtime.context(configuration: configuration)
            enhanced.deliver(sample)
            try require(after.boundInterfaceName == "en-rebound-fixture"
                && after.runtimeSessionID != before.runtimeSessionID, "接口变化未刷新出口和会话身份")
            try require(operation.isCancelled && enhanced.cancellations[0].value == 1
                && deliveries == 0, "旧物理接口请求仍可交付")
        }

        do {
            let listener = owner(false)
            let enhanced = owner(true, startedAt: Date(timeIntervalSince1970: 1))
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let before = runtime.context(configuration: configuration)
            var deliveries = 0
            let operation = runtime.startDiagnostics(configuration: configuration) { _ in deliveries += 1 }
            enhanced.value.startedAt = Date(timeIntervalSince1970: 2)
            let after = runtime.context(configuration: configuration)
            enhanced.deliver(sample)
            try require(after.engineRunning && after.backend == .enhanced
                && after.runtimeSessionID != before.runtimeSessionID,
                "同 phase 的新增强实例未换代")
            try require(operation.isCancelled && enhanced.cancellations[0].value == 1
                && deliveries == 0, "startedAt 变化未撤销旧实例结果")
        }

        for backend in [NetworkRuntimeBackend.listener, .enhanced] {
            let listener = owner(backend == .listener), enhanced = owner(backend == .enhanced)
            let selected = backend == .listener ? listener : enhanced
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let original = runtime.context(configuration: configuration)
            var deliveries = 0
            let old = runtime.startDiagnostics(configuration: configuration) { _ in deliveries += 1 }
            selected.value.lifecycleRevision &+= 1
            let restarted = runtime.context(configuration: configuration)
            selected.deliver(sample)
            try require(restarted.engineRunning && restarted.backend == backend
                && restarted.runtimeSessionID != original.runtimeSessionID,
                "\(backend) 同状态重启未换代")
            try require(old.isCancelled && deliveries == 0 && selected.cancellations[0].value == 1,
                "\(backend) 同状态重启后旧回调仍有效")
            try require(runtime.context(configuration: configuration) == restarted,
                "\(backend) 重复相同状态造成额外换代")
        }

        do {
            let listener = owner(false), enhanced = owner(true)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            enhanced.inlineSnapshot = sample
            var deliveries = 0
            let operation = runtime.startDiagnostics(configuration: configuration) { _ in deliveries += 1 }
            try require(deliveries == 1 && !operation.isCancelled,
                "provider 在返回句柄前的同步回调丢失")
            operation.cancel()
            try require(enhanced.cancellations[0].value == 1, "同步回调路径未清理子句柄")
        }

        do {
            let listener = owner(false), enhanced = owner(true)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            enhanced.beforeReturn = { [weak runtime, weak enhanced] in
                guard let runtime, let enhanced else { return }
                enhanced.value.lifecycleRevision &+= 1
                _ = runtime.context(configuration: configuration)
            }
            var deliveries = 0
            let operation = runtime.startDiagnostics(configuration: configuration) { _ in deliveries += 1 }
            enhanced.beforeReturn = nil
            enhanced.deliver(sample)
            try require(operation.isCancelled && enhanced.cancellations[0].value == 1
                && deliveries == 0, "provider 返回前换代未取消晚到句柄")
        }

        do {
            let listener = owner(false), enhanced = owner(true)
            var runtime: AppNetworkRuntime? = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            weak var weakRuntime = runtime
            var deliveries = 0
            let first = runtime!.startDiagnostics(configuration: configuration) { _ in deliveries += 1 }
            let second = runtime!.startDiagnostics(configuration: configuration) { _ in deliveries += 1 }
            runtime = nil
            enhanced.deliver(sample, at: 0)
            enhanced.deliver(sample, at: 1)
            try require(weakRuntime == nil && first.isCancelled && second.isCancelled,
                "适配层存在保留环或析构未撤销子请求")
            try require(enhanced.cancellations.map(\.value) == [1, 1] && deliveries == 0,
                "析构后子请求未恰好清理一次或仍交付")
        }

        do {
            let listener = owner(false), enhanced = owner(true)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let context = runtime.context(configuration: configuration)
            guard let id = context.runtimeSessionID,
                  let report = NetworkDiagnosticsSummary.report(context: context, local: nil,
                    connectivity: terminal, performance: NetworkPerformanceSnapshot()),
                  let object = try JSONSerialization.jsonObject(with: Data(report.utf8)) as? [String: Any],
                  let encodedRuntime = object["runtime"] as? [String: Any] else {
                throw Failure(text: "真实适配层上下文无法生成报告")
            }
            try require(encodedRuntime["diagnosticsBackend"] as? String == "enhanced"
                && encodedRuntime["engineRunning"] as? Bool == true, "报告丢失实际核心或就绪状态")
            try require(!report.contains(id.uuidString) && !report.contains("runtimeSessionID")
                && !report.contains("runtimeRevision") && !report.contains("runtimeBackend"),
                "报告导出内部会话身份或协调元数据")
            try require(!report.contains(configuration.selectedPolicy)
                && !report.contains("private-group") && !report.contains("private-node"),
                "报告导出策略或节点原名")
        }
        assertions += try connectionPresentationChecks()
        print("App network runtime self-test passed: \(assertions) assertions; capture/route presentation, owner selection, readiness, configuration epochs, restart, interface, callback cancellation and report privacy; no network operations")
    }

    private static func connectionPresentationChecks() throws -> Int {
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw Failure(text: text) }
        }
        func owner(_ phase: RuntimePhase, present: Bool) -> Owner {
            Owner(AppRuntimeOwnerSnapshot(endpoint: RuntimeEndpointState(phase: phase, isPresent: present),
                lifecycleRevision: 0))
        }
        for mode in OutboundMode.allCases {
            let route = mode == .direct ? "直连" : mode.displayName
            let listener = owner(.stopped, present: false), enhanced = owner(.stopped, present: false)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let direct = runtime.connectionPresentation(mode: mode, systemProxyEnabled: false)
            try require(direct.title == "直连模式" && direct.tone == .neutral,
                "\(mode) 未接管时错误地声称已代理或全停")
            listener.value.endpoint = RuntimeEndpointState(phase: .running, isPresent: true)
            runtime.observe(listenerStatus: .running)
            let optional = runtime.connectionPresentation(mode: mode, systemProxyEnabled: false)
            try require(optional.title == direct.title && optional.tone == .neutral
                && optional.detail.contains("手动使用"), "本地入口开关错误地决定主页连接模式")
            let proxy = runtime.connectionPresentation(mode: mode, systemProxyEnabled: true)
            try require(proxy.title == "代理模式 · \(route)" && proxy.tone == .active,
                "\(mode) 已就绪的系统代理未表达有效出站模式")
            enhanced.value.endpoint = RuntimeEndpointState(phase: .running, isPresent: true)
            runtime.observe(enhancedStatus: .running(interface: "utun-fixture", physicalInterface: "en-fixture"))
            for systemProxy in [false, true] {
                for listenerPresent in [false, true] {
                    listener.value.endpoint = RuntimeEndpointState(phase: listenerPresent ? .running : .stopped,
                        isPresent: listenerPresent)
                    let value = runtime.connectionPresentation(mode: mode, systemProxyEnabled: systemProxy)
                    try require(value.title == "增强模式 · \(route)" && value.tone == .active,
                        "\(mode) 增强就绪被本地入口或系统代理开关覆盖")
                    try require(!value.title.contains("停止") && value.detail.contains("已就绪"),
                        "增强运行被显示为停止，或缺少已就绪证据")
                }
            }
            try require(listener.starts == 0 && enhanced.starts == 0,
                "主页状态观察启动了诊断 IO")
        }
        for (phase, present, expected, tone) in [
            (RuntimePhase.starting, false, "增强模式正在启动", AppConnectionPresentation.Tone.pending),
            (.starting, true, "增强模式正在启动", .pending),
            (.stopping, true, "增强模式正在停止", .pending),
            (.failed, true, "增强模式异常", .failure),
            (.stopped, true, "增强模式尚未就绪", .pending)
        ] {
            let listener = owner(.running, present: true), enhanced = owner(phase, present: present)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let value = runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: true)
            try require(value.title == expected && value.tone == tone,
                "增强\(phase)错误回退成监听器运行或已停止")
        }
        for mode in OutboundMode.allCases {
            let listener = owner(.stopped, present: false), enhanced = owner(.stopped, present: false)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            runtime.observe(enhancedStatus: .waitingForNetwork("等待 Wi-Fi 网关"))
            let waiting = runtime.connectionPresentation(mode: mode, systemProxyEnabled: false,
                enhancedRequested: true)
            try require(waiting.title == "增强模式等待网络恢复" && waiting.tone == .pending
                && waiting.detail == "等待 Wi-Fi 网关", "持续开启但无资源被伪报为已连通或直连")
            let configuration = NetworkDiagnosticsConfiguration(mode: mode.rawValue, selectedPolicy: "sample",
                groupSelections: [:], profileRevision: 1, systemProxy: false)
            try require(!runtime.context(configuration: configuration).engineRunning,
                "用户开启意图被误当成真实网络就绪")
            runtime.observe(enhancedStatus: .failed("安全恢复尚未确认"))
            let blocked = runtime.connectionPresentation(mode: mode, systemProxyEnabled: false,
                enhancedRequested: true)
            try require(blocked.tone == .failure && blocked.detail.contains("安全恢复尚未确认"),
                "持续开启意图隐藏了实际恢复错误")
            runtime.observe(enhancedStatus: .starting)
            enhanced.value.endpoint = RuntimeEndpointState(phase: .starting, isPresent: true)
            try require(runtime.connectionPresentation(mode: mode, systemProxyEnabled: false,
                enhancedRequested: true).title == "增强模式正在启动", "新会话正在启动仍被显示为旧错误")
            enhanced.value.endpoint = RuntimeEndpointState(phase: .running, isPresent: true)
            runtime.observe(enhancedStatus: .running(interface: "utun-new", physicalInterface: "en-fixture"))
            try require(runtime.connectionPresentation(mode: mode, systemProxyEnabled: false,
                enhancedRequested: true).tone == .active, "新的真实运行结果未清除等待")
            enhanced.value.endpoint = .stopped
            runtime.observe(enhancedStatus: .waitingForNetwork("迟到等待通知"))
            try require(runtime.connectionPresentation(mode: mode, systemProxyEnabled: false).title == "直连模式",
                "已撤销意图被迟到等待通知重新激活")
        }
        do {
            let listener = owner(.stopped, present: false), enhanced = owner(.stopped, present: false)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            let pending = runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: false,
                enhancedRequestPending: true)
            try require(pending.title == "增强模式正在启动" && pending.tone == .pending,
                "RULE-SET 准备阶段被显示为已连接或停止")
            let cancelled = runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: false)
            try require(cancelled.title == "直连模式" && cancelled.tone == .neutral,
                "未取得资源的增强取消未回归实际模式")
            runtime.observe(enhancedStatus: .failed("controlled prepare failure"))
            let failed = runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: false)
            try require(failed.title == "直连模式 · 有异常" && failed.tone == .warning
                && failed.toolTip.contains("controlled prepare failure"), "取得资源前的增强失败丢失原始原因")
            runtime.observe(enhancedStatus: .starting)
            let retry = runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: false,
                enhancedRequestPending: true)
            try require(retry.tone == .pending && !retry.toolTip.contains("controlled prepare failure"),
                "重试仍残留旧增强错误")
        }
        do {
            let listener = owner(.failed, present: false), enhanced = owner(.running, present: true)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            runtime.observe(listenerStatus: .failed("controlled listener failure"))
            let running = runtime.connectionPresentation(mode: .rule, systemProxyEnabled: false)
            try require(running.title == "增强模式 · 规则" && running.tone == .warning
                && running.toolTip.contains("controlled listener failure"),
                "本地入口失败覆盖了仍正常运行的增强，或错误原因不可见")
            enhanced.value.endpoint = .stopped
            runtime.observe(enhancedStatus: .failed("controlled enhanced failure"))
            listener.value.endpoint = RuntimeEndpointState(phase: .running, isPresent: true)
            runtime.observe(listenerStatus: .running)
            let fallback = runtime.connectionPresentation(mode: .direct, systemProxyEnabled: true)
            try require(fallback.title == "代理模式 · 直连" && fallback.tone == .warning
                && fallback.toolTip.contains("controlled enhanced failure"),
                "资源已释放的增强失败隐藏了有效系统代理或残留错误")
            runtime.observe(enhancedStatus: .stopped)
            let restored = runtime.connectionPresentation(mode: .direct, systemProxyEnabled: true)
            try require(restored.tone == .active && !restored.toolTip.contains("controlled enhanced failure"),
                "已确认增强清理仍残留旧失败提示")
        }
        // Core starts HTTP and SOCKS together and attests running only after
        // both listeners are ready. A partially-ready listener owner remains
        // starting; the presentation must not invent readiness for either port.
        for present in [false, true] {
            let listener = owner(.starting, present: present), enhanced = owner(.stopped, present: false)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            try require(runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: true).tone == .pending,
                "双入口尚未全就绪时错误宣告代理运行")
            try require(runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: false).title == "直连模式",
                "可选入口准备改变了机器的实际接管模式")
        }
        do {
            let listener = owner(.running, present: false), enhanced = owner(.running, present: false)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            try require(runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: true).tone == .failure,
                "没有owner的running标签被误当成实际可用代理")
            enhanced.value.endpoint = RuntimeEndpointState(phase: .failed, isPresent: true)
            runtime.observe(enhancedStatus: .failed("cleanup pending"))
            let retained = runtime.connectionPresentation(mode: .direct, systemProxyEnabled: false)
            try require(retained.title == "增强模式异常" && retained.tone == .failure
                && retained.toolTip.contains("cleanup pending"), "恢复未确认时错误宣告安全直连")
        }
        do {
            let listener = owner(.running, present: true), enhanced = owner(.stopped, present: false)
            let runtime = AppNetworkRuntime(listener: listener, enhanced: enhanced)
            for snapshotExists in [false, true] {
                let pending = runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: snapshotExists,
                    systemProxyChanging: true)
                try require(pending.title == "代理模式切换中" && pending.tone == .pending,
                    "系统代理命令未完成时把提前保存的快照误作已接管")
            }
            runtime.observe(systemProxyResult: .failure(Failure(text: "partial system proxy restoration")))
            let failed = runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: true)
            try require(failed.title == "代理模式异常" && failed.tone == .failure
                && failed.toolTip.contains("partial system proxy restoration"), "部分恢复失败后快照仍在却误报代理已接管")
            let noSnapshot = runtime.connectionPresentation(mode: .proxy, systemProxyEnabled: false)
            try require(noSnapshot.tone == .warning && noSnapshot.toolTip.contains("partial system proxy restoration"),
                "失败后无快照时隐藏系统代理错误")
            enhanced.value.endpoint = RuntimeEndpointState(phase: .running, isPresent: true)
            let protected = runtime.connectionPresentation(mode: .direct, systemProxyEnabled: true,
                systemProxyChanging: true)
            try require(protected.title == "增强模式 · 直连" && protected.tone == .warning,
                "可用增强模式被系统代理切换/失败覆盖")
            runtime.observe(systemProxyResult: .success(()))
            let confirmed = runtime.connectionPresentation(mode: .direct, systemProxyEnabled: false)
            try require(confirmed.title == "增强模式 · 直连" && confirmed.tone == .active
                && !confirmed.toolTip.contains("partial system proxy restoration"), "系统代理成功恢复后仍残留失败闩锁")
        }
        print("App connection presentation self-test passed: \(assertions) assertions; capture, route, optional listeners, readiness, retry, cancellation and retained-failure matrix; memory owners only")
        return assertions
    }

    private static func snapshot(isRunning: Bool) throws -> NetworkConnectivityDiagnosticsSnapshot {
        try JSONDecoder().decode(NetworkConnectivityDiagnosticsSnapshot.self, from: Data("""
            {"id":"11111111-2222-3333-4444-555555555555","startedAt":0,"updatedAt":1,
             "isRunning":\(isRunning),"omittedEndpointCount":0,"rows":[]}
            """.utf8))
    }
}

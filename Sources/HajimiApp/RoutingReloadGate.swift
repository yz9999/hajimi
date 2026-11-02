import Foundation
import HajimiCore
import HajimiRuntime

/// A queue-confined application gate, not routing or resolver authority.
/// Configuration equality is structural: no credential-bearing signature is
/// persisted, logged or shared with diagnostics. Real changes still take the
/// existing policy invalidation and flow-reset path.
final class RoutingReloadGate {
    struct Configuration: Equatable {
        var profile: Profile
        var mode: OutboundMode
        var globalPolicy: String
        var groupSelections: [String: String]
    }

    enum Decision: Equatable {
        case unchanged
        case unrelatedSelections
        case reload
    }

    private(set) var applied: Configuration?
    private let reloadState = RuntimeReloadState()
    var needsRecovery: Bool { reloadState.needsRecovery }

    func decision(for next: Configuration) -> Decision {
        guard !needsRecovery, let applied else { return .reload }
        return Self.decision(previous: applied, next: next)
    }

    /// Mark the attempt dirty before invoking any partial external work. A
    /// throwing reload must not make a same-configuration retry or rollback a
    /// no-op. The closure executes synchronously on the owner's queue.
    @discardableResult
    func apply(_ next: Configuration, reload: () throws -> Void) rethrows -> Bool {
        try reloadState.apply(requiresReload: decision(for: next) == .reload, reload: reload) {
            applied = next
        }
    }

    /// A successful start establishes the actual routing baseline separately
    /// from a reload. A stop discards it, so the next start cannot be skipped.
    func recordApplied(_ configuration: Configuration) {
        reloadState.recordApplied { applied = configuration }
    }

    func reset() {
        reloadState.reset { applied = nil }
    }

    static func decision(previous: Configuration, next: Configuration) -> Decision {
        if previous == next { return .unchanged }
        // Profile includes all node parameters/credentials/chains, loaded
        // rules, DNS settings, listener and system-route settings. Comparing a
        // node name alone would silently retain an obsolete safety snapshot.
        guard previous.profile == next.profile,
              previous.mode == next.mode,
              previous.globalPolicy == next.globalPolicy,
              next.mode == .proxy,
              next.profile.groups[next.globalPolicy] == nil,
              let root = next.profile.proxies[next.globalPolicy] else { return .reload }
        switch root.kind {
        case .http, .socks5, .native: break
        case .direct, .reject, .external: return .reload
        }

        let changed = Set(previous.groupSelections.keys).union(next.groupSelections.keys)
            .filter { previous.groupSelections[$0] != next.groupSelections[$0] }
        guard !changed.isEmpty,
              let dependencies = relevantGroups(profile: next.profile,
                                                globalPolicy: next.globalPolicy,
                                                changed: changed,
                                                previous: previous.groupSelections,
                                                next: next.groupSelections),
              dependencies.isDisjoint(with: changed) else { return .reload }
        return .unrelatedSelections
    }

    private static func relevantGroups(profile: Profile, globalPolicy: String,
                                       changed: Set<String>, previous: [String: String],
                                       next: [String: String]) -> Set<String>? {
        var groups = Set<String>(), visiting = Set<String>(), complete = Set<String>()
        var visits = 0
        func canonicalName(_ name: String) -> String {
            if profile.groups[name] != nil || profile.proxies[name] != nil { return name }
            if name.uppercased() == "DIRECT" { return "DIRECT" }
            if name.uppercased().hasPrefix("REJECT") { return "REJECT" }
            return name
        }
        func visit(_ raw: String, depth: Int = 0) -> Bool {
            // A malformed/cyclic/very large graph is not proof of irrelevance.
            guard depth < 32, visits < 4096 else { return false }
            visits += 1
            let name = canonicalName(raw)
            if complete.contains(name) { return true }
            guard visiting.insert(name).inserted else { return false }
            defer { visiting.remove(name) }
            if let group = profile.groups[name] {
                guard !group.members.isEmpty else { return false }
                groups.insert(name)
                // Expand every member, including dormant and balanced paths;
                // never infer safety from the currently selected leaf alone.
                for member in group.members where !visit(member, depth: depth + 1) { return false }
            } else if let proxy = profile.proxies[name] {
                for key in ["underlying-proxy", "underlying_proxy", "dialer-proxy"] {
                    if let carrier = proxy.parameters[key], !visit(carrier, depth: depth + 1) { return false }
                }
            } else { return false }
            complete.insert(name)
            return true
        }

        guard visit(globalPolicy) else { return nil }
        // DNS original/QNAME/resolver preflight consults rule-mode REJECT even
        // in global proxy mode. Every rule action therefore remains relevant.
        for rule in profile.rules where !visit(rule.policy) { return nil }
        let relevant = groups
        // Invalid or stale changed-group metadata is handled conservatively,
        // even if that group is not currently referenced by a traffic root.
        for name in changed {
            guard let group = profile.groups[name], !group.members.isEmpty,
                  previous[name].map(group.members.contains) ?? true,
                  next[name].map(group.members.contains) ?? true,
                  visit(name) else { return nil }
        }
        return relevant
    }
}

/// Pure configuration and synchronous-memory actions only: no AppKit view,
/// user profile, listener, helper, route, resolver or outbound is constructed.
enum RoutingReloadGateSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "路由重载门控自检失败：\(text)" }
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ text: String) throws {
        if !condition() { throw Failure(text: text) }
    }

    private static func profile() -> Profile {
        var profile = Profile()
        for (index, name) in ["Pinned", "A", "B"].enumerated() {
            profile.proxies[name] = ProxyPolicy(name: name, kind: .native,
                host: "203.0.113.\(10 + index)", port: 443,
                adapterType: "vmess", parameters: ["uuid": "memory-fixture-v1"])
        }
        profile.groups["Unused"] = PolicyGroup(name: "Unused", kind: .urlTest, members: ["A", "B"])
        profile.groups["Referenced"] = PolicyGroup(name: "Referenced", members: ["A", "B"])
        profile.rules = [RoutingRule(kind: .final, policy: "Pinned", sourceLine: 1)]
        return profile
    }

    private static func configuration(_ profile: Profile = profile()) -> RoutingReloadGate.Configuration {
        RoutingReloadGate.Configuration(profile: profile, mode: .proxy, globalPolicy: "Pinned",
                                        groupSelections: ["Unused": "A", "Referenced": "A"])
    }

    static func run() throws {
        try equivalentAndUnrelatedSelections()
        try materialConfigurationChanges()
        try relevantAndInvalidDependencies()
        try failedReloadAndLifecycle()
        try reentrantReloadLifecycle()
    }

    private static func equivalentAndUnrelatedSelections() throws {
        let gate = RoutingReloadGate(), first = configuration()
        var routerUpdates = 0, factoryConfigurations = 0, flowResets = 0, helperReloads = 0
        func reload() {
            routerUpdates += 1; factoryConfigurations += 1; flowResets += 1; helperReloads += 1
        }
        try expect(gate.apply(first, reload: reload), "首次配置未执行真正重载")
        try expect(!gate.apply(first, reload: reload), "完全等价配置仍重置连接")
        var next = first; next.groupSelections["Unused"] = "B"
        try expect(gate.decision(for: next) == .unrelatedSelections
                   && !gate.apply(next, reload: reload) && gate.applied == next,
                   "固定节点下无关自动组仍执行外部动作或丢失最新选择")
        next.groupSelections.removeValue(forKey: "Unused")
        try expect(!gate.apply(next, reload: reload), "无关组恢复默认选择仍重置连接")
        try expect(routerUpdates == 1 && factoryConfigurations == 1 && flowResets == 1 && helperReloads == 1,
                   "等价/无关组更新触碰 DNS/mux/长连接/helper")
        next.globalPolicy = "Unused"
        try expect(gate.apply(next, reload: reload) && flowResets == 2,
                   "后续真正选择该组时没有提交完整最新选择")
    }

    private static func materialConfigurationChanges() throws {
        let first = configuration()
        let edits: [(inout Profile) -> Void] = [
            { $0.proxies["Pinned"]?.host = "203.0.113.99" },
            { $0.proxies["Pinned"]?.port = 8443 },
            { $0.proxies["Pinned"]?.username = "memory-user-v2" },
            { $0.proxies["Pinned"]?.password = "memory-secret-v2" },
            { $0.proxies["Pinned"]?.parameters["uuid"] = "memory-fixture-v2" },
            { $0.proxies["Pinned"]?.parameters["underlying-proxy"] = "A" },
            { $0.proxies["Pinned"]?.parameters["skip-cert-verify"] = "true" },
            { $0.proxies["Pinned"]?.adapterType = "trojan" },
            { $0.proxies["A"]?.parameters["uuid"] = "memory-dormant-v2" },
            { $0.dnsServers = ["192.0.2.53"] },
            { $0.encryptedDNSServers = ["https://dns.memory.invalid/dns-query#192.0.2.54"] },
            { $0.dnsLeakProtectionEnabled = false },
            { $0.dnsSelectionMode = .encryptedOnly },
            { $0.dnsPrewarmEnabled = false },
            { $0.fakeIPEnabled = true },
            { $0.alwaysRealIP = ["googlevideo.com"] },
            { $0.hijackDNS = ["*:53"] },
            { $0.rules = [RoutingRule(kind: .domainSuffix("googlevideo.com"), policy: "REJECT", sourceLine: 2)] },
            { $0.ruleSetContents["memory.rules"] = [.domainSuffix("youtube.com")] },
            { $0.groups["Unused"]?.members = ["A", "REJECT"] },
            { $0.tunExcludedRoutes = ["192.0.2.0/24"] },
            { $0.tunIncludedRoutes = ["0.0.0.0/1"] },
            { $0.proxyBypassDomains = ["localhost"] },
            { $0.httpListen.port = 8262 }
        ]
        for (index, edit) in edits.enumerated() {
            var next = first; edit(&next.profile)
            try expect(RoutingReloadGate.decision(previous: first, next: next) == .reload,
                       "完整配置字段变化被误忽略（用例 \(index)）")
        }
        for mode in [OutboundMode.rule, .direct] {
            var next = first; next.mode = mode
            try expect(RoutingReloadGate.decision(previous: first, next: next) == .reload, "模式变化被忽略")
            var later = next; later.groupSelections["Unused"] = "B"
            try expect(RoutingReloadGate.decision(previous: next, next: later) == .reload,
                       "非固定节点 proxy 模式擅自忽略组变化")
        }
        var next = first; next.globalPolicy = "B"
        try expect(RoutingReloadGate.decision(previous: first, next: next) == .reload, "同种出站的全局节点变更被忽略")
    }

    private static func relevantAndInvalidDependencies() throws {
        func mustReload(_ profile: Profile, changed: String = "Unused", member: String = "B",
                        globalPolicy: String = "Pinned") throws {
            var first = configuration(profile); first.globalPolicy = globalPolicy
            var next = first; next.groupSelections[changed] = member
            try expect(RoutingReloadGate.decision(previous: first, next: next) == .reload,
                       "可达、未知、空、循环或 REJECT 相关组变化被误忽略")
        }
        var directRule = profile()
        directRule.rules.insert(RoutingRule(kind: .domainSuffix("googlevideo.com"), policy: "Referenced", sourceLine: 2), at: 0)
        try mustReload(directRule, changed: "Referenced")
        directRule.groups["Top"] = PolicyGroup(name: "Top", members: ["Referenced", "Pinned"])
        directRule.rules[0].policy = "Top"
        try mustReload(directRule, changed: "Referenced")
        directRule.groups["Referenced"]?.members.append("REJECT")
        try mustReload(directRule, changed: "Referenced", member: "REJECT")

        for key in ["underlying-proxy", "underlying_proxy", "dialer-proxy"] {
            var chained = profile(); chained.proxies["Pinned"]?.parameters[key] = "Unused"
            try mustReload(chained)
        }
        try mustReload(profile(), globalPolicy: "Referenced")
        var invalid = profile(); invalid.rules[0].policy = "Missing"
        try mustReload(invalid)
        invalid = profile(); invalid.groups["Empty"] = PolicyGroup(name: "Empty", members: [])
        invalid.rules[0].policy = "Empty"; try mustReload(invalid)
        invalid = profile(); invalid.groups["LoopA"] = PolicyGroup(name: "LoopA", members: ["LoopB"])
        invalid.groups["LoopB"] = PolicyGroup(name: "LoopB", members: ["LoopA"])
        invalid.rules[0].policy = "LoopA"; try mustReload(invalid)
        invalid = profile(); invalid.proxies["Pinned"]?.parameters["underlying-proxy"] = "A"
        invalid.proxies["A"]?.parameters["dialer-proxy"] = "Pinned"; try mustReload(invalid)
        invalid = profile(); invalid.groups["Unused"]?.members.append("Missing")
        try mustReload(invalid)
        try mustReload(profile(), changed: "Missing")
        try mustReload(profile(), member: "Missing")
        invalid = profile()
        for index in 0..<40 {
            invalid.groups["Deep\(index)"] = PolicyGroup(name: "Deep\(index)",
                members: index == 39 ? ["Pinned"] : ["Deep\(index + 1)"])
        }
        invalid.rules[0].policy = "Deep0"; try mustReload(invalid)
    }

    private static func failedReloadAndLifecycle() throws {
        let gate = RoutingReloadGate(), first = configuration()
        gate.recordApplied(first)
        var next = first; next.globalPolicy = "B"
        var attempts = 0
        do {
            try gate.apply(next) {
                attempts += 1
                throw Failure(text: "expected memory reload failure")
            }
            throw Failure(text: "失败动作未抛错")
        } catch let error as Failure {
            try expect(error.text == "expected memory reload failure", "错误分类不符")
        }
        try expect(gate.applied == first && gate.needsRecovery && gate.decision(for: first) == .reload,
                   "部分失败后的等价 rollback 被判 no-op")
        try expect(gate.apply(first) { attempts += 1 } && !gate.needsRecovery && attempts == 2,
                   "失败恢复没有执行真正动作或成功后仍 dirty")
        try expect(!gate.apply(first) { attempts += 1 }, "恢复成功后等价配置仍重载")
        gate.reset()
        try expect(gate.applied == nil && gate.decision(for: first) == .reload,
                   "stop 后仍沿用旧运行会话基线")
        gate.recordApplied(first)
        try expect(!gate.apply(first) { attempts += 1 } && attempts == 2,
                   "成功 start 未建立正确基线")
    }

    private static func reentrantReloadLifecycle() throws {
        let gate = RoutingReloadGate(), first = configuration()
        var next = first; next.globalPolicy = "B"
        var newer = first; newer.globalPolicy = "A"
        gate.recordApplied(first)
        var calls = 0
        try gate.apply(next) {
            calls += 1
            try expect(gate.needsRecovery && gate.applied == first,
                       "真实 reload 动作前没有保留旧基线并置 dirty")
            // EnhancedModeManager's successful reload performs this same
            // synchronous same-configuration record before apply returns.
            gate.recordApplied(next)
            try expect(!gate.needsRecovery && gate.applied == next,
                       "同配置重入提交没有建立真实成功基线")
        }
        try expect(gate.applied == next && !gate.needsRecovery && calls == 1
                   && !gate.apply(next) { calls += 1 }, "真实管理器的同配置重入成功行为改变")

        gate.recordApplied(first)
        gate.apply(next) { gate.reset() }
        try expect(gate.applied == nil && !gate.needsRecovery && gate.decision(for: first) == .reload,
                   "外层旧 reload 覆盖了重入 stop 的清理基线")
        gate.recordApplied(first)
        gate.apply(next) { gate.recordApplied(newer) }
        try expect(gate.applied == newer && !gate.needsRecovery,
                   "外层旧 reload 覆盖了新 start 的成功基线")

        gate.recordApplied(first)
        try gate.apply(next) {
            try expect(gate.apply(newer) { calls += 1 }, "重入新配置没有执行同步 reload")
        }
        try expect(gate.applied == newer && !gate.needsRecovery,
                   "外层旧 reload 覆盖了内层新 reload 的提交")

        gate.recordApplied(first)
        try gate.apply(next) {
            do {
                try gate.apply(newer) { throw Failure(text: "expected nested reload failure") }
                throw Failure(text: "重入失败动作未抛错")
            } catch let error as Failure {
                try expect(error.text == "expected nested reload failure", "重入错误被替换")
            }
        }
        try expect(gate.applied == first && gate.needsRecovery && gate.decision(for: first) == .reload,
                   "外层旧 reload 清除了重入新失败的恢复要求")
        try expect(gate.apply(first) { calls += 1 } && !gate.needsRecovery,
                   "重入失败后 rollback 没有执行实际恢复")
        var unrelated = first; unrelated.groupSelections["Unused"] = "B"
        try expect(!gate.apply(unrelated) { calls += 1 } && gate.applied == unrelated,
                   "恢复后无关组选择没有保留完整最新基线")
        gate.reset()
        try expect(gate.apply(unrelated) { calls += 1 } && gate.applied == unrelated && !gate.needsRecovery,
                   "重入 stop/start 后等价配置被错误跳过")
    }
}

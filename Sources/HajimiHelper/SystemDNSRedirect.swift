import Foundation
import Darwin
import Security
import HajimiIPC

/// DNS configuration is a verified transaction, not a best-effort loop.
/// All effects are injected so failures and rollback can be exercised without
/// creating a helper, a tunnel, or running `networksetup`.
enum SystemDNSRedirectTransaction {
    static func enabledServices(from output: String) throws -> [String] {
        let lines = output.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard let first = lines.first,
              first.lowercased().contains("asterisk") || first.contains("星号") else {
            throw HelperServiceError.command("无法确认 networksetup 的网络服务列表")
        }
        var seen = Set<String>()
        let services = lines.dropFirst().filter {
            !$0.hasPrefix("*") && seen.insert($0).inserted
        }
        guard !services.isEmpty else {
            throw HelperServiceError.command("没有可验证的已启用网络服务，拒绝声明 DNS 保护已就绪")
        }
        return Array(services)
    }

    static func servers(from output: String) throws -> [String] {
        let lines = output.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        if lines.count == 1, lines[0].contains("aren't any DNS Servers") { return [] }
        guard !lines.isEmpty, lines.allSatisfy({ value in
            var v4 = in_addr()
            if value.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return true }
            let address = value.split(separator: "%", maxSplits: 1).first.map(String.init) ?? value
            var v6 = in6_addr()
            return address.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1
        }) else {
            throw HelperServiceError.command("无法验证 networksetup 返回的 DNS 配置")
        }
        return lines
    }

    static func install(services: [String], sink: String,
                        saved: inout [String: [String]],
                        read: (String) throws -> [String],
                        write: (String, [String]) throws -> Void) throws {
        guard !services.isEmpty else {
            throw HelperServiceError.command("没有可验证的已启用网络服务")
        }
        var originals: [String: [String]] = [:]
        var verified = Set<String>()
        // Read all originals before the first mutation. A failed snapshot may
        // never silently leave that service using plaintext system DNS.
        for service in services {
            let current = try read(service)
            if current == [sink] {
                guard saved[service] != nil else {
                    throw HelperServiceError.command(
                        "网络服务 \(service) 已指向 Hajimi DNS，但没有可恢复的原始配置")
                }
                verified.insert(service)
            }
            originals[service] = current
        }
        for service in services {
            guard let previous = originals[service] else { continue }
            if previous == [sink] { continue }
            // Record BEFORE setting: a timeout can occur after macOS changed
            // the setting. The caller publishes this inventory even on throw.
            saved[service] = previous
            try write(service, [sink])
            guard try read(service) == [sink] else {
                throw HelperServiceError.command("网络服务 \(service) 的 DNS 重定向读回校验失败")
            }
            verified.insert(service)
        }
        // Recheck any service not yet verified in this transaction.
        for service in services where !verified.contains(service) {
            guard try read(service) == [sink] else {
                throw HelperServiceError.command("网络服务 \(service) 尚未受到 Hajimi DNS 保护")
            }
        }
    }

    static func restore(sink: String, saved: [String: [String]],
                        read: (String) throws -> [String],
                        write: (String, [String]) throws -> Void) -> [String: [String]] {
        var pending: [String: [String]] = [:]
        for service in saved.keys.sorted() {
            guard let original = saved[service] else { continue }
            do {
                // A user's or another app's replacement is not ours to undo.
                guard try read(service) == [sink] else { continue }
                try write(service, original)
                guard try read(service) == original else {
                    pending[service] = original
                    continue
                }
            } catch {
                pending[service] = original
            }
        }
        return pending
    }
}

enum FakeIPDNSRedirectPlan: Equatable {
    case keep
    case install
    case restore

    static func plan(fakeIPEnabled: Bool, redirectActive: Bool) -> FakeIPDNSRedirectPlan {
        switch (fakeIPEnabled, redirectActive) {
        case (true, false): return .install
        case (false, true): return .restore
        default: return .keep
        }
    }
}

enum FakeIPDNSRedirectSelfTest {
    static func run() throws {
        try UnixFileDescriptorPassing.runSelfTest()
        try PhysicalIPv6ScopedRouteSelfTest.run()
        try EnhancedTunnelStartupSelfTest.run()
        func expect(_ condition: Bool, _ message: String) throws {
            guard condition else { throw HelperServiceError.command(message) }
        }
        let mayMutate = EnhancedTunnelService.mayMutateTunnel
        let owner = EnhancedTunnelService.MutationCaller.authenticatedPeer(uid: 501, pid: 42,
                                                                          allowedUID: 501)
        let other = EnhancedTunnelService.MutationCaller.authenticatedPeer(uid: 501, pid: 43,
                                                                          allowedUID: 501)
        let unknownPID = EnhancedTunnelService.MutationCaller.authenticatedPeer(uid: 501, pid: 0,
                                                                               allowedUID: 501)
        let foreignUID = EnhancedTunnelService.MutationCaller.authenticatedPeer(uid: 502, pid: 42,
                                                                               allowedUID: 501)
        let root = EnhancedTunnelService.MutationCaller.authenticatedPeer(uid: 0, pid: 99,
                                                                         allowedUID: 501)
        try expect(mayMutate(owner, 42, true), "隧道 owner 必须能够重载和停止自己的会话")
        try expect(!mayMutate(other, 42, true), "同 UID 的其他活进程不得重载或停止 owner 的会话")
        try expect(mayMutate(other, 42, false) && mayMutate(other, 0, false),
                   "owner 退出或会话为空时，新进程必须仍能恢复网络")
        try expect(!mayMutate(unknownPID, 42, false) && !mayMutate(unknownPID, 0, false),
                   "未知 PID 不得借孤儿/空会话绕过权限验证")
        try expect(!mayMutate(foreignUID, 42, true) && !mayMutate(foreignUID, 0, false),
                   "未授权 UID 即使 PID 相同也不得变更会话")
        try expect(mayMutate(root, 42, true) && mayMutate(.daemonCleanup, 42, true),
                   "已认证 root 维护和 daemon 内部故障清理必须仍可恢复网络")
        // Evaluate against the owner at execution time, not the queued one.
        try expect(mayMutate(other, 43, true) && !mayMutate(owner, 43, true),
                   "排队期间 owner 变化后必须使用最新权限判定")
        let shouldTearDown = EnhancedTunnelService.shouldExecuteQueuedTeardown
        try expect(shouldTearDown(true, 3, 0, 42, 42, 7, 7),
                   "三个未应答心跳后应自动清理隧道")
        try expect(!shouldTearDown(false, 3, 0, 42, 42, 7, 7),
                   "隧道已关闭时不得再次关停")
        try expect(!shouldTearDown(true, 0, 0, 42, 42, 7, 7),
                   "排队期间恢复心跳后不得误关隧道")
        try expect(!shouldTearDown(true, 3, 0, 43, 42, 7, 7),
                   "新进程接管后不得执行旧 owner 的关停")
        try expect(!shouldTearDown(true, 3, 0, 42, 42, 8, 7),
                   "新隧道不得由旧任务关停")
        try expect(!shouldTearDown(true, 3, 1, 42, 42, 7, 7),
                   "FD 传递尚在进行时不得关停隧道")
        let retryCleanup = EnhancedTunnelService.shouldRetryStoppedCleanup
        try expect(retryCleanup(false, false, false, 5),
                   "客户端未发起状态查询时，也必须自动重试未完成的 DNS/路由恢复")
        try expect(!retryCleanup(true, false, false, 5) &&
                   !retryCleanup(false, true, false, 5) &&
                   !retryCleanup(false, false, true, 5) &&
                   !retryCleanup(false, false, false, 4),
                   "清理任务只应在停止、未恢复且没有排队任务时触发")
        let customRoutes = ["192.0.2.0/24", "2001:db8::/32"]
        let failedRoutes = EnhancedTunnelService.routesRequiringRetry(customRoutes) {
            $0 != "2001:db8::/32"
        }
        try expect(failedRoutes == ["2001:db8::/32"],
                   "路由删除失败后必须保留自定义 CIDR 的清理记录")
        try expect(EnhancedTunnelService.routesRequiringRetry(failedRoutes, remove: { _ in true }).isEmpty,
                   "重新删除成功后必须清空对应的清理记录")
        try expect(EnhancedTunnelService.isMissingRoute(
            HelperServiceError.command("route: writing to routing socket: not in table")),
            "已不存在的路由不应使系统恢复永远处于待处理状态")
        try isolationSelfTest()
        try routeTransitionSelfTest()
        try bypassTransitionSelfTest()
        try dnsTransactionSelfTest()
        try expect(FakeIPDNSRedirectPlan.plan(fakeIPEnabled: true, redirectActive: false) == .install,
                   "启用 fake-IP 时应安装 DNS 重定向")
        try expect(FakeIPDNSRedirectPlan.plan(fakeIPEnabled: true, redirectActive: true) == .keep,
                   "已重定向时重复启用不应再安装")
        try expect(FakeIPDNSRedirectPlan.plan(fakeIPEnabled: false, redirectActive: true) == .restore,
                   "关闭 fake-IP 时应恢复系统 DNS")
        try expect(FakeIPDNSRedirectPlan.plan(fakeIPEnabled: false, redirectActive: false) == .keep,
                   "未重定向时关闭 fake-IP 不应操作 DNS")

        let excluded = EnhancedTunnelService.normalizedExcludedRoutes([
            "10.0.0.0/8", "10.0.0.0/8", "127.0.0.1/32", "0.0.0.0/8",
            "198.18.0.0/15", "224.0.0.0/4", "192.168.0.0/16",
            "fe80::1/64", "::1/128", "2001:db8::/32", "not-an-ip"
        ])
        try expect(excluded == ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"],
                   "排除路由清洗结果错误：\(excluded)")
        try expect(!excluded.contains(where: { !$0.contains("/") }),
                   "排除路由必须保留 CIDR 前缀，不能退化成 host")

        let included = EnhancedTunnelService.normalizedIncludedRoutes([
            "1.1.1.0/24", "8.8.8.8", "198.18.0.0/24", "0.0.0.0/0", "bad"
        ])
        try expect(included == ["1.1.1.0/24", "8.8.8.8/32", "198.18.0.0/24"],
                   "包含路由清洗结果错误：\(included)")
    }

    /// Pure fixtures from macOS route/netstat output; no helper instance is
    /// created and no network configuration command runs during --self-test.
    private static func dnsTransactionSelfTest() throws {
        enum InjectedFailure: Error { case rejected }
        func expect(_ condition: Bool, _ message: String) throws {
            guard condition else { throw HelperServiceError.command(message) }
        }
        func expectFailure(_ message: String, _ operation: () throws -> Void) throws {
            var failed = false
            do { try operation() } catch { failed = true }
            try expect(failed, message)
        }
        let sink = "198.18.16.2"
        let services = ["Wi-Fi", "Ethernet"]
        let original = ["Wi-Fi": ["1.1.1.1", "2606:4700:4700::1111"], "Ethernet": []]
        var current = original
        var saved: [String: [String]] = [:]
        var writes: [String] = []
        func read(_ service: String) throws -> [String] {
            guard let value = current[service] else { throw InjectedFailure.rejected }
            return value
        }
        func write(_ service: String, _ servers: [String]) throws {
            writes.append(service)
            current[service] = servers
        }
        let listing = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*VPN\nEthernet\nWi-Fi\n"
        try expect(try SystemDNSRedirectTransaction.enabledServices(from: listing) == services,
                   "DNS 保护只能覆盖已启用服务，且不能重复设置同一服务")
        try expect(try SystemDNSRedirectTransaction.servers(
            from: "There aren't any DNS Servers set on Ethernet.\n").isEmpty,
                   "自动 DHCP DNS 应保存为空配置以便恢复")
        try expect(try SystemDNSRedirectTransaction.servers(
            from: "1.1.1.1\nfe80::1%en0\n") == ["1.1.1.1", "fe80::1%en0"],
                   "有效 IPv4 与带 scope 的 IPv6 DNS 必须可恢复")
        try expectFailure("空/失败服务列表不得被误判为 DNS 就绪") {
            _ = try SystemDNSRedirectTransaction.enabledServices(from: "Error: failed\n")
        }
        try expectFailure("只有禁用服务的列表不得被误判为 DNS 就绪") {
            _ = try SystemDNSRedirectTransaction.enabledServices(
                from: "An asterisk (*) denotes that a network service is disabled.\n*Wi-Fi\n")
        }
        try expectFailure("DNS 读取错误文本不能当作原始服务器地址") {
            _ = try SystemDNSRedirectTransaction.servers(from: "Error: unknown service\n")
        }

        try SystemDNSRedirectTransaction.install(services: services, sink: sink,
                                                saved: &saved, read: read, write: write)
        try expect(saved == original && current.values.allSatisfy { $0 == [sink] },
                   "必须先保存全部原始 DNS 并逐服务确认 sink，才能声明成功")
        let restored = SystemDNSRedirectTransaction.restore(
            sink: sink, saved: saved, read: read, write: write)
        try expect(restored.isEmpty && current == original,
                   "成功停止后必须验证手动 DNS 与 DHCP 自动 DNS 都已恢复")

        current = original; saved = [:]; writes = []
        try expectFailure("任一服务的原始 DNS 读取失败必须使安装失败") {
            try SystemDNSRedirectTransaction.install(
                services: services, sink: sink, saved: &saved,
                read: { service in
                    if service == "Ethernet" { throw InjectedFailure.rejected }
                    return try read(service)
                }, write: write)
        }
        try expect(writes.isEmpty && saved.isEmpty && current == original,
                   "原始快照不完整时不得先修改任何系统 DNS")

        current = original; saved = [:]; writes = []
        try expectFailure("set 超时即使已经改变 DNS 也必须使安装失败") {
            try SystemDNSRedirectTransaction.install(
                services: services, sink: sink, saved: &saved, read: read,
                write: { service, servers in
                    try write(service, servers)
                    if service == "Ethernet" { throw InjectedFailure.rejected }
                })
        }
        try expect(saved == original && current.values.allSatisfy { $0 == [sink] },
                   "部分成功/结果不确定时，throw 仍必须保存全部已尝试服务的恢复快照")
        let partialRollback = SystemDNSRedirectTransaction.restore(
            sink: sink, saved: saved, read: read, write: write)
        try expect(partialRollback.isEmpty && current == original,
                   "部分安装失败必须能恢复之前成功和超时但已生效的服务")

        current = original; saved = [:]; writes = []
        try expectFailure("set 返回成功但读回不匹配时不能声称 DNS 已就绪") {
            try SystemDNSRedirectTransaction.install(
                services: services, sink: sink, saved: &saved, read: read,
                write: { service, _ in writes.append(service) })
        }
        try expect(saved["Wi-Fi"] == original["Wi-Fi"] && writes == ["Wi-Fi"],
                   "读回失败必须保留已尝试服务的快照，且停止修改后续服务")

        current = ["Wi-Fi": [sink], "Ethernet": [sink]]; saved = original
        let unconfirmedRestore = SystemDNSRedirectTransaction.restore(
            sink: sink, saved: saved, read: read, write: { _, _ in })
        try expect(unconfirmedRestore == original,
                   "restore 返回成功但 DNS 仍指向 sink 时，必须保留待重试快照")
        let retried = SystemDNSRedirectTransaction.restore(
            sink: sink, saved: unconfirmedRestore, read: read, write: write)
        try expect(retried.isEmpty && current == original,
                   "重新恢复并读回成功后才允许清空恢复记录")

        current = ["Wi-Fi": [sink], "Ethernet": [sink]]; saved = original
        let unreadableRestore = SystemDNSRedirectTransaction.restore(
            sink: sink, saved: saved,
            read: { _ in throw InjectedFailure.rejected }, write: write)
        try expect(unreadableRestore == original,
                   "无法读取当前 DNS 时不得丢弃待恢复快照")

        current = ["Wi-Fi": [sink], "Ethernet": []]; saved = ["Wi-Fi": original["Wi-Fi"]!]
        try SystemDNSRedirectTransaction.install(services: services, sink: sink,
                                                saved: &saved, read: read, write: write)
        try expect(saved == original && current["Ethernet"] == [sink],
                   "已有重定向时，新增/重新启用的服务也必须安装并验证 sink")
        current["Wi-Fi"] = ["8.8.8.8"]
        try SystemDNSRedirectTransaction.install(services: services, sink: sink,
                                                saved: &saved, read: read, write: write)
        try expect(saved["Wi-Fi"] == ["8.8.8.8"] && current["Wi-Fi"] == [sink],
                   "重载再次保护被用户更新的服务时，必须恢复到用户最新 DNS 而非旧快照")
        current["Ethernet"] = ["9.9.9.9"]; writes = []
        let externalChange = SystemDNSRedirectTransaction.restore(
            sink: sink, saved: saved, read: read, write: write)
        try expect(externalChange.isEmpty && current["Ethernet"] == ["9.9.9.9"] &&
                   !writes.contains("Ethernet"),
                   "停止时不得覆盖用户或其他应用新设置的 DNS")

        current = ["Wi-Fi": [sink]]; saved = [:]; writes = []
        try expectFailure("没有原始快照的旧 sink 不得被认领") {
            try SystemDNSRedirectTransaction.install(services: ["Wi-Fi"], sink: sink,
                                                    saved: &saved, read: read, write: write)
        }
        try expect(saved.isEmpty && writes.isEmpty,
                   "拒绝孤儿 DNS 时不得生成虚假的恢复记录或覆盖配置")
    }

    /// Pure fixtures from macOS route/netstat output; no helper instance is
    /// created and no network configuration command runs during --self-test.
    private static func isolationSelfTest() throws {
        func expect(_ condition: Bool, _ message: String) throws {
            guard condition else { throw HelperServiceError.command(message) }
        }
        let lurgeRoute = """
           route to: 1.0.0.0
        destination: 1.0.0.0
               mask: 255.0.0.0
            gateway: 198.18.0.1
          interface: utun3
              flags: <UP,GATEWAY,DONE,STATIC>
        """
        let hajimiRoute = lurgeRoute.replacingOccurrences(of: "198.18.0.1", with: "198.18.16.1")
            .replacingOccurrences(of: "utun3", with: "utun4")
        func belongs(_ lookup: String, route: String, gateway: String,
                     tunnel: Bool, tunnelInterface: String? = nil) -> Bool {
            EnhancedTunnelService.routeLookupIsOwned(
                lookup, route: route, gateway: gateway,
                tunnel: tunnel, tunnelInterface: tunnelInterface)
        }
        try expect(!belongs(lurgeRoute, route: "1.0.0.0/8", gateway: "198.18.16.1",
                            tunnel: true),
                   "Lurge 路由即使目的网段相同，也不得被 Hajimi 删除")
        try expect(belongs(hajimiRoute, route: "1.0.0.0/8", gateway: "198.18.16.1",
                           tunnel: true, tunnelInterface: "utun4"),
                   "Hajimi 自己的路由应可恢复")
        try expect(!belongs(hajimiRoute, route: "1.0.0.0/16", gateway: "198.18.16.1",
                            tunnel: true) &&
                   !belongs(hajimiRoute, route: "1.0.0.0/8", gateway: "198.18.16.1",
                            tunnel: true, tunnelInterface: "utun5"),
                   "前缀或 utun 接口不同的路由不得删除")
        let otherRoute = hajimiRoute.replacingOccurrences(of: "destination: 1.0.0.0",
                                                             with: "destination: default")
        try expect(!belongs(otherRoute, route: "1.0.0.0/8", gateway: "198.18.16.1",
                            tunnel: true),
                   "route get 回退到默认路由不能误判为安装成功")
        let ipv6Route = """
           route to: ::
        destination: ::
               mask: 8000::
            gateway: fd00:6861:6a69::1
          interface: utun4
              flags: <UP,GATEWAY,DONE,STATIC>
        """
        try expect(belongs(ipv6Route, route: "::/1", gateway: "fd00:6861:6a69::1",
                           tunnel: true, tunnelInterface: "utun4") &&
                   !belongs(ipv6Route, route: "::/1", gateway: "fd00:7162::1", tunnel: true),
                   "IPv6 网关必须独立，且只删除自己的前缀")
        let physicalRoute = """
           route to: 203.0.113.9
        destination: 203.0.113.9
            gateway: 192.0.2.1
          interface: en1
              flags: <UP,GATEWAY,HOST,DONE,STATIC>
        """
        try expect(belongs(physicalRoute, route: "203.0.113.9", gateway: "192.0.2.1",
                           tunnel: false) &&
                   !belongs(physicalRoute, route: "203.0.113.9", gateway: "192.0.2.254",
                            tunnel: false),
                   "仅可删除仍指向原物理网关的旁路主机路由")
        let lurgeTable = """
        Destination        Gateway            Flags           Netif Expire
        default            10.240.169.184     UGScg             en1
        1                  198.18.0.1         UGSc            utun3
        2/7                198.18.0.1         UGSc            utun3
        198.18.0.1         198.18.0.1         UH              utun3
        """
        let conflict = EnhancedTunnelService.firstConflictingTunnelRoute
        try expect(conflict(lurgeTable)?.contains("utun3") == true,
                   "Lurge 仍有接管流量的路由时，Hajimi 必须拒绝启动")
        let scopedTable = """
        Destination              Gateway                 Flags     Netif Expire
        default                  fe80::%utun0            UGcIg     utun0
        fe80::%utun0/64          fe80::1%utun0           UcI       utun0
        ff00::/8                 fe80::1%utun0           UmCI      utun0
        """
        try expect(conflict(scopedTable) == nil,
                   "macOS 休眠的 IPv6 scoped utun 默认路由不应误判为接管全局网络")
        try expect(conflict("Destination Gateway Flags Netif\n203.0.113/24 10.0.0.1 Uc utun9") != nil,
                   "其他客户端的自定义 split-tunnel 路由也应阻止启动")
        let noDNS = "There aren't any DNS Servers set on Wi-Fi.\n"
        try expect(EnhancedTunnelService.configuredDNSServers(from: noDNS).isEmpty &&
                   EnhancedTunnelService.configuredDNSServers(from: "198.18.16.2\n") == ["198.18.16.2"] &&
                   EnhancedTunnelService.configuredDNSServers(from: "198.18.0.2\n") != ["198.18.16.2"],
                   "DNS 所有权比较必须区分空配置、Hajimi 和 Lurge 的地址")
        var unownedRouteDeletes = 0
        let unknown = EnhancedTunnelService.routesRequiringRetry([]) { _ in
            unownedRouteDeletes += 1
            return true
        }
        try expect(unknown.isEmpty && unownedRouteDeletes == 0,
                   "无路由所有权记录时不应触发任何删除")
    }

    /// All route mutations below are an injected in-memory Set. No root,
    /// utun, networksetup, or /sbin/route subprocess is touched by --self-test.
    private static func routeTransitionSelfTest() throws {
        typealias Mutation = EnhancedTunnelService.TunnelRouteMutation
        enum InjectedFailure: Error { case rejected }
        func expect(_ condition: Bool, _ message: String) throws {
            guard condition else { throw HelperServiceError.command(message) }
        }
        func mutate(_ operation: Mutation, active: inout Set<String>) throws {
            switch operation {
            case .add(let route):
                guard active.insert(route).inserted else { throw InjectedFailure.rejected }
            case .remove(let route):
                guard active.remove(route) != nil else { throw InjectedFailure.rejected }
            }
        }

        let old = ["1.0.0.0/8", "8.0.0.0/5"]
        let new = "203.0.113.0/24"
        var active = Set(old)
        var order: [Mutation] = []
        let successful = EnhancedTunnelService.transitionTunnelRoutes(
            from: old, to: [old[1], new]) { operation in
                order.append(operation)
                try mutate(operation, active: &active)
            }
        try expect(successful.failure == nil && successful.installed == [old[1], new] &&
                   active == Set([old[1], new]) &&
                   order == [.add(new), .remove(old[0])],
                   "新路由必须在旧路由删除前安装，共有路由不能反复删除")

        active = Set(old)
        let second = "198.51.100.0/24"
        let addFailure = EnhancedTunnelService.transitionTunnelRoutes(
            from: old, to: [new, second]) { operation in
                if operation == .add(second) { throw InjectedFailure.rejected }
                try mutate(operation, active: &active)
            }
        try expect(addFailure.failure != nil && !addFailure.requiresTeardown &&
                   addFailure.installed == old && active == Set(old),
                   "新增路由失败后应删除已添加路由，保留整个旧路由集")

        active = Set(old)
        var deleteOrder: [Mutation] = []
        let deleteFailure = EnhancedTunnelService.transitionTunnelRoutes(
            from: old, to: [new]) { operation in
                deleteOrder.append(operation)
                if operation == .remove(old[1]) { throw InjectedFailure.rejected }
                try mutate(operation, active: &active)
            }
        try expect(deleteFailure.failure != nil && !deleteFailure.requiresTeardown &&
                   deleteFailure.installed == old && active == Set(old) &&
                   deleteOrder == [.add(new), .remove(old[0]), .remove(old[1]),
                                   .add(old[0]), .remove(new)],
                   "删旧路由失败后必须恢复已删路由，撤销新增路由")

        active = Set(old)
        let restoreFailure = EnhancedTunnelService.transitionTunnelRoutes(
            from: old, to: [new]) { operation in
                if operation == .remove(old[1]) || operation == .add(old[0]) {
                    throw InjectedFailure.rejected
                }
                try mutate(operation, active: &active)
            }
        try expect(restoreFailure.requiresTeardown &&
                   restoreFailure.installed.contains(old[0]) &&
                   active != Set(old),
                   "恢复旧路由失败时必须触发停机，保留可能仍在内核的自定义路由记录")

        active = Set(old)
        let revokeFailure = EnhancedTunnelService.transitionTunnelRoutes(
            from: old, to: [new, second]) { operation in
                if operation == .add(second) || operation == .remove(new) {
                    throw InjectedFailure.rejected
                }
                try mutate(operation, active: &active)
            }
        try expect(revokeFailure.requiresTeardown && revokeFailure.installed.contains(new) &&
                   active.contains(new),
                   "新增路由无法撤销时应保留它并立刻关停失效的隧道")

        active = Set(old)
        let uncertain = EnhancedTunnelService.transitionTunnelRoutes(
            from: old, to: [new]) { operation in
                if operation == .add(new) {
                    try mutate(operation, active: &active)
                    throw HelperServiceError.timeout("注入 route add 超时")
                }
                try mutate(operation, active: &active)
            }
        try expect(uncertain.requiresTeardown && active == Set(old),
                   "route 超时即使命令回滚也不能悄悄宣称运行状态安全")
    }

    private static func bypassTransitionSelfTest() throws {
        typealias Bypass = EnhancedTunnelService.InstalledBypassRoute
        typealias Mutation = EnhancedTunnelService.RouteMutation<Bypass>
        enum InjectedFailure: Error { case alreadyExists, rejected }
        func expect(_ condition: Bool, _ message: String) throws {
            guard condition else { throw HelperServiceError.command(message) }
        }
        let old = Bypass(destination: "203.0.113.9", isIPv6: false,
                         isNetwork: false, gateway: "192.0.2.1")
        let added = Bypass(destination: "198.51.100.0/24", isIPv6: false,
                           isNetwork: true, gateway: "192.0.2.1")
        let later = Bypass(destination: "198.51.101.0/24", isIPv6: false,
                           isNetwork: true, gateway: "192.0.2.1")
        func mutate(_ mutation: Mutation, active: inout Set<Bypass>) throws {
            switch mutation {
            case .add(let route):
                guard active.insert(route).inserted else { throw InjectedFailure.alreadyExists }
            case .remove(let route):
                guard active.remove(route) != nil else { throw InjectedFailure.rejected }
            }
        }

        var calls = 0
        let repeated = EnhancedTunnelService.transitionRouteInventory(
            from: [old], to: [old], label: { $0.destination }) { _ in
                calls += 1
                throw InjectedFailure.rejected
            }
        try expect(repeated.failure == nil && repeated.installed == [old] && calls == 0,
                   "相同旁路配置不应重复删加现有物理路由")

        var active: Set<Bypass> = [old]
        var order: [Mutation] = []
        let changed = EnhancedTunnelService.transitionRouteInventory(
            from: [old], to: [added], label: { $0.destination }) { mutation in
                order.append(mutation)
                try mutate(mutation, active: &active)
            }
        try expect(changed.failure == nil && active == Set([added]) &&
                   changed.installed == [added] && order == [.add(added), .remove(old)],
                   "旁路更新必须先安装新路由，再删除旧路由")

        active = Set([old])
        let failedAdd = EnhancedTunnelService.transitionRouteInventory(
            from: [old], to: [added, later], label: { $0.destination }) { mutation in
                if mutation == .add(later) { throw InjectedFailure.rejected }
                try mutate(mutation, active: &active)
            }
        try expect(failedAdd.failure != nil && failedAdd.installed == [old] &&
                   active == Set([old]),
                   "新增旁路失败必须撤销已添加的路由，保留原物理路径")

        active = Set([old, added])
        let failedDelete = EnhancedTunnelService.transitionRouteInventory(
            from: [old, added], to: [later], label: { $0.destination }) { mutation in
                if mutation == .remove(added) { throw InjectedFailure.rejected }
                try mutate(mutation, active: &active)
            }
        try expect(failedDelete.failure != nil && failedDelete.installed == [old, added] &&
                   active == Set([old, added]),
                   "删旧旁路失败须恢复此前已删的物理路由并撤销新旁路")

        // An unrelated physical route can satisfy a bypass request, but must
        // never enter this Helper's future delete inventory.
        let external = Bypass(destination: "192.0.2.22", isIPv6: false,
                              isNetwork: false, gateway: "192.0.2.1")
        let physical = EnhancedTunnelService.transitionRouteInventory(
            from: [], to: [external], label: { $0.destination },
            alreadySatisfied: { route, error in
                route == external && (error as? InjectedFailure) != nil
            }) { mutation in
                guard mutation == .add(external) else { throw InjectedFailure.rejected }
                throw InjectedFailure.alreadyExists
            }
        try expect(physical.failure == nil && physical.installed.isEmpty,
                   "外部物理路由无需重复安装，也不能被本 Helper 删除")

        let nextGateway = Bypass(destination: old.destination, isIPv6: false,
                                 isNetwork: false, gateway: "192.0.2.254")
        let wrongGateway = EnhancedTunnelService.transitionRouteInventory(
            from: [old], to: [nextGateway], label: { $0.destination },
            alreadySatisfied: { route, _ in route.gateway == old.gateway }) { mutation in
                if mutation == .add(nextGateway) { throw InjectedFailure.alreadyExists }
                throw InjectedFailure.rejected
            }
        try expect(wrongGateway.failure != nil && wrongGateway.installed == [old],
                   "旧网关路由不能被误判为新物理网关旁路已建立")

        active = Set([old])
        let failedRollback = EnhancedTunnelService.transitionRouteInventory(
            from: [old], to: [added, later], label: { $0.destination }) { mutation in
                if mutation == .add(later) || mutation == .remove(added) {
                    throw InjectedFailure.rejected
                }
                try mutate(mutation, active: &active)
            }
        try expect(failedRollback.requiresTeardown &&
                   failedRollback.installed.contains(added) && active.contains(added),
                   "旁路回滚失败时必须保留残余路由供停机后台清理")
    }
}

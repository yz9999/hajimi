import Foundation

/// Reads only association identity from a State AirPort dictionary. Raw Wi-Fi
/// identifiers never leave this call; the randomized in-process hash is not
/// persisted or logged. Signal/channel/counters and all credential keys are
/// deliberately absent from the comparison.
enum EnhancedWiFiAssociationStamp {
    static func make(from state: [String: Any]) -> Int? {
        let ssid: Data? = {
            if let data = state["SSID"] as? Data, data.count <= 32 { return data }
            if let text = state["SSID_STR"] as? String, text.utf8.count <= 32 {
                return Data(text.utf8)
            }
            return nil
        }()
        let bssid: Data? = {
            if let data = state["BSSID"] as? Data, data.count == 6 { return data }
            guard let text = state["BSSID"] as? String, text.utf8.count <= 17 else { return nil }
            let fields = text.split(separator: ":", omittingEmptySubsequences: false)
            guard fields.count == 6, fields.allSatisfy({ $0.count == 2 }) else { return nil }
            let bytes = fields.compactMap { UInt8($0, radix: 16) }
            return bytes.count == 6 ? Data(bytes) : nil
        }()
        guard ssid != nil || bssid != nil else { return nil }
        var hasher = Hasher()
        hasher.combine(ssid); hasher.combine(bssid)
        return hasher.finalize()
    }
}

/// The useful physical-network identity, not every NWPath/DNS notification.
/// Only a bounded, normalized snapshot is retained; Wi-Fi identity is opaque.
struct EnhancedNetworkSnapshot: Equatable {
    let available: Bool
    let interfaceName: String
    let interfaceIndex: UInt32
    let addresses: [String]
    let gateways: [String]
    let associationStamp: Int?

    init(available: Bool, interfaceName: String, interfaceIndex: UInt32,
         addresses: [String], gateways: [String], associationStamp: Int? = nil) {
        self.available = available
        self.interfaceName = String(interfaceName.prefix(64))
        self.interfaceIndex = interfaceIndex
        self.addresses = Self.normalize(addresses, maximum: 128)
        self.gateways = Self.normalize(gateways, maximum: 16)
        self.associationStamp = associationStamp
    }

    private static func normalize(_ values: [String], maximum: Int) -> [String] {
        let bounded = values.prefix(maximum).map {
            String($0.prefix(256)).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }.filter { !$0.isEmpty }
        return Array(Set(bounded)).sorted()
    }

    func hasSameIdentity(as other: Self) -> Bool {
        interfaceName == other.interfaceName && interfaceIndex == other.interfaceIndex
            && addresses == other.addresses && gateways == other.gateways
            && associationStamp == other.associationStamp
    }
}

/// Pure, queue-confined debounce admission. A duplicate cannot postpone work;
/// loss/recovery and wake are latched even if the network returns to baseline.
/// Tickets reject already-cancelled work and callbacks from an older session.
struct EnhancedNetworkChangeGate {
    struct ReadinessRetry {
        let ticket: Ticket
        let delay: TimeInterval
    }
    struct Ticket: Equatable {
        fileprivate let session: UInt64
        fileprivate let revision: UInt64
    }
    struct Action: Equatable {
        fileprivate let ticket: Ticket
        let snapshot: EnhancedNetworkSnapshot
        let forcedByWake: Bool
        let observedUnavailable: Bool
        let identityChanged: Bool
        let retrying: Bool
    }

    private(set) var session: UInt64 = 0
    private(set) var snapshot: EnhancedNetworkSnapshot?
    private(set) var pendingTicket: Ticket?
    private var revision: UInt64 = 0
    private var forcedByWake = false
    private var observedUnavailable = false
    private var identityChanged = false
    private var pendingIsRetry = false
    private var lastTakenTicket: Ticket?
    private var recoveryAction: Action?
    private var readinessRetries = 0

    /// Seed BEFORE the first NWPath callback. A real startup race changing the
    /// bound interface or losing connectivity is not suppressed as "initial".
    mutating func begin(seed: EnhancedNetworkSnapshot, boundInterface: String) -> Ticket? {
        stop()
        snapshot = seed
        guard !seed.available || seed.interfaceName != boundInterface else { return nil }
        observedUnavailable = !seed.available
        identityChanged = seed.interfaceName != boundInterface
        return enqueue()
    }

    mutating func stop() {
        session &+= 1
        snapshot = nil
        pendingTicket = nil
        forcedByWake = false
        observedUnavailable = false
        identityChanged = false
        pendingIsRetry = false
        lastTakenTicket = nil
        recoveryAction = nil
        readinessRetries = 0
    }

    mutating func observe(_ next: EnhancedNetworkSnapshot, session expected: UInt64) -> Ticket? {
        guard expected == session, let previous = snapshot, previous != next else { return nil }
        snapshot = next
        // An availability-only recovery can continue an already invalidated
        // uplink. A genuinely different IP/gateway/interface/association is
        // a new DNS epoch even if the previous recovery was unsuccessful.
        pendingIsRetry = previous.hasSameIdentity(as: next) &&
            (pendingIsRetry || recoveryAction != nil)
        recoveryAction = nil; lastTakenTicket = nil; readinessRetries = 0
        observedUnavailable = observedUnavailable || !previous.available || !next.available
        identityChanged = identityChanged || !previous.hasSameIdentity(as: next)
        return enqueue()
    }

    mutating func wake(_ next: EnhancedNetworkSnapshot, session expected: UInt64) -> Ticket? {
        guard expected == session, let previous = snapshot else { return nil }
        snapshot = next
        pendingIsRetry = false
        recoveryAction = nil; lastTakenTicket = nil; readinessRetries = 0
        forcedByWake = true
        observedUnavailable = observedUnavailable || !previous.available || !next.available
        identityChanged = identityChanged || !previous.hasSameIdentity(as: next)
        return enqueue()
    }

    mutating func take(_ ticket: Ticket) -> Action? {
        guard ticket.session == session, pendingTicket == ticket, let snapshot else { return nil }
        let action = Action(ticket: ticket, snapshot: snapshot, forcedByWake: forcedByWake,
                            observedUnavailable: observedUnavailable, identityChanged: identityChanged,
                            retrying: pendingIsRetry)
        pendingTicket = nil
        lastTakenTicket = ticket
        forcedByWake = false
        observedUnavailable = false
        identityChanged = false
        pendingIsRetry = false
        return action
    }

    /// The mutating operation is synchronous on its owner's serial queue. An
    /// older completion must never resurrect recovery after a newer event.
    mutating func finished(_ action: Action, succeeded: Bool) {
        guard action.ticket.session == session, lastTakenTicket == action.ticket else { return }
        lastTakenTicket = nil
        guard pendingTicket == nil, snapshot == action.snapshot else { return }
        recoveryAction = succeeded ? nil : action
        if succeeded { readinessRetries = 0 }
    }

    /// Called only by the existing healthy five-second monitor, not an
    /// additional timer or every duplicate NWPath event. One failed action is
    /// retained; its retry uses current state/configuration, not old payloads.
    mutating func retry(session expected: UInt64) -> Ticket? {
        guard expected == session, pendingTicket == nil, lastTakenTicket == nil,
              let failed = recoveryAction, snapshot?.available == true else { return nil }
        forcedByWake = failed.forcedByWake
        observedUnavailable = failed.observedUnavailable
        identityChanged = failed.identityChanged
        pendingIsRetry = true
        return enqueue()
    }

    /// Only an owner that just confirmed a local/Helper readiness deferral
    /// may request these probes. They also inspect an offline snapshot, but
    /// the manager forbids binding or Helper mutation until it is ready.
    /// Duplicate notifications and the five-second monitor never refill the
    /// budget. A real new network identity starts a new bounded recovery.
    mutating func retryReadinessSoon(session expected: UInt64) -> ReadinessRetry? {
        let delays: [TimeInterval] = [0.15, 0.4, 1.0]
        guard expected == session, pendingTicket == nil, lastTakenTicket == nil,
              let failed = recoveryAction, readinessRetries < delays.count else { return nil }
        let delay = delays[readinessRetries]
        readinessRetries += 1
        forcedByWake = failed.forcedByWake
        observedUnavailable = failed.observedUnavailable
        identityChanged = failed.identityChanged
        pendingIsRetry = true
        return ReadinessRetry(ticket: enqueue(), delay: delay)
    }

    /// A newer configuration may supersede the authority captured by pending
    /// work. Replace only that exact ticket, preserving whether its DNS epoch
    /// was already invalidated and how much readiness budget it has spent.
    /// The cancelled body can never consume the replacement ticket.
    mutating func reissuePending(_ ticket: Ticket) -> Ticket? {
        guard ticket.session == session, pendingTicket == ticket, lastTakenTicket == nil else { return nil }
        return enqueue()
    }

    /// A deferred configuration or bypass reload can need recovery without
    /// a new path identity. Reuse the existing debounce and healthy monitor;
    /// never replace an already pending/active action or revive a stopped gate.
    mutating func requestRecovery(_ next: EnhancedNetworkSnapshot, session expected: UInt64) -> Ticket? {
        guard expected == session, let previous = snapshot,
              pendingTicket == nil, lastTakenTicket == nil else { return nil }
        snapshot = next
        recoveryAction = nil
        observedUnavailable = observedUnavailable || !previous.available || !next.available
        identityChanged = identityChanged || !previous.hasSameIdentity(as: next)
        pendingIsRetry = false
        readinessRetries = 0
        return enqueue()
    }

    private mutating func enqueue() -> Ticket {
        revision &+= 1
        let ticket = Ticket(session: session, revision: revision)
        pendingTicket = ticket
        return ticket
    }
}

/// Pure injected snapshots only: no monitor, dynamic store, Helper or sockets.
enum EnhancedNetworkChangeGateSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }

    static func run() throws {
        func expect(_ value: Bool, _ message: String) throws {
            if !value { throw Failure(text: "网络通知去重自检失败：" + message) }
        }
        func sample(_ name: String = "en0", index: UInt32 = 4, available: Bool = true,
                    address: String = "192.0.2.7", gateway: String = "192.0.2.1",
                    association: Int? = 11) -> EnhancedNetworkSnapshot {
            EnhancedNetworkSnapshot(available: available, interfaceName: name, interfaceIndex: index,
                                    addresses: [address, "2001:DB8::7"], gateways: [gateway],
                                    associationStamp: association)
        }
        let original = sample()
        var gate = EnhancedNetworkChangeGate()
        try expect(gate.begin(seed: original, boundInterface: "en0") == nil,
                   "初始化不得丢弃已有 DNS 池")
        let session = gate.session
        for _ in 0..<10_000 {
            try expect(gate.observe(original, session: session) == nil && gate.pendingTicket == nil,
                       "等价路径不能反复调度或保留工作")
        }
        let reordered = EnhancedNetworkSnapshot(available: true, interfaceName: "en0", interfaceIndex: 4,
            addresses: ["2001:db8::7", "192.0.2.7", "192.0.2.7"], gateways: [" 192.0.2.1 "],
            associationStamp: 11)
        try expect(gate.observe(reordered, session: session) == nil,
                   "地址顺序、重复值和表示大小写不是网络切换")
        let association: [String: Any] = ["SSID_STR": "fixture-network", "BSSID": "02:00:00:00:00:01",
                                          "RSSI": -60, "Channel": 1]
        var signalOnly = association
        signalOnly["RSSI"] = -80; signalOnly["Channel"] = 11; signalOnly["Counter"] = 12
        signalOnly["AuthPassword"] = "ignored-fixture"
        try expect(EnhancedWiFiAssociationStamp.make(from: association) ==
                   EnhancedWiFiAssociationStamp.make(from: signalOnly),
                   "信号、信道、计数和凭据字段不属于网络身份")
        var nextAssociation = association; nextAssociation["SSID_STR"] = "fixture-next"
        try expect(EnhancedWiFiAssociationStamp.make(from: association) !=
                   EnhancedWiFiAssociationStamp.make(from: nextAssociation),
                   "相同地址下 Wi-Fi 关联变化也必须可识别")
        var dataAssociation = association
        dataAssociation["SSID"] = Data("fixture-network".utf8)
        dataAssociation["BSSID"] = Data([2, 0, 0, 0, 0, 1])
        try expect(EnhancedWiFiAssociationStamp.make(from: association) ==
                   EnhancedWiFiAssociationStamp.make(from: dataAssociation),
                   "Wi-Fi 关联身份的 String/Data 表示不能造成伪切换")
        try expect(EnhancedWiFiAssociationStamp.make(from: ["RSSI": -60, "AuthPassword": "ignored"]) == nil,
                   "没有公开关联标识时不能把信号变化当作 Wi-Fi 切换")

        for changed in [sample("en1", index: 5), sample(index: 6), sample(address: "192.0.2.8"),
                        sample(gateway: "192.0.2.254"), sample(association: 12)] {
            _ = gate.begin(seed: original, boundInterface: "en0")
            let ticket = gate.observe(changed, session: gate.session)
            try expect(ticket != nil, "网卡、网卡代次、IP、网关和 Wi-Fi 关联变化均必须失效")
            guard let ticket else { continue }
            try expect(gate.observe(changed, session: gate.session) == nil && gate.pendingTicket == ticket,
                       "重复通知不得推迟真实变更的处理")
            let action = gate.take(ticket)
            try expect(action?.snapshot == changed && action?.identityChanged == true,
                       "有效变更必须交付一次明确动作")
            try expect(gate.take(ticket) == nil, "同一失效动作不能重复消费")
        }

        _ = gate.begin(seed: original, boundInterface: "en0")
        let lost = gate.observe(sample(available: false), session: gate.session)!
        let recovered = gate.observe(original, session: gate.session)!
        try expect(gate.take(lost) == nil, "取消的掉线处理不能抢先覆盖恢复")
        try expect(gate.take(recovered)?.observedUnavailable == true,
                   "短暂掉线恢复到相同 IP 也必须使旧网络资源失效")
        let wake = gate.wake(original, session: gate.session)!
        try expect(gate.take(wake)?.forcedByWake == true, "唤醒必须使等价网络失效")
        let first = gate.observe(sample(address: "192.0.2.8"), session: gate.session)!
        let back = gate.observe(original, session: gate.session)!
        try expect(gate.take(first) == nil && gate.take(back)?.identityChanged == true,
                   "防抖期间切出再切回不能伪装成没有变更")

        let oldSession = gate.session
        let stale = gate.wake(original, session: oldSession)!
        gate.stop()
        try expect(gate.take(stale) == nil && gate.observe(original, session: oldSession) == nil,
                   "停止后旧回调与旧工作必须失效")
        _ = gate.begin(seed: original, boundInterface: "en0")
        try expect(gate.take(stale) == nil && gate.wake(original, session: oldSession) == nil,
                   "重启不能复活上一个会话的通知")
        let startupRace = gate.begin(seed: sample("en1", index: 5), boundInterface: "en0")
        try expect(startupRace != nil && gate.take(startupRace!)?.identityChanged == true,
                   "启动过程中真实切换物理接口不能被首通知去重忽略")
        let startupLoss = gate.begin(seed: sample(available: false), boundInterface: "en0")
        try expect(startupLoss != nil && gate.take(startupLoss!)?.observedUnavailable == true,
                   "启动过程中掉线必须失效")
        // The retained seed was captured before helper.start, not after FD
        // attach. Compare the whole post-installation snapshot on first use.
        for changed in [sample(address: "192.0.2.8"), sample(gateway: "192.0.2.254"),
                        sample(association: 12)] {
            _ = gate.begin(seed: original, boundInterface: "en0")
            let startupChange = gate.observe(changed, session: gate.session)
            try expect(startupChange != nil && gate.take(startupChange!)?.identityChanged == true,
                       "helper 启动期间同网卡 IP、网关、Wi-Fi 关联变化必须失效")
        }

        _ = gate.begin(seed: original, boundInterface: "en0")
        let failedTicket = gate.wake(original, session: gate.session)!
        let failedAction = gate.take(failedTicket)!
        gate.finished(failedAction, succeeded: false)
        for _ in 0..<10_000 {
            try expect(gate.observe(original, session: gate.session) == nil,
                       "失败恢复不得被等价通知驱动忙循环")
        }
        let retry = gate.retry(session: gate.session)
        try expect(retry != nil && gate.retry(session: gate.session) == nil,
                   "健康 monitor 应仅调度一个有界恢复工作")
        let retryAction = gate.take(retry!)!
        try expect(retryAction.retrying && retryAction.forcedByWake,
                   "重试必须保留恢复意图，但不得重复清除 DNS")
        gate.finished(retryAction, succeeded: true)
        try expect(gate.retry(session: gate.session) == nil, "成功重绑后必须清除恢复标记")

        let failureAgainTicket = gate.wake(original, session: gate.session)!
        let failureAgain = gate.take(failureAgainTicket)!
        gate.finished(failureAgain, succeeded: false)
        let different = gate.observe(sample(gateway: "192.0.2.254"), session: gate.session)!
        let replacement = gate.take(different)!
        gate.finished(failureAgain, succeeded: false)
        try expect(!replacement.retrying && gate.retry(session: gate.session) == nil,
                   "新真实变化必须替换旧恢复并开始新 DNS 代次，迟到失败不能复活旧工作")
        gate.finished(replacement, succeeded: true)
        let offlineTicket = gate.observe(sample(available: false), session: gate.session)!
        let offline = gate.take(offlineTicket)!
        gate.finished(offline, succeeded: false)
        try expect(gate.retry(session: gate.session) == nil, "离线时不能重试重绑或清除物理绑定")
        gate.stop()
        try expect(gate.retry(session: gate.session) == nil, "停止必须清除失败恢复库存")

        _ = gate.begin(seed: original, boundInterface: "en0")
        let unavailable = sample(available: false)
        let firstReadiness = gate.observe(unavailable, session: gate.session)!
        var readinessAction = gate.take(firstReadiness)!
        gate.finished(readinessAction, succeeded: false)
        for delay in [0.15, 0.4, 1.0] {
            guard let probe = gate.retryReadinessSoon(session: gate.session) else {
                throw Failure(text: "网络通知去重自检失败：就绪探测未保留三次短重试")
            }
            try expect(probe.delay == delay, "就绪探测退避必须为 150/400/1000ms")
            for _ in 0..<100 {
                try expect(gate.observe(unavailable, session: gate.session) == nil &&
                           gate.pendingTicket == probe.ticket,
                           "重复离线通知不得推迟探测或补充预算")
            }
            try expect(gate.retryReadinessSoon(session: gate.session) == nil &&
                       gate.retry(session: gate.session) == nil,
                       "短探测与五秒 monitor 不得产生重复工作")
            readinessAction = gate.take(probe.ticket)!
            try expect(readinessAction.retrying && readinessAction.observedUnavailable,
                       "短探测必须沿用失败意图且不能再次清除 DNS")
            gate.finished(readinessAction, succeeded: false)
        }
        try expect(gate.retryReadinessSoon(session: gate.session) == nil,
                   "三个短探测耗尽后必须退出快速重试")
        let readyAfterProbes = gate.observe(original, session: gate.session)!
        let readyAction = gate.take(readyAfterProbes)!
        try expect(readyAction.retrying && readyAction.observedUnavailable,
                   "同 IP 恢复必须立即接续原恢复且不重复清 DNS")
        gate.finished(readyAction, succeeded: false)
        let renewed = gate.retryReadinessSoon(session: gate.session)!
        try expect(renewed.delay == 0.15, "真实就绪事件必须开启新的有界探测预算")
        let renewedAction = gate.take(renewed.ticket)!
        gate.finished(renewedAction, succeeded: false)
        let slow = gate.retry(session: gate.session)!
        let slowAction = gate.take(slow)!
        gate.finished(slowAction, succeeded: false)
        let retainedBudget = gate.retryReadinessSoon(session: gate.session)!
        try expect(retainedBudget.delay == 0.4, "五秒 monitor 不得补充快速预算")
        let cancelledProbe = retainedBudget.ticket
        let cancelledSession = gate.session
        gate.stop()
        try expect(gate.take(cancelledProbe) == nil &&
                   gate.retryReadinessSoon(session: cancelledSession) == nil,
                   "停止必须撤销短探测及旧会话的恢复权限")
        _ = gate.begin(seed: original, boundInterface: "en0")
        try expect(gate.take(cancelledProbe) == nil, "短探测不得跨会话复活")
        for changed in [sample("en1", index: 5), sample(index: 6), sample(address: "192.0.2.8"),
                        sample(gateway: "192.0.2.254"), sample(association: 12)] {
            _ = gate.begin(seed: original, boundInterface: "en0")
            let failure = gate.wake(original, session: gate.session)!
            gate.finished(gate.take(failure)!, succeeded: false)
            let oldProbe = gate.retryReadinessSoon(session: gate.session)!
            let newEpoch = gate.observe(changed, session: gate.session)!
            try expect(gate.take(oldProbe.ticket) == nil,
                       "新网络身份必须撤销旧出口的短探测")
            let fresh = gate.take(newEpoch)!
            try expect(!fresh.retrying, "旧出口已清 DNS 不能免除新 IP、网关、网卡或 Wi-Fi 关联的失效")
            gate.finished(fresh, succeeded: false)
            let newProbe = gate.retryReadinessSoon(session: gate.session)!
            try expect(newProbe.delay == 0.15, "新出口必须获得独立的有界探测预算")
        }
        _ = gate.begin(seed: original, boundInterface: "en0")
        let wakeFailure = gate.wake(original, session: gate.session)!
        gate.finished(gate.take(wakeFailure)!, succeeded: false)
        let newWake = gate.wake(original, session: gate.session)!
        try expect(gate.take(newWake)?.retrying == false, "新的系统唤醒必须失效一次旧 DNS 资源")

        _ = gate.begin(seed: original, boundInterface: "en0")
        let originalAuthority = gate.observe(sample(gateway: "192.0.2.254"), session: gate.session)!
        let nextAuthority = gate.reissuePending(originalAuthority)!
        try expect(originalAuthority != nextAuthority && gate.take(originalAuthority) == nil,
                   "配置更新必须换发新票据，旧回调不得消费新动作")
        let nextAuthorityAction = gate.take(nextAuthority)!
        try expect(!nextAuthorityAction.retrying && nextAuthorityAction.identityChanged,
                   "尚未失效的新出口动作换发票据后仍必须清理旧 DNS")
        gate.finished(nextAuthorityAction, succeeded: false)
        let originalReadiness = gate.retryReadinessSoon(session: gate.session)!
        let currentReadiness = gate.reissuePending(originalReadiness.ticket)!
        try expect(gate.take(originalReadiness.ticket) == nil &&
                   gate.reissuePending(originalReadiness.ticket) == nil,
                   "被替换的短探测不得再次换发或消费当前票据")
        let currentReadinessAction = gate.take(currentReadiness)!
        try expect(currentReadinessAction.retrying && currentReadinessAction.identityChanged,
                   "已失效动作换发权限后不能重复清理 DNS")
        gate.finished(currentReadinessAction, succeeded: false)
        let remainingReadiness = gate.retryReadinessSoon(session: gate.session)!
        try expect(remainingReadiness.delay == 0.4, "配置票据换发不得补充短重试预算")
        gate.stop()
        try expect(gate.reissuePending(remainingReadiness.ticket) == nil,
                   "停止会话后不得换发旧配置的恢复权限")

        let bounded = EnhancedNetworkSnapshot(available: true, interfaceName: String(repeating: "x", count: 1_000),
            interfaceIndex: 4, addresses: (0..<1_000).map { "address-\($0)" },
            gateways: (0..<1_000).map { "gateway-\($0)" })
        try expect(bounded.interfaceName.count <= 64 && bounded.addresses.count <= 128 &&
                   bounded.gateways.count <= 16, "通知状态必须固定有界")
    }
}

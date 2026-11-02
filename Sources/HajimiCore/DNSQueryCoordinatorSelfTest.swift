import Foundation
import HajimiDNS

/// Deterministic in-memory checks; no socket, helper or system DNS is used.
public enum DNSQueryCoordinatorSelfTest {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { "DNS 查询性能自检失败：\(message)" }
    }
    private static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(message: message) }
    }
    private static func query(_ id: UInt16, type: UInt16 = 1,
                              name: String = "cached.example.test") -> Data {
        DNSMessageInspection.query(for: name, type: type, id: id)!
    }
    private static func answer(_ query: Data, ttl: UInt32 = 60) -> Data {
        let question = DNSMessageInspection.singleQuestion(in: query)!
        var response = Data(query.prefix(question.questionEnd))
        response[2] = 0x80 | (query[query.startIndex + 2] & 1); response[3] = 0x80
        for index in 6...11 { response[index] = 0 }
        response[7] = 1
        response.append(contentsOf: [0xc0, 0x0c, UInt8(question.type >> 8), UInt8(truncatingIfNeeded: question.type), 0, 1,
            UInt8(truncatingIfNeeded: ttl >> 24), UInt8(truncatingIfNeeded: ttl >> 16),
            UInt8(truncatingIfNeeded: ttl >> 8), UInt8(truncatingIfNeeded: ttl)])
        let body: Data
        switch question.type {
        case 1: body = Data([203, 0, 113, 7])
        case 28: body = Data(Array(repeating: UInt8(0), count: 15) + [1])
        case 16: body = Data([4, 116, 101, 115, 116])
        case 15: body = Data([0, 10, 0]) // MX preference, root exchange.
        case 33: body = Data([0, 0, 0, 0, 1, 187, 0]) // SRV, root target.
        case 64, 65: body = Data([0, 1, 0]) // ServiceMode, root target, no parameters.
        case 257: body = Data([0, 5] + Array("issueca.example.test".utf8))
        default: body = Data([0])
        }
        response.append(contentsOf: [UInt8(body.count >> 8), UInt8(truncatingIfNeeded: body.count)])
        response.append(body)
        return response
    }

    private static func addingNeutralOPT(_ query: Data, payload: UInt16 = 1232,
                                         options: [UInt8] = []) -> Data {
        var message = query; message[11] = 1
        message.append(contentsOf: [0, 0, 41, UInt8(payload >> 8), UInt8(truncatingIfNeeded: payload),
            0, 0, 0, 0, UInt8(options.count >> 8), UInt8(truncatingIfNeeded: options.count)])
        message.append(contentsOf: options); return message
    }

    private static func settingID(_ query: Data, _ id: UInt16) -> Data {
        var message = Data(query)
        message[0] = UInt8(id >> 8); message[1] = UInt8(truncatingIfNeeded: id)
        return message
    }
    private static func neutralPaddedAnswer(_ query: Data, ttl: UInt32 = 300) -> Data {
        let question = DNSMessageInspection.singleQuestion(in: query)!
        var response = answer(query, ttl: ttl)
        var second = Data(response.dropFirst(question.questionEnd))
        second[second.count - 1] = question.type == 1 ? 8 : 2
        response[7] = 2; response.append(second)
        let padding = 468 - response.count - 15, length = padding + 4
        precondition(padding >= 0)
        response[11] = 1
        response.append(contentsOf: [0, 0, 41, 2, 0, 0, 0, 0, 0,
            UInt8(length >> 8), UInt8(truncatingIfNeeded: length),
            0, 12, UInt8(padding >> 8), UInt8(truncatingIfNeeded: padding)])
        response.append(Data(repeating: 0, count: padding))
        return response
    }
    private final class Clock {
        private let lock = NSLock()
        private var seconds: TimeInterval = 100
        func set(_ value: TimeInterval) { lock.lock(); seconds = value; lock.unlock() }
        func now() -> Date { lock.lock(); defer { lock.unlock() }; return Date(timeIntervalSince1970: seconds) }
    }
    private final class MemoryTransport: NativeRoutedDatagram {
        private let lock = NSLock()
        private let receive: (Data) -> Void
        private var query: Data?
        private var cancellations = 0
        init(receive: @escaping (Data) -> Void) { self.receive = receive }
        func send(_ data: Data) { lock.lock(); query = data; lock.unlock() }
        func cancel() { lock.lock(); cancellations += 1; lock.unlock() }
        var cancelCount: Int { lock.lock(); defer { lock.unlock() }; return cancellations }
        var sentID: UInt16? {
            lock.lock(); defer { lock.unlock() }
            guard let query, query.count >= 2 else { return nil }
            return UInt16(query[query.startIndex]) << 8 | UInt16(query[query.startIndex + 1])
        }
        func reply(ttl: UInt32 = 60, wrongID: Bool = false, rcode: UInt8 = 0, empty: Bool = false) throws {
            lock.lock(); let message = query; lock.unlock()
            guard let message else { throw Failure(message: "上游还未收到查询") }
            var response: Data
            if empty || rcode != 0 {
                let question = DNSMessageInspection.singleQuestion(in: message)!
                response = Data(message.prefix(question.questionEnd))
                response[2] = 0x81; response[3] = 0x80 | (rcode & 0x0f)
                for index in 6...11 { response[index] = 0 }
            } else { response = answer(message, ttl: ttl) }
            if wrongID { response[1] ^= 1 }
            // Deliberately allow late callbacks after cancellation so stale
            // operation tokens, not the fixture, provide the protection.
            receive(response)
        }
        func replyNeutralPadding(ttl: UInt32 = 300) throws {
            lock.lock(); let message = query; lock.unlock()
            guard let message else { throw Failure(message: "中性 padding 上游还未收到查询") }
            receive(neutralPaddedAnswer(message, ttl: ttl))
        }
    }
    private final class Harness {
        private let lock = NSLock()
        private var values: [MemoryTransport] = []
        var transports: [MemoryTransport] { lock.lock(); defer { lock.unlock() }; return values }
        var factory: DNSQueryCoordinator.Factory {
            { _, receive, _ in
                let value = MemoryTransport(receive: receive)
                self.lock.lock(); self.values.append(value); self.lock.unlock()
                return value
            }
        }
    }
    private final class DeadlineMemoryTransport: NativeRoutedDatagram, DNSQueryDeadlineAwareDatagram {
        struct Receipt {
            let query: Data?
            let sends: [UInt64]
            let cancellations: [UInt64]
            let deadlines: [UInt64]
        }
        let sent = DispatchSemaphore(value: 0)
        let terminated = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private let receive: (Data) -> Void
        private var message: Data?
        private var sends: [UInt64] = [], cancellations: [UInt64] = [], deadlines: [UInt64] = []
        init(receive: @escaping (Data) -> Void) { self.receive = receive }
        func send(_ data: Data) {
            let entered = DispatchTime.now().uptimeNanoseconds
            lock.lock(); message = data; sends.append(entered); lock.unlock()
            sent.signal()
        }
        func cancel() {
            let entered = DispatchTime.now().uptimeNanoseconds
            lock.lock(); cancellations.append(entered); lock.unlock()
            terminated.signal()
        }
        func queryDeadlineReached() {
            let entered = DispatchTime.now().uptimeNanoseconds
            lock.lock(); deadlines.append(entered); lock.unlock()
            terminated.signal()
        }
        var receipt: Receipt {
            lock.lock(); defer { lock.unlock() }
            return Receipt(query: message, sends: sends, cancellations: cancellations, deadlines: deadlines)
        }
        func reply() throws {
            lock.lock(); let query = message; lock.unlock()
            guard let query else { throw Failure(message: "deadline 子查询尚未实际 send") }
            // Do not hide a stale callback or suppress duplicate cleanup in
            // this fixture; production operation tokens must reject it.
            receive(answer(query))
        }
    }
    private final class DeadlineHarness {
        private let lock = NSLock()
        private var owner: DispatchQueue?
        private var children: [DeadlineMemoryTransport] = []
        var receipt: (owner: DispatchQueue?, children: [DeadlineMemoryTransport]) {
            lock.lock(); defer { lock.unlock() }; return (owner, children)
        }
        var factory: DNSQueryCoordinator.Factory {
            { owner, receive, _ in
                let child = DeadlineMemoryTransport(receive: receive)
                self.lock.lock(); self.owner = owner; self.children.append(child); self.lock.unlock()
                return child
            }
        }
    }
    private final class OwnerQueueGate {
        struct Receipt {
            let entered: UInt64?
            let returned: UInt64?
            let released: Bool
            let actionFence: UInt64?
            let childAtFence: DeadlineMemoryTransport.Receipt?
        }
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let returned = DispatchSemaphore(value: 0)
        let actionFence = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var enteredAt: UInt64?, returnedAt: UInt64?
        private var released = false
        private var actionFenceAt: UInt64?
        private var childAtFence: DeadlineMemoryTransport.Receipt?
        func start(on owner: DispatchQueue) {
            owner.async {
                self.lock.lock(); self.enteredAt = DispatchTime.now().uptimeNanoseconds; self.lock.unlock()
                self.entered.signal()
                let result = self.release.wait(timeout: .now() + 1)
                self.lock.lock()
                self.returnedAt = DispatchTime.now().uptimeNanoseconds
                self.released = result == .success
                self.lock.unlock()
                self.returned.signal()
            }
        }
        func enqueueActionFence(on owner: DispatchQueue, child: DeadlineMemoryTransport) {
            owner.async {
                let entered = DispatchTime.now().uptimeNanoseconds, receipt = child.receipt
                self.lock.lock(); self.actionFenceAt = entered; self.childAtFence = receipt; self.lock.unlock()
                self.actionFence.signal()
            }
        }
        var receipt: Receipt {
            lock.lock(); defer { lock.unlock() }
            return Receipt(entered: enteredAt, returned: returnedAt, released: released,
                           actionFence: actionFenceAt, childAtFence: childAtFence)
        }
    }
    private final class CompletionLedger {
        struct Receipt: Equatable {
            let role: String
            let hasAnswer: Bool
            let entered: UInt64
        }
        private let lock = NSLock()
        private var values: [Receipt] = []
        func callback(for role: String) -> (Data?) -> Void {
            { response in
                let receipt = Receipt(role: role, hasAnswer: response != nil,
                                      entered: DispatchTime.now().uptimeNanoseconds)
                self.lock.lock(); self.values.append(receipt); self.lock.unlock()
            }
        }
        var receipts: [Receipt] { lock.lock(); defer { lock.unlock() }; return values }
    }
    private enum DelayedTermination: String, CaseIterable {
        case ordinaryCancellation, explicitDeadline, leaderWithFollower
        case revokedEpochDeadline, epochInvalidation, naturalDeadline
    }
    private final class Results {
        let group = DispatchGroup()
        private let lock = NSLock()
        private var failures = 0
        func callback(for query: Data, shouldFail: Bool = false) -> (Data?) -> Void {
            group.enter()
            return { response in
                let valid = shouldFail ? response == nil
                    : response.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true
                self.lock.lock(); if !valid { self.failures += 1 }; self.lock.unlock()
                self.group.leave()
            }
        }
        func wait() throws {
            try require(group.wait(timeout: .now() + 3) == .success, "回调未按时完成")
            lock.lock(); let count = failures; lock.unlock()
            try require(count == 0, "客户端收到错误 ID、问题或失败状态")
        }
    }
    private final class Epoch {
        private let lock = NSLock()
        private var value = true
        var permitted: Bool { lock.lock(); defer { lock.unlock() }; return value }
        func set(_ value: Bool) { lock.lock(); self.value = value; lock.unlock() }
    }
    private static let callbackQueue = DispatchQueue(label: "app.hajimi.dns.coordinator.self-test")

    public static func run() throws {
        try burstAndCache()
        try neutralPaddingBurstAndCache()
        try scopeAndFamilyIsolation()
        try cancellationAndLateReplies()
        try epochAndInvalidation()
        try failureBoundsAndTimeout()
        try diagnosticOutcomeSemantics()
        try uncachedTypeSingleFlight()
        try serviceRecordBurstAndCache()
        try exactWireSingleFlightIsolation()
        try authenticatedAdditionsRemainIndependent()
        try metaQueryTypesRemainIndependent()
        try crossScopeBackpressureBurst()
        try queuedFIFOAndCancellation()
        try queuedCacheRecheck()
        try queuedDeadlinesAndFollowers()
        try delayedCancellationProvenance()
        try queuedEpochAndLateReplies()
        try throwingFactoryPump()
    }

    private static func burstAndCache() throws {
        let coordinator = DNSQueryCoordinator(), harness = Harness(), results = Results()
        for id in UInt16(1)...32 {
            let message = query(id)
            coordinator.resolve(scope: "same-policy", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
        }
        let cold = coordinator.statistics
        try require(cold.upstreamQueries == 1 && cold.mergedQueries == 31 && cold.waitingClients == 32,
                    "32 个相同问题没有合并成一次上游交换")
        try harness.transports[0].reply()
        try results.wait()
        for id in UInt16(100)...131 {
            let message = query(id)
            coordinator.resolve(scope: "same-policy", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
        }
        try results.wait()
        let warm = coordinator.statistics
        try require(warm.upstreamQueries == 1 && warm.cacheHits == 32
                    && warm.pendingQueries == 0 && warm.waitingClients == 0,
                    "热缓存重复拨号或遗留 waiter")
        print("DNS query performance check passed: 32 concurrent + 32 warm queries, 1 upstream exchange, 31 merged, 32 cache hits")
    }

    private static func uncachedTypeSingleFlight() throws {
        let cache = DNSQueryCache(), diagnostics = NetworkPerformanceDiagnostics()
        let coordinator = DNSQueryCoordinator(cache: cache, diagnostics: diagnostics)
        let harness = Harness(), results = Results()
        let types = [UInt16(16), 15, 33, 257]
        for (typeIndex, type) in types.enumerated() {
            for index in 0..<32 {
                let message = query(UInt16(0x8800 + typeIndex * 32 + index), type: type)
                coordinator.resolve(scope: "same-uncached-policy", query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
            }
        }
        let cold = coordinator.statistics
        try require(cold.upstreamQueries == 4 && cold.mergedQueries == 124 && cold.waitingClients == 128
                    && cold.pendingQueries == 4 && harness.transports.count == 4,
                    "TXT/MX/SRV/CAA 同型在途问题未合并，或不同 QTYPE 被串答")
        try harness.transports.forEach { try $0.reply() }; try results.wait()
        try require(cache.usage.entries == 0 && coordinator.statistics.cacheHits == 0,
                    "仅合并类型错误扩大了持久缓存资格")
        for (index, type) in types.enumerated() {
            let message = query(UInt16(0x8900 + index), type: type)
            coordinator.resolve(scope: "same-uncached-policy", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
        }
        let next = coordinator.statistics
        try require(next.upstreamQueries == 8 && next.cacheHits == 0 && next.mergedQueries == 124
                    && harness.transports.count == 8,
                    "已完成 TXT/MX/SRV/CAA 问题被当作缓存或残留 single-flight 复用")
        try harness.transports.dropFirst(4).forEach { try $0.reply() }; try results.wait()
        try require(coordinator.statistics.pendingQueries == 0 && cache.usage.entries == 0
                    && diagnostics.snapshot().dnsFailures == 0
                    && diagnostics.snapshot().dnsCacheBypassedQueries == 132
                    && diagnostics.snapshot().dnsCacheEligibleQueries == 0,
                    "非地址合并的客户端 ID、后续新交换或 cleanup 失败")
        print("DNS merge-only single-flight passed: 128 TXT/MX/SRV/CAA clients, 4 strict type-specific exchanges, correct IDs and no warm response caching")
    }

    private static func serviceRecordBurstAndCache() throws {
        let diagnostics = NetworkPerformanceDiagnostics(), cache = DNSQueryCache()
        let coordinator = DNSQueryCoordinator(cache: cache, diagnostics: diagnostics)
        let harness = Harness(), results = Results(), types: [UInt16] = [64, 65]
        for (typeIndex, type) in types.enumerated() {
            for index in 0..<32 {
                let message = query(UInt16(0x8a00 + typeIndex * 32 + index), type: type)
                coordinator.resolve(scope: "service-records", query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
            }
        }
        let cold = coordinator.statistics
        try require(cold.upstreamQueries == 2 && cold.mergedQueries == 62 && cold.waitingClients == 64,
                    "HTTPS/SVCB 并发问题未保持 QTYPE 隔离与单飞")
        try harness.transports.forEach { try $0.reply() }; try results.wait()
        for (index, type) in types.enumerated() {
            let message = query(UInt16(0x8b00 + index), type: type)
            coordinator.resolve(scope: "service-records", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
        }
        try results.wait()
        let warm = coordinator.statistics, measured = diagnostics.snapshot()
        try require(warm.upstreamQueries == 2 && warm.cacheHits == 2 && warm.pendingQueries == 0
                    && harness.transports.count == 2 && cache.usage.entries == 2
                    && measured.dnsCacheEligibleQueries == 66 && measured.dnsCacheStoredResponses == 2
                    && measured.dnsCacheRejectedResponses == 0 && measured.dnsCacheBypassedQueries == 0,
                    "HTTPS/SVCB 正答没有安全缓存、重复交换或缓存资格诊断错误")
        let uncacheable = query(0x8b10, type: 65, name: "zero-ttl-service.example.test")
        coordinator.resolve(scope: "service-records", query: uncacheable, callbackQueue: callbackQueue,
            permitted: { true }, factory: harness.factory, completion: results.callback(for: uncacheable))
        _ = coordinator.statistics
        try harness.transports.last!.reply(ttl: 0); try results.wait()
        try require(diagnostics.snapshot().dnsCacheRejectedResponses == 1
                    && cache.lookup(scopeKey: "service-records", query: uncacheable) == nil,
                    "TTL=0 应答被保存或未存原因不可见")
        print("DNS HTTPS/SVCB cache passed: 64 concurrent clients, 2 exchanges, 2 warm hits, exact IDs and TTL-zero exclusion")
    }

    private static func exactWireSingleFlightIsolation() throws {
        let diagnostics = NetworkPerformanceDiagnostics()
        let coordinator = DNSQueryCoordinator(diagnostics: diagnostics), harness = Harness(), results = Results()
        let base = query(0x9000, type: 16)
        var noRecursion = base; noRecursion[2] = 0
        var aware = base; aware[3] = 0x20
        let values: [(String, Data)] = [
            ("source-A", base), ("source-A", noRecursion), ("source-A", aware),
            ("source-A", query(0x9000, type: 16, name: "CACHED.example.test")),
            ("source-A", query(0x9000, type: 64)), ("source-B", base),
            ("source-A", addingNeutralOPT(base)), ("source-A", addingNeutralOPT(base, payload: 512)),
            ("source-A", addingNeutralOPT(base, options: [0, 12, 0, 1, 0])),
            ("source-A", addingNeutralOPT(base, options: [0, 12, 0, 2, 0, 0]))
        ]
        for (index, value) in values.enumerated() {
            for offset in 0..<2 {
                let message = settingID(value.1, UInt16(0x9000 + index * 2 + offset))
                coordinator.resolve(scope: value.0, query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
            }
        }
        let cold = coordinator.statistics
        try require(cold.upstreamQueries == values.count && cold.mergedQueries == values.count
                    && cold.waitingClients == values.count * 2 && harness.transports.count == values.count,
                    "单飞规范化了 type/case/RD/AD/payload/padding，或跨 source scope 共享")
        try harness.transports.forEach { try $0.reply() }; try results.wait()
        try require(diagnostics.snapshot().dnsFailures == 0 && coordinator.statistics.cacheHits == 0,
                    "精确能力隔离后客户端 ID 或完成响应错误")
        print("DNS exact single-flight isolation passed: query type/case/RD/AD, OPT payload/padding and strict source scopes remain distinct")
    }

    private static func authenticatedAdditionsRemainIndependent() throws {
        let diagnostics = NetworkPerformanceDiagnostics()
        let coordinator = DNSQueryCoordinator(diagnostics: diagnostics), harness = Harness(), results = Results()
        let base = query(0xa000, type: 65)
        var cd = base; cd[3] = 0x10
        var dnssec = addingNeutralOPT(base); dnssec[dnssec.count - 4] = 0x80
        func addingOpaqueRecord(_ type: UInt16) -> Data {
            var message = base; message[11] = 1
            message.append(contentsOf: [0, UInt8(type >> 8), UInt8(truncatingIfNeeded: type),
                0, 255, 0, 0, 0, 0, 0, 1, 0])
            return message
        }
        let unsafe = [cd, dnssec,
            addingNeutralOPT(base, options: [0, 10, 0, 8] + Array(repeating: 0, count: 8)),
            addingNeutralOPT(base, options: [0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2]),
            addingOpaqueRecord(250), addingOpaqueRecord(24), addingOpaqueRecord(65_000)]
        for (index, value) in unsafe.enumerated() {
            try require(DNSQueryCache.coalescingIdentity(for: value) == nil, "认证/复杂问题错误获得单飞资格")
            for offset in 0..<2 {
                let message = settingID(value, UInt16(0xa000 + index * 2 + offset))
                coordinator.resolve(scope: "same-authenticated-policy", query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
            }
        }
        let cold = coordinator.statistics
        try require(cold.upstreamQueries == unsafe.count * 2 && cold.mergedQueries == 0
                    && harness.transports.count == unsafe.count * 2,
                    "CD/DO/TSIG/SIG0/ECS/COOKIE/未知 addition 被按除 ID 外相同的问题合并")
        try harness.transports.forEach { try $0.reply() }; try results.wait()
        try require(coordinator.statistics.pendingQueries == 0 && diagnostics.snapshot().dnsFailures == 0,
                    "未合并的复杂问题丢失原始 ID 或未正确 cleanup")
        print("DNS authenticated query isolation passed: CD/DO/TSIG/SIG0/ECS/COOKIE/unknown additions each retain independent in-flight work")
    }

    private static func metaQueryTypesRemainIndependent() throws {
        let diagnostics = NetworkPerformanceDiagnostics()
        let coordinator = DNSQueryCoordinator(diagnostics: diagnostics), harness = Harness(), results = Results()
        let types = [UInt16(65_280), 252, 251, 255, 249, 250, 41, 24]
        for (index, type) in types.enumerated() {
            for offset in 0..<2 {
                let message = query(UInt16(0xa100 + index * 2 + offset), type: type)
                try require(DNSQueryCache.coalescingIdentity(for: message) == nil,
                            "简单 unsigned header 为未知/meta/transfer QTYPE 授予单飞资格")
                coordinator.resolve(scope: "same-meta-query-policy", query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
            }
        }
        let cold = coordinator.statistics
        try require(cold.upstreamQueries == types.count * 2 && cold.mergedQueries == 0
                    && harness.transports.count == types.count * 2,
                    "未知、AXFR/IXFR/ANY/TKEY/TSIG/OPT/SIG 类型被仅按去 ID 的简单头合并")
        try harness.transports.forEach { try $0.reply(empty: true) }; try results.wait()
        try require(coordinator.statistics.pendingQueries == 0 && coordinator.statistics.cacheHits == 0
                    && diagnostics.snapshot().dnsFailures == 0,
                    "meta QTYPE 独立事务丢失 ID、意外缓存或遗留 in-flight 工作")
        print("DNS meta-query isolation passed: unknown/AXFR/IXFR/ANY/TKEY/TSIG/OPT/SIG simple headers stay independently routed")
    }

    private static func crossScopeBackpressureBurst() throws {
        for count in [192, 256] {
            let diagnostics = NetworkPerformanceDiagnostics(), coordinator = DNSQueryCoordinator(diagnostics: diagnostics)
            let harness = Harness(), results = Results()
            for index in 0..<count {
                let message = query(UInt16(0x2000 + index))
                coordinator.resolve(scope: "bounded-scope-\(index)", query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
            }
            let cold = coordinator.statistics
            try require(cold.activeUpstreams == 16 && cold.queuedUpstreams == count - 16
                        && cold.pendingQueries == count && cold.waitingClients == count
                        && cold.upstreamQueries == 16 && harness.transports.count == 16,
                        "跨 scope 峰值未排队，或运行数超过 16，或仍被旧 128 leader 门槛拒绝")
            var replied = 0, peak = cold.activeUpstreams
            while replied < count {
                let values = harness.transports
                try require(values.count > replied && values.count - replied <= 16,
                            "等待 leader 没有前进，或一次发起超过 16 个新上游")
                for transport in values.dropFirst(replied) { try transport.reply() }
                replied = values.count
                let progress = coordinator.statistics
                peak = max(peak, progress.activeUpstreams)
                try require(progress.activeUpstreams <= 16
                            && progress.activeUpstreams + progress.queuedUpstreams == progress.pendingQueries,
                            "FIFO 推进时遗留/重复运行名额或突破全局并发上限")
            }
            try results.wait()
            let drained = coordinator.statistics, snapshot = diagnostics.snapshot()
            try require(peak == 16 && drained.upstreamQueries == count && drained.waitingClients == 0
                        && drained.pendingQueries == 0 && drained.activeUpstreams == 0 && drained.queuedUpstreams == 0
                        && snapshot.dnsFailures == 0 && snapshot.dnsFailureReasons.isEmpty
                        && harness.transports.allSatisfy({ $0.cancelCount == 1 }),
                        "跨 scope 有界峰值错误、失败被隐藏，或完成后遗留 FIFO/transport")
            for index in 0..<count {
                let message = query(UInt16(0x3000 + index))
                coordinator.resolve(scope: "bounded-scope-\(index)", query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
            }
            try results.wait()
            let warm = coordinator.statistics
            try require(warm.cacheHits == count && warm.upstreamQueries == count && warm.mergedQueries == 0
                        && harness.transports.count == count && warm.waitingClients == 0,
                        "跨 scope 暖查询重复拨号、错误合并或未保留每个客户端的 ID")
        }
        print("DNS global backpressure checks passed: 192/256 distinct strict scopes, 16 live leaders, FIFO waves, zero capacity failures and isolated warm answers")
    }

    private static func queuedFIFOAndCancellation() throws {
        let diagnostics = NetworkPerformanceDiagnostics()
        let coordinator = DNSQueryCoordinator(maximumPending: 4, maximumWaiters: 8,
                                              maximumActiveUpstreams: 1, diagnostics: diagnostics)
        let harness = Harness(), results = Results(), cancelled = Epoch()
        var canceledID: UUID?
        for index in 0..<5 {
            let message = query(UInt16(0x4100 + index))
            let completion: (Data?) -> Void = index == 2
                ? { _ in cancelled.set(false) }
                : results.callback(for: message, shouldFail: index == 4)
            let id = coordinator.resolve(scope: "fifo-\(index)", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: completion)
            if index == 2 { canceledID = id }
        }
        let full = coordinator.statistics
        try require(full.activeUpstreams == 1 && full.queuedUpstreams == 3 && full.pendingQueries == 4
                    && harness.transports.count == 1, "显式总 leader 小限额不再生效")
        coordinator.cancel(canceledID!)
        let trimmed = coordinator.statistics
        try require(trimmed.queuedUpstreams == 2 && trimmed.pendingQueries == 3 && trimmed.waitingClients == 3,
                    "取消排队 leader 没有删除 FIFO/载荷名额")
        for expected in [UInt16(0x4100), 0x4101, 0x4103] {
            let transport = harness.transports.last!
            try require(transport.sentID == expected, "FIFO 越序或被取消的 leader 获得 factory")
            try transport.reply()
            _ = coordinator.statistics
        }
        try results.wait(); callbackQueue.sync {}
        let drained = coordinator.statistics, snapshot = diagnostics.snapshot()
        try require(cancelled.permitted && drained.pendingQueries == 0 && drained.queuedUpstreams == 0
                    && drained.activeUpstreams == 0 && harness.transports.count == 3
                    && snapshot.dnsFailureReasons == [.capacity: 1] && snapshot.dnsCancelledQueries == 1,
                    "真实容量拒绝被隐藏/泛化，或排队取消被交付/重拨")
        print("DNS queued FIFO checks passed: explicit total bounds, stable order, eager canceled-entry removal and genuine capacity diagnostics")
    }

    private static func queuedCacheRecheck() throws {
        let clock = Clock(), diagnostics = NetworkPerformanceDiagnostics()
        let cache = DNSQueryCache(clock: clock.now)
        let coordinator = DNSQueryCoordinator(cache: cache, maximumActiveUpstreams: 1, diagnostics: diagnostics)
        let harness = Harness(), results = Results()
        let first = query(0x5100), queued = query(0x5101)
        for (scope, message) in [("cache-blocker", first), ("cache-warmed-while-waiting", queued)] {
            coordinator.resolve(scope: scope, query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
        }
        let cold = coordinator.statistics
        try require(cold.activeUpstreams == 1 && cold.queuedUpstreams == 1 && harness.transports.count == 1,
                    "缓存重查样本没有真实排队")
        try require(cache.store(scopeKey: "cache-warmed-while-waiting", query: queued, response: answer(queued)),
                    "排队期间不能准备安全暖答案")
        clock.set(100.75)
        try harness.transports[0].reply(); try results.wait()
        let warm = coordinator.statistics
        try require(warm.upstreamQueries == 1 && warm.cacheHits == 1 && warm.pendingQueries == 0
                    && warm.activeUpstreams == 0 && warm.queuedUpstreams == 0 && harness.transports.count == 1
                    && diagnostics.snapshot().dnsFailures == 0
                    && diagnostics.snapshot().dnsCacheEligibleQueries == 2
                    && diagnostics.snapshot().dnsCacheBypassedQueries == 0
                    && diagnostics.snapshot().dnsCacheStoredResponses == 1,
                    "等待期间已暖缓存仍启动第二次上游，或缓存重查绕过原 scope")
        clock.set(159.9)
        try require(cache.lookup(scopeKey: "cache-warmed-while-waiting", query: queued) != nil,
                    "出队缓存交付重新存储取整 TTL，提前缩短了原应答寿命")
        clock.set(160)
        try require(cache.lookup(scopeKey: "cache-warmed-while-waiting", query: queued) == nil,
                    "出队缓存交付没有保留原应答到期时刻")
        print("DNS queued cache recheck passed: safe scoped answer, no extra factory/dial, original expiry preserved")
    }

    private static func queuedDeadlinesAndFollowers() throws {
        do {
            let diagnostics = NetworkPerformanceDiagnostics()
            let coordinator = DNSQueryCoordinator(maximumActiveUpstreams: 1, diagnostics: diagnostics)
            let harness = Harness(), results = Results(), canceled = Epoch()
            let blocker = query(0x6000), leader = query(0x6001), follower = query(0x6002)
            coordinator.resolve(scope: "queued-leader-cancel-blocker", query: blocker, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: blocker))
            let id = coordinator.resolve(scope: "queued-leader-cancel", query: leader, callbackQueue: callbackQueue,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2,
                permitted: { true }, factory: harness.factory) { _ in canceled.set(false) }
            let deadline = coordinator.deadlineForSelfTest(scope: "queued-leader-cancel", query: leader)
            coordinator.resolve(scope: "queued-leader-cancel", query: follower, callbackQueue: callbackQueue,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 3,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: follower))
            coordinator.cancel(id)
            let afterCancel = coordinator.statistics
            try require(afterCancel.waitingClients == 2 && afterCancel.queuedUpstreams == 1
                        && deadline != nil && deadline == coordinator.deadlineForSelfTest(scope: "queued-leader-cancel", query: follower),
                        "取消排队 leader 移除 follower 或延长原始上游期限")
            try harness.transports[0].reply()
            _ = coordinator.statistics
            try require(harness.transports.count == 2 && harness.transports[1].sentID == 0x6001,
                        "leader 取消后排队 follower 没有共享原查询/factory")
            try harness.transports[1].reply(); try results.wait(); callbackQueue.sync {}
            try require(canceled.permitted && diagnostics.snapshot().dnsCancelledQueries == 1
                        && diagnostics.snapshot().dnsFailures == 0,
                        "排队 leader 取消仍被交付，或 follower 的独立 ID 被丢失")
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics()
            let coordinator = DNSQueryCoordinator(maximumActiveUpstreams: 1, diagnostics: diagnostics)
            let harness = Harness(), results = Results()
            let blocker = query(0x6100), queued = query(0x6101), timedFollower = query(0x6102)
            coordinator.resolve(scope: "deadline-blocker", query: blocker, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: blocker))
            coordinator.resolve(scope: "deadline-queued", query: queued, callbackQueue: callbackQueue,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: queued))
            let deadline = coordinator.deadlineForSelfTest(scope: "deadline-queued", query: queued)
            let expired = DispatchSemaphore(value: 0), follower = results.callback(for: timedFollower, shouldFail: true)
            coordinator.resolve(scope: "deadline-queued", query: timedFollower, callbackQueue: callbackQueue,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 0.05,
                permitted: { true }, factory: harness.factory) { response in follower(response); expired.signal() }
            try require(expired.wait(timeout: .now() + 2) == .success, "排队 follower 没有按更早的原始期限结束")
            let afterFollower = coordinator.statistics
            try require(afterFollower.waitingClients == 2 && afterFollower.pendingQueries == 2
                        && afterFollower.activeUpstreams == 1 && afterFollower.queuedUpstreams == 1
                        && harness.transports.count == 1,
                        "更短 follower 期限取消了 leader/其他来源，或已失效等待项仍消耗名额")
            try harness.transports[0].reply()
            _ = coordinator.statistics
            try require(deadline != nil && deadline == coordinator.deadlineForSelfTest(scope: "deadline-queued", query: queued)
                        && harness.transports.count == 2,
                        "leader 出队重新获得计时预算，或存活 leader 未获上游")
            try harness.transports[1].reply(); try results.wait()
            try require(diagnostics.snapshot().dnsFailureReasons == [.timeout: 1],
                        "较短 follower 的真实 timeout 被抹掉或误计容量")
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics()
            let coordinator = DNSQueryCoordinator(maximumActiveUpstreams: 1, diagnostics: diagnostics)
            let harness = Harness(), results = Results()
            let blocker = query(0x6200), queued = query(0x6201)
            coordinator.resolve(scope: "queued-total-blocker", query: blocker, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: blocker))
            let expired = DispatchSemaphore(value: 0), completion = results.callback(for: queued, shouldFail: true)
            coordinator.resolve(scope: "queued-total-timeout", query: queued, callbackQueue: callbackQueue,
                absoluteDeadline: ProcessInfo.processInfo.systemUptime + 0.05,
                permitted: { true }, factory: harness.factory) { response in completion(response); expired.signal() }
            try require(expired.wait(timeout: .now() + 2) == .success, "queued leader 未消耗原始总期限")
            let timed = coordinator.statistics
            try require(timed.activeUpstreams == 1 && timed.queuedUpstreams == 0 && timed.waitingClients == 1
                        && harness.transports.count == 1, "已经失效的 queued leader 发起连接或遗留 FIFO")
            try harness.transports[0].reply(); try results.wait()
            try require(diagnostics.snapshot().dnsFailureReasons == [.timeout: 1], "排队总期限被错计为取消/容量")
        }
        do {
            // Hold only this fixture's coordinator queue. Both budgets start
            // at resolve(), so queue admission cannot grant a fresh deadline.
            let diagnostics = NetworkPerformanceDiagnostics()
            let coordinator = DNSQueryCoordinator(timeout: .milliseconds(50), diagnostics: diagnostics)
            let harness = Harness(), results = Results()
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let first = query(0x6300), second = query(0x6301)
            defer { release.signal() }
            coordinator.resolve(scope: "admission-blocker", query: first, callbackQueue: callbackQueue,
                permitted: { true }, factory: { queue, receive, failure in
                    entered.signal()
                    guard release.wait(timeout: .now() + 1) == .success else { throw DNSQueryTimeoutError() }
                    return try harness.factory(queue, receive, failure)
                }, completion: results.callback(for: first, shouldFail: true))
            try require(entered.wait(timeout: .now() + 1) == .success, "无法准备 queue-admission 边界")
            coordinator.resolve(scope: "admission-already-expired", query: second, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory,
                completion: results.callback(for: second, shouldFail: true))
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { release.signal() }
            try results.wait()
            let drained = coordinator.statistics
            try require(harness.transports.count == 1 && harness.transports[0].sentID == nil
                        && drained.upstreamQueries == 0 && drained.pendingQueries == 0
                        && diagnostics.snapshot().dnsFailureReasons == [.timeout: 2],
                        "owner queue 等待未计入期限，或超时之后仍 send/拨第二条连接")
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics(), cache = DNSQueryCache()
            let coordinator = DNSQueryCoordinator(cache: cache, maximumPending: 0, diagnostics: diagnostics)
            let harness = Harness(), results = Results()
            let handoff = DispatchQueue(label: "app.hajimi.dns.self-test.delayed-handoff")
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            defer { release.signal() }
            handoff.async { entered.signal(); _ = release.wait(timeout: .now() + 2) }
            try require(entered.wait(timeout: .now() + 1) == .success, "无法准备单独的 callback handoff 边界")
            let lateAnswer = query(0x6400), knownCapacity = query(0x6401)
            try require(cache.store(scopeKey: "late-handoff-answer", query: lateAnswer, response: answer(lateAnswer)),
                        "无法准备已缓存 handoff 答案")
            let deadline = ProcessInfo.processInfo.systemUptime + 0.5
            for (scope, message) in [("late-handoff-answer", lateAnswer), ("late-handoff-capacity", knownCapacity)] {
                coordinator.resolve(scope: scope, query: message, callbackQueue: handoff,
                    absoluteDeadline: deadline, permitted: { true }, factory: harness.factory,
                    completion: results.callback(for: message, shouldFail: scope == "late-handoff-capacity"))
            }
            let admitted = coordinator.statistics
            try require(admitted.cacheHits == 1 && harness.transports.isEmpty,
                        "handoff 样本没有在原期限内完成 cache/admission 判定")
            DispatchQueue.global().asyncAfter(deadline: .now() + max(0, deadline - ProcessInfo.processInfo.systemUptime) + 0.05) {
                release.signal()
            }
            try results.wait()
            try require(diagnostics.snapshot().dnsFailureReasons == [.capacity: 1],
                        "期限内完成的答复因交付队列被误记超时，或已知 capacity 因忙 callback 被改类")
        }
        print("DNS queued deadlines passed: invocation budget, no dequeue reset, earlier follower timeout and expired leaders create no IO")
    }

    private static func delayedCancellationProvenance() throws {
        for (index, mode) in DelayedTermination.allCases.enumerated() {
            let diagnostics = NetworkPerformanceDiagnostics(), cache = DNSQueryCache(), epoch = Epoch()
            let coordinator = DNSQueryCoordinator(cache: cache, timeout: .milliseconds(350), diagnostics: diagnostics)
            let harness = DeadlineHarness(), gate = OwnerQueueGate(), completions = CompletionLedger()
            let scope = "delayed-cancellation-\(mode.rawValue)"
            let leader = query(UInt16(0xb100 + index * 2)), follower = query(UInt16(0xb101 + index * 2))
            let hasFollower = mode == .leaderWithFollower
            var deadline: UInt64?, actionEntered: UInt64?, actionReturned: UInt64?, fenceEnqueueReturned: UInt64?
            defer {
                // These are real memory-method/queue receipts, not physical
                // socket cancellation ACKs. Nil fields retain early failures.
                let child = harness.receipt.children.first?.receipt, owner = gate.receipt
                func time(_ value: UInt64?) -> String { value.map { String($0) } ?? "nil" }
                print("DNS delayed cancellation receipt: mode=\(mode.rawValue) deadline=\(time(deadline)) sends=\(child?.sends ?? []) gateEntered=\(time(owner.entered)) actionEntered=\(time(actionEntered)) actionReturned=\(time(actionReturned)) fenceEnqueueReturned=\(time(fenceEnqueueReturned)) gateReturned=\(time(owner.returned)) gateReleased=\(owner.released) actionFenceEntered=\(time(owner.actionFence)) fenceChildCancel=\(owner.childAtFence?.cancellations ?? []) fenceChildDeadline=\(owner.childAtFence?.deadlines ?? []) childCancel=\(child?.cancellations ?? []) childDeadline=\(child?.deadlines ?? []) callbacks=\(completions.receipts)")
                gate.release.signal()
                coordinator.invalidate()
            }
            let leaderID = coordinator.resolve(scope: scope, query: leader, callbackQueue: callbackQueue,
                permitted: { epoch.permitted }, factory: harness.factory,
                completion: completions.callback(for: "leader"))
            if hasFollower {
                coordinator.resolve(scope: scope, query: follower, callbackQueue: callbackQueue,
                    permitted: { epoch.permitted }, factory: harness.factory,
                    completion: completions.callback(for: "follower"))
            }
            // Reading statistics/deadline drains admission before any gate is
            // installed. Never block the factory or its post-factory guard.
            let admitted = coordinator.statistics, fixture = harness.receipt
            guard fixture.children.count == 1, let owner = fixture.owner else {
                throw Failure(message: "\(mode.rawValue) 未获得唯一真实 owner/子查询")
            }
            let child = fixture.children[0]
            try require(child.sent.wait(timeout: .now() + 1) == .success,
                        "\(mode.rawValue) 没有在 post-factory guard 后实际 send")
            deadline = coordinator.deadlineForSelfTest(scope: scope, query: leader)
            guard let originalDeadline = deadline, let sentAt = child.receipt.sends.first else {
                throw Failure(message: "\(mode.rawValue) 缺少真实 send/原始期限")
            }
            try require(admitted.upstreamQueries == 1 && admitted.activeUpstreams == 1
                        && admitted.queuedUpstreams == 0 && admitted.waitingClients == (hasFollower ? 2 : 1)
                        && admitted.mergedQueries == (hasFollower ? 1 : 0)
                        && child.receipt.query == leader && child.receipt.sends.count == 1
                        && sentAt < originalDeadline,
                        "\(mode.rawValue) 未建立真实在途查询/follower 或 send 已越过期限")
            gate.start(on: owner)
            try require(gate.entered.wait(timeout: .now() + 1) == .success,
                        "\(mode.rawValue) 无法占用实际 coordinator owner queue")
            guard let gateEntered = gate.receipt.entered else {
                throw Failure(message: "\(mode.rawValue) 缺少 gate 入队处理回执")
            }
            try require(sentAt <= gateEntered && gateEntered < originalDeadline,
                        "\(mode.rawValue) gate 未在实际 send 后、原始期限前开始")
            if mode == .revokedEpochDeadline || mode == .epochInvalidation { epoch.set(false) }
            if mode != .naturalDeadline {
                // The actual queue.async enqueue is inside this synchronous
                // API call. Its return BEFORE the deadline proves enqueue was
                // before the deadline; neither endpoint is called an exact
                // enqueue timestamp. Child-method entry proves late processing.
                let entered = DispatchTime.now().uptimeNanoseconds
                actionEntered = entered
                switch mode {
                case .ordinaryCancellation, .leaderWithFollower: coordinator.cancel(leaderID)
                case .explicitDeadline, .revokedEpochDeadline:
                    coordinator.cancel(leaderID, deadlineExpired: true)
                case .epochInvalidation: coordinator.invalidate()
                case .naturalDeadline: break
                }
                let returned = DispatchTime.now().uptimeNanoseconds
                actionReturned = returned
                try require(entered <= returned && returned < originalDeadline,
                            "\(mode.rawValue) 实际动作未在原始期限前完成入队；不重试/不重置期限")
            }
            // This FIFO fence is also enqueued before the deadline. Its real
            // execution brackets the preceding action's processing after gate
            // return. In follower mode it must precede the real deadline timer
            // and witness zero child cleanup, not substitute its own ACK.
            gate.enqueueActionFence(on: owner, child: child)
            let fenceReturned = DispatchTime.now().uptimeNanoseconds
            fenceEnqueueReturned = fenceReturned
            try require(fenceReturned < originalDeadline,
                        "\(mode.rawValue) 实际 owner fence 未在原始期限前入队")
            DispatchQueue.global().asyncAfter(deadline: DispatchTime(uptimeNanoseconds: originalDeadline) + .milliseconds(10)) {
                gate.release.signal()
            }
            try require(gate.returned.wait(timeout: .now() + 1) == .success
                        && gate.actionFence.wait(timeout: .now() + 1) == .success
                        && child.terminated.wait(timeout: .now() + 1) == .success,
                        "\(mode.rawValue) gate/实际子查询清理未按有界预算完成")
            let drained = coordinator.statistics
            callbackQueue.sync {}
            let terminal = child.receipt, queueReceipt = gate.receipt
            guard let gateReturned = queueReceipt.returned, let fenceEntered = queueReceipt.actionFence,
                  let fencedChild = queueReceipt.childAtFence else {
                throw Failure(message: "\(mode.rawValue) 缺少实际 owner gate/fence 处理回执")
            }
            let expected: (failures: UInt64, cancellations: UInt64, callbacks: [String], childDeadline: Bool)
            switch mode {
            case .ordinaryCancellation, .revokedEpochDeadline: expected = (0, 1, [], false)
            case .explicitDeadline: expected = (1, 0, [], true)
            case .leaderWithFollower: expected = (1, 1, ["follower"], true)
            case .epochInvalidation: expected = (0, 1, ["leader"], false)
            case .naturalDeadline: expected = (1, 0, ["leader"], true)
            }
            let processing = expected.childDeadline ? terminal.deadlines : terminal.cancellations
            try require(queueReceipt.released && gateReturned >= originalDeadline && fenceEntered >= gateReturned
                        && processing.count == 1
                        && processing.first.map({ $0 >= gateReturned }) == true
                        && terminal.cancellations.count == (expected.childDeadline ? 0 : 1)
                        && terminal.deadlines.count == (expected.childDeadline ? 1 : 0),
                        "\(mode.rawValue) 普通取消/epoch 被重分类超时，真实期限被抹掉，或子清理重复/未晚于期限")
            let timerMustFollowFence = hasFollower || mode == .naturalDeadline
            try require(timerMustFollowFence
                        ? fencedChild.cancellations.isEmpty && fencedChild.deadlines.isEmpty
                            && processing.first.map({ $0 >= fenceEntered }) == true
                        : fencedChild.cancellations == terminal.cancellations
                            && fencedChild.deadlines == terminal.deadlines
                            && processing.first.map({ $0 <= fenceEntered }) == true,
                        "\(mode.rawValue) FIFO fence 未夹住动作处理，或 leader 取消提前终止 follower 的子查询")
            let calls = completions.receipts, snapshot = diagnostics.snapshot()
            let stage = snapshot.stages[.dnsResolution] ?? NetworkStageSnapshot()
            try require(calls.map(\.role) == expected.callbacks && calls.allSatisfy({ !$0.hasAnswer })
                        && stage.count == UInt64(hasFollower ? 2 : 1) && stage.sampleCount == 0
                        && stage.failureCount == expected.failures && stage.cancellationCount == expected.cancellations
                        && snapshot.dnsFailures == expected.failures && snapshot.dnsCancelledQueries == expected.cancellations
                        && snapshot.dnsFailureReasons == (expected.failures == 0 ? [:] : [.timeout: expected.failures])
                        && drained.pendingQueries == 0 && drained.waitingClients == 0
                        && drained.activeUpstreams == 0 && drained.queuedUpstreams == 0 && cache.usage.entries == 0,
                        "\(mode.rawValue) 原始诊断/客户端取消/follower/epoch 语义变化或遗留 pending")
            try child.reply(); try child.reply()
            coordinator.cancel(leaderID); coordinator.cancel(leaderID, deadlineExpired: true)
            let afterLate = coordinator.statistics
            callbackQueue.sync {}
            let final = child.receipt
            try require(final.sends == terminal.sends && final.cancellations == terminal.cancellations
                        && final.deadlines == terminal.deadlines && completions.receipts == calls
                        && diagnostics.snapshot() == snapshot && harness.receipt.children.count == 1
                        && afterLate.pendingQueries == 0 && afterLate.waitingClients == 0
                        && afterLate.activeUpstreams == 0 && afterLate.queuedUpstreams == 0 && cache.usage.entries == 0,
                        "\(mode.rawValue) 迟到回包/重复动作再次清理、重复交付/计数或复活缓存")
        }
        print("DNS delayed cancellation checks passed: actual post-send owner queue, before-deadline enqueue/after-deadline cleanup, ordinary cancellation, explicit/natural deadlines, followers, revoked epochs and exact-once stale rejection")
    }

    private static func queuedEpochAndLateReplies() throws {
        do {
            let diagnostics = NetworkPerformanceDiagnostics()
            let coordinator = DNSQueryCoordinator(maximumActiveUpstreams: 2, diagnostics: diagnostics)
            let harness = Harness(), results = Results()
            for index in 0..<32 {
                let message = query(UInt16(0x7100 + index))
                coordinator.resolve(scope: "queued-epoch-\(index)", query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory,
                    completion: results.callback(for: message, shouldFail: true))
            }
            let cold = coordinator.statistics
            try require(cold.activeUpstreams == 2 && cold.queuedUpstreams == 30, "epoch 样本缺少排队工作")
            // Even if a caller's epoch closure is unchanged, invalidate() must
            // not pump the next old factory while tearing down current IO.
            coordinator.invalidate(); try results.wait()
            let flushed = coordinator.statistics, snapshot = diagnostics.snapshot()
            try require(flushed.pendingQueries == 0 && flushed.queuedUpstreams == 0 && flushed.waitingClients == 0
                        && flushed.activeUpstreams == 0 && harness.transports.count == 2
                        && snapshot.dnsCancelledQueries == 32 && snapshot.dnsFailures == 0,
                        "invalidate 在逐项清理时启动旧排队工厂，或把 epoch 清理计成故障")
            for old in harness.transports { try old.reply() }
            _ = coordinator.statistics
            let fresh = query(0x7140)
            coordinator.resolve(scope: "queued-epoch-0", query: fresh, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: fresh))
            _ = coordinator.statistics
            try require(harness.transports.count == 3, "失效旧回复复活了缓存，或 FIFO 泵没有恢复")
            try harness.transports.last!.reply(); try results.wait()
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics()
            let coordinator = DNSQueryCoordinator(maximumActiveUpstreams: 1, diagnostics: diagnostics)
            let harness = Harness(), results = Results(), canceled = Epoch()
            let oldQuery = query(0x7200), otherQuery = query(0x7201), replacement = query(0x7202)
            let id = coordinator.resolve(scope: "queued-token-reuse", query: oldQuery, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory) { _ in canceled.set(false) }
            coordinator.resolve(scope: "queued-token-other", query: otherQuery, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: otherQuery))
            _ = coordinator.statistics
            let old = harness.transports[0]
            coordinator.cancel(id)
            _ = coordinator.statistics
            coordinator.resolve(scope: "queued-token-reuse", query: replacement, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: replacement))
            _ = coordinator.statistics
            try old.reply()
            let waiting = coordinator.statistics
            try require(waiting.pendingQueries == 2 && waiting.queuedUpstreams == 1,
                        "旧 canceled token 完成/缓存了同 key 的排队 replacement")
            try harness.transports[1].reply()
            _ = coordinator.statistics
            try require(harness.transports.count == 3 && harness.transports[2].sentID == 0x7202,
                        "replacement 复用了旧客户端事务或没有开始")
            try old.reply()
            try require(coordinator.statistics.pendingQueries == 1, "旧 callback 完成了正在运行的 replacement")
            try harness.transports[2].reply(); try results.wait(); callbackQueue.sync {}
            try require(canceled.permitted && diagnostics.snapshot().dnsCancelledQueries == 1
                        && diagnostics.snapshot().dnsFailures == 0,
                        "迟到 callback 唤醒 canceled client 或新增假失败")
        }
        print("DNS queued epoch/token checks passed: atomic old-factory revocation, restart, running cancellation and late replies cannot complete queued/running replacements")
    }

    private static func throwingFactoryPump() throws {
        let diagnostics = NetworkPerformanceDiagnostics()
        let coordinator = DNSQueryCoordinator(maximumActiveUpstreams: 1, diagnostics: diagnostics)
        let harness = Harness(), results = Results()
        for index in 0..<256 {
            let message = query(UInt16(0x8100 + index))
            let factory: DNSQueryCoordinator.Factory = index == 0 ? harness.factory : { _, _, _ in
                throw EncryptedDNSQueryFailure.network
            }
            coordinator.resolve(scope: "throwing-queued-factory-\(index)", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: factory,
                completion: results.callback(for: message, shouldFail: index != 0))
        }
        try require(coordinator.statistics.queuedUpstreams == 255 && harness.transports.count == 1,
                    "同步 throw 样本没有进入有界等待队列")
        try harness.transports[0].reply(); try results.wait()
        let drained = coordinator.statistics
        try require(drained.pendingQueries == 0 && drained.waitingClients == 0 && drained.activeUpstreams == 0
                    && drained.queuedUpstreams == 0 && drained.upstreamQueries == 1
                    && diagnostics.snapshot().dnsFailureReasons == [.upstreamOrResponse: 255],
                    "同步 throw 泵递归重入、遗留队列或掩盖实际网络失败")
        print("DNS queued factory check passed: 255 synchronous throws drain iteratively with original failure classes and no leaked slots")
    }

    private static func neutralPaddingBurstAndCache() throws {
        for type: UInt16 in [1, 28] {
            let clock = Clock(), cache = DNSQueryCache(clock: clock.now)
            let coordinator = DNSQueryCoordinator(cache: cache, diagnostics: NetworkPerformanceDiagnostics())
            let harness = Harness(), results = Results()
            let first = query(1, type: type, name: "example.com")
            let reference = neutralPaddedAnswer(first)
            let answerEnd = DNSMessageInspection.singleQuestion(in: first)!.questionEnd + 2 * (type == 1 ? 16 : 28)
            let opt = Data(reference.dropFirst(answerEnd))
            try require(reference.count == 468 && reference[7] == 2 && reference[11] == 1
                        && opt.count == (type == 1 ? 392 : 368) + 15,
                        "中性 padding 协调器回归帧未重现真实 A/AAAA 响应")
            func resolve(_ id: UInt16, scope: String, ttl: UInt32) {
                let message = query(id, type: type, name: "example.com")
                let callback = results.callback(for: message)
                coordinator.resolve(scope: scope, query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory) { response in
                    let valid = response.map { value in
                        let records = DNSMessageInspection.addressAnswers(in: value)
                        return value.count == 468 && records.count == 2 && records.allSatisfy({ $0.ttl == ttl })
                            && Data(value.suffix(opt.count)) == opt
                    } ?? false
                    callback(valid ? response : nil)
                }
            }
            for id in UInt16(1)...32 { resolve(id, scope: "neutral-primary", ttl: 300) }
            let cold = coordinator.statistics
            try require(cold.upstreamQueries == 1 && cold.mergedQueries == 31
                        && cold.waitingClients == 32 && harness.transports.count == 1,
                        "带中性 padding 的冷并发查询没有合并成一次上游")
            try harness.transports[0].replyNeutralPadding()
            try results.wait()
            clock.set(101.1)
            for id in UInt16(100)...131 { resolve(id, scope: "neutral-primary", ttl: 298) }
            try results.wait()
            let warm = coordinator.statistics
            try require(warm.upstreamQueries == 1 && warm.cacheHits == 32 && warm.mergedQueries == 31
                        && warm.pendingQueries == 0 && warm.waitingClients == 0 && harness.transports.count == 1,
                        "带中性 padding 的暖查询重复拨号、未缓存或遗留 waiter")

            clock.set(102)
            resolve(200, scope: "neutral-other-policy", ttl: 45)
            let other = coordinator.statistics
            try require(other.upstreamQueries == 2 && other.cacheHits == 32
                        && other.waitingClients == 1 && harness.transports.count == 2,
                        "中性 padding 协调器跨策略 scope 合并或缓存串答")
            try harness.transports[1].replyNeutralPadding(ttl: 45)
            try results.wait()
            clock.set(103.1)
            resolve(201, scope: "neutral-primary", ttl: 296)
            resolve(202, scope: "neutral-other-policy", ttl: 43)
            try results.wait()
            let isolated = coordinator.statistics
            try require(isolated.upstreamQueries == 2 && isolated.cacheHits == 34
                        && isolated.pendingQueries == 0 && isolated.waitingClients == 0 && cache.usage.entries == 2,
                        "中性 padding 的 scope 独立 TTL、客户端 ID 或缓存生命周期错误")
        }
        print("DNS neutral padding coordinator check passed: A/AAAA 468-byte replies, 1 primary exchange, 31 merged + 32 warm hits per family, ID/TTL/OPT and scoped isolation")
    }

    private static func scopeAndFamilyIsolation() throws {
        let coordinator = DNSQueryCoordinator(), harness = Harness(), results = Results()
        let cases: [(String, UInt16)] = [("route-A", 1), ("route-B", 1),
                                         ("interface-B", 1), ("source-B", 1), ("route-A", 28)]
        for (index, item) in cases.enumerated() {
            let message = query(UInt16(index + 1), type: item.1)
            coordinator.resolve(scope: item.0, query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
        }
        try require(coordinator.statistics.upstreamQueries == cases.count,
                    "不同策略、接口、来源或 A/AAAA 被错误合并")
        try harness.transports.forEach { try $0.reply() }
        try results.wait()
    }

    private static func cancellationAndLateReplies() throws {
        let coordinator = DNSQueryCoordinator(), harness = Harness(), results = Results()
        let cancelled = Epoch()
        let first = query(1), second = query(2)
        let leader = coordinator.resolve(scope: "cancel-leader", query: first, callbackQueue: callbackQueue,
            permitted: { true }, factory: harness.factory) { _ in cancelled.set(false) }
        coordinator.resolve(scope: "cancel-leader", query: second, callbackQueue: callbackQueue,
            permitted: { true }, factory: harness.factory, completion: results.callback(for: second))
        _ = coordinator.statistics
        coordinator.cancel(leader)
        try require(coordinator.statistics.waitingClients == 1 && harness.transports[0].cancelCount == 0,
                    "取消 leader 同时取消了其他客户端")
        try harness.transports[0].reply()
        try results.wait()
        callbackQueue.sync {}
        try require(cancelled.permitted, "已取消客户端仍收到回包")

        let old = coordinator.resolve(scope: "late", query: first, callbackQueue: callbackQueue,
            permitted: { true }, factory: harness.factory) { _ in cancelled.set(false) }
        _ = coordinator.statistics
        let oldTransport = harness.transports.last!
        coordinator.cancel(old)
        try require(coordinator.statistics.waitingClients == 0 && oldTransport.cancelCount == 1,
                    "最后一个取消的 waiter 没有释放上游")
        try oldTransport.reply()
        _ = coordinator.statistics
        coordinator.resolve(scope: "late", query: second, callbackQueue: callbackQueue,
            permitted: { true }, factory: harness.factory, completion: results.callback(for: second))
        try require(coordinator.statistics.upstreamQueries == 3, "迟到应答复活了被取消的缓存")
        try oldTransport.reply()
        try require(coordinator.statistics.pendingQueries == 1, "旧 token 完成了新的查询")
        try harness.transports.last!.reply()
        try results.wait()
        try require(cancelled.permitted, "已取消 waiter 被迟到应答唤醒")
    }

    private static func epochAndInvalidation() throws {
        let coordinator = DNSQueryCoordinator(), harness = Harness(), results = Results(), epoch = Epoch()
        let first = query(1), second = query(2)
        coordinator.resolve(scope: "epoch", query: first, callbackQueue: callbackQueue,
            permitted: { epoch.permitted }, factory: harness.factory, completion: results.callback(for: first))
        _ = coordinator.statistics
        try harness.transports[0].reply()
        try results.wait()
        epoch.set(false)
        coordinator.resolve(scope: "epoch", query: second, callbackQueue: callbackQueue,
            permitted: { epoch.permitted }, factory: harness.factory,
            completion: results.callback(for: second, shouldFail: true))
        try results.wait()
        try require(coordinator.statistics.cacheHits == 0, "过期策略仍命中旧答案")
        coordinator.invalidate()
        _ = coordinator.statistics
        epoch.set(true)
        coordinator.resolve(scope: "epoch", query: second, callbackQueue: callbackQueue,
            permitted: { epoch.permitted }, factory: harness.factory, completion: results.callback(for: second))
        try require(coordinator.statistics.upstreamQueries == 2, "清空 DNS 没有撤销缓存")
        try harness.transports.last!.reply()
        try results.wait()
        let third = query(3)
        coordinator.resolve(scope: "pending", query: third, callbackQueue: callbackQueue,
            permitted: { epoch.permitted }, factory: harness.factory,
            completion: results.callback(for: third, shouldFail: true))
        _ = coordinator.statistics
        let late = harness.transports.last!
        epoch.set(false); coordinator.invalidate()
        try results.wait()
        try late.reply()
        try require(coordinator.statistics.pendingQueries == 0, "策略失效后上游仍在途")
    }

    private static func failureBoundsAndTimeout() throws {
        let coordinator = DNSQueryCoordinator(), harness = Harness(), results = Results()
        let first = query(1)
        coordinator.resolve(scope: "bad", query: first, callbackQueue: callbackQueue,
            permitted: { true }, factory: harness.factory, completion: results.callback(for: first, shouldFail: true))
        _ = coordinator.statistics
        try harness.transports[0].reply(wrongID: true)
        try results.wait()
        coordinator.resolve(scope: "bad", query: first, callbackQueue: callbackQueue,
            permitted: { true }, factory: harness.factory, completion: results.callback(for: first))
        try require(coordinator.statistics.upstreamQueries == 2, "无效 ID 的响应被缓存")
        try harness.transports.last!.reply(ttl: 0)
        try results.wait()
        coordinator.resolve(scope: "bad", query: first, callbackQueue: callbackQueue,
            permitted: { true }, factory: harness.factory, completion: results.callback(for: first))
        try require(coordinator.statistics.upstreamQueries == 3, "TTL=0 的响应被缓存")
        try harness.transports.last!.reply()
        try results.wait()

        let bounded = DNSQueryCoordinator(maximumPending: 1, maximumWaiters: 2, maximumWaitersPerQuery: 2)
        let held = Harness(), limits = Results()
        for id in UInt16(1)...3 {
            let message = query(id)
            bounded.resolve(scope: "bounded", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: held.factory,
                completion: limits.callback(for: message, shouldFail: id == 3))
        }
        try require(bounded.statistics.upstreamQueries == 1 && bounded.statistics.waitingClients == 2,
                    "合并 waiters 绕过有界准入")
        try held.transports[0].reply()
        try limits.wait()
        try require(bounded.statistics.waitingClients == 0, "完成后未释放准入名额")

        let timed = DNSQueryCoordinator(timeout: .milliseconds(20)), silent = Harness(), deadlines = Results()
        timed.resolve(scope: "timeout", query: first, callbackQueue: callbackQueue,
            permitted: { true }, factory: silent.factory,
            completion: deadlines.callback(for: first, shouldFail: true))
        try deadlines.wait()
        try require(timed.statistics.pendingQueries == 0 && timed.statistics.waitingClients == 0
                    && silent.transports[0].cancelCount == 1, "超时后遗留连接、waiter 或计时器")
    }

    private static func diagnosticOutcomeSemantics() throws {
        func stage(_ diagnostics: NetworkPerformanceDiagnostics) -> NetworkStageSnapshot {
            diagnostics.snapshot().stages[.dnsResolution] ?? NetworkStageSnapshot()
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics()
            let coordinator = DNSQueryCoordinator(diagnostics: diagnostics), harness = Harness(), results = Results()
            // Empty NOERROR (including AAAA NODATA) and NXDOMAIN are valid
            // completed questions. SERVFAIL and REFUSED remain failures.
            for (index, code) in [UInt8(0), 3, 2, 5].enumerated() {
                let message = query(UInt16(index + 1), type: 28)
                coordinator.resolve(scope: "rcode-\(code)", query: message, callbackQueue: callbackQueue,
                    permitted: { true }, factory: harness.factory, completion: results.callback(for: message))
                _ = coordinator.statistics
                try harness.transports.last!.reply(rcode: code, empty: true)
                try results.wait()
            }
            let value = stage(diagnostics), snapshot = diagnostics.snapshot()
            try require(value.count == 4 && value.failureCount == 2 && value.cancellationCount == 0
                        && value.sampleCount == 2 && snapshot.dnsFailures == 2
                        && snapshot.dnsFailureReasons == [.upstreamOrResponse: 2],
                        "NODATA/NXDOMAIN 被误报失败，或 SERVFAIL/REFUSED 被计成成功")
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics(), epoch = Epoch()
            let coordinator = DNSQueryCoordinator(diagnostics: diagnostics), harness = Harness(), results = Results()
            let message = query(1)
            epoch.set(false)
            coordinator.resolve(scope: "old-epoch", query: message, callbackQueue: callbackQueue,
                permitted: { epoch.permitted }, factory: harness.factory,
                completion: results.callback(for: message, shouldFail: true))
            try results.wait()
            epoch.set(true)
            coordinator.resolve(scope: "invalidate", query: message, callbackQueue: callbackQueue,
                permitted: { epoch.permitted }, factory: harness.factory,
                completion: results.callback(for: message, shouldFail: true))
            _ = coordinator.statistics
            coordinator.invalidate()
            try results.wait()
            let value = stage(diagnostics), snapshot = diagnostics.snapshot()
            try require(value.count == 2 && value.failureCount == 0 && value.cancellationCount == 2
                        && value.sampleCount == 0 && snapshot.dnsFailures == 0
                        && snapshot.dnsCancelledQueries == 2 && harness.transports.count == 1,
                        "策略过期/缓存失效被混作网络失败或成功延迟")
        }
        for externalDeadline in [false, true] {
            let diagnostics = NetworkPerformanceDiagnostics(), harness = Harness(), results = Results()
            let coordinator = DNSQueryCoordinator(timeout: externalDeadline ? .seconds(8) : .milliseconds(20),
                                                   diagnostics: diagnostics)
            let message = query(1)
            let cancelled = Epoch()
            let id = coordinator.resolve(scope: "total-deadline", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory,
                completion: externalDeadline ? { _ in cancelled.set(false) }
                    : results.callback(for: message, shouldFail: true))
            if externalDeadline {
                _ = coordinator.statistics
                coordinator.cancel(id, deadlineExpired: true)
                _ = coordinator.statistics
                callbackQueue.sync {}
                try require(cancelled.permitted, "外层取消意外增加查询回调")
            } else { try results.wait() }
            let value = stage(diagnostics), snapshot = diagnostics.snapshot()
            try require(value.count == 1 && value.failureCount == 1 && value.cancellationCount == 0
                        && value.sampleCount == 0 && snapshot.dnsFailures == 1
                        && snapshot.dnsFailureReasons == [.timeout: 1]
                        && harness.transports[0].cancelCount == 1,
                        "真实总期限超时被遗漏或误计中止")
        }
        for synchronousFailure in [true, false] {
            let diagnostics = NetworkPerformanceDiagnostics(), harness = Harness(), results = Results()
            let coordinator = DNSQueryCoordinator(diagnostics: diagnostics), message = query(1)
            coordinator.resolve(scope: "child-deadline", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: { queue, receive, failure in
                    if synchronousFailure { throw DNSQueryTimeoutError() }
                    let transport = try harness.factory(queue, receive, failure)
                    queue.async { failure(DNSQueryTimeoutError()) }
                    return transport
                }, completion: results.callback(for: message, shouldFail: true))
            try results.wait()
            let value = stage(diagnostics), snapshot = diagnostics.snapshot()
            try require(value.count == 1 && value.failureCount == 1 && value.cancellationCount == 0
                        && snapshot.dnsFailures == 1 && snapshot.dnsFailureReasons == [.timeout: 1],
                        "子查询总期限错误被误计上游响应错误或中止")
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics(), harness = Harness(), called = Epoch()
            let coordinator = DNSQueryCoordinator(diagnostics: diagnostics), message = query(1)
            let id = coordinator.resolve(scope: "ordinary-cancel", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory) { _ in called.set(false) }
            _ = coordinator.statistics
            coordinator.cancel(id)
            _ = coordinator.statistics
            callbackQueue.sync {}
            try harness.transports[0].reply()
            _ = coordinator.statistics
            callbackQueue.sync {}
            let value = stage(diagnostics), snapshot = diagnostics.snapshot()
            try require(called.permitted && value.count == 1 && value.failureCount == 0
                        && value.cancellationCount == 1 && value.sampleCount == 0
                        && snapshot.dnsFailures == 0 && snapshot.dnsCancelledQueries == 1,
                        "普通取消/迟到回包被计成故障、成功或重复计数")
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics(), results = Results(), harness = Harness()
            let coordinator = DNSQueryCoordinator(maximumPending: 0, diagnostics: diagnostics), message = query(1)
            coordinator.resolve(scope: "capacity", query: message, callbackQueue: callbackQueue,
                permitted: { true }, factory: harness.factory,
                completion: results.callback(for: message, shouldFail: true))
            try results.wait()
            let value = stage(diagnostics), snapshot = diagnostics.snapshot()
            try require(value.count == 1 && value.failureCount == 1 && value.cancellationCount == 0
                        && snapshot.dnsFailureReasons == [.capacity: 1] && harness.transports.isEmpty,
                        "容量拒绝被隐藏为成功、中止或上游故障")
        }
        print("DNS diagnostic outcome check passed: NODATA/NXDOMAIN, SERVFAIL/REFUSED, invalidation, cancellation, parent/child deadlines and capacity")
    }
}

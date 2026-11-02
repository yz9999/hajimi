import Foundation
import HajimiDNS

/// Memory-only ownership checks. A held child ACK represents the logical
/// cancellation fence, not an assertion about native dial/FD completion.
enum DNSResolverLeaseSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS resolver lease 自检失败：\(text)" }
    }

    private static func require(_ condition: Bool, _ text: String) throws {
        guard condition else { throw Failure(text: text) }
    }

    private final class Counter {
        private let lock = NSLock()
        private var count = 0
        func increment() { lock.lock(); count += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    }

    private final class Owner {
        let cancellations = Counter()
        func cancel() { cancellations.increment() }
    }

    private final class HeldACKTransport: NativeRoutedDatagram, DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding {
        private let lock = NSLock()
        private var callbacks: [() -> Void] = []
        private var stopped = false
        private var cancellations = 0, sends = 0

        func send(_ data: Data) {
            lock.lock(); if !stopped { sends += 1 }; lock.unlock()
        }
        func cancel() { cancel(completion: {}) }
        func cancel(completion: @escaping () -> Void) {
            lock.lock(); stopped = true; cancellations += 1; callbacks.append(completion); lock.unlock()
        }
        func acknowledgeAll() {
            lock.lock(); let pending = callbacks; callbacks.removeAll(); lock.unlock()
            pending.forEach { $0() }
        }
        func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
            .failure(EncryptedDNSQueryFailure.authentication)
        }
        var snapshot: (cancellations: Int, sends: Int, pendingACKs: Int) {
            lock.lock(); defer { lock.unlock() }
            return (cancellations, sends, callbacks.count)
        }
    }

    static func run() throws {
        try destructionWaitsForACK()
        try duplicateCancelPreservesAnotherClient()
        try lateACKCannotReleaseReplacement()
        print("DNS resolver lease fences passed: deinit/cancel retain the pool until logical ACK, duplicate release is inert, other live clients and replacement epochs stay leased")
    }

    private static func destructionWaitsForACK() throws {
        let cache = BoundedConnectionOwnerCache<String, Owner>(maximumEntries: 1, maximumBytes: 4)
        let owner = Owner(), transport = HeldACKTransport()
        guard let inserted = cache.insert(owner, for: "old-pool", cost: 4) else {
            throw Failure(text: "无法创建单 pool 样本")
        }
        var wrapper: DNSResolverLeaseDatagram<Owner>? = DNSResolverLeaseDatagram(transport: transport, owner: inserted.lease)
        weak var observedWrapper = wrapper
        wrapper?.send(Data([1]))
        wrapper = nil
        try require(observedWrapper == nil && transport.snapshot.cancellations == 1
                    && transport.snapshot.pendingACKs == 1,
                    "wrapper 未释放或 deinit 没有建立 child cancellation fence")
        try require(cache.insert(Owner(), for: "replacement", cost: 4) == nil && cache.usage.entries == 1,
                    "deinit 在 child ACK 前把仍未 fenced 的 pool 变为 LRU idle")
        transport.acknowledgeAll()
        guard let replacement = cache.insert(Owner(), for: "replacement", cost: 4) else {
            throw Failure(text: "deinit child ACK 后没有释放 pool lease")
        }
        replacement.retired.forEach { $0.cancel() }
        try require(replacement.retired.count == 1 && replacement.retired[0] === owner
                    && owner.cancellations.value == 1 && transport.snapshot.sends == 1,
                    "ACK 后 LRU 退休了错误 pool，或 deinit 重复发出数据")
        replacement.lease.release()
    }

    private static func duplicateCancelPreservesAnotherClient() throws {
        let cache = BoundedConnectionOwnerCache<String, Owner>(maximumEntries: 1, maximumBytes: 4)
        let owner = Owner(), first = HeldACKTransport(), second = HeldACKTransport(), completed = Counter()
        guard let inserted = cache.insert(owner, for: "shared-pool", cost: 4),
              let otherLease = cache.acquire("shared-pool") else {
            throw Failure(text: "无法为同一 pool 创建两份独立 lease")
        }
        var one: DNSResolverLeaseDatagram<Owner>? = DNSResolverLeaseDatagram(transport: first, owner: inserted.lease)
        var two: DNSResolverLeaseDatagram<Owner>? = DNSResolverLeaseDatagram(transport: second, owner: otherLease)
        guard case .failure(let barrier)? = one?.proxyFallbackBarrier(),
              let typed = barrier as? EncryptedDNSQueryFailure, case .authentication = typed else {
            throw Failure(text: "pool lease wrapper 吞掉 child 身份验证 barrier")
        }
        one?.cancel { completed.increment() }
        one?.cancel { completed.increment() }
        one = nil // The destructor creates a third held ACK, never an early release.
        try require(first.snapshot.pendingACKs == 3 && completed.value == 0
                    && second.snapshot.cancellations == 0
                    && cache.insert(Owner(), for: "new-pool", cost: 4) == nil,
                    "重复 cancel/deinit 提前释放或误取消另一个 live client")
        first.acknowledgeAll()
        two?.send(Data([2]))
        try require(completed.value == 2 && second.snapshot.sends == 1 && owner.cancellations.value == 0
                    && cache.insert(Owner(), for: "new-pool", cost: 4) == nil,
                    "第一份 lease 重复 ACK 释放了另一份 lease 或取消共享 pool")
        two = nil
        try require(second.snapshot.pendingACKs == 1 && cache.insert(Owner(), for: "new-pool", cost: 4) == nil,
                    "最后一个 client deinit 尚未 ACK 就可以被 LRU 退休")
        second.acknowledgeAll()
        guard let replacement = cache.insert(Owner(), for: "new-pool", cost: 4) else {
            throw Failure(text: "所有独立 ACK 后仍无法退休共享 pool")
        }
        replacement.retired.forEach { $0.cancel() }
        try require(replacement.retired.count == 1 && replacement.retired[0] === owner
                    && owner.cancellations.value == 1 && completed.value == 2,
                    "重复 ACK 破坏 owner 使用计数或多次完成显式 cancel")
        replacement.lease.release()
    }

    private static func lateACKCannotReleaseReplacement() throws {
        let cache = BoundedConnectionOwnerCache<String, Owner>(maximumEntries: 1, maximumBytes: 4)
        let oldOwner = Owner(), newOwner = Owner(), transport = HeldACKTransport()
        guard let old = cache.insert(oldOwner, for: "same-key", cost: 4) else {
            throw Failure(text: "无法创建 epoch replacement 样本")
        }
        var wrapper: DNSResolverLeaseDatagram<Owner>? = DNSResolverLeaseDatagram(transport: transport, owner: old.lease)
        let removed = cache.remove { _ in true }
        removed.forEach { $0.cancel() }
        guard let current = cache.insert(newOwner, for: "same-key", cost: 4) else {
            throw Failure(text: "显式旧代 detach 没有让新代 owner 正常提交")
        }
        wrapper?.cancel(); wrapper = nil
        transport.acknowledgeAll(); transport.acknowledgeAll()
        try require(removed.count == 1 && removed[0] === oldOwner && oldOwner.cancellations.value == 1
                    && newOwner.cancellations.value == 0
                    && cache.insert(Owner(), for: "pressure", cost: 4) == nil,
                    "迟到旧 lease ACK 释放/退休了相同 key 的当前代 owner")
        current.lease.release()
        guard let pressure = cache.insert(Owner(), for: "pressure", cost: 4) else {
            throw Failure(text: "新代自己的 lease 完成后没有恢复有界容量")
        }
        try require(pressure.retired.count == 1 && pressure.retired[0] === newOwner,
                    "相同 key 的新代 owner 没有独立的 lease 生命周期")
        pressure.lease.release()
    }
}

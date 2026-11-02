import Foundation

/// A lease is retained by the pending operation, then by its delivered stream.
/// Releasing a stream lease never cancels a shared protocol client's sessions.
final class BoundedConnectionOwnerLease<Owner: AnyObject> {
    let owner: Owner
    private let lock = NSLock()
    private var releaseAction: (() -> Void)?
    fileprivate init(owner: Owner, release: @escaping () -> Void) {
        self.owner = owner; releaseAction = release
    }
    func release() {
        lock.lock(); let action = releaseAction; releaseAction = nil; lock.unlock()
        action?()
    }
    deinit { release() }
}

/// Idle-only eviction: a new address identity can never evict/cancel a client
/// which still owns a pending connection or a live application stream.
final class BoundedConnectionOwnerCache<Key: Hashable, Owner: AnyObject> {
    struct Insertion {
        let lease: BoundedConnectionOwnerLease<Owner>
        let retired: [Owner]
    }
    private final class Entry {
        let owner: Owner
        let cost: Int
        var users = 0
        var touched: UInt64 = 0
        init(owner: Owner, cost: Int) { self.owner = owner; self.cost = cost }
    }
    private let lock = NSLock()
    private let maximumEntries: Int
    private let maximumBytes: Int
    private var entries: [Key: Entry] = [:]
    private var bytes = 0
    private var ticks: UInt64 = 0

    init(maximumEntries: Int = 128, maximumBytes: Int = 16 * 1_024 * 1_024) {
        self.maximumEntries = min(128, max(0, maximumEntries))
        self.maximumBytes = min(16 * 1_024 * 1_024, max(0, maximumBytes))
    }
    var usage: (entries: Int, bytes: Int) {
        lock.lock(); defer { lock.unlock() }; return (entries.count, bytes)
    }
    var owners: [Owner] {
        lock.lock(); defer { lock.unlock() }; return entries.values.map(\.owner)
    }

    /// Advisory inspection does not borrow transport ownership or touch LRU.
    /// An operation must still acquire a lease and revalidate its authority.
    func peek(_ key: Key) -> Owner? {
        lock.lock(); defer { lock.unlock() }; return entries[key]?.owner
    }

    func acquire(_ key: Key) -> BoundedConnectionOwnerLease<Owner>? {
        lock.lock(); defer { lock.unlock() }
        guard let entry = entries[key] else { return nil }
        return lease(entry)
    }

    func insert(_ owner: Owner, for key: Key, cost: Int) -> Insertion? {
        lock.lock(); defer { lock.unlock() }
        if let entry = entries[key] { return Insertion(lease: lease(entry), retired: [owner]) }
        guard maximumEntries > 0, cost >= 0, cost <= maximumBytes else { return nil }
        let idle = entries.filter { $0.value.users == 0 }.sorted { $0.value.touched < $1.value.touched }
        var count = entries.count, retained = bytes, retired: [Owner] = []
        var victims: [(key: Key, value: Entry)] = []
        for candidate in idle {
            if count < maximumEntries && cost <= maximumBytes - retained { break }
            victims.append(candidate); count -= 1; retained -= candidate.value.cost
        }
        guard count < maximumEntries, cost <= maximumBytes - retained else { return nil }
        for victim in victims {
            entries.removeValue(forKey: victim.key); bytes -= victim.value.cost
            retired.append(victim.value.owner)
        }
        let entry = Entry(owner: owner, cost: cost)
        entries[key] = entry; bytes += cost
        return Insertion(lease: lease(entry), retired: retired)
    }

    /// Explicit policy/interface invalidation may retire live owners. The
    /// caller performs cancellation after releasing its configuration lock.
    func remove(where predicate: (Owner) -> Bool) -> [Owner] {
        lock.lock(); defer { lock.unlock() }
        let stale = entries.filter { predicate($0.value.owner) }
        for (key, entry) in stale { entries.removeValue(forKey: key); bytes -= entry.cost }
        return stale.values.map(\.owner)
    }

    private func lease(_ entry: Entry) -> BoundedConnectionOwnerLease<Owner> {
        ticks &+= 1; entry.touched = ticks; entry.users += 1
        return BoundedConnectionOwnerLease(owner: entry.owner) { [weak self, entry] in
            guard let self else { return }
            self.lock.lock(); entry.users -= 1; self.lock.unlock()
        }
    }
}

public enum BoundedConnectionOwnerCacheSelfTest {
    private final class Owner {
        let identity: String
        var cancellations = 0
        init(_ identity: String) { self.identity = identity }
        func cancel() { cancellations += 1 }
    }
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "连接 owner 缓存自检失败：\(text)" }
    }
    public static func run() throws {
        func expect(_ value: Bool, _ text: String) throws {
            guard value else { throw Failure(text: text) }
        }
        let cache = BoundedConnectionOwnerCache<String, Owner>(maximumEntries: 2, maximumBytes: 8)
        let first = Owner("node|203.0.113.1|en0"), second = Owner("node|2001:db8::1|en0")
        let one = cache.insert(first, for: first.identity, cost: 4)!
        let two = cache.insert(second, for: second.identity, cost: 4)!
        try expect(one.retired.isEmpty && two.retired.isEmpty && first.cancellations == 0,
                   "a second address identity displaced a live client")
        let reused = cache.acquire(first.identity)!
        try expect(reused.owner === first, "stable address identity did not reuse its owner")
        let denied = Owner("third")
        try expect(cache.insert(denied, for: denied.identity, cost: 4) == nil
                   && cache.usage.entries == 2 && first.cancellations == 0 && second.cancellations == 0,
                   "full cache evicted an in-use client")
        one.lease.release(); one.lease.release()
        try expect(cache.insert(denied, for: denied.identity, cost: 4) == nil,
                   "duplicate lease release made a still-borrowed client evictable")
        reused.release()
        let inserted = cache.insert(denied, for: denied.identity, cost: 4)!
        inserted.retired.forEach { $0.cancel() }
        try expect(inserted.retired.count == 1 && inserted.retired[0] === first
                   && first.cancellations == 1 && second.cancellations == 0,
                   "idle-only eviction did not preserve the other live client")
        let stale = cache.remove { $0.identity == second.identity }
        stale.forEach { $0.cancel() }
        try expect(stale.count == 1 && second.cancellations == 1 && cache.usage.entries == 1,
                   "explicit invalidation did not retire exactly the revoked identity")
        two.lease.release(); inserted.lease.release()
        try expect(cache.insert(Owner("oversized"), for: "oversized", cost: 9) == nil
                   && cache.usage.bytes == 4, "oversized admission mutated the bounded cache")

        let partial = BoundedConnectionOwnerCache<String, Owner>(maximumEntries: 2, maximumBytes: 8)
        let active = partial.insert(Owner("active"), for: "active", cost: 4)!
        let idle = partial.insert(Owner("idle"), for: "idle", cost: 4)!
        idle.lease.release()
        try expect(partial.insert(Owner("large"), for: "large", cost: 6) == nil
                   && partial.usage.entries == 2 && partial.usage.bytes == 8,
                   "failed admission partially evicted idle owners")
        active.lease.release()
    }
}

import Foundation
import Dispatch

/// Local UDP admission is independent of the TCP admission limit. In
/// particular, one UDP ASSOCIATE must not multiply into unlimited sockets.
enum SOCKSUDPResourceLimits {
    static let clientsPerAssociation = 32
    static let directFlowsPerAssociation = 256
    static let relaysPerAssociation = 32
    static let targetsPerRelay = 128
    static let queuedPackets = 64
    static let queuedBytes = 256 * 1_024
    static let idleTimeout: TimeInterval = 120
    static let reapInterval: TimeInterval = 30
    static let shared = SOCKSUDPGlobalBudget(resources: 1_024, packets: 8_192, bytes: 8 * 1_024 * 1_024)

    static var now: TimeInterval { TimeInterval(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }
    static func ownedKey(client: UUID, target: String) -> String { "\(client.uuidString)|\(target)" }
}

/// Reservations have a single owner but may be released by cancellation and
/// an already-submitted send callback. A late callback cannot double-release.
final class SOCKSUDPReservation {
    private let lock = NSLock()
    private var onRelease: (() -> Void)?
    init(_ onRelease: @escaping () -> Void) { self.onRelease = onRelease }
    func release() {
        lock.lock(); let callback = onRelease; onRelease = nil; lock.unlock()
        callback?()
    }
    deinit { release() }
}

final class SOCKSUDPGlobalBudget {
    private let lock = NSLock()
    private let maximumResources: Int
    private let maximumPackets: Int
    private let maximumBytes: Int
    private var resources = 0
    private var packets = 0
    private var bytes = 0

    init(resources: Int, packets: Int, bytes: Int) {
        maximumResources = max(0, resources)
        maximumPackets = max(0, packets)
        maximumBytes = max(0, bytes)
    }

    func reserveResource() -> SOCKSUDPReservation? {
        lock.lock()
        guard resources < maximumResources else { lock.unlock(); return nil }
        resources += 1; lock.unlock()
        return SOCKSUDPReservation { [self] in
            lock.lock(); resources -= 1; lock.unlock()
        }
    }

    func reservePacket(bytes count: Int) -> SOCKSUDPReservation? {
        lock.lock()
        guard count >= 0, packets < maximumPackets, count <= maximumBytes - bytes else {
            lock.unlock(); return nil
        }
        packets += 1; bytes += count; lock.unlock()
        return SOCKSUDPReservation { [self] in
            lock.lock(); packets -= 1; bytes -= count; lock.unlock()
        }
    }

    var usage: (resources: Int, packets: Int, bytes: Int) {
        lock.lock(); defer { lock.unlock() }; return (resources, packets, bytes)
    }
}

/// Queue-local registry. Identity is checked on removal/touch, so a canceled
/// flow's late completion cannot delete a replacement using the same target.
struct SOCKSUDPResourceRegistry<Key: Hashable, Value> {
    private struct Entry {
        let value: Value
        let token: UUID
        var activity: TimeInterval
    }
    private let maximumCount: Int
    private var entries: [Key: Entry] = [:]
    init(maximumCount: Int) { self.maximumCount = max(0, maximumCount) }
    var count: Int { entries.count }
    var values: [Value] { entries.values.map { $0.value } }
    var hasCapacity: Bool { entries.count < maximumCount }
    func value(forKey key: Key) -> Value? { entries[key]?.value }
    @discardableResult
    mutating func insert(_ value: Value, forKey key: Key, token: UUID,
                         now: TimeInterval = SOCKSUDPResourceLimits.now) -> Bool {
        guard entries[key] == nil, hasCapacity else { return false }
        entries[key] = Entry(value: value, token: token, activity: now)
        return true
    }
    mutating func touch(_ key: Key, token: UUID, now: TimeInterval = SOCKSUDPResourceLimits.now) {
        guard entries[key]?.token == token else { return }
        entries[key]?.activity = now
    }
    @discardableResult
    mutating func removeValue(forKey key: Key, token: UUID) -> Value? {
        guard entries[key]?.token == token else { return nil }
        return entries.removeValue(forKey: key)?.value
    }
    mutating func remove(where predicate: (Value) -> Bool) -> [Value] {
        let keys = entries.filter { predicate($0.value.value) }.map { $0.key }
        return keys.compactMap { entries.removeValue(forKey: $0)?.value }
    }
    func expiredValues(now: TimeInterval = SOCKSUDPResourceLimits.now,
                       timeout: TimeInterval = SOCKSUDPResourceLimits.idleTimeout) -> [Value] {
        entries.values.filter { now - $0.activity >= timeout }.map { $0.value }
    }
    mutating func removeExpired(now: TimeInterval = SOCKSUDPResourceLimits.now,
                                timeout: TimeInterval = SOCKSUDPResourceLimits.idleTimeout) -> [Value] {
        let keys = entries.filter { now - $0.value.activity >= timeout }.map { $0.key }
        return keys.compactMap { entries.removeValue(forKey: $0)?.value }
    }
    mutating func removeAll() -> [Value] {
        let current = values; entries.removeAll(keepingCapacity: false); return current
    }
}

/// Includes the single in-flight send in both the local and global budgets.
/// Empty datagrams consume a packet slot even though they consume zero bytes.
struct SOCKSUDPWriteQueue<Value> {
    struct Entry {
        let id = UUID()
        let value: Value
        let byteCount: Int
        let reservation: SOCKSUDPReservation
    }
    private let maximumPackets: Int
    private let maximumBytes: Int
    private let budget: SOCKSUDPGlobalBudget
    private var waiting: [Entry?] = []
    private var head = 0
    private var inFlight: Entry?
    private(set) var count = 0
    private(set) var bytes = 0

    init(packets: Int = SOCKSUDPResourceLimits.queuedPackets,
         bytes: Int = SOCKSUDPResourceLimits.queuedBytes,
         budget: SOCKSUDPGlobalBudget = SOCKSUDPResourceLimits.shared) {
        maximumPackets = max(0, packets); maximumBytes = max(0, bytes); self.budget = budget
    }

    mutating func append(_ value: Value, bytes byteCount: Int) -> Bool {
        guard byteCount >= 0, count < maximumPackets, byteCount <= maximumBytes - bytes,
              let reservation = budget.reservePacket(bytes: byteCount) else { return false }
        waiting.append(Entry(value: value, byteCount: byteCount, reservation: reservation))
        count += 1; bytes += byteCount; return true
    }

    mutating func beginNext() -> Entry? {
        guard inFlight == nil, head < waiting.count, let next = waiting[head] else { return nil }
        waiting[head] = nil; head += 1; inFlight = next
        if head >= 32, head * 2 >= waiting.count {
            waiting.removeFirst(head); head = 0
        }
        return next
    }

    @discardableResult
    mutating func complete(_ id: UUID) -> Bool {
        guard let current = inFlight, current.id == id else { return false }
        count -= 1; bytes -= current.byteCount; inFlight = nil
        current.reservation.release(); return true
    }

    /// The caller must retain the submitted packet's reservation in its send
    /// callback. Cancellation releases unsent packets now; an in-flight send
    /// remains globally accounted until Network.framework completes it.
    mutating func discard() -> [Value] {
        let pending = waiting[head...].compactMap { $0?.value }
        waiting.removeAll(keepingCapacity: false); head = 0; inFlight = nil
        count = 0; bytes = 0; return pending
    }
}

public enum SOCKSUDPResourcePolicySelfTest {
    /// Pure production-budget checks: no socket is created and the shared
    /// process budget is not changed by the self-test.
    public static func run() -> String? {
        let budget = SOCKSUDPGlobalBudget(resources: 2, packets: 3, bytes: 8)
        guard let first = budget.reserveResource(), let second = budget.reserveResource(),
              budget.reserveResource() == nil else { return "global UDP resource cap was bypassed" }
        first.release(); first.release()
        guard let replacement = budget.reserveResource(), budget.usage.resources == 2 else {
            return "UDP resource release was not idempotent/reusable"
        }
        second.release(); replacement.release()
        guard budget.usage.resources == 0 else { return "UDP resource slots leaked" }
        do {
            let automatic = budget.reserveResource()
            guard automatic != nil, budget.usage.resources == 1 else { return "UDP automatic lease failed" }
            withExtendedLifetime(automatic) {}
        }
        guard budget.usage.resources == 0 else { return "UDP deinit did not release its slot" }
        let sourceA = UUID(), sourceB = UUID()
        guard SOCKSUDPResourceLimits.ownedKey(client: sourceA, target: "same-target")
                != SOCKSUDPResourceLimits.ownedKey(client: sourceB, target: "same-target"),
              SOCKSUDPResourceLimits.ownedKey(client: sourceA, target: "same-target")
                == SOCKSUDPResourceLimits.ownedKey(client: sourceA, target: "same-target") else {
            return "UDP destination/relay identity omitted its client owner"
        }

        var registry = SOCKSUDPResourceRegistry<String, Int>(maximumCount: 1)
        let old = UUID(), current = UUID()
        guard registry.insert(1, forKey: "same", token: old, now: 0),
              !registry.insert(2, forKey: "other", token: current, now: 0),
              registry.removeValue(forKey: "same", token: old) == 1,
              registry.insert(2, forKey: "same", token: current, now: 0),
              registry.removeValue(forKey: "same", token: old) == nil else {
            return "local UDP cap/late-close identity protection failed"
        }
        registry.touch("same", token: old, now: 100)
        guard registry.removeExpired(now: 120, timeout: 120) == [2], registry.count == 0 else {
            return "stale UDP activity prevented idle reclamation"
        }

        var queue = SOCKSUDPWriteQueue<Data>(packets: 2, bytes: 4, budget: budget)
        guard queue.append(Data(), bytes: 0), queue.append(Data([1, 2, 3, 4]), bytes: 4),
              !queue.append(Data(), bytes: 0), let empty = queue.beginNext(),
              queue.beginNext() == nil, queue.count == 2, budget.usage.packets == 2,
              queue.complete(empty.id), !queue.complete(empty.id), let payload = queue.beginNext(),
              payload.value == Data([1, 2, 3, 4]), budget.usage.bytes == 4 else {
            return "single-in-flight UDP packet/byte cap or empty datagram compatibility failed"
        }
        // A canceled in-flight send must remain in the global budget until its
        // completion, even if the local registry already admitted a new flow.
        _ = queue.discard()
        guard queue.count == 0, budget.usage.bytes == 4 else {
            return "cancel prematurely released an in-flight UDP byte reservation"
        }
        payload.reservation.release()
        guard !queue.complete(payload.id), budget.usage.bytes == 0, budget.usage.packets == 0 else {
            return "late UDP send completion leaked or double-released its budget"
        }
        var left = SOCKSUDPWriteQueue<Data>(budget: budget), right = SOCKSUDPWriteQueue<Data>(budget: budget)
        guard left.append(Data(repeating: 0, count: 8), bytes: 8),
              !right.append(Data([1]), bytes: 1), right.append(Data(), bytes: 0),
              right.append(Data(), bytes: 0), !right.append(Data(), bytes: 0) else {
            return "cross-association UDP global byte/packet cap was bypassed"
        }
        _ = left.discard(); _ = right.discard()
        guard budget.usage.bytes == 0, budget.usage.packets == 0 else {
            return "canceled pending UDP queues retained their budgets"
        }
        return nil
    }
}

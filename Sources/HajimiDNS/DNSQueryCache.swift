import Foundation

/// Conservative, bounded wire-answer cache. It has no resolver or routing
/// authority: callers must validate policy before lookup and partition scope.
public final class DNSQueryCache {
    private struct Key: Hashable { let scope: String; let question: Data }
    private struct TTLField { let offset: Int; let value: UInt32 }
    private struct Entry {
        let response: Data
        let fields: [TTLField]
        let inserted: Date
        let expires: Date
        let cost: Int
        var access: UInt64
    }
    fileprivate struct Question {
        let name: String
        let type: UInt16
        let end: Int
        let hasOPT: Bool
        let payloadLimit: Int
        let recursionDesired: UInt8
    }
    private struct Name { let value: String; let end: Int }
    /// One immutable inspection of the original wire query. Only this file
    /// constructs the metadata, so callers cannot grant eligibility by hand.
    package struct PreparedQuery {
        package let cacheEligible: Bool
        package let coalescingIdentity: Data?
        fileprivate let query: Data
        fileprivate let question: Question?
    }
    // Transfers, authentication/meta queries and unknown QTYPEs must keep
    // independent transactions even when their question headers look simple.
    private static let coalescableReadTypes: Set<UInt16> = [
        1, 2, 5, 6, 12, 15, 16, 28, 33, 35, 64, 65, 257
    ]
    private static let cacheableReadTypes: Set<UInt16> = [1, 28, 64, 65]
    private let lock = NSLock()
    private let maximumEntries: Int, maximumBytes: Int
    private let maximumTTL: UInt32
    private let clock: () -> Date
    private var entries: [Key: Entry] = [:]
    private var staleArchive: [Key: Entry] = [:]
    private var bytes = 0
    private var access: UInt64 = 0
    private var lastClock: Date?

    public init(maximumEntries: Int = 512, maximumBytes: Int = 2 * 1024 * 1024,
                maximumTTL: UInt32 = 3600,
                clock: @escaping () -> Date = {
                    Date(timeIntervalSince1970: ProcessInfo.processInfo.systemUptime)
                }) {
        self.maximumEntries = max(0, maximumEntries); self.maximumBytes = max(0, maximumBytes)
        self.maximumTTL = maximumTTL; self.clock = clock
    }

    /// Only the ID is removed. Case, RD, EDNS payload and padding remain exact
    /// so no privacy/security flags or client capabilities are merged away.
    public static func identity(for query: Data) -> Data? {
        let prepared = prepare(query)
        return prepared.cacheEligible ? prepared.coalescingIdentity : nil
    }

    /// An unsigned, simple common read-only IN question can share live IO even
    /// when its answer type is deliberately not stored (TXT/CAA).
    /// This alone grants no response-cache eligibility: flags, question case, type,
    /// client capabilities and neutral OPT/padding stay byte-for-byte exact.
    /// Authenticated/complex additions are never parsed away or merged.
    package static func coalescingIdentity(for query: Data) -> Data? {
        prepare(query).coalescingIdentity
    }

    package static func prepare(_ query: Data) -> PreparedQuery {
        let bytes = [UInt8](query)
        let original = Data(bytes)
        guard let question = inspectQuery(bytes) else {
            return PreparedQuery(cacheEligible: false, coalescingIdentity: nil,
                                 query: original, question: nil)
        }
        var identity = bytes; identity[0] = 0; identity[1] = 0
        return PreparedQuery(cacheEligible: cacheableReadTypes.contains(question.type),
                             coalescingIdentity: Data(identity), query: original, question: question)
    }

    public static func rewritingResponseID(_ response: Data, for query: Data) -> Data? {
        guard response.count >= 12, query.count >= 12 else { return nil }
        var bytes = [UInt8](response)
        bytes[0] = query[query.startIndex]; bytes[1] = query[query.startIndex + 1]
        let answer = Data(bytes)
        return DNSMessageInspection.responseMatchesQuery(answer, query: query) ? answer : nil
    }

    public func lookup(scopeKey: String, query: Data) -> Data? {
        lookup(scopeKey: scopeKey, prepared: Self.prepare(query))
    }

    package func lookup(scopeKey: String, prepared: PreparedQuery) -> Data? {
        guard prepared.cacheEligible, let identity = prepared.coalescingIdentity else { return nil }
        let key = Key(scope: scopeKey, question: identity)
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), var entry = entries[key] else { return nil }
        guard now < entry.expires else { archiveAndRemove(key, now: now); return nil }
        access &+= 1; entry.access = access; entries[key] = entry
        let age = UInt32(min(Double(UInt32.max), max(0, ceil(now.timeIntervalSince(entry.inserted)))))
        let remaining = UInt32(min(Double(UInt32.max), max(0, floor(entry.expires.timeIntervalSince(now)))))
        var response = [UInt8](entry.response)
        for field in entry.fields {
            let value = min(field.value > age ? field.value - age : 0, remaining)
            Self.write32(value, at: field.offset, in: &response)
        }
        // Only strict store() can create an entry, and both wire snapshots are
        // owned. The exact ID-zero query key binds this prepared query to that
        // validated answer; aging only touches recorded RR TTL fields after
        // the question. Re-parsing the same question cannot add validation.
        // The public arbitrary-response rewriter deliberately remains strict.
        response[0] = prepared.query[prepared.query.startIndex]
        response[1] = prepared.query[prepared.query.startIndex + 1]
        return Data(response)
    }

    /// Optimistic DNS Prefetching lookup: returns the validated cached response
    /// along with its remaining TTL and whether an asynchronous background
    /// refresh is recommended (when remaining TTL drops below `prefetchFraction`
    /// of original lifetime or `<= minimumPrefetchRemainingTTL`).
    public func lookupWithPrefetchHint(scopeKey: String, query: Data,
                                       prefetchFraction: Double = 0.15,
                                       minimumPrefetchRemainingTTL: UInt32 = 10)
        -> (response: Data, remainingTTL: UInt32, shouldPrefetch: Bool)? {
        lookupWithPrefetchHint(scopeKey: scopeKey, prepared: Self.prepare(query),
                               prefetchFraction: prefetchFraction,
                               minimumPrefetchRemainingTTL: minimumPrefetchRemainingTTL)
    }

    package func lookupWithPrefetchHint(scopeKey: String, prepared: PreparedQuery,
                                        prefetchFraction: Double = 0.15,
                                        minimumPrefetchRemainingTTL: UInt32 = 10)
        -> (response: Data, remainingTTL: UInt32, shouldPrefetch: Bool)? {
        guard prepared.cacheEligible, let identity = prepared.coalescingIdentity else { return nil }
        let key = Key(scope: scopeKey, question: identity)
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now), var entry = entries[key] else { return nil }
        guard now < entry.expires else { archiveAndRemove(key, now: now); return nil }
        access &+= 1; entry.access = access; entries[key] = entry
        let age = UInt32(min(Double(UInt32.max), max(0, ceil(now.timeIntervalSince(entry.inserted)))))
        let remaining = UInt32(min(Double(UInt32.max), max(0, floor(entry.expires.timeIntervalSince(now)))))
        let totalLifetime = max(1.0, entry.expires.timeIntervalSince(entry.inserted))
        let safeFraction = prefetchFraction.isFinite ? min(0.5, max(0.01, prefetchFraction)) : 0.15
        let shouldPrefetch = remaining <= minimumPrefetchRemainingTTL
            || Double(remaining) <= totalLifetime * safeFraction
        var response = [UInt8](entry.response)
        for field in entry.fields {
            let value = min(field.value > age ? field.value - age : 0, remaining)
            Self.write32(value, at: field.offset, in: &response)
        }
        response[0] = prepared.query[prepared.query.startIndex]
        response[1] = prepared.query[prepared.query.startIndex + 1]
        return (Data(response), remaining, shouldPrefetch)
    }

    /// RFC 8767 Serve-Stale emergency lookup: called only after upstream resolution
    /// fails due to timeout or transient network error, within the exact same
    /// verified `scopeKey` and `coalescingIdentity`. Rewrites RR TTLs to a small
    /// emergency lifetime (`staleServeTTL`, default 30s per RFC 8767 §4).
    public func lookupStale(scopeKey: String, query: Data,
                            maximumStaleWindow: TimeInterval = 1800,
                            staleServeTTL: UInt32 = 30) -> Data? {
        lookupStale(scopeKey: scopeKey, prepared: Self.prepare(query),
                    maximumStaleWindow: maximumStaleWindow, staleServeTTL: staleServeTTL)
    }

    package func lookupStale(scopeKey: String, prepared: PreparedQuery,
                             maximumStaleWindow: TimeInterval = 1800,
                             staleServeTTL: UInt32 = 30) -> Data? {
        guard prepared.cacheEligible, let identity = prepared.coalescingIdentity,
              maximumStaleWindow.isFinite, maximumStaleWindow > 0,
              staleServeTTL > 0, maximumTTL > 0 else { return nil }
        let key = Key(scope: scopeKey, question: identity)
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now) else { return nil }
        if let active = entries[key] {
            if now >= active.expires {
                archiveAndRemove(key, now: now)
            } else {
                return nil
            }
        }
        guard let stale = staleArchive[key] else { return nil }
        let overdue = now.timeIntervalSince(stale.expires)
        guard overdue >= 0, overdue <= maximumStaleWindow else {
            staleArchive.removeValue(forKey: key)
            return nil
        }
        let emergencyTTL = min(staleServeTTL, maximumTTL)
        var response = [UInt8](stale.response)
        for field in stale.fields {
            Self.write32(emergencyTTL, at: field.offset, in: &response)
        }
        response[0] = prepared.query[prepared.query.startIndex]
        response[1] = prepared.query[prepared.query.startIndex + 1]
        return Data(response)
    }

    @discardableResult
    public func store(scopeKey: String, query: Data, response: Data) -> Bool {
        store(scopeKey: scopeKey, prepared: Self.prepare(query), response: response)
    }

    @discardableResult
    package func store(scopeKey: String, prepared: PreparedQuery, response: Data) -> Bool {
        let answer = [UInt8](response)
        guard prepared.cacheEligible, let question = prepared.question,
              let identity = prepared.coalescingIdentity,
              // Match the generic inspector's post-case-fold name bound too;
              // some Unicode labels expand when lowercased.
              question.name == "." || question.name.utf8.count <= 253,
              answer.count >= 12, answer[0] == prepared.query[0], answer[1] == prepared.query[1],
              // The strict response inspection below checks the question,
              // class, opcode and flags against the prepared metadata too.
              let fields = Self.inspectResponse(answer, question: question), !fields.isEmpty,
              maximumEntries > 0, maximumTTL > 0 else { return false }
        let cost = answer.count + identity.count + scopeKey.utf8.count
            + fields.count * MemoryLayout<TTLField>.stride
            + MemoryLayout<Entry>.stride + MemoryLayout<Key>.stride
        guard cost <= maximumBytes else { return false }
        let lifetime = min(fields.map(\.value).min()!, maximumTTL)
        guard lifetime > 0 else { return false }
        let key = Key(scope: scopeKey, question: identity)
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard checkClock(now) else { return false }
        let expires = now.addingTimeInterval(TimeInterval(lifetime))
        guard expires > now else { return false }
        expire(now)
        remove(key)
        while !entries.isEmpty && (entries.count >= maximumEntries || cost > maximumBytes - bytes) {
            guard let oldest = entries.min(by: { $0.value.access < $1.value.access })?.key else { return false }
            remove(oldest)
        }
        guard entries.count < maximumEntries, cost <= maximumBytes - bytes else { return false }
        access &+= 1
        entries[key] = Entry(response: Data(answer), fields: fields, inserted: now,
                             expires: expires, cost: cost, access: access)
        bytes += cost
        return true
    }

    public func removeAll() {
        lock.lock(); entries.removeAll(); staleArchive.removeAll(); bytes = 0; lastClock = nil; lock.unlock()
    }

    public var usage: (entries: Int, bytes: Int) {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        if checkClock(now) { expire(now) }
        return (entries.count, bytes)
    }

    private func checkClock(_ now: Date) -> Bool {
        guard now.timeIntervalSince1970.isFinite else {
            entries.removeAll(); staleArchive.removeAll(); bytes = 0; lastClock = nil; return false
        }
        if let previous = lastClock, now < previous {
            entries.removeAll(); staleArchive.removeAll(); bytes = 0; lastClock = now; return false
        }
        lastClock = now; return true
    }
    private func remove(_ key: Key) {
        staleArchive.removeValue(forKey: key)
        if let value = entries.removeValue(forKey: key) { bytes -= value.cost }
    }
    private func archiveAndRemove(_ key: Key, now: Date) {
        guard let value = entries.removeValue(forKey: key) else { return }
        bytes -= value.cost
        let staleLimit = min(max(1, maximumEntries), 64)
        if staleArchive.count >= staleLimit,
           let oldest = staleArchive.min(by: { $0.value.access < $1.value.access })?.key {
            staleArchive.removeValue(forKey: oldest)
        }
        staleArchive[key] = value
    }
    private func expire(_ now: Date) {
        for (key, value) in entries where value.expires <= now { archiveAndRemove(key, now: now) }
        for (key, value) in staleArchive where now.timeIntervalSince(value.expires) > 1800 {
            staleArchive.removeValue(forKey: key)
        }
    }

    private static func inspectQuery(_ bytes: [UInt8]) -> Question? {
        // AD advertises that a stub understands the upstream's validation
        // result. Preserve it exactly in the key, rather than disabling cache
        // for common stubs/dig. CD and DO still require uncached handling.
        guard (12...65_535).contains(bytes.count), bytes[2] <= 1, bytes[3] & 0xdf == 0,
              read16(bytes, 4) == 1, read16(bytes, 6) == 0, read16(bytes, 8) == 0,
              read16(bytes, 10) <= 1 else { return nil }
        var names = Set<Int>()
        guard let name = readName(bytes, at: 12, known: &names, compressed: false),
              name.end <= bytes.count - 4 else { return nil }
        let type = read16(bytes, name.end), cls = read16(bytes, name.end + 2), end = name.end + 4
        guard coalescableReadTypes.contains(type), cls == 1 else { return nil }
        let hasOPT = read16(bytes, 10) == 1
        var payload = 512
        if hasOPT {
            guard end <= bytes.count - 11, bytes[end] == 0, read16(bytes, end + 1) == 41,
                  read16(bytes, end + 3) >= 512, read32(bytes, end + 5) == 0 else { return nil }
            let length = Int(read16(bytes, end + 9))
            guard length == bytes.count - end - 11,
                  paddingOnly(bytes, from: end + 11, to: bytes.count) else { return nil }
            payload = Int(read16(bytes, end + 3))
        } else if end != bytes.count { return nil }
        return Question(name: name.value, type: type, end: end, hasOPT: hasOPT,
                        payloadLimit: payload, recursionDesired: bytes[2] & 1)
    }

    private static func inspectResponse(_ bytes: [UInt8], question: Question) -> [TTLField]? {
        guard (12...65_535).contains(bytes.count), bytes.count <= question.payloadLimit,
              bytes[2] & 0x80 != 0, bytes[2] & 0x7a == 0, bytes[3] & 0x5f == 0,
              bytes[2] & 1 == question.recursionDesired,
              read16(bytes, 4) == 1 else { return nil }
        let counts = [Int(read16(bytes, 6)), Int(read16(bytes, 8)), Int(read16(bytes, 10))]
        guard counts[0] > 0, counts.reduce(0, +) <= 256 else { return nil }
        var names = Set<Int>()
        guard let named = readName(bytes, at: 12, known: &names), named.value == question.name,
              named.end <= bytes.count - 4, read16(bytes, named.end) == question.type,
              read16(bytes, named.end + 2) == 1 else { return nil }
        var offset = named.end + 4, fields: [TTLField] = [], aliases: [String: String] = [:]
        var answerOwners: [String] = [], optCount = 0
        for section in counts.indices {
            for _ in 0..<counts[section] {
                let ownerOffset = offset
                guard let owner = readName(bytes, at: offset, known: &names), owner.end <= bytes.count - 10 else { return nil }
                offset = owner.end
                let type = read16(bytes, offset), cls = read16(bytes, offset + 2)
                let ttl = read32(bytes, offset + 4), length = Int(read16(bytes, offset + 8))
                let ttlOffset = offset + 4
                offset += 10
                guard length <= bytes.count - offset else { return nil }
                let end = offset + length
                if type == 41 {
                    optCount += 1
                    // A DoH server may add neutral response padding even if
                    // the client did not send OPT. This grants no capability:
                    // the original query's payload bound above still applies
                    // (512 without OPT), and every OPT flag must remain zero.
                    guard section == 2, optCount == 1, owner.value == ".",
                          bytes[ownerOffset] == 0, cls >= 512, ttl == 0,
                          paddingOnly(bytes, from: offset, to: end) else { return nil }
                    // OPT's TTL-position is a flags/version field, not TTL.
                } else {
                    guard cls == 1, ttl > 0 else { return nil }
                    fields.append(TTLField(offset: ttlOffset, value: ttl))
                    switch type {
                    case 1, 28:
                        guard length == (type == 1 ? 4 : 16), section != 1 else { return nil }
                        if section == 0 {
                            guard type == question.type else { return nil }
                            answerOwners.append(owner.value)
                        }
                    case 5:
                        guard section == 0, let alias = readName(bytes, at: offset, known: &names),
                              alias.end == end else { return nil }
                        if let old = aliases[owner.value], old != alias.value { return nil }
                        aliases[owner.value] = alias.value
                    case 2:
                        guard section != 0, let ns = readName(bytes, at: offset, known: &names), ns.end == end else { return nil }
                    case 6:
                        guard section == 1, let ns = readName(bytes, at: offset, known: &names),
                              let mailbox = readName(bytes, at: ns.end, known: &names), mailbox.end == end - 20 else { return nil }
                    case 64, 65:
                        guard section == 0, type == question.type,
                              serviceBinding(bytes, from: offset, to: end, known: &names) else { return nil }
                        answerOwners.append(owner.value)
                    default: return nil // Signatures, TSIG and complex RRs stay uncached.
                    }
                }
                offset = end
            }
        }
        guard offset == bytes.count, !answerOwners.isEmpty else { return nil }
        var chain = Set<String>(), terminal = question.name
        for _ in 0..<64 {
            guard chain.insert(terminal).inserted else { return nil }
            if let next = aliases[terminal] { terminal = next; continue }
            guard aliases.keys.allSatisfy({ chain.contains($0) }),
                  answerOwners.allSatisfy({ $0 == terminal }) else { return nil }
            return fields
        }
        return nil
    }

    /// SVCB/HTTPS stay whole wire answers. Target names and address hints do not
    /// grant routing or address authority. Initially admit only common, fully
    /// framed parameters; unsupported keys keep their ordinary uncached path.
    private static func serviceBinding(_ bytes: [UInt8], from start: Int, to end: Int,
                                       known: inout Set<Int>) -> Bool {
        guard end - start >= 3,
              let target = readName(bytes, at: start + 2, known: &known, compressed: false),
              target.end <= end else { return false }
        let priority = read16(bytes, start)
        if priority == 0 { return target.value != "." && target.end == end }
        var offset = target.end, previous: Int = -1
        var keys = Set<UInt16>(), mandatory = Set<UInt16>()
        while offset < end {
            guard end - offset >= 4 else { return false }
            let key = read16(bytes, offset), length = Int(read16(bytes, offset + 2))
            offset += 4
            guard Int(key) > previous, key <= 6, length <= end - offset else { return false }
            let valueEnd = offset + length
            previous = Int(key); keys.insert(key)
            switch key {
            case 0:
                guard length > 0, length % 2 == 0 else { return false }
                var last: UInt16 = 0
                for index in stride(from: offset, to: valueEnd, by: 2) {
                    let required = read16(bytes, index)
                    guard required > last, required <= 6 else { return false }
                    mandatory.insert(required); last = required
                }
            case 1:
                guard length > 0 else { return false }
                var index = offset
                while index < valueEnd {
                    let count = Int(bytes[index]); index += 1
                    guard count > 0, count <= valueEnd - index else { return false }
                    index += count
                }
            case 2:
                guard length == 0 else { return false }
            case 3:
                guard length == 2 else { return false }
            case 4:
                guard length > 0, length % 4 == 0 else { return false }
            case 5:
                // ECHConfigList framing only. Its versioned contents remain
                // opaque to DNS and are never treated as validated TLS data.
                guard length >= 7, Int(read16(bytes, offset)) == length - 2 else { return false }
                var index = offset + 2
                while index < valueEnd {
                    guard valueEnd - index >= 4 else { return false }
                    let count = Int(read16(bytes, index + 2)); index += 4
                    guard count > 0, count <= valueEnd - index else { return false }
                    index += count
                }
            case 6:
                guard length > 0, length % 16 == 0 else { return false }
            default: return false
            }
            offset = valueEnd
        }
        return mandatory.isSubset(of: keys) && (!keys.contains(2) || keys.contains(1))
    }

    private static func paddingOnly(_ bytes: [UInt8], from start: Int, to end: Int) -> Bool {
        guard start >= 0, end >= start, end <= bytes.count else { return false }
        if start == end { return true }
        guard end - start >= 4, read16(bytes, start) == 12,
              Int(read16(bytes, start + 2)) == end - start - 4 else { return false }
        return bytes[(start + 4)..<end].allSatisfy { $0 == 0 }
    }

    /// Compression targets must be previously parsed name boundaries, never
    /// arbitrary RDATA/TTL bytes that rewriting might turn into another name.
    private static func readName(_ bytes: [UInt8], at start: Int, known: inout Set<Int>,
                                 compressed: Bool = true) -> Name? {
        guard start < bytes.count else { return nil }
        var offset = start, end: Int?, labels: [String] = [], visited = Set<Int>(), expanded = 1
        for _ in 0..<256 {
            guard offset < bytes.count, visited.insert(offset).inserted else { return nil }
            let position = offset, length = Int(bytes[offset])
            if length & 0xc0 == 0xc0 {
                guard compressed, offset + 1 < bytes.count else { return nil }
                let target = (length & 0x3f) << 8 | Int(bytes[offset + 1])
                guard target >= 12, target < offset, known.contains(target) else { return nil }
                known.insert(position)
                if end == nil { end = offset + 2 }
                offset = target; continue
            }
            guard length <= 63 else { return nil }
            known.insert(position); offset += 1
            if length == 0 { return Name(value: labels.isEmpty ? "." : labels.joined(separator: ".").lowercased(), end: end ?? offset) }
            guard length <= bytes.count - offset, expanded <= 255 - length - 1,
                  let label = String(bytes: bytes[offset..<(offset + length)], encoding: .utf8),
                  !label.contains("."), !label.contains("\\"), !label.contains("\0") else { return nil }
            expanded += length + 1; labels.append(label); offset += length
        }
        return nil
    }
    private static func read16(_ bytes: [UInt8], _ offset: Int) -> UInt16 { UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1]) }
    private static func read32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
    }
    private static func write32(_ value: UInt32, at offset: Int, in bytes: inout [UInt8]) {
        for i in 0..<4 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (24 - i * 8)) }
    }
}

/// Pure wire/clock fixtures. Includes malformed compression and EDNS so
/// optimization cannot change the security/capability meaning of a query.
public enum DNSQueryCacheSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "DNS TTL 缓存自检失败：\(text)" }
    }
    private final class Clock {
        private let lock = NSLock()
        private var seconds: TimeInterval = 100
        func set(_ value: TimeInterval) { lock.lock(); seconds = value; lock.unlock() }
        func now() -> Date { lock.lock(); defer { lock.unlock() }; return Date(timeIntervalSince1970: seconds) }
    }
    private static func require(_ value: Bool, _ text: String) throws {
        if !value { throw Failure(text: text) }
    }
    private static func query(_ id: UInt16 = 1, name: String = "cached.example.test", type: UInt16 = 1,
                              edns: Bool = false, options: [UInt8] = []) -> Data {
        var message = DNSMessageInspection.query(for: name, type: type, id: id)!
        if edns {
            message[11] = 1
            message.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 0, 0,
                                       UInt8(options.count >> 8), UInt8(options.count & 255)])
            message.append(contentsOf: options)
        }
        return message
    }
    private static func name(_ text: String) -> Data {
        var data = Data()
        for label in text.split(separator: ".") { data.append(UInt8(label.utf8.count)); data.append(contentsOf: label.utf8) }
        data.append(0); return data
    }
    private static func appendRecord(_ owner: Data, type: UInt16, ttl: UInt32,
                                     body: Data, to data: inout Data) {
        data.append(owner)
        data.append(contentsOf: [UInt8(type >> 8), UInt8(type & 255), 0, 1,
            UInt8(truncatingIfNeeded: ttl >> 24), UInt8(truncatingIfNeeded: ttl >> 16),
            UInt8(truncatingIfNeeded: ttl >> 8), UInt8(truncatingIfNeeded: ttl),
            UInt8(body.count >> 8), UInt8(body.count & 255)])
        data.append(body)
    }
    private static func answer(_ query: Data, ttl: UInt32 = 60, aliasTTL: UInt32? = nil,
                               edns: Bool = false) -> Data {
        let question = DNSMessageInspection.singleQuestion(in: query)!
        var data = Data(query.prefix(question.questionEnd))
        data[2] = 0x80 | (query[query.startIndex + 2] & 1); data[3] = 0x80
        for index in 6...11 { data[index] = 0 }
        data[7] = aliasTTL == nil ? 1 : 2
        if let aliasTTL {
            appendRecord(Data([0xc0, 0x0c]), type: 5, ttl: aliasTTL,
                         body: name("alias.example.test"), to: &data)
        }
        let owner = aliasTTL == nil ? Data([0xc0, 0x0c]) : name("alias.example.test")
        let address = question.type == 1 ? Data([203, 0, 113, 7])
            : Data([0x20, 0x01, 0x0d, 0xb8] + Array(repeating: UInt8(0), count: 11) + [7])
        appendRecord(owner, type: question.type, ttl: ttl, body: address, to: &data)
        if edns {
            data[11] = 1
            data.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 12, 0, 8])
            data.append(contentsOf: Array(repeating: UInt8(0), count: 8))
        }
        return data
    }

    public static func run() throws {
        try identityAndEDNS()
        try coalescingIdentityWithoutStorage()
        try serviceBindings()
        try cachedDeliveryValidation()
        try unsolicitedNeutralPadding()
        try paddedResourceBounds()
        try ttlAndScopes()
        try serveStaleAndOptimisticPrefetch()
        try malformedAndResourceBounds()
        try concurrentIDs()
    }

    private static func serveStaleAndOptimisticPrefetch() throws {
        let clock = Clock(), cache = DNSQueryCache(clock: clock.now)
        let first = query(0x1111, name: "resilient.example.test", type: 1)
        let second = query(0x2222, name: "resilient.example.test", type: 1)
        let response = answer(first, ttl: 100)
        try require(cache.store(scopeKey: "scope-A", query: first, response: response),
                    "Serve-Stale 初始正向记录未能写入缓存")
        clock.set(150) // 50s elapsed, 50s remaining (50% > 15% prefetch threshold)
        guard let mid = cache.lookupWithPrefetchHint(scopeKey: "scope-A", query: second) else {
            throw Failure(text: "中期缓存查询未命中")
        }
        try require(mid.remainingTTL == 50 && !mid.shouldPrefetch
                    && cache.lookupStale(scopeKey: "scope-A", query: second) == nil,
                    "未到期条目误触发预取提示或提前进入 Stale 容灾")
        clock.set(190) // 90s elapsed, 10s remaining (<= 15% threshold -> shouldPrefetch = true)
        guard let nearExpiry = cache.lookupWithPrefetchHint(scopeKey: "scope-A", query: second) else {
            throw Failure(text: "临期缓存查询未命中")
        }
        try require(nearExpiry.remainingTTL == 10 && nearExpiry.shouldPrefetch,
                    "临期缓存未触发乐观预取提示")
        clock.set(205) // 5s past expiry -> regular lookup returns nil, lookupStale serves 30s emergency TTL
        try require(cache.lookup(scopeKey: "scope-A", query: second) == nil
                    && cache.usage.entries == 0 && cache.usage.bytes == 0,
                    "已过期记录仍在常规 lookup 中返回或占用活跃字节预算")
        guard let staleHit = cache.lookupStale(scopeKey: "scope-A", query: second,
                                               maximumStaleWindow: 1800, staleServeTTL: 30) else {
            throw Failure(text: "RFC 8767 Serve-Stale 未能在容灾窗口内恢复过期答案")
        }
        try require(DNSMessageInspection.responseMatchesQuery(staleHit, query: second)
                    && DNSMessageInspection.addressAnswers(in: staleHit).first?.ttl == 30
                    && cache.lookupStale(scopeKey: "scope-B", query: second) == nil,
                    "Serve-Stale 事务 ID、应急 TTL (30s) 或作用域隔离错误")
        clock.set(2005) // > 1800s past expiry -> outside stale grace window
        try require(cache.lookupStale(scopeKey: "scope-A", query: second, maximumStaleWindow: 1800) == nil,
                    "超过最大容灾窗口仍返回陈旧记录")
    }

    private static func cachedDeliveryValidation() throws {
        for host in ["MiXeD.cached.example.test", "中文.café.example.test"] {
            for type: UInt16 in [1, 28, 64, 65] {
                let clock = Clock(), cache = DNSQueryCache(maximumTTL: 17, clock: clock.now)
                let original = query(0x1234, name: host, type: type, edns: true)
                var response: Data
                if type == 1 || type == 28 {
                    response = answer(original, ttl: 90, aliasTTL: 60, edns: true)
                } else {
                    response = serviceAnswer(original, records: [(serviceBody(target: "svc.example.test"), 90)],
                        aliasTTL: 60, glueTTL: 60, edns: true).wire
                }
                // A server may echo a different letter case. The identity of
                // the client's original question remains exact in the key.
                if host.hasPrefix("MiXeD") { response[13] = 0x6d }
                try require(cache.store(scopeKey: "validated", query: original, response: response),
                            "有效缓存快照不能进入新交付回归")
                for (seconds, ttl): (TimeInterval, UInt32) in [(100, 17), (100.25, 16), (101.75, 15), (116.75, 0)] {
                    clock.set(seconds)
                    for id: UInt16 in [0, 1, 0x1234, 0x7fff, 0x8000, 0xffff] {
                        var next = original
                        next[0] = UInt8(id >> 8); next[1] = UInt8(truncatingIfNeeded: id)
                        let sliced = (Data([7, 8, 9]) + next).dropFirst(3)
                        guard let hit = cache.lookup(scopeKey: "validated", prepared: DNSQueryCache.prepare(sliced)) else {
                            throw Failure(text: "已校验快照在原到期前未命中")
                        }
                        try require(DNSMessageInspection.responseMatchesQuery(hit, query: sliced)
                                    && DNSQueryCache.rewritingResponseID(hit, for: sliced) == hit
                                    && hit.count == response.count,
                                    "缓存直接交付偏离独立通用问题校验、事务 ID 或报文长度")
                        if type == 1 || type == 28 {
                            let records = DNSMessageInspection.addressAnswers(in: hit)
                            try require(records.count == 1 && records[0].ttl == ttl,
                                        "可信快照直接交付改变了 CNAME/上限 TTL 递减")
                        }
                        let mismatch = query(id, name: "unrelated.example.test", type: type, edns: true)
                        var malformed = hit; malformed[5] = 2
                        var request = hit; request[2] &= 0x7f
                        try require(DNSQueryCache.rewritingResponseID(hit, for: mismatch) == nil
                                    && DNSQueryCache.rewritingResponseID(malformed, for: sliced) == nil
                                    && DNSQueryCache.rewritingResponseID(request, for: sliced) == nil
                                    && cache.lookup(scopeKey: "other-scope", query: sliced) == nil,
                                    "私有缓存交付放宽了任意报文重写或权限范围")
                    }
                }
                clock.set(117)
                try require(cache.lookup(scopeKey: "validated", query: original) == nil,
                            "可信快照交付越过原始缓存到期时间")
            }
        }
        print("DNS cached delivery passed: strict stored snapshots, independent generic oracle, sliced queries, case/Unicode, IDs, TTL and unchanged arbitrary-response rejection")
    }

    private static func identityAndEDNS() throws {
        let first = query(), second = query(2), opt = query(edns: true)
        try require(DNSQueryCache.identity(for: first) == DNSQueryCache.identity(for: second), "事务 ID 没有从 key 分离")
        try require(DNSQueryCache.identity(for: first) != DNSQueryCache.identity(for: opt), "EDNS 能力被丢弃")
        try require(DNSQueryCache.identity(for: query(name: "CACHED.example.test")) != DNSQueryCache.identity(for: first),
                    "问题大小写被不安全合并")
        var nonRecursive = first; nonRecursive[2] = 0
        try require(DNSQueryCache.identity(for: nonRecursive) != DNSQueryCache.identity(for: first), "RD 被忽略")
        for flag: UInt8 in [0x10, 0x40] {
            var secured = first; secured[3] = flag
            try require(DNSQueryCache.identity(for: secured) == nil, "CD/保留标记被误合并")
        }
        var aware = first; aware[3] = 0x20
        try require(DNSQueryCache.identity(for: aware) != nil
                    && DNSQueryCache.identity(for: aware) != DNSQueryCache.identity(for: first), "AD 能力没有独立缓存 key")
        var dnssec = opt; dnssec[dnssec.count - 4] = 0x80
        try require(DNSQueryCache.identity(for: dnssec) == nil, "DO 被误合并")
        var awareDisabled = aware; awareDisabled[3] |= 0x10
        dnssec[3] |= 0x20
        try require(DNSQueryCache.identity(for: awareDisabled) == nil
                    && DNSQueryCache.identity(for: dnssec) == nil, "AD-aware 的 CD/DO 被误缓存")
        try require(DNSQueryCache.identity(for: query(type: 16)) == nil
                    && DNSQueryCache.identity(for: query(edns: true, options: [0, 10, 0, 1, 7])) == nil,
                    "复杂问题或未知 EDNS 选项被缓存")
        let padded = query(edns: true, options: [0, 12, 0, 2, 0, 0])
        try require(DNSQueryCache.identity(for: padded) != nil
                    && DNSQueryCache.identity(for: padded) != DNSQueryCache.identity(for: opt), "EDNS padding 未精确隔离")
        let clock = Clock(), cache = DNSQueryCache(clock: clock.now)
        var validated = answer(aware); validated[3] |= 0x20
        try require(cache.store(scopeKey: "aware", query: aware, response: validated), "合法 AD-aware 结果未缓存")
        guard let authenticated = cache.lookup(scopeKey: "aware", query: aware) else {
            throw Failure(text: "AD-aware 热查询未命中")
        }
        try require(authenticated[3] & 0x20 != 0 && cache.lookup(scopeKey: "aware", query: first) == nil,
                    "上游 AD 结果被清除或跨客户端能力复用")
        let response = answer(opt, edns: true)
        try require(cache.store(scopeKey: "edns", query: opt, response: response), "合法 EDNS/padding 响应未缓存")
        clock.set(101.1)
        guard let hit = cache.lookup(scopeKey: "edns", query: query(2, edns: true)) else {
            throw Failure(text: "EDNS 热查询没有命中")
        }
        try require(hit.suffix(23) == response.suffix(23), "OPT flags/padding 被当作 TTL 改写")
        try require(DNSMessageInspection.addressAnswers(in: hit).first?.ttl == 58, "TTL 未向下取整递减")
        try require(cache.store(scopeKey: "unsolicited", query: first, response: answer(first, edns: true)),
                    "无 OPT 请求的中性响应 padding 使合法正向答案无法缓存")
        try require(cache.lookup(scopeKey: "unsolicited", query: second) != nil
                    && cache.lookup(scopeKey: "unsolicited", query: opt) == nil,
                    "中性响应 padding 未命中或跨请求 EDNS 能力复用")
        let slice = Data([99]) + first
        try require(DNSQueryCache.identity(for: slice.dropFirst()) == DNSQueryCache.identity(for: first), "Data slice 索引处理错误")
    }

    private static func coalescingIdentityWithoutStorage() throws {
        let cache = DNSQueryCache()
        var identities = Set<Data>()
        for type in [UInt16(1), 2, 5, 6, 12, 15, 16, 28, 33, 35, 64, 65, 257] {
            let first = query(type: type), second = query(2, type: type)
            var expected = first; expected[0] = 0; expected[1] = 0
            guard let identity = DNSQueryCache.coalescingIdentity(for: first) else {
                throw Failure(text: "简单 unsigned IN 问题没有单飞资格")
            }
            try require(identity == expected && identity == DNSQueryCache.coalescingIdentity(for: second)
                        && identities.insert(identity).inserted,
                        "单飞丢失 type、精确字节或 ID 没有分离")
            let slice = Data([99]) + first
            try require(DNSQueryCache.coalescingIdentity(for: slice.dropFirst()) == identity,
                        "单飞 Data slice 索引错误")
            if type != 1 && type != 28 {
                let serviceBinding = type == 64 || type == 65
                try require((DNSQueryCache.identity(for: first) != nil) == serviceBinding
                            && !cache.store(scopeKey: "coalescing-not-storage", query: first, response: answer(first))
                            && cache.lookup(scopeKey: "coalescing-not-storage", query: second) == nil,
                            "非地址单飞错误缓存未知或无效的 RR 结构")
            }
        }
        try require(cache.usage.entries == 0, "非地址单飞生成持久缓存条目")
        for type in [UInt16(0), 24, 41, 249, 250, 251, 252, 255, 65_280] {
            try require(DNSQueryCache.coalescingIdentity(for: query(type: type)) == nil,
                        "未知 QTYPE、authentication/meta 类型或 AXFR/IXFR/ANY 获得单飞资格")
        }
        let base = query(type: 65)
        let identity = DNSQueryCache.coalescingIdentity(for: base)
        var nonRecursive = base; nonRecursive[2] = 0
        var aware = base; aware[3] = 0x20
        let opt = query(type: 65, edns: true), padded = query(type: 65, edns: true, options: [0, 12, 0, 2, 0, 0])
        for isolated in [nonRecursive, aware, query(name: "CACHED.example.test", type: 65), opt, padded] {
            try require(DNSQueryCache.coalescingIdentity(for: isolated) != nil
                        && DNSQueryCache.coalescingIdentity(for: isolated) != identity,
                        "单飞忽略 case/RD/AD/EDNS/padding 的精确能力")
        }
        try require(DNSQueryCache.coalescingIdentity(for: opt) != DNSQueryCache.coalescingIdentity(for: padded),
                    "neutral padding 被规范化跨能力合并")

        func addition(_ type: UInt16, recordClass: UInt16 = 1, owner: Data = Data([0]), body: Data) -> Data {
            var message = base; message[11] = 1
            message.append(owner)
            message.append(contentsOf: [UInt8(type >> 8), UInt8(truncatingIfNeeded: type),
                UInt8(recordClass >> 8), UInt8(truncatingIfNeeded: recordClass), 0, 0, 0, 0,
                UInt8(body.count >> 8), UInt8(truncatingIfNeeded: body.count)])
            message.append(body); return message
        }
        var tsig = name("hmac-sha256")
        tsig.append(contentsOf: [0, 0, 0, 0, 0, 1, 1, 44, 0, 32])
        tsig.append(Data(repeating: 0, count: 32))
        tsig.append(contentsOf: [0, 1, 0, 0, 0, 0])
        var sig0 = Data([0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1])
        sig0.append(name("signer.example.test")); sig0.append(Data(repeating: 0, count: 16))
        var dnssec = opt; dnssec[dnssec.count - 4] = 0x80
        var cd = base; cd[3] = 0x10
        var reserved = base; reserved[3] = 0x40
        var foreignClass = base; foreignClass[foreignClass.count - 1] = 3
        var duplicateQuestions = base; duplicateQuestions[5] = 2; duplicateQuestions.append(base.dropFirst(12))
        var answersInQuery = base; answersInQuery[7] = 1
        var authorityInQuery = base; authorityInQuery[9] = 1
        var trailing = base; trailing.append(0)
        let complex = [cd, reserved, dnssec, foreignClass, duplicateQuestions, answersInQuery, authorityInQuery, trailing,
            query(type: 65, edns: true, options: [0, 10, 0, 8] + Array(repeating: 0, count: 8)),
            query(type: 65, edns: true, options: [0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2]),
            query(type: 65, edns: true, options: [0xfd, 0xe9, 0, 0]),
            query(type: 65, edns: true, options: [0, 12, 0, 1, 7]),
            addition(250, recordClass: 255, owner: name("key.example.test"), body: tsig),
            addition(24, recordClass: 255, body: sig0), addition(65_000, body: Data([0]))]
        for unsafe in complex {
            try require(DNSQueryCache.coalescingIdentity(for: unsafe) == nil,
                        "CD/DO/TSIG/SIG0/ECS/COOKIE/未知扩展或复杂问题被合并")
        }
        print("DNS safe in-flight identity passed: exact unsigned IN reads; only structured SVCB/HTTPS expand positive storage; authenticated/complex additions remain unmerged")
    }

    private struct ServiceFixture {
        let wire: Data
        let ttlOffsets: [Int]
    }

    private static func serviceBody(priority: UInt16 = 1, target: String = ".",
                                    parameters: [(UInt16, [UInt8])] = []) -> Data {
        var body = Data([UInt8(priority >> 8), UInt8(truncatingIfNeeded: priority)])
        body.append(name(target))
        for (key, value) in parameters {
            body.append(contentsOf: [UInt8(key >> 8), UInt8(truncatingIfNeeded: key),
                                     UInt8(value.count >> 8), UInt8(value.count & 255)])
            body.append(contentsOf: value)
        }
        return body
    }

    private static func serviceAnswer(_ query: Data, records: [(Data, UInt32)],
                                      aliasTTL: UInt32? = nil, glueTTL: UInt32? = nil,
                                      edns: Bool = false, recordType: UInt16? = nil,
                                      owner: Data? = nil) -> ServiceFixture {
        let question = DNSMessageInspection.singleQuestion(in: query)!
        var data = Data(query.prefix(question.questionEnd)), offsets: [Int] = []
        data[2] = 0x80 | (query[query.startIndex + 2] & 1)
        data[3] = 0x80 | (query[query.startIndex + 3] & 0x20)
        for index in 6...11 { data[index] = 0 }
        data[7] = UInt8(records.count + (aliasTTL == nil ? 0 : 1))
        func append(_ owner: Data, type: UInt16, ttl: UInt32, body: Data) {
            offsets.append(data.count + owner.count + 4)
            appendRecord(owner, type: type, ttl: ttl, body: body, to: &data)
        }
        if let aliasTTL {
            append(Data([0xc0, 0x0c]), type: 5, ttl: aliasTTL, body: name("alias.example.test"))
        }
        let serviceOwner = owner ?? (aliasTTL == nil ? Data([0xc0, 0x0c]) : name("alias.example.test"))
        for (body, ttl) in records { append(serviceOwner, type: recordType ?? question.type, ttl: ttl, body: body) }
        if let glueTTL {
            data[11] = 1
            append(name("svc.example.test"), type: 1, ttl: glueTTL, body: Data([203, 0, 113, 9]))
        }
        if edns {
            data[11] += 1
            data.append(optRecord(options: Data([0, 12, 0, 8] + Array(repeating: 0, count: 8)), payload: 1232))
        }
        return ServiceFixture(wire: data, ttlOffsets: offsets)
    }

    private static func expectedServiceHit(_ fixture: ServiceFixture, id: UInt16, ttl: UInt32) -> Data {
        var data = fixture.wire
        data[0] = UInt8(id >> 8); data[1] = UInt8(truncatingIfNeeded: id)
        for offset in fixture.ttlOffsets {
            for index in 0..<4 { data[offset + index] = UInt8(truncatingIfNeeded: ttl >> (24 - 8 * index)) }
        }
        return data
    }

    private static func serviceBindings() throws {
        let parameters: [(UInt16, [UInt8])] = [
            (0, [0, 1, 0, 3, 0, 4, 0, 5, 0, 6]), (1, [2, 104, 50, 2, 104, 51]),
            (2, []), (3, [1, 187]), (4, [192, 0, 2, 7]),
            (5, [0, 5, 0xfe, 0x0d, 0, 1, 7]),
            (6, [0x20, 0x01, 0x0d, 0xb8] + Array(repeating: 0, count: 11) + [7])
        ]
        for type: UInt16 in [64, 65] {
            let clock = Clock(), cache = DNSQueryCache(clock: clock.now)
            let first = query(type: type, edns: true, options: [0, 12, 0, 2, 0, 0])
            let second = query(0x2345, type: type, edns: true, options: [0, 12, 0, 2, 0, 0])
            let prepared = DNSQueryCache.prepare(first), next = DNSQueryCache.prepare(second)
            let fixture = serviceAnswer(first, records: [
                (serviceBody(target: "svc.example.test", parameters: parameters), 120),
                (serviceBody(priority: 2), 60)
            ], aliasTTL: 30, glueTTL: 45, edns: true)
            try require(prepared.cacheEligible && next.cacheEligible
                        && prepared.coalescingIdentity == next.coalescingIdentity
                        && prepared.coalescingIdentity == DNSQueryCache.identity(for: first)
                        && prepared.coalescingIdentity == DNSQueryCache.coalescingIdentity(for: first),
                        "HTTPS/SVCB prepared 与兼容 identity 不一致")
            try require(cache.store(scopeKey: "service", prepared: prepared, response: fixture.wire),
                        "合法 CNAME + HTTPS/SVCB 参数正答未缓存")
            let initial = expectedServiceHit(fixture, id: 0x2345, ttl: 30)
            try require(cache.lookup(scopeKey: "service", prepared: next) == initial
                        && cache.lookup(scopeKey: "service", query: second) == initial
                        && DNSMessageInspection.addressAnswers(in: initial).isEmpty,
                        "服务绑定未保留原始 RDATA/OPT、最短 TTL、客户端 ID，或提示/glue 成为应用地址")
            clock.set(110.25)
            try require(cache.lookup(scopeKey: "service", prepared: next)
                        == expectedServiceHit(fixture, id: 0x2345, ttl: 19),
                        "服务绑定 TTL 未保守递减，或改写了参数/OPT")
            for scope in ["other-policy", "other-interface", "other-source"] {
                try require(cache.lookup(scopeKey: scope, prepared: next) == nil, "服务绑定跨作用域复用")
            }
            var rd = second; rd[2] = 0
            var ad = second; ad[3] = 0x20
            let isolated = [rd, ad, query(2, name: "CACHED.example.test", type: type, edns: true,
                                         options: [0, 12, 0, 2, 0, 0]),
                            query(2, type: type), query(2, type: type, edns: true),
                            query(2, type: type == 64 ? 65 : 64, edns: true, options: [0, 12, 0, 2, 0, 0])]
            for message in isolated {
                try require(DNSQueryCache.prepare(message).cacheEligible
                            && cache.lookup(scopeKey: "service", prepared: DNSQueryCache.prepare(message)) == nil,
                            "服务绑定忽略 type/case/RD/AD/EDNS/padding 精确隔离")
            }
            clock.set(130)
            try require(cache.lookup(scopeKey: "service", prepared: next) == nil && cache.usage.entries == 0,
                        "服务绑定超过最短 CNAME TTL")
            let capClock = Clock(), capped = DNSQueryCache(maximumTTL: 5, clock: capClock.now)
            try require(capped.store(scopeKey: "cap", query: first, response: fixture.wire)
                        && capped.lookup(scopeKey: "cap", prepared: next)
                        == expectedServiceHit(fixture, id: 0x2345, ttl: 5), "服务绑定绕过 TTL 上限")
            capClock.set(105)
            try require(capped.lookup(scopeKey: "cap", prepared: next) == nil, "服务绑定 TTL 上限过期无效")
            let alias = serviceAnswer(first, records: [(serviceBody(priority: 0, target: "alias.service.test"), 60)])
            try require(cache.store(scopeKey: "alias", prepared: prepared, response: alias.wire)
                        && cache.lookup(scopeKey: "alias", prepared: next)
                        == expectedServiceHit(alias, id: 0x2345, ttl: 60), "合法 AliasMode 未按原始回答缓存")
            cache.removeAll()
            try require(cache.usage.entries == 0 && cache.usage.bytes == 0
                        && cache.lookup(scopeKey: "alias", prepared: next) == nil, "服务绑定清空后残留条目")
            try serviceBindingBounds(type: type)
            try malformedServiceBindings(type: type)
        }
        let originalQuery = query(type: 65)
        let queryMemory = UnsafeMutableRawBufferPointer.allocate(byteCount: originalQuery.count, alignment: 1)
        defer { queryMemory.deallocate() }
        originalQuery.withUnsafeBytes { queryMemory.copyMemory(from: $0) }
        let borrowedQuery = Data(bytesNoCopy: queryMemory.baseAddress!, count: queryMemory.count, deallocator: .none)
        let prepared = DNSQueryCache.prepare(borrowedQuery)
        queryMemory[0] = 99; queryMemory[13] = 90
        let fixture = serviceAnswer(originalQuery, records: [(serviceBody(), 60)])
        let responseMemory = UnsafeMutableRawBufferPointer.allocate(byteCount: fixture.wire.count, alignment: 1)
        defer { responseMemory.deallocate() }
        fixture.wire.withUnsafeBytes { responseMemory.copyMemory(from: $0) }
        let borrowedResponse = Data(bytesNoCopy: responseMemory.baseAddress!, count: responseMemory.count, deallocator: .none)
        let copyClock = Clock(), copyCache = DNSQueryCache(clock: copyClock.now)
        try require(copyCache.store(scopeKey: "owned", prepared: prepared, response: borrowedResponse),
                    "PreparedQuery 未保留原始问题快照")
        responseMemory[fixture.wire.count - 1] = 99
        try require(copyCache.lookup(scopeKey: "owned", prepared: prepared) == fixture.wire
                    && copyCache.lookup(scopeKey: "owned", query: borrowedQuery) == nil,
                    "缓存查询或响应复用了外部可变存储")
        for type: UInt16 in [1, 28, 16, 257, 255] {
            let message = query(type: type), value = DNSQueryCache.prepare(message)
            try require(value.cacheEligible == (type == 1 || type == 28)
                        && value.coalescingIdentity == DNSQueryCache.coalescingIdentity(for: message)
                        && DNSQueryCache.identity(for: message) == (value.cacheEligible ? value.coalescingIdentity : nil),
                        "PreparedQuery 扩大了无关 RR 缓存资格")
        }
        print("DNS HTTPS/SVCB positive cache passed: strict parameters, prepared API, CNAME/minimum TTL, exact wire identity, scope/budget/flush and malformed/authenticated bypass")
    }

    private static func serviceBindingBounds(type: UInt16) throws {
        let clock = Clock(), first = query(type: type), next = query(2, type: type)
        let fixture = serviceAnswer(first, records: [(serviceBody(parameters: [(4, [192, 0, 2, 7])]), 60)], glueTTL: 8)
        let measure = DNSQueryCache(clock: clock.now)
        try require(measure.store(scopeKey: "A", query: first, response: fixture.wire), "服务绑定预算样本未缓存")
        let cost = measure.usage.bytes
        try require(measure.lookup(scopeKey: "A", query: next) == expectedServiceHit(fixture, id: 2, ttl: 8),
                    "附加 glue 最短 TTL 未约束完整缓存消息")
        let exact = DNSQueryCache(maximumBytes: cost, clock: clock.now)
        try require(exact.store(scopeKey: "A", query: first, response: fixture.wire)
                    && exact.usage.bytes == cost, "服务绑定精确预算未准入")
        let short = DNSQueryCache(maximumBytes: cost - 1, clock: clock.now)
        try require(!short.store(scopeKey: "A", query: first, response: fixture.wire)
                    && short.usage.entries == 0 && short.usage.bytes == 0, "服务绑定超预算仍缓存")
        let lru = DNSQueryCache(maximumEntries: 2, maximumBytes: cost * 2, clock: clock.now)
        try require(lru.store(scopeKey: "A", query: first, response: fixture.wire)
                    && lru.store(scopeKey: "B", prepared: DNSQueryCache.prepare(first), response: fixture.wire),
                    "服务绑定有界缓存未写入")
        _ = lru.lookup(scopeKey: "A", prepared: DNSQueryCache.prepare(next))
        try require(lru.store(scopeKey: "C", query: first, response: fixture.wire)
                    && lru.lookup(scopeKey: "B", query: next) == nil
                    && lru.lookup(scopeKey: "A", query: next) != nil
                    && lru.lookup(scopeKey: "C", query: next) != nil
                    && lru.usage.entries == 2 && lru.usage.bytes == cost * 2,
                    "服务绑定未遵守条目/字节 LRU 边界")
        clock.set(108)
        try require(lru.usage.entries == 0 && lru.usage.bytes == 0, "服务绑定过期未回收预算")
    }

    private static func malformedServiceBindings(type: UInt16) throws {
        let first = query(type: type), prepared = DNSQueryCache.prepare(first), cache = DNSQueryCache()
        let invalidParameters: [[(UInt16, [UInt8])]] = [
            [(3, [1, 187]), (1, [2, 104, 50])], [(1, [2, 104, 50]), (1, [2, 104, 51])],
            [(7, [])], [(0, [])], [(0, [1])], [(0, [0, 0])], [(0, [0, 3])],
            [(0, [0, 7]), (7, [])], [(0, [0, 3, 0, 1]), (1, [2, 104, 50]), (3, [1, 187])],
            [(0, [0, 1, 0, 1]), (1, [2, 104, 50])], [(1, [])], [(1, [0])], [(1, [3, 104, 50])],
            [(2, [])], [(1, [2, 104, 50]), (2, [1])], [(3, [1])], [(3, [1, 2, 3])],
            [(4, [])], [(4, [1, 2, 3])], [(6, [])], [(6, Array(repeating: 0, count: 15))],
            [(5, [])], [(5, [0, 0])], [(5, [0, 4, 0xfe, 0x0d, 0, 1, 7])],
            [(5, [0, 5, 0xfe, 0x0d, 0, 2, 7])], [(5, [0, 5, 0xfe, 0x0d, 0, 0, 7])]
        ]
        var badBodies = invalidParameters.map { serviceBody(parameters: $0) }
        badBodies += [Data(), Data([0]), Data([0, 1]), Data([0, 1, 0xc0, 0x0c]),
                      Data([0, 1, 1, 97]), Data([0, 1, 1, 0xff, 0]), Data([0, 1, 64] + Array(repeating: 97, count: 64) + [0]),
                      serviceBody(priority: 0), serviceBody(priority: 0, target: "alias.service.test", parameters: [(3, [1, 187])]),
                      serviceBody() + Data([0]), serviceBody() + Data([0, 1]), serviceBody() + Data([0, 1, 0]),
                      serviceBody() + Data([0, 3, 0, 3, 1, 187])]
        for (index, body) in badBodies.enumerated() {
            try require(!cache.store(scopeKey: "bad", prepared: prepared,
                                     response: serviceAnswer(first, records: [(body, 60)]).wire),
                        "HTTPS/SVCB 误缓存无效 TargetName/SvcParam：\(index)")
        }
        let base = serviceAnswer(first, records: [(serviceBody(), 60)]).wire
        var badResponses: [Data] = []
        for length in 0..<base.count { badResponses.append(Data(base.prefix(length))) }
        badResponses.append(base + Data([0]))
        badResponses.append(serviceAnswer(first, records: [(serviceBody(), 0)]).wire)
        badResponses.append(serviceAnswer(first, records: [(serviceBody(), 60)], recordType: type == 64 ? 65 : 64).wire)
        badResponses.append(serviceAnswer(first, records: [(serviceBody(), 60)], owner: name("unrelated.example.test")).wire)
        badResponses.append(serviceAnswer(first, records: [(serviceBody(), 60)], aliasTTL: 20,
                                          owner: Data([0xc0, 0x0c])).wire)
        for (offset, value): (Int, UInt8) in [(0, 99), (2, 0x83), (3, 0x83), (3, 0x82), (3, 0x85), (3, 0x90)] {
            var response = base; response[offset] = value; badResponses.append(response)
        }
        for responseType: UInt16 in [64, 65, 46, 24, 250, 65_000] {
            for section in [9, 11] {
                var response = base; response[section] = 1
                appendRecord(Data([0xc0, 0x0c]), type: responseType, ttl: 60, body: serviceBody(), to: &response)
                badResponses.append(response)
            }
        }
        let questionEnd = DNSMessageInspection.singleQuestion(in: first)!.questionEnd
        for code: UInt8 in [0, 2, 3, 5] {
            var negative = Data(base.prefix(questionEnd)); negative[7] = 0; negative[3] = 0x80 | code
            badResponses.append(negative)
        }
        badResponses.append(serviceAnswer(query(type: type == 64 ? 65 : 64), records: [(serviceBody(), 60)]).wire)
        badResponses.append(serviceAnswer(query(name: "other.example.test", type: type), records: [(serviceBody(), 60)]).wire)
        for response in badResponses {
            try require(!cache.store(scopeKey: "bad", prepared: prepared, response: response),
                        "服务绑定误缓存错配、额外/签名 RR、错误/负答、截断或零 TTL")
        }
        var cd = first; cd[3] = 0x10
        var reserved = first; reserved[3] = 0x40
        var dnssec = query(type: type, edns: true); dnssec[dnssec.count - 4] = 0x80
        for unsafe in [cd, reserved, dnssec, query(type: type, edns: true, options: [0, 10, 0, 0])] {
            let value = DNSQueryCache.prepare(unsafe)
            try require(!value.cacheEligible && value.coalescingIdentity == nil
                        && !cache.store(scopeKey: "bad", prepared: value, response: base),
                        "PreparedQuery 使 CD/DO/未知扩展获得服务绑定缓存资格")
        }
        let expandedName = Array(repeating: String(repeating: "İ", count: 30), count: 4).joined(separator: ".")
        let expandedQuery = query(name: expandedName, type: type)
        var expandedResponse = expandedQuery
        expandedResponse[2] = 0x81; expandedResponse[3] = 0x80; expandedResponse[7] = 1
        appendRecord(Data([0xc0, 0x0c]), type: type, ttl: 60, body: serviceBody(), to: &expandedResponse)
        try require(DNSMessageInspection.singleQuestion(in: expandedQuery) == nil
                    && !cache.store(scopeKey: "bad", prepared: DNSQueryCache.prepare(expandedQuery), response: expandedResponse),
                    "PreparedQuery 放宽了通用解析器的 case-fold 名称长度边界")
        try require(cache.usage.entries == 0 && cache.usage.bytes == 0,
                    "服务绑定异常或负答创建了持久缓存条目")
    }

    private static func optRecord(options: Data = Data(), owner: Data = Data([0]),
                                  payload: UInt16 = 512) -> Data {
        var record = owner
        record.append(contentsOf: [0, 41, UInt8(payload >> 8), UInt8(truncatingIfNeeded: payload),
            0, 0, 0, 0, UInt8(options.count >> 8), UInt8(truncatingIfNeeded: options.count)])
        record.append(options)
        return record
    }

    private static func zeroPadding(_ count: Int) -> Data {
        precondition((0...65_531).contains(count))
        var option = Data([0, 12, UInt8(count >> 8), UInt8(truncatingIfNeeded: count)])
        option.append(Data(repeating: 0, count: count))
        return option
    }

    private static func withOPT(_ base: Data, record: Data) -> Data {
        var response = base
        response[10] = 0; response[11] = 1
        response.append(record)
        return response
    }

    private static func twoAddressAnswer(_ message: Data, ttl: UInt32 = 300) -> Data {
        let question = DNSMessageInspection.singleQuestion(in: message)!
        var response = answer(message, ttl: ttl)
        response[7] = 2
        let address = question.type == 1 ? Data([203, 0, 113, 8])
            : Data([0x20, 0x01, 0x0d, 0xb8] + Array(repeating: UInt8(0), count: 11) + [8])
        appendRecord(Data([0xc0, 0x0c]), type: question.type, ttl: ttl, body: address, to: &response)
        return response
    }

    private static func paddedAnswer(_ base: Data, size: Int, payload: UInt16 = 512) -> Data {
        precondition(size >= base.count + 15)
        return withOPT(base, record: optRecord(options: zeroPadding(size - base.count - 15), payload: payload))
    }

    /// Reproduce the public DoH shape without any sockets: two positive RRs,
    /// then a flags-zero OPT with 392/368 zero-padding octets, totaling 468 B.
    /// Only response compatibility changes; query identities and scopes do not.
    private static func unsolicitedNeutralPadding() throws {
        for type: UInt16 in [1, 28] {
            let message = query(name: "example.com", type: type)
            let next = query(2, name: "example.com", type: type)
            let base = twoAddressAnswer(message)
            for size in [468, 512] {
                let clock = Clock(), cache = DNSQueryCache(clock: clock.now)
                let response = paddedAnswer(base, size: size)
                let opt = Data(response.dropFirst(base.count))
                try require(response.count == size && response[7] == 2 && response[11] == 1,
                            "中性 OPT 正向回归帧长度或记录数错误")
                if size == 468 {
                    try require(size - base.count - 15 == (type == 1 ? 392 : 368),
                                "468 字节回归没有覆盖真实 A/AAAA padding 长度")
                }
                try require(cache.store(scopeKey: "neutral", query: message, response: response),
                            "无 OPT 请求的合法 468/512 字节 padding 正答未缓存")
                clock.set(101.1)
                guard let hit = cache.lookup(scopeKey: "neutral", query: next) else {
                    throw Failure(text: "中性 padding 正答没有以新事务 ID 命中")
                }
                let records = DNSMessageInspection.addressAnswers(in: hit)
                try require(hit.count == size && DNSMessageInspection.responseMatchesQuery(hit, query: next)
                            && records.count == 2 && records.allSatisfy({ $0.ttl == 298 })
                            && Data(hit.suffix(opt.count)) == opt,
                            "中性 padding 被改写成 TTL、正向 TTL 未递减或客户端 ID 错误")
                try require(cache.lookup(scopeKey: "neutral", query: query(2, name: "example.com", type: type, edns: true)) == nil,
                            "响应 OPT 放宽了不同请求的 EDNS 能力隔离")
                for scope in ["other-policy", "other-source", "other-original", "other-interface"] {
                    try require(cache.lookup(scopeKey: scope, query: next) == nil,
                                "中性 padding 正答跨来源/目的/策略/接口 scope 共享")
                }
                clock.set(400)
                try require(cache.lookup(scopeKey: "neutral", query: next) == nil && cache.usage.entries == 0,
                            "中性 OPT 延长了真实 DNS TTL")
            }

            let tooLarge = paddedAnswer(base, size: 513, payload: 1232)
            try require(!DNSQueryCache().store(scopeKey: "legacy-size", query: message, response: tooLarge),
                        "响应自报 OPT payload 放宽了无 OPT 请求的 512 字节上限")
            try require(DNSQueryCache().store(scopeKey: "advertised-size",
                query: query(name: "example.com", type: type, edns: true), response: tooLarge),
                        "合法请求明确声明的 EDNS payload 上限被忽略")
            try require(DNSQueryCache().store(scopeKey: "empty-opt", query: message,
                response: withOPT(base, record: optRecord())), "中性空 OPT 被当作新的 EDNS 能力")
            try require(DNSQueryCache().store(scopeKey: "empty-padding", query: message,
                response: withOPT(base, record: optRecord(options: zeroPadding(0)))), "零长度 padding 被误拒绝")
            try require(!DNSQueryCache().store(scopeKey: "zero-ttl", query: message,
                response: paddedAnswer(twoAddressAnswer(message, ttl: 0), size: 468)), "中性 padding 使 TTL=0 被缓存")
            let capClock = Clock(), capped = DNSQueryCache(maximumTTL: 5, clock: capClock.now)
            try require(capped.store(scopeKey: "cap", query: message, response: paddedAnswer(base, size: 468)),
                        "有 TTL 上限的中性 padding 正答未缓存")
            guard let cappedHit = capped.lookup(scopeKey: "cap", query: next) else {
                throw Failure(text: "有界中性 padding 正答没有命中")
            }
            try require(DNSMessageInspection.addressAnswers(in: cappedHit).allSatisfy({ $0.ttl == 5 }),
                        "中性 padding 使 DNS TTL 上限失效")
            capClock.set(105)
            try require(capped.lookup(scopeKey: "cap", query: next) == nil, "中性 padding 绕过 TTL 上限的过期")
        }

        let message = query(name: "example.com"), base = twoAddressAnswer(message)
        let response = paddedAnswer(base, size: 468), optOffset = base.count
        var invalid: [(String, Data)] = []
        let mutations: [(String, Int, UInt8)] = [
            ("extended-rcode", optOffset + 5, 1), ("version", optOffset + 6, 1),
            ("DO", optOffset + 7, 0x80), ("flags", optOffset + 8, 1),
            ("small-payload", optOffset + 3, 1), ("nonzero-padding", response.count - 1, 1),
            ("rdata-length", optOffset + 10, 0), ("padding-length", optOffset + 14, 0)
        ]
        for (label, offset, value) in mutations {
            var corrupt = response; corrupt[offset] = value; invalid.append((label, corrupt))
        }
        // Validly framed options with meaning beyond padding remain uncached.
        let options: [(String, [UInt8])] = [
            ("COOKIE", [0, 10, 0, 8] + Array(repeating: UInt8(0), count: 8)),
            ("ECS", [0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2]),
            ("EDE", [0, 15, 0, 2, 0, 0]), ("unknown-option", [0, 99, 0, 0]),
            ("multiple-padding", [0, 12, 0, 0, 0, 12, 0, 0])
        ]
        for (label, option) in options {
            invalid.append((label, withOPT(base, record: optRecord(options: Data(option)))))
        }
        invalid.append(("nonroot-owner", withOPT(base, record: optRecord(owner: name("opt.example.test")))))
        // This points to a previously parsed, literal root label. It is a
        // well-formed name compression target, but OPT still requires root
        // encoded as the one-byte zero rather than a pointer.
        let questionEnd = DNSMessageInspection.singleQuestion(in: message)!.questionEnd
        var zeroAnswerTTL = response
        for offset in (questionEnd + 6)..<(questionEnd + 10) { zeroAnswerTTL[offset] = 0 }
        invalid.append(("one-answer-zero-ttl", zeroAnswerTTL))
        let compressedRoot = Data([0xc0, UInt8(questionEnd - 5)])
        invalid.append(("compressed-root", withOPT(base, record: optRecord(owner: compressedRoot))))
        var multiple = response; multiple[11] = 2; multiple.append(optRecord())
        invalid.append(("multiple-opt", multiple))
        var inAnswer = response; inAnswer[7] = 3; inAnswer[11] = 0
        invalid.append(("opt-in-answer", inAnswer))
        var inAuthority = response; inAuthority[9] = 1; inAuthority[11] = 0
        invalid.append(("opt-in-authority", inAuthority))
        for length in optOffset..<response.count {
            invalid.append(("truncated-opt-\(length - optOffset)", Data(response.prefix(length))))
        }
        let cache = DNSQueryCache()
        for (label, corrupt) in invalid {
            try require(!cache.store(scopeKey: "invalid-neutral", query: message, response: corrupt)
                        && cache.usage.entries == 0, "中性 OPT 回归误缓存异常帧：\(label)")
        }
        for flag: UInt8 in [0x10, 0x40] {
            var secured = message; secured[3] = flag
            try require(!cache.store(scopeKey: "secured", query: secured, response: response),
                        "中性响应 padding 放宽了请求 CD/保留标记")
        }
        var dnssec = query(name: "example.com", edns: true)
        dnssec[dnssec.count - 4] = 0x80
        try require(!cache.store(scopeKey: "dnssec", query: dnssec, response: response),
                    "中性响应 padding 放宽了请求 DO")
    }

    private static func paddedResourceBounds() throws {
        for type: UInt16 in [1, 28] {
            let clock = Clock(), message = query(name: "example.com", type: type)
            let next = query(2, name: "example.com", type: type), base = twoAddressAnswer(message)
            let padded468 = paddedAnswer(base, size: 468), padded512 = paddedAnswer(base, size: 512)
            func cost(of response: Data) throws -> Int {
                let measured = DNSQueryCache(clock: clock.now)
                try require(measured.store(scopeKey: "A", query: message, response: response),
                            "中性 padding 字节预算测量无法缓存正向帧")
                return measured.usage.bytes
            }
            let baseCost = try cost(of: base), cost468 = try cost(of: padded468), cost512 = try cost(of: padded512)
            try require(cost468 == baseCost + 468 - base.count && cost512 == cost468 + 44,
                        "缓存成本未包含完整 OPT/padding 响应字节")
            for (response, cost) in [(padded468, cost468), (padded512, cost512)] {
                let exact = DNSQueryCache(maximumEntries: 8, maximumBytes: cost, clock: clock.now)
                try require(exact.store(scopeKey: "A", query: message, response: response)
                            && exact.usage.entries == 1 && exact.usage.bytes == cost
                            && exact.lookup(scopeKey: "A", query: next)?.count == response.count,
                            "中性 padding 精确字节预算未准入或客户端 ID 查找失败")
                let short = DNSQueryCache(maximumEntries: 8, maximumBytes: cost - 1, clock: clock.now)
                try require(!short.store(scopeKey: "A", query: message, response: response)
                            && short.usage.entries == 0 && short.usage.bytes == 0,
                            "中性 padding 超出真实字节预算仍被缓存")
            }
            let limited = DNSQueryCache(maximumEntries: 8, maximumBytes: cost468, clock: clock.now)
            try require(limited.store(scopeKey: "A", query: message, response: padded468)
                        && !limited.store(scopeKey: "A", query: message, response: padded512)
                        && limited.usage.entries == 1 && limited.usage.bytes == cost468
                        && limited.lookup(scopeKey: "A", query: next)?.count == 468,
                        "超预算大帧替换破坏已有中性 padding 缓存")

            let budget = cost468 + cost512
            let lru = DNSQueryCache(maximumEntries: 8, maximumBytes: budget, clock: clock.now)
            try require(lru.store(scopeKey: "A", query: message, response: padded468)
                        && lru.store(scopeKey: "B", query: message, response: padded512)
                        && lru.usage.entries == 2 && lru.usage.bytes == budget,
                        "中性 padding 多帧未遵守总字节预算")
            _ = lru.lookup(scopeKey: "A", query: next)
            try require(lru.store(scopeKey: "C", query: message, response: padded512)
                        && lru.lookup(scopeKey: "B", query: next) == nil
                        && lru.lookup(scopeKey: "A", query: next)?.count == 468
                        && lru.lookup(scopeKey: "C", query: next)?.count == 512
                        && lru.usage.entries == 2 && lru.usage.bytes == budget,
                        "中性 padding 未按字节压力淘汰最旧条目或预算泄漏")
            lru.removeAll()
            try require(lru.usage.entries == 0 && lru.usage.bytes == 0, "清空中性 padding 缓存未释放计费字节")
        }
        print("DNS padded cache budget check passed: A/AAAA 468/512-byte replies, padding-aware costs, exact byte admission and byte-limited LRU")
    }

    private static func ttlAndScopes() throws {
        let clock = Clock(), cache = DNSQueryCache(clock: clock.now), first = query(), second = query(2)
        let response = answer(first, ttl: 60, aliasTTL: 40)
        try require(cache.store(scopeKey: "policy-A", query: first, response: response), "CNAME 正向响应未缓存")
        guard let hit = cache.lookup(scopeKey: "policy-A", query: second) else { throw Failure(text: "正向缓存未命中") }
        try require(DNSMessageInspection.responseMatchesQuery(hit, query: second)
                    && DNSMessageInspection.addressAnswers(in: hit).first?.ttl == 40, "CNAME TTL 或客户端 ID 错误")
        for scope in ["policy-B", "interface-B", "source-B", "original-B"] {
            try require(cache.lookup(scopeKey: scope, query: second) == nil, "缓存跨作用域共享")
        }
        try require(cache.lookup(scopeKey: "policy-A", query: query(type: 28)) == nil, "A 与 AAAA 混淆")
        clock.set(110.25)
        try require(DNSMessageInspection.addressAnswers(in: cache.lookup(scopeKey: "policy-A", query: second)!).first?.ttl == 29,
                    "缓存延长了最低 CNAME TTL")
        clock.set(140)
        try require(cache.lookup(scopeKey: "policy-A", query: second) == nil && cache.usage.entries == 0, "过期时仍返回旧答案")
        try require(!cache.store(scopeKey: "zero", query: first, response: answer(first, ttl: 0)), "TTL=0 被缓存")
        let capped = DNSQueryCache(maximumTTL: 5, clock: clock.now)
        try require(capped.store(scopeKey: "cap", query: first, response: answer(first, ttl: 600)), "有界 TTL 样本未缓存")
        try require(DNSMessageInspection.addressAnswers(in: capped.lookup(scopeKey: "cap", query: first)!).first?.ttl == 5, "TTL 上限未生效")
        clock.set(139)
        try require(capped.lookup(scopeKey: "cap", query: first) == nil && capped.usage.entries == 0, "时钟倒退延长了缓存")
        cache.removeAll()
        let ipv6 = query(type: 28)
        try require(cache.store(scopeKey: "ipv6", query: ipv6, response: answer(ipv6)), "合法 AAAA 未缓存")
        cache.removeAll()
        try require(cache.lookup(scopeKey: "ipv6", query: ipv6) == nil && cache.usage.bytes == 0, "清空 DNS 遗留缓存字节")
    }

    private static func malformedAndResourceBounds() throws {
        let message = query(), response = answer(message), cache = DNSQueryCache()
        let end = DNSMessageInspection.singleQuestion(in: message)!.questionEnd
        var invalid: [Data] = []
        for length in 0..<response.count { invalid.append(Data(response.prefix(length))) }
        let corruptions: [(Int, UInt8)] = [(2, 0x83), (3, 0x83), (0, 99), (6, 99),
                                          (end + 1, 11), (end + 2, 0xff), (end + 10, 0xff)]
        for (offset, value) in corruptions {
            var corrupt = response; corrupt[offset] = value; invalid.append(corrupt)
        }
        invalid.append(response + Data([0]))
        for value in invalid { try require(!cache.store(scopeKey: "bad", query: message, response: value), "截断/异常帧被缓存") }
        let root = query(name: "."), rootEnd = DNSMessageInspection.singleQuestion(in: root)!.questionEnd
        var bogusPointer = answer(root); bogusPointer[rootEnd + 1] = UInt8(rootEnd - 4)
        try require(!cache.store(scopeKey: "pointer", query: root, response: bogusPointer), "压缩指针引用非名字字段")
        let clock = Clock(), bounded = DNSQueryCache(maximumEntries: 2, maximumBytes: 1024, clock: clock.now)
        for scope in ["A", "B"] { try require(bounded.store(scopeKey: scope, query: message, response: response), "有界缓存未写入") }
        _ = bounded.lookup(scopeKey: "A", query: message)
        try require(bounded.store(scopeKey: "C", query: message, response: response), "LRU 未淘汰旧条目")
        try require(bounded.lookup(scopeKey: "B", query: message) == nil && bounded.usage.entries == 2
                    && bounded.usage.bytes <= 1024, "缓存超出条目/字节上限")
        for constrained in [DNSQueryCache(maximumEntries: 0), DNSQueryCache(maximumBytes: 1), DNSQueryCache(maximumTTL: 0)] {
            try require(!constrained.store(scopeKey: "none", query: message, response: response)
                        && constrained.usage.entries == 0, "禁用或耗尽的缓存仍接受条目")
        }
    }

    private static func concurrentIDs() throws {
        let cache = DNSQueryCache(), group = DispatchGroup(), lock = NSLock()
        var failures = 0
        for index in 1...128 {
            group.enter()
            DispatchQueue.global().async {
                let message = query(UInt16(index)), response = answer(message)
                let stored = cache.store(scopeKey: "shared", query: message, response: response)
                let hit = cache.lookup(scopeKey: "shared", query: message)
                let valid = stored && hit.map { DNSMessageInspection.responseMatchesQuery($0, query: message) } == true
                lock.lock(); if !valid { failures += 1 }; lock.unlock()
                group.leave()
            }
        }
        try require(group.wait(timeout: .now() + 3) == .success, "并发缓存操作超时")
        lock.lock(); let errors = failures; lock.unlock()
        try require(errors == 0 && cache.usage.entries == 1, "并发客户端 ID 串答或重复占用 cache entry")
    }
}

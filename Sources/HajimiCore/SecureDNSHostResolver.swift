import Foundation
import HajimiDNS
import Darwin

protocol SecureDNSBootstrapResolver: AnyObject {
    @discardableResult
    func resolve(query: Data, completion: @escaping (Data?) -> Void) -> UUID?
    func cancel(_ id: UUID)
    func cancel()
}

extension DoHResolver: SecureDNSBootstrapResolver {}

/// A stable transport pool per pinned endpoint. Transaction cancellation is
/// always by UUID; only a path flush revokes the whole resolver/pool.
private final class SecureDNSBootstrapResolverPool {
    typealias Factory = (DoHEndpoint) -> any SecureDNSBootstrapResolver
    private struct Entry {
        let endpoint: DoHEndpoint
        let resolver: any SecureDNSBootstrapResolver
    }
    private let lock = NSLock()
    private let factory: Factory
    private var entries: [Entry] = []
    private var generation: UInt64 = 0
    init(factory: @escaping Factory) { self.factory = factory }

    func lookup(_ endpoint: DoHEndpoint, _ query: Data,
                _ completion: @escaping (Data?) -> Void) -> () -> Void {
        lock.lock()
        let resolver: any SecureDNSBootstrapResolver
        if let entry = entries.first(where: { $0.endpoint == endpoint }) { resolver = entry.resolver }
        else {
            guard entries.count < 8 else { lock.unlock(); completion(nil); return {} }
            resolver = factory(endpoint); entries.append(Entry(endpoint: endpoint, resolver: resolver))
        }
        let epoch = generation
        lock.unlock()
        let id = resolver.resolve(query: query) { [weak self] answer in
            guard let self else { completion(nil); return }
            self.lock.lock(); let current = self.generation == epoch; self.lock.unlock()
            completion(current ? answer : nil)
        }
        lock.lock(); let current = generation == epoch; lock.unlock()
        if !current, let id { resolver.cancel(id) }
        return { if let id { resolver.cancel(id) } }
    }

    func flush() {
        lock.lock()
        generation &+= 1
        let old = entries; entries.removeAll()
        lock.unlock()
        old.forEach { $0.resolver.cancel() }
    }
    deinit { entries.forEach { $0.resolver.cancel() } }
}

/// Explicit first-hop bootstrapping for proxy servers. Application destination
/// names must use the query-routed resolver in NativePacketRouter instead.
/// Only pinned, certificate-verified encrypted endpoints are tried; there is
/// deliberately no getaddrinfo, system DNS, or plaintext fallback.
public final class SecureDNSHostResolver {
    public static let shared = SecureDNSHostResolver()

    typealias Lookup = (DoHEndpoint, Data, @escaping (Data?) -> Void) -> (() -> Void)
    private struct Cached {
        let addresses: [String]
        let expiry: Date
    }
    private struct Waiter {
        let id: UUID
        let queue: DispatchQueue
        let completion: (Result<[String], Error>) -> Void
        let generation: UInt64
        let started: UInt64
        let admitted: Bool
    }
    private final class Request {
        let id = UUID()
        var waiters: [Waiter]
        var cancellations: [() -> Void] = []
        var deadline: DispatchWorkItem?
        var round = 0
        var remaining = 0
        var returnedTypes = Set<UInt16>()
        var answers: [(address: String, ttl: UInt32)] = []
        let generation: UInt64
        init(waiter: Waiter) { waiters = [waiter]; generation = waiter.generation }
    }

    private let workQueue = DispatchQueue(label: "app.hajimi.dns.node-bootstrap", qos: .utility)
    private let admission = NSLock()
    private var reserved = 0
    private var generation: UInt64 = 0
    private struct FastEntry {
        let addresses: [String]
        let expiry: Date
        let generation: UInt64
    }
    private let fastCacheLock = NSLock()
    private var fastCache: [String: FastEntry] = [:]
    private var staleFastCache: [String: FastEntry] = [:]
    private var cache: [String: Cached] = [:]
    private var requests: [String: Request] = [:]
    private let endpoints: [DoHEndpoint]
    private let lookup: Lookup
    private let flushLookup: () -> Void
    private let now: () -> Date
    private let timeout: TimeInterval
    private let diagnostics: NetworkPerformanceDiagnostics

    public convenience init() {
        self.init(endpoints: [
            DoHEndpoint("https://dns.alidns.com/dns-query#223.5.5.5")!,
            DoHEndpoint("https://doh.pub/dns-query#1.12.12.12")!,
            DoHEndpoint("https://cloudflare-dns.com/dns-query#1.1.1.1")!,
            DoHEndpoint("https://dns.google/dns-query#8.8.8.8")!
        ])
    }

    init(endpoints: [DoHEndpoint], timeout: TimeInterval = 12,
         now: @escaping () -> Date = { Date(timeIntervalSince1970: LiteralAddressAttemptClock.now) },
         lookup: Lookup? = nil,
         resolverFactory: @escaping (DoHEndpoint) -> any SecureDNSBootstrapResolver = { DoHResolver(endpoint: $0, timeout: 1.2) },
         diagnostics: NetworkPerformanceDiagnostics = .shared) {
        self.endpoints = Array(endpoints.filter { DoHEndpoint.isAddressLiteral($0.connectHost) }.prefix(8))
        self.timeout = max(0.01, timeout)
        self.now = now
        self.diagnostics = diagnostics
        if let lookup { self.lookup = lookup; flushLookup = {} }
        else {
            let pool = SecureDNSBootstrapResolverPool(factory: resolverFactory)
            self.lookup = pool.lookup; flushLookup = pool.flush
        }
    }

    var currentGeneration: UInt64 {
        admission.lock(); defer { admission.unlock() }; return generation
    }
    func isCurrentGeneration(_ expected: UInt64) -> Bool {
        admission.lock(); defer { admission.unlock() }; return generation == expected
    }

    @discardableResult
    public func resolve(host: String, queue: DispatchQueue,
                        completion: @escaping (Result<[String], Error>) -> Void) -> UUID? {
        let started = NetworkPerformanceDiagnostics.now()
        func immediate(_ result: Result<[String], Error>) {
            deliver(Waiter(id: UUID(), queue: queue, completion: completion,
                generation: currentGeneration, started: started, admitted: false), result)
        }
        if host.lowercased() == "localhost" || host.lowercased() == "localhost." {
            immediate(.success(["127.0.0.1", "::1"]))
            return nil
        }
        if DoHEndpoint.isAddressLiteral(host) {
            let address = DoHEndpoint.unbracketed(host)
            immediate(.success([address]))
            return nil
        }
        guard let name = Self.normalizedName(host) else {
            immediate(.failure(Self.failure("无效的代理服务器域名")))
            return nil
        }
        admission.lock()
        guard reserved < 256 else {
            admission.unlock()
            immediate(.failure(NodeConnectionAdmissionError.capacityExceeded))
            return nil
        }
        reserved += 1
        let epoch = generation
        admission.unlock()
        let waiter = Waiter(id: UUID(), queue: queue, completion: completion,
                            generation: epoch, started: started, admitted: true)
        workQueue.async {
            guard self.isCurrentGeneration(waiter.generation) else {
                self.deliver(waiter, .failure(Self.failure("网络路径已更新，已拒绝旧 DNS 引导")),
                             outcome: .cancelled); return
            }
            if let cached = self.cache[name], cached.expiry > self.now() {
                self.deliver(waiter, .success(cached.addresses))
                return
            }
            self.cache.removeValue(forKey: name)
            if let current = self.requests[name] {
                current.waiters.append(waiter)
                return
            }
            guard self.requests.count < 64 else {
                self.deliver(waiter, .failure(NodeConnectionAdmissionError.capacityExceeded))
                return
            }
            let request = Request(waiter: waiter)
            self.requests[name] = request
            let deadline = DispatchWorkItem { [weak self, weak request] in
                guard let self, let request, self.requests[name] === request else { return }
                if request.answers.isEmpty {
                    let stale = self.sameGenerationStaleAddresses(for: name, generation: request.generation)
                    if !stale.isEmpty {
                        self.finish(name, request, .success(stale))
                    } else {
                        self.finish(name, request, .failure(Self.failure("代理服务器的加密 DNS 引导超时")))
                    }
                } else { self.completeAnswers(name, request) }
            }
            request.deadline = deadline
            self.workQueue.asyncAfter(deadline: .now() + self.timeout, execute: deadline)
            self.start(name, request)
        }
        return waiter.id
    }

    public func cancel(_ id: UUID) {
        workQueue.async {
            for (name, request) in self.requests {
                guard let index = request.waiters.firstIndex(where: { $0.id == id }) else { continue }
                let waiter = request.waiters.remove(at: index)
                self.deliver(waiter, .failure(Self.failure("安全 DNS 引导已取消")), outcome: .cancelled)
                if request.waiters.isEmpty {
                    self.requests.removeValue(forKey: name)
                    request.deadline?.cancel()
                    request.cancellations.forEach { $0() }
                }
                return
            }
        }
    }

    private func sameGenerationStaleAddresses(for name: String, generation: UInt64) -> [String] {
        let referenceNow = now()
        return fastCacheLock.withLock {
            guard let stale = staleFastCache[name],
                  stale.generation == generation,
                  isCurrentGeneration(generation),
                  stale.expiry > referenceNow else { return [] }
            return stale.addresses
        }
    }

    public func cachedAddresses(for host: String, now: Date? = nil,
                                allowStaleWithinGeneration: Bool = true) -> [String] {
        guard let name = Self.normalizedName(host.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            return []
        }
        let referenceNow = now ?? self.now()
        return fastCacheLock.withLock {
            if let entry = fastCache[name], isCurrentGeneration(entry.generation),
               entry.expiry > referenceNow {
                return entry.addresses
            }
            if allowStaleWithinGeneration,
               let stale = staleFastCache[name], isCurrentGeneration(stale.generation),
               stale.expiry > referenceNow {
                return stale.addresses
            }
            return []
        }
    }

    /// A path/interface change must not reuse an old node address indefinitely.
    public func flush() {
        admission.lock()
        generation &+= 1
        fastCacheLock.withLock {
            fastCache.removeAll()
            staleFastCache.removeAll()
        }
        workQueue.async {
            self.cache.removeAll()
            for (name, request) in Array(self.requests) {
                self.finish(name, request, .failure(Self.failure("网络路径已更新，已取消旧 DNS 引导")),
                            outcome: .cancelled)
            }
            self.flushLookup()
        }
        admission.unlock()
    }

    private func start(_ name: String, _ request: Request) {
        guard isCurrentGeneration(request.generation) else {
            finish(name, request, .failure(Self.failure("网络路径已更新，已取消旧 DNS 引导")),
                   outcome: .cancelled); return
        }
        guard request.round < endpoints.count else {
            let stale = sameGenerationStaleAddresses(for: name, generation: request.generation)
            if !stale.isEmpty {
                finish(name, request, .success(stale))
            } else {
                finish(name, request, .failure(Self.failure("代理服务器的加密 DNS 引导失败；未回退系统 DNS")))
            }
            return
        }
        request.cancellations.forEach { $0() }
        request.cancellations.removeAll()
        request.remaining = 2
        request.returnedTypes.removeAll()
        let round = request.round
        let endpoint = endpoints[round]
        for type: UInt16 in [1, 28] {
            guard let query = DNSMessageInspection.query(for: name, type: type) else {
                finish(name, request, .failure(Self.failure("无法编码代理服务器域名")))
                return
            }
            let cancel = lookup(endpoint, query) { [weak self, weak request] answer in
                guard let self, let request else { return }
                self.workQueue.async {
                    guard self.requests[name] === request, request.round == round,
                          self.isCurrentGeneration(request.generation),
                          request.returnedTypes.insert(type).inserted else { return }
                    if let answer, DNSMessageInspection.responseMatchesQuery(answer, query: query) {
                        let records = DNSMessageInspection.addressAnswers(in: answer)
                        request.answers.append(contentsOf: records.compactMap { record in
                            var v4 = in_addr(), v6 = in6_addr()
                            let valid = type == 1 ? inet_pton(AF_INET, record.address, &v4) == 1
                                : inet_pton(AF_INET6, record.address, &v6) == 1
                            return valid ? (record.address, record.ttl) : nil
                        }.prefix(16))
                    }
                    request.remaining -= 1
                    guard request.remaining == 0 else { return }
                    if request.answers.isEmpty {
                        request.round += 1
                        self.start(name, request)
                    } else { self.completeAnswers(name, request) }
                }
            }
            request.cancellations.append(cancel)
        }
    }

    private func completeAnswers(_ name: String, _ request: Request) {
        guard requests[name] === request, isCurrentGeneration(request.generation) else { return }
        var seen = Set<String>()
        // Prefer IPv4 while keeping IPv6 answers available to the caller.
        let addresses = request.answers.map(\.address).sorted {
            !$0.contains(":") && $1.contains(":")
        }.filter { seen.insert($0).inserted }.prefix(16)
        guard !addresses.isEmpty else {
            finish(name, request, .failure(Self.failure("加密 DNS 未返回可用服务器地址")))
            return
        }
        let values = Array(addresses)
        let rawTTL = request.answers.map(\.ttl).min() ?? 0
        // Enforce a 60s minimum floor for positive TTLs so 30s DDNS/CDN node records
        // do not stall Mieru-UDP stream dials every 30s (as seen in 235847.json att[30..114]).
        let ttl = rawTTL > 0 ? min(max(rawTTL, 60), 300) : 0
        if ttl > 0 {
            if cache.count >= 512 {
                cache = cache.filter { $0.value.expiry > now() }
                if cache.count >= 512 { cache.removeAll(keepingCapacity: true) }
            }
            let expiry = now().addingTimeInterval(TimeInterval(ttl))
            cache[name] = Cached(addresses: values, expiry: expiry)
            let staleExpiry = now().addingTimeInterval(3_600)
            fastCacheLock.withLock {
                if fastCache.count >= 512 { fastCache.removeAll(keepingCapacity: true) }
                if staleFastCache.count >= 512 { staleFastCache.removeAll(keepingCapacity: true) }
                fastCache[name] = FastEntry(addresses: values, expiry: expiry, generation: request.generation)
                staleFastCache[name] = FastEntry(addresses: values, expiry: staleExpiry, generation: request.generation)
            }
        }
        finish(name, request, .success(values))
    }

    private func finish(_ name: String, _ request: Request, _ result: Result<[String], Error>,
                        outcome: NetworkPerformanceOutcome? = nil) {
        guard requests[name] === request else { return }
        requests.removeValue(forKey: name)
        request.deadline?.cancel()
        request.cancellations.forEach { $0() }
        request.cancellations.removeAll()
        request.waiters.forEach { deliver($0, result, outcome: outcome) }
        request.waiters.removeAll()
    }

    private func deliver(_ waiter: Waiter, _ result: Result<[String], Error>,
                         outcome: NetworkPerformanceOutcome? = nil) {
        if waiter.admitted { admission.lock(); reserved -= 1; admission.unlock() }
        waiter.queue.async {
            let current = self.isCurrentGeneration(waiter.generation)
            let result = current ? result
                : .failure(Self.failure("网络路径已更新，已拒绝旧 DNS 引导回复"))
            let success: Bool
            if case .success = result { success = true } else { success = false }
            self.diagnostics.record(.nodeResolution,
                milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: waiter.started),
                outcome: !current ? .cancelled : outcome ?? (success ? .success : .failure))
            waiter.completion(result)
        }
    }

    fileprivate func drainForSelfTest() { workQueue.sync {} }

    private static func normalizedName(_ host: String) -> String? {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name.utf8.count <= 253,
              name.utf8.allSatisfy({ (48...57).contains($0) || (97...122).contains($0)
                  || $0 == 45 || $0 == 46 || $0 == 95 }),
              DNSMessageInspection.query(for: name, type: 1) != nil else { return nil }
        return name
    }
    private static func failure(_ text: String) -> Error { NativeOutboundError.connection(text) }
}

public enum SecureDNSHostResolverSelfTest {
    private final class EndpointProbe: SecureDNSBootstrapResolver {
        struct Transaction {
            let id: UUID
            let query: Data
            let completion: (Data?) -> Void
        }
        private let lock = NSLock()
        private var transactions: [Transaction] = []
        private var cancellations = Set<UUID>()
        private var flushes = 0
        func resolve(query: Data, completion: @escaping (Data?) -> Void) -> UUID? {
            let id = UUID()
            lock.lock(); transactions.append(Transaction(id: id, query: query, completion: completion)); lock.unlock()
            return id
        }
        func cancel(_ id: UUID) { lock.lock(); cancellations.insert(id); lock.unlock() }
        func cancel() { lock.lock(); flushes += 1; lock.unlock() }
        var snapshot: [Transaction] { lock.lock(); defer { lock.unlock() }; return transactions }
        var cancelledIDs: Set<UUID> { lock.lock(); defer { lock.unlock() }; return cancellations }
        var poolCancellations: Int { lock.lock(); defer { lock.unlock() }; return flushes }
        func answer(_ name: String) {
            for transaction in snapshot {
                guard let question = DNSMessageInspection.singleQuestion(in: transaction.query),
                      question.name == name else { continue }
                var reply = transaction.query
                reply[2] = 0x81; reply[3] = 0x80
                if question.type == 1 {
                    reply[7] = 1
                    reply.append(contentsOf: [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9])
                }
                transaction.completion(reply)
            }
        }
    }
    private final class Results {
        private let lock = NSLock()
        private var answers: [String: [Result<[String], Error>]] = [:]
        func append(_ name: String, _ value: Result<[String], Error>) {
            lock.lock(); answers[name, default: []].append(value); lock.unlock()
        }
        func values(_ name: String) -> [Result<[String], Error>] {
            lock.lock(); defer { lock.unlock() }; return answers[name] ?? []
        }
    }

    public static func run() throws {
        func expect(_ value: Bool, _ text: String) throws {
            if !value { throw NativeOutboundError.protocolError(text) }
        }
        let callbacks = DispatchQueue(label: "app.hajimi.dns.bootstrap-test.callbacks")
        let endpoint = DoHEndpoint("https://dns.google/dns-query#127.0.0.1")!
        let lock = NSLock()
        var lookups = 0
        let resolver = SecureDNSHostResolver(endpoints: [endpoint], lookup: { endpoint, query, done in
            lock.lock(); lookups += 1; lock.unlock()
            guard endpoint.connectHost == "127.0.0.1", endpoint.host == "dns.google",
                  let question = DNSMessageInspection.singleQuestion(in: query) else { done(nil); return {} }
            var answer = query
            answer[2] = 0x81; answer[3] = 0x80
            if question.type == 1 {
                answer[7] = 1
                answer.append(contentsOf: [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9])
            }
            done(answer)
            return {}
        })
        func resolve(_ host: String, with resolver: SecureDNSHostResolver) throws -> Result<[String], Error> {
            let semaphore = DispatchSemaphore(value: 0)
            var result: Result<[String], Error>?
            resolver.resolve(host: host, queue: callbacks) { result = $0; semaphore.signal() }
            try expect(semaphore.wait(timeout: .now() + 2) == .success, "安全节点 DNS 自测超时")
            return result!
        }
        try expect(try resolve("Node.Example.", with: resolver).get() == ["203.0.113.9"],
                   "节点域名未通过固定 IP 加密引导")
        try expect(try resolve("node.example", with: resolver).get() == ["203.0.113.9"],
                   "安全节点解析缓存未命中")
        try expect(try resolve("::1", with: resolver).get() == ["::1"], "literal节点不应查询DNS")
        try expect(try resolve("[::1]", with: resolver).get() == ["::1"], "IPv6 pin必须去除URL括号")
        lock.lock(); let count = lookups; lock.unlock()
        try expect(count == 2, "缓存或literal节点触发额外DNS请求")
        if case .success = try resolve("bad host", with: resolver) {
            throw NativeOutboundError.protocolError("节点域名包含空白却被接受")
        }
        let failureDiagnostics = NetworkPerformanceDiagnostics()
        let failing = SecureDNSHostResolver(endpoints: [endpoint], lookup: { _, _, done in done(nil); return {} },
                                            diagnostics: failureDiagnostics)
        if case .success = try resolve("unreachable.example", with: failing) {
            throw NativeOutboundError.protocolError("加密引导失败却退回了系统DNS")
        }
        let timedOut = SecureDNSHostResolver(endpoints: [endpoint], timeout: 0.02,
                                             lookup: { _, _, _ in {} }, diagnostics: failureDiagnostics)
        if case .success = try resolve("deadline.example", with: timedOut) {
            throw NativeOutboundError.protocolError("未响应的安全DNS没有触发deadline")
        }
        let failedStage = failureDiagnostics.snapshot().stages[.nodeResolution]
        try expect(failedStage?.count == 2 && failedStage?.failureCount == 2
                   && failedStage?.cancellationCount == 0 && failedStage?.sampleCount == 0,
                   "真实节点 DNS 故障/超时被隐藏为中止或成功")
        try sharedResolversAndCancellation()
    }

    private static func sharedResolversAndCancellation() throws {
        func expect(_ value: Bool, _ text: String) throws {
            guard value else { throw NativeOutboundError.protocolError("安全引导池自检失败：\(text)") }
        }
        let callbacks = DispatchQueue(label: "app.hajimi.bootstrap-pool.selftest.callbacks")
        let endpoint = DoHEndpoint("https://bootstrap.selftest.invalid/dns-query#127.0.0.1")!
        let factoryLock = NSLock(); var instances: [EndpointProbe] = []
        let diagnostics = NetworkPerformanceDiagnostics()
        let resolver = SecureDNSHostResolver(endpoints: [endpoint], resolverFactory: { _ in
            let probe = EndpointProbe()
            factoryLock.lock(); instances.append(probe); factoryLock.unlock()
            return probe
        }, diagnostics: diagnostics)
        func probes() -> [EndpointProbe] { factoryLock.lock(); defer { factoryLock.unlock() }; return instances }
        func drain() { resolver.drainForSelfTest(); callbacks.sync {} }
        let results = Results()
        let cancelled = resolver.resolve(host: "cancelled.node", queue: callbacks) { results.append("cancelled", $0) }!
        resolver.resolve(host: "kept.node", queue: callbacks) { results.append("kept", $0) }
        drain()
        try expect(probes().count == 1 && probes()[0].snapshot.count == 4,
                   "two hosts did not share one endpoint resolver for their A/AAAA transactions")
        let first = probes()[0]
        resolver.cancel(cancelled); drain()
        let cancelledTransactions = first.snapshot.filter { first.cancelledIDs.contains($0.id) }
        try expect(cancelledTransactions.count == 2 && first.poolCancellations == 0
                   && cancelledTransactions.allSatisfy {
                       DNSMessageInspection.singleQuestion(in: $0.query)?.name == "cancelled.node"
                   }, "one waiter cancelled another host or its shared endpoint pool")
        first.answer("kept.node"); drain()
        try expect(results.values("cancelled").count == 1 && (try? results.values("cancelled")[0].get()) == nil
                   && results.values("kept").count == 1
                   && (try? results.values("kept")[0].get()) == ["203.0.113.9"]
                   && resolver.cachedAddresses(for: "kept.node") == ["203.0.113.9"],
                   "isolated cancellation suppressed an independent host reply or fastCache clock mismatched")

        let merged = resolver.resolve(host: "merged.node", queue: callbacks) { results.append("merged-cancel", $0) }!
        resolver.resolve(host: "merged.node", queue: callbacks) { results.append("merged-kept", $0) }
        drain()
        let before = first.cancelledIDs
        resolver.cancel(merged); drain()
        try expect(first.snapshot.count == 6 && first.cancelledIDs == before,
                   "a coalesced waiter cancelled the remaining waiter's A/AAAA requests")
        first.answer("merged.node"); drain()
        try expect(results.values("merged-kept").count == 1
                   && (try? results.values("merged-kept")[0].get()) == ["203.0.113.9"],
                   "remaining coalesced waiter lost its result")

        resolver.resolve(host: "late.node", queue: callbacks) { results.append("late", $0) }
        drain()
        let generation = resolver.currentGeneration
        resolver.flush()
        try expect(!resolver.isCurrentGeneration(generation), "flush did not synchronously revoke the old generation")
        drain()
        try expect(first.poolCancellations == 1 && results.values("late").count == 1,
                   "flush did not close its old pool and active node lookup")
        first.answer("late.node"); first.answer("kept.node"); drain()
        try expect(results.values("late").count == 1 && (try? results.values("late")[0].get()) == nil,
                   "late old-generation reply republished a node address")
        resolver.resolve(host: "kept.node", queue: callbacks) { results.append("new", $0) }
        drain()
        try expect(probes().count == 2 && probes()[1].snapshot.count == 2,
                   "flush reused a cancelled endpoint resolver or old hostname cache")
        probes()[1].answer("kept.node"); drain()
        try expect(results.values("new").count == 1 && (try? results.values("new")[0].get()) == ["203.0.113.9"],
                   "fresh generation did not resolve normally")

        // A cache reply already queued for delivery must also honor a flush.
        let blocked = DispatchQueue(label: "app.hajimi.bootstrap-pool.selftest.blocked")
        let release = DispatchSemaphore(value: 0)
        blocked.async { _ = release.wait(timeout: .now() + 2) }
        resolver.resolve(host: "kept.node", queue: blocked) { results.append("stale-cache", $0) }
        resolver.drainForSelfTest(); resolver.flush(); release.signal(); blocked.sync {}
        drain()
        try expect(results.values("stale-cache").count == 1
                   && (try? results.values("stale-cache")[0].get()) == nil,
                   "queued cache delivery escaped a generation flush")
        let stage = diagnostics.snapshot().stages[.nodeResolution]
        try expect(stage?.count == 7 && stage?.failureCount == 0 && stage?.cancellationCount == 4
                   && stage?.sampleCount == 3,
                   "普通取消、路径更新或排队中的旧缓存被误报节点 DNS 故障/成功")
    }
}

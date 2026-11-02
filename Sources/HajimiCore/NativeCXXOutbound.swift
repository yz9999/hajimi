import Foundation
import HajimiProtocolsCXX
import HajimiCXXProtocolBridge
import HajimiProxyRuntime

/// A carrier recipe, not a request-bound closure. Cached clients supply their
/// independent transport queue, remaining setup deadline and policy guard.
typealias NativeCXXPreparedTransportDialer = (
    DispatchQueue, TimeInterval, @escaping () -> Bool,
    @escaping (Result<any HJByteStream, Error>) -> Void
) -> (() -> Void)?

/// Configuration and ownership only. All supported proxy handshakes, payload
/// authentication/encryption, framing and protocol sessions live in C++.
enum NativeCXXOutbound {
    private struct Configuration: Encodable {
        let type: String
        let name: String
        let host: String
        let connectHost: String?
        let port: UInt16
        let parameters: [String: String]
    }
    private struct ConfigurationIdentity: Hashable {
        let policy: ProxyPolicy
        let connectHost: String?
        init(policy: ProxyPolicy, connectHost: String?) {
            self.policy = policy; self.connectHost = connectHost.map(DoHEndpoint.unbracketed)
        }
        static func == (left: Self, right: Self) -> Bool {
            left.policy == right.policy && left.connectHost == right.connectHost
        }
        func hash(into hasher: inout Hasher) {
            hasher.combine(policy.name); hasher.combine(policy.kind.rawValue)
            hasher.combine(policy.host); hasher.combine(policy.port)
            hasher.combine(policy.username); hasher.combine(policy.password)
            hasher.combine(policy.adapterType); hasher.combine(policy.parameters)
            hasher.combine(connectHost)
        }
    }
    private struct ClientKey: Hashable {
        let configuration: ConfigurationIdentity
        let interfaceName: String?
        let addresses: [String]?
        let bootstrapGeneration: UInt64?
    }
    private final class PhysicalOwner {
        private struct Pending { var cancel: (() -> Void)?; var scopes: Set<UUID>; let soleScope: UUID? }
        // Datagram construction is not transport readiness: SOCKS starts its
        // association in start(), and stream-UDP dials only on a later send.
        // A nil deadline is a live session; each actual dial still gets 12s.
        private struct Scope {
            let generation: UInt64
            let deadline: TimeInterval?
            // An independent TCP setup may still be reading HTTP/SOCKS/etc.
            // after its native dial is ready. Ownership is detached only when
            // the C++ result is published; shared/live UDP carriers stay out.
            var readyCancellation: (() -> Void)?
        }
        private let lock = NSLock()
        private let clock: () -> TimeInterval
        private var generation: UInt64
        private var revoked = false
        private var scopes: [UUID: Scope] = [:]
        private var admissions = Set<UUID>()
        private var pending: [UUID: Pending] = [:]
        init(generation: UInt64, clock: @escaping () -> TimeInterval = { LiteralAddressAttemptClock.now }) {
            self.generation = generation; self.clock = clock
        }
        func scope(generation: UInt64, deadline: TimeInterval) -> UUID? {
            try? connectionScope(generation: generation, deadline: deadline)
        }
        func connectionScope(generation: UInt64, deadline: TimeInterval) throws -> UUID {
            try addScope(generation: generation, deadline: deadline)
        }
        func datagramScope(generation: UInt64) throws -> UUID { try addScope(generation: generation, deadline: nil) }
        private func addScope(generation: UInt64, deadline: TimeInterval?) throws -> UUID {
            lock.lock(); defer { lock.unlock() }
            guard !revoked, self.generation == generation,
                  deadline.map({ $0.isFinite && $0 > clock() }) ?? true else {
                throw NativeOutboundError.connection("C++ 连接作用域已过期")
            }
            guard scopes.count < 128 else { throw NodeConnectionAdmissionError.capacityExceeded }
            let id = UUID(); scopes[id] = Scope(generation: generation, deadline: deadline); return id
        }
        func removeScope(_ id: UUID) { removeScope(id, cancelReady: true) }
        func removeScope(_ id: UUID, cancelReady: Bool) {
            lock.lock(); let scope = scopes.removeValue(forKey: id); admissions.remove(id)
            var cancellations: [() -> Void] = []
            if cancelReady, let cancel = scope?.readyCancellation { cancellations.append(cancel) }
            // Only scopes present at invocation may keep that attempt alive.
            // A later unrelated session cannot revive an already-cancelled dial.
            for key in Array(pending.keys) {
                pending[key]?.scopes.remove(id)
                if pending[key]?.scopes.isEmpty == true {
                    if let cancel = pending.removeValue(forKey: key)?.cancel { cancellations.append(cancel) }
                }
            }
            lock.unlock(); cancellations.forEach { $0() }
        }
        func begin(generation: UInt64, scopeID: UUID? = nil) -> (UUID, TimeInterval)? {
            lock.lock(); defer { lock.unlock() }
            let now = clock()
            let eligible: [UUID: Scope]
            if let scopeID {
                // Independent TCP/stream-UDP factories carry their immutable
                // sole owner, even for later lazy dials. A missing, expired or
                // cancelled owner must not borrow another session's lifetime.
                guard let scope = scopes[scopeID], scope.generation == generation,
                      scope.deadline.map({ $0 > now }) ?? true else { return nil }
                eligible = [scopeID: scope]
            } else {
                // Only genuine shared factories (AnyTLS/SSH/QUIC) use nil.
                eligible = scopes.filter {
                    $0.value.generation == generation && ($0.value.deadline.map { $0 > now } ?? true)
                }
            }
            guard !revoked, self.generation == generation,
                  let deadline = eligible.values.map({ $0.deadline ?? now + 12 }).max()
            else { return nil }
            let id = UUID(); pending[id] = Pending(scopes: Set(eligible.keys), soleScope: scopeID)
            return (id, min(deadline, now + 12))
        }
        func install(_ id: UUID, cancel: @escaping () -> Void) {
            lock.lock(); let active = pending[id] != nil
            if active { pending[id]?.cancel = cancel }
            lock.unlock(); if !active { cancel() }
        }
        @discardableResult
        func complete(_ id: UUID, admissionFailed: Bool = false, readyCancellation: (() -> Void)? = nil) -> Bool {
            lock.lock()
            guard let attempt = pending[id] else {
                lock.unlock(); readyCancellation?(); return false
            }
            // Attribute only this actual attempt's still-live participants,
            // atomically before retiring its ownership. Never broadcast a
            // single physical capacity rejection to the whole generation.
            if admissionFailed {
                for scope in attempt.scopes where scopes[scope] != nil { admissions.insert(scope) }
            }
            var accepted = true
            if let readyCancellation {
                let now = clock()
                let eligible = attempt.scopes.filter { id in
                    guard let scope = scopes[id] else { return false }
                    return scope.generation == generation && (scope.deadline.map { $0 > now } ?? true)
                }
                if revoked || eligible.isEmpty { accepted = false }
                else if let scopeID = attempt.soleScope, let scope = scopes[scopeID], scope.deadline != nil {
                    // Independent supported TCP protocols request one carrier
                    // per setup. Unexpected extra ready carriers fail closed.
                    if scope.readyCancellation != nil { accepted = false }
                    else { scopes[scopeID]?.readyCancellation = readyCancellation }
                }
            }
            pending.removeValue(forKey: id)
            lock.unlock()
            if !accepted { readyCancellation?() }
            return accepted
        }
        func consumeAdmission(_ scope: UUID) -> Bool {
            lock.lock(); defer { lock.unlock() }; return admissions.remove(scope) != nil
        }
        func allowed(_ id: UUID, generation: UInt64) -> Bool {
            lock.lock(); defer { lock.unlock() }
            guard !revoked, self.generation == generation, let attempt = pending[id] else { return false }
            let now = clock()
            return attempt.scopes.contains { id in
                guard let scope = scopes[id] else { return false }
                return scope.generation == generation && (scope.deadline.map { $0 > now } ?? true)
            }
        }
        func advance(generation: UInt64, revoke: Bool = false) -> [() -> Void] {
            lock.lock()
            self.generation = generation; revoked = revoked || revoke
            let ready = scopes.values.compactMap(\.readyCancellation)
            scopes.removeAll(); admissions.removeAll()
            let old = pending.values.compactMap(\.cancel) + ready; pending.removeAll()
            lock.unlock(); return old
        }
    }
    private final class Entry {
        let policy: ProxyPolicy
        let interfaceName: String?
        let client: HJCppProtocolClient
        let physical: PhysicalOwner
        init(policy: ProxyPolicy, interfaceName: String?, client: HJCppProtocolClient, physical: PhysicalOwner) {
            self.policy = policy; self.interfaceName = interfaceName; self.client = client; self.physical = physical
        }
    }
    private struct ValidationResult {
        let error: String?
    }
    private struct ValidationEntry {
        let policy: ProxyPolicy
        var retainedBytes: Int
        var wire: Data?
        var tcp: ValidationResult?
        var udp: ValidationResult?
    }
    private final class ConfigurationState {
        let lock = NSLock()
        let clients: BoundedConnectionOwnerCache<ClientKey, Entry>
        let validationEntryLimit: Int, validationByteLimit: Int
        var validations: [String: ValidationEntry] = [:]
        var validationBytes = 0
        var generation: UInt64 = 0
        init(maximumClients: Int = 128, maximumClientBytes: Int = 16 * 1_024 * 1_024,
             maximumValidationEntries: Int = 1_024, maximumValidationBytes: Int = 8 * 1_024 * 1_024) {
            clients = BoundedConnectionOwnerCache(maximumEntries: maximumClients, maximumBytes: maximumClientBytes)
            validationEntryLimit = min(1_024, max(0, maximumValidationEntries))
            validationByteLimit = min(8 * 1_024 * 1_024, max(0, maximumValidationBytes))
        }
        func configure(policies: [String: ProxyPolicy], interfaceName: String?) {
            lock.lock()
            generation &+= 1
            let generation = self.generation
            let stale = clients.remove { policies[$0.policy.name] != $0.policy || $0.interfaceName != interfaceName }
            let cancellations = clients.owners.flatMap { $0.physical.advance(generation: generation) }
                + stale.flatMap { $0.physical.advance(generation: generation, revoke: true) }
            validations = validations.filter { policies[$0.key] == $0.value.policy }
            validationBytes = validations.values.reduce(0) { $0 + $1.retainedBytes }
            lock.unlock()
            cancellations.forEach { $0() }
            stale.forEach { $0.client.cancel() }
        }

        func invalidateForNetworkChange() {
            lock.lock()
            generation &+= 1
            let generation = self.generation
            let stale = clients.remove { _ in true }
            let cancellations = stale.flatMap { $0.physical.advance(generation: generation, revoke: true) }
            lock.unlock()
            cancellations.forEach { $0() }
            stale.forEach { $0.client.cancel() }
        }
    }
    private typealias ConfigurationEncoder = (ProxyPolicy, String?) throws -> Data
    private static let sharedState = ConfigurationState()
    private static var lock: NSLock { sharedState.lock }
    private static var configurationGeneration: UInt64 { sharedState.generation }
    private static let pendingConnections = LiteralAddressAttemptBudget(limit: 128)
    private static let maximumValidationEntryBytes = 64 * 1_024

    private static func validationCacheCost(_ policy: ProxyPolicy) -> Int? {
        // Count all retained fields, including credentials overridden by
        // parameters and adapterType omitted from a protocol's encoded form.
        // Per-entry/string allowances also bound many tiny parameter objects.
        var bytes = 256
        func retain(_ text: String?) -> Bool {
            guard let text else { return true }
            let count = text.utf8.count
            guard count <= maximumValidationEntryBytes - bytes - 32 else { return false }
            bytes += count + 32; return true
        }
        for text in [policy.name, policy.host, policy.username, policy.password, policy.adapterType] {
            guard retain(text) else { return nil }
        }
        for (key, value) in policy.parameters {
            guard bytes <= maximumValidationEntryBytes - 64 else { return nil }
            bytes += 64
            guard retain(key), retain(value) else { return nil }
        }
        return bytes
    }

    private static func configuration(_ policy: ProxyPolicy, connectHost: String? = nil) throws -> Data {
        guard let host = policy.host, let port = policy.port else {
            throw NativeOutboundError.unsupported("C++ 协议节点缺少服务器或端口")
        }
        let type: String
        switch policy.kind {
        case .http: type = policy.adapterType?.lowercased() == "https" ? "https" : "http"
        case .socks5: type = policy.adapterType?.lowercased() == "socks5-tls" ? "socks5-tls" : "socks5"
        default: type = policy.adapterType?.lowercased() ?? ""
        }
        var parameters = policy.parameters
        if parameters["username"] == nil { parameters["username"] = policy.username }
        if parameters["password"] == nil { parameters["password"] = policy.password }
        if ["1", "true", "yes", "on"].contains(parameters["ws"]?.lowercased() ?? "") {
            parameters["network"] = "ws"
        }
        let literal = DoHEndpoint.isAddressLiteral(host)
        let identityHost = literal ? DoHEndpoint.unbracketed(host) : host
        let pinnedAddress = connectHost.map(DoHEndpoint.unbracketed) ?? (literal ? identityHost : nil)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(Configuration(type: type, name: policy.name, host: identityHost, connectHost: pinnedAddress,
                                                port: port, parameters: parameters))
    }

    /// Reuse the existing bounded validation entry for an immutable unpinned
    /// wire image. Pinned variants live only in their bounded client owners;
    /// a live client's structural key is checked before reaching any encoder.
    private static func configurationWire(_ policy: ProxyPolicy, connectHost: String? = nil,
                                          state: ConfigurationState, expectedGeneration: UInt64,
                                          encode: ConfigurationEncoder) throws -> Data {
        state.lock.lock()
        guard state.generation == expectedGeneration else {
            state.lock.unlock(); throw NativeOutboundError.connection("节点配置已更新，已拒绝旧配置编码")
        }
        if connectHost == nil, let cached = state.validations[policy.name], cached.policy == policy,
           let wire = cached.wire {
            state.lock.unlock(); return wire
        }
        state.lock.unlock()
        let wire = try encode(policy, connectHost)
        if connectHost == nil {
            cacheValidation(policy: policy, wire: wire, result: nil, udp: false,
                            state: state, expectedGeneration: expectedGeneration)
        }
        return wire
    }

    private static func cacheValidation(policy: ProxyPolicy, wire: Data?, result: ValidationResult?, udp: Bool,
                                        state: ConfigurationState, expectedGeneration: UInt64) {
        // Large inline keys/configurations remain usable without extending
        // their lifetime through this UI/wire cache. Count the full policy,
        // including credentials overridden by its encoded parameters.
        guard let policyBytes = validationCacheCost(policy) else { return }
        state.lock.lock(); defer { state.lock.unlock() }
        guard state.generation == expectedGeneration, state.validationEntryLimit > 0 else { return }
        var cached = state.validations[policy.name].flatMap { $0.policy == policy ? $0 : nil }
            ?? ValidationEntry(policy: policy, retainedBytes: policyBytes)
        if let result {
            if udp { cached.udp = result } else { cached.tcp = result }
        }
        let baseBytes = policyBytes + (cached.tcp?.error?.utf8.count ?? 0) + (cached.udp?.error?.utf8.count ?? 0)
        guard baseBytes <= maximumValidationEntryBytes else { return }
        if let wire { cached.wire = wire }
        if (cached.wire?.count ?? 0) > maximumValidationEntryBytes - baseBytes { cached.wire = nil }
        cached.retainedBytes = baseBytes + (cached.wire?.count ?? 0)
        guard cached.retainedBytes <= state.validationByteLimit else { return }
        let previousBytes = state.validations[policy.name]?.retainedBytes ?? 0
        if (state.validations.count >= state.validationEntryLimit && state.validations[policy.name] == nil)
            || cached.retainedBytes > state.validationByteLimit - (state.validationBytes - previousBytes) {
            state.validations.removeAll(); state.validationBytes = 0
        }
        let stale = state.validations.updateValue(cached, forKey: policy.name)
        state.validationBytes += cached.retainedBytes - (stale?.retainedBytes ?? 0)
    }

    static func validationError(for policy: ProxyPolicy, udp: Bool = false) -> String? {
        validationError(for: policy, udp: udp, state: sharedState, encode: configuration)
    }

    private static func validationError(for policy: ProxyPolicy, udp: Bool, state: ConfigurationState,
                                        encode: ConfigurationEncoder) -> String? {
        state.lock.lock()
        let generation = state.generation
        if let cached = state.validations[policy.name], cached.policy == policy,
           let result = udp ? cached.udp : cached.tcp {
            state.lock.unlock(); return result.error
        }
        state.lock.unlock()
        let result: ValidationResult
        var wire: Data?
        do {
            let encoded = try configurationWire(policy, state: state, expectedGeneration: generation, encode: encode)
            wire = encoded
            result = ValidationResult(error: HJCppProtocolClient.validationError(
                configuration: encoded, udp: udp)?.localizedDescription)
        } catch { result = ValidationResult(error: error.localizedDescription) }
        cacheValidation(policy: policy, wire: wire, result: result, udp: udp,
                        state: state, expectedGeneration: generation)
        return result.error
    }

    static func selfTest() throws {
        guard hajimi_cpp_protocol_self_test() == 0 else {
            throw NativeOutboundError.protocolError("C++ 协议与加密已知答案自检失败")
        }
    }

    private final class ConfigurationEncodingProbe {
        private let lock = NSLock()
        private var encodings = 0
        private let beforeEncoding: (() -> Void)?
        init(beforeEncoding: (() -> Void)? = nil) { self.beforeEncoding = beforeEncoding }
        var count: Int { lock.lock(); defer { lock.unlock() }; return encodings }
        var encode: ConfigurationEncoder {
            { policy, host in
                self.lock.lock(); self.encodings += 1; self.lock.unlock()
                self.beforeEncoding?()
                return try configuration(policy, connectHost: host)
            }
        }
    }
    private final class ConfigurationCacheResults {
        private let lock = NSLock()
        private var identities = Set<ObjectIdentifier>(), errors: [Error] = []
        func accept(_ result: Result<BoundedConnectionOwnerLease<Entry>, Error>) {
            lock.lock(); defer { lock.unlock() }
            switch result {
            case .success(let lease): identities.insert(ObjectIdentifier(lease.owner)); lease.release()
            case .failure(let error): errors.append(error)
            }
        }
        var snapshot: (owners: Int, errors: Int) {
            lock.lock(); defer { lock.unlock() }; return (identities.count, errors.count)
        }
    }

    /// Separate cache state and configuration-only native constructors: no
    /// socket, resolver, current application configuration or dial is used.
    static func configurationCacheSelfTest() throws {
        func expect(_ value: Bool, _ text: String) throws {
            guard value else { throw NativeOutboundError.protocolError("C++ 配置缓存自检失败：\(text)") }
        }
        let policy = ProxyPolicy(name: "memory-configuration", kind: .native, host: "203.0.113.41", port: 443,
            username: "source-user", password: "source-secret", adapterType: "vmess",
            parameters: ["uuid": "00112233-4455-6677-8899-aabbccddeeff",
                         "username": "encoded-user", "password": "encoded-secret"])
        func acquire(_ policy: ProxyPolicy, state: ConfigurationState, generation: UInt64,
                     probe: ConfigurationEncodingProbe, pin: String? = nil,
                     addresses: [String]? = nil, bootstrap: UInt64? = nil,
                     interface: String? = nil) throws -> BoundedConnectionOwnerLease<Entry> {
            try client(for: policy, preparedDialer: nil, connectHost: pin, addresses: addresses,
                       bootstrapGeneration: bootstrap, interfaceName: interface, expectedGeneration: generation,
                       state: state, currentInterface: { interface }, encode: probe.encode)
        }

        let state = ConfigurationState(), probe = ConfigurationEncodingProbe()
        state.configure(policies: [policy.name: policy], interfaceName: nil)
        try expect(validationError(for: policy, udp: false, state: state, encode: probe.encode) == nil
                   && validationError(for: policy, udp: true, state: state, encode: probe.encode) == nil,
                   "memory node validation failed")
        let first = try acquire(policy, state: state, generation: 1, probe: probe)
        defer { first.release() }
        for _ in 0..<32 {
            let hit = try acquire(policy, state: state, generation: 1, probe: probe)
            try expect(hit.owner === first.owner, "identical configuration did not reuse its owner")
            hit.release()
        }
        try expect(probe.count == 1, "TCP/UDP validation and client hits repeated JSON encoding")
        let hits = ConfigurationCacheResults()
        DispatchQueue.concurrentPerform(iterations: 32) { _ in
            hits.accept(Result { try acquire(policy, state: state, generation: 1, probe: probe) })
        }
        try expect(hits.snapshot == (1, 0) && probe.count == 1,
                   "concurrent hits encoded again or published different owners")

        // Overridden source credentials still belong to the full policy
        // identity, even when their resulting JSON is deliberately identical.
        var password = policy; password.password = "changed-source-secret"
        var username = policy; username.username = "changed-source-user"
        var chain = policy; chain.parameters["underlying-proxy"] = "memory-other-hop"
        var adapter = policy; adapter.adapterType = "VMESS"
        var kind = policy; kind.kind = .external
        for changed in [password, username, chain, adapter, kind] {
            let separate = try acquire(changed, state: state, generation: 1, probe: probe)
            try expect(separate.owner !== first.owner && separate.owner.policy == changed,
                       "same-name source credentials, chain or adapter reused another policy owner")
            separate.release()
        }
        var host = policy; host.host = "203.0.113.42"
        var port = policy; port.port = 8443
        let identities = [policy, password, username, chain, adapter, kind, host, port]
            .map { ConfigurationIdentity(policy: $0, connectHost: nil) }
        try expect(Set(identities).count == identities.count
                   && (try configuration(policy)) == (try configuration(password)),
                   "full policy keys collapsed a field or source-credential fixture did not share wire bytes")
        var owners = Set<ObjectIdentifier>()
        for (pin, addresses, bootstrap, interface) in [
            ("203.0.113.50", ["203.0.113.50"], UInt64(1), Optional<String>.none),
            ("203.0.113.51", ["203.0.113.51"], UInt64(1), nil),
            ("203.0.113.50", ["203.0.113.50", "203.0.113.51"], UInt64(1), nil),
            ("203.0.113.50", ["203.0.113.50"], UInt64(2), nil),
            ("203.0.113.50", ["203.0.113.50"], UInt64(1), "en-memory")
        ] {
            let value = try acquire(policy, state: state, generation: 1, probe: probe,
                                    pin: pin, addresses: addresses, bootstrap: bootstrap, interface: interface)
            owners.insert(ObjectIdentifier(value.owner)); value.release()
        }
        try expect(owners.count == 5, "pinned address vector, bootstrap epoch or interface identities merged")

        _ = try configurationWire(policy, state: state, expectedGeneration: 1, encode: probe.encode)
        let oldScope = try first.owner.physical.connectionScope(generation: 1, deadline: LiteralAddressAttemptClock.now + 12)
        state.configure(policies: [policy.name: policy], interfaceName: nil)
        let beforeGenerationHit = probe.count
        var rejectedOldGeneration = false
        do { try acquire(policy, state: state, generation: 1, probe: probe).release() }
        catch { rejectedOldGeneration = true }
        try expect(rejectedOldGeneration && state.generation == 2 && probe.count == beforeGenerationHit,
                   "stale generation was accepted or reached an encoder")
        let advanced = try acquire(policy, state: state, generation: 2, probe: probe)
        _ = try configurationWire(policy, state: state, expectedGeneration: 2, encode: probe.encode)
        try expect(advanced.owner === first.owner && probe.count == beforeGenerationHit
                   && first.owner.physical.begin(generation: 1, scopeID: oldScope) == nil
                   && first.owner.physical.scope(generation: 2, deadline: LiteralAddressAttemptClock.now + 12) != nil,
                   "unchanged configure lost wire/client reuse or revived an old physical scope")
        advanced.release()
        state.configure(policies: [password.name: password], interfaceName: nil)
        try expect(first.owner.physical.scope(generation: 3, deadline: LiteralAddressAttemptClock.now + 12) == nil
                   && state.validations[policy.name] == nil,
                   "credential replacement retained a revoked physical owner or old cached wire")

        // Race actual encoding against configure; an old result must neither
        // repopulate the wire cache nor publish a stale native client.
        let racing = ConfigurationState(), entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        racing.configure(policies: [policy.name: policy], interfaceName: nil)
        let delayed = ConfigurationEncodingProbe {
            entered.signal(); _ = release.wait(timeout: .now() + 3)
        }
        let raced = ConfigurationCacheResults()
        DispatchQueue.global(qos: .userInitiated).async {
            raced.accept(Result { try acquire(policy, state: racing, generation: 1, probe: delayed) })
            finished.signal()
        }
        defer { release.signal() }
        try expect(entered.wait(timeout: .now() + 2) == .success, "delayed encoding did not start")
        racing.configure(policies: [password.name: password], interfaceName: nil)
        release.signal()
        try expect(finished.wait(timeout: .now() + 3) == .success && raced.snapshot == (0, 1)
                   && racing.clients.usage.entries == 0 && racing.validations.isEmpty,
                   "old in-flight encoding republished credentials or a native owner after configure")

        let concurrent = ConfigurationState(), concurrentProbe = ConfigurationEncodingProbe()
        concurrent.configure(policies: [policy.name: policy], interfaceName: nil)
        let misses = ConfigurationCacheResults()
        DispatchQueue.concurrentPerform(iterations: 16) { _ in
            misses.accept(Result { try acquire(policy, state: concurrent, generation: 1, probe: concurrentProbe) })
        }
        try expect(misses.snapshot == (1, 0) && concurrent.clients.usage.entries == 1,
                   "concurrent cold misses published duplicate client owners")

        let bounded = ConfigurationState(maximumClients: 2), capacityProbe = ConfigurationEncodingProbe()
        var secondPolicy = policy; secondPolicy.name = "memory-second"
        var thirdPolicy = policy; thirdPolicy.name = "memory-third"
        let one = try acquire(policy, state: bounded, generation: 0, probe: capacityProbe)
        let two = try acquire(secondPolicy, state: bounded, generation: 0, probe: capacityProbe)
        defer { one.release(); two.release() }
        do {
            _ = try acquire(thirdPolicy, state: bounded, generation: 0, probe: capacityProbe)
            throw NativeOutboundError.protocolError("full in-use cache accepted a third client")
        } catch NodeConnectionAdmissionError.capacityExceeded {}
        try expect(bounded.clients.usage.entries == 2
                   && one.owner.physical.scope(generation: 0, deadline: LiteralAddressAttemptClock.now + 12) != nil
                   && two.owner.physical.scope(generation: 0, deadline: LiteralAddressAttemptClock.now + 12) != nil,
                   "capacity rejection evicted an active owner")
        one.release()
        let three = try acquire(thirdPolicy, state: bounded, generation: 0, probe: capacityProbe)
        defer { three.release() }
        try expect(bounded.clients.usage.entries == 2
                   && one.owner.physical.scope(generation: 0, deadline: LiteralAddressAttemptClock.now + 12) == nil
                   && two.owner.physical.scope(generation: 0, deadline: LiteralAddressAttemptClock.now + 12) != nil,
                   "idle eviction weakened physical-owner revocation or evicted another live owner")

        let wires = ConfigurationState(maximumValidationEntries: 1, maximumValidationBytes: 4_096)
        let wireProbe = ConfigurationEncodingProbe()
        for value in [policy, policy, secondPolicy, policy] {
            _ = try configurationWire(value, state: wires, expectedGeneration: 0, encode: wireProbe.encode)
        }
        try expect(wireProbe.count == 3 && wires.validations.count == 1 && wires.validationBytes <= 4_096,
                   "wire-cache capacity retained old credential entries without bound")
        var oversized = policy; oversized.parameters["inline-memory-key"] = String(repeating: "x", count: maximumValidationEntryBytes)
        let beforeOversized = wires.validationBytes
        for _ in 0..<2 {
            _ = try configurationWire(oversized, state: wires, expectedGeneration: 0, encode: wireProbe.encode)
        }
        try expect(wireProbe.count == 5 && wires.validationBytes == beforeOversized
                   && wires.validations[policy.name]?.policy == policy,
                   "oversized credentials were retained by the wire cache")
    }

    static func bootstrapOwnershipSelfTest() throws {
        func expect(_ value: Bool, _ text: String) throws {
            guard value else { throw NativeOutboundError.protocolError("C++ bootstrap owner 自检失败：\(text)") }
        }
        let cache = BoundedConnectionOwnerCache<String, PhysicalOwner>(maximumEntries: 2, maximumBytes: 8)
        let owner = PhysicalOwner(generation: 10)
        let first = cache.insert(owner, for: "node|203.0.113.1|en0", cost: 4)!
        let other = PhysicalOwner(generation: 10)
        let second = cache.insert(other, for: "node|2001:db8::1|en0", cost: 4)!
        try expect(first.retired.isEmpty && second.retired.isEmpty, "a second IP displaced the first in-use owner")
        let scope = owner.scope(generation: 10, deadline: LiteralAddressAttemptClock.now + 2)!
        let pending = owner.begin(generation: 10)!.0
        let lock = NSLock(); var cancelled = 0
        owner.install(pending) { lock.lock(); cancelled += 1; lock.unlock() }
        // This is the retained-owner path used by unchanged configure().
        owner.advance(generation: 11).forEach { $0() }
        let reused = cache.acquire("node|203.0.113.1|en0")!
        let newScope = owner.scope(generation: 11, deadline: LiteralAddressAttemptClock.now + 2)!
        let fresh = owner.begin(generation: 11)!.0
        try expect(reused.owner === owner && !owner.allowed(pending, generation: 10)
                   && owner.allowed(fresh, generation: 11), "unchanged configure poisoned the stable owner's fresh physical dial")
        owner.install(fresh) { lock.lock(); cancelled += 1; lock.unlock() }
        owner.advance(generation: 12, revoke: true).forEach { $0() }
        lock.lock(); let count = cancelled; lock.unlock()
        try expect(count == 2 && owner.scope(generation: 12, deadline: LiteralAddressAttemptClock.now + 2) == nil
                   && !owner.allowed(fresh, generation: 11), "modified policy/interface did not revoke pending attempts")
        owner.removeScope(scope); owner.removeScope(newScope)
        reused.release(); first.lease.release(); second.lease.release()

        let shared = PhysicalOwner(generation: 20)
        let one = shared.scope(generation: 20, deadline: LiteralAddressAttemptClock.now + 2)!
        let two = shared.scope(generation: 20, deadline: LiteralAddressAttemptClock.now + 2)!
        let sharedAttempt = shared.begin(generation: 20)!.0
        var sharedCancels = 0
        shared.install(sharedAttempt) { sharedCancels += 1 }
        shared.removeScope(one)
        try expect(shared.allowed(sharedAttempt, generation: 20) && sharedCancels == 0,
                   "one logical waiter cancelled another waiter's shared physical attempt")
        shared.complete(sharedAttempt); shared.removeScope(two)
        try expect(sharedCancels == 0, "completed physical cancel reached a ready/reusable session")
        let admitted = shared.scope(generation: 20, deadline: LiteralAddressAttemptClock.now + 2)!
        let unaffected = shared.scope(generation: 20, deadline: LiteralAddressAttemptClock.now + 2)!
        let rejected = shared.begin(generation: 20, scopeID: admitted)!.0
        shared.complete(rejected, admissionFailed: true)
        try expect(shared.consumeAdmission(admitted) && !shared.consumeAdmission(admitted)
                   && !shared.consumeAdmission(unaffected),
                   "one independent physical rejection contaminated another logical scope")
        let retired = shared.begin(generation: 20, scopeID: admitted)!.0
        shared.removeScope(admitted); shared.complete(retired, admissionFailed: true)
        try expect(!shared.consumeAdmission(admitted) && !shared.consumeAdmission(unaffected)
                   && shared.begin(generation: 20, scopeID: admitted) == nil,
                   "a retired scope leaked admission metadata or borrowed another owner's dial")
        shared.removeScope(unaffected)

        // Exercise the exact production lane factory without publishing a
        // client, changing live configuration, or opening a socket. A stalled
        // first DNS caller must not become the cached factory's target queue.
        let firstCaller = DispatchQueue(label: "app.hajimi.cpp-first-caller.selftest", qos: .utility)
        let callerKey = DispatchSpecificKey<UInt8>()
        firstCaller.setSpecific(key: callerKey, value: 1)
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let progressed = DispatchSemaphore(value: 0), transport = makeTransportQueue()
        defer { release.signal() }
        firstCaller.async {
            entered.signal()
            _ = release.wait(timeout: .now() + 3)
        }
        try expect(entered.wait(timeout: .now() + 1) == .success, "first-caller scheduling fixture did not start")
        var independent = false
        transport.async {
            lock.lock(); independent = DispatchQueue.getSpecific(key: callerKey) == nil; lock.unlock()
            progressed.signal()
        }
        try expect(transport.qos.qosClass == .userInitiated && progressed.wait(timeout: .now() + 1) == .success,
                   "cached-client transport inherited a utility/caller lane or stalled behind it")
        lock.lock(); let independentResult = independent; lock.unlock()
        try expect(independentResult, "transport work executed on the first logical caller's queue")
    }

    static func configure(policies: [String: ProxyPolicy]) {
        sharedState.configure(policies: policies, interfaceName: ProxyEngine.currentOutboundInterface?.name)
    }

    static func invalidateForNetworkChange() {
        sharedState.invalidateForNetworkChange()
    }

    private static func client(for policy: ProxyPolicy,
                               preparedDialer: NativeCXXPreparedTransportDialer?, connectHost: String? = nil,
                               addresses: [String]? = nil, bootstrapGeneration: UInt64? = nil,
                               interfaceName: String? = ProxyEngine.currentOutboundInterface?.name,
                               expectedGeneration: UInt64,
                               state: ConfigurationState = sharedState,
                               currentInterface: () -> String? = { ProxyEngine.currentOutboundInterface?.name },
                               encode: ConfigurationEncoder = configuration) throws -> BoundedConnectionOwnerLease<Entry> {
        let interface = interfaceName
        guard currentInterface() == interface else {
            throw NativeOutboundError.connection("网络接口已更新，已拒绝旧节点连接")
        }
        let key = ClientKey(configuration: ConfigurationIdentity(policy: policy, connectHost: connectHost), interfaceName: interface,
                            addresses: addresses, bootstrapGeneration: bootstrapGeneration)
        let lock = state.lock, clients = state.clients
        lock.lock()
        guard state.generation == expectedGeneration else {
            lock.unlock()
            throw NativeOutboundError.connection("节点配置已更新，已拒绝使用旧 DNS 客户端")
        }
        if let existing = clients.acquire(key) {
            lock.unlock(); return existing
        }
        lock.unlock()
        let wire = try configurationWire(policy, connectHost: connectHost, state: state,
                                         expectedGeneration: expectedGeneration, encode: encode)
        let physical = PhysicalOwner(generation: expectedGeneration)
        // The cache is node/physical-identity scoped, not request-queue scoped.
        // Never inherit the first DNS (.utility) or data-plane caller's lane:
        // the same AnyTLS/QUIC factory may subsequently serve other callers.
        // Logical outputs are bound per connect/datagram session below.
        let transportQueue = makeTransportQueue()
        let candidates = addresses ?? connectHost.map { [$0] }
            ?? policy.host.flatMap { DoHEndpoint.isAddressLiteral($0) ? [DoHEndpoint.unbracketed($0)] : nil }
        let physicalDialer = preparedDialer == nil ? candidates.map {
            makePhysicalDialer(addresses: $0, interfaceName: interface, bootstrapGeneration: bootstrapGeneration,
                               physical: physical, queue: transportQueue)
        } : nil
        let prepared = preparedDialer.map {
            makePreparedDialer($0, interfaceName: interface, physical: physical, queue: transportQueue)
        }
        let client = try HJCppProtocolClient(configuration: wire, interfaceName: interface,
            queue: transportQueue, preparedTransportDialer: nil,
            scopedPreparedTransportDialer: prepared, scopedPhysicalTransportDialer: physicalDialer)
        let entry = Entry(policy: policy, interfaceName: interface, client: client, physical: physical)
        lock.lock()
        guard state.generation == expectedGeneration else {
            lock.unlock(); client.cancel()
            throw NativeOutboundError.connection("节点配置已更新，已拒绝发布旧 DNS 客户端")
        }
        if let existing = clients.acquire(key) {
            lock.unlock(); client.cancel(); return existing
        }
        let cost = clientCacheCost(policy, configuration: wire, addresses: addresses)
        let insertion = cost.flatMap { clients.insert(entry, for: key, cost: $0) }
        lock.unlock()
        guard let insertion else {
            client.cancel()
            throw NodeConnectionAdmissionError.capacityExceeded
        }
        for retired in insertion.retired {
            retired.physical.advance(generation: expectedGeneration, revoke: true).forEach { $0() }
            retired.client.cancel()
        }
        return insertion.lease
    }

    private static func makeTransportQueue() -> DispatchQueue {
        DispatchQueue(label: "app.hajimi.cpp-client.transport", qos: .userInitiated,
                      autoreleaseFrequency: .workItem)
    }

    private static func clientCacheCost(_ policy: ProxyPolicy, configuration: Data, addresses: [String]?) -> Int? {
        let maximum = 16 * 1_024 * 1_024
        var bytes = configuration.count + 512
        func retain(_ value: String?) -> Bool {
            guard let value else { return true }
            guard bytes <= maximum - 32, value.utf8.count <= maximum - bytes - 32 else { return false }
            bytes += value.utf8.count + 32; return true
        }
        for value in [policy.name, policy.host, policy.username, policy.password, policy.adapterType] {
            guard retain(value) else { return nil }
        }
        for (key, value) in policy.parameters { guard retain(key), retain(value) else { return nil } }
        for address in addresses ?? [] { guard retain(address) else { return nil } }
        return bytes <= maximum ? bytes : nil
    }

    private static func makePhysicalDialer(addresses: [String], interfaceName: String?, bootstrapGeneration: UInt64?,
                                          physical: PhysicalOwner, queue: DispatchQueue) -> HJCppScopedPhysicalTransportDialer {
        return { host, port, tls, serverName, skipVerify, alpn, interface, scope, done in
            lock.lock(); let generation = configurationGeneration; lock.unlock()
            guard DoHEndpoint.isAddressLiteral(host), interface == interfaceName,
                  ProxyEngine.currentOutboundInterface?.name == interfaceName,
                  bootstrapGeneration.map({ SecureDNSHostResolver.shared.isCurrentGeneration($0) }) ?? true,
                  let (id, deadline) = physical.begin(generation: generation, scopeID: scope) else {
                done(nil, NativeOutboundError.connection("节点物理连接已取消或配置/路径已更新")); return {}
            }
            let owner = ObjCNetworkByteStream.connectAddresses(addresses, port: port, tls: tls, serverName: serverName,
                skipCertificateVerification: skipVerify, alpn: alpn, interfaceName: interfaceName,
                queue: queue, deadline: deadline, permitted: {
                    lock.lock(); let current = configurationGeneration == generation; lock.unlock()
                    return current && physical.allowed(id, generation: generation)
                        && ProxyEngine.currentOutboundInterface?.name == interfaceName
                        && (bootstrapGeneration.map({ SecureDNSHostResolver.shared.isCurrentGeneration($0) }) ?? true)
                }, recordSetup: false) { result in
                    switch result {
                    case .success(let stream):
                        if physical.complete(id, readyCancellation: { stream.cancel() }) { done(stream.native, nil) }
                        else { done(nil, NativeOutboundError.connection("已关闭取消、过期或配置已更新的节点物理连接")) }
                    case .failure(let error):
                        physical.complete(id, admissionFailed: error is NodeConnectionAdmissionError)
                        done(nil, error)
                    }
                }
            physical.install(id) { owner.cancel() }
            return { owner.cancel() }
        }
    }

    private static func makePreparedDialer(_ dial: @escaping NativeCXXPreparedTransportDialer,
                                          interfaceName: String?, physical: PhysicalOwner,
                                          queue: DispatchQueue) -> HJCppScopedPreparedTransportDialer {
        { scope, done in
            lock.lock(); let generation = configurationGeneration; lock.unlock()
            guard ProxyEngine.currentOutboundInterface?.name == interfaceName,
                  let (id, deadline) = physical.begin(generation: generation, scopeID: scope) else {
                done(nil, NativeOutboundError.connection("已拒绝取消或旧路径的可选载体")); return {}
            }
            // Later XHTTP redials belong to the delivered carrier. Its own
            // cancel gate governs them; do not bind them to a retired setup ID.
            let permitted = {
                lock.lock(); let current = configurationGeneration == generation; lock.unlock()
                return current && ProxyEngine.currentOutboundInterface?.name == interfaceName
            }
            let cancel = dial(queue, deadline, permitted) { result in
                switch result {
                case .success(let stream):
                    if physical.complete(id, readyCancellation: { stream.cancel() }) { done(stream, nil) }
                    else { done(nil, NativeOutboundError.connection("已关闭取消或过期的可选载体")) }
                case .failure(let error):
                    physical.complete(id, admissionFailed: error is NodeConnectionAdmissionError)
                    done(nil, error)
                }
            }
            let cancellation: () -> Void = { cancel?() }
            physical.install(id, cancel: cancellation)
            return cancellation
        }
    }

    @discardableResult
    static func connect(policy: ProxyPolicy, target: RequestTarget, plainHTTP: Bool = false,
                        queue: DispatchQueue, preparedDialer: NativeCXXPreparedTransportDialer? = nil,
                        deadline: TimeInterval = LiteralAddressAttemptClock.now + 12,
                        waitForSetupAcknowledgement: Bool = false,
                        completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void)
        -> NativeCXXConnectionAttempt {
        lock.lock(); let generation = configurationGeneration; lock.unlock()
        let interface = ProxyEngine.currentOutboundInterface?.name
        let bootstrapGeneration = SecureDNSHostResolver.shared.currentGeneration
        let operation = NativeCXXConnectionAttempt(queue: queue, deadline: deadline, interfaceName: interface, permitted: {
            lock.lock(); let current = configurationGeneration == generation; lock.unlock()
            return current && ProxyEngine.currentOutboundInterface?.name == interface
                && SecureDNSHostResolver.shared.isCurrentGeneration(bootstrapGeneration)
        }, waitForSetupAcknowledgement: waitForSetupAcknowledgement, completion: completion)
        let dial: (String?, [String]?) -> Void = { connectHost, addresses in
            connectPinned(policy: policy, target: target, plainHTTP: plainHTTP, queue: queue,
                          preparedDialer: preparedDialer, connectHost: connectHost,
                          addresses: addresses, bootstrapGeneration: preparedDialer == nil ? bootstrapGeneration : nil,
                          generation: generation, operation: operation)
        }
        // Prepared/chained carriers resolve only their actual physical first
        // hop. Do not send an inner proxy name to a direct bootstrap resolver.
        guard preparedDialer == nil, let host = policy.host,
              !DoHEndpoint.isAddressLiteral(host) else { dial(nil, nil); return operation }
        let id = SecureDNSHostResolver.shared.resolve(host: host, queue: queue) { result in
            guard operation.isPending else { return }
            lock.lock(); let current = configurationGeneration == generation; lock.unlock()
            guard current else {
                operation.finish(.failure(NativeOutboundError.connection("节点配置已更新，已取消旧 DNS 引导"))); return
            }
            switch result {
            case .failure(let error): operation.finish(.failure(error))
            case .success(let addresses):
                guard let address = addresses.first else {
                    operation.finish(.failure(NativeOutboundError.connection("安全 DNS 未返回节点地址"))); return
                }
                // The factory races TCP/TLS only. Native UDP/QUIC factories
                // keep their pinned single-address semantics and reuse.
                dial(address, addresses)
            }
        }
        if let id { operation.setResolutionCancellation { SecureDNSHostResolver.shared.cancel(id) } }
        return operation
    }

    private static func connectPinned(policy: ProxyPolicy, target: RequestTarget, plainHTTP: Bool,
                                      queue: DispatchQueue, preparedDialer: NativeCXXPreparedTransportDialer?,
                                      connectHost: String?, addresses: [String]?, bootstrapGeneration: UInt64?,
                                      generation: UInt64, operation: NativeCXXConnectionAttempt) {
        guard operation.canStart else {
            operation.finish(.failure(NativeOutboundError.connection("节点连接已取消、过期或路径已更新"))); return
        }
        do {
            guard let reservation = pendingConnections.reserve() else {
                throw NodeConnectionAdmissionError.capacityExceeded
            }
            let lease: BoundedConnectionOwnerLease<Entry>
            do {
                lease = try client(for: policy, preparedDialer: preparedDialer,
                    connectHost: connectHost, addresses: addresses, bootstrapGeneration: bootstrapGeneration,
                    interfaceName: operation.interfaceName,
                    expectedGeneration: generation)
            } catch { reservation.complete(); throw error }
            let owner = lease.owner
            let scope: UUID
            do { scope = try owner.physical.connectionScope(generation: generation, deadline: operation.deadline) }
            catch { reservation.complete(); lease.release(); throw error }
            let clientRef = owner.client
            operation.setSetupCancellation {
                owner.physical.removeScope(scope)
                clientRef.cancel(connectionScope: scope)
            }
            operation.setForceFinishCleanup {
                reservation.complete()
                lease.release()
            }
            guard operation.beginSetup() else {
                reservation.complete(); owner.physical.removeScope(scope); lease.release()
                operation.finish(.failure(NativeOutboundError.connection("节点连接已取消、过期或路径已更新"))); return
            }
            owner.client.connect(host: target.host, port: target.port, udp: target.protocolName.uppercased() == "UDP",
                          plainHTTP: plainHTTP, callbackQueue: queue, connectionScope: scope) { stream, error in
                reservation.complete()
                queue.async {
                    let admission = owner.physical.consumeAdmission(scope)
                    owner.physical.removeScope(scope, cancelReady: error != nil || stream == nil)
                    lock.lock(); let current = configurationGeneration == generation; lock.unlock()
                    guard current, operation.isPending else {
                        stream?.cancel(); lease.release()
                        operation.finish(.failure(NativeOutboundError.cancelled)); return
                    }
                    if let error {
                        stream?.cancel(); lease.release()
                        operation.finish(.failure(admission ? NodeConnectionAdmissionError.capacityExceeded : error))
                    }
                    else if let stream {
                        operation.finish(.success(NativeCXXByteStream(stream, owner: owner.client, release: lease.release)))
                    } else {
                        lease.release(); operation.finish(.failure(NativeOutboundError.connection("C++ 引擎未返回连接")))
                    }
                }
            }
        } catch { operation.finish(.failure(error)) }
    }

    static func makeDatagramSession(policy: ProxyPolicy, queue: DispatchQueue,
                                    preparedDialer: NativeCXXPreparedTransportDialer? = nil,
                                    receive: @escaping (RequestTarget, Data) -> Void,
                                    failure: @escaping (Error) -> Void) throws -> NativeOutboundDatagramSession {
        if let error = validationError(for: policy, udp: true) {
            throw NativeOutboundError.unsupported(error)
        }
        lock.lock(); let generation = configurationGeneration; lock.unlock()
        let interface = ProxyEngine.currentOutboundInterface?.name
        let bootstrapGeneration = SecureDNSHostResolver.shared.currentGeneration
        if preparedDialer == nil, let host = policy.host, !DoHEndpoint.isAddressLiteral(host) {
            return BootstrappedDatagramSession(queue: queue, resolve: { completion in
                SecureDNSHostResolver.shared.resolve(host: host, queue: queue) { result in
                    lock.lock(); let current = configurationGeneration == generation; lock.unlock()
                    guard current, ProxyEngine.currentOutboundInterface?.name == interface,
                          SecureDNSHostResolver.shared.isCurrentGeneration(bootstrapGeneration) else {
                        completion(.failure(NativeOutboundError.connection("节点配置已更新，已取消旧 UDP DNS 引导"))); return
                    }
                    completion(result.flatMap { addresses in
                        guard let address = addresses.first else {
                            return .failure(NativeOutboundError.connection("安全 DNS 未返回 UDP 节点地址"))
                        }
                        do {
                            let lease = try client(for: policy,
                                preparedDialer: preparedDialer, connectHost: address, addresses: addresses,
                                bootstrapGeneration: bootstrapGeneration, interfaceName: interface,
                                expectedGeneration: generation)
                            return .success(try datagramSession(lease: lease, generation: generation,
                                                                 interfaceName: interface, bootstrapGeneration: bootstrapGeneration,
                                                                 queue: queue, receive: receive, failure: failure))
                        } catch { return .failure(error) }
                    })
                }
            }, failure: failure)
        }
        return try datagramSession(lease: client(for: policy, preparedDialer: preparedDialer,
                                                interfaceName: interface, expectedGeneration: generation), generation: generation,
                                   interfaceName: interface, bootstrapGeneration: preparedDialer == nil ? bootstrapGeneration : nil,
                                   queue: queue, receive: receive, failure: failure)
    }

    private static func datagramSession(lease: BoundedConnectionOwnerLease<Entry>, generation: UInt64,
                                        interfaceName: String?, bootstrapGeneration: UInt64?,
                                        queue: DispatchQueue, receive: @escaping (RequestTarget, Data) -> Void,
                                        failure: @escaping (Error) -> Void) throws -> NativeOutboundDatagramSession {
        try leasedDatagramSession(lease: lease, generation: generation, queue: queue,
            budget: pendingConnections, permitted: {
                lock.lock(); let current = configurationGeneration == generation; lock.unlock()
                return current && ProxyEngine.currentOutboundInterface?.name == interfaceName
                    && (bootstrapGeneration.map { SecureDNSHostResolver.shared.isCurrentGeneration($0) } ?? true)
            }, receive: receive, failure: failure)
    }

    private static func leasedDatagramSession(lease: BoundedConnectionOwnerLease<Entry>, generation: UInt64,
                                              queue: DispatchQueue, budget: LiteralAddressAttemptBudget,
                                              permitted: @escaping () -> Bool,
                                              receive: @escaping (RequestTarget, Data) -> Void,
                                              failure: @escaping (Error) -> Void,
                                              creationObserved: (() -> Void)? = nil) throws -> NativeOutboundDatagramSession {
        guard let reservation = budget.reserve() else {
            lease.release()
            throw NodeConnectionAdmissionError.capacityExceeded
        }
        let scope: UUID
        do { scope = try lease.owner.physical.datagramScope(generation: generation) }
        catch { reservation.complete(); lease.release(); throw error }
        return try NativeCXXDatagramSession(owner: lease.owner.client, queue: queue, receive: receive, failure: failure,
            release: lease.release, setupFinished: { lease.owner.physical.removeScope(scope); lease.owner.client.cancel(connectionScope: scope) }, reservation: reservation,
            scope: scope, permitted: permitted, creationObserved: creationObserved)
    }

    private final class DatagramTestClock {
        private let lock = NSLock()
        private var value: TimeInterval = 100
        func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ delta: TimeInterval) { lock.lock(); value += delta; lock.unlock() }
    }
    private final class DatagramPhysicalProbe {
        typealias Ready = ((any HJByteStream)?, Error?) -> Void
        private struct Dial {
            let id: UUID
            let scopeID: UUID?
            let deadline: TimeInterval
            let reservation: LiteralAddressAttemptReservation
            var completion: Ready?
            var cancellations = 0
        }
        let physical: PhysicalOwner
        let budget = LiteralAddressAttemptBudget(limit: 4)
        let started = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var dials: [Dial] = []
        private var invalidMetadata = false
        init(_ clock: DatagramTestClock) { physical = PhysicalOwner(generation: 7, clock: clock.now) }
        var snapshot: [(deadline: TimeInterval, cancellations: Int, scopeID: UUID?)] {
            lock.lock(); defer { lock.unlock() }; return dials.map { ($0.deadline, $0.cancellations, $0.scopeID) }
        }
        var metadataValid: Bool { lock.lock(); defer { lock.unlock() }; return !invalidMetadata }
        func dialer() -> HJCppScopedPhysicalTransportDialer {
            { host, port, tls, serverName, _, _, interface, scope, done in
                self.lock.lock()
                self.invalidMetadata = self.invalidMetadata || host != "203.0.113.41" || port != 443
                    || interface != "en-memory-datagrams" || (tls && serverName != "identity.scope.invalid")
                self.lock.unlock()
                guard let (id, deadline) = self.physical.begin(generation: 7, scopeID: scope) else {
                    done(nil, NativeOutboundError.connection("fixture physical dial had no live scope"))
                    self.started.signal(); return {}
                }
                guard let reservation = self.budget.reserve() else {
                    self.physical.complete(id, admissionFailed: true)
                    done(nil, NodeConnectionAdmissionError.capacityExceeded)
                    self.started.signal(); return {}
                }
                self.lock.lock(); let index = self.dials.count
                self.dials.append(Dial(id: id, scopeID: scope, deadline: deadline, reservation: reservation, completion: done))
                self.lock.unlock()
                self.physical.install(id) { self.cancel(index) }
                self.started.signal()
                return { self.cancel(index) }
            }
        }
        private func cancel(_ index: Int) {
            lock.lock(); defer { lock.unlock() }
            if dials[index].completion != nil, dials[index].cancellations == 0 { dials[index].cancellations = 1 }
            // A cancelled mock physical dial retains admission until its callback.
        }
        func complete(_ index: Int, carrier: NativeDatagramMemoryCarrier) {
            complete(index, native: carrier.native)
        }
        func complete(_ index: Int, native: any HJByteStream) {
            lock.lock(); let dial = dials[index]; dials[index].completion = nil; lock.unlock()
            let permitted = physical.allowed(dial.id, generation: 7)
            let accepted = physical.complete(dial.id, readyCancellation: { native.cancel() })
            dial.reservation.complete()
            guard let done = dial.completion else { native.cancel(); return }
            if permitted && accepted { done(native, nil) }
            else {
                native.cancel()
                done(nil, NativeOutboundError.connection("fixture late physical result revoked"))
            }
        }
        func fail(_ index: Int, error: Error) {
            lock.lock(); let dial = dials[index]; dials[index].completion = nil; lock.unlock()
            let permitted = physical.allowed(dial.id, generation: 7)
            physical.complete(dial.id, admissionFailed: error is NodeConnectionAdmissionError)
            dial.reservation.complete()
            if permitted { dial.completion?(nil, error) }
            else { dial.completion?(nil, NativeOutboundError.connection("fixture revoked physical failure")) }
        }
        func acknowledgeAll() {
            lock.lock(); let pending = dials
            for index in dials.indices { dials[index].completion = nil }
            lock.unlock()
            for dial in pending where dial.completion != nil {
                physical.complete(dial.id); dial.reservation.complete()
                dial.completion?(nil, NativeOutboundError.connection("fixture cleanup"))
            }
        }
    }

    private final class PhysicalScopeResults {
        let finished = DispatchSemaphore(value: 0), acknowledged = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var completions = 0, acknowledgements = 0
        private var resultError: Error?, resultStream: (any NativeOutboundByteStream)?
        func finish(_ result: Result<any NativeOutboundByteStream, Error>) {
            lock.lock(); completions += 1
            switch result {
            case .failure(let error): resultError = error
            case .success(let stream): resultStream = stream
            }
            lock.unlock(); finished.signal()
        }
        func acknowledge() { lock.lock(); acknowledgements += 1; lock.unlock(); acknowledged.signal() }
        var snapshot: (completions: Int, acknowledgements: Int, error: Error?, stream: (any NativeOutboundByteStream)?) {
            lock.lock(); defer { lock.unlock() }; return (completions, acknowledgements, resultError, resultStream)
        }
    }

    /// Exercise actual C++ VMess/HTTP/SOCKS/AnyTLS connects with immutable
    /// scoped memory carriers. No cache publication, live configuration,
    /// native socket, interface lookup, DNS, Helper or public network is used.
    static func physicalScopeIsolationSelfTest() throws {
        try NativeOutboundFactory.preparedCarrierSetupSelfTest()
        func expect(_ value: Bool, _ text: String) throws {
            guard value else { throw NativeOutboundError.protocolError("C++ 物理作用域自检失败：\(text)") }
        }
        func wait(_ value: DispatchSemaphore, _ text: String) throws {
            try expect(value.wait(timeout: .now() + 5) == .success, text)
        }
        func fixtureError(_ text: String) -> NSError {
            NSError(domain: "app.hajimi.cpp-scope-memory", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
        }
        let callbacks = DispatchQueue(label: "app.hajimi.cpp-scope-memory.callbacks")
        let diagnostics = NetworkPerformanceDiagnostics()
        func client(_ type: String, _ probe: DatagramPhysicalProbe, queue: DispatchQueue = makeTransportQueue(),
                    prepared: Bool = false) throws -> HJCppProtocolClient {
            var parameters = ["password": "memory-only", "sni": "identity.scope.invalid",
                "uuid": "00112233-4455-6677-8899-aabbccddeeff"]
            if type == "vmess" { parameters["tls"] = "true" }
            if prepared, type == "vmess" { parameters["network"] = "ws" }
            let policy = ProxyPolicy(name: "memory-connection", kind: .native, host: "node.scope.invalid", port: 443,
                adapterType: type, parameters: parameters)
            if prepared {
                let physical = probe.dialer()
                let prepared: HJCppScopedPreparedTransportDialer = { scope, done in
                    physical("203.0.113.41", 443, true, "identity.scope.invalid", false, [],
                             "en-memory-datagrams", scope, done)
                }
                return try HJCppProtocolClient(configuration: configuration(policy),
                    interfaceName: "en-memory-datagrams", queue: queue, preparedTransportDialer: nil,
                    scopedPreparedTransportDialer: prepared, scopedPhysicalTransportDialer: nil)
            }
            return try HJCppProtocolClient(configuration: configuration(policy, connectHost: "203.0.113.41"),
                interfaceName: "en-memory-datagrams", queue: queue,
                preparedTransportDialer: nil, scopedPhysicalTransportDialer: probe.dialer())
        }
        func start(_ native: HJCppProtocolClient, _ probe: DatagramPhysicalProbe, _ clock: DatagramTestClock,
                   scope: UUID, budget: LiteralAddressAttemptBudget, results: PhysicalScopeResults,
                   waitForSetupAcknowledgement: Bool = false) throws -> NativeCXXConnectionAttempt {
            guard let reservation = budget.reserve() else { throw NodeConnectionAdmissionError.capacityExceeded }
            let operation = NativeCXXConnectionAttempt(queue: callbacks, deadline: clock.now() + 12,
                interfaceName: "en-memory-datagrams", permitted: { true }, clock: clock.now,
                timing: NativeConnectionSetupTiming(diagnostics: diagnostics),
                waitForSetupAcknowledgement: waitForSetupAcknowledgement, completion: results.finish)
            operation.setSetupCancellation { probe.physical.removeScope(scope) }
            guard operation.beginSetup() else {
                reservation.complete(); probe.physical.removeScope(scope)
                throw fixtureError("memory setup could not begin")
            }
            native.connect(host: "destination.scope.invalid", port: 443, udp: false, plainHTTP: false,
                           callbackQueue: callbacks, connectionScope: scope) { stream, error in
                // Only the actual C++ connect callback retires this logical
                // reservation. Logical cancellation never synthesizes an ACK.
                reservation.complete()
                let admission = probe.physical.consumeAdmission(scope)
                probe.physical.removeScope(scope, cancelReady: error != nil || stream == nil)
                if let error { stream?.cancel(); operation.finish(.failure(admission ? NodeConnectionAdmissionError.capacityExceeded : error)) }
                else if let stream { operation.finish(.success(NativeCXXByteStream(stream, owner: native))) }
                else { operation.finish(.failure(fixtureError("memory C++ callback returned neither stream nor error"))) }
                results.acknowledge()
            }
            return operation
        }
        // Prepared/chained carriers must not borrow another logical setup's
        // scope. A DNS cancel waits for the real C++ callback, keeping both
        // the native and physical reservations occupied until that receipt.
        do {
            let clock = DatagramTestClock(), probe = DatagramPhysicalProbe(clock), budget = LiteralAddressAttemptBudget(limit: 4)
            let native = try client("vmess", probe, prepared: true), a = PhysicalScopeResults(), b = PhysicalScopeResults()
            defer { probe.acknowledgeAll(); native.cancel() }
            let scopeA = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let scopeB = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let attemptA = try start(native, probe, clock, scope: scopeA, budget: budget, results: a,
                                     waitForSetupAcknowledgement: true)
            let attemptB = try start(native, probe, clock, scope: scopeB, budget: budget, results: b,
                                     waitForSetupAcknowledgement: true)
            try wait(probe.started, "prepared A did not dial"); try wait(probe.started, "prepared B did not dial")
            attemptA.cancel(); callbacks.sync {}
            try expect(probe.snapshot.map { $0.scopeID } == [scopeA, scopeB]
                       && probe.snapshot[0].cancellations == 1 && probe.snapshot[1].cancellations == 0
                       && a.snapshot.completions == 0 && a.snapshot.acknowledgements == 0
                       && budget.usage == 2 && probe.budget.usage == 2 && attemptB.isPending,
                       "prepared cancellation fabricated an ACK, borrowed B's scope, or refunded an unacknowledged reservation")
            probe.fail(0, error: fixtureError("prepared-real-cancel-receipt"))
            try wait(a.finished, "prepared A did not finish after its actual callback")
            try wait(a.acknowledged, "prepared A did not acknowledge its C++ callback")
            try expect(budget.usage == 1 && probe.budget.usage == 1 && a.snapshot.completions == 1,
                       "prepared real receipt did not return exactly one reservation")
            attemptB.cancel(); probe.fail(1, error: fixtureError("prepared-real-cancel-receipt"))
            try wait(b.finished, "prepared B did not finish after its own receipt")
            try wait(b.acknowledged, "prepared B did not acknowledge")
            try expect(budget.usage == 0 && probe.budget.usage == 0 && b.snapshot.completions == 1,
                       "prepared cancellation leaked or repeated terminal receipts")
        }
        do {
            let clock = DatagramTestClock(), probe = DatagramPhysicalProbe(clock), budget = LiteralAddressAttemptBudget(limit: 4)
            let native = try client("vmess", probe), a = PhysicalScopeResults(), b = PhysicalScopeResults()
            defer { probe.acknowledgeAll(); native.cancel() }
            let scopeA = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let scopeB = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let attemptA = try start(native, probe, clock, scope: scopeA, budget: budget, results: a)
            let attemptB = try start(native, probe, clock, scope: scopeB, budget: budget, results: b)
            try wait(probe.started, "first independent VMess dial did not start")
            try wait(probe.started, "second independent VMess dial did not start")
            try expect(probe.snapshot.map { $0.scopeID } == [scopeA, scopeB], "VMess TCP operations lost their distinct immutable scopes")
            attemptA.cancel(); try wait(a.finished, "cancelled VMess operation did not finish independently")
            try expect(probe.snapshot[0].cancellations == 1 && probe.snapshot[1].cancellations == 0
                       && attemptB.isPending && b.snapshot.completions == 0 && probe.budget.usage == 2 && budget.usage == 2,
                       "a live unrelated VMess operation kept A's dial alive or cancellation refunded an unacknowledged slot")
            let late = NativeDatagramMemoryCarrier(type: "vmess", queue: callbacks)
            probe.complete(0, carrier: late); try wait(late.closed, "cancelled VMess scope leaked its late ready carrier")
            try wait(a.acknowledged, "cancelled VMess C++ operation never acknowledged its late physical callback")
            probe.fail(1, error: fixtureError("independent-memory-network-failure"))
            try wait(b.finished, "unrelated VMess operation failed to finish normally"); try wait(b.acknowledged, "unrelated VMess callback was not acknowledged")
            try expect(a.snapshot.completions == 1 && a.snapshot.acknowledgements == 1
                       && b.snapshot.completions == 1 && b.snapshot.acknowledgements == 1
                       && b.snapshot.error?.localizedDescription == "independent-memory-network-failure"
                       && probe.budget.usage == 0 && budget.usage == 0 && probe.metadataValid,
                       "independent cancellation repeated completion, corrupted B's error, or leaked real acknowledgements")
        }
        for reason in ["independent-memory-network-failure", "independent-memory-TLS-identity-failure"] {
            let clock = DatagramTestClock(), probe = DatagramPhysicalProbe(clock), budget = LiteralAddressAttemptBudget(limit: 4)
            let native = try client("vmess", probe), a = PhysicalScopeResults(), b = PhysicalScopeResults()
            defer { probe.acknowledgeAll(); native.cancel() }
            let scopeA = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let scopeB = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            _ = try start(native, probe, clock, scope: scopeA, budget: budget, results: a)
            _ = try start(native, probe, clock, scope: scopeB, budget: budget, results: b)
            try wait(probe.started, "capacity-test VMess A did not dial"); try wait(probe.started, "capacity-test VMess B did not dial")
            probe.fail(0, error: NodeConnectionAdmissionError.capacityExceeded)
            try wait(a.finished, "physical capacity rejection did not finish its owner"); try wait(a.acknowledged, "capacity owner did not acknowledge")
            probe.fail(1, error: fixtureError(reason)); try wait(b.finished, "B's genuine physical failure did not finish")
            try wait(b.acknowledged, "B's genuine failure did not acknowledge")
            try expect(a.snapshot.error.map { $0 is NodeConnectionAdmissionError } == true
                       && b.snapshot.error.map { $0 is NodeConnectionAdmissionError } != true
                       && b.snapshot.error?.localizedDescription == reason && budget.usage == 0 && probe.budget.usage == 0,
                       "one VMess physical capacity refusal overwrote another operation's real network/TLS failure")
        }
        // HTTP and SOCKS must cancel after native readiness as well as while
        // dialing. Keep the C++ strand held after a real native read begins:
        // raw cancel may happen, but admission cannot retire before its actual
        // native read callback reaches the C++ completion on that strand.
        for (prepared, acknowledged) in [(false, false), (true, false), (true, true)] {
        for type in ["http", "socks5"] {
            let clock = DatagramTestClock(), probe = DatagramPhysicalProbe(clock), budget = LiteralAddressAttemptBudget(limit: 4)
            let transport = makeTransportQueue(), native = try client(type, probe, queue: transport, prepared: prepared)
            let a = PhysicalScopeResults(), b = PhysicalScopeResults()
            let rawA = NativeScopeHandshakeMemoryCarrier(type: type), rawB = NativeScopeHandshakeMemoryCarrier(type: type)
            defer { a.snapshot.stream?.cancel(); b.snapshot.stream?.cancel(); probe.acknowledgeAll(); native.cancel() }
            let scopeA = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let scopeB = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let attemptA = try start(native, probe, clock, scope: scopeA, budget: budget, results: a,
                                     waitForSetupAcknowledgement: acknowledged)
            let attemptB = try start(native, probe, clock, scope: scopeB, budget: budget, results: b)
            try wait(probe.started, "blackhole A did not dial"); try wait(probe.started, "blackhole B did not dial")
            probe.complete(0, native: rawA.native); probe.complete(1, native: rawB.native)
            try wait(rawA.reading, "A did not enter the real C++ handshake read"); try wait(rawB.reading, "B did not enter the real C++ handshake read")
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            transport.async { entered.signal(); _ = release.wait(timeout: .now() + 5) }
            defer { release.signal() }
            try wait(entered, "handshake fixture could not hold the C++ strand")
            attemptA.cancel()
            if !acknowledged { try wait(a.finished, "raw-ready A did not finish its own cancellation") }
            try wait(rawA.closed, "raw-ready A's blocked HTTP/SOCKS carrier was not closed")
            try expect(rawA.closeCount == 1 && rawB.closeCount == 0 && attemptB.isPending
                       && a.snapshot.acknowledgements == 0 && b.snapshot.completions == 0
                       && a.snapshot.completions == (acknowledged ? 0 : 1)
                       && budget.usage == 2 && probe.budget.usage == 0
                       && probe.snapshot.allSatisfy { $0.cancellations == 0 },
                       "handshake cancellation closed B, missed A's raw owner, or fabricated an early C++/native acknowledgement")
            release.signal(); try wait(a.acknowledged, "A's native read cancellation never reached the real C++ completion")
            if acknowledged { try wait(a.finished, "raw-ready A did not publish its actual cancellation receipt") }
            try expect(budget.usage == 1 && a.snapshot.completions == 1, "raw-ready A leaked or double-retired its logical reservation")
            rawB.releaseHandshake(); try wait(b.finished, "B's unchanged carrier could not complete its handshake")
            try wait(b.acknowledged, "successful B did not acknowledge its real C++ callback")
            guard let published = b.snapshot.stream else { throw fixtureError("successful memory B did not return a stream") }
            probe.physical.removeScope(scopeB); attemptB.cancel()
            let sent = DispatchSemaphore(value: 0), sentResult = PhysicalScopeResults()
            published.send(Data("after-publication".utf8)) { error in
                if let error { sentResult.finish(.failure(error)) }; sent.signal()
            }
            try wait(sent, "published stream was no longer writable after setup ownership detached")
            try expect(rawB.closeCount == 0 && sentResult.snapshot.error == nil && b.snapshot.error == nil
                       && b.snapshot.completions == 1 && budget.usage == 0,
                       "successful setup detachment closed an established published stream")
            published.cancel(); try wait(rawB.closed, "explicit established-stream cancellation no longer closed its carrier")
        }
        }
        for prepared in [false, true] {
            let clock = DatagramTestClock(), probe = DatagramPhysicalProbe(clock), budget = LiteralAddressAttemptBudget(limit: 4)
            let native = try client("anytls", probe, prepared: prepared), a = PhysicalScopeResults(), b = PhysicalScopeResults()
            defer { probe.acknowledgeAll(); native.cancel() }
            let scopeA = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let scopeB = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let attemptA = try start(native, probe, clock, scope: scopeA, budget: budget, results: a)
            let attemptB = try start(native, probe, clock, scope: scopeB, budget: budget, results: b)
            try wait(probe.started, "shared AnyTLS first dial did not start"); try wait(probe.started, "shared AnyTLS second dial did not start")
            try expect(probe.snapshot.allSatisfy { $0.scopeID == nil }, "AnyTLS factory identity was incorrectly made operation-scoped")
            attemptA.cancel(); try wait(a.finished, "AnyTLS A did not finish its logical cancellation")
            try expect(probe.snapshot.allSatisfy { $0.cancellations == 0 } && attemptB.isPending,
                       "one logical AnyTLS cancellation revoked another live owner's shared factory")
            attemptB.cancel(); try wait(b.finished, "AnyTLS B did not finish its logical cancellation")
            try expect(probe.snapshot.allSatisfy { $0.cancellations == 1 } && probe.budget.usage == 2 && budget.usage == 2,
                       "last shared AnyTLS owner did not revoke its pending carriers or refunded without acknowledgement")
            probe.fail(0, error: fixtureError("shared-memory-cancelled")); probe.fail(1, error: fixtureError("shared-memory-cancelled"))
            try wait(a.acknowledged, "shared AnyTLS A never acknowledged"); try wait(b.acknowledged, "shared AnyTLS B never acknowledged")
            try expect(a.snapshot.completions == 1 && b.snapshot.completions == 1 && budget.usage == 0 && probe.budget.usage == 0,
                       "shared AnyTLS cancellation repeated callbacks or leaked actual acknowledgements")
        }
        for invalid in 0..<4 {
            let clock = DatagramTestClock(), probe = DatagramPhysicalProbe(clock), native = try client("vmess", probe)
            defer { probe.acknowledgeAll(); native.cancel() }
            let scope: UUID?
            switch invalid {
            case 0: scope = nil
            case 1: scope = UUID()
            case 2:
                let cancelled = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12)
                probe.physical.removeScope(cancelled); scope = cancelled
            default:
                scope = try probe.physical.connectionScope(generation: 7, deadline: clock.now() + 12); clock.advance(13)
            }
            let result = PhysicalScopeResults()
            native.connect(host: "destination.scope.invalid", port: 443, udp: false, plainHTTP: false,
                callbackQueue: callbacks, connectionScope: scope) { stream, error in
                stream?.cancel(); result.finish(.failure(error ?? fixtureError("invalid scope returned a stream"))); result.acknowledge()
            }
            try wait(result.acknowledged, "missing/cancelled/expired independent scope did not reject its callback")
            try expect(probe.snapshot.isEmpty && probe.budget.usage == 0 && result.snapshot.error != nil,
                       "missing/cancelled/expired independent scope started or borrowed a physical dial")
        }
        do {
            let clock = DatagramTestClock(), physical = PhysicalOwner(generation: 7, clock: clock.now)
            let old = try physical.connectionScope(generation: 7, deadline: clock.now() + 12)
            let pending = physical.begin(generation: 7, scopeID: old)!.0
            var pendingCancellations = 0, lateCloses = 0
            physical.install(pending) { pendingCancellations += 1 }
            physical.advance(generation: 8).forEach { $0() }
            let fresh = try physical.connectionScope(generation: 8, deadline: clock.now() + 12)
            physical.complete(pending, admissionFailed: true, readyCancellation: { lateCloses += 1 })
            try expect(pendingCancellations == 1 && lateCloses == 1 && !physical.consumeAdmission(fresh)
                       && physical.begin(generation: 7, scopeID: old) == nil
                       && physical.begin(generation: 8, scopeID: fresh) != nil,
                       "late old-epoch completion reopened a cancelled owner or contaminated the new generation")
            physical.removeScope(fresh)
        }
    }

    /// Runs actual C++ protocol/Objective-C adapters with memory-only physical
    /// carriers. Documentation-range addresses and interface identity are
    /// metadata, never socket destinations or platform interface lookups.
    static func datagramLifecycleSelfTest() throws {
        func expect(_ value: Bool, _ text: String) throws {
            guard value else { throw NativeOutboundError.protocolError("C++ UDP 生命周期自检失败：\(text)") }
        }
        func wait(_ semaphore: DispatchSemaphore, _ text: String) throws {
            try expect(semaphore.wait(timeout: .now() + 5) == .success, text)
        }
        let callbacks = DispatchQueue(label: "app.hajimi.cpp-datagram-lifecycle.selftest")
        func client(_ type: String, _ probe: DatagramPhysicalProbe) throws -> HJCppProtocolClient {
            let policy = ProxyPolicy(name: "memory-datagram", kind: .native, host: "node.scope.invalid", port: 443,
                adapterType: type, parameters: ["password": "memory-only", "sni": "identity.scope.invalid",
                    "uuid": "00112233-4455-6677-8899-aabbccddeeff"])
            return try HJCppProtocolClient(configuration: configuration(policy, connectHost: "203.0.113.41"),
                interfaceName: "en-memory-datagrams", queue: callbacks,
                preparedTransportDialer: nil, scopedPhysicalTransportDialer: probe.dialer())
        }
        func session(_ client: HJCppProtocolClient, _ probe: DatagramPhysicalProbe, _ results: NativeDatagramLifecycleResults,
                     _ created: DispatchSemaphore) throws -> NativeCXXDatagramSession {
            let policy = ProxyPolicy(name: "memory-datagram", kind: .native)
            let entry = Entry(policy: policy, interfaceName: "en-memory-datagrams", client: client, physical: probe.physical)
            let cache = BoundedConnectionOwnerCache<String, Entry>(maximumEntries: 1, maximumBytes: 1)
            let lease = cache.insert(entry, for: "fixture", cost: 1)!.lease
            let value = try leasedDatagramSession(lease: lease, generation: 7, queue: callbacks,
                budget: LiteralAddressAttemptBudget(limit: 2), permitted: { true },
                receive: results.receive, failure: results.fail, creationObserved: { created.signal() })
            return value as! NativeCXXDatagramSession
        }
        for type in ["trojan", "vless"] {
            let clock = DatagramTestClock(), probe = DatagramPhysicalProbe(clock), results = NativeDatagramLifecycleResults()
            let native = try client(type, probe), created = DispatchSemaphore(value: 0)
            let value = try session(native, probe, results, created)
            defer { value.cancel(); probe.acknowledgeAll(); native.cancel() }
            try wait(created, "lazy session construction did not acknowledge")
            try expect(probe.snapshot.isEmpty, "lazy session unexpectedly dialed before its first payload")
            let first = RequestTarget(host: "198.51.100.7", port: 53, protocolName: "UDP")
            let payload = Data("first-packet".utf8)
            value.send(payload, to: first); try wait(probe.started, "first payload never requested physical transport")
            try expect(probe.snapshot.count == 1 && probe.snapshot[0].deadline == clock.now() + 12,
                       "creation callback revoked the first lazy physical dial or gave it an invalid deadline")
            let firstPeer = NativeDatagramMemoryCarrier(type: type, queue: callbacks)
            probe.complete(0, carrier: firstPeer); try wait(results.packet, "first UDP payload produced no C++ roundtrip")
            try expect(results.packets.count == 1 && results.packets[0].0.host == first.host && results.packets[0].1 == payload,
                       "first C++ datagram roundtrip lost its target or payload")
            clock.advance(13)
            let second = RequestTarget(host: "198.51.100.8", port: 123, protocolName: "UDP")
            value.send(payload, to: second); try wait(probe.started, "a later destination could not start physical transport")
            try expect(probe.snapshot.count == 2 && probe.snapshot[1].deadline == clock.now() + 12,
                       "a long-lived session reused its expired creation deadline")
            let secondPeer = NativeDatagramMemoryCarrier(type: type, queue: callbacks)
            probe.complete(1, carrier: secondPeer); try wait(results.packet, "later destination produced no C++ roundtrip")
            value.send(payload, to: first); try wait(results.packet, "ready datagram flow was not reusable")
            try expect(probe.snapshot.count == 2 && results.packets.count == 3 && results.failures.isEmpty && probe.metadataValid,
                       "ready flow reuse, interface/TLS identity, or deferred failure accounting regressed")
            value.cancel(); value.drainForSelfTest()
            try wait(firstPeer.closed, "cancel did not close this session's first ready carrier")
            try wait(secondPeer.closed, "cancel did not close this session's second ready carrier")
            try expect(probe.snapshot.allSatisfy { $0.cancellations == 0 } && probe.budget.usage == 0,
                       "ready cancellation reached a completed pending dial or leaked its reservation")
        }
        // SOCKS start() may already be dialing when createDatagramSession
        // acknowledges; Basic stream-UDP first dials on send(). Both must
        // retain the live scope and dispose a cancelled attempt's late result.
        for type in ["socks5", "trojan"] {
            let clock = DatagramTestClock(), probe = DatagramPhysicalProbe(clock), results = NativeDatagramLifecycleResults()
            let native = try client(type, probe), created = DispatchSemaphore(value: 0)
            let value = try session(native, probe, results, created)
            defer { value.cancel(); probe.acknowledgeAll(); native.cancel() }
            try wait(created, "pending association creation did not acknowledge")
            if type == "trojan" { value.send(Data([1]), to: RequestTarget(host: "198.51.100.9", port: 53, protocolName: "UDP")) }
            try wait(probe.started, "pending association did not request a physical transport")
            try expect(probe.snapshot.count == 1 && probe.snapshot[0].cancellations == 0,
                       "creation acknowledgment cancelled a pending SOCKS/stream-UDP transport")
            value.cancel(); value.drainForSelfTest()
            try expect(probe.snapshot[0].cancellations == 1 && probe.budget.usage == 1,
                       "cancel did not revoke the pending physical attempt or released its slot before acknowledgment")
            let late = NativeDatagramMemoryCarrier(type: type, queue: callbacks)
            probe.complete(0, carrier: late); try wait(late.closed, "cancelled session leaked its late native carrier")
            try expect(probe.budget.usage == 0 && results.packets.isEmpty,
                       "late native callback escaped cancellation or retained physical admission")
        }
        do {
            let clock = DatagramTestClock(), owner = PhysicalOwner(generation: 7, clock: clock.now)
            let old = try owner.datagramScope(generation: 7), attempt = owner.begin(generation: 7)!.0
            let later = try owner.datagramScope(generation: 7)
            var cancellations = 0; owner.install(attempt) { cancellations += 1 }
            owner.removeScope(old)
            try expect(cancellations == 1 && !owner.allowed(attempt, generation: 7),
                       "a later unrelated session revived an older revoked pending attempt")
            let ready = owner.begin(generation: 7)!.0; owner.complete(ready); owner.removeScope(later)
            try expect(cancellations == 1, "removing a ready session scope cancelled a completed/shared owner")
        }
        do {
            let owner = PhysicalOwner(generation: 7)
            var scopes: [UUID] = []
            for _ in 0..<128 { scopes.append(try owner.datagramScope(generation: 7)) }
            do {
                _ = try owner.datagramScope(generation: 7)
                throw NativeOutboundError.protocolError("C++ UDP lifecycle admitted a 129th live scope")
            } catch is NodeConnectionAdmissionError {}
            do {
                _ = try owner.connectionScope(generation: 7, deadline: LiteralAddressAttemptClock.now + 12)
                throw NativeOutboundError.protocolError("C++ UDP lifecycle admitted TCP beyond the shared live scope cap")
            } catch is NodeConnectionAdmissionError {}
            scopes.forEach(owner.removeScope)
            owner.advance(generation: 8, revoke: true).forEach { $0() }
            var rejected = false
            do {
                _ = try owner.datagramScope(generation: 8)
            } catch { rejected = true }
            try expect(rejected, "a revoked generation admitted a live datagram scope")
        }
    }
}

/// Bound admission while a node hostname is being resolved. No datagram is
/// emitted to the system resolver or to an unverified alternative endpoint.
private final class BootstrappedDatagramSession: NativeOutboundDatagramSession {
    private let queue: DispatchQueue
    private let failure: (Error) -> Void
    private let admission = NSLock()
    private var reservedBytes = 0
    private var reservedRequests = 0
    private var closed = false
    private var cancelled = false
    private var resolverID: UUID?
    private var pending: [(Data, RequestTarget)] = []
    private var session: (any NativeOutboundDatagramSession)?

    init(queue: DispatchQueue,
         resolve: @escaping (@escaping (Result<any NativeOutboundDatagramSession, Error>) -> Void) -> UUID?,
         failure: @escaping (Error) -> Void) {
        self.queue = DispatchQueue(label: "app.hajimi.cpp-datagram.bootstrap", target: queue)
        self.failure = failure
        self.queue.async {
        self.resolverID = resolve { [weak self] result in
            guard let self else {
                if case .success(let session) = result { session.cancel() }
                return
            }
            self.queue.async {
                guard !self.cancelled else {
                    if case .success(let session) = result { session.cancel() }
                    return
                }
                self.resolverID = nil
                switch result {
                case .failure(let error): self.stop(); self.failure(error)
                case .success(let session):
                    self.session = session
                    for (data, target) in self.pending {
                        session.send(data, to: target)
                        self.release(data.count)
                    }
                    self.pending.removeAll()
                }
            }
        }
        }
    }

    func send(_ data: Data, to target: RequestTarget) {
        admission.lock()
        guard !closed, reservedRequests < 256, data.count <= 65_535,
              data.count <= 2 * 1_024 * 1_024 - reservedBytes else { admission.unlock(); return }
        reservedBytes += data.count; reservedRequests += 1; admission.unlock()
        queue.async {
            guard !self.cancelled else { self.release(data.count); return }
            if let session = self.session { session.send(data, to: target); self.release(data.count) }
            else { self.pending.append((data, target)) }
        }
    }
    private func release(_ bytes: Int) {
        admission.lock(); reservedBytes -= bytes; reservedRequests -= 1; admission.unlock()
    }
    private func stop() {
        guard !cancelled else { return }
        cancelled = true
        admission.lock(); closed = true; admission.unlock()
        if let resolverID { SecureDNSHostResolver.shared.cancel(resolverID) }
        resolverID = nil
        pending.forEach { release($0.0.count) }; pending.removeAll()
        session?.cancel(); session = nil
    }
    func cancel() { queue.async { self.stop() } }
    deinit {
        if let resolverID { SecureDNSHostResolver.shared.cancel(resolverID) }
        session?.cancel()
    }
}

final class NativeCXXByteStream: NativeOutboundByteStream {
    let native: HJCppByteStream
    private let owner: HJCppProtocolClient
    private let releaseOwner: () -> Void
    init(_ native: HJCppByteStream, owner: HJCppProtocolClient, release: @escaping () -> Void = {}) {
        self.native = native; self.owner = owner; releaseOwner = release
    }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) { native.sendData(data, completion: completion) }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        native.receiveData(maximum: UInt(clamping: maximum), completion: completion)
    }
    func cancel() { native.cancel(); releaseOwner() }
    deinit { native.cancel(); releaseOwner() }
}

private final class NativeCXXDatagramSession: NativeOutboundDatagramSession {
    private let owner: HJCppProtocolClient
    private let queue: DispatchQueue
    private let receiveHandler: (RequestTarget, Data) -> Void
    private let failureHandler: (Error) -> Void
    private let admission = NSLock()
    private var reservedBytes = 0
    private var reservedRequests = 0
    private var admissionClosed = false
    private var handle: HJCppDatagramSession?
    private var pending: [(Data, RequestTarget)] = []
    private var head = 0
    private var sending = false
    private var cancelled = false
    private var creationAcknowledged = false
    private let releaseOwner: () -> Void
    private let setupFinished: () -> Void
    private let permitted: () -> Bool

    init(owner: HJCppProtocolClient, queue: DispatchQueue,
         receive: @escaping (RequestTarget, Data) -> Void,
         failure: @escaping (Error) -> Void, release: @escaping () -> Void,
         setupFinished: @escaping () -> Void, reservation: LiteralAddressAttemptReservation,
         scope: UUID, permitted: @escaping () -> Bool, creationObserved: (() -> Void)? = nil) throws {
        self.owner = owner
        self.queue = DispatchQueue(label: "app.hajimi.cpp-datagram.adapter", target: queue)
        receiveHandler = receive; failureHandler = failure
        releaseOwner = release; self.setupFinished = setupFinished
        self.permitted = permitted
        owner.createDatagramSession(callbackQueue: queue, connectionScope: scope, receive: { [weak self] host, port, payload in
            self?.queue.async { [weak self] in
                guard let self, !self.cancelled, self.permitted() else { return }
                self.receiveHandler(RequestTarget(host: host, port: port, protocolName: "UDP"), payload)
            }
        }, failure: { [weak self] error in
            if let error { self?.queue.async { [weak self] in self?.fail(error) } }
        }, completion: { [weak self] handle, error in
            reservation.complete()
            guard let self else { handle?.cancel(); setupFinished(); release(); creationObserved?(); return }
            self.queue.async {
                defer { creationObserved?() }
                self.creationAcknowledged = true
                if self.cancelled { handle?.cancel(); self.setupFinished(); self.releaseOwner(); return }
                guard self.permitted() else {
                    handle?.cancel(); self.fail(NativeOutboundError.connection("已关闭旧代际或接口的 UDP 会话")); return
                }
                if let error { self.fail(error) }
                else if let handle { self.handle = handle; self.flush() }
                else { self.fail(NativeOutboundError.connection("C++ 引擎未返回 UDP 会话")) }
            }
        })
    }

    func send(_ payload: Data, to target: RequestTarget) {
        admission.lock()
        guard !admissionClosed, reservedRequests < 512,
              payload.count <= 65_535, payload.count <= 2 * 1_024 * 1_024 - reservedBytes else {
            admission.unlock(); return // Bounded UDP admission: drop under pressure.
        }
        reservedBytes += payload.count; reservedRequests += 1; admission.unlock()
        queue.async {
            guard !self.cancelled else { self.release(payload.count); return }
            guard self.permitted() else {
                self.release(payload.count); self.fail(NativeOutboundError.connection("UDP 会话的路径或策略已更新")); return
            }
            self.pending.append((payload, target)); self.flush()
        }
    }
    private func release(_ bytes: Int) {
        admission.lock(); reservedBytes -= bytes; reservedRequests -= 1; admission.unlock()
    }
    private func flush() {
        guard !cancelled, !sending, let handle, head < pending.count else { return }
        let item = pending[head]; sending = true
        handle.send(item.0, host: item.1.host, port: item.1.port) { [weak self] error in
            self?.queue.async { [weak self] in
                guard let self, !self.cancelled else { return }
                self.sending = false; self.release(item.0.count)
                self.head += 1
                if self.head == self.pending.count { self.pending.removeAll(keepingCapacity: true); self.head = 0 }
                else if self.head >= 64 { self.pending.removeFirst(self.head); self.head = 0 }
                if let error { self.fail(error) } else { self.flush() }
            }
        }
    }
    private func stop() {
        guard !cancelled else { return }
        cancelled = true; admission.lock(); admissionClosed = true; admission.unlock()
        for item in pending.dropFirst(head) { release(item.0.count) }
        pending.removeAll(); head = 0; handle?.cancel(); handle = nil
        setupFinished()
        if creationAcknowledged { releaseOwner() }
    }
    private func fail(_ error: Error) {
        guard !cancelled else { return }; stop(); failureHandler(error)
    }
    func cancel() { queue.async { self.stop() } }
    fileprivate func drainForSelfTest() { queue.sync {} }
    deinit { handle?.cancel(); setupFinished(); if creationAcknowledged { releaseOwner() } }
}

/// A request deadline/cancellation gate, separate from the shared C++ client.
/// Native callbacks still own their admission/lease until they acknowledge.
final class NativeCXXConnectionAttempt {
    private enum StopReason { case cancelled, timeout }
    let deadline: TimeInterval
    let interfaceName: String?
    private let queue: DispatchQueue
    private let lock = NSLock()
    private let permitted: () -> Bool
    private let clock: () -> TimeInterval
    private var completion: ((Result<any NativeOutboundByteStream, Error>) -> Void)?
    private var resolutionCancellation: (() -> Void)?
    private var setupCancellation: (() -> Void)?
    private var forceFinishCleanup: (() -> Void)?
    private var timer: DispatchWorkItem?
    private var cancelWatchdog: DispatchWorkItem?
    private let timing: NativeConnectionSetupTiming
    private var stopReason: StopReason?
    private let waitForSetupAcknowledgement: Bool
    private var setupStarted = false
    init(queue: DispatchQueue, deadline: TimeInterval, interfaceName: String?, permitted: @escaping () -> Bool,
         clock: @escaping () -> TimeInterval = { LiteralAddressAttemptClock.now },
         timing: NativeConnectionSetupTiming = NativeConnectionSetupTiming(),
         waitForSetupAcknowledgement: Bool = false,
         completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        self.queue = queue; self.permitted = permitted; self.completion = completion; self.interfaceName = interfaceName
        self.timing = timing; self.clock = clock
        self.waitForSetupAcknowledgement = waitForSetupAcknowledgement
        let now = clock()
        self.deadline = deadline.isFinite ? min(deadline, now + 12) : now
        let timer = DispatchWorkItem { [weak self] in self?.expire() }
        self.timer = timer; queue.asyncAfter(deadline: .now() + max(0, self.deadline - now), execute: timer)
    }
    var isPending: Bool { lock.lock(); defer { lock.unlock() }; return completion != nil && stopReason == nil }
    var canStart: Bool { isPending && permitted() && clock() < deadline }
    @discardableResult
    func beginSetup() -> Bool {
        guard permitted(), clock() < deadline else { return false }
        lock.lock(); defer { lock.unlock() }
        guard completion != nil, stopReason == nil else { return false }
        setupStarted = true; timing.begin(); return true
    }
    func setResolutionCancellation(_ action: @escaping () -> Void) {
        lock.lock(); let active = completion != nil && stopReason == nil
        if active { resolutionCancellation = action }
        lock.unlock(); if !active { action() }
    }
    func setSetupCancellation(_ action: @escaping () -> Void) {
        lock.lock(); let active = completion != nil && stopReason == nil
        if active { setupCancellation = action; resolutionCancellation = nil }
        lock.unlock(); if !active { action() }
    }
    func setForceFinishCleanup(_ action: @escaping () -> Void) {
        lock.lock(); let active = completion != nil
        if active { forceFinishCleanup = action }
        lock.unlock(); if !active { action() }
    }
    func finish(_ result: Result<any NativeOutboundByteStream, Error>) {
        lock.lock()
        let done = completion; completion = nil
        let reason = stopReason
        let resolve = resolutionCancellation, setup = setupCancellation
        resolutionCancellation = nil; setupCancellation = nil
        forceFinishCleanup = nil
        timer?.cancel(); timer = nil
        cancelWatchdog?.cancel(); cancelWatchdog = nil
        lock.unlock()
        guard let done else { if case .success(let stream) = result { stream.cancel() }; return }
        resolve?(); setup?()
        let allowed = permitted(), expired = clock() >= deadline
        let effectiveResult: Result<any NativeOutboundByteStream, Error> = {
            guard reason == nil, allowed, !expired else {
                if case .success(let stream) = result { stream.cancel() }
                if reason == .cancelled || !allowed { return .failure(NativeOutboundError.cancelled) }
                return .failure(NativeOutboundError.connection("已拒绝发布过期或已取消的 C++ 节点连接"))
            }
            return result
        }()
        if reason == .cancelled || !allowed { timing.finish(outcome: .unobserved) }
        else if reason == .timeout { timing.finish(outcome: .networkFailure) }
        else {
            switch result {
            case .success where expired: timing.finish(outcome: .networkFailure)
            default: timing.finish(result: result)
            }
        }
        done(effectiveResult)
    }
    func cancel() { stop(.cancelled) }
    private func expire() { stop(.timeout) }
    private func stop(_ reason: StopReason) {
        lock.lock()
        guard completion != nil, stopReason == nil else { lock.unlock(); return }
        stopReason = reason
        let wait = waitForSetupAcknowledgement && setupStarted
        let setup = wait ? setupCancellation : nil
        lock.unlock()
        if wait {
            // Close the carrier now, but keep the native setup's real callback
            // as the only receipt. DNS must not refund its physical pool slot
            // from this logical cancellation while C++ still owns admission.
            // Arm a 2.0s post-stop watchdog so if a stalled transport ever fails
            // to deliver its callback after cancellation, the attempt still finishes.
            let watchdog = DispatchWorkItem { [weak self] in
                guard let self else { return }
                self.lock.lock()
                let cleanup = self.forceFinishCleanup
                self.forceFinishCleanup = nil
                self.lock.unlock()
                cleanup?()
                self.finish(.failure(reason == .cancelled ? NativeOutboundError.cancelled : NativeOutboundError.connection("C++ 节点连接超过总截止时间或已取消")))
            }
            lock.lock()
            if completion != nil {
                cancelWatchdog?.cancel()
                cancelWatchdog = watchdog
                queue.asyncAfter(deadline: .now() + 2.0, execute: watchdog)
            }
            lock.unlock()
            setup?(); return
        }
        queue.async { [self] in finish(.failure(reason == .cancelled ? NativeOutboundError.cancelled : NativeOutboundError.connection("C++ 节点连接超过总截止时间或已取消"))) }
    }
    func expireForSelfTest() { expire() }
}

public enum NativeCXXBootstrapOwnershipSelfTest {
    public static func run() throws { try NativeCXXOutbound.bootstrapOwnershipSelfTest() }
}

public enum NativeCXXConfigurationCacheSelfTest {
    public static func run() throws { try NativeCXXOutbound.configurationCacheSelfTest() }
}

public enum NativeCXXDatagramLifecycleSelfTest {
    public static func run() throws { try NativeCXXOutbound.datagramLifecycleSelfTest() }
}

public enum NativeCXXPhysicalScopeIsolationSelfTest {
    public static func run() throws { try NativeCXXOutbound.physicalScopeIsolationSelfTest() }
}

private final class NativeDatagramLifecycleResults {
    let packet = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var received: [(RequestTarget, Data)] = []
    private var errors: [Error] = []
    func receive(_ target: RequestTarget, _ data: Data) { lock.lock(); received.append((target, data)); lock.unlock(); packet.signal() }
    func fail(_ error: Error) { lock.lock(); errors.append(error); lock.unlock() }
    var packets: [(RequestTarget, Data)] { lock.lock(); defer { lock.unlock() }; return received }
    var failures: [Error] { lock.lock(); defer { lock.unlock() }; return errors }
}

/// HTTP/SOCKS memory peer with a deliberately blackholed handshake read.
/// HJCallbackStream's actual native read cancellation completion is the only
/// route back into C++: this peer never completes a C++ operation directly.
private final class NativeScopeHandshakeMemoryCarrier {
    let reading = DispatchSemaphore(value: 0), closed = DispatchSemaphore(value: 0)
    private let type: String
    private let queue = DispatchQueue(label: "app.hajimi.cpp-scope-memory.carrier", qos: .userInitiated)
    private let lock = NSLock()
    private var bytes = Data()
    private var pending: (UInt, HJDataReadCompletion)?
    private var stage = 0, closes = 0
    private var responding = false
    lazy var native = HJCallbackStream(queue: queue, supportsHalfClose: true,
        receiveHandler: { [weak self] maximum, done in self?.receive(maximum, done) },
        sendHandler: { [weak self] data, complete, done in self?.send(data, complete: complete, done) },
        cancelHandler: { [weak self] in self?.cancel() })
    init(type: String) { self.type = type }
    var closeCount: Int { lock.lock(); defer { lock.unlock() }; return closes }
    private func reply() {
        if type == "http", stage == 1 { bytes.append(Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)) }
        else if type == "socks5", stage == 1 { bytes.append(contentsOf: [5, 0]) }
        else if type == "socks5", stage == 2 { bytes.append(contentsOf: [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]) }
    }
    private func delivery() -> (HJDataReadCompletion, Data)? {
        guard let pending, !bytes.isEmpty else { return nil }
        let result = Data(bytes.prefix(Int(pending.0))); bytes.removeFirst(result.count); self.pending = nil
        return (pending.1, result)
    }
    private func receive(_ maximum: UInt, _ done: @escaping HJDataReadCompletion) {
        lock.lock()
        if closes != 0 { lock.unlock(); done(nil, true, nil); return }
        pending = (maximum, done); let ready = delivery(); lock.unlock()
        reading.signal(); if let ready { ready.0(ready.1, false, nil) }
    }
    private func send(_ payload: Data?, complete: Bool, _ done: @escaping HJStreamWriteCompletion) {
        lock.lock()
        guard closes == 0, !complete, payload != nil else {
            lock.unlock(); done(NativeOutboundError.connection("memory handshake carrier was closed")); return
        }
        if stage == 0 { stage = 1; if responding { reply() } }
        else if type == "socks5", stage == 1 { stage = 2; if responding { reply() } }
        let ready = delivery(); lock.unlock(); done(nil)
        if let ready { ready.0(ready.1, false, nil) }
    }
    func releaseHandshake() {
        lock.lock(); responding = true; reply(); let ready = delivery(); lock.unlock()
        if let ready { ready.0(ready.1, false, nil) }
    }
    private func cancel() {
        lock.lock(); let first = closes == 0
        if first { closes = 1; pending = nil; bytes.removeAll() }
        lock.unlock(); if first { closed.signal() }
    }
}

/// A bounded byte echo peer, not an NWConnection. It consumes the real C++
/// protocol's first handshake write and echoes subsequent UDP frames.
private final class NativeDatagramMemoryCarrier {
    let closed = DispatchSemaphore(value: 0)
    private let type: String
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var bytes = Data()
    private var initial = true
    private var cancelled = false
    private var pending: (UInt, HJDataReadCompletion)?
    lazy var native = HJCallbackStream(queue: queue, supportsHalfClose: true,
        receiveHandler: { [weak self] maximum, done in self?.receive(maximum, done) },
        sendHandler: { [weak self] data, _, done in self?.send(data, done) },
        cancelHandler: { [weak self] in self?.cancel() })
    init(type: String, queue: DispatchQueue) { self.type = type; self.queue = queue }
    private func receive(_ maximum: UInt, _ done: @escaping HJDataReadCompletion) {
        lock.lock()
        if cancelled { lock.unlock(); done(nil, true, nil); return }
        if bytes.isEmpty { pending = (maximum, done); lock.unlock(); return }
        let data = Data(bytes.prefix(Int(maximum))); bytes.removeFirst(data.count)
        lock.unlock(); done(data, false, nil)
    }
    private func send(_ data: Data?, _ done: @escaping HJStreamWriteCompletion) {
        lock.lock()
        if initial { initial = false; if type == "vless" { bytes.append(contentsOf: [0, 0]) } }
        else if let data { bytes.append(data) }
        let receive = pending
        let response = receive.map { Data(bytes.prefix(Int($0.0))) }
        if let response, !response.isEmpty { pending = nil; bytes.removeFirst(response.count) }
        lock.unlock(); done(nil)
        if let response, !response.isEmpty { receive?.1(response, false, nil) }
    }
    private func cancel() {
        lock.lock(); let first = !cancelled; cancelled = true; pending = nil; bytes.removeAll(); lock.unlock()
        if first { closed.signal() }
    }
}

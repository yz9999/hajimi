import Foundation
import HajimiDNS
import Network
import Security

/// Per-router fixture trust is injected only after the real routed raw stream
/// exists, never as a replacement dialer for proxy routes.
typealias DNSFixtureTLSUpgrader = (
    _ stream: any NativeOutboundByteStream, _ connectHost: String, _ port: UInt16,
    _ serverName: String, _ queue: DispatchQueue, _ alpn: [String],
    _ attemptTrace: DNSConnectionAttemptTrace?,
    _ failureObserver: @escaping (Error) -> Void,
    _ completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void
) -> (() -> Void)?

/// Only the guarded three-provider CLI supplies this factory. It uses real
/// approved transports and authenticated answers to measure warmup RTTs.
typealias DNSFixtureCandidateWarmup = (
    Int, Data, DispatchQueue, @escaping (Data) -> Void, @escaping (Error) -> Void
) throws -> NativeRoutedDatagram

/// Internal implementation of the single explicit CLI fixture entry point.
/// No initializer, environment variable or mutable global exposes its anchor
/// to an ordinary router. Both the complete profile and every dial are guarded.
final class DNSAdaptiveLoopbackFixture {
    private enum Scenario: String {
        case failure, success, identityFailure = "identity-failure"
        case productionSuccess = "production-success", productionIdentityFailure = "production-identity-failure"
        case sourceScopeBurst = "source-scope-burst"
        case multiUpstreamBurst = "multi-upstream-burst"
        case multiUpstreamConnectFailureBurst = "multi-upstream-connect-failure-burst"
        case thirdCandidateRotation = "third-candidate-rotation"
        var multiUpstream: Bool {
            self == .multiUpstreamBurst || self == .multiUpstreamConnectFailureBurst
        }
        var scopePressure: Bool { self == .sourceScopeBurst || multiUpstream }
        var production: Bool {
            self == .productionSuccess || self == .productionIdentityFailure || scopePressure
                || self == .thirdCandidateRotation
        }
    }
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private struct Expected {
        let query: Data, code: UInt8, address: String?, started: TimeInterval
    }
    let profile: Profile
    private let scenario: Scenario
    private let ports: Set<UInt16>
    private let firstPort: UInt16
    private let anchor: SecCertificate?
    private let physical: DNSFixturePhysicalProbe

    var measuresThirdCandidateRotation: Bool { scenario == .thirdCandidateRotation }

    init(profileText: String, scenario: String, anchorDER: Data?) throws {
        guard CommandLine.arguments.contains("--dns-adaptive-loopback-test"),
              let selected = Scenario(rawValue: scenario) else {
            throw Failure(text: "Adaptive DNS fixture requires its explicit CLI flag and fixed scenario")
        }
        let parsed = try ProfileParser.parse(profileText)
        try Self.require(!parsed.fakeIPEnabled && parsed.groups.isEmpty && parsed.ruleSetContents.isEmpty
                         && parsed.proxies.count == (selected.production ? 3 : 2) && parsed.proxies["DIRECT"]?.kind == .direct
                         && parsed.proxies["REJECT"]?.kind == .reject,
                         "Adaptive fixture cannot configure groups, external proxy peers or fake-IP")
        // Source/transport pooling is a component test with one approved
        // provider. The other scenarios exercise genuine two-provider
        // selection, hedging and identity failures independently.
        let endpointCount = selected == .sourceScopeBurst ? 1 : selected == .thirdCandidateRotation ? 3 : 2
        try Self.require(parsed.encryptedDNSServers.count == endpointCount
                         && parsed.configuredEncryptedDNSServers.count == endpointCount,
                         selected == .sourceScopeBurst
                         ? "Source-scope fixture requires exactly one explicit encrypted endpoint"
                         : selected == .thirdCandidateRotation
                         ? "Third-candidate fixture requires exactly three explicit encrypted endpoints"
                         : "Adaptive fixture requires exactly two explicit encrypted endpoints")
        let endpoints = parsed.encryptedDNSServers.compactMap(DoHEndpoint.init)
        try Self.require(endpoints.count == endpointCount && Set(endpoints.map(\.port)).count == endpointCount
                         && endpoints.allSatisfy({ $0.host == "127.0.0.1" && $0.connectHost == "127.0.0.1"
                             && $0.port > 0 && $0.url.path == "/dns-query" && $0.url.query == nil
                             && $0.url.user == nil && $0.url.password == nil && $0.url.fragment == nil }),
                         "Adaptive fixture endpoints must be distinct literal-loopback HTTPS ports")
        try Self.require(parsed.dnsServers.count == 1 && parsed.traditionalDNSServers.count == 1,
                         "Adaptive fixture requires one unused loopback traditional peer")
        guard let traditional = TraditionalDNSServer(parsed.dnsServers[0]), traditional.host == "127.0.0.1",
              traditional.port > 0 else { throw Failure(text: "Traditional fixture peer must be literal loopback") }
        if selected.production {
            guard let proxy = parsed.proxies["LoopbackHTTP"], proxy.kind == .http,
                  proxy.host == "127.0.0.1", let port = proxy.port, port > 0,
                  proxy.username == nil, proxy.password == nil, proxy.adapterType == nil, proxy.parameters.isEmpty,
                  !endpoints.contains(where: { $0.port == port }), traditional.port != port else {
                throw Failure(text: "Production fixture proxy must be one literal-loopback HTTP port with no credentials or options")
            }
        }
        try Self.require(!endpoints.contains(where: { $0.port == traditional.port }),
                         "Traditional fixture port cannot overlap an encrypted endpoint")
        var rules: [(RuleKind, String)] = [(.domain("blocked.example.test"), "REJECT")]
        if selected == .thirdCandidateRotation {
            try Self.require(!parsed.dnsProxyFallbackEnabled && parsed.dnsProxyFallbackServers.isEmpty,
                             "Third-candidate fixture cannot enable plaintext fallback")
        }
        if selected.scopePressure {
            try Self.require(!parsed.dnsProxyFallbackEnabled && parsed.dnsProxyFallbackServers.isEmpty,
                             "Source-scope fixture cannot enable plaintext fallback")
            rules.append((.sourcePort(65535...65535), "REJECT"))
        }
        rules.append((.final, selected.production ? "LoopbackHTTP" : "DIRECT"))
        try Self.require(parsed.rules.count == rules.count && zip(parsed.rules, rules).allSatisfy({
            $0.0.kind == $0.1.0 && $0.0.policy == $0.1.1
        }), "Adaptive fixture requires fixed QNAME REJECT and its single approved route")
        let certificate: SecCertificate?
        if selected == .failure {
            try Self.require(anchorDER == nil, "Failure fixture cannot override platform trust")
            certificate = nil
        } else {
            guard let bytes = anchorDER, !bytes.isEmpty, bytes.count <= 16_384,
                  let value = SecCertificateCreateWithData(nil, bytes as CFData) else {
                throw Failure(text: "Healthy fixture requires its bounded temporary DER anchor")
            }
            certificate = value
        }
        profile = parsed; self.scenario = selected
        physical = DNSFixturePhysicalProbe(permitsBoundCancellation: selected.multiUpstream,
                                          observesIdentity: selected == .productionIdentityFailure)
        ports = Set(endpoints.map(\.port)); firstPort = endpoints[0].port; anchor = certificate
    }

    private static func require(_ condition: Bool, _ text: String) throws {
        if !condition { throw Failure(text: text) }
    }

    var streamDialer: EncryptedDNSStreamDialer? {
        guard !scenario.production, let anchor else { return nil }
        let ports = self.ports
        return { host, port, name, queue, completion in
            // Repeat the literal/approved-port guard immediately before the
            // only socket creation, even though admission already checked it.
            guard host == "127.0.0.1", name == "127.0.0.1", ports.contains(port),
                  let endpointPort = NWEndpoint.Port(rawValue: port) else {
                completion(.failure(Failure(text: "Test TLS dial escaped its fixed loopback endpoints"))); return
            }
            let tls = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, "127.0.0.1")
            sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
            sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, peerTrust, complete in
                let trust = sec_trust_copy_ref(peerTrust).takeRetainedValue()
                // This is normal server chain and IP-SAN verification with one
                // ephemeral anchor, not a skip-verify block or keychain write.
                let policy = SecPolicyCreateSSL(true, "127.0.0.1" as CFString)
                guard SecTrustSetPolicies(trust, policy) == errSecSuccess,
                      SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess,
                      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
                      SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else {
                    complete(false); return
                }
                complete(SecTrustEvaluateWithError(trust, nil))
            }, queue)
            let connection = NWConnection(host: .ipv4(.loopback), port: endpointPort,
                                          using: NWParameters(tls: tls, tcp: .init()))
            let attempt = DNSFixtureTLSAttempt(connection: connection, completion: completion)
            connection.stateUpdateHandler = { [attempt] state in
                switch state {
                case .ready: attempt.finish(.success(DNSFixtureTLSStream(connection)))
                case .failed(let error): attempt.finish(.failure(error), cancel: true)
                case .waiting(let error):
                    if case .tls = error { attempt.finish(.failure(error), cancel: true) }
                case .cancelled: attempt.finish(.failure(Failure(text: "Fixture TLS dial cancelled")))
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 4) { [weak attempt] in
                attempt?.finish(.failure(Failure(text: "Fixture TLS handshake timed out")), cancel: true)
            }
        }
    }

    var tlsUpgrader: DNSFixtureTLSUpgrader? {
        guard scenario.production, let anchor else { return nil }
        let ports = self.ports, firstPort = self.firstPort
        let identity = scenario == .productionIdentityFailure
        let observed = scenario.scopePressure || scenario == .productionSuccess || identity ? physical : nil
        let delayReady = scenario == .multiUpstreamBurst
        let bindCarrier = scenario.multiUpstream
        return { stream, host, port, name, queue, alpn, trace, failureObserver, completion in
            guard CommandLine.arguments.contains("--dns-adaptive-loopback-test"), host == "127.0.0.1",
                  name == "127.0.0.1", ports.contains(port), alpn == ["http/1.1"] else {
                stream.cancel()
                completion(.failure(Failure(text: "Production fixture TLS upgrade escaped its admitted loopback endpoints")))
                return nil
            }
            // This point is reached only after the genuine routed raw socket
            // and HTTP CONNECT have succeeded. Count separately from logical
            // DNS admission, and retain normal CA + IP-SAN validation.
            let token = observed?.beginTLS(providerOrdinal: port == firstPort ? 0 : 1, identityPort: identity ? port : nil)
            // Passive observation only: never split, rewrite or add bytes to
            // the original TLS record stream. Other CLI scenarios are unchanged.
            let tlsCarrier: any NativeOutboundByteStream
            if identity, let observed, let token {
                tlsCarrier = DNSFixtureIdentityRawStream(stream, probe: observed, token: token)
            } else { tlsCarrier = stream }
            let receive: (Result<any NativeOutboundByteStream, Error>) -> Void = { result in
                guard let observed, let token else { completion(result); return }
                observed.tlsResult(result, token: token)
                completion(result.map { DNSFixtureObservedTLSStream($0, probe: observed, token: token)
                    as any NativeOutboundByteStream })
            }
            // A real TLS handshake still runs over the real routed carrier.
            // Only its queue handoff is delayed in this explicit CLI case,
            // modelling a late transport completion after the hedge cancels
            // its logical owner. The pending-dial reservation must survive.
            let delayed: DNSFixtureDelayedTLSHandoff?
            if delayReady, port == firstPort, let observed, observed.snapshot.rawReady != 1 {
                delayed = DNSFixtureDelayedTLSHandoff(queue: queue, probe: observed, completion: receive)
            } else { delayed = nil }
            let observeFailure: (Error) -> Void = { error in
                let entered = NetworkPerformanceDiagnostics.now()
                // The original metadata sink still receives the exact error,
                // synchronously and before forensic formatting can delay its
                // admission. The recorded time is this wrapper's entry.
                failureObserver(error)
                if let observed, let token { observed.failureObserved(error, token: token, at: entered) }
            }
            let startTLS: () -> (() -> Void) = {
                if let observed, let token { observed.nativeTLSStarted(token: token) }
                let nativeCompletion: (Result<any NativeOutboundByteStream, Error>) -> Void = { result in
                    // Real factory completion before optional fixture delay.
                    if let observed, let token { observed.nativeTLSResult(result, token: token) }
                    if let delayed { delayed.receive(result) }
                    else { receive(result) }
                }
                if identity, let observed, let token {
                    // The SDK receipts and raw/result wrappers close over the
                    // same original physical token. They cannot admit a DNS
                    // answer, replace a native error or alter verify(trusted).
                    return NativeOutboundFactory.beginTLSUpgradeForDNSIdentityObservedFixture(
                        stream: tlsCarrier, serverName: name, queue: queue, alpn: alpn, anchor: anchor,
                        trustObserver: { observed.identityTrustObserved($0, token: token) },
                        failureObserver: observeFailure, attemptTrace: trace, completion: nativeCompletion)
                }
                return NativeOutboundFactory.beginTLSUpgradeForDNSLoopbackFixture(stream: tlsCarrier, serverName: name,
                    queue: queue, alpn: alpn, anchor: anchor, failureObserver: observeFailure,
                    attemptTrace: trace, completion: nativeCompletion)
            }
            let cancel: () -> Void
            if bindCarrier {
                guard let observed, let token, let ordinal = observed.carrierOrdinal(token: token) else {
                    stream.cancel()
                    completion(.failure(Failure(text: "Multi-provider carrier cannot start TLS without its bounded binding record")))
                    return nil
                }
                // Extra protocol ONLY for these admitted multi-provider CLI
                // peers. This nonce has no DNS name or credentials. A real
                // raw-stream ACK binds it to the server's actual TCP peer;
                // it does not authenticate TLS or create a DNS question.
                let binding = DNSFixtureCarrierBinding(stream: stream, token: token, ordinal: ordinal,
                    provider: port == firstPort ? 0 : 1, queue: queue, probe: observed,
                    observeFailure: observeFailure, startTLS: startTLS, preTLSFailure: { error, branch in
                        observed.preludeFailed(error, branch: branch, token: token)
                        completion(.failure(error))
                    })
                binding.start(); cancel = binding.cancel
            } else { cancel = startTLS() }
            guard observed != nil || delayed != nil else { return cancel }
            return {
                if let observed, let token { observed.upgradeCancellationRequested(token: token) }
                delayed?.cancelRequested()
                // Observation must not defer, suppress or reinterpret the
                // actual native cancellation of a pending handshake.
                cancel()
            }
        }
    }

    func run(router: NativePacketRouter,
             queryStatistics: (() -> DNSQueryCoordinator.Statistics)? = nil,
             warmCandidate: DNSFixtureCandidateWarmup? = nil) throws -> String {
        if scenario == .thirdCandidateRotation {
            guard let warmCandidate else { throw Failure(text: "Third-candidate fixture requires real measured warmup") }
            return try runThirdCandidateRotation(router: router, warmCandidate: warmCandidate)
        }
        if scenario.scopePressure {
            guard let queryStatistics else { throw Failure(text: "Source-scope fixture requires production governor counters") }
            return try runSourceScopeBurst(router: router, queryStatistics: queryStatistics)
        }
        let queue = DispatchQueue(label: "app.hajimi.dns.adaptive-loopback-fixture")
        NetworkPerformanceDiagnostics.shared.reset()
        physical.beginTimingWindow(at: NetworkPerformanceDiagnostics.now())
        let lock = NSLock(), ready = DispatchSemaphore(value: 0)
        var expected: [UInt16: Expected] = [:], responses: [UInt16: Data] = [:]
        var elapsed: [UInt16: TimeInterval] = [:], failure: Error?
        var successAssertionsCompleted = false
        var identityWitnessWritten = false
        func identifier(_ data: Data) -> UInt16 { UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1]) }
        let flow = try router.makeUDPFlow(host: "127.0.0.1", port: 53, queue: queue,
            sourceHost: "127.0.0.1", sourcePort: 41000, receive: { response in
                lock.lock(); defer { lock.unlock(); ready.signal() }
                guard response.count >= 12, let item = expected[identifier(response)],
                      responses[identifier(response)] == nil,
                      DNSMessageInspection.responseMatchesQuery(response, query: item.query) else {
                    failure = Failure(text: "Adaptive reply lost its original question, ID or ownership"); return
                }
                if response[response.startIndex + 3] & 0x0f != item.code {
                    failure = Failure(text: "TLS outage/identity failure did not fail closed or QNAME REJECT was bypassed")
                }
                if let address = item.address,
                   DNSMessageInspection.addressAnswers(in: response).map(\.address) != [address] {
                    failure = Failure(text: "Adaptive result did not come from the expected authenticated provider")
                }
                if item.code == 0 {
                    let addresses = DNSMessageInspection.addressAnswers(in: response).map(\.address)
                    if addresses.count != 1 || !["203.0.113.80", "203.0.113.81"].contains(addresses[0]) {
                        failure = Failure(text: "Adaptive success did not contain exactly one approved authenticated provider address")
                    }
                    if ProcessInfo.processInfo.systemUptime - item.started >= 8 {
                        failure = Failure(text: "Adaptive success exceeded the original eight-second query deadline")
                    }
                }
                responses[identifier(response)] = response
                elapsed[identifier(response)] = ProcessInfo.processInfo.systemUptime - item.started
            }, failure: { error in lock.lock(); failure = error; lock.unlock(); ready.signal() })
        defer {
            if scenario == .productionIdentityFailure, !identityWitnessWritten {
                lock.lock(); let answers = responses; lock.unlock()
                // Failure evidence before teardown; never authorizes exit 1.
                do { try emitIdentityWitness(responses: answers, success: false) }
                catch { print("DNS-ADAPTIVE-IDENTITY {\"fixtureOnly\":true,\"formatVersion\":1,\"observationError\":\"private-identity-witness-write-failed\"}") }
            }
            if scenario == .success || scenario == .productionSuccess {
                lock.lock(); let answers = responses; lock.unlock()
                emitFunctionalWitness(responses: answers, queryStatistics: queryStatistics?(),
                                      success: successAssertionsCompleted)
            }
            flow.cancel(); router.flushDNS()
        }
        func send(_ id: UInt16, name: String, code: UInt8 = 0, address: String? = nil) throws {
            guard let query = DNSMessageInspection.query(for: name, type: 1, id: id) else {
                throw Failure(text: "Cannot encode adaptive fixture query")
            }
            lock.lock()
            expected[id] = Expected(query: query, code: code, address: address, started: ProcessInfo.processInfo.systemUptime)
            lock.unlock(); flow.send(query)
        }
        func wait(_ ids: [UInt16]) throws {
            for _ in ids { try Self.require(ready.wait(timeout: .now() + 12) == .success,
                                           "Adaptive query exceeded its bounded deadline") }
            lock.lock(); let error = failure, complete = ids.allSatisfy { responses[$0] != nil }; lock.unlock()
            if let error { throw error }
            try Self.require(complete, "Adaptive fixture did not finish each transaction")
        }
        switch scenario {
        case .failure:
            try send(0x7101, name: "adaptive.loopback.example.test", code: 2)
            try send(0x7102, name: "blocked.example.test", code: 5)
            try wait([0x7101, 0x7102])
            router.flushDNS()
            try send(0x7103, name: "adaptive.after-flush.example.test", code: 2)
            try wait([0x7103])
        case .success, .productionSuccess:
            // A planned hedge may legally beat the cold primary. Validate
            // both admitted providers here; the parent independently binds
            // every returned address to its actual authenticated wire peer.
            try send(0x7201, name: "adaptive.cold.example.test"); try wait([0x7201])
            try send(0x7202, name: "adaptive.discover.example.test", address: "203.0.113.81"); try wait([0x7202])
            try send(0x7203, name: "adaptive.preferred.example.test", address: "203.0.113.81"); try wait([0x7203])
            // A health-order change must not alter cache scope or transaction IDs.
            lock.lock()
            let coldAddress = responses[0x7201].flatMap { DNSMessageInspection.addressAnswers(in: $0).first?.address }
            lock.unlock()
            guard let coldAddress else { throw Failure(text: "Cold adaptive query has no authenticated cache result") }
            try send(0x7204, name: "adaptive.cold.example.test", address: coldAddress); try wait([0x7204])
            try send(0x7205, name: "blocked.example.test", code: 5); try wait([0x7205])
            router.flushDNS()
            try send(0x7206, name: "adaptive.cold.example.test"); try wait([0x7206])
            lock.lock(); let cold = elapsed[0x7201] ?? 0, fast = elapsed[0x7203] ?? .infinity; lock.unlock()
            try Self.require(cold >= 0.45 && fast < cold, "Real successful exchange latency did not improve")
            if scenario.production {
                // Logical cancel is not a raw dial completion. Keep this
                // observation wait inside the fixture, never a fresh query
                // timeout, until actual connection-stage receipts retire.
                let receiptDeadline = ProcessInfo.processInfo.systemUptime + 3
                while ProcessInfo.processInfo.systemUptime < receiptDeadline {
                    let value = NetworkPerformanceDiagnostics.shared.snapshot()
                    if (value.stages[.dnsUpstreamConnection]?.count ?? 0)
                        >= value.dnsUpstreamAttempts - min(value.dnsUpstreamAttempts, value.dnsConnectionsReused),
                        (value.stages[.dnsTLSHandshake]?.count ?? 0) >= physical.snapshot.rawReady { break }
                    _ = RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.005))
                }
            }
            successAssertionsCompleted = true
        case .identityFailure, .productionIdentityFailure:
            // First has a trusted chain but an incompatible IP SAN. It must
            // receive no HTTP query; the second normally verified peer wins.
            try send(0x7301, name: "adaptive.identity.example.test", address: "203.0.113.81"); try wait([0x7301])
            try send(0x7302, name: "adaptive.identity-next.example.test", address: "203.0.113.81"); try wait([0x7302])
            try send(0x7303, name: "blocked.example.test", code: 5); try wait([0x7303])
            router.flushDNS()
            try send(0x7304, name: "adaptive.identity.example.test", address: "203.0.113.81"); try wait([0x7304])
        case .sourceScopeBurst, .multiUpstreamBurst, .multiUpstreamConnectFailureBurst, .thirdCandidateRotation:
            throw Failure(text: "Source-scope burst must use its independent guarded production workload")
        }
        if scenario == .productionIdentityFailure {
            lock.lock(); let answers = responses; lock.unlock()
            try emitIdentityWitness(responses: answers, success: true)
            identityWitnessWritten = true
        }
        return "DNS adaptive loopback checks passed: protection=\(profile.dnsLeakProtectionEnabled), "
            + "scenario=\(scenario.rawValue), transactions=\(responses.count), QNAME REJECT, TLS/flush, no traditional fallback"
            + (scenario.production ? ", production HTTP CONNECT/CXX/nested TLS" : "")
    }

    private func runThirdCandidateRotation(router: NativePacketRouter,
                                            warmCandidate: DNSFixtureCandidateWarmup) throws -> String {
        let queue = DispatchQueue(label: "app.hajimi.dns.third-candidate-loopback")
        var nextID: UInt16 = 0x7900
        var warmRTTs: [[Double]] = []
        defer { router.flushDNS() }

        func exchange(_ name: String, candidate: Int? = nil, address: String?, code: UInt8 = 0)
            throws -> (milliseconds: Double, attempts: UInt64) {
            let id = nextID; nextID &+= 1
            guard let query = DNSMessageInspection.query(for: name, type: 1, id: id) else {
                throw Failure(text: "Cannot encode fixed three-provider question")
            }
            let done = DispatchSemaphore(value: 0), lock = NSLock()
            var response: Data?, error: Error?, callbacks = 0
            let receive: (Data) -> Void = { data in
                lock.lock(); callbacks += 1
                if response == nil, error == nil { response = data; lock.unlock(); done.signal() }
                else { lock.unlock() }
            }
            let failed: (Error) -> Void = { value in
                lock.lock(); callbacks += 1
                if response == nil, error == nil { error = value; lock.unlock(); done.signal() }
                else { lock.unlock() }
            }
            let attempts = NetworkPerformanceDiagnostics.shared.snapshot().dnsUpstreamAttempts
            let started = ProcessInfo.processInfo.systemUptime
            let flow: NativeRoutedDatagram
            if let candidate { flow = try warmCandidate(candidate, query, queue, receive, failed) }
            else {
                flow = try router.makeUDPFlow(host: "127.0.0.1", port: 53, queue: queue,
                    sourceHost: "127.0.0.1", sourcePort: 41000, receive: receive, failure: failed)
            }
            defer { flow.cancel() }
            flow.send(query)
            try Self.require(done.wait(timeout: .now() + 8.5) == .success,
                             "Three-provider query exceeded its original eight-second budget")
            let elapsed = (ProcessInfo.processInfo.systemUptime - started) * 1000
            lock.lock(); let result = response, failure = error, count = callbacks; lock.unlock()
            if let failure { throw failure }
            try Self.require(count == 1 && result.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true,
                             "Three-provider answer lost exact question/ID or completed twice")
            guard let result else { throw Failure(text: "Three-provider query has no response") }
            try Self.require(result[result.startIndex + 3] & 0x0f == code && elapsed < 8000,
                             "Three-provider query changed RCODE or total eight-second deadline")
            if let address {
                try Self.require(DNSMessageInspection.addressAnswers(in: result).map(\.address) == [address],
                                 "Three-provider winner was not its authenticated expected peer")
            }
            return (elapsed, NetworkPerformanceDiagnostics.shared.snapshot().dnsUpstreamAttempts - attempts)
        }
        func warm(_ prefix: String, count: Int) throws {
            var values: [Double] = []
            for index in 0..<count {
                _ = try exchange("rotation.setup-\(prefix)-\(index).example.test", candidate: index,
                    address: "203.0.113.\(80 + index)")
                values.append(try exchange("rotation.warm-\(prefix)-\(index).example.test", candidate: index,
                    address: "203.0.113.\(80 + index)").milliseconds)
            }
            warmRTTs.append(values)
        }

        // With no successful third RTT, retain the existing conservative
        // schedule. The control is the same real production path and 8s
        // budget, rather than a shortened timeout or a synthetic sleep.
        try warm("control", count: 2)
        let control = try exchange("rotation.control.example.test", address: "203.0.113.82")
        try Self.require(control.attempts == 3 && control.milliseconds >= 5000,
                         "Unknown third candidate did not retain the conservative rotation control")
        router.flushDNS()

        // Successful warm RTTs must not shorten the conservative rotation
        // boundary when the next hedge needs a new carrier. All observations
        // still come from genuine successful TLS/DNS probes.
        try warm("measured", count: 3)
        let measured = try exchange("rotation.measured.example.test", address: "203.0.113.82")
        try Self.require(measured.attempts == 3 && measured.milliseconds >= 5000,
                         "Warm third-candidate history shortened the conservative rotation boundary")
        router.flushDNS()

        try warm("slow", count: 3)
        let slow = try exchange("rotation.slow-hedge.example.test", address: "203.0.113.81")
        try Self.require(slow.attempts == 2 && slow.milliseconds >= 600 && slow.milliseconds < 2000,
                         "A legitimate slow measured backup was clipped in favor of a third dial")
        let refused = try exchange("blocked.example.test", address: nil, code: 5)
        try Self.require(refused.attempts == 0, "QNAME REJECT acquired an encrypted provider")
        let value: [String: Any] = ["fixtureOnly": true, "formatVersion": 1,
            "parentDeadlineMilliseconds": 8000, "liveLimit": 2, "attemptLimit": 3,
            "controlMilliseconds": control.milliseconds, "measuredMilliseconds": measured.milliseconds,
            "slowHedgeMilliseconds": slow.milliseconds, "controlAttempts": control.attempts,
            "measuredAttempts": measured.attempts, "slowHedgeAttempts": slow.attempts,
            "warmRTTMilliseconds": warmRTTs]
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        print("DNS-THIRD-CANDIDATE-ROTATION " + String(decoding: data, as: UTF8.self))
        return "DNS adaptive loopback checks passed: protection=\(profile.dnsLeakProtectionEnabled), "
            + "scenario=third-candidate-rotation, measured authenticated RTTs, 8000ms parent, QNAME REJECT, no traditional fallback"
    }

    private func emitIdentityWitness(responses: [UInt16: Data], success: Bool) throws {
        let root = try sourceScopeRoot()
        let providerPorts = profile.encryptedDNSServers.compactMap(DoHEndpoint.init).map(\.port)
        guard let proxyPort = profile.proxies["LoopbackHTTP"]?.port else {
            throw Failure(text: "Identity witness lost its admitted literal CONNECT node")
        }
        var proof = physical.identityProof()
        proof["scenario"] = scenario.rawValue; proof["successAssertionsCompleted"] = success
        proof["approvedProviderPorts"] = providerPorts
        proof["approvedProxy"] = ["name": "LoopbackHTTP", "host": "127.0.0.1", "port": proxyPort]
        proof["answers"] = responses.keys.sorted().map { id -> [Any] in
            let data = responses[id]!
            let address: Any
            if let found = DNSMessageInspection.addressAnswers(in: data).first?.address { address = found }
            else { address = NSNull() }
            return [id, Int(data[data.startIndex + 3] & 15), address]
        }
        let bytes = try JSONSerialization.data(withJSONObject: proof, options: [.sortedKeys])
        let file = root.appendingPathComponent("identity-carriers.proof.json")
        try Self.require(bytes.count <= 16_384 && !FileManager.default.fileExists(atPath: file.path)
                         && FileManager.default.createFile(atPath: file.path, contents: bytes,
                             attributes: [.posixPermissions: 0o600]),
                         "Cannot write the complete bounded private identity witness")
        print("DNS-ADAPTIVE-IDENTITY " + String(decoding: bytes, as: UTF8.self))
    }

    /// Fixed fixture identifiers and aggregate real callback receipts only.
    /// Neither this observation nor NativeDebug authorizes an extra dial.
    private func emitFunctionalWitness(responses: [UInt16: Data],
                                       queryStatistics: DNSQueryCoordinator.Statistics?, success: Bool) {
        let value = NetworkPerformanceDiagnostics.shared.snapshot()
        func stage(_ name: NetworkPerformanceStage) -> [String: Any] {
            let item = value.stages[name] ?? NetworkStageSnapshot()
            return ["count": item.count, "failures": item.failureCount, "cancelled": item.cancellationCount]
        }
        let answers: [[Any]] = responses.keys.sorted().compactMap { id in
            guard let data = responses[id], data.count >= 12, data[data.startIndex + 3] & 15 == 0,
                  let address = DNSMessageInspection.addressAnswers(in: data).first?.address else { return nil }
            return [id, address]
        }
        let observed = physical.snapshot
        var result: [String: Any] = ["formatVersion": 1, "fixtureOnly": true,
            "scenario": scenario.rawValue, "successAssertionsCompleted": success,
            "answers": answers, "transactions": responses.count,
            "upstreamAttempts": value.dnsUpstreamAttempts, "failovers": value.dnsFailovers,
            "connectionReuse": value.dnsConnectionsReused, "dnsFailures": value.dnsFailures,
            "capacityFailures": value.dnsFailureReasons[.capacity, default: 0],
            "timeoutFailures": value.dnsFailureReasons[.timeout, default: 0],
            "connectionStage": stage(.dnsUpstreamConnection), "tlsStage": stage(.dnsTLSHandshake),
            "rawReady": observed.rawReady, "tlsReady": observed.tlsReady, "tlsFailures": observed.tlsFailed,
            "wireQueries": observed.wireQueries, "invalidObservations": observed.invalid]
        if let state = queryStatistics {
            result["logical"] = ["leaders": state.upstreamQueries, "cacheHits": state.cacheHits,
                "active": state.activeUpstreams, "queued": state.queuedUpstreams,
                "pending": state.pendingQueries, "waiting": state.waitingClients]
        }
        if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), data.count <= 16_384 {
            print("DNS-ADAPTIVE-FUNCTIONAL " + String(decoding: data, as: UTF8.self))
        } else {
            print("DNS-ADAPTIVE-FUNCTIONAL {\"fixtureOnly\":true,\"formatVersion\":1,\"observationError\":\"bounded-serialization-failed\"}")
        }
    }

    /// All source/original tuples are virtual DNS ingress metadata. The
    /// existing one-provider case isolates pooling; independent two-provider
    /// cases exercise the same pressure with late readiness and dial faults.
    /// The only physical sockets are the admitted 127.0.0.1 HTTP/TLS peers.
    private func runSourceScopeBurst(router: NativePacketRouter,
                                     queryStatistics: @escaping () -> DNSQueryCoordinator.Statistics) throws -> String {
        let multi = scenario.multiUpstream
        let marker = multi ? "DNS-MULTI-UPSTREAM" : "DNS-SOURCE-SCOPE"
        let fencePrefix = multi ? "multi-upstream" : "source-scope"
        let root = try sourceScopeRoot()
        let queue = DispatchQueue(label: "app.hajimi.dns.source-scope-loopback", qos: .userInitiated)
        let replies = DNSFixtureScopeReplies(approvedAddresses: multi ? ["203.0.113.80", "203.0.113.81"] : ["203.0.113.80"])
        let capacity = DNSFixtureCapacityProbe(queryStatistics)
        var flows: [any NativeRoutedDatagram] = []
        let timingStarted = NetworkPerformanceDiagnostics.now()
        var successAssertionsCompleted = false
        physical.beginTimingWindow(at: timingStarted)
        defer {
            // Observe before teardown: cancel/flush would obscure the very
            // pending handshakes and callback queues that caused a failure.
            emitSourceScopeTiming(started: timingStarted, success: successAssertionsCompleted,
                                  logical: queryStatistics(), capacity: capacity.snapshot,
                                  completedClients: replies.snapshot.completed, marker: marker + "-TIMING")
            capacity.stop(); flows.forEach { $0.cancel() }; router.flushDNS()
        }
        NetworkPerformanceDiagnostics.shared.reset()

        // Warm the same genuine carrier and trust services, not the DNS cache
        // or the governor. This is one explicitly observed, eight-second TLS
        // preflight with zero DNS questions. Read its tiny authenticated ACK
        // before closing: client TLS-ready alone does not prove that the
        // server has received Finished through the opaque CONNECT relay.
        let preflightACKBytes = try sourceScopeTLSPreflight(router: router, queue: queue)
        let preflight = physical.snapshot
        try Self.require(preflight.rawReady == 1 && preflight.tlsReady == 1
                         && preflight.tlsFailed == 0 && preflight.wireQueries == 0,
                         "Source-scope preflight did not authenticate exactly one empty real carrier")

        func original(_ index: Int) -> RequestTarget {
            RequestTarget(host: index % 2 == 0 ? "127.0.0.1" : "127.0.0.2", port: 53, protocolName: "UDP",
                sourceHost: "127.0.0.\(1 + index % 200)", sourcePort: UInt16(46000 + index),
                inboundPort: UInt16(7263 + index % 2))
        }
        func makeFlow(_ target: RequestTarget) throws -> (UUID, any NativeRoutedDatagram) {
            let owner = UUID()
            let flow = try router.makeUDPFlow(host: target.host, port: target.port, queue: queue,
                sourceHost: target.sourceHost, sourcePort: target.sourcePort, inboundPort: target.inboundPort,
                receive: { replies.receive($0, owner: owner) }, failure: { replies.fail($0) })
            flows.append(flow); return (owner, flow)
        }
        func send(_ flow: (UUID, any NativeRoutedDatagram), id: UInt16, name: String,
                  code: UInt8 = 0, cached: Bool = false) throws {
            guard let query = DNSMessageInspection.query(for: name, type: 1, id: id) else {
                throw Failure(text: "Cannot encode source-scope fixture query")
            }
            try replies.register(query, owner: flow.0, code: code, cached: cached)
            flow.1.send(query)
        }
        func wait(_ label: String) throws {
            try replies.wait(label)
            let state = queryStatistics()
            capacity.observe(state)
            try Self.require(state.pendingQueries == 0 && state.waitingClients == 0
                             && state.activeUpstreams == 0 && state.queuedUpstreams == 0,
                             "Completed source-scope phase retained logical governor work")
        }
        func waitForLateTLSCallbacks() throws {
            guard multi else { return }
            let deadline = ProcessInfo.processInfo.systemUptime + 3
            while physical.snapshot.pendingTLSCallbacks != 0 && ProcessInfo.processInfo.systemUptime < deadline {
                _ = RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.005))
            }
            try Self.require(physical.snapshot.pendingTLSCallbacks == 0,
                             "Multi-upstream cancellations did not receive their real delayed TLS completions")
        }
        func json(_ value: [String: Any]) throws -> Data {
            try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        }
        func printJSON(_ marker: String, _ value: [String: Any]) throws {
            print(marker + " " + String(decoding: try json(value), as: UTF8.self))
        }

        // One real PolicyDNS association per tuple, two messages per flow.
        // This exercises coalescing without fabricating a resource-cap failure
        // by allocating a new 1024-budget association for every packet.
        var originals: [(UUID, any NativeRoutedDatagram)] = []
        for index in 0..<96 {
            let flow = try makeFlow(original(index)); originals.append(flow)
            try send(flow, id: UInt16(0x7400 + index * 2), name: "scope.shared.example.test")
            try send(flow, id: UInt16(0x7401 + index * 2), name: "scope.shared.example.test")
        }
        try wait("96 source/original scopes and 192 correctly owned replies")
        // Two-provider pressure can legitimately hedge a later, reused
        // winner while earlier cancelled TLS handoffs still await callbacks.
        // Observe those real callbacks before checking resource/SSL evidence;
        // an early fixture abort would manufacture handshake EOFs in teardown.
        try waitForLateTLSCallbacks()
        let merged = queryStatistics(), scoped = physical.snapshot
        try Self.require(merged.upstreamQueries == 96 && merged.mergedQueries == 96 && merged.cacheHits == 0
                         && (multi ? (96...192).contains(scoped.wireQueries) : scoped.wireQueries == 96),
                         "Source scopes shared answers/coalescing, or duplicate same-scope queries were not merged")
        try Self.require(scoped.tlsFailed == 0 && scoped.preludeFailures == 0
                         && scoped.rawReady - preflight.rawReady <= (multi ? 64 : 32),
                         "96 source scopes recreated a cold real transport per source")

        let cachedAddress = multi ? replies.address(for: 0x7400) : nil
        try send(originals[0], id: 0x7500, name: "scope.shared.example.test", cached: true)
        try wait("same-source warm cache without a wire request")
        if let cachedAddress {
            try Self.require(replies.address(for: 0x7500) == cachedAddress,
                             "Multi-upstream warm cache changed its authenticated provider result")
        }
        let cached = queryStatistics()
        try Self.require(cached.cacheHits == 1 && cached.upstreamQueries == 96
                         && physical.snapshot.wireQueries == scoped.wireQueries,
                         "Warm source cache disappeared or was mistaken for transport reuse")

        for index in 0..<256 {
            let flow = try makeFlow(original(300 + index))
            try send(flow, id: UInt16(0x7600 + index), name: "scope.burst-\(index).example.test")
        }
        try wait("256 distinct source/original queries under the production eight-second deadlines")
        try waitForLateTLSCallbacks()
        let burst = queryStatistics(), beforeFlush = physical.snapshot
        let aggregate = NetworkPerformanceDiagnostics.shared.snapshot()
        if multi {
            // Complete evidence BEFORE a pressure assertion can throw. This
            // private artifact remains diagnostic on failure, not permission
            // to waive a prelude/unknown/SSL failure in the independent oracle.
            let proofURL = root.appendingPathComponent("multi-upstream-carriers.proof.json")
            let proof = try json(physical.carrierProof())
            try Self.require(proof.count <= 16_384 && !FileManager.default.fileExists(atPath: proofURL.path)
                             && FileManager.default.createFile(atPath: proofURL.path, contents: proof,
                                attributes: [.posixPermissions: 0o600]),
                             "Cannot create the bounded private complete carrier binding/cancellation proof")
        }
        try Self.require(burst.upstreamQueries == 352 && burst.mergedQueries == 96 && burst.cacheHits == 1
                         && (multi ? (352...704).contains(beforeFlush.wireQueries) : beforeFlush.wireQueries == 352)
                         && aggregate.dnsQueries == 449 && aggregate.dnsUpstreamAttempts <= 352 * 3
                         && aggregate.dnsFailures == 0 && aggregate.dnsCancelledQueries == 0
                         && (multi ? aggregate.dnsFailovers > 0 : aggregate.dnsFailovers == 0)
                         && aggregate.dnsProxyFallbackAttempts == 0,
                         "Production burst lost queries, retried healthy endpoints or relaxed DNS privacy")
        try Self.require(beforeFlush.rawReady - preflight.rawReady <= 64 && beforeFlush.tlsFailed == 0
                         && beforeFlush.preludeFailures == 0
                         && beforeFlush.tlsReady + beforeFlush.tlsCancelled == beforeFlush.rawReady && beforeFlush.invalid == 0
                         && aggregate.dnsConnectionsReused >= 288,
                         "Many source tuples still amplify real CONNECT/TLS dials or overlap stream ownership")
        if scenario == .multiUpstreamBurst {
            try Self.require(beforeFlush.delayedTLSCallbacks > 0 && beforeFlush.lateCancelledTLSCallbacks > 0,
                             "Multi-upstream slow carrier did not exercise delayed native completions after logical cancel")
        }
        let admitted = capacity.snapshot
        try Self.require(admitted.activePeak == 16 && admitted.queuedPeak > 0 && admitted.queuedPeak <= 512
                         && admitted.waitingPeak <= 512,
                         "Source burst did not exercise bounded global logical admission/backpressure")

        let rejectedWire = beforeFlush.wireQueries, rejectedDials = beforeFlush.rawReady
        try send(originals[0], id: 0x7700, name: "blocked.example.test", code: 5)
        try wait("QNAME REJECT with no native I/O")
        var denied = original(0); denied.sourcePort = 65535
        do {
            let forbidden = try router.makeUDPFlow(host: denied.host, port: denied.port, queue: queue,
                sourceHost: denied.sourceHost, sourcePort: denied.sourcePort, inboundPort: denied.inboundPort,
                receive: { _ in }, failure: { _ in })
            forbidden.cancel(); throw Failure(text: "Source-port REJECT accepted an association")
        } catch let failure as Failure { throw failure }
        catch {
            try Self.require(error.localizedDescription.contains("拒绝"),
                             "Source-port guard failed for an unrelated reason, not REJECT")
        }
        try Self.require(physical.snapshot.wireQueries == rejectedWire && physical.snapshot.rawReady == rejectedDials,
                         "QNAME/source REJECT acquired or created a network stream")

        try printJSON(marker + "-LOGICAL", [
            "queries": aggregate.dnsQueries, "completedClients": replies.snapshot.completed,
            "upstreamLeaders": burst.upstreamQueries, "mergedClients": burst.mergedQueries,
            "cacheHits": burst.cacheHits, "logicalActivePeak": admitted.activePeak,
            "logicalQueuedPeak": admitted.queuedPeak, "logicalWaitingClientsPeak": admitted.waitingPeak,
            "activeLimit": 16, "leaderCapacity": 512, "failures": aggregate.dnsFailures,
            "capacityFailures": aggregate.dnsFailureReasons[.capacity, default: 0],
            "timeoutFailures": aggregate.dnsFailureReasons[.timeout, default: 0],
            "failovers": aggregate.dnsFailovers, "upstreamAttempts": aggregate.dnsUpstreamAttempts,
            "maximumSuccessfulMilliseconds": replies.snapshot.maximumSuccessfulSeconds * 1000,
            "perQueryDeadlineMilliseconds": 8000])
        try printJSON(marker + "-PHYSICAL", [
            "approvedEncryptedProviders": profile.encryptedDNSServers.count,
            "preflightRawReady": preflight.rawReady, "preflightTLSReady": preflight.tlsReady,
            "preflightDNSQueries": preflight.wireQueries,
            "preflightAcknowledgementBytes": preflightACKBytes, "preflightAuthenticatedACK": true,
            "dnsRawCarrierReady": beforeFlush.rawReady - preflight.rawReady,
            "dnsTLSReady": beforeFlush.tlsReady - preflight.tlsReady,
            "typedTLSCancelled": beforeFlush.tlsCancelled, "preludeFailures": beforeFlush.preludeFailures,
            "tlsFailures": beforeFlush.tlsFailed, "clientHTTPQueries": beforeFlush.wireQueries,
            "encryptedConnectionReuse": aggregate.dnsConnectionsReused,
            "cancelRequests": beforeFlush.cancelRequests,
            "nativeTerminalReadACKs": beforeFlush.terminalReads,
            "delayedTLSCallbacks": beforeFlush.delayedTLSCallbacks,
            "lateCancelledTLSCallbacks": beforeFlush.lateCancelledTLSCallbacks,
            "physicalCloseEvidence": "server-side fence required; cancel requests are not TCP ACKs"])

        router.flushDNS()
        let cancelDeadline = ProcessInfo.processInfo.systemUptime + 3
        while ProcessInfo.processInfo.systemUptime < cancelDeadline {
            let state = queryStatistics(), observed = physical.snapshot
            if state.pendingQueries == 0 && state.activeUpstreams == 0
                && observed.cancelRequests == observed.tlsReady { break }
            _ = RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.005))
        }
        let drained = queryStatistics(), flushed = physical.snapshot
        try Self.require(drained.pendingQueries == 0 && drained.activeUpstreams == 0
                         && flushed.cancelRequests == flushed.tlsReady,
                         "Flush did not revoke all old query/pool owners")
        let readyURL = root.appendingPathComponent(fencePrefix + "-flush.ready.json")
        let ackURL = root.appendingPathComponent(fencePrefix + "-flush.ack.json")
        try Self.require(!FileManager.default.fileExists(atPath: readyURL.path)
                         && !FileManager.default.fileExists(atPath: ackURL.path),
                         "Source-scope fixture cannot reuse a prior flush fence")
        let pendingReady = root.appendingPathComponent(fencePrefix + "-flush.ready.pending.json")
        let readyData = try json(["version": 1, "phase": "flush-ready", "logicalActive": drained.activeUpstreams,
            "logicalPending": drained.pendingQueries, "rawReady": flushed.rawReady,
            "tlsReady": flushed.tlsReady, "cancelRequests": flushed.cancelRequests,
            "typedTLSCancelled": flushed.tlsCancelled, "preludeFailures": flushed.preludeFailures,
            "clientHTTPQueries": flushed.wireQueries])
        try Self.require(!FileManager.default.fileExists(atPath: pendingReady.path)
                         && FileManager.default.createFile(atPath: pendingReady.path, contents: readyData,
                             attributes: [.posixPermissions: 0o600]),
                         "Cannot create the private source-scope flush fence")
        try FileManager.default.moveItem(at: pendingReady, to: readyURL)
        let fenceDeadline = ProcessInfo.processInfo.systemUptime + 10
        while !FileManager.default.fileExists(atPath: ackURL.path)
            && ProcessInfo.processInfo.systemUptime < fenceDeadline {
            _ = RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.005))
        }
        guard FileManager.default.fileExists(atPath: ackURL.path) else {
            throw Failure(text: "Parent did not observe physical TLS/CONNECT close before fresh-epoch I/O")
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: ackURL.path)
        try Self.require(ackURL.resolvingSymlinksInPath() == ackURL && attributes[.type] as? FileAttributeType == .typeRegular
                         && (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600
                         && (attributes[.size] as? NSNumber).map({ (1...4096).contains($0.intValue) }) == true,
                         "Physical close ACK must be a bounded private fixture artifact")
        guard let acknowledgement = try JSONSerialization.jsonObject(with: Data(contentsOf: ackURL)) as? [String: Any],
              acknowledgement["version"] as? Int == 1, acknowledgement["phase"] as? String == "flush-closed",
              acknowledgement["tlsStarted"] as? Int == flushed.rawReady,
              acknowledgement["tlsClosed"] as? Int == flushed.rawReady,
              (multi ? (acknowledgement["tlsReady"] as? Int).map({ (flushed.tlsReady...flushed.rawReady).contains($0) }) == true
                     : acknowledgement["tlsReady"] as? Int == flushed.tlsReady),
              acknowledgement["tlsHandlersActive"] as? Int == 0,
              acknowledgement["connectHandlersActive"] as? Int == 0,
              acknowledgement["traditionalQueries"] as? Int == 0 else {
            throw Failure(text: "Physical flush ACK did not prove all old admitted carriers closed")
        }
        try send(originals[0], id: 0x7701, name: "scope.shared.example.test")
        try wait("physically fenced flush requires a fresh epoch, not the old answer or carrier")
        try waitForLateTLSCallbacks()
        let fresh = physical.snapshot, final = queryStatistics()
        let freshCarriers = scenario == .multiUpstreamBurst ? 2 : 1
        let freshQuestions = fresh.wireQueries - beforeFlush.wireQueries
        try Self.require((multi ? (1...2).contains(freshQuestions) : freshQuestions == 1)
                         && fresh.rawReady == beforeFlush.rawReady + freshCarriers && fresh.tlsFailed == 0
                         && fresh.preludeFailures == 0 && fresh.tlsReady + fresh.tlsCancelled == fresh.rawReady
                         && final.upstreamQueries == 353 && final.cacheHits == 1,
                         "Fresh query reused an old cache/transport or retried an authenticated loopback peer")
        try replies.validate()
        if multi {
            try printJSON(marker + "-ANSWERS", ["fixtureOnly": true, "replyAddresses": replies.addressLedger])
        }
        try printJSON(marker + "-FLUSH", ["oldTLSCarriersClosedByServer": flushed.rawReady,
            "newEpochRawCarriers": fresh.rawReady - flushed.rawReady,
            "newEpochWireQueries": freshQuestions,
            "serverCloseFence": true, "logicalActive": final.activeUpstreams, "logicalPending": final.pendingQueries])
        if multi {
            let proof = physical.carrierProof()
            try Self.require(try json(proof).count <= 16_384, "Complete fresh-epoch carrier proof exceeded its private bound")
            try printJSON(marker + "-CARRIERS", proof)
        }
        successAssertionsCompleted = true
        return "DNS adaptive loopback checks passed: protection=\(profile.dnsLeakProtectionEnabled), "
            + "scenario=\(scenario.rawValue), transactions=\(replies.snapshot.completed), "
            + "\(profile.encryptedDNSServers.count) approved encrypted providers, 96 strict source scopes/192 replies, 256 unique burst, QNAME/source REJECT, "
            + "8s original query deadlines, physical flush fence, production HTTP CONNECT/CXX/nested TLS, no traditional fallback"
    }

    /// Diagnostics only, not a new allowance in the wire/privacy oracle. The
    /// marker must survive an early thrown assertion and stay small enough to
    /// be captured independently of the CLI's human-readable failure text.
    private func emitSourceScopeTiming(started: UInt64, success: Bool,
                                       logical: DNSQueryCoordinator.Statistics,
                                       capacity: DNSFixtureCapacityProbe.Snapshot,
                                       completedClients: Int, marker: String = "DNS-SOURCE-SCOPE-TIMING") {
        let aggregate = NetworkPerformanceDiagnostics.shared.snapshot()
        var stages: [String: Any] = [:]
        for stage in NetworkPerformanceStage.allCases {
            let value = aggregate.stages[stage] ?? NetworkStageSnapshot()
            var fields: [String: Any] = ["count": value.count, "failures": value.failureCount,
                "cancelled": value.cancellationCount, "samples": value.sampleCount]
            if let milliseconds = value.medianMilliseconds { fields["medianMilliseconds"] = milliseconds }
            if let milliseconds = value.p95Milliseconds { fields["p95Milliseconds"] = milliseconds }
            if let milliseconds = value.latestMilliseconds { fields["latestMilliseconds"] = milliseconds }
            stages[stage.rawValue] = fields
        }
        var result: [String: Any] = ["formatVersion": 1, "fixtureOnly": true,
            "clock": "monotonic milliseconds from source-scope workload; before teardown",
            "successAssertionsCompleted": success,
            "elapsedMilliseconds": NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started),
            "physical": physical.timingSnapshot(),
            "logical": ["upstreamLeaders": logical.upstreamQueries, "cacheHits": logical.cacheHits,
                "mergedClients": logical.mergedQueries, "activeUpstreams": logical.activeUpstreams,
                "queuedUpstreams": logical.queuedUpstreams, "pendingQueries": logical.pendingQueries,
                "waitingClients": logical.waitingClients, "completedClients": completedClients],
            "capacity": ["activePeak": capacity.activePeak, "queuedPeak": capacity.queuedPeak,
                "waitingPeak": capacity.waitingPeak],
            "diagnostics": ["queries": aggregate.dnsQueries, "failures": aggregate.dnsFailures,
                "cancelledQueries": aggregate.dnsCancelledQueries, "attempts": aggregate.dnsUpstreamAttempts,
                "failovers": aggregate.dnsFailovers, "connectionReuse": aggregate.dnsConnectionsReused,
                "proxyFallbackAttempts": aggregate.dnsProxyFallbackAttempts],
            "stages": stages]
        var serialized = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        // Added forensic rows must not displace the original counters, spans
        // or marker. If their bounded block still reaches the whole marker's
        // existing ceiling, trim only those additional rows and report it.
        while let data = serialized, data.count > 16_384,
              var measured = result["physical"] as? [String: Any],
              var lifecycle = measured["tlsLifecycle"] as? [String: Any] {
            let key: String
            if let rows = lifecycle["ordinaryRows"] as? [[String: Any]], !rows.isEmpty { key = "ordinaryRows" }
            else if let rows = lifecycle["failureRows"] as? [[String: Any]], !rows.isEmpty { key = "failureRows" }
            else { break }
            guard var rows = lifecycle[key] as? [[String: Any]] else { break }
            rows.removeLast(); lifecycle[key] = rows
            let omitted = key == "ordinaryRows" ? "omittedOrdinaryRows" : "omittedFailureRows"
            lifecycle[omitted] = (lifecycle[omitted] as? Int ?? 0) + 1
            lifecycle["wholeMarkerByteTrimming"] = true
            measured["tlsLifecycle"] = lifecycle; result["physical"] = measured
            serialized = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        }
        if let data = serialized, data.count <= 16_384 {
            print(marker + " " + String(decoding: data, as: UTF8.self))
        } else {
            print(marker + " {\"fixtureOnly\":true,\"formatVersion\":1,\"observationError\":\"bounded-serialization-failed\"}")
        }
    }

    private func sourceScopeRoot() throws -> URL {
        let arguments = CommandLine.arguments, flag = "--dns-adaptive-fixture-root"
        guard arguments.filter({ $0 == flag }).count == 1, let index = arguments.firstIndex(of: flag),
              index + 1 < arguments.count else { throw Failure(text: "Source-scope fixture requires its exact private root") }
        let raw = URL(fileURLWithPath: arguments[index + 1]).standardizedFileURL
        let root = raw.resolvingSymlinksInPath()
        let temporary = FileManager.default.temporaryDirectory.standardizedFileURL.resolvingSymlinksInPath()
        let attributes = try FileManager.default.attributesOfItem(atPath: root.path)
        try Self.require(raw == root && root.deletingLastPathComponent() == temporary
                         && root.lastPathComponent.hasPrefix("hajimi-dns-adaptive-")
                         && attributes[.type] as? FileAttributeType == .typeDirectory
                         && (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700,
                         "Source-scope flush artifacts must stay in the private temporary fixture root")
        return root
    }

    private func sourceScopeTLSPreflight(router: NativePacketRouter, queue: DispatchQueue) throws -> Int {
        guard let upgrade = tlsUpgrader else { throw Failure(text: "Source-scope fixture requires real routed TLS") }
        let port: UInt16
        if scenario == .multiUpstreamConnectFailureBurst {
            guard let healthy = ports.first(where: { $0 != firstPort }) else {
                throw Failure(text: "Multi-upstream preflight has no healthy admitted peer")
            }
            port = healthy
        } else { port = firstPort }
        let state = DNSFixturePreflightState(deadline: ProcessInfo.processInfo.systemUptime + 8)
        router.connectTCP(host: "127.0.0.1", port: port, queue: queue,
            sourceHost: nil, sourcePort: nil, inboundPort: nil, synthesizeFakeIP: false) { result in
            switch result {
            case .failure(let error): state.finish(.failure(error))
            case .success(let raw):
                guard state.adopt(raw) else { raw.cancel(); return }
                let cancel = upgrade(raw, "127.0.0.1", port, "127.0.0.1", queue, ["http/1.1"],
                                     nil, { _ in }, state.finish)
                state.adoptCancellation(cancel)
            }
        }
        if state.done.wait(timeout: .now() + 8) != .success, !state.hasFinished {
            state.expire()
            throw Failure(text: "Source-scope real TLS preflight exceeded its original eight-second bound")
        }
        let acknowledgementBytes = try state.result()
        print("DNS-SOURCE-SCOPE-PREFLIGHT realHTTPConnect=true privateCA+IP-SAN=true TLS=1 DNSQueries=0 "
              + "authenticatedACKBytes=\(acknowledgementBytes) deadlineMilliseconds=8000")
        return acknowledgementBytes
    }
}

private struct DNSFixtureScopeError: LocalizedError {
    let text: String
    var errorDescription: String? { text }
}

private final class DNSFixturePreflightState {
    // Kept identical to the fixed, fixture-only server marker. This is not
    // HTTP or a DNS question and is never sent to a production resolver.
    private static let acknowledgement = Data("HAJIMI-DNS-PREFLIGHT/1\r\n".utf8)
    let done = DispatchSemaphore(value: 0)
    private let lock = NSLock(), deadline: TimeInterval
    private var outcome: Result<Int, Error>?
    private var raw: (any NativeOutboundByteStream)?
    private var secured: (any NativeOutboundByteStream)?
    private var receivedAcknowledgement = Data()
    private var cancellation: (() -> Void)?
    init(deadline: TimeInterval) { self.deadline = deadline }

    var hasFinished: Bool { lock.lock(); defer { lock.unlock() }; return outcome != nil }
    func adopt(_ stream: any NativeOutboundByteStream) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard outcome == nil, ProcessInfo.processInfo.systemUptime < deadline else { return false }
        raw = stream; return true
    }
    func adoptCancellation(_ action: (() -> Void)?) {
        lock.lock(); let finished = outcome != nil
        if !finished { cancellation = action }; lock.unlock()
        if finished { action?() }
    }
    func finish(_ result: Result<any NativeOutboundByteStream, Error>) {
        switch result {
        case .failure(let error): complete(.failure(error))
        case .success(let stream):
            lock.lock()
            guard outcome == nil else { lock.unlock(); stream.cancel(); return }
            if let secured {
                let duplicate = secured === stream
                lock.unlock(); if !duplicate { stream.cancel() }; return
            }
            secured = stream; cancellation = nil
            lock.unlock()
            receiveAcknowledgement(from: stream)
        }
    }
    private func receiveAcknowledgement(from stream: any NativeOutboundByteStream) {
        lock.lock()
        guard outcome == nil, secured === stream else { lock.unlock(); return }
        guard ProcessInfo.processInfo.systemUptime < deadline else {
            lock.unlock(); complete(.failure(DNSFixtureScopeError(text: "Real TLS preflight expired"))); return
        }
        // One extra byte detects trailing payload delivered with the ACK;
        // every prefix is checked before requesting a fragmented remainder.
        let maximum = Self.acknowledgement.count - receivedAcknowledgement.count + 1
        lock.unlock()
        stream.receive(maximum: maximum) { data, eof, error in
            self.lock.lock()
            guard self.outcome == nil, self.secured === stream else { self.lock.unlock(); return }
            let result: Result<Int, Error>?
            if ProcessInfo.processInfo.systemUptime >= self.deadline {
                result = .failure(DNSFixtureScopeError(text: "Real TLS preflight expired"))
            } else if let error {
                result = .failure(error)
            } else if eof {
                result = .failure(DNSFixtureScopeError(text: "Real TLS preflight ACK was truncated or invalid"))
            } else if let data, !data.isEmpty, data.count <= maximum {
                self.receivedAcknowledgement.append(data)
                if !Self.acknowledgement.starts(with: self.receivedAcknowledgement) {
                    result = .failure(DNSFixtureScopeError(text: "Real TLS preflight ACK did not match its authenticated marker"))
                } else if self.receivedAcknowledgement.count == Self.acknowledgement.count {
                    result = .success(self.receivedAcknowledgement.count)
                } else { result = nil }
            } else { result = .failure(DNSFixtureScopeError(text: "Real TLS preflight ACK was truncated or invalid")) }
            self.lock.unlock()
            if let result { self.complete(result) }
            else { self.receiveAcknowledgement(from: stream) }
        }
    }
    private func complete(_ result: Result<Int, Error>) {
        lock.lock()
        guard outcome == nil else { lock.unlock(); return }
        if ProcessInfo.processInfo.systemUptime >= deadline {
            outcome = .failure(DNSFixtureScopeError(text: "Real TLS preflight expired"))
        } else { outcome = result }
        let saved = raw, protected = secured, cancel = cancellation
        raw = nil; secured = nil; cancellation = nil; lock.unlock()
        cancel?(); protected?.cancel(); saved?.cancel(); done.signal()
    }
    func expire() {
        lock.lock()
        guard outcome == nil else { lock.unlock(); return }
        outcome = .failure(DNSFixtureScopeError(text: "Real TLS preflight expired"))
        let saved = raw, protected = secured, cancel = cancellation
        raw = nil; secured = nil; cancellation = nil; lock.unlock()
        cancel?(); protected?.cancel(); saved?.cancel(); done.signal()
    }
    func result() throws -> Int {
        lock.lock(); let result = outcome; lock.unlock()
        guard let result else { throw DNSFixtureScopeError(text: "Real TLS preflight did not finish") }
        return try result.get()
    }
    deinit { expire() }
}

/// These are actual raw-ready/TLS-ready observations, not query admission or
/// a speculative claim that stream.cancel() has closed a server TCP socket.
private final class DNSFixtureDelayedTLSHandoff {
    private let queue: DispatchQueue, probe: DNSFixturePhysicalProbe
    private let completion: (Result<any NativeOutboundByteStream, Error>) -> Void
    private let readyDeadline = ProcessInfo.processInfo.systemUptime + 1.4
    private let lock = NSLock()
    private var received = false, delivered = false, cancelledAt: TimeInterval?
    init(queue: DispatchQueue, probe: DNSFixturePhysicalProbe,
         completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        self.queue = queue; self.probe = probe; self.completion = completion
    }
    func receive(_ result: Result<any NativeOutboundByteStream, Error>) {
        lock.lock()
        guard !received else {
            lock.unlock(); if case .success(let stream) = result { stream.cancel() }
            probe.invalidRead(); return
        }
        received = true; lock.unlock()
        queue.asyncAfter(deadline: .now() + max(0, readyDeadline - ProcessInfo.processInfo.systemUptime)) {
            self.lock.lock(); self.delivered = true
            let cancelledAt = self.cancelledAt; self.lock.unlock()
            self.probe.delayedTLSCallback(cancelledAt: cancelledAt)
            // Preserve the exact real transport result and the normal stale
            // result cancellation path. This is not a fabricated TLS success,
            // cancelled failure or physical socket-close acknowledgement.
            self.completion(result)
        }
    }
    func cancelRequested() {
        lock.lock()
        if !delivered && cancelledAt == nil { cancelledAt = ProcessInfo.processInfo.systemUptime }
        lock.unlock()
    }
}

/// This extra nonce/ACK wire protocol exists only between the explicitly
/// admitted multi-provider CLI peers. Ordinary profiles and every other
/// fixture use the unchanged C++ CONNECT -> verified TLS path. No extra timer
/// is introduced: query/preflight cancellation retains the original 8s bound.
private final class DNSFixtureCarrierBinding {
    private enum Phase { case idle, prelude, tls, failed }
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "Fixture pre-TLS binding: \(text)" }
    }
    private let stream: any NativeOutboundByteStream, token: UUID
    private let queue: DispatchQueue, probe: DNSFixturePhysicalProbe
    private let frame: Data, expectedACK: Data
    private let observeFailure: (Error) -> Void, startTLS: () -> (() -> Void), preTLSFailure: (Error, String) -> Void
    private let cancellationLock = NSLock()
    private var cancelled = false
    private var phase = Phase.idle, received = Data()
    private var nativeCancellation: (() -> Void)?
    init(stream: any NativeOutboundByteStream, token: UUID, ordinal: Int, provider: Int,
         queue: DispatchQueue, probe: DNSFixturePhysicalProbe, observeFailure: @escaping (Error) -> Void,
         startTLS: @escaping () -> (() -> Void), preTLSFailure: @escaping (Error, String) -> Void) {
        self.stream = stream; self.token = token; self.probe = probe
        self.queue = DispatchQueue(label: "app.hajimi.fixture-only.carrier-binding", target: queue)
        self.observeFailure = observeFailure; self.startTLS = startTLS; self.preTLSFailure = preTLSFailure
        let suffix = "\(token.uuidString) \(provider) \(String(format: "%03d", ordinal))\r\n"
        frame = Data(("HAJIMI-TLS-BIND/1 " + suffix).utf8)
        expectedACK = Data(("HAJIMI-TLS-ACK/1 " + suffix).utf8)
    }
    func start() {
        queue.async {
            guard self.phase == .idle else { return }
            self.phase = .prelude
            self.probe.preludeStarted(token: self.token)
            guard !self.isCancelled else {
                self.fail(Failure(text: "own prelude cancellation before write; native TLS never started"), branch: "local-before-write"); return
            }
            self.stream.send(self.frame) { error in
                let entered = NetworkPerformanceDiagnostics.now()
                if let error { self.observeFailure(error) }
                self.probe.rawPreludeCallback(write: true, bytes: 0, eof: false, error: error, token: self.token, at: entered)
                self.queue.async {
                    guard self.phase == .prelude else { return }
                    if let error { self.fail(error, branch: "raw-write-error"); return }
                    guard !self.isCancelled else {
                        self.fail(Failure(text: "own cancellation after real prelude write callback; TLS never started"), branch: "local-after-write"); return
                    }
                    self.readACK()
                }
            }
        }
    }
    func cancel() {
        cancellationLock.lock()
        guard !cancelled else { cancellationLock.unlock(); return }
        cancelled = true; cancellationLock.unlock()
        queue.async {
            guard self.phase != .failed else { return }
            if self.phase == .tls { self.nativeCancellation?() }
            else {
                // Keep the pending raw callback as the real receipt. Never
                // fabricate a native TLS success, cancellation or close ACK.
                self.stream.cancel()
            }
        }
    }
    private var isCancelled: Bool { cancellationLock.lock(); defer { cancellationLock.unlock() }; return cancelled }
    private func readACK() {
        stream.receive(maximum: expectedACK.count - received.count) { data, eof, error in
            let entered = NetworkPerformanceDiagnostics.now()
            if let error { self.observeFailure(error) }
            self.probe.rawPreludeCallback(write: false, bytes: data?.count ?? 0, eof: eof, error: error, token: self.token, at: entered)
            self.queue.async {
                guard self.phase == .prelude else { return }
                if let error { self.fail(error, branch: "raw-read-error"); return }
                if let data { self.received.append(data) }
                self.probe.observePreludeACK(bytes: self.received.count, prefixMatches: self.expectedACK.starts(with: self.received),
                    complete: !eof && self.received == self.expectedACK, token: self.token)
                guard !self.isCancelled else {
                    self.fail(Failure(text: "own cancellation after real prelude read callback; TLS never started"), branch: "local-after-read"); return
                }
                guard !eof, self.received.count <= self.expectedACK.count,
                      self.expectedACK.starts(with: self.received) else {
                    self.fail(Failure(text: "partial/EOF/incorrect nonce ACK; TLS never started"), branch: "local-invalid-ack"); return
                }
                if self.received == self.expectedACK {
                    // Linearize prelude cancellation with the transition and
                    // installation of the real native TLS cancel action. A
                    // second unlocked isCancelled check leaves a TOCTOU gap.
                    self.cancellationLock.lock()
                    guard !self.cancelled else {
                        self.cancellationLock.unlock()
                        self.fail(Failure(text: "own cancellation at the completed raw ACK; native TLS never started"), branch: "local-atomic-cancel"); return
                    }
                    self.probe.preludeAcknowledged(token: self.token)
                    self.phase = .tls; self.nativeCancellation = self.startTLS()
                    self.cancellationLock.unlock()
                } else { self.readACK() }
            }
        }
    }
    private func fail(_ error: Error, branch: String) {
        guard phase == .prelude || phase == .idle else { return }
        phase = .failed; stream.cancel()
        // A separate fixture prelude terminal, not a native TLS completion.
        preTLSFailure(error, branch)
    }
}

private final class DNSFixturePhysicalProbe {
    struct Snapshot {
        let rawReady: Int, tlsReady: Int, tlsFailed: Int, wireQueries: Int
        let tlsCancelled: Int, preludeFailures: Int
        let cancelRequests: Int, terminalReads: Int, invalid: Int
        let pendingTLSCallbacks: Int, delayedTLSCallbacks: Int, lateCancelledTLSCallbacks: Int
    }
    /// Fixed-size passive SDK receipts. Preserve the first actual event and
    /// count duplicates rather than silently replacing them with a valid one.
    /// Security may invoke the callback before its evaluation call returns.
    private struct IdentityTrustReceipts {
        var startCount = 0, returnCount = 0, callbackCount = 0
        var started: UInt64?, returned: UInt64?, callback: UInt64?, returnStatus: OSStatus?
        var trusted: Bool?, hasError: Bool?, errorIsCFError: Bool?
        var errorDomain: String?, errorCode: Int?, certificateCount: Int?
        var leafSHA256: String?, evaluatedAnchorSHA256: String?, fixtureAnchorSHA256: String?
    }
    private struct CarrierTiming {
        let ordinal: Int, providerOrdinal: Int, rawReady: UInt64
        var tlsReady: UInt64?, tlsFailure: UInt64?
        var preludeStarted: UInt64?, preludeACK: UInt64?, preludeFailure: UInt64?, preludeError: ErrorMetadata?
        var preludeBranch: String?, rawWriteCallback: UInt64?, rawReadCallback: UInt64?
        var rawWriteError: ErrorMetadata?, rawReadError: ErrorMetadata?, rawReadBytes = 0, rawReadEOF = false
        var observedACKBytes = 0, observedACKPrefix = false, observedACKComplete = false
        var nativeTLSStarted: UInt64?, firstObserverDeny: UInt64?, observerAuthenticationCount = 0
        var nativeResultIngress: UInt64?, nativeResultKind: String?, nativeResultError: ErrorMetadata?
        var nativeResultCount = 0
        var firstFailureObserverIngress: UInt64?, lastFailureObserverIngress: UInt64?
        var firstFailureObserverError: ErrorMetadata?, lastFailureObserverError: ErrorMetadata?
        var failureObserverCount = 0
        var firstExplicitCancel: UInt64?, nativeResultPresentAtCancel: Bool?
        var explicitCancelCount = 0
        var firstHTTPSend: UInt64?, firstNativeWriteCallback: UInt64?, firstHTTPBytes: UInt64?
        var lastHTTPSend: UInt64?, awaitingHTTPBytes = false
        var queries = 0
        var applicationBytes = 0
        var identityPort: UInt16?, identityPrefix = Data(), identityPrefixWrites = 0, identityPrefixCallbacks = 0
        var identityPrefixWrittenBytes = 0, identityPrefixWriteFailures = 0
        var firstPrefixCallback: UInt64?, lastPrefixCallback: UInt64?, prefixWriteError: ErrorMetadata?
        var firstRawCancel: UInt64?, rawCancelCount = 0, firstRawTerminal: UInt64?, rawTerminalError: ErrorMetadata?
        var firstCertificateObserver: UInt64?, certificateObserverError: ErrorMetadata?, firstUnknownObserver: UInt64?
        var identityTrust = IdentityTrustReceipts()
    }
    /// Immutable, bounded forensic metadata from this admitted CLI fixture.
    /// Error text is never consulted by a guard or fallback policy. Native
    /// cancellation eligibility uses the actual enum plus this fixture's
    /// explicit ACK/phase/observer provenance, never a message/domain match.
    private struct ErrorMetadata: Equatable {
        let swiftType: String, nativeCase: String?, nsDomain: String, nsCode: Int
        let networkKind: String?, networkCode: Int?, classification: String, description: String
        init(_ error: Error) {
            swiftType = Self.bounded(String(reflecting: type(of: error)), bytes: 96)
            if let native = error as? NativeOutboundError {
                switch native {
                case .unsupported: nativeCase = "unsupported"
                case .connection: nativeCase = "connection"
                case .protocolError: nativeCase = "protocolError"
                case .crypto: nativeCase = "crypto"
                case .cancelled: nativeCase = "cancelled"
                }
            } else { nativeCase = nil }
            let bridged = error as NSError
            nsDomain = Self.bounded(bridged.domain, bytes: 96); nsCode = bridged.code
            if let network = error as? NWError {
                switch network {
                case .tls(let value): networkKind = "tls"; networkCode = Int(value)
                case .dns(let value): networkKind = "dns"; networkCode = Int(value)
                case .posix(let value): networkKind = "posix"; networkCode = Int(value.rawValue)
                @unknown default: networkKind = "unknown"; networkCode = nil
                }
            } else { networkKind = nil; networkCode = nil }
            classification = String(describing: EncryptedDNSQueryFailure.classify(error))
            description = Self.bounded(error.localizedDescription, bytes: 160)
        }
        private static func bounded(_ value: String, bytes: Int) -> String {
            String(decoding: value.utf8.prefix(bytes), as: UTF8.self)
        }
        var fields: [String: Any] {
            var result: [String: Any] = ["swiftType": swiftType, "NSErrorDomain": nsDomain, "NSErrorCode": nsCode,
                "classification": classification, "localizedDescriptionForensicsOnly": description]
            if let nativeCase { result["NativeOutboundErrorCase"] = nativeCase }
            if let networkKind { result["NWErrorKind"] = networkKind }
            if let networkCode { result["NWErrorCode"] = networkCode }
            return result
        }
    }
    private struct SpanWindow {
        private(set) var count = 0
        private var values: [Double] = [], next = 0
        mutating func record(_ milliseconds: Double) {
            guard milliseconds.isFinite, milliseconds >= 0 else { return }
            count += 1
            if values.count < 128 { values.append(milliseconds) }
            else { values[next] = milliseconds }
            next = (next + 1) % 128
        }
        var summary: [String: Any] {
            let sorted = values.sorted()
            var result: [String: Any] = ["count": count, "samples": sorted.count]
            if !sorted.isEmpty {
                result["minimumMilliseconds"] = sorted[0]
                result["medianMilliseconds"] = sorted[max(0, Int(ceil(Double(sorted.count) * 0.5)) - 1)]
                result["p95Milliseconds"] = sorted[max(0, Int(ceil(Double(sorted.count) * 0.95)) - 1)]
                result["maximumMilliseconds"] = sorted[sorted.count - 1]
            }
            return result
        }
    }
    private let lock = NSLock()
    private let permitsBoundCancellation: Bool, observesIdentity: Bool
    private var started = Set<UUID>(), ready = Set<UUID>(), completed = Set<UUID>()
    private var typedCancelledTokens = Set<UUID>(), preludeFailedTokens = Set<UUID>()
    private var cancelledTokens = Set<UUID>(), terminalReads = Set<UUID>()
    private var wireQueries = 0, failures = 0, invalid = 0
    private var timingOrigin = NetworkPerformanceDiagnostics.now()
    private var timings: [UUID: CarrierTiming] = [:]
    private var spans: [String: SpanWindow] = [:]
    private var droppedCarrierTimings = 0, nativeWriteCallbacks = 0, nativeWriteFailures = 0
    private var delayedTLSCallbacks = 0, lateCancelledTLSCallbacks = 0
    init(permitsBoundCancellation: Bool = false, observesIdentity: Bool = false) {
        self.permitsBoundCancellation = permitsBoundCancellation; self.observesIdentity = observesIdentity
    }
    func beginTimingWindow(at origin: UInt64) { lock.lock(); timingOrigin = origin; lock.unlock() }
    func carrierOrdinal(token: UUID) -> Int? { lock.lock(); defer { lock.unlock() }; return timings[token]?.ordinal }
    func preludeStarted(token: UUID) {
        let now = NetworkPerformanceDiagnostics.now(); lock.lock(); timings[token]?.preludeStarted = now; lock.unlock()
    }
    func preludeAcknowledged(token: UUID) {
        let now = NetworkPerformanceDiagnostics.now(); lock.lock(); timings[token]?.preludeACK = now; lock.unlock()
    }
    func nativeTLSStarted(token: UUID) {
        let now = NetworkPerformanceDiagnostics.now(); lock.lock(); timings[token]?.nativeTLSStarted = now; lock.unlock()
    }
    func identityTrustObserved(_ observation: DNSFixtureTrustObservation, token: UUID) {
        lock.lock(); defer { lock.unlock() }
        guard observesIdentity, var timing = timings[token], timing.identityPort != nil else { invalid += 1; return }
        switch observation {
        case .evaluationStarted(let at):
            timing.identityTrust.startCount += 1
            if timing.identityTrust.startCount == 1 { timing.identityTrust.started = at }
        case .evaluationReturned(let status, let at):
            timing.identityTrust.returnCount += 1
            if timing.identityTrust.returnCount == 1 {
                timing.identityTrust.returned = at; timing.identityTrust.returnStatus = status
            }
        case .evaluationCompleted(let trusted, let hasError, let errorIsCFError, let errorDomain, let errorCode,
                                  let certificateCount, let leafSHA256, let evaluatedAnchorSHA256,
                                  let fixtureAnchorSHA256, let at):
            timing.identityTrust.callbackCount += 1
            if timing.identityTrust.callbackCount == 1 {
                timing.identityTrust.callback = at; timing.identityTrust.trusted = trusted
                timing.identityTrust.hasError = hasError; timing.identityTrust.errorIsCFError = errorIsCFError
                timing.identityTrust.errorDomain = errorDomain; timing.identityTrust.errorCode = errorCode
                timing.identityTrust.certificateCount = certificateCount; timing.identityTrust.leafSHA256 = leafSHA256
                timing.identityTrust.evaluatedAnchorSHA256 = evaluatedAnchorSHA256
                timing.identityTrust.fixtureAnchorSHA256 = fixtureAnchorSHA256
            }
        }
        timings[token] = timing
    }
    func rawPreludeCallback(write: Bool, bytes: Int, eof: Bool, error: Error?, token: UUID, at now: UInt64) {
        let metadata = error.map { ErrorMetadata($0) }
        lock.lock(); defer { lock.unlock() }
        if write { timings[token]?.rawWriteCallback = now; timings[token]?.rawWriteError = metadata }
        else {
            timings[token]?.rawReadCallback = now; timings[token]?.rawReadError = metadata
            timings[token]?.rawReadBytes = bytes; timings[token]?.rawReadEOF = eof
        }
    }
    func observePreludeACK(bytes: Int, prefixMatches: Bool, complete: Bool, token: UUID) {
        lock.lock(); defer { lock.unlock() }
        timings[token]?.observedACKBytes = bytes; timings[token]?.observedACKPrefix = prefixMatches
        timings[token]?.observedACKComplete = complete
    }
    func preludeFailed(_ error: Error, branch: String, token: UUID) {
        let now = NetworkPerformanceDiagnostics.now(), metadata = ErrorMetadata(error)
        lock.lock(); defer { lock.unlock() }
        guard started.contains(token), completed.insert(token).inserted else { invalid += 1; return }
        preludeFailedTokens.insert(token)
        timings[token]?.preludeFailure = now; timings[token]?.preludeError = metadata; timings[token]?.preludeBranch = branch
    }
    func beginTLS(providerOrdinal: Int, identityPort: UInt16? = nil) -> UUID {
        let now = NetworkPerformanceDiagnostics.now(), token = UUID()
        lock.lock()
        let ordinal = started.count
        started.insert(token)
        if timings.count < 128 {
            timings[token] = CarrierTiming(ordinal: ordinal, providerOrdinal: providerOrdinal, rawReady: now)
            timings[token]?.identityPort = identityPort
        } else { droppedCarrierTimings += 1 }
        lock.unlock(); return token
    }
    func nativeTLSResult(_ result: Result<any NativeOutboundByteStream, Error>, token: UUID) {
        let now = NetworkPerformanceDiagnostics.now()
        let kind: String
        if case .failure = result { kind = "failure" } else { kind = "success" }
        lock.lock()
        guard var timing = timings[token] else { lock.unlock(); return }
        timing.nativeResultCount += 1
        let first = timing.nativeResultIngress == nil
        if first {
            timing.nativeResultIngress = now
            timing.nativeResultKind = kind
            if let cancelled = timing.firstExplicitCancel {
                timing.nativeResultPresentAtCancel = now <= cancelled
            }
        }
        timings[token] = timing; lock.unlock()
        // Publish completion presence before computing descriptive metadata;
        // a concurrent explicit cancel must not see a formatting delay as a
        // missing real result. This retains no stream or Error object.
        if first, case .failure(let error) = result {
            let metadata = ErrorMetadata(error)
            lock.lock(); timings[token]?.nativeResultError = metadata; lock.unlock()
        }
    }
    func failureObserved(_ error: Error, token: UUID, at now: UInt64) {
        let metadata = ErrorMetadata(error)
        let reason = EncryptedDNSQueryFailure.classify(error)
        lock.lock(); defer { lock.unlock() }
        guard var timing = timings[token] else { return }
        timing.failureObserverCount += 1
        if !reason.permitsProxyFallback, reason != .cancelled,
           timing.firstObserverDeny.map({ now < $0 }) ?? true { timing.firstObserverDeny = now }
        if reason == .authentication { timing.observerAuthenticationCount += 1 }
        if timing.identityPort != nil {
            // These fields originate only from the actual NWError cast above,
            // never an NSError domain, code, message or cancellation flag.
            // -9808 is only a retained typed candidate. The identity oracle
            // still requires this owner's actual CFError hostname mismatch,
            // evaluated leaf/anchor and real pre-close callback; this field
            // alone never proves a SAN rejection or changes classification.
            if metadata.networkKind == "tls", let code = metadata.networkCode, [-9808, -9807, -9843].contains(code),
               timing.firstCertificateObserver.map({ now < $0 }) ?? true {
                timing.firstCertificateObserver = now; timing.certificateObserverError = metadata
            }
            if reason == .other, timing.firstUnknownObserver.map({ now < $0 }) ?? true { timing.firstUnknownObserver = now }
        }
        // Native observer callbacks can be concurrent; entry timestamps, not
        // the order in which formatting finishes, define first and last.
        if timing.firstFailureObserverIngress.map({ now < $0 }) ?? true {
            timing.firstFailureObserverIngress = now; timing.firstFailureObserverError = metadata
        }
        if timing.lastFailureObserverIngress.map({ now >= $0 }) ?? true {
            timing.lastFailureObserverIngress = now; timing.lastFailureObserverError = metadata
        }
        timings[token] = timing
    }
    func upgradeCancellationRequested(token: UUID) {
        let now = NetworkPerformanceDiagnostics.now()
        lock.lock(); defer { lock.unlock() }
        guard var timing = timings[token] else { return }
        timing.explicitCancelCount += 1
        if timing.firstExplicitCancel == nil {
            timing.firstExplicitCancel = now
            timing.nativeResultPresentAtCancel = timing.nativeResultIngress.map({ $0 <= now }) ?? false
        }
        timings[token] = timing
    }
    func tlsResult(_ result: Result<any NativeOutboundByteStream, Error>, token: UUID) {
        let now = NetworkPerformanceDiagnostics.now()
        lock.lock(); defer { lock.unlock() }
        guard started.contains(token), completed.insert(token).inserted else { invalid += 1; return }
        if case .success = result {
            ready.insert(token)
            if var timing = timings[token] {
                timing.tlsReady = now; timings[token] = timing
                recordSpan("rawReadyToTLSCallback", from: timing.rawReady, to: now, provider: timing.providerOrdinal)
            }
        } else if case .failure(let error) = result {
            // Only the real native typed own-cancel result can be a separate
            // non-network abort. Binding must already have succeeded and no
            // HTTP/DNS payload or prior observer denial may be hidden by it.
            let timing = timings[token]
            let typed: Bool
            if let native = error as? NativeOutboundError, case .cancelled = native { typed = true }
            else { typed = false }
            var boundAbort = false
            if permitsBoundCancellation, typed, let timing, let acknowledged = timing.preludeACK,
               let nativeStarted = timing.nativeTLSStarted, let cancelled = timing.firstExplicitCancel,
               let realResult = timing.nativeResultIngress, acknowledged <= nativeStarted,
               nativeStarted <= cancelled, cancelled <= realResult, timing.queries == 0,
               timing.nativeResultKind == "failure", timing.observerAuthenticationCount == 0,
               timing.firstObserverDeny.map({ cancelled < $0 }) != false { boundAbort = true }
            if boundAbort { typedCancelledTokens.insert(token) }
            else { failures += 1 }
            if var timing = timings[token] {
                timing.tlsFailure = now; timings[token] = timing
                recordSpan(boundAbort ? "rawReadyToTypedTLSCancellation" : "rawReadyToTLSFailure",
                           from: timing.rawReady, to: now, provider: timing.providerOrdinal)
            }
        }
    }
    func sent(_ data: Data, token: UUID) -> UInt64 {
        let now = NetworkPerformanceDiagnostics.now()
        let valid: Bool
        if data.starts(with: Data("POST /dns-query HTTP/1.1\r\n".utf8)),
           let separator = data.range(of: Data("\r\n\r\n".utf8)),
           let question = DNSMessageInspection.singleQuestion(in: Data(data[separator.upperBound...])),
           question.type == 1, question.`class` == 1 {
            valid = question.name == "scope.shared.example.test"
                || (question.name.hasPrefix("scope.burst-") && question.name.hasSuffix(".example.test"))
                || ["adaptive.cold.example.test", "adaptive.discover.example.test",
                    "adaptive.preferred.example.test"].contains(question.name)
                || (observesIdentity && ["adaptive.identity.example.test", "adaptive.identity-next.example.test"].contains(question.name))
        } else { valid = false }
        lock.lock(); defer { lock.unlock() }
        if !ready.contains(token) || cancelledTokens.contains(token) || !valid { invalid += 1 }
        wireQueries += 1
        if var timing = timings[token] {
            if timing.firstHTTPSend == nil {
                timing.firstHTTPSend = now
                if let ready = timing.tlsReady {
                    recordSpan("tlsCallbackToFirstHTTPSend", from: ready, to: now, provider: timing.providerOrdinal)
                }
            }
            timing.lastHTTPSend = now; timing.awaitingHTTPBytes = true; timing.queries += 1
            timing.applicationBytes += data.count
            timings[token] = timing
        }
        return now
    }

    func identityRawWriteOffered(_ data: Data, token: UUID) -> Int {
        lock.lock(); defer { lock.unlock() }
        guard var timing = timings[token], timing.identityPort != nil else { return 0 }
        let count = min(43 - timing.identityPrefix.count, data.count)
        if count > 0 {
            timing.identityPrefix.append(contentsOf: data.prefix(count)); timing.identityPrefixWrites += 1
            timings[token] = timing
        }
        return count
    }
    func identityRawWriteCompleted(token: UUID, prefixBytes: Int, error: Error?, at now: UInt64) {
        guard prefixBytes > 0 else { return }
        let metadata = error.map { ErrorMetadata($0) }
        lock.lock(); defer { lock.unlock() }
        timings[token]?.identityPrefixCallbacks += 1
        if timings[token]?.firstPrefixCallback == nil { timings[token]?.firstPrefixCallback = now }
        timings[token]?.lastPrefixCallback = now
        if error == nil { timings[token]?.identityPrefixWrittenBytes += prefixBytes }
        else {
            timings[token]?.identityPrefixWriteFailures += 1
            if timings[token]?.prefixWriteError == nil { timings[token]?.prefixWriteError = metadata }
        }
    }
    func identityRawTerminal(token: UUID, eof: Bool, error: Error?, at now: UInt64) {
        guard eof || error != nil else { return }
        let metadata = error.map { ErrorMetadata($0) }
        lock.lock(); defer { lock.unlock() }
        if timings[token]?.firstRawTerminal == nil {
            timings[token]?.firstRawTerminal = now; timings[token]?.rawTerminalError = metadata
        }
    }
    func identityRawCancelled(token: UUID, at now: UInt64) {
        lock.lock(); defer { lock.unlock() }
        timings[token]?.rawCancelCount += 1
        if timings[token]?.firstRawCancel == nil { timings[token]?.firstRawCancel = now }
    }
    func identityProof() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        func milliseconds(_ value: UInt64?) -> Any {
            guard let value else { return NSNull() }
            return NetworkPerformanceDiagnostics.elapsedMilliseconds(since: timingOrigin, at: value)
        }
        func error(_ metadata: ErrorMetadata?) -> Any {
            guard let metadata else { return NSNull() }
            var fields = metadata.fields
            fields["actualNWErrorTLS"] = metadata.networkKind == "tls"
            return fields
        }
        func optional(_ value: Any?) -> Any { value ?? NSNull() }
        func trust(_ receipts: IdentityTrustReceipts, token: UUID) -> [String: Any] {
            ["ownerToken": token.uuidString, "startCount": receipts.startCount,
             "returnCount": receipts.returnCount, "callbackCount": receipts.callbackCount,
             "startedAt": milliseconds(receipts.started), "returnedAt": milliseconds(receipts.returned),
             "callbackAt": milliseconds(receipts.callback), "returnStatus": optional(receipts.returnStatus),
             "trusted": optional(receipts.trusted), "hasError": optional(receipts.hasError),
             "errorIsCFError": optional(receipts.errorIsCFError), "errorDomain": optional(receipts.errorDomain),
             "errorCode": optional(receipts.errorCode), "certificateCount": optional(receipts.certificateCount),
             "leafSHA256": optional(receipts.leafSHA256), "evaluatedAnchorSHA256": optional(receipts.evaluatedAnchorSHA256),
             "fixtureAnchorSHA256": optional(receipts.fixtureAnchorSHA256)]
        }
        let records = timings.sorted { $0.value.ordinal < $1.value.ordinal }.map { token, timing -> [String: Any] in
            ["token": token.uuidString, "ordinal": timing.ordinal, "provider": timing.providerOrdinal,
             "port": timing.identityPort.map(Int.init) ?? 0, "clientHelloPrefixHex": timing.identityPrefix.map { String(format: "%02x", $0) }.joined(),
             "clientHelloPrefixBytes": timing.identityPrefix.count, "prefixWrites": timing.identityPrefixWrites,
             "prefixCallbacks": timing.identityPrefixCallbacks, "prefixWrittenBytes": timing.identityPrefixWrittenBytes,
             "prefixWriteFailures": timing.identityPrefixWriteFailures, "rawReadyAt": milliseconds(timing.rawReady),
             "firstPrefixCallbackAt": milliseconds(timing.firstPrefixCallback), "lastPrefixCallbackAt": milliseconds(timing.lastPrefixCallback),
             "prefixWriteError": error(timing.prefixWriteError),
             "nativeTLSStartedAt": milliseconds(timing.nativeTLSStarted), "rawCancelAt": milliseconds(timing.firstRawCancel),
             "rawCancelCount": timing.rawCancelCount, "ownCancelAt": milliseconds(timing.firstExplicitCancel),
             "rawTerminalAt": milliseconds(timing.firstRawTerminal), "rawTerminalError": error(timing.rawTerminalError),
             "certificateObserverAt": milliseconds(timing.firstCertificateObserver), "certificateError": error(timing.certificateObserverError),
             "firstObserverAt": milliseconds(timing.firstFailureObserverIngress), "firstObserverError": error(timing.firstFailureObserverError),
             "lastObserverAt": milliseconds(timing.lastFailureObserverIngress), "lastObserverError": error(timing.lastFailureObserverError),
             "firstUnknownObserverAt": milliseconds(timing.firstUnknownObserver), "observerCount": timing.failureObserverCount,
             "nativeResultAt": milliseconds(timing.nativeResultIngress), "nativeResult": timing.nativeResultKind ?? "missing",
             "nativeResultCount": timing.nativeResultCount, "nativeError": error(timing.nativeResultError),
             "handoffAt": milliseconds(timing.tlsReady ?? timing.tlsFailure), "httpSends": timing.queries,
             "applicationBytes": timing.applicationBytes, "trustEvaluation": trust(timing.identityTrust, token: token)]
        }
        return ["formatVersion": 1, "fixtureOnly": true, "binding": "passive existing TLS ClientHello.random",
            "recordLimit": 128, "prefixBytesLimit": 43, "rawReady": started.count, "tlsReady": ready.count,
            "tlsFailures": failures, "pendingCallbacks": started.count - completed.count,
            "droppedRecords": droppedCarrierTimings, "invalidObservations": invalid,
            "nativeWriteFailures": nativeWriteFailures, "records": records]
    }
    /// Complete old-epoch evidence, not a sampled diagnostic. Compact fixed
    /// columns keep all <=65 admitted old carriers inside a private 16KiB
    /// artifact. Any missing record, unbound prelude or denied cancel fails
    /// the parent's independent peer/EOF oracle rather than becoming a PASS.
    func carrierProof() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        func value(_ optional: Any?) -> Any { optional ?? NSNull() }
        func milliseconds(_ time: UInt64?) -> Any {
            guard let time else { return NSNull() }
            return NetworkPerformanceDiagnostics.elapsedMilliseconds(since: timingOrigin, at: time)
        }
        let records = timings.sorted { $0.value.ordinal < $1.value.ordinal }.map { token, timing -> [Any] in
            [token.uuidString, timing.ordinal, timing.providerOrdinal,
             milliseconds(timing.preludeACK), milliseconds(timing.nativeTLSStarted),
             milliseconds(timing.firstExplicitCancel), milliseconds(timing.nativeResultIngress),
             milliseconds(timing.tlsReady ?? timing.tlsFailure), value(timing.nativeResultKind),
             value(timing.nativeResultError?.nativeCase), value(timing.nativeResultError?.nsDomain),
             value(timing.nativeResultError?.nsCode), value(timing.nativeResultError?.classification), timing.queries,
             milliseconds(timing.firstObserverDeny), timing.observerAuthenticationCount,
             timing.preludeFailure != nil, typedCancelledTokens.contains(token)]
        }
        let diagnosticCandidates = timings.filter({ $0.value.preludeFailure != nil }).sorted(by: { $0.value.ordinal < $1.value.ordinal })
        var diagnostics = diagnosticCandidates.prefix(16).map({ token, timing in preludeDiagnostic(timing, token: token) })
        var result: [String: Any] = ["formatVersion": 1, "fixtureOnly": true, "extraProtocol": "loopback-only nonce binding + raw ACK before genuine TLS",
            "columns": ["nonce", "ordinal", "provider", "bindingACK", "nativeTLSStarted", "explicitCancel", "nativeResultAt",
                        "handoffAt", "nativeResult", "nativeCase", "NSErrorDomain", "NSErrorCode", "classification",
                        "httpQueries", "firstObserverDeny", "observerAuthenticationCount", "preludeFailure", "boundTypedAbort"],
            "recordLimit": 128, "rawReady": started.count, "tlsReady": ready.count,
            "typedTLSCancelled": typedCancelledTokens.count, "tlsFailures": failures,
            "preludeFailures": preludeFailedTokens.count, "records": records,
            "preludeDiagnostics": diagnostics, "preludeDiagnosticsTotal": diagnosticCandidates.count,
            "preludeDiagnosticsOmitted": diagnosticCandidates.count - diagnostics.count]
        // Additional observations cannot displace any complete fixed-column
        // owner/result record. If those records alone exceed the original
        // ceiling, the caller's existing hard failure remains unchanged.
        while let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]),
              data.count > 16_384, !diagnostics.isEmpty {
            diagnostics.removeLast(); result["preludeDiagnostics"] = diagnostics
            result["preludeDiagnosticsOmitted"] = diagnosticCandidates.count - diagnostics.count
        }
        return result
    }
    // Caller holds lock. Code-branch tags and raw callback metadata are only
    // evidence; eligibility, guards, oracle and native results are unchanged.
    private func preludeDiagnostic(_ timing: CarrierTiming, token: UUID? = nil) -> [String: Any] {
        var result: [String: Any] = ["carrierOrdinal": timing.ordinal, "providerOrdinal": timing.providerOrdinal,
            "rawReadCallbackBytes": timing.rawReadBytes, "rawReadEOF": timing.rawReadEOF,
            "observedACKBytes": timing.observedACKBytes, "observedACKPrefixMatches": timing.observedACKPrefix,
            "observedACKComplete": timing.observedACKComplete, "observerAuthenticationCount": timing.observerAuthenticationCount]
        if let token { result["nonce"] = token.uuidString }
        if let branch = timing.preludeBranch { result["terminalCodeBranchForensicsOnly"] = branch }
        for (name, time) in [("rawReadyMilliseconds", Optional(timing.rawReady)), ("preludeStartedMilliseconds", timing.preludeStarted),
            ("rawWriteCallbackIngressMilliseconds", timing.rawWriteCallback), ("rawReadCallbackIngressMilliseconds", timing.rawReadCallback),
            ("bindingACKMilliseconds", timing.preludeACK), ("nativeTLSStartedMilliseconds", timing.nativeTLSStarted),
            ("callerCancellationMilliseconds", timing.firstExplicitCancel), ("firstObserverDenyMilliseconds", timing.firstObserverDeny),
            ("preTLSFailureMilliseconds", timing.preludeFailure)] {
            if let time { result[name] = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: timingOrigin, at: time) }
        }
        if let error = timing.preludeError { result["preTLSFailureError"] = error.fields }
        for (key, error) in [("rawWriteError", timing.rawWriteError), ("rawReadError", timing.rawReadError)] {
            if let error {
                if error == timing.preludeError { result[key + "MatchesPreludeMetadata"] = true }
                else { result[key] = error.fields }
            }
        }
        return result
    }
    func writeCompleted(token: UUID, sent: UInt64, error: Error?, at now: UInt64) {
        lock.lock(); defer { lock.unlock() }
        nativeWriteCallbacks += 1
        if error != nil { nativeWriteFailures += 1 }
        if var timing = timings[token] {
            if timing.firstNativeWriteCallback == nil { timing.firstNativeWriteCallback = now }
            recordSpan("httpSendToNativeWriteCallback", from: sent, to: now, provider: timing.providerOrdinal)
            timings[token] = timing
        }
    }
    func received(_ data: Data?, token: UUID, at now: UInt64) {
        guard data?.isEmpty == false else { return }
        lock.lock(); defer { lock.unlock() }
        guard var timing = timings[token], let sent = timing.lastHTTPSend, timing.awaitingHTTPBytes else { return }
        // The preflight ACK has no HTTP send, so cannot become an application
        // first-byte measurement. Nothing about these bytes asserts validity.
        timing.awaitingHTTPBytes = false
        if timing.firstHTTPBytes == nil { timing.firstHTTPBytes = now }
        recordSpan("httpSendToFirstBytes", from: sent, to: now, provider: timing.providerOrdinal)
        timings[token] = timing
    }
    // Caller holds lock. Names and ordinals are fixed fixture metadata only.
    private func recordSpan(_ name: String, from started: UInt64, to now: UInt64, provider: Int) {
        let milliseconds = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started, at: now)
        spans[name, default: SpanWindow()].record(milliseconds)
        spans["\(name)Provider\(provider)", default: SpanWindow()].record(milliseconds)
    }
    // Caller holds lock. There are never more than 128 retained carrier
    // records, two observer error values per record, or 16 emitted failure
    // rows. Actual native/handoff failures take priority over observer-only
    // rows; later errors on an already handed-off stream remain visible as
    // such, not automatically relabelled as pending-handshake failures.
    private func tlsLifecycleSnapshot() -> [String: Any] {
        let ordered = timings.values.sorted { $0.ordinal < $1.ordinal }
        let failureRecords = ordered.filter {
            $0.preludeFailure != nil || $0.nativeResultKind == "failure" || $0.tlsFailure != nil || $0.failureObserverCount > 0
        }.sorted {
            if ($0.preludeFailure != nil) != ($1.preludeFailure != nil) { return $0.preludeFailure != nil }
            let first = $0.nativeResultKind == "failure" || $0.tlsFailure != nil
            let second = $1.nativeResultKind == "failure" || $1.tlsFailure != nil
            return first != second ? first : $0.ordinal < $1.ordinal
        }
        func row(_ timing: CarrierTiming) -> [String: Any] {
            if timing.preludeFailure != nil { return preludeDiagnostic(timing) }
            var result: [String: Any] = ["carrierOrdinal": timing.ordinal, "providerOrdinal": timing.providerOrdinal,
                "nativeResultCount": timing.nativeResultCount, "failureObserverCount": timing.failureObserverCount,
                "explicitCancelCount": timing.explicitCancelCount]
            for (name, time) in [("rawReadyMilliseconds", Optional(timing.rawReady)),
                ("nativeCompletionIngressMilliseconds", timing.nativeResultIngress),
                ("bindingACKMilliseconds", timing.preludeACK), ("nativeTLSStartedMilliseconds", timing.nativeTLSStarted),
                ("preTLSFailureMilliseconds", timing.preludeFailure),
                ("firstFailureObserverIngressMilliseconds", timing.firstFailureObserverIngress),
                ("lastFailureObserverIngressMilliseconds", timing.lastFailureObserverIngress),
                ("explicitCancelBeforeNativeCallMilliseconds", timing.firstExplicitCancel),
                ("finalHandoffMilliseconds", timing.tlsReady ?? timing.tlsFailure)] {
                if let time { result[name] = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: timingOrigin, at: time) }
            }
            if let kind = timing.nativeResultKind { result["nativeResult"] = kind }
            if timing.tlsReady != nil { result["finalHandoffResult"] = "success" }
            else if timing.tlsFailure != nil { result["finalHandoffResult"] = "failure" }
            if let present = timing.nativeResultPresentAtCancel { result["nativeResultPresentAtCancel"] = present }
            if let error = timing.nativeResultError { result["nativeResultError"] = error.fields }
            if let error = timing.preludeError { result["preTLSFailureError"] = error.fields }
            if let error = timing.firstFailureObserverError { result["firstFailureObserverError"] = error.fields }
            if let error = timing.lastFailureObserverError {
                if error == timing.firstFailureObserverError { result["lastFailureObserverErrorMatchesFirst"] = true }
                else { result["lastFailureObserverError"] = error.fields }
            }
            return result
        }
        var failures = Array(failureRecords.prefix(16)).map(row)
        let failureOrdinals = Set(failureRecords.map(\.ordinal))
        let ordinary = ordered.filter { !failureOrdinals.contains($0.ordinal) }
        var carriers = Array(ordinary.prefix(8)).map(row)
        var result: [String: Any] = ["fixtureOnly": true, "carrierRecordLimit": 128, "failureRowsLimit": 16,
            "ordinaryRowsLimit": 8, "serializedBytesLimit": 5_120, "trackedCarrierRecords": timings.count,
            "failureCarrierRecords": failureRecords.count,
            "boundary": "real factory caller-queue completion before optional fixture delay; observer ingress and explicit cancel calls, not native readiness or TCP close ACKs"]
        // The existing whole timing marker still has its separate 16 KiB
        // ceiling. Keep this additional forensic block at most 5 KiB and
        // report every row omitted for either the row or byte boundary.
        while true {
            result["failureRows"] = failures; result["ordinaryRows"] = carriers
            result["omittedFailureRows"] = failureRecords.count - failures.count
            result["omittedOrdinaryRows"] = ordinary.count - carriers.count
            if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), data.count <= 5_120 {
                return result
            }
            if !carriers.isEmpty { carriers.removeLast() }
            else if !failures.isEmpty { failures.removeLast() }
            else {
                return ["fixtureOnly": true, "observationError": "bounded-tls-lifecycle-serialization-failed"]
            }
        }
    }
    func timingSnapshot() -> [String: Any] {
        let now = NetworkPerformanceDiagnostics.now()
        lock.lock(); defer { lock.unlock() }
        let pending = timings.values.filter { $0.tlsReady == nil && $0.tlsFailure == nil }
        let pendingAge = pending.map { NetworkPerformanceDiagnostics.elapsedMilliseconds(since: $0.rawReady, at: now) }.max()
        let rows = timings.values.sorted { $0.ordinal < $1.ordinal }.prefix(8).map { timing -> [String: Any] in
            var row: [String: Any] = ["carrierOrdinal": timing.ordinal, "providerOrdinal": timing.providerOrdinal,
                "rawReadyMilliseconds": NetworkPerformanceDiagnostics.elapsedMilliseconds(since: timingOrigin, at: timing.rawReady),
                "httpQueries": timing.queries]
            for (name, timestamp) in [("tlsCallbackMilliseconds", timing.tlsReady), ("tlsFailureMilliseconds", timing.tlsFailure),
                ("firstHTTPSendMilliseconds", timing.firstHTTPSend), ("firstNativeWriteCallbackMilliseconds", timing.firstNativeWriteCallback),
                ("firstHTTPBytesMilliseconds", timing.firstHTTPBytes)] {
                if let timestamp {
                    row[name] = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: timingOrigin, at: timestamp)
                }
            }
            return row
        }
        var result: [String: Any] = ["rawReady": started.count, "tlsCallbacksReady": ready.count,
            "tlsFailures": failures, "pendingTLSCallbacks": started.count - completed.count,
            "typedTLSCancelled": typedCancelledTokens.count, "preludeFailures": preludeFailedTokens.count,
            "httpQueries": wireQueries, "nativeWriteCallbacks": nativeWriteCallbacks,
            "nativeWriteFailures": nativeWriteFailures, "invalidObservations": invalid,
            "cancelRequests": cancelledTokens.count, "terminalReadCallbacks": terminalReads.count,
            "delayedTLSCallbacks": delayedTLSCallbacks, "lateCancelledTLSCallbacks": lateCancelledTLSCallbacks,
            "trackedCarrierTimings": timings.count, "droppedCarrierTimings": droppedCarrierTimings,
            "carrierTimingLimit": 128, "spanSampleLimit": 128, "carrierRowsLimit": 8,
            "boundary": "routed raw/CONNECT ready to nested TLS callback; send/receive API callbacks, not TCP close ACKs",
            "spans": spans.mapValues(\.summary), "carriers": rows, "tlsLifecycle": tlsLifecycleSnapshot()]
        if let pendingAge { result["oldestTrackedTLSCallbackPendingMilliseconds"] = pendingAge }
        return result
    }
    func invalidRead() { lock.lock(); invalid += 1; lock.unlock() }
    func cancelled(_ token: UUID) {
        lock.lock(); cancelledTokens.insert(token); lock.unlock()
    }
    func terminalRead(_ token: UUID) {
        lock.lock(); terminalReads.insert(token); lock.unlock()
    }
    func delayedTLSCallback(cancelledAt: TimeInterval?) {
        lock.lock(); delayedTLSCallbacks += 1
        if let cancelledAt, ProcessInfo.processInfo.systemUptime - cancelledAt >= 0.1 {
            lateCancelledTLSCallbacks += 1
        }
        lock.unlock()
    }
    var snapshot: Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(rawReady: started.count, tlsReady: ready.count, tlsFailed: failures,
            wireQueries: wireQueries, tlsCancelled: typedCancelledTokens.count, preludeFailures: preludeFailedTokens.count,
            cancelRequests: cancelledTokens.count, terminalReads: terminalReads.count, invalid: invalid,
            pendingTLSCallbacks: started.count - completed.count, delayedTLSCallbacks: delayedTLSCallbacks,
            lateCancelledTLSCallbacks: lateCancelledTLSCallbacks)
    }
}

/// Identity CLI only. Forward each original operation once and unchanged;
/// retain at most the first 43 existing TLS ciphertext bytes per carrier.
private final class DNSFixtureIdentityRawStream: NativeOutboundByteStream {
    private let source: any NativeOutboundByteStream, probe: DNSFixturePhysicalProbe, token: UUID
    init(_ source: any NativeOutboundByteStream, probe: DNSFixturePhysicalProbe, token: UUID) {
        self.source = source; self.probe = probe; self.token = token
    }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        let prefixBytes = probe.identityRawWriteOffered(data, token: token)
        source.send(data) { error in
            let entered = NetworkPerformanceDiagnostics.now()
            completion(error)
            self.probe.identityRawWriteCompleted(token: self.token, prefixBytes: prefixBytes, error: error, at: entered)
        }
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        source.receive(maximum: maximum) { data, eof, error in
            let entered = NetworkPerformanceDiagnostics.now()
            completion(data, eof, error)
            self.probe.identityRawTerminal(token: self.token, eof: eof, error: error, at: entered)
        }
    }
    func cancel() {
        let entered = NetworkPerformanceDiagnostics.now()
        probe.identityRawCancelled(token: token, at: entered)
        source.cancel()
    }
}

private final class DNSFixtureObservedTLSStream: NativeOutboundByteStream {
    private let source: any NativeOutboundByteStream
    private let probe: DNSFixturePhysicalProbe, token: UUID
    private let lock = NSLock()
    private var cancelled = false, reading = false
    init(_ source: any NativeOutboundByteStream, probe: DNSFixturePhysicalProbe, token: UUID) {
        self.source = source; self.probe = probe; self.token = token
    }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        let sent = probe.sent(data, token: token)
        source.send(data) { error in
            self.probe.writeCompleted(token: self.token, sent: sent, error: error, at: NetworkPerformanceDiagnostics.now())
            completion(error)
        }
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        lock.lock(); let overlap = reading; reading = true; lock.unlock()
        if overlap { probe.invalidRead() }
        source.receive(maximum: maximum) { data, eof, error in
            let arrived = NetworkPerformanceDiagnostics.now()
            self.lock.lock(); self.reading = false; self.lock.unlock()
            self.probe.received(data, token: self.token, at: arrived)
            if eof || error != nil { self.probe.terminalRead(self.token) }
            completion(data, eof, error)
        }
    }
    func cancel() {
        lock.lock(); let first = !cancelled; cancelled = true; lock.unlock()
        if first { probe.cancelled(token); source.cancel() }
    }
    deinit { cancel() }
}

private final class DNSFixtureCapacityProbe {
    struct Snapshot {
        let activePeak: Int, queuedPeak: Int, waitingPeak: Int
    }
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "app.hajimi.dns.source-scope-capacity", qos: .userInitiated)
    private var timer: DispatchSourceTimer?
    private var activePeak = 0, queuedPeak = 0, waitingPeak = 0
    init(_ read: @escaping () -> DNSQueryCoordinator.Statistics) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        self.timer = timer
        timer.setEventHandler { [weak self] in self?.observe(read()) }
        timer.schedule(deadline: .now(), repeating: .milliseconds(2)); timer.resume()
    }
    func observe(_ state: DNSQueryCoordinator.Statistics) {
        lock.lock(); activePeak = max(activePeak, state.activeUpstreams)
        queuedPeak = max(queuedPeak, state.queuedUpstreams); waitingPeak = max(waitingPeak, state.waitingClients)
        lock.unlock()
    }
    var snapshot: Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(activePeak: activePeak, queuedPeak: queuedPeak, waitingPeak: waitingPeak)
    }
    func stop() {
        let timer = self.timer; self.timer = nil
        timer?.setEventHandler {}; timer?.cancel(); queue.sync {}
    }
    deinit { stop() }
}

private final class DNSFixtureScopeReplies {
    private struct Expected {
        let query: Data, owner: UUID, code: UInt8, cached: Bool, started: TimeInterval
    }
    struct Snapshot {
        let completed: Int, maximumSuccessfulSeconds: TimeInterval
    }
    private let lock = NSLock(), done = DispatchGroup()
    private var expected: [UInt16: Expected] = [:]
    private var completed = Set<UInt16>()
    private var failure: Error?
    private var maximumSuccessfulSeconds: TimeInterval = 0
    private let approvedAddresses: Set<String>
    private var addresses: [UInt16: String] = [:]
    init(approvedAddresses: Set<String> = ["203.0.113.80"]) { self.approvedAddresses = approvedAddresses }
    private func identifier(_ data: Data) -> UInt16 {
        UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1])
    }
    func register(_ query: Data, owner: UUID, code: UInt8, cached: Bool) throws {
        let id = identifier(query)
        lock.lock(); defer { lock.unlock() }
        guard expected[id] == nil else { throw DNSFixtureScopeError(text: "Source fixture reused a transaction ID") }
        expected[id] = Expected(query: query, owner: owner, code: code, cached: cached,
                                started: ProcessInfo.processInfo.systemUptime)
        done.enter()
    }
    func receive(_ response: Data, owner: UUID) {
        lock.lock()
        guard response.count >= 12, let item = expected[identifier(response)], item.owner == owner,
              completed.insert(identifier(response)).inserted else {
            failure = failure ?? DNSFixtureScopeError(text: "Source reply duplicated/lost client ID, question or flow ownership")
            lock.unlock(); return
        }
        let elapsed = ProcessInfo.processInfo.systemUptime - item.started
        let addresses = DNSMessageInspection.addressAnswers(in: response)
        if !DNSMessageInspection.responseMatchesQuery(response, query: item.query)
            || response[response.startIndex + 3] & 15 != item.code {
            failure = failure ?? DNSFixtureScopeError(text: "Source reply failed policy/RCODE/ID validation")
        } else if item.code == 0 {
            if addresses.count != 1 || !approvedAddresses.contains(addresses.first?.address ?? "")
                || addresses.contains(where: { $0.ttl == 0 || $0.ttl > 120 || (!item.cached && $0.ttl != 120) }) {
                failure = failure ?? DNSFixtureScopeError(text: "Source reply changed its authenticated address or wire/cache TTL")
            }
            if elapsed >= 8 {
                failure = failure ?? DNSFixtureScopeError(text: "Source successful query exceeded its original eight-second budget")
            }
            maximumSuccessfulSeconds = max(maximumSuccessfulSeconds, elapsed)
            self.addresses[identifier(response)] = addresses.first?.address
        }
        lock.unlock(); done.leave()
    }
    func fail(_ error: Error) { lock.lock(); failure = failure ?? error; lock.unlock() }
    func wait(_ label: String) throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 12
        while done.wait(timeout: .now() + .milliseconds(20)) != .success {
            lock.lock(); let error = failure; lock.unlock()
            if let error { throw error }
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                throw DNSFixtureScopeError(text: "Source-scope observation wait expired: \(label); query deadlines remain 8s")
            }
        }
        try validate()
    }
    func validate() throws {
        lock.lock(); let error = failure, full = completed.count == expected.count; lock.unlock()
        if let error { throw error }
        guard full else { throw DNSFixtureScopeError(text: "Source-scope phase did not finish every owned transaction") }
    }
    var snapshot: Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(completed: completed.count, maximumSuccessfulSeconds: maximumSuccessfulSeconds)
    }
    func address(for id: UInt16) -> String? { lock.lock(); defer { lock.unlock() }; return addresses[id] }
    var addressLedger: [[Any]] {
        lock.lock(); defer { lock.unlock() }
        return addresses.keys.sorted().map { [$0, addresses[$0]!] }
    }
}

private final class DNSFixtureTLSAttempt {
    private var connection: NWConnection?
    private var completion: ((Result<any NativeOutboundByteStream, Error>) -> Void)?
    init(connection: NWConnection, completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        self.connection = connection; self.completion = completion
    }
    func finish(_ result: Result<any NativeOutboundByteStream, Error>, cancel: Bool = false) {
        guard let callback = completion else { return }
        completion = nil; let value = connection; connection = nil
        value?.stateUpdateHandler = nil
        if cancel { value?.cancel() }
        callback(result)
    }
}

private final class DNSFixtureTLSStream: NativeOutboundByteStream {
    private let connection: NWConnection
    init(_ connection: NWConnection) { self.connection = connection }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed(completion))
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) {
            data, _, complete, error in completion(data, complete, error)
        }
    }
    func cancel() { connection.cancel() }
}

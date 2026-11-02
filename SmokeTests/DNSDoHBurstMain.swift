import Foundation
import Darwin
import Network
import Security
#if HAJIMI_LEGACY_TESTING_CORE
@testable import HajimiCore
#else
import HajimiCore
#endif

/// Standalone, prebuilt-Core pressure test. Its only destinations are one
/// admitted literal 127.0.0.1 TLS port and optionally one loopback proxy port.
/// The temporary anchor is scoped to this explicitly flagged process only.
@main
enum DNSDoHBurstMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }

    /// An explicit fixture setup check, not a DNS query or a relaxed timeout.
    /// macOS trust services may cold-start for this isolated temporary HOME.
    /// Authenticate the very same private anchor/IP-SAN policy once, report its
    /// timing, and close it before starting any concurrent, unique DNS queries.
    private final class TLSPreflight {
        private let lock = NSLock()
        private var finished = false, success = false
        private var elapsed = 0.0, failure = ""
        func complete(_ value: Result<any NativeOutboundByteStream, Error>, started: UInt64) {
            let duration = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started)
            let authenticated: Bool, message: String
            switch value {
            case .success(let stream):
                stream.cancel(); authenticated = true; message = ""
            case .failure(let error):
                authenticated = false; message = String(error.localizedDescription.prefix(256))
            }
            lock.lock(); defer { lock.unlock() }
            guard !finished else { return }
            finished = true; success = authenticated; elapsed = duration; failure = message
        }
        var snapshot: (finished: Bool, success: Bool, elapsed: Double, failure: String) {
            lock.lock(); defer { lock.unlock() }
            return (finished, success, elapsed, failure)
        }
    }

    private final class Probe {
        private let lock = NSLock()
        private let origin = NetworkPerformanceDiagnostics.now()
        private var dials = 0, dialResults = 0, dialFailures = 0, active = 0, maximumActive = 0
        private var sentBytes = 0, receivedBytes = 0, sends = 0, reads = 0, readErrors = 0, overlaps = 0
        private var completed: [Int: (success: Bool, elapsed: Double)] = [:]
        private var peakFD = 0
        private var errors: [String: Int] = [:]
        private var rawPending = 0, rawPeak = 0, rawReady = 0, rawFailed = 0
        private var rawSends = 0, rawSendResults = 0, rawSendErrors = 0, rawReadResults = 0
        private var rawSentBytes = 0, rawReceivedBytes = 0
        private var stages: [Int: [String: Double]] = [:]
        private var heartbeat: DispatchSourceTimer?
        private var heartbeatQueue = "", heartbeatLast: UInt64 = 0
        private var heartbeatGaps: [Double] = []
        func rawStart() { lock.lock(); rawPending += 1; rawPeak = max(rawPeak, rawPending); lock.unlock() }
        func rawReadyResult(_ success: Bool) {
            lock.lock(); rawPending -= 1
            if success { rawReady += 1 } else { rawFailed += 1 }; lock.unlock()
        }
        func rawSent(_ bytes: Int) { lock.lock(); rawSends += 1; rawSentBytes += bytes; lock.unlock() }
        func rawSendResult(_ failed: Bool) {
            lock.lock(); rawSendResults += 1; if failed { rawSendErrors += 1 }; lock.unlock()
        }
        func rawReadResult(_ bytes: Int) { lock.lock(); rawReadResults += 1; rawReceivedBytes += bytes; lock.unlock() }
        func descriptorCount(_ count: Int) { lock.lock(); peakFD = max(peakFD, count); lock.unlock() }
        func dial() -> Int { lock.lock(); defer { lock.unlock() }; dials += 1; return dials }
        func stage(_ name: String, dial: Int) {
            let elapsed = NetworkPerformanceDiagnostics.elapsedMilliseconds(since: origin)
            lock.lock(); defer { lock.unlock() }
            if stages[dial]?[name] == nil { stages[dial, default: [:]][name] = elapsed }
        }
        func observeResolverQueue(_ queue: DispatchQueue) {
            lock.lock(); defer { lock.unlock() }
            guard heartbeat == nil else { return }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            heartbeat = timer; heartbeatQueue = queue.label; heartbeatLast = NetworkPerformanceDiagnostics.now()
            timer.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
            timer.setEventHandler { [weak self] in self?.heartbeatPulse() }; timer.resume()
        }
        private func heartbeatPulse() {
            let stamp = NetworkPerformanceDiagnostics.now()
            lock.lock(); defer { lock.unlock() }
            guard heartbeat != nil else { return }
            if heartbeatGaps.count < 2_048 {
                heartbeatGaps.append(NetworkPerformanceDiagnostics.elapsedMilliseconds(since: heartbeatLast))
            }
            heartbeatLast = stamp
        }
        func stopHeartbeat() {
            lock.lock(); let timer = heartbeat; heartbeat = nil; lock.unlock()
            timer?.setEventHandler {}; timer?.cancel()
        }
        var stageJSON: (summary: String, trace: String) {
            lock.lock(); let recorded = stages, gaps = heartbeatGaps.sorted(), sampledQueue = heartbeatQueue; lock.unlock()
            var counts: [String: Int] = [:], timing: [String: [String: Double]] = [:]
            for row in recorded.values { for name in row.keys { counts[name, default: 0] += 1 } }
            let spans = [("dial-to-verify", "dial", "verify-start"),
                         ("verify-configuration", "verify-start", "verify-configured"),
                         ("verify-call-return", "verify-configured", "verify-call-returned"),
                         ("trust-evaluation", "verify-configured", "verify-trusted"),
                         ("trust-to-NW-ready", "verify-trusted", "NW-ready"),
                         ("dial-to-ready", "dial", "TLS-ready"),
                         ("ready-to-send", "TLS-ready", "first-send"),
                         ("send-ack", "first-send", "first-send-completed"),
                         ("send-to-first-byte", "first-send", "first-byte")]
            for (name, begin, end) in spans {
                let values = recorded.values.compactMap { row -> Double? in
                    guard let begin = row[begin], let end = row[end] else { return nil }; return end - begin
                }.sorted()
                guard !values.isEmpty else { continue }
                timing[name] = ["count": Double(values.count), "minimumMs": values[0],
                    "p50Ms": values[(values.count - 1) / 2],
                    "p95Ms": values[min(values.count - 1, Int(ceil(Double(values.count) * 0.95)) - 1)],
                    "maximumMs": values[values.count - 1]]
            }
            func json(_ object: Any) -> String {
                guard JSONSerialization.isValidJSONObject(object),
                      let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
                      let text = String(data: data, encoding: .utf8) else { return "{\"fixtureSerializationError\":true}" }; return text
            }
            let trace = Dictionary(uniqueKeysWithValues: recorded.map { (String($0.key), $0.value) })
            // Unwrap before entering an Any-typed dictionary. Otherwise Swift
            // can promote Optional<Double> to Any before evaluating `??`.
            let largestGap: Double = gaps.last ?? 0
            let p95Gap: Double = gaps.isEmpty ? 0 : gaps[min(gaps.count - 1, Int(ceil(Double(gaps.count) * 0.95)) - 1)]
            let pulses: [String: Any] = ["queue": sampledQueue, "pulses": gaps.count,
                "largestGapMs": largestGap, "largestLagAbove100ms": max(0, largestGap - 100), "p95GapMs": p95Gap]
            let summary: [String: Any] = ["counts": counts, "timing": timing, "queueHeartbeat": pulses]
            return (json(summary), json(trace))
        }
        func dialResult(_ result: Result<any NativeOutboundByteStream, Error>) {
            lock.lock(); dialResults += 1
            if case .failure(let error) = result {
                dialFailures += 1
                let native = error as NSError
                errors["\(native.domain):\(native.code):\(String(error.localizedDescription.prefix(160)))", default: 0] += 1
            }
            lock.unlock()
        }
        func opened() { lock.lock(); active += 1; maximumActive = max(maximumActive, active); lock.unlock() }
        func closed() { lock.lock(); active -= 1; lock.unlock() }
        func sent(_ bytes: Int) { lock.lock(); sends += 1; sentBytes += bytes; lock.unlock() }
        func read(_ bytes: Int, error: Bool, overlap: Bool) {
            lock.lock(); reads += 1; receivedBytes += bytes
            if error { readErrors += 1 }; if overlap { overlaps += 1 }; lock.unlock()
        }
        func result(_ index: Int, success: Bool, started: UInt64) {
            lock.lock()
            if completed[index] != nil { overlaps += 1 }
            completed[index] = (success, NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started))
            lock.unlock()
        }
        var snapshot: (count: Int, failed: Int, p50: Double, p95: Double, dials: Int,
                       dialResults: Int, dialFailures: Int, active: Int, maximumActive: Int,
                       sends: Int, reads: Int, readErrors: Int, overlaps: Int, sentBytes: Int, receivedBytes: Int,
                       lateSuccessfulReplies: Int, maximumSuccessfulElapsed: Double) {
            lock.lock(); defer { lock.unlock() }
            let values = completed.values.map(\.elapsed).sorted()
            func percentile(_ q: Double) -> Double {
                guard !values.isEmpty else { return 0 }
                return values[min(values.count - 1, Int(ceil(Double(values.count) * q)) - 1)]
            }
            return (completed.count, completed.values.filter { !$0.success }.count, percentile(0.5), percentile(0.95),
                    dials, dialResults, dialFailures, active, maximumActive, sends, reads,
                    readErrors, overlaps, sentBytes, receivedBytes,
                    completed.values.filter { $0.success && $0.elapsed >= 8_000 }.count,
                    completed.values.filter { $0.success }.map(\.elapsed).max() ?? 0)
        }
        var resourceSnapshot: (peakFD: Int, errors: [String: Int], rawPending: Int, rawPeak: Int,
                               rawReady: Int, rawFailed: Int, rawSends: Int, rawSendResults: Int,
                               rawSendErrors: Int, rawReadResults: Int, rawSentBytes: Int, rawReceivedBytes: Int) {
            lock.lock(); defer { lock.unlock() }
            return (peakFD, errors, rawPending, rawPeak, rawReady, rawFailed, rawSends, rawSendResults,
                    rawSendErrors, rawReadResults, rawSentBytes, rawReceivedBytes)
        }
    }

    private final class ObservedRaw: NativeOutboundByteStream {
        private let source: any NativeOutboundByteStream
        private let probe: Probe
        init(_ source: any NativeOutboundByteStream, probe: Probe) { self.source = source; self.probe = probe }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            probe.rawSent(data.count)
            source.send(data) { error in self.probe.rawSendResult(error != nil); completion(error) }
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            source.receive(maximum: maximum) { data, eof, error in
                self.probe.rawReadResult(data?.count ?? 0); completion(data, eof, error)
            }
        }
        func cancel() { source.cancel() }
    }

    private final class ObservedStream: NativeOutboundByteStream {
        private let source: any NativeOutboundByteStream
        private let probe: Probe
        private let dial: Int
        private let lock = NSLock()
        private var cancelled = false, reading = false
        init(_ source: any NativeOutboundByteStream, probe: Probe, dial: Int) {
            self.source = source; self.probe = probe; self.dial = dial; probe.opened()
        }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            probe.stage("first-send", dial: dial); probe.sent(data.count)
            source.send(data) { error in
                self.probe.stage("first-send-completed", dial: self.dial); completion(error)
            }
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock(); let overlap = reading; reading = true; lock.unlock()
            source.receive(maximum: maximum) { data, eof, error in
                self.lock.lock(); self.reading = false; self.lock.unlock()
                if let data, !data.isEmpty { self.probe.stage("first-byte", dial: self.dial) }
                self.probe.read(data?.count ?? 0, error: error != nil, overlap: overlap)
                completion(data, eof, error)
            }
        }
        func cancel() {
            lock.lock(); let first = !cancelled; cancelled = true; lock.unlock()
            if first { probe.stage("stream-cancel-requested", dial: dial); probe.closed(); source.cancel() }
        }
        deinit { cancel() }
    }

    private final class NetworkStream: NativeOutboundByteStream {
        let connection: NWConnection
        init(_ connection: NWConnection) { self.connection = connection }
        func send(_ data: Data, completion: @escaping (Error?) -> Void) {
            connection.send(content: data, completion: .contentProcessed(completion))
        }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { data, _, eof, error in
                completion(data, eof, error)
            }
        }
        func cancel() { connection.cancel() }
    }

    private final class DirectAttempt {
        let connection: NWConnection
        private var callback: ((Result<any NativeOutboundByteStream, Error>) -> Void)?
        init(_ connection: NWConnection, _ callback: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
            self.connection = connection; self.callback = callback
        }
        func finish(_ result: Result<any NativeOutboundByteStream, Error>, cancel: Bool = false) {
            guard let callback else { return }
            self.callback = nil; connection.stateUpdateHandler = nil
            if cancel { connection.cancel() }
            callback(result)
        }
    }

    /// The public router exposes no raw-connect cancellation handle. Keep that
    /// dial alive/budgeted until its actual callback, dispose late raw success,
    /// and cancel only the request-local TLS handshake once it has started.
    private final class RoutedAttempt {
        typealias Value = Result<any NativeOutboundByteStream, Error>
        private let queue: DispatchQueue
        private let connect: (@escaping (Value) -> Void) -> Void
        private let upgrade: (any NativeOutboundByteStream, @escaping (Value) -> Void) -> (() -> Void)
        private var completion: ((Value) -> Void)?
        private var cancellation: (() -> Void)?
        private var cancelled = false
        init(queue: DispatchQueue, connect: @escaping (@escaping (Value) -> Void) -> Void,
             upgrade: @escaping (any NativeOutboundByteStream, @escaping (Value) -> Void) -> (() -> Void),
             completion: @escaping (Value) -> Void) {
            self.queue = DispatchQueue(label: "fixture.burst.routed-tls-owner", target: queue)
            self.connect = connect; self.upgrade = upgrade; self.completion = completion
        }
        func start() {
            queue.async {
                guard self.completion != nil else { return }
                guard !self.cancelled else { self.finish(.failure(Failure(text: "Raw fixture dial cancelled before start"))); return }
                self.connect { value in
                    self.queue.async {
                        guard self.completion != nil, !self.cancelled else {
                            if case .success(let stream) = value { stream.cancel() }
                            self.finish(.failure(Failure(text: "Raw fixture dial cancelled"))); return
                        }
                        switch value {
                        case .failure: self.finish(value)
                        case .success(let stream):
                            self.cancellation = self.upgrade(stream) { value in
                                self.queue.async {
                                    if self.cancelled {
                                        if case .success(let winner) = value { winner.cancel() }
                                        self.finish(.failure(Failure(text: "TLS fixture dial cancelled")))
                                    } else { self.finish(value) }
                                }
                            }
                        }
                    }
                }
            }
        }
        func cancel() {
            queue.async {
                guard self.completion != nil, !self.cancelled else { return }
                self.cancelled = true; self.cancellation?()
            }
        }
        private func finish(_ value: Value) {
            guard let completion else {
                if case .success(let stream) = value { stream.cancel() }; return
            }
            self.completion = nil; cancellation = nil; completion(value)
        }
    }

    private static func require(_ condition: Bool, _ text: String) throws {
        if !condition { throw Failure(text: text) }
    }

    private static func until(_ text: String, seconds: TimeInterval = 12, _ condition: () -> Bool) throws {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while !condition() && ProcessInfo.processInfo.systemUptime < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.005))
        }
        try require(condition(), text)
    }

    private static func makeQuery(index: Int) -> Data {
        let type: UInt16 = [1, 28, 65][index % 3]
        var query = DNSMessageInspection.query(for: "q-\(index).burst.fixture.test", type: type,
                                               id: UInt16(0x2000 + index))!
        query[11] = 1
        let flags: [UInt8] = index % 2 == 0 ? [0, 0, 0x80, 0] : [0, 0, 0, 0]
        let cookie = [UInt8](repeating: UInt8(truncatingIfNeeded: index), count: 8)
        var options = Data([0, 10, 0, 8]); options.append(contentsOf: cookie)
        if index % 4 == 0 {
            options.append(contentsOf: [0, 12, 0, 64]); options.append(Data(repeating: 0, count: 64))
        }
        query.append(contentsOf: [0, 0, 41, 4, 208])
        query.append(contentsOf: flags)
        query.append(contentsOf: [UInt8(options.count >> 8), UInt8(truncatingIfNeeded: options.count)])
        query.append(options)
        return query
    }

    private static func descriptors() -> Int {
        var limits = rlimit()
        _ = getrlimit(RLIMIT_NOFILE, &limits)
        return (0..<Int(min(limits.rlim_cur, 4096))).reduce(0) {
            $0 + (fcntl(Int32($1), F_GETFD) == -1 ? 0 : 1)
        }
    }

    private static func run() throws {
        let args = CommandLine.arguments
        func option(_ name: String) -> String? {
            guard args.filter({ $0 == name }).count == 1, let index = args.firstIndex(of: name),
                  index + 1 < args.count else { return nil }
            return args[index + 1]
        }
        guard args.contains("--dns-adaptive-loopback-test"),
              let rootPath = option("--burst-root"), let port = option("--tls-port").flatMap(UInt16.init), port > 0,
              let mode = option("--mode"), ["direct", "nested-direct", "nested-http", "nested-vmess"].contains(mode),
              let count = option("--count").flatMap(Int.init), (64...96).contains(count),
              let proxyPort = option("--proxy-port").flatMap(UInt16.init),
              (mode == "direct" || mode == "nested-direct" ? proxyPort == 0 : proxyPort > 0), proxyPort != port else {
            throw Failure(text: "Burst fixture requires its explicit flag and bounded loopback-only parameters")
        }
        let rawRouter: NativePacketRouter?
        if mode == "direct" { rawRouter = nil }
        else {
            var profile = Profile(); profile.fakeIPEnabled = false
            let policyName: String
            if mode == "nested-direct" { policyName = "DIRECT" }
            else {
                policyName = "BurstNode"
                profile.proxies[policyName] = mode == "nested-http"
                    ? ProxyPolicy(name: policyName, kind: .http, host: "127.0.0.1", port: proxyPort)
                    : ProxyPolicy(name: policyName, kind: .native, host: "127.0.0.1", port: proxyPort,
                        adapterType: "vmess", parameters: ["uuid": "00112233-4455-6677-8899-aabbccddeeff"])
            }
            profile.rules = [RoutingRule(kind: .final, policy: policyName, sourceLine: 1)]
            // Its configure() hook can prepare process limits. Construct it
            // before forcing the controlled before-case back down to 256.
            rawRouter = NativePacketRouter(profile: profile, mode: .proxy, globalPolicy: policyName,
                                            groupSelections: [:], fakeIPStoreURL: nil)
        }
        let fixtureFDLimit = option("--fd-limit").flatMap(Int.init) ?? 0
        try require([0, 128, 256, 512, 1024].contains(fixtureFDLimit), "Unexpected fixture-only file-descriptor limit")
        if fixtureFDLimit > 0 {
            var limits = rlimit()
            try require(getrlimit(RLIMIT_NOFILE, &limits) == 0 && rlim_t(fixtureFDLimit) <= limits.rlim_max,
                        "Cannot inspect the isolated fixture's descriptor limit")
            limits.rlim_cur = rlim_t(fixtureFDLimit)
            try require(setrlimit(RLIMIT_NOFILE, &limits) == 0, "Cannot set the isolated fixture's descriptor limit")
        }
        if args.contains("--prepare-process-resources") {
            #if HAJIMI_FD_RESOURCE_PREPARATION
            let prepared = NetworkProcessResources.prepareOpenFileLimit()
            print("BURST-PREPARE previous=\(prepared.previous ?? 0) current=\(prepared.current ?? 0) changed=\(prepared.changed) adequate=\(prepared.isAdequate)")
            try require(prepared.isAdequate, "Explicit process-resource preparation did not obtain an adequate descriptor budget")
            #else
            throw Failure(text: "This before-fix fixture was not linked with the explicit process-resource preparation API")
            #endif
        }
        var actualLimits = rlimit()
        try require(getrlimit(RLIMIT_NOFILE, &actualLimits) == 0, "Cannot verify the fixture's actual descriptor limit")
        if args.contains("--prepare-process-resources") {
            try require(actualLimits.rlim_cur >= rlim_t(4_096), "Process-resource preparation reported success without an actual 4096 descriptor budget")
        }
        print("BURST-LIMIT mode=\(mode) soft-fd=\(actualLimits.rlim_cur) fixture-only=true")
        let root = URL(fileURLWithPath: rootPath).standardizedFileURL.resolvingSymlinksInPath()
        let temp = FileManager.default.temporaryDirectory.standardizedFileURL.resolvingSymlinksInPath()
        let properties = try FileManager.default.attributesOfItem(atPath: root.path)
        try require(root.deletingLastPathComponent() == temp && root.lastPathComponent.hasPrefix("hajimi-dns-burst-")
                    && properties[.type] as? FileAttributeType == .typeDirectory
                    && (properties[.posixPermissions] as? NSNumber)?.intValue == 0o700,
                    "Burst fixture root must be its isolated private temporary directory")
        let anchorPath = root.appendingPathComponent("ca.der")
        let anchorProperties = try FileManager.default.attributesOfItem(atPath: anchorPath.path)
        try require(anchorPath.resolvingSymlinksInPath() == anchorPath
                    && anchorProperties[.type] as? FileAttributeType == .typeRegular
                    && (anchorProperties[.posixPermissions] as? NSNumber)?.intValue == 0o600
                    && (anchorProperties[.size] as? NSNumber).map({ (1...16_384).contains($0.intValue) }) == true,
                    "Burst fixture anchor must be a bounded private regular artifact")
        let anchorBytes = try Data(contentsOf: anchorPath)
        guard let anchor = SecCertificateCreateWithData(nil, anchorBytes as CFData) else {
            throw Failure(text: "Invalid ephemeral fixture anchor")
        }
        let probe = Probe()
        let descriptorTimer = Timer(timeInterval: 0.1, repeats: true) { _ in probe.descriptorCount(descriptors()) }
        RunLoop.main.add(descriptorTimer, forMode: .common)
        defer { descriptorTimer.invalidate() }
        probe.descriptorCount(descriptors())
        let endpoint = DoHEndpoint("https://127.0.0.1:\(port)/dns-query")!
        NetworkPerformanceDiagnostics.shared.reset()
        let dialer: CancellableEncryptedDNSStreamDialer = { host, targetPort, name, queue, completion in
            guard host == "127.0.0.1", targetPort == port, name == "127.0.0.1" else {
                completion(.failure(Failure(text: "Burst dial escaped its single literal-loopback endpoint"))); return nil
            }
            let dial = probe.dial()
            probe.stage("dial", dial: dial)
            if dial > 1 { probe.observeResolverQueue(queue) }
            let ready: (Result<any NativeOutboundByteStream, Error>) -> Void = { result in
                if case .success = result { probe.stage("TLS-ready", dial: dial) }
                else { probe.stage("TLS-failed", dial: dial) }
                probe.dialResult(result)
                completion(result.map { ObservedStream($0, probe: probe, dial: dial) as any NativeOutboundByteStream })
            }
            if mode == "direct" {
                let tls = NWProtocolTLS.Options()
                sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, "127.0.0.1")
                sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
                sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, peerTrust, verify in
                    probe.stage("verify-start", dial: dial)
                    let trust = sec_trust_copy_ref(peerTrust).takeRetainedValue()
                    guard SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, "127.0.0.1" as CFString)) == errSecSuccess,
                          SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess,
                          SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
                          SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else {
                        probe.stage("verify-configuration-failed", dial: dial); verify(false); return
                    }
                    probe.stage("verify-configured", dial: dial)
                    let status = SecTrustEvaluateAsyncWithError(trust, queue) { _, trusted, _ in
                        probe.stage(trusted ? "verify-trusted" : "verify-rejected", dial: dial)
                        verify(trusted); probe.stage("verify-replied", dial: dial)
                    }
                    probe.stage("verify-call-returned", dial: dial)
                    if status != errSecSuccess { verify(false) }
                }, queue)
                let connection = NWConnection(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port)!,
                                              using: NWParameters(tls: tls, tcp: .init()))
                let attempt = DirectAttempt(connection, ready)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .preparing: probe.stage("NW-preparing", dial: dial)
                    case .ready:
                        probe.stage("NW-ready", dial: dial); attempt.finish(.success(NetworkStream(connection)))
                    case .failed(let error):
                        probe.stage("NW-failed", dial: dial); attempt.finish(.failure(error), cancel: true)
                    case .waiting(let error):
                        probe.stage("NW-waiting", dial: dial)
                        if case .tls = error { attempt.finish(.failure(error), cancel: true) }
                    case .cancelled:
                        probe.stage("NW-cancelled", dial: dial); attempt.finish(.failure(Failure(text: "Direct burst TLS cancelled")))
                    default: break
                    }
                }
                connection.start(queue: queue)
                return { queue.async {
                    probe.stage("dial-cancel-requested", dial: dial)
                    attempt.finish(.failure(Failure(text: "Burst handshake cancelled")), cancel: true)
                } }
            }
            let operation = RoutedAttempt(queue: queue, connect: { connected in
                probe.rawStart()
                let rawReady: (Result<any NativeOutboundByteStream, Error>) -> Void = { result in
                    if case .success = result { probe.rawReadyResult(true) } else { probe.rawReadyResult(false) }
                    connected(result.map { ObservedRaw($0, probe: probe) as any NativeOutboundByteStream })
                }
                rawRouter!.connectTCP(host: "127.0.0.1", port: port, queue: queue,
                    sourceHost: nil, sourcePort: nil, inboundPort: nil, synthesizeFakeIP: false,
                    completion: rawReady)
            }, upgrade: { stream, upgraded in
                NativeOutboundFactory.beginTLSUpgradeForDNSLoopbackFixture(stream: stream,
                    serverName: "127.0.0.1", queue: queue, alpn: ["http/1.1"], anchor: anchor, completion: upgraded)
            }, completion: ready)
            operation.start()
            return operation.cancel
        }
        let preflight = TLSPreflight(), preflightStarted = NetworkPerformanceDiagnostics.now()
        let preflightQueue = DispatchQueue(label: "fixture.burst.explicit-tls-preflight")
        print("BURST-PREFLIGHT mode=\(mode) start same-route=true private-anchor+IP-SAN=true deadline=8000ms DNS-questions=0")
        fflush(stdout)
        let cancelPreflight = dialer("127.0.0.1", port, "127.0.0.1", preflightQueue) {
            preflight.complete($0, started: preflightStarted)
        }
        do {
            try until("Explicit private-CA TLS preflight did not finish inside the original 8-second deadline", seconds: 8) {
                preflight.snapshot.finished
            }
        } catch {
            cancelPreflight?()
            print("BURST-PREFLIGHT mode=\(mode) FAILED elapsed=\(NetworkPerformanceDiagnostics.elapsedMilliseconds(since: preflightStarted))ms DNS-questions=0")
            fflush(stdout)
            throw error
        }
        let authenticated = preflight.snapshot
        print(String(format: "BURST-PREFLIGHT mode=%@ completed success=%@ elapsed=%.1fms cancel-requested=true DNS-questions=0 error=%@",
                     mode, authenticated.success ? "true" : "false", authenticated.elapsed, authenticated.failure))
        fflush(stdout)
        try require(authenticated.success && authenticated.elapsed < 8_000,
                    "Explicit TLS preflight failed normal private-anchor authentication or its original 8-second deadline")
        try until("Preflight left its published TLS stream active", seconds: 4) { probe.snapshot.active == 0 }
        print("BURST-PREFLIGHT mode=\(mode) logical-active=0 physical-close-ACK=unavailable DNS-questions=0")
        fflush(stdout)
        NetworkPerformanceDiagnostics.shared.reset()
        let resolver = DoHResolver(endpoint: endpoint, cancellableStreamDialer: dialer)
        defer { resolver.cancel(); probe.stopHeartbeat() }
        func issue(_ index: Int) {
            let query = makeQuery(index: index), started = NetworkPerformanceDiagnostics.now()
            _ = resolver.resolve(query: query) { answer in
                let success = answer.map {
                    DNSMessageInspection.responseMatchesQuery($0, query: query)
                        && $0[$0.startIndex + 3] & 15 == 0 && $0[$0.startIndex + 7] == 1
                } ?? false
                probe.result(index, success: success, started: started)
            }
        }
        var target = 0
        for wave in 0..<3 {
            print("BURST-RESOURCE mode=\(mode) wave=\(wave) before-fd=\(descriptors())")
            fflush(stdout)
            let start = target
            for offset in 0..<count { issue(start + offset) }
            target += count
            try until("Burst wave did not complete inside its normal DoH deadline") { probe.snapshot.count == target }
            let state = probe.snapshot
            print(String(format: "BURST mode=%@ wave=%d complete=%d failures=%d dials=%d TLS-ready=%d TLS-failures=%d active=%d peak=%d p50=%.1fms p95=%.1fms", mode,
                         wave, state.count, state.failed, state.dials, state.dialResults - state.dialFailures,
                         state.dialFailures, state.active, state.maximumActive, state.p50, state.p95))
            print("BURST-RESOURCE mode=\(mode) wave=\(wave) after-fd=\(descriptors()) peak-fd=\(probe.resourceSnapshot.peakFD) errors=\(probe.resourceSnapshot.errors)")
            let rawState = probe.resourceSnapshot
            print("BURST-RAW mode=\(mode) wave=\(wave) logical-setup-pending=\(rawState.rawPending) logical-setup-peak=\(rawState.rawPeak) ready=\(rawState.rawReady) failed=\(rawState.rawFailed) sends=\(rawState.rawSends) send-results=\(rawState.rawSendResults) send-errors=\(rawState.rawSendErrors) receives=\(rawState.rawReadResults) sent-bytes=\(rawState.rawSentBytes) received-bytes=\(rawState.rawReceivedBytes)")
            let stages = probe.stageJSON
            try require(!stages.summary.contains("fixtureSerializationError") && !stages.trace.contains("fixtureSerializationError"),
                        "Fixture-only timing serialization failed; not a production DNS transport failure")
            print("BURST-STAGE-SUMMARY mode=\(mode) wave=\(wave) \(stages.summary)")
            fflush(stdout)
            for _ in 0..<8 {
                issue(target); target += 1
                try until("Warm reused TLS query did not complete") { probe.snapshot.count == target }
            }
        }
        resolver.cancel()
        try until("Burst cancellation left published TLS streams live", seconds: 4) { probe.snapshot.active == 0 }
        probe.stopHeartbeat()
        let result = probe.snapshot
        let metrics = NetworkPerformanceDiagnostics.shared.snapshot()
        print("BURST-FINAL mode=\(mode) questions=\(result.count) failures=\(result.failed) A/AAAA/HTTPS+EDNS TLS-preflight=1 TLS-dials=\(result.dials) TLS-results=\(result.dialResults) TLS-failures=\(result.dialFailures) reuse=\(metrics.dnsConnectionsReused) read-errors=\(result.readErrors) overlapping-reads-or-duplicate-replies=\(result.overlaps) active=\(result.active) sends=\(result.sends) reads=\(result.reads) sent-bytes=\(result.sentBytes) received-bytes=\(result.receivedBytes)")
        print("BURST-RESOURCE-FINAL mode=\(mode) after-fd=\(descriptors()) peak-fd=\(probe.resourceSnapshot.peakFD) native-errors=\(probe.resourceSnapshot.errors)")
        print("BURST-DEADLINE mode=\(mode) original=8000ms late-successful-replies=\(result.lateSuccessfulReplies) maximum-successful-elapsed=\(result.maximumSuccessfulElapsed)ms watchdog-only=12000ms")
        if result.failed > 0 || result.dialFailures > 0 {
            print("BURST-STAGE-TRACE mode=\(mode) clock=milliseconds-from-probe-creation \(probe.stageJSON.trace)")
        }
        fflush(stdout)
        try require(result.count == target && result.failed == 0 && result.overlaps == 0
                    && result.dialFailures == 0 && result.dialResults == result.dials,
                    "DoH burst failed after TCP/TLS admission; preserve its stage and wire trace")
        try require(result.lateSuccessfulReplies == 0 && metrics.dnsConnectionsReused >= 24,
                    "DoH burst accepted a reply after its original 8-second deadline or failed to reuse the 24 warm queries")
    }

    static func main() {
        do { try run() }
        catch {
            FileHandle.standardError.write(Data("DNS DoH burst fixture failed: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}

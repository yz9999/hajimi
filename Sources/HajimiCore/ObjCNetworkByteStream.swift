import Foundation
import HajimiProxyRuntime

/// Ownership/configuration adapter; TCP, TLS, I/O and cancellation are native
/// Objective-C through Network.framework's C API.
final class ObjCNetworkByteStream: NativeOutboundByteStream {
    let native: HJNetworkStream
    init(_ native: HJNetworkStream) { self.native = native }
    @discardableResult
    static func connect(host: String, port: UInt16, tls: Bool = false, serverName: String? = nil,
                        skipCertificateVerification: Bool = false, alpn: [String] = [],
                        interfaceName: String?, queue: DispatchQueue,
                        deadline: TimeInterval = LiteralAddressAttemptClock.now + 12,
                        permitted: @escaping () -> Bool = { true },
                        recordSetup: Bool = true,
                        completion: @escaping (Result<ObjCNetworkByteStream, Error>) -> Void)
        -> ObjCNetworkConnectionAttempt {
        let generation = SecureDNSHostResolver.shared.currentGeneration
        let interface = ProxyEngine.currentOutboundInterface?.name
        let allowed = {
            permitted() && SecureDNSHostResolver.shared.isCurrentGeneration(generation)
                && ProxyEngine.currentOutboundInterface?.name == interface
        }
        let operation = ObjCNetworkConnectionAttempt(queue: queue, deadline: deadline, permitted: allowed,
            timing: recordSetup ? NativeConnectionSetupTiming() : nil, completion: completion)
        let connect: ([String]) -> Void = { addresses in
            let owner = connectAddresses(addresses, port: port, tls: tls,
                serverName: serverName?.isEmpty == false ? serverName : (tls ? host : nil),
                skipCertificateVerification: skipCertificateVerification, alpn: alpn,
                interfaceName: interfaceName, queue: queue, deadline: deadline,
                permitted: { allowed() && operation.isPending }, recordSetup: false,
                onAttemptStarted: operation.beginSetup, completion: operation.finish)
            operation.setCancellation { owner.cancel() }
        }
        guard DoHEndpoint.isAddressLiteral(host) else {
            // This low-level adapter is also used for first-hop proxy nodes.
            // DIRECT application targets are resolved by NativePacketRouter
            // first, so they never bypass their query's routing policy here.
            let id = SecureDNSHostResolver.shared.resolve(host: host, queue: queue) { result in
                guard operation.isPending else { return }
                switch result {
                case .failure(let error): operation.finish(.failure(error))
                case .success(let addresses): connect(addresses)
                }
            }
            if let id { operation.setResolutionCancellation { SecureDNSHostResolver.shared.cancel(id) } }
            return operation
        }
        connect([host])
        return operation
    }

    /// The DIRECT router supplies policy-routed addresses here. This overload
    /// never resolves a hostname and preserves the caller's original identity.
    @discardableResult
    static func connectAddresses(_ addresses: [String], port: UInt16,
                                 tls: Bool = false, serverName: String? = nil,
                                 skipCertificateVerification: Bool = false, alpn: [String] = [],
                                 interfaceName: String?, queue: DispatchQueue, deadline: TimeInterval,
                                 permitted: @escaping () -> Bool = { true }, recordSetup: Bool = true,
                                 onAttemptStarted: (() -> Void)? = nil,
                                 completion: @escaping (Result<ObjCNetworkByteStream, Error>) -> Void)
        -> ObjCNetworkAddressConnectionAttempt {
        let timing = recordSetup ? NativeConnectionSetupTiming() : nil
        let interface = ProxyEngine.currentOutboundInterface?.name
        let owner = LiteralAddressAttemptCoordinator<ObjCNetworkByteStream>.start(addresses: addresses, deadline: deadline, queue: queue,
            permitted: { permitted() && ProxyEngine.currentOutboundInterface?.name == interface },
            dial: { address, remaining, done in
                guard port > 0 else {
                    done(.failure(NativeOutboundError.connection("原生 TCP/TLS 端口无效"))); return {}
                }
                timing?.begin(); onAttemptStarted?()
                let effectiveInterface = Self.isLoopbackAddress(address) ? nil : interfaceName
                return HJNetworkStream.beginConnect(host: address, port: port, tls: tls,
                    serverName: serverName.map(DoHEndpoint.unbracketed),
                    skipCertificateVerification: skipCertificateVerification, alpn: alpn,
                    interfaceName: effectiveInterface, queue: queue, timeout: remaining) { stream, error in
                        if let error { stream?.cancel(); done(.failure(error)) }
                        else if let stream { done(.success(ObjCNetworkByteStream(stream))) }
                        else { done(.failure(NativeOutboundError.connection("原生 TCP/TLS 未返回连接"))) }
                    }
            }, dispose: { $0.cancel() }, completion: { result in
                timing?.finish(result: result, permitted: permitted()
                    && ProxyEngine.currentOutboundInterface?.name == interface)
                completion(result)
            })
        return ObjCNetworkAddressConnectionAttempt(timing: timing, cancellation: owner.cancel)
    }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        native.sendData(data, completion: completion)
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        native.receiveData(maximum: UInt(clamping: maximum), completion: completion)
    }
    func cancel() { native.cancel() }

    private static func isLoopbackAddress(_ host: String) -> Bool {
        let value = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        return value == "localhost" || value == "::1" || value.hasPrefix("127.")
    }
}

/// Canceling an admitted address race is not a network failure. Keep that
/// request-local outcome separate from the racer's internal timeout errors.
final class ObjCNetworkAddressConnectionAttempt {
    private let lock = NSLock()
    private let timing: NativeConnectionSetupTiming?
    private var cancellation: (() -> Void)?
    init(timing: NativeConnectionSetupTiming?, cancellation: @escaping () -> Void) {
        self.timing = timing; self.cancellation = cancellation
    }
    func cancel() {
        lock.lock(); let action = cancellation; cancellation = nil; lock.unlock()
        timing?.finish(outcome: .unobserved); action?()
    }
}

/// Owns DNS and dial cancellation before a stream is published. Finishing or
/// canceling the operation later never reaches an already-delivered stream.
final class ObjCNetworkConnectionAttempt {
    private let lock = NSLock()
    private let queue: DispatchQueue
    private var completion: ((Result<ObjCNetworkByteStream, Error>) -> Void)?
    private var resolutionCancellation: (() -> Void)?
    private var cancellation: (() -> Void)?
    private var timer: DispatchWorkItem?
    private let timing: NativeConnectionSetupTiming?
    private let permitted: () -> Bool

    init(queue: DispatchQueue, deadline: TimeInterval,
         permitted: @escaping () -> Bool = { true }, timing: NativeConnectionSetupTiming? = nil,
         completion: @escaping (Result<ObjCNetworkByteStream, Error>) -> Void) {
        self.queue = queue; self.completion = completion; self.permitted = permitted; self.timing = timing
        let delay = deadline.isFinite ? max(0, min(12, deadline - LiteralAddressAttemptClock.now)) : 0
        let item = DispatchWorkItem { [weak self] in self?.expire() }
        timer = item; queue.asyncAfter(deadline: .now() + delay, execute: item)
    }
    var isPending: Bool { lock.lock(); defer { lock.unlock() }; return completion != nil }
    func beginSetup() {
        lock.lock(); if completion != nil { timing?.begin() }; lock.unlock()
    }
    func setResolutionCancellation(_ action: @escaping () -> Void) {
        lock.lock()
        let active = completion != nil
        if active { resolutionCancellation = action }
        lock.unlock()
        if !active { action() }
    }
    func setCancellation(_ action: @escaping () -> Void) {
        lock.lock()
        let active = completion != nil
        if active { cancellation = action; resolutionCancellation = nil }
        lock.unlock()
        if !active { action() }
    }
    func finish(_ result: Result<ObjCNetworkByteStream, Error>) {
        lock.lock()
        let done = completion; completion = nil
        timer?.cancel(); timer = nil
        resolutionCancellation = nil; cancellation = nil
        lock.unlock()
        if let done { timing?.finish(result: result, permitted: permitted()); done(result) }
        else if case .success(let stream) = result { stream.cancel() }
    }
    func cancel() {
        stop(timeout: false)
    }
    private func expire() { stop(timeout: true) }
    private func stop(timeout: Bool) {
        lock.lock()
        let done = completion; completion = nil
        let resolve = resolutionCancellation, dial = cancellation
        resolutionCancellation = nil; cancellation = nil
        timer?.cancel(); timer = nil
        lock.unlock()
        resolve?(); dial?()
        if let done {
            timing?.finish(outcome: timeout && permitted() ? .networkFailure : .unobserved)
            queue.async { done(.failure(NativeOutboundError.connection("原生连接总截止时间已到或已取消"))) }
        }
    }
    func expireForSelfTest() { expire() }
}

/// One observed setup, not DNS/queue admission or user cancellation. The first
/// physical/native client invocation owns the start; late completions cannot
/// add another sample. A disabled/never-started stage is not a zero-ms success.
final class NativeConnectionSetupTiming {
    enum Outcome { case success, networkFailure, unobserved }
    private let lock = NSLock()
    private let diagnostics: NetworkPerformanceDiagnostics
    private let clock: () -> UInt64
    private var started: UInt64?
    private var ended = false
    init(diagnostics: NetworkPerformanceDiagnostics = .shared,
         clock: @escaping () -> UInt64 = NetworkPerformanceDiagnostics.now) {
        self.diagnostics = diagnostics; self.clock = clock
    }
    func begin() {
        lock.lock(); defer { lock.unlock() }
        guard !ended, started == nil else { return }
        started = clock()
    }
    func finish<Value>(result: Result<Value, Error>, permitted: Bool = true) {
        let outcome: Outcome
        if !permitted { outcome = .unobserved }
        else {
            switch result {
            case .success: outcome = .success
            case .failure(let error): outcome = Self.isNonNetworkFailure(error) ? .unobserved : .networkFailure
            }
        }
        finish(outcome: outcome)
    }
    func finish(outcome: Outcome) {
        lock.lock()
        guard !ended else { lock.unlock(); return }
        ended = true; let started = started
        lock.unlock()
        guard let started, outcome != .unobserved else { return }
        diagnostics.record(.connectionSetup,
            milliseconds: NetworkPerformanceDiagnostics.elapsedMilliseconds(since: started, at: clock()),
            success: outcome == .success)
    }
    private static func isNonNetworkFailure(_ error: Error) -> Bool {
        let value = error as NSError
        if error is NodeConnectionAdmissionError
            || (value.domain == NodeConnectionAdmissionError.errorDomain
                && value.code == NodeConnectionAdmissionError.capacityExceeded.errorCode) { return true }
        if value.domain == HJProxyRuntimeErrorDomain {
            return [HJProxyRuntimeError.Code.invalidArgument.rawValue, HJProxyRuntimeError.Code.cancelled.rawValue,
                    HJProxyRuntimeError.Code.interfaceUnavailable.rawValue,
                    HJProxyRuntimeError.Code.busy.rawValue, HJProxyRuntimeError.Code.queueLimit.rawValue].contains(value.code)
        }
        return false
    }
}

/// No DNS lookup, socket or native client is created by these timing fixtures.
public enum NativeConnectionTimingSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "原生连接计时自检失败：\(text)" }
    }
    private final class Clock {
        private let lock = NSLock()
        private var value: UInt64 = 1_000_000_000
        func now() -> UInt64 { lock.lock(); defer { lock.unlock() }; return value }
        func advance(milliseconds: UInt64) { lock.lock(); value += milliseconds * 1_000_000; lock.unlock() }
    }
    private final class Gate {
        private let lock = NSLock()
        private var current = true
        func allowed() -> Bool { lock.lock(); defer { lock.unlock() }; return current }
        func revoke() { lock.lock(); current = false; lock.unlock() }
    }
    private final class Results<Value> {
        private let lock = NSLock()
        private var values: [Result<Value, Error>] = []
        func append(_ value: Result<Value, Error>) { lock.lock(); values.append(value); lock.unlock() }
        var snapshot: [Result<Value, Error>] { lock.lock(); defer { lock.unlock() }; return values }
    }
    private final class Stream: NativeOutboundByteStream {
        private let lock = NSLock()
        private var closes = 0
        func send(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
        func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) { completion(nil, true, nil) }
        func cancel() { lock.lock(); closes += 1; lock.unlock() }
        var cancellations: Int { lock.lock(); defer { lock.unlock() }; return closes }
    }

    public static func run() throws {
        func expect(_ value: Bool, _ text: String) throws {
            guard value else { throw Failure(text: text) }
        }
        func stage(_ diagnostics: NetworkPerformanceDiagnostics) -> NetworkStageSnapshot {
            diagnostics.snapshot().stages[.connectionSetup] ?? NetworkStageSnapshot()
        }
        let queue = DispatchQueue(label: "app.hajimi.native-connection-timing.selftest")
        let fixtureError = NativeOutboundError.connection("injected network failure")
        func makeCXX(_ diagnostics: NetworkPerformanceDiagnostics, _ clock: Clock, _ gate: Gate,
                     _ results: Results<any NativeOutboundByteStream>) -> NativeCXXConnectionAttempt {
            NativeCXXConnectionAttempt(queue: queue, deadline: Double(clock.now()) / 1_000_000_000 + 12,
                interfaceName: nil, permitted: gate.allowed, clock: { Double(clock.now()) / 1_000_000_000 },
                timing: NativeConnectionSetupTiming(diagnostics: diagnostics, clock: clock.now),
                completion: results.append)
        }

        do {
            let diagnostics = NetworkPerformanceDiagnostics(), clock = Clock(), gate = Gate()
            let results = Results<any NativeOutboundByteStream>()
            let operation = makeCXX(diagnostics, clock, gate, results)
            clock.advance(milliseconds: 8_000) // Simulated DNS, before native invocation.
            try expect(stage(diagnostics).count == 0 && operation.beginSetup(), "DNS/admission contributed a setup sample")
            clock.advance(milliseconds: 3); operation.beginSetup(); clock.advance(milliseconds: 7)
            let winner = Stream(); operation.finish(.success(winner))
            let late = Stream(); operation.finish(.success(late)); operation.cancel(); operation.expireForSelfTest()
            queue.sync {}
            let sample = stage(diagnostics)
            try expect(sample.count == 1 && sample.failureCount == 0 && sample.latestMilliseconds == 10,
                       "success included DNS, reset its start, or produced duplicate samples")
            try expect(results.snapshot.count == 1 && winner.cancellations == 0 && late.cancellations == 1,
                       "a completed request cancellation reached its winner or a late stream leaked")
        }
        // DNS/pre-dial failures, including expiry during DNS, have no setup stage.
        for timeout in [false, true] {
            let diagnostics = NetworkPerformanceDiagnostics(), clock = Clock(), gate = Gate()
            let results = Results<any NativeOutboundByteStream>()
            let operation = makeCXX(diagnostics, clock, gate, results)
            if timeout { operation.expireForSelfTest() } else { operation.finish(.failure(fixtureError)) }
            queue.sync {}
            try expect(stage(diagnostics).count == 0 && results.snapshot.count == 1,
                       "DNS failure/no native invocation was counted as setup failure")
        }
        // Native callbacks may bridge a typed quota failure through NSError.
        for started in [false, true] {
            for expired in [false, true] {
                for error in [NodeConnectionAdmissionError.capacityExceeded as Error,
                              NodeConnectionAdmissionError.capacityExceeded as NSError] {
                    let diagnostics = NetworkPerformanceDiagnostics(), clock = Clock(), gate = Gate()
                    let results = Results<any NativeOutboundByteStream>()
                    let operation = makeCXX(diagnostics, clock, gate, results)
                    if started { operation.beginSetup() }
                    if expired { clock.advance(milliseconds: 12_000) }
                    operation.finish(.failure(error)); queue.sync {}
                    try expect(stage(diagnostics).count == 0 && results.snapshot.count == 1,
                               "typed admission rejection, including a late callback, was counted as network failure")
                }
            }
        }
        // Real errors/timeouts count; cancel/invalidation remain unobserved.
        for outcome in 0..<4 {
            let diagnostics = NetworkPerformanceDiagnostics(), clock = Clock(), gate = Gate()
            let results = Results<any NativeOutboundByteStream>()
            let operation = makeCXX(diagnostics, clock, gate, results)
            operation.beginSetup(); clock.advance(milliseconds: 25)
            switch outcome {
            case 0: operation.finish(.failure(fixtureError))
            case 1: operation.expireForSelfTest(); operation.cancel()
            case 2: operation.cancel(); operation.expireForSelfTest()
            default: gate.revoke(); operation.expireForSelfTest()
            }
            let late = Stream(); operation.finish(.success(late)); queue.sync {}
            let expected: UInt64 = outcome < 2 ? 1 : 0
            try expect(stage(diagnostics).count == expected && stage(diagnostics).failureCount == expected
                       && results.snapshot.count == 1 && late.cancellations == 1,
                       "C++ stop reason, invalidation, or late callback setup accounting is incorrect")
        }
        // Exercise the ordinary ObjC DNS/dial owner without constructing HJNetworkStream.
        for outcome in 0..<5 {
            let diagnostics = NetworkPerformanceDiagnostics(), clock = Clock(), gate = Gate()
            let results = Results<ObjCNetworkByteStream>()
            let operation = ObjCNetworkConnectionAttempt(queue: queue, deadline: LiteralAddressAttemptClock.now + 12,
                permitted: gate.allowed, timing: NativeConnectionSetupTiming(diagnostics: diagnostics, clock: clock.now),
                completion: results.append)
            if outcome < 4 { operation.beginSetup() }
            clock.advance(milliseconds: 10)
            switch outcome {
            case 0: operation.finish(.failure(fixtureError))
            case 1: operation.expireForSelfTest(); operation.cancel()
            case 2: operation.cancel(); operation.expireForSelfTest()
            case 3: gate.revoke(); operation.finish(.failure(fixtureError))
            default: operation.finish(.failure(fixtureError))
            }
            operation.finish(.failure(fixtureError)); queue.sync {}
            let expected: UInt64 = outcome < 2 ? 1 : 0
            try expect(stage(diagnostics).count == expected && stage(diagnostics).failureCount == expected
                       && results.snapshot.count == 1, "ObjC setup terminal outcome was miscounted")
        }
        do {
            let diagnostics = NetworkPerformanceDiagnostics(), clock = Clock()
            let timing = NativeConnectionSetupTiming(diagnostics: diagnostics, clock: clock.now)
            timing.begin(); var cancellations = 0
            let handle = ObjCNetworkAddressConnectionAttempt(timing: timing) {
                cancellations += 1
                timing.finish(result: Result<Void, Error>.failure(fixtureError))
            }
            handle.cancel(); handle.cancel(); timing.finish(result: Result<Void, Error>.success(()))
            try expect(stage(diagnostics).count == 0 && cancellations == 1,
                       "DIRECT racer explicit cancellation was counted as a network failure")
        }
        for code in [HJProxyRuntimeError.Code.invalidArgument, .cancelled, .interfaceUnavailable, .busy, .queueLimit] {
            let diagnostics = NetworkPerformanceDiagnostics(), clock = Clock()
            let timing = NativeConnectionSetupTiming(diagnostics: diagnostics, clock: clock.now)
            timing.begin()
            timing.finish(result: Result<Void, Error>.failure(NSError(domain: HJProxyRuntimeErrorDomain, code: code.rawValue)))
            try expect(stage(diagnostics).count == 0, "native resource/cancellation error was counted as network failure")
        }
    }
}

/// TCP readiness probe only (not proxy/TLS/UDP latency). A ready connection is
/// closed immediately, and the caller owns only this request's cancel handle.
public final class NodeTCPAddressProbe {
    private let lock = NSLock()
    private var cancellation: (() -> Void)?
    private var pending = true
    private init() {}

    @discardableResult
    public static func start(addresses: [String], port: UInt16, queue: DispatchQueue,
                             deadline: UInt64, permitted: @escaping () -> Bool = { true },
                             completion: @escaping (Result<Void, Error>) -> Void) -> NodeTCPAddressProbe {
        let probe = NodeTCPAddressProbe()
        let generation = SecureDNSHostResolver.shared.currentGeneration
        let owner = ObjCNetworkByteStream.connectAddresses(addresses, port: port,
            interfaceName: ProxyEngine.currentOutboundInterface?.name, queue: queue,
            deadline: Double(deadline) / 1_000_000_000,
            permitted: { permitted() && SecureDNSHostResolver.shared.isCurrentGeneration(generation) },
            recordSetup: false) { result in
                probe.complete()
                switch result {
                case .success(let stream): stream.cancel(); completion(.success(()))
                case .failure(let error): completion(.failure(error))
                }
            }
        probe.install { owner.cancel() }
        return probe
    }
    private func install(_ action: @escaping () -> Void) {
        lock.lock(); let active = pending
        if active { cancellation = action }
        lock.unlock(); if !active { action() }
    }
    private func complete() { lock.lock(); pending = false; cancellation = nil; lock.unlock() }
    public func cancel() {
        lock.lock(); pending = false; let action = cancellation; cancellation = nil; lock.unlock()
        action?()
    }
}

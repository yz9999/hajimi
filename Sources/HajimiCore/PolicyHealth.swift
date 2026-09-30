import Foundation
import Network

// MARK: - Group options

/// Health-check settings for one `url-test` or `fallback` group.
public struct PolicyHealthOptions: Equatable {
    /// Plain HTTP on purpose: a 204 endpoint over TCP measures the proxy path
    /// without adding a TLS handshake whose cost varies by cipher and by
    /// whether the outbound already terminates TLS itself.
    public static let defaultTestURL = "http://www.gstatic.com/generate_204"

    public var testURL: String
    public var host: String
    public var port: UInt16
    public var path: String
    public var interval: TimeInterval
    public var timeout: TimeInterval
    /// Hysteresis. A challenger must beat the member in use by more than this
    /// before traffic moves, otherwise two nodes with near-identical latency
    /// would swap on every round and reset every connection each time.
    public var tolerance: TimeInterval

    public init?(parameters: [String: String]) {
        let raw = parameters["url"] ?? parameters["test-url"]
            ?? parameters["internet-test-url"] ?? Self.defaultTestURL
        guard let parsed = Self.parse(raw) else { return nil }
        testURL = raw
        host = parsed.host
        port = parsed.port
        path = parsed.path
        interval = Self.seconds(parameters["interval"], default: 600)
        timeout = Self.seconds(parameters["timeout"], default: 5)
        // Surge and Clash both express tolerance in milliseconds.
        tolerance = (Double(parameters["tolerance"] ?? "") ?? 150) / 1000
    }

    private static func seconds(_ raw: String?, default fallback: TimeInterval) -> TimeInterval {
        guard let raw, let value = Double(raw), value > 0 else { return fallback }
        return value
    }

    static func parse(_ raw: String) -> (host: String, port: UInt16, path: String)? {
        guard let components = URLComponents(string: raw), let host = components.host,
              !host.isEmpty else { return nil }
        let scheme = (components.scheme ?? "http").lowercased()
        guard scheme == "http" || scheme == "https" else { return nil }
        // URLComponents does not range-check the port, so an out-of-range
        // value from a subscription-supplied URL would trap the initialiser.
        let rawPort = components.port ?? (scheme == "https" ? 443 : 80)
        guard rawPort > 0, rawPort <= Int(UInt16.max) else { return nil }
        let port = UInt16(rawPort)
        let path = components.path.isEmpty ? "/" : components.path
        return (host, port, path)
    }
}

// MARK: - Selection policy

/// Turns probe results into a member choice.
///
/// Kept pure and separate from the probing so the behaviour that decides where
/// traffic goes can be exercised directly, including the cases that only show
/// up when nodes fail.
public enum PolicySelectionPolicy {
    /// `url-test`: the lowest latency wins, subject to hysteresis.
    ///
    /// Returns nil when nothing is healthy, which leaves the previous selection
    /// in place rather than blackholing traffic on a member already known to be
    /// down.
    public static func urlTest(members: [String], latencies: [String: TimeInterval],
                               current: String?, tolerance: TimeInterval) -> String? {
        let healthy = members.compactMap { member -> (String, TimeInterval)? in
            guard let latency = latencies[member] else { return nil }
            return (member, latency)
        }
        guard let best = healthy.min(by: { $0.1 < $1.1 }) else { return nil }
        guard let current, members.contains(current),
              let currentLatency = latencies[current] else { return best.0 }
        // Only move when the challenger is meaningfully faster.
        return best.1 + tolerance < currentLatency ? best.0 : current
    }

    /// `fallback`: the first healthy member in declared order.
    ///
    /// Order is the user's stated preference, so a recovered higher-priority
    /// member takes traffic back rather than sticking to whatever answered last.
    public static func fallback(members: [String],
                                latencies: [String: TimeInterval]) -> String? {
        members.first { latencies[$0] != nil }
    }

    static func select(group: PolicyGroup, latencies: [String: TimeInterval],
                       current: String?, tolerance: TimeInterval) -> String? {
        switch group.kind {
        case .urlTest, .smart:
            return urlTest(members: group.members, latencies: latencies,
                           current: current, tolerance: tolerance)
        case .fallback:
            return fallback(members: group.members, latencies: latencies)
        case .select, .loadBalance, .subnet:
            return nil
        }
    }
}

// MARK: - Probe

public enum PolicyProbe {
    /// Dials `route` and times a plain HTTP request through it.
    ///
    /// The measurement is time-to-first-response-byte, which includes the
    /// outbound handshake — that is the delay a user actually pays on a new
    /// connection, so it is the right thing to rank members by.
    public static func measure(route: ResolvedRoute, options: PolicyHealthOptions,
                               queue: DispatchQueue,
                               completion: @escaping (TimeInterval?) -> Void) {
        if case .reject = route { completion(nil); return }
        let target = RequestTarget(host: options.host, port: options.port,
                                   protocolName: "TCP")
        let started = Date()
        let finished = Atomic(false)
        // The stream is registered as soon as it exists so a timeout can close
        // it. Completing the probe without cancelling used to leak the whole
        // outbound connection — one per timed-out probe, every interval,
        // forever.
        let live = Atomic<(any NativeOutboundByteStream)?>(nil)
        let finish: (TimeInterval?) -> Void = { value in
            guard finished.exchange(true) == false else { return }
            live.exchange(nil)?.cancel()
            completion(value)
        }
        queue.asyncAfter(deadline: .now() + options.timeout) { finish(nil) }

        TunnelConnector.connect(route: route, target: target, plainHTTP: false,
                                queue: queue) { result in
            switch result {
            case .failure:
                finish(nil)
            case .success(let (stream, initial)):
                guard finished.exchange(false) == false else {
                    // The timeout already fired; do not leave this one open.
                    stream.cancel()
                    return
                }
                _ = live.exchange(stream)
                let request = "GET \(options.path) HTTP/1.1\r\nHost: \(options.host)\r\n"
                    + "User-Agent: Hajimi\r\nConnection: close\r\n\r\n"
                stream.send(Data(request.utf8)) { error in
                    guard error == nil else { finish(nil); return }
                    readStatusLine(stream: stream, buffered: initial, started: started) { latency in
                        finish(latency)
                    }
                }
            }
        }
    }

    /// Reads until an HTTP status line is available. Anything that is not an
    /// HTTP response means the path is broken even though the socket opened,
    /// which is exactly the failure a TCP-only latency test misses.
    private static func readStatusLine(stream: any NativeOutboundByteStream, buffered: Data,
                                       started: Date, attempt: Int = 0,
                                       accumulated: Data = Data(),
                                       completion: @escaping (TimeInterval?) -> Void) {
        var buffer = accumulated
        buffer.append(buffered)
        if let range = buffer.range(of: Data("\r\n".utf8)) {
            let line = String(data: buffer[buffer.startIndex..<range.lowerBound],
                              encoding: .utf8) ?? ""
            guard line.hasPrefix("HTTP/1.") else { completion(nil); return }
            completion(Date().timeIntervalSince(started))
            return
        }
        guard buffer.count < 8 * 1024, attempt < 32 else { completion(nil); return }
        stream.receive(maximum: 4096) { data, isComplete, error in
            guard error == nil, let data, !data.isEmpty else {
                completion(nil); return
            }
            guard !isComplete || !data.isEmpty else { completion(nil); return }
            readStatusLine(stream: stream, buffered: data, started: started,
                           attempt: attempt + 1, accumulated: buffer,
                           completion: completion)
        }
    }
}

fileprivate final class Atomic<Value> {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func exchange(_ newValue: Value) -> Value {
        lock.lock(); defer { lock.unlock() }
        let old = value
        value = newValue
        return old
    }
}

// MARK: - Monitor

/// Drives `url-test` and `fallback` groups.
///
/// Results are published as ordinary group selections, which the routing path
/// already consults ahead of a group's declared order. That keeps the hot path
/// untouched: routing has no idea health checking exists.
public final class PolicyHealthMonitor {
    public struct Report: Equatable {
        public var group: String
        public var selected: String?
        public var latencies: [String: TimeInterval]
        public var checkedAt: Date
    }

    /// Fires with the full set of automatic selections whenever one changes.
    public var onSelectionsChanged: (([String: String]) -> Void)?
    /// Fires after every round so the UI can show per-member latency.
    public var onReport: ((Report) -> Void)?

    private let queue = DispatchQueue(label: "app.hajimi.policy-health", qos: .utility)
    private let probeQueue = DispatchQueue(label: "app.hajimi.policy-health.probe",
                                           qos: .utility, attributes: .concurrent)
    private var profile: Profile?
    private var timer: DispatchSourceTimer?
    private var selections: [String: String] = [:]
    private var lastChecked: [String: Date] = [:]
    private var inFlight: Set<String> = []

    public init() {}

    deinit { timer?.cancel() }

    /// Groups whose member this monitor owns. Manual selection stays with the
    /// user for every other kind.
    public static func managesSelection(of group: PolicyGroup) -> Bool {
        group.kind == .urlTest || group.kind == .fallback || group.kind == .smart
    }

    public func update(profile: Profile) {
        queue.async {
            self.profile = profile
            let managed = Set(profile.groups.values
                .filter { Self.managesSelection(of: $0) }.map(\.name))
            // Drop state for groups that disappeared or changed kind.
            self.selections = self.selections.filter { managed.contains($0.key) }
            self.lastChecked = self.lastChecked.filter { managed.contains($0.key) }
            guard !managed.isEmpty else { self.stopLocked(); return }
            self.startLocked()
            self.runDueProbes(force: true)
        }
    }

    public func stop() { queue.async { self.stopLocked() } }

    /// Immediately re-tests every managed group, ignoring its interval.
    public func refresh() { queue.async { self.runDueProbes(force: true) } }

    public var currentSelections: [String: String] { queue.sync { selections } }

    private func startLocked() {
        guard timer == nil else { return }
        let source = DispatchSource.makeTimerSource(queue: queue)
        // One shared tick; each group decides whether its own interval elapsed.
        source.schedule(deadline: .now() + 5, repeating: 5, leeway: .seconds(1))
        source.setEventHandler { [weak self] in self?.runDueProbes(force: false) }
        timer = source
        source.resume()
    }

    private func stopLocked() {
        timer?.cancel(); timer = nil
    }

    private func runDueProbes(force: Bool) {
        guard let profile else { return }
        let now = Date()
        for group in profile.groups.values where Self.managesSelection(of: group) {
            guard let options = PolicyHealthOptions(parameters: group.parameters) else { continue }
            guard !inFlight.contains(group.name) else { continue }
            if !force, let last = lastChecked[group.name],
               now.timeIntervalSince(last) < options.interval { continue }
            inFlight.insert(group.name)
            probe(group: group, options: options, profile: profile)
        }
    }

    private func probe(group: PolicyGroup, options: PolicyHealthOptions, profile: Profile) {
        let members = group.members
        guard !members.isEmpty else { inFlight.remove(group.name); return }
        let target = RequestTarget(host: options.host, port: options.port, protocolName: "TCP")
        let collected = ProbeCollector(expected: members.count)
        for member in members {
            let route = profile.route(for: target, mode: .proxy, globalPolicy: member,
                                      groupSelections: selections)
            probeQueue.async {
                PolicyProbe.measure(route: route, options: options,
                                    queue: self.probeQueue) { latency in
                    guard let complete = collected.record(member: member, latency: latency) else {
                        return
                    }
                    self.queue.async {
                        self.finish(group: group, options: options, latencies: complete)
                    }
                }
            }
        }
    }

    private func finish(group: PolicyGroup, options: PolicyHealthOptions,
                        latencies: [String: TimeInterval]) {
        inFlight.remove(group.name)
        lastChecked[group.name] = Date()
        let previous = selections[group.name]
        let chosen = PolicySelectionPolicy.select(group: group, latencies: latencies,
                                                  current: previous,
                                                  tolerance: options.tolerance)
        if let chosen { selections[group.name] = chosen }
        let snapshot = selections
        onReport?(Report(group: group.name, selected: chosen,
                         latencies: latencies, checkedAt: Date()))
        if chosen != previous, chosen != nil {
            onSelectionsChanged?(snapshot)
        }
    }
}

/// Gathers one round of concurrent probes and reports once they have all
/// answered.
private final class ProbeCollector {
    private let lock = NSLock()
    private let expected: Int
    private var latencies: [String: TimeInterval] = [:]
    private var answered = 0

    init(expected: Int) { self.expected = expected }

    /// Returns the complete result set on the final answer, nil before that.
    func record(member: String, latency: TimeInterval?) -> [String: TimeInterval]? {
        lock.lock(); defer { lock.unlock() }
        if let latency { latencies[member] = latency }
        answered += 1
        return answered >= expected ? latencies : nil
    }
}

// MARK: - Self-test

public enum PolicyHealthSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "策略健康检查自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try optionParsing()
        try urlTestSelection()
        try fallbackSelection()
        try probeAgainstLoopback()
    }

    /// Exercises the real probe path against a loopback server.
    ///
    /// The case that matters is the third one: a member whose socket opens but
    /// which never speaks HTTP must be reported unhealthy. A TCP-connect
    /// latency test — which is what the node list already offers — calls that
    /// member healthy, which is exactly how a dead proxy keeps receiving
    /// traffic.
    private static func probeAgainstLoopback() throws {
        let healthy = try LoopbackServer(response: Data("HTTP/1.1 204 No Content\r\n\r\n".utf8))
        defer { healthy.stop() }
        guard let options = PolicyHealthOptions(parameters: [
            "url": "http://127.0.0.1:\(healthy.port)/generate_204", "timeout": "3",
        ]) else { throw Failure(text: "回环测试地址无法解析") }
        guard let latency = measure(options: options) else {
            throw Failure(text: "回环 HTTP 服务未被判定为健康")
        }
        try expect(latency >= 0 && latency < 3, "回环延迟不合理：\(latency)")

        // Speaks TCP, never speaks HTTP.
        let broken = try LoopbackServer(response: Data("NOT-HTTP garbage\r\n\r\n".utf8))
        defer { broken.stop() }
        guard let brokenOptions = PolicyHealthOptions(parameters: [
            "url": "http://127.0.0.1:\(broken.port)/generate_204", "timeout": "3",
        ]) else { throw Failure(text: "回环测试地址无法解析") }
        try expect(measure(options: brokenOptions) == nil,
                   "非 HTTP 响应被误判为健康 —— 纯 TCP 测延迟正是漏在这里")

        // Nothing listening at all.
        let closed = try LoopbackServer(response: Data())
        let closedPort = closed.port
        closed.stop()
        guard let closedOptions = PolicyHealthOptions(parameters: [
            "url": "http://127.0.0.1:\(closedPort)/generate_204", "timeout": "2",
        ]) else { throw Failure(text: "回环测试地址无法解析") }
        try expect(measure(options: closedOptions) == nil, "无监听端口被误判为健康")
    }

    private static func measure(options: PolicyHealthOptions) -> TimeInterval? {
        let queue = DispatchQueue(label: "app.hajimi.policy-health.selftest")
        let semaphore = DispatchSemaphore(value: 0)
        var result: TimeInterval?
        PolicyProbe.measure(route: .direct("DIRECT"), options: options, queue: queue) {
            result = $0
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + options.timeout + 3) == .success else { return nil }
        return result
    }
    private static func optionParsing() throws {
        guard let defaults = PolicyHealthOptions(parameters: [:]) else {
            throw Failure(text: "默认参数无法解析")
        }
        try expect(defaults.host == "www.gstatic.com", "默认测试地址错误")
        try expect(defaults.port == 80, "默认端口错误")
        try expect(defaults.path == "/generate_204", "默认路径错误")
        try expect(defaults.interval == 600, "默认间隔错误")
        try expect(abs(defaults.tolerance - 0.150) < 1e-9, "默认容差应为 150 毫秒")

        guard let custom = PolicyHealthOptions(parameters: [
            "url": "https://example.org:8443/probe",
            "interval": "30", "timeout": "2", "tolerance": "50",
        ]) else { throw Failure(text: "自定义参数无法解析") }
        try expect(custom.host == "example.org" && custom.port == 8443,
                   "自定义主机/端口解析错误")
        try expect(custom.path == "/probe", "自定义路径解析错误")
        try expect(custom.interval == 30 && custom.timeout == 2, "自定义间隔/超时解析错误")
        try expect(abs(custom.tolerance - 0.050) < 1e-9, "自定义容差解析错误")

        // A non-HTTP scheme is a configuration error, not something to guess at.
        try expect(PolicyHealthOptions(parameters: ["url": "ftp://example.org/x"]) == nil,
                   "非 HTTP 测试地址未被拒绝")
        try expect(PolicyHealthOptions(parameters: ["url": "not a url"]) == nil,
                   "非法测试地址未被拒绝")
        // A zero or negative interval must fall back rather than busy-loop.
        guard let clamped = PolicyHealthOptions(parameters: ["interval": "0"]) else {
            throw Failure(text: "零间隔参数无法解析")
        }
        try expect(clamped.interval == 600, "零间隔未回退到默认值")
    }

    private static func urlTestSelection() throws {
        let members = ["A", "B", "C"]
        let tolerance: TimeInterval = 0.150

        // With nothing selected yet, the fastest healthy member wins.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: ["A": 0.30, "B": 0.10, "C": 0.20],
            current: nil, tolerance: tolerance) == "B", "未选出最低延迟成员")

        // A challenger inside the tolerance band must not cause a switch.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: ["A": 0.30, "B": 0.10, "C": 0.20],
            current: "C", tolerance: tolerance) == "C",
            "容差范围内发生了不必要的切换")

        // Beyond the band it must switch.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: ["A": 0.30, "B": 0.01, "C": 0.20],
            current: "C", tolerance: tolerance) == "B",
            "超出容差后未切换到更快成员")

        // An unhealthy current member is abandoned immediately.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: ["A": 0.30], current: "C",
            tolerance: tolerance) == "A", "当前成员失效后未切换")

        // Everything down leaves the decision to the caller.
        try expect(PolicySelectionPolicy.urlTest(
            members: members, latencies: [:], current: "B",
            tolerance: tolerance) == nil, "全部失效时不应给出选择")
    }

    private static func fallbackSelection() throws {
        let members = ["Primary", "Secondary", "Tertiary"]
        try expect(PolicySelectionPolicy.fallback(
            members: members, latencies: ["Primary": 0.5, "Secondary": 0.01]) == "Primary",
            "fallback 应优先声明顺序而非最低延迟")
        try expect(PolicySelectionPolicy.fallback(
            members: members, latencies: ["Secondary": 0.2, "Tertiary": 0.1]) == "Secondary",
            "首个成员失效后未降级到第二个")
        // Recovery must take traffic back to the preferred member.
        try expect(PolicySelectionPolicy.fallback(
            members: members, latencies: ["Primary": 0.9, "Tertiary": 0.1]) == "Primary",
            "首个成员恢复后未回切")
        try expect(PolicySelectionPolicy.fallback(members: members, latencies: [:]) == nil,
                   "全部失效时不应给出选择")
    }
}

/// Minimal loopback TCP server that replies with a fixed byte string.
private final class LoopbackServer {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "app.hajimi.policy-health.loopback")
    let port: UInt16

    init(response: Data) throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
            if case .failed = state { ready.signal() }
        }
        let connectionQueue = queue
        listener.newConnectionHandler = { connection in
            connection.start(queue: connectionQueue)
            // Read the request, then answer. The probe only needs the status
            // line, so a single send is enough.
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                guard !response.isEmpty else { connection.cancel(); return }
                connection.send(content: response, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success,
              let assigned = listener.port?.rawValue else {
            listener.cancel()
            throw PolicyHealthSelfTest.Failure(text: "无法启动回环测试服务")
        }
        port = assigned
    }

    func stop() { listener.cancel() }
}

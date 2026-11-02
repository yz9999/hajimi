import Foundation
import Network

/// Compiled with the unchanged production declarations in one fixture file.
/// Native state injection never starts a connection; real sockets bind only
/// 127.0.0.1 or ::1 and exercise the production UDP/TCP transport itself.
@main
enum TraditionalDNSConnectivityProbeMain {
    private struct Failure: Error { let text: String }
    private static var assertions = 0
    private static func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
        assertions += 1
        if !condition() { throw Failure(text: text) }
    }

    private final class Results {
        let done = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var values: [Result<Data, Error>] = []
        func add(_ value: Result<Data, Error>) {
            lock.lock(); values.append(value); lock.unlock(); done.signal()
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return values.count }
        func wait() throws -> Result<Data, Error> {
            guard done.wait(timeout: .now() + 5) == .success else {
                throw Failure(text: "bounded probe completion missing")
            }
            lock.lock(); defer { lock.unlock() }
            guard let value = values.first else { throw Failure(text: "empty completion") }
            return value
        }
    }

    private final class Evidence {
        private let lock = NSLock()
        private var values: [DNSAttemptErrorSnapshot?] = []
        func observe(_ error: Error?) {
            let value = error.map(DNSAttemptErrorSnapshot.capture)
            lock.lock(); values.append(value); lock.unlock()
        }
        var all: [DNSAttemptErrorSnapshot?] { lock.lock(); defer { lock.unlock() }; return values }
    }

    private static func error(from result: Result<Data, Error>) throws -> Error {
        if case .failure(let error) = result { return error }
        throw Failure(text: "failure expected")
    }

    private static func response(to query: Data, truncated: Bool = false,
                                 servfail: Bool = false) -> Data? {
        guard let question = DNSMessageInspection.singleQuestion(in: query),
              question.name == "captive.apple.com", question.type == 1,
              question.class == 1 else { return nil }
        var answer = Data(query.prefix(question.questionEnd))
        answer[2] = truncated ? 0x83 : 0x81; answer[3] = servfail ? 0x82 : 0x80
        for index in 6..<12 { answer[index] = 0 }
        if truncated { return answer }
        if servfail {
            answer[11] = 1
            answer.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 6,
                0, 15, 0, 2, 0, 6])
        } else {
            answer[7] = 1
            answer.append(contentsOf: [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60,
                0, 4, 192, 0, 2, 80])
        }
        return answer
    }

    private static func parsing() throws {
        for value in ["2402:4e00::", "2408:8888::8", "2408:8899::8", "2400:3200::1"] {
            for raw in [value, "[\(value)]", "udp://[\(value)]:53"] {
                let parsed = TraditionalDNSServer(raw)
                try require(parsed?.host == value && parsed?.port == 53,
                            "IPv6 literal incorrectly rejected or split: \(raw)")
                try require(parsed?.usesIPv6Transport == true, "true IPv6 endpoint mislabeled")
            }
        }
        let custom = TraditionalDNSServer("udp://[2001:db8::53]:5353")
        try require(custom?.host == "2001:db8::53" && custom?.port == 5353,
                    "bracketed IPv6 port changed")
        try require(TraditionalDNSServer("udp://192.0.2.53:5353")?.port == 5353,
                    "IPv4 endpoint regressed")
        try require(TraditionalDNSServer("192.0.2.53")?.usesIPv6Transport == false,
                    "IPv4 endpoint mislabeled as IPv6")
        for mapped in ["::ffff:192.0.2.53", "[::ffff:c000:235]:5353"] {
            try require(TraditionalDNSServer(mapped)?.usesIPv6Transport == false,
                        "IPv4-mapped endpoint mislabeled as IPv6")
        }
        for raw in ["[2001:db8::53]:0", "[2001:db8::53]:65536", "[2001:db8::53]:bad",
                    "[2001:db8::53", "[192.0.2.53]:53", "dns.example.invalid",
                    "::", "ff02::1", "[fe80::1%en1]:53", "198.18.16.1"] {
            try require(TraditionalDNSServer(raw) == nil, "invalid/scoped/loop endpoint admitted: \(raw)")
        }
    }

    private static func memoryTransport() throws {
        let queue = DispatchQueue(label: "app.hajimi.fixed-dns-probe.memory")
        let query = DNSMessageInspection.query(for: "captive.apple.com", type: 1)!
        let server = TraditionalDNSServer("[::1]:5353")!

        let nativeFailure = Results(), nativeEvidence = Evidence()
        let failed = TraditionalDNSNetworkExchange(server: server, query: query, interface: nil,
            queue: queue, timeout: 0, absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2,
            startConnection: { connection, _ in
                connection.stateUpdateHandler?(.failed(.posix(.ENETUNREACH)))
            }, onWaitingError: nativeEvidence.observe, completion: nativeFailure.add)
        queue.async { failed.start() }
        let original = try error(from: nativeFailure.wait())
        let codes = DNSAttemptErrorSnapshot.capture(original).codes
        try require(codes.first?.domain == NSPOSIXErrorDomain
                    && codes.first?.code == Int(ENETUNREACH), "native error was generalized")
        try require(nativeEvidence.all.first??.codes.first?.code == Int(ENETUNREACH),
                    "terminal native error did not reach independent deadline evidence")

        let waiting = Results(), waitingStarted = DispatchSemaphore(value: 0), waitingEvidence = Evidence()
        let deadline = ProcessInfo.processInfo.systemUptime + 0.25
        let waitingExchange = TraditionalDNSNetworkExchange(server: server, query: query, interface: nil,
            queue: queue, timeout: 99, absoluteDeadline: deadline,
            startConnection: { connection, lane in
                connection.stateUpdateHandler?(.waiting(.posix(.EHOSTUNREACH)))
                lane.asyncAfter(deadline: .now() + .milliseconds(25)) { waitingStarted.signal() }
            }, onWaitingError: waitingEvidence.observe, completion: waiting.add)
        queue.async { waitingExchange.start() }
        try require(waitingStarted.wait(timeout: .now() + 2) == .success && waiting.count == 0,
                    "recoverable waiting path ended before the original deadline")
        let timedOut = try error(from: waiting.wait()) as? TraditionalDNSProbeDeadlineError
        try require(timedOut != nil, "deadline lost its distinct fixed reason")
        let cause = timedOut.flatMap { $0.cause }.map(DNSAttemptErrorSnapshot.capture)?.codes.first
        try require(cause?.domain == NSPOSIXErrorDomain && cause?.code == Int(EHOSTUNREACH),
                    "deadline lost the waiting path's original cause")
        try require(ProcessInfo.processInfo.systemUptime >= deadline,
                    "deadline fired before its original absolute value")
        try require(waitingEvidence.all.count == 1, "deadline fabricated or cleared path evidence")

        // Hold the actual transport lane across its deadline. The inline
        // state callback runs before the queued timer, so correctness depends
        // on the production clock guard rather than timer-delivery order.
        let afterDeadline = Results(), beforeDeadlineEvidence = Evidence()
        let releaseLane = DispatchSemaphore(value: 0)
        let lateDeadline = ProcessInfo.processInfo.systemUptime + 0.12
        DispatchQueue.global().asyncAfter(deadline: DispatchTime(uptimeNanoseconds:
            UInt64((lateDeadline + 0.03) * 1_000_000_000))) { releaseLane.signal() }
        let lateExchange = TraditionalDNSNetworkExchange(server: server, query: query, interface: nil,
            queue: queue, timeout: 0, absoluteDeadline: lateDeadline,
            startConnection: { connection, _ in
                connection.stateUpdateHandler?(.waiting(.posix(.ENETUNREACH)))
                _ = releaseLane.wait(timeout: .now() + 2)
                connection.stateUpdateHandler?(.waiting(.posix(.EHOSTUNREACH)))
            }, onWaitingError: beforeDeadlineEvidence.observe, completion: afterDeadline.add)
        queue.async { lateExchange.start() }
        let lateError = try error(from: afterDeadline.wait()) as? TraditionalDNSProbeDeadlineError
        let lateCause = lateError.flatMap { $0.cause }.map(DNSAttemptErrorSnapshot.capture)?.codes.first
        try require(lateCause?.code == Int(ENETUNREACH) && beforeDeadlineEvidence.all.count == 1,
                    "after-deadline native callback replaced the original path cause before timer delivery")

        let canceled = Results(), entered = DispatchSemaphore(value: 0)
        var lateState: ((NWConnection.State) -> Void)?
        let cancelExchange = TraditionalDNSNetworkExchange(server: server, query: query, interface: nil,
            queue: queue, timeout: 0, absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2,
            startConnection: { connection, _ in
                lateState = connection.stateUpdateHandler
                connection.stateUpdateHandler?(.waiting(.posix(.ENETUNREACH))); entered.signal()
            }, completion: canceled.add)
        queue.async { cancelExchange.start() }
        try require(entered.wait(timeout: .now() + 2) == .success, "cancel fixture did not enter transport")
        cancelExchange.cancel()
        let cancelError = try error(from: canceled.wait())
        try require((cancelError as? TraditionalDNSBootstrapError).map {
            if case .cancelled = $0 { return true }; return false
        } == true, "explicit cancel became a network/deadline failure")
        queue.sync { lateState?(.failed(.posix(.ECONNRESET))) }
        try require(canceled.count == 1, "late native callback delivered a second result")

        for invalid in [ProcessInfo.processInfo.systemUptime - 1, Double.nan, Double.infinity] {
            let result = Results()
            var networkStarted = false
            let exchange = TraditionalDNSNetworkExchange(server: server, query: query, interface: nil,
                queue: queue, timeout: 0, absoluteDeadline: invalid,
                startConnection: { _, _ in networkStarted = true }, completion: result.add)
            queue.async { exchange.start() }
            let invalidError = try error(from: result.wait())
            try require(invalidError is TraditionalDNSProbeDeadlineError,
                        "expired/invalid deadline was not rejected")
            try require(!networkStarted, "expired/invalid probe started network IO")
        }

        let beforeStart = Results()
        let neverStarted = TraditionalDNSConnectivityProbe(server: server, interface: nil, queue: queue,
            deadline: ProcessInfo.processInfo.systemUptime + 2, queryID: 0x5051, completion: beforeStart.add)
        neverStarted.cancel(); neverStarted.start(); neverStarted.start()
        _ = try error(from: beforeStart.wait())
        queue.sync {}
        try require(beforeStart.count == 1, "cancel-before-start or duplicate-start delivered twice")
        let question = DNSMessageInspection.singleQuestion(in: neverStarted.query)
        try require(question?.name == "captive.apple.com" && question?.type == 1,
                    "probe did not retain its single fixed A question")
        try require(neverStarted.query[0] == 0x50 && neverStarted.query[1] == 0x51,
                    "caller-supplied transaction identity changed")
    }

    private final class ListenerReceipt {
        let terminal = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var value: NWListener.State = .setup
        func record(_ state: NWListener.State) {
            lock.lock(); value = state; lock.unlock()
            switch state {
            case .ready, .failed, .cancelled, .waiting: terminal.signal()
            default: break
            }
        }
        func ready(_ listener: NWListener, queue: DispatchQueue) throws -> NWEndpoint.Port {
            listener.stateUpdateHandler = record
            listener.start(queue: queue)
            guard terminal.wait(timeout: .now() + 2) == .success else {
                throw Failure(text: "loopback listener readiness timed out")
            }
            lock.lock(); let state = value; lock.unlock()
            switch state {
            case .ready:
                guard let port = listener.port else { throw Failure(text: "loopback port missing") }
                return port
            case .failed(let error), .waiting(let error): throw error
            default: throw Failure(text: "loopback listener not ready")
            }
        }
    }

    private final class LoopbackServer {
        enum Mode { case udp, truncated, delayed, servfail, wrongID }
        let port: UInt16
        private let mode: Mode
        private let queue = DispatchQueue(label: "app.hajimi.fixed-dns-probe.loopback")
        private let lock = NSLock()
        private var listeners: [NWListener] = []
        private var connections: [NWConnection] = []
        private var udpQuestions = 0, tcpQuestions = 0, invalidQuestions = 0
        private var closed = false

        init(host: String, mode: Mode) throws {
            self.mode = mode
            var pair: (NWListener, NWListener, NWEndpoint.Port)?
            var requested: NWEndpoint.Port = .any
            for attempt in 0..<4 {
                let tcpParameters = NWParameters.tcp
                tcpParameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: requested)
                let tcp = try NWListener(using: tcpParameters)
                tcp.newConnectionHandler = { $0.cancel() }
                var udp: NWListener?
                do {
                    let tcpPort = try ListenerReceipt().ready(tcp, queue: queue)
                    let udpParameters = NWParameters.udp
                    udpParameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: tcpPort)
                    let candidate = try NWListener(using: udpParameters); udp = candidate
                    candidate.newConnectionHandler = { $0.cancel() }
                    let udpPort = try ListenerReceipt().ready(candidate, queue: queue)
                    guard tcpPort == udpPort else { throw Failure(text: "UDP/TCP fixture ports differ") }
                    pair = (tcp, candidate, tcpPort); break
                } catch {
                    tcp.cancel(); udp?.cancel()
                    guard attempt < 3, let native = error as? NWError,
                          case .posix(.EADDRINUSE) = native else { throw error }
                    requested = NWEndpoint.Port(rawValue: UInt16.random(in: 49_152...65_535))!
                }
            }
            guard let pair else { throw Failure(text: "bounded loopback setup exhausted") }
            port = pair.2.rawValue
            listeners = [pair.0, pair.1]
            pair.0.newConnectionHandler = { [weak self] connection in self?.accept(connection, tcp: true) }
            pair.1.newConnectionHandler = { [weak self] connection in self?.accept(connection, tcp: false) }
        }

        func cancel() {
            lock.lock(); closed = true
            let live = connections; connections.removeAll(); let passive = listeners; listeners.removeAll()
            lock.unlock(); passive.forEach { $0.cancel() }; live.forEach { $0.cancel() }
        }
        deinit { cancel() }
        var counts: (udp: Int, tcp: Int, invalid: Int) {
            lock.lock(); defer { lock.unlock() }; return (udpQuestions, tcpQuestions, invalidQuestions)
        }
        private func accept(_ connection: NWConnection, tcp: Bool) {
            lock.lock(); let allowed = !closed
            if allowed { connections.append(connection) }
            lock.unlock()
            guard allowed else { connection.cancel(); return }
            connection.start(queue: queue)
            if tcp { readTCP(connection, buffer: Data()) }
            else {
                connection.receiveMessage { [weak self] data, _, _, error in
                    guard let self, error == nil, let data else { connection.cancel(); return }
                    self.reply(connection, query: data, tcp: false)
                }
            }
        }
        private func readTCP(_ connection: NWConnection, buffer: Data) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_537 - buffer.count) {
                [weak self] data, _, eof, error in
                guard let self, error == nil else { connection.cancel(); return }
                var next = buffer; if let data { next.append(data) }
                if next.count >= 2 {
                    let length = Int(next[0]) << 8 | Int(next[1])
                    guard length >= 12, next.count <= length + 2 else { connection.cancel(); return }
                    if next.count == length + 2 {
                        self.reply(connection, query: Data(next.dropFirst(2)), tcp: true); return
                    }
                }
                if eof { connection.cancel() }
                else { self.readTCP(connection, buffer: next) }
            }
        }
        private func reply(_ connection: NWConnection, query: Data, tcp: Bool) {
            let answer = TraditionalDNSConnectivityProbeMain.response(to: query,
                truncated: !tcp && mode == .truncated, servfail: mode == .servfail)
            lock.lock()
            if answer == nil { invalidQuestions += 1 }
            else if tcp { tcpQuestions += 1 } else { udpQuestions += 1 }
            let allowed = !closed
            lock.unlock()
            guard allowed, let answer else { connection.cancel(); return }
            let send = { [weak self] in
                guard let self else { return }
                self.lock.lock(); let allowed = !self.closed; self.lock.unlock()
                guard allowed else { return }
                if tcp {
                    var wire = Data([UInt8(answer.count >> 8), UInt8(truncatingIfNeeded: answer.count)])
                    wire.append(answer)
                    connection.send(content: Data(wire.prefix(1)), completion: .contentProcessed { error in
                        guard error == nil else { connection.cancel(); return }
                        connection.send(content: Data(wire.dropFirst()), completion: .contentProcessed { _ in connection.cancel() })
                    })
                } else if self.mode == .wrongID {
                    var mismatch = answer; mismatch[0] ^= 1
                    connection.send(content: mismatch, completion: .contentProcessed { _ in
                        connection.send(content: answer, completion: .contentProcessed { _ in connection.cancel() })
                    })
                } else {
                    connection.send(content: answer, completion: .contentProcessed { _ in connection.cancel() })
                }
            }
            if mode == .delayed { queue.asyncAfter(deadline: .now() + 1.65, execute: send) }
            else { send() }
        }
    }

    private static func loopback() throws {
        var scenarios: [(String, LoopbackServer.Mode)] = []
        for host in ["127.0.0.1", "::1"] { scenarios += [(host, .udp), (host, .truncated)] }
        scenarios += [("::1", .delayed), ("::1", .servfail), ("::1", .wrongID)]
        for (host, mode) in scenarios {
            let server = try LoopbackServer(host: host, mode: mode)
            defer { server.cancel() }
            let queue = DispatchQueue(label: "app.hajimi.fixed-dns-probe.real-client")
            let results = Results()
            let endpoint = host.contains(":") ? "[\(host)]:\(server.port)" : "\(host):\(server.port)"
            let started = ProcessInfo.processInfo.systemUptime
            let probe = TraditionalDNSConnectivityProbe(server: TraditionalDNSServer(endpoint)!,
                interface: nil, queue: queue, deadline: started + 3, completion: results.add)
            probe.start(); probe.start()
            let answer = try results.wait().get()
            try require(DNSMessageInspection.responseMatchesQuery(answer, query: probe.query),
                        "real loopback response lost query identity")
            let measurement = NetworkConnectivityDNSResponse.inspect(answer, query: probe.query)
            if mode == .servfail {
                try require(measurement.status == .failure && measurement.responseCode == 2
                            && measurement.extendedDNSErrorCodes == [6], "raw SERVFAIL/EDE lost in probe")
            } else {
                try require(measurement.status == .success, "fixed A query failed on \(host)")
            }
            if mode == .delayed {
                try require(ProcessInfo.processInfo.systemUptime - started >= 1.6,
                            "delayed real response did not cross former 1.5s slice")
            }
            let counts = server.counts
            try require(counts.udp == 1 && counts.tcp == (mode == .truncated ? 1 : 0)
                        && counts.invalid == 0, "wrong QTYPE, duplicate UDP or unexpected TCP fallback")
            probe.cancel(); queue.sync {}
            try require(results.count == 1, "finish/cancel delivered more than one result")
            print("Fixed DNS real loopback: host=\(host), mode=\(mode), UDP=\(counts.udp), TCP=\(counts.tcp)")
        }

        let recovered = try LoopbackServer(host: "::1", mode: .udp)
        defer { recovered.cancel() }
        let lane = DispatchQueue(label: "app.hajimi.fixed-dns-probe.recovered-path")
        let results = Results(), evidence = Evidence()
        let fixed = DNSMessageInspection.query(for: "captive.apple.com", type: 1)!
        let exchange = TraditionalDNSNetworkExchange(
            server: TraditionalDNSServer("[::1]:\(recovered.port)")!, query: fixed, interface: nil,
            queue: lane, timeout: 0, absoluteDeadline: ProcessInfo.processInfo.systemUptime + 2,
            startConnection: { connection, queue in
                connection.stateUpdateHandler?(.waiting(.posix(.ENETUNREACH)))
                connection.start(queue: queue)
            }, onWaitingError: evidence.observe, completion: results.add)
        lane.async { exchange.start() }
        _ = try results.wait().get()
        let observations = evidence.all
        try require(observations.count >= 2 && observations.first??.codes.first?.code == Int(ENETUNREACH)
                    && observations.last! == nil, "ready path failed to clear its recoverable waiting error")
    }

    static func main() throws {
        try parsing()
        try memoryTransport()
        try loopback()
        try TraditionalDNSBootstrapSelfTest.runOffline()
        print("Fixed traditional DNS probe passed: \(assertions) assertions; IPv4/IPv6 literal transport, fixed A, validated TC/TCP, raw native/RCODE/EDE, original deadline, waiting cause, cancellation; bootstrap offline checks unchanged")
    }
}

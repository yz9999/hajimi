import Foundation
import Darwin
import HajimiIPC

/// Exercises the real prepare/commit/rollback/watchdog service through injected
/// OS commands. Every descriptor is an ordinary /dev/null duplicate; no system
/// interface, route, resolver or Helper daemon is created.
enum EnhancedTunnelStartupSelfTest {
    private final class Fixture {
        struct Route {
            let destination: String
            let gateway: String
            let interface: String
            let host: Bool
        }
        let lock = NSRecursiveLock()
        var clock: TimeInterval = 100
        var physical = "en-fixture"
        var alive: Set<pid_t> = [42, 43]
        let originals = ["Wi-Fi": ["9.9.9.9"], "USB": ["1.1.1.1"]]
        var dns = ["Wi-Fi": ["9.9.9.9"], "USB": ["1.1.1.1"]]
        var routes: [String: Route] = [:]
        var ipv6Gateway: String?
        var scopedIPv6: [String: String] = [:]
        var failIPv6Lookup = false
        var failScopedDelete = false
        var timeoutScopedDeleteAfterMutation = false
        var failTunnelAdd: String?
        var failScopedAdd = false
        var timeoutScopedAddAfterMutation = false
        var failScopedPostAddLookup = false
        var malformedScopedLookup = false
        var scopedAddRace = false
        var commands: [String] = []
        var mutations: [String] = []
        var opened: [Int32] = []
        var failSinkWrite = false
        var failRestore = false
        var onMutation: (() -> Void)?
        let sink = "198.18.16.2"

        func environment() -> EnhancedTunnelService.Environment {
            EnhancedTunnelService.Environment(
                run: { [self] path, args in try run(path, args) },
                openUTUN: { [self] in
                    let fd = Darwin.open("/dev/null", O_RDONLY)
                    guard fd >= 0 else { throw HelperServiceError.command("fixture FD") }
                    lock.lock(); opened.append(fd); lock.unlock()
                    return (fd, "utun-fixture")
                },
                isProcessAlive: { [self] pid in
                    lock.lock(); defer { lock.unlock() }
                    return alive.contains(pid)
                },
                now: { [self] in
                    lock.lock(); defer { lock.unlock() }
                    return clock
                }, monitorHealth: false)
        }

        func run(_ path: String, _ args: [String]) throws -> String {
            lock.lock(); defer { lock.unlock() }
            commands.append(([path] + args).joined(separator: " "))
            if path.hasSuffix("/netstat") { return "Destination Gateway Flags Netif\n" }
            if path.hasSuffix("/ifconfig") {
                if !args.isEmpty { mutations.append("interface " + args.joined(separator: " ")) }
                return ""
            }
            if path.hasSuffix("/networksetup") {
                if args.first == "-listallnetworkservices" {
                    return "An asterisk (*) denotes that a network service is disabled.\nUSB\nWi-Fi\n"
                }
                guard args.count >= 2, let servers = dns[args[1]] else {
                    throw HelperServiceError.command("unknown fixture network service")
                }
                if args[0] == "-getdnsservers" { return servers.joined(separator: "\n") + "\n" }
                if args[0] == "-setdnsservers" {
                    let next = Array(args.dropFirst(2))
                    if failRestore && next != [sink] {
                        throw HelperServiceError.command("fixture restore failure")
                    }
                    dns[args[1]] = next == ["Empty"] ? [] : next
                    mutations.append("dns " + args[1] + " " + next.joined(separator: ","))
                    onMutation?()
                    if failSinkWrite && next == [sink] {
                        failSinkWrite = false
                        throw HelperServiceError.command("fixture failure after DNS mutation")
                    }
                    return ""
                }
            }
            if path.hasSuffix("/route") {
                if args.contains("get") {
                    if args.contains("-inet6"), args.last == "default" {
                        if failIPv6Lookup { throw HelperServiceError.timeout("fixture IPv6 lookup timeout") }
                        if let scopeIndex = args.firstIndex(of: "-ifscope") {
                            if failScopedPostAddLookup && !scopedIPv6.isEmpty {
                                throw HelperServiceError.timeout("fixture scoped verification timeout")
                            }
                            let interface = args[scopeIndex + 1]
                            if let gateway = scopedIPv6[interface] {
                                return "destination: ::\nmask: \(malformedScopedLookup ? "garbage" : "default")\ngateway: \(gateway)\ninterface: \(interface)\nflags: <UP,GATEWAY,IFSCOPE>\n"
                            }
                            // Real route get -ifscope can return the unscoped
                            // default successfully; this must not mean present.
                        }
                        guard let gateway = ipv6Gateway else { throw HelperServiceError.command("route: not in table") }
                        return "destination: ::\nmask: default\ngateway: \(gateway)\ninterface: \(physical)\nflags: <UP,GATEWAY,GLOBAL>\n"
                    }
                    if let type = args.firstIndex(where: { $0 == "-host" || $0 == "-net" }) {
                        let destination = args[type + 1]
                        guard let route = routes[destination] else {
                            throw HelperServiceError.command("route: not in table")
                        }
                        let address = route.destination.split(separator: "/")[0]
                        let ipv6 = address.contains(":")
                        let prefix = route.destination.split(separator: "/").last.flatMap { Int($0) } ?? (ipv6 ? 128 : 32)
                        let bytes = (0..<(ipv6 ? 16 : 4)).map { index -> UInt8 in
                            let bits = min(8, max(0, prefix - index * 8))
                            return UInt8(bits == 0 ? 0 : 256 - (1 << (8 - bits)))
                        }
                        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                        _ = bytes.withUnsafeBytes { inet_ntop(ipv6 ? AF_INET6 : AF_INET, $0.baseAddress,
                                                              &text, socklen_t(text.count)) }
                        let mask = String(cString: text)
                        return "destination: \(address)\nmask: \(mask)\ngateway: \(route.gateway)\ninterface: \(route.interface)\nflags: \(route.host ? "HOST" : "UP,GATEWAY")\n"
                    }
                    return "destination: default\nmask: default\ngateway: 192.0.2.1\ninterface: \(physical)\nflags: <UP,GATEWAY,GLOBAL>\n"
                }
                if args.contains("-inet6"), let scopeIndex = args.firstIndex(of: "-ifscope"),
                   args.contains("add") || args.contains("delete") {
                    let interface = args[scopeIndex + 1]
                    guard args[scopeIndex + 2] == "default", args.count == scopeIndex + 4 else {
                        throw HelperServiceError.command("fixture scoped mutation is not exact default")
                    }
                    let gateway = args[scopeIndex + 3]
                    if args.contains("add") {
                        if failScopedAdd { throw HelperServiceError.command("fixture permission denied") }
                        if scopedAddRace {
                            scopedAddRace = false; scopedIPv6[interface] = gateway
                            throw HelperServiceError.command("route: File exists")
                        }
                        guard scopedIPv6[interface] == nil else { throw HelperServiceError.command("route: File exists") }
                        scopedIPv6[interface] = gateway; mutations.append("scoped add " + interface)
                        onMutation?()
                        if timeoutScopedAddAfterMutation {
                            timeoutScopedAddAfterMutation = false
                            throw HelperServiceError.timeout("fixture add accepted then timeout")
                        }
                    } else {
                        if failScopedDelete { throw HelperServiceError.command("fixture scoped delete failure") }
                        guard scopedIPv6[interface] == gateway else { throw HelperServiceError.command("route: not in table") }
                        scopedIPv6.removeValue(forKey: interface); mutations.append("scoped delete " + interface)
                        if timeoutScopedDeleteAfterMutation {
                            timeoutScopedDeleteAfterMutation = false
                            throw HelperServiceError.timeout("fixture scoped delete accepted then timeout")
                        }
                    }
                    return ""
                }
                if let type = args.firstIndex(where: { $0 == "-host" || $0 == "-net" }),
                   args.contains("add") || args.contains("delete") {
                    let destination = args[type + 1]
                    let gateway = args[type + 2]
                    let add = args.contains("add")
                    if add {
                        if failTunnelAdd == destination { throw HelperServiceError.command("fixture tunnel add rejected") }
                        routes[destination] = Route(destination: destination, gateway: gateway,
                            interface: ["198.18.16.1", "fd00:6861:6a69::1"].contains(gateway) ? "utun-fixture" : physical,
                            host: args[type] == "-host")
                    } else { routes.removeValue(forKey: destination) }
                    mutations.append((add ? "add " : "delete ") + destination)
                    onMutation?()
                    return ""
                }
            }
            throw HelperServiceError.command("unexpected fixture command: \(path) \(args)")
        }

        var trafficMutations: [String] {
            lock.lock(); defer { lock.unlock() }
            return mutations.filter { !$0.hasPrefix("interface ") }
        }
        var isRestored: Bool {
            lock.lock(); defer { lock.unlock() }
            return routes.isEmpty && dns == originals
        }
    }

    static func run() throws {
        var assertions = 0
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
            assertions += 1
            guard condition() else { throw HelperServiceError.command("two-phase startup: " + message) }
        }
        func rejected(_ message: String, _ body: () throws -> Void) throws {
            var didReject = false
            do { try body() } catch { didReject = true }
            try expect(didReject, message)
        }
        let owner = EnhancedTunnelService.MutationCaller.authenticatedPeer(uid: 501, pid: 42, allowedUID: 501)
        let other = EnhancedTunnelService.MutationCaller.authenticatedPeer(uid: 501, pid: 43, allowedUID: 501)
        func prepare(_ service: EnhancedTunnelService) throws -> EnhancedTunnelService.PrepareResult {
            try service.prepare(fakeIPEnabled: true, bypassAddresses: ["198.51.100.7"],
                                includedRoutes: ["203.0.113.0/24"], clientPID: 42)
        }
        func acknowledge(_ service: EnhancedTunnelService, _ result: EnhancedTunnelService.PrepareResult) {
            Darwin.close(result.fileDescriptorToSend)
            service.finishHandoff(generation: result.sessionGeneration, delivered: true)
        }

        // A restarted Helper knows nothing about an older session. An empty
        // inventory is never a positive recovery ACK for a caller's token.
        do {
            let fixture = Fixture()
            fixture.routes["203.0.113.0/24"] = Fixture.Route(destination: "203.0.113.0/24",
                gateway: "198.18.16.1", interface: "utun-previous-helper", host: false)
            fixture.dns["Wi-Fi"] = [fixture.sink]
            let service = EnhancedTunnelService(environment: fixture.environment())
            let idle = service.state(clientPID: 42, renewLiveness: false)
            try expect(idle.networkCleanupPending == false && idle.lastRestoredSessionToken == nil,
                       "fresh Helper must have no historical recovery ACK")
            try rejected("empty restarted Helper cannot acknowledge an unknown token-stop") {
                _ = try service.stop(caller: owner, sessionToken: "previous-helper-token")
            }
            let stopped = try service.stop(caller: owner)
            try expect(stopped.lastRestoredSessionToken == nil && fixture.mutations.isEmpty && !fixture.isRestored,
                       "idle no-token stop must not invent recovery authority")
        }

        // A queued commit must wait for actual SCM_RIGHTS completion without
        // holding the mutation queue or blocking independent heartbeats.
        do {
            let fixture = Fixture()
            let service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepare(service)
            let token = ready.state.sessionToken
            try expect(ready.state.phase == .prepared && !ready.state.running && token != nil,
                       "prepare must return an owned prepared session")
            try expect(fixture.trafficMutations.isEmpty, "prepare must not change routes or DNS")
            try expect(service.state(clientPID: 43).sessionToken == nil, "foreign status must not reveal token")
            try rejected("foreign PID cannot inherit even a dead owner's prepared FD") {
                fixture.alive.remove(42)
                _ = try service.prepare(fakeIPEnabled: false, bypassAddresses: [], clientPID: 43)
            }
            try rejected("foreign PID cannot cancel a dead owner's prepared session") {
                _ = try service.stop(caller: other, sessionToken: token)
            }
            fixture.alive.insert(42)
            try rejected("commit without current token must fail") {
                _ = try service.commit(sessionToken: "old-token", clientPID: 42)
            }
            try rejected("token cannot authorize another PID") {
                _ = try service.commit(sessionToken: token, clientPID: 43)
            }
            try rejected("undelivered FD cannot capture traffic") {
                _ = try service.commit(sessionToken: token, clientPID: 42)
            }
            try expect(fixture.trafficMutations.isEmpty, "failed preconditions must have zero capture side effects")
            let began = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
            let resultLock = NSLock()
            var committed = false
            DispatchQueue.global().async {
                began.signal()
                let ok = (try? service.commit(sessionToken: token, clientPID: 42))?.running == true
                resultLock.lock(); committed = ok; resultLock.unlock()
                done.signal()
            }
            try expect(began.wait(timeout: .now() + 1) == .success, "commit worker must start")
            // Before acknowledgement the route inventory is still empty.
            try expect(fixture.trafficMutations.isEmpty, "pending handoff must not capture")
            acknowledge(service, ready)
            try expect(done.wait(timeout: .now() + 3) == .success, "handoff acknowledgement must unblock commit")
            resultLock.lock(); let successfulCommit = committed; resultLock.unlock()
            try expect(successfulCommit, "same-PID delivered session must commit")
            let mutations = fixture.trafficMutations
            try expect(mutations.first == "add 198.51.100.7" && mutations.dropFirst().first == "add 203.0.113.0/24",
                       "proxy bypass must precede capture")
            try expect(mutations.firstIndex(where: { $0.hasPrefix("dns ") })! > 1,
                       "verified DNS redirection must follow capture")
            let count = fixture.trafficMutations.count
            let replay = try service.commit(sessionToken: token, clientPID: 42)
            try expect(replay.running && replay.phase == .running && fixture.trafficMutations.count == count,
                       "commit replay must be idempotent")
            try rejected("old-token stop must not tear down current reader") {
                _ = try service.stop(caller: owner, sessionToken: "old-token")
            }
            let stopped = try service.stop(caller: owner, sessionToken: token)
            try expect(!stopped.running && stopped.phase == nil && stopped.networkCleanupPending == false && fixture.isRestored,
                       "stop must verify restoration before releasing the session")
            try expect(stopped.lastRestoredSessionToken == token &&
                       service.state(clientPID: 42, renewLiveness: false).lastRestoredSessionToken == token,
                       "verified restoration must acknowledge the exact original owner/token")
            let retried = try service.stop(caller: owner, sessionToken: token)
            try expect(retried.lastRestoredSessionToken == token && retried.networkCleanupPending == false,
                       "owner may safely retry a lost successful stop response")
            try expect(service.state(clientPID: 43, renewLiveness: false).lastRestoredSessionToken == nil &&
                       service.state(clientPID: 0, renewLiveness: false).lastRestoredSessionToken == nil,
                       "other or unknown PID must not read recovery ACK")
            try rejected("other PID cannot replay a known completed session token") {
                _ = try service.stop(caller: other, sessionToken: token)
            }
            let foreignStop = try service.stop(caller: other)
            try expect(foreignStop.lastRestoredSessionToken == nil,
                       "mutation responses must mask another PID's historical ACK")
            let next = try prepare(service)
            acknowledge(service, next)
            try expect(next.state.lastRestoredSessionToken == token,
                       "next prepare must retain an original owner's previous recovery ACK")
            try rejected("completed old token cannot stop a newly prepared session") {
                _ = try service.stop(caller: owner, sessionToken: token)
            }
            _ = try service.stop(caller: owner, sessionToken: next.state.sessionToken)
            try rejected("completed token cannot be replayed") { _ = try service.commit(sessionToken: token, clientPID: 42) }
        }

        // Prepare has both owner-only liveness and an absolute, nonrenewable
        // deadline; repeated prepare/status cannot turn it into a resource leak.
        do {
            let fixture = Fixture()
            let service = EnhancedTunnelService(environment: fixture.environment())
            let first = try prepare(service)
            acknowledge(service, first)
            let again = try prepare(service)
            try expect(again.state.sessionToken == first.state.sessionToken && fixture.opened.count == 1,
                       "same-owner prepare must reuse the session")
            acknowledge(service, again)
            for _ in 0..<3 {
                _ = service.state(clientPID: 43)
                service.healthTickForSelfTest()
            }
            try expect(service.state(clientPID: 42).phase == nil && fixture.isRestored,
                       "foreign status must not renew prepared liveness")
            let second = try prepare(service)
            acknowledge(service, second)
            try expect(second.state.sessionToken != first.state.sessionToken, "new session must use a fresh token")
            fixture.clock += 16
            _ = service.state(clientPID: 42)
            service.healthTickForSelfTest()
            try expect(service.state(clientPID: 42).phase == nil && fixture.isRestored,
                       "owner heartbeat must not extend absolute preparation deadline")
            try rejected("old token must not commit after watchdog cleanup") {
                _ = try service.commit(sessionToken: second.state.sessionToken, clientPID: 42)
            }
        }

        // Cancellation and failed SCM_RIGHTS delivery close only the matching
        // prepared generation, and read-only owner pings never renew liveness.
        do {
            let fixture = Fixture()
            let service = EnhancedTunnelService(environment: fixture.environment())
            let first = try prepare(service)
            Darwin.close(first.fileDescriptorToSend)
            service.finishHandoff(generation: first.sessionGeneration, delivered: false)
            service.drainOperationsForSelfTest()
            try expect(service.state(clientPID: 42).phase == nil && fixture.trafficMutations.isEmpty &&
                       fcntl(fixture.opened[0], F_GETFD) == -1,
                       "failed handoff must release prepared FD without capture")
            let next = try prepare(service)
            acknowledge(service, next)
            service.finishHandoff(generation: first.sessionGeneration, delivered: false)
            service.drainOperationsForSelfTest()
            try expect(service.state(clientPID: 42).sessionToken == next.state.sessionToken,
                       "late old-generation handoff failure cannot stop a new prepare")
            _ = try service.stop(caller: owner, sessionToken: next.state.sessionToken)
            try rejected("cancelled prepared token cannot commit") {
                _ = try service.commit(sessionToken: next.state.sessionToken, clientPID: 42)
            }
            let last = try prepare(service)
            acknowledge(service, last)
            for _ in 0..<3 {
                _ = service.state(clientPID: 42, renewLiveness: false)
                service.healthTickForSelfTest()
            }
            try expect(service.state(clientPID: 42).phase == nil && fixture.isRestored,
                       "owner read-only pings must not renew prepared liveness")
            let pending = try prepare(service)
            fixture.clock += 16
            _ = service.state(clientPID: 42)
            service.healthTickForSelfTest()
            Darwin.close(pending.fileDescriptorToSend)
            service.finishHandoff(generation: pending.sessionGeneration, delivered: true)
            try expect(service.state(clientPID: 42).phase == nil && fixture.trafficMutations.isEmpty,
                       "pending FD handoff must not extend preparation's absolute deadline")
        }

        // A route command can block the mutation queue. Status must still
        // return the current committing snapshot and renew the owner's lease.
        do {
            let fixture = Fixture()
            let service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepare(service)
            acknowledge(service, ready)
            let commandBegan = DispatchSemaphore(value: 0)
            let releaseCommand = DispatchSemaphore(value: 0)
            let committed = DispatchSemaphore(value: 0)
            var didPause = false
            fixture.onMutation = {
                guard !didPause else { return }
                didPause = true
                commandBegan.signal()
                _ = releaseCommand.wait(timeout: .now() + 3)
            }
            DispatchQueue.global().async {
                _ = try? service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
                committed.signal()
            }
            let began = commandBegan.wait(timeout: .now() + 2) == .success
            let started = ProcessInfo.processInfo.systemUptime
            let state = service.state(clientPID: 42)
            let latency = ProcessInfo.processInfo.systemUptime - started
            releaseCommand.signal()
            let finished = committed.wait(timeout: .now() + 3) == .success
            fixture.onMutation = nil
            try expect(began && state.phase == .committing && latency < 0.25,
                       "status must not wait behind blocked route commands")
            try expect(finished && service.state(clientPID: 42).running,
                       "valid heartbeats must allow blocked commit to finish")
            for _ in 0..<3 {
                _ = service.state(clientPID: 42, renewLiveness: false)
                service.healthTickForSelfTest()
            }
            try expect(!service.state(clientPID: 42).running && fixture.isRestored,
                       "running session must retain the original three-second liveness teardown")
        }

        // Partial DNS mutation followed by failed restoration retains both
        // descriptor/interface and token until the real watchdog retries cleanly.
        do {
            let fixture = Fixture()
            let service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepare(service)
            acknowledge(service, ready)
            fixture.failSinkWrite = true; fixture.failRestore = true
            try rejected("DNS verification failure must fail commit") {
                _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            }
            let failed = service.state(clientPID: 42)
            try expect(!failed.running && failed.phase == nil && failed.networkCleanupPending == true &&
                       failed.sessionToken == ready.state.sessionToken,
                       "uncertain cleanup must retain session identity and explicit pending state")
            try expect(failed.lastRestoredSessionToken == nil,
                       "failed DNS restoration must not publish a recovery ACK")
            try expect(fcntl(fixture.opened[0], F_GETFD) >= 0 &&
                       !fixture.mutations.contains("interface utun-fixture down"),
                       "uncertain cleanup must leave the descriptor/interface usable by the reader")
            try rejected("pending restoration must block a new prepare") { _ = try prepare(service) }
            fixture.failRestore = false
            for _ in 0..<5 { service.healthTickForSelfTest() }
            let restored = service.state(clientPID: 42)
            try expect(restored.networkCleanupPending == false && restored.sessionToken == nil && fixture.isRestored,
                       "watchdog must finish restoration without another App mutation")
            try expect(restored.lastRestoredSessionToken == ready.state.sessionToken,
                       "only successful watchdog restoration may acknowledge the failed-start session")
            try expect(fcntl(fixture.opened[0], F_GETFD) == -1 &&
                       fixture.mutations.contains("interface utun-fixture down"),
                       "only verified cleanup may close/down the old interface")
        }

        // A network switch invalidates the App's prepared binding before the
        // first capture command. Loss of heartbeat during commit aborts too.
        do {
            let fixture = Fixture()
            let service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepare(service)
            acknowledge(service, ready)
            fixture.physical = "en-changed"
            try rejected("changed physical interface must invalidate prepare") {
                _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            }
            try expect(fixture.trafficMutations.isEmpty && fixture.isRestored,
                       "network switch must fail before any route/DNS mutation")
        }
        do {
            let fixture = Fixture()
            let service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepare(service)
            acknowledge(service, ready)
            var lostContact = false
            fixture.onMutation = {
                guard !lostContact else { return }
                lostContact = true
                for _ in 0..<3 { service.healthTickForSelfTest(waitForOperations: false) }
            }
            try rejected("committing session must retain the three-second liveness gate") {
                _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            }
            fixture.onMutation = nil
            service.drainOperationsForSelfTest()
            try expect(fixture.isRestored && service.state(clientPID: 42).networkCleanupPending == false,
                       "commit liveness failure must roll back without blocking cleanup commands")
        }
        func prepareIPv6(_ service: EnhancedTunnelService) throws -> EnhancedTunnelService.PrepareResult {
            let result = try service.prepare(fakeIPEnabled: false,
                bypassAddresses: ["198.51.100.7", "2402:4e00::"], clientPID: 42)
            acknowledge(service, result)
            return result
        }
        func fixtureIPv6() -> Fixture {
            let fixture = Fixture(); fixture.ipv6Gateway = "fe80::1%en-fixture"; return fixture
        }
        do {
            let fixture = fixtureIPv6(), service: EnhancedTunnelService
            service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            // Physical defaults may be inspected before opening utun. Capture
            // and scoped route mutations still wait for reader ACK and commit.
            try expect(!fixture.commands.contains { $0.contains("-ifscope") }
                       && fixture.trafficMutations.isEmpty,
                       "IPv6 plumbing must wait for reader ACK and commit")
            _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            let mutations = fixture.trafficMutations
            try expect(mutations.firstIndex(of: "scoped add en-fixture")! < mutations.firstIndex(of: "add ::/1")!,
                       "physical scoped escape must precede IPv6 capture")
            try expect(fixture.scopedIPv6[fixture.physical] == fixture.ipv6Gateway,
                       "unscoped fallback GET must trigger a scoped add")
            // Controlled route-selection model: the interface-scoped default
            // is eligible only for a socket that explicitly requests en-fixture.
            let bound = fixture.scopedIPv6[fixture.physical] != nil ? fixture.physical : nil
            let unboundLower = fixture.routes["::/1"]?.interface
            let unboundUpper = fixture.routes["8000::/1"]?.interface
            try expect(bound == fixture.physical && unboundLower == "utun-fixture" && unboundUpper == "utun-fixture",
                       "scoped repair must preserve both unbound WebRTC capture halves")
            try expect(fixture.routes["2402:4e00::"] == nil && fixture.routes["198.51.100.7"] != nil,
                       "scoped repair must not add an unscoped IPv6 host bypass")
            _ = try service.reload(fakeIPEnabled: false, bypassAddresses: ["198.51.100.7"], caller: owner)
            try expect(fixture.trafficMutations.filter { $0 == "scoped add en-fixture" }.count == 1,
                       "same-config reload must preserve ownership without duplicating add")
            fixture.ipv6Gateway = "fe80::2%en-fixture"
            _ = try service.reload(fakeIPEnabled: false, bypassAddresses: ["198.51.100.7"], caller: owner)
            try expect(fixture.scopedIPv6[fixture.physical] == fixture.ipv6Gateway,
                       "same-interface gateway change retained stale scoped route")
            fixture.physical = "en-next"; fixture.ipv6Gateway = "fe80::3%en-next"
            _ = try service.reload(fakeIPEnabled: false, bypassAddresses: ["198.51.100.7"], caller: owner)
            try expect(fixture.scopedIPv6["en-fixture"] == nil && fixture.scopedIPv6["en-next"] == fixture.ipv6Gateway,
                       "interface change failed to retire old scoped inventory")
            _ = try service.stop(caller: owner, sessionToken: ready.state.sessionToken)
            try expect(fixture.scopedIPv6.isEmpty && fixture.isRestored,
                       "stop failed to remove owned scoped default")
        }
        for borrowed in [true, false] {
            let fixture = fixtureIPv6()
            if borrowed { fixture.scopedIPv6[fixture.physical] = fixture.ipv6Gateway }
            else { fixture.scopedAddRace = true }
            let service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            _ = try service.stop(caller: owner, sessionToken: ready.state.sessionToken)
            try expect(fixture.scopedIPv6[fixture.physical] == fixture.ipv6Gateway
                       && !fixture.trafficMutations.contains { $0.hasPrefix("scoped ") },
                       "pre-existing or raced-in exact route was wrongly owned/deleted")
        }
        do {
            let fixture = fixtureIPv6(); fixture.scopedIPv6[fixture.physical] = "fe80::99%en-fixture"
            let service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            try rejected("different external scoped default must reject commit") {
                _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            }
            try expect(fixture.scopedIPv6[fixture.physical] == "fe80::99%en-fixture"
                       && !fixture.trafficMutations.contains { $0.hasPrefix("scoped ") },
                       "conflicting external default was changed")
        }
        do {
            let fixture = fixtureIPv6(), service: EnhancedTunnelService
            service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            fixture.scopedIPv6[fixture.physical] = "fe80::99%en-fixture"
            _ = try service.stop(caller: owner, sessionToken: ready.state.sessionToken)
            try expect(fixture.scopedIPv6[fixture.physical] == "fe80::99%en-fixture"
                       && !fixture.trafficMutations.contains("scoped delete en-fixture"),
                       "stop deleted an external replacement")
        }
        for failure in ["add", "timeout", "verify", "lookup"] {
            let fixture = fixtureIPv6()
            fixture.failScopedAdd = failure == "add"
            fixture.timeoutScopedAddAfterMutation = failure == "timeout"
            fixture.failScopedPostAddLookup = failure == "verify"
            fixture.failScopedDelete = failure == "timeout"
            let service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            fixture.failIPv6Lookup = failure == "lookup"
            try rejected("uncertain IPv6 setup must not commit: " + failure) {
                _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            }
            let stopped = service.state(clientPID: 42, renewLiveness: false)
            if failure == "timeout" || failure == "verify" {
                try expect(stopped.networkCleanupPending == true && stopped.lastRestoredSessionToken == nil
                           && fcntl(fixture.opened[0], F_GETFD) >= 0,
                           "uncertain scoped cleanup must retain inventory, token and FD without ACK")
                try rejected("scoped cleanup pending must block new prepare") { _ = try prepareIPv6(service) }
                fixture.failScopedDelete = false; fixture.failScopedPostAddLookup = false
                for _ in 0..<5 { service.healthTickForSelfTest() }
                let restored = service.state(clientPID: 42, renewLiveness: false)
                try expect(restored.networkCleanupPending == false && restored.lastRestoredSessionToken == ready.state.sessionToken
                           && fixture.scopedIPv6.isEmpty, "watchdog lost uncertain IPv6 cleanup inventory")
            } else {
                try expect(stopped.networkCleanupPending == false && fixture.scopedIPv6.isEmpty,
                           "deterministic no-effect failure acquired route ownership")
            }
        }
        do {
            let fixture = fixtureIPv6(), service: EnhancedTunnelService
            service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            fixture.failTunnelAdd = "203.0.114.0/24"
            try rejected("later tunnel rollback cannot leave changed scoped intent running") {
                _ = try service.reload(fakeIPEnabled: false, bypassAddresses: ["198.51.100.7"],
                    includedRoutes: ["203.0.113.0/24", "203.0.114.0/24"], caller: owner)
            }
            let failed = service.state(clientPID: 42, renewLiveness: false)
            try expect(!failed.running && failed.networkCleanupPending == false && fixture.routes.isEmpty
                       && fixture.scopedIPv6.isEmpty && fixture.mutations.contains("add 203.0.113.0/24")
                       && fixture.mutations.contains("delete 203.0.113.0/24"),
                       "cross-transaction reload failure silently retained running capture without escape")
        }
        do {
            let fixture = fixtureIPv6(), service: EnhancedTunnelService
            service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            var interrupted = false
            fixture.onMutation = {
                guard !interrupted, fixture.mutations.last == "scoped add en-fixture" else { return }
                interrupted = true
                for _ in 0..<3 { service.healthTickForSelfTest(waitForOperations: false) }
            }
            try rejected("post-add liveness rejection must retain scoped cleanup ownership") {
                _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            }
            fixture.onMutation = nil; service.drainOperationsForSelfTest()
            try expect(interrupted && fixture.scopedIPv6.isEmpty
                       && fixture.mutations.contains("scoped delete en-fixture"),
                       "successful add lost ownership before rejected verification GET")
        }
        do {
            let fixture = fixtureIPv6(), service: EnhancedTunnelService
            service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            fixture.timeoutScopedDeleteAfterMutation = true
            try rejected("delete timeout must not acknowledge unverified cleanup") {
                _ = try service.stop(caller: owner, sessionToken: ready.state.sessionToken)
            }
            try expect(service.state(clientPID: 42, renewLiveness: false).networkCleanupPending == true
                       && fixture.scopedIPv6.isEmpty,
                       "uncertain delete outcome wrongly published a restoration ACK")
            for _ in 0..<5 { service.healthTickForSelfTest() }
            try expect(service.state(clientPID: 42, renewLiveness: false).lastRestoredSessionToken == ready.state.sessionToken,
                       "watchdog failed to verify an already-applied timed-out delete")
        }
        do {
            let fixture = fixtureIPv6(), service: EnhancedTunnelService
            service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            fixture.malformedScopedLookup = true
            try rejected("malformed scoped lookup must retain cleanup ownership") {
                _ = try service.stop(caller: owner, sessionToken: ready.state.sessionToken)
            }
            let pending = service.state(clientPID: 42, renewLiveness: false)
            try expect(pending.networkCleanupPending == true && pending.lastRestoredSessionToken == nil
                       && fixture.scopedIPv6[fixture.physical] != nil && fcntl(fixture.opened[0], F_GETFD) >= 0,
                       "invalid mask was treated as a foreign route and falsely acknowledged")
            fixture.malformedScopedLookup = false
            for _ in 0..<5 { service.healthTickForSelfTest() }
            try expect(service.state(clientPID: 42, renewLiveness: false).lastRestoredSessionToken == ready.state.sessionToken
                       && fixture.scopedIPv6.isEmpty, "valid retry lost retained malformed-lookup inventory")
        }
        do {
            let fixture = Fixture(), service: EnhancedTunnelService
            service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try prepareIPv6(service)
            _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
            try expect(fixture.scopedIPv6.isEmpty && fixture.routes["::/1"] != nil,
                       "missing physical IPv6 default must preserve ordinary IPv4 startup/capture")
            _ = try service.stop(caller: owner, sessionToken: ready.state.sessionToken)
        }
        try expect(HelperSocketServer.isAuthorizedPeerExecutablePath("/Applications/哈基米.app/Contents/MacOS/HajimiApp")
                   && HelperSocketServer.isAuthorizedPeerExecutablePath("/Users/test/Build/Products/Release/HajimiApp")
                   && HelperSocketServer.isAuthorizedPeerExecutablePath("/tmp/hajimi-test-support/HajimiHelperSelfTest")
                   && !HelperSocketServer.isAuthorizedPeerExecutablePath("/usr/bin/python3")
                   && !HelperSocketServer.isAuthorizedPeerExecutablePath("/usr/bin/nc"),
                   "HelperSocketServer peer executable path whitelist rejected valid client or allowed foreign process")
        print("EnhancedTunnel prepare/commit self-test passed (\(assertions) assertions; injected network only)")
    }
}

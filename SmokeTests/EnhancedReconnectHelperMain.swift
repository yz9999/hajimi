import Foundation
import Darwin

/// Complete production EnhancedTunnelService with injected command results and
/// ordinary descriptors. Never constructs the socket server or a real utun.
@main
private enum EnhancedReconnectHelperMain {
    private struct Failure: Error { let text: String }
    private struct Route: Equatable {
        let destination: String
        let gateway: String
        let interface: String
        let host: Bool
    }
    private final class Fixture {
        enum Fault { case none, missing, timeout, noGateway, noInterface, down, tunnel, loopback, selfGateway }
        var physical = "en-fixture", gateway = "192.0.2.1"
        var fault = Fault.none, ipv6ReadTimeout = false
        var ipv6Gateway: String?
        var scoped: [String: String] = [:]
        var routes: [String: Route] = [:]
        let originals = ["Wi-Fi": ["9.9.9.9"], "USB": ["1.1.1.1"]]
        var dns = ["Wi-Fi": ["9.9.9.9"], "USB": ["1.1.1.1"]]
        var commands: [String] = [], mutations: [String] = [], opened: [Int32] = []
        var defaultReads = 0, ipv6DefaultReads = 0, poisonSecondDefaultRead = false
        var failAdd: String?, timeoutAfterAdd: String?, failDNSRead = false, timeoutAfterDNSWrite = false
        let sink = "198.18.16.2"
        func environment() -> EnhancedTunnelService.Environment {
            EnhancedTunnelService.Environment(run: { [self] in try run($0, $1) }, openUTUN: { [self] in
                let descriptor = Darwin.open("/dev/null", O_RDONLY)
                precondition(descriptor >= 0, "fixture could not open ordinary descriptor")
                opened.append(descriptor); return (descriptor, "utun-fixture")
            }, isProcessAlive: { [42, 43].contains($0) }, now: { 100 }, monitorHealth: false)
        }
        func resetObservations() { commands.removeAll(); mutations.removeAll(); defaultReads = 0; ipv6DefaultReads = 0 }
        func run(_ executable: String, _ args: [String]) throws -> String {
            commands.append(([executable] + args).joined(separator: " "))
            if executable == "/usr/sbin/netstat" { return "Destination Gateway Flags Netif\n" }
            if executable == "/sbin/ifconfig" { mutations.append("ifconfig " + args.joined(separator: " ")); return "" }
            if executable == "/usr/sbin/networksetup" {
                if args == ["-listallnetworkservices"] {
                    return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nUSB\n"
                }
                precondition(args.count >= 2 && dns[args[1]] != nil, "unexpected fixture network service")
                if args[0] == "-getdnsservers" {
                    if failDNSRead { failDNSRead = false; throw HelperServiceError.command("fixture DNS read failed") }
                    let values = dns[args[1]]!
                    return values.isEmpty ? "There aren't any DNS Servers set on this service.\n" : values.joined(separator: "\n") + "\n"
                }
                if args[0] == "-setdnsservers" {
                    let values = Array(args.dropFirst(2)); dns[args[1]] = values == ["Empty"] ? [] : values
                    mutations.append("dns " + args[1])
                    if timeoutAfterDNSWrite { timeoutAfterDNSWrite = false; throw HelperServiceError.timeout("fixture DNS accepted before timeout") }
                    return ""
                }
            }
            if executable == "/sbin/route" {
                if args.contains("get") {
                    if args.contains("-inet6"), args.last == "default" {
                        if let index = args.firstIndex(of: "-ifscope") {
                            let name = args[index + 1]
                            if let gateway = scoped[name] { return ipv6Output(interface: name, gateway: gateway, scoped: true) }
                        } else {
                            ipv6DefaultReads += 1
                            if ipv6ReadTimeout { throw HelperServiceError.timeout("fixture IPv6 default read timeout") }
                        }
                        guard let gateway = ipv6Gateway else { throw HelperServiceError.command("route: not in table") }
                        return ipv6Output(interface: physical, gateway: gateway, scoped: false)
                    }
                    if let type = args.firstIndex(where: { $0 == "-host" || $0 == "-net" }) {
                        guard let route = routes[args[type + 1]] else { throw HelperServiceError.command("route: not in table") }
                        return routeOutput(route)
                    }
                    if args.last == "default" {
                        defaultReads += 1
                        if poisonSecondDefaultRead && defaultReads > 1 { throw HelperServiceError.timeout("fixture default changed between repeated reads") }
                        switch fault {
                        case .missing: throw HelperServiceError.command("route: not in table")
                        case .timeout: throw HelperServiceError.timeout("fixture default read timeout")
                        default: break
                        }
                        let name = fault == .tunnel ? "utun-foreign" : (fault == .loopback ? "lo0" : physical)
                        let gateway = fault == .selfGateway ? "198.18.16.1" : self.gateway
                        return "destination: default\nmask: default\n"
                            + (fault == .noGateway ? "" : "gateway: \(gateway)\n")
                            + (fault == .noInterface ? "" : "interface: \(name)\n")
                            + "flags: <\(fault == .down ? "GATEWAY" : "UP,GATEWAY"),GLOBAL>\n"
                    }
                    if let destination = args.last, let route = routes[destination] { return routeOutput(route) }
                    // An unknown Internet host follows the installed capture,
                    // not the physical default hidden by the split routes.
                    if !routes.isEmpty { return "gateway: 198.18.16.1\ninterface: utun-fixture\n" }
                    // Conflict probes before prepare inspect only interface.
                    return "gateway: \(gateway)\ninterface: \(physical)\n"
                }
                if let index = args.firstIndex(of: "-ifscope"), args.contains("-inet6") {
                    precondition(args.count == index + 4 && args[index + 2] == "default", "nonexact scoped route mutation")
                    let interface = args[index + 1], gateway = args[index + 3]
                    if args.contains("add") {
                        guard scoped[interface] == nil else { throw HelperServiceError.command("route: File exists") }
                        scoped[interface] = gateway; mutations.append("scoped add " + interface)
                    } else if args.contains("delete") {
                        guard scoped[interface] == gateway else { throw HelperServiceError.command("route: not in table") }
                        scoped.removeValue(forKey: interface); mutations.append("scoped delete " + interface)
                    } else { preconditionFailure("unexpected scoped command") }
                    return ""
                }
                if let type = args.firstIndex(where: { $0 == "-host" || $0 == "-net" }) {
                    let destination = args[type + 1], gateway = args[type + 2], add = args.contains("add")
                    precondition(add || args.contains("delete"), "unexpected route mutation")
                    if add {
                        // Darwin route add does not replace an existing route
                        // just because the next hop changed after DHCP.
                        guard routes[destination] == nil else { throw HelperServiceError.command("route: File exists") }
                        if failAdd == destination { failAdd = nil; throw HelperServiceError.command("fixture route add rejected") }
                        routes[destination] = Route(destination: destination, gateway: gateway,
                            interface: ["198.18.16.1", "fd00:6861:6a69::1"].contains(gateway) ? "utun-fixture" : physical,
                            host: args[type] == "-host")
                    } else {
                        guard let existing = routes[destination], existing.gateway == gateway,
                              existing.host == (args[type] == "-host") else {
                            throw HelperServiceError.command("route: not in table")
                        }
                        routes.removeValue(forKey: destination)
                    }
                    mutations.append((add ? "add " : "delete ") + destination)
                    if add && timeoutAfterAdd == destination {
                        timeoutAfterAdd = nil; throw HelperServiceError.timeout("fixture route accepted before timeout")
                    }
                    return ""
                }
            }
            preconditionFailure("No real OS command is permitted: \(executable) \(args)")
        }
        private func ipv6Output(interface: String, gateway: String, scoped: Bool) -> String {
            "destination: ::\nmask: default\ngateway: \(gateway)\ninterface: \(interface)\nflags: <UP,GATEWAY,\(scoped ? "IFSCOPE" : "GLOBAL")>\n"
        }
        private func routeOutput(_ route: Route) -> String {
            let address = String(route.destination.split(separator: "/")[0]), ipv6 = address.contains(":")
            let prefix = route.destination.split(separator: "/").last.flatMap { Int($0) } ?? (ipv6 ? 128 : 32)
            let bytes = (0..<(ipv6 ? 16 : 4)).map { index -> UInt8 in
                let bits = min(8, max(0, prefix - index * 8)); return UInt8(bits == 0 ? 0 : 256 - (1 << (8 - bits)))
            }
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            precondition(bytes.withUnsafeBytes { inet_ntop(ipv6 ? AF_INET6 : AF_INET, $0.baseAddress, &text, socklen_t(text.count)) } != nil)
            return "destination: \(address)\nmask: \(String(cString: text))\ngateway: \(route.gateway)\ninterface: \(route.interface)\nflags: <UP,GATEWAY\(route.host ? ",HOST" : "")>\n"
        }
    }
    private static let owner = EnhancedTunnelService.MutationCaller.authenticatedPeer(uid: 501, pid: 42, allowedUID: 501)
    private static var assertions = 0, groups = 0, failures: [String] = [], verifiedRegressions: [String] = []
    private static var after = true
    private static var gatewayFixed = true
    private static var verifiedGatewayRegressions: [String] = []
    private static func expect(_ value: @autoclosure () -> Bool, _ text: String) throws {
        assertions += 1; if !value() { throw Failure(text: text) }
    }
    private static func check(_ name: String, _ body: () throws -> Void) {
        groups += 1
        do { try body(); print("PASS " + name) }
        catch { failures.append(name); print("FAIL " + name + ": " + ((error as? Failure)?.text ?? error.localizedDescription)) }
    }
    private static func typed(_ error: Error?) -> Bool {
        #if HAVE_RECONNECT_PREFLIGHT
        if case .physicalNetworkNotReady = error as? HelperServiceError { return true }
        #endif
        return false
    }
    private static func caught(_ body: () throws -> Void) -> Error? {
        do { try body(); return nil } catch { return error }
    }
    private static func started(_ fixture: Fixture) throws -> (EnhancedTunnelService, String) {
        let service = EnhancedTunnelService(environment: fixture.environment())
        let ready = try service.prepare(fakeIPEnabled: true, bypassAddresses: ["198.51.100.7"], clientPID: 42)
        service.finishHandoff(generation: ready.sessionGeneration, delivered: true)
        Darwin.close(ready.fileDescriptorToSend)
        let state = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
        try expect(state.running && state.phase == .running && state.sessionToken != nil, "fixture did not commit")
        fixture.resetObservations(); return (service, state.sessionToken!)
    }
    private static func reload(_ service: EnhancedTunnelService, token: String, addresses: [String] = ["198.51.100.7"]) throws -> HajimiHelperTunnelState {
        try service.reload(fakeIPEnabled: true, bypassAddresses: addresses, caller: owner, sessionToken: token)
    }
    private static func clean(_ service: EnhancedTunnelService, _ fixture: Fixture, token: String) throws {
        fixture.fault = .none; fixture.ipv6ReadTimeout = false; fixture.poisonSecondDefaultRead = false; fixture.failDNSRead = false
        _ = try service.stop(caller: owner, sessionToken: token)
        try expect(fixture.routes.isEmpty && fixture.scoped.isEmpty, "owned routes were not restored")
    }
    private static func transientCases() {
        for fault in [Fixture.Fault.missing, .timeout, .noGateway, .noInterface] {
            check("temporary-\(fault)") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                let initial = service.state(clientPID: 42, renewLiveness: false), routes = fixture.routes, dns = fixture.dns
                fixture.fault = fault
                let error = caught { _ = try reload(service, token: token) }
                let next = service.state(clientPID: 42, renewLiveness: false)
                try expect(error != nil, "temporary absence was reported successful")
                if after {
                    try expect(typed(error) && next == initial, "temporary read failure stopped/replaced the owned session")
                    try expect(fixture.mutations.isEmpty && fixture.routes == routes && fixture.dns == dns, "preflight failure modified routes or DNS")
                    try expect(fcntl(fixture.opened[0], F_GETFD) >= 0 && next.lastRestoredSessionToken == nil, "preflight closed reader or invented cleanup ACK")
                } else {
                    try expect(!typed(error) && !next.running && !fixture.mutations.isEmpty, "Build37 did not reproduce premature teardown")
                    verifiedRegressions.append("teardown-\(fault)")
                }
                try clean(service, fixture, token: token)
            }
        }
        check("temporary-ipv6-read-timeout-before-any-mutation") {
            let fixture = Fixture(); fixture.ipv6Gateway = "fe80::1%en-fixture"
            let (service, token) = try started(fixture), routes = fixture.routes, scoped = fixture.scoped, dns = fixture.dns
            fixture.ipv6ReadTimeout = true
            let error = caught { _ = try reload(service, token: token) }, state = service.state(clientPID: 42, renewLiveness: false)
            if after {
                try expect(typed(error) && state.running && state.sessionToken == token, "IPv6 preflight read failure stopped owner")
                try expect(fixture.mutations.isEmpty && fixture.routes == routes && fixture.scoped == scoped && fixture.dns == dns, "IPv6 preflight wrote before failing")
            } else {
                try expect(error != nil && !state.running && !fixture.mutations.isEmpty, "Build37 IPv6 read failure did not tear down")
                verifiedRegressions.append("teardown-ipv6-read-timeout")
            }
            try clean(service, fixture, token: token)
        }
        check("link-up-with-down-route-waits") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            fixture.fault = .down
            let error = caught { _ = try reload(service, token: token) }
            if after { try expect(typed(error) && fixture.mutations.isEmpty, "route without UP was admitted") }
            else { try expect(error == nil, "Build37 no-UP negative control changed"); verifiedRegressions.append("no-up-route-admitted") }
            try expect(service.state(clientPID: 42, renewLiveness: false).running, "temporary route state killed owner")
            try clean(service, fixture, token: token)
        }
    }
    private static func recoveryCases() {
        check("same-IP-new-gateway-recovery") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            fixture.gateway = "192.0.2.254"
            let state = try reload(service, token: token)
            try expect(state.running && state.sessionToken == token && state.physicalInterface == "en-fixture", "DHCP gateway change replaced session")
            try expect(fixture.routes["198.51.100.7"]?.gateway == "192.0.2.254", "same-IP recovery retained old gateway")
            try expect(fixture.defaultReads == (after ? 1 : 2) && fixture.ipv6DefaultReads == 1, "default intent was re-read during reconcile")
            try expect(fixture.dns.values.allSatisfy { $0 == [fixture.sink] }, "recovery removed DNS protection")
            try clean(service, fixture, token: token)
        }
        check("single-observation-cannot-mix-interface-and-gateway") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            fixture.physical = "en-next"; fixture.gateway = "198.51.100.1"; fixture.poisonSecondDefaultRead = true
            let error = caught { _ = try reload(service, token: token) }
            let state = service.state(clientPID: 42, renewLiveness: false)
            if after {
                try expect(error == nil && fixture.defaultReads == 1 && state.running && state.physicalInterface == "en-next", "reload required a second inconsistent default observation")
                try expect(fixture.routes["198.51.100.7"]?.gateway == "198.51.100.1"
                            && fixture.routes["198.51.100.7"]?.interface == "en-next", "physical observation was mixed")
            } else {
                try expect(error != nil && !state.running && fixture.defaultReads == 2, "Build37 repeated-default teardown not reproduced")
                verifiedRegressions.append("mixed-default-observation")
            }
            try clean(service, fixture, token: token)
        }
        check("interface-and-IPv6-gateway-change") {
            let fixture = Fixture(); fixture.ipv6Gateway = "fe80::1%en-fixture"
            let (service, token) = try started(fixture)
            fixture.physical = "en-next"; fixture.gateway = "198.51.100.1"; fixture.ipv6Gateway = "fe80::2%en-next"
            let state = try reload(service, token: token)
            try expect(state.running && state.sessionToken == token && state.physicalInterface == "en-next", "interface recovery changed owner")
            try expect(fixture.scoped["en-fixture"] == nil && fixture.scoped["en-next"] == "fe80::2%en-next", "old scoped path was retained")
            try clean(service, fixture, token: token)
        }
        check("absent-IPv6-default-remains-supported") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            let state = try reload(service, token: token)
            try expect(state.running && fixture.scoped.isEmpty && fixture.routes["::/1"] != nil, "missing IPv6 default broke ordinary running capture")
            try clean(service, fixture, token: token)
        }
    }
    private static func protectionCases() {
        for fault in [Fixture.Fault.tunnel, .selfGateway, .loopback] {
            check("confirmed-unsafe-default-\(fault)") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                fixture.fault = fault
                let error = caught { _ = try reload(service, token: token) }, state = service.state(clientPID: 42, renewLiveness: false)
                if !after && fault == .loopback {
                    try expect(error == nil && state.running, "Build37 loopback negative control changed")
                    verifiedRegressions.append("loopback-default-admitted")
                } else { try expect(error != nil && !typed(error) && !state.running, "confirmed unsafe default was labelled transient") }
                try clean(service, fixture, token: token)
            }
        }
        for timeout in [false, true] {
            check("actual-bypass-write-failure-\(timeout)") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                if timeout { fixture.timeoutAfterAdd = "198.51.100.8" } else { fixture.failAdd = "198.51.100.8" }
                let error = caught { _ = try reload(service, token: token, addresses: ["198.51.100.7", "198.51.100.8"]) }
                try expect(error != nil && !typed(error) && !service.state(clientPID: 42, renewLiveness: false).running, "route write failure became a retryable preflight")
                try expect(fixture.routes.isEmpty && fixture.dns == fixture.originals, "real failed mutation abandoned rollback inventory")
                try clean(service, fixture, token: token)
            }
        }
        for timeout in [false, true] {
            check("DNS-protection-failure-still-stops-\(timeout)") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                if timeout { fixture.dns["Wi-Fi"] = ["8.8.8.8"]; fixture.timeoutAfterDNSWrite = true }
                else { fixture.failDNSRead = true }
                let error = caught { _ = try reload(service, token: token) }
                try expect(error != nil && !typed(error) && !service.state(clientPID: 42, renewLiveness: false).running, "DNS protection failure became temporary network absence")
                try expect(fixture.routes.isEmpty && fixture.dns["USB"] == fixture.originals["USB"]
                            && fixture.dns["Wi-Fi"] == (timeout ? ["8.8.8.8"] : fixture.originals["Wi-Fi"]), "DNS cleanup lost original/replaced ownership")
                try clean(service, fixture, token: token)
            }
        }
        check("external-scoped-conflict-still-stops-without-deleting-foreign-route") {
            let fixture = Fixture(); fixture.ipv6Gateway = "fe80::1%en-fixture"
            let (service, token) = try started(fixture)
            fixture.scoped["en-fixture"] = "fe80::99%en-fixture"
            let error = caught { _ = try reload(service, token: token) }
            try expect(error != nil && !typed(error) && !service.state(clientPID: 42, renewLiveness: false).running, "foreign scoped conflict became transient")
            try expect(fixture.scoped["en-fixture"] == "fe80::99%en-fixture", "foreign scoped route was deleted")
            fixture.scoped.removeAll(); try clean(service, fixture, token: token)
        }
        check("owner-and-session-checks-precede-retryable-preflight") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            fixture.fault = .missing
            for (caller, candidate) in [(owner, "expired-token"),
                (.authenticatedPeer(uid: 501, pid: 43, allowedUID: 501), token),
                (.authenticatedPeer(uid: 502, pid: 42, allowedUID: 501), token)] {
                let error = caught { _ = try service.reload(fakeIPEnabled: true, bypassAddresses: ["198.51.100.7"], caller: caller, sessionToken: candidate) }
                try expect(error != nil && !typed(error) && fixture.defaultReads == 0 && fixture.mutations.isEmpty, "unauthorized reload reached transient preflight")
                try expect(service.state(clientPID: 42, renewLiveness: false).running, "unauthorized reload stopped owner")
            }
            try clean(service, fixture, token: token)
        }
        #if HAVE_RECONNECT_PREFLIGHT
        check("server-retryable-code-preserves-only-current-owner-token-without-FD") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            fixture.fault = .missing
            guard let error = caught({ _ = try reload(service, token: token) }) else { throw Failure(text: "fixture did not fail preflight") }
            let response = HelperSocketServer.errorResponse(error, service: service, peerPID: 42)
            try expect(!response.ok && response.errorCode == .physicalNetworkNotReady && response.sendsTunnelFileDescriptor != true,
                       "retryable service error lost typed code or promised a descriptor")
            try expect(response.state?.running == true && response.state?.phase == .running
                       && response.state?.networkCleanupPending == false && response.state?.sessionToken == token,
                       "retryable reply lost live owner/session identity")
            let wire = try JSONEncoder().encode(response), decoded = try JSONDecoder().decode(HajimiHelperResponse.self, from: wire)
            try expect(decoded.errorCode == .physicalNetworkNotReady && decoded.state?.sessionToken == token
                       && String(decoding: wire, as: UTF8.self).contains("physical-network-not-ready"), "machine code did not survive real wire coding")
            let otherPeer = HelperSocketServer.errorResponse(error, service: service, peerPID: 43)
            try expect(otherPeer.state?.sessionToken == nil, "retryable response disclosed another peer's token")
            let generic = HelperSocketServer.errorResponse(HelperServiceError.command("fixture ordinary failure"), service: service, peerPID: 42)
            try expect(generic.errorCode == nil && generic.state?.sessionToken == nil, "ordinary error gained retry code or unredacted owner token")
            try expect(fixture.mutations.isEmpty && service.state(clientPID: 42, renewLiveness: false).running, "error response mutated the live session")
            try clean(service, fixture, token: token)
        }
        #endif
    }
    private static func gatewayCases() {
        check("unchanged-gateway-keeps-existing-routes") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            let routes = fixture.routes
            let state = try reload(service, token: token)
            try expect(state.running && state.sessionToken == token && fixture.routes == routes,
                       "same gateway changed the active session or routes")
            try expect(!fixture.mutations.contains { $0.hasPrefix("add ") || $0.hasPrefix("delete ") },
                       "same gateway needlessly rewrote owned routes")
            try clean(service, fixture, token: token)
        }
        check("DHCP-new-gateway-replaces-owned-host-before-add") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            fixture.gateway = "192.0.2.254"
            let error = caught { _ = try reload(service, token: token) }
            let state = service.state(clientPID: 42, renewLiveness: false)
            if gatewayFixed {
                try expect(error == nil && state.running && state.sessionToken == token,
                           "new gateway hit EEXIST and tore down the session")
                try expect(fixture.routes["198.51.100.7"]?.gateway == fixture.gateway,
                           "new physical gateway was not installed")
                let deletion = fixture.commands.firstIndex(of: "/sbin/route -n delete -host 198.51.100.7 192.0.2.1")
                let addition = fixture.commands.firstIndex(of: "/sbin/route -n add -host 198.51.100.7 192.0.2.254")
                try expect(deletion != nil && addition != nil && deletion! < addition!,
                           "replacement add ran before the verified old destination was removed")
            } else {
                try expect(error != nil && !state.running && fixture.routes.isEmpty,
                           "Build38 did not reproduce same-destination EEXIST teardown")
                verifiedGatewayRegressions.append("gateway-host-EEXIST-teardown")
            }
            try clean(service, fixture, token: token)
        }
        check("DHCP-new-gateway-replaces-owned-network-before-add") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            _ = try service.reload(fakeIPEnabled: true, bypassAddresses: [],
                excludedRoutes: ["203.0.113.0/24"], caller: owner, sessionToken: token)
            fixture.resetObservations(); fixture.gateway = "192.0.2.254"
            let error = caught {
                _ = try service.reload(fakeIPEnabled: true, bypassAddresses: [],
                    excludedRoutes: ["203.0.113.0/24"], caller: owner, sessionToken: token)
            }
            if gatewayFixed {
                try expect(error == nil && service.state(clientPID: 42, renewLiveness: false).running,
                           "network bypass replacement tore down the session")
                try expect(fixture.routes["203.0.113.0/24"]?.gateway == fixture.gateway,
                           "network bypass retained the old gateway")
            } else {
                try expect(error != nil && !service.state(clientPID: 42, renewLiveness: false).running,
                           "Build38 network replacement no longer reproduces EEXIST")
                verifiedGatewayRegressions.append("gateway-network-EEXIST-teardown")
            }
            try clean(service, fixture, token: token)
        }
        for destination in ["198.51.100.7", "128.0.0.0/1"] {
            check("system-removed-owned-route-is-reinstalled-\(destination)") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                let expected = fixture.routes.removeValue(forKey: destination)
                try expect(expected != nil, "test did not remove an owned kernel route")
                let state = try reload(service, token: token)
                try expect(state.running && state.sessionToken == token, "missing-route repair replaced session")
                if gatewayFixed {
                    try expect(fixture.routes[destination] == expected, "unchanged inventory hid a missing kernel route")
                } else {
                    try expect(fixture.routes[destination] == nil, "Build38 no longer reproduces the stale inventory")
                    verifiedGatewayRegressions.append("missing-route-not-reinstalled-" + destination)
                }
                try clean(service, fixture, token: token)
            }
        }
        check("external-bypass-replacement-is-not-overwritten-or-deleted") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            let foreign = Route(destination: "198.51.100.7", gateway: "192.0.2.99",
                                interface: "en-fixture", host: true)
            fixture.routes[foreign.destination] = foreign
            let error = caught { _ = try reload(service, token: token) }
            if gatewayFixed {
                try expect(error != nil && !service.state(clientPID: 42, renewLiveness: false).running,
                           "foreign gateway replacement was silently accepted as owned")
            } else {
                try expect(error == nil && service.state(clientPID: 42, renewLiveness: false).running,
                           "Build38 no longer reproduces an unverified route inventory")
                verifiedGatewayRegressions.append("foreign-route-blindly-retained")
            }
            try expect(fixture.routes[foreign.destination] == foreign,
                       "foreign same-destination route was overwritten or deleted")
            _ = try service.stop(caller: owner, sessionToken: token)
            try expect(fixture.routes[foreign.destination] == foreign, "stop deleted the external route")
            fixture.routes.removeValue(forKey: foreign.destination)
            try clean(service, fixture, token: token)
        }
        if gatewayFixed {
            check("same-gateway-new-interface-replaces-owned-host") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                fixture.physical = "en-next"
                let state = try reload(service, token: token)
                try expect(state.running && state.physicalInterface == fixture.physical,
                           "same-gateway interface change stopped or kept the old state")
                try expect(fixture.routes["198.51.100.7"]?.interface == fixture.physical,
                           "same gateway hid a host route bound to the old physical interface")
                try clean(service, fixture, token: token)
            }
            check("external-same-gateway-other-interface-is-not-deleted") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                fixture.physical = "en-next"
                let foreign = Route(destination: "198.51.100.7", gateway: fixture.gateway,
                                    interface: fixture.physical, host: true)
                fixture.routes[foreign.destination] = foreign
                let state = try reload(service, token: token)
                try expect(state.running && fixture.routes[foreign.destination] == foreign,
                           "external same-gateway route on the new physical interface was replaced")
                _ = try service.stop(caller: owner, sessionToken: token)
                try expect(fixture.routes[foreign.destination] == foreign,
                           "old same-gateway ownership deleted an external route on another interface")
                fixture.routes.removeValue(forKey: foreign.destination)
                try clean(service, fixture, token: token)
            }
            check("external-tunnel-prefix-replacement-is-not-overwritten-or-deleted") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                let foreign = Route(destination: "128.0.0.0/1", gateway: "198.18.99.1",
                                    interface: "utun-foreign", host: false)
                fixture.routes[foreign.destination] = foreign
                let error = caught { _ = try reload(service, token: token) }
                try expect(error != nil && !service.state(clientPID: 42, renewLiveness: false).running,
                           "failed capture repair claimed the original tunnel was healthy")
                try expect(fixture.routes[foreign.destination] == foreign,
                           "foreign capture prefix was overwritten or deleted")
                fixture.routes.removeValue(forKey: foreign.destination)
                try clean(service, fixture, token: token)
            }
            check("externally-satisfied-bypass-stays-outside-delete-inventory") {
                let fixture = Fixture(), (service, token) = try started(fixture)
                fixture.gateway = "192.0.2.254"
                let foreign = Route(destination: "198.51.100.7", gateway: fixture.gateway,
                                    interface: fixture.physical, host: true)
                fixture.routes[foreign.destination] = foreign
                let state = try reload(service, token: token)
                try expect(state.running && fixture.routes[foreign.destination] == foreign,
                           "external correct physical route did not satisfy bypass")
                _ = try service.stop(caller: owner, sessionToken: token)
                try expect(fixture.routes[foreign.destination] == foreign,
                           "external physical route entered the Helper's delete inventory")
                fixture.routes.removeValue(forKey: foreign.destination)
                try clean(service, fixture, token: token)
            }
        }
        #if HAVE_ROUTE_REPLACEMENT
        check("gateway-replacement-rolls-back-in-inverse-kernel-order") {
            typealias Bypass = EnhancedTunnelService.InstalledBypassRoute
            typealias Mutation = EnhancedTunnelService.RouteMutation<Bypass>
            let old = Bypass(destination: "198.51.100.7", isIPv6: false, isNetwork: false, gateway: "192.0.2.1")
            let next = Bypass(destination: old.destination, isIPv6: false, isNetwork: false, gateway: "192.0.2.254")
            let later = Bypass(destination: "198.51.100.8", isIPv6: false, isNetwork: false, gateway: next.gateway)
            var active = [old.destination: old], order: [Mutation] = []
            let result = EnhancedTunnelService.transitionRouteInventory(from: [old], to: [next, later],
                label: { $0.destination }, replaces: { $0.hasSameDestination(as: $1) }) { mutation in
                order.append(mutation)
                switch mutation {
                case .add(let route):
                    if route == later { throw Failure(text: "injected later add failure") }
                    guard active[route.destination] == nil else { throw HelperServiceError.command("route: File exists") }
                    active[route.destination] = route
                case .remove(let route):
                    guard active[route.destination] == route else { throw HelperServiceError.command("route: not in table") }
                    active.removeValue(forKey: route.destination)
                }
            }
            try expect(result.failure != nil && !result.requiresTeardown && result.installed == [old]
                       && active == [old.destination: old], "replacement rollback did not restore the exact old gateway")
            try expect(order == [.remove(old), .add(next), .add(later), .remove(next), .add(old)],
                       "rollback tried to restore the old destination before withdrawing the new one")
        }
        check("gateway-replacement-rollback-failure-retains-cleanup-inventory") {
            typealias Bypass = EnhancedTunnelService.InstalledBypassRoute
            let old = Bypass(destination: "198.51.100.7", isIPv6: false, isNetwork: false, gateway: "192.0.2.1")
            let next = Bypass(destination: old.destination, isIPv6: false, isNetwork: false, gateway: "192.0.2.254")
            let later = Bypass(destination: "198.51.100.8", isIPv6: false, isNetwork: false, gateway: next.gateway)
            var active = [old.destination: old]
            let result = EnhancedTunnelService.transitionRouteInventory(from: [old], to: [next, later],
                label: { $0.destination }, replaces: { $0.hasSameDestination(as: $1) }) { mutation in
                switch mutation {
                case .add(let route):
                    if route == later { throw Failure(text: "injected later add failure") }
                    guard active[route.destination] == nil else { throw HelperServiceError.command("route: File exists") }
                    active[route.destination] = route
                case .remove(let route):
                    if route == next { throw Failure(text: "injected rollback delete failure") }
                    guard active[route.destination] == route else { throw HelperServiceError.command("route: not in table") }
                    active.removeValue(forKey: route.destination)
                }
            }
            try expect(result.failure != nil && result.requiresTeardown && !result.rollbackFailures.isEmpty,
                       "replacement rollback uncertainty was reported healthy")
            try expect(result.installed.contains(next) && active[next.destination] == next,
                       "rollback failure discarded the residual new route from cleanup inventory")
        }
        #endif
    }
    private static func startupReadinessCases() {
        #if HAVE_ROUTE_REPLACEMENT
        for fault in [Fixture.Fault.missing, .timeout, .noGateway, .noInterface] {
            check("cold-prepare-waits-without-acquiring-resources-\(fault)") {
                let fixture = Fixture(), service = EnhancedTunnelService(environment: fixture.environment())
                fixture.fault = fault
                guard let error = caught({
                    _ = try service.prepare(fakeIPEnabled: true, bypassAddresses: ["198.51.100.7"], clientPID: 42)
                }) else { throw Failure(text: "cold prepare ignored missing physical readiness") }
                let state = service.state(clientPID: 42, renewLiveness: false)
                try expect(typed(error) && !state.running && state.phase == nil && state.sessionToken == nil
                           && state.networkCleanupPending == false, "cold prepare did not return clean typed idle state")
                try expect(fixture.opened.isEmpty && fixture.mutations.isEmpty && fixture.routes.isEmpty
                           && fixture.dns == fixture.originals, "cold preflight opened utun or changed network state")
                let response = HelperSocketServer.errorResponse(error, service: service, peerPID: 42)
                try expect(response.errorCode == .physicalNetworkNotReady && response.sendsTunnelFileDescriptor != true
                           && response.state?.sessionToken == nil && response.state?.phase == nil,
                           "cold prepare error response promised resources or lost typed readiness")
                fixture.fault = .none
                let ready = try service.prepare(fakeIPEnabled: true, bypassAddresses: ["198.51.100.7"], clientPID: 42)
                service.finishHandoff(generation: ready.sessionGeneration, delivered: true)
                Darwin.close(ready.fileDescriptorToSend)
                let active = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42)
                try expect(active.running && fixture.opened.count == 1,
                           "a later fresh prepare did not recover after DHCP readiness")
                try clean(service, fixture, token: active.sessionToken!)
            }
        }
        for fault in [Fixture.Fault.missing, .timeout, .noGateway, .noInterface] {
            check("commit-preflight-waits-only-after-exact-session-cleanup-\(fault)") {
                let fixture = Fixture(), service = EnhancedTunnelService(environment: fixture.environment())
                let ready = try service.prepare(fakeIPEnabled: true, bypassAddresses: ["198.51.100.7"], clientPID: 42)
                service.finishHandoff(generation: ready.sessionGeneration, delivered: true)
                Darwin.close(ready.fileDescriptorToSend)
                fixture.resetObservations(); fixture.fault = fault
                guard let error = caught({ _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42) }) else {
                    throw Failure(text: "commit ignored missing physical readiness")
                }
                let state = service.state(clientPID: 42, renewLiveness: false)
                try expect(typed(error) && !state.running && state.phase == nil && state.sessionToken == nil
                           && state.networkCleanupPending == false
                           && state.lastRestoredSessionToken == ready.state.sessionToken,
                           "commit readiness did not acknowledge the exact fully cleaned generation")
                try expect(fixture.routes.isEmpty && fixture.scoped.isEmpty && fixture.dns == fixture.originals
                           && !fixture.mutations.contains { $0.hasPrefix("add ") || $0.hasPrefix("dns ") },
                           "commit preflight installed capture or changed DNS")
                try expect(fcntl(fixture.opened[0], F_GETFD) == -1, "failed commit retained the old utun descriptor")
                let response = HelperSocketServer.errorResponse(error, service: service, peerPID: 42)
                try expect(response.errorCode == .physicalNetworkNotReady && response.sendsTunnelFileDescriptor != true
                           && response.state?.lastRestoredSessionToken == ready.state.sessionToken,
                           "commit error response lost exact cleanup proof")
                let other = HelperSocketServer.errorResponse(error, service: service, peerPID: 43)
                try expect(other.state?.lastRestoredSessionToken == nil, "commit readiness disclosed another peer's cleanup token")
                try clean(service, fixture, token: ready.state.sessionToken!)
            }
        }
        check("commit-interface-change-requires-new-clean-generation") {
            let fixture = Fixture(), service = EnhancedTunnelService(environment: fixture.environment())
            let ready = try service.prepare(fakeIPEnabled: true, bypassAddresses: ["198.51.100.7"], clientPID: 42)
            service.finishHandoff(generation: ready.sessionGeneration, delivered: true)
            Darwin.close(ready.fileDescriptorToSend)
            fixture.resetObservations(); fixture.physical = "en-next"
            let error = caught { _ = try service.commit(sessionToken: ready.state.sessionToken, clientPID: 42) }
            let state = service.state(clientPID: 42, renewLiveness: false)
            try expect(typed(error) && state.lastRestoredSessionToken == ready.state.sessionToken
                       && state.networkCleanupPending == false && state.sessionToken == nil,
                       "commit interface change was not recoverable after verified cleanup")
            try expect(fixture.routes.isEmpty && fixture.dns == fixture.originals, "changed interface committed old startup plan")
            try clean(service, fixture, token: ready.state.sessionToken!)
        }
        check("busy-and-stale-commit-reject-before-physical-preflight") {
            let fixture = Fixture(), (service, token) = try started(fixture)
            fixture.fault = .missing
            let busy = caught { _ = try service.prepare(fakeIPEnabled: true, bypassAddresses: [], clientPID: 43) }
            let stale = caught { _ = try service.commit(sessionToken: "foreign-token", clientPID: 42) }
            try expect(busy != nil && !typed(busy) && stale != nil && !typed(stale)
                       && fixture.defaultReads == 0 && fixture.mutations.isEmpty,
                       "owner or stale-token rejection was changed into retryable physical absence")
            try expect(service.state(clientPID: 42, renewLiveness: false).sessionToken == token,
                       "unauthorized readiness probe replaced current ownership")
            try clean(service, fixture, token: token)
        }
        for fault in [Fixture.Fault.tunnel, .selfGateway, .loopback] {
            check("unsafe-cold-prepare-remains-protection-error-\(fault)") {
                let fixture = Fixture(), service = EnhancedTunnelService(environment: fixture.environment())
                fixture.fault = fault
                let error = caught { _ = try service.prepare(fakeIPEnabled: true, bypassAddresses: [], clientPID: 42) }
                try expect(error != nil && !typed(error) && fixture.opened.isEmpty && fixture.mutations.isEmpty,
                           "unsafe cold default acquired a tunnel or became a readiness retry")
            }
        }
        #endif
    }
    static func main() {
        after = CommandLine.arguments.last != "before"
        gatewayFixed = CommandLine.arguments.last != "before-gateway"
        if !gatewayFixed { gatewayCases() }
        else {
            transientCases(); recoveryCases(); protectionCases()
            if after { gatewayCases(); startupReadinessCases() }
            check("existing-prepare-commit-cleanup-watchdog-regression") { try EnhancedTunnelStartupSelfTest.run() }
        }
        let report: [String: Any] = ["expect": gatewayFixed ? (after ? "after" : "before") : "before-gateway", "groups": groups, "assertions": assertions,
            "failedGroups": failures, "verifiedLegacyRegressions": verifiedRegressions,
            "verifiedGatewayRegressions": verifiedGatewayRegressions, "realService": true,
            "networkAccess": false, "helperDaemonStarted": false, "systemSettingsChanged": false]
        print(String(data: try! JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!)
        if !failures.isEmpty { exit(1) }
    }
}

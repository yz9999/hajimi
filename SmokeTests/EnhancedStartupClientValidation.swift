import Foundation
import Dispatch
import Darwin

/// The runner inserts the real client session methods verbatim above this
/// extension. Only request()/the IPC transport is replaced; invalid server
/// replies exercise production validation and descriptor ownership.
extension PrivilegedHelperClient {
    private struct FixtureFailure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }

    private static func fixtureExpect(_ value: Bool, _ text: String) throws {
        if !value { throw FixtureFailure(text: text) }
    }

    static func runIsolatedStartupClientChecks() throws {
        try runIntentChecks()
        try runReplyValidationChecks()
        let client = PrivilegedHelperClient()
        let token = "fixture-generation-1"
        let prepared = HajimiHelperTunnelState(running: false, phase: .prepared,
            sessionToken: token, tunnelInterface: "utun-fixture0", physicalInterface: "en-fixture0")
        let original = open("/dev/null", O_RDONLY)
        try fixtureExpect(original >= 0, "cannot open memory fixture descriptor")
        client.fixtureResponse = DecodedHelperResponse(response: HajimiHelperResponse(
            ok: true, state: prepared, sendsTunnelFileDescriptor: true), fileDescriptor: original)
        let session = try client.prepare(fakeIPEnabled: true, bypassAddresses: ["203.0.113.7"],
            excludedRoutes: ["192.0.2.0/24"], includedRoutes: ["203.0.113.0/24"])
        defer { Darwin.close(session.fileDescriptor) }
        try fixtureExpect(session.state == prepared && session.fileDescriptor == original &&
                          fcntl(original, F_GETFD, 0) >= 0,
                          "valid prepared reply lost its live descriptor or generation")
        let prepareRequest = client.fixtureCalls.last!
        try fixtureExpect(prepareRequest.expectFD && prepareRequest.request.action == .prepare &&
                          prepareRequest.request.sessionToken == nil &&
                          prepareRequest.request.fakeIPEnabled == true &&
                          prepareRequest.request.bypassAddresses == ["203.0.113.7"] &&
                          prepareRequest.request.excludedRoutes == ["192.0.2.0/24"] &&
                          prepareRequest.request.includedRoutes == ["203.0.113.0/24"],
                          "prepare changed intent or did not require SCM_RIGHTS")

        var running = prepared
        running.running = true
        running.phase = .running
        client.fixtureResponse = DecodedHelperResponse(response: HajimiHelperResponse(
            ok: true, state: running), fileDescriptor: nil)
        let committed = try client.commit(sessionToken: token)
        try fixtureExpect(committed == running && client.fixtureCalls.last?.request.action == .commit &&
                          client.fixtureCalls.last?.request.sessionToken == token &&
                          client.fixtureCalls.last?.expectFD == false,
                          "commit did not bind the running reply to the prepared generation")

        var prepareRejects = 0, commitRejects = 0, stopRejects = 0
        func rejectPrepare(_ state: HajimiHelperTunnelState?, _ description: String,
                           descriptor: Bool = true, descriptorFlag: Bool? = true) throws {
            prepareRejects += 1
            let fd = descriptor ? open("/dev/null", O_RDONLY) : -1
            try fixtureExpect(!descriptor || fd >= 0, "cannot open rejected-reply fixture descriptor")
            client.fixtureResponse = DecodedHelperResponse(response: HajimiHelperResponse(
                ok: true, state: state, sendsTunnelFileDescriptor: descriptorFlag),
                fileDescriptor: descriptor ? fd : nil)
            var rejected = false
            do {
                let result = try client.prepare(fakeIPEnabled: false, bypassAddresses: [])
                Darwin.close(result.fileDescriptor)
            } catch { rejected = true }
            try fixtureExpect(rejected, "prepare accepted " + description)
            if descriptor {
                errno = 0
                try fixtureExpect(fcntl(fd, F_GETFD, 0) == -1 && errno == EBADF,
                                  "prepare leaked descriptor from " + description)
            }
        }
        var invalid = prepared
        invalid.phase = nil
        try rejectPrepare(invalid, "missing phase")
        try rejectPrepare(running, "running phase instead of reader preparation")
        invalid = prepared; invalid.phase = .committing
        try rejectPrepare(invalid, "committing phase")
        invalid = prepared; invalid.running = true
        try rejectPrepare(invalid, "running=true with prepared phase")
        invalid = prepared; invalid.sessionToken = nil
        try rejectPrepare(invalid, "missing session token")
        invalid = prepared; invalid.sessionToken = ""
        try rejectPrepare(invalid, "empty session token")
        invalid = prepared; invalid.tunnelInterface = nil
        try rejectPrepare(invalid, "missing tunnel interface")
        invalid = prepared; invalid.tunnelInterface = ""
        try rejectPrepare(invalid, "empty tunnel interface")
        invalid = prepared; invalid.physicalInterface = nil
        try rejectPrepare(invalid, "missing physical interface")
        invalid = prepared; invalid.physicalInterface = ""
        try rejectPrepare(invalid, "empty physical interface")
        invalid = prepared; invalid.helperProtocolVersion -= 1
        try rejectPrepare(invalid, "incompatible protocol")
        invalid = prepared; invalid.helperBuildRevision += 1
        try rejectPrepare(invalid, "incompatible helper revision")
        invalid = prepared; invalid.helperBuildRevision -= 1
        try rejectPrepare(invalid, "older helper without the scoped IPv6 route contract")
        invalid = prepared; invalid.networkCleanupPending = true
        try rejectPrepare(invalid, "network cleanup still pending")
        invalid = prepared; invalid.networkCleanupPending = nil
        try rejectPrepare(invalid, "unknown network cleanup state")
        try rejectPrepare(nil, "missing state")
        try rejectPrepare(prepared, "missing SCM_RIGHTS descriptor", descriptor: false)
        try rejectPrepare(prepared, "missing descriptor announcement", descriptorFlag: nil)
        try rejectPrepare(prepared, "false descriptor announcement", descriptorFlag: false)

        func rejectCommit(_ state: HajimiHelperTunnelState?, _ description: String) throws {
            commitRejects += 1
            client.fixtureResponse = DecodedHelperResponse(response: HajimiHelperResponse(
                ok: true, state: state), fileDescriptor: nil)
            var rejected = false
            do { _ = try client.commit(sessionToken: token) }
            catch { rejected = true }
            try fixtureExpect(rejected, "commit accepted " + description)
        }
        try rejectCommit(prepared, "a prepared state")
        invalid = running; invalid.running = false
        try rejectCommit(invalid, "running=false")
        invalid = running; invalid.phase = nil
        try rejectCommit(invalid, "missing phase")
        invalid = running; invalid.phase = .committing
        try rejectCommit(invalid, "unfinished committing phase")
        invalid = running; invalid.sessionToken = "previous-generation"
        try rejectCommit(invalid, "a stale generation token")
        invalid = running; invalid.sessionToken = nil
        try rejectCommit(invalid, "missing generation token")
        invalid = running; invalid.helperProtocolVersion -= 1
        try rejectCommit(invalid, "incompatible protocol")
        invalid = running; invalid.helperBuildRevision += 1
        try rejectCommit(invalid, "incompatible helper revision")
        invalid = running; invalid.helperBuildRevision -= 1
        try rejectCommit(invalid, "older helper without the scoped IPv6 route contract")
        invalid = running; invalid.networkCleanupPending = true
        try rejectCommit(invalid, "network cleanup still pending")
        invalid = running; invalid.networkCleanupPending = nil
        try rejectCommit(invalid, "unknown network cleanup state")
        invalid = running; invalid.tunnelInterface = nil
        try rejectCommit(invalid, "missing tunnel interface")
        invalid = running; invalid.tunnelInterface = ""
        try rejectCommit(invalid, "empty tunnel interface")
        invalid = running; invalid.physicalInterface = nil
        try rejectCommit(invalid, "missing physical interface")
        invalid = running; invalid.physicalInterface = ""
        try rejectCommit(invalid, "empty physical interface")
        try rejectCommit(nil, "missing state")

        var stopped = HajimiHelperTunnelState(running: false)
        stopped.lastRestoredSessionToken = token
        client.fixtureResponse = DecodedHelperResponse(response: HajimiHelperResponse(
            ok: true, state: stopped), fileDescriptor: nil)
        _ = try client.stop(sessionToken: token)
        try fixtureExpect(client.fixtureCalls.last?.request.action == .stop &&
                          client.fixtureCalls.last?.request.sessionToken == token,
                          "rollback omitted the prepared session token")
        func rejectStop(_ state: HajimiHelperTunnelState?, _ description: String) throws {
            stopRejects += 1
            client.fixtureResponse = DecodedHelperResponse(response: HajimiHelperResponse(
                ok: true, state: state), fileDescriptor: nil)
            var rejected = false
            do { _ = try client.stop(sessionToken: token) }
            catch { rejected = true }
            try fixtureExpect(rejected, "stop accepted " + description)
        }
        invalid = stopped; invalid.networkCleanupPending = true
        try rejectStop(invalid, "unrestored system network")
        invalid = stopped; invalid.networkCleanupPending = nil
        try rejectStop(invalid, "unknown system network restoration")
        invalid = stopped; invalid.running = true
        try rejectStop(invalid, "a running tunnel")
        invalid = stopped; invalid.phase = .prepared
        try rejectStop(invalid, "a prepared tunnel")
        invalid = stopped; invalid.sessionToken = token
        try rejectStop(invalid, "a retained live generation")
        invalid = stopped; invalid.helperProtocolVersion -= 1
        try rejectStop(invalid, "incompatible protocol")
        invalid = stopped; invalid.helperBuildRevision += 1
        try rejectStop(invalid, "incompatible helper revision")
        invalid = stopped; invalid.helperBuildRevision -= 1
        try rejectStop(invalid, "older helper without the scoped IPv6 cleanup contract")
        invalid = stopped; invalid.lastRestoredSessionToken = nil
        try rejectStop(invalid, "missing restoration acknowledgement for the prepared generation")
        invalid = stopped; invalid.lastRestoredSessionToken = "previous-generation"
        try rejectStop(invalid, "another generation's restoration acknowledgement")
        try rejectStop(HajimiHelperTunnelState(running: false),
                       "a restarted Helper's empty inventory as proof of old network restoration")
        try rejectStop(nil, "missing state")
        print("PASS exact startup client methods: valid prepare/commit, \(prepareRejects) invalid prepare replies with descriptor cleanup, \(commitRejects) invalid commits, \(stopRejects) unconfirmed stops, generation-bound stop; fake IPC only")
    }

    /// Exercise the real response validator without opening an IPC socket.
    private static func runReplyValidationChecks() throws {
        enum Outcome: Equatable { case accepted, waiting, helperFailure, invalid }
        var checks = 0
        func check(_ response: HajimiHelperResponse, request: HajimiHelperRequest,
                   expectFD: Bool = false, outcome: Outcome, _ text: String) throws {
            checks += 1
            let actual: Outcome
            do {
                try validateResponse(response, for: request, expectFileDescriptor: expectFD)
                actual = .accepted
            } catch ClientError.physicalNetworkNotReady {
                actual = .waiting
            } catch ClientError.invalidResponse {
                actual = .invalid
            } catch {
                actual = .helperFailure
            }
            try fixtureExpect(actual == outcome, "reply validation: " + text)
        }
        let token = "memory-owned-reload"
        let request = HajimiHelperRequest(action: .reload, sessionToken: token)
        let running = HajimiHelperTunnelState(running: true, phase: .running, sessionToken: token,
            tunnelInterface: "utun-fixture", physicalInterface: "en-fixture")
        let waiting = HajimiHelperResponse(ok: false, message: "memory preflight deferred",
            errorCode: .physicalNetworkNotReady, state: running)
        try check(waiting, request: request, outcome: .waiting, "owned zero-mutation preflight")
        for action in [HajimiHelperRequest.Action.ping, .status, .prepare, .commit, .start, .stop] {
            try check(waiting, request: HajimiHelperRequest(action: action, sessionToken: token),
                      outcome: .helperFailure, "wait code on another operation")
        }
        for invalidToken in [nil, "", "other-owner"] as [String?] {
            try check(waiting, request: HajimiHelperRequest(action: .reload, sessionToken: invalidToken),
                      outcome: .helperFailure, "missing or stale request token")
        }
        var variants: [HajimiHelperTunnelState] = []
        var state = running; state.helperProtocolVersion -= 1; variants.append(state)
        state = running; state.helperBuildRevision -= 1; variants.append(state)
        state = running; state.helperBuildRevision += 1; variants.append(state)
        state = running; state.running = false; variants.append(state)
        for phase in [nil, .prepared, .committing] as [HajimiHelperTunnelPhase?] {
            state = running; state.phase = phase; variants.append(state)
        }
        for invalidToken in [nil, "", "other-owner"] as [String?] {
            state = running; state.sessionToken = invalidToken; variants.append(state)
        }
        for pending in [nil, true] as [Bool?] {
            state = running; state.networkCleanupPending = pending; variants.append(state)
        }
        state = running; state.tunnelInterface = nil; variants.append(state)
        state = running; state.tunnelInterface = ""; variants.append(state)
        state = running; state.physicalInterface = nil; variants.append(state)
        state = running; state.physicalInterface = ""; variants.append(state)
        for invalid in variants {
            var response = waiting; response.state = invalid
            try check(response, request: request, outcome: .helperFailure, "invalid owned snapshot")
        }
        var response = waiting; response.state = nil
        try check(response, request: request, outcome: .helperFailure, "missing snapshot")
        response = waiting; response.errorCode = nil
        try check(response, request: request, outcome: .helperFailure, "ordinary error is preserved")
        response = waiting; response.sendsTunnelFileDescriptor = true
        try check(response, request: request, outcome: .helperFailure, "unexpected FD announcement")
        try check(waiting, request: request, expectFD: true, outcome: .helperFailure, "FD wait is forbidden")
        response = waiting; response.ok = true
        try check(response, request: request, outcome: .invalid, "success cannot carry an error code")
        try check(HajimiHelperResponse(ok: true, state: running), request: request,
                  outcome: .accepted, "ordinary reload reply")
        try check(HajimiHelperResponse(ok: true, sendsTunnelFileDescriptor: true),
                  request: HajimiHelperRequest(action: .prepare), expectFD: true,
                  outcome: .accepted, "prepare retains its FD contract")
        try check(HajimiHelperResponse(ok: true), request: HajimiHelperRequest(action: .prepare),
                  expectFD: true, outcome: .invalid, "missing announced FD")
        let prepareRequest = HajimiHelperRequest(action: .prepare)
        let commitRequest = HajimiHelperRequest(action: .commit, sessionToken: token)
        let idle = HajimiHelperTunnelState(running: false)
        let idleWait = HajimiHelperResponse(ok: false, errorCode: .physicalNetworkNotReady, state: idle)
        try check(idleWait, request: prepareRequest, expectFD: true, outcome: .waiting,
                  "prepare preflight left no ownership, routes or FD")
        try check(idleWait, request: prepareRequest, outcome: .helperFailure, "prepare requires the real FD contract")
        try check(idleWait, request: HajimiHelperRequest(action: .prepare, sessionToken: token),
                  expectFD: true, outcome: .helperFailure, "prepare cannot borrow a running token")
        try check(idleWait, request: commitRequest, outcome: .helperFailure, "empty daemon state cannot prove prepared cleanup")
        var restored = idle; restored.lastRestoredSessionToken = token
        let commitWait = HajimiHelperResponse(ok: false, errorCode: .physicalNetworkNotReady, state: restored)
        try check(commitWait, request: commitRequest, outcome: .waiting, "commit preflight restored its exact prepared generation")
        try check(commitWait, request: commitRequest, expectFD: true, outcome: .helperFailure, "commit cannot announce an FD")
        for action in [HajimiHelperRequest.Action.ping, .status, .start, .stop, .reload] {
            try check(commitWait, request: HajimiHelperRequest(action: action, sessionToken: token),
                      outcome: .helperFailure, "idle wait is valid only for prepare or exact restored commit")
        }
        for requestToken in [nil, "", "wrong-generation"] as [String?] {
            try check(commitWait, request: HajimiHelperRequest(action: .commit, sessionToken: requestToken),
                      outcome: .helperFailure, "commit wait requires a matching nonempty request token")
        }
        var idleVariants: [HajimiHelperTunnelState] = []
        state = restored; state.running = true; idleVariants.append(state)
        for phase in [HajimiHelperTunnelPhase.prepared, .committing, .running] {
            state = restored; state.phase = phase; idleVariants.append(state)
        }
        for pending in [nil, true] as [Bool?] {
            state = restored; state.networkCleanupPending = pending; idleVariants.append(state)
        }
        state = restored; state.helperProtocolVersion -= 1; idleVariants.append(state)
        state = restored; state.helperBuildRevision -= 1; idleVariants.append(state)
        state = restored; state.helperBuildRevision += 1; idleVariants.append(state)
        state = restored; state.sessionToken = token; idleVariants.append(state)
        state = restored; state.sessionToken = ""; idleVariants.append(state)
        state = restored; state.tunnelInterface = "utun-old"; idleVariants.append(state)
        state = restored; state.physicalInterface = "en-old"; idleVariants.append(state)
        for invalid in idleVariants {
            let badWait = HajimiHelperResponse(ok: false, errorCode: .physicalNetworkNotReady, state: invalid)
            try check(badWait, request: prepareRequest, expectFD: true, outcome: .helperFailure, "prepare wait requires a verified empty state")
            try check(badWait, request: commitRequest, outcome: .helperFailure, "commit wait requires verified cleanup of its generation")
        }
        var invalidWait = commitWait; invalidWait.sendsTunnelFileDescriptor = true
        try check(invalidWait, request: commitRequest, outcome: .helperFailure, "waiting commit must not transfer a descriptor")
        invalidWait = idleWait; invalidWait.errorCode = nil
        try check(invalidWait, request: prepareRequest, expectFD: true, outcome: .helperFailure, "generic prepare failures never trigger retries")
        let legacy = try JSONDecoder().decode(HajimiHelperResponse.self, from: Data(#"{"ok":false,"message":"legacy"}"#.utf8))
        try fixtureExpect(legacy.errorCode == nil, "old responses must remain decodable")
        try check(legacy, request: request, outcome: .helperFailure, "legacy error remains a failure")
        let unknown = try? JSONDecoder().decode(HajimiHelperResponse.self,
            from: Data(#"{"ok":false,"errorCode":"unknown-future-code"}"#.utf8))
        try fixtureExpect(unknown == nil, "unknown error code must not become a wait signal")
        print("Helper reply validation passed: \(checks) cases plus legacy/unknown-code decoding; idle prepare, restored commit, owned reload, token, revision, phase, cleanup and FD fences")
    }

    /// A blocked manager queue must not hide a stop request. Delayed callbacks
    /// then lose their startup ticket even if a new generation has begun.
    private static func runIntentChecks() throws {
        let intent = EnhancedStartupIntent()
        guard let first = intent.reserve() else { throw FixtureFailure(text: "initial startup reservation failed") }
        try fixtureExpect(intent.reserve() == nil, "overlapping startup obtained a second ownership inventory")
        let blocked = DispatchSemaphore(value: 0), proceed = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0), resultLock = NSLock()
        var staleMayCommit = true
        DispatchQueue(label: "startup-intent-blocked-fixture").async {
            blocked.signal()
            _ = proceed.wait(timeout: .now() + 2)
            let current = intent.isCurrent(first)
            resultLock.lock(); staleMayCommit = current; resultLock.unlock()
            finished.signal()
        }
        try fixtureExpect(blocked.wait(timeout: .now() + 1) == .success, "startup worker did not block")
        try fixtureExpect(intent.cancel() == first && !intent.isCurrent(first),
                          "stop did not revoke a ticket outside the blocked manager queue")
        proceed.signal()
        try fixtureExpect(finished.wait(timeout: .now() + 1) == .success, "cancelled startup callback did not finish")
        resultLock.lock(); let wasStale = !staleMayCommit; resultLock.unlock()
        try fixtureExpect(wasStale, "late startup callback retained commit authority")
        try fixtureExpect(intent.reserve() == nil, "cancelled resources were reusable before cleanup acknowledgement")
        intent.release(first)
        guard let next = intent.reserve() else { throw FixtureFailure(text: "cleaned startup reservation was not reusable") }
        intent.release(first)
        try fixtureExpect(next != first && !intent.isCurrent(first) && intent.isCurrent(next) && intent.reserve() == nil,
                          "late cleanup released a replacement startup generation")
        intent.release(next)

        let race = EnhancedStartupIntent(), group = DispatchGroup(), winnersLock = NSLock()
        var winners: [EnhancedStartupIntent.Ticket] = []
        for _ in 0..<64 {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { group.leave() }
                if let ticket = race.reserve() {
                    winnersLock.lock(); winners.append(ticket); winnersLock.unlock()
                }
            }
        }
        try fixtureExpect(group.wait(timeout: .now() + 2) == .success, "concurrent startup reservations did not finish")
        winnersLock.lock(); let reserved = winners; winnersLock.unlock()
        try fixtureExpect(reserved.count == 1 && race.isCurrent(reserved[0]),
                          "concurrent startup reservations produced multiple owners")
        race.release(reserved[0])
        print("PASS startup intent: stop revokes blocked startup, cleanup retains reservation, old callbacks cannot release replacement, 64 concurrent reservations yield one owner")
    }
}

@main
struct EnhancedStartupClientMain {
    static func main() {
        do { try PrivilegedHelperClient.runIsolatedStartupClientChecks() }
        catch {
            FileHandle.standardError.write(Data(("FAIL startup client: " + error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }
}

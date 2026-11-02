import Foundation

@main
enum DNSAttemptDiagnosticsMain {
    static func main() throws {
        try NetworkPerformanceDiagnosticsSelfTest.run()
        try queryProgressAndLineage()
        try startupFailureRetention()
        try questionAndExtendedErrorMetadata()
        print("DNS attempt diagnostics passed: bounded correlation, original errors, privacy, progress generations and callback ordering")
    }

    private struct Failure: Error { let message: String }
    private static func queryProgressAndLineage() throws {
        func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
            if !condition() { throw Failure(message: message) }
        }
        let context = DNSQueryExecutionContext(), child = context.child()
        try check(context.rootID == child.rootID && context.candidateID != child.candidateID,
                  "child changed the logical root or reused its candidate ID")
        let original = UUID(), replacement = UUID()
        context.beginConnectionAttempt(original)
        context.record(.transportStarted, attemptID: original, at: 10)
        context.record(.transportReady, attemptID: original, at: 11)
        context.record(.tlsStarted, attemptID: original, at: 11.1)
        context.record(.tlsReady, attemptID: original, at: 13)
        context.record(.querySendStarted, attemptID: original, at: 13.1)
        context.record(.querySent, attemptID: original, at: 13.2)
        context.record(.tlsStarted, attemptID: original, at: 9)
        try check(context.progress().stage == .awaitingResponse && context.progress().changedAt == 13.2,
                  "late handshake regressed an actual query send")
        context.record(.responseStarted, attemptID: original, at: 13.3)
        context.record(.responseComplete, attemptID: original, at: 13.4)
        let complete = context.progress()
        try check(complete.transportStartedAt == 10 && complete.transportReadyAt == 11
                  && complete.tlsStartedAt == 11.1 && complete.tlsReadyAt == 13
                  && complete.querySentAt == 13.2 && complete.responseStartedAt == 13.3
                  && complete.responseCompletedAt == 13.4 && complete.stage == .completed,
                  "real phase timestamps were lost or overwritten")
        context.record(.requestFinished, attemptID: original, at: 13.5)
        context.beginConnectionAttempt(replacement)
        context.record(.responseComplete, attemptID: original, at: 20)
        context.record(.transportStarted, attemptID: replacement, at: 14)
        context.record(.tlsStarted, attemptID: replacement, at: 15)
        try check(context.progress().stage == .tlsHandshaking && context.progress().tlsReadyAt == nil
                  && context.progress().querySentAt == nil && context.progress().responseCompletedAt == nil,
                  "fresh retry retained reused stamps or admitted an old generation")

        let diagnostics = NetworkPerformanceDiagnostics(maximumDNSAttempts: 2)
        let exchange = diagnostics.beginDNSExchange(requestID: UUID(), context: child,
            transport: .doh, endpointIdentity: "https://private.invalid/private-token")
        exchange.record(.connectionReused)
        exchange.record(.querySendStarted); exchange.record(.querySent)
        exchange.record(.responseStarted); exchange.record(.responseComplete)
        exchange.finish(.success, failureReason: nil)
        let reused = diagnostics.snapshot().dnsQueryExchanges[0]
        try check(reused.rootID == child.rootID && reused.candidateID == child.candidateID
                  && reused.reusedConnection && reused.physicalAttemptIDs.isEmpty
                  && reused.observations.map(\.event) == [.connectionReused, .querySendStarted,
                    .querySent, .responseStarted, .responseComplete, .requestFinished]
                  && diagnostics.snapshot().dnsConnectionAttempts.isEmpty
                  && child.progress().tlsStartedAt == nil && child.progress().stage == .completed,
                  "reused connection invented a physical dial or lost query timings")
        let native = diagnostics.beginDNSAttempt(requestID: UUID(), transport: .doh, purpose: .query,
            serverName: "private.invalid", endpointIdentity: "https://private.invalid/private-token",
            address: "203.0.113.53", context: context)
        native.record(.transportStarted)
        native.cancel(.winnerSelected); native.record(.localCancel)
        native.record(.rawFailure, error: NSError(domain: "app.hajimi.cpp-protocol", code: 1))
        let postCancel = diagnostics.snapshot().dnsConnectionAttempts[0]
        try check(postCancel.rootID == context.rootID && postCancel.candidateID == context.candidateID
                  && postCancel.firstError?.codes.first?.code == 1
                  && postCancel.firstErrorBeforeCancellation == nil,
                  "post-cancel C++ callback became an initial failure or lost its original code")

        let leader = UUID(), waiterIDs = (0..<90).map { _ in UUID() }, root = UUID()
        diagnostics.beginDNSQuery(rootID: root, waiterID: leader, started: 1, absoluteDeadline: 10)
        for id in waiterIDs { diagnostics.joinDNSQuery(rootID: root, waiterID: id, started: 2, absoluteDeadline: 10) }
        diagnostics.finishDNSQueryWaiter(rootID: root, waiterID: leader, outcome: .failure,
            failureReason: .timeout, milliseconds: 9)
        diagnostics.finishDNSQueryWaiter(rootID: root, waiterID: leader, outcome: .failure,
            failureReason: .timeout, milliseconds: 9)
        for id in waiterIDs { diagnostics.finishDNSQueryWaiter(rootID: root, waiterID: id,
            outcome: .success, failureReason: nil, milliseconds: 3) }
        let logical = diagnostics.snapshot().dnsLogicalQueries[0]
        try check(logical.waiters.count == 64 && logical.admittedCount == 91 && logical.mergedCount == 90
                  && logical.finishedCount == 91 && logical.omittedWaiters == 27
                  && logical.outcomeCounts == ["success": 90, "failure": 1]
                  && logical.failureCounts == ["timeout": 1],
                  "bounded merged-query records lost outcomes or counted one waiter twice")
        diagnostics.beginDNSQuery(rootID: UUID(), waiterID: UUID(), started: 3, absoluteDeadline: 10)
        diagnostics.beginDNSQuery(rootID: UUID(), waiterID: UUID(), started: 4, absoluteDeadline: 10)
        diagnostics.finishDNSQueryWaiter(rootID: root, waiterID: leader, outcome: .success,
            failureReason: nil, milliseconds: 3)
        try check(diagnostics.snapshot().dnsLogicalQueries.first(where: { $0.rootID == root })?.finishedCount == 91,
                  "ordinary churn erased the retained failure or duplicate completion changed its counts")
        let newerRoot = UUID(), newerWaiter = UUID()
        diagnostics.beginDNSQuery(rootID: newerRoot, waiterID: newerWaiter, started: 5, absoluteDeadline: 10)
        diagnostics.finishDNSQueryWaiter(rootID: newerRoot, waiterID: newerWaiter, outcome: .failure,
            failureReason: .timeout, milliseconds: 1)
        diagnostics.beginDNSQuery(rootID: UUID(), waiterID: UUID(), started: 6, absoluteDeadline: 10)
        diagnostics.finishDNSQueryWaiter(rootID: root, waiterID: leader, outcome: .success,
            failureReason: nil, milliseconds: 3)
        try check(diagnostics.snapshot().dnsLogicalQueries.count == 2
                  && !diagnostics.snapshot().dnsLogicalQueries.contains(where: { $0.rootID == root }),
                  "late completion recreated an evicted logical query")
        let json = String(data: try JSONEncoder().encode(diagnostics.snapshot().dnsQueryExchanges), encoding: .utf8)!
        try check(!json.contains("private") && !json.contains("203.0.113"), "exchange exported endpoint data")
        diagnostics.reset()
        exchange.record(.responseComplete)
        try check(diagnostics.snapshot() == NetworkPerformanceSnapshot(), "late exchange recreated reset diagnostics")
    }

    private static func questionAndExtendedErrorMetadata() throws {
        func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
            if !condition() { throw Failure(message: message) }
        }
        let diagnostics = NetworkPerformanceDiagnostics(maximumDNSAttempts: 1)
        let trace = diagnostics.beginDNSExchange(requestID: UUID(), context: nil,
            transport: .doh, endpointIdentity: "https://private.invalid/credential")
        trace.recordQuestion(type: 65)
        trace.recordQuestion(type: 28)
        trace.recordResponse(httpStatusCode: 200, dnsResponseCode: 2,
            extendedDNSErrorCodes: [6, 6, UInt16.max, 0, 15, 23, 24, 25, 26, 27])
        trace.recordResponse(extendedDNSErrorCodes: [])
        trace.finish(.success, failureReason: nil)
        let first = diagnostics.snapshot().dnsQueryExchanges[0]
        try check(first.queryType == 65 && first.extendedDNSErrorCodes == [6, UInt16.max, 0, 15, 23, 24, 25, 26],
                  "QTYPE or bounded distinct EDE codes lost zero/unknown values or were overwritten")
        try check(first.outcome == .success && first.dnsResponseCode == 2
                  && diagnostics.snapshot().dnsFailures == 0,
                  "numeric EDE metadata changed wire outcomes or invented logical failure counts")
        let data = try JSONEncoder().encode(first)
        let decoded = try JSONDecoder().decode(DNSQueryExchangeSnapshot.self, from: data)
        try check(decoded.id == first.id && decoded.queryType == first.queryType
                  && decoded.extendedDNSErrorCodes == first.extendedDNSErrorCodes
                  && decoded.httpStatusCode == first.httpStatusCode && decoded.dnsResponseCode == first.dnsResponseCode,
                  "QTYPE/EDE diagnostic round trip changed numeric metadata or exchange identity")
        let text = String(decoding: data, as: UTF8.self)
        try check(!text.contains("private.invalid") && !text.contains("credential"),
                  "QTYPE/EDE diagnostic metadata exported endpoint text")
        var legacy = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        for key in ["queryType", "extendedDNSErrorCodes"] { legacy.removeValue(forKey: key) }
        let legacyDecoded = try JSONDecoder().decode(DNSQueryExchangeSnapshot.self,
            from: JSONSerialization.data(withJSONObject: legacy))
        try check(legacyDecoded.queryType == nil && legacyDecoded.extendedDNSErrorCodes == nil
                  && legacyDecoded.httpStatusCode == 200 && legacyDecoded.dnsResponseCode == 2,
                  "QTYPE/EDE fields broke decoding of Build19 schema-2 exchanges")
        let replacement = diagnostics.beginDNSExchange(requestID: UUID(), context: nil,
            transport: .dot, endpointIdentity: "dot.invalid")
        trace.recordQuestion(type: 1)
        trace.recordResponse(extendedDNSErrorCodes: [4])
        let current = diagnostics.snapshot().dnsQueryExchanges
        try check(current.count == 1 && current[0].id == replacement.id
                  && current[0].queryType == nil && current[0].extendedDNSErrorCodes == nil,
                  "late QTYPE/EDE receipts recreated an evicted exchange")
        diagnostics.reset()
        replacement.recordQuestion(type: 1)
        replacement.recordResponse(extendedDNSErrorCodes: [23])
        try check(diagnostics.snapshot() == NetworkPerformanceSnapshot(),
                  "late numeric DNS metadata recreated reset diagnostics")
        print("DNS QTYPE/EDE diagnostics passed: numeric-only, first question, distinct eight-code bound, zero/unknown codes, schema-2 compatibility and stale receipts")
    }

    private static func startupFailureRetention() throws {
        func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
            if !condition() { throw Failure(message: message) }
        }
        let diagnostics = NetworkPerformanceDiagnostics()
        func exchange(_ index: Int, failed: Bool) -> (root: UUID, exchange: UUID, physical: UUID) {
            let context = DNSQueryExecutionContext(), waiter = UUID()
            diagnostics.beginDNSQuery(rootID: context.rootID, waiterID: waiter,
                started: UInt64(index + 1), absoluteDeadline: 100)
            let trace = diagnostics.beginDNSExchange(requestID: UUID(), context: context,
                transport: .doh, endpointIdentity: "https://private.invalid/credential")
            let physical = diagnostics.beginDNSAttempt(requestID: UUID(), transport: .doh,
                purpose: .query, serverName: "private.invalid",
                endpointIdentity: "https://private.invalid/credential", address: "203.0.113.53", context: context)
            trace.attachPhysicalAttempt(physical.id)
            if failed {
                physical.recordRawEOF(peerCiphertextBytes: 0)
                physical.record(.tlsFailure, error: NSError(domain: "app.hajimi.nested-tls-carrier", code: 2))
                physical.complete(.dnsTLSHandshake, outcome: .failure)
                trace.recordResponse(httpStatusCode: 503, responseBytes: 81,
                    dnsResponseCode: 2, rejection: "httpFraming")
                trace.finish(.failure, failureReason: "network")
            } else {
                physical.complete(.dnsTLSHandshake, outcome: .success)
                trace.recordResponse(httpStatusCode: 200, responseBytes: 100, dnsResponseCode: 0)
                trace.finish(.success, failureReason: nil)
            }
            physical.record(.requestFinished)
            diagnostics.finishDNSQueryWaiter(rootID: context.rootID, waiterID: waiter,
                outcome: failed ? .failure : .success,
                failureReason: failed ? .upstreamOrResponse : nil, milliseconds: 100)
            return (context.rootID, trace.id, physical.id)
        }
        let startup = (0..<9).map { exchange($0, failed: true) }
        var latest: (root: UUID, exchange: UUID, physical: UUID)!
        for index in 9..<409 { latest = exchange(index, failed: false) }
        let snapshot = diagnostics.snapshot()
        try check(snapshot.dnsLogicalQueries.count == 128 && snapshot.dnsQueryExchanges.count == 128
                  && snapshot.dnsConnectionAttempts.count == 128, "diagnostic retention grew beyond the existing bounds")
        for record in startup {
            try check(snapshot.dnsLogicalQueries.contains { $0.rootID == record.root }
                      && snapshot.dnsQueryExchanges.contains { $0.id == record.exchange }
                      && snapshot.dnsConnectionAttempts.contains { $0.id == record.physical },
                      "400 ordinary successes erased a startup failure")
        }
        try check(snapshot.dnsLogicalQueries.contains { $0.rootID == latest.root }
                  && snapshot.dnsQueryExchanges.contains { $0.id == latest.exchange }
                  && snapshot.dnsConnectionAttempts.contains { $0.id == latest.physical },
                  "preserving failures prevented recent successful records from rotating")
        let first = snapshot.dnsQueryExchanges.first { $0.id == startup[0].exchange }!
        let origin = snapshot.dnsConnectionAttempts.first { $0.id == startup[0].physical }!
        try check(first.httpStatusCode == 503 && first.responseBytes == 81
                  && first.dnsResponseCode == 2 && first.responseRejection == "httpFraming"
                  && origin.firstCarrierClosure?.peerCiphertextBytes == 0
                  && origin.firstError?.codes.first?.domain == "app.hajimi.nested-tls-carrier",
                  "bounded response/EOF metadata or original closure source was lost")
        let data = try JSONEncoder().encode(snapshot.dnsQueryExchanges)
        let json = String(decoding: data, as: UTF8.self)
        try check(!json.contains("private.invalid") && !json.contains("credential")
                  && !json.contains("203.0.113"), "metadata exposed endpoint or payload data")
        var old = try JSONSerialization.jsonObject(with: JSONEncoder().encode(first)) as! [String: Any]
        for key in ["httpStatusCode", "responseBytes", "dnsResponseCode", "responseRejection"] { old.removeValue(forKey: key) }
        let decoded = try JSONDecoder().decode(DNSQueryExchangeSnapshot.self,
            from: JSONSerialization.data(withJSONObject: old))
        try check(decoded.httpStatusCode == nil && decoded.responseBytes == nil,
                  "new optional response metadata broke old diagnostic decoding")
        var oldPhysical = try JSONSerialization.jsonObject(with: JSONEncoder().encode(origin)) as! [String: Any]
        var oldObservations = oldPhysical["observations"] as! [[String: Any]]
        for index in oldObservations.indices { oldObservations[index].removeValue(forKey: "peerCiphertextBytes") }
        oldPhysical["observations"] = oldObservations
        for key in ["firstCarrierClosure", "firstLocalCancellation", "firstCancellationRequest"] {
            if var observation = oldPhysical[key] as? [String: Any] {
                observation.removeValue(forKey: "peerCiphertextBytes")
                oldPhysical[key] = observation
            }
        }
        let decodedPhysical = try JSONDecoder().decode(DNSConnectionAttemptSnapshot.self,
            from: JSONSerialization.data(withJSONObject: oldPhysical))
        try check(decodedPhysical.firstCarrierClosure?.peerCiphertextBytes == nil
                  && decodedPhysical.firstCarrierClosure != nil,
                  "new optional EOF byte count broke old physical diagnostic decoding")
        for index in 409..<609 { _ = exchange(index, failed: true) }
        let rotated = diagnostics.snapshot()
        try check(rotated.dnsLogicalQueries.count == 128 && rotated.dnsQueryExchanges.count == 128
                  && rotated.dnsConnectionAttempts.count == 128
                  && !rotated.dnsLogicalQueries.contains { $0.rootID == startup[0].root },
                  "new failures could not replace old failures within the existing capacity")
        try check(rotated.dnsQueries == 0 && rotated.dnsFailures == 0,
                  "trace retention invented aggregate queries or failures")
        diagnostics.reset()
        try check(diagnostics.snapshot() == NetworkPerformanceSnapshot(), "reset retained protected failures")
        print("DNS startup failure retention passed: 9 failures survive 400 successes; 128-slot bounds, new-failure rotation, raw-EOF bytes, numeric response metadata, privacy and old-schema decoding")
    }
}

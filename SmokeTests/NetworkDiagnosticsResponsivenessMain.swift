import AppKit
import HajimiCore
import HajimiDiagnosticsUI
import HajimiRuntime
import HajimiUIComponents

/// Actual presentation and scroll layout with bounded synthetic reports.
/// The window is never shown; providers and report copies stay in memory.
@main private enum NetworkDiagnosticsResponsivenessMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private final class Audit {
        private let lock = NSLock()
        private var count = 0
        private var mainCalls = 0
        func record() { lock.lock(); count += 1; if Thread.isMainThread { mainCalls += 1 }; lock.unlock() }
        var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
        var callsOnMain: Int { lock.lock(); defer { lock.unlock() }; return mainCalls }
    }
    private final class HeldStatistics {
        let audit = Audit()
        private let permits = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var returned = 0
        private let scheduler = ProbeScheduler(maximumActive: 1, maximumQueued: 1)
        var completed: Int { lock.lock(); defer { lock.unlock() }; return returned }
        func release() { permits.signal() }
        func read() -> NetworkDiagnosticsStatistics {
            audit.record()
            let ordinal = audit.calls
            precondition(permits.wait(timeout: .now() + 5) == .success, "Fixture statistics provider was not released")
            let value = UInt64(ordinal * 11)
            let snapshot = NetworkPerformanceSnapshot(dnsQueries: value, dnsFailures: value,
                dnsFailureReasons: [.timeout: value],
                stages: [.dnsResolution: .init(count: value, failureCount: value)])
            lock.lock(); returned += 1; lock.unlock()
            return .init(performance: snapshot, scheduler: scheduler.snapshot())
        }
    }
    private static var measurements: [String: Double] = [:]
    private static var assertions = 0
    private static func require(_ value: @autoclosure () -> Bool, _ text: String) throws {
        assertions += 1
        if !value() { throw Failure(text: text) }
    }
    private static func measured<T>(_ name: String, _ work: () throws -> T) rethrows -> T {
        let wall = ProcessInfo.processInfo.systemUptime, cpu = clock()
        let result = try work()
        measurements[name + "WallMilliseconds"] = (ProcessInfo.processInfo.systemUptime - wall) * 1000
        measurements[name + "CPUMilliseconds"] = Double(clock() - cpu) * 1000 / Double(CLOCKS_PER_SEC)
        return result
    }
    private static func drain(until condition: () -> Bool = { true }) throws {
        let deadline = Date().addingTimeInterval(3)
        repeat {
            RunLoop.current.run(until: Date().addingTimeInterval(0.002))
        } while !condition() && Date() < deadline
        try require(condition(), "Expected presentation callback was not delivered")
    }
    private static func decoded<T: Decodable>(_ type: T.Type, _ value: Any) throws -> T {
        try JSONDecoder().decode(type, from: JSONSerialization.data(withJSONObject: value))
    }
    private static func maximumReport() throws -> NetworkPerformanceSnapshot {
        let error: [String: Any] = ["category": "tlsClosedWithoutNotify", "codes": (0..<4).map { _ in
            ["domain": "NSOSStatusErrorDomain", "code": -9816] as [String: Any]
        }]
        let events: [[String: Any]] = (0..<24).map {
            ["sequence": $0 + 1, "event": "tlsWaiting", "milliseconds": Double($0) * 25,
             "error": error]
        }
        let waiters: [[String: Any]] = (0..<64).map { _ in
            ["waiterID": UUID().uuidString, "startedUptimeNanoseconds": 1,
             "absoluteDeadlineUptime": 8, "outcome": "failure", "failureReason": "timeout",
             "milliseconds": 8000]
        }
        var attempts: [DNSConnectionAttemptSnapshot] = [], logical: [DNSLogicalQuerySnapshot] = []
        var exchanges: [DNSQueryExchangeSnapshot] = []
        for index in 0..<128 {
            let id = UUID().uuidString, requestID = UUID().uuidString, rootID = UUID().uuidString
            attempts.append(try decoded(DNSConnectionAttemptSnapshot.self,
                ["id": id, "requestID": requestID, "rootID": rootID, "upstreamID": "resolver-fixture-00000001",
                 "addressID": "address-fixture-00000001", "provider": "dnspod", "transport": "doh",
                 "purpose": "query", "route": "direct", "transportOutcome": "success", "tlsOutcome": "failure",
                 "requestFinished": true, "firstError": error, "firstErrorBeforeCancellation": error,
                 "observations": events, "omittedObservations": 0, "observedEventCount": 24, "started": index + 1]))
            logical.append(try decoded(DNSLogicalQuerySnapshot.self,
                ["rootID": rootID, "waiters": waiters, "admittedCount": 64, "mergedCount": 63,
                 "finishedCount": 64, "outcomeCounts": ["failure": 64], "failureCounts": ["timeout": 64],
                 "omittedWaiters": 0, "started": index + 1]))
            exchanges.append(try decoded(DNSQueryExchangeSnapshot.self,
                ["id": UUID().uuidString, "requestID": requestID, "rootID": rootID,
                 "upstreamID": "resolver-fixture-00000001", "transport": "doh", "physicalAttemptIDs": [id],
                 "reusedConnection": false, "outcome": "failure", "failureReason": "timeout", "queryType": 12,
                 "queryClass": 1, "queryFlags": 256, "queryBytes": 72, "queryAdditionalRecordCount": 1,
                 "ptrQueryKind": "dnsSDDomainEnumeration", "ptrTargetCategory": "other",
                 "observations": events, "omittedObservations": 0, "observedEventCount": 24, "started": index + 1]))
        }
        return NetworkPerformanceSnapshot(dnsQueries: 8192, dnsFailures: 8192, dnsFailureReasons: [.timeout: 8192],
            stages: Dictionary(uniqueKeysWithValues: NetworkPerformanceStage.allCases.map {
                ($0, NetworkStageSnapshot(count: 1000, failureCount: 500, cancellationCount: 100,
                    sampleCount: 128, medianMilliseconds: 250, p95Milliseconds: 7000, latestMilliseconds: 8000))
            }), dnsConnectionAttempts: attempts, dnsLogicalQueries: logical, dnsQueryExchanges: exchanges)
    }
    private static func connectivity() throws -> NetworkConnectivityDiagnosticsSnapshot {
        try decoded(NetworkConnectivityDiagnosticsSnapshot.self,
            ["id": UUID().uuidString, "startedAt": 0, "updatedAt": 1, "isRunning": false,
             "omittedEndpointCount": 0, "rows": (0..<18).map { index in
                ["id": "fixture-\(index)", "kind": "encryptedDNS", "title": "加密 DNS \(index + 1)",
                 "endpoint": "DoH memory-fixture.invalid:443", "route": "物理出口直连 · 固定测试",
                 "status": "failure", "milliseconds": 8000, "responseCode": 2,
                 "extendedDNSErrorCodes": [6, 22], "errorDomain": "NSPOSIXErrorDomain", "errorCode": 60,
                 "detail": String(repeating: "上游检测在原截止时间内未收到有效响应。", count: 16)] as [String: Any]
             }])
    }
    private static var context: NetworkDiagnosticsRuntimeContext {
        .init(engineState: "运行中", engineRunning: true, mode: "规则", selectedPolicy: "memory-policy",
              groupSelections: [:], profileRevision: 42, enhancedMode: true, systemProxy: false,
              boundInterfaceName: "en-fixture")
    }

    private static func button(_ view: NSView, title: String) -> NSButton? {
        for child in view.subviews {
            if let button = child as? NSButton, button.title == title { return button }
            if let found = button(child, title: title) { return found }
        }
        return nil
    }

    private static func hasText(_ view: NSView, containing text: String) -> Bool {
        view.subviews.contains { child in
            (child as? NSTextField)?.stringValue.contains(text) == true || hasText(child, containing: text)
        }
    }

    private static func boundedWorkerAndStaleDelivery() throws {
        let provider = HeldStatistics()
        var currentContext = context, clock: UInt64 = 0, reports: [String] = [], detectionStarts = 0
        var feature: NetworkDiagnosticsFeature? = NetworkDiagnosticsFeature(capabilities: .init(
            context: { currentContext }, statistics: provider.read, captureLocalNetwork: { _, complete in
                complete(.init(capturedAt: Date(timeIntervalSince1970: 1), localLinkStatus: .unknown,
                    interfaces: [], systemPrimaryIPv4Interface: nil, systemPrimaryIPv6Interface: nil,
                    physicalInterfaceName: nil, physicalInterfaceSelection: .undetermined, gateways: [],
                    systemDNSServers: [], physicalDNSServers: [], collectionIssues: []))
            }, startDiagnostics: { _ in detectionStarts += 1; return RuntimeOperation() },
            now: { clock }, applicationVersion: "版本 memory · Build 42", copyReport: { reports.append($0) }))
        feature!.setVisible(true)
        try drain { provider.audit.calls == 1 && hasText(feature!.view, containing: "本地链路状态待确认") }
        let copyNetwork = button(feature!.view, title: "复制网络诊断")
        try require(copyNetwork != nil && copyNetwork?.isEnabled == false && feature!.canStartDetection
                    && hasText(feature!.view, containing: "正在读取运行统计"),
                    "Early local capture enabled copying placeholder statistics or blocked detection")
        feature!.view.copyNetworkReport()
        try require(reports.isEmpty, "An action queued before statistics arrived exported placeholder zero totals")
        feature!.beginDetection()
        try require(feature!.isDetectionRunning && detectionStarts == 1 && copyNetwork?.isEnabled == false,
                    "Waiting for statistics blocked starting diagnostics or enabled an incomplete report")
        feature!.stopDetection()
        for tick in 1...10 { clock = UInt64(tick) * 1_000_000_000; feature!.refreshIfVisible() }
        feature!.setVisible(false)
        clock = 11_000_000_000; currentContext.profileRevision += 1; feature!.setVisible(true)
        try require(provider.audit.calls == 1 && provider.audit.callsOnMain == 0,
                    "Busy ticks or hide/reveal admitted duplicate statistics reads")
        provider.release()
        try drain { provider.completed == 1 }
        try drain()
        try require(feature!.view.displayedRows.allSatisfy { $0.counts == "0 / 0 / 0" },
                    "A previous visibility/context epoch repopulated the reopened view")

        clock = 12_000_000_000; feature!.refreshIfVisible()
        try drain { provider.audit.calls == 2 }
        provider.release()
        try drain { feature!.view.displayedRows.contains { $0.stage == .dnsResolution && $0.counts == "22 / 22 / 0" } }
        try require(copyNetwork?.isEnabled == true, "First real statistics did not restore full report copying")
        feature!.view.copyNetworkReport()
        let copied = try JSONSerialization.jsonObject(with: Data((reports.last ?? "").utf8)) as? [String: Any]
        let dns = copied?["dnsDiagnostics"] as? [String: Any]
        let totals = dns?["totals"] as? [String: Any], failures = dns?["failureReasons"] as? [String: Any]
        try require(copied?["schemaVersion"] as? Int == 1 && dns?["schemaVersion"] as? Int == 2
                    && totals?["queries"] as? Int == 22 && totals?["failedQueries"] as? Int == 22
                    && failures?["timeout"] as? Int == 22,
                    "Background preparation dropped failures or copied a stale performance snapshot")

        clock = 13_000_000_000; feature!.refreshIfVisible()
        try drain { provider.audit.calls == 3 }
        currentContext.runtimeRevision += 1
        provider.release()
        try drain { provider.completed == 3 }
        try drain()
        try require(feature!.view.displayedRows.contains { $0.stage == .dnsResolution && $0.counts == "22 / 22 / 0" },
                    "A changed context accepted an old read before the next timer refresh")

        clock = 14_000_000_000; feature!.refreshIfVisible()
        try drain { provider.audit.calls == 4 }
        weak var weakFeature = feature
        feature!.close(); feature = nil
        try require(weakFeature == nil, "An executing statistics read retained the closed presentation feature")
        provider.release()
        try drain { provider.completed == 4 }
        try drain()
        try require(reports.count == 1 && provider.audit.calls == 4 && provider.audit.callsOnMain == 0,
                    "Late statistics copied reports, admitted more work or touched a released feature")
    }

    static func main() throws {
        _ = NSApplication.shared
        let snapshot = try maximumReport(), connectivity = try connectivity()
        let scheduler = ProbeScheduler(maximumActive: 8, maximumQueued: 512).snapshot()
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 880, height: 680),
            styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        let view = measured("constructView") {
            NetworkDiagnosticsView(frame: .zero, applicationVersion: "版本 memory · Build 42",
                now: { 0 }, copyReport: { _ in })
        }
        let wrapper = WidthFittingScrollContentView(content: view)
        window.contentView = wrapper
        measured("initialEmptyLayout") { wrapper.layoutSubtreeIfNeeded() }
        measured("maximumReportApply") { view.apply(snapshot, scheduler: scheduler) }
        measured("firstLayout") { wrapper.layoutSubtreeIfNeeded() }
        measured("maximumConnectivityApply") { view.applyConnectivity(connectivity) }
        measured("completedLayout") { wrapper.layoutSubtreeIfNeeded() }
        for _ in 0..<3 { try drain(); wrapper.layoutSubtreeIfNeeded() }
        measured("steadyRefreshAndLayout") {
            view.apply(snapshot, scheduler: scheduler); wrapper.layoutSubtreeIfNeeded()
        }
        let audit = Audit()
        let feature = NetworkDiagnosticsFeature(capabilities: .init(context: { context }, statistics: {
            audit.record()
            Thread.sleep(forTimeInterval: 0.35)
            return .init(performance: snapshot, scheduler: scheduler)
        }, captureLocalNetwork: { _, _ in }, now: { 0 }, applicationVersion: "版本 memory · Build 42",
            copyReport: { _ in }))
        measured("slowStatisticsReveal") { feature.setVisible(true) }
        var nextMainDelivered = false
        DispatchQueue.main.async { nextMainDelivered = true }
        try measured("nextMainDelivery") { try drain { nextMainDelivered } }
        if !CommandLine.arguments.contains("--baseline") {
            try require((measurements["slowStatisticsRevealWallMilliseconds"] ?? .infinity) < 100,
                        "Showing diagnostics synchronously waited for the 350ms statistics provider")
            try drain { audit.calls > 0 && feature.view.displayedRows.first?.counts.hasPrefix("1000") == true }
            try require(audit.callsOnMain == 0, "Statistics lock/snapshot preparation still runs on main")
            try boundedWorkerAndStaleDelivery()
        }
        feature.close()
        try require(!window.isVisible && !window.isKeyWindow && !window.isMainWindow,
                    "Memory fixture unexpectedly showed or activated its window")
        let output: [String: Any] = ["measurements": measurements, "assertions": assertions,
            "rings": [snapshot.dnsConnectionAttempts.count, snapshot.dnsLogicalQueries.count, snapshot.dnsQueryExchanges.count],
            "observationsPerRecord": 24, "waitersPerLogicalQuery": 64, "connectivityRows": 18,
            "statisticsCalls": audit.calls, "statisticsCallsOnMain": audit.callsOnMain,
            "windowShown": false, "nativeNetworkUsed": false]
        print(String(data: try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys]), encoding: .utf8)!)
    }
}

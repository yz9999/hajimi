import AppKit
import HajimiCore
import HajimiDiagnosticsUI
import HajimiRuntime
import HajimiUIComponents

/// Imports the actual feature and actual Core snapshots. Only capabilities
/// are in memory; no window, owner, interface read, probe or pasteboard write.
final class NetworkDiagnosticsFeatureSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "Diagnostics UI import fixture: \(text)" }
    }

    private final class Counter {
        private let lock = NSLock()
        private var count = 0
        private var allMain = true
        func increment() {
            lock.lock(); count += 1; allMain = allMain && Thread.isMainThread; lock.unlock()
        }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
        var isMainOnly: Bool { lock.lock(); defer { lock.unlock() }; return allMain }
    }

    private final class Environment {
        var context = NetworkDiagnosticsRuntimeContext(engineState: "运行中", engineRunning: true,
            mode: "规则", selectedPolicy: "private-policy-marker", groupSelections: ["private-group": "private-node"],
            profileRevision: 30, enhancedMode: true, systemProxy: false, boundInterfaceName: "en-fixture",
            runtimeRevision: 9, runtimeBackend: .enhanced,
            runtimeSessionID: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"))
        var clock: UInt64 = 0
        let statisticsAudit = Counter()
        var statisticsCalls: Int { statisticsAudit.value }
        var localCallbacks: [(LocalNetworkDiagnosticsSnapshot) -> Void] = []
        var callbacks: [(NetworkConnectivityDiagnosticsSnapshot) -> Void] = []
        var operations: [RuntimeOperation] = []
        var cancellations: [Counter] = []
        var reports: [String] = []
        var exportedFiles: [(report: String, filename: String)] = []
        var immediateResult: NetworkConnectivityDiagnosticsSnapshot?
        var beforeReturn: (() -> Void)?
        var contextHook: (() -> Void)?
        var cancellationHook: ((Int) -> Void)?
        let calls = Counter()
        let scheduler = ProbeScheduler(maximumActive: 1, maximumQueued: 1)
        let performance = NetworkPerformanceSnapshot(dnsQueries: 13, dnsCacheHits: 3, dnsFailures: 2,
            dnsFailureReasons: [.timeout: 2], stages: [.dnsResolution: .init(count: 4,
                sampleCount: 2, medianMilliseconds: 12, p95Milliseconds: 24)])

        private let copyAudit: Counter
        init(copyAudit: Counter) { self.copyAudit = copyAudit }

        func capabilities(canDetect: Bool = true) -> NetworkDiagnosticsCapabilities {
            var start: NetworkDiagnosticsCapabilities.StartDiagnostics?
            if canDetect {
                start = { [self] update in
                    calls.increment(); callbacks.append(update)
                    let operation = RuntimeOperation(), counter = Counter()
                    let index = operations.count
                    cancellations.append(counter); operations.append(operation)
                    operation.installCancellation { [weak self] in
                        counter.increment(); self?.cancellationHook?(index)
                    }
                    if let immediateResult { update(immediateResult) }
                    beforeReturn?()
                    return operation
                }
            }
            return NetworkDiagnosticsCapabilities(context: { [self] in
                    calls.increment(); contextHook?(); return context
                },
                statistics: { [self] in
                    statisticsAudit.increment()
                    return NetworkDiagnosticsStatistics(performance: performance, scheduler: scheduler.snapshot())
                }, captureLocalNetwork: { [self] bound, callback in
                    calls.increment()
                    if bound != context.boundInterfaceName { fatalError("capture used the wrong context binding") }
                    localCallbacks.append(callback)
                }, startDiagnostics: start, now: { [self] in calls.increment(); return clock },
                applicationVersion: "版本 memory · Build 30", copyReport: { [self] text in
                    calls.increment(); reports.append(text); copyAudit.increment()
                }, exportReport: { [self] text, filename, _ in
                    calls.increment(); exportedFiles.append((text, filename)); copyAudit.increment()
                })
        }
    }

    private var assertions = 0
    private let copyAudit = Counter()
    private func expect(_ condition: @autoclosure () -> Bool, _ text: String) throws {
        assertions += 1
        if !condition() { throw Failure(text: text) }
    }

    private func drainMain(until condition: (() -> Bool)? = nil) {
        let deadline = Date().addingTimeInterval(2)
        repeat {
            RunLoop.current.run(until: Date().addingTimeInterval(0.015))
        } while condition.map({ !$0() }) == true && Date() < deadline
    }

    private func local(_ gateway: String = "192.0.2.1", capturedAt: TimeInterval = 1)
        -> LocalNetworkDiagnosticsSnapshot {
        .init(capturedAt: Date(timeIntervalSince1970: capturedAt), localLinkStatus: .available,
              interfaces: [.init(name: "en-fixture", index: 7, kind: .physical, isUp: true, isRunning: true,
                  ipv4Addresses: ["192.0.2.20"], ipv6Addresses: ["2001:db8::20"])],
              systemPrimaryIPv4Interface: "en-fixture", systemPrimaryIPv6Interface: "en-fixture",
              physicalInterfaceName: "en-fixture", physicalInterfaceSelection: .boundInterface,
              gateways: [gateway], systemDNSServers: ["127.0.0.1"], physicalDNSServers: ["192.0.2.53"],
              collectionIssues: [])
    }

    private func connectivity(_ marker: String, running: Bool = false)
        throws -> NetworkConnectivityDiagnosticsSnapshot {
        let object: [String: Any] = ["id": UUID().uuidString, "startedAt": 0, "updatedAt": 1,
            "isRunning": running, "omittedEndpointCount": 2, "rows": [
                ["id": "local", "kind": "localLatency", "title": "本地网络 HTTP 首响应",
                 "endpoint": "http://diagnostics-fixture.invalid:80", "route": "DIRECT",
                 "status": running ? "running" : "success", "milliseconds": 12.5,
                 "responseCode": 200, "detail": marker],
                ["id": "dns", "kind": "encryptedDNS", "title": "加密 DNS 1",
                 "endpoint": "DoH resolver.example:443", "route": "代理", "status": "failure",
                 "responseCode": 2, "extendedDNSErrorCodes": [6, 22], "errorDomain": "app.hajimi.dns",
                 "errorCode": 2, "detail": "上游返回 SERVFAIL"]]]
        return try JSONDecoder().decode(NetworkConnectivityDiagnosticsSnapshot.self,
                                        from: JSONSerialization.data(withJSONObject: object))
    }

    private func copied(_ feature: NetworkDiagnosticsFeature, _ environment: Environment) throws -> [String: Any] {
        drainMain { feature.view.displayedRows == NetworkDiagnosticsFormatting.rows(environment.performance) }
        feature.view.copyNetworkReport()
        guard let report = environment.reports.last,
              let value = try JSONSerialization.jsonObject(with: Data(report.utf8)) as? [String: Any] else {
            throw Failure(text: "copy capability did not receive a valid report")
        }
        return value
    }

    private func button(_ view: NSView, titled title: String) -> NSButton? {
        for child in view.subviews {
            if let button = child as? NSButton, button.title == title { return button }
            if let found = button(child, titled: title) { return found }
        }
        return nil
    }

    func run() throws {
        try expect(Thread.isMainThread, "fixture must run on main")
        _ = NSApplication.shared
        try refreshAndCaptureBounds()
        try actionsAndRoundIsolation()
        try lateHandlesAndVisibility()
        try synchronousAndBackgroundDelivery()
        try cancellationReentry()
        try contextProviderReentry()
        try configurationChanges()
        try localNetworkChanges()
        try copiedReportPrivacy()
        try deallocation()
        try expect(copyAudit.value > 0 && copyAudit.isMainOnly,
                   "report copies did not reach the injected memory sink on main")
        print("Diagnostics UI module passed: \(assertions) public capability assertions plus existing formatting/layout vectors; actual buttons, prepare/stop/hide/close, late handles/results, main delivery, 1Hz/5s bounds and injected report copies; no window/network/clipboard writes")
    }

    private func refreshAndCaptureBounds() throws {
        let environment = Environment(copyAudit: copyAudit)
        let owner = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
        try expect(environment.statisticsCalls == 0 && environment.localCallbacks.isEmpty,
                   "constructing a hidden feature invoked providers")
        owner.beginDetection()
        try expect(environment.callbacks.isEmpty, "hidden feature started connectivity work")
        owner.setVisible(true)
        drainMain { environment.statisticsCalls == 1 && owner.view.displayedRows.contains { $0.counts == "4 / 0 / 0" } }
        try expect(environment.statisticsCalls == 1 && environment.localCallbacks.count == 1
            && environment.callbacks.isEmpty && owner.canStartDetection, "initial reveal did not refresh once without automatic probes")
        environment.localCallbacks[0](local()); drainMain()
        owner.refreshIfVisible(); environment.clock = 999_000_000; owner.refreshIfVisible()
        try expect(environment.statisticsCalls == 1, "feature refreshed faster than 1Hz")
        environment.clock = 4_000_000_000; owner.refreshIfVisible()
        drainMain { environment.statisticsCalls == 2 }
        try expect(environment.localCallbacks.count == 1, "local capture repeated before five seconds")
        environment.clock = 5_000_000_000; owner.refreshIfVisible()
        drainMain { environment.statisticsCalls == 3 }
        try expect(environment.localCallbacks.count == 2, "local capture did not resume at five seconds")
        environment.clock = 100_000_000_000; owner.refreshIfVisible()
        drainMain { environment.statisticsCalls == 4 }
        try expect(environment.localCallbacks.count == 2, "a held physical capture admitted another capture")
        owner.setVisible(false); environment.clock += 1; owner.setVisible(true)
        try expect(environment.localCallbacks.count == 2, "hide/reopen released a physical capture before its callback")
        environment.localCallbacks[1](local("192.0.2.200")); drainMain()
        let report = try copied(owner, environment)
        try expect(!String(describing: report["localNetwork"]).contains("192.0.2.200"),
                   "a local capture from an earlier visible epoch overwrote the reopened feature")
        environment.clock = 101_000_000_000; owner.refreshIfVisible()
        drainMain { environment.statisticsCalls == 5 }
        try expect(environment.localCallbacks.count == 3, "a rejected old capture permanently blocked a fresh capture")
        owner.setVisible(false); environment.clock = 102_000_000_000; owner.refreshIfVisible()
        try expect(environment.statisticsCalls == 5, "hidden refresh continued invoking statistics")
        owner.close(); try expect(environment.calls.isMainOnly && !environment.statisticsAudit.isMainOnly,
                                 "UI capabilities ran off main or statistics still ran on main")
    }

    private func actionsAndRoundIsolation() throws {
        let environment = Environment(copyAudit: copyAudit)
        let owner = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
        owner.setVisible(true)
        drainMain { owner.view.displayedRows == NetworkDiagnosticsFormatting.rows(environment.performance) }
        guard let start = button(owner.view, titled: "开始网络检测"),
              let stop = button(owner.view, titled: "停止检测") else { throw Failure(text: "actual detection buttons missing") }
        start.performClick(nil)
        try expect(environment.callbacks.count == 1 && owner.isDetectionRunning && !start.isEnabled && stop.isEnabled,
                   "actual start button did not enter the preparation barrier")
        start.performClick(nil); owner.beginDetection()
        try expect(environment.callbacks.count == 1, "preparation admitted duplicate detection")
        stop.performClick(nil)
        try expect(environment.cancellations[0].value == 1 && !owner.isDetectionRunning && owner.canStartDetection,
                   "actual stop button did not synchronously cancel and restore controls")
        environment.callbacks[0](try connectivity("old-cancelled-result")); drainMain()
        let cancelledReport = try copied(owner, environment)
        try expect(cancelledReport["connectivity"] == nil, "cancelled result repopulated the view")
        start.performClick(nil)
        environment.callbacks[1](try connectivity("new-current-result")); drainMain()
        environment.callbacks[0](try connectivity("old-round-result")); drainMain()
        let report = try copied(owner, environment)
        try expect(String(describing: report["connectivity"]).contains("new-current-result")
            && !String(describing: report["connectivity"]).contains("old-round-result") && !owner.isDetectionRunning,
                   "old round overwrote the completed new round")
        owner.close()
    }

    private func lateHandlesAndVisibility() throws {
        for action in ["stop", "hide", "close"] {
            let environment = Environment(copyAudit: copyAudit)
            let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
            feature.setVisible(true)
            environment.beforeReturn = {
                switch action {
                case "stop": feature.stopDetection()
                case "hide": feature.setVisible(false)
                default: feature.close()
                }
            }
            feature.beginDetection(); environment.beforeReturn = nil
            try expect(environment.operations.count == 1 && environment.operations[0].isCancelled
                && environment.cancellations[0].value == 1 && !feature.isDetectionRunning,
                       "\(action) before provider return leaked the late child handle")
            environment.callbacks[0](try connectivity("late-\(action)-result")); drainMain()
            feature.close()
            try expect(environment.cancellations[0].value == 1, "\(action) repeated physical child cancellation")
        }
    }

    private func synchronousAndBackgroundDelivery() throws {
        let environment = Environment(copyAudit: copyAudit)
        environment.immediateResult = try connectivity("inline-terminal")
        let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
        feature.setVisible(true); feature.beginDetection()
        try expect(feature.isDetectionRunning, "synchronous callback applied before the provider handle was installed")
        drainMain()
        try expect(!feature.isDetectionRunning && feature.canStartDetection,
                   "synchronous terminal result lost its next-main-turn delivery")
        environment.immediateResult = nil
        feature.beginDetection()
        let callback = environment.callbacks[1], snapshot = try connectivity("background-terminal")
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async { callback(snapshot); finished.signal() }
        try expect(finished.wait(timeout: .now() + 1) == .success && feature.isDetectionRunning,
                   "background provider result did not enqueue without touching the UI inline")
        drainMain()
        try expect(!feature.isDetectionRunning && environment.calls.isMainOnly,
                   "background callback bypassed main delivery or invoked providers off main")
        feature.close()

        let reentrant = Environment(copyAudit: copyAudit)
        reentrant.immediateResult = try connectivity("terminal-before-handle-return")
        let nested = NetworkDiagnosticsFeature(capabilities: reentrant.capabilities())
        nested.setVisible(true)
        let progress = try connectivity("forbidden-progress-after-terminal", running: true)
        reentrant.beforeReturn = {
            self.drainMain()
            reentrant.callbacks[0](progress)
            self.drainMain()
        }
        nested.beginDetection(); reentrant.beforeReturn = nil
        let report = try copied(nested, reentrant)
        try expect(!nested.isDetectionRunning && nested.canStartDetection
            && reentrant.operations[0].isCancelled && reentrant.cancellations[0].value == 1
            && String(describing: report["connectivity"]).contains("terminal-before-handle-return")
            && !String(describing: report["connectivity"]).contains("forbidden-progress-after-terminal"),
                   "nested main delivery before provider return reopened a terminal round or leaked the late child")
        nested.close()
    }

    private func cancellationReentry() throws {
        for terminal in [false, true] {
            let environment = Environment(copyAudit: copyAudit)
            let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
            feature.setVisible(true)
            drainMain { feature.view.displayedRows == NetworkDiagnosticsFormatting.rows(environment.performance) }
            feature.beginDetection()
            environment.cancellationHook = { index in
                if index == 0 { feature.beginDetection() }
            }
            if terminal {
                environment.callbacks[0](try connectivity("retired-terminal")); drainMain()
            } else { feature.stopDetection() }
            try expect(environment.callbacks.count == 2 && feature.isDetectionRunning
                && environment.cancellations[0].value == 1 && environment.cancellations[1].value == 0,
                       "\(terminal ? "terminal" : "stop") cancellation reentry lost the replacement round or its handle")
            environment.callbacks[0](try connectivity("forbidden-retired-progress", running: true)); drainMain()
            environment.callbacks[1](try connectivity("replacement-progress", running: true)); drainMain()
            let report = try copied(feature, environment)
            try expect(feature.isDetectionRunning
                && String(describing: report["connectivity"]).contains("replacement-progress")
                && !String(describing: report["connectivity"]).contains("forbidden-retired-progress"),
                       "retired callback or outer cancellation overwrote a replacement round")
            feature.stopDetection()
            try expect(environment.cancellations[1].value == 1 && !feature.isDetectionRunning,
                       "cancellation reentry detached the replacement operation from stop")
            environment.cancellationHook = nil
            feature.close()
        }
    }

    private func contextProviderReentry() throws {
        for action in ["stop", "hide", "restart"] {
            let environment = Environment(copyAudit: copyAudit)
            let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
            feature.setVisible(true)
            drainMain { feature.view.displayedRows == NetworkDiagnosticsFormatting.rows(environment.performance) }
            feature.beginDetection()
            environment.contextHook = {
                environment.contextHook = nil
                if action == "hide" { feature.setVisible(false) }
                else {
                    feature.stopDetection()
                    if action == "restart" { feature.beginDetection() }
                }
            }
            environment.callbacks[0](try connectivity("forbidden-context-\(action)")); drainMain()
            let report = try copied(feature, environment)
            try expect(environment.cancellations[0].value == 1
                && !String(describing: report["connectivity"]).contains("forbidden-context-\(action)")
                && feature.isDetectionRunning == (action == "restart"),
                       "context provider \(action) reentry accepted a revoked callback")
            if action == "restart" {
                try expect(environment.callbacks.count == 2 && environment.cancellations[1].value == 0,
                           "context provider restart did not preserve its replacement handle")
            }
            feature.close()
        }

        let environment = Environment(copyAudit: copyAudit)
        let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
        feature.setVisible(true)
        environment.contextHook = {
            environment.contextHook = nil
            feature.beginDetection()
        }
        feature.beginDetection()
        try expect(environment.callbacks.count == 1 && feature.isDetectionRunning
            && environment.cancellations[0].value == 0,
                   "outer begin restarted after its context provider had already begun a round")
        feature.close()
        try expect(environment.cancellations[0].value == 1,
                   "context provider begin reentry detached the sole current handle")

        for reopen in [false, true] {
            let environment = Environment(copyAudit: copyAudit)
            let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
            feature.setVisible(true)
            drainMain { feature.view.displayedRows == NetworkDiagnosticsFormatting.rows(environment.performance) }
            environment.contextHook = {
                environment.contextHook = nil
                feature.setVisible(false)
                if reopen { feature.setVisible(true) }
            }
            environment.localCallbacks[0](local("192.0.2.222")); drainMain()
            let report = try copied(feature, environment)
            try expect(report["localNetwork"] == nil && feature.isVisible == reopen,
                       "local context provider hide\(reopen ? "/reopen" : "") applied a prior-epoch capture")
            feature.close()
        }
    }

    private func configurationChanges() throws {
        let edits: [(String, (inout NetworkDiagnosticsRuntimeContext) -> Void)] = [
            ("profile", { $0.profileRevision += 1 }), ("runtime", { $0.runtimeRevision += 1 }),
            ("session", { $0.runtimeSessionID = UUID() }), ("interface", { $0.boundInterfaceName = "en-next" }),
            ("mode", { $0.mode = "全局代理" }), ("policy", { $0.selectedPolicy = "changed-private-policy" }),
            ("group", { $0.groupSelections["private-group"] = "changed-private-node" }),
            ("systemProxy", { $0.systemProxy.toggle() }), ("backend", { $0.runtimeBackend = .listener })]
        for (name, edit) in edits {
            let environment = Environment(copyAudit: copyAudit)
            let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
            feature.setVisible(true)
            drainMain { feature.view.displayedRows == NetworkDiagnosticsFormatting.rows(environment.performance) }
            feature.beginDetection()
            edit(&environment.context)
            environment.clock = 1_000_000_000; feature.refreshIfVisible()
            environment.callbacks[0](try connectivity("stale-\(name)"))
            environment.localCallbacks[0](local()); drainMain()
            let report = try copied(feature, environment)
            try expect(environment.cancellations[0].value == 1 && !feature.isDetectionRunning
                && report["connectivity"] == nil && report["localNetwork"] == nil,
                       "\(name) change retained old work, results or local configuration")
            feature.close()
        }
        let environment = Environment(copyAudit: copyAudit)
        environment.context.engineRunning = false
        let stopped = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
        stopped.setVisible(true); stopped.beginDetection()
        try expect(!stopped.canStartDetection && environment.callbacks.isEmpty, "unready owner admitted diagnostic I/O")
        stopped.close()
        environment.context.engineRunning = true
        let unsupported = NetworkDiagnosticsFeature(capabilities: environment.capabilities(canDetect: false))
        unsupported.setVisible(true); unsupported.beginDetection()
        try expect(!unsupported.canStartDetection && environment.callbacks.isEmpty, "missing capability fabricated a detection path")
        unsupported.close()
    }

    private func localNetworkChanges() throws {
        let environment = Environment(copyAudit: copyAudit)
        let owner = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
        owner.setVisible(true); environment.localCallbacks[0](local()); drainMain()
        owner.beginDetection()
        environment.clock = 5_000_000_000; owner.refreshIfVisible()
        environment.localCallbacks[1](local(capturedAt: 9)); drainMain()
        try expect(environment.cancellations[0].value == 0 && owner.isDetectionRunning,
                   "capture timestamp alone invalidated the current round")
        environment.clock = 10_000_000_000; owner.refreshIfVisible()
        environment.localCallbacks[2](local("192.0.2.254", capturedAt: 10)); drainMain()
        environment.callbacks[0](try connectivity("old-gateway-result")); drainMain()
        let report = try copied(owner, environment)
        try expect(environment.cancellations[0].value == 1 && !owner.isDetectionRunning
            && report["connectivity"] == nil && String(describing: report["localNetwork"]).contains("192.0.2.254"),
                   "changed local gateway did not revoke stale connectivity while publishing the new local snapshot")
        owner.close()
    }

    private func copiedReportPrivacy() throws {
        let environment = Environment(copyAudit: copyAudit)
        let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
        feature.setVisible(true)
        drainMain { feature.view.displayedRows == NetworkDiagnosticsFormatting.rows(environment.performance) }
        environment.localCallbacks[0](local()); drainMain()
        feature.beginDetection(); environment.callbacks[0](try connectivity("current-copy-result")); drainMain()
        let report = try copied(feature, environment)
        let runtime = report["runtime"] as? [String: Any], dns = report["dnsDiagnostics"] as? [String: Any]
        let text = environment.reports.last ?? ""
        try expect(report["schemaVersion"] as? Int == 1 && report["containsLocalAddresses"] as? Bool == true
            && report["applicationVersion"] as? String == "版本 memory · Build 30"
            && runtime?["diagnosticsBackend"] as? String == "enhanced" && report["stages"] is [[String: Any]]
            && dns?["schemaVersion"] as? Int == 2 && text.contains("192.0.2.20")
            && text.contains("extendedDNSErrorCodes") && text.contains("current-copy-result"),
                   "injected network copy changed report schemas, version, source, local addresses or DNS evidence")
        for privateValue in ["private-policy-marker", "private-group", "private-node",
                             "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "runtimeSessionID", "runtimeRevision"] {
            try expect(!text.contains(privateValue), "copy report exported internal identity or policy: \(privateValue)")
        }
        feature.view.copyDNSAttempts()
        guard let dnsText = environment.reports.last,
              let raw = try JSONSerialization.jsonObject(with: Data(dnsText.utf8)) as? [String: Any] else {
            throw Failure(text: "injected DNS copy returned invalid JSON")
        }
        let totals = raw["totals"] as? [String: Any]
        try expect(raw["schemaVersion"] as? Int == 2 && raw["applicationVersion"] as? String == "版本 memory · Build 30"
            && totals?["queries"] as? Int == 13 && raw["attempts"] is [Any]
            && raw["logicalQueries"] is [Any] && raw["exchanges"] is [Any]
            && environment.reports.count == 2 && environment.calls.isMainOnly,
                   "DNS copy did not use current supplied snapshots and the injected main-thread sink")
        feature.view.exportNetworkReport()
        feature.view.exportDNSAttempts()
        try expect(environment.exportedFiles.count == 2
            && environment.exportedFiles[0].filename.hasPrefix("哈基米-网络诊断报告-")
            && environment.exportedFiles[0].filename.hasSuffix(".json")
            && environment.exportedFiles[0].report == text
            && environment.exportedFiles[1].filename.hasPrefix("哈基米-DNS建连诊断报告-")
            && environment.exportedFiles[1].filename.hasSuffix(".json")
            && environment.exportedFiles[1].report == dnsText,
                   "Network and DNS report file exports did not deliver exact JSON payloads and filenames")
        feature.close()
    }

    private func deallocation() throws {
        let environment = Environment(copyAudit: copyAudit)
        var feature: NetworkDiagnosticsFeature? = NetworkDiagnosticsFeature(capabilities: environment.capabilities())
        weak var weakFeature = feature
        feature!.setVisible(true); feature!.beginDetection()
        feature = nil
        try expect(weakFeature == nil && environment.cancellations[0].value == 1,
                   "feature deallocation leaked a retain cycle or owned diagnostic operation")
        environment.callbacks[0](try connectivity("after-deinit"))
        environment.localCallbacks[0](local()); drainMain()
        try expect(environment.reports.isEmpty && environment.cancellations[0].value == 1,
                   "deallocated feature delivered late results or repeated cleanup")
    }
}

import AppKit
import HajimiCore
import HajimiDiagnosticsUI
import HajimiRuntime
import HajimiUIComponents

/// Uses real feature delivery and real scroll geometry. The caller supplies
/// an offscreen host; providers return memory snapshots and never perform I/O.
enum NetworkDiagnosticsScrollLayoutSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "Diagnostics dynamic scroll: \(text)" }
    }

    private final class Environment {
        var update: ((NetworkConnectivityDiagnosticsSnapshot) -> Void)?
        var clock: UInt64 = 0
        private let performanceLock = NSLock()
        private var storedPerformance = NetworkPerformanceSnapshot()
        var performance: NetworkPerformanceSnapshot {
            get { performanceLock.lock(); defer { performanceLock.unlock() }; return storedPerformance }
            set { performanceLock.lock(); storedPerformance = newValue; performanceLock.unlock() }
        }
        let context = NetworkDiagnosticsRuntimeContext(engineState: "运行中", engineRunning: true,
            mode: "规则", selectedPolicy: "memory-policy", groupSelections: [:], profileRevision: 35,
            enhancedMode: true, systemProxy: false, boundInterfaceName: "en-fixture")

        var capabilities: NetworkDiagnosticsCapabilities {
            NetworkDiagnosticsCapabilities(context: { self.context }, statistics: {
                .init(performance: self.performance,
                      scheduler: ProbeScheduler(maximumActive: 1, maximumQueued: 1).snapshot())
            }, captureLocalNetwork: { _, complete in
                complete(.init(capturedAt: Date(timeIntervalSince1970: 1), localLinkStatus: .available,
                    interfaces: [.init(name: "en-fixture", index: 1, kind: .physical, isUp: true,
                        isRunning: true, ipv4Addresses: ["192.0.2.20"], ipv6Addresses: ["2001:db8::20"])],
                    systemPrimaryIPv4Interface: "en-fixture", systemPrimaryIPv6Interface: "en-fixture",
                    physicalInterfaceName: "en-fixture", physicalInterfaceSelection: .boundInterface,
                    gateways: ["192.0.2.1"], systemDNSServers: ["192.0.2.53"],
                    physicalDNSServers: ["192.0.2.53"], collectionIssues: []))
            }, startDiagnostics: { update in
                self.update = update
                return RuntimeOperation()
            }, now: { self.clock }, applicationVersion: "版本 memory · Build 35", copyReport: { _ in })
        }
    }

    static func run(in host: NSView) throws {
        var assertions = 0, readinessChecks = 0
        func require(_ condition: Bool, _ text: String) throws {
            assertions += 1
            guard condition else { throw Failure(text: text) }
        }
        func drain(until condition: (() -> Bool)? = nil) {
            let deadline = Date().addingTimeInterval(2)
            repeat {
                RunLoop.current.run(until: Date().addingTimeInterval(0.02))
            } while condition.map({ !$0() }) == true && Date() < deadline
            host.layoutSubtreeIfNeeded()
        }
        func textFields(_ view: NSView) -> [NSTextField] {
            view.subviews.flatMap { child in
                (child as? NSTextField).map { [$0] } ?? textFields(child)
            }
        }
        func awaitPresentation(_ condition: () -> Bool, _ phase: String) throws {
            let deadline = Date().addingTimeInterval(2)
            repeat {
                RunLoop.current.run(until: Date().addingTimeInterval(0.002))
            } while !condition() && Date() < deadline
            readinessChecks += 1
            guard condition() else { throw Failure(text: "\(phase): expected presentation state was not delivered within 2s") }
            // Geometry is checked only after the actual public state/text
            // arrived. A height predicate must never make a layout test pass.
            host.layoutSubtreeIfNeeded()
        }
        for size in [NSSize(width: 880, height: 680), NSSize(width: 850, height: 400),
                     NSSize(width: 850, height: 260)] {
            for style in [NSScroller.Style.legacy, .overlay] {
                let environment = Environment()
                let feature = NetworkDiagnosticsFeature(capabilities: environment.capabilities)
                let wrapper = WidthFittingScrollContentView(content: feature.view)
                host.setFrameSize(size)
                wrapper.frame = host.bounds
                wrapper.autoresizingMask = [.width, .height]
                host.addSubview(wrapper)
                let scroll = wrapper.scrollView
                scroll.scrollerStyle = style
                feature.setVisible(true)
                try awaitPresentation({
                    let texts = textFields(feature.view).map(\.stringValue)
                    return texts.contains(NetworkDiagnosticsFormatting.dns(environment.performance))
                        && texts.contains { $0.contains("本地 IPv4：192.0.2.20") }
                }, "initial statistics/local network")
                for _ in 0..<3 {
                    drain()
                    if scroll.scrollerStyle == style { break }
                    scroll.scrollerStyle = style
                }
                try require(scroll.scrollerStyle == style, "requested scroller style was not exercised")
                guard let document = scroll.documentView,
                      let stack = feature.view.subviews.first as? NSStackView,
                      let note = stack.arrangedSubviews.last as? NSTextField,
                      let detectionRows = stack.arrangedSubviews.compactMap({ $0 as? NSStackView })
                        .first(where: { $0.orientation == .vertical }),
                      let copyDNS = stack.arrangedSubviews.compactMap({ $0 as? NSButton })
                        .first(where: { $0.title == "复制 DNS 建连诊断" }) else {
                    throw Failure(text: "missing real diagnostics document or footer")
                }
                let clip = scroll.contentView
                let phase = "\(Int(size.width))x\(Int(size.height))/\(style == .legacy ? "legacy" : "overlay")"
                func shows(_ snapshot: NetworkConnectivityDiagnosticsSnapshot) -> Bool {
                    guard feature.isDetectionRunning == snapshot.isRunning,
                          detectionRows.arrangedSubviews.count == snapshot.rows.count else { return false }
                    return zip(detectionRows.arrangedSubviews, snapshot.rows).allSatisfy { row, expected in
                        let texts = textFields(row).map(\.stringValue)
                        return texts.contains(expected.title)
                            && texts.contains(NetworkDiagnosticsSummary.status(expected))
                            && texts.contains(NetworkDiagnosticsSummary.detail(expected))
                    }
                }
                try require(style == .legacy ? clip.bounds.width < wrapper.bounds.width - 1
                    : abs(clip.bounds.width - wrapper.bounds.width) < 1,
                    "\(phase): requested style did not produce its actual viewport width")

                func verifyBottom(_ update: String) throws {
                    try require(!wrapper.needsLayout,
                                "\(phase)/\(update): content size invalidation did not settle")
                    let copyButton = copyDNS.convert(copyDNS.bounds, to: document)
                    try require(document.bounds.insetBy(dx: -0.5, dy: -0.5).contains(copyButton),
                                "\(phase)/\(update): DNS copy control is outside the scroll document")
                    let copyBounds = NSRect(origin: NSPoint(x: 0,
                        y: max(0, copyButton.maxY - clip.bounds.height)), size: clip.bounds.size)
                    clip.scroll(to: clip.constrainBoundsRect(copyBounds).origin)
                    scroll.reflectScrolledClipView(clip)
                    try require(clip.bounds.insetBy(dx: -0.5, dy: -0.5).contains(copyButton),
                                "\(phase)/\(update): DNS copy control cannot scroll into view")
                    let footer = note.convert(note.bounds, to: document)
                    try require(document.frame.height + 0.5 >= footer.maxY + 8,
                                "\(phase)/\(update): document excludes footer (height \(document.frame.height), footer \(footer))")
                    let bottomBounds = NSRect(origin: NSPoint(x: 0,
                        y: max(0, document.frame.height - clip.bounds.height)), size: clip.bounds.size)
                    clip.scroll(to: clip.constrainBoundsRect(bottomBounds).origin)
                    scroll.reflectScrolledClipView(clip)
                    try require(clip.bounds.insetBy(dx: -0.5, dy: -0.5).contains(footer),
                                "\(phase)/\(update): real constrained bottom cannot show footer")
                    try require(abs(document.frame.width - clip.bounds.width) < 1,
                                "\(phase)/\(update): document width did not follow actual viewport")
                    try require(!wrapper.needsLayout,
                                "\(phase)/\(update): scrolling bounds unnecessarily invalidated outer layout")
                }

                let initialHeight = document.frame.height
                try verifyBottom("initial")
                feature.beginDetection()
                guard let update = environment.update else { throw Failure(text: "missing memory provider callback") }
                let firstRows = try snapshot(count: 14, longDetail: false, running: true)
                update(firstRows)
                try awaitPresentation({ shows(firstRows) }, phase + "/rows14")
                let grownHeight = document.frame.height
                print("Diagnostics scroll \(phase): initial=\(initialHeight), rows14=\(grownHeight), fitting=\(feature.view.fittingSize.height)")
                try require(grownHeight > initialHeight + 600,
                            "\(phase): asynchronous results did not extend the scroll range; initial=\(initialHeight), document=\(grownHeight), fitting=\(feature.view.fittingSize.height)")
                try verifyBottom("rows14")

                // Same row identities: rebuilding the list is not required for
                // detail text to acquire additional wrapped lines.
                let longRows = try snapshot(count: 14, longDetail: true, running: true)
                update(longRows)
                try awaitPresentation({ shows(longRows) }, phase + "/long-detail")
                let longHeight = document.frame.height
                try require(longHeight > grownHeight + 300,
                            "\(phase): same-ID detail growth did not extend the scroll range")
                try verifyBottom("same-ID-long-detail")

                let completedRows = try snapshot(count: 14, longDetail: false, running: false)
                update(completedRows)
                try awaitPresentation({ shows(completedRows) }, phase + "/completed")
                try require(document.frame.height < longHeight - 300 && !feature.isDetectionRunning,
                            "\(phase): completed short details did not shrink the document")
                try verifyBottom("completed")

                // Starting another round clears a completed result. Scrolling
                // must be clamped to the new range while the user is at bottom.
                feature.beginDetection()
                try awaitPresentation({ feature.isDetectionRunning && detectionRows.arrangedSubviews.isEmpty },
                                      phase + "/cleared")
                try require(document.frame.height < grownHeight - 600,
                            "\(phase): clearing the completed list retained its old height")
                try require(clip.bounds.minY <= max(0, document.frame.height - clip.bounds.height) + 0.5,
                            "\(phase): clearing results left the viewport beyond the new bottom")
                try verifyBottom("cleared")

                guard let secondUpdate = environment.update else { throw Failure(text: "missing second memory callback") }
                let secondRows = try snapshot(count: 2, longDetail: false, running: false)
                secondUpdate(secondRows)
                try awaitPresentation({ shows(secondRows) }, phase + "/second-round")
                try verifyBottom("short-second-round")

                let beforeStatistics = document.frame.height
                let performance = try attemptsSnapshot()
                environment.performance = performance
                environment.clock = 2_000_000_000
                feature.refreshIfVisible()
                try awaitPresentation({ copyDNS.isEnabled && textFields(feature.view).contains {
                    $0.stringValue == NetworkDiagnosticsFormatting.dnsAttempts(performance)
                } }, phase + "/DNS-attempts-expanded")
                let expandedStatistics = document.frame.height
                try require(expandedStatistics > beforeStatistics + 250,
                            "\(phase): async statistics/attempt detail growth did not extend the document")
                try verifyBottom("DNS-attempts-expanded")
                environment.performance = .init()
                environment.clock = 4_000_000_000
                feature.refreshIfVisible()
                try awaitPresentation({ !copyDNS.isEnabled && textFields(feature.view).contains {
                    $0.stringValue == NetworkDiagnosticsFormatting.dnsAttempts(.init())
                } }, phase + "/DNS-attempts-cleared")
                try require(document.frame.height < expandedStatistics - 250,
                            "\(phase): cleared DNS attempt text retained its old scroll range")
                try verifyBottom("DNS-attempts-cleared")
                feature.close()
                wrapper.removeFromSuperview()
            }
        }
        print("Diagnostics dynamic scroll passed: \(assertions) assertions; six size/scroller scenes; memory callbacks only; \(readinessChecks) readiness checks")
    }

    private static func attemptsSnapshot() throws -> NetworkPerformanceSnapshot {
        let attempts = (0..<8).map { index -> [String: Any] in
            ["id": "00000000-0000-0000-0000-00000000000\(index)",
             "requestID": "11111111-2222-3333-4444-555555555555", "upstreamID": "upstream-memory",
             "addressID": "address-memory", "provider": "memory-provider", "transport": "doh",
             "purpose": "query", "route": "proxy", "requestFinished": true, "observations": [],
             "omittedObservations": 0, "observedEventCount": 0, "started": 0]
        }
        let decoded = try JSONDecoder().decode([DNSConnectionAttemptSnapshot].self,
            from: JSONSerialization.data(withJSONObject: attempts))
        return NetworkPerformanceSnapshot(dnsConnectionAttempts: decoded)
    }

    private static func snapshot(count: Int, longDetail: Bool, running: Bool) throws
        -> NetworkConnectivityDiagnosticsSnapshot {
        let detail = longDetail ? Array(repeating:
            "固定查询收到匹配 DNS 应答；传输与查询类型分别统计，不能代表所有域名或全部公网目的地。", count: 9).joined(separator: " ")
            : "固定查询收到匹配 DNS 应答；不能代表所有域名或全部公网目的地。"
        let rows: [[String: Any]] = (0..<count).map { index in
            ["id": "memory-row-\(index)", "kind": index < 2 ? "localLatency" : (index < 8 ? "traditionalDNS" : "encryptedDNS"),
             "title": index < 8 ? "普通 DNS \(index) · IPv6 传输 / A 查询" : "加密 DNS \(index) · 固定 A 查询",
             "endpoint": index < 8 ? "[2001:db8::53]:53" : "DoH resolver.example:443",
             "route": "物理接口 en-fixture 直连 · 固定测试", "status": "success", "milliseconds": 40.5,
             "responseCode": 0, "detail": detail]
        }
        return try JSONDecoder().decode(NetworkConnectivityDiagnosticsSnapshot.self,
            from: JSONSerialization.data(withJSONObject: ["id": "11111111-2222-3333-4444-555555555555",
                "startedAt": 0, "updatedAt": 1, "isRunning": running, "omittedEndpointCount": 0, "rows": rows]))
    }
}

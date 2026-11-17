import AppKit
import Foundation
import Network
import HajimiCore
import HajimiDiagnosticsUI
import HajimiMacOSObjC
import HajimiNativeCore
import HajimiRuntime
import HajimiUIComponents
import UniformTypeIdentifiers

extension MainWindowController {
    func resolveLeafProxyName(from policyName: String) -> String {
        var current = policyName
        var visited = Set<String>()
        for _ in 0..<12 {
            guard visited.insert(current).inserted, let group = profile.groups[current] else { break }
            let next = groupSelections[current].flatMap { group.members.contains($0) ? $0 : nil }
                ?? group.members.first
            guard let next else { break }
            current = next
        }
        return current
    }

    func statusItemOptimalMemberName(forGroup groupName: String) -> String? {
        guard let group = profile.groups[groupName] else { return nil }
        var bestName: String?
        var bestMs = Int.max
        for member in group.members {
            let leaf = resolveLeafProxyName(from: member)
            if case .success(let ms)? = nodeLatencies[leaf], ms < bestMs {
                bestMs = ms
                bestName = member
            }
        }
        return bestName
    }

    func statusItemNodeItem(named name: String, optimalName: String? = nil) -> StatusProxyNodeItem {
        let proto: String
        let leaf = resolveLeafProxyName(from: name)
        if let policy = profile.proxies[name] {
            if let raw = policy.adapterType, !raw.isEmpty {
                proto = raw.uppercased()
            } else {
                proto = policy.kind.rawValue.uppercased()
            }
        } else if profile.groups[name] != nil {
            proto = "GROUP"
        } else {
            proto = "DIRECT"
        }
        let lat: NodeLatency
        if name.uppercased() == "DIRECT" || leaf.uppercased() == "DIRECT" {
            lat = .untested
        } else {
            lat = nodeLatencies[name] ?? nodeLatencies[leaf] ?? .untested
        }
        let ms: Int?
        if case .success(let value) = lat {
            ms = value
        } else {
            ms = nil
        }
        let best = optimalName ?? statusItemOptimalNodeName
        return StatusProxyNodeItem(
            name: name,
            protocolTag: proto,
            latency: lat,
            latencyMillis: ms,
            isOptimal: best != nil && best == name
        )
    }

    var isStatusItemTestingNodes: Bool {
        !nodeProbeRequests.isEmpty || nodeProbeBatch != nil
    }

    var statusItemLatencySummary: String {
        let nodes = profile.globalProxyNodes
        guard !nodes.isEmpty else { return "暂无可测速节点" }
        var testedCount = 0
        var reachableCount = 0
        var fastest: Int?
        for name in nodes {
            guard let lat = nodeLatencies[name] else { continue }
            switch lat {
            case .untested, .queued, .testing:
                break
            case .success(let ms):
                testedCount += 1
                reachableCount += 1
                if let currentFastest = fastest {
                    if ms < currentFastest { fastest = ms }
                } else {
                    fastest = ms
                }
            case .failed, .unavailable:
                testedCount += 1
            }
        }
        if isStatusItemTestingNodes {
            return "⚡ 正在测速 (\(testedCount)/\(nodes.count))…"
        }
        if testedCount == 0 {
            return "⚡ 节点延迟测速（共 \(nodes.count) 个节点）"
        }
        if let fastest {
            return "⚡ 节点测速：可用 \(reachableCount)/\(nodes.count) · 最快 \(fastest) ms"
        }
        return "⚡ 节点测速：已测 \(testedCount)/\(nodes.count) · 暂无可达"
    }

    func statusItemTelemetrySnapshot(uploadRate: Double, downloadRate: Double) -> StatusBarTelemetrySnapshot {
        let activeNode: String
        let rawTargetForLatency: String
        switch selectedModeForExtension {
        case .direct:
            activeNode = "DIRECT"
            rawTargetForLatency = "DIRECT"
        case .proxy:
            activeNode = statusItemGlobalPolicy
            rawTargetForLatency = activeNode
        case .rule:
            if let firstGroup = statusItemPolicyGroups.first,
               let effective = firstGroup.selectedMember ?? firstGroup.effectiveMember {
                let leaf = resolveLeafProxyName(from: effective)
                activeNode = (leaf != effective && !leaf.isEmpty && leaf != "DIRECT")
                    ? "\(effective) · \(leaf)"
                    : effective
                rawTargetForLatency = effective
            } else if let firstGroupName = profile.groupOrder.first {
                let leaf = resolveLeafProxyName(from: firstGroupName)
                activeNode = leaf
                rawTargetForLatency = firstGroupName
            } else {
                activeNode = profile.globalProxyNodes.first ?? "DIRECT"
                rawTargetForLatency = activeNode
            }
        }
        let leafNode = resolveLeafProxyName(from: rawTargetForLatency)
        let latencyMs: Int
        if let lat = nodeLatencies[leafNode] ?? nodeLatencies[activeNode] {
            switch lat {
            case .success(let ms): latencyMs = max(1, ms)
            case .failed, .unavailable: latencyMs = 0
            case .untested, .queued, .testing: latencyMs = -1
            }
        } else {
            latencyMs = -1
        }
        let totalUp = UInt64(max(0, uploaded)) + enhancedUploaded
        let totalDown = UInt64(max(0, downloaded)) + enhancedDownloaded
        let activeConns = activeConnectionIDs.count + enhancedActiveConnections
        return StatusBarTelemetrySnapshot(
            running: isEngineActive || isEnhancedModeActive,
            enhancedMode: isEnhancedModeActive,
            systemProxy: isSystemProxyActive,
            modeTitle: statusItemOutboundMode.displayName,
            activeNodeName: activeNode,
            activeNodeLatencyMillis: latencyMs,
            uploadBytesPerSecond: uploadRate,
            downloadBytesPerSecond: downloadRate,
            totalUploadedBytes: totalUp,
            totalDownloadedBytes: totalDown,
            activeConnections: activeConns
        )
    }

    func testAllNodesFromStatusItem() {
        testAllNodes()
        onStatusBarStateChanged?()
    }

    func testSingleNodeFromStatusItem(_ name: String) {
        guard profile.proxies[name] != nil else { return }
        testNode(named: name)
        onStatusBarStateChanged?()
    }

    func testActiveNodeFromStatusItem() {
        let snapshot = statusItemTelemetrySnapshot(uploadRate: 0, downloadRate: 0)
        let targetLeaf: String
        if selectedModeForExtension == .rule, let firstGroup = statusItemPolicyGroups.first,
           let eff = firstGroup.selectedMember ?? firstGroup.effectiveMember {
            targetLeaf = resolveLeafProxyName(from: eff)
        } else {
            targetLeaf = resolveLeafProxyName(from: snapshot.activeNodeName)
        }
        if profile.proxies[targetLeaf] != nil {
            testSingleNodeFromStatusItem(targetLeaf)
        } else if let first = profile.globalProxyNodes.first {
            testSingleNodeFromStatusItem(first)
        } else {
            testAllNodesFromStatusItem()
        }
    }

    func testGroupNodesFromStatusItem(group groupName: String) {
        guard let group = profile.groups[groupName] else { return }
        var seen = Set<String>()
        var nodes: [String] = []
        func appendProxy(_ candidate: String) {
            guard profile.proxies[candidate] != nil, profile.groups[candidate] == nil,
                  seen.insert(candidate).inserted else { return }
            nodes.append(candidate)
        }
        for member in group.members {
            if profile.proxies[member] != nil && profile.groups[member] == nil {
                appendProxy(member)
            } else if profile.groups[member] != nil {
                appendProxy(resolveLeafProxyName(from: member))
            }
        }
        if nodes.isEmpty {
            for member in group.members {
                if let sub = profile.groups[member] {
                    for subMember in sub.members {
                        appendProxy(resolveLeafProxyName(from: subMember))
                    }
                }
            }
        }
        guard !nodes.isEmpty else { return }
        cancelNodeTests(refresh: false)
        for name in nodes { nodeLatencies[name] = .queued }
        nodeProbeBatch = NodeProbeBatchCursor(names: nodes)
        policyStatusLabel.stringValue = "正在测试策略组 \(groupName) 的 \(nodes.count) 个节点…"
        policyStatusLabel.textColor = .systemBlue
        pumpNodeProbeBatch(refreshStarts: false)
        schedulePolicyCardUpdates(proxies: Set(nodes), immediately: true)
        onStatusBarStateChanged?()
    }

    var statusItemPolicyGroups: [StatusPolicyGroupSelection] {
        profile.groupOrder.compactMap { name in
            guard let group = profile.groups[name], group.showsInStatusBar else { return nil }
            let current = groupSelections[name].flatMap { group.members.contains($0) ? $0 : nil }
            let isManual = !PolicyHealthMonitor.managesSelection(of: group) || manualManagedGroupSelections.contains(name)
            let explicit = isManual ? current : nil
            let effective = current ?? group.members.first
            return StatusPolicyGroupSelection(
                name: name,
                kind: group.kind,
                members: group.members,
                selectedMember: explicit,
                effectiveMember: effective
            )
        }
    }

    /// Bytes per second, engine and helper combined.
    ///
    /// This advances the measurement windows, so it is a function rather than a
    /// property: calling it twice in the same tick would consume a window and
    /// halve the reported rate.
    func statusItemTrafficRate() -> (upload: Double, download: Double) {
        let now = ProcessInfo.processInfo.systemUptime
        if isEngineActive {
            engineUploadRate.observe(UInt64(max(0, uploaded)), at: now)
            engineDownloadRate.observe(UInt64(max(0, downloaded)), at: now)
        } else {
            engineUploadRate.idle(at: now)
            engineDownloadRate.idle(at: now)
        }
        if !isEnhancedModeActive {
            enhancedUploadRate.idle(at: now)
            enhancedDownloadRate.idle(at: now)
        }
        let rates = (upload: engineUploadRate.bytesPerSecond + enhancedUploadRate.bytesPerSecond,
                     download: engineDownloadRate.bytesPerSecond + enhancedDownloadRate.bytesPerSecond)
        nativeTrafficView.update(uploadBytesPerSecond: rates.upload, downloadBytesPerSecond: rates.download,
                                 activeConnections: activeConnectionIDs.count + enhancedActiveConnections)
        return rates
    }

    

    func revealFromStatusItem() {
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if !dashboardView.isHidden {
            updateStatistics(force: true)
            nativeTrafficView.needsDisplay = true
        }
        applyPendingPolicyCardUpdates()
    }

    func toggleEngineFromStatusItem() { toggleEngineForExtension() }

    func toggleSystemProxyFromStatusItem() {
        systemProxyButton.state = isSystemProxyActive ? .off : .on
        toggleSystemProxyForExtension()
    }

    func toggleEnhancedModeFromStatusItem() {
        enhancedModeButton.state = isEnhancedModeActive ? .off : .on
        toggleEnhancedModeForExtension()
    }

    func selectOutboundModeFromStatusItem(_ mode: OutboundMode) {
        guard let index = OutboundMode.allCases.firstIndex(of: mode) else { return }
        modePopup.selectItem(at: index)
        modeChangedForExtension()
        onStatusBarStateChanged?()
    }

    func selectGlobalPolicyFromStatusItem(_ name: String) {
        guard profile.groups[name] == nil, profile.selectablePolicies.contains(name) else { return }
        if selectedModeForExtension != .proxy {
            modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: .proxy) ?? 2)
            UserDefaults.standard.set(OutboundMode.proxy.rawValue, forKey: "outboundMode")
            policyPopup.isEnabled = true
        }
        policyPopup.selectItem(withTitle: name)
        policyChanged()
        onStatusBarStateChanged?()
    }

    func selectGroupMemberFromStatusItem(group: String, member: String?) {
        guard let policyGroup = profile.groups[group] else { return }
        if let member, !policyGroup.members.contains(member) { return }
        setGroupSelection(group: group, member: member)
        onStatusBarStateChanged?()
    }

    /// Best-effort helper teardown for process exit. Safe to call more than once.
    func shutdownEnhancedModeForQuit() {
        diagnosticsPanel?.closeAndTeardown()
        diagnosticsPanel = nil
        if let ticket = enhancedRequestIntent.cancel() { enhancedRequestIntent.release(ticket) }
        enhancedMode.shutdownForQuit()
        networkRuntime.lifecycleDidChange()
        enhancedModeButton.state = .off
        dataPlaneRuntimeValue.stringValue = "HajimiNativeCore"
        enhancedActiveConnections = 0
        enhancedTotalConnections = 0
        enhancedUploaded = 0
        enhancedDownloaded = 0
    }

    func restoreSystemProxyBeforeQuit() throws {
        cancelLaunchRestorePreparationForExtension()
        // Enhanced mode is stopped separately in applicationShouldTerminate so
        // a system-proxy restore failure cannot leave utun routes installed.
        if enhancedMode.isEnabled { enhancedMode.shutdownForQuit() }
        // Always join the manager queue: an enable may have been enqueued but
        // not yet saved its snapshot when the user chooses Quit.
        try systemProxy.disableSynchronously()
        stopListenerResourcesForExtension()
        externalController.stop()
    }
}

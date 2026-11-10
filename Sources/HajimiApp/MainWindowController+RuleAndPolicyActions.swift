import Network
import AppKit
import HajimiCore
import HajimiDiagnosticsUI
import HajimiMacOSObjC
import HajimiNativeCore
import HajimiRuntime
import HajimiUIComponents
import UniformTypeIdentifiers

extension MainWindowController {
    @objc func addRule() {
        guard let window, ruleEditor == nil, rulePolicyEditor == nil else { return }
        refreshRulesPage()
        do {
            let snapshot = try ruleEditingSnapshot()
            let editor = RuleEditorSheetController(draft: nil, policyNames: rulePolicyNames) { [weak self] draft in
                guard let self else { return }
                try self.verifyRuleEditingSnapshot(snapshot)
                try self.validateRulePolicy(draft.policy, in: snapshot.text)
                var document = SurgeProfileDocument(snapshot.text)
                let line = try document.insertRule(draft)
                try self.applyRuleChange(document.text, snapshot: snapshot,
                                         prefix: "已新增并应用规则", selection: [line])
            }
            ruleEditor = editor
            guard let sheet = editor.window else { ruleEditor = nil; return }
            window.beginSheet(sheet) { [weak self] _ in self?.ruleEditor = nil }
        } catch {
            showError(title: "无法新增规则", error: error)
        }
    }

    @objc func editSelectedRules() {
        guard let window, ruleEditor == nil, rulePolicyEditor == nil else { return }
        do {
            let snapshot = try ruleEditingSnapshot()
            let lines = selectedRuleSourceLines
            guard !lines.isEmpty else { return }
            if lines.count > 1 {
                let editor = RulePolicySheetController(count: lines.count,
                                                       policyNames: rulePolicyNames) { [weak self] policy in
                    guard let self else { return }
                    try self.verifyRuleEditingSnapshot(snapshot)
                    try self.validateRulePolicy(policy, in: snapshot.text)
                    var document = SurgeProfileDocument(snapshot.text)
                    try document.setRulePolicies(atSourceLines: lines, policy: policy)
                    try self.applyRuleChange(document.text, snapshot: snapshot,
                                             prefix: "已更新并应用 \(lines.count) 条规则的策略",
                                             selection: lines)
                }
                rulePolicyEditor = editor
                guard let sheet = editor.window else { rulePolicyEditor = nil; return }
                window.beginSheet(sheet) { [weak self] _ in self?.rulePolicyEditor = nil }
            } else if let line = lines.first {
                let draft = try SurgeProfileDocument(snapshot.text).ruleDraft(atSourceLine: line)
                let editor = RuleEditorSheetController(draft: draft,
                                                       policyNames: rulePolicyNames) { [weak self] updated in
                    guard let self else { return }
                    try self.verifyRuleEditingSnapshot(snapshot)
                    try self.validateRulePolicy(updated.policy, in: snapshot.text)
                    var document = SurgeProfileDocument(snapshot.text)
                    try document.updateRule(atSourceLine: line, draft: updated)
                    let changed = try ProfileParser.parse(document.text)
                    let catchAll = ["FINAL", "MATCH"].contains(updated.type.uppercased())
                    let selectedLine = catchAll
                        ? changed.rules.first(where: { $0.kind == .final })?.sourceLine : line
                    let selection = selectedLine.map { Set([$0]) } ?? []
                    try self.applyRuleChange(document.text, snapshot: snapshot,
                                             prefix: "已更新并应用规则",
                                             selection: selection)
                }
                ruleEditor = editor
                guard let sheet = editor.window else { ruleEditor = nil; return }
                window.beginSheet(sheet) { [weak self] _ in self?.ruleEditor = nil }
            }
        } catch {
            showError(title: "无法编辑规则", error: error)
        }
    }

    @objc func deleteSelectedRules() {
        guard let window else { return }
        do {
            let snapshot = try ruleEditingSnapshot()
            let lines = selectedRuleSourceLines
            guard !lines.isEmpty else { return }
            let selected = filteredRules.filter { lines.contains($0.sourceLine) }
            let preview = selected.prefix(6).map { rule in
                let description = ruleDescription(rule)
                return "第 \(rule.sourceLine) 行 · \(description.type) · \(description.value.prefix(90))"
            }.joined(separator: "\n")
            let more = selected.count > 6 ? "\n…另有 \(selected.count - 6) 条" : ""
            let finalWarning = selected.contains { $0.kind == .final }
                ? "\n\n包含 FINAL / MATCH 兜底规则，删除会改变未命中流量的处理方式。" : ""
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "删除选中的 \(lines.count) 条规则？"
            alert.informativeText = preview + more + finalWarning + "\n\n只删除选中主规则，保存后应用；不会删除远程规则集源文件。"
            alert.addButton(withTitle: "删除")
            alert.addButton(withTitle: "取消")
            alert.buttons[0].keyEquivalent = ""
            alert.buttons[1].keyEquivalent = "\r"
            alert.beginSheetModal(for: window) { [weak self] response in
                guard response == .alertFirstButtonReturn, let self else { return }
                do {
                    try self.verifyRuleEditingSnapshot(snapshot)
                    var document = SurgeProfileDocument(snapshot.text)
                    try document.deleteRules(atSourceLines: lines)
                    try self.applyRuleChange(document.text, snapshot: snapshot,
                                             prefix: "已删除并应用 \(lines.count) 条规则", selection: [])
                } catch {
                    self.showError(title: "无法删除规则", error: error)
                }
            }
        } catch {
            showError(title: "无法删除规则", error: error)
        }
    }

    @objc func updateRuleSets() {
        do {
            let snapshot = try ruleEditingSnapshot()
            let locations = selectedRuleSetLocations
            guard !locations.isEmpty else { return }
            try applyRuleChange(snapshot.text, snapshot: snapshot,
                                prefix: "已更新并应用 \(locations.count) 个规则集",
                                selection: selectedRuleSourceLines,
                                forceRefreshLocations: locations)
        } catch {
            showError(title: "无法更新规则集", error: error)
        }
    }

    func applyRuleChange(_ text: String, snapshot: (text: String, revision: Int),
                                 prefix: String, selection: Set<Int>,
                                 forceRefreshLocations: Set<String> = []) throws {
        try verifyRuleEditingSnapshot(snapshot)
        _ = try ProfileParser.parse(text)
        let requestID = UUID()
        ruleOperationID = requestID
        ruleStatusLabel.stringValue = forceRefreshLocations.isEmpty
            ? "正在后台保存并应用规则…"
            : "正在后台更新 \(forceRefreshLocations.count) 个规则集，界面可继续使用…"
        ruleStatusLabel.textColor = .systemBlue
        ruleStatusLabel.toolTip = nil
        updateRuleSelectionControls()
        let recoveryGuard = ProfileApplyCommitGuard(generation: profileApplyGeneration &+ 1,
                                                     revision: snapshot.revision,
                                                     editorText: snapshot.text)
        applyProfileTextInBackground(
            text, prefix: prefix, keepEditorOnFailure: true,
            forceRefreshRuleSetLocations: forceRefreshLocations,
            stillApplicable: { [weak self] in self?.ruleOperationID == requestID }
        ) { [weak self] result in
            guard let self, self.ruleOperationID == requestID else { return }
            self.ruleOperationID = nil
            switch result {
            case .success:
                let warnings = (self.resolvedProfile?.warnings ?? [])
                    .filter { $0.contains("RULE-SET") && $0.contains("更新失败") }
                self.ruleStatusLabel.stringValue = warnings.isEmpty ? prefix
                    : (forceRefreshLocations.isEmpty ? prefix + "；部分资源使用旧缓存"
                       : "规则集检查已完成；部分更新失败，已继续使用旧缓存")
                self.ruleStatusLabel.textColor = warnings.isEmpty ? .systemGreen : .systemOrange
                self.ruleStatusLabel.toolTip = warnings.isEmpty ? nil : warnings.joined(separator: "\n")
                self.refreshRulesPage(selecting: selection)
            case .failure(let error):
                // Keep a recoverable UI draft only if no newer edit replaced
                // its baseline or superseded the save, even with identical text.
                // The disk and running configuration stay intact.
                let keepDraft = text != snapshot.text &&
                    recoveryGuard.isCurrent(generation: self.profileApplyGeneration,
                                            revision: self.profileRevision,
                                            editorText: self.profileTextView.string)
                if keepDraft { self.profileTextView.string = text }
                self.refreshRulesPage()
                self.ruleStatusLabel.stringValue = "未应用：\(error.localizedDescription)"
                    
                self.ruleStatusLabel.textColor = .systemRed
                self.ruleStatusLabel.toolTip = error.localizedDescription
            }
            self.updateRuleSelectionControls()
        }
    }

    @objc func addProxy() {
        presentProxyEditor(draft: nil, originalName: nil, isNew: true)
    }

    @objc func importShareLinks() {
        guard let window else { return }
        ShareLinkImportSheetController.present(
            on: window,
            title: "导入分享链接",
            confirmTitle: "导入节点",
            allowMultiple: true
        ) { [weak self] rawLinks in
            guard let self else { return }
            do {
                let result = try self.commitShareLinks(rawLinks)
                let shownNames = result.names.prefix(8).joined(separator: "、")
                var message = "已添加 \(result.names.count) 个节点：\(shownNames)"
                if result.names.count > 8 { message += " 等" }
                if !result.warnings.isEmpty {
                    message += "\n\n" + result.warnings.prefix(8).joined(separator: "\n")
                    if result.warnings.count > 8 {
                        message += "\n另有 \(result.warnings.count - 8) 条提示"
                    }
                }
                if self.subscriptions.isActiveSubscriptionRemoteURL {
                    message += "\n\n提示：当前使用的是 URL 下载的订阅配置，更新订阅会覆盖原文件中新增的节点或策略组信息。"
                }
                self.showMessage(title: "分享链接已导入", text: message)
            } catch {
                self.showError(title: "导入分享链接失败", error: error)
            }
        }
    }

    @objc func addPolicyGroup() {
        presentGroupEditor(draft: nil, originalName: nil, isNew: true)
    }

    @objc func editSelectedProxy() {
        let row = proxyTableView.clickedRow >= 0 ? proxyTableView.clickedRow : proxyTableView.selectedRow
        guard filteredProxyNames.indices.contains(row) else { return }
        editProxy(named: filteredProxyNames[row])
    }

    @objc func proxyMenuEdit(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        editProxy(named: name)
    }

    @objc func proxyMenuDuplicate(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String,
              let policy = profile.proxies[name] else { return }
        var draft = SurgeProxyDraft(policy: policy)
        draft.name = uniqueProxyName(basedOn: name)
        presentProxyEditor(draft: draft, originalName: nil, isNew: true)
    }

    @objc func proxyMenuDelete(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        confirmDeleteProxy(named: name)
    }

    @objc func proxyMenuUse(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        useProxy(named: name)
    }

    @objc func proxyMenuTest(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        testNode(named: name)
    }

    @objc func groupMenuEdit(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String,
              let group = profile.groups[name] else { return }
        presentGroupEditor(draft: SurgePolicyGroupDraft(group: group),
                           originalName: name, isNew: false)
    }

    @objc func groupMenuDuplicate(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String,
              let group = profile.groups[name] else { return }
        var draft = SurgePolicyGroupDraft(group: group)
        draft.name = uniqueGroupName(basedOn: name)
        presentGroupEditor(draft: draft, originalName: nil, isNew: true)
    }

    @objc func groupMenuDelete(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        confirmDeleteGroup(named: name)
    }

    @objc func testAllNodes() {
        cancelNodeTests(refresh: false)
        for name in profile.proxyOrder { nodeLatencies[name] = .queued }
        nodeProbeBatch = NodeProbeBatchCursor(names: profile.proxyOrder)
        policyStatusLabel.stringValue = "正在测试 \(profile.proxyOrder.count) 个节点（独立并发队列 24，排队不计入延迟）…"
        policyStatusLabel.textColor = .systemBlue
        pumpNodeProbeBatch(refreshStarts: false)
        schedulePolicyCardUpdates(proxies: Set(profile.proxyOrder), immediately: true)
    }

    func isEditableProxy(named name: String) -> Bool {
        guard let policy = profile.proxies[name],
              policy.kind != .direct, policy.kind != .reject else { return false }
        if policy.adapterType?.lowercased() == "wireguard" {
            return SurgeProfileDocument(profileTextView.string).containsProxy(named: name)
        }
        return true
    }

    func editProxy(named name: String) {
        guard isEditableProxy(named: name) else {
            showMessage(title: "请在原始配置中编辑",
                        text: "“\(name)”来自 [WireGuard \(name)] 等独立配置段，暂不支持直接编辑；它仍可复制为新的 [Proxy] 节点。")
            return
        }
        guard let policy = profile.proxies[name] else { return }
        presentProxyEditor(draft: SurgeProxyDraft(policy: policy), originalName: name, isNew: false)
    }

    func editPolicyGroup(named name: String) {
        guard let group = profile.groups[name] else { return }
        presentGroupEditor(draft: SurgePolicyGroupDraft(group: group), originalName: name, isNew: false)
    }

    func presentProxyEditor(draft: SurgeProxyDraft?, originalName: String?, isNew: Bool) {
        guard let window, nodeEditor == nil else { return }
        let unavailable = Set(profile.proxies.keys).union(profile.groups.keys)
        let editor = SurgeProxyEditorController(draft: draft, isNew: isNew,
                                                unavailableNames: unavailable,
                                                availableProxyNames: profile.proxyOrder) { [weak self] updated in
            guard let self else { return }
            try self.commitProxyDraft(updated, originalName: originalName)
        }
        nodeEditor = editor
        guard let sheet = editor.window else { nodeEditor = nil; return }
        window.beginSheet(sheet) { [weak self] _ in self?.nodeEditor = nil }
    }

    func presentGroupEditor(draft: SurgePolicyGroupDraft?, originalName: String?, isNew: Bool) {
        guard let window, groupEditor == nil, nodeEditor == nil else { return }
        let unavailable = Set(profile.proxies.keys).union(profile.groups.keys)
        var policies = profile.groupOrder + profile.proxyOrder
        for builtin in ["DIRECT", "REJECT"] where !policies.contains(builtin) { policies.append(builtin) }
        let editor = PolicyGroupEditorController(draft: draft, isNew: isNew,
                                                 unavailableNames: unavailable,
                                                 availablePolicies: policies) { [weak self] updated in
            guard let self else { return }
            try self.commitGroupDraft(updated, originalName: originalName)
        }
        groupEditor = editor
        guard let sheet = editor.window else { groupEditor = nil; return }
        window.beginSheet(sheet) { [weak self] _ in self?.groupEditor = nil }
    }

    func notifyURLSubscriptionEditIfNeeded() {
        guard subscriptions.isActiveSubscriptionRemoteURL,
              let sub = subscriptions.activeSubscription else { return }
        policyStatusLabel.stringValue += "（URL 订阅提示：更新订阅会覆盖新增或修改的节点/策略组）"
        DispatchQueue.main.async { [weak self] in
            guard let self, let window = self.window else { return }
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = "已保存到配置文件（URL 订阅提示）"
            alert.informativeText = "当前使用的是 URL 下载的订阅配置“\(sub.name)”，本次编辑的节点或策略组已直接保存到本地配置文件，下次打开应用无需重新添加。\n\n请注意：后续如果执行“更新订阅”，远程下载的订阅内容将会覆盖原文件中新增或修改的节点与策略组信息。"
            alert.addButton(withTitle: "知道了")
            alert.beginSheetModal(for: window, completionHandler: nil)
        }
    }

    func commitProxyDraft(_ draft: SurgeProxyDraft, originalName: String?) throws {
        var document = SurgeProfileDocument(profileTextView.string)
        try document.upsertProxy(originalName: originalName, draft: draft,
                                 appendToSelectGroups: originalName == nil)

        let oldSelectedPolicy = selectedPolicy
        let preferredPolicy = oldSelectedPolicy == originalName ? draft.name : oldSelectedPolicy
        let previousSelections = groupSelections
        let oldLatency = originalName.flatMap { nodeLatencies[$0] }
        let oldHost = originalName.flatMap { profile.proxies[$0]?.host }
        let oldPort = originalName.flatMap { profile.proxies[$0]?.port }
        let replacedPolicy: (from: String, to: String)? =
            (originalName != nil && originalName != draft.name) ? (originalName!, draft.name) : nil
        if let originalName, originalName != draft.name {
            for (group, member) in groupSelections where member == originalName {
                groupSelections[group] = draft.name
            }
        }
        do {
            try applyProfileText(document.text, prefix: originalName == nil ? "已添加并应用节点" : "已更新并应用节点",
                                 preferredPolicy: preferredPolicy,
                                 reusingRulesFrom: profile,
                                 replacedRulePolicy: replacedPolicy)
        } catch {
            groupSelections = previousSelections
            throw error
        }
        if let originalName, originalName != draft.name,
           let oldLatency, oldHost == draft.host, oldPort == draft.port {
            nodeLatencies[draft.name] = oldLatency
            schedulePolicyCardUpdates(proxies: [draft.name])
        }
        policyStatusLabel.stringValue = "✓ \(draft.name) 已保存到配置文件" +
            ((engineStatus == .running || engineStatus == .starting) ? "，代理引擎已热重载" : "")
        policyStatusLabel.textColor = .systemGreen
        notifyURLSubscriptionEditIfNeeded()
    }

    func commitShareLinks(_ text: String) throws
        -> (names: [String], warnings: [String]) {
        let parsed = try ShareLinkSubscription.parse(text)
        var document = SurgeProfileDocument(profileTextView.string)
        var used = Set(profile.proxies.keys).union(profile.groups.keys)
        var names: [String] = []
        var drafts: [SurgeProxyDraft] = []
        var warnings = parsed.warnings

        for policy in parsed.proxies {
            var draft = SurgeProxyDraft(policy: policy)
            let original = draft.name
            var candidate = original
            var suffix = 2
            while used.contains(candidate) {
                candidate = "\(original) \(suffix)"
                suffix += 1
            }
            if candidate != original {
                warnings.append("节点名已调整：\(original) → \(candidate)")
            }
            draft.name = candidate
            drafts.append(draft)
            used.insert(candidate)
            names.append(candidate)
        }
        try document.insertProxies(drafts, appendToSelectGroups: true)

        try applyProfileText(document.text, prefix: "已导入分享链接",
                             preferredPolicy: selectedPolicy,
                             reusingRulesFrom: profile)
        policyStatusLabel.stringValue = "✓ 已从分享链接导入 \(names.count) 个节点并保存到配置文件"
        policyStatusLabel.textColor = .systemGreen
        notifyURLSubscriptionEditIfNeeded()
        return (names, warnings)
    }

    func commitGroupDraft(_ draft: SurgePolicyGroupDraft, originalName: String?) throws {
        var document = SurgeProfileDocument(profileTextView.string)
        try document.upsertGroup(originalName: originalName, draft: draft)
        let preferredPolicy = selectedPolicy == originalName ? draft.name : selectedPolicy
        let previousSelections = groupSelections
        let replacedPolicy: (from: String, to: String)? =
            (originalName != nil && originalName != draft.name) ? (originalName!, draft.name) : nil
        if let originalName, originalName != draft.name {
            let oldSelection = groupSelections.removeValue(forKey: originalName)
            if let oldSelection, draft.members.contains(oldSelection) {
                groupSelections[draft.name] = oldSelection
            }
            for (group, member) in groupSelections where member == originalName {
                groupSelections[group] = draft.name
            }
        }
        do {
            try applyProfileText(document.text,
                                 prefix: originalName == nil ? "已添加并应用策略组" : "已更新并应用策略组",
                                 preferredPolicy: preferredPolicy,
                                 preferredGroup: draft.name,
                                 reusingRulesFrom: profile,
                                 replacedRulePolicy: replacedPolicy)
        } catch {
            groupSelections = previousSelections
            throw error
        }
        policyStatusLabel.stringValue = "✓ 策略组 \(draft.name) 已保存到配置文件并应用"
        policyStatusLabel.textColor = .systemGreen
        notifyURLSubscriptionEditIfNeeded()
    }

    func confirmDeleteProxy(named name: String) {
        guard isEditableProxy(named: name) else {
            showMessage(title: "不能在节点列表删除",
                        text: "该节点来自独立的 WireGuard 配置段，请通过更新或更换订阅移除。")
            return
        }
        let groupReferences = profile.groups.values.filter { $0.members.contains(name) }.count
        let ruleReferences = profile.rules.filter { $0.policy == name }.count
        let dialerReferences = profile.adapterPolicies.filter {
            $0.parameters["underlying-proxy"] == name || $0.parameters["dialer-proxy"] == name
        }.count
        let alert = NSAlert()
        alert.messageText = "删除节点“\(name)”？"
        alert.informativeText = "将从 \(groupReferences) 个策略组移除，并把 \(ruleReferences) 条规则、\(dialerReferences) 个底层代理引用改为 DIRECT。修改会立即写入并应用。"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "删除")
        alert.addButton(withTitle: "取消")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self else { return }
            do {
                var updated = SurgeProfileDocument(self.profileTextView.string)
                try updated.deleteProxy(named: name)
                let preferred = self.selectedPolicy == name ? "DIRECT" : self.selectedPolicy
                try self.applyProfileText(updated.text, prefix: "已删除并应用节点",
                                          preferredPolicy: preferred,
                                          reusingRulesFrom: self.profile,
                                          replacedRulePolicy: (name, "DIRECT"))
                self.policyStatusLabel.stringValue = "✓ 已删除 \(name)，相关引用已安全更新"
                self.policyStatusLabel.textColor = .systemGreen
                self.notifyURLSubscriptionEditIfNeeded()
            } catch {
                self.showError(title: "删除节点失败", error: error)
            }
        }
    }

    func confirmDeleteGroup(named name: String) {
        let nestedReferences = profile.groups.values.filter { $0.name != name && $0.members.contains(name) }.count
        let ruleReferences = profile.rules.filter { $0.policy == name }.count
        let alert = NSAlert()
        alert.messageText = "删除策略组“\(name)”？"
        alert.informativeText = "将从 \(nestedReferences) 个上级策略组移除，并把 \(ruleReferences) 条规则引用切换到 DIRECT。"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "删除")
        alert.addButton(withTitle: "取消")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self else { return }
            do {
                var document = SurgeProfileDocument(self.profileTextView.string)
                try document.deleteGroup(named: name)
                let preferred = self.selectedPolicy == name ? "DIRECT" : self.selectedPolicy
                try self.applyProfileText(document.text, prefix: "已删除并应用策略组",
                                          preferredPolicy: preferred,
                                          reusingRulesFrom: self.profile,
                                          replacedRulePolicy: (name, "DIRECT"))
                self.policyStatusLabel.stringValue = "✓ 已删除策略组 \(name)"
                self.policyStatusLabel.textColor = .systemGreen
                self.notifyURLSubscriptionEditIfNeeded()
            } catch { self.showError(title: "删除策略组失败", error: error) }
        }
    }

    func useProxy(named name: String) {
        guard profile.groups[name] == nil, profile.selectablePolicies.contains(name) else { return }
        modePopup.selectItem(at: OutboundMode.allCases.firstIndex(of: .proxy) ?? 2)
        policyPopup.selectItem(withTitle: name)
        policyPopup.isEnabled = true
        UserDefaults.standard.set(OutboundMode.proxy.rawValue, forKey: "outboundMode")
        UserDefaults.standard.set(name, forKey: "globalPolicy")
        updateEngineRoutingForExtension()
        updateOverviewDetailsForExtension()
        refreshActiveProxyCards()
        policyStatusLabel.stringValue = "✓ 全局代理已切换到 \(name)，新连接立即使用"
        policyStatusLabel.textColor = .systemGreen
    }

    func testNode(named name: String) {
        // A new manual test supersedes a running bulk round. No old queued or
        // late callback may overwrite the fresh per-node request identifier.
        if nodeProbeBatch != nil { cancelNodeTests() }
        policyStatusLabel.stringValue = "正在测试节点 TCP 建连延迟（排队不计入延迟）…"
        policyStatusLabel.textColor = .systemBlue
        startNodeProbe(named: name, requestID: UUID(), batchID: nil, refreshStart: true)
    }

    func startNodeProbe(named name: String, requestID: UUID, batchID: UUID?, refreshStart: Bool) {
        nodeProbeTickets.removeValue(forKey: name)?.cancel()
        nodeProbeRequests[name] = requestID
        let epoch = nodeProbeEpoch
        guard let policy = profile.proxies[name], let host = policy.host, let port = policy.port else {
            // Keep even invalid-node completions asynchronous so a large
            // invalid profile cannot recursively refill the entire batch.
            DispatchQueue.main.async { [weak self] in
                self?.finishNodeProbe(named: name, requestID: requestID, batchID: batchID,
                                      epoch: epoch, result: .failure(NWError.posix(.EINVAL)))
            }
            return
        }
        nodeLatencies[name] = .testing
        if refreshStart { schedulePolicyCardUpdates(proxies: [name]) }
        let isUDP = TCPNodeLatencyProbe.usesUDPTransport(policy)
        nodeProbeTickets[name] = TCPNodeLatencyProbe.measure(host: host, port: port, udp: isUDP) { [weak self] result in
            self?.finishNodeProbe(named: name, requestID: requestID, batchID: batchID, epoch: epoch, result: result)
        }
    }

    func finishNodeProbe(named name: String, requestID: UUID, batchID: UUID?, epoch: UInt64,
                                 result: Result<Int, Error>) {
        guard nodeProbeEpoch == epoch, nodeProbeRequests[name] == requestID else { return }
        nodeProbeRequests.removeValue(forKey: name)
        nodeProbeTickets.removeValue(forKey: name)
        switch result {
        case .success(let milliseconds): nodeLatencies[name] = .success(milliseconds)
        case .failure(let error):
            nodeLatencies[name] = NodeLatency.from(error: error)
        }
        schedulePolicyCardUpdates(proxies: [name])
        if let batchID, nodeProbeBatch?.id == batchID {
            nodeProbeBatch?.finish(requestID)
            pumpNodeProbeBatch()
        } else if nodeProbeRequests.isEmpty, nodeProbeBatch == nil {
            policyStatusLabel.stringValue = "节点 TCP 延迟测试完成；超限或排队超时不代表节点不可达"
            policyStatusLabel.textColor = .secondaryLabelColor
        }
        onStatusBarStateChanged?()
    }

    func pumpNodeProbeBatch(refreshStarts: Bool = true) {
        guard let batchID = nodeProbeBatch?.id else { return }
        while let request = nodeProbeBatch?.takeNext() {
            startNodeProbe(named: request.name, requestID: request.id, batchID: batchID,
                           refreshStart: refreshStarts)
        }
        if nodeProbeBatch?.isComplete == true {
            let names = nodeProbeBatch?.names ?? []
            let successes = names.reduce(0) { count, name in
                if case .success? = nodeLatencies[name] { return count + 1 }; return count
            }
            let deferred = names.reduce(0) { count, name in
                if case .unavailable(let failure)? = nodeLatencies[name], failure != .requestExpired {
                    return count + 1
                }; return count
            }
            nodeProbeBatch = nil
            policyStatusLabel.stringValue = "延迟测试完成：\(successes) 个可建立 TCP 连接，\(deferred) 个未测试（资源或排队限制）"
            policyStatusLabel.textColor = .secondaryLabelColor
        }
    }

    func cancelNodeTests(refresh: Bool = true) {
        let wasTesting = !nodeProbeRequests.isEmpty || nodeProbeBatch != nil
        nodeProbeEpoch &+= 1
        let tickets = Array(nodeProbeTickets.values)
        nodeProbeTickets.removeAll(); nodeProbeRequests.removeAll(); nodeProbeBatch = nil
        var changed = Set<String>()
        for (name, latency) in nodeLatencies where latency == .testing || latency == .queued {
            nodeLatencies[name] = .untested
            changed.insert(name)
        }
        tickets.forEach { $0.cancel() }
        if wasTesting {
            policyStatusLabel.stringValue = "上一轮测速已取消，旧结果不会覆盖当前配置"
            policyStatusLabel.textColor = .secondaryLabelColor
        }
        if refresh { schedulePolicyCardUpdates(proxies: changed) }
        else { pendingProxyCards.formUnion(changed) }
    }

    func uniqueProxyName(basedOn name: String) -> String {
        let base = name + " 副本"
        if profile.proxies[base] == nil, profile.groups[base] == nil { return base }
        var index = 2
        while profile.proxies["\(base) \(index)"] != nil || profile.groups["\(base) \(index)"] != nil {
            index += 1
        }
        return "\(base) \(index)"
    }

    func uniqueGroupName(basedOn name: String) -> String {
        let base = name + " 副本"
        if profile.groups[base] == nil, profile.proxies[base] == nil { return base }
        var index = 2
        while profile.groups["\(base) \(index)"] != nil || profile.proxies["\(base) \(index)"] != nil {
            index += 1
        }
        return "\(base) \(index)"
    }

    struct PersistedPolicyGroupSelectionArchive: Codable {
        var byProfileKey: [String: [String: String]] = [:]
        var manualGroupsByProfileKey: [String: [String]] = [:]
        var globalPolicyByProfileKey: [String: String] = [:]
        var historicalMemberMRU: [String: [String]] = [:]
        var lastActiveGroupSelections: [String: String] = [:]
        var lastActiveGlobalPolicy: String?
    }

    private var policyGroupSelectionsArchiveURL: URL {
        configurationStore.directoryURL.appendingPathComponent("policy-group-selections.json")
    }

    func loadPolicyGroupSelectionArchive() -> PersistedPolicyGroupSelectionArchive {
        let url = policyGroupSelectionsArchiveURL
        if let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode(PersistedPolicyGroupSelectionArchive.self, from: data) {
            return decoded
        }
        var archive = PersistedPolicyGroupSelectionArchive()
        if let legacy = UserDefaults.standard.dictionary(forKey: "groupSelections") {
            for (k, v) in legacy {
                if let str = v as? String, !str.isEmpty {
                    archive.lastActiveGroupSelections[k] = str
                    archive.historicalMemberMRU[k] = [str]
                }
            }
        }
        if let legacyGlobal = UserDefaults.standard.string(forKey: "globalPolicy"), !legacyGlobal.isEmpty {
            archive.lastActiveGlobalPolicy = legacyGlobal
        }
        return archive
    }

    func savePolicyGroupSelectionArchive(_ archive: PersistedPolicyGroupSelectionArchive) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(archive) {
            try? data.write(to: policyGroupSelectionsArchiveURL, options: .atomic)
        }
    }

    func profileSelectionStorageKeys(text: String, parsed: Profile) -> [String] {
        var keys: [String] = []
        for name in SubscriptionMerge.managedNames(in: text) where !name.isEmpty {
            let k = "sub:\(name)"
            if !keys.contains(k) { keys.append(k) }
        }
        if keys.isEmpty, let activeSub = subscriptions.selectedName, !activeSub.isEmpty {
            keys.append("sub:\(activeSub)")
        }
        if !parsed.groupOrder.isEmpty {
            let topoKey = "groups:\(parsed.groupOrder.joined(separator: "|"))"
            if !keys.contains(topoKey) { keys.append(topoKey) }
        }
        if keys.isEmpty {
            keys.append("default-profile")
        }
        return keys
    }

    func saveCurrentProfileGroupSelectionsSnapshot(text: String, parsed: Profile,
                                                   selections: [String: String],
                                                   manualGroups: Set<String>,
                                                   globalPolicy: String,
                                                   explicitlyClearedGroup: String? = nil) {
        guard !parsed.groups.isEmpty || !parsed.proxies.isEmpty else { return }
        var archive = loadPolicyGroupSelectionArchive()
        let keys = profileSelectionStorageKeys(text: text, parsed: parsed)

        var explicitForProfile: [String: String] = [:]
        for (groupName, group) in parsed.groups {
            let isManaged = PolicyHealthMonitor.managesSelection(of: group)
            if isManaged && !manualGroups.contains(groupName) {
                continue
            }
            if let member = selections[groupName], group.members.contains(member) {
                explicitForProfile[groupName] = member
                var mru = archive.historicalMemberMRU[groupName] ?? []
                mru.removeAll { $0 == member || $0 == "__DEFAULT__" }
                mru.insert(member, at: 0)
                if mru.count > 24 { mru = Array(mru.prefix(24)) }
                archive.historicalMemberMRU[groupName] = mru
            }
        }

        let validManual = Array(manualGroups.filter { parsed.groups[$0] != nil }).sorted()
        for key in keys {
            var mapForKey = archive.byProfileKey[key] ?? [:]
            for (groupName, member) in explicitForProfile {
                mapForKey[groupName] = member
            }
            if let cleared = explicitlyClearedGroup {
                mapForKey[cleared] = "__DEFAULT__"
            }
            archive.byProfileKey[key] = mapForKey
            archive.manualGroupsByProfileKey[key] = validManual
            if !globalPolicy.isEmpty, parsed.selectablePolicies.contains(globalPolicy) {
                archive.globalPolicyByProfileKey[key] = globalPolicy
            }
        }

        for (groupName, member) in explicitForProfile {
            archive.lastActiveGroupSelections[groupName] = member
        }
        if let cleared = explicitlyClearedGroup {
            archive.lastActiveGroupSelections.removeValue(forKey: cleared)
        }
        if !globalPolicy.isEmpty {
            archive.lastActiveGlobalPolicy = globalPolicy
        }
        savePolicyGroupSelectionArchive(archive)
    }

    func restoreProfileGroupSelectionsSnapshot(text: String, parsed: Profile,
                                               currentSelections: [String: String],
                                               preferredPolicy: String?) -> (selections: [String: String], manualGroups: Set<String>, preferredGlobalPolicy: String?) {
        let archive = loadPolicyGroupSelectionArchive()
        let keys = profileSelectionStorageKeys(text: text, parsed: parsed)
        let legacyDefaults = (UserDefaults.standard.dictionary(forKey: "groupSelections") as? [String: String]) ?? [:]

        var restoredManual = Set<String>()
        for key in keys {
            if let savedManual = archive.manualGroupsByProfileKey[key] {
                for g in savedManual where parsed.groups[g] != nil {
                    restoredManual.insert(g)
                }
                break
            }
        }
        for g in manualManagedGroupSelections where parsed.groups[g] != nil {
            if keys.allSatisfy({ archive.manualGroupsByProfileKey[$0] == nil }) {
                restoredManual.insert(g)
            }
        }

        var restoredSelections: [String: String] = [:]
        for (groupName, group) in parsed.groups {
            let isManaged = PolicyHealthMonitor.managesSelection(of: group)
            if isManaged && !restoredManual.contains(groupName) {
                if let autoMember = policyHealth.currentSelections[groupName], group.members.contains(autoMember) {
                    restoredSelections[groupName] = autoMember
                }
                continue
            }

            var foundMember: String?
            var explicitlyDefault = false
            for key in keys {
                if let candidate = archive.byProfileKey[key]?[groupName] {
                    if candidate == "__DEFAULT__" {
                        explicitlyDefault = true
                        break
                    } else if group.members.contains(candidate) {
                        foundMember = candidate
                        break
                    }
                }
            }
            if explicitlyDefault {
                continue
            }
            if let foundMember {
                restoredSelections[groupName] = foundMember
                continue
            }

            if let current = currentSelections[groupName], group.members.contains(current) {
                restoredSelections[groupName] = current
                continue
            }

            if let mruList = archive.historicalMemberMRU[groupName] {
                for candidate in mruList where candidate != "__DEFAULT__" {
                    if group.members.contains(candidate) {
                        restoredSelections[groupName] = candidate
                        break
                    }
                }
                if restoredSelections[groupName] != nil { continue }
            }

            if let last = archive.lastActiveGroupSelections[groupName] ?? legacyDefaults[groupName],
               group.members.contains(last) {
                restoredSelections[groupName] = last
            }
        }

        var resolvedGlobal = preferredPolicy
        if resolvedGlobal == nil || !parsed.selectablePolicies.contains(resolvedGlobal ?? "") {
            for key in keys {
                if let savedGlobal = archive.globalPolicyByProfileKey[key],
                   parsed.selectablePolicies.contains(savedGlobal) {
                    resolvedGlobal = savedGlobal
                    break
                }
            }
            if resolvedGlobal == nil, let lastGlobal = archive.lastActiveGlobalPolicy,
               parsed.selectablePolicies.contains(lastGlobal) {
                resolvedGlobal = lastGlobal
            }
        }

        return (restoredSelections, restoredManual, resolvedGlobal)
    }

    func setGroupSelection(group name: String, member: String?) {
        if let member {
            if let group = profile.groups[name], PolicyHealthMonitor.managesSelection(of: group) {
                manualManagedGroupSelections.insert(name)
            }
            groupSelections[name] = member
            saveCurrentProfileGroupSelectionsSnapshot(
                text: profileTextView.string,
                parsed: profile,
                selections: groupSelections,
                manualGroups: manualManagedGroupSelections,
                globalPolicy: selectedPolicy
            )
        } else {
            manualManagedGroupSelections.remove(name)
            if let autoMember = policyHealth.currentSelections[name] {
                groupSelections[name] = autoMember
            } else {
                groupSelections.removeValue(forKey: name)
            }
            saveCurrentProfileGroupSelectionsSnapshot(
                text: profileTextView.string,
                parsed: profile,
                selections: groupSelections,
                manualGroups: manualManagedGroupSelections,
                globalPolicy: selectedPolicy,
                explicitlyClearedGroup: name
            )
        }
        UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
        if selectedGroup == name { refreshGroupMembers() }
        updateEngineRoutingForExtension()
        updateOverviewDetailsForExtension()
        schedulePolicyCardUpdates(groups: [name])
        policyStatusLabel.stringValue = member.map { "✓ \(name) 已切换到 \($0)（已记忆保存）" } ?? "✓ \(name) 已恢复配置默认行为"
        policyStatusLabel.textColor = .systemGreen
        onStatusBarStateChanged?()
    }

    @objc func menuNeedsUpdate(_ menu: NSMenu) {
        if menu === rulesTableView.menu {
            menu.removeAllItems()
            let row = rulesTableView.clickedRow
            if filteredRules.indices.contains(row), !rulesTableView.selectedRowIndexes.contains(row) {
                rulesTableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            }
            updateRuleSelectionControls()
            func add(_ title: String, _ action: Selector, enabled: Bool) {
                let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
                item.target = self
                item.isEnabled = enabled
                menu.addItem(item)
            }
            add("新增规则…", #selector(addRule), enabled: ruleAddButton.isEnabled)
            add(ruleEditButton.title + "…", #selector(editSelectedRules), enabled: ruleEditButton.isEnabled)
            add("删除选中规则…", #selector(deleteSelectedRules), enabled: ruleDeleteButton.isEnabled)
            menu.addItem(.separator())
            add(selectedRuleSourceLines.isEmpty ? "更新全部规则集" : "更新选中规则集",
                #selector(updateRuleSets), enabled: ruleUpdateButton.isEnabled)
            menu.addItem(.separator())
            add("全选当前搜索结果", #selector(selectAllRules), enabled: ruleSelectAllButton.isEnabled)
            add("取消选择", #selector(clearRuleSelection), enabled: ruleClearSelectionButton.isEnabled)
            return
        }
        guard menu === proxyTableView.menu else { return }
        menu.removeAllItems()
        let row = proxyTableView.clickedRow >= 0 ? proxyTableView.clickedRow : proxyTableView.selectedRow
        guard filteredProxyNames.indices.contains(row) else { return }
        populateProxyMenu(menu, name: filteredProxyNames[row])
    }

    func makeProxyMenu(name: String) -> NSMenu {
        let menu = NSMenu(title: name)
        populateProxyMenu(menu, name: name)
        return menu
    }

    @objc func groupMenuToggleStatusBar(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String,
              let group = profile.groups[name] else { return }
        var draft = SurgePolicyGroupDraft(group: group)
        if group.showsInStatusBar {
            draft.parameters["show-in-status-bar"] = "false"
        } else if draft.parameters["hidden"].map({ ["true", "yes", "on", "1"].contains($0.lowercased()) }) == true {
            draft.parameters["show-in-status-bar"] = "true"
        } else {
            draft.parameters.removeValue(forKey: "show-in-status-bar")
        }
        do {
            try commitGroupDraft(draft, originalName: name)
            onStatusBarStateChanged?()
        } catch {
            showError(title: "无法更新状态栏显示设置", error: error)
        }
    }

    func makeGroupMenu(name: String) -> NSMenu {
        let menu = NSMenu(title: name)
        func item(_ title: String, _ action: Selector) -> NSMenuItem {
            let value = NSMenuItem(title: title, action: action, keyEquivalent: "")
            value.target = self
            value.representedObject = name
            return value
        }
        let statusItemToggle = item("在顶部状态栏菜单中显示", #selector(groupMenuToggleStatusBar(_:)))
        statusItemToggle.state = (profile.groups[name]?.showsInStatusBar ?? true) ? .on : .off
        menu.addItem(statusItemToggle)
        menu.addItem(.separator())
        menu.addItem(item("编辑成员与选项…", #selector(groupMenuEdit(_:))))
        menu.addItem(item("复制策略组…", #selector(groupMenuDuplicate(_:))))
        menu.addItem(.separator())
        menu.addItem(item("删除策略组…", #selector(groupMenuDelete(_:))))
        return menu
    }

    func populateProxyMenu(_ menu: NSMenu, name: String) {
        let editable = isEditableProxy(named: name)
        func item(_ title: String, _ action: Selector, enabled: Bool = true) -> NSMenuItem {
            let value = NSMenuItem(title: title, action: action, keyEquivalent: "")
            value.target = self
            value.representedObject = name
            value.isEnabled = enabled
            return value
        }
        menu.addItem(item("作为全局代理使用", #selector(proxyMenuUse(_:))))
        menu.addItem(item("测试 TCP 延迟", #selector(proxyMenuTest(_:))))
        menu.addItem(.separator())
        menu.addItem(item("编辑…", #selector(proxyMenuEdit(_:)), enabled: editable))
        menu.addItem(item("复制…", #selector(proxyMenuDuplicate(_:))))
        menu.addItem(item("删除…", #selector(proxyMenuDelete(_:)), enabled: editable))
    }
}

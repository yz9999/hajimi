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
    @objc func numberOfRows(in tableView: NSTableView) -> Int {
        if tableView === proxyTableView { return filteredProxyNames.count }
        if tableView === groupTableView { return profile.groupOrder.count }
        if tableView === rulesTableView { return filteredRules.count }
        return 0
    }

    @objc func tableViewSelectionDidChange(_ notification: Notification) {
        guard let table = notification.object as? NSTableView, table === rulesTableView,
              !ruleSelectionRefreshInProgress else { return }
        updateRuleSelectionControls()
        if ruleMultiSelectButton.state == .on,
           let column = rulesTableView.tableColumns.firstIndex(where: { $0.identifier.rawValue == "selected" }),
           !filteredRules.isEmpty {
            ruleSelectionRefreshInProgress = true
            rulesTableView.reloadData(forRowIndexes: IndexSet(integersIn: 0..<filteredRules.count),
                                      columnIndexes: IndexSet(integer: column))
            ruleSelectionRefreshInProgress = false
        }
    }

    @objc func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        if tableView === proxyTableView {
            guard filteredProxyNames.indices.contains(row),
                  let policy = profile.proxies[filteredProxyNames[row]] else { return nil }
            let name = policy.name
            let cell = ProxyNodeCellView()
            cell.configure(policy: policy, latency: nodeLatencies[name] ?? .untested,
                           isActive: selectedModeForExtension == .proxy && selectedPolicy == name,
                           onUse: { [weak self] in self?.useProxy(named: name) })
            return cell
        }
        if tableView === groupTableView {
            guard profile.groupOrder.indices.contains(row),
                  let group = profile.groups[profile.groupOrder[row]] else { return nil }
            let cell = PolicyGroupCellView()
            cell.configure(group: group, selected: groupSelections[group.name]) { [weak self] member in
                self?.setGroupSelection(group: group.name, member: member)
            }
            return cell
        }
        if tableView === rulesTableView {
            guard filteredRules.indices.contains(row), let identifier = tableColumn?.identifier else { return nil }
            let rule = filteredRules[row]
            if identifier.rawValue == "selected" {
                let checkbox = NSButton(checkboxWithTitle: "", target: self,
                                        action: #selector(ruleRowSelectionChanged(_:)))
                checkbox.tag = rule.sourceLine
                checkbox.isEnabled = rulesPageIsEditable
                checkbox.state = rulesTableView.selectedRowIndexes.contains(row) ? .on : .off
                checkbox.toolTip = "选择第 \(rule.sourceLine) 行规则"
                checkbox.setAccessibilityLabel("选择第 \(rule.sourceLine) 行规则")
                return checkbox
            }
            let description = filteredRuleRows[row]
            let cell = NSTextField(labelWithString: "")
            cell.font = identifier.rawValue == "value"
                ? .monospacedSystemFont(ofSize: 10.5, weight: .regular)
                : .systemFont(ofSize: 11)
            cell.lineBreakMode = .byTruncatingMiddle
            switch identifier.rawValue {
            case "line":
                cell.stringValue = String(rule.sourceLine)
                cell.font = .monospacedDigitSystemFont(ofSize: 10.5, weight: .regular)
                cell.textColor = .tertiaryLabelColor
            case "type":
                cell.stringValue = description.type
                cell.font = .systemFont(ofSize: 11, weight: .semibold)
                cell.textColor = HajimiAppearance.accentText
            case "value":
                cell.stringValue = description.value
                cell.toolTip = description.value
            case "policy":
                cell.stringValue = rule.policy
                cell.font = .systemFont(ofSize: 11, weight: .semibold)
                let upper = rule.policy.uppercased()
                if upper == "REJECT" || upper == "REJECT-TINYGIF" {
                    cell.textColor = .systemRed
                } else if upper == "DIRECT" {
                    cell.textColor = HajimiAppearance.accentText
                } else {
                    cell.textColor = HajimiAppearance.indigoAccent
                }
            case "loaded":
                cell.font = .systemFont(ofSize: 11, weight: .medium)
                if case .ruleSet(let reference) = rule.kind {
                    let count = (rulesPageProfile ?? resolvedProfile ?? profile).ruleSetContents[reference.location]?.count
                    cell.stringValue = count.map { "\($0) 条" } ?? "未加载"
                    cell.textColor = count == nil ? .systemOrange : HajimiAppearance.accentText
                } else {
                    cell.stringValue = "本地"
                    cell.textColor = .secondaryLabelColor
                }
            default: break
            }
            return cell
        }

        return nil
    }
}

extension MainWindowController: ExternalControllerBackend {
    func controllerSnapshot() -> ExternalControllerSnapshot {
        let runtime = engine.runtimeSnapshot()
        return ExternalControllerSnapshot(
            mode: selectedModeForExtension,
            globalPolicy: selectedPolicy,
            groupSelections: groupSelections,
            profile: resolvedProfile ?? profile,
            engineStatus: engineStatus,
            httpListen: runtime.httpListen,
            socksListen: runtime.socksListen,
            uploaded: runtime.uploaded + enhancedUploaded,
            downloaded: runtime.downloaded + enhancedDownloaded,
            startedAt: runtime.startedAt,
            active: runtime.active,
            recent: runtime.recent,
            systemProxyEnabled: isSystemProxyActive,
            enhancedModeEnabled: isEnhancedModeActive,
            fakeIP: enhancedMode.fakeIPEntries(),
            policyLatencies: policyLatencies)
    }

    func controllerSetOutboundMode(_ mode: OutboundMode) {
        DispatchQueue.main.async { self.selectOutboundModeFromStatusItem(mode) }
    }

    func controllerSetGlobalPolicy(_ name: String) -> Bool {
        let known = profile.groups[name] == nil && profile.selectablePolicies.contains(name)
        if known {
            DispatchQueue.main.async { self.selectGlobalPolicyFromStatusItem(name) }
        }
        return known
    }

    func controllerSetGroupSelection(group: String, policy: String) -> Bool {
        guard profile.groups[group]?.members.contains(policy) == true else { return false }
        DispatchQueue.main.async { self.setGroupSelection(group: group, member: policy) }
        return true
    }

    func controllerSetSystemProxy(_ enabled: Bool) {
        DispatchQueue.main.async {
            guard enabled != self.isSystemProxyActive else { return }
            self.systemProxyButton.state = enabled ? .on : .off
            self.toggleSystemProxyForExtension()
        }
    }

    func controllerSetEnhancedMode(_ enabled: Bool) {
        DispatchQueue.main.async {
            guard enabled != self.isEnhancedModeActive else { return }
            self.enhancedModeButton.state = enabled ? .on : .off
            self.toggleEnhancedModeForExtension()
        }
    }

    func controllerReloadProfile() {
        DispatchQueue.main.async {
            do {
                let text = try self.configurationStore.loadTextThrowing()
                self.applyProfileTextInBackground(text, prefix: "控制器已重载",
                                                  allowExternalChanges: true,
                                                  completion: { [weak self] result in
                    guard let self, case .failure(let error) = result else { return }
                    self.showError(title: "控制器重载配置失败", error: error)
                })
            } catch {
                self.showError(title: "控制器重载配置失败", error: error)
            }
        }
    }

    func controllerFlushDNS() {
        engine.flushDNS()
        enhancedMode.flushDNS()
    }

    func controllerFlushFakeIP() {
        enhancedMode.flushFakeIP()
    }

    func controllerKillRequest(id: String) -> Bool {
        guard let uuid = UUID(uuidString: id) else { return false }
        return engine.killConnection(id: uuid)
    }

    func controllerTestGroup(_ name: String) {
        DispatchQueue.main.async { self.policyHealth.refresh() }
        _ = name
    }
}

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
    // MARK: Subscriptions

    /// Ensures that on launch, if a subscription is selected and cached, the
    /// profile does not retain mixed nodes or groups from other subscriptions
    /// or previous unbracketed imports.
    func reconcileStartupActiveSubscription() {
        let current = profileTextView.string
        if !profile.globalProxyNodes.isEmpty || !profile.groups.isEmpty {
            subscriptions.syncEditedProfileText(current, proxyCount: profile.globalProxyNodes.count)
            return
        }
        guard let activeName = subscriptions.selectedName,
              let prepared = try? subscriptions.prepareSelection(name: activeName) else { return }
        let cleaned = SubscriptionRefreshMerge.activate(
            (name: prepared.name, contents: prepared.contents),
            toCurrentText: { current })
        guard cleaned != current,
              let parsed = try? ProfileParser.parse(cleaned) else { return }
        profile = parsed
        launchProfilePlan = .ready(parsed)
        profileTextView.string = cleaned
        try? configurationStore.save(cleaned)
        lastKnownStoredProfileText = cleaned
    }

    func refreshSubscriptionSettings(preferredSelection: String? = nil) {
        let all = subscriptions.all
        let activeName = subscriptions.selectedName
        let currentPopupSelection = preferredSelection ?? subscriptionSelectPopup.titleOfSelectedItem ?? activeName
        subscriptionSelectPopup.removeAllItems()
        guard !all.isEmpty else {
            subscriptionSelectPopup.addItem(withTitle: "暂无订阅")
            subscriptionSelectPopup.isEnabled = false
            subscriptionUseButton.isEnabled = false
            subscriptionEditButton.isEnabled = false
            subscriptionUpdateButton.isEnabled = false
            subscriptionDeleteButton.isEnabled = false
            subscriptionSummaryLabel.stringValue = "尚未添加订阅 · 点击“导入配置…”导入本地配置文件，或点击“URL 下载…”添加远程订阅。"
            subscriptionSummaryLabel.textColor = .secondaryLabelColor
            subscriptionSummaryLabel.toolTip = subscriptionSummaryLabel.stringValue
            return
        }
        subscriptionSelectPopup.addItems(withTitles: all.map(\.name))
        if let target = currentPopupSelection, all.contains(where: { $0.name == target }) {
            subscriptionSelectPopup.selectItem(withTitle: target)
        } else if let activeName, all.contains(where: { $0.name == activeName }) {
            subscriptionSelectPopup.selectItem(withTitle: activeName)
        }
        subscriptionSelectPopup.isEnabled = true
        let highlightedName = subscriptionSelectPopup.titleOfSelectedItem ?? activeName ?? all[0].name
        let highlighted = all.first(where: { $0.name == highlightedName }) ?? all[0]
        let managedInProfile = SubscriptionMerge.managedNames(in: profileTextView.string)
        let isUsingHighlighted = highlighted.name == activeName
            && managedInProfile == [highlighted.name]
        let isLocalFile = URL(string: highlighted.url)?.isFileURL == true
        subscriptionUseButton.isEnabled = true
        subscriptionUseButton.title = isUsingHighlighted ? "正在使用" : "选择使用"
        subscriptionEditButton.isEnabled = !isLocalFile
        subscriptionEditButton.toolTip = isLocalFile
            ? "仅 URL 订阅支持编辑 URL 与自动更新时间"
            : "编辑订阅名称、替换 URL、设置是否自动更新及更新时间"
        subscriptionUpdateButton.isEnabled = !isLocalFile
        subscriptionUpdateButton.toolTip = isLocalFile
            ? "本地导入的配置文件无需 URL 更新，编辑节点与策略组会自动保存"
            : "从远程 URL 拉取最新订阅内容"
        subscriptionDeleteButton.isEnabled = true

        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        let sourceKind = isLocalFile ? "本地导入" : "URL 订阅"
        var summary = isUsingHighlighted ? "✓ 当前使用：\(highlighted.name)" : "已选择：\(highlighted.name)（当前使用：\(activeName ?? "无")）"
        summary += " · \(sourceKind)"
        if !isLocalFile {
            if highlighted.updateInterval > 0 {
                let hours = highlighted.updateInterval / 3600
                let hoursText = hours.truncatingRemainder(dividingBy: 1) == 0
                    ? "\(Int(hours))" : String(format: "%.1f", hours)
                summary += " · 自动更新 \(hoursText)h"
            } else {
                summary += " · 仅手动更新"
            }
        }
        if let format = highlighted.lastFormat { summary += " · \(format.rawValue)" }
        summary += " · \(highlighted.lastProxyCount) 个节点"
        if isLocalFile {
            summary += " · 已保存到本地配置（无需 URL 更新）"
        } else if let updated = highlighted.lastUpdated {
            summary += " · 更新于 \(formatter.string(from: updated))"
        } else {
            summary += " · 尚未更新"
        }
        if let error = highlighted.lastError {
            summary += " · ⚠︎ \(error)"
            subscriptionSummaryLabel.textColor = .systemOrange
        } else {
            subscriptionSummaryLabel.textColor = isUsingHighlighted ? .systemGreen : .secondaryLabelColor
        }
        subscriptionSummaryLabel.stringValue = summary
        subscriptionSummaryLabel.toolTip = summary
    }

    @objc func subscriptionSelectionPopupChanged() {
        guard let name = subscriptionSelectPopup.titleOfSelectedItem,
              subscriptions.all.contains(where: { $0.name == name }) else {
            refreshSubscriptionSettings()
            return
        }
        activateSubscription(name: name, announce: false)
    }

    @objc func useSelectedSubscriptionAction() {
        guard let name = subscriptionSelectPopup.titleOfSelectedItem,
              subscriptions.all.contains(where: { $0.name == name }) else { return }
        activateSubscription(name: name, announce: false)
    }

    @objc func updateSelectedSubscriptionAction() {
        let selected = subscriptionSelectPopup.titleOfSelectedItem ?? subscriptions.selectedName
        guard let name = selected, subscriptions.all.contains(where: { $0.name == name }) else {
            if let first = subscriptions.selectedName ?? subscriptions.all.first?.name {
                updateSubscriptions(names: [first], announce: true)
            }
            return
        }
        updateSubscriptions(names: [name], announce: true)
    }

    @objc func deleteSelectedSubscriptionAction() {
        let selected = subscriptionSelectPopup.titleOfSelectedItem ?? subscriptions.selectedName
        guard let name = selected, subscriptions.all.contains(where: { $0.name == name }) else { return }
        let alert = NSAlert()
        alert.messageText = "删除订阅“\(name)”？"
        alert.informativeText = "删除后，该订阅的节点与策略组将从当前配置中移除。"
        alert.addButton(withTitle: "删除")
        alert.addButton(withTitle: "取消")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn, let self else { return }
            self.removeSubscriptionByName(name)
        }
    }

    func removeSubscriptionByName(_ name: String) {
        let remaining = subscriptions.all.map(\.name).filter { $0 != name }
        let initialEditorText = profileTextView.string
        let wasActive = subscriptions.selectedName == name
            || SubscriptionMerge.managedNames(in: initialEditorText).contains(name)
        if wasActive, let nextName = remaining.first {
            subscriptionSummaryLabel.stringValue = "正在删除订阅并切换到“\(nextName)”…"
            subscriptionSummaryLabel.textColor = .systemBlue
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                let nextPrepared = try? self.subscriptions.prepareSelection(name: nextName)
                let precomputedText: String
                if let nextPrepared {
                    precomputedText = SubscriptionRefreshMerge.activate(
                        (name: nextPrepared.name, contents: nextPrepared.contents),
                        toCurrentText: { initialEditorText })
                } else {
                    let removed = SubscriptionMerge.remove(name: name, from: initialEditorText)
                    precomputedText = SubscriptionMerge.reconcileDanglingRulePolicies(in: removed)
                }
                DispatchQueue.main.async {
                    let currentEditorText = self.profileTextView.string
                    if let nextPrepared {
                        let text = currentEditorText == initialEditorText
                            ? precomputedText
                            : SubscriptionRefreshMerge.activate(
                                (name: nextPrepared.name, contents: nextPrepared.contents),
                                toCurrentText: { currentEditorText })
                        self.applyProfileTextInBackground(text, prefix: "已删除订阅并切换到 \(nextName)",
                                                          stillApplicable: { [weak self] in
                            self?.subscriptions.all.contains(where: { $0.name == name }) == true
                        }) { [weak self] result in
                            guard let self else { return }
                            switch result {
                            case .success:
                                self.subscriptions.remove(name: name)
                                self.subscriptions.select(name: nextName)
                                self.subscriptions.recordApplied(nextPrepared)
                                self.refreshSubscriptionSettings(preferredSelection: nextName)
                            case .failure(let error):
                                self.refreshSubscriptionSettings()
                                self.showError(title: "删除订阅失败", error: error)
                            }
                        }
                    } else {
                        let text = currentEditorText == initialEditorText
                            ? precomputedText
                            : SubscriptionMerge.reconcileDanglingRulePolicies(
                                in: SubscriptionMerge.remove(name: name, from: currentEditorText))
                        self.applyProfileTextInBackground(text, prefix: "删除订阅",
                                                          stillApplicable: { [weak self] in
                            self?.subscriptions.all.contains(where: { $0.name == name }) == true
                        }) { [weak self] result in
                            guard let self else { return }
                            switch result {
                            case .success:
                                self.subscriptions.remove(name: name)
                                self.subscriptions.select(name: nextName)
                                self.refreshSubscriptionSettings(preferredSelection: nextName)
                            case .failure(let error):
                                self.refreshSubscriptionSettings()
                                self.showError(title: "删除订阅失败", error: error)
                            }
                        }
                    }
                }
            }
            return
        }
        subscriptionSummaryLabel.stringValue = "正在删除订阅“\(name)”…"
        subscriptionSummaryLabel.textColor = .systemBlue
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let removed = SubscriptionMerge.remove(name: name, from: initialEditorText)
            let precomputedText = SubscriptionMerge.reconcileDanglingRulePolicies(in: removed)
            DispatchQueue.main.async {
                let currentEditorText = self.profileTextView.string
                let text = currentEditorText == initialEditorText
                    ? precomputedText
                    : SubscriptionMerge.reconcileDanglingRulePolicies(
                        in: SubscriptionMerge.remove(name: name, from: currentEditorText))
                self.applyProfileTextInBackground(text, prefix: "删除订阅",
                                                  stillApplicable: { [weak self] in
                    self?.subscriptions.all.contains(where: { $0.name == name }) == true
                }) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .success:
                        self.subscriptions.remove(name: name)
                        self.refreshSubscriptionSettings()
                    case .failure(let error):
                        self.refreshSubscriptionSettings()
                        self.showError(title: "删除订阅失败", error: error)
                    }
                }
            }
        }
    }

    @objc func importSubscriptionFileAction() {
        let panel = NSOpenPanel()
        panel.title = "导入本地订阅或配置文件"
        panel.prompt = "导入并使用"
        panel.allowsOtherFileTypes = true
        panel.allowedContentTypes = ["conf", "yaml", "yml", "ini", "txt"]
            .compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard let window else { return }
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK, let url = panel.url, let self else { return }
            self.importSubscription(fromFileURL: url)
        }
    }

    func importSubscription(fromFileURL url: URL, customName: String? = nil) {
        let suggested = customName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let rawName = suggested.isEmpty ? url.deletingPathExtension().lastPathComponent : suggested
        let initialEditorText = profileTextView.string
        subscriptionSummaryLabel.stringValue = "正在导入配置 \(url.lastPathComponent)…"
        subscriptionSummaryLabel.textColor = .systemBlue
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let imported = Result { () -> (SubscriptionManager.PreparedUpdate, String) in
                let prepared = try self.subscriptions.importFile(name: rawName, sourceURL: url)
                let precomputed = SubscriptionRefreshMerge.activate(
                    (name: prepared.name, contents: prepared.contents),
                    toCurrentText: { initialEditorText })
                return (prepared, precomputed)
            }
            DispatchQueue.main.async {
                switch imported {
                case .failure(let error):
                    self.refreshSubscriptionSettings()
                    self.showError(title: "导入配置失败", error: error)
                case .success(let (prepared, precomputed)):
                    let currentEditorText = self.profileTextView.string
                    let merged = currentEditorText == initialEditorText
                        ? precomputed
                        : SubscriptionRefreshMerge.activate(
                            (name: prepared.name, contents: prepared.contents),
                            toCurrentText: { currentEditorText })
                    self.applyProfileTextInBackground(merged, prefix: "导入并使用订阅 \(prepared.name)",
                                                      keepEditorOnFailure: true,
                                                      stillApplicable: { [weak self] in
                        self?.subscriptions.isCurrent(prepared) == true
                    }) { [weak self] result in
                        guard let self else { return }
                        switch result {
                        case .success:
                            self.subscriptions.select(name: prepared.name)
                            self.subscriptions.recordApplied(prepared)
                            self.refreshSubscriptionSettings(preferredSelection: prepared.name)
                        case .failure(let error):
                            self.subscriptions.recordFailure(name: prepared.name, error: error)
                            self.refreshSubscriptionSettings(preferredSelection: prepared.name)
                            self.showError(title: "应用导入的订阅失败", error: error)
                        }
                    }
                }
            }
        }
    }

    func activateSubscription(name: String, announce: Bool) {
        let initialEditorText = profileTextView.string
        subscriptionSummaryLabel.stringValue = "正在切换并加载订阅“\(name)”…"
        subscriptionSummaryLabel.textColor = .systemBlue
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let preparedResult = Result { () -> (SubscriptionManager.PreparedUpdate, String) in
                let prepared = try self.subscriptions.prepareSelection(name: name)
                let precomputed = SubscriptionRefreshMerge.activate(
                    (name: prepared.name, contents: prepared.contents),
                    toCurrentText: { initialEditorText })
                return (prepared, precomputed)
            }
            DispatchQueue.main.async {
                switch preparedResult {
                case .failure(let error):
                    self.subscriptions.recordFailure(name: name, error: error)
                    self.refreshSubscriptionSettings(preferredSelection: name)
                    self.showError(title: "切换订阅失败", error: error)
                case .success(let (prepared, precomputed)):
                    guard self.subscriptions.isCurrent(prepared) else {
                        self.refreshSubscriptionSettings()
                        return
                    }
                    let currentEditorText = self.profileTextView.string
                    let merged = currentEditorText == initialEditorText
                        ? precomputed
                        : SubscriptionRefreshMerge.activate(
                            (name: prepared.name, contents: prepared.contents),
                            toCurrentText: { currentEditorText })
                    self.applyProfileTextInBackground(merged, prefix: "已切换到订阅 \(prepared.name)",
                                                      keepEditorOnFailure: true,
                                                      stillApplicable: { [weak self] in
                        self?.subscriptions.isCurrent(prepared) == true
                    }) { [weak self] result in
                        guard let self else { return }
                        switch result {
                        case .success:
                            self.subscriptions.select(name: prepared.name)
                            self.subscriptions.recordApplied(prepared)
                            self.refreshSubscriptionSettings(preferredSelection: prepared.name)
                            if announce {
                                self.reportSubscriptionOutcome(results: [prepared.result], failures: [])
                            }
                        case .failure(let error):
                            self.subscriptions.recordFailure(name: prepared.name, error: error)
                            self.refreshSubscriptionSettings(preferredSelection: prepared.name)
                            self.showError(title: "应用订阅失败", error: error)
                        }
                    }
                }
            }
        }
    }

    private final class URLSubscriptionFormView: NSView {
        let nameField = NSTextField()
        let urlField = NSTextField()
        let autoUpdateCheckbox: NSButton
        let intervalField = NSTextField()

        init(name: String, url: String, updateInterval: TimeInterval) {
            autoUpdateCheckbox = NSButton(checkboxWithTitle: "自动更新订阅", target: nil, action: nil)
            super.init(frame: NSRect(x: 0, y: 0, width: 390, height: 118))

            let nameLabel = NSTextField(labelWithString: "订阅名称")
            nameLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
            nameLabel.frame = NSRect(x: 0, y: 92, width: 64, height: 18)

            nameField.frame = NSRect(x: 68, y: 89, width: 322, height: 22)
            nameField.placeholderString = "名称，例如 机场A（留空则自动根据地址命名）"
            nameField.stringValue = name

            let urlLabel = NSTextField(labelWithString: "订阅 URL")
            urlLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
            urlLabel.frame = NSRect(x: 0, y: 58, width: 64, height: 18)

            urlField.frame = NSRect(x: 68, y: 55, width: 322, height: 22)
            urlField.placeholderString = "https://example.com/subscribe?token=…"
            urlField.stringValue = url

            let isAuto = updateInterval > 0
            autoUpdateCheckbox.state = isAuto ? .on : .off
            autoUpdateCheckbox.target = self
            autoUpdateCheckbox.action = #selector(autoUpdateToggled)
            autoUpdateCheckbox.frame = NSRect(x: 68, y: 24, width: 112, height: 20)

            let intervalLabel = NSTextField(labelWithString: "更新时间（小时）：")
            intervalLabel.font = .systemFont(ofSize: 11.5, weight: .regular)
            intervalLabel.textColor = .secondaryLabelColor
            intervalLabel.frame = NSRect(x: 186, y: 25, width: 110, height: 18)

            let hours = isAuto ? (updateInterval / 3600) : 24
            let hoursString = hours.truncatingRemainder(dividingBy: 1) == 0
                ? "\(Int(hours))" : String(format: "%.1f", hours)
            intervalField.frame = NSRect(x: 298, y: 23, width: 92, height: 22)
            intervalField.placeholderString = "小时（如 24）"
            intervalField.stringValue = hoursString
            intervalField.isEnabled = isAuto

            let hintLabel = NSTextField(labelWithString: "勾选“自动更新订阅”后，将按设定的小时数定期拉取最新节点。")
            hintLabel.font = .systemFont(ofSize: 10.5)
            hintLabel.textColor = .tertiaryLabelColor
            hintLabel.frame = NSRect(x: 68, y: 2, width: 322, height: 16)

            [nameLabel, nameField, urlLabel, urlField,
             autoUpdateCheckbox, intervalLabel, intervalField, hintLabel].forEach(addSubview)
        }

        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

        @objc func autoUpdateToggled() {
            let enabled = autoUpdateCheckbox.state == .on
            intervalField.isEnabled = enabled
            if enabled, (Double(intervalField.stringValue.trimmingCharacters(in: .whitespaces)) ?? 0) <= 0 {
                intervalField.stringValue = "24"
            }
        }

        var effectiveUpdateInterval: TimeInterval {
            guard autoUpdateCheckbox.state == .on else { return 0 }
            let hours = Double(intervalField.stringValue.trimmingCharacters(in: .whitespaces)) ?? 24
            return max(0.1, hours) * 3600
        }
    }

    @objc func addSubscriptionAction() {
        let alert = NSAlert()
        alert.messageText = "增加订阅（URL 下载或导入配置）"
        alert.informativeText = "支持 Clash YAML、Surge .conf 与分享链接列表（可为 base64 包装）。"
            + "输入订阅 URL 点击“添加并使用”，或点击“导入本地配置文件…”直接从文件创建订阅。"
        alert.addButton(withTitle: "添加并使用")
        alert.addButton(withTitle: "导入本地配置文件…")
        alert.addButton(withTitle: "取消")

        let form = URLSubscriptionFormView(name: "", url: "", updateInterval: 24 * 3600)
        alert.accessoryView = form
        alert.window.initialFirstResponder = form.nameField

        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            if response == .alertSecondButtonReturn {
                self.importSubscriptionFileAction()
                return
            }
            guard response == .alertFirstButtonReturn else { return }
            let rawName = form.nameField.stringValue.trimmingCharacters(in: .whitespaces)
            let url = form.urlField.stringValue.trimmingCharacters(in: .whitespaces)
            let fallbackHost = URL(string: url)?.host ?? "订阅"
            let name = rawName.isEmpty ? self.subscriptions.uniqueName(basedOn: fallbackHost) : rawName
            do {
                try self.subscriptions.add(name: name, url: url,
                                           updateInterval: form.effectiveUpdateInterval)
                self.subscriptions.select(name: name)
                self.refreshSubscriptionSettings(preferredSelection: name)
            } catch {
                self.showError(title: "添加订阅失败", error: error)
                return
            }
            self.updateSubscriptions(names: [name], announce: true)
        }
    }

    @objc func editSelectedSubscriptionAction() {
        let selected = subscriptionSelectPopup.titleOfSelectedItem ?? subscriptions.selectedName
        guard let originalName = selected,
              let current = subscriptions.all.first(where: { $0.name == originalName }) else { return }
        guard URL(string: current.url)?.isFileURL != true else {
            showMessage(title: "本地导入的订阅不支持编辑 URL",
                        text: "当前选择的是本地导入配置，如需更换请点击“导入配置…”或“URL 下载…”。")
            return
        }

        let alert = NSAlert()
        alert.messageText = "编辑 URL 订阅“\(current.name)”"
        alert.informativeText = "可更换订阅名称、替换订阅 URL、勾选是否自动更新并设置自动更新时间（小时）。若替换了 URL，保存后将立即拉取并切换为新订阅内容。"
        alert.addButton(withTitle: "保存")
        alert.addButton(withTitle: "保存并立即更新")
        alert.addButton(withTitle: "取消")

        let form = URLSubscriptionFormView(name: current.name,
                                           url: current.url,
                                           updateInterval: current.updateInterval)
        alert.accessoryView = form
        alert.window.initialFirstResponder = form.nameField

        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            guard response == .alertFirstButtonReturn || response == .alertSecondButtonReturn else { return }
            let forceRefresh = response == .alertSecondButtonReturn
            let rawName = form.nameField.stringValue.trimmingCharacters(in: .whitespaces)
            let url = form.urlField.stringValue.trimmingCharacters(in: .whitespaces)
            let fallbackHost = URL(string: url)?.host ?? current.name
            let requestedName = rawName.isEmpty ? fallbackHost : rawName
            do {
                let outcome = try self.subscriptions.updateSubscription(
                    originalName: originalName,
                    newName: requestedName,
                    url: url,
                    updateInterval: form.effectiveUpdateInterval)
                let newName = outcome.subscription.name
                let wasUsingOriginal = SubscriptionMerge.managedNames(in: self.profileTextView.string)
                    .contains(originalName)
                if outcome.nameChanged && wasUsingOriginal {
                    self.profileTextView.string = SubscriptionMerge.renameManagedBlock(
                        from: originalName, to: newName, in: self.profileTextView.string)
                }
                if outcome.urlChanged || forceRefresh {
                    self.subscriptions.select(name: newName)
                    self.refreshSubscriptionSettings(preferredSelection: newName)
                    self.updateSubscriptions(names: [newName], announce: true)
                } else if outcome.nameChanged && wasUsingOriginal {
                    self.applyProfileTextInBackground(self.profileTextView.string,
                                                      prefix: "已更新订阅名称为 \(newName)",
                                                      keepEditorOnFailure: true,
                                                      completion: { [weak self] _ in
                        self?.refreshSubscriptionSettings(preferredSelection: newName)
                    })
                } else {
                    self.refreshSubscriptionSettings(preferredSelection: newName)
                }
            } catch {
                self.showError(title: "编辑订阅失败", error: error)
            }
        }
    }

    @objc func manageSubscriptionsAction() {
        selectPage(4)
    }

    func promptRemoveSubscription(_ names: [String]) {
        guard let first = names.first else { return }
        removeSubscriptionByName(first)
    }

    /// Fetches named subscriptions off the main thread, then applies the active
    /// subscription into the latest profile text in one transaction on the main thread.
    func updateSubscriptions(names: [String], announce: Bool) {
        guard !names.isEmpty else { return }
        let initialEditorText = profileTextView.string
        let initialSelectedName = subscriptions.selectedName
        subscriptionSummaryLabel.stringValue = "正在更新订阅：\(names.joined(separator: "、"))…"
        subscriptionSummaryLabel.textColor = .systemBlue
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var updates: [SubscriptionManager.PreparedUpdate] = []
            var failures: [String] = []
            for name in names {
                do {
                    updates.append(try self.subscriptions.prepareUpdate(name: name))
                } catch {
                    self.subscriptions.recordFailure(name: name, error: error)
                    failures.append("• \(name)：\(error.localizedDescription)")
                }
            }
            let downloadFailures = failures
            let preparedUpdates = updates
            let precomputedTarget = preparedUpdates.first(where: { $0.name == initialSelectedName }) ?? preparedUpdates.first
            let precomputedMerged = precomputedTarget.map { target in
                SubscriptionRefreshMerge.activate(
                    (name: target.name, contents: target.contents),
                    toCurrentText: { initialEditorText })
            }
            DispatchQueue.main.async {
                var failures = downloadFailures
                let current = preparedUpdates.filter { update in
                    guard self.subscriptions.isCurrent(update) else {
                        failures.append("• \(update.name)：订阅已移除或更换，未应用旧下载结果")
                        return false
                    }
                    return true
                }
                guard !current.isEmpty else {
                    self.refreshSubscriptionSettings()
                    if announce { self.reportSubscriptionOutcome(results: [], failures: failures) }
                    return
                }
                let activeTarget = current.first(where: { $0.name == self.subscriptions.selectedName }) ?? current[0]
                let currentEditorText = self.profileTextView.string
                let merged: String
                if let precomputedMerged, precomputedTarget?.name == activeTarget.name,
                   currentEditorText == initialEditorText {
                    merged = precomputedMerged
                } else {
                    merged = SubscriptionRefreshMerge.activate(
                        (name: activeTarget.name, contents: activeTarget.contents),
                        toCurrentText: { currentEditorText })
                }
                self.applyProfileTextInBackground(merged, prefix: "更新订阅",
                                                  keepEditorOnFailure: true,
                                                  stillApplicable: { [weak self] in
                    guard let self else { return false }
                    return current.allSatisfy(self.subscriptions.isCurrent)
                }) { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .success:
                        self.subscriptions.select(name: activeTarget.name)
                        for update in current { self.subscriptions.recordApplied(update) }
                        self.refreshSubscriptionSettings(preferredSelection: activeTarget.name)
                        if announce {
                            self.reportSubscriptionOutcome(results: current.map(\.result),
                                                           failures: failures)
                        }
                    case .failure(let error):
                        for update in current {
                            self.subscriptions.recordFailure(name: update.name, error: error)
                        }
                        self.refreshSubscriptionSettings(preferredSelection: activeTarget.name)
                        self.showError(title: "应用订阅失败", error: error)
                    }
                }
            }
        }
    }

    func reportSubscriptionOutcome(results: [SubscriptionManager.UpdateResult],
                                           failures: [String]) {
        let alert = NSAlert()
        alert.messageText = failures.isEmpty ? "订阅已更新" : "订阅更新部分失败"
        alert.alertStyle = failures.isEmpty ? .informational : .warning
        var lines = results.map { result -> String in
            "• \(result.name)（\(result.format.rawValue)）："
                + "\(result.proxyCount) 个节点、\(result.groupCount) 个策略组"
        }
        lines.append(contentsOf: failures)
        let warnings = results.flatMap(\.warnings)
        let skipCert = warnings.filter { $0.contains("跳过服务器证书验证") }
        let other = warnings.filter { !$0.contains("跳过服务器证书验证") }
        if !skipCert.isEmpty {
            alert.alertStyle = .warning
            lines.append("")
            lines.append("证书风险：")
            lines.append(contentsOf: skipCert.prefix(5).map { "· \($0)" })
        }
        if !other.isEmpty {
            lines.append("")
            lines.append(contentsOf: other.prefix(10).map { "· \($0)" })
            if other.count > 10 { lines.append("· 另有 \(other.count - 10) 条提示") }
        }
        alert.informativeText = lines.joined(separator: "\n")
        alert.addButton(withTitle: "好")
        if let window { alert.beginSheetModal(for: window) { _ in } } else { alert.runModal() }
    }

    @objc func importSurgeProfile() {
        importSubscriptionFileAction()
    }

    func loadProfileText(_ text: String) {
        profileTextView.string = text
        profileStatus.stringValue = "配置将在启动时加载"
    }

    func applyProfileValidationStatus(_ value: Profile, prefix: String) {
        let loadedRules = value.ruleSetContents.values.reduce(0) { $0 + $1.count }
        let ruleSetText = value.ruleSetReferences.isEmpty
            ? "" : "，\(value.ruleSetReferences.count) 个 RULE-SET / \(loadedRules) 条子规则"
        let skipCertCount = value.proxiesSkippingCertificateVerification.count
        let skipCertText = skipCertCount == 0 ? "" : "，\(skipCertCount) 个节点跳过证书验证"
        let otherWarnings = value.warnings.filter { !$0.contains("跳过服务器证书验证") }
        let warningText = otherWarnings.isEmpty ? "" : "，\(otherWarnings.count) 项兼容提示"
        profileStatus.stringValue = "✓ \(prefix)：\(value.rules.count) 条主规则，\(value.proxyOrder.count) 个代理\(ruleSetText)\(skipCertText)\(warningText)"
        profileStatus.textColor = skipCertCount > 0
            ? .systemOrange
            : (value.warnings.isEmpty ? .systemGreen : .systemOrange)
        var tips = value.warnings
        if skipCertCount > 0, !tips.contains(where: { $0.contains("跳过服务器证书验证") }) {
            tips.insert(SkipCertificateWarning.message(
                names: value.proxiesSkippingCertificateVerification), at: 0)
        }
        profileStatus.toolTip = tips.isEmpty ? nil : tips.joined(separator: "\n")
    }
}

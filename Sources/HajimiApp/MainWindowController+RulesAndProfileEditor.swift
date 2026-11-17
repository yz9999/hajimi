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
    func configureProxyTable() {
        proxyTableView.dataSource = self
        proxyTableView.delegate = self
        proxyTableView.headerView = nil
        proxyTableView.rowHeight = 72
        proxyTableView.intercellSpacing = NSSize(width: 0, height: 0)
        proxyTableView.backgroundColor = .clear
        proxyTableView.selectionHighlightStyle = .none
        proxyTableView.doubleAction = #selector(editSelectedProxy)
        proxyTableView.target = self
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("proxy"))
        column.resizingMask = .autoresizingMask
        proxyTableView.addTableColumn(column)
        let menu = NSMenu(title: "节点")
        menu.delegate = self
        proxyTableView.menu = menu
    }

    func configureGroupTable() {
        groupTableView.dataSource = self
        groupTableView.delegate = self
        groupTableView.headerView = nil
        groupTableView.rowHeight = 68
        groupTableView.intercellSpacing = NSSize(width: 0, height: 0)
        groupTableView.backgroundColor = .clear
        groupTableView.selectionHighlightStyle = .none
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("group"))
        column.resizingMask = .autoresizingMask
        groupTableView.addTableColumn(column)
    }

    func buildRules() {
        let header = pageHeaderForExtension(eyebrow: "RULES", title: "规则",
                                subtitle: "管理主规则 · 多选操作与 RULE-SET 更新")
        rulesView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: rulesView.topAnchor, constant: 48)
        ])

        ruleSearchField.placeholderString = "搜索类型、值、策略或行号"
        ruleSearchField.sendsSearchStringImmediately = true
        ruleSearchField.target = self
        ruleSearchField.action = #selector(ruleSearchChanged)
        ruleSearchField.widthAnchor.constraint(equalToConstant: 250).isActive = true
        ruleCountLabel.font = .systemFont(ofSize: 11, weight: .medium)
        ruleCountLabel.textColor = .secondaryLabelColor

        let actions: [(NSButton, Selector)] = [
            (ruleAddButton, #selector(addRule)),
            (ruleEditButton, #selector(editSelectedRules)),
            (ruleDeleteButton, #selector(deleteSelectedRules)),
            (ruleUpdateButton, #selector(updateRuleSets)),
            (ruleMultiSelectButton, #selector(ruleMultiSelectionChanged)),
            (ruleSelectAllButton, #selector(selectAllRules)),
            (ruleClearSelectionButton, #selector(clearRuleSelection))
        ]
        for (button, action) in actions {
            button.target = self
            button.action = action
            button.controlSize = .small
            button.font = .systemFont(ofSize: 11.5, weight: .medium)
            if button !== ruleMultiSelectButton {
                button.bezelStyle = .rounded
                button.imagePosition = .imageLeading
            }
        }
        ruleAddButton.image = NSImage(systemSymbolName: "plus", accessibilityDescription: nil)
        ruleEditButton.image = NSImage(systemSymbolName: "pencil", accessibilityDescription: nil)
        ruleDeleteButton.image = NSImage(systemSymbolName: "trash", accessibilityDescription: nil)
        ruleUpdateButton.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
        ruleSelectAllButton.image = NSImage(systemSymbolName: "checkmark.circle", accessibilityDescription: nil)
        ruleClearSelectionButton.image = NSImage(systemSymbolName: "xmark.circle", accessibilityDescription: nil)
        ruleMultiSelectButton.toolTip = "显示逐项勾选；也可用 ⌘ / Shift 多选"
        ruleSelectAllButton.toolTip = "只选择当前搜索结果，不包含隐藏规则"
        ruleSelectionCountLabel.font = .systemFont(ofSize: 11, weight: .medium)
        ruleSelectionCountLabel.textColor = HajimiAppearance.accentText

        let toolbar = NSStackView(views: [
            ruleSearchField, ruleCountLabel, NSView(),
            ruleUpdateButton, ruleAddButton, ruleEditButton, ruleDeleteButton
        ])
        toolbar.orientation = .horizontal
        toolbar.alignment = .centerY
        toolbar.spacing = 8
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(toolbar)

        let actionBar = NSStackView(views: [
            ruleMultiSelectButton, ruleSelectAllButton, ruleClearSelectionButton,
            NSView(), ruleSelectionCountLabel
        ])
        actionBar.orientation = .horizontal
        actionBar.alignment = .centerY
        actionBar.spacing = 8
        actionBar.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(actionBar)

        let panel = cardViewForExtension()
        panel.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(panel)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        configureRulesTable()
        scroll.documentView = rulesTableView
        panel.addSubview(scroll)

        ruleStatusLabel.font = .systemFont(ofSize: 10.5, weight: .medium)
        ruleStatusLabel.textColor = .secondaryLabelColor
        ruleStatusLabel.maximumNumberOfLines = 2
        ruleStatusLabel.lineBreakMode = .byTruncatingTail
        ruleStatusLabel.stringValue = "新增规则默认插入 FINAL / MATCH 之前；更新按钮刷新规则集，编辑可修改本地规则。"
        ruleStatusLabel.translatesAutoresizingMaskIntoConstraints = false
        rulesView.addSubview(ruleStatusLabel)

        NSLayoutConstraint.activate([
            toolbar.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 30),
            toolbar.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            toolbar.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 19),
            actionBar.leadingAnchor.constraint(equalTo: toolbar.leadingAnchor),
            actionBar.trailingAnchor.constraint(equalTo: toolbar.trailingAnchor),
            actionBar.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 8),
            panel.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 30),
            panel.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            panel.topAnchor.constraint(equalTo: actionBar.bottomAnchor, constant: 10),
            panel.bottomAnchor.constraint(equalTo: ruleStatusLabel.topAnchor, constant: -9),
            scroll.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 6),
            scroll.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -6),
            scroll.topAnchor.constraint(equalTo: panel.topAnchor, constant: 4),
            scroll.bottomAnchor.constraint(equalTo: panel.bottomAnchor, constant: -6),
            ruleStatusLabel.leadingAnchor.constraint(equalTo: rulesView.leadingAnchor, constant: 32),
            ruleStatusLabel.trailingAnchor.constraint(equalTo: rulesView.trailingAnchor, constant: -30),
            ruleStatusLabel.bottomAnchor.constraint(equalTo: rulesView.bottomAnchor, constant: -18)
        ])
    }

    func configureRulesTable() {
        rulesTableView.dataSource = self
        rulesTableView.delegate = self
        rulesTableView.allowsMultipleSelection = true
        rulesTableView.allowsEmptySelection = true
        rulesTableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        rulesTableView.target = self
        rulesTableView.doubleAction = #selector(rulesDoubleClicked)
        rulesTableView.rowHeight = 34
        rulesTableView.backgroundColor = HajimiAppearance.panel
        rulesTableView.usesAlternatingRowBackgroundColors = false
        rulesTableView.headerView = NSTableHeaderView()
        let columns: [(String, String, CGFloat)] = [
            ("selected", "选择", 34),
            ("line", "行", 55), ("type", "类型", 125), ("value", "匹配值 / 资源", 380),
            ("policy", "策略", 180), ("loaded", "状态", 120)
        ]
        for item in columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(item.0))
            column.title = item.1
            column.width = item.2
            column.minWidth = item.0 == "selected" ? item.2 : item.2 * 0.6
            column.resizingMask = [.autoresizingMask, .userResizingMask]
            column.isHidden = item.0 == "selected"
            rulesTableView.addTableColumn(column)
        }
        let menu = NSMenu(title: "规则操作")
        menu.delegate = self
        menu.autoenablesItems = false
        rulesTableView.menu = menu
        updateRuleSelectionControls()
    }

    func buildProfileEditor() {
        let header = pageHeaderForExtension(eyebrow: "PROFILE", title: "配置文件",
                                subtitle: "Surge INI Profile")
        profileView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: profileView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: profileView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: profileView.topAnchor, constant: 48)
        ])

        profilePathLabel.stringValue = configurationStore.profileURL.path
        profilePathLabel.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        profilePathLabel.textColor = .secondaryLabelColor
        profilePathLabel.lineBreakMode = .byTruncatingMiddle

        let reveal = NSButton(title: "在 Finder 中显示", target: self, action: #selector(revealProfile))
        let importSurge = NSButton(title: "导入 Surge 配置", target: self,
                                   action: #selector(importSurgeProfile))
        let addSubscription = NSButton(title: "添加订阅", target: self,
                                       action: #selector(addSubscriptionAction))
        let manageSubscriptions = NSButton(title: "订阅…", target: self,
                                           action: #selector(manageSubscriptionsAction))
        let validate = NSButton(title: "检查配置", target: self, action: #selector(validateProfile))
        let save = NSButton(title: "保存并重载", target: self, action: #selector(saveProfile))
        save.bezelStyle = .rounded
        save.keyEquivalent = "s"
        save.keyEquivalentModifierMask = [.command]
        let toolbar = NSStackView(views: [profilePathLabel, reveal, importSurge,
                                          addSubscription, manageSubscriptions, validate, save])
        toolbar.orientation = .horizontal
        toolbar.alignment = .centerY
        toolbar.spacing = 10
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        profileView.addSubview(toolbar)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        profileTextView.isRichText = false
        profileTextView.isAutomaticQuoteSubstitutionEnabled = false
        profileTextView.isAutomaticDashSubstitutionEnabled = false
        profileTextView.isAutomaticTextReplacementEnabled = false
        profileTextView.isContinuousSpellCheckingEnabled = false
        profileTextView.isGrammarCheckingEnabled = false
        profileTextView.isAutomaticSpellingCorrectionEnabled = false
        profileTextView.layoutManager?.allowsNonContiguousLayout = true
        profileTextView.font = .monospacedSystemFont(ofSize: 12.5, weight: .regular)
        profileTextView.backgroundColor = HajimiAppearance.mutedPanel
        profileTextView.insertionPointColor = HajimiAppearance.accentText
        profileTextView.textContainerInset = NSSize(width: 10, height: 10)
        profileTextView.minSize = NSSize(width: 0, height: 0)
        profileTextView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                         height: CGFloat.greatestFiniteMagnitude)
        profileTextView.isVerticallyResizable = true
        profileTextView.isHorizontallyResizable = true
        profileTextView.autoresizingMask = [.width]
        profileTextView.textContainer?.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                                               height: CGFloat.greatestFiniteMagnitude)
        profileTextView.textContainer?.widthTracksTextView = false
        scroll.documentView = profileTextView
        profileView.addSubview(scroll)

        profileStatus.font = .systemFont(ofSize: 11, weight: .medium)
        profileStatus.textColor = .secondaryLabelColor
        profileStatus.translatesAutoresizingMaskIntoConstraints = false
        profileView.addSubview(profileStatus)
        NSLayoutConstraint.activate([
            toolbar.leadingAnchor.constraint(equalTo: profileView.leadingAnchor, constant: 30),
            toolbar.trailingAnchor.constraint(equalTo: profileView.trailingAnchor, constant: -30),
            toolbar.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 20),
            profilePathLabel.widthAnchor.constraint(greaterThanOrEqualToConstant: 240),
            scroll.leadingAnchor.constraint(equalTo: profileView.leadingAnchor, constant: 30),
            scroll.trailingAnchor.constraint(equalTo: profileView.trailingAnchor, constant: -30),
            scroll.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 12),
            scroll.bottomAnchor.constraint(equalTo: profileStatus.topAnchor, constant: -8),
            profileStatus.leadingAnchor.constraint(equalTo: profileView.leadingAnchor, constant: 30),
            profileStatus.bottomAnchor.constraint(equalTo: profileView.bottomAnchor, constant: -20)
        ])
    }

    func buildAbout() {
        let header = pageHeaderForExtension(eyebrow: "CAPABILITIES", title: "运行能力",
                                subtitle: "协议能力与系统接管的实际边界")
        aboutView.addSubview(header)
        NSLayoutConstraint.activate([
            header.leadingAnchor.constraint(equalTo: aboutView.leadingAnchor, constant: 30),
            header.trailingAnchor.constraint(equalTo: aboutView.trailingAnchor, constant: -30),
            header.topAnchor.constraint(equalTo: aboutView.topAnchor, constant: 48)
        ])
        let items: [(String, String, NSColor)] = [
            ("HTTP / HTTPS 出站", "CONNECT、正向转发、Basic 鉴权；TLS 默认验证证书", HajimiAppearance.accent),
            ("SOCKS5 / SOCKS5-TLS", "支持用户名密码与本地 UDP；TLS 上游仅支持 TCP", HajimiAppearance.accent),
            ("常见节点协议", "Swift 协议适配；C++ VLESS/Trojan 编码与 Objective-C TCP/TLS", HajimiAppearance.accent),
            ("QUIC 与 AnyTLS", "Hysteria v1/v2、TUIC v5、AnyTLS 经静态链接的 Go 核心", HajimiAppearance.uploadAccent),
            ("数据平面", "Objective-C++ 转发；C 报文；C++ 缓冲、重组、计时与规则", HajimiAppearance.indigoAccent),
            ("macOS 系统代理", "手动启用；恢复前检查代理设置是否仍由哈基米管理", HajimiAppearance.accent),
            ("增强模式 VIF", "root Helper 接管 utun；发现其他隧道时拒绝启动与断网自愈", HajimiAppearance.accent),
            ("Network Extension", "Objective-C 接入；需签名、entitlement 与原生 Provider 引擎", .systemOrange),
            ("尚未实现", "MITM、Rewrite、WireGuard 与 Gateway VM 需要单独开发", .systemOrange)
        ]
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        for item in items {
            let row = capabilityRow(item.0, detail: item.1, color: item.2)
            stack.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        let scroll = ScrollableSettingsContentView(content: stack)
        scroll.translatesAutoresizingMaskIntoConstraints = false
        aboutView.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: aboutView.leadingAnchor, constant: 22),
            scroll.trailingAnchor.constraint(equalTo: aboutView.trailingAnchor, constant: -22),
            scroll.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 16),
            scroll.bottomAnchor.constraint(equalTo: aboutView.bottomAnchor, constant: -20)
        ])
    }

    func refreshPolicies(preferred: String?) {
        let old = preferred ?? policyPopup.titleOfSelectedItem
        let candidates = profile.globalProxyNodes.isEmpty ? profile.selectablePolicies : profile.globalProxyNodes
        policyPopup.removeAllItems()
        policyPopup.addItems(withTitles: candidates)
        if let old, profile.groups[old] == nil, candidates.contains(old) {
            policyPopup.selectItem(withTitle: old)
        } else {
            let fallback = candidates.first ?? "DIRECT"
            policyPopup.selectItem(withTitle: fallback)
            UserDefaults.standard.set(fallback, forKey: "globalPolicy")
        }
        policyPopup.isEnabled = selectedModeForExtension == .proxy
    }

    func refreshGroups(preferred: String?) {
        let names = profile.groupOrder.filter { name in
            guard let group = profile.groups[name], group.kind == .select else { return false }
            return group.parameters["hidden"].map(surgeBoolean) != true
        }
        let old = preferred ?? groupPopup.titleOfSelectedItem
        groupPopup.removeAllItems()
        groupPopup.addItems(withTitles: names)
        if let old, names.contains(old) { groupPopup.selectItem(withTitle: old) }
        else if !names.isEmpty { groupPopup.selectItem(at: 0) }
        groupPopup.isEnabled = !names.isEmpty
        refreshGroupMembers()
    }

    func refreshGroupMembers() {
        groupMemberPopup.removeAllItems()
        guard let selectedGroup, let group = profile.groups[selectedGroup] else {
            groupMemberPopup.isEnabled = false
            return
        }
        groupMemberPopup.addItems(withTitles: group.members)
        if let saved = groupSelections[selectedGroup], group.members.contains(saved) {
            groupMemberPopup.selectItem(withTitle: saved)
        } else if !group.members.isEmpty { groupMemberPopup.selectItem(at: 0) }
        groupMemberPopup.isEnabled = !group.members.isEmpty
    }

    func refreshPolicyPage() {
        pruneProxyCardMetadata()
        let groupPlan = PolicyListRefreshPlan(previousOrder: renderedGroupOrder,
                                             order: profile.groupOrder, changedNames: [])
        if groupPlan.requiresReload {
            renderedGroupOrder = profile.groupOrder
            renderedGroupPolicies = profile.groups
            renderedGroupSelections = groupSelections
            pendingGroupCards.removeAll()
        }
        let currentQuery = ListSearchIndex<String>.normalizedQuery(proxySearchField.stringValue)
        if currentQuery.isEmpty {
            proxySearchQueue.cancelAllOperations()
            proxySearchDebouncer.cancel()
            applyProxySearch(names: profile.proxyOrder, query: "",
                             total: profile.proxyOrder.count, immediately: true,
                             forceFullReload: groupPlan.requiresReload)
        } else {
            if groupPlan.requiresReload {
                policyCollectionView.reloadData()
            }
            scheduleProxySearch(after: 0)
        }
        if !groupPlan.requiresReload {
            let changed = Set(profile.groupOrder.filter {
                renderedGroupPolicies[$0] != profile.groups[$0]
                    || renderedGroupSelections[$0] != groupSelections[$0]
            })
            schedulePolicyCardUpdates(groups: changed, immediately: true)
        }
        if policyStatusLabel.stringValue.isEmpty {
            policyStatusLabel.stringValue = "延迟为服务器 TCP 建连耗时；修改节点或策略组将立即热重载并自动保存到配置文件。"
        }
    }

    func scheduleProxySearch(after delay: TimeInterval = 0.15) {
        proxySearchQueue.cancelAllOperations()
        proxySearchDebouncer.schedule(after: delay) { [weak self] generation in
            guard let self else { return }
            let query = ListSearchIndex<String>.normalizedQuery(self.proxySearchField.stringValue)
            if query.isEmpty {
                self.applyProxySearch(names: self.profile.proxyOrder, query: "",
                                      total: self.profile.proxyOrder.count, immediately: true)
                return
            }
            let request = ListSearchRequest(generation: generation, revision: self.profileRevision,
                                            editorText: nil, query: query)
            let order = self.profile.proxyOrder
            let policies = self.profile.proxies
            let cached = self.proxySearchIndexRevision == request.revision ? self.proxySearchIndex : nil
            self.proxySearchQueue.addOperation { [weak self] in
                let index = cached ?? ListSearchIndex(order) { name in
                    guard let policy = policies[name] else { return [name] }
                    return [name, policy.adapterType ?? policy.kind.rawValue, policy.host ?? ""]
                }
                let names = index.matchingIndexes(query: query).map { index.values[$0] }
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    guard request.isCurrent(
                        generation: self.proxySearchDebouncer.generation, revision: self.profileRevision,
                        editorText: nil,
                        query: ListSearchIndex<String>.normalizedQuery(self.proxySearchField.stringValue)) else {
                        if generation == self.proxySearchDebouncer.generation { self.scheduleProxySearch(after: 0) }
                        return
                    }
                    self.proxySearchIndex = index
                    self.proxySearchIndexRevision = request.revision
                    self.applyProxySearch(names: names, query: query, total: order.count, immediately: true)
                }
            }
        }
    }

    func applyProxySearch(names: [String], query: String, total: Int,
                                  immediately: Bool = false, forceFullReload: Bool = false) {
        let plan = PolicyListRefreshPlan(previousOrder: renderedProxyOrder, order: names, changedNames: [])
        filteredProxyNames = names
        proxyCountLabel.stringValue = query.isEmpty ? "\(total) 个节点" : "\(names.count) / \(total)"
        if plan.requiresReload || forceFullReload || renderedGroupOrder != profile.groupOrder {
            renderedProxyOrder = names
            renderedGroupOrder = profile.groupOrder
            renderedGroupPolicies = profile.groups
            renderedGroupSelections = groupSelections
            renderedActiveProxy = activeProxyCardName
            for name in names { renderedProxyPolicies[name] = profile.proxies[name] }
            // A filtered reload covers these identities only. Hidden dirty
            // cards still need to be reconciled when they become visible.
            pendingProxyCards.subtract(Set(names))
            pendingGroupCards.removeAll()
            policyCollectionView.reloadData()
        } else {
            schedulePolicyCardUpdates(immediately: immediately)
            refreshActiveProxyCards()
        }
    }

    var activeProxyCardName: String? { selectedModeForExtension == .proxy ? selectedPolicy : nil }

    func pruneProxyCardMetadata() {
        let pruned = PolicyCardMetadataPruning.apply(metadata: renderedProxyPolicies, dirty: pendingProxyCards,
                                                     current: profile.proxies, order: profile.proxyOrder)
        renderedProxyPolicies = pruned.metadata
        pendingProxyCards = pruned.dirty
        proxyCardIdentities = pruned.identities
    }

    func syncDashboardRoutingControlsVisibility() {
        let mode = selectedModeForExtension
        policyPopup.superview?.isHidden = (mode != .proxy)
        groupPopup.superview?.isHidden = (mode != .rule)
        groupMemberPopup.superview?.isHidden = (mode != .rule)
        if let stack = modePopup.superview?.superview as? NSStackView, stack.views.count >= 5 {
            stack.views[2].isHidden = (mode != .rule && mode != .proxy) || true
        }
    }

    func refreshActiveProxyCards() {
        syncDashboardRoutingControlsVisibility()
        guard renderedActiveProxy != activeProxyCardName else { return }
        schedulePolicyCardUpdates(proxies: Set([renderedActiveProxy, activeProxyCardName].compactMap { $0 }))
    }

    /// Keep dirty identities while the page/window is hidden; opening the page
    /// reconciles them once. This does not pause health checking or API updates.
    func schedulePolicyCardUpdates(proxies: Set<String> = [], groups: Set<String> = [],
                                           immediately: Bool = false) {
        pendingProxyCards.formUnion(proxies.intersection(proxyCardIdentities))
        pendingProxyCards.formIntersection(proxyCardIdentities)
        pendingGroupCards.formUnion(groups)
        guard !pendingProxyCards.isEmpty || !pendingGroupCards.isEmpty,
              !policiesView.isHidden, window?.isVisible == true else { return }
        if immediately {
            policyCardRefreshWork?.cancel(); policyCardRefreshWork = nil
            applyPendingPolicyCardUpdates()
        } else if policyCardRefreshWork == nil {
            let work = DispatchWorkItem { [weak self] in
                self?.policyCardRefreshWork = nil
                self?.applyPendingPolicyCardUpdates()
            }
            policyCardRefreshWork = work
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(80), execute: work)
        }
    }

    func applyPendingPolicyCardUpdates() {
        guard !policiesView.isHidden, window?.isVisible == true,
              !pendingProxyCards.isEmpty || !pendingGroupCards.isEmpty else { return }
        let proxies = pendingProxyCards.intersection(proxyCardIdentities)
        let groups = pendingGroupCards
        pendingProxyCards.removeAll(); pendingGroupCards.removeAll()
        let proxyPlan = PolicyListRefreshPlan(previousOrder: renderedProxyOrder,
                                             order: filteredProxyNames, changedNames: proxies)
        let groupPlan = PolicyListRefreshPlan(previousOrder: renderedGroupOrder,
                                             order: profile.groupOrder, changedNames: groups)
        let expectedSection0 = (renderedProxyOrder ?? filteredProxyNames).count + 1
        let expectedSection1 = (renderedGroupOrder ?? profile.groupOrder).count + 1
        let countsConsistent = policyCollectionView.numberOfSections == 2
            && policyCollectionView.numberOfItems(inSection: 0) == expectedSection0
            && policyCollectionView.numberOfItems(inSection: 1) == expectedSection1
        if proxyPlan.requiresReload || groupPlan.requiresReload || !countsConsistent {
            renderedProxyOrder = filteredProxyNames
            renderedGroupOrder = profile.groupOrder
            renderedGroupPolicies = profile.groups
            renderedGroupSelections = groupSelections
            for name in filteredProxyNames { renderedProxyPolicies[name] = profile.proxies[name] }
            renderedActiveProxy = activeProxyCardName
            policyCollectionView.reloadData()
            return
        }
        let validProxyPaths = Set(proxyPlan.paths.filter { $0.section == 0 && $0.item >= 0 && $0.item < expectedSection0 })
        if !validProxyPaths.isEmpty { policyCollectionView.reloadItems(at: validProxyPaths) }
        for name in proxies { renderedProxyPolicies[name] = profile.proxies[name] }
        if !proxies.isEmpty { renderedActiveProxy = activeProxyCardName }
        let validGroupPaths = Set(groupPlan.paths.compactMap { path -> IndexPath? in
            guard path.item >= 0 && path.item < expectedSection1 else { return nil }
            return IndexPath(item: path.item, section: 1)
        })
        if !validGroupPaths.isEmpty {
            policyCollectionView.reloadItems(at: validGroupPaths)
        }
        for name in groups {
            renderedGroupPolicies[name] = profile.groups[name]
            renderedGroupSelections[name] = groupSelections[name]
        }
    }

    func refreshRulesPage(selecting selection: Set<Int>? = nil) {
        if let selection {
            pendingRuleSelection = (profileTextView.string, profileRevision, selection)
        }
        scheduleRuleSearch(after: 0)
    }

    func scheduleRuleSearch(after delay: TimeInterval = 0.15) {
        ruleListQueue.cancelAllOperations()
        ruleSearchDebouncer.schedule(after: delay) { [weak self] generation in
            guard let self else { return }
            let request = ListSearchRequest(
                generation: generation, revision: self.profileRevision,
                editorText: self.profileTextView.string,
                query: ListSearchIndex<String>.normalizedQuery(self.ruleSearchField.stringValue))
            let fallback = self.resolvedProfile ?? self.profile
            let preparation = self.ruleListPreparation
            self.ruleListQueue.addOperation { [weak self] in
                let snapshot = preparation.prepare(editorText: request.editorText ?? "",
                                                   revision: request.revision, fallback: fallback,
                                                   query: request.query)
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    guard request.isCurrent(
                        generation: self.ruleSearchDebouncer.generation, revision: self.profileRevision,
                        editorText: self.profileTextView.string,
                        query: ListSearchIndex<String>.normalizedQuery(self.ruleSearchField.stringValue)) else {
                        if generation == self.ruleSearchDebouncer.generation { self.refreshRulesPage() }
                        return
                    }
                    self.applyRuleList(snapshot, request: request)
                }
            }
        }
        if !rulesPageIsEditable { ruleCountLabel.stringValue = "正在准备规则…" }
        updateRuleSelectionControls()
    }

    func applyRuleList(_ snapshot: RuleListSnapshot, request: ListSearchRequest) {
        let previousText = rulesPageSourceText
        let selectedLines = selectedRuleSourceLines
        rulesPageSourceText = snapshot.sourceText
        rulesPageRevision = request.revision
        rulesPageProfile = snapshot.sourceText == nil ? nil : snapshot.profile
        rulesPageRuleSetLocations = snapshot.ruleSetLocations
        filteredRules = snapshot.rules
        filteredRuleRows = snapshot.rows
        filteredRuleSourceLines = snapshot.sourceLines
        if ruleOperationID == nil {
            if let error = snapshot.errorDescription {
                ruleStatusLabel.stringValue = "配置草稿无效，当前规则只读：\(error)"
                ruleStatusLabel.textColor = .systemRed
                ruleStatusLabel.toolTip = error
            } else if ruleStatusLabel.stringValue.hasPrefix("配置草稿无效，当前规则只读：") {
                ruleStatusLabel.stringValue = "新增规则默认插入 FINAL / MATCH 之前；更新按钮刷新规则集，编辑可修改本地规则。"
                ruleStatusLabel.textColor = .secondaryLabelColor
                ruleStatusLabel.toolTip = nil
            }
        }
        let ruleSetPart = snapshot.ruleSetCount == 0 ? ""
            : " · \(snapshot.ruleSetCount) 个 RULE-SET / \(snapshot.loadedRuleCount) 条子规则"
        ruleCountLabel.stringValue = request.query.isEmpty
            ? "\(snapshot.totalRuleCount) 条主规则\(ruleSetPart)"
            : "\(snapshot.rules.count) / \(snapshot.totalRuleCount)\(ruleSetPart)"
        if snapshot.sourceText != nil, request.editorText != lastKnownStoredProfileText {
            ruleCountLabel.stringValue += " · 未保存"
        }
        let retained: Set<Int>
        if let pending = pendingRuleSelection, pending.text == request.editorText,
           pending.revision == request.revision, snapshot.sourceText != nil {
            retained = pending.lines.intersection(snapshot.sourceLines)
        } else {
            retained = RuleTableSelection.retaining(
                selectedLines, visibleSourceLines: snapshot.sourceLines,
                sourceTextChanged: previousText != snapshot.sourceText || snapshot.sourceText == nil)
        }
        pendingRuleSelection = nil
        ruleSelectionRefreshInProgress = true
        rulesTableView.reloadData()
        rulesTableView.selectRowIndexes(
            RuleTableSelection.rowIndexes(sourceLines: retained,
                                          orderedSourceLines: filteredRuleSourceLines),
            byExtendingSelection: false)
        ruleSelectionRefreshInProgress = false
        updateRuleSelectionControls()
    }

    var selectedRuleSourceLines: Set<Int> {
        RuleTableSelection.sourceLines(rows: rulesTableView.selectedRowIndexes,
                                       orderedSourceLines: filteredRuleSourceLines)
    }

    var selectedRuleSetLocations: Set<String> {
        let rows = rulesTableView.selectedRowIndexes
        guard !rows.isEmpty else { return rulesPageRuleSetLocations }
        return Set(rows.compactMap { row in
            guard filteredRules.indices.contains(row) else { return nil }
            if case .ruleSet(let reference) = filteredRules[row].kind { return reference.location }
            return nil
        })
    }

    var rulesPageIsEditable: Bool {
        rulesPageSourceText == profileTextView.string && rulesPageRevision == profileRevision
            && rulesPageProfile != nil
    }

    func updateRuleSelectionControls() {
        let count = selectedRuleSourceLines.count
        let editable = rulesPageIsEditable
        let available = editable && ruleOperationID == nil
        ruleAddButton.isEnabled = available
        ruleEditButton.isEnabled = available && count > 0
        ruleEditButton.title = count > 1 ? "批量改策略" : "编辑规则"
        ruleEditButton.toolTip = count > 1
            ? "批量修改选中规则的策略，匹配值和参数保持不变"
            : "编辑所选规则；也可双击一行"
        ruleDeleteButton.isEnabled = available && count > 0
        ruleUpdateButton.isEnabled = available && !selectedRuleSetLocations.isEmpty
        ruleUpdateButton.toolTip = count == 0
            ? "强制刷新全部 RULE-SET；本地规则请使用编辑"
            : "强制刷新选中规则中的 RULE-SET；本地规则请使用编辑"
        let checking = ruleMultiSelectButton.state == .on
        rulesTableView.tableColumns.first { $0.identifier.rawValue == "selected" }?.isHidden = !checking
        ruleSelectAllButton.isHidden = !checking
        ruleClearSelectionButton.isHidden = !checking
        ruleSelectAllButton.isEnabled = !filteredRules.isEmpty && editable
        ruleClearSelectionButton.isEnabled = count > 0
        ruleSelectionCountLabel.stringValue = count == 0 ? "未选择" : "已选 \(count) 条"
    }

    func selectRuleSourceLines(_ lines: Set<Int>) {
        rulesTableView.selectRowIndexes(
            RuleTableSelection.rowIndexes(sourceLines: lines,
                                          orderedSourceLines: filteredRuleSourceLines),
            byExtendingSelection: false)
        updateRuleSelectionControls()
    }

    func surgeBoolean(_ value: String) -> Bool {
        ["true", "yes", "on", "1"].contains(value.lowercased())
    }

    /// Starts or re-targets health checking after the profile changes.
    ///
    /// Automatic selections are seeded into `groupSelections` immediately so a
    /// managed group does not sit on its first declared member until the first
    /// probe round lands.
    func refreshPolicyHealth() {
        policyHealthEpoch &+= 1
        let epoch = policyHealthEpoch
        let selectionsChanged: ([String: String]) -> Void = { [weak self] selections in
            DispatchQueue.main.async {
                guard let self, self.policyHealthEpoch == epoch else { return }
                var changed = Set<String>()
                for (group, member) in selections
                where !self.manualManagedGroupSelections.contains(group) && self.groupSelections[group] != member {
                    self.groupSelections[group] = member
                    changed.insert(group)
                }
                // Automatic selections are deliberately not persisted to
                // UserDefaults: they are a live measurement, and restoring a
                // stale one at launch would point traffic at whatever was
                // fastest yesterday.
                guard !changed.isEmpty else { return }
                self.updateEngineRoutingForExtension()
                self.schedulePolicyCardUpdates(groups: changed)
            }
        }
        let reportReceived: (PolicyHealthMonitor.Report) -> Void = { [weak self] report in
            DispatchQueue.main.async {
                guard let self, self.policyHealthEpoch == epoch,
                      self.profile.groups[report.group] != nil else { return }
                self.policyLatencies[report.group] = report.latencies
            }
        }
        policyHealth.update(profile: resolvedProfile ?? profile,
                            onSelectionsChanged: selectionsChanged, onReport: reportReceived)
    }

    @objc func policyChanged() {
        UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
        saveCurrentProfileGroupSelectionsSnapshot(
            text: profileTextView.string,
            parsed: profile,
            selections: groupSelections,
            manualGroups: manualManagedGroupSelections,
            globalPolicy: selectedPolicy
        )
        updateEngineRoutingForExtension()
        updateOverviewDetailsForExtension()
        refreshActiveProxyCards()
    }

    @objc func groupChanged() {
        if let selectedGroup {
            UserDefaults.standard.set(selectedGroup, forKey: "selectedPolicyGroup")
        }
        refreshGroupMembers()
    }

    @objc func groupMemberChanged() {
        guard let selectedGroup, let member = groupMemberPopup.titleOfSelectedItem else { return }
        setGroupSelection(group: selectedGroup, member: member)
    }

    @objc func proxySearchChanged() { scheduleProxySearch() }
    @objc func ruleSearchChanged() { scheduleRuleSearch() }

    @objc func ruleMultiSelectionChanged() {
        let selection = selectedRuleSourceLines
        updateRuleSelectionControls()
        ruleSelectionRefreshInProgress = true
        rulesTableView.reloadData()
        ruleSelectionRefreshInProgress = false
        selectRuleSourceLines(selection)
    }

    @objc func selectAllRules() {
        guard rulesPageIsEditable else { refreshRulesPage(); return }
        rulesTableView.selectRowIndexes(IndexSet(integersIn: 0..<filteredRules.count),
                                        byExtendingSelection: false)
        updateRuleSelectionControls()
    }

    @objc func clearRuleSelection() {
        rulesTableView.deselectAll(nil)
        updateRuleSelectionControls()
    }

    @objc func ruleRowSelectionChanged(_ sender: NSButton) {
        guard rulesPageIsEditable,
              let row = filteredRules.firstIndex(where: { $0.sourceLine == sender.tag }) else {
            refreshRulesPage()
            return
        }
        var indexes = rulesTableView.selectedRowIndexes
        if sender.state == .on { indexes.insert(row) }
        else { indexes.remove(row) }
        rulesTableView.selectRowIndexes(indexes, byExtendingSelection: false)
        updateRuleSelectionControls()
    }

    @objc func rulesDoubleClicked() {
        let row = rulesTableView.clickedRow
        guard ruleOperationID == nil, filteredRules.indices.contains(row) else { return }
        rulesTableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        editSelectedRules()
    }

    var rulePolicyNames: [String] {
        let source = rulesPageProfile ?? profile
        var names = ["DIRECT", "REJECT"]
        for name in source.groupOrder + source.proxyOrder where !names.contains(name) {
            names.append(name)
        }
        return names
    }

    func ruleEditingSnapshot() throws -> (text: String, revision: Int) {
        guard ruleOperationID == nil else {
            throw makeProfileApplyErrorForExtension("规则操作正在进行，请稍候")
        }
        guard rulesPageIsEditable else {
            refreshRulesPage()
            throw makeProfileApplyErrorForExtension("配置已变化或草稿无效，请检查后重新选择规则")
        }
        try verifyStoredProfileHasNotChanged(expected: lastKnownStoredProfileText)
        return (profileTextView.string, profileRevision)
    }

    func verifyRuleEditingSnapshot(_ snapshot: (text: String, revision: Int)) throws {
        guard snapshot.text == profileTextView.string, snapshot.revision == profileRevision else {
            throw makeProfileApplyErrorForExtension("配置在编辑期间已变化，未覆盖新内容，请关闭编辑框后重新选择")
        }
        guard ruleOperationID == nil else {
            throw makeProfileApplyErrorForExtension("规则操作正在进行，请稍候")
        }
        try verifyStoredProfileHasNotChanged(expected: lastKnownStoredProfileText)
    }

    func validateRulePolicy(_ rawPolicy: String, in text: String) throws {
        let source = try ProfileParser.parse(text)
        let policy = rawPolicy.trimmingCharacters(in: .whitespacesAndNewlines)
        guard policy == "DIRECT" || policy == "REJECT" ||
                source.proxies[policy] != nil || source.groups[policy] != nil else {
            throw makeProfileApplyErrorForExtension("策略“\(policy)”不存在，请选择已有节点、策略组、DIRECT 或 REJECT")
        }
    }


    @objc func validateProfile() {
        let text = profileTextView.string
        let proxy = ruleSetDownloadProxy
        profileValidationGeneration += 1
        let generation = profileValidationGeneration
        profileStatus.stringValue = "正在解析 Surge Profile、更新 RULE-SET 并检查出站…"
        profileStatus.textColor = .systemBlue
        profileStatus.toolTip = nil
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result: Result<Profile, Error>
            do {
                let value = try ProfileParser.parse(text)
                let resolved = try self.surgeRuleSets.prepare(profile: value, httpProxy: proxy)
                try self.protocolAdapters.validate(profile: resolved)
                result = .success(resolved)
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async {
                guard generation == self.profileValidationGeneration,
                      text == self.profileTextView.string else { return }
                switch result {
                case .success(let value):
                    self.applyProfileValidationStatus(value, prefix: "配置有效")
                case .failure(let error):
                    self.profileStatus.stringValue = "✕ \(error.localizedDescription)"
                    self.profileStatus.textColor = .systemRed
                    self.profileStatus.toolTip = error.localizedDescription
                }
            }
        }
    }

    @objc func saveProfile() {
        applyProfileTextInBackground(profileTextView.string, prefix: "已保存并重载")
    }

    /// Resolve remote RULE-SETs away from AppKit's main thread. The editor,
    /// running profile and subscription definitions are checked again before
    /// anything is written, since preparation may outlive a user's next edit.
    func applyProfileTextInBackground(
        _ text: String, prefix: String, keepEditorOnFailure: Bool = false,
        allowExternalChanges: Bool = false,
        forceRefreshRuleSetLocations: Set<String> = [],
        stillApplicable: @escaping () -> Bool = { true },
        completion: @escaping (Result<Void, Error>) -> Void = { _ in }
    ) {
        profileApplyGeneration &+= 1
        profileValidationGeneration &+= 1
        let guardState = ProfileApplyCommitGuard(generation: profileApplyGeneration,
                                                 revision: profileRevision,
                                                 editorText: profileTextView.string)
        activeProfilePreparationGeneration = guardState.generation
        let expectedStoredText = allowExternalChanges ? text : lastKnownStoredProfileText
        let existingResolved = resolvedProfile
        let proxy = ruleSetDownloadProxy
        profileStatus.stringValue = "正在后台准备 RULE-SET…"
        profileStatus.textColor = .systemBlue
        profileStatus.toolTip = nil
        ruleSetPreparationQueue.async { [weak self] in
            guard let self else { return }
            let prepared: Result<(parsed: Profile, resolved: Profile), Error> = Result {
                let parsed = try ProfileParser.parse(text)
                let referencedLocations = Set(parsed.ruleSetReferences.map(\.location))
                if forceRefreshRuleSetLocations.isEmpty,
                   let existingResolved,
                   referencedLocations.isSubset(of: Set(existingResolved.ruleSetContents.keys)) {
                    var reused = parsed
                    for location in referencedLocations {
                        reused.ruleSetContents[location] = existingResolved.ruleSetContents[location]
                    }
                    if !reused.adoptCompiledRoutingRules(from: existingResolved) {
                        reused.prepareCompiledRoutingRules()
                    }
                    return (parsed, reused)
                }
                if forceRefreshRuleSetLocations.isEmpty {
                    do {
                        return (parsed, try self.surgeRuleSets.prepare(profile: parsed, mode: .cacheOnly))
                    } catch let error as SurgeRuleSetManager.RuleSetError where error.isMissingCache {
                        // Fall through to download missing cache entries.
                    }
                }
                return (parsed, try self.surgeRuleSets.prepare(
                    profile: parsed, forceRefreshLocations: forceRefreshRuleSetLocations,
                    httpProxy: proxy))
            }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                if self.activeProfilePreparationGeneration == guardState.generation {
                    self.activeProfilePreparationGeneration = nil
                }
                guard guardState.isCurrent(generation: self.profileApplyGeneration,
                                           revision: self.profileRevision,
                                           editorText: self.profileTextView.string),
                      stillApplicable() else {
                    let error = makeProfileApplyErrorForExtension(
                        "配置或订阅在准备规则集期间已更改，未覆盖新内容，请重试")
                    if guardState.generation == self.profileApplyGeneration {
                        self.reportProfileApplyFailure(error)
                    }
                    completion(.failure(error))
                    return
                }
                do {
                    let result = try prepared.get()
                    try self.applyPreparedProfileText(text, parsed: result.parsed,
                                                      resolved: result.resolved,
                                                      prefix: prefix,
                                                      preferredPolicy: self.selectedPolicy,
                                                      keepEditorOnFailure: keepEditorOnFailure,
                                                      expectedStoredText: expectedStoredText)
                    completion(.success(()))
                } catch {
                    self.reportProfileApplyFailure(error)
                    completion(.failure(error))
                }
            }
        }
    }

    func reportProfileApplyFailure(_ error: Error) {
        profileStatus.stringValue = "✕ \(error.localizedDescription)"
        profileStatus.textColor = .systemRed
        profileStatus.toolTip = error.localizedDescription
    }

    func verifyStoredProfileHasNotChanged(expected: String?) throws {
        guard let expected else { return } // Allow repair when the initial file was unreadable.
        let actual = try configurationStore.loadTextThrowing()
        guard ProfileApplyCommitGuard.diskTextMatches(expected: expected, actual: actual) else {
            throw makeProfileApplyErrorForExtension(
                "配置文件已由其他程序修改，未覆盖磁盘更改；请重新加载配置后再试")
        }
    }

    func autoManagedHealthGroupsChanged(from oldProfile: Profile, to newProfile: Profile) -> Bool {
        let oldManaged = oldProfile.groups.filter { PolicyHealthMonitor.managesSelection(of: $0.value) }
        let newManaged = newProfile.groups.filter { PolicyHealthMonitor.managesSelection(of: $0.value) }
        guard oldManaged == newManaged else { return true }
        guard !newManaged.isEmpty else { return false }
        for group in newManaged.values {
            for member in group.members {
                if oldProfile.proxies[member] != newProfile.proxies[member] ||
                   oldProfile.groups[member] != newProfile.groups[member] {
                    return true
                }
            }
        }
        return false
    }

    func applyProfileText(_ text: String, prefix: String,
                                  preferredPolicy: String?,
                                  preferredGroup: String? = nil,
                                  keepEditorOnFailure: Bool = false,
                                  reusingRulesFrom baseProfile: Profile? = nil,
                                  replacedRulePolicy: (from: String, to: String)? = nil) throws {
        profileApplyGeneration &+= 1
        profileValidationGeneration &+= 1
        activeProfilePreparationGeneration = nil
        let expectedStoredText = lastKnownStoredProfileText
        try verifyStoredProfileHasNotChanged(expected: expectedStoredText)
        let parsed: Profile
        if let baseProfile, !baseProfile.rules.isEmpty {
            parsed = try ProfileParser.parseReusingRules(text, baseRules: baseProfile.rules,
                                                         replacedPolicy: replacedRulePolicy)
        } else {
            parsed = try ProfileParser.parse(text)
        }
        let resolved: Profile
        let referencedLocations = Set(parsed.ruleSetReferences.map(\.location))
        if let existingResolved = resolvedProfile,
           referencedLocations.isSubset(of: Set(existingResolved.ruleSetContents.keys)) {
            var reused = parsed
            for location in referencedLocations {
                reused.ruleSetContents[location] = existingResolved.ruleSetContents[location]
            }
            if !reused.adoptCompiledRoutingRules(from: existingResolved) {
                reused.prepareCompiledRoutingRules()
            }
            resolved = reused
        } else {
            do {
                resolved = try surgeRuleSets.prepare(profile: parsed, mode: .cacheOnly)
            } catch let error as SurgeRuleSetManager.RuleSetError where error.isMissingCache {
                resolved = try surgeRuleSets.prepare(profile: parsed, httpProxy: ruleSetDownloadProxy)
            }
        }
        try applyPreparedProfileText(text, parsed: parsed, resolved: resolved,
                                     prefix: prefix, preferredPolicy: preferredPolicy,
                                     preferredGroup: preferredGroup,
                                     keepEditorOnFailure: keepEditorOnFailure,
                                     expectedStoredText: expectedStoredText,
                                     alreadyVerifiedStoredText: true)
    }

    func applyPreparedProfileText(_ text: String, parsed: Profile,
                                          resolved: Profile, prefix: String,
                                          preferredPolicy: String?,
                                          preferredGroup: String? = nil,
                                          keepEditorOnFailure: Bool = false,
                                          expectedStoredText: String? = nil,
                                          alreadyVerifiedStoredText: Bool = false) throws {
        try protocolAdapters.validate(profile: resolved)
        if systemProxyIsOrWillBeEnabled && parsed.httpListen != profile.httpListen {
            throw makeProfileApplyErrorForExtension("HTTP 监听地址已变化。请先在总览中关闭系统代理。")
        }
        if systemProxyIsOrWillBeEnabled && parsed.proxyBypassDomains != profile.proxyBypassDomains {
            throw makeProfileApplyErrorForExtension("Surge skip-proxy 绕过列表已变化。请先关闭系统代理。")
        }
        let wasRunning = engineStatus == .running || engineStatus == .starting
        let wasEnhanced = enhancedMode.isRequested || enhancedMode.isEnabled
        if !alreadyVerifiedStoredText {
            try verifyStoredProfileHasNotChanged(expected: expectedStoredText)
        }
        let oldStoredText: String
        if let expectedStoredText {
            oldStoredText = expectedStoredText
        } else {
            oldStoredText = wasRunning || wasEnhanced
                ? try configurationStore.loadTextThrowing() : configurationStore.loadText()
        }
        let oldEditorText = profileTextView.string
        let oldProfile = profile
        let oldResolved = resolvedProfile
        let oldSelectedPolicy = selectedPolicy
        let oldSelectedGroup = selectedGroup
        let oldGroupSelections = groupSelections
        let oldManualManagedGroups = manualManagedGroupSelections
        if !oldProfile.groups.isEmpty {
            saveCurrentProfileGroupSelectionsSnapshot(
                text: oldStoredText,
                parsed: oldProfile,
                selections: oldGroupSelections,
                manualGroups: oldManualManagedGroups,
                globalPolicy: oldSelectedPolicy
            )
        }
        let oldLatencies = nodeLatencies.mapValues { $0 == .testing || $0 == .queued ? .untested : $0 }
        let oldPolicyLatencies = policyLatencies
        try configurationStore.save(text)
        cancelNodeTests(refresh: false)
        profile = parsed
        resolvedProfile = resolved
        launchProfilePlan = .ready(parsed)
        lastKnownStoredProfileText = text
        profileRevision &+= 1
        if profileTextView.string != text {
            profileTextView.string = text
        }
        let restored = restoreProfileGroupSelectionsSnapshot(
            text: text,
            parsed: parsed,
            currentSelections: oldGroupSelections,
            preferredPolicy: preferredPolicy
        )
        manualManagedGroupSelections = restored.manualGroups
        groupSelections = restored.selections
        refreshPolicies(preferred: restored.preferredGlobalPolicy)
        UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
        UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
        saveCurrentProfileGroupSelectionsSnapshot(
            text: text,
            parsed: parsed,
            selections: groupSelections,
            manualGroups: manualManagedGroupSelections,
            globalPolicy: selectedPolicy
        )
        refreshGroups(preferred: preferredGroup ?? oldSelectedGroup)
        nodeLatencies = nodeLatencies.filter { name, _ in
            parsed.proxies[name] != nil && parsed.proxies[name] == oldProfile.proxies[name]
        }
        policyLatencies = policyLatencies.filter { parsed.groups[$0.key] != nil }
        let controllerSettingsChanged = parsed.httpAPI != oldProfile.httpAPI
            || parsed.httpAPIKey != oldProfile.httpAPIKey
            || parsed.externalController != oldProfile.externalController
            || parsed.externalControllerKey != oldProfile.externalControllerKey

        if wasRunning || wasEnhanced {
            do {
                let runtime = try protocolAdapters.prepare(profile: resolved)
                if wasEnhanced {
                    try enhancedMode.reload(profile: runtime, mode: selectedModeForExtension,
                                            globalPolicy: selectedPolicy,
                                            groupSelections: groupSelections)
                }
                if wasRunning {
                    if engineStatus == .running &&
                       parsed.httpListen == oldProfile.httpListen &&
                       parsed.socksListen == oldProfile.socksListen {
                        var runtimeProfile = runtime
                        runtimeProfile.httpListen = engine.activeHTTPListen
                        let routingConfiguration = RoutingReloadGate.Configuration(
                            profile: runtime, mode: selectedModeForExtension, globalPolicy: selectedPolicy,
                            groupSelections: groupSelections)
                        try reloadListenerForExtension {
                            engine.updateConfiguration(profile: runtimeProfile, mode: selectedModeForExtension,
                                                       globalPolicy: selectedPolicy,
                                                       groupSelections: groupSelections)
                        }
                        routingReloadGate.recordApplied(routingConfiguration)
                    } else {
                        try startEngineThrowingForExtension(prepared: resolved)
                    }
                }
            } catch {
                let restored = (try? configurationStore.save(oldStoredText)) != nil
                lastKnownStoredProfileText = restored ? oldStoredText : nil
                profile = oldProfile
                resolvedProfile = oldResolved
                launchProfilePlan = .ready(oldProfile)
                profileRevision &+= 1
                let rollbackEditorText = keepEditorOnFailure ? oldEditorText : oldStoredText
                if profileTextView.string != rollbackEditorText {
                    profileTextView.string = rollbackEditorText
                }
                refreshPolicies(preferred: oldSelectedPolicy)
                UserDefaults.standard.set(selectedPolicy, forKey: "globalPolicy")
                manualManagedGroupSelections = oldManualManagedGroups
                groupSelections = oldGroupSelections
                UserDefaults.standard.set(groupSelections, forKey: "groupSelections")
                nodeLatencies = oldLatencies
                policyLatencies = oldPolicyLatencies
                refreshGroups(preferred: oldSelectedGroup)
                refreshPolicyPage()
                refreshRulesPage()
                let oldRuntimeProfile = oldResolved ?? oldProfile
                if wasEnhanced,
                   let runtime = try? protocolAdapters.prepare(profile: oldRuntimeProfile) {
                    try? enhancedMode.reload(profile: runtime, mode: selectedModeForExtension,
                                             globalPolicy: oldSelectedPolicy,
                                             groupSelections: oldGroupSelections)
                }
                if wasRunning { try? startEngineThrowingForExtension(prepared: oldRuntimeProfile) }
                refreshPolicyHealth()
                if controllerSettingsChanged { restartExternalController() }
                throw makeProfileApplyErrorForExtension("新配置无法启动，已恢复旧配置：\(error.localizedDescription)")
            }
        } else {
            updateEngineRoutingForExtension()
        }
        refreshPolicyPage()
        if !rulesView.isHidden {
            refreshRulesPage()
        } else {
            rulesPageProfile = resolved
        }
        updateOverviewDetailsForExtension()
        if autoManagedHealthGroupsChanged(from: oldProfile, to: parsed) {
            refreshPolicyHealth()
        }
        if controllerSettingsChanged { restartExternalController() }
        applyProfileValidationStatus(resolved, prefix: prefix)
        subscriptions.syncEditedProfileText(text, proxyCount: parsed.globalProxyNodes.count)
        if !settingsView.isHidden {
            refreshSubscriptionSettings()
        }
    }
}

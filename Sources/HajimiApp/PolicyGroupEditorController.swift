import AppKit
import HajimiCore

final class PolicyGroupEditorController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    private let originalName: String?
    private let unavailableNames: Set<String>
    private let commit: (SurgePolicyGroupDraft) throws -> Void
    private var members: [String]

    private let nameField = NSTextField()
    private let kindPopup = NSPopUpButton()
    private let memberPopup = NSPopUpButton()
    private let table = NSTableView()
    private let optionsView = NSTextView()
    private let errorLabel = NSTextField(labelWithString: "")

    init(draft: SurgePolicyGroupDraft?, isNew: Bool,
         unavailableNames: Set<String>, availablePolicies: [String],
         commit: @escaping (SurgePolicyGroupDraft) throws -> Void) {
        originalName = isNew ? nil : draft?.name
        self.unavailableNames = unavailableNames
        self.commit = commit
        members = draft?.members ?? ["DIRECT"]
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 650, height: 590),
                            styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = isNew ? "新增策略组" : "编辑策略组"
        panel.minSize = NSSize(width: 580, height: 520)
        super.init(window: panel)
        buildUI(draft: draft, isNew: isNew, availablePolicies: availablePolicies)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildUI(draft: SurgePolicyGroupDraft?, isNew: Bool,
                         availablePolicies: [String]) {
        guard let root = window?.contentView else { return }
        let title = NSTextField(labelWithString: isNew ? "新增策略组" : "编辑策略组")
        title.font = .systemFont(ofSize: 18, weight: .semibold)
        title.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(title)

        nameField.stringValue = draft?.name ?? ""
        nameField.placeholderString = "策略组名称"
        let kinds: [(String, PolicyGroupKind)] = [
            ("手动选择", .select), ("负载均衡", .loadBalance),
            ("URL 测试", .urlTest), ("故障转移", .fallback),
            ("Smart", .smart), ("子网", .subnet)
        ]
        for (name, kind) in kinds {
            kindPopup.addItem(withTitle: name)
            kindPopup.lastItem?.representedObject = kind.rawValue
        }
        if let kind = draft?.kind,
           let index = kinds.firstIndex(where: { $0.1 == kind }) { kindPopup.selectItem(at: index) }
        let top = NSGridView(views: [
            [label("名称"), nameField],
            [label("类型"), kindPopup]
        ])
        top.rowSpacing = 9
        top.columnSpacing = 10
        top.column(at: 0).width = 64
        top.column(at: 0).xPlacement = .trailing
        top.column(at: 1).xPlacement = .fill
        top.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(top)

        let memberTitle = NSTextField(labelWithString: "策略成员")
        memberTitle.font = .systemFont(ofSize: 12.5, weight: .semibold)
        memberPopup.addItems(withTitles: availablePolicies.filter { $0 != originalName })
        let add = NSButton(title: "添加", target: self, action: #selector(addMember))
        let memberToolbar = NSStackView(views: [memberTitle, NSView(), memberPopup, add])
        memberToolbar.orientation = .horizontal
        memberToolbar.alignment = .centerY
        memberToolbar.spacing = 8
        memberToolbar.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(memberToolbar)

        table.dataSource = self
        table.delegate = self
        table.headerView = nil
        table.rowHeight = 28
        table.allowsMultipleSelection = true
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("member"))
        column.resizingMask = .autoresizingMask
        table.addTableColumn(column)
        let tableScroll = NSScrollView()
        tableScroll.hasVerticalScroller = true
        tableScroll.borderType = .bezelBorder
        tableScroll.documentView = table
        tableScroll.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(tableScroll)

        let remove = NSButton(title: "删除", target: self, action: #selector(removeMembers))
        let up = NSButton(title: "上移", target: self, action: #selector(moveMemberUp(_:)))
        let down = NSButton(title: "下移", target: self, action: #selector(moveMemberDown(_:)))
        let memberActions = NSStackView(views: [remove, up, down])
        memberActions.orientation = .horizontal
        memberActions.spacing = 7
        memberActions.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(memberActions)

        let optionsTitle = NSTextField(labelWithString: "策略组选项")
        optionsTitle.font = .systemFont(ofSize: 12.5, weight: .semibold)
        optionsTitle.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(optionsTitle)
        let optionsScroll = NSScrollView()
        optionsScroll.hasVerticalScroller = true
        optionsScroll.borderType = .bezelBorder
        optionsScroll.translatesAutoresizingMaskIntoConstraints = false
        optionsView.isRichText = false
        optionsView.isAutomaticQuoteSubstitutionEnabled = false
        optionsView.isAutomaticDashSubstitutionEnabled = false
        optionsView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        optionsView.textContainerInset = NSSize(width: 7, height: 6)
        optionsView.string = draft?.parameters.keys.sorted().map {
            "\($0)=\(draft!.parameters[$0]!)"
        }.joined(separator: "\n") ?? ""
        optionsScroll.documentView = optionsView
        root.addSubview(optionsScroll)

        let hint = NSTextField(wrappingLabelWithString:
            "每行 key=value。支持 hidden、include-all-proxies、url、interval、timeout、tolerance、algorithm 等 Surge 选项。")
        hint.font = .systemFont(ofSize: 9.5)
        hint.textColor = .secondaryLabelColor
        hint.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(hint)

        errorLabel.font = .systemFont(ofSize: 10.5, weight: .medium)
        errorLabel.textColor = .systemRed
        errorLabel.lineBreakMode = .byTruncatingTail
        errorLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(errorLabel)
        let cancel = NSButton(title: "取消", target: self, action: #selector(cancelPressed))
        let save = NSButton(title: isNew ? "添加并应用" : "完成",
                            target: self, action: #selector(savePressed))
        save.bezelStyle = .rounded
        save.keyEquivalent = "\r"
        let buttons = NSStackView(views: [cancel, save])
        buttons.orientation = .horizontal
        buttons.spacing = 9
        buttons.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(buttons)

        NSLayoutConstraint.activate([
            title.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            title.topAnchor.constraint(equalTo: root.topAnchor, constant: 20),
            top.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            top.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            top.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 16),
            memberToolbar.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            memberToolbar.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            memberToolbar.topAnchor.constraint(equalTo: top.bottomAnchor, constant: 18),
            memberPopup.widthAnchor.constraint(greaterThanOrEqualToConstant: 180),
            tableScroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            tableScroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            tableScroll.topAnchor.constraint(equalTo: memberToolbar.bottomAnchor, constant: 7),
            tableScroll.heightAnchor.constraint(equalToConstant: 150),
            memberActions.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            memberActions.topAnchor.constraint(equalTo: tableScroll.bottomAnchor, constant: 7),
            optionsTitle.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            optionsTitle.topAnchor.constraint(equalTo: memberActions.bottomAnchor, constant: 15),
            optionsScroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            optionsScroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            optionsScroll.topAnchor.constraint(equalTo: optionsTitle.bottomAnchor, constant: 7),
            optionsScroll.heightAnchor.constraint(equalToConstant: 88),
            hint.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 25),
            hint.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -25),
            hint.topAnchor.constraint(equalTo: optionsScroll.bottomAnchor, constant: 5),
            errorLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            errorLabel.trailingAnchor.constraint(lessThanOrEqualTo: buttons.leadingAnchor, constant: -10),
            errorLabel.centerYAnchor.constraint(equalTo: buttons.centerYAnchor),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16)
        ])
    }

    func numberOfRows(in tableView: NSTableView) -> Int { members.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard members.indices.contains(row) else { return nil }
        let value = NSTextField(labelWithString: members[row])
        value.font = .systemFont(ofSize: 11.5)
        value.lineBreakMode = .byTruncatingMiddle
        return value
    }

    @objc private func addMember() {
        guard let name = memberPopup.titleOfSelectedItem, !name.isEmpty,
              !members.contains(name) else { return }
        members.append(name)
        table.reloadData()
        table.selectRowIndexes([members.count - 1], byExtendingSelection: false)
        table.scrollRowToVisible(members.count - 1)
    }

    @objc private func removeMembers() {
        let indexes = table.selectedRowIndexes
        guard !indexes.isEmpty else { return }
        for index in indexes.sorted(by: >) where members.indices.contains(index) { members.remove(at: index) }
        table.reloadData()
    }

    @objc private func moveMemberUp(_ sender: Any?) {
        guard table.selectedRowIndexes.count == 1, let index = table.selectedRowIndexes.first,
              index > 0 else { return }
        members.swapAt(index, index - 1)
        table.reloadData()
        table.selectRowIndexes([index - 1], byExtendingSelection: false)
    }

    @objc private func moveMemberDown(_ sender: Any?) {
        guard table.selectedRowIndexes.count == 1, let index = table.selectedRowIndexes.first,
              index + 1 < members.count else { return }
        members.swapAt(index, index + 1)
        table.reloadData()
        table.selectRowIndexes([index + 1], byExtendingSelection: false)
    }

    private func parsedOptions() throws -> [String: String] {
        var result: [String: String] = [:]
        for (lineNumber, raw) in optionsView.string.components(separatedBy: .newlines).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            guard let equal = line.firstIndex(of: "=") else {
                throw EditorError("选项第 \(lineNumber + 1) 行缺少 =")
            }
            let key = line[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, result[key] == nil else { throw EditorError("选项 \(key) 重复或无效") }
            result[key] = value
        }
        return result
    }

    @objc private func savePressed() {
        do {
            let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if name != originalName, unavailableNames.contains(name) { throw EditorError("已经存在同名节点或策略组") }
            let rawKind = kindPopup.selectedItem?.representedObject as? String ?? PolicyGroupKind.select.rawValue
            let kind = PolicyGroupKind(rawValue: rawKind) ?? .select
            let draft = SurgePolicyGroupDraft(name: name, kind: kind,
                                              members: members, parameters: try parsedOptions())
            _ = try SurgeProfileDocument.definition(for: draft)
            try commit(draft)
            close(.OK)
        } catch { errorLabel.stringValue = error.localizedDescription }
    }

    @objc private func cancelPressed() { close(.cancel) }

    private func close(_ response: NSApplication.ModalResponse) {
        guard let window else { return }
        if let parent = window.sheetParent { parent.endSheet(window, returnCode: response) }
        else { window.close() }
    }

    private func label(_ text: String) -> NSTextField {
        let value = NSTextField(labelWithString: text)
        value.font = .systemFont(ofSize: 11, weight: .medium)
        value.textColor = .secondaryLabelColor
        return value
    }

    private struct EditorError: LocalizedError {
        let text: String
        init(_ text: String) { self.text = text }
        var errorDescription: String? { text }
    }
}

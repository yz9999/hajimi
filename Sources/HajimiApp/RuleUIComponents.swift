import AppKit
import HajimiCore

/// Edits one rule without serializing or replacing the rest of the profile.
/// The document layer is responsible for preserving ordering and comments.
final class RuleEditorSheetController: NSWindowController {
    private let commit: (SurgeRuleDraft) throws -> Void
    private let originalOptions: [String]
    private let typePopup = NSPopUpButton()
    private let valueField = NSTextField()
    private let policyCombo = NSComboBox()
    private let optionsView = NSTextView(frame: NSRect(x: 0, y: 0, width: 592, height: 100))
    private let helpLabel = NSTextField(wrappingLabelWithString: "")
    private let errorLabel = NSTextField(wrappingLabelWithString: "")
    private let saveButton = NSButton(title: "保存并应用", target: nil, action: nil)
    private var isCommitting = false

    init(draft: SurgeRuleDraft?, policyNames: [String],
         commit: @escaping (SurgeRuleDraft) throws -> Void) {
        self.commit = commit
        originalOptions = draft?.options ?? []
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 640, height: 500),
                            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = draft == nil ? "新增规则" : "编辑规则"
        panel.isReleasedWhenClosed = false
        super.init(window: panel)
        buildUI(draft: draft, policyNames: policyNames)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildUI(draft: SurgeRuleDraft?, policyNames: [String]) {
        guard let root = window?.contentView else { return }
        let heading = RuleSheetUI.heading(title: draft == nil ? "新增规则" : "编辑规则",
                                         subtitle: "保存到当前配置并应用，其他规则和注释保持不变")
        root.addSubview(heading)

        typePopup.target = self
        typePopup.action = #selector(typeChanged)
        typePopup.addItems(withTitles: SurgeRuleDraft.supportedTypes)
        let initialType = draft?.type.uppercased() ?? "DOMAIN-SUFFIX"
        // Preserve the selected type even if a newer profile contains a type
        // that this version cannot validate, instead of silently substituting it.
        if typePopup.item(withTitle: initialType) == nil {
            typePopup.addItem(withTitle: initialType)
        }
        typePopup.selectItem(withTitle: initialType)
        typePopup.setAccessibilityLabel("规则类型")

        valueField.stringValue = draft?.value ?? ""
        valueField.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        valueField.usesSingleLineMode = true
        valueField.cell?.isScrollable = true
        valueField.setAccessibilityLabel("匹配值或资源")
        RuleSheetUI.configurePolicyCombo(policyCombo, policyNames: policyNames,
                                         selected: draft?.policy ?? "DIRECT")

        let grid = NSGridView(views: [
            [RuleSheetUI.formLabel("规则类型"), typePopup],
            [RuleSheetUI.formLabel("匹配值 / 资源"), valueField],
            [RuleSheetUI.formLabel("策略"), policyCombo]
        ])
        grid.rowSpacing = 11
        grid.columnSpacing = 12
        grid.column(at: 0).width = 88
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(grid)

        helpLabel.font = .systemFont(ofSize: 10.5)
        helpLabel.textColor = .secondaryLabelColor
        helpLabel.maximumNumberOfLines = 3
        helpLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(helpLabel)

        let optionsTitle = NSTextField(labelWithString: "附加参数（可选）")
        optionsTitle.font = .systemFont(ofSize: 12, weight: .semibold)
        optionsTitle.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(optionsTitle)

        let optionsScroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 592, height: 100))
        optionsScroll.hasVerticalScroller = true
        optionsScroll.borderType = .bezelBorder
        optionsScroll.translatesAutoresizingMaskIntoConstraints = false
        optionsView.isRichText = false
        optionsView.isAutomaticQuoteSubstitutionEnabled = false
        optionsView.isAutomaticDashSubstitutionEnabled = false
        optionsView.isAutomaticTextReplacementEnabled = false
        optionsView.isContinuousSpellCheckingEnabled = false
        optionsView.isGrammarCheckingEnabled = false
        optionsView.isAutomaticSpellingCorrectionEnabled = false
        optionsView.allowsUndo = true
        optionsView.isVerticallyResizable = true
        optionsView.isHorizontallyResizable = false
        optionsView.autoresizingMask = [.width]
        optionsView.minSize = NSSize(width: 0, height: 100)
        optionsView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                    height: CGFloat.greatestFiniteMagnitude)
        optionsView.textContainer?.widthTracksTextView = true
        optionsView.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        optionsView.textContainerInset = NSSize(width: 8, height: 7)
        optionsView.string = originalOptions.joined(separator: "\n")
        optionsView.setAccessibilityLabel("附加参数，每行一个")
        optionsView.frame = NSRect(origin: .zero, size: optionsScroll.contentSize)
        optionsScroll.documentView = optionsView
        root.addSubview(optionsScroll)

        let optionsHint = NSTextField(wrappingLabelWithString:
            "每行一个参数，例如 no-resolve 或 update-interval=3600。原有参数及其顺序会保留；不需要重新输入整条规则。")
        optionsHint.font = .systemFont(ofSize: 10.5)
        optionsHint.textColor = .secondaryLabelColor
        optionsHint.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(optionsHint)

        RuleSheetUI.configureErrorLabel(errorLabel)
        root.addSubview(errorLabel)
        let cancel = NSButton(title: "取消", target: self, action: #selector(cancelPressed))
        cancel.bezelStyle = .rounded
        cancel.keyEquivalent = "\u{1b}"
        saveButton.target = self
        saveButton.action = #selector(savePressed)
        saveButton.bezelStyle = .rounded
        saveButton.keyEquivalent = "\r"
        let buttons = RuleSheetUI.buttonRow(cancel: cancel, save: saveButton)
        root.addSubview(buttons)

        NSLayoutConstraint.activate([
            heading.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            heading.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            heading.topAnchor.constraint(equalTo: root.topAnchor, constant: 22),
            grid.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            grid.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            grid.topAnchor.constraint(equalTo: heading.bottomAnchor, constant: 20),
            helpLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 25),
            helpLabel.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -25),
            helpLabel.topAnchor.constraint(equalTo: grid.bottomAnchor, constant: 10),
            helpLabel.heightAnchor.constraint(equalToConstant: 44),
            optionsTitle.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            optionsTitle.topAnchor.constraint(equalTo: helpLabel.bottomAnchor, constant: 14),
            optionsScroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            optionsScroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            optionsScroll.topAnchor.constraint(equalTo: optionsTitle.bottomAnchor, constant: 6),
            optionsScroll.heightAnchor.constraint(equalToConstant: 100),
            optionsHint.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 25),
            optionsHint.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -25),
            optionsHint.topAnchor.constraint(equalTo: optionsScroll.bottomAnchor, constant: 7),
            errorLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 25),
            errorLabel.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -25),
            errorLabel.topAnchor.constraint(equalTo: optionsHint.bottomAnchor, constant: 10),
            errorLabel.heightAnchor.constraint(equalToConstant: 46),
            errorLabel.bottomAnchor.constraint(lessThanOrEqualTo: buttons.topAnchor, constant: -10),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18)
        ])
        updateTypeHelp()
        window?.initialFirstResponder = valueField.isEnabled ? valueField : policyCombo
    }

    private var selectedType: String { typePopup.titleOfSelectedItem ?? "DOMAIN-SUFFIX" }

    private var hasMatchingValue: Bool { !["FINAL", "MATCH"].contains(selectedType.uppercased()) }

    @objc private func typeChanged() { updateTypeHelp() }

    private func updateTypeHelp() {
        // Do not clear the value when switching to a catch-all type: users may
        // switch back before saving, and must not lose their in-progress input.
        valueField.isEnabled = hasMatchingValue
        switch selectedType.uppercased() {
        case "FINAL", "MATCH":
            valueField.placeholderString = "此规则类型无需匹配值"
            helpLabel.stringValue = "兜底规则处理此前规则未匹配的流量。匹配值不会写入配置，建议将此类规则放在末尾。"
        case "DOMAIN":
            valueField.placeholderString = "例如：dl.google.com"
            helpLabel.stringValue = "匹配完整域名。只输入域名，不包含协议或路径；策略可选择 DIRECT、REJECT、节点或策略组。"
        case "DOMAIN-SUFFIX":
            valueField.placeholderString = "例如：example.com"
            helpLabel.stringValue = "匹配域名本身及所有子域名。策略可从列表选择，也可以输入当前配置中的策略名称。"
        case "DOMAIN-KEYWORD", "DOMAIN-WILDCARD":
            valueField.placeholderString = selectedType == "DOMAIN-WILDCARD" ? "例如：*.example.com" : "例如：google"
            helpLabel.stringValue = "关键词匹配包含该文字的域名；通配符匹配可使用 * 或 ?。规则按配置顺序依次判断。"
        case "IP-CIDR", "IP-CIDR6", "SRC-IP", "SRC-IP-CIDR", "SOURCE-IP-CIDR":
            valueField.placeholderString = selectedType == "IP-CIDR6" ? "例如：2001:db8::/32" : "例如：192.168.0.0/16"
            helpLabel.stringValue = "输入有效 IP 网段。若不希望解析域名，可在附加参数中添加 no-resolve。"
        case "RULE-SET", "RULESET", "DOMAIN-SET":
            valueField.placeholderString = "规则资源的 HTTPS 地址或本地路径"
            helpLabel.stringValue = "输入规则集资源。可在附加参数中保留 no-resolve、update-interval 等设置；更新规则集可使用规则页的更新操作。"
        case "AND", "OR", "NOT":
            valueField.placeholderString = "例如：((DOMAIN-SUFFIX,example.com),(DEST-PORT,443))"
            helpLabel.stringValue = "输入完整括号表达式，内部逗号会原样保留。这里只填写匹配表达式，最外层策略在下方单独选择。"
        case "GEOIP":
            valueField.placeholderString = "例如：CN"
            helpLabel.stringValue = "填写国家或地区代码，例如 CN。可在附加参数中添加 no-resolve。"
        case "PROCESS-NAME":
            valueField.placeholderString = "例如：Safari 或 /Applications/Safari.app/Contents/MacOS/Safari"
            helpLabel.stringValue = "按进程名称或可执行文件路径匹配，填写现有配置支持的值。"
        case "DST-PORT", "SRC-PORT", "SOURCE-PORT", "IN-PORT", "DEST-PORT":
            valueField.placeholderString = "例如：443 或 8000-9000"
            helpLabel.stringValue = "填写端口或端口范围（1…65535）。规则策略可选择 DIRECT、REJECT、节点或策略组。"
        case "PROTOCOL":
            valueField.placeholderString = "例如：TCP 或 UDP"
            helpLabel.stringValue = "按传输协议匹配，支持 TCP 或 UDP。规则按配置顺序依次判断。"
        case "IP-ASN":
            valueField.placeholderString = "例如：13335"
            helpLabel.stringValue = "填写自治系统编号，使用不带 AS 前缀的数字。可在附加参数中添加 no-resolve。"
        default:
            valueField.placeholderString = "填写此类型对应的匹配值"
            helpLabel.stringValue = "规则按配置顺序依次判断。只修改本条规则，其他配置和注释保持不变。"
        }
    }

    @objc private func savePressed() {
        guard !isCommitting else { return }
        isCommitting = true
        saveButton.isEnabled = false
        errorLabel.stringValue = ""
        errorLabel.toolTip = nil
        do {
            // Split options by lines, never by commas. Commas within quoted
            // option values and within logical expressions belong to the rule.
            let options: [String]
            if optionsView.string == originalOptions.joined(separator: "\n") {
                // Also preserve legacy empty fields and the original lexical
                // form when the options editor has not been changed.
                options = originalOptions
            } else {
                options = optionsView.string.components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
            }
            let draft = SurgeRuleDraft(type: selectedType,
                                       value: hasMatchingValue ? valueField.stringValue : "",
                                       policy: policyCombo.stringValue,
                                       options: options)
            _ = try SurgeProfileDocument.definition(for: draft)
            try commit(draft)
            RuleSheetUI.close(window, response: .OK)
        } catch {
            errorLabel.stringValue = error.localizedDescription
            errorLabel.toolTip = error.localizedDescription
            isCommitting = false
            saveButton.isEnabled = true
        }
    }

    @objc private func cancelPressed() { RuleSheetUI.close(window, response: .cancel) }
}

/// Applies one policy to multiple selected rules; all matching values,
/// additional options and comments remain the document layer's responsibility.
final class RulePolicySheetController: NSWindowController {
    private let commit: (String) throws -> Void
    private let policyCombo = NSComboBox()
    private let errorLabel = NSTextField(wrappingLabelWithString: "")
    private let saveButton = NSButton(title: "保存并应用", target: nil, action: nil)
    private var isCommitting = false

    init(count: Int, policyNames: [String], commit: @escaping (String) throws -> Void) {
        self.commit = commit
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 540, height: 250),
                            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "批量更新策略"
        panel.isReleasedWhenClosed = false
        super.init(window: panel)
        buildUI(count: count, policyNames: policyNames)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildUI(count: Int, policyNames: [String]) {
        guard let root = window?.contentView else { return }
        let heading = RuleSheetUI.heading(title: "批量更新策略",
                                         subtitle: "为选中的 \(count) 条规则设置同一策略")
        root.addSubview(heading)
        RuleSheetUI.configurePolicyCombo(policyCombo, policyNames: policyNames, selected: "DIRECT")
        let grid = NSGridView(views: [[RuleSheetUI.formLabel("目标策略"), policyCombo]])
        grid.columnSpacing = 12
        grid.column(at: 0).width = 70
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .fill
        grid.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(grid)

        let hint = NSTextField(wrappingLabelWithString:
            "仅更改策略；规则类型、匹配值、附加参数、顺序和注释保持不变。")
        hint.font = .systemFont(ofSize: 10.5)
        hint.textColor = .secondaryLabelColor
        hint.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(hint)
        RuleSheetUI.configureErrorLabel(errorLabel)
        root.addSubview(errorLabel)

        let cancel = NSButton(title: "取消", target: self, action: #selector(cancelPressed))
        cancel.bezelStyle = .rounded
        cancel.keyEquivalent = "\u{1b}"
        saveButton.target = self
        saveButton.action = #selector(savePressed)
        saveButton.bezelStyle = .rounded
        saveButton.keyEquivalent = "\r"
        let buttons = RuleSheetUI.buttonRow(cancel: cancel, save: saveButton)
        root.addSubview(buttons)
        NSLayoutConstraint.activate([
            heading.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            heading.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            heading.topAnchor.constraint(equalTo: root.topAnchor, constant: 22),
            grid.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            grid.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            grid.topAnchor.constraint(equalTo: heading.bottomAnchor, constant: 20),
            hint.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 25),
            hint.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -25),
            hint.topAnchor.constraint(equalTo: grid.bottomAnchor, constant: 12),
            errorLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 25),
            errorLabel.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -25),
            errorLabel.topAnchor.constraint(equalTo: hint.bottomAnchor, constant: 12),
            errorLabel.heightAnchor.constraint(equalToConstant: 42),
            errorLabel.bottomAnchor.constraint(lessThanOrEqualTo: buttons.topAnchor, constant: -10),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18)
        ])
        window?.initialFirstResponder = policyCombo
    }

    @objc private func savePressed() {
        guard !isCommitting else { return }
        isCommitting = true
        saveButton.isEnabled = false
        errorLabel.stringValue = ""
        errorLabel.toolTip = nil
        do {
            let policy = policyCombo.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            // Use the same escaping and validation as the individual editor.
            // The callback additionally checks that this policy exists.
            _ = try SurgeProfileDocument.definition(for: SurgeRuleDraft(type: "FINAL", value: "", policy: policy))
            try commit(policy)
            RuleSheetUI.close(window, response: .OK)
        } catch {
            errorLabel.stringValue = error.localizedDescription
            errorLabel.toolTip = error.localizedDescription
            isCommitting = false
            saveButton.isEnabled = true
        }
    }

    @objc private func cancelPressed() { RuleSheetUI.close(window, response: .cancel) }
}

private enum RuleSheetUI {
    static func heading(title: String, subtitle: String) -> NSStackView {
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 20, weight: .semibold)
        let subtitleLabel = NSTextField(wrappingLabelWithString: subtitle)
        subtitleLabel.font = .systemFont(ofSize: 11)
        subtitleLabel.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [titleLabel, subtitleLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }

    static func formLabel(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = .systemFont(ofSize: 11.5, weight: .medium)
        label.textColor = .secondaryLabelColor
        return label
    }

    static func configurePolicyCombo(_ combo: NSComboBox, policyNames: [String], selected: String) {
        var names: [String] = []
        var seen: Set<String> = []
        for name in ["DIRECT", "REJECT"] + policyNames + [selected] where !name.isEmpty {
            if seen.insert(name).inserted { names.append(name) }
        }
        combo.addItems(withObjectValues: names)
        combo.isEditable = true
        combo.completes = true
        combo.hasVerticalScroller = true
        combo.numberOfVisibleItems = 12
        combo.stringValue = selected
        combo.placeholderString = "DIRECT、REJECT、节点或策略组"
        combo.setAccessibilityLabel("策略")
        combo.setContentHuggingPriority(.defaultLow, for: .horizontal)
    }

    static func configureErrorLabel(_ label: NSTextField) {
        label.font = .systemFont(ofSize: 11, weight: .medium)
        label.textColor = .systemRed
        label.maximumNumberOfLines = 3
        label.lineBreakMode = .byTruncatingTail
        label.translatesAutoresizingMaskIntoConstraints = false
        label.setAccessibilityLabel("规则保存错误")
    }

    static func buttonRow(cancel: NSButton, save: NSButton) -> NSStackView {
        let stack = NSStackView(views: [cancel, save])
        stack.orientation = .horizontal
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }

    static func close(_ window: NSWindow?, response: NSApplication.ModalResponse) {
        guard let window else { return }
        if let parent = window.sheetParent {
            parent.endSheet(window, returnCode: response)
            window.orderOut(nil)
        } else {
            window.close()
        }
    }
}

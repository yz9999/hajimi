import AppKit
import Foundation
import UniformTypeIdentifiers
import HajimiUIComponents

/// 远程 URL 主题导入弹窗表单视图（支持单主题 JSON 与 50 款合集包 URL 导入）
private final class URLThemeImportFormView: NSView {
    let nameField = NSTextField()
    let urlField = NSTextField()
    let autoApplyCheckbox = NSButton(checkboxWithTitle: "导入后立即应用该主题", target: nil, action: nil)

    init(defaultName: String = "", defaultURL: String = "") {
        super.init(frame: NSRect(x: 0, y: 0, width: 410, height: 112))

        let nameLabel = NSTextField(labelWithString: "主题名称")
        nameLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
        nameLabel.frame = NSRect(x: 0, y: 84, width: 66, height: 18)

        nameField.frame = NSRect(x: 70, y: 81, width: 340, height: 22)
        nameField.placeholderString = "可选，留空则使用 JSON 内置名称（如：橘猫拍拍 / Linear 暗色）"
        nameField.stringValue = defaultName

        let urlLabel = NSTextField(labelWithString: "主题 URL")
        urlLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
        urlLabel.frame = NSRect(x: 0, y: 50, width: 66, height: 18)

        urlField.frame = NSRect(x: 70, y: 47, width: 340, height: 22)
        urlField.placeholderString = "https://example.com/themes/08-ginger-tabby.hajimitheme.json"
        urlField.stringValue = defaultURL

        autoApplyCheckbox.state = .on
        autoApplyCheckbox.frame = NSRect(x: 70, y: 20, width: 220, height: 20)

        let hintLabel = NSTextField(labelWithString: "支持单个 .hajimitheme.json 地址或包含 50 款主题的合集包 URL。")
        hintLabel.font = .systemFont(ofSize: 10.5)
        hintLabel.textColor = .tertiaryLabelColor
        hintLabel.frame = NSRect(x: 70, y: 2, width: 340, height: 16)

        [nameLabel, nameField, urlLabel, urlField, autoApplyCheckbox, hintLabel].forEach(addSubview)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }
}

extension MainWindowController {

    // MARK: - UI Theme Settings Integration (Settings Card + Subpage + URL & File Importer)

    func buildThemeSettings() {
        themeSettingsView.translatesAutoresizingMaskIntoConstraints = false
        themeSettingsView.isHidden = true
        settingsView.addSubview(themeSettingsView)
        NSLayoutConstraint.activate([
            themeSettingsView.leadingAnchor.constraint(equalTo: settingsView.leadingAnchor),
            themeSettingsView.trailingAnchor.constraint(equalTo: settingsView.trailingAnchor),
            themeSettingsView.topAnchor.constraint(equalTo: settingsView.topAnchor),
            themeSettingsView.bottomAnchor.constraint(equalTo: settingsView.bottomAnchor)
        ])

        installThemeOverviewCard()
        buildThemeSettingsSubpage()
        refreshThemeSettingsUI()

        NotificationCenter.default.addObserver(
            forName: HajimiThemeCenter.didChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            self.refreshThemeSettingsUI()
            self.nativeTrafficView.needsDisplay = true
            self.policyCollectionView.reloadData()
            self.rulesTableView.backgroundColor = HajimiAppearance.panel
            self.rulesTableView.reloadData()
            if self.isEngineActive || self.isEnhancedModeActive {
                self.statusLabel.textColor = HajimiAppearance.accentText
                self.sidebarStatusDot.fillColor = HajimiAppearance.accent
            }
            self.onStatusBarStateChanged?()
            AppTrafficTelemetryCenter.shared.onNeedsRefresh?()
        }
    }

    private func installThemeOverviewCard() {
        let themeCard = HajimiSurfaceView(fill: HajimiAppearance.panel, border: HajimiAppearance.border)
        themeCard.translatesAutoresizingMaskIntoConstraints = false

        let icon = HajimiAppearance.iconBadge(
            symbolName: "paintpalette.fill",
            tint: HajimiAppearance.accentText,
            background: HajimiAppearance.accentSubtle,
            size: 38,
            symbolSize: 17
        )
        let titleLabel = NSTextField(labelWithString: "UI 主题与外观")
        titleLabel.font = .systemFont(ofSize: 15, weight: .semibold)

        let detailLabel = NSTextField(wrappingLabelWithString:
            "内置 8 大美学系列共 50 款 UI 主题，支持通过本地文件 (.hajimitheme / .json) 或远程 URL 导入自定义主题配置。")
        detailLabel.font = .systemFont(ofSize: 11)
        detailLabel.textColor = .secondaryLabelColor

        themeOverviewSummaryLabel.font = .systemFont(ofSize: 11, weight: .medium)
        themeOverviewSummaryLabel.textColor = HajimiAppearance.accentText
        themeOverviewSummaryLabel.maximumNumberOfLines = 2
        themeOverviewSummaryLabel.lineBreakMode = .byTruncatingTail

        themeQuickSelectPopup.target = self
        themeQuickSelectPopup.action = #selector(themeQuickPopupChanged)
        themeQuickSelectPopup.controlSize = .small
        themeQuickSelectPopup.font = .systemFont(ofSize: 11.5)
        themeQuickSelectPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let importFileBtn = NSButton(title: "导入文件…", target: self, action: #selector(importThemeFileAction))
        importFileBtn.image = NSImage(systemSymbolName: "square.and.arrow.down", accessibilityDescription: nil)

        let importURLBtn = NSButton(title: "URL 导入…", target: self, action: #selector(importThemeURLAction))
        importURLBtn.image = NSImage(systemSymbolName: "link.badge.plus", accessibilityDescription: nil)

        let exportBtn = NSButton(title: "导出主题…", target: self, action: #selector(exportCurrentThemeAction))
        exportBtn.image = NSImage(systemSymbolName: "square.and.arrow.up", accessibilityDescription: nil)

        let openSubpageBtn = NSButton(title: "UI 主题设置…", target: self, action: #selector(openThemeSettings))
        openSubpageBtn.image = NSImage(systemSymbolName: "slider.horizontal.3", accessibilityDescription: nil)

        for button in [importFileBtn, importURLBtn, exportBtn, openSubpageBtn] {
            button.bezelStyle = .rounded
            button.controlSize = .small
            button.font = .systemFont(ofSize: 11.5, weight: .medium)
            button.imagePosition = .imageLeading
            button.setContentHuggingPriority(.required, for: .horizontal)
            button.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
        }

        let spacer = NSView()
        spacer.setContentHuggingPriority(.init(1), for: .horizontal)
        spacer.setContentCompressionResistancePriority(.init(1), for: .horizontal)

        let controlsRow = NSStackView(views: [
            themeQuickSelectPopup, spacer,
            importFileBtn, importURLBtn, exportBtn, openSubpageBtn
        ])
        controlsRow.orientation = .horizontal
        controlsRow.alignment = .centerY
        controlsRow.spacing = 6
        controlsRow.translatesAutoresizingMaskIntoConstraints = false

        let textStack = NSStackView(views: [titleLabel, detailLabel, themeOverviewSummaryLabel, controlsRow])
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 7
        textStack.translatesAutoresizingMaskIntoConstraints = false

        themeCard.addSubview(icon)
        themeCard.addSubview(textStack)

        NSLayoutConstraint.activate([
            themeCard.heightAnchor.constraint(equalToConstant: 152),
            icon.leadingAnchor.constraint(equalTo: themeCard.leadingAnchor, constant: 18),
            icon.topAnchor.constraint(equalTo: themeCard.topAnchor, constant: 20),
            textStack.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 14),
            textStack.trailingAnchor.constraint(equalTo: themeCard.trailingAnchor, constant: -20),
            textStack.centerYAnchor.constraint(equalTo: themeCard.centerYAnchor),
            detailLabel.widthAnchor.constraint(equalTo: textStack.widthAnchor),
            themeOverviewSummaryLabel.widthAnchor.constraint(equalTo: textStack.widthAnchor),
            controlsRow.widthAnchor.constraint(equalTo: textStack.widthAnchor),
            themeQuickSelectPopup.widthAnchor.constraint(greaterThanOrEqualToConstant: 140),
            themeQuickSelectPopup.widthAnchor.constraint(lessThanOrEqualToConstant: 260)
        ])

        // Insert themeCard into settingsOverviewView's stack (right after subscriptionCard)
        if let scroll = settingsOverviewView.subviews.compactMap({ $0 as? ScrollableSettingsContentView }).first,
           let cardsStack = scroll.content as? NSStackView {
            let insertIndex = min(1, cardsStack.arrangedSubviews.count)
            cardsStack.insertArrangedSubview(themeCard, at: insertIndex)
            themeCard.widthAnchor.constraint(equalTo: cardsStack.widthAnchor).isActive = true
        }
    }

    private func buildThemeSettingsSubpage() {
        let back = NSButton(title: "返回设置", target: self, action: #selector(closeThemeSettings))
        back.image = NSImage(systemSymbolName: "chevron.left", accessibilityDescription: nil)
        back.imagePosition = .imageLeading
        back.bezelStyle = .recessed
        back.isBordered = false
        back.translatesAutoresizingMaskIntoConstraints = false
        themeSettingsView.addSubview(back)

        let eyebrow = HajimiAppearance.pillBadge(text: "UI THEME & APPEARANCE", fontSize: 9.5)
        let titleLabel = NSTextField(labelWithString: "UI 主题设置")
        titleLabel.font = .systemFont(ofSize: 28, weight: .bold)
        let subtitleLabel = NSTextField(labelWithString: "切换 8 大系列 50 款预设主题，或通过本地文件与远程 URL 导入主题配置")
        subtitleLabel.font = .systemFont(ofSize: 12.5)
        subtitleLabel.textColor = .secondaryLabelColor
        let headerStack = NSStackView(views: [eyebrow, titleLabel, subtitleLabel])
        headerStack.orientation = .vertical
        headerStack.alignment = .leading
        headerStack.spacing = 6
        headerStack.translatesAutoresizingMaskIntoConstraints = false
        themeSettingsView.addSubview(headerStack)

        // Card 1: Category Filter, Theme Selector, Appearance Mode & Live Swatch Bar
        let selectorCard = HajimiSurfaceView(fill: HajimiAppearance.panel, border: HajimiAppearance.border)
        selectorCard.translatesAutoresizingMaskIntoConstraints = false

        let section1Title = NSTextField(labelWithString: "1. 主题方案选择与外观模式")
        section1Title.font = .systemFont(ofSize: 14.5, weight: .bold)
        section1Title.textColor = HajimiAppearance.accentText

        let catLabel = NSTextField(labelWithString: "美学系列：")
        catLabel.font = .systemFont(ofSize: 12, weight: .medium)
        themeCategoryPopup.target = self
        themeCategoryPopup.action = #selector(themeCategoryChanged)
        themeCategoryPopup.font = .systemFont(ofSize: 12)

        let themeLabel = NSTextField(labelWithString: "当前主题：")
        themeLabel.font = .systemFont(ofSize: 12, weight: .medium)
        themeDetailSelectPopup.target = self
        themeDetailSelectPopup.action = #selector(themeDetailPopupChanged)
        themeDetailSelectPopup.font = .systemFont(ofSize: 12, weight: .medium)

        let modeLabel = NSTextField(labelWithString: "明暗外观：")
        modeLabel.font = .systemFont(ofSize: 12, weight: .medium)
        themeAppearanceModePopup.removeAllItems()
        themeAppearanceModePopup.addItems(withTitles: [
            "跟随主题默认设定",
            "强制暗色模式 (Dark)",
            "强制亮色模式 (Light)",
            "跟随 macOS 系统外观"
        ])
        themeAppearanceModePopup.target = self
        themeAppearanceModePopup.action = #selector(themeAppearanceModeChanged)
        themeAppearanceModePopup.font = .systemFont(ofSize: 12)

        let resetBtn = NSButton(title: "恢复默认翡翠主题 (#01)", target: self, action: #selector(resetDefaultThemeAction))
        resetBtn.bezelStyle = .rounded
        resetBtn.controlSize = .small
        resetBtn.font = .systemFont(ofSize: 11.5, weight: .medium)

        let row1 = NSStackView(views: [catLabel, themeCategoryPopup, themeLabel, themeDetailSelectPopup, NSView(), resetBtn])
        row1.orientation = .horizontal
        row1.alignment = .centerY
        row1.spacing = 10

        let row2 = NSStackView(views: [modeLabel, themeAppearanceModePopup, NSView()])
        row2.orientation = .horizontal
        row2.alignment = .centerY
        row2.spacing = 10

        themeInspectorDetailLabel.font = .systemFont(ofSize: 11.5)
        themeInspectorDetailLabel.textColor = .secondaryLabelColor
        themeInspectorDetailLabel.maximumNumberOfLines = 3

        themeSwatchStack.orientation = .horizontal
        themeSwatchStack.alignment = .centerY
        themeSwatchStack.spacing = 8
        themeSwatchStack.translatesAutoresizingMaskIntoConstraints = false

        let selectorStack = NSStackView(views: [section1Title, row1, row2, themeInspectorDetailLabel, themeSwatchStack])
        selectorStack.orientation = .vertical
        selectorStack.alignment = .leading
        selectorStack.spacing = 12
        selectorStack.translatesAutoresizingMaskIntoConstraints = false
        selectorCard.addSubview(selectorStack)

        // Card 2: File Import, URL Import, Refresh & Export
        let importCard = HajimiSurfaceView(fill: HajimiAppearance.panel, border: HajimiAppearance.border)
        importCard.translatesAutoresizingMaskIntoConstraints = false

        let section2Title = NSTextField(labelWithString: "2. 主题导入与导出（支持 URL 远程导入 & 本地文件导入）")
        section2Title.font = .systemFont(ofSize: 14.5, weight: .bold)
        section2Title.textColor = HajimiAppearance.accentText

        let section2Desc = NSTextField(wrappingLabelWithString:
            "支持导入单个主题文件（.hajimitheme / .json）或包含多款主题的合集包。通过 URL 导入的主题会自动记录远程源地址，方便随时一键拉取更新。")
        section2Desc.font = .systemFont(ofSize: 11.5)
        section2Desc.textColor = .secondaryLabelColor

        let btnImportFile = NSButton(title: "本地文件导入…", target: self, action: #selector(importThemeFileAction))
        btnImportFile.image = NSImage(systemSymbolName: "doc.badge.plus", accessibilityDescription: nil)

        let btnImportURL = NSButton(title: "URL 远程导入…", target: self, action: #selector(importThemeURLAction))
        btnImportURL.image = NSImage(systemSymbolName: "link.badge.plus", accessibilityDescription: nil)

        let btnRefreshURL = NSButton(title: "更新当前 URL 主题", target: self, action: #selector(refreshCurrentURLThemeAction))
        btnRefreshURL.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)

        let btnExportSingle = NSButton(title: "导出当前主题 (.json)…", target: self, action: #selector(exportCurrentThemeAction))
        btnExportSingle.image = NSImage(systemSymbolName: "square.and.arrow.up", accessibilityDescription: nil)

        let btnExportAll = NSButton(title: "导出全部 50 款主题包…", target: self, action: #selector(exportAllThemesPackAction))
        btnExportAll.image = NSImage(systemSymbolName: "archivebox", accessibilityDescription: nil)

        let btnDeleteCustom = NSButton(title: "删除自定义主题", target: self, action: #selector(deleteSelectedCustomThemeAction))
        btnDeleteCustom.image = NSImage(systemSymbolName: "trash", accessibilityDescription: nil)
        btnDeleteCustom.contentTintColor = .systemRed

        for btn in [btnImportFile, btnImportURL, btnRefreshURL, btnExportSingle, btnExportAll, btnDeleteCustom] {
            btn.bezelStyle = .rounded
            btn.font = .systemFont(ofSize: 12, weight: .medium)
            btn.imagePosition = .imageLeading
        }

        let importBtnRow = NSStackView(views: [
            btnImportFile, btnImportURL, btnRefreshURL,
            btnExportSingle, btnExportAll, btnDeleteCustom, NSView()
        ])
        importBtnRow.orientation = .horizontal
        importBtnRow.alignment = .centerY
        importBtnRow.spacing = 8

        themeImportStatusLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
        themeImportStatusLabel.textColor = .secondaryLabelColor
        themeImportStatusLabel.stringValue = "就绪 · 已加载 \(HajimiThemeCenter.builtInThemes.count) 款内置主题与 \(HajimiThemeCenter.shared.importedThemes.count) 款外部导入主题"

        let importStack = NSStackView(views: [section2Title, section2Desc, importBtnRow, themeImportStatusLabel])
        importStack.orientation = .vertical
        importStack.alignment = .leading
        importStack.spacing = 10
        importStack.translatesAutoresizingMaskIntoConstraints = false
        importCard.addSubview(importStack)

        let bodyStack = NSStackView(views: [selectorCard, importCard])
        bodyStack.orientation = .vertical
        bodyStack.alignment = .leading
        bodyStack.spacing = 16

        let scroll = ScrollableSettingsContentView(content: bodyStack)
        scroll.translatesAutoresizingMaskIntoConstraints = false
        themeSettingsView.addSubview(scroll)

        NSLayoutConstraint.activate([
            back.leadingAnchor.constraint(equalTo: themeSettingsView.leadingAnchor, constant: 28),
            back.topAnchor.constraint(equalTo: themeSettingsView.topAnchor, constant: 26),
            headerStack.leadingAnchor.constraint(equalTo: themeSettingsView.leadingAnchor, constant: 30),
            headerStack.trailingAnchor.constraint(equalTo: themeSettingsView.trailingAnchor, constant: -30),
            headerStack.topAnchor.constraint(equalTo: back.bottomAnchor, constant: 13),
            scroll.leadingAnchor.constraint(equalTo: themeSettingsView.leadingAnchor, constant: 30),
            scroll.trailingAnchor.constraint(equalTo: themeSettingsView.trailingAnchor, constant: -30),
            scroll.topAnchor.constraint(equalTo: headerStack.bottomAnchor, constant: 20),
            scroll.bottomAnchor.constraint(equalTo: themeSettingsView.bottomAnchor, constant: -20),
            selectorCard.widthAnchor.constraint(equalTo: bodyStack.widthAnchor),
            importCard.widthAnchor.constraint(equalTo: bodyStack.widthAnchor),
            selectorStack.leadingAnchor.constraint(equalTo: selectorCard.leadingAnchor, constant: 20),
            selectorStack.trailingAnchor.constraint(equalTo: selectorCard.trailingAnchor, constant: -20),
            selectorStack.topAnchor.constraint(equalTo: selectorCard.topAnchor, constant: 18),
            selectorStack.bottomAnchor.constraint(equalTo: selectorCard.bottomAnchor, constant: -18),
            row1.widthAnchor.constraint(equalTo: selectorStack.widthAnchor),
            row2.widthAnchor.constraint(equalTo: selectorStack.widthAnchor),
            themeInspectorDetailLabel.widthAnchor.constraint(equalTo: selectorStack.widthAnchor),
            importStack.leadingAnchor.constraint(equalTo: importCard.leadingAnchor, constant: 20),
            importStack.trailingAnchor.constraint(equalTo: importCard.trailingAnchor, constant: -20),
            importStack.topAnchor.constraint(equalTo: importCard.topAnchor, constant: 18),
            importStack.bottomAnchor.constraint(equalTo: importCard.bottomAnchor, constant: -18),
            section2Desc.widthAnchor.constraint(equalTo: importStack.widthAnchor),
            importBtnRow.widthAnchor.constraint(equalTo: importStack.widthAnchor)
        ])
    }

    func refreshThemeSettingsUI() {
        let center = HajimiThemeCenter.shared
        let all = center.allThemes
        let current = center.currentTheme

        // Overview Card Popup
        themeQuickSelectPopup.removeAllItems()
        for item in all {
            themeQuickSelectPopup.addItem(withTitle: "\(item.code) \(item.name)")
            themeQuickSelectPopup.lastItem?.representedObject = item.id
            if item.id == current.id {
                themeQuickSelectPopup.select(themeQuickSelectPopup.lastItem)
            }
        }

        let sourceTag = current.isBuiltIn ? "官方内置" : (current.sourceURL != nil ? "URL 远程导入" : "本地文件导入")
        themeOverviewSummaryLabel.stringValue = "✓ 当前主题：\(current.code) \(current.name) · \(current.category) · \(current.layoutStyle) · 圆角 \(Int(current.cardCornerRadius))pt (\(sourceTag))"
        themeOverviewSummaryLabel.toolTip = current.description

        // Category Popup
        let selectedCat = themeCategoryPopup.titleOfSelectedItem ?? "全部主题"
        themeCategoryPopup.removeAllItems()
        themeCategoryPopup.addItems(withTitles: center.categories)
        if center.categories.contains(selectedCat) {
            themeCategoryPopup.selectItem(withTitle: selectedCat)
        } else {
            themeCategoryPopup.selectItem(at: 0)
        }

        // Filtered Detail Popup
        let activeCat = themeCategoryPopup.titleOfSelectedItem ?? "全部主题"
        let filtered = activeCat == "全部主题" ? all : all.filter { $0.category == activeCat }
        themeDetailSelectPopup.removeAllItems()
        for item in filtered {
            themeDetailSelectPopup.addItem(withTitle: "\(item.code) \(item.name) — \(item.category)")
            themeDetailSelectPopup.lastItem?.representedObject = item.id
            if item.id == current.id {
                themeDetailSelectPopup.select(themeDetailSelectPopup.lastItem)
            }
        }

        let urlNotice = current.sourceURL.map { " · 源 URL: \($0)" } ?? ""
        themeInspectorDetailLabel.stringValue = "设计亮点：\(current.featureSummary)\n说明：\(current.description)（推荐布局：\(current.layoutStyle) · 默认外观：\(current.appearanceMode.uppercased()) · 卡片圆角：\(Int(current.cardCornerRadius))pt\(urlNotice)）"

        // Rebuild Swatch Row
        themeSwatchStack.views.forEach { $0.removeFromSuperview() }
        let swatches: [(String, String)] = [
            ("背景 Workspace", current.workspaceHex),
            ("侧栏 Sidebar", current.sidebarHex),
            ("卡片 Panel", current.panelHex),
            ("高亮 Elevated", current.elevatedPanelHex),
            ("主色 Accent", current.accentHex),
            ("上行 Upload", current.uploadAccentHex),
            ("靛紫 Indigo", current.indigoAccentHex)
        ]
        for (label, hex) in swatches {
            let chip = HajimiSurfaceView(
                fill: HajimiUITheme.color(fromHex: hex),
                border: NSColor.labelColor.withAlphaComponent(0.22),
                cornerRadius: 6
            )
            chip.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                chip.widthAnchor.constraint(equalToConstant: 22),
                chip.heightAnchor.constraint(equalToConstant: 22)
            ])
            let text = NSTextField(labelWithString: "\(label) \(hex)")
            text.font = .monospacedSystemFont(ofSize: 10.5, weight: .medium)
            text.textColor = .secondaryLabelColor
            let pair = NSStackView(views: [chip, text])
            pair.orientation = .horizontal
            pair.alignment = .centerY
            pair.spacing = 5
            themeSwatchStack.addArrangedSubview(pair)
        }
    }

    // MARK: - Actions

    func revealThemeSettingsFromStatusItem() {
        revealFromStatusItem()
        selectPage(4)
        openThemeSettings()
    }

    @objc func openThemeSettings() {
        refreshThemeSettingsUI()
        settingsOverviewView.isHidden = true
        dnsSettingsView.isHidden = true
        themeSettingsView.isHidden = false
    }

    @objc func closeThemeSettings() {
        themeSettingsView.isHidden = true
        settingsOverviewView.isHidden = false
        refreshThemeSettingsUI()
    }

    @objc func themeQuickPopupChanged() {
        guard let id = themeQuickSelectPopup.selectedItem?.representedObject as? String else { return }
        HajimiThemeCenter.shared.selectTheme(id: id)
    }

    @objc func themeCategoryChanged() {
        refreshThemeSettingsUI()
        if let firstID = themeDetailSelectPopup.itemArray.first?.representedObject as? String {
            HajimiThemeCenter.shared.selectTheme(id: firstID)
        }
    }

    @objc func themeDetailPopupChanged() {
        guard let id = themeDetailSelectPopup.selectedItem?.representedObject as? String else { return }
        HajimiThemeCenter.shared.selectTheme(id: id)
    }

    @objc func themeAppearanceModeChanged() {
        let idx = themeAppearanceModePopup.indexOfSelectedItem
        switch idx {
        case 1: HajimiThemeCenter.shared.appearanceOverride = "dark"
        case 2: HajimiThemeCenter.shared.appearanceOverride = "light"
        case 3: HajimiThemeCenter.shared.appearanceOverride = "system"
        default: HajimiThemeCenter.shared.appearanceOverride = "theme"
        }
    }

    @objc func resetDefaultThemeAction() {
        HajimiThemeCenter.shared.resetToDefaultTheme()
        themeAppearanceModePopup.selectItem(at: 0)
        themeImportStatusLabel.stringValue = "✓ 已恢复为 #01 翡翠原石 · 现版精修默认主题"
        themeImportStatusLabel.textColor = .systemGreen
    }

    @objc func importThemeFileAction() {
        let panel = NSOpenPanel()
        panel.title = "导入哈基米 UI 主题配置文件 (.hajimitheme / .json)"
        panel.prompt = "导入并应用"
        panel.allowsOtherFileTypes = true
        panel.allowedContentTypes = ["json", "hajimitheme", "txt"]
            .compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        guard let window else { return }
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK, !panel.urls.isEmpty, let self else { return }
            var totalImported: [HajimiUITheme] = []
            for fileURL in panel.urls {
                do {
                    let items = try HajimiThemeCenter.shared.importFromFile(url: fileURL, autoApply: true)
                    totalImported.append(contentsOf: items)
                } catch {
                    self.themeImportStatusLabel.stringValue = "✕ 导入失败：\(error.localizedDescription)"
                    self.themeImportStatusLabel.textColor = .systemRed
                    self.showError(title: "导入 UI 主题文件失败", error: error)
                    return
                }
            }
            if let first = totalImported.first {
                self.themeCategoryPopup.selectItem(at: 0)
                self.refreshThemeSettingsUI()
                self.themeImportStatusLabel.stringValue = "✓ 已从本地文件成功导入 \(totalImported.count) 款主题，当前已切换至“\(first.displayTitle)”"
                self.themeImportStatusLabel.textColor = .systemGreen
            }
        }
    }

    @objc func importThemeURLAction() {
        let alert = NSAlert()
        alert.messageText = "通过 URL 导入 UI 主题配置"
        alert.informativeText = "支持输入单个主题 JSON (.hajimitheme.json) 的 HTTP/HTTPS 链接，或包含 50 款主题的全套主题合集包 URL。"
        alert.addButton(withTitle: "下载并导入")
        alert.addButton(withTitle: "从本地文件导入…")
        alert.addButton(withTitle: "取消")

        let form = URLThemeImportFormView()
        alert.accessoryView = form
        alert.window.initialFirstResponder = form.urlField

        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard let self else { return }
            if response == .alertSecondButtonReturn {
                self.importThemeFileAction()
                return
            }
            guard response == .alertFirstButtonReturn else { return }
            let urlString = form.urlField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let customName = form.nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let autoApply = form.autoApplyCheckbox.state == .on

            self.themeImportStatusLabel.stringValue = "正在从远程 URL 下载主题配置：\(urlString)…"
            self.themeImportStatusLabel.textColor = .systemBlue

            HajimiThemeCenter.shared.importFromURL(
                urlString: urlString,
                customName: customName.isEmpty ? nil : customName,
                autoApply: autoApply
            ) { [weak self] result in
                guard let self else { return }
                switch result {
                case .success(let imported):
                    self.themeCategoryPopup.selectItem(at: 0)
                    self.refreshThemeSettingsUI()
                    let firstTitle = imported.first?.displayTitle ?? "新主题"
                    self.themeImportStatusLabel.stringValue = "✓ 已通过 URL 成功导入 \(imported.count) 款主题（\(firstTitle)）"
                    self.themeImportStatusLabel.textColor = .systemGreen
                case .failure(let error):
                    self.themeImportStatusLabel.stringValue = "✕ URL 主题导入失败：\(error.localizedDescription)"
                    self.themeImportStatusLabel.textColor = .systemRed
                    self.showError(title: "URL 主题导入失败", error: error)
                }
            }
        }
    }

    @objc func refreshCurrentURLThemeAction() {
        let current = HajimiThemeCenter.shared.currentTheme
        guard let url = current.sourceURL, !url.isEmpty else {
            showMessage(
                title: "当前主题不是 URL 导入主题",
                text: "仅通过“URL 远程导入”添加的主题支持从源 URL 刷新。如需添加新远程主题，请点击“URL 远程导入…”。"
            )
            return
        }
        themeImportStatusLabel.stringValue = "正在从 \(url) 刷新主题“\(current.name)”…"
        themeImportStatusLabel.textColor = .systemBlue
        HajimiThemeCenter.shared.importFromURL(urlString: url, customName: current.name, autoApply: true) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let list):
                self.refreshThemeSettingsUI()
                self.themeImportStatusLabel.stringValue = "✓ 已成功从 URL 更新 \(list.count) 款主题"
                self.themeImportStatusLabel.textColor = .systemGreen
            case .failure(let error):
                self.themeImportStatusLabel.stringValue = "✕ 刷新失败：\(error.localizedDescription)"
                self.themeImportStatusLabel.textColor = .systemRed
            }
        }
    }

    @objc func exportCurrentThemeAction() {
        let current = HajimiThemeCenter.shared.currentTheme
        let panel = NSSavePanel()
        panel.title = "导出当前 UI 主题配置"
        let safeCode = current.code.replacingOccurrences(of: "#", with: "")
        panel.nameFieldStringValue = "hajimi-theme-\(safeCode)-\(current.name).hajimitheme.json"
        panel.canCreateDirectories = true
        guard let window else { return }
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK, let url = panel.url, let self else { return }
            do {
                try HajimiThemeCenter.shared.exportTheme(current, to: url)
                self.themeImportStatusLabel.stringValue = "✓ 已导出主题到：\(url.lastPathComponent)"
                self.themeImportStatusLabel.textColor = .systemGreen
            } catch {
                self.showError(title: "导出主题失败", error: error)
            }
        }
    }

    @objc func exportAllThemesPackAction() {
        let panel = NSSavePanel()
        panel.title = "导出全部 50 款哈基米 UI 主题合集包"
        panel.nameFieldStringValue = "hajimi-all-50-themes-pack.hajimitheme.json"
        panel.canCreateDirectories = true
        guard let window else { return }
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK, let url = panel.url, let self else { return }
            do {
                try HajimiThemeCenter.shared.exportAllThemesPack(to: url)
                self.themeImportStatusLabel.stringValue = "✓ 已导出全套 \(HajimiThemeCenter.shared.allThemes.count) 款主题合集包：\(url.lastPathComponent)"
                self.themeImportStatusLabel.textColor = .systemGreen
            } catch {
                self.showError(title: "导出主题合集包失败", error: error)
            }
        }
    }

    @objc func deleteSelectedCustomThemeAction() {
        let current = HajimiThemeCenter.shared.currentTheme
        guard !current.isBuiltIn else {
            showMessage(title: "内置预设主题不可删除", text: "50 款官方内置主题为只读预设；您导入的自定义主题可通过此按钮移除。")
            return
        }
        do {
            try HajimiThemeCenter.shared.removeCustomTheme(id: current.id)
            refreshThemeSettingsUI()
            themeImportStatusLabel.stringValue = "✓ 已删除自定义主题“\(current.name)”"
            themeImportStatusLabel.textColor = .secondaryLabelColor
        } catch {
            showError(title: "删除自定义主题失败", error: error)
        }
    }
}

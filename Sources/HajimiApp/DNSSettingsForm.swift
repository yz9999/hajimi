import AppKit
import HajimiCore
import HajimiUIComponents

/// Raw text is part of the draft: an asynchronous Save must not erase edits
/// made in any DNS list/toggle while that earlier snapshot was being applied.
struct DNSSettingsDraft: Equatable {
    var encryptedText: String
    var traditionalText: String
    var protectionEnabled: Bool
    var proxyFallbackEnabled: Bool
    var proxyFallbackText: String
    var selectionMode: DNSSelectionMode
    var prewarmEnabled: Bool

    init(encryptedText: String, traditionalText: String, protectionEnabled: Bool,
         proxyFallbackEnabled: Bool = false, proxyFallbackText: String = "",
         selectionMode: DNSSelectionMode = .balanced, prewarmEnabled: Bool = true) {
        self.encryptedText = encryptedText
        self.traditionalText = traditionalText
        self.protectionEnabled = protectionEnabled
        self.proxyFallbackEnabled = proxyFallbackEnabled
        self.proxyFallbackText = proxyFallbackText
        self.selectionMode = selectionMode
        self.prewarmEnabled = prewarmEnabled
    }

    init(profile: Profile) {
        encryptedText = profile.configuredEncryptedDNSServers.joined(separator: "\n")
        traditionalText = profile.traditionalDNSServers.joined(separator: "\n")
        protectionEnabled = profile.dnsLeakProtectionEnabled
        proxyFallbackEnabled = profile.dnsProxyFallbackEnabled
        proxyFallbackText = profile.dnsProxyFallbackServers.joined(separator: "\n")
        selectionMode = profile.dnsSelectionMode
        prewarmEnabled = profile.dnsPrewarmEnabled
    }

    // A comma is a legal URL character, so encrypted entries are separated
    // by lines only. Traditional IP entries also accept comma shorthand.
    var encryptedServers: [String] { Self.servers(in: encryptedText, separators: .newlines) }
    var traditionalServers: [String] {
        Self.servers(in: traditionalText, separators: CharacterSet(charactersIn: ",\n\r"))
    }
    var proxyFallbackServers: [String] {
        Self.servers(in: proxyFallbackText, separators: CharacterSet(charactersIn: ",\n\r"))
    }

    func applying(to text: String) throws -> String {
        var fallback = Profile()
        fallback.dnsProxyFallbackEnabled = proxyFallbackEnabled
        fallback.dnsProxyFallbackServers = proxyFallbackServers
        fallback.dnsSelectionMode = selectionMode
        fallback.dnsPrewarmEnabled = prewarmEnabled
        try fallback.validateDNSProxyFallbackSettings()
        var document = SurgeProfileDocument(text)
        try document.setGeneralOption("encrypted-dns-server",
                                      value: Self.configurationValue(encryptedServers))
        try document.setGeneralOption("dns-server",
                                      value: Self.configurationValue(traditionalServers))
        try document.setGeneralOption("dns-leak-protection", value: protectionEnabled ? "true" : "false")
        try document.setGeneralOption("dns-selection-mode", value: selectionMode.rawValue)
        try document.setGeneralOption("dns-prewarm", value: prewarmEnabled ? "true" : "false")
        try document.setGeneralOption("dns-proxy-fallback", value: proxyFallbackEnabled ? "true" : "false")
        // Turning the toggle off retains the user's independent approval
        // list and raw draft; explicitly clearing this editor removes it.
        try document.setGeneralOption("dns-proxy-fallback-server",
                                      value: Self.configurationValue(proxyFallbackServers))
        return document.text
    }

    private static func servers(in text: String, separators: CharacterSet) -> [String] {
        var seen = Set<String>()
        return text.components(separatedBy: separators)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    private static func configurationValue(_ servers: [String]) -> String? {
        guard !servers.isEmpty else { return nil }
        return servers.map { value in
            guard value.contains(where: { $0 == "," || $0 == "\"" || $0 == "'" || $0 == "\\" || $0.isWhitespace }) else {
                return value
            }
            let escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
            return "\"" + escaped + "\""
        }.joined(separator: ", ")
    }
}

/// A standalone, offscreen-testable form. Creating or editing it never starts
/// a resolver, changes a profile, or touches system networking.
final class DNSSettingsFormView: NSView {
    let protectionButton = NSButton(checkboxWithTitle: "DNS 防泄漏保护（推荐）", target: nil, action: nil)
    let selectionModePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let prewarmButton = NSButton(checkboxWithTitle: "预热 DNS 连接（推荐）", target: nil, action: nil)
    let encryptedServersTextView = NSTextView()
    let traditionalServersTextView = NSTextView()
    let proxyFallbackButton = NSButton(checkboxWithTitle: "允许失败后备（默认关闭）", target: nil, action: nil)
    let proxyFallbackServersTextView = NSTextView()
    let connectivityButton = NSButton(title: "测试传统 DNS 连通性", target: nil, action: nil)
    let defaultEncryptedButton = NSButton(title: "填入默认加密 DNS", target: nil, action: nil)
    /// Changes are drafts until Save. The controller can show status without
    /// taking over the controls' local explanatory-text actions.
    var onBehaviorChange: (() -> Void)?
    private let modeDescriptionLabel = NSTextField(wrappingLabelWithString: "")
    private let fallbackDescriptionLabel = NSTextField(wrappingLabelWithString: "")

    var draft: DNSSettingsDraft {
        DNSSettingsDraft(encryptedText: encryptedServersTextView.string,
                         traditionalText: traditionalServersTextView.string,
                         protectionEnabled: protectionButton.state == .on,
                         proxyFallbackEnabled: proxyFallbackButton.state == .on,
                         proxyFallbackText: proxyFallbackServersTextView.string,
                         selectionMode: selectedMode,
                         prewarmEnabled: prewarmButton.state == .on)
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        buildForm()
    }

    convenience init() { self.init(frame: .zero) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        refreshEditorAppearance()
    }

    func load(_ draft: DNSSettingsDraft) {
        encryptedServersTextView.string = draft.encryptedText
        traditionalServersTextView.string = draft.traditionalText
        protectionButton.state = draft.protectionEnabled ? .on : .off
        proxyFallbackButton.state = draft.proxyFallbackEnabled ? .on : .off
        proxyFallbackServersTextView.string = draft.proxyFallbackText
        selectionModePopup.selectItem(at: DNSSelectionMode.allCases.firstIndex(of: draft.selectionMode) ?? 1)
        prewarmButton.state = draft.prewarmEnabled ? .on : .off
        refreshBehaviorExplanation()
    }

    override func layout() {
        super.layout()
        for textView in [encryptedServersTextView, traditionalServersTextView, proxyFallbackServersTextView] {
            guard let scroll = textView.enclosingScrollView else { continue }
            scroll.layoutSubtreeIfNeeded()
            let viewport = scroll.contentView.bounds.size
            if abs(textView.frame.width - viewport.width) > 0.5 || textView.frame.height < viewport.height {
                textView.setFrameSize(NSSize(width: viewport.width, height: max(textView.frame.height, viewport.height)))
            }
        }
    }

    private func buildForm() {
        let title = label("智能选择与解析器", font: .systemFont(ofSize: 15.5, weight: .bold))
        let modeTitle = label("解析方案", font: .systemFont(ofSize: 12, weight: .semibold))
        modeTitle.textColor = .secondaryLabelColor
        let modeTitles = ["A · 仅用加密", "B · 稳定均衡（推荐）", "C · 速度优先（普通 + 加密）"]
        for (index, mode) in DNSSelectionMode.allCases.enumerated() {
            selectionModePopup.addItem(withTitle: modeTitles[index])
            selectionModePopup.lastItem?.representedObject = mode.rawValue
        }
        selectionModePopup.selectItem(at: 1)
        selectionModePopup.target = self
        selectionModePopup.action = #selector(behaviorChanged)
        selectionModePopup.font = .systemFont(ofSize: 12, weight: .medium)
        selectionModePopup.toolTip = "选择方案后点击保存并应用。速度优先会授权独立批准的普通 DNS 参与日常择优；不会自动使用传统 DNS 栏或改为本机直连。"
        prewarmButton.state = .on
        prewarmButton.target = self
        prewarmButton.action = #selector(behaviorChanged)
        prewarmButton.toolTip = "默认开启。预先建立可复用连接，不发送应用查询；必要时仅解析已配置 DoH 的端点域名。关闭后按需建立连接，保存并应用后生效。"
        let prewarmNote = note("不发送应用查询；必要时仅解析已配置 DoH 的端点域名。")
        configureNote(modeDescriptionLabel)
        configureNote(fallbackDescriptionLabel)
        let encryptedTitle = label("加密 DNS（DoH / DoT）", font: .systemFont(ofSize: 12.5, weight: .semibold))
        let encryptedNote = note("每行一个 HTTPS 或 tls:// 地址。加密 DNS 根据所选方案参与择优；未填写时，A / C 使用默认加密 DNS。")
        let traditionalTitle = label("传统 DNS（IP / IP:端口）", font: .systemFont(ofSize: 12.5, weight: .semibold))
        let traditionalNote = note("用于解析 DoH 服务器域名与连通性测试；不会自动加入下方普通 DNS 的独立批准名单。")
        let encryptedScroll = editor(encryptedServersTextView, height: 92)
        let traditionalScroll = editor(traditionalServersTextView, height: 76)
        let fallbackTitle = label("普通 DNS 独立批准名单（IP / IP:端口）", font: .systemFont(ofSize: 12.5, weight: .semibold))
        let fallbackScroll = editor(proxyFallbackServersTextView, height: 64)
        let explanation = note("DoH 可附 #IP 固定引导地址；未固定的自定义 DoH 需要填写传统 DNS。DoT 域名需内置或手动指定 #IP。B 保留仅设置传统 DNS 的兼容配置，保护开启的 DIRECT 查询仍使用加密 DNS。A / C 不自动改用本机普通 DNS。仅系统代理模式不能接管所有应用的本地解析。")

        for heading in [encryptedTitle, traditionalTitle, fallbackTitle] {
            heading.textColor = HajimiAppearance.accentText
        }
        for button in [protectionButton, prewarmButton, proxyFallbackButton] {
            button.font = .systemFont(ofSize: 11.5, weight: .medium)
            button.contentTintColor = HajimiAppearance.accentText
        }
        for button in [defaultEncryptedButton, connectivityButton] {
            button.font = .systemFont(ofSize: 11.5, weight: .semibold)
            button.contentTintColor = HajimiAppearance.accentText
            button.imagePosition = .imageLeading
        }
        defaultEncryptedButton.image = NSImage(systemSymbolName: "sparkles", accessibilityDescription: nil)
        defaultEncryptedButton.bezelStyle = .inline
        defaultEncryptedButton.isBordered = false
        defaultEncryptedButton.target = self
        defaultEncryptedButton.action = #selector(fillDefaultEncryptedDNS)
        connectivityButton.image = NSImage(systemSymbolName: "waveform.path.ecg", accessibilityDescription: nil)
        connectivityButton.bezelStyle = .inline
        connectivityButton.isBordered = false
        connectivityButton.toolTip = "仅向本栏的传统 DNS 查询固定测试域名 captive.apple.com；不保存设置，也不测试加密 DNS。"
        proxyFallbackButton.toolTip = "默认关闭，只控制 B 稳定均衡的失败后备。A 暂停使用，C 由所选方案直接授权名单参与日常择优。本机不直连；代理出口仍明文，节点可见域名。关闭会保留独立服务器列表。"
        for view in [title, protectionButton, modeTitle, selectionModePopup, modeDescriptionLabel,
                     prewarmButton, prewarmNote, encryptedTitle, defaultEncryptedButton,
                     encryptedNote, encryptedScroll, traditionalTitle, connectivityButton,
                     traditionalNote, traditionalScroll, fallbackTitle, proxyFallbackButton,
                     fallbackDescriptionLabel, fallbackScroll, explanation] {
            view.translatesAutoresizingMaskIntoConstraints = false
            addSubview(view)
        }
        NSLayoutConstraint.activate([
            title.leadingAnchor.constraint(equalTo: leadingAnchor),
            title.topAnchor.constraint(equalTo: topAnchor),
            protectionButton.trailingAnchor.constraint(equalTo: trailingAnchor),
            protectionButton.centerYAnchor.constraint(equalTo: title.centerYAnchor),
            protectionButton.leadingAnchor.constraint(greaterThanOrEqualTo: title.trailingAnchor, constant: 16),
            modeTitle.leadingAnchor.constraint(equalTo: leadingAnchor),
            modeTitle.centerYAnchor.constraint(equalTo: selectionModePopup.centerYAnchor),
            selectionModePopup.leadingAnchor.constraint(equalTo: modeTitle.trailingAnchor, constant: 14),
            selectionModePopup.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor),
            selectionModePopup.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 18),
            selectionModePopup.widthAnchor.constraint(equalToConstant: 310),
            modeDescriptionLabel.leadingAnchor.constraint(equalTo: leadingAnchor),
            modeDescriptionLabel.trailingAnchor.constraint(equalTo: trailingAnchor),
            modeDescriptionLabel.topAnchor.constraint(equalTo: selectionModePopup.bottomAnchor, constant: 6),
            prewarmButton.leadingAnchor.constraint(equalTo: leadingAnchor),
            prewarmButton.topAnchor.constraint(equalTo: modeDescriptionLabel.bottomAnchor, constant: 12),
            prewarmNote.leadingAnchor.constraint(equalTo: leadingAnchor),
            prewarmNote.trailingAnchor.constraint(equalTo: trailingAnchor),
            prewarmNote.topAnchor.constraint(equalTo: prewarmButton.bottomAnchor, constant: 4),
            encryptedTitle.leadingAnchor.constraint(equalTo: leadingAnchor),
            encryptedTitle.topAnchor.constraint(equalTo: prewarmNote.bottomAnchor, constant: 24),
            defaultEncryptedButton.trailingAnchor.constraint(equalTo: trailingAnchor),
            defaultEncryptedButton.centerYAnchor.constraint(equalTo: encryptedTitle.centerYAnchor),
            defaultEncryptedButton.leadingAnchor.constraint(greaterThanOrEqualTo: encryptedTitle.trailingAnchor, constant: 16),
            encryptedNote.leadingAnchor.constraint(equalTo: leadingAnchor),
            encryptedNote.trailingAnchor.constraint(equalTo: trailingAnchor),
            encryptedNote.topAnchor.constraint(equalTo: encryptedTitle.bottomAnchor, constant: 5),
            encryptedScroll.leadingAnchor.constraint(equalTo: leadingAnchor),
            encryptedScroll.trailingAnchor.constraint(equalTo: trailingAnchor),
            encryptedScroll.topAnchor.constraint(equalTo: encryptedNote.bottomAnchor, constant: 8),
            encryptedScroll.heightAnchor.constraint(equalToConstant: 92),
            traditionalTitle.leadingAnchor.constraint(equalTo: leadingAnchor),
            traditionalTitle.topAnchor.constraint(equalTo: encryptedScroll.bottomAnchor, constant: 24),
            connectivityButton.trailingAnchor.constraint(equalTo: trailingAnchor),
            connectivityButton.centerYAnchor.constraint(equalTo: traditionalTitle.centerYAnchor),
            connectivityButton.leadingAnchor.constraint(greaterThanOrEqualTo: traditionalTitle.trailingAnchor, constant: 16),
            traditionalNote.leadingAnchor.constraint(equalTo: leadingAnchor),
            traditionalNote.trailingAnchor.constraint(equalTo: trailingAnchor),
            traditionalNote.topAnchor.constraint(equalTo: traditionalTitle.bottomAnchor, constant: 5),
            traditionalScroll.leadingAnchor.constraint(equalTo: leadingAnchor),
            traditionalScroll.trailingAnchor.constraint(equalTo: trailingAnchor),
            traditionalScroll.topAnchor.constraint(equalTo: traditionalNote.bottomAnchor, constant: 8),
            traditionalScroll.heightAnchor.constraint(equalToConstant: 76),
            fallbackTitle.leadingAnchor.constraint(equalTo: leadingAnchor),
            fallbackTitle.topAnchor.constraint(equalTo: traditionalScroll.bottomAnchor, constant: 24),
            proxyFallbackButton.trailingAnchor.constraint(equalTo: trailingAnchor),
            proxyFallbackButton.centerYAnchor.constraint(equalTo: fallbackTitle.centerYAnchor),
            proxyFallbackButton.leadingAnchor.constraint(greaterThanOrEqualTo: fallbackTitle.trailingAnchor, constant: 16),
            fallbackDescriptionLabel.leadingAnchor.constraint(equalTo: leadingAnchor),
            fallbackDescriptionLabel.trailingAnchor.constraint(equalTo: trailingAnchor),
            fallbackDescriptionLabel.topAnchor.constraint(equalTo: fallbackTitle.bottomAnchor, constant: 5),
            fallbackScroll.leadingAnchor.constraint(equalTo: leadingAnchor),
            fallbackScroll.trailingAnchor.constraint(equalTo: trailingAnchor),
            fallbackScroll.topAnchor.constraint(equalTo: fallbackDescriptionLabel.bottomAnchor, constant: 8),
            fallbackScroll.heightAnchor.constraint(equalToConstant: 64),
            explanation.leadingAnchor.constraint(equalTo: leadingAnchor),
            explanation.trailingAnchor.constraint(equalTo: trailingAnchor),
            explanation.topAnchor.constraint(equalTo: fallbackScroll.bottomAnchor, constant: 18),
            explanation.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])
        refreshEditorAppearance()
        refreshBehaviorExplanation()
    }

    private var selectedMode: DNSSelectionMode {
        guard let raw = selectionModePopup.selectedItem?.representedObject as? String,
              let mode = DNSSelectionMode(rawValue: raw) else { return .balanced }
        return mode
    }

    @objc private func behaviorChanged() {
        refreshBehaviorExplanation()
        onBehaviorChange?()
    }

    private func refreshBehaviorExplanation() {
        switch selectedMode {
        case .encryptedOnly:
            modeDescriptionLabel.stringValue = "仅在加密 DNS 之间择优。普通 DNS 名单与失败后备授权会保留，本模式不启用。"
            fallbackDescriptionLabel.stringValue = "本模式暂停普通 DNS。切回 B 后，仅在已开启失败后备且加密 DNS 网络失败/超时时使用独立名单；本机绝不直连。代理出口仍明文、节点可见域名。"
        case .balanced:
            modeDescriptionLabel.stringValue = "优先选择稳定的加密 DNS。只有下方另行开启的失败后备，才能使用独立批准的普通 DNS 名单。"
            fallbackDescriptionLabel.stringValue = "仅在加密 DNS 网络失败/超时时经合格加密代理回退；本机绝不直连。代理出口仍明文、节点可见域名。每行填写明确批准的数字 IP，不会自动使用上方传统 DNS。"
        case .mixedSpeed:
            modeDescriptionLabel.stringValue = "选择并保存本模式，即授权下方独立批准名单中的普通 DNS 参与日常择优。仅经合格加密代理；本机绝不直连。代理出口仍明文、节点可见域名。"
            fallbackDescriptionLabel.stringValue = "本模式允许名单内的普通 DNS 与加密 DNS 按速度择优，不要求加密 DNS 先失败。原后备开关仅决定切回 B 后的失败后备授权，当前值和名单均保留。不会自动使用上方传统 DNS。"
        }
        modeDescriptionLabel.textColor = selectedMode == .mixedSpeed ? .systemOrange : .secondaryLabelColor
        fallbackDescriptionLabel.textColor = selectedMode == .encryptedOnly ? .secondaryLabelColor : .systemOrange
        proxyFallbackButton.isEnabled = selectedMode == .balanced
        needsLayout = true
        superview?.needsLayout = true
    }

    @objc private func fillDefaultEncryptedDNS() {
        encryptedServersTextView.string = Profile.defaultSecureDNSServers.joined(separator: "\n")
    }

    private func label(_ text: String, font: NSFont) -> NSTextField {
        let result = NSTextField(labelWithString: text)
        result.font = font
        result.textColor = .labelColor
        return result
    }

    private func note(_ text: String) -> NSTextField {
        let result = NSTextField(wrappingLabelWithString: text)
        configureNote(result)
        return result
    }

    private func configureNote(_ result: NSTextField) {
        result.font = .systemFont(ofSize: 11)
        result.textColor = .secondaryLabelColor
        result.setContentCompressionResistancePriority(.required, for: .vertical)
    }

    private func editor(_ textView: NSTextView, height: CGFloat) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = true
        scroll.backgroundColor = HajimiAppearance.mutedPanel
        scroll.wantsLayer = true
        scroll.layer?.cornerRadius = 10
        scroll.layer?.cornerCurve = .continuous
        scroll.layer?.borderWidth = 1.1
        scroll.layer?.masksToBounds = true
        textView.isRichText = false
        textView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.backgroundColor = HajimiAppearance.mutedPanel
        textView.textColor = .labelColor
        textView.insertionPointColor = HajimiAppearance.accentText
        textView.textContainerInset = NSSize(width: 12, height: 8)
        textView.frame = NSRect(x: 0, y: 0, width: 0, height: height)
        textView.minSize = NSSize(width: 0, height: height)
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.textContainer?.widthTracksTextView = true
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        scroll.documentView = textView
        return scroll
    }

    private func refreshEditorAppearance() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            for textView in [encryptedServersTextView, traditionalServersTextView, proxyFallbackServersTextView] {
                textView.enclosingScrollView?.layer?.borderColor = HajimiAppearance.border.cgColor
            }
        }
    }
}

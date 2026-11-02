import AppKit
import HajimiCore
import HajimiUIComponents

private final class EditorFlippedView: NSView {
    override var isFlipped: Bool { true }
}

/// Surge-style structured proxy editor. Dynamically displays only the sections
/// and native controls (dropdowns, switches, text fields) relevant to the
/// selected protocol, while preserving unknown options in a lossless module.
final class SurgeProxyEditorController: NSWindowController {
    private enum ControlKind {
        case text(placeholder: String, secure: Bool)
        case select(options: [(title: String, value: String)], defaultValue: String)
        case toggle(defaultOn: Bool)
    }

    private struct FieldSpec {
        let key: String
        let label: String
        let kind: ControlKind
    }

    private let originalName: String?
    private let unavailableNames: Set<String>
    private let availableProxyNames: [String]
    private let commit: (SurgeProxyDraft) throws -> Void
    private var workingParameters: [String: String]
    private var originallySkippedCertificate = false
    private var editingType = "vmess"

    private var credentialTextFields: [String: NSTextField] = [:]
    private var credentialPopups: [String: NSPopUpButton] = [:]
    private var credentialToggles: [String: NSButton] = [:]

    private let nameField = NSTextField()
    private let typePopup = NSPopUpButton()
    private let hostField = NSTextField()
    private let portField = NSTextField()
    private let credentialStack = NSStackView()
    private weak var authenticationBox: NSBox?
    private weak var tlsBoxRef: NSBox?
    private weak var transportBoxRef: NSBox?
    private weak var chainBoxRef: NSBox?

    private let tlsButton = NSButton(checkboxWithTitle: "使用 TLS", target: nil, action: nil)
    private let skipCertificateButton = NSButton(checkboxWithTitle: "跳过服务器证书验证（不安全）", target: nil, action: nil)
    private let skipCertificateWarning = NSTextField(wrappingLabelWithString: SkipCertificateWarning.headline)
    private let sniField = NSTextField()
    private let fingerprintField = NSTextField()
    private let alpnField = NSTextField()
    private var sniRow: NSStackView?
    private var fingerprintRow: NSStackView?
    private var alpnRow: NSStackView?

    private let transportPopup = NSPopUpButton()
    private let wsPathField = NSTextField()
    private let wsHostField = NSTextField()
    private let grpcServiceField = NSTextField()
    private let xhttpPathField = NSTextField()
    private let xhttpHostField = NSTextField()
    private let kcpHeaderField = NSTextField()
    private let kcpSeedField = NSTextField()
    private let kcpMTUField = NSTextField()
    private let kcpAuthenticatorPopup = NSPopUpButton()
    private var wsPathRow: NSStackView?
    private var wsHostRow: NSStackView?
    private var grpcRow: NSStackView?
    private var xhttpRow: NSStackView?
    private var kcpHeaderRow: NSStackView?
    private var kcpAuthRow: NSStackView?
    private var kcpHintField: NSTextField?

    private let underlyingPopup = NSPopUpButton()
    private let udpButton = NSButton(checkboxWithTitle: "UDP 转发 (UDP Relay)", target: nil, action: nil)
    private let tfoButton = NSButton(checkboxWithTitle: "TCP Fast Open (TFO)", target: nil, action: nil)
    private let ipVersionPopup = NSPopUpButton()
    private let interfaceField = NSTextField()
    private let parametersView = NSTextView()
    private let protocolHelp = NSTextField(wrappingLabelWithString: "")
    private let errorLabel = NSTextField(wrappingLabelWithString: "")

    private static let types: [(String, String)] = [
        ("HTTP", "http"), ("HTTPS", "https"), ("SOCKS5", "socks5"),
        ("SOCKS5 TLS", "socks5-tls"), ("Shadowsocks", "ss"),
        ("ShadowsocksR", "ssr"), ("Snell", "snell"), ("VMess", "vmess"),
        ("VLESS", "vless"), ("Trojan", "trojan"), ("AnyTLS", "anytls"),
        ("Sudoku", "sudoku"), ("Mieru", "mieru"), ("TrustTunnel", "trusttunnel"),
        ("Hysteria", "hysteria"), ("Hysteria 2", "hysteria2"),
        ("TUIC", "tuic"), ("SSH", "ssh"), ("WireGuard", "wireguard")
    ]

    /// Standard V2Ray-family carriers for VMess/VLESS/Trojan.
    private static let v2rayTransports: [(String, String)] = [
        ("TCP", "tcp"), ("WebSocket", "ws"), ("gRPC", "grpc"),
        ("XHTTP", "xhttp"), ("mKCP (UDP)", "kcp")
    ]

    /// Mieru-specific transport selector (TCP / UDP).
    private static let mieruTransports: [(String, String)] = [
        ("TCP", "TCP"), ("UDP", "UDP")
    ]

    private static let carrierKeys: [String] = [
        "network", "ws", "ws-path", "ws-host", "grpc-service-name",
        "xhttp-path", "xhttp-host",
        "kcp-header", "kcp-seed", "kcp-mtu", "kcp-authenticator"
    ]

    private static let sharedOptionKeys: [String] = [
        "tls", "skip-cert-verify", "skip-common-name-verify", "sni", "servername",
        "fingerprint", "client-fingerprint", "alpn", "udp", "udp-relay", "tfo",
        "fast-open", "ip-version", "interface-name", "underlying-proxy", "dialer-proxy"
    ]

    init(draft: SurgeProxyDraft?, isNew: Bool = false, unavailableNames: Set<String>,
         availableProxyNames: [String], commit: @escaping (SurgeProxyDraft) throws -> Void) {
        originalName = isNew ? nil : draft?.name
        self.unavailableNames = unavailableNames
        self.availableProxyNames = availableProxyNames
        self.commit = commit
        workingParameters = Self.normalizedParameters(draft?.parameters ?? [:],
                                                      type: draft?.type ?? "vmess")
        originallySkippedCertificate = Self.truthy(workingParameters["skip-cert-verify"])
            || Self.truthy(workingParameters["skip-common-name-verify"])
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 900, height: 800),
                            styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = isNew || draft == nil ? "新增代理" : "编辑代理"
        panel.minSize = NSSize(width: 820, height: 680)
        super.init(window: panel)
        buildUI(draft: draft, adding: isNew || draft == nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private static func normalizedParameters(_ source: [String: String], type: String) -> [String: String] {
        var result = source
        if (type == "vmess" || type == "vless"), result["uuid"] == nil,
           let username = result.removeValue(forKey: "username") {
            result["uuid"] = username
        }
        if result["alter-id"] == nil, let value = result.removeValue(forKey: "alterid") {
            result["alter-id"] = value
        }
        if type == "sudoku" {
            if result["key"] == nil, let password = result.removeValue(forKey: "password") {
                result["key"] = password
            }
            if result["aead-method"] == nil, let cipher = result.removeValue(forKey: "cipher") {
                result["aead-method"] = cipher
            }
            if result["table-type"] == nil, let ascii = result.removeValue(forKey: "ascii") {
                result["table-type"] = ascii
            }
            if result["multiplex"] == nil, let mux = result.removeValue(forKey: "http-mask-multiplex") {
                result["multiplex"] = mux
            }
            if result["disable-http-mask"] == nil, let mask = result.removeValue(forKey: "http-mask") {
                result["disable-http-mask"] = truthy(mask) ? "false" : "true"
            }
        }
        if type == "mieru" {
            if let t = result["transport"] {
                result["transport"] = t.uppercased()
            } else if let net = result.removeValue(forKey: "network"),
                      ["tcp", "udp"].contains(net.lowercased()) {
                result["transport"] = net.uppercased()
            }
        }
        return result
    }

    private func buildUI(draft: SurgeProxyDraft?, adding: Bool) {
        guard let window else { return }
        let root = HajimiSurfaceView(fill: HajimiAppearance.workspace, cornerRadius: 0)
        root.frame = window.contentView?.frame ?? NSRect(x: 0, y: 0, width: 900, height: 800)
        window.contentView = root

        let title = NSTextField(labelWithString: adding ? "新增代理" : "编辑代理")
        title.font = .systemFont(ofSize: 19, weight: .bold)
        let badge = HajimiAppearance.pillBadge(text: "OUTBOUND ADAPTER", fontSize: 9.0)
        let parseLinkBtn = NSButton(title: "从分享链接填入…", target: self, action: #selector(fillFromShareLinkPrompt))
        parseLinkBtn.bezelStyle = .rounded
        parseLinkBtn.controlSize = .small
        let titleRow = NSStackView(views: [title, badge, NSView(), parseLinkBtn])
        titleRow.orientation = .horizontal
        titleRow.alignment = .centerY
        titleRow.spacing = 10
        titleRow.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(titleRow)

        nameField.stringValue = draft?.name ?? ""
        nameField.placeholderString = "节点名称（可直接粘贴分享链接自动识别）"
        nameField.font = .systemFont(ofSize: 12.5)
        typePopup.removeAllItems()
        for (display, raw) in Self.types {
            typePopup.addItem(withTitle: display)
            typePopup.lastItem?.representedObject = raw
        }
        if let type = draft?.type,
           let index = Self.types.firstIndex(where: { $0.1 == type.lowercased() }) {
            typePopup.selectItem(at: index)
        } else {
            typePopup.selectItem(at: Self.types.firstIndex(where: { $0.1 == "vmess" }) ?? 0)
        }
        editingType = selectedType
        typePopup.target = self
        typePopup.action = #selector(typeChanged)
        let topForm = NSStackView(views: [formLabel("名称:"), nameField,
                                         formLabel("协议:"), typePopup])
        topForm.orientation = .horizontal
        topForm.alignment = .centerY
        topForm.spacing = 9
        topForm.translatesAutoresizingMaskIntoConstraints = false
        nameField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        typePopup.widthAnchor.constraint(equalToConstant: 180).isActive = true
        root.addSubview(topForm)

        let divider = NSBox()
        divider.boxType = .separator
        divider.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(divider)

        hostField.stringValue = draft?.host ?? ""
        hostField.placeholderString = "server.example.com 或 IP（支持粘贴分享链接）"
        portField.stringValue = draft.map { String($0.port) } ?? "443"
        portField.placeholderString = "443"
        portField.alignment = .right
        portField.widthAnchor.constraint(equalToConstant: 82).isActive = true

        configureCommonControls()

        let serverRow = NSStackView(views: [hostField, formLabel(":"), portField])
        serverRow.orientation = .horizontal
        serverRow.alignment = .centerY
        serverRow.spacing = 6
        hostField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let serverBox = moduleBox(title: "服务器信息", content: verticalStack([
            formRow("服务器地址", serverRow)
        ]))

        let authHeader = NSStackView(views: [protocolHelp])
        authHeader.orientation = .vertical
        authHeader.alignment = .leading
        authHeader.spacing = 4
        let authContent = verticalStack([authHeader, credentialStack])
        let authBox = moduleBox(title: "\(selectedType.uppercased()) 协议配置", content: authContent)
        authenticationBox = authBox
        authBox.identifier = NSUserInterfaceItemIdentifier("authenticationBox")

        let rSNI = formRow("自定义 TLS SNI", sniField)
        let rFP = formRow("客户端指纹", fingerprintField)
        let rALPN = formRow("ALPN", alpnField)
        sniRow = rSNI
        fingerprintRow = rFP
        alpnRow = rALPN

        let tlsContent = verticalStack([
            tlsButton,
            skipCertificateButton,
            skipCertificateWarning,
            rSNI,
            rFP,
            rALPN
        ])
        let tlsBox = moduleBox(title: "TLS 安全设置", content: tlsContent)
        tlsBoxRef = tlsBox

        let rWSPath = formRow("WebSocket 路径", wsPathField)
        let rWSHost = formRow("WebSocket Host", wsHostField)
        let rGRPC = formRow("gRPC Service", grpcServiceField)
        let rXHTTP = formRow("XHTTP 路径 / Host", pairRow(xhttpPathField, xhttpHostField))
        let rKCPHeader = formRow("mKCP 伪装头 / Seed", pairRow(kcpHeaderField, kcpSeedField))
        let rKCPAuth = formRow("mKCP 认证层 / MTU", pairRow(kcpAuthenticatorPopup, kcpMTUField))
        let rKCPHint = hint("mKCP 走 UDP 并自带可靠性。伪装头由接收端按长度盲剥，认证层需与服务端一致。")
        wsPathRow = rWSPath
        wsHostRow = rWSHost
        grpcRow = rGRPC
        xhttpRow = rXHTTP
        kcpHeaderRow = rKCPHeader
        kcpAuthRow = rKCPAuth
        kcpHintField = rKCPHint

        let transportContent = verticalStack([
            formRow("传输方式", transportPopup),
            rWSPath,
            rWSHost,
            rGRPC,
            rXHTTP,
            rKCPHeader,
            rKCPAuth,
            rKCPHint
        ])
        let transportBox = moduleBox(title: "传输设置", content: transportContent)
        transportBoxRef = transportBox

        let chainBox = moduleBox(title: "代理链", content: verticalStack([
            formRow("跳板代理", underlyingPopup),
            hint("使用另一个代理节点作为前置跳板连接当前节点（对应 underlying-proxy）。")
        ]))
        chainBoxRef = chainBox

        let networkBox = moduleBox(title: "网络与出站", content: verticalStack([
            udpButton,
            tfoButton,
            formRow("IP 版本", ipVersionPopup),
            formRow("指定网络设备", interfaceField),
            hint("网络设备可填写 en0、en1 或 VPN 接口名称；留空时自动选择。")
        ]))

        let template = NSButton(title: "填入当前协议推荐默认值", target: self,
                                action: #selector(insertTemplate))
        template.controlSize = .small
        template.bezelStyle = .rounded
        let protocolBox = moduleBox(title: "快捷操作", content: verticalStack([
            template,
            hint("已根据所选协议自动精简表单，只展示当前协议所需的专属配置项。")
        ]))

        let extraScroll = NSScrollView()
        extraScroll.hasVerticalScroller = true
        extraScroll.borderType = .bezelBorder
        extraScroll.wantsLayer = true
        extraScroll.layer?.cornerRadius = 7
        extraScroll.layer?.cornerCurve = .continuous
        extraScroll.translatesAutoresizingMaskIntoConstraints = false
        extraScroll.heightAnchor.constraint(equalToConstant: 110).isActive = true
        parametersView.isRichText = false
        parametersView.isAutomaticQuoteSubstitutionEnabled = false
        parametersView.isAutomaticDashSubstitutionEnabled = false
        parametersView.font = .monospacedSystemFont(ofSize: 10.5, weight: .regular)
        parametersView.textContainerInset = NSSize(width: 7, height: 6)
        extraScroll.documentView = parametersView
        let extraBox = moduleBox(title: "附加高级参数（可选）", content: verticalStack([
            extraScroll,
            hint("每行 key=value。仅用于填写未在上方表单列出的额外底层参数。")
        ]))

        let left = verticalStack([serverBox, authBox, tlsBox, transportBox])
        let right = verticalStack([networkBox, chainBox, protocolBox, extraBox])
        left.alignment = .leading
        right.alignment = .leading
        let columns = NSStackView(views: [left, right])
        columns.orientation = .horizontal
        columns.alignment = .top
        columns.distribution = .fillEqually
        columns.spacing = 12
        columns.translatesAutoresizingMaskIntoConstraints = false

        let scrollContainer = NSScrollView()
        scrollContainer.drawsBackground = false
        scrollContainer.borderType = .noBorder
        scrollContainer.hasVerticalScroller = true
        scrollContainer.autohidesScrollers = true
        scrollContainer.translatesAutoresizingMaskIntoConstraints = false
        let docView = EditorFlippedView()
        docView.translatesAutoresizingMaskIntoConstraints = false
        docView.addSubview(columns)
        scrollContainer.documentView = docView
        root.addSubview(scrollContainer)

        left.widthAnchor.constraint(equalTo: right.widthAnchor).isActive = true
        if let contentView = scrollContainer.contentView as NSView? {
            NSLayoutConstraint.activate([
                docView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
                docView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
                docView.topAnchor.constraint(equalTo: contentView.topAnchor),
                columns.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 6),
                columns.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -6),
                columns.topAnchor.constraint(equalTo: docView.topAnchor, constant: 2),
                columns.bottomAnchor.constraint(equalTo: docView.bottomAnchor, constant: -8)
            ])
        }

        let footerDivider = NSBox()
        footerDivider.boxType = .separator
        footerDivider.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(footerDivider)
        errorLabel.font = .systemFont(ofSize: 10.5, weight: .medium)
        errorLabel.textColor = .systemRed
        errorLabel.lineBreakMode = .byTruncatingTail
        errorLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(errorLabel)
        let cancel = NSButton(title: "取消", target: self, action: #selector(cancelPressed))
        cancel.bezelStyle = .rounded
        let save = NSButton(title: adding ? "添加并应用" : "完成",
                            target: self, action: #selector(savePressed))
        save.bezelStyle = .rounded
        save.keyEquivalent = "\r"
        let buttons = NSStackView(views: [cancel, save])
        buttons.orientation = .horizontal
        buttons.spacing = 10
        buttons.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(buttons)

        NSLayoutConstraint.activate([
            titleRow.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            titleRow.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            titleRow.topAnchor.constraint(equalTo: root.topAnchor, constant: 16),
            topForm.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            topForm.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            topForm.topAnchor.constraint(equalTo: titleRow.bottomAnchor, constant: 12),
            divider.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            divider.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            divider.topAnchor.constraint(equalTo: topForm.bottomAnchor, constant: 12),
            scrollContainer.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 12),
            scrollContainer.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -12),
            scrollContainer.topAnchor.constraint(equalTo: divider.bottomAnchor, constant: 10),
            scrollContainer.bottomAnchor.constraint(equalTo: footerDivider.topAnchor, constant: -8),
            footerDivider.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            footerDivider.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            footerDivider.bottomAnchor.constraint(equalTo: buttons.topAnchor, constant: -11),
            errorLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            errorLabel.trailingAnchor.constraint(lessThanOrEqualTo: buttons.leadingAnchor, constant: -12),
            errorLabel.centerYAnchor.constraint(equalTo: buttons.centerYAnchor),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -14)
        ])

        configureCredentialStack()
        populateCommonFields(type: selectedType)
        refreshExtraParameters()
        updateProtocolHelp()
        updateSectionVisibilityAndTransportControls()
    }

    private var selectedType: String {
        typePopup.selectedItem?.representedObject as? String ?? "vmess"
    }

    private static func usesTLSBox(for type: String) -> Bool {
        ["https", "socks5-tls", "vmess", "vless", "trojan", "anytls",
         "trusttunnel", "hysteria", "hysteria2", "tuic"].contains(type)
    }

    private static func impliesMandatoryTLS(for type: String) -> Bool {
        ["https", "socks5-tls", "trojan", "anytls", "trusttunnel",
         "hysteria", "hysteria2", "tuic"].contains(type)
    }

    private static func usesV2RayCarriers(for type: String) -> Bool {
        ["vmess", "vless", "trojan"].contains(type)
    }

    private static func supportsUnderlyingProxy(for type: String) -> Bool {
        ["http", "https", "socks5", "socks5-tls", "ss", "ssr",
         "vmess", "vless", "trojan"].contains(type)
    }

    private func configureCommonControls() {
        for button in [tlsButton, skipCertificateButton, udpButton, tfoButton] {
            button.setButtonType(.switch)
            button.controlSize = .small
        }
        tlsButton.target = self
        tlsButton.action = #selector(tlsToggled)
        skipCertificateButton.target = self
        skipCertificateButton.action = #selector(skipCertificateChanged)
        skipCertificateButton.toolTip = SkipCertificateWarning.headline
        skipCertificateWarning.font = .systemFont(ofSize: 10, weight: .medium)
        skipCertificateWarning.textColor = .systemOrange
        skipCertificateWarning.isHidden = true

        transportPopup.target = self
        transportPopup.action = #selector(transportChanged)
        wsPathField.placeholderString = "/"
        wsHostField.placeholderString = "可选 Host"
        grpcServiceField.placeholderString = "service-name"
        xhttpPathField.placeholderString = "/tunnel"
        xhttpHostField.placeholderString = "可选 Host"
        kcpHeaderField.placeholderString = "none / dtls / srtp …"
        kcpSeedField.placeholderString = "可选"
        kcpMTUField.placeholderString = "1350"
        sniField.placeholderString = "可选，默认使用服务器地址"
        fingerprintField.placeholderString = "例如 chrome"
        alpnField.placeholderString = "例如 h2,http/1.1"
        interfaceField.placeholderString = "自动"

        let authenticators = [
            ("自动", ""), ("无", "none"),
            ("SimpleAuthenticator", "simple"), ("AES-128-GCM（需 Seed）", "seed")
        ]
        for (title, value) in authenticators {
            kcpAuthenticatorPopup.addItem(withTitle: title)
            kcpAuthenticatorPopup.lastItem?.representedObject = value
        }

        let ipVersions = [
            ("自动", ""), ("仅 IPv4", "v4-only"), ("仅 IPv6", "v6-only"),
            ("优先 IPv4", "v4-preferred"), ("优先 IPv6", "v6-preferred")
        ]
        for (title, value) in ipVersions {
            ipVersionPopup.addItem(withTitle: title)
            ipVersionPopup.lastItem?.representedObject = value
        }
        underlyingPopup.addItem(withTitle: "不使用")
        underlyingPopup.lastItem?.representedObject = ""
        for name in availableProxyNames where name != originalName {
            underlyingPopup.addItem(withTitle: name)
            underlyingPopup.lastItem?.representedObject = name
        }
    }

    private func rebuildTransportPopupItems(for type: String) {
        transportPopup.removeAllItems()
        let items = (type == "mieru") ? Self.mieruTransports : Self.v2rayTransports
        for (display, raw) in items {
            transportPopup.addItem(withTitle: display)
            transportPopup.lastItem?.representedObject = raw
        }
    }

    private func populateCommonFields(type: String) {
        rebuildTransportPopupItems(for: type)
        let mandatoryTLS = Self.impliesMandatoryTLS(for: type)
        let tlsEnabled = mandatoryTLS || isTrue(workingParameters["tls"])
        tlsButton.state = tlsEnabled ? .on : .off
        tlsButton.isEnabled = !mandatoryTLS
        skipCertificateButton.state = isTrue(workingParameters["skip-cert-verify"] ??
                                             workingParameters["skip-common-name-verify"]) ? .on : .off
        refreshSkipCertificateWarning()
        sniField.stringValue = workingParameters["servername"] ?? workingParameters["sni"] ?? ""
        fingerprintField.stringValue = workingParameters["client-fingerprint"] ??
            workingParameters["fingerprint"] ?? ""
        alpnField.stringValue = workingParameters["alpn"] ?? ""

        if type == "mieru" {
            let mTransport = (workingParameters["transport"] ?? workingParameters["network"] ?? "TCP").uppercased()
            let idx = Self.mieruTransports.firstIndex { $0.1 == mTransport } ?? 0
            transportPopup.selectItem(at: idx)
        } else {
            var network = workingParameters["network"]?.lowercased() ?? "tcp"
            if isTrue(workingParameters["ws"]) { network = "ws" }
            if network == "tcp", workingParameters["grpc-service-name"] != nil { network = "grpc" }
            if network == "mkcp" { network = "kcp" }
            if network == "splithttp" { network = "xhttp" }
            transportPopup.selectItem(at: Self.v2rayTransports.firstIndex { $0.1 == network } ?? 0)
        }

        wsPathField.stringValue = workingParameters["ws-path"] ?? ""
        wsHostField.stringValue = workingParameters["ws-host"] ?? ""
        grpcServiceField.stringValue = workingParameters["grpc-service-name"] ?? ""
        xhttpPathField.stringValue = workingParameters["xhttp-path"] ?? ""
        xhttpHostField.stringValue = workingParameters["xhttp-host"] ?? ""
        kcpHeaderField.stringValue = workingParameters["kcp-header"] ?? ""
        kcpSeedField.stringValue = workingParameters["kcp-seed"] ?? ""
        kcpMTUField.stringValue = workingParameters["kcp-mtu"] ?? ""
        let authenticator = workingParameters["kcp-authenticator"]?.lowercased() ?? ""
        kcpAuthenticatorPopup.selectItem(at: kcpAuthenticatorPopup.itemArray.firstIndex {
            ($0.representedObject as? String) == authenticator
        } ?? 0)

        let supportsUDP = !["http", "https", "ssh"].contains(type)
        let defaultUDP = supportsUDP && workingParameters["udp"] == nil && workingParameters["udp-relay"] == nil
        udpButton.state = (defaultUDP || isTrue(workingParameters["udp"] ??
                                               workingParameters["udp-relay"])) ? .on : .off
        udpButton.isEnabled = supportsUDP
        tfoButton.state = isTrue(workingParameters["tfo"] ?? workingParameters["fast-open"]) ? .on : .off
        let ipVersion = workingParameters["ip-version"] ?? ""
        if let index = ipVersionPopup.itemArray.firstIndex(where: { ($0.representedObject as? String) == ipVersion }) {
            ipVersionPopup.selectItem(at: index)
        } else {
            ipVersionPopup.selectItem(at: 0)
        }
        interfaceField.stringValue = workingParameters["interface-name"] ?? ""
        let underlying = workingParameters["underlying-proxy"] ?? workingParameters["dialer-proxy"] ?? ""
        if !underlying.isEmpty, underlyingPopup.itemArray.contains(where: { $0.title == underlying }) == false {
            underlyingPopup.addItem(withTitle: underlying)
            underlyingPopup.lastItem?.representedObject = underlying
        }
        underlyingPopup.selectItem(withTitle: underlying.isEmpty ? "不使用" : underlying)
    }

    private func configureCredentialStack() {
        for view in credentialStack.arrangedSubviews {
            credentialStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        credentialTextFields.removeAll(keepingCapacity: true)
        credentialPopups.removeAll(keepingCapacity: true)
        credentialToggles.removeAll(keepingCapacity: true)

        credentialStack.orientation = .vertical
        credentialStack.alignment = .leading
        credentialStack.spacing = 7

        for spec in fieldSpecs(for: selectedType) {
            let row: NSView
            switch spec.kind {
            case .text(let placeholder, let secure):
                let field: NSTextField = secure ? NSSecureTextField() : NSTextField()
                field.stringValue = workingParameters[spec.key] ?? ""
                field.placeholderString = placeholder
                field.controlSize = .small
                if spec.key == "key" || spec.key == "uuid" || spec.key == "custom-table" {
                    field.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
                }
                credentialTextFields[spec.key] = field
                row = formRow(spec.label, field)

            case .select(let options, let defaultValue):
                let popup = NSPopUpButton()
                popup.controlSize = .small
                for (title, val) in options {
                    popup.addItem(withTitle: title)
                    popup.lastItem?.representedObject = val
                }
                let rawCurrent = workingParameters[spec.key] ?? defaultValue
                if let idx = options.firstIndex(where: { $0.value.caseInsensitiveCompare(rawCurrent) == .orderedSame }) {
                    popup.selectItem(at: idx)
                } else if !rawCurrent.isEmpty {
                    popup.addItem(withTitle: rawCurrent)
                    popup.lastItem?.representedObject = rawCurrent
                    popup.selectItem(at: popup.numberOfItems - 1)
                } else {
                    popup.selectItem(at: 0)
                }
                if spec.key == "transport" {
                    popup.target = self
                    popup.action = #selector(mieruAuthTransportPopupChanged(_:))
                }
                credentialPopups[spec.key] = popup
                row = formRow(spec.label, popup)

            case .toggle(let defaultOn):
                let toggle = NSButton(checkboxWithTitle: spec.label, target: self, action: #selector(credentialToggleChanged(_:)))
                toggle.setButtonType(.switch)
                toggle.controlSize = .small
                let current = workingParameters[spec.key]
                let isOn = current != nil ? Self.truthy(current) : defaultOn
                toggle.state = isOn ? .on : .off
                credentialToggles[spec.key] = toggle
                row = toggle
            }
            credentialStack.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: credentialStack.widthAnchor).isActive = true
        }
        updateSudokuMaskControlEnabling()
    }

    @objc private func credentialToggleChanged(_ sender: NSButton) {
        updateSudokuMaskControlEnabling()
    }

    @objc private func mieruAuthTransportPopupChanged(_ sender: NSPopUpButton) {
        guard selectedType == "mieru",
              let val = sender.selectedItem?.representedObject as? String else { return }
        if let idx = Self.mieruTransports.firstIndex(where: { $0.1 == val }) {
            transportPopup.selectItem(at: idx)
        }
    }

    private func updateSudokuMaskControlEnabling() {
        guard selectedType == "sudoku" else { return }
        let maskDisabled = credentialToggles["disable-http-mask"]?.state == .on
        credentialPopups["http-mask-mode"]?.isEnabled = !maskDisabled
        credentialToggles["http-mask-tls"]?.isEnabled = !maskDisabled
        credentialTextFields["http-mask-host"]?.isEnabled = !maskDisabled
        credentialTextFields["path-root"]?.isEnabled = !maskDisabled
    }

    private func fieldSpecs(for type: String) -> [FieldSpec] {
        func text(_ key: String, _ label: String, _ placeholder: String = "", _ secure: Bool = false) -> FieldSpec {
            FieldSpec(key: key, label: label, kind: .text(placeholder: placeholder, secure: secure))
        }
        func select(_ key: String, _ label: String, _ options: [(String, String)], default defaultValue: String) -> FieldSpec {
            FieldSpec(key: key, label: label, kind: .select(options: options, defaultValue: defaultValue))
        }
        func toggle(_ key: String, _ label: String, defaultOn: Bool) -> FieldSpec {
            FieldSpec(key: key, label: label, kind: .toggle(defaultOn: defaultOn))
        }

        switch type {
        case "http", "https", "socks5", "socks5-tls":
            return [
                text("username", "用户名", "可选"),
                text("password", "密码", "可选", true)
            ]
        case "ss":
            return [
                select("cipher", "加密算法", [
                    ("aes-128-gcm", "aes-128-gcm"),
                    ("aes-256-gcm", "aes-256-gcm"),
                    ("chacha20-ietf-poly1305", "chacha20-ietf-poly1305"),
                    ("2022-blake3-aes-128-gcm", "2022-blake3-aes-128-gcm"),
                    ("2022-blake3-aes-256-gcm", "2022-blake3-aes-256-gcm"),
                    ("2022-blake3-chacha20-poly1305", "2022-blake3-chacha20-poly1305"),
                    ("rc4-md5", "rc4-md5")
                ], default: "aes-128-gcm"),
                text("password", "密码", "必填", true),
                select("obfs", "混淆模式", [
                    ("无混淆", ""),
                    ("HTTP 混淆 (http)", "http"),
                    ("TLS 混淆 (tls)", "tls")
                ], default: ""),
                text("obfs-host", "混淆 Host", "可选，如 bing.com")
            ]
        case "ssr":
            return [
                select("cipher", "加密算法", [
                    ("aes-128-cfb", "aes-128-cfb"),
                    ("aes-192-cfb", "aes-192-cfb"),
                    ("aes-256-cfb", "aes-256-cfb"),
                    ("chacha20-ietf", "chacha20-ietf")
                ], default: "aes-128-cfb"),
                text("password", "密码", "必填", true),
                select("protocol", "协议插件", [
                    ("origin", "origin"),
                    ("auth_sha1_v4", "auth_sha1_v4"),
                    ("auth_aes128_md5", "auth_aes128_md5"),
                    ("auth_aes128_sha1", "auth_aes128_sha1"),
                    ("auth_chain_a", "auth_chain_a")
                ], default: "origin"),
                text("protocol-param", "协议参数", "可选"),
                select("obfs", "混淆插件", [
                    ("plain", "plain"),
                    ("http_simple", "http_simple"),
                    ("http_post", "http_post"),
                    ("tls1.2_ticket_auth", "tls1.2_ticket_auth")
                ], default: "plain"),
                text("obfs-param", "混淆参数", "可选")
            ]
        case "snell":
            return [
                text("psk", "PSK 密钥", "必填", true),
                select("version", "协议版本", [
                    ("v4 (推荐)", "4"), ("v5", "5"), ("v3", "3"), ("v2", "2"), ("v1", "1")
                ], default: "4"),
                toggle("reuse", "启用连接复用 (reuse)", defaultOn: true)
            ]
        case "vmess":
            return [
                text("uuid", "ID / UUID", "必填，如 b831381d-6324-4d53-ad4f-8cda48b30811"),
                text("alter-id", "Alter ID", "默认 0"),
                select("cipher", "加密方式", [
                    ("自动 (auto)", "auto"),
                    ("aes-128-gcm", "aes-128-gcm"),
                    ("chacha20-poly1305", "chacha20-poly1305"),
                    ("none", "none")
                ], default: "auto")
            ]
        case "vless":
            return [
                text("uuid", "ID / UUID", "必填，如 b831381d-6324-4d53-ad4f-8cda48b30811"),
                select("flow", "XTLS 流控 (Flow)", [
                    ("不使用", ""),
                    ("xtls-rprx-vision", "xtls-rprx-vision"),
                    ("xtls-rprx-vision-udp443", "xtls-rprx-vision-udp443")
                ], default: "")
            ]
        case "trojan", "anytls":
            return [
                text("password", "密码", "必填", true)
            ]
        case "hysteria":
            return [
                text("auth-str", "认证字符串", "必填", true),
                text("up", "上传带宽", "例如 10 Mbps"),
                text("down", "下载带宽", "例如 50 Mbps"),
                text("obfs", "混淆口令", "可选")
            ]
        case "hysteria2":
            return [
                text("password", "认证密码", "必填", true),
                select("obfs", "混淆类型", [
                    ("无混淆", ""),
                    ("Salamander", "salamander")
                ], default: ""),
                text("obfs-password", "混淆密码", "启用 Salamander 时必填", true),
                text("ports", "端口跳跃", "可选，如 20000-30000")
            ]
        case "tuic":
            return [
                text("token", "Token (v4)", "与 UUID 方式二选一", true),
                text("uuid", "UUID (v5)", "与 Token 方式二选一"),
                text("password", "密码 (v5)", "UUID 方式必填", true),
                select("congestion-controller", "拥塞控制", [
                    ("BBR", "bbr"),
                    ("CUBIC", "cubic"),
                    ("NewReno", "new_reno")
                ], default: "bbr")
            ]
        case "sudoku":
            return [
                text("key", "密钥 (Key)", "必填（64字节Hex密钥或UUID）"),
                select("aead-method", "AEAD 加密", [
                    ("chacha20-poly1305 (默认)", "chacha20-poly1305"),
                    ("aes-128-gcm", "aes-128-gcm"),
                    ("none (无加密)", "none")
                ], default: "chacha20-poly1305"),
                select("table-type", "编码表方向", [
                    ("上行 ASCII / 下行低熵 (up_ascii_down_entropy)", "up_ascii_down_entropy"),
                    ("偏好 ASCII (prefer_ascii)", "prefer_ascii"),
                    ("偏好低熵 (prefer_entropy)", "prefer_entropy"),
                    ("上行低熵 / 下行 ASCII (up_entropy_down_ascii)", "up_entropy_down_ascii")
                ], default: "prefer_ascii"),
                text("custom-table", "自定义编码表", "可选 8位 x/p/v 布局，如 xvxvppvv"),
                toggle("enable-pure-downlink", "纯 Sudoku 下行编码 (enable-pure-downlink)", defaultOn: true),
                text("padding-min", "最小填充率 %", "默认 2 (0-100)"),
                text("padding-max", "最大填充率 %", "默认 7 (0-100)"),
                toggle("disable-http-mask", "禁用 HTTP 隧道伪装 (disable-http-mask)", defaultOn: false),
                select("http-mask-mode", "HTTP 伪装模式", [
                    ("自动 (auto)", "auto"),
                    ("传统头 (legacy)", "legacy"),
                    ("流式 (stream)", "stream"),
                    ("轮询 (poll)", "poll"),
                    ("WebSocket (ws)", "ws")
                ], default: "auto"),
                toggle("http-mask-tls", "HTTP 伪装强制 HTTPS (TLS)", defaultOn: false),
                text("http-mask-host", "伪装 Host / SNI", "可选，如 example.com"),
                text("path-root", "HTTP 路径前缀", "可选，如 hajimipath"),
                select("multiplex", "多路复用", [
                    ("关闭 (off)", "off"),
                    ("自动复用连接 (auto)", "auto"),
                    ("单会话多路复用 (on)", "on")
                ], default: "off")
            ]
        case "mieru":
            return [
                text("username", "用户名", "必填"),
                text("password", "密码", "必填", true),
                select("transport", "传输协议", [
                    ("TCP (推荐)", "TCP"),
                    ("UDP", "UDP")
                ], default: "TCP"),
                select("multiplexing", "多路复用级别", [
                    ("高复用 (MULTIPLEXING_HIGH)", "MULTIPLEXING_HIGH"),
                    ("中复用 (MULTIPLEXING_MIDDLE)", "MULTIPLEXING_MIDDLE"),
                    ("低复用 (MULTIPLEXING_LOW)", "MULTIPLEXING_LOW"),
                    ("关闭复用 (MULTIPLEXING_OFF)", "MULTIPLEXING_OFF")
                ], default: "MULTIPLEXING_HIGH"),
                select("handshake-mode", "握手模式", [
                    ("标准握手 (HANDSHAKE_STANDARD)", "HANDSHAKE_STANDARD"),
                    ("0-RTT 握手 (HANDSHAKE_NO_WAIT)", "HANDSHAKE_NO_WAIT")
                ], default: "HANDSHAKE_STANDARD"),
                text("port-range", "端口范围", "可选，如 2012-2022（留空用上方端口）"),
                text("mtu", "MTU", "默认 1400")
            ]
        case "trusttunnel":
            return [
                text("username", "用户名", "必填"),
                text("password", "密码", "必填", true),
                select("quic", "隧道传输层", [
                    ("HTTP/2 over TLS (TCP)", "false"),
                    ("HTTP/3 over QUIC (UDP)", "true")
                ], default: "false")
            ]
        case "ssh":
            return [
                text("username", "用户名", "必填"),
                text("password", "密码", "密码或私钥二选一", true),
                text("private-key", "私钥路径", "例如 ~/.ssh/id_ed25519")
            ]
        case "wireguard":
            return [
                text("private-key", "本机私钥", "必填 (Base64)", true),
                text("ip", "本机 IPv4", "例如 172.16.0.2/32"),
                text("ipv6", "本机 IPv6", "可选"),
                text("public-key", "对端公钥", "必填 (Base64)"),
                text("pre-shared-key", "预共享密钥", "可选", true),
                text("allowed-ips", "Allowed IPs", "0.0.0.0/0;::/0"),
                text("mtu", "MTU", "1420")
            ]
        default:
            return []
        }
    }

    private var representedKeys: Set<String> {
        var keys = Set(Self.types.flatMap { fieldSpecs(for: $0.1).map(\.key) })
        keys.formUnion(Self.sharedOptionKeys)
        keys.formUnion(Self.carrierKeys)
        keys.insert("http-mask")
        keys.insert("http-mask-multiplex")
        return keys
    }

    private func refreshExtraParameters() {
        let extras = workingParameters.filter { !representedKeys.contains($0.key) }
        parametersView.string = extras.keys.sorted().map { "\($0)=\(extras[$0]!)" }.joined(separator: "\n")
    }

    private func parsedExtraParameters() throws -> [String: String] {
        var result: [String: String] = [:]
        for (offset, raw) in parametersView.string.components(separatedBy: .newlines).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            guard let equal = line.firstIndex(of: "=") else {
                throw EditorError.message("附加参数第 \(offset + 1) 行缺少 =")
            }
            let key = line[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { throw EditorError.message("附加参数第 \(offset + 1) 行键名为空") }
            guard !representedKeys.contains(key) else {
                throw EditorError.message("参数 \(key) 已在上方表单中提供，请勿重复填写")
            }
            guard result[key] == nil else { throw EditorError.message("参数 \(key) 重复") }
            result[key] = value
        }
        return result
    }

    private func collectCredentialFields() {
        for (key, field) in credentialTextFields {
            let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if value.isEmpty { workingParameters.removeValue(forKey: key) }
            else { workingParameters[key] = value }
        }
        for (key, popup) in credentialPopups {
            let value = (popup.selectedItem?.representedObject as? String ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if value.isEmpty { workingParameters.removeValue(forKey: key) }
            else { workingParameters[key] = value }
        }
        for (key, toggle) in credentialToggles {
            workingParameters[key] = (toggle.state == .on) ? "true" : "false"
        }
    }

    private func transportParameters(for type: String) -> [String: String] {
        if type == "mieru" {
            let selected = (credentialPopups["transport"]?.selectedItem?.representedObject as? String)
                ?? (transportPopup.selectedItem?.representedObject as? String)
                ?? "TCP"
            return ["transport": selected.uppercased()]
        }
        guard Self.usesV2RayCarriers(for: type) else { return [:] }
        func text(_ field: NSTextField) -> String {
            field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        var result: [String: String] = [:]
        let network = transportPopup.selectedItem?.representedObject as? String ?? "tcp"
        if network != "tcp" { result["network"] = network }
        switch network {
        case "ws":
            if !text(wsPathField).isEmpty { result["ws-path"] = text(wsPathField) }
            if !text(wsHostField).isEmpty { result["ws-host"] = text(wsHostField) }
        case "grpc":
            if !text(grpcServiceField).isEmpty {
                result["grpc-service-name"] = text(grpcServiceField)
            }
        case "xhttp":
            if !text(xhttpPathField).isEmpty { result["xhttp-path"] = text(xhttpPathField) }
            if !text(xhttpHostField).isEmpty { result["xhttp-host"] = text(xhttpHostField) }
        case "kcp":
            if !text(kcpHeaderField).isEmpty { result["kcp-header"] = text(kcpHeaderField) }
            if !text(kcpSeedField).isEmpty { result["kcp-seed"] = text(kcpSeedField) }
            if !text(kcpMTUField).isEmpty { result["kcp-mtu"] = text(kcpMTUField) }
            if let value = kcpAuthenticatorPopup.selectedItem?.representedObject as? String,
               !value.isEmpty {
                result["kcp-authenticator"] = value
            }
        default: break
        }
        return result
    }

    private func captureVisibleParameters(type: String) {
        collectCredentialFields()
        if let extras = try? parsedExtraParameters() {
            for (key, value) in extras { workingParameters[key] = value }
        }
        for key in Self.sharedOptionKeys + Self.carrierKeys {
            workingParameters.removeValue(forKey: key)
        }
        if Self.usesTLSBox(for: type) {
            if tlsButton.state == .on, !Self.impliesMandatoryTLS(for: type) {
                workingParameters["tls"] = "true"
            }
            if skipCertificateButton.state == .on { workingParameters["skip-cert-verify"] = "true" }
            let sni = sniField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !sni.isEmpty { workingParameters[["vmess", "vless"].contains(type) ? "servername" : "sni"] = sni }
            let fingerprint = fingerprintField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !fingerprint.isEmpty, ["vmess", "vless", "trojan"].contains(type) {
                workingParameters["client-fingerprint"] = fingerprint
            }
            let alpn = alpnField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !alpn.isEmpty { workingParameters["alpn"] = alpn }
        }
        for (key, value) in transportParameters(for: type) { workingParameters[key] = value }
        if udpButton.isEnabled { workingParameters["udp"] = udpButton.state == .on ? "true" : "false" }
        if tfoButton.state == .on { workingParameters["tfo"] = "true" }
        if let value = ipVersionPopup.selectedItem?.representedObject as? String, !value.isEmpty {
            workingParameters["ip-version"] = value
        }
        if !interfaceField.stringValue.isEmpty { workingParameters["interface-name"] = interfaceField.stringValue }
        if Self.supportsUnderlyingProxy(for: type),
           let value = underlyingPopup.selectedItem?.representedObject as? String, !value.isEmpty {
            workingParameters["underlying-proxy"] = value
        }
    }

    private func collectedParameters() throws -> [String: String] {
        let type = selectedType
        collectCredentialFields()
        var result = try parsedExtraParameters()
        for spec in fieldSpecs(for: type) {
            let key = spec.key
            if let field = credentialTextFields[key] {
                let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
                if !value.isEmpty { result[key] = value }
            } else if let popup = credentialPopups[key] {
                let value = (popup.selectedItem?.representedObject as? String ?? "")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if !value.isEmpty { result[key] = value }
            } else if let toggle = credentialToggles[key] {
                result[key] = (toggle.state == .on) ? "true" : "false"
            }
        }
        if type == "sudoku", let customTables = workingParameters["custom-tables"], !customTables.isEmpty {
            result["custom-tables"] = customTables
        }
        if Self.usesTLSBox(for: type) {
            if tlsButton.state == .on, !Self.impliesMandatoryTLS(for: type) {
                result["tls"] = "true"
            }
            if skipCertificateButton.state == .on { result["skip-cert-verify"] = "true" }
            let sni = sniField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !sni.isEmpty { result[["vmess", "vless"].contains(type) ? "servername" : "sni"] = sni }
            let fingerprint = fingerprintField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !fingerprint.isEmpty, ["vmess", "vless", "trojan"].contains(type) {
                result["client-fingerprint"] = fingerprint
            }
            let alpn = alpnField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !alpn.isEmpty { result["alpn"] = alpn }
        }
        for (key, value) in transportParameters(for: type) { result[key] = value }
        if udpButton.isEnabled { result["udp"] = udpButton.state == .on ? "true" : "false" }
        if tfoButton.state == .on { result["tfo"] = "true" }
        if let ipVersion = ipVersionPopup.selectedItem?.representedObject as? String, !ipVersion.isEmpty {
            result["ip-version"] = ipVersion
        }
        let interface = interfaceField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !interface.isEmpty { result["interface-name"] = interface }
        if Self.supportsUnderlyingProxy(for: type),
           let underlying = underlyingPopup.selectedItem?.representedObject as? String, !underlying.isEmpty {
            result["underlying-proxy"] = underlying
        }
        return result
    }

    @objc private func typeChanged() {
        captureVisibleParameters(type: editingType)
        editingType = selectedType
        authenticationBox?.title = "\(selectedType.uppercased()) 协议配置"
        configureCredentialStack()
        populateCommonFields(type: selectedType)
        refreshExtraParameters()
        updateProtocolHelp()
        updateSectionVisibilityAndTransportControls()
    }

    @objc private func tlsToggled() {
        updateSectionVisibilityAndTransportControls()
    }

    @objc private func transportChanged() {
        if selectedType == "mieru",
           let val = transportPopup.selectedItem?.representedObject as? String,
           let authPopup = credentialPopups["transport"],
           let idx = authPopup.itemArray.firstIndex(where: { ($0.representedObject as? String) == val }) {
            authPopup.selectItem(at: idx)
        }
        updateSectionVisibilityAndTransportControls()
    }

    private func updateSectionVisibilityAndTransportControls() {
        let type = selectedType

        // 1. TLS Box visibility & sub-controls
        let showTLS = Self.usesTLSBox(for: type)
        tlsBoxRef?.isHidden = !showTLS
        if showTLS {
            let mandatoryTLS = Self.impliesMandatoryTLS(for: type)
            tlsButton.isHidden = mandatoryTLS
            let tlsActive = mandatoryTLS || tlsButton.state == .on
            skipCertificateButton.isEnabled = tlsActive
            sniField.isEnabled = tlsActive
            alpnField.isEnabled = tlsActive
            let supportsFP = ["vmess", "vless", "trojan"].contains(type)
            fingerprintRow?.isHidden = !supportsFP
            fingerprintField.isEnabled = tlsActive && supportsFP
        }

        // 2. Transport Box visibility & sub-rows
        let isV2Ray = Self.usesV2RayCarriers(for: type)
        let isMieru = (type == "mieru")
        transportBoxRef?.isHidden = !isV2Ray

        if isMieru {
            wsPathRow?.isHidden = true
            wsHostRow?.isHidden = true
            grpcRow?.isHidden = true
            xhttpRow?.isHidden = true
            kcpHeaderRow?.isHidden = true
            kcpAuthRow?.isHidden = true
            kcpHintField?.isHidden = true
        } else if isV2Ray {
            let network = transportPopup.selectedItem?.representedObject as? String ?? "tcp"
            wsPathRow?.isHidden = (network != "ws")
            wsHostRow?.isHidden = (network != "ws")
            grpcRow?.isHidden = (network != "grpc")
            xhttpRow?.isHidden = (network != "xhttp")
            let kcp = (network == "kcp")
            kcpHeaderRow?.isHidden = !kcp
            kcpAuthRow?.isHidden = !kcp
            kcpHintField?.isHidden = !kcp
        }

        // 3. Chain Box visibility
        chainBoxRef?.isHidden = !Self.supportsUnderlyingProxy(for: type)
    }

    private func updateProtocolHelp() {
        let required: String
        switch selectedType {
        case "http", "https", "socks5", "socks5-tls": required = "用户名和密码均可选"
        case "ss": required = "选择加密算法并填写密码，可选 simple-obfs 混淆"
        case "ssr": required = "选择加密算法、协议插件与混淆插件并填写密码"
        case "snell": required = "填写 PSK 密钥并选择协议版本"
        case "vmess", "vless": required = "填写 UUID；可在下方配置 TLS 与传输方式（TCP/WS/gRPC/XHTTP/mKCP）"
        case "trojan": required = "填写密码；默认启用 TLS，可在下方选择传输方式"
        case "anytls": required = "填写密码；基于 TLS 隧道传输"
        case "hysteria": required = "填写认证字符串、上传和下载带宽"
        case "hysteria2": required = "填写认证密码，可选 Salamander 混淆与端口跳跃"
        case "tuic": required = "使用 Token (v4)，或填写 UUID + 密码 (v5)"
        case "sudoku": required = "填写密钥 (Key)，选择 AEAD 加密、编码表方向与 HTTP 伪装策略（也可点击右上角直接粘贴 sudoku:// 链接自动填入）"
        case "mieru": required = "填写用户名与密码，选择 TCP 或 UDP 传输协议、多路复用级别与握手模式"
        case "trusttunnel": required = "填写用户名与密码，选择 HTTP/2 TLS 或 HTTP/3 QUIC 隧道模式"
        case "ssh": required = "填写用户名，以及密码或私钥路径"
        case "wireguard": required = "填写本机私钥、本机内网 IP 与对端 Peer 公钥"
        default: required = ""
        }
        protocolHelp.stringValue = required
        protocolHelp.font = .systemFont(ofSize: 10)
        protocolHelp.textColor = .secondaryLabelColor
    }

    @objc private func fillFromShareLinkPrompt() {
        guard let window else { return }
        ShareLinkImportSheetController.present(
            on: window,
            title: "从分享链接解析并填入",
            confirmTitle: "解析并填入",
            allowMultiple: false
        ) { [weak self] rawLink in
            self?.applyShareLinkString(rawLink)
        }
    }

    @discardableResult
    private func applyShareLinkString(_ rawLink: String) -> Bool {
        let trimmed = rawLink.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ShareLinkSubscription.looksLikeShareLinks(trimmed) else {
            errorLabel.stringValue = "未识别到受支持的分享链接格式"
            return false
        }
        do {
            let parsed = try ShareLinkSubscription.parse(trimmed)
            guard let policy = parsed.proxies.first else {
                errorLabel.stringValue = "分享链接中未能解析出有效节点"
                return false
            }
            let draft = SurgeProxyDraft(policy: policy)
            if nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                ShareLinkSubscription.looksLikeShareLinks(nameField.stringValue) {
                nameField.stringValue = draft.name
            }
            hostField.stringValue = draft.host
            portField.stringValue = String(draft.port)
            let targetType = draft.type.lowercased()
            if let idx = Self.types.firstIndex(where: { $0.1 == targetType }) {
                typePopup.selectItem(at: idx)
            }
            editingType = selectedType
            workingParameters = Self.normalizedParameters(draft.parameters, type: selectedType)
            authenticationBox?.title = "\(selectedType.uppercased()) 协议配置"
            configureCredentialStack()
            populateCommonFields(type: selectedType)
            refreshExtraParameters()
            updateProtocolHelp()
            updateSectionVisibilityAndTransportControls()
            errorLabel.stringValue = ""
            return true
        } catch {
            errorLabel.stringValue = "分享链接解析失败：\(error.localizedDescription)"
            return false
        }
    }

    @objc private func insertTemplate() {
        captureVisibleParameters(type: editingType)
        let templates: [String: [String: String]] = [
            "ss": ["cipher": "aes-128-gcm", "udp": "true"],
            "ssr": ["cipher": "aes-128-cfb", "protocol": "origin", "obfs": "plain"],
            "snell": ["version": "4", "reuse": "true", "udp": "true"],
            "vmess": ["alter-id": "0", "cipher": "auto", "tls": "true", "network": "ws", "ws-path": "/"],
            "vless": ["tls": "true"],
            "trojan": ["tls": "true", "udp": "true"],
            "anytls": ["tls": "true", "udp": "true"],
            "hysteria": ["up": "10 Mbps", "down": "50 Mbps"],
            "hysteria2": ["tls": "true"],
            "sudoku": ["aead-method": "chacha20-poly1305", "table-type": "up_ascii_down_entropy",
                       "padding-min": "2", "padding-max": "7", "enable-pure-downlink": "true",
                       "disable-http-mask": "false", "http-mask-mode": "auto", "multiplex": "off", "udp": "true"],
            "mieru": ["transport": "TCP", "multiplexing": "MULTIPLEXING_HIGH",
                      "handshake-mode": "HANDSHAKE_STANDARD", "mtu": "1400", "udp": "true"],
            "trusttunnel": ["tls": "true", "quic": "false", "udp": "true"],
            "tuic": ["congestion-controller": "bbr"],
            "wireguard": ["ip": "172.16.0.2/32", "allowed-ips": "0.0.0.0/0;::/0", "mtu": "1420"]
        ]
        for (key, value) in templates[selectedType] ?? [:] where workingParameters[key] == nil {
            workingParameters[key] = value
        }
        configureCredentialStack()
        populateCommonFields(type: selectedType)
        refreshExtraParameters()
        updateSectionVisibilityAndTransportControls()
    }

    @objc private func skipCertificateChanged() {
        refreshSkipCertificateWarning()
    }

    private func refreshSkipCertificateWarning() {
        let enabled = skipCertificateButton.state == .on
        skipCertificateWarning.isHidden = !enabled
        skipCertificateWarning.stringValue = enabled ? SkipCertificateWarning.headline : ""
        skipCertificateButton.contentTintColor = enabled ? .systemOrange : nil
    }

    @objc private func savePressed() {
        do {
            // If the user pasted a share link directly into the name or host field, auto-parse it first
            let rawHostInput = hostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let rawNameInput = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if ShareLinkSubscription.looksLikeShareLinks(rawHostInput) {
                guard applyShareLinkString(rawHostInput) else { return }
            } else if ShareLinkSubscription.looksLikeShareLinks(rawNameInput) {
                guard applyShareLinkString(rawNameInput) else { return }
            }

            if Self.usesTLSBox(for: selectedType), skipCertificateButton.state == .on, !originallySkippedCertificate {
                let confirm = NSAlert()
                confirm.messageText = "确认跳过服务器证书验证？"
                confirm.informativeText = SkipCertificateWarning.headline + "。只应在明确知道风险时使用。"
                confirm.alertStyle = .warning
                confirm.addButton(withTitle: "仍然保存")
                confirm.addButton(withTitle: "取消")
                if confirm.runModal() != .alertFirstButtonReturn { return }
            }
            let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if name != originalName, unavailableNames.contains(name) {
                throw EditorError.message("已经存在同名节点或策略组")
            }
            var portValue = UInt16(portField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            let params = try collectedParameters()
            if portValue == 0, let pr = params["port-range"] ?? params["ports"] {
                let firstPart = pr.split(separator: ",").first.map(String.init) ?? pr
                let startPart = firstPart.split(separator: "-").first.map(String.init) ?? firstPart
                portValue = UInt16(startPart.trimmingCharacters(in: .whitespaces)) ?? 0
            }
            guard portValue > 0 else {
                throw EditorError.message("端口必须为 1…65535")
            }
            let draft = SurgeProxyDraft(name: name, type: selectedType,
                                        host: hostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
                                        port: portValue,
                                        parameters: params)
            _ = try SurgeProfileDocument.definition(for: draft)
            try commit(draft)
            closeSheet(returnCode: .OK)
        } catch {
            errorLabel.stringValue = error.localizedDescription
        }
    }

    @objc private func cancelPressed() { closeSheet(returnCode: .cancel) }

    private func closeSheet(returnCode: NSApplication.ModalResponse) {
        guard let window else { return }
        if let parent = window.sheetParent { parent.endSheet(window, returnCode: returnCode) }
        else { window.close() }
    }

    private func formLabel(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = .systemFont(ofSize: 10.5, weight: .medium)
        label.textColor = .secondaryLabelColor
        return label
    }

    private func formRow(_ title: String, _ control: NSView) -> NSStackView {
        let label = formLabel(title + ":")
        label.alignment = .left
        label.widthAnchor.constraint(equalToConstant: 112).isActive = true
        control.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let row = NSStackView(views: [label, control])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 7
        return row
    }

    private func pairRow(_ first: NSView, _ second: NSView) -> NSStackView {
        let stack = NSStackView(views: [first, second])
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.distribution = .fillEqually
        stack.spacing = 6
        return stack
    }

    private func verticalStack(_ views: [NSView]) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 7
        for view in views { view.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true }
        return stack
    }

    private func moduleBox(title: String, content: NSView) -> NSBox {
        let box = NSBox()
        box.boxType = .primary
        box.title = title
        box.titlePosition = .atTop
        box.titleFont = .systemFont(ofSize: 11, weight: .semibold)
        guard let container = box.contentView else { return box }
        content.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 9),
            content.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -9),
            content.topAnchor.constraint(equalTo: container.topAnchor, constant: 8),
            content.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -9)
        ])
        return box
    }

    private func hint(_ text: String) -> NSTextField {
        let label = NSTextField(wrappingLabelWithString: text)
        label.font = .systemFont(ofSize: 9)
        label.textColor = .tertiaryLabelColor
        return label
    }

    private func isTrue(_ value: String?) -> Bool { Self.truthy(value) }

    private static func truthy(_ value: String?) -> Bool {
        guard let value else { return false }
        return ["true", "yes", "on", "1"].contains(value.lowercased())
    }

    private enum EditorError: LocalizedError {
        case message(String)
        var errorDescription: String? { if case .message(let value) = self { return value }; return nil }
    }
}

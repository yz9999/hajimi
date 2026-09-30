import AppKit
import HajimiCore

private final class EditorFlippedView: NSView {
    override var isFlipped: Bool { true }
}

/// Surge-style structured proxy editor. Common protocol options are exposed
/// as native controls, while unknown options remain available in a lossless
/// key/value module.
final class SurgeProxyEditorController: NSWindowController {
    private struct FieldSpec {
        let key: String
        let label: String
        let placeholder: String
        let secure: Bool
    }

    private let originalName: String?
    private let unavailableNames: Set<String>
    private let availableProxyNames: [String]
    private let commit: (SurgeProxyDraft) throws -> Void
    private var workingParameters: [String: String]
    private var originallySkippedCertificate = false
    private var editingType = "vmess"
    private var credentialFields: [String: NSTextField] = [:]

    private let nameField = NSTextField()
    private let typePopup = NSPopUpButton()
    private let hostField = NSTextField()
    private let portField = NSTextField()
    private let credentialStack = NSStackView()
    private weak var authenticationBox: NSBox?
    private let tlsButton = NSButton(checkboxWithTitle: "使用 TLS", target: nil, action: nil)
    private let skipCertificateButton = NSButton(checkboxWithTitle: "跳过服务器证书验证（不安全）", target: nil, action: nil)
    private let skipCertificateWarning = NSTextField(wrappingLabelWithString: SkipCertificateWarning.headline)
    private let sniField = NSTextField()
    private let fingerprintField = NSTextField()
    private let alpnField = NSTextField()
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
    private let underlyingPopup = NSPopUpButton()
    private let udpButton = NSButton(checkboxWithTitle: "UDP Relay", target: nil, action: nil)
    private let tfoButton = NSButton(checkboxWithTitle: "TCP Fast Open", target: nil, action: nil)
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
        ("Hysteria", "hysteria"), ("Hysteria 2", "hysteria2"),
        ("TUIC", "tuic"), ("SSH", "ssh"), ("WireGuard", "wireguard")
    ]

    /// Carriers the native core actually accepts. `mkcp` and `splithttp` are
    /// aliases the core also honours; only the canonical spelling is written.
    private static let transports: [(String, String)] = [
        ("TCP", "tcp"), ("WebSocket", "ws"), ("gRPC", "grpc"),
        ("XHTTP", "xhttp"), ("mKCP", "kcp")
    ]

    /// Every option owned by the transport module. All of them are cleared
    /// before the selected carrier's options are written back, so switching
    /// carriers cannot leave a stale key behind that the core would honour.
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
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 900, height: 820),
                            styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = isNew || draft == nil ? "新增代理" : "编辑代理"
        panel.minSize = NSSize(width: 820, height: 760)
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
        return result
    }

    private func buildUI(draft: SurgeProxyDraft?, adding: Bool) {
        guard let root = window?.contentView else { return }
        root.wantsLayer = true
        root.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor

        let title = NSTextField(labelWithString: adding ? "新增代理" : "编辑代理")
        title.font = .systemFont(ofSize: 16, weight: .semibold)
        title.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(title)

        nameField.stringValue = draft?.name ?? ""
        nameField.placeholderString = "节点名称"
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
        hostField.placeholderString = "server.example.com 或 IPv6"
        portField.stringValue = draft.map { String($0.port) } ?? "443"
        portField.placeholderString = "443"
        portField.alignment = .right
        portField.widthAnchor.constraint(equalToConstant: 82).isActive = true

        configureCommonControls()
        populateCommonFields(type: selectedType)
        configureCredentialStack()
        refreshExtraParameters()
        updateProtocolHelp()

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
        let authBox = moduleBox(title: "\(selectedType.uppercased()) 身份验证", content: authContent)
        authenticationBox = authBox
        authBox.identifier = NSUserInterfaceItemIdentifier("authenticationBox")

        let tlsContent = verticalStack([
            tlsButton,
            skipCertificateButton,
            skipCertificateWarning,
            formRow("自定义 TLS SNI", sniField),
            formRow("客户端指纹", fingerprintField),
            formRow("ALPN", alpnField)
        ])
        let tlsBox = moduleBox(title: "TLS", content: tlsContent)

        let transportContent = verticalStack([
            formRow("传输方式", transportPopup),
            formRow("WebSocket 路径", wsPathField),
            formRow("WebSocket Host", wsHostField),
            formRow("gRPC Service", grpcServiceField),
            formRow("XHTTP 路径 / Host", pairRow(xhttpPathField, xhttpHostField)),
            formRow("mKCP 伪装头 / Seed", pairRow(kcpHeaderField, kcpSeedField)),
            formRow("mKCP 认证层 / MTU", pairRow(kcpAuthenticatorPopup, kcpMTUField)),
            hint("mKCP 走 UDP 并自带可靠性。伪装头由接收端按长度盲剥、从不校验内容，" +
                 "填错的表现是两个方向每个包静默丢弃，与服务端不可达无法区分。认证层" +
                 "无法探测也不协商：拆分之前的服务端需选 SimpleAuthenticator。")
        ])
        let transportBox = moduleBox(title: "传输设置", content: transportContent)

        let chainBox = moduleBox(title: "代理链", content: verticalStack([
            formRow("跳板代理", underlyingPopup),
            hint("使用一个代理节点连接另一个节点；对应 Surge underlying-proxy。")
        ]))

        let networkBox = moduleBox(title: "网络与出站", content: verticalStack([
            udpButton,
            tfoButton,
            formRow("IP 版本", ipVersionPopup),
            formRow("指定网络设备", interfaceField),
            hint("网络设备可填写 en0、en1 或 VPN 接口名称；留空时使用自动选择。")
        ]))

        let template = NSButton(title: "填入当前协议模板", target: self,
                                action: #selector(insertTemplate))
        template.controlSize = .small
        let protocolBox = moduleBox(title: "协议选项", content: verticalStack([
            template,
            hint("常用的认证、TLS、传输、UDP 和代理链参数已拆分为表单。")
        ]))

        let extraScroll = NSScrollView()
        extraScroll.hasVerticalScroller = true
        extraScroll.borderType = .bezelBorder
        extraScroll.translatesAutoresizingMaskIntoConstraints = false
        extraScroll.heightAnchor.constraint(equalToConstant: 126).isActive = true
        parametersView.isRichText = false
        parametersView.isAutomaticQuoteSubstitutionEnabled = false
        parametersView.isAutomaticDashSubstitutionEnabled = false
        parametersView.font = .monospacedSystemFont(ofSize: 10.5, weight: .regular)
        parametersView.textContainerInset = NSSize(width: 7, height: 6)
        extraScroll.documentView = parametersView
        let extraBox = moduleBox(title: "更多参数", content: verticalStack([
            extraScroll,
            hint("每行 key=value。这里保留所有尚未映射到上方表单的 Surge 参数，" +
                 "例如 kcp-tti、kcp-congestion、kcp-header-domain、xhttp-mode。")
        ]))

        let left = verticalStack([serverBox, authBox, tlsBox, transportBox])
        let right = verticalStack([chainBox, networkBox, protocolBox, extraBox])
        left.alignment = .leading
        right.alignment = .leading
        let columns = NSStackView(views: [left, right])
        columns.orientation = .horizontal
        columns.alignment = .top
        columns.distribution = .fillEqually
        columns.spacing = 12
        columns.translatesAutoresizingMaskIntoConstraints = false

        root.addSubview(columns)
        left.widthAnchor.constraint(equalTo: right.widthAnchor).isActive = true

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
            title.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            title.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),
            topForm.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 42),
            topForm.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            topForm.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 15),
            divider.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            divider.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            divider.topAnchor.constraint(equalTo: topForm.bottomAnchor, constant: 15),
            columns.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 18),
            columns.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -18),
            columns.topAnchor.constraint(equalTo: divider.bottomAnchor, constant: 10),
            columns.bottomAnchor.constraint(lessThanOrEqualTo: footerDivider.topAnchor, constant: -9),
            footerDivider.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            footerDivider.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            footerDivider.bottomAnchor.constraint(equalTo: buttons.topAnchor, constant: -11),
            errorLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            errorLabel.trailingAnchor.constraint(lessThanOrEqualTo: buttons.leadingAnchor, constant: -12),
            errorLabel.centerYAnchor.constraint(equalTo: buttons.centerYAnchor),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -14)
        ])
        updateTransportControls()
    }

    private var selectedType: String {
        typePopup.selectedItem?.representedObject as? String ?? "vmess"
    }

    private func configureCommonControls() {
        for button in [tlsButton, skipCertificateButton, udpButton, tfoButton] {
            button.setButtonType(.switch)
            button.controlSize = .small
        }
        skipCertificateButton.target = self
        skipCertificateButton.action = #selector(skipCertificateChanged)
        skipCertificateButton.toolTip = SkipCertificateWarning.headline
        skipCertificateWarning.font = .systemFont(ofSize: 10, weight: .medium)
        skipCertificateWarning.textColor = .systemOrange
        skipCertificateWarning.isHidden = true
        transportPopup.removeAllItems()
        for (display, raw) in Self.transports {
            transportPopup.addItem(withTitle: display)
            transportPopup.lastItem?.representedObject = raw
        }
        transportPopup.target = self
        transportPopup.action = #selector(transportChanged)
        wsPathField.placeholderString = "/"
        wsHostField.placeholderString = "可选 Host"
        grpcServiceField.placeholderString = "service-name"
        xhttpPathField.placeholderString = "/tunnel"
        xhttpHostField.placeholderString = "可选 Host"
        // The camouflage names are decided by MKCPHeaderCamouflage, which
        // rejects an unknown one at configuration time with a clear message.
        // Duplicating the list here would only drift from the core.
        kcpHeaderField.placeholderString = "none / dtls / srtp …"
        kcpSeedField.placeholderString = "可选"
        kcpMTUField.placeholderString = "1350"
        sniField.placeholderString = "可选，默认使用服务器地址"
        fingerprintField.placeholderString = "例如 chrome"
        alpnField.placeholderString = "例如 h2;http/1.1"
        interfaceField.placeholderString = "自动"

        // Unlike the camouflage, this set is closed and a wrong choice fails
        // silently on every datagram, so it must not be free text.
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

    private func populateCommonFields(type: String) {
        let tlsEnabled = type == "https" || type == "socks5-tls" || isTrue(workingParameters["tls"])
        tlsButton.state = tlsEnabled ? .on : .off
        tlsButton.isEnabled = type != "https" && type != "socks5-tls"
        skipCertificateButton.state = isTrue(workingParameters["skip-cert-verify"] ??
                                             workingParameters["skip-common-name-verify"]) ? .on : .off
        refreshSkipCertificateWarning()
        sniField.stringValue = workingParameters["servername"] ?? workingParameters["sni"] ?? ""
        fingerprintField.stringValue = workingParameters["client-fingerprint"] ??
            workingParameters["fingerprint"] ?? ""
        alpnField.stringValue = workingParameters["alpn"] ?? ""
        var network = workingParameters["network"]?.lowercased() ?? "tcp"
        if isTrue(workingParameters["ws"]) { network = "ws" }
        // Only infer the carrier when none was stated. Overriding an explicit
        // network would show a ws or kcp node carrying a leftover service name
        // as gRPC, and saving would then make that display the truth.
        if network == "tcp", workingParameters["grpc-service-name"] != nil { network = "grpc" }
        if network == "mkcp" { network = "kcp" }
        if network == "splithttp" { network = "xhttp" }
        transportPopup.selectItem(at: Self.transports.firstIndex { $0.1 == network } ?? 0)
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
        credentialFields.removeAll(keepingCapacity: true)
        credentialStack.orientation = .vertical
        credentialStack.alignment = .leading
        credentialStack.spacing = 7
        for spec in fieldSpecs(for: selectedType) {
            let field: NSTextField = spec.secure ? NSSecureTextField() : NSTextField()
            field.stringValue = workingParameters[spec.key] ?? ""
            field.placeholderString = spec.placeholder
            field.controlSize = .small
            credentialFields[spec.key] = field
            let row = formRow(spec.label, field)
            credentialStack.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: credentialStack.widthAnchor).isActive = true
        }
    }

    private func fieldSpecs(for type: String) -> [FieldSpec] {
        func f(_ key: String, _ label: String, _ placeholder: String = "", _ secure: Bool = false) -> FieldSpec {
            FieldSpec(key: key, label: label, placeholder: placeholder, secure: secure)
        }
        switch type {
        case "http", "https", "socks5", "socks5-tls":
            return [f("username", "用户名", "可选"), f("password", "密码", "可选", true)]
        case "ss":
            return [f("cipher", "加密方式", "aes-128-gcm"), f("password", "密码", "必填", true),
                    f("obfs", "混淆", "可选"), f("obfs-host", "混淆 Host", "可选")]
        case "ssr":
            return [f("cipher", "加密方式", "chacha20-ietf"), f("password", "密码", "必填", true),
                    f("protocol", "协议", "origin"), f("obfs", "混淆", "plain")]
        case "snell":
            return [f("psk", "PSK", "必填", true), f("version", "版本", "4"),
                    f("obfs-mode", "混淆模式", "可选"), f("obfs-host", "混淆 Host", "可选")]
        case "vmess":
            return [f("uuid", "ID / UUID", "必填", true), f("alter-id", "Alter ID", "0")]
        case "vless":
            return [f("uuid", "ID / UUID", "必填", true), f("flow", "Flow", "可选")]
        case "trojan", "anytls":
            return [f("password", "密码", "必填", true)]
        case "hysteria":
            return [f("auth-str", "认证字符串", "必填", true), f("up", "上传带宽", "10 Mbps"),
                    f("down", "下载带宽", "50 Mbps")]
        case "hysteria2":
            return [f("password", "密码", "必填", true), f("obfs", "混淆", "可选"),
                    f("obfs-password", "混淆密码", "可选", true)]
        case "tuic":
            return [f("token", "Token", "与 UUID 方式二选一", true),
                    f("uuid", "UUID", "与 Token 方式二选一", true),
                    f("password", "密码", "UUID 方式必填", true),
                    f("congestion-controller", "拥塞控制", "bbr")]
        case "ssh":
            return [f("username", "用户名", "必填"), f("password", "密码", "密码或私钥二选一", true),
                    f("private-key", "私钥路径", "例如 ~/.ssh/id_ed25519")]
        case "wireguard":
            return [f("private-key", "私钥", "必填", true), f("ip", "本机地址", "172.16.0.2/32"),
                    f("public-key", "Peer 公钥", "必填", true),
                    f("allowed-ips", "Allowed IPs", "0.0.0.0/0;::/0")]
        default: return []
        }
    }

    private var representedKeys: Set<String> {
        var keys = Set(Self.types.flatMap { fieldSpecs(for: $0.1).map(\.key) })
        keys.formUnion(Self.sharedOptionKeys)
        keys.formUnion(Self.carrierKeys)
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
                throw EditorError.message("更多参数第 \(offset + 1) 行缺少 =")
            }
            let key = line[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { throw EditorError.message("更多参数第 \(offset + 1) 行键名为空") }
            guard !representedKeys.contains(key) else {
                throw EditorError.message("参数 \(key) 已在上方表单中，请勿重复填写")
            }
            guard result[key] == nil else { throw EditorError.message("参数 \(key) 重复") }
            result[key] = value
        }
        return result
    }

    private func collectCredentialFields() {
        for (key, field) in credentialFields {
            let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if value.isEmpty { workingParameters.removeValue(forKey: key) }
            else { workingParameters[key] = value }
        }
    }

    /// Options belonging to the selected carrier only. The caller clears every
    /// key in `carrierKeys` first, so a node moved from ws to kcp cannot keep a
    /// ws-path that the core would still act on.
    private func transportParameters() -> [String: String] {
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
        if tlsButton.state == .on, type != "https", type != "socks5-tls" {
            workingParameters["tls"] = "true"
        }
        if skipCertificateButton.state == .on { workingParameters["skip-cert-verify"] = "true" }
        let sni = sniField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !sni.isEmpty { workingParameters[["vmess", "vless"].contains(type) ? "servername" : "sni"] = sni }
        let fingerprint = fingerprintField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !fingerprint.isEmpty { workingParameters["client-fingerprint"] = fingerprint }
        let alpn = alpnField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !alpn.isEmpty { workingParameters["alpn"] = alpn }
        for (key, value) in transportParameters() { workingParameters[key] = value }
        if udpButton.isEnabled { workingParameters["udp"] = udpButton.state == .on ? "true" : "false" }
        if tfoButton.state == .on { workingParameters["tfo"] = "true" }
        if let value = ipVersionPopup.selectedItem?.representedObject as? String, !value.isEmpty {
            workingParameters["ip-version"] = value
        }
        if !interfaceField.stringValue.isEmpty { workingParameters["interface-name"] = interfaceField.stringValue }
        if let value = underlyingPopup.selectedItem?.representedObject as? String, !value.isEmpty {
            workingParameters["underlying-proxy"] = value
        }
    }

    private func collectedParameters() throws -> [String: String] {
        collectCredentialFields()
        var result = try parsedExtraParameters()
        for (key, field) in credentialFields {
            let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !value.isEmpty { result[key] = value }
        }
        if tlsButton.state == .on, selectedType != "https", selectedType != "socks5-tls" {
            result["tls"] = "true"
        }
        if skipCertificateButton.state == .on { result["skip-cert-verify"] = "true" }
        let sni = sniField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !sni.isEmpty { result[["vmess", "vless"].contains(selectedType) ? "servername" : "sni"] = sni }
        let fingerprint = fingerprintField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !fingerprint.isEmpty { result["client-fingerprint"] = fingerprint }
        let alpn = alpnField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !alpn.isEmpty { result["alpn"] = alpn }
        for (key, value) in transportParameters() { result[key] = value }
        if udpButton.isEnabled { result["udp"] = udpButton.state == .on ? "true" : "false" }
        if tfoButton.state == .on { result["tfo"] = "true" }
        if let ipVersion = ipVersionPopup.selectedItem?.representedObject as? String, !ipVersion.isEmpty {
            result["ip-version"] = ipVersion
        }
        let interface = interfaceField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !interface.isEmpty { result["interface-name"] = interface }
        if let underlying = underlyingPopup.selectedItem?.representedObject as? String, !underlying.isEmpty {
            result["underlying-proxy"] = underlying
        }
        return result
    }

    @objc private func typeChanged() {
        captureVisibleParameters(type: editingType)
        editingType = selectedType
        authenticationBox?.title = "\(selectedType.uppercased()) 身份验证"
        configureCredentialStack()
        populateCommonFields(type: selectedType)
        refreshExtraParameters()
        updateProtocolHelp()
        updateTransportControls()
    }

    @objc private func transportChanged() { updateTransportControls() }

    private func updateTransportControls() {
        let network = transportPopup.selectedItem?.representedObject as? String ?? "tcp"
        wsPathField.isEnabled = network == "ws"
        wsHostField.isEnabled = network == "ws"
        grpcServiceField.isEnabled = network == "grpc"
        xhttpPathField.isEnabled = network == "xhttp"
        xhttpHostField.isEnabled = network == "xhttp"
        let kcp = network == "kcp"
        kcpHeaderField.isEnabled = kcp
        kcpSeedField.isEnabled = kcp
        kcpMTUField.isEnabled = kcp
        kcpAuthenticatorPopup.isEnabled = kcp
    }

    private func updateProtocolHelp() {
        let required: String
        switch selectedType {
        case "http", "https", "socks5", "socks5-tls": required = "用户名和密码均可选"
        case "ss": required = "需要加密方式与密码"
        case "ssr": required = "需要加密、密码、协议和混淆"
        case "snell": required = "需要 PSK"
        case "vmess", "vless": required = "需要 UUID"
        case "trojan", "anytls", "hysteria2": required = "需要密码"
        case "hysteria": required = "需要认证、上传和下载带宽"
        case "tuic": required = "使用 Token，或 UUID + 密码"
        case "ssh": required = "需要用户名，以及密码或私钥"
        case "wireguard": required = "需要私钥、本机地址和 Peer 公钥"
        default: required = ""
        }
        protocolHelp.stringValue = required
        protocolHelp.font = .systemFont(ofSize: 9.5)
        protocolHelp.textColor = .secondaryLabelColor
    }

    @objc private func insertTemplate() {
        captureVisibleParameters(type: editingType)
        let templates: [String: [String: String]] = [
            "ss": ["cipher": "aes-128-gcm", "udp": "true"],
            "ssr": ["cipher": "chacha20-ietf", "protocol": "origin", "obfs": "plain"],
            "snell": ["version": "4", "udp": "true"],
            "vmess": ["alter-id": "0", "tls": "true", "network": "ws", "ws-path": "/"],
            "vless": ["tls": "true"],
            "trojan": ["tls": "true", "udp": "true"],
            "anytls": ["tls": "true", "udp": "true"],
            "hysteria": ["up": "10 Mbps", "down": "50 Mbps"],
            "hysteria2": ["tls": "true"],
            "tuic": ["congestion-controller": "bbr"],
            "wireguard": ["ip": "172.16.0.2/32", "allowed-ips": "0.0.0.0/0;::/0"]
        ]
        for (key, value) in templates[selectedType] ?? [:] where workingParameters[key] == nil {
            workingParameters[key] = value
        }
        populateCommonFields(type: selectedType)
        configureCredentialStack()
        refreshExtraParameters()
        updateTransportControls()
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
            if skipCertificateButton.state == .on, !originallySkippedCertificate {
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
            guard let port = UInt16(portField.stringValue), port > 0 else {
                throw EditorError.message("端口必须为 1…65535")
            }
            let draft = SurgeProxyDraft(name: name, type: selectedType,
                                        host: hostField.stringValue, port: port,
                                        parameters: try collectedParameters())
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
        label.widthAnchor.constraint(equalToConstant: 100).isActive = true
        control.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let row = NSStackView(views: [label, control])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 7
        return row
    }

    /// Two controls sharing one row. The transport module would otherwise grow
    /// past the panel, and the columns are pinned with a lessThanOrEqual bottom
    /// constraint — overflow drops the last module rather than scrolling.
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
        box.titleFont = .systemFont(ofSize: 10.5, weight: .medium)
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

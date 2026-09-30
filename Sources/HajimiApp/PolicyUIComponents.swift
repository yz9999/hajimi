import AppKit
import Network
import HajimiCore

final class ContextCollectionView: NSCollectionView {
    var contextMenuProvider: ((IndexPath) -> NSMenu?)?

    override func menu(for event: NSEvent) -> NSMenu? {
        let point = convert(event.locationInWindow, from: nil)
        guard let indexPath = indexPathForItem(at: point) else { return nil }
        selectionIndexPaths = [indexPath]
        return contextMenuProvider?(indexPath)
    }
}

enum NodeLatency: Equatable {
    case untested
    case testing
    case success(Int)
    case failed

    var text: String {
        switch self {
        case .untested: return "未测试"
        case .testing: return "测试中…"
        case .success(let milliseconds): return "\(milliseconds) ms"
        case .failed: return "连接失败"
        }
    }

    var color: NSColor {
        switch self {
        case .untested: return .tertiaryLabelColor
        case .testing: return .systemBlue
        case .success(let value):
            if value < 180 { return .systemGreen }
            if value < 500 { return .systemOrange }
            return .systemRed
        case .failed: return .systemRed
        }
    }
}

final class TCPNodeLatencyProbe {
    static func measure(host: String, port: UInt16, timeout: TimeInterval = 4,
                        completion: @escaping (Result<Int, Error>) -> Void) {
        let queue = DispatchQueue(label: "app.hajimi.latency.\(UUID().uuidString)")
        let start = DispatchTime.now()
        let connection = NWConnection(host: NWEndpoint.Host(host),
                                      port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        var finished = false
        func finish(_ result: Result<Int, Error>) {
            guard !finished else { return }
            finished = true
            connection.stateUpdateHandler = nil
            connection.cancel()
            DispatchQueue.main.async { completion(result) }
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let elapsed = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
                finish(.success(max(1, Int(Double(elapsed) / 1_000_000))))
            case .failed(let error): finish(.failure(error))
            case .cancelled where !finished:
                finish(.failure(NWError.posix(.ECANCELED)))
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) {
            finish(.failure(NWError.posix(.ETIMEDOUT)))
        }
    }
}

final class ProxyNodeCellView: NSTableCellView {
    private let card = NSView()
    private let iconBackground = NSView()
    private let icon = NSImageView()
    private let nameLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(labelWithString: "")
    private let latencyLabel = NSTextField(labelWithString: "")
    private let useButton = NSButton(title: "使用", target: nil, action: nil)
    private var onUse: (() -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        card.translatesAutoresizingMaskIntoConstraints = false
        card.wantsLayer = true
        card.layer?.cornerRadius = 8
        card.layer?.borderWidth = 0.5
        addSubview(card)

        iconBackground.translatesAutoresizingMaskIntoConstraints = false
        iconBackground.wantsLayer = true
        iconBackground.layer?.cornerRadius = 8
        card.addSubview(iconBackground)
        icon.image = NSImage(systemSymbolName: "point.3.connected.trianglepath.dotted",
                             accessibilityDescription: "节点")
        icon.contentTintColor = .white
        icon.symbolConfiguration = .init(pointSize: 16, weight: .medium)
        icon.translatesAutoresizingMaskIntoConstraints = false
        iconBackground.addSubview(icon)

        nameLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        nameLabel.lineBreakMode = .byTruncatingTail
        detailLabel.font = .monospacedSystemFont(ofSize: 10.5, weight: .regular)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.lineBreakMode = .byTruncatingMiddle
        let labels = NSStackView(views: [nameLabel, detailLabel])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 3
        labels.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(labels)

        latencyLabel.font = .monospacedDigitSystemFont(ofSize: 10.5, weight: .medium)
        latencyLabel.alignment = .right
        latencyLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(latencyLabel)

        useButton.bezelStyle = .rounded
        useButton.controlSize = .small
        useButton.target = self
        useButton.action = #selector(usePressed)
        useButton.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(useButton)

        NSLayoutConstraint.activate([
            card.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            card.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            card.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            card.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4),
            iconBackground.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 12),
            iconBackground.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            iconBackground.widthAnchor.constraint(equalToConstant: 38),
            iconBackground.heightAnchor.constraint(equalToConstant: 38),
            icon.centerXAnchor.constraint(equalTo: iconBackground.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: iconBackground.centerYAnchor),
            labels.leadingAnchor.constraint(equalTo: iconBackground.trailingAnchor, constant: 11),
            labels.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            labels.trailingAnchor.constraint(lessThanOrEqualTo: latencyLabel.leadingAnchor, constant: -10),
            latencyLabel.trailingAnchor.constraint(equalTo: useButton.leadingAnchor, constant: -10),
            latencyLabel.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            latencyLabel.widthAnchor.constraint(equalToConstant: 70),
            useButton.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -10),
            useButton.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            useButton.widthAnchor.constraint(equalToConstant: 58)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(policy: ProxyPolicy, latency: NodeLatency, isActive: Bool,
                   onUse: @escaping () -> Void) {
        nameLabel.stringValue = policy.name
        let baseType = (policy.adapterType ?? policy.kind.rawValue).uppercased()
        let type = NativeOutboundFactory.supports(policy) ? baseType + " · 原生" : baseType
        let portText = policy.port.map { String($0) } ?? "—"
        let endpoint = policy.host.map { "\($0):\(portText)" } ?? "内建策略"
        if policy.skipsCertificateVerification {
            detailLabel.stringValue = "\(type)  ·  \(endpoint)  ·  跳过证书验证"
            detailLabel.textColor = .systemOrange
            detailLabel.toolTip = SkipCertificateWarning.headline
        } else {
            detailLabel.stringValue = "\(type)  ·  \(endpoint)"
            detailLabel.textColor = .secondaryLabelColor
            detailLabel.toolTip = endpoint
        }
        latencyLabel.stringValue = latency.text
        latencyLabel.textColor = latency.color
        useButton.title = isActive ? "使用中" : "使用"
        useButton.isEnabled = !isActive
        self.onUse = onUse

        let palette: [NSColor] = [.systemIndigo, .systemBlue, .systemPurple, .systemTeal,
                                  .systemPink, .systemOrange]
        let hash = policy.name.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) & 0x7fffffff }
        iconBackground.layer?.backgroundColor = palette[hash % palette.count].cgColor
        card.layer?.backgroundColor = (isActive
            ? NSColor.systemGreen.withAlphaComponent(0.12)
            : NSColor.controlBackgroundColor).cgColor
        card.layer?.borderColor = (isActive
            ? NSColor.systemGreen.withAlphaComponent(0.72)
            : NSColor.separatorColor).cgColor
        card.layer?.borderWidth = isActive ? 1.2 : 0.5
    }

    @objc private func usePressed() { onUse?() }
}

final class PolicyGroupCellView: NSTableCellView {
    private let card = NSView()
    private let nameLabel = NSTextField(labelWithString: "")
    private let kindLabel = NSTextField(labelWithString: "")
    private let popup = NSPopUpButton()
    private var members: [String] = []
    private var onSelection: ((String?) -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        card.translatesAutoresizingMaskIntoConstraints = false
        card.wantsLayer = true
        card.layer?.cornerRadius = 8
        card.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        card.layer?.borderColor = NSColor.separatorColor.cgColor
        card.layer?.borderWidth = 0.5
        addSubview(card)

        nameLabel.font = .systemFont(ofSize: 12.5, weight: .semibold)
        nameLabel.lineBreakMode = .byTruncatingTail
        kindLabel.font = .systemFont(ofSize: 10.5)
        kindLabel.textColor = .secondaryLabelColor
        let labels = NSStackView(views: [nameLabel, kindLabel])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 2
        labels.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(labels)

        popup.controlSize = .small
        popup.target = self
        popup.action = #selector(selectionChanged)
        popup.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(popup)
        NSLayoutConstraint.activate([
            card.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            card.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            card.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            card.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4),
            labels.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 13),
            labels.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            labels.trailingAnchor.constraint(lessThanOrEqualTo: popup.leadingAnchor, constant: -10),
            popup.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -12),
            popup.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            popup.widthAnchor.constraint(greaterThanOrEqualToConstant: 145)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(group: PolicyGroup, selected: String?,
                   onSelection: @escaping (String?) -> Void) {
        nameLabel.stringValue = group.name
        switch group.kind {
        case .select: kindLabel.stringValue = "手动选择 · \(group.members.count) 个成员"
        case .loadBalance: kindLabel.stringValue = "负载均衡 · 可临时固定成员"
        case .urlTest: kindLabel.stringValue = "URL 测试 · 可临时固定成员"
        case .fallback: kindLabel.stringValue = "故障转移 · 可临时固定成员"
        case .smart: kindLabel.stringValue = "Smart · 按延迟自动选择"
        case .subnet: kindLabel.stringValue = "子网 · 可临时固定成员"
        }
        members = group.members
        popup.removeAllItems()
        popup.addItem(withTitle: group.kind == .select ? "配置默认" : "自动（按组策略）")
        popup.menu?.items.first?.representedObject = NSNull()
        for member in members {
            popup.addItem(withTitle: member)
            popup.lastItem?.representedObject = member
        }
        if let selected, let index = members.firstIndex(of: selected) {
            popup.selectItem(at: index + 1)
        } else {
            popup.selectItem(at: 0)
        }
        popup.isEnabled = !members.isEmpty
        self.onSelection = onSelection
    }

    @objc private func selectionChanged() {
        guard popup.indexOfSelectedItem > 0 else { onSelection?(nil); return }
        onSelection?(popup.selectedItem?.representedObject as? String)
    }
}

final class ProxyCardCollectionItem: NSCollectionViewItem {
    static let identifier = NSUserInterfaceItemIdentifier("ProxyCardCollectionItem")

    private let typeLabel = NSTextField(labelWithString: "")
    private let nameLabel = NSTextField(labelWithString: "")
    private let latencyLabel = NSTextField(labelWithString: "")
    private let endpointLabel = NSTextField(labelWithString: "")
    private var onEdit: (() -> Void)?

    override func loadView() {
        let card = NSView()
        card.wantsLayer = true
        card.layer?.cornerRadius = 8
        card.layer?.borderWidth = 0.7
        view = card

        typeLabel.font = .systemFont(ofSize: 9.5, weight: .medium)
        typeLabel.textColor = .tertiaryLabelColor
        typeLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(typeLabel)
        nameLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        nameLabel.lineBreakMode = .byTruncatingTail
        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(nameLabel)
        endpointLabel.font = .monospacedSystemFont(ofSize: 8.5, weight: .regular)
        endpointLabel.textColor = .tertiaryLabelColor
        endpointLabel.lineBreakMode = .byTruncatingMiddle
        endpointLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(endpointLabel)
        latencyLabel.font = .monospacedDigitSystemFont(ofSize: 9.5, weight: .medium)
        latencyLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(latencyLabel)
        let doubleClick = NSClickGestureRecognizer(target: self, action: #selector(doubleClicked))
        doubleClick.numberOfClicksRequired = 2
        card.addGestureRecognizer(doubleClick)

        NSLayoutConstraint.activate([
            typeLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 10),
            typeLabel.topAnchor.constraint(equalTo: card.topAnchor, constant: 8),
            typeLabel.trailingAnchor.constraint(lessThanOrEqualTo: card.trailingAnchor, constant: -9),
            nameLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 10),
            nameLabel.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -9),
            nameLabel.topAnchor.constraint(equalTo: typeLabel.bottomAnchor, constant: 3),
            endpointLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 10),
            endpointLabel.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -9),
            endpointLabel.topAnchor.constraint(equalTo: nameLabel.bottomAnchor, constant: 3),
            latencyLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 10),
            latencyLabel.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -8)
        ])
    }

    func configure(policy: ProxyPolicy, latency: NodeLatency, active: Bool,
                   onEdit: @escaping () -> Void) {
        let baseType = (policy.adapterType ?? policy.kind.rawValue).uppercased()
        var typeText = NativeOutboundFactory.supports(policy)
            ? baseType + " · 原生" : baseType
        if policy.skipsCertificateVerification {
            typeText += " · 跳过证书"
            typeLabel.textColor = .systemOrange
        } else {
            typeLabel.textColor = .tertiaryLabelColor
        }
        typeLabel.stringValue = typeText
        typeLabel.toolTip = policy.skipsCertificateVerification
            ? SkipCertificateWarning.headline : nil
        nameLabel.stringValue = policy.name
        let portText = policy.port.map { String($0) } ?? "—"
        endpointLabel.stringValue = policy.host.map { "\($0):\(portText)" } ?? ""
        endpointLabel.toolTip = policy.skipsCertificateVerification
            ? SkipCertificateWarning.headline : endpointLabel.stringValue
        latencyLabel.stringValue = latency.text
        latencyLabel.textColor = latency.color
        self.onEdit = onEdit
        view.layer?.backgroundColor = (active
            ? NSColor.systemGreen.withAlphaComponent(0.15)
            : NSColor.controlBackgroundColor).cgColor
        view.layer?.borderColor = (active
            ? NSColor.systemGreen.withAlphaComponent(0.72)
            : NSColor.separatorColor).cgColor
        view.layer?.borderWidth = active ? 1.2 : 0.7
    }

    @objc private func doubleClicked() { onEdit?() }
}

final class AddProxyCollectionItem: NSCollectionViewItem {
    static let identifier = NSUserInterfaceItemIdentifier("AddProxyCollectionItem")
    private var onAdd: (() -> Void)?

    override func loadView() {
        let button = NSButton(title: "新增节点", target: self, action: #selector(addPressed))
        button.image = NSImage(systemSymbolName: "plus", accessibilityDescription: "新增节点")
        button.imagePosition = .imageAbove
        button.font = .systemFont(ofSize: 10.5, weight: .medium)
        button.contentTintColor = .secondaryLabelColor
        button.bezelStyle = .regularSquare
        button.wantsLayer = true
        button.layer?.cornerRadius = 8
        button.layer?.borderWidth = 0.7
        button.layer?.borderColor = NSColor.separatorColor.cgColor
        button.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.45).cgColor
        view = button
    }

    func configure(onAdd: @escaping () -> Void) { self.onAdd = onAdd }
    @objc private func addPressed() { onAdd?() }
}

final class AddGroupCollectionItem: NSCollectionViewItem {
    static let identifier = NSUserInterfaceItemIdentifier("AddGroupCollectionItem")
    private var onAdd: (() -> Void)?

    override func loadView() {
        let button = NSButton(title: "新增策略组", target: self, action: #selector(addPressed))
        button.image = NSImage(systemSymbolName: "plus", accessibilityDescription: "新增策略组")
        button.imagePosition = .imageAbove
        button.font = .systemFont(ofSize: 10.5, weight: .medium)
        button.contentTintColor = .secondaryLabelColor
        button.bezelStyle = .regularSquare
        button.wantsLayer = true
        button.layer?.cornerRadius = 8
        button.layer?.borderWidth = 0.7
        button.layer?.borderColor = NSColor.separatorColor.cgColor
        button.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.45).cgColor
        view = button
    }

    func configure(onAdd: @escaping () -> Void) { self.onAdd = onAdd }
    @objc private func addPressed() { onAdd?() }
}

final class GroupCardCollectionItem: NSCollectionViewItem {
    static let identifier = NSUserInterfaceItemIdentifier("GroupCardCollectionItem")
    private let kindLabel = NSTextField(labelWithString: "")
    private let nameLabel = NSTextField(labelWithString: "")
    private let popup = NSPopUpButton()
    private var onSelection: ((String?) -> Void)?
    private var isConfiguring = false

    override func loadView() {
        let card = NSView()
        card.wantsLayer = true
        card.layer?.cornerRadius = 8
        card.layer?.borderWidth = 0.7
        card.layer?.borderColor = NSColor.separatorColor.cgColor
        card.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        view = card
        kindLabel.font = .systemFont(ofSize: 9, weight: .medium)
        kindLabel.textColor = .tertiaryLabelColor
        kindLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(kindLabel)
        nameLabel.font = .systemFont(ofSize: 11.5, weight: .semibold)
        nameLabel.lineBreakMode = .byTruncatingTail
        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(nameLabel)
        popup.controlSize = .mini
        popup.font = .systemFont(ofSize: 9.5)
        popup.target = self
        popup.action = #selector(selectionChanged)
        popup.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(popup)
        NSLayoutConstraint.activate([
            kindLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 9),
            kindLabel.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -9),
            kindLabel.topAnchor.constraint(equalTo: card.topAnchor, constant: 7),
            nameLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 9),
            nameLabel.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -9),
            nameLabel.topAnchor.constraint(equalTo: kindLabel.bottomAnchor, constant: 3),
            popup.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 7),
            popup.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -7),
            popup.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -7)
        ])
    }

    func configure(group: PolicyGroup, selected: String?,
                   onSelection: @escaping (String?) -> Void) {
        isConfiguring = true
        defer { isConfiguring = false }
        switch group.kind {
        case .select: kindLabel.stringValue = "手动选择策略组"
        case .loadBalance: kindLabel.stringValue = "负载均衡策略组"
        case .urlTest: kindLabel.stringValue = "URL 测试策略组"
        case .fallback: kindLabel.stringValue = "故障转移策略组"
        case .smart: kindLabel.stringValue = "Smart 策略组"
        case .subnet: kindLabel.stringValue = "子网策略组"
        }
        nameLabel.stringValue = group.name
        popup.removeAllItems()
        popup.addItem(withTitle: group.kind == .select ? "配置默认" : "自动（按组策略）")
        popup.menu?.items.first?.representedObject = NSNull()
        for member in group.members {
            popup.addItem(withTitle: member)
            popup.lastItem?.representedObject = member
        }
        if let selected, let index = group.members.firstIndex(of: selected) {
            popup.selectItem(at: index + 1)
        } else {
            popup.selectItem(at: 0)
        }
        popup.isEnabled = !group.members.isEmpty
        self.onSelection = onSelection
    }

    @objc private func selectionChanged() {
        guard !isConfiguring else { return }
        if popup.indexOfSelectedItem <= 0 { onSelection?(nil) }
        else { onSelection?(popup.selectedItem?.representedObject as? String) }
    }
}

final class ProxyEditorSheetController: NSWindowController {
    private let originalName: String?
    private let unavailableNames: Set<String>
    private let nameField = NSTextField()
    private let typePopup = NSPopUpButton()
    private let hostField = NSTextField()
    private let portField = NSTextField()
    private let parametersView = NSTextView()
    private let helpLabel = NSTextField(wrappingLabelWithString: "")
    private let errorLabel = NSTextField(wrappingLabelWithString: "")
    private let commit: (SurgeProxyDraft) throws -> Void

    private static let types: [(String, String)] = [
        ("HTTP", "http"), ("HTTPS", "https"), ("SOCKS5", "socks5"),
        ("SOCKS5 TLS", "socks5-tls"), ("Shadowsocks", "ss"),
        ("ShadowsocksR", "ssr"), ("Snell", "snell"), ("VMess", "vmess"),
        ("VLESS", "vless"), ("Trojan", "trojan"), ("AnyTLS", "anytls"),
        ("Hysteria", "hysteria"), ("Hysteria 2", "hysteria2"),
        ("TUIC", "tuic"), ("SSH", "ssh"), ("WireGuard", "wireguard")
    ]

    init(draft: SurgeProxyDraft?, isNew: Bool = false, unavailableNames: Set<String>,
         commit: @escaping (SurgeProxyDraft) throws -> Void) {
        originalName = isNew ? nil : draft?.name
        self.unavailableNames = unavailableNames
        self.commit = commit
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 620, height: 610),
                            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = isNew || draft == nil ? "新增代理节点" : "编辑代理节点"
        super.init(window: panel)
        buildUI(draft: draft, isNew: isNew)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildUI(draft: SurgeProxyDraft?, isNew: Bool) {
        guard let root = window?.contentView else { return }
        root.wantsLayer = true
        root.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor

        let adding = isNew || draft == nil
        let title = NSTextField(labelWithString: adding ? "添加节点" : "节点设置")
        title.font = .systemFont(ofSize: 21, weight: .bold)
        let subtitle = NSTextField(labelWithString: "直接写入 Surge [Proxy]，保存后立即热重载")
        subtitle.font = .systemFont(ofSize: 11.5)
        subtitle.textColor = .secondaryLabelColor
        let heading = NSStackView(views: [title, subtitle])
        heading.orientation = .vertical
        heading.alignment = .leading
        heading.spacing = 3
        heading.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(heading)

        nameField.placeholderString = "例如：东京 01"
        nameField.stringValue = draft?.name ?? ""
        typePopup.target = self
        typePopup.action = #selector(typeChanged)
        for item in Self.types {
            typePopup.addItem(withTitle: item.0)
            typePopup.lastItem?.representedObject = item.1
        }
        if let type = draft?.type,
           let index = Self.types.firstIndex(where: { $0.1 == type.lowercased() }) {
            typePopup.selectItem(at: index)
        } else {
            typePopup.selectItem(at: Self.types.firstIndex(where: { $0.1 == "vmess" }) ?? 0)
        }
        hostField.placeholderString = "server.example.com 或 IPv6"
        hostField.stringValue = draft?.host ?? ""
        portField.placeholderString = "443"
        portField.stringValue = draft.map { String($0.port) } ?? "443"

        let grid = NSGridView(views: [
            [formLabel("名称"), nameField],
            [formLabel("协议"), typePopup],
            [formLabel("服务器"), hostField],
            [formLabel("端口"), portField]
        ])
        grid.rowSpacing = 10
        grid.columnSpacing = 12
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 0).width = 70
        grid.column(at: 1).xPlacement = .fill
        grid.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(grid)

        let parameterTitle = NSTextField(labelWithString: "协议参数")
        parameterTitle.font = .systemFont(ofSize: 12.5, weight: .semibold)
        let template = NSButton(title: "填入参数模板", target: self, action: #selector(insertTemplate))
        template.controlSize = .small
        let parameterHeader = NSStackView(views: [parameterTitle, NSView(), template])
        parameterHeader.orientation = .horizontal
        parameterHeader.alignment = .centerY
        parameterHeader.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(parameterHeader)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        parametersView.isRichText = false
        parametersView.isAutomaticQuoteSubstitutionEnabled = false
        parametersView.isAutomaticDashSubstitutionEnabled = false
        parametersView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        parametersView.textContainerInset = NSSize(width: 8, height: 8)
        parametersView.string = draft.map { parameterText($0.parameters) } ?? ""
        scroll.documentView = parametersView
        root.addSubview(scroll)

        helpLabel.font = .systemFont(ofSize: 10.5)
        helpLabel.textColor = .secondaryLabelColor
        helpLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(helpLabel)
        errorLabel.font = .systemFont(ofSize: 11, weight: .medium)
        errorLabel.textColor = .systemRed
        errorLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(errorLabel)

        let cancel = NSButton(title: "取消", target: self, action: #selector(cancelPressed))
        let save = NSButton(title: adding ? "添加并应用" : "保存并应用",
                            target: self, action: #selector(savePressed))
        save.bezelStyle = .rounded
        save.keyEquivalent = "\r"
        let buttons = NSStackView(views: [cancel, save])
        buttons.orientation = .horizontal
        buttons.spacing = 10
        buttons.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(buttons)

        NSLayoutConstraint.activate([
            heading.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 26),
            heading.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            heading.topAnchor.constraint(equalTo: root.topAnchor, constant: 24),
            grid.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 26),
            grid.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            grid.topAnchor.constraint(equalTo: heading.bottomAnchor, constant: 21),
            parameterHeader.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 26),
            parameterHeader.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            parameterHeader.topAnchor.constraint(equalTo: grid.bottomAnchor, constant: 20),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 26),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            scroll.topAnchor.constraint(equalTo: parameterHeader.bottomAnchor, constant: 7),
            scroll.heightAnchor.constraint(equalToConstant: 170),
            helpLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 27),
            helpLabel.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -27),
            helpLabel.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 7),
            errorLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 27),
            errorLabel.trailingAnchor.constraint(equalTo: buttons.leadingAnchor, constant: -12),
            errorLabel.centerYAnchor.constraint(equalTo: buttons.centerYAnchor),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -22)
        ])
        updateHelp()
    }

    private func formLabel(_ value: String) -> NSTextField {
        let label = NSTextField(labelWithString: value)
        label.font = .systemFont(ofSize: 12, weight: .medium)
        label.textColor = .secondaryLabelColor
        return label
    }

    private func parameterText(_ parameters: [String: String]) -> String {
        parameters.keys.sorted().map { "\($0)=\(parameters[$0]!)" }.joined(separator: "\n")
    }

    private var selectedType: String {
        typePopup.selectedItem?.representedObject as? String ?? "vmess"
    }

    @objc private func typeChanged() { updateHelp() }

    private func updateHelp() {
        let required: String
        switch selectedType {
        case "http", "https", "socks5", "socks5-tls": required = "可选：username、password"
        case "ss": required = "必需：cipher、password"
        case "ssr": required = "必需：cipher、password、protocol、obfs"
        case "snell": required = "必需：psk；常用：version=4"
        case "vmess", "vless": required = "必需：uuid"
        case "trojan", "anytls", "hysteria2": required = "必需：password"
        case "hysteria": required = "必需：auth-str、up、down"
        case "tuic": required = "必需：token，或 uuid + password"
        case "ssh": required = "必需：username，以及 password 或 private-key"
        case "wireguard": required = "必需：private-key、ip、public-key"
        default: required = ""
        }
        helpLabel.stringValue = "每行 key=value，无需加引号。\(required)。可选 TLS、SNI、WebSocket、UDP 与 underlying-proxy 等 Surge 参数。"
    }

    @objc private func insertTemplate() {
        let templates: [String: [(String, String)]] = [
            "http": [("username", ""), ("password", "")],
            "https": [("username", ""), ("password", "")],
            "socks5": [("username", ""), ("password", ""), ("udp", "true")],
            "socks5-tls": [("username", ""), ("password", ""), ("udp", "true")],
            "ss": [("cipher", "aes-128-gcm"), ("password", ""), ("udp", "true")],
            "ssr": [("cipher", "chacha20-ietf"), ("password", ""), ("protocol", "origin"), ("obfs", "plain")],
            "snell": [("psk", ""), ("version", "4"), ("udp", "true")],
            "vmess": [("uuid", ""), ("tls", "true"), ("servername", hostField.stringValue), ("network", "ws"), ("ws-path", "/")],
            "vless": [("uuid", ""), ("tls", "true"), ("servername", hostField.stringValue), ("network", "tcp")],
            "trojan": [("password", ""), ("sni", hostField.stringValue), ("udp", "true")],
            "anytls": [("password", ""), ("sni", hostField.stringValue), ("udp", "true")],
            "hysteria": [("auth-str", ""), ("up", "10 Mbps"), ("down", "50 Mbps"), ("sni", hostField.stringValue)],
            "hysteria2": [("password", ""), ("sni", hostField.stringValue)],
            "tuic": [("token", ""), ("sni", hostField.stringValue), ("congestion-controller", "bbr")],
            "ssh": [("username", ""), ("password", "")],
            "wireguard": [("private-key", ""), ("ip", "172.16.0.2/32"), ("public-key", ""), ("allowed-ips", "0.0.0.0/0;::/0")]
        ]
        var current = (try? parsedParameters()) ?? [:]
        for (key, value) in templates[selectedType] ?? [] where current[key] == nil { current[key] = value }
        parametersView.string = parameterText(current)
    }

    private func parsedParameters() throws -> [String: String] {
        var result: [String: String] = [:]
        for (offset, rawLine) in parametersView.string.components(separatedBy: .newlines).enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            guard let equal = line.firstIndex(of: "=") else {
                throw EditorError.message("参数第 \(offset + 1) 行缺少 =")
            }
            let key = line[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { throw EditorError.message("参数第 \(offset + 1) 行键名为空") }
            guard result[key] == nil else { throw EditorError.message("参数 \(key) 重复") }
            result[key] = value
        }
        return result
    }

    @objc private func savePressed() {
        do {
            let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if name != originalName, unavailableNames.contains(name) {
                throw EditorError.message("已经存在同名节点或策略组")
            }
            guard let port = UInt16(portField.stringValue), port > 0 else {
                throw EditorError.message("端口必须为 1…65535")
            }
            let draft = SurgeProxyDraft(name: name, type: selectedType,
                                        host: hostField.stringValue, port: port,
                                        parameters: try parsedParameters())
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

    private enum EditorError: LocalizedError {
        case message(String)
        var errorDescription: String? { if case .message(let value) = self { return value }; return nil }
    }
}

import AppKit
import HajimiCore
import HajimiUIComponents

private final class DiagnosticsMetricTileView: NSView {
    private let surface = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                            border: HajimiAppearance.subtleDivider,
                                            cornerRadius: 10)
    private let iconView = NSImageView()
    private let captionLabel = NSTextField(labelWithString: "")
    private let valueLabel = NSTextField(labelWithString: "--")

    init(caption: String, symbolName: String, tint: NSColor = HajimiAppearance.accentText) {
        super.init(frame: .zero)
        translatesAutoresizingMaskIntoConstraints = false
        surface.translatesAutoresizingMaskIntoConstraints = false
        addSubview(surface)

        iconView.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: caption)
        iconView.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 11, weight: .semibold)
        iconView.contentTintColor = tint
        iconView.translatesAutoresizingMaskIntoConstraints = false

        captionLabel.stringValue = caption
        captionLabel.font = .systemFont(ofSize: 10.5, weight: .medium)
        captionLabel.textColor = .secondaryLabelColor
        captionLabel.lineBreakMode = .byTruncatingTail
        captionLabel.translatesAutoresizingMaskIntoConstraints = false

        valueLabel.font = .monospacedDigitSystemFont(ofSize: 12.5, weight: .semibold)
        valueLabel.textColor = .labelColor
        valueLabel.lineBreakMode = .byTruncatingTail
        valueLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        valueLabel.translatesAutoresizingMaskIntoConstraints = false

        for sub in [iconView, captionLabel, valueLabel] {
            surface.addSubview(sub)
        }

        NSLayoutConstraint.activate([
            surface.leadingAnchor.constraint(equalTo: leadingAnchor),
            surface.trailingAnchor.constraint(equalTo: trailingAnchor),
            surface.topAnchor.constraint(equalTo: topAnchor),
            surface.bottomAnchor.constraint(equalTo: bottomAnchor),
            heightAnchor.constraint(equalToConstant: 52),
            iconView.leadingAnchor.constraint(equalTo: surface.leadingAnchor, constant: 11),
            iconView.topAnchor.constraint(equalTo: surface.topAnchor, constant: 9),
            iconView.widthAnchor.constraint(equalToConstant: 13),
            iconView.heightAnchor.constraint(equalToConstant: 13),
            captionLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 5),
            captionLabel.centerYAnchor.constraint(equalTo: iconView.centerYAnchor),
            captionLabel.trailingAnchor.constraint(lessThanOrEqualTo: surface.trailingAnchor, constant: -10),
            valueLabel.leadingAnchor.constraint(equalTo: surface.leadingAnchor, constant: 11),
            valueLabel.trailingAnchor.constraint(equalTo: surface.trailingAnchor, constant: -10),
            valueLabel.bottomAnchor.constraint(equalTo: surface.bottomAnchor, constant: -8)
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    func setValue(_ text: String, tint: NSColor? = nil) {
        let display = text.isEmpty ? "--" : text
        if valueLabel.stringValue != display { valueLabel.stringValue = display }
        if let tint { valueLabel.textColor = tint }
        else { valueLabel.textColor = .labelColor }
    }
}

private final class NetworkConnectivityDiagnosticRowView: NSView {
    private let surface = HajimiSurfaceView(fill: HajimiAppearance.elevatedPanel,
                                            border: HajimiAppearance.border,
                                            cornerRadius: 12)
    private let statusBar = HajimiSurfaceView(fill: .tertiaryLabelColor, cornerRadius: 2)
    private let iconContainer = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                                  border: HajimiAppearance.subtleDivider,
                                                  cornerRadius: 8)
    private let iconView = NSImageView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let kindTagBadge = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel, cornerRadius: 5)
    private let kindTagLabel = NSTextField(labelWithString: "")
    private let latencyTrack = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel, cornerRadius: 3)
    private let latencyFill = HajimiSurfaceView(fill: HajimiAppearance.accent, cornerRadius: 3)
    private var latencyFillWidthConstraint: NSLayoutConstraint?
    private let statusBadge = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel, cornerRadius: 6)
    private let statusLabel = NSTextField(labelWithString: "")
    private let detailWell = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                               border: HajimiAppearance.subtleDivider,
                                               cornerRadius: 8)
    private let detailLabel = NSTextField(wrappingLabelWithString: "")

    init() {
        super.init(frame: .zero)
        surface.translatesAutoresizingMaskIntoConstraints = false
        addSubview(surface)
        statusBar.translatesAutoresizingMaskIntoConstraints = false
        addSubview(statusBar)

        iconContainer.translatesAutoresizingMaskIntoConstraints = false
        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconView.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 13, weight: .semibold)
        iconContainer.addSubview(iconView)
        addSubview(iconContainer)

        titleLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        titleLabel.textColor = .labelColor
        titleLabel.lineBreakMode = .byTruncatingTail

        kindTagLabel.font = .systemFont(ofSize: 10, weight: .semibold)
        kindTagLabel.textColor = .secondaryLabelColor
        kindTagLabel.translatesAutoresizingMaskIntoConstraints = false
        kindTagBadge.translatesAutoresizingMaskIntoConstraints = false
        kindTagBadge.addSubview(kindTagLabel)

        latencyTrack.translatesAutoresizingMaskIntoConstraints = false
        latencyFill.translatesAutoresizingMaskIntoConstraints = false
        latencyTrack.addSubview(latencyFill)
        let fillWidth = latencyFill.widthAnchor.constraint(equalToConstant: 0)
        latencyFillWidthConstraint = fillWidth

        statusLabel.font = .monospacedDigitSystemFont(ofSize: 11, weight: .semibold)
        statusLabel.setContentCompressionResistancePriority(.required, for: .horizontal)
        statusBadge.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusBadge.addSubview(statusLabel)

        detailWell.translatesAutoresizingMaskIntoConstraints = false
        detailLabel.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.isSelectable = true
        detailLabel.setContentCompressionResistancePriority(.required, for: .vertical)
        detailLabel.translatesAutoresizingMaskIntoConstraints = false

        for view in [titleLabel, kindTagBadge, latencyTrack, statusBadge, detailWell, detailLabel] {
            view.translatesAutoresizingMaskIntoConstraints = false
            addSubview(view)
        }

        NSLayoutConstraint.activate([
            surface.leadingAnchor.constraint(equalTo: leadingAnchor),
            surface.trailingAnchor.constraint(equalTo: trailingAnchor),
            surface.topAnchor.constraint(equalTo: topAnchor),
            surface.bottomAnchor.constraint(equalTo: bottomAnchor),

            statusBar.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 5),
            statusBar.topAnchor.constraint(equalTo: topAnchor, constant: 10),
            statusBar.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -10),
            statusBar.widthAnchor.constraint(equalToConstant: 3.5),

            iconContainer.leadingAnchor.constraint(equalTo: statusBar.trailingAnchor, constant: 10),
            iconContainer.topAnchor.constraint(equalTo: topAnchor, constant: 11),
            iconContainer.widthAnchor.constraint(equalToConstant: 28),
            iconContainer.heightAnchor.constraint(equalToConstant: 28),
            iconView.centerXAnchor.constraint(equalTo: iconContainer.centerXAnchor),
            iconView.centerYAnchor.constraint(equalTo: iconContainer.centerYAnchor),

            titleLabel.leadingAnchor.constraint(equalTo: iconContainer.trailingAnchor, constant: 10),
            titleLabel.centerYAnchor.constraint(equalTo: iconContainer.centerYAnchor),
            kindTagBadge.leadingAnchor.constraint(equalTo: titleLabel.trailingAnchor, constant: 8),
            kindTagBadge.centerYAnchor.constraint(equalTo: titleLabel.centerYAnchor),
            kindTagBadge.trailingAnchor.constraint(lessThanOrEqualTo: latencyTrack.leadingAnchor, constant: -10),
            kindTagLabel.leadingAnchor.constraint(equalTo: kindTagBadge.leadingAnchor, constant: 6),
            kindTagLabel.trailingAnchor.constraint(equalTo: kindTagBadge.trailingAnchor, constant: -6),
            kindTagLabel.topAnchor.constraint(equalTo: kindTagBadge.topAnchor, constant: 2),
            kindTagLabel.bottomAnchor.constraint(equalTo: kindTagBadge.bottomAnchor, constant: -2),

            latencyTrack.trailingAnchor.constraint(equalTo: statusBadge.leadingAnchor, constant: -10),
            latencyTrack.centerYAnchor.constraint(equalTo: titleLabel.centerYAnchor),
            latencyTrack.widthAnchor.constraint(equalToConstant: 64),
            latencyTrack.heightAnchor.constraint(equalToConstant: 6),
            latencyFill.leadingAnchor.constraint(equalTo: latencyTrack.leadingAnchor),
            latencyFill.topAnchor.constraint(equalTo: latencyTrack.topAnchor),
            latencyFill.bottomAnchor.constraint(equalTo: latencyTrack.bottomAnchor),
            fillWidth,

            statusBadge.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            statusBadge.centerYAnchor.constraint(equalTo: titleLabel.centerYAnchor),
            statusLabel.leadingAnchor.constraint(equalTo: statusBadge.leadingAnchor, constant: 8),
            statusLabel.trailingAnchor.constraint(equalTo: statusBadge.trailingAnchor, constant: -8),
            statusLabel.topAnchor.constraint(equalTo: statusBadge.topAnchor, constant: 3),
            statusLabel.bottomAnchor.constraint(equalTo: statusBadge.bottomAnchor, constant: -3),

            detailWell.leadingAnchor.constraint(equalTo: iconContainer.leadingAnchor),
            detailWell.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            detailWell.topAnchor.constraint(equalTo: iconContainer.bottomAnchor, constant: 8),
            detailWell.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -10),

            detailLabel.leadingAnchor.constraint(equalTo: detailWell.leadingAnchor, constant: 10),
            detailLabel.trailingAnchor.constraint(equalTo: detailWell.trailingAnchor, constant: -10),
            detailLabel.topAnchor.constraint(equalTo: detailWell.topAnchor, constant: 7),
            detailLabel.bottomAnchor.constraint(equalTo: detailWell.bottomAnchor, constant: -7)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func apply(_ value: NetworkConnectivityDiagnosticResult) {
        let status = NetworkDiagnosticsSummary.status(value), detail = NetworkDiagnosticsSummary.detail(value)
        if titleLabel.stringValue != value.title { titleLabel.stringValue = value.title }
        if statusLabel.stringValue != status { statusLabel.stringValue = status }
        if detailLabel.stringValue != detail { detailLabel.stringValue = detail }

        let (symbolName, tagText): (String, String)
        switch value.kind {
        case .localLatency:
            symbolName = "globe.americas.fill"
            tagText = "HTTP 直连"
        case .proxyLatency:
            symbolName = "paperplane.fill"
            tagText = "代理隧道"
        case .traditionalDNS:
            symbolName = "server.rack"
            tagText = "传统 DNS"
        case .encryptedDNS:
            symbolName = "lock.shield.fill"
            tagText = "加密 DoH/DoT"
        case .proxyDNS:
            symbolName = "network.badge.shield.half.filled"
            tagText = "代理内 DNS"
        }
        iconView.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: tagText)
        if kindTagLabel.stringValue != tagText { kindTagLabel.stringValue = tagText }

        let color: NSColor
        switch value.status {
        case .success:
            if let ms = value.milliseconds, ms.isFinite {
                if ms < 120 { color = HajimiAppearance.statusSuccess }
                else if ms < 320 { color = HajimiAppearance.accentText }
                else { color = HajimiAppearance.statusWarning }
            } else {
                color = HajimiAppearance.accentText
            }
        case .failure:
            color = HajimiAppearance.statusDanger
        case .queued, .running:
            color = HajimiAppearance.statusInfo
        case .skipped, .cancelled:
            color = .secondaryLabelColor
        }

        statusLabel.textColor = color
        statusBar.fillColor = color
        statusBadge.fillColor = color.withAlphaComponent(0.12)
        statusBadge.borderColor = color.withAlphaComponent(0.26)
        iconView.contentTintColor = color
        iconContainer.fillColor = color.withAlphaComponent(0.10)
        iconContainer.borderColor = color.withAlphaComponent(0.22)
        kindTagBadge.fillColor = HajimiAppearance.mutedPanel
        kindTagBadge.borderColor = HajimiAppearance.subtleDivider

        if value.status == .success, let ms = value.milliseconds, ms.isFinite, ms >= 0 {
            latencyTrack.isHidden = false
            let ratio = max(0.12, min(1.0, CGFloat(ms / 500.0)))
            latencyFillWidthConstraint?.constant = round(64.0 * ratio)
            latencyFill.fillColor = color
        } else if value.status == .running {
            latencyTrack.isHidden = false
            latencyFillWidthConstraint?.constant = 28
            latencyFill.fillColor = HajimiAppearance.statusInfo
        } else {
            latencyTrack.isHidden = true
            latencyFillWidthConstraint?.constant = 0
        }
    }
}

public final class NetworkDiagnosticsView: NSView {
    private let applicationVersion: String
    private let now: () -> UInt64
    private let copyReport: (String) -> Void
    private let exportReport: (String, String, NSWindow?) -> Void
    private let runtimeLabel = NSTextField(wrappingLabelWithString: "")
    private let localNetworkLabel = NSTextField(wrappingLabelWithString: "正在读取本地网络信息…")
    private let detectionStateLabel = NSTextField(wrappingLabelWithString: "尚未检测；点击“开始网络检测”查看当前连通性与延迟。")
    private let detectionRows = NSStackView()
    private let startDetectionButton = NSButton(title: "开始网络检测", target: nil, action: nil)
    private let stopDetectionButton = NSButton(title: "停止检测", target: nil, action: nil)
    private let copyNetworkButton = NSButton(title: "复制网络诊断", target: nil, action: nil)
    private let exportNetworkButton = NSButton(title: "导出网络诊断", target: nil, action: nil)
    private let dnsLabel = NSTextField(wrappingLabelWithString: "")
    private let schedulerLabel = NSTextField(wrappingLabelWithString: "")
    private let dnsAttemptsLabel = NSTextField(wrappingLabelWithString: "")
    private let copyDNSAttemptsButton = NSButton(title: "复制 DNS 建连诊断", target: nil, action: nil)
    private let exportDNSAttemptsButton = NSButton(title: "导出 DNS 建连诊断", target: nil, action: nil)

    // Enhanced dashboard visual widgets
    private let engineStatusBadge = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                                      border: HajimiAppearance.border,
                                                      cornerRadius: 8)
    private let engineStatusDot = HajimiSurfaceView(fill: .tertiaryLabelColor, cornerRadius: 4)
    private let engineStatusText = NSTextField(labelWithString: "待命")
    private let modeTile = DiagnosticsMetricTileView(caption: "运行模式与策略", symbolName: "point.3.connected.trianglepath.dotted")
    private let channelTile = DiagnosticsMetricTileView(caption: "当前检测通道", symbolName: "waveform.path.ecg")
    private let enhancedTile = DiagnosticsMetricTileView(caption: "增强模式 (TUN)", symbolName: "shield.lefthalf.filled")
    private let interfaceTile = DiagnosticsMetricTileView(caption: "绑定物理出口", symbolName: "cable.connector.horizontal")

    private let localLinkBadge = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                                   border: HajimiAppearance.border,
                                                   cornerRadius: 7)
    private let localLinkLabel = NSTextField(labelWithString: "采集中")
    private let localInterfaceTile = DiagnosticsMetricTileView(caption: "物理主接口", symbolName: "wifi")
    private let localIPv4Tile = DiagnosticsMetricTileView(caption: "本地 IPv4 地址", symbolName: "number.square")
    private let localGatewayTile = DiagnosticsMetricTileView(caption: "物理默认网关", symbolName: "arrow.up.right.square")
    private let localDNSTile = DiagnosticsMetricTileView(caption: "系统 / 物理 DNS", symbolName: "server.rack")

    private let progressTrack = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel, cornerRadius: 3.5)
    private let progressFill = HajimiSurfaceView(fill: HajimiAppearance.accent, cornerRadius: 3.5)
    private var progressFillRatioConstraint: NSLayoutConstraint?

    private var latestSnapshot = NetworkPerformanceSnapshot()
    private var latestContext = NetworkDiagnosticsRuntimeContext.unavailable
    private var latestLocalNetwork: LocalNetworkDiagnosticsSnapshot?
    private var latestConnectivity: NetworkConnectivityDiagnosticsSnapshot?
    private var statisticsReady = false
    private var preparingDetection = false
    private var connectivityRowIDs: [String] = []
    private var connectivityRows: [NetworkConnectivityDiagnosticRowView] = []
    private var statisticsGrid: NSGridView?
    private var values: [NetworkPerformanceStage: [NSTextField]] = [:]
    public private(set) var displayedRows: [NetworkDiagnosticsFormatting.Row] = []
    public var onStartDetection: (() -> Void)?
    public var onStopDetection: (() -> Void)?
    public var isDetectionRunning: Bool { preparingDetection || latestConnectivity?.isRunning == true }
    public var canStartDetection: Bool { startDetectionButton.isEnabled }

    public override convenience init(frame frameRect: NSRect) {
        self.init(frame: frameRect, applicationVersion: NetworkDiagnosticsCapabilities.currentApplicationVersion,
                  now: { DispatchTime.now().uptimeNanoseconds },
                  copyReport: NetworkDiagnosticsCapabilities.copyToPasteboard,
                  exportReport: NetworkDiagnosticsCapabilities.exportToFilePanel)
    }

    public init(frame frameRect: NSRect, applicationVersion: String,
                now: @escaping () -> UInt64, copyReport: @escaping (String) -> Void,
                exportReport: @escaping (String, String, NSWindow?) -> Void = NetworkDiagnosticsCapabilities.exportToFilePanel) {
        self.applicationVersion = applicationVersion
        self.now = now
        self.copyReport = copyReport
        self.exportReport = exportReport
        super.init(frame: frameRect)
        precondition(Thread.isMainThread)
        wantsLayer = true

        for label in [runtimeLabel, localNetworkLabel, detectionStateLabel] {
            label.font = .monospacedDigitSystemFont(ofSize: 11.5, weight: .regular)
            label.isSelectable = true
            label.setContentCompressionResistancePriority(.required, for: .vertical)
        }
        runtimeLabel.textColor = .secondaryLabelColor
        localNetworkLabel.textColor = .labelColor
        detectionStateLabel.textColor = .labelColor

        startDetectionButton.target = self
        startDetectionButton.action = #selector(startDetection)
        stopDetectionButton.target = self
        stopDetectionButton.action = #selector(stopDetection)
        stopDetectionButton.isEnabled = false
        copyNetworkButton.target = self
        copyNetworkButton.action = #selector(copyNetworkReport)
        copyNetworkButton.isEnabled = false
        exportNetworkButton.target = self
        exportNetworkButton.action = #selector(exportNetworkReport)
        exportNetworkButton.isEnabled = false
        copyDNSAttemptsButton.target = self
        copyDNSAttemptsButton.action = #selector(copyDNSAttempts)
        exportDNSAttemptsButton.target = self
        exportDNSAttemptsButton.action = #selector(exportDNSAttempts)
        exportDNSAttemptsButton.isEnabled = false

        for button in [startDetectionButton, stopDetectionButton, copyNetworkButton, exportNetworkButton, copyDNSAttemptsButton, exportDNSAttemptsButton] {
            button.bezelStyle = .rounded
            button.controlSize = .regular
            button.font = .systemFont(ofSize: 12, weight: .semibold)
            button.imagePosition = .imageLeading
        }
        startDetectionButton.image = NSImage(systemSymbolName: "play.fill", accessibilityDescription: nil)
        startDetectionButton.contentTintColor = HajimiAppearance.accentText
        stopDetectionButton.image = NSImage(systemSymbolName: "stop.fill", accessibilityDescription: nil)
        stopDetectionButton.contentTintColor = .secondaryLabelColor
        copyNetworkButton.image = NSImage(systemSymbolName: "doc.on.doc", accessibilityDescription: nil)
        copyNetworkButton.contentTintColor = HajimiAppearance.accentText
        exportNetworkButton.image = NSImage(systemSymbolName: "square.and.arrow.down", accessibilityDescription: nil)
        exportNetworkButton.contentTintColor = HajimiAppearance.accentText
        copyDNSAttemptsButton.image = NSImage(systemSymbolName: "doc.on.doc.fill", accessibilityDescription: nil)
        copyDNSAttemptsButton.contentTintColor = HajimiAppearance.accentText
        exportDNSAttemptsButton.image = NSImage(systemSymbolName: "square.and.arrow.down.fill", accessibilityDescription: nil)
        exportDNSAttemptsButton.contentTintColor = HajimiAppearance.accentText

        // 1. Hero Telemetry Header Card
        let headerCard = buildHeaderCard()

        // 2. Local Network Topology Card
        let localCard = buildLocalNetworkCard()

        // 3. Connectivity & Latency Workbench Card
        let connectivityCard = buildConnectivityWorkbenchCard()

        // 4. Connectivity Rows Stack (MUST remain the first vertical NSStackView in root stack)
        detectionRows.orientation = .vertical
        detectionRows.alignment = .leading
        detectionRows.spacing = 10

        // 5. Runtime Stage & DNS Telemetry Card
        let telemetryCard = buildTelemetryCard()

        // 6. DNS Attempts Console Card & Scope Note
        let attemptsCard = buildAttemptsConsoleCard()
        let note = NSTextField(wrappingLabelWithString: NetworkDiagnosticsFormatting.scope)
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        note.setContentCompressionResistancePriority(.required, for: .vertical)

        let stack = NSStackView(views: [
            headerCard,
            localCard,
            connectivityCard,
            detectionRows,
            telemetryCard,
            copyDNSAttemptsButton,
            attemptsCard,
            note
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        stack.setCustomSpacing(12, after: connectivityCard)
        stack.setCustomSpacing(18, after: detectionRows)
        stack.setCustomSpacing(10, after: copyDNSAttemptsButton)
        stack.setCustomSpacing(14, after: attemptsCard)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 24),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: bottomAnchor, constant: -24),
            headerCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            localCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            connectivityCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            detectionRows.widthAnchor.constraint(equalTo: stack.widthAnchor),
            telemetryCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            attemptsCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            note.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])

        refreshSurfaceAppearance()
        apply(NetworkPerformanceSnapshot(), scheduler: nil)
    }

    public required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildHeaderCard() -> HajimiSurfaceView {
        let card = HajimiSurfaceView(fill: HajimiAppearance.panel,
                                     border: HajimiAppearance.border,
                                     cornerRadius: 15)
        card.translatesAutoresizingMaskIntoConstraints = false

        let heroBadge = HajimiAppearance.iconBadge(symbolName: "waveform.path.ecg.rectangle.fill",
                                                   tint: HajimiAppearance.accentText,
                                                   background: HajimiAppearance.accentSubtle,
                                                   size: 44, symbolSize: 20)
        let eyebrow = HajimiAppearance.pillBadge(text: "DIAGNOSTICS & TELEMETRY", fontSize: 9.5)
        let title = NSTextField(labelWithString: "网络诊断与遥测中心")
        title.font = .systemFont(ofSize: 22, weight: .bold)
        title.textColor = .labelColor
        let subtitle = NSTextField(wrappingLabelWithString: applicationVersion
            + " · 本机网络拓扑、按需连通性探测与核心数据面实时遥测")
        subtitle.font = .systemFont(ofSize: 12)
        subtitle.textColor = .secondaryLabelColor
        subtitle.setContentCompressionResistancePriority(.required, for: .vertical)

        engineStatusDot.translatesAutoresizingMaskIntoConstraints = false
        engineStatusText.font = .systemFont(ofSize: 11.5, weight: .semibold)
        engineStatusText.textColor = .secondaryLabelColor
        engineStatusText.translatesAutoresizingMaskIntoConstraints = false
        engineStatusBadge.translatesAutoresizingMaskIntoConstraints = false
        engineStatusBadge.addSubview(engineStatusDot)
        engineStatusBadge.addSubview(engineStatusText)

        let tilesRow = NSStackView(views: [modeTile, channelTile, enhancedTile, interfaceTile])
        tilesRow.orientation = .horizontal
        tilesRow.distribution = .fillEqually
        tilesRow.spacing = 10
        tilesRow.translatesAutoresizingMaskIntoConstraints = false

        let runtimeWell = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                            border: HajimiAppearance.subtleDivider,
                                            cornerRadius: 9)
        runtimeWell.translatesAutoresizingMaskIntoConstraints = false
        runtimeLabel.translatesAutoresizingMaskIntoConstraints = false
        runtimeWell.addSubview(runtimeLabel)

        for view in [heroBadge, eyebrow, title, subtitle, engineStatusBadge, tilesRow, runtimeWell] {
            view.translatesAutoresizingMaskIntoConstraints = false
            card.addSubview(view)
        }

        NSLayoutConstraint.activate([
            heroBadge.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 18),
            heroBadge.topAnchor.constraint(equalTo: card.topAnchor, constant: 18),

            eyebrow.leadingAnchor.constraint(equalTo: heroBadge.trailingAnchor, constant: 14),
            eyebrow.topAnchor.constraint(equalTo: card.topAnchor, constant: 16),

            title.leadingAnchor.constraint(equalTo: eyebrow.leadingAnchor),
            title.topAnchor.constraint(equalTo: eyebrow.bottomAnchor, constant: 5),
            title.trailingAnchor.constraint(lessThanOrEqualTo: engineStatusBadge.leadingAnchor, constant: -12),

            engineStatusBadge.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -18),
            engineStatusBadge.centerYAnchor.constraint(equalTo: title.centerYAnchor),
            engineStatusDot.leadingAnchor.constraint(equalTo: engineStatusBadge.leadingAnchor, constant: 10),
            engineStatusDot.centerYAnchor.constraint(equalTo: engineStatusBadge.centerYAnchor),
            engineStatusDot.widthAnchor.constraint(equalToConstant: 8),
            engineStatusDot.heightAnchor.constraint(equalToConstant: 8),
            engineStatusText.leadingAnchor.constraint(equalTo: engineStatusDot.trailingAnchor, constant: 6),
            engineStatusText.trailingAnchor.constraint(equalTo: engineStatusBadge.trailingAnchor, constant: -10),
            engineStatusText.topAnchor.constraint(equalTo: engineStatusBadge.topAnchor, constant: 4),
            engineStatusText.bottomAnchor.constraint(equalTo: engineStatusBadge.bottomAnchor, constant: -4),

            subtitle.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 18),
            subtitle.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -18),
            subtitle.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 6),

            tilesRow.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 18),
            tilesRow.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -18),
            tilesRow.topAnchor.constraint(equalTo: subtitle.bottomAnchor, constant: 14),

            runtimeWell.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 18),
            runtimeWell.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -18),
            runtimeWell.topAnchor.constraint(equalTo: tilesRow.bottomAnchor, constant: 10),
            runtimeWell.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -16),

            runtimeLabel.leadingAnchor.constraint(equalTo: runtimeWell.leadingAnchor, constant: 12),
            runtimeLabel.trailingAnchor.constraint(equalTo: runtimeWell.trailingAnchor, constant: -12),
            runtimeLabel.topAnchor.constraint(equalTo: runtimeWell.topAnchor, constant: 8),
            runtimeLabel.bottomAnchor.constraint(equalTo: runtimeWell.bottomAnchor, constant: -8)
        ])
        return card
    }

    private func buildLocalNetworkCard() -> HajimiSurfaceView {
        let card = HajimiSurfaceView(fill: HajimiAppearance.panel,
                                     border: HajimiAppearance.border,
                                     cornerRadius: 14)
        card.translatesAutoresizingMaskIntoConstraints = false

        let badge = HajimiAppearance.iconBadge(symbolName: "network", size: 28, symbolSize: 13)
        let heading = NSTextField(labelWithString: "本地网络拓扑与接口快照")
        heading.font = .systemFont(ofSize: 14, weight: .semibold)
        heading.textColor = .labelColor

        localLinkLabel.font = .systemFont(ofSize: 11, weight: .semibold)
        localLinkLabel.textColor = .secondaryLabelColor
        localLinkLabel.translatesAutoresizingMaskIntoConstraints = false
        localLinkBadge.translatesAutoresizingMaskIntoConstraints = false
        localLinkBadge.addSubview(localLinkLabel)

        let tilesRow = NSStackView(views: [localInterfaceTile, localIPv4Tile, localGatewayTile, localDNSTile])
        tilesRow.orientation = .horizontal
        tilesRow.distribution = .fillEqually
        tilesRow.spacing = 10
        tilesRow.translatesAutoresizingMaskIntoConstraints = false

        let detailWell = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                           border: HajimiAppearance.subtleDivider,
                                           cornerRadius: 10)
        detailWell.translatesAutoresizingMaskIntoConstraints = false
        localNetworkLabel.translatesAutoresizingMaskIntoConstraints = false
        detailWell.addSubview(localNetworkLabel)

        for view in [badge, heading, localLinkBadge, tilesRow, detailWell] {
            view.translatesAutoresizingMaskIntoConstraints = false
            card.addSubview(view)
        }

        NSLayoutConstraint.activate([
            badge.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            badge.topAnchor.constraint(equalTo: card.topAnchor, constant: 14),
            heading.leadingAnchor.constraint(equalTo: badge.trailingAnchor, constant: 10),
            heading.centerYAnchor.constraint(equalTo: badge.centerYAnchor),

            localLinkBadge.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            localLinkBadge.centerYAnchor.constraint(equalTo: badge.centerYAnchor),
            localLinkLabel.leadingAnchor.constraint(equalTo: localLinkBadge.leadingAnchor, constant: 8),
            localLinkLabel.trailingAnchor.constraint(equalTo: localLinkBadge.trailingAnchor, constant: -8),
            localLinkLabel.topAnchor.constraint(equalTo: localLinkBadge.topAnchor, constant: 3),
            localLinkLabel.bottomAnchor.constraint(equalTo: localLinkBadge.bottomAnchor, constant: -3),

            tilesRow.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            tilesRow.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            tilesRow.topAnchor.constraint(equalTo: badge.bottomAnchor, constant: 12),

            detailWell.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            detailWell.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            detailWell.topAnchor.constraint(equalTo: tilesRow.bottomAnchor, constant: 10),
            detailWell.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -14),

            localNetworkLabel.leadingAnchor.constraint(equalTo: detailWell.leadingAnchor, constant: 12),
            localNetworkLabel.trailingAnchor.constraint(equalTo: detailWell.trailingAnchor, constant: -12),
            localNetworkLabel.topAnchor.constraint(equalTo: detailWell.topAnchor, constant: 10),
            localNetworkLabel.bottomAnchor.constraint(equalTo: detailWell.bottomAnchor, constant: -10)
        ])
        return card
    }

    private func buildConnectivityWorkbenchCard() -> HajimiSurfaceView {
        let card = HajimiSurfaceView(fill: HajimiAppearance.panel,
                                     border: HajimiAppearance.border,
                                     cornerRadius: 14)
        card.translatesAutoresizingMaskIntoConstraints = false

        let badge = HajimiAppearance.iconBadge(symbolName: "bolt.horizontal.circle.fill", size: 28, symbolSize: 14)
        let heading = NSTextField(labelWithString: "连通性与端到端延迟探测")
        heading.font = .systemFont(ofSize: 14, weight: .semibold)
        heading.textColor = .labelColor

        let detectionControls = NSStackView(views: [startDetectionButton, stopDetectionButton, copyNetworkButton, exportNetworkButton])
        detectionControls.orientation = .horizontal
        detectionControls.spacing = 8
        detectionControls.translatesAutoresizingMaskIntoConstraints = false

        let statusBanner = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                             border: HajimiAppearance.subtleDivider,
                                             cornerRadius: 9)
        statusBanner.translatesAutoresizingMaskIntoConstraints = false

        progressTrack.translatesAutoresizingMaskIntoConstraints = false
        progressFill.translatesAutoresizingMaskIntoConstraints = false
        progressTrack.addSubview(progressFill)
        let widthZero = progressFill.widthAnchor.constraint(equalToConstant: 0)
        progressFillRatioConstraint = widthZero

        let detectionNote = NSTextField(wrappingLabelWithString: NetworkDiagnosticsSummary.detectionScope
            + "\n" + NetworkDiagnosticsSummary.reportScope)
        detectionNote.font = .systemFont(ofSize: 11)
        detectionNote.textColor = .secondaryLabelColor
        detectionNote.setContentCompressionResistancePriority(.required, for: .vertical)

        detectionStateLabel.translatesAutoresizingMaskIntoConstraints = false
        statusBanner.addSubview(detectionStateLabel)
        statusBanner.addSubview(progressTrack)

        for view in [badge, heading, detectionControls, statusBanner, detectionNote] {
            view.translatesAutoresizingMaskIntoConstraints = false
            card.addSubview(view)
        }

        NSLayoutConstraint.activate([
            badge.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            badge.topAnchor.constraint(equalTo: card.topAnchor, constant: 14),
            heading.leadingAnchor.constraint(equalTo: badge.trailingAnchor, constant: 10),
            heading.centerYAnchor.constraint(equalTo: badge.centerYAnchor),

            detectionControls.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            detectionControls.centerYAnchor.constraint(equalTo: badge.centerYAnchor),
            heading.trailingAnchor.constraint(lessThanOrEqualTo: detectionControls.leadingAnchor, constant: -12),

            statusBanner.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            statusBanner.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            statusBanner.topAnchor.constraint(equalTo: badge.bottomAnchor, constant: 12),

            detectionStateLabel.leadingAnchor.constraint(equalTo: statusBanner.leadingAnchor, constant: 12),
            detectionStateLabel.trailingAnchor.constraint(equalTo: statusBanner.trailingAnchor, constant: -12),
            detectionStateLabel.topAnchor.constraint(equalTo: statusBanner.topAnchor, constant: 8),

            progressTrack.leadingAnchor.constraint(equalTo: statusBanner.leadingAnchor, constant: 12),
            progressTrack.trailingAnchor.constraint(equalTo: statusBanner.trailingAnchor, constant: -12),
            progressTrack.topAnchor.constraint(equalTo: detectionStateLabel.bottomAnchor, constant: 7),
            progressTrack.heightAnchor.constraint(equalToConstant: 5),
            progressTrack.bottomAnchor.constraint(equalTo: statusBanner.bottomAnchor, constant: -8),
            progressFill.leadingAnchor.constraint(equalTo: progressTrack.leadingAnchor),
            progressFill.topAnchor.constraint(equalTo: progressTrack.topAnchor),
            progressFill.bottomAnchor.constraint(equalTo: progressTrack.bottomAnchor),
            widthZero,

            detectionNote.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            detectionNote.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            detectionNote.topAnchor.constraint(equalTo: statusBanner.bottomAnchor, constant: 10),
            detectionNote.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -14)
        ])
        return card
    }

    private func buildTelemetryCard() -> HajimiSurfaceView {
        let card = HajimiSurfaceView(fill: HajimiAppearance.panel,
                                     border: HajimiAppearance.border,
                                     cornerRadius: 14)
        card.translatesAutoresizingMaskIntoConstraints = false

        let badge = HajimiAppearance.iconBadge(symbolName: "chart.bar.xaxis", size: 28, symbolSize: 13)
        let heading = NSTextField(labelWithString: "应用运行统计与阶段耗时分位数")
        heading.font = .systemFont(ofSize: 14, weight: .semibold)
        heading.textColor = .labelColor

        let dnsWell = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                        border: HajimiAppearance.subtleDivider,
                                        cornerRadius: 9)
        dnsWell.translatesAutoresizingMaskIntoConstraints = false
        let dnsCaption = NSTextField(labelWithString: "DNS 解析与缓存命中概览")
        dnsCaption.font = .systemFont(ofSize: 10.5, weight: .semibold)
        dnsCaption.textColor = HajimiAppearance.accentText
        dnsCaption.translatesAutoresizingMaskIntoConstraints = false
        dnsLabel.font = .monospacedDigitSystemFont(ofSize: 11.5, weight: .regular)
        dnsLabel.isSelectable = true
        dnsLabel.setContentCompressionResistancePriority(.required, for: .vertical)
        dnsLabel.translatesAutoresizingMaskIntoConstraints = false
        dnsWell.addSubview(dnsCaption)
        dnsWell.addSubview(dnsLabel)

        let schedulerWell = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                              border: HajimiAppearance.subtleDivider,
                                              cornerRadius: 9)
        schedulerWell.translatesAutoresizingMaskIntoConstraints = false
        let schedulerCaption = NSTextField(labelWithString: "并发探测调度器队列")
        schedulerCaption.font = .systemFont(ofSize: 10.5, weight: .semibold)
        schedulerCaption.textColor = .secondaryLabelColor
        schedulerCaption.translatesAutoresizingMaskIntoConstraints = false
        schedulerLabel.font = .monospacedDigitSystemFont(ofSize: 11.5, weight: .regular)
        schedulerLabel.textColor = .secondaryLabelColor
        schedulerLabel.setContentCompressionResistancePriority(.required, for: .vertical)
        schedulerLabel.translatesAutoresizingMaskIntoConstraints = false
        schedulerWell.addSubview(schedulerCaption)
        schedulerWell.addSubview(schedulerLabel)

        let headers = ["阶段", "次数 / 失败 / 中止", "近期成功样本", "p50", "p95", "最近"]
        var rows: [[NSView]] = [headers.map { header in
            let label = NSTextField(labelWithString: header)
            label.font = .systemFont(ofSize: 11, weight: .semibold)
            label.textColor = HajimiAppearance.accentText
            return label
        }]
        for (stage, name) in NetworkDiagnosticsFormatting.stages {
            let label = NSTextField(labelWithString: name)
            label.font = .systemFont(ofSize: 12, weight: .medium)
            label.textColor = .labelColor
            let fields = (0..<5).map { index in
                let field = NSTextField(labelWithString: "--")
                field.font = .monospacedDigitSystemFont(ofSize: 12, weight: index >= 2 ? .medium : .regular)
                field.textColor = index == 0 ? .secondaryLabelColor : .labelColor
                return field
            }
            values[stage] = fields
            rows.append([label] + fields)
        }
        let grid = NSGridView(views: rows)
        statisticsGrid = grid
        grid.wantsLayer = true
        grid.layer?.cornerRadius = 11
        grid.layer?.cornerCurve = .continuous
        grid.layer?.borderWidth = 1
        grid.rowSpacing = 12
        grid.columnSpacing = 16
        grid.column(at: 0).width = 158
        for column in 1..<6 { grid.column(at: column).width = column == 1 ? 140 : (column == 2 ? 100 : 85) }
        grid.column(at: 0).leadingPadding = 12
        grid.column(at: 5).trailingPadding = 12
        grid.row(at: 0).topPadding = 12
        grid.row(at: 0).bottomPadding = 4
        grid.row(at: rows.count - 1).bottomPadding = 12
        grid.translatesAutoresizingMaskIntoConstraints = false

        for view in [badge, heading, dnsWell, schedulerWell, grid] {
            view.translatesAutoresizingMaskIntoConstraints = false
            card.addSubview(view)
        }

        NSLayoutConstraint.activate([
            badge.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            badge.topAnchor.constraint(equalTo: card.topAnchor, constant: 14),
            heading.leadingAnchor.constraint(equalTo: badge.trailingAnchor, constant: 10),
            heading.centerYAnchor.constraint(equalTo: badge.centerYAnchor),

            dnsWell.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            dnsWell.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            dnsWell.topAnchor.constraint(equalTo: badge.bottomAnchor, constant: 12),
            dnsCaption.leadingAnchor.constraint(equalTo: dnsWell.leadingAnchor, constant: 12),
            dnsCaption.topAnchor.constraint(equalTo: dnsWell.topAnchor, constant: 8),
            dnsLabel.leadingAnchor.constraint(equalTo: dnsWell.leadingAnchor, constant: 12),
            dnsLabel.trailingAnchor.constraint(equalTo: dnsWell.trailingAnchor, constant: -12),
            dnsLabel.topAnchor.constraint(equalTo: dnsCaption.bottomAnchor, constant: 4),
            dnsLabel.bottomAnchor.constraint(equalTo: dnsWell.bottomAnchor, constant: -8),

            schedulerWell.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            schedulerWell.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            schedulerWell.topAnchor.constraint(equalTo: dnsWell.bottomAnchor, constant: 8),
            schedulerCaption.leadingAnchor.constraint(equalTo: schedulerWell.leadingAnchor, constant: 12),
            schedulerCaption.topAnchor.constraint(equalTo: schedulerWell.topAnchor, constant: 7),
            schedulerLabel.leadingAnchor.constraint(equalTo: schedulerWell.leadingAnchor, constant: 12),
            schedulerLabel.trailingAnchor.constraint(equalTo: schedulerWell.trailingAnchor, constant: -12),
            schedulerLabel.topAnchor.constraint(equalTo: schedulerCaption.bottomAnchor, constant: 3),
            schedulerLabel.bottomAnchor.constraint(equalTo: schedulerWell.bottomAnchor, constant: -7),

            grid.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            grid.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            grid.topAnchor.constraint(equalTo: schedulerWell.bottomAnchor, constant: 12),
            grid.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -14)
        ])
        return card
    }

    private func buildAttemptsConsoleCard() -> HajimiSurfaceView {
        let card = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel,
                                     border: HajimiAppearance.border,
                                     cornerRadius: 12)
        card.translatesAutoresizingMaskIntoConstraints = false

        let caption = NSTextField(labelWithString: "DNS 建连与交换匿名追踪控制台")
        caption.font = .systemFont(ofSize: 11, weight: .semibold)
        caption.textColor = .secondaryLabelColor
        caption.translatesAutoresizingMaskIntoConstraints = false

        dnsAttemptsLabel.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        dnsAttemptsLabel.textColor = .labelColor
        dnsAttemptsLabel.isSelectable = true
        dnsAttemptsLabel.setContentCompressionResistancePriority(.required, for: .vertical)
        dnsAttemptsLabel.translatesAutoresizingMaskIntoConstraints = false

        exportDNSAttemptsButton.translatesAutoresizingMaskIntoConstraints = false

        card.addSubview(caption)
        card.addSubview(exportDNSAttemptsButton)
        card.addSubview(dnsAttemptsLabel)

        NSLayoutConstraint.activate([
            caption.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),
            caption.topAnchor.constraint(equalTo: card.topAnchor, constant: 12),
            exportDNSAttemptsButton.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -14),
            exportDNSAttemptsButton.centerYAnchor.constraint(equalTo: caption.centerYAnchor),
            caption.trailingAnchor.constraint(lessThanOrEqualTo: exportDNSAttemptsButton.leadingAnchor, constant: -12),
            dnsAttemptsLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),
            dnsAttemptsLabel.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -14),
            dnsAttemptsLabel.topAnchor.constraint(equalTo: caption.bottomAnchor, constant: 10),
            dnsAttemptsLabel.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -10)
        ])
        return card
    }

    public override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        refreshSurfaceAppearance()
    }

    private func refreshSurfaceAppearance() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.backgroundColor = HajimiAppearance.workspace.cgColor
            statisticsGrid?.layer?.backgroundColor = HajimiAppearance.elevatedPanel.cgColor
            statisticsGrid?.layer?.borderColor = HajimiAppearance.border.cgColor
        }
    }

    public func applyContext(_ context: NetworkDiagnosticsRuntimeContext, detectionAvailable: Bool) {
        precondition(Thread.isMainThread)
        let wasReady = latestContext.engineRunning
        latestContext = context
        let text = NetworkDiagnosticsSummary.runtime(context)
        if runtimeLabel.stringValue != text { runtimeLabel.stringValue = text }

        let statusColor = context.engineRunning ? HajimiAppearance.statusSuccess : HajimiAppearance.statusWarning
        engineStatusDot.fillColor = statusColor
        engineStatusText.stringValue = context.engineState
        engineStatusText.textColor = statusColor
        engineStatusBadge.fillColor = statusColor.withAlphaComponent(0.12)
        engineStatusBadge.borderColor = statusColor.withAlphaComponent(0.28)

        modeTile.setValue("\(context.mode) · \(context.selectedPolicy)")
        channelTile.setValue(context.backend.displayName,
                             tint: context.engineRunning ? HajimiAppearance.accentText : .secondaryLabelColor)
        enhancedTile.setValue(context.enhancedMode ? "已开启 (Native TUN)" : (context.systemProxy ? "系统代理已启用" : "未开启"),
                              tint: context.enhancedMode ? HajimiAppearance.statusSuccess : .labelColor)
        interfaceTile.setValue(context.boundInterfaceName ?? "自动感知")

        startDetectionButton.isEnabled = detectionAvailable && context.engineRunning && !isDetectionRunning
        if !context.engineRunning && !isDetectionRunning && latestConnectivity == nil {
            detectionStateLabel.stringValue = "当前网络核心未就绪：\(context.engineState)。请先开启增强模式或启动代理引擎，等待就绪后检测。"
        } else if !wasReady && context.engineRunning && !isDetectionRunning && latestConnectivity == nil {
            detectionStateLabel.stringValue = "尚未检测；点击“开始网络检测”查看当前连通性与延迟。"
        }
    }

    public func applyLocalNetwork(_ snapshot: LocalNetworkDiagnosticsSnapshot) {
        precondition(Thread.isMainThread)
        latestLocalNetwork = snapshot
        let text = NetworkDiagnosticsSummary.local(snapshot)
        if localNetworkLabel.stringValue != text { localNetworkLabel.stringValue = text }

        let linkColor: NSColor
        let linkTitle: String
        switch snapshot.localLinkStatus {
        case .available:
            linkColor = HajimiAppearance.statusSuccess
            linkTitle = "● 本地链路已配置"
        case .unavailable:
            linkColor = HajimiAppearance.statusDanger
            linkTitle = "● 本地链路未就绪"
        case .unknown:
            linkColor = HajimiAppearance.statusWarning
            linkTitle = "● 链路状态待确认"
        }
        localLinkLabel.stringValue = linkTitle
        localLinkLabel.textColor = linkColor
        localLinkBadge.fillColor = linkColor.withAlphaComponent(0.12)
        localLinkBadge.borderColor = linkColor.withAlphaComponent(0.26)

        let physical = snapshot.interfaces.first { $0.name == snapshot.physicalInterfaceName }
        localInterfaceTile.setValue(snapshot.physicalInterfaceName ?? "--", tint: HajimiAppearance.accentText)
        localIPv4Tile.setValue(physical?.ipv4Addresses.first ?? "--")
        localGatewayTile.setValue(snapshot.gateways.first ?? "--")
        localDNSTile.setValue(snapshot.systemDNSServers.first ?? snapshot.physicalDNSServers.first ?? "--")

        copyNetworkButton.isEnabled = statisticsReady
        exportNetworkButton.isEnabled = statisticsReady
    }

    public func clearLocalNetwork() {
        precondition(Thread.isMainThread)
        latestLocalNetwork = nil
        localNetworkLabel.stringValue = "网络或配置已变化，正在重新读取本地网络信息…"
        localLinkLabel.stringValue = "● 正在刷新…"
        localLinkLabel.textColor = .secondaryLabelColor
        localInterfaceTile.setValue("--")
        localIPv4Tile.setValue("--")
        localGatewayTile.setValue("--")
        localDNSTile.setValue("--")
        let canExportNetwork = statisticsReady && latestConnectivity != nil
        copyNetworkButton.isEnabled = canExportNetwork
        exportNetworkButton.isEnabled = canExportNetwork
    }

    public func prepareDetection() {
        precondition(Thread.isMainThread)
        preparingDetection = true
        detectionStateLabel.stringValue = "正在准备本轮网络检测…"
        progressFill.fillColor = HajimiAppearance.statusInfo
        progressFillRatioConstraint?.constant = 48
        startDetectionButton.isEnabled = false
        stopDetectionButton.isEnabled = true
    }

    public func applyConnectivity(_ snapshot: NetworkConnectivityDiagnosticsSnapshot) {
        precondition(Thread.isMainThread)
        preparingDetection = false
        latestConnectivity = snapshot
        startDetectionButton.isEnabled = !snapshot.isRunning && onStartDetection != nil && latestContext.engineRunning
        stopDetectionButton.isEnabled = snapshot.isRunning
        detectionStateLabel.stringValue = NetworkDiagnosticsSummary.progress(snapshot)

        let total = max(1, snapshot.rows.count)
        let finished = snapshot.rows.filter { ![.queued, .running].contains($0.status) }.count
        let failures = snapshot.rows.filter { $0.status == .failure }.count
        let trackWidth = max(120, progressTrack.bounds.width > 0 ? progressTrack.bounds.width : 520)
        progressFillRatioConstraint?.constant = round(trackWidth * CGFloat(finished) / CGFloat(total))
        if snapshot.isRunning {
            progressFill.fillColor = HajimiAppearance.statusInfo
        } else if failures > 0 {
            progressFill.fillColor = HajimiAppearance.statusWarning
        } else {
            progressFill.fillColor = HajimiAppearance.statusSuccess
        }

        if connectivityRowIDs != snapshot.rows.map(\.id) {
            for row in connectivityRows { detectionRows.removeArrangedSubview(row); row.removeFromSuperview() }
            connectivityRowIDs = snapshot.rows.map(\.id)
            connectivityRows = snapshot.rows.map { _ in NetworkConnectivityDiagnosticRowView() }
            for row in connectivityRows {
                detectionRows.addArrangedSubview(row)
                row.widthAnchor.constraint(equalTo: detectionRows.widthAnchor).isActive = true
            }
        }
        for (row, value) in zip(connectivityRows, snapshot.rows) { row.apply(value) }
        copyNetworkButton.isEnabled = statisticsReady
        exportNetworkButton.isEnabled = statisticsReady
    }

    public func clearConnectivity(reason: String) {
        precondition(Thread.isMainThread)
        preparingDetection = false
        latestConnectivity = nil
        connectivityRowIDs = []
        for row in connectivityRows { detectionRows.removeArrangedSubview(row); row.removeFromSuperview() }
        connectivityRows = []
        detectionStateLabel.stringValue = reason
        progressFillRatioConstraint?.constant = 0
        startDetectionButton.isEnabled = onStartDetection != nil && latestContext.engineRunning
        stopDetectionButton.isEnabled = false
        let canExportNetwork = statisticsReady && latestLocalNetwork != nil
        copyNetworkButton.isEnabled = canExportNetwork
        exportNetworkButton.isEnabled = canExportNetwork
    }

    @objc private func startDetection() { onStartDetection?() }
    @objc private func stopDetection() { onStopDetection?() }

    private static func exportTimestampString() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }

    @objc public func copyNetworkReport() {
        precondition(Thread.isMainThread)
        guard statisticsReady,
              let report = NetworkDiagnosticsSummary.report(context: latestContext, local: latestLocalNetwork,
            connectivity: latestConnectivity, performance: latestSnapshot, applicationVersion: applicationVersion,
            capturedUptimeNanoseconds: now()) else { return }
        copyReport(report)
    }

    @objc public func exportNetworkReport() {
        precondition(Thread.isMainThread)
        guard statisticsReady,
              let report = NetworkDiagnosticsSummary.report(context: latestContext, local: latestLocalNetwork,
            connectivity: latestConnectivity, performance: latestSnapshot, applicationVersion: applicationVersion,
            capturedUptimeNanoseconds: now()) else { return }
        let filename = "哈基米-网络诊断报告-\(Self.exportTimestampString()).json"
        exportReport(report, filename, window)
    }

    public func apply(_ snapshot: NetworkPerformanceSnapshot, scheduler: ProbeScheduler.Snapshot?) {
        precondition(Thread.isMainThread)
        apply(NetworkDiagnosticsPreparedStatistics(snapshot: snapshot,
            rows: NetworkDiagnosticsFormatting.rows(snapshot), dns: NetworkDiagnosticsFormatting.dns(snapshot),
            scheduler: scheduler.map(NetworkDiagnosticsFormatting.scheduler) ?? "测速统计：等待应用提供数据",
            attempts: NetworkDiagnosticsFormatting.dnsAttempts(snapshot)))
    }

    func showStatisticsLoading() {
        precondition(Thread.isMainThread)
        statisticsReady = false
        dnsLabel.stringValue = "正在读取运行统计…"
        copyNetworkButton.isEnabled = false
        exportNetworkButton.isEnabled = false
        copyDNSAttemptsButton.isEnabled = false
        exportDNSAttemptsButton.isEnabled = false
    }

    func apply(_ prepared: NetworkDiagnosticsPreparedStatistics) {
        precondition(Thread.isMainThread)
        statisticsReady = true
        latestSnapshot = prepared.snapshot
        displayedRows = prepared.rows
        for row in displayedRows {
            guard let fields = values[row.stage] else { continue }
            let strings = [row.counts, row.samples, row.median, row.p95, row.latest]
            for (field, string) in zip(fields, strings) where field.stringValue != string {
                field.stringValue = string
            }
        }
        if dnsLabel.stringValue != prepared.dns { dnsLabel.stringValue = prepared.dns }
        if schedulerLabel.stringValue != prepared.scheduler { schedulerLabel.stringValue = prepared.scheduler }
        if dnsAttemptsLabel.stringValue != prepared.attempts { dnsAttemptsLabel.stringValue = prepared.attempts }
        let hasDNSAttempts = !prepared.snapshot.dnsConnectionAttempts.isEmpty
            || !prepared.snapshot.dnsLogicalQueries.isEmpty || !prepared.snapshot.dnsQueryExchanges.isEmpty
        copyDNSAttemptsButton.isEnabled = hasDNSAttempts
        exportDNSAttemptsButton.isEnabled = hasDNSAttempts
        let hasNetwork = latestLocalNetwork != nil || latestConnectivity != nil
        copyNetworkButton.isEnabled = hasNetwork
        exportNetworkButton.isEnabled = hasNetwork
    }

    @objc public func copyDNSAttempts() {
        precondition(Thread.isMainThread)
        guard statisticsReady,
              let report = NetworkDiagnosticsFormatting.dnsAttemptReport(latestSnapshot,
            applicationVersion: applicationVersion, capturedUptimeNanoseconds: now()) else { return }
        copyReport(report)
    }

    @objc public func exportDNSAttempts() {
        precondition(Thread.isMainThread)
        guard statisticsReady,
              let report = NetworkDiagnosticsFormatting.dnsAttemptReport(latestSnapshot,
            applicationVersion: applicationVersion, capturedUptimeNanoseconds: now()) else { return }
        let filename = "哈基米-DNS建连诊断报告-\(Self.exportTimestampString()).json"
        exportReport(report, filename, window)
    }
}

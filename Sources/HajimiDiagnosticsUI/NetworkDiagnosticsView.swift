import AppKit
import HajimiCore
import HajimiUIComponents

private final class NetworkConnectivityDiagnosticRowView: NSView {
    private let statusBar = HajimiSurfaceView(fill: .tertiaryLabelColor, cornerRadius: 1.5)
    private let titleLabel = NSTextField(labelWithString: "")
    private let statusBadge = HajimiSurfaceView(fill: HajimiAppearance.mutedPanel, cornerRadius: 5)
    private let statusLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")

    init() {
        super.init(frame: .zero)
        let surface = HajimiSurfaceView(fill: HajimiAppearance.panel,
                                        border: HajimiAppearance.border, cornerRadius: 12)
        surface.translatesAutoresizingMaskIntoConstraints = false
        addSubview(surface)
        statusBar.translatesAutoresizingMaskIntoConstraints = false
        addSubview(statusBar)
        titleLabel.font = .systemFont(ofSize: 12.5, weight: .semibold)
        statusLabel.font = .monospacedDigitSystemFont(ofSize: 11, weight: .semibold)
        statusLabel.setContentCompressionResistancePriority(.required, for: .horizontal)
        statusBadge.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusBadge.addSubview(statusLabel)
        detailLabel.font = .systemFont(ofSize: 11)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.isSelectable = true
        detailLabel.setContentCompressionResistancePriority(.required, for: .vertical)
        for view in [titleLabel, statusBadge, detailLabel] {
            view.translatesAutoresizingMaskIntoConstraints = false
            addSubview(view)
        }
        NSLayoutConstraint.activate([
            surface.leadingAnchor.constraint(equalTo: leadingAnchor),
            surface.trailingAnchor.constraint(equalTo: trailingAnchor),
            surface.topAnchor.constraint(equalTo: topAnchor),
            surface.bottomAnchor.constraint(equalTo: bottomAnchor),
            statusBar.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            statusBar.topAnchor.constraint(equalTo: topAnchor, constant: 10),
            statusBar.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -10),
            statusBar.widthAnchor.constraint(equalToConstant: 3),
            titleLabel.leadingAnchor.constraint(equalTo: statusBar.trailingAnchor, constant: 10),
            titleLabel.topAnchor.constraint(equalTo: topAnchor, constant: 12),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: statusBadge.leadingAnchor, constant: -12),
            statusBadge.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            statusBadge.centerYAnchor.constraint(equalTo: titleLabel.centerYAnchor),
            statusLabel.leadingAnchor.constraint(equalTo: statusBadge.leadingAnchor, constant: 7),
            statusLabel.trailingAnchor.constraint(equalTo: statusBadge.trailingAnchor, constant: -7),
            statusLabel.topAnchor.constraint(equalTo: statusBadge.topAnchor, constant: 2),
            statusLabel.bottomAnchor.constraint(equalTo: statusBadge.bottomAnchor, constant: -2),
            detailLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            detailLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            detailLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 6),
            detailLabel.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -12)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func apply(_ value: NetworkConnectivityDiagnosticResult) {
        let status = NetworkDiagnosticsSummary.status(value), detail = NetworkDiagnosticsSummary.detail(value)
        if titleLabel.stringValue != value.title { titleLabel.stringValue = value.title }
        if statusLabel.stringValue != status { statusLabel.stringValue = status }
        if detailLabel.stringValue != detail { detailLabel.stringValue = detail }
        let color: NSColor
        switch value.status {
        case .success: color = HajimiAppearance.accentText
        case .failure: color = .systemRed
        case .queued, .running: color = .systemBlue
        case .skipped, .cancelled: color = .secondaryLabelColor
        }
        statusLabel.textColor = color
        statusBar.fillColor = color
        statusBadge.fillColor = color.withAlphaComponent(0.11)
        statusBadge.borderColor = color.withAlphaComponent(0.22)
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
    private let closeDiagnosticsButton = NSButton(title: "退出诊断", target: nil, action: nil)
    private let dnsLabel = NSTextField(wrappingLabelWithString: "")
    private let schedulerLabel = NSTextField(wrappingLabelWithString: "")
    private let dnsAttemptsLabel = NSTextField(wrappingLabelWithString: "")
    private let copyDNSAttemptsButton = NSButton(title: "复制 DNS 建连诊断", target: nil, action: nil)
    private let exportDNSAttemptsButton = NSButton(title: "导出 DNS 建连诊断", target: nil, action: nil)
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
    public var onCloseDiagnostics: (() -> Void)?
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
        let eyebrow = HajimiAppearance.pillBadge(text: "DIAGNOSTICS & TELEMETRY", fontSize: 9.5)
        let title = NSTextField(labelWithString: "网络诊断")
        title.font = .systemFont(ofSize: 25, weight: .bold)
        let subtitle = NSTextField(wrappingLabelWithString: applicationVersion
            + "\n本机网络信息、按需连通性检测与当前进程的实际运行记录。")
        subtitle.font = .systemFont(ofSize: 12)
        subtitle.textColor = .secondaryLabelColor
        for label in [runtimeLabel, localNetworkLabel, detectionStateLabel] {
            label.font = .monospacedDigitSystemFont(ofSize: 12, weight: .regular)
            label.isSelectable = true
            label.setContentCompressionResistancePriority(.required, for: .vertical)
        }
        runtimeLabel.textColor = .secondaryLabelColor
        detectionStateLabel.textColor = .secondaryLabelColor
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
        closeDiagnosticsButton.target = self
        closeDiagnosticsButton.action = #selector(closeDiagnostics)
        copyDNSAttemptsButton.target = self
        copyDNSAttemptsButton.action = #selector(copyDNSAttempts)
        exportDNSAttemptsButton.target = self
        exportDNSAttemptsButton.action = #selector(exportDNSAttempts)
        exportDNSAttemptsButton.isEnabled = false
        for button in [startDetectionButton, stopDetectionButton, copyNetworkButton,
                       exportNetworkButton, closeDiagnosticsButton,
                       copyDNSAttemptsButton, exportDNSAttemptsButton] {
            button.bezelStyle = .rounded
            button.font = .systemFont(ofSize: 12, weight: .medium)
            button.imagePosition = .imageLeading
        }
        startDetectionButton.image = NSImage(systemSymbolName: "play.fill", accessibilityDescription: nil)
        stopDetectionButton.image = NSImage(systemSymbolName: "stop.fill", accessibilityDescription: nil)
        stopDetectionButton.contentTintColor = .secondaryLabelColor
        copyNetworkButton.image = NSImage(systemSymbolName: "doc.on.doc", accessibilityDescription: nil)
        copyNetworkButton.contentTintColor = HajimiAppearance.accentText
        exportNetworkButton.image = NSImage(systemSymbolName: "square.and.arrow.down", accessibilityDescription: nil)
        exportNetworkButton.contentTintColor = HajimiAppearance.accentText
        closeDiagnosticsButton.image = NSImage(systemSymbolName: "xmark.circle", accessibilityDescription: nil)
        closeDiagnosticsButton.contentTintColor = .secondaryLabelColor
        copyDNSAttemptsButton.image = NSImage(systemSymbolName: "doc.on.doc", accessibilityDescription: nil)
        copyDNSAttemptsButton.contentTintColor = HajimiAppearance.accentText
        exportDNSAttemptsButton.image = NSImage(systemSymbolName: "square.and.arrow.down", accessibilityDescription: nil)
        exportDNSAttemptsButton.contentTintColor = HajimiAppearance.accentText
        let detectionControls = NSStackView(views: [startDetectionButton, stopDetectionButton,
                                                    copyNetworkButton, exportNetworkButton, closeDiagnosticsButton])
        detectionControls.orientation = .horizontal
        detectionControls.spacing = 10
        detectionRows.orientation = .vertical
        detectionRows.alignment = .leading
        detectionRows.spacing = 10
        let detectionNote = NSTextField(wrappingLabelWithString: NetworkDiagnosticsSummary.detectionScope
            + "\n" + NetworkDiagnosticsSummary.reportScope)
        detectionNote.font = .systemFont(ofSize: 11)
        detectionNote.textColor = .secondaryLabelColor
        detectionNote.setContentCompressionResistancePriority(.required, for: .vertical)
        func heading(_ text: String) -> NSTextField {
            let label = NSTextField(labelWithString: text)
            label.font = .systemFont(ofSize: 14, weight: .semibold)
            label.textColor = HajimiAppearance.accentText
            return label
        }
        dnsLabel.font = .monospacedDigitSystemFont(ofSize: 12, weight: .regular)
        schedulerLabel.font = .monospacedDigitSystemFont(ofSize: 12, weight: .regular)
        schedulerLabel.textColor = .secondaryLabelColor
        dnsAttemptsLabel.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        dnsAttemptsLabel.isSelectable = true
        let headers = ["阶段", "次数 / 失败 / 中止", "近期成功样本", "p50", "p95", "最近"]
        var rows: [[NSView]] = [headers.map { header in
            let label = NSTextField(labelWithString: header)
            label.font = .systemFont(ofSize: 11, weight: .semibold)
            label.textColor = .secondaryLabelColor
            return label
        }]
        for (stage, name) in NetworkDiagnosticsFormatting.stages {
            let label = NSTextField(labelWithString: name)
            label.font = .systemFont(ofSize: 12, weight: .medium)
            let fields = (0..<5).map { _ in
                let field = NSTextField(labelWithString: "--")
                field.font = .monospacedDigitSystemFont(ofSize: 12, weight: .regular)
                return field
            }
            values[stage] = fields
            rows.append([label] + fields)
        }
        let grid = NSGridView(views: rows)
        statisticsGrid = grid
        grid.wantsLayer = true
        grid.layer?.cornerRadius = 12
        grid.layer?.cornerCurve = .continuous
        grid.layer?.borderWidth = 1
        grid.rowSpacing = 13
        grid.columnSpacing = 16
        grid.column(at: 0).width = 158
        for column in 1..<6 { grid.column(at: column).width = column == 1 ? 140 : (column == 2 ? 100 : 85) }
        grid.column(at: 0).leadingPadding = 12
        grid.column(at: 5).trailingPadding = 12
        grid.row(at: 0).topPadding = 12
        grid.row(at: 0).bottomPadding = 4
        grid.row(at: rows.count - 1).bottomPadding = 12
        let line = NSBox()
        line.boxType = .separator
        let note = NSTextField(wrappingLabelWithString: NetworkDiagnosticsFormatting.scope)
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        note.setContentCompressionResistancePriority(.required, for: .vertical)
        let localHeading = heading("本地网络")
        let connectivityHeading = heading("连通性与延迟")
        let statisticsHeading = heading("应用运行统计")
        let stack = NSStackView(views: [eyebrow, title, subtitle, runtimeLabel, localHeading, localNetworkLabel,
                                        connectivityHeading, detectionControls, detectionStateLabel,
                                        detectionRows, detectionNote, line, statisticsHeading, dnsLabel, schedulerLabel, grid,
                                        copyDNSAttemptsButton, exportDNSAttemptsButton, dnsAttemptsLabel, note])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        stack.setCustomSpacing(5, after: eyebrow)
        stack.setCustomSpacing(6, after: title)
        stack.setCustomSpacing(24, after: runtimeLabel)
        stack.setCustomSpacing(10, after: localHeading)
        stack.setCustomSpacing(24, after: localNetworkLabel)
        stack.setCustomSpacing(10, after: connectivityHeading)
        stack.setCustomSpacing(10, after: statisticsHeading)
        stack.setCustomSpacing(8, after: copyDNSAttemptsButton)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 24),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: bottomAnchor, constant: -24),
            subtitle.widthAnchor.constraint(equalTo: stack.widthAnchor),
            runtimeLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            localNetworkLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            detectionStateLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            detectionRows.widthAnchor.constraint(equalTo: stack.widthAnchor),
            detectionNote.widthAnchor.constraint(equalTo: stack.widthAnchor),
            dnsLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            schedulerLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            dnsAttemptsLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            note.widthAnchor.constraint(equalTo: stack.widthAnchor),
            line.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        refreshSurfaceAppearance()
        apply(NetworkPerformanceSnapshot(), scheduler: nil)
    }

    public required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    public override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        refreshSurfaceAppearance()
    }

    private func refreshSurfaceAppearance() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.backgroundColor = HajimiAppearance.workspace.cgColor
            statisticsGrid?.layer?.backgroundColor = HajimiAppearance.panel.cgColor
            statisticsGrid?.layer?.borderColor = HajimiAppearance.border.cgColor
        }
    }

    public func applyContext(_ context: NetworkDiagnosticsRuntimeContext, detectionAvailable: Bool) {
        precondition(Thread.isMainThread)
        let wasReady = latestContext.engineRunning
        latestContext = context
        let text = NetworkDiagnosticsSummary.runtime(context)
        if runtimeLabel.stringValue != text { runtimeLabel.stringValue = text }
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
        copyNetworkButton.isEnabled = statisticsReady
        exportNetworkButton.isEnabled = statisticsReady
    }

    public func clearLocalNetwork() {
        precondition(Thread.isMainThread)
        latestLocalNetwork = nil
        localNetworkLabel.stringValue = "网络或配置已变化，正在重新读取本地网络信息…"
        let canExportNetwork = statisticsReady && latestConnectivity != nil
        copyNetworkButton.isEnabled = canExportNetwork
        exportNetworkButton.isEnabled = canExportNetwork
    }

    public func prepareDetection() {
        precondition(Thread.isMainThread)
        preparingDetection = true
        detectionStateLabel.stringValue = "正在准备本轮网络检测…"
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
        startDetectionButton.isEnabled = onStartDetection != nil && latestContext.engineRunning
        stopDetectionButton.isEnabled = false
        let canExportNetwork = statisticsReady && latestLocalNetwork != nil
        copyNetworkButton.isEnabled = canExportNetwork
        exportNetworkButton.isEnabled = canExportNetwork
    }

    @objc private func startDetection() { onStartDetection?() }
    @objc private func stopDetection() { onStopDetection?() }
    @objc private func closeDiagnostics() {
        onStopDetection?()
        if let onCloseDiagnostics {
            onCloseDiagnostics()
        } else {
            window?.performClose(nil)
        }
    }

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

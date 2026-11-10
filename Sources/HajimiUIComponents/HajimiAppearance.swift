import AppKit

public enum HajimiAppearance {
    public static var cardCornerRadius: CGFloat {
        CGFloat(HajimiThemeCenter.shared.currentTheme.cardCornerRadius)
    }
    public static var innerCornerRadius: CGFloat {
        CGFloat(HajimiThemeCenter.shared.currentTheme.innerCornerRadius)
    }

    public static let workspace = themedColor(
        defaultLight: NSColor(calibratedRed: 0.952, green: 0.965, blue: 0.961, alpha: 1),
        defaultDark: NSColor(calibratedRed: 0.058, green: 0.071, blue: 0.078, alpha: 1),
        custom: { HajimiUITheme.color(fromHex: $0.workspaceHex, alpha: 1.0) }
    )
    public static let sidebar = themedColor(
        defaultLight: NSColor(calibratedRed: 0.916, green: 0.934, blue: 0.928, alpha: 0.97),
        defaultDark: NSColor(calibratedRed: 0.078, green: 0.095, blue: 0.104, alpha: 0.98),
        custom: { HajimiUITheme.color(fromHex: $0.sidebarHex, alpha: 0.98) }
    )
    public static let panel = themedColor(
        defaultLight: NSColor(calibratedRed: 0.997, green: 0.999, blue: 0.998, alpha: 0.98),
        defaultDark: NSColor(calibratedRed: 0.102, green: 0.122, blue: 0.132, alpha: 0.97),
        custom: { HajimiUITheme.color(fromHex: $0.panelHex, alpha: 0.98) }
    )
    public static let elevatedPanel = themedColor(
        defaultLight: NSColor(calibratedRed: 1.000, green: 1.000, blue: 1.000, alpha: 0.99),
        defaultDark: NSColor(calibratedRed: 0.125, green: 0.149, blue: 0.161, alpha: 0.98),
        custom: { HajimiUITheme.color(fromHex: $0.elevatedPanelHex, alpha: 0.99) }
    )
    public static let mutedPanel = themedColor(
        defaultLight: NSColor(calibratedRed: 0.935, green: 0.950, blue: 0.945, alpha: 1),
        defaultDark: NSColor(calibratedRed: 0.130, green: 0.154, blue: 0.166, alpha: 1),
        custom: { HajimiUITheme.color(fromHex: $0.mutedPanelHex, alpha: 1.0) }
    )
    public static let cardHeaderFill = themedColor(
        defaultLight: NSColor(calibratedRed: 0.944, green: 0.958, blue: 0.952, alpha: 0.78),
        defaultDark: NSColor(calibratedRed: 0.118, green: 0.142, blue: 0.153, alpha: 0.78),
        custom: { HajimiUITheme.color(fromHex: $0.elevatedPanelHex, alpha: 0.82) }
    )
    public static let border = themedColor(
        defaultLight: NSColor(calibratedRed: 0.06, green: 0.16, blue: 0.12, alpha: 0.10),
        defaultDark: NSColor(calibratedRed: 0.80, green: 0.94, blue: 0.88, alpha: 0.12),
        custom: { HajimiUITheme.color(fromHex: $0.accentHex, alpha: CGFloat($0.borderAlpha)) }
    )
    public static let specularHighlight = themedColor(
        defaultLight: NSColor(calibratedWhite: 1.0, alpha: 0.76),
        defaultDark: NSColor(calibratedRed: 0.84, green: 0.96, blue: 0.91, alpha: 0.08),
        custom: { NSColor(calibratedWhite: 1.0, alpha: CGFloat($0.highlightAlpha)) }
    )
    public static let subtleDivider = themedColor(
        defaultLight: NSColor(calibratedRed: 0.06, green: 0.16, blue: 0.12, alpha: 0.065),
        defaultDark: NSColor(calibratedRed: 0.80, green: 0.94, blue: 0.88, alpha: 0.075),
        custom: { HajimiUITheme.color(fromHex: $0.accentHex, alpha: CGFloat(max(0.06, $0.borderAlpha * 0.55))) }
    )
    public static let selection = themedColor(
        defaultLight: NSColor(calibratedRed: 0.04, green: 0.56, blue: 0.42, alpha: 0.13),
        defaultDark: NSColor(calibratedRed: 0.18, green: 0.82, blue: 0.61, alpha: 0.20),
        custom: { HajimiUITheme.color(fromHex: $0.accentHex, alpha: 0.18) }
    )
    public static let accent = themedColor(
        defaultLight: NSColor(calibratedRed: 0.04, green: 0.56, blue: 0.41, alpha: 1),
        defaultDark: NSColor(calibratedRed: 0.18, green: 0.82, blue: 0.61, alpha: 1),
        custom: { HajimiUITheme.color(fromHex: $0.accentHex, alpha: 1.0) }
    )
    public static let accentText = themedColor(
        defaultLight: NSColor(calibratedRed: 0.03, green: 0.45, blue: 0.33, alpha: 1),
        defaultDark: NSColor(calibratedRed: 0.34, green: 0.91, blue: 0.72, alpha: 1),
        custom: { HajimiUITheme.color(fromHex: $0.accentTextHex, alpha: 1.0) }
    )
    public static let accentSubtle = themedColor(
        defaultLight: NSColor(calibratedRed: 0.04, green: 0.56, blue: 0.42, alpha: 0.10),
        defaultDark: NSColor(calibratedRed: 0.18, green: 0.82, blue: 0.61, alpha: 0.16),
        custom: { HajimiUITheme.color(fromHex: $0.accentHex, alpha: 0.15) }
    )
    public static let uploadAccent = themedColor(
        defaultLight: NSColor(calibratedRed: 0.11, green: 0.46, blue: 0.84, alpha: 1),
        defaultDark: NSColor(calibratedRed: 0.35, green: 0.69, blue: 0.98, alpha: 1),
        custom: { HajimiUITheme.color(fromHex: $0.uploadAccentHex, alpha: 1.0) }
    )
    public static let indigoAccent = themedColor(
        defaultLight: NSColor(calibratedRed: 0.33, green: 0.36, blue: 0.84, alpha: 1),
        defaultDark: NSColor(calibratedRed: 0.54, green: 0.58, blue: 0.98, alpha: 1),
        custom: { HajimiUITheme.color(fromHex: $0.indigoAccentHex, alpha: 1.0) }
    )
    public static let statusSuccess = dynamicColor(
        light: NSColor(calibratedRed: 0.06, green: 0.58, blue: 0.38, alpha: 1),
        dark: NSColor(calibratedRed: 0.24, green: 0.84, blue: 0.58, alpha: 1)
    )
    public static let statusWarning = dynamicColor(
        light: NSColor(calibratedRed: 0.82, green: 0.48, blue: 0.04, alpha: 1),
        dark: NSColor(calibratedRed: 0.98, green: 0.68, blue: 0.22, alpha: 1)
    )
    public static let statusDanger = dynamicColor(
        light: NSColor(calibratedRed: 0.82, green: 0.18, blue: 0.20, alpha: 1),
        dark: NSColor(calibratedRed: 0.98, green: 0.36, blue: 0.38, alpha: 1)
    )
    public static let statusInfo = dynamicColor(
        light: NSColor(calibratedRed: 0.12, green: 0.46, blue: 0.82, alpha: 1),
        dark: NSColor(calibratedRed: 0.36, green: 0.68, blue: 0.96, alpha: 1)
    )

    public static func iconBadge(symbolName: String,
                                 tint: NSColor = HajimiAppearance.accentText,
                                 background: NSColor = HajimiAppearance.accentSubtle,
                                 size: CGFloat = 34,
                                 symbolSize: CGFloat = 15) -> HajimiSurfaceView {
        let badge = HajimiSurfaceView(
            fill: background,
            border: tint.themedAlpha(0.22),
            cornerRadius: min(11, round(size * 0.3))
        )
        badge.translatesAutoresizingMaskIntoConstraints = false
        let icon = NSImageView()
        icon.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: nil)
        icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: symbolSize, weight: .semibold)
        icon.contentTintColor = tint
        icon.translatesAutoresizingMaskIntoConstraints = false
        badge.addSubview(icon)
        NSLayoutConstraint.activate([
            badge.widthAnchor.constraint(equalToConstant: size),
            badge.heightAnchor.constraint(equalToConstant: size),
            icon.centerXAnchor.constraint(equalTo: badge.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: badge.centerYAnchor)
        ])
        return badge
    }

    public static func pillBadge(text: String,
                                 tint: NSColor = HajimiAppearance.accentText,
                                 fill: NSColor? = nil,
                                 fontSize: CGFloat = 10) -> HajimiSurfaceView {
        let resolvedFill = fill ?? tint.themedAlpha(0.12)
        let pill = HajimiSurfaceView(
            fill: resolvedFill,
            border: tint.themedAlpha(0.24),
            cornerRadius: 6
        )
        pill.translatesAutoresizingMaskIntoConstraints = false
        let label = NSTextField(labelWithString: text)
        label.font = .systemFont(ofSize: fontSize, weight: .semibold)
        label.textColor = tint
        label.translatesAutoresizingMaskIntoConstraints = false
        pill.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: pill.leadingAnchor, constant: 7),
            label.trailingAnchor.constraint(equalTo: pill.trailingAnchor, constant: -7),
            label.topAnchor.constraint(equalTo: pill.topAnchor, constant: 2.5),
            label.bottomAnchor.constraint(equalTo: pill.bottomAnchor, constant: -2.5)
        ])
        return pill
    }

    public static func formatByteCount(_ bytes: UInt64) -> String {
        if bytes < 1024 {
            return "\(bytes) B"
        }
        let units = ["KB", "MB", "GB", "TB"]
        var value = Double(bytes) / 1024.0
        var unitIndex = 0
        while value >= 1024.0 && unitIndex < units.count - 1 {
            value /= 1024.0
            unitIndex += 1
        }
        if value >= 100.0 {
            return String(format: "%.0f %@", value, units[unitIndex])
        } else if value >= 10.0 {
            return String(format: "%.1f %@", value, units[unitIndex])
        } else {
            return String(format: "%.2f %@", value, units[unitIndex])
        }
    }

    private static func dynamicColor(light: NSColor, dark: NSColor) -> NSColor {
        NSColor(name: nil) { appearance in
            let match = appearance.bestMatch(from: [.darkAqua, .aqua])
            return match == .darkAqua ? dark : light
        }
    }

    private static func themedColor(defaultLight: NSColor,
                                    defaultDark: NSColor,
                                    custom: @escaping (HajimiUITheme) -> NSColor) -> NSColor {
        NSColor(name: nil) { appearance in
            let center = HajimiThemeCenter.shared
            if center.isDefaultAdaptiveThemeActive {
                let match = appearance.bestMatch(from: [.darkAqua, .aqua])
                return match == .darkAqua ? defaultDark : defaultLight
            }
            return custom(center.currentTheme)
        }
    }
}

public final class HajimiSurfaceView: NSView {
    public var fillColor: NSColor { didSet { needsDisplay = true } }
    public var borderColor: NSColor? { didSet { needsDisplay = true } }
    public var cornerRadius: CGFloat { didSet { updateLayerAppearance() } }
    public var borderWidth: CGFloat { didSet { needsDisplay = true } }
    private let baseCornerRadius: CGFloat
    private let topHighlightLayer = CALayer()

    public init(fill: NSColor = HajimiAppearance.panel,
                border: NSColor? = nil,
                cornerRadius: CGFloat = HajimiAppearance.cardCornerRadius,
                borderWidth: CGFloat = 1) {
        self.fillColor = fill
        self.borderColor = border
        self.baseCornerRadius = cornerRadius
        self.cornerRadius = cornerRadius
        self.borderWidth = borderWidth
        super.init(frame: .zero)
        wantsLayer = true
        layer?.addSublayer(topHighlightLayer)
    }

    public func syncThemeCornerRadiusIfAppropriate() {
        guard baseCornerRadius > 4 else { return }
        let themeCardR = HajimiAppearance.cardCornerRadius
        let scale = themeCardR / 14.0
        let updated = max(0, min(28, round(baseCornerRadius * scale)))
        if abs(cornerRadius - updated) > 0.4 {
            cornerRadius = updated
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override public var wantsUpdateLayer: Bool { true }

    override public func updateLayer() {
        updateLayerAppearance()
    }

    override public func layout() {
        super.layout()
        updateHighlightGeometry()
    }

    override public func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }

    private func updateHighlightGeometry() {
        guard cornerRadius >= 10, borderColor != nil, bounds.width > 24, bounds.height > 20 else {
            topHighlightLayer.isHidden = true
            return
        }
        topHighlightLayer.isHidden = false
        let inset = max(6, cornerRadius * 0.65)
        let y = isFlipped ? 1.0 : max(0, bounds.height - 1.5)
        topHighlightLayer.frame = CGRect(x: inset, y: y, width: max(0, bounds.width - inset * 2), height: 1.0)
    }

    private func updateLayerAppearance() {
        guard let layer else { return }
        layer.cornerRadius = cornerRadius
        layer.cornerCurve = .continuous
        updateHighlightGeometry()
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer.backgroundColor = fillColor.cgColor
            topHighlightLayer.backgroundColor = HajimiAppearance.specularHighlight.cgColor
            if let borderColor {
                layer.borderWidth = borderWidth
                layer.borderColor = borderColor.cgColor
            } else {
                layer.borderWidth = 0
                layer.borderColor = nil
            }
        }
    }
}

public final class HajimiNavigationButton: NSButton {
    private let activeIndicator = NSView()
    private var trackingAreaRef: NSTrackingArea?
    private var isHovered = false { didSet { needsDisplay = true } }

    public var isActivePage = false {
        didSet {
            font = .systemFont(ofSize: 13, weight: isActivePage ? .semibold : .medium)
            contentTintColor = isActivePage ? HajimiAppearance.accentText : .secondaryLabelColor
            activeIndicator.isHidden = !isActivePage
            needsDisplay = true
        }
    }

    public var isCurrentPage: Bool {
        get { isActivePage }
        set { isActivePage = newValue }
    }

    public init(title: String, symbolName: String? = nil, target: AnyObject?, action: Selector?) {
        super.init(frame: .zero)
        self.title = title
        self.target = target
        self.action = action
        isBordered = false
        bezelStyle = .regularSquare
        if let symbolName { image = NSImage(systemSymbolName: symbolName, accessibilityDescription: title) }
        imagePosition = .imageLeading
        imageHugsTitle = true
        alignment = .left
        symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 14, weight: .semibold)
        font = .systemFont(ofSize: 13, weight: .medium)
        contentTintColor = .secondaryLabelColor
        wantsLayer = true
        layer?.cornerRadius = 10
        layer?.cornerCurve = .continuous

        activeIndicator.wantsLayer = true
        activeIndicator.layer?.cornerRadius = 1.75
        activeIndicator.layer?.cornerCurve = .continuous
        activeIndicator.translatesAutoresizingMaskIntoConstraints = false
        activeIndicator.isHidden = true
        addSubview(activeIndicator)

        translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            heightAnchor.constraint(equalToConstant: 36),
            activeIndicator.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            activeIndicator.centerYAnchor.constraint(equalTo: centerYAnchor),
            activeIndicator.widthAnchor.constraint(equalToConstant: 3.5),
            activeIndicator.heightAnchor.constraint(equalToConstant: 18)
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override public var intrinsicContentSize: NSSize {
        let base = super.intrinsicContentSize
        return NSSize(width: base.width + 24, height: 36)
    }

    override public func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingAreaRef {
            removeTrackingArea(trackingAreaRef)
        }
        let area = NSTrackingArea(
            rect: bounds,
            options: [.mouseEnteredAndExited, .activeInActiveApp, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
        trackingAreaRef = area
    }

    override public func mouseEntered(with event: NSEvent) {
        super.mouseEntered(with: event)
        isHovered = true
        if !isActivePage {
            contentTintColor = .labelColor
        }
    }

    override public func mouseExited(with event: NSEvent) {
        super.mouseExited(with: event)
        isHovered = false
        if !isActivePage {
            contentTintColor = .secondaryLabelColor
        }
    }

    override public var wantsUpdateLayer: Bool { true }

    override public func updateLayer() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            activeIndicator.layer?.backgroundColor = HajimiAppearance.accent.cgColor
            if isActivePage {
                layer?.backgroundColor = HajimiAppearance.selection.cgColor
                layer?.borderWidth = 1
                layer?.borderColor = HajimiAppearance.accent.themedAlpha(0.28).cgColor
            } else if isHovered {
                layer?.backgroundColor = HajimiAppearance.mutedPanel.themedAlpha(0.85).cgColor
                layer?.borderWidth = 1
                layer?.borderColor = HajimiAppearance.border.cgColor
            } else {
                layer?.backgroundColor = NSColor.clear.cgColor
                layer?.borderWidth = 0
                layer?.borderColor = nil
            }
        }
    }

    override public func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

// MARK: - Home Page Traffic Usage & Split Widgets (Zero Auto-Layout Conflict Custom-Drawn Bento Components)

public struct HajimiTrafficUsageEntry: Equatable {
    public let id: String
    public let title: String
    public let subtitle: String
    public let symbolName: String
    public let tintColor: NSColor
    public let uploadedBytes: UInt64
    public let downloadedBytes: UInt64
    public let activeConnections: Int
    public let totalConnections: Int
    public let appIcon: NSImage?

    public var totalBytes: UInt64 {
        uploadedBytes &+ downloadedBytes
    }

    public init(id: String,
                title: String,
                subtitle: String,
                symbolName: String,
                tintColor: NSColor,
                uploadedBytes: UInt64,
                downloadedBytes: UInt64,
                activeConnections: Int,
                totalConnections: Int,
                appIcon: NSImage? = nil) {
        self.id = id
        self.title = title
        self.subtitle = subtitle
        self.symbolName = symbolName
        self.tintColor = tintColor
        self.uploadedBytes = uploadedBytes
        self.downloadedBytes = downloadedBytes
        self.activeConnections = activeConnections
        self.totalConnections = totalConnections
        self.appIcon = appIcon
    }

    public static func == (lhs: HajimiTrafficUsageEntry, rhs: HajimiTrafficUsageEntry) -> Bool {
        lhs.id == rhs.id &&
        lhs.title == rhs.title &&
        lhs.subtitle == rhs.subtitle &&
        lhs.symbolName == rhs.symbolName &&
        lhs.uploadedBytes == rhs.uploadedBytes &&
        lhs.downloadedBytes == rhs.downloadedBytes &&
        lhs.activeConnections == rhs.activeConnections &&
        lhs.totalConnections == rhs.totalConnections &&
        ((lhs.appIcon != nil) == (rhs.appIcon != nil))
    }
}

public struct HajimiTrafficSplitSnapshot: Equatable {
    public let proxyBytes: UInt64
    public let directBytes: UInt64
    public let dnsAndSystemBytes: UInt64
    public let trackedAppCount: Int
    public let trackedPolicyCount: Int

    public var totalBytes: UInt64 {
        proxyBytes &+ directBytes &+ dnsAndSystemBytes
    }

    public init(proxyBytes: UInt64 = 0,
                directBytes: UInt64 = 0,
                dnsAndSystemBytes: UInt64 = 0,
                trackedAppCount: Int = 0,
                trackedPolicyCount: Int = 0) {
        self.proxyBytes = proxyBytes
        self.directBytes = directBytes
        self.dnsAndSystemBytes = dnsAndSystemBytes
        self.trackedAppCount = trackedAppCount
        self.trackedPolicyCount = trackedPolicyCount
    }
}

/// Compact 3-way traffic split bar (Proxy vs Direct vs DNS/System) for the Runtime Overview card.
public final class HajimiTrafficSplitBarView: NSView {
    public static weak var activeInstance: HajimiTrafficSplitBarView?

    public var snapshot = HajimiTrafficSplitSnapshot() {
        didSet {
            if snapshot != oldValue {
                needsDisplay = true
            }
        }
    }

    public override init(frame frameRect: NSRect = .zero) {
        super.init(frame: frameRect)
        wantsLayer = true
        Self.activeInstance = self
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override public var isFlipped: Bool { true }
    override public var isOpaque: Bool { false }

    override public func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }

    override public func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard bounds.width > 40, bounds.height >= 16 else { return }

        let total = snapshot.totalBytes
        let proxyRatio: CGFloat
        let directRatio: CGFloat
        let dnsRatio: CGFloat
        if total > 0 {
            proxyRatio = CGFloat(Double(snapshot.proxyBytes) / Double(total))
            directRatio = CGFloat(Double(snapshot.directBytes) / Double(total))
            dnsRatio = max(0, 1.0 - proxyRatio - directRatio)
        } else {
            proxyRatio = 0
            directRatio = 0
            dnsRatio = 0
        }

        let proxyPct = total > 0 ? Int(round(proxyRatio * 100)) : 0
        let directPct = total > 0 ? Int(round(directRatio * 100)) : 0
        let dnsPct = total > 0 ? max(0, 100 - proxyPct - directPct) : 0

        let labelFont = NSFont.systemFont(ofSize: 10, weight: .semibold)
        let metricFont = NSFont.monospacedDigitSystemFont(ofSize: 10, weight: .medium)

        let titleAttrs: [NSAttributedString.Key: Any] = [
            .font: labelFont,
            .foregroundColor: NSColor.secondaryLabelColor
        ]
        let legendText = total > 0
            ? "代理出站 \(proxyPct)%  ·  直连分流 \(directPct)%  ·  DNS/系统 \(dnsPct)%"
            : "代理出站 0%  ·  直连分流 0%  ·  DNS/系统 0%"
        let legendAttrs: [NSAttributedString.Key: Any] = [
            .font: metricFont,
            .foregroundColor: NSColor.secondaryLabelColor
        ]

        let title = "分流流量占比"
        (title as NSString).draw(at: NSPoint(x: 4, y: 1), withAttributes: titleAttrs)

        let legendSize = (legendText as NSString).size(withAttributes: legendAttrs)
        if bounds.width > legendSize.width + 95 {
            (legendText as NSString).draw(
                at: NSPoint(x: bounds.width - legendSize.width - 4, y: 1),
                withAttributes: legendAttrs
            )
        }

        let barRect = NSRect(x: 4, y: 17, width: max(12, bounds.width - 8), height: 6)
        let trackPath = NSBezierPath(roundedRect: barRect, xRadius: 3, yRadius: 3)
        HajimiAppearance.mutedPanel.setFill()
        trackPath.fill()

        guard total > 0 else { return }

        NSGraphicsContext.saveGraphicsState()
        trackPath.addClip()

        var cursorX = barRect.minX
        let segments: [(CGFloat, NSColor)] = [
            (proxyRatio, HajimiAppearance.accent),
            (directRatio, HajimiAppearance.uploadAccent),
            (dnsRatio, HajimiAppearance.indigoAccent)
        ]
        for (ratio, color) in segments where ratio > 0.002 {
            let segWidth = max(3, barRect.width * ratio)
            let segRect = NSRect(x: cursorX, y: barRect.minY, width: segWidth, height: barRect.height)
            color.setFill()
            NSBezierPath.fill(segRect)
            cursorX += segWidth
        }
        NSGraphicsContext.restoreGraphicsState()
    }
}

/// Interactive Home Page Widget displaying real-time and cumulative per-application / per-policy traffic usage.
public final class HajimiAppTrafficWidgetView: NSView {
    public enum DisplayMode: Int {
        case byApplication = 0
        case byPolicy = 1
    }

    public static weak var activeInstance: HajimiAppTrafficWidgetView?

    public var displayMode: DisplayMode = .byApplication {
        didSet {
            scrollOffset = 0
            updateModeButtonTitle()
            needsDisplay = true
        }
    }

    public var appEntries: [HajimiTrafficUsageEntry] = [] {
        didSet {
            if appEntries != oldValue && displayMode == .byApplication {
                clampScrollOffset()
                needsDisplay = true
            }
        }
    }

    public var policyEntries: [HajimiTrafficUsageEntry] = [] {
        didSet {
            if policyEntries != oldValue && displayMode == .byPolicy {
                clampScrollOffset()
                needsDisplay = true
            }
        }
    }

    public var splitSnapshot = HajimiTrafficSplitSnapshot() {
        didSet {
            if splitSnapshot != oldValue {
                needsDisplay = true
            }
        }
    }

    public var onResetRequested: (() -> Void)?

    private var scrollOffset: CGFloat = 0
    private let modeButton = NSButton(title: "视图: 按程序", target: nil, action: nil)
    private let resetButton = NSButton(title: "清空", target: nil, action: nil)

    public override init(frame frameRect: NSRect = .zero) {
        super.init(frame: frameRect)
        wantsLayer = true
        Self.activeInstance = self

        modeButton.target = self
        modeButton.action = #selector(toggleDisplayMode)
        modeButton.bezelStyle = .rounded
        modeButton.controlSize = .small
        modeButton.font = .systemFont(ofSize: 10.5, weight: .medium)
        modeButton.image = NSImage(systemSymbolName: "arrow.left.arrow.right", accessibilityDescription: nil)
        modeButton.imagePosition = .imageLeading
        modeButton.toolTip = "在“按本地应用程序”与“按出站策略/节点”之间切换流量排行视图"

        resetButton.target = self
        resetButton.action = #selector(handleResetButton)
        resetButton.bezelStyle = .rounded
        resetButton.controlSize = .small
        resetButton.font = .systemFont(ofSize: 10.5, weight: .medium)
        resetButton.image = NSImage(systemSymbolName: "arrow.counterclockwise", accessibilityDescription: nil)
        resetButton.imagePosition = .imageLeading
        resetButton.toolTip = "清空当前会话的应用程序与策略流量排行统计"

        addSubview(modeButton)
        addSubview(resetButton)
        updateModeButtonTitle()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override public var isFlipped: Bool { true }
    override public var isOpaque: Bool { false }

    public func update(appEntries: [HajimiTrafficUsageEntry],
                       policyEntries: [HajimiTrafficUsageEntry],
                       split: HajimiTrafficSplitSnapshot) {
        let changed = (self.appEntries != appEntries)
            || (self.policyEntries != policyEntries)
            || (self.splitSnapshot != split)
        self.appEntries = appEntries
        self.policyEntries = policyEntries
        self.splitSnapshot = split
        if changed {
            clampScrollOffset()
            needsDisplay = true
        }
    }

    @objc private func toggleDisplayMode() {
        displayMode = (displayMode == .byApplication) ? .byPolicy : .byApplication
    }

    @objc private func handleResetButton() {
        appEntries.removeAll()
        policyEntries.removeAll()
        splitSnapshot = HajimiTrafficSplitSnapshot()
        scrollOffset = 0
        needsDisplay = true
        onResetRequested?()
    }

    private func updateModeButtonTitle() {
        modeButton.title = displayMode == .byApplication ? "按程序" : "按策略"
    }

    private func clampScrollOffset() {
        let activeList = displayMode == .byApplication ? appEntries : policyEntries
        let topOffset: CGFloat = 50
        let bottomPadding: CGFloat = 10
        let viewportHeight = max(60, bounds.height - topOffset - bottomPadding)
        let rowHeight: CGFloat = 38
        let rowSpacing: CGFloat = 5
        let contentHeight = activeList.isEmpty
            ? 0
            : CGFloat(activeList.count) * rowHeight + CGFloat(max(0, activeList.count - 1)) * rowSpacing
        let maxScroll = max(0, contentHeight - viewportHeight)
        scrollOffset = min(maxScroll, max(0, scrollOffset))
    }

    override public func scrollWheel(with event: NSEvent) {
        let activeList = displayMode == .byApplication ? appEntries : policyEntries
        guard activeList.count > 4 else {
            super.scrollWheel(with: event)
            return
        }
        let delta = event.hasPreciseScrollingDeltas ? event.scrollingDeltaY : event.scrollingDeltaY * 10.0
        let previous = scrollOffset
        scrollOffset -= delta
        clampScrollOffset()
        if abs(scrollOffset - previous) > 0.1 {
            needsDisplay = true
        }
    }

    override public func layout() {
        super.layout()
        clampScrollOffset()
        let showButtons = bounds.width > 280 && bounds.height > 80
        modeButton.isHidden = !showButtons
        resetButton.isHidden = !showButtons
        guard showButtons else { return }
        let resetWidth: CGFloat = 58
        let modeWidth: CGFloat = 68
        let topY: CGFloat = 12
        resetButton.frame = NSRect(x: bounds.width - resetWidth - 14, y: topY, width: resetWidth, height: 22)
        modeButton.frame = NSRect(x: resetButton.frame.minX - modeWidth - 6, y: topY, width: modeWidth, height: 22)
    }

    override public func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }

    override public func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard bounds.width > 40, bounds.height > 40 else { return }

        let cardRect = bounds.insetBy(dx: 0.5, dy: 0.5)
        let cardPath = NSBezierPath(roundedRect: cardRect, xRadius: HajimiAppearance.cardCornerRadius, yRadius: HajimiAppearance.cardCornerRadius)
        HajimiAppearance.panel.setFill()
        cardPath.fill()
        HajimiAppearance.border.setStroke()
        cardPath.lineWidth = 1.0
        cardPath.stroke()

        if cardRect.width > 28 {
            let sheen = NSBezierPath()
            sheen.move(to: NSPoint(x: cardRect.minX + 12, y: cardRect.minY + 1.0))
            sheen.line(to: NSPoint(x: cardRect.maxX - 12, y: cardRect.minY + 1.0))
            sheen.lineWidth = 1.0
            HajimiAppearance.specularHighlight.setStroke()
            sheen.stroke()
        }

        // Header: Eyebrow pill + Title + Subtitle
        let eyebrowText = displayMode == .byApplication ? "APP TELEMETRY" : "POLICY TELEMETRY"
        let eyebrowAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 9.0, weight: .bold),
            .foregroundColor: HajimiAppearance.accentText
        ]
        let eyebrowSize = (eyebrowText as NSString).size(withAttributes: eyebrowAttrs)
        let pillRect = NSRect(x: 16, y: 12, width: eyebrowSize.width + 12, height: 16)
        let pillPath = NSBezierPath(roundedRect: pillRect, xRadius: 5, yRadius: 5)
        HajimiAppearance.accentSubtle.setFill()
        pillPath.fill()
        (eyebrowText as NSString).draw(at: NSPoint(x: pillRect.minX + 6, y: pillRect.minY + 2), withAttributes: eyebrowAttrs)

        let titleText = displayMode == .byApplication ? "应用流量排行" : "策略流量分布"
        let titleAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 13.5, weight: .bold),
            .foregroundColor: NSColor.labelColor
        ]
        let titleX = pillRect.maxX + 8
        (titleText as NSString).draw(at: NSPoint(x: titleX, y: 11), withAttributes: titleAttrs)

        let activeList = displayMode == .byApplication ? appEntries : policyEntries
        let grandTotal = activeList.reduce(UInt64(0)) { $0 &+ $1.totalBytes }
        let countText = displayMode == .byApplication
            ? (activeList.isEmpty ? "按本地 macOS 应用程序实时统计上下行流量" : "已统计 \(max(splitSnapshot.trackedAppCount, activeList.count)) 个应用 · 共 \(HajimiAppearance.formatByteCount(grandTotal))")
            : (activeList.isEmpty ? "按出站策略与节点统计上下行流量" : "已统计 \(max(splitSnapshot.trackedPolicyCount, activeList.count)) 项策略 · 共 \(HajimiAppearance.formatByteCount(grandTotal))")
        let subAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 10.5, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor
        ]
        (countText as NSString).draw(at: NSPoint(x: 16, y: 31), withAttributes: subAttrs)

        let topOffset: CGFloat = 50
        let bottomPadding: CGFloat = 10
        let viewportRect = NSRect(
            x: 14,
            y: topOffset,
            width: max(40, cardRect.width - 28),
            height: max(60, cardRect.height - topOffset - bottomPadding)
        )

        if activeList.isEmpty {
            let wellR = min(14, max(0, HajimiAppearance.innerCornerRadius))
            let emptyWell = NSBezierPath(roundedRect: viewportRect, xRadius: wellR, yRadius: wellR)
            HajimiAppearance.mutedPanel.themedAlpha(0.45).setFill()
            emptyWell.fill()
            HajimiAppearance.subtleDivider.setStroke()
            emptyWell.lineWidth = 1.0
            emptyWell.stroke()

            let centerStyle = NSMutableParagraphStyle()
            centerStyle.alignment = .center
            let mainEmpty = displayMode == .byApplication ? "暂无应用流量记录" : "暂无策略流量记录"
            let subEmpty = displayMode == .byApplication
                ? "当 Safari、Chrome、微信、Telegram 等本地应用产生连接时，将在此实时显示各 App 用量"
                : "当代理或直连策略产生网络传输时，将在此实时显示各策略流量占比"
            let mainAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 12.0, weight: .semibold),
                .foregroundColor: NSColor.secondaryLabelColor,
                .paragraphStyle: centerStyle
            ]
            let detailAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 10.5, weight: .regular),
                .foregroundColor: NSColor.tertiaryLabelColor,
                .paragraphStyle: centerStyle
            ]
            let midY = viewportRect.midY
            (mainEmpty as NSString).draw(
                in: NSRect(x: viewportRect.minX + 16, y: midY - 18, width: viewportRect.width - 32, height: 18),
                withAttributes: mainAttrs
            )
            (subEmpty as NSString).draw(
                in: NSRect(x: viewportRect.minX + 16, y: midY + 2, width: viewportRect.width - 32, height: 28),
                withAttributes: detailAttrs
            )
            return
        }

        let rowHeight: CGFloat = 38
        let rowSpacing: CGFloat = 5
        let contentHeight = CGFloat(activeList.count) * rowHeight + CGFloat(max(0, activeList.count - 1)) * rowSpacing
        let hasScrollbar = contentHeight > viewportRect.height + 1

        NSGraphicsContext.saveGraphicsState()
        NSBezierPath(rect: viewportRect).addClip()

        for (index, entry) in activeList.enumerated() {
            let rowY = topOffset + CGFloat(index) * (rowHeight + rowSpacing) - scrollOffset
            if rowY + rowHeight < viewportRect.minY || rowY > viewportRect.maxY {
                continue
            }
            let rowWidth = hasScrollbar ? max(40, viewportRect.width - 7) : viewportRect.width
            let rowRect = NSRect(x: viewportRect.minX, y: rowY, width: rowWidth, height: rowHeight)
            let rowR = min(12, max(0, round(HajimiAppearance.innerCornerRadius * 0.8)))
            let wellPath = NSBezierPath(roundedRect: rowRect, xRadius: rowR, yRadius: rowR)
            HajimiAppearance.elevatedPanel.themedAlpha(0.62).setFill()
            wellPath.fill()
            HajimiAppearance.subtleDivider.setStroke()
            wellPath.lineWidth = 1.0
            wellPath.stroke()

            let title = entry.title
            let subtitle = entry.subtitle
            let symbolName = entry.symbolName
            let tint = entry.tintColor
            let upBytes = entry.uploadedBytes
            let downBytes = entry.downloadedBytes
            let itemTotal = upBytes &+ downBytes
            let shareRatio: CGFloat = (grandTotal > 0 && itemTotal > 0)
                ? min(1.0, max(0.02, CGFloat(Double(itemTotal) / Double(grandTotal))))
                : 0.0
            let sharePct = (grandTotal > 0 && itemTotal > 0)
                ? Int(round(Double(itemTotal) * 100.0 / Double(grandTotal)))
                : 0

            // App Icon or SF Symbol Badge
            let iconSize: CGFloat = 26
            let iconRect = NSRect(
                x: rowRect.minX + 8,
                y: rowRect.minY + floor((rowHeight - iconSize) * 0.5),
                width: iconSize,
                height: iconSize
            )
            if let appIcon = entry.appIcon {
                appIcon.draw(in: iconRect, from: .zero, operation: .sourceOver, fraction: 1.0, respectFlipped: true, hints: nil)
            } else {
                let iconBg = NSBezierPath(roundedRect: iconRect, xRadius: 6, yRadius: 6)
                tint.withAlphaComponent(0.16).setFill()
                iconBg.fill()
                let sizeConfig = NSImage.SymbolConfiguration(pointSize: iconSize * 0.52, weight: .semibold)
                let colorConfig = NSImage.SymbolConfiguration(paletteColors: [tint])
                if let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: nil)?
                    .withSymbolConfiguration(sizeConfig.applying(colorConfig)) {
                    let imgSize = image.size
                    let imgRect = NSRect(
                        x: iconRect.midX - imgSize.width * 0.5,
                        y: iconRect.midY - imgSize.height * 0.5,
                        width: imgSize.width,
                        height: imgSize.height
                    )
                    image.draw(in: imgRect, from: .zero, operation: .sourceOver, fraction: 0.92, respectFlipped: true, hints: nil)
                }
            }

            // Right-side traffic metrics & share badge
            let pctText = "\(sharePct)%"
            let pctAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 10.0, weight: .bold),
                .foregroundColor: tint
            ]
            let pctSize = (pctText as NSString).size(withAttributes: pctAttrs)
            let pctBadgeWidth = max(34, pctSize.width + 10)
            let pctBadgeRect = NSRect(
                x: rowRect.maxX - pctBadgeWidth - 8,
                y: rowRect.minY + floor((rowHeight - 16) * 0.5),
                width: pctBadgeWidth,
                height: 16
            )
            let pctBadgePath = NSBezierPath(roundedRect: pctBadgeRect, xRadius: 4.5, yRadius: 4.5)
            tint.withAlphaComponent(0.14).setFill()
            pctBadgePath.fill()
            (pctText as NSString).draw(
                at: NSPoint(x: pctBadgeRect.midX - pctSize.width * 0.5, y: pctBadgeRect.minY + 1.5),
                withAttributes: pctAttrs
            )

            // Up / Down text before pctBadge
            let downStr = "↓ " + HajimiAppearance.formatByteCount(downBytes)
            let upStr = "↑ " + HajimiAppearance.formatByteCount(upBytes)
            let downAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 10.5, weight: .semibold),
                .foregroundColor: HajimiAppearance.accentText
            ]
            let upAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 10.0, weight: .medium),
                .foregroundColor: HajimiAppearance.uploadAccent
            ]
            let downSize = (downStr as NSString).size(withAttributes: downAttrs)
            let upSize = (upStr as NSString).size(withAttributes: upAttrs)

            var rightAnchorX = pctBadgeRect.minX - 8
            if rowRect.width > 240 {
                let upX = rightAnchorX - upSize.width
                let downX = upX - downSize.width - 8
                let textY = rowRect.minY + floor((rowHeight - downSize.height) * 0.5)
                (upStr as NSString).draw(at: NSPoint(x: upX, y: textY + 0.5), withAttributes: upAttrs)
                (downStr as NSString).draw(at: NSPoint(x: downX, y: textY), withAttributes: downAttrs)
                rightAnchorX = downX - 10
            }

            // Dual-tone proportion bar in middle-right if width allows
            if rowRect.width > 340 {
                let barWidth = min(92, max(44, floor(rowRect.width * 0.16)))
                let barRect = NSRect(
                    x: rightAnchorX - barWidth,
                    y: rowRect.minY + floor((rowHeight - 5) * 0.5),
                    width: barWidth,
                    height: 5
                )
                let track = NSBezierPath(roundedRect: barRect, xRadius: 2.5, yRadius: 2.5)
                HajimiAppearance.border.setFill()
                track.fill()

                if shareRatio > 0 && itemTotal > 0 {
                    let fillWidth = max(4, barRect.width * shareRatio)
                    let downFraction = CGFloat(Double(downBytes) / Double(itemTotal))
                    let fillRect = NSRect(x: barRect.minX, y: barRect.minY, width: fillWidth, height: barRect.height)
                    let fillPath = NSBezierPath(roundedRect: fillRect, xRadius: 2.5, yRadius: 2.5)
                    NSGraphicsContext.saveGraphicsState()
                    fillPath.addClip()
                    let downPartWidth = fillWidth * downFraction
                    if downPartWidth > 0.5 {
                        HajimiAppearance.accent.setFill()
                        NSBezierPath.fill(NSRect(x: fillRect.minX, y: fillRect.minY, width: downPartWidth, height: fillRect.height))
                    }
                    if fillWidth - downPartWidth > 0.5 {
                        HajimiAppearance.uploadAccent.setFill()
                        NSBezierPath.fill(NSRect(x: fillRect.minX + downPartWidth, y: fillRect.minY, width: fillWidth - downPartWidth, height: fillRect.height))
                    }
                    NSGraphicsContext.restoreGraphicsState()
                }
                rightAnchorX = barRect.minX - 10
            }

            // Title & Subtitle on left
            let textLeftX = iconRect.maxX + 8
            let maxTextWidth = max(40, rightAnchorX - textLeftX)
            let paragraph = NSMutableParagraphStyle()
            paragraph.lineBreakMode = .byTruncatingTail

            let rowTitleAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 11.5, weight: .semibold),
                .foregroundColor: NSColor.labelColor,
                .paragraphStyle: paragraph
            ]
            let rowSubAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 9.5, weight: .regular),
                .foregroundColor: NSColor.tertiaryLabelColor,
                .paragraphStyle: paragraph
            ]

            (title as NSString).draw(
                in: NSRect(x: textLeftX, y: rowRect.minY + 4.0, width: maxTextWidth, height: 15),
                withAttributes: rowTitleAttrs
            )
            (subtitle as NSString).draw(
                in: NSRect(x: textLeftX, y: rowRect.minY + 19.5, width: maxTextWidth, height: 13),
                withAttributes: rowSubAttrs
            )
        }

        if hasScrollbar {
            let maxScroll = max(1, contentHeight - viewportRect.height)
            let thumbHeight = max(20, (viewportRect.height / contentHeight) * viewportRect.height)
            let scrollTrackLen = max(1, viewportRect.height - thumbHeight)
            let thumbY = viewportRect.minY + (scrollOffset / maxScroll) * scrollTrackLen
            let thumbRect = NSRect(x: viewportRect.maxX - 3.5, y: thumbY, width: 3.0, height: thumbHeight)
            let thumbPath = NSBezierPath(roundedRect: thumbRect, xRadius: 1.5, yRadius: 1.5)
            NSColor.tertiaryLabelColor.withAlphaComponent(0.45).setFill()
            thumbPath.fill()
        }

        NSGraphicsContext.restoreGraphicsState()
    }
}

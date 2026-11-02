import AppKit

public enum HajimiAppearance {
    public static let cardCornerRadius: CGFloat = 14
    public static let innerCornerRadius: CGFloat = 10

    public static let workspace = dynamicColor(
        light: NSColor(calibratedRed: 0.954, green: 0.966, blue: 0.961, alpha: 1),
        dark: NSColor(calibratedRed: 0.064, green: 0.078, blue: 0.084, alpha: 1)
    )
    public static let sidebar = dynamicColor(
        light: NSColor(calibratedRed: 0.918, green: 0.935, blue: 0.928, alpha: 0.96),
        dark: NSColor(calibratedRed: 0.084, green: 0.102, blue: 0.110, alpha: 0.98)
    )
    public static let panel = dynamicColor(
        light: NSColor(calibratedRed: 0.996, green: 0.999, blue: 0.998, alpha: 0.98),
        dark: NSColor(calibratedRed: 0.106, green: 0.126, blue: 0.135, alpha: 0.97)
    )
    public static let elevatedPanel = dynamicColor(
        light: NSColor(calibratedRed: 1.000, green: 1.000, blue: 1.000, alpha: 0.99),
        dark: NSColor(calibratedRed: 0.128, green: 0.152, blue: 0.163, alpha: 0.98)
    )
    public static let mutedPanel = dynamicColor(
        light: NSColor(calibratedRed: 0.938, green: 0.952, blue: 0.946, alpha: 1),
        dark: NSColor(calibratedRed: 0.134, green: 0.158, blue: 0.170, alpha: 1)
    )
    public static let cardHeaderFill = dynamicColor(
        light: NSColor(calibratedRed: 0.946, green: 0.960, blue: 0.954, alpha: 0.75),
        dark: NSColor(calibratedRed: 0.122, green: 0.146, blue: 0.156, alpha: 0.75)
    )
    public static let border = dynamicColor(
        light: NSColor(calibratedRed: 0.07, green: 0.17, blue: 0.13, alpha: 0.10),
        dark: NSColor(calibratedRed: 0.82, green: 0.93, blue: 0.88, alpha: 0.12)
    )
    public static let specularHighlight = dynamicColor(
        light: NSColor(calibratedWhite: 1.0, alpha: 0.72),
        dark: NSColor(calibratedRed: 0.85, green: 0.96, blue: 0.91, alpha: 0.075)
    )
    public static let subtleDivider = dynamicColor(
        light: NSColor(calibratedRed: 0.07, green: 0.17, blue: 0.13, alpha: 0.065),
        dark: NSColor(calibratedRed: 0.82, green: 0.93, blue: 0.88, alpha: 0.075)
    )
    public static let selection = dynamicColor(
        light: NSColor(calibratedRed: 0.05, green: 0.56, blue: 0.42, alpha: 0.13),
        dark: NSColor(calibratedRed: 0.19, green: 0.80, blue: 0.60, alpha: 0.20)
    )
    public static let accent = dynamicColor(
        light: NSColor(calibratedRed: 0.04, green: 0.55, blue: 0.41, alpha: 1),
        dark: NSColor(calibratedRed: 0.18, green: 0.81, blue: 0.61, alpha: 1)
    )
    public static let accentText = dynamicColor(
        light: NSColor(calibratedRed: 0.03, green: 0.45, blue: 0.33, alpha: 1),
        dark: NSColor(calibratedRed: 0.35, green: 0.91, blue: 0.72, alpha: 1)
    )
    public static let accentSubtle = dynamicColor(
        light: NSColor(calibratedRed: 0.05, green: 0.56, blue: 0.42, alpha: 0.10),
        dark: NSColor(calibratedRed: 0.19, green: 0.80, blue: 0.60, alpha: 0.16)
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
            border: tint.withAlphaComponent(0.22),
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
        let resolvedFill = fill ?? tint.withAlphaComponent(0.12)
        let pill = HajimiSurfaceView(
            fill: resolvedFill,
            border: tint.withAlphaComponent(0.24),
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

    private static func dynamicColor(light: NSColor, dark: NSColor) -> NSColor {
        NSColor(name: nil) { appearance in
            let match = appearance.bestMatch(from: [.darkAqua, .aqua])
            return match == .darkAqua ? dark : light
        }
    }
}

public final class HajimiSurfaceView: NSView {
    public var fillColor: NSColor { didSet { needsDisplay = true } }
    public var borderColor: NSColor? { didSet { needsDisplay = true } }
    public var cornerRadius: CGFloat { didSet { updateLayerAppearance() } }
    public var borderWidth: CGFloat { didSet { needsDisplay = true } }
    private let topHighlightLayer = CALayer()

    public init(fill: NSColor = HajimiAppearance.panel,
                border: NSColor? = nil,
                cornerRadius: CGFloat = HajimiAppearance.cardCornerRadius,
                borderWidth: CGFloat = 1) {
        self.fillColor = fill
        self.borderColor = border
        self.cornerRadius = cornerRadius
        self.borderWidth = borderWidth
        super.init(frame: .zero)
        wantsLayer = true
        layer?.addSublayer(topHighlightLayer)
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
                layer?.borderColor = HajimiAppearance.accent.withAlphaComponent(0.28).cgColor
            } else if isHovered {
                layer?.backgroundColor = HajimiAppearance.mutedPanel.withAlphaComponent(0.85).cgColor
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

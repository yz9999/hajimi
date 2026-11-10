import AppKit
import Darwin
import HajimiCore
import HajimiMacOSObjC
import HajimiNativeCore
import HajimiUIComponents

// A stale/restarting privileged Helper may close its Unix socket between
// connect and write. Convert that race into EPIPE instead of terminating the
// GUI process with SIGPIPE.
signal(SIGPIPE, SIG_IGN)

/// Custom menu item view that renders a themed menu selection highlight on hover
/// and invokes its action on click without dismissing the enclosing NSMenu.
private final class StatusMenuActionItemView: NSView {
    private let highlightView = NSVisualEffectView()
    private let iconView = NSImageView()
    private let titleField = NSTextField(labelWithString: "")
    private var trackingAreaRef: NSTrackingArea?
    private var isHovered = false
    private var didFireInCurrentPress = false
    var onAction: (() -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        autoresizingMask = [.width]

        highlightView.material = .selection
        highlightView.blendingMode = .withinWindow
        highlightView.state = .active
        highlightView.isEmphasized = true
        highlightView.wantsLayer = true
        highlightView.layer?.cornerRadius = 6
        highlightView.isHidden = true
        highlightView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(highlightView)

        iconView.imageScaling = .scaleProportionallyDown
        iconView.contentTintColor = HajimiAppearance.accentText
        iconView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(iconView)

        titleField.font = NSFont.systemFont(ofSize: 12.5, weight: .semibold)
        titleField.textColor = HajimiAppearance.accentText
        titleField.lineBreakMode = .byTruncatingTail
        titleField.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleField)

        NSLayoutConstraint.activate([
            highlightView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 6),
            highlightView.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -6),
            highlightView.topAnchor.constraint(equalTo: topAnchor, constant: 1),
            highlightView.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -1),
            iconView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            iconView.centerYAnchor.constraint(equalTo: centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 16),
            iconView.heightAnchor.constraint(equalToConstant: 16),
            titleField.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 6),
            titleField.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -14),
            titleField.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        let pillRect = bounds.insetBy(dx: 6, dy: 1.5)
        let radius = min(8.0, max(4.0, HajimiAppearance.innerCornerRadius * 0.65))
        let path = NSBezierPath(roundedRect: pillRect, xRadius: radius, yRadius: radius)
        let active = isHovered || (enclosingMenuItem?.isHighlighted ?? false)
        let fill = active
            ? HajimiAppearance.accent.withAlphaComponent(0.24)
            : HajimiAppearance.panel.withAlphaComponent(0.72)
        let stroke = active
            ? HajimiAppearance.accent.withAlphaComponent(0.55)
            : HajimiAppearance.border
        fill.setFill()
        path.fill()
        stroke.setStroke()
        path.lineWidth = 1.0
        path.stroke()
    }

    func configure(title: String, image: NSImage?) {
        if titleField.stringValue != title {
            titleField.stringValue = title
        }
        if iconView.image !== image {
            iconView.image = image
        }
        updateHighlightAppearance()
    }

    func resetHoverState() {
        isHovered = false
        didFireInCurrentPress = false
        updateHighlightAppearance()
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingAreaRef {
            removeTrackingArea(trackingAreaRef)
        }
        let options: NSTrackingArea.Options = [
            .mouseEnteredAndExited,
            .mouseMoved,
            .activeAlways,
            .inVisibleRect,
            .enabledDuringMouseDrag,
        ]
        let area = NSTrackingArea(rect: bounds, options: options, owner: self, userInfo: nil)
        addTrackingArea(area)
        trackingAreaRef = area
    }

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func mouseEntered(with event: NSEvent) {
        isHovered = true
        updateHighlightAppearance()
    }

    override func mouseMoved(with event: NSEvent) {
        let inside = bounds.contains(convert(event.locationInWindow, from: nil))
        if inside != isHovered {
            isHovered = inside
            updateHighlightAppearance()
        }
    }

    override func mouseExited(with event: NSEvent) {
        isHovered = false
        updateHighlightAppearance()
    }

    override func mouseDown(with event: NSEvent) {
        didFireInCurrentPress = true
        isHovered = true
        updateHighlightAppearance()
        onAction?()
    }

    override func mouseUp(with event: NSEvent) {
        let inside = bounds.contains(convert(event.locationInWindow, from: nil))
        if !didFireInCurrentPress && inside {
            onAction?()
        }
        didFireInCurrentPress = false
        isHovered = inside
        updateHighlightAppearance()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil {
            resetHoverState()
        }
    }

    private func updateHighlightAppearance() {
        let active = isHovered || (enclosingMenuItem?.isHighlighted ?? false)
        highlightView.isHidden = true
        let theme = HajimiThemeCenter.shared.currentTheme
        let color: NSColor = active
            ? HajimiUITheme.color(fromHex: theme.textPrimaryHex)
            : HajimiAppearance.accentText
        titleField.textColor = color
        iconView.contentTintColor = color
        needsDisplay = true
    }
}

/// Interactive status-bar popover card matching the "STATUS BAR CAT ICON & POPOVER"
/// design: Ginger Cat avatar + "哈基米 · 运行中" + glowing latency pill + 3-column
/// segmented mode pills ("规则判定" / "全局代理" / "全部直连") + inner telemetry &
/// node selector box + compact quick-action footer bar.
private final class StatusBarPopoverCardView: NSView {
    struct Model {
        var isRunning: Bool
        var subtitle: String
        var latencyMillis: Int
        var activeMode: OutboundMode
        var speedTestLeftText: String
        var speedTestRightText: String
        var activeNodeLabel: String
        var activeNodeTitle: String
        var isEnhancedMode: Bool
        var isSystemProxy: Bool
        var themeBadgeText: String
    }

    var onSelectMode: ((OutboundMode) -> Void)?
    var onClickLatencyPill: (() -> Void)?
    var onClickSpeedTestRow: (() -> Void)?
    var onClickNodeRow: ((NSView) -> Void)?
    var onToggleEnhancedMode: (() -> Void)?
    var onToggleSystemProxy: (() -> Void)?
    var onClickThemeSelector: ((NSView) -> Void)?
    var onOpenConsole: (() -> Void)?
    var onQuitApp: (() -> Void)?

    private var model = Model(
        isRunning: false,
        subtitle: "代理引擎未启动",
        latencyMillis: -1,
        activeMode: .rule,
        speedTestLeftText: "⚡ 节点测速",
        speedTestRightText: "点击测速",
        activeNodeLabel: "当前主节点",
        activeNodeTitle: "DIRECT",
        isEnhancedMode: false,
        isSystemProxy: false,
        themeBadgeText: "#01 翡翠原石"
    )

    private let catImageView = NSImageView()
    private var hoveredMode: OutboundMode?
    private var isLatencyHovered = false
    private var isSpeedTestHovered = false
    private var isNodeRowHovered = false
    private var hoveredFooterIndex: Int?
    private var trackingAreaRef: NSTrackingArea?
    private let nodeAnchorView = NSView(frame: .zero)
    private let themeAnchorView = NSView(frame: .zero)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        catImageView.image = Self.loadBrandCatAvatar()
        catImageView.imageScaling = .scaleProportionallyUpOrDown
        catImageView.frame = NSRect(x: 20, y: 18, width: 38, height: 38)
        addSubview(catImageView)
        addSubview(nodeAnchorView)
        addSubview(themeAnchorView)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override var isFlipped: Bool { true }

    static func loadBrandCatAvatar() -> NSImage {
        let img = HajimiBrandIcon.makeImage()
        if !img.isTemplate { return img }
        let fallbackPaths = [
            "Resources/Hajimi.icns",
            "Resources/Hajimi.png",
            Bundle.main.bundlePath + "/Contents/Resources/Hajimi.icns"
        ]
        for path in fallbackPaths {
            if let loaded = NSImage(contentsOfFile: path), loaded.isValid {
                loaded.isTemplate = false
                return loaded
            }
        }
        return img
    }

    func update(with newModel: Model) {
        self.model = newModel
        needsDisplay = true
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingAreaRef {
            removeTrackingArea(trackingAreaRef)
        }
        let area = NSTrackingArea(
            rect: bounds,
            options: [.mouseEnteredAndExited, .mouseMoved, .activeAlways, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
        trackingAreaRef = area
    }

    // MARK: - Geometry Layout Rects

    private var latencyPillRect: NSRect {
        let text = latencyBadgeText
        let font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .bold)
        let w = max(56.0, ceil((text as NSString).size(withAttributes: [.font: font]).width) + 20.0)
        return NSRect(x: bounds.width - 20.0 - w, y: 24.0, width: w, height: 25.0)
    }

    private func modeButtonRect(for index: Int) -> NSRect {
        let left: CGFloat = 20.0
        let totalW: CGFloat = bounds.width - 40.0
        let gap: CGFloat = 9.0
        let btnW = floor((totalW - gap * 2.0) / 3.0)
        let x = left + CGFloat(index) * (btnW + gap)
        return NSRect(x: x, y: 72.0, width: btnW, height: 34.0)
    }

    private var innerBoxRect: NSRect {
        NSRect(x: 20.0, y: 118.0, width: bounds.width - 40.0, height: 68.0)
    }

    private var speedTestRowRect: NSRect {
        let box = innerBoxRect
        return NSRect(x: box.minX + 4, y: box.minY + 4, width: box.width - 8, height: 28)
    }

    private var nodeRowRect: NSRect {
        let box = innerBoxRect
        return NSRect(x: box.minX + 4, y: box.minY + 34, width: box.width - 8, height: 30)
    }

    private func footerButtonRect(for index: Int) -> NSRect {
        // 0: 增强模式, 1: 系统代理, 2: UI 主题, 3: 控制台, 4: 退出
        let y: CGFloat = 198.0
        let h: CGFloat = 28.0
        let left: CGFloat = 20.0
        let totalW = bounds.width - 40.0
        let gap: CGFloat = 6.0
        let quitW: CGFloat = 32.0
        let remainW = totalW - quitW - gap * 4.0
        let w0 = floor(remainW * 0.27)
        let w1 = floor(remainW * 0.25)
        let w2 = floor(remainW * 0.25)
        let w3 = remainW - w0 - w1 - w2
        let widths = [w0, w1, w2, w3, quitW]
        var curX = left
        for i in 0..<index {
            curX += widths[i] + gap
        }
        return NSRect(x: curX, y: y, width: widths[index], height: h)
    }

    private var latencyBadgeText: String {
        if model.latencyMillis > 0 {
            return "\(model.latencyMillis) ms"
        } else if model.latencyMillis == 0 {
            return "超时"
        } else {
            return "测速"
        }
    }

    // MARK: - Mouse Interaction

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func mouseMoved(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        let modes: [OutboundMode] = [.rule, .proxy, .direct]
        var newHoveredMode: OutboundMode?
        for (i, m) in modes.enumerated() where modeButtonRect(for: i).contains(pt) {
            newHoveredMode = m
            break
        }
        let newLatHover = latencyPillRect.contains(pt)
        let newSpeedHover = speedTestRowRect.contains(pt)
        let newNodeHover = nodeRowRect.contains(pt)
        var newFooterHover: Int?
        for i in 0..<5 where footerButtonRect(for: i).contains(pt) {
            newFooterHover = i
            break
        }
        if newHoveredMode != hoveredMode ||
           newLatHover != isLatencyHovered ||
           newSpeedHover != isSpeedTestHovered ||
           newNodeHover != isNodeRowHovered ||
           newFooterHover != hoveredFooterIndex {
            hoveredMode = newHoveredMode
            isLatencyHovered = newLatHover
            isSpeedTestHovered = newSpeedHover
            isNodeRowHovered = newNodeHover
            hoveredFooterIndex = newFooterHover
            needsDisplay = true
        }
    }

    override func mouseExited(with event: NSEvent) {
        hoveredMode = nil
        isLatencyHovered = false
        isSpeedTestHovered = false
        isNodeRowHovered = false
        hoveredFooterIndex = nil
        needsDisplay = true
    }

    override func mouseDown(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        let modes: [OutboundMode] = [.rule, .proxy, .direct]
        for (i, m) in modes.enumerated() where modeButtonRect(for: i).contains(pt) {
            onSelectMode?(m)
            return
        }
        if latencyPillRect.contains(pt) {
            onClickLatencyPill?()
            return
        }
        if speedTestRowRect.contains(pt) {
            onClickSpeedTestRow?()
            return
        }
        if nodeRowRect.contains(pt) {
            nodeAnchorView.frame = nodeRowRect
            onClickNodeRow?(nodeAnchorView)
            return
        }
        for i in 0..<5 where footerButtonRect(for: i).contains(pt) {
            switch i {
            case 0: onToggleEnhancedMode?()
            case 1: onToggleSystemProxy?()
            case 2:
                themeAnchorView.frame = footerButtonRect(for: 2)
                onClickThemeSelector?(themeAnchorView)
            case 3: onOpenConsole?()
            case 4: onQuitApp?()
            default: break
            }
            return
        }
    }

    // MARK: - Drawing

    private static func isLightColor(_ color: NSColor) -> Bool {
        guard let rgb = color.usingColorSpace(.deviceRGB) else { return true }
        let lum = 0.299 * rgb.redComponent + 0.587 * rgb.greenComponent + 0.114 * rgb.blueComponent
        return lum > 0.52
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        let theme = HajimiThemeCenter.shared.currentTheme
        let panelColor = HajimiUITheme.color(fromHex: theme.panelHex, alpha: 0.98)
        let workspaceColor = HajimiUITheme.color(fromHex: theme.workspaceHex, alpha: 0.95)
        let elevatedColor = HajimiUITheme.color(fromHex: theme.elevatedPanelHex, alpha: 0.98)
        let accentColor = HajimiUITheme.color(fromHex: theme.accentHex, alpha: 1.0)
        let accentTextColor = HajimiUITheme.color(fromHex: theme.accentTextHex, alpha: 1.0)
        let uploadColor = HajimiUITheme.color(fromHex: theme.uploadAccentHex, alpha: 1.0)
        let textPrimary = HajimiUITheme.color(fromHex: theme.textPrimaryHex, alpha: 1.0)
        let textSecondary = HajimiUITheme.color(fromHex: theme.textSecondaryHex, alpha: 0.92)
        let borderColor = accentColor.withAlphaComponent(CGFloat(max(0.14, min(0.65, theme.borderAlpha + 0.04))))
        let subtleBorder = textSecondary.withAlphaComponent(theme.isDark ? 0.18 : 0.22)
        let activePillTextColor: NSColor = Self.isLightColor(accentColor)
            ? NSColor(calibratedRed: 0.02, green: 0.14, blue: 0.10, alpha: 1.0)
            : .white

        let outerRadius = CGFloat(max(12.0, min(22.0, theme.cardCornerRadius)))
        let innerRadius = CGFloat(max(8.0, min(14.0, theme.innerCornerRadius)))

        // 1. Main Card Background & Border
        let cardRect = bounds.insetBy(dx: 1.0, dy: 1.0)
        let cardPath = NSBezierPath(roundedRect: cardRect, xRadius: outerRadius, yRadius: outerRadius)
        NSGraphicsContext.saveGraphicsState()
        cardPath.addClip()
        if let grad = NSGradient(starting: elevatedColor, ending: panelColor) {
            grad.draw(in: cardRect, angle: 90.0)
        } else {
            panelColor.setFill()
            cardPath.fill()
        }
        NSGraphicsContext.restoreGraphicsState()

        borderColor.setStroke()
        cardPath.lineWidth = 1.0
        cardPath.stroke()

        // 2. Header: Title ("哈基米 · 运行中") + Subtitle + Latency Pill ("18 ms")
        let titleText = model.isRunning ? "哈基米 · 运行中" : "哈基米 · 已停止"
        let titleAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 14.5, weight: .bold),
            .foregroundColor: textPrimary
        ]
        (titleText as NSString).draw(at: NSPoint(x: 68.0, y: 17.0), withAttributes: titleAttrs)

        let subAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11.5, weight: .medium),
            .foregroundColor: textSecondary
        ]
        let maxSubW = latencyPillRect.minX - 74.0
        let subStyle = NSMutableParagraphStyle()
        subStyle.lineBreakMode = .byTruncatingTail
        var truncatedSubAttrs = subAttrs
        truncatedSubAttrs[.paragraphStyle] = subStyle
        (model.subtitle as NSString).draw(
            in: NSRect(x: 68.0, y: 38.0, width: max(80.0, maxSubW), height: 18.0),
            withAttributes: truncatedSubAttrs
        )

        let latRect = latencyPillRect
        let latPath = NSBezierPath(roundedRect: latRect, xRadius: latRect.height / 2.0, yRadius: latRect.height / 2.0)
        let latFill: NSColor
        let latTextColor: NSColor
        if model.latencyMillis > 0 {
            latFill = isLatencyHovered ? accentTextColor : accentColor
            latTextColor = activePillTextColor
        } else if model.latencyMillis == 0 {
            latFill = NSColor.systemRed.withAlphaComponent(0.22)
            latTextColor = .systemRed
        } else {
            latFill = accentColor.withAlphaComponent(isLatencyHovered ? 0.30 : 0.18)
            latTextColor = accentTextColor
        }
        latFill.setFill()
        latPath.fill()

        let latAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 12.0, weight: .bold),
            .foregroundColor: latTextColor
        ]
        let latStr = latencyBadgeText as NSString
        let latSize = latStr.size(withAttributes: latAttrs)
        latStr.draw(
            at: NSPoint(
                x: latRect.midX - latSize.width / 2.0,
                y: latRect.midY - latSize.height / 2.0
            ),
            withAttributes: latAttrs
        )

        // 3. Three-Column Mode Switcher ("规则判定" / "全局代理" / "全部直连")
        let modeSpecs: [(OutboundMode, String)] = [
            (.rule, "规则判定"),
            (.proxy, "全局代理"),
            (.direct, "全部直连")
        ]
        for (idx, spec) in modeSpecs.enumerated() {
            let mRect = modeButtonRect(for: idx)
            let isSelected = (model.activeMode == spec.0)
            let isHovered = (hoveredMode == spec.0)
            let btnRadius = max(7.0, min(10.0, innerRadius))
            let mPath = NSBezierPath(roundedRect: mRect, xRadius: btnRadius, yRadius: btnRadius)

            if isSelected {
                (isHovered ? accentTextColor : accentColor).setFill()
                mPath.fill()
            } else {
                let inactiveFill = isHovered
                    ? accentColor.withAlphaComponent(0.14)
                    : workspaceColor.withAlphaComponent(0.45)
                inactiveFill.setFill()
                mPath.fill()
                (isHovered ? borderColor : subtleBorder).setStroke()
                mPath.lineWidth = 1.0
                mPath.stroke()
            }

            let mTextColor = isSelected ? activePillTextColor : textPrimary
            let mAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 12.5, weight: .bold),
                .foregroundColor: mTextColor
            ]
            let mStr = spec.1 as NSString
            let mSize = mStr.size(withAttributes: mAttrs)
            mStr.draw(
                at: NSPoint(
                    x: mRect.midX - mSize.width / 2.0,
                    y: mRect.midY - mSize.height / 2.0
                ),
                withAttributes: mAttrs
            )
        }

        // 4. Inner Telemetry & Active Node Box
        let box = innerBoxRect
        let boxPath = NSBezierPath(roundedRect: box, xRadius: innerRadius, yRadius: innerRadius)
        workspaceColor.withAlphaComponent(theme.isDark ? 0.58 : 0.72).setFill()
        boxPath.fill()
        subtleBorder.setStroke()
        boxPath.lineWidth = 1.0
        boxPath.stroke()

        if isSpeedTestHovered {
            let hoverPath = NSBezierPath(roundedRect: speedTestRowRect, xRadius: 6, yRadius: 6)
            accentColor.withAlphaComponent(0.10).setFill()
            hoverPath.fill()
        }
        if isNodeRowHovered {
            let hoverPath = NSBezierPath(roundedRect: nodeRowRect, xRadius: 6, yRadius: 6)
            accentColor.withAlphaComponent(0.12).setFill()
            hoverPath.fill()
        }

        // Row 1 inside box: "⚡ 节点测速：可用 24/24" ... "最快 18 ms"
        let row1Y = box.minY + 11.0
        let leftRow1Attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11.5, weight: .medium),
            .foregroundColor: isSpeedTestHovered ? textPrimary : textSecondary
        ]
        (model.speedTestLeftText as NSString).draw(at: NSPoint(x: box.minX + 12.0, y: row1Y), withAttributes: leftRow1Attrs)

        let rightRow1Attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 11.5, weight: .bold),
            .foregroundColor: accentTextColor
        ]
        let r1Str = model.speedTestRightText as NSString
        let r1Size = r1Str.size(withAttributes: rightRow1Attrs)
        r1Str.draw(at: NSPoint(x: box.maxX - 12.0 - r1Size.width, y: row1Y), withAttributes: rightRow1Attrs)

        // Row 2 inside box: "当前主节点" ... "HK-VLESS-Reality-01 ▾"
        let row2Y = box.minY + 39.0
        let leftRow2Attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11.5, weight: .medium),
            .foregroundColor: textSecondary
        ]
        (model.activeNodeLabel as NSString).draw(at: NSPoint(x: box.minX + 12.0, y: row2Y), withAttributes: leftRow2Attrs)

        let nodeDisplay = "\(model.activeNodeTitle) ▾" as NSString
        let rightRow2Attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 12.0, weight: .bold),
            .foregroundColor: isNodeRowHovered ? accentTextColor : textPrimary,
            .paragraphStyle: subStyle
        ]
        let nodeSize = nodeDisplay.size(withAttributes: rightRow2Attrs)
        let maxNodeW = box.width - 110.0
        let drawNodeW = min(maxNodeW, ceil(nodeSize.width) + 2.0)
        nodeDisplay.draw(
            in: NSRect(x: box.maxX - 12.0 - drawNodeW, y: row2Y - 0.5, width: drawNodeW, height: 18.0),
            withAttributes: rightRow2Attrs
        )

        // 5. Compact Bottom Quick-Action Bar (增强模式 | 系统代理 | 主题 | 控制台 | 退出)
        let footerItems: [(String, Bool, NSColor)] = [
            (model.isEnhancedMode ? "● 增强模式" : "○ 增强模式", model.isEnhancedMode, uploadColor),
            (model.isSystemProxy ? "● 系统代理" : "○ 系统代理", model.isSystemProxy, accentTextColor),
            ("🎨 主题", false, accentTextColor),
            ("控制台", false, textPrimary),
            ("⏻", false, textSecondary)
        ]
        for (idx, item) in footerItems.enumerated() {
            let fRect = footerButtonRect(for: idx)
            let isHov = (hoveredFooterIndex == idx)
            let fPath = NSBezierPath(roundedRect: fRect, xRadius: 7.0, yRadius: 7.0)
            let fill: NSColor
            let stroke: NSColor
            let fg: NSColor
            if item.1 {
                fill = item.2.withAlphaComponent(isHov ? 0.26 : 0.16)
                stroke = item.2.withAlphaComponent(0.45)
                fg = item.2
            } else {
                fill = isHov ? accentColor.withAlphaComponent(0.14) : workspaceColor.withAlphaComponent(0.38)
                stroke = isHov ? borderColor : subtleBorder
                fg = isHov ? textPrimary : textSecondary
            }
            fill.setFill()
            fPath.fill()
            stroke.setStroke()
            fPath.lineWidth = 1.0
            fPath.stroke()

            let fAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 11.0, weight: item.1 ? .bold : .semibold),
                .foregroundColor: fg
            ]
            let fStr = item.0 as NSString
            let fSize = fStr.size(withAttributes: fAttrs)
            fStr.draw(
                at: NSPoint(
                    x: fRect.midX - fSize.width / 2.0,
                    y: fRect.midY - fSize.height / 2.0
                ),
                withAttributes: fAttrs
            )
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private var mainWindowController: MainWindowController?
    private var statusItem: NSStatusItem?
    private let statusPopover = NSPopover()
    private let popoverViewController = NSViewController()
    private let popoverCardView = StatusBarPopoverCardView(frame: NSRect(x: 0, y: 0, width: 364, height: 242))
    private var outsideClickMonitor: Any?
    private var trafficTicker: Timer?
    private var lastTrafficReadoutKey: String = ""
    private var lastUploadBytesPerSecond: Double = 0
    private var lastDownloadBytesPerSecond: Double = 0
    private var processActivityToken: NSObjectProtocol?

    private final class PolicyGroupMenuEntry {
        let groupName: String
        let item: NSMenuItem
        let submenu: NSMenu
        let testItem: NSMenuItem
        let testView: StatusMenuActionItemView
        let defaultItem: NSMenuItem
        let separatorItem = NSMenuItem.separator()

        init(groupName: String, onTestGroup: @escaping () -> Void, target: AnyObject, defaultAction: Selector) {
            self.groupName = groupName
            self.item = NSMenuItem(title: groupName, action: nil, keyEquivalent: "")
            self.submenu = NSMenu(title: groupName)
            self.submenu.minimumWidth = 280
            self.testItem = NSMenuItem(title: "⚡ 测速本组节点", action: nil, keyEquivalent: "")
            self.testView = StatusMenuActionItemView(frame: NSRect(x: 0, y: 0, width: 280, height: 26))
            self.testView.onAction = onTestGroup
            self.testItem.view = self.testView
            self.defaultItem = NSMenuItem(title: "配置默认", action: defaultAction, keyEquivalent: "")
            self.defaultItem.target = target
            self.defaultItem.representedObject = ["group": groupName]
            self.submenu.addItem(self.testItem)
            self.submenu.addItem(self.defaultItem)
            self.submenu.addItem(self.separatorItem)
            self.item.submenu = self.submenu
        }
    }

    private let nodePickerMenu = NSMenu(title: "节点与策略组选择")
    private let globalTestAllItem = NSMenuItem(title: "⚡ 一键测速全部节点", action: nil, keyEquivalent: "")
    private let globalTestAllView = StatusMenuActionItemView(frame: NSRect(x: 0, y: 0, width: 280, height: 26))
    private let globalTestSeparator = NSMenuItem.separator()
    private let uiThemeMenu = NSMenu(title: "UI 主题切换")
    private let openThemeSettingsItem = NSMenuItem(title: "打开 UI 主题设置与导入面板…", action: #selector(openThemeSettingsFromStatusItem), keyEquivalent: "")
    private var policyGroupMenuEntries: [String: PolicyGroupMenuEntry] = [:]

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Prevent macOS App Nap from throttling proxy queues, timers, and
        // Helper heartbeats when the screen turns off (Display Sleep) or the
        // main window is closed to the status bar, while still allowing normal
        // idle system sleep.
        processActivityToken = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiatedAllowingIdleSystemSleep, .latencyCritical],
            reason: "Hajimi Network Proxy and Packet Tunnel Engine"
        )
        buildMainMenu()
        let controller = MainWindowController()
        mainWindowController = controller
        controller.onStatusBarStateChanged = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            self.syncStatusPopoverAppearance()
            self.refreshPopoverCard(controller: ctrl)
            self.updateOpenNodePickerMenuInPlace(controller: ctrl)
        }
        buildStatusItem()
        NotificationCenter.default.addObserver(
            forName: HajimiThemeCenter.didChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            self.syncStatusPopoverAppearance()
            self.lastTrafficReadoutKey = ""
            self.refreshTrafficReadout()
            if let ctrl = self.mainWindowController {
                self.refreshPopoverCard(controller: ctrl)
            }
        }
        controller.launch()
    }

    /// Closing the red window button hides the UI but leaves the proxy and its
    /// menu-bar controls running. Only “退出哈基米” performs network cleanup.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { mainWindowController?.revealFromStatusItem() }
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Always drop the helper tunnel first. A quit that leaves utun routes
        // up black-holes the machine until the helper's liveness timer fires.
        mainWindowController?.shutdownEnhancedModeForQuit()
        do {
            try mainWindowController?.restoreSystemProxyBeforeQuit()
            return .terminateNow
        } catch {
            let alert = NSAlert()
            alert.messageText = "无法恢复系统代理"
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: "取消退出")
            alert.addButton(withTitle: "仍然退出")
            let choice = alert.runModal()
            if choice == .alertSecondButtonReturn {
                // User insisted — make sure helper routes are still gone.
                mainWindowController?.shutdownEnhancedModeForQuit()
                return .terminateNow
            }
            return .terminateCancel
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let token = processActivityToken {
            ProcessInfo.processInfo.endActivity(token)
            processActivityToken = nil
        }
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
        mainWindowController?.shutdownEnhancedModeForQuit()
    }

    private func buildMainMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "关于哈基米", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出哈基米", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        let editItem = NSMenuItem()
        main.addItem(editItem)
        let editMenu = NSMenu(title: "编辑")
        editMenu.addItem(withTitle: "撤销", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "剪切", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "复制", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "粘贴", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "全选", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        NSApp.mainMenu = main
    }

    private static func menuSymbol(_ name: String, tint: NSColor? = nil) -> NSImage? {
        guard let base = NSImage(systemSymbolName: name, accessibilityDescription: nil) else { return nil }
        let baseConfig = NSImage.SymbolConfiguration(pointSize: 13, weight: .medium)
        let color = tint ?? HajimiAppearance.accentText
        let paletteConfig = baseConfig.applying(NSImage.SymbolConfiguration(paletteColors: [color]))
        let configured = base.withSymbolConfiguration(paletteConfig) ?? base
        configured.isTemplate = false
        return configured
    }

    private static func makeMenuBarCatImage() -> NSImage {
        let source = StatusBarPopoverCardView.loadBrandCatAvatar()
        if source.isTemplate {
            return source
        }
        let targetSize = NSSize(width: 18, height: 18)
        let resized = NSImage(size: targetSize, flipped: false) { rect in
            NSGraphicsContext.current?.imageInterpolation = .high
            source.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 1.0)
            return true
        }
        resized.isTemplate = false
        return resized
    }

    private static func themePrimaryTextColor() -> NSColor {
        HajimiUITheme.color(fromHex: HajimiThemeCenter.shared.currentTheme.textPrimaryHex)
    }

    private static func themeSecondaryTextColor() -> NSColor {
        HajimiUITheme.color(fromHex: HajimiThemeCenter.shared.currentTheme.textSecondaryHex)
    }

    private func syncStatusPopoverAppearance() {
        let appearance = HajimiThemeCenter.shared.effectiveMenuAppearance
            ?? NSAppearance(named: HajimiThemeCenter.shared.currentTheme.isDark ? .darkAqua : .aqua)
        statusPopover.appearance = appearance
        popoverCardView.appearance = appearance
        nodePickerMenu.appearance = appearance
        uiThemeMenu.appearance = appearance
        popoverCardView.needsDisplay = true
        for entry in policyGroupMenuEntries.values {
            entry.submenu.appearance = appearance
        }
    }

    private func buildStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.image = Self.makeMenuBarCatImage()
            Self.configureTrafficButton(button)
            button.target = self
            button.action = #selector(toggleStatusPopover(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
            button.toolTip = "哈基米"
        }

        popoverViewController.view = popoverCardView
        statusPopover.contentSize = popoverCardView.frame.size
        statusPopover.behavior = .transient
        statusPopover.animates = true
        statusPopover.contentViewController = popoverViewController
        statusPopover.delegate = self

        globalTestAllView.configure(
            title: "⚡ 一键测速全部节点",
            image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
        )
        globalTestAllView.onAction = { [weak self] in
            self?.testAllNodesFromStatusItem()
        }
        globalTestAllItem.view = globalTestAllView
        nodePickerMenu.minimumWidth = 280
        uiThemeMenu.minimumWidth = 280
        openThemeSettingsItem.target = self

        popoverCardView.onSelectMode = { [weak self] mode in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.selectOutboundModeFromStatusItem(mode)
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onClickLatencyPill = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.testActiveNodeFromStatusItem()
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onClickSpeedTestRow = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            if ctrl.statusItemOutboundMode == .rule {
                if let firstGroup = ctrl.statusItemPolicyGroups.first {
                    ctrl.testGroupNodesFromStatusItem(group: firstGroup.name)
                }
            } else {
                ctrl.testAllNodesFromStatusItem()
            }
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onClickNodeRow = { [weak self] anchor in
            guard let self, let ctrl = self.mainWindowController else { return }
            self.presentNodePickerMenu(from: anchor, controller: ctrl)
        }
        popoverCardView.onToggleEnhancedMode = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.toggleEnhancedModeFromStatusItem()
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onToggleSystemProxy = { [weak self] in
            guard let self, let ctrl = self.mainWindowController else { return }
            ctrl.toggleSystemProxyFromStatusItem()
            self.refreshPopoverCard(controller: ctrl)
        }
        popoverCardView.onClickThemeSelector = { [weak self] anchor in
            guard let self else { return }
            self.presentThemePickerMenu(from: anchor)
        }
        popoverCardView.onOpenConsole = { [weak self] in
            guard let self else { return }
            self.closeStatusPopover()
            self.mainWindowController?.revealFromStatusItem()
        }
        popoverCardView.onQuitApp = { [weak self] in
            self?.closeStatusPopover()
            NSApp.terminate(nil)
        }

        statusItem = item
        syncStatusPopoverAppearance()
        if let controller = mainWindowController {
            refreshPopoverCard(controller: controller)
        }
        startTrafficTicker()
    }

    @objc private func toggleStatusPopover(_ sender: AnyObject?) {
        if statusPopover.isShown {
            closeStatusPopover()
        } else {
            openStatusPopover()
        }
    }

    private func openStatusPopover() {
        guard let button = statusItem?.button, let controller = mainWindowController else { return }
        syncStatusPopoverAppearance()
        refreshPopoverCard(controller: controller)
        statusPopover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        statusPopover.contentViewController?.view.window?.makeKey()
        if outsideClickMonitor == nil {
            outsideClickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
                guard let self, self.statusPopover.isShown else { return }
                self.closeStatusPopover()
            }
        }
    }

    private func closeStatusPopover() {
        if statusPopover.isShown {
            statusPopover.performClose(nil)
        }
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
    }

    func popoverDidClose(_ notification: Notification) {
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
    }

    private func refreshPopoverCard(controller: MainWindowController) {
        let snap = controller.statusItemTelemetrySnapshot(
            uploadRate: lastUploadBytesPerSecond,
            downloadRate: lastDownloadBytesPerSecond
        )
        let isRunning = controller.isEngineActive || controller.isEnhancedModeActive
        let subtitle: String
        if snap.enhancedMode && snap.systemProxy {
            subtitle = "增强模式 (utun) + 系统代理"
        } else if snap.enhancedMode {
            subtitle = "增强模式 (utun) · 原生 TUN 数据面已就绪"
        } else if snap.systemProxy {
            subtitle = "系统代理 · 本地监听已就绪"
        } else if isRunning {
            subtitle = "本地代理监听运行中 · \(snap.modeTitle)"
        } else {
            subtitle = "代理引擎已停止 · 点击下方开关启动"
        }

        let speedLeft: String
        let speedRight: String
        let nodeLabel: String
        switch controller.statusItemOutboundMode {
        case .rule:
            let groups = controller.statusItemPolicyGroups
            if let firstGroup = groups.first {
                nodeLabel = "当前策略 (\(firstGroup.name))"
                if controller.isStatusItemTestingNodes {
                    speedLeft = "⚡ 正在对策略组内节点进行延迟测速…"
                    speedRight = "测速中…"
                } else {
                    speedLeft = "⚡ 策略组分流（共 \(groups.count) 个策略组）"
                    speedRight = snap.activeNodeLatencyMillis > 0 ? "当前 \(snap.activeNodeLatencyMillis) ms" : "测速当前组"
                }
            } else {
                nodeLabel = "当前策略"
                speedLeft = "⚡ 策略组分流"
                speedRight = "点击查看"
            }
        case .proxy:
            nodeLabel = "当前主节点"
            let rawSummary = controller.statusItemLatencySummary
            let parts = rawSummary.components(separatedBy: " · ")
            if parts.count >= 2 {
                speedLeft = parts[0]
                speedRight = parts[1]
            } else {
                speedLeft = rawSummary
                speedRight = controller.isStatusItemTestingNodes ? "测速中…" : "点击测速"
            }
        case .direct:
            nodeLabel = "当前出站"
            speedLeft = "直连模式（所有流量直接连接）"
            speedRight = "DIRECT"
        }

        let theme = HajimiThemeCenter.shared.currentTheme
        popoverCardView.update(with: .init(
            isRunning: isRunning,
            subtitle: subtitle,
            latencyMillis: snap.activeNodeLatencyMillis,
            activeMode: controller.statusItemOutboundMode,
            speedTestLeftText: speedLeft,
            speedTestRightText: speedRight,
            activeNodeLabel: nodeLabel,
            activeNodeTitle: snap.activeNodeName,
            isEnhancedMode: snap.enhancedMode,
            isSystemProxy: snap.systemProxy,
            themeBadgeText: theme.displayTitle
        ))
        statusItem?.button?.toolTip = "哈基米 · \(controller.statusItemSummary)"
    }

    private static func attributedGroupRowTitle(groupName: String, effective: String, latencyMillis: Int?) -> NSAttributedString {
        let attr = NSMutableAttributedString()
        attr.append(NSAttributedString(string: "\(groupName)：", attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .medium),
            .foregroundColor: themePrimaryTextColor()
        ]))
        attr.append(NSAttributedString(string: effective, attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold),
            .foregroundColor: HajimiAppearance.accentText
        ]))
        if let ms = latencyMillis {
            attr.append(NSAttributedString(string: "  \(ms) ms", attributes: [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .semibold),
                .foregroundColor: HajimiAppearance.uploadAccent
            ]))
        }
        return attr
    }

    private func updateOpenNodePickerMenuInPlace(controller: MainWindowController) {
        let testAllTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测试节点延迟…" : "⚡ 一键测速全部节点"
        globalTestAllItem.title = testAllTitle
        globalTestAllView.configure(
            title: testAllTitle,
            image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
        )

        let groupTestTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测速本组节点…" : "⚡ 测速本组节点"
        let groupsByName = Dictionary(uniqueKeysWithValues: controller.statusItemPolicyGroups.map { ($0.name, $0) })

        for (groupName, entry) in policyGroupMenuEntries {
            entry.testItem.title = groupTestTitle
            entry.testView.configure(
                title: groupTestTitle,
                image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
            )
            guard let group = groupsByName[groupName] else { continue }
            let effective = group.effectiveMember ?? "DIRECT"
            let effectiveNodeItem = controller.statusItemNodeItem(named: effective)
            entry.item.title = "\(group.name)：\(effective)"
            entry.item.attributedTitle = Self.attributedGroupRowTitle(
                groupName: group.name,
                effective: effective,
                latencyMillis: effectiveNodeItem.latencyMillis
            )

            let optimalMember = controller.statusItemOptimalMemberName(forGroup: group.name)
            let memberNodeItems = group.members.map {
                controller.statusItemNodeItem(named: $0, optimalName: optimalMember)
            }
            let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
            let maxNameWidth = memberNodeItems.map {
                ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
            }.max() ?? 120
            let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)

            for (offset, nodeItem) in memberNodeItems.enumerated() {
                let menuIndex = offset + 3
                guard entry.submenu.items.indices.contains(menuIndex) else { continue }
                let item = entry.submenu.items[menuIndex]
                let isSelected = group.selectedMember == nodeItem.name
                    || (group.selectedMember == nil && group.effectiveMember == nodeItem.name)
                item.state = isSelected ? .on : .off
                item.attributedTitle = Self.attributedNodeMenuTitle(
                    node: nodeItem, isSelected: isSelected, tabLocation: tabLocation)
            }
        }

        if controller.statusItemOutboundMode == .proxy {
            let globalNodes = controller.statusItemGlobalNodeItems
            let activeNodeName = controller.statusItemGlobalPolicy
            let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
            let maxNameWidth = globalNodes.map {
                ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
            }.max() ?? 120
            let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)
            for (offset, node) in globalNodes.enumerated() {
                let menuIndex = offset + 2
                guard nodePickerMenu.items.indices.contains(menuIndex) else { continue }
                let item = nodePickerMenu.items[menuIndex]
                let isSelected = (activeNodeName == node.name)
                item.state = isSelected ? .on : .off
                item.attributedTitle = Self.attributedNodeMenuTitle(
                    node: node, isSelected: isSelected, tabLocation: tabLocation)
            }
        }
    }

    private func presentNodePickerMenu(from anchorView: NSView, controller: MainWindowController) {
        syncStatusPopoverAppearance()
        nodePickerMenu.removeAllItems()

        let activeMode = controller.statusItemOutboundMode
        if activeMode == .rule {
            let groups = controller.statusItemPolicyGroups
            let groupTestTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测速本组节点…" : "⚡ 测速本组节点"
            if !groups.isEmpty {
                for group in groups {
                    let entry: PolicyGroupMenuEntry
                    if let existing = policyGroupMenuEntries[group.name] {
                        entry = existing
                    } else {
                        let groupName = group.name
                        entry = PolicyGroupMenuEntry(
                            groupName: groupName,
                            onTestGroup: { [weak self] in
                                guard let self, let ctrl = self.mainWindowController else { return }
                                ctrl.testGroupNodesFromStatusItem(group: groupName)
                                self.updateOpenNodePickerMenuInPlace(controller: ctrl)
                            },
                            target: self,
                            defaultAction: #selector(selectPolicyGroupDefault(_:))
                        )
                        policyGroupMenuEntries[groupName] = entry
                    }
                    entry.submenu.appearance = statusPopover.appearance
                    entry.testItem.title = groupTestTitle
                    entry.testView.resetHoverState()
                    entry.testView.configure(
                        title: groupTestTitle,
                        image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
                    )

                    let effective = group.effectiveMember ?? "DIRECT"
                    let effectiveNodeItem = controller.statusItemNodeItem(named: effective)
                    entry.item.title = "\(group.name)：\(effective)"
                    entry.item.attributedTitle = Self.attributedGroupRowTitle(
                        groupName: group.name,
                        effective: effective,
                        latencyMillis: effectiveNodeItem.latencyMillis
                    )
                    entry.item.image = Self.groupSymbol(for: group.kind)

                    let firstMember = group.members.first ?? "DIRECT"
                    entry.defaultItem.title = group.kind == .select
                        ? "配置默认（\(firstMember)）"
                        : "自动（按\(group.kindBadgeText)策略 · 默认 \(firstMember)）"
                    entry.defaultItem.state = group.selectedMember == nil ? .on : .off

                    while entry.submenu.items.count > 3 {
                        entry.submenu.removeItem(at: entry.submenu.items.count - 1)
                    }
                    let optimalMember = controller.statusItemOptimalMemberName(forGroup: group.name)
                    let memberNodeItems = group.members.map {
                        controller.statusItemNodeItem(named: $0, optimalName: optimalMember)
                    }
                    let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
                    let maxNameWidth = memberNodeItems.map {
                        ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
                    }.max() ?? 120
                    let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)
                    entry.submenu.minimumWidth = max(276, tabLocation + 132)

                    for nodeItem in memberNodeItems {
                        let memberItem = NSMenuItem(title: nodeItem.name, action: #selector(selectPolicyGroupMember(_:)), keyEquivalent: "")
                        memberItem.target = self
                        memberItem.representedObject = ["group": group.name, "member": nodeItem.name]
                        let isSelected = group.selectedMember == nodeItem.name
                            || (group.selectedMember == nil && group.effectiveMember == nodeItem.name)
                        memberItem.state = isSelected ? .on : .off
                        memberItem.attributedTitle = Self.attributedNodeMenuTitle(
                            node: nodeItem, isSelected: isSelected, tabLocation: tabLocation)
                        entry.submenu.addItem(memberItem)
                    }
                    nodePickerMenu.addItem(entry.item)
                }
                nodePickerMenu.minimumWidth = 288
                nodePickerMenu.popUp(positioning: nil, at: NSPoint(x: anchorView.bounds.minX, y: anchorView.bounds.maxY + 4), in: anchorView)
                return
            }
        }

        if activeMode == .direct {
            let directInfo = NSMenuItem(title: "当前为全部直连模式（所有流量直接连接）", action: nil, keyEquivalent: "")
            directInfo.isEnabled = false
            nodePickerMenu.addItem(directInfo)
            nodePickerMenu.popUp(positioning: nil, at: NSPoint(x: anchorView.bounds.minX, y: anchorView.bounds.maxY + 4), in: anchorView)
            return
        }

        let testTitle = controller.isStatusItemTestingNodes ? "⚡ 正在测试节点延迟…" : "⚡ 一键测速全部节点"
        globalTestAllItem.title = testTitle
        globalTestAllView.resetHoverState()
        globalTestAllView.configure(
            title: testTitle,
            image: Self.menuSymbol("bolt.horizontal.circle", tint: HajimiAppearance.accentText)
        )
        nodePickerMenu.addItem(globalTestAllItem)
        nodePickerMenu.addItem(globalTestSeparator)

        let globalNodes = controller.statusItemGlobalNodeItems
        let activeNodeName = controller.statusItemGlobalPolicy
        let measureFont = NSFont.systemFont(ofSize: 13, weight: .semibold)
        let maxNameWidth = globalNodes.map {
            ($0.name as NSString).size(withAttributes: [.font: measureFont]).width
        }.max() ?? 120
        let tabLocation = max(144.0, ceil(maxNameWidth) + 22.0)
        nodePickerMenu.minimumWidth = max(276, tabLocation + 132)

        for node in globalNodes {
            let item = NSMenuItem(title: node.name, action: #selector(selectGlobalPolicy(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = node.name
            let isSelected = (activeNodeName == node.name)
            item.state = isSelected ? .on : .off
            item.attributedTitle = Self.attributedNodeMenuTitle(
                node: node, isSelected: isSelected, tabLocation: tabLocation)
            nodePickerMenu.addItem(item)
        }

        nodePickerMenu.popUp(positioning: nil, at: NSPoint(x: anchorView.bounds.minX, y: anchorView.bounds.maxY + 4), in: anchorView)
    }

    private func presentThemePickerMenu(from anchorView: NSView) {
        syncStatusPopoverAppearance()
        uiThemeMenu.removeAllItems()
        let current = HajimiThemeCenter.shared.currentTheme
        openThemeSettingsItem.image = Self.menuSymbol("slider.horizontal.3", tint: HajimiAppearance.accentText)
        uiThemeMenu.addItem(openThemeSettingsItem)
        uiThemeMenu.addItem(.separator())

        for theme in HajimiThemeCenter.shared.allThemes {
            let item = NSMenuItem(title: theme.displayTitle, action: #selector(selectUIThemeFromStatusItem(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = theme.id
            let isSelected = (theme.id == current.id)
            item.state = isSelected ? .on : .off

            let attr = NSMutableAttributedString()
            let dotColor = HajimiUITheme.color(fromHex: theme.accentHex)
            attr.append(NSAttributedString(string: "● ", attributes: [
                .font: NSFont.systemFont(ofSize: 12, weight: .bold),
                .foregroundColor: dotColor
            ]))
            attr.append(NSAttributedString(string: theme.displayTitle, attributes: [
                .font: NSFont.systemFont(ofSize: 12.5, weight: isSelected ? .bold : .medium),
                .foregroundColor: isSelected ? HajimiAppearance.accentText : Self.themePrimaryTextColor()
            ]))
            attr.append(NSAttributedString(string: "  \(theme.category)", attributes: [
                .font: NSFont.systemFont(ofSize: 10.5, weight: .regular),
                .foregroundColor: Self.themeSecondaryTextColor()
            ]))
            item.attributedTitle = attr
            uiThemeMenu.addItem(item)
        }

        uiThemeMenu.popUp(positioning: nil, at: NSPoint(x: 0, y: anchorView.bounds.maxY + 4), in: anchorView)
    }

    private func startTrafficTicker() {
        trafficTicker?.invalidate()
        let timer = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.refreshTrafficReadout()
        }
        RunLoop.main.add(timer, forMode: .common)
        trafficTicker = timer
        refreshTrafficReadout()
    }

    private static let emptyTrafficTitle = NSAttributedString(string: "")
    private static let trafficTitleAttributes: [NSAttributedString.Key: Any] = {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .right
        paragraph.lineSpacing = -3
        paragraph.maximumLineHeight = 9
        return [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .regular),
            .foregroundColor: NSColor.controlTextColor,
            .paragraphStyle: paragraph,
            .baselineOffset: -1,
        ]
    }()

    private func refreshTrafficReadout() {
        guard let button = statusItem?.button else { return }
        guard let controller = mainWindowController else {
            if !lastTrafficReadoutKey.isEmpty {
                lastTrafficReadoutKey = ""
                button.attributedTitle = Self.emptyTrafficTitle
            }
            return
        }
        let rate = controller.statusItemTrafficRate()
        lastUploadBytesPerSecond = rate.upload
        lastDownloadBytesPerSecond = rate.download
        if statusPopover.isShown {
            refreshPopoverCard(controller: controller)
        }
        let uploadText = TrafficRateFormatter.compact(bytesPerSecond: rate.upload)
        let downloadText = TrafficRateFormatter.compact(bytesPerSecond: rate.download)
        let themeID = HajimiThemeCenter.shared.currentTheme.id
        let key = "\(uploadText)|\(downloadText)|\(themeID)"
        guard key != lastTrafficReadoutKey else { return }
        lastTrafficReadoutKey = key
        button.attributedTitle = Self.menuBarInlineTrafficTitle(upload: uploadText, download: downloadText)
    }

    static func configureTrafficButton(_ button: NSButton) {
        button.imagePosition = .imageLeading
    }

    /// Single-line menu bar readout matching the UI showcase: ` ⚡ ▲ 2.4M ▼ 38.6M`
    static func menuBarInlineTrafficTitle(upload: String, download: String) -> NSAttributedString {
        let font = NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .bold)
        let accent = HajimiAppearance.accentText
        let upColor = HajimiAppearance.uploadAccent

        let result = NSMutableAttributedString()
        result.append(NSAttributedString(string: " ⚡ ", attributes: [
            .font: NSFont.systemFont(ofSize: 10.5, weight: .bold),
            .foregroundColor: accent
        ]))
        result.append(NSAttributedString(string: "▲ \(upload) ", attributes: [
            .font: font,
            .foregroundColor: upColor
        ]))
        result.append(NSAttributedString(string: "▼ \(download)", attributes: [
            .font: font,
            .foregroundColor: accent
        ]))
        return result
    }

    static func trafficTitle(upload: String, download: String) -> NSAttributedString {
        return NSAttributedString(string: "↑ \(upload)\n↓ \(download)", attributes: trafficTitleAttributes)
    }

    static func validateTrafficTitleMetrics() throws {
        struct Failure: LocalizedError {
            let text: String
            var errorDescription: String? { "状态栏速率显示自检失败：\(text)" }
        }
        let title = trafficTitle(upload: "999K", download: "12M")
        let size = title.size()
        guard title.string.split(separator: "\n").count == 2 else {
            throw Failure(text: "速率标题应为两行")
        }
        guard size.height <= 22 else {
            throw Failure(text: "两行高度为 \(size.height) 点，超过菜单栏的 22 点")
        }
        guard size.height >= 12 else {
            throw Failure(text: "两行高度仅 \(size.height) 点，行距过紧会互相压盖")
        }
        guard size.width <= 60 else {
            throw Failure(text: "宽度为 \(size.width) 点，菜单栏占位过宽")
        }
    }

    private static func attributedNodeMenuTitle(node: StatusProxyNodeItem, isSelected: Bool,
                                                tabLocation: CGFloat = 156) -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.tabStops = [NSTextTab(textAlignment: .left, location: tabLocation)]
        paragraph.defaultTabInterval = tabLocation

        let result = NSMutableAttributedString()
        let nameFont = NSFont.systemFont(ofSize: 13, weight: isSelected ? .semibold : .regular)
        let nameColor = isSelected ? HajimiAppearance.accentText : themePrimaryTextColor()
        result.append(NSAttributedString(string: node.name, attributes: [
            .font: nameFont,
            .foregroundColor: nameColor,
            .paragraphStyle: paragraph
        ]))

        let badgeText: String
        let badgeColor: NSColor
        switch node.latency {
        case .success(let ms):
            let digits = String(ms)
            let padded = String(repeating: "\u{2007}", count: max(0, 3 - digits.count)) + digits
            badgeText = "\t● \(padded) ms"
            if ms < 180 {
                badgeColor = HajimiAppearance.accentText
            } else if ms < 500 {
                badgeColor = .systemOrange
            } else {
                badgeColor = .systemRed
            }
        case .testing:
            badgeText = "\t◌ 测速中…"
            badgeColor = HajimiAppearance.uploadAccent
        case .queued:
            badgeText = "\t◌ 排队中"
            badgeColor = themeSecondaryTextColor()
        case .failed:
            badgeText = "\t● 超时"
            badgeColor = .systemRed
        case .unavailable(let failure):
            badgeText = "\t● \(NodeLatency.unavailable(failure).text)"
            badgeColor = .systemOrange
        case .untested:
            badgeText = "\t· 未测速"
            badgeColor = themeSecondaryTextColor().withAlphaComponent(0.7)
        }

        let latFont = NSFont.monospacedDigitSystemFont(ofSize: 11.5, weight: .semibold)
        result.append(NSAttributedString(string: badgeText, attributes: [
            .font: latFont,
            .foregroundColor: badgeColor,
            .paragraphStyle: paragraph
        ]))
        if node.isOptimal {
            let optFont = NSFont.systemFont(ofSize: 10, weight: .bold)
            result.append(NSAttributedString(string: " ★最优", attributes: [
                .font: optFont,
                .foregroundColor: HajimiAppearance.accentText,
                .paragraphStyle: paragraph
            ]))
        }
        return result
    }

    private static func groupSymbol(for kind: PolicyGroupKind) -> NSImage? {
        switch kind {
        case .select: return menuSymbol("square.stack.3d.up", tint: HajimiAppearance.accentText)
        case .urlTest, .smart: return menuSymbol("bolt.badge.clock", tint: HajimiAppearance.uploadAccent)
        case .fallback: return menuSymbol("arrow.triangle.swap", tint: HajimiAppearance.accentText)
        case .loadBalance: return menuSymbol("circle.grid.cross", tint: HajimiAppearance.indigoAccent)
        case .subnet: return menuSymbol("network", tint: HajimiAppearance.accentText)
        }
    }

    @objc private func openThemeSettingsFromStatusItem() {
        closeStatusPopover()
        mainWindowController?.revealThemeSettingsFromStatusItem()
    }
    @objc private func selectUIThemeFromStatusItem(_ sender: NSMenuItem) {
        guard let themeID = sender.representedObject as? String else { return }
        HajimiThemeCenter.shared.selectTheme(id: themeID)
        if let ctrl = mainWindowController {
            refreshPopoverCard(controller: ctrl)
        }
    }
    @objc private func testAllNodesFromStatusItem() {
        guard let ctrl = mainWindowController else { return }
        ctrl.testAllNodesFromStatusItem()
        refreshPopoverCard(controller: ctrl)
    }
    @objc private func selectGlobalPolicy(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String, let ctrl = mainWindowController else { return }
        ctrl.selectGlobalPolicyFromStatusItem(name)
        refreshPopoverCard(controller: ctrl)
    }
    @objc private func selectPolicyGroupDefault(_ sender: NSMenuItem) {
        guard let info = sender.representedObject as? [String: String],
              let group = info["group"], let ctrl = mainWindowController else { return }
        ctrl.selectGroupMemberFromStatusItem(group: group, member: nil)
        refreshPopoverCard(controller: ctrl)
    }
    @objc private func selectPolicyGroupMember(_ sender: NSMenuItem) {
        guard let info = sender.representedObject as? [String: String],
              let group = info["group"],
              let member = info["member"], let ctrl = mainWindowController else { return }
        ctrl.selectGroupMemberFromStatusItem(group: group, member: member)
        refreshPopoverCard(controller: ctrl)
    }
}

#if !HAJIMI_MINIMAL_RELEASE
if CommandLine.arguments.contains("--protocol-adapter-smoke-test") {
    Darwin.exit(runProtocolAdapterSmokeCheck())
}
if CommandLine.arguments.contains("--dns-security-self-test") {
    do { try runDNSSecuritySelfTest(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--dns-performance-self-test") {
    do { try runDNSPerformanceSelfTest(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--dns-proxy-fallback-self-test") {
    do { try DNSProxyFallbackSelfTest.run(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--network-optimization-self-test") {
    do { try runNetworkOptimizationSelfTest(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--dns-adaptive-loopback-test") {
    Darwin.exit(runDNSAdaptiveLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--dns-performance-loopback-test") {
    Darwin.exit(runDNSPerformanceLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--dns-loopback-test") {
    Darwin.exit(runDNSLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--dns-split-loopback-test") {
    Darwin.exit(runDNSSplitLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--proxy-performance-smoke-test") {
    Darwin.exit(runProxyPerformanceSmokeCheck())
}
if CommandLine.arguments.contains("--video-stream-loopback-test") {
    Darwin.exit(runVideoStreamLoopbackSmokeCheck())
}
if CommandLine.arguments.contains("--enhanced-helper-ipc-test") {
    Darwin.exit(runEnhancedHelperIPCCheck())
}
if CommandLine.arguments.contains("--helper-install-maintenance") {
    Darwin.exit(runHelperInstallMaintenance())
}
if CommandLine.arguments.contains("--helper-start-current-maintenance") {
    Darwin.exit(runHelperStartCurrentMaintenance())
}
if CommandLine.arguments.contains("--helper-stop-maintenance") {
    Darwin.exit(runHelperStopMaintenance())
}
if CommandLine.arguments.contains("--native-policy-live-test") {
    Darwin.exit(runSelectedNativePolicyLiveCheck())
}
if CommandLine.arguments.contains("--native-quic-codec-test") {
    Darwin.exit(runNativeQUICCodecCheck())
}
if CommandLine.arguments.contains("--ingress-security-self-test") {
    do { try runIngressSecuritySelfTest(); Darwin.exit(0) }
    catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--native-dataplane-self-test") {
    if let failure = NativeCoreSelfTest.run() {
        FileHandle.standardError.write(Data((failure + "\n").utf8))
        Darwin.exit(1)
    }
    print("HajimiNativeCore self-test passed")
    Darwin.exit(0)
}
if CommandLine.arguments.contains("--native-tunnel-packet-load-self-test") {
    do {
        print(try NativeTunnelStreamRegressionFixture.runPacketLoad())
        Darwin.exit(0)
    } catch {
        FileHandle.standardError.write(Data("Native tunnel packet load failed: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--native-tunnel-stream-self-test") {
    do {
        print(try NativeTunnelStreamRegressionFixture.run())
        Darwin.exit(0)
    } catch {
        FileHandle.standardError.write(Data("Native tunnel stream regression failed: \(error.localizedDescription)\n".utf8))
        Darwin.exit(1)
    }
}
if CommandLine.arguments.contains("--native-policy-listener-live-test") {
    Darwin.exit(runNativePolicyListenerLiveCheck())
}
if CommandLine.arguments.contains("--native-policy-stress-test") {
    Darwin.exit(runNativePolicyStressCheck())
}
if let index = CommandLine.arguments.firstIndex(of: "--surge-profile-smoke-test"),
   CommandLine.arguments.indices.contains(index + 1) {
    Darwin.exit(runSurgeProfileCompatibilityCheck(path: CommandLine.arguments[index + 1]))
}
#endif

NetworkProcessResources.prepareOpenFileLimit()
let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()

import AppKit

/// Minimalist, resolution-independent status-bar template icon: a crisp circular
/// badge with a point-symmetric lightning cutout rendered via even-odd alpha mask.
enum StatusBarCatIcon {
    static func makeImage() -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: false) { bounds in
            NSGraphicsContext.saveGraphicsState()
            defer { NSGraphicsContext.restoreGraphicsState() }

            let transform = NSAffineTransform()
            transform.translateX(by: bounds.minX, yBy: bounds.minY)
            transform.scaleX(by: bounds.width / size.width, yBy: bounds.height / size.height)
            transform.concat()
            NSGraphicsContext.current?.shouldAntialias = true
            NSColor.black.setFill()

            let badge = NSBezierPath(ovalIn: NSRect(x: 2.6, y: 2.6, width: 12.8, height: 12.8))

            let bolt = NSBezierPath()
            bolt.move(to: NSPoint(x: 10.15, y: 13.55))
            bolt.line(to: NSPoint(x: 5.65, y: 8.45))
            bolt.line(to: NSPoint(x: 8.55, y: 8.45))
            bolt.line(to: NSPoint(x: 7.85, y: 4.45))
            bolt.line(to: NSPoint(x: 12.35, y: 9.55))
            bolt.line(to: NSPoint(x: 9.45, y: 9.55))
            bolt.close()

            badge.append(bolt)
            badge.windingRule = .evenOdd
            badge.fill()
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "哈基米状态栏图标"
        return image
    }
}

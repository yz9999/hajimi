import AppKit

/// A small, winking cat drawn in points, so AppKit can render it at any
/// backing scale without a bitmap resource or newer SF Symbol availability.
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
            NSColor.black.setStroke()

            func stroke(_ path: NSBezierPath, width: CGFloat = 1.25) {
                path.lineWidth = width
                path.lineCapStyle = .round
                path.lineJoinStyle = .round
                path.stroke()
            }

            // Rounded cheeks and short, pointed ears keep the silhouette
            // recognisably feline even at the menu bar's small size.
            let head = NSBezierPath()
            head.move(to: NSPoint(x: 2.25, y: 10.9))
            head.curve(to: NSPoint(x: 2.0, y: 15.75),
                       controlPoint1: NSPoint(x: 1.8, y: 12.6),
                       controlPoint2: NSPoint(x: 1.7, y: 16.3))
            head.curve(to: NSPoint(x: 5.85, y: 13.75),
                       controlPoint1: NSPoint(x: 2.5, y: 16.35),
                       controlPoint2: NSPoint(x: 4.7, y: 14.6))
            head.curve(to: NSPoint(x: 12.15, y: 13.75),
                       controlPoint1: NSPoint(x: 7.7, y: 14.45),
                       controlPoint2: NSPoint(x: 10.3, y: 14.45))
            head.curve(to: NSPoint(x: 16.0, y: 15.75),
                       controlPoint1: NSPoint(x: 13.3, y: 14.6),
                       controlPoint2: NSPoint(x: 15.5, y: 16.35))
            head.curve(to: NSPoint(x: 15.75, y: 10.9),
                       controlPoint1: NSPoint(x: 16.3, y: 16.3),
                       controlPoint2: NSPoint(x: 16.2, y: 12.6))
            head.curve(to: NSPoint(x: 16.1, y: 7.6),
                       controlPoint1: NSPoint(x: 16.15, y: 10.05),
                       controlPoint2: NSPoint(x: 16.35, y: 8.85))
            head.curve(to: NSPoint(x: 9, y: 2.05),
                       controlPoint1: NSPoint(x: 15.65, y: 3.9),
                       controlPoint2: NSPoint(x: 12.65, y: 2.05))
            head.curve(to: NSPoint(x: 1.9, y: 7.6),
                       controlPoint1: NSPoint(x: 5.35, y: 2.05),
                       controlPoint2: NSPoint(x: 2.35, y: 3.9))
            head.curve(to: NSPoint(x: 2.25, y: 10.9),
                       controlPoint1: NSPoint(x: 1.65, y: 8.85),
                       controlPoint2: NSPoint(x: 1.85, y: 10.05))
            head.close()
            stroke(head)

            let ears = NSBezierPath()
            ears.move(to: NSPoint(x: 3.15, y: 14.05))
            ears.line(to: NSPoint(x: 4.25, y: 13.35))
            ears.move(to: NSPoint(x: 14.85, y: 14.05))
            ears.line(to: NSPoint(x: 13.75, y: 13.35))
            stroke(ears, width: 0.9)

            // The eye's highlight is a transparent hole, not white paint:
            // template images must remain a pure alpha mask in dark mode.
            let eye = NSBezierPath(ovalIn: NSRect(x: 4.55, y: 8.75, width: 3.35, height: 3.85))
            eye.append(NSBezierPath(ovalIn: NSRect(x: 5.05, y: 10.6, width: 1.05, height: 1.15)))
            eye.windingRule = .evenOdd
            eye.fill()

            let wink = NSBezierPath()
            wink.move(to: NSPoint(x: 10.7, y: 9.8))
            wink.curve(to: NSPoint(x: 14.0, y: 9.8),
                       controlPoint1: NSPoint(x: 11.55, y: 11.1),
                       controlPoint2: NSPoint(x: 13.15, y: 11.1))
            stroke(wink)

            let nose = NSBezierPath()
            nose.move(to: NSPoint(x: 8.2, y: 7.55))
            nose.line(to: NSPoint(x: 9.8, y: 7.55))
            nose.line(to: NSPoint(x: 9, y: 6.65))
            nose.close()
            nose.fill()

            let smile = NSBezierPath()
            smile.move(to: NSPoint(x: 9, y: 6.7))
            smile.line(to: NSPoint(x: 9, y: 5.8))
            smile.curve(to: NSPoint(x: 6.85, y: 5.65),
                        controlPoint1: NSPoint(x: 8.35, y: 4.95),
                        controlPoint2: NSPoint(x: 7.4, y: 4.95))
            smile.move(to: NSPoint(x: 9, y: 5.8))
            smile.curve(to: NSPoint(x: 11.15, y: 5.65),
                        controlPoint1: NSPoint(x: 9.65, y: 4.95),
                        controlPoint2: NSPoint(x: 10.6, y: 4.95))
            stroke(smile, width: 1)

            let whiskers = NSBezierPath()
            whiskers.move(to: NSPoint(x: 3.25, y: 7.4))
            whiskers.line(to: NSPoint(x: 4.6, y: 7.05))
            whiskers.move(to: NSPoint(x: 3.55, y: 5.7))
            whiskers.line(to: NSPoint(x: 4.75, y: 5.85))
            whiskers.move(to: NSPoint(x: 14.75, y: 7.4))
            whiskers.line(to: NSPoint(x: 13.4, y: 7.05))
            whiskers.move(to: NSPoint(x: 14.45, y: 5.7))
            whiskers.line(to: NSPoint(x: 13.25, y: 5.85))
            stroke(whiskers, width: 0.9)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "哈基米猫咪头像"
        return image
    }
}

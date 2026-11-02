import AppKit
import Darwin

/// Standalone, offscreen checks; this does not launch Hajimi or touch networking.
@main
struct IconAssetsSmokeTest {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static func main() {
        do {
            let resources = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? "Resources",
                                isDirectory: true)
            try validateStatusIcon()
            try validateApplicationIcons(in: resources)
            try validateBrandFallback()
            if CommandLine.arguments.count > 2 {
                try validateBrandIcon(in: URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true))
            }
            print("PASS: all icon assets")
        } catch {
            FileHandle.standardError.write(Data("FAIL: \(error.localizedDescription)\n".utf8))
            exit(EXIT_FAILURE)
        }
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(message: message) }
    }

    private static func color(_ bitmap: NSBitmapImageRep, x: Int, y: Int) throws -> NSColor {
        guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else {
            throw Failure(message: "Cannot read RGBA pixel at \(x),\(y)")
        }
        return color
    }

    private static func validateTransparentEdges(_ bitmap: NSBitmapImageRep, label: String) throws {
        for x in 0..<bitmap.pixelsWide {
            for y in [0, bitmap.pixelsHigh - 1] {
                try require(try color(bitmap, x: x, y: y).alphaComponent == 0,
                            "\(label): nontransparent edge at \(x),\(y)")
            }
        }
        for y in 0..<bitmap.pixelsHigh {
            for x in [0, bitmap.pixelsWide - 1] {
                try require(try color(bitmap, x: x, y: y).alphaComponent == 0,
                            "\(label): nontransparent edge at \(x),\(y)")
            }
        }
    }

    private static func render(_ image: NSImage, points: Int = 18, scale: Int) throws -> NSBitmapImageRep {
        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: points * scale, pixelsHigh: points * scale,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
            isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
              let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
            throw Failure(message: "Cannot create icon rendering context")
        }
        NSGraphicsContext.saveGraphicsState()
        defer { NSGraphicsContext.restoreGraphicsState() }
        NSGraphicsContext.current = context
        context.cgContext.scaleBy(x: CGFloat(scale), y: CGFloat(scale))
        image.draw(in: NSRect(x: 0, y: 0, width: points, height: points),
                   from: .zero, operation: .sourceOver, fraction: 1)
        return bitmap
    }

    private static func pixels(_ bitmap: NSBitmapImageRep) throws -> Data {
        guard let bytes = bitmap.bitmapData else { throw Failure(message: "Missing bitmap pixels") }
        return Data(bytes: bytes, count: bitmap.bytesPerRow * bitmap.pixelsHigh)
    }

    private static func validateBrandFallback() throws {
        let missingResources = Bundle(for: NSImage.self)
        try require(missingResources.url(forResource: "Hajimi", withExtension: "icns") == nil,
                    "Fallback test bundle unexpectedly contains Hajimi.icns")
        let fallback = HajimiBrandIcon.makeImage(bundle: missingResources)
        try require(fallback.isTemplate && fallback.size == NSSize(width: 18, height: 18),
                    "Missing brand resources must fall back to the 18 pt cat template")
        let actual = try render(fallback, scale: 2)
        let expected = try render(StatusBarCatIcon.makeImage(), scale: 2)
        try require(try pixels(actual) == pixels(expected), "Brand fallback does not match the status cat")
        print("PASS: missing brand resources fall back to the cat template")
    }

    private static func validateColorSubject(_ bitmap: NSBitmapImageRep, label: String) throws {
        var colored = 0
        for y in 0..<bitmap.pixelsHigh {
            for x in 0..<bitmap.pixelsWide {
                let pixel = try color(bitmap, x: x, y: y)
                let channels = [pixel.redComponent, pixel.greenComponent, pixel.blueComponent]
                if pixel.alphaComponent > 0.5 && channels.max()! - channels.min()! > 0.1 { colored += 1 }
            }
        }
        try require(colored > bitmap.pixelsWide * bitmap.pixelsHigh / 100,
                    "\(label): missing visible color subject (blank or incorrectly tinted)")
    }

    private static func validateBrandIcon(in appURL: URL) throws {
        guard appURL.pathExtension == "app", let bundle = Bundle(url: appURL),
              let resource = bundle.url(forResource: "Hajimi", withExtension: "icns"),
              let reference = NSImage(contentsOf: resource), reference.isValid else {
            throw Failure(message: "Cannot load Hajimi.icns from \(appURL.path)")
        }
        let image = HajimiBrandIcon.makeImage(bundle: bundle)
        try require(!image.isTemplate && image.isValid, "Bundled brand icon must be a valid, non-template image")
        for scale in [1, 2, 3] {
            let bitmap = try render(image, points: 44, scale: scale)
            let expected = try render(reference, points: 44, scale: scale)
            let label = "Brand icon 44 pt \(scale)×"
            try require(try pixels(bitmap) == pixels(expected), "\(label): does not match bundled Hajimi.icns")
            try validateTransparentEdges(bitmap, label: label)
            try validateColorSubject(bitmap, label: label)
            print("PASS: \(label), matches bundled ICNS, unclipped color subject")
        }

        // Match the sidebar image view: labelColor must only tint templates,
        // not turn the full-color orange cat into a monochrome silhouette.
        let view = NSImageView(frame: NSRect(x: 0, y: 0, width: 44, height: 44))
        view.image = image
        view.imageScaling = .scaleProportionallyUpOrDown
        view.imageAlignment = .alignCenter
        view.contentTintColor = .labelColor
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            throw Failure(message: "Cannot render the brand image view")
        }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        try validateTransparentEdges(bitmap, label: "Sidebar brand view")
        try validateColorSubject(bitmap, label: "Sidebar brand view")
        print("PASS: sidebar image view preserves color with labelColor tint")
    }

    private static func validateStatusIcon() throws {
        let image = StatusBarCatIcon.makeImage()
        try require(image.size == NSSize(width: 18, height: 18), "Status icon must be 18 pt")
        try require(image.isTemplate, "Status icon must be a template")
        try require(image.representations.contains { $0 is NSCustomImageRep },
                    "Status icon must have a resolution-independent drawing representation")
        try require(image.accessibilityDescription?.isEmpty == false,
                    "Status icon must have an accessibility description")

        for scale in [1, 2, 3] {
            let bitmap = try render(image, scale: scale)
            let label = "Status icon \(scale)×"
            try validateTransparentEdges(bitmap, label: label)
            var visible = 0
            var transparent = 0
            for y in 0..<bitmap.pixelsHigh {
                for x in 0..<bitmap.pixelsWide {
                    let pixel = try color(bitmap, x: x, y: y)
                    if pixel.alphaComponent > 0.75 { visible += 1 }
                    if pixel.alphaComponent == 0 { transparent += 1 }
                    if pixel.alphaComponent > 0 {
                        try require(pixel.redComponent == 0 && pixel.greenComponent == 0 && pixel.blueComponent == 0,
                                    "\(label): template must contain only black RGB with varying alpha")
                    }
                }
            }
            try require(visible > 25 * scale * scale, "\(label): missing visible cat glyph")
            try require(transparent > 90 * scale * scale, "\(label): missing transparent background")
            print("PASS: \(label), \(bitmap.pixelsWide)×\(bitmap.pixelsHigh), unclipped black alpha mask")
        }
    }

    private static func validateApplicationIcons(in resources: URL) throws {
        for size in [16, 32, 128, 256, 512] {
            for scale in [1, 2] {
                let filename = "icon_\(size)x\(size)\(scale == 2 ? "@2x" : "").png"
                let url = resources.appendingPathComponent("Hajimi.iconset").appendingPathComponent(filename)
                guard let bitmap = NSBitmapImageRep(data: try Data(contentsOf: url)) else {
                    throw Failure(message: "Cannot load \(filename)")
                }
                let expected = size * scale
                try require(bitmap.pixelsWide == expected && bitmap.pixelsHigh == expected,
                            "\(filename): expected \(expected)×\(expected) pixels")
                try require(bitmap.hasAlpha, "\(filename): missing alpha channel")
                try validateTransparentEdges(bitmap, label: filename)

                // A uniform interior grid finds the subject without decoding
                // every large PNG pixel into an NSColor during each test run.
                let step = max(1, expected / 32)
                var hasSubject = false
                for y in stride(from: 1, to: expected - 1, by: step) {
                    for x in stride(from: 1, to: expected - 1, by: step) {
                        if try color(bitmap, x: x, y: y).alphaComponent > 0.5 { hasSubject = true }
                    }
                }
                try require(hasSubject, "\(filename): empty image")
                print("PASS: \(filename), \(expected)×\(expected), transparent edges and visible subject")
            }
        }
        let icns = resources.appendingPathComponent("Hajimi.icns")
        guard let image = NSImage(contentsOf: icns), image.isValid, !image.representations.isEmpty else {
            throw Failure(message: "Cannot load Hajimi.icns")
        }
        print("PASS: Hajimi.icns loads")
    }
}

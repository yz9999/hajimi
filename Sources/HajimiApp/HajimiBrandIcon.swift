import AppKit

/// Keep in-app branding in sync with the Dock/Finder icon, without relying
/// on AppKit's process-wide named-image cache.
enum HajimiBrandIcon {
    static func makeImage(bundle: Bundle = .main) -> NSImage {
        guard let url = bundle.url(forResource: "Hajimi", withExtension: "icns"),
              let image = NSImage(contentsOf: url), image.isValid else {
            // SwiftPM's unbundled executable still shows a cat, not a blank
            // image or the previous letter-based logo.
            return StatusBarCatIcon.makeImage()
        }
        image.isTemplate = false
        image.accessibilityDescription = "哈基米橘猫图标"
        return image
    }
}

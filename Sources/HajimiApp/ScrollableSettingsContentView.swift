import AppKit
import HajimiUIComponents

// Keep the existing Settings/DNS call sites on the same width-fitted scroll view.
typealias ScrollableSettingsContentView = WidthFittingScrollContentView

enum ScrollableSettingsContentSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "可滚动设置页布局自检失败：\(text)" }
    }

    static func run() throws {
        _ = NSApplication.shared
        let form = DNSSettingsFormView()
        let footer = NSButton(title: "保存并应用", target: nil, action: nil)
        let stack = NSStackView(views: [form, footer])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        form.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        let wrapper = ScrollableSettingsContentView(content: stack)
        let host = NSView(frame: NSRect(x: 0, y: 0, width: 700, height: 300))
        wrapper.frame = host.bounds
        host.addSubview(wrapper)
        for width in [700.0, 650.0, 860.0] {
            wrapper.setFrameSize(NSSize(width: width, height: 300))
            wrapper.needsLayout = true
            wrapper.layoutSubtreeIfNeeded()
            guard let document = wrapper.scrollView.documentView else { throw Failure(text: "缺少 document") }
            let clip = wrapper.scrollView.contentView
            guard document.frame.height > clip.bounds.height,
                  abs(document.frame.width - clip.bounds.width) < 1,
                  form.frame.width > 600,
                  footer.frame.height > 0 else {
                throw Failure(text: "document=\(document.frame.size), viewport=\(clip.bounds.size), form=\(form.frame.size), footer=\(footer.frame.size), natural=\(stack.fittingSize)")
            }
            clip.scroll(to: NSPoint(x: 0, y: max(0, document.frame.height - clip.bounds.height)))
            wrapper.scrollView.reflectScrolledClipView(clip)
            let bottom = footer.convert(footer.bounds, to: document)
            guard bottom.maxY <= clip.bounds.maxY + 1, bottom.minY >= clip.bounds.minY - 1 else {
                throw Failure(text: "footer=\(bottom), viewport=\(clip.bounds)")
            }
        }
        print("Scrollable DNS settings check passed: narrow viewport, width fitting, resize and reachable Save button")
    }
}

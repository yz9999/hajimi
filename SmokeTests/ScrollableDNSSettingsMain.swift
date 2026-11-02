import AppKit
import Darwin
import HajimiCore

@main
enum ScrollableDNSSettingsMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }

    private final class SaveTarget: NSObject {
        let form: DNSSettingsFormView
        private(set) var saved: [Profile] = []
        private(set) var error: Error?
        init(form: DNSSettingsFormView) { self.form = form }
        @objc func save(_ sender: Any?) {
            do {
                let text = try form.draft.applying(to: "[General]\ncustom = preserved\n[Rule]\nFINAL,REJECT\n")
                guard text.contains("custom = preserved\n") else { throw Failure(text: "Save lost unrelated profile text") }
                saved.append(try ProfileParser.parse(text))
            } catch { self.error = error }
        }
    }

    static func main() {
        do {
            try ScrollableSettingsContentSelfTest.run()
            try checkModeChangesAndSaving()
        }
        catch {
            FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
            Darwin.exit(1)
        }
    }

    private static func checkModeChangesAndSaving() throws {
        let form = DNSSettingsFormView()
        let target = SaveTarget(form: form)
        let save = NSButton(title: "保存并应用", target: target, action: #selector(SaveTarget.save(_:)))
        let stack = NSStackView(views: [form, save])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        form.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        let wrapper = ScrollableSettingsContentView(content: stack)
        let host = NSView(frame: NSRect(x: 0, y: 0, width: 650, height: 260))
        wrapper.frame = host.bounds
        host.addSubview(wrapper)
        let draft = DNSSettingsDraft(encryptedText: "", traditionalText: "9.9.9.9\n",
            protectionEnabled: true, proxyFallbackEnabled: false, proxyFallbackText: "1.1.1.1\n")
        form.load(draft)
        var expectedSaves = 0
        for width in [650.0, 760.0] {
            wrapper.setFrameSize(NSSize(width: width, height: 260))
            for (index, mode) in DNSSelectionMode.allCases.enumerated() {
                form.selectionModePopup.selectItem(at: index)
                _ = form.selectionModePopup.sendAction(form.selectionModePopup.action!, to: form.selectionModePopup.target)
                form.prewarmButton.state = mode == .balanced ? .off : .on
                for _ in 0..<3 {
                    wrapper.needsLayout = true
                    wrapper.layoutSubtreeIfNeeded()
                }
                guard let document = wrapper.scrollView.documentView else { throw Failure(text: "Missing scrolling document") }
                let clip = wrapper.scrollView.contentView
                guard document.frame.height > clip.bounds.height,
                      abs(document.frame.width - clip.bounds.width) < 1,
                      !wrapper.scrollView.hasHorizontalScroller else {
                    throw Failure(text: "Mode changes broke width fitting or vertical scrolling")
                }
                clip.scroll(to: NSPoint(x: 0, y: max(0, document.frame.height - clip.bounds.height)))
                wrapper.scrollView.reflectScrolledClipView(clip)
                let button = save.convert(save.bounds, to: document)
                guard button.minY >= clip.bounds.minY - 1, button.maxY <= clip.bounds.maxY + 1 else {
                    throw Failure(text: "Save is unreachable after mode change at \(width) pt")
                }
                save.performClick(nil)
                expectedSaves += 1
                if let error = target.error { throw error }
                guard target.saved.count == expectedSaves, let profile = target.saved.last,
                      profile.dnsSelectionMode == mode,
                      profile.dnsPrewarmEnabled == (mode != .balanced),
                      !profile.dnsProxyFallbackEnabled, profile.dnsProxyFallbackServers == ["1.1.1.1"],
                      form.draft.traditionalText == draft.traditionalText,
                      form.draft.proxyFallbackText == draft.proxyFallbackText else {
                    throw Failure(text: "Reachable Save did not apply mode/prewarm or retained list consent incorrectly")
                }
            }
        }
        print("Scrollable DNS mode/save check passed: all three modes at 650/760 pt, 260 pt viewport, six functional Saves")
    }
}

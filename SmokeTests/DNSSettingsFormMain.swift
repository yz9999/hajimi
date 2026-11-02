import AppKit
import Darwin
import HajimiCore

/// Offscreen form/model checks only: no MainWindowController, resolver,
/// listeners, Helper, configuration store, or visible application window.
@main
struct DNSSettingsFormChecks {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }
    private static var assertions = 0
    private static let doh = "https://dns.google/dns-query#8.8.8.8"
    private static let dot = "tls://dns.example.test:8853#2001:db8::8"

    private static func expect(_ condition: Bool, _ message: String) throws {
        assertions += 1
        if !condition { throw Failure(message: message) }
    }
    private static func rejects(_ message: String, _ action: () throws -> Void) throws {
        var failed = false
        do { try action() } catch { failed = true }
        try expect(failed, message)
    }

    static func main() {
        // Cocoa control actions/font metrics are available without a window.
        // Prohibited activation prevents a standalone fixture gaining UI.
        _ = NSApplication.shared.setActivationPolicy(.prohibited)
        do { try run() }
        catch {
            FileHandle.standardError.write(Data("FAILED DNS settings form: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }

    private static func run() throws {
        let legacyText = """
        # keep profile
        [General]
        dns-server = 1.1.1.1, https://old.example.test/dns-query#203.0.113.7  # keep legacy comment
        encrypted-dns-server = tls://old.example.test:853#2001:db8::7  # keep encrypted comment
        http-listen = 127.0.0.1:18062 # keep listener
        unrelated = untouched # keep unrelated
        [Proxy]
        Local = socks5, 127.0.0.1, 1080, password="p,a#ss" # keep node
        [Rule]
        FINAL,DIRECT # keep rule
        """ + "\n"
        let old = try ProfileParser.parse(legacyText)
        let legacyDraft = DNSSettingsDraft(profile: old)
        try expect(legacyDraft.traditionalServers == ["1.1.1.1"],
                   "loading legacy mixed DNS must put only traditional addresses in the traditional editor")
        try expect(legacyDraft.encryptedServers == ["tls://old.example.test:853#2001:db8::7",
                                                   "https://old.example.test/dns-query#203.0.113.7"],
                   "loading legacy mixed DNS must display new encrypted entries before legacy encrypted URIs")
        try expect(!legacyDraft.proxyFallbackEnabled && legacyDraft.proxyFallbackServers.isEmpty,
                   "an old profile must not implicitly approve bootstrap resolvers for proxy fallback")
        try expect(legacyDraft.selectionMode == .balanced && legacyDraft.prewarmEnabled,
                   "old profile drafts must default to balanced mode and enabled connection prewarming")

        let form = DNSSettingsFormView()
        form.load(legacyDraft)
        try expect(form.draft == legacyDraft && form.protectionButton.state == .on,
                   "loading a profile lost raw DNS draft state or protection")
        try expect(form.encryptedServersTextView.isEditable && form.traditionalServersTextView.isEditable,
                   "both independent DNS editors must remain editable")
        try expect(form.proxyFallbackButton.state == .off && form.proxyFallbackServersTextView.isEditable &&
                   form.proxyFallbackServersTextView.string.isEmpty,
                   "fallback must default off with an independent editable, empty approval list")
        let originalTraditional = form.draft.traditionalText
        form.encryptedServersTextView.string = doh + "\n" + dot
        try expect(form.draft.traditionalText == originalTraditional && form.draft.encryptedServers == [doh, dot],
                   "editing encrypted DNS unexpectedly changed the traditional editor")
        let originalEncrypted = form.draft.encryptedText
        form.traditionalServersTextView.string = "127.0.0.1:5300\n[::1]:5400"
        try expect(form.draft.encryptedText == originalEncrypted &&
                   form.draft.traditionalServers == ["127.0.0.1:5300", "[::1]:5400"],
                   "editing traditional DNS unexpectedly changed encrypted settings")
        try expect(form.draft.proxyFallbackText.isEmpty && !form.draft.proxyFallbackEnabled,
                   "editing bootstrap DNS accidentally approved or enabled ordinary proxy fallback")

        let saved = form.draft
        form.encryptedServersTextView.string += " "
        try expect(form.draft != saved && form.draft.encryptedServers == saved.encryptedServers,
                   "raw encrypted whitespace edits during async Save must count as an unsaved draft")
        form.load(saved)
        form.traditionalServersTextView.string += "\n"
        try expect(form.draft != saved && form.draft.traditionalServers == saved.traditionalServers,
                   "raw traditional whitespace edits during async Save must count as an unsaved draft")
        form.load(saved)
        form.protectionButton.state = .off
        try expect(form.draft != saved && !form.draft.protectionEnabled &&
                   form.draft.encryptedServers == saved.encryptedServers &&
                   form.draft.traditionalServers == saved.traditionalServers,
                   "protection edits must be detected without mutating either resolver list")

        let applied = try form.draft.applying(to: legacyText)
        let reread = try ProfileParser.parse(applied)
        try expect(reread.dnsServers == ["127.0.0.1:5300", "[::1]:5400"] &&
                   reread.encryptedDNSServers == [doh, dot] && !reread.dnsLeakProtectionEnabled,
                   "Save mixed up the two General DNS keys or protection state")
        try expect(!applied.contains("#203.0.113.7") && !applied.contains("#2001:db8::7"),
                   "replacing bootstrap pins retained the old pin as a fake trailing comment")
        for text in ["# keep profile\n", "# keep legacy comment", "# keep encrypted comment",
                     "http-listen = 127.0.0.1:18062 # keep listener\n",
                     "unrelated = untouched # keep unrelated\n",
                     "Local = socks5, 127.0.0.1, 1080, password=\"p,a#ss\" # keep node\n",
                     "FINAL,DIRECT # keep rule\n"] {
            try expect(applied.contains(text), "DNS form Save rewrote unrelated text or lost a real comment: \(text)")
        }

        let migratedText = try legacyDraft.applying(to: legacyText)
        let migrated = try ProfileParser.parse(migratedText)
        try expect(migrated.dnsServers == ["1.1.1.1"] &&
                   migrated.encryptedDNSServers == legacyDraft.encryptedServers,
                   "saving an unchanged legacy form must migrate mixed settings into independent keys")
        let traditionalLine = migratedText.components(separatedBy: .newlines)
            .first(where: { $0.hasPrefix("dns-server") }) ?? ""
        try expect(!traditionalLine.contains("https://") && !traditionalLine.contains("tls://") &&
                   !traditionalLine.contains("#203.0.113.7") && traditionalLine.contains("# keep legacy comment"),
                   "legacy migration left an encrypted URI/bootstrap pin in the traditional line")

        // A comma is legal inside a URI path/query. Quote-containing raw
        // configuration values must likewise survive CSV emission verbatim;
        // runtime endpoint validation remains a separate fail-closed step.
        let commaURI = "https://dns.google/dns-query?x=a,b#8.8.8.8"
        let quoteURI = "https://dns.google/dns-query?tag=\"hello,cat\"#8.8.8.8"
        let localIPv6URI = "https://dns.google/dns-query#[::1]"
        let remoteIPv6URI = "tls://dns.example.test:8853#[2001:db8::8]"
        var uriProfile = Profile()
        uriProfile.dnsServers = ["1.1.1.1", commaURI]
        uriProfile.encryptedDNSServers = [quoteURI, localIPv6URI, remoteIPv6URI]
        let uriDraft = DNSSettingsDraft(profile: uriProfile)
        let expectedURIs = [quoteURI, localIPv6URI, remoteIPv6URI, commaURI]
        try expect(uriDraft.encryptedServers == expectedURIs && uriDraft.traditionalServers == ["1.1.1.1"],
                   "legacy/new comma or quoted URIs were split into false server entries during load")
        form.load(uriDraft)
        let uriSaved = try form.draft.applying(to: "[General]\ndns-server = 1.1.1.1 # keep traditional\n")
        let uriReread = try ProfileParser.parse(uriSaved)
        try expect(uriReread.encryptedDNSServers == expectedURIs && uriReread.dnsServers == ["1.1.1.1"] &&
                   uriSaved.contains("# keep traditional"),
                   "saving comma/quote/bracketed-pin URIs corrupted encrypted values or the traditional setting")
        let loadedAgain = DNSSettingsDraft(profile: uriReread)
        try expect(loadedAgain.encryptedServers == expectedURIs,
                   "serialized encrypted URIs were not stable across a second form load")
        form.load(loadedAgain)
        form.encryptedServersTextView.string = [remoteIPv6URI, commaURI, quoteURI, localIPv6URI].joined(separator: "\n")
        let reordered = try ProfileParser.parse(form.draft.applying(to: uriSaved))
        try expect(reordered.encryptedDNSServers == [remoteIPv6URI, commaURI, quoteURI, localIPv6URI] &&
                   reordered.dnsServers == ["1.1.1.1"],
                   "editing/reordering complex encrypted URIs failed to preserve order or changed traditional DNS")

        let beforeDefault = form.draft
        form.defaultEncryptedButton.performClick(nil)
        try expect(form.draft.encryptedServers == Profile.defaultSecureDNSServers &&
                   form.draft.traditionalText == beforeDefault.traditionalText &&
                   form.draft.protectionEnabled == beforeDefault.protectionEnabled &&
                   form.draft.proxyFallbackEnabled == beforeDefault.proxyFallbackEnabled &&
                   form.draft.proxyFallbackText == beforeDefault.proxyFallbackText,
                   "default-encrypted button must only update the encrypted editor")
        try expect(form.connectivityButton.target == nil && form.connectivityButton.action == nil,
                   "constructing an offscreen form must not attach a network-test action implicitly")

        let beforeFallback = form.draft
        form.proxyFallbackServersTextView.string = "1.1.1.1\n[2606:4700:4700::1111]:5353"
        form.proxyFallbackButton.state = .on
        let fallbackSubmitted = form.draft
        try expect(fallbackSubmitted.proxyFallbackEnabled && fallbackSubmitted.proxyFallbackServers ==
                   ["1.1.1.1", "[2606:4700:4700::1111]:5353"] &&
                   fallbackSubmitted.encryptedText == beforeFallback.encryptedText &&
                   fallbackSubmitted.traditionalText == beforeFallback.traditionalText,
                   "fallback edits must be explicit and never mutate encrypted/bootstrap drafts")
        let fallbackSaved = try fallbackSubmitted.applying(to: legacyText)
        let fallbackProfile = try ProfileParser.parse(fallbackSaved)
        try expect(fallbackProfile.dnsProxyFallbackEnabled &&
                   fallbackProfile.dnsProxyFallbackServers == fallbackSubmitted.proxyFallbackServers &&
                   fallbackProfile.traditionalDNSServers == fallbackSubmitted.traditionalServers &&
                   fallbackProfile.configuredEncryptedDNSServers == fallbackSubmitted.encryptedServers,
                   "Save did not round-trip the distinct opt-in and approval list")
        form.proxyFallbackServersTextView.string += " "
        try expect(form.draft != fallbackSubmitted && form.draft.proxyFallbackServers == fallbackSubmitted.proxyFallbackServers,
                   "raw fallback edits during async Save must preserve the later unsaved draft")
        form.load(fallbackSubmitted)
        form.proxyFallbackButton.state = .off
        try expect(form.draft != fallbackSubmitted && !form.draft.proxyFallbackEnabled &&
                   form.draft.proxyFallbackText == fallbackSubmitted.proxyFallbackText,
                   "an async toggle change must remain dirty and must not erase approved servers")
        let disabledFallback = try ProfileParser.parse(form.draft.applying(to: fallbackSaved))
        try expect(!disabledFallback.dnsProxyFallbackEnabled &&
                   disabledFallback.dnsProxyFallbackServers == fallbackSubmitted.proxyFallbackServers,
                   "turning fallback off discarded the independent approval list")
        let labels = form.subviews.compactMap { ($0 as? NSTextField)?.stringValue }
        try expect(labels.contains { $0.contains("本机绝不直连") && $0.contains("代理出口仍明文") && $0.contains("节点可见") },
                   "the form must disclose node visibility and plaintext at the proxy exit")
        try expect(form.proxyFallbackButton.toolTip?.contains("默认关闭") == true &&
                   form.proxyFallbackButton.toolTip?.contains("关闭会保留") == true,
                   "fallback consent tooltip must explain defaults and approval retention")
        form.proxyFallbackServersTextView.string = ""
        let cleared = try ProfileParser.parse(form.draft.applying(to: fallbackSaved))
        try expect(!cleared.dnsProxyFallbackEnabled && cleared.dnsProxyFallbackServers.isEmpty,
                   "explicit editor clearing failed to remove the approval list")
        form.proxyFallbackButton.state = .on
        try rejects("empty opt-in must not inherit bootstrap servers") { _ = try form.draft.applying(to: legacyText) }
        for invalid in ["system", "dns.google", "udp://1.1.1.1:53", "198.18.16.2", "127.0.0.1", "[::1]:53"] {
            form.proxyFallbackServersTextView.string = invalid
            try rejects("invalid fallback endpoint passed Save validation: \(invalid)") { _ = try form.draft.applying(to: legacyText) }
        }
        form.proxyFallbackServersTextView.string = (1...9).map { "192.168.10.\($0)" }.joined(separator: "\n")
        try rejects("fallback form allowed an unbounded server list") { _ = try form.draft.applying(to: legacyText) }

        try validateModeAndPrewarmDrafts(form, originalText: legacyText)
        for width: CGFloat in [760, 650] {
            for mode in DNSSelectionMode.allCases { try validateLayout(width: width, mode: mode) }
        }
        print("DNS settings form checks passed: \(assertions) assertions, three modes, independent editors and 760/650 pt layouts")
    }

    private static func validateModeAndPrewarmDrafts(_ form: DNSSettingsFormView, originalText: String) throws {
        let draft = DNSSettingsDraft(encryptedText: "  \(doh) \n\n\(dot)\n",
            traditionalText: "9.9.9.9,\n8.8.8.8 \n", protectionEnabled: false,
            proxyFallbackEnabled: true, proxyFallbackText: "\n1.1.1.1 \n8.8.8.8\n")
        let text = originalText.replacingOccurrences(of: "[General]\n", with:
            "[General]\ndns-selection-mode = balanced # keep mode\ndns-prewarm = true # keep prewarm\n")
        var behaviorChanges = 0
        form.onBehaviorChange = { behaviorChanges += 1 }
        defer { form.onBehaviorChange = nil }
        form.load(draft)
        try expect(behaviorChanges == 0 && form.draft == draft,
                   "loading a draft must not act like a user change or normalize raw input")
        for (index, mode) in DNSSelectionMode.allCases.enumerated() {
            form.selectionModePopup.selectItem(at: index)
            guard let action = form.selectionModePopup.action else { throw Failure(message: "mode selector has no local action") }
            try expect(form.selectionModePopup.sendAction(action, to: form.selectionModePopup.target),
                       "mode selector is not connected to a real form action")
            let changed = form.draft
            try expect(changed.selectionMode == mode && changed.prewarmEnabled &&
                       changed.encryptedText == draft.encryptedText && changed.traditionalText == draft.traditionalText &&
                       changed.proxyFallbackText == draft.proxyFallbackText && changed.proxyFallbackEnabled &&
                       !changed.protectionEnabled,
                       "mode selection erased raw lists, previous consent, prewarm or protection state")
            try expect(form.proxyFallbackButton.isEnabled == (mode == .balanced) && form.proxyFallbackButton.state == .on,
                       "inactive fallback permission must retain its old value and explain the current mode")
            let savedText = try changed.applying(to: text)
            let profile = try ProfileParser.parse(savedText)
            try expect(profile.dnsSelectionMode == mode && profile.dnsPrewarmEnabled &&
                       profile.dnsProxyFallbackEnabled && profile.dnsProxyFallbackServers == changed.proxyFallbackServers &&
                       profile.dnsServers == changed.traditionalServers && profile.encryptedDNSServers == changed.encryptedServers,
                       "Save did not apply the actual mode while retaining independent resolver lists and authorization")
            for original in ["# keep mode", "# keep prewarm", "# keep encrypted comment", "# keep legacy comment",
                             "unrelated = untouched # keep unrelated\n", "FINAL,DIRECT # keep rule\n"] {
                try expect(savedText.contains(original), "mode/prewarm Save lost unrelated text or comments: \(original)")
            }
        }
        try expect(behaviorChanges == 3, "each mode action must notify the controller without starting network work")
        let labels = form.subviews.compactMap { ($0 as? NSTextField)?.stringValue }
        try expect(labels.contains { $0.contains("选择并保存") && $0.contains("日常择优") && $0.contains("本机绝不直连") },
                   "mixed mode must explicitly disclose selection-and-save consent for regular ordinary queries")
        try expect(labels.contains { $0.contains("不要求加密 DNS 先失败") && $0.contains("原后备开关") },
                   "mixed mode must distinguish its regular consent from the retained failure-only toggle")

        let submitted = form.draft
        form.prewarmButton.performClick(nil)
        try expect(!form.draft.prewarmEnabled && form.draft != submitted && behaviorChanges == 4 &&
                   form.draft.encryptedText == submitted.encryptedText && form.draft.proxyFallbackText == submitted.proxyFallbackText,
                   "prewarm edits during an asynchronous Save must remain dirty without rewriting lists")
        let completedEarlier = try ProfileParser.parse(submitted.applying(to: text))
        try expect(completedEarlier.dnsPrewarmEnabled && !form.draft.prewarmEnabled,
                   "saving an earlier snapshot overwrote the user's later prewarm draft")
        try expect(form.prewarmButton.toolTip?.contains("不发送应用查询") == true &&
                   form.prewarmButton.toolTip?.contains("端点域名") == true,
                   "connection prewarming must distinguish application queries from endpoint bootstrap")

        var mixedWithoutFallback = submitted
        mixedWithoutFallback.proxyFallbackEnabled = false
        form.load(mixedWithoutFallback)
        let mixedProfile = try ProfileParser.parse(form.draft.applying(to: text))
        try expect(mixedProfile.dnsSelectionMode == .mixedSpeed && !mixedProfile.dnsProxyFallbackEnabled &&
                   mixedProfile.dnsProxyFallbackServers == submitted.proxyFallbackServers,
                   "mixed authorization must not silently enable or depend on the failure-only toggle")
        for mode in [DNSSelectionMode.encryptedOnly, .balanced, .mixedSpeed] {
            form.selectionModePopup.selectItem(at: DNSSelectionMode.allCases.firstIndex(of: mode)!)
            _ = form.selectionModePopup.sendAction(form.selectionModePopup.action!, to: form.selectionModePopup.target)
            try expect(form.draft.proxyFallbackText == mixedWithoutFallback.proxyFallbackText &&
                       !form.draft.proxyFallbackEnabled && form.draft.encryptedText == mixedWithoutFallback.encryptedText,
                       "switching away from and back to mixed mode changed prior ordinary consent or raw lists")
        }
        form.proxyFallbackServersTextView.string = ""
        try rejects("mixed mode with an empty approval editor must not borrow bootstrap resolvers") {
            _ = try form.draft.applying(to: text)
        }
        form.load(submitted)
        form.selectionModePopup.selectItem(at: 0)
        _ = form.selectionModePopup.sendAction(form.selectionModePopup.action!, to: form.selectionModePopup.target)
        try expect(form.draft != submitted && form.draft.prewarmEnabled == submitted.prewarmEnabled,
                   "a later mode edit must remain dirty when an earlier Save finishes")
    }

    private static func validateLayout(width: CGFloat, mode: DNSSelectionMode) throws {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: width, height: 1_000))
        let form = DNSSettingsFormView(frame: NSRect(x: 0, y: 0, width: width, height: 500))
        form.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(form)
        // Height is determined by the form's actual content constraints,
        // matching its embedding in a scrollable settings page.
        NSLayoutConstraint.activate([
            form.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            form.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            form.topAnchor.constraint(equalTo: container.topAnchor)
        ])
        form.load(DNSSettingsDraft(encryptedText: doh + "\n" + dot,
                                  traditionalText: "127.0.0.1:5300\n[::1]:5400", protectionEnabled: true,
                                  proxyFallbackEnabled: true,
                                  proxyFallbackText: "1.1.1.1\n[2606:4700:4700::1111]:5353",
                                  selectionMode: mode))
        for _ in 0..<3 {
            container.layoutSubtreeIfNeeded()
            form.layoutSubtreeIfNeeded()
        }
        try expect(abs(form.bounds.width - width) < 1 && form.bounds.height > 250 &&
                   form.bounds.height < container.bounds.height,
                   "form auto-height/width failed at \(width) pt: \(form.frame)")
        let scrolls = form.subviews.compactMap { $0 as? NSScrollView }
        try expect(scrolls.count == 3, "form must have three separately scrollable DNS editors")
        for child in form.subviews {
            // Cocoa labels use a 2 pt optical/alignment inset: an aligned
            // leading edge can legitimately have frame.origin.x == -2.
            // Auto Layout's alignment rectangle is the actual layout extent.
            let rect = child.alignmentRect(forFrame: child.frame)
            try expect(rect.width > 0 && rect.height > 0 && rect.minX >= -1 && rect.minY >= -1 &&
                       rect.maxX <= form.bounds.maxX + 1 && rect.maxY <= form.bounds.maxY + 1,
                       "form control overflows/has zero size at \(width) pt: \(type(of: child)) \(rect)")
        }
        for (name, textView) in [("encrypted", form.encryptedServersTextView),
                                 ("traditional", form.traditionalServersTextView),
                                 ("proxy fallback", form.proxyFallbackServersTextView)] {
            guard let scroll = textView.enclosingScrollView else {
                throw Failure(message: "\(name) text view is not in a scroll view")
            }
            scroll.layoutSubtreeIfNeeded()
            scroll.contentView.layoutSubtreeIfNeeded()
            textView.layoutSubtreeIfNeeded()
            let viewport = scroll.contentView.bounds
            try expect(viewport.width > 100 && viewport.height > 40 &&
                       textView.frame.width > 100 && textView.frame.height > 40,
                       "\(name) editor has a zero/undersized viewport or document at \(width) pt")
            try expect(textView.frame.width <= viewport.width + 1 &&
                       textView.textContainer?.widthTracksTextView == true &&
                       !textView.isHorizontallyResizable && !scroll.hasHorizontalScroller,
                       "\(name) text view horizontally overflows its clipping viewport at \(width) pt: \(textView.frame), \(viewport)")
        }
        print("PASS DNS form layout \(Int(width)) pt \(mode.rawValue): content height \(Int(form.bounds.height)), nonzero unclipped editors")
    }
}

import AppKit
import Darwin
import HajimiCore

/// Standalone, offscreen rule-sheet checks. Never launches Hajimi, displays
/// windows, writes previews, or changes profile/network state.
@main
struct RuleEditorUISmokeTest {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private struct CommitFailure: LocalizedError {
        var errorDescription: String? { "模拟配置保存失败，请重试" }
    }

    private struct Controls {
        let root: NSView
        let type: NSPopUpButton
        let value: NSTextField
        let policy: NSComboBox
        let options: NSTextView
        let save: NSButton
    }

    static func main() {
        do {
            NSApplication.shared.setActivationPolicy(.prohibited)
            try validateRoundTrip()
            try validateCatchAll()
            try validateInvalidValue()
            try validateCommitRetry()
            try validateBatchPolicy()
            print("PASS: rule editor UI (offscreen; no profile or network changes)")
        } catch {
            FileHandle.standardError.write(Data("FAIL: \(error.localizedDescription)\n".utf8))
            exit(EXIT_FAILURE)
        }
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(message: message) }
    }

    private static func descendants(_ view: NSView) -> [NSView] {
        [view] + view.subviews.flatMap(descendants)
    }

    private static func controls(_ controller: RuleEditorSheetController) throws -> Controls {
        guard let root = controller.window?.contentView else { throw Failure(message: "Missing rule sheet") }
        let views = descendants(root)
        guard let type = views.compactMap({ $0 as? NSPopUpButton }).first,
              let value = views.compactMap({ $0 as? NSTextField }).first(where: { $0.isEditable && !($0 is NSComboBox) }),
              let policy = views.compactMap({ $0 as? NSComboBox }).first,
              let options = views.compactMap({ $0 as? NSTextView }).first,
              let save = views.compactMap({ $0 as? NSButton }).first(where: { $0.title == "保存并应用" })
        else { throw Failure(message: "Missing rule editor controls") }
        return Controls(root: root, type: type, value: value, policy: policy, options: options, save: save)
    }

    private static func choose(_ title: String, in popup: NSPopUpButton) throws {
        try require(popup.item(withTitle: title) != nil, "Missing rule type \(title)")
        popup.selectItem(withTitle: title)
        guard let action = popup.action else { throw Failure(message: "Missing type-change action") }
        try require(NSApp.sendAction(action, to: popup.target, from: popup), "Type-change action did not run")
    }

    private static func validateLayout(_ root: NSView) throws {
        root.layoutSubtreeIfNeeded()
        for view in root.subviews {
            let rect = root.convert(view.bounds, from: view)
            try require(rect.minX >= -0.5 && rect.maxX <= root.bounds.maxX + 0.5 &&
                        rect.minY >= -0.5 && rect.maxY <= root.bounds.maxY + 0.5,
                        "Sheet view overflows: \(rect) outside \(root.bounds)")
        }
    }

    private static func validateRoundTrip() throws {
        let options = ["no-resolve", "update-interval=3600", "custom=\"a,b\""]
        let original = SurgeRuleDraft(type: "DOMAIN-SUFFIX", value: "example.com", policy: "🐱 原策略", options: options)
        var captured: SurgeRuleDraft?
        let editor = RuleEditorSheetController(draft: original, policyNames: ["DIRECT", "REJECT", "🐱 策略组"]) { captured = $0 }
        let ui = try controls(editor)
        try require(ui.type.titleOfSelectedItem == original.type && ui.policy.stringValue == original.policy,
                    "Original type or unlisted policy was replaced")
        try choose("FINAL", in: ui.type)
        try require(!ui.value.isEnabled && ui.value.stringValue == original.value, "FINAL lost the in-progress value")
        try choose(original.type, in: ui.type)
        try require(ui.value.isEnabled && ui.value.stringValue == original.value, "Switching back lost the matching value")
        let logical = "((DOMAIN-SUFFIX,example.com),(DEST-PORT,443))"
        try choose("AND", in: ui.type)
        ui.value.stringValue = logical
        try validateLayout(ui.root)
        guard let clip = ui.options.superview as? NSClipView else { throw Failure(message: "Missing parameter clip view") }
        try require(ui.options.frame.width > 0 && abs(ui.options.frame.width - clip.bounds.width) < 1 &&
                    ui.options.frame.height >= min(90, clip.bounds.height), "Parameter editor is empty-sized or incorrectly sized")
        ui.save.performClick(nil)
        try require(captured?.type == "AND" && captured?.value == logical && captured?.policy == original.policy && captured?.options == options,
                    "Logical commas, original policy, or quoted option order changed")

        var legacyCapture: SurgeRuleDraft?
        let legacyOptions = ["", "no-resolve", "custom=\"a,b\"", ""]
        let legacy = RuleEditorSheetController(draft: SurgeRuleDraft(type: "DOMAIN", value: "example.com", policy: "DIRECT", options: legacyOptions), policyNames: []) { legacyCapture = $0 }
        try controls(legacy).save.performClick(nil)
        try require(legacyCapture?.options == legacyOptions, "Unchanged legacy empty parameters were removed")
        print("PASS: rule type/value/policy/options round-trip and sheet layout")
    }

    private static func validateCatchAll() throws {
        for type in ["FINAL", "MATCH"] {
            var captured: SurgeRuleDraft?
            let editor = RuleEditorSheetController(draft: nil, policyNames: []) { captured = $0 }
            let ui = try controls(editor)
            ui.value.stringValue = "retained until save"
            try choose(type, in: ui.type)
            try require(!ui.value.isEnabled, "\(type) must disable matching values")
            try validateLayout(ui.root)
            ui.save.performClick(nil)
            try require(captured?.type == type && captured?.value == "", "\(type) emitted a matching value")
        }
        print("PASS: FINAL/MATCH disable and omit matching values")
    }

    private static func validateInvalidValue() throws {
        var commits = 0
        let editor = RuleEditorSheetController(draft: SurgeRuleDraft(type: "IP-CIDR", value: "not-an-ip", policy: "DIRECT"), policyNames: []) { _ in commits += 1 }
        let ui = try controls(editor)
        ui.save.performClick(nil)
        try require(commits == 0 && ui.save.isEnabled, "Invalid CIDR reached commit or blocked retry")
        try require(descendants(ui.root).compactMap { $0 as? NSTextField }.contains { $0.stringValue.hasPrefix("规则无效") },
                    "Invalid CIDR validation error was not displayed")
        print("PASS: Core validation blocks invalid CIDR")
    }

    private static func validateCommitRetry() throws {
        var attempts = 0
        let editor = RuleEditorSheetController(draft: nil, policyNames: []) { _ in
            attempts += 1
            throw CommitFailure()
        }
        let ui = try controls(editor)
        var closed = false
        let observer = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification,
                                                               object: editor.window, queue: nil) { _ in closed = true }
        defer { NotificationCenter.default.removeObserver(observer) }
        ui.value.stringValue = "example.com"
        ui.save.performClick(nil)
        ui.save.performClick(nil)
        try require(attempts == 2 && ui.save.isEnabled && !closed, "Commit error closed the sheet or prevented retry")
        try require(descendants(ui.root).compactMap { $0 as? NSTextField }.contains { $0.stringValue == CommitFailure().localizedDescription },
                    "Commit error was not displayed")
        try validateLayout(ui.root)
        print("PASS: failed commit keeps the sheet editable and supports retry")
    }

    private static func validateBatchPolicy() throws {
        var captured: String?
        let editor = RulePolicySheetController(count: 24, policyNames: ["🐱 策略组"]) { captured = $0 }
        guard let root = editor.window?.contentView,
              let policy = descendants(root).compactMap({ $0 as? NSComboBox }).first,
              let save = descendants(root).compactMap({ $0 as? NSButton }).first(where: { $0.title == "保存并应用" })
        else { throw Failure(message: "Missing batch policy controls") }
        try validateLayout(root)
        policy.stringValue = " 🐱 策略组 "
        save.performClick(nil)
        try require(captured == "🐱 策略组", "Batch policy did not trim surrounding whitespace")
        print("PASS: batch policy selection, trim and sheet layout")
    }
}

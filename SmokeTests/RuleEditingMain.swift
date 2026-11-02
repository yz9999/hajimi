import Foundation

@main
struct RuleEditingChecks {
    private enum Failure: Error { case assertion(String) }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw Failure.assertion(message) }
    }

    private static func rejects(_ document: inout SurgeProfileDocument, _ message: String,
                                _ operation: (inout SurgeProfileDocument) throws -> Void) throws {
        let original = document.text
        do { try operation(&document) }
        catch {
            try expect(document.text == original, message + ": changed text on failure")
            return
        }
        throw Failure.assertion(message + ": unexpectedly accepted")
    }

    static func main() throws {
        var passed = 0
        func test(_ name: String, _ body: () throws -> Void) throws {
            try body()
            passed += 1
            print("✓ \(name)")
        }

        try test("ordinary rules precede FINAL and remain reachable") {
            var document = SurgeProfileDocument("[Rule]\n# keep\nFINAL,REJECT\n")
            let line = try document.insertRule(SurgeRuleDraft(type: "DOMAIN-SUFFIX", value: "example.com", policy: "DIRECT"))
            let parsed = try ProfileParser.parse(document.text)
            let target = RequestTarget(host: "www.example.com", port: 443, protocolName: "TCP")
            try expect(line == 3 && parsed.rules.first?.sourceLine == line, "wrong inserted source line")
            try expect(parsed.rules.first?.matches(target) == true && parsed.rules.first?.policy == "DIRECT", "rule shadowed by FINAL")
            try expect(parsed.rules.last?.kind == .final, "FINAL not last")
        }

        try test("explicit insertion uses physical lines and refuses unreachable placement") {
            var document = SurgeProfileDocument("[Rule]\nDOMAIN,a,DIRECT\nFINAL,REJECT\nDOMAIN,b,DIRECT\n")
            let draft = SurgeRuleDraft(type: "DOMAIN", value: "first", policy: "DIRECT")
            let line = try document.insertRule(draft, beforeSourceLine: 2)
            try expect(line == 2 && document.text.hasPrefix("[Rule]\nDOMAIN, first, DIRECT\nDOMAIN,a"), "explicit insertion reordered unrelated rules")
            try rejects(&document, "insert after FINAL") { _ = try $0.insertRule(draft, beforeSourceLine: 5) }
        }

        try test("update retains original quoting, options, indentation and comments") {
            let source = "[Rule]\n\tDOMAIN,'a,b#c',DIRECT, no-resolve ,custom=\"a,b#c\" \t# keep\n[Other]\nx = untouched\n"
            var document = SurgeProfileDocument(source)
            var draft = try document.ruleDraft(atSourceLine: 2)
            try expect(draft.value == "a,b#c" && draft.options == ["no-resolve", "custom=\"a,b#c\""], "draft lost quoted fields")
            try document.updateRule(atSourceLine: 2, draft: draft)
            try expect(document.text == source, "no-op update changed bytes")
            draft.policy = "Other, #policy"
            try document.updateRule(atSourceLine: 2, draft: draft)
            try expect(document.text == source.replacingOccurrences(of: "DIRECT,", with: "\"Other, #policy\","), "update damaged untouched fields")
        }

        try test("multi-delete validates all rows before committing") {
            var document = SurgeProfileDocument("[Rule]\n# keep\nDOMAIN,a,DIRECT\nDOMAIN,b,REJECT\nDOMAIN,c,DIRECT\n[Other]\nx=1\n")
            try rejects(&document, "batch contains section header") { try $0.deleteRules(atSourceLines: [3, 6]) }
            try document.deleteRules(atSourceLines: [3, 5])
            try expect(document.text == "[Rule]\n# keep\nDOMAIN,b,REJECT\n[Other]\nx=1\n", "multi-delete removed wrong rows")
        }

        try test("batch policy replacement is atomic and preserves options") {
            var document = SurgeProfileDocument("[Rule]\nDOMAIN,a,DIRECT,no-resolve # a\nRULE-SET,https://example.com/rules,DIRECT,update-interval=3600,custom=\"a,b\" # b\nFINAL,REJECT\n")
            try rejects(&document, "batch contains out-of-range row") { try $0.setRulePolicies(atSourceLines: [2, 99], policy: "P") }
            try document.setRulePolicies(atSourceLines: [2, 3], policy: "P, #1")
            try expect(document.text.contains("DOMAIN,a,\"P, #1\",no-resolve # a"), "ordinary options changed")
            try expect(document.text.contains("update-interval=3600,custom=\"a,b\" # b\nFINAL,REJECT"), "RULE-SET options or final changed")
            let parsed = try ProfileParser.parse(document.text)
            try expect(parsed.rules.prefix(2).allSatisfy { $0.policy == "P, #1" }, "batch policy not parsed correctly")
        }

        try test("filtered multi-selection never substitutes table indexes for source lines") {
            var document = SurgeProfileDocument("[Rule]\n# keep\nDOMAIN,a,DIRECT\n# gap\nDOMAIN,b,DIRECT\n# gap\nDOMAIN,c,DIRECT\nFINAL,REJECT\n")
            let visible = [5, 7]
            let selected = RuleTableSelection.sourceLines(rows: IndexSet(integer: 1), orderedSourceLines: visible)
            try expect(selected == [7], "filtered row mapped to wrong source line")
            try document.deleteRules(atSourceLines: selected)
            try expect(document.text.contains("DOMAIN,a,DIRECT") && document.text.contains("DOMAIN,b,DIRECT") && !document.text.contains("DOMAIN,c,DIRECT"), "filtered deletion targeted wrong rule")
            let retained = RuleTableSelection.retaining([3, 7], visibleSourceLines: visible, sourceTextChanged: false)
            try expect(retained == [7], "hidden selection retained")
            try expect(RuleTableSelection.retaining([7], visibleSourceLines: visible, sourceTextChanged: true).isEmpty, "stale source selection retained")
            try expect(RuleTableSelection.rowIndexes(sourceLines: [7], orderedSourceLines: visible) == IndexSet(integer: 1), "reverse selection mapping failed")
        }

        try test("CRLF source lines and terminators round-trip") {
            let source = "[Rule]\r\n\tDOMAIN,a,DIRECT # keep\r\nFINAL,REJECT\r\n[Other]\r\nx=1\r\n"
            var document = SurgeProfileDocument(source)
            let parsed = try ProfileParser.parse(source)
            try expect(parsed.rules.map(\.sourceLine) == [2, 3], "CRLF counted as two lines")
            let draft = try document.ruleDraft(atSourceLine: 2)
            try document.updateRule(atSourceLine: 2, draft: draft)
            try expect(document.text == source, "CRLF no-op changed bytes")
            _ = try document.insertRule(SurgeRuleDraft(type: "DOMAIN", value: "b", policy: "DIRECT"))
            try expect(document.text.contains("DOMAIN, b, DIRECT\r\nFINAL,REJECT\r\n[Other]\r\nx=1\r\n"), "CRLF insertion changed unrelated sections")
        }

        try test("mixed terminators and missing EOF newline are preserved") {
            var document = SurgeProfileDocument("[Rule]\r\n DOMAIN,a,DIRECT  # first\nDOMAIN,b,REJECT\r\n[Other]\nx=1")
            try document.setRulePolicies(atSourceLines: [2, 3], policy: "P")
            try expect(document.text == "[Rule]\r\n DOMAIN,a,P  # first\nDOMAIN,b,P\r\n[Other]\nx=1", "mixed terminators or EOF changed")
            var last = SurgeProfileDocument("[Rule]\nDOMAIN,a,DIRECT\nDOMAIN,b,DIRECT")
            try last.deleteRules(atSourceLines: [3])
            try expect(last.text == "[Rule]\nDOMAIN,a,DIRECT", "EOF convention changed on deletion")
            _ = try last.insertRule(SurgeRuleDraft(type: "DOMAIN", value: "c", policy: "DIRECT"))
            try expect(!last.text.hasSuffix("\n"), "insertion added EOF newline")
        }

        try test("bounds, comments, unsupported rules and other sections cannot be mutated") {
            var document = SurgeProfileDocument("[Rule]\n# keep\n\nDOMAIN,a,DIRECT\nUNKNOWN,x,DIRECT\n[Other]\nDOMAIN,b,DIRECT\n")
            for line in [Int.min, -1, 0, 1, 2, 3, 5, 6, 7, Int.max] {
                try rejects(&document, "invalid line \(line)") { try $0.deleteRules(atSourceLines: [4, line]) }
            }
        }

        try test("invalid type, empty required fields, CIDR and port input are rejected") {
            var document = SurgeProfileDocument("[Rule]\nFINAL,DIRECT\n")
            let invalid: [SurgeRuleDraft] = [
                SurgeRuleDraft(type: "UNSUPPORTED", value: "x", policy: "DIRECT"),
                SurgeRuleDraft(type: "DOMAIN", value: "", policy: "DIRECT"),
                SurgeRuleDraft(type: "DOMAIN", value: "x", policy: ""),
                SurgeRuleDraft(type: "IP-CIDR", value: "192.0.2.1/33", policy: "DIRECT"),
                SurgeRuleDraft(type: "IP-CIDR6", value: "2001:db8::/129", policy: "DIRECT"),
                SurgeRuleDraft(type: "SRC-IP", value: "not-an-address/24", policy: "DIRECT"),
                SurgeRuleDraft(type: "DEST-PORT", value: "80-abc", policy: "DIRECT"),
                SurgeRuleDraft(type: "SOURCE-PORT", value: "443-80", policy: "DIRECT"),
                SurgeRuleDraft(type: "IN-PORT", value: "65536", policy: "DIRECT"),
                SurgeRuleDraft(type: "DEST-PORT", value: "0", policy: "DIRECT"),
                SurgeRuleDraft(type: "RULE-SET", value: "https://example.com/list", policy: "DIRECT", options: ["update-interval=nan"])
            ]
            for draft in invalid { try rejects(&document, "invalid draft \(draft.type)") { _ = try $0.insertRule(draft) } }
        }

        try test("newline and control-character injection is rejected before trimming") {
            var document = SurgeProfileDocument("[Rule]\nDOMAIN,a,DIRECT\nFINAL,DIRECT\n")
            for separator in ["\n", "\r", "\u{0085}", "\u{2028}", "\u{2029}", "\u{0000}", "\t"] {
                let base = SurgeRuleDraft(type: "DOMAIN", value: "example.com", policy: "DIRECT")
                for field in 0..<4 {
                    var draft = base
                    let injection = separator + "[General]" + separator + "allow-wifi-access=true"
                    switch field {
                    case 0: draft.type += injection
                    case 1: draft.value += injection
                    case 2: draft.policy += injection
                    default: draft.options = ["no-resolve" + injection]
                    }
                    try rejects(&document, "injection field \(field)") { try $0.updateRule(atSourceLine: 2, draft: draft) }
                }
            }
        }

        try test("nested logical rules retain quoted values, policy and options") {
            let draft = SurgeRuleDraft(type: "NOT", value: "((OR,((DOMAIN,\"a,b#c)\"),(DOMAIN-KEYWORD,\"quote\\\"x\"))))",
                                       policy: "Node (x), #1", options: ["no-resolve", "custom=\"a,b#c\""])
            var document = SurgeProfileDocument("[Rule]\nFINAL,DIRECT\n")
            let line = try document.insertRule(draft)
            let read = try document.ruleDraft(atSourceLine: line)
            try expect(read == draft, "logical draft did not round-trip")
            let before = document.text
            try document.updateRule(atSourceLine: line, draft: read)
            try expect(document.text == before, "logical no-op changed raw fields")
            try document.setRulePolicies(atSourceLines: [line], policy: "Other, (Node)#")
            let changed = try document.ruleDraft(atSourceLine: line)
            try expect(changed.policy == "Other, (Node)#" && changed.value == draft.value && changed.options == draft.options, "logical batch policy damaged operands/options")
            for value in ["((DOMAIN,a),(DOMAIN,b))", "((UNKNOWN,a))", "((DOMAIN,a,DIRECT))", "((DOMAIN,a)"] {
                let invalid = SurgeRuleDraft(type: "NOT", value: value, policy: "DIRECT")
                try rejects(&document, "invalid logical condition") { _ = try $0.insertRule(invalid) }
            }
        }

        try test("FINAL and MATCH are unique catch-all aliases") {
            var document = SurgeProfileDocument("[Rule]\nDOMAIN,a,DIRECT\nMATCH,REJECT\n")
            for type in ["FINAL", "MATCH"] {
                let draft = SurgeRuleDraft(type: type, value: "", policy: "DIRECT")
                try rejects(&document, "duplicate \(type)") { _ = try $0.insertRule(draft) }
                try rejects(&document, "conversion duplicates \(type)") { try $0.updateRule(atSourceLine: 2, draft: draft) }
            }
            try document.deleteRules(atSourceLines: [3])
            let line = try document.insertRule(SurgeRuleDraft(type: "FINAL", value: "", policy: "DIRECT"))
            try expect(line == 3, "new catch-all not at end")
        }

        try test("conversion to FINAL moves to the end without losing inline comments") {
            var document = SurgeProfileDocument("[Rule]\nDOMAIN,a,DIRECT # keep\nDOMAIN,b,REJECT\n\n[Unknown]\nx=1\n")
            try document.updateRule(atSourceLine: 2, draft: SurgeRuleDraft(type: "FINAL", value: "", policy: "DIRECT"))
            try expect(document.text == "[Rule]\nDOMAIN,b,REJECT\nFINAL,DIRECT # keep\n\n[Unknown]\nx=1\n", "catch-all move damaged ordering/comments")
            let parsed = try ProfileParser.parse(document.text)
            try expect(parsed.rules.last?.kind == .final && parsed.rules.last?.sourceLine == 3, "moved catch-all source line incorrect")
        }

        try test("every advertised rule type is actually accepted by the parser") {
            for type in SurgeRuleDraft.supportedTypes {
                let value: String
                switch type {
                case "FINAL", "MATCH": value = ""
                case "AND", "OR", "NOT": value = "((DOMAIN,example.com))"
                case "IP-CIDR", "SRC-IP", "SRC-IP-CIDR", "SOURCE-IP-CIDR": value = "192.0.2.0/24"
                case "IP-CIDR6": value = "2001:db8::/32"
                case "SRC-PORT", "SOURCE-PORT", "IN-PORT", "DEST-PORT": value = "80-443"
                case "RULE-SET": value = "https://example.com/rules.list"
                case "PROTOCOL": value = "TCP"
                case "GEOIP": value = "CN"
                case "IP-ASN": value = "13335"
                case "PROCESS-NAME": value = "Safari"
                default: value = "example.com"
                }
                let definition = try SurgeProfileDocument.definition(for: SurgeRuleDraft(type: type, value: value, policy: "DIRECT"))
                let parsed = try ProfileParser.parse("[Rule]\n" + definition + "\n")
                try expect(parsed.rules.count == 1 && parsed.warnings.isEmpty, "advertised type \(type) ignored")
            }
        }
        print("Rule editing smoke tests passed (\(passed) cases)")
    }
}

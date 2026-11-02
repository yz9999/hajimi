import Foundation
import HajimiCore

struct RuleListRow {
    let rule: RoutingRule
    let type: String
    let value: String

    init(_ rule: RoutingRule) {
        self.rule = rule
        let description = Self.description(of: rule.kind)
        type = description.type
        value = description.value
    }

    static func description(of kind: RuleKind) -> (type: String, value: String) {
        switch kind {
        case .domain(let value): return ("DOMAIN", value)
        case .domainSuffix(let value): return ("DOMAIN-SUFFIX", value)
        case .domainKeyword(let value): return ("DOMAIN-KEYWORD", value)
        case .domainWildcard(let value): return ("DOMAIN-WILDCARD", value)
        case .ipCIDR(let value): return (value.contains(":") ? "IP-CIDR6" : "IP-CIDR", value)
        case .destinationPort(let range): return ("DEST-PORT", portRange(range))
        case .sourceIPCIDR(let value): return ("SRC-IP", value)
        case .sourcePort(let range): return ("SRC-PORT", portRange(range))
        case .inboundPort(let range): return ("IN-PORT", portRange(range))
        case .protocolName(let value): return ("PROTOCOL", value)
        case .geoIP(let value): return ("GEOIP", value)
        case .ipASN(let value): return ("IP-ASN", value)
        case .processName(let value): return ("PROCESS-NAME", value)
        case .logicalAnd(let children): return ("AND", logical(children))
        case .logicalOr(let children): return ("OR", logical(children))
        case .logicalNot(let child): return ("NOT", logical([child]))
        case .ruleSet(let reference): return ("RULE-SET", reference.location)
        case .final: return ("FINAL", "匹配其余连接")
        }
    }

    private static func portRange(_ range: ClosedRange<UInt16>) -> String {
        range.lowerBound == range.upperBound
            ? String(range.lowerBound) : "\(range.lowerBound)-\(range.upperBound)"
    }

    private static func logical(_ children: [RuleKind]) -> String {
        children.map { child in
            let description = description(of: child)
            return "\(description.type),\(description.value)"
        }.joined(separator: "; ")
    }
}

struct RuleListSnapshot {
    let profile: Profile
    /// Nil means that a malformed draft is displaying the saved rules read-only.
    let sourceText: String?
    let errorDescription: String?
    let rows: [RuleListRow]
    let rules: [RoutingRule]
    let sourceLines: [Int]
    let totalRuleCount: Int
    let ruleSetCount: Int
    let ruleSetLocations: Set<String>
    let loadedRuleCount: Int
}

/// Confined to the rule-list preparation queue. Parsing and descriptions are
/// cached by draft text; searches only inspect the prepared lowercase fields.
/// This helper never downloads, saves, or changes the running profile.
final class RuleListPreparation {
    private struct Source {
        let text: String
        let revision: Int
        let profile: Profile
        let errorDescription: String?
        let references: [RuleSetReference]
        let index: ListSearchIndex<RuleListRow>
    }

    private var cached: Source?

    func prepare(editorText: String, revision: Int, fallback: Profile, query: String) -> RuleListSnapshot {
        let prepared: Source
        if let cached, cached.text == editorText,
           cached.errorDescription == nil || cached.revision == revision {
            prepared = cached
        } else {
            let profile: Profile
            let errorDescription: String?
            do {
                profile = try ProfileParser.parse(editorText)
                errorDescription = nil
            } catch {
                profile = fallback
                errorDescription = error.localizedDescription
            }
            prepared = Source(
                text: editorText, revision: revision, profile: profile,
                errorDescription: errorDescription, references: profile.ruleSetReferences,
                index: ListSearchIndex(profile.rules.map(RuleListRow.init)) { row in
                    [row.type, row.value, row.rule.policy, String(row.rule.sourceLine)]
                })
            cached = prepared
        }

        var source = prepared.errorDescription == nil ? prepared.profile : fallback
        if prepared.errorDescription == nil {
            // Loaded bodies come from the current runtime, while source lines
            // and rule ordering always belong to this exact editor snapshot.
            source.ruleSetContents = [:]
            for reference in prepared.references {
                if let content = fallback.ruleSetContents[reference.location] {
                    source.ruleSetContents[reference.location] = content
                }
            }
        }
        let indexes = prepared.index.matchingIndexes(query: query)
        let rows = indexes.map { prepared.index.values[$0] }
        return RuleListSnapshot(
            profile: source, sourceText: prepared.errorDescription == nil ? editorText : nil,
            errorDescription: prepared.errorDescription, rows: rows, rules: rows.map(\.rule),
            sourceLines: rows.map { $0.rule.sourceLine }, totalRuleCount: source.rules.count,
            ruleSetCount: prepared.references.count,
            ruleSetLocations: Set(prepared.references.map(\.location)),
            loadedRuleCount: source.ruleSetContents.values.reduce(0) { $0 + $1.count })
    }
}

enum RuleListPreparationSelfTest {
    private struct Failure: LocalizedError {
        let errorDescription: String?
    }

    static func run() throws {
        func require(_ value: Bool, _ message: String) throws {
            if !value { throw Failure(errorDescription: message) }
        }

        var indexed = 0
        let index = ListSearchIndex(["A", "B"]) { value in
            indexed += 1
            return value == "A" ? ["Alpha", "VMess", "Node.Example"] : ["猫咪节点", "SOCKS5", "host"]
        }
        try require(index.matchingIndexes(query: "vmess") == [0]
                    && index.matchingIndexes(query: "node.example") == [0]
                    && index.matchingIndexes(query: "猫咪") == [1]
                    && index.matchingIndexes(query: "alpha vmess").isEmpty
                    && index.matchingIndexes(query: "") == [0, 1]
                    && indexed == 2, "搜索字段缓存、Unicode 或字段边界发生变化")
        try require(ListSearchIndex<String>.normalizedQuery(" \nVMESS \t") == "vmess",
                    "搜索大小写或空白规范化发生变化")

        let request = ListSearchRequest(generation: 2, revision: 7, editorText: "draft", query: "node")
        try require(request.isCurrent(generation: 2, revision: 7, editorText: "draft", query: "node")
                    && !request.isCurrent(generation: 3, revision: 7, editorText: "draft", query: "node")
                    && !request.isCurrent(generation: 2, revision: 8, editorText: "draft", query: "node")
                    && !request.isCurrent(generation: 2, revision: 7, editorText: "edited", query: "node")
                    && !request.isCurrent(generation: 2, revision: 7, editorText: "draft", query: "new"),
                    "旧搜索、相同文本的新保存或新草稿结果可覆盖当前列表")

        let location = "https://example.invalid/rules.list"
        let text = "[Rule]\n# preserved comment\nDOMAIN-SUFFIX,Example.COM,DIRECT\nRULE-SET,\(location),REJECT\nFINAL,DIRECT"
        var runtime = try ProfileParser.parse(text)
        runtime.ruleSetContents[location] = [.domain("loaded.invalid")]
        let preparation = RuleListPreparation()
        let initial = preparation.prepare(editorText: text, revision: 1, fallback: runtime, query: "example.com")
        try require(initial.sourceText == text && initial.errorDescription == nil
                    && initial.sourceLines == [3] && initial.rows.first?.type == "DOMAIN-SUFFIX"
                    && initial.totalRuleCount == 3 && initial.ruleSetCount == 1 && initial.loadedRuleCount == 1,
                    "规则搜索丢失物理行号、描述或当前已加载规则集")
        let draft = "# inserted draft line\n" + text
        let changed = preparation.prepare(editorText: draft, revision: 1, fallback: runtime, query: "example.com")
        try require(changed.sourceLines == [4] && changed.sourceText == draft,
                    "草稿插入行后沿用了旧 sourceLine")
        runtime.ruleSetContents[location] = [.domain("new.invalid"), .domain("another.invalid")]
        let refreshed = preparation.prepare(editorText: draft, revision: 2, fallback: runtime, query: "rule-set")
        try require(refreshed.sourceLines == [5] && refreshed.loadedRuleCount == 2
                    && refreshed.profile.ruleSetContents[location] == runtime.ruleSetContents[location],
                    "缓存草稿没有读取当前版本的已加载规则体")
        let invalid = "[Rule]\nDOMAIN"
        let readOnly = preparation.prepare(editorText: invalid, revision: 2, fallback: runtime, query: "")
        try require(readOnly.sourceText == nil && readOnly.errorDescription != nil
                    && readOnly.rules == runtime.rules, "无效草稿丢失只读回退或被误标为可编辑")
        let replacement = try ProfileParser.parse("[Rule]\nDOMAIN,replacement.invalid,REJECT\nFINAL,DIRECT")
        let replaced = preparation.prepare(editorText: invalid, revision: 3, fallback: replacement, query: "replacement")
        try require(replaced.sourceText == nil && replaced.sourceLines == [2]
                    && replaced.rules.first?.policy == "REJECT",
                    "相同无效草稿跨配置版本保留了旧回退规则")
    }
}

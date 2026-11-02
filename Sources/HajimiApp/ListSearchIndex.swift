import Foundation

/// Searchable text is prepared once per source snapshot. Keeping fields
/// separate preserves the previous substring behavior at field boundaries.
struct ListSearchIndex<Value> {
    let values: [Value]
    private let fields: [[String]]

    init(_ values: [Value], fields: (Value) -> [String]) {
        self.values = values
        self.fields = values.map { fields($0).map { $0.lowercased() } }
    }

    static func normalizedQuery(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    func matchingIndexes(query: String) -> [Int] {
        guard !query.isEmpty else { return Array(values.indices) }
        return values.indices.filter { index in fields[index].contains { $0.contains(query) } }
    }
}

/// Main-queue admission for results prepared without touching AppKit. Text
/// equality alone is insufficient when a save replaces an identical draft.
struct ListSearchRequest {
    let generation: UInt64
    let revision: Int
    let editorText: String?
    let query: String

    func isCurrent(generation: UInt64, revision: Int, editorText: String?, query: String) -> Bool {
        self.generation == generation && self.revision == revision
            && self.editorText == editorText && self.query == query
    }
}

/// Coalesces keystrokes before any expensive preparation is submitted. The
/// generation also revokes work that was already running when input changed.
final class ListSearchDebouncer {
    private(set) var generation: UInt64 = 0
    private var work: DispatchWorkItem?

    func schedule(after delay: TimeInterval = 0.15, _ action: @escaping (UInt64) -> Void) {
        cancel()
        let expected = generation
        let next = DispatchWorkItem { [weak self] in
            guard let self, self.generation == expected else { return }
            self.work = nil
            action(expected)
        }
        work = next
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: next)
    }

    func cancel() {
        generation &+= 1
        work?.cancel()
        work = nil
    }

    deinit { work?.cancel() }
}

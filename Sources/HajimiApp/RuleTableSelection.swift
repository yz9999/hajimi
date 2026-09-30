import Foundation

/// Table indexes are relative to the current search. Mutations always use
/// physical profile line numbers, never the displayed row indexes.
enum RuleTableSelection {
    static func sourceLines(rows: IndexSet, orderedSourceLines: [Int]) -> Set<Int> {
        Set(rows.compactMap { orderedSourceLines.indices.contains($0) ? orderedSourceLines[$0] : nil })
    }

    static func rowIndexes(sourceLines: Set<Int>, orderedSourceLines: [Int]) -> IndexSet {
        IndexSet(orderedSourceLines.indices.filter { sourceLines.contains(orderedSourceLines[$0]) })
    }

    static func retaining(_ selection: Set<Int>, visibleSourceLines: [Int],
                          sourceTextChanged: Bool) -> Set<Int> {
        sourceTextChanged ? [] : selection.intersection(visibleSourceLines)
    }
}

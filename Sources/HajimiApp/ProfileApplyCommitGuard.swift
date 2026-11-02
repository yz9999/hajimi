/// A background RULE-SET result or failed draft recovery may not overwrite
/// edits, a newer save request, or a newer running profile.
struct ProfileApplyCommitGuard {
    let generation: Int
    let revision: Int
    let editorText: String

    func isCurrent(generation: Int, revision: Int, editorText: String) -> Bool {
        self.generation == generation && self.revision == revision
            && self.editorText == editorText
    }

    static func diskTextMatches(expected: String?, actual: String) -> Bool {
        expected.map { $0 == actual } ?? true
    }
}

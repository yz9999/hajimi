import Foundation

@main
struct RuleCommitGuardSmokeTest {
    static func main() {
        let baseline = "[Rule]\nFINAL,DIRECT\n"
        let guardState = ProfileApplyCommitGuard(generation: 4, revision: 2, editorText: baseline)
        func require(_ value: Bool, _ message: String) {
            if !value {
                FileHandle.standardError.write(Data("FAILED: \(message)\n".utf8))
                exit(1)
            }
        }
        require(guardState.isCurrent(generation: 4, revision: 2, editorText: baseline),
                "Current failed request may retain its draft")
        require(!guardState.isCurrent(generation: 5, revision: 2, editorText: baseline),
                "A newer save with identical text must prevent old draft recovery")
        require(!guardState.isCurrent(generation: 4, revision: 3, editorText: baseline),
                "A newer committed profile must prevent old draft recovery")
        require(!guardState.isCurrent(generation: 4, revision: 2, editorText: baseline + "# edited\n"),
                "Newer editor text must prevent old draft recovery")
        require(!ProfileApplyCommitGuard.diskTextMatches(expected: baseline, actual: baseline + "# external\n"),
                "External disk changes must be detected")
        require(ProfileApplyCommitGuard.diskTextMatches(expected: baseline, actual: baseline),
                "Unchanged disk text remains usable")
        require(ProfileApplyCommitGuard.diskTextMatches(expected: nil, actual: baseline),
                "Explicit repair remains possible when the initial file was unreadable")
        print("PASS: rule draft recovery respects generation, revision, editor and disk guards")
    }
}

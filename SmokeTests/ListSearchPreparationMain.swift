import Foundation

/// In-memory checks only: no AppKit application, files, listeners or network.
@main
enum ListSearchPreparationCheck {
    private struct Failure: LocalizedError {
        let errorDescription: String?
    }

    static func main() throws {
        try RuleListPreparationSelfTest.run()
        let debouncer = ListSearchDebouncer()
        var submissions: [UInt64] = []
        for _ in 0..<30 {
            debouncer.schedule(after: 0.01) { submissions.append($0) }
        }
        let expected = debouncer.generation
        let deadline = Date().addingTimeInterval(1)
        while submissions.isEmpty && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        guard submissions == [expected] else {
            throw Failure(errorDescription: "连续输入没有合并为最后一次准备请求")
        }
        debouncer.schedule(after: 0) { submissions.append($0) }
        debouncer.cancel()
        RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        guard submissions == [expected], debouncer.generation != expected else {
            throw Failure(errorDescription: "取消的输入请求仍执行或没有撤销已运行结果")
        }
        print("PASS: cached list search, draft/revision admission, physical rule lines, read-only fallback and input coalescing (in-memory only)")
    }
}

import Foundation

/// Main-queue admission for background updates. Starting a listener alone is
/// insufficient while launch is still restoring the requested tunnel.
struct RuleSetBackgroundRefreshPlan {
    struct Request: Equatable {
        let id = UUID()
        let revision: Int
        let applyGeneration: Int

        func isCurrent(revision: Int, applyGeneration: Int) -> Bool {
            self.revision == revision && self.applyGeneration == applyGeneration
        }
    }

    private(set) var active: Request?
    private(set) var nextCheck = Date.distantPast

    static func isReady(restoringSession: Bool, engineRunning: Bool,
                        enhancedRunning: Bool) -> Bool {
        !restoringSession && (engineRunning || enhancedRunning)
    }

    mutating func begin(ready: Bool, revision: Int, applyGeneration: Int,
                        now: Date = Date()) -> Request? {
        guard ready, active == nil, now >= nextCheck else { return nil }
        let request = Request(revision: revision, applyGeneration: applyGeneration)
        active = request
        return request
    }

    mutating func finish(_ request: Request, retrySoon: Bool = false,
                         now: Date = Date()) {
        guard active == request else { return }
        active = nil
        nextCheck = now.addingTimeInterval(retrySoon ? 5 : 60)
    }
}

enum RuleSetBackgroundRefreshPlanSelfTest {
    private struct Failure: LocalizedError {
        let errorDescription: String?
    }

    static func run() throws {
        func expect(_ value: Bool, _ message: String) throws {
            if !value { throw Failure(errorDescription: message) }
        }
        try expect(!RuleSetBackgroundRefreshPlan.isReady(restoringSession: true,
            engineRunning: true, enhancedRunning: false), "增强模式恢复期间提前启动规则下载")
        try expect(RuleSetBackgroundRefreshPlan.isReady(restoringSession: false,
            engineRunning: false, enhancedRunning: true), "仅增强模式就绪后仍无法更新规则")
        try expect(!RuleSetBackgroundRefreshPlan.isReady(restoringSession: false,
            engineRunning: false, enhancedRunning: false), "无可用入口时启动自动规则下载")

        let now = Date(timeIntervalSince1970: 100)
        var plan = RuleSetBackgroundRefreshPlan()
        try expect(plan.begin(ready: false, revision: 1, applyGeneration: 2, now: now) == nil,
                   "入口未就绪仍准入后台任务")
        guard let first = plan.begin(ready: true, revision: 1, applyGeneration: 2, now: now) else {
            throw Failure(errorDescription: "入口就绪没有准入后台更新")
        }
        try expect(plan.begin(ready: true, revision: 1, applyGeneration: 2, now: now) == nil,
                   "同时启动了两个自动规则更新")
        try expect(first.isCurrent(revision: 1, applyGeneration: 2)
            && !first.isCurrent(revision: 2, applyGeneration: 2)
            && !first.isCurrent(revision: 1, applyGeneration: 3),
                   "后台结果可能覆盖新配置或正在保存的配置")
        plan.finish(first, now: now)
        try expect(plan.begin(ready: true, revision: 1, applyGeneration: 2,
                              now: now.addingTimeInterval(59)) == nil,
                   "成功或失败后没有限制自动检查频率")
        guard let next = plan.begin(ready: true, revision: 2, applyGeneration: 3,
                                     now: now.addingTimeInterval(60)) else {
            throw Failure(errorDescription: "到期后无法再次检查规则")
        }
        plan.finish(first, now: now)
        try expect(plan.active == next, "旧任务完成清除了新任务")
        plan.finish(next, retrySoon: true, now: now)
        try expect(plan.begin(ready: true, revision: 2, applyGeneration: 3,
                              now: now.addingTimeInterval(4)) == nil
            && plan.begin(ready: true, revision: 2, applyGeneration: 3,
                          now: now.addingTimeInterval(5)) != nil,
                   "配置变化后的重试没有遵守短暂退避")
    }
}

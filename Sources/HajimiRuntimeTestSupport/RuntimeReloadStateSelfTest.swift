import Foundation
import HajimiRuntime

/// Public reload contracts with opaque integer baselines and synchronous
/// memory actions only. No Profile, router, platform owner or I/O is used.
enum RuntimeReloadStateSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "重载状态契约自检失败：\(text)" }
    }

    static func run() throws {
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw Failure(text: text) }
        }
        let state = RuntimeReloadState()
        var baseline: Int?, calls = 0, commits = 0
        func commit(_ value: Int) { baseline = value; commits += 1 }
        try require(!state.hasAppliedConfiguration && !state.needsRecovery && baseline == nil,
                    "新拥有者错误继承已应用或失败状态")
        let initial = try state.apply(requiresReload: false, reload: {
            calls += 1
            try require(!state.hasAppliedConfiguration && state.needsRecovery && baseline == nil,
                        "首次外部动作前没有置 dirty")
        }, commit: { commit(1) })
        try require(initial && calls == 1 && commits == 1 && baseline == 1
                    && state.hasAppliedConfiguration && !state.needsRecovery,
                    "没有基线时错误跳过 reload 或未完整提交")
        let unchanged = state.apply(requiresReload: false, reload: { calls += 1 }, commit: { commit(2) })
        try require(!unchanged && calls == 1 && commits == 2 && baseline == 2 && !state.needsRecovery,
                    "不需 reload 的元数据更新触发外部动作或未保存最新基线")
        let changed = try state.apply(requiresReload: true, reload: {
            calls += 1
            try require(state.hasAppliedConfiguration && state.needsRecovery && baseline == 2,
                        "重载期间没有保留已应用基线或未预先置 dirty")
        }, commit: { commit(3) })
        try require(changed && calls == 2 && commits == 3 && baseline == 3 && !state.needsRecovery,
                    "成功 reload 未一次提交新基线")

        do {
            try state.apply(requiresReload: true, reload: {
                calls += 1
                try require(state.needsRecovery && baseline == 3, "失败动作前 dirty/基线错误")
                throw Failure(text: "expected reload failure")
            }, commit: { commit(4) })
            throw Failure(text: "同步 reload 失败没有传播")
        } catch let error as Failure {
            try require(error.text == "expected reload failure", "reload 错误被改变")
        }
        try require(calls == 3 && commits == 3 && baseline == 3
                    && state.hasAppliedConfiguration && state.needsRecovery,
                    "失败提交了未应用基线或清除了恢复要求")
        let rollback = try state.apply(requiresReload: false, reload: {
            calls += 1
            try require(state.needsRecovery && baseline == 3, "rollback 前恢复状态丢失")
        }, commit: { commit(3) })
        try require(rollback && calls == 4 && commits == 4 && baseline == 3 && !state.needsRecovery,
                    "失败后的相同配置 rollback 被当成 no-op")
        state.reset { baseline = nil }
        try require(!state.hasAppliedConfiguration && !state.needsRecovery && baseline == nil,
                    "stop 没有一起清除状态与拥有者基线")
        let restarted = state.apply(requiresReload: false, reload: { calls += 1 }, commit: { commit(3) })
        try require(restarted && calls == 5 && baseline == 3 && !state.needsRecovery,
                    "stop 后同配置重启跳过真实动作")
        state.recordApplied { commit(5) }
        let started = state.apply(requiresReload: false, reload: { calls += 1 }, commit: { commit(5) })
        try require(!started && calls == 5 && baseline == 5
                    && state.hasAppliedConfiguration && !state.needsRecovery,
                    "成功 start 没有建立可复用基线")

        // Reentrant state changes belong to the same queue. The outer action
        // ran, but its old completion must not overwrite a newer lifecycle.
        let beforeSame = commits
        let same = state.apply(requiresReload: true, reload: {
            state.recordApplied { commit(6) }
        }, commit: { commit(6) })
        try require(same && commits == beforeSame + 1 && baseline == 6 && !state.needsRecovery,
                    "真实管理器的重入相同配置提交被拒绝或重复提交")
        let beforeStop = commits
        state.apply(requiresReload: true, reload: { state.reset { baseline = nil } }, commit: { commit(7) })
        try require(commits == beforeStop && baseline == nil
                    && !state.hasAppliedConfiguration && !state.needsRecovery,
                    "旧 reload 回执复活了重入 stop 已清理的基线")
        let beforeStart = commits
        state.apply(requiresReload: true, reload: { state.recordApplied { commit(8) } }, commit: { commit(7) })
        try require(commits == beforeStart + 1 && baseline == 8
                    && state.hasAppliedConfiguration && !state.needsRecovery,
                    "旧 reload 回执覆盖了重入 start 的新基线")
        let beforeNested = commits
        try state.apply(requiresReload: true, reload: {
            let inner = try state.apply(requiresReload: true, reload: {
                try require(state.needsRecovery && baseline == 8, "重入 reload 前 dirty/基线错误")
            }, commit: { commit(9) })
            try require(inner && baseline == 9 && !state.needsRecovery, "内层成功 reload 未提交")
        }, commit: { commit(7) })
        try require(commits == beforeNested + 1 && baseline == 9 && !state.needsRecovery,
                    "外层提交覆盖了内层成功 reload")
        let beforeFailure = commits
        try state.apply(requiresReload: true, reload: {
            do {
                try state.apply(requiresReload: false, reload: {
                    try require(state.needsRecovery, "内层失败动作没有预先置 dirty")
                    throw Failure(text: "expected nested failure")
                }, commit: { commit(10) })
                throw Failure(text: "内层失败没有传播")
            } catch let error as Failure {
                try require(error.text == "expected nested failure", "内层失败被替换")
            }
        }, commit: { commit(7) })
        try require(commits == beforeFailure && baseline == 9
                    && state.hasAppliedConfiguration && state.needsRecovery,
                    "外层成功回执掩盖了内层失败的恢复要求")
        let recovered = state.apply(requiresReload: false, reload: { calls += 1 }, commit: { commit(9) })
        try require(recovered && baseline == 9 && !state.needsRecovery, "重入失败后无法恢复原基线")

        do {
            try state.apply(requiresReload: true, reload: {
                state.recordApplied { commit(11) }
                throw Failure(text: "expected obsolete outer failure")
            }, commit: { commit(7) })
            throw Failure(text: "旧外层错误没有传播")
        } catch let error as Failure {
            try require(error.text == "expected obsolete outer failure", "旧外层错误被替换")
        }
        try require(baseline == 11 && !state.needsRecovery,
                    "旧外层失败改写了后来明确建立的成功基线")
        do {
            try state.apply(requiresReload: true, reload: {
                state.reset { baseline = nil }
                throw Failure(text: "expected stopped outer failure")
            }, commit: { commit(7) })
            throw Failure(text: "停止后的旧外层错误没有传播")
        } catch let error as Failure {
            try require(error.text == "expected stopped outer failure", "停止后旧外层错误被替换")
        }
        try require(baseline == nil && !state.hasAppliedConfiguration && !state.needsRecovery,
                    "停止后的旧外层失败复活了资源基线")

        let other = RuntimeReloadState()
        var otherBaseline: Int?
        state.recordApplied { commit(12) }
        state.apply(requiresReload: true, reload: {
            other.recordApplied { otherBaseline = 99 }
        }, commit: { commit(13) })
        try require(baseline == 13 && !state.needsRecovery && otherBaseline == 99 && !other.needsRecovery,
                    "另一个拥有者的状态变更撤销了当前提交")
        state.reset { baseline = nil }
        try require(otherBaseline == 99 && other.hasAppliedConfiguration && !other.needsRecovery,
                    "一个拥有者 stop 改变了其他拥有者")
        other.apply(requiresReload: true, reload: { state.recordApplied { commit(14) } }, commit: { otherBaseline = 100 })
        try require(baseline == 14 && otherBaseline == 100
                    && state.hasAppliedConfiguration && other.hasAppliedConfiguration,
                    "跨拥有者交叉同步回调破坏独立基线")

        let publishing = RuntimeReloadState()
        var published: Int?, callbackObservedSuccess = false, callbackObservedStop = false
        publishing.recordApplied {
            published = 1
            callbackObservedSuccess = publishing.hasAppliedConfiguration && !publishing.needsRecovery
            publishing.reset { published = nil }
        }
        try require(callbackObservedSuccess && published == nil
                    && !publishing.hasAppliedConfiguration && !publishing.needsRecovery,
                    "成功发布回调中的重入 stop 被旧状态覆盖")
        publishing.reset {
            published = nil
            callbackObservedStop = !publishing.hasAppliedConfiguration && !publishing.needsRecovery
            publishing.recordApplied { published = 2 }
        }
        try require(callbackObservedStop && published == 2
                    && publishing.hasAppliedConfiguration && !publishing.needsRecovery,
                    "清理回调中的重入 start 被旧 stop 覆盖")
        let committed = publishing.apply(requiresReload: true, reload: {}, commit: {
            published = 3
            publishing.apply(requiresReload: true, reload: {}, commit: { published = 4 })
        })
        try require(committed && published == 4 && publishing.hasAppliedConfiguration && !publishing.needsRecovery,
                    "提交回调中的重入新 reload 被外层完成覆盖")
        let skipped = publishing.apply(requiresReload: false, reload: { published = -1 }, commit: {
            published = 4
            publishing.reset { published = nil }
        })
        try require(!skipped && published == nil && !publishing.hasAppliedConfiguration && !publishing.needsRecovery,
                    "无关元数据发布回调中的重入 stop 被 no-op 回执覆盖")
        print("Runtime reload state self-test passed: \(assertions) assertions; dirty-before-action, failure recovery, stop/start and reentrant baseline ownership")
    }
}

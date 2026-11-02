import Foundation
import HajimiRuntime

/// Real public lifecycle transitions, with ownership attestations supplied by
/// memory-only owners. No platform resource, listener, Helper or timer exists.
enum RuntimeLifecycleSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "运行时生命周期自检失败：\(text)" }
    }

    private final class Tickets {
        private let lock = NSLock()
        private var values: [RuntimeLifecycle.Ticket] = []
        func add(_ value: RuntimeLifecycle.Ticket) { lock.lock(); values.append(value); lock.unlock() }
        var all: [RuntimeLifecycle.Ticket] { lock.lock(); defer { lock.unlock() }; return values }
    }

    static func run() throws {
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw Failure(text: text) }
        }
        func reserve(_ owner: RuntimeLifecycle) throws -> RuntimeLifecycle.Ticket {
            guard let ticket = owner.reserve() else { throw Failure(text: "无法保留新启动") }
            return ticket
        }
        let owner = RuntimeLifecycle(), idle = owner.snapshot
        try require(idle.phase == .stopped && !idle.isPresent && !idle.isReady && !idle.startupPending,
                    "空闲快照宣称已拥有或就绪")
        try require(owner.cancel() == nil && owner.snapshot == idle, "空闲停止改变会话或创建票据")
        let first = try reserve(owner), preparing = owner.snapshot
        try require(preparing.phase == .starting && preparing.startupPending && !preparing.isPresent
            && !preparing.isReady && preparing.sessionID != idle.sessionID, "规则准备提前宣称真实资源就绪")
        try require(owner.reserve() == nil && !owner.markRunning(first), "重入启动或无资源回执绕过准入")
        try require(owner.cancel() == first && !owner.isCurrent(first) && owner.snapshot.phase == .stopping,
                    "停止没有同步撤销待完成启动")
        try require(owner.markOwned(first) && owner.snapshot.isPresent && !owner.snapshot.isReady,
                    "取消后实际迟到获取的资源未保留归属")
        owner.release(first)
        try require(!owner.snapshot.startupPending && owner.snapshot.isPresent && owner.reserve() == nil,
                    "startup完成释放了仍待清理的实际资源")
        owner.confirmStopped(first)
        let stopped = owner.snapshot
        try require(stopped.phase == .stopped && !stopped.isPresent && stopped.sessionID != preparing.sessionID,
                    "真实清理确认没有结束原会话")
        owner.markFailure(first); owner.markRecovery(first)
        try require(!owner.markOwned(first) && !owner.markRunning(first) && !owner.confirmHealthy(first),
                    "清理后旧票据仍能获取或恢复资源")
        owner.release(first, preservingFailure: true); owner.confirmStopped(first, preservingFailure: true)
        try require(owner.snapshot == stopped, "cancel→confirmStopped后的迟到失败覆盖了已停止状态")

        let second = try reserve(owner)
        try require(second != first && owner.markOwned(second) && owner.markRunning(second),
                    "重新启动无法完成实际资源与就绪确认")
        let running = owner.snapshot
        owner.release(second)
        try require(owner.snapshot == running && running.isReady && !running.startupPending
            && owner.reserve() == nil, "成功startup释放错误释放了running owner")
        try require(owner.markRunning(second) && owner.snapshot == running, "当前running重复回执错误换代")
        guard let reload = owner.beginReload() else { throw Failure(text: "运行会话无法开始重载") }
        let reloading = owner.snapshot
        try require(reloading.isPresent && !reloading.isReady && reloading.isReloading && reloading.needsRecovery
            && reloading.phase == .starting && reloading.sessionID == running.sessionID && owner.isCurrent(reload),
                    "实际重载没有保留资源并撤销旧就绪许可")
        try require(owner.beginReload() == nil && !owner.markRunning(second) && !owner.confirmHealthy(second)
            && owner.snapshot == reloading, "旧startup或健康回执覆盖了在途reload")
        owner.release(second)
        try require(owner.snapshot == reloading && owner.reserve() == nil, "startup release释放了重载归属")
        try require(owner.finishReload(reload, success: false), "实际重载失败未获得确认")
        let failedReload = owner.snapshot
        try require(failedReload.phase == .failed && failedReload.isPresent && !failedReload.isReady
            && failedReload.needsRecovery && !failedReload.isReloading && !owner.isCurrent(reload), "部分重载失败错误恢复就绪")
        try require(!owner.markRunning(second) && !owner.confirmHealthy(second)
            && owner.snapshot == failedReload, "旧startup/heartbeat消除了重载恢复要求")
        guard let recovery = owner.beginReload() else { throw Failure(text: "失败后无法实际恢复重载") }
        try require(owner.finishReload(recovery, success: true) && owner.snapshot.isReady
            && !owner.snapshot.needsRecovery, "真实恢复重载未恢复准入")
        let recovered = owner.snapshot
        try require(!owner.finishReload(reload, success: true) && !owner.finishReload(recovery, success: false)
            && owner.snapshot == recovered, "旧reload回执覆盖了已恢复配置")
        guard let cancelledReload = owner.beginReload() else { throw Failure(text: "无法保留待取消重载") }
        try require(owner.cancel() == second && owner.snapshot.isPresent && owner.snapshot.phase == .stopping,
                    "停止在途重载丢失真实资源归属")
        let cancelling = owner.snapshot
        try require(!owner.finishReload(cancelledReload, success: true) && !owner.markRunning(second)
            && !owner.confirmHealthy(second) && owner.snapshot == cancelling,
                    "停止后迟到reload/startup/health回执恢复了I/O")
        owner.release(second)
        try require(owner.reserve() == nil && owner.snapshot.isPresent, "取消的running owner未确认清理即替换")
        owner.confirmStopped(second)
        let verified = owner.snapshot
        owner.markFailure(second); owner.markRecovery(second)
        try require(owner.snapshot == verified, "已确认停止后的失败回执改变了状态")

        let foreign = RuntimeLifecycle(), foreignTicket = try reserve(foreign)
        let third = try reserve(owner)
        try require(third != foreignTicket && owner.markOwned(third) && owner.markRunning(third)
            && foreign.markOwned(foreignTicket) && foreign.markRunning(foreignTicket), "独立owner票据或资源相混淆")
        let ownerBefore = owner.snapshot, foreignBefore = foreign.snapshot
        owner.release(foreignTicket); owner.confirmStopped(foreignTicket)
        owner.markFailure(foreignTicket); owner.markRecovery(foreignTicket)
        foreign.release(third); foreign.confirmStopped(third)
        try require(!owner.isCurrent(foreignTicket) && !owner.markOwned(foreignTicket)
            && !owner.markRunning(foreignTicket) && !foreign.confirmHealthy(third)
            && owner.snapshot == ownerBefore && foreign.snapshot == foreignBefore,
                    "交叉owner的start/stop/failure回执改变了当前会话")
        guard let ownerReload = owner.beginReload(), let foreignReload = foreign.beginReload() else {
            throw Failure(text: "独立owner无法保留各自重载")
        }
        let ownerReloading = owner.snapshot, foreignReloading = foreign.snapshot
        try require(!owner.finishReload(foreignReload, success: true)
            && !foreign.finishReload(ownerReload, success: false)
            && !owner.isCurrent(foreignReload) && !foreign.isCurrent(ownerReload)
            && owner.snapshot == ownerReloading && foreign.snapshot == foreignReloading,
                    "外部owner重载回执覆盖了当前reload")
        try require(owner.finishReload(ownerReload, success: true)
            && foreign.finishReload(foreignReload, success: true), "合法独立reload未完成")
        owner.confirmStopped(second); owner.release(first)
        try require(owner.isCurrent(third) && owner.snapshot.isReady && owner.reserve() == nil,
                    "旧session清理释放了替代owner")
        let beforeSameConfigRestart = owner.snapshot
        _ = owner.cancel(); owner.confirmStopped(third)
        let fourth = try reserve(owner)
        try require(owner.markOwned(fourth) && owner.markRunning(fourth)
            && owner.snapshot.sessionID != beforeSameConfigRestart.sessionID,
                    "相同状态与配置停重启复用了原会话身份")
        owner.markFailure(fourth)
        try require(owner.snapshot.phase == .failed && owner.snapshot.isPresent && !owner.snapshot.needsRecovery
            && !owner.snapshot.isReady, "普通监控失败丢失owner或仍可I/O")
        try require(!owner.markRunning(fourth) && owner.confirmHealthy(fourth) && owner.snapshot.isReady,
                    "普通健康恢复混入startup或无法恢复非reload故障")

        let preparationFailure = RuntimeLifecycle(), failedTicket = try reserve(preparationFailure)
        preparationFailure.markFailure(failedTicket)
        try require(!preparationFailure.confirmHealthy(failedTicket), "heartbeat绕过失败startup的就绪门")
        preparationFailure.release(failedTicket, preservingFailure: true)
        let failure = preparationFailure.snapshot
        try require(failure.phase == .failed && !failure.isPresent && !failure.startupPending,
                    "无资源启动失败未显式保留错误")
        preparationFailure.markFailure(failedTicket); preparationFailure.markRecovery(failedTicket)
        try require(preparationFailure.snapshot == failure && !preparationFailure.markOwned(failedTicket),
                    "失败release后的旧票据重新获取写权限")
        let afterFailure = try reserve(preparationFailure)
        try require(preparationFailure.markOwned(afterFailure), "失败后无法开始新会话")
        preparationFailure.markFailure(afterFailure)
        preparationFailure.confirmStopped(afterFailure, preservingFailure: true)
        try require(preparationFailure.snapshot.phase == .failed && !preparationFailure.snapshot.isPresent,
                    "失败资源清理没有显式保留失败状态")

        let blocked = RuntimeLifecycle(), blockedTicket = try reserve(blocked)
        let entered = DispatchSemaphore(value: 0), proceed = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0), late = Tickets()
        DispatchQueue(label: "app.hajimi.runtime-lifecycle-blocked").async {
            entered.signal()
            _ = proceed.wait(timeout: .now() + 2)
            if blocked.markOwned(blockedTicket), blocked.markRunning(blockedTicket) { late.add(blockedTicket) }
            finished.signal()
        }
        try require(entered.wait(timeout: .now() + 2) == .success, "无法固定阻塞准备边界")
        _ = blocked.cancel()
        try require(!blocked.isCurrent(blockedTicket) && blocked.reserve() == nil, "队列阻塞时停止未同步撤销")
        proceed.signal()
        try require(finished.wait(timeout: .now() + 2) == .success && late.all.isEmpty
            && blocked.snapshot.isPresent && !blocked.snapshot.isReady, "迟到实际获取绕过停止或丢失清理归属")
        blocked.release(blockedTicket)
        try require(blocked.reserve() == nil, "迟到startup释放了尚未清理资源")
        blocked.confirmStopped(blockedTicket)
        try require(blocked.reserve() != nil, "确认清理后仍无法启动")

        let concurrent = RuntimeLifecycle(), winners = Tickets()
        DispatchQueue.concurrentPerform(iterations: 64) { _ in
            if let ticket = concurrent.reserve() { winners.add(ticket) }
        }
        try require(winners.all.count == 1, "并发启动产生多个owner")
        guard let winner = winners.all.first else { throw Failure(text: "并发启动没有胜者") }
        DispatchQueue.concurrentPerform(iterations: 64) { _ in _ = concurrent.cancel() }
        try require(!concurrent.isCurrent(winner) && concurrent.markOwned(winner) && concurrent.reserve() == nil,
                    "并发停止允许新启动或丢失迟到资源")
        DispatchQueue.concurrentPerform(iterations: 64) { _ in concurrent.release(winner) }
        try require(concurrent.snapshot.isPresent && concurrent.reserve() == nil,
                    "并发startup release清除了实际owner")
        DispatchQueue.concurrentPerform(iterations: 64) { _ in concurrent.confirmStopped(winner) }
        let concurrentReplacement = try reserve(concurrent)
        let replacementState = concurrent.snapshot
        DispatchQueue.concurrentPerform(iterations: 64) { _ in
            concurrent.confirmStopped(winner); concurrent.markFailure(winner); concurrent.markRecovery(winner)
        }
        try require(concurrent.isCurrent(concurrentReplacement) && concurrent.snapshot == replacementState,
                    "并发旧清理或失败覆盖了替代owner")
        print("Runtime lifecycle self-test passed: \(assertions) assertions; resource ownership, blocked stop, stale/cross-owner receipts, reload recovery and concurrent cleanup")
    }
}

import Foundation
import HajimiRuntime

/// Exercises the public lifecycle reservation without a platform owner,
/// configuration, helper, descriptor, transport or timer.
enum RuntimeStartupIntentSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "启动意图契约自检失败：\(text)" }
    }

    private final class Tickets {
        private let lock = NSLock()
        private var values: [RuntimeStartupIntent.Ticket] = []
        func append(_ ticket: RuntimeStartupIntent.Ticket) { lock.lock(); values.append(ticket); lock.unlock() }
        var all: [RuntimeStartupIntent.Ticket] { lock.lock(); defer { lock.unlock() }; return values }
    }

    private final class Flag {
        private let lock = NSLock()
        private var value = true
        func set(_ next: Bool) { lock.lock(); value = next; lock.unlock() }
        var current: Bool { lock.lock(); defer { lock.unlock() }; return value }
    }

    static func run() throws {
        var assertions = 0
        func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
            assertions += 1
            if !condition() { throw Failure(text: text) }
        }
        let idle = RuntimeStartupIntent()
        try require(idle.cancel() == nil && idle.cancel() == nil, "空闲取消错误创建了资源归属")
        guard let idleTicket = idle.reserve() else { throw Failure(text: "空闲取消后无法开始新一代") }
        try require(idle.isCurrent(idleTicket), "空闲取消状态错误污染新启动")
        idle.release(idleTicket)

        let intent = RuntimeStartupIntent()
        guard let first = intent.reserve() else { throw Failure(text: "无法保留初次启动意图") }
        try require(intent.isCurrent(first) && intent.reserve() == nil, "启动重入产生多个资源归属")
        try require(intent.cancel() == first && !intent.isCurrent(first), "取消未同步撤销当前启动权限")
        try require(intent.cancel() == first && intent.reserve() == nil, "重复取消提前释放了待清理资源")
        intent.release(first)
        try require(!intent.isCurrent(first), "清理完成后旧启动仍有效")
        guard let second = intent.reserve() else { throw Failure(text: "确认清理后不能重新启动") }
        try require(second != first && intent.isCurrent(second), "重启复用了旧启动身份")
        intent.release(first)
        try require(intent.isCurrent(second) && intent.reserve() == nil, "迟到清理释放了替代启动")
        try require(intent.cancel() == second && !intent.isCurrent(second), "新一代取消未绑定当前启动")
        intent.release(first)
        try require(intent.reserve() == nil, "旧一代清理释放了已取消的新一代库存")
        intent.release(second); intent.release(second)
        guard let third = intent.reserve() else { throw Failure(text: "幂等清理后无法再次启动") }
        try require(third != first && third != second && intent.isCurrent(third), "重复清理破坏下一代身份")
        intent.release(third)

        let ownerA = RuntimeStartupIntent(), ownerB = RuntimeStartupIntent()
        guard let ticketA = ownerA.reserve(), let ticketB = ownerB.reserve() else {
            throw Failure(text: "独立拥有者无法保留首次启动")
        }
        try require(ticketA != ticketB, "不同拥有者的同代启动票据发生身份碰撞")
        try require(!ownerA.isCurrent(ticketB) && !ownerB.isCurrent(ticketA), "外部拥有者票据错误获得当前启动权限")
        ownerA.release(ticketB); ownerB.release(ticketA)
        try require(ownerA.isCurrent(ticketA) && ownerB.isCurrent(ticketB)
            && ownerA.reserve() == nil && ownerB.reserve() == nil, "交叉清理释放了其他拥有者的启动库存")
        let cancellationA = ownerA.cancel()
        try require(cancellationA == ticketA && cancellationA != ticketB
            && !ownerA.isCurrent(ticketA) && ownerB.isCurrent(ticketB), "取消回执混淆拥有者或取消影响另一个拥有者")
        ownerA.release(ticketB)
        try require(!ownerA.isCurrent(ticketA) && ownerA.reserve() == nil && ownerB.isCurrent(ticketB),
                    "外部清理回执重置了已取消的启动状态")
        let cancellationB = ownerB.cancel()
        try require(cancellationB == ticketB && cancellationB != cancellationA && !ownerB.isCurrent(ticketB),
                    "独立拥有者取消回执发生身份碰撞")
        ownerB.release(ticketA)
        try require(ownerB.reserve() == nil && !ownerB.isCurrent(ticketB), "外部票据释放了待确认清理的取消库存")
        ownerA.release(ticketA); ownerB.release(ticketB)
        guard let nextA = ownerA.reserve(), let nextB = ownerB.reserve() else {
            throw Failure(text: "独立拥有者清理后不能重新启动")
        }
        try require(nextA != nextB && nextA != ticketA && nextB != ticketB
            && ownerA.isCurrent(nextA) && ownerB.isCurrent(nextB), "同代重启没有保持拥有者和代次身份隔离")
        ownerA.release(nextB); ownerB.release(nextA)
        try require(ownerA.isCurrent(nextA) && ownerB.isCurrent(nextB)
            && ownerA.reserve() == nil && ownerB.reserve() == nil, "新一代交叉清理破坏拥有者隔离")
        ownerA.cancel()
        try require(ownerB.isCurrent(nextB), "拥有者重启后的取消影响了其他核心")
        ownerA.release(nextA); ownerB.release(nextB)

        let blockedIntent = RuntimeStartupIntent()
        guard let blockedTicket = blockedIntent.reserve() else { throw Failure(text: "无法保留阻塞启动") }
        let entered = DispatchSemaphore(value: 0), proceed = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0), mayCommit = Flag()
        defer { proceed.signal() }
        DispatchQueue(label: "app.hajimi.runtime-startup-intent-selftest").async {
            entered.signal()
            _ = proceed.wait(timeout: .now() + 2)
            mayCommit.set(blockedIntent.isCurrent(blockedTicket))
            finished.signal()
        }
        try require(entered.wait(timeout: .now() + 2) == .success, "无法固定待完成启动的阻塞边界")
        try require(blockedIntent.cancel() == blockedTicket && !blockedIntent.isCurrent(blockedTicket),
                    "拥有者队列阻塞时取消不可见")
        try require(blockedIntent.reserve() == nil, "阻塞启动尚未清理即允许替代启动")
        proceed.signal()
        try require(finished.wait(timeout: .now() + 2) == .success && !mayCommit.current,
                    "迟到启动回执仍有提交权限")
        blockedIntent.release(blockedTicket)
        guard let afterBlocked = blockedIntent.reserve() else { throw Failure(text: "阻塞启动清理后不能恢复") }
        blockedIntent.release(blockedTicket)
        try require(blockedIntent.isCurrent(afterBlocked), "迟到阻塞回执破坏恢复后的新启动")
        blockedIntent.release(afterBlocked)

        let concurrent = RuntimeStartupIntent(), winners = Tickets(), workers = DispatchGroup()
        for _ in 0..<64 {
            workers.enter()
            DispatchQueue.global().async {
                if let ticket = concurrent.reserve() { winners.append(ticket) }
                workers.leave()
            }
        }
        try require(workers.wait(timeout: .now() + 2) == .success, "并发保留意图未及时完成")
        let reserved = winners.all
        try require(reserved.count == 1, "64个并发启动获得多个资源归属")
        guard let winner = reserved.first else { throw Failure(text: "并发启动没有获准者") }
        try require(concurrent.isCurrent(winner), "并发获准者没有当前代次权限")
        DispatchQueue.concurrentPerform(iterations: 64) { _ in _ = concurrent.cancel() }
        try require(!concurrent.isCurrent(winner) && concurrent.reserve() == nil,
                    "并发取消未撤销权限或提前释放资源归属")
        DispatchQueue.concurrentPerform(iterations: 64) { _ in concurrent.release(winner) }
        guard let replacement = concurrent.reserve() else { throw Failure(text: "并发清理后无法重新保留意图") }
        try require(replacement != winner && concurrent.isCurrent(replacement), "并发清理后身份未换代")
        DispatchQueue.concurrentPerform(iterations: 64) { _ in concurrent.release(winner) }
        try require(concurrent.isCurrent(replacement) && concurrent.reserve() == nil,
                    "并发旧清理破坏替代启动的资源归属")
        concurrent.release(replacement)
        print("Runtime startup intent self-test passed: \(assertions) assertions; owner-bound reservation, blocked cancellation, cleanup acknowledgement, stale completion and concurrent ownership")
    }
}

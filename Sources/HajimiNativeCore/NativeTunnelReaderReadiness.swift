import Foundation

/// A registration ACK is valid only for the current descriptor generation.
/// Invalidation wakes waiters immediately; a late libdispatch callback from
/// a cancelled source cannot make its replacement appear ready.
final class NativeTunnelReaderReadiness {
    private let condition = NSCondition()
    private var generation: UInt64 = 0
    private var active = false
    private var ready = false

    func begin() -> UInt64 {
        condition.lock(); defer { condition.unlock() }
        generation &+= 1
        active = true
        ready = false
        condition.broadcast()
        return generation
    }

    func confirm(_ epoch: UInt64) {
        condition.lock(); defer { condition.unlock() }
        guard active, epoch == generation else { return }
        ready = true
        condition.broadcast()
    }

    func invalidate() {
        condition.lock(); defer { condition.unlock() }
        active = false
        ready = false
        generation &+= 1
        condition.broadcast()
    }

    func wait(timeout: TimeInterval) throws {
        guard timeout.isFinite, timeout >= 0 else {
            throw NativeTunnelError.utun("无效的收包就绪等待期限")
        }
        condition.lock(); defer { condition.unlock() }
        let epoch = generation
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while active, epoch == generation, !ready {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else {
                throw NativeTunnelError.utun("等待 utun 收包就绪超时")
            }
            _ = condition.wait(until: Date().addingTimeInterval(min(remaining, 0.1)))
        }
        guard active, epoch == generation, ready else {
            throw NativeTunnelError.utun("utun 收包启动已取消")
        }
    }
}

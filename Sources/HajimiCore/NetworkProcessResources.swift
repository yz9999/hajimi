import Foundation
import Darwin

/// Finder/launchd may give the GUI a 256-descriptor soft limit while a
/// terminal-built fixture inherits a much larger one. A proxied TLS stream
/// owns the node socket plus two local TLS bridge sockets (and a transient
/// listener), so the existing bounded DNS concurrency can exhaust 256 even
/// without leaking a socket. Prepare only this process, never launchctl or
/// the system hard limit; all connection/query admission bounds still apply.
public enum NetworkProcessResources {
    public struct OpenFilePreparation {
        public let previous: UInt64?
        public let current: UInt64?
        public let changed: Bool
        public var isAdequate: Bool { current.map { $0 >= recommendedOpenFiles } ?? false }
    }

    public static let recommendedOpenFiles: UInt64 = 4096
    private static let lock = NSLock()

    @discardableResult
    public static func prepareOpenFileLimit() -> OpenFilePreparation {
        lock.lock(); defer { lock.unlock() }
        return prepare(read: {
            var limit = rlimit()
            return getrlimit(RLIMIT_NOFILE, &limit) == 0 ? limit : nil
        }, write: { value in
            var limit = value
            return setrlimit(RLIMIT_NOFILE, &limit) == 0
        })
    }

    // Injection is internal and used only by the pure-memory self-test.
    static func prepare(read: () -> rlimit?, write: (rlimit) -> Bool) -> OpenFilePreparation {
        guard var limit = read() else {
            return OpenFilePreparation(previous: nil, current: nil, changed: false)
        }
        let previous = UInt64(limit.rlim_cur)
        let target = min(rlim_t(recommendedOpenFiles), limit.rlim_max)
        guard limit.rlim_cur < target else {
            return OpenFilePreparation(previous: previous, current: previous, changed: false)
        }
        limit.rlim_cur = target
        guard write(limit) else {
            return OpenFilePreparation(previous: previous, current: previous, changed: false)
        }
        return OpenFilePreparation(previous: previous,
                                   current: read().map { UInt64($0.rlim_cur) } ?? UInt64(target),
                                   changed: true)
    }
}

/// No real limit changes, sockets, files, helper or system state are used.
public enum NetworkProcessResourcesSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "网络进程资源自检失败：\(text)" }
    }
    private static func require(_ value: Bool, _ text: String) throws {
        if !value { throw Failure(text: text) }
    }
    public static func run() throws {
        for (soft, hard, expected, changed) in [
            (256, 65536, 4096, true), (256, 1024, 1024, true),
            (256, 256, 256, false), (4096, 65536, 4096, false),
            (16384, 65536, 16384, false)
        ] {
            var state = rlimit(rlim_cur: rlim_t(soft), rlim_max: rlim_t(hard))
            var writes = 0
            let result = NetworkProcessResources.prepare(read: { state }, write: {
                writes += 1; state = $0; return true
            })
            try require(result.previous == UInt64(soft) && result.current == UInt64(expected)
                        && result.changed == changed && writes == (changed ? 1 : 0)
                        && state.rlim_max == rlim_t(hard)
                        && result.isAdequate == (expected >= 4096),
                        "软限额准备降低了已有预算、修改了硬限额或错误报告结果")
            let again = NetworkProcessResources.prepare(read: { state }, write: {
                writes += 1; state = $0; return true
            })
            try require(!again.changed && writes == (changed ? 1 : 0), "重复准备仍写限额")
        }
        var writes = 0
        let denied = NetworkProcessResources.prepare(
            read: { rlimit(rlim_cur: 256, rlim_max: 65536) },
            write: { _ in writes += 1; return false })
        try require(!denied.changed && !denied.isAdequate && denied.current == 256 && writes == 1,
                    "设置失败仍声称资源已准备")
        let unavailable = NetworkProcessResources.prepare(read: { nil }, write: { _ in
            writes += 1; return true
        })
        try require(unavailable.previous == nil && unavailable.current == nil
                    && !unavailable.changed && !unavailable.isAdequate && writes == 1,
                    "读取失败后仍修改了资源上限")
        // Darwin's RLIM_INFINITY macro is not imported by Swift.
        let infinity = rlim_t(Int64.max)
        var unlimited = rlimit(rlim_cur: 256, rlim_max: infinity)
        let raised = NetworkProcessResources.prepare(read: { unlimited }, write: {
            unlimited = $0; return true
        })
        try require(raised.current == 4096 && unlimited.rlim_max == infinity,
                    "无限硬限额被修改或没有保持有限软预算")
    }
}

import Foundation

/// A cancellable operation whose underlying handle may arrive after its owner
/// has stopped. Cancellation is synchronous and handlers never run under lock.
public final class RuntimeOperation {
    private let lock = NSLock()
    private var cancelled = false
    private var installed = false
    private var cancellation: (() -> Void)?

    public init() {}

    public var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    public func installCancellation(_ value: @escaping () -> Void) {
        lock.lock()
        let cancelNow = cancelled || installed
        if !cancelNow {
            installed = true
            cancellation = value
        }
        lock.unlock()
        if cancelNow { value() }
    }

    public func cancel() {
        lock.lock()
        guard !cancelled else {
            lock.unlock()
            return
        }
        cancelled = true
        let value = cancellation
        cancellation = nil
        lock.unlock()
        value?()
    }

    deinit { cancel() }
}

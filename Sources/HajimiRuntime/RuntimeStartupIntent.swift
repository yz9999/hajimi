import Foundation

/// A startup reservation remains owned until its original resources have
/// finished cleanup. Cancellation is visible independently of an owner's
/// serial queue; it revokes completion authority without releasing ownership.
/// This contract owns no router, helper session, descriptor or platform state.
public final class RuntimeStartupIntent {
    /// Opaque identity for one generation of one intent owner.
    public typealias Ticket = RuntimeLifecycle.Ticket
    private let lifecycle = RuntimeLifecycle()

    public init() {}

    public func reserve() -> Ticket? {
        lifecycle.reserve()
    }

    @discardableResult
    public func cancel() -> Ticket? {
        lifecycle.cancel()
    }

    public func isCurrent(_ ticket: Ticket) -> Bool {
        lifecycle.isCurrent(ticket)
    }

    public func release(_ ticket: Ticket) {
        lifecycle.release(ticket)
    }
}

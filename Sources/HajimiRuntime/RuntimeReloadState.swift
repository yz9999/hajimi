import Foundation

/// Synchronous reload bookkeeping for one serial owner. All access, including
/// reads and reentrant calls, must stay on that owner's queue. This type does
/// not synchronize callers, retain configuration or own external resources.
public final class RuntimeReloadState {
    public private(set) var hasAppliedConfiguration = false
    public private(set) var needsRecovery = false
    private var revision = UUID()

    public init() {}

    /// The owner decides whether configuration changed. Missing or dirty
    /// baselines always require reload. Mark dirty before external work; a
    /// thrown error propagates without committing a successful baseline.
    ///
    /// Reload may synchronously reenter this state. A newer apply, successful
    /// start or stop supersedes the outer attempt, whose late return cannot
    /// commit over it. The return value reports whether reload was invoked,
    /// including an attempt superseded while that closure was executing.
    /// Commit must only publish the owner's baseline synchronously; it cannot
    /// throw and is never retained. External resource ordering stays with the
    /// owner, and supersession alone does not cancel external work.
    @discardableResult
    public func apply(requiresReload: Bool, reload: () throws -> Void,
                      commit: () -> Void) rethrows -> Bool {
        guard requiresReload || !hasAppliedConfiguration || needsRecovery else {
            recordApplied(commit: commit)
            return false
        }
        let ticket = UUID()
        revision = ticket
        needsRecovery = true
        try reload()
        if revision == ticket { recordApplied(commit: commit) }
        return true
    }

    /// A successful start, recovery or irrelevant metadata change establishes
    /// the baseline and invalidates any older in-progress reload's commit.
    public func recordApplied(commit: () -> Void) {
        revision = UUID()
        hasAppliedConfiguration = true
        needsRecovery = false
        commit()
    }

    /// Stop discards the baseline, so a same-configuration start cannot skip
    /// external work. Publish the cleared baseline on the same owner queue.
    public func reset(clear: () -> Void) {
        revision = UUID()
        hasAppliedConfiguration = false
        needsRecovery = false
        clear()
    }
}

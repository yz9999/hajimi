import HajimiRuntime

/// Cancellation must be visible while the manager's serial queue is inside
/// a synchronous Helper call. A reservation also fences late completions
/// from a cancelled start and prevents overlapping ownership inventories.
typealias EnhancedStartupIntent = RuntimeLifecycle

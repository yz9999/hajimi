import Foundation

/// A full collection reload is needed only when item identity/order changes.
/// Repeated updates to the same card collapse to one index path.
struct PolicyListRefreshPlan {
    let requiresReload: Bool
    let paths: Set<IndexPath>

    init(previousOrder: [String]?, order: [String], changedNames: Set<String>) {
        requiresReload = previousOrder != order
        paths = Set(order.enumerated().compactMap { index, name in
            changedNames.contains(name) ? IndexPath(indexes: [0, index]) : nil
        })
    }
}

/// Profile epochs also replace metadata for filtered-out cards. Updating only
/// the visible list would retain removed definitions (including credentials)
/// indefinitely when a search still returns the same empty result.
enum PolicyCardMetadataPruning {
    static func apply<Value: Equatable>(metadata: [String: Value], dirty: Set<String>,
                                       current: [String: Value], order: [String])
        -> (metadata: [String: Value], dirty: Set<String>, identities: Set<String>) {
        let identities = Set(order).intersection(current.keys)
        let changed = Set(identities.filter { metadata[$0] != current[$0] })
        return (current.filter { identities.contains($0.key) },
                dirty.intersection(identities).union(changed), identities)
    }
}

/// Maintains only a bounded number of submitted requests, even if a profile
/// contains thousands of nodes. The names themselves are profile data, not
/// queued scheduler closures or open connections.
struct NodeProbeBatchCursor {
    let id = UUID()
    let names: [String]
    let window: Int
    private(set) var nextIndex = 0
    private(set) var outstanding = Set<UUID>()

    init(names: [String], window: Int = 32) {
        self.names = names; self.window = max(1, window)
    }

    mutating func takeNext() -> (id: UUID, name: String)? {
        guard outstanding.count < window, nextIndex < names.count else { return nil }
        let requestID = UUID()
        let name = names[nextIndex]
        nextIndex += 1
        outstanding.insert(requestID)
        return (requestID, name)
    }

    mutating func finish(_ id: UUID) { outstanding.remove(id) }
    var isComplete: Bool { nextIndex == names.count && outstanding.isEmpty }
}

enum PolicyRefreshPlanSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "节点 UI 更新自检失败：\(text)" }
    }

    static func run() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        let order = ["A", "B", "C"]
        let partial = PolicyListRefreshPlan(previousOrder: order, order: order,
                                            changedNames: ["B", "removed"])
        try require(!partial.requiresReload && partial.paths == [IndexPath(indexes: [0, 1])],
                    "普通选择变化触发全量刷新或错误索引")
        try require(PolicyListRefreshPlan(previousOrder: nil, order: order, changedNames: []).requiresReload,
                    "首次加载未完整初始化")
        try require(PolicyListRefreshPlan(previousOrder: order, order: ["B", "A", "C"],
                                         changedNames: []).requiresReload, "顺序变化未完整刷新")
        try require(PolicyListRefreshPlan(previousOrder: order, order: ["A", "B"],
                                         changedNames: []).requiresReload, "删除节点未完整刷新")
        var batch = NodeProbeBatchCursor(names: (0..<2_000).map(String.init), window: 32)
        var started = 0
        while let _ = batch.takeNext() { started += 1 }
        try require(started == 32 && batch.outstanding.count == 32, "大订阅一次提交了全部测速")
        let first = batch.outstanding.first!
        batch.finish(first); batch.finish(first)
        try require(batch.takeNext() != nil && batch.outstanding.count == 32,
                    "完成窗口未补充任务或重复完成破坏窗口")
        while !batch.isComplete {
            for id in batch.outstanding { batch.finish(id) }
            while let _ = batch.takeNext() {}
            try require(batch.outstanding.count <= 32, "滑动窗口超过上限")
        }
        try require(batch.nextIndex == 2_000 && batch.isComplete, "大订阅测速窗口丢失任务")
        let pruned = PolicyCardMetadataPruning.apply(metadata: ["removed": "old-secret", "valid": "old-definition"],
            dirty: ["removed", "valid"], current: ["valid": "new-definition", "not-in-order": "hidden-secret"],
            order: ["valid"])
        try require(pruned.metadata == ["valid": "new-definition"] && pruned.dirty == ["valid"]
                    && pruned.identities == ["valid"], "空搜索跨 profile epoch 保留了旧隐藏定义或失效 dirty 名称")
        let retained = PolicyCardMetadataPruning.apply(metadata: ["valid": "same"], dirty: ["valid"],
                                                       current: ["valid": "same"], order: ["valid"])
        try require(retained.dirty == ["valid"], "剪枝错误清空了仍有效的待刷新卡片")
    }
}

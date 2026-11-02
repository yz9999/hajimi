import Foundation
import HajimiRuntime

/// The original backend and pending-request ownership regressions, exercised
/// through the public runtime module rather than an App implementation copy.
public enum RuntimeCoordinatorSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "网络诊断后端自检失败：\(text)" }
    }

    public static func run() throws {
        try runBackendChecks()
        try runCoordinatorChecks()
        try RuntimeStartupIntentSelfTest.run()
        try RuntimeReloadStateSelfTest.run()
        try RuntimeLifecycleSelfTest.run()
    }

    private static func runBackendChecks() throws {
        var assertions = 0
        func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
            assertions += 1
            if !value() { throw Failure(text: message) }
        }
        for (enhanced, listener, expected) in [
            (false, false, NetworkRuntimeBackend.unavailable),
            (false, true, .listener),
            (true, false, .enhanced),
            (true, true, .enhanced)
        ] {
            let backend = NetworkRuntimeBackend.select(enhancedModeActive: enhanced, listenerRunning: listener)
            try require(backend == expected, "后端选择错误 enhanced=\(enhanced) listener=\(listener)")
            var calls: [NetworkRuntimeBackend] = []
            let selected = backend.start(enhanced: { calls.append(.enhanced); return NetworkRuntimeBackend.enhanced },
                listener: { calls.append(.listener); return NetworkRuntimeBackend.listener },
                unavailable: { calls.append(.unavailable); return NetworkRuntimeBackend.unavailable })
            try require(calls == [expected] && selected == expected, "检测启动走了错误或多个后端")
        }
        try require(NetworkRuntimeBackend.enhanced.displayName == "增强模式"
            && NetworkRuntimeBackend.listener.displayName == "HTTP／SOCKS代理"
            && NetworkRuntimeBackend.unavailable.displayName == "未启动", "后端显示名称错误")
        var rejectedCalls: [NetworkRuntimeBackend] = []
        let rejected: Bool = NetworkRuntimeBackend.select(enhancedModeActive: true, listenerRunning: true).start(
            enhanced: { rejectedCalls.append(.enhanced); return false },
            listener: { rejectedCalls.append(.listener); return true },
            unavailable: { rejectedCalls.append(.unavailable); return true })
        try require(!rejected && rejectedCalls == [.enhanced], "增强会话未就绪时错误回退至监听器")

        let pending = RuntimeOperation()
        try require(!pending.isCancelled, "新请求已取消")
        pending.cancel(); pending.cancel()
        try require(pending.isCancelled, "pending取消未同步撤销准入")
        var lateCancellations = 0
        pending.installCancellation { lateCancellations += 1 }
        pending.cancel()
        try require(lateCancellations == 1, "取消后迟到句柄未恰好清理一次")

        let attached = RuntimeOperation()
        var originalCancellations = 0, duplicateCancellations = 0
        attached.installCancellation { originalCancellations += 1 }
        try require(originalCancellations == 0 && !attached.isCancelled, "安装有效句柄时提前取消")
        attached.installCancellation { duplicateCancellations += 1 }
        try require(duplicateCancellations == 1 && originalCancellations == 0 && !attached.isCancelled,
                    "重复安装替换有效句柄或未清理多余句柄")
        attached.cancel(); attached.cancel()
        try require(attached.isCancelled && originalCancellations == 1 && duplicateCancellations == 1,
                    "重复取消丢失或重复调用清理")
        var afterCancellation = 0
        attached.installCancellation { afterCancellation += 1 }
        try require(afterCancellation == 1 && originalCancellations == 1, "取消后重复安装未立即清理")

        let reentrant = RuntimeOperation()
        var observedCancelled = false, reentrantCalls = 0, nestedCalls = 0
        reentrant.installCancellation {
            reentrantCalls += 1
            observedCancelled = reentrant.isCancelled
            reentrant.cancel()
            reentrant.installCancellation { nestedCalls += 1; _ = reentrant.isCancelled }
        }
        reentrant.cancel()
        try require(observedCancelled && reentrantCalls == 1 && nestedCalls == 1,
                    "清理回调仍持有锁或重入导致重复清理")

        var owned: RuntimeOperation? = RuntimeOperation()
        weak var weakOwned = owned
        var droppedCancellations = 0
        owned?.installCancellation { droppedCancellations += 1 }
        owned = nil
        try require(weakOwned == nil && droppedCancellations == 1, "释放请求所有权未清理已安装句柄")
        var alreadyCancelled: RuntimeOperation? = RuntimeOperation()
        var dropAfterCancel = 0
        alreadyCancelled?.installCancellation { dropAfterCancel += 1 }
        alreadyCancelled?.cancel(); alreadyCancelled = nil
        try require(dropAfterCancel == 1, "释放已取消请求重复执行清理")

        final class Counter {
            private let lock = NSLock()
            private var count = 0
            func increment() { lock.lock(); count += 1; lock.unlock() }
            var value: Int { lock.lock(); defer { lock.unlock() }; return count }
        }
        for _ in 0..<64 {
            let request = RuntimeOperation(), counter = Counter(), workers = DispatchGroup()
            workers.enter()
            DispatchQueue.global().async {
                request.installCancellation { counter.increment() }
                workers.leave()
            }
            workers.enter()
            DispatchQueue.global().async { request.cancel(); workers.leave() }
            try require(workers.wait(timeout: .now() + 2) == .success, "并发安装与取消未及时完成")
            request.cancel()
            try require(request.isCancelled && counter.value == 1, "安装/取消竞态丢失或重复执行清理")
        }
        let concurrent = RuntimeOperation(), counter = Counter()
        DispatchQueue.concurrentPerform(iterations: 64) { _ in
            concurrent.installCancellation { counter.increment() }
        }
        try require(!concurrent.isCancelled && counter.value == 63, "并发重复安装未只保留一个有效句柄")
        DispatchQueue.concurrentPerform(iterations: 64) { _ in concurrent.cancel() }
        try require(concurrent.isCancelled && counter.value == 64, "并发取消未恰好清理全部句柄")
        print("Network diagnostics backend self-test passed: \(assertions) assertions; public runtime selection, pending cancellation, reentrancy and ownership")
    }

    private final class Counter {
        private let lock = NSLock()
        private var count = 0
        func increment() { lock.lock(); count += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    }

    private final class Values {
        private let lock = NSLock()
        private var items: [String] = []
        func add(_ value: String) { lock.lock(); items.append(value); lock.unlock() }
        var all: [String] { lock.lock(); defer { lock.unlock() }; return items }
    }

    private final class Emitter {
        private let lock = NSLock()
        private var callback: ((String) -> Void)?
        func install(_ value: @escaping (String) -> Void) { lock.lock(); callback = value; lock.unlock() }
        func send(_ value: String) {
            lock.lock(); let callback = callback; lock.unlock()
            callback?(value)
        }
    }

    private final class OperationBox {
        private let lock = NSLock()
        private var stored: RuntimeOperation?
        func set(_ value: RuntimeOperation) { lock.lock(); stored = value; lock.unlock() }
        var value: RuntimeOperation? { lock.lock(); defer { lock.unlock() }; return stored }
    }

    private static func runCoordinatorChecks() throws {
        var assertions = 0
        func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
            assertions += 1
            if !value() { throw Failure(text: message) }
        }
        func endpoint(_ phase: RuntimePhase, present: Bool = true, interface: String? = "en0") -> RuntimeEndpointState {
            RuntimeEndpointState(phase: phase, isPresent: present, boundInterfaceName: interface)
        }
        let stopped = endpoint(.stopped, present: false, interface: nil)
        let running = endpoint(.running)
        let initialCoordinator = RuntimeCoordinator()
        let initial = initialCoordinator.snapshot
        let initialLease = initialCoordinator.acquireSession()
        let secondInitialLease = initialCoordinator.acquireSession()
        try require(initial.backend == .unavailable && !initial.ready, "初始协调器错误宣称核心就绪")
        try require(initialLease.isCurrent && !initialLease.isReady && initialLease.backend == .unavailable,
                    "未启动会话未保留明确报告资格或错误获准IO")
        try require(initialLease.id != secondInitialLease.id && initialLease.snapshot.sessionID == secondInitialLease.snapshot.sessionID
                    && initialLease.generation == initial.revision, "请求身份与核心会话代次被混用")
        withExtendedLifetime(initialCoordinator) {}

        let scenarios: [(String, RuntimeEndpointState, RuntimeEndpointState, NetworkRuntimeBackend, Bool)] = [
            ("stopped", stopped, stopped, .unavailable, false),
            ("listener-only", running, stopped, .listener, true),
            ("enhanced-only", stopped, running, .enhanced, true),
            ("both", running, running, .enhanced, true),
            ("preparing-retained", running, endpoint(.starting), .enhanced, false),
            ("recovery-retained", running, endpoint(.failed), .enhanced, false),
            ("stopping-retained", running, endpoint(.stopping), .enhanced, false),
            ("stopped-retained", running, endpoint(.stopped), .enhanced, false),
            ("preparing-unowned", running, endpoint(.starting, present: false), .listener, true),
            ("preparing-no-listener", stopped, endpoint(.starting, present: false), .unavailable, false),
            ("listener-preparing", endpoint(.starting), stopped, .listener, false),
            ("listener-failed", endpoint(.failed), stopped, .listener, false),
            ("listener-failed-unowned", endpoint(.failed, present: false), stopped, .unavailable, false)
        ]
        for (name, listener, enhanced, expectedBackend, ready) in scenarios {
            let coordinator = RuntimeCoordinator()
            let snapshot = coordinator.update(listener: listener, enhanced: enhanced, configurationRevision: 42)
            let lease = coordinator.acquireSession()
            try require(snapshot.backend == expectedBackend && snapshot.ready == ready, "\(name) 后端或就绪状态错误")
            let selectedEndpoint = expectedBackend == .enhanced ? enhanced : listener
            try require(snapshot.phase == selectedEndpoint.phase && snapshot.boundInterfaceName == selectedEndpoint.boundInterfaceName,
                        "\(name) 未保留所选核心或无归属时监听器的阶段与接口信息")
            try require(lease.backend == expectedBackend && lease.isCurrent && lease.isReady == ready
                && lease.snapshot.sessionID == snapshot.sessionID && lease.generation == snapshot.revision,
                "\(name) 会话许可与快照不一致")
            var called: [NetworkRuntimeBackend] = []
            let values = Values()
            let operation = coordinator.start(onUpdate: values.add) { session, update in
                called.append(session.backend)
                session.backend.start(enhanced: { update(session.isReady ? "enhanced-ready" : "enhanced-pending") },
                    listener: { update(session.isReady ? "listener-ready" : "listener-pending") },
                    unavailable: { update("unavailable") })
                return RuntimeOperation()
            }
            let expectedValue = expectedBackend == .unavailable ? "unavailable"
                : expectedBackend.rawValue + (ready ? "-ready" : "-pending")
            try require(called == [expectedBackend] && values.all == [expectedValue],
                        "\(name) 未通过实际协调入口分派到唯一当前核心")
            operation.cancel()
        }

        let restartCoordinator = RuntimeCoordinator()
        let first = restartCoordinator.update(listener: running, enhanced: stopped, configurationRevision: 7)
        let firstLease = restartCoordinator.acquireSession()
        let restartValues = Values(), restartEmitter = Emitter(), restartCancelled = Counter()
        let firstOperation = restartCoordinator.start(onUpdate: restartValues.add) { _, update in
            restartEmitter.install(update)
            let inner = RuntimeOperation()
            inner.installCancellation { restartCancelled.increment() }
            return inner
        }
        restartEmitter.send("before-stop")
        let duplicate = restartCoordinator.update(listener: running, enhanced: stopped, configurationRevision: 7)
        try require(duplicate.revision == first.revision && duplicate.sessionID == first.sessionID
            && firstLease.isCurrent && !firstOperation.isCancelled && restartCancelled.value == 0,
            "相同配置/状态通知无故换代或取消活跃检查")
        _ = restartCoordinator.update(listener: stopped, enhanced: stopped, configurationRevision: 7)
        try require(!firstLease.isCurrent && !firstLease.isReady && firstOperation.isCancelled && restartCancelled.value == 1,
                    "停止核心未撤销旧会话与活跃检查")
        let restarted = restartCoordinator.update(listener: running, enhanced: stopped, configurationRevision: 7)
        restartEmitter.send("late-before-restart")
        try require(restarted.sessionID != first.sessionID && restarted.revision != first.revision
            && restartValues.all == ["before-stop"] && !firstLease.isCurrent,
            "相同配置停重启复用了旧会话或接收旧回调")
        try require(restartCoordinator.acquireSession().isReady, "重启后的新会话未就绪")
        withExtendedLifetime(restartCoordinator) {}

        for change in ["configuration", "physical-interface"] {
            let coordinator = RuntimeCoordinator()
            let before = coordinator.update(listener: stopped, enhanced: running, configurationRevision: 8)
            let lease = coordinator.acquireSession(), cancelled = Counter(), values = Values(), emitter = Emitter()
            let active = coordinator.start(onUpdate: values.add) { _, update in
                emitter.install(update)
                let inner = RuntimeOperation()
                inner.installCancellation { cancelled.increment() }
                return inner
            }
            emitter.send("before-change")
            let after = coordinator.update(listener: stopped,
                enhanced: change == "physical-interface" ? endpoint(.running, interface: "en1") : running,
                configurationRevision: change == "configuration" ? 9 : 8)
            emitter.send("after-change")
            try require(after.revision != before.revision && after.sessionID != before.sessionID
                && !lease.isCurrent && !lease.isReady && active.isCancelled && cancelled.value == 1,
                "\(change) 改变未同步撤销会话并取消活跃检查")
            try require(values.all == ["before-change"] && coordinator.acquireSession().isReady,
                        "\(change) 改变接收旧结果或未提供新会话")
            withExtendedLifetime(coordinator) {}
        }

        let explicit = RuntimeCoordinator()
        let explicitBefore = explicit.update(listener: stopped, enhanced: running, configurationRevision: 10)
        let explicitLease = explicit.acquireSession(), explicitCancelled = Counter()
        let explicitOperation = explicit.start(onUpdate: { (_: String) in }) { _, _ in
            let inner = RuntimeOperation()
            inner.installCancellation { explicitCancelled.increment() }
            return inner
        }
        let advanced = explicit.advanceRevision()
        try require(advanced.backend == explicitBefore.backend && advanced.ready == explicitBefore.ready
            && advanced.boundInterfaceName == explicitBefore.boundInterfaceName
            && advanced.revision != explicitBefore.revision && advanced.sessionID != explicitBefore.sessionID,
            "显式核心换代未保留配置并分离会话身份")
        try require(!explicitLease.isCurrent && explicitOperation.isCancelled && explicitCancelled.value == 1,
                    "显式换代未撤销旧许可与活跃检查")

        let pendingCoordinator = RuntimeCoordinator()
        _ = pendingCoordinator.update(listener: stopped, enhanced: running, configurationRevision: 11)
        let lateInner = RuntimeOperation(), lateCancelled = Counter(), pendingValues = Values(), pendingEmitter = Emitter()
        let pending = pendingCoordinator.start(onUpdate: pendingValues.add) { _, update in
            pendingEmitter.install(update)
            return lateInner
        }
        pending.cancel()
        lateInner.installCancellation { lateCancelled.increment() }
        pendingEmitter.send("late-result")
        try require(pending.isCancelled && lateInner.isCancelled && lateCancelled.value == 1 && pendingValues.all.isEmpty,
                    "pending取消未清理迟到句柄或仍交付旧结果")
        let changedInner = RuntimeOperation(), changedCancelled = Counter(), changedValues = Values(), changedEmitter = Emitter()
        let changedPending = pendingCoordinator.start(onUpdate: changedValues.add) { _, update in
            changedEmitter.install(update)
            return changedInner
        }
        _ = pendingCoordinator.update(listener: stopped, enhanced: running, configurationRevision: 12)
        changedInner.installCancellation { changedCancelled.increment() }
        changedEmitter.send("late-after-change")
        try require(changedPending.isCancelled && changedInner.isCancelled && changedCancelled.value == 1 && changedValues.all.isEmpty,
                    "pending配置换代未清理迟到句柄或仍交付旧结果")

        // Run this reentrant provider on a bounded worker: a regression that
        // calls user code under the coordinator lock must fail the fixture
        // instead of hanging its main self-test lane indefinitely.
        let reentrantCoordinator = RuntimeCoordinator()
        _ = reentrantCoordinator.update(listener: stopped, enhanced: running, configurationRevision: 20)
        let reentrantDone = DispatchSemaphore(value: 0), reentrantBox = OperationBox()
        let reentrantValues = Values(), reentrantEmitter = Emitter(), reentrantCancelled = Counter(), nestedCancelled = Counter()
        DispatchQueue.global().async {
            let operation = reentrantCoordinator.start(onUpdate: { (value: String) in
                reentrantValues.add(value)
                _ = reentrantCoordinator.snapshot
                _ = reentrantCoordinator.acquireSession()
                _ = reentrantCoordinator.advanceRevision()
                let nested = reentrantCoordinator.start(onUpdate: { (_: String) in }) { _, _ in
                    let inner = RuntimeOperation()
                    inner.installCancellation { nestedCancelled.increment() }
                    return inner
                }
                nested.cancel()
            }, start: { _, update in
                _ = reentrantCoordinator.snapshot
                _ = reentrantCoordinator.acquireSession()
                reentrantEmitter.install(update)
                update("synchronous")
                let inner = RuntimeOperation()
                inner.installCancellation {
                    reentrantCancelled.increment()
                    _ = reentrantCoordinator.acquireSession()
                    _ = reentrantCoordinator.advanceRevision()
                }
                return inner
            })
            reentrantBox.set(operation)
            reentrantDone.signal()
        }
        try require(reentrantDone.wait(timeout: .now() + 2) == .success, "同步更新/再注册/取消在协调锁内死锁")
        reentrantEmitter.send("late-reentrant")
        try require(reentrantBox.value?.isCancelled == true && reentrantValues.all == ["synchronous"]
            && reentrantCancelled.value == 1 && nestedCancelled.value == 1,
            "同步回调触发换代后迟到句柄丢失或重复清理")

        let dropCoordinator = RuntimeCoordinator()
        _ = dropCoordinator.update(listener: stopped, enhanced: running, configurationRevision: 30)
        let dropCancelled = Counter(), droppedEmitter = Emitter(), droppedValues = Values()
        weak var weakInner: RuntimeOperation?
        var owned: RuntimeOperation? = dropCoordinator.start(onUpdate: droppedValues.add) { _, update in
            droppedEmitter.install(update)
            let inner = RuntimeOperation()
            weakInner = inner
            inner.installCancellation { dropCancelled.increment() }
            return inner
        }
        weak var weakOuter = owned
        owned = nil
        droppedEmitter.send("after-owner-drop")
        try require(weakOuter == nil && weakInner == nil && dropCancelled.value == 1 && droppedValues.all.isEmpty,
                    "协调器或回调强持有请求，释放所有权未取消")
        try require(dropCoordinator.acquireSession().isReady, "释放单次请求错误停止了核心会话")
        withExtendedLifetime(dropCoordinator) {}

        var ephemeral: RuntimeCoordinator? = RuntimeCoordinator()
        _ = ephemeral?.update(listener: stopped, enhanced: running, configurationRevision: 31)
        weak var weakCoordinator = ephemeral
        let orphanLease = ephemeral!.acquireSession(), orphanCancelled = Counter(), orphanEmitter = Emitter(), orphanValues = Values()
        let orphanOperation = ephemeral!.start(onUpdate: orphanValues.add) { _, update in
            orphanEmitter.install(update)
            let inner = RuntimeOperation()
            inner.installCancellation { orphanCancelled.increment() }
            return inner
        }
        ephemeral = nil
        orphanEmitter.send("after-coordinator-drop")
        try require(weakCoordinator == nil && !orphanLease.isCurrent && !orphanLease.isReady,
                    "会话许可强持有协调器或协调器释放后仍可用")
        try require(orphanOperation.isCancelled && orphanCancelled.value == 1 && orphanValues.all.isEmpty,
                    "协调器释放未取消已注册请求或回填旧结果")
        print("Runtime coordinator self-test passed: \(assertions) assertions; state selection, session epochs, configuration/interface revocation, pending ownership, reentrancy and lifetime")
    }
}

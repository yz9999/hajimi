#!/usr/bin/env python3
"""Exercise the actual enhanced-mode App lifecycle with controlled adapters.

The complete production manager declaration is copied verbatim except for three
read-only platform adapters (physical identity and dynamic-store installation).
The real path/wake callbacks and scheduling bodies use memory platform objects.
DispatchWorkItem is a platform boundary: older cases hold work explicitly,
while reconnect timing cases submit its real GCD item/deadline unchanged.
Adversarial explicit perform() can deliver cancelled bodies to test authority.
The helper,
router, engine and packet reader are replaced at their existing type boundary.
No installed helper, GUI, IP socket, route or resolver is used. The real runtime
and diagnostics modules are imported from an existing source-checked SwiftPM
build. App reload gate/compatibility aliases and IPC models compile without
edits. A manifest makes exact inputs reviewable. Actual diagnostic operations
remain fail-closed resource substitutes and are not invoked by this fixture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def opening_brace(source: str, start: int) -> int:
    """Locate a declaration body; its signatures contain no literal braces."""
    found = source.find("{", start)
    if found < 0:
        raise ValueError("Missing declaration body")
    return found


def declaration_end(source: str, body: int) -> int:
    """Balance Swift braces without interpreting comment/string contents."""
    depth = 0
    index = body
    state = "code"
    comments = 0
    while index < len(source):
        if state == "line":
            if source[index] == "\n":
                state = "code"
            index += 1
            continue
        if state == "block":
            if source.startswith("/*", index):
                comments += 1
                index += 2
            elif source.startswith("*/", index):
                comments -= 1
                index += 2
                if not comments:
                    state = "code"
            else:
                index += 1
            continue
        if state == "triple":
            if source.startswith('"""', index):
                state = "code"
                index += 3
            elif source[index] == "\\":
                index += 2
            else:
                index += 1
            continue
        if state == "string":
            if source[index] == "\\":
                index += 2
            elif source[index] == '"':
                state = "code"
                index += 1
            else:
                index += 1
            continue
        if source.startswith("//", index):
            state = "line"
            index += 2
        elif source.startswith("/*", index):
            state = "block"
            comments = 1
            index += 2
        elif source.startswith('"""', index):
            state = "triple"
            index += 3
        elif source[index] == '"':
            state = "string"
            index += 1
        elif source[index] == "{":
            depth += 1
            index += 1
        elif source[index] == "}":
            depth -= 1
            index += 1
            if not depth:
                return index
        else:
            index += 1
    raise ValueError("Unterminated Swift declaration")


def declaration(source: str, anchor: str) -> tuple[int, int, int]:
    start = source.index(anchor)
    body = opening_brace(source, start)
    return start, body, declaration_end(source, body)


def prepare_sources(work: Path, manager_source: Path | None = None) -> list[dict]:
    manager_path = manager_source or ROOT / "Sources/HajimiApp/EnhancedModeManager.swift"
    manager_raw = manager_path.read_bytes()
    manager_text = manager_raw.decode()
    start, _, end = declaration(manager_text, "final class EnhancedModeManager {")
    original = manager_text[start:end]
    copied = original
    persistent_recovery = re.search(r"\bvar isRequested\s*:", original) is not None
    adapters = {
        "private func defaultInterface()": "return try HandoffFixture.defaultInterface()",
        "private func physicalNetworkSnapshot(":
            "return HandoffFixture.networkSnapshot(path: path, boundInterface: boundInterface)",
        "private func installNetworkStateObserver(": "HandoffFixture.event(\"observer.state.installed\")",
    }
    replacements = []
    for anchor, replacement in adapters.items():
        first, body, last = declaration(copied, anchor)
        replacements.append({"declaration": anchor,
                             "productionSha256": sha(copied[first:last].encode())})
        copied = copied[:body + 1] + "\n        " + replacement + "\n    }" + copied[last:]
    retained = []
    names = ("start", "stop", "stopSynchronously", "rollbackFailedStart", "shutdownForQuit",
             "stopOwnedSession", "releaseLocalResources", "beginNetworkRecovery", "checkNetworkRecovery",
             "attachDataPlane", "requireCurrentStart", "requireStartupNetwork", "bindOutbound", "startHeartbeat",
             "startNetworkObservers", "stopNetworkObservers", "scheduleRebindCheck",
             "reload", "rebindOutboundIfNeeded", "refreshBypassRoutesIfNeeded", "monitorOnce")
    for name in names:
        anchor = "func " + name + "("
        first, _, last = declaration(original, anchor)
        production = original[first:last]
        if production not in copied:
            raise RuntimeError(f"A tested lifecycle declaration was modified: {name}")
        retained.append({"declaration": name, "sha256": sha(production.encode())})
    for name in ("beginStart", "attemptRequestedStart", "checkRequestedConnection",
                 "cancelConnectionRequest", "waitForRequestedConnection", "resumeSupersededStart",
                 "requestNetworkRebind"):
        anchor = "func " + name + "("
        if anchor in original:
            first, _, last = declaration(original, anchor)
            production = original[first:last]
            if production not in copied:
                raise RuntimeError(f"A tested recovery declaration was modified: {name}")
            retained.append({"declaration": name, "sha256": sha(production.encode())})
    imports = "import Foundation\nimport AppKit\nimport Network\nimport Darwin\nimport SystemConfiguration\nimport HajimiCore\n"
    # Fixture-only calls into the exact private queue-owned methods. These
    # hooks fabricate network-change value snapshots; they neither replace
    # production mutation bodies nor invoke any physical observation adapter.
    hooks = """
extension EnhancedModeManager {
    func fixtureLifecycleRebind(retrying: Bool = false, completion: @escaping () -> Void) {
        queue.async {
            defer { completion() }
            let ticket: EnhancedNetworkChangeGate.Ticket?
            if retrying {
                ticket = self.networkChangeGate.pendingTicket
                    ?? self.networkChangeGate.retry(session: self.networkChangeGate.session)
            } else {
                let seed = EnhancedNetworkSnapshot(available: true, interfaceName: "en-fixture",
                    interfaceIndex: 7, addresses: ["192.0.2.7"], gateways: ["192.0.2.1"])
                _ = self.networkChangeGate.begin(seed: seed, boundInterface: "en-fixture")
                let next = EnhancedNetworkSnapshot(available: true, interfaceName: "en-fixture",
                    interfaceIndex: 7, addresses: ["192.0.2.7"], gateways: ["192.0.2.2"])
                HandoffFixture.setNetwork(next)
                ticket = self.networkChangeGate.observe(next, session: self.networkChangeGate.session)
            }
            guard let ticket, let action = self.networkChangeGate.take(ticket) else { return }
            self.rebindOutboundIfNeeded(change: action)
        }
    }
    func fixtureLifecycleRefreshBypass() {
        queue.async { self.refreshBypassRoutesIfNeeded() }
    }
    func fixtureLifecycleMonitor(completion: @escaping () -> Void) {
        queue.async { self.monitorOnce(); completion() }
    }
    func fixtureNetworkBarrier() { queue.sync {} }
    func fixtureNetworkPendingWork() -> DispatchWorkItem? { queue.sync { pendingRebind } }
    func fixtureNetworkPerformPendingWork() {
        queue.sync { pendingRebind?.perform() }
    }
    func fixtureNetworkPerform(_ work: DispatchWorkItem, completion: @escaping () -> Void) {
        queue.async { work.perform(); completion() }
    }
    func fixtureNetworkRunStale(_ work: DispatchWorkItem) {
        queue.sync { work.perform() }
    }
    func fixtureAppliedExcludedRoutes() -> [String]? {
        queue.sync { lock.withLock { appliedConfiguration?.profile.tunExcludedRoutes } }
    }
    func fixtureRequestedConnectionPoll(completion: @escaping () -> Void) {
        queue.async {
            #if HAVE_PERSISTENT_ENHANCED_RECOVERY
            self.checkRequestedConnection()
            #else
            self.monitorOnce()
            #endif
            completion()
        }
    }
    func fixtureCleanupRecoveryPoll(completion: @escaping () -> Void) {
        queue.async { self.checkNetworkRecovery(); completion() }
    }
}
"""
    if not persistent_recovery:
        # Build38 had no independent desired state. This read-only compatibility
        # property exposes exactly its former startup/ownership semantics, so
        # current assertions can demonstrate the missing recovery on old code.
        hooks += """
extension EnhancedModeManager {
    var isRequested: Bool { isEnabled || lifecycleSnapshot.startupPending }
}
"""
    (work / "ManagerProduction.swift").write_text(imports + copied + "\n" + hooks)
    snapshots = [{"source": str(manager_path.relative_to(ROOT)) if manager_path.is_relative_to(ROOT) else str(manager_path),
                  "sha256": sha(manager_raw), "frozenManager": manager_source is not None,
                  "extractedClassSha256": sha(original.encode()),
                  "persistentRecovery": persistent_recovery,
                  "platformSchedulingBoundary": "DispatchWorkItem wrapper; actual GCD queue/deadlines for timing cases; explicit controlled work for old handoff cases",
                  "fixtureOnlyPrivateEntryHooksSha256": sha(hooks.encode()),
                  "replacedPlatformAdapters": replacements, "retainedLifecycle": retained}]
    for path in ["Sources/HajimiApp/EnhancedStartupIntent.swift",
                 "Sources/HajimiApp/AppNetworkRuntime.swift",
                 "Sources/HajimiApp/RoutingReloadGate.swift",
                 "Sources/HajimiApp/NetworkDiagnosticsBackend.swift",
                 "Sources/HajimiApp/EnhancedNetworkChangeGate.swift",
                 "Sources/HajimiIPC/PrivilegedHelperProtocol.swift",
                 "SmokeTests/EnhancedHandoffFixture.swift"]:
        source = ROOT / path
        frozen_companion = False
        if manager_source and source.name == "EnhancedNetworkChangeGate.swift":
            companion = manager_path.with_name(source.name)
            if companion.is_file():
                # A before control must not combine the old manager with a
                # newer gate that grants recovery the old App never had.
                source = companion
                frozen_companion = True
        if manager_source and not persistent_recovery and source.name == "AppNetworkRuntime.swift":
            # New presentation code can name a Status case Build38 did not
            # contain. Its matching frozen adapter preserves the old program;
            # no production recovery or lifecycle body is fabricated here.
            source = manager_path.with_name("AppNetworkRuntime.swift")
            if not source.is_file():
                raise RuntimeError("Frozen manager control requires its sibling AppNetworkRuntime.swift")
            frozen_companion = True
        raw = source.read_bytes()
        (work / source.name).write_bytes(raw)
        recorded_path = str(source.relative_to(ROOT)) if source.is_relative_to(ROOT) else str(source)
        snapshots.append({"source": recorded_path, "sha256": sha(raw), "wholeFile": True,
                          "frozenCompanion": frozen_companion})
    script = Path(__file__).resolve()
    snapshots.append({"source": str(script.relative_to(ROOT)),
                      "sha256": sha(script.read_bytes()), "wholeFile": True})
    return snapshots


def run_logged(command: list[str], log: Path, timeout: int) -> None:
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout, check=False)
    log.write_text(result.stdout)
    if result.returncode:
        print(result.stdout[-18000:], end="", flush=True)
        raise SystemExit(result.returncode)


def main() -> None:
    from swiftpm_test_support import collect_prebuilt_inputs, default_build_directory

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/enhanced-handoff-validation")
    parser.add_argument("--configuration", choices=["debug", "release"], default="release")
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--manager-source", type=Path,
                        help="exact unmodified frozen EnhancedModeManager.swift for a before/after control")
    parser.add_argument("--expect-failure", action="store_true",
                        help="require the selected cases to fail their same current assertions on a frozen manager")
    parser.add_argument("--case", action="append", default=[], help="run only a named scenario")
    args = parser.parse_args()
    if args.expect_failure and (not args.manager_source or not args.case):
        parser.error("--expect-failure requires --manager-source and explicitly selected --case values")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    prebuilt = collect_prebuilt_inputs(args.build_dir or default_build_directory(args.configuration), work)
    snapshots = prepare_sources(work, args.manager_source.resolve() if args.manager_source else None)
    executable = work / "enhanced-handoff-fixture"
    command = ["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library", *prebuilt.flags,
                "-module-name", "EnhancedHandoffFixture", *map(str, sorted(work.glob("*.swift"))),
                *prebuilt.objects, *prebuilt.libraries, *prebuilt.linker_flags, "-o", str(executable)]
    if snapshots[0]["persistentRecovery"]:
        command[2:2] = ["-D", "HAVE_PERSISTENT_ENHANCED_RECOVERY"]
    (work / "compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    run_logged(command, work / "compile.log", 120)
    cases = args.case or ["success", "stop-installation", "stop-bypass", "stop-binding",
                         "stop-prepare", "stop-reader", "stop-commit", "reader-start-failure",
                         "reader-ready-failure", "commit-failure", "commit-pending-recovery",
                         "stop-pending-recovery", "shutdown-prepare", "commit-restart-empty-status",
                         "stop-restart-empty-status", "running-restart-empty-status", "late-success-cancelled",
                         "stop-reload", "unrelated-reload", "rebind-recovery", "bypass-recovery",
                         "bypass-stop-reload", "network-duplicate-first-frame", "network-first-frame-offline",
                         "network-offline-online-debounce", "network-offline-online-after-debounce",
                         "network-offline-bypass", "network-offline-bypass-late-result",
                         "network-bypass-preflight-recovery",
                         "network-dhcp-late-gateway", "network-health-retry", "network-health-detects-recovery",
                         "network-pending-configuration-recovery",
                         "network-stale-work-and-path", "network-stale-wake", "network-user-stop-fences",
                         "network-stop-during-rebind",
                         "network-reconnect-immediate", "network-reconnect-dhcp-probe",
                         "network-reconnect-missing-ready-event", "network-reconnect-probe-bound",
                         "network-reconnect-offline-probe-bound", "network-reconnect-probe-new-identity",
                         "network-reconnect-probe-cancel", "network-reconnect-probe-config",
                         "network-reconnect-unknown-failure", "network-reconnect-single-bind-prewarm",
                         "network-reconnect-duplicate-ready",
                         "requested-initial-offline", "requested-restored-offline",
                         "requested-same-session-offline",
                         "requested-prepare-network-wait", "requested-prepare-fatal-pause", "requested-cleanup-ack",
                         "requested-foreign-session", "requested-stop-waiting",
                         "requested-stop-bypass",
                         "requested-stop-prepare", "requested-stop-reader", "requested-stop-commit",
                         "requested-latest-configuration", "requested-late-configuration",
                         "requested-notification-burst",
                         "requested-reconnect-throttle",
                         "requested-shutdown-waiting"]
    outputs = []
    outcomes = []
    failure = None
    for case in cases:
        if not re.fullmatch(r"[a-z-]+", case):
            raise ValueError("Invalid case name")
        log = work / f"{case}.log"
        isolated = work / "isolated-preferences"
        isolated.mkdir(exist_ok=True)
        completed = subprocess.run(["env", "CFFIXED_USER_HOME=" + str(isolated), str(executable), case],
                                   cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=20, check=False)
        output = completed.stdout
        log.write_text(output)
        print(output, end="", flush=True)
        outputs.append(output)
        expected = (completed.returncode == 1 and "FAIL App enhanced handoff:" in output
                    if args.expect_failure else completed.returncode == 0)
        outcomes.append({"case": case, "returnCode": completed.returncode,
                         "expectedFailure": args.expect_failure, "matchedExpectation": expected})
        if not expected:
            failure = completed.returncode or 1
            break
    for item in snapshots:
        item["unchanged"] = sha((ROOT / item["source"]).read_bytes()) == item["sha256"]
    prebuilt.verify()
    (work / "source-manifest.json").write_text(json.dumps(snapshots, ensure_ascii=False, indent=2) + "\n")
    (work / "results.log").write_text("".join(outputs))
    (work / "case-outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
    if not all(item["unchanged"] for item in snapshots):
        raise RuntimeError("Production sources changed during the run; rerun the coherent snapshot")
    if failure is not None:
        raise SystemExit(failure)
    expectation = "expected negative controls" if args.expect_failure else "App lifecycle scenarios"
    print(f"PASS {len(outcomes)} {expectation}; production source manifest unchanged")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compile exact Main lifecycle methods with memory-only resource/UI adapters.

The actual Runtime, App routing gate, Profile models and Main lifecycle bodies
remain byte-for-byte intact. Rule preparation completion, UI controls, resource
owners and UserDefaults are controlled in memory. No App, installed Helper,
listener, socket, interface lookup, route, resolver or OS preference is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from test_enhanced_handoff import declaration, run_logged
from routing_test_support import build_routing_module


ROOT = Path(__file__).resolve().parents[1]


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/main-lifecycle-tests")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    routing = build_routing_module(work)
    main_path = ROOT / "Sources/HajimiApp/MainWindowController.swift"
    main_raw = main_path.read_bytes()
    main_text = main_raw.decode()
    values = []
    retained = []
    for anchor in ["struct SessionRestoreIntent:", "enum LaunchProfilePlan {", "struct SystemProxyListenerPlan {"]:
        start, _, end = declaration(main_text, anchor)
        body = main_text[start:end]
        values.append(body)
        retained.append({"declaration": anchor, "sha256": sha(body.encode())})
    methods = []
    anchors = ["var isEngineActive: Bool", "var isEnhancedModeActive: Bool", "private func startEngine()",
               "private func startEngineThrowing(", "private func stopListenerResources()",
               "private func stopProxyEngine()", "private func disableSystemProxyAndStopEngine()",
               "private func reloadListener(", "private func updateEngineRouting()",
               "private func restoreLastSession(", "private func restoreEnhancedMode(",
               "@objc private func toggleEngine()", "@objc private func toggleEnhancedMode()",
               "private func discardStaleEnhancedStart(", "private func canStartAfterSystemProxyRecovery()",
               "private func acceptListenerStatus(", "private func isCurrentListener(",
               "private func prepareLaunchSession()", "private func cancelLaunchRestorePreparation()",
               "private func finishLaunchRestore()",
               "private func apply(enhancedStatus",
               "@objc private func uninstallHelperFromSettings()",
               "private func applyPendingSystemProxyRestore()", "private func reconcileSystemProxyListener()",
               "private func recoverSystemProxyAfterListenerFailure()", "@objc private func toggleSystemProxy()",
               "private enum ProfileApplyError:"]
    for anchor in anchors:
        start, _, end = declaration(main_text, anchor)
        body = main_text[start:end]
        methods.append(body)
        retained.append({"declaration": anchor, "sha256": sha(body.encode())})
    template_path = ROOT / "SmokeTests/MainLifecycleFixture.swift"
    template_raw = template_path.read_bytes()
    copied = template_raw.decode()
    copied = copied.replace("// @INSERT_MAIN_VALUE_DECLARATIONS@", "\n\n".join(values))
    copied = copied.replace("// @INSERT_MAIN_LIFECYCLE_DECLARATIONS@", "\n\n".join(methods))
    (work / "MainProductionFixture.swift").write_text(copied)
    manifest = [{"source": str(main_path.relative_to(ROOT)), "sha256": sha(main_raw),
                 "retainedLifecycleDeclarations": retained,
                 "substitutedBoundaries": ["RULE-SET async preparation", "resource owners", "UI controls", "UserDefaults"]},
                {"source": str(template_path.relative_to(ROOT)), "sha256": sha(template_raw), "wholeFile": True}]
    manifest.extend(routing.manifest)
    for source in [Path(__file__).resolve(), ROOT / "scripts/test_enhanced_handoff.py"]:
        manifest.append({"source": str(source.relative_to(ROOT)), "sha256": sha(source.read_bytes()), "wholeFile": True})
    for path in ["Sources/HajimiApp/RoutingReloadGate.swift"]:
        source = ROOT / path
        raw = source.read_bytes()
        (work / source.name).write_bytes(raw)
        manifest.append({"source": path, "sha256": sha(raw), "wholeFile": True})
    for name, sources in [
        ("runtime", sorted((ROOT / "Sources/HajimiRuntime").glob("*.swift"))),
        ("core", [ROOT / "Sources/HajimiCore/Profile.swift", ROOT / "Sources/HajimiCore/SurgeProfileDocument.swift"]),
    ]:
        directory = work / (name + "-sources")
        directory.mkdir(parents=True, exist_ok=True)
        for source in sources:
            raw = source.read_bytes()
            (directory / source.name).write_bytes(raw)
            manifest.append({"source": str(source.relative_to(ROOT)), "sha256": sha(raw), "wholeFile": True})
        module = work / (name + "-module")
        module.mkdir(parents=True, exist_ok=True)
        module_name = "HajimiRuntime" if name == "runtime" else "HajimiCore"
        run_logged(["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library",
                    *(routing.flags if name == "core" else []),
                    "-emit-module", "-emit-library", "-module-name", module_name,
                    *map(str, sorted(directory.glob("*.swift"))),
                    "-emit-module-path", str(module / (module_name + ".swiftmodule")),
                    "-Xlinker", "-install_name", "-Xlinker", "@rpath/lib" + module_name + ".dylib",
                    "-o", str(module / ("lib" + module_name + ".dylib"))], work / (name + "-compile.log"), 120)
    executable = work / "main-lifecycle-fixture"
    run_logged(["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library",
                *routing.flags,
                *map(str, sorted(work.glob("*.swift"))),
                "-I", str(work / "runtime-module"), "-L", str(work / "runtime-module"), "-lHajimiRuntime",
                "-I", str(work / "core-module"), "-L", str(work / "core-module"), "-lHajimiCore",
                "-Xlinker", "-rpath", "-Xlinker", "@loader_path/runtime-module",
                "-Xlinker", "-rpath", "-Xlinker", "@loader_path/core-module",
                "-o", str(executable)], work / "compile.log", 120)
    run_logged([str(executable)], work / "results.log", 20)
    print((work / "results.log").read_text(), end="", flush=True)
    routing.verify()
    for item in manifest:
        item["unchanged"] = sha((ROOT / item["source"]).read_bytes()) == item["sha256"]
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    if not all(item["unchanged"] for item in manifest):
        raise RuntimeError("Sources changed during the Main lifecycle run; rerun the coherent snapshot")
    print(f"PASS exact Main lifecycle methods; {len(manifest)} source inputs unchanged")


if __name__ == "__main__":
    main()

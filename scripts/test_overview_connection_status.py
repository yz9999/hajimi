#!/usr/bin/env python3
"""Compile the exact App runtime and Main status/event methods with memory owners.

No real Main controller, window, network operation, Helper or system preference
is created. Existing source-checked SwiftPM objects supply unrelated imported
modules. The complete current App runtime and self-test compile from frozen
source, and the Main declarations are retained byte-for-byte in the fixture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from swiftpm_test_support import ROOT, collect_prebuilt_inputs, default_build_directory
from test_enhanced_handoff import declaration


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", choices=["debug", "release"], default="release")
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/overview-connection-status")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    prebuilt = collect_prebuilt_inputs(args.build_dir or default_build_directory(args.configuration), work)
    paths = [ROOT / "Sources/HajimiApp/MainWindowController.swift",
             ROOT / "Sources/HajimiApp/AppNetworkRuntime.swift",
             ROOT / "Sources/HajimiApp/AppNetworkRuntimeSelfTest.swift",
             ROOT / "SmokeTests/OverviewConnectionStatusFixture.swift",
             Path(__file__).resolve(), ROOT / "scripts/test_enhanced_handoff.py"]
    captured = {path: path.read_bytes() for path in paths}
    frozen = {}
    for path, raw in captured.items():
        destination = work / "inputs" / path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        frozen[path] = destination
    text = captured[paths[0]].decode()
    methods = []
    retained = []
    for anchor in ["private func bindEngine()", "private func apply(enhancedStatus",
                   "private func apply(status:", "private var connectionPresentation:",
                   "private func refreshConnectionStatus()", "var statusItemSummary:",
                   "private var selectedMode:", "@objc private func modeChanged()",
                   "private func updateOverviewDetails()", "@objc private func toggleSystemProxy()",
                   "private func isCurrentListener(", "private func acceptListenerStatus(",
                   "private func applyPendingSystemProxyRestore()", "private func reconcileSystemProxyListener()",
                   "private func recoverSystemProxyAfterListenerFailure()", "var isEnhancedModeActive: Bool"]:
        first, _, last = declaration(text, anchor)
        body = text[first:last]
        methods.append(body)
        retained.append({"declaration": anchor, "sha256": sha(body.encode()), "wholeDeclaration": True})
    values = []
    for anchor in ["private enum HajimiTheme {", "struct SessionRestoreIntent:", "struct SystemProxyListenerPlan {"]:
        first, _, last = declaration(text, anchor)
        body = text[first:last]
        values.append(body)
        retained.append({"declaration": anchor, "sha256": sha(body.encode()), "wholeDeclaration": True})
    fixture = captured[paths[3]].decode()
    for marker in ["// @THEME@", "// @MAIN_VALUES@", "// @PRODUCTION_METHODS@"]:
        if fixture.count(marker) != 1:
            raise RuntimeError("The exact fixture insertion boundary changed: " + marker)
    generated = fixture.replace("// @THEME@", values[0]).replace("// @MAIN_VALUES@", "\n\n".join(values[1:]))
    generated = generated.replace("// @PRODUCTION_METHODS@", "\n\n".join(methods))
    fixture_path = work / "OverviewProductionFixture.swift"
    fixture_path.write_text(generated, encoding="utf-8")
    binary = work / "overview-connection-status"
    command = ["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library",
               "-package-name", "哈基米", *prebuilt.flags,
               str(frozen[paths[1]]), str(frozen[paths[2]]), str(fixture_path),
               *prebuilt.objects, *prebuilt.libraries, *prebuilt.linker_flags, "-o", str(binary)]
    receipts = []
    def run(name: str, arguments: list[str], timeout: int, *, env=None) -> None:
        (work / (name + "-command.json")).write_text(json.dumps(arguments, ensure_ascii=False, indent=2) + "\n")
        started = time.monotonic()
        result = subprocess.run(arguments, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout, check=False)
        (work / (name + ".log")).write_text(result.stdout, encoding="utf-8")
        receipts.append({"name": name, "exitCode": result.returncode,
                         "elapsedSeconds": round(time.monotonic() - started, 3),
                         "logSha256": sha(result.stdout.encode())})
        (work / "command-receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
        print(result.stdout[-18000:], end="", flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)
    run("compile", command, 120)
    isolated = work / "isolated-preferences"
    isolated.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment["CFFIXED_USER_HOME"] = str(isolated)
    run("results", [str(binary)], 60, env=environment)
    prebuilt.verify()
    manifest = [{"source": str(path.relative_to(ROOT)), "sha256": sha(captured[path]),
                 "wholeFile": True, "frozenPath": str(frozen[path]),
                 "unchanged": sha(path.read_bytes()) == sha(captured[path])
                    and sha(frozen[path].read_bytes()) == sha(captured[path])} for path in paths]
    manifest[0]["exactProductionDeclarations"] = retained
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("Overview status source changed during validation")
    print(f"PASS {len(manifest)} source inputs and {len(prebuilt.manifest)} prebuilt inputs unchanged; exact App runtime and Main event paths; no windows or network owners")


if __name__ == "__main__":
    main()

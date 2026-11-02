#!/usr/bin/env python3
"""Measure actual diagnostics view/feature with maximum memory-only reports."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from swiftpm_test_support import ROOT, collect_prebuilt_inputs, default_build_directory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=default_build_directory("release"))
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/network-diagnostics-responsiveness")
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    prebuilt = collect_prebuilt_inputs(args.build_dir, work)
    paths = [ROOT / "SmokeTests/NetworkDiagnosticsResponsivenessMain.swift", Path(__file__).resolve()]
    frozen = {}
    for path in paths:
        raw = path.read_bytes()
        destination = work / "inputs" / path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        frozen[path] = {"path": destination, "sha256": hashlib.sha256(raw).hexdigest()}
    binary = work / "diagnostics-responsiveness"
    command = ["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library", *prebuilt.flags,
               str(frozen[paths[0]]["path"]), *prebuilt.objects, *prebuilt.libraries,
               *prebuilt.linker_flags, "-o", str(binary)]
    (work / "compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    compiled = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    isolated = work / "isolated-preferences"
    isolated.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment["CFFIXED_USER_HOME"] = str(isolated)
    result = subprocess.run([str(binary), *(["--baseline"] if args.baseline else [])], cwd=ROOT,
                            env=environment, text=True, capture_output=True, timeout=60, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout + result.stderr, end="", flush=True)
    prebuilt.verify()
    inventory = []
    for path, value in frozen.items():
        inventory.append({"path": str(path), "sha256": value["sha256"],
            "unchanged": hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]
            and hashlib.sha256(value["path"].read_bytes()).hexdigest() == value["sha256"]})
    (work / "source-manifest.json").write_text(json.dumps(inventory, indent=2) + "\n")
    if not all(value["unchanged"] for value in inventory):
        raise RuntimeError("Diagnostics responsiveness inputs changed during execution")
    if result.returncode:
        raise SystemExit(result.returncode)
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"PASS unchanged actual diagnostics imports; artifacts={work}")


if __name__ == "__main__":
    main()

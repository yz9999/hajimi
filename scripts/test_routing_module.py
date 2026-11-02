#!/usr/bin/env python3
"""Compile and import the complete routing library without Core or native I/O.

Runs fixed public-API vectors against the real module, retaining the source
hashes, compiler commands and dynamic dependencies. No App/Helper, profile,
listener, resolver, external network or system setting is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess

from routing_test_support import ROOT, build_routing_module


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/routing-module-tests")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    routing = build_routing_module(work)
    runner = ROOT / "SmokeTests/RoutingModuleMain.swift"
    raw = runner.read_bytes()
    frozen = work / runner.name
    frozen.write_bytes(raw)
    script = Path(__file__).resolve()
    manifest = routing.manifest + [
        {"source": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(data).hexdigest(), "wholeFile": True}
        for path, data in [(runner, raw), (script, script.read_bytes())]]
    binary = work / "routing-module-check"
    # Deliberately compile the runner as an outside public client: package
    # visibility is needed by Core adapters, not by these public API vectors.
    command = ["xcrun", "swiftc", "-O", "-swift-version", "5", "-target",
               platform.machine() + "-apple-macos13.0", "-parse-as-library",
               *routing.flags[2:], str(frozen), "-o", str(binary)]
    (work / "runner-compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    for label, command in [("runner-compile", command), ("results", [str(binary)]),
                           ("linked-libraries", ["xcrun", "otool", "-L", str(binary)])]:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
        output = result.stdout + result.stderr
        (work / (label + ".log")).write_text(output, encoding="utf-8")
        if result.returncode:
            print(output[-18000:], end="", flush=True)
            raise SystemExit(result.returncode)
        if label == "results":
            print(output, end="", flush=True)
        if label == "linked-libraries" and re.search(r"Hajimi(?:Core|DNS|Native|RoutingCXX)|/(?:AppKit|Network)\.framework/", output):
            raise RuntimeError("The independent routing runner unexpectedly links platform/Core dependencies")
    routing.verify()
    for row in manifest:
        row["unchanged"] = hashlib.sha256((ROOT / row["source"]).read_bytes()).hexdigest() == row["sha256"]
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("Routing public fixture inputs changed during execution")
    print(f"PASS real import HajimiRouting; {len(manifest)} source inputs unchanged; artifacts: {work}")


if __name__ == "__main__":
    main()

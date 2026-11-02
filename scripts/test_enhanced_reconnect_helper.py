#!/usr/bin/env python3
"""Run the entire helper service against memory commands and ordinary FDs.

No app, daemon/socket server, utun, network command or external network is run.
The service source is frozen verbatim; only the HajimiIPC module import is
removed when compiling the same real IPC declarations into this test binary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/enhanced-reconnect-helper")
    parser.add_argument("--helper-source", type=Path, default=ROOT / "Sources/HajimiHelper/HelperDaemon.swift")
    parser.add_argument("--expect", choices=["before", "before-gateway", "after"], default="after")
    args = parser.parse_args()
    work = args.work_dir.resolve(); work.mkdir(parents=True, exist_ok=True)
    paths = [ROOT / "Sources/HajimiIPC/PrivilegedHelperProtocol.swift",
             ROOT / "Sources/HajimiIPC/UnixFileDescriptorPassing.swift", args.helper_source.resolve(),
             ROOT / "Sources/HajimiHelper/PhysicalIPv6ScopedRoute.swift",
             ROOT / "Sources/HajimiHelper/EnhancedTunnelStartupSelfTest.swift",
             ROOT / "SmokeTests/EnhancedReconnectHelperMain.swift"]
    inputs = {path: path.read_bytes() for path in paths}
    source = "\n".join(data.decode().replace("import HajimiIPC\n", "") for data in inputs.values())
    generated = work / "ProductionEnhancedReconnectHelper.swift"
    generated.write_text(source, encoding="utf-8")
    source_hash = hashlib.sha256(generated.read_bytes()).hexdigest()
    manifest = [{"source": str(path), "sha256": hashlib.sha256(data).hexdigest()} for path, data in inputs.items()]
    (work / "source-manifest.json").write_text(json.dumps({"frozenInputSHA256": source_hash,
        "sources": manifest, "expectedBehavior": args.expect}, indent=2) + "\n")
    binary = work / "enhanced-reconnect-helper"
    command = ["xcrun", "swiftc", "-package-name", "Hajimi", "-swift-version", "5", "-O", "-parse-as-library"]
    if args.expect != "before": command += ["-D", "HAVE_RECONNECT_PREFLIGHT"]
    if args.expect == "after": command += ["-D", "HAVE_ROUTE_REPLACEMENT"]
    compiled = subprocess.run(command + [str(generated), "-o", str(binary), "-framework", "Foundation"],
        text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr); raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary), args.expect], text=True, capture_output=True, timeout=30, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    unchanged = all(path.read_bytes() == data for path, data in inputs.items())
    frozen_unchanged = hashlib.sha256(generated.read_bytes()).hexdigest() == source_hash
    (work / "source-unchanged.json").write_text(json.dumps({"unchanged": unchanged, "frozenUnchanged": frozen_unchanged}) + "\n")
    if not unchanged or not frozen_unchanged: raise RuntimeError("tested source changed during the run")
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if result.returncode: raise SystemExit(result.returncode)
    if args.expect == "before" and len(report["verifiedLegacyRegressions"]) != 8:
        raise RuntimeError("Build37 did not reproduce all eight specified legacy outcomes")
    if args.expect == "before-gateway" and len(report["verifiedGatewayRegressions"]) != 5:
        raise RuntimeError("Build38 did not reproduce all five specified route reconciliation failures")
    print(f"Frozen full helper service passed ({args.expect}); artifacts: {work}")


if __name__ == "__main__":
    main()

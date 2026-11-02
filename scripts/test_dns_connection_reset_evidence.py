#!/usr/bin/env python3
"""Verify native reset provenance and attempt-local atomic progress in memory.

Compile the exact full production recorder/context plus their real module
contracts. CFErrorCreate models the ObjC runtime's toll-free native errors;
no network call, application, Helper or system configuration is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import PACKAGE_FLAGS, monolithic, source_path, write_source_inventory


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-connection-reset-evidence")
    parser.add_argument("--baseline-manifest", type=Path)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    baseline = args.baseline_manifest.resolve() if args.baseline_manifest else None
    preserved = json.loads(baseline.read_text())["sources"] if baseline else {}
    filenames = ["DNSQueryContracts.swift", "DNSAdaptiveUpstreamSelector.swift", "DNSMessageInspection.swift",
                 "DNSQueryExecutionContext.swift", "NetworkPerformanceDiagnostics.swift"]
    paths: list[Path] = []
    for filename in filenames:
        current = source_path(filename)
        row = preserved.get(str(current.relative_to(ROOT)))
        path = ROOT / row["preservedAt"] if row else current
        if row and hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
            raise RuntimeError("Full preserved Build41 baseline changed")
        paths.append(path)
    paths += [ROOT / "SmokeTests/DNSConnectionResetEvidenceMain.swift", Path(__file__).resolve(),
              ROOT / "scripts/dns_test_sources.py"]
    if baseline:
        paths.append(baseline)
    inputs = [(path, path.read_text(encoding="utf-8")) for path in paths]
    manifest = [{"source": str(path), "wholeFile": True, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                 "unchanged": True} for path, text in inputs]
    generated = work / "ProductionDNSConnectionResetEvidence.swift"
    generated.write_text(monolithic("\n".join(text for _, text in inputs[:len(filenames) + 1])), encoding="utf-8")
    source_hash = hashlib.sha256(generated.read_bytes()).hexdigest()
    provenance = {"baselineManifest": str(baseline) if baseline else None,
                  "frozenInputSHA256": source_hash, "inputs": manifest}
    manifest_path = work / "source-manifest.json"
    manifest_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-connection-reset-evidence"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library"]
    if not baseline:
        command += ["-D", "HAVE_CONNECTION_RESET_EVIDENCE"]
    compiled = subprocess.run(command + [str(generated), "-framework", "Foundation", "-framework", "Network",
        "-o", str(binary)], text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout + result.stderr, end="")
    for row, (path, text) in zip(manifest, inputs):
        row["unchanged"] = path.read_text(encoding="utf-8") == text
    manifest_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("Native reset evidence inputs changed during the run")
    if hashlib.sha256(generated.read_bytes()).hexdigest() != source_hash:
        raise RuntimeError("Frozen native reset compiler input changed")
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if baseline:
        if result.returncode != 1 or set(report["failedGroups"]) != set(report["evidenceGroups"]):
            raise RuntimeError("Baseline did not fail exactly for absent native reset evidence")
        print("PASS negative control: original recorder/progress semantics remain; new native reset evidence is absent")
    elif result.returncode:
        raise SystemExit(result.returncode)
    print(f"Exact full recorder/context inputs unchanged; manifest={manifest_path}")


if __name__ == "__main__":
    main()

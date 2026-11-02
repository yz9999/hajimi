#!/usr/bin/env python3
"""Check narrowly scoped local DNS-SD answers with exact production wire code.

All fixtures are memory packets. No socket, App, Helper or system DNS/route
setting is accessed. A full older source can be supplied as a negative control:
only the three groups requiring the new local answer must then fail.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import PACKAGE_FLAGS, source_path, write_source_inventory


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-local-service-discovery")
    parser.add_argument("--baseline-source", type=Path)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    baseline = args.baseline_source.resolve() if args.baseline_source else None
    source = baseline or source_path("DNSMessageInspection.swift")
    fixture = ROOT / "SmokeTests/DNSLocalServiceDiscoveryMain.swift"
    paths = [source, fixture, Path(__file__).resolve(), ROOT / "scripts/dns_test_sources.py"]
    inputs = [(path, path.read_text(encoding="utf-8")) for path in paths]
    manifest = [{"source": str(path), "wholeFile": True,
                 "sha256": hashlib.sha256(text.encode()).hexdigest(), "unchanged": True}
                for path, text in inputs]
    generated = work / "ProductionDNSLocalServiceDiscovery.swift"
    generated.write_text(inputs[0][1] + "\n" + inputs[1][1], encoding="utf-8")
    generated_hash = hashlib.sha256(generated.read_bytes()).hexdigest()
    manifest_path = work / "source-manifest.json"
    provenance = {"baselineSource": str(baseline) if baseline else None,
                  "frozenInputSHA256": generated_hash, "inputs": manifest}
    manifest_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-local-service-discovery"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library"]
    if not baseline:
        command += ["-D", "HAVE_LOCAL_SERVICE_DISCOVERY_RESPONSE"]
    compiled = subprocess.run(command + [str(generated), "-framework", "Foundation", "-o", str(binary)],
                              text=True, capture_output=True, timeout=120, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout + result.stderr, end="")
    for row, (path, text) in zip(manifest, inputs):
        row["unchanged"] = path.read_text(encoding="utf-8") == text
    manifest_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("Local DNS-SD test inputs changed during the run")
    if hashlib.sha256(generated.read_bytes()).hexdigest() != generated_hash:
        raise RuntimeError("Frozen wire compiler input changed during the run")
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if baseline:
        if result.returncode != 1 or set(report["failedGroups"]) != set(report["responseGroups"]):
            raise RuntimeError("Baseline did not fail exactly for absent local DNS-SD answers")
        print("PASS negative control: older wire parser is unchanged; new local answers are absent")
    elif result.returncode:
        raise SystemExit(result.returncode)
    print(f"Exact wire source unchanged; manifest={manifest_path}")


if __name__ == "__main__":
    main()

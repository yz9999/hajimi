#!/usr/bin/env python3
"""Compile unchanged production DNS declarations; use memory and loopback only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from test_dns_empty_eof_failure import ROOT, manifest
from test_network_connectivity_diagnostics import selected
from dns_test_sources import PACKAGE_FLAGS, monolithic, write_source_inventory


def sources() -> dict[str, str]:
    values = selected()
    values["smoke-test"] = (ROOT / "SmokeTests/TraditionalDNSConnectivityProbeMain.swift").read_text(encoding="utf-8")
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/traditional-dns-connectivity-probe")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    values = sources()
    before = manifest(values)
    production = work / "ProductionTraditionalDNSConnectivityProbe.swift"
    production.write_text(monolithic("import Foundation\nimport Network\nimport Security\nimport Darwin\n"
        "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { nil } }\n"
        + "\n".join(values.values())), encoding="utf-8")
    binary = work / "traditional-dns-connectivity-probe"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library",
        str(production), "-o", str(binary), "-framework", "Foundation", "-framework", "Network",
        "-framework", "Security"], text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=45, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr)
    after = manifest(sources())
    write_source_inventory(work)
    (work / "source-manifest.json").write_text(json.dumps({name: {
        "before": digest, "after": after.get(name), "unchanged": digest == after.get(name)}
        for name, digest in before.items()}, indent=2) + "\n")
    print(result.stdout + result.stderr, end="")
    if before != after:
        raise RuntimeError("production or fixture sources changed during run")
    if result.returncode:
        raise SystemExit(result.returncode)
    print(f"Exact production declarations unchanged; memory/loopback evidence: {work}")


if __name__ == "__main__":
    main()

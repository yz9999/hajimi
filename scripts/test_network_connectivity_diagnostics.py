#!/usr/bin/env python3
"""Run exact production diagnostics and traditional-DNS memory-only checks.

No test invokes the network operations, GUI or Helper. The traditional wire is
injected, and its production socket-entry revocation vector denies admission
before creating a connection. Only the unused physical-interface getter is
replaced. Full ProxyEngine policy planning is covered by the final app selftest.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from test_dns_empty_eof_failure import ROOT, manifest
from dns_test_sources import PACKAGE_FLAGS, monolithic, source_text, write_source_inventory


def selected() -> dict[str, str]:
    values = {name: source_text(name) for name in (
        "ProbeScheduler.swift", "DNSMessageInspection.swift", "DNSQueryExecutionContext.swift",
        "DNSQueryContracts.swift", "DNSAdaptiveUpstreamSelector.swift",
        "NetworkPerformanceDiagnostics.swift", "NetworkConnectivityDiagnostics.swift", "TraditionalDNSResolver.swift")}
    for filename, marker in (
        ("NativeOutbound.swift", "public protocol NativeOutboundByteStream:"),
        ("EncryptedDNS.swift", "public enum EncryptedDNSBootstrap {"),
        ("EncryptedDNS.swift", "public struct DoHEndpoint:"),
    ):
        source = source_text(filename)
        start = source.index(marker)
        end = source.index("\n}\n", start) + 3
        values[filename + ":" + marker] = source[start:end]
    values["smoke-test"] = (ROOT / "SmokeTests/NetworkConnectivityDiagnosticsMain.swift").read_text(encoding="utf-8")
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/network-connectivity-diagnostics")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    values = selected()
    before = manifest(values)
    production = work / "ProductionNetworkConnectivityDiagnostics.swift"
    production.write_text(monolithic("import Foundation\nimport Network\nimport Security\nimport Darwin\n"
        "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { nil } }\n"
        + "\n".join(values.values())), encoding="utf-8")
    binary = work / "network-connectivity-diagnostics"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library",
        "-D", "NETWORK_DIAGNOSTICS_TRADITIONAL", str(production), "-o", str(binary),
        "-framework", "Foundation", "-framework", "Network", "-framework", "Security"],
        text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr)
    after = manifest(selected())
    write_source_inventory(work)
    (work / "source-manifest.json").write_text(json.dumps({name: {
        "before": digest, "after": after.get(name), "unchanged": digest == after.get(name)}
        for name, digest in before.items()}, indent=2) + "\n")
    print(result.stdout + result.stderr, end="")
    if before != after:
        raise RuntimeError("tested production or fixture source changed during run")
    if result.returncode:
        raise SystemExit(result.returncode)
    print(f"Exact production declarations unchanged; offline evidence: {work}")


if __name__ == "__main__":
    main()

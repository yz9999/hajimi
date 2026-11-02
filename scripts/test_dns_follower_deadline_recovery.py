#!/usr/bin/env python3
"""Exercise production DNS follower deadline handoff using memory-only peers.

No listener, network, Helper, route, profile, DNS setting or GUI is used.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

from dns_test_sources import PACKAGE_FLAGS, declaration, monolithic, write_source_inventory

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lineage", ROOT / "scripts/test_dns_query_lineage.py")
LINEAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINEAGE)


def chunks() -> dict[str, str]:
    values = LINEAGE.chunks()
    values["transport-evidence"] = declaration("DNSAdaptiveUpstreamSelector.swift", "public enum DNSQueryTransportEvidence:")[1]
    for key in ["lineage-test", "deadline-test", "existing-phase-sequence-tests", "fallback-parent",
                "server", "profile-bound", "selector", "sequence"]:
        del values[key]
    # Compile the exact production declarations; unrelated public self-test
    # bodies are exercised by the separate lineage suite, not this binary.
    for key, marker in [
        ("coordinator", "public enum DNSQueryCoordinatorSelfTest {"),
        ("cache", "public enum DNSQueryCacheSelfTest {"),
        ("diagnostics", "public enum NetworkPerformanceDiagnosticsSelfTest {"),
    ]:
        if values[key].count(marker) != 1:
            raise AssertionError(f"production boundary changed: {marker}")
        values[key] = values[key][:values[key].index(marker)]
    values["recovery-test"] = (ROOT / "SmokeTests/DNSFollowerDeadlineRecoveryMain.swift").read_text()
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-follower-deadline-recovery")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    values = chunks()
    before = LINEAGE.manifest(values)
    (work / "source-manifest.json").write_text(json.dumps(before, indent=2) + "\n")
    production = work / "ProductionFollowerRecovery.swift"
    production.write_text(monolithic("import Foundation\nimport Network\nimport Darwin\n" + "\n".join(
        text for label, text in values.items() if label != "recovery-test")))
    test = work / "DNSFollowerDeadlineRecoveryMain.swift"
    test.write_text(monolithic(values["recovery-test"]))
    binary = work / "dns-follower-deadline-recovery"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-O", "-parse-as-library", str(production), str(test),
        "-o", str(binary), "-framework", "Foundation", "-framework", "Network"],
        text=True, capture_output=True, timeout=240)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(f"follower recovery compile failed; inspect {work / 'compile.log'}")
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=45)
    (work / "results.log").write_text(result.stdout + result.stderr)
    unchanged = before == LINEAGE.manifest(chunks())
    write_source_inventory(work)
    (work / "source-unchanged.json").write_text(json.dumps({"unchanged": unchanged}, indent=2) + "\n")
    if result.returncode:
        raise RuntimeError(f"follower recovery failed; inspect {work / 'results.log'}")
    if not unchanged:
        raise RuntimeError("follower recovery source changed during check; rerun final source")
    print(result.stdout.strip())
    print(f"Artifacts: {work}")


if __name__ == "__main__":
    main()

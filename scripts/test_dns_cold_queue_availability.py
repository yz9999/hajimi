#!/usr/bin/env python3
"""Freeze the real DNS pool and verify scalar hints under queue/cancel pressure.

The only edited input is the older fixture's @main attribute; all production
declarations remain verbatim. Memory peers create no socket or application.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import PACKAGE_FLAGS, monolithic, write_source_inventory
from test_dns_empty_eof_failure import ROOT, chunks, manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-cold-queue-availability")
    parser.add_argument("--encrypted-dns-source", type=Path)
    parser.add_argument("--expected-fresh-retry-reusable", type=int, choices=[0, 1], default=1)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    values = chunks(args.encrypted_dns_source)
    values.pop("smoke-test")
    previous = (ROOT / "SmokeTests/DNSColdDialLimitMain.swift").read_text(encoding="utf-8")
    marker = "@main\nprivate enum DNSColdDialLimitMain {"
    if previous.count(marker) != 1:
        raise AssertionError("cold fixture entrypoint marker changed")
    values["cold-fixture-support"] = previous.replace(marker, "private enum DNSColdDialLimitMain {", 1)
    values["cold-availability-fixture"] = (ROOT / "SmokeTests/DNSColdQueueAvailabilityMain.swift").read_text(encoding="utf-8")
    source = monolithic("import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"
        "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { "
        "preconditionFailure(\"Memory queue fixture attempted direct transport\") } }\n"
        + "\n".join(values.values()))
    frozen = work / "ProductionDNSColdQueueAvailability.swift"
    frozen.write_text(source, encoding="utf-8")
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    provenance = {"frozenInputSHA256": source_hash, "chunks": manifest(values)}
    (work / "source-manifest.json").write_text(json.dumps(provenance, indent=2) + "\n")
    binary = work / "dns-cold-queue-availability"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-Onone", "-parse-as-library",
        "-D", "HAVE_RESOLVER_QUEUE_DIAGNOSTICS", str(frozen), "-o", str(binary),
        "-framework", "Foundation", "-framework", "Network", "-framework", "Security"]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary), "--expected-fresh-retry-reusable", str(args.expected_fresh_retry_reusable)],
                            text=True, capture_output=True, timeout=25, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    if hashlib.sha256(frozen.read_bytes()).hexdigest() != source_hash:
        raise RuntimeError("frozen compilation input changed during test")
    write_source_inventory(work)
    if result.stdout.splitlines():
        report = json.loads(result.stdout.splitlines()[-1])
        (work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if result.returncode:
        raise SystemExit(result.returncode)
    print(f"Frozen production queue availability passed; artifacts: {work}")


if __name__ == "__main__":
    main()

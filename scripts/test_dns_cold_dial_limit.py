#!/usr/bin/env python3
"""Compile frozen real DoH/DoT code; hold memory-only physical dial callbacks.

No full build, application, Helper, listeners or external network is involved.
Each run snapshots its complete compilation input before swiftc starts, so
other agents editing production source cannot change what that run tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from test_dns_empty_eof_failure import chunks, manifest, ROOT
from dns_test_sources import PACKAGE_FLAGS, monolithic, write_source_inventory


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-cold-dial-limit")
    parser.add_argument("--encrypted-dns-source", type=Path)
    parser.add_argument("--archived-production", type=Path,
                        help="existing ProductionDNSEmptyEOF.swift, preserving its original declarations")
    parser.add_argument("--expected-cold-limit", type=int, choices=[4, 16], default=4)
    args = parser.parse_args()
    if args.archived_production and args.encrypted_dns_source:
        parser.error("use either archived production or a source override")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    fixture = (ROOT / "SmokeTests/DNSColdDialLimitMain.swift").read_text(encoding="utf-8")
    if args.archived_production:
        archived = args.archived_production.resolve()
        original = archived.read_text(encoding="utf-8")
        marker = "@main\nprivate enum DNSEmptyEOFFailureMain {"
        if original.count(marker) != 1:
            raise AssertionError("archive must contain the unique original empty-EOF entrypoint")
        prefix = original[:original.index(marker)]
        values = {"archived-production-prefix": prefix, "cold-dial-fixture": fixture}
        source = prefix + fixture
        provenance = {"archive": str(archived), "archiveSHA256": sha256(original)}
    else:
        values = chunks(args.encrypted_dns_source)
        values.pop("smoke-test")
        values["cold-dial-fixture"] = fixture
        source = ("import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"
                  "// Injected memory dialers never read this direct-network accessor.\n"
                  "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { nil } }\n"
                  + "\n".join(values.values()))
        provenance = {"encryptedDNSSource": str(args.encrypted_dns_source or ROOT / "Sources/HajimiCore/EncryptedDNS.swift")}
    frozen = work / "ProductionDNSColdDialLimit.swift"
    source = monolithic(source)
    frozen.write_text(source, encoding="utf-8")
    provenance.update({"frozenInputSHA256": sha256(source), "chunks": manifest(values)})
    (work / "source-manifest.json").write_text(json.dumps(provenance, indent=2) + "\n")
    binary = work / "dns-cold-dial-limit"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library"]
    if "enum DNSResolverQueueReason:" in source:
        command += ["-D", "HAVE_RESOLVER_QUEUE_DIAGNOSTICS"]
    command += [str(frozen), "-o", str(binary), "-framework", "Foundation", "-framework", "Network", "-framework", "Security"]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary), "--expect-cold-limit", str(args.expected_cold_limit)],
                            text=True, capture_output=True, timeout=30, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    if sha256(frozen.read_text(encoding="utf-8")) != provenance["frozenInputSHA256"]:
        raise RuntimeError("the frozen compilation input changed during its run")
    write_source_inventory(work)
    if result.stdout.splitlines():
        report = json.loads(result.stdout.splitlines()[-1])
        (work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if result.returncode:
        raise SystemExit(result.returncode)
    print(f"Frozen real production resolver fixture passed; artifacts: {work}")


if __name__ == "__main__":
    main()

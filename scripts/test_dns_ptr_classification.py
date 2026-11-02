#!/usr/bin/env python3
"""Check fixed PTR target labels through real wire, resolver and JSON code.

Production declarations are verbatim. Every dial is a memory callback and the
unused native-interface accessor fails immediately if reached. No socket,
application, Helper, DNS/proxy/route setting or public network is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import PACKAGE_FLAGS, declaration, monolithic, write_source_inventory
from test_dns_empty_eof_failure import ROOT, chunks, manifest


def selected(baseline: Path | None) -> dict[str, str]:
    values = chunks(baseline / "EncryptedDNS.swift" if baseline else None)
    values.pop("smoke-test")
    if baseline:
        for filename in ("DNSMessageInspection.swift", "NetworkPerformanceDiagnostics.swift"):
            values[filename] = (baseline / filename).read_text(encoding="utf-8")
    values["real-fake-ip-allocator"] = declaration("FakeIP.swift", "public final class FakeIPAllocator {")[1]
    values["ptr-classification-fixture"] = (ROOT / "SmokeTests/DNSPTRClassificationMain.swift").read_text(encoding="utf-8")
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-ptr-classification")
    parser.add_argument("--baseline-directory", type=Path)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    baseline = args.baseline_directory.resolve() if args.baseline_directory else None
    values = selected(baseline)
    before = manifest(values)
    source = monolithic("import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"
        "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { "
        "preconditionFailure(\"Memory PTR fixture attempted native transport\") } }\n"
        + "\n".join(values.values()))
    frozen = work / "ProductionDNSPTRClassification.swift"
    frozen.write_text(source, encoding="utf-8")
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    provenance = {"frozenInputSHA256": source_hash, "chunks": before, "baselineDirectory": str(baseline) if baseline else None}
    if baseline:
        provenance["baselineSources"] = {filename: hashlib.sha256((baseline / filename).read_bytes()).hexdigest()
            for filename in ("EncryptedDNS.swift", "DNSMessageInspection.swift", "NetworkPerformanceDiagnostics.swift")}
    (work / "source-manifest.json").write_text(json.dumps(provenance, indent=2) + "\n")
    binary = work / "dns-ptr-classification"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library"]
    if not baseline:
        command += ["-D", "HAVE_PTR_CLASSIFICATION"]
    compiled = subprocess.run(command + [str(frozen), "-o", str(binary), "-framework", "Foundation",
        "-framework", "Network", "-framework", "Security"], text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    if hashlib.sha256(frozen.read_bytes()).hexdigest() != source_hash:
        raise RuntimeError("frozen compiler input changed during the test")
    if before != manifest(selected(baseline)):
        raise RuntimeError("tested input changed during the test")
    write_source_inventory(work)
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if baseline:
        if result.returncode != 1 or set(report["failedGroups"]) != set(report["metadataGroups"]):
            raise RuntimeError("baseline did not fail exactly for absent PTR metadata")
        print("PASS Build36 negative control: missing PTR categories reproduced; wire, acceptance, cancellation and legacy decoding unchanged")
    elif result.returncode:
        raise SystemExit(result.returncode)
    print(f"Frozen PTR diagnostic input checked; artifacts: {work}")


if __name__ == "__main__":
    main()

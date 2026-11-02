#!/usr/bin/env python3
"""Check per-lease DNS I/O and query metadata through real memory-only pools.

The production request, pool, connection broker and diagnostic recorder are
extracted verbatim. Observable memory streams model independent raw/TLS/read
callbacks; no native network API, App, Helper or system setting is invoked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import PACKAGE_FLAGS, monolithic, write_source_inventory
from test_dns_empty_eof_failure import ROOT, chunks, manifest


def selected() -> dict[str, str]:
    values = chunks()
    values.pop("smoke-test")
    values["query-io-fixture"] = (ROOT / "SmokeTests/DNSQueryIOProgressMain.swift").read_text(encoding="utf-8")
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-query-io-progress")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    values = selected()
    before = manifest(values)
    source = monolithic("import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"
        "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { "
        "preconditionFailure(\"Memory DNS I/O fixture attempted native transport\") } }\n"
        + "\n".join(values.values()))
    generated = work / "ProductionDNSQueryIOProgress.swift"
    generated.write_text(source, encoding="utf-8")
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    script_paths = [Path(__file__).resolve(), ROOT / "scripts/test_dns_empty_eof_failure.py",
                    ROOT / "scripts/dns_test_sources.py"]
    scripts = {str(path): path.read_bytes() for path in script_paths}
    provenance = {"frozenInputSHA256": source_hash, "chunks": before,
                  "scripts": {name: hashlib.sha256(data).hexdigest() for name, data in scripts.items()}}
    (work / "source-manifest.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-query-io-progress"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O",
        "-parse-as-library", str(generated), "-o", str(binary), "-framework", "Foundation",
        "-framework", "Network", "-framework", "Security"], text=True, capture_output=True,
        timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=45, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout + result.stderr, end="")
    unchanged = before == manifest(selected()) and all(Path(name).read_bytes() == data for name, data in scripts.items())
    if hashlib.sha256(generated.read_bytes()).hexdigest() != source_hash:
        raise RuntimeError("Frozen DNS I/O compiler input changed")
    write_source_inventory(work)
    (work / "source-unchanged.json").write_text(json.dumps({"unchanged": unchanged}, indent=2) + "\n", encoding="utf-8")
    if not unchanged:
        raise RuntimeError("DNS I/O production/test input changed during the run")
    if result.returncode:
        raise SystemExit(result.returncode)
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Exact production DNS I/O inputs unchanged; artifacts={work}")


if __name__ == "__main__":
    main()

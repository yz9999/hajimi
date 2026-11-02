#!/usr/bin/env python3
"""Verify fixed PTR query-shape metadata using the exact wire inspector.

Every input and answer is an in-memory DNS packet. No sockets, application,
Helper, external resolver or system network configuration are involved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import PACKAGE_FLAGS, source_path, source_text, write_source_inventory


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-ptr-query-shape")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    source = source_path("DNSMessageInspection.swift")
    harness = ROOT / "SmokeTests/DNSPTRQueryShapeMain.swift"
    inputs = [(source, source_text("DNSMessageInspection.swift")),
              (harness, harness.read_text(encoding="utf-8")),
              (Path(__file__).resolve(), Path(__file__).read_text(encoding="utf-8")),
              (ROOT / "scripts/dns_test_sources.py", (ROOT / "scripts/dns_test_sources.py").read_text(encoding="utf-8"))]
    manifest = [{"source": str(path), "wholeFile": True,
                 "sha256": hashlib.sha256(text.encode()).hexdigest(), "unchanged": True}
                for path, text in inputs]
    generated = work / "ProductionDNSPTRQueryShape.swift"
    generated.write_text(inputs[0][1] + "\n" + inputs[1][1], encoding="utf-8")
    manifest_path = work / "source-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-ptr-query-shape"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O",
                               "-parse-as-library", str(generated), "-framework", "Foundation", "-o", str(binary)],
                              text=True, capture_output=True, timeout=120, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    completed = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20, check=False)
    (work / "results.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    print(completed.stdout + completed.stderr, end="")
    for row, (path, text) in zip(manifest, inputs):
        row["unchanged"] = path.read_text(encoding="utf-8") == text
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("PTR shape test inputs changed during the run")
    if completed.returncode:
        raise SystemExit(completed.returncode)
    report = json.loads(completed.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Exact production wire source unchanged; manifest={manifest_path}")


if __name__ == "__main__":
    main()

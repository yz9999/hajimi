#!/usr/bin/env python3
"""Replay mixed forward/PTR DNS queries through exact production scheduling.

All peers, clocks and pool availability are in memory. A frozen ProxyEngine
input supplies an actual before/after control; no production body is patched.
The existing cold-admission harness is reused only as test support, with its
entry point removed. No socket, App, Helper or system network setting is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from dns_test_sources import (PACKAGE_FLAGS, declaration, declaration_match,
                              monolithic, source_path, source_text,
                              write_source_inventory)
from test_dns_progress_rotation import DECLARATIONS, WHOLE_FILES


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path,
                        default=ROOT / ".build/dns-query-health-isolation")
    parser.add_argument("--proxy-engine-source", type=Path,
                        help="unmodified ProxyEngine.swift or frozen declaration bundle")
    parser.add_argument("--expect", choices=["before", "after"], default="after")
    args = parser.parse_args()
    if args.expect == "before" and not args.proxy_engine_source:
        parser.error("--expect before requires --proxy-engine-source")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    frozen_path = args.proxy_engine_source.resolve() if args.proxy_engine_source else None
    frozen_text = frozen_path.read_text(encoding="utf-8") if frozen_path else None
    manifest: list[dict] = []
    snapshots: list[tuple[Path, str]] = []

    def retain(path: Path, value: str, *, marker: str | None = None,
               start: int = 0, full: str | None = None, support: bool = False) -> str:
        original = value if full is None else full
        row = {"source": str(path), "sha256": hashlib.sha256(value.encode()).hexdigest(),
               "sourceSHA256": hashlib.sha256(original.encode()).hexdigest(),
               "unchanged": True, "frozenProxyEngine": path == frozen_path}
        if marker:
            row.update(marker=marker, firstLine=original[:start].count("\n") + 1)
        else:
            row["wholeFile"] = True
        if support:
            row["testSupportEntryPointRemoved"] = True
        manifest.append(row)
        snapshots.append((path, original))
        return f"\n// Verbatim {path.name}; SHA256 {row['sha256']}\n{value}"

    code = ["import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"]
    for filename, marker in DECLARATIONS:
        if filename == "ProxyEngine.swift" and frozen_path:
            assert frozen_text is not None
            match = declaration_match(frozen_text, marker)
            if match is None:
                raise RuntimeError(f"Missing frozen declaration: {marker}")
            finish = re.search(r"^}\n", frozen_text[match.end():], re.M)
            if finish is None:
                raise RuntimeError(f"Unterminated frozen declaration: {marker}")
            value = frozen_text[match.start():match.end() + finish.end()]
            code.append(retain(frozen_path, value, marker=marker,
                               start=match.start(), full=frozen_text))
        else:
            path, value, start = declaration(filename, marker)
            code.append(retain(path, value, marker=marker, start=start,
                               full=path.read_text(encoding="utf-8")))
    for filename in WHOLE_FILES:
        code.append(retain(source_path(filename), source_text(filename)))

    support_path = ROOT / "SmokeTests/DNSColdProviderAdmissionMain.swift"
    original_support = support_path.read_text(encoding="utf-8")
    marker = "@main private enum DNSColdProviderAdmissionMain {"
    if original_support.count(marker) != 1:
        raise RuntimeError("Cold-admission support entry point changed")
    support = original_support.replace(marker, "private enum DNSColdProviderAdmissionMain {", 1)
    code.append(retain(support_path, support, full=original_support, support=True))
    harness_path = ROOT / "SmokeTests/DNSQueryHealthIsolationMain.swift"
    code.append(retain(harness_path, harness_path.read_text(encoding="utf-8")))
    for path in (Path(__file__).resolve(), ROOT / "scripts/test_dns_progress_rotation.py",
                 ROOT / "scripts/dns_test_sources.py"):
        retain(path, path.read_text(encoding="utf-8"))

    generated = work / "ProductionDNSQueryHealthIsolation.swift"
    generated.write_text(monolithic("\n".join(code)), encoding="utf-8")
    manifest_path = work / "source-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-query-health-isolation"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-Onone",
               "-parse-as-library", str(generated), "-framework", "Foundation",
               "-framework", "Network", "-framework", "Security", "-o", str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr)[-16000:])
        raise SystemExit(compiled.returncode)
    completed = subprocess.run([str(binary), args.expect], text=True, capture_output=True,
                               timeout=30, check=False)
    (work / "results.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    print(completed.stdout + completed.stderr, end="")
    for row, (path, original) in zip(manifest, snapshots):
        row["unchanged"] = path.read_text(encoding="utf-8") == original
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("Test inputs changed during the replay; rerun a coherent snapshot")
    print(f"Exact production inputs unchanged; manifest={manifest_path}")
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise production DNS selection and its coordinator/adaptive consumers in memory.

--before-selector can select an exact frozen selector source for a before audit.
All other production declarations are extracted verbatim from current Sources.
The fixture opens no socket and touches no Helper, profile or network setting.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from test_dns_progress_rotation import DECLARATIONS, WHOLE_FILES
from dns_test_sources import (PACKAGE_FLAGS, declaration, monolithic,
                              source_path, source_text, write_source_inventory)

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "Sources/HajimiCore"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-verified-preference")
    parser.add_argument("--before-selector", type=Path)
    parser.add_argument("--expect", choices=["before", "after"], default="after")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    originals: dict[Path, str] = {}
    manifest: list[dict] = []
    snapshots: list[tuple[Path, str]] = []

    def source(filename: str) -> str:
        path = source_path(filename)
        if path not in originals:
            originals[path] = source_text(filename)
        return originals[path]

    def retain(path: Path, text: str, marker: str | None = None, start: int = 0) -> str:
        digest = hashlib.sha256(text.encode()).hexdigest()
        row = {"source": str(path), "sha256": digest, "unchanged": True}
        if marker:
            row.update(marker=marker, firstLine=originals[path][:start].count("\n") + 1)
        else:
            row["wholeFile"] = True
        manifest.append(row); snapshots.append((path, text))
        return f"\n// Verbatim {path.name}; SHA256 {digest}\n{text}"

    code = ["import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"]
    extra = [("DNSQueryCoordinator.swift", "final class DNSQueryCoordinator {"),
             ("DNSQueryCoordinator.swift", "final class DNSCoalescedQueryDatagram:"),
             ("DNSQueryCoordinator.swift", "private struct DNSQueryCoordinationError:"),
             ("DNSQueryCache.swift", "public final class DNSQueryCache {")]
    for filename, marker in DECLARATIONS + extra:
        path, text, start = declaration(filename, marker)
        source(filename)
        code.append(retain(path, text, marker, start))
    code.append(retain(source_path("DNSQueryModuleAdapter.swift"), source("DNSQueryModuleAdapter.swift")))
    for filename in WHOLE_FILES:
        if filename == "DNSAdaptiveUpstreamSelector.swift" and args.before_selector:
            path = args.before_selector.resolve()
            code.append(retain(path, path.read_text(encoding="utf-8")))
        else:
            retained = retain(source_path(filename), source(filename))
            if filename == "DNSQueryContracts.swift" and args.before_selector:
                # A pre-module selector already carries this exact capability.
                # Select only one declaration in the combined legacy fixture;
                # both original whole inputs remain present in the manifest.
                legacy = args.before_selector.read_text(encoding="utf-8")
                if "protocol DNSQueryTransportEvidenceProviding:" in legacy:
                    duplicate = declaration("DNSQueryContracts.swift", "protocol DNSQueryTransportEvidenceProviding:")[1]
                    retained = retained.replace(duplicate, "", 1)
            code.append(retained)
    harness = ROOT / "SmokeTests/DNSVerifiedPreferenceMain.swift"
    code.append(retain(harness, harness.read_text(encoding="utf-8")))
    for path in [Path(__file__).resolve(), ROOT / "scripts/test_dns_progress_rotation.py"]:
        retain(path, path.read_text(encoding="utf-8"))
    generated = work / "ProductionDNSVerifiedPreference.swift"
    generated.write_text(monolithic("\n".join(code)), encoding="utf-8")
    manifest_path = work / "source-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-verified-preference"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-Onone", "-parse-as-library",
               str(generated), "-framework", "Foundation", "-framework", "Network",
               "-framework", "Security", "-o", str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr)[-16000:])
        raise SystemExit(compiled.returncode)
    completed = subprocess.run([str(binary), args.expect], text=True, capture_output=True, timeout=20, check=False)
    (work / "results.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    print(completed.stdout + completed.stderr, end="")
    current = {path: path.read_text(encoding="utf-8") for path, _ in snapshots}
    for row, (path, text) in zip(manifest, snapshots):
        row["unchanged"] = text in current[path]
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    protected = {"DNSAdaptiveUpstreamSelector.swift", "DNSQueryCoordinator.swift", "DNSVerifiedPreferenceMain.swift"}
    changed = [row for row in manifest if not row["unchanged"]]
    if any(Path(row["source"]).name in protected or row.get("marker", "").startswith("private final class DNSAdaptiveQueryDatagram:")
           for row in changed):
        raise RuntimeError("A tested selection/coordinator/adaptive declaration changed during the audit")
    print(f"Subject declarations unchanged; supporting snapshots changed live={len(changed)}; manifest={manifest_path}")
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()

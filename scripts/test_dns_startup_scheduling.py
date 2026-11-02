#!/usr/bin/env python3
"""Exercise real global/adaptive/provider-pool DNS startup scheduling in memory.

The eight-second production deadlines and all production concurrency limits
remain unchanged. Only the metadata dialer and authenticated HTTP byte peer
are controlled. No SwiftPM build, socket, GUI, Helper or system setting is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import (PACKAGE_FLAGS, declaration, monolithic,
                              source_path, source_text, write_source_inventory)
from test_dns_handoff_window import EXTRA_DECLARATIONS
from test_dns_progress_rotation import DECLARATIONS, WHOLE_FILES

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-startup-scheduling")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    snapshots: list[tuple[Path, str]] = []
    rows: list[dict] = []

    def retain(path: Path, text: str, marker: str | None = None) -> str:
        rows.append({"source": str(path.relative_to(ROOT)), "marker": marker,
                     "sha256": hashlib.sha256(text.encode()).hexdigest()})
        snapshots.append((path, text))
        return f"\n// Verbatim {path.name}; SHA256 {rows[-1]['sha256']}\n{text}"

    code = ["import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"]
    selected = DECLARATIONS + EXTRA_DECLARATIONS + [
        ("DNSConnectionPrewarming.swift", "protocol DNSConnectionPrewarming:"),
        ("EncryptedDNS.swift", "public final class DoHRoutedDatagram:"),
        ("EncryptedDNS.swift", "private final class EncryptedDNSDatagramFlow {"),
    ]
    for filename, marker in selected:
        path, text, _ = declaration(filename, marker)
        code.append(retain(path, text, marker))
    for filename in ["DNSQueryModuleAdapter.swift", *WHOLE_FILES]:
        code.append(retain(source_path(filename), source_text(filename)))
    encrypted = source_text("EncryptedDNS.swift")
    start = encrypted.index("public typealias EncryptedDNSStreamDialer = (")
    end = encrypted.index("/// Native metadata admission", start)
    code.append(retain(source_path("EncryptedDNS.swift"), encrypted[start:end], "stream dialer typealiases"))
    harness = ROOT / "SmokeTests/DNSStartupSchedulingMain.swift"
    code.append(retain(harness, harness.read_text(encoding="utf-8")))
    for path in [Path(__file__).resolve(), ROOT / "scripts/test_dns_handoff_window.py",
                 ROOT / "scripts/test_dns_progress_rotation.py", ROOT / "scripts/dns_test_sources.py"]:
        retain(path, path.read_text(encoding="utf-8"))

    production = work / "ProductionDNSStartupScheduling.swift"
    production.write_text(monolithic("\n".join(code)), encoding="utf-8")
    (work / "source-manifest.json").write_text(json.dumps(rows, indent=2) + "\n")
    binary = work / "dns-startup-scheduling"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-Onone",
        "-parse-as-library", str(production), "-framework", "Foundation", "-framework", "Network",
        "-framework", "Security", "-o", str(binary)], text=True, capture_output=True, timeout=180)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr)[-18000:])
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=55)
    (work / "results.log").write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    for row, (path, text) in zip(rows, snapshots):
        row["unchanged"] = text in path.read_text(encoding="utf-8")
    (work / "source-manifest.json").write_text(json.dumps(rows, indent=2) + "\n")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in rows):
        raise RuntimeError("tested declarations or fixtures changed during this run; rerun a frozen snapshot")
    if result.returncode:
        raise SystemExit(result.returncode)
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Frozen production startup scheduling passed; artifacts: {work}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise exact production adaptive DNS SERVFAIL scheduling in memory.

The optional --before-archive uses exact source files from the Build19 baseline
tar, rather than synthesizing the previous behavior by changing production text.
No sockets, GUI, Helper, profile, network or operating-system settings are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile

from test_dns_progress_rotation import DECLARATIONS, WHOLE_FILES, LEGACY_CONTRACT_DECLARATIONS
from dns_test_sources import (PACKAGE_FLAGS, declaration, monolithic,
                              source_path, source_text, write_source_inventory)

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "Sources/HajimiCore"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-servfail-diversity")
    parser.add_argument("--before-archive", type=Path)
    parser.add_argument("--expect", choices=["before", "after"], default="after")
    args = parser.parse_args()
    if (args.expect == "before") != bool(args.before_archive):
        parser.error("before requires --before-archive, after uses current production sources")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    frozen: dict[str, str] = {}
    if args.before_archive:
        with tarfile.open(args.before_archive.resolve()) as archive:
            for member in archive.getmembers():
                if member.isfile() and member.name.startswith("Sources/HajimiCore/"):
                    frozen[Path(member.name).name] = archive.extractfile(member).read().decode("utf-8")
    originals: dict[str, str] = {}
    manifest: list[dict] = []
    snapshots: list[tuple[Path, str, bool]] = []

    def source(filename: str) -> str:
        if filename not in originals:
            originals[filename] = frozen.get(filename) or source_text(filename)
        return originals[filename]

    def retain(path: Path, text: str, marker: str | None = None, start: int = 0,
               is_frozen: bool = False) -> str:
        digest = hashlib.sha256(text.encode()).hexdigest()
        row = {"source": str(path), "sha256": digest, "unchanged": True,
               "frozenBuild19": is_frozen}
        if marker:
            row.update(marker=marker, firstLine=originals[path.name][:start].count("\n") + 1)
        else:
            row["wholeFile"] = True
        manifest.append(row); snapshots.append((path, text, is_frozen))
        return f"\n// Verbatim {path.name}; SHA256 {digest}\n{text}"

    code = ["import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"]
    declarations = DECLARATIONS + (LEGACY_CONTRACT_DECLARATIONS if frozen else [])
    for filename, marker in declarations:
        text = source(filename)
        if filename in frozen:
            matches = list(re.finditer(r"^" + re.escape(marker) + r"[^\n]*\n", text, re.M))
            if len(matches) != 1:
                raise RuntimeError(f"Missing frozen declaration: {filename}: {marker}")
            start = matches[0].start()
            finish = re.search(r"^}\n", text[matches[0].end():], re.M)
            if finish is None:
                raise RuntimeError(f"Missing frozen declaration end: {filename}: {marker}")
            end = matches[0].end() + finish.end()
            code.append(retain(CORE / filename, text[start:end], marker, start, True))
        else:
            path, text, start = declaration(filename, marker)
            code.append(retain(path, text, marker, start))
    for filename in WHOLE_FILES:
        if frozen and filename == "DNSQueryContracts.swift":
            continue
        path = CORE / filename if filename in frozen else source_path(filename)
        code.append(retain(path, source(filename), is_frozen=filename in frozen))
    harness = ROOT / "SmokeTests/DNSServfailDiversityMain.swift"
    code.append(retain(harness, harness.read_text(encoding="utf-8")))
    for path in [Path(__file__).resolve(), ROOT / "scripts/test_dns_progress_rotation.py"]:
        retain(path, path.read_text(encoding="utf-8"))
    generated = work / "ProductionDNSServfailDiversity.swift"
    generated.write_text(monolithic("\n".join(code)), encoding="utf-8")
    manifest_path = work / "source-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-servfail-diversity"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-Onone", "-parse-as-library"]
    if args.expect == "after":
        command += ["-D", "BUILD20_SERVFAIL_SERVICE_GROUPS"]
    command += [str(generated), "-framework", "Foundation", "-framework", "Network",
                "-framework", "Security", "-o", str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr)[-16000:])
        raise SystemExit(compiled.returncode)
    completed = subprocess.run([str(binary), args.expect], text=True, capture_output=True, timeout=20, check=False)
    (work / "results.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    print(completed.stdout + completed.stderr, end="")
    current = {path: path.read_text(encoding="utf-8") for path, _, is_frozen in snapshots if not is_frozen}
    for row, (path, text, is_frozen) in zip(manifest, snapshots):
        row["unchanged"] = text in (frozen[path.name] if is_frozen else current[path])
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("Tested production declarations changed during the audit; rerun a coherent snapshot")
    print(f"Production declarations unchanged; manifest={manifest_path}")
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()

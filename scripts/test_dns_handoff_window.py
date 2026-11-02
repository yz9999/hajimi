#!/usr/bin/env python3
"""Run current production DNS pool + adaptive/coordinator against memory streams.

The before case explicitly supplies 250ms (unchanged by the current clamp);
the after case calls the real DoT initializer without a grace argument.
No socket, Helper, GUI, profile, or system network setting is touched.
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
EXTRA_DECLARATIONS = [
    ("NativeOutbound.swift", "public protocol NativeOutboundByteStream:"),
    ("NativeOutbound.swift", "protocol NativeOutboundFailureObservingByteStream:"),
    ("SOCKSUDPResources.swift", "enum SOCKSUDPResourceLimits {"),
    ("SOCKSUDPResources.swift", "final class SOCKSUDPReservation {"),
    ("SOCKSUDPResources.swift", "final class SOCKSUDPGlobalBudget {"),
    ("Profile.swift", "public struct DNSProxyFallbackServer:"),
    ("DNSQueryCoordinator.swift", "final class DNSQueryCoordinator {"),
    ("DNSQueryCoordinator.swift", "final class DNSCoalescedQueryDatagram:"),
    ("DNSQueryCoordinator.swift", "private struct DNSQueryCoordinationError:"),
    ("DNSQueryCache.swift", "public final class DNSQueryCache {"),
    ("EncryptedDNS.swift", "private final class EncryptedDNSFailureAdmission {"),
    ("EncryptedDNS.swift", "public final class DoHResolver {"),
    ("EncryptedDNS.swift", "private enum EncryptedDNSProtocol {"),
    ("EncryptedDNS.swift", "private final class EncryptedDNSConnectionStore {"),
    ("EncryptedDNS.swift", "private func encryptedDNSDirectTLSStateHandler("),
    ("EncryptedDNS.swift", "private final class EncryptedDNSPooledConnection {"),
    ("EncryptedDNS.swift", "private final class EncryptedDNSRequestPool {"),
    ("EncryptedDNS.swift", "private final class EncryptedDNSRequest {"),
    ("EncryptedDNS.swift", "private final class EncryptedDNSNetworkStream:"),
    ("EncryptedDNS.swift", "private enum DoHHTTPWire {"),
    ("EncryptedDNS.swift", "private struct DoHHTTPResponseParser {"),
    ("EncryptedDNS.swift", "public final class DoTResolver {"),
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-handoff-window")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    originals: dict[Path, str] = {}
    snapshots: list[tuple[Path, str]] = []
    manifest: list[dict] = []

    def source(filename: str) -> str:
        path = source_path(filename)
        if path not in originals:
            originals[path] = source_text(filename)
        return originals[path]

    def retain(path: Path, text: str, marker: str | None = None, start: int = 0) -> str:
        digest = hashlib.sha256(text.encode()).hexdigest()
        row = {"source": str(path.relative_to(ROOT)), "sha256": digest, "unchanged": True}
        if marker:
            row.update(marker=marker, firstLine=originals[path][:start].count("\n") + 1)
        else:
            row["wholeFile"] = True
        manifest.append(row); snapshots.append((path, text))
        return f"\n// Verbatim {path.name}; SHA256 {digest}\n{text}"

    code = ["import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"]
    for filename, marker in DECLARATIONS + EXTRA_DECLARATIONS:
        path, text, start = declaration(filename, marker)
        source(filename)
        code.append(retain(path, text, marker, start))
    code.append(retain(source_path("DNSQueryModuleAdapter.swift"), source("DNSQueryModuleAdapter.swift")))
    text = source("EncryptedDNS.swift")
    start = text.index("public typealias EncryptedDNSStreamDialer = (")
    end = text.index("/// Native metadata admission", start)
    code.append(retain(source_path("EncryptedDNS.swift"), text[start:end], "encrypted stream dialer typealiases", start))
    for filename in WHOLE_FILES:
        code.append(retain(source_path(filename), source(filename)))
    harness = ROOT / "SmokeTests/DNSHandoffWindowMain.swift"
    code.append(retain(harness, harness.read_text(encoding="utf-8")))
    for path in [Path(__file__).resolve(), ROOT / "scripts/test_dns_progress_rotation.py"]:
        retain(path, path.read_text(encoding="utf-8"))

    generated = work / "ProductionDNSHandoffWindow.swift"
    generated.write_text(monolithic("\n".join(code)), encoding="utf-8")
    manifest_path = work / "source-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-handoff-window"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-Onone", "-parse-as-library",
               str(generated), "-framework", "Foundation", "-framework", "Network",
               "-framework", "Security", "-o", str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr)[-16000:])
        raise SystemExit(compiled.returncode)
    completed = subprocess.run([str(binary)], text=True, capture_output=True, timeout=15, check=False)
    (work / "results.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    print(completed.stdout + completed.stderr, end="")
    current = {path: path.read_text(encoding="utf-8") for path, _ in snapshots}
    for row, (path, text) in zip(manifest, snapshots):
        row["unchanged"] = text in current[path]
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("Tested source changed during the audit; rerun for a coherent snapshot")
    print(f"Production source unchanged; manifest={manifest_path}")
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()

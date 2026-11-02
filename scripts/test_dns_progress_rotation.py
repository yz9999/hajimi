#!/usr/bin/env python3
"""Run production DNS rotation/progress state machines against memory peers.

The Swift harness uses an injected monotonic clock and calls the production
timer callbacks on their owning queue. No external DNS, listener, network,
GUI, Helper, profile or system setting is touched. Production declarations
are extracted verbatim; a manifest records the exact tested source snapshot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from dns_test_sources import (PACKAGE_FLAGS, declaration, monolithic,
                              source_path, source_text, write_source_inventory)


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "Sources/HajimiCore"
LEGACY_CONTRACT_DECLARATIONS = [
    ("DNSQueryCoordinator.swift", "protocol DNSQueryDeadlineAwareDatagram:"),
    ("DNSQueryCoordinator.swift", "protocol DNSQueryDeadlineAcknowledging:"),
    ("SecureDNSProxyFallback.swift", "protocol DNSQueryCancellationAcknowledging:"),
    ("SecureDNSProxyFallback.swift", "extension DNSQueryCancellationAcknowledging {"),
    ("SecureDNSProxyFallback.swift", "protocol DNSQueryPhaseDeadlineAcknowledging:"),
    ("SecureDNSProxyFallback.swift", "protocol DNSQueryEncryptedPhaseScheduling:"),
    ("SecureDNSProxyFallback.swift", "enum DNSProxyFallbackBarrier {"),
    ("SecureDNSProxyFallback.swift", "protocol DNSProxyFallbackBarrierProviding:"),
]
DECLARATIONS = [
    ("ProxyEngine.swift", "public protocol NativeRoutedDatagram:"),
    ("DNSQueryCoordinator.swift", "struct DNSQueryTimeoutError:"),
    ("RoutingTypes.swift", "public struct RequestTarget:"),
    ("EncryptedDNS.swift", "public enum EncryptedDNSBootstrap {"),
    ("EncryptedDNS.swift", "public struct DoHEndpoint:"),
    ("EncryptedDNS.swift", "public struct DoTEndpoint:"),
    ("ProxyEngine.swift", "private enum DNSConfiguredUpstream {"),
    ("ProxyEngine.swift", "private struct DNSBootstrapConfiguration:"),
    ("ProxyEngine.swift", "private struct DNSUpstreamCandidate {"),
    ("ProxyEngine.swift", "private enum DNSPolicyFailure:"),
    ("ProxyEngine.swift", "private struct EngineError:"),
    ("LiteralAddressAttemptCoordinator.swift", "public enum NodeConnectionAdmissionError:"),
    ("TraditionalDNSResolver.swift", "enum TraditionalDNSBootstrapError:"),
    ("NativeOutbound.swift", "enum NativeOutboundError:"),
    ("NativeOutbound.swift", "func nativeDebug("),
    ("EncryptedDNS.swift", "enum EncryptedDNSQueryFailure:"),
    ("ProxyEngine.swift", "private final class DNSAdaptiveQueryDatagram:"),
    ("SecureDNSProxyFallback.swift", "enum DNSProxyFallbackBudget {"),
    ("SecureDNSProxyFallback.swift", "final class DNSProxyFallbackQueryDatagram:"),
]
WHOLE_FILES = [
    "DNSQueryContracts.swift",
    "NetworkPerformanceDiagnostics.swift",
    "DNSQueryExecutionContext.swift",
    "DNSAdaptiveUpstreamSelector.swift",
    "DNSMessageInspection.swift",
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-progress-rotation")
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

    def retain(filename: str, text: str, marker: str | None, start: int = 0) -> str:
        first_line = source(filename)[:start].count("\n") + 1
        digest = hashlib.sha256(text.encode()).hexdigest()
        path = source_path(filename)
        row = {"source": str(path.relative_to(ROOT)),
               "sha256": digest, "unchanged": True}
        if marker is None:
            row["wholeFile"] = True
        else:
            row.update(marker=marker, firstLine=first_line,
                       lastLine=first_line + text.count("\n") - 1)
        manifest.append(row)
        snapshots.append((path, text))
        return f"\n// Verbatim {filename}:{first_line}; SHA256 {digest}\n{text}"

    code = ["import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"]
    for filename, marker in DECLARATIONS:
        _, text, start = declaration(filename, marker)
        code.append(retain(filename, text, marker, start))
    for filename in WHOLE_FILES:
        code.append(retain(filename, source(filename), None))

    harness = ROOT / "SmokeTests/DNSProgressRotationMain.swift"
    harness_source = harness.read_text(encoding="utf-8")
    manifest.append({"source": str(harness.relative_to(ROOT)), "wholeFile": True,
                     "sha256": hashlib.sha256(harness_source.encode()).hexdigest(), "unchanged": True})
    snapshots.append((harness, harness_source))
    code.append("\n// Test-only private-access adapters and memory peers.\n" + harness_source)
    generated = work / "ProductionDNSProgressRotation.swift"
    generated.write_text(monolithic("\n".join(code)), encoding="utf-8")
    manifest_path = work / "source-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    binary = work / "dns-progress-rotation"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library",
               str(generated), "-framework", "Foundation", "-framework", "Network",
               "-framework", "Security", "-o", str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr)[-16000:])
        raise SystemExit(compiled.returncode)
    completed = subprocess.run([str(binary)], text=True, capture_output=True, timeout=15, check=False)
    (work / "results.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="")
    current = {path: path.read_text(encoding="utf-8") for path, _ in snapshots}
    for row, (path, text) in zip(manifest, snapshots):
        row["unchanged"] = text in current[path]
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("A tested production declaration changed during this audit; rerun for a coherent snapshot")
    print(f"Production source unchanged; manifest={manifest_path}")
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()

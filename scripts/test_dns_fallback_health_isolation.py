#!/usr/bin/env python3
"""Run the exact proxy fallback sequence against memory-only health fixtures.

No sockets, App/GUI, Helper, TUN, user configuration or system network writes.
There is no reconstructed baseline or edited production declaration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import (PACKAGE_FLAGS, declaration, monolithic,
                              source_path, source_text, write_source_inventory)
from test_dns_fallback_deadline_health import section


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path,
                        default=ROOT / ".build/dns-fallback-health-isolation")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    secure = source_text("SecureDNSProxyFallback.swift")
    profile = source_text("Profile.swift")
    chunks = {
        "datagram": section(source_text("ProxyEngine.swift"), "public protocol NativeRoutedDatagram:", "private final class DirectRoutedDatagram:"),
        "deadline-protocol": declaration("DNSQueryCoordinator.swift", "struct DNSQueryTimeoutError:")[1],
        "fallback-protocols": source_text("DNSQueryContracts.swift"),
        "fallback-parent": section(secure, "enum DNSProxyFallbackBudget {", "/// Pure memory/clock/crypto-configuration checks."),
        "server": section(profile, "public struct DNSProxyFallbackServer:", "public enum DNSProxyFallbackValidationError:"),
        "native-error": section(source_text("NativeOutbound.swift"), "enum NativeOutboundError:", "extension NativeOutboundFactory {\n    /// Exercises the production prepared"),
        "node-admission": section(source_text("LiteralAddressAttemptCoordinator.swift"), "public enum NodeConnectionAdmissionError:", "enum LiteralAddressAttemptClock"),
        "bootstrap-error": section(source_text("TraditionalDNSResolver.swift"), "enum TraditionalDNSBootstrapError:", "/// Internal wire injection"),
        "classifier": section(source_text("EncryptedDNS.swift"), "enum EncryptedDNSQueryFailure:", "/// Bootstrap addresses for endpoints"),
    }
    maximum = next(line.strip() for line in profile.splitlines()
                   if "static let maximumDNSProxyFallbackServers =" in line)
    chunks["profile-bound"] = "enum Profile { " + maximum + " }\n"
    for label, filename in [
        ("selector", "DNSAdaptiveUpstreamSelector.swift"),
        ("execution-context", "DNSQueryExecutionContext.swift"),
        ("wire", "DNSMessageInspection.swift"),
        ("diagnostics", "NetworkPerformanceDiagnostics.swift"),
        ("sequence", "DNSProxyFallbackResolverSequence.swift"),
    ]:
        chunks[label] = source_text(filename)
    inputs = [ROOT / "SmokeTests/DNSFallbackHealthIsolationMain.swift",
              Path(__file__).resolve(), ROOT / "scripts/dns_test_sources.py",
              ROOT / "scripts/test_dns_fallback_deadline_health.py"]
    snapshots = {path: path.read_text(encoding="utf-8") for path in inputs}
    production = work / "ProductionFallbackHealthIsolation.swift"
    production.write_text(monolithic("import Foundation\nimport Network\nimport Darwin\n"
                                     + "\n".join(chunks.values())), encoding="utf-8")
    entry = work / "DNSFallbackHealthIsolationMain.swift"
    entry.write_text(snapshots[inputs[0]], encoding="utf-8")
    manifest = {
        "declarationsVerbatim": True,
        "removedImportsOnly": "import HajimiDNS",
        "chunks": {label: hashlib.sha256(text.encode()).hexdigest()
                   for label, text in chunks.items()},
        "fixtureInputs": [{"source": str(path), "sha256": hashlib.sha256(text.encode()).hexdigest()}
                          for path, text in snapshots.items()],
    }
    binary = work / "dns-fallback-health-isolation"
    compiled = subprocess.run(
        ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-Onone", "-parse-as-library",
         str(production), str(entry), "-o", str(binary), "-framework", "Foundation", "-framework", "Network"],
        text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr)[-16000:])
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    for row, (path, text) in zip(manifest["fixtureInputs"], snapshots.items()):
        row["unchanged"] = path.read_text(encoding="utf-8") == text
    (work / "source-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    print(result.stdout + result.stderr, end="")
    if not all(row["unchanged"] for row in manifest["fixtureInputs"]):
        raise RuntimeError("Regression inputs changed during run")
    print(f"Artifacts: {work}")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()

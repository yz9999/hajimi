#!/usr/bin/env python3
"""Narrow deterministic production parent/sequence/selector deadline regression.

Extracts unchanged declarations and compiles memory peers only. No SwiftPM,
GUI, Helper, profile, listener, network, DNS or real waiting timer is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import (PACKAGE_FLAGS, declaration, monolithic,
                              source_text, write_source_inventory)

ROOT = Path(__file__).resolve().parents[1]

def section(text: str, start: str, end: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise AssertionError(f"production boundary changed: {start}")
    begin = text.index(start)
    return text[begin:text.index(end, begin)]

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-fallback-deadline-health")
    args = parser.parse_args()
    work = args.work_dir.resolve(); work.mkdir(parents=True, exist_ok=True)
    secure = source_text("SecureDNSProxyFallback.swift")
    profile = source_text("Profile.swift")
    native = source_text("NativeOutbound.swift")
    chunks = {
        "datagram": section(source_text("ProxyEngine.swift"), "public protocol NativeRoutedDatagram:", "private final class DirectRoutedDatagram:"),
        "deadline-protocol": declaration("DNSQueryCoordinator.swift", "struct DNSQueryTimeoutError:")[1],
        "fallback-protocols": source_text("DNSQueryContracts.swift"),
        "fallback-parent": section(secure, "enum DNSProxyFallbackBudget {", "/// Pure memory/clock/crypto-configuration checks."),
        "server": section(profile, "public struct DNSProxyFallbackServer:", "public enum DNSProxyFallbackValidationError:"),
        "native-error": section(native, "enum NativeOutboundError:", "extension NativeOutboundFactory {\n    /// Exercises the production prepared"),
        "node-admission": section(source_text("LiteralAddressAttemptCoordinator.swift"), "public enum NodeConnectionAdmissionError:", "enum LiteralAddressAttemptClock"),
        "bootstrap-error": section(source_text("TraditionalDNSResolver.swift"), "enum TraditionalDNSBootstrapError:", "/// Internal wire injection"),
        "classifier": section(source_text("EncryptedDNS.swift"), "enum EncryptedDNSQueryFailure:", "/// Bootstrap addresses for endpoints"),
    }
    maximum = next(line.strip() for line in profile.splitlines() if "static let maximumDNSProxyFallbackServers =" in line)
    chunks["profile-bound"] = "enum Profile { " + maximum + " }\n"
    for label, filename in [("selector", "DNSAdaptiveUpstreamSelector.swift"),
            ("execution-context", "DNSQueryExecutionContext.swift"),
            ("wire", "DNSMessageInspection.swift"), ("diagnostics", "NetworkPerformanceDiagnostics.swift"),
            ("sequence", "DNSProxyFallbackResolverSequence.swift"), ("test", "DNSFallbackDeadlineHealthSelfTest.swift")]:
        chunks[label] = source_text(filename)
    # Reuse the existing phase/serial safety vectors as well; only their
    # entry-point wrapper changes, excluding unrelated route eligibility I/O.
    fixtures = section(secure, "public enum DNSProxyFallbackSelfTest {", "    public static func run() throws {")
    legacy_cases = secure[secure.index("    private static func phaseSafety() throws {"):]
    chunks["existing-phase-sequence-tests"] = fixtures + "\n    static func runNarrow() throws { try phaseSafety(); try resolverSequenceSafety() }\n" + legacy_cases
    manifest = {label: hashlib.sha256(text.encode()).hexdigest() for label, text in chunks.items()}
    (work / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    # Preserve the new test's actual cross-file access boundaries. Only the
    # established private legacy fixtures remain with their original class.
    code = "import Foundation\nimport Network\nimport Darwin\n" + "\n".join(text for label, text in chunks.items() if label != "test")
    production = work / "ProductionDeadlineHealth.swift"; production.write_text(monolithic(code))
    test = work / "DNSFallbackDeadlineHealthSelfTest.swift"; test.write_text(monolithic(chunks["test"]))
    entry = work / "DeadlineHealthMain.swift"
    entry.write_text("@main enum DeadlineHealthMain { static func main() throws { try DNSProxyFallbackSelfTest.runNarrow(); try DNSFallbackDeadlineHealthSelfTest.run() } }\n")
    binary = work / "dns-fallback-deadline-health"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-O", "-parse-as-library", str(production), str(test), str(entry),
        "-o", str(binary), "-framework", "Foundation", "-framework", "Network"], text=True, capture_output=True, timeout=120)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(f"production deadline regression compile failed; inspect {work / 'compile.log'}")
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
    (work / "results.log").write_text(result.stdout + result.stderr)
    write_source_inventory(work)
    if result.returncode:
        raise RuntimeError(f"deadline health regression failed; inspect {work / 'results.log'}")
    print(result.stdout.strip())
    print(f"Artifacts: {work}")

if __name__ == "__main__":
    main()

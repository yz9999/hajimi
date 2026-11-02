#!/usr/bin/env python3
"""Compile unchanged coordinator/fallback production declarations with memory peers.

No SwiftPM, GUI, Helper, profile, listener, network, DNS or system setting is used.
The generated source manifest is rechecked after execution to reject stale runs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from dns_test_sources import (PACKAGE_FLAGS, monolithic, source_text,
                              write_source_inventory)

ROOT = Path(__file__).resolve().parents[1]


def section(text: str, start: str, end: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise AssertionError(f"production boundary changed: {start}")
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def chunks() -> dict[str, str]:
    secure = source_text("SecureDNSProxyFallback.swift")
    profile = source_text("Profile.swift")
    native = source_text("NativeOutbound.swift")
    values = {
        "datagram": section(source_text("ProxyEngine.swift"), "public protocol NativeRoutedDatagram:", "private final class DirectRoutedDatagram:"),
        "fallback-protocols": source_text("DNSQueryContracts.swift"),
        "fallback-parent": section(secure, "enum DNSProxyFallbackBudget {", "/// Pure memory/clock/crypto-configuration checks."),
        "server": section(profile, "public struct DNSProxyFallbackServer:", "public enum DNSProxyFallbackValidationError:"),
        "native-error": section(native, "enum NativeOutboundError:", "extension NativeOutboundFactory {\n    /// Exercises the production prepared"),
        "node-admission": section(source_text("LiteralAddressAttemptCoordinator.swift"), "public enum NodeConnectionAdmissionError:", "enum LiteralAddressAttemptClock"),
        "bootstrap-error": section(source_text("TraditionalDNSResolver.swift"), "enum TraditionalDNSBootstrapError:", "/// Internal wire injection"),
        "classifier": section(source_text("EncryptedDNS.swift"), "enum EncryptedDNSQueryFailure:", "/// Bootstrap addresses for endpoints"),
    }
    maximum = next(line.strip() for line in profile.splitlines() if "static let maximumDNSProxyFallbackServers =" in line)
    values["profile-bound"] = "enum Profile { " + maximum + " }\n"
    for label, filename in [
        ("selector", "DNSAdaptiveUpstreamSelector.swift"),
        ("wire", "DNSMessageInspection.swift"),
        ("diagnostics", "NetworkPerformanceDiagnostics.swift"),
        ("execution-context", "DNSQueryExecutionContext.swift"),
        ("coordinator", "DNSQueryCoordinator.swift"),
        ("cache", "DNSQueryCache.swift"),
        ("sequence", "DNSProxyFallbackResolverSequence.swift"),
        ("deadline-test", "DNSFallbackDeadlineHealthSelfTest.swift"),
    ]:
        values[label] = source_text(filename)
    values["coordinator"] += "\n" + source_text("DNSQueryCoordinatorSelfTest.swift")
    values["coordinator-adapter"] = source_text("DNSQueryModuleAdapter.swift")
    fixtures = section(secure, "public enum DNSProxyFallbackSelfTest {", "    public static func run() throws {")
    legacy_cases = secure[secure.index("    private static func phaseSafety() throws {"):]
    values["existing-phase-sequence-tests"] = fixtures + "\n    static func runNarrow() throws { try phaseSafety(); try resolverSequenceSafety() }\n" + legacy_cases
    values["lineage-test"] = (ROOT / "SmokeTests/DNSQueryLineageMain.swift").read_text()
    return values


def manifest(values: dict[str, str]) -> dict[str, str]:
    return {label: hashlib.sha256(text.encode()).hexdigest() for label, text in values.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-query-lineage")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    values = chunks()
    before = manifest(values)
    (work / "source-manifest.json").write_text(json.dumps(before, indent=2) + "\n")
    production = work / "ProductionQueryLineage.swift"
    production.write_text(monolithic("import Foundation\nimport Network\nimport Darwin\n" + "\n".join(
        text for label, text in values.items() if label not in {"lineage-test", "deadline-test"})))
    test = work / "DNSQueryLineageMain.swift"
    test.write_text(monolithic(values["lineage-test"]))
    deadline_test = work / "DNSFallbackDeadlineHealthSelfTest.swift"
    deadline_test.write_text(monolithic(values["deadline-test"]))
    binary = work / "dns-query-lineage"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-O", "-parse-as-library", str(production),
        str(test), str(deadline_test), "-o", str(binary), "-framework", "Foundation", "-framework", "Network"],
        text=True, capture_output=True, timeout=240)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(f"query lineage compile failed; inspect {work / 'compile.log'}")
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=45)
    (work / "results.log").write_text(result.stdout + result.stderr)
    unchanged = before == manifest(chunks())
    write_source_inventory(work)
    (work / "source-unchanged.json").write_text(json.dumps({"unchanged": unchanged}, indent=2) + "\n")
    if result.returncode:
        raise RuntimeError(f"query lineage check failed; inspect {work / 'results.log'}")
    if not unchanged:
        raise RuntimeError("query lineage source changed during check; run again against final source")
    print(result.stdout.strip())
    print(f"Artifacts: {work}")


if __name__ == "__main__":
    main()

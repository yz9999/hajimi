#!/usr/bin/env python3
"""Exercise real DNS resolver empty-EOF handling with memory-only byte streams.

Extracts unchanged production declarations, including request/pool/connection,
HTTP/DNS parsers and security admission. Only the unused global interface
accessor is stubbed. No listener, external DNS, Helper or settings are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from dns_test_sources import (PACKAGE_FLAGS, declaration as current_declaration, declaration_match, monolithic,
                              source_path, source_text, write_source_inventory)


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "Sources/HajimiCore"


def chunks(encrypted_source: Path | None = None) -> dict[str, str]:
    sources: dict[str, str] = {}

    def source(filename: str) -> str:
        if filename not in sources:
            if filename == "EncryptedDNS.swift" and encrypted_source:
                sources[filename] = encrypted_source.read_text(encoding="utf-8")
            else:
                sources[filename] = source_text(filename)
        return sources[filename]

    def declaration(filename: str, marker: str) -> str:
        text = source(filename)
        match = declaration_match(text, marker)
        if match is None:
            raise AssertionError(f"missing unique declaration: {filename}: {marker}")
        indent = re.match(r" *", marker).group()
        end = re.search(r"^" + indent + r"}\n", text[match.end():], re.M)
        if end is None:
            raise AssertionError(f"missing declaration end: {filename}: {marker}")
        return text[match.start():match.end() + end.end()]

    values = {}
    values["query-timeout"] = current_declaration("DNSQueryCoordinator.swift", "struct DNSQueryTimeoutError:")[1]
    for filename, marker in [
        ("NativeOutbound.swift", "public protocol NativeOutboundByteStream:"),
        ("NativeOutbound.swift", "protocol NativeOutboundFailureObservingByteStream:"),
        ("NativeOutbound.swift", "enum NativeOutboundError:"),
        ("LiteralAddressAttemptCoordinator.swift", "public enum NodeConnectionAdmissionError:"),
        ("TraditionalDNSResolver.swift", "enum TraditionalDNSBootstrapError:"),
        ("Profile.swift", "public struct DNSProxyFallbackServer:"),
        ("EncryptedDNS.swift", "enum EncryptedDNSQueryFailure:"),
    ]:
        values[filename + ":" + marker] = declaration(filename, marker)
    resources = source("SOCKSUDPResources.swift")
    start, end = "enum SOCKSUDPResourceLimits {", "/// Queue-local registry."
    values["resources"] = resources[resources.index(start):resources.index(end)]
    encrypted = source("EncryptedDNS.swift")
    start, end = "public enum EncryptedDNSBootstrap {", "/// Request-local ownership"
    values["endpoints-and-failure-admission"] = encrypted[encrypted.index(start):encrypted.index(end)]
    for marker in [
        "public final class DoHResolver {", "private enum EncryptedDNSProtocol {",
        "private final class EncryptedDNSConnectionStore {", "private func encryptedDNSDirectTLSStateHandler(",
        "private final class EncryptedDNSPooledConnection {", "private final class EncryptedDNSRequestPool {",
        "private final class EncryptedDNSRequest {", "private final class EncryptedDNSNetworkStream:",
        "private enum DoHHTTPWire {", "private struct DoHHTTPResponseParser {",
        "public struct DoTEndpoint:", "public final class DoTResolver {", "final class ProxyTCPDNSResolver {",
    ]:
        values["EncryptedDNS.swift:" + marker] = declaration("EncryptedDNS.swift", marker)
    for filename in ["DNSQueryContracts.swift", "DNSMessageInspection.swift", "NetworkPerformanceDiagnostics.swift",
                     "DNSAdaptiveUpstreamSelector.swift", "DNSQueryExecutionContext.swift"]:
        values[filename] = source(filename)
    values["smoke-test"] = (ROOT / "SmokeTests/DNSEmptyEOFFailureMain.swift").read_text(encoding="utf-8")
    return values


def manifest(values: dict[str, str]) -> dict[str, str]:
    return {name: hashlib.sha256(text.encode()).hexdigest() for name, text in values.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-empty-eof-failure")
    parser.add_argument("--encrypted-dns-source", type=Path)
    parser.add_argument("--expect-current-gap", action="store_true",
                        help="assert the five Build 18 EOF gaps, plus absent response evidence when applicable")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    values = chunks(args.encrypted_dns_source)
    before = manifest(values)
    (work / "source-manifest.json").write_text(json.dumps(before, indent=2) + "\n")
    production = work / "ProductionDNSEmptyEOF.swift"
    production.write_text(monolithic("import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"
        "// Injected memory dialers never read this direct-network accessor.\n"
        "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { nil } }\n"
        + "\n".join(values.values())), encoding="utf-8")
    binary = work / "dns-empty-eof-failure"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library",
        str(production), "-o", str(binary), "-framework", "Foundation", "-framework", "Network",
        "-framework", "Security"], text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    unchanged = before == manifest(chunks(args.encrypted_dns_source))
    write_source_inventory(work)
    (work / "source-unchanged.json").write_text(json.dumps({"unchanged": unchanged}, indent=2) + "\n")
    if not unchanged:
        raise RuntimeError("tested production source changed during the run")
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if args.expect_current_gap:
        expected = {"doh-fresh-nil-empty-eof", "doh-fresh-empty-data-eof", "doh-reused-retry-fresh-empty-eof",
                    "doh-admitted-authentication-empty-eof", "doh-admitted-other-empty-eof"}
        # The original source also predates numeric response diagnostics. Its
        # absence is independent of the five functional EOF regressions.
        if "private func recordResponseMetadata(" not in values["EncryptedDNS.swift:private final class EncryptedDNSRequest {"]:
            expected.add("numeric-response-evidence-and-fixed-rejection-categories")
        if result.returncode != 1 or set(report["failedGroups"]) != expected:
            raise RuntimeError("Build 18 baseline did not reproduce exactly the expected empty-EOF gap")
        print("PASS: Build 18 reproduced exactly its expected EOF/evidence gaps; other resolver/security boundaries passed")
    elif result.returncode:
        raise SystemExit(result.returncode)
    print(f"Production/test source unchanged; artifacts: {work}")


if __name__ == "__main__":
    main()

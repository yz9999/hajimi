#!/usr/bin/env python3
"""Compile exact DNS pool/flow declarations and selected memory-only self-tests.

No SwiftPM build, listener, DNS request to an external server, GUI, Helper or
system setting is involved. Only the unused global-interface accessor is
stubbed; all tested request, connection, flow and stream declarations retain
their original source. The manifest records every extraction and its hash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from dns_test_sources import (PACKAGE_FLAGS, declaration as current_declaration, monolithic,
                              source_path, source_text, write_source_inventory)


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "Sources/HajimiCore"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("prewarm-evidence", "proxy-tcp"), default="prewarm-evidence")
    parser.add_argument("--work-dir", type=Path)
    arguments = parser.parse_args()
    default_work = ROOT / (".build/dns-proxy-tcp-pool" if arguments.mode == "proxy-tcp"
                           else ".build/dns-prewarm-evidence")
    work = (arguments.work_dir or default_work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    originals: dict[Path, str] = {}
    manifest: list[dict] = []
    snapshots: list[tuple[Path, str]] = []

    def source(filename: str) -> str:
        path = source_path(filename)
        if path not in originals:
            originals[path] = source_text(filename)
        return originals[path]

    def retained(filename: str, marker: str, text: str, start: int, path: Path | None = None) -> str:
        path = path or source_path(filename)
        digest = hashlib.sha256(text.encode()).hexdigest()
        first_line = source_text(path.name)[:start].count("\n") + 1
        manifest.append({"source": str(path.relative_to(ROOT)), "marker": marker,
                         "firstLine": first_line, "lastLine": first_line + text.count("\n") - 1,
                         "sha256": digest, "unchanged": True})
        snapshots.append((path, text))
        return f"\n// Verbatim {filename}:{first_line}; SHA256 {digest}\n{text}"

    def declaration(filename: str, marker: str) -> str:
        path, text, start = current_declaration(filename, marker)
        return retained(filename, marker, text, start, path)

    def section(filename: str, start_marker: str, end_marker: str) -> str:
        text = source(filename)
        if text.count(start_marker) != 1 or text.count(end_marker) != 1:
            raise RuntimeError(f"Nonunique extraction boundary: {filename}: {start_marker}")
        start = text.index(start_marker)
        finish = text.index(end_marker, start)
        return retained(filename, start_marker, text[start:finish], start)

    code = ["import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n",
            "// The injected memory dialer never reads this direct-network accessor.\n"
            "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { nil } }\n"]
    for filename, marker in [
        ("NativeOutbound.swift", "public protocol NativeOutboundByteStream:"),
        ("NativeOutbound.swift", "protocol NativeOutboundFailureObservingByteStream:"),
        ("NativeOutbound.swift", "enum NativeOutboundError:"),
        ("DNSQueryCoordinator.swift", "struct DNSQueryTimeoutError:"),
        ("LiteralAddressAttemptCoordinator.swift", "public enum NodeConnectionAdmissionError:"),
        ("TraditionalDNSResolver.swift", "enum TraditionalDNSBootstrapError:"),
        ("ProxyEngine.swift", "public protocol NativeRoutedDatagram:"),
        ("Profile.swift", "public struct DNSProxyFallbackServer:"),
        ("FakeIP.swift", "public final class FakeIPAllocator {"),
        ("FakeIP.swift", "public struct FakeIPQuestion:"),
        ("FakeIP.swift", "public enum FakeIPResponder {"),
        ("EncryptedDNS.swift", "enum EncryptedDNSQueryFailure:"),
    ]:
        code.append(declaration(filename, marker))
    code.append(section("SOCKSUDPResources.swift", "enum SOCKSUDPResourceLimits {", "/// Queue-local registry."))
    code.append(section("EncryptedDNS.swift", "public enum EncryptedDNSBootstrap {", "/// Request-local ownership"))
    for marker in [
        "public final class DoHResolver {", "private enum EncryptedDNSProtocol {",
        "private final class EncryptedDNSConnectionStore {", "private func encryptedDNSDirectTLSStateHandler(",
        "private final class EncryptedDNSPooledConnection {", "private final class EncryptedDNSRequestPool {",
        "private final class EncryptedDNSRequest {", "private final class EncryptedDNSNetworkStream:",
        "private enum DoHHTTPWire {", "private struct DoHHTTPResponseParser {",
        "public final class DoHRoutedDatagram:", "private final class EncryptedDNSDatagramFlow {",
        "public struct DoTEndpoint:", "public final class DoTResolver {", "public final class DoTRoutedDatagram:",
    ]:
        code.append(declaration("EncryptedDNS.swift", marker))
    if arguments.mode == "proxy-tcp":
        for marker in ["final class ProxyTCPDNSResolver {", "final class ProxyTCPDNSRoutedDatagram:"]:
            code.append(declaration("EncryptedDNS.swift", marker))
    code.append("enum FakeIPSelfTest {\n" + declaration("FakeIP.swift", "    static func query(") + "}\n")
    code.append("enum EncryptedDNSSelfTest {\n")
    test_markers = [
        "    struct Failure:", "    private static func expect(_ condition: Bool, _ message: String)",
        "    private final class ReuseMemoryStream:",
        "    private final class ReuseProbe {", "    private static func reuseWireReply(",
        "    private static func reuseAuto(",
    ]
    if arguments.mode == "proxy-tcp":
        test_markers.extend([
            "    fileprivate static func proxyTCPConnectionPool()",
            "    private static func proxyTCPPendingDialFence(", "    private static func proxyTCPIngressFence(",
        ])
    else:
        test_markers.extend([
            "    private final class MemoryStream:", "    private static func queryTransportEvidence()",
            "    private static func encryptedConnectionPrewarming()",
        ])
    for marker in test_markers:
        code.append(declaration("EncryptedDNS.swift", marker))
    if arguments.mode == "proxy-tcp":
        code.append("""
    static func runProxyTCPPoolIsolation() throws { try proxyTCPConnectionPool() }
}
@main
enum ProxyTCPPoolMain {
    static func main() throws {
        try EncryptedDNSSelfTest.runProxyTCPPoolIsolation()
        print("PASS: exact production proxy TCP DNS pool, physical trace and cancellation fences; memory peers only")
    }
}
""")
    else:
        code.append("""
    static func runPrewarmEvidenceIsolation() throws {
        try queryTransportEvidence()
        print("Encrypted DNS transport evidence: fresh, reused, reusedThenFresh, datagram and queue-only timeout passed")
        try encryptedConnectionPrewarming()
    }
}
@main
enum PrewarmEvidenceMain {
    static func main() throws {
        try EncryptedDNSSelfTest.runPrewarmEvidenceIsolation()
        print("PASS: exact production DNS prewarm/evidence state machines; memory peers only")
    }
}
""")
    whole_files = ["DNSQueryContracts.swift", "DNSMessageInspection.swift", "NetworkPerformanceDiagnostics.swift",
                   "DNSAdaptiveUpstreamSelector.swift", "DNSConnectionPrewarming.swift",
                   "DNSQueryExecutionContext.swift"]
    for filename in whole_files:
        text = source(filename)
        manifest.append({"source": str(source_path(filename).relative_to(ROOT)), "wholeFile": True,
                         "sha256": hashlib.sha256(text.encode()).hexdigest(), "unchanged": True})
        snapshots.append((source_path(filename), text))
    generated = work / ("ProductionDNSProxyTCPPool.swift" if arguments.mode == "proxy-tcp"
                        else "ProductionDNSPrewarmEvidence.swift")
    generated.write_text(monolithic("\n".join(code)), encoding="utf-8")
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    binary = work / ("dns-proxy-tcp-pool" if arguments.mode == "proxy-tcp" else "dns-prewarm-evidence")
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library", str(generated)]
    if arguments.mode == "proxy-tcp":
        command.append("-whole-module-optimization")
    for filename in whole_files:
        frozen = work / filename
        frozen.write_text(monolithic(source(filename)), encoding="utf-8")
        command.append(str(frozen))
    command.extend(["-o", str(binary), "-framework", "Foundation", "-framework", "Network", "-framework", "Security"])
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
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("A tested production declaration changed during this audit; rerun for a coherent snapshot")
    print(f"Production source unchanged; manifest={work / 'source-manifest.json'}")
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()

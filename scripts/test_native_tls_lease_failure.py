#!/usr/bin/env python3
"""Compile exact bounded TLS/pool declarations; exercise only loopback peers.

No SwiftPM build, GUI, Helper, system DNS, user profile or external endpoint.
The extracted production classes are unchanged. Their standard Foundation,
Security, Network and CryptoKit dependencies are linked normally. The peer
alone injects fixed raw error events after a real verified first exchange.
"""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import tempfile
import threading

from dns_test_sources import (PACKAGE_FLAGS, declaration, monolithic,
                              source_text, write_source_inventory)

ROOT = Path(__file__).resolve().parents[1]

def section(source: str, start: str, end: str) -> str:
    if source.count(start) != 1 or source.count(end) != 1:
        raise AssertionError(f"Production declaration boundary changed: {start}")
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]

def production() -> tuple[str, dict]:
    native = source_text("NativeOutbound.swift")
    dns = source_text("EncryptedDNS.swift")
    sources = {
        "stream-and-relay": section(native, "public protocol NativeOutboundByteStream:", "/// Private identity-fixture evidence"),
        "fixture-trust": section(native, "enum DNSFixtureTrustObservation", "public protocol NativeOutboundDatagramSession"),
        "native-error": section(native, "enum NativeOutboundError:", "extension NativeOutboundFactory {\n    /// Exercises the production prepared"),
        "byte-transport": section(native, "protocol ByteTransport:", "/// A prepared carrier owns"),
        "stream-adapter": section(native, "private final class OutboundStreamTransport:", "private final class NetworkByteTransport:"),
        "native-tls": section(native, "func nativeOutboundTLSFailureAdmission(", "final class BufferedByteReader {"),
        "native-debug": section(native, "func nativeDebug(", "private func sealHeader("),
        "dns-classifier": section(dns, "enum EncryptedDNSQueryFailure:", "/// Bootstrap addresses for endpoints"),
        "dns-pool": section(dns, "private final class EncryptedDNSPooledConnection {", "private final class EncryptedDNSRequestPool {"),
    }
    dependencies = [
        ("node-admission", "LiteralAddressAttemptCoordinator.swift", "public enum NodeConnectionAdmissionError:", "enum LiteralAddressAttemptClock"),
        ("dns-bootstrap-error", "TraditionalDNSResolver.swift", "enum TraditionalDNSBootstrapError:", "/// Internal wire injection"),
        ("resource-budget", "SOCKSUDPResources.swift", "enum SOCKSUDPResourceLimits {", "/// Queue-local registry."),
    ]
    for label, filename, start, end in dependencies:
        sources[label] = section(source_text(filename), start, end)
    sources["dns-timeout"] = declaration("DNSQueryCoordinator.swift", "struct DNSQueryTimeoutError:")[1]
    for filename in ("DNSMessageInspection.swift", "DNSQueryContracts.swift", "DNSQueryExecutionContext.swift",
                     "DNSAdaptiveUpstreamSelector.swift", "NetworkPerformanceDiagnostics.swift"):
        sources[filename] = source_text(filename)
    manifest = {label: hashlib.sha256(text.encode()).hexdigest() for label, text in sources.items()}
    prefix = "import Foundation\nimport Network\nimport Security\nimport CryptoKit\nimport Darwin\n"
    return monolithic(prefix + "\n".join(sources.values())), manifest

def serve(listener: socket.socket, context: ssl.SSLContext) -> None:
    try:
        peer, _ = listener.accept()
        peer.settimeout(4)
        with context.wrap_socket(peer, server_side=True) as tls:
            first = tls.recv(1)
            tls.sendall(first)
            # A second lease may write; its response is deliberately held.
            with contextlib.suppress(OSError):
                while tls.recv(1024):
                    pass
    except (OSError, ssl.SSLError):
        pass
    finally:
        listener.close()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/native-tls-lease-failure")
    arguments = parser.parse_args()
    work = arguments.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    code, manifest = production()
    main_source = ROOT / "SmokeTests/NativeTLSLeaseFailureMain.swift"
    manifest["fixture-main"] = hashlib.sha256(main_source.read_bytes()).hexdigest()
    # Mechanical diagnostic extraction only; the main is in the same source
    # file so private production declarations keep their exact access levels.
    isolated = work / "ProductionTLSLeaseFailure.swift"
    isolated.write_text(code + "\n" + main_source.read_text())
    (work / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    binary = work / "native-tls-lease-failure"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-O", "-parse-as-library", str(isolated),
        "-o", str(binary), "-framework", "Foundation", "-framework", "Network", "-framework", "Security"],
        text=True, capture_output=True, timeout=120)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(f"isolated production TLS/pool compile failed; inspect {work / 'compile.log'}")
    helper = runpy.run_path(str(ROOT / "SmokeTests/live_dns_adaptive.py"))["certificates"]
    results = []
    with tempfile.TemporaryDirectory(prefix="local-tls-", dir=work) as temporary:
        directory = Path(temporary)
        good, _, key = helper(directory)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(good, key)
        for mode in ["tls", "unknown", "network", "cancel", "eof"]:
            timings = ["pending", "late", "pool"] if mode in ["tls", "unknown", "network"] else ["pending", "late"]
            if mode in ["tls", "network", "eof"]:
                timings.append("handshake")
            for timing in timings:
                for iteration in range(3):
                    listener = socket.socket()
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    thread = threading.Thread(target=serve, args=(listener, context), daemon=True)
                    thread.start()
                    result = subprocess.run([str(binary), str(listener.getsockname()[1]), str(directory / "ca.der"),
                        mode, timing, "--dns-adaptive-loopback-test"], text=True, capture_output=True, timeout=12)
                    if result.returncode:
                        (work / "failure.log").write_text(result.stdout + result.stderr)
                        raise RuntimeError(f"local production fixture failed mode={mode} timing={timing} iteration={iteration}; inspect {work / 'failure.log'}")
                    results.append(result.stdout.strip())
                    thread.join(timeout=5)
    (work / "results.log").write_text("\n".join(results) + "\n")
    write_source_inventory(work)
    print(f"PASS: {len(results)} verified loopback TLS lease cases; artifacts: {work}")

if __name__ == "__main__":
    main()

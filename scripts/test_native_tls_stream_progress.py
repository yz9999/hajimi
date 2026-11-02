#!/usr/bin/env python3
"""Check bounded anonymous progress on exact production nested TLS, locally.

Only the explicit smoke executable, compiler, certificate fixture and private
127.0.0.1 peers run. No App, Helper, resolver or system network mutation.
The optional Build40 NativeOutbound input is a verified negative control for
missing progress capability; the current diagnostics types remain the harness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import tempfile
import threading

from dns_test_sources import PACKAGE_FLAGS, declaration, monolithic, source_text, write_source_inventory

ROOT = Path(__file__).resolve().parents[1]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def section(source: str, start: str, end: str) -> str:
    if source.count(start) != 1 or source.count(end) != 1:
        raise RuntimeError("Production extraction boundary changed: " + start)
    return source[source.index(start):source.index(end, source.index(start))]


def production(native_baseline: Path | None) -> tuple[str, dict]:
    native = source_text("NativeOutbound.swift")
    baseline = None
    if native_baseline is not None:
        raw = native_baseline.read_bytes()
        pins = json.loads((ROOT / ".build/build40-package-inputs.json").read_text())["production"]
        expected = pins["Sources/HajimiCore/NativeOutbound.swift"]["sha256"]
        if digest(raw) != expected:
            raise RuntimeError("Native baseline is not the pinned complete Build40 source")
        native = raw.decode()
        baseline = {"path": str(native_baseline.resolve()), "sha256": expected, "build": 40}
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
    }
    for label, filename, start, end in (
        ("node-admission", "LiteralAddressAttemptCoordinator.swift", "public enum NodeConnectionAdmissionError:", "enum LiteralAddressAttemptClock"),
        ("dns-bootstrap-error", "TraditionalDNSResolver.swift", "enum TraditionalDNSBootstrapError:", "/// Internal wire injection"),
    ):
        sources[label] = section(source_text(filename), start, end)
    sources["dns-timeout"] = declaration("DNSQueryCoordinator.swift", "struct DNSQueryTimeoutError:")[1]
    for filename in ("DNSMessageInspection.swift", "DNSQueryContracts.swift", "DNSQueryExecutionContext.swift", "DNSAdaptiveUpstreamSelector.swift",
                     "NetworkPerformanceDiagnostics.swift"):
        sources[filename] = source_text(filename)
    manifest = {label: digest(text.encode()) for label, text in sources.items()}
    if baseline is not None:
        manifest["negative-control-native-input"] = baseline
    prefix = "import Foundation\nimport Network\nimport Security\nimport CryptoKit\nimport Darwin\n"
    return monolithic(prefix + "\n".join(sources.values())), manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/build41-native-stream-progress")
    parser.add_argument("--native-baseline", type=Path)
    parser.add_argument("--expect", choices=("current", "missing"), default="current")
    arguments = parser.parse_args()
    if (arguments.expect == "missing") != (arguments.native_baseline is not None):
        parser.error("--expect missing requires the pinned --native-baseline, and vice versa")
    work = arguments.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    code, manifest = production(arguments.native_baseline)
    fixture = ROOT / "SmokeTests/NativeTLSStreamProgressMain.swift"
    raw_fixture = fixture.read_bytes()
    manifest["fixture-input"] = digest(raw_fixture)
    manifest["runner-input"] = digest(Path(__file__).read_bytes())
    generated = code + "\n" + raw_fixture.decode()
    manifest["generated"] = digest(generated.encode())
    isolated = work / "ProductionNativeTLSStreamProgress.swift"
    isolated.write_text(generated)
    (work / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    binary = work / "native-tls-stream-progress"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-O", "-parse-as-library", str(isolated), "-o", str(binary),
               "-framework", "Foundation", "-framework", "Network", "-framework", "Security"]
    built = subprocess.run(command, text=True, capture_output=True, timeout=120)
    (work / "compile.log").write_text(built.stdout + built.stderr)
    if built.returncode:
        raise RuntimeError("Production TLS fixture compile failed; inspect " + str(work / "compile.log"))
    results = []

    def run_case(name: str, params: list[str]) -> subprocess.CompletedProcess:
        value = subprocess.run([str(binary), *params, "--dns-adaptive-loopback-test"],
                               text=True, capture_output=True, timeout=12)
        output = value.stdout + value.stderr
        (work / (name + ".log")).write_text(output)
        results.append({"name": name, "exitCode": value.returncode, "logSha256": digest(output.encode()),
                        "assertionGroups": [line for line in value.stdout.splitlines() if line.startswith("PASS ")]})
        return value

    memory = run_case("memory", ["memory"])
    if arguments.expect == "missing":
        if memory.returncode == 0 or "missing-DNS-TLS-progress-evidence" not in memory.stdout + memory.stderr:
            raise RuntimeError("Build40 Native negative control did not fail for missing progress capability")
        print("PASS pinned Build40 Native negative control: missing-DNS-TLS-progress-evidence", flush=True)
    else:
        if memory.returncode:
            raise RuntimeError("Memory stream-progress fixture failed; inspect " + str(work / "memory.log"))
        print(memory.stdout, end="", flush=True)
        certificates = runpy.run_path(str(ROOT / "SmokeTests/live_dns_adaptive.py"))["certificates"]
        with tempfile.TemporaryDirectory(prefix="local-progress-tls-", dir=work) as temporary:
            directory = Path(temporary)
            good, _, key = certificates(directory)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.set_alpn_protocols(["http/1.1"])
            context.load_cert_chain(good, key)
            for scenario, expected_bytes in (("echo", b"ABCDE"), ("silent", b"S"),
                                             ("held-write", b"S"), ("untraced", b"ABC")):
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(4)
                port = listener.getsockname()[1]
                received = bytearray()
                peer_errors = []

                def serve() -> None:
                    try:
                        peer, _ = listener.accept()
                        peer.settimeout(4)
                        with context.wrap_socket(peer, server_side=True) as tls:
                            while True:
                                value = tls.recv(1024)
                                if not value:
                                    break
                                received.extend(value)
                                if scenario in ("echo", "untraced"):
                                    tls.sendall(value)
                    except (OSError, ssl.SSLError) as error:
                        # Local cancellation may omit close_notify. The exact
                        # peer-received payload below is the test authority.
                        peer_errors.append(type(error).__name__)
                    finally:
                        listener.close()

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                value = run_case(scenario, [str(port), str(directory / "ca.der"), scenario])
                thread.join(timeout=5)
                # The held-write case deliberately releases the carrier's
                # local completion immediately before cancellation. Receipt
                # by the TLS peer can legitimately lose that race; neither
                # contentProcessed nor this counter promises a remote ACK.
                allowed_payloads = (b"", expected_bytes) if scenario == "held-write" else (expected_bytes,)
                if thread.is_alive() or value.returncode or bytes(received) not in allowed_payloads:
                    raise RuntimeError(f"Private loopback case failed: {scenario}; bytes={len(received)}, "
                                       f"peer={peer_errors}; inspect {work / (scenario + '.log')}")
                print(value.stdout, end="", flush=True)
                print(f"PASS private-peer {scenario} receivedBytes={len(received)} localCompletionIsNotRemoteACK=true", flush=True)
    if fixture.read_bytes() != raw_fixture or digest(Path(__file__).read_bytes()) != manifest["runner-input"]:
        raise RuntimeError("Fixture/runner changed during verification")
    write_source_inventory(work)
    (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"PASS {len(results)} bounded fixture processes; production, fixture and runner inputs unchanged; {work}")


if __name__ == "__main__":
    main()

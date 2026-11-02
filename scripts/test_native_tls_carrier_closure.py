#!/usr/bin/env python3
"""Compile exact production TLS declarations and test private loopback peers.

No SwiftPM, App, Helper, user profile, DNS settings or external endpoint.
The production extraction is unmodified; only the smoke peer combines real
ciphertext and EOF and exposes its fixed numeric receipt to the assertions.
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

from dns_test_sources import PACKAGE_FLAGS, write_source_inventory

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/build19-native-carrier-closure")
    parser.add_argument("--iterations", type=int, default=2)
    arguments = parser.parse_args()
    work = arguments.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    runner = runpy.run_path(str(ROOT / "scripts/test_native_tls_lease_failure.py"))
    code, manifest = runner["production"]()
    fixture_path = ROOT / "SmokeTests/NativeTLSLeaseFailureMain.swift"
    fixture = fixture_path.read_text()
    manifest["legacy-fixture-input"] = hashlib.sha256(fixture.encode()).hexdigest()
    assert fixture.count("static func main() throws {") == 1
    fixture = fixture.replace("static func main() throws {", "static func legacyMain() throws {")
    needle = "private var firstReadInjection: String?"
    assert fixture.count(needle) == 1
    fixture = fixture.replace(needle, needle + """
        private var finishNextRead = false
        let finalCiphertextObserved = DispatchSemaphore(value: 0)
        private(set) var finalCiphertextByteCount = 0
        func finishNextReadWithEOF() { lock.lock(); finishNextRead = true; lock.unlock() }
""")
    needle = "self.lock.unlock(); callback?(data, eof, error)"
    assert fixture.count(needle) == 1
    fixture = fixture.replace(needle, """let forcedEOF = self.finishNextRead && data?.isEmpty == false
                if forcedEOF { self.finishNextRead = false; self.finalCiphertextByteCount = data?.count ?? 0 }
                self.lock.unlock(); callback?(data, eof || forcedEOF, error)
                if forcedEOF { self.finalCiphertextObserved.signal() }""")
    carrier_path = ROOT / "SmokeTests/NativeTLSCarrierClosureMain.swift"
    carrier = carrier_path.read_text()
    manifest["carrier-fixture-input"] = hashlib.sha256(carrier.encode()).hexdigest()
    code += "\n" + fixture + "\n" + carrier
    manifest["generated-all"] = hashlib.sha256(code.encode()).hexdigest()
    isolated = work / "ProductionNativeTLSCarrierClosure.swift"
    isolated.write_text(code)
    (work / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    binary = work / "native-tls-carrier-closure"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-O", "-parse-as-library", str(isolated),
        "-o", str(binary), "-framework", "Foundation", "-framework", "Network", "-framework", "Security"],
        text=True, capture_output=True, timeout=120)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(f"isolated TLS compile failed; {work / 'compile.log'}")
    results = []

    def run_case(port, anchor, mode, scenario, iteration):
        completed = subprocess.run([str(binary), str(port), str(anchor), mode, scenario,
            "--dns-adaptive-loopback-test"], text=True, capture_output=True, timeout=15)
        output = completed.stdout + completed.stderr
        (work / f"{mode}-{scenario}-{iteration}.log").write_text(output)
        if completed.returncode:
            raise RuntimeError(f"controlled case failed: {mode}/{scenario}/{iteration}; {work}")
        rows = [line for line in completed.stdout.splitlines() if line.startswith("PASS ")]
        if not rows:
            raise RuntimeError(f"case emitted no completed assertions: {mode}/{scenario}/{iteration}")
        results.append({"mode": mode, "scenario": scenario, "iteration": iteration, "assertions": rows})
        print("\n".join(rows), flush=True)

    run_case(1, work / "unused-anchor", "none", "memory", 0)
    certificates = runpy.run_path(str(ROOT / "SmokeTests/live_dns_adaptive.py"))["certificates"]
    with tempfile.TemporaryDirectory(prefix="loopback-tls-", dir=work) as temporary:
        directory = Path(temporary)
        good, wrong, key = certificates(directory)
        good_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        good_context.set_alpn_protocols(["http/1.1"])
        good_context.load_cert_chain(good, key)
        wrong_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        wrong_context.set_alpn_protocols(["http/1.1"])
        wrong_context.load_cert_chain(wrong, key)
        handshake_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        handshake_context.minimum_version = ssl.TLSVersion.TLSv1_3
        handshake_context.maximum_version = ssl.TLSVersion.TLSv1_3
        handshake_context.set_alpn_protocols(["http/1.1"])
        handshake_context.load_cert_chain(good, key)
        scenarios = [("none", scenario) for scenario in
                     ["last-record", "late-send", "handshake-final", "wrong-san", "wrong-san-final"]]
        for mode in ["tls", "unknown", "network", "cancel", "eof"]:
            timings = ["pending", "late", "pool"] if mode in ["tls", "unknown", "network"] else ["pending", "late"]
            if mode in ["tls", "network", "eof"]:
                timings.append("handshake")
            scenarios.extend((mode, timing) for timing in timings)
        for mode, scenario in scenarios:
            for iteration in range(arguments.iterations):
                listener = socket.socket()
                listener.settimeout(4)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                port = listener.getsockname()[1]
                context = wrong_context if scenario.startswith("wrong-san") else (
                    handshake_context if scenario == "handshake-final" else good_context)

                def serve_case():
                    try:
                        peer, _ = listener.accept()
                        peer.settimeout(4)
                        with context.wrap_socket(peer, server_side=True) as tls:
                            if scenario in ["last-record", "late-send"]:
                                for _ in range(2):
                                    value = tls.recv(1)
                                    if not value:
                                        return
                                    tls.sendall(value)
                                with contextlib.suppress(OSError, ssl.SSLError):
                                    tls.unwrap()
                            else:
                                first = tls.recv(1)
                                if first:
                                    tls.sendall(first)
                                with contextlib.suppress(OSError, ssl.SSLError):
                                    while tls.recv(1024):
                                        pass
                    except (OSError, ssl.SSLError):
                        pass
                    finally:
                        listener.close()

                thread = threading.Thread(target=serve_case, daemon=True)
                thread.start()
                run_case(port, directory / "ca.der", mode, scenario, iteration)
                thread.join(timeout=5)
                if thread.is_alive():
                    raise RuntimeError(f"loopback peer retained resources: {mode}/{scenario}")
    (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    write_source_inventory(work)
    assertion_count = sum(len(result["assertions"]) for result in results)
    print(f"PASS: {len(results)} processes, {assertion_count} completed assertion groups; {work}")


if __name__ == "__main__":
    main()

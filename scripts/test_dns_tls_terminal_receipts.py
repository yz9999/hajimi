#!/usr/bin/env python3
"""Run exact routed-DNS TLS ownership and terminal-receipt memory checks.

Extracts production declarations without rewriting them. No SwiftPM, listener,
GUI, Helper, DNS query, remote network or system setting is involved. Each
extracted declaration and its hash is retained in the source manifest.
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-tls-terminal-receipts")
    arguments = parser.parse_args()
    work = arguments.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    sources: dict[Path, str] = {}
    snapshots: list[tuple[Path, str]] = []
    manifest: list[dict] = []
    code = ["import Foundation\nimport Dispatch\nimport Network\nimport Darwin\n"]

    def source(filename: str) -> str:
        path = source_path(filename)
        if path not in sources:
            sources[path] = source_text(filename)
        return sources[path]

    def retain(filename: str, marker: str | None = None) -> None:
        text = source(filename)
        start = 0
        if marker is not None:
            path, text, start = declaration(filename, marker)
        else:
            path = source_path(filename)
        digest = hashlib.sha256(text.encode()).hexdigest()
        first_line = source(filename)[:start].count("\n") + 1
        manifest.append({"source": str(path.relative_to(ROOT)), "marker": marker,
                         "firstLine": first_line, "sha256": digest})
        snapshots.append((path, text))
        code.append(f"\n// Verbatim {filename}:{first_line}; SHA256 {digest}\n{text}")

    for filename, marker in [
        ("NativeOutbound.swift", "public protocol NativeOutboundByteStream:"),
        ("NativeOutbound.swift", "enum NativeOutboundError:"),
        ("LiteralAddressAttemptCoordinator.swift", "public enum NodeConnectionAdmissionError:"),
        ("TraditionalDNSResolver.swift", "enum TraditionalDNSBootstrapError:"),
        ("DNSQueryCoordinator.swift", "struct DNSQueryTimeoutError:"),
        ("EncryptedDNS.swift", "enum EncryptedDNSQueryFailure:"),
        ("EncryptedDNS.swift", "final class DNSRoutedTLSConnectionAttempt {"),
        ("EncryptedDNS.swift", "private extension DNSRoutedTLSConnectionAttempt {"),
        ("EncryptedDNS.swift", "enum DNSRoutedTLSConnectionAttemptSelfTest {"),
    ]:
        retain(filename, marker)
    retain("NetworkPerformanceDiagnostics.swift")
    retain("DNSQueryContracts.swift")
    retain("DNSAdaptiveUpstreamSelector.swift")
    retain("DNSQueryExecutionContext.swift")
    code.append("""
@main enum DNSTLSTerminalReceiptsMain {
    static func main() throws {
        try DNSRoutedTLSConnectionAttemptSelfTest.run()
        print("PASS: exact production routed-DNS TLS ownership and terminal receipts; memory peers only")
    }
}
""")
    generated = work / "ProductionDNSTLSTerminalReceipts.swift"
    generated.write_text(monolithic("\n".join(code)), encoding="utf-8")
    binary = work / "dns-tls-terminal-receipts"
    compiled = subprocess.run(["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library",
        str(generated), "-framework", "Foundation", "-framework", "Network", "-o", str(binary)],
        text=True, capture_output=True, timeout=120, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        raise RuntimeError(f"Production DNS TLS receipt compilation failed; inspect {work / 'compile.log'}")
    completed = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30, check=False)
    (work / "results.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="")
    for row, (path, text) in zip(manifest, snapshots):
        row["unchanged"] = text in path.read_text(encoding="utf-8")
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_source_inventory(work)
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("A tested production declaration changed during the run; rerun for a coherent snapshot")
    print(f"Production source unchanged; manifest={work / 'source-manifest.json'}")
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise production QTYPE/EDE parsing and real memory-only DNS resolvers.

Uses the existing exact-declaration resolver extractor; no listener, DNS,
Helper, proxy endpoint or system configuration is used. The sole substituted
production dependency is an unused direct-interface accessor.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tarfile

from test_dns_empty_eof_failure import ROOT, chunks, manifest
from dns_test_sources import PACKAGE_FLAGS, declaration, monolithic, source_text, write_source_inventory


def selected(archive: Path | None) -> dict[str, str]:
    values = chunks()
    values["smoke-test"] = (ROOT / "SmokeTests/DNSEDEMetadataMain.swift").read_text(encoding="utf-8")
    if archive:
        # Frozen Build19 declarations compile against the same behavioral
        # fixture. Only the new metadata accessors are conditionally absent.
        with tarfile.open(archive) as baseline:
            baseline_files = {name: baseline.extractfile("Sources/HajimiCore/" + name).read().decode()
                              for name in ("EncryptedDNS.swift", "DNSMessageInspection.swift", "NetworkPerformanceDiagnostics.swift")}
        encrypted = baseline_files["EncryptedDNS.swift"]
        current = source_text("EncryptedDNS.swift")
        for key, value in list(values.items()):
            if key.startswith("EncryptedDNS.swift:") or key == "endpoints-and-failure-admission":
                if current.count(value) != 1:
                    raise AssertionError("nonunique current production chunk " + key)
                marker = value.splitlines()[0]
                start = encrypted.index(marker)
                if key == "endpoints-and-failure-admission":
                    end = encrypted.index("/// Request-local ownership", start)
                else:
                    end = encrypted.index("\n}\n", start) + 3
                values[key] = encrypted[start:end]
        for name in ("DNSMessageInspection.swift", "NetworkPerformanceDiagnostics.swift"):
            values[name] = baseline_files[name]
        # Build19's archived metrics file still owns these four declarations.
        # Keep one real definition of each while retaining the current logical
        # contracts required by the current selector/context dependency files.
        for marker in ("public enum DNSAttemptCancellationReason:",
                       "public enum DNSConnectionAttemptEvent:",
                       "public enum DNSPerformanceEvent {",
                       "public enum DNSQueryFailureReason:"):
            text = declaration("DNSQueryContracts.swift", marker)[1]
            values["DNSQueryContracts.swift"] = values["DNSQueryContracts.swift"].replace(text, "", 1)
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-ede-metadata")
    parser.add_argument("--baseline-archive", type=Path)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    values = selected(args.baseline_archive)
    before = manifest(values)
    production = work / "ProductionDNSEDEMetadata.swift"
    production.write_text(monolithic("import Foundation\nimport Dispatch\nimport Network\nimport Security\nimport Darwin\n"
        "private enum ProxyEngine { static var currentOutboundInterface: NWInterface? { nil } }\n"
        + "\n".join(values.values())), encoding="utf-8")
    binary = work / "dns-ede-metadata"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-O", "-parse-as-library"]
    if args.baseline_archive:
        command += ["-D", "BUILD19_BASELINE"]
    compiled = subprocess.run(command + [str(production), "-o", str(binary),
        "-framework", "Foundation", "-framework", "Network", "-framework", "Security"],
        text=True, capture_output=True, timeout=180, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    after = manifest(selected(args.baseline_archive))
    write_source_inventory(work)
    (work / "source-manifest.json").write_text(json.dumps({name: {
        "before": digest, "after": after.get(name), "unchanged": digest == after.get(name)}
        for name, digest in before.items()}, indent=2) + "\n")
    if before != after:
        raise RuntimeError("tested source changed during run")
    report = json.loads(result.stdout.splitlines()[-1])
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if args.baseline_archive:
        expected = {"parser-numeric-unknown-zero-dedup-and-text", "parser-caps-values-and-still-scans-remainder",
                    "parser-no-ede-and-valid-compressed-other-records"}
        for kind in ("doh", "dot", "proxyTCP"):
            expected.update({kind + "-question-and-ede-case-" + str(sample) for sample in range(5)})
            expected.update({kind + suffix for suffix in (
                "-qtype-before-dial-failure", "-reuse-retry-eof", "-reuse-retry-answer",
                "-cancel-and-late-response", "-timeout-retains-question-only")})
        if result.returncode != 1 or set(report["failedGroups"]) != expected:
            raise RuntimeError("baseline did not reproduce exactly the expected missing metadata groups")
        print("PASS Build19 baseline: expected optional QTYPE/EDE fields absent; framing and response boundaries unchanged")
    elif result.returncode:
        raise SystemExit(result.returncode)
    print(f"Production and test source unchanged; artifacts: {work}")


if __name__ == "__main__":
    main()

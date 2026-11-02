#!/usr/bin/env python3
"""Exercise exact engine forwarding and router prewarm scheduling in memory.

Policy preparation and transport I/O are controlled. Actual production dispatch,
generation checks and cancellation/retirement declarations are compiled verbatim.
Use test_dns_prewarm_evidence.py for the independent real DNS pool/flow boundaries.
No SwiftPM build, listener, GUI, Helper or system-network setting is involved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from dns_test_sources import PACKAGE_FLAGS, declaration, source_path, source_text, write_source_inventory


ROOT = Path(__file__).resolve().parents[1]


def member(text: str, class_marker: str, marker: str) -> tuple[str, int]:
    start = text.index(marker, text.index(class_marker))
    line_end = text.index("\n", start) + 1
    first = text[start:line_end]
    # Frozen Build43's engine entry is a one-line method. Preserve that line
    # intact; the compatibility overload is explicitly fixture-only below.
    if first.count("{") == first.count("}") and "{" in first:
        return first, start
    end = re.search(r"^    }\n", text[line_end:], re.M)
    if end is None:
        raise RuntimeError(f"Cannot find method end: {marker}")
    return text[start:line_end + end.end()], start


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/dns-immediate-prewarm")
    parser.add_argument("--legacy-engine-source", type=Path,
                        help="explicit frozen Build43 source; only its old engine entry is used as a negative control")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    snapshots: list[tuple[Path, str]] = []
    manifest: list[dict] = []

    def retain(path: Path, text: str, marker: str, start: int = 0) -> str:
        snapshots.append((path, text))
        digest = hashlib.sha256(text.encode()).hexdigest()
        manifest.append({"source": str(path.relative_to(ROOT)), "marker": marker,
                         "firstLine": path.read_text()[:start].count("\n") + 1,
                         "sha256": digest, "unchanged": True})
        return f"\n// Verbatim {path.name}; SHA256 {digest}\n{text}"

    core = source_path("ProxyEngine.swift")
    current = source_text("ProxyEngine.swift")
    dependencies = []
    for filename, marker in [
        ("DNSQueryContracts.swift", "public protocol DNSQueryDatagram:"),
        ("DNSQueryContracts.swift", "public enum DNSAttemptCancellationReason:"),
        ("DNSQueryContracts.swift", "package protocol DNSQueryCancellationAcknowledging:"),
        ("ProxyEngine.swift", "public protocol NativeRoutedDatagram:"),
        ("DNSConnectionPrewarming.swift", "protocol DNSConnectionPrewarming:"),
        ("ProxyEngine.swift", "private final class WeakDNSQueryDatagram {"),
        ("RoutingTypes.swift", "public struct RequestTarget:"),
    ]:
        path, text, start = declaration(filename, marker)
        dependencies.append(retain(path, text, marker, start))
    inspection = source_path("DNSMessageInspection.swift")
    dependencies.append(retain(inspection, source_text("DNSMessageInspection.swift"), "whole file"))
    fields_start = current.index('    private let dnsPrewarmQueue = DispatchQueue(')
    fields_end = current.index("\n    public init(profile:", fields_start)
    fields = retain(core, current[fields_start:fields_end], "prewarm fields", fields_start)
    methods = []
    for marker in [
        "    public func prewarmDNS(immediately: Bool = false) {",
        "    private func beginDNSPrewarm(",
        "    fileprivate func isCurrentDNSGeneration(",
        "    private func detachEncryptedResolversLocked()",
        "    fileprivate func cancelDNSQueries(",
    ]:
        text, start = member(current, "public final class NativePacketRouter {", marker)
        methods.append(retain(core, text, marker, start))

    if args.legacy_engine_source:
        legacy = args.legacy_engine_source.resolve()
        frozen = legacy.read_text(encoding="utf-8")
        text, start = member(frozen, "public final class ProxyEngine {", "    public func prewarmDNS()")
        engine = retain(legacy, text, "frozen Build43 engine default entry", start)
        engine += """
    // FIXTURE-ONLY negative-control adapter: the frozen API has no immediate
    // parameter. Discard it and run the exact old default entry unchanged.
    func prewarmDNS(immediately: Bool) { prewarmDNS() }
"""
    else:
        marker = "    public func prewarmDNS(immediately: Bool = false) {"
        text, start = member(current, "public final class ProxyEngine {", marker)
        engine = retain(core, text, "ProxyEngine immediate forwarding", start)

    fixture_path = ROOT / "SmokeTests/DNSImmediatePrewarmMain.swift"
    fixture = fixture_path.read_text(encoding="utf-8")
    retain(fixture_path, fixture, "whole fixture")
    retain(Path(__file__).resolve(), Path(__file__).read_text(encoding="utf-8"), "whole runner")
    for marker, code in {
        "// INSERT_PRODUCTION_DEPENDENCIES": "\n".join(dependencies),
        "    // INSERT_PRODUCTION_ROUTER_FIELDS": fields,
        "    // INSERT_PRODUCTION_ROUTER_METHODS": "\n".join(methods),
        "    // INSERT_PRODUCTION_ENGINE_METHOD": engine,
    }.items():
        if fixture.count(marker) != 1:
            raise RuntimeError(f"Nonunique fixture boundary: {marker}")
        fixture = fixture.replace(marker, code)
    generated = work / "ProductionDNSImmediatePrewarm.swift"
    generated.write_text(fixture, encoding="utf-8")
    binary = work / "dns-immediate-prewarm"
    command = ["xcrun", "swiftc", *PACKAGE_FLAGS, "-swift-version", "5", "-Onone",
               "-parse-as-library", str(generated), "-framework", "Foundation", "-framework", "Network",
               "-o", str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr)[-18000:])
        raise SystemExit(compiled.returncode)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20, check=False)
    (work / "results.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout + result.stderr, end="")
    for row, (path, text) in zip(manifest, snapshots):
        row["unchanged"] = text in path.read_text(encoding="utf-8")
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    write_source_inventory(work)
    receipt = {"exitCode": result.returncode, "legacyEngineAdapter": bool(args.legacy_engine_source),
               "engineSource": str(args.legacy_engine_source or core),
               "productionSHA256": hashlib.sha256(current.encode()).hexdigest(),
               "binarySHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "declarationsUnchanged": all(row["unchanged"] for row in manifest)}
    (work / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    if not receipt["declarationsUnchanged"]:
        raise RuntimeError("Tested declarations changed during the run; repeat against a stable snapshot")
    if result.returncode == 0:
        report = json.loads(result.stdout.splitlines()[-1])
        (work / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()

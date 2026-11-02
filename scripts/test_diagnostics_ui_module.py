#!/usr/bin/env python3
"""Import the real diagnostics test support using existing SwiftPM products.

The shared test support supplies memory snapshots, a monotonic clock, held
callbacks and cancellation handles. A test-only window supplies real Auto Layout
delivery without ever being shown, ordered, activated or run. There is no App
controller, Helper, listener, resolver, network request or clipboard write. Core
and native products are linked from source-checked output maps, never rebuilt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from swiftpm_test_support import ROOT, collect_prebuilt_inputs, default_build_directory


def swift_code(source: str) -> str:
    """Mask comments and literals for these direct source-boundary checks."""
    tokens = re.compile(r'//[^\n]*|/\*.*?\*/|""".*?"""|"(?:\\.|[^"\\])*"', re.DOTALL)
    return tokens.sub(lambda match: "".join("\n" if char == "\n" else " " for char in match[0]), source)


def validate_module_boundaries(work: Path) -> None:
    ui = sorted((ROOT / "Sources/HajimiDiagnosticsUI").rglob("*.swift"))
    support = sorted((ROOT / "Sources/HajimiDiagnosticsUITestSupport").rglob("*.swift"))
    if not ui or not support:
        raise RuntimeError("Both actual diagnostics UI and test-support targets must contain Swift sources")
    violations = []
    for path in ui:
        code = swift_code(path.read_text(encoding="utf-8"))
        if "SelfTest" in path.name or re.search(r"\b\w*SelfTest\b", code):
            violations.append(str(path.relative_to(ROOT)) + ": production UI contains self-tests")
        if re.search(r"\bimport\s+\w*TestSupport\b", code):
            violations.append(str(path.relative_to(ROOT)) + ": production UI imports test support")
    package = (ROOT / "Package.swift").read_text(encoding="utf-8")
    dependencies = re.findall(r'\.target\(name:\s*"HajimiDiagnosticsUI"\s*,\s*dependencies:\s*\[([^\]]*)\]',
                              package, flags=re.DOTALL)
    ui_dependencies = re.findall(r'"([^"\n]+)"', dependencies[0]) if len(dependencies) == 1 else []
    if len(dependencies) != 1:
        violations.append("Package.swift: cannot identify the production diagnostics UI dependency list")
    elif any("TestSupport" in name for name in ui_dependencies):
        violations.append("Package.swift: production diagnostics UI depends on test support")
    allowed_imports = {"AppKit", "Foundation", "HajimiCore", "HajimiDiagnosticsUI",
                       "HajimiRuntime", "HajimiUIComponents"}
    forbidden = [
        (r"\bNSPasteboard\b|\bcopyToPasteboard\b", "real pasteboard reference"),
        (r"\bNS(?:Window|Panel|WindowController)\b", "window owner reference"),
        (r"\b(?:NSApp|NSApplication\.shared)\s*\.\s*(?:run|activate|setActivationPolicy)\s*\(",
         "application event loop or activation"),
        (r"\b(?:SCDynamicStore\w*|SCNetwork\w*|getifaddrs|getaddrinfo|NWConnection|NWPathMonitor|URLSession)\b",
         "platform capture or network operation"),
        (r"\b(?:socket|connect|sendto|recvfrom)\s*\(", "IP socket operation"),
        (r"\b(?:ProbeScheduler|NetworkPerformanceDiagnostics)\s*\.\s*shared\b", "global diagnostics owner"),
        (r"\b(?:LocalNetworkDiagnostics|NetworkDiagnosticsAppAdapter|ProxyEngine|NativePacketRouter|NativeTunnel)\b",
         "App or native resource owner"),
    ]
    imported = set()
    for path in support:
        code = swift_code(path.read_text(encoding="utf-8"))
        modules = re.findall(r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*import\s+([A-Za-z_]\w*)", code, re.MULTILINE)
        imported.update(modules)
        for module in sorted(set(modules) - allowed_imports):
            violations.append(f"{path.relative_to(ROOT)}: unsupported import {module}")
        for pattern, reason in forbidden:
            if re.search(pattern, code):
                violations.append(f"{path.relative_to(ROOT)}: {reason}")
    report = {"productionUISources": [str(path.relative_to(ROOT)) for path in ui],
              "productionUIDependencies": ui_dependencies,
              "testSupportSources": [str(path.relative_to(ROOT)) for path in support],
              "testSupportImports": sorted(imported), "violations": violations,
              "passed": not violations}
    (work / "module-boundaries.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if violations:
        raise RuntimeError("Diagnostics module boundary check failed:\n" + "\n".join(violations))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", choices=["debug", "release"], default="release")
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/diagnostics-ui-module-tests")
    parser.add_argument("--skip-local-collector", action="store_true",
                        help="omit the separate, existing local-snapshot assembly fixture")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    validate_module_boundaries(work)
    prebuilt = collect_prebuilt_inputs(args.build_dir or default_build_directory(args.configuration), work,
                                       extra_swift_targets=("HajimiDiagnosticsUITestSupport",))
    runners = [("diagnostics-ui", [ROOT / "SmokeTests/NetworkDiagnosticsUIMain.swift"])]
    if not args.skip_local_collector:
        runners.append(("local-network", [ROOT / "Sources/HajimiApp/LocalNetworkDiagnostics.swift",
                                          ROOT / "SmokeTests/LocalNetworkDiagnosticsMain.swift"]))
    sources = {path for _, inputs in runners for path in inputs}
    sources.update({Path(__file__).resolve(), ROOT / "scripts/swiftpm_test_support.py", ROOT / "scripts/dns_test_sources.py"})
    frozen = {}
    expected = {}
    for source in sorted(sources):
        raw = source.read_bytes()
        destination = work / "inputs" / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        frozen[source] = destination
        expected[source] = hashlib.sha256(raw).hexdigest()
    isolated = work / "isolated-preferences"
    isolated.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment["CFFIXED_USER_HOME"] = str(isolated)
    outputs = []
    for name, inputs in runners:
        binary = work / (name + "-module-check")
        command = ["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library", *prebuilt.flags,
                   *[str(frozen[path]) for path in inputs], *prebuilt.objects, *prebuilt.libraries,
                   *prebuilt.linker_flags, "-o", str(binary)]
        (work / (name + "-compile-command.json")).write_text(json.dumps(command, indent=2) + "\n")
        result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=120, check=False)
        (work / (name + "-compile.log")).write_text(result.stdout, encoding="utf-8")
        if result.returncode:
            print(result.stdout[-18000:], end="", flush=True)
            raise SystemExit(result.returncode)
        result = subprocess.run([str(binary)], cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=30, check=False)
        (work / (name + "-results.log")).write_text(result.stdout, encoding="utf-8")
        print(result.stdout, end="", flush=True)
        outputs.append(result.stdout)
        if result.returncode:
            raise SystemExit(result.returncode)
        if name == "diagnostics-ui":
            counts = re.findall(r"^Diagnostics UI module passed: (\d+) public capability assertions\b",
                                result.stdout, re.MULTILINE)
            if counts != ["67", "67"]:
                raise RuntimeError("The same process must complete two independent 67-assertion capability runs")
            layout_counts = re.findall(r"^Diagnostics dynamic scroll passed: (\d+) assertions\b",
                                       result.stdout, re.MULTILINE)
            if layout_counts != ["390", "390"]:
                raise RuntimeError("Both runs must complete the 390-assertion dynamic scroll matrix")
            if "Diagnostics layout window was never ordered, activated or run; memory snapshots only" not in result.stdout:
                raise RuntimeError("The unshown fixture window invariant was not verified")
    prebuilt.verify()
    manifest = [{"source": str(path.relative_to(ROOT)), "sha256": expected[path],
                 "frozenPath": str(frozen[path]), "wholeFile": True,
                 "unchanged": hashlib.sha256(path.read_bytes()).hexdigest() == expected[path]
                     and hashlib.sha256(frozen[path].read_bytes()).hexdigest() == expected[path]}
                for path in sorted(sources)]
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (work / "results.log").write_text("".join(outputs), encoding="utf-8")
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("A diagnostics fixture input changed during execution")
    print(f"PASS real import HajimiDiagnosticsUITestSupport twice; module boundaries, {len(manifest)} fixture inputs and all prebuilt sources stable; artifacts: {work}")


if __name__ == "__main__":
    main()

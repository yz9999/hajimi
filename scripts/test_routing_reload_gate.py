#!/usr/bin/env python3
"""Run the complete real App reload gate with its existing memory cases.

Compiles the Foundation-only runtime, the real Profile/value parser files and
the complete unmodified gate declaration/self-test with a standalone runner.
There is no App, Helper, GUI, native build, listener or network. Every compiler
input is frozen before compilation and checked against its live source after
the run; the runtime never receives a Profile or resource owner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess

from routing_test_support import build_routing_module


ROOT = Path(__file__).resolve().parents[1]


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/routing-reload-gate")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    routing = build_routing_module(work)
    runtime = sorted((ROOT / "Sources/HajimiRuntime").glob("*.swift"))
    core = [ROOT / "Sources/HajimiCore/Profile.swift", ROOT / "Sources/HajimiCore/SurgeProfileDocument.swift"]
    gate = ROOT / "Sources/HajimiApp/RoutingReloadGate.swift"
    runner = ROOT / "SmokeTests/RoutingReloadGateMain.swift"
    sources = runtime + core + [gate, runner, Path(__file__).resolve()]
    frozen: dict[Path, Path] = {}
    expected: dict[Path, str] = {}
    for source in sources:
        raw = source.read_bytes()
        expected[source] = sha(raw)
        destination = work / "inputs" / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        frozen[source] = destination
    manifest = {str(source.relative_to(ROOT)): expected[source] for source in sources}
    manifest.update({row["source"]: row["sha256"] for row in routing.manifest})
    (work / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    def run(label: str, command: list[str], timeout: int = 180) -> None:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False)
        output = result.stdout + result.stderr
        (work / (label + ".log")).write_text(output, encoding="utf-8")
        if result.returncode:
            print(output, end="")
            raise SystemExit(result.returncode)
        if label == "results":
            print(output, end="")

    flags = ["-O", "-swift-version", "5", "-target", platform.machine() + "-apple-macos13.0", "-parse-as-library"]
    for module, inputs in [("HajimiRuntime", runtime), ("HajimiCore", core)]:
        run(module + "-compile", ["xcrun", "swiftc", *flags, "-emit-module", "-emit-library", "-module-name", module,
            *(routing.flags if module == "HajimiCore" else []),
            *[str(frozen[source]) for source in inputs], "-emit-module-path", str(work / (module + ".swiftmodule")),
            "-Xlinker", "-install_name", "-Xlinker", "@rpath/lib" + module + ".dylib",
            "-o", str(work / ("lib" + module + ".dylib"))])
    binary = work / "routing-reload-gate-check"
    run("gate-compile", ["xcrun", "swiftc", *flags, "-I", str(work), "-L", str(work),
        *routing.flags,
        "-lHajimiRuntime", "-lHajimiCore", "-Xlinker", "-rpath", "-Xlinker", "@loader_path",
        str(frozen[gate]), str(frozen[runner]), "-o", str(binary)])
    run("results", [str(binary)], timeout=30)
    routing.verify()
    unchanged = all(sha(source.read_bytes()) == digest and sha(frozen[source].read_bytes()) == digest
                    for source, digest in expected.items())
    (work / "source-unchanged.json").write_text(json.dumps({"unchanged": unchanged, "inputCount": len(manifest)}, indent=2) + "\n")
    if not unchanged:
        raise RuntimeError("reload-gate compilation input changed during its run")
    print(f"Frozen real routing gate passed; {len(manifest)} source inputs unchanged; artifacts: {work}")


if __name__ == "__main__":
    main()

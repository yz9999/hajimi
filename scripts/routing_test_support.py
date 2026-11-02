"""Build the real, dependency-free routing module for standalone fixtures.

Each caller receives a frozen source manifest and linker flags. No Core,
C++ implementation, App, Helper or platform resource is built or started.
The frozen and live inputs must still match when a fixture completes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import platform
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass
class RoutingTestModule:
    directory: Path
    manifest: list[dict]

    @property
    def flags(self) -> list[str]:
        return ["-package-name", "Hajimi", "-I", str(self.directory),
                "-L", str(self.directory), "-lHajimiRouting",
                "-Xlinker", "-rpath", "-Xlinker", str(self.directory)]

    def verify(self) -> None:
        for row in self.manifest:
            row["unchanged"] = digest((ROOT / row["source"]).read_bytes()) == row["sha256"]
            if "frozenPath" in row:
                row["unchanged"] = row["unchanged"] and digest(
                    Path(row["frozenPath"]).read_bytes()) == row["sha256"]
        (self.directory.parent / "routing-source-manifest.json").write_text(
            json.dumps(self.manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if not all(row["unchanged"] for row in self.manifest):
            raise RuntimeError("Routing fixture inputs changed; rerun the coherent snapshot")


def build_routing_module(work: Path) -> RoutingTestModule:
    sources = sorted((ROOT / "Sources/HajimiRouting").glob("*.swift"))
    if not sources:
        raise RuntimeError("The production HajimiRouting target has no Swift sources")
    directory = work / "routing-module"
    inputs = work / "routing-sources"
    directory.mkdir(parents=True, exist_ok=True)
    inputs.mkdir(parents=True, exist_ok=True)
    frozen = []
    manifest = []
    for source in sources:
        raw = source.read_bytes()
        destination = inputs / source.name
        destination.write_bytes(raw)
        frozen.append(destination)
        manifest.append({"source": str(source.relative_to(ROOT)), "sha256": digest(raw),
                         "wholeFile": True, "frozenPath": str(destination), "unchanged": True})
    helper = Path(__file__).resolve()
    manifest.append({"source": str(helper.relative_to(ROOT)), "sha256": digest(helper.read_bytes()),
                     "wholeFile": True, "unchanged": True})
    command = ["xcrun", "swiftc", "-O", "-swift-version", "5", "-package-name", "Hajimi",
               "-target", platform.machine() + "-apple-macos13.0", "-parse-as-library",
               "-emit-module", "-emit-library", "-module-name", "HajimiRouting",
               *map(str, frozen), "-emit-module-path", str(directory / "HajimiRouting.swiftmodule"),
               "-Xlinker", "-install_name", "-Xlinker", "@rpath/libHajimiRouting.dylib",
               "-o", str(directory / "libHajimiRouting.dylib")]
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=120, check=False)
    (work / "routing-compile.log").write_text(result.stdout, encoding="utf-8")
    (work / "routing-compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    module = RoutingTestModule(directory, manifest)
    module.verify()
    if result.returncode:
        print(result.stdout[-18000:], end="", flush=True)
        raise SystemExit(result.returncode)
    return module

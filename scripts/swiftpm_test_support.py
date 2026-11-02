"""Source-aware linker inputs for fixtures using existing SwiftPM products.

This helper never invokes SwiftPM, launches the App/Helper or starts network
operations. Swift objects come only from the current output-file-map, and
native objects are selected from current source paths instead of a glob of
possibly obsolete build products. Input hashes remain available for review.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform

from dns_test_sources import ROOT, swift_target_objects


SWIFT_TARGETS = ("HajimiCore", "HajimiDNS", "HajimiRouting", "HajimiRuntime",
                 "HajimiUIComponents", "HajimiDiagnosticsUI")
NATIVE_TARGETS = ("HajimiCXXProtocolBridge", "HajimiProtocolsCXX", "HajimiProtocolCXX",
                  "HajimiProxyRuntime", "HajimiRoutingCXX")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class PrebuiltTestInputs:
    flags: list[str]
    objects: list[str]
    libraries: list[str]
    manifest: list[dict]
    work: Path

    @property
    def linker_flags(self) -> list[str]:
        return ["-lc++", "-framework", "Foundation", "-framework", "AppKit",
                "-framework", "Network", "-framework", "Security",
                "-framework", "CoreFoundation", "-framework", "SystemConfiguration"]

    def verify(self) -> None:
        for row in self.manifest:
            path = Path(row["path"])
            row["unchanged"] = path.is_file() and digest(path) == row["sha256"]
        (self.work / "prebuilt-input-manifest.json").write_text(
            json.dumps(self.manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if not all(row["unchanged"] for row in self.manifest):
            raise RuntimeError("A prebuilt fixture input changed during execution")


def default_build_directory(configuration: str) -> Path:
    return ROOT / ".build" / (platform.machine() + "-apple-macosx") / configuration


def collect_prebuilt_inputs(build: Path, work: Path, *,
                            extra_swift_targets: tuple[str, ...] = ()) -> PrebuiltTestInputs:
    build = build.resolve()
    if not build.is_dir():
        raise RuntimeError("The requested prebuilt directory does not exist: " + str(build))
    work.mkdir(parents=True, exist_ok=True)
    records: dict[Path, dict] = {}

    def retain(path: Path, kind: str, target: str | None = None) -> None:
        path = path.resolve()
        if not path.is_file():
            raise RuntimeError("Missing prebuilt fixture input: " + str(path))
        if path in records:
            return
        row = {"path": str(path), "kind": kind, "sha256": digest(path), "unchanged": True}
        if path.is_relative_to(ROOT):
            row["source"] = str(path.relative_to(ROOT))
        if target:
            row["target"] = target
        records[path] = row

    flags = ["-I", str(build)]
    if (build / "Modules").is_dir():
        flags += ["-I", str(build / "Modules")]
    objects = []
    selected_swift_targets = tuple(dict.fromkeys((*SWIFT_TARGETS, *extra_swift_targets)))
    for target in selected_swift_targets:
        module = build / (target + ".swiftmodule")
        if not module.is_file():
            module = build / "Modules" / (target + ".swiftmodule")
        retain(module, "swiftModule", target)
        output_map = build / (target + ".build") / "output-file-map.json"
        retain(output_map, "swiftOutputMap", target)
        planned_objects = swift_target_objects(build, target)
        mapping = {Path(name).resolve(): Path(record["object"]).resolve()
                   for name, record in json.loads(output_map.read_text(encoding="utf-8")).items() if name}
        sources = sorted((ROOT / "Sources" / target).rglob("*.swift"))
        for source in sources:
            # Swift preserves an unchanged serialized public module, even
            # when a new implementation has been compiled and linked. The
            # current output-map object is the implementation freshness gate.
            if source.stat().st_mtime_ns > mapping[source.resolve()].stat().st_mtime_ns:
                raise RuntimeError(f"The {target} object is older than {source.name}; complete the external build first")
            retain(source, "productionSource", target)
        for obj in planned_objects:
            retain(obj, "swiftObject", target)
            objects.append(str(obj))
    for target in NATIVE_TARGETS:
        source_root = ROOT / "Sources" / target
        module_map = build / (target + ".build") / "module.modulemap"
        retain(module_map, "nativeModuleMap", target)
        flags += ["-I", str(source_root / "include"), "-Xcc", "-fmodule-map-file=" + str(module_map)]
        sources = sorted(path for path in source_root.rglob("*") if path.suffix in {".c", ".cpp", ".mm"})
        if not sources:
            raise RuntimeError("No current native inputs for " + target)
        for source in sources:
            obj = build / (target + ".build") / (str(source.relative_to(source_root)) + ".o")
            retain(source, "productionSource", target)
            retain(obj, "nativeObject", target)
            objects.append(str(obj))
        for header in sorted(path for path in source_root.rglob("*") if path.suffix in {".h", ".hpp"}):
            retain(header, "productionHeader", target)
    default_ssl = Path("/opt/homebrew/opt/openssl@3")
    if not (default_ssl / "include/openssl/ssl.h").is_file():
        default_ssl = Path("/usr/local/opt/openssl@3")
    ssl = Path(os.environ.get("HAJIMI_OPENSSL_ROOT", str(default_ssl)))
    if (ssl / platform.machine()).is_dir():
        ssl = ssl / platform.machine()
    libraries = [ROOT / ".build/Vendor/HajimiQUIC/lib/libngtcp2_crypto_ossl.a",
                 ROOT / ".build/Vendor/HajimiQUIC/lib/libngtcp2.a",
                 ROOT / ".build/Vendor/HajimiQUIC/lib/libnghttp3.a",
                 ROOT / ".build/Vendor/HajimiSSH/lib/libssh2.a", ssl / "lib/libssl.a", ssl / "lib/libcrypto.a"]
    for library in libraries:
        retain(library, "staticLibrary")
    for helper in [Path(__file__).resolve(), ROOT / "scripts/dns_test_sources.py", ROOT / "Package.swift"]:
        retain(helper, "fixtureBuildInput")
    result = PrebuiltTestInputs(flags, objects, [str(path) for path in libraries], list(records.values()), work)
    result.verify()
    return result

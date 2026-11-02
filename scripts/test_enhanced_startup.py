#!/usr/bin/env python3
"""Check enhanced startup with exact production sources and isolated transports.

Only NativeCore is recompiled, against a completed release build's Core and
native-library objects. No SwiftPM build, GUI, Helper, IP socket or system
network setting is started. Production client session methods are additionally
tested against malformed fake IPC replies. A manifest records source hashes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_logged(command: list[str], log: Path, timeout: int) -> None:
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout, check=False)
    log.write_text(result.stdout, encoding="utf-8")
    if result.returncode:
        print(result.stdout[-20000:], end="", flush=True)
        raise SystemExit(result.returncode)


def compile_runtime(work: Path, snapshots: list[dict]) -> Path:
    source_directory = work / "runtime-sources"
    module_directory = work / "runtime-module"
    source_directory.mkdir(parents=True, exist_ok=True)
    module_directory.mkdir(parents=True, exist_ok=True)
    copied = []
    for source in sorted((ROOT / "Sources/HajimiRuntime").glob("*.swift")):
        raw = source.read_bytes()
        target = source_directory / source.name
        target.write_bytes(raw)
        copied.append(str(target))
        snapshots.append({"source": str(source.relative_to(ROOT)), "wholeFile": True,
                          "sha256": hashlib.sha256(raw).hexdigest()})
    run_logged(["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library",
                "-emit-module", "-emit-library", "-module-name", "HajimiRuntime", *copied,
                "-emit-module-path", str(module_directory / "HajimiRuntime.swiftmodule"),
                "-Xlinker", "-install_name", "-Xlinker", "@rpath/libHajimiRuntime.dylib",
                "-o", str(module_directory / "libHajimiRuntime.dylib")], work / "runtime-compile.log", 90)
    return module_directory


def compile_client(work: Path, snapshots: list[dict]) -> Path:
    source_path = ROOT / "Sources/HajimiApp/PrivilegedHelperClient.swift"
    source = source_path.read_text(encoding="utf-8")

    def retained(marker: str, text: str, first: int) -> str:
        snapshots.append({"source": str(source_path.relative_to(ROOT)), "marker": marker,
                          "firstLine": source[:first].count("\n") + 1,
                          "sha256": hashlib.sha256(text.encode()).hexdigest(), "text": text})
        return f"\n// Verbatim production declaration: {marker}\n{text}"

    def declaration(marker: str) -> str:
        matches = list(re.finditer(r"^" + re.escape(marker) + r"[^\n]*\n", source, re.M))
        if len(matches) != 1:
            raise RuntimeError(f"Missing unique production declaration: {marker}")
        first = matches[0].start()
        indent = re.match(r" *", marker).group()
        end = re.search(r"^" + indent + r"}\n", source[matches[0].end():], re.M)
        if end is None:
            raise RuntimeError(f"Missing declaration end: {marker}")
        finish = matches[0].end() + end.end()
        return retained(marker, source[first:finish], first)

    first = source.index("    struct TunnelSession {")
    finish = source.index("    /// Prompts only", first)
    declarations = [declaration("    enum ClientError:"), declaration("    static var adHocOptInPath:"),
                    declaration("    func isCompatible("), declaration("    private struct DecodedHelperResponse {"),
                    declaration("    private static func validateResponse(")]
    declarations.append(retained("TunnelSession and session operations", source[first:finish], first))
    injected = """
    private var fixtureResponse: DecodedHelperResponse?
    private var fixtureCalls: [(request: HajimiHelperRequest, expectFD: Bool)] = []
    private func request(_ request: HajimiHelperRequest,
                         expectFileDescriptor: Bool = false) throws -> DecodedHelperResponse {
        fixtureCalls.append((request, expectFileDescriptor))
        guard let response = fixtureResponse else { throw ClientError.invalidResponse }
        fixtureResponse = nil
        return response
    }
"""
    test_path = ROOT / "SmokeTests/EnhancedStartupClientValidation.swift"
    protocol_path = ROOT / "Sources/HajimiIPC/PrivilegedHelperProtocol.swift"
    intent_path = ROOT / "Sources/HajimiApp/EnhancedStartupIntent.swift"
    for path in [test_path, protocol_path, intent_path]:
        snapshots.append({"source": str(path.relative_to(ROOT)), "wholeFile": True,
                          "sha256": digest(path)})
    generated = work / "IsolatedProductionStartupClient.swift"
    generated.write_text("import Foundation\nimport Darwin\nfinal class PrivilegedHelperClient {\n" +
                         "\n".join(declarations) + injected + "}\n" + test_path.read_text(),
                         encoding="utf-8")
    runtime_module = compile_runtime(work, snapshots)
    binary = work / "startup-client-validation"
    run_logged(["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library",
                str(protocol_path), str(intent_path), str(generated),
                "-I", str(runtime_module), "-L", str(runtime_module), "-lHajimiRuntime",
                "-Xlinker", "-rpath", "-Xlinker", "@loader_path/runtime-module", "-o", str(binary)],
               work / "client-compile.log", 90)
    return binary


def compile_reader(build: Path, work: Path, snapshots: list[dict]) -> Path:
    description = json.loads((build / "description.json").read_text())
    native = description["swiftCommands"]["C.HajimiNativeCore-release.module"]
    arguments = native["otherArguments"]
    selected: list[str] = []
    index = 0
    while index < len(arguments):
        item = arguments[index]
        if item in {"-emit-objc-header-path", "-module-cache-path"}:
            index += 2
            continue
        if item not in {"-parseable-output", "-emit-objc-header"} and not re.fullmatch(r"-j\d+", item):
            selected.append(item)
        index += 1
    selected += ["-whole-module-optimization", "-module-cache-path", str(work / "ModuleCache")]
    objects = shlex.split((build / "Hajimi.product/Objects.LinkFileList").read_text())
    objects = [item for item in objects if Path(item).parent.name not in
               {"HajimiNativeCore.build", "HajimiApp.build"}]
    release_yaml = build.parent.parent / "release.yaml"
    link = next(json.loads(line.split("args: ", 1)[1]) for line in release_yaml.read_text().splitlines()
                if "args: [" in line and str(build / "Hajimi.product/Objects.LinkFileList") in line)
    libraries = [item for item in link if item.endswith(".a")]
    frameworks: list[str] = []
    platform: list[str] = []
    for index, item in enumerate(link):
        if item == "-framework":
            frameworks += [item, link[index + 1]]
        if item in {"-target", "-sdk"}:
            platform += [item, link[index + 1]]
    # A completed build description predates this task's new readiness source.
    # Compile every current NativeCore file rather than silently missing it.
    inputs = sorted((ROOT / "Sources/HajimiNativeCore").glob("*.swift"))
    inputs.append(ROOT / "SmokeTests/NativeTunnelReaderReadyMain.swift")
    copied: list[str] = []
    snapshot_directory = work / "sources"
    snapshot_directory.mkdir(parents=True, exist_ok=True)
    for source in inputs:
        target = snapshot_directory / source.name
        raw = source.read_bytes()
        target.write_bytes(raw)
        snapshots.append({"source": str(source.relative_to(ROOT)),
                          "sha256": hashlib.sha256(raw).hexdigest(), "wholeFile": True})
        copied.append(str(target))
    output = work / "native-reader-ready"
    native_object = work / "NativeReaderReady.o"
    run_logged(["xcrun", "swiftc", "-module-name", "HajimiNativeCore", "-I", str(build),
                *selected, "-emit-object", *copied, "-o", str(native_object)],
               work / "reader-compile.log", 240)
    run_logged(["xcrun", "swiftc", "-emit-executable", "-I", str(build), *platform,
                str(native_object), *objects, "-lc++", *frameworks, *libraries,
                "-Xlinker", "-dead_strip", "-o", str(output)], work / "reader-link.log", 120)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path,
                        help="completed x86_64/arm64 release directory containing description.json")
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/enhanced-startup-validation")
    parser.add_argument("--client-only", action="store_true", help="skip the NativeCore compile")
    parser.add_argument("--reader-only", action="store_true", help="skip the isolated client checks")
    arguments = parser.parse_args()
    work = arguments.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    snapshots: list[dict] = []
    script = Path(__file__).resolve()
    snapshots.append({"source": str(script.relative_to(ROOT)), "wholeFile": True,
                      "sha256": digest(script)})
    if arguments.reader_only and arguments.client_only:
        parser.error("--reader-only and --client-only are mutually exclusive")
    if not arguments.reader_only:
        binary = compile_client(work, snapshots)
        run_logged([str(binary)], work / "client-results.log", 15)
        print((work / "client-results.log").read_text(), end="", flush=True)
    if not arguments.client_only:
        if arguments.build_dir is None:
            parser.error("reader checks require --build-dir")
        binary = compile_reader(arguments.build_dir.resolve(), work, snapshots)
        run_logged([str(binary)], work / "reader-results.log", 30)
        print((work / "reader-results.log").read_text(), end="", flush=True)
    for snapshot in snapshots:
        if "text" in snapshot:
            text = snapshot.pop("text")
            snapshot["unchanged"] = text in (ROOT / snapshot["source"]).read_text()
        else:
            snapshot["unchanged"] = digest(ROOT / snapshot["source"]) == snapshot["sha256"]
    (work / "source-manifest.json").write_text(json.dumps(snapshots, ensure_ascii=False, indent=2) + "\n",
                                              encoding="utf-8")
    if not all(item["unchanged"] for item in snapshots):
        raise RuntimeError("Tested source changed during compilation; rerun the coherent production snapshot")
    print(f"Production sources unchanged; manifest={work / 'source-manifest.json'}")


if __name__ == "__main__":
    main()

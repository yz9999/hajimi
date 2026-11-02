#!/usr/bin/env python3
"""Build only NativeCore against completed release objects, or test an App CLI.

No SwiftPM/build dependencies, GUI, IP socket, Helper or network setting is
started. Swift's descriptor fixture validates real TCP bytes and checksums.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import subprocess

FLAG = "--native-tunnel-packet-load-self-test"


def has_cli_flag(binary: Path) -> bool:
    needle, tail = FLAG.encode("ascii"), b""
    with binary.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            data = tail + chunk
            if needle in data:
                return True
            tail = data[-len(needle):]
    return False


def compile_fixture(build: Path, output: Path) -> None:
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
        if item not in {"-parseable-output", "-emit-objc-header", "-j8"}:
            selected.append(item)
        index += 1
    output.parent.mkdir(parents=True, exist_ok=True)
    selected += ["-whole-module-optimization", "-module-cache-path", str(output.parent / "ModuleCache")]
    objects = shlex.split((build / "Hajimi.product/Objects.LinkFileList").read_text())
    objects = [item for item in objects if Path(item).parent.name not in {"HajimiNativeCore.build", "HajimiApp.build"}]
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
    sources = [item["name"] for item in native["inputs"] if item["name"].endswith(".swift")]
    root = Path(__file__).resolve().parents[1]
    native_object = output.with_suffix(".o")
    subprocess.run(["xcrun", "swiftc", "-module-name", "HajimiNativeCore", "-I", str(build), *selected,
                    "-emit-object", *sources, str(root / "SmokeTests/NativeTunnelPacketLoadMain.swift"),
                    "-o", str(native_object)], check=True)
    subprocess.run(["xcrun", "swiftc", "-emit-executable", "-I", str(build), *platform,
                    str(native_object), *objects, "-lc++", *frameworks, *libraries,
                    "-Xlinker", "-dead_strip", "-o", str(output)], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--compile-only", action="store_true")
    args = parser.parse_args()
    if args.build_dir:
        if not args.output:
            parser.error("--build-dir requires --output")
        compile_fixture(args.build_dir.resolve(), args.output.resolve())
        binary = args.output.resolve()
    elif args.binary:
        binary = args.binary.resolve()
    else:
        parser.error("provide --binary or --build-dir with --output")
    if args.compile_only:
        return
    if not binary.is_file() or not has_cli_flag(binary):
        parser.error("binary has no packet-load CLI fixture; refusing to launch an older App UI")
    result = subprocess.run([str(binary), FLAG],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    print(result.stdout, end="", flush=True)
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    reports = [json.loads(line.removeprefix("TUN-PACKET-LOAD ")) for line in result.stdout.splitlines()
               if line.startswith("TUN-PACKET-LOAD ")]
    if len(reports) != 2 or {item["scenario"] for item in reports} != {"ack-sack-packet-load", "download-packet-load"}:
        raise AssertionError("Both production packet workloads must report")
    for item in reports:
        if (item["exactBytesAndChecksums"] is not True or item["drainPacketsPeak"] > 1024
                or item["stopMilliseconds"] >= 1000 or item["outstandingCreated"] != item["outstandingAcknowledged"]):
            raise AssertionError("Packet correctness/drain/outstanding retirement was not preserved")
        if item.get("stopDuringContinuousIngress") is not True:
            raise AssertionError("Stop must run while valid packet ingress is still active")
        if (item["downloadStorageBoundViolations"] != 0
                or item["downloadStoredPeak"] < item["downloadBufferedPeak"]
                or item["downloadStoredPeak"] >= 2 * item["downloadBufferedPeak"] + 64 * 1024
                or item["downloadRetainedPrefixPeak"] > item["downloadStoredPeak"]):
            raise AssertionError("Logical download storage/prefix bound was not preserved")
        if item["scenario"] == "ack-sack-packet-load" and (item["floodPackets"] != 131072
                or item["selectiveAcknowledgmentPackets"] != 131072 or item["outstandingPeak"] < 500):
            raise AssertionError("ACK/SACK workload did not exercise a large real outstanding window")
    print("PASS independent packet-load report checks: both workloads, exact retired records, 131072 real SACK packets, logical download storage/prefix bounds")


if __name__ == "__main__":
    main()

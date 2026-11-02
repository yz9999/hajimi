#!/usr/bin/env python3
"""Exercise the bridge's exact private queue helper without native I/O."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("Sources/HajimiCXXProtocolBridge/HajimiCXXProtocolBridge.mm"))
    parser.add_argument("--work-dir", type=Path, default=Path(".build/cpp-post-dispatch-tests"))
    parser.add_argument("--allow-payload-copies", action="store_true", help="Baseline evidence only; preserve all semantic assertions")
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    fixture = Path("SmokeTests/CppPostDispatchMain.mm")
    original = {path: path.read_bytes() for path in (args.source, fixture, Path(__file__))}
    source = original[args.source].decode()
    start = source.index("void post(dispatch_queue_t queue,std::function<void()> work)")
    end = source.index("class PlatformStream", start)
    helper = source[start:end].strip()
    template = original[fixture].decode()
    marker = "// HAJIMI_PRODUCTION_POST_HELPER"
    if template.count(marker) != 1:
        raise RuntimeError("Post dispatch fixture must have one source insertion point")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    generated = args.work_dir / "CppPostDispatchActual.mm"
    binary = args.work_dir / "post-dispatch-check"
    generated.write_text(template.replace(marker, helper))
    manifest = {str(path): hashlib.sha256(content).hexdigest() for path, content in original.items()}
    manifest["actual_helper_sha256"] = hashlib.sha256(helper.encode()).hexdigest()
    (args.work_dir / "inputs.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    command = ["xcrun", "clang++", "-std=c++17", "-O2", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
               "-target", platform.machine() + "-apple-macos13.0", str(generated), "-framework", "Foundation", "-o", str(binary)]
    subprocess.run(command, check=True)
    run = [str(binary.resolve())]
    if not args.allow_payload_copies:
        run.append("--require-single-owner")
    if args.benchmark:
        run.append("--benchmark")
    result = subprocess.run(run, check=False)
    for path, content in original.items():
        if path.read_bytes() != content:
            raise RuntimeError("Source changed during post dispatch fixture: " + str(path))
    print("Post helper/fixture source inputs remained stable: " + str(len(original)), flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

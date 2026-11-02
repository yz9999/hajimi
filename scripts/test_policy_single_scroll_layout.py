#!/usr/bin/env python3
"""Exercise the actual policy page with offscreen, memory-only AppKit views.

The production builders, collection delegates and card classes are unchanged
inputs. Existing, source-checked SwiftPM objects supply Core and UIComponents.
No MainWindowController, listener, Helper, public network request or
system proxy/DNS/route preference is created or changed. An unshown test
NSWindow supplies AppKit's native collection tiling lifecycle; it is never
ordered, activated or run. Synthetic wheel and
PageDown commands test the view responder path, without claiming focused key
event coverage in a real window.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from swiftpm_test_support import ROOT, collect_prebuilt_inputs, default_build_directory
from test_enhanced_handoff import declaration


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", choices=["debug", "release"], default="release")
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/policy-single-scroll-layout")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    prebuilt = collect_prebuilt_inputs(args.build_dir or default_build_directory(args.configuration), work)
    paths = [ROOT / "Sources/HajimiApp/MainWindowController.swift",
             ROOT / "Sources/HajimiApp/PolicyUIComponents.swift",
             ROOT / "SmokeTests/PolicySingleScrollLayoutFixture.swift",
             Path(__file__).resolve(), ROOT / "scripts/test_enhanced_handoff.py"]
    captured = {path: path.read_bytes() for path in paths}
    frozen = {}
    for path, raw in captured.items():
        destination = work / "inputs" / path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        frozen[path] = destination
    text = captured[paths[0]].decode()
    methods = []
    retained = []
    for anchor in ["private func buildPolicies()", "private func configurePolicyCollection()",
                   "private func sectionHeading(",
                   "private func pageHeader(", "private func cardView()",
                   "func numberOfSections(in collectionView:",
                   "func collectionView(_ collectionView: NSCollectionView,\n                        numberOfItemsInSection",
                   "func collectionView(_ collectionView: NSCollectionView,\n                        itemForRepresentedObjectAt",
                   "func collectionView(_ collectionView: NSCollectionView,\n                        viewForSupplementaryElementOfKind",
                   "func collectionView(_ collectionView: NSCollectionView, layout collectionViewLayout: NSCollectionViewLayout,",
                   "func collectionView(_ collectionView: NSCollectionView,\n                        shouldSelectItemsAt",
                   "func collectionView(_ collectionView: NSCollectionView,\n                        didSelectItemsAt"]:
        first, _, last = declaration(text, anchor)
        body = text[first:last]
        methods.append(body)
        retained.append({"declaration": anchor, "sha256": digest(body.encode()), "wholeDeclaration": True})
    first, _, last = declaration(text, "private enum HajimiTheme {")
    theme = text[first:last]
    template = captured[paths[2]].decode()
    if template.count("// @THEME@") != 1 or template.count("// @PRODUCTION_METHODS@") != 1:
        raise RuntimeError("Exact fixture insertion boundary changed")
    fixture = work / "PolicySingleScrollProductionFixture.swift"
    fixture.write_text(template.replace("// @THEME@", theme)
                       .replace("// @PRODUCTION_METHODS@", "\n\n".join(methods)), encoding="utf-8")
    binary = work / "policy-single-scroll-layout"
    command = ["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library",
               "-package-name", "哈基米", *prebuilt.flags, str(frozen[paths[1]]), str(fixture),
               *prebuilt.objects, *prebuilt.libraries, *prebuilt.linker_flags, "-o", str(binary)]
    isolated = work / "isolated-preferences"
    isolated.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment["CFFIXED_USER_HOME"] = str(isolated)
    receipts = []

    def run(name: str, arguments: list[str], timeout: int, *, env=None) -> None:
        (work / (name + "-command.json")).write_text(json.dumps(arguments, ensure_ascii=False, indent=2) + "\n")
        started = time.monotonic()
        result = subprocess.run(arguments, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout, check=False)
        (work / (name + ".log")).write_text(result.stdout, encoding="utf-8")
        receipts.append({"name": name, "exitCode": result.returncode,
                         "elapsedSeconds": round(time.monotonic() - started, 3),
                         "logSha256": digest(result.stdout.encode())})
        (work / "command-receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
        print(result.stdout[-18000:], end="", flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)

    run("compile", command, 120)
    run("results", [str(binary), str(work / "images")], 120, env=environment)
    prebuilt.verify()
    manifest = [{"source": str(path.relative_to(ROOT)), "sha256": digest(captured[path]),
                 "frozenPath": str(frozen[path]), "wholeFile": True,
                 "unchanged": digest(path.read_bytes()) == digest(captured[path])
                     and digest(frozen[path].read_bytes()) == digest(captured[path])}
                for path in paths]
    manifest[0]["exactProductionDeclarations"] = retained
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    if not all(row["unchanged"] for row in manifest):
        raise RuntimeError("Policy UI or fixture inputs changed during validation")
    print(f"PASS {len(manifest)} source inputs and {len(prebuilt.manifest)} prebuilt inputs stable; "
          f"compile/runtime exitCode 0; artifacts: {work}")


if __name__ == "__main__":
    main()

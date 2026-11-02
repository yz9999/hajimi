#!/usr/bin/env python3
"""Exercise Main's actual local-proxy settings/home builders offscreen.

The dashboard builder, settings overview prefix, UI helpers and status/action
methods are extracted verbatim. Only runtime/persistent/network boundaries are
memory inputs. No MainWindowController, window, listener, Helper, resolver or
OS proxy preference is created or changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from test_enhanced_handoff import declaration, run_logged
from ui_components_test_support import build_ui_components_module


ROOT = Path(__file__).resolve().parents[1]


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/local-proxy-settings-layout")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    components = build_ui_components_module(work)
    source = ROOT / "Sources/HajimiApp/MainWindowController.swift"
    fixture = ROOT / "SmokeTests/LocalProxySettingsLayoutFixture.swift"
    scrolling_source = ROOT / "Sources/HajimiApp/ScrollableSettingsContentView.swift"
    inputs = [source, fixture, Path(__file__).resolve(), ROOT / "scripts/test_enhanced_handoff.py",
              scrolling_source]
    captured = {path: path.read_bytes() for path in inputs}
    main_raw = captured[source]
    main_text = main_raw.decode()
    retained = []
    methods = []
    for anchor in ["private func buildDashboard()", "private func pageHeader(",
                   "private func cardView()", "private func statCard(", "private func overviewInfoColumn(",
                   "private func labeledControl(", "private func separator()",
                   "private func refreshLocalProxySettings()", "@objc private func toggleLocalProxyFromSettings()"]:
        start, _, end = declaration(main_text, anchor)
        body = main_text[start:end]
        methods.append(body)
        retained.append({"declaration": anchor, "sha256": sha(body.encode()), "wholeDeclaration": True})
    start, _, end = declaration(main_text, "private func buildSettings()")
    full = main_text[start:end]
    marker = '        let back = NSButton(title: "返回设置"'
    if full.count(marker) != 1:
        raise RuntimeError("Settings overview boundary changed; update the exact extraction")
    overview = full[:full.index(marker)]
    methods.append(overview + "    }")
    retained.append({"declaration": "private func buildSettings() overview prefix",
                     "sha256": sha(overview.encode()), "wholeDeclaration": False,
                     "boundary": marker})
    start, _, end = declaration(main_text, "private enum HajimiTheme {")
    theme = main_text[start:end]
    retained.append({"declaration": "private enum HajimiTheme {", "sha256": sha(theme.encode()),
                     "wholeDeclaration": True})
    fixture_raw = captured[fixture]
    generated = fixture_raw.decode().replace("// @INSERT_THEME@", theme)
    generated = generated.replace("// @INSERT_PRODUCTION_UI_DECLARATIONS@", "\n\n".join(methods))
    (work / "LocalProxySettingsProductionFixture.swift").write_text(generated)
    # Import the actual shared UI component through the unmodified App alias.
    # Its unrelated DNS form self-test is not part of this fixture.
    scrolling = captured[scrolling_source].decode()
    boundary = "enum ScrollableSettingsContentSelfTest {"
    if scrolling.count(boundary) != 1 or "typealias ScrollableSettingsContentView" not in scrolling:
        raise RuntimeError("The production shared scrolling alias boundary changed")
    (work / "ScrollableSettingsProduction.swift").write_text(scrolling[:scrolling.index(boundary)])
    manifest = [{"source": str(path.relative_to(ROOT)), "sha256": sha(captured[path])} for path in inputs]
    manifest.extend(components.manifest)
    manifest[0]["retainedDeclarations"] = retained
    executable = work / "local-proxy-settings-layout"
    run_logged(["xcrun", "swiftc", "-swift-version", "5", "-O", "-parse-as-library",
                *components.flags,
                str(work / "LocalProxySettingsProductionFixture.swift"),
                str(work / "ScrollableSettingsProduction.swift"), "-o", str(executable)],
               work / "compile.log", 120)
    isolated = work / "isolated-preferences"
    isolated.mkdir(exist_ok=True)
    run_logged(["env", "CFFIXED_USER_HOME=" + str(isolated), str(executable)], work / "results.log", 30)
    print((work / "results.log").read_text(), end="", flush=True)
    components.verify()
    for entry in manifest:
        entry["unchanged"] = sha((ROOT / entry["source"]).read_bytes()) == entry["sha256"]
    (work / "source-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    if not all(entry["unchanged"] for entry in manifest):
        raise RuntimeError("UI sources changed during validation; rerun the coherent snapshot")
    print(f"PASS {len(manifest)} source inputs unchanged; no window or network owners instantiated")


if __name__ == "__main__":
    main()

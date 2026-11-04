"""Locate the current DNS production sources for standalone regression runners.

The declarations remain verbatim. Monolithic private-access fixtures remove
only imports of the separately tested DNS module; their manifests retain the
original source and this inventory records every physical input path.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import argparse


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "Sources/HajimiCore"
DNS = ROOT / "Sources/HajimiDNS"
ROUTING = ROOT / "Sources/HajimiRouting"
PACKAGE_FLAGS = ["-package-name", "Hajimi"]
MODULE_FILES = {
    "DNSMessageInspection.swift", "DNSQueryCache.swift",
    "DNSAdaptiveUpstreamSelector.swift", "DNSQueryExecutionContext.swift",
    "DNSQueryCoordinator.swift", "DNSQueryContracts.swift",
    "DNSProtocolRulePolicy.swift",
}
SPLIT_CORE_DNS_FILES = (
    "EncryptedDNSRoutedTLSAttempt.swift",
    "EncryptedDNSFrontierEndpoints.swift",
    "EncryptedDNSSelfTest.swift",
    "DNSProtocolRouterAdapter.swift",
)
_INPUTS: dict[Path, str] = {}


def source_path(filename: str) -> Path:
    directory = ROUTING if filename == "RoutingTypes.swift" else DNS if filename in MODULE_FILES else CORE
    path = directory / filename
    if filename in MODULE_FILES and (CORE / filename).exists():
        raise RuntimeError(f"Moved DNS production source still has a Core copy: {filename}")
    return path


def source_text(filename: str) -> str:
    path = source_path(filename)
    text = path.read_text(encoding="utf-8")
    _INPUTS.setdefault(path, text)
    return text


def declaration_match(text: str, marker: str) -> re.Match[str] | None:
    """Allow only the access-level change needed by the actual package split."""
    indent = re.match(r" *", marker).group()
    body = marker[len(indent):]
    if body.startswith("public "):
        body = body[len("public "):]
        prefix = r"(?:public |package )"
    elif body.startswith("package "):
        body = body[len("package "):]
        prefix = r"package "
    elif body.startswith("private "):
        body = body[len("private "):]
        prefix = r"(?:private |fileprivate |package |)"
    elif body.startswith("fileprivate "):
        body = body[len("fileprivate "):]
        prefix = r"(?:fileprivate |private |package |)"
    else:
        prefix = r"(?:package )?"
    matches = list(re.finditer(r"^" + re.escape(indent) + prefix
                              + re.escape(body) + r"[^\n]*\n", text, re.M))
    if len(matches) > 1:
        raise RuntimeError(f"Nonunique production declaration: {marker}")
    return matches[0] if matches else None


def declaration_input(filename: str, marker: str) -> tuple[Path, str, re.Match[str]]:
    path = source_path(filename)
    text = source_text(filename)
    match = declaration_match(text, marker)
    if match is not None:
        return path, text, match
    fallback_files = ["DNSQueryContracts.swift", "DNSProtocolRulePolicy.swift", *SPLIT_CORE_DNS_FILES]
    for candidate_name in fallback_files:
        candidate_path = source_path(candidate_name)
        if path != candidate_path and candidate_path.exists():
            text = source_text(candidate_name)
            match = declaration_match(text, marker)
            if match is not None:
                return candidate_path, text, match
    raise RuntimeError(f"Missing current production declaration: {filename}: {marker}")


def declaration(filename: str, marker: str) -> tuple[Path, str, int]:
    path, text, match = declaration_input(filename, marker)
    indent = re.match(r" *", marker).group()
    finish = re.search(r"^" + re.escape(indent) + r"}\n", text[match.end():], re.M)
    if finish is None:
        raise RuntimeError(f"Missing production declaration end: {filename}: {marker}")
    return path, text[match.start():match.end() + finish.end()], match.start()


def monolithic(text: str) -> str:
    # Module imports are the only removed text. Access modifiers, declarations,
    # comments and production method bodies keep their current exact bytes.
    return re.sub(r"^(?:@_exported )?import HajimiDNS\n", "", text, flags=re.M)


def write_source_inventory(work: Path) -> None:
    rows = [{"source": str(path.relative_to(ROOT)),
             "sha256": hashlib.sha256(text.encode()).hexdigest(),
             "unchanged": path.read_text(encoding="utf-8") == text}
            for path, text in sorted(_INPUTS.items())]
    (work / "production-source-paths.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not all(row["unchanged"] for row in rows):
        raise RuntimeError("Current DNS production inputs changed during the standalone regression")


def swift_target_objects(build: Path, target: str, *, legacy: bool = False) -> list[Path]:
    """Use SwiftPM's current plan, never stale objects left by moved sources."""
    if target not in {"HajimiCore", "HajimiDNS", "HajimiRouting", "HajimiRuntime",
                      "HajimiUIComponents", "HajimiDiagnosticsUI", "HajimiDiagnosticsUITestSupport"}:
        raise RuntimeError(f"Unsupported standalone Swift target: {target}")
    directory = (build / (target + ".build")).resolve()
    mapping = json.loads((directory / "output-file-map.json").read_text(encoding="utf-8"))
    records = {Path(name).resolve(): record for name, record in mapping.items() if name}
    if not records:
        raise RuntimeError(f"The {target} output-file-map contains no Swift inputs")
    if not legacy:
        current = {path.resolve() for path in (ROOT / "Sources" / target).rglob("*.swift")}
        if set(records) != current:
            missing = sorted(str(path) for path in current - set(records))
            stale = sorted(str(path) for path in set(records) - current)
            raise RuntimeError(f"Stale {target} build plan; missing={missing}, obsolete={stale}")
    objects = []
    for source, record in sorted(records.items()):
        if source.suffix != ".swift" or "object" not in record:
            raise RuntimeError(f"Missing Swift object mapping for {source}")
        path = Path(record["object"]).resolve()
        if path.parent != directory or not path.is_file() or "\n" in str(path):
            raise RuntimeError(f"Invalid or missing planned Swift object: {path}")
        if path not in objects:
            objects.append(path)
    return objects


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inspect the exact prebuilt standalone Swift object plan.")
    parser.add_argument("--objects", nargs=2, metavar=("BUILD_DIRECTORY", "SWIFT_TARGET"), required=True)
    parser.add_argument("--legacy", action="store_true",
                        help="use an explicitly selected older plan without requiring today's source layout")
    args = parser.parse_args()
    for path in swift_target_objects(Path(args.objects[0]), args.objects[1], legacy=args.legacy):
        print(path)

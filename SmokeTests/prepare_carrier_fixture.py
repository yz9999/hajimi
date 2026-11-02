#!/usr/bin/env python3
"""Compile private production WS/reader code verbatim in an isolated fixture.

This generates only a test translation unit. There is no copied/reimplemented
client codec: declaration boundaries are unique and the exact production text
is retained, alongside a small same-file entry point for the private class.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def section(source: str, start: str, end: str | None) -> str:
    if source.count(start) != 1 or (end is not None and source.count(end) != 1):
        raise RuntimeError("Production declaration boundary changed; inspect the fixture generator")
    first = source.index(start)
    last = source.index(end, first) if end else len(source)
    return source[first:last]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    path = root / "Sources/HajimiCore/NativeOutbound.swift"
    source = path.read_text(encoding="utf-8")
    sections = [
        section(source, "final class BufferedByteReader {", "private enum ShadowsocksCipher {"),
        section(source, "func secureRandom(count: Int) -> Data {", "private func fnv1a("),
        section(source, "private func parseHeaders(_ value: String?)", "private func boolean("),
        section(source, "private func append16(_ value: UInt16", None),
    ]
    wrapper = r'''
enum WebSocketProductionFixture {
    static func connect(raw: any ByteTransport,
                        completion: @escaping (Result<any ByteTransport, Error>) -> Void) {
        let policy = ProxyPolicy(name: "memory", kind: .native, host: "fixture.invalid", port: 80,
                                 adapterType: "vmess", parameters: ["network": "ws", "ws-path": "/fixture"])
        WebSocketByteTransport.upgrade(raw: raw, policy: policy, queue: .global(), completion: completion)
    }
    static func runExistingSelfTest() throws { try WebSocketByteTransport.runSelfTest() }
}
'''
    digest = hashlib.sha256("".join(sections).encode()).hexdigest()
    text = ("import Foundation\nimport CryptoKit\nimport Security\n"
            f"// Verbatim production WS/reader sections SHA256: {digest}\n"
            + "\n".join(sections) + wrapper)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    print(f"Production WS/reader fixture SHA256 {digest}")


if __name__ == "__main__":
    main()

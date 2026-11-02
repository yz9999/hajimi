#!/usr/bin/env python3
"""Loopback proof of DNS cache/single-flight at router and real SOCKS ingress.

No public DNS, GUI, helper, route or resolver settings are used. The DNS peer
only accepts one framed query per proxied TCP connection. Its trace proves
that 139 application questions use exactly nine selected-proxy exchanges:
duplicates collapse, A/AAAA and UDP/TCP stay separate, TXT and TTL=0 never
enter the cache, and a refused domain sends no upstream traffic.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

import live_dns as base


FLAG = "--dns-performance-loopback-test"
OPT_REQUEST = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
EXPECTED = Counter({
    ("cached.example.test", 1, "http"): 1,
    ("cached.example.test", 28, "http"): 1,
    ("cached.example.test", 1, "socks5"): 1,
    ("txt.example.test", 16, "http"): 2,
    ("zero.example.test", 1, "http"): 2,
    ("edns.example.test", 1, "http"): 2,
})


class PerformanceTrace(base.Trace):
    def verify(self, dns_port: int) -> None:
        self.wait_idle()
        with self._condition:
            base.expect(not self.errors, "fixture errors: " + "; ".join(self.errors))
            targets = Counter({("http", base.LOOPBACK, dns_port): 8,
                               ("socks5", base.LOOPBACK, dns_port): 1})
            base.expect(self.targets == targets, f"wrong proxy exchange counts: {dict(self.targets)}")
            base.expect(self.questions == EXPECTED,
                        f"cache/merge/policy/TTL isolation failed: {dict(self.questions)}; expected {dict(EXPECTED)}")


def question(packet: bytes) -> tuple[int, str, int, bytes, bool, bool]:
    base.expect(12 <= len(packet) <= 65_535, "invalid DNS wire length")
    identifier, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    base.expect(flags in (0x0100, 0x0120) and (qd, an, ns) == (1, 0, 0) and ar in (0, 1),
                "performance fixture requires a single plain/EDNS RD question")
    offset, labels = 12, []
    while True:
        base.expect(offset < len(packet), "truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        base.expect(length <= 63 and offset + length <= len(packet), "invalid DNS label")
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
    end = offset + 4
    base.expect(end <= len(packet), "truncated DNS question")
    qtype, qclass = struct.unpack("!HH", packet[offset:end])
    base.expect(qclass == 1 and qtype in (1, 28, 16), "unexpected question family")
    base.expect(packet[end:] == (OPT_REQUEST if ar else b""), "unexpected EDNS options or trailing data")
    name = ".".join(labels)
    base.expect(name in {item[0] for item in EXPECTED}, "refused/unknown domain reached upstream")
    return identifier, name, qtype, packet[12:end], bool(ar), bool(flags & 0x20)


class PerformanceDNSHandler(base.TracedHandler):
    def run(self) -> None:
        length = struct.unpack("!H", base.read_exact(self.request, 2))[0]
        packet = base.read_exact(self.request, length)
        identifier, name, qtype, encoded, edns, aware = question(packet)
        self.server.trace.question(self.client_address[1], name, qtype)
        if qtype == 1:
            payload = bytes((203, 0, 113, 7))
        elif qtype == 28:
            payload = socket.inet_pton(socket.AF_INET6, "2001:db8::7")
        else:
            text = b"uncached-txt"
            payload = bytes((len(text),)) + text
        ttl = 0 if name == "zero.example.test" else 60
        response = struct.pack("!6H", identifier, 0x8180 | (0x20 if aware else 0), 1, 1, 0, int(edns)) + encoded
        response += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(payload)) + payload
        if edns:
            response += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 12)
            response += struct.pack("!HH", 12, 8) + bytes(8)  # EDNS padding, not an RR TTL.
        # A controlled 50ms peer delay makes cold vs warm latency visible.
        time.sleep(0.05)
        wire = struct.pack("!H", len(response)) + response
        self.request.sendall(wire[:1]); self.request.sendall(wire[1:7]); self.request.sendall(wire[7:])
        base.expect(not self.request.recv(1), "plain DNS transaction sent an extra request")


def profile_text(dns: base.LoopbackServer, http: base.LoopbackServer, socks: base.LoopbackServer) -> str:
    return (f"[General]\ndns-server = {base.LOOPBACK}:{dns.port}\ndns-leak-protection = true\nfake-ip = false\n"
            f"[Proxy]\nNodeHTTP = http, {base.LOOPBACK}, {http.port}\n"
            f"NodeSOCKS = socks5, {base.LOOPBACK}, {socks.port}\n"
            "[Rule]\nDOMAIN,blocked.example.test,REJECT\nPROTOCOL,UDP,NodeHTTP\nFINAL,NodeSOCKS\n")


def has_cli_flag(binary: Path) -> bool:
    needle, tail = FLAG.encode("ascii"), b""
    with binary.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            data = tail + chunk
            if needle in data:
                return True
            tail = data[-len(needle):]
    return False


def fixture_self_test(http: base.LoopbackServer, socks: base.LoopbackServer) -> None:
    identifier = 0
    for (name, qtype, protocol), count in EXPECTED.items():
        for attempt in range(count):
            identifier += 1
            server = http if protocol == "http" else socks
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
                peer.settimeout(5); peer.connect((base.LOOPBACK, server.port))
                if protocol == "http":
                    peer.sendall(f"CONNECT {base.LOOPBACK}:{server.dns_port} HTTP/1.1\r\n\r\n".encode("ascii"))
                    header = bytearray()
                    while not header.endswith(b"\r\n\r\n"):
                        header.extend(base.read_exact(peer, 1))
                    base.expect(header.startswith(b"HTTP/1.1 200 "), "fixture CONNECT failed")
                else:
                    peer.sendall(b"\x05\x01\x00")
                    base.expect(base.read_exact(peer, 2) == b"\x05\x00", "fixture SOCKS greeting failed")
                    peer.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", server.dns_port))
                    base.expect(base.read_exact(peer, 10)[:2] == b"\x05\x00", "fixture SOCKS CONNECT failed")
                encoded = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0"
                edns = name == "edns.example.test"
                aware = edns and attempt == 1
                flags = 0x0100 | (0x20 if aware else 0)
                packet = struct.pack("!6H", identifier, flags, 1, 0, 0, int(edns))
                packet += encoded + struct.pack("!HH", qtype, 1) + (OPT_REQUEST if edns else b"")
                peer.sendall(struct.pack("!H", len(packet)) + packet)
                size = struct.unpack("!H", base.read_exact(peer, 2))[0]
                response = base.read_exact(peer, size)
                base.expect(response[:2] == packet[:2] and struct.unpack("!H", response[2:4])[0] == (0x8180 | (flags & 0x20)),
                            "fixture response lost its ID/flags")


def run_ingress(binary: Path, ingress: str, *, self_test: bool = False) -> None:
    trace = PerformanceTrace()
    with tempfile.TemporaryDirectory(prefix=f"hajimi-dns-performance-{ingress}-") as directory, ExitStack() as stack:
        temporary = Path(directory)
        dns = stack.enter_context(base.running(base.LoopbackServer(PerformanceDNSHandler, trace)))
        http = stack.enter_context(base.running(base.LoopbackServer(base.ProxyHandler, trace, "http", dns.port)))
        socks = stack.enter_context(base.running(base.LoopbackServer(base.ProxyHandler, trace, "socks5", dns.port)))
        if self_test:
            fixture_self_test(http, socks)
        else:
            profile = temporary / "profile.conf"
            profile.write_text(profile_text(dns, http, socks), encoding="utf-8"); profile.chmod(0o600)
            home = temporary / "home"; home.mkdir()
            environment = os.environ.copy()
            for key in tuple(environment):
                if key.startswith("HAJIMI_TEST_"):
                    environment.pop(key)
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                        "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
                environment[key] = ""
            environment.update({"HOME": str(home), "CFFIXED_USER_HOME": str(home),
                                "HAJIMI_TEST_PROFILE": str(profile), "HAJIMI_TEST_DNS_INGRESS": ingress})
            completed = subprocess.run((str(binary), FLAG), env=environment, capture_output=True,
                                       text=True, timeout=25, check=False)
            details = (completed.stdout + "\n" + completed.stderr).strip()
            base.expect(completed.returncode == 0,
                        f"{ingress} performance CLI exited {completed.returncode}: {details}; "
                        f"targets={dict(trace.targets)}, questions={dict(trace.questions)}, errors={trace.errors}")
            base.expect(f"ingress={ingress}" in completed.stdout, "binary did not confirm the actual ingress")
            print(details)
        trace.verify(dns.port)
    print(f"PASS DNS performance {ingress if not self_test else 'fixtures'}: "
          "139 app questions -> 9 proxy exchanges; refused=0; cache/source/protocol/TTL/EDNS/AD isolation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(".build/x86_64-apple-macosx/release/Hajimi"))
    parser.add_argument("--ingress", choices=("router", "listener", "both"), default="both")
    parser.add_argument("--self-test", action="store_true", help="only exercise Python loopback fixtures")
    args = parser.parse_args()
    binary = args.binary.expanduser().resolve()
    try:
        if args.self_test:
            run_ingress(binary, "router", self_test=True)
            return 0
        base.expect(binary.is_file() and os.access(binary, os.X_OK), f"binary is not executable: {binary}")
        base.expect(has_cli_flag(binary), "binary lacks the early-exit performance flag; refusing to launch a GUI")
        for ingress in (("router", "listener") if args.ingress == "both" else (args.ingress,)):
            run_ingress(binary, ingress)
        return 0
    except (OSError, ValueError, base.CheckFailure, subprocess.TimeoutExpired) as error:
        print(f"DNS performance check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

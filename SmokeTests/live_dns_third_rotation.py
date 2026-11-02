#!/usr/bin/env python3
"""Three approved loopback providers under the unchanged production 8s budget.

The control has no successful third RTT. The measured case primes all three
through real certificate-verified DNS exchanges, then silences the first two.
A measured slow backup is a separate counterexample and must still win.
No GUI, Helper, public endpoint, credential or system network setting is used.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import json
import math
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import time

from live_dns_adaptive import (
    CONNECT, DNSService, HandlerDrainTracker, Trace, certificates, failure_trace,
    require_completed_cli, running,
)


LABELS = ("first", "second", "third")
ADDRESSES = ("203.0.113.80", "203.0.113.81", "203.0.113.82")
MARKER = "DNS-THIRD-CANDIDATE-ROTATION "
NORMAL = ("rotation.control.example.test", "rotation.measured.example.test", "rotation.slow-hedge.example.test")
WARM = {
    f"rotation.{kind}-{phase}-{index}.example.test": index
    for phase, count in (("control", 2), ("measured", 3), ("slow", 3))
    for index in range(count) for kind in ("setup", "warm")
}


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def question(query: bytes) -> str:
    require(12 <= len(query) <= 65_535, "Unbounded rotation DNS query")
    _, flags, questions, answers, authority, additional = struct.unpack("!6H", query[:12])
    require(not flags & 0x8000 and (questions, answers, authority, additional) == (1, 0, 0, 0),
            "Rotation peer received unexpected DNS counts/flags")
    labels, offset = [], 12
    while True:
        require(offset < len(query), "Truncated rotation QNAME")
        size = query[offset]; offset += 1
        if size == 0:
            break
        require(size <= 63 and offset + size <= len(query), "Compressed or invalid rotation QNAME")
        labels.append(query[offset:offset + size].decode("ascii")); offset += size
    name = ".".join(labels)
    require(name in WARM or name in NORMAL, "Unexpected or REJECT question reached a TLS peer")
    require(offset + 4 == len(query) and query[offset:] == b"\x00\x01\x00\x01", "Expected one fixed IN/A question")
    return name


def answer(query: bytes, address: str) -> bytes:
    return (query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + query[12:]
            + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address))


class RotationTLS(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        trace, index = self.server.trace, self.server.index
        label, address = LABELS[index], ADDRESSES[index]
        silent_name = None
        try:
            require(self.client_address[0] == "127.0.0.1", "Non-loopback rotation TLS peer")
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.request.settimeout(10)
            with trace.lock:
                trace.hellos.append(label); trace.tls_peers.append((label, self.client_address))
            with self.server.context.wrap_socket(self.request, server_side=True) as peer:
                require(peer.selected_alpn_protocol() == "http/1.1", "Rotation ALPN changed")
                buffered = bytearray()
                while True:
                    while b"\r\n\r\n" not in buffered:
                        payload = peer.recv(4096)
                        if not payload:
                            require(not buffered, "Truncated rotation HTTP headers")
                            return
                        buffered.extend(payload)
                        require(len(buffered) <= 16_384, "Unbounded rotation HTTP headers")
                    header, remainder = bytes(buffered).split(b"\r\n\r\n", 1)
                    buffered = bytearray(remainder)
                    lines = header.decode("ascii").split("\r\n")
                    require(lines.pop(0) == "POST /dns-query HTTP/1.1", "Rotation method/path changed")
                    fields = {}
                    for line in lines:
                        key, value = line.split(":", 1); key = key.lower()
                        require(key not in fields, "Duplicate rotation HTTP header")
                        fields[key] = value.strip()
                    size = int(fields.get("content-length", "0"))
                    require(12 <= size <= 65_535 and "transfer-encoding" not in fields, "Invalid rotation body length")
                    require(fields.get("host") == self.server.authority
                            and fields.get("content-type") == "application/dns-message", "Rotation identity/content type changed")
                    while len(buffered) < size:
                        payload = peer.recv(min(4096, size - len(buffered)))
                        require(bool(payload), "Truncated rotation DNS body")
                        buffered.extend(payload)
                    query = bytes(buffered[:size]); del buffered[:size]
                    name = question(query)
                    if name in WARM:
                        require(WARM[name] == index, "Warmup used a different approved candidate")
                        delay = 0 if name.startswith("rotation.setup-") else (
                            (0.01, 0.5, 1.0)[index] if "warm-slow-" in name else (0.01, 0.02, 0.1)[index])
                    elif name == NORMAL[2]:
                        require(index != 2, "A legal slow backup was clipped for an unnecessary third request")
                        delay = 0.6 if index == 1 else None
                    else:
                        delay = 0.1 if index == 2 else None
                    with trace.lock:
                        trace.queries.append((label, name))
                        trace.event_locked("rotation-query", provider=label, name=name,
                                           queryID=int.from_bytes(query[:2], "big"), address=address)
                    if delay is None:
                        silent_name = name
                        require(not buffered and not peer.recv(4096), "Silent carrier received an extra question")
                        return
                    time.sleep(delay)
                    response = answer(query, address)
                    peer.sendall(("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                                  f"Content-Length: {len(response)}\r\nConnection: keep-alive\r\n\r\n").encode("ascii")
                                 + response)
                    with trace.lock:
                        trace.event_locked("rotation-answer", provider=label, name=name,
                                           queryID=int.from_bytes(query[:2], "big"), address=address)
        except (ConnectionResetError, BrokenPipeError):
            return
        except (AssertionError, OSError, UnicodeError, ValueError) as error:
            with trace.lock:
                trace.errors.append(str(error))
        finally:
            if silent_name is not None:
                with trace.lock:
                    trace.event_locked("rotation-silent-closed", provider=label, name=silent_name)


class RotationTLSService(HandlerDrainTracker, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, trace: Trace, index: int, certificate: Path, key: Path) -> None:
        require(index in range(3), "Exactly three fixed TLS peer indices are permitted")
        self.trace, self.index = trace, index
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.load_cert_chain(certificate, key)
        super().__init__(("127.0.0.1", 0), RotationTLS)
        self.authority = f"127.0.0.1:{self.server_address[1]}"


class RotationCONNECTService(HandlerDrainTracker, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, trace: Trace, ports: tuple[int, ...], excluded: tuple[int, ...]) -> None:
        require(len(ports) == len(set(ports)) == 3 and all(0 < port <= 65_535 for port in ports),
                "Rotation CONNECT requires exactly three distinct bounded TLS ports")
        self.trace, self.failure_ports, self.identity_provider_by_port = trace, set(), {}
        self.authorities = {f"127.0.0.1:{port}": port for port in ports}
        for _ in range(16):
            super().__init__(("127.0.0.1", 0), CONNECT)
            if self.server_address[1] not in set(ports) | set(excluded):
                with trace.lock:
                    trace.approved_proxy_endpoint = self.server_address
                return
            self.server_close()
        raise AssertionError("Cannot allocate a distinct literal rotation CONNECT port")


def validate(trace: Trace, marker: dict, ports: tuple[int, ...]) -> None:
    data = trace.snapshot()
    require(not data["errors"] and not data["proxyRejected"] and data["plaintext"] == 0,
            "Rotation traffic failed or reached the plaintext sink")
    expected = Counter((LABELS[index], name) for name, index in WARM.items())
    expected.update((label, name) for name in NORMAL[:2] for label in LABELS)
    expected.update((label, NORMAL[2]) for label in LABELS[:2])
    require(Counter(tuple(item) for item in data["queries"]) == expected,
            "Rotation wire questions were missing, duplicated, extra or sent to a different provider")
    require(set(tuple(item) for item in data["connects"]) == {("127.0.0.1", port) for port in ports}
            and len(data["tlsPeers"]) == len(data["connects"])
            and all(peer == "127.0.0.1" for peer in data["proxyPeers"]), "Rotation TLS escaped its approved proxy/ports")
    require(marker.get("fixtureOnly") is True and marker.get("formatVersion") == 1
            and marker.get("parentDeadlineMilliseconds") == 8000
            and marker.get("liveLimit") == 2 and marker.get("attemptLimit") == 3
            and (marker.get("controlAttempts"), marker.get("measuredAttempts"), marker.get("slowHedgeAttempts")) == (3, 3, 2),
            "Rotation CLI lost its unchanged limits or actual per-query attempt counts")
    for field in ("controlMilliseconds", "measuredMilliseconds", "slowHedgeMilliseconds"):
        require(type(marker.get(field)) in (int, float) and math.isfinite(marker[field]) and 0 < marker[field] < 8000,
                "Rotation elapsed time is invalid or exceeds its original parent budget")
    require(5000 <= marker["controlMilliseconds"] < 8000 and 5000 <= marker["measuredMilliseconds"] < 8000
            and 600 <= marker["slowHedgeMilliseconds"] < 2000, "Conservative rotation or slow-response protection failed")
    events = data["events"]
    for name in NORMAL:
        questions = [row for row in events if row["event"] == "rotation-query" and row["name"] == name]
        answers = [row for row in events if row["event"] == "rotation-answer" and row["name"] == name]
        closed = [row for row in events if row["event"] == "rotation-silent-closed" and row["name"] == name]
        require(len({row["queryID"] for row in questions}) == 1 and len(answers) == 1,
                "A rotation query changed wire IDs or received more than one authenticated answer")
        require(answers[0]["provider"] == ("second" if name == NORMAL[2] else "third"), "Wrong authenticated winner")
        require(len(closed) == (1 if name == NORMAL[2] else 2), "A retired or completed silent carrier did not close")
        primary = questions[0]["provider"]
        primary_closed = next(row for row in closed if row["provider"] == primary)
        require(primary_closed["seconds"] + 0.01 >= answers[0]["seconds"], "The original primary was cancelled before a valid winner")
        if name != NORMAL[2]:
            third = next(row for row in questions if row["provider"] == "third")
            delay = third["seconds"] - questions[0]["seconds"]
            require(delay >= 5.0, "Warm third-provider history shortened the conservative rotation boundary")
            if name == NORMAL[1]:
                require(answers[0]["seconds"] - questions[0]["seconds"] >= 5.0,
                        "Independent wire timing bypassed conservative rotation")


def python_peer_check(proxy, peers, root: Path) -> None:
    context = ssl.create_default_context(cafile=str(root / "ca.pem"))
    context.set_alpn_protocols(["http/1.1"])
    for index, name in ((0, "rotation.setup-control-0.example.test"),
                        (2, "rotation.warm-measured-2.example.test"), (1, NORMAL[2]), (0, NORMAL[0])):
        query = struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0)
        query += b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0\0\1\0\1"
        with socket.create_connection(proxy.server_address, timeout=3) as raw:
            authority = peers[index].authority
            raw.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                payload = raw.recv(1); require(bool(payload), "Truncated self-test CONNECT reply")
                header.extend(payload); require(len(header) <= 4096, "Unbounded self-test CONNECT reply")
            require(header.startswith(b"HTTP/1.1 200 "), "Self-test CONNECT failed")
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.sendall((f"POST /dns-query HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/dns-message\r\n"
                             f"Content-Length: {len(query)}\r\n\r\n").encode("ascii") + query)
                if name == NORMAL[0]:
                    continue  # The silent peer must observe real TLS/TCP teardown.
                response = bytearray()
                expected = answer(query, ADDRESSES[index])
                while len(response) < len(expected) or b"\r\n\r\n" not in response:
                    payload = tls.recv(4096); require(bool(payload), "Truncated self-test HTTPS reply")
                    response.extend(payload)
                while len(response.split(b"\r\n\r\n", 1)[1]) < len(expected):
                    payload = tls.recv(4096); require(bool(payload), "Truncated self-test HTTPS body")
                    response.extend(payload)
                require(response.split(b"\r\n\r\n", 1)[1] == expected, "Python TLS peer changed the DNS answer")


def run(binary: Path | None, protection: bool) -> None:
    trace = Trace(maximum_events=256)
    with failure_trace(trace, protection, "third-candidate-rotation"), \
            tempfile.TemporaryDirectory(prefix="hajimi-dns-adaptive-") as directory, ExitStack() as stack:
        root = Path(directory).resolve(); root.chmod(0o700)
        home = root / "home"; home.mkdir(mode=0o700)
        certificate, _, key = certificates(root)
        peers = [stack.enter_context(running(RotationTLSService(trace, index, certificate, key))) for index in range(3)]
        ports = tuple(peer.server_address[1] for peer in peers)
        require(len(set(ports)) == 3, "TLS peer ports overlap")
        plain = stack.enter_context(running(DNSService(trace, excluded_ports=ports)))
        proxy = stack.enter_context(running(RotationCONNECTService(trace, ports, (plain.server_address[1],))))
        if binary is None:
            python_peer_check(proxy, peers, root)
            for peer in [proxy, *peers, plain]:
                require(peer.wait_idle(), "Python rotation peer did not close after self-test")
            require(not trace.errors and not trace.proxy_rejected and trace.plaintext == 0, "Python rotation peer failed")
            print("PASS three-provider Python peers: verified temporary CA/IP SAN, literal CONNECT, fixed delays and silent-peer teardown")
            return
        profile = (f"[General]\ndns-leak-protection = {str(protection).lower()}\nfake-ip = false\n"
                   f"dns-server = 127.0.0.1:{plain.server_address[1]}\n"
                   "encrypted-dns-server = " + ", ".join(f"https://127.0.0.1:{port}/dns-query" for port in ports) + "\n"
                   f"[Proxy]\nLoopbackHTTP = http, 127.0.0.1, {proxy.server_address[1]}\n"
                   "[Rule]\nDOMAIN,blocked.example.test,REJECT\nFINAL,LoopbackHTTP\n")
        path = root / "fixture.conf"; path.write_text(profile, encoding="ascii"); path.chmod(0o600)
        environment = os.environ.copy()
        for item in tuple(environment):
            if item.startswith("HAJIMI_TEST_"):
                environment.pop(item)
        for item in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            environment[item] = ""
        environment.update({"HOME": str(home), "CFFIXED_USER_HOME": str(home), "LANG": "C", "LC_ALL": "C",
                            "TMPDIR": str(root.parent) + os.sep, "HAJIMI_NATIVE_DEBUG": "1"})
        result = subprocess.run((str(binary), "--dns-adaptive-loopback-test", "--dns-adaptive-fixture-root", str(root),
                                 "--dns-adaptive-fixture-scenario", "third-candidate-rotation"),
                                env=environment, text=True, capture_output=True, timeout=40, check=False)
        details = require_completed_cli(result)
        rows = [line[len(MARKER):] for line in details.splitlines() if line.startswith(MARKER)]
        require(len(rows) == 1 and len(rows[0].encode()) <= 4096, "Missing or unbounded three-provider timing proof")
        marker = json.loads(rows[0])
        for peer in [proxy, *peers, plain]:
            require(peer.wait_idle(), "Rotation physical handlers did not close after CLI completion")
        validate(trace, marker, ports)
        print(f"PASS three-provider rotation protection={str(protection).lower()}: "
              f"conservative control={marker['controlMilliseconds']:.1f}ms; measured={marker['measuredMilliseconds']:.1f}ms; "
              f"legal slow backup={marker['slowHedgeMilliseconds']:.1f}ms, original budget=8000ms; "
              "attempts=3/3/2, primary retained, REJECT=0 wire, plaintext=0")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(".build/x86_64-apple-macosx/release/Hajimi"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--protection", choices=("on", "off", "both"), default="both")
    args = parser.parse_args()
    binary = None if args.self_test else args.binary.resolve()
    require(binary is None or binary.is_file() and os.access(binary, os.X_OK), "Build Hajimi before running --binary")
    for protection in ([True] if args.self_test or args.protection == "on" else [False] if args.protection == "off" else [True, False]):
        run(binary, protection)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"DNS third-candidate rotation failed: {error}", file=sys.stderr)
        raise SystemExit(1)

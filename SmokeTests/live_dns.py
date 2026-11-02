#!/usr/bin/env python3
"""Loopback-only DNS-over-TCP through C++ HTTP/SOCKS5 proxy regressions.

Usage: python3 SmokeTests/live_dns.py --binary path/to/Hajimi --ingress both

The CLI exercises the in-memory router and/or isolated actual SOCKS listeners.
This script's upstream services are dynamic 127.0.0.1 TCP listeners only; no
UDP upstream is provided. It never queries real DNS, starts the App UI/helper,
or changes system networking. Each ingress has a fresh trace, services, home
and profile. --self-test validates Python fixtures without launching Hajimi.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import selectors
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading


LOOPBACK = "127.0.0.1"
FLAG = "--dns-loopback-test"
DNS_ID = 4242
EXPECTED = {
    ("udp-a.example.test", 1): "http",
    ("tcp-a.example.test", 1): "http",
    ("udp-txt.example.test", 16): "socks5",
    ("tcp-txt.example.test", 16): "socks5",
    ("udp-https.example.test", 65): "socks5",
}


class CheckFailure(RuntimeError):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def read_exact(peer: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = peer.recv(count - len(result))
        if not chunk:
            raise EOFError("loopback connection closed mid-frame")
        result.extend(chunk)
    return bytes(result)


class Trace:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._active = 0
        self._upstreams: dict[int, str] = {}
        self.targets: Counter[tuple[str, str, int]] = Counter()
        self.questions: Counter[tuple[str, int, str]] = Counter()
        self.errors: list[str] = []

    def begin(self) -> None:
        with self._condition:
            self._active += 1

    def end(self) -> None:
        with self._condition:
            self._active -= 1
            self._condition.notify_all()

    def error(self, error: BaseException) -> None:
        with self._condition:
            self.errors.append(str(error))

    def target(self, protocol: str, host: str, port: int) -> None:
        with self._condition:
            self.targets[(protocol, host, port)] += 1

    def upstream(self, source_port: int, protocol: str) -> None:
        with self._condition:
            self._upstreams[source_port] = protocol

    def question(self, source_port: int, name: str, qtype: int) -> None:
        with self._condition:
            protocol = self._upstreams.get(source_port)
            expect(protocol is not None, "DNS server was reached directly, bypassing both proxies")
            self.questions[(name, qtype, protocol)] += 1

    def wait_idle(self) -> None:
        with self._condition:
            expect(self._condition.wait_for(lambda: self._active == 0, timeout=3),
                   "loopback DNS/proxy connections did not close after the CLI exited")

    def verify(self, dns_port: int) -> None:
        self.wait_idle()
        with self._condition:
            expect(not self.errors, "fixture errors: " + "; ".join(self.errors))
            expected_targets = Counter({("http", LOOPBACK, dns_port): 2,
                                        ("socks5", LOOPBACK, dns_port): 3})
            expected_questions = Counter({(name, qtype, policy): 1
                                          for (name, qtype), policy in EXPECTED.items()})
            expect(self.targets == expected_targets,
                   f"wrong/duplicate proxy targets: {dict(self.targets)}; expected {dict(expected_targets)}")
            expect(self.questions == expected_questions,
                   f"DNS policy/duplicate/REJECT error: {dict(self.questions)}; expected {dict(expected_questions)}")


class LoopbackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, handler: type[socketserver.BaseRequestHandler], trace: Trace,
                 protocol: str = "dns", dns_port: int = 0) -> None:
        super().__init__((LOOPBACK, 0), handler)
        self.trace = trace
        self.protocol = protocol
        self.dns_port = dns_port

    @property
    def port(self) -> int:
        return self.server_address[1]


class TracedHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.trace.begin()
        self.request.settimeout(5)
        try:
            self.run()
        except (OSError, EOFError, ValueError, CheckFailure) as error:
            self.server.trace.error(error)
        finally:
            self.server.trace.end()

    def run(self) -> None:
        raise NotImplementedError


def question(packet: bytes) -> tuple[str, int, bytes]:
    expect(12 <= len(packet) <= 65_535, "invalid DNS wire length")
    identifier, flags, questions, answers, authority, additional = struct.unpack("!6H", packet[:12])
    expect(identifier == DNS_ID and flags & 0x8000 == 0 and (flags >> 11) & 15 == 0,
           "unexpected DNS transaction ID/opcode/response bit")
    expect((questions, answers, authority, additional) == (1, 0, 0, 0),
           "test DNS request must contain exactly one plain question")
    offset = 12
    labels = []
    while True:
        expect(offset < len(packet), "truncated DNS question")
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        expect(size <= 63 and offset + size <= len(packet), "invalid/compressed DNS question label")
        labels.append(packet[offset:offset + size].decode("ascii").lower())
        offset += size
    expect(offset + 4 == len(packet), "DNS frame has truncated question or trailing wire bytes")
    qtype, qclass = struct.unpack("!HH", packet[offset:])
    expect(qclass == 1 and qtype in (1, 16, 65), "unexpected DNS question type/class")
    return ".".join(labels), qtype, packet[12:]


def answer(packet: bytes, qtype: int, encoded_question: bytes) -> bytes:
    if qtype == 1:
        payload = bytes((203, 0, 113, 7))
    elif qtype == 16:
        text = b"hajimi-loopback-txt"
        payload = bytes((len(text),)) + text
    else:
        payload = None  # HTTPS NODATA is a valid NOERROR answer.
    flags = 0x8080 | (struct.unpack("!H", packet[2:4])[0] & 0x0100)
    header = struct.pack("!6H", DNS_ID, flags, 1, int(payload is not None), 0, 0)
    response = header + encoded_question
    if payload is not None:
        response += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(payload)) + payload
    return response


class DNSHandler(TracedHandler):
    def run(self) -> None:
        length = struct.unpack("!H", read_exact(self.request, 2))[0]
        expect(length >= 12, "TCP DNS prefix announced an undersized frame")
        packet = read_exact(self.request, length)
        name, qtype, encoded = question(packet)
        self.server.trace.question(self.client_address[1], name, qtype)
        response = answer(packet, qtype, encoded)
        framed = struct.pack("!H", len(response)) + response
        # Force separate prefix/body writes; ingress also deliberately splits
        # and coalesces frames and reads replies three bytes at a time.
        self.request.sendall(framed[:1])
        self.request.sendall(framed[1:7])
        self.request.sendall(framed[7:])
        expect(not self.request.recv(1), "a DNS transaction sent more than one upstream request")


def relay(client: socket.socket, upstream: socket.socket) -> None:
    with selectors.DefaultSelector() as selector:
        selector.register(client, selectors.EVENT_READ, upstream)
        selector.register(upstream, selectors.EVENT_READ, client)
        while True:
            ready = selector.select(timeout=5)
            expect(bool(ready), "loopback proxy tunnel did not make progress")
            for key, _ in ready:
                packet = key.fileobj.recv(65_536)
                if not packet:
                    return
                key.data.sendall(packet)


class ProxyHandler(TracedHandler):
    def http_target(self) -> tuple[str, int]:
        header = bytearray()
        # Consume only headers; a following DNS frame must stay in the socket.
        while not header.endswith(b"\r\n\r\n"):
            expect(len(header) < 16_384, "HTTP CONNECT headers exceeded the fixture limit")
            header.extend(read_exact(self.request, 1))
        request = bytes(header).split(b"\r\n", 1)[0].decode("ascii").split()
        expect(len(request) == 3 and request[0] == "CONNECT" and request[2] == "HTTP/1.1",
               "DNS-over-HTTP proxy must use CONNECT, never an HTTP URL/GET")
        host, separator, port = request[1].rpartition(":")
        expect(bool(separator) and port.isdecimal(), "invalid CONNECT authority")
        return host, int(port)

    def socks_target(self) -> tuple[str, int]:
        version, count = read_exact(self.request, 2)
        methods = read_exact(self.request, count)
        expect(version == 5 and 0 in methods, "unexpected SOCKS5 greeting/authentication")
        self.request.sendall(b"\x05\x00")
        version, command, reserved, atyp = read_exact(self.request, 4)
        expect((version, command, reserved) == (5, 1, 0),
               "DNS must use SOCKS5 TCP CONNECT, not a UDP association")
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, read_exact(self.request, 4))
        elif atyp == 3:
            host = read_exact(self.request, read_exact(self.request, 1)[0]).decode("ascii")
        else:
            raise CheckFailure("SOCKS5 fixture only permits the loopback IPv4 DNS target")
        return host, struct.unpack("!H", read_exact(self.request, 2))[0]

    def run(self) -> None:
        server = self.server
        host, port = self.http_target() if server.protocol == "http" else self.socks_target()
        server.trace.target(server.protocol, host, port)
        expect(host == LOOPBACK and port == server.dns_port,
               f"forbidden proxy destination {host}:{port}; only fake DNS at {LOOPBACK}:{server.dns_port} is allowed")
        # Connect using a literal AF_INET socket: never resolve a client host.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
            upstream.settimeout(5)
            upstream.connect((LOOPBACK, server.dns_port))
            server.trace.upstream(upstream.getsockname()[1], server.protocol)
            if server.protocol == "http":
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", server.dns_port))
            relay(self.request, upstream)


@contextmanager
def running(server: LoopbackServer):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def fixture_self_test(http: LoopbackServer, socks: LoopbackServer) -> None:
    for (name, qtype), protocol in EXPECTED.items():
        server = http if protocol == "http" else socks
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
            peer.settimeout(5)
            peer.connect((LOOPBACK, server.port))
            if protocol == "http":
                peer.sendall(f"CONNECT {LOOPBACK}:{server.dns_port} HTTP/1.1\r\nHost: {LOOPBACK}:{server.dns_port}\r\n\r\n".encode("ascii"))
                header = bytearray()
                while not header.endswith(b"\r\n\r\n"):
                    header.extend(read_exact(peer, 1))
                expect(header.startswith(b"HTTP/1.1 200 "), "fixture CONNECT failed")
            else:
                peer.sendall(b"\x05\x01\x00")
                expect(read_exact(peer, 2) == b"\x05\x00", "fixture SOCKS5 greeting failed")
                peer.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", server.dns_port))
                expect(read_exact(peer, 10)[:2] == b"\x05\x00", "fixture SOCKS5 CONNECT failed")
            encoded_name = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\x00"
            query = struct.pack("!6H", DNS_ID, 0x0100, 1, 0, 0, 0) + encoded_name + struct.pack("!HH", qtype, 1)
            peer.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", read_exact(peer, 2))[0]
            response = read_exact(peer, length)
            expect(response[:2] == query[:2] and response[3] & 15 == 0 and response[12:len(query)] == query[12:],
                   "fixture produced a mismatched DNS response")


def profile_text(dns: LoopbackServer, http: LoopbackServer, socks: LoopbackServer) -> str:
    rules = [f"DOMAIN,{name},{'NodeHTTP' if policy == 'http' else 'NodeSOCKS'}"
             for (name, _), policy in EXPECTED.items()]
    rules.extend(("DOMAIN,blocked.example.test,REJECT", "IP-CIDR,127.0.0.0/8,NodeHTTP", "FINAL,REJECT"))
    return (f"[General]\ndns-server = {LOOPBACK}:{dns.port}\ndns-leak-protection = true\nfake-ip = false\n"
            f"[Proxy]\nNodeHTTP = http, {LOOPBACK}, {http.port}\nNodeSOCKS = socks5, {LOOPBACK}, {socks.port}\n"
            "[Rule]\n" + "\n".join(rules) + "\n")


def has_cli_flag(binary: Path) -> bool:
    # Prevent accidentally invoking the ordinary GUI of an older build which
    # does not recognize this early-exit CLI. No process is launched to check.
    flag = FLAG.encode("ascii")
    tail = b""
    with binary.open("rb") as source:
        while chunk := source.read(1_024 * 1_024):
            data = tail + chunk
            if flag in data:
                return True
            tail = data[-len(flag):]
    return False


def run_ingress(binary: Path, ingress: str, *, self_test: bool = False) -> None:
    trace = Trace()
    with tempfile.TemporaryDirectory(prefix=f"hajimi-loopback-dns-{ingress}-") as directory, ExitStack() as stack:
        temporary = Path(directory)
        dns = stack.enter_context(running(LoopbackServer(DNSHandler, trace)))
        http = stack.enter_context(running(LoopbackServer(ProxyHandler, trace, "http", dns.port)))
        socks = stack.enter_context(running(LoopbackServer(ProxyHandler, trace, "socks5", dns.port)))
        if self_test:
            fixture_self_test(http, socks)
        else:
            profile = temporary / "dns.conf"
            profile.write_text(profile_text(dns, http, socks), encoding="utf-8")
            profile.chmod(0o600)
            home = temporary / "isolated-home"
            home.mkdir()
            environment = os.environ.copy()
            for name in tuple(environment):
                if name.startswith("HAJIMI_TEST_"):
                    environment.pop(name)
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                         "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
                environment[name] = ""
            environment.update({"HOME": str(home), "CFFIXED_USER_HOME": str(home),
                                "HAJIMI_TEST_PROFILE": str(profile),
                                "HAJIMI_TEST_DNS_INGRESS": ingress})
            completed = subprocess.run((str(binary), FLAG), env=environment, capture_output=True,
                                       text=True, timeout=25, check=False)
            details = (completed.stdout + "\n" + completed.stderr).strip()
            expect(completed.returncode == 0,
                   f"{ingress} DNS CLI exited {completed.returncode}: {details}; targets={dict(trace.targets)}, "
                   f"questions={dict(trace.questions)}, fixture_errors={trace.errors}")
            # Older router-only CLIs can recognize FLAG yet ignore the new
            # environment selector. Never count that as actual listener proof.
            expect(f"ingress={ingress}" in completed.stdout,
                   f"Binary did not confirm ingress={ingress}; build the new DNS CLI before testing: {details}")
            if details:
                print(details)
        trace.verify(dns.port)
    label = "fixtures" if self_test else f"{ingress} UDP/TCP ingress + query-routed DNS"
    print(f"PASS {label}: 5 exactly-once allowed questions; HTTP CONNECT=2, SOCKS5 CONNECT=3; "
          "blocked=0 upstream requests; TCP-only loopback DNS, no UDP proxy required")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(".build/x86_64-apple-macosx/release/Hajimi"))
    parser.add_argument("--ingress", choices=("router", "listener", "both"), default="both",
                        help="DNS ingress to exercise (default: both, with independent fixtures)")
    parser.add_argument("--self-test", action="store_true", help="test only the Python loopback fixtures")
    args = parser.parse_args()
    binary = args.binary.expanduser().resolve()
    if args.self_test:
        run_ingress(binary, "fixtures", self_test=True)
        return 0
    expect(binary.is_file() and os.access(binary, os.X_OK), "Build Hajimi before running --binary")
    expect(has_cli_flag(binary), f"Binary has no {FLAG} CLI; refusing to launch an older App UI")
    modes = ("router", "listener") if args.ingress == "both" else (args.ingress,)
    for ingress in modes:
        run_ingress(binary, ingress)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CheckFailure, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error

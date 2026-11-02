#!/usr/bin/env python3
"""Loopback proof that traditional DNS is bootstrap/probe-only with DoH.

Usage: python3 SmokeTests/live_dns_split.py --binary path/to/Hajimi --ingress both

Each router/listener and protection-on/off variant gets independent loopback
UDP DNS and rejecting TCP TLS services, profile and HOME. Traditional DNS may
see only the configured DoH host and the fixed connectivity probe. Failed TLS
must produce SERVFAIL, never a traditional query for an application domain.
Reserved DIRECT/REJECT overrides must be rejected before any fixture traffic.
No public DNS, App UI, Helper or system network configuration is touched.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading


LOOPBACK = "127.0.0.1"
DOH_HOST = "doh.bootstrap.selftest.invalid"
PROBE_HOST = "captive.apple.com"
FLAG = "--dns-split-loopback-test"
RESERVED_GUARD_ERROR = "Split fixture must not configure external proxies or override DIRECT/REJECT semantics"
EXPECTED = Counter({(name, qtype): 1 for name in (DOH_HOST, PROBE_HOST) for qtype in (1, 28)})


class CheckFailure(RuntimeError):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


class Trace:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._active = 0
        self.questions: Counter[tuple[str, int]] = Counter()
        self.udp_datagrams = 0
        self.tcp_connections = 0
        self.tls_hellos = 0
        self.aborted_tcp = 0
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

    def question(self, name: str, qtype: int) -> None:
        with self._condition:
            self.questions[(name, qtype)] += 1

    def arrival(self, *, datagram: bool) -> None:
        # Count at socket acceptance, before a handler thread is scheduled.
        # Even a connection cancelled before ClientHello is forbidden in an
        # early-reject guard check, not just a nonempty application payload.
        with self._condition:
            if datagram:
                self.udp_datagrams += 1
            else:
                self.tcp_connections += 1

    def tls(self, prefix: bytes) -> None:
        with self._condition:
            if not prefix:
                self.aborted_tcp += 1  # Cancelled before sending any content.
                return
            expect(prefix == b"\x16", f"non-TLS payload reached DoH TCP service: first byte {prefix.hex()}")
            self.tls_hellos += 1

    def verify(self) -> None:
        with self._condition:
            expect(self._condition.wait_for(lambda: self._active == 0, timeout=3),
                   "fixture handlers did not finish after the CLI exited")
            expect(not self.errors, "fixture errors: " + "; ".join(self.errors))
            expect(self.questions == EXPECTED,
                   f"traditional DNS leaked/repeated/missed a question: {dict(self.questions)}; expected {dict(EXPECTED)}")
            expect(self.udp_datagrams == sum(EXPECTED.values()),
                   f"traditional service received unexpected UDP datagrams: {self.udp_datagrams}")
            expect(self.tls_hellos >= 2,
                   f"expected at least two real TLS ClientHello attempts, got {self.tls_hellos}")

    def verify_unused(self) -> None:
        with self._condition:
            expect(self._condition.wait_for(lambda: self._active == 0, timeout=3),
                   "guard fixture handlers did not finish after the CLI exited")
            expect(not self.errors, "guard fixture errors: " + "; ".join(self.errors))
            expect(self.udp_datagrams == 0 and self.tcp_connections == 0 and not self.questions
                   and self.tls_hellos == 0 and self.aborted_tcp == 0,
                   f"CLI guard performed network work before rejection: UDP={self.udp_datagrams}, "
                   f"TCP={self.tcp_connections}, questions={dict(self.questions)}, "
                   f"TLS={self.tls_hellos}, aborted TCP={self.aborted_tcp}")


def parse_question(packet: bytes) -> tuple[str, int, bytes]:
    expect(12 <= len(packet) <= 65_535, "invalid traditional DNS datagram length")
    _, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    expect(flags & 0x8000 == 0 and (flags >> 11) & 15 == 0,
           "traditional service received an invalid query opcode/response")
    expect((qd, an, ns, ar) == (1, 0, 0, 0), "expected one uncompressed ordinary DNS question")
    offset = 12
    labels: list[str] = []
    while True:
        expect(offset < len(packet), "truncated traditional DNS name")
        size = packet[offset]
        offset += 1
        if not size:
            break
        expect(size <= 63 and offset + size <= len(packet), "invalid/compressed traditional DNS label")
        labels.append(packet[offset:offset + size].decode("ascii").lower())
        offset += size
    expect(offset + 4 == len(packet), "traditional DNS frame has extra/truncated wire bytes")
    qtype, qclass = struct.unpack("!HH", packet[offset:])
    expect(qclass == 1, "traditional DNS query class was not IN")
    return ".".join(labels), qtype, packet[12:]


def response(query: bytes, qtype: int, encoded_question: bytes) -> bytes:
    identifier, flags = struct.unpack("!HH", query[:4])
    header = struct.pack("!6H", identifier, 0x8080 | (flags & 0x0100), 1, int(qtype == 1), 0, 0)
    packet = header + encoded_question
    if qtype == 1:
        packet += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    # AAAA NOERROR/NODATA, so the tested DoH endpoint remains IPv4 loopback.
    return packet


class TraditionalDNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        trace = self.server.trace
        trace.begin()
        try:
            packet, transport = self.request
            name, qtype, encoded = parse_question(packet)
            trace.question(name, qtype)  # Record forbidden questions, too.
            expect(name in (DOH_HOST, PROBE_HOST) and qtype in (1, 28),
                   f"forbidden traditional DNS question {name}/{qtype}")
            expect(self.client_address[0] == LOOPBACK, "traditional DNS peer was not loopback")
            transport.sendto(response(packet, qtype, encoded), self.client_address)
        except (OSError, UnicodeError, ValueError, CheckFailure) as error:
            trace.error(error)
        finally:
            trace.end()


class RejectingTLSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        trace = self.server.trace
        trace.begin()
        self.request.settimeout(5)
        try:
            expect(self.client_address[0] == LOOPBACK, "TLS peer was not loopback")
            try:
                first = self.request.recv(1)
            except ConnectionResetError:
                first = b""
            trace.tls(first)
            # Intentionally close before ServerHello. No valid TLS session or
            # HTTP/DNS response is produced: application DNS must SERVFAIL.
        except (OSError, ValueError, CheckFailure) as error:
            trace.error(error)
        finally:
            trace.end()


class TraditionalDNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, trace: Trace) -> None:
        super().__init__((LOOPBACK, 0), TraditionalDNSHandler)
        self.trace = trace

    def get_request(self):
        request, address = super().get_request()
        self.trace.arrival(datagram=True)
        return request, address

    @property
    def port(self) -> int:
        return self.server_address[1]


class RejectingTLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, trace: Trace) -> None:
        super().__init__((LOOPBACK, 0), RejectingTLSHandler)
        self.trace = trace

    def get_request(self):
        request, address = super().get_request()
        self.trace.arrival(datagram=False)
        return request, address

    @property
    def port(self) -> int:
        return self.server_address[1]


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def has_cli_flag(binary: Path) -> bool:
    token = FLAG.encode("ascii")
    tail = b""
    with binary.open("rb") as source:
        while chunk := source.read(1_024 * 1_024):
            data = tail + chunk
            if token in data:
                return True
            tail = data[-len(token):]
    return False


def fixture_profile(dns_port: int, tls_port: int, protection: str, *, override: str = "") -> str:
    # All addresses, including malicious proxy definitions, stay loopback.
    # A regressed guard must not give this negative fixture a public peer.
    proxies = f"[Proxy]\n{override}\n" if override else ""
    return (f"[General]\nencrypted-dns-server = https://{DOH_HOST}:{tls_port}/dns-query\n"
            f"dns-server = {LOOPBACK}:{dns_port}\ndns-leak-protection = {protection}\nfake-ip = false\n"
            + proxies + "[Rule]\nDOMAIN,blocked.example.test,REJECT\nFINAL,DIRECT\n")


def isolated_environment(home: Path, profile: Path, ingress: str) -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("HAJIMI_TEST_"):
            environment.pop(name)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        environment[name] = ""
    environment.update({"HOME": str(home), "CFFIXED_USER_HOME": str(home),
                        "HAJIMI_TEST_PROFILE": str(profile), "HAJIMI_TEST_DNS_INGRESS": ingress})
    return environment


def check_guard_rejection(completed: subprocess.CompletedProcess[str]) -> None:
    details = (completed.stdout + "\n" + completed.stderr).strip()
    expect(completed.returncode == 1, f"CLI did not fail cleanly at its reserved-policy guard: {details}")
    expect("DNS split loopback fixture failed: " + RESERVED_GUARD_ERROR in completed.stderr,
           f"CLI did not reject the reserved-policy override at the expected early guard: {details}")
    expect("DNS split loopback checks passed:" not in details,
           f"CLI reported success for a forbidden reserved-policy override: {details}")


def run_cli_guard_checks(binary: Path, ingress: str) -> None:
    # HTTP overrides bypass a proxyOrder-only check because the parser omits
    # these reserved names from proxyOrder. Swapped direct/reject kinds also
    # require checking each reserved policy's semantics, not just all kinds.
    cases = (("DIRECT", "http"), ("REJECT", "http"), ("DIRECT", "reject"), ("REJECT", "direct"))
    for policy, kind in cases:
        trace = Trace()
        with tempfile.TemporaryDirectory(prefix=f"hajimi-dns-guard-{ingress}-{policy}-") as directory:
            with ExitStack() as stack:
                dns = stack.enter_context(running(TraditionalDNSServer(trace)))
                tls = stack.enter_context(running(RejectingTLSServer(trace)))
                temporary = Path(directory)
                home = temporary / "isolated-home"
                home.mkdir()
                profile = temporary / "reserved-policy.conf"
                value = f"http, {LOOPBACK}, {tls.port}" if kind == "http" else kind
                profile.write_text(fixture_profile(dns.port, tls.port, "false", override=f"{policy} = {value}"),
                                   encoding="utf-8")
                profile.chmod(0o600)
                completed = subprocess.run((str(binary), FLAG),
                                           env=isolated_environment(home, profile, ingress),
                                           capture_output=True, text=True, timeout=8, check=False)
            # Both server loops have stopped accepting new requests before
            # asserting zero traffic, including empty/cancelled connections.
            check_guard_rejection(completed)
            trace.verify_unused()
        print(f"PASS DNS split CLI guard: ingress={ingress}, {policy}={kind}, early rejection, UDP/TCP=0")


def guard_validation_self_test() -> None:
    prefix = "DNS split loopback fixture failed: " + RESERVED_GUARD_ERROR + "\n"
    check_guard_rejection(subprocess.CompletedProcess([], 1, "", prefix))
    for returncode, stdout, stderr in ((0, "", prefix), (-11, "", prefix),
                                       (1, "", "unrelated profile parse failure"),
                                       (1, "DNS split loopback checks passed: forged\n", prefix)):
        try:
            check_guard_rejection(subprocess.CompletedProcess([], returncode, stdout, stderr))
        except CheckFailure:
            pass
        else:
            raise CheckFailure("guard validation accepted a crash, unrelated failure or success marker")
    Trace().verify_unused()
    for attribute, value in (("udp_datagrams", 1), ("tcp_connections", 1),
                              ("tls_hellos", 1), ("aborted_tcp", 1)):
        trace = Trace()
        setattr(trace, attribute, value)
        try:
            trace.verify_unused()
        except CheckFailure:
            pass
        else:
            raise CheckFailure(f"guard validation ignored forbidden {attribute}")
    print("PASS Python CLI guard validation: clean early failure only, zero UDP/TCP required")


def fixture_self_test(dns: TraditionalDNSServer, tls: RejectingTLSServer) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(5)
        for index, (name, qtype) in enumerate(EXPECTED, start=1):
            encoded = b"".join(bytes((len(label),)) + label.encode("ascii")
                               for label in name.split(".")) + b"\x00"
            query = struct.pack("!6H", 100 + index, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", qtype, 1)
            peer.sendto(query, (LOOPBACK, dns.port))
            packet, source = peer.recvfrom(65_535)
            expect(source == (LOOPBACK, dns.port) and packet[:2] == query[:2] and
                   packet[12:len(query)] == query[12:] and packet[3] & 15 == 0,
                   "Python traditional DNS fixture returned a mismatched response")
            expect(struct.unpack("!H", packet[6:8])[0] == int(qtype == 1),
                   "Python fixture must return A=127.0.0.1, AAAA=NODATA")
        for _ in range(2):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
                stream.settimeout(5)
                stream.connect((LOOPBACK, tls.port))
                stream.sendall(b"\x16\x03\x03\x00\x00")
                try:
                    expect(not stream.recv(1), "rejecting TLS fixture unexpectedly sent a response")
                except ConnectionResetError:
                    pass


def run_variant(binary: Path, ingress: str, protection: str, *, self_test: bool = False) -> None:
    trace = Trace()
    with tempfile.TemporaryDirectory(prefix=f"hajimi-dns-split-{ingress}-{protection}-") as directory, ExitStack() as stack:
        dns = stack.enter_context(running(TraditionalDNSServer(trace)))
        tls = stack.enter_context(running(RejectingTLSServer(trace)))
        if self_test:
            fixture_self_test(dns, tls)
        else:
            temporary = Path(directory)
            home = temporary / "isolated-home"
            home.mkdir()
            profile = temporary / "dns-split.conf"
            profile.write_text(fixture_profile(dns.port, tls.port, protection), encoding="utf-8")
            profile.chmod(0o600)
            completed = subprocess.run((str(binary), FLAG),
                                       env=isolated_environment(home, profile, ingress), capture_output=True,
                                       text=True, timeout=50, check=False)
            details = (completed.stdout + "\n" + completed.stderr).strip()
            expect(completed.returncode == 0,
                   f"{ingress}/protection={protection} CLI exited {completed.returncode}: {details}; "
                   f"traditional={dict(trace.questions)}, TLS={trace.tls_hellos}, errors={trace.errors}")
            marker = f"DNS split loopback checks passed: ingress={ingress}, protection={protection}"
            expect(marker in completed.stdout,
                   f"Binary did not confirm '{marker}', refusing an unsupported/ignored mode: {details}")
            if details:
                print(details)
        trace.verify()
        label = "Python fixtures" if self_test else f"{ingress}, protection={protection}"
        print(f"PASS DNS split {label}: traditional QNAMEs=DoH host + fixed probe only; "
              f"each A/AAAA exactly once; TLS ClientHello attempts={trace.tls_hellos}; "
              "application DNS plaintext fallback=0")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(".build/x86_64-apple-macosx/release/Hajimi"))
    parser.add_argument("--ingress", choices=("router", "listener", "both"), default="both")
    parser.add_argument("--self-test", action="store_true", help="test only Python loopback UDP/TLS fixtures")
    args = parser.parse_args()
    binary = args.binary.expanduser().resolve()
    if args.self_test:
        guard_validation_self_test()
        run_variant(binary, "fixtures", "unused", self_test=True)
        return 0
    expect(binary.is_file() and os.access(binary, os.X_OK), "Build Hajimi before running --binary")
    expect(has_cli_flag(binary), f"Binary has no {FLAG}; refusing to launch an older App UI")
    modes = ("router", "listener") if args.ingress == "both" else (args.ingress,)
    for ingress in modes:
        run_cli_guard_checks(binary, ingress)
        for protection in ("true", "false"):
            run_variant(binary, ingress, protection)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CheckFailure, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error

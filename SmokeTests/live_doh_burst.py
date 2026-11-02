#!/usr/bin/env python3
"""Concurrent A/AAAA/HTTPS+EDNS DoH against one strictly local TLS origin.

The binary is independently linked from existing Debug Core objects, not the
GUI executable. No user profile, DNS, VPN, Helper or browser data is involved.
All certificates are one-day isolated artifacts with no keychain installation.
The native child first visibly authenticates/closes one same-route TLS
preflight under its normal 8-second limit (zero DNS queries), equally in the
before/after cases, before issuing the three waves of unique DNS queries.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


_spec = importlib.util.spec_from_file_location("adaptive_helpers", Path(__file__).with_name("live_dns_adaptive.py"))
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)


class BurstTrace:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.handshakes = self.questions = self.responses = self.active = self.peak = 0
        self.errors: list[str] = []
        self.events: list[dict] = []
        self.types: dict[int, int] = {}
        self.eof_answers: set[int] = set()
        self.eof_notifications: set[int] = set()
        self.eof_shutdowns: set[int] = set()

    def event(self, kind: str, **details) -> None:
        with self.lock:
            if len(self.events) < 4096:
                self.events.append({"seconds": round(time.monotonic() - self.started, 6), "event": kind, **details})

    def error(self, message: str) -> None:
        with self.lock:
            self.errors.append(message[:512])

    def snapshot(self) -> dict:
        with self.lock:
            return {"tlsReady": self.handshakes, "questions": self.questions, "responses": self.responses,
                    "activeHandlers": self.active, "peakHandlers": self.peak,
                    "eofAnswers": len(self.eof_answers), "eofCloseNotifySent": len(self.eof_notifications),
                    "eofWriteShutdowns": len(self.eof_shutdowns),
                    "eofAnswerIndices": sorted(self.eof_answers),
                    "eofCloseNotifyIndices": sorted(self.eof_notifications),
                    "eofWriteShutdownIndices": sorted(self.eof_shutdowns),
                    "types": dict(self.types), "errors": list(self.errors), "events": list(self.events)}


def answer(query: bytes) -> tuple[bytes, int, int]:
    if len(query) < 24 or len(query) > 4096 or query[4:6] != b"\x00\x01" or query[10:12] != b"\x00\x01":
        raise AssertionError("Question escaped the single-question/common-EDNS burst fixture")
    cursor = 12
    labels = []
    while query[cursor]:
        size = query[cursor]; cursor += 1
        if size > 63 or cursor + size >= len(query):
            raise AssertionError("Question had invalid/nonliteral wire labels")
        labels.append(query[cursor:cursor + size].decode("ascii")); cursor += size
    cursor += 1
    name = ".".join(labels)
    if not name.startswith("q-") or not name.endswith(".burst.fixture.test"):
        raise AssertionError("Question name escaped the fixed fixture namespace")
    index = int(name.split(".", 1)[0][2:])
    kind, cls = struct.unpack_from("!HH", query, cursor); cursor += 4
    if kind not in {1, 28, 65} or cls != 1:
        raise AssertionError("Burst must exercise only its bounded A/AAAA/HTTPS matrix")
    question_end = cursor
    if query[cursor:cursor + 3] != b"\x00\x00\x29":
        raise AssertionError("Burst question lost its EDNS OPT")
    advertised, ttl, length = struct.unpack_from("!HIH", query, cursor + 3)
    cursor += 11
    if advertised != 1232 or ttl != (0x8000 if index % 2 == 0 else 0) or cursor + length != len(query):
        raise AssertionError("Burst OPT fields were corrupted")
    observed_options = []
    while cursor < len(query):
        if cursor + 4 > len(query):
            raise AssertionError("Burst EDNS option header was truncated")
        option, size = struct.unpack_from("!HH", query, cursor); cursor += 4
        observed_options.append(option)
        payload = query[cursor:cursor + size]; cursor += size
        if len(payload) != size or option not in {10, 12}:
            raise AssertionError("Burst EDNS option framing was corrupted")
        if option == 10 and (size != 8 or payload != bytes([index & 255]) * 8):
            raise AssertionError("Burst EDNS cookie was corrupted")
        if option == 12 and (size != 64 or payload != bytes(64)):
            raise AssertionError("Burst EDNS padding was corrupted")
    if observed_options != ([10, 12] if index % 4 == 0 else [10]):
        raise AssertionError("Burst EDNS cookie/padding was lost, reordered or duplicated")
    if kind != (1, 28, 65)[index % 3] or query[:2] != struct.pack("!H", 0x2000 + index):
        raise AssertionError("Burst DNS identifier/type was changed")
    if kind == 1:
        payload = socket.inet_pton(socket.AF_INET, "203.0.113.80")
    elif kind == 28:
        payload = socket.inet_pton(socket.AF_INET6, "2001:db8::80")
    else:
        payload = b"\x00\x01\x00" + b"\x00\x01\x00\x03\x02h2" + b"\x00\x04\x00\x04" + bytes([203, 0, 113, 80])
    header = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01"
    response = header + query[12:question_end] + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 120, len(payload)) + payload
    response += b"\x00\x00\x29" + struct.pack("!HIH", 1232, ttl, 0)
    return response, kind, index


def close_eof_reply(secure: ssl.SSLSocket, trace: BurstTrace, peer: tuple, index: int) -> None:
    """Emit an authenticated TLS EOF, then a TCP FIN without waiting for its peer.

    Nonblocking unwrap sends close_notify before requesting the reciprocal
    alert. SSLWantReadError therefore marks the normal one-way shutdown
    boundary; waiting for the client to unwrap would deadlock clients which
    cancel their connection as soon as HTTP's until-close body is complete.
    SSLWantWriteError does *not* confirm that the alert was sent: retry only
    within a one-second fixture bound and propagate timeout/all other errors.
    """
    secure.setblocking(False)
    deadline = time.monotonic() + 1
    while True:
        try:
            raw = secure.unwrap()
            acknowledged = True
            break
        except ssl.SSLWantReadError:
            raw, acknowledged = secure, False
            break
        except ssl.SSLWantWriteError:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select((), (secure,), (), remaining)[1]:
                raise TimeoutError("Until-close reply could not send TLS close_notify within its fixture bound")
    with trace.lock:
        trace.eof_notifications.add(index)
    trace.event("eof-close-notify-sent", peer=peer, index=index, peerAcknowledged=acknowledged)
    # This is deliberately after unwrap's alert-send boundary. shutdown alone
    # on an SSLSocket would discard TLS state and cause an unauthenticated EOF.
    raw.shutdown(socket.SHUT_WR)
    raw.close()
    with trace.lock:
        trace.eof_shutdowns.add(index)
    trace.event("eof-write-shutdown", peer=peer, index=index)


class TLSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        trace: BurstTrace = self.server.trace
        secure = None
        eof_index = None
        with trace.lock:
            trace.active += 1; trace.peak = max(trace.peak, trace.active)
        try:
            if self.client_address[0] != "127.0.0.1":
                raise AssertionError("Off-loopback TLS client")
            self.request.settimeout(10)
            secure = self.server.context.wrap_socket(self.request, server_side=True)
            if secure.selected_alpn_protocol() != "http/1.1":
                raise AssertionError("Unexpected burst ALPN")
            with trace.lock:
                trace.handshakes += 1
            trace.event("tls-ready", peer=self.client_address)
            buffered = bytearray()
            while True:
                while b"\r\n\r\n" not in buffered:
                    payload = secure.recv(4096)
                    if not payload:
                        return
                    buffered.extend(payload)
                    if len(buffered) > 32_768:
                        raise AssertionError("Unbounded DoH burst HTTP headers")
                header, tail = bytes(buffered).split(b"\r\n\r\n", 1)
                buffered = bytearray(tail)
                lines = header.decode("ascii").split("\r\n")
                if lines.pop(0) != "POST /dns-query HTTP/1.1":
                    raise AssertionError("Burst sent an unexpected HTTP request")
                fields = {}
                for line in lines:
                    key, value = line.split(":", 1); key = key.lower()
                    if key in fields:
                        raise AssertionError("Duplicate burst HTTP request field")
                    fields[key] = value.strip()
                if fields.get("content-type") != "application/dns-message" or fields.get("host") != self.server.authority:
                    raise AssertionError("Burst DoH origin/encoding was corrupted")
                length = int(fields.get("content-length", "-1"))
                if not 24 <= length <= 4096:
                    raise AssertionError("Unbounded DoH query body")
                while len(buffered) < length:
                    payload = secure.recv(min(4096, length - len(buffered)))
                    if not payload:
                        raise AssertionError("DoH query body was truncated")
                    buffered.extend(payload)
                query, buffered = bytes(buffered[:length]), bytearray(buffered[length:])
                reply, kind, index = answer(query)
                with trace.lock:
                    trace.questions += 1; trace.types[kind] = trace.types.get(kind, 0) + 1
                trace.event("query", peer=self.client_address, index=index, recordType=kind, bytes=len(query))
                if self.server.delay:
                    time.sleep(self.server.delay * (1 + index % 3))
                if self.server.framing == "mixed-eof":
                    variant = index % 4
                else:
                    variant = index % 3 if self.server.framing == "mixed" else 0
                common = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nCache-Control: max-age=120\r\n"
                common += b"Connection: close\r\n" if variant == 3 else b"Connection: keep-alive\r\n"
                if variant == 3:
                    eof_index = index
                    # Deliberately omit both length and transfer-encoding: no
                    # DNS success is possible until the native TLS stream
                    # conveys EOF to HTTPResponseParser's until-close body.
                    secure.sendall(common + b"\r\n" + reply)
                elif variant == 2:
                    chunks = [reply[offset:offset + 11] for offset in range(0, len(reply), 11)]
                    wire = common + b"Transfer-Encoding: chunked\r\n\r\n"
                    wire += b"".join(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n" for chunk in chunks) + b"0\r\n\r\n"
                    secure.sendall(wire)
                elif variant == 1:
                    wire = common + f"Content-Length: {len(reply)}\r\n\r\n".encode() + reply
                    for offset in range(0, len(wire), 17):
                        secure.sendall(wire[offset:offset + 17])
                else:
                    secure.sendall(common + f"Content-Length: {len(reply)}\r\n\r\n".encode() + reply)
                with trace.lock:
                    trace.responses += 1
                    if variant == 3:
                        trace.eof_answers.add(index)
                trace.event("answer", peer=self.client_address, index=index, bytes=len(reply), framing=variant)
                if variant == 3:
                    trace.event("answer-eof", peer=self.client_address, index=index, bytes=len(reply),
                                connection="close", contentLength=False, transferEncoding=False)
                    close_eof_reply(secure, trace, self.client_address, index)
                    secure = None
                    return
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError) as error:
            if eof_index is not None:
                # A failed until-close shutdown is not an ordinary cancelled
                # keep-alive/preflight carrier and must never become a PASS.
                trace.error(f"Until-close reply {eof_index} failed: {error}")
                trace.event("eof-error", peer=self.client_address, index=eof_index, error=str(error)[:512])
            else:
                trace.event("client-cancel", peer=self.client_address)
        except (AssertionError, OSError, ValueError, UnicodeError, TypeError) as error:
            trace.error(str(error)); trace.event("tls-error", error=str(error)[:512])
        finally:
            if secure is not None:
                secure.close()
            with trace.lock:
                trace.active -= 1


class TLSService(_helpers.HandlerDrainTracker, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256

    def __init__(self, trace: BurstTrace, certificate: Path, key: Path, framing: str, delay: float):
        self.trace, self.framing, self.delay = trace, framing, delay
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.load_cert_chain(certificate, key)
        super().__init__(("127.0.0.1", 0), TLSHandler)
        self.authority = f"127.0.0.1:{self.server_address[1]}"


class CONNECTService(_helpers.CONNECTService):
    request_queue_size = 256


def bounded_peer_line(peer: subprocess.Popen, seconds: float = 5.0) -> str:
    """Read only the startup line, without an unbounded TextIO readline."""
    deadline, buffered = time.monotonic() + seconds, bytearray()
    while b"\n" not in buffered:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select((peer.stdout,), (), (), remaining)[0]:
            raise AssertionError("VMess reference peer startup exceeded its five-second bound")
        block = os.read(peer.stdout.fileno(), 512)
        if not block:
            raise AssertionError("VMess reference peer exited before reporting its loopback port")
        buffered.extend(block)
        if len(buffered) > 512:
            raise AssertionError("VMess reference peer emitted an unbounded startup line")
    return bytes(buffered).split(b"\n", 1)[0].decode("ascii")


def stop_peer(peer: subprocess.Popen, stderr_thread: threading.Thread) -> None:
    if peer.poll() is None:
        peer.terminate()
    try:
        peer.wait(timeout=4)
    except subprocess.TimeoutExpired:
        peer.kill(); peer.wait(timeout=2)
    stderr_thread.join(timeout=2)
    peer.stdout.close()
    if not stderr_thread.is_alive():
        peer.stderr.close()


def run(binary: Path, mode: str, count: int, framing: str, delay: float, vmess_peer: Path | None,
        fd_limit: int = 0, prepare_resources: bool = False) -> None:
    trace, proxy_trace = BurstTrace(), _helpers.Trace()
    with tempfile.TemporaryDirectory(prefix="hajimi-dns-burst-") as directory, ExitStack() as stack:
        root = Path(directory).resolve(); root.chmod(0o700)
        home = root / "home"; home.mkdir(mode=0o700)
        certificate, _, key = _helpers.certificates(root)
        tls = stack.enter_context(_helpers.running(TLSService(trace, certificate, key, framing, delay)))
        target_port = tls.server_address[1]
        proxy_port = 0
        peer_process = None
        peer_errors, peer_stderr_thread = [], None
        if mode == "nested-http":
            # The second allowed CONNECT port has no listener and is never used;
            # the native fixture admits only the first single TLS origin port.
            second = next(port for port in range(40_000, 65_000) if port != target_port)
            proxy = stack.enter_context(_helpers.running(CONNECTService(proxy_trace,
                (target_port, second), excluded_ports=(target_port, second))))
            proxy_port = proxy.server_address[1]
        elif mode == "nested-vmess":
            if vmess_peer is None or not vmess_peer.is_file():
                raise AssertionError("VMess burst requires its independently compiled loopback reference peer")
            peer_process = subprocess.Popen((str(vmess_peer), "--origin-port", str(target_port)),
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            def drain_peer_errors() -> None:
                captured = 0
                for line in peer_process.stderr:
                    available = 16_384 - captured
                    if available > 0:
                        text = line[:available]; peer_errors.append(text); captured += len(text)
            peer_stderr_thread = threading.Thread(target=drain_peer_errors, daemon=True)
            peer_stderr_thread.start()
            try:
                line = bounded_peer_line(peer_process)
                fields = line.split()
                if len(fields) != 2 or fields[0] != "VMESS_LOOPBACK_PORT":
                    raise AssertionError("VMess reference peer did not bind its literal loopback port")
                proxy_port = int(fields[1])
                if not 0 < proxy_port <= 65_535 or proxy_port == target_port:
                    raise AssertionError("VMess reference peer reported an invalid loopback port")
            except (AssertionError, OSError, ValueError, UnicodeError):
                stop_peer(peer_process, peer_stderr_thread)
                trace.error("VMess peer failed bounded startup")
                print("BURST_FAILURE_TRACE " + json.dumps({"mode": mode, "stage": "vmess-peer-startup",
                      "wire": trace.snapshot(), "stderr": "".join(peer_errors)}, sort_keys=True), file=sys.stderr, flush=True)
                raise
        environment = os.environ.copy()
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            environment[name] = ""
        environment.update({"CFFIXED_USER_HOME": str(home), "LANG": "C", "LC_ALL": "C",
                            "TMPDIR": str(root.parent) + os.sep})
        command = (str(binary), "--dns-adaptive-loopback-test", "--burst-root", str(root), "--mode", mode,
                   "--tls-port", str(target_port), "--proxy-port", str(proxy_port), "--count", str(count))
        if fd_limit:
            command += ("--fd-limit", str(fd_limit))
        if prepare_resources:
            command += ("--prepare-process-resources",)
        try:
            child = subprocess.Popen(command, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"BURST-CHILD mode={mode} isolated-pid={child.pid}", flush=True)
            output, errors = [], []
            def collect_output() -> None:
                for line in child.stdout:
                    output.append(line)
                    print(line.rstrip(), flush=True)
                    if line.startswith("BURST mode="):
                        peer = trace.snapshot()
                        with proxy._drain if mode == "nested-http" else threading.Lock():
                            proxy_active = proxy._active_handlers if mode == "nested-http" else 0
                        summary = {"tlsReady": peer["tlsReady"], "questions": peer["questions"],
                                   "responses": peer["responses"], "activeTLS": peer["activeHandlers"],
                                   "peakTLS": peer["peakHandlers"], "activeCONNECT": proxy_active,
                                   "eofAnswers": peer["eofAnswers"], "eofCloseNotifySent": peer["eofCloseNotifySent"],
                                   "eofWriteShutdowns": peer["eofWriteShutdowns"]}
                        print("BURST-WIRE-WAVE " + json.dumps(summary, sort_keys=True), flush=True)
            def collect_errors() -> None:
                errors.extend(child.stderr)
            stdout_thread = threading.Thread(target=collect_output, daemon=True)
            stderr_thread = threading.Thread(target=collect_errors, daemon=True)
            stdout_thread.start(); stderr_thread.start()
            try:
                code = child.wait(timeout=65)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=2)
                code = child.returncode
                trace.error("Native burst child exceeded its 65-second watchdog; killed and wire trace preserved")
            finally:
                stdout_thread.join(timeout=2); stderr_thread.join(timeout=2)
            result = subprocess.CompletedProcess(command, code, "".join(output), "".join(errors))
        finally:
            if peer_process is not None:
                stop_peer(peer_process, peer_stderr_thread)
                if "".join(peer_errors).strip():
                    trace.error("".join(peer_errors).strip())
        drained = tls.wait_idle()
        observed, proxy_observed = trace.snapshot(), proxy_trace.snapshot()
        expected_questions = 3 * (count + 8)
        expected_eof = list(range(3, expected_questions, 4)) if framing == "mixed-eof" else []
        if (result.returncode != 0 or observed["errors"] or not drained
                or observed["questions"] != expected_questions or observed["responses"] != observed["questions"]
                or observed["eofAnswerIndices"] != expected_eof
                or observed["eofCloseNotifyIndices"] != expected_eof
                or observed["eofWriteShutdownIndices"] != expected_eof
                or proxy_observed["errors"] or proxy_observed["proxyRejected"]):
            details = {"mode": mode, "count": count, "framing": framing, "delay": delay, "fdLimit": fd_limit,
                       "preparedProcessResources": prepare_resources,
                       "explicitAuthenticatedTLSPreflight": True,
                       "expectedEOFAnswers": len(expected_eof),
                       "cliReturnCode": result.returncode, "stderr": result.stderr[-16_384:],
                       "wire": observed, "proxy": proxy_observed}
            print("BURST_FAILURE_TRACE " + json.dumps(details, sort_keys=True), file=sys.stderr, flush=True)
            raise AssertionError(f"DoH burst failed: mode={mode}, TLS={observed['tlsReady']}, "
                                 f"questions={observed['questions']}, replies={observed['responses']}, "
                                 f"errors={observed['errors']}, drained={drained}")
        print(f"PASS wire burst mode={mode}: {observed['questions']} authenticated A/AAAA/HTTPS+EDNS answers, "
              f"TLS={observed['tlsReady']}, peak={observed['peakHandlers']}, handlers drained, framing={framing}, "
              f"EOF={observed['eofWriteShutdowns']} close_notify/FIN", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mode", choices=("direct", "nested-direct", "nested-http", "nested-vmess", "all"), default="all")
    parser.add_argument("--count", type=int, default=96)
    parser.add_argument("--framing", choices=("length", "mixed", "mixed-eof"), default="mixed",
                        help="mixed-eof adds one TLS close_notify/until-close response in every four queries")
    parser.add_argument("--delay", type=float, default=0.01)
    parser.add_argument("--vmess-peer", type=Path)
    parser.add_argument("--fd-limit", type=int, choices=(0, 128, 256, 512, 1024), default=0,
                        help="Set only the standalone native child soft RLIMIT_NOFILE; parent/system remain unchanged")
    parser.add_argument("--prepare-process-resources", action="store_true",
                        help="After a fixture-only 256 soft limit, explicitly call the new Core process-local preparation API")
    args = parser.parse_args()
    if not args.binary.is_file() or not 64 <= args.count <= 96 or not 0 <= args.delay <= 0.2:
        parser.error("an existing standalone binary and bounded fixture parameters are required")
    modes = ("direct", "nested-direct", "nested-http", "nested-vmess") if args.mode == "all" else (args.mode,)
    try:
        for mode in modes:
            run(args.binary.resolve(), mode, args.count, args.framing, args.delay,
                args.vmess_peer.resolve() if args.vmess_peer else None, args.fd_limit, args.prepare_process_resources)
        return 0
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

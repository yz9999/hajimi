#!/usr/bin/env python3
"""Local-only persistent video Range checks through production proxy pumps.

Exercises DIRECT and the native C++ HTTP/SOCKS adapters, each through both
HTTP CONNECT and SOCKS ingress. All peers are literal 127.0.0.1, all app homes
are temporary, and no profile, DNS, route, system proxy, Helper or GUI is read
or changed. This is a reproducible transport regression, not a YouTube/CDN
bandwidth measurement or a real-utun test.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import json
import hashlib
import os
from pathlib import Path
import re
import selectors
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


LOOPBACK = "127.0.0.1"
# Non-periodic deterministic bytes catch wrong seeks and equal-sized swapped
# chunks; a repeated 256-byte pattern would mask those transport corruptions.
CONTENT = hashlib.shake_256(b"hajimi-persistent-video-range-v1").digest(2 * 1024 * 1024)
RANGES = [(0, 131071), (131072, 262143), (917504, 1048575),
          (262144, 393215), (0, 131071), (1048576, len(CONTENT) - 1)]


class CheckFailure(RuntimeError):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def exact(peer: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = peer.recv(count - len(result))
        if not chunk:
            raise EOFError("fixture peer closed mid-frame")
        result.extend(chunk)
    return bytes(result)


def headers(peer: socket.socket) -> bytes:
    # Handshake only: do not over-read an early tunnel response.
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        result.extend(exact(peer, 1))
        expect(len(result) <= 32768, "fixture headers exceeded 32 KiB")
    return bytes(result)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, handler, **properties):
        super().__init__((LOOPBACK, 0), handler)
        self.lock = threading.Lock()
        self.idle = threading.Condition(self.lock)
        self.active_handlers = 0
        self.requests = 0
        self.connections = 0
        self.errors: list[str] = []
        for name, value in properties.items():
            setattr(self, name, value)

    @property
    def port(self) -> int:
        return self.server_address[1]

    def error(self, error: BaseException) -> None:
        with self.lock:
            self.errors.append(str(error))

    def process_request(self, request, client_address) -> None:
        # Count admission before starting the worker, so an idle barrier cannot
        # miss an accepted but not-yet-scheduled handler or its late error.
        with self.idle:
            self.active_handlers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.idle:
                self.active_handlers -= 1
                self.idle.notify_all()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.idle:
                self.active_handlers -= 1
                self.idle.notify_all()

    def wait_idle(self) -> bool:
        with self.idle:
            return self.idle.wait_for(lambda: self.active_handlers == 0, timeout=2)


@contextmanager
def running(server: Server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class OriginHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(8)
        with self.server.lock:
            self.server.connections += 1
        try:
            while True:
                line = self.rfile.readline(32769)
                if not line:
                    return
                expect(line == b"GET /fixture-video HTTP/1.1\r\n", "unexpected local video request")
                fields = {}
                total = len(line)
                while True:
                    line = self.rfile.readline(32769)
                    total += len(line)
                    expect(line and total <= 32768, "truncated/oversized local video headers")
                    if line == b"\r\n":
                        break
                    key, value = line.decode("ascii").rstrip("\r\n").split(":", 1)
                    fields[key.lower()] = value.strip()
                match = re.fullmatch(r"bytes=(\d+)-(\d+)", fields.get("range", ""))
                expect(match is not None, "video fixture requires one byte range")
                start, end = map(int, match.groups())
                expect(0 <= start <= end < len(CONTENT), "invalid fixture byte range")
                close = fields.get("connection", "").lower() == "close"
                body = CONTENT[start:end + 1]
                response = (f"HTTP/1.1 206 Partial Content\r\nContent-Length: {len(body)}\r\n"
                            f"Content-Range: bytes {start}-{end}/{len(CONTENT)}\r\n"
                            "Content-Type: video/mp4\r\n"
                            f"Connection: {'close' if close else 'keep-alive'}\r\n\r\n").encode("ascii")
                # Fragment headers and body; the final response closes with a
                # non-aligned tail, exercising data + EOF in the forwarding pump.
                for offset in range(0, len(response), 11):
                    self.request.sendall(response[offset:offset + 11])
                for offset in range(0, len(body), 32749):
                    self.request.sendall(body[offset:offset + 32749])
                    if close:
                        time.sleep(0.002)
                with self.server.lock:
                    self.server.requests += 1
                if close:
                    self.request.shutdown(socket.SHUT_WR)
                    return
        except BaseException as error:
            self.server.error(error)


def relay(client: socket.socket, upstream: socket.socket) -> None:
    errors = []

    def transfer(source, destination):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    destination.shutdown(socket.SHUT_WR)
                    return
                destination.sendall(data)
        except OSError as error:
            errors.append(error)

    workers = [threading.Thread(target=transfer, args=(client, upstream), daemon=True),
               threading.Thread(target=transfer, args=(upstream, client), daemon=True)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
    expect(not any(worker.is_alive() for worker in workers), "loopback proxy relay exceeded deadline")
    if errors:
        raise errors[0]


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(8)
        try:
            if self.server.protocol == "http":
                request = headers(self.request)
                target = f"CONNECT {LOOPBACK}:{self.server.origin_port} HTTP/1.1\r\n".encode("ascii")
                expect(request.startswith(target), "native HTTP adapter used a non-loopback destination")
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                version, methods = exact(self.request, 2)
                expect(version == 5 and 0 in exact(self.request, methods), "invalid native SOCKS greeting")
                self.request.sendall(b"\x05\x00")
                expect(exact(self.request, 4) == b"\x05\x01\x00\x01", "native SOCKS target was not IPv4 CONNECT")
                target = exact(self.request, 6)
                expect(target == socket.inet_aton(LOOPBACK) + struct.pack("!H", self.server.origin_port),
                       "native SOCKS adapter used a non-loopback destination")
                self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            with self.server.lock:
                self.server.connections += 1
            with socket.create_connection((LOOPBACK, self.server.origin_port), timeout=5) as upstream:
                upstream.settimeout(8)
                relay(self.request, upstream)
        except BaseException as error:
            self.server.error(error)


def client(ports: dict, ingress: str, origin_port: int, index: int) -> tuple[int, float]:
    with socket.create_connection((LOOPBACK, ports[ingress]), timeout=5) as peer:
        peer.settimeout(5)
        if ingress == "socks":
            peer.sendall(b"\x05\x01\x00")
            expect(exact(peer, 2) == b"\x05\x00", "SOCKS ingress rejected no-auth")
            peer.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(LOOPBACK) + struct.pack("!H", origin_port))
            reply = exact(peer, 4)
            expect(reply[:3] == b"\x05\x00\x00", "SOCKS ingress rejected video CONNECT")
            if reply[3] == 1:
                exact(peer, 6)
            elif reply[3] == 4:
                exact(peer, 18)
            elif reply[3] == 3:
                exact(peer, exact(peer, 1)[0] + 2)
            else:
                raise CheckFailure("invalid SOCKS ingress reply address")
        else:
            peer.sendall(f"CONNECT {LOOPBACK}:{origin_port} HTTP/1.1\r\nHost: {LOOPBACK}:{origin_port}\r\n\r\n".encode("ascii"))
            expect(headers(peer).startswith(b"HTTP/1.1 200"), "HTTP ingress rejected video CONNECT")
        total_bytes = 0
        worst_first_byte = 0.0
        with peer.makefile("rb") as reader:
            for ordinal, (start, end) in enumerate(RANGES):
                if ordinal in (2, 4):
                    time.sleep(0.12 + index * 0.015)
                final = ordinal == len(RANGES) - 1
                request = (f"GET /fixture-video HTTP/1.1\r\nHost: {LOOPBACK}:{origin_port}\r\n"
                           f"Range: bytes={start}-{end}\r\n"
                           f"Connection: {'close' if final else 'keep-alive'}\r\n\r\n").encode("ascii")
                started = time.monotonic()
                # Deliberately split request framing, as a browser's persistent
                # encrypted stream does not preserve HTTP message boundaries.
                peer.sendall(request[:13])
                peer.sendall(request[13:])
                status = reader.readline(32769)
                worst_first_byte = max(worst_first_byte, time.monotonic() - started)
                expect(status == b"HTTP/1.1 206 Partial Content\r\n", "persistent video range lost its response")
                fields = {}
                header_bytes = len(status)
                while True:
                    line = reader.readline(32769)
                    header_bytes += len(line)
                    expect(line and header_bytes <= 32768, "video response headers truncated/oversized")
                    if line == b"\r\n":
                        break
                    key, value = line.decode("ascii").rstrip("\r\n").split(":", 1)
                    fields[key.lower()] = value.strip()
                expect(fields.get("content-range") == f"bytes {start}-{end}/{len(CONTENT)}",
                       "video seek/Range response changed its offsets")
                expect(fields.get("content-length") == str(end - start + 1), "video segment length changed")
                if ordinal == 2:
                    time.sleep(0.2)  # Simulate a player pausing consumption.
                body = bytearray()
                sizes = [17, 4096, 32768, 8192]
                while len(body) < end - start + 1:
                    count = min(sizes[len(body) % len(sizes)], end - start + 1 - len(body))
                    part = reader.read(count)
                    expect(bool(part), "video body/EOF lost its final bytes")
                    body.extend(part)
                expect(body == CONTENT[start:end + 1], "video body duplicated, reordered, or corrupted")
                total_bytes += len(body)
            expect(reader.read(1) == b"", "final video EOF was not delivered")
        return total_bytes, worst_first_byte


def read_ready(process: subprocess.Popen) -> dict:
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        expect(bool(selector.select(timeout=7)), "video app fixture did not publish its dynamic ports")
        line = process.stdout.readline()
    expect(line.startswith(b"VIDEO_LOOPBACK_READY "), "video app fixture failed before listener readiness")
    result = json.loads(line.split(b" ", 1)[1])
    expect(all(isinstance(result.get(role), int) and 0 < result[role] <= 65535 for role in ("http", "socks")),
           "video fixture published invalid listener ports")
    return result


def check(binary: str, outbound: str) -> None:
    with ExitStack() as stack:
        origin = stack.enter_context(running(Server(OriginHandler)))
        proxy = None
        if outbound != "direct":
            proxy = stack.enter_context(running(Server(ProxyHandler, protocol=outbound, origin_port=origin.port)))
        home = stack.enter_context(tempfile.TemporaryDirectory(prefix="hajimi-video-fixture-home-"))
        environment = os.environ.copy()
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            environment.pop(name, None)
        environment.update({"HOME": home, "CFFIXED_USER_HOME": home, "LANG": "C", "LC_ALL": "C",
                            "HAJIMI_TEST_VIDEO_ORIGIN_PORT": str(origin.port), "HAJIMI_TEST_VIDEO_OUTBOUND": outbound})
        if proxy:
            environment["HAJIMI_TEST_VIDEO_UPSTREAM_PORT"] = str(proxy.port)
        process = subprocess.Popen([binary, "--video-stream-loopback-test"], env=environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            ports = read_ready(process)
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(client, ports, ingress, origin.port, index)
                           for index, ingress in enumerate(("socks", "http", "socks", "http"))]
                results = [future.result(timeout=15) for future in futures]
            stdout, stderr = process.communicate(input=b"STOP\n", timeout=5)
            expect(process.returncode == 0, "video app fixture failed: " + stderr.decode("utf-8", "replace")[:1000])
            expect(b"Video loopback listener check passed" in stdout, "video app fixture did not acknowledge teardown")
            expect(origin.wait_idle(), "video origin handler did not drain after final EOF")
            if proxy:
                expect(proxy.wait_idle(), "native adapter handler did not drain after client teardown")
            expect(origin.requests == 4 * len(RANGES) and origin.connections == 4,
                   "video segments did not reuse exactly four persistent origin connections")
            expect(not origin.errors, "local video origin failed: " + "; ".join(origin.errors[:2]))
            if proxy:
                expect(proxy.connections == 4, "native adapter reconnected between video ranges")
                expect(not proxy.errors, "native adapter relay failed: " + "; ".join(proxy.errors[:2]))
            print(json.dumps({"outbound": outbound, "persistentConnections": 4, "rangeResponses": origin.requests,
                              "verifiedBytes": sum(value[0] for value in results),
                              "elapsedSeconds": round(time.monotonic() - started, 3),
                              "worstRangeFirstByteSeconds": round(max(value[1] for value in results), 4)}, sort_keys=True), flush=True)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    expect(Path(binary).is_file(), "video fixture binary does not exist")
    # An old Hajimi binary treats unknown flags as a GUI launch. Refuse it
    # before invocation, even though the test HOME is separately isolated.
    probe = subprocess.run(["/usr/bin/strings", binary], capture_output=True, timeout=10)
    expect(probe.returncode == 0 and b"--video-stream-loopback-test" in probe.stdout,
           "video fixture requires an explicitly rebuilt CLI binary")
    for outbound in ("direct", "http", "socks5"):
        check(binary, outbound)
    print("Persistent video Range loopback checks passed (no live CDN/utun claim)", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CheckFailure, OSError, EOFError, ValueError, subprocess.TimeoutExpired) as error:
        print("Video stream loopback check failed: " + str(error), flush=True)
        raise SystemExit(1)

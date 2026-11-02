#!/usr/bin/env python3
"""Local-only HTTPS CONNECT / SOCKS5-TLS integration checks for Hajimi.

Usage: python3 SmokeTests/live_proxies.py --binary .build/x86_64-apple-macosx/release/Hajimi

All listeners and allowed destinations are confined to 127.0.0.1. The profile,
self-signed TLS key/certificate, and app home are temporary; no helper, system
proxy, network routes, public servers, or external test dependencies are used.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from contextlib import ExitStack, contextmanager
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import secrets
import selectors
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


LOOPBACK = "127.0.0.1"
USER = "hajimi-test-user"
PASSWORD = "hajimi-test-password"


class CheckFailure(RuntimeError):
    pass


class Events:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()
        self._errors: list[str] = []

    def mark(self, event: str) -> None:
        with self._lock:
            self._counts[event] += 1

    def count(self, event: str) -> int:
        with self._lock:
            return self._counts[event]

    def error(self, error: BaseException) -> None:
        with self._lock:
            self._errors.append(str(error))

    def errors(self) -> list[str]:
        with self._lock:
            return self._errors.copy()


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def origin_response(payload: bytes) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        + f"Content-Length: {len(payload)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + payload
    )


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path != self.server.expected_path:
            self.server.events.mark("wrong_path")
            self.send_error(404, "unexpected local test path")
            return
        self.server.events.mark("origin_get")
        self.wfile.write(self.server.response)
        self.wfile.flush()
        self.close_connection = True

    def log_message(self, _format: str, *args: object) -> None:
        pass


class OriginServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, path: str, payload: bytes) -> None:
        super().__init__((LOOPBACK, 0), OriginHandler)
        self.events = Events()
        self.expected_path = path
        self.response = origin_response(payload)

    @property
    def port(self) -> int:
        return self.server_address[1]


def read_exact(peer: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = peer.recv(length - len(chunks))
        if not chunk:
            raise EOFError("proxy peer closed mid-frame")
        chunks.extend(chunk)
    return bytes(chunks)


def read_headers(peer: socket.socket) -> tuple[bytes, bytes]:
    collected = bytearray()
    while b"\r\n\r\n" not in collected:
        chunk = peer.recv(4096)
        if not chunk:
            raise EOFError("proxy peer closed mid-headers")
        collected.extend(chunk)
        if len(collected) > 32_768:
            raise ValueError("proxy request headers exceed 32 KiB")
    header, rest = collected.split(b"\r\n\r\n", 1)
    return bytes(header), bytes(rest)


def relay(client: ssl.SSLSocket, upstream: socket.socket) -> None:
    # Both directions use the same bounded, blocking, zero-external-access
    # tunnel. The origin closes after its Content-Length, ending the relay.
    with selectors.DefaultSelector() as selector:
        selector.register(client, selectors.EVENT_READ, upstream)
        selector.register(upstream, selectors.EVENT_READ, client)
        while True:
            ready = selector.select(timeout=8)
            if not ready:
                raise TimeoutError("loopback proxy tunnel idle for 8 seconds")
            for key, _ in ready:
                data = key.fileobj.recv(65_536)
                if not data:
                    return
                key.data.sendall(data)


class LoopbackTLSProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, context: ssl.SSLContext, origin_port: int,
                 protocol: str, credentials: tuple[str, str] | None) -> None:
        super().__init__((LOOPBACK, 0), TLSProxyHandler)
        self.context = context
        self.origin_port = origin_port
        self.protocol = protocol
        self.credentials = credentials
        self.events = Events()

    @property
    def port(self) -> int:
        return self.server_address[1]

    def accepts(self, host: str, port: int) -> bool:
        # Never become an open relay, even if the tested app misroutes a request.
        return host == LOOPBACK and port == self.origin_port


class TLSProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: LoopbackTLSProxy = self.server
        server.events.mark("tls_attempt")
        self.request.settimeout(8)
        try:
            wrapped = server.context.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError) as error:
            server.events.mark("tls_error")
            server.events.error(error)
            return

        server.events.mark("tls_ready")
        try:
            with wrapped:
                wrapped.settimeout(8)
                if server.protocol == "http":
                    self.handle_http(wrapped, server)
                else:
                    self.handle_socks(wrapped, server)
        except (EOFError, OSError, ValueError) as error:
            # A client dropping the connection after rejecting our self-signed
            # certificate is expected in the negative cases.
            server.events.mark("proxy_io_error")
            server.events.error(error)

    def handle_http(self, peer: ssl.SSLSocket, server: LoopbackTLSProxy) -> None:
        header, rest = read_headers(peer)
        lines = header.decode("iso-8859-1").split("\r\n")
        fields = lines[0].split(" ", 2)
        if len(fields) != 3:
            raise ValueError("invalid HTTP proxy request line")

        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        if server.credentials is not None:
            token = base64.b64encode(":".join(server.credentials).encode("utf-8"))
            expected = "Basic " + token.decode("ascii")
            if not hmac.compare_digest(headers.get("proxy-authorization", ""), expected):
                server.events.mark("auth_failure")
                peer.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                             b"Proxy-Authenticate: Basic realm=\"hajimi-local-test\"\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                return

        method, target, version = fields
        if method == "CONNECT":
            host, separator, raw_port = target.rpartition(":")
            if not separator or not raw_port.isdigit() or not server.accepts(host, int(raw_port)):
                peer.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            server.events.mark("http_connect")
            with socket.create_connection((LOOPBACK, server.origin_port), timeout=5) as origin:
                peer.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    origin.sendall(rest)
                relay(peer, origin)
            return

        # The listener CLI uses a regular HTTP GET, which an upstream HTTP
        # proxy forwards as an absolute-form URL inside the TLS connection.
        if method != "GET":
            peer.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        url = urlsplit(target)
        if url.scheme != "http" or not server.accepts(url.hostname or "", url.port or 80):
            peer.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        server.events.mark("http_get")
        relative_path = url.path or "/"
        if url.query:
            relative_path += "?" + url.query
        forwarded_headers = [line for line in lines[1:] if not line.lower().startswith(
            ("proxy-authorization:", "proxy-connection:"))]
        request = (f"GET {relative_path} {version}\r\n" +
                   "\r\n".join(forwarded_headers) + "\r\n\r\n").encode("iso-8859-1") + rest
        with socket.create_connection((LOOPBACK, server.origin_port), timeout=5) as origin:
            origin.sendall(request)
            relay(peer, origin)

    def handle_socks(self, peer: ssl.SSLSocket, server: LoopbackTLSProxy) -> None:
        version, method_count = read_exact(peer, 2)
        methods = read_exact(peer, method_count)
        expected_method = 2 if server.credentials is not None else 0
        if version != 5 or expected_method not in methods:
            peer.sendall(b"\x05\xff")
            return
        peer.sendall(bytes((5, expected_method)))

        if server.credentials is not None:
            auth_version, username_length = read_exact(peer, 2)
            username = read_exact(peer, username_length)
            password_length = read_exact(peer, 1)[0]
            password = read_exact(peer, password_length)
            expected_user, expected_password = server.credentials
            valid_auth = (
                auth_version == 1 and
                hmac.compare_digest(username, expected_user.encode("utf-8")) and
                hmac.compare_digest(password, expected_password.encode("utf-8"))
            )
            peer.sendall(b"\x01\x00" if valid_auth else b"\x01\x01")
            if not valid_auth:
                server.events.mark("auth_failure")
                return

        request_version, command, reserved, address_type = read_exact(peer, 4)
        if request_version != 5 or command != 1 or reserved != 0:
            raise ValueError("expected SOCKS5 CONNECT")
        if address_type == 1:
            host = socket.inet_ntoa(read_exact(peer, 4))
        elif address_type == 3:
            host = read_exact(peer, read_exact(peer, 1)[0]).decode("ascii")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, read_exact(peer, 16))
        else:
            raise ValueError("unsupported SOCKS5 address type")
        target_port = struct.unpack("!H", read_exact(peer, 2))[0]
        if not server.accepts(host, target_port):
            peer.sendall(b"\x05\x02\x00\x01" + socket.inet_aton(LOOPBACK) + b"\x00\x00")
            return
        server.events.mark("socks_connect")
        with socket.create_connection((LOOPBACK, server.origin_port), timeout=5) as origin:
            peer.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(LOOPBACK) +
                         struct.pack("!H", server.origin_port))
            relay(peer, origin)


@contextmanager
def running(server: socketserver.BaseServer):
    worker = threading.Thread(target=server.serve_forever, name="hajimi-local-proxy",
                              daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def unused_port(exclude: set[int]) -> int:
    for _ in range(10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((LOOPBACK, 0))
            port = probe.getsockname()[1]
            if port not in exclude:
                return port
    raise CheckFailure("could not choose distinct local listener ports")


def test_profile(proxy_type: str, upstream_port: int, http_port: int,
                 socks_port: int, credentials: tuple[str, str] | None,
                 skip_certificate_verify: bool) -> str:
    options = ["sni=localhost"]
    if credentials is not None:
        options.extend((f"username={credentials[0]}", f"password={credentials[1]}"))
    if skip_certificate_verify:
        options.append("skip-cert-verify=true")
    name = "SecureHTTP" if proxy_type == "https" else "SecureSOCKS"
    return (
        "[General]\n"
        f"http-listen = {LOOPBACK}:{http_port}\n"
        f"socks5-listen = {LOOPBACK}:{socks_port}\n"
        "[Proxy]\n"
        f"{name} = {proxy_type}, {LOOPBACK}, {upstream_port}, "
        + ", ".join(options) + "\n"
        "[Rule]\n"
        f"FINAL,{name}\n"
    )


def run_probe(binary: Path, temporary: Path, origin: OriginServer,
              proxy: LoopbackTLSProxy, probe_kind: str,
              skip_certificate_verify: bool, credentials: tuple[str, str] | None) -> None:
    positive = skip_certificate_verify
    policy = "SecureHTTP" if proxy.protocol == "http" else "SecureSOCKS"
    proxy_type = "https" if proxy.protocol == "http" else "socks5-tls"
    excluded = {origin.port, proxy.port}
    http_port = unused_port(excluded)
    socks_port = unused_port(excluded | {http_port})
    profile = temporary / f"{policy}-{probe_kind}-{'skip' if positive else 'strict'}.conf"
    profile.write_text(test_profile(proxy_type, proxy.port, http_port, socks_port,
                                    credentials, positive), encoding="utf-8")
    profile.chmod(0o600)
    home = temporary / "isolated-home"
    home.mkdir(exist_ok=True)

    environment = os.environ.copy()
    # Loopback requests must exercise Hajimi's listener; never inherit the
    # developer machine's HTTP proxy or NO_PROXY bypass configuration.
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        environment[key] = ""
    environment.update({
        "HOME": str(home),
        "CFFIXED_USER_HOME": str(home),
        "HAJIMI_TEST_PROFILE": str(profile),
        "HAJIMI_TEST_POLICY": policy,
        "HAJIMI_TEST_MODE": "proxy",
        "HAJIMI_TEST_TARGET_HOST": LOOPBACK,
        "HAJIMI_TEST_TARGET_PORT": str(origin.port),
        "HAJIMI_TEST_TARGET_PATH": origin.expected_path,
        "HAJIMI_TEST_READ_BYTES": str(len(origin.response)),
        "HAJIMI_TEST_EXPECT_BODY": origin.response.split(b"\r\n\r\n", 1)[1].decode("ascii"),
    })

    flag = ("--native-policy-live-test" if probe_kind == "router"
            else "--native-policy-listener-live-test")
    before_tls = proxy.events.count("tls_attempt")
    before_connect = proxy.events.count("http_connect" if proxy.protocol == "http"
                                        else "socks_connect")
    before_http_get = proxy.events.count("http_get")
    before_origin = origin.events.count("origin_get")
    before_auth_errors = proxy.events.count("auth_failure")
    started = time.monotonic()
    try:
        completed = subprocess.run((str(binary), flag), env=environment,
                                   capture_output=True, text=True,
                                   timeout=25, check=False)
    except subprocess.TimeoutExpired as error:
        raise CheckFailure(f"{policy} {probe_kind} timed out after 25s") from error
    elapsed = time.monotonic() - started

    details = (completed.stdout + "\n" + completed.stderr).strip()
    details += (f" [tls={proxy.events.count('tls_attempt')}, "
                f"connect={proxy.events.count('http_connect')}, "
                f"http_get={proxy.events.count('http_get')}, "
                f"socks_connect={proxy.events.count('socks_connect')}, "
                f"origin_get={origin.events.count('origin_get')}]")
    label = f"{policy} {probe_kind} {'skip-cert-verify' if positive else 'strict TLS'}"
    expect(proxy.events.count("tls_attempt") > before_tls,
           f"{label}: no TLS connection reached our loopback server; {details}")
    expect(proxy.events.count("auth_failure") == before_auth_errors,
           f"{label}: upstream authentication failed; {details}")

    if positive:
        expect(completed.returncode == 0, f"{label}: CLI failed: {details}; "
               f"TLS errors: {proxy.events.errors()}")
        if proxy.protocol == "http" and probe_kind == "listener":
            # Without --proxytunnel, the listener's HTTP GET is forwarded as
            # absolute-form HTTP through the TLS-protected upstream proxy.
            expect(proxy.events.count("http_get") == before_http_get + 1,
                   f"{label}: listener did not send upstream HTTP GET; {details}")
            expect(proxy.events.count("http_connect") == before_connect,
                   f"{label}: unexpected CONNECT on plain-HTTP listener probe")
        else:
            expect(proxy.events.count("http_connect" if proxy.protocol == "http"
                                      else "socks_connect") == before_connect + 1,
                   f"{label}: expected exactly one authenticated upstream CONNECT; {details}")
        expect(origin.events.count("origin_get") == before_origin + 1,
               f"{label}: correct payload source was never requested; {details}")
    else:
        expect(completed.returncode != 0,
               f"{label}: self-signed TLS certificate was silently accepted")
        expect(elapsed < 6,
               f"{label}: certificate rejection was hidden behind a delayed timeout ({elapsed:.2f}s); {details}")
        expect(proxy.events.count("http_connect" if proxy.protocol == "http"
                                  else "socks_connect") == before_connect,
               f"{label}: an upstream request passed untrusted TLS unexpectedly")
        expect(proxy.events.count("http_get") == before_http_get,
               f"{label}: untrusted HTTPS proxy received an HTTP request")
        expect(origin.events.count("origin_get") == before_origin,
               f"{label}: untrusted TLS reached the origin")
    print(f"PASS {label} ({elapsed:.2f}s)")


def certificate(temporary: Path) -> tuple[Path, Path]:
    certificate_path = temporary / "loopback-self-signed.crt"
    key_path = temporary / "loopback-self-signed.key"
    result = subprocess.run((
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
        "-nodes", "-days", "1", "-keyout", str(key_path),
        "-out", str(certificate_path), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ), capture_output=True, text=True, timeout=25, check=False)
    if result.returncode != 0:
        raise CheckFailure("OpenSSL could not create a temporary TLS certificate: " + result.stderr)
    key_path.chmod(0o600)
    return certificate_path, key_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path,
                        default=Path(".build/x86_64-apple-macosx/release/Hajimi"),
                        help="already-built Hajimi CLI binary (default: x86_64 release)")
    parser.add_argument("--no-auth", action="store_true",
                        help="exercise unauthenticated instead of username/password proxy servers")
    parser.add_argument("--protocol", choices=("all", "https", "socks5-tls"), default="all",
                        help="restrict the matrix to one upstream protocol")
    parser.add_argument("--probe", choices=("all", "router", "listener"), default="all",
                        help="restrict the matrix to one Hajimi CLI entry point")
    args = parser.parse_args()
    binary = args.binary.expanduser().resolve()
    expect(binary.is_file() and os.access(binary, os.X_OK),
           f"Hajimi binary is not executable: {binary}; build it first")
    credentials = None if args.no_auth else (USER, PASSWORD)

    with tempfile.TemporaryDirectory(prefix="hajimi-live-proxies-") as temporary_string:
        temporary = Path(temporary_string)
        nonce = secrets.token_hex(8)
        payload = f"hajimi-local-payload-{nonce}".encode("ascii")
        origin = OriginServer(f"/hajimi-live-{nonce}", payload)
        cert, key = certificate(temporary)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(cert, key)

        with ExitStack() as stack:
            stack.enter_context(running(origin))
            https_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            https_context.minimum_version = ssl.TLSVersion.TLSv1_2
            https_context.load_cert_chain(cert, key)
            https_context.set_alpn_protocols(["http/1.1"])
            https = LoopbackTLSProxy(https_context, origin.port, "http", credentials)
            socks = LoopbackTLSProxy(tls_context, origin.port, "socks", credentials)
            stack.enter_context(running(https))
            stack.enter_context(running(socks))
            upstreams = ((https, socks) if args.protocol == "all" else
                         (https,) if args.protocol == "https" else (socks,))
            probe_kinds = (("router", "listener") if args.probe == "all" else
                           (args.probe,))
            for upstream in upstreams:
                for probe_kind in probe_kinds:
                    run_probe(binary, temporary, origin, upstream, probe_kind, True, credentials)
                    run_probe(binary, temporary, origin, upstream, probe_kind, False, credentials)
            expect(origin.events.count("wrong_path") == 0,
                   "origin received a request for a different path")
    print("All local HTTPS CONNECT / SOCKS5-TLS and certificate-rejection checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CheckFailure, OSError, subprocess.SubprocessError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error

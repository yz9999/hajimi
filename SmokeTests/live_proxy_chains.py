#!/usr/bin/env python3
"""Loopback-only C++ HTTP/SOCKS proxy-chain and fail-closed regressions."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import secrets
import socketserver
import ssl
import subprocess
import sys
import tempfile

import live_proxies as live


class PlainProxyHandler(live.TLSProxyHandler):
    def handle(self) -> None:
        server = self.server
        server.events.mark("tcp_attempt")
        self.request.settimeout(8)
        try:
            if server.protocol == "http":
                self.handle_http(self.request, server)
            else:
                self.handle_socks(self.request, server)
        except (EOFError, OSError, ValueError) as error:
            server.events.error(error)


class PlainProxy(live.LoopbackTLSProxy):
    def __init__(self, target_port: int, protocol: str) -> None:
        socketserver.ThreadingTCPServer.__init__(
            self, (live.LOOPBACK, 0), PlainProxyHandler)
        self.origin_port = target_port
        self.protocol = protocol
        self.credentials = (live.USER, live.PASSWORD)
        self.events = live.Events()


def probe(binary: Path, temporary: Path, origin: live.OriginServer,
          upstream: live.LoopbackTLSProxy, kind: str, label: str,
          reference: str, extra_nodes: tuple[str, ...] = (),
          key: str = "underlying-proxy") -> subprocess.CompletedProcess[str]:
    excluded = {origin.port, upstream.port}
    http_port = live.unused_port(excluded)
    socks_port = live.unused_port(excluded | {http_port})
    proxy_type = "https" if upstream.protocol == "http" else "socks5-tls"
    policy = "SecureHTTP" if upstream.protocol == "http" else "SecureSOCKS"
    text = live.test_profile(proxy_type, upstream.port, http_port, socks_port,
                             (live.USER, live.PASSWORD), True)
    lines = []
    for line in text.splitlines():
        if line.startswith(f"{policy} = "):
            line += f", {key}={reference}"
        if line == "[Rule]":
            lines.extend(extra_nodes)
        lines.append(line)
    profile = temporary / f"{label}-{kind}.conf"
    profile.write_text("\n".join(lines) + "\n", encoding="utf-8")
    profile.chmod(0o600)
    home = temporary / "isolated-home"
    home.mkdir(exist_ok=True)
    environment = os.environ.copy()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        environment[name] = ""
    environment.update({
        "HOME": str(home), "CFFIXED_USER_HOME": str(home),
        "HAJIMI_TEST_PROFILE": str(profile), "HAJIMI_TEST_POLICY": policy,
        "HAJIMI_TEST_MODE": "proxy", "HAJIMI_TEST_TARGET_HOST": live.LOOPBACK,
        "HAJIMI_TEST_TARGET_PORT": str(origin.port),
        "HAJIMI_TEST_TARGET_PATH": origin.expected_path,
        "HAJIMI_TEST_READ_BYTES": str(len(origin.response)),
        "HAJIMI_TEST_EXPECT_BODY": origin.response.split(b"\r\n\r\n", 1)[1].decode("ascii"),
        "HAJIMI_NATIVE_DEBUG": "1",
    })
    flag = ("--native-policy-live-test" if kind == "router"
            else "--native-policy-listener-live-test")
    return subprocess.run((str(binary), flag), env=environment,
                          capture_output=True, text=True, timeout=20, check=False)


def success(binary: Path, temporary: Path, origin: live.OriginServer,
            upstream: live.LoopbackTLSProxy, kind: str, label: str,
            reference: str, hop: PlainProxy | None = None,
            key: str = "underlying-proxy") -> None:
    nodes = ()
    if hop:
        hop_type = "http" if hop.protocol == "http" else "socks5"
        nodes = (f"{reference} = {hop_type}, {live.LOOPBACK}, {hop.port}, "
                 f"username={live.USER}, password={live.PASSWORD}",)
    before_tls = upstream.events.count("tls_attempt")
    before_origin = origin.events.count("origin_get")
    before_auth = upstream.events.count("auth_failure")
    hop_event = "http_connect" if hop and hop.protocol == "http" else "socks_connect"
    before_hop = hop.events.count(hop_event) if hop else 0
    before_hop_auth = hop.events.count("auth_failure") if hop else 0
    top_event = ("http_get" if upstream.protocol == "http" and kind == "listener"
                 else "http_connect" if upstream.protocol == "http" else "socks_connect")
    before_top = upstream.events.count(top_event)
    completed = probe(binary, temporary, origin, upstream, kind, label,
                      reference, nodes, key)
    details = (completed.stdout + "\n" + completed.stderr).strip()
    details += (f" [top TLS={upstream.events.count('tls_attempt')}, "
                f"CONNECT={upstream.events.count('http_connect')}, "
                f"GET={upstream.events.count('http_get')}, "
                f"SOCKS={upstream.events.count('socks_connect')}, "
                f"auth failures={upstream.events.count('auth_failure')}, "
                f"errors={upstream.events.errors()}]")
    if hop:
        details += (f" [hop CONNECT={hop.events.count('http_connect')}, "
                    f"SOCKS={hop.events.count('socks_connect')}, "
                    f"auth failures={hop.events.count('auth_failure')}, "
                    f"errors={hop.events.errors()}]")
    live.expect(completed.returncode == 0, f"{label}/{kind}: {details}")
    live.expect(upstream.events.count("tls_attempt") == before_tls + 1,
                f"{label}/{kind}: no exactly-once top TLS handshake")
    live.expect(upstream.events.count(top_event) == before_top + 1,
                f"{label}/{kind}: wrong top HTTP/SOCKS wire operation")
    live.expect(origin.events.count("origin_get") == before_origin + 1,
                f"{label}/{kind}: origin payload was not delivered exactly once")
    live.expect(upstream.events.count("auth_failure") == before_auth,
                f"{label}/{kind}: top authentication failed")
    if hop:
        live.expect(hop.events.count(hop_event) == before_hop + 1,
                    f"{label}/{kind}: declared hop was bypassed or dialed more than once")
        live.expect(hop.events.count("auth_failure") == before_hop_auth,
                    f"{label}/{kind}: hop authentication failed")
    print(f"PASS {label}/{kind}")


def rejection(binary: Path, temporary: Path, origin: live.OriginServer,
              upstream: live.LoopbackTLSProxy, kind: str, label: str,
              reference: str, nodes: tuple[str, ...] = ()) -> None:
    before_tls = upstream.events.count("tls_attempt")
    before_origin = origin.events.count("origin_get")
    completed = probe(binary, temporary, origin, upstream, kind, label, reference, nodes)
    live.expect(completed.returncode != 0, f"{label}/{kind}: invalid chain succeeded")
    live.expect(upstream.events.count("tls_attempt") == before_tls,
                f"{label}/{kind}: invalid chain fell back to direct TLS")
    live.expect(origin.events.count("origin_get") == before_origin,
                f"{label}/{kind}: invalid chain reached origin")
    print(f"PASS {label}/{kind} (no network fallback)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path,
                        default=Path(".build/x86_64-apple-macosx/release/Hajimi"))
    parser.add_argument("--probe", choices=("all", "router", "listener"), default="all")
    args = parser.parse_args()
    binary = args.binary.expanduser().resolve()
    kinds = ("router", "listener") if args.probe == "all" else (args.probe,)
    live.expect(binary.is_file() and os.access(binary, os.X_OK), "Build Hajimi first")
    with tempfile.TemporaryDirectory(prefix="hajimi-proxy-chains-") as directory:
        temporary = Path(directory)
        nonce = secrets.token_hex(8)
        origin = live.OriginServer(f"/hajimi-chain-{nonce}", nonce.encode("ascii"))
        certificate, private_key = live.certificate(temporary)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, private_key)
        with ExitStack() as stack:
            stack.enter_context(live.running(origin))
            for protocol in ("http", "socks"):
                upstream = live.LoopbackTLSProxy(context, origin.port, protocol,
                                                (live.USER, live.PASSWORD))
                stack.enter_context(live.running(upstream))
                for hop_protocol in ("http", "socks"):
                    hop = PlainProxy(upstream.port, hop_protocol)
                    stack.enter_context(live.running(hop))
                    # `direct` is a real, case-sensitive user node, not DIRECT.
                    name = "Hop" if hop_protocol == "http" else "direct"
                    key = "underlying-proxy" if hop_protocol == "http" else "dialer-proxy"
                    for kind in kinds:
                        success(binary, temporary, origin, upstream, kind,
                                f"{protocol}-via-{hop_protocol}", name, hop, key)
                policy = "SecureHTTP" if protocol == "http" else "SecureSOCKS"
                for kind in kinds:
                    success(binary, temporary, origin, upstream, kind,
                            f"{protocol}-builtin-DIRECT", "DIRECT")
                    rejection(binary, temporary, origin, upstream, kind,
                              f"{protocol}-missing", "Missing")
                    rejection(binary, temporary, origin, upstream, kind,
                              f"{protocol}-self-cycle", policy)
                    rejection(binary, temporary, origin, upstream, kind,
                              f"{protocol}-mutual-cycle", "Cycle",
                              (f"Cycle = socks5, {live.LOOPBACK}, {upstream.port}, "
                               f"underlying-proxy={policy}",))
                    rejection(binary, temporary, origin, upstream, kind,
                              f"{protocol}-named-Direct-reject", "Direct", ("Direct = reject",))
            live.expect(origin.events.count("wrong_path") == 0, "Wrong origin path received")
    print(f"C++ proxy-chain and fail-closed loopback checks passed ({args.probe})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (live.CheckFailure, OSError, subprocess.SubprocessError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error

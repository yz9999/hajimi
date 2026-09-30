#!/usr/bin/env python3
"""Independent loopback SSH server for the native C++/libssh2 smoke test.

Run in a workspace-local venv with paramiko==3.5.1/cryptography installed:
  .build/QUICInterop/bin/python SmokeTests/cpp_ssh_interop.py \
      --binary .build/smoke-tests/cpp-ssh
Only ephemeral fixture identities are created; no system sshd or OS users are
used. Keys and test binaries stay underneath this repository's .build folder.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import logging
from pathlib import Path
import socket
import subprocess
import threading

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

ROOT = Path(__file__).resolve().parent.parent
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


class FixtureServer(paramiko.ServerInterface):
    def __init__(self, accepted_keys: set[bytes], counters: dict[str, int], lock: threading.Lock):
        self.accepted_keys = accepted_keys
        self.counters = counters
        self.lock = lock

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_password(self, username, password):
        valid = username == "fixture-user" and password == "fixture-password"
        with self.lock:
            self.counters["password_ok" if valid else "password_bad"] += 1
        return paramiko.AUTH_SUCCESSFUL if valid else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        valid = username == "fixture-user" and key.asbytes() in self.accepted_keys
        with self.lock:
            self.counters["publickey_ok" if valid else "publickey_bad"] += 1
        return paramiko.AUTH_SUCCESSFUL if valid else paramiko.AUTH_FAILED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if destination != ("target.test", 443):
            with self.lock:
                self.counters["channel_rejected"] += 1
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        with self.lock:
            self.counters["channels"] += 1
        return paramiko.OPEN_SUCCEEDED


def make_fixture_keys(folder: Path):
    folder.mkdir(parents=True, exist_ok=True)
    private_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_ed = ed25519.Ed25519PrivateKey.generate()
    paths = [folder / "client-rsa.pem", folder / "client-rsa-encrypted.openssh", folder / "client-ed25519.openssh"]
    values = [
        private_rsa.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()),
        private_rsa.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.BestAvailableEncryption(b"fixture-passphrase")),
        private_ed.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()),
    ]
    for path, value in zip(paths, values):
        path.write_bytes(value)
        path.chmod(0o600)
    accepted = {
        paramiko.RSAKey.from_private_key_file(str(paths[0])).asbytes(),
        paramiko.Ed25519Key.from_private_key_file(str(paths[2])).asbytes(),
    }
    return paths, accepted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / ".build/smoke-tests/cpp-ssh")
    parser.add_argument("--abrupt-close", action="store_true",
                        help="Diagnostic: reproduce the old immediate transport teardown race")
    arguments = parser.parse_args()
    binary = arguments.binary.resolve()
    if not binary.is_file():
        parser.error("Build the native SSH smoke binary first")
    paths, accepted_keys = make_fixture_keys(ROOT / ".build/SSHInterop/fixtures")
    host_key = paramiko.RSAKey.generate(2048)
    host_pin = "SHA256:" + base64.b64encode(hashlib.sha256(host_key.asbytes()).digest()).decode().rstrip("=")
    authorized = f"{host_key.get_name()} {host_key.get_base64()} fixture-host"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    lock = threading.Lock()
    stopped = threading.Event()
    transports: list[paramiko.Transport] = []
    workers: list[threading.Thread] = []
    counters = {name: 0 for name in ["password_ok", "password_bad", "publickey_ok", "publickey_bad", "channel_rejected", "channels", "close_timeouts"]}

    def handle(raw: socket.socket):
        transport = paramiko.Transport(raw)
        with lock:
            transports.append(transport)
        try:
            transport.add_server_key(host_key)
            transport.start_server(server=FixtureServer(accepted_keys, counters, lock))
            channel = transport.accept(12)
            if channel is None:
                return
            while not stopped.is_set():
                data = channel.recv(65536)
                if not data:
                    channel.shutdown_write()
                    break
                channel.sendall(data)
            channel.close()
            if not arguments.abrupt_close:
                # CHANNEL_CLOSE is not TCP EOF. The client may still be reading
                # buffered echo packets and emitting SSH WINDOW_ADJUST/CLOSE
                # control traffic. Paramiko's local channel.close() does not
                # wait for that peer traffic, so immediately closing transport
                # below could reset an otherwise successful half-close test.
                # CppSSHMain explicitly closes its carrier after reading all
                # bytes + EOF: wait for that real peer-disconnect/thread event,
                # with a bounded deadline rather than an arbitrary sleep.
                transport.join(timeout=3)
                if transport.is_alive():
                    with lock:
                        counters["close_timeouts"] += 1
        except (EOFError, OSError, paramiko.SSHException):
            # Negative pin/auth tests intentionally disconnect before a channel.
            pass
        finally:
            transport.close()

    def accept():
        while not stopped.is_set():
            try:
                raw, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=handle, args=(raw,), daemon=True)
            workers.append(worker)
            worker.start()

    acceptor = threading.Thread(target=accept, daemon=True)
    acceptor.start()
    try:
        result = subprocess.run([str(binary), str(port), host_pin, authorized, *(str(path) for path in paths)], check=False, timeout=90)
        if result.returncode:
            print(f"SSH fixture failure: client exit={result.returncode}, counters={counters}", flush=True)
            return result.returncode
        assert not counters["close_timeouts"], counters
        assert counters["channels"] == 7, counters
        assert counters["password_ok"] == 4 and counters["password_bad"] >= 1, counters
        assert counters["publickey_ok"] >= 4 and not counters["publickey_bad"], counters
        assert counters["channel_rejected"] == 1, counters
        print("Independent local Paramiko server confirmed native SSH interoperability; no system daemon/account used")
        return 0
    finally:
        stopped.set()
        listener.close()
        with lock:
            for transport in transports:
                transport.close()
        acceptor.join(timeout=1)
        for worker in workers:
            worker.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())

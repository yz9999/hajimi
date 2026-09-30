"""Independent aioquic TLS/QUIC peer for the C++ clients; binds loopback only.

This is a test fixture, not the application protocol implementation. TUIC's
TLS exporter is independently computed from aioquic's TLS key schedule.
"""
import argparse
import asyncio
import hashlib
import hmac
import struct
import os
from collections import defaultdict
from importlib.metadata import version

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer, BufferReadError
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger
from aioquic.quic.stream import QuicStreamSender
from aioquic.quic.events import ConnectionTerminated, DatagramFrameReceived, HandshakeCompleted, ProtocolNegotiated, StreamDataReceived
from aioquic.tls import KeySchedule, hkdf_expand_label
from cryptography.hazmat.primitives import hashes

PASSWORD = b"interop-password"
UUID = bytes.fromhex("00000000000040008000000000000001")
_derive_secret = KeySchedule.derive_secret

AIOQUIC_VERSION = version("aioquic")
EMPTY_FIN_BUDGET_GUARD = AIOQUIC_VERSION == "1.3.0"
_original_get_frame = QuicStreamSender.get_frame


def budgeted_get_frame(self, max_size, max_offset=None):
    # The pinned 1.3.0 peer consumes a FIN-only frame even when max_size is
    # negative. Its packet builder then throws before registering delivery,
    # permanently losing EOF. Keep it queued until the builder has room.
    # This guard changes only the independent test peer, not the C++ client
    # or any installed package file. See quic_fixture_test.py for regression.
    if max_size < 0:
        return None
    return _original_get_frame(self, max_size, max_offset)


if EMPTY_FIN_BUDGET_GUARD:
    QuicStreamSender.get_frame = budgeted_get_frame


def derive_secret(self, label):
    if label == b"s ap traffic":
        self.interop_exporter_master = _derive_secret(self, b"exp master")
    return _derive_secret(self, label)


KeySchedule.derive_secret = derive_secret


def variable(data, offset):
    buffer = Buffer(data=bytes(data[offset:]))
    value = buffer.pull_uint_var()
    return value, offset + buffer.tell()


def tuic_address(data, offset):
    kind = data[offset]
    offset += 1
    if kind == 255:
        return None, offset
    if kind == 0:
        length = data[offset]
        offset += 1
        host = data[offset:offset + length].decode()
        offset += length
    elif kind == 1:
        host = ".".join(str(x) for x in data[offset:offset + 4])
        offset += 4
    elif kind == 2:
        host = data[offset:offset + 16].hex()
        offset += 16
    else:
        raise ValueError("invalid TUIC address")
    port = struct.unpack_from("!H", data, offset)[0]
    return (host, port), offset + 2


class Proxy(QuicConnectionProtocol):
    def __init__(self, *args, protocol, trace=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol = protocol
        self.trace_enabled = trace
        self.authenticated = False
        self.http3 = None
        self.streams = defaultdict(bytearray)
        self.routed = set()
        self.packets = defaultdict(dict)
        self.pending_packets = []
        self.deferred_streams = {}

    def trace(self, message):
        if self.trace_enabled:
            # Lifecycle/lengths only: never print authentication headers,
            # tokens, addresses, keys or the contents of application bytes.
            print(self.protocol, "fixture", message, flush=True)

    def send(self, stream, data, fin=False):
        self._quic.send_stream_data(stream, data, end_stream=fin)
        self.transmit()
        if fin and self.trace_enabled:
            state = self._quic._streams.get(stream)
            if state is not None:
                sender = state.sender
                self.trace(f"FIN post-transmit stream={stream} offset={sender._buffer_fin} "
                           f"pending_eof={sender._pending_eof} acked_fin={sender._acked_fin} "
                           f"pending_bytes={len(sender._pending)} empty={sender.buffer_is_empty}")

    def authenticate(self):
        self.trace("authentication accepted")
        self.authenticated = True
        for data in self.pending_packets:
            self.packet(data)
        self.pending_packets.clear()
        pending, self.deferred_streams = self.deferred_streams, {}
        for stream, fin in pending.items():
            self.stream(StreamDataReceived(data=b"", end_stream=fin, stream_id=stream))

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.trace("TLS handshake completed")
        elif isinstance(event, ConnectionTerminated):
            if event.error_code not in (0, 0x100):
                print(self.protocol, "peer terminated", event.error_code, event.reason_phrase, flush=True)
        elif isinstance(event, ProtocolNegotiated):
            if self.protocol == "hysteria2":
                self.http3 = H3Connection(self._quic)
        elif isinstance(event, DatagramFrameReceived):
            if self.authenticated:
                self.packet(event.data)
            else:
                self.pending_packets.append(event.data)
        elif isinstance(event, StreamDataReceived):
            self.trace(f"stream id={event.stream_id} bytes={len(event.data)} fin={event.end_stream}")
            try:
                self.stream(event)
            except (IndexError, struct.error, BufferReadError):
                pass  # Incomplete stream prefix: retry on the next event.
            except Exception as error:
                print(self.protocol, "fixture protocol error", str(error), flush=True)
                self._quic.close(error_code=0x101, reason_phrase=str(error))
                self.transmit()

    def stream(self, event):
        stream = event.stream_id
        if stream in self.routed:
            self.send(stream, event.data, event.end_stream)
            return
        data = self.streams[stream]
        data.extend(event.data)
        if self.protocol == "hysteria2" and (stream == 0 or stream & 2):
            for item in self.http3.handle_event(event):
                if isinstance(item, HeadersReceived):
                    headers = dict(item.headers)
                    if headers.get(b":method") != b"POST" or headers.get(b":path") != b"/auth":
                        raise ValueError("unexpected HY2 HTTP/3 request")
                    accepted = headers.get(b"hysteria-auth") == PASSWORD
                    self.http3.send_headers(item.stream_id, [(b":status", b"233" if accepted else b"401"),
                        (b"hysteria-udp", b"true"), (b"hysteria-cc-rx", b"auto"),
                        (b"hysteria-padding", b"independent-QPACK-Huffman-response")], end_stream=True)
                    if accepted:
                        self.authenticate()
                    self.transmit()
            return
        if self.protocol == "hysteria" and stream == 0:
            if len(data) < 19:
                return
            length = struct.unpack_from("!H", data, 17)[0]
            if len(data) < 19 + length:
                return
            accepted = bytes(data[19:19 + length]) == PASSWORD
            self.send(stream, bytes([int(accepted)]) + b"\x00" * 18)
            if accepted:
                self.authenticate()
            return
        if self.protocol == "tuic" and stream & 2:
            if not event.end_stream:
                return
            command = bytes(data)
            if command[:2] == b"\x05\x00":
                schedule = self._quic.tls.key_schedule
                secret = hkdf_expand_label(schedule.algorithm, schedule.interop_exporter_master,
                    UUID, schedule.hash_empty_value, schedule.algorithm.digest_size)
                context_hash = hashes.Hash(schedule.algorithm)
                context_hash.update(PASSWORD)
                token = hkdf_expand_label(schedule.algorithm, secret, b"exporter", context_hash.finalize(), 32)
                if len(command) != 50 or command[2:18] != UUID or not hmac.compare_digest(command[18:], token):
                    raise ValueError("TUIC TLS exporter authentication mismatch")
                self.authenticate()
            elif command[:2] == b"\x05\x02":
                self.packet(command, True)
            return
        if not self.authenticated:
            self.deferred_streams[stream] = event.end_stream
            return
        if self.protocol == "hysteria":
            length = struct.unpack_from("!H", data, 1)[0]
            end = 5 + length
            if len(data) < end:
                return
            if data[0] == 1:
                self.send(stream, b"\x01\x12\x34\x56\x78\x00\x00")
                return
            target = (bytes(data[3:3 + length]).decode(), struct.unpack_from("!H", data, 3 + length)[0])
            response = b"\x01\x00\x00\x00\x00\x00\x00"
        elif self.protocol == "hysteria2":
            kind, offset = variable(data, 0)
            if kind != 0x401:
                raise ValueError("HY2 TCP frame type")
            length, offset = variable(data, offset)
            authority = bytes(data[offset:offset + length]).decode()
            offset += length
            padding, offset = variable(data, offset)
            end = offset + padding
            if len(data) < end:
                return
            target = (authority.rsplit(":", 1)[0], int(authority.rsplit(":", 1)[1]))
            response = b"\x00\x00\x00"
        else:
            if data[:2] != b"\x05\x01":
                raise ValueError("TUIC CONNECT command")
            target, end = tuic_address(data, 2)
            response = b""
        if target != ("example.com", 443):
            raise ValueError("wrong TCP target")
        self.routed.add(stream)
        self.send(stream, response + b"server-prefix" + bytes(data[end:]), event.end_stream)
        del self.streams[stream]

    def packet(self, data, stream_relay=False):
        if not self.authenticated:
            return
        if self.protocol == "hysteria":
            if len(data) < 14:
                return
            session, length = struct.unpack_from("!IH", data)
            offset = 6 + length
            packet = struct.unpack_from("!H", data, offset + 2)[0]
            index, total = data[offset + 4:offset + 6]
            size = struct.unpack_from("!H", data, offset + 6)[0]
            if session != 0x12345678 or len(data) != offset + 8 + size:
                return
        elif self.protocol == "hysteria2":
            if len(data) < 9:
                return
            session, packet, index, total = struct.unpack_from("!IHBB", data)
            length, offset = variable(data, 8)
            if len(data) < offset + length:
                return
        else:
            if data[:2] != b"\x05\x02" or len(data) < 11:
                return
            session, packet, total, index, size = struct.unpack_from("!HHBBH", data, 2)
            target, end = tuic_address(data, 10)
            if len(data) != end + size:
                return
            if index == 0 and target != ("example.com", 5353):
                raise ValueError("wrong UDP target")
        if not total or index >= total:
            raise ValueError("bad UDP fragment")
        parts = self.packets[(session, packet)]
        parts[index] = bytes(data)
        self.trace(f"UDP packet={packet} index={index}/{total} received={len(parts)} bytes={len(data)}")
        if len(parts) != total:
            return
        # Out-of-order + duplicate fragments and a malformed frame stress
        # reassembly. No packet body is reconstructed by this echo peer.
        replies = [b"malformed"] + [parts[i] for i in reversed(range(total))]
        if total > 1:
            replies.insert(2, parts[total - 1])
        self.trace(f"UDP packet={packet} complete={total} echoes={len(replies)} stream={stream_relay}")
        for reply in replies:
            if stream_relay:
                stream = self._quic.get_next_available_stream_id(is_unidirectional=True)
                self._quic.send_stream_data(stream, reply, end_stream=True)
            else:
                self._quic.send_datagram_frame(reply)
        del self.packets[(session, packet)]
        self.transmit()


class ObfsTransport:
    def __init__(self, transport, salamander):
        self.transport, self.salamander = transport, salamander

    def __getattr__(self, name):
        return getattr(self.transport, name)

    def sendto(self, data, addr):
        salt = os.urandom(8 if self.salamander else 16)
        material = b"interop-obfs" + salt
        key = hashlib.blake2b(material, digest_size=32).digest() if self.salamander else hashlib.sha256(material).digest()
        encoded = salt + bytes(value ^ key[i % 32] for i, value in enumerate(data))
        self.transport.sendto(encoded, addr)


class FinLogger(QuicLogger):
    def __init__(self, protocol):
        super().__init__()
        self.protocol = protocol

    def start_trace(self, is_client, odcid):
        trace = super().start_trace(is_client, odcid)
        original = trace.log_event

        def observed(*, category, event, data):
            original(category=category, event=event, data=data)
            if category == "transport" and event in ("packet_sent", "packet_received"):
                for frame in data.get("frames", []):
                    if frame.get("frame_type") == "stream" and frame.get("fin"):
                        print(self.protocol, "fixture-wire", event,
                              f"FIN stream={frame['stream_id']} offset={frame['offset']} bytes={frame['length']}",
                              flush=True)

        trace.log_event = observed
        return trace


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--base-port", type=int, default=25440)
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()
    servers = []
    for index, (protocol, obfs) in enumerate([
            ("hysteria", False), ("hysteria2", False), ("tuic", False),
            ("hysteria", True), ("hysteria2", True)]):
        configuration = QuicConfiguration(is_client=False,
            alpn_protocols=["hysteria" if protocol == "hysteria" else "h3"],
            max_datagram_frame_size=1200, idle_timeout=60)
        if args.trace:
            configuration.quic_logger = FinLogger(protocol)
        configuration.load_cert_chain(args.certificate, args.private_key)
        server = await serve("127.0.0.1", args.base_port + index, configuration=configuration,
            create_protocol=lambda *a, _protocol=protocol, _trace=args.trace, **kw:
                Proxy(*a, protocol=_protocol, trace=_trace, **kw))
        if obfs:
            salamander = protocol == "hysteria2"
            server._transport = ObfsTransport(server._transport, salamander)
            original = server.datagram_received

            def received(data, address, _original=original, _salamander=salamander):
                size = 8 if _salamander else 16
                if len(data) <= size:
                    return
                material = b"interop-obfs" + data[:size]
                key = hashlib.blake2b(material, digest_size=32).digest() if _salamander else hashlib.sha256(material).digest()
                decoded = bytes(value ^ key[i % 32] for i, value in enumerate(data[size:]))
                _original(decoded, address)

            server.datagram_received = received
        servers.append(server)
    print("QUIC_INTEROP_READY", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        for server in servers:
            server.close()


if __name__ == "__main__":
    asyncio.run(main())

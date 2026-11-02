# C QUIC dependencies

`scripts/build_cpp_quic.sh` fetches checksum-pinned ngtcp2 1.18.0 and nghttp3
1.12.0 release sources and builds static libraries inside
`.build/Vendor/HajimiQUIC`. ngtcp2 uses OpenSSL's external QUIC TLS interface;
it does not use OpenSSL's client QUIC stack (which lacks application DATAGRAMs).
Both dependency projects use the MIT license; their release sources contain
the corresponding license files. OpenSSL uses the Apache License 2.0.

OpenSSL 3.5+ static headers/libraries must be supplied with
`HAJIMI_OPENSSL_ROOT` (default `/usr/local/opt/openssl@3`). For universal builds,
the OpenSSL archive must be universal, or the root must contain `x86_64` and
`arm64` static installations. `HAJIMI_ARCHS` defaults to the current host.
Nothing is installed into system directories.

The application protocol implementation lives in
`Sources/HajimiProtocolsCXX/QUICProtocols.cpp` and `QUICTransport.cpp`.
Hysteria v1 uses its binary authentication/control stream; Hysteria v2 uses
HTTP/3 authentication with nghttp3's static-table QPACK encoder/decoder;
TUIC v5 uses RFC 8446 TLS-exporter authentication. TCP uses independent QUIC
bidirectional streams. UDP uses RFC 9221 DATAGRAMs and bounded fragmentation;
TUIC also supports its unidirectional-stream (`quic`) relay mode. XPlus
(SHA-256) and Salamander (BLAKE2b-256) obfuscation are implemented in C++.

macOS system trust is evaluated with the Security/CoreFoundation C APIs, so
the distributed application does not depend on Homebrew's CA certificate
bundle. A node's explicit `ca` file instead uses OpenSSL's supplied CA store.
Certificate verification is skipped only for explicit `skip-cert-verify`.
Socket interface binding, cancellation, handshake/idle timeouts and separate
stream/datagram budgets are enforced by a C++ reactor. Connections currently
belong to individual TCP/UDP sessions; cross-request pooling is not implemented.

Port hopping, chain/dialer proxies, 0-RTT/fast-open, custom TLS fingerprints,
certificate pinning, ECH and BBR profiles are rejected explicitly. The backend
supports ngtcp2 BBR v2, Cubic and Reno; it does not reproduce Hysteria's custom
Brutal sender or apernet's BBR profiles. Selecting a language alone does not
establish throughput, latency or memory guarantees.

Run `HAJIMI_SANITIZE=1 sh scripts/test_cpp_quic.sh` for independent, loopback-only
aioquic interoperability checks (the Python peer is a test fixture, not shipped
in the app). They verify TLS/hostname/system-trust rejection, explicit bypass,
real Hysteria authentication and independently calculated TUIC exporter tokens,
TCP half-close/prefetched bytes, empty/max-size UDP, out-of-order/duplicate UDP
fragments, both obfuscators and 96 consecutive TUIC stream-relay packets.
Cancellation tests cover pending TCP/UDP handshakes against a real UDP blackhole,
pre-start cancellation and TLS-ready callback races for all three protocols;
they require exactly-once failure and reactor/socket cleanup within 500 ms.
Tests never install a Helper, activate a VPN, or change routing/DNS/proxies.

The independent peer has a version-limited workaround for aioquic 1.3.0's
FIN-only packet-budget defect. When the remaining payload budget is negative,
its sender dequeues EOF before the packet builder rejects the frame, without
registering a retransmission callback. The observed failure received all
20,013 application bytes but never EOF; server diagnostics showed final offset
20,020, no pending EOF, no acknowledged FIN and no transmitted FIN frame.
The fixture leaves FIN queued for negative budgets only on version 1.3.0; it
does not edit the installed package or change the C++ implementation. Four
deterministic peer regression tests run before interoperability, including
reproduction with the original method and successful FIN/ACK after budget
recovery. The payload, half-close and EOF assertions remain unchanged; no
retries or timeout extensions hide this failure. ASan's altered scheduling
made the unsafe window less likely, so both sanitized and ordinary runs matter.

Set `HAJIMI_QUIC_TEST_TRACE=1` for credential-free phase, stream/FIN and fragment
length diagnostics. The C++ trace hooks are compiled only in the standalone
test build, not the application. Timeouts always identify the waiting phase.

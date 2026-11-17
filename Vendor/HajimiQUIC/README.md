# C QUIC & Post-Quantum TLS dependencies

`scripts/build_cpp_quic.sh` fetches SHA-256-pinned `ngtcp2 1.18.0` and `nghttp3 1.12.0`
release sources over HTTPS (TLS 1.2+) and builds static libraries inside
`.build/Vendor/HajimiQUIC`. `ngtcp2` uses OpenSSL 3.5+'s external QUIC TLS
interface (`SSL_set_quic_tls_cbs`) rather than OpenSSL's internal QUIC engine so
RFC 9221 unreliable `DATAGRAM` frames remain natively supported. Both `ngtcp2`
and `nghttp3` use the MIT license; OpenSSL uses the Apache License 2.0.

OpenSSL 3.5+ static headers/libraries are supplied via `HAJIMI_OPENSSL_ROOT`
(default `/usr/local/opt/openssl@3` or `/opt/homebrew/opt/openssl@3`; when
absent, `scripts/build_native_core.sh` builds SHA-256-verified `OpenSSL 3.5.9 LTS`
inside `.build/Vendor/OpenSSL`). Nothing is installed into host system directories.

 Frontier standards enabled in `Sources/HajimiProtocolsCXX/QUICTransport.cpp`,
`QUICProtocols.cpp`, and `TrustTunnelProtocol.cpp`:
- **Post-Quantum Hybrid TLS 1.3 (RFC 10024 / NIST FIPS 203)**: Prioritizes
  `X25519MLKEM768` (`0x11EC`) via OpenSSL 3.5+ (`pqc = auto | true | false`) with
  automatic fallback to `X25519:P-256:P-384`.
- **QUIC Version 2 & Compatible Version Negotiation (RFC 9369 & RFC 9368)**:
  Advertises `{QUIC v2 (0x6b3343cf), QUIC v1 (0x00000001)}` in `preferred_versions`
  by default (`quic-version = auto | 1 | 2`) and enables **RFC 9287**
  `grease_quic_bit = 1`.
- **Kernel Unfragmented UDP & DPLPMTUD (RFC 9000 §14 & RFC 8899)**: Sets
  `IP_DONTFRAG` / `IPV6_DONTFRAG` (`IP_PMTUDISC_DO` on Linux) so oversized UDP
  packets surface `EMSGSIZE` directly to the C++ DPLPMTUD state machine instead
  of silently IP-fragmenting.
- **HTTP/3 & MASQUE (`nghttp3`)**: Hysteria v2 and TrustTunnel QUIC enforce
  RFC 9114 §7.2 control-frame restrictions, skip unknown/GREASE frames per
  §7.2.8, and transport UDP over RFC 9221 `DATAGRAM` or RFC 9298 `connect-udp`
  RFC 9297 capsules.

macOS system trust is evaluated with the `Security.framework` / `CoreFoundation`
C APIs unless an explicit node `ca` bundle is configured, and certificate
verification is skipped only when `skip-cert-verify` is explicitly set.

Run `HAJIMI_SANITIZE=1 sh scripts/test_cpp_quic.sh` for loopback-only `aioquic`
interoperability checks.

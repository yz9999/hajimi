#!/bin/sh
# Live, loopback-only independent QUIC/TLS interoperability (no Go).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$ROOT/.build/QUICInterop"
DEFAULT_SSL=/usr/local/opt/openssl@3
if [ -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]; then DEFAULT_SSL=/opt/homebrew/opt/openssl@3; fi
SSL=${HAJIMI_OPENSSL_ROOT:-$DEFAULT_SSL}
QUIC="$ROOT/.build/Vendor/HajimiQUIC"
PORT=${HAJIMI_QUIC_TEST_PORT:-25440}
mkdir -p "$BUILD"
if [ ! -f "$QUIC/lib/libngtcp2_crypto_ossl.a" ]; then sh "$ROOT/scripts/build_cpp_quic.sh"; fi
if [ ! -x "$BUILD/bin/python" ]; then python3 -m venv "$BUILD"; fi
if ! "$BUILD/bin/python" -c 'import aioquic' >/dev/null 2>&1; then
    "$BUILD/bin/pip" install --only-binary=:all: \
        'cryptography==44.0.3' 'pyopenssl==25.1.0' 'service-identity==24.2.0' 'aioquic==1.3.0'
fi
FLAGS=""
if [ "${HAJIMI_SANITIZE:-0}" = 1 ]; then FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"; fi
if [ "${HAJIMI_QUIC_SKIP_BUILD:-0}" != 1 ]; then
    OBJ="$BUILD/obj-${HAJIMI_SANITIZE:-0}"
    mkdir -p "$OBJ"
    for SOURCE in "$ROOT/NativeTests/QUICInteropClient.cpp" \
        "$ROOT/Sources/HajimiProtocolsCXX/QUICTransport.cpp" \
        "$ROOT/Sources/HajimiProtocolsCXX/QUICProtocols.cpp" \
        "$ROOT/Sources/HajimiProtocolsCXX/Runtime.cpp" \
        "$ROOT/Sources/HajimiProtocolsCXX/Crypto.cpp" \
        "$ROOT/Sources/HajimiProtocolsCXX/BLAKE3.cpp" \
        "$ROOT/Sources/HajimiProtocolCXX/ProtocolCodec.cpp"; do
        NAME=$(basename "$SOURCE" .cpp)
        OBJECT="$OBJ/$NAME.o"
        REBUILD=0
        if [ ! -f "$OBJECT" ] || [ "$SOURCE" -nt "$OBJECT" ]; then REBUILD=1; fi
        for HEADER in "$ROOT/Sources/HajimiProtocolsCXX/Runtime.hpp" \
            "$ROOT/Sources/HajimiProtocolsCXX/Crypto.hpp" "$ROOT/Sources/HajimiProtocolsCXX/QUICTransport.hpp" \
            "$ROOT/Sources/HajimiProtocolsCXX/BLAKE3.hpp" "$ROOT/Sources/HajimiProtocolCXX/include/HajimiProtocolCXX.h"; do
            if [ "$HEADER" -nt "$OBJECT" ]; then REBUILD=1; fi
        done
        if [ "$REBUILD" = 1 ]; then
            # shellcheck disable=SC2086
            clang++ -std=c++17 -O1 -g $FLAGS -DHAJIMI_QUIC_DIAGNOSTICS -Wall -Wextra -Werror \
                -I "$SSL/include" -I "$QUIC/include" -I "$ROOT/Sources/HajimiProtocolCXX/include" \
                -c "$SOURCE" -o "$OBJECT"
        fi
    done
    # shellcheck disable=SC2086
    clang++ -Wl,-dead_strip $FLAGS "$OBJ"/*.o \
        "$QUIC/lib/libngtcp2_crypto_ossl.a" "$QUIC/lib/libngtcp2.a" "$QUIC/lib/libnghttp3.a" \
        "$SSL/lib/libssl.a" "$SSL/lib/libcrypto.a" \
        -framework Security -framework CoreFoundation -o "$BUILD/quic-check"
fi
"$BUILD/bin/python" "$ROOT/NativeTests/quic_fixture_test.py"
"$SSL/bin/openssl" req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' \
    -keyout "$BUILD/server-key.pem" -out "$BUILD/server-cert.pem" >/dev/null 2>&1
TRACE=""
if [ "${HAJIMI_QUIC_TEST_TRACE:-0}" = 1 ]; then TRACE="--trace"; fi
# shellcheck disable=SC2086
"$BUILD/bin/python" "$ROOT/NativeTests/quic_interop_server.py" $TRACE \
    --certificate "$BUILD/server-cert.pem" --private-key "$BUILD/server-key.pem" \
    --base-port "$PORT" >"$BUILD/server.log" 2>&1 &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true; wait "$SERVER" 2>/dev/null || true' EXIT INT TERM
# A bounded readiness poll (10 seconds); this never touches system routing.
ATTEMPT=0
while [ "$ATTEMPT" -lt 40 ]; do
    if rg -q QUIC_INTEROP_READY "$BUILD/server.log"; then break; fi
    if ! kill -0 "$SERVER" 2>/dev/null; then sed -n '1,80p' "$BUILD/server.log"; exit 1; fi
    sleep 0.25
    ATTEMPT=$((ATTEMPT + 1))
done
if ! rg -q QUIC_INTEROP_READY "$BUILD/server.log"; then echo "QUIC fixture not ready" >&2; exit 1; fi
"$BUILD/quic-check" hysteria "$PORT" "$BUILD/server-cert.pem"
"$BUILD/quic-check" hysteria2 "$((PORT + 1))" "$BUILD/server-cert.pem"
"$BUILD/quic-check" tuic "$((PORT + 2))" "$BUILD/server-cert.pem"
"$BUILD/quic-check" tuic "$((PORT + 2))" "$BUILD/server-cert.pem" quic
"$BUILD/quic-check" hysteria "$((PORT + 3))" "$BUILD/server-cert.pem" obfs
"$BUILD/quic-check" hysteria2 "$((PORT + 4))" "$BUILD/server-cert.pem" obfs
for PROTOCOL in hysteria hysteria2 tuic; do
    case "$PROTOCOL" in hysteria) OFFSET=0;; hysteria2) OFFSET=1;; tuic) OFFSET=2;; esac
    "$BUILD/quic-check" "$PROTOCOL" "$((PORT + OFFSET))" "$BUILD/server-cert.pem" bad-auth
    "$BUILD/quic-check" "$PROTOCOL" "$((PORT + OFFSET))" "$BUILD/server-cert.pem" cancel
    "$BUILD/quic-check" "$PROTOCOL" "$((PORT + OFFSET))" "$BUILD/server-cert.pem" cancel-ready
done
"$BUILD/quic-check" hysteria2 "$((PORT + 1))" "$BUILD/server-cert.pem" reject
"$BUILD/quic-check" hysteria2 "$((PORT + 1))" "$BUILD/server-cert.pem" system-reject
"$BUILD/quic-check" hysteria2 "$((PORT + 1))" "$BUILD/server-cert.pem" skip
echo "C++ QUIC loopback interoperability checks passed"

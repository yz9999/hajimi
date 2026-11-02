#!/bin/sh
# Isolated count/byte admission, cancellation and per-address bind regression.
# No server traffic, routing changes, application or Helper operations.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$ROOT/.build/QUICBoundary"
DEFAULT_SSL=/usr/local/opt/openssl@3
if [ -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]; then DEFAULT_SSL=/opt/homebrew/opt/openssl@3; fi
SSL=${HAJIMI_OPENSSL_ROOT:-$DEFAULT_SSL}
QUIC="$ROOT/.build/Vendor/HajimiQUIC"
FLAGS=""
if [ "${HAJIMI_SANITIZE:-0}" = 1 ]; then FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"; fi
OBJ="$BUILD/obj-${HAJIMI_SANITIZE:-0}"
mkdir -p "$OBJ"
for SOURCE in "$ROOT/NativeTests/QUICBoundaryChecks.cpp" \
    "$ROOT/Sources/HajimiProtocolsCXX/Runtime.cpp" \
    "$ROOT/Sources/HajimiProtocolsCXX/Crypto.cpp" \
    "$ROOT/Sources/HajimiProtocolsCXX/BLAKE3.cpp" \
    "$ROOT/Sources/HajimiProtocolCXX/ProtocolCodec.cpp"; do
    NAME=$(basename "$SOURCE" .cpp)
    OBJECT="$OBJ/$NAME.o"
    REBUILD=0
    if [ ! -f "$OBJECT" ] || [ "$SOURCE" -nt "$OBJECT" ] || [ "$ROOT/scripts/test_cpp_quic_boundaries.sh" -nt "$OBJECT" ]; then REBUILD=1; fi
    for HEADER in "$ROOT/Sources/HajimiProtocolsCXX/Runtime.hpp" \
        "$ROOT/Sources/HajimiProtocolsCXX/Crypto.hpp" "$ROOT/Sources/HajimiProtocolsCXX/QUICTransport.hpp" \
        "$ROOT/Sources/HajimiProtocolsCXX/BLAKE3.hpp" "$ROOT/Sources/HajimiProtocolCXX/include/HajimiProtocolCXX.h"; do
        if [ "$HEADER" -nt "$OBJECT" ]; then REBUILD=1; fi
    done
    if [ "$NAME" = QUICBoundaryChecks ] && [ "$ROOT/Sources/HajimiProtocolsCXX/QUICTransport.cpp" -nt "$OBJECT" ]; then REBUILD=1; fi
    if [ "$REBUILD" = 0 ]; then continue; fi
    # shellcheck disable=SC2086
    clang++ -std=c++17 -O1 -g $FLAGS -Wall -Wextra -Werror \
        -I "$SSL/include" -I "$QUIC/include" -I "$ROOT/Sources/HajimiProtocolCXX/include" \
        -c "$SOURCE" -o "$OBJECT"
done
# shellcheck disable=SC2086
clang++ -Wl,-dead_strip $FLAGS "$OBJ"/*.o \
    "$QUIC/lib/libngtcp2_crypto_ossl.a" "$QUIC/lib/libngtcp2.a" "$QUIC/lib/libnghttp3.a" \
    "$SSL/lib/libssl.a" "$SSL/lib/libcrypto.a" \
    -framework Security -framework CoreFoundation -o "$BUILD/quic-boundary-check-${HAJIMI_SANITIZE:-0}"
"$BUILD/quic-boundary-check-${HAJIMI_SANITIZE:-0}"

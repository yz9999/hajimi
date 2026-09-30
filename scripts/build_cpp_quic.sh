#!/bin/sh
# Reproducible, repository-local C QUIC/TLS dependencies. No package manager.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$ROOT/.build/Vendor/HajimiQUIC"
DEFAULT_SSL=/usr/local/opt/openssl@3
if [ -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]; then DEFAULT_SSL=/opt/homebrew/opt/openssl@3; fi
OPENSSL_ROOT=${HAJIMI_OPENSSL_ROOT:-$DEFAULT_SSL}
ARCHS=${HAJIMI_ARCHS:-$(uname -m)}
JOBS=${HAJIMI_BUILD_JOBS:-4}
mkdir -p "$BUILD/downloads" "$BUILD/src" "$BUILD/include" "$BUILD/lib"

fetch() {
    NAME=$1 VERSION=$2 HASH=$3
    ARCHIVE="$BUILD/downloads/$NAME-$VERSION.tar.xz"
    if [ ! -f "$ARCHIVE" ]; then
        curl --fail --location --retry 2 --max-time 120 \
            "https://github.com/ngtcp2/$NAME/releases/download/v$VERSION/$NAME-$VERSION.tar.xz" \
            -o "$ARCHIVE"
    fi
    ACTUAL=$(shasum -a 256 "$ARCHIVE" | cut -d ' ' -f 1)
    if [ "$ACTUAL" != "$HASH" ]; then
        echo "Checksum mismatch for $NAME-$VERSION; remove $ARCHIVE and retry" >&2
        exit 1
    fi
    if [ ! -d "$BUILD/src/$NAME-$VERSION" ]; then
        tar -xf "$ARCHIVE" -C "$BUILD/src"
    fi
}

fetch ngtcp2 1.18.0 aac91fbcb8af77216862cc1bf6e9ddcabfe42b4c373a438b7b1d36b763a4ac5f
fetch nghttp3 1.12.0 6ca1e523b7edd75c02502f2bcf961125c25577e29405479016589c5da48fc43d

for ARCH in $ARCHS; do
    case "$ARCH" in x86_64|arm64) ;; *) echo "Unsupported architecture: $ARCH" >&2; exit 1;; esac
    SSL_ROOT=$OPENSSL_ROOT
    if [ -d "$OPENSSL_ROOT/$ARCH" ]; then SSL_ROOT="$OPENSSL_ROOT/$ARCH"; fi
    if [ ! -f "$SSL_ROOT/lib/libssl.a" ] || [ ! -f "$SSL_ROOT/lib/libcrypto.a" ]; then
        echo "OpenSSL 3.5+ static archives required at $SSL_ROOT" >&2
        exit 1
    fi
    if ! rg -q SSL_set_quic_tls_cbs "$SSL_ROOT/include/openssl/ssl.h"; then
        echo "OpenSSL 3.5+ external QUIC TLS API required at $SSL_ROOT" >&2
        exit 1
    fi
    if ! lipo "$SSL_ROOT/lib/libssl.a" -verify_arch "$ARCH" >/dev/null 2>&1; then
        echo "OpenSSL archive lacks $ARCH; set HAJIMI_OPENSSL_ROOT to per-architecture static installs" >&2
        exit 1
    fi
    PREFIX="$BUILD/$ARCH"
    for NAME in ngtcp2 nghttp3; do
        case "$NAME" in ngtcp2) VERSION=1.18.0;; nghttp3) VERSION=1.12.0;; esac
        CMAKE_BUILD="$BUILD/build-$NAME-$ARCH"
        cmake -S "$BUILD/src/$NAME-$VERSION" -B "$CMAKE_BUILD" \
            -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
            -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 -DCMAKE_INSTALL_PREFIX="$PREFIX" \
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTING=OFF \
            -DENABLE_LIB_ONLY=ON -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF \
            -DENABLE_OPENSSL=ON -DENABLE_GNUTLS=OFF \
            -DENABLE_BORINGSSL=OFF -DENABLE_PICOTLS=OFF -DENABLE_WOLFSSL=OFF \
            -DOPENSSL_ROOT_DIR="$SSL_ROOT" -DOPENSSL_USE_STATIC_LIBS=TRUE
        cmake --build "$CMAKE_BUILD" --parallel "$JOBS"
        cmake --install "$CMAKE_BUILD"
    done
done

FIRST_ARCH=$(printf '%s\n' "$ARCHS" | awk '{print $1}')
# Preserve installed header timestamps so no-op vendor builds stay incremental.
cp -pR "$BUILD/$FIRST_ARCH/include/" "$BUILD/include/"
for NAME in ngtcp2 ngtcp2_crypto_ossl nghttp3; do
    for ARCH in $ARCHS; do
        FILE="$BUILD/$ARCH/lib/lib$NAME.a"
        if [ ! -f "$FILE" ]; then echo "Missing $FILE" >&2; exit 1; fi
    done
    # Paths are rooted under the workspace, which may contain spaces.
    set --
    for ARCH in $ARCHS; do set -- "$@" "$BUILD/$ARCH/lib/lib$NAME.a"; done
    lipo -create "$@" -output "$BUILD/lib/lib$NAME.a"
done
echo "Built C QUIC dependencies for $ARCHS at $BUILD"

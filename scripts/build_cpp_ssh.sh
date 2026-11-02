#!/bin/sh
# Build a locked libssh2 snapshot only inside this workspace. No package-manager
# installation, signing, helper installation, or network settings are involved.
set -eu
export LC_ALL=C
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE="$ROOT/.build/Vendor/HajimiSSH"
COMMIT=2e1717456b8dd4c980e8e48d6dbfec524c2e62d1
HASH=cffa24d90bf14a26154b1124e0dcdaab1fe4038000a8f5a127acb77631a8ebe5
ARCHIVE="$BASE/downloads/libssh2-$COMMIT.tar.gz"
SOURCE="$BASE/src/libssh2-$COMMIT"
DEFAULT_SSL=/usr/local/opt/openssl@3
if [ -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]; then DEFAULT_SSL=/opt/homebrew/opt/openssl@3; fi
OPENSSL_ROOT=${HAJIMI_OPENSSL_ROOT:-${OPENSSL_ROOT_DIR:-$DEFAULT_SSL}}
ARCHS=${HAJIMI_ARCHS:-$(uname -m)}
JOBS=${HAJIMI_BUILD_JOBS:-${HJ_BUILD_JOBS:-4}}
mkdir -p "$BASE/downloads" "$BASE/src" "$BASE/include" "$BASE/lib"
if [ ! -f "$ARCHIVE" ]; then
    curl --fail --location --connect-timeout 10 --max-time 120 \
        "https://codeload.github.com/libssh2/libssh2/tar.gz/$COMMIT" -o "$ARCHIVE"
fi
ACTUAL=$(/usr/bin/shasum -a 256 "$ARCHIVE" | /usr/bin/awk '{print $1}')
if [ "$ACTUAL" != "$HASH" ]; then
    printf '%s\n' "libssh2 source checksum mismatch; refusing to extract or compile." >&2
    exit 1
fi
if [ ! -d "$SOURCE" ]; then tar -xzf "$ARCHIVE" -C "$BASE/src"; fi

# This 2026-09-14 pinned upstream snapshot contains security fixes absent from
# the unpatched 1.11.1 release. Its exact source digest is locked above.
for ARCH in $ARCHS; do
    case "$ARCH" in x86_64|arm64) ;; *) printf '%s\n' "Unsupported architecture: $ARCH" >&2; exit 1;; esac
    SSL_ROOT=$OPENSSL_ROOT
    if [ -d "$OPENSSL_ROOT/$ARCH" ]; then SSL_ROOT="$OPENSSL_ROOT/$ARCH"; fi
    if [ ! -f "$SSL_ROOT/include/openssl/ssl.h" ] || [ ! -f "$SSL_ROOT/lib/libcrypto.a" ]; then
        printf '%s\n' "Set HAJIMI_OPENSSL_ROOT to an existing OpenSSL static install (or per-architecture installs)." >&2
        exit 1
    fi
    if ! lipo "$SSL_ROOT/lib/libcrypto.a" -verify_arch "$ARCH" >/dev/null 2>&1; then
        printf '%s\n' "OpenSSL archive lacks $ARCH; use per-architecture HAJIMI_OPENSSL_ROOT/$ARCH installs." >&2
        exit 1
    fi
    PREFIX="$BASE/$ARCH"
    CMAKE_BUILD="$BASE/build-$ARCH"
    cmake -S "$SOURCE" -B "$CMAKE_BUILD" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCRYPTO_BACKEND=OpenSSL -DOPENSSL_ROOT_DIR="$SSL_ROOT" \
        -DOPENSSL_USE_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON \
        -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DLIBSSH2_BUILD_DOCS=OFF \
        -DPICKY_COMPILER=OFF -DENABLE_ZLIB_COMPRESSION=OFF
    cmake --build "$CMAKE_BUILD" --parallel "$JOBS"
    cmake --install "$CMAKE_BUILD"
done

FIRST_ARCH=$(printf '%s\n' "$ARCHS" | awk '{print $1}')
# Preserve installed header timestamps so no-op vendor builds stay incremental.
cp -pR "$BASE/$FIRST_ARCH/include/" "$BASE/include/"
set --
for ARCH in $ARCHS; do
    FILE="$BASE/$ARCH/lib/libssh2.a"
    if [ ! -f "$FILE" ]; then printf '%s\n' "Missing native SSH archive for $ARCH" >&2; exit 1; fi
    set -- "$@" "$FILE"
done
TEMPORARY="$BASE/lib/.libssh2.a.$$.tmp"
lipo -create "$@" -output "$TEMPORARY"
mv -f "$TEMPORARY" "$BASE/lib/libssh2.a"
printf '%s\n' "Built native SSH for $ARCHS: $BASE/include, $BASE/lib/libssh2.a"

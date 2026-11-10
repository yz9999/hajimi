#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export MACOSX_DEPLOYMENT_TARGET=13.0
export HAJIMI_ARCHS=${HAJIMI_ARCHS:-$(uname -m)}
export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/CMake.app/Contents/bin:$ROOT/.build/Vendor/CMake/CMake.app/Contents/bin:${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"

ensure_cmake() {
    if command -v cmake >/dev/null 2>&1; then
        return 0
    fi
    if command -v brew >/dev/null 2>&1; then
        echo "Installing cmake via Homebrew..."
        brew install cmake && return 0
    fi
    CMAKE_DIR="$ROOT/.build/Vendor/CMake"
    CMAKE_VER="3.31.6"
    CMAKE_TAR="$CMAKE_DIR/cmake-$CMAKE_VER-macos-universal.tar.gz"
    mkdir -p "$CMAKE_DIR"
    if [ ! -x "$CMAKE_DIR/CMake.app/Contents/bin/cmake" ]; then
        echo "Downloading portable CMake $CMAKE_VER..."
        curl --fail --location --retry 2 --max-time 180 \
            "https://github.com/Kitware/CMake/releases/download/v$CMAKE_VER/cmake-$CMAKE_VER-macos-universal.tar.gz" \
            -o "$CMAKE_TAR"
        tar -xzf "$CMAKE_TAR" -C "$CMAKE_DIR" --strip-components=1
    fi
    export PATH="$CMAKE_DIR/CMake.app/Contents/bin:$PATH"
}

check_openssl_valid() {
    CANDIDATE=${1:-}
    if [ -z "$CANDIDATE" ] || [ ! -f "$CANDIDATE/include/openssl/ssl.h" ] || [ ! -f "$CANDIDATE/include/openssl/core_names.h" ]; then
        return 1
    fi
    if ! grep -q SSL_set_quic_tls_cbs "$CANDIDATE/include/openssl/ssl.h"; then
        return 1
    fi
    for ARCH in $HAJIMI_ARCHS; do
        SSL_ARCH_ROOT=$CANDIDATE
        if [ -d "$CANDIDATE/$ARCH" ]; then SSL_ARCH_ROOT="$CANDIDATE/$ARCH"; fi
        if [ ! -f "$SSL_ARCH_ROOT/lib/libssl.a" ] || [ ! -f "$SSL_ARCH_ROOT/lib/libcrypto.a" ]; then
            return 1
        fi
        if ! lipo "$SSL_ARCH_ROOT/lib/libssl.a" -verify_arch "$ARCH" >/dev/null 2>&1; then
            return 1
        fi
    done
    return 0
}

build_vendor_openssl() {
    VENDOR_SSL="$ROOT/.build/Vendor/OpenSSL"
    if check_openssl_valid "$VENDOR_SSL"; then
        HAJIMI_OPENSSL_ROOT="$VENDOR_SSL"
        export HAJIMI_OPENSSL_ROOT
        return 0
    fi
    OPENSSL_VER="3.5.0"
    mkdir -p "$VENDOR_SSL/downloads" "$VENDOR_SSL/src" "$VENDOR_SSL/include" "$VENDOR_SSL/lib"
    ARCHIVE="$VENDOR_SSL/downloads/openssl-$OPENSSL_VER.tar.gz"
    if [ ! -f "$ARCHIVE" ]; then
        echo "Downloading OpenSSL $OPENSSL_VER source for local static build (macOS 13.0+)..."
        curl --fail --location --retry 2 --max-time 180 \
            "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz" \
            -o "$ARCHIVE"
    fi
    JOBS=${HAJIMI_BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}
    for ARCH in $HAJIMI_ARCHS; do
        case "$ARCH" in
            x86_64) TARGET="darwin64-x86_64-cc" ;;
            arm64)  TARGET="darwin64-arm64-cc" ;;
            *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
        esac
        BUILD_SUB="$VENDOR_SSL/build-$ARCH"
        PREFIX_SUB="$VENDOR_SSL/$ARCH"
        rm -rf "$BUILD_SUB"
        mkdir -p "$BUILD_SUB"
        tar -xzf "$ARCHIVE" -C "$BUILD_SUB" --strip-components=1
        (
            cd "$BUILD_SUB"
            ./Configure "$TARGET" \
                no-shared no-module no-dso no-tests no-docs \
                "-mmacosx-version-min=13.0" \
                --prefix="$PREFIX_SUB" \
                --openssldir="$PREFIX_SUB/ssl"
            make -j"$JOBS" build_libs
            mkdir -p "$PREFIX_SUB/lib" "$PREFIX_SUB/include"
            cp -f libssl.a libcrypto.a "$PREFIX_SUB/lib/"
            cp -pR include/openssl "$PREFIX_SUB/include/"
        )
    done
    FIRST_ARCH=$(printf '%s\n' "$HAJIMI_ARCHS" | awk '{print $1}')
    rm -rf "$VENDOR_SSL/include/openssl"
    cp -pR "$VENDOR_SSL/$FIRST_ARCH/include/openssl" "$VENDOR_SSL/include/"
    for LIB in libssl.a libcrypto.a; do
        set --
        for ARCH in $HAJIMI_ARCHS; do
            set -- "$@" "$VENDOR_SSL/$ARCH/lib/$LIB"
        done
        lipo -create "$@" -output "$VENDOR_SSL/lib/$LIB"
    done
    HAJIMI_OPENSSL_ROOT="$VENDOR_SSL"
    export HAJIMI_OPENSSL_ROOT
}

ensure_cmake

if ! check_openssl_valid "${HAJIMI_OPENSSL_ROOT:-}"; then
    HAJIMI_OPENSSL_ROOT=""
    for CANDIDATE in "/usr/local/opt/openssl@3" "/opt/homebrew/opt/openssl@3" "$ROOT/.build/Vendor/OpenSSL"; do
        if check_openssl_valid "$CANDIDATE"; then
            HAJIMI_OPENSSL_ROOT="$CANDIDATE"
            break
        fi
    done
fi

if ! check_openssl_valid "${HAJIMI_OPENSSL_ROOT:-}"; then
    if command -v brew >/dev/null 2>&1; then
        echo "Checking Homebrew openssl@3 (requires OpenSSL 3.5+)..."
        brew install openssl@3 || true
        BREW_SSL=$(brew --prefix openssl@3 2>/dev/null || true)
        if check_openssl_valid "$BREW_SSL"; then
            HAJIMI_OPENSSL_ROOT="$BREW_SSL"
        fi
    fi
fi

if ! check_openssl_valid "${HAJIMI_OPENSSL_ROOT:-}"; then
    build_vendor_openssl
fi

export HAJIMI_OPENSSL_ROOT
sh "$ROOT/scripts/build_cpp_quic.sh"
sh "$ROOT/scripts/build_cpp_ssh.sh"

# Stage all headers and OpenSSL static libraries into local workspace paths so
# SwiftPM finds them reliably even when the project directory contains spaces.
VENDOR_SSL="$ROOT/.build/Vendor/OpenSSL"
mkdir -p "$VENDOR_SSL/include" "$VENDOR_SSL/lib"
if [ "$HAJIMI_OPENSSL_ROOT" != "$VENDOR_SSL" ]; then
    rm -rf "$VENDOR_SSL/include/openssl"
    cp -pR "$HAJIMI_OPENSSL_ROOT/include/openssl" "$VENDOR_SSL/include/"
    for LIB in libssl.a libcrypto.a; do
        if [ -f "$HAJIMI_OPENSSL_ROOT/lib/$LIB" ]; then
            cp -f "$HAJIMI_OPENSSL_ROOT/lib/$LIB" "$VENDOR_SSL/lib/$LIB"
        else
            set --
            for ARCH in $HAJIMI_ARCHS; do
                set -- "$@" "$HAJIMI_OPENSSL_ROOT/$ARCH/lib/$LIB"
            done
            lipo -create "$@" -output "$VENDOR_SSL/lib/$LIB"
        fi
    done
fi

VENDOR_INC="$ROOT/Sources/HajimiProtocolsCXX/VendorInclude"
mkdir -p "$VENDOR_INC"
rm -rf "$VENDOR_INC/openssl" "$VENDOR_INC/ngtcp2" "$VENDOR_INC/nghttp3"
cp -pR "$VENDOR_SSL/include/openssl" "$VENDOR_INC/"
cp -pR "$ROOT/.build/Vendor/HajimiQUIC/include/ngtcp2" "$VENDOR_INC/"
cp -pR "$ROOT/.build/Vendor/HajimiQUIC/include/nghttp3" "$VENDOR_INC/"
cp -pR "$ROOT/.build/Vendor/HajimiSSH/include/"* "$VENDOR_INC/"

echo "Built native C++ protocol dependencies ($HAJIMI_ARCHS) using OpenSSL at $HAJIMI_OPENSSL_ROOT"

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
    CMAKE_TAR_NAME="cmake-$CMAKE_VER-macos-universal.tar.gz"
    CMAKE_TAR="$CMAKE_DIR/$CMAKE_TAR_NAME"
    CMAKE_SHA_FILE="$CMAKE_DIR/cmake-$CMAKE_VER-SHA-256.txt"
    mkdir -p "$CMAKE_DIR"
    if [ ! -x "$CMAKE_DIR/CMake.app/Contents/bin/cmake" ]; then
        echo "Downloading portable CMake $CMAKE_VER and official SHA-256 manifest..."
        curl --proto '=https' --tlsv1.2 --fail --location --retry 2 --max-time 180 \
            "https://github.com/Kitware/CMake/releases/download/v$CMAKE_VER/cmake-$CMAKE_VER-SHA-256.txt" \
            -o "$CMAKE_SHA_FILE"
        EXPECTED_CMAKE_SHA=$(/usr/bin/awk -v f="$CMAKE_TAR_NAME" '$2 == f || $2 == ("*" f) { print $1; exit }' "$CMAKE_SHA_FILE")
        case "$EXPECTED_CMAKE_SHA" in
            [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
            *) echo "Failed to parse valid SHA-256 for $CMAKE_TAR_NAME" >&2; exit 1 ;;
        esac
        if [ "${#EXPECTED_CMAKE_SHA}" -ne 64 ]; then
            echo "Invalid SHA-256 digest length for $CMAKE_TAR_NAME" >&2
            exit 1
        fi
        curl --proto '=https' --tlsv1.2 --fail --location --retry 2 --max-time 180 \
            "https://github.com/Kitware/CMake/releases/download/v$CMAKE_VER/$CMAKE_TAR_NAME" \
            -o "$CMAKE_TAR"
        ACTUAL_CMAKE_SHA=$(/usr/bin/shasum -a 256 "$CMAKE_TAR" | /usr/bin/awk '{print $1}')
        if [ "$ACTUAL_CMAKE_SHA" != "$EXPECTED_CMAKE_SHA" ]; then
            echo "CMake SHA-256 mismatch (expected $EXPECTED_CMAKE_SHA, got $ACTUAL_CMAKE_SHA); refusing extraction." >&2
            rm -f "$CMAKE_TAR"
            exit 1
        fi
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
    # OpenSSL 3.5 LTS latest security patch release (EOL 2030-04-08, native ML-KEM / QUIC TLS API)
    OPENSSL_VER="3.5.9"
    OPENSSL_SHA256="603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
    mkdir -p "$VENDOR_SSL/downloads" "$VENDOR_SSL/src" "$VENDOR_SSL/include" "$VENDOR_SSL/lib"
    ARCHIVE="$VENDOR_SSL/downloads/openssl-$OPENSSL_VER.tar.gz"
    if [ ! -f "$ARCHIVE" ]; then
        echo "Downloading OpenSSL $OPENSSL_VER LTS source for local static build (macOS 13.0+)..."
        curl --proto '=https' --tlsv1.2 --fail --location --retry 2 --max-time 180 \
            "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz" \
            -o "$ARCHIVE"
    fi
    ACTUAL_SSL_SHA=$(/usr/bin/shasum -a 256 "$ARCHIVE" | /usr/bin/awk '{print $1}')
    if [ "$ACTUAL_SSL_SHA" != "$OPENSSL_SHA256" ]; then
        echo "OpenSSL $OPENSSL_VER SHA-256 mismatch (expected $OPENSSL_SHA256, got $ACTUAL_SSL_SHA); remove $ARCHIVE and retry." >&2
        exit 1
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

REQUESTED_OPENSSL_ROOT="${HAJIMI_OPENSSL_ROOT:-}"
if [ "$REQUESTED_OPENSSL_ROOT" = "$ROOT/.build/Vendor/OpenSSL" ]; then
    build_vendor_openssl
else
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
            echo "Checking/installing openssl@3 via Homebrew..."
            brew install openssl@3 >/dev/null 2>&1 || true
            BREW_SSL=$(brew --prefix openssl@3 2>/dev/null || true)
            if check_openssl_valid "$BREW_SSL"; then
                HAJIMI_OPENSSL_ROOT="$BREW_SSL"
            fi
        fi
    fi

    if ! check_openssl_valid "${HAJIMI_OPENSSL_ROOT:-}"; then
        build_vendor_openssl
    fi
fi

export HAJIMI_OPENSSL_ROOT
echo "Using OpenSSL 3.5+ from: $HAJIMI_OPENSSL_ROOT"

sh "$ROOT/scripts/build_cpp_quic.sh"
sh "$ROOT/scripts/build_cpp_ssh.sh"

BUILD_FLAGS="-c release"
for ARCH in $HAJIMI_ARCHS; do
    BUILD_FLAGS="$BUILD_FLAGS --arch $ARCH"
done

echo "Building Hajimi & HajimiHelper ($HAJIMI_ARCHS)..."
# shellcheck disable=SC2086
swift build $BUILD_FLAGS --product Hajimi
# shellcheck disable=SC2086
swift build $BUILD_FLAGS --product HajimiHelper
echo "Native core build completed successfully."

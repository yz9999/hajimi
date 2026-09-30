#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export HAJIMI_ARCHS=${HAJIMI_ARCHS:-$(uname -m)}
if [ -z "${HAJIMI_OPENSSL_ROOT:-}" ]; then
    if [ -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]; then
        HAJIMI_OPENSSL_ROOT=/opt/homebrew/opt/openssl@3
    else
        HAJIMI_OPENSSL_ROOT=/usr/local/opt/openssl@3
    fi
    export HAJIMI_OPENSSL_ROOT
fi
# Only pinned C libraries are built under .build/Vendor. No Go, global package
# installation, helper installation or system-network changes are performed.
sh "$ROOT/scripts/build_cpp_quic.sh"
sh "$ROOT/scripts/build_cpp_ssh.sh"
echo "Built native C++ protocol dependencies ($HAJIMI_ARCHS)"

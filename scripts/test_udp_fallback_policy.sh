#!/bin/bash
# Source-aware QUIC/UDP admission against already-built SwiftPM objects.
# This script never invokes SwiftPM or creates an IP socket/listener. The
# programmatic fixture sends nothing and isolates Foundation preferences.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONFIGURATION=debug
WORK_DIR=

usage() {
    printf '%s\n' \
        'Usage: scripts/test_udp_fallback_policy.sh [--configuration debug|release] [--work-dir DIRECTORY]' \
        'Link and run the memory-only policy matrix after the requested build has completed.' \
        'No SwiftPM build is started; missing or stale build products fail closed.' \
        'Binary, compile log and result log are retained in DIRECTORY (a private temp directory by default).'
}

fail() {
    printf 'UDP fallback policy fixture: %s\n' "$*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --configuration)
            [[ $# -ge 2 ]] || fail '--configuration requires debug or release'
            CONFIGURATION=$2
            shift 2
            ;;
        --work-dir)
            [[ $# -ge 2 && -n "$2" ]] || fail '--work-dir requires a directory'
            WORK_DIR=$2
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unexpected argument: $1" ;;
    esac
done
case "$CONFIGURATION" in debug|release) ;; *) fail '--configuration must be debug or release' ;; esac
[[ $(uname -s) == Darwin ]] || fail 'the prebuilt Core fixture requires macOS'
ARCH=$(uname -m)
case "$ARCH" in arm64|x86_64) ;; *) fail "unsupported architecture: $ARCH" ;; esac

BUILD="$ROOT/.build/$ARCH-apple-macosx/$CONFIGURATION"
MODULE="$BUILD/HajimiCore.swiftmodule"
if [[ ! -f "$MODULE" ]]; then MODULE="$BUILD/Modules/HajimiCore.swiftmodule"; fi
[[ -f "$MODULE" ]] || fail "missing $CONFIGURATION HajimiCore module; complete the external build first"
for source in ProxyEngine.swift DNSQueryModuleAdapter.swift NetworkPerformanceDiagnostics.swift; do
    [[ ! "$ROOT/Sources/HajimiCore/$source" -nt "$MODULE" ]] \
        || fail "the $CONFIGURATION Core module is older than $source; complete the external build first"
done
DNS_MODULE="$BUILD/HajimiDNS.swiftmodule"
if [[ ! -f "$DNS_MODULE" ]]; then DNS_MODULE="$BUILD/Modules/HajimiDNS.swiftmodule"; fi
[[ -f "$DNS_MODULE" ]] || fail "missing $CONFIGURATION DNS module; complete the external build first"
for source in "$ROOT"/Sources/HajimiDNS/*.swift; do
    [[ ! "$source" -nt "$DNS_MODULE" ]] \
        || fail "the $CONFIGURATION DNS module is older than ${source##*/}; complete the external build first"
done
ROUTING_MODULE="$BUILD/HajimiRouting.swiftmodule"
if [[ ! -f "$ROUTING_MODULE" ]]; then ROUTING_MODULE="$BUILD/Modules/HajimiRouting.swiftmodule"; fi
[[ -f "$ROUTING_MODULE" ]] || fail "missing $CONFIGURATION routing module; complete the external build first"
for source in "$ROOT"/Sources/HajimiRouting/*.swift; do
    [[ ! "$source" -nt "$ROUTING_MODULE" ]] \
        || fail "the $CONFIGURATION routing module is older than ${source##*/}; complete the external build first"
done

DEFAULT_SSL=/usr/local/opt/openssl@3
if [[ -f /opt/homebrew/opt/openssl@3/include/openssl/ssl.h ]]; then DEFAULT_SSL=/opt/homebrew/opt/openssl@3; fi
SSL=${HAJIMI_OPENSSL_ROOT:-$DEFAULT_SSL}
if [[ -d "$SSL/$ARCH" ]]; then SSL="$SSL/$ARCH"; fi
LIBRARIES=(
    "$ROOT/.build/Vendor/HajimiQUIC/lib/libngtcp2_crypto_ossl.a"
    "$ROOT/.build/Vendor/HajimiQUIC/lib/libngtcp2.a"
    "$ROOT/.build/Vendor/HajimiQUIC/lib/libnghttp3.a"
    "$ROOT/.build/Vendor/HajimiSSH/lib/libssh2.a"
    "$SSL/lib/libssl.a"
    "$SSL/lib/libcrypto.a"
)
for library in "${LIBRARIES[@]}"; do [[ -f "$library" ]] || fail "missing prebuilt library: $library"; done

TARGETS=(HajimiCore HajimiDNS HajimiRouting HajimiCXXProtocolBridge HajimiProtocolsCXX HajimiProtocolCXX HajimiProxyRuntime HajimiRoutingCXX)
FLAGS=(-I "$BUILD")
if [[ -d "$BUILD/Modules" ]]; then FLAGS+=(-I "$BUILD/Modules"); fi
OBJECTS=()
shopt -s nullglob
for target in "${TARGETS[@]}"; do
    if [[ "$target" == HajimiCore || "$target" == HajimiDNS || "$target" == HajimiRouting ]]; then
        selectedObjects=$(python3 "$ROOT/scripts/dns_test_sources.py" --objects "$BUILD" "$target") \
            || fail "invalid $CONFIGURATION Swift object plan for $target"
        targetObjects=()
        while IFS= read -r object; do
            if [[ -n "$object" ]]; then targetObjects+=("$object"); fi
        done <<< "$selectedObjects"
    else
        targetObjects=("$BUILD/$target.build/"*.o)
    fi
    [[ ${#targetObjects[@]} -gt 0 ]] || fail "missing $CONFIGURATION objects for $target; complete the external build first"
    OBJECTS+=("${targetObjects[@]}")
    if [[ "$target" != HajimiCore && "$target" != HajimiDNS && "$target" != HajimiRouting ]]; then
        moduleMap="$BUILD/$target.build/module.modulemap"
        [[ -f "$moduleMap" ]] || fail "missing prebuilt module map for $target"
        FLAGS+=(-I "$ROOT/Sources/$target/include" -Xcc "-fmodule-map-file=$moduleMap")
    fi
done

umask 077
if [[ -z "$WORK_DIR" ]]; then WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hajimi-udp-fallback.XXXXXX"); fi
mkdir -p -- "$WORK_DIR"
WORK_DIR=$(CDPATH= cd -- "$WORK_DIR" && pwd)
PRIVATE_HOME=$(mktemp -d "$WORK_DIR/udp-fallback-home.XXXXXX")
BINARY="$WORK_DIR/udp-fallback-policy-$CONFIGURATION"
COMPILE_LOG="$WORK_DIR/udp-fallback-policy-$CONFIGURATION-compile.log"
RUN_LOG="$WORK_DIR/udp-fallback-policy-$CONFIGURATION.log"

if ! xcrun swiftc -O -parse-as-library \
    -D HAJIMI_SOURCE_AWARE_UDP_GATE "${FLAGS[@]}" \
    "$ROOT/SmokeTests/QUICFallbackPolicyMain.swift" "${OBJECTS[@]}" "${LIBRARIES[@]}" \
    -lc++ -framework Foundation -framework Network -framework Security -framework CoreFoundation \
    -o "$BINARY" >"$COMPILE_LOG" 2>&1; then
    sed -n '1,100p' "$COMPILE_LOG" >&2
    fail "link failed; full log retained at $COMPILE_LOG"
fi
if ! CFFIXED_USER_HOME="$PRIVATE_HOME" LANG=C LC_ALL=C "$BINARY" >"$RUN_LOG" 2>&1; then
    sed -n '1,100p' "$RUN_LOG" >&2
    fail "policy matrix failed; full log retained at $RUN_LOG"
fi
sed -n '1,40p' "$RUN_LOG"
printf 'UDP fallback policy fixture artifacts: %s\n' "$WORK_DIR"

#!/bin/bash
# Link only already-built Core/native objects. The raw transport is a bounded
# memory black hole; only the production one-shot TLS loopback bridge listens.
# No SwiftPM, GUI, Helper, user profile, public DNS or external address is used.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONFIGURATION=debug
BUILD_DIR_OVERRIDE=
WORK_DIR=
EXPECT_GAP=false

usage() {
    printf '%s\n' \
        'Usage: bash scripts/test_dns_transport_cancellation.sh [--configuration debug|release] [--build-dir DIRECTORY] [--work-dir DIRECTORY] [--expect-current-gap]' \
        'After an external build, run 128 cancellation/acknowledgment/capacity cases against nested TLS.' \
        'The explicit before-fix flag uses the legacy noncancelable dialer and allows older prebuilt Core objects.'
}
fail() { printf 'Encrypted DNS transport cancellation fixture: %s\n' "$*" >&2; exit 1; }

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
        --build-dir)
            [[ $# -ge 2 && -n "$2" ]] || fail '--build-dir requires a directory'
            BUILD_DIR_OVERRIDE=$2
            shift 2
            ;;
        --expect-current-gap) EXPECT_GAP=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unexpected argument: $1" ;;
    esac
done
case "$CONFIGURATION" in debug|release) ;; *) fail '--configuration must be debug or release' ;; esac
[[ $(uname -s) == Darwin ]] || fail 'the prebuilt fixture requires macOS'
ARCH=$(uname -m)
case "$ARCH" in arm64|x86_64) ;; *) fail "unsupported architecture: $ARCH" ;; esac

BUILD="$ROOT/.build/$ARCH-apple-macosx/$CONFIGURATION"
if [[ -n "$BUILD_DIR_OVERRIDE" ]]; then
    [[ -d "$BUILD_DIR_OVERRIDE" ]] || fail 'the requested build directory does not exist'
    BUILD=$(CDPATH= cd -- "$BUILD_DIR_OVERRIDE" && pwd)
fi
MODULE="$BUILD/HajimiCore.swiftmodule"
if [[ ! -f "$MODULE" ]]; then MODULE="$BUILD/Modules/HajimiCore.swiftmodule"; fi
[[ -f "$MODULE" ]] || fail "missing $CONFIGURATION Core module; complete the external build first"
if [[ "$EXPECT_GAP" != true ]]; then
    for source in Profile.swift CompiledRoutingRules.swift NativeOutbound.swift EncryptedDNS.swift DNSQueryModuleAdapter.swift NetworkPerformanceDiagnostics.swift; do
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
fi

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

TARGETS=(HajimiCore HajimiCXXProtocolBridge HajimiProtocolsCXX HajimiProtocolCXX HajimiProxyRuntime HajimiRoutingCXX)
if [[ "$EXPECT_GAP" != true ]]; then TARGETS+=(HajimiDNS HajimiRouting); fi
FLAGS=(-I "$BUILD")
if [[ -d "$BUILD/Modules" ]]; then FLAGS+=(-I "$BUILD/Modules"); fi
if [[ "$EXPECT_GAP" != true ]]; then FLAGS+=(-D HAJIMI_CANCELLABLE_TLS_TRANSPORT); fi
OBJECTS=()
shopt -s nullglob
for target in "${TARGETS[@]}"; do
    if [[ "$target" == HajimiCore || "$target" == HajimiDNS || "$target" == HajimiRouting ]]; then
        objectCommand=(python3 "$ROOT/scripts/dns_test_sources.py" --objects "$BUILD" "$target")
        if [[ "$EXPECT_GAP" == true ]]; then objectCommand+=(--legacy); fi
        selectedObjects=$("${objectCommand[@]}") || fail "invalid $CONFIGURATION Swift object plan for $target"
        targetObjects=()
        while IFS= read -r object; do
            if [[ -n "$object" ]]; then targetObjects+=("$object"); fi
        done <<< "$selectedObjects"
    else
        targetObjects=("$BUILD/$target.build/"*.o)
    fi
    [[ ${#targetObjects[@]} -gt 0 ]] || fail "missing $CONFIGURATION objects for $target"
    OBJECTS+=("${targetObjects[@]}")
    if [[ "$target" != HajimiCore && "$target" != HajimiDNS && "$target" != HajimiRouting ]]; then
        moduleMap="$BUILD/$target.build/module.modulemap"
        [[ -f "$moduleMap" ]] || fail "missing prebuilt module map for $target"
        FLAGS+=(-I "$ROOT/Sources/$target/include" -Xcc "-fmodule-map-file=$moduleMap")
    fi
done

umask 077
if [[ -z "$WORK_DIR" ]]; then WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hajimi-dns-tls-cancel.XXXXXX"); fi
mkdir -p -- "$WORK_DIR"
WORK_DIR=$(CDPATH= cd -- "$WORK_DIR" && pwd)
PRIVATE_HOME=$(mktemp -d "$WORK_DIR/transport-home.XXXXXX")
MODE=after
if [[ "$EXPECT_GAP" == true ]]; then MODE=before; fi
BINARY="$WORK_DIR/dns-tls-cancellation-$CONFIGURATION-$MODE"
RUN_COMMAND=("$BINARY")
if [[ "$EXPECT_GAP" == true ]]; then RUN_COMMAND+=(--expect-current-gap); fi
COMPILE_LOG="$WORK_DIR/dns-tls-cancellation-$CONFIGURATION-$MODE-compile.log"
RUN_LOG="$WORK_DIR/dns-tls-cancellation-$CONFIGURATION-$MODE.log"

if ! xcrun swiftc -O -parse-as-library "${FLAGS[@]}" \
    "$ROOT/SmokeTests/EncryptedDNSTransportCancellationMain.swift" "${OBJECTS[@]}" "${LIBRARIES[@]}" \
    -lc++ -framework Foundation -framework Network -framework Security -framework CoreFoundation \
    -o "$BINARY" >"$COMPILE_LOG" 2>&1; then
    sed -n '1,100p' "$COMPILE_LOG" >&2
    fail "link failed; full log retained at $COMPILE_LOG"
fi
if ! CFFIXED_USER_HOME="$PRIVATE_HOME" LANG=C LC_ALL=C \
    "${RUN_COMMAND[@]}" >"$RUN_LOG" 2>&1; then
    sed -n '1,100p' "$RUN_LOG" >&2
    fail "cancellation regression failed; full log retained at $RUN_LOG"
fi
sed -n '1,40p' "$RUN_LOG"
printf 'Encrypted DNS cancellation fixture artifacts: %s\n' "$WORK_DIR"

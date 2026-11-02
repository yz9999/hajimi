#!/bin/bash
# Independently link already-built Core/native objects and the bounded VMess
# reference peer. No SwiftPM, GUI, Helper, user configuration or system limits.
# The optional 256 limit / preparation apply only to the standalone child.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONFIGURATION=debug
BUILD_DIR_OVERRIDE=
WORK_DIR=
FD_LIMIT=0
PREPARE=false
MODE=all
COUNT=96
FRAMING=length
DELAY=0.01

usage() {
    printf '%s\n' \
        'Usage: bash scripts/test_dns_doh_burst.sh [--configuration debug|release] [--build-dir DIRECTORY] [--work-dir DIRECTORY]' \
        '       [--fd-limit 0|128|256|512|1024] [--prepare-process-resources]' \
        '       [--mode all|direct|nested-direct|nested-http|nested-vmess] [--count 64|96] [--framing length|mixed|mixed-eof]' \
        'mixed-eof: one in four authenticated HTTP replies requires TLS close_notify/EOF; others stay reusable.' \
        'Resource-limit comparison: --fd-limit 256 (unprepared isolated child, stage/wire trace retained).' \
        'After case:  --fd-limit 256 --prepare-process-resources (explicit child-only 256 -> 4096).' \
        'Both cases visibly authenticate/close one private-CA TLS preflight within the original 8s (no DNS query).' \
        'Compile/link only existing build products; missing/stale Core fails closed.'
}
fail() { printf 'DNS DoH burst fixture: %s\n' "$*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --configuration|--build-dir|--work-dir|--fd-limit|--mode|--count|--framing|--delay)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            option=$1; value=$2; shift 2
            case "$option" in
                --configuration) CONFIGURATION=$value ;;
                --build-dir) BUILD_DIR_OVERRIDE=$value ;;
                --work-dir) WORK_DIR=$value ;;
                --fd-limit) FD_LIMIT=$value ;;
                --mode) MODE=$value ;;
                --count) COUNT=$value ;;
                --framing) FRAMING=$value ;;
                --delay) DELAY=$value ;;
            esac
            ;;
        --prepare-process-resources) PREPARE=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unexpected argument: $1" ;;
    esac
done
case "$CONFIGURATION" in debug|release) ;; *) fail '--configuration must be debug or release' ;; esac
case "$FD_LIMIT" in 0|128|256|512|1024) ;; *) fail 'invalid isolated child descriptor limit' ;; esac
case "$MODE" in all|direct|nested-direct|nested-http|nested-vmess) ;; *) fail 'invalid bounded transport mode' ;; esac
case "$COUNT" in 64|96) ;; *) fail '--count must be 64 or 96' ;; esac
case "$FRAMING" in length|mixed|mixed-eof) ;; *) fail '--framing must be length, mixed or mixed-eof' ;; esac
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
for source in Profile.swift CompiledRoutingRules.swift NativeOutbound.swift EncryptedDNS.swift ProxyEngine.swift NetworkProcessResources.swift DNSQueryModuleAdapter.swift NetworkPerformanceDiagnostics.swift; do
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
FLAGS=(-I "$BUILD" -D HAJIMI_FD_RESOURCE_PREPARATION)
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
    [[ ${#targetObjects[@]} -gt 0 ]] || fail "missing $CONFIGURATION objects for $target"
    OBJECTS+=("${targetObjects[@]}")
    if [[ "$target" != HajimiCore && "$target" != HajimiDNS && "$target" != HajimiRouting ]]; then
        moduleMap="$BUILD/$target.build/module.modulemap"
        [[ -f "$moduleMap" ]] || fail "missing prebuilt module map for $target"
        FLAGS+=(-I "$ROOT/Sources/$target/include" -Xcc "-fmodule-map-file=$moduleMap")
    fi
done
CRYPTO_OBJECT="$BUILD/HajimiProtocolsCXX.build/Crypto.cpp.o"
[[ -f "$CRYPTO_OBJECT" ]] || fail 'missing the prebuilt native crypto object for the reference peer'

umask 077
if [[ -z "$WORK_DIR" ]]; then WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hajimi-dns-burst-artifacts.XXXXXX"); fi
mkdir -p -- "$WORK_DIR"
WORK_DIR=$(CDPATH= cd -- "$WORK_DIR" && pwd)
BINARY="$WORK_DIR/doh-burst-$CONFIGURATION"
PEER="$WORK_DIR/vmess-loopback-peer-$CONFIGURATION"
COMPILE_LOG="$WORK_DIR/doh-burst-$CONFIGURATION-compile.log"
PEER_COMPILE_LOG="$WORK_DIR/vmess-loopback-peer-$CONFIGURATION-compile.log"
RUN_LOG="$WORK_DIR/doh-burst-$CONFIGURATION-$MODE-fd$FD_LIMIT-$PREPARE-$FRAMING.log"

if ! xcrun swiftc -O -parse-as-library "${FLAGS[@]}" \
    "$ROOT/SmokeTests/DNSDoHBurstMain.swift" "${OBJECTS[@]}" "${LIBRARIES[@]}" \
    -lc++ -framework Foundation -framework Network -framework Security -framework CoreFoundation \
    -o "$BINARY" >"$COMPILE_LOG" 2>&1; then
    sed -n '1,100p' "$COMPILE_LOG" >&2
    fail "standalone link failed; full log retained at $COMPILE_LOG"
fi
if ! xcrun clang++ -std=c++17 -O2 -I "$ROOT/Sources/HajimiProtocolsCXX" -I "$SSL/include" \
    "$ROOT/SmokeTests/DoHBurstVMessPeer.cpp" "$CRYPTO_OBJECT" "$SSL/lib/libcrypto.a" \
    -o "$PEER" >"$PEER_COMPILE_LOG" 2>&1; then
    sed -n '1,100p' "$PEER_COMPILE_LOG" >&2
    fail "reference peer link failed; full log retained at $PEER_COMPILE_LOG"
fi
PYTHON_ARGS=(--binary "$BINARY" --vmess-peer "$PEER" --mode "$MODE" --count "$COUNT"
             --framing "$FRAMING" --delay "$DELAY" --fd-limit "$FD_LIMIT")
if [[ "$PREPARE" == true ]]; then PYTHON_ARGS+=(--prepare-process-resources); fi
if ! python3 "$ROOT/SmokeTests/live_doh_burst.py" "${PYTHON_ARGS[@]}" >"$RUN_LOG" 2>&1; then
    sed -n '1,45p' "$RUN_LOG" | cut -c 1-2000 >&2
    fail "burst regression failed; full stage/wire trace retained at $RUN_LOG"
fi
sed -n '1,100p' "$RUN_LOG"
printf 'DNS DoH burst fixture artifacts: %s\n' "$WORK_DIR"

#!/bin/bash
# Compile the actual WS/gRPC/XHTTP code with independent in-memory peers.
# No SwiftPM, GUI, Helper, configuration, DNS or network socket is used.
set -euo pipefail

FIXTURE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FIXTURE_WORK=
BASELINE_DIR=
RUN_ARGS=()
usage() {
    printf '%s\n' \
        'Usage: bash SmokeTests/test_carrier_framing.sh [--work-dir DIRECTORY]' \
        '       [--checks-only | --bench-only | --grpc-malformed] [--baseline-dir DIRECTORY]' \
        'An optional baseline directory supplies frozen WebSocketFraming.swift and HTTP2.swift.' \
        'Use --bench-only for a baseline that intentionally fails the malformed-pump regression.' \
        'The generated WS translation unit contains verbatim private production code.'
}
fail() { printf 'Carrier framing fixture: %s\n' "$*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --work-dir|--baseline-dir)
            [[ $# -ge 2 && -n "$2" ]] || fail "$1 requires a directory"
            option=$1; value=$2; shift 2
            case "$option" in --work-dir) FIXTURE_WORK=$value ;; --baseline-dir) BASELINE_DIR=$value ;; esac
            ;;
        --checks-only|--bench-only|--grpc-malformed) RUN_ARGS+=("$1"); shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unexpected argument: $1" ;;
    esac
done
[[ $(uname -s) == Darwin ]] || fail 'macOS is required for the production CryptoKit and Security code'
if [[ -z "$FIXTURE_WORK" ]]; then FIXTURE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/hajimi-carrier-framing.XXXXXX"); fi
mkdir -p -- "$FIXTURE_WORK"
FIXTURE_WORK=$(CDPATH= cd -- "$FIXTURE_WORK" && pwd)
python3 "$FIXTURE_ROOT/SmokeTests/prepare_carrier_fixture.py" \
    --output "$FIXTURE_WORK/ProductionWebSocket.swift"
SOURCES=()
for source in HPACKHuffman.swift HPACK.swift HTTP2.swift XHTTP.swift XHTTPStreaming.swift WebSocketFraming.swift; do
    path="$FIXTURE_ROOT/Sources/HajimiCore/$source"
    case "$source" in
        WebSocketFraming.swift|HTTP2.swift)
            if [[ -n "$BASELINE_DIR" ]]; then path="$BASELINE_DIR/$source"; fi ;;
    esac
    [[ -f "$path" ]] || fail "missing production source: $path"
    SOURCES+=("$path")
done
SOURCES+=("$FIXTURE_WORK/ProductionWebSocket.swift"
    "$FIXTURE_ROOT/SmokeTests/CarrierFramingSupport.swift"
    "$FIXTURE_ROOT/SmokeTests/WebSocketCarrierFixture.swift"
    "$FIXTURE_ROOT/SmokeTests/CarrierFramingMain.swift")
LANG=C LC_ALL=C shasum -a 256 "${SOURCES[@]}" >"$FIXTURE_WORK/source-sha256.txt"
if ! xcrun swiftc -O -whole-module-optimization -parse-as-library -target "$(uname -m)-apple-macos13.0" "${SOURCES[@]}" \
    -o "$FIXTURE_WORK/carrier-framing" >"$FIXTURE_WORK/compile.log" 2>&1; then
    sed -n '1,100p' "$FIXTURE_WORK/compile.log" >&2
    fail "compile failed; log retained at $FIXTURE_WORK/compile.log"
fi
run_fixture() {
    if [[ ${#RUN_ARGS[@]} -gt 0 ]]; then
        LANG=C LC_ALL=C "$FIXTURE_WORK/carrier-framing" "${RUN_ARGS[@]}"
    else
        LANG=C LC_ALL=C "$FIXTURE_WORK/carrier-framing"
    fi
}
if ! run_fixture >"$FIXTURE_WORK/run.log" 2>&1; then
    tail -n 80 "$FIXTURE_WORK/run.log" >&2
    fail "regression failed; log retained at $FIXTURE_WORK/run.log"
fi
sed -n '1,100p' "$FIXTURE_WORK/run.log"
printf 'Carrier framing memory artifacts: %s\n' "$FIXTURE_WORK"

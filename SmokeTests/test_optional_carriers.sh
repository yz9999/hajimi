#!/bin/bash
# Compile the actual optional-carrier production files with a memory-only
# substrate. No SwiftPM, GUI, Helper, DNS, socket or external service is used.
set -euo pipefail

FIXTURE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FIXTURE_WORK=
BASELINE_DIR=
BENCH_ONLY=false
SAMPLE=false
usage() {
    printf '%s\n' \
        'Usage: bash SmokeTests/test_optional_carriers.sh [--work-dir DIRECTORY] [--bench-only] [--sample]' \
        '       [--baseline-dir DIRECTORY]' \
        'The optional baseline directory supplies frozen NativeMux.swift, XUDP.swift and MKCPTransport.swift.' \
        'Use --bench-only for a baseline that intentionally fails the new late-read cancellation regression.'
}
fail() { printf 'Optional carrier memory fixture: %s\n' "$*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --work-dir|--baseline-dir)
            [[ $# -ge 2 && -n "$2" ]] || fail "$1 requires a directory"
            option=$1; value=$2; shift 2
            case "$option" in --work-dir) FIXTURE_WORK=$value ;; --baseline-dir) BASELINE_DIR=$value ;; esac
            ;;
        --bench-only) BENCH_ONLY=true; shift ;;
        --sample) SAMPLE=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unexpected argument: $1" ;;
    esac
done
[[ $(uname -s) == Darwin ]] || fail 'macOS is required for the production Network and CryptoKit files'
if [[ -z "$FIXTURE_WORK" ]]; then FIXTURE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/hajimi-optional-carriers.XXXXXX"); fi
mkdir -p -- "$FIXTURE_WORK"
FIXTURE_WORK=$(CDPATH= cd -- "$FIXTURE_WORK" && pwd)
SOURCES=("$FIXTURE_ROOT/SmokeTests/OptionalCarrierMemorySupport.swift")
for source in NativeMux.swift XUDP.swift MKCPSegment.swift MKCPTransport.swift MKCPOutbound.swift; do
    path="$FIXTURE_ROOT/Sources/HajimiCore/$source"
    case "$source" in
        NativeMux.swift|XUDP.swift|MKCPTransport.swift)
            if [[ -n "$BASELINE_DIR" ]]; then path="$BASELINE_DIR/$source"; fi
            ;;
    esac
    [[ -f "$path" ]] || fail "missing production source: $path"
    SOURCES+=("$path")
done
SOURCES+=("$FIXTURE_ROOT/SmokeTests/OptionalCarrierPerformanceMain.swift")
if ! xcrun swiftc -O -whole-module-optimization -parse-as-library "${SOURCES[@]}" \
    -o "$FIXTURE_WORK/optional-carriers" >"$FIXTURE_WORK/compile.log" 2>&1; then
    sed -n '1,80p' "$FIXTURE_WORK/compile.log" >&2
    fail "compile failed; log retained at $FIXTURE_WORK/compile.log"
fi
RUN_COMMAND=("$FIXTURE_WORK/optional-carriers")
if [[ "$BENCH_ONLY" == true ]]; then RUN_COMMAND+=(--bench-only); fi
if [[ "$SAMPLE" == true ]]; then RUN_COMMAND+=(--sample); fi
if ! LANG=C LC_ALL=C "${RUN_COMMAND[@]}" >"$FIXTURE_WORK/run.log" 2>&1; then
    tail -n 60 "$FIXTURE_WORK/run.log" >&2
    fail "regression failed; log retained at $FIXTURE_WORK/run.log"
fi
sed -n '1,80p' "$FIXTURE_WORK/run.log"
printf 'Optional carrier memory artifacts: %s\n' "$FIXTURE_WORK"

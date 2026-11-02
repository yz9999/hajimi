#!/bin/sh
# Compile only: no signing, embedding, installation, preference writes, or VPN
# activation. A missing native engine is intentionally permitted at link time;
# that development bundle explicitly refuses to start/capture traffic.
set -eu

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SOURCE_DIR/.." && pwd)
OUTPUT=${1:-"$ROOT_DIR/.build/NetworkExtension/HajimiPacketTunnel.appex"}
SDK=$(xcrun --sdk macosx --show-sdk-path)
ARCH=${ARCH:-$(uname -m)}
MINIMUM_OS=${MACOSX_DEPLOYMENT_TARGET:-13.0}

case "$ARCH" in
    arm64|x86_64) ;;
    *) printf '%s\n' "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

mkdir -p "$OUTPUT/Contents/MacOS"
set -- -arch "$ARCH" -isysroot "$SDK" "-mmacosx-version-min=$MINIMUM_OS" \
    -fobjc-arc -fblocks -fapplication-extension -Wall -Wextra -Werror \
    -I "$SOURCE_DIR" "$SOURCE_DIR/HajimiPacketTunnelProvider.m" \
    "$SOURCE_DIR/HJPacketEngineUnavailable.m" \
    -framework Foundation -framework NetworkExtension -framework Network \
    -Wl,-e,_NSExtensionMain -o "$OUTPUT/Contents/MacOS/HajimiPacketTunnel"

# Force-load the optional archive: a weak factory reference by itself would
# not pull its object out of a static library. The archive must provide the
# complete ABI in HJPacketEngineBridge.h, not just packet-codec functions.
if [ -n "${HJ_PACKET_ENGINE_LIBRARY:-}" ]; then
    if [ ! -f "$HJ_PACKET_ENGINE_LIBRARY" ]; then
        printf '%s\n' "Native packet-engine archive not found: $HJ_PACKET_ENGINE_LIBRARY" >&2
        exit 1
    fi
    set -- "$@" -Xlinker -force_load -Xlinker "$HJ_PACKET_ENGINE_LIBRARY"
fi

xcrun --sdk macosx clang "$@"
cp "$SOURCE_DIR/Info.plist" "$OUTPUT/Contents/Info.plist"
plutil -lint "$OUTPUT/Contents/Info.plist"
printf '%s\n' "Built unsigned development extension: $OUTPUT"
if [ -z "${HJ_PACKET_ENGINE_LIBRARY:-}" ]; then
    printf '%s\n' "No shared native packet engine linked; this extension will refuse to start."
fi

#!/bin/bash
# 哈基米 (Hajimi) 一键编译与打包脚本 (支持 Intel / Apple Silicon, macOS 13.0+)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

export PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/CMake.app/Contents/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"
export MACOSX_DEPLOYMENT_TARGET=13.0
unset HAJIMI_OPENSSL_ROOT
ARCH="${ARCHS:-$(uname -m)}"

echo "========================================================"
echo "  正在编译 哈基米.app"
echo "  目标架构: ${ARCH} | 最低系统要求: macOS ${MACOSX_DEPLOYMENT_TARGET}+"
echo "========================================================"

chmod +x scripts/*.sh
rm -f .build/manifest.db
make app ARCHS="${ARCH}"

echo ""
echo "========================================================"
echo "✅ 编译完成！"
echo "应用路径: ${DIR}/dist/哈基米.app"
echo "========================================================"

if command -v open >/dev/null 2>&1; then
    open -R "${DIR}/dist/哈基米.app"
fi

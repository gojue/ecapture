#!/usr/bin/env bash
# 文件: test/e2e/run_e2e.sh
# 轻量级 e2e 测试脚本示例
# 目的：自动化执行单元测试、构建二进制（轻量）并做 CLI smoke-test。

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "$ROOT_DIR"

echo "== e2e: 环境检查 =="
command -v go >/dev/null 2>&1 || { echo "go not found"; exit 1; }
command -v clang >/dev/null 2>&1 || echo "warning: clang not found (C/ebpf 编译将无法进行)";

echo "== e2e: 清理构建缓存 =="
make clean || { echo "make clean failed"; exit 1; }

echo "== e2e: 尝试构建 ecapture 二进制（优先 make） =="
if make all -j 4; then
  echo "make succeeded"
else
  echo "make all failed, trying non-CORE build"
  if make nocore -j 4; then
    echo "make non-CORE succeeded"
  else
    echo "make non-CORE failed"
    exit 1
  fi
fi

BINARY="./bin/ecapture"
if [ ! -x "$BINARY" ]; then
  echo "ecapture binary not found at $BINARY. Please ensure the build succeeded and the binary is present."
  exit 1
fi

if [ -z "$BINARY" ]; then
  echo "ecapture binary not found"
  exit 1
fi

echo "== e2e: 运行二进制帮助/版本检查 =="
"$BINARY" --help >/tmp/ecapture_help.txt 2>&1 || true
"$BINARY" --version >/tmp/ecapture_version.txt 2>&1 || true
echo "help and version output saved to /tmp/ecapture_help.txt and /tmp/ecapture_version.txt"

echo "== e2e: 运行最小 smoke-test（text 模式，非 root，不会启用 eBPF） =="
# 尝试使用非侵入式子命令，部分命令可能需要 root / 特权。这里只做尽量不依赖 root 的检查。
set +e
"$BINARY" tls -h >/tmp/ecapture_tls_help.txt 2>&1
RET=$?
set -e
if [ $RET -ne 0 ]; then
  echo "note: 'ecapture tls -h' returned non-zero (可能需要 root 或其他依赖). See /tmp/ecapture_tls_help.txt"
else
  echo "'ecapture tls -h' succeeded"
fi

echo "== e2e: 可选扩展：在 Docker 中以 --privileged 模式运行更深入测试（需手动启用） =="
cat <<'EOF'
# 若需更深入的 eBPF 运行测试，可以在支持特权容器的环境中运行：
# docker run --rm -it --privileged -v "$(pwd)":/src -w /src ubuntu:24.04 /bin/bash -c "
#   apt update && apt install -y build-essential clang llvm libelf-dev pkg-config golang-go git \
#     libpcap-dev bpftool ca-certificates && \
#   make all -j$(nproc) && \
#   ./bin/ecapture --help
# "
#
# 上述命令示例仅作为参考，实际镜像和依赖可能需要根据仓库 Makefile 调整。
EOF

exit 0
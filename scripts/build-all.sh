#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> [1/4] 编译轻量前端静态资源 (Vite + SHA-384 SRI)..."
(cd web && npm run build)

mkdir -p dist

echo "==> [2/4] 编译服务端部署单文件可执行程序 (Linux amd64 / arm64)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o dist/sns-server-linux-amd64 ./cmd/server

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" \
  -o dist/sns-server-linux-arm64 ./cmd/server

echo "==> [3/4] 交叉编译纯本地 Windows 桌面应用程序 (无控制台原生 GUI 窗口)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H windowsgui" \
  -o dist/ServerNeedSafe-windows-amd64.exe ./cmd/desktop

CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w -H windowsgui" \
  -o dist/ServerNeedSafe-windows-arm64.exe ./cmd/desktop

echo "==> [4/4] 生成 SHA-256 完整性校验清单..."
(
  cd dist
  sha256sum \
    ServerNeedSafe-windows-amd64.exe \
    ServerNeedSafe-windows-arm64.exe \
    sns-server-linux-amd64 \
    sns-server-linux-arm64 > SHA256SUMS.txt
)

echo "==> 构建完成！输出产物："
ls -lh dist/

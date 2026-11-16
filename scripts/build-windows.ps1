$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RootDir

Write-Host "==> [1/2] 构建前端静态资源..." -ForegroundColor Cyan
Push-Location web
npm install --no-audit --no-fund
npm run build
Pop-Location

if (-not (Test-Path "dist")) {
    New-Item -ItemType Directory -Path "dist" | Out-Null
}

Write-Host "==> [2/2] 编译纯本地 Windows 桌面应用 (ServerNeedSafe.exe)..." -ForegroundColor Cyan
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -trimpath -ldflags="-s -w -H windowsgui" -o "dist\ServerNeedSafe.exe" .\cmd\desktop

Write-Host "==> 编译成功: dist\ServerNeedSafe.exe (可直接双击独立运行，无需任何外部依赖)" -ForegroundColor Green

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
$SnsVersion = if ($env:SNS_VERSION) { $env:SNS_VERSION } else {
    try { (git describe --tags --exact-match 2>$null).Trim() } catch { "dev" }
}
if (-not $SnsVersion) { $SnsVersion = "dev" }
$SnsCommit = if ($env:SNS_COMMIT) { $env:SNS_COMMIT } else {
    try { (git rev-parse --short HEAD 2>$null).Trim() } catch { "" }
}
$SnsBuildTime = if ($env:SNS_BUILD_TIME) { $env:SNS_BUILD_TIME } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
$VersionPkg = "github.com/icaruszezen/ServerNeedSafe/internal/version"
$LdFlags = "-s -w -H windowsgui -X $VersionPkg.Version=$SnsVersion -X $VersionPkg.Commit=$SnsCommit -X $VersionPkg.BuildTime=$SnsBuildTime"

$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -trimpath -ldflags="$LdFlags" -o "dist\ServerNeedSafe.exe" .\cmd\desktop

Write-Host "==> 编译成功: dist\ServerNeedSafe.exe (可直接双击独立运行，无需任何外部依赖)" -ForegroundColor Green

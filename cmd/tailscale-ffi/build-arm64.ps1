# Build tailscale-ffi.dll for Windows ARM64 (c-shared).
#
# Requires an aarch64 Windows cross-compiler:
#   - llvm-mingw (recommended): https://github.com/mstorsjo/llvm-mingw
#   - or zig: zig cc -target aarch64-windows-gnu
#
# Usage (from repo root or this directory):
#   .\cmd\tailscale-ffi\build-arm64.ps1
#   .\cmd\tailscale-ffi\build-arm64.ps1 -DownloadToolchain
#   .\cmd\tailscale-ffi\build-arm64.ps1 -Out tailscale-ffi-arm64.dll

param(
    [string]$Out = "tailscale-ffi-arm64.dll",
    [switch]$DownloadToolchain,
    [string]$ToolchainDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$OutPath = Join-Path $ScriptDir $Out

function Find-AArch64GCC {
    param([string]$SearchRoot)
    $names = @(
        "aarch64-w64-mingw32-gcc.exe",
        "aarch64-w64-mingw32-clang.exe"
    )
    foreach ($name in $names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Path }
    }
    if ($SearchRoot -and (Test-Path $SearchRoot)) {
        foreach ($name in $names) {
            $hit = Get-ChildItem -Path $SearchRoot -Filter $name -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    return $null
}

function Ensure-LlvmMingw {
    param([string]$DestRoot)
    $ver = "20250402"
    $zipName = "llvm-mingw-$ver-ucrt-aarch64.zip"
    $url = "https://github.com/mstorsjo/llvm-mingw/releases/download/$ver/$zipName"
    $dest = Join-Path $DestRoot "llvm-mingw-$ver-ucrt-aarch64"
    if (Test-Path $dest) {
        return $dest
    }
    New-Item -ItemType Directory -Force -Path $DestRoot | Out-Null
    $zipPath = Join-Path $DestRoot $zipName
    Write-Host "Downloading llvm-mingw $ver ..."
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    Write-Host "Extracting to $dest ..."
    Expand-Archive -Path $zipPath -DestinationPath $dest -Force
    Remove-Item $zipPath -Force
    return $dest
}

$toolchainRoot = if ($ToolchainDir) { $ToolchainDir } else { Join-Path $env:LOCALAPPDATA "tailscale-ffi-toolchain" }
$gcc = Find-AArch64GCC -SearchRoot $toolchainRoot

if (-not $gcc -and $DownloadToolchain) {
    $extracted = Ensure-LlvmMingw -DestRoot $toolchainRoot
    $gcc = Find-AArch64GCC -SearchRoot $extracted
}

if (-not $gcc) {
    Write-Error @"
No aarch64 Windows C compiler found.

Options:
  1) Run with -DownloadToolchain (downloads llvm-mingw to $toolchainRoot)
  2) Install llvm-mingw and add aarch64-w64-mingw32-gcc to PATH
  3) Install zig and set: `$env:CC = 'zig cc -target aarch64-windows-gnu'

Example:
  .\build-arm64.ps1 -DownloadToolchain
"@
}

$binDir = Split-Path -Parent $gcc
Write-Host "Using CC: $gcc"

$env:GOOS = "windows"
$env:GOARCH = "arm64"
$env:CGO_ENABLED = "1"
$env:CC = $gcc
$env:PATH = "$binDir;$env:PATH"

Push-Location $RepoRoot
try {
    Write-Host "Building $OutPath ..."
    go build -trimpath -buildmode=c-shared -ldflags="-s -w" -o $OutPath ./cmd/tailscale-ffi
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $headerSrc = Join-Path $RepoRoot "tailscale-ffi.h"
    $headerDst = Join-Path $ScriptDir "tailscale-ffi-arm64.h"
    if (Test-Path $headerSrc) {
        Copy-Item -Force $headerSrc $headerDst
        Write-Host "Header: $headerDst"
    }
    Write-Host "OK: $OutPath"
}
finally {
    Pop-Location
}

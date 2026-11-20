
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "       NETSHADOW WINDOWS BUILD" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python launcher not found."
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Cargo not found. Install Rust first."
}

py --version
cargo --version

Write-Host "[1/3] Installing build dependencies..." -ForegroundColor Yellow

py -m pip install --upgrade build setuptools setuptools-rust wheel

Write-Host "[2/3] Building NETSHADOW..." -ForegroundColor Yellow

py -m build --wheel

Write-Host "[3/3] Build completed." -ForegroundColor Green

Get-ChildItem dist\*.whl

Write-Host "NETSHADOW Windows build completed." -ForegroundColor Green

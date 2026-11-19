
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "      NETSHADOW WINDOWS INSTALL" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python launcher not found."
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Cargo not found. Install Rust first."
}

Write-Host "[1/4] Creating virtual environment..."

if (-not (Test-Path ".venv")) {
    py -m venv .venv
}

$Python = Join-Path $RootDir ".venv\Scripts\python.exe"

Write-Host "[2/4] Updating pip..."
& $Python -m pip install --upgrade pip

Write-Host "[3/4] Installing NETSHADOW..."
& $Python -m pip install .

Write-Host "[4/4] Installation completed." -ForegroundColor Green

Write-Host ""
Write-Host "To activate:"
Write-Host ".\.venv\Scripts\Activate.ps1"

Write-Host ""
Write-Host "To start:"
Write-Host "netshadow --help"

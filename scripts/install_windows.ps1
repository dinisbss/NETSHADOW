$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$netshadow = Join-Path $projectRoot ".venv\Scripts\netshadow.exe"

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python 3.10+ is required. Install Python and ensure the 'py' launcher is available."
}

Push-Location $projectRoot
try {
    & py -3 -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10 or newer is required.'"
    if ($LASTEXITCODE -ne 0) {
        throw "Python 3.10 or newer is required."
    }

    if (-not (Test-Path $venvPython)) {
        & py -3 -m venv .venv
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create the virtual environment."
        }
    }

    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "Could not upgrade pip."
    }

    & $venvPython -m pip install -e .
    if ($LASTEXITCODE -ne 0) {
        throw "Could not install NETSHADOW."
    }

    & $netshadow start
    if ($LASTEXITCODE -ne 0) {
        throw "NETSHADOW did not start successfully."
    }
}
finally {
    Pop-Location
}
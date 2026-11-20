
#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "======================================"
echo "       NETSHADOW LINUX INSTALL"
echo "======================================"

command -v python3 >/dev/null || {
    echo "[ERROR] Python 3 not found."
    exit 1
}

echo "[1/4] Creating virtual environment..."

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

echo "[2/4] Activating environment..."
source .venv/bin/activate

echo "[3/4] Updating pip..."
python -m pip install --upgrade pip

echo "[4/4] Installing NETSHADOW..."
python -m pip install .

echo
echo "Installation completed."
echo "Activate with: source .venv/bin/activate"
echo "Start with: netshadow --help"

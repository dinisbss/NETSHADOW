
#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "======================================"
echo "       NETSHADOW LINUX BUILD"
echo "======================================"

command -v python3 >/dev/null || {
    echo "[ERROR] Python 3 not found."
    exit 1
}

command -v cargo >/dev/null || {
    echo "[ERROR] Cargo not found. Install Rust first."
    exit 1
}

python3 --version
cargo --version

echo "[1/3] Installing build dependencies..."
python3 -m pip install --upgrade build setuptools setuptools-rust wheel

echo "[2/3] Building NETSHADOW..."
python3 -m build --wheel

echo "[3/3] Build completed."

echo "Wheel files:"
ls -lh dist/*.whl

echo "NETSHADOW Linux build completed."

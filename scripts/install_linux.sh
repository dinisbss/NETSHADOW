#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

python_bin="${PYTHON:-python3}"
"$python_bin" -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10 or newer is required."'

if [[ ! -x .venv/bin/python ]]; then
    "$python_bin" -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/netshadow start
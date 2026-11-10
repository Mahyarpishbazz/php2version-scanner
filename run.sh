#!/usr/bin/env bash
#
# small wrapper so I don't have to remember the venv setup every time on
# Linux/macOS. doesn't do any of the actual scanning logic - that's all
# in scanner.py, this just handles python/venv/deps and then calls it.
#
# usage:
#   ./run.sh                    (no args? it'll ask you for targets)
#   ./run.sh example.com 10.0.0.5
#   ./run.sh targets.txt
#   ./run.sh targets.txt -o custom_report.csv

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# find a python3
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "Error: Python 3 was not found on this system." >&2
    echo "Install it first, e.g.:" >&2
    echo "  macOS:  brew install python3" >&2
    echo "  Debian/Ubuntu: sudo apt install python3 python3-venv python3-pip" >&2
    exit 1
fi

# make a venv the first time, reuse it after that
if [ ! -d "$VENV_DIR" ]; then
    echo "Setting up a local environment (first run only)..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

pip install --quiet --disable-pip-version-check -r "$SCRIPT_DIR/requirements.txt"

# no args is fine - scanner.py handles that itself (asks you interactively)
python "$SCRIPT_DIR/scanner.py" "$@"

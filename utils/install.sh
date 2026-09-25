#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

command -v "${PYTHON_BIN}" >/dev/null 2>&1 || {
  printf 'Python is required: %s\n' "${PYTHON_BIN}" >&2
  exit 1
}

if [[ ! -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  "${PYTHON_BIN}" -m venv "${REPO_ROOT}/.venv"
fi

"${REPO_ROOT}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
(
  cd -- "${REPO_ROOT}"
  "${REPO_ROOT}/.venv/bin/python" -m pip install -r requirements.txt
)

printf 'Installed dependencies in %s/.venv\n' "${REPO_ROOT}"
printf 'Preview skill links with: ./utils/link-codex-skills.sh --dry-run\n'

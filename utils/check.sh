#!/usr/bin/env bash
# One entry point for contributors and coding agents: setup, fast checks, full suite.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PY=.venv/bin/python
LOG_DIR=.local/check
# Same cache the runtime and tests use, so one download serves offline runs.
export TIKTOKEN_CACHE_DIR="${TIKTOKEN_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/vraptor/tiktoken}"

usage() {
  cat <<'USAGE'
Usage: utils/check.sh [setup|fast|full]

  setup  Create .venv, install the runtime editable with test extras and ruff,
         and cache the tokenizer encodings (needs network once).
  fast   ruff, git diff --check, public export validation and core tests (default).
  full   Whole pytest suite. Output goes to .local/check/pytest.log; the tail is
         printed on failure. CHECK_TIMEOUT (seconds, default 1800) bounds the run
         when timeout or gtimeout is installed.
USAGE
}

need_venv() {
  if [[ ! -x "$PY" ]]; then
    echo "Missing $PY; run utils/check.sh setup first." >&2
    exit 2
  fi
}

tokenizer_ready() {
  "$PY" -c 'import tiktoken; [tiktoken.get_encoding(n) for n in ("o200k_base", "cl100k_base")]' \
    >/dev/null 2>&1
}

warn_tokenizer() {
  tokenizer_ready && return 0
  echo "[WARN]  Tokenizer encodings are not cached in $TIKTOKEN_CACHE_DIR." >&2
  echo "[WARN]  Token-counting tests fail offline; run utils/check.sh setup with network." >&2
}

case "${1:-fast}" in
  setup)
    ./utils/install.sh --no-configure --no-path
    "$PY" -m pip install --quiet ruff -e '.[ai,azure,anthropic,claude,test]'
    warn_tokenizer
    ;;
  fast)
    need_venv
    warn_tokenizer
    "$PY" -m ruff check src utils tests
    git diff --check HEAD
    ./utils/validate-public-export.py
    "$PY" -m pytest -q --tb=short tests/core
    ;;
  full)
    need_venv
    warn_tokenizer
    mkdir -p "$LOG_DIR"
    run=("$PY" -m pytest -q --tb=short -rfE)
    tbin=$(command -v timeout || command -v gtimeout || true)
    if [[ -n "$tbin" ]]; then
      # --foreground keeps Ctrl-C and a caller's process-group kill reaching pytest.
      run=("$tbin" --foreground "${CHECK_TIMEOUT:-1800}" "${run[@]}")
    else
      echo "[WARN]  timeout/gtimeout not found; CHECK_TIMEOUT is not enforced." >&2
    fi
    if "${run[@]}" >"$LOG_DIR/pytest.log" 2>&1; then
      tail -n 3 "$LOG_DIR/pytest.log"
    else
      tail -n 60 "$LOG_DIR/pytest.log"
      echo "Full log: $LOG_DIR/pytest.log" >&2
      exit 1
    fi
    ;;
  -h | --help | help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
CONFIGURE=auto
INSTALL_PATH=yes
PATH_ONLY=no

while [[ $# -gt 0 ]]; do
  case "$1" in
    --configure) CONFIGURE=yes ;;
    --no-configure) CONFIGURE=no ;;
    --no-path) INSTALL_PATH=no ;;
    --path-only) PATH_ONLY=yes ;;
    -h|--help)
      cat <<'HELP'
Usage: ./utils/install.sh [--configure | --no-configure] [--no-path | --path-only]

Install vraptor plus the OpenAI, Anthropic and Claude Agent SDKs in .venv.
In a terminal, continue into setup configure (live server + OpenAI defaults).
Non-interactive runs install dependencies and print the configuration command.
By default, add this checkout to PATH and persist it for your zsh or Bash shell.
--configure     Require a terminal and run configuration after installation.
--no-configure  Skip the configuration wizard.
--no-path       Leave PATH and shell startup files unchanged (for example, CI).
--path-only     Set up PATH for an existing install; skip dependencies and wizard.
PYTHON_BIN      Select Python 3.11+ when python3 is not suitable.
HELP
      exit 0 ;;
    *) printf 'Unknown option: %s (use --help)\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

if [[ "${PATH_ONLY}" == yes && ( "${INSTALL_PATH}" == no || "${CONFIGURE}" == yes ) ]]; then
  printf '%s\n' '--path-only cannot be combined with --no-path or --configure.' >&2
  exit 2
fi

configure_cli_path() {
  local export_line path_line startup_file candidate already_saved=no
  printf -v export_line 'export PATH=%q:"$PATH"' "${REPO_ROOT}"
  # Guard both the immediate export and future startup against duplicate entries.
  case ":${PATH}:" in
    *:"${REPO_ROOT}":*) ;;
    *) export PATH="${REPO_ROOT}:${PATH}" ;;
  esac
  printf -v path_line 'case ":${PATH}:" in *:%q:*) ;; *) %s ;; esac' "${REPO_ROOT}" "${export_line}"
  case "${SHELL:-}" in
    */zsh|zsh) startup_file="${ZDOTDIR:-${HOME}}/.zshrc" ;;
    */bash|bash) startup_file="${HOME}/.bashrc" ;;
    *)
      printf 'PATH updated for this installer. Shell %s has no automatic startup-file support.\n' "${SHELL:-unknown}"
      printf 'Add the checkout using your shell configuration; for Bash/zsh:\n  %s\n' "${export_line}"
      return ;;
  esac
  for candidate in "${path_line}" "${export_line}" "export PATH=\"${REPO_ROOT}:\$PATH\""; do
    if [[ -f "${startup_file}" ]] && grep -Fxq -- "${candidate}" "${startup_file}"; then
      already_saved=yes
    fi
  done
  if [[ "${REPO_ROOT}" == "${HOME}/"* && -f "${startup_file}" ]]; then
    candidate='export PATH="$HOME/'"${REPO_ROOT#"${HOME}/"}"':$PATH"'
    if grep -Fxq -- "${candidate}" "${startup_file}"; then
      already_saved=yes
    fi
  fi
  if [[ "${already_saved}" == yes ]]; then
    printf 'PATH entry already saved in %s\n' "${startup_file}"
  else
    mkdir -p -- "$(dirname -- "${startup_file}")"
    printf '\n# Velociraptor Skills CLI\n%s\n' "${path_line}" >> "${startup_file}"
    printf 'Saved PATH entry in %s\n' "${startup_file}"
  fi
  printf 'Open a new terminal, or update your existing terminal now:\n  %s\n' "${export_line}"
  printf 'An installer subprocess cannot change its parent terminal environment.\n'
  printf 'The root launchers select this checkout and its .venv; keep the checkout at this path.\n'
}

if [[ "${PATH_ONLY}" == yes ]]; then
  configure_cli_path
  exit 0
fi

if [[ "${CONFIGURE}" == yes && ! -t 0 ]]; then
  printf 'Configuration requires an interactive terminal. Run ./utils/install.sh --no-configure, then ./vraptor setup configure in a terminal.\n' >&2
  exit 2
fi

command -v "${PYTHON_BIN}" >/dev/null 2>&1 || {
  printf 'Python is required: %s\n' "${PYTHON_BIN}" >&2
  exit 1
}

CHECK_PYTHON="${REPO_ROOT}/.venv/bin/python"
[[ -x "${CHECK_PYTHON}" ]] || CHECK_PYTHON="${PYTHON_BIN}"
"${CHECK_PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required; select it with PYTHON_BIN, or recreate an outdated .venv after preserving anything needed.")'

if [[ ! -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  if ! "${PYTHON_BIN}" -m venv "${REPO_ROOT}/.venv"; then
    printf 'Could not create .venv. Install Python 3.11+ with venv/ensurepip support (python3-venv on Debian/Ubuntu), then retry.\n' >&2
    exit 1
  fi
fi

if ! "${REPO_ROOT}/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
  "${REPO_ROOT}/.venv/bin/python" -m ensurepip --upgrade
fi
"${REPO_ROOT}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
(
  cd -- "${REPO_ROOT}"
  "${REPO_ROOT}/.venv/bin/python" -m pip install -r requirements.txt
)

printf 'Installed dependencies in %s/.venv\n' "${REPO_ROOT}"
if [[ "${INSTALL_PATH}" == yes ]]; then
  configure_cli_path
fi
if [[ "${CONFIGURE}" == yes || ( "${CONFIGURE}" == auto && -t 0 && -t 1 ) ]]; then
  printf '\nConfigure an existing live server and OpenAI analysis. Have your API-client YAML path and OpenAI credential environment ready.\n'
  "${REPO_ROOT}/vraptor" setup configure
else
  printf 'Next, configure live-server access and OpenAI in a terminal: %q setup configure\n' "${REPO_ROOT}/vraptor"
fi
printf '\nInspect saved settings: %q config --server-profile "<SERVER REFERENCE>"\n' "${REPO_ROOT}/vraptor"
printf 'Inspect AI settings: %q ai config\n' "${REPO_ROOT}/vraptor"
printf 'Check AI dependencies and credentials offline: %q ai doctor\n' "${REPO_ROOT}/vraptor"
printf 'Replace <SERVER REFERENCE> with a saved server name; multiple server profiles are supported.\n'
printf 'Configuration is saved separately; a repository .env is optional.\n'
printf 'Preview skill links with: %q --dry-run\n' "${REPO_ROOT}/utils/link-codex-skills.sh"

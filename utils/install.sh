#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
CONFIGURE=auto
INSTALL_PATH=yes
PATH_ONLY=no
PATH_STARTUP_FILE=""

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
If codex is missing, include an available ChatGPT macOS bundled CLI in the same export.
--configure     Require a terminal and run configuration after installation.
--no-configure  Skip the configuration wizard.
--no-path       Leave PATH and shell startup files unchanged (for example, CI).
--path-only     Set up PATH for an existing install; skip dependencies and wizard.
PYTHON_BIN      Select Python 3.11+ when python3 is not suitable.
CHATGPT_APP     Override the ChatGPT.app location for bundled Codex discovery.
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

print_cli_reload() {
  [[ -n "${PATH_STARTUP_FILE}" ]] || return 0
  printf '\nEnable commands in your current terminal:\n\n'
  printf '  source %q\n' "${PATH_STARTUP_FILE}"
  case "${SHELL}" in
    */zsh|zsh) printf '  rehash\n' ;;
    */bash|bash) printf '  hash -r\n' ;;
  esac
  printf '\n  command -v vraptor\n  vraptor --help\n\n'
}

configure_cli_path() {
  local export_line entry_export path_line startup_file candidate directory app codex_command
  local already_saved path_prefix="${REPO_ROOT}" missing_prefix=""
  local path_dirs=("${REPO_ROOT}") app_candidates=()
  printf '\nPATH setup\n\n'
  if codex_command="$(command -v codex 2>/dev/null)"; then
    printf 'Codex CLI already on PATH:\n\n  %s\n\n' "${codex_command}"
  else
    if [[ -n "${CHATGPT_APP:-}" ]]; then
      app_candidates=("${CHATGPT_APP}")
    else
      app_candidates=("/Applications/ChatGPT.app" "${HOME}/Applications/ChatGPT.app")
    fi
    for app in "${app_candidates[@]}"; do
      for directory in "${app}/Contents/Resources/codex-cli/bin" "${app}/Contents/Resources"; do
        printf 'Checking ChatGPT Codex launcher:\n  %s/codex\n\n' "${directory}"
        if [[ -f "${directory}/codex" && -x "${directory}/codex" ]]; then
          directory="$(cd -- "${directory}" && pwd)"
          path_dirs+=("${directory}")
          path_prefix="${path_prefix}:${directory}"
          printf 'Including ChatGPT bundled Codex CLI: %s\n\n' "${directory}"
          break 2
        fi
      done
    done
    if [[ ${#path_dirs[@]} -eq 1 ]]; then
      printf 'Codex CLI was not found. Codex-managed AI needs codex on PATH.\n'
      printf 'Install it separately if needed: https://learn.chatgpt.com/docs/codex/cli\n\n'
    fi
  fi
  printf -v export_line 'export PATH=%q:"$PATH"' "${path_prefix}"
  # Export once for this process; persist each component with its own guard.
  for directory in "${path_dirs[@]}"; do
    case ":${PATH}:" in
      *:"${directory}":*) ;;
      *) missing_prefix="${missing_prefix}${directory}:" ;;
    esac
  done
  export PATH="${missing_prefix}${PATH}"
  case "${SHELL:-}" in
    */zsh|zsh) startup_file="${ZDOTDIR:-${HOME}}/.zshrc" ;;
    */bash|bash) startup_file="${HOME}/.bashrc" ;;
    *)
      printf 'PATH updated for this installer. Shell %s has no automatic startup-file support.\n' "${SHELL:-unknown}"
      printf 'Add the checkout using your shell configuration; for Bash/zsh:\n  %s\n' "${export_line}"
      return ;;
  esac
  for directory in "${path_dirs[@]}"; do
    already_saved=no
    printf -v entry_export 'export PATH=%q:"$PATH"' "${directory}"
    printf -v path_line 'case ":${PATH}:" in *:%q:*) ;; *) %s ;; esac' "${directory}" "${entry_export}"
    for candidate in "${path_line}" "${entry_export}" "export PATH=\"${directory}:\$PATH\""; do
      if [[ -f "${startup_file}" ]] && grep -Fxq -- "${candidate}" "${startup_file}"; then
        already_saved=yes
      fi
    done
    if [[ "${directory}" == "${HOME}/"* && -f "${startup_file}" ]]; then
      candidate='export PATH="$HOME/'"${directory#"${HOME}/"}"':$PATH"'
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
  done
  PATH_STARTUP_FILE="${startup_file}"
  printf '\nOpen a new terminal, or reload PATH in your existing terminal.\n'
  printf 'An installer subprocess cannot change its parent terminal environment.\n'
  print_cli_reload
  printf 'Alternatively, enable this checkout directly in your terminal:\n\n  %s\n\n' "${export_line}"
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

printf '\nPython virtual environment\n\n'
CHECK_PYTHON="${REPO_ROOT}/.venv/bin/python"
[[ -x "${CHECK_PYTHON}" ]] || CHECK_PYTHON="${PYTHON_BIN}"
"${CHECK_PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required; select it with PYTHON_BIN, or recreate an outdated .venv after preserving anything needed.")'

if [[ ! -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  printf 'Creating %s/.venv\n\n' "${REPO_ROOT}"
  if ! "${PYTHON_BIN}" -m venv "${REPO_ROOT}/.venv"; then
    printf 'Could not create .venv. Install Python 3.11+ with venv/ensurepip support (python3-venv on Debian/Ubuntu), then retry.\n' >&2
    exit 1
  fi
else
  printf 'Reusing %s/.venv\n\n' "${REPO_ROOT}"
fi

if ! "${REPO_ROOT}/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
  "${REPO_ROOT}/.venv/bin/python" -m ensurepip --upgrade
fi
printf '\nUpdating Python packaging tools\n\n'
"${REPO_ROOT}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
printf '\nInstalling Python dependencies\n\n'
(
  cd -- "${REPO_ROOT}"
  "${REPO_ROOT}/.venv/bin/python" -m pip install -r requirements.txt
)

printf '\nInstalled dependencies in %s/.venv\n\n' "${REPO_ROOT}"
if [[ "${INSTALL_PATH}" == yes ]]; then
  configure_cli_path
fi
if [[ "${CONFIGURE}" == yes || ( "${CONFIGURE}" == auto && -t 0 && -t 1 ) ]]; then
  printf '\nConfigure an existing live server and OpenAI analysis. Have your API-client YAML path and OpenAI credential environment ready.\n\n'
  "${REPO_ROOT}/vraptor" setup configure
else
  printf '\nNext, configure live-server access and OpenAI in a terminal:\n\n  %q setup configure\n\n' "${REPO_ROOT}/vraptor"
fi
printf '\nUseful commands\n\n'
printf 'Inspect saved settings:\n\n  %q config --server-profile "<SERVER REFERENCE>"\n\n' "${REPO_ROOT}/vraptor"
printf 'Replace <SERVER REFERENCE> with a saved server name; multiple server profiles are supported.\n\n'
printf 'Inspect AI settings:\n\n  %q ai config\n\n' "${REPO_ROOT}/vraptor"
printf 'Check AI dependencies and credentials offline:\n\n  %q ai doctor\n\n' "${REPO_ROOT}/vraptor"
printf 'Configuration is saved separately; a repository .env is optional.\n\n'
printf 'Preview skill links:\n\n  %q --dry-run\n' "${REPO_ROOT}/utils/link-codex-skills.sh"
print_cli_reload

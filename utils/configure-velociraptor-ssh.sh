#!/usr/bin/env bash

set -euo pipefail

KEY_INPUT="${VELO_REMOTE_SSH_KEY:-}"

usage() {
  cat <<'EOF'
Usage: utils/configure-velociraptor-ssh.sh [--key-path <path>]

Load the pinned Velociraptor SSH key into the current user's SSH agent.
On macOS, also store the key passphrase in the user's login Keychain.

Options:
  --key-path <path>  SSH private-key path. Defaults to VELO_REMOTE_SSH_KEY.
  -h, --help         Show this help.

The script never accepts or reads an SSH passphrase. ssh-add obtains any
passphrase directly from the local terminal or operating-system prompt.
EOF
}

error() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

expand_home_path() {
  local value="$1"
  case "$value" in
    '$HOME') value="$HOME" ;;
    '$HOME/'*) value="${HOME}/${value:6}" ;;
    '${HOME}') value="$HOME" ;;
    '${HOME}/'*) value="${HOME}/${value:8}" ;;
    '~') value="$HOME" ;;
    '~/'*) value="${HOME}/${value:2}" ;;
  esac
  printf '%s' "$value"
}

generic_home_path() {
  local value="$1"
  if [[ "$value" == "$HOME" ]]; then
    printf '%s' '$HOME'
  elif [[ "$value" == "$HOME/"* ]]; then
    printf '$HOME/%s' "${value#"$HOME"/}"
  else
    printf '%s' "$value"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key-path)
      [[ $# -ge 2 ]] || error "--key-path requires a value"
      KEY_INPUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      error "unknown option: $1"
      ;;
  esac
done

if [[ -z "$KEY_INPUT" ]]; then
  [[ -t 0 ]] || error "no interactive terminal; rerun with --key-path"
  printf 'Velociraptor SSH private key path: '
  IFS= read -r KEY_INPUT
  [[ -n "$KEY_INPUT" ]] || error "SSH private-key path is required"
fi

KEY_PATH="$(expand_home_path "$KEY_INPUT")"
[[ "$KEY_PATH" == /* ]] || error "SSH key path must resolve to an absolute path: $KEY_INPUT"
[[ -f "$KEY_PATH" ]] || error "SSH private key does not exist: $KEY_PATH"
command -v ssh-add >/dev/null 2>&1 || error "ssh-add is not installed"

if [[ "$(uname -s)" == "Darwin" ]]; then
  # Remove any existing agent and Keychain entry first. This prevents
  # ssh-add from trying a stale Keychain passphrase before prompting for the
  # current one. The removal is expected to fail when the key is not present.
  ssh-add -d --apple-use-keychain "$KEY_PATH" >/dev/null 2>&1 || true
  ssh-add --apple-use-keychain "$KEY_PATH"
  printf 'SSH key added to the current user SSH agent and macOS login Keychain.\n'
else
  ssh-add "$KEY_PATH"
  printf 'SSH key added to the current user SSH agent.\n'
fi

printf 'Keep this non-secret repository setting: VELO_REMOTE_SSH_KEY=%s\n' \
  "$(generic_home_path "$KEY_PATH")"

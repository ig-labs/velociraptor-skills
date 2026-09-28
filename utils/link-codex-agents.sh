#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SOURCE_DIR="${AI_SKILLS_AGENTS_DIR:-${REPO_ROOT}/.codex/agents}"
CODEX_HOME_DIR="${CODEX_HOME:-${HOME}/.codex}"
DEST_DIR="${CODEX_HOME_DIR}/agents"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: utils/link-codex-agents.sh [--dry-run]

Create or update one symlink in $CODEX_HOME/agents for every standalone TOML
custom agent under the repository .codex/agents directory.

Existing real files and directories are never replaced. README files and the
analysis profile settings are not installed.

Environment variables:
  AI_SKILLS_AGENTS_DIR  Override the source custom-agent directory.
  CODEX_HOME            Override the Codex home directory.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ ! -d "${SOURCE_DIR}" ]]; then
  printf 'Custom-agent directory not found: %s\n' "${SOURCE_DIR}" >&2
  exit 1
fi
# Keep logical absolute paths so existing owned retired links still match.
SOURCE_DIR="$(cd -- "${SOURCE_DIR}" && pwd)"

if [[ "${DRY_RUN}" == false ]]; then
  mkdir -p -- "${DEST_DIR}"
fi

# Remove only retired links owned by this source checkout. Preserve real files
# and links to other checkouts, including operator-managed replacements.
for name in case-manager.toml scribe-agent.toml; do
  destination="${DEST_DIR}/${name}"
  source="${SOURCE_DIR}/${name}"
  if [[ ! -e "${source}" && -L "${destination}" && "$(readlink "${destination}")" == "${source}" ]]; then
    if [[ "${DRY_RUN}" == true ]]; then
      printf 'Would unlink retired entry: %s\n' "${destination}"
    else
      rm -- "${destination}"
      printf 'Unlinked retired entry: %s\n' "${destination}"
    fi
  fi
done

linked=0
unchanged=0
conflicts=0
found=0

for source in "${SOURCE_DIR}"/*.toml; do
  [[ -f "${source}" ]] || continue
  found=$((found + 1))
  name="$(basename -- "${source}")"
  destination="${DEST_DIR}/${name}"

  if [[ -L "${destination}" ]]; then
    current_target="$(readlink "${destination}")"
    if [[ "${current_target}" == "${source}" ]]; then
      printf 'Unchanged: %s -> %s\n' "${destination}" "${source}"
      unchanged=$((unchanged + 1))
      continue
    fi
  elif [[ -e "${destination}" ]]; then
    printf 'Conflict: refusing to replace existing path: %s\n' "${destination}" >&2
    conflicts=$((conflicts + 1))
    continue
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    printf 'Would link: %s -> %s\n' "${destination}" "${source}"
  else
    ln -sfn -- "${source}" "${destination}"
    printf 'Linked: %s -> %s\n' "${destination}" "${source}"
  fi
  linked=$((linked + 1))
done

if (( found == 0 )); then
  printf 'No standalone custom-agent TOML files found: %s\n' "${SOURCE_DIR}" >&2
  exit 1
fi

printf 'Summary: linked=%d unchanged=%d conflicts=%d%s\n' \
  "${linked}" "${unchanged}" "${conflicts}" \
  "$([[ "${DRY_RUN}" == true ]] && printf ' (dry run)')"

if (( conflicts > 0 )); then
  exit 1
fi

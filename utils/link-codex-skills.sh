#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SOURCE_DIR="${AI_SKILLS_SKILLS_DIR:-${REPO_ROOT}/skills}"
CODEX_HOME_DIR="${CODEX_HOME:-${HOME}/.codex}"
DEST_DIR="${CODEX_HOME_DIR}/skills"
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: utils/link-codex-skills.sh [--dry-run]

Create or update one symlink in $CODEX_HOME/skills for every directory under
the repository skills/ directory that contains a SKILL.md file.

Existing real files and directories are never replaced.

Environment variables:
  AI_SKILLS_SKILLS_DIR  Override the source skills directory.
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
  printf 'Skills directory not found: %s\n' "${SOURCE_DIR}" >&2
  exit 1
fi

if [[ "${DRY_RUN}" == false ]]; then
  mkdir -p -- "${DEST_DIR}"
fi

linked=0
unchanged=0
conflicts=0

for source in "${SOURCE_DIR}"/*; do
  [[ -d "${source}" ]] || continue
  [[ -f "${source}/SKILL.md" ]] || continue

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

printf 'Summary: linked=%d unchanged=%d conflicts=%d%s\n' \
  "${linked}" "${unchanged}" "${conflicts}" \
  "$([[ "${DRY_RUN}" == true ]] && printf ' (dry run)')"

if (( conflicts > 0 )); then
  exit 1
fi

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

python3 "${SCRIPT_DIR}/validate-public-export.py"

while IFS= read -r -d '' script; do
  bash -n "${script}"
done < <(find "${REPO_ROOT}" -type f -name '*.sh' -print0)

python3 -m compileall -q "${REPO_ROOT}/src/vraptor" "${SCRIPT_DIR}"

"${REPO_ROOT}/dfir" --help >/dev/null
"${REPO_ROOT}/dfir" tools prep --help >/dev/null
"${REPO_ROOT}/dfir" velociraptor --help >/dev/null
"${REPO_ROOT}/vraptor" --help >/dev/null
"${REPO_ROOT}/vraptor" agent config --view defaults >/dev/null
"${REPO_ROOT}/vraptor" tools prep --help >/dev/null
validation_python="${REPO_ROOT}/.venv/bin/python3"
[[ -x "${validation_python}" ]] || validation_python="python3"
PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" \
  "${validation_python}" -c \
  'from vraptor.agent.profiles import load_agent_profile_config; load_agent_profile_config()'

tmp_codex_home="$(mktemp -d)"
cleanup() {
  rm -rf -- "${tmp_codex_home}"
}
trap cleanup EXIT
CODEX_HOME="${tmp_codex_home}" "${SCRIPT_DIR}/link-codex-skills.sh" --dry-run >/dev/null
CODEX_HOME="${tmp_codex_home}" "${SCRIPT_DIR}/link-codex-agents.sh" --dry-run >/dev/null

printf 'Shell, Python, CLI, runtime-profile, skill-link, and agent-link validation passed.\n'

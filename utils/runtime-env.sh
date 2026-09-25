#!/usr/bin/env bash
# Shared environment for the public launchers and legacy script entrypoints.
VRAPTOR_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
. "${VRAPTOR_REPO_ROOT}/src/vraptor/resources/scripts/load_repo_env.sh"
load_repo_env "${VRAPTOR_REPO_ROOT}"
export AI_SKILLS_REPO_ROOT="${VRAPTOR_REPO_ROOT}"
export VELOCIRAPTOR_SKILLS_REPO_ROOT="${VRAPTOR_REPO_ROOT}"
export PYTHONPATH="${VRAPTOR_REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
VRAPTOR_PYTHON="${VRAPTOR_REPO_ROOT}/.venv/bin/python3"
[[ -x "${VRAPTOR_PYTHON}" ]] || VRAPTOR_PYTHON=python3

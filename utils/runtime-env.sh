#!/usr/bin/env bash
# Checkout bootstrap only. Python owns settings and credential resolution.
VRAPTOR_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export AI_SKILLS_REPO_ROOT="${VRAPTOR_REPO_ROOT}"
export VELOCIRAPTOR_SKILLS_REPO_ROOT="${VRAPTOR_REPO_ROOT}"
export PYTHONPATH="${VRAPTOR_REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
VRAPTOR_PYTHON="${VRAPTOR_REPO_ROOT}/.venv/bin/python3"
[[ -x "${VRAPTOR_PYTHON}" ]] || VRAPTOR_PYTHON=python3

#!/usr/bin/env bash

load_repo_env() {
  [[ "${VRAPTOR_SETTINGS_RESOLVED:-}" == "1" ]] && return 0
  local repo_root="${1:?repo root required}"
  local codex_dotenv_path=""
  local dotenv_path="${repo_root}/.env"
  local process_environment_keys=""

  # Preserve source identity for Python-side configuration resolution. This
  # records names only; values and credentials are never copied into metadata.
  process_environment_keys="$(compgen -e | LC_ALL=C sort)"
  export AI_SKILLS_ORIGINAL_PROCESS_ENV_KEYS="${process_environment_keys}"

  if [[ -n "${HOME-}" ]]; then
    codex_dotenv_path="${HOME}/.codex/.env"
  fi

  _load_dotenv_file_safely "${codex_dotenv_path}" "${process_environment_keys}"
  _load_dotenv_file_safely "${dotenv_path}" "${process_environment_keys}"
}

_load_dotenv_file_safely() {
  local dotenv_path="${1-}"
  local inherited_keys="${2-}"
  local line=""
  local key=""
  local value=""
  local quote=""
  local rest=""
  local blanks=$' \t'

  [[ -n "${dotenv_path}" && -f "${dotenv_path}" ]] || return 0

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "${line}" && "${line}" != \#* ]] || continue
    if [[ "${line}" == export[[:space:]]* ]]; then
      line="${line#export}"
      line="${line#"${line%%[![:space:]]*}"}"
    fi
    [[ "${line}" == *=* ]] || continue

    key="${line%%=*}"
    value="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    case "${key}" in
      BASH_ENV|BASHOPTS|CDPATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|ENV|GLOBIGNORE|IFS|LD_LIBRARY_PATH|LD_PRELOAD|NODE_OPTIONS|PATH|PERL5OPT|PROMPT_COMMAND|PS4|PYTHONHOME|PYTHONINSPECT|PYTHONPATH|PYTHONSTARTUP|RUBYOPT|SHELLOPTS)
        continue
        ;;
    esac

    # Values are data, never shell source. Strip one matching quote pair, or
    # keep only the quoted text when a "#" comment follows the closing quote,
    # and drop a comment after a blank in an unquoted value. This matches
    # vraptor.paths.parse_dotenv_value. Variables, substitutions, escapes and
    # globs are deliberately never expanded.
    quote="${value:0:1}"
    if [[ "${quote}" == "'" || "${quote}" == '"' ]]; then
      rest="${value:1}"
      if [[ "${rest}" == *"${quote}"* ]]; then
        if [[ "${rest#*"${quote}"}" =~ ^[${blanks}]*# ]]; then
          value="${rest%%"${quote}"*}"
        elif [[ "${value: -1}" == "${quote}" ]]; then
          value="${value:1:${#value}-2}"
        fi
      fi
    else
      rest="${line#*=}"
      rest="${rest%%[${blanks}]#*}"
      if [[ "${rest}" != *[\"\']* ]]; then
        value="${rest#"${rest%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
      fi
    fi

    # Explicit process values retain precedence. Repository values are loaded
    # after shared values and therefore replace only dotenv-derived defaults.
    if [[ $'\n'"${inherited_keys}"$'\n' == *$'\n'"${key}"$'\n'* ]]; then
      continue
    fi
    printf -v "${key}" '%s' "${value}"
    export "${key}"
  done < "${dotenv_path}"
}

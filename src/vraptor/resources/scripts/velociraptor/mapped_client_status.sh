#!/usr/bin/env bash

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${AI_SKILLS_REPO_ROOT:-$PWD}"
WORKSPACE_DIR="${VELO_MAPPED_CLIENT_WORKSPACE:-${VELO_LOCAL_WORKSPACE:-${REPO_ROOT}/velociraptor}}"
OUTPUT_FORMAT="table"
CLIENT_FILTER=""

usage() {
    printf '%s\n' \
        "Usage:" \
        " ./dfir mapped status [OPTIONS]" \
        "" \
        "Options:" \
        " --workspace <path>  Velociraptor workspace containing mapped-clients/" \
        " --client <name>     Show one mapped client" \
        " --json              Emit a machine-readable JSON array" \
        " -h, --help          Show this help message"
    exit 0
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

absolute_path() {
    local target="$1"
    (
        cd "$target" >/dev/null 2>&1
        pwd -P
    )
}

read_env_value() {
    local file="$1"
    local key="$2"
    [ -f "$file" ] || return 0
    awk -F= -v key="$key" '
        $1 == key {
            sub(/^[^=]*=/, "", $0)
            print
            exit
        }
    ' "$file"
}

pid_running() {
    local pid="$1"
    local identity_file="$2"
    [ -n "$pid" ] && [ -s "$identity_file" ] && kill -0 "$pid" >/dev/null 2>&1 || return 1
    [ "$(ps -p "$pid" -o lstart= -o command= 2>/dev/null)" = "$(cat "$identity_file")" ]
}

json_escape() {
    local value="${1-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

bool_json() {
    if "$@"; then
        printf 'true'
    else
        printf 'false'
    fi
}

client_id_from_info() {
    local client_info_file="$1"

    [ -s "$client_info_file" ] || return 1
    sed -n \
        's/.*"client_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$client_info_file" \
        | head -n 1
}

effective_state() {
    local reported_state="$1"
    local client_pid="$2"
    local supervisor_pid="$3"
    local client_dir="$4"

    if ! pid_running "$supervisor_pid" "${client_dir}/supervisor.pid.identity"; then
        if [ "$reported_state" = "stopped" ]; then
            printf 'stopped'
        else
            printf 'supervisor_dead'
        fi
        return 0
    fi

    if ! pid_running "$client_pid" "${client_dir}/client.pid.identity"; then
        case "$reported_state" in
            identity_error|evidence_unavailable|backoff|waiting_identity|starting)
                printf '%s' "$reported_state"
                ;;
            *)
                printf 'process_dead'
                ;;
        esac
        return 0
    fi

    printf '%s' "${reported_state:-unknown}"
}

emit_json_record() {
    local client_dir="$1"
    local status_file="${client_dir}/client-status.env"
    local session_file="${client_dir}/session.env"
    local client_name=""
    local client_id=""
    local state=""
    local detail=""
    local updated_at=""
    local evidence_path=""
    local mapped_mode=""
    local supervisor_mode=""
    local client_pid=""
    local supervisor_pid=""
    local derived_state=""

    client_name="$(read_env_value "$session_file" "CLIENT_NAME")"
    client_name="${client_name:-$(basename "$client_dir")}"
    client_id="$(read_env_value "$status_file" "CLIENT_ID")"
    if [ -z "$client_id" ] && [ -s "${client_dir}/client.id" ]; then
        client_id="$(head -n 1 "${client_dir}/client.id")"
    fi
    if [ -z "$client_id" ] && [ -s "${client_dir}/Velociraptor.writeback.yaml" ]; then
        client_id="$(sed -n 's/^client_id:[[:space:]]*//p' "${client_dir}/Velociraptor.writeback.yaml" | head -n 1)"
    fi
    if [ -z "$client_id" ]; then
        client_id="$(client_id_from_info "${client_dir}/client-info.json" 2>/dev/null || true)"
    fi
    state="$(read_env_value "$status_file" "STATE")"
    detail="$(read_env_value "$status_file" "DETAIL")"
    updated_at="$(read_env_value "$status_file" "UPDATED_AT")"
    evidence_path="$(read_env_value "$session_file" "EVIDENCE_PATH")"
    mapped_mode="$(read_env_value "$session_file" "MAPPED_CLIENT_MODE")"
    supervisor_mode="$(read_env_value "$status_file" "SUPERVISOR_MODE")"
    supervisor_mode="${supervisor_mode:-$(read_env_value "$session_file" "SUPERVISOR_MODE")}"
    client_pid="$(cat "${client_dir}/client.pid" 2>/dev/null || true)"
    supervisor_pid="$(cat "${client_dir}/supervisor.pid" 2>/dev/null || true)"
    derived_state="$(effective_state "${state:-unknown}" "$client_pid" "$supervisor_pid" "$client_dir")"

    printf '{'
    printf '"client_name":"%s",' "$(json_escape "$client_name")"
    printf '"client_id":"%s",' "$(json_escape "$client_id")"
    printf '"state":"%s",' "$(json_escape "$derived_state")"
    printf '"reported_state":"%s",' "$(json_escape "${state:-unknown}")"
    printf '"detail":"%s",' "$(json_escape "$detail")"
    printf '"updated_at":"%s",' "$(json_escape "$updated_at")"
    printf '"mapped_client_mode":"%s",' "$(json_escape "$mapped_mode")"
    printf '"supervisor_mode":"%s",' "$(json_escape "$supervisor_mode")"
    printf '"evidence_path":"%s",' "$(json_escape "$evidence_path")"
    printf '"client_pid":"%s",' "$(json_escape "$client_pid")"
    printf '"client_process_running":'
    bool_json pid_running "$client_pid" "${client_dir}/client.pid.identity"
    printf ','
    printf '"supervisor_pid":"%s",' "$(json_escape "$supervisor_pid")"
    printf '"supervisor_process_running":'
    bool_json pid_running "$supervisor_pid" "${client_dir}/supervisor.pid.identity"
    printf '}'
}

emit_table_record() {
    local client_dir="$1"
    local status_file="${client_dir}/client-status.env"
    local session_file="${client_dir}/session.env"
    local client_name=""
    local client_id=""
    local state=""
    local client_pid=""
    local supervisor_pid=""
    local client_live="no"
    local supervisor_live="no"
    local derived_state=""

    client_name="$(read_env_value "$session_file" "CLIENT_NAME")"
    client_name="${client_name:-$(basename "$client_dir")}"
    client_id="$(read_env_value "$status_file" "CLIENT_ID")"
    if [ -z "$client_id" ] && [ -s "${client_dir}/client.id" ]; then
        client_id="$(head -n 1 "${client_dir}/client.id")"
    fi
    if [ -z "$client_id" ] && [ -s "${client_dir}/Velociraptor.writeback.yaml" ]; then
        client_id="$(sed -n 's/^client_id:[[:space:]]*//p' "${client_dir}/Velociraptor.writeback.yaml" | head -n 1)"
    fi
    if [ -z "$client_id" ]; then
        client_id="$(client_id_from_info "${client_dir}/client-info.json" 2>/dev/null || true)"
    fi
    state="$(read_env_value "$status_file" "STATE")"
    client_pid="$(cat "${client_dir}/client.pid" 2>/dev/null || true)"
    supervisor_pid="$(cat "${client_dir}/supervisor.pid" 2>/dev/null || true)"
    if pid_running "$client_pid" "${client_dir}/client.pid.identity"; then client_live="yes"; fi
    if pid_running "$supervisor_pid" "${client_dir}/supervisor.pid.identity"; then supervisor_live="yes"; fi
    derived_state="$(effective_state "${state:-unknown}" "$client_pid" "$supervisor_pid" "$client_dir")"

    printf '%-28s %-20s %-22s %-8s %-10s\n' \
        "$client_name" "${client_id:--}" "$derived_state" "$client_live" "$supervisor_live"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --workspace)
            WORKSPACE_DIR="${2:?missing value for --workspace}"
            shift 2
            ;;
        --client)
            CLIENT_FILTER="${2:?missing value for --client}"
            shift 2
            ;;
        --json)
            OUTPUT_FORMAT="json"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown argument: $1"
            ;;
    esac
done

[ -d "$WORKSPACE_DIR" ] || error "Velociraptor workspace does not exist: ${WORKSPACE_DIR}"
WORKSPACE_DIR="$(absolute_path "$WORKSPACE_DIR")"
MAPPED_ROOT="${WORKSPACE_DIR}/mapped-clients"

client_dirs=()
if [ -n "$CLIENT_FILTER" ]; then
    [ -d "${MAPPED_ROOT}/${CLIENT_FILTER}" ] || error "Mapped client not found: ${CLIENT_FILTER}"
    client_dirs+=("${MAPPED_ROOT}/${CLIENT_FILTER}")
elif [ -d "$MAPPED_ROOT" ]; then
    while IFS= read -r client_dir; do
        client_dirs+=("$client_dir")
    done < <(find "$MAPPED_ROOT" -mindepth 1 -maxdepth 1 -type d -print | sort)
fi

if [ "$OUTPUT_FORMAT" = "json" ]; then
    printf '[\n'
    first=1
    for client_dir in "${client_dirs[@]}"; do
        if [ "$first" -eq 0 ]; then
            printf ',\n'
        fi
        printf '  '
        emit_json_record "$client_dir"
        first=0
    done
    printf '\n]\n'
else
    printf '%-28s %-20s %-22s %-8s %-10s\n' "CLIENT" "CLIENT_ID" "STATE" "PROCESS" "SUPERVISOR"
    for client_dir in "${client_dirs[@]}"; do
        emit_table_record "$client_dir"
    done
fi

#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${AI_SKILLS_REPO_ROOT:-$PWD}"
ENV_HELPER="${SCRIPT_DIR}/../load_repo_env.sh"
if [ -f "$ENV_HELPER" ]; then
    # shellcheck source=/dev/null
    . "$ENV_HELPER"
    load_repo_env "$REPO_ROOT"
fi
WORKSPACE_DIR="${VELO_MAPPED_CLIENT_WORKSPACE:-${VELO_LOCAL_WORKSPACE:-${REPO_ROOT}/velociraptor}}"
VELOCIRAPTOR_BIN="${VELO_BIN:-${HOME}/velociraptor/velociraptor}"
SERVER_CONFIG="${WORKSPACE_DIR}/server.config.yaml"
CLIENT_CONFIG="${WORKSPACE_DIR}/client.config.yaml"
API_CLIENT_CONFIG="${WORKSPACE_DIR}/api_client.yaml"
MAPPED_CLIENT_MODE="local_dead_disk"
CLIENT_INFO_WAIT_SECONDS=30
SUPERVISOR_LOOP_SECONDS="${VELO_MAPPED_CLIENT_POLL_SECONDS:-15}"
STALE_SECONDS="${VELO_MAPPED_CLIENT_STALE_SECONDS:-120}"
HEALTH_FAILURE_THRESHOLD="${VELO_MAPPED_CLIENT_FAILURE_THRESHOLD:-3}"
MAX_RESTARTS="${VELO_MAPPED_CLIENT_MAX_RESTARTS:-5}"
RESTART_WINDOW_SECONDS="${VELO_MAPPED_CLIENT_RESTART_WINDOW_SECONDS:-600}"
SUPERVISOR_MODE="${VELO_MAPPED_CLIENT_WATCHDOG_MODE:-nohup}"
VELOCIRAPTOR_API_USER="${VELO_REMOTE_API_USER:-${VELO_LOCAL_API_USER:-codex}}"

EVIDENCE_PATH=""
EVIDENCE_TYPE="auto"
HOSTNAME_OVERRIDE=""
JSON_OUT=""
CLIENT_CONFIG_OVERRIDE=""
API_CLIENT_CONFIG_OVERRIDE=""
CONFIG_BINDING_SHA256=""
WORKSPACE_OVERRIDE=""
VELOCIRAPTOR_BIN_OVERRIDE=""

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

api_query() {
    if [ -n "${VELO_LOCAL_ORG_ID:-}" ]; then
        set -- "--org=${VELO_LOCAL_ORG_ID}" "$@"
    fi
    if "$VELOCIRAPTOR_BIN" -a "$API_CLIENT_CONFIG" "$@"; then
        return 0
    fi

    "$VELOCIRAPTOR_BIN" -a "$API_CLIENT_CONFIG" --runas "$VELOCIRAPTOR_API_USER" "$@"
}

write_env_line() {
    local key="$1"
    local value="${2-}"
    printf '%s=%q\n' "$key" "$value"
}

usage() {
    printf '%s\n' \
        "Usage:" \
        " ./dfir mapped add-remote [OPTIONS] <evidence-path>" \
        "" \
        "Options:" \
        " -n <name>  Override the mapped client hostname shown in Velociraptor" \
        " --evidence-type <auto|windows-disk|windows-directory|velociraptor-export|velociraptor-kapefiles-zip>  Select evidence layout" \
        " --client-config <path>  Use this client config instead of the local workspace client config" \
        " --api-client <path>     Use this API client config for readiness checks instead of the local workspace API config" \
        " --workspace <path>      Runtime directory for mapped-client state" \
        " --velociraptor-bin <path-or-command>  Velociraptor executable; defaults to VELO_BIN" \
        " --foreground            Keep the mapped-client supervisor attached to this terminal" \
        " --mode <mode>           Supervisor mode: nohup or foreground" \
        " --json-out <path>  Write a machine-readable manifest to the given path" \
        " -h         Show this help message" \
        "" \
        "Examples:" \
        " ./dfir mapped add-remote --api-client api.yaml --client-config client.yaml /cases/disk.E01" \
        " ./dfir mapped add-remote --api-client api.yaml --client-config client.yaml -n dead-disk-lab01 /mnt/windows" \
        ""
    exit 0
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

json_field() {
    local key="$1"
    local value="${2-}"
    printf '  "%s": "%s"' "$key" "$(json_escape "$value")"
}

client_id_from_info() {
    local client_info_file="$1"

    [ -s "$client_info_file" ] || return 1
    sed -n \
        's/.*"client_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$client_info_file" \
        | head -n 1
}

write_json_manifest() {
    local output_path="$1"
    local client_name="$2"
    local client_dir="$3"
    local client_config="$4"
    local remap_file="$5"
    local session_file="$6"
    local supervisor_pid_file="$7"
    local supervisor_pid=""
    local client_info_file="${client_dir}/client-info.json"
    local client_id_file="${client_dir}/client.id"
    local client_id=""

    if [ -f "$supervisor_pid_file" ]; then
        supervisor_pid="$(cat "$supervisor_pid_file" 2>/dev/null || true)"
    fi
    if [ -s "$client_id_file" ]; then
        client_id="$(head -n 1 "$client_id_file")"
    fi
    if [ -z "$client_id" ] && [ -s "${client_dir}/Velociraptor.writeback.yaml" ]; then
        client_id="$(sed -n 's/^client_id:[[:space:]]*//p' "${client_dir}/Velociraptor.writeback.yaml" | head -n 1)"
    fi
    if [ -z "$client_id" ]; then
        client_id="$(client_id_from_info "$client_info_file" 2>/dev/null || true)"
    fi

    mkdir -p "$(dirname "$output_path")"
    {
        printf '{\n'
        json_field "status" "ready"
        printf ',\n'
        json_field "mode" "$MAPPED_CLIENT_MODE"
        printf ',\n'
        json_field "workspace_dir" "$WORKSPACE_DIR"
        printf ',\n'
        json_field "api_client_config" "$API_CLIENT_CONFIG"
        printf ',\n'
        json_field "client_name" "$client_name"
        printf ',\n'
        json_field "client_id" "$client_id"
        printf ',\n'
        json_field "client_dir" "$client_dir"
        printf ',\n'
        json_field "client_config" "$client_config"
        printf ',\n'
        json_field "source_client_config" "$CLIENT_CONFIG"
        printf ',\n'
        json_field "remap_file" "$remap_file"
        printf ',\n'
        json_field "evidence_path" "$EVIDENCE_PATH"
        printf ',\n'
        if [ "$EVIDENCE_TYPE" = "velociraptor-export" ] || [ "$EVIDENCE_TYPE" = "velociraptor-kapefiles-zip" ]; then
            json_field "evidence_type" "$EVIDENCE_TYPE"
        elif [ -d "$EVIDENCE_PATH" ]; then
            json_field "evidence_type" "mounted_windows_directory"
        else
            json_field "evidence_type" "disk_image"
        fi
        printf ',\n'
        json_field "client_info_file" "$client_info_file"
        printf ',\n'
        json_field "session_file" "$session_file"
        printf ',\n'
        json_field "gui_url" "$(operator_gui_url)"
        printf ',\n'
        json_field "supervisor_pid" "$supervisor_pid"
        printf ',\n'
        json_field "supervisor_mode" "$SUPERVISOR_MODE"
        printf '\n}\n'
    } >"${output_path}.tmp"
    mv "${output_path}.tmp" "$output_path"
}

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || error "Required command not found: $cmd"
    done
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    case "$value" in
        ""|*[!0-9]*|0)
            error "${name} must be a positive integer: ${value}"
            ;;
    esac
}

absolute_path() {
    local target="$1"
    local dir=""
    local base=""

    if [ -d "$target" ]; then
        (
            cd "$target" >/dev/null 2>&1 && pwd -P
        ) || return 1
        return 0
    fi

    dir="$(dirname "$target")"
    base="$(basename "$target")"

    dir="$(absolute_path "$dir")" || return 1
    case "$base" in
        .) printf '%s\n' "$dir" ;;
        ..) dirname "$dir" ;;
        *) printf '%s/%s\n' "${dir%/}" "$base" ;;
    esac
}

resolve_executable() {
    local target="$1"
    local resolved=""

    target="${target/#\~/${HOME}}"
    if [[ "$target" == */* ]]; then
        resolved="$(absolute_path "$target")" || return 1
        [ -x "$resolved" ] || return 1
        printf '%s\n' "$resolved"
        return 0
    fi

    resolved="$(command -v "$target" 2>/dev/null || true)"
    [ -n "$resolved" ] && [ -x "$resolved" ] || return 1
    printf '%s\n' "$resolved"
}

read_yaml_section_value() {
    local file="$1"
    local section="$2"
    local key="$3"

    awk -v section="$section" -v key="$key" '
        $0 ~ ("^" section ":") { in_section=1; next }
        in_section && $0 ~ /^[^[:space:]]/ { in_section=0 }
        in_section {
            gsub(/^[[:space:]]+/, "", $0)
            if ($0 ~ ("^" key ":")) {
                sub("^" key ":[[:space:]]*", "", $0)
                print $0
                exit
            }
        }
    ' "$file"
}

gui_host() {
    local host=""
    if [ -f "$SERVER_CONFIG" ]; then
        host="$(read_yaml_section_value "$SERVER_CONFIG" "GUI" "bind_address" || true)"
    fi

    case "$host" in
        ""|0.0.0.0|::) echo "127.0.0.1" ;;
        *) echo "$host" ;;
    esac
}

gui_port() {
    local port=""
    if [ -f "$SERVER_CONFIG" ]; then
        port="$(read_yaml_section_value "$SERVER_CONFIG" "GUI" "bind_port" || true)"
    fi

    if [ -n "$port" ]; then
        echo "$port"
    else
        echo "8889"
    fi
}

api_port() {
    local port=""
    if [ -f "$SERVER_CONFIG" ]; then
        port="$(read_yaml_section_value "$SERVER_CONFIG" "API" "bind_port" || true)"
    fi

    if [ -n "$port" ]; then
        echo "$port"
    else
        echo "8001"
    fi
}

gui_url() {
    printf 'https://%s:%s/app/index.html' "$(gui_host)" "$(gui_port)"
}

operator_gui_url() {
    if [ "$MAPPED_CLIENT_MODE" = "local_dead_disk" ]; then
        gui_url
    fi
}

listener_running() {
    local port="$1"

    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
        return $?
    fi

    if command -v nc >/dev/null 2>&1; then
        nc -z "$(gui_host)" "$port" >/dev/null 2>&1
        return $?
    fi

    return 1
}

gui_running() {
    if listener_running "$(gui_port)" && listener_running "$(api_port)"; then
        return 0
    fi

    curl -ksSf --max-time 2 "$(gui_url)" >/dev/null 2>&1
}

ensure_workspace_ready() {
    [ -x "$VELOCIRAPTOR_BIN" ] || error "Velociraptor binary not found or not executable: ${VELOCIRAPTOR_BIN}. Set VELO_BIN or pass --velociraptor-bin."
    if [ "$MAPPED_CLIENT_MODE" = "local_dead_disk" ]; then
        [ -f "$SERVER_CONFIG" ] || error "Velociraptor server config not found: ${SERVER_CONFIG}"
    fi
    [ -f "$CLIENT_CONFIG" ] || error "Velociraptor client config not found: ${CLIENT_CONFIG}"
    [ -f "$API_CLIENT_CONFIG" ] || error "Velociraptor API config not found: ${API_CLIENT_CONFIG}"
}

start_gui_if_needed() {
    if gui_running; then
        info "Velociraptor GUI is already reachable at $(gui_url)"
        return 0
    fi

    error "Local server is unavailable. Start it with vraptor setup start --mode local-deaddisk."
}

safe_name() {
    local input="$1"
    printf '%s' "$input" \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//'
}

normalize_hostname_base() {
    local base="$1"

    printf '%s' "$base" | sed -E '
        s/([._-])(disk|image|img|mem|memory)$//;
        s/([._-])([a-z])drive$//;
        s/([._-])drive$//;
        s/[._-]+$//
    '
}

default_hostname() {
    local source="$1"
    local base=""

    base="$(basename "$source")"
    base="${base%%.*}"
    base="$(safe_name "$base")"
    base="$(normalize_hostname_base "$base")"

    if [ -n "$base" ]; then
        printf '%s' "$base"
    else
        printf 'mapped-client'
    fi
}

read_env_value() {
    local file="$1"
    local key="$2"

    awk -F= -v key="$key" '
        $1 == key {
            sub(/^[^=]*=/, "", $0)
            print
            exit
        }
    ' "$file"
}

process_matches() {
    local pid="${1:-}"
    local identity_file="$2"
    [ -n "$pid" ] && [ -s "$identity_file" ] && kill -0 "$pid" >/dev/null 2>&1 || return 1
    [ "$(ps -p "$pid" -o lstart= -o command= 2>/dev/null)" = "$(cat "$identity_file")" ]
}

prepare_remote_client_runtime() {
    local client_dir="$1"
    local session_file="${client_dir}/session.env"
    local key="" expected="" actual=""
    if [ -f "$session_file" ]; then
        for key in API_CLIENT_CONFIG SOURCE_CLIENT_CONFIG EVIDENCE_PATH; do
            case "$key" in
                API_CLIENT_CONFIG) expected="$API_CLIENT_CONFIG" ;;
                SOURCE_CLIENT_CONFIG) expected="$CLIENT_CONFIG" ;;
                EVIDENCE_PATH) expected="$EVIDENCE_PATH" ;;
            esac
            expected="$(printf '%q' "$expected")"
            actual="$(read_env_value "$session_file" "$key")"
            [ "$actual" = "$expected" ] || error "Mapping ${key} differs from saved state; identity preserved. Use a separate workspace."
        done
    fi
    if [ -s "${client_dir}/client.id" ] && [ ! -s "${client_dir}/Velociraptor.writeback.yaml" ]; then
        error "Mapped writeback is missing; restore the original writeback before resuming."
    fi
    [ ! -s "${client_dir}/supervisor.hold" ] || error "Mapping is held after an identity error; preserve writeback and investigate before resuming."
    CONFIG_BINDING_SHA256="$("${VRAPTOR_PYTHON:-python3}" -m vraptor.lifecycle \
        "$API_CLIENT_CONFIG" "$CLIENT_CONFIG" "$session_file")" || \
        error "Credential binding validation failed; saved identity was preserved."
}

validate_evidence_path() {
    [ -e "$EVIDENCE_PATH" ] || error "Evidence path does not exist: ${EVIDENCE_PATH}"

    EVIDENCE_PATH="$(absolute_path "$EVIDENCE_PATH")" || \
        error "Failed to resolve evidence path: ${EVIDENCE_PATH}"

    if [ -f "$EVIDENCE_PATH" ]; then
        local size
        size="$(wc -c < "$EVIDENCE_PATH" | tr -d '[:space:]')"
        if [ "${size:-0}" -lt 1024 ]; then
            warn "Evidence file is smaller than 1 KiB: ${EVIDENCE_PATH}"
            warn "Small text placeholders are not valid dead-disk images."
        fi
    fi
}

validate_remap_file() {
    local remap_file="$1"

    [ -s "$remap_file" ] || error "Remapping file was not created: ${remap_file}"

    if grep -qx 'remappings: true' "$remap_file"; then
        error "Generated remapping file is only a placeholder. Verify the evidence path points to a real image or mounted Windows directory."
    fi

    grep -q 'type: mount' "$remap_file" || \
        error "Generated remapping file does not contain any mount directives: ${remap_file}"
}

write_session_file() {
    local session_file="$1"
    local client_name="$2"
    local remap_file="$3"
    local client_pid="$4"
    local client_config="$5"
    local client_info_file="$6"
    local client_info_status="$7"
    local supervisor_pid="${8-}"
    local client_id=""
    client_id="$(current_writeback_client_id "$(dirname "$session_file")" 2>/dev/null || true)"

    {
        write_env_line "CLIENT_NAME" "$client_name"
        write_env_line "CLIENT_ID" "$client_id"
        write_env_line "EVIDENCE_PATH" "$EVIDENCE_PATH"
        write_env_line "REMAP_FILE" "$remap_file"
        write_env_line "CLIENT_PID" "$client_pid"
        write_env_line "CLIENT_CONFIG" "$client_config"
        write_env_line "SOURCE_CLIENT_CONFIG" "$CLIENT_CONFIG"
        write_env_line "CONFIG_BINDING_SHA256" "$CONFIG_BINDING_SHA256"
        write_env_line "API_CLIENT_CONFIG" "$API_CLIENT_CONFIG"
        write_env_line "VELOCIRAPTOR_BIN" "$VELOCIRAPTOR_BIN"
        write_env_line "WORKSPACE_DIR" "$WORKSPACE_DIR"
        write_env_line "MAPPED_CLIENT_MODE" "$MAPPED_CLIENT_MODE"
        write_env_line "GUI_URL" "$(operator_gui_url)"
        write_env_line "STARTED_AT" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        write_env_line "CLIENT_INFO_FILE" "$client_info_file"
        write_env_line "CLIENT_INFO_STATUS" "$client_info_status"
        write_env_line "SUPERVISOR_PID" "$supervisor_pid"
        write_env_line "SUPERVISOR_MODE" "$SUPERVISOR_MODE"
        write_env_line "SUPERVISOR_LOOP_SECONDS" "$SUPERVISOR_LOOP_SECONDS"
        write_env_line "STALE_SECONDS" "$STALE_SECONDS"
        write_env_line "HEALTH_FAILURE_THRESHOLD" "$HEALTH_FAILURE_THRESHOLD"
        write_env_line "MAX_RESTARTS" "$MAX_RESTARTS"
        write_env_line "RESTART_WINDOW_SECONDS" "$RESTART_WINDOW_SECONDS"
    } >"${session_file}.tmp"
    mv "${session_file}.tmp" "$session_file"
}

regex_escape() {
    printf '%s' "$1" | sed -e 's/[][(){}.^$*+?|\/\\]/\\&/g'
}

build_client_id_info_vql() {
    local client_id="$1"
    local escaped_client_id=""
    local escaped_hostname=""
    escaped_hostname="$(regex_escape "$2")"

    escaped_client_id="$(regex_escape "$client_id")"

    printf '%s' \
        "SELECT client_id," \
        "timestamp(epoch=first_seen_at) as FirstSeen," \
        "timestamp(epoch=last_seen_at) as LastSeen," \
        "os_info.hostname as Hostname," \
        "os_info.fqdn as Fqdn," \
        "os_info.system as OSType," \
        "os_info.release as OS," \
        "os_info.machine as Machine," \
        "agent_information.version as AgentVersion " \
        "FROM clients() WHERE client_id =~ '^${escaped_client_id}$' AND (os_info.hostname =~ '^${escaped_hostname}$' OR os_info.fqdn =~ '^${escaped_hostname}$') ORDER BY LastSeen DESC LIMIT 1"
}

current_writeback_client_id() {
    local client_dir="$1"
    local writeback_file="${client_dir}/Velociraptor.writeback.yaml"

    [ -f "$writeback_file" ] || return 1
    sed -n 's/^client_id:[[:space:]]*//p' "$writeback_file" | head -n 1
}

find_client_info() {
    local hostname="$1"
    local client_info_file="$2"
    local client_info_log="$3"
    local expected_client_id="${4-}"
    local tmp_file="${client_info_file}.tmp"
    local vql=""

    [ -n "$expected_client_id" ] || return 1
    vql="$(build_client_id_info_vql "$expected_client_id" "$hostname")"

    if ! api_query query --format json "$vql" >"$tmp_file" 2>>"$client_info_log"; then
        rm -f "$tmp_file"
        return 1
    fi

    mv "$tmp_file" "$client_info_file"
    grep -q '"client_id"' "$client_info_file"
}

wait_for_client_info() {
    local hostname="$1"
    local client_dir="$2"
    local expected_client_id="${3-}"
    local client_info_file="${client_dir}/client-info.json"
    local client_info_log="${client_dir}/client-info.log"
    local tries=0
    local current_client_id=""

    : >"$client_info_log"

    while [ "$tries" -lt "$CLIENT_INFO_WAIT_SECONDS" ]; do
        current_client_id="$expected_client_id"
        if [ -z "$current_client_id" ]; then
            current_client_id="$(current_writeback_client_id "$client_dir" 2>/dev/null || true)"
        fi

        if find_client_info "$hostname" "$client_info_file" "$client_info_log" "$current_client_id"; then
            return 0
        fi

        sleep 1
        tries=$((tries + 1))
    done

    return 1
}

escape_sed_replacement() {
    printf '%s' "$1" | sed 's/[\/&]/\\&/g'
}

build_client_config() {
    local client_dir="$1"
    local client_config="${client_dir}/client.config.yaml"
    local writeback_file="${client_dir}/Velociraptor.writeback.yaml"
    local temp_dir="${client_dir}/temp"
    local escaped_writeback_file=""
    local escaped_temp_dir=""

    mkdir -p "$temp_dir"
    cp "$CLIENT_CONFIG" "$client_config"

    escaped_writeback_file="$(escape_sed_replacement "$writeback_file")"
    escaped_temp_dir="$(escape_sed_replacement "$temp_dir")"

    sed -i.bak \
        -e "s|^  writeback_darwin: .*|  writeback_darwin: ${escaped_writeback_file}|" \
        -e "s|^  writeback_linux: .*|  writeback_linux: ${escaped_writeback_file}|" \
        -e "s|^  writeback_windows: .*|  writeback_windows: ${escaped_writeback_file}|" \
        -e "s|^  tempdir_linux: .*|  tempdir_linux: ${escaped_temp_dir}|" \
        -e "s|^  tempdir_windows: .*|  tempdir_windows: ${escaped_temp_dir}|" \
        -e "s|^  tempdir_darwin: .*|  tempdir_darwin: ${escaped_temp_dir}|" \
        "$client_config"
    rm -f "${client_config}.bak"

    printf '%s\n' "$client_config"
}

start_mapped_client() {
    local client_name="$1"
    local client_dir="$2"
    local remap_file="$3"
    local client_config="$4"
    local client_log="${client_dir}/client.log"
    local client_pid_file="${client_dir}/client.pid"
    local supervisor_pid_file="${client_dir}/supervisor.pid"
    local supervisor_log="${client_dir}/supervisor.log"
    local session_file="${client_dir}/session.env"
    local client_info_file="${client_dir}/client-info.json"
    local client_info_status="pending"
    local existing_pid=""
    local supervisor_pid=""
    local expected_client_id=""
    local supervisor_args=()

    if [ -f "$supervisor_pid_file" ]; then
        supervisor_pid="$(cat "$supervisor_pid_file" 2>/dev/null || true)"
        if process_matches "$supervisor_pid" "${supervisor_pid_file}.identity"; then
            existing_pid="$(cat "$client_pid_file" 2>/dev/null || true)"
            info "Mapped client supervisor for ${client_name} is already running with PID ${supervisor_pid}"
            expected_client_id="$(current_writeback_client_id "$client_dir" 2>/dev/null || true)"
            if wait_for_client_info "$client_name" "$client_dir" "$expected_client_id"; then
                client_info_status="found"
            fi
            write_session_file "$session_file" "$client_name" "$remap_file" "$existing_pid" "$client_config" "$client_info_file" "$client_info_status" "$supervisor_pid"
            [ "$client_info_status" = "found" ] || error "Cannot verify mapped hostname ${client_name}; inspect ${client_log} and verify the binary retains --remap impersonation."
            return 0
        fi
        if [ -n "$supervisor_pid" ] && kill -0 "$supervisor_pid" 2>/dev/null; then
            error "Supervisor PID has no matching ownership identity; refusing duplicate startup."
        fi
    fi

    supervisor_args=(
        "$WORKSPACE_DIR"
        "$client_name"
        "$client_dir"
        "$client_config"
        "$remap_file"
        "$API_CLIENT_CONFIG"
        "$SUPERVISOR_LOOP_SECONDS"
        "$STALE_SECONDS"
        "$HEALTH_FAILURE_THRESHOLD"
        "$MAX_RESTARTS"
        "$RESTART_WINDOW_SECONDS"
        "$EVIDENCE_PATH"
        "$SUPERVISOR_MODE"
        "$VELOCIRAPTOR_BIN"
    )

    if [ "$SUPERVISOR_MODE" = "foreground" ]; then
        info "Starting mapped Velociraptor client supervisor in foreground mode: ${client_name}"
        info "Keep this terminal/session open; status is written to ${client_dir}/client-status.env"
        write_session_file "$session_file" "$client_name" "$remap_file" "" "$client_config" "$client_info_file" "pending" "$$"
        release_mapping_lock
        cd "$WORKSPACE_DIR"
        exec bash "${SCRIPT_DIR}/supervise_mapped_client.sh" "${supervisor_args[@]}"
    fi

    write_session_file "$session_file" "$client_name" "$remap_file" "" "$client_config" "$client_info_file" "pending" ""
    info "Starting mapped Velociraptor client supervisor: ${client_name}"
    (
        cd "$WORKSPACE_DIR"
        nohup bash "${SCRIPT_DIR}/supervise_mapped_client.sh" \
            "${supervisor_args[@]}" >"$supervisor_log" 2>&1 &
        disown "$!" 2>/dev/null || true
    )

    sleep 2

    supervisor_pid="$(cat "$supervisor_pid_file")"
    if ! process_matches "$supervisor_pid" "${supervisor_pid_file}.identity"; then
        warn "Mapped client supervisor exited early. Check: ${supervisor_log}"
        return 1
    fi

    sleep 2
    local client_pid=""
    client_pid="$(cat "$client_pid_file" 2>/dev/null || true)"

    expected_client_id="$(current_writeback_client_id "$client_dir" 2>/dev/null || true)"
    if wait_for_client_info "$client_name" "$client_dir" "$expected_client_id"; then
        client_info_status="found"
    else
        warn "Client info was not available yet for ${client_name}. Check: ${client_dir}/client-info.log"
    fi

    write_session_file "$session_file" "$client_name" "$remap_file" "$client_pid" "$client_config" "$client_info_file" "$client_info_status" "$supervisor_pid"
    [ "$client_info_status" = "found" ] || error "Cannot verify mapped hostname ${client_name}; inspect ${client_log} and verify the binary retains --remap impersonation."
    success "Mapped client ${client_name} is supervised by PID ${supervisor_pid}"
    if [ -n "$client_pid" ]; then
        info "Current client PID: ${client_pid}"
    fi
    info "Supervisor log: ${supervisor_log}"
    info "Client log: ${client_log}"
}

build_remap() {
    local client_name="$1"
    local client_dir="$2"
    local remap_file="${client_dir}/remapping.yaml"

    if [ -d "$EVIDENCE_PATH" ]; then
        info "Generating remapping from mounted Windows directory"
        (
            cd "$WORKSPACE_DIR"
            "$VELOCIRAPTOR_BIN" deaddisk --hostname "$client_name" --add_windows_directory "$EVIDENCE_PATH" "$remap_file"
        )
    else
        info "Generating remapping from disk image"
        (
            cd "$WORKSPACE_DIR"
            "$VELOCIRAPTOR_BIN" deaddisk --hostname "$client_name" --add_windows_disk "$EVIDENCE_PATH" "$remap_file"
        )
    fi

    validate_remap_file "$remap_file"
    success "Remapping file created at: ${remap_file}"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -n)
            HOSTNAME_OVERRIDE="${2:?missing value for -n}"
            shift 2
            ;;
        --client-config)
            CLIENT_CONFIG_OVERRIDE="${2:?missing value for --client-config}"
            shift 2
            ;;
        --api-client)
            API_CLIENT_CONFIG_OVERRIDE="${2:?missing value for --api-client}"
            shift 2
            ;;
        --workspace)
            WORKSPACE_OVERRIDE="${2:?missing value for --workspace}"
            shift 2
            ;;
        --evidence-type)
            EVIDENCE_TYPE="${2:?missing value for --evidence-type}"
            shift 2
            ;;
        --velociraptor-bin)
            VELOCIRAPTOR_BIN_OVERRIDE="${2:?missing value for --velociraptor-bin}"
            shift 2
            ;;
        --foreground)
            SUPERVISOR_MODE="foreground"
            shift
            ;;
        --mode)
            SUPERVISOR_MODE="${2:?missing value for --mode}"
            shift 2
            ;;
        --json-out)
            JSON_OUT="${2:?missing value for --json-out}"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            break
            ;;
        -*)
            error "Unknown argument: $1"
            ;;
        *)
            break
            ;;
    esac
done

if [ "$#" -ne 1 ]; then
    usage
fi

EVIDENCE_PATH="$1"
require_cmd curl awk sed basename wc date grep

if [ -n "$CLIENT_CONFIG_OVERRIDE" ] &&
   [ -n "$API_CLIENT_CONFIG_OVERRIDE" ] &&
   [ -z "${VELO_MAPPED_CLIENT_STALE_SECONDS:-}" ]; then
    STALE_SECONDS=600
fi

case "$SUPERVISOR_MODE" in
    nohup|foreground) ;;
    *) error "Unsupported supervisor mode: ${SUPERVISOR_MODE}. Use nohup or foreground." ;;
esac

require_positive_integer "VELO_MAPPED_CLIENT_POLL_SECONDS" "$SUPERVISOR_LOOP_SECONDS"
require_positive_integer "VELO_MAPPED_CLIENT_STALE_SECONDS" "$STALE_SECONDS"
require_positive_integer "VELO_MAPPED_CLIENT_FAILURE_THRESHOLD" "$HEALTH_FAILURE_THRESHOLD"
require_positive_integer "VELO_MAPPED_CLIENT_MAX_RESTARTS" "$MAX_RESTARTS"
require_positive_integer "VELO_MAPPED_CLIENT_RESTART_WINDOW_SECONDS" "$RESTART_WINDOW_SECONDS"

if [ "$SUPERVISOR_MODE" = "nohup" ]; then
    require_cmd nohup
fi

if [ "$SUPERVISOR_MODE" = "foreground" ] && [ -n "$JSON_OUT" ]; then
    error "--json-out cannot be combined with foreground mode because the supervisor does not return"
fi

validate_evidence_path
WORKSPACE_DIR="${WORKSPACE_OVERRIDE:-$WORKSPACE_DIR}"
WORKSPACE_DIR="$(absolute_path "${WORKSPACE_DIR/#\~/${HOME}}")" || \
    error "Failed to resolve mapped-client workspace"
for output_path in "$WORKSPACE_DIR" "${JSON_OUT:-$WORKSPACE_DIR}"; do
    output_path="$(absolute_path "$output_path")" || error "Failed to resolve output path"
    if [ "$output_path" = "$EVIDENCE_PATH" ] || [ "$output_path" -ef "$EVIDENCE_PATH" ]; then
        error "Setup outputs must be outside the evidence source"
    fi
    if [ -d "$EVIDENCE_PATH" ]; then
        case "$output_path" in
            "${EVIDENCE_PATH%/}"/*) error "Setup outputs must be outside the evidence source" ;;
        esac
    fi
done
mkdir -p "$WORKSPACE_DIR"

SERVER_CONFIG="${WORKSPACE_DIR}/server.config.yaml"
CLIENT_CONFIG="${WORKSPACE_DIR}/client.config.yaml"
API_CLIENT_CONFIG="${WORKSPACE_DIR}/api_client.yaml"

if [ -n "$VELOCIRAPTOR_BIN_OVERRIDE" ]; then
    VELOCIRAPTOR_BIN="$(resolve_executable "$VELOCIRAPTOR_BIN_OVERRIDE")" || \
        error "Failed to resolve Velociraptor executable: ${VELOCIRAPTOR_BIN_OVERRIDE}"
else
    VELOCIRAPTOR_BIN="$(resolve_executable "$VELOCIRAPTOR_BIN")" || \
        error "Failed to resolve Velociraptor executable: ${VELOCIRAPTOR_BIN}"
fi

if [ -n "$CLIENT_CONFIG_OVERRIDE" ] || [ -n "$API_CLIENT_CONFIG_OVERRIDE" ]; then
    [ -n "$CLIENT_CONFIG_OVERRIDE" ] || error "--client-config is required when --api-client is provided"
    [ -n "$API_CLIENT_CONFIG_OVERRIDE" ] || error "--api-client is required when --client-config is provided"
    CLIENT_CONFIG="$(absolute_path "${CLIENT_CONFIG_OVERRIDE/#\~/${HOME}}")" || \
        error "Failed to resolve client config path: ${CLIENT_CONFIG_OVERRIDE}"
    API_CLIENT_CONFIG="$(absolute_path "${API_CLIENT_CONFIG_OVERRIDE/#\~/${HOME}}")" || \
        error "Failed to resolve API client config path: ${API_CLIENT_CONFIG_OVERRIDE}"
    MAPPED_CLIENT_MODE="remote_dead_disk"
fi

ensure_workspace_ready

CLIENT_NAME="${HOSTNAME_OVERRIDE:-$(default_hostname "$EVIDENCE_PATH")}"
CLIENT_DIR="${WORKSPACE_DIR}/mapped-clients/${CLIENT_NAME}"
CLIENT_RUNTIME_CONFIG=""

[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || error "Invalid mapped client hostname: ${CLIENT_NAME}"

mkdir -p "$CLIENT_DIR"
MAPPING_LOCK="${CLIENT_DIR}/.ensure.lock"
release_mapping_lock() { rm -f "${MAPPING_LOCK}/pid" "${MAPPING_LOCK}/identity"; rmdir "$MAPPING_LOCK" 2>/dev/null || true; }
if ! mkdir "$MAPPING_LOCK" 2>/dev/null; then
    lock_pid="$(cat "${MAPPING_LOCK}/pid" 2>/dev/null || true)"
    [ -n "$lock_pid" ] && [ -s "${MAPPING_LOCK}/identity" ] || error "Mapping lock is incomplete; inspect ${MAPPING_LOCK} before retrying."
    if process_matches "$lock_pid" "${MAPPING_LOCK}/identity"; then
        error "Another mapped-client setup is running."
    fi
    release_mapping_lock
    mkdir "$MAPPING_LOCK" 2>/dev/null || error "Another mapped-client setup acquired the lock."
fi
ps -p "$$" -o lstart= -o command= >"${MAPPING_LOCK}/identity"
printf '%s\n' "$$" >"${MAPPING_LOCK}/pid"
trap release_mapping_lock EXIT
prepare_remote_client_runtime "$CLIENT_DIR"

if [ "$MAPPED_CLIENT_MODE" = "local_dead_disk" ]; then
    start_gui_if_needed || error "Failed to start or reach the Velociraptor GUI"
else
    info "Using external Velociraptor API and client config; local GUI startup is not required"
fi
EVIDENCE_TYPE="$("${VRAPTOR_PYTHON:-python3}" -m vraptor.export_mapping \
    "$EVIDENCE_PATH" "${CLIENT_DIR}/remapping.yaml" "$VELOCIRAPTOR_BIN" "$CLIENT_NAME" \
    --evidence-type "$EVIDENCE_TYPE")" || error "Evidence layout validation failed; saved remap preserved"
if [ ! -s "${CLIENT_DIR}/remapping.yaml" ]; then
    build_remap "$CLIENT_NAME" "$CLIENT_DIR"
fi
validate_remap_file "${CLIENT_DIR}/remapping.yaml"
CLIENT_RUNTIME_CONFIG="${CLIENT_DIR}/client.config.yaml"
if [ ! -s "$CLIENT_RUNTIME_CONFIG" ]; then
    CLIENT_RUNTIME_CONFIG="$(build_client_config "$CLIENT_DIR")"
fi
start_mapped_client "$CLIENT_NAME" "$CLIENT_DIR" "${CLIENT_DIR}/remapping.yaml" "$CLIENT_RUNTIME_CONFIG" || \
    error "Failed to start the mapped client for ${EVIDENCE_PATH}"

if [ -n "$JSON_OUT" ]; then
    write_json_manifest \
        "$JSON_OUT" \
        "$CLIENT_NAME" \
        "$CLIENT_DIR" \
        "$CLIENT_RUNTIME_CONFIG" \
        "${CLIENT_DIR}/remapping.yaml" \
        "${CLIENT_DIR}/session.env" \
        "${CLIENT_DIR}/supervisor.pid"
fi

if [ "$MAPPED_CLIENT_MODE" = "local_dead_disk" ]; then
    success "Mapped client ready. Open $(gui_url) and look for host: ${CLIENT_NAME}"
else
    success "Mapped client ready on the external Velociraptor server. Look for host: ${CLIENT_NAME}"
    info "External API client config: ${API_CLIENT_CONFIG}"
fi
info "Client workspace: ${CLIENT_DIR}"
info "Client config: ${CLIENT_RUNTIME_CONFIG}"
info "Client log: ${CLIENT_DIR}/client.log"
info "Supervisor log: ${CLIENT_DIR}/supervisor.log"

#!/usr/bin/env bash

set -uo pipefail
umask 077

usage() {
    printf '%s\n' \
        "Usage:" \
        " bash ./src/vraptor/resources/scripts/velociraptor/supervise_mapped_client.sh \\" \
        "   <workspace-dir> <client-name> <client-dir> <client-config> <remap-file> <api-client-config> \\" \
        "   [supervisor-loop-seconds] [stale-seconds] [health-failure-threshold] \\" \
        "   [max-restarts] [restart-window-seconds] [evidence-path] [foreground|nohup] [velociraptor-bin]" \
        "" \
        "Internal supervisor used by add_mapped_client.sh. Most operators should use:" \
        " ./dfir mapped add-remote [OPTIONS] <evidence-path>"
    exit 0
}

case "${1-}" in
    -h|--help) usage ;;
esac

WORKSPACE_DIR="${1:?workspace dir required}"
CLIENT_NAME="${2:?client name required}"
CLIENT_DIR="${3:?client dir required}"
CLIENT_CONFIG="${4:?client config required}"
REMAP_FILE="${5:?remap file required}"
API_CLIENT_CONFIG="${6:?api client config required}"
SUPERVISOR_LOOP_SECONDS="${7:-15}"
STALE_SECONDS="${8:-120}"
HEALTH_FAILURE_THRESHOLD="${9:-3}"
MAX_RESTARTS="${10:-5}"
RESTART_WINDOW_SECONDS="${11:-600}"
EVIDENCE_PATH="${12:-}"
SUPERVISOR_MODE="${13:-foreground}"
VELOCIRAPTOR_BIN="${14:-${VELO_BIN:-${HOME}/velociraptor/velociraptor}}"
VELOCIRAPTOR_API_USER="${VELO_REMOTE_API_USER:-${VELO_LOCAL_API_USER:-codex}}"

CLIENT_PID_FILE="${CLIENT_DIR}/client.pid"
SUPERVISOR_PID_FILE="${CLIENT_DIR}/supervisor.pid"
STATUS_FILE="${CLIENT_DIR}/client-status.env"
CLIENT_ID_FILE="${CLIENT_DIR}/client.id"
CLIENT_LOG="${CLIENT_DIR}/client.log"
WRITEBACK_FILE="${CLIENT_DIR}/Velociraptor.writeback.yaml"
RESTART_HISTORY_FILE="${CLIENT_DIR}/restart-history.tsv"
NEXT_RESTART_FILE="${CLIENT_DIR}/next-restart-epoch"
SUPERVISOR_HOLD_FILE="${CLIENT_DIR}/supervisor.hold"

info() { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

require_positive_integer() {
    local name="$1"
    local value="$2"
    case "$value" in
        ""|*[!0-9]*|0)
            error "${name} must be a positive integer: ${value}"
            ;;
    esac
}

api_query() {
    if [ -n "${VELO_LOCAL_ORG_ID:-}" ]; then
        set -- "--org=${VELO_LOCAL_ORG_ID}" "$@"
    fi
    if "$VELOCIRAPTOR_BIN" -a "$API_CLIENT_CONFIG" "$@"; then
        return 0
    fi

    "$VELOCIRAPTOR_BIN" -a "$API_CLIENT_CONFIG" --runas "$VELOCIRAPTOR_API_USER" "$@"
}

write_status() {
    local state="$1"
    local detail="${2-}"
    local client_id=""
    client_id="$(current_client_id 2>/dev/null || true)"
    {
        printf 'STATE=%q\n' "$state"
        printf 'DETAIL=%q\n' "$detail"
        printf 'CLIENT_ID=%q\n' "$client_id"
        printf 'CLIENT_PID=%q\n' "$(current_client_pid)"
        printf 'SUPERVISOR_PID=%q\n' "$$"
        printf 'SUPERVISOR_MODE=%q\n' "$SUPERVISOR_MODE"
        printf 'UPDATED_AT=%q\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } >"${STATUS_FILE}.tmp"
    mv "${STATUS_FILE}.tmp" "$STATUS_FILE"
}

regex_escape() {
    printf '%s' "$1" | sed -e 's/[][(){}.^$*+?|\/\\]/\\&/g'
}

api_reachable() {
    api_query query --format json "SELECT 1 AS ok FROM scope()" >/dev/null 2>&1
}

current_client_id() {
    local client_id=""

    if [ -s "$WRITEBACK_FILE" ]; then
        client_id="$(sed -n 's/^client_id:[[:space:]]*//p' "$WRITEBACK_FILE" | head -n 1)"
    fi
    if [ -z "$client_id" ] && [ -s "$CLIENT_ID_FILE" ]; then
        client_id="$(head -n 1 "$CLIENT_ID_FILE")"
    fi
    if [ -n "$client_id" ]; then
        printf '%s\n' "$client_id" >"$CLIENT_ID_FILE"
        printf '%s\n' "$client_id"
        return 0
    fi
    return 1
}

client_record_json() {
    local client_id="$1"
    local escaped_client_id=""
    escaped_client_id="$(regex_escape "$client_id")"

    api_query query --format json \
        "SELECT client_id, last_seen_at, os_info.hostname AS hostname, os_info.fqdn AS fqdn FROM clients() WHERE client_id =~ '^${escaped_client_id}$' LIMIT 1" \
        2>/dev/null
}

client_identity_matches() {
    local client_id="$1"
    local escaped_client_id=""
    local escaped_hostname=""
    local output=""
    escaped_client_id="$(regex_escape "$client_id")"
    escaped_hostname="$(regex_escape "$CLIENT_NAME")"

    if ! output="$(api_query query --format json \
        "SELECT client_id FROM clients() WHERE client_id =~ '^${escaped_client_id}$' AND (os_info.hostname =~ '^${escaped_hostname}$' OR os_info.fqdn =~ '^${escaped_hostname}$') LIMIT 1" \
        2>/dev/null)"; then
        return 2
    fi
    printf '%s\n' "$output" | grep -q '"client_id"'
}

client_last_seen_age_seconds() {
    local record="$1"
    local last_seen_us=""
    local now_us=""
    last_seen_us="$(printf '%s\n' "$record" | sed -n 's/.*"last_seen_at"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
    if [ -z "$last_seen_us" ]; then
        return 1
    fi
    now_us="$(( $(date +%s) * 1000000 ))"
    printf '%s\n' "$(( (now_us - last_seen_us) / 1000000 ))"
}

current_client_pid() {
    cat "$CLIENT_PID_FILE" 2>/dev/null || true
}

process_matches() {
    local pid="${1:-}"
    local identity_file="$2"
    [ -n "$pid" ] && [ -s "$identity_file" ] && kill -0 "$pid" >/dev/null 2>&1 || return 1
    [ "$(ps -p "$pid" -o lstart= -o command= 2>/dev/null)" = "$(cat "$identity_file")" ]
}

client_running() {
    local pid=""
    pid="$(current_client_pid)"
    process_matches "$pid" "${CLIENT_PID_FILE}.identity"
}

evidence_available() {
    if [ -z "$EVIDENCE_PATH" ]; then
        return 0
    fi
    [ -e "$EVIDENCE_PATH" ] && [ -r "$EVIDENCE_PATH" ]
}

runtime_files_available() {
    [ -x "$VELOCIRAPTOR_BIN" ] &&
        [ -r "$CLIENT_CONFIG" ] &&
        [ -s "$REMAP_FILE" ] &&
        grep -q 'type: mount' "$REMAP_FILE"
}

start_client() {
    info "Starting mapped client ${CLIENT_NAME}"
    (
        cd "$WORKSPACE_DIR" || exit 1
        if [ "$SUPERVISOR_MODE" = "foreground" ]; then
            "$VELOCIRAPTOR_BIN" client -v --config "$CLIENT_CONFIG" --remap "$REMAP_FILE" >>"$CLIENT_LOG" 2>&1 &
        else
            nohup "$VELOCIRAPTOR_BIN" client -v --config "$CLIENT_CONFIG" --remap "$REMAP_FILE" >>"$CLIENT_LOG" 2>&1 &
        fi
        local pid="$!"
        echo "$pid" >"$CLIENT_PID_FILE"
        sleep 0.1
        ps -p "$pid" -o lstart= -o command= >"${CLIENT_PID_FILE}.identity"
    )
}

stop_client() {
    local pid=""
    local reason="${1:-supervisor requested stop}"
    pid="$(current_client_pid)"
    if process_matches "$pid" "${CLIENT_PID_FILE}.identity"; then
        warn "Stopping mapped client ${CLIENT_NAME} pid ${pid}: ${reason}"
        kill "$pid" >/dev/null 2>&1 || true
        sleep 1
        if process_matches "$pid" "${CLIENT_PID_FILE}.identity"; then
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
    fi
    rm -f "$CLIENT_PID_FILE" "${CLIENT_PID_FILE}.identity"
}

prune_restart_history() {
    local now=""
    local cutoff=""
    local tmp_file="${RESTART_HISTORY_FILE}.tmp"
    now="$(date +%s)"
    cutoff="$((now - RESTART_WINDOW_SECONDS))"

    if [ ! -f "$RESTART_HISTORY_FILE" ]; then
        : >"$RESTART_HISTORY_FILE"
        return 0
    fi

    awk -F '\t' -v cutoff="$cutoff" '$1 >= cutoff' "$RESTART_HISTORY_FILE" >"$tmp_file"
    mv "$tmp_file" "$RESTART_HISTORY_FILE"
}

restart_count() {
    prune_restart_history
    wc -l <"$RESTART_HISTORY_FILE" | tr -d '[:space:]'
}

next_restart_epoch() {
    cat "$NEXT_RESTART_FILE" 2>/dev/null || printf '0\n'
}

record_restart() {
    local reason="$1"
    local now=""
    local count=""
    local delay=5
    local exponent=1
    now="$(date +%s)"
    printf '%s\t%s\n' "$now" "$reason" >>"$RESTART_HISTORY_FILE"
    count="$(restart_count)"

    while [ "$exponent" -lt "$count" ]; do
        delay=$((delay * 2))
        exponent=$((exponent + 1))
    done
    if [ "$delay" -gt 300 ]; then
        delay=300
    fi
    printf '%s\n' "$((now + delay))" >"$NEXT_RESTART_FILE"
}

restart_allowed() {
    local now=""
    local next=""
    local count=""
    now="$(date +%s)"
    next="$(next_restart_epoch)"
    count="$(restart_count)"

    if [ "$count" -ge "$MAX_RESTARTS" ]; then
        return 1
    fi
    [ "$now" -ge "$next" ]
}

restart_client() {
    local reason="$1"
    local count=""
    local next=""
    local now=""

    if ! evidence_available; then
        write_status "evidence_unavailable" "evidence path is missing or unreadable: ${EVIDENCE_PATH}"
        return 1
    fi
    if ! runtime_files_available; then
        write_status "evidence_unavailable" "client config, remapping file, or Velociraptor binary is missing or invalid"
        return 1
    fi
    if ! restart_allowed; then
        count="$(restart_count)"
        next="$(next_restart_epoch)"
        now="$(date +%s)"
        if [ "$count" -ge "$MAX_RESTARTS" ]; then
            write_status "backoff" "restart budget exhausted: ${count}/${MAX_RESTARTS} restarts in ${RESTART_WINDOW_SECONDS}s"
        else
            write_status "backoff" "next restart permitted in $((next - now))s"
        fi
        return 1
    fi

    stop_client "$reason"
    record_restart "$reason"
    start_client
    write_status "starting" "restarted client after ${reason}"
    return 0
}

register_supervisor() {
    local existing_pid=""
    existing_pid="$(cat "$SUPERVISOR_PID_FILE" 2>/dev/null || true)"
    if [ "$existing_pid" != "$$" ] && process_matches "$existing_pid" "${SUPERVISOR_PID_FILE}.identity"; then
        info "Mapped client supervisor already running with PID ${existing_pid}"
        exit 0
    fi
    if [ -n "$existing_pid" ] && [ "$existing_pid" != "$$" ] && kill -0 "$existing_pid" 2>/dev/null; then
        error "Supervisor PID ownership mismatch; preserving existing process."
    fi
    ps -p "$$" -o lstart= -o command= >"${SUPERVISOR_PID_FILE}.identity"
    printf '%s\n' "$$" >"$SUPERVISOR_PID_FILE"
}

cleanup() {
    local registered_pid=""
    registered_pid="$(cat "$SUPERVISOR_PID_FILE" 2>/dev/null || true)"
    write_status "stopped" "supervisor stopped"
    stop_client "supervisor stopped"
    if [ "$registered_pid" = "$$" ]; then
        rm -f "$SUPERVISOR_PID_FILE" "${SUPERVISOR_PID_FILE}.identity"
    fi
}

case "$SUPERVISOR_MODE" in
    foreground|nohup) ;;
    *)
        echo "[ERROR] Unsupported supervisor mode: ${SUPERVISOR_MODE}" >&2
        exit 1
        ;;
esac

require_positive_integer "supervisor-loop-seconds" "$SUPERVISOR_LOOP_SECONDS"
require_positive_integer "stale-seconds" "$STALE_SECONDS"
require_positive_integer "health-failure-threshold" "$HEALTH_FAILURE_THRESHOLD"
require_positive_integer "max-restarts" "$MAX_RESTARTS"
require_positive_integer "restart-window-seconds" "$RESTART_WINDOW_SECONDS"

mkdir -p "$CLIENT_DIR"
register_supervisor
trap 'exit 0' INT TERM
trap cleanup EXIT
write_status "starting" "initializing supervisor"

consecutive_stale_failures=0
consecutive_identity_failures=0
identity_grace_until=$(( $(date +%s) + 30 ))

while true; do
    if [ -s "$SUPERVISOR_HOLD_FILE" ]; then
        write_status "identity_error" "$(head -n 1 "$SUPERVISOR_HOLD_FILE")"
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi

    if ! evidence_available; then
        write_status "evidence_unavailable" "evidence path is missing or unreadable: ${EVIDENCE_PATH}"
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi

    if ! runtime_files_available; then
        write_status "evidence_unavailable" "client config, remapping file, or Velociraptor binary is missing or invalid"
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi

    if ! client_running; then
        raw_pid="$(current_client_pid)"
        if [ -n "$raw_pid" ] && kill -0 "$raw_pid" 2>/dev/null; then
            write_status "identity_error" "client PID ownership mismatch; preserving process"
            sleep "$SUPERVISOR_LOOP_SECONDS"
            continue
        fi
        if [ ! -e "$CLIENT_PID_FILE" ]; then
            start_client
            write_status "starting" "started client process"
        else
            restart_client "process_dead" || true
        fi
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi

    if ! api_reachable; then
        consecutive_stale_failures=0
        consecutive_identity_failures=0
        write_status "server_unreachable" "API health query failed; preserving the running client process"
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi

    client_id="$(current_client_id 2>/dev/null || true)"
    if [ -z "$client_id" ]; then
        consecutive_identity_failures=$((consecutive_identity_failures + 1))
        if [ "$consecutive_identity_failures" -ge "$HEALTH_FAILURE_THRESHOLD" ]; then
            restart_client "client_identity_unavailable" || true
            consecutive_identity_failures=0
        else
            write_status "waiting_identity" "client id unavailable (${consecutive_identity_failures}/${HEALTH_FAILURE_THRESHOLD})"
        fi
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi

    if ! record="$(client_record_json "$client_id")"; then
        consecutive_stale_failures=0
        consecutive_identity_failures=0
        write_status "server_unreachable" "client-record query failed; preserving the running client process"
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi
    if ! printf '%s\n' "$record" | grep -q '"client_id"'; then
        if [ "$(date +%s)" -lt "$identity_grace_until" ]; then
            write_status "waiting_identity" "waiting for initial mapped-client enrollment"
            sleep "$SUPERVISOR_LOOP_SECONDS"
            continue
        fi
        consecutive_identity_failures=$((consecutive_identity_failures + 1))
        if [ "$consecutive_identity_failures" -ge "$HEALTH_FAILURE_THRESHOLD" ]; then
            stop_client "persisted client id is not present on the server"
            printf '%s\n' "client id ${client_id} is not present on the reachable server; rerun mapped-client ensure" >"$SUPERVISOR_HOLD_FILE"
            write_status "identity_error" "$(head -n 1 "$SUPERVISOR_HOLD_FILE")"
        else
            write_status "waiting_identity" "client id ${client_id} not visible (${consecutive_identity_failures}/${HEALTH_FAILURE_THRESHOLD})"
        fi
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi

    client_identity_matches "$client_id"
    identity_status=$?
    if [ "$identity_status" -eq 2 ]; then
        consecutive_stale_failures=0
        consecutive_identity_failures=0
        write_status "server_unreachable" "client-identity query failed; preserving the running client process"
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi
    if [ "$identity_status" -ne 0 ]; then
        if [ "$(date +%s)" -lt "$identity_grace_until" ]; then
            write_status "waiting_identity" "waiting for initial remapped hostname update"
            sleep "$SUPERVISOR_LOOP_SECONDS"
            continue
        fi
        stop_client "persisted client id does not match the expected mapped hostname"
        printf '%s\n' "client id ${client_id} does not match mapped hostname ${CLIENT_NAME}; rerun mapped-client ensure" >"$SUPERVISOR_HOLD_FILE"
        write_status "identity_error" "$(head -n 1 "$SUPERVISOR_HOLD_FILE")"
        sleep "$SUPERVISOR_LOOP_SECONDS"
        continue
    fi

    consecutive_identity_failures=0
    if age="$(client_last_seen_age_seconds "$record")"; then
        if [ "$age" -gt "$STALE_SECONDS" ]; then
            consecutive_stale_failures=$((consecutive_stale_failures + 1))
            if [ "$consecutive_stale_failures" -ge "$HEALTH_FAILURE_THRESHOLD" ]; then
                restart_client "last_seen_stale_${age}s" || true
                consecutive_stale_failures=0
            else
                write_status "disconnected" "last seen ${age}s ago (${consecutive_stale_failures}/${HEALTH_FAILURE_THRESHOLD})"
            fi
        else
            consecutive_stale_failures=0
            write_status "online" "client id ${client_id} last seen ${age}s ago"
        fi
    else
        write_status "disconnected" "client id ${client_id} has no parseable LastSeen value"
    fi

    sleep "$SUPERVISOR_LOOP_SECONDS"
done

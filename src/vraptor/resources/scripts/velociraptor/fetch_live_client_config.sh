#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${AI_SKILLS_REPO_ROOT:-$PWD}"
ENV_HELPER="${SCRIPT_DIR}/../load_repo_env.sh"
. "${SCRIPT_DIR}/remote_config_access.sh"

REMOTE_SSH_USER=""
SERVER_IP=""
SERVER_IP_SOURCE="cli"
ENGAGEMENT_CODE=""
OUTPUT_PATH=""
IDENTITY_FILE=""
REMOTE_CLIENT_CONFIG_PATH=""
REMOTE_SERVER_CONFIG_PATH=""
REMOTE_VELOCIRAPTOR_BIN=""
REMOTE_RUN_AS=""
REMOTE_OUTPUT_DIR=""
LOCAL_OUTPUT_ROOT=""
LOCAL_KNOWN_HOSTS_FILE=""
DRY_RUN=0
JSON_OUT=""
FORCE=0
PROVISION_CLIENT=0

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

first_env() {
    local key=""
    local value=""

    for key in "$@"; do
        value="${!key-}"
        if [ -n "$value" ]; then
            printf '%s' "$value"
            return 0
        fi
    done
}

expand_home_path() {
    local value="${1-}"
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

usage() {
    cat <<'EOF'
Usage:
  ./dfir config fetch-client \
    --server-profile <profile> \
    [--server-ip <ip-or-host>] \
    [--output-path <local-path>] \
    [--force] \
    [--provision-client] \
    [--json-out <path>] \
    [--dry-run]
EOF
    exit 0
}

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || error "Required command not found: $cmd"
    done
}

bootstrap_ssh_known_hosts() {
    local scan_output=""
    local known_hosts_dir

    known_hosts_dir="$(dirname "$LOCAL_KNOWN_HOSTS_FILE")"
    mkdir -p "$known_hosts_dir"
    if [ -f "$LOCAL_KNOWN_HOSTS_FILE" ] && ssh-keygen -F "$SERVER_IP" -f "$LOCAL_KNOWN_HOSTS_FILE" >/dev/null 2>&1; then
        return 0
    fi

    info "Bootstrapping SSH host key cache for ${SERVER_IP} at ${LOCAL_KNOWN_HOSTS_FILE}"
    scan_output="$(ssh-keyscan -H -T 5 -t rsa,ecdsa,ed25519 "$SERVER_IP" 2>/dev/null || true)"
    if [ -z "$scan_output" ]; then
        error "Could not retrieve an SSH host key from ${SERVER_IP}. Verify network reachability and retry."
    fi
    printf '%s\n' "$scan_output" >> "$LOCAL_KNOWN_HOSTS_FILE"
    chmod 600 "$LOCAL_KNOWN_HOSTS_FILE"
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

write_json_manifest() {
    local output_path="$1"
    mkdir -p "$(dirname "$output_path")"
    {
        printf '{\n'
        json_field "status" "ready"
        printf ',\n'
        json_field "mode" "live_remote_client_config"
        printf ',\n'
        json_field "server_ip" "$SERVER_IP"
        printf ',\n'
        json_field "server_ip_source" "$SERVER_IP_SOURCE"
        printf ',\n'
        json_field "server_profile" "$ENGAGEMENT_CODE"
        printf ',\n'
        json_field "ssh_target" "${REMOTE_SSH_USER}@${SERVER_IP}"
        printf ',\n'
        json_field "remote_client_config_path" "$REMOTE_CLIENT_CONFIG_PATH"
        printf ',\n'
        json_field "remote_server_config_path" "$REMOTE_SERVER_CONFIG_PATH"
        printf ',\n'
        json_field "remote_run_as" "$REMOTE_RUN_AS"
        printf ',\n'
        json_field "local_dest_dir" "$LOCAL_DEST_DIR"
        printf ',\n'
        json_field "local_dest_path" "$LOCAL_DEST_PATH"
        printf '\n}\n'
    } >"$output_path"
}

remote_dirname() {
    local path="$1"
    if [[ "$path" == */* ]]; then
        printf '%s\n' "${path%/*}"
    else
        printf '.\n'
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --server-ip)
            SERVER_IP="${2:?missing value for --server-ip}"
            shift 2
            ;;
        --server-profile|--engagement-code)
            ENGAGEMENT_CODE="${2:?missing value for --server-profile}"
            shift 2
            ;;
        --output-path)
            OUTPUT_PATH="${2:?missing value for --output-path}"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --provision-client)
            PROVISION_CLIENT=1
            shift
            ;;
        --json-out)
            JSON_OUT="${2:?missing value for --json-out}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
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

[ -n "$ENGAGEMENT_CODE" ] || error "--server-profile is required"

if [[ ! "$ENGAGEMENT_CODE" =~ ^[A-Za-z0-9._-]+$ ]]; then
    error "--server-profile may contain only letters, numbers, dots, underscores, and hyphens"
fi

# shellcheck source=/dev/null
. "$ENV_HELPER"
load_repo_env "$REPO_ROOT"

REMOTE_SSH_USER="$(first_env VELO_REMOTE_SSH_USER)"
REMOTE_CLIENT_CONFIG_PATH="$(first_env VELO_REMOTE_CLIENT_CONFIG_PATH)"
REMOTE_SERVER_CONFIG_PATH="$(first_env VELO_REMOTE_SERVER_CONFIG_PATH)"
REMOTE_VELOCIRAPTOR_BIN="$(first_env VELO_REMOTE_BIN || true)"
REMOTE_VELOCIRAPTOR_BIN="${REMOTE_VELOCIRAPTOR_BIN:-velociraptor}"
REMOTE_RUN_AS="$(first_env VELO_REMOTE_RUN_AS)"
REMOTE_RUN_AS="${REMOTE_RUN_AS:-root}"
LOCAL_OUTPUT_ROOT="$(first_env VELO_LOCAL_CONFIG_ROOT)"
IDENTITY_FILE="$(first_env VELO_REMOTE_SSH_KEY)"

REMOTE_SSH_USER="${REMOTE_SSH_USER:-root}"
REMOTE_CLIENT_CONFIG_PATH="${REMOTE_CLIENT_CONFIG_PATH:-/etc/velociraptor/client.config.yaml}"
REMOTE_SERVER_CONFIG_PATH="${REMOTE_SERVER_CONFIG_PATH:-/etc/velociraptor/server.config.yaml}"
LOCAL_OUTPUT_ROOT="${LOCAL_OUTPUT_ROOT:-${HOME}/.config/velociraptor}"
LOCAL_OUTPUT_ROOT="$(expand_home_path "$LOCAL_OUTPUT_ROOT")"
LOCAL_KNOWN_HOSTS_FILE="${LOCAL_OUTPUT_ROOT}/${ENGAGEMENT_CODE}_known_hosts"

if [ -n "$OUTPUT_PATH" ]; then
    OUTPUT_PATH="$(expand_home_path "$OUTPUT_PATH")"
    LOCAL_DEST_PATH="$OUTPUT_PATH"
else
    LOCAL_DEST_PATH="${LOCAL_OUTPUT_ROOT}/${ENGAGEMENT_CODE}_client.config.yaml"
fi
LOCAL_DEST_DIR="$(dirname "$LOCAL_DEST_PATH")"
if [ -f "$LOCAL_DEST_PATH" ] && [ "$FORCE" -ne 1 ]; then
    [ -n "$SERVER_IP" ] || SERVER_IP_SOURCE="local_cache_unresolved"
    if [ "$DRY_RUN" -ne 1 ]; then
        chmod 600 "$LOCAL_DEST_PATH"
        if [ -n "$JSON_OUT" ]; then
            write_json_manifest "$JSON_OUT"
        fi
    fi
    success "Using existing local client config at ${LOCAL_DEST_PATH}. Pass --force to refresh."
    exit 0
fi

[ -n "$SERVER_IP" ] || error "--server-ip is required when remote client configuration must be fetched"
require_cmd ssh scp ssh-keyscan ssh-keygen mkdir chmod mv rm
[ -n "$IDENTITY_FILE" ] || error "Missing required config: set VELO_REMOTE_SSH_KEY in .env or the shell environment"
IDENTITY_FILE="$(expand_home_path "$IDENTITY_FILE")"
[ -f "$IDENTITY_FILE" ] || error "Configured SSH identity file does not exist: $IDENTITY_FILE"
LOCAL_TEMP_PATH="${LOCAL_DEST_PATH}.tmp.$$"

SSH_KEYCHAIN_ARGS=()
if [[ "$(uname -s)" == "Darwin" ]]; then
    SSH_KEYCHAIN_ARGS=(-o UseKeychain=yes -o AddKeysToAgent=yes)
fi
SCP_ARGS=(-o BatchMode=yes -o IdentitiesOnly=yes "${SSH_KEYCHAIN_ARGS[@]}" -o UserKnownHostsFile="$LOCAL_KNOWN_HOSTS_FILE" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -i "$IDENTITY_FILE")
SSH_ARGS=(-o BatchMode=yes -o IdentitiesOnly=yes "${SSH_KEYCHAIN_ARGS[@]}" -o UserKnownHostsFile="$LOCAL_KNOWN_HOSTS_FILE" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -i "$IDENTITY_FILE")
SSH_TARGET="${REMOTE_SSH_USER}@${SERVER_IP}"
REMOTE_CLIENT_DIR="$(remote_dirname "$REMOTE_CLIENT_CONFIG_PATH")"
prepare_remote_commands "$REMOTE_CLIENT_CONFIG_PATH" "set -e; umask 077; mkdir -p $(shell_quote "$REMOTE_CLIENT_DIR"); $(shell_quote "$REMOTE_VELOCIRAPTOR_BIN") --config $(shell_quote "$REMOTE_SERVER_CONFIG_PATH") config client > $(shell_quote "$REMOTE_CLIENT_CONFIG_PATH")" client

if [ "$DRY_RUN" -eq 1 ]; then
    printf 'umask 077\n'
    printf 'ssh-keyscan -H -T 5 -t rsa,ecdsa,ed25519 %q >> %q\n' "$SERVER_IP" "$LOCAL_KNOWN_HOSTS_FILE"
    printf 'mkdir -p %q\n' "$LOCAL_DEST_DIR"
    preview_remote_copy "$REMOTE_CLIENT_CONFIG_PATH"
    if [ "$PROVISION_CLIENT" -eq 1 ]; then
        printf '# Only after a failed privileged read and confirmed remote absence:\n'
        printf 'ssh'
        printf ' %q' "${SSH_ARGS[@]}"
        printf ' %q %q\n' "$SSH_TARGET" "$VERIFY_MISSING_COMMAND"
        printf 'ssh'
        printf ' %q' "${SSH_ARGS[@]}"
        printf ' %q %q\n' "$SSH_TARGET" "$GENERATE_REMOTE_COMMAND"
        preview_remote_copy "$REMOTE_CLIENT_CONFIG_PATH"
    fi
    printf 'mv -f %q %q\n' "$LOCAL_TEMP_PATH" "$LOCAL_DEST_PATH"
    exit 0
fi

mkdir -p "$LOCAL_DEST_DIR"

trap 'rm -f "$LOCAL_TEMP_PATH"' EXIT
bootstrap_ssh_known_hosts

info "Trying to copy existing remote client config from ${REMOTE_CLIENT_CONFIG_PATH}"
if copy_remote_config "$REMOTE_CLIENT_CONFIG_PATH"; then
    COPY_RESULT=0
else
    COPY_RESULT=$?
fi
[ "$COPY_RESULT" -ne 3 ] || exit 3
[ "$COPY_RESULT" -ne 70 ] || error "Remote configuration preparation or validation failed; no automatic retry"
[ "$COPY_RESULT" -eq 0 ] || [ "${REMOTE_UID:-0}" = 0 ] ||
    error "Remote sudo configuration retrieval failed; no automatic retry"
if [ "$COPY_RESULT" -ne 0 ]; then
    rm -f "$LOCAL_TEMP_PATH"
    [ "$PROVISION_CLIENT" -eq 1 ] || error "Could not copy remote client configuration; creation requires explicit --provision-client"
    ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "$VERIFY_MISSING_COMMAND" ||
        error "Remote client configuration absence was not confirmed; no configuration was generated"
    warn "Remote client configuration is absent; generating one from ${REMOTE_SERVER_CONFIG_PATH}"
    generate_remote_config "$REMOTE_CLIENT_CONFIG_PATH"
    copy_remote_config "$REMOTE_CLIENT_CONFIG_PATH"
fi

test -s "$LOCAL_TEMP_PATH" || error "Downloaded client configuration is empty; local cache preserved"
mv -f "$LOCAL_TEMP_PATH" "$LOCAL_DEST_PATH"
trap - EXIT
chmod 600 "$LOCAL_DEST_PATH"

if [ -n "$JSON_OUT" ]; then
    write_json_manifest "$JSON_OUT"
fi

success "Saved live client config to ${LOCAL_DEST_PATH}"

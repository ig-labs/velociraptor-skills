#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${AI_SKILLS_REPO_ROOT:-$PWD}"
ENV_HELPER="${SCRIPT_DIR}/../load_repo_env.sh"
. "${SCRIPT_DIR}/remote_config_access.sh"

REMOTE_SSH_USER=""
API_USER=""
SERVER_IP=""
SERVER_IP_SOURCE="cli"
ENGAGEMENT_CODE=""
OUTPUT_PATH=""
IDENTITY_FILE=""
REMOTE_OUTPUT_PATH=""
REMOTE_SERVER_CONFIG_PATH=""
REMOTE_VELOCIRAPTOR_BIN=""
REMOTE_RUN_AS=""
LOCAL_OUTPUT_ROOT=""
LOCAL_KNOWN_HOSTS_FILE=""
DRY_RUN=0
JSON_OUT=""
FORCE=0
REGENERATE_REMOTE_API=0
PROVISION_API=0
API_ROLE_PROFILE=""
API_ROLES=""
API_CLIENT_SOURCE=""
SERVER_RESOLUTION_SECONDS=0
SSH_HOST_KEY_SECONDS=0
REMOTE_COPY_SECONDS=0
REMOTE_GENERATION_SECONDS=0
TOTAL_START_SECONDS=$SECONDS

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
  ./dfir config fetch-api \
    --server-profile <profile> \
    [--server-ip <ip-or-host>] \
    [--output-path <local-path>] \
    [--force] \
    [--regenerate-remote-api] \
    [--provision-api] \
    [--api-role-profile <provisioning-admin|investigation>] \
    [--run-as <remote-generation-user>] \
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

remote_dirname() {
    local path="$1"
    if [[ "$path" == */* ]]; then
        printf '%s\n' "${path%/*}"
    else
        printf '.\n'
    fi
}

write_json_manifest() {
    local output_path="$1"
    local total_seconds=$((SECONDS - TOTAL_START_SECONDS))
    local ssh_target=""
    if [ -n "$SERVER_IP" ]; then
        ssh_target="${REMOTE_SSH_USER}@${SERVER_IP}"
    fi
    mkdir -p "$(dirname "$output_path")"
    {
        printf '{\n'
        json_field "status" "ready"
        printf ',\n'
        json_field "mode" "live_remote"
        printf ',\n'
        json_field "server_ip" "$SERVER_IP"
        printf ',\n'
        json_field "server_ip_source" "$SERVER_IP_SOURCE"
        printf ',\n'
        json_field "server_profile" "$ENGAGEMENT_CODE"
        printf ',\n'
        json_field "api_user" "$API_USER"
        printf ',\n'
        json_field "api_role_profile" "$API_ROLE_PROFILE"
        printf ',\n'
        printf '  "api_roles": ["%s", "api"],\n' "$(json_escape "${API_ROLES%%,*}")"
        json_field "api_client_source" "$API_CLIENT_SOURCE"
        printf ',\n'
        json_field "ssh_target" "$ssh_target"
        printf ',\n'
        json_field "remote_output_path" "$REMOTE_OUTPUT_PATH"
        printf ',\n'
        json_field "remote_server_config_path" "$REMOTE_SERVER_CONFIG_PATH"
        printf ',\n'
        json_field "remote_run_as" "$REMOTE_RUN_AS"
        printf ',\n'
        json_field "local_dest_dir" "$LOCAL_DEST_DIR"
        printf ',\n'
        json_field "local_dest_path" "$LOCAL_DEST_PATH"
        printf ',\n'
        printf '  "timing": {\n'
        printf '    "server_resolution_seconds": %d,\n' "$SERVER_RESOLUTION_SECONDS"
        printf '    "ssh_host_key_seconds": %d,\n' "$SSH_HOST_KEY_SECONDS"
        printf '    "remote_copy_seconds": %d,\n' "$REMOTE_COPY_SECONDS"
        printf '    "remote_generation_seconds": %d,\n' "$REMOTE_GENERATION_SECONDS"
        printf '    "total_seconds": %d\n' "$total_seconds"
        printf '  }'
        printf '\n}\n'
    } >"$output_path"
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
        --regenerate-remote-api)
            REGENERATE_REMOTE_API=1
            FORCE=1
            shift
            ;;
        --provision-api)
            PROVISION_API=1
            shift
            ;;
        --api-role-profile)
            API_ROLE_PROFILE="${2:?missing value for --api-role-profile}"
            shift 2
            ;;
        --run-as)
            REMOTE_RUN_AS="${2:?missing value for --run-as}"
            shift 2
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

API_ROLE_PROFILE="${API_ROLE_PROFILE:-$(first_env VELO_REMOTE_API_ROLE_PROFILE || true)}"
API_ROLE_PROFILE="${API_ROLE_PROFILE:-provisioning-admin}"
case "$API_ROLE_PROFILE" in
    provisioning-admin) API_ROLES="administrator,api" ;;
    investigation) API_ROLES="investigator,api" ;;
    *) error "--api-role-profile must be provisioning-admin or investigation" ;;
esac

API_USER="$(first_env VELO_REMOTE_API_USER || true)"
if [ -z "$API_USER" ]; then
    error "Missing required config: set VELO_REMOTE_API_USER to the explicitly provisioned API user"
fi
if [[ "$API_USER" == "api_username" || "$API_USER" == "your_api_user" || "$API_USER" == '<api-user>' ]]; then
    error "VELO_REMOTE_API_USER is still set to the example placeholder '${API_USER}'. Set it to the explicitly provisioned API user"
fi
if [[ ! "$API_USER" =~ ^[A-Za-z0-9._-]+$ ]]; then
    error "VELO_REMOTE_API_USER may contain only letters, numbers, dots, underscores, and hyphens"
fi

REMOTE_SSH_USER="$(first_env VELO_REMOTE_SSH_USER)"
REMOTE_OUTPUT_PATH="$(first_env VELO_REMOTE_API_CONFIG_PATH)"
REMOTE_SERVER_CONFIG_PATH="$(first_env VELO_REMOTE_SERVER_CONFIG_PATH)"
REMOTE_VELOCIRAPTOR_BIN="$(first_env VELO_REMOTE_BIN || true)"
REMOTE_VELOCIRAPTOR_BIN="${REMOTE_VELOCIRAPTOR_BIN:-velociraptor}"
REMOTE_RUN_AS_DEFAULT=0
if [ -z "$REMOTE_RUN_AS" ]; then
    REMOTE_RUN_AS="$(first_env VELO_REMOTE_RUN_AS)"
    if [ -z "$REMOTE_RUN_AS" ] || [ "${VRAPTOR_REMOTE_RUN_AS_DEFAULT:-0}" = 1 ]; then
        REMOTE_RUN_AS_DEFAULT=1
    fi
fi
REMOTE_RUN_AS="${REMOTE_RUN_AS:-velociraptor}"
LOCAL_OUTPUT_ROOT="$(first_env VELO_LOCAL_CONFIG_ROOT)"
IDENTITY_FILE="$(first_env VELO_REMOTE_SSH_KEY)"

REMOTE_SSH_USER="${REMOTE_SSH_USER:-root}"
REMOTE_SERVER_CONFIG_PATH="${REMOTE_SERVER_CONFIG_PATH:-/etc/velociraptor/server.config.yaml}"
LOCAL_OUTPUT_ROOT="${LOCAL_OUTPUT_ROOT:-${HOME}/.config/velociraptor}"

LOCAL_OUTPUT_ROOT="$(expand_home_path "$LOCAL_OUTPUT_ROOT")"
IDENTITY_FILE="$(expand_home_path "$IDENTITY_FILE")"

if [ -z "$REMOTE_OUTPUT_PATH" ]; then
    REMOTE_OUTPUT_PATH="/etc/velociraptor/api_access_${API_USER}.yaml"
fi

LOCAL_KNOWN_HOSTS_FILE="${LOCAL_OUTPUT_ROOT}/${ENGAGEMENT_CODE}_known_hosts"

if [ -n "$OUTPUT_PATH" ]; then
    OUTPUT_PATH="$(expand_home_path "$OUTPUT_PATH")"
    LOCAL_DEST_PATH="$OUTPUT_PATH"
else
    LOCAL_DEST_PATH="${LOCAL_OUTPUT_ROOT}/${ENGAGEMENT_CODE}_api_client.yaml"
fi
LOCAL_DEST_DIR="$(dirname "$LOCAL_DEST_PATH")"

if [ "$DRY_RUN" -ne 1 ]; then
    mkdir -p "$LOCAL_DEST_DIR"
fi
if [ -f "$LOCAL_DEST_PATH" ] && [ "$FORCE" -ne 1 ] && [ "$REGENERATE_REMOTE_API" -ne 1 ]; then
    API_CLIENT_SOURCE="local_cache"
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP_SOURCE="local_cache_unresolved"
    fi
    if [ "$DRY_RUN" -ne 1 ]; then
        chmod 600 "$LOCAL_DEST_PATH"
        if [ -n "$JSON_OUT" ]; then
            write_json_manifest "$JSON_OUT"
        fi
    fi
    success "Using existing local API client at ${LOCAL_DEST_PATH}. Pass --force to refresh."
    exit 0
fi

[ -n "$SERVER_IP" ] || error "--server-ip is required when remote API configuration must be fetched"

require_cmd ssh scp ssh-keyscan ssh-keygen mkdir chmod mv rm
if [ -z "$IDENTITY_FILE" ]; then
    error "Missing required config: set VELO_REMOTE_SSH_KEY in .env or the shell environment"
fi
if [ ! -f "$IDENTITY_FILE" ]; then
    error "Configured SSH identity file does not exist: $IDENTITY_FILE"
fi

SSH_KEYCHAIN_ARGS=()
if [[ "$(uname -s)" == "Darwin" ]]; then
    SSH_KEYCHAIN_ARGS=(-o UseKeychain=yes -o AddKeysToAgent=yes)
fi
SCP_ARGS=(-o BatchMode=yes -o IdentitiesOnly=yes "${SSH_KEYCHAIN_ARGS[@]}" -o UserKnownHostsFile="$LOCAL_KNOWN_HOSTS_FILE" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -i "$IDENTITY_FILE")
SSH_ARGS=(-o BatchMode=yes -o IdentitiesOnly=yes "${SSH_KEYCHAIN_ARGS[@]}" -o UserKnownHostsFile="$LOCAL_KNOWN_HOSTS_FILE" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -i "$IDENTITY_FILE")
SSH_TARGET="${REMOTE_SSH_USER}@${SERVER_IP}"
LOCAL_TEMP_PATH="${LOCAL_DEST_PATH}.tmp.$$"
REMOTE_DEST_DIR="$(remote_dirname "$REMOTE_OUTPUT_PATH")"
prepare_remote_commands "$REMOTE_OUTPUT_PATH" "set -e; umask 077; mkdir -p $(shell_quote "$REMOTE_DEST_DIR"); $(shell_quote "$REMOTE_VELOCIRAPTOR_BIN") --config $(shell_quote "$REMOTE_SERVER_CONFIG_PATH") config api_client --name $(shell_quote "$API_USER") --role $(shell_quote "$API_ROLES") $(shell_quote "$REMOTE_OUTPUT_PATH")" api

if [ "$DRY_RUN" -eq 1 ]; then
    printf 'umask 077\n'
    printf 'ssh-keyscan -H -T 5 -t rsa,ecdsa,ed25519 %q >> %q\n' "$SERVER_IP" "$LOCAL_KNOWN_HOSTS_FILE"
    printf 'mkdir -p %q\n' "$LOCAL_DEST_DIR"
    if [ "$REGENERATE_REMOTE_API" -eq 1 ]; then
        printf 'ssh'
        printf ' %q' "${SSH_ARGS[@]}"
        printf ' %q %q\n' "$SSH_TARGET" "$GENERATE_REMOTE_COMMAND"
        preview_remote_copy "$REMOTE_OUTPUT_PATH"
        printf 'mv -f %q %q\n' "$LOCAL_TEMP_PATH" "$LOCAL_DEST_PATH"
    else
        preview_remote_copy "$REMOTE_OUTPUT_PATH"
        if [ "$PROVISION_API" -eq 1 ]; then
            printf '# Only after a failed privileged read and confirmed remote absence:\n'
            printf 'ssh'
            printf ' %q' "${SSH_ARGS[@]}"
            printf ' %q %q\n' "$SSH_TARGET" "$VERIFY_MISSING_COMMAND"
            printf 'ssh'
            printf ' %q' "${SSH_ARGS[@]}"
            printf ' %q %q\n' "$SSH_TARGET" "$GENERATE_REMOTE_COMMAND"
            preview_remote_copy "$REMOTE_OUTPUT_PATH"
        fi
        printf 'mv -f %q %q\n' "$LOCAL_TEMP_PATH" "$LOCAL_DEST_PATH"
    fi
    exit 0
fi

trap 'rm -f "$LOCAL_TEMP_PATH"' EXIT
ssh_host_key_start=$SECONDS
bootstrap_ssh_known_hosts
SSH_HOST_KEY_SECONDS=$((SECONDS - ssh_host_key_start))

if [ "$REGENERATE_REMOTE_API" -eq 1 ]; then
    info "Regenerating target API client from ${REMOTE_SERVER_CONFIG_PATH}"
    remote_generation_start=$SECONDS
    generate_remote_config "$REMOTE_OUTPUT_PATH"
    REMOTE_GENERATION_SECONDS=$((SECONDS - remote_generation_start))
    remote_copy_start=$SECONDS
    copy_remote_config "$REMOTE_OUTPUT_PATH"
    REMOTE_COPY_SECONDS=$((SECONDS - remote_copy_start))
    API_CLIENT_SOURCE="server_config_regenerated"
else
    info "Trying to copy existing remote API client from ${REMOTE_OUTPUT_PATH}"
    API_CLIENT_SOURCE="remote_existing"
    remote_copy_start=$SECONDS
    if copy_remote_config "$REMOTE_OUTPUT_PATH"; then
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
        REMOTE_COPY_SECONDS=$((REMOTE_COPY_SECONDS + SECONDS - remote_copy_start))
        [ "$PROVISION_API" -eq 1 ] || error "Could not copy remote API client; creation requires explicit --provision-api"
        ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "$VERIFY_MISSING_COMMAND" ||
            error "Remote API client absence was not confirmed; no credentials were generated"
        warn "Remote API client is absent; generating one from ${REMOTE_SERVER_CONFIG_PATH}"
        remote_generation_start=$SECONDS
        generate_remote_config "$REMOTE_OUTPUT_PATH"
        REMOTE_GENERATION_SECONDS=$((SECONDS - remote_generation_start))
        remote_copy_start=$SECONDS
        copy_remote_config "$REMOTE_OUTPUT_PATH"
        REMOTE_COPY_SECONDS=$((REMOTE_COPY_SECONDS + SECONDS - remote_copy_start))
        API_CLIENT_SOURCE="server_config_generated"
    else
        REMOTE_COPY_SECONDS=$((SECONDS - remote_copy_start))
    fi
fi

test -s "$LOCAL_TEMP_PATH" || error "Downloaded API configuration is empty; local cache preserved"
mv -f "$LOCAL_TEMP_PATH" "$LOCAL_DEST_PATH"
trap - EXIT
chmod 600 "$LOCAL_DEST_PATH"

if [ -n "$JSON_OUT" ]; then
    write_json_manifest "$JSON_OUT"
fi

success "Saved live API client config to ${LOCAL_DEST_PATH}"

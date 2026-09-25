#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_SCRIPT="${SCRIPT_DIR}/add_mapped_client.sh"

API_CLIENT_CONFIG=""
CLIENT_CONFIG=""
ARGS=()

usage() {
    cat <<'EOF'
Usage:
  ./dfir mapped add-remote \
    --client-config <local-client.config.yaml> \
    --api-client <local-api_client.yaml> \
    [add_mapped_client options] \
    <evidence-path>

Remote dead-disk wrapper for mapping local evidence into an external
Velociraptor server. Most operators should fetch the two configs first with:

  ./dfir config fetch-api
  ./dfir config fetch-client
EOF
    exit 0
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --client-config)
            CLIENT_CONFIG="${2:?missing value for --client-config}"
            shift 2
            ;;
        --api-client)
            API_CLIENT_CONFIG="${2:?missing value for --api-client}"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

[ -n "$CLIENT_CONFIG" ] || error "--client-config is required for remote dead-disk mapping"
[ -n "$API_CLIENT_CONFIG" ] || error "--api-client is required for remote dead-disk mapping"

exec "$ENGINE_SCRIPT" \
    --client-config "$CLIENT_CONFIG" \
    --api-client "$API_CLIENT_CONFIG" \
    "${ARGS[@]}"

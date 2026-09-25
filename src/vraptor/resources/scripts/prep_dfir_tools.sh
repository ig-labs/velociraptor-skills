#!/usr/bin/env bash
# =============================================================================
# prep_dfir_tools.sh
#
# Prepare common DFIR tools for Linux and macOS:
#   - Velociraptor  (https://github.com/Velocidex/velociraptor/releases)
#   - Volatility 3  (https://github.com/volatilityfoundation/volatility3)
#   - Plaso / log2timeline  (https://github.com/log2timeline/plaso)
#   - The Sleuth Kit / TSK  (https://github.com/sleuthkit/sleuthkit)
#
# Usage:
#   ./dfir tools prep [OPTIONS]
#
# Options:
#   -d <dir>   Override tool staging directory; Velociraptor appends /velociraptor/velociraptor
#   -t <tool>  Prepare a specific component: venv | plaso | velociraptor |
#              volatility | tsk | all
#              (default: all)
#   --init-velociraptor-workspace
#              Initialize a local GUI/API workspace after installing the binary
#   -h, --help Show this help message
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${AI_SKILLS_REPO_ROOT:-$PWD}"
ENV_HELPER="${SCRIPT_DIR}/load_repo_env.sh"
VENV_DIR="${REPO_ROOT}/.venv"
REQUIREMENTS_FILE="${REPO_ROOT}/requirements.txt"
if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
    REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements.txt"
fi
VENV_PYTHON="${VENV_DIR}/bin/python"
VENV_LOG2TIMELINE="${VENV_DIR}/bin/log2timeline"
VELOCIRAPTOR_INIT_SECONDS=10
VELOCIRAPTOR_API_WAIT_SECONDS=60
VELOCIRAPTOR_API_ROLES="administrator,api"

DOWNLOAD_DIR=""
DOWNLOAD_DIR_EXPLICIT=0
TOOL="all"
OS="$(uname -s)"
ARCH="$(uname -m)"
VENV_READY=0
INITIALIZE_VELOCIRAPTOR_WORKSPACE=0

if [ -f "$ENV_HELPER" ]; then
    # shellcheck source=/dev/null
    . "$ENV_HELPER"
    load_repo_env "$REPO_ROOT"
fi

VELOCIRAPTOR_API_USER="${VELO_LOCAL_API_USER:-codex}"
VELOCIRAPTOR_LOCAL_PORTS="${VELO_LOCAL_PORTS:-8000 8001 8889}"
TOOLS_DATA_ROOT="${AI_SKILLS_TOOLS_DATA_ROOT:-${REPO_ROOT}}"
DOWNLOAD_DIR="${TOOLS_DATA_ROOT}/tools"
PLASO_VERSION="${PLASO_VERSION:-20260512}"

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

velociraptor_api() {
    local binary="$1"
    local api_client_file="$2"
    shift 2

    if "$binary" -a "$api_client_file" "$@"; then
        return 0
    fi

    "$binary" -a "$api_client_file" --runas "$VELOCIRAPTOR_API_USER" "$@"
}

wait_for_file() {
    local path="$1"
    local timeout="$2"
    local waited=0

    while [ ! -f "$path" ] && [ "$waited" -lt "$timeout" ]; do
        sleep 1
        waited=$((waited + 1))
    done

    [ -f "$path" ]
}

wait_for_velociraptor_api() {
    local workspace_dir="$1"
    local binary="$VELOCIRAPTOR_BINARY"
    local api_client_file="${workspace_dir}/api_client.yaml"
    local timeout="${2:-20}"
    local waited=0

    while [ "$waited" -lt "$timeout" ]; do
        if velociraptor_api "$binary" "$api_client_file" query --format json \
            "SELECT 'ready' AS status FROM scope()" >/dev/null 2>&1; then
            return 0
        fi

        sleep 1
        waited=$((waited + 1))
    done

    return 1
}

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || error "Required command not found: $cmd"
    done
}

github_latest_release_json() {
    local repo="$1"
    curl -fsSL "https://api.github.com/repos/${repo}/releases/latest"
}

github_release_json() {
    local repo="$1"
    local tag="${2-}"

    if [ -n "$tag" ]; then
        curl -fsSL "https://api.github.com/repos/${repo}/releases/tags/${tag}"
    else
        github_latest_release_json "$repo"
    fi
}

github_latest_tag() {
    local repo="$1"
    github_latest_release_json "$repo" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

github_release_tag() {
    local repo="$1"
    local tag="${2-}"
    github_release_json "$repo" "$tag" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

github_release_download_url() {
    local repo="$1"
    local asset_regex="$2"
    local tag="${3-}"
    github_release_json "$repo" "$tag" \
        | grep '"browser_download_url"' \
        | sed -E 's/.*"browser_download_url": "([^"]+)".*/\1/' \
        | grep -E "/${asset_regex}$" \
        | grep -v '\.sig$' \
        | tail -1
}

usage() {
    printf '%s\n' \
        "Usage:" \
        " ./dfir tools prep [OPTIONS]" \
        "" \
        "Options:" \
        " -d <dir>   Override tool staging directory; Velociraptor appends /velociraptor/velociraptor" \
        "            Velociraptor default: workstation.binary, then ~/velociraptor/velociraptor" \
        "            Other tools default: AI_SKILLS_TOOLS_DATA_ROOT/tools (or <repo>/tools)" \
        " -t <tool>  Prepare a specific component: venv | plaso | velociraptor | volatility | tsk | all" \
        "            (default: all)" \
        "            Creates or reuses the repo virtualenv at ./.venv" \
        " --init-velociraptor-workspace" \
        "            Initialize a local GUI/API workspace after installing Velociraptor" \
        " -h, --help Show this help message"
    exit 0
}

requirements_include_plaso() {
    [ -f "$REQUIREMENTS_FILE" ] || return 1
    grep -Eq '^[[:space:]]*plaso([[:space:]]*[<>=!~].*)?$' "$REQUIREMENTS_FILE"
}

ensure_pkg_config() {
    if command -v pkg-config >/dev/null 2>&1; then
        return 0
    fi

    if [ "$OS" != "Darwin" ]; then
        warn "pkg-config not found; Plaso native dependency builds may fail"
        return 1
    fi

    if ! command -v brew >/dev/null 2>&1; then
        warn "pkg-config not found and Homebrew is unavailable"
        warn "Install pkg-config before retrying native Plaso prep"
        return 1
    fi

    info "Installing pkg-config via Homebrew for native Plaso dependencies"
    brew install pkg-config || {
        warn "Homebrew could not install pkg-config"
        return 1
    }

    command -v pkg-config >/dev/null 2>&1
}

verify_plaso_cli() {
    [ -x "$VENV_LOG2TIMELINE" ] || return 1
    "$VENV_LOG2TIMELINE" --version >/dev/null 2>&1
}

ensure_repo_venv() {
    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 not found - cannot create repo virtual environment at ${VENV_DIR}"
        return 1
    fi

    if [ ! -d "$VENV_DIR" ]; then
        info "Creating repo virtual environment at: $VENV_DIR"
        python3 -m venv "$VENV_DIR" || {
            warn "Could not create repo virtual environment at ${VENV_DIR}"
            return 1
        }
    else
        info "Using repo virtual environment: $VENV_DIR"
    fi

    if [ ! -x "$VENV_PYTHON" ]; then
        warn "Repo virtual environment is missing Python executable: $VENV_PYTHON"
        return 1
    fi

    info "Upgrading repo virtual environment packaging helpers"
    "$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel || \
        warn "Could not upgrade pip, setuptools, and wheel inside ${VENV_DIR}"

    if [ -f "$REQUIREMENTS_FILE" ]; then
        if requirements_include_plaso; then
            ensure_pkg_config || warn "Proceeding without pkg-config; native Plaso install may fail"
        fi
        info "Installing repo Python requirements into: $VENV_DIR"
        (cd -- "$REPO_ROOT" && "$VENV_PYTHON" -m pip install -r "$REQUIREMENTS_FILE") || \
            warn "Could not install repo requirements from ${REQUIREMENTS_FILE}"
    fi

    VENV_READY=1
    success "Repo virtual environment ready at: $VENV_DIR"
}

ensure_plaso() {
    ensure_repo_venv || return 1
    if verify_plaso_cli; then
        success "Native Plaso is already available in: $VENV_DIR"
        return 0
    fi

    ensure_pkg_config || warn "Proceeding without pkg-config; native Plaso install may fail"
    info "Installing Plaso ${PLASO_VERSION} into: $VENV_DIR"
    "$VENV_PYTHON" -m pip install "plaso==${PLASO_VERSION}" || return 1
    verify_plaso_cli
}

check_velociraptor_import_connectivity() {
    info "Checking outbound HTTPS access required for Velociraptor artifact imports"

    curl -fsSL --max-time 10 -o /dev/null "https://sigma.velocidex.com/" || return 1
    curl -fsSL --max-time 10 -o /dev/null "https://api.github.com/" || return 1
}

stop_velociraptor_pid() {
    local pid="${1-}"
    local listener_pid=""
    local port=""
    local waited=0

    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" 2>/dev/null || true
    elif [ -n "$pid" ]; then
        wait "$pid" 2>/dev/null || true
    fi

    pkill -f 'velociraptor gui -v --datastore=\. --nobrowser --noclient' >/dev/null 2>&1 || true

    command -v lsof >/dev/null 2>&1 || return 0

    for port in $VELOCIRAPTOR_LOCAL_PORTS; do
        listener_pid="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
        if [ -n "$listener_pid" ]; then
            info "Stopping local Velociraptor listener on TCP port ${port}"
            kill $listener_pid >/dev/null 2>&1 || true
        fi
    done

    while [ "$waited" -lt 10 ]; do
        for port in $VELOCIRAPTOR_LOCAL_PORTS; do
            if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
                sleep 1
                waited=$((waited + 1))
                continue 2
            fi
        done
        return 0
    done
}

ensure_velociraptor_api_user() {
    local binary="$1"
    local config_file="$2"
    local api_user="$3"

    if [ "$api_user" = "admin" ]; then
        info "Using built-in Velociraptor admin account for local API access"
        return 0
    fi

    info "Creating or updating local Velociraptor API user: ${api_user}"
    "$binary" --config "$config_file" user add --role "$VELOCIRAPTOR_API_ROLES" "$api_user" "$VELO_LOCAL_API_PASSWORD" \
        || return 1
    "$binary" --config "$config_file" acl grant --role "$VELOCIRAPTOR_API_ROLES" "$api_user" \
        || return 1
}

collect_velociraptor_server_artifact() {
    local workspace_dir="$1"
    local artifact_name="$2"
    local binary="$VELOCIRAPTOR_BINARY"
    local api_client_file="${workspace_dir}/api_client.yaml"
    local output_stem="${artifact_name//./-}"
    local import_log="${workspace_dir}/${output_stem}.log"
    local import_json="${workspace_dir}/${output_stem}.json"
    local attempt=""

    if [ ! -f "$api_client_file" ]; then
        warn "Cannot collect ${artifact_name} without API config: ${api_client_file}"
        return 1
    fi

    info "Collecting ${artifact_name} into the root org as API user '${VELOCIRAPTOR_API_USER}'"
    : >"$import_log"

    for attempt in 1 2 3; do
        if velociraptor_api "$binary" "$api_client_file" \
            artifacts collect "$artifact_name" \
            --client_id server --org_id root --format json \
            >"$import_json" 2>>"$import_log"; then
            success "${artifact_name} completed in: ${workspace_dir}"
            return 0
        fi

        sleep 2
    done

    warn "${artifact_name} did not complete successfully"
    warn "Check import log: ${import_log}"
    return 1
}

initialize_velociraptor_workspace() {
    local workspace_dir="$1"
    local binary="$VELOCIRAPTOR_BINARY"
    local config_file="${workspace_dir}/server.config.yaml"
    local api_client_file="${workspace_dir}/api_client.yaml"
    local gui_log="${workspace_dir}/gui-init.log"
    local pid=""

    info "Initializing Velociraptor workspace in: $workspace_dir"
    info "Starting GUI mode and waiting up to ${VELOCIRAPTOR_INIT_SECONDS} seconds for local config"

    (
        cd "$workspace_dir"
        exec "$binary" gui -v --datastore=. --nobrowser --noclient >"$gui_log" 2>&1
    ) &
    pid=$!

    if ! wait_for_file "$config_file" "$VELOCIRAPTOR_INIT_SECONDS"; then
        stop_velociraptor_pid "$pid"
        warn "Velociraptor did not generate ${config_file}"
        warn "Check initialization log: ${gui_log}"
        return 1
    fi

    info "Stopping Velociraptor GUI before local API bootstrap"
    stop_velociraptor_pid "$pid"
    if [ -n "${VELO_LOCAL_API_PASSWORD:-}" ]; then
        ensure_velociraptor_api_user "$binary" "$config_file" "$VELOCIRAPTOR_API_USER" \
            || {
                warn "Could not create or update local Velociraptor API user: ${VELOCIRAPTOR_API_USER}"
                return 1
            }
    else
        info "Leaving the local GUI default credentials unchanged; set VELO_LOCAL_API_PASSWORD to create a local password-authenticated user"
    fi

    info "Generating Velociraptor API client config at: $api_client_file"
    "$binary" --config "$config_file" config api_client --name "$VELOCIRAPTOR_API_USER" --role "$VELOCIRAPTOR_API_ROLES" "$api_client_file" \
        || {
            warn "Could not generate Velociraptor API client config at ${api_client_file}"
            return 1
        }

    info "Restarting Velociraptor GUI for API verification and artifact imports"
    (
        cd "$workspace_dir"
        exec "$binary" gui -v --datastore=. --nobrowser --noclient >"$gui_log" 2>&1
    ) &
    pid=$!

    if ! wait_for_velociraptor_api "$workspace_dir" "$VELOCIRAPTOR_API_WAIT_SECONDS"; then
        warn "Velociraptor API did not become ready during initialization; skipping artifact imports"
    elif check_velociraptor_import_connectivity; then
        collect_velociraptor_server_artifact "$workspace_dir" "Server.Import.Extras" \
            || warn "Velociraptor extra artifact import did not complete cleanly"
        collect_velociraptor_server_artifact "$workspace_dir" "Server.Import.ArtifactExchange" \
            || warn "Velociraptor artifact exchange import did not complete cleanly"
        collect_velociraptor_server_artifact "$workspace_dir" "Server.Import.DetectRaptor" \
            || warn "Velociraptor DetectRaptor import did not complete cleanly"
    else
        warn "Outbound internet check failed; skipping Velociraptor community artifact imports"
    fi

    info "Stopping Velociraptor GUI initialization process"
    stop_velociraptor_pid "$pid"

    success "Velociraptor workspace initialized at: $workspace_dir"
}

make_velociraptor_root_only() {
    local workspace_dir="$1"
    local config_file="${workspace_dir}/server.config.yaml"
    local temp_file="${workspace_dir}/server.config.yaml.tmp"

    [ -f "$config_file" ] || return 0

    if grep -q '^  initial_orgs:$' "$config_file"; then
        info "Removing default Velociraptor tenant definitions and keeping root only"
        awk '
            {
                if (skip) {
                    if ($0 ~ /^  [A-Za-z_][A-Za-z0-9_]*:/) {
                        skip=0
                    } else {
                        next
                    }
                }

                if ($0 ~ /^  initial_orgs:$/) {
                    skip=1
                    next
                }

                print
            }
        ' "$config_file" > "$temp_file"
        mv "$temp_file" "$config_file"
    fi

    rm -rf "${workspace_dir}/orgs/O123" "${workspace_dir}/orgs/O123.json.db"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -d)
            DOWNLOAD_DIR="${2:?missing value for -d}"
            DOWNLOAD_DIR_EXPLICIT=1
            shift 2
            ;;
        -t)
            TOOL="${2:?missing value for -t}"
            shift 2
            ;;
        --init-velociraptor-workspace)
            INITIALIZE_VELOCIRAPTOR_WORKSPACE=1
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

case "$OS" in
    Linux|Darwin) ;;
    *) error "Unsupported operating system: $OS (supported: Linux, Darwin/macOS)" ;;
esac

case "$TOOL" in
    venv|plaso|velociraptor|volatility|tsk|all) ;;
    *) error "Unknown tool '$TOOL'. Choose from: venv, plaso, velociraptor, volatility, tsk, all" ;;
esac

info "Repo root detected as: $REPO_ROOT"
info "Repo virtual environment path: $VENV_DIR"

if [ "$TOOL" = "venv" ]; then
    ensure_repo_venv || error "Failed to prepare repo virtual environment at ${VENV_DIR}"
    success "Done. Repo virtual environment is prepared at: $VENV_DIR"
    exit 0
fi

if [ "$TOOL" = "plaso" ]; then
    ensure_plaso || error "Plaso is not available in ${VENV_DIR}. Check pip output and host build prerequisites."
    success "Done. Native Plaso is prepared in: $VENV_DIR"
    info "Verify with:"
    info "  ${VENV_LOG2TIMELINE} --version"
    exit 0
fi

require_cmd curl
case "$TOOL" in
    volatility|tsk|all) require_cmd tar ;;
esac

case "$TOOL" in
    volatility|tsk|all)
        mkdir -p "$DOWNLOAD_DIR"
        DOWNLOAD_DIR="$(cd "$DOWNLOAD_DIR" && pwd)"
        info "Other tools will be saved to: $DOWNLOAD_DIR"
        ;;
esac
case "$TOOL" in
    volatility|all) ensure_repo_venv || true ;;
esac

download_velociraptor() {
    local dest="${VELO_BIN:-${HOME}/velociraptor/velociraptor}"
    if [ "$DOWNLOAD_DIR_EXPLICIT" -eq 1 ]; then
        dest="${DOWNLOAD_DIR}/velociraptor/velociraptor"
    fi
    case "$dest" in
        '~/'*) dest="${HOME}/${dest#\~/}" ;;
        '$HOME/'*) dest="${HOME}/${dest#\$HOME/}" ;;
        '${HOME}/'*) dest="${HOME}/${dest#\$\{HOME\}/}" ;;
    esac
    if [[ "$dest" != */* ]]; then
        dest="$(command -v "$dest")" || error "Configured Velociraptor command is not on PATH; set workstation.binary to an executable path or use -d <parent>"
        [[ "$dest" == /* ]] || dest="${PWD}/${dest}"
    elif [[ "$dest" != /* ]]; then
        if [ "$DOWNLOAD_DIR_EXPLICIT" -eq 1 ]; then
            dest="${PWD}/${dest}"
        else
            dest="${REPO_ROOT}/${dest}"
        fi
    fi
    local dest_dir
    dest_dir="$(dirname "$dest")"
    VELOCIRAPTOR_BINARY="$dest"

    local requested_tag="${VELO_LOCAL_VERSION_TAG:-}"
    if [ -n "$requested_tag" ] && [[ "$requested_tag" != v* ]]; then
        requested_tag="v${requested_tag}"
    fi

    if [ -n "$requested_tag" ]; then
        info "Fetching configured Velociraptor release tag: ${requested_tag}"
    else
        info "Fetching latest Velociraptor release tag..."
    fi

    local tag
    tag="$(github_release_tag "Velocidex/velociraptor" "$requested_tag")"
    [ -n "$tag" ] || error "Could not resolve Velociraptor release tag: ${requested_tag:-latest}"

    info "Velociraptor release: $tag"

    local asset_regex
    case "$OS" in
        Linux)
            case "$ARCH" in
                x86_64|amd64) asset_regex='velociraptor-v[0-9][0-9A-Za-z.-]*-linux-amd64' ;;
                aarch64|arm64) asset_regex='velociraptor-v[0-9][0-9A-Za-z.-]*-linux-arm64' ;;
                *) error "Unsupported architecture for Velociraptor on Linux: $ARCH" ;;
            esac
            ;;
        Darwin)
            case "$ARCH" in
                x86_64) asset_regex='velociraptor-v[0-9][0-9A-Za-z.-]*-darwin-amd64' ;;
                arm64)  asset_regex='velociraptor-v[0-9][0-9A-Za-z.-]*-darwin-arm64' ;;
                *) error "Unsupported architecture for Velociraptor on macOS: $ARCH" ;;
            esac
            ;;
    esac

    local url
    url="$(github_release_download_url "Velocidex/velociraptor" "$asset_regex" "$tag")"
    [ -n "$url" ] || error "Could not find a Velociraptor release asset matching ${asset_regex} in tag ${tag}"
    mkdir -p "$dest_dir"

    info "Downloading Velociraptor from: $url"
    curl -fsSL --retry 3 -o "$dest" "$url"
    chmod +x "$dest"
    success "Velociraptor saved to: $dest"
    if [ "$INITIALIZE_VELOCIRAPTOR_WORKSPACE" -eq 1 ]; then
        initialize_velociraptor_workspace "$dest_dir" || warn "Velociraptor workspace initialization did not complete cleanly"
        make_velociraptor_root_only "$dest_dir"
        info "Velociraptor workspace: $dest_dir"
        info "API client config is generated at:"
        info "  ${dest_dir}/api_client.yaml"
    else
        info "Local GUI workspace initialization was not requested"
        info "Use --init-velociraptor-workspace only for an intentional local GUI deployment"
    fi
    info "To save this executable path in your settings:"
    printf '  vraptor setup configure --velociraptor-bin %q\n' "$dest"
}

download_volatility() {
    info "Fetching latest Volatility 3 release tag..."
    local tag
    tag="$(github_latest_tag "volatilityfoundation/volatility3")"

    info "Latest Volatility 3 release: $tag"

    local archive_name="volatility3-${tag}.tar.gz"
    local url="https://github.com/volatilityfoundation/volatility3/archive/refs/tags/${tag}.tar.gz"
    local dest_archive="${DOWNLOAD_DIR}/${archive_name}"
    local dest_dir="${DOWNLOAD_DIR}/volatility3"

    info "Downloading Volatility 3 from: $url"
    curl -fsSL --retry 3 -o "$dest_archive" "$url"

    info "Extracting Volatility 3 archive..."
    mkdir -p "$dest_dir"
    tar -xzf "$dest_archive" -C "$dest_dir" --strip-components=1
    rm -f "$dest_archive"

    success "Volatility 3 extracted to: $dest_dir"

    if [ "$VENV_READY" -eq 1 ]; then
        if [ -f "${dest_dir}/requirements.txt" ]; then
            info "Installing Volatility 3 requirements.txt into: $VENV_DIR"
            "$VENV_PYTHON" -m pip install --quiet -r "${dest_dir}/requirements.txt" \
                || warn "Could not auto-install Volatility 3 requirements into ${VENV_DIR}"
        elif [ -f "${dest_dir}/pyproject.toml" ]; then
            info "Installing Volatility 3 package extras (full, cloud, arrow) into: $VENV_DIR"
            "$VENV_PYTHON" -m pip install --quiet -e "${dest_dir}[full,cloud,arrow]" \
                || warn "Could not auto-install Volatility 3 package extras into ${VENV_DIR}"
            if [ -f "$REQUIREMENTS_FILE" ]; then
                info "Re-applying repo Python requirements after Volatility 3 install"
                (cd -- "$REPO_ROOT" && "$VENV_PYTHON" -m pip install --quiet -r "$REQUIREMENTS_FILE") \
                    || warn "Could not re-apply repo requirements after Volatility 3 install"
            fi
        else
            warn "Volatility 3 install metadata not found in ${dest_dir}"
        fi
    else
        warn "Repo virtual environment is not ready - create ${VENV_DIR} and install ${dest_dir}/requirements.txt manually"
    fi

    info "Run Volatility through the repo virtual environment:"
    info "  ${VENV_PYTHON} ${dest_dir}/vol.py --help"
}

download_tsk() {
    info "Fetching latest Sleuth Kit release tag..."
    local tag
    tag="$(github_latest_tag "sleuthkit/sleuthkit")"
    local version="${tag#sleuthkit-}"

    info "Latest Sleuth Kit release: $tag"

    case "$OS" in
        Darwin)
            if command -v brew >/dev/null 2>&1; then
                info "Installing Sleuth Kit via Homebrew..."
                brew install sleuthkit
                success "Sleuth Kit installed via Homebrew"
                return
            fi
            ;;
    esac

    local archive_name="sleuthkit-${version}.tar.gz"
    local url="https://github.com/sleuthkit/sleuthkit/releases/download/${tag}/${archive_name}"
    local dest_archive="${DOWNLOAD_DIR}/${archive_name}"
    local dest_dir="${DOWNLOAD_DIR}/sleuthkit-${version}"

    info "Downloading Sleuth Kit source from: $url"
    curl -fsSL --retry 3 -o "$dest_archive" "$url"

    info "Extracting Sleuth Kit archive..."
    tar -xzf "$dest_archive" -C "$DOWNLOAD_DIR"
    rm -f "$dest_archive"

    success "Sleuth Kit source extracted to: $dest_dir"
    info "To build, run:"
    info "  cd ${dest_dir} && ./configure && make && sudo make install"
}

case "$TOOL" in
    velociraptor) download_velociraptor ;;
    volatility)   download_volatility ;;
    tsk)          download_tsk ;;
    all)
        ensure_plaso || warn "Plaso installation did not complete cleanly"
        download_velociraptor
        download_volatility
        download_tsk
        ;;
esac

if verify_plaso_cli; then
    success "Native Plaso is available in: $VENV_DIR"
else
    warn "Native Plaso is not currently available in: $VENV_DIR"
fi

success "Done. All requested tools are prepared."

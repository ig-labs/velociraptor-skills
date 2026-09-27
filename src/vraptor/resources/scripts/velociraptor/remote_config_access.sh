#!/usr/bin/env bash
# Shared privilege boundary for remote configuration access. Never print payloads.

shell_quote() {
    local value="${1-}"
    printf "'"
    while [[ "$value" == *"'"* ]]; do
        printf '%s' "${value%%\'*}" "'\\''"
        value="${value#*\'}"
    done
    printf "%s'" "$value"
}

remote_as_user() {
    local command="$1" run_as="$2"
    printf '_vraptor_command=%s; _vraptor_user=%s; ' "$(shell_quote "$command")" "$(shell_quote "$run_as")"
    printf '%s' 'if [ "$(id -un)" = "$_vraptor_user" ]; then exec sh -c "$_vraptor_command"; elif command -v runuser >/dev/null 2>&1; then exec runuser -u "$_vraptor_user" -- sh -c "$_vraptor_command"; else exec su -s /bin/sh "$_vraptor_user" -c "$_vraptor_command"; fi'
}

detect_remote_user() {
    if [ -z "${REMOTE_UID:-}" ]; then
        REMOTE_UID="$(ssh "${SSH_ARGS[@]}" "$SSH_TARGET" 'id -u')" || return 1
        [[ "$REMOTE_UID" =~ ^[0-9]+$ ]] || return 1
    fi
}

prepare_remote_commands() {
    local path="$1" generation="$2" missing
    REMOTE_CONFIG_KIND="${3:-api}"
    missing="if test -e $(shell_quote "$path") || test -L $(shell_quote "$path"); then exit 1; elif test -d $(shell_quote "$(remote_dirname "$path")") && test -x $(shell_quote "$(remote_dirname "$path")"); then exit 0; else exit 2; fi"
    VERIFY_MISSING_COMMAND="$missing"
    READ_REMOTE_COMMAND="test -f $(shell_quote "$path") && cat -- $(shell_quote "$path")"
    GENERATE_REMOTE_COMMAND="$generation"
    if [ "$REMOTE_RUN_AS" != root ]; then
        GENERATE_REMOTE_COMMAND="$(remote_as_user "$generation" "$REMOTE_RUN_AS")"
    fi
}

manual_remote_config() {
    local path="$1" terminal command instructions answer account_shell handoff arg
    local run_as="${REMOTE_RUN_AS:-root}" installed_path filename generation output
    terminal="$(
        printf 'ssh'
        for arg in "${SSH_ARGS[@]}"; do
            if [[ "$arg" == -* ]]; then
                printf ' \\\n  %q' "$arg"
            else
                printf ' %q' "$arg"
            fi
        done
        printf ' \\\n  %q' "$SSH_TARGET"
    )"
    if [ "$run_as" = root ]; then
        account_shell='sudo su'
    else
        account_shell="sudo -u $(shell_quote "$run_as") bash"
    fi
    # Keep service-owned configuration beside the selected server configuration.
    # The separately configured fetch path may be an operator-readable copy.
    if [ "${REMOTE_CONFIG_KIND:-api}" = api ]; then
        case "$API_USER" in
            ''|*/*|*$'\n'*|*$'\r'*) error "API username must be usable as a single filename component" ;;
        esac
        filename="${API_USER}_api_client.yaml"
    else
        filename='dfir_client.config.yaml'
    fi
    installed_path="$(remote_dirname "$REMOTE_SERVER_CONFIG_PATH")/$filename"
    output='"$config_tmp/config.yaml"'
    generation="$(shell_quote "$REMOTE_VELOCIRAPTOR_BIN") \\
    --config $(shell_quote "$REMOTE_SERVER_CONFIG_PATH") \\
    config"
    if [ "${REMOTE_CONFIG_KIND:-api}" = api ]; then
        generation+=" api_client --name $(shell_quote "$API_USER") \\
    --role $(shell_quote "$API_ROLES") $output"
    else
        generation+=" client > $output"
    fi
    generation="  umask 077
  config_tmp=\$(mktemp -d /tmp/velociraptor-config.XXXXXXXX)
  $generation
  test -s $output
  chmod 600 $output
  mv -- $output $(shell_quote "$installed_path")
  rmdir -- \"\$config_tmp\""
    if [ "${REGENERATE_REMOTE_API:-0}" -eq 1 ]; then
        command="(
  set -e
$generation
)"
    elif [ "${PROVISION_API:-0}" -eq 1 ] || [ "${PROVISION_CLIENT:-0}" -eq 1 ]; then
        command="(
  set -e
  # Reuse either existing file, including symlinks.
  for file in $(shell_quote "$path") \\
              $(shell_quote "$installed_path"); do
    if [ -e \"\$file\" ] || [ -L \"\$file\" ]; then
      exit 0
    fi
  done
$generation
)"
    else
        command="# Reuse an existing configuration. Missing files require an explicitly authorized --provision-api or --provision-client invocation."
        installed_path="$path"
    fi
    # Leave the generation shell before using the SSH operator's sudo rights.
    if [ "$installed_path" = "$path" ]; then
        handoff="sudo chown -- $(shell_quote "$REMOTE_SSH_USER") $(shell_quote "$path")
sudo chmod 600 -- $(shell_quote "$path")"
    else
        handoff="sudo install -o $(shell_quote "$REMOTE_SSH_USER") -m 600 -- $(shell_quote "$installed_path") $(shell_quote "$path")"
        # Provisioning must preserve an existing selected retrieval file too.
        if [ "${REGENERATE_REMOTE_API:-0}" -ne 1 ]; then
            handoff="if [ -e $(shell_quote "$path") ] || [ -L $(shell_quote "$path") ]; then
  sudo chown -- $(shell_quote "$REMOTE_SSH_USER") $(shell_quote "$path")
  sudo chmod 600 -- $(shell_quote "$path")
else
  $handoff
fi"
        fi
    fi
    # The operator hands back only the requested YAML, never the server config.
    instructions="$(printf '%s\n' \
        'Non-root SSH account: prepare the requested configuration in your own terminal.' \
        '' \
        '# 1. Connect to the server.' \
        "$terminal" \
        '' \
        '# 2. Open the generation shell (enter your sudo password there).' \
        "$account_shell" \
        '' \
        '# 3. Prepare the configuration. Paste this entire block.' \
        "$command" \
        '' \
        '# Stop if generation fails; do not run the handoff commands below.' \
        '# 4. Leave the generation shell, then prepare the download.' \
        'exit' \
        "$handoff" \
        '' \
        '# 5. Disconnect from the server.' \
        'exit' \
        '' \
        'Return here and confirm Continue. If no sudo access is available, ask an administrator to prepare this file.')"
    printf '[USER ACTION REQUIRED]\n%s\n' "$instructions"
    if [ -n "${JSON_OUT:-}" ]; then
        mkdir -p "$(dirname "$JSON_OUT")"
        { printf '{\n'; json_field status needs_user_action; printf ',\n';
          json_field ssh_target "$SSH_TARGET"; printf ',\n';
          json_field instructions "$instructions"; printf '\n}\n'; } > "$JSON_OUT"
    fi
    if [ -t 0 ]; then
        read -r -p 'Configuration ready? Continue [y/N]: ' answer || return 3
        case "$answer" in
            y|Y|yes|YES)
                # Resume retrieval only; never execute privileged commands here.
                scp "${SCP_ARGS[@]}" "${SSH_TARGET}:${path}" "$LOCAL_TEMP_PATH" && return 0
                ;;
        esac
    fi
    return 3
}

generate_remote_config() {
    detect_remote_user || return 1
    if [ "$REMOTE_UID" != 0 ]; then
        manual_remote_config "$1"
    else
        ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "$GENERATE_REMOTE_COMMAND"
    fi
}

copy_remote_config() {
    local path="$1"
    # Preserve the unprivileged fast path for readable configurations.
    if scp "${SCP_ARGS[@]}" "${SSH_TARGET}:${path}" "$LOCAL_TEMP_PATH"; then
        return 0
    fi
    rm -f "$LOCAL_TEMP_PATH"
    detect_remote_user || return 1
    if [ "$REMOTE_UID" != 0 ]; then
        manual_remote_config "$path"
    else
        # stdout contains credentials and must go directly to the protected file.
        ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "$READ_REMOTE_COMMAND" > "$LOCAL_TEMP_PATH"
    fi
}

preview_remote_copy() {
    printf 'scp'
    printf ' %q' "${SCP_ARGS[@]}"
    printf ' %q %q\n' "${SSH_TARGET}:$1" "$LOCAL_TEMP_PATH"
    printf '# If SCP fails: root may stream the file; Non-root accounts receive manual instructions and a Continue prompt.\n'
    printf 'ssh'
    printf ' %q' "${SSH_ARGS[@]}"
    printf ' %q %q > %q\n' "$SSH_TARGET" "$READ_REMOTE_COMMAND" "$LOCAL_TEMP_PATH"
}

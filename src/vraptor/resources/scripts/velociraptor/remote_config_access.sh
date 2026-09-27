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

# Resolve a missing implicit service account before generation starts. Never
# retry a native generation failure under another identity.
select_remote_generation_user() {
    local result
    [ "${REMOTE_RUN_AS_DEFAULT:-0}" = 1 ] && [ "$REMOTE_RUN_AS" = velociraptor ] || return 0
    if ssh "${SSH_ARGS[@]}" "$SSH_TARGET" 'id -u velociraptor >/dev/null 2>&1'; then
        REMOTE_RUN_AS_DEFAULT=0
        return 0
    else
        result=$?
    fi
    if [ "$result" -ne 1 ]; then
        printf '[ERROR] Could not check the default remote generation account; no generation attempted.\n' >&2
        return 70
    fi
    warn "Default generation account velociraptor is absent; using root"
    REMOTE_RUN_AS=root
    REMOTE_RUN_AS_DEFAULT=0
    GENERATE_REMOTE_COMMAND="$REMOTE_GENERATION_COMMAND"
}

prepare_remote_commands() {
    local path="$1" generation="$2" missing
    REMOTE_CONFIG_KIND="${3:-api}"
    missing="if test -e $(shell_quote "$path") || test -L $(shell_quote "$path"); then exit 1; elif test -d $(shell_quote "$(remote_dirname "$path")") && test -x $(shell_quote "$(remote_dirname "$path")"); then exit 0; else exit 2; fi"
    VERIFY_MISSING_COMMAND="$missing"
    READ_REMOTE_COMMAND="test -f $(shell_quote "$path") && cat -- $(shell_quote "$path")"
    REMOTE_GENERATION_COMMAND="$generation"
    GENERATE_REMOTE_COMMAND="$generation"
    if [ "$REMOTE_RUN_AS" != root ]; then
        GENERATE_REMOTE_COMMAND="$(remote_as_user "$generation" "$REMOTE_RUN_AS")"
    fi
}

build_remote_config_steps() {
    local path="$1" sudo_prefix="${2-sudo }"
    local installed_path filename generation output command handoff
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
  command -v $(shell_quote "$REMOTE_VELOCIRAPTOR_BIN") >/dev/null 2>&1 || exit 72
  test -r $(shell_quote "$REMOTE_SERVER_CONFIG_PATH") || exit 73
  config_tmp=\$(mktemp -d /tmp/velociraptor-config.XXXXXXXX) || exit 77
  trap 'rm -rf -- \"\$config_tmp\"' 0
  if { $generation; } >\"\$config_tmp/generation.log\" 2>&1; then
    :
  else
    if LC_ALL=C grep -Fq 'Velociraptor should be running as the ' \"\$config_tmp/generation.log\"; then
      exit 71
    fi
    exit 74
  fi
  test -s $output || exit 75
  chmod 600 $output
  mv -- $output $(shell_quote "$installed_path") || exit 76"
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
        handoff="${sudo_prefix}chown -- $(shell_quote "$REMOTE_SSH_USER") $(shell_quote "$path")
${sudo_prefix}chmod 600 -- $(shell_quote "$path")"
    else
        handoff="${sudo_prefix}install -o $(shell_quote "$REMOTE_SSH_USER") -m 600 -- $(shell_quote "$installed_path") $(shell_quote "$path")"
        # Provisioning must preserve an existing selected retrieval file too.
        if [ "${REGENERATE_REMOTE_API:-0}" -ne 1 ]; then
            handoff="if [ -e $(shell_quote "$path") ] || [ -L $(shell_quote "$path") ]; then
  ${sudo_prefix}chown -- $(shell_quote "$REMOTE_SSH_USER") $(shell_quote "$path")
  ${sudo_prefix}chmod 600 -- $(shell_quote "$path")
else
  $handoff
fi"
        fi
    fi
    CONFIG_GENERATION_STEP="$command"
    CONFIG_INSTALLED_PATH="$installed_path"
    CONFIG_HANDOFF_STEP="test -s $(shell_quote "$installed_path")
$handoff"
    # An existing retrieval file takes precedence over the installed original.
    if [ "${REGENERATE_REMOTE_API:-0}" -ne 1 ]; then
        CONFIG_HANDOFF_STEP="if [ -e $(shell_quote "$path") ] || [ -L $(shell_quote "$path") ]; then
  test -s $(shell_quote "$path")
else
  test -s $(shell_quote "$installed_path")
fi
$handoff"
    fi
}

manual_remote_config() {
    local path="$1" terminal command instructions answer account_shell handoff arg
    local run_as="${REMOTE_RUN_AS:-velociraptor}"
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
    build_remote_config_steps "$path"
    command="$CONFIG_GENERATION_STEP"
    handoff="$CONFIG_HANDOFF_STEP"
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
    if [ "${VRAPTOR_CONFIG_MANUAL_PROMPT:-1}" = 1 ] && [ -t 0 ]; then
        read -r -p 'Configuration ready? Continue [y/N]: ' answer || return 3
        case "$answer" in
            y|Y|yes|YES)
                # Resume retrieval only; never execute privileged commands here.
                scp "${SCP_ARGS[@]}" "${SSH_TARGET}:${path}" "$LOCAL_TEMP_PATH" && test -s "$LOCAL_TEMP_PATH" && return 0
                ;;
        esac
    fi
    return 3
}

# Exit 70-79 means the privileged body ran and failed: never retry provisioning.
# Sudo authentication failures happen before that body starts.
report_remote_config_failure() {
    local result="$1" message
    case "$result" in
        71) message="Velociraptor rejected the generation account (${REMOTE_RUN_AS:-velociraptor}). Set --run-as to the server's Frontend.run_as_user, then retry." ;;
        72) message="Remote Velociraptor binary is unavailable in the generation account's PATH. Configure remote_bin with its absolute path." ;;
        73) message="The generation account cannot read the remote server configuration. Check --run-as and server_config." ;;
        74) message="Velociraptor credential generation failed. Check server configuration, datastore access and API roles; raw output is withheld because it may contain credentials." ;;
        75) message="Velociraptor returned an empty configuration; no generated file was installed." ;;
        76) message="Generated configuration could not be installed beside the server configuration. Check directory permissions for --run-as." ;;
        77) message="The generation account could not create a private temporary directory." ;;
        *) message="Remote configuration path checks, validation or ownership handoff failed." ;;
    esac
    printf '[ERROR] %s\n' "$message" >&2
}

sudo_remote_config() {
    local path="$1" command generation result
    if [ "${PROVISION_API:-0}" -eq 1 ] || [ "${PROVISION_CLIENT:-0}" -eq 1 ] || [ "${REGENERATE_REMOTE_API:-0}" -eq 1 ]; then
        select_remote_generation_user || return 70
    fi
    build_remote_config_steps "$path" ""
    generation="( $(remote_as_user "$CONFIG_GENERATION_STEP" "${REMOTE_RUN_AS:-velociraptor}") ) >/dev/null 2>&1"
    if [ "${REGENERATE_REMOTE_API:-0}" -ne 1 ]; then
        # Check as root before switching users: an inaccessible retrieval path
        # must never look absent to a less-privileged datastore owner.
        generation="if [ -e $(shell_quote "$path") ] || [ -L $(shell_quote "$path") ] ||
   [ -e $(shell_quote "$CONFIG_INSTALLED_PATH") ] || [ -L $(shell_quote "$CONFIG_INSTALLED_PATH") ]; then
  :
else
  test -d $(shell_quote "$(remote_dirname "$path")")
  test -x $(shell_quote "$(remote_dirname "$path")")
  test -d $(shell_quote "$(remote_dirname "$CONFIG_INSTALLED_PATH")")
  test -x $(shell_quote "$(remote_dirname "$CONFIG_INSTALLED_PATH")")
  $generation
fi"
    fi
    command="set -e
trap 'result=\$?; case \$result in 0|7[0-9]) exit \$result;; *) exit 70;; esac' 0
$generation
$CONFIG_HANDOFF_STEP"
    if ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "sudo -n -- sh -c $(shell_quote "$command")" >/dev/null 2>&1; then
        result=0
    else
        result=$?
    fi
    case "$result" in
        0) ;;
        7[0-9]) report_remote_config_failure "$result"; return 70 ;;
        255|130|137|143) return "$result" ;;
        *)
            # All three descriptors bypass captured helper output. The password
            # goes straight from the operator's terminal to remote sudo.
            if [ -t 0 ] && ( : </dev/tty ) 2>/dev/null; then
                printf '[INFO]  Remote configuration needs sudo; authenticate in this terminal.\n' >/dev/tty
                if ssh -t "${SSH_ARGS[@]}" "$SSH_TARGET" "sudo -- sh -c $(shell_quote "$command")" </dev/tty >/dev/tty 2>&1; then
                    result=0
                else
                    result=$?
                fi
                case "$result" in
                    0) ;;
                    7[0-9]) report_remote_config_failure "$result"; return 70 ;;
                    255|130|137|143) return "$result" ;;
                    *) manual_remote_config "$path"; return $? ;;
                esac
            else
                manual_remote_config "$path"
                return $?
            fi
            ;;
    esac
    API_CLIENT_SOURCE=remote_sudo_prepared
    REMOTE_CONFIG_PREPARED=1
    scp "${SCP_ARGS[@]}" "${SSH_TARGET}:${path}" "$LOCAL_TEMP_PATH" || return 1
    test -s "$LOCAL_TEMP_PATH"
}

generate_remote_config() {
    detect_remote_user || return 1
    if [ "$REMOTE_UID" != 0 ]; then
        sudo_remote_config "$1"
    else
        select_remote_generation_user || return 70
        ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "$GENERATE_REMOTE_COMMAND"
    fi
}

copy_remote_config() {
    local path="$1"
    # Preserve the unprivileged fast path for readable configurations.
    if scp "${SCP_ARGS[@]}" "${SSH_TARGET}:${path}" "$LOCAL_TEMP_PATH"; then
        test -s "$LOCAL_TEMP_PATH" || return 70
        return 0
    fi
    rm -f "$LOCAL_TEMP_PATH"
    # A transfer failure must not run an already completed generation again.
    [ "${REMOTE_CONFIG_PREPARED:-0}" -eq 0 ] || return 70
    detect_remote_user || return 1
    if [ "$REMOTE_UID" != 0 ]; then
        sudo_remote_config "$path"
    else
        # stdout contains credentials and must go directly to the protected file.
        ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "$READ_REMOTE_COMMAND" > "$LOCAL_TEMP_PATH"
    fi
}

preview_remote_copy() {
    printf 'scp'
    printf ' %q' "${SCP_ARGS[@]}"
    printf ' %q %q\n' "${SSH_TARGET}:$1" "$LOCAL_TEMP_PATH"
    printf '# If SCP fails: root may stream the file; non-root uses sudo, with a terminal-only password prompt or manual fallback.\n'
    printf 'ssh'
    printf ' %q' "${SSH_ARGS[@]}"
    printf ' %q %q > %q\n' "$SSH_TARGET" "$READ_REMOTE_COMMAND" "$LOCAL_TEMP_PATH"
}

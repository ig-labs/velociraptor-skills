# Shared remote API and endpoint configuration generation

Both `live-remote` and `remote-deaddisk` use the same API identity and API-client
YAML procedure. Only remote dead-disk additionally needs an endpoint YAML to
enroll its mapped client; do not generate an endpoint YAML for live API access.

## Account setup comes before YAML generation

Setup passes `--provision-api` under the
[API-user provisioning rule](../../../docs/reference/velociraptor-operation-authorization.md#api-user-provisioning).
Inspect the effective identity first; do not infer it from cached YAML, the OS
login or application defaults. Existing accounts remain unchanged, and failed
absence checks stop creation.

Use `vraptor setup start --mode live-remote --id CASE --server-profile NAME
--server-ip HOST --api-user USER --provision-api` for account setup. The same
account procedure applies to `remote-deaddisk`. Provisioning runs even when the
operational YAML is already cached. It never changes an existing account's roles,
password, or organization memberships.

Generic installations have no built-in bootstrap account. Setup displays the
selected username, roles, organization and an administrator-notebook VQL command.
The operator verifies the intended running server, checks that the account does
not already exist (including in another org), coordinates other administrators,
and creates it only if absent. For an existing account, inspect its permissions;
resolve differences separately rather than rerunning `user_create()` over it.
After confirming the account, continue in the terminal or rerun the same setup
command with `--api-account-ready`. This acknowledgement never bypasses final
selected-user authentication or authorization checks.

If the existing API YAML is kept (no `--force` or `--regenerate-remote-api`)
and already authenticates as the selected user with the selected roles, setup
skips this manual step and says so; a terminal session
asks whether to run it anyway. Add `--api-account-setup` to run it when the
operator asks.

An explicitly configured remote administrator may automate this account step:
`--bootstrap-api-config /secure/admin.yaml --bootstrap-api-user bootstrap-admin`.
Equivalent named-connection keys are `bootstrap_api_config` and
`bootstrap_api_user`. There are no generic default values. These credentials stay
on the SSH host and are never installed locally or used for operational readiness,
client discovery, collections, hunts or analysis. Only bootstrap identity and
permission checks, selected-account lookup, creation and creation verification
may use this connection. A failure stops setup without another identity fallback.

Remote automation requires trusted SSH host keys, a readable protected bootstrap
YAML and selected server config, Python 3 with PyYAML, and the Velociraptor binary
on the SSH host. It does not install prerequisites, invoke sudo, or generate an
administrator credential. It verifies the YAML/server CA binding and authenticated
bootstrap identity, selected org, ANY_QUERY and SERVER_ADMIN. When operational
YAML is cached, its CA must also match before any remote API query or account
creation; the cached private key is never sent to the SSH host. The SSH account must
be able to read both files. Existing `<profile>_known_hosts` is used when present;
otherwise normal SSH known-hosts files apply. Establish host trust in the user's
terminal when missing; do not disable host verification.

The remote API CLI runs with `--verbose --nocolor` so account diagnostics are
available for validation. Its stdout and stderr stay captured on the SSH host;
raw diagnostics are never included in the receipt. A null account result confirms
absence only with the exact selected-user-not-found diagnostic and no other query
error. Missing diagnostics, permission failures and conflicting results stop
provisioning; a null result alone never authorizes creation.

A server-local lock beside the bootstrap YAML serializes these provisioning runs.
The account is checked again immediately before one `user_create()` call. This
VQL function is an upsert, not an atomic create-if-absent: unrelated GUI/API
administrators must not modify the same account during provisioning. A private
`.vraptor-api-*.pending` marker prevents automatic replay after an uncertain write.
A later run can reconcile a correctly provisioned account read-only; otherwise an
administrator must resolve the pending operation before another creation attempt.
Any failure after submitting creation, including its verification lookup, reports
an uncertain write and retains the marker; it must not claim no creation occurred.
No service restart or credential regeneration is used to repair authentication.

After account setup, missing YAML is generated **without `--role`** so generation
cannot replace an existing ACL. Staged local YAML is verified using only the
selected operational identity before replacing an existing local file. The
returned identity, organization, expected roles and effective permissions must
match. Explicit remote YAML replacement still requires `--regenerate-remote-api`.

The lower-level `config fetch-api --provision-api` helper only permits signing a
missing YAML; it neither creates accounts nor verifies live readiness. Use it only
after the account step above. A helper's `ready` manifest denotes completed file
retrieval, not an authenticated account. `api_roles` records expected roles only.

## Credential generation and retrieval

Prefer `vraptor config fetch-api --server-profile NAME --provision-api --force`
with the configured SSH connection. The helper uses root or sudo, prompts for a
sudo password directly in the terminal when necessary, then fetches the YAML
automatically. Use `fetch-client --provision-client` for endpoint YAML. `--force`
refreshes the local copy only; remote API replacement requires
`--regenerate-remote-api`.

The manual sequence below is the fallback when sudo is unavailable or an agent
cannot open an interactive terminal. Use for explicitly authorized generation or replacement. Substitute the SSH host,
key, login user, configured generation user (`run_as`), API identity and
retrieval paths for the selected deployment. Confirm the active server config
path first; `/etc/velociraptor/server.config.yaml` is the example here.
The selected commands replace the named YAMLs. Reuse existing valid
files when replacement was not requested.

Include the API username in its credential filename: the example uses
`investigation-api_api_client.yaml` for `--name investigation-api`. Substitute
the same username in every API YAML path below. The endpoint configuration and
server reference are deployment-wide and keep their existing names.

Run in the operator's terminal. Plain `ssh -i` opens an interactive login;
`-t` is only needed to force terminal allocation, such as when passing a remote
interactive command. Do not handle sudo passwords in chat.

For a non-root SSH login, choose the shell from the configured `run_as`:
use `sudo su` when it is `root`, or `sudo -u velociraptor bash` when it is
`velociraptor` (substitute another service account when configured). The SSH
login user and generation user are separate settings. A direct root SSH login
retains automatic helper generation; it does not need the manual sudo handoff.

Connect and enter the selected generation shell:

```sh
ssh -i ~/.ssh/velociraptor-test operator@velo.example.net
sudo -u velociraptor bash
# If run_as is root, use sudo su instead of the line above.
umask 077

# Use a private temporary directory to avoid collisions in shared /tmp.
config_tmp=$(mktemp -d /tmp/velociraptor-config.XXXXXXXX)
/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name investigation-api "$config_tmp/investigation-api_api_client.yaml"
test -s "$config_tmp/investigation-api_api_client.yaml"

# Stop if either generation or validation failed. Otherwise move into place.
mv "$config_tmp/investigation-api_api_client.yaml" /etc/velociraptor/investigation-api_api_client.yaml
chmod 600 /etc/velociraptor/investigation-api_api_client.yaml
```

For remote dead-disk only, additionally run in the same generation shell:

```sh
/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml config client > "$config_tmp/dfir_client.config.yaml"
test -s "$config_tmp/dfir_client.config.yaml"
# Stop if generation or validation failed. Otherwise move into place.
mv "$config_tmp/dfir_client.config.yaml" /etc/velociraptor/dfir_client.config.yaml
chmod 600 /etc/velociraptor/dfir_client.config.yaml
```

Then finish the generation shell and prepare the selected retrieval copies:

```sh
rmdir "$config_tmp"
exit

# Retrieval copies: retain the service-owned originals in /etc/velociraptor.
sudo install -o operator -m 600 /etc/velociraptor/investigation-api_api_client.yaml /home/operator/investigation-api_api_client.yaml
# Remote dead-disk only:
sudo install -o operator -m 600 /etc/velociraptor/dfir_client.config.yaml /home/operator/dfir_client.config.yaml

# Optional: only when a server-reference copy was explicitly requested.
sudo install -o operator -m 600 /etc/velociraptor/server.config.yaml /home/operator/dfir_server.reference.yaml
exit
```

`umask 077` removes group/other permissions from newly created files and
directories (normally resulting in modes `600` and `700`). It applies to the
current shell and children, and does not change existing permissions.

Configure fetch helpers to use the operator-readable retrieval paths. After the
operator confirms completion, fetch the API YAML (and endpoint YAML for remote
dead-disk) with `--force`, verify nonempty
parseable content and mode `0600`, then validate the API and matching endpoint
configuration. Copy a requested server reference into the protected local
configuration directory, outside the repository; it contains server secrets.
Do not print its contents or use it to start a second server.

An API target of `127.0.0.1:8001` refers to the machine running the API client.
Verify the intended remote transport or SSH tunnel before using that address.
Never disable TLS verification to resolve an endpoint mismatch.

Generated non-root handoffs use private temporary files, validate nonempty output,
and move it beside the configured server YAML before copying to the configured
retrieval path. Missing-file provisioning preserves existing installed/retrieval
files; explicit API regeneration replaces the selected API identity's files.
Configure an operator-readable retrieval path distinct from the installed path
to retain service ownership of the installed original. When the fetch path is
the installed file itself, handoff transfers only that file to the SSH user.
Existing configured paths and the legacy `api_access_<API_USER>.yaml` default
remain supported; no existing files are renamed automatically.

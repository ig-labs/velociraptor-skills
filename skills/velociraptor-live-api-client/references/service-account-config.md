# Shared remote API and endpoint configuration generation

Both `live-remote` and `remote-deaddisk` use the same API identity and API-client
YAML procedure. Only remote dead-disk additionally needs an endpoint YAML to
enroll its mapped client; do not generate an endpoint YAML for live API access.

Use for explicitly authorized generation or replacement. Substitute the SSH host,
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
/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name investigation-api --role administrator,api "$config_tmp/investigation-api_api_client.yaml"
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

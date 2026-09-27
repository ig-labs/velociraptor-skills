---
name: velociraptor-live-api-client
description: Connect with existing Velociraptor API credentials, explicitly fetch remote API or endpoint configurations over SSH, execute bounded operator-provided VQL, and find or list clients. Use for generic live-server access, direct queries, client inventory, and remote offline-evidence setup.
---

# Velociraptor API access

**Required server prerequisite:** follow the shared
[DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md)
for every new local server and connected live/remote server. If the live catalog
contains no `DetectRaptor.` artifacts, run `Server.Import.Extras` with the
DetectRaptor CSV row and verify installation before proceeding. Reuse a successful
session check; a failed import blocks the workflow. Explicit read-only/no-import
instructions and offline-only work retain their scope.

Use the shared `vraptor` CLI (`dfir` is equivalent). Apply the shared
[operation authorization policy](../../docs/reference/velociraptor-operation-authorization.md)
and [investigation context](../../docs/reference/velociraptor-engagement-context.md).

For an existing deployment, provide the API-client YAML to shared setup:

```bash
vraptor setup start --mode live-remote --id ir1234 \
  --api-client /secure/lab_api_client.yaml --hostname host01
```

The YAML supplies the connection and certificate/private-key material. SSH access
and remote provisioning are optional. Keep credentials in native protected files;
operational settings store their paths. Analyst keys and tokens remain in the
selected environment source. Never substitute credentials from a different server
because an address happens to match.

For offline local evidence enrolled with a remote server, provide both native
configurations:

```bash
vraptor setup start --mode remote-deaddisk --id ir1234 \
  --api-client /secure/lab_api_client.yaml \
  --client-config /secure/lab_client.config.yaml \
  --evidence-path /evidence/disk.E01
```

Shared setup owns credential validation, readiness and mapping orchestration.
Live remote and remote dead-disk use the same API-user, role selection and
API-client generation/retrieval workflow. Remote dead-disk additionally needs
the matching endpoint configuration; live API access does not.
`velociraptor-mapped-client` owns the mapping lifecycle. Reuse existing evidence
with `vraptor analyze`; collection remains an explicit operation.

## Explicit SSH acquisition

Fetch a selected remote identity or endpoint configuration only when needed:

```bash
vraptor config fetch-api --server-profile lab --server-ip velo.example.net
vraptor config fetch-client --server-profile lab --server-ip velo.example.net
```

The fetch helpers require a server address when remote access is necessary. A
cached local file is reused before SSH checks unless `--force` is supplied.
Operational settings provide SSH user/key and remote paths; the legacy
`VELO_REMOTE_*` variables remain compatibility inputs. API acquisition also
uses the shared API identity (`CLI > environment/dotenv > named connection >
connection_defaults > vraptor`). Shared SSH user/key, server and endpoint config
paths, remote binary and service account can also live in `[connection_defaults]`.
Named connections override these defaults. Default destinations are
`<config_root>/<server-profile>_api_client.yaml` and
`<config_root>/<server-profile>_client.config.yaml`.

Save `org_id` on the named connection when the server uses organizations;
`--org-id` and resolved `VELO_LOCAL_ORG_ID` overrides remain supported. Verify the
organization alongside the server and API identity. `[api].grpc_max_message_bytes`
sets a positive send/receive and request-planning limit (64 MiB by default);
`--grpc-max-message-bytes` or `VELO_GRPC_MAX_MESSAGE_BYTES` can override it.
Use `setup show --server-profile NAME` to inspect values and sources.
Leave unused dotenv overrides empty so they do not mask saved settings.

Successful setup prints `To configure AI, run: vraptor ai setup`; `agent`
remains an alias for `ai`. This is a next-step note, not an automatic provider
configuration or connectivity test. Follow the printed settings-file selector.

Generation is explicit:

- `fetch-api --provision-api` may generate the selected API identity only after
  confirming the remote file is absent.
- `fetch-client --provision-client` may generate endpoint configuration only after
  confirming the remote file is absent.
- `fetch-api --regenerate-remote-api` replaces the selected remote API YAML and
  implies `--force`. Use only when replacement is authorized.

A failed copy, SSH error or permission error alone never triggers generation.
Fetches use temporary local files and replace the cache only after a complete
copy. Native credential validation and server permissions are checked by setup.
Root SSH sessions generate the requested YAML using the current root user;
an explicit `run_as` can select another datastore owner. Existing readable files
are copied with SCP. Root can also stream a protected file into a local
mode-0600 temporary file without displaying it.

For non-root SSH accounts, generation or an unreadable remote YAML returns
`needs_user_action` (fetch-helper exit 3). Show the supplied terminal commands:
interactive SSH, a shell selected by configured `run_as` (`sudo su` for `root`,
`sudo -u velociraptor bash` for that service account), the selected API-user/YAML generation command, and
ownership handoff of only that YAML to the SSH user with mode `0600`. Existing
remote files are reused unless regeneration was explicitly requested.
The helper prints numbered steps with multiline commands. Preserve the complete
preparation block when showing it: the subshell stops on errors, and its existing-file
checks prevent provisioning from replacing credentials.
Ask the user to confirm **Continue**, and pause credential-dependent setup until
they reply. Then retry the same setup/fetch command to retrieve the files and
verify readiness. Do not attempt sudo automatically, collect a password, retry
without confirmation, or mark the setup ready while waiting. Direct terminal
invocations provide a `Configuration ready? Continue [y/N]` prompt; noninteractive
agents must present that prompt to the user themselves.
`--api-role-profile investigation|provisioning-admin` selects the expected role
set. `--dry-run` does not create directories, change cached-file permissions or
write manifests. `--output-path`, `--json-out`, and `--dry-run` provide explicit destinations,
operation metadata and command preview. No raw evidence is exported by setup.

For a service-account deployment using `/etc/velociraptor/server.config.yaml`,
see [manual generation and protected reference copies](references/service-account-config.md).
Use this sequence when the operator requests generation or replacement; it
includes moving temporary YAMLs beside the server configuration (normally
`/etc/velociraptor/`) before protected retrieval copies. Endpoint-YAML steps
apply only to remote dead-disk; API steps are shared with live remote.

Do not modify skill/runtime configuration during operational use unless requested.
Use bounded read-only VQL unless a server mutation is explicitly authorized.

## Direct VQL

Use the engagement-specific cached API client by id:

```bash
dfir query \
  --server-profile lab \
  --vql "SELECT client_id, os_info.hostname AS Hostname FROM clients() LIMIT 10"
```

Read a longer query from a file:

```bash
dfir query \
  --server-profile lab \
  --vql-file /path/to/query.vql
```

Pass VQL environment values without interpolating them into shell text:

```bash
dfir query \
  --server-profile lab \
  --env HostRegex='^server-' \
  --vql "SELECT * FROM clients() WHERE os_info.hostname =~ HostRegex"
```

Behavior:

- API-client resolution is explicit `--api-client`, then
  `<VELO_LOCAL_CONFIG_ROOT>/<server-profile>_api_client.yaml`, then configured
  and default cached clients
- output is a JSON metadata envelope by default; use `--format jsonl` for rows
  only
- output is bounded to 1,000 rows by default; use `--max-rows` to change the
  bound and `--max-rows 0` only for deliberate unbounded output
- VQL may also be piped on stdin
- the response records a SHA-256 of the query but does not persist evidence
  rows automatically

Do not create one-off Python API snippets when this command can express the
query.

## Client Discovery

Find exact client details and labels by hostname or FQDN:

```bash
dfir clients find \
  --server-profile lab \
  --name major
```

Find by exact client id:

```bash
dfir clients find \
  --server-profile lab \
  --client-id C.eeca51bbad4f01eb
```

List all clients carrying an exact label:

```bash
dfir clients list \
  --server-profile lab \
  --label investigation-scope \
  --limit 0
```

Combine inventory filters:

```bash
dfir clients list \
  --server-profile lab \
  --search 'srv|dc' \
  --os windows \
  --label production \
  --exclude-label decommissioned \
  --online-within-minutes 5
```

Behavior:

- `--search` is a regex over hostname, FQDN, and client id
- repeated `--os` values use OR semantics
- repeated `--label` or `--tag` values use exact AND semantics
- repeated `--exclude-label` or `--exclude-tag` values exclude any match
- `--ignore-case` applies to name, search, OS, and label filters
- `--online-within-minutes` compares the returned `LastSeen` with command time
- client output includes identity, first/last seen, platform, machine,
  agent version, last IP, and normalized labels
- client output defaults to 1,000 rows; use `--limit 0` for every match

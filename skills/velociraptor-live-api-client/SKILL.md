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
  --api-client /secure/lab_api_client.yaml
```

Live setup defaults to server readiness for maintenance and hunt review. No
hostname or visible client is required; empty inventory is recorded separately
from API access and authorization. Optional host/client/label selectors require
target visibility without restricting later site-wide work. Resume preserves
saved selectors; `--environment-only-ok` clears them for server-only work.

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
Remote YAML generation defaults to the `velociraptor` service account, including
root SSH sessions. Explicit `run_as` settings or `--run-as` select another account
(for example, `--run-as root` for a root-owned deployment). Existing readable files
are copied with SCP. Root can also stream a protected file into a local
mode-0600 temporary file without displaying it.

If the default `velociraptor` account is absent, the fetch helper reports this
and selects root before generation. Explicit `run_as` settings (including
`velociraptor`) and `--run-as` disable this fallback. Account lookup errors and
generation failures stop without retrying as root.

For non-root SSH accounts, the fetch helper tries noninteractive sudo. If sudo
requires authentication and the invocation has a terminal, SSH opens a remote
terminal and sudo prompts there directly. The helper prepares only the requested
YAML with mode `0600`, retrieves it through SCP, and resumes automatically.
Generation still requires the provisioning flag; `--force` refreshes only the
local cache. The configured `run_as` selects the datastore owner for generation.
Passwords and generated YAML must never enter chat or captured setup output.
A failed privileged preparation is reported without automatically retrying it.
Diagnostics distinguish a rejected generation account, missing binary, unreadable
server config, native generation failure, empty output, and installation failure.
If Velociraptor rejects the account, set `--run-as` to `Frontend.run_as_user` from
the server configuration; sudo root access does not override that requirement.
Native output stays in a private temporary file and is removed after the attempt;
only fixed diagnostic messages are displayed, never credential-bearing logs.

If sudo is unavailable, or requires a password without an interactive terminal,
the helper returns `needs_user_action` (exit 3) with numbered manual steps.
Show those steps and wait for **Continue** before retrying the same fetch/setup
command. Preserve complete command blocks and existing-file checks. Direct
terminal invocations provide the Continue prompt; noninteractive agents must
present it themselves. Do not mark setup ready while waiting.
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

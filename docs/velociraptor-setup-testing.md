# Velociraptor setup and three-use-case test guide

Offline settings/setup regression checks (no live endpoint or provisioning):

```sh
.venv/bin/python -m pytest -q tests/test_vraptor_settings.py tests/test_vraptor_setup.py \
  tests/test_operational_connection_options.py tests/test_vraptor_lifecycle.py \
  tests/test_setup_config_transfer.py tests/test_reset_vraptor_config.py \
  tests/test_agent_profile_schema.py tests/test_agent_setup.py \
  tests/test_agent_setup_defaults.py tests/test_agent_settings_environment.py \
```

These cover connection-default precedence/source reporting, API-user prompting,
generic setup, settings transfer/reset, and analyst-path migration
without replacing an existing destination.
Additional checks cover copied dotenv defaults, shared SSH settings, per-profile
organizations, API transport caps, mapping timeouts, export/deploy/reset, and
the AI-setup completion note and singular `agent` compatibility alias. External API/process
boundaries are mocked.

Interactive configuration checks cover the grouped sections for live remote,
local-server and mapped-evidence settings, saved-profile selection, shared SSH
defaults, path normalization, invalid numeric input, skipped/blank-field
preservation and preview mode without writes. Run `vraptor setup configure
--preview` in an isolated test environment to review the terminal presentation;
headings and section descriptions appear with blank lines between groups.

Manual acceptance tests for the three supported setup workflows. These commands
have not been run against a live deployment as part of writing this guide.
Record actual results at the end; examples and successful offline checks are not
evidence of live completion.

These tests cover offline analyst-agent configuration, connection readiness,
mapped-client enrollment, case-local runtime, stop/resume behavior, and Windows
Prefetch plus evidence-of-execution collection. AI analysis remains outside this
test. Begin with [Install and set up vraptor](vraptor-installation.md) for the
combined installation and configuration flow; use the
[setup skill](../skills/velociraptor-engagement-setup/SKILL.md) for workflow details.

Give this guide to a tester on macOS or Linux. It uses generic inputs and requires
no site integration, Slack access or AI credentials.

| Use case | Runs on the tester's workstation | Uses server XYZ |
|---|---|---|
| Local | Local server and mapped evidence client | No |
| Mapped to XYZ | Mapped evidence client | Yes |
| Live on XYZ | API access to an existing live endpoint | Yes |

## Offline mapping input use cases

Both local-server and remote-server mapped-client workflows support these inputs:

| Offline use case | Evidence selector | Input |
|---|---|---|
| Windows disk image | `windows-disk` | Supported Windows disk image |
| Windows folder / mounted volume | `windows-directory` | Windows directory tree |
| Extracted Velociraptor KapeFiles collection | `velociraptor-export` | Extracted collection with `uploads.json` |
| Velociraptor KapeFiles zip | `velociraptor-kapefiles-zip` | Collection ZIP, optionally AES-protected `data.zip` |

`auto` detects supported collection folders and ZIP containers. These are input
variants of the two offline deployment workflows, not additional server modes.
Use a distinct mapping ID/workspace for each input binding.

For ZIP acceptance, verify file enumeration, actual content reads, registry
reads, client identity, heartbeat, supervisor health and same-identity resume.
Test missing/wrong passwords and changed ZIP rejection. Run
`.venv/bin/python -m pytest tests/test_zip_mapping.py tests/test_export_mapping.py`.
See [ZIP mapping](../skills/velociraptor-mapped-client/SKILL.md#velociraptor-kapefiles-zip)
for password handling, coverage limitations and performance trade-offs.

## Required DetectRaptor setup gate

For every new local server and connected live/remote server, follow the
[mandatory bootstrap](../docs/reference/detectraptor-bootstrap.md).
Acceptance requires a live nonempty `DetectRaptor.` catalog check. When initially
absent, run `Server.Import.Extras` with the DetectRaptor CSV row appended to the
server's existing Details, record the terminal import flow, inspect errors and
verify the catalog again. Test both the already-installed/no-reimport branch and
the missing/import branch. Failed imports block proceeding. Offline init alone
does not satisfy this server gate. This requirement is enforced by the skills;
it is not an automatic CLI bootstrap implementation.

## Inputs

- Python 3.11 or newer and a checkout of the supplied `vraptor` package/repository.
- A native Velociraptor executable for the two mapped-client tests; installation
  instructions are below.
- One supported Windows E01/raw image or a read-only mounted Windows volume.
  Select one exact path, not a wildcard or a directory containing many images.
- An existing remote server with an API-client YAML and matching endpoint/client
  YAML. Only the API YAML is needed for remote live work.
- An existing live endpoint visible to that API identity.
- If fetching existing credentials: SSH hostname, username, private-key path,
  API username and the remote configuration paths. SSH and API identities are
  independent. Do not put key contents or passwords in this document.

Replace example paths before running commands. Use unused investigation IDs for
the first run; keep the same IDs during stop/resume checks. An existing ID retains
its connection and runtime binding. Keep results and deployment-specific copies
of this guide outside the repository.

Replace these placeholders consistently:

| Placeholder | Tester or server administrator supplies |
|---|---|
| `SERVER_XYZ` | Remote server DNS name or IP address |
| `SSH_USER` | Existing SSH account on XYZ, only needed for SSH credential retrieval |
| `API_USER` | Existing Velociraptor API identity, independent of the SSH username |
| `/evidence/test.E01` | Exact local Windows image or read-only mounted Windows directory |
| Remote YAML paths | Actual locations readable by the selected SSH account |

The profile name `xyz` below is a local connection label, not a DNS hostname.

## 1. Install the tools

From the exported public repository root containing `pyproject.toml`:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
source .venv/bin/activate
vraptor --help
```

From the `ai_skills` root, replace the pip command with
`.venv/bin/python -m pip install ./packages/vraptor`. Keep the virtual environment
activated for the remaining commands. For an existing installation, activate its
environment and skip reinstalling. The Python package and native Velociraptor
executable are separate tools.

The native binary defaults to `~/velociraptor/velociraptor`. The next section
selects a separate test installation through `workstation.binary`. If reusing
an existing binary, substitute its absolute path and skip the download.

## 2. Prepare separate test settings

Run in Bash or zsh. This helper is for setup commands only:

```sh
vtest() {
  vraptor "$@" \
    --settings-file "$HOME/.config/vraptor/setup-tests.toml" \
    --case-root "$HOME/cases/setup-tests"
}

vtest setup configure \
  --velociraptor-bin "$HOME/velociraptor-test-tools/velociraptor/velociraptor"

vtest setup show
```

Install the native binary at the configured test path if needed:

```sh
vraptor tools prep -t velociraptor \
  --settings-file "$HOME/.config/vraptor/setup-tests.toml"
```

This writes `~/velociraptor-test-tools/velociraptor/velociraptor` without starting
a server. Check `vtest setup show` before installation: prep replaces any binary
at the effective path, including a legacy `VELO_BIN` override. After moving the
binary, rerun `vtest setup configure --velociraptor-bin /new/path/to/velociraptor`.

**Check before continuing:** effective paths and profile sources must be the
intended test values. Separate TOML does not suppress process or dotenv
overrides. Resolve unexpected overrides using the
[configuration reset instructions](../CONFIG.md#reset-velociraptor-setup-preferences)
or by correcting their source. The reset utility is optional and affects shared
preferences; it is not required just to create a test settings file.

### Configure the analyst agent once

Operational settings reference a shared `analyst-agents.toml`; exporting and
deploying them does not copy analyst profiles or provider credentials. Inspect
the selected path with `vtest setup show`, then review the effective profile:

```sh
vraptor ai config --settings-file "$HOME/.config/vraptor/setup-tests.toml"
vraptor ai setup --settings-file "$HOME/.config/vraptor/setup-tests.toml"
vraptor ai config --settings-file "$HOME/.config/vraptor/setup-tests.toml"
vraptor ai doctor --settings-file "$HOME/.config/vraptor/setup-tests.toml"
```

Run setup interactively to select or review the provider/harness, execution
profile, model, reasoning effort, timeout and concurrency. Reuse intended saved
values and preserve shared token budgets. To isolate analyst settings too, first
run `vtest setup configure --analyst-config-file /path/to/test-analyst-agents.toml`.
Alternatively pass `--config-file PATH` directly to the agent commands. Add
`--execution-profile NAME` consistently when selecting an existing named profile.
The setup, config and doctor commands must inspect the same file/profile;
process and dotenv overrides still apply.

Credentials stay in the selected environment or managed login source; TOML
stores references, not secret values. Record the effective file, profile,
provider, transport, model and doctor status. These checks are offline: they do
not prove live authentication or inference. Leave `ai doctor --live`,
`ai test` and evidence analysis for separately scoped tests. Missing analyst
credentials or dependencies are reported independently and do not block the
Velociraptor infrastructure tests. Configure the shared analyst once for all
investigations; do not create a separate profile per mapped host.

## 3. Use case: local server and mapped client

This test needs no remote server, SSH key or pre-existing API credentials. Setup
creates the local server's own configuration and credentials.

```sh
vtest setup start --mode local-deaddisk \
  --id test-local01 --server-profile test-local \
  --evidence-path /evidence/test.E01 --hostname test-local-disk

vtest setup status --id test-local01
```

Record the client ID and server identity before stopping.

Pass criteria:

- Setup reports ready and verifies an API-visible mapped client with recent
  `LastSeen` and healthy client/supervisor processes.
- Server state is under
  `~/cases/setup-tests/test-local01/runtime/velociraptor/server/` and mapping
  state is in the sibling `mapping/` directory.
- Mutable outputs are outside the evidence source. A read-only remap check does
  not substitute for a byte-for-byte evidence integrity comparison when required.

Test a complete shutdown and restart, then leave the test stopped:

```sh
vtest setup stop --id test-local01 --stop-server
vtest setup status --id test-local01
vtest setup resume --id test-local01
vtest setup status --id test-local01
# Run section 7 for this mapping's exact client ID before the final stop.
vtest setup stop --id test-local01 --stop-server
```

**Pass:** stop reports the owned processes stopped; resume succeeds with the same
mapped-client ID, server identity and datastore. If a port is occupied, setup
must fail without terminating the unrelated listener. Stop this local server
before starting another test that requires the same ports.

## 4. Prepare access to server XYZ

Ask the server administrator for an API-client YAML and the matching endpoint
client YAML. The API YAML's address and the client YAML's frontend address must
be reachable from the workstation; successful SSH alone does not prove API or
frontend connectivity. The administrator must also confirm the API identity's
role set and access to a live test endpoint.

### Option A: administrator supplies the native YAML files

Place them in the following private directory, using the filenames below. No
SSH key is required when both files have already been supplied securely:

```sh
mkdir -p "$HOME/.config/velociraptor"
# Place the administrator-supplied files here before the chmod command.
chmod 600 "$HOME/.config/velociraptor/xyz_api_client.yaml" \
  "$HOME/.config/velociraptor/xyz_client.config.yaml"
```

### Option B: retrieve existing YAML files over SSH

Reuse a suitable existing key, or create a dedicated test key. If the requested
filename already exists, reuse it or choose another name; decline any overwrite
prompt. Keep existing keys and authorized access in place.

```sh
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/velociraptor-test" -C velociraptor-testing
ssh-add "$HOME/.ssh/velociraptor-test"
```

Choose a passphrase locally. If no SSH agent is running, start one with
`eval "$(ssh-agent -s)"`, then repeat `ssh-add`. Send only
`~/.ssh/velociraptor-test.pub` to the server administrator; retain the private
key on the workstation.

The administrator appends the public-key line to the intended SSH account's
`~/.ssh/authorized_keys`, preserving existing entries. Run the following as that
account to prepare permissions; the files must be owned by the account:

```sh
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

After the administrator has added the public key, test from the workstation:

```sh
ssh -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \
  -i "$HOME/.ssh/velociraptor-test" SSH_USER@SERVER_XYZ 'id -un'
```

Verify the host-key fingerprint with the administrator on first connection.
Expected output is the selected SSH username. This check establishes SSH access,
not Velociraptor API authorization.

Configure retrieval using the actual API identity and remote paths:

```sh
vtest setup configure --server-profile xyz \
  --server-ip SERVER_XYZ \
  --ssh-user SSH_USER --ssh-key "$HOME/.ssh/velociraptor-test" \
  --api-user API_USER \
  --remote-api-config /etc/velociraptor/api_access_API_USER.yaml \
  --remote-client-config /etc/velociraptor/client.config.yaml

vraptor config fetch-api \
  --settings-file "$HOME/.config/vraptor/setup-tests.toml" \
  --server-profile xyz --server-ip SERVER_XYZ \
  --output-path "$HOME/.config/velociraptor/xyz_api_client.yaml"

vraptor config fetch-client \
  --settings-file "$HOME/.config/vraptor/setup-tests.toml" \
  --server-profile xyz --server-ip SERVER_XYZ \
  --output-path "$HOME/.config/velociraptor/xyz_client.config.yaml"
```

The example `/etc/velociraptor` paths are not universal. Readable files are copied
with SCP. Root accounts can generate the requested YAML as the current user;
`run_as` optionally selects another datastore owner. Non-root fetches use sudo:
passwordless access completes automatically, while password-required access
prompts directly in an SSH terminal and then resumes retrieval. Only the requested
YAML is handed off with mode `0600`; neither passwords nor YAML are captured in
setup output. If sudo is unavailable or authentication needs a terminal that is
not present, the helper prints manual steps and waits for Continue. Noninteractive
agents must display those fallback steps and wait. Missing-file generation still
requires explicit provisioning flags. These fetch-only commands request neither
generation nor deletion; `--force` replaces only the local cache.

For service-account generation, temporary YAMLs, moves into `/etc/velociraptor/`,
and protected retrieval/reference copies, follow the
[manual command sequence](../skills/velociraptor-live-api-client/references/service-account-config.md).
Server-reference copies are optional and require an explicit request.
The API-account/YAML sequence is shared by live remote and remote dead-disk;
execute the endpoint-YAML steps only for remote dead-disk. Keep installed originals
service-owned by configuring a separate operator-readable retrieval path.

### Both options: save the shared XYZ connection

```sh
vtest setup configure --server-profile xyz \
  --server-ip SERVER_XYZ \
  --api-client "$HOME/.config/velociraptor/xyz_api_client.yaml" \
  --client-config "$HOME/.config/velociraptor/xyz_client.config.yaml" \
  --api-role-profile provisioning-admin

vtest setup show --server-profile xyz
```

Use `investigation` instead of `provisioning-admin` for an API identity with
`investigator,api` roles. The `provisioning-admin` profile expects
`administrator,api` access. Match the administrator-provided identity; do not
change its privileges merely to match an example. One named connection and one
set of native YAML files serve both remote tests.

## 5. Use case: local evidence mapped to server XYZ

This test enrolls a new mapped client on the remote test server.

```sh
vtest setup start --mode remote-deaddisk \
  --id test-remote01 --server-profile xyz \
  --evidence-path /evidence/test.E01 --hostname test-remote-disk

vtest setup status --id test-remote01
vtest setup stop --id test-remote01
vtest setup status --id test-remote01
vtest setup resume --id test-remote01
vtest setup status --id test-remote01
# Run section 7 for this mapping's exact client ID before the final stop.
vtest setup stop --id test-remote01
```

Pass criteria:

- The remote server sees the expected mapped hostname and recent `LastSeen`.
- Resume preserves the client ID recorded after start.
- Mapping state is under
  `~/cases/setup-tests/test-remote01/runtime/velociraptor/mapping/`.
- No local server is created. Shared native configuration files remain in their
  original location and can be reused by the next investigation.
- Stop ends the owned local mapped client and supervisor. It leaves the remote
  server running and retains the enrolled client record.

## 6. Use case: live endpoint on server XYZ

List a bounded set of recently online endpoints and select an existing live
endpoint, rather than the mapped test client from the previous section:

```sh
vraptor clients \
  --settings-file "$HOME/.config/vraptor/setup-tests.toml" \
  --server-profile xyz --online-within-minutes 5 --limit 10
```

Replace `C.REPLACE_WITH_SELECTED_ID` with the chosen client ID:

```sh
vtest setup start --mode live-remote \
  --id test-live01 --server-profile xyz \
  --client-id C.REPLACE_WITH_SELECTED_ID

vtest setup status --id test-live01
vtest setup resume --id test-live01
```

Pass criteria:

- The online inventory returns the chosen endpoint; start/resume verifies that
  exact target and the intended server/org identity.
- Readiness is saved under `~/cases/setup-tests/test-live01/engagement.json`.
- No local server or mapping runtime is created. `status` reports no owned
  mapping or local server, so there is nothing for `setup stop` to stop.

`--environment-only-ok` may test API access and visibility when no target has
been chosen, but does not pass the exact live-endpoint test above. `status` has
`api_checked=false`; use `resume` for fresh API readiness checks. Neither endpoint
visibility nor a saved ready status alone proves current endpoint connectivity.
For the selected Windows test endpoint, run the collection checks in section 7.

## 7. Prefetch and evidence-of-execution collection

After readiness succeeds, run both checks for each test client: local mapped,
remote mapped, and the explicitly selected Windows live endpoint. For the
two-image variant, repeat for each of the four mapping/client IDs. Keep mappings
and their server running until their checks finish, then perform the final stops.
Use the exact client ID returned by setup and its investigation ID; collection
commands select the client, not `--mapping-id`. If already stopped, resume that
investigation/mapping first.
Use the exact API-client path recorded by setup (the case-owned YAML for the
local server, or the supplied remote YAML). The explicit API path and case root
keep these collection commands bound to the test deployment.

First ensure or reuse the standalone Prefetch artifact:

```sh
vraptor collect ensure \
  --api-client /path/TO_SAVED_API_CLIENT.yaml \
  --case-root "$HOME/cases/setup-tests" \
  --id INVESTIGATION_ID --client-id C.REPLACE_WITH_SELECTED_ID \
  --artifact Windows.Forensics.Prefetch \
  --flow-timeout-seconds 600 --poll-timeout-seconds 900 \
  --no-export
```

Then ensure or reuse the named evidence-of-execution collection:

```sh
vraptor collect ensure \
  --api-client /path/TO_SAVED_API_CLIENT.yaml \
  --case-root "$HOME/cases/setup-tests" \
  --id INVESTIGATION_ID --client-id C.REPLACE_WITH_SELECTED_ID \
  --collection-type execution \
  --flow-timeout-seconds 600 --poll-timeout-seconds 900 \
  --no-export
```

The `execution` type includes Amcache, BAM, RecentFileCache, Windows Timeline,
SRUM, AppCompatPCA and Prefetch; see the
[canonical membership](../skills/velociraptor-collection/references/collection-types.md#execution).
It is distinct from the capability-aware `execution-history` group. Both commands
use identical Prefetch parameters and timeout so an exact successful or in-flight
Prefetch flow can be reused. Record that reuse rather than forcing a duplicate.
`ensure` performs artifact preflight and polls by default; these commands do not
invoke analyst agents or export results. Do not add `--force-run`, `collect analyze`,
file uploads, broad hunts or unrelated collection types to this acceptance test.

Record both request IDs, every artifact's exact flow ID, terminal state, row count,
and any errors or missing-artifact preflight failures. Verify results belong to
the intended client/image. Successful collection with zero rows is an empty result,
not proof that the source was present or that no programs executed. Keep startup,
collection completion and evidence availability separate in the result.

If polling times out, inspect the saved request instead of submitting another one:

```sh
vraptor collect poll \
  --api-client /path/TO_SAVED_API_CLIENT.yaml \
  --case-root "$HOME/cases/setup-tests" \
  --id INVESTIGATION_ID --client-id C.REPLACE_WITH_SELECTED_ID \
  --request-id SAVED_REQUEST_ID --timeout-seconds 900 --no-export
```

Do not poll a preflight failure that has no flow IDs, or silently drop unavailable
members of `execution`. Report partial/blocked coverage and continue independent
clients. Retain results server-side and request/coverage metadata in the case.

## 8. Record results and retain recovery state

| Test | Result | Client ID / server identity | Notes |
|---|---|---|---|
| Analyst-agent configuration and offline doctor | Not run | Not applicable | Record file, profile, provider, transport and model |
| Local start | Not run | | |
| Local stop/resume, identity retained | Not run | | |
| Remote mapped start | Not run | | |
| Remote mapped stop/resume, identity retained | Not run | | |
| Remote live target readiness | Not run | | |
| Remote live resume | Not run | | |
| Prefetch, per selected client | Not run | | Request/flow ID, completion, rows/errors |
| Execution collection, per selected client | Not run | | Per-artifact flows, Prefetch reuse, coverage |
| Local resources stopped after tests | Not run | | |

Record the date, binary version, investigation IDs and any failure messages in
your local copy. Do not paste credential YAML or secret environment values.
Use `needs_attention` or a failed check as a failure, not a reason to silently
change server identity or recreate mapped-client writeback.

The stop commands retain evidence, case folders, native configs and writeback.
Leave these in place for diagnosis and future resume tests. The remote mapped
client record also remains; deleting it is a separate server-side action.
Normal workstation settings and analyst configuration are not reset by this
guide. Dedicated test settings can be retained for another run.

## Two images per investigation

For the four dead-disk combinations, use two investigations, not four:
`test-local` for both local-server images and `test-remote` for both remote-server
images. Keep the same case root and connection configuration throughout.

```sh
vtest setup start --mode local-deaddisk --id test-local --mapping-id wkstn01 \
  --evidence-path /evidence/wkstn01.E01 --hostname test-local-wkstn01
vtest setup start --mode local-deaddisk --id test-local --mapping-id wkstn05 \
  --evidence-path /evidence/wkstn05.E01 --hostname test-local-wkstn05
vtest setup start --mode remote-deaddisk --id test-remote --server-profile xyz \
  --mapping-id wkstn01 --evidence-path /evidence/wkstn01.E01 --hostname test-remote-wkstn01
vtest setup start --mode remote-deaddisk --id test-remote --server-profile xyz \
  --mapping-id wkstn05 --evidence-path /evidence/wkstn05.E01 --hostname test-remote-wkstn05
```

The local case owns one server under `runtime/velociraptor/server/`. Each case
has separate `runtime/velociraptor/mappings/wkstn01/` and `wkstn05/` directories,
per-host `systems/` records, and one `engagement.json` containing both saved
mapping recipes/readiness results. Explicit runtime-root overrides retain their
configured layout. Do not move or delete previous per-image test cases.

For each mapping, run `setup status` and `setup resume` with its investigation ID
and `--mapping-id`. Verify distinct client IDs on each server, persistent
writeback across resume and both mappings visible together. Run the Prefetch and
execution collection checks from section 7 for each exact client ID before
stopping the mappings. These replace the previous exact-path filesystem probe.
Record four result rows even though there are only two investigation folders,
with separate startup/resume, Prefetch and execution-collection outcomes.

Stop the local mappings separately, then their shared server:

```sh
vtest setup stop --id test-local --mapping-id wkstn01
vtest setup stop --id test-local --mapping-id wkstn05 --stop-server
vtest setup stop --id test-remote --mapping-id wkstn01
vtest setup stop --id test-remote --mapping-id wkstn05
```

Offline regression checks from the `ai_skills` checkout:

```sh
.venv/bin/python -m pytest tests/test_remote_config_privileges.py \
  tests/test_remote_config_sudo.py \
  tests/test_velociraptor_live_api_client_sh.py tests/test_vraptor_setup.py \
  tests/test_engagement_state.py
```

The privilege tests execute root commands through fake SSH tools, test quoted
paths, automatic sudo preparation, terminal-only authentication, and manual fallback.
They also verify credential preservation and that failed generation is not retried.
They do not prove that a live deployment permits API provisioning.

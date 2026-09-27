---
name: velociraptor-engagement-setup
description: Start or resume Velociraptor investigations using a local server and mapped client, a remote server and mapped client, or remote live endpoints. Configure reusable settings, verify readiness, and inspect or stop owned local resources; excludes case databases and task management.
---

# Velociraptor Engagement Setup

For first installation, follow [Install and set up vraptor](../../docs/vraptor-installation.md):
install the package and selected AI extras, use the combined operational/AI
configuration wizard, verify settings, then select an investigation mode.
Package installation and configuration alone do not establish server readiness.

**Required server prerequisite:** follow the shared
[DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md)
for every new local server and connected live/remote server. If the live catalog
contains no `DetectRaptor.` artifacts, run `Server.Import.Extras` with the
DetectRaptor CSV row and verify installation before proceeding. Reuse a successful
session check; a failed import blocks the workflow. Explicit read-only/no-import
instructions and offline-only work retain their scope.

Prepare a durable investigation workspace, then prove Velociraptor readiness.
`dfir` and `vraptor` use the same CLI. Initialization is standalone and does not
contact a server or collect evidence.

Read the [operation authorization policy](../../docs/reference/velociraptor-operation-authorization.md)
and [engagement context contract](../../docs/reference/velociraptor-engagement-context.md)
when selecting a connection or recovering readiness. Normal authorized readiness
and configuration work needs no additional approval prompt.

## Inputs and workspace

Use the investigation ID, an optional investigations parent (`--case-root`,
otherwise saved settings, legacy `CASE_ROOT`, or `~/cases`), and the selected server profile. Ask for a
missing target or deployment rather than guessing. Preserve the ID's spelling.

Initialize once at the beginning of work:

```bash
dfir setup init --id ir1234
# Or select a different investigations parent:
dfir setup init --id ir1234 --case-root /investigations
```

An explicit `--investigation-dir /investigations/ir1234` is also supported; its
final component must match the ID. The result returns the effective parent to
use in later commands. Initialization creates only the folder and a minimal
`AGENTS.md` when missing. It preserves existing guidance, reports and evidence,
rejects a conflicting readiness identity, and lists up to 500 existing report,
request and checkpoint paths without reading their contents. A truncated listing
is not complete coverage. It does not validate the old readiness against a server.

Work from that investigation folder for as long as needed. Repeating `setup init`
is safe. Read the relevant existing reports and accepted checkpoints before
assigning new work. No database, task register, workbook or empty analysis tree
is created.

## Environment and analyst configuration

Use bare `vraptor setup configure` in a terminal for the complete operational
wizard and optional AI handoff. No repository `.env` is required: save reusable
preferences in TOML and reference existing credential files or process credentials.
Environment/dotenv overrides remain supported and can mask wizard changes;
inspect effective sources before changing a saved value again.

Remote profiles inherit `api_user` and `api_role_profile` from
`[connection_defaults]`, including previously unseen profile names. Precedence is
CLI > environment/dotenv > named connection > connection defaults > application
defaults (`vraptor`, `provisioning-admin`). Interactive configure offers
`Remote API username [vraptor]:` on a fresh setup; Enter saves it. Explicit saved
identities remain authoritative. `setup show --server-profile NAME` reports values
and sources. Without an explicit analyst path, the default is
`~/.config/vraptor/analyst-agents.toml` (XDG-aware); the legacy `ai_skills` file
migrates only when the destination is absent, preserving contents and permissions.
`[connection_defaults]` also supports shared SSH user/key, remote configuration
paths, binary and service account. Named profiles may select `org_id`.
`[api].grpc_max_message_bytes` and `[mapping].startup_timeout_seconds` /
`ready_timeout_seconds` expose validated transport and startup/readiness limits.
Leave unused environment overrides empty so TOML remains effective.

Interactive configure offers an **AI analyst configuration** section with
`Configure AI analyst settings [Y/n]:`. Enter or Yes saves operational settings,
then opens the existing `vraptor ai setup` wizard using that settings file. No
skips it. New setups suggest server name `live` and AI provider `openai`; saved
selections remain authoritative. Enter `-` at the server-name prompt for shared
defaults/local-only configuration. Preview never launches AI setup; a failed wizard leaves operational settings
saved and reports a retry command. AI wizard output goes to stderr.

The AI wizard groups **Analysis token budgets** separately and saves
`max_input_tokens` / `max_output_tokens` in the selected analyst profile. New
OpenAI/Azure profiles suggest 272000 / 128000, deriving 400000 context and keeping
the shared 200000 evidence ceiling. Known models default to maximum available input
and their output recommendation, including reruns;
smaller model/deployment limits still apply. Inspect the resolved values and
sources with `vraptor ai config`. Setup displays the resolved model's published
context, standard-price input ceiling, output maximum and reference defaults.
`--no-auto-token-budgets` retains saved budgets within the allowed range, with a
note if they differ from the reference.
Oversized saved budgets default to the applicable maximum, with a reduction note.
Setup selects output first and shows the exact remaining input maximum. `max` or
`auto` at a prompt fills that field's available capacity. Oversized interactive
entries are adjusted with an explanation; invalid CLI flags fail before writing.
The default `--auto-token-budgets` replaces saved budgets with model output recommendations
and maximum remaining standard-price input. JSON reports include maxima and
adjustments; runtime environment precedence is unchanged.
Input has a 100000-token minimum when the available maximum is at least 100000;
smaller available contexts retain a lower minimum. Prompt brackets show the
calculated default, e.g. `Maximum input tokens [872000] (Enter to keep):`.
Haiku 4.5 recommends 32000 output (model maximum 64000) and 168000 input;
Sonnet 5 recommends 128000 output and 872000 input. The fixed 25% context reduction
is removed from setup and runtime; evidence reserves remain inside input. Known
models record their context on new and existing profiles, preserving explicit
smaller deployment caps. Unknown IDs/custom deployments/short harness
aliases show unverified limits and use saved/application fallbacks. Do not treat
these offline API references as account discovery or managed-plan price guarantees.
See
[`docs/model-execution.md`](../../docs/model-execution.md#shared-token-budgets)
for reserve calculation, environment precedence and legacy compatibility.

When AI setup is skipped, or after successful start/resume, setup prints
`To configure AI, run: vraptor ai setup`, retaining any explicit settings-file
selector. `agent` remains an alias for `ai`. The note goes to stderr so JSON
stdout remains parseable; the wizard is not started automatically.

Configure reusable operational defaults independently of analyst settings:

Inspect operational settings with `vraptor config` and analyst settings with
`vraptor ai config`. Both accept `--view effective` (default) or `--view defaults`
and print JSON; defaults inspection ignores local files and environment overrides.
`vraptor config --server NAME` reports the same effective values and sources as
`setup show`. Use `setup configure` and `ai setup` to configure each subsystem.

```bash
dfir setup configure
# Targeted updates skip the interactive wizard and AI handoff:
dfir setup configure --case-root ~/cases
dfir setup configure --server-profile lab --api-client /configs/lab_api_client.yaml
dfir setup show --server-profile lab
dfir setup migrate --server-profile lab          # Preview legacy env migration
dfir setup migrate --server-profile lab --write  # Apply nonconflicting settings
```

The default file is `$XDG_CONFIG_HOME/vraptor/config.toml`, otherwise
`~/.config/vraptor/config.toml`; `--settings-file` selects another file.
`workstation.binary` defaults to `~/velociraptor/velociraptor` and is shared by
installation and execution. Use `setup configure --velociraptor-bin PATH` before
installing elsewhere or after moving an existing binary.
With no setting flags or template, `configure` runs a terminal wizard grouped
under spaced headings: workstation, remote connection, remote SSH access, local
server, mapped evidence, advanced paths/API transport, and credentials. Optional
sections can be skipped; Enter preserves saved fields. `--server-profile NAME`
edits that named connection; a blank name edits shared connection defaults.
The wizard writes settings only and does not connect, fetch credentials, provision
accounts or start resources. It supports `--preview` and `--template`, and keeps
one backup when replacing an existing file. TOML holds
workstation paths, optional named connections, a credential-env-file reference
and advanced lifecycle defaults. It references native API YAML and SSH-key paths;
never copy credential contents into TOML. `show` reports effective non-secret
values and their sources. Migration preserves conflicting TOML values and leaves
the original dotenv files and their override behavior intact.

Optionally select a shared analyst TOML with `setup configure
--analyst-config-file PATH`, stored as `[analyst].config_file`. `setup show`
reports the selected analyst path, existence and an `inspect_command` for
`vraptor ai config`, without dumping analyst settings or loading a provider.
Use the reported command to retain the same operational settings file and
credential source. Analyst `--config-file` and the existing
`AI_SKILLS_ANALYST_AGENT_CONFIG_FILE` environment/dotenv override take precedence.

Operational precedence is explicit arguments, process environment, explicitly
selected credential dotenv, repository `.env`, shared `~/.codex/.env`, named
connection, connection defaults, then application defaults. Other TOML sections
also override application defaults. Settings resolve once per operation. The selected credential dotenv
also feeds analyst operations; analyst profiles remain in `analyst-agents.toml`.
Infrastructure setup does not require AI credentials.
Writable investigation, runtime and fetched-credential paths must stay outside
mounted evidence and must not overwrite an evidence image; setup rejects these
overlaps before creating the affected outputs.

When setup includes the analyst agent, inspect the selected profile with
`dfir ai config`, run `dfir ai setup` interactively to review/configure it,
then rerun `dfir ai config` and `dfir ai doctor`. Carry the same operational
`--settings-file`, analyst `--config-file` and `--execution-profile` selectors
where explicitly selected. Reuse the intended provider/model and preserve shared
analysis budgets. Configure this shared profile once across investigations;
operational export/deploy transfers its file reference, not analyst settings or
credentials. Report the effective profile and offline diagnostic status separately
from server readiness. See the [setup test guide](../../docs/velociraptor-setup-testing.md#configure-the-analyst-agent-once)
for the command sequence and limits of offline checks.

Use `vraptor ai setup --from-harness codex` to reuse Codex settings, or
`--from-harness claude_code` for Claude-managed login. Claude settings discovery
prefers an explicit/saved file, then
`~/Library/Application Support/Claude/settings.json`, then
`~/.claude/settings.json`; enter a model if neither automatic file exists.
Use `--provider anthropic --model MODEL_ID` for a separate Anthropic API-key
profile. The wizard offers advanced API settings and optional native Claude
login; it never imports Desktop `config.json` tokens. `vraptor ai setup --help`
lists grouped options and offline OpenAI/Claude model examples. The model prompt
shows provider-specific suggestions while accepting other supported IDs and
preserving saved defaults. These examples do not establish account access;
the reasoning-effort prompt likewise lists model-specific choices, including
`xhigh` where supported. Enter preserves/inherits effort; recognized Claude models
with effort support default to `medium` only if no explicit, saved, shared or native
effort exists. Haiku and unknown models receive no automatic effort setting.
Azure requires the deployment name. A native login check is not an inference or server check.

`setup init` also checks repository `.env` and shared `~/.codex/.env` sources,
reporting their paths, loading status and accepted key counts without values.
It reuses the offline `dfir ai doctor` checks for the selected analyst config
file/profile, provider, transport, model, credential presence, dependencies and
analysis limits. Explicit process values retain precedence over repository and
shared dotenv defaults; analyst TOML/harness selection follows the normal resolver.
An investigation-local `.env` is not a configuration source.

Save/deploy/reset reusable operational settings with:

```bash
dfir setup export --output ~/.config/vraptor/presets/current.toml
dfir setup deploy --from ~/.config/vraptor/presets/current.toml
dfir setup deploy --from ~/.config/vraptor/presets/current.toml --apply
dfir setup reset
dfir setup reset --apply
```

Export captures effective settings and all named connections without copying
secrets; local home paths become `~`. An environment-only connection needs
`--server-profile NAME`. Deploy and reset preview unless `--apply` is supplied;
an existing export is never overwritten. Reset backs up changed files and clears
only operational preferences/overrides while preserving credential and analyst
references, investigations and tools. Deploy merges snapshot values into the
selected settings file and preserves unrelated entries. Follow user-authorized
deployment/reset scope and inspect `setup show` afterward; see
[configuration recovery](../../CONFIG.md#export-and-deploy-current-settings).

Read `configuration_checks.status` and `configuration_checks.analyst_agent.issues`.
Missing dotenv files are allowed when configuration comes from other sources.
Invalid configuration, missing dependencies/credentials and disabled analysts are
reported as needing attention. They do not prevent folder creation or reuse:
exit 0 means initialization succeeded, even when configuration needs fixing.
Use `dfir ai doctor` for diagnostics and `dfir ai setup` to configure the
analyst, then rerun initialization or the doctor before analyst execution.

Checks do not modify dotenv, analyst configuration or existing investigation
guidance. Authentication and inference remain untested; startup makes no server
or model requests. A successful offline check does not prove live access.

## Concurrent work and switching projects

Each command selects its investigation with `--id` and, for a nondefault parent,
`--case-root`. There is no global current investigation and changing directory
does not change another process's target. Keep those selectors explicit when
switching projects or running several workstreams. Bind each stream to an exact
host, hunt or request; avoid duplicate analysis of the same saved operation.

Use the selected investigation as the working folder. Create or navigate Codex
projects/tasks only when requested; folder initialization itself does neither.

## Velociraptor readiness

`setup start` prepares the folder and readiness together. `setup init` remains
the offline folder-only operation. Reuse valid saved readiness
while its identity and operational checks pass; do not refresh on a timer.
At session start inspect saved readiness and effective analyst configuration. Reuse
successful initialization/doctor checks already performed in the session; repeat
setup or doctor only after relevant changes or failures, not for every collection.
The CLI still validates case/server/credential/target bindings per operation.
Use investigation `AGENTS.md` to retain analysis intent, reuse accepted checkpoints,
and apply the appropriate incident, hunt or host reporting thresholds.
After a connection failure, repair readiness and resume saved operations rather
than blindly resubmitting a collection.

### Live remote

```bash
dfir setup start --mode live-remote --id ir1234 --server-profile lab \
  --api-client /configs/lab_api_client.yaml --hostname host01
```

Use `--host-label` and optional `--exclude-host-label` for fleet scope instead of
a hostname. Use `--environment-only-ok` only when no specific target is available;
it proves API reachability and at least one visible client, not intended scope.

Existing API YAML connects directly. For remote credential acquisition, supply
`--server-ip` and explicitly select `--fetch-config`. Generation of missing
API credentials additionally requires `--provision-api`. Endpoint YAML and
`--provision-client` apply to remote dead-disk setup below.
`--force` refreshes the local copy when fetching is selected;
`--regenerate-remote-api` explicitly replaces the selected remote API YAML.
Never handle SSH passphrases in chat. Setup verifies certificate lifetime,
private-key presence, ownership,
private file mode, a real API query, server-side roles/effective permissions, and
hostname or label visibility.

`--api-role-profile provisioning-admin` is the current default and requires
`administrator,api` plus effective administration capability. An explicitly
selected `investigation` profile requires `investigator,api`, rejects an
administrator credential, and verifies query, result-read, collection and hunt
permissions. Preserve the selected credential profile during recovery.

### Local server and mapped client

Both `local-deaddisk` and `remote-deaddisk` accept `--evidence-type`:
`auto` (default), `windows-disk`, `windows-directory`, `velociraptor-export`, or
`velociraptor-kapefiles-zip`.
Auto detects extracted exports by `uploads.json`; it rejects ambiguous directories.
See [extracted collection exports](../velociraptor-mapped-client/SKILL.md#extracted-velociraptor-kapefiles-collection)
for mapping behavior and coverage limits.

```bash
dfir setup start --mode local-deaddisk --id ir1234 \
  --evidence-path /evidence/disk.E01
```

Setup initializes or reuses a managed loopback-only local server, then starts or
reuses its mapped client. Native server configuration, datastore and credentials
persist under `<case-root>/<id>/runtime/velociraptor/server/`; the default local
profile is `local`. For an existing shared server, select a named connection or supply its
`--api-client` and matching `--client-config`; setup does not take ownership of
that server. The legacy `setup local-deaddisk --client-id ...` command remains a
verification-only interface for an existing mapping.

For a newly generated local server, an unset `VELO_LOCAL_API_PASSWORD` retains
the native test GUI default: `admin` / `password`. If it is set, setup creates
or updates the selected `VELO_LOCAL_API_USER` with that explicit password.
Local GUI access is loopback-only and intended for testing, not production use.

### Remote dead-disk client

Use the same API-account/YAML provisioning and retrieval procedure as live
remote, including role selection and automatic root/sudo preparation. Passwords
are entered only in the operator's terminal; manual handoff is the fallback.
The additional credential is the matching endpoint YAML, needed to enroll the mapped client.
See [shared generation and manual fallback](../velociraptor-live-api-client/references/service-account-config.md).

```bash
dfir setup start --mode remote-deaddisk --id ir1234 --server-profile lab \
  --api-client /configs/lab_api_client.yaml \
  --client-config /configs/lab_client.config.yaml \
  --evidence-path /evidence/disk.E01 --hostname evidence-host
```

Both offline modes share the `velociraptor-mapped-client` lifecycle and verify
the evidence remap, enrolled identity, API-visible hostname, `LastSeen`, client
and supervisor processes, and final online health. Inspect existing mapping
state before invoking creation; do not recreate an active mapping merely to
resume analysis. Mutable mapping state defaults to
`<case-root>/<id>/runtime/velociraptor/mapping/`; `--workspace` selects an explicit
mapping workspace. Existing cases keep saved paths; an explicitly configured
`runtime_root` retains its external layout. Native API/client YAML may remain in
a common directory referenced by several investigations. Remote live mode
creates no local server or mapping runtime. See the mapped-client skill for
supported evidence and the lower-level mapping interface.

### Several mapped hosts in one investigation

Use one investigation ID per use case/server and a stable `--mapping-id` per
image. For example, put both local images in `test-local` and both remote images
in `test-remote`, under the configured case root:

```bash
dfir setup start --mode local-deaddisk --id test-local --mapping-id wkstn01 \
  --evidence-path /evidence/wkstn01.E01 --hostname test-local-wkstn01
dfir setup start --mode local-deaddisk --id test-local --mapping-id wkstn05 \
  --evidence-path /evidence/wkstn05.E01 --hostname test-local-wkstn05
dfir setup resume --id test-local --mapping-id wkstn01
dfir setup status --id test-local --mapping-id wkstn05
```

The case shares one server/organization/API identity and, for managed local
setup, one server runtime. Each host retains its own evidence binding, remap,
writeback and readiness in `engagement.json`'s `mappings` records. Default runtime
is `runtime/velociraptor/mappings/<mapping-id>/`; reports remain in
`systems/<hostname>/`. Select `--mapping-id` for status/resume/stop when more than
one mapping exists. Stop every mapping before stopping the shared local server.
Existing single-mapping investigations keep their saved paths; when adding a
named mapping, the original becomes `default`. Do not relocate existing cases.
Case readiness is conservative if any mapping is stopped or failed; a command
selecting an exact host validates that host's own saved readiness independently.

### Resume, inspect and stop

```bash
dfir setup status --id ir1234
dfir setup resume --id ir1234
dfir setup stop --id ir1234
dfir setup stop --id ir1234 --stop-server
```

`status` inspects saved state and local process ownership; its `api_checked=false`
does not establish current server reachability. `resume` reuses the saved mode,
connection, evidence and client identity and reruns readiness. Older readiness
without a saved setup recipe remains usable; adopt it with explicit `setup start`
inputs before using `resume`.
Credential renewal is allowed for the same server, organization, CA, API username
and endpoint enrollment nonce. Hash-only legacy mapping sessions must first
resume with their original credentials to establish a stable binding; missing or
already changed originals block automatic upgrade. Never reset writeback to recover.

`stop` stops only the investigation's owned mapped client and supervisor. Add
`--stop-server` to stop an owned local server only when no other active mapping
needs it. Remote live mode has no managed local mapping to stop. Never terminate
unrelated port listeners or adopt an existing unmanaged datastore. Conflicting
server/evidence bindings fail while preserving prior identities and evidence.

## Outputs and failure handling

Readiness writes `<case-root>/<id>/engagement.json` with server/org identity,
credential fingerprint/security, verification time, scope and matched-client
count. Mapping modes also retain compact `systems/<host>/system.json` identity.
Progress goes to `logs/velociraptor-progress.log`; credentials and raw evidence
must not appear in startup output. Leaf transport manifests are temporary.

Report the investigation folder, exact mode/server/target, readiness path,
existing analysis relevant to the request, and any failed check. A failure blocks
live work; return the bounded recovery action instead of creating a case task.
Folder initialization succeeding is not proof of API readiness, and visibility
is not proof an endpoint is online or that evidence has been collected.

Then route the authorized request:

- Cross-host scope: `velociraptor-hunting`.
- One-host review: `velociraptor-host-analysis`.
- Explicit acquisition: `velociraptor-collection` (`collect analyze` may collect).
- Existing flow/request/hunt: `dfir analyze`, which cannot collect or retry clients.

See the [CLI contract](../../docs/contracts/cli.md).

## Required DetectRaptor installation

The [shared bootstrap procedure](../../docs/reference/detectraptor-bootstrap.md)
is mandatory for local and remote server setup, including reused connections.
The [example Details CSV](references/import-extras.csv) includes DetectRaptor;
preserve the connected server's current entries when preparing the import.

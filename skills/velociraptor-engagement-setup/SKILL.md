---
name: velociraptor-engagement-setup
description: Set up and map local, remote and live Velociraptor engagements, including local-server and remote dead-disk mapping. Initialize or resume an investigation, configure reusable operational and AI analyst settings, verify readiness, and inspect or stop owned local resources. Not for collection, hunting, analysis or direct VQL; use velociraptor-collection, velociraptor-hunting, velociraptor-host-analysis or velociraptor-live-api-client.
---

# Velociraptor Engagement Setup


For first installation, follow [Install and set up vraptor](../../docs/vraptor-installation.md):
install the package and selected AI extras, use the combined operational/AI
configuration wizard, verify settings, then select an investigation mode.
Package installation and configuration alone do not establish server readiness.

**Server prerequisite:** complete the [DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md) for each new local or connected live/remote server before server work; a failed import blocks the workflow.
The bootstrap's [example Details CSV](references/import-extras.csv) includes the
DetectRaptor row.

Prepare a durable investigation workspace, then prove Velociraptor readiness.
Use the shared `vraptor` CLI. Initialization is standalone and does not
contact a server or collect evidence.

Read the [operation authorization policy](../../docs/reference/velociraptor-operation-authorization.md)
and [engagement context contract](../../docs/reference/velociraptor-engagement-context.md)
before selecting a connection or recovering readiness. Normal authorized readiness
and configuration work needs no additional approval prompt.

## Inputs and workspace

Use the investigation ID, an optional investigations parent (`--case-root`,
otherwise saved settings, legacy `CASE_ROOT`, or `~/cases`), and the selected server profile.
Ask for a missing deployment rather than guessing; request a target only when
the operation requires one. Preserve the ID's spelling.

Initialize once at the beginning of work:

```bash
vraptor setup init --id ir1234
# Or select a different investigations parent:
vraptor setup init --id ir1234 --case-root /investigations
```

An explicit `--investigation-dir /investigations/ir1234` is also supported; its
final component must match the ID. The result returns the effective parent to
use in later commands. Initialization creates only the folder and a minimal
`AGENTS.md` when missing. It preserves existing guidance, reports and evidence,
rejects a conflicting readiness identity, and lists up to 500 existing report,
request and checkpoint paths without reading their contents. A truncated listing
is not complete coverage. It does not validate the old readiness against a server.
It also runs offline dotenv and analyst checks; read `configuration_checks` as
described in [configuration checks](references/configuration.md#configuration-checks-during-setup-init).
Exit 0 means the folder was initialized even when configuration needs attention,
and a passing offline check does not prove live access.

New guidance uses the packaged `resources/templates/investigation-agents.md`
template in the `vraptor` Python package. Edit the template for future defaults;
edit an investigation's own `AGENTS.md` for case-specific guidance. Repeating
initialization never overwrites existing guidance.

Work from that investigation folder for as long as needed. Repeating `setup init`
is safe. Read the relevant existing reports and accepted checkpoints before
assigning new work. No database, task register, workbook or empty analysis tree
is created.

## Environment and analyst configuration

Run bare `vraptor setup configure` in a terminal for the operational wizard and
its optional AI handoff; setting flags such as `--case-root` make targeted
updates without the wizard. Configuration writes settings only: it does not
connect, fetch credentials, provision accounts or start resources. Inspect
effective values and their sources with `vraptor setup show --server-profile NAME`
or `vraptor config`, and analyst settings with `vraptor ai config`;
environment/dotenv overrides can mask saved TOML. Configure `api_user` or pass
`--api-user` before fetching or provisioning API credentials. Infrastructure
setup does not require AI credentials. Writable investigation, runtime and
fetched-credential paths must stay outside mounted evidence; setup rejects
overlaps.

Read [setup configuration](references/configuration.md) before changing saved
settings, precedence or credential sources, or before export, deploy or reset.
When setup includes the analyst agent, follow
[AI analyst configuration](references/configuration.md#ai-analyst-configuration)
and report the effective profile and offline `vraptor ai doctor` status
separately from server readiness.

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
vraptor setup start --mode live-remote --id ir1234 --server-profile lab \
  --api-client /configs/lab_api_client.yaml
```

Without target selectors, live setup verifies server readiness for maintenance
and hunt review; do not ask for a hostname unless the work requires one. An empty
client inventory is recorded and does not block server readiness. API query or
authorization failures still block readiness.

Optionally add `--hostname`, `--client-id`, or `--host-label` with optional
`--exclude-host-label` to require target visibility. These checks do not restrict
later site-wide work; each operation selects its authorized host or hunt scope.
Resume retains saved target checks. An explicit selection replaces the previous
selection; use the compatible `--environment-only-ok` flag to clear saved target
checks and return to server-only verification. Dead-disk bindings are unchanged.

For a setup request with an explicitly configured API user (CLI,
environment/dotenv or saved settings), pass `--provision-api` without a separate
approval prompt, even with cached YAML. Cached YAML or an application fallback
alone does not count; honor no-provision, read-only and fetch-only requests; local
dead-disk setup never provisions. Full rule:
[API-user provisioning](../../docs/reference/velociraptor-operation-authorization.md#api-user-provisioning).

Existing API YAML can otherwise connect directly. For remote credential acquisition, supply
`--server-ip` and explicitly select `--fetch-config`. `--provision-api` starts account setup before generating missing API credentials,
including when operational YAML is cached. Generic installations prompt the
operator to create/verify the account in the running server; continue or rerun
with `--api-account-ready` only after completing that manual step. If the kept
cached YAML already passes the selected user's role checks, setup skips the manual step
and says so; add `--api-account-setup` only when the operator asks to run it. They have no
built-in administrator API account. An explicitly configured remote bootstrap
connection may automate this step; its identity is never used operationally.
See the [shared account procedure](../velociraptor-live-api-client/references/service-account-config.md). Endpoint YAML and
`--provision-client` apply to remote dead-disk setup below.
`--force` refreshes the local copy when fetching is selected;
`--regenerate-remote-api` explicitly replaces the selected remote API YAML.
Never handle SSH passphrases in chat. Setup verifies certificate lifetime,
private-key presence, ownership,
private file mode, a real API query, server-side roles/effective permissions, and
any explicitly requested hostname, client ID or label visibility.

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
vraptor setup start --mode local-deaddisk --id ir1234 \
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
vraptor setup start --mode remote-deaddisk --id ir1234 --server-profile lab \
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
vraptor setup start --mode local-deaddisk --id test-local --mapping-id wkstn01 \
  --evidence-path /evidence/wkstn01.E01 --hostname test-local-wkstn01
vraptor setup start --mode local-deaddisk --id test-local --mapping-id wkstn05 \
  --evidence-path /evidence/wkstn05.E01 --hostname test-local-wkstn05
vraptor setup resume --id test-local --mapping-id wkstn01
vraptor setup status --id test-local --mapping-id wkstn05
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
vraptor setup status --id ir1234
vraptor setup resume --id ir1234
vraptor setup stop --id ir1234
vraptor setup stop --id ir1234 --stop-server
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
- Existing flow/request/hunt: `vraptor analyze`, which cannot collect or retry clients.

See the [CLI contract](../../docs/contracts/cli.md).

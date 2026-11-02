# CLI and existing-state contract

Use `vraptor`; `dfir` remains a legacy alias of the same entry point, kept for
compatibility. The CLI exposes `query`, `clients`, `artifacts`, `collect`, `analyze`,
`summarize`, `analysis-results`, `hunt`, `export`, `reports`, `ai`, and
`tools prep`. `agent` remains a compatible alias for `ai`. The advanced
`setup`, `config`, `mapped`, `autoruns` and `logs` groups retain their existing
lower-level commands.
`setup` also provides shared configuration and three managed startup journeys.
`--server` aliases `--server-profile`; `--profile` remains an analysis profile.
`--client`, `--hunt`, `--request` and query `--file` alias the existing ID/file flags.

Replace `<SERVER REFERENCE>` in examples with a saved connection name. Multiple
servers can be configured in the same installation; each command selects one
reference. `vraptor config` lists saved names in `connections`. See the
[server-profile and engagement context](../reference/velociraptor-engagement-context.md).

```sh
vraptor ai config --view defaults
vraptor config --view defaults
vraptor config --server "<SERVER REFERENCE>"
vraptor ai setup
vraptor ai doctor
vraptor tools prep --help
vraptor query --api-client /configs/lab.yaml --file clients.vql
vraptor clients --server "<SERVER REFERENCE>" --name host01
vraptor artifacts policy show
vraptor collect --id IR1234 --server "<SERVER REFERENCE>" --client C.1234abcd --artifact Windows.Forensics.Prefetch
vraptor analyze --id IR1234 --server "<SERVER REFERENCE>" --client C.1234abcd --flow F.EXAMPLE --skip-ai --json
vraptor analyze --id IR1234 --server "<SERVER REFERENCE>" --client C.1234abcd --request-id REQUEST_ID --json
vraptor analyze --id IR1234 --server "<SERVER REFERENCE>" --hunt H.EXAMPLE --artifact Windows.Forensics.Prefetch --skip-ai --json
vraptor analyze --from /exports/hunt-snapshot.json --skip-ai --json
vraptor export --id IR1234 --server "<SERVER REFERENCE>" --client C.1234abcd --request-id REQUEST_ID
```

Configuration inspection uses `vraptor config` for operational settings and
`vraptor ai config` for analyst settings. Both output JSON and accept
`--view effective|defaults`; defaults inspection ignores local files/environment.
Operational inspection accepts `--settings-file` (also `--config-file`) and
`--server-profile`/`--server`, with the same effective values and sources as
`setup show`. Editing remains under `setup configure` and `ai setup`.
The explicit `config fetch-api` and `config fetch-client` routes are unchanged.

Examples use synthetic IDs. Operational commands require the existing readiness
record and the correct API config; they do not initialize a case automatically.
`query` executes operator-supplied VQL and retains the existing authorization
boundary. Arbitrary VQL can mutate a server.

`analyze` selects exactly one existing flow, saved request, hunt, or supported
hunt snapshot manifest. Hostname selection uses the existing unique-client
resolver. It fails on conflicting selectors, missing flows, and collection/retry
options. It does not create or ensure collections/hunts, retry clients, upload
GoldenDB, or call a business result sink. Other export formats and provenance-free
CSV are not implicitly accepted as verified snapshots. Use the source-native
validators and existing detached-evidence workflows for those formats.

A flow is adopted into the existing request schema only if needed. Matching saved
requests are reused; multiple matches require `--request-id`. A different flow
already owning the calculated request identity fails closed. Accepted artifact
checkpoints, source fingerprints and report hashes remain the resume authority.
Resume by repeating `analyze --request-id`; failed resets remain explicit.

Analysis supports run-only `--execution-profile`, `--ai-config-file`, `--model`,
`--reasoning-effort`, `--max-input-tokens TOKENS|max` and
`--max-output-tokens TOKENS|max`. `max` respects the standard-price input ceiling,
reserves output space, and honors smaller declared deployment limits. Advanced
`--model-context-tokens TOKENS|max` and `--model-max-output-tokens TOKENS|max`
can override those ceilings; `max` requires a recognized model reference.
Input has a 100000-token floor when available input capacity permits it, otherwise
a 10-token floor. Overrides outrank environment and saved settings, are validated
before API access, and never change persisted configuration. Omitting them keeps
the existing defaults. `analyze --help` lists this shared option group.

Machine output is JSON with `--json` (analysis) or the retained `--format json`.
Progress and deprecation messages go to stderr. Analysis exits 0 for completed
work, 1 for runtime/transport failure, and 2 for incomplete review, including
`--skip-ai` host or hunt preparation (`review_complete=false`; host status is `planned`). Argparse
also uses 2 for invalid arguments. Inspect the result status, not the exit code
alone. Legacy routes retain their existing exit/status behavior.

Operational commands own one logger from dispatch to termination. Nested legacy
routes reuse it; `summarize` and `ai test` use the same accounting as analysis.
Case-bound operations use case logs; other operations use
`${XDG_STATE_HOME:-~/.local/state}/vraptor/logs`. Explicit `--log-file` overrides
the destination. Help and log inspection do not write logs.
`setup init` uses the user-level destination to preserve workspace initialization
semantics; an explicit `--log-file` still overrides it.

Final structured analysis, saved-synthesis and AI-management results include
`token_usage`: command-scoped known counters, attempts/retries, provider/model
groups, usage completeness, log completeness and persistence state. A concise
command token summary also goes to stderr; stdout remains one structured result.
`--no-log-file` disables persistence while retaining in-memory accounting and
returned counters. Cached input is included in input, never added twice.

`vraptor logs usage --id CASE --case-root PATH [--json] [--ledger-only]` reports
read-only retained totals and the latest operation separately. It works without
server credentials or a usable connection configuration. Exit 2 means coverage
gaps or inconsistent records; it does not mean zero usage. See the
[logging contract](../reference/velociraptor-logging.md#usage-reporting).
Use `--global` instead of `--id` to inspect the user-level ledger. Operation
summaries include zero-call runs; incomplete operation lifecycles and unavailable
provider telemetry remain explicit coverage gaps.

Report-producing commands accept `--report-*` overrides for the shared
`[reporting]` policy. These affect presentation without changing analysis-cache
identity. `vraptor reports render --checkpoint PATH [--output-dir PATH]` renders
retained host/hunt results offline and preserves original checkpoints and hashed
artifact reports. See [reporting policy](../reference/reporting-policy.md) for
priority ordering, configuration precedence, pagination and unavailable legacy
examples. Caller-written assessments remain separate publications.

Use `vraptor setup init --id ir1234` once to create/reuse a standalone workspace.
`--case-root` selects its parent; `--investigation-dir` accepts an exact folder
ending in the ID. Existing `AGENTS.md` and investigation data are preserved.
New guidance comes from the packaged
`src/vraptor/resources/templates/investigation-agents.md` template. Edit that
Markdown file to change defaults for future investigations; initialization
substitutes `{{investigation_id}}`, `{{investigation_id_arg}}` and
`{{case_root_arg}}`. The `_arg` values retain the CLI argument quoting.
Other Markdown, braces and dollar signs are literal. Existing investigation
guidance is never refreshed from the template.
The result lists at most 500 existing analysis paths and reports truncation.
It also returns `configuration_checks` for repository/shared dotenv loading and
the offline analyst doctor, including selected config/profile, execution settings,
credential presence, dependencies and limits. Missing dotenv files are optional;
unreadable files or analyst configuration issues produce `needs_attention`.
Folder creation/reuse still succeeds with exit 0; callers must inspect the check
status before analyst execution. Checks print no credential values, modify no
configuration, and make no authentication or inference requests.
Initialization does not contact Velociraptor or establish readiness. Run a setup
mode separately before live work. Pass explicit investigation selectors when
switching projects or running concurrent streams.

## Operational setup

Run bare `vraptor setup configure` in a terminal for the complete operational
wizard and optional AI handoff. Setting flags provide targeted configuration and
skip that wizard. No repository `.env` is required; TOML stores preferences and
credential-file references. Inspect effective sources after configuration.

```sh
vraptor setup configure
# Targeted, non-interactive updates:
vraptor setup configure --case-root ~/cases
vraptor setup configure --server-profile "<SERVER REFERENCE>" --api-client /configs/lab.yaml
vraptor setup show --server-profile "<SERVER REFERENCE>"
vraptor setup migrate --server-profile "<SERVER REFERENCE>"
vraptor setup migrate --server-profile "<SERVER REFERENCE>" --write

vraptor setup start --mode live-remote --id live01 --server-profile "<SERVER REFERENCE>" \
  --api-client /configs/lab.yaml
vraptor setup start --mode remote-deaddisk --id disk01 --server-profile "<SERVER REFERENCE>" \
  --api-client /configs/lab.yaml --client-config /configs/lab_client.yaml \
  --evidence-path /evidence/disk.E01
vraptor setup start --mode local-deaddisk --id local01 --evidence-path /evidence/disk.E01
vraptor setup status --id local01
vraptor setup resume --id local01
vraptor setup stop --id local01 --stop-server
```

`setup start` initializes the investigation folder and readiness together;
`setup init` remains offline. Startup prompts only on a terminal and accepts
equivalent noninteractive inputs. Existing API YAML connects directly without
remote acquisition. `--fetch-config` enables copying missing configurations over
SSH using an explicit/configured `--server-ip`; `--provision-api` prepares the selected account before acquiring credentials,
even with cached YAML. Without explicit remote bootstrap configuration, it prompts
for manual administrator account setup, unless the cached YAML is kept (no
`--force` or `--regenerate-remote-api`) and already authenticates as the
selected user with the selected roles: setup then skips the
step (a terminal asks whether to run it anyway), and `--api-account-setup` runs
it. `--api-account-ready` acknowledges the manual step without bypassing
selected-user verification. `--bootstrap-api-config` and
`--bootstrap-api-user` select a remote provisioning-only connection. The credential
stays on the SSH host and cannot be the operational identity. Generation never
sets roles; existing accounts are unchanged. `--provision-client` separately
permits generation of missing endpoint YAML.
`--regenerate-remote-api` explicitly replaces the selected remote API YAML.
`--force` refreshes the local copy when acquisition is enabled.

Live setup defaults to server readiness with no hostname prompt; an empty client
inventory does not block verified API access and authorization. Explicit host,
client or label selectors still require visibility. Resume retains saved checks;
an explicit selection replaces the old one, and `--environment-only-ok` clears
saved target checks. This flag remains compatible but is unnecessary for a new
server-only setup. Live readiness is site-wide; later commands select their own
authorized scope.

Dead-disk setup accepts `--mapping-id NAME` to add several images to one
investigation. Its mappings share the case's server/organization/API identity
and managed local server, while each mapping retains its own runtime, saved
recipe and readiness. Use the selector on `start`, `resume`, `status` and `stop`;
it is required after more than one mapping exists. `engagement.json.mappings`
stores those records atomically under the case setup lock. Exact-host operational
commands validate the selected mapping; unscoped commands require all mappings
ready. Legacy single-mapping state and runtime paths remain supported.

Remote credential access uses SCP first. YAML generation defaults to the
`velociraptor` service account; explicit `run_as` settings or `--run-as` override
that default. Root SSH sessions can switch to the generation account and stream
protected files into the local temporary file. Non-root sessions try noninteractive sudo;
when authentication is required, interactive invocations open an SSH terminal
for sudo's password prompt. Passwords bypass captured setup output. Generation
runs as `run_as`, stages private output, validates it, and prepares only the
requested YAML for mode-0600 SCP retrieval. Successful sudo preparation resumes
automatically, without a Continue prompt. Failed preparation is not retried.
Preparation failures report a fixed diagnostic for the failing stage. A rejected
generation account requires `--run-as` matching the server's `Frontend.run_as_user`.
Raw native output is kept only in a private temporary file, then removed.
`--force` refreshes the local cache; generation requires `--provision-api` or
`--provision-client`, and remote API replacement requires `--regenerate-remote-api`.

If the default `velociraptor` account is absent, the fetch helper reports this
and selects root before generation. Explicit `run_as` settings (including
`velociraptor`) and `--run-as` disable this fallback. Account lookup errors and
generation failures stop without retrying as root.

If sudo is unavailable, or needs a password without a terminal, fetch helpers
exit 3 and write `status=needs_user_action` plus numbered manual steps to
`--json-out`. Agents must show the steps and wait for Continue before retrying.
In the manual fallback, `run_as` selects `sudo su` for root or
`sudo -u <user> bash` for a service account. Both live remote and remote dead-disk
share API generation; only remote dead-disk requires endpoint YAML.

`setup export --output SNAPSHOT.toml` saves effective workstation settings and
named connections, with local home paths expressed as `~`. API/client YAML, SSH
keys, credential dotenv and analyst TOML remain external references; no secret
values are exported. An environment-only connection needs `--server-profile`.
Existing export files are never overwritten. `setup deploy --from SNAPSHOT.toml`
previews the merged settings; `--apply` writes them and backs up an existing
target. Snapshot values replace matching keys and preserve unrelated settings.
`setup reset` previews removing operational preferences; `--apply` backs them
up and clears recognized setup overrides from selected/repository/shared dotenv
sources. Credential and analyst references are retained. These commands do not
deploy binaries, credentials or remote resources; see `CONFIG.md` for recovery.

Operational settings use `$XDG_CONFIG_HOME/vraptor/config.toml`, otherwise
`~/.config/vraptor/config.toml`; `--settings-file` selects another file.
Precedence is explicit arguments, process environment, selected credential dotenv,
repository dotenv, shared `~/.codex/.env`, TOML and code defaults. Native YAML
credentials and SSH keys remain files referenced by paths. Analyst profiles remain
in `analyst-agents.toml`; operational setup works without AI configuration.
`show` returns effective values and provenance, excluding credential values.
Its compact `analyst_agent` object contains `config_file`, `exists` and
`inspect_command`. Configure an optional `[analyst].config_file` reference with
`setup configure --analyst-config-file PATH`; `ai config` prints the full
analyst settings. Analyst `--config-file` and the existing environment/dotenv
config-file override take precedence over this reference. Inspection does not
load the referenced analyst TOML until the detailed command is run.
`configure` can materialize a `--template`, supports `--preview`, and keeps one
rotating `.bak`; `migrate` previews unless `--write` is supplied, retains
conflicting TOML entries and never rewrites credential dotenv files.

New case-owned runtime defaults to `<case-root>/<id>/runtime/velociraptor/`, with
`server/` for a dedicated local server and `mapping/` for a mapped client.
Remote live work creates neither. `--workspace` overrides the mapping directory.
An explicit `workstation.runtime_root` retains the external `servers/<profile>`
and `mappings/<id>` layout; saved setup paths always remain pinned on resume.
A supplied local API and matching endpoint configuration uses an existing server
without adopting its lifecycle. Named connections can reference configurations
in a common location across investigations, without copying them into case folders.
Both offline journeys preserve mapped client identity/writeback and reject changed
server/evidence bindings. Operations lock their investigation and managed resource
state; unrelated listeners and unmanaged datastores are not replaced.
Mapping state version 2 records the API username in its stable connection binding.
The shell session records a canonical connection hash rather than whole-file
credential hashes. Renewal is accepted for the same endpoint, organization, CA,
API identity and client enrollment nonce; certificate and permission checks still
apply. Version 1/hash-only mappings upgrade only when original credential hashes
match. An already changed or incomplete legacy credential record fails closed.

`status` returns recorded readiness and local process state with
`api_checked=false`; it does not make a live API query. `resume` reuses the saved
setup recipe and verifies readiness again. Older readiness remains supported;
use explicit `setup start` inputs to adopt it before calling `resume`. `stop`
terminates owned mapped-client/supervisor processes while retaining runtime files.
`--stop-server` additionally stops an owned local server only when no other active
mapping uses it. Remote live investigations have no managed local mapping to stop.
If local startup failed before the mapping was initialized, `stop --stop-server`
can still stop the owned server. Setup rejects writable investigation, runtime,
and fetched-credential paths inside mounted evidence or over the evidence image.
Mapped readiness shares the same enrollment and process-health checks across
the lifecycle and older setup commands.
Setup lifecycle/configuration commands emit JSON; runtime failures return 1 and
argument errors return 2.

`dfir case` and the `dfir-case` executable have been removed. Installed
entrypoints use the flat commands above. Hunt engine commands such as `check`,
`ensure`, `stop` and `review-results` run only as `hunt native <command>`; the
bare `hunt <command>` form prints `Use: vraptor hunt native <command>` and exits 1.
For compatibility, the checkout `./dfir` launcher strips the retired `velociraptor` namespace and enters the same Python settings resolver. `collect analyze` may ensure
missing collections; `analyze` only selects existing evidence. Neither publishes
case-management events.

All agent configuration options remain supported: views, provider, model,
transport, reasoning effort, timeout, retries, concurrency, configuration source,
Codex config and profile, and shared TOML file/execution-profile selection.
`ai setup` adds or updates named profiles, retaining saved values as prompt
defaults and one rotating backup. `ai config` and `ai doctor` are offline;
`ai models` and `ai doctor --live` request metadata, `ai test` makes a
synthetic model request, and `ai login` invokes native harness login.
Preparation retains
`venv`, `plaso`, `velociraptor`, `volatility`, `tsk`, and `all`, the staging-directory
option, and explicit local-workspace initialization. Installation is never used
as a dispatch test.

No case migration is required. These paths and their existing filenames remain:

- `<case-root>/<id>/engagement.json`
- `<case-root>/<id>/systems/<host>/collection/requests/<request-id>/`
- Existing host/artifact reports, analysis checkpoints and explicit exports
- `<case-root>/<id>/hunts/<hunt-id>/`
- `<case-root>/<id>/logs/velociraptor-progress.log` and operation metadata

`--id`, `--engagement-id`, `--investigation-id`, `--case-root`, server-profile
fallback, configuration locations and existing environment precedence remain.
There is no `workspace.json`, new case-level `vraptor` directory, or run hierarchy.
## Optional synthesis and saved candidates

Host/collection and live-hunt analysis accept `--synthesis none|full` (standalone
default: `full`). Use `--synthesis none` explicitly for preliminary candidates and
caller-owned final review. `--skip-ai` disables both analysis and synthesis model
calls. `analysis-results` retrieves bounded saved candidates without model
calls; `summarize` reviews a saved host request or streaming-hunt checkpoint only.
See [analysis synthesis](../reference/analysis-synthesis.md) for source selectors,
cache invalidation, persistence and coverage semantics.

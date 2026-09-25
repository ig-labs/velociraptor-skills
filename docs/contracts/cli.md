# CLI and existing-state contract

`dfir` and `vraptor` are equivalent entrypoints. They expose `query`, `clients`, `artifacts`, `collect`, `analyze`, `hunt`,
`export`, `ai`, and `tools prep`. `agent` remains a compatible alias
for `ai`. The advanced `setup`, `config`,
`mapped`, `autoruns` and `logs` groups retain their existing lower-level commands.
`setup` also provides shared configuration and three managed startup journeys.
`--server` aliases `--server-profile`; `--profile` remains an analysis profile.
`--client`, `--hunt`, `--request` and query `--file` alias the existing ID/file flags.

```sh
vraptor ai config --view defaults
vraptor config --view defaults
vraptor config --server lab
vraptor ai setup
vraptor ai doctor
vraptor tools prep --help
vraptor query --api-client /configs/lab.yaml --file clients.vql
vraptor clients --server lab --name host01
vraptor artifacts policy show
vraptor collect --id IR1234 --server lab --client C.1234abcd --artifact Windows.Forensics.Prefetch
vraptor analyze --id IR1234 --server lab --client C.1234abcd --flow F.EXAMPLE --skip-ai --json
vraptor analyze --id IR1234 --server lab --client C.1234abcd --request-id REQUEST_ID --json
vraptor analyze --id IR1234 --server lab --hunt H.EXAMPLE --artifact Windows.Forensics.Prefetch --skip-ai --json
vraptor analyze --from /exports/hunt-snapshot.json --skip-ai --json
vraptor export --id IR1234 --server lab --client C.1234abcd --request-id REQUEST_ID
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

Use `dfir setup init --id ir1234` once to create/reuse a standalone workspace.
`--case-root` selects its parent; `--investigation-dir` accepts an exact folder
ending in the ID. Existing `AGENTS.md` and investigation data are preserved.
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
vraptor setup configure --server-profile lab --api-client /configs/lab.yaml
vraptor setup show --server-profile lab
vraptor setup migrate --server-profile lab
vraptor setup migrate --server-profile lab --write

vraptor setup start --mode live-remote --id live01 --server-profile lab \
  --api-client /configs/lab.yaml --hostname host01
vraptor setup start --mode remote-deaddisk --id disk01 --server-profile lab \
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
SSH using an explicit/configured `--server-ip`; `--provision-api` and
`--provision-client` separately permit generation of missing remote files.
`--regenerate-remote-api` explicitly replaces the selected remote API YAML.
`--force` refreshes the local copy when acquisition is enabled.

Dead-disk setup accepts `--mapping-id NAME` to add several images to one
investigation. Its mappings share the case's server/organization/API identity
and managed local server, while each mapping retains its own runtime, saved
recipe and readiness. Use the selector on `start`, `resume`, `status` and `stop`;
it is required after more than one mapping exists. `engagement.json.mappings`
stores those records atomically under the case setup lock. Exact-host operational
commands validate the selected mapping; unscoped commands require all mappings
ready. Legacy single-mapping state and runtime paths remain supported.

Remote credential access uses SCP first. Root SSH sessions may generate YAML
as the current root user or an explicitly configured `run_as` datastore owner,
and stream protected files directly into the local temporary file. Non-root
sessions never escalate automatically: generation/unreadable files produce
manual SSH/generation/ownership instructions and a Continue prompt. The configured
`run_as` selects `sudo su` for `root` or `sudo -u <user> bash` for a service account.
Both live remote and remote dead-disk share API generation; only remote dead-disk
requires endpoint YAML. Manual generation stages private temporary output, validates
it and moves it beside the server config, then prepares the selected retrieval copy
with mode `0600`. Existing configured paths remain supported.
Without a terminal, fetch helpers exit 3 and write `status=needs_user_action`
plus instructions to `--json-out`; agents must show the steps and wait for the
user before retrying. A confirmation retries copying, not privileged execution.

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

`dfir case` and the `dfir-case` executable have been removed. Installed console
entrypoints use the flat commands above; the repository `./dfir velociraptor`
launcher remains a compatibility route to `vraptor.legacy_cli`. `collect analyze` may ensure
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
default: `none`). Use `full` explicitly for harness synthesis. Caller-led workflows own the
final review. `analysis-results` retrieves bounded saved candidates without model
calls; `summarize` reviews a saved host request or streaming-hunt checkpoint only.
See [analysis synthesis](../reference/analysis-synthesis.md) for source selectors,
cache invalidation, persistence and coverage semantics.

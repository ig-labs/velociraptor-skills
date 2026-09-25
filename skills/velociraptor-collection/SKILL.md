---
name: velociraptor-collection
description: Ensure or exactly reuse, monitor, analyze, and explicitly export one-host Velociraptor flows. Use for the canonical collect analyze workflow, focused artifacts, bounded timelines, saved-request recovery, deterministic artifact-scoped AI execution, and immutable exports.
---

# Velociraptor Collection

**Required server prerequisite:** follow the shared
[DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md)
for every new local server and connected live/remote server. If the live catalog
contains no `DetectRaptor.` artifacts, run `Server.Import.Extras` with the
DetectRaptor CSV row and verify installation before proceeding. Reuse a successful
session check; a failed import blocks the workflow. Explicit read-only/no-import
instructions and offline-only work retain their scope.

The standalone `vraptor` CLI uses the same case paths and configuration. Use
`vraptor analyze --flow F.ID --client C.ID --id ID` or
`vraptor analyze --hunt H.ID --id ID` for existing evidence only. Collection,
client retries and GoldenDB uploads remain explicit. Legacy `dfir`
routes retain their behavior. See the [shared CLI contract](../../docs/contracts/cli.md).

When a calling analyst such as Codex will write the assessment, pass
`--synthesis none` and review the validated preliminary candidates in the caller.
Use `--synthesis full` for a standalone harness report. The shared
[synthesis contract](../../docs/reference/analysis-synthesis.md)
covers candidate/context pagination, saved-summary-only execution and coverage.

The CLI defaults to `--synthesis none`; request `--synthesis full` explicitly
for harness synthesis. Save caller-reviewed host conclusions as
`assessment-host.md` and hunt conclusions as `assessment-hunt.md`, following
the provenance and freshness requirements in the shared
[synthesis contract](../../docs/reference/analysis-synthesis.md#caller-assessment-files).

Use `--skip-ai` on the analysis command when only deterministic preparation is
requested. Follow the shared [no-AI preparation contract](../../docs/reference/analysis-skip-ai.md)
for outputs, limitations and review status. A prepared result is not an AI assessment.

Use this skill for one-host collection mechanics. Use `velociraptor-host-analysis` for investigations and `velociraptor-hunting` for cross-host questions.
For explicitly requested prompt inspection, use `--debug-chunk-prompts [N]`
(one prompt by default when enabled), optionally with host `--skip-ai`.
This retains evidence-bearing prompts and, when AI runs, their raw responses
and correction retries. With `--skip-ai`, only prompts are saved. Follow the shared
[prompt export contract](../../docs/reference/chunk-prompt-debug.md).
Apply the [authorization policy](../../docs/reference/velociraptor-operation-authorization.md),
[analysis reduction contract](../../docs/reference/analysis-reduction-contract.md), [finding enrichment workflow](../../docs/reference/indicator-enrichment-workflow.md), and [server-profile/engagement context](../../docs/reference/velociraptor-engagement-context.md).

## Core rules

1. Reuse valid `engagement.json`; use `velociraptor-engagement-setup` only when
   readiness is missing, invalid, or affected by connection/credential/mapping
   changes or failures. Do not rerun setup/doctor for every collection; keep
   automatic CLI validation enabled.
2. Prefer exact client ID and reject ambiguous hostname resolution.
3. Treat Velociraptor flow state and result rows as authoritative.
4. Match prior flows by client, artifact, effective parameters, bounds, and timeout.
5. Reuse terminal-success or in-flight exact matches.
6. Ask only before adding `--force-run` unless the user already authorized it.
7. Keep ordinary evidence server-side and in process memory.
8. Query every successful artifact result component exactly once per analysis run.
9. Never export as a fallback for failed analysis.
10. Treat an explicit export command as authorization; do not ask twice.

## Canonical workflow

"Run execution" or another collection group means collect/reuse **and analyze**
unless the user explicitly requests collection-only, planning, or no AI. Use
`collect analyze` even when all exact flows are already complete; do not stop at
`collect ensure` or wait for a second analysis request. Existing-evidence-only
requests retain the `analyze` route. Follow the shared
[intent, continuation, and completion rules](../../docs/reference/velociraptor-operation-authorization.md#collection-intent-and-completion):
keep monitoring unfinished flows, analyze terminal artifacts as they arrive, and
verify the saved analysis checkpoint, final review, and coverage before closing.

Run one command:

```bash
dfir collect analyze \
  --investigation-id IR1234 \
  --server-profile lab7 \
  --client-id C.1234abcd \
  --question "What activity is malicious, security-relevant, or useful host context?"
```

`collect analyze` performs the complete deterministic workflow:

1. fail closed unless setup readiness verifies the site/API identity, hash and provisioning; readiness has no age expiry;
2. resolve one exact client;
3. verify server artifacts, then ensure or exactly reuse per-artifact flows;
4. manage one batched poll cycle for all saved Flow IDs;
5. fan each newly terminal artifact once into the coordinator's in-memory queue while
   polling continues;
6. project preferred fields and query each result component through repeatable 100,000-row `source()` windows, streamed in 5,000-row gRPC packets;
7. create one logical task per artifact;
8. send a fitting artifact directly to one read-only analyst;
9. split only oversized artifacts into contiguous token-bounded chunks;
10. run chunk/direct tasks in one flat globally bounded provider API pool;
11. validate request-wide `Sxxxx-R<number>` component-row references and field selections, hydrate evidence in Python, and apply the configured correction budget (two extra attempts by default);
12. synthesize chunked artifacts, then synthesize multiple artifact results once;
13. atomically write one terminal `complete` or `failed` artifact summary/component
    and one `request-analysis.json` checkpoint per completed request;
14. refresh cumulative `analysis-host.md`, then publish compact JSON and current-request `host-analysis-state.json`.

Collection analysis returns material findings to the owning host coordinator.
That coordinator invokes the bounded CTI enrichment decision and merges the
result; collection workers and CTI workers do not compete to write
`analysis-host.md`.

The standard readiness state is `<case-root>/<id>/engagement.json`; use `--readiness-manifest PATH` only for an explicit diagnostic override. The CLI owns one polling coordinator, in-memory scheduling/deduplication, retry, and 30-second/event-driven reconciliation. It does not create a persistent analysis lock.
Client ID defaults to `all`; use one collection type or repeated artifacts.
Resume saved flows after timeout; a missing flow ID requires a corrected new request:

```bash
dfir collect analyze \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --request-id REQUEST_ID \
  --question "Was malicious execution observed?"
```

Missing non-terminal local analysis is reconstructed from the saved Velociraptor
flows. Use `--retry-failed --request-id REQUEST_ID` to resume failed stages while
reusing accepted chunks and artifact candidates. `--reset-artifact NAME` and
`--reset-analysis` explicitly discard accepted local work. These options require
the exact request and never recollect evidence. Read the shared
[correction and recovery contract](../../docs/reference/analysis-recovery.md)
for separate correction settings, default failure diagnostics and retention.
Use `--rebuild-host-summary` to rebuild the cumulative host report from completed request checkpoints without analyst execution.

Inspect sizing without launching analyst agents:

```bash
dfir collect analyze \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --collection-type execution \
  --question "Was malicious execution observed?" \
  --plan-only
```

## Analyst runtime contract

Repository-root `.env` may override the shared stateless API runner. This
example explicitly selects Codex-managed OpenAI routing; omitted settings use
the code-owned defaults reported by `dfir ai config --view defaults`:

```dotenv
AI_SKILLS_ANALYST_AGENT_ENABLED=true
AI_SKILLS_ANALYST_AGENT_TRANSPORT=codex_app_server
AI_SKILLS_ANALYST_AGENT_PROVIDER=openai
AI_SKILLS_ANALYST_AGENT_MODEL=gpt-5.6-luna
AI_SKILLS_ANALYST_AGENT_REASONING_EFFORT=high
```
`codex_app_server` uses the installed Codex managed login and does not expose its
credential to Python; set the transport to `api` to use environment-backed
provider credentials and endpoints from `config/example.env`. Workers receive
bounded prompts without resumable provider or Codex conversation state. The
app-server adapter requests a read-only, no-network, ephemeral turn and
interrupts any observed tool, file, web, MCP, interaction, or subagent item.
The token, row, and byte envelope is also shared. `CONFIG.md` is the prose
overview; `config/example.env` lists optional override names,
`dfir ai config --view defaults` reports machine-independent code defaults,
and `dfir ai config` reports effective values and provenance.

Optional shared TOML execution profiles also configure OpenAI, Azure and Anthropic.
Use `vraptor ai setup` and offline `vraptor ai doctor`; see
repository `docs/model-execution.md` for native Codex/Claude login and API setup.
Setup reruns preserve saved settings and use the existing harness path as the
prompt default; verify an Azure model value against its deployment name.
Setup saves per-profile input/output budgets and fills shared `[analysis_defaults]`.
`collect analyze` accepts run-only AI profile/model and token overrides, including
`--max-input-tokens max --max-output-tokens max`. See repository
`docs/model-execution.md` under **Analysis model overrides** for precedence,
deployment ceilings and the conditional 100000 input floor.
Model envelopes tighten chunk/input/output limits; Claude uses shared budgets
when model limits are omitted.
Execution profiles are separate from analysis profiles.
Planning and runner admission apply the same model limits and retain valid
caller-supplied budgets.

The packet may rise to 20,000 rows after two full 5,000-row responses at most 2 MiB
with no row above 64 KiB; EVTX and PowerShell stay at 5,000. Size failures retry to
one row and later 100,000-row windows continue without changing logical chunks.

Environment values override code defaults; the immutable envelope resolves
once per operation, and input reserves scale down with smaller model contexts. Chunk,
artifact-correlation, and final synthesis stages
use the code-owned `high-volume`, `reasoning`, and `synthesis` routes. The stdin runner
disables user config, persists no prompts/CSV, and hydrates values in Python.

## Collection routing

- `--bundle ir-standard-live`: capability-aware running-endpoint IR baseline.
- `--bundle ir-standard-disk`: capability-aware mapped-disk IR baseline with
  volatile sources recorded as `not_applicable`.
- repeated `--collection-group`: custom combinations of `signal-triage`,
  `volatile-state`, `execution-history`, `identity-state`,
  `persistence-state`, `authentication-lateral`, `script-execution`, and
  `defense-evasion`; requires explicit `--target-mode`.
- `triage`: DetectRaptor plus PublicIP leads.
- `network`: live Netstat and DNS cache.
- `execution`: focused execution artifacts.
- `persistence-expanded`: startup, services, tasks, WMI, and Autoruns.
- `lateral-movement`: remote access, explicit logon, mounted resources, services.
- `all`: the unchanged legacy Windows baseline artifact union.
- `timeline`: bounded MFT and EVTX correlation.
- `exfiltration`: concrete staging or transfer hypothesis.
- `registry`: explicit full Registry Hunter request only.
- `--artifact`: exact server-supported artifacts.

Read [collection-types.md](references/collection-types.md) for exact membership.

Before a new IR bundle, use the read-only resolution command when the operator
needs to inspect capability and applicability without flow lookup or mutation:

```bash
dfir collect plan \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --bundle ir-standard-live
```

The resolved policy records core, recommended, optional, alternative,
applicability, and cost state. A missing core source blocks an explicitly
requested lane. In a standard bundle it marks that lane `core_missing` while
other resolvable lanes continue with degraded coverage. Recommended and
optional gaps never become clean absence. One selected physical artifact may
serve multiple logical groups and is collected only once.

For one explicit artifact, use `--env KEY=VALUE` for collection parameters and
`--analysis-input KEY=VALUE` for analysis constraints. Use `--flow-timeout-seconds`
for endpoint collection and `--poll-timeout-seconds` for local waiting.
For `collect analyze`, `--query-timeout-seconds N` caps each API query, including
client/flow lookup, polling queries, result acquisition and drill-down. The
default `0` adds no ceiling; shorter internal query limits remain effective.
It also works with `--request-id` and does not change collection parameters or
flow reuse identity. Streamed deadlines include pauses for AI capacity. This
option does not change endpoint execution, overall polling or model timeouts.

## Bounded timeline

Use only after evidence identifies an interval:

```bash
dfir collect analyze \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --collection-type timeline \
  --date-after 2026-08-07T07:00:00Z \
  --date-before 2026-08-07T08:00:00Z \
  --question "What changed in the suspicious interval?"
```

## Low-level collection and export

Use `collect check`, `ensure`, `queue`, `status`, and `poll` for explicit collection
operations. Their output explicitly notes that they do not run analysis or final
review. Do not interpret a collection command completing as analysis completion. `queue` and `ensure` poll by default. Pass the exact `--request-id` when
recovering saved state.

These commands, `export`, `export-registry-hunter`, and `hydrate` emit flushed,
evidence-free `DFIR-STATUS v=1 scope=collection` markers on stderr and append
the same `op-v1-*` correlation id to the human-readable
`<case-root>/<id>/logs/velociraptor-progress.log`, while keeping their JSON
result on stdout. The file includes stage progress, safe query purposes,
command scope, model/provider identity and usage, retries, counts, timings,
query-aware heartbeats, and sanitized server messages.
Set `VELO_PROGRESS_FILE_DEBUG=true` for normal plus verbose DEBUG file lines.
DEBUG adds response part/query IDs, server-reported totals, transport sizing,
and provider lifecycle detail. The submitted VQL, evidence rows, prompts, model
responses, environment values, provider bodies, and raw stderr remain excluded.
Inspect with
`dfir logs show --id <id>` or monitor with `dfir logs follow
--id <id>`; both accept `--operation`, `--level`, `--since`, `--scope`,
`--hunt-id`, and `--task-id`. Concurrent commands interleave safely under
distinct operation ids. Parallel task lifecycle events are not throttled,
heartbeats aggregate task state, and every operation ends with query, model,
task, retry, row, batch, rotation, and dropped-event counts when applicable.
The mode-`0600` adjacent `.lock` file serializes cross-process append and
rotation with a bounded wait; logging failure never fails collection. Use `--no-progress`
when stderr is not drained and
`--progress-interval-seconds N` to adjust heartbeat frequency. Treat durable
request state, coverage, and export manifests as authoritative; progress markers
are transient operational visibility.
INFO records bounded, single-line sanitized server messages and automatically
extracts valid numeric completed, total, percent, rows-scanned, bytes-scanned,
and elapsed-seconds fields under `progress_*`. Server text may contain
evidence-sensitive hostnames, usernames, paths, or VQL. Recognized API keys,
tokens, passwords, secrets, authorization values, URL credentials, PEM material,
and configured credential values are redacted. Message length and SHA-256 are
not logged. Each query has a local `q-NNNN` identifier and one heartbeat with
elapsed and server-idle time; unbounded queries and server silence are warned.
Unchanged queries receive five-minute reminders. `logs status --id <id>` checks
local PID/start identity and retained operation overlap; old logs without PID
identity report `UNKNOWN`. Silence is not proof of a remote stall.

Inventory validation precedes flow lookup. Submission/discovery are bounded to 60
seconds; `artifact_preflight` and `queue_progress` expose failures and provenance.
A replacement names the no-flow failed request with `--supersedes-request-id`; its
available/unavailable sets must partition the failed request exactly.

Export only for immutable preservation, offline review, or interoperability:

```bash
dfir collect export \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --request-id REQUEST_ID \
  --collection-type execution
```

Read [export-and-state.md](references/export-and-state.md) and
[registry-hunter.md](references/registry-hunter.md) when needed.

## Failure behavior
- Preserve success, empty, partial, failed, missing, and timed-out states separately.
- Fail closed on stale/mismatched readiness; resolve live targets dynamically and retain exact-target binding for local dead-disk and legacy manifests.
- Fail before queueing when a selected physical artifact disappears or an
  explicitly requested IR lane has no available core source. Standard bundles
  continue other lanes while recording missing core, recommended, optional,
  and inapplicable sources.
- Never poll a saved request whose required artifact flow ID was not recorded.
- Do not infer absence from zero rows without applicability and adjacent evidence.
- Fail if effective server arguments differ from the request.
- Fail closed when the analyst runner is disabled, missing, or exceeds token limits.
- Exhausting the configured correction budget is a coverage limitation; do not sample around it.
- Do not write evidence, prompts, model output, or review decisions under `/tmp`.
- Raw analyst output, stderr and execution manifests are transient, except explicitly requested prompt exports. Durable summaries, checkpoints and current state contain compact results, provenance, failures, retry counts and coverage. Reference-only accepted chunk decisions support failed-stage recovery; bounded value-free diagnostics are saved normally. Source aliases bind request, organization, client, Flow, artifact and result component; chunking never renumbers source rows. Derived host-state snapshots are no longer archived on request switching.

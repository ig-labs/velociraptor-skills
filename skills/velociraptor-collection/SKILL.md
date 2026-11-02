---
name: velociraptor-collection
description: Queue or exactly reuse (ensure), monitor, analyze through collect analyze, and explicitly export one-host Velociraptor flows, including collection groups such as run execution, focused artifacts, bounded timelines and saved-request recovery. Use for one-host collection and collect analyze runs and immutable exports. Not for open-ended host investigation; use velociraptor-host-analysis.
---

# Velociraptor Collection

**Server prerequisite:** complete the [DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md) for each new local or connected live/remote server before server work; a failed import blocks the workflow.

Use this skill for one-host collection mechanics. Use `velociraptor-host-analysis`
for investigations and `velociraptor-hunting` for cross-host questions. For
existing evidence only, `vraptor analyze --flow F.ID --client C.ID --id ID`
never collects; see the [shared CLI contract](../../docs/contracts/cli.md).

The CLI defaults to `--synthesis full`; use it for normal analysis, including
when Codex is the caller. Add `--synthesis none` only when preliminary-only
analysis or caller-only final review is requested, then review the validated
candidates in the caller. Use `--skip-ai` when only deterministic preparation is
requested; it takes precedence and prevents all model calls, and a prepared
result is not an AI assessment. Save caller-reviewed host conclusions as
`assessment-host.md` and hunt conclusions as `assessment-hunt.md`. Before using
these modes, read the shared
[synthesis contract](../../docs/reference/analysis-synthesis.md)
(candidate/context pagination, saved-summary-only execution, coverage, and the
[caller assessment files](../../docs/reference/analysis-synthesis.md#caller-assessment-files)
provenance and freshness rules) or the
[no-AI preparation contract](../../docs/reference/analysis-skip-ai.md)
(outputs, limitations and review status).

For explicitly requested prompt inspection, use `--debug-chunk-prompts [N]`
(one prompt by default when enabled), optionally with host `--skip-ai`.
This retains evidence-bearing prompts and, when AI runs, their raw responses
and correction retries. With `--skip-ai`, only prompts are saved. Follow the shared
[prompt export contract](../../docs/reference/chunk-prompt-debug.md).

Read the shared [authorization policy](../../docs/reference/velociraptor-operation-authorization.md)
before `--force-run`, retries, cancellation or any action beyond normal
collection, reuse, monitoring and explicit export; the
[analysis reduction contract](../../docs/reference/analysis-reduction-contract.md)
before scoping a question, judging coverage or handing results to another
workflow; and the [server-profile/engagement context](../../docs/reference/velociraptor-engagement-context.md)
when choosing `--server-profile`, case paths or readiness.

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
vraptor collect analyze \
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
6. project preferred fields and query each result component through repeatable 100,000-row `source()` windows, streamed in 5,000-row gRPC packets (packet growth and size fallback: [export-and-state.md](references/export-and-state.md#state-paths));
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
That coordinator applies the bounded
[finding enrichment workflow](../../docs/reference/indicator-enrichment-workflow.md)
and merges the result; collection workers and CTI workers do not compete to write
`analysis-host.md`.

The standard readiness state is `<case-root>/<id>/engagement.json`; use `--readiness-manifest PATH` only for an explicit diagnostic override. The CLI owns one polling coordinator, in-memory scheduling/deduplication, retry, and 30-second/event-driven reconciliation. It does not create a persistent analysis lock.
Client ID defaults to `all`; use one collection type or repeated artifacts.
Resume saved flows after timeout; a missing flow ID requires a corrected new request:

```bash
vraptor collect analyze \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --request-id REQUEST_ID \
  --question "Was malicious execution observed?"
```

Missing non-terminal local analysis is reconstructed from the saved Velociraptor
flows. Use `--retry-failed --request-id REQUEST_ID` to resume failed stages while
reusing accepted chunks and artifact candidates. A chunk whose corrections all
fail gets one AI repair call in the run (`--chunk-repair-limit N`, default 4, 0
disables) and, if accepted, is labelled `accepted after AI repair`. Chunks that
still fail are named in the summary and the request's `analysis/failed-chunks.json`; after
review, `--waive-failed-chunk KEY --waive-reason TEXT` publishes the accepted
chunks with that gap. `--reset-artifact NAME` and
`--reset-analysis` explicitly discard accepted local work. These options require
the exact request and never recollect evidence. Read the shared
[correction and recovery contract](../../docs/reference/analysis-recovery.md)
for separate correction settings, default failure diagnostics and retention.
Use `--rebuild-host-summary` to rebuild the cumulative host report from completed request checkpoints without analyst execution.

Inspect sizing without launching analyst agents:

```bash
vraptor collect analyze \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --collection-type execution \
  --question "Was malicious execution observed?" \
  --plan-only
```

## Analyst settings

**AI analyst settings:** inspect with `vraptor ai config` and `vraptor ai doctor`; run-only overrides include `--model`, `--reasoning-effort`, `--execution-profile`, `--ai-config-file`, `--max-input-tokens` and `--max-output-tokens` ([full list](../../docs/model-execution.md#analysis-model-overrides)). Setup: [AI analyst configuration](../velociraptor-engagement-setup/references/configuration.md#ai-analyst-configuration). Budgets and execution: [model execution](../../docs/model-execution.md).

`collect analyze` accepts `--max-input-tokens max --max-output-tokens max`; see
[analysis model overrides](../../docs/model-execution.md#analysis-model-overrides)
for precedence, deployment ceilings and the input/output minimums. Chunk,
artifact-correlation, and final synthesis stages use the code-owned
`high-volume`, `reasoning`, and `synthesis` routes. The stdin runner disables
user config, persists no prompts/CSV, and hydrates values in Python. Transports,
credential boundaries and the read-only, no-network Codex app-server turn are in
[provider analyst execution](../../docs/reference/provider-api-execution.md).

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
vraptor collect plan \
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
vraptor collect analyze \
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

Progress: these commands, `export`, `export-registry-hunter`, and `hydrate` emit
flushed, evidence-free `DFIR-STATUS v=1 scope=collection` markers on stderr and
append the same `op-v1-*` correlation id to
`<case-root>/<id>/logs/velociraptor-progress.log`, keeping their JSON result on
stdout. Inspect with `vraptor logs show|follow|status --id <id>`; `show` and
`follow` filter by `--operation`, `--level`, `--since`, `--scope`, `--hunt-id`,
and `--task-id`. Use `--no-progress` when stderr is not drained and
`--progress-interval-seconds N` to adjust heartbeat frequency. Progress is
transient visibility: durable request state, coverage, and export manifests stay
authoritative, and silence is not proof of a remote stall. Details:
[logging reference](../../docs/reference/velociraptor-logging.md#progress-logging)
and the collection [progress log](references/export-and-state.md#progress-log).

Inventory validation precedes flow lookup. Submission/discovery are bounded to 60
seconds; `artifact_preflight` and `queue_progress` expose failures and provenance.
When preflight reports unavailable artifacts, follow
[server-capability recovery](../velociraptor-artifact-selection/SKILL.md#server-capability-recovery).

Export only for immutable preservation, offline review, or interoperability:

```bash
vraptor collect export \
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
- A chunk that still fails after its correction budget and one AI repair call is a coverage limitation; do not sample around it. Report `accepted after AI repair` labels with any finding from those rows.
- Do not write evidence, prompts, model output, or review decisions under `/tmp`.
- Raw analyst output, stderr and execution manifests are transient, except explicitly requested prompt exports. Durable summaries, checkpoints and current state contain compact results, provenance, failures, retry counts and coverage. Reference-only accepted chunk decisions support failed-stage recovery; bounded value-free diagnostics are saved normally. Source aliases bind request, organization, client, Flow, artifact and result component; chunking never renumbers source rows. Derived host-state snapshots are no longer archived on request switching.

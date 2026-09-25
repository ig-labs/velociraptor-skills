---
name: velociraptor-hunting
description: Canonical Velociraptor cross-host workflow for Windows, Linux, and macOS. Discover, classify, create, or safely reuse hunts, run grouped or targeted Windows hunts, retry missing clients, analyze live results, review DetectRaptor, correlate artifacts, extract evidence only on request, analyze explicit snapshots or saved exports, and verify operator-requested stops while Velociraptor remains authoritative. Review candidate Autoruns CSVs offline and prepare approved GoldenDB updates.
---

# Velociraptor Hunting

## Prefer existing hunt evidence

Always prefer reviewing suitable existing hunts before proposing new collection,
including when the user gives a question or artifact rather than a hunt ID. Reuse
the known inventory or discover existing hunts read-only, check their case, target,
artifact/parameter, time and result coverage, then use the analysis branch below.
A compatible multi-artifact hunt can satisfy a narrower question. Review available
results even when the hunt is stopped or some flows failed; state the coverage gaps.

Only consider new collection when existing evidence cannot answer the requested
scope/freshness or the user explicitly requests fresh collection. Explain the
specific gap and retain collection authorization requirements. A missing local
baseline, stopped state, or absent prior analysis alone does not justify a new
hunt. Different-case/template evidence remains outside the current case unless
the user explicitly selects it for review.

## Analyze an existing hunt

For requests such as "run analysis on H.ID", use this branch directly. The named
hunt is the evidence scope; collection discovery, `check`/`ensure`, and a separate
native `status` call are not prerequisites. The analysis command performs live
metadata and flow-status preflight itself, including for hunts without local
collection state. It reviews exposed results from RUNNING or STOPPED hunts.

1. Reuse the session's verified server profile, case root, investigation ID,
   readiness and analyst setup. If they are missing, resolve them from saved
   engagement/configuration; ask only for an unresolved connection or scope.
   Apply the server prerequisite below, reusing a successful session check.
2. Run one existing-evidence analysis. Replace the example values with the exact
   saved context; `--case-root` is the parent of the investigation directory:

   ```bash
   vraptor analyze --hunt H.EXAMPLE --id IR1234 --case-root ~/cases \
     --server-profile lab --synthesis none
   ```

   Omit `--artifact` to review the hunt's declared artifacts. Preserve requested
   artifact/time filters and saved task policy; do not invent new bounds or model
   overrides. General Autoruns review needs `--profile autoruns` plus one exact
   Autoruns `--artifact`; use its specialized reference below for mixed hunts.
   Keep default text/progress output and monitor this invocation until terminal.
3. Review `analysis-hunt.md`. For standard streaming results, retrieve retained
   candidates without inference (specialized Autoruns/stack review uses its native
   report and classification state):

   ```bash
   vraptor analysis-results --checkpoint \
     ~/cases/IR1234/hunts/H.EXAMPLE/analysis/hunt-analysis-state.json --limit 25
   ```

   Continue using the returned next offset until the selected candidates are
   covered. Correlate findings and evidence, make the bounded enrichment decision,
   then save `hunts/<hunt-id>/assessment-hunt.md` under the case directory using
   the [caller assessment contract](../../docs/reference/analysis-synthesis.md#caller-assessment-files).
   Report result-review coverage separately from target execution; missing target
   baselines mean `not_assessed`, not blocked result review. A running hunt remains
   a point-in-time review. Caller assessment does not require another analysis run.

These commands cover the ordinary request without help discovery. Use the
[existing-hunt reference](references/existing-hunt-analysis.md) only for saved
review versus refresh, paging details, specialized results, or a concrete failure.
Use source-specific help only for an undocumented option or installed-version
mismatch. The collection and advanced-review sections below are conditional paths.

**Required server prerequisite:** follow the shared
[DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md)
for every new local server and connected live/remote server. If the live catalog
contains no `DetectRaptor.` artifacts, run `Server.Import.Extras` with the
DetectRaptor CSV row and verify installation before proceeding. Reuse a successful
session check; a failed import blocks the workflow. Explicit read-only/no-import
instructions and offline-only work retain their scope.

Existing-evidence analysis uses `vraptor analyze`; collection, retries and
GoldenDB uploads remain explicit. See the [shared CLI contract](../../docs/contracts/cli.md).
`--synthesis none` is the default: classification runs and the caller reviews its
preliminary candidates. Use `--synthesis full` only for requested harness synthesis;
see the [synthesis contract](../../docs/reference/analysis-synthesis.md)
for saved-summary execution and specialized-path limits.

Use `--skip-ai` for deterministic preparation without an AI assessment; follow the
[shared output and status contract](../../docs/reference/analysis-skip-ai.md).

For explicitly requested inspection of standard streamed chunk prompts, use
`--debug-chunk-prompts [N]` (one when enabled without a count). It exports
evidence-bearing prompts and their returned AI responses/correction retries
separately from metadata-only `--debug`; see the
[prompt export contract](../../docs/reference/chunk-prompt-debug.md)
for supported paths and zero-capture cases.

Use native Velociraptor hunts for cross-host questions. This skill owns their discovery, lifecycle, live analysis, explicit extraction, and saved review.

For general Autoruns hunt AI review, use the `autoruns` profile
and its [dedup AI and regex-only GoldenDB workflow](references/windows-persistence-autoruns.md#dedup-ai-review-and-regex-only-goldendb).
It keeps host samples out of AI/cache input, joins them only to suspicious rows, and
validates each source export without VQL context enrichment. Individual-host
entry-level analysis remains separate. With case context, a validated residual
copy is written to the hunt's `analysis/autoruns_review.csv` before AI review.
The root `analysis-hunt.md`, `analysis/hunt-analysis-state.json` and
`analysis/autoruns_potential_golden.csv` form the canonical publication.
For repository GoldenDB updates, review prospects, update the canonical
`src/vraptor/resources/golden/autoruns-golden.csv`, then generate the
complete database with `regex-build`. Follow the
[CSV-first maintenance workflow](references/windows-persistence-autoruns.md#regex-only-database-migration-and-updates).
Direct `regex-import` is for standalone databases, not repository maintenance;
legacy exact/promotion writes are disabled for schema 10.

The earlier general Autoruns and counts-only test workflows are retired.
`hunt run --profile autoruns` selects the collector; `hunt analyze --profile autoruns`
requires one hunt, one Autoruns artifact and a schema-10 database (schema 9 remains readable); output
directories are created automatically. The retired `autoruns_test` and `autoruns_dedup` profile names are
rejected. For mixed hunts, select other artifacts separately. Completed host-free
classifications are reusable from canonical hunt state after validation.
Local VQL benchmark fixtures are retained for development only.

For a supplied candidate Autoruns CSV targeting schema 6, use the [offline GoldenDB review workflow](references/windows-persistence-autoruns.md#offline-csv-review-and-repository-update): propose CSV updates, present them for review, and import approved additions locally. This branch needs no live readiness, case state, or API access; the live workflow below does not apply. The user can distribute the repository database update through a PR.

Legacy GoldenDB schema 6 matches exact HashKey identities and paired image/launch regex
rules across categories. Category remains source evidence and is not required
in offline update CSVs; legacy Category columns are accepted and ignored. Exact
identity hashes still include Signer; regex signer references do not affect
matching. Review proposed rules for their applicability across categories.

Use `velociraptor-artifact-selection` when the artifact, parameters, or safe pivots are unknown. Use `velociraptor-host-analysis` for one-machine deep dives.

Follow the shared [Velociraptor operation authorization policy](../../docs/reference/velociraptor-operation-authorization.md) and [analysis reduction contract](../../docs/reference/analysis-reduction-contract.md).
Apply the shared [finding enrichment workflow](../../docs/reference/indicator-enrichment-workflow.md) to every material result before final publication. The machine-readable ownership matrix is [velociraptor-hunting-capabilities.json](../../src/vraptor/resources/contracts/velociraptor-hunting-capabilities.json).
The executable output and closure policy is [velociraptor-persistence-policy.json](../../src/vraptor/resources/contracts/velociraptor-persistence-policy.json); full/update transport behavior is documented in [velociraptor-hunt-flow-analysis.md](../../docs/reference/velociraptor-hunt-flow-analysis.md). Use the shared [server-profile and engagement context](../../docs/reference/velociraptor-engagement-context.md).

## Operating Contract

- Select exact incident/hunt intent or declared assessment discovery before scoping work; apply [task-intent and output policy](references/task-intent-and-output.md). Velociraptor server hunt state, flows, and result rows are authoritative.
- Before creating anything, enumerate every server hunt containing all requested artifacts. Artifact matching is case-insensitive and a request may be a subset of an existing multi-artifact bundle.
- Classify candidates as exact current case, generic template, different-IR template, or unrelated. Engagement identifiers and IR labels compare case-insensitively.
- For collection scheduling, reuse only an exact current-case candidate with compatible requested artifact parameters and target scope. For evidence review, prefer existing in-scope results and disclose their coverage. A compatible multi-artifact bundle may satisfy a smaller request; do not create a duplicate single-artifact hunt.
- Calculate canonical run identity from source mode, artifact, effective parameters, timeout, OS or label scope, and available source-version data.
- For collection scheduling, rank exact matches as terminal success,
  in-flight/paused, then failed/cancelled/stopped/unknown; reuse only the first
  two classes as collection runs. This does not exclude available evidence from
  the other states from review or require `--force-run` to analyze it.
- Generic and different-IR candidates are templates only. Return their complete
  artifact set and parameters, never treat their results as current-case evidence,
  and never activate, retarget, clone, stop, or mutate them automatically.
- Require explicit `--authorize-template-create` after template review before
  creating a separate current-case hunt. Require `--force-run` before bypassing
  an exact prior current-case hunt. Record both decisions.
- Treat the local collection state as a pointer to the authoritative server
  hunt. Retain an original target baseline only when point-in-time fleet
  coverage or missing-client retry is required.
- Query live results with bounded server-side VQL. Keep ordinary returned rows
  in process memory.
- Persist compact state, filters, decisions, summaries, complete required
  aggregates, and exact suspicious drill-down evidence only.
- Treat `analysis-hunt.md` as generated analysis memory, not a hand-maintained
  report. Persist analyst findings, bounded review coverage, source watermarks
  or query hashes, limitations, and case-note references in
  `analysis/hunt-analysis-state.json` before regenerating it. Attach available host,
  identity, session, process, file, network, and time context to the finding it explains; do not emit a disconnected enrichment catalogue.
- Treat snapshot, CSV export, and JSONL download as explicit evidence
  extraction. Never extract only to simplify implementation.
- Never stage prompts, API responses, review rows, decisions, databases, or
  model output in `/tmp`. Use stdin/stdout or private case-owned sibling paths.
- When the task requests a stop, execute it without a second prompt and verify server
  readback.

Targeting rules:

- `--target windows|linux|macos` scopes by OS when no include label is set.
- `--include-label` or `--host-label` takes precedence over OS.
- `--exclude-label` may be combined with either form.
- No OS or include label means all eligible clients.

Case-aware commands use `--server-profile` for the Velociraptor deployment and `--engagement-id` for local storage. If the engagement id is omitted, it falls back to the server profile. Labels remain explicit and independent.

## Collection lifecycle and advanced review

For an explicitly named hunt analysis, follow the existing-hunt branch above.
Steps 2–6 below concern collection selection/lifecycle; stacking, decisions and
manual review-memory publication apply only when those operations are needed.

1. Inspect saved readiness at session start and reuse valid `engagement.json`;
   use `velociraptor-engagement-setup` only when missing, invalid, or affected by
   connection/credential/mapping changes or failures. Reuse successful session
   analyst checks instead of repeating setup/doctor for each hunt. Automatic CLI
   validation remains enabled.
   Live commands validate `<case-root>/<id>/engagement.json` against the current
   API credential, server fingerprint and org before querying. Readiness does not
   expire by age. Reuse it; regenerate through engagement setup after a connection
   or readiness failure, then resume the existing hunt.
2. Select the smallest artifact and parameter set that answers the question.
3. Run `check`, then `ensure` or the public `run` wrapper. Both paths discover
   candidates server-wide before mutation; grouped runs preflight every artifact
   before creating the first hunt.
4. Inspect the candidate classification/rank, source artifact set and parameters,
   human summary, run-identity hash, reuse decision, force decision, and mismatch rationale.
5. Reuse terminal-success or in-flight/paused exact current-case matches. If only
   a compatible generic or different-IR template exists, review it and obtain
   explicit `--authorize-template-create` permission. Its results remain out of scope.
6. Run `status` for target execution coverage and result availability.
   If the hunt has no local collection state or baseline, automatically use
   `ad_hoc_review`: review the complete server-reported result set and mark
   target execution `not_assessed` without blocking review completion.
7. Run `hunt analyze --hunt-id|--group` against live results. Use the explicit
   `--profile autoruns` workflow above for general Autoruns review. For other artifacts, the default path
   enumerates `hunt_flows(..., basic_info=FALSE)`, streams profile-projected `hunt_results()` once
   per selected artifact, accounts for every row Velociraptor exposes—including rows
   already available from open flows—and streams token-bounded transient chunks into
   artifact-named lanes on one hunt-scoped async scheduler and shared client. It
   does not construct a complete hunt plan or pending prompt queue; the global
   Row-count, 32 MiB, item-credit, and token-weight bounds pause acquisition. Default stdout is bounded
   text with `chat_summary`. Keep text output for interactive and operator-initiated
   runs. Use `--format json` only when an explicit downstream integration will
   parse the structured response; do not select JSON merely for agent convenience.
8. Rerun the same full command to rebuild from Velociraptor, or pass `--update`
   after a successful full analysis to merge flows completed since the persisted
   server cutoff. Updates read exact `source()` results in server-side batches of
   at most 250 flows. The cursor advances only after accepted analysis publication
   (validated synthesis in `full`, validated preliminary candidates in `none`):
   either a fully validated result or the grounded deterministic
   `complete_with_failures` fallback.
9. Keep live analysis in streaming mode. Use `--analysis-mode stack` when the
   question requires prevalence or structured reduction; stacking changes the
   server-side reduction, not the streamed execution model. Generic stacks
   stream every aggregate group through token-bounded transient analyst parts
   with bounded concurrency and acquisition backpressure; `codex_app_server` uses shared-daemon ephemeral turns rather than one Codex process per request. Only flagged groups
   become compact drill-down review items. The aggregate AI pass receives
   occurrence and distinct-host prevalence statistics. The workflow then
   requeries flagged groups for impacted machine names and relevant original
   rows, performs a second AI assessment, and writes provisional findings to
   `analysis-hunt.md`. Analyst-backed stacking runs this complete aggregate
   review regardless of whether the source has fewer than the 1,000-row direct
   review threshold. If stack-field discovery cannot produce a safe pivot and
   the complete artifact still fits that threshold, fall back to one exhaustive
   direct review instead of a discovery sample. Declared Autoruns workflows select
   their specialized streaming stacks automatically; indicators, filters, and decisions require explicit stacking.
   DetectRaptor defaults to stream-only review. EVTX discovers detection/size workloads and plans each detection independently. Small detections and direct fallbacks stream complete evidence. Large detections run an exhaustive exact-payload census; materially reducible detections stream every exact group rare-first. Apply one time-and-detection `WHERE` clause to every query. Do not sample, generate filters, or apply exclusions. An optional EVTX `--detection-regex` scopes the same canonical planner; `detectraptor-stack` is a deprecated stream alias.
   Exact grouping uses no signature-count ceiling or hash equivalence. Every source row contributes to Python-owned represented-row accounting. Send each full exact-payload group through the same bounded CSV chunk workflow and `reference-line-v3` response contract as normal live hunting. Use `_SourceRef`, `Detection`, `OccurrenceCount`, `FirstSeen`, `LastSeen`, `PayloadField`, and trailing `Payload`; standard CSV quoting preserves commas, quotes, tabs, and embedded newlines. Return only reportable findings, and use `RESULT<TAB>no_reportable_findings` for a clean chunk; do not require benign or expected output per group. Permit sparse `UPLIFT` records only for high-confidence reusable benign patterns, scoped `global` or `site`; Python copies the full source payload into the final field of `analysis/detectraptor_whitelist_candidates.csv`. Run detection producers concurrently in unique fair lanes under the one scope-wide analyst ceiling. Do not run a preview pass or second semantic pass. Batch-query timestamps and machines only for source references returned in findings; attach that context without asking AI to reassess it. Use configured stack definitions
   only as field-priority guidance for interpretation or explicit bounded
   server-side pivots. Do not invoke generic `--analysis-mode stack` for
   DetectRaptor, and analyze mixed DetectRaptor/Autoruns selections separately.
   Without a curated signature, derive a validated ephemeral rare-first stack
   from 10-20 transient rows; never update `preferred-artifacts.json`.
   Chat callers may supply repeated `--stack-field-preference` names and
   `--stack-field-guidance`; the AI evaluates those inputs with transient
   statistics, while deterministic code allows at most three total dimensions.
   A guided selection with no safe result stops for operator clarification.
   Configure execution through `AI_SKILLS_ANALYST_AGENT_*` or shared TOML profiles; inspect it with `vraptor ai config` or offline `vraptor ai doctor`. See repository `docs/model-execution.md` for setup and native Codex/Claude login.
   Setup saves per-profile input/output budgets and fills shared `[analysis_defaults]`.
   Hunt, Autoruns and snapshot analysis accept run-only AI profile/model and token
   overrides, including `--max-input-tokens max --max-output-tokens max`. See
   repository `docs/model-execution.md` under **Analysis model overrides** for
   CLI precedence, deployment ceilings and the conditional 100000 input floor.
   Resolve limits once per operation; Claude uses shared budgets when model limits are omitted. Analysis profiles choose
   only `high-volume`, `reasoning`, or `synthesis`; code derives the task.
10. Use bounded rows only to propose filters or select exact normalized groups.
   Sampling never accounts for unseen rows.
11. Requery suspicious groups for original rows and hosts. Submit decisions by
   `review_id`; every suppression requires an exact match count, disposition,
   and reason.
12. For structured or bounded reviews intended for harness publication, persist findings and
    coverage in `analysis/hunt-analysis-state.json`. For manual review outside
    `review_id`, append
    compact `analyst_review_memory`, then rerun `hunt analyze` to regenerate
    `analysis-hunt.md`.
    Ordinary caller review of accepted candidates instead writes
    `assessment-hunt.md`; it neither edits the harness checkpoint nor reruns
    analysis just to publish the caller's conclusions.
13. Verify the regenerated analysis contains the new memory and still exposes
    any unresolved structured-accounting or target-coverage blockers.
14. Repeat until no review items remain, result review is complete at the
    current aggregate watermark, and target execution has the required
    coverage; otherwise report the exact provisional/incomplete state.
15. Send every material finding through the bounded CTI enrichment decision,
    merge the returned context into that finding, and record `complete`,
    `partial`, or `not_applicable` before final publication.
16. Use `snapshot`, `export-results`, or `download-results` only when durable
    evidence is required.

Use the shared `analyst-agent` only as a separate read-only semantic-review lane over bounded evidence. Hunt creation, retries, stops, and analysis checkpoint updates stay with the hunt workflow.

## Reference Routing
Read only the references needed for the current branch:

- [existing-hunt-analysis.md](references/existing-hunt-analysis.md): saved review,
  refresh/update choices, candidate paging and failure recovery for an exact hunt.
- [live-analysis.md](references/live-analysis.md): review IDs, generic adaptive
  reduction, filters, drill-down, and closure.
- [windows-hunt-orchestration.md](references/windows-hunt-orchestration.md):
  grouped DetectRaptor, targeted Windows hunts, exact reuse, and missing-client
  retry.
- [windows-live-analysis.md](references/windows-live-analysis.md): Windows path,
  signer, PowerShell, DLL/.NET, normalization, and drill-down controls.
- [detectraptor-analysis.md](references/detectraptor-analysis.md): artifact
  fleet adapter for the shared priority, correlation, disposition, and uplift
  contract.
- [extracted-evidence-analysis.md](references/extracted-evidence-analysis.md):
  explicit snapshot/export/download review.
- [windows-persistence-autoruns.md](references/windows-persistence-autoruns.md):
  Autoruns GoldenDB aggregate exception and focused use cases.

## Public Commands

### Grouped or Targeted Windows Hunt

```bash
dfir hunt run \
  --id IR1234 \
  --profile detectraptor \
  --task-mode compromise-assessment \
  --response-depth standard \
  --question "Find Windows compromise leads"

dfir hunt run \
  --id IR1234 \
  --artifact Windows.Search.FileFinder \
  --env 'Glob=C:\\ProgramData\\Vendor\\beacon.dll' \
  --question "Find the known file"
```

Add `--force-run` only when a fresh exact collection is desired after reviewing
prior-match details.

`run` stores `--task-mode` and the resolved `--response-depth` in the group
manifest. A later live `analyze` inherits them when those flags are omitted;
explicit analysis flags take precedence.

If discovery returns a generic or different-IR template, review the reported
source artifact set and parameters. To create a separate current-case hunt after
explicit authorization:

```bash
dfir hunt run \
  --id IR1234 \
  --artifact IG.Windows.Sysinternals.Autoruns \
  --question "Review persistence" \
  --authorize-template-create
```

This flag never retargets or mutates the source template and never reuses its results.

### Native Cross-Platform Check and Ensure

```bash
dfir hunt native check \
  --investigation-id IR1234 \
  --target linux \
  --artifact Linux.Sys.Users

dfir hunt native ensure \
  --investigation-id IR1234 \
  --target linux \
  --artifact Linux.Sys.Users
```

Use native `check`/`ensure` for Linux or macOS and for one-off expert scopes.
Use `--activate-paused` to resume an exact paused hunt. Use `--force-run` to
intentionally create a new exact run.

### Status and Live Analysis

```bash
dfir hunt status \
  --id IR1234 \
  --group DR-20260725T120000Z

dfir hunt analyze \
  --id IR1234 \
  --group DR-20260725T120000Z

dfir hunt analyze \
  --id IR1234 \
  --hunt-id H.1234 \
  --artifact DetectRaptor.Windows.Detection.Evtx

```

The ordinary command requires no chunking option. A full rerun rebuilds from authoritative `hunt_results()`; `--update` resumes from the last successfully published server cutoff except for detection-partitioned EVTX analysis, which rejects `--update` and requires a full rerun. Timezone-aware strict `(after,before)` bounds and repeatable logical `--time-field` roles use each selected profile when available. Artifact names containing `EventLogs` default to `event=EventTime` unless explicitly overridden or disabled; `Windows.Detection.PublicIP` is explicitly mapped to `EventTime`. Apply the resolved `WHERE` predicate inside `hunt_results()` or each batched `source()` query so filtering occurs before gRPC transport. For EVTX, use the same time predicate in discovery and each partition. Optional regex scope adds parameterized `Detection.Name =~ RequestedDetection`; resolved queries retain exact `Detection.Name = PartitionDetection`. With no requested bounds or known mapping, use normal unfiltered behavior. Keep local predicates as defensive validation. Bounded hunts require stream mode.

The verified matrix and source-specific roles are in [analysis-time-filter-support.md](references/analysis-time-filter-support.md). Bounded mixed-artifact runs persist exact expressions and `complete`, `partial`, or `unsupported` time-filter coverage; partial filtering keeps overall coverage partial.

The coordinator holds one 5,000-row or 32 MiB logical segment, one partial token chunk, and at most the configured number of active analyst prompts. It releases each prompt and source-row validation map immediately after validation. To use fleet-prevalence stacking explicitly:

```bash
dfir hunt analyze \
  --id IR1234 \
  --hunt-id H.1234 \
  --analysis-mode stack
```

Apply a command-line indicator or approved filter reference when needed:

```bash
dfir hunt analyze \
  --id IR1234 \
  --hunt-id H.1234 \
  --analysis-mode stack \
  --indicator 'Evidence=beacon\\.dll|rundll32' \
  --filter-reference /path/to/hunt-filters.json
```

### Optional Query Timeout

Live `hunt analyze` accepts `--query-timeout-seconds N`. The default `0` adds
no timeout ceiling and preserves existing query-specific limits. A positive
integer caps each API query, including inventory, accounting, stacks and
original-row drill-downs; shorter internal timeouts still win. The effective
value is sent to Velociraptor and the gRPC deadline and appears in query logs.
This is not an overall command timeout, an AI timeout, or a collection timeout.
Streamed queries include time spent paused for downstream analysis capacity.
The option is rejected with `--snapshot`.

```bash
dfir hunt analyze \
  --id IR1234 --hunt-id H.1234 \
  --artifact IG.Windows.Sysinternals.Autoruns \
  --query-timeout-seconds 1800
```

### Missing-Client Retry

```bash
dfir hunt retry-missing \
  --id IR1234 \
  --hunt-id H.1234 \
  --after-hours 24 \
  --max-attempts 1 \
  --batch-size 100
```

This writes policy only. A later live analysis pass requeues only original
baseline clients with no flow. Retry state stores client IDs and attempt
timestamps, not result rows.

### Explicit Evidence Extraction and Offline Review

```bash
dfir hunt snapshot \
  --id IR1234 \
  --hunt-id H.1234

dfir hunt analyze \
  --snapshot /path/to/snapshot.json

dfir hunt native export-results \
  --investigation-id IR1234 \
  --hunt-id H.1234

dfir hunt native download-results \
  --investigation-id IR1234 \
  --hunt-id H.1234
```

`hunt analyze --hunt-id` and `hunt analyze --group` never resolve
`latest.json` and never create a snapshot. Use `hunt analyze-saved` only for an
explicit existing export/download manifest.

### Stop and Verify

```bash
dfir hunt native stop \
  --investigation-id IR1234 \
  --hunt-id H.1234
```

## DetectRaptor Requirements

Use the fleet adapter and shared
[DetectRaptor contract](../../docs/reference/detectraptor-analysis-contract.md).
Use accounted streaming rather than generic stack analysis. EVTX automatically
groups exact script-block payloads for large, materially reducible detections,
without hash equivalence, sampling, exclusions, or a signature-count ceiling.
The optional detection regex scopes the same canonical analysis. Group review receives the complete exact payload; query only timestamp and machine context for groups already classified as notable or suspicious.
Run each EVTX detection in an isolated recovery lane that replays only the active detection after a safe transport reset, reuses completed detections only during unfinished-run recovery, and retires recovery after publication. Keep recovery state identity-free and payload-free. Atomically refresh `analysis-hunt.md` after accepted detection checkpoints, including failed or provisional runs. Write compact
uplift-review candidates to `analysis/detectraptor_whitelist_candidates.csv`, never generated ignore rules. Consolidate equivalent reportable exact-payload assessments in `analysis-hunt.md` and show represented occurrences, endpoint/time scope, and at most three representative timestamped events; retain every hydrated event only in the separate interesting-context ledger. A synthesis exception must terminalize the report and ledgers as failed without discarding completed detection recovery. Concurrent lanes share one model concurrency ceiling; a failed lane cannot cancel accepted peers. Follow machine-validated priority,
use prevalence only as context, retrieve exact host rows, perform cross-artifact correlation, and require fleet/replay validation for
reusable rule-uplift proposals.

## Persistence and Output Contract

Normal live analysis writes compact control products under:

```text
<case_root>/<id>/hunts/<hunt_id>/
  analysis-hunt.md
  analysis/
    hunt-analysis-state.json
    finding-evidence.md  # optional, manager-selected full projected rows
    filters.json         # only when filter records exist
```

Read the [persistence and output details](references/live-analysis.md#persistence-and-output-details)
for checkpoint bounds, debug/logging controls, recovery/reference semantics,
aggregate review, and report-rendering limits before operating those lanes.
Transient source rows, prompts, model transcripts, aggregate parts, and failed
chunk payloads are not persisted by default. Explicit `--debug-chunk-prompts`
exports are retained outside the analysis tree as described above.
A failed chunk or hard synthesis failure leaves
the prior checkpoint and cursor unchanged. The validated grounded
`complete_with_failures` synthesis fallback retains partial coverage.

`analysis-hunt.md` is the cumulative hunt assessment and task memory. The
generic flow-analysis coordinator is its sole writer. It atomically composes
available generic flow state with compact specialized state after every general,
focused, structured-decision, or bounded analyst-review pass. Stacking and
focused analysis write their bounded accounting, findings, representative
context, and next action into this canonical report. Do not edit it directly.
For custom reviews that must enter the harness report, persist compact `analyst_review_memory` with
the artifact, review time, source row count, source watermark or query hash,
coverage statement, assessment, limitations, and case-note reference before
rerunning analysis.
Caller-owned `assessment-hunt.md` is a separate supported publication: retain its
checkpoint provenance and coverage without modifying harness state or rerunning
acquisition. See the caller assessment contract linked above.

`hunt-analysis-state.json` contains watermarks,
coverage, reviewed branches, findings, analyst review memory, run identity,
and compact query metadata. Ordinary result rows are not stored in state,
analysis memory, or command responses as bulk evidence.

It also records `source_identifiers`, normalized `coverage_state`, closure
blockers, and `persistence_manifest`. The runtime classifies every live
analysis file by both path and content. Row-shaped or oversized Markdown and
JSON containing inline row arrays are rejected even when their filenames look
allowed. Before live hunt processing, the command checks existing analysis
files and analysis memory with the same classification rules used at publishing.
Explicit hunts are checked before API discovery; groups are checked after hunt
discovery but before processing any selected hunt. Incompatible files fail early
with absolute paths, reasons, and recovery instructions in the terminal and
sanitized progress-log diagnostics. Files are preserved by default. Move unrelated
historical files into the case reviews directory outside the analysis tree, or
correct their format/classification, then rerun. The final audit remains in place
to reject incompatible outputs created during processing.

Allowed evidence-bearing exceptions are:

- explicit immutable snapshots, exports, or downloads;
- the attested Autoruns `autoruns_potential_golden.csv` candidate set;
- exact suspicious drill-down outputs tied to a finding outside the streaming
  Autoruns lanes; and
- explicit interoperability outputs requested by the operator.

Explicit export and download manifests include persistence authorization tied
to their hunt and artifact source identifiers.

Autoruns focused and GoldenDB outputs are defined in
[windows-persistence-autoruns.md](references/windows-persistence-autoruns.md).
Potential GoldenDB rows never update trust automatically.

## Closure Guardrails

Hunt status/preflight projects only client/flow IDs, state, collected-row totals
and artifact-result names from `hunt_flows(basic_info=FALSE)`. Full flow records
can repeat large compiled collector requests per endpoint and exceed gRPC
message limits. Transport metadata in 100-row batches without a total-result
limit; retain nested `Flow` fields needed by status and snapshot routing.

- A sampled, token-limited, or group-truncated result branch cannot be reported
  as complete.
- In `managed_collection`, preserve target-execution coverage separately and
  require the necessary point-in-time scope before making fleet-wide closure or
  missing-client claims.
- In `ad_hoc_review`, accept the selected Velociraptor hunt as authoritative,
  mark target execution `not_assessed`, and allow complete result-set review.
  Do not translate result-set completion into a claim about nonresponding hosts.
- At most 1,000 raw/direct/sample/drill-down rows are returned per pass.
  Automated generic stacking reviews the complete aggregate stream without a
  source-group cap and retains at most 100 flagged drill-down items. Manual or
  specialized fallback queues remain bounded by their configured group and
  200,000-token ceilings.
- Known-bad matches remain visible through approved suppressions.
- Detection names define analyst scope; suppress the profile-approved
  evidence-bearing field, not the detection name.
- Validate candidate filters server-side before they remove rows.
- Normalized groups are pivots unless the artifact reference explicitly allows
  closure and all hidden-variant and hijack-risk checks are recorded.
- Requery suspicious normalized groups against original hunt rows.
- Running-hunt result-review coverage and target-execution coverage are
  separate. Row-count changes invalidate prior closure watermarks.
- For a full run, stream the complete aggregate `hunt_results()` result set,
  including rows Velociraptor exposes from open flows. For `--update`, stream
  each selected successful-terminal `source()` result. Keep gRPC packets
  bounded and form fixed logical segments locally.
- A nonzero aggregate result count with zero acquired aggregate rows fails
  closed. Never publish zero-row completion for that contradiction.
- Propagate managed target coverage into the general flow analyzer. An ad-hoc
  review does not require a local baseline and uses `not_assessed` as a
  nonblocking target-execution state.
- Flow inventory and result acquisition are separate: open and unknown flows
  remain visible in target-execution coverage while any rows already exposed by
  `hunt_results()` are reviewed. A later run re-reads the current aggregate;
  `--update` adds newly successful terminal sources.
- API `max_row` is a streamed-response row target, not a total-result ceiling.
  Full/update acquisition starts at 5,000 transport rows and retries message-size failures at 2,500, 1,000, 500, 100, 10, and 1. Segments stop at 5,000 rows or 32 MiB. A single row larger than the configured gRPC receive limit remains an explicit coverage failure.
- Direct EVTX review transports full PowerShell Evidence. Exact-stack review requeries selected groups; use extraction only when that follow-up is insufficient.

### Autoruns live stack count changes
Follow the [accounting and identity contract](references/windows-persistence-autoruns.md#accounting-and-identity-diagnostics)
for complete-stream accounting, changing counts, request-byte batching and memory limits.

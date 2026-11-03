---
name: velociraptor-hunting
description: Velociraptor cross-host hunt workflow for Windows, Linux, and macOS. Discover, classify, create, or safely reuse hunts, run grouped or targeted Windows hunts, retry missing clients, analyze live results, review DetectRaptor, correlate artifacts, extract evidence only on request, analyze explicit snapshots or saved exports, and verify operator-requested stops while Velociraptor remains authoritative. Review candidate Autoruns CSVs offline and prepare approved GoldenDB updates. For one endpoint use velociraptor-host-analysis; to choose artifacts use velociraptor-artifact-selection.
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
     --server-profile lab
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

These commands cover the ordinary request without help discovery. Read the
[existing-hunt reference](references/existing-hunt-analysis.md) only for saved
review versus refresh, paging, specialized results, or a concrete failure, and
source-specific help only for an undocumented option or installed-version
mismatch. The collection and advanced-review sections below are conditional.

**Server prerequisite:** complete the [DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md) for each new local or connected live/remote server before server work; a failed import blocks the workflow.

Existing-evidence analysis uses `vraptor analyze`; collection, retries and
GoldenDB uploads remain explicit. See the [shared CLI contract](../../docs/contracts/cli.md).
`--synthesis full` is the default. Add `--synthesis none` only when preliminary-only
analysis or caller-only final review is requested; classification still runs and
the caller reviews its candidates. `--skip-ai` disables all model calls for
deterministic preparation without an AI assessment; follow the
[shared output and status contract](../../docs/reference/analysis-skip-ai.md) and see the
[synthesis contract](../../docs/reference/analysis-synthesis.md) for saved-summary execution and
specialized-path limits.

For explicitly requested inspection of standard streamed chunk prompts, use
`--debug-chunk-prompts [N]` (one when enabled without a count). It exports
evidence-bearing prompts and their returned AI responses/correction retries
outside the analysis tree, separately from metadata-only `--debug`; see the
[prompt export contract](../../docs/reference/chunk-prompt-debug.md)
for supported paths and zero-capture cases.

**AI analyst settings:** inspect with `vraptor ai config` and `vraptor ai doctor`; run-only overrides include `--model`, `--reasoning-effort`, `--execution-profile`, `--ai-config-file`, `--max-input-tokens` and `--max-output-tokens` ([full list](../../docs/model-execution.md#analysis-model-overrides)). Setup: [AI analyst configuration](../velociraptor-engagement-setup/references/configuration.md#ai-analyst-configuration). Budgets and execution: [model execution](../../docs/model-execution.md).

Use native Velociraptor hunts for cross-host questions. This skill owns their
discovery, lifecycle, live analysis, explicit extraction, and saved review. Use
`velociraptor-artifact-selection` when the artifact, parameters, or safe pivots
are unknown. Use `velociraptor-host-analysis` for one-machine deep dives.

Follow the shared [Velociraptor operation authorization policy](../../docs/reference/velociraptor-operation-authorization.md)
and use the shared [server-profile and engagement context](../../docs/reference/velociraptor-engagement-context.md).
Apply the shared [finding enrichment workflow](../../docs/reference/indicator-enrichment-workflow.md)
to every material result before final publication. Read the
[analysis reduction contract](../../docs/reference/analysis-reduction-contract.md) before custom
reduction, filtering, or closure decisions.

## Autoruns and GoldenDB

General Autoruns hunt AI review (`--profile autoruns`, one hunt, one exact
Autoruns `--artifact`) needs a schema-10 GoldenDB (schema 9 remains readable);
`hunt run --profile autoruns` selects the collector and output directories are
created automatically. Follow the
[dedup AI and regex-only GoldenDB workflow](references/windows-persistence-autoruns.md#dedup-ai-review-and-regex-only-goldendb).
The retired `autoruns_test` and `autoruns_dedup` profile names are rejected. For
mixed hunts, select other artifacts separately. For focused stack count changes,
request-byte batching, and exact-identity rules, follow the
[accounting and identity contract](references/goldendb-maintenance.md#accounting-and-identity-diagnostics).

Potential GoldenDB rows never update trust automatically. GoldenDB changes
follow [goldendb-maintenance.md](references/goldendb-maintenance.md):

- For repository GoldenDB updates, review prospects, update the canonical
  `src/vraptor/resources/golden/autoruns-golden.csv`, then
  generate the complete database with `regex-build`. Follow the
  [CSV-first maintenance workflow](references/goldendb-maintenance.md#regex-only-database-migration-and-updates).
  Direct `regex-import` is for standalone databases, not repository
  maintenance; legacy exact/promotion writes are disabled for schema 10.
- For a supplied candidate Autoruns CSV targeting schema 6, use the
  [offline GoldenDB review workflow](references/goldendb-maintenance.md#offline-csv-review-and-repository-update):
  propose CSV updates, present them for review, and import approved additions
  locally. This branch needs no live readiness, case state, or API access; the
  live workflow below does not apply. The user can distribute the repository
  database update through a PR.

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

Targeting and case rules:

- `--target windows|linux|macos` scopes by OS when no include label is set.
- `--include-label` or `--host-label` takes precedence over OS.
- `--exclude-label` may be combined with either form.
- No OS or include label means all eligible clients.
- Case-aware commands use `--server-profile` for the Velociraptor deployment and `--engagement-id` for local storage. If the engagement id is omitted, it falls back to the server profile. Labels remain explicit and independent.

## Collection lifecycle and advanced review

For an explicitly named hunt analysis, follow the existing-hunt branch above.
Steps 2–6 below concern collection selection/lifecycle; stacking, decisions and
manual review-memory publication apply only when those operations are needed.

1. Inspect saved readiness at session start and reuse valid `engagement.json`;
   it does not expire by age. Live commands validate
   `<case-root>/<id>/engagement.json` against the current API credential, server
   fingerprint and org before querying. Use `velociraptor-engagement-setup` only
   when it is missing, invalid, or affected by connection/credential/mapping
   changes or failures, then resume the existing hunt. Reuse successful session
   analyst checks instead of repeating setup/doctor for each hunt.
2. Select the smallest artifact and parameter set that answers the question.
3. Run `hunt native check`, then `hunt native ensure` or the public `hunt run`
   wrapper. Both paths discover candidates server-wide before mutation; grouped
   runs preflight every artifact before creating the first hunt.
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
   `--profile autoruns` workflow above for general Autoruns review. Other
   artifacts stream every row Velociraptor exposes, including rows already
   available from open flows, through token-bounded transient chunks; see
   [acquisition and transport sizing](references/live-analysis.md#acquisition-and-transport-sizing).
   Default stdout is bounded text with `chat_summary`. Keep text output for
   interactive and operator-initiated runs. Use `--format json` only when an
   explicit downstream integration will parse the structured response; do not
   select JSON merely for agent convenience.
8. Rerun the same full command to rebuild from Velociraptor, or pass `--update`
   after a successful full analysis to merge flows completed since the persisted
   server cutoff. The cursor advances only after accepted analysis publication
   (validated synthesis in `full`, validated preliminary candidates in `none`):
   either a fully validated result or the grounded deterministic
   `complete_with_failures` fallback, which retains partial coverage. A failed
   chunk or hard synthesis failure leaves the prior checkpoint and cursor
   unchanged.
9. Keep live analysis in streaming mode. Use `--analysis-mode stack` when the
   question requires prevalence or structured reduction; stacking changes the
   server-side reduction, not the streamed execution model. Only flagged groups
   become drill-down items, requeried for impacted machines and original rows
   before a second AI assessment. Declared Autoruns workflows select
   their specialized streaming stacks automatically; indicators, filters, and
   decisions require explicit stacking. Without a curated signature the runtime
   derives a validated ephemeral rare-first stack; never update
   `preferred-artifacts.json`. Chat-derived `--stack-field-preference` and
   `--stack-field-guidance` inputs are advisory, and a guided selection with no
   safe result stops for operator clarification. See
   [adaptive reduction](references/live-analysis.md#adaptive-reduction).
   Do not invoke generic `--analysis-mode stack` for DetectRaptor, and analyze
   mixed DetectRaptor/Autoruns selections separately; see
   [DetectRaptor requirements](#detectraptor-requirements).
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
16. Use `hunt snapshot`, `hunt native export-results`, or
    `hunt native download-results` only when durable evidence is required.

Use the shared `analyst-agent` only as a separate read-only semantic-review lane over bounded evidence. Hunt creation, retries, stops, and analysis checkpoint updates stay with the hunt workflow.

## Reference Routing

Read a reference only before work on its branch:

- [existing-hunt-analysis.md](references/existing-hunt-analysis.md): saved review versus refresh, candidate paging, or failure recovery for an exact hunt.
- [live-analysis.md](references/live-analysis.md): stacking, filters, decisions, drill-down, closure, or acquisition diagnosis.
- [windows-hunt-orchestration.md](references/windows-hunt-orchestration.md): grouped DetectRaptor, targeted Windows hunts, exact reuse, or missing-client retry.
- [windows-live-analysis.md](references/windows-live-analysis.md): Windows path, signer, PowerShell, DLL/.NET, normalization, and drill-down controls.
- [detectraptor-analysis.md](references/detectraptor-analysis.md): DetectRaptor fleet review (shared priority, correlation, disposition, and uplift).
- [extracted-evidence-analysis.md](references/extracted-evidence-analysis.md): explicit snapshot/export/download review.
- [windows-persistence-autoruns.md](references/windows-persistence-autoruns.md): live or focused Autoruns review.
- [goldendb-maintenance.md](references/goldendb-maintenance.md): GoldenDB updates, candidate CSV review, promotion, or publication.

Contracts: [ownership matrix](../../src/vraptor/resources/contracts/velociraptor-hunting-capabilities.json),
[output and closure policy](../../src/vraptor/resources/contracts/velociraptor-persistence-policy.json),
and [full/update transport behavior](../../docs/reference/velociraptor-hunt-flow-analysis.md).

## Public Commands

### Grouped or Targeted Windows Hunt

```bash
vraptor hunt run --id IR1234 --profile detectraptor \
  --task-mode compromise-assessment --response-depth standard \
  --question "Find Windows compromise leads"

vraptor hunt run --id IR1234 --artifact Windows.Search.FileFinder \
  --env 'Glob=C:\\ProgramData\\Vendor\\beacon.dll' --question "Find the known file"
```

Add `--force-run` only when a fresh exact collection is desired after reviewing
prior-match details. `run` stores `--task-mode` and the resolved
`--response-depth` in the group manifest. A later live `analyze` inherits them
when those flags are omitted; explicit analysis flags take precedence.

If discovery returns a generic or different-IR template, review the reported
source artifact set and parameters. To create a separate current-case hunt after
explicit authorization:

```bash
vraptor hunt run --id IR1234 --artifact IG.Windows.Sysinternals.Autoruns \
  --question "Review persistence" --authorize-template-create
```

This flag never retargets or mutates the source template and never reuses its results.

### Native Cross-Platform Check and Ensure

```bash
vraptor hunt native check --investigation-id IR1234 --target linux \
  --artifact Linux.Sys.Users
vraptor hunt native ensure --investigation-id IR1234 --target linux \
  --artifact Linux.Sys.Users
```

Use native `check`/`ensure` for Linux or macOS and for one-off expert scopes.
Use `--activate-paused` to resume an exact paused hunt. Use `--force-run` to
intentionally create a new exact run.

### Status and Live Analysis

```bash
vraptor hunt status --id IR1234 --group DR-20260725T120000Z
vraptor hunt analyze --id IR1234 --group DR-20260725T120000Z
vraptor hunt analyze --id IR1234 --hunt-id H.1234 \
  --artifact DetectRaptor.Windows.Detection.Evtx
```

The ordinary command requires no chunking option. A full rerun rebuilds from
authoritative `hunt_results()`; `--update` resumes from the last successfully
published server cutoff, except detection-partitioned EVTX analysis, which
rejects `--update` and requires a full rerun. Strict `--time-after`/`--time-before`
bounds and repeatable logical `--time-field` roles filter server-side before
transport; bounded hunts require stream mode. The verified matrix, default
mappings and source-specific roles are in
[analysis-time-filter-support.md](references/analysis-time-filter-support.md).
Bounded mixed-artifact runs persist exact expressions and `complete`, `partial`,
or `unsupported` time-filter coverage; partial filtering keeps overall coverage
partial.

To use fleet-prevalence stacking explicitly:

```bash
vraptor hunt analyze --id IR1234 --hunt-id H.1234 --analysis-mode stack
```

Apply a command-line indicator or approved filter reference when needed:

```bash
vraptor hunt analyze --id IR1234 --hunt-id H.1234 --analysis-mode stack \
  --indicator 'Evidence=beacon\\.dll|rundll32' \
  --filter-reference /path/to/hunt-filters.json
```

### Optional Query Timeout

Live `hunt analyze` accepts `--query-timeout-seconds N`. The default `0` adds
no timeout ceiling. A positive integer caps each API query, including inventory,
accounting, stacks and original-row drill-downs; shorter internal timeouts still
win. It is not an overall command, AI, or collection timeout, and streamed
queries include time paused for downstream analysis capacity. The option is
rejected with `--snapshot`. See the
[query deadline contract](../../docs/reference/velociraptor-logging.md#optional-live-analysis-query-deadline).

```bash
vraptor hunt analyze --id IR1234 --hunt-id H.1234 --profile autoruns \
  --artifact IG.Windows.Sysinternals.Autoruns --query-timeout-seconds 1800
```

### Missing-Client Retry

```bash
vraptor hunt retry-missing --id IR1234 --hunt-id H.1234 \
  --after-hours 24 --max-attempts 1 --batch-size 100
```

This writes policy only. A later live analysis pass requeues only original
baseline clients with no flow. Retry state stores client IDs and attempt
timestamps, not result rows.

### Explicit Evidence Extraction and Offline Review

```bash
vraptor hunt snapshot --id IR1234 --hunt-id H.1234
vraptor hunt analyze --snapshot /path/to/snapshot.json
vraptor hunt native export-results --investigation-id IR1234 --hunt-id H.1234
vraptor hunt native download-results --investigation-id IR1234 --hunt-id H.1234
```

`hunt analyze --hunt-id` and `hunt analyze --group` never resolve
`latest.json` and never create a snapshot. Use `hunt analyze-saved` only for an
explicit existing export/download manifest.

### Stop and Verify

```bash
vraptor hunt native stop --investigation-id IR1234 --hunt-id H.1234
```

## DetectRaptor Requirements

Use the [fleet adapter](references/detectraptor-analysis.md) (recovery lanes,
concurrency, progressive publication, and report consolidation) and the shared
[DetectRaptor contract](../../docs/reference/detectraptor-analysis-contract.md).
DetectRaptor defaults to stream-only review: use accounted streaming rather than
generic stack analysis, and do not sample, generate filters, or apply
exclusions. EVTX automatically groups exact payloads only for large, materially
reducible detections, without hash equivalence or a signature-count ceiling;
group review receives the complete exact payload. Write compact uplift-review
candidates to `analysis/detectraptor_whitelist_candidates.csv`, never generated
ignore rules. Follow machine-validated priority, use prevalence only as context,
retrieve exact host rows, perform cross-artifact correlation, and require
fleet/replay validation for reusable rule-uplift proposals.

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
for checkpoint bounds, persistence classification, debug/logging controls,
recovery/reference semantics, aggregate review, and report-rendering limits
before operating those lanes. Transient source rows, prompts, model
transcripts, aggregate parts, and failed chunk payloads are not persisted by
default.

`analysis-hunt.md` is the cumulative hunt assessment and task memory. The
generic flow-analysis coordinator is its sole writer and atomically composes
generic and compact specialized state after every pass. Do not edit it directly.
A custom review that must enter the harness report persists compact
`analyst_review_memory` (step 12) with the artifact, review time, source row
count, source watermark or query hash, coverage statement, assessment,
limitations, and case-note reference. Caller-owned `assessment-hunt.md` keeps
its checkpoint provenance and coverage without modifying harness state.

`hunt-analysis-state.json` holds compact watermarks, coverage, reviewed
branches, findings, review memory, run identity, query metadata, source
identifiers, closure blockers, and the persistence manifest; ordinary result rows
are never stored as bulk evidence in state, analysis memory, or command
responses. Incompatible existing analysis files fail before processing and are
preserved: move unrelated historical files into the case reviews directory
outside the analysis tree, or correct their format/classification, then rerun.

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

## Closure Guardrails

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
- A nonzero aggregate result count with zero acquired aggregate rows fails
  closed. Never publish zero-row completion for that contradiction.
- Flow inventory and result acquisition are separate: open and unknown flows
  remain visible in target-execution coverage while any rows already exposed by
  `hunt_results()` are reviewed.

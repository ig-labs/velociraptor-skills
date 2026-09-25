# Live Hunt Analysis Loop

`--skip-ai` retains deterministic preparation and skips model execution. See the
[shared output and status contract](../../../docs/reference/analysis-skip-ai.md).


General Autoruns hunt review uses `hunt analyze --profile autoruns` with one
hunt, one Autoruns artifact and case context. It automatically writes
`analysis/autoruns_review.csv` with Category, ImagePath, LaunchString, Signer,
TotalRows and ExampleHosts; no review-path switches are required.
It materializes regex-only GoldenRules, counts/samples and deduplicates before
matching, reviews host-free stacks, and rejoins host samples only to suspicious rows. See the
[Autoruns workflow](windows-persistence-autoruns.md#dedup-ai-review-and-regex-only-goldendb).
The previous general Autoruns and counts-only test workflows are retired;
`autoruns_test` and `autoruns_dedup` are no longer valid profile names.
The generic and focused analysis controls below apply to their separate lanes.

Use this workflow for prevalence stacking, filters, decisions, indicators,
drill-down, and GoldenDB review. The ordinary `hunt analyze` path streams
aggregate `hunt_results()` through transient analyst chunks. After one full
streaming analysis—including rows Velociraptor already exposes from open
flows—`--update` can merge newly completed flows using batched
exact `source()` reads. Select this reduction explicitly with
`--analysis-mode stack`. The generic stack lane still streams: it consumes
deterministic server-side aggregate batches without a total-result limit,
token-chunks them lazily, and submits them to bounded analyst slots with
acquisition backpressure. Declared Autoruns workflows select their specialized
streaming stacks automatically. Indicators, filter references, and decisions
require explicit stacking. Both paths query Velociraptor directly, keep
ordinary rows and aggregate parts transient, and persist compact control state.

Use `--stack-max-total-rows 100` with `--analysis-mode stack` or
`--profile autoruns` to omit high-count aggregate entries from AI review. Only
counts **greater than** the threshold are excluded: 100 is reviewed, 101 is not.
The positive integer counts source occurrences (`Count` for generic stacks,
`TotalRows` for Autoruns), not distinct hosts. Autoruns defaults to 20; generic
stacking defaults to no cutoff. A positive value overrides the cutoff, and
`--stack-max-total-rows 0` disables it for either mode.
For Autoruns, selection happens in VQL after complete aggregation and before
GoldenDB matching. Excluded identities are not matched and are absent from the
residual CSV; row/group exclusion counts remain in state and reports. The full
scan and aggregation cost remains. `--stack-max-total-rows 0 --skip-ai` exports
all GoldenDB residual groups without AI. Generic stacking applies the cutoff
before AI chunking and does not change source aggregation. Generic discovery may still
sample source rows to choose stack fields. Excluded group and record counts
remain in state and reports, and review coverage stays incomplete/partial when
any groups are omitted. Threshold changes invalidate prior completion reuse.
No aggregate classification call is made when all groups are excluded.
Unsupported stream analysis rejects the switch; a failed stack-field selection
cannot silently fall back to unfiltered AI review. With `--skip-ai`, all AI
review is skipped regardless of the cutoff.

Configure analyst execution only through the root `.env` shared settings:
`AI_SKILLS_ANALYST_AGENT_ENABLED`, `AI_SKILLS_ANALYST_AGENT_MODEL`,
`AI_SKILLS_ANALYST_AGENT_TIMEOUT_SECONDS`, and
`AI_SKILLS_ANALYST_AGENT_MAX_CONCURRENCY`. Full live analysis, generic stacks,
and Autoruns stacks use the same resolved analyst specification. The hunt CLI
has no stack-specific AI enablement, model, timeout, or concurrency overrides.

## Start or Continue

Startup reads hunt metadata through `hunts(hunt_id=...)`. A complete modern
record already supplies the request, artifact list, and nonempty artifact-source
list; `hunt_info()` is then unnecessary. Sparse or legacy records retain the
fallback lookup and fill-only request-field merge.

An explicit single-hunt analysis reuses its just-discovered metadata for status
preflight when no missing-client retry was attempted. Flow status is always
queried fresh. Group analysis, successful or failed retry attempts, and ordinary
status/polling callers retain fresh metadata reads; there is no persistent cache.

```bash
dfir hunt analyze \
  --id IR1234 \
  --hunt-id H.1234 \
  --analysis-mode stack
```

Supply chat-derived field preferences when the operator wants the AI to assess
a specific composite against the transient sample:

```bash
dfir hunt analyze \
  --id IR1234 \
  --hunt-id H.1234 \
  --analysis-mode stack \
  --stack-field-preference Name \
  --stack-field-preference Exe \
  --stack-field-preference CommandLine \
  --stack-field-guidance "Use one process identity stack."
```

The JSON response contains a bounded `review_items` view. By default it returns
at most 100 items with a stable `review_id`, exact scope count, evidence hash,
query metadata, `decision_template`, and up to three clipped representative
rows. For generic stacking, only analyst-flagged groups become review items;
expected groups are covered by validated streamed-part accounting.
The aggregate AI pass receives occurrence count, distinct impacted-host count,
fleet denominator, and host prevalence. A second automatic pass requeries each
retained flagged group for impacted machine names and relevant original rows,
then returns a final provisional assessment for the command response and
`analysis-hunt.md`.
`analysis/review-items.json` contains the complete retained metadata-only queue
and live-query references without raw rows. Use `--include-review-rows` when
full transient rows are explicitly required in command JSON.

- `direct`: one in-memory review when the remaining artifact has at most 1,000
  rows and analyst-backed stacking is unavailable or the source is not using a
  stacking review strategy. Explicit analyst-backed stack analysis bypasses
  this threshold and reviews every aggregate group through transient parts. If
  dynamic stack discovery cannot select a safe pivot, an artifact that still
  fits the threshold returns to exhaustive direct review rather than stopping
  at a discovery sample.
- `pivot`: exhaustive review of one small approved scope branch.
- `signature`: one representative for an exact signature plus its exact group
  count. Completion requires a disposition and reason.
- `normalized_stack`: one representative for a normalized field stack. It is
  normally a filter-discovery or drill-down pivot. Artifact-specific guidance
  may permit direct closure when the normalized fields are sufficient and all
  required hidden-variant and hijack-risk checks are explicitly recorded.
- `drilldown`: the original projected rows and machines matching a selected
  normalized or exact stack key.
- `sample`: bounded discovery when no safe server-side pivot is defined.
- `known_bad`: priority review for a configured or command-line indicator.
- `filter_validation`: exact match count and a bounded sample for a proposed
  suppression.

Focused Autoruns scopes may be selected with `--use-case autoruns-lolbin`,
`--use-case autoruns-rmm`, or `--use-case autoruns-unverified`. They bypass
GoldenDB. LOLBin and unverified stream complete mode-specific identity stacks,
use bounded AI classification, and query exact original context for every
selected identity in the same run without detail files. RMM retains a
metadata-only review item because authorization is environment-specific.

The `autoruns` profile uses Category, ImagePath, LaunchString and Signer as
its identity and reports `TotalRows`. Its transient source export contains
`review.csv` and `stats.json`; canonical outputs are `analysis/autoruns_review.csv`,
`analysis/autoruns_potential_golden.csv`, `analysis/hunt-analysis-state.json` and
`analysis-hunt.md`. Sample hostnames are excluded from AI input and caches. Add reviewed
schema-10 CSV rules through `autoruns regex-import`; legacy exact promotion does not
apply to this workflow.

Do not write returned rows to the case unless explicit evidence extraction is
required. Review them in the current agent context. Query metadata contains a
stable `query_hash`; use server logs or explicit extraction when full VQL must
be retained.

Configured projection aliases are applied only after branch predicates. This
is required because VQL makes aliases visible to `WHERE`; an alias such as
`Detection.Name AS Detection` can shadow the source `Detection` object and
silently turn a positive-count scope into a zero-row review query.

## Adaptive Reduction

For a large artifact, the automated generic stack lane:

1. Uses the artifact-approved scope and signature when available. A curated
   signature may run at global scope.
2. Within every curated scope, streams the complete artifact-approved family signature,
   falling back to the exact signature when no family signature is configured.
3. If no curated signature is usable, queries exactly 20 deterministic rows by
   default, configurable from 10 through 20 with `--stack-discovery-rows`.
   These rows remain transient. Python calculates presence/null ratios, scalar
   types, cardinality, rendered-length bounds, nested/array flags, and bounded
   representative values.
4. Sends only those transient statistics to the configured analyst. The prompt
   treats all values as untrusted evidence and prohibits embedded instructions.
   Repeated `--stack-field-preference FIELD` values and optional bounded
   `--stack-field-guidance TEXT` are included as advisory operator intent.
   Strict line-v2 output contains an optional scope field, one to three
   signature fields, rationales, and explicit rejections, with at most three
   total dimensions. It contains field names only, never VQL.
5. Deterministically rejects unknown or unsafe names, time and record IDs,
   provenance, payloads, nested/array values, constants, sparse or excessive
   text, and mostly unique identifiers without a documented semantic exception.
   Python quotes accepted identifiers and constructs an ephemeral runtime
   profile; it never executes model-authored VQL or updates canonical policy.
6. Forms token-bounded aggregate parts only as analyst capacity becomes
   available. It constructs no complete group list or pending prompt queue.
7. Orders complete server-side groups by ascending `Count` using
   `ORDER BY Count`, so rare groups reach review first. Global scope is used
   when no safe scope field exists.
8. Computes distinct-host prevalence server-side and sends occurrence, host,
   and fleet statistics to the aggregate analyst.
9. Requeries retained high-value groups for exact impacted endpoint identities
   and relevant original rows, then sends the enriched evidence through a
   second strict line-v2 analyst pass.
10. Python owns supplied-part and row-count accounting. It validates sparse
   `FLAG` records and requires exactly one `ASSESSMENT` for every follow-up
   GroupId. One invalid result receives one retry, then the run fails closed.
11. Accounts expected groups compactly. Only notable or suspicious groups become
   live-query drill-down items.
12. Requeries flagged groups using the original server-side scope and signature
   expressions before asserting malicious activity or closure.
13. Builds filters against the original server-side Evidence expression,
   validates exact matches, applies approved filters, and reruns the probe.

If unguided discovery AI is disabled, invalid twice, or yields no safe signature,
retain the existing sample-first queue and record the fallback reason. When
operator preferences or guidance were supplied, stop with
`awaiting_stack_field_input` and a bounded `operator_question` instead of
silently selecting unrelated fields. The discovery sample never establishes
exhaustive coverage. Persist only its row count,
query/statistics/recommendation hashes, selected model and validated fields,
deterministic rejection codes, aggregate-query hash, represented rows/groups,
rare-first flag, and fallback reason. Do not persist discovery rows, prompts,
model output, or aggregate data files. This is an ephemeral runtime fallback,
not promotion into `preferred-artifacts.json`.

The default raw response budget remains 1,000 direct/sample/drill-down rows.
The 200,000-token value is a per-part ceiling for automated streaming, not a
whole-stack ceiling. Generic aggregate source groups have no total-result cap.
At most 100 flagged groups are retained per pass; an overflow is explicit and
keeps coverage incomplete. After those groups are decided, the next pass
excludes their accounting keys and continues safely.

Use [windows-live-analysis.md](windows-live-analysis.md) for Windows path,
signer, PowerShell, DLL/.NET, and drill-down guidance.

Query metadata distinguishes:

- `first_row_oversized`: one bounded row still exceeds the per-item ceiling;
- `token_limit_reached`: the current query returned rows, then exhausted the
  shared pass budget;
- `shared_budget_exhausted`: a later branch cannot fit in the remaining shared
  budget; no empty review item is emitted; and
- a positive-count query returning no rows without a budget outcome: profile
  scope/signature mismatch, which fails closed.

The analyzer does not page an unordered `LIMIT`. Scope and signature aggregate
queries use deterministic ordering and consume every streamed batch. The
manifest records group count, represented source rows, stack SHA-256, transient
part count, analyst concurrency, retries, flagged counts, and any compact-output
overflow. A represented-row mismatch fails closed.

## Normalization and Drill-Down

Review responses include configured normalizers and allow
`normalization_candidates`. A candidate records the field, normalization kind,
scope, and rationale; it is not applied automatically. Validate it in the
artifact profile so the profile-hash change resets affected watermarks.

A normalized-stack decision may request original records:

```json
{
  "review_id": "review-example",
  "complete": true,
  "disposition": "suspicious",
  "reason": "Normalized path and entry require host-level validation.",
  "drilldown": {
    "reason": "Retrieve original entries, launch strings, hashes, and machines."
  }
}
```

The next pass runs the exact scope and normalized stack predicate against the
original hunt rows. Complete the drill-down only when it is exhaustive. A
truncated drill-down remains incomplete and requires tighter scope or explicit
evidence extraction.

Platform-specific closure requirements belong in the relevant platform or
artifact reference. For Windows Autoruns, use
[windows-persistence-autoruns.md](windows-persistence-autoruns.md).

## Record Decisions

Create a temporary decision file outside the hunt output:

```json
{
  "reviews": [
    {
      "review_id": "review-example",
      "complete": true,
      "disposition": "expected",
      "reason": "Expected management-agent activity.",
      "findings": [
        {
          "summary": "Expected management-agent execution only."
        }
      ],
      "filters": [
        {
          "scope": {
            "Detection": "Managed service execution"
          },
          "conditions": [
            {
              "field": "Evidence",
              "operator": "regex",
              "pattern": "approved-agent-path"
            }
          ],
          "reason": "Approved management agent path observed in this detection."
        }
      ]
    }
  ]
}
```

Only fields listed under the artifact profile's `review.filter_fields` may be
filtered. DetectRaptor EVTX does not participate in this decision/filter lane;
its automatic direct/exact-stack workflow applies no exclusions. Every generic
filter requires a concrete reason.
New filters are always stored as `candidate`, even if a submitted decision
claims a stronger status.

Filters use an AND-conjoined `conditions` list. A single-field filter still
uses a one-item list; use compound filters when one field is too broad:

```json
{
  "scope": {
    "Category": "Logon"
  },
  "conditions": [
    {
      "field": "ImagePath",
      "operator": "regex",
      "pattern": "(?i)^c:\\\\windows\\\\system32\\\\securityhealthsystray\\.exe$"
    },
    {
      "field": "Signer",
      "operator": "regex",
      "pattern": "(?i)^\\(verified\\).*microsoft"
    }
  ],
  "reason": "noise-reduction"
}
```

All conditions must match. The category scope and each condition are compiled
into the server-side VQL predicate. Known-bad predicates take precedence over
approved filters.

Rerun with the decisions:

```bash
dfir hunt analyze \
  --id IR1234 \
  --hunt-id H.1234 \
  --analysis-mode stack \
  --decisions /case-work/IR1234/H.1234-decisions.json
```

## Validate Filters

A candidate generates a `filter_validation` item before it can suppress
anything. Review the exact match count and returned bounded sample, then
explicitly approve or retire it:

```json
{
  "reviews": [
    {
      "review_id": "review-filter-validation",
      "complete": true,
      "filter_status": "case-approved",
      "findings": []
    }
  ]
}
```

Use `filter_status: retired` when the expression is too broad, unsafe,
redundant, or has no useful matches. A zero-match filter cannot be approved.
Approval also requires at least one reviewable sampled row; an oversized row
cannot authorize an unseen suppression. Approved filters are applied on the
next pass. A known-bad match is never hidden merely because an approved
suppression also matches it.

## Non-Exhaustive Reviews

Do not mark a sampled or token-truncated review complete unless the decision
also proposes a filter that can make the next query narrower. A
non-exhaustive completion with no filter fails closed.

If the branch is suspicious or too heterogeneous for a safe suppression:

1. submit `complete: false` and retain the finding;
2. increase the bounded row/token limits or define a safer profile pivot; or
3. explicitly snapshot/export the branch for exhaustive evidence review.

The engine does not silently page the same unordered `LIMIT` sample and claim
coverage.

## Persistence and Output Details

These controls apply to generic and focused live review. The `autoruns`
profile uses the separate source-export, AI-cache and report contract linked above.

### Checkpoints, diagnostics, and references

`hunt-analysis-state.json` is the schema-7 checkpoint for default and specialized
live analysis. It stores one
compact cumulative result, its last successful server cutoff, current coverage,
stable aliases still referenced by the checkpoint, and at most 20 bounded run
records. While running, `active_analysis` reports acquired and emitted rows and
chunks, active analyst slots, accepted/failed chunks, heartbeat, and whether
acquisition is paused by backpressure. Transient source rows, prompts, model
transcripts, source/segment/chunk manifests, and failed chunk payloads are not
persisted. Run records retain at most 20 compact failed-attempt diagnostics with
chunk identity and counts, failure category, clipped error, and value-free
validation codes. The first failed attempt remains visible when a retry succeeds.
During execution these records are written immediately under `active_analysis`;
at completion they are retained in the bounded `runs` entry.
For targeted diagnosis on any live or snapshot hunt-analysis lane, add `--debug`. It atomically retains schema-3 value-free provider selection, configuration provenance, request-option presence, stage timing, usage, retries, HTTP status/error classification, validation failures, synthesis status, and the current operation id in `analysis/hunt-analysis-validation-debug.json`, capped at 512 attempt records and 1 MiB. Safe provider request IDs, known internal field names, and valid source references may be retained; unknown strings are hashed. Debug mode never enables prompt, model-output, raw-row, raw-stderr, raw-provider-payload, event-log, or runtime-file persistence. A later non-debug run preserves the last debug file but marks its reference as not current.
All case-bound hunt commands append to the human-readable `<case-root>/<id>/logs/velociraptor-progress.log`; its `op-v1-*` id is shared with `DFIR-STATUS` and final structured output. Concurrent commands interleave safely under distinct operation ids and an adjacent mode-`0600` lock file serializes append and rotation with a bounded wait; logging failure never fails the hunt. Parallel task lifecycle events are unthrottled, API activity from worker threads remains correlated, and every operation ends with compact query/model/task/retry/row/batch/rotation/drop counts. INFO records bounded single-line sanitized server text and automatic numeric progress. Text may contain evidence-sensitive hostnames, usernames, paths, or VQL; recognized API keys, tokens, passwords, secrets, authorization values, URL credentials, PEM material, and configured credential values are redacted. Message length and SHA-256 are not logged. Queries have local `q-NNNN` ids and purposes; `response_rows` counts response records while `matched_rows` reports interpreted analysis counts. Unbounded queries, disk spills, and server silence are warned; silence is not proof of a remote stall. Unchanged queries receive five-minute reminders after initial wait/silence events. Set `VELO_PROGRESS_FILE_DEBUG=true`, or use analysis `--debug`, for batch/transport and provider detail. Use `logs status --id <id>` to check local process identity and retained operation overlaps; old logs without PID identity report `UNKNOWN`. Use `dfir logs show --id <id>` or `dfir logs follow --id <id>` with optional `--operation`, `--level`, `--since`, `--scope`, `--hunt-id`, and `--task-id` filters. Hunt status uses `hunt_flows()` metadata for aggregate collected-row counts rather than scanning `hunt_results()` with `count()`; per-artifact counts are emitted only for a single selected artifact, while multi-artifact counts remain `aggregate_only`.
The analyst prompt exposes `_SourceRef` as reference-only metadata. Analysts
return canonical ATT&CK tactic names and one exact reference per `EVIDENCE` or
`CONTEXT` line, never evidence values or field names. Python hydrates the
authoritative row after validation. Final prose fields consume embedded tabs; fixed structural fields remain strict. Invalid output receives one bounded retry
and is never mechanically rewritten into an accepted result.
A failed chunk or hard synthesis failure leaves the prior checkpoint and cursor
unchanged. When every chunk is accepted but final narrative synthesis fails
deterministic validation, publish the grounded `complete_with_failures` fallback
with partial coverage and retain EVTX completed-detection recovery so the same
compatible full command retries synthesis without reanalysis. Retire recovery
only after accepted synthesis; rebuild unsupported state from Velociraptor.
The state does not store bulk result rows or duplicate cumulative finding copies. It also
records `review_scope` as `managed_collection` or `ad_hoc_review`. Specialized
stacking, decision, filter, and GoldenDB metadata is stored under the bounded
`specialized_analysis` member; there is no separate `analysis/state.json` lane.

Evidence references use `Sxxxx-R<number>`. For full analysis the alias identifies
the hunt/artifact aggregate; for updates it identifies one deterministic batched
exact-source acquisition. Row provenance retains the actual client and Flow.
Aliases referenced by the current checkpoint remain stable; superseded
unreferenced aliases are pruned. Unsupported local state rebuilds from the
authoritative hunt and requires a successful full analysis before `--update`
is available.

### Aggregate review and report rendering

The hunt synthesis manager consolidates semantically equivalent observations and selects representative rows. Model-facing workers use strict line-v2 records; Python owns task, question, chunk, status, and coverage metadata and rejects model-generated JSON.
`analysis-hunt.md` groups references under findings,
includes hostname with client ID when available, and shows bounded examples. When a
selected row contains materially useful long-form content—commonly EVTXHunter or
PowerShell—the runtime writes `analysis/finding-evidence.md` with deduplicated full
projected representative for rows sharing the same hydrated field set. This generic
mechanism is available to any artifact. Full-row Markdown is capped at 2,000,000
characters; omitted groups remain authoritative in Velociraptor. The primary
report and command response remain compact and link to the supplement.

Generic stack analysis consumes deterministic server-side aggregate queries
without a total-result `LIMIT`. Aggregate batches are token-chunked lazily and
submitted directly to the bounded analyst pool; full analyst occupancy pauses
query consumption. The analyst must attest every group in each part. Expected
groups are accounted compactly, while notable or suspicious groups retain a
live-query pivot for original-row drill-down. At most 100 flagged groups are
retained in one pass. If more are flagged, coverage remains incomplete and the
next decisions pass excludes accounted groups before rerunning. Prompts, model
responses, aggregate rows, and part manifests remain transient.

Stack-analysis human output groups exact repeated context, caps representative
context at 10 groups and 10 endpoints per group, clips displayed field values
to 320 characters, and sends compact specialized finding summaries through a
validated semantic manager. Repeated accounting tables are capped at 100 rows
and narrative collections at 50 items before the hard output guard. Accounting,
finding, filter, and normalization sections use independently bounded renderers.
Generic finding summaries retain every compact finding and source group, render the
first 20 findings in detail, and index every additional finding in one line. The chat
summary has a 32,000-character guard. Canonical Markdown remains under
the persistence policy's compact-report guard and preserves the next action.
Exact Autoruns rows remain authoritative
in Velociraptor and are streamed through bounded drill-down validation; command
JSON and state do not duplicate those rows. Compact state retains bounded named endpoints, persistence variants, omission counts, and query references; chat and canonical reports share a renderer and label legacy count-only host context.

The default command response returns at most 100 review items and three clipped
representative rows per item. `analysis/review-items.json` is the complete
metadata-only decision manifest and points each item back to its authoritative
Velociraptor live query without persisting raw rows. Use
`--include-review-rows` only when full transient review rows are explicitly
needed in command JSON. The manifest is the maintained review contract and
retains compact queue metadata and authoritative query pointers.

## Repeat Until Closed

Continue reviewing and resubmitting decisions until:

- response `status` is `complete`;
- `result_review_coverage` is `complete`;
- `target_execution_coverage` is `complete`;
- combined response `coverage` is `complete`;
- `review_item_count` is zero; and
- the summary reports no unreviewed rows at the recorded watermark.

Coverage is `provisional` while the hunt is still running. If the saved target
baseline is unavailable, target execution coverage is `unknown` and the
analyzer reports `review_complete_coverage_unknown` rather than hunt-wide
completion. A fully reviewed current result set from a non-terminal hunt reports
`review_complete_source_non_terminal`; it does not claim final hunt execution
coverage. If row counts or analysis inputs change, prior reviewed-scope
watermarks are cleared so new rows cannot remain hidden. Unsupported local
state is rebuilt from authoritative Velociraptor results.

The generic durable outputs are:

- `<hunt_id>/analysis-hunt.md`: cumulative findings, row accounting, filter story,
  coverage, specialized reduction, stacking, bounded representative context,
  next action, and workflow memory across all analysis passes;
- `<hunt_id>/analysis/filters.json`: candidate, approved, retired, and reusable
  filter records with reasons and validation metadata; omitted, and any stale
  empty file removed, when the normal lane has no filter records;
- `<hunt_id>/analysis/review-items.json`: complete metadata-only review queue
  with authoritative Velociraptor query references and no raw rows;
- `<hunt_id>/analysis/filters-<use-case>.json`: filter history scoped only to
  that focused use case, written only when that lane has filter records;
- `<hunt_id>/analysis/hunt-analysis-state.json`: schema-7 default and specialized
  watermarks, hashes, bounded findings, query ledger, and completion state.

The generic flow-analysis coordinator is the sole writer of `analysis-hunt.md`.
It atomically composes any generic flow-analysis state with bounded specialized
state; specialized and focused runs request a coordinator refresh and do not
write sibling summary Markdown. `filters.json` remains the normal/general
filter lane when records exist; empty filter lanes do not create files. A
focused run does not overwrite another focused use case's files.
`hunt-analysis-state.json` remains shared compact control state and records the
canonical report and control-file paths for each mode.

Generic flow evidence uses source-qualified `Sxxxx-R<number>` references. The
alias binds hunt, organization, client, Flow, artifact, and result source; the
suffix is the actual one-based row in that source. Logical segmentation and
token chunking do not change it. Unsupported local state is rebuilt from
authoritative Velociraptor results.

`analysis-hunt.md` and `autoruns_chat_summary` contain bounded representative
groups, not copies of every exact context row. Exact repeats are consolidated,
specialized findings receive validated semantic consolidation, display values
and endpoints are capped, and omitted counts point back to authoritative live
Velociraptor queries. Consolidation state records compact
model/timing/cache/fallback telemetry.
Accounting, finding, filter, and normalization sections are independently
bounded; tables are capped at 100 rows and narrative lists at 50 items before the
hard guard. Canonical Markdown is subject to the compact-report persistence
guard; chat Markdown is guarded at 32,000 characters. Command JSON returns compact
workflow counts and paths without duplicating transient suspicious context or a
second raw context-detail payload.

`review-items.json` is the maintained review-queue contract. Review queues
remain metadata-only files for explicit consumers.

When an analyst completes a bounded live review outside the structured
`review_id` decision loop, persist a compact `analyst_review_memory` record in
`analysis/hunt-analysis-state.json` instead of editing `analysis-hunt.md`
directly. Record the
artifact, review time, source row count, source query hash, coverage at the
watermark, detailed case-note reference, assessment, and limitations. The
renderer includes this durable memory on future passes. This memory does not
replace deterministic row accounting: pending structured review items and
coverage blockers remain visible until decisions or validated filters account
for them.

These files contain no raw review rows. Use `snapshot` only for explicit
immutable evidence extraction or development.

The Autoruns aggregate-file exception is limited to the attested
`analysis/autoruns_potential_golden.csv` candidate set. Residual stacks,
classification subsets, exact suspicious context, scope rows, model responses,
and chunk files remain transient; `--debug` emits bounded value-free provider,
timing, retry, validation, and synthesis metadata only.

For noise-heavy inventories, optimize filters rather than writing one benign
narrative per stack group. Validate a candidate filter against the complete
hunt, approve it, then let the next pass apply it before stacking. Preserve the
filter ID, match count, scope, and conditions; reserve detailed findings for
residual or suspicious evidence.

After review, the matching use case's filter file can be passed to
`--filter-reference` only for that same mode.
Its top-level `filters` list contains only active approved records;
`case_filters` retains the complete candidate and retirement history.

## Reuse and Known-Bad Search

Load approved reusable registries with repeated `--filter-reference` arguments
or `VELO_HUNT_FILTER_PATHS`. A reusable registry has this shape:

```json
{
  "schema_version": 2,
  "filters": [
    {
      "artifact": "Artifact.Example",
      "scope": {
        "Category": "Managed service execution"
      },
      "conditions": [
        {
          "field": "Evidence",
          "operator": "regex",
          "pattern": "approved-agent-path"
        }
      ],
      "reason": "Approved management agent path.",
      "status": "promoted",
      "owner": "detection-engineering",
      "review_after": "2026-12-31"
    }
  ]
}
```

Use `--indicator '[FIELD=]REGEX'` for a known-bad priority search. Repeat every
indicator on every decisions pass; changing the indicator set invalidates prior
coverage. If the regex contains `=`, always provide an explicit approved field,
for example `--indicator 'Evidence=https?://[^ ]+\\?id='`.

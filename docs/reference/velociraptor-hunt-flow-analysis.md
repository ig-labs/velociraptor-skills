# Velociraptor Hunt Flow Analysis

## Document metadata

- Created: `2026-08-13`
- Last reviewed: `2026-08-27`

## Purpose

`analysis/hunt-analysis-state.json` is a compact publication checkpoint for the
default live hunt analyzer. Velociraptor remains authoritative for result rows;
the file is not an evidence export or a chunk-retry database.

This document describes the default streaming live hunt-analysis path implemented
by `flow_analysis.py`, `flow_analysis_runtime.py`,
`flow_analysis_coordinator.py`, and `hunt_workflow.py`. Explicit
`--analysis-mode stack` and declared Autoruns workflows use the separate
live-analysis reduction workflow and do not support `--update`. Generic
stacking nevertheless uses the same bounded execution principle: complete
server-side aggregate queries are consumed in streamed batches and token parts
are submitted only when analyst capacity is available. Indicators, filter
references, and decisions require stacking.
DetectRaptor EVTX uses an automatic per-detection planner in the normal stream
lane. An optional `--detection-regex` narrows discovery, but every resolved query
also uses exact detection equality. Large detections run an exhaustive
exact-payload census before model work; small detections and immaterial censuses
use direct review with complete evidence. Exact groups use script-block payloads or a serialized
message/event fallback, never hash equivalence. Empty or missing values remain
explicit keys. Model-facing exact groups use the normal live-hunt CSV and
`reference-line-v3` contract. `Payload` is the final CSV column; standard CSV
quoting preserves commas, quotes, literal tabs, and embedded CR/LF content. The
same sparse response may emit `UPLIFT` only for a high-confidence reusable
benign group, with `global` or `site` scope and a trailing free-text reason.
Python copies the complete source payload into the final column of
`analysis/detectraptor_whitelist_candidates.csv`; the model does not repeat it.
Ordinary clean groups remain silent and no candidate is automatically applied.
The
deprecated `detectraptor-stack` mode value routes to this same planner and
canonical state.

EVTX detections execute in isolated recovery lanes. A retryable read-only gRPC
reset reconnects the API channel and replays only the active detection from its
beginning; partial rows, chunks, and model results from the failed attempt are
discarded. Completed detections are represented by compact accepted results and
are reused while an interrupted run resumes. The unfinished-run recovery member
is retired on successful publication so a later ordinary full command still
rebuilds from authoritative Velociraptor rows.
Pending detection lanes execute concurrently through one scope-owned dynamic
queue. The queue applies a global model/token ceiling and fair lane dispatch;
each producer waits only for its own futures. The detection-partition ceiling
derives from `AI_SKILLS_ANALYST_AGENT_MAX_CONCURRENCY`, so one value bounds model
requests and concurrent Velociraptor partition queries.
Census and selected-context calls run outside the event loop. Peer failures are
collected after successful lanes checkpoint, and published result order follows
discovery rather than completion order.
Recovery and report records expose value-free per-detection census, analysis,
partition-synthesis, selected-context, and total elapsed seconds, plus local
submitted/completed/abandoned chunk counts. Active and final state also records
the shared analysis concurrency limit, peak active partitions, reused/reanalysed partitions,
query deadline, and bounded retry diagnostics. They do not persist prompts or raw
payloads; the separately attested whitelist-candidate CSV is the only optional
full-payload output. `analysis-hunt.md` consolidates equivalent reportable
exact-payload assessments and includes occurrence, endpoint, observation-range,
variant, and bounded representative-event context. The separate interesting-
context ledger retains every hydrated event. If cumulative synthesis raises or
returns an unpublishable result, the progressive Markdown and DetectRaptor
ledgers are atomically terminalized as failed while the prior successful
checkpoint and completed-partition recovery remain unchanged.
The canonical context ledger, whitelist CSV, and report are mirrored at each
publication under `analysis/runs/<analysis-id>/<run-id>/`. Existing legacy
canonical files are archived before replacement. The canonical paths continue
to represent the latest run. Before an incompatible analysis identity rebuilds
canonical state, the complete prior state is also copied to its prior
analysis/run directory so accepted partition recovery is not silently lost.

## Operator workflow

1. Run or exactly reuse the required Velociraptor hunt.
2. Use `hunt status` to inspect target execution and result availability.
3. Run a full analysis to establish or replace the local checkpoint:

   ```bash
   ./dfir hunt analyze \
     --id IR1234 \
     --hunt-id H.1234
   ```

4. If more hosts finish later, either rerun the full command or request an
   incremental update:

   ```bash
   ./dfir hunt analyze \
     --id IR1234 \
     --hunt-id H.1234 \
     --update
   ```

5. Treat `analysis-hunt.md` as generated analysis memory and Velociraptor as the
   source of truth. Use `snapshot`, `export-results`, or `download-results` only
   when durable evidence extraction is explicitly required.

A full run is the normal path. It gives a fresh analysis of the current hunt
result set with query count based primarily on selected artifacts, not host
count. An update is an optimization for adding newly completed flows without
re-reading the complete hunt result set.

## Full analysis pipeline

The default command performs the following sequence:

1. Query Velociraptor for a server-side cutoff time.
2. Enumerate the complete `hunt_flows(hunt_id=..., basic_info=FALSE)` inventory
   using deterministic pages. This inventory supplies flow state, completion
   accounting, result artifacts, client/Flow identifiers, and update activity
   times.
3. Resolve the selected result artifacts. With no explicit `--artifact`, use
   the result artifacts reported by the hunt inventory.
4. For each selected artifact, execute one aggregate query:

   ```vql
   SELECT *
   FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)
   WHERE (
     EventTime > AnalysisTimeAfter
     AND EventTime < AnalysisTimeBefore
   )
   ```

   The `WHERE` clause is present only for a bounded run and uses the selected
   profile's trusted time expressions. Multiple expressions use OR semantics.
   With no time bounds, or when an artifact has no known requested/default time
   field, the query remains unfiltered. The aggregate is the authoritative result
   set for a full run. Every in-scope row Velociraptor exposes is reviewed,
   including rows already available from open or running flows. Flow state does
   not gate full-run acquisition.
5. Stream the complete query result through bounded gRPC response packets.
6. Project artifact-approved fields, add client/Flow provenance, and allocate
   stable `Sxxxx-R<number>` evidence references.

Aggregate `hunt_results()` rows do not always contain client or Flow IDs. The
coordinator resolves a unique client from returned hostname/FQDN against the
current client inventory, then resolves a Flow ID only when the hunt inventory
contains exactly one Flow for that client. Ambiguous identifiers remain empty;
the hunt ID is never substituted as a Flow ID. Update `source()` rows carry
their exact descriptor-provided client and Flow IDs.

7. Form deterministic 5,000-row logical segments locally. An acquisition-ordered
   token chunker carries only one partial compatible chunk across segment
   boundaries and emits it as soon as the next unit would exceed the evidence
   token ceiling.
8. Submit emitted chunks directly to available analyst slots. No complete hunt
   plan, 100,000-row acquisition window, pending prompt queue, or complete CSV
   dictionary is constructed. When every configured slot is occupied, result
   acquisition pauses until a validated outcome frees a slot.
9. Synthesize all accepted chunk results into one cumulative hunt result.
10. Atomically publish schema-7 state and regenerate `analysis-hunt.md` after
    either fully validated synthesis or the grounded deterministic
    `complete_with_failures` fallback. Fallback publication remains explicitly
    partial and preserves its bounded synthesis diagnostic.

Every completed or provisional command response also includes a non-empty
bounded Markdown `chat_summary`. Normal streaming derives it from the compact
Python-owned synthesis result. Specialized Autoruns and generic-stack paths use
their bounded workflow summaries, and grouped hunt responses combine per-hunt
summaries under the same 32,000-character guard. Callers must surface this value
to the operator. Default stdout is bounded text and interactive or
operator-initiated runs must retain it. Use `--format json` only when an explicit
downstream integration will parse the unchanged structured response.

Analysis emits flushed, one-line `DFIR-STATUS v=1` markers on stderr. Streamed
analysis reports acquisition, chunk, retry, active-agent, synthesis, and publishing
state. Specialized lanes report inventory, GoldenDB, stack, analyst-review,
consolidation, and publishing phases. A bounded heartbeat covers silent provider
waits. Markers never include source rows, prompts, model output, or provider bodies;
`--no-progress` disables them for callers that capture stderr without draining it.

For `A` selected non-EVTX artifacts, normal acquisition uses approximately `A`
`hunt_results()` VQL calls, plus inventory, cutoff, and optional client-identity
queries. If `DetectRaptor.Windows.Detection.Evtx` is selected, replace its one
query with at least `1 + D`: one complete in-scope `GROUP BY Detection.Name`
discovery query and one direct or exact-group query for each of the `D`
discovered detections. A large detection adds one census query, and reportable
exact groups add bounded context-hydration queries. The same
optional time predicate is included in discovery and each detection query. It
does not issue one result query per endpoint. Discovery also returns evidence
size metrics. A detection is large when it has at least 1,000 rows or its total
evidence size estimates at least 10 direct chunks. The exact census is material
when it removes at least 100 model rows and 5 percent. Every census group is
streamed rare-first without a signature ceiling. Census failure or immaterial
reduction falls back to direct review. No AI-generated filter or exclusion is
executed. Source rows must be at least the discovery baseline; the greater-than
case permits normal hunt growth. Every exact group is reviewed once through the
normal live-hunt CSV chunk workflow with its complete trailing payload, count,
and first/last timestamps. Standard CSV quoting preserves commas, tabs, quotes,
and embedded newlines. The normal sparse `reference-line-v3` response returns
only reportable findings; clean groups require no per-group record. Only source
references returned in findings are batch-queried for original timestamps and
machines, without a second AI pass.

## Incremental update pipeline

`--update` is accepted only by the streaming live path and requires a
successful schema-7 full checkpoint. Detection-partitioned
`DetectRaptor.Windows.Detection.Evtx` analysis rejects `--update` and requires a
full rerun. Other artifacts perform the following sequence:

1. Read `inventory.last_successful_check_at` from the prior checkpoint.
2. Capture a new server-side cutoff and enumerate the current hunt-flow
   inventory.
3. Select successful terminal flows whose activity time falls after the prior
   cutoff minus a five-minute overlap and at or before the new cutoff. A flow
   without a usable activity time is conservatively included.
4. Expand each selected flow into its matching artifact result sources.
5. Sort sources deterministically by artifact, client ID, and Flow ID.
6. Partition each artifact into batches of at most 250 source descriptors.
7. Execute one server-side `foreach` query per batch. Each query invokes exact
   `source()` reads on the server:

   ```vql
   SELECT *
   FROM foreach(
     row=parse_json_array(data=SourcesJson),
     query={
       SELECT *
       FROM source(
         client_id=ClientId,
         flow_id=FlowId,
         artifact=ArtifactName)
       WHERE (
         EventTime > AnalysisTimeAfter
         AND EventTime < AnalysisTimeBefore
       )
     })
   ```

   As in a full run, the `WHERE` clause is omitted when no bounds are requested.
8. Apply the same projection, defensive local time validation,
   evidence-reference, transient chunk-analysis, and validation pipeline used
   by a full run.
9. Synthesize the prior compact checkpoint together with the newly accepted
   results.
10. Merge obvious exact duplicate findings and publish a new checkpoint when
    synthesis is fully validated or produces the grounded deterministic
    `complete_with_failures` fallback. The latter remains partial.

For `N_a` newly selected flows for artifact `a`, the expected result-query count
is:

```text
sum over artifacts a of ceil(N_a / 250)
```

The 250-flow limit controls how many exact source descriptors are submitted in
one VQL call. It does not limit the number of result rows returned by that call.

## Transport and row batching

Full `hunt_results()` acquisition and batched update `source()` acquisition use
the same `_iter_query_segments()` transport implementation.

For each VQL call:

- `query_batches_with_metadata()` starts with gRPC `max_row=5,000`;
- `max_row` is a preferred streamed-response packet size, not a total-result
  limit;
- all response packets are consumed until the query is exhausted;
- a gRPC message-size or `RESOURCE_EXHAUSTED` failure retries the query using
  `2,500`, `1,000`, `500`, `100`, `10`, and finally `1` row per packet;
- rows already yielded by a failed larger-packet attempt are skipped when the
  query restarts, avoiding duplicate local processing; and
- if one row still exceeds the gRPC receive limit at `max_row=1`, acquisition
  fails closed.

There are therefore two independent limits during an update:

| Layer | Limit | Purpose |
| --- | ---: | --- |
| VQL source batch | 250 flows per artifact | Bound server-side `foreach(source())` work and API-call count |
| gRPC response packet | Starts at 5,000 rows | Bound transport message size while streaming the complete batch result |
| Logical segment | 5,000 rows | Give deterministic local row boundaries before token planning |
| Analyst chunk | Token-policy dependent | Keep model input within the configured evidence ceiling |
| Active analyst pool | `AI_SKILLS_ANALYST_AGENT_MAX_CONCURRENCY` | Bound simultaneous prompts and apply acquisition backpressure |

Neither the 250-flow batch nor `max_row` truncates the result set.

## Demand-driven memory lifecycle

Default hunt analysis does not plan or enqueue the complete workload. One
hunt-scoped dynamic async scheduler routes chunks into artifact-named lanes and
reuses one runner/client. The producer must acquire one of the global
`max_concurrency + 1` credits before requesting and constructing another chunk.
It therefore holds approximately one projected 5,000-row logical segment, one
partial token chunk, and at most the credited active/queued prompt-validation
payloads across every artifact lane. A final partial chunk is submitted at
end-of-stream so no acquired row is omitted.

Validation and its configured correction retries (two extra attempts by default)
execute inside the same queue worker. See [analysis correction settings](analysis-recovery.md).
Model output uses the strict reference-line-v3 grammar: workers begin with
`RESULT`, emit only finding/context/limitation/follow-up records, and end with
`END`. Synthesis emits only the five report sections and `END`. Python owns
artifact, chunk, row, task, question, status, and coverage metadata. Specialized
consolidation, generic-stack, and Autoruns lanes use similarly bounded tab records
instead of model-generated JSON. In every analyst protocol, a declared final
prose field consumes the remainder of its line, including embedded tabs. Fixed
identity, reference, classification, and accounting fields remain positional and
strict. General-analysis context text has no protocol-specific character limit;
existing specialized-lane reason limits remain unchanged.
After each terminal worker result, its prompt, CSV evidence, source-row
validation map, and provenance hydration map are explicitly released. Only one
compact accepted result and a small emitted-chunk accounting record remain for
final synthesis. Accepted results are ordered by deterministic chunk ID before
synthesis so worker completion order cannot change the cumulative input.
If a chunk remains failed after its bounded retry, the producer stops requesting
new rows, already active work is drained, and publication fails closed.

Chunk progress callbacks are attached to the shared scheduler only while chunk
work is executing. They are restored before the scheduler is reused for final
synthesis or closed, so a late queue-status notification cannot overwrite a
terminal checkpoint with stale `chunk_analysis` state. After shared scheduler
and runner cleanup, the public workflow reads the state back and verifies the
schema, checkpoint, run identity, row and chunk counts, coverage, absence of
`active_analysis`, and current debug hash when `--debug` is enabled. A mismatch
fails closed and terminalizes a still-running record.

The limits are row- and token-based rather than a strict resident-byte ceiling.
One unusually wide row can still require substantial memory, but transport
fallback reduces gRPC packets to one row and fails closed if that single row
cannot be received. Increasing hunt row volume no longer creates a whole-hunt
raw-row or prompt backlog.

## Checkpoint contents

Schema 7 persists the following compact state:

- identity: schema, scope, analysis ID, creation/update times and review scope;
- `inventory`: last successful server cutoff, last full-analysis time, current
  flow-state counts, target/completed machine counts, completion ratio and the
  sub-70% warning;
- `source_aliases`: stable aliases still used by the published checkpoint plus
  aliases for the most recent acquisition. Superseded unreferenced batch aliases
  are pruned;
- `checkpoint`: one compact cumulative result, generation, analysis method,
  artifact list, cumulative row count, last-update row count and result hash;
- `coverage`: result review, target execution and overall status;
- `runs`: a deterministic ring of at most 20 bounded operational records,
  including at most five clipped synthesis failure diagnostics and 20 failed
  chunk-attempt diagnostics per run. Chunk diagnostics retain only chunk ID,
  ordinal, artifact, row/token counts, attempt, category, clipped error and
  value-free validation codes; recovered first attempts remain visible; and
- `active_analysis`: local phase, heartbeat, acquired/emitted/accepted/failed
  counters, submitted/completed/abandoned scheduler counts, active-agent count,
  source-exhaustion/stop state, and acquisition-backpressure status while an
  analysis process is active, plus immediately persisted bounded attempt
  diagnostics when a chunk fails or retries; and
- optional `detectraptor_recovery` while an EVTX run is unfinished: one
  versioned contract and compact detection records containing stable partition
  identity, stage/status/attempt, row and group counts, query hashes, bounded
  transport status metadata, identity-free compact accepted results, selected
  group IDs, and classification counts; and
- optional paths/policy metadata needed to reproduce the report; and
- `specialized_analysis`, including Autoruns source provenance and compact
  classification references into `analysis/autoruns_review.csv`. Its canonical
  report and candidate CSV are reproducible without VQL or AI calls.

It never persists source rows, hostnames, payloads, prompts, model transcripts, per-segment state,
per-chunk evidence state, failed chunk payloads, or duplicate top-level copies
named `hunt_result`, `findings`, or `analysis_summary`. The command response
and Markdown report are derived from `checkpoint.result`.

The EVTX recovery contract binds the hunt, artifact, safe server/organization
identity, requested time scope and detection regex, profile identity, discovery
query, projection/query contract, stack-key version, analysis route, resolved
execution route, and output
contract. A mismatch rebuilds recovery. A running hunt may grow: a completed
detection remains reusable only when its acquired row count is still at least
the current discovery count; otherwise that detection is replayed and the run
remains provisional.

`active_analysis` describes local analysis, not Velociraptor hunt execution. It
moves through `inventory_complete`, `acquiring_results`, `chunk_analysis`,
`reconciling_accounting`, `cumulative_synthesis`, and `publishing`. Throttled
progress writes are atomic and never replace the checkpoint or advance the
update cursor. Failed attempts bypass the normal throttle so their compact
diagnostic is durable before retry. After scheduler cleanup, any otherwise
unhandled exception terminalizes a still-running record as `failed`, retaining
only its stage and exception class. A stale running record is converted to a
bounded `interrupted` run when the next analysis acquires the directory lock.

### Validation debug mode

`hunt analyze --debug` is available for live full/update, DetectRaptor stream,
generic stack, Autoruns general/focused, group, and offline snapshot analysis.
It atomically replaces
`analysis/hunt-analysis-validation-debug.json` with the latest explicit debug
run. Schema-2 manifests are capped at 512 attempt records and 1 MiB, with total
and truncated counts. Every provider-backed lane retains safe resolved
provider/model/protocol and field sources, request-option presence, stage timing,
usage, retries, HTTP status/error code/parameter, provider request ID, recovered
first-attempt errors, structured tactic/reference diagnostics, response hashes,
and synthesis status. Specialized lanes additionally retain bounded value-free
artifact status, counts, hashes, and Autoruns candidate publication status.

Valid `Sxxxx-R<number>` references may be stored. Unknown tactic strings and
malformed references are hashed because they may contain copied evidence values.
Prompts, source rows, model output, raw provider payloads, raw stderr, event logs,
and runtime files remain transient by default. The separate explicit
`--debug-chunk-prompts [N]` option retains standard chunk prompts, their returned
AI responses/correction retries and a provenance manifest outside the analysis
tree; see [prompt exports](chunk-prompt-debug.md).
It does not change the contents of this value-free validation manifest.
`last_validation_debug` in the compact state
identifies the debug run, path, final status, timestamp, and file hash. A later
non-debug run does not rewrite the last explicit debug manifest and marks its
state reference `current_run: false`.

## Acquisition and lifecycle

### Full analysis (default)

1. Capture a server-side cutoff and enumerate `hunt_flows(...,
   basic_info=FALSE)` for coverage.
2. Stream `hunt_results(hunt_id=..., artifact=...)` once for each selected
   artifact.
3. Assign deterministic `Sxxxx-Rn` references and stream acquisition-ordered,
   token-bounded chunks directly into free analyst slots. The coordinator
   records every emitted chunk ID and validates every analyst result. The model
   returns only canonical ATT&CK tactic names, concise finding/context text, and
   exact one-reference-per-line `EVIDENCE` or `CONTEXT` records. It never returns
   raw values or field names. Python hydrates authoritative rows and provenance
   after validation. Invalid output receives the configured bounded correction attempts and
   is never mechanically rewritten into an accepted result.
4. If any chunk or hard cumulative synthesis fails, do not publish a new
   checkpoint.
5. On fully validated synthesis, atomically replace the checkpoint and advance
   the inventory cursor with complete result-review coverage. If final narrative
   validation fails after every chunk was accepted, publish the grounded
   deterministic fallback, advance the cursor, and keep result-review and
   overall coverage partial. A later full run replaces, rather than appends to,
   cumulative content.

### Explicit update

`hunt analyze --update` requires an existing successful schema-7 full
checkpoint and is unavailable for detection-partitioned EVTX analysis. For
other artifacts, it selects successful terminal flows active after
`last_successful_check_at` with a five-minute overlap, groups exact
`source(client_id, flow_id, artifact)` reads into server-side `foreach` batches
of at most 250 flows per artifact, and synthesizes the prior checkpoint with the
new validated results. The overlap may rediscover rows observed before a flow
finished. Exact duplicate findings are merged; Velociraptor remains the evidence
source of truth.

The cursor advances only after every transient chunk is accepted and cumulative
synthesis is either fully validated or reduced to the grounded deterministic
`complete_with_failures` fallback. A hard synthesis failure leaves the old
checkpoint and cursor authoritative, so the next explicit update re-reads the
same window. Failed and provisional run records retain bounded status, counts,
and clipped synthesis errors, never model output or evidence.

## Duplicate behavior

`hunt_results()` can expose rows from a flow before that flow becomes terminal.
The later update overlap may consequently rediscover those rows through exact
`source()` acquisition. This is acceptable for threat hunting: the cumulative
synthesis merges findings, and deterministic exact consolidation combines
findings with the same normalized summary, confidence, and domains while
deduplicating identical evidence records.

Distinct grounded context statements may cite the same source row. Python
hydrates the same authoritative row for each accepted reference; conflicting
provenance remains ambiguous and exact duplicates remain deduplicated.

This is finding-level consolidation, not guaranteed event-level deduplication.
Velociraptor retains the authoritative rows, and analysts should not interpret
the cumulative finding count as a unique-event count unless the artifact itself
provides a suitable stable event identity.

## Failure and publication boundary

The workflow is failure-closed:

- any rejected or failed transient analyst chunk prevents publication;
- failed chunk evidence and model output are not written to state;
- a hard cumulative synthesis failure prevents publication;
- the previous successful checkpoint and update cursor remain unchanged;
- a subsequent full run rebuilds from `hunt_results()`; and
- a subsequent update reselects the same overlapped time window because the
  cursor did not advance.

For EVTX, safe transport recovery is narrower than ordinary message-size
fallback. `UNAVAILABLE` replays the complete active semantic unit after channel
reconnect. `DEADLINE_EXCEEDED` is retried only before rows are received.
Authentication, authorization, invalid VQL, `CANCELLED`, and semantic validation
failures are not transport retries. Census and grouped payload review replay one
detection. Selected timestamp/machine hydration uses bounded batches and never
causes a second semantic review.
Each DetectRaptor VQL call has a 900-second default deadline, configurable with
the positive integer `AI_SKILLS_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS`. Retryable
read-only failures receive at most four total attempts with reconnect backoffs
of 2, 5, and 15 seconds. All attempts are bounded. The published checkpoint remains unchanged until all
required detections and final synthesis are publishable.

When all transient chunks are accepted but final narrative synthesis fails
deterministic validation, the runtime's grounded fallback is publishable as
`complete_with_failures`. It retains validated findings and references, records
partial result-review and overall coverage, exposes the synthesis limitation in
`analysis-hunt.md`, and advances the cursor because the current rows have been
reviewed. Synthesis prompts permit only `FINDING` and `EVIDENCE` records in the
findings section and require each synthesized tactic to be supported by its
cited input evidence. Structured retry diagnostics identify unsupported records
and evidence-unsupported tactics without persisting model output or evidence
values. For detection-partitioned EVTX, a degraded synthesis publication retains
the compact completed-partition recovery checkpoint. Repeating the same
compatible full command retries synthesis without requerying or reanalysing
completed detections. Only fully accepted synthesis retires that recovery state.

Only a bounded run record containing method, timestamps, cutoff, row/chunk
counts, status, and at most five 2,048-character synthesis errors may be added.
It is diagnostic metadata, not a retry queue, and contains no model output or
evidence rows.

## Coverage and limitations

- Result review describes the rows successfully reviewed, not machine execution
  coverage. Managed hunts remain partial when target execution is partial.
- If fewer than 70% of baseline machines have successful terminal flows, state,
  command JSON and the report carry an explicit warning.
- The five-minute overlap prevents timestamp-boundary misses but can cause
  duplicate analysis. Only obvious exact finding duplicates are merged; hunting
  is not an exact event-deduplication system.
- Flow active times missing from server inventory are conservatively included in
  an update window.
- Alias and checkpoint growth is proportional to retained findings and current
  acquisition sources, not raw rows. Optional `finding-evidence.md` remains a
  separately bounded, manager-selected context product.
- Every write is a sorted atomic JSON replacement, so update cost remains linear
  in the compact checkpoint size.

## Checkpoint recovery

Unsupported or mismatched local state is discarded and rebuilt from
authoritative Velociraptor results by the next full analysis. `--update` is
available only after a successful schema-7 full checkpoint and is unavailable
for detection-partitioned EVTX analysis.

## Validation

`tests/test_flow_analysis.py` covers:

- unchanged full rerun size and stable evidence references;
- changed-source update selection and cursor advancement;
- failed update followed by successful reprocessing;
- grounded `complete_with_failures` publication with partial coverage;
- degraded DetectRaptor synthesis recovery and completed-partition reuse;
- hard synthesis failure with bounded diagnostics and no report publication;
- exact duplicate-finding merge;
- 250-flow server batching, including 10,000-flow query-count scaling;
- the sub-70% completion warning;
- unsupported-state rebuild behavior and deterministic atomic writes; and
- a generated 100-source, 100,000-row, multi-revision fixture;
- a lazy 100,000-row-equivalent workload proving producer consumption and
  simultaneous prompts never exceed configured analyst concurrency;
- cross-segment token packing and final-partial-chunk coverage; and
- retry acceptance with explicit release of prompt and validation payloads; and
- shared-scheduler callback restoration and terminal checkpoint verification
  after scheduler shutdown;
- detection-scoped replay after a reset before or during a response, without
  duplicate accepted rows;
- compatible completed-detection reuse and incompatible-state rebuild;
- exact-stack restart from accepted initial analysis, detection-scoped rescan,
  and group-scoped representative retry;
- non-retryable transport failure and retry-exhaustion attribution; and
- recovery-state rejection of raw evidence, prompts, and model transcripts.

The tested bound is independent of row volume:

```text
64 KiB + 1 KiB/retained source alias + 4 KiB/finding
```

No live case file is read or modified by these tests or measurements.

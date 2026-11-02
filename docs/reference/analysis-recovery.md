# Analysis correction and recovery

Analysis correction is distinct from provider/transport retry. A provider call
must succeed before an output-validation defect can trigger correction. Failed
authentication, cancellation, deterministic token-limit failures and exhausted
transport retries do not receive another call from the correction loop.

The shared analyst TOML supports:

```toml
[analysis_defaults]
validation_correction_attempts = 2
synthesis_correction_attempts = 2
```

Each value counts **extra attempts**, so the defaults permit three total attempts
per chunk or synthesis stage. The range is 0–5; zero disables correction. Non-empty
`AI_SKILLS_ANALYST_AGENT_VALIDATION_CORRECTION_ATTEMPTS` and
`AI_SKILLS_ANALYST_AGENT_SYNTHESIS_CORRECTION_ATTEMPTS` override TOML values.
`vraptor ai config` reports effective values and provenance. Corrections remain
inside the existing scheduler and model token/deadline guards. Provider retries
continue to use `AI_SKILLS_ANALYST_AGENT_MAX_RETRIES` separately.

## Resume failed host analysis

```bash
vraptor analyze --id IR1234 --client C.1234abcd \
  --request-id REQUEST_ID --question 'Was malicious execution observed?' \
  --synthesis full --retry-failed
```

Use the original question, analysis settings, time bounds and case connection.
The exact request is required; the option cannot be combined with reset, force,
preparation or report-only rebuilding. It never recollects evidence.
Generated continuation commands preserve `--synthesis none|full`. When recovering
final synthesis, keep `--synthesis full` (also the default). Explicit
`--synthesis none` skips final review; `--skip-ai` disables all model work.

Accepted artifacts are reused after source and report-hash verification. Failed
artifacts reacquire their existing flow rows once; accepted chunks are restored
from reference-only decisions, revalidated and hydrated against those rows. Only
failed chunks and their dependent synthesis are sent to the model. Source,
question, configuration or prompt changes invalidate reuse. A failed final host
review reuses accepted artifact candidates. Legacy runs without these chunk
checkpoints must review the failed artifact again.

`--reset-artifact` and `--reset-analysis` still explicitly discard accepted work.
Ordinary reruns keep terminal failed artifacts held; use `--retry-failed` to
resume them, or waive reviewed chunks as described below. Final synthesis can also be resumed by rerunning the saved request.
For a synthesis-only failure with accepted checkpoints, `vraptor summarize
--checkpoint /path/to/request-analysis.json` validates the retained inputs and
runs only final synthesis, without querying flows or rerunning artifact analysis.
Both forms review the saved request's scope. `--reset-artifact` invalidates an
artifact's accepted work; it does not narrow a multi-artifact request to that artifact.

## Repair a chunk after its correction attempts

When a chunk's last correction attempt still fails output validation, the chunk
is recorded first (below, with repair `pending`), then gets one repair call in
the same run. It goes to the same model with the original chunk prompt
unchanged, the last answer's defects (`DEFECT`, with line numbers), the earlier
answers' defects (`EARLIER_DEFECT`, without line numbers), and the last answer
quoted between fences as untrusted, line-numbered (`L<n>`) data. The reply must
start with 1-5 lines `DIAGNOSIS<TAB>cause<TAB>location<TAB>explanation`, where
the cause is a defect code or one of `reference_confusion`, `record_grammar`,
`format_drift`, `context_link`, `tactic_or_confidence`, `missing_evidence`,
`instruction_conflict`, `output_too_long`, `ambiguous_evidence`, `other`, and the
location is `L<n>`, a source reference of the chunk's rows, or `-`; any other
location is recorded as `-`. A
`REPAIRED` line and one complete answer follow, or `UNREPAIRABLE<TAB>cause`.

The answer passes the same validator as any other attempt; the diagnosis never
decides acceptance. A repaired chunk is published and labelled in the chunk
coverage line (`2/2 chunks accepted (1 after AI repair)`), the artifact
limitations and the chat summary, for example ``Artifact chunk 2/2 rows 4-7
(S0001-R4..S0003-R3) accepted after AI repair (format_drift at L1); verify these
rows in Velociraptor. Key `Artifact:artifact-task-1-chunk-1`.`` The line adds
``The rejected answers had 2 finding(s); the accepted answer has 1.`` when the
repaired answer reports fewer findings. The label is kept with the chunk
checkpoint, so a resumed run still shows it. Hunt labels name the reference
range and streaming chunk ID instead of a row position, and are added to the
published hunt result after synthesis, with `coverage.repaired_chunks`.

Only validation failures are repaired: provider failures, cancellation, input
and output token limits are not. At most 4 repair calls are made per run,
whether or not they succeed; set `--chunk-repair-limit N` (0-20, 0 disables) on
`analyze`, `collect analyze` or `hunt analyze`, or
`AI_SKILLS_ANALYST_AGENT_CHUNK_REPAIR_LIMIT`. Chunks past the cap stay failed
with `AI repair was skipped: per-run repair limit reached`. The continuation
command keeps the flag. The repair prompt is checked against the input token
limit before it is sent: an answer that does not fit is cut to the lines the
defects cite (at most 120,000 characters are quoted in any case), and if even
that does not fit the repair is skipped (`the repair prompt would exceed the
input limit`) without using a slot. A failed repair call adds one attempt to the
entry; the entry's final category stays the validation failure and the repair
call's own category (for example `timeout`) is kept in its `repair` object.

## Review chunks that fail every attempt

A chunk that still fails after its correction and provider retry budgets is
recorded in a durable, value-free review file:

- host: `analysis/failed-chunks.json` under the request, scoped to client and request;
- hunt: `hunt-failed-chunks.json` beside `hunt-analysis-state.json`, scoped to hunt and org.

Host entries are keyed `ARTIFACT:TASK_ID`; hunt entries use the streaming chunk
ID. Each entry holds the artifact and flow or hunt ID, the chunk position (row
range, chunk index/count, first and last `Sxxxx-R<number>` reference), the
input hash (`input_sha256`, the SHA-256 of the JSON-encoded rendered chunk
prompt), attempts used and the configured budget, per-attempt category, defect
codes, timestamps and response hashes, a failure count across runs, and the next
commands. A `repair` object holds the repair outcome (`pending`, `repaired`,
`failed`, `unrepairable` or `skipped`), cause codes and locations, finding counts
before and after, and a SHA-256 of the explanations; the explanations
themselves are kept only in the explicit raw exports (failed-chunk evidence and
`--debug-chunk-prompts`). Reruns merge into the file; the record written before
a repair call and the result of that call count as one failure, and any other
record, including one after an interrupted repair, counts as a new failure. A later accepted chunk marks its entry `resolved` with `resolution`
`{"by": "acceptance"}`, or `{"by": "repair", ...}` after a repair call, and a host re-plan that no longer has
the chunk marks it `superseded`. At most 500 entries are kept, dropping closed
entries first, with an omitted count. The file is `compact_state`:
prompts, model output, validator free text and source values are excluded.

The host result, artifact report and chat summary name each failed chunk, for
example ``Artifact chunk 71/71 rows 6901-7000 (S0003-R6901..S0003-R7000) failed
after 3 attempts: validation_failed; invalid_reference``, report
`Chunk coverage: 70/71 chunks accepted`, and give the resume command. Inspect the
referenced rows in Velociraptor, then choose one action:

```bash
# Retry: accepted chunks are reused; only failed chunks are sent.
vraptor analyze --id IR1234 --client C.1234abcd --request-id REQUEST_ID \
  --question 'Was malicious execution observed?' --retry-failed

# Accept the gap after manual review (repeat the key option per chunk).
vraptor analyze --id IR1234 --client C.1234abcd --request-id REQUEST_ID \
  --question 'Was malicious execution observed?' \
  --waive-failed-chunk 'Artifact:artifact-task-1-chunk-70' \
  --waive-reason 'Rows reviewed manually in Velociraptor'
```

`--waive-failed-chunk KEY` accepts a recorded key or unique task ID, requires
`--waive-reason` (1-500 characters) and implies `--retry-failed`. A waived chunk
is not analysed: the artifact publishes its accepted chunks as
`complete_with_failures`, the waived rows and reason are passed to synthesis as a
coverage gap, and summaries show `waived by operator, not analysed: REASON`. The
entry records the reason, time and input hash; the waiver lapses when the
rendered chunk changes (question, configuration or prompt). Changed source rows
re-plan the chunk under a new key and mark the old entry `superseded`. A lapsed
chunk is sent again; if it fails, the entry is `failed` again, its decision gains
`lapsed_at`, and summaries add `An earlier waiver lapsed: the chunk input
changed.` Review the rows again before a new waiver. Use
`--retry-waived` to revoke the request's waivers and send those chunks again. An
artifact with no accepted chunk still fails. `--reset-artifact NAME` discards the
artifact's accepted chunks instead.

Hunt analysis remains fail-closed and has no chunk-level resume or waiver. Its
error names the record file and chunk IDs, and the run record carries
`failed_chunks_file` and `failed_chunk_ids`; rerun the same command after review.
Hunt chunks get the same repair call. Their record is written when the analysis
run ends, and a run with repaired chunks lists them in `repaired_chunk_ids`. A
failed DetectRaptor EVTX partition chunk ends the run with `failure_stage`
`detectraptor_partition` and the same error, record and run fields; the rerun
reviews that partition again and reuses completed partitions. Specialized
generic stack and Autoruns reviews (live `hunt analyze` stack and Autoruns
workflows, and `--profile autoruns`) keep their one-retry part review with no
repair call or `hunt-failed-chunks.json` entry: a failed stack part fails the
run, and a failed Autoruns review is recorded as a failed AI review status.

To inspect the raw material, add `--keep-failed-chunk-evidence` to `analyze`,
`collect analyze` or live `hunt analyze`. Only chunks that fail every attempt,
including those a repair call then recovered, are exported with the repair
prompt and reply, under `<case-root>/<id>/debug/failed-chunks/<UTC timestamp>-<suffix>/`
as `failed-NNN.attempt-NNN.prompt.txt`, `.response.txt` and `.error.txt` with a
`manifest.json`. Files are mode `0600` in `0700` directories. This is an explicit
`interoperability_export` containing evidence and untrusted model output; the
review entry references it by path and SHA-256, with `failure` set to the
`failure_count` it was exported for. A later failure without the option keeps
that reference; only a new export replaces it. The `next` commands do not repeat
the option: add it again to export the next failure. Remove the export explicitly
when no longer needed; the reference is not removed with it.

## Troubleshooting and retention

`FINDING` confidence accepts only `low`, `medium`, or `high`; chunk and synthesis
validators normalize surrounding whitespace and casing. Confidence measures
evidence certainty, separately from report priority. Priority-only labels such as
`critical` are rejected, as are numeric scores and unknown labels; no confidence
is inferred or silently substituted. `invalid_confidence` diagnostics include the
allowed values and a safe reason code. Recognized priority-only labels can be
retained as `received`; arbitrary rejected text is excluded from diagnostics.

Every host analysis writes `analysis/analysis-diagnostics.json` under its request.
It records stage/task identity, attempts, provider category, elapsed time,
affected chunk row ranges, structured validator defects, allowed references and
response hashes. Up to 200 task records are retained, prioritizing failures, with
an explicit omitted count. The normal result and report include failed stages,
the diagnostic path and a shell-quoted resume command. Model output, provider
bodies, credentials and source values are excluded. `--debug` adds the existing
provider diagnostics; `--debug-chunk-prompts` explicitly retains evidence-bearing
prompts/responses.

Synthesis distinguishes candidate evidence references from accepted context
references. A context-only row cannot be promoted to `EVIDENCE`, and a candidate
row cannot be emitted as `CONTEXT` unless it was also accepted as context.
Downgraded candidates use `DISPOSITION`; Python creates their lead/context rows.
Wrong-role, unknown-source and wrong-candidate errors include structured defects
and bounded allowed references in correction prompts and diagnostics. If there
are no accepted context references, `RELEVANT_CONTEXT` must contain `None.`.
References are never guessed, silently reassigned or dropped to make review pass.

Supported-candidate mapping errors distinguish `missing_mapped_finding` from
`mapped_finding_evidence_mismatch`. The latter includes the candidate ID, output
finding ID, selected disposition references, missing evidence references and the
allowed intersection of candidate evidence with that output finding. Every
selected disposition reference must appear as an `EVIDENCE` record under the same
output finding ID. Merged findings include the union of selected references from
their supported candidate dispositions; candidate rows are never silently added.

`summarize` writes a separate `synthesis-diagnostics.json` beside its checkpoint.
This is the latest synthesis invocation, including cache hits, not a replacement
for the original `analysis-diagnostics.json`. It records operation ID, provider,
model, timestamps, status, bounded provider-call timing and per-attempt validation
diagnostics. It retains at most 200 task/call records, seven correction attempts
per task and 50 defects/references per diagnostic list; omissions are counted.
No raw source values, response bodies or credentials are retained. The file is
updated before dispatch and after each call so an interrupted run is identifiable.
Cache hits show zero model calls. JSON and text output expose the diagnostics path.
Cache hits regenerate the derived summary using current reporting limits without
changing the accepted checkpoint or calling a model. Diagnostic identifiers are
restricted to protocol references and known vocabulary; arbitrary model-supplied
IDs and labels are excluded even when they contain only letters or spaces.
Checkpoint conflicts preserve the changed checkpoint and retain failure diagnostics.

`artifact-recovery/*.json` retains one current generation of accepted compact
chunk decisions per artifact, with hashes and no copied row fields. Request
checkpoints retain accepted artifact candidates, plans, report hashes and final
dispositions, permitting recovery after switching requests. Current host state
and `analysis-host.md` remain atomically replaced derived views. Request switching
or schema mismatch no longer creates `previous-analysis/state-*` snapshots.
Existing historical snapshots and standalone `run_analyst_agent --replace`
bundles are unaffected. Finder `.DS_Store` metadata is ignored by tree validation.

Artifact reports distinguish review completion over exposed rows from collection
completion. Final review checks the evidence-to-claim link, tactics, confidence
and benign explanations, and cannot promote confidence beyond supporting input
candidates. Deterministic checks enforce references and confidence bounds;
semantic accuracy still requires model qualification. Exact normalized duplicate
limitations are removed, while the final reviewer is instructed to consolidate
equivalent prose without losing distinct coverage gaps.

## Offline validation

```bash
.venv/bin/python -m pytest -q tests/test_analysis_recovery.py tests/test_failed_chunk_review.py tests/test_host_final_review.py tests/test_synthesis_reference_recovery.py tests/test_saved_synthesis_diagnostics.py tests/test_analysis_operator_status.py tests/test_agent_analysis_defaults.py tests/core/test_core_collection_analysis_integration.py tests/core/test_core_host_analysis_state.py
```

Synthetic tests cover correction budgets, terminal failures, failed-chunk reuse,
failed-chunk records, in-run repair and its cap, waivers, opt-in failed-chunk evidence,
source/configuration invalidation, corruption, request switching, retained
diagnostics, confidence validation, coverage labels and atomic state publication.

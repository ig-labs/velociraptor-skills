# Preliminary analysis and optional synthesis

Host, collection and live hunt analysis accept `--synthesis none|full`.
The CLI default is `none` for host, collection and live hunt analysis. Calling
analysts review the returned candidates. Use `--synthesis full` explicitly when
the harness should write the final assessment.
The switch affects only this invocation; it does not change saved AI settings.

| Mode | Model work | Result |
| --- | --- | --- |
| `none` | Direct artifact or chunk analysis; specialized classification still runs | Validated preliminary candidates, selected evidence references, context and coverage. No artifact or scope synthesis. |
| `full` | Analysis plus required artifact and host/hunt synthesis | Existing standalone report and final-review behavior. |
| `--skip-ai` | No model calls | Deterministic preparation only; it takes precedence over synthesis selection. |

Snapshot and saved-export preparation remain preparation-only workflows. Selecting
`full` on those paths does not introduce model review. Use live source analysis or
a retained accepted analysis checkpoint for AI synthesis.

```sh
vraptor analyze --id IR1234 --client C.EXAMPLE --flow F.EXAMPLE --synthesis none
vraptor analyze --id IR1234 --hunt H.EXAMPLE --synthesis none
```

One fitting artifact uses one analysis call. Larger artifacts use the existing
deterministic chunks and shared concurrency limit. Multiple artifacts retain
their separate provenance and candidate namespaces; `none` performs no semantic
merge across artifacts. The caller correlates candidates by host, user, time and
evidence, and distinguishes malicious activity, security observations and context.
Source-qualified references remain essential because row 1 can occur in many
artifacts, flows and hosts.

`analysis_status` describes accepted analysis coverage. `review_status=not_requested`
means no final synthesis was requested, even when analysis is complete. Zero
candidates are not a benign verdict. Failed sources, chunks, omitted context and
target-execution gaps remain explicit. A failed hunt leaves its prior cursor and
published checkpoint intact; accepted partial candidates are separately retrievable.

## Retrieve candidates without inference

```sh
vraptor analysis-results --id IR1234 --client C.EXAMPLE --request-id REQUEST_ID --limit 25
vraptor analysis-results --id IR1234 --hunt H.EXAMPLE --artifact Windows.System.Pslist --offset 25
vraptor analysis-results --checkpoint /path/to/request-analysis.json --candidate A0001:F1
vraptor analysis-results --checkpoint /path/to/request-analysis.json --reference S0001-R27
```

Retrieval supports exact artifact, host/client, candidate and reference filters.
It reports total, matching, returned and undisplayed candidates plus continuation
offsets. `--limit` accepts 1–200, but byte budgets can shorten a page. Each candidate
shows at most ten evidence rows; use `--candidate` with `--evidence-offset` or an
exact `--reference` to continue. Context has its own `--context-offset`. Large
field values are explicitly marked as previews; use source-native evidence
retrieval for complete values. Filtering and pagination do not change saved
coverage or imply that undisplayed records were reviewed by the caller.

DetectRaptor retains its existing separate context ledger and payload persistence
rules. Candidate output links that ledger; reduced checkpoint fields are not the
complete event. Specialized Autoruns/stack paths retain their native candidate
reports and classification state; the generic saved-result commands require a
host request or streaming-hunt checkpoint.

## Synthesize saved analysis only

```sh
vraptor summarize --id IR1234 --client C.EXAMPLE --request-id REQUEST_ID
vraptor summarize --id IR1234 --hunt H.EXAMPLE --reasoning-effort medium
vraptor summarize --checkpoint /path/to/request-analysis.json --force-synthesis
```

This command validates saved candidates and their integrity, runs only scope
synthesis, and writes `synthesis-summary.md` beside the checkpoint. It does not
query Velociraptor, recollect, rerun chunks, advance hunt cursors or replace the
original analysis report. The summary and its input fingerprint are cached in
the existing checkpoint. An identical repeat uses zero model calls. The cache
depends on accepted evidence, question, analysis policy, model/route, reasoning,
limits and contract version. A changed review setting reruns only synthesis.
`--force-synthesis` bypasses this summary cache. Old hunt checkpoints lacking
accepted candidates fail explicitly rather than silently reanalysing evidence.

Padding variants such as `S1-R01` are repaired locally only when they uniquely
identify the existing `S0001-R1`. Duplicate disposition references are collapsed.
Unknown sources, ambiguous identities and references belonging to a different
candidate remain validation failures, with bounded received/allowed diagnostics.

## Validation

Synthetic call-count checks cover one or multiple artifacts and direct or chunked
analysis. For C chunks across A chunked artifacts, preliminary host analysis uses
C calls; full analysis uses C + A + 1, excluding correction/transport retries.
Single-chunk artifacts need no artifact synthesis. Saved-summary cache hits use
zero calls. These are call-count guarantees, not live latency measurements.

```sh
.venv/bin/python -m pytest -q tests/test_synthesis_modes.py tests/test_flow_analysis.py tests/test_host_final_review.py tests/test_collection_analysis_runtime.py
```

## Caller assessment files

After caller review, write `systems/<host>/assessment-host.md` for a host or
`hunts/<hunt-id>/assessment-hunt.md` for a hunt under the case directory. These
are caller-owned assessments; `analysis-host.md` and `analysis-hunt.md` remain
harness-owned outputs and may be regenerated. Do not overwrite harness reports
or change harness review status to imply that an external review ran there.

Record reviewer identity, review time, original question/scope, exact request or
hunt IDs, source checkpoint paths and hashes, acquisition dates, coverage gaps,
reviewed conclusions, rejected or corrected candidate claims, enrichment and
next actions. Mark partial coverage explicitly. Recheck source fingerprints
before reusing an assessment; later harness runs do not update it automatically.
Update the caller assessment after reviewing new evidence. Avoid `final` in the
filename because a completed review can retain unresolved leads.

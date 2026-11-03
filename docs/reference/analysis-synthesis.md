# Preliminary analysis and optional synthesis

Host, collection and live hunt analysis accept `--synthesis none|full`.
The CLI default is `full` for host, collection and live hunt analysis. The harness
performs final review and writes its analysis report unless `--synthesis none`
explicitly disables synthesis. In `none` mode, calling analysts review the returned
preliminary candidates; artifact/chunk analysis still uses AI. `--skip-ai` disables
all model work, including synthesis, regardless of this setting. Full synthesis does
not create the caller-owned `assessment-host.md` or `assessment-hunt.md`.
The switch affects only this invocation; it does not change saved AI settings.

| Mode | Model work | Result |
| --- | --- | --- |
| `none` | Direct artifact or chunk analysis; specialized classification still runs | Validated preliminary candidates, selected evidence references, context and coverage. No artifact or scope synthesis. |
| `full` | Analysis plus required artifact and host/hunt synthesis | Existing standalone report and final-review behavior. |
| `--skip-ai` | No model calls | Deterministic preparation only; it takes precedence over synthesis selection. |

Snapshot and saved-export preparation remain preparation-only workflows. Selecting
`full` on those paths does not introduce model review. Use live source analysis or
a retained accepted analysis checkpoint for AI synthesis.

For full analysis, omit the switch. To request preliminary candidates explicitly:

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
the existing checkpoint. An identical repeat uses zero model calls and refreshes
`synthesis-summary.md` using the current reporting settings. The cache
depends on accepted evidence, question, analysis policy, model/route, reasoning,
limits and contract version. A changed review setting reruns only synthesis.
`--force-synthesis` bypasses this summary cache. Old hunt checkpoints lacking
accepted candidates fail explicitly rather than silently reanalysing evidence.

Padding variants such as `S1-R01` are repaired locally only when they uniquely
identify the existing `S0001-R1`. Duplicate disposition references are collapsed.
Unknown sources, ambiguous identities and references belonging to a different
candidate remain validation failures, with bounded received/allowed diagnostics.
Synthesis prompts distinguish evidence from context references and list the
context references visible after projection. `DISPOSITION` references must
belong to that exact candidate. Downgraded candidates need no duplicate `CONTEXT`
record: Python produces their context from the validated disposition. Correction
attempts receive the rejected record type, reference and allowed alternatives;
exhausted validation still leaves the final assessment failed and candidates intact.
Supported dispositions must map to an existing output finding and select only
candidate references also present under that finding's `EVIDENCE` records. Missing
finding IDs and mismatched evidence produce separate correction defects. Saved
synthesis writes latest-run metadata and bounded attempts to
`synthesis-diagnostics.json`, including failed, interrupted and cached invocations;
the original artifact analysis diagnostics remain unchanged.

## Validation

For generic host analysis with C chunks across A chunked artifacts, preliminary
analysis uses C calls; full analysis uses C + A + 1, excluding correction/transport
retries. Single-chunk artifacts need no artifact synthesis. Specialized routes
can have additional classification passes; hunt scope synthesis can reuse a
single accepted artifact without another call. Saved-summary cache hits use zero
calls. These counts describe the tested paths, not live latency or usage estimates.

```sh
.venv/bin/python -m pytest -q tests/test_synthesis_modes.py tests/test_flow_analysis.py tests/test_host_final_review.py tests/test_collection_analysis_runtime.py
```

## Caller assessment files

| File | Owner and purpose |
| --- | --- |
| `analysis-host.md` / `analysis-hunt.md` | Harness-generated analysis, with review and coverage status. |
| `synthesis-summary.md` | Harness review of saved accepted candidates, created by `summarize`. |
| `assessment-host.md` / `assessment-hunt.md` | Caller-reviewed conclusions and cross-artifact correlation. |

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

To start a fresh assessment from processed evidence:

1. Select the exact request/hunt checkpoint and inspect its review and coverage
   status. Use `analysis-results` for bounded candidate retrieval as needed.
2. Review the linked artifact results, correlate claims and references, and
   retain uncertainty and unresolved leads. Do not recollect or reset analysis
   merely to write an assessment.
3. Write the assessment with the provenance above. When a fresh revision is
   requested and an assessment already exists, preserve it as a dated revision
   before replacing the current file.

An assessment can retain partial coverage; it must not imply that missing evidence
was reviewed. `summarize` and `reports render` do not perform this caller workflow.

Use the shared [reporting policy](reporting-policy.md) for finding priority,
display budgets and omission counts. Priority is distinct from confidence. When
reducing detail, higher-priority findings displace lower-priority detailed entries;
retain the displaced entries in the findings index and preserve source references.
`reports render` can rebuild a derived report from a retained checkpoint without
another analysis call. It does not update caller assessments automatically.

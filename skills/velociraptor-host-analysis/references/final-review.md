# Final host review

## Purpose and inputs

Artifact/chunk results are candidates until final review validates. With
`--synthesis none`, the calling analyst owns this review and correlation; the
harness reports `review_status=not_requested`. With `--synthesis full`, this
document defines the mandatory harness review. The full-mode requirement
applies to a single artifact and single chunk. Multi-artifact host synthesis is
itself the final review; artifact lanes do not run independent host reviews.
Chunked artifacts in full mode retain artifact synthesis before final review.

The reviewer receives the original question, selected task mode, response depth,
profile/objectives, candidate IDs, accepted summaries, bounded exact selected
source fields/context, and Python-owned coverage, failures and reduction/omission
accounting. Missing reduction metadata is unavailable, not zero reduction.
Existing prompt/token limits apply; an oversized review fails closed. Full rows,
ordinary evidence, prompts and raw model responses remain transient. No new
Velociraptor query is needed to review accepted references.

## Reporting threshold

For incident response and host forensics, supported findings must affect case
scope, hypotheses, chronology, impact, containment or recovery. A standalone hunt
or compromise assessment may retain broader security observations when relevant
to its question. Consider plausible administrative and benign explanations without
automatically declaring an entry benign.

GoldenDB mismatch, execution-policy bypass, RMM presence, missing files and
unverified signatures alone establish neither suspiciousness nor incident
relevance. Keep presence, configured persistence, execution, unauthorized activity
and compromise distinct. Do not invent evidence or infer absence from incomplete
coverage.

## Disposition protocol

Use the existing synthesis story, adding `DISPOSITIONS` immediately before `END`.
Emit one tab-separated record for every input candidate, including omissions:

```text
DISPOSITIONS
DISPOSITION	A0001:F1	supported_finding	M1	S0001-R5	Corroborated execution affects containment.
DISPOSITION	A0001:F2	investigative_lead	-	S0001-R6	Resolve authorization and file identity.
DISPOSITION	A0001:F3	relevant_context	-	S0001-R7	Configured support agent explains the registration.
DISPOSITION	A0001:F4	omit	-	S0001-R8	Missing target alone has no established incident relevance.
END
```

Each candidate needs a disposition, concise rationale and exact candidate source
references. Separate multiple references with commas. Supported candidates map to
an output `FINDING` and its cited evidence. Other dispositions use `-`; Python
renders leads/context separately from supported findings. `None.` is valid only
when no candidates exist. A valid review may retain zero supported findings.

Python rejects unknown, duplicate or missing candidates, unavailable or wrong
candidate references, invalid dispositions, empty rationales, dangling mappings,
and output findings/evidence without supported candidates. Existing tactic and
source-provenance validation remains in force. Semantic judgments remain the AI
reviewer's responsibility; synthetic tests validate the protocol and application,
not live-model detection accuracy.

## Publication, failure and resume

The final assessment, material limitations and up to five prioritized bounded
follow-ups must agree with the dispositions. Python attaches coverage and derives
finding counts from the final findings. Markdown, chat summary, request checkpoint
and host state use these results. Compact `final_review` provenance retains every
candidate-to-disposition mapping and source references. Per-artifact reports show
the corresponding final findings, leads and context rather than the original
candidate findings with an added caveat.

Reviewed request reports use a content-hash suffix and are written before the
state pointer changes. Existing checkpoint reports are never overwritten, so an
interrupted publication cannot invalidate accepted artifact reuse. Identical
review output reuses the same report file; current host report filenames remain
stable.

The host artifact entry's `result` is the publication projection. Its separate
`accepted_result`, labeled `provisional_candidates`, preserves accepted artifact
analysis for resume. Artifact completion remains an analysis checkpoint, not proof
of final review success. Reconciliation validates the existing source/report
fingerprints and reuses accepted results without rerunning accepted artifact work.
Final review uses the existing scheduler, backend and configured synthesis
correction budget (two extra attempts by default). Its claim/evidence check must
distinguish file presence from ATT&CK behavior and weigh benign explanations.
Deterministic validation rejects confidence above supporting candidates and
returns candidate-specific reference defects for correction. Consolidate
equivalent limitations without discarding distinct source/coverage caveats.

If review fails or exceeds input limits, publish a clearly provisional
`complete_with_failures` result when accepted analysis exists, or `failed` when it
does not. Publish no supported findings; explicitly state that review failure is
not a zero-finding assessment. Preserve accepted candidates for a review-only
retry using the same request. Do not recollect, reset artifacts, or change GoldenDB.
Historical report-only rebuilds do not run a new review or upgrade older results.

## Offline validation

From the repository root:

```bash
.venv/bin/python -m pytest -q tests/test_host_final_review.py tests/test_collection_analysis_runtime.py tests/core/test_core_collection_analysis_integration.py tests/core/test_core_collection_analysis_cli.py tests/core/test_core_host_analysis_state.py
```

Fixtures are synthetic. Tests cover single-chunk review, one multi-artifact final
review, dispositions, corroborated findings, zero findings, incomplete coverage,
invalid review retry/failure, report/state counts, and checkpoint resume without
new source queries or accepted chunk execution.

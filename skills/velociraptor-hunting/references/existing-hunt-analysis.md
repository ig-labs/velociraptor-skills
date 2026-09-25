# Existing hunt analysis: continuation and recovery

Use the **Analyze an existing hunt** workflow in `../SKILL.md` for a normal
"analyze H.ID" request. This reference resolves conditional decisions; it is not
a checklist to execute before every run.

## Choose the requested operation

| Request or state | Action |
| --- | --- |
| Investigate a question/artifact without a hunt ID | Prefer known or read-only discovered existing hunts whose evidence fits the case and requested scope. Review them first; identify a concrete evidence/freshness gap before considering authorized collection. |
| Analyze current results for an exact hunt | Run `vraptor analyze --hunt H.ID` with the saved case/connection context and `--synthesis none`. The CLI inventories artifacts and flow status. |
| Explain or review an already completed analysis | Read the report and use `analysis-results`; verify its scope, acquisition time and coverage. Do not acquire again unless current evidence is requested. |
| Refresh all currently exposed results | Repeat the full analysis command. This includes rows exposed by open flows. |
| Incrementally update a successful streaming analysis | Add `--update` only when newly completed flows are the intended scope. It requires a successful full checkpoint and does not refresh every open flow. DetectRaptor EVTX, generic stacks and specialized Autoruns do not support this incremental route. |
| Request harness synthesis of retained candidates | Use `vraptor summarize --checkpoint PATH`; this makes synthesis calls without reacquiring or rerunning chunks. Ordinary caller review needs no synthesis command. |
| Prepare without model review | Add `--skip-ai` and omit `--update`; label the result preparation-only. |

An existing checkpoint does not automatically justify `--update`, and a RUNNING
hunt does not automatically justify repeating a completed analysis. Follow the
requested freshness and preserve the exact hunt, artifact and time scope.

## Reuse context and monitor once

The required identities are the hunt ID, saved server profile, case root and
investigation ID. Prefer the values already verified in the conversation or
`engagement.json`. If unresolved, `vraptor config --server-profile lab` reports
effective settings and their sources without exposing credential values. A
credential/readiness failure goes through engagement setup; a missing local hunt
collection record is not a readiness failure.

Keep one analysis invocation active for the selected scope. Read its progress and
wait for completion through the existing tool/process handle; a polling timeout
does not authorize a second invocation. Do not poll native hunt status in parallel
merely to duplicate the analyzer's flow inventory. Review failure diagnostics
before deciding whether a rerun is appropriate.

Omitting `--artifact` selects the declared artifact set, including artifacts with
no parameterized spec. Do not split a normal multi-artifact hunt into separate
commands merely to discover its result sources. The runtime preserves explicit
parameters and fills missing default specs. General Autoruns is the exception:
select one exact Autoruns artifact with `--profile autoruns` and analyze other
artifacts separately. DetectRaptor uses its own streaming planner; load those
specialized references only when selected artifacts require them.

## Retrieve and assess without rerunning

Outputs are under `<case-root>/<id>/hunts/<hunt-id>/`:

- `analysis-hunt.md`: generated report and coverage.
- `analysis/hunt-analysis-state.json`: accepted checkpoint and source accounting.
- `assessment-hunt.md`: caller-reviewed conclusions, written after candidate review.

Use the checkpoint path printed by the run. Avoid guessing internal JSON keys:
checkpoint schemas and specialized states differ. For standard streaming results:

```bash
vraptor analysis-results --checkpoint /path/to/hunt-analysis-state.json --limit 25
vraptor analysis-results --checkpoint /path/to/hunt-analysis-state.json --limit 25 --offset 25
vraptor analysis-results --checkpoint /path/to/hunt-analysis-state.json --candidate A0001:F1
vraptor analysis-results --checkpoint /path/to/hunt-analysis-state.json --candidate A0001:F1 --evidence-offset 10
vraptor analysis-results --checkpoint /path/to/hunt-analysis-state.json --reference S0001-R27
```

IDs and offsets above are examples: use returned candidate/reference IDs and next
offsets. A byte budget may shorten pages. Continue candidate, evidence and context
pages as needed; `--context-offset` pages context. Undisplayed candidates and
clipped fields are not reviewed evidence. Use a bounded source-native query when
full original context is needed, preserving exact source references. Specialized
Autoruns/stack reports retain their native findings; generic saved-result retrieval
requires a compatible streaming checkpoint. DetectRaptor findings may also point
to a separate context ledger. See the
[synthesis contract](../../../docs/reference/analysis-synthesis.md)
for these limits.

Before reporting, reconcile represented/reviewed rows, artifact coverage, accepted
and failed chunks, candidate paging, acquisition cutoff and target-execution gaps.
`review_status=not_requested` is expected with `--synthesis none`; it is not a
failure. A zero-candidate result is not proof of benign activity. Deduplicate and
correlate repeated candidates, record rejected/corrected claims, and complete the
[bounded enrichment decision](../../../docs/reference/indicator-enrichment-workflow.md).
Save the caller assessment with checkpoint hashes and review scope. Do not edit
the generated report, rewrite checkpoint status or reacquire evidence just to
publish the caller assessment.

## Resolve concrete failures

| Observed failure | Next bounded action |
| --- | --- |
| Unknown option or installed-version mismatch | Use `vraptor analyze --hunt H.EXAMPLE --help` once for the hunt parser. Bare `analyze --help` shows only shared options. Preserve scope when correcting flags. |
| Missing credentials, invalid readiness or provider failure | Follow the reported setup/recovery path and reuse accepted evidence; repeat only after the cause changes. Do not reset settings or switch providers automatically. |
| Older checkpoint lacks retained candidates | Read its generated report and state for the requested historical review. A fresh analysis is appropriate when the request is for current evidence; do not silently reacquire for a saved-only review. |
| Nonzero result inventory but zero acquired rows, or a declared artifact disappears | Stop claiming coverage. Inspect one bounded exact-hunt metadata response and the selected source names, using `vraptor query` through the live API skill. Keep parameters, named sources and coverage provenance intact. |
| Partial/failed analysis | Report accepted coverage and the exact failed stage. Use the supported recovery diagnostics; neither add `--update` nor reset accepted work as a generic retry strategy. |

Runtime/source-code investigation is warranted after a concrete inconsistency,
not as normal command discovery. Operational analysis alone does not authorize
editing the installed runtime. Preserve diagnostics and report a compatibility
blocker when a code fix is needed outside the user's maintenance scope.

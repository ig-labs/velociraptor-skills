# Reporting policy and finding priority

Report limits control presentation, not accepted evidence or reviewed coverage.
Model token budgets remain separate: `max_output_tokens` limits one provider
response, while reporting settings use counts, characters or UTF-8 bytes.
Increasing a model budget does not automatically increase report limits.
Generated reports omit the repetitive source-of-truth and bulk-export yes/no
metadata lines. Export provenance remains in the relevant manifests.

## Configuration

Set shared values in the analyst configuration's `[reporting]` table and profile
overrides in `[profiles.NAME.reporting]`:

```toml
[reporting]
detailed_findings = 20
examples_per_finding = 3
context_items = 10
timeline_rows = 20
preview_chars = 320
chat_chars = 32000
evidence_chars = 2000000
compact_markdown_bytes = 524288
artifact_sections = 100
detectraptor_notes = 100
detectraptor_events = 3
detectraptor_source_refs = 3
follow_up_actions = 5

[profiles.example.reporting]
detailed_findings = 30
```

The values above are the application defaults. An explicit CLI
`--report-detailed-findings 30` overrides `VRAPTOR_REPORT_DETAILED_FINDINGS`,
which overrides profile and shared settings. Environment precedence is process,
repository `.env`, then shared `~/.codex/.env`; empty values do not override a
lower layer. Counts and character budgets must be positive integers; chat and
compact Markdown budgets must be at least 512. Very small Markdown budgets can
still fail if report navigation or an indivisible fenced block will not fit.
Unknown settings and invalid limits fail with a configuration error.
Inspect effective limits and their source with `vraptor ai doctor`.

Token settings remain in the existing analysis/profile tables. For a recognized
model, `max_output_tokens = "max"` resolves to its effective output ceiling;
`max_input_tokens = "max"` fills the remaining permitted input envelope, including
the model reference's standard-price input ceiling. A smaller declared deployment
ceiling still wins. Unknown deployment names need explicit model limits. Numeric
overrides remain supported; reporting counts do not accept `"max"`.

Reporting settings are excluded from model execution/cache identity. They do not
change acquisition, evidence chunking, review-queue accounting or the meaning of
analysis completion. Model/deployment ceilings and evidence authorization still
apply independently.

## Priority and overflow

Findings carry `report_priority` and `priority_rationale`, separately from
confidence. Priority describes response relevance and urgency; confidence
describes evidence support. A high-confidence observation is not automatically a
high-priority incident finding. The existing synthesis/review call can supply
priority without another model request. Explicit severity from specialized
analyzers is retained. New finding priorities are `critical`, `high`, `medium`,
and `low`; confidence remains `low`, `medium`, or `high`. Missing priority uses
the internal `unranked` sentinel and displays **Not assessed**.

Chunk and synthesis line responses can include
`PRIORITY<TAB>finding-id<TAB>level<TAB>rationale` after the corresponding finding
(within `FINDINGS` for synthesis responses). Validation checks the finding identity, allowed level,
nonempty rationale and duplicate records. Priority schema version 1 is additive;
older accepted responses remain readable without this record. New model output
cannot assign `informational` or `unranked`. Retained `informational` findings
keep their classification, evidence and confidence; they are not automatically
moved or recategorized. Recovery preserves priority and rationale when rebuilding
accepted chunks. New informational observations use relevant context, subject to
the existing finding-link and reference-role rules.

The shared instructions and ordering apply to host and hunt analysis, including
DetectRaptor direct and exact-stack paths and specialized grouped summaries.
Focused Autoruns retains its native `severity` wire field: reportable suspicious
or notable rows use the same four levels; expected rows use native `info` and
remain context. Its confidence field remains independent. Native Autoruns
`SUSPICIOUS` and generic-stack `FLAG`/`ASSESSMENT` records have no confidence field;
the renderer never invents confidence for those records. Generic-stack first-pass
review omits expected groups; its follow-up protocol retains notable/suspicious
dispositions and expresses uncertainty in reasons, without inventing impact.
Legacy severity values are retained when reading saved records. Grouping-only
summaries inherit source priority rather than inventing a new assessment. Specialized and generic stack
reports use the same missing-priority label and priority-first detail selection.

Sort before applying display limits. Ordering is critical, high, medium,
Not assessed (internally `unranked`), low, then retained informational findings,
with deterministic identity/content tie-breaks.
For example, a high-priority finding arriving after 20 low-priority findings
displaces one low-priority detailed entry; that entry remains in the additional
findings index and structured results. Completion order never determines priority.

Compact results retain every available finding and its source groups. Markdown
expands the configured number of findings and indexes the rest. Examples and
related context follow finding priority. Reporting metadata distinguishes total,
detailed and indexed findings and omitted examples. Complete reports retain
critical/high findings at least in their index. Shortened chat reserves a concise
urgent-finding inventory and material caveats before lower-priority detail. If
even that inventory or the caveats exceed the chat budget, it reports unshown
counts by priority and shortened/unshown limitation counts, with a link to saved
detail when a report path is available. A bounded chat message is not the complete
report. Follow-up limits affect display only; they do not reject valid actions or
invalidate accepted review.

Oversized compact reports use linked detail pages within the configured byte
budget. Pages are content-addressed and published before the root index, so an
interruption preserves the previous index. Existing unrelated or modified pages
are not overwritten. Old pages are retained; repeated changed reports can grow
the output directory and no automatic historical-page cleanup is performed.
Selected exact evidence continues to require finding-linked authorization;
pagination does not permit raw evidence dumps. The full-evidence character budget
counts serialized field content and emits omission counts for excluded groups.
Source evidence remains authoritative in Velociraptor.

## Offline re-rendering

```sh
./vraptor reports render --checkpoint /path/to/request-analysis.json \
  --output-dir /path/to/review-report --report-detailed-findings 30
```

The command also accepts a saved hunt checkpoint. It validates retained source
identity and renders available saved results without collecting evidence or
calling a model. Output includes source provenance and the effective reporting
policy. Accepted checkpoints and hashed artifact reports are preserved.

New saved synthesis caches bind their result to accepted inputs and review scope.
A stale cache, or a legacy cache without that binding, is not assumed current:
re-rendering falls back to the current retained result/candidates and records this
limitation. This can produce a preliminary report even when a separate historical
synthesis report exists; it never silently promotes an unverified old review.
When a hunt has newer partial candidates from a failed update, re-rendering uses
those candidates and their coverage limitations instead of the previous published
checkpoint's assessment. The previous checkpoint remains unchanged.
Published hunt results must match their stored `result_sha256`; changed results
are rejected, and legacy results without that hash fall back to the validated
accepted candidates. Fresh synthesis reports state their model-call count;
offline re-render reports explicitly state zero calls.

Native Autoruns terminal summaries follow the shared chat bound and sanitize
control characters in both detailed and indexed entries. The canonical Autoruns
publication retains its complete summary and separately authorized CSV-derived
evidence; compact pagination does not fragment that raw-evidence contract.

Older compact checkpoints may already lack examples discarded by earlier
versions. Re-rendering cannot reconstruct these values, assign a justified new
priority or strengthen a failed/partial review. Missing priority displays
**Not assessed**; missing examples remain unavailable. Retained findings and their references remain
usable without forcing an analysis rerun.

Caller-owned `assessment-host.md` and `assessment-hunt.md` should follow the same
priority and omission rules. They remain separate from harness-generated reports;
changing configuration does not rewrite an existing caller assessment.

## Validation

Regressions cover configuration precedence, priority arriving last, deterministic
selection, legacy priority, overflow, byte boundaries, source preservation and
zero-inference re-rendering.

# Fast Host Report Contract

## Purpose

Provide a question-first operator summary from validated artifact results without raw
chunks or ordinary-row inflation.

## Required order

1. Analysis metadata and coverage
2. Exact question
3. Direct answer
4. Supported findings with grouped source references and representative examples
5. Relevant context linked to the finding it explains
6. Links to per-artifact analysis
7. Collection/review limitations
8. Bounded follow-up

State whether findings exist, how many planned rows were reviewed, and whether any
collection or analysis task failed.

For `host-forensics` with `deep` response depth, follow the direct answer with a
UTC timeline using:

```text
timestamp | host | user/session | process/action | evidence source | interpretation | confidence
```

For `rapid`, return only the highest-signal entries, essential linked context,
material coverage gaps, and immediate next action. Do not remove caveats merely
to shorten the output.

During execution, atomically replace
`<case_root>/<id>/systems/<host>/analysis-host.md` with a provisional report after
each terminal task or retry transition. Include phase, timestamp, accepted coverage,
provisional findings, and current failures. Replace it with the final validated report
when analysis closes.

## Size controls

- Keep the answer to two short paragraphs.
- Keep at most ten context items.
- Keep at most ten highest-priority findings.
- Keep at most five next actions.
- Indicate additional grouped items without expanding them.
- Cap selected full-row Markdown content at 2,000,000 characters per report;
  identify omitted groups and leave their authoritative content in Velociraptor.

## Evidence detail

For each supported finding or separately labeled unresolved investigative lead,
group repeated source references under the item, retain compact `Sxxxx-R<number>` or same-source range notation, and show at most three
manager-selected examples with long values truncated. Do not repeat a client, flow,
artifact, or evidence prefix for every row. Include hostname with client ID when the
server exposes it. Distinct result components in one Flow remain separate source
groups.

Context is not a separate enrichment catalogue. Label it with the related finding
ID and one of `identity`, `session`, `process`, `file`, `network`, `timeline`,
`environment`, or `general`. Include available username/account/SID and other
causal context when it materially changes interpretation.

Publish one `systems/<host>/analysis/<readable-artifact>--<short-hash>.md` current report per
analyzed artifact. The stable hash is derived from the original artifact name so
sanitized or case-folded names cannot collide. It contains
the artifact assessment and one full projected representative for rows with the same
manager-selected fields. The parent `analysis-host.md` remains a standalone host summary and
links to those reports; it is not an index-only document. Preserve request-specific
copies under `collection/requests/<request-id>/analysis/artifact-analysis/` so older
request checkpoints remain verifiable. Historical sections link to their original
request report when the current artifact report has different contents. Do not embed raw CSV,
unrelated complete rows, prompts, full event streams, or duplicated evidence.

Include deterministic domain assessments for execution, persistence, authentication,
lateral movement, and network activity. Distinguish `observed`,
`not_observed_in_accepted_evidence`, `unknown_due_to_coverage`, and `not_assessed`.

Do not add landscape, RMM, greyware, administration, or benign context unless the
question requests it or it materially changes a finding.

Final publication follows the mandatory [final AI review](final-review.md).
Disposition records control findings, leads, context, counts and structured state;
zero supported findings is valid. A failed review remains provisional and does
not publish the original candidates as supported findings.

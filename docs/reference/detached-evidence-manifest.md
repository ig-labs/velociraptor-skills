# Detached Evidence Manifest

Use this contract for deliberately detached standalone evidence processed by
`dfir-data-stacking` or `dfir-log-chunker`. It does not authorize exporting
source-native evidence.

## Source

Record:

- immutable source path, SHA-256, byte size, and format;
- source system or platform;
- acquisition/export context; and
- `detached-file` or `stdin` authority.

The original source remains authoritative. Derived stacks and chunks are not
raw-evidence replacements.

## Scope and reduction

Record the bounded question, source filters, projection, time bounds,
normalization, deduplication, grouping, partitioning, and limits. A description
records provenance; it does not prove the source tool enforced the filter.
Record compression, encoding, decoding-error policy, delimiter, JSON record
path, field-resolution counts, and timestamp parsing when applicable.

## Coverage

Use the shared states from `analysis-reduction-contract.md`. Record source,
processed, omitted, and duplicate-reference counts. Set `closure_eligible`
only for complete `exhaustive` or explicitly `filtered` coverage without an
unresolved limitation. Source count must equal processed plus omitted count.

Plain-text overlap creates duplicate references, not duplicate source
evidence. Structured chunks must cover each parsed source record exactly once.
Replacement decoding and timestamp parse failures are limitations and prevent
closure eligibility when they affect the derived result.

## Outputs and handoff

Every output record contains role, path, SHA-256, byte size, and record count.
The handoff records exact source references, unresolved work, and the next
pivot. The content-derived `handoff_id` changes whenever provenance, coverage,
or output identity changes.

Chunk manifests distinguish parsed-value preservation from byte preservation.
Canonical structured JSONL envelopes are transformed review material. UTF-8
strict uncompressed text may be byte-faithful per recorded source reference.

## Policy

Every manifest asserts:

- rarity is not a maliciousness verdict; and
- reduced output is not a complete raw-evidence copy.

Review representative and exact source rows before promoting a rare or common
group to a finding.

See `detached-evidence-examples.md` for sanitized SIEM, EDR, timeline,
application-log, and generic JSONL commands.

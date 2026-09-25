# Analysis Reduction Contract

Use this contract for DFIR workflows that reduce evidence before analyst or
model review. It applies to Velociraptor-native analysis and to deliberately
detached standalone evidence.

For preparation without AI, use the shared [`--skip-ai` contract](analysis-skip-ai.md).
Do not treat prepared evidence as completed analyst review.

## 1. Preserve the Source of Truth

- For live Velociraptor work, the saved hunt or collection flow is
  authoritative. Query and reduce results in Velociraptor.
- Do not download CSV, JSON, or JSONL merely to make analysis convenient.
- Export only when immutable evidence, offline operation, interoperability, or
  an explicitly approved exhaustive suspicious subset requires a file.
- For detached evidence, treat the original file as immutable and record its
  path, size, SHA-256, format, and acquisition context.

Generic detached-evidence workflows implement the shared
[`detached-evidence-manifest.md`](detached-evidence-manifest.md) vocabulary.

## 2. Ask One Bounded Question

Each reduction pass must state one analytical question. Choose the smallest
artifact set, fields, time range, host scope, and normalization that can answer
it. Do not combine unrelated questions into one stack or chunk set.

## 3. Use the Least Expensive Complete Review

Apply these modes in order:

1. Directly review bounded evidence when it fits the configured analysis
   ceiling.
2. Filter or project server-side/source-side to remove irrelevant fields and
   rows.
3. Stack or aggregate when prevalence, frequency, or repeated values are part
   of the question.
4. Chunk only the reduced raw rows that still require detailed review.
5. Retrieve exact original rows for suspicious or ambiguous reduced groups.

Sampling can propose filters or pivots. It cannot establish exhaustive
coverage, clear unseen evidence, or close an investigation question.

## 4. Keep Provenance Through Every Reduction

Every derived result must retain enough information to reproduce the pass:

- source identifier, file hash, or Velociraptor hunt/flow identifier
- artifact and effective parameters
- target scope and time bounds
- query, filter, projection, grouping fields, and normalizers
- source row count and reduced row/group count
- stable evidence, group, chunk, or review identifiers
- exact references needed to retrieve original rows

Do not silently normalize hashes, exact IOCs, attacker-controlled names, or
material paths.

## 5. Declare Coverage

Label each result with one or more explicit coverage states:

- `exhaustive`: every in-scope row was processed
- `filtered`: every row matching the recorded filter was processed
- `sampled`: only a sample was reviewed
- `token-limited`: configured analysis capacity excluded rows or chunks
- `group-truncated`: aggregate groups were capped
- `provisional`: the source hunt or flow was not terminal

Only exhaustive or explicitly filtered complete coverage can support closure.
Sampled, token-limited, group-truncated, and provisional results must state the
gap and the exact next action.

## 6. Persist the Minimum Necessary Output

Default retained outputs are compact state, reduction definitions, review
decisions, provenance, and summaries. Keep raw evidence in the authoritative
system.

Native hunt and host analysts return stable source references and concise
interpretation only. They do not echo source values or select field names.
Python validates each reference and hydrates the authoritative row only after
acceptance; synthesis receives compact references rather than duplicated row
payloads.

Live Velociraptor analysis enforces
[`velociraptor-persistence-policy.json`](../../src/vraptor/resources/contracts/velociraptor-persistence-policy.json).
Every analysis state records authoritative source identifiers, normalized
coverage state, closure blockers, and a classified persistence manifest.
Unclassified CSV or JSONL files under a live analysis directory are removed
and the analysis fails. The exception for normalized standalone agent event logs
is narrow: canonical and one-level `previous-analysis/` history files are
content-validated as `bounded_agent_runtime_events`, remain evidence-free, and
are capped at 4,096 events and 1 MiB per log.

Permitted durable raw outputs are:

- explicit immutable evidence exports
- content-addressed detached evidence supplied by the caller
- complete reduced aggregates required for repeatable review
- exact original rows for reviewed suspicious or ambiguous groups

Explicit hunt and collection exports record an executable persistence
authorization. Immutable evidence and interoperability classes require an
operator-requested export and authoritative hunt or flow identifiers.

Never use `/tmp` for evidence, prompts, model responses, or review decisions.
Use caller-owned case paths and atomic sibling writes.

## 7. Reuse Exact Prior Runs

Before creating a Velociraptor hunt or collection flow, calculate the canonical
run identity from:

- source mode
- exact target client or hunt scope
- artifact set
- effective artifact parameters and time bounds
- collection timeout
- available source-version fingerprints

Rank exact matches in this order:

1. terminal successful
2. in-flight, including a deliberately paused hunt
3. failed, cancelled, stopped, timed out, or unknown
4. no exact match

Reuse terminal-success and in-flight matches. Do not silently reuse or replace
a failed/cancelled exact match; require `--force-run`. A forced run must still
record the prior-match check, the bypass decision, and the new source ID.

Similar runs with different parameters, timeout, or scope are not exact matches.
For hunt selection only, an exact current-case multi-artifact run may satisfy a
smaller requested artifact subset when the requested artifact parameters and
target scope remain compatible. Generic and different-engagement supersets are
templates only and require explicit authorization before separate current-case
hunt creation. Persist the run-identity hash, selected source, candidate
classification/rank, decision, reason, template source parameters, and near-match
mismatch fields.

## 8. Route by Evidence Boundary

| Evidence boundary | Primary workflow |
| --- | --- |
| Live Velociraptor hunt | `velociraptor-hunting` |
| Saved single-host Velociraptor flow | `velociraptor-host-analysis` using the `velociraptor-collection` runtime |
| Explicit immutable Velociraptor hunt snapshot/export | extracted-evidence branch of `velociraptor-hunting` |
| Explicit immutable Velociraptor host export | extracted-evidence branch of `velociraptor-host-analysis` |
| Standalone CSV/TSV/JSON/JSONL requiring prevalence analysis | `dfir-data-stacking` |
| Reduced standalone raw rows requiring bounded partitioning | `dfir-log-chunker` |

Do not route Velociraptor evidence through generic file workflows unless the
export itself is required. Generic workflows must remain usable for evidence
from any DFIR platform.

## 9. Handoff Requirements

A handoff to another skill or analyst must include:

- the analytical question
- source authority and provenance
- coverage state
- applied reductions
- retained evidence references
- unresolved groups or rows
- the exact next pivot

The receiving workflow must not infer complete coverage from a bounded sample
or a partial handoff.

For detached evidence, include a content-derived handoff ID, output hashes,
exact source-row or line-fragment references, duplicate-reference accounting,
and a closure-eligibility decision. A prevalence stack must preserve a
reproducible immutable-source rescan path. A chunk handoff must preserve source
order and account for every record in its reduced scope.

### Autoruns residual review aggregate

The `autoruns` hunt profile may persist its validated full residual aggregate as
`analysis/autoruns_review.csv` beside the potential-Golden CSV. The provenance
comment attests source completion and row/group accounting, identifies the hunt
and artifact, and binds the CSV payload to its source, query and database hashes.
The persistence checker classifies this file as `complete_required_aggregate`
only when the provenance, accounting and payload checksum validate. It contains
bounded host samples, not original endpoint rows or an AI disposition list.
Publication is atomic after source validation and before AI classification;
the original source export remains the immutable input for saved review.

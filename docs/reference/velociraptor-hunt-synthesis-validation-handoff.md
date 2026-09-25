# Velociraptor Source-Qualified Evidence Reference Handoff

## Document metadata

- Created: `2026-08-13`
- Last reviewed: `2026-08-13`

## Purpose

This sanitized engineering handoff records the resolution of a provenance
collision in Velociraptor hunt and machine-collection synthesis. It contains no
customer identifiers, credentials, raw result rows, or indicators.

## Original failure

A live hunt reviewed all 813 planned rows across 11 terminal sources and 26
analysis chunks, but final synthesis cited a chunk-local `R1` that did not exist
in the validator's selected artifact/chunk namespace. Deterministic validation
correctly rejected the story and retained grounded fallback findings.

The root problem was the reference model: local `R<number>` labels were reused
across chunks, artifacts, flows, and result components, then remapped during
later synthesis stages. Artifact/chunk coordinates were required to recover the
intended row, and compact prompt projection could make that recovery ambiguous.

## Replacement contract

Evidence now uses one source-qualified, source-local reference:

```text
S0003-R1004
```

- `S0003` is a persisted short alias for one immutable result source.
- `R1004` is the actual one-based row number within that result source.
- A chunk containing source rows 1001-2000 therefore cites its fourth row as
  `S0003-R1004`, not as a chunk-local `R4`.
- Chunk ranges remain review-accounting metadata. They are not evidence identity.

The immutable source identity depends on acquisition mode:

- full hunt analysis uses one aggregate identity per organization, hunt and
  artifact for the ordered `hunt_results()` stream;
- hunt updates use one deterministic identity per artifact-homogeneous batch of
  exact client/Flow source descriptors; and
- machine collection uses organization, request, client, Flow, artifact and
  terminal result component.

Each row retains its actual client and Flow provenance independently of the
aggregate or batch alias. Full `hunt_results()` rows that omit those identifiers
are matched through returned hostname/FQDN and the current hunt/client inventory;
ambiguous values remain empty rather than substituting the hunt ID as a Flow ID.
The persisted alias registry does not renumber aliases still referenced by the
current checkpoint.

## Implemented behavior

- Hunt acquisition assigns references before logical segmentation or token
  chunking. Repacking a row does not change its reference.
- Machine collection assigns a distinct source alias to every Flow result
  component and maintains one request-wide alias registry across incrementally
  scheduled artifacts.
- Worker and synthesis protocols accept only `Sxxxx-R<number>` references.
  Legacy `R<number>` references are rejected.
- Artifact and host synthesis preserve the source reference directly. The old
  renumber-and-restore provenance path has been removed.
- Synthesis sees a bounded compact projection, and deterministic validation uses
  that exact projection. A row omitted from the prompt cannot be selected.
- Artifact, chunk, Flow, hunt/request, client, and component metadata are
  coordinator-owned and hydrated from the accepted reference map; the model
  does not restate or choose those coordinates.
- Invalid references or field selections still fail closed to grounded
  deterministic fallback with `complete_with_failures`.
- A grounded `complete_with_failures` fallback is published as a provisional
  checkpoint and `analysis-hunt.md`. Result-review and overall coverage remain
  partial, while a bounded synthesis diagnostic is retained in the run record.
  Hard synthesis failure still retains the prior checkpoint and cursor.

## Breaking migration policy

There is intentionally no compatibility layer.

- Analysis plan, runtime, flow-state, worker, synthesis, artifact-result, host,
  and hunt output contracts were versioned forward.
- Old compact flow-analysis state is invalidated and rebuilt from authoritative
  Velociraptor result sources.
- Old incremental machine-collection state is not loaded.
- No parser accepts local `R<number>` evidence references.
- No migration rewrites old accepted findings into the new namespace.

This invalidates analysis state only. Existing Velociraptor hunts and collection
Flows remain authoritative and are reused; the required result rows are
reacquired and reviewed under the new contract.

## Acceptance criteria

1. A chunk covering source rows 1001-2000 preserves row 1004 as
   `Sxxxx-R1004`.
2. Two full-hunt rows may share an aggregate alias but preserve distinct exact
   client/Flow provenance; an ambiguous Flow ID remains empty.
3. Two result components within one machine-collection Flow receive different
   `Sxxxx` aliases.
4. Incrementally scheduled artifacts share one request-wide alias registry and
   cannot each claim `S0001` for different sources.
5. A synthesis reference omitted by compact projection is rejected.
6. Valid multi-source artifact and host synthesis preserves references without
   renumbering or provenance restoration.
7. Legacy `R<number>` worker or synthesis output is rejected.
8. An invalid reference retains accepted findings through deterministic fallback
   and never reports full completion.
9. Ad-hoc result review continues to keep target execution as `not_assessed`;
   reference changes do not expand the coverage claim.

## Affected implementation

- `src/vraptor/analyze/references.py`
- `src/vraptor/analyze/host.py`
- `src/vraptor/analyze/runtime.py`
- `src/vraptor/analyze/command.py`
- `src/vraptor/analyze/flow.py`
- `src/vraptor/analyze/coordinator.py`

## Non-goals

- Do not weaken deterministic provenance validation.
- Do not persist bulk result rows or prompts.
- Do not treat chunks as evidence identity.
- Do not migrate legacy local references.
- Do not convert result-review completion into hunt-wide target-execution
  completion.

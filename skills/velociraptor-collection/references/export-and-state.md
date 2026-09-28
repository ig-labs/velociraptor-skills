# Collection State and Export

## Contents

- State paths
- Export controls
- Export projections
- Hydration

## State paths

Host collection state uses layout version 3:

```text
<case_root>/<investigation_id>/systems/<host>/
  system.json
  analysis-host.md
  analysis/<readable-artifact>--<short-hash>.md
  collection/
    current.json
    coverage.json
    requests/<request_id>/
      state.json
      coverage.json
      analysis/
        request-analysis.json
        artifact-analysis/<readable-artifact>--<short-hash>.md
  host-analysis-state.json
```

`collect analyze` atomically updates host-root `analysis-host.md` throughout
execution, then rebuilds it from completed request checkpoints. The host-root
`host-analysis-state.json` tracks only the current/latest selected request; each
completed request has one `request-analysis.json` and terminal complete/failed
artifact summaries. A single in-process coordinator owns polling and scheduling;
queued/running status is transient and no persistent analysis lock is written. Legacy
plan/run/report/agent trees are ignored. The host `analysis/` folder holds current
artifact reports; request copies retain history and checkpoint integrity.
`--rebuild-host-summary` restores current reports from validated checkpoints.

A failed artifact summary is a terminal local-analysis result and does not block
sibling artifacts. Retry it explicitly with `--reset-artifact` and the exact request
ID; the existing Velociraptor flow is reused and only that component is replaced.

`state.json` is created before queue submission and carries `queue_progress`:
`starting`, `running`, `complete`, or `failed`, plus the active artifact,
completed/planned counts, error text, and update time. Status and poll refreshes
must preserve this queue record.

Result pagination is transport-only. Changing the server page size must not alter
source-qualified `Sxxxx-R<number>` references, source or plan fingerprints, or
chunk boundaries. The suffix is the actual one-based row within one result
component, not a chunk-local counter. Source aliases distinguish multiple
components returned by the same Flow.
If one result component fails, preserve successful sibling components and record
partial artifact coverage rather than dropping all rows.

Validate an exact saved request without recollection with
`utils/validate_collection_analysis_forward.py`. The harness checks
the provisional host report, checkpoint and artifact hashes, retry counts,
durable-state hygiene, canonical paths, and coverage.

## Export controls

The explicit export command or `--export` is sufficient authorization. Export the
exact saved flow IDs and arguments. Do not choose an older similar flow or use export
as a fallback for failed analysis.

Zero-row artifacts remain in coverage state but do not create empty CSV files.

## Export projections

The exporter uses stable projected schemas for raw MFT, EVTX Hunter, RDP authentication,
and explicit logon rather than unrestricted `SELECT *` output.

SRUM exports separate execution, application-resource, network-connection, and
network-usage scopes. Registry Hunter exports one file per category or curated profile.

Environment-bound exports receive a stable argument-derived suffix so targeted runs do
not overwrite each other.

## Hydration

Hydrate previously saved host requests with:

```bash
dfir collect hydrate --investigation-id IR1234
```

Use `--host` to restrict the target and `--force-export` only when a new snapshot is
required. Hydration records complete, partial, incomplete, and missing saved-request
states in the case-level manifest.

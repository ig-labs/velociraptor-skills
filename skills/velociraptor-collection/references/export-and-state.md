# Collection State and Export

## Contents

- State paths
- Progress log
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
sibling artifacts. Resume it with `--retry-failed` and the exact request ID, which
reuses accepted chunks; `--reset-artifact` discards them. Either way the existing
Velociraptor flow is reused and only that component is replaced. Chunks that fail
every attempt are listed in the request's `analysis/failed-chunks.json`, including
those an AI repair call then recovered (`resolution` `by: repair`).

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

The gRPC packet starts at 5,000 rows and may rise to 20,000 rows after two full
5,000-row responses of at most 2 MiB with no row above 64 KiB; EVTX and
PowerShell stay at 5,000. Size failures retry down to one row, and later
100,000-row windows continue without changing logical chunks.

Validate an exact saved request without recollection with
`utils/validate_collection_analysis_forward.py`. The harness checks
the provisional host report, checkpoint and artifact hashes, retry counts,
durable-state hygiene, canonical paths, and coverage.

## Progress log

Read this when inspecting `<case-root>/<id>/logs/velociraptor-progress.log`
for a collection command. The shared
[logging reference](../../../docs/reference/velociraptor-logging.md#progress-logging)
covers DEBUG mode, waiting messages, rotation and `logs status`.

- The file records stage progress, safe query purposes, command scope,
  model/provider identity and usage, retries, counts, timings, query-aware
  heartbeats, and sanitized server messages. `VELO_PROGRESS_FILE_DEBUG=true`
  adds DEBUG lines with response part/query IDs, server-reported totals,
  transport sizing, and provider lifecycle detail.
- The submitted VQL, evidence rows, prompts, model responses, environment
  values, provider bodies, and raw stderr are never logged.
- Concurrent commands interleave safely under distinct operation ids. Parallel
  task lifecycle events are not throttled, heartbeats aggregate task state, and
  every operation ends with query, model, task, retry, row, batch, rotation, and
  dropped-event counts when applicable.
- The mode-`0600` adjacent `.lock` file serializes cross-process append and
  rotation with a bounded wait; logging failure never fails collection.
- INFO records bounded, single-line sanitized server messages and extracts valid
  numeric completed, total, percent, rows-scanned, bytes-scanned, and
  elapsed-seconds fields under `progress_*`. Server text may contain
  evidence-sensitive hostnames, usernames, paths, or VQL. Recognized API keys,
  tokens, passwords, secrets, authorization values, URL credentials, PEM
  material, and configured credential values are redacted. Message length and
  SHA-256 are not logged.
- Each query has a local `q-NNNN` identifier and one heartbeat with elapsed and
  server-idle time; unbounded queries and server silence are warned, and
  unchanged queries receive five-minute reminders. `logs status --id <id>`
  checks local PID/start identity and retained operation overlap; old logs
  without PID identity report `UNKNOWN`.

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
vraptor collect hydrate --investigation-id IR1234
```

Use `--host` to restrict the target and `--force-export` only when a new snapshot is
required. Hydration records complete, partial, incomplete, and missing saved-request
states in the case-level manifest.

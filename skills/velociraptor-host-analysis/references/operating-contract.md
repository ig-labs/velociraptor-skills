# Host Analysis Operating Contract

## Authorization boundary

The user's Velociraptor task authorizes normal setup, exact collection reuse,
collection, analysis, and host-directory writes. Require approval only before adding
`--force-run` to bypass an exact prior flow unless already authorized.

Use `collect analyze` as the single owner of automatic collection and analysis. Do
not manually launch agents, run per-artifact commands, or recreate its worker pool.

## Process boundaries

- The orchestration process alone queries Velociraptor and writes plan, run, and report
  state.
- Analyst requests run from the request analysis directory through the configured
  stateless provider API client without shell, filesystem, browser, or MCP tools.
- Prompts travel over stdin. Raw prompts and CSV evidence are not persisted.
- One logical task owns one artifact. A fitting artifact runs once; only an oversized
  artifact splits into contiguous chunks.
- Assign one request-wide `Sxxxx` alias per result component and retain the
  actual one-based component row as `Sxxxx-R<number>`. Multiple components in
  one Flow must not share an alias, and chunking must not renumber rows.
- Treat server pagination as transport-only. Acquire repeatable 100,000-row source
  windows using 5,000-row response packets with guarded promotion to 20,000 and
  size-failure fallback to one row. Page size must not alter logical row
  references, source fingerprints, plan fingerprints, or chunk boundaries.
- If one result component fails, preserve accepted sibling component rows and mark
  the artifact partial. Discard the artifact only when no component rows are usable.
- One host-scoped async scheduler owns all direct and chunk work. Artifact groups
  are dynamic lanes sharing one runner/client and one flat global concurrency limit,
  with one `max_concurrency + 1` production-credit bound. No nested agent holds a
  worker slot while waiting for child tasks.
- Retry a validation-rejected response using the configured budget (two extra
  attempts by default) and a value-free brief containing every defect. Preserve diagnostics after a
  successful retry. Never redispatch an accepted task in the same run.
- Analyze accessible rows from a terminal partial flow, but carry the collection
  failure into artifact and host status. Partial evidence never closes as complete.
- In `--synthesis full`, chunked artifacts synthesize from compact accepted
  results, then every host run requires [AI disposition review](final-review.md).
  In `--synthesis none`, the harness returns preliminary candidates and the
  caller performs final review and correlation without another harness call.
- Workers never export, recollect, query Velociraptor, mutate endpoints, or update
  saved analysis state.

## Flow lifecycle

Rank exact matches:

1. terminal success;
2. in flight;
3. failed, cancelled, stopped, timed out, or unknown;
4. no match.

Reuse the first two. Require `--force-run` for the third. Different artifacts,
parameters, time bounds, target scope, or timeouts are not exact matches.

Keep ordinary rows server-side. Use explicit export only for immutable evidence,
offline work, or interoperability.

## State and resume

The request analysis directory stores one compact `request-analysis.json` after
completion and one Markdown summary per terminal artifact, including bounded failed
summaries. The host-root
`host-analysis-state.json` holds current/latest request status and resumable compact
artifact results. Each terminal artifact component and its status are published in
one atomic state replacement. Queued and running ownership remains in the single
coordinator's memory; there is no persistent analysis lock or unlock workflow.
Reference-only accepted chunks and bounded failure diagnostics support recovery;
raw responses, detailed task records, and per-attempt manifests are transient;
explicit `--plan-only` writes `analysis-plan.json`.

Old local-row reference state is not migrated. Contract-version mismatch discards
compact analysis state and rebuilds it from the authoritative saved Flows without
recollection.

The host-root `analysis-host.md` report is atomically refreshed throughout execution
and then regenerated from completed request checkpoints as cumulative host memory.
No compatibility mirror is written. Do not persist raw CSV, prompts, analyst runtime
files, detailed task records, or bulk flow rows.

After a collection polling timeout, rerun `collect analyze` with the exact reported
`--request-id`. The server remains authoritative for flow state and rows. Do not
replace unchanged flows automatically.

A terminal failed component remains held until `--retry-failed --request-id ID`
resumes its failed stages. Explicit `--reset-artifact` or `--reset-analysis`
instead discards accepted work. These are local analysis operations and do not
recollect. See [correction and recovery](../../../docs/reference/analysis-recovery.md)
for diagnostics and the request-owned retention contract.

Run new evidence needs as separate focused `collect analyze --artifact ...` requests.

For forward validation, run
`utils/validate_collection_analysis_forward.py` against an exact
saved request. Supply client and request IDs only; do not recollect or force a run.
The harness verifies the provisional report, durable checkpoint and artifact hashes,
canonical paths, retry counts, coverage, and the cumulative host report.

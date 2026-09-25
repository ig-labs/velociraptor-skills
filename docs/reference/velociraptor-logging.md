# Velociraptor logging improvement plan and behavior

## Scope and revised priorities

The implementation improves operator visibility without changing query results,
collection scope, deadlines, or live process execution. The review baseline was
177 log lines, including 92 query waiting/silence entries and repeated transport
messages. Long aggregation queries returned only one count response row, so
response row counts alone did not explain progress.

Replaying the recorded heartbeat times and response-count changes with the new
policy emits 15 waiting/silence entries instead of 92 (83.7% fewer). This measures
log noise only, not query runtime; historical log files are left unchanged.

1. **Implemented: truthful status.** Silence means no recent server response;
   it is not proof of a stalled server. Record PID, process start identity,
   local hostname, and `log_schema=2` at command start. `logs status` reads the
   current log and retained rotations, verifies process identity with the local
   OS, and shows `ALIVE`, `STOPPED`, `EXITED`, `EXITED-PID-REUSED`, `UNKNOWN`, or
   a recorded terminal outcome. The reader flags logs older than six minutes
   and overlapping retained operations on the same command/target/artifact.
   It does not alter process execution or issue Velociraptor queries.
2. **Implemented: meaningful query context.** Source, GoldenDB residual,
   remaining-row, and populated-Autoruns counts have distinct purposes.
   Stack queries name scope, signature, aggregate, residual, or impacted-host
   work. API events inherit command and query scope so hunt filters include
   their query activity. Generic grouping classification takes precedence over
   `count()` inside grouping queries; `GROUP BY TRUE` remains a scalar count.
3. **Implemented: honest numbers.** API `response_rows` counts returned rows;
   `matched_rows` is emitted by the trusted analysis count wrapper after the
   existing count result is interpreted. Arbitrary evidence response values are
   not forwarded into logging.
4. **Implemented: native server messages.** Disk spill is a nonfatal WARNING
   with `group_bins`. Cache-fill messages become `cache_rows`. Routine query
   start and response-send messages are suppressed; DEBUG has one decoded-batch
   event with transport metadata instead of a duplicate response event.
5. **Implemented: bounded waiting messages.** A first heartbeat occurs after
   30 seconds, a silence warning at the first tick with at least 60 seconds
   since server activity, then reminders every five minutes. Observed renewed
   activity after a silence warning emits a recovery event at the next tick.
   Short queries that finish before that tick already report completion.
   Timers describe local observations; they do not estimate rows scanned or ETA.
6. **Implemented: simplify the human log.** No message/query/error fingerprints
   or server identity hash are rendered. Zero server query IDs/totals and API
   component/stage boilerplate are omitted. Genuine response part zero is kept
   on batch events because batches use zero-based part numbers. Server-message
   envelope part numbers are omitted because they need not identify the batch
   described in the message text.
7. **Validation and cleanup.** Replay representative heartbeat timing, verify
   real native message shapes, process identity reuse, missing/old logs,
   context restoration, exact filters, permissions, rotation, and credential
   redaction. Measure emitted waiting-line counts against the same baseline.
   Run the affected analysis tests and repository validation suite.

## Follow-up work requiring separate performance design

- General GoldenDB Autoruns counts and residual grouping now share one source
  pass. Other count reuse still requires predicate and source-consistency checks.
- Evaluate aggregation memory and query plans before changing grouping or
  cache lifetime. A disk spill is a performance event, not a query failure.
- Introduce explicit query deadlines with defined partial-result and retry
  behavior; changing timeouts solely to quiet logging can interrupt analysis.
- Add duplicate-run prevention separately if desired. Matching targets in
  retained logs only establishes overlap, not identical questions or filters.
  This implementation warns in the status view and does not refuse commands.
- No operation leases or background monitor are necessary for the current
  status view. A stopped process cannot write its own suspended-state event;
  inspect it from a separate `logs status` command.

## Usage

```bash
./dfir logs status --id case-example
./dfir logs status --id case-example --operation op-v1-1111111111111111
./dfir logs follow --id case-example --hunt-id H.example
```

`status` accepts `--case-root`, `--id`, `--operation`, and `--hunt-id`.
It uses only retained logs and verifies PIDs only for logs from this hostname.
Older logs without PID/start identity, rotated-out start records, missing OS
support, or inaccessible processes report `UNKNOWN`. A live local PID does not
prove that a remote query is executing; remote state remains explicitly unknown.
`follow` remains an append/rotation reader; use `status` when it stops updating.

Representative abbreviated log lines:

```text
INFO [...] Velociraptor query started | hunt_id=H.example query=hunt_results.count query_id=q-0007 purpose=count-source-rows
INFO [...] Count completed | hunt_id=H.example purpose=count-source-rows matched_rows=12500
INFO [...] Velociraptor query started | hunt_id=H.example query=hunt_results.group query_id=q-0010 purpose=build-autoruns-residual-stack
INFO [...] Server lookup cache ready | query_id=q-0010 cache_rows=3216
WARNING [...] GROUP BY switched to slower disk processing | query_id=q-0010 group_bins=30001
WARNING [...] No recent response from Velociraptor | query_id=q-0010 server_silent=90s elapsed=90s
```

## Configuration and data boundary

`VELO_PROGRESS_FILE_DEBUG=true` adds batch/transport and provider diagnostics.
Analysis `--debug` also enables these; explicit `--log-level` takes precedence.
No server-metrics opt-in variable is needed. Start a new command to load updated
code; an already running process does not change its logging implementation.

Server messages are single-line, limited to 512 characters, and sanitized for
recognized credentials and configured secret values. They can contain evidence
context such as paths, usernames, hostnames, or VQL. Logs must be treated as
sensitive; redaction is not a guarantee against unknown secret encodings.
The file and rotation lock remain mode `0600`, with 1 MiB rotation and three
backups. Text in quoted messages cannot supply operation/PID/filter fields.

## Validation commands

```bash
./.venv/bin/python -m unittest tests.test_velociraptor_logging_monitoring tests.test_velociraptor_operation_log tests.test_analysis_cli_output tests.test_live_hunt_analysis
./.venv/bin/python -m unittest discover -s tests
git diff --check
```

### Autoruns diagnostics and timing

General GoldenDB stack analysis uses `purpose=autoruns-accounted-stack` for one
source pass producing source, matched, residual, populated-residual and group
counts followed by the residual stack. `autoruns_accounting_completed` reports
the summary and time spent acquiring it. Successful review requires exact
row/group equality and the completion marker; successful transport alone does
not establish complete review. Focused and direct lanes keep scope-specific
accounting. Only separate-query stacks may explain an increased count as growth.

INFO events distinguish accounting, AI review parts, suspicious drill-down
batches, and validation. A drill-down completeness failure emits
`error_code=autoruns_missing_identity` with selected, matched, and missing
identity counts. Counts describe distinct identities, not returned rows.
`autoruns_drilldown_started` includes `request_bytes` and `request_max_bytes` for
the 1 MiB default serialized request bound. An oversized individual identity
emits `autoruns_identity_request_too_large` before any drill-down query. The
optional Python count cap does not replace the byte bound.
DEBUG adds at most ten opaque missing-identity references and an omission count;
raw paths, commands, signers, and model output are not added to these events.
Publication preparation is not a successful durable checkpoint: the command's
final outcome remains authoritative.

DEBUG `api_query_timing` events report `first_batch_ms`, `consumer_pause_ms`,
and overall duration, correlated with the existing query id. First-batch latency
includes server work and transport/batching delay. Consumer pause measures time
suspended at the API generator's yield, including local processing and analyst
backpressure. These are overlapping wall-clock measurements, not server CPU
times. Empty queries have no first-batch value. Timing summaries currently
cover successfully exhausted streams; failed/cancelled streams retain their
existing failure events rather than a misleading completion summary.

The review manifest and INFO `autoruns_review_timing` event separate
`source_acquisition_seconds` from `model_execution_seconds`.
`duration_seconds` remains total pipeline wall time (event `duration_ms` uses
milliseconds), including time spent acquiring the combined query's summary
before classification starts. Source acquisition measures iterator waits and
that initial acquisition. Model execution measures the union of in-flight calls,
including retries, rather than adding concurrent call durations. These intervals
can overlap and must not be added; none is server CPU time. The combined query's
initial acquisition also appears in its accounting event and must not be counted
twice when interpreting logs.

Run the focused synthetic regressions with:

```bash
.venv/bin/python -m pytest tests/test_autoruns_diagnostics.py tests/test_autoruns_accounted_stack.py tests/test_autoruns_request_batches.py tests/test_live_hunt_analysis.py tests/test_autoruns_ai_review.py tests/test_velociraptor_operation_log.py tests/test_run_velociraptor_collection.py
```

The VQL execution tests use the installed local Velociraptor binary and synthetic
rows only; they skip when that binary is absent. They do not query a live case.

### Optional live-analysis query deadline

`hunt analyze --query-timeout-seconds N` and
`collect analyze --query-timeout-seconds N` apply a per-query ceiling to their
analysis client's queries. The default `0` preserves existing behaviour;
positive integers cap otherwise unlimited calls and never extend shorter
internal timeouts. Queries log their effective `timeout_seconds`, send it to
Velociraptor, and apply the same gRPC deadline. A timed-out query remains a
failure/partial review according to the existing analysis coverage rules.
Streamed query deadlines include consumer pauses, so allow headroom for AI
backpressure. This option does not apply to snapshots, endpoint collection
limits or model request timeouts. For host analysis it also caps individual
client lookup, flow reconciliation and completion-watcher queries through the
same client; it does not replace the overall collection polling deadline.
Saved-request resumes accept it without changing evidence collection scope.

Validate option parsing, command wiring and transport deadlines with
`.venv/bin/python -m pytest tests/test_velociraptor_query_timeout.py`.

### Autoruns phases

`--profile autoruns` labels its source scan `autoruns.accounted_stack`
with purpose `autoruns-source-export`. Progress advances through source
query/validation, `residual_csv_published` when case context is supplied,
classification cache, AI review on cache misses, and reporting.
Saved-source runs log live readiness as skipped; cache hits do not announce an
AI run. Source-export statistics carry `action=autoruns`, `stage=source_export`
and explicitly distinguish source completion from the AI status in `report.json`.
The counts-only workflow is retired. Earlier `autoruns_test` and `autoruns_dedup`
logs and exports are historical records and are not rewritten.

# Velociraptor logging and token usage

## AI token usage

Operational `vraptor` commands (and the legacy `dfir` alias of the same entry
point) share one operation logger, including saved synthesis, specialized
analysis and `ai test`. Nested dispatch borrows the active
logger so it cannot duplicate accounting or finalize its parent's operation.
The standalone `utils/run_analyst_agent.py` launcher uses the same lifecycle.
Direct embedded Python use of the agent runner must provide an operation logger;
it does not implicitly create user log files.

Case-bound commands automatically append a separate
`<case-root>/<id>/logs/token-usage.jsonl` file. Non-case commands use
`${XDG_STATE_HOME:-~/.local/state}/vraptor/logs/token-usage.jsonl`. Exact checkpoint
paths in the supported case layout can identify the case without `--id`; arbitrary
checkpoint paths use the user-level destination. Explicit `--log-file` wins.
`setup init` uses the user-level destination as well, so logging does not create
the workspace before initialization determines whether it is new or reused.
The destination is bound before inference. Each operation records `operation_started`.
Each dispatched provider request
attempt writes one `request_usage` record when it completes, fails, times out or
is cancelled. The command writes one `operation_summary` when it exits normally
or unwinds an error/interruption. All concurrent agents within that command
contribute to the same summary, with totals grouped by provider and model.
Operational commands with no model calls, including summary cache hits, record
an explicit zero-attempt summary. Help, log inspection and standalone `--dry-run`
remain free of logging side effects.
Separate commands retain separate operation IDs and summaries in the shared file.

The records include UTC timestamp, operation ID, PID, command, invocation ID,
task/request ID, attempt number, provider/model/protocol, stage, status, duration,
and `input_tokens`, `output_tokens`, `total_tokens`, `cached_input_tokens`.
Prompts, model responses, credentials and raw evidence are excluded. The counts
come from provider usage metadata; local prompt/output token estimates are not
included. Cached input is a breakdown of input, not an extra amount to add to
`total_tokens`. Anthropic input totals include cache reads and cache creation.

`usage_status` distinguishes `reported`, `partial` and `unavailable` usage.
Explicit provider-reported zero remains zero; unavailable token fields are
`null`. Interrupted streams retain the latest known cumulative snapshot as
partial. Summaries contain known token totals, `reported_requests`,
`partial_requests`, `unavailable_requests`, `attempts`, `retry_attempts`, and
per-model `groups`. `usage_complete=false` means the totals omit unknown usage.
These are local observations of provider usage, not billed costs.
If a successful response omits final usage, the result and progress log retain
the latest streaming snapshot consistently with the ledger. When no usage was
observed, progress events omit token counters rather than implying reported zero.

Retries have separate records, including failed attempts that returned usage.
`transport_retry_attempts` counts repeated transport dispatches;
`correction_attempts` counts additional validation-correction invocations.
`retry_attempts` counts repeated dispatches across both kinds without counting
one dispatch twice. A request's `correction_attempt` is zero for the initial
response, one for the first correction, and so on.
Repeated streaming notifications replace the current snapshot; progress
heartbeats and terminal events do not count usage again. Requests rejected
locally before provider dispatch, including cancelled queue waits, have no usage
record. The ledger does not depend on progress callbacks or runtime output-file
persistence, so analysis paths with transient runtime files are covered.

The usage file uses thread/process locks and mode `0600`, with independent
rotation at the progress log's size and retained-file limits (currently 1 MiB,
four files including the current file). It is not subject to the progress
event-count cap or log-level filtering. Older request rows may have rotated out
even when a command summary remains.
Aggregate either request records or operation summaries for a given operation,
not both. A forced process kill can omit the summary and in-flight request;
already-written records remain available. A retained operation start without a
terminal summary is reported as unfinished, not as complete zero usage. This
alone cannot distinguish a still-running process from an abrupt termination.

`--no-log-file` disables both logs, but in-memory command counters and returned
usage remain available. An explicit `--log-file /path/run.log` places
the usage file at `/path/run-token-usage.jsonl`. A write failure warns once on
stderr, tracks `records_dropped`, and marks `log_complete=false` in a later
summary; the progress summary also exposes `usage_records_dropped`. Logging
failure does not abort analysis. Existing `logs show/follow/status` commands
continue to read the progress log; the usage file is ordinary JSONL.

## Usage reporting

Analysis commands print a token summary to stderr after their last model request.
Final structured results also include a `token_usage` object through the shared
operation metadata: `scope: command`, input/output/total/cached-input counters,
attempts, retries, per-provider/model groups, reported/partial/unavailable request
counts, `usage_complete`, `log_complete`, `persistence_enabled`, and `log_file`.
These counters belong to this command, including its failed attempts that
returned usage. They are not cumulative case totals or costs. The structured
result snapshots request accounting before the final log-summary write.
Operation metadata includes zero-use counters when no model request was dispatched.
Raw query/stream output retains its existing format; its accounting is in the
operation ledger rather than a second stdout document. Zero-call commands stay
quiet on stderr; model-using operations print the token summary there.

OpenAI Responses `input_tokens` already includes cached input. Anthropic Messages
reports uncached `input_tokens`, `cache_read_input_tokens` and
`cache_creation_input_tokens` separately; vraptor adds these three once to obtain
normalized input, then adds output for the total. Cached-input counters denote
cache reads. Raw numeric provider fields, including cache creation, remain in
the agent result/manifest. Stream updates are cumulative snapshots, not amounts
to add; Anthropic `message_start` and `message_delta` merge into one attempt.
See [OpenAI token semantics](https://developers.openai.com/api/docs/guides/token-counting),
[Anthropic caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching),
and [Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming).

```sh
./vraptor logs usage --id example-case --case-root /path/to/cases
./vraptor logs usage --id example-case --case-root /path/to/cases --json
./vraptor logs usage --global --json
```

The read-only report reads the current ledger and up to three rotations, plus
the corresponding progress logs. It uses each operation summary once, or the
request records when no summary exists. It deduplicates matching request IDs
and can recover older completed requests absent from the ledger. It never sums
a summary and its requests. `--ledger-only` excludes progress-log recovery.
Summary-only retained counts remain usable when detailed request rows have
rotated out, and the report labels that coverage explicitly. Conflicting
operations are excluded from known totals and flagged. Missing/partial usage,
unterminated requests, malformed files and concurrent changes produce coverage
warnings and exit 2. Successful parsing cannot prove lifetime coverage: older
rotations or unlogged activity may be absent. The report excludes the surrounding
Codex conversation and never modifies or backfills original source logs.

Offline validation:

```bash
.venv/bin/python -m pytest tests/test_cli_operation_lifecycle.py tests/test_agent_usage.py tests/test_agent_usage_logging.py tests/test_token_usage_log.py tests/test_token_usage_report.py tests/test_standalone_usage_logging.py tests/test_run_analyst_agent.py tests/test_agent_runtime.py tests/test_agent_providers.py tests/test_additional_agent_providers.py tests/test_velociraptor_operation_log.py
```

## Progress logging

Progress logging describes observed command and query activity. It does not
change query results, collection scope, deadlines or live process execution.

1. **Process status.** Silence means no recent server response;
   it is not proof of a stalled server. Record PID, process start identity,
   local hostname, and `log_schema=2` at command start. `logs status` reads the
   current log and retained rotations, verifies process identity with the local
   OS, and shows `ALIVE`, `STOPPED`, `EXITED`, `EXITED-PID-REUSED`, `UNKNOWN`, or
   a recorded terminal outcome. The reader flags logs older than six minutes
   and overlapping retained operations on the same command/target/artifact.
   It does not alter process execution or issue Velociraptor queries.
2. **Query context.** Source, use-case scope,
   remaining-row, and populated-Autoruns counts have distinct purposes.
   Stack queries name scope, signature, aggregate, residual, or impacted-host
   work. API events inherit command and query scope so hunt filters include
   their query activity. Generic grouping classification takes precedence over
   `count()` inside grouping queries; `GROUP BY TRUE` remains a scalar count.
3. **Row counts.** API `response_rows` counts returned rows;
   `matched_rows` is emitted by the trusted analysis count wrapper after the
   existing count result is interpreted. Arbitrary evidence response values are
   not forwarded into logging.
4. **Native server messages.** Disk spill is a nonfatal WARNING
   with `group_bins`. Cache-fill messages become `cache_rows`. Routine query
   start and response-send messages are suppressed; DEBUG has one decoded-batch
   event with transport metadata instead of a duplicate response event.
5. **Waiting messages.** A first heartbeat occurs after
   30 seconds, a silence warning at the first tick with at least 60 seconds
   since server activity, then reminders every five minutes. Observed renewed
   activity after a silence warning emits a recovery event at the next tick.
   Short queries that finish before that tick already report completion.
   Timers describe local observations; they do not estimate rows scanned or ETA.
6. **Human-readable output.** No message/query/error fingerprints
   or server identity hash are rendered. Zero server query IDs/totals and API
   component/stage boilerplate are omitted. Genuine response part zero is kept
   on batch events because batches use zero-based part numbers. Server-message
   envelope part numbers are omitted because they need not identify the batch
   described in the message text.

## Operational limits

- A disk spill is a performance event, not a query failure. Logging does not
  alter aggregation memory, cache lifetime or query deadlines.
- Matching targets in retained logs establish overlap, not identical questions
  or filters. The status view warns but does not prevent duplicate runs.
- There are no operation leases or background monitors. Inspect suspended or
  stopped processes with a separate `logs status` command.

## Usage

```bash
./vraptor logs status --id case-example
./vraptor logs status --id case-example --operation op-v1-1111111111111111
./vraptor logs follow --id case-example --hunt-id H.example
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

Focused and direct lanes keep scope-specific accounting. A focused stack is
counted and streamed by separate queries, so it may explain an increased count
as growth; a stack that represents fewer rows than its count fails.

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
milliseconds). Source acquisition measures iterator waits. Model execution
measures the union of in-flight calls, including retries, rather than adding
concurrent call durations. These intervals can overlap and must not be added;
none is server CPU time.

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

# DetectRaptor Fleet Analysis

Use this adapter for fleet or saved-hunt DetectRaptor review. Apply the shared
[`DetectRaptor analysis contract`](../../../docs/reference/detectraptor-analysis-contract.md)
for artifact priority, review-field guidance, evidence preservation,
correlation, dispositions, and detection uplift.

Single-host DetectRaptor collection analysis belongs to
`velociraptor-host-analysis`.

## Fleet method

1. Record hunt ID/state, original target baseline, target-execution coverage,
   artifact versions, effective parameters, time bounds, and row counts.
2. Run the default streaming analyzer. For EVTX, discover all in-scope
   `Detection.Name` groups first, then plan detections rare-first. Direct review
   receives complete evidence. Apply any requested time predicate to discovery and combine it
   with the detection predicate in each query. Discovery records row count,
   total/average/max evidence characters, estimated tokens/chunks, and rows
   beyond the routine preview. Small
   detections use direct review. Large detections run an exhaustive exact-payload
   census. Stream every exact group only when the census removes at least 100
   model rows and 5 percent; otherwise fall back to direct review. Do not sample,
   generate filters, or exclude evidence.
   Do not select generic `--analysis-mode stack` for DetectRaptor hunt artifacts.
   An optional parameterized `--detection-regex` narrows the same automatic
   planner. The deprecated `detectraptor-stack` value is only a stream alias.
3. Follow the shared artifact priority. Treat its configured stack definitions
   as field-review and bounded-pivot guidance, not as authorization to replace
   complete row review with generic stacking. Analyze every other returned
   DetectRaptor artifact afterward.
4. Measure detection and signature prevalence with distinct-host counts and
   bounded time ranges.
5. Retrieve exact source rows and host context for rare, high-impact,
   ambiguous, or rule-uplift candidates.
6. Correlate independent evidence by host, user, time, process, command, path,
   hash, URL/domain, RMM family, and detection family.
7. Record dispositions and next pivots. Keep target execution, result review,
   and cross-artifact corroboration as separate coverage claims.

## Fleet-specific controls

- Prevalence is context, not proof of benignity.
- Rarity is a prioritization signal, not proof of maliciousness.
- Generic stack analysis is prohibited for DetectRaptor fleet hunts. Use
  bounded server-side stacks only as targeted pivots after full-row streaming
  review identifies a concrete question.
- Automatic exact-evidence stacking is the exception: scoped discovery applies
  `Detection.Name =~ RequestedDetection`, resolved partitions also apply exact
  `PartitionDetection`, and every source row is accounted by its group count.
  Prefer exact `EventData.ScriptBlockText` for PowerShell; otherwise use the
  serialized message/event payload. Internal group IDs do not authorize
  hash-based evidence equivalence.
- Do not impose a signature-count ceiling. Every exact group is streamed and
  its occurrence count contributes to represented-row accounting.
- Stream every grouped record with its complete exact payload through the same
  bounded CSV chunk workflow used by normal live hunting. The model-visible
  columns are `_SourceRef`, `Detection`, `OccurrenceCount`, `FirstSeen`,
  `LastSeen`, `PayloadField`, and trailing `Payload`. Use standard CSV quoting;
  commas, quotes, literal tabs, and embedded newlines in `Payload` must round-trip.
- Use the normal sparse `reference-line-v3` response. Return findings only for
  reportable groups and `RESULT<TAB>no_reportable_findings` for a clean chunk.
  Do not require a benign or expected assessment for every group. Python owns
  group, represented-row, and review accounting.
- Batch-query original timestamp and machine context only for `_SourceRef`
  values returned in findings. Attach those rows to the accepted finding; do
  not run another semantic AI pass or rescan unselected payloads.
- EVTX detection-partition analysis is full-run only; reject `--update` rather
  than mixing incremental flow batches with detection partition identities.
- Execute each EVTX detection in an isolated scheduler/result namespace. On a
  retryable read-only transport reset, reconnect and replay only that detection
  from its beginning, discarding partial chunks and accepted results from the
  failed attempt. Reuse compact completed-detection outputs when resuming an
  unfinished compatible run; do not requery or reanalyse them.
- Run detection namespaces concurrently through unique fair lanes in one
  scope-owned analyst queue. Derive the active detection-partition ceiling from
  `AI_SKILLS_ANALYST_AGENT_MAX_CONCURRENCY`, the same value used for provider
  requests and model work. Keep census/context queries off the
  event loop, enforce the one global model concurrency ceiling for chunk and
  synthesis calls, and let each producer await only its own futures. A failed
  partition must not cancel or discard successful peer checkpoints.
- Give each DetectRaptor VQL call a 900-second absolute deadline by default;
  `AI_SKILLS_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS` may set another positive value.
  Replay retryable read-only transport failures at most four times total, with
  2, 5, and 15 second reconnect backoffs. Record value-free stage, attempt,
  status, elapsed time, rows received, and next delay. Do not retry semantic,
  authentication, authorization, or cancellation failures.
- Bind unfinished-run recovery to the hunt, safe server and organization
  identity, time/detection scope, profile, discovery/query contract, analysis
  route and resolved execution route,
  and output contract. Persist only compact counts, hashes, stages, bounded
  transport status, selected source references, and identity-free accepted results.
  Never persist raw Evidence, source rows, hostnames, prompts, model transcripts,
  or failed payloads in recovery state. Retire recovery after successful
  publication so the next ordinary full run rebuilds from Velociraptor.
- Use the detection as the replay unit for census and exact-group review. Batch
  selected context requests under a bounded request size. Publish accepted
  detection progress atomically even while other detections remain pending.
- Treat detection-discovery counts as an acquisition lower bound. A partition
  is valid when acquisition returns at least its discovered row count; fail
  closed only when it returns fewer rows. A non-terminal hunt remains
  provisional, and a later run picks up detection names added after discovery.
- A repeated result generated by one upstream rule is not independent
  corroboration.
- Preserve named LolRMM result sources independently before family-level
  summarization. Review Applications, Processes, and ResolvedDomains with the
  source-specific stack order in the shared contract.
- A Webhistory record is browser evidence, not proof of DNS resolution.
- Do not claim a narrow temporal correlation for LolRMM process or
  resolved-domain snapshots unless exact source data or an independent
  artifact supplies a semantically valid event time.
- Apply no autonomous EVTX filters or exclusions. Known-bad detections remain
  visible and prevalence changes priority only.
- Do not close from sampled, token-limited, group-truncated, running-hunt, or
  unknown-baseline evidence.
- Do not infer zero detections when a hunt has no flows or incomplete target
  execution.

## Fleet outputs

Return:

- target and result-review coverage with limitations;
- priority findings with exact hunt/source references;
- expected clusters with evidence-backed rationale;
- unresolved items and exact next pivots;
- cross-host and cross-artifact correlations; and
- sanitized reusable uplift proposals that follow the shared schema.

Grouped runs write `analysis/detectraptor-interesting-context.json` for
timestamped events associated with reportable source references. Clean groups
produce no model record. The model may sparsely return high-confidence reusable
benign candidates with `global` or `site` scope; Python writes the complete exact
payload as the final CSV field in
`analysis/detectraptor_whitelist_candidates.csv`. This is a simple review input
for a later uplift workflow, not a full audit trail. No generated ignore regex
is created and DetectRaptor is never mutated or promoted.

Every progressive publication also writes the same context ledger, candidate
CSV, and Markdown under
`analysis/runs/<analysis-id>/<run-id>/`. The root report and `analysis/` files
remain the canonical latest view; run-scoped copies preserve prior route/run
results from later canonical replacement. Legacy canonical DetectRaptor files
are copied into a content-addressed legacy run directory before their first
replacement. When the requested analysis identity is incompatible, the complete
prior `hunt-analysis-state.json` is archived under its prior analysis/run path
before canonical state is rebuilt; this preserves completed-partition recovery
for diagnosis or an explicitly restored compatible route.
If cumulative synthesis publishes only the grounded `complete_with_failures`
fallback, retain the compact completed-partition recovery checkpoint. Repeating
the same compatible full command retries synthesis from those accepted
partitions; only fully accepted synthesis retires recovery.

`analysis-hunt.md` consolidates exact-payload groups that have the same
detection, confidence, and analyst assessment. Each consolidated note records
represented occurrences, distinct hydrated endpoints, first/last observation,
exact-payload variant count, and up to three endpoint-diverse or timeline-spread
representative events with timestamp, endpoint, user, channel/event ID, and
source reference. The Markdown never embeds the full payload or every event;
the interesting-context ledger remains the complete hydrated result. Direct
partition findings remain visible in progressive failed-run reports even when
they did not require exact-payload hydration. A cumulative-synthesis exception
must publish the report and both DetectRaptor ledgers with terminal `failed`
status while retaining the prior canonical checkpoint and resumable completed
partitions.

Reusable DetectRaptor logic changes require fleet or replay validation across
true-positive, false-positive, benign collision, and performance fixtures.
Environment-only exceptions remain scoped site filters or overlays.

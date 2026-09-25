---
name: velociraptor-host-analysis
description: Perform fast, evidence-backed analysis of one Velociraptor endpoint through exact-flow reuse and the configurable artifact-scoped analyst pool. Use for host analysis by client ID, hostname, collection scope, or explicit artifact on Windows, Linux, or macOS.
---

# Velociraptor Host Analysis

**Required server prerequisite:** follow the shared
[DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md)
for every new local server and connected live/remote server. If the live catalog
contains no `DetectRaptor.` artifacts, run `Server.Import.Extras` with the
DetectRaptor CSV row and verify installation before proceeding. Reuse a successful
session check; a failed import blocks the workflow. Explicit read-only/no-import
instructions and offline-only work retain their scope.

The standalone `vraptor` CLI uses the same case paths and configuration. Use
`vraptor analyze --flow F.ID --client C.ID --id ID` or
`vraptor analyze --hunt H.ID --id ID` for existing evidence only. Collection,
client retries and GoldenDB uploads remain explicit. Legacy `dfir`
routes retain their behavior. See the [shared CLI contract](../../docs/contracts/cli.md).

When acting as the calling analyst, pass `--synthesis none`, retrieve bounded
candidates with `vraptor analysis-results`, then perform the final evidence review
and cross-artifact correlation here. Use `--synthesis full` when the user requests
a standalone harness report. Follow the shared [synthesis contract](../../docs/reference/analysis-synthesis.md)
for saved-summary reuse, pagination, partial coverage and preliminary labels.

The CLI defaults to `--synthesis none`; request `--synthesis full` explicitly
for harness synthesis. Save caller-reviewed host conclusions as
`assessment-host.md` and hunt conclusions as `assessment-hunt.md`, following
the provenance and freshness requirements in the shared
[synthesis contract](../../docs/reference/analysis-synthesis.md#caller-assessment-files).

Use `--skip-ai` on the analysis command when only deterministic preparation is
requested. Follow the shared [no-AI preparation contract](../../docs/reference/analysis-skip-ai.md)
for outputs, limitations and review status. A prepared result is not an AI assessment.

Analyze one endpoint. Use `velociraptor-hunting` for cross-host questions and `velociraptor-artifact-selection` when the required artifact is unknown.
Read [operating-contract.md](references/operating-contract.md), the shared [authorization policy](../../docs/reference/velociraptor-operation-authorization.md),
[analysis reduction contract](../../docs/reference/analysis-reduction-contract.md), and
[finding enrichment workflow](../../docs/reference/indicator-enrichment-workflow.md), and
[server-profile/engagement context](../../docs/reference/velociraptor-engagement-context.md).

## Non-negotiable rules

1. Resolve one exact client, preferring client ID.
2. Execute normal workflow actions without another approval prompt.
3. Treat Velociraptor as authoritative and keep ordinary evidence server-side.
4. Reuse exact terminal-success or in-flight flows.
5. Ask only before adding `--force-run` unless already authorized.
6. Use only `collect analyze` for automatic collection and analysis.
7. Do not manually spawn artifact or chunk agents; the CLI owns the globally bounded pool.
8. Require validated line-oriented analyst results; models select source references
   and field names, while Python hydrates exact evidence values.
9. Require validated final AI dispositions before publishing findings, even for one artifact/chunk.
10. Export only on explicit request or evidential need, never to rescue analysis.
11. Use skill contracts and documented `dfir --help`; do not inspect Python
    implementation to discover investigation workflow or CLI semantics.
12. Never manually construct readiness manifests or poll a saved request without
    every required flow ID.

## Workflow

Requests to investigate a host or run a collection group imply collection/reuse
through analysis and final review, unless explicitly limited to collection-only,
planning, no AI, or existing evidence. Completed collections alone do not finish
the task. Follow the shared
[intent, continuation, and completion rules](../../docs/reference/velociraptor-operation-authorization.md#collection-intent-and-completion)
for long-running monitoring, exact-request resume, and completion checks. An
already validated matching analysis checkpoint may be reused.

1. Inspect saved readiness at session start and reuse valid `engagement.json`.
   Use `velociraptor-engagement-setup` only when missing, invalid, or affected by
   connection/credential/mapping changes or failures. Reuse successful session
   analyst checks; do not rerun setup/doctor for every collection. Automatic CLI
   validation remains enabled.
   Readiness has no age expiry and is bound to setup provenance,
   API identity/hash, server fingerprint, org, and live provisioning at `<case-root>/<id>/engagement.json`.
2. Resolve the exact client and case directory.
3. Select `--task-mode host-forensics` for incident and machine deep dives.
   Select response depth independently: `rapid` for high-signal triage,
   `standard` for normal review, or `deep` for full bounded forensic chronology.
   Use `--task-mode compromise-assessment` only when environment discovery is
   explicitly requested.
4. For Linux or macOS, use inventory-validated explicit artifacts rather than the
   default Windows `all` target.
5. Run the canonical command once:

   ```bash
   dfir collect analyze \
     --investigation-id IR1234 \
     --server-profile lab7 \
     --client-id C.1234abcd \
     --task-mode host-forensics \
     --response-depth deep \
     --question "What activity is malicious, security-relevant, or useful host context?"
   ```

   Optionally add `--query-timeout-seconds 1800` for a 30-minute ceiling on each
   API query. Default `0` adds no limit and preserves shorter internal deadlines.
   This applies to fresh and saved-request analysis, including result queries
   and drill-downs. Streamed deadlines include waiting for downstream AI capacity;
   endpoint collection and polling timeouts remain separate.

6. Add `--artifact Windows.Forensics.Prefetch` for one artifact or
   `--collection-type execution` for a focused bundle.
7. Let the CLI verify server artifacts, ensure/reuse flows, and manage one batched
   poll cycle. One in-process coordinator tracks queued/running artifact keys in
   memory. It must create one task per artifact as each becomes terminal while
   polling continues.
8. Monitor flushed `DFIR-STATUS` markers on stderr; request `state.json` remains
   the durable fallback. Submission and flow-ID discovery are bounded.
   Claude managed execution and Codex app-server report completed assistant
   messages rather than individual streaming fragments. While waiting, both use
   the shared heartbeat (20 seconds by default; override with
   `--progress-interval-seconds`). Request lifecycle and retry events remain visible.
9. Monitor the atomically refreshed current host report at
   `<case_root>/<id>/systems/<host>/analysis-host.md`, then review the final
   request checkpoint and linked per-artifact reports. Default stdout is a bounded
   text result containing `chat_summary`. Keep text output for interactive and
   operator-initiated runs. Use `--format json` only when an explicit downstream
   integration will parse the structured response.
   Surface every successful or provisional result to the operator.
10. If collection polling times out, rerun with the reported `--request-id`; do not
   create replacement flows. If the saved request has a missing flow ID, correct the
   queue failure and start a new request instead of polling it.
11. For follow-up, ask one exact question and choose the smallest relevant artifact.
12. Send every material finding through the bounded CTI enrichment decision,
    then merge the returned identity, session, process, file, network,
    prevalence, or chronology context into the finding. The CTI worker must not
    write `analysis-host.md` directly.

## Server-capability recovery

When collection preflight reports unavailable artifacts:

1. Do not add `--force-run`, retry the failed request, or inspect implementation code.
2. Read `artifact_preflight.requested_artifacts`, `available_artifacts`, and
   `missing_artifacts` from the request `state.json`. Confirm its `checked_at`,
   `api_client_path`, `api_client_sha256`, and `org_id` provenance. Available
   artifacts are the requested names present on that server, not the complete
   server catalog.
3. Use `velociraptor-artifact-selection` to refresh one disposable live-inventory
   cache when the saved
   preflight is absent, a live artifact request fails, or it predates an API config, org, or
   artifact-import change. Do not write per-question inventory directories under
   `evidence/`; Velociraptor remains authoritative.
4. Compare the requested membership in
   `../velociraptor-collection/references/collection-types.md` with the live inventory.
5. For a broad `all` question, start one new request containing the full supported
   intersection as repeated `--artifact` values. Use a named type only when its full
   membership preserves the intended scope. Preserve the same question.
6. Add `--supersedes-request-id FAILED_ID`, repeat `--unavailable-artifact` for the
   exact missing set, and repeat `--artifact` for the exact available set. Runtime
   validation rejects stale or incomplete partitions and any failed request that
   already owns a flow.
7. The replacement report retains the failed request ID and unavailable artifacts,
   is capped at `complete_with_failures`, and must not claim complete baseline
   coverage.
8. If the skills and documented CLI do not define the required operation, report a
   skill-documentation gap instead of reverse-engineering Python.

The manager polls all request artifacts, fans each newly terminal flow into analysis once, and continues polling unfinished flows. The default reconciliation interval is 30 seconds; completion events may wake it earlier.
The runtime sends a fitting artifact to one analyst. Oversized artifacts split into contiguous chunks and run as artifact lanes in the same host-scoped async scheduler, sharing one runner/client, one flat global concurrency limit, one production-credit bound, and one in-flight token-weight bound. With `AI_SKILLS_ANALYST_AGENT_TRANSPORT=codex_app_server`, those requests are ephemeral turns on one shared Codex daemon connection, not separate Codex processes.
No nested agent holds a worker slot. With `--synthesis full`, chunked artifacts
receive one synthesis pass and every host run receives final AI review, including
one artifact with one chunk. With `--synthesis none`, the caller reviews the
validated candidates. See [final-review.md](references/final-review.md).

Actual execution uses the shared `AI_SKILLS_ANALYST_AGENT_*` settings and optional
TOML execution profiles. Use `vraptor ai config` or offline `vraptor ai doctor`
to inspect the effective model, endpoint and provenance before analysis. Setup is
documented in repository `docs/model-execution.md`; model selection is independent
of artifact profiles. Analysis limits resolve once per host operation and tighten
to an explicit model context. Claude managed login ignores inherited API/token
credentials in its subprocess; they may remain set for direct API profiles.
Claude uses shared budgets when model limits are
omitted.
Setup saves per-profile input/output budgets and fills shared `[analysis_defaults]`.
Claude aliases `haiku`, `sonnet`, `opus`, and `fable` have dated default-model budget
references in setup and run-only overrides. Haiku is capped at 200000 context /
64000 output; its defaults are 120000 input / 64000 output. The other three default
to 872000 input / 128000 output within 1000000 context. Setup and run-only overrides
require at least 100000 input and 32000 output; smaller configured caps remain
binding and are rejected if they cannot fit both minimums. For remapped aliases,
use the exact model ID or smaller deployment caps;
these references do not verify the native client's current alias resolution.
Optional analysis flags `--execution-profile`, `--ai-config-file`, `--model`,
`--reasoning-effort`, `--max-input-tokens TOKENS|max` and
`--max-output-tokens TOKENS|max` override environment and saved settings for this
run only. See `docs/model-execution.md` under **Analysis model overrides** for
deployment ceilings, standard-price maxima and the input/output minimums.
Artifact profiles use
`analysis_routes`; code owns the route-to-task mapping and accepts only
`high-volume`, `reasoning`, and `synthesis`.

For diagnosis, `--debug` writes schema-2 bounded, value-free `analysis/host-analysis-validation-debug.json`. It covers every collection type and explicit artifact run; records provider/model/protocol selection and provenance, request-option presence, timing, usage, retries, safe HTTP status/error metadata, validation failures, and synthesis status; and excludes prompts, model output, raw provider payloads, stderr, runtime files, raw rows, and evidence values.

Each terminal result component uses profile-projected, repeatable 100,000-row `source()` windows with 5,000-row packets, 32 MiB logical segment bounds, guarded 20,000-row promotion, and one-row size fallback.
Transport cannot alter request-wide `Sxxxx-R<number>` identities: aliases bind request, organization, client, Flow, artifact, and component; suffixes are actual component rows. Multi-component Flows get separate monotonic aliases; old local references/state rebuild from authoritative saved Flows.

Optional `--time-after`, `--time-before`, and repeatable `--time-field` arguments
filter analysis of existing exact flows without recollection. Bounds are
timezone-aware and strict `(after,before)`. Logical fields resolve from each
artifact profile before a new collection can be queued. Artifact names containing
`EventLogs` default to `event=EventTime` unless explicitly overridden or disabled;
`Windows.Detection.PublicIP` is explicitly mapped to `EventTime`. A bounded mixed request
filters artifacts with a known requested/default role and analyzes other
artifacts normally without a time filter. The resolved predicate runs in a
numbered exact `source()` query before preferred-field projection and transport;
the local evaluator rejects any returned out-of-window row. Source ordinals are
assigned before filtering, so evidence references remain actual component rows.
When a profile has no preferred live projection, retain all source fields after
the server filter rather than reducing the result to timestamp fields alone.
The profile's live projection may include `Fqdn` or `Hostname` for live hunt
attribution. Exact-client host analysis removes those simple expressions before
querying because the workflow already resolved the authoritative hostname.
Retain `ClientId` for source provenance and artifact-native fields such as EVTX
`Computer`, which can describe event origin rather than workflow host identity.

## Analysis contract
Review every row once, but return only content that answers the question, changes
confidence or priority, or supports a specific follow-up. Omit routine inventory;
retain RMM, greyware, or administration only when it changes interpretation.

In host-forensics mode, organize material events as a UTC timeline and link
context to the finding it explains. Retain available username/account/SID,
logon/session, parent-child process, path/hash/signer, source/destination network
tuple, timestamp, and exact source reference. Omit unavailable values rather than
infer them.

Use ephemeral CSV, line-oriented exact references, Python-owned hydration and JSON
state, and Markdown for humans. Analysts never serialize evidence values, return
field names, or build a raw evidence catalogue.
See [analysis-output-contract.md](references/analysis-output-contract.md).

## Interpretation routing
Read only the relevant reference:

- Windows mode selection: [windows-host-analysis.md](references/windows-host-analysis.md)
- Windows execution: [windows-artifact-analysis.md](references/windows-artifact-analysis.md)
- Autoruns/GoldenDB: [windows-autoruns-analysis.md](references/windows-autoruns-analysis.md)
- DetectRaptor: [detectraptor-host-analysis.md](references/detectraptor-host-analysis.md)
- Linux: run `artifacts linux-plan`, then read
  [linux-host-analysis.md](references/linux-host-analysis.md) and one specialist.
  - [linux-persistence-execution.md](references/linux-persistence-execution.md)
  - [linux-authentication.md](references/linux-authentication.md)
  - [linux-web-container-analysis.md](references/linux-web-container-analysis.md)
  - [linux-timeline-filesystem.md](references/linux-timeline-filesystem.md)
- macOS: [macos-host-analysis.md](references/macos-host-analysis.md)
- Explicit exports: [extracted-host-evidence.md](references/extracted-host-evidence.md)
- Source verification only: use an operator-approved incident-response guidebook when available.

Do not infer execution from presence-only artifacts. Do not infer absence from zero
rows without applicability and adjacent evidence. Keep presence, execution,
persistence, authentication, and network claims distinct.

## Output and state

The canonical run writes:

```text
<case_root>/<id>/systems/<host>/collection/requests/<request-id>/analysis/request-analysis.json
<case_root>/<id>/systems/<host>/collection/requests/<request-id>/analysis/artifact-analysis/<readable-artifact>--<short-hash>.md
<case_root>/<id>/systems/<host>/analysis/<readable-artifact>--<short-hash>.md
<case_root>/<id>/systems/<host>/analysis-host.md
<case_root>/<id>/systems/<host>/host-analysis-state.json
```

`request-analysis.json` covers that exact request. The host-root report runs provisionally,
then regenerates from all completed request checkpoints. `host-analysis-state.json` contains
only current/latest selected-request state, compact artifact checkpoints, and the
final value-free scope scheduler counters. The host `analysis/` folder contains
current artifact reports for easy review. Request-specific copies preserve
historical content and checkpoint hashes; rebuilding the host summary refreshes
current reports from validated request history.

Request `state.json` retains `artifact_preflight` time, API path/hash and org, plus
`queue_progress` status, current artifact, counts, errors, and update time.

Each terminal artifact gets one atomically replaced Markdown summary and a matching
terminal component in `host-analysis-state.json`: `complete` or `failed`. A usable
result with coverage loss keeps `result_status: complete_with_failures` inside the
component. Prompts, CSV, detailed task/chunk records, analyst files, provider events,
and `.api-runtime` are transient by default. Explicit `--debug-chunk-prompts [N]`
exports up to N standard chunk prompts (one when enabled without a count),
including evidence, and their raw responses/correction retries under the case
debug directory. Host `--skip-ai` saves prompts only and supports
this inspection without model calls. Follow the shared
[prompt export contract](../../docs/reference/chunk-prompt-debug.md).
Queued/running
status is in-memory only. A failed component does not block sibling artifacts and
remains terminal until explicitly selected for reanalysis. Use repeatable
`--reset-artifact NAME --request-id REQUEST_ID` or
`--reset-analysis --request-id REQUEST_ID`; neither option recollects evidence.

The response includes structured `analysis_result` for automation and a bounded Markdown `chat_summary` with status, assessment, findings, finding-linked context, limitations, and next action; chat/GUI callers surface it without another model call.

The report is question-first:

1. analysis metadata and coverage;
2. exact question and direct answer;
3. consolidated findings with grouped references and bounded representative examples;
4. links to collision-resistant readable-plus-hash per-artifact reports;
5. relevant context;
6. limitations;
7. bounded follow-up.

See [report-contract.md](references/report-contract.md).
## Failure behavior
- Stop if the configured read-only analyst runner is unavailable.
- Mark failed collection or analysis tasks as coverage failures.
- Retry an objectively unusable output once, then stop retrying that task.
- Distinguish completed candidate analysis from final review. Claim a completed
  assessment only after required coverage and the harness or caller review validate.
- Use `complete_with_failures` when defensible results exist with coverage loss.
- Use `failed` when no defensible analysis is possible.

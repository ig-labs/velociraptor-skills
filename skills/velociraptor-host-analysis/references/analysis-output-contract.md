# Host Analysis Output Contract

## Transport

- Give each analyst the exact question, artifact/chunk metadata, ephemeral CSV, and
  compact output grammar.
- Run Codex with user config disabled and a read-only sandbox.
- Analysts cannot query Velociraptor or update saved analysis state.
- Require line-oriented analyst and synthesis text. Models do not generate JSON.
- Reserve JSON for Python-owned plans, state, manifests, and parsed results.

## Reference-only artifact/chunk result

Require this compact tab-delimited body. Python owns artifact, chunk, row-range,
row-count, and status metadata, so the model must not repeat it:

```text
RESULT	findings
```

Allow only `FINDING`, `EVIDENCE`, `CONTEXT`, `LIMITATION`, and `FOLLOW_UP`,
followed by `END`. A completed task with nothing relevant uses
`RESULT	no_reportable_findings`.

Use exact source-qualified `Sxxxx-R<number>` references. `Sxxxx` identifies one
request, organization, client, Flow, artifact, and result component; `R<number>`
is the actual one-based row in that component. Each `EVIDENCE` or `CONTEXT`
record cites exactly one reference:

```text
FINDING	F1	high	Execution,Credential Access	Suspicious PowerShell execution.
EVIDENCE	F1	S0003-R1004
CONTEXT	F1	S0003-R1007	identity	Related username and logon context.
```

For records whose final field is prose, Python treats every tab after the fixed
structural prefix as part of that final field. For example, everything after the
`CONTEXT` context type is context text. Embedded tabs do not create extra
fields, and context text has no protocol-specific character limit. Fixed
structural records such as `RESULT` and `EVIDENCE` retain exact field counts.

The model returns no raw values and no field names. Python validates each
reference, hydrates the accepted source row from the ephemeral map, and attaches
authoritative provenance. Pipe-delimited references, `ROW`, `EXPLAINED`, and `-`
placeholders are invalid. Emit another `EVIDENCE` or `CONTEXT` line when another
row is required.

Classify findings with one or more current Enterprise ATT&CK high-level tactic
names: `Reconnaissance`, `Resource Development`, `Initial Access`, `Execution`,
`Persistence`, `Privilege Escalation`, `Stealth`, `Defense Impairment`,
`Credential Access`, `Discovery`, `Lateral Movement`, `Collection`, `Command and
Control`, `Exfiltration`, or `Impact`. Harmless case, underscore, and hyphen
variants are normalized. Unknown or obsolete names are rejected. Reports use the
canonical names and do not require TA identifiers.

## Relevance

Review every assigned row, but return an item only when it answers the exact
question, changes confidence or priority, or supports a bounded follow-up. Omit
routine inventory and unrelated benign activity. Retain administration, RMM,
greyware, or security-tooling context only when requested or materially relevant.

## Validation, retry, and debug

For explicit prompt inspection, `--debug-chunk-prompts [N]` exports up to N
standard chunk prompts (one when enabled without a count), including evidence,
under the case debug directory. When AI runs, raw responses and correction
retry prompts/responses are saved beside each captured prompt with validation
status. Host `--skip-ai` supports model-free prompt
preparation. This is separate from value-free `--debug`; follow the shared
[prompt export contract](../../../docs/reference/chunk-prompt-debug.md).

Validate coordinator-owned artifact/chunk/range/count metadata independently, then
validate result type, record grammar, tactic names, finding-to-evidence linkage, exact reference
availability, deterministic hydration, and final `END`. Chunk ranges are
accounting only and never define evidence identity.

Use the configured chunk/synthesis correction budgets, both defaulting to two
extra attempts, for successful provider responses with forbidden metadata,
unsupported records, invalid tactics or references. Provider/transport failures
use their own retry policy. The correction brief contains only defect metadata
and allowed identities. Budget exhaustion is a fail-closed coverage limitation.
Do not mutate a model response into an accepted result. See the shared
[correction and recovery contract](../../../docs/reference/analysis-recovery.md).

`collect analyze --debug` persists the bounded, value-free
`analysis/host-analysis-validation-debug.json`. Schema 2 contains resolved
provider/model/protocol and field sources, request-option presence, stage timing,
usage, retries, safe HTTP status/error metadata, validation codes, hashes, and
accounting. It contains no prompts, model output, raw provider payloads, stderr,
runtime files, raw rows, or evidence values. A normal run does not create a new
debug file and preserves any prior debug-enabled run with a non-current reference.

## Synthesis story

Chunked artifact synthesis and final host review use this reference-only output
structure. Final host review also requires [candidate dispositions](final-review.md):

```text
ANSWER
No confirmed malicious execution was identified.

FINDINGS
FINDING	M1	high	Execution,Command and Control	Observed execution with a connection.
EVIDENCE	M1	S0003-R1004

RELEVANT_CONTEXT
CONTEXT	M1	S0003-R1007	identity	Related username and logon context.

LIMITATIONS
None.

FOLLOW_UP
None.
END
```

Use `-` instead of a finding ID only for environment-level context that cannot
honestly be attached to a finding. Context types are `identity`, `session`,
`process`, `file`, `network`, `timeline`, `environment`, and `general`.
The same `-` rule applies to artifact-worker context, primarily for an explicit
compromise-assessment environment baseline.

Artifact synthesis receives compact accepted references and summaries. Final host
review additionally receives bounded exact selected source values and context. It may cite only references retained in that bounded input. Python then
hydrates the authoritative values and provenance. The synthesis manager consolidates
equivalent observations and selects the smallest representative reference set.
Python owns and attaches task, exact question, terminal status, and coverage; the
model returns only the report sections, final host dispositions where required,
and `END`.

Python renders the accepted compact result into a bounded Markdown
`chat_summary` containing status, assessment, findings, limitations, and next
action. The command prints that bounded result as text by default. Interactive
and operator-initiated runs must retain text output. Use `--format json` only
when an explicit downstream integration will parse the unchanged structured
`analysis_result` and `chat_summary`; callers surface the summary without
another model call. The structured result retains every compact finding and
source group. The first 20
findings receive detailed human rendering with representative examples; every
additional finding appears in a one-line index. Finding counts distinguish detailed,
indexed, and unavailable findings.

Live `DFIR-STATUS v=1` markers are flushed to stderr during preflight, collection
polling, artifact analysis, synthesis, publication, retries, and silent provider
waits. They contain only allowlisted identity and accounting fields. Use
`--no-progress` when stderr is captured but not drained, or
`--progress-interval-seconds N` to adjust heartbeat frequency. Standalone
low-level collection commands use the same stderr contract while retaining JSON
results on stdout.

## Coverage

Derive planned/reviewed chunk and row counts from the plan and accepted identities.
Accept `no_reportable_findings` as complete coverage. Use `complete` only when every
required task validates. Keep deterministic coverage domains—execution,
persistence, authentication, lateral movement, and network—separate from ATT&CK
finding classification. Relevant collection or synthesis failure makes a coverage
domain `unknown_due_to_coverage`; it must not be reported as negatively assessed.

## Operator status and evidence dates

Host chat summaries and cumulative reports distinguish collection completion from
analysis/final-review completion. Flow creation and last-active dates, and the saved
reuse decision, come from collection metadata; analysis completion is shown
separately. Legacy checkpoints with no dates report them as unavailable. Flow
dates do not establish the event period reviewed or current host state; a later
analysis does not refresh reused evidence. Preserve exact-flow reuse and the
existing recollection authorization policy.

Polling timeouts include an exact-request resume command. Failed/provisional
reports expose the saved continuation command even when detailed failed-stage
diagnostics are absent. Check active runner or monitor ownership before resuming;
retain the existing bounded follow-up and unresolved-lead sections as continuity.
No new engagement state, scheduler, or task registry is required.

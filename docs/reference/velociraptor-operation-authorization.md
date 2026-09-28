# Velociraptor Operation Authorization

## Default authorization

A user request to use a Velociraptor workflow authorizes its normal actions. Do not
pause for additional approval before:

- engagement setup, API-client refresh, client lookup, or bounded read-only VQL;
- required [DetectRaptor bootstrap](detectraptor-bootstrap.md) via
  `Server.Import.Extras` when the connected server has no DetectRaptor artifacts;
- exact flow or hunt checks and reuse;
- a new collection, or a new hunt when no reusable exact current-case match or
  compatible template exists;
- monitoring, live analysis, bounded follow-up queries, and case-owned writes;
- explicit snapshot, export, download, or stop actions required by the task.

Normal setup connects with existing native configuration. `--fetch-config`
authorizes acquisition of existing remote API/endpoint configurations over SSH.
Remote creation requires the requested provisioning operation and its explicit
`--provision-api` or `--provision-client` flag; each helper first confirms the
target file is absent. Connection, permission and copy failures do not authorize
generation. `--regenerate-remote-api` explicitly replaces the selected remote API
credential and is never an automatic authentication-recovery step. An existing
user instruction to create or replace those configurations is sufficient
authorization; do not request duplicate approval.

Keep ordinary evidence server-side and avoid unnecessary exports, but do not ask for a
second approval after selecting an explicit export action.

## Collection intent and completion

Requests to run a collection group (for example, "run execution") or investigate
a host mean collection/reuse followed by analysis within the requested scope.
Use `collect analyze`, including when all exact flows already succeeded. A
successful `collect ensure` is an intermediate collection milestone, not completion
of that task. Do not require a second request to start analysis.

Honor explicit collection-only, planning, no-AI, and existing-evidence-only scope.
Use the corresponding collection command, `--plan-only`, `--skip-ai`, or `analyze`
route. Listing clients/groups or setting up a connection alone does not authorize
an investigation. Keep low-level `collect ensure` semantics collection-only.

At session start before analysis, inspect shared/repository environment sources
and effective analyst configuration. Reuse successful initialization/doctor checks
already performed in that session. Repeat `dfir ai doctor` only after relevant
configuration/provider changes or failures, not before every collection. Reuse
valid `engagement.json`; rerun setup only when readiness is missing, invalid, or
affected by connection, credential, or mapping changes/failures. Automatic
per-operation identity, credential and target validation remains enabled.
If analysis is unavailable, report the specific blocker and
saved request/checkpoint rather than silently downgrading to collection-only.
Preserve accepted work; use bounded failed-stage recovery from the
[analysis recovery contract](analysis-recovery.md). Do not reset accepted work,
change provider settings, or force recollection merely to make progress.

### Continue through collection and review

- Keep the canonical coordinator running: it analyzes each terminal artifact
  while polling unfinished flows. Do not wait for the slowest collection before
  analyzing available results or start competing coordinators for one request.
- For ordinary waits, continue the active task with progress updates. For
  long-running collections, independent work may proceed while monitoring remains
  active. A polling timeout does not cancel the server flows or finish the task.
- After a polling timeout, resume `collect analyze` with the exact saved
  `--request-id`, client, investigation ID, case root, and connection. Omit fresh
  collection selectors such as `--collection-type`, `--collection-group`,
  `--bundle`, and `--artifact` when resuming. Verify every required flow ID is
  recorded; missing IDs need queue-failure recovery, not a blind poll or replacement.
- Before ending a turn with unfinished work, establish and verify a supported
  continuation mechanism if available and authorized (for example, a scheduled
  task wakeup). Record its identifier and carry the exact case/client/request,
  connection, original question, and checkpoint paths. On wakeup, check existing
  runner ownership and state first; monitor an active runner or resume the saved
  request, never launch a duplicate. Continue into analysis when results become
  available. Notify only on meaningful change, completion, failure, or required
  action; retire the monitor on completion or an explicit stop.
- A detached process or a promise to check later is not verified continuation.
  If no continuation mechanism is available, keep monitoring in the active task;
  if a concrete limit prevents that, report incomplete work, the blocker, and the
  exact resume command. Honor explicit stop/pause requests and do not retry
  unchanged failures indefinitely.

Before reporting analysis complete, inspect the saved request checkpoint,
final-review outcome, and row/artifact coverage; collection status or exit code
alone is insufficient. Distinguish collection completion, prepared/no-AI results,
provisional findings, validated final review, and partial/failed coverage. A
failed final review is not a clean assessment. Reuse an already validated analysis
checkpoint when it still matches the requested scope and source identity.

## Approval gates

Require user approval before adding `--force-run` to a collection or hunt command
that will bypass an exact prior flow or exact current-case hunt.

If the current request already explicitly says to force, recollect, rerun fresh, or
ignore the reusable exact match, treat that as approval. Otherwise report the target,
artifact or profile, prior flow or hunt ID, prior state, and bypass reason, then ask one
concise question.

Do not ask for approval when:

- the prior result is reused;
- only a near match exists because scope, parameters, bounds, timeout, or artifacts
  differ;
- a new canonical run identity has no exact match;
- `--force` refreshes local configuration or artifact inventory rather than bypassing
  a collected flow or hunt.

After approval, preserve the prior-match inventory and force decision in state.

Hunt creation has one additional gate. Before mutation, discover all hunts that
contain the requested artifacts case-insensitively, including multi-artifact
supersets. If no reusable exact current-case hunt exists but a compatible generic
or different-engagement template does, return the source hunt's artifact set and
parameters and require explicit `--authorize-template-create` before creating a
separate current-case hunt. Template results are never current-case evidence.

Template authorization never authorizes retargeting, activating, cloning,
stopping, or otherwise mutating the source hunt. Those operations require their
own explicit operator request and are not performed by hunt selection.

This policy controls workflow-level prompts. Platform-enforced tool or filesystem
permissions still apply.

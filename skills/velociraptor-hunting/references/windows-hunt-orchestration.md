# Windows Hunt Orchestration

Use this reference for Windows cross-host questions. The canonical owner is
`velociraptor-hunting`.

## Hunt Choices

First prefer reviewing existing in-scope hunt evidence, including suitable
multi-artifact hunts. Use the known inventory or read-only discovery to select
them, then `vraptor analyze --hunt H.ID` with the saved case/connection context.
The collection choices below apply only when existing evidence is insufficient
for the requested scope/freshness or fresh collection was explicitly requested.
Explain the evidence gap before proposing a new hunt.

Use the smallest option that answers the question:

- `detectraptor`: first-pass lead generation, one native hunt per artifact;
- targeted artifact: one artifact with concrete IOC, path, regex, label, or
  time parameters; or
- `lateral-movement`: the narrow
  `Windows.EventLogs.ServiceCreationComspec` follow-up.

Do not start broad execution, persistence, or registry-heavy fleet profiles
without a concrete cross-host question. Move machine-specific questions to the
`velociraptor-host-analysis` lane.

## Grouped DetectRaptor Hunt

```bash
dfir hunt run \
  --id IR1234 \
  --profile detectraptor \
  --question "Find Windows compromise leads"

dfir hunt status \
  --id IR1234 \
  --group DR-20260725T120000Z

dfir hunt analyze \
  --id IR1234 \
  --group DR-20260725T120000Z
```

The grouped command still creates, checks, and records one native hunt per
artifact. Run decisions against one `--hunt-id` when exact review accounting is
required.

## Targeted Hunt

```bash
dfir hunt run \
  --id IR1234 \
  --artifact Windows.EventLogs.EvtxHunter \
  --env 'EvtxGlob=%SystemRoot%\\System32\\Winevt\\Logs\\*{security,powershell}*.evtx' \
  --env 'IocRegex=rundll32|beacon\\.dll|encodedcommand' \
  --date-after 2026-05-16T23:00:00Z \
  --date-before 2026-05-17T09:00:00Z \
  --question "Scope the known execution indicators"
```

Broad EVTX and MFT requests fail closed without narrowing parameters. Prefer
source-family globs and case indicators over generic fleet-wide acquisition.

## Artifact-First Discovery, Reuse, and Templates

Every `run` or native `ensure` first enumerates all server hunts containing the
requested artifact, regardless of label or description. Artifact matching is
case-insensitive, and a requested artifact may be satisfied by a compatible
multi-artifact hunt. Only after discovery does the workflow evaluate canonical
identity, parameters, timeout, and operating-system or label scope.

Candidates rank as exact current case, generic template, different-IR template,
then create new. IR labels and engagement identifiers compare case-insensitively.
An exact current-case multi-artifact hunt prevents a duplicate single-artifact
hunt when the requested artifact parameters and target scope are compatible.

For collection scheduling, reuse terminal-success or in-flight/paused exact current-case matches. Failed,
cancelled, stopped, unknown, stale by operator policy, or intentionally repeated
exact matches require `--force-run`. Generic and different-IR candidates are
reference-only templates: report their artifact set and parameters, never use
their results as current-case evidence, and never mutate them automatically.
Creating a separate current-case hunt when a template exists requires explicit
`--authorize-template-create`.

These collection reuse rules do not prevent reviewing results already exposed by
stopped, failed or cancelled hunts. Analyze their in-scope evidence with explicit
coverage limits; `--force-run` is not needed for existing-evidence analysis.

```bash
dfir hunt native check \
  --investigation-id IR1234 \
  --target windows \
  --artifact DetectRaptor.Windows.Detection.Evtx

dfir hunt native ensure \
  --investigation-id IR1234 \
  --target windows \
  --artifact DetectRaptor.Windows.Detection.Evtx \
  --force-run
```

Use `--activate-paused` when the exact paused hunt should be resumed rather
than replaced.

`check` and `ensure` JSON include the discovery scope, candidate classification
counts, ranked candidates, selection decision/reason, and a compact
`human_summary`. The public grouped wrapper preflights every requested artifact
before any hunt is created.

## Missing-Client Retry

Opt in only when late endpoints must receive the original hunt:

```bash
dfir hunt run \
  --id IR1234 \
  --profile detectraptor \
  --question "Find Windows compromise leads" \
  --retry-missing-after-hours 24 \
  --retry-max-attempts 1
```

For an existing hunt with a saved original target baseline:

```bash
dfir hunt retry-missing \
  --id IR1234 \
  --hunt-id H.1234 \
  --after-hours 24 \
  --max-attempts 1 \
  --batch-size 100
```

The configuration action is local. A later live analysis pass requeues only
baseline clients with no flow, after the delay and within attempt and batch
limits. Retry state contains client IDs and attempt timestamps, never hunt
result rows. Missing baseline data fails closed.

## Windows Analysis Rules

- At 1,000 or fewer remaining rows, use bounded direct review when it fits the
  token ceiling.
- For larger results, use artifact-approved server-side stacks and exact
  Evidence signatures.
- Detection name defines scope; suppress only an approved evidence-bearing
  field.
- Validate every filter against an exact server-side match count.
- Treat prevalence as context, not proof of benignity.
- Preserve the unseen tail after sampling.
- Running-hunt target coverage is provisional.

Read [windows-live-analysis.md](windows-live-analysis.md) for path, signer,
PowerShell, DLL/.NET, normalization, and drill-down controls. Read
[windows-persistence-autoruns.md](windows-persistence-autoruns.md) for the
Autoruns GoldenDB aggregate exception and focused-use-case workflows.

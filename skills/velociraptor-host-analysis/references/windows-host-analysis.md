# Windows Host Analysis

Use this reference for one Windows endpoint. The canonical owner is
`velociraptor-host-analysis`.

## Contents

- Mode mapping
- Review order
- Deep follow-ups
- Windows risk and coverage controls
- Existing-export helpers

## Mode mapping

### Triage

Run `collect analyze --collection-type triage` for the DetectRaptor lead-finding
subset. Run a separate `collect analyze --collection-type network` only for a
live current-state question; network
rows are volatile and are not historical execution evidence.

### Standard

Run `collect analyze` with the exact client ID as the Windows baseline. The runtime
deduplicates the baseline artifact union, creates one logical task per artifact, and
runs the flat configured worker pool. Review DetectRaptor, execution, persistence,
authentication/lateral movement, and system inventory as separate analytical slices.

For live persistence, prefer `collect analyze --collection-type persistence`
and analyze the saved Autoruns flow with read-only GoldenDB reduction. Use
`persistence-expanded` only when services, tasks, startup items, hidden tasks,
or permanent WMI must corroborate Autoruns.

### Deep

Do not treat deep mode as one unconditional bundle. Start from standard results
and add only the artifacts needed by the lead:

- `Windows.Detection.BinaryHunter` for exact suspicious binary identity;
- `Windows.Search.FileFinder` for known paths, filenames, or IOC patterns;
- `Windows.NTFS.MFT` for raw file presence and timestamp context;
- `Windows.Registry.Hunter[...]` for a bounded registry category;
- YARA artifacts for a bounded path, file, or process question;
- `exfiltration` only for a concrete staging or transfer hypothesis; and
- `network` only when live volatile state remains relevant.

### Bounded timeline

Use `--collection-type timeline` only after analysis identifies a suspicious
interval. Supply `--date-after`, `--date-before`, or both. It runs the Windows
MFT and EVTX pivots with the same bounds. Sampling or missing source coverage
must remain explicit.

## Review order

1. Confirm client ID, hostname/FQDN, OS, collection mode, request ID, flow IDs,
   run identity, and coverage.
2. Review DetectRaptor host leads in the canonical priority order.
3. Review execution evidence across independent sources. Do not infer execution
   from simple file or application presence.
4. Review Autoruns and persistence context. Zero rows on mapped dead-disk
   clients may be a collection limitation.
5. Review authentication, service creation, RDP, explicit logon, mounted
   resources, and public-IP context when relevant.
6. Correlate by user, path, hash, process, command, bounded time, and source
   record identifiers.
7. Run exact targeted follow-ups; do not rerun the whole baseline unless the
   operator explicitly requests `--force-run`.

Read [windows-artifact-analysis.md](windows-artifact-analysis.md) before making
strong execution, presence, user-activity, or registry-backed claims. Read
[windows-autoruns-analysis.md](windows-autoruns-analysis.md) for one-host
Autoruns and GoldenDB controls.

## Windows risk and coverage controls

- Treat Amcache, Shimcache, SRUM, UserAssist, Prefetch, BAM, PCA, and MFT as
  different evidence types with different limitations.
- Treat installed software, browser extensions, RMM, and YARA hits as leads,
  not proof of malicious execution.
- Require exact source context for suspicious normalized groups.
- Preserve signer, hash, path, command line, user, timestamps, host, client ID,
  flow ID, artifact, and source record identity when available.
- Treat `0` rows as absence only when artifact applicability, collection
  success, parameters, and adjacent-source coverage support that conclusion.
- Do not write GoldenDB changes from host analysis.

## Existing-export helpers

Use these only for already exported Windows evidence. They do not replace live
flow analysis.

Reuse the exact saved request or flow through `dfir analyze`; explicitly exported files can be reviewed with the detached-data skills.

Escalate a confirmed cross-host question to `velociraptor-hunting`; do not turn
one-host review into an implicit fleet hunt.

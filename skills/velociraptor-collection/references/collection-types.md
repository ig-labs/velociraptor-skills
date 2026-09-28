# Velociraptor Collection Types

## Contents

- Capability-aware IR bundles
- IR evidence groups
- Resolution and coverage semantics
- Legacy Windows baseline
- Focused collection types
- Heavy follow-ups
- Cross-platform use

## Capability-aware IR bundles

Use the versioned IR policy for new Windows incident-response collection:

- `ir-standard-live` selects all eight evidence groups for a running endpoint.
- `ir-standard-disk` selects the disk-applicable portions of the same groups and
  records volatile-only sources as `not_applicable`.

Resolve the collection against the connected server without finding, queueing,
or persisting any flows:

```bash
./dfir collect plan \
  --id IR1234 \
  --client-id C.0123456789abcdef \
  --bundle ir-standard-live
```

Run the same exact capability-aware request with safe reuse:

```bash
./dfir collection ensure \
  --id IR1234 \
  --client-id C.0123456789abcdef \
  --bundle ir-standard-live
```

Custom lane combinations use repeated `--collection-group` and require an
explicit `--target-mode live|mapped-disk`. Do not combine policy bundles or
groups with legacy `--collection-type`, explicit `--artifact`, or artifact
parameter flags.

## IR evidence groups

| Group | Evidence objective |
| --- | --- |
| `signal-triage` | Fast DetectRaptor-led lead finding across event logs, execution, browser/download, remote-tool, and selected process-memory signals. |
| `volatile-state` | Live processes, connections, DNS cache, and logged-in users. |
| `execution-history` | Corroborated Amcache, Prefetch, BAM, PCA, SRUM, UserAssist, and supporting execution traces. |
| `identity-state` | Local users, local administrators, hidden users, and active sessions. |
| `persistence-state` | Services, tasks, startup items, WMI persistence, and live Autoruns alternatives. |
| `authentication-lateral` | RDP, explicit logons, remote mounts, service-mediated execution, and optional site authentication summaries. |
| `script-execution` | PSReadLine, PowerShell script-block, and module evidence. |
| `defense-evasion` | Event-log tampering, boot changes, risky drivers, and library-search manipulation. |

Exact artifact alternatives, applicability, cost, and follow-up routing live in
`src/vraptor/resources/collection-groups.json`.
An explicit `VRAPTOR_COLLECTION_POLICY` file overrides this shared default.
Every candidate has a selection and interpretation profile in
`preferred-artifacts.json`; field projections remain conservative where no
representative server schema has been validated.

## Resolution and coverage semantics

- `core`: absence blocks an explicitly requested lane. In a standard bundle,
  that lane is marked `core_missing` while other resolvable lanes continue.
- `recommended`: collect when available; otherwise continue with a named
  coverage limitation.
- `optional`: collect when available; otherwise retain a lower-priority gap.
- target-inapplicable sources are `not_applicable`, never clean absence.
- alternatives are selected in policy order from the actual server inventory.
- one physical artifact is collected once even when it serves multiple logical
  groups; the resolution retains every group membership.

Collection state, export manifests, and coverage manifests retain the policy
id, schema version, canonical policy hash, selected alternatives, group status,
missing sources, and target applicability. The policy hash affects the saved
request id, while exact-flow reuse remains based on client, physical artifact,
effective parameters, and timeout.

## Legacy Windows baseline

`all` remains unchanged for compatibility and covers five collection scopes.
It is not an alias for either new IR standard bundle. The analysis runtime regroups
the returned components by source artifact before creating analyst tasks:

### triage

- DetectRaptor baseline excluding `DetectRaptor.Generic.Detection.YaraWebshell`
- `Windows.Detection.PublicIP`

The standalone `detectraptor` type retains the complete 12-artifact bundle, including
YaraWebshell, and excludes PublicIP. Direct `--artifact` collection also remains
available for YaraWebshell. Standalone `evtx` contains DetectRaptor EVTX plus PublicIP.
Standalone `mft` contains only DetectRaptor MFT, not the raw Windows MFT artifact.

The explicit `detectraptor` bundle is:

- `DetectRaptor.Windows.Detection.Evtx`
- `DetectRaptor.Windows.Detection.MFT`
- `DetectRaptor.Windows.Detection.Powershell.PSReadline`
- `DetectRaptor.Windows.Detection.Applications`
- `DetectRaptor.Windows.Detection.LolRMM`
- `DetectRaptor.Windows.Detection.Amcache`
- `DetectRaptor.Windows.Detection.BinaryRename`
- `DetectRaptor.Windows.Detection.Webhistory`
- `DetectRaptor.Windows.Detection.YaraProcessWin`
- `DetectRaptor.Generic.Detection.YaraWebshell`
- `DetectRaptor.Generic.Detection.BrowserExtensions`
- `DetectRaptor.Windows.Detection.ZoneIdentifier`

### network

- `Windows.Network.NetstatEnriched`
- `Windows.System.DNSCache`

This is live-only and not applicable to an offline or mapped-disk client.

### execution

- `Windows.Detection.Amcache`
- `Windows.Forensics.Bam`
- `Windows.Forensics.RecentFileCache`
- `Windows.Forensics.Timeline`
- `Windows.Forensics.SRUM`
- `Windows.System.AppCompatPCA`
- `Windows.Forensics.Prefetch`

### persistence-expanded

- `Windows.Sys.StartupItems`
- `Windows.System.Services`
- `Windows.System.TaskScheduler`
- `Windows.Registry.TaskCache.HiddenTasks`
- `Windows.Persistence.PermanentWMIEvents`
- `Windows.Sysinternals.Autoruns`

Standalone `persistence` contains only Autoruns.

### lateral-movement

- `Windows.EventLogs.RDPAuth`
- `Windows.EventLogs.ExplicitLogon`
- `Windows.Registry.MountPoints2`
- `Windows.EventLogs.ServiceCreationComspec`

## Focused collection types

`timeline`:

- `Windows.NTFS.MFT`
- `Windows.EventLogs.EvtxHunter`

`exfiltration`:

- `Windows.EventLogs.EvtxHunter`
- `Windows.NTFS.MFT`
- `Windows.Forensics.SRUM`
- `Windows.Forensics.Prefetch`

This focused type now requires both `--date-after` and `--date-before`, plus at
least one concrete `--mft-path-regex`, `--mft-file-regex`, or
`--evtx-ioc-regex`. The bounds are passed to raw MFT and EVTX Hunter; SRUM and
Prefetch remain supporting sources whose native collection parameters do not
use those generic bounds.

`registry`:

- `Windows.Registry.Hunter[all]`

## Heavy follow-ups

Keep raw MFT, broad EVTX Hunter, full Registry Hunter, Binary Hunter, FileFinder, and
wide YARA out of the standard baseline. Add only the smallest artifact and bounds that
answer the established question.

## Cross-platform use

Named groups are Windows-oriented. For Linux, run `artifacts linux-plan` against the
connected server inventory and execute its emitted explicit-artifact checks. For macOS,
select explicit server-supported artifacts. Do not assume Windows groups are portable.

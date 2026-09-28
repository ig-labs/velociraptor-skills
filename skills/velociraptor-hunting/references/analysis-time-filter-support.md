# Artifact-aware analysis time filters

Live hunt analysis applies timezone-aware, strict `(after,before)` predicates
inside `hunt_results()` or each batched `source()` query before transport. Host
analysis applies the same resolved predicate to a numbered exact `source()` query
before preferred-field projection and transport, while retaining original component
row ordinals and defensively rejecting any returned out-of-window row.
Repeated logical roles use OR semantics. With no bounds, all artifacts retain
the existing unfiltered behavior. A bounded mixed-artifact run filters only
verified profiles, leaves the other artifacts unfiltered, and records partial
time-filter coverage in state, command output, and `analysis-hunt.md`.
Artifact names containing the literal `EventLogs` default to `event=EventTime`
unless their explicit profile overrides the mapping or declares an empty
`time_filter` opt-out. `Windows.Detection.PublicIP` has the same mapping through
an explicit profile.

`time_bound_support` describes collection-time parameters such as `DateAfter`
and `DateBefore`. It is independent of `review.time_filter`, which describes
analysis-time result fields.

Status meanings:

- `confirmed`: live definition and representative result schema verified.
- `collection-only`: collection bounds exist, but analysis mapping is not enabled.
- `schema-required`: a plausible field exists in the definition, but no usable
  representative result schema was available.
- `unsupported`: no reliable emitted timestamp, or its format/semantics are unsafe.
- `state-time-only`: analysis can filter a file/registry state timestamp, not an
  event, execution, installation, or download time.

## IR9007-validated artifact families

| Artifact | Status | Analysis role or limitation | Collection bounds |
| --- | --- | --- | --- |
| `Windows.Detection.PublicIP` | confirmed | `event=EventTime` | yes |
| `Windows.EventLogs.RDPAuth` | confirmed | `event=EventTime` | yes |
| `IG.Windows.EventLogs.LateralMovement.RDP` | confirmed | `event=EventTime` | yes |
| `IG.Windows.EventLogs.LateralMovement.Kerberos` | confirmed | `event=EventTime` | yes |
| `IG.Windows.EventLogs.LateralMovement.LogonEvents` | confirmed | `event=EventTime` | yes |
| `IG.Windows.EventLogs.LateralMovement.NTLM` | confirmed | `event=EventTime` | yes |
| `Windows.EventLogs.PowershellModule` | confirmed | `event=EventTime` | yes |
| `Windows.EventLogs.PowershellScriptblock` | confirmed | `event=EventTime` | yes |
| `IG.Windows.EventLogs.PowershellScriptblock` | confirmed | `event=EventTime` | yes |
| `IG.Windows.EventLogs.ServiceCreations` | confirmed | `event=EventTime`; service-creation event time | no |
| `IG.Windows.Applications.RAT.AnyDesk` | confirmed | `log=Timestamp`; AnyDesk log-record time | yes |
| `Windows.Applications.AnyDesk` | confirmed | `log=Timestamp`; AnyDesk log-record time | yes |
| `Windows.Applications.TeamViewer.Incoming` | confirmed | `session=StartTime OR EndTime` | yes |
| `IG.Windows.EventLogs.Splashtop` | collection-only | Inherits bounded EVTX collection, but the live hunt had no result row to verify `EventTime` | yes |
| `DetectRaptor.Windows.Detection.Evtx` | confirmed | `event=EventTime` | yes |
| `IG.Windows.Master.ApplicationExecution` | schema-required | No shared parent field; supported and unsupported sources are listed below | no |
| `DetectRaptor.Windows.Detection.Webhistory` | confirmed | `visit=ArtifactData.Visit_Date OR ArtifactData.Last_Visit_Date`; `download=ArtifactData.Download_Date` | no |
| `DetectRaptor.Windows.Detection.ZoneIdentifier` | state-time-only | `mtime/btime/ctime/atime=HostTimestampsSI.*`; no MOTW or browser-download timestamp | no |
| `DetectRaptor.Windows.Detection.MFT` | confirmed | `mtime=SITimestamps.LastModified0x10 OR FNTimestamps.LastModified0x30`; `btime=SITimestamps.Created0x10 OR FNTimestamps.Created0x30` | yes |
| `Windows.NTFS.MFT` | confirmed | `mtime=LastModified0x10`; `btime=Created0x10`; optional `ctime` and `atime` | yes |
| `DetectRaptor.Windows.Detection.LolDriversMalicious` | schema-required | Definition can emit `KeyMTime`; no representative result rows | no |
| `DetectRaptor.Windows.Detection.LolDriversVulnerable` | schema-required | Definition can emit `KeyMTime`; no representative result rows | no |
| `DetectRaptor.Windows.Detection.HijackLibsEnv` | unsupported | No reliable emitted timestamp | no |
| `DetectRaptor.Windows.Detection.HijackLibsMFT` | unsupported | Definition constructs MFT times, but observed results omit them | no |
| `DetectRaptor.Windows.Detection.Bootloaders` | state-time-only | file `mtime/btime/ctime/atime=Mtime/Btime/Ctime/Atime` | no |
| `Windows.EventLogs.Cleared` | confirmed | `event=EventTime` | yes |
| `Windows.EventLogs.Modifications` | state-time-only | source-specific `mtime=Mtime`; registry key last-write, not event time | yes |
| `Windows.EventLogs.ScheduledTasks` | confirmed | `event=EventTime` | yes |
| `IG.Windows.EventLogs.Ntdsutil` | confirmed | `event=EventTime` | no |
| `Windows.Persistence.PermanentWMIEvents` | unsupported | Current WMI binding state has no reliable creation/modification time | no |
| `Windows.System.WMIProviders` | unsupported | Current provider registration has no reliable registration/file time | no |
| `Windows.Analysis.SuspiciousWMIConsumers` | unsupported | Current consumer/filter state has no reliable creation/modification time | no |
| `IG.Windows.Registry.HiddenTasks` | unsupported | `Date` was present but empty in representative rows | no |
| `Windows.Registry.TaskCache.HiddenTasks` | unsupported | `Date` was present but empty in representative rows | no |

## ApplicationExecution source policy

The parent wrapper expands into source artifacts. Exact source profiles are
required for time filtering; an unknown source remains unfiltered.

| Source | Status | Analysis role or limitation |
| --- | --- | --- |
| `ShimCache` | state-time-only | `mtime=ModificationTime`; cache state, not execution time |
| `Amcache` | state-time-only | `record=Timestamp`; inventory/key time, not proof of execution; inconsistent `InstallDate` excluded |
| `Windows10Timeline` | confirmed | `execution=LastModifiedTime` |
| `BAM` | schema-required | Definition emits `Bam_time`; no representative wrapper result row |
| `SRUM` | schema-required | Underlying sources vary across `TimeStamp`, `StartTime`, and `EndTime`; no representative wrapper row |
| `SRUMInventory` | unsupported | `Timestamp` values were empty or non-ISO identifier content |
| `Prefetch` | confirmed | default `execution=event_time`; optional `mtime=prefetch_mtime`, `btime=prefetch_ctime` |
| `CommandExecutedRunDialog` | state-time-only | `mtime=event_time`; RunMRU key last-write, not confirmed command execution |
| `CapabilityAccessManager` | schema-required | Definition emits `LastUsedTimeStart/Stop`; no representative wrapper row |
| `UserAssist` | confirmed | `execution=LastExecution`; some rows may be null |
| `ProcessTracking` | schema-required | Definition emits `EventTime`; no representative wrapper row |
| `ProgramCompatibilityAssistant` | confirmed | `event=EventTime` |
| `RecentApps` | confirmed | `execution=LastExecution` |
| `AppCompatPCA` | unsupported | `LastExecuted` is a raw date-time string without verified timezone semantics |

Do not promote a `schema-required` or `unsupported` entry from row-key guessing.
Recheck `artifact_definitions()` and a representative live result schema, then
update the canonical profile and tests together.

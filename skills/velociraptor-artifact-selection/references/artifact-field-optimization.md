# Velociraptor Artifact Field Optimization

Use this reference when selecting artifacts, reviewing proposed fields,
projecting large exports into slim review files, or deciding which exporter
should be optimized.

The executable source of truth is
`../../../src/vraptor/resources/preferred-artifacts.json`
including accepted `review.vql_select` analysis and extraction projections,
`review.live_vql_select` bounded in-memory projections,
plus the curated VQL exporters under
`../../../src/vraptor/resources/vql/`.
Use this Markdown as the human review checklist. Apply accepted field-policy
changes to the canonical JSON or exporter rather than treating this file as
runtime configuration.

## Contents

- [Field-handling contract](#field-handling-contract)
- [Registry Hunter narrowing](#registry-hunter-narrowing)
- [DetectRaptor review](#detectraptor-review)
- [Execution](#execution)
- [Persistence](#persistence)
- [Authentication and lateral movement](#authentication-and-lateral-movement)
- [System inventory](#system-inventory)
- [Deep and targeted follow-up](#deep-and-targeted-follow-up)
- [Optimization priorities](#optimization-priorities)

## Field-Handling Contract

Keep these layers separate:

- `review.live_vql_select` is the shared bounded live projection. Live hunts
  keep `Fqdn` for row-to-host attribution.
- Exact-client host analysis removes simple `Fqdn` and `Hostname` expressions
  from that projection before querying. It already owns the resolved hostname,
  retains `ClientId` for source provenance, and keeps artifact-native context
  such as EVTX `Computer`.
- Do not project a missing `Fqdn` merely to obtain a blank value: Velociraptor
  may reject the query at symbol resolution before any blank fallback applies.

1. **Authoritative source**
   Preserve the complete result on Velociraptor, or create an explicit full
   export when local field-for-field preservation is required. A projected
   snapshot is a bounded analysis source, not a complete raw export.
2. **Slim review projection**
   Select the fields listed below for routine analyst or model review.
3. **Stack/index projection**
   Use the listed normalized dimensions for prevalence, grouping, or search.
4. **Provenance**
   Preserve the host, client id, artifact, flow id, request id, collection
   parameters, and source file in the surrounding manifest. Single-host review
   rows do not need to repeat all of that data when the manifest binds it
   unambiguously.

Field names under **Review fields** come from the canonical
`preferred-artifacts.json` profile unless an explicit curated export schema is
shown. Treat fields marked **unprofiled** as runtime schema: inspect a real
export header before adding a projection.

For live hunt stacking only, an unprofiled artifact may use the guarded
ephemeral fallback in `field-selection-rules.md`: derive statistics from 10-20
transient rows, validate AI-returned field names deterministically, and run a
complete rare-first server aggregate. This does not establish a canonical
projection and must never update `preferred-artifacts.json` automatically.

Large values such as `Message`, `EventData`, `UserData`, `Details`,
`FailureActions`, certificate objects, and nested hash objects should remain in
raw evidence. Put bounded snippets or selected nested members in the slim
review file.

## Registry Hunter Narrowing

When the live artifact exposes the parameters:

- use `IocRegex` for explicit registry IOC or string search
- use `ModifiedAfter` and `ModifiedBefore` to bound results by registry-key
  `Mtime`
- combine these with one category-scoped preset where possible

Treat `Mtime` as registry-key modification context. It is not direct evidence
of execution, persistence creation, or the write time of one specific value.
Keep `Mtime` in review output and preserve all collection parameters in the
manifest. Do not add Registry Hunter to a default timeline collection; select
it as an explicit adjacent lane when the investigation requires registry
evidence.

## DetectRaptor Review

These artifacts have review and stack fields defined. Snapshot projections may
reduce result width before transport when the global projection reference
defines a validated schema.

### `DetectRaptor.Windows.Detection.Evtx`

- Review fields:
  `Detection`, `Evidence`, `EventTime`, `Channel`, `EventID`, `Username`,
  `Fqdn`
- Direct live fields:
  `Detection`, `EventTime`, `Channel`, `EventID`, `Username`, `Computer`,
  `ClientId`, `Fqdn`, `EvidencePath`, `Evidence`
- Grouped live fields:
  `Detection`, exact payload field/value, `FirstSeen`, `LastSeen`, `count`;
  machine and individual timestamp fields are hydrated only for interesting groups
- Stack/index fields:
  - scope guidance only: `DetectionIdentity`
  - exact-payload reduction is owned by the automatic EVTX planner
- Optimization:
  select `Detection.Name AS Detection`; select `Message` when present and
  otherwise `EventData` as `Evidence`. The server-side hunt remains the source
  for omitted fields.
- Large-value handling:
  direct review returns complete evidence; exact-stack review returns one
  complete payload per exact group.
  Full hunt analysis partitions by `Detection.Name`. Large detections run an
  exhaustive exact-payload census and use every group only when consolidation
  is material; otherwise they stream directly. No samples or exclusions are
  applied. Only groups classified `notable` or `suspicious` are batch-queried
  for timestamp and machine context, with no second semantic pass.

### `DetectRaptor.Windows.Detection.Applications`

- Review fields:
  `Category`, `Regex`, `DisplayName`, `DisplayVersion`, `KeyName`,
  `InstallLocation`, `InstallSource`, `UninstallString`, `Publisher`,
  `ClientId`, `Fqdn`, `KeyLastWriteTimestamp`
- Stack/index fields:
  - application identity, preferring `Category`, `Regex`, `DisplayName`,
    `Name`, then `KeyName`;
  - application identity and `DisplayVersion`;
  - application identity and `NormalizedInstallLocation`;
  - application identity and `NormalizedInstallSource`;
  - application identity and `Publisher`.
- Optimization:
  normalize user-profile path segments only in stack keys. Retain original
  install paths, installation sources, usernames, publisher, and hash context
  in raw evidence and model-review records for attribution.

### `DetectRaptor.Windows.Detection.Powershell.PSReadline`

- Review fields:
  `RuleID`, `RuleName`, `RuleRegex`, `Line`, `LineNum`, `Username`,
  `FileInfo`, `ClientId`, `Fqdn`
- Stack/index fields:
  `RuleIdentity`, `NormalizedCommand`
- Optimization:
  retain the original `Line` in exact source context; stack by rule identity
  and normalized command. `FileInfo` timestamps describe the history file and
  are not per-command execution timestamps.

### `DetectRaptor.Windows.Detection.MFT`

- Review fields:
  `Detection.Name`, `Detection.Criticality`, `Detection.StringHit`,
  `Detection.KeywordRegex`, `Detection.PathRegex`, `Detection.IgnoreRegex`,
  `OSPath`, `EntryNumber`, `FileSize`, `SITimestamps`, `FNTimestamps`,
  `ClientId`, `Fqdn`
- Stack/index fields:
  `DetectionIdentity`, `Detection.Criticality`, `Detection.StringHit`,
  `NormalizedPath`
- Optimization:
  prioritize criticality and detection identity, then normalized path and
  string hit before retrieving exact SI/FN timestamp context.

### `DetectRaptor.Windows.Detection.ZoneIdentifier`

- Review fields:
  `DownloadedFilePath`, `HostUrl`, `ReferrerUrl`, `FileHash`, `ClientId`,
  `Fqdn`, `Timestamp`
- Stack/index fields:
  `HostUrl`, `NormalizedPath`
- Optimization:
  extract hostname/domain from URLs for indexing while retaining complete URLs
  in raw evidence.

## Execution

### `Windows.System.Pslist`

- Review fields:
  `Name`, `Exe`, `AuthenticodeTrusted`, `CommandLine`, `Pid`, `Ppid`,
  `Username`, `TokenIsElevated`, `CreateTime`, `Authenticode`, `Hash`
- Stack/index views:
  - default process trust: `Name`, `Exe`, `AuthenticodeTrusted`
  - complete process identity: `Name`, `Exe`, `CommandLine`
- Stack semantics:
  use `Authenticode.Trusted AS AuthenticodeTrusted` to keep trusted,
  untrusted, and missing trust results distinct for the same image path.
  `AuthenticodeTrusted` is a trust-validation result, not proof that a
  certificate merely exists. Use the secondary complete-process-identity view
  when command-line variation is the analytical question.
- Optimization:
  keep the complete command line, process and parent identifiers, user, full
  Authenticode object, hash, and creation time as representative-row context.

### `Windows.Detection.Amcache`

- Review fields:
  `FullPath`, `SHA1`, `ProgramID`, `FileDescription`, `FileVersion`,
  `Publisher`, `CompileTime`, `LastModified`, `LastRunTime`
- Stack/index fields:
  `NormalizedPath`, `SHA1`, `ProgramID`
- Export status:
  generic full export
- Optimization:
  keep path, SHA1, publisher/version, and all three timestamps in the slim
  execution view.

### `Windows.Forensics.Bam`

- Review fields:
  `Binary`, `User`, `LastExecution`, `KeyLastWriteTimestamp`, `FullPath`
- Stack/index fields:
  `NormalizedPath`
- Export status:
  generic full export
- Optimization:
  normalize `Binary`/`FullPath` into one path field but retain both source
  values when they differ.

### `Windows.Forensics.RecentFileCache`

- Export status:
  generic `SELECT *`
- Review profile:
  analysis-time `event=EventTime`; field projection remains unprofiled
- Optimization:
  inspect a current export header, then pin path/name, file identity, cache
  timestamp, and available version/hash fields. Do not guess a stable schema.

### `Windows.Forensics.Timeline`

- Export status:
  generic `SELECT *`
- Review profile:
  **unprofiled**
- Optimization:
  inspect each emitted result component. Define separate projections for
  activity timestamp, application, file/path, user, activity type, and source
  database instead of flattening unrelated timeline scopes together.

### `Windows.Forensics.SRUM`

- Export components:
  - `Windows.Forensics.SRUM/Execution Stats`
  - `Windows.Forensics.SRUM/Application Resource Usage`
  - `Windows.Forensics.SRUM/Network Connections`
  - `Windows.Forensics.SRUM/Network Usage`
- Common review fields:
  `Timestamp`, `AppId`, `User`, `BytesSent`, `BytesReceived`, `Interface`
- Stack/index fields:
  `AppId`
- Optimization:
  create a field projection per component. Do not assume one SRUM component
  contains all six common fields.

### `Windows.System.AppCompatPCA`

- Export status:
  generic `SELECT *`
- Review profile:
  **unprofiled**
- Optimization:
  inspect a current export header, then pin executable path/name, launch time,
  user, run status, and source PCA record fields.

### `Windows.Forensics.Prefetch`

- Review fields:
  `Binary`, `CreationTime`, `LastRunTimes`, `RunCount`, `Hash`
- Stack/index fields:
  `Binary`, `Hash`
- Export status:
  generic full export
- Optimization:
  keep `LastRunTimes` as an array in raw evidence; emit one bounded display
  value or normalized child rows only in derived review output.

### `Windows.Registry.Hunter[execution]` — execution views

Collect the `Program Execution` category only. Do not run
`Windows.Registry.Hunter[all]` merely to produce these execution views.

#### AppCompatCache

- Curated fields:
  `filename`, `LastMod`, `Execution`, `Stat`, `Hashes`, `Magic`, `Signatures`
- Stack/index fields:
  normalized `filename`, selected hash members

#### UserAssist

- Curated fields:
  `User`, `Program`, `NumberOfExecutions`, `LastExecutionTime`, `Stat`,
  `Hashes`, `Magic`, `Signatures`
- Stack/index fields:
  `Program`, optionally `User`

#### RADAR

- Current curated query:
  `SELECT *` from `Details.Programs`
- Optimization:
  sample the live nested schema and pin program path/name, user or SID,
  execution/termination timestamps, and available metadata.

#### BAM

- Current curated query:
  `SELECT *` from `Details.Programs`
- Optimization:
  sample the live nested schema and pin binary path, user/SID, execution time,
  and registry-key timestamp.

#### General Program Execution category

- Curated fields:
  `Description`, `Key`, `Mtime`, `Details`
- Optimization:
  use only as a fallback exploration view; prefer the four execution-specific
  projections above.

## Persistence

### `Windows.Sys.StartupItems`

- Export status:
  generic `SELECT *`
- Review profile:
  **unprofiled**
- Optimization:
  inspect a current export header, then pin entry name, source/category,
  executable or command, path, user scope, timestamp, signer, and hashes when
  available.

### `Windows.System.Services`

- Review fields:
  `Name`, `DisplayName`, `State`, `Status`, `StartMode`, `ServiceType`,
  `UserAccount`, `Created`, `PathName`, `AbsoluteExePath`, `ServiceDll`,
  `FailureCommand`, `FailureActions`, `HashServiceExe`, `CertinfoServiceExe`,
  `HashServiceDll`, `CertinfoServiceDll`
- Independent stack/index views:
  - service identity: `Name`
  - executable: `NormalizedPath`
  - DLL: `NormalizedServiceDll`
  - account: `UserAccount`
  - executable hash: `HashServiceExe.SHA256`
  - DLL hash: `HashServiceDll.SHA256`
  - failure command: `NormalizedFailureCommand`
  - start mode: `StartMode`
  - drift view: `Name`, `NormalizedPath`
- Optimization:
  do not combine every dimension into one stack. Keep each rarity question
  independent.

### `Windows.System.TaskScheduler`

- Export status:
  generic `SELECT *`
- Review profile:
  **unprofiled**
- Optimization:
  inspect a current export header, then pin task path/name, enabled/hidden
  state, principal/user, action command, arguments, working directory,
  triggers, registration/last-run times, and task XML provenance.

### `Windows.Registry.TaskCache.HiddenTasks`

- Export status:
  generic `SELECT *`
- Review profile:
  **unprofiled**
- Optimization:
  inspect a current export header, then pin task name/path, GUID, registry key,
  SD presence/status, command/action, user/SID, and relevant timestamps.

### Category-scoped `Windows.Registry.Hunter` — persistence views

- `Persistence`, `Services`, and `Autoruns` curated fields:
  `Description`, `Key`, `Mtime`, `Details`
- Optimization:
  collect only the required category preset and prefer dedicated artifacts
  when they answer the question;
  retain `Details` in raw evidence and derive normalized command/path,
  value-name, account, and hash fields where the category payload exposes them.

### `Windows.Persistence.PermanentWMIEvents`

- Review fields:
  `Consumer`, `Filter`, `CommandLine`, `User`, `Query`, `EventNamespace`
- Stack/index fields:
  `Consumer`, `Filter`, `NormalizedCommand`
- Export status:
  generic full export
- Optimization:
  keep filter and consumer identities together in review rows. Treat zero rows
  on mapped dead-disk clients as a collection limitation.

### `IG.Windows.Sysinternals.Autoruns` and `Windows.Sysinternals.Autoruns`

- Live review fields:
  `Entry`, `Category`, `Profile`, `Description`, `Signer`, `ImagePath`,
  `Version`, `LaunchString`, `SHA256`, `Fqdn`, `ClientId`
- First pivot:
  `Category`
- In-category grouping:
  exact hash of entry, profile, description, signer, image path, version,
  launch string, and SHA-256. Host identity is not part of the grouping key.
- Normalized reduction:
  case-normalized `Entry`, `ImagePath`, and `Signer`, plus group count. This
  compact stack is reviewed directly when it fits the evidence budget.
  Suspicious groups are requeried to return original entries, launch strings,
  hashes, `Fqdn`, and `ClientId`. A clearly benign group may close directly
  after explicit DLL/.NET hijack-risk review. Multiple or unresolved exact
  variants require additional variant-risk review or drill-down.
- Optimization:
  both artifact names use the same artifact profile. This prevents equivalent
  Autoruns output from receiving different projections or pivot behavior.
  category is persistence-mechanism context, not a suppression field. Review
  user-writable or missing scheduled-task targets, WMI consumers, boot-execute
  values, and Image Hijacks before broad Drivers or Services inventories.

## Authentication and Lateral Movement

### `Windows.Detection.PublicIP`

- Export status:
  generic `SELECT *`
- Review profile:
  **unprofiled**
- Optimization:
  inspect a current export header, then pin public IP, source/interface,
  observation time, lookup/provider, and available hostname/client context.

### `Windows.EventLogs.RDPAuth`

- Curated export fields:
  `EventTime`, `Channel`, `EventID`, `DomainName`, `UserName`, `LogonType`,
  `SourceIP`, `Description`, `EventRecordID`
- Stack/index fields:
  `SourceIP`, `EventID`
- Optimization:
  derive normalized account as `DomainName\UserName`; keep `EventRecordID` for
  exact event provenance.

### `Windows.EventLogs.ExplicitLogon`

- Curated export fields:
  `EventTime`, `EventID`, `EventRecordID`, `SubjectUserName`,
  `SubjectDomainName`, `TargetUserName`, `TargetDomainName`,
  `TargetServerName`, `ProcessName`, `EventData`, `Message`
- Stack/index fields:
  `ProcessName`, `TargetServerName`
- Optimization:
  derive normalized subject and target accounts. Keep `EventData` and
  `Message` in raw evidence and bounded snippets in review output.

### `Windows.Registry.MountPoints2`

- Export status:
  generic `SELECT *`
- Review profile:
  **unprofiled**
- Optimization:
  inspect a current export header, then pin user/SID, mounted target,
  drive/share/volume identity, registry key, and key modification time.

### `Windows.EventLogs.ServiceCreationComspec`

- Review fields:
  `ServiceName`, `ImagePath`, `AccountName`, `Message`, `ClientId`, `Fqdn`,
  `Timestamp`
- Stack/index fields:
  `ServiceName`, `NormalizedPath`
- Export status:
  generic full export
- Optimization:
  retain the full service command in raw evidence and split executable path
  from arguments in derived review output.

## System Inventory

Registry-backed system inventory uses explicit category-scoped Registry Hunter
presets. Do not collect `[all]` to obtain a single inventory category.

Each of these views currently exports:
`Description`, `Key`, `Mtime`, `Details`.

- `System Info`
- `Installed Software`
- `User Accounts`
- `Devices`
- `Volume Shadow Copies`
- `Cloud Storage`
- `Web Browsers`
- `Network Shares`
- `Third Party Applications`
- `Microsoft Office`
- `Microsoft Exchange`

Optimization:

- retain `Details` in the raw category export
- derive category-specific slim fields rather than applying one universal
  projection
- normalize software names/versions/publishers
- normalize user names/SIDs and account status
- normalize device or volume identifiers
- normalize share paths and cloud-storage roots
- keep `Key` and `Mtime` for registry provenance

## Deep and Targeted Follow-Up

### `Windows.NTFS.MFT`

- Curated export fields:
  `EntryNumber`, `ParentEntryNumber`, `InUse`, `OSPath`, `FileSize`,
  `Created0x10`, `Created0x30`, `LastModified0x10`, `LastModified0x30`,
  `LastRecordChange0x10`, `LastRecordChange0x30`, `LastAccess0x10`,
  `LastAccess0x30`
- Stack/index fields:
  filename and extension derived from `OSPath`, plus `NormalizedPath`
- Optimization:
  the current fixed projection is appropriate. Add derived filename and
  extension only in review output.

### `Windows.EventLogs.EvtxHunter`

- Curated export fields:
  `EventTime`, `Provider`, `EventID`, `EventRecordID`, `UserSID`, `Username`,
  `EventData`, `UserData`
- Review-only optional field:
  `Message` when the selected artifact output provides it
- Optimization:
  use bounded keyword snippets for large `EventData` or `UserData` values.

### `Windows.Search.FileFinder`

- Review fields:
  `OSPath`, `Name`, `Size`, `Mtime`, `Btime`, `Hash`, `ClientId`, `Fqdn`
- Stack/index fields:
  `Name`, `NormalizedPath`, `Hash`
- Export status:
  generic full export

### `Windows.Detection.BinaryHunter`

- Current host-analysis field contract:
  exact file path, `MD5`, `SHA1`, `SHA256`, file version, PE compile timestamp,
  signer subject, signer issuer, import hash, notable imports, PDB path, and
  threat-intelligence value when enrichment is performed
- Export profile:
  **unprofiled**
- Optimization:
  add a canonical artifact profile only after validating the exact live artifact
  schema and nested hash/certificate field names.

## Optimization Priorities

Prioritize changes in this order:

1. Add canonical profiles and fixed derived projections for the currently
   unprofiled baseline artifacts:
   `Windows.Forensics.RecentFileCache`,
   `Windows.Forensics.Timeline`,
   `Windows.System.AppCompatPCA`,
   `Windows.Sys.StartupItems`,
   `Windows.System.TaskScheduler`,
   `Windows.Registry.TaskCache.HiddenTasks`,
   `Windows.Network.NetstatEnriched`,
   `Windows.System.DNSCache`,
   `Windows.Detection.PublicIP`, and
   `Windows.Registry.MountPoints2`.
2. Add component-specific SRUM projections.
3. Replace the Registry Hunter RADAR and BAM nested `SELECT *` review queries
   with validated field lists.
4. Normalize aliases between artifact profiles and curated exports, especially
   `Timestamp` versus `EventTime`, `User` versus `UserName`, and
   `TargetServer` versus `TargetServerName`.
5. Add category-specific Registry Hunter derived views instead of passing the
   entire nested `Details` value to routine model review.
6. Keep generic full exports as raw evidence and write slim files alongside
   them. Do not optimize by destructively removing source evidence.

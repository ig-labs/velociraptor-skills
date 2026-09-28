# Shared DetectRaptor Analysis Contract

Use this contract for both fleet hunts and one-host DetectRaptor collections.
Apply the evidence-boundary adapter in the calling skill after these common
rules.

The machine-readable priority, stack, disposition, and ownership contract is
[`detectraptor-analysis-contract.json`](../../src/vraptor/resources/contracts/detectraptor-analysis-contract.json).

## Common operating rules

- Treat every DetectRaptor result as a lead, not proof.
- Fleet hunt analysis defaults to accounted streaming, not generic stack
  analysis. EVTX automatically reviews small detections directly and may group
  large detections by exact script-block payload after an exhaustive census,
  falling back to serialized message/event data when no script block exists.
  Group counts account for every source row with no signature ceiling, hash
  equivalence, sampling, or exclusions. Every group is reviewed once with its
  complete exact payload; only groups classified `notable` or `suspicious` are
  batch-queried for timestamp and machine context, with no second AI pass. Configured
  stack IDs otherwise define review-field priority and bounded follow-up pivots.
- Keep Velociraptor hunt, flow, artifact, parameters, and source rows
  authoritative.
- Record source state, artifact/version, effective parameters, time bounds,
  row counts, result-review coverage, and reduction limitations.
- Keep complete review of returned rows separate from complete endpoint,
  artifact, or telemetry coverage.
- Review complete approved reductions before retrieving exact source context
  for suspicious or ambiguous groups.
- Preserve stable rule identity and the rule metadata that caused the match.
- Keep presence, historical activity, current execution, network activity,
  and external intelligence classification as separate claims.
- Require independent corroboration before asserting malicious activity.
- Treat PSReadLine absence as unknown coverage rather than negative evidence.

## Priority and review stacks

Review the configured stacks in this order, then every other returned
DetectRaptor artifact:

| Rank | Artifact | Stack order |
| --- | --- | --- |
| 1 | `DetectRaptor.Windows.Detection.Evtx` | `detection` scope guidance; automatic exact-payload planner owns reduction |
| 2 | `DetectRaptor.Windows.Detection.MFT` | `criticality_detection`, `detection_path`, `string_hit` |
| 3 | `DetectRaptor.Windows.Detection.Powershell.PSReadline` | `rule`, `command`, `rule_command` |
| 4 | `DetectRaptor.Windows.Detection.Applications` | `category_application`, `application`, `application_version` |
| 5 | `DetectRaptor.Windows.Detection.LolRMM` | `rmm_application`, `install_location` |
| 6 | `DetectRaptor.Windows.Detection.Amcache` | `criticality_detection`, `detection_path`, `hash` |
| 7 | `DetectRaptor.Windows.Detection.BinaryRename` | `rename_identity`, `path`, `hash` |
| 8 | `DetectRaptor.Windows.Detection.Webhistory` | `category_domain`, `browser_domain` |
| 9 | `DetectRaptor.Windows.Detection.YaraProcessWin` | `rule_process`, `rule_path` |
| 10 | `DetectRaptor.Generic.Detection.YaraWebshell` | `rule_tags`, `rule_path` |
| 11 | `DetectRaptor.Generic.Detection.BrowserExtensions` | `threat_type`, `extension`, `path_version` |

Within LolRMM rank 5, keep named sources independent and review:

- `DetectRaptor.Windows.Detection.LolRMM/Processes` as `rmm_process`,
  `executable`, then `command_line`; and
- `DetectRaptor.Windows.Detection.LolRMM/ResolvedDomains` as `rmm_domain`,
  then `dns_record`.

Do not silently substitute an unknown stack. Validate stack IDs against the
resolved artifact profiles before analysis.

## Evidence preservation

Retain these common fields when available:

- hunt ID or client/flow IDs;
- artifact and source component;
- rule ID, name, regex, ignore condition, criticality, and tags;
- host/client, user, bounded time, event or record identity;
- command, filename, original filename, path, hash, signer, and version;
- URL, domain, browser/profile, process, PID, matched string, offset, and
  bounded context; and
- query/filter hashes, reduction counts, review IDs, and exact context
  references.

Do not persist bulk result rows during normal live analysis. Use the shared
Velociraptor persistence policy for complete required aggregates and exact
finding-linked context.

Keep exact rows in memory by default. Normal live analysis may write the
bounded `analysis/finding-evidence.md` supplement for manager-selected findings
or ambiguous review context. It retains authoritative references and only the
selected full representatives; this is not authorization for a bulk export.

## Cross-artifact correlation

Correlate by:

- endpoint and stable client identity;
- user or account;
- bounded time;
- process, parent/child behavior, command, and executable;
- normalized path, filename, original filename, hash, signer, and version;
- URL, domain, browser/profile, network identity, and RMM family;
- rule identity, detection family, and criticality.

Prefer independent evidence lanes. Two rows generated from the same source or
the same upstream rule are not independent corroboration.

Only claim temporal correlation when each evidence lane has a semantically
valid event or observation time. Collection time can bound a current-state
snapshot but is not process start, DNS-resolution, browser-visit, or command
execution time.

## Artifact interpretation

### EVTX

For fleet live-hunt analysis, discover every in-scope detection name and record
row/evidence-size metrics. Stream small detections directly. For large
detections, run an exhaustive exact-payload census and stream every group
rare-first only when reduction is material; otherwise use direct review. Apply
any regex/time predicates to discovery, census, analysis, and selected-evidence
requeries. Do not sample, hash, exclude, or cap exact groups. Preserve
`Detection.Name`, `Detection.EventId`, `Detection.Regex`,
`Detection.Ignore`, channel, event ID, event time, user, computer,
`EventData`, and `Message`.

Discovery is a lower bound: represented rows may exceed it while a hunt grows,
but must never be lower. Grouped review sends the complete exact payload, count,
and first/last timestamps through the normal bounded CSV analyst workflow once.
Use `_SourceRef` plus the standard sparse `reference-line-v3` response; clean
groups require no per-group record. `Payload` is the final CSV column and normal
CSV quoting preserves commas, tabs, quotes, and embedded newlines. Batch-query
timestamps and machines only for source references returned in findings, then
attach those rows without another semantic AI pass. Direct review receives
complete evidence. The sparse protocol may also return only high-confidence
reusable benign candidates with `global` or `site` scope. Python, not the model,
copies each candidate's complete exact payload into the trailing `Payload`
column of `analysis/detectraptor_whitelist_candidates.csv`; standard CSV quoting
preserves commas, tabs, quotes, and newlines. Do not emit one record per benign
group. The candidate ledger is review-only: do not generate or apply an ignore
rule or automatically mutate DetectRaptor. Keep host identities and payloads out
of recovery/control state.

### MFT

Review criticality and detection identity, normalized path and string hit,
then exact SI/FN timestamps and file metadata. Pivot to raw MFT or FileFinder
for path and timeline precision. Preserve rule regex metadata, `OSPath`,
`EntryNumber`, `FileSize`, `SITimestamps`, and `FNTimestamps`.

### PSReadLine

Review rule identity, normalized command variants, then exact line, user, line
number, and history-file metadata. Correlate with EVTX, process, and file
evidence. Preserve `RuleID`, `RuleName`, `RuleRegex`, `Line`, `LineNum`,
`Username`, and `FileInfo`. `FileInfo` timestamps describe the history file;
they are not per-command execution timestamps. Establish command timing from
PowerShell, process-creation, Sysmon, or Security event evidence.

### Applications

Review category, display name/version, install location/source, publisher,
uninstall command, registry path, and key last-write time. Installed presence
does not establish execution.

### LolRMM

Keep installed-program, process, command-line, executable, signer/version,
and resolved-domain sources distinct. Authorization is host- and time-specific.
Deduplicate summaries without discarding original source attribution. A
Webhistory record is browser evidence, not proof of DNS resolution; retain the
LolRMM resolved-domain source when making a DNS claim. Current LolRMM process
and resolved-domain profiles have no declared timestamp field. Treat them as
collection-time observations unless exact nested source data or an independent
artifact supplies a valid event time; do not place them in a narrower temporal
sequence otherwise.

### Amcache

Review criticality, detection identity, path, entry/original filename,
publisher, SHA-1, and key modification time. Treat it as historical presence
or execution-adjacent metadata requiring corroboration.

### BinaryRename

Compare observed filename with PE original/internal filename, full path, hash,
signer/version, and filesystem timestamps. Prioritize renamed system tools,
user-writable paths, unsigned binaries, and uncommon hashes.

### Webhistory

Review category/domain, complete URL, browser artifact, user, title,
visit/download time, target path, referrer, and browser database. A
domain-category match is a lead.

### YaraProcessWin

Review rule, namespace, metadata, process, executable, command line, PID,
matched string, offset, and bounded context. Corroborate with signer, network,
and on-disk evidence. Treat process dumps as sensitive evidence.

### YaraWebshell

Review rule, tags, metadata, target path, file metadata, matched string,
offset, and bounded context. Confirm deployment or reachability in a web root.
A YARA match alone does not establish webshell execution.

### BrowserExtensions

Review extension ID/name, category, threat type, reference URL, known CRX
SHA-256, observed version, source path, modification time, browser/user scope,
and enabled/installed state. External classification is enrichment, not proof.

## Dispositions

Use exactly:

- `suspicious`: corroborated or independently high-confidence malicious lead;
- `notable`: security-relevant but not established malicious activity;
- `expected`: explained authorized activity with adequate evidence;
- `false_positive`: matched behavior outside the intended rule semantics; or
- `unresolved`: insufficient evidence.

Record disposition, rationale, observed count, source references, and next
exact pivot for every reviewed candidate.

## Detection uplift

Before proposing reusable logic changes, record the upstream commit SHA or
content hash and the applicable source:

- EVTX: `csv/Eventlogs.csv` and generated `vql/Evtx.yaml`
- MFT: `csv/MFT.csv` and generated `vql/MFT.yaml`
- PSReadLine: generated `vql/PSReadline.yaml`
- Applications: `csv/InstalledSoftware.csv` and generated
  `vql/Applications.yaml`
- LolRMM: `csv/lolrmm.csv` and generated `vql/LolRMM.yaml`
- Amcache: `csv/MFT.csv` and generated `vql/Amcache.yaml`
- BinaryRename: `csv/ExeOriginalName.csv` and generated
  `vql/BinaryRename.yaml`
- Webhistory: `csv/WebBrowsers.csv` and generated `vql/Webhistory.yaml`
- YaraProcessWin, YaraWebshell, and BrowserExtensions: generated VQL and
  embedded or fetched rule/intelligence sources

Each proposal must include artifact, source file, stable rule identity,
problem class, sanitized evidence pattern, observed scope, proposed change,
regression risk, positive/negative tests, performance impact, acceptance
criteria, and status.

Validate against reviewed true positives, reviewed false positives,
representative benign data, casing/escaping/path boundary collisions, and
expected row-count/runtime impact. Never add a broad ignore merely to reduce
review workload. Keep environment-only exceptions in a scoped site overlay
with provenance, ownership, and review expiry.

## Evidence-boundary adapters

| Boundary | Allowed reasoning | Prohibited shortcut |
| --- | --- | --- |
| Fleet hunt | Prevalence, distinct-host counts, cross-host clustering, reusable logic validation | Treating commonness as proof of benignity |
| One host | Local timeline, independent host artifacts, current/historical state, exact pivots | Using one-host rarity or prevalence as proof |

Host-derived uplift remains a candidate until validated against appropriate
fleet or replay data. Fleet findings still require exact host context before
asserting compromise. If a host-mode reduction exposes `distinct_hosts = 1`,
that value is tautological and must not be represented as prevalence.

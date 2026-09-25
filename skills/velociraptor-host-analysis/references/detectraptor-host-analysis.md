# DetectRaptor Host Analysis

Use this adapter for DetectRaptor results from one saved client collection.
Apply the shared
[`DetectRaptor analysis contract`](../../../docs/reference/detectraptor-analysis-contract.md)
for artifact priority, review stacks, evidence preservation, correlation,
dispositions, and detection uplift.

Fleet DetectRaptor review remains in `velociraptor-hunting`.

## Host method

1. Confirm exact client, request, flow, artifact/version, effective parameters,
   time bounds, terminal state, and row coverage.
2. Follow the shared priority and stack order. Analyze every other returned
   DetectRaptor artifact afterward.
3. Retrieve exact source context for suspicious or ambiguous groups.
4. Build a bounded host timeline across independent local evidence.
5. Correlate by user, process, command, path, filename, hash, URL/domain,
   network identity, RMM family, and detection family.
6. Separate installed presence, historical presence, current execution,
   network activity, and external intelligence classification.
7. Record disposition, rationale, evidence references, limitations, and the
   next exact host pivot.

## Host-specific controls

- Do not use one-host rarity or prevalence as proof.
- Treat `distinct_hosts = 1` in a host-only reduction as tautological, not
  prevalence evidence.
- Complete review of returned rows does not prove complete endpoint telemetry
  or complete PSReadLine history.
- Fleet prevalence is supporting context only when its hunt ID, target scope,
  time range, artifact, and coverage are cited.
- Do not convert authorized RMM on one host into a global allowlist.
- Pivot MFT leads to raw MFT or FileFinder for path and timestamp precision.
- Do not use PSReadLine `FileInfo` timestamps as command execution time; pivot
  to PowerShell or process-creation events for command timing.
- Corroborate Amcache and BinaryRename with file identity, signer/version, and
  execution-adjacent evidence.
- Validate full Webhistory URL, browser/user scope, time, and related file or
  download evidence.
- Treat LolRMM process and resolved-domain results as collection-time
  observations unless exact source data or an independent artifact supplies a
  valid event time.
- Validate YARA rule quality, metadata, matched string, offset/context, and
  target process or path before asserting malware or webshell activity.

## Host outputs

Return host coverage, priority findings, expected activity, unresolved gaps, a
bounded timeline/correlation, and exact next collections.

Host evidence may create a sanitized uplift candidate, but reusable
DetectRaptor logic remains unvalidated until it passes fleet or replay validation
under the shared uplift contract.

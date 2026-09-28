# Explicitly Extracted Hunt Evidence

Use this lane only after an operator explicitly requested a snapshot, export,
or download. Routine hunt analysis stays live and server-authoritative.

## Boundaries

- Do not create a snapshot or export merely because file-based analysis is
  easier to implement.
- `hunt analyze --hunt-id` and `hunt analyze --group` never resolve a latest
  snapshot and never create one.
- Treat the selected snapshot or extraction manifest as immutable evidence.
- Write evidence once. Derived stacks, caches, summaries, and manifests must
  reference the original chunks rather than copy raw rows.
- Keep chunk-reference review non-persistent. Derived output may write products,
  but not another raw evidence copy.
- Default review is exhaustive. Selective review requires an explicit total
  token ceiling and must report omitted coverage.

## Create and Analyze a Snapshot

```bash
dfir hunt snapshot \
  --id IR1234 \
  --hunt-id H.1234

dfir hunt analyze \
  --snapshot /path/to/hunt-reviews/H.1234/snapshots/<snapshot>/snapshot.json \
  --artifact-reference /path/to/site/artifact-profiles.json
```

Chunk output is the default. It normalizes, deduplicates, accounts for evidence,
and returns canonical token-bounded CSV chunk paths without writing derived
analysis files.

Request derived output only when reusable derived products are required:

```bash
dfir hunt analyze \
  --snapshot /path/to/snapshot.json \
  --snapshot-output derived
```

Derived output may write artifact-aware stacks, cache records, analysis-route
manifests, and summaries under the versioned `analysis-v8` directory. Cache
reuse is valid only when the snapshot, artifact profile, analysis version, and
canonical limit identity match.

Analysis behavior uses only `high-volume`, `reasoning`, and `synthesis`.
Artifact profiles select a route through `analysis_routes`; code derives the
corresponding task. `--analysis-route` is the only snapshot route override.
Operational token, row, byte, and encoding limits come from the canonical
limit configuration: environment overrides, shared TOML `[analysis_defaults]`
token settings, then code defaults. CLI flags do not replace these limits.
Lower the effective ceiling before re-snapshotting when needed; never split one
CSV row across chunks.

Selective review is explicit and incomplete by design:

```bash
dfir hunt analyze \
  --snapshot /path/to/snapshot.json \
  --review-mode selective \
  --max-total-analysis-tokens 120000 \
  --review-term suspicious.exe
```

## Saved Export or Download Review

Use the saved-analysis manifest path only for evidence that was already
extracted:

```bash
dfir hunt analyze-saved \
  --export-manifest /path/to/exports/velociraptor-hunting-export.json \
  --download-manifest /path/to/downloads/velociraptor-hunting-download.json
```

A saved state file or explicit hunt directory may also identify the durable
manifests. Do not use transient latest-action fields as evidence identity.

## Review Method

1. Verify the immutable manifest, source hunt ID, artifact inventory, chunk
   hashes, extraction consistency, and coverage state.
2. Resolve the canonical artifact profile and any ordered site overlays.
3. Preserve natural artifact and host/client partitions.
4. Review default low-noise stacks before secondary stacks or raw detail.
5. Dispatch bounded chunks independently and assign stable evidence IDs with
   source-file and line-range provenance.
6. Remove empty fields and collapse exact duplicates without changing source
   order.
7. Retrieve exact source chunks for suspicious or ambiguous groups.
8. Report complete, filtered, sampled, token-limited, group-truncated, or
   provisional coverage accurately.

For large exported EVTX rows, use the shared bounded snippet helper:

```bash
./.venv/bin/python utils/review_evtx_csv.py \
  --input /path/to/Windows.EventLogs.EvtxHunter_full.csv \
  --output /path/to/review/evtx-keyword-snippets.csv \
  --literal "powershell -enc" \
  --regex "IEX|DownloadString|FromBase64String" \
  --field Message \
  --field EventData \
  --context-chars 180
```

The helper writes compact matched snippets and a provenance manifest. It does
not replace the immutable source export.

## Outputs

Snapshot evidence remains under:

```text
<snapshot_dir>/chunks/<artifact>/<client-or-host>/<sha256>.csv
```

Derived products may be written under:

```text
<snapshot_dir>/analysis/
<hunt_root>/analysis-cache/by-chunk/
```

Saved-manifest compatibility review writes under `<hunt_dir>/review/`.
Unknown artifacts remain reviewable as chunks but receive
`no_artifact_profile`; do not invent generic stack fields.

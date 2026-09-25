# Windows Autoruns Analysis

Use this guide for one-host Autoruns review after Velociraptor collection. It
is live-first: analyze the saved flow with server-side read-only GoldenDB
reduction. Export and local filtering are explicit offline fallbacks.

## Contents

- Scope
- Live workflow
- Explicit offline workflow
- Collection manifest
- GoldenDB filter semantics
- AI review
- Local context lookup
- Handoff

## Scope

Supported artifacts:

- `IG.Windows.Sysinternals.Autoruns`
- `Windows.Sysinternals.Autoruns`

GoldenDB updates, removals, and publication belong to the reviewed
`velociraptor-hunting` workflow. Machine analysis must not modify GoldenDB.

Live and offline host filtering use the shared
[Autoruns identity contract](../../velociraptor-hunting/references/windows-persistence-autoruns.md#accounting-and-identity-diagnostics).
Version 4 preserves non-ASCII spelling exactly and rejects earlier GoldenDB
versions. Use `--no-autoruns-golden` for unfiltered review while a compatible
database is rebuilt from reviewed original rows. Host cache identities are
versioned to invalidate results produced under the earlier contract.

## Live Workflow

1. Collect or reuse the full Autoruns artifact with
   `velociraptor-collection`.
2. Run the completed saved request through the canonical analyzer:

   ```bash
   dfir collect analyze \
     --id IR1234 \
     --client-id C.1234abcd \
     --request-id REQUEST_ID \
     --question "Which persistence entries are suspicious or unresolved?"
   ```

3. Let the live analyzer subtract GoldenDB HashKey OR paired-regex matches and
   return bounded residual entries with full persistence context. The flow
   projection canonicalizes spaced source fields such as `Image Path`,
   `Launch String`, `Entry Location`, and `SHA-256`, and retains `HashKey` plus
   `GoldenDBStatus`.
4. Use local GoldenDB lookup for context on individual identities when needed.
5. Pivot suspicious residual rows into adjacent persistence, execution, file,
   and event-log evidence.

Do not build a prevalence stack for one-host Autoruns. The live workflow is
read-only and cannot update GoldenDB. Unlike the hunt workflow, it does not
need an additional post-finding suspicious-identity query because the original
flow row is projected directly into the ephemeral residual artifact workload.

## Explicit Offline Workflow

Only when immutable or offline evidence is required:

1. Export/download the finished collection and retain the original CSV.
2. Resolve the collection manifest returned by the export operation.
3. Filter the Autoruns export against the local GoldenDB.
4. Send only the residual CSV to AI.
5. Preserve the original export unchanged.

## Collection Manifest

`--manifest` is the JSON index written when `dfir collect export`
downloads finished collection results, or when `queue`, `ensure`, or `poll`
is invoked with explicit `--export`. It records exported artifacts, flow IDs,
row counts, and local output paths.

Use the `manifest_file` or `export_manifest_file` value returned by the
collection command. For a normal full machine collection, the path is
typically:

```text
<case_root>/<investigation_id>/systems/<host>/exports/
  velociraptor-collection-export-all.json
```

Example:

```bash
dfir autoruns filter \
  --manifest \
  /cases/IR1234/systems/HOST01/exports/velociraptor-collection-export-all.json
```

The filename can include a collection-type or request suffix. Prefer the path
returned by the collection command instead of guessing it. A request-scoped
`coverage.json` containing exported-file entries is also accepted.

If no manifest is available, pass the downloaded CSV directly:

```bash
dfir autoruns filter \
  --input /path/to/Windows.Sysinternals.Autoruns_full.csv \
  --output /path/to/autoruns-residual.csv
```

## GoldenDB Filter Semantics

The reusable database defaults to:

```text
<repo>/src/vraptor/resources/golden/autoruns-golden.sqlite
```

The filter:

- opens GoldenDB read-only;
- normalizes ImagePath, LaunchString, Signer, usernames, SIDs, and Windows
  environment paths with the canonical Autoruns transforms;
- calculates the same ImagePath+LaunchString+Signer SHA-1 identity used by
  Velociraptor VQL;
- suppresses rows matching an exact HashKey or paired image/launch regex rule
  across all categories, including rows without Category;
- preserves Category as source evidence; it is absent from GoldenDB schema 6;
- keeps Signer in the exact identity hash; regex signer metadata is reference-only;
- applies the runtime regex veto for RMM/greyware, missing files, and unsafe paths;
- drops and counts rows where both ImagePath and LaunchString are blank;
- preserves the original collection export;
- writes a separate `*.golden-residual.csv`.

Residual rows include:

- `HashKey`
- `GoldenDBStatus`

Expected status values:

- `not_known_good`

Missing-file entries, RMM/greyware, unverified binaries, LOLBIN use, unusual
launch strings, user-writable paths, and other unmatched identities remain
available for analysis.

## AI Review

Send only the residual CSV to AI. Retain these fields where available:

- EntryLocation
- Entry
- Category
- Profile
- Description
- Company
- Signer
- ImagePath
- LaunchString
- Version
- SHA256
- HashKey
- GoldenDBStatus
- Fqdn
- ClientId

Prioritize:

- suspicious LOLBIN launch arguments;
- unsigned or unverified binaries;
- user-profile, temporary, download, public, or other writable paths;
- filename/path masquerading;
- script interpreters and encoded or obfuscated commands;
- unusual services, drivers, boot components, codecs, or shell extensions;
- unquoted or hijackable command paths;
- DLL or .NET loading and search-order hijacking opportunities;
- missing-file entries that may represent removed or stale persistence;
- low-prevalence identities unexplained by installed software.

If the residual exceeds the model context, process deterministic category or
normalized identity chunks. Sampling may propose prioritization but must not
close unseen rows.

## Local Context Lookup

Query one identity without changing GoldenDB:

```bash
dfir autoruns lookup \
  --category Logon \
  --image-path 'C:\Program Files\Vendor\app.exe' \
  --launch-string '"C:\Program Files\Vendor\app.exe" --background' \
  --signer '(Verified) Vendor'
```

The response reports whether the identity exists, whether the Category
association matches, known categories, and sanitized example context.

## Handoff

Return:

- full export path;
- collection manifest path;
- residual CSV path;
- input, suppressed, blank-identity, and residual row counts;
- suspicious rows with exact Category, ImagePath, LaunchString, Signer, and
  host context;
- adjacent evidence reviewed;
- collection or analysis gaps.

Do not add residual identities to GoldenDB from machine analysis. Route
candidate baseline improvements through a reviewed Autoruns hunt.

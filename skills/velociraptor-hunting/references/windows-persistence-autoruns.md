# Windows Persistence: Autoruns

`--skip-ai` retains deterministic preparation and skips model execution. See the
[shared output and status contract](../../../docs/reference/analysis-skip-ai.md).

Applies to:

- `IG.Windows.Sysinternals.Autoruns`
- `Windows.Sysinternals.Autoruns`

Both artifacts use the `autoruns` hunt analysis profile. For its dedup AI workflow,
use [Dedup AI review and regex-only GoldenDB](#dedup-ai-review-and-regex-only-goldendb).
Focused use cases and individual-host analysis retain their separate contracts.
Database changes, offline candidate CSV review, legacy schema-6 maintenance,
publication and the identity contract are in
[goldendb-maintenance.md](goldendb-maintenance.md). The previous general hunt and
counts-only test workflows are retired.

Autoruns-only reports and CLI summaries omit the redundant `Target execution:
not_assessed` label and its explanatory host-coverage bullet. Structured coverage
state is retained unchanged. This field describes collection coverage against the
original target fleet, not proof that a persisted command ran. Mixed-artifact
reports and assessed or incomplete target coverage remain visible.

## Dedup AI review and regex-only GoldenDB

Use `--profile autoruns` for general cross-host Autoruns AI review. It requires
one existing hunt, one Autoruns artifact, case context, and a schema-10 GoldenDB.
General Autoruns cannot fall through to the generic hunt analyzer;
for mixed hunts, select the other artifacts separately. Individual-host collection
analysis remains entry-level and retains its original flow context; its GoldenDB
reader also supports schemas 9 and 10.

```bash
./vraptor hunt analyze \
  --id IR1234 --hunt-id H.EXAMPLE \
  --artifact IG.Windows.Sysinternals.Autoruns \
  --profile autoruns \
  --autoruns-golden-db /path/to/autoruns-golden.sqlite
```

To create or reuse a collection, use `hunt run --profile autoruns`; its response
supplies a complete analysis follow-up with automatic output paths. `autoruns_test`
and `autoruns_dedup` are no longer accepted as profile names. Test-only CLI flags,
including `--autoruns-test-mode`, `--autoruns-test-vql-file`, `--show-vql` and
`--vql-only`, are removed. Historical test hunt tags and local manifests remain
recognizable, but collection reuse depends on current-case artifact, parameter and
scope compatibility, not the retired analysis tag; existing evidence and output
directories are not rewritten. Existing exports and caches remain historical
evidence, and earlier experimental exports must meet the production fingerprint
contract before AI reuse. The current source
contract is `autoruns-pre-golden-count-v1`, classification contract is
`autoruns-dedup-ai-v2`, and publication schema is `autoruns-review-v4`.
The threshold is bound to the query fingerprint and classification cache key;
old exports cannot be reused as current source exports. Historical reports retain
their original AI-only cutoff and complete-CSV semantics.

The profile uses the pinned package resource
[regex-review-dedup-first.vql](../../../src/vraptor/resources/autoruns/regex-review-dedup-first.vql),
selected by `command_autoruns()` through `autoruns_dedup_ai.template()`.
It materializes GoldenRules once, applies eligibility and V4 normalization, and
counts every occurrence while sampling hosts in a dictionary keyed by serialized
Category, ImagePath, LaunchString and Signer. Matching keys update the same
aggregate. The materialized `dedup()` key list (a `<=` barrier) drains the full
source before totals or samples are read, and an emit-once guard publishes each
completed identity once even when evicted keys repeat. The dictionary still
retains all eligible identities in memory.
The count cutoff is applied after this full-scan barrier. Only completed
identities at or below the cutoff enter GoldenDB matching, once per identity,
with `ApplyMatching = TRUE`. Zero disables the cutoff. The full source scan,
normalization, counting and bounded host sampling still occur for every eligible
identity. This reduces matching work, not aggregation cost.

Python validates and transports the rules, checks complete-stream accounting,
and orchestrates AI and reporting. It does not repeat GoldenDB matching over
the returned hunt stacks. Individual-host and explicit offline filtering use
the shared RE2 matcher in Python and retain their separate entry-level context.

The AI CSV has exactly these fields:

```text
RowId,Category,ImagePath,LaunchString,Signer,TotalRows
```

`ExampleHosts` stays local and is joined only to suspicious rows by the
four-field identity after classification. Potential GoldenDB rows contain
`Category,ImagePath,LaunchString,Signer,TotalRows,Reason,IdentityId`. Host samples do not enter the AI prompt, model metadata, or
classification-cache identity. Category is persistence context, and a Signer
label is source evidence rather than independent signature verification.
`TotalRows` counts source records, not distinct endpoints. Reports include at
most 20 distinct example hostnames per suspicious identity; they do not identify every
affected endpoint or recover original Entry, Profile, hash, or entry location.

Every invocation validates live readiness and queries the current existing hunt
results. Case context comes from `--id` (or its aliases), falling back to
`--server-profile`. The output location is automatic:

```text
<case-root>/<id>/hunts/<hunt-id>/analysis/autoruns_review.csv
```

The first line is the CSV header, with no provenance comment:

```csv
Category,ImagePath,LaunchString,Signer,TotalRows,ExampleHosts
```

Add `--stack-max-total-rows 100` to exclude identities with `TotalRows > 100`
in VQL before GoldenDB matching. Autoruns defaults to 20; a positive integer
overrides the threshold, and `--stack-max-total-rows 0` disables it. Exactly 20
remains eligible under the default; 21 is excluded. Counts are source
occurrences, not distinct hosts. Excluded identities are not evaluated against
GoldenDB and are absent from both the residual CSV and AI input. Their row/group
totals remain in state and reports; exclusions mean partial result review, not
a benign classification. AI completion refers only to the retained residuals.
Generic `hunt analyze --analysis-mode stack` retains its AI-only cutoff and
unlimited default.

The production `dedup()` query clears a group's hostname samples once its count
exceeds the limit (at occurrence 21 by default), then continues counting without
sampling that group. Exact identity counts and exclusion accounting are retained;
`--stack-max-total-rows 0` keeps normal bounded sampling for every group.

The production VQL sets `VQL_MATERIALIZE_ROW_LIMIT` to 100,000 for a performance
experiment (engine default: 1,000). This is query-local, not a server-wide change.
The `Materialize of LET deduplicated_keys: Expand larger than 100000 rows` warning
means the key list exceeded that threshold and spilled to a temporary JSONL file;
it is not a group limit or dropped results. Up to 100,000 materialized key rows
now remain in RAM, increasing memory use in exchange for avoiding disk I/O on
smaller lists. The separate 100,000-entry `dedup()` LRU, complete count dictionary,
10-host sample cap and default 20-occurrence cutoff are unchanged. Re-emitted
keys after cache eviction or expiry count toward the materialization threshold.
To revert this experiment, set `VQL_MATERIALIZE_ROW_LIMIT` back to 1000 in the VQL.
Host-sample clearing does not bound the identity dictionary.


Complete-stream accounting requires:

```text
SourceRows = ExcludedRows + EligibleRows
EligibleRows = HighCountExcludedRows + MatchedRows + ResidualRows
EligibleGroups = HighCountExcludedGroups + MatchedGroups + GroupCount
```

`ExcludedRows` remains the initial eligibility exclusion count. `MatchedRows`
and `MatchedGroups` count identities actually evaluated and matched after the
count cutoff. The GoldenDB-first experiment has been rolled back; its historical
publications remain readable, with matched-group counts unavailable as originally
recorded. Production uses full aggregation, count cutoff, then GoldenDB matching.
Python rejects stacks above the requested cutoff, inconsistent counters,
truncated streams and saved exports with a different threshold.
`--stack-max-total-rows 0 --skip-ai` writes every GoldenDB residual group without
calling AI. `--skip-ai` alone still applies the default cutoff and writes the
filtered residual CSV. A run with no retained groups writes a header-only CSV.

The terminal summary and `analysis-hunt.md` show source/GoldenDB/residual counts,
AI-reviewed identities, excluded counts, severity totals, representative
suspicious findings, and GoldenDB prospect counts. Detail uses the shared
[reporting policy](../../../docs/reference/reporting-policy.md)
(twenty findings by default), with additional findings indexed and terminal
output bounded by the chat budget. Elapsed seconds cover the
Autoruns command through AI classification (including its server query), with
cache reuse shown separately; report and state paths are printed by the CLI.

The file contains every validated residual stack surviving the count cutoff,
in descending `TotalRows` order.
`ExampleHosts` is a JSON array stored in a quoted CSV field, capped at 10 hosts.
Source counts, database/query/CSV hashes and AI completion status live in
`analysis/hunt-analysis-state.json`, under `specialized_analysis.autoruns_review`.
The current schema-7 hunt container preserves other artifact checkpoints and
specialized state. Classifications retain identity IDs, reasons and severity;
source identities and bounded host samples remain in the CSV, not duplicated in
JSON state. Persistence validation checks the CSV against the canonical hashes.
Historical inline provenance and sidecars remain readable for unmigrated outputs.

The canonical report is `<hunt-root>/analysis-hunt.md`. It is rebuilt from the
saved state and residual CSV without another query or model call. Candidates use
`analysis/autoruns_potential_golden.csv` with the seven fields listed above and no
host samples. Both CSVs begin with their header, with no metadata comments.
The residual CSV is available before classification; failed AI review records
`failed`, and skipped AI review records `skipped`, with an empty candidate file
containing only its header. Neither status is a clean finding. An incomplete
source stream leaves the previous outputs intact.

Source exports and model work stay in a private, transient directory under the
case's hunts directory and are removed on normal completion or handled failure.
Abrupt termination can leave that staging directory for explicit recovery.
Normal analysis does not create a `reviews/autoruns` tree, provenance sidecar,
or separate AI cache. Existing historical outputs require explicit migration.

Progress follows `hunt_preflight`, `source_query`, `source_validation`,
`residual_csv_published`, `classification_cache`, `ai_review` and `reporting`.
Only completed classifications from the latest canonical state are reusable.
The key binds rows/counts, database/matching contract, prompt, model route and
limits. Host samples are excluded; a hit joins fresh hosts locally. Skipping AI
does not reuse classifications. Partial AI work is not checkpointed.

Autoruns publishers hold an exclusive hunt-directory lock without a lock file.
Each output replacement is atomic; the state commits last and binds both CSV
hashes. Ordinary write failures restore replaced files. An abrupt interruption
between replacements fails hash validation rather than presenting mixed sources
as a completed review. Rerunning analysis rebuilds the publication. The profile
performs no additional VQL context query, inventory upload, collection retry or
GoldenDB promotion, and does not establish endpoint execution.

Aggregation keeps state for **all** distinct eligible identities, including later
matches. The 100,000-key dedup LRU and 20-host sample bounds do not bound total
aggregation memory; materialization and sorting can also use temporary files.
Fleet memory and end-to-end AI performance require measurement on the selected
source; local synthetic results are not fleet estimates.

## Projection

Return:

- `Entry Location` as `EntryLocation`
- `Entry`
- `Category`
- `Signer`
- `Image Path` as `ImagePath`
- `Launch String` as `LaunchString`
- `Profile`
- `Description`
- `Version`
- `SHA-256` as `SHA256`
- `Fqdn`
- `ClientId`

## Scope and Stack

The `autoruns` profile uses the complete four-field identity
`Category`, `ImagePath`, `LaunchString`, `Signer`, with `TotalRows` and bounded
`ExampleHosts`. Schema-7 regex matching follows complete aggregation. Source
eligibility, normalization, accounting and sample limits are defined above.

Focused LOLBIN, unverified and RMM analysis continue to
use `Category` as the first pivot. Within each category, use the compact
case-normalized stack:

- `EntryLocation`
- `Entry`
- `ImagePath`
- `LaunchString`
- `Signer`
- `Count`

Normalize `ImagePath` and `LaunchString` case-insensitively by replacing every
`C:\Users\<profile>` component with `c:\users\user`, `%SystemRoot%` and
`%WinDir%` with `c:\windows`, and a leading `\SystemRoot\` with
`c:\windows\`, then folding ASCII case only. Apply the ordered transformations
with `regex_transform()` and version its cache key. Do not convert command-line
`/` switches to path separators.

This stack is intended to fit materially more evidence than full Autoruns rows.
The automated Autoruns lane streams the complete normalized aggregate through
token-bounded analyst parts; it does not impose a total-group limit. Retain the
separate 1,000-row limit for original-row drilldowns.

## Focused Use Cases

Run `--profile autoruns` first for efficient inventory
review. Run focused scopes independently against the complete hunt when their
detection coverage is required. Focused scopes bypass GoldenDB.

LOLBIN and unverified passes use the same streamed stack, bounded analyst pool,
validated identity reconstruction and live drill-down method. They write no
stack, suspicious, context, scope or part files.

RMM technical triage remains streamed, but business authorization cannot be
inferred safely from stack evidence alone. RMM questions use the canonical
metadata-only `analysis/review-items.json` manifest rather than an editable CSV.

### LOLBins

Use `--use-case autoruns-lolbin`.

1. Match the maintained LOLBAS executable basename registry against raw
   `Image Path`.
2. Stack `EntryLocation`, `Entry`, normalized `ImagePath`, normalized
   `LaunchString`, and `Signer`.
3. Close clearly routine tuples without retrieving host rows.
4. Mark suspicious tuples `suspicious` and request drill-down.
5. Requery the exact tuple and return every matching original row, FQDN, and
   client ID.

Do not exclude Microsoft-signed binaries until this use case is complete.
Signed LOLBins with suspicious arguments remain findings.

### Unverified populated entries

Use `--use-case autoruns-unverified`. The server-side inclusion predicate is
equivalent to:

```vql
WHERE NOT Signer =~ '(?i)verified'
  AND (
    len(list=string=`Image Path`) > 0
    OR len(list=string=`Launch String`) > 0
  )
```

Stack normalized `EntryLocation`, `Entry`, `ImagePath`, `LaunchString`, and
`Signer`. Review the stack first, then request exhaustive drill-down only for
suspicious tuples.

### RMM, remote access, and greyware

Use `--use-case autoruns-rmm`.

1. Match the maintained executable-name and installation-path registry against
   raw `Image Path` and `Launch String`.
2. Stack normalized `EntryLocation`, `Entry`, `ImagePath`, `LaunchString`, and
   `Signer`.
3. Compare product, signer, path, persistence category, launch behavior, and
   fleet prevalence with the approved site RMM inventory.
4. Drill down unknown, unauthorized, renamed, unsigned, user-writable, hidden,
   encoded, or otherwise suspicious tuples.

An RMM match is dual-use classification, not proof of maliciousness. RMM and
greyware identities remain permanently non-promotable to the global GoldenDB,
including when they are locally authorized.

Focused suspicious drill-downs remain transient live-query results. Persist
only bounded counts and summaries in canonical state and reports. Persist exact
context only when the operator explicitly requests an evidence export.

An ad-hoc hunt review closes only the server-reported result set. Record target
execution as `not_assessed`; the persistence audit accepts that value only when
`review_scope` is `ad_hoc_review`. Managed hunts and collections still require
complete target execution coverage before claiming complete coverage.

## Filter Optimization

Treat the stack as a detection-tuning input. Consolidate recurring benign
groups into category-scoped compound filters, normally:

- anchored normalized `ImagePath` regex; and
- expected verified `Signer` regex.

Use `Entry`, `LaunchString`, or `SHA256` as additional conditions when the
category requires stronger identity. Validate each candidate against the
complete hunt before approval. Approved filters are applied server-side on the
next analysis pass, before the category and normalized stacks are generated.
Keep only the filter ID, conditions, scope, and match count for benign
reduction; retain detailed findings for exceptions and suspicious residuals.

Do not suppress an entire Run-key category. Suppress only validated known entry
families within the `Logon` category.

## Category Handling

Keep these mechanisms separate for interpretation:

- Logon
- Scheduled Tasks
- WMI
- Image Hijacks
- Boot Execute
- Winlogon
- LSA Providers
- Network Providers
- Winsock Providers
- Office

In focused or generic analysis, large inventory categories such as Drivers,
Services, Codecs, Explorer, and Known DLLs may share one model-response budget,
but their `Category` values must not be merged in stack keys or closure records.
The `autoruns` profile also retains Category in its full four-field identity.

## Closure Guidance

Drivers are often straightforward when all of the following hold:

- `Category=Drivers`;
- verified Microsoft signer;
- expected `C:\Windows\System32\drivers\` path;
- common fleet prevalence;
- no missing-file, user-writable, alternate-data-stream, or path anomaly;
- DLL/.NET or driver-loading hijack risk has been considered;
- exact variants are expected version/hash differences, or have been drilled
  down.

Do not treat signer or prevalence alone as proof of benignity.

For Services and other executable persistence:

- validate service name against path and signer;
- retain command-line and service-DLL loading context;
- drill down user-writable paths, missing files, unexpected interpreters,
  unsigned binaries, signer/path mismatches, and rare entries.

Blank signer values remain evidence. The `autoruns` source query requires
enabled entries with a populated ImagePath or LaunchString and excludes
file-not-found rows; `ExcludedRows` accounts for all eligibility exclusions. Focused or generic category analysis may retain those
rows when blank-target persistence itself is in scope; they require
original-row drill-down because the compact identity is insufficient.

## Machine deep-dive live GoldenDB analysis

For a live one-host collection, prefer the same server-side GoldenDB workflow
used by hunts:

```bash
vraptor collect analyze \
  --id IR1234 \
  --host HOST01 \
  --collection-type persistence \
  --question "Are suspicious Autoruns entries present?"
```

The collection-analysis runtime uses the exact saved flow as its source, applies
the selected database matching contract (legacy hash OR paired regex, or schema-10
regex-only rules), writes the normalized residual and
classification outputs under the host analysis directory, and retrieves exact
suspicious context from the flow. It cannot promote rows into GoldenDB.

## Machine deep-dive offline filter

When immutable or offline evidence is required, collect and download the full
Autoruns artifact. Keep that export unchanged, then filter it locally:

```bash
vraptor autoruns filter \
  --manifest /path/to/velociraptor-collection-export-all.json
```

`--manifest` is the JSON index written when `vraptor collect export`
downloads finished collection results, or when `queue`, `ensure`, or `poll`
is invoked with explicit `--export`. It records each exported artifact, row
count, flow ID, and local CSV path. Use the `manifest_file` or
`export_manifest_file` value returned by the collection command.

For a normal full machine collection, the path is typically:

```text
<case_root>/<investigation_id>/systems/<host>/exports/
  velociraptor-collection-export-all.json
```

For example:

```bash
vraptor autoruns filter \
  --manifest \
  /cases/IR1234/systems/HOST01/exports/velociraptor-collection-export-all.json
```

The exact filename can include a collection-type or request suffix. Do not
guess it when the collection response provides the manifest path. A
request-scoped `coverage.json` containing exported-file entries is also
accepted.

The command selects only exported `IG.Windows.Sysinternals.Autoruns` or
`Windows.Sysinternals.Autoruns` files and writes:

```text
autoruns-golden-filter/<source>.golden-residual.csv
```

It opens GoldenDB read-only, calculates the same normalized
ImagePath+LaunchString+Signer SHA-1 used by VQL, and suppresses a row when its
HashKey or an eligible paired image/launch regex rule matches. Matching applies
across categories, including rows without Category; preserve Category in the
original evidence. Unmatched rows retain `GoldenDBStatus=not_known_good`.
Rows where both ImagePath and LaunchString are blank are dropped and counted.
Send only the residual CSV to AI.

Filter one downloaded CSV directly when no manifest is available:

```bash
vraptor autoruns filter \
  --input /path/to/Windows.Sysinternals.Autoruns_full.csv \
  --output /path/to/autoruns-residual.csv
```

Query one row against the local database without changing it:

```bash
vraptor autoruns lookup \
  --image-path 'C:\Program Files\Vendor\app.exe' \
  --launch-string '"C:\Program Files\Vendor\app.exe" --background' \
  --signer '(Verified) Vendor'
```

To build, merge, publish or remove database entries, use
[GoldenDB maintenance](goldendb-maintenance.md#build-merge-publish-and-remove).

## Live GoldenDB Reduction

The `autoruns` hunt profile reads the local schema-10 database and sends its
materialized regex rules with the pinned query. Live `hunt analyze --profile autoruns`
first synchronizes `Autoruns.GoldenDB/current`, including with `--skip-ai`. The
shared publication helper skips identical hashes and uploads missing or changed
databases, then verifies the server hash. Sync failure stops analysis before the
source query. Progress records `golden_sync`, the outcome, hash and elapsed seconds.
`--no-autoruns-golden-sync` skips this step; rules still come from the local database.
Dated inventory entries are retained. This requires the
[publication permissions](goldendb-maintenance.md#build-merge-publish-and-remove)
and explicit authorization to update server inventory. For a
read-only scope, use `vraptor analyze --hunt ... --profile autoruns`, which skips
publication, or pass `--no-autoruns-golden-sync` to `hunt analyze`.
Saved/offline and individual-host analysis remain unchanged.

Focused `autoruns-lolbin`, `autoruns-rmm`, and `autoruns-unverified` passes bypass
GoldenDB and retain their own coverage and drill-down contracts. General hunt
filtering uses the [production dedup query](../../../src/vraptor/resources/autoruns/regex-review-dedup-first.vql).

## Data Flow

1. Validate the local regex-only database and build the pinned VQL request.
2. Materialize GoldenRules, count and sample each occurrence, deduplicate complete
   identities, then match and export the validated residual stacks.
3. Validate source fingerprints and accounting; pass host-free rows to AI or a
   completed classification cache.
4. Rejoin current source host samples only to suspicious rows by complete identity
   in JSON and Markdown. Potential GoldenDB candidates omit `ExampleHosts`.

The canonical state and report use shared atomic writers while preserving Unicode.
Classifications are stored once as references into the residual CSV. Model prompts,
responses and duplicate source exports stay transient. Candidates are proposals;
database publication and promotion require a separate
[maintenance operation](goldendb-maintenance.md).

## Drill-Down

The `autoruns` profile already has normalized identity fields, `TotalRows` and
bounded host samples; it does not requery VQL context. The samples do not provide
every affected endpoint or original entry metadata. Use an explicitly scoped
follow-up if original rows are needed.

Focused stack drill-down keeps its exact Category and normalized EntryLocation,
Entry, ImagePath, LaunchString and Signer scope, and returns original context.
Individual-host analysis keeps its original flow context.

## Autoruns live stack count changes

Focused Autoruns stacks compare the represented count with the earlier populated-row
count. A higher count continues with all reviewed rows and logs a warning with
the expected count, actual count, and increase. The stack state retains
`expected_rows`, `represented_rows`, `additional_rows`, and the warning. Growth
may reflect results arriving between live queries; the warning does not establish
which clients contributed them. A lower count still fails accounting validation.
This does not impose a row cap or sample results, and existing hunt-closure and
review-coverage checks still apply.
See the [accounting and identity contract](goldendb-maintenance.md#accounting-and-identity-diagnostics)
for request-byte batching and exact-identity rules.

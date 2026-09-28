# Windows Persistence: Autoruns

`--skip-ai` retains deterministic preparation and skips model execution. See the
[shared output and status contract](../../../docs/reference/analysis-skip-ai.md).


Applies to:

- `IG.Windows.Sysinternals.Autoruns`
- `Windows.Sysinternals.Autoruns`

Both artifacts use the `autoruns` hunt analysis profile. For its dedup AI workflow
and schema-10 maintenance, use [Dedup AI review and regex-only GoldenDB](#dedup-ai-review-and-regex-only-goldendb).
Focused use cases, individual-host analysis and legacy schema-6 database maintenance
retain their separate contracts. The previous general hunt and counts-only test
workflows are retired.

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
./dfir hunt analyze \
  --id IR1234 --hunt-id H.EXAMPLE \
  --artifact IG.Windows.Sysinternals.Autoruns \
  --profile autoruns \
  --autoruns-golden-db /path/to/autoruns-golden.sqlite
```

To create or reuse a collection, use `hunt run --profile autoruns`; its response
supplies a complete analysis follow-up with automatic output paths. `autoruns_test`
and `autoruns_dedup` are no longer accepted as profile names. Test-only CLI flags,
including `--autoruns-test-mode`, `--autoruns-test-vql-file`, `--show-vql` and
`--vql-only`, are removed. Existing exports and caches remain historical evidence. The current source
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
aggregate. A materialized `count() ... GROUP BY TRUE` drains the full source,
producing at most one summary row. `items(item=DedupState)` then emits each
completed identity once, without a separate `dedup()` cache or materialized key
list. The dictionary still retains all eligible identities in memory.
The count cutoff is applied after this full-scan barrier. Only completed
identities at or below the cutoff enter GoldenDB matching, once per identity,
with `ApplyMatching = TRUE`. Zero disables the cutoff. The full source scan,
normalization, counting and bounded host sampling still occur for every eligible
identity. This reduces matching work, not aggregation cost.
Edits to `vql/autoruns_test/` do not change this pinned query.

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
AI-reviewed identities, excluded counts, severity totals, up to five representative
suspicious findings, and GoldenDB prospect counts. Elapsed seconds cover the
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

### Regex-only database migration and updates

The repository source of truth is
`src/vraptor/resources/golden/autoruns-golden.csv`. Review prospective
rules from `autoruns_potential_golden.csv` or other candidate inputs, resolve
overlaps with existing rules, and edit the canonical CSV first. Candidate fields
are evidence, not automatically approved regexes. Preserve the six-column format
and category ordering; update LastModified only for changed rows. Then use
`regex-build` against the complete canonical CSV to generate the database update.
Do not use direct database edits or `regex-import` for repository updates, because
they would leave the source CSV out of sync. Standalone database imports remain
available. Follow the [build and version procedure](../../../src/vraptor/resources/golden/README.md).

Schema 10 stores rules in `GoldenRules` with exactly these columns, in order:
`Category, ImagePath, LaunchString, Signer, Notes, LastModified`. There is no
RuleId, hash table, SourceHash, origin or signer-reference column. A separate
`metadata` table identifies the schema, canonicalization and matching contract.

Each of the four regex fields must match the same normalized source identity.
Matching uses case-insensitive regex **search**, as in native VQL. Expressions
are preserved exactly: a leading `^` means a prefix; `^...$` means a whole value.
No extra whole-field anchors are added and Category is a real matching condition.
Use `(?s).*` explicitly for an unrestricted field, or `^$` for an empty field.
Notes describe what the rule filters out and its constraints, without approval
labels. The hunt pipeline filters in VQL; CSV maintenance only validates patterns.
Host/offline readers use the same schema-specific matching semantics.

CSV maintenance accepts these five columns in order:

```csv
Category,ImagePath,LaunchString,Signer,Notes
^Services,^c:\\vendor\\service\.exe$,^"?c:\\vendor\\service\.exe,^\(Verified\) Vendor$,Filters out the vendor service with any launch suffix.
```

Use a CSV writer or spreadsheet export to quote cells containing quotes, commas
or line breaks correctly. An optional trailing `LastModified` column allows an
existing six-field export to be reused, but supplied dates are ignored. Creation
and actual edits receive the current local `YYYY-MM-DD` date. Unchanged rules
retain their previous dates, and no-op imports leave the database byte-identical.
A SQLite trigger also refreshes LastModified on direct matching-field or Notes
edits, without changing dates for no-op updates. Rules are grouped alphabetically
by category (ignoring display anchors), preserving their order within each group.

Create or replace a database from the **complete** reviewed CSV:

```bash
./dfir autoruns regex-build \
  --db /path/to/autoruns-golden.sqlite \
  --input /path/to/all-rules.csv \
  --backup-dir /path/to/backups/autoruns-golden \
  --dry-run
```

`regex-build` replaces the complete rule set. Use it when changing matching
expressions, consolidating rules or removing rows. Without a public RuleId,
changed regexes are new identities and absent identities are removed. Unchanged
four-field identities with unchanged Notes retain their dates.

For additions or Notes edits, use the same arguments with `regex-import`.
It creates a schema-10 database if absent, adds new four-field identities and
updates Notes for existing identities. It does not remove old identities, so use
`regex-build` for regex replacements. Duplicate four-field identities inside one
CSV are rejected. Both operations validate every expression, schema, row count
and the round trip before locked atomic replacement. Existing databases receive
verified SHA-256-named backups. Omit `--dry-run` to apply an already reviewed
change. Neither command uploads the database or runs a hunt.

Schema 9 remains readable with its older category-independent, whole-field
contract. Its JSON importer and `regex-migrate` remain legacy tools for schema
7/8/9 maintenance. They do not convert a curated schema-10 CSV. Use `regex-build`
with a complete reviewed CSV to replace an older production database. Legacy
exact import, merge, delta and promotion writes are rejected for schema 10.
Standalone `autoruns_four_field_regex_v1` candidates remain supported by the
review loader; production schema 10 preserves their four-field search semantics.

Before publishing changed rules, compare against the same complete saved source
and explain changed decisions. Preserve old exports/reports as historical
evidence. Database and matching-contract fingerprints prevent reuse of previous
filtering results under changed rules. Local synthetic checks do not establish
full-fleet coverage or performance.

Run synthetic native-VQL, privacy/cache, saved-source, and database checks:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m pytest \
  tests/test_autoruns_dedup_ai.py tests/test_autoruns_dedup_first.py \
  tests/test_autoruns_regex.py tests/test_autoruns_unicode_contract.py \
  tests/test_autoruns_approved_rules.py tests/test_autoruns_csv_db.py -q
```

Autoruns-only reports and CLI summaries omit the redundant `Target execution:
not_assessed` label and its explanatory host-coverage bullet. Structured coverage
state is retained unchanged. This field describes collection coverage against the
original target fleet, not proof that a persisted command ran. Mixed-artifact
reports and assessed or incomplete target coverage remain visible.

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

## Known-Good SQLite Key

This exact-key contract applies to legacy databases. Schema 9 contains no
exact entries and uses the regex-only contract documented above.

For the reusable SQLite registry, calculate `trusted_key` from only:

1. user-normalized, ASCII-folded `ImagePath`;
2. user-normalized, ASCII-folded `LaunchString`;
3. ASCII-folded `Signer`.

Keep that field order stable. The Python and VQL implementations serialize the
ordered object as JSON and calculate SHA-1. This is an identity key rather than
a file-integrity hash. `EntryLocation`, `Entry`, and
`Category` are deliberately excluded from the hash. Store one row per reviewed
`HashKey`. Automatic exact exclusion requires a matching `trusted_key` and
applies across persistence categories, including when Category is absent.
An identical path, launch string, and signer therefore remain known good when
observed through another persistence mechanism. Review candidate eligibility
with this scope in mind and preserve Category in source evidence.

Schema 6 has one `autoruns_known_good` table containing
`hash_key`, normalized `image_path`,
`launch_string`, normalized `signer`, bounded `description`, and
`modified_time`. Its primary key is `hash_key`. Database metadata
records `schema_version`, `canonicalization_version`, `hash_algorithm`,
`transform_key`, and `built_at`.

Description does not affect the identity hash or suppression. Normalize
control characters and whitespace, truncate it to 256 characters, and select
deterministically when multiple descriptions exist. Do not store
EntryLocation, Entry, Company, Version, FQDNs, client IDs, customer
identifiers, internal domains, raw usernames, or raw user profile paths.

Set `modified_time` when a row is inserted or its selected description is
updated. Reject a merge if the same hash has different normalized identity
fields. Set `built_at` when generating a new complete build or merge;
publishing does not rewrite the SQLite file.

Canonicalization version 4 normalizes `%USERPROFILE%`, `%APPDATA%`,
`%LOCALAPPDATA%`, `C:\Users\<name>`,
`C:\Documents and Settings\<name>`, account SIDs, `%SystemRoot%`, `%WinDir%`,
and leading `\SystemRoot\`. Pattern matching and case folding are ASCII-only;
all other spelling and Unicode composition are preserved exactly. Python and
Go use different Unicode case tables, so Unicode lowercasing or `casefold()`
must not determine a shared identity. This can leave more residuals for review.
Hashing uses UTF-8 JSON with ordered fields, one-space indentation, and Go's
escaping of `&`, `<`, `>`, U+2028 and U+2029.

Earlier canonicalization versions are rejected before lookup, merge, promotion,
or publication. Rebuild a new database from reviewed original rows; rehashing old
keys cannot recover distinctions already lost through case folding. The shared
database is not automatically migrated. Prepare a compatible regex-only database
before using the `autoruns` hunt profile.

Candidate CSVs must attest `CanonicalizationVersion: 4`. Older candidate files
must be regenerated by analyzing original evidence and reviewing the new output;
editing their metadata does not restore the original identities. Existing AI
part caches are also invalidated for the changed contract.

The [legacy schema-6 SQL](../../../src/vraptor/resources/autoruns/windows-autoruns-known-good-schema.sql)
is still used by legacy database build and migration commands. The schema-10
contract is defined in `autoruns_csv_db.py`.

For current candidate review, use the validated residual stacks from the
[dedup AI workflow](#dedup-ai-review-and-regex-only-goldendb). Review the complete
four-field patterns, then add approved rules with `autoruns regex-import` as
described in [regex-only database updates](#regex-only-database-migration-and-updates).
Review is the final policy decision; schema 10 applies no later path/RMM veto.
Legacy schema-6 build, merge and promotion commands retain their own eligibility
checks and cannot write the schema-10 database.

## GoldenDB Commands

Refresh the RMM/remote-access classification:

```bash
dfir autoruns refresh-rmm
```

### Offline CSV review and repository update

This exact/paired-regex CSV procedure targets schema 6. For schema 10, retain
the evidence-review step, prepare five-field regex CSV, and use
[`regex-import`](#regex-only-database-migration-and-updates).

Use this workflow when the user supplies a CSV and asks AI to determine what
belongs in GoldenDB. The outcome is reviewed update CSVs followed by an approved
local database update. The user can then submit a PR to distribute the shared
GoldenDB through the project. This is an offline branch: do not resolve case
state, collect evidence, query Velociraptor, or publish remotely.

Example prompt:

> Review `/path/to/candidates.csv` against the repository GoldenDB. Use AI to
> identify justified additions and produce appropriate exact and optional regex
> update CSVs. Show what you recommend adding, what is already covered, and what
> you withheld with reasons. Preview the update for my review. Once I approve
> the files, import them locally so I can submit the GoldenDB change in a PR.

Inputs are the candidate CSV path and any supplied evidence, plus an optional
target database and output directory. Resolve and report the selected target:
`--db` overrides `VELO_AUTORUNS_GOLDEN_DB`, which overrides the shared tools
location. For a project PR, select the repository database explicitly:
`src/vraptor/resources/golden/autoruns-golden.sqlite`. Write review
outputs to the user's chosen review directory; preserve the source CSV.

1. Read the entire candidate set and compare it with the target's exact
   `HashKey` records and paired image/launch regex rules. Identify
   already-covered rows and proposed new identities or description
   improvements. Keep a source-row reference for every disposition. Do not use
   an import or a full database merge to decide whether a candidate is safe.
2. Use AI to accelerate interpretation and grouping, while retaining the
   supplied evidence. Require a justified benign purpose, expected path and
   launch behavior, and applicability across categories. Signing, prevalence,
   file presence, and a familiar product name alone do not establish trust. Exclude
   RMM/greyware, remote administration, and missing-file identities. Withhold
   unresolved user-writable execution, interpreters/LOLBIN arguments, ADS/path
   anomalies, and other ambiguous entries for explicit evidence-based review.
3. Prefer exact rules. A fixed reusable path may be eligible; keep exact
   version/package paths and unresolved GUIDs unless evidence supports a narrow
   regex. Propose regex only for explained variability within an otherwise
   stable path and command. Require positive examples and negative examples
   covering extra arguments, different executables, and unsafe locations.
   Check that category changes do not alter the intended eligibility;
   Category cannot restrict a rule. `signer_regex` is reference metadata,
   never a matching condition.
4. Produce `exact-update.csv` and, only if needed, `regex-update.csv`. Summarize
   accepted, already-covered, rejected, and withheld rows with reasons and
   coverage counts. Account for every source row; do not silently sample or
   treat a model's suggestion as approval. Use a CSV writer to preserve commas,
   quotes, and multiline fields.
5. Run `autoruns import --dry-run` with those files. Present their paths,
   SHA-256 values, the selected target/revision, exact additions, regex scope,
   and change counts for the user's review. If anything is withheld, state what
   evidence is missing. Review the concrete files before requesting merge
   approval; do not import unapproved proposals.
6. After the user approves those files, rerun the same command without
   `--dry-run`. If the files or intended rule scope change, present that change
   for review. A changed target is reconciled by a new invocation; rerun the
   preview if its effective additions differ from the approved proposal.
7. Check the final database validation, backup path, replay/no-change status,
   and Git diff. The user can submit the sanitized shared database update in a
   PR. Keep customer CSVs, review evidence, backups, and temporary files out of
   the commit. A repository PR distributes the shared baseline to consumers
   when they update; it does not automatically replace separate investigation-local GoldenDB copies
   or remote Velociraptor inventory.

Exact update columns:

```text
HashKey,ImagePath,LaunchString,Signer,Description
```

The first four columns are required; `Description` is optional. `Signer` may be
explicitly empty; `ImagePath` and `LaunchString` cannot both be empty. Recompute HashKey with the
shared `autoruns.trusted_key` V4 implementation, then require it to match during
import. Legacy `Category` columns are accepted and ignored; they are not stored
and never restrict matching. Never invent a signer, path, or launch string. A
candidate CSV without sufficient original identity evidence must be enriched
from supplied evidence before creating these updates. The separate live
`promote` workflow below can recover that evidence only when authorized.

Regex update columns:

```text
image_path_regex,launch_string_regex,description
```

All three columns are required text; optional `signer_regex` is also text.
Legacy `category` columns are accepted and ignored. Both patterns are mandatory;
use `^$` for an explicitly empty field. Patterns use
RE2 syntax with implicit full-field anchors. The importer rejects duplicate
keys and obvious prohibited or unrestricted rules. Runtime regex filtering
also retains prohibited identities independently of the stored patterns;
import validation is not a proof that a regex describes only benign software.

```bash
./dfir autoruns import \
  --input /path/to/reviews/exact-update.csv \
  --regex-input /path/to/reviews/regex-update.csv \
  --db src/vraptor/resources/golden/autoruns-golden.sqlite \
  --dry-run
```

Omit `--regex-input` if there are no regex proposals. Either input option can
be repeated; regex-only updates are supported. After approval, remove
`--dry-run` to merge. The command does not run AI itself: the skill performs
the evidence review and the command validates/applies its approved output.

CSV accepts a UTF-8 BOM and leading `#` metadata comments before the header.
After the header, every line is CSV data, including `#` lines inside quoted
multiline fields. Duplicate/ambiguous headers, malformed quoting, wrong column
counts, non-text required values, and mismatched hashes fail closed. JSON
objects/lists, JSONL, and NDJSON are also supported; duplicate
JSON keys are rejected. A valid header with no rows is a no-op.

Import hashes the bytes it parses and reconciles against a private immutable
baseline snapshot. It builds a temporary delta bound to that revision and
checks the current target under its apply lock. A conflicting revision fails
without replacing it. Dry-run creates no target backup or lock file. Apply
validates a private sibling database and a byte-exact backup, preserves target
permissions, and atomically replaces the target. Exact replays do not replace
or back up the database. Temporary input-independent baseline/delta files are
removed on completion or handled failure. WAL databases and active journals
are rejected: use a closed, checkpointed standalone database in DELETE journal
mode. Do not change a live writer's journal settings as part of this workflow.

Regression checks:

```bash
.venv/bin/python -m unittest tests.test_autoruns_golden tests.test_autoruns_regex tests.test_autoruns_unicode_contract tests.test_live_hunt_analysis
git diff --check
```

### Deletion-only candidate promotion

Preserve the canonical candidate file, copy it to any convenient review path,
and delete only data rows that should not enter GoldenDB:

```bash
cp <hunt>/analysis/autoruns_potential_golden.csv \
  /path/to/reviews/IR1234-H.1234-reviewed.csv

dfir autoruns promote \
  --input /path/to/reviews/IR1234-H.1234-reviewed.csv \
  --dry-run

dfir autoruns promote \
  --input /path/to/reviews/IR1234-H.1234-reviewed.csv
```

The selected file may be outside the case so the full canonical list can be
retained for later. Do not change comments, metadata, header, field values, or
row order semantics. The selected rows must be an exact, duplicate-free subset
of the canonical rows; only deletion is permitted. New files embed engagement,
hunt, and artifact provenance. Legacy files beside the hunt analysis directory
infer that context from their path; moved legacy files require the old explicit
case and hunt overrides.

The command verifies schema-5 state, source stack/query hashes, complete review
counts, target execution appropriate to the review scope, and the selected
GoldenDB schema. `--db` is optional and defaults to the built-in shared
GoldenDB. Managed collections require complete target
execution; `ad_hoc_review` accepts `not_assessed` because it is explicitly
limited to the server-reported result set. A hunt may remain running because
the selected CSV is bound to the attested review checkpoint and exact selected
identities are enriched from current live results. It rejects retained
RMM/greyware and missing-file candidates. Retained LOLBIN and unverified rows
are recorded as explicitly operator-approved priority-review identities. The
command then recovers Category and Description and writes:

```text
<hunt>/analysis/autoruns_potential_golden_enriched.csv
<hunt>/analysis/autoruns-golden-delta.sqlite
<hunt>/analysis/autoruns-golden-delta.json
```

Promotion reconciles every enriched HashKey against the current target
and reports `already_applied`, `new_identity`, or
`description_update`. The source baseline hash remains provenance rather than a
hard equality gate; a fresh delta is built against the current target.
`--dry-run` reports the effective changes without modifying GoldenDB. A normal
run creates a timestamped backup, validates a temporary merge, and atomically
replaces the shared database. Exact replays return `no_changes` with per-entry
`already_applied` rows and leave the database byte-for-byte unchanged.
Publication remains a separate `autoruns push`.

The reusable baseline defaults to:

```text
<repo>/src/vraptor/resources/golden/autoruns-golden.sqlite
```

Use `AI_SKILLS_TOOLS_DATA_ROOT` to relocate the shared tools-data tree,
`VELO_AUTORUNS_GOLDEN_DB` to override the exact path, or `--db` for an
intentional baseline override. `autoruns stage` remains the non-mutating
staging primitive. `autoruns apply --diff PATH` remains available after manual
delta inspection or for recovery.

Inspect and apply the completed delta:

```bash
dfir autoruns inspect \
  --db <hunt>/analysis/autoruns-golden-delta.sqlite

dfir autoruns apply \
  --diff <hunt>/analysis/autoruns-golden-delta.sqlite \
  --dry-run

dfir autoruns apply \
  --diff <hunt>/analysis/autoruns-golden-delta.sqlite
```

`apply` defaults the target to the shared DFIR tools database. It rejects a
stale baseline revision, reports identity/description changes, creates a
timestamped backup for updates, validates a temporary merge, and atomically
replaces the target. A baseline-free delta may only install a new database.
Publication remains a separate `push`.

LOLBIN and unverified-signer entries are priority-review identities rather than
permanently non-promotable identities. In deletion-only promotion, retaining
the exact row is the explicit operator approval and is recorded in the delta
manifest. The general pass may therefore suppress an exact reviewed
HashKey match. Run the dedicated full-hunt LOLBIN or unverified use
case when that focused detection coverage is required.

### Machine deep-dive live GoldenDB analysis

For a live one-host collection, prefer the same server-side GoldenDB workflow
used by hunts:

```bash
dfir collect analyze \
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

### Machine deep-dive offline filter

When immutable or offline evidence is required, collect and download the full
Autoruns artifact. Keep that export unchanged, then filter it locally:

```bash
dfir autoruns filter \
  --manifest /path/to/velociraptor-collection-export-all.json
```

`--manifest` is the JSON index written when `dfir collect export`
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
dfir autoruns filter \
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
dfir autoruns filter \
  --input /path/to/Windows.Sysinternals.Autoruns_full.csv \
  --output /path/to/autoruns-residual.csv
```

Query one row against the local database without changing it:

```bash
dfir autoruns lookup \
  --image-path 'C:\Program Files\Vendor\app.exe' \
  --launch-string '"C:\Program Files\Vendor\app.exe" --background' \
  --signer '(Verified) Vendor'
```

Build a database from reviewed VQL CSV, JSON, or JSONL rows:

```bash
dfir autoruns build \
  --input /path/to/reviewed-autoruns.json \
  --exclude-hashes /path/to/suspicious-hashes.json \
  --output /path/to/autoruns-golden.sqlite
```

Build a mergeable delta against one or more existing GoldenDB files:

```bash
dfir autoruns build \
  --input /path/to/reviewed-autoruns.json \
  --baseline-db /path/to/current-golden.sqlite \
  --output /path/to/autoruns-golden-delta.sqlite

dfir autoruns merge \
  --input /path/to/current-golden.sqlite \
  --input /path/to/autoruns-golden-delta.sqlite \
  --output /path/to/autoruns-golden-next.sqlite
```

Baseline subtraction is opt-in. Without `--baseline-db`, build emits the full
reviewed set. With it, build omits identities already represented by the
combined baselines, but retains a row when it introduces a better deterministic
Description. The delta records its build mode, baseline count, and baseline
database SHA-256 values in metadata.

The builder recalculates every supplied `HashKey`, rejects mismatches, removes
missing-file and RMM/greyware identities, deduplicates normalized identities,
and stores one bounded Description per HashKey row. Category is not stored.

Merge databases collected from multiple Velociraptor servers:

```bash
dfir autoruns merge \
  --input /path/to/server-a.sqlite \
  --input /path/to/server-b.sqlite \
  --output /path/to/merged.sqlite
```

Inspect or query when needed, then publish:

```bash
dfir autoruns inspect --db /path/to/merged.sqlite

dfir autoruns lookup \
  --db /path/to/merged.sqlite \
  d45a537211ce08541a21a1e4fb343ea1fa652a25

dfir autoruns push \
  --db /path/to/merged.sqlite \
  --api-client /path/to/api-client.yaml
```

Publication first probes the exact tool/version and compares its SHA-256 with
the validated local database. An identical hash returns `status: current` and
`uploaded: false`, without compression or upload. Missing or different hashes
trigger publication; other API errors abort without uploading. Successful
uploads return `status: updated` and `uploaded: true` after hash verification.

Publication gzip-compresses the SQLite database locally, base64-encodes the
compressed bytes, and sends them through the mTLS Query API. Server-side VQL
uses `base64decode()` and `gunzip()`, streams the restored bytes directly into
`inventory_add()` through the `data` accessor, and verifies the published
SHA-256 through `inventory_get()`. `push` fixes the tool name to
`Autoruns.GoldenDB` with the stable version `current`, so subsequent uploads
overwrite that inventory entry. Publication output retains the database SHA-256
and build timestamp. `publish` uses the same default; an explicit `--tool-version`
still creates or replaces that exact version. Existing dated versions are not
removed through VQL: a one-time server-side `tools rm Autoruns.GoldenDB` removes
all versions and must be followed by `push` to restore `current`. Perform that
migration during a maintenance window with no active tool consumers; removal
does not provide atomic replacement. The API identity
used for publication and live inventory verification requires Velociraptor
`SERVER_ADMIN`.

Retract a complete identity:

```bash
dfir autoruns remove \
  --hash d45a537211ce08541a21a1e4fb343ea1fa652a25
```

Removal applies to the complete HashKey identity. Legacy nonempty
`--category CATEGORY` values are rejected; category-specific removal is no
longer supported. Publish separately with `push` when intended.

## Live GoldenDB Reduction

The `autoruns` hunt profile reads the local schema-10 database and sends its
materialized regex rules with the pinned query. Live `hunt analyze --profile autoruns`
first synchronizes `Autoruns.GoldenDB/current`, including with `--skip-ai`. The
shared publication helper skips identical hashes and uploads missing or changed
databases, then verifies the server hash. Sync failure stops analysis before the
source query. Progress records `golden_sync`, the outcome, hash and elapsed seconds.
`--no-autoruns-golden-sync` skips this step; rules still come from the local database.
Dated inventory entries are retained. This requires the publication permissions
described above and explicit authorization to update server inventory. For a
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
database publication and promotion require a separate maintenance operation.

## Drill-Down

The `autoruns` profile already has normalized identity fields, `TotalRows` and
bounded host samples; it does not requery VQL context. The samples do not provide
every affected endpoint or original entry metadata. Use an explicitly scoped
follow-up if original rows are needed.

Focused stack drill-down keeps its exact Category and normalized EntryLocation,
Entry, ImagePath, LaunchString and Signer scope, and returns original context.
Individual-host analysis keeps its original flow context.

## Accounting and identity diagnostics

The following legacy reducer checks are retained as internal regression and
benchmark coverage, not as a selectable general hunt workflow. For the current
profile, run `tests.test_autoruns_workflow`, `tests.test_autoruns_dedup_ai` and
`tests.test_autoruns_dedup_first`; the validation command above covers the latter.

The general GoldenDB stack lane counts source, matched, residual, and populated
residual rows and groups residual identities in **one source pass**. Matching
checks exact hashes before paired regex rules. Only populated residual identities
create individual bins; matched and blank residual rows each collapse into one
accounting bucket. The server materializes these reduced aggregates, emits the
accounting summary, streams deterministically ordered residual groups, then emits
a completion marker. Memory therefore scales with residual identity cardinality,
not all-source cardinality; large residual sets still require aggregate memory
and may trigger native grouping/sort spill.

Every group and the terminal marker must arrive, with exact represented-row and
group-count equality. Malformed, duplicate, out-of-order, or incomplete streams
fail validation. Same-pass count differences cannot be explained by hunt growth.
Focused and direct-review accounting retain their existing scope-specific paths;
focused separate-count stacks still allow growth with an explicit warning.

Suspicious drill-down defaults to a 1 MiB serialized protobuf request ceiling,
including VQL, compressed identities, environment, organization fallback, and
transport settings. Globally deduplicated canonical identities are sorted and
deterministically bisected until each request fits. The Python
`identity_batch_size` argument remains an optional additional count cap; it no
longer defaults to 100. All individual identities and batch sizes are checked
before the first query, and an oversized individual identity fails without
querying. This limits request size only; response batches remain streamed and
every selected identity and returned hash must validate.

Suspicious drill-down preserves normalized identities exactly as VQL produced
them, and projects the server-normalized identity alongside original context.
Do not apply Python `casefold()` to these identities: it differs from VQL
`lowcase()` for Unicode values such as `straße` and can make a selected identity
unfindable. Candidate enrichment follows the same exact-identity rule. New
identities use the shared version-4 contract above across hunt stacks, drill-down,
host filtering, candidate staging, and GoldenDB promotion. Hunt watermarks and
host cache identities are versioned so earlier normalization results are not
silently resumed. Generic stack pivots preserve their server dimension values;
ordinary host and DetectRaptor evidence rows do not need Unicode rewriting.

Run the cross-runtime regression checks with:

```bash
.venv/bin/python -m pytest -q tests/test_autoruns_unicode_contract.py
```

The Python/VQL parity checks use the local Velociraptor binary and synthetic
evidence only; they skip when the binary is unavailable. They cover paths,
commands, signers, categories, JSON hashes, legacy trust rejection, and exact
selected identities. ASCII inputs use a guarded fast path; non-ASCII inputs
use explicit ASCII substitutions independent of either runtime's Unicode tables.

Missing selected identities still fail validation. INFO logs expose the stage
and selected/matched/missing counts; DEBUG adds bounded opaque references and
query timing. See [logging diagnostics](../../../docs/reference/velociraptor-logging.md#autoruns-diagnostics-and-timing).

Run the synthetic pipeline integration tests and performance comparison with:

```bash
.venv/bin/python -m pytest -q tests/test_autoruns_accounted_stack.py tests/test_autoruns_request_batches.py tests/test_live_hunt_analysis.py tests/test_autoruns_ai_review.py
.venv/bin/python -m tests.benchmark_autoruns_pipeline --rows 20000 --identities 200 --rules 20 --repeats 3
.venv/bin/python -m tests.benchmark_autoruns_pipeline --rows 68000 --identities 34000 --rules 20 --repeats 3
```

The benchmark compares separate scans, combined accounting/grouping, and an
experimental grouping-before-matching query using synthetic rows and the bundled
Velociraptor binary. Pre-grouping is not enabled in production: low-cardinality
speedups alone do not justify retaining all-source identities when fleet
cardinality is unknown. Report local time, RSS, and spill measurements separately
from projected savings on remote source scans.

Synthetic local measurements (2026-09-09, bundled binary, three repetitions;
time is the median and RSS is the maximum child-process peak):

| Source rows / identities | Residual groups | Separate scans | Combined pass | Pre-group experiment | Peak RSS: separate / combined / pre-group |
| --- | ---: | ---: | ---: | ---: | --- |
| 20,000 / 200 | 21 | 9.171 s | 4.674 s | 1.154 s | 78.48 / 79.31 / 76.17 MiB |
| 68,000 / 34,000 | 3,401 | 32.225 s | 16.408 s | 9.081 s | 90.94 / 88.52 / 179.61 MiB |

Combined time fell 49.0–49.1% with comparable RSS. At high cardinality,
pre-grouping doubled RSS relative to the combined pass and used 4.958 MiB of
observed temporary data versus 0.454 MiB for combined and none for separate.
Every high-cardinality pre-group repetition confirmed native `GROUP BY` spill at
30,001 bins; aggregate materialization also spilled. Temporary-file peaks are sampled and
may miss shorter-lived files. These measurements include local process startup
and synthetic source I/O; they do not measure remote fleet runtime.

Request planning with 166 synthetic Unicode identities and the full drill-down
projection reduced two count-capped requests to one, from 39,274 to 24,493 total
protobuf bytes. At 6,600 selected identities it reduced 66 requests to one.
Request planning retains selected identities only; context responses continue
to stream. This predicts fewer source rescans only when the real selected
identities also fit the request ceiling.

## Generic GoldenDB regex rules

This section describes schema-6 paired regex rules and legacy write commands.
For schema-10 four-field rules, migration, and local updates, use
[regex-only database migration and updates](#regex-only-database-migration-and-updates).

Schema 6 removes Category from exact entries and regex rules; identity
canonicalization remains V4. Schemas 3, 4, and 5 remain readable without
mutation and normalize to category-independent entries in memory, including
deduplication of legacy Category associations. Schema 3 and 4 regex rules have
an empty signer reference. Build and merge write schema 6. Direct legacy
database mutation fails with instructions to merge into schema 6 first;
applying updates retains the existing backup and atomic replacement workflow.

The compact `WITHOUT ROWID` table contains `image_path_regex`,
`launch_string_regex`, `signer_regex`, `description`, and `modified_time`. Its composite primary
key is the two matching patterns; no category, hash, example identities,
rule IDs, or duplicate indexes are stored. Description sanitization and length
limits are the same as for exact entries. To change a pattern, remove the old
rule from a reviewed full rule source and rebuild/replace that rule set; merge
and delta operations are additive and do not infer deletions.

Both patterns must match the **same row**, across all categories, including rows
without Category. Category is neither stored nor evaluated.
They operate on V4-normalized image paths and launch strings. Matching is
case-insensitive by default and implicitly anchored with `\A` and `\z` to the
whole field, including multiline values. Inline case flags can narrow this.
Unlike the hash's ASCII-only case normalization, regex case-insensitivity uses
RE2 Unicode simple folding. Signer is intentionally not a regex-rule condition.
Both patterns are required; use `^$` to explicitly match an empty field.
Lookarounds, backreferences and `\C` are rejected. Local filtering uses
`google-re2`, installed with the repository dependencies.

Local, host, hunt and inventory regex matching use the approved rule patterns
directly. Path location, RMM classification and command risk are review inputs;
they do not veto an approved match afterward. Required field, RE2 syntax,
whole-field matching, database integrity and stream accounting checks remain.
The lookup digest includes the matching-contract version so old suppression
caches cannot silently survive this behavior change.

Example reviewed JSON input (the command requires paired quotes and `/service`):

```json
[
  {
    "image_path_regex": "c:\\\\program files\\\\vendor\\\\[0-9]+(?:\\.[0-9]+){3}\\\\agent\\.exe",
    "launch_string_regex": "\"c:\\\\program files\\\\vendor\\\\[0-9]+(?:\\.[0-9]+){3}\\\\agent\\.exe\" /service",
    "description": "Vendor agent service across four-part version directories"
  }
]
```

Create a baseline-bound delta and apply it using the normal workflow:

```bash
./dfir autoruns build \
  --regex-input /path/to/reviewed-regex-rules.json \
  --baseline-db /path/to/autoruns-golden.sqlite \
  --output /path/to/regex-delta.sqlite
./dfir autoruns apply \
  --db /path/to/autoruns-golden.sqlite --diff /path/to/regex-delta.sqlite
```

For CSV-driven AI review followed by an approved local import and project PR,
use [offline CSV review and repository update](#offline-csv-review-and-repository-update).

`--regex-input` also accepts CSV, can be repeated, and can accompany exact
`--input` files. `inspect` reports `regex_rule_count`; row-based `lookup` reports
`hash_match`, `regex_match`, and their combined `filter_match`. Hash-only
lookup still describes exact identities. Build, merge, delta comparison, apply,
and publication preserve regex rows and descriptions. Creating rules does not
publish them; use the existing `push` workflow when publication is intended.

VQL receives only the hash keys and paired image/launch patterns, compressed
once at setup. Description and modification time stay in SQLite. The normal
filter materializes both indexes and uses a lazy hash-first `if()` followed by
`any()` over paired image/launch conditions. `any()` stops at the first matching
rule; hash hits skip it entirely. All rules are eligible across categories.
The hunt source is not rescanned for each rule. Existing focused-query and priority-override behaviour
is unchanged. Rules are compiled/cached by the matching runtime; do not create
patterns from row-specific values. Databases without regex rules generate the
original hash-only query.

Run local parity and lifecycle checks plus a synthetic VQL benchmark:

```bash
.venv/bin/python -m unittest tests.test_autoruns_regex tests.test_autoruns_unicode_contract
.venv/bin/python -m tests.benchmark_autoruns_regex --rows 10000 --rules 100 --repeats 3
```

Native VQL tests use the bundled local Velociraptor binary and skip when it is
unavailable. The benchmark requires that binary and measures exact hits, regex
first/last hits and misses. It uses synthetic rows
and makes no server queries or GoldenDB changes.

### Reference signer values and consolidation

`signer_regex` is optional RE2 metadata, validated when nonempty and retained
through build, merge, delta application, and publication. It documents observed
Autoruns Signer values, including verified and unverified variants when present.
It is **not evaluated** by Python or VQL matching, is not part of the rule key,
and does not change suppression. Empty means no recorded reference, not a match
requirement. Populate it from observed values; do not infer verification.

Consolidate repeated version directories, instance IDs, or approved command
arguments with paired image/launch patterns that are appropriate across
categories. Keep executable names and installation roots explicit. Broad
argument suffixes such as `.+` are
supported when approved. Before removing exact entries, verify every removed
HashKey row matches a replacement rule and preserve all unrelated rows.
Keep source entries, replacement rules, validation, and rollback backups under a
case reviews directory outside the live hunt analysis tree. A path match alone
is not proof of legitimate execution. Avoid generic directory-wide exclusions
and unconstrained command interpreters.

## Retired test workflow and retained development fixtures

The counts-only `autoruns_test` hunt workflow and its CLI flags have been removed.
Historical test hunt tags and local manifests remain recognizable. Collection
reuse is decided by current-case artifact, parameter and scope compatibility,
not by the retired analysis tag;
existing evidence and output directories are not rewritten. Earlier experimental
exports still need to meet the production fingerprint contract before AI reuse.

Full experimental query versions remain in
`vql/autoruns_test/` (experimental fixtures absent from this checkout) for synthetic local
regressions and benchmarks. They cannot be selected through the production CLI.
Internal experimental database builders and native test helpers retain historical
schema/binding names; they are not additional hunt analysis profiles.

Run the profile, native query and host-path regression checks from the repository:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m pytest \
  tests/test_autoruns_workflow.py tests/test_autoruns_dedup_ai.py \
  tests/test_autoruns_dedup_first.py tests/test_collection_analysis.py \
  tests/test_velociraptor_persistence_policy.py -q
```

### Autoruns live stack count changes

General GoldenDB Autoruns accounting and residual grouping share one source
pass. Require exact row/group totals and the final stream marker before treating
review as complete. See the [accounting and identity contract](#accounting-and-identity-diagnostics)
for request-byte batching, memory limits, and synthetic validation.

Focused Autoruns stacks compare the represented count with the earlier populated-row
count. A higher count continues with all reviewed rows and logs a warning with
the expected count, actual count, and increase. The stack state retains
`expected_rows`, `represented_rows`, `additional_rows`, and the warning. Growth
may reflect results arriving between live queries; the warning does not establish
which clients contributed them. A lower count still fails accounting validation.
This does not impose a row cap or sample results, and existing hunt-closure and
review-coverage checks still apply.

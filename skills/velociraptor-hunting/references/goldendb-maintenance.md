# Autoruns GoldenDB Maintenance

Use this reference to change or publish the Autoruns GoldenDB: schema-10 CSV
updates, offline candidate CSV review, legacy schema-6 import, promotion and
regex rules, database build, merge, publication and removal, and the shared
identity contract. Live and focused Autoruns hunt review is in
[windows-persistence-autoruns.md](windows-persistence-autoruns.md). Candidates
are proposals; apply GoldenDB changes only through the review and approval steps
below, and publish to server inventory only with explicit authorization.

## Regex-only database migration and updates

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
./vraptor autoruns regex-build \
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
[dedup AI workflow](windows-persistence-autoruns.md#dedup-ai-review-and-regex-only-goldendb). Review the complete
four-field patterns, then add approved rules with `autoruns regex-import` as
described in [regex-only database updates](#regex-only-database-migration-and-updates).
Review is the final policy decision; schema 10 applies no later path/RMM veto.
Legacy schema-6 build, merge and promotion commands retain their own eligibility
checks and cannot write the schema-10 database.

## GoldenDB Commands

Refresh the RMM/remote-access classification:

```bash
vraptor autoruns refresh-rmm
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
./vraptor autoruns import \
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

### Deletion-only candidate promotion

`autoruns stage` and `autoruns promote` accept only historical candidate files
written by the retired general live hunt analysis, which carry the attestation
metadata checked below. The `--profile autoruns` candidate CSV has no metadata
and is rejected; add its reviewed rules through `regex-build` or `regex-import`
as described in [regex-only database migration and updates](#regex-only-database-migration-and-updates).

Preserve the canonical candidate file, copy it to any convenient review path,
and delete only data rows that should not enter GoldenDB:

```bash
cp <hunt>/analysis/autoruns_potential_golden.csv \
  /path/to/reviews/IR1234-H.1234-reviewed.csv

vraptor autoruns promote \
  --input /path/to/reviews/IR1234-H.1234-reviewed.csv \
  --dry-run

vraptor autoruns promote \
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
vraptor autoruns inspect \
  --db <hunt>/analysis/autoruns-golden-delta.sqlite

vraptor autoruns apply \
  --diff <hunt>/analysis/autoruns-golden-delta.sqlite \
  --dry-run

vraptor autoruns apply \
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

### Build, merge, publish and remove

Build a database from reviewed VQL CSV, JSON, or JSONL rows:

```bash
vraptor autoruns build \
  --input /path/to/reviewed-autoruns.json \
  --exclude-hashes /path/to/suspicious-hashes.json \
  --output /path/to/autoruns-golden.sqlite
```

Build a mergeable delta against one or more existing GoldenDB files:

```bash
vraptor autoruns build \
  --input /path/to/reviewed-autoruns.json \
  --baseline-db /path/to/current-golden.sqlite \
  --output /path/to/autoruns-golden-delta.sqlite

vraptor autoruns merge \
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
vraptor autoruns merge \
  --input /path/to/server-a.sqlite \
  --input /path/to/server-b.sqlite \
  --output /path/to/merged.sqlite
```

Inspect or query when needed, then publish:

```bash
vraptor autoruns inspect --db /path/to/merged.sqlite

vraptor autoruns lookup \
  --db /path/to/merged.sqlite \
  d45a537211ce08541a21a1e4fb343ea1fa652a25

vraptor autoruns push \
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
vraptor autoruns remove \
  --hash d45a537211ce08541a21a1e4fb343ea1fa652a25
```

Removal applies to the complete HashKey identity. Legacy nonempty
`--category CATEGORY` values are rejected; category-specific removal is no
longer supported. Publish separately with `push` when intended.

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
./vraptor autoruns build \
  --regex-input /path/to/reviewed-regex-rules.json \
  --baseline-db /path/to/autoruns-golden.sqlite \
  --output /path/to/regex-delta.sqlite
./vraptor autoruns apply \
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

Local and host filtering load the hash keys and paired image/launch patterns
once. Description and modification time stay in SQLite. A hash hit skips the
regex rules, and the first matching rule ends the check. All rules are eligible
across categories. Rules are compiled once by the matching runtime; do not
create patterns from row-specific values.

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

## Accounting and identity diagnostics

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
ASCII inputs use a guarded fast path; non-ASCII inputs use explicit ASCII
substitutions independent of either runtime's Unicode tables.

Missing selected identities still fail validation. INFO logs expose the stage
and selected/matched/missing counts; DEBUG adds bounded opaque references and
query timing. See [logging diagnostics](../../../docs/reference/velociraptor-logging.md#autoruns-diagnostics-and-timing).

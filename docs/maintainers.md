# Maintaining velociraptor-skills

This guide is for maintainers who import upstream changes. Users need only the
[README](../README.md).

## Repository synchronization

The shared runtime lives in `src/vraptor/`, portable tests in `tests/core/`,
and shared contracts in `docs/contracts/` and `docs/reference/`. Packaged scripts
and Autoruns GoldenDB assets live under `src/vraptor/resources/`; standalone
review and validation utilities live under `utils/`. The retired
`dfir-case-tools/` directory and its legacy discovery helpers have been removed.
Use `./vraptor` for runtime commands; `./dfir` remains a compatibility CLI alias.
The shared runtime uses explicit connection settings and excludes private
discovery adapters and business case-management modules.

The shared export uses these folder mappings:

| ai_skills | This repository |
| --- | --- |
| `packages/vraptor/src/vraptor` | `src/vraptor` |
| `packages/vraptor/tests/core` | `tests/core` |
| `packages/vraptor/docs/contracts` | `docs/contracts` |
| `packages/vraptor/docs/reference` | `docs/reference` |
| `packages/vraptor/pyproject.toml` | `pyproject.toml` |

The manifest is `config/sync-manifest.tsv`. An optional fourth column lists
comma-separated globs that a tree row skips, such as private markers or bulky
assets. Imports rewrite ai_skills package paths in text to this layout
(`packages/vraptor/src/vraptor` to `src/vraptor`, and likewise for
`tests/core`, `docs/` and package-doc links to repository-root targets), and
both directions compare in this layout. `to-ai --apply` refuses files that contain
layout paths, so port those to ai_skills by hand. `.sync-state.json` records the
content hash at the last successful synchronization. The baseline is local to
each checkout and Git-ignored; keep it locally to preserve change tracking.
Fresh clones start without a baseline. The first reviewed `--apply` creates it;
without a baseline, differing files present on both sides are treated as
conflicts and require manual review. Public-export validation does not require
the baseline, but checks it when present.

The shared setup skill may contain single-line local routing ending in
`<!-- private-setup-routing -->`. Imports strip those lines before comparison,
hashing and copying; all other content retains normal conflict and policy checks.
Review reverse-sync conflicts to preserve private routing. Run public-export
validation after importing; never copy the private setup adapter into this repository.

Preview and import a committed revision from a sibling `ai_skills` checkout:

```sh
./utils/sync-repos.py from-ai --source ../ai_skills --check
./utils/sync-repos.py from-ai --source ../ai_skills --apply --require-plan-hash SHA256_FROM_PREVIEW
```

Preview and propagate committed public changes back to `ai_skills`:

```sh
./utils/sync-repos.py to-ai --target ../ai_skills --check
./utils/sync-repos.py to-ai --target ../ai_skills --apply --require-plan-hash SHA256_FROM_PREVIEW
```

Committed revisions are used by default. `--working-tree` deliberately uses
tracked and non-ignored untracked working-tree content. Source deletions require `--allow-delete`.
Both source and destination working-tree paths reject symlinked files or parent
directories. Manifest paths must be canonical, relative and non-overlapping on
either side. Malformed baseline records stop synchronization before any writes.
Conflicting changes on both sides are never merged automatically. Use
`--allow-reverse-pending` only to apply independent source changes while
leaving destination-only changes untouched for a later reverse sync.

Every preview prints a `Plan SHA256`. Pass it to `--require-plan-hash` when
applying to reject changes since review before writing files or sync state.
For example, to import uncommitted upstream work while retaining public changes:

```sh
./utils/sync-repos.py from-ai --source ../ai_skills --working-tree --allow-reverse-pending --check
./utils/sync-repos.py from-ai --source ../ai_skills --working-tree --allow-reverse-pending --apply --require-plan-hash SHA256_FROM_PREVIEW
```

Use the same options in both commands, except `--check`/`--apply`, `--diff`, and
the hash guard. The hash covers repository paths, revision or working-tree
identity, file bytes and executable modes on both sides, baselines, manifest,
deny rules, the held list, accepted resolutions, and allow flags. If any of these change,
preview and review again. Git inventories are loaded once per repository, and
committed content is fetched in one batch containing only managed blobs.
Preview exits with `0` for unchanged, converged or held content, `1` for drift or policy
findings, and `2` for an invalid request or failed safety check. It changes no
managed files or baseline; it appends local audit metadata.

Add `--diff` to a preview for destination-to-source text comparisons and binary
size summaries. Comparisons include conflicts and public-only differences, so
they may contain private source text; keep review output outside this repository.

For a conflict, manually merge the upstream change into the destination while
preserving public adaptations. Then preview with
`--accept-resolved path/to/destination` (repeat for each reviewed file), and use
the same options with `--apply`. This preserves the destination bytes, checks
them for merge markers and public deny patterns, and advances the source
fingerprint without hand-editing `.sync-state.json`. Remaining public differences
continue to appear as `reverse-needed`; a later upstream change still conflicts
and requires review. Unknown paths and deletion conflicts are rejected.

`config/sync-held.tsv` lists managed files that keep a reviewed public
adaptation, such as the per-repository AI setup defaults, with the upstream
fingerprint that was reviewed for each. Both directions report them as `held`
(with `--diff` showing the difference) and never write them, even after
`--accept-resolved` has moved a baseline, so a later apply in the other
direction cannot overwrite either side. Held files do not block other imports,
and `--accept-resolved` refuses them. When upstream changes a held file, it
reports `held-changed` with the new upstream fingerprint, preview exits `1` and
`--apply` refuses: port the change by hand, then record the new fingerprint in
the row (or remove the row once the files converge).

When upstream adds dependencies, references, or regression tests, review the
public package metadata and explicit manifest entries as well as managed trees.
Packaged `src/vraptor/resources/profiles/profiles.toml` supplies runtime response
profiles. Generic operational and analyst examples live in `config/`. Setup,
provider, lifecycle, credential handling, and analysis regression tests are
explicitly allowlisted. Custom Codex agents live in `.codex/agents/`; runtime
response profiles are owned solely by the packaged file above.

Public-owned files such as the README, this guide, CI, configuration templates, and sync
utilities are outside the managed export unless they are explicitly present in
the manifest.

Retired utility mappings must stay removed from future exports. Use
`vraptor artifacts validate-schema --snapshot FILE --strict` for offline schema
validation and native `ssh-add` for SSH-agent enrollment.

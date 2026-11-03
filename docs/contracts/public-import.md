# Reviewed public import

Export staging applies no public repository changes. The public working tree,
existing `.sync-state.json`, adaptations, README, integration tests and sync
policy remain owned by that repository.

The public `config/sync-manifest.tsv` is the authoritative export inventory,
including explicitly mapped skills, utilities and regression tests. Tree rows may
list exclude globs in an optional fourth column (the
`packages/vraptor/src/vraptor` row excludes `integrations/*`), and imports rewrite
upstream `packages/vraptor` source, test and docs paths to the public layout.
Export staging applies the same exclusions and rewrites. The exporter reads
Git-visible working-tree files and current baseline keys. Ignored
credentials/generated files, retired utilities and broad utility trees are
excluded or rejected. Export staging never applies files or accepts
fingerprints; public installer, launcher, CI, configuration and sync-tool
adaptations stay owned by the public checkout.

The metadata is deliberately shared. Keep additional public dependencies in
separate requirements files or deliberately coordinate future extras upstream.
Never replace the entire public repository with upstream content.

## Prepare without importing

The exporter, `utils/vraptor-export.py`, lives in the private source
repository and is not exported. From that checkout, stage the export for
offline review:

```sh
.venv/bin/python utils/vraptor-export.py \
  --public /path/to/velociraptor-skills \
  --output /private/tmp/vraptor-export-review
```

Use a new output directory for each review. The exporter refuses an existing
directory, writes outside both repositories, and exports reviewed working-tree
bytes, including new Git-visible mapped files. It records source revision, schema version,
every path, SHA-256, mode, original baseline hash, path mapping and plan hash.

Review all of:

- `source/`: mapped shared content in its public view, laid out at its public
  destination paths.
- `destination-layout/`: current public bytes at the same paths, including
  public adaptations.
- `export-plan.json`: source/destination/base fingerprints for every path;
  two-sided changes remain `conflict`.
- `sync-state-original.json`: the public baseline the plan was built from.
- `sync-manifest-additions.tsv`: the reviewed allowlist rows the plan used.

Run core tests and a clean wheel install against `source/`. Check public deny
patterns, forbidden dependencies, schemas and GoldenDB pairing before import.
Do not rebuild GoldenDB as part of copying code or update it from live evidence.

## Import

Set `PUBLIC_CHECKOUT` to the public checkout and preview the import of a
reviewed committed upstream revision:

```sh
"$PUBLIC_CHECKOUT/utils/sync-repos.py" from-ai --source /path/to/ai_skills \
  --rev REVIEWED_REVISION --check
# Or replace --rev REVIEWED_REVISION with --working-tree for indexed review.
```

Add `--diff` to show destination-to-source comparisons; its output may contain
sensitive text. Review every conflict, deletion, public-only change and policy
finding, and every `held-changed` file listed in the public `config/sync-held.tsv`:
port that upstream change by hand and record its new reviewed fingerprint. `--accept-resolved DESTINATION_PATH` records reviewed resolutions; do
not discard the baseline or permit policy findings wholesale.

Run the same preview with the intended resolution flags, record its **sync
Plan SHA256** (distinct from the staging-export plan hash), then apply exactly
that preview:

```sh
"$PUBLIC_CHECKOUT/utils/sync-repos.py" from-ai --source /path/to/ai_skills \
  --rev REVIEWED_REVISION --apply --require-plan-hash REVIEWED_SYNC_HASH
```

Repeat reviewed `--accept-resolved` flags and use `--allow-delete` only for
reviewed deletions. Preserve destination-only changes with the existing
`--allow-reverse-pending` mechanism; it does not resolve conflicts. Run public
export validation and the core and public integration tests before committing
the result. No live collection, API upload or case migration is part of this
process.

## Ongoing setup and utility ownership

The public dependency installer, checkout bootstrap, root documentation, CI and
sync utilities remain public-owned unless explicitly mapped. Shared setup code
and documentation must lead with bare `vraptor setup configure`, its optional AI
handoff, XDG TOML settings and optional credential dotenv/process environment.
Preserve private launcher consumers when aligning configuration resolution.

Keep utility mappings explicit. The retired `configure-velociraptor-ssh.sh` and
`validate_velociraptor_artifact_schemas.py` must not be restored by export
inventories or a broad `utils/` tree mapping: native `ssh-add` and
`vraptor artifacts validate-schema --snapshot FILE --strict` replace them.
Retain the functional regression coverage when retiring wrappers. Removing a
mapping prevents future imports; stale baseline entries are pruned by successful
sync, not by manually editing accepted fingerprints. Reverse-sync deletions need
independent review because a private package may retain modules absent publicly.

The private `packages/vraptor/src/vraptor/integrations/__init__.py` is a retained
package marker. The manifest excludes it, so sync never pairs it; its absence
publicly does not authorize deleting it upstream. Merge CSV evidence-preservation tests with existing large-field and
truncation coverage instead of replacing either suite.

Public sync and validation now use `utils/sync-repos.py` and
`utils/validate-public-export.py`. Their removed shell entrypoints must not be
recreated by exporters. The Python validator includes the previous syntax, CLI,
profile and isolated linker checks.

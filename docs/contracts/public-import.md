> Legacy path lists below describe migration from older public checkouts. Current runtime code lives entirely in `packages/vraptor`; old Python paths are not installation requirements.

# Reviewed public import

No public repository changes are applied by this implementation. The public
working tree, existing `.sync-state.json`, adaptations, README, integration tests
and sync policy remain owned by that repository.

For older checkouts without a sync manifest, the legacy migration mappings are:

| Upstream | Public | Kind |
| --- | --- | --- |
| `packages/vraptor/src/vraptor` | `src/vraptor` | tree |
| `packages/vraptor/tests/core` | `tests/core` | tree |
| `packages/vraptor/docs/contracts` | `docs/contracts` | tree |
| `packages/vraptor/pyproject.toml` | `pyproject.toml` | file |

For current checkouts, the public `config/sync-manifest.tsv` is the authoritative
export inventory, including explicitly mapped skills, utilities and regression
tests. The exporter reads Git-visible working-tree files and current baseline
keys before considering legacy keys. Ignored credentials/generated files,
retired utilities and broad utility trees are excluded or rejected. Export staging
never applies files or accepts fingerprints; public installer, launcher, CI,
configuration and sync-tool adaptations stay owned by the public checkout.

`module-map.json` records the old-to-new Python module names. The exporter uses
it to map existing public files and accepted baseline keys into the new groups;
packaged resource paths are mapped separately without rewriting their bytes.

The metadata is deliberately shared. Keep additional public dependencies in
separate requirements files or deliberately coordinate future extras upstream.
Never replace the entire public repository with upstream content.

## Prepare without importing

From the upstream checkout:

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

- `source/`: mapped shared content, laid out at its public destination paths.
- `destination-layout/`: current public bytes at the proposed new locations,
  without namespace rewrites or loss of public adaptations.
- `export-plan.json`: exact path conversions and source/destination/base
  fingerprints; two-sided changes remain `conflict`.
- `sync-state-original.json` and `sync-state-proposal.json`: old and renamed keys.
  The proposal preserves accepted fingerprints and the last source revision;
  it does not mark new bytes as accepted.
- `sync-manifest-additions.tsv`: current reviewed allowlist, or the four legacy
  mappings when no public manifest exists. Do not append duplicate mappings.

Run core tests and a clean wheel install against `source/`. Check public deny
patterns, forbidden dependencies, schemas and GoldenDB pairing before import.
Do not rebuild GoldenDB as part of copying code or update it from live evidence.

## First namespace conversion, after separate approval

1. Preserve the public working tree and original baseline in an external backup.
   Bind review to the plan hash and recheck every destination fingerprint and the
   original baseline SHA-256 immediately before changing the layout. If anything
   changed, generate a new staging plan. No automatic resolution is authorized.
2. Apply the exact `path_moves` from the reviewed JSON to a **public staging
   checkout**: copy old public bytes to `public_path`; retain the original where
   `retain_legacy=true`. Otherwise remove the old path only after the copy is
   verified. Reject an occupied destination with different bytes. Keep unrelated
   files and all public-only adaptations. Copy `sync-state-proposal.json` to that
   checkout's `.sync-state.json`; never reset or bootstrap the baseline.
3. In the public staging checkout's `config/sync-manifest.tsv`, remove the rows
   whose first column is one of these exact paths, then append the four rows in
   `sync-manifest-additions.tsv`:

   ```text
   dfir-case-tools/dfir_case_tools
   dfir-case-tools/scripts/explain_agent_config.py
   packages/vraptor/src/vraptor/resources/scripts/load_repo_env.sh
   packages/vraptor/src/vraptor/resources/scripts/prep_dfir_tools.sh
   dfir-case-tools/scripts/velociraptor
   dfir-case-tools/tools/Autoruns.GoldenDB/autoruns-golden.csv
   dfir-case-tools/tools/Autoruns.GoldenDB/autoruns-golden.sqlite
   ```

   The account-pivot mapping is excluded because it consumes business case
   scope. Removing an allowlist row does not authorize deleting its destination
   file. Preserve legacy configuration/assets and separately review their public
   callers. Keep the existing skill/reference/integration-test mappings and
   public configuration adaptations; they need their usual independent review.
   Do not import upstream compatibility wrappers or `vraptor_adapter.py`.
4. Select a reviewed **committed upstream revision** after this implementation
   is accepted, or explicitly stage the reviewed new package paths and use the
   existing tool's `--working-tree` mode. Its working-tree reader only inventories
   Git-visible managed files; untracked package files must not be silently missed.
5. Set `PUBLIC_CHECKOUT` to the public staging checkout and run its existing sync command:

   ```sh
   "$PUBLIC_CHECKOUT/utils/sync-repos.py" from-ai --source /path/to/ai_skills \
     --rev REVIEWED_REVISION --check
   # Or replace --rev REVIEWED_REVISION with --working-tree for indexed review.
   ```

   Review every conflict, deletion, public-only change and policy finding.
   Resolve namespace/resource changes once, preserving public adaptations.
   `--accept-resolved DESTINATION_PATH` records reviewed resolutions; do not
   discard the baseline or permit policy findings wholesale.
6. Run the same preview with the intended resolution flags, record its **sync
   Plan SHA256** (distinct from the staging-export plan hash), then apply exactly
   that preview:

   ```sh
   "$PUBLIC_CHECKOUT/utils/sync-repos.py" from-ai --source /path/to/ai_skills \
     --rev REVIEWED_REVISION --apply --require-plan-hash REVIEWED_SYNC_HASH
   ```

   Repeat reviewed `--accept-resolved` flags and use `--allow-delete` only for
   reviewed deletions. Preserve destination-only changes with the existing
   `--allow-reverse-pending` mechanism; it does not resolve conflicts.
7. Adapt the public launcher/installer to install this package and invoke
   `vraptor.cli:main`. The public `dfir velociraptor` alias strips its old namespace
   before entering that same settings resolver; operational groups still use
   the internal legacy dispatcher where needed. Do not preload dotenv in the
   public launchers. The case-management package has been removed from the source checkout. Change public skill links
   from upstream `packages/vraptor/docs/contracts` to `docs/contracts`. Retain
   public help, integration tests and generic configuration examples.
8. Run public export validation, core and public integration tests, an unrelated-
   directory wheel install, and the no-AI/no-case dependency checks. Review the
   complete diff and baseline update before applying the staged result to the
   real public repository. No live collection, API upload or case migration is
   part of this process.

After the initial conversion, later shared updates use the same folder mappings
and existing hash-bound sync procedure. Rollback restores the source checkout
and pre-conversion sync baseline; runtime case directories require no rollback
or data conversion.

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
package marker. Its absence publicly does not authorize a reverse-sync deletion.
Review that ownership difference independently; never use blanket `--allow-delete`
to bypass it. Merge CSV evidence-preservation tests with existing large-field and
truncation coverage instead of replacing either suite.

Public sync and validation now use `utils/sync-repos.py` and
`utils/validate-public-export.py`. Their removed shell entrypoints must not be
recreated by exporters. The Python validator includes the previous syntax, CLI,
profile and isolated linker checks.

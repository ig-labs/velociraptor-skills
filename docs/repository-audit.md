# Repository retention and public-data audit

This is the original retention snapshot. The later
[setup configuration audit](setup-configuration-audit.md) supersedes its utility
retention recommendations and records utility consolidation, launcher dotenv
cleanup, and corrections to the remaining utilities.

Reviewed 2026-09-25. Scope: folder and utility ownership, references, packaging,
generated files, synchronization safeguards, and public-data validation. This is
a structural/maintenance review, not a complete security review of every runtime
function or a live endpoint assessment. No source files were deleted, no sync
was applied, and no remote collection or configuration was performed.

The starting checkout had 392 Git-visible files, including non-ignored untracked
files. Most imported content was uncommitted. Existing work and the sync baseline
were preserved. Nonempty Git-visible files had no exact byte duplicates.

## Recommendations

1. Keep the runtime, all eight skills, policy assets, reviewed GoldenDB source
   and database, regression tests, CI, and sync state. None is demonstrated dead
   merely by being large, generated from a reviewed source, or called indirectly.
2. Generated `build/`, pytest/Python caches, and package metadata are cleanup
   candidates. They are already ignored. The local `.venv/` is reproducible but
   deleting it removes the working development environment. No cleanup was
   performed as part of this audit.
3. The standalone SSH-agent helper is optional and has no runtime callers in the
   inspected tree. Remove it only if that convenience workflow is unwanted,
   coordinating the upstream source and sync manifest so it is not reimported.
4. Keep the EVTX review, saved-request validation and schema validation helpers:
   they have documentation or test consumers and provide distinct workflows.
5. Keep tests that exercise behavior. The exact skill-list and fixed package-name/
   Python-version assertions in `tests/test_public_layout.py` are candidates for
   simplification if release-inventory pinning is no longer desired. Do not delete
   the entire file: it also loads profiles, validates SQLite, and checks executable
   entrypoints. `test_velociraptor_layout.py` tests persisted identity and state
   contracts, despite its name; retain it.
6. The largest code modules are `hunt/live.py` (~355 KB),
   `analyze/coordinator.py` (~312 KB), and `collect/requests.py` (~195 KB).
   Their size is a maintenance concern, not evidence that they are removable.

## Folders

Counts below describe the starting Git-visible snapshot, not generated caches.

| Folder | Role / evidence | Recommendation |
| --- | --- | --- |
| `.git/` | Repository history, index and references. | Keep; never treat as cache. |
| `.claude-plugin/` | One plugin manifest with public repository metadata. | Keep for plugin consumers; optional only if that distribution route is retired. |
| `.codex/agents/` | Four scoped role templates consumed by the agent installer. | Keep while custom roles are supported. |
| `.github/workflows/` | CI installs dependencies/native test executable, runs export gate and tests. | Keep. |
| `config/` | Five files: public examples, export allowlist, deny rules. | Keep; see individual roles below. |
| `docs/` | Installation, model execution, setup testing, agent installation, historical release review. | Keep operational guides; historical review is useful provenance, not current validation. |
| `docs/contracts/` | Architecture, CLI, import contract, module map. | Keep alongside implementation. |
| `docs/reference/` | Seventeen detailed state, evidence, authorization, analysis and logging contracts. | Keep; consolidate only with link/behavior review. |
| `skills/prep-dfir-tools/` | Toolchain preparation instructions. | Keep; backed by packaged installer. |
| `skills/velociraptor-artifact-selection/` | Artifact selection instructions and four reference/example files. | Keep; overlays and field policy are separate from collection groups. |
| `skills/velociraptor-collection/` | Collection workflow and three references. | Keep. |
| `skills/velociraptor-engagement-setup/` | Setup workflow and `references/import-extras.csv`. | Keep; the CSV is setup input, not captured case evidence. |
| `skills/velociraptor-host-analysis/` | Host workflow, fifteen reference documents and `agents/openai.yaml`. | Keep; platform guides and output/review contracts have distinct roles. |
| `skills/velociraptor-hunting/` | Hunt workflow, eight references and `agents/openai.yaml`. | Keep; includes offline review and live-analysis contracts. |
| `skills/velociraptor-live-api-client/` | Direct API workflow and service-account reference. | Keep. |
| `skills/velociraptor-mapped-client/` | Offline-evidence client workflow. | Keep. |
| `src/vraptor/` | Eighteen root modules for CLI, API, paths, settings, readiness, lifecycle and workspace. | Keep; `legacy_cli.py` is reachable compatibility code. |
| `src/vraptor/agent/` | Fifteen modules for provider execution, limits, configuration and diagnostics. | Keep; optional provider dependencies do not imply removable adapters. |
| `src/vraptor/analyze/` | Thirty-two modules for acquisition, planning, analysis, saved results and recovery. | Keep; checkpoint and provenance contracts are functional behavior. |
| `src/vraptor/artifacts/` | Thirteen inventory, policy, profile, scenario and schema modules. | Keep. |
| `src/vraptor/autoruns/` | Fifteen modules for GoldenDB and review. | Keep; experimental/test commands are exposed functionality, not pytest leftovers. |
| `src/vraptor/collect/` | Five modules for collection catalog, requests and state. | Keep. |
| `src/vraptor/common/` | Seven modules for shared validation, hashing, atomic IO, labels and budgets. | Keep; shared callers rely on them. |
| `src/vraptor/hunt/` | Five modules for hunt execution and analysis. | Keep. |
| `src/vraptor/logging/` | Three modules for operational progress logging and inspection. | Keep; this is distinct from the public-export audit log. |
| `src/vraptor/resources/` | Nine root package assets/modules, including artifact policies and enrichment references. | Keep; setuptools includes these in wheels. |
| `src/vraptor/resources/autoruns/` | Three VQL variants, schema SQL and signature contract. | Keep; `review.py` selects normal/cached queries and `dedup_ai.py` uses the dedup query. |
| `src/vraptor/resources/contracts/` | Six machine-readable runtime contracts. | Keep; these are not replacements for human documentation. |
| `src/vraptor/resources/golden/` | Reviewed CSV, generated SQLite and maintenance guide. | Keep both data formats; CSV is editing authority, SQLite is runtime input. |
| `src/vraptor/resources/profiles/` | Packaged `profiles.toml` used by standalone installations. | Keep; example TOML in `config/` does not replace it. |
| `src/vraptor/resources/scripts/` | Runtime preparation scripts and fallback requirements. | Keep; individual scripts listed below. |
| `src/vraptor/resources/scripts/velociraptor/` | Seven bootstrap/supervision scripts. | Keep; used by setup, readiness, lifecycle and compatibility CLI. |
| `src/vraptor/resources/vql/` | Thirty-eight bounded query/export templates. | Keep; category/source templates and compatibility exports support different paths. |
| `tests/` | Ninety-three root test/support files in the starting snapshot. | Retain functional coverage; review individual assertions, not filenames. |
| `tests/core/` | Six portable runtime/integration test files. | Keep for standalone package behavior. |
| `tests/core/fixtures/velociraptor/` | One synthetic pagination/component fixture. | Keep; not customer evidence. |
| `utils/` | Fourteen original utilities, plus the new audit writer. | See utility table. |
| `build/` | Approximately 4.2 MiB of generated package output. | Safe cleanup candidate when no build is active. |
| `.pytest_cache/`, `**/__pycache__/` | Generated test/bytecode caches. | Safe cleanup candidates when no run is active. |
| `src/vraptor.egg-info/` | Generated packaging metadata. | Rebuildable; regenerate after removal for editable-install tooling. |
| `.venv/` | Approximately 375 MiB local dependency environment. | Keep for ongoing work; recreating it costs installs and may resolve newer dependencies. |
| `.local/` | New ignored export-check audit directory. | Keep locally as needed; removable if its history is no longer needed. |

No `src/vraptor/integrations/` directory is present. Its name remains in the
historical sync baseline/preview; that is not a live runtime folder or a reason
to manually remove baseline records.

## Root and configuration files

| Files | Purpose / disposition |
| --- | --- |
| `dfir`, `vraptor` | Keep both launcher aliases; both load `utils/runtime-env.sh` and the shared CLI. |
| `pyproject.toml`, `requirements.txt`, `pytest.ini` | Keep package metadata/dependencies, editable AI install convenience, and test discovery/import configuration. These have different consumers. |
| `README.md`, `CONFIG.md`, `AGENTS.md`, `LICENSE` | Keep user configuration, repository instructions and licensing. README's stale claim that a license was absent was corrected to reference the existing Unlicense. |
| `.gitattributes` | Keep the GoldenDB CSV line-ending/whitespace exception. |
| `.gitignore` | Keep credential, evidence and generated-file exclusions. Generic template entries and repeated Python rules can be shortened for readability but consume negligible space and are not a functional problem. |
| `.sync-state.json` | Keep last-sync fingerprints and mode baselines locally; the file is Git-ignored and untracked. Removing the local copy loses the basis for conflict and destination-only change detection. The export gate checks it when present and permits its absence on fresh clones. |
| `config/sync-manifest.tsv` | Keep directional file/tree mappings. Removing a file without updating ownership here may reintroduce it on later synchronization. |
| `config/public-deny-patterns.tsv` | Keep labeled private-marker and recognizable credential regexes. The validator excludes this policy file's own content from matching itself. |
| `config/example.env` | Keep sanitized environment example. Secret-like key/token/password/secret values must be empty. |
| `config/vraptor.example.toml`, `config/analyst-agents.example.toml` | Keep operational and model-execution examples; they are not live credentials or the packaged runtime response profiles. |

## Every utility

| Utility | Behavior / consumers | Disposition |
| --- | --- | --- |
| `install.sh` | Creates/reuses `.venv`, installs editable requirements; documented and used by CI. | Keep. |
| `runtime-env.sh` | Shared interpreter, import path and environment setup for both launchers. | Essential. |
| `link-codex-skills.sh` | Links repository skills; preserves real-file conflicts; gate exercises dry run. | Keep. |
| `link-codex-agents.sh` | Links optional role TOMLs, removes only specific retired links owned by this source. | Keep while roles supported. |
| `link-claude-skills.sh` | Claude skill linking with conflict handling and regression tests. | Keep while Claude supported. |
| `configure-velociraptor-ssh.sh` | Loads a selected key into SSH agent/macOS Keychain. No in-tree runtime caller found; referenced by sync metadata. | Optional removal candidate, not automatically obsolete. Do not execute as part of audit. |
| `sync-repos.py` | Manifest inventory, fingerprint comparison, policy scanning, reviewed plan hashing and guarded apply. | Essential for paired-repository workflow. |
| `validate-public-export.py` | Scans Git-visible release files, validates metadata/resources, then runs syntax, CLI/profile and installer checks. | Essential release check; now owns the former shell checks. |
| `check-vraptor-install.py` | Builds/installs a wheel in a temporary environment and checks core operation without AI SDKs using local fixtures/mocked API. | Keep. Temporary directory is not automatically removed; potential maintenance cleanup outside this repository. Not rerun in this audit. |
| `review_evtx_csv.py` | Bounded literal/regex review of CSV rows with snippets and manifest; linked from extracted-evidence hunting guide. | Keep optional offline workflow. |
| `validate_collection_analysis_forward.py` | Replays an exact saved request via `analyze.forward`; documented by collection/host guides. Can run analysis and write output. | Keep maintenance harness; not a harmless generic static check. Not executed here. |
| `validate_velociraptor_artifact_schemas.py` | Offline schema-snapshot CLI adapter with regression coverage. | Keep small compatibility entrypoint. |
| `public_audit.py` (new) | Shared metadata-only JSONL writer for sync policy and export static checks. | Keep with both callers and tests. |

## Packaged scripts

| Script / file | Role |
| --- | --- |
| `load_repo_env.sh` | Environment helper sourced by repository launchers and bootstrap scripts. |
| `prep_dfir_tools.sh` | Installs/checks supported forensic tools; routed from CLI. |
| `requirements.txt` | Fallback bootstrap dependencies when repository requirements are unavailable. |
| `velociraptor/add_mapped_client.sh` | Mapping engine used by the remote wrapper; invokes supervisor. |
| `velociraptor/add_remote_mapped_client.sh` | Remote enrollment wrapper called by readiness/lifecycle/CLI. |
| `velociraptor/supervise_mapped_client.sh` | Owns mapped-client supervision. |
| `velociraptor/mapped_client_status.sh` | Readiness/status inspection. |
| `velociraptor/fetch_live_api_client.sh` | API configuration retrieval/provisioning workflow. |
| `velociraptor/fetch_live_client_config.sh` | Endpoint configuration retrieval workflow. |
| `velociraptor/remote_config_access.sh` | Shared SSH/privilege access helper used by both fetch scripts. |

## How protected-data checks work

There are separate controls, with different coverage:

1. **Git ignore rules** keep common credentials, environment files, evidence,
   builds and local logs out of normal `git add`. They do not remove tracked
   files or prevent an explicit force-add.
2. **Sync allowlist** limits imported paths. Fingerprints compare source,
   destination and last-sync state; conflicts require review. The optional
   `--require-plan-hash` guard binds application to the reviewed plan. Repository
   instructions require preview/review first; the CLI still permits apply without
   that option, so workflow discipline remains necessary.
3. **Sync deny scan** applies labeled case-insensitive regexes to source content
   selected for add/update/convergence, or retained destination content explicitly
   accepted as resolved. It reports rule/path and refuses apply unless the explicit
   `--allow-policy-findings` override is set. Before this audit it skipped files
   containing a NUL in the first 8 KiB and did not inspect filenames. Both gaps were
   closed: it now removes NULs before matching and also checks the public path.
   Unchanged, conflicting and destination-only files are not covered by this scan;
   it is not a full-tree release gate.
4. **Public export validator** inventories cached/tracked plus non-ignored
   untracked paths using Git. It scans complete regular-file bytes, including large
   files, SQLite bytes/free pages and sync state, and checks relative filenames.
   NUL removal exposes ASCII markers embedded in UTF-16/32; this is not arbitrary
   encoding/decompression support. It rejects symlinks, selected sensitive config
   filenames, private-key file extensions, an excluded reference PDF, and any
   Git-visible `.local/` audit state. It separately checks example secrets, manifest
   paths, state fingerprints, skill frontmatter, Markdown links and SQLite integrity.
5. **Shell release gate and CI** add syntax, launchers, runtime profiles, installer
   dry runs and tests. CI currently runs the custom export validator, not an
   automated history-aware secret scanner.

Limitations: known regexes cannot discover arbitrary customer names, all passwords,
all private infrastructure, compressed archives, Base64 content or other obfuscation.
Ignored untracked files and previous Git revisions are outside the static inventory.
The gate reads working-tree bytes for tracked paths, not a separate staged-content
snapshot. Therefore it can pass when the index contains different bytes. The deny
policy itself is excluded from content matching. File read/parser errors can abort
before a completed-check record is written. A clean result is bounded to these
checks and is not proof of absence of all protected data.

In particular, force-adding arbitrary evidence or customer data is not reliably
blocked by these regexes: the evidence-directory ignore rules are not a general
content-classification system.

The existing security policy correctly calls for a separate history-aware secret
scanner before release. Useful next improvements are automated redacted secret
scanning in CI and a staged/release-artifact check. They were not added by this
bounded audit. Do not use raw `--diff` output as the audit log: diffs can include
the exact content being blocked.

## Local audit log

Both Python checks now append `.local/public-checks.jsonl`. `/.local/` is explicitly
ignored. Force-added local audit files are rejected by the export validator.

- Each record has schema version, UTC time, check name and status.
- Export records include file/error counts and deny findings. Other validation
  errors remain in terminal output; their raw messages are not copied into logs.
- Sync records include direction, requested mode, plan hash, explicit policy
  override flag and deny findings. `apply-requested` does not mean files were
  applied; subsequent hash, conflict, deletion and destination checks can reject it.
- Findings contain a rule label and SHA-256 of the relative path. Neither matched
  values, raw filenames, absolute checkout paths, diffs, nor regex bodies are saved.
  To identify a file, use the contemporaneous terminal output or compare its
  relative-path SHA-256. Hashing is pseudonymization, not encryption.
- New directory/file permissions are `0700`/`0600`; existing log permissions are
  tightened to `0600`. Links/non-regular log files are refused. Appends are locked
  so concurrent records remain separate. Failure to write the log fails the caller.
- This is a local completed-check history, not a signed/tamper-proof compliance
  record, full-shell-gate status, Git-history scan or record of past sanitization.
  Earlier runs are not backfilled. There is no automatic rotation; remove/archive
  locally when no checks are running if history is no longer needed.

Run the existing release command to generate a record:

```sh
./utils/validate-public-export.py
git check-ignore -v .local/public-checks.jsonl
```

## Validation for this change

- Focused security/sync/log tests: **54 passed**.
- Final complete test suite: **2,262 passed, 664 subtests passed** in 77.11 seconds.
- First complete-suite run exposed a concurrent initial log-creation failure.
  It was reproduced outside pytest and fixed by locking the audit directory
  before file creation as well as append. A stress check then passed 100 batches
  of 20 concurrent records, in addition to the regression test.
- Release gate: passed; **395 Git-visible files, 8 skills, database integrity OK**,
  plus shell/Python/CLI/profile/installer checks.
- Read-only sync preview: **285 unchanged, 78 destination-only adaptations**;
  no add/update/conflict/policy findings. Exit 1 reports destination-only drift;
  it is not an all-clear exit code or authorization to reverse-sync adaptations.
- Log ignore rule and `0700`/`0600` permissions verified; `git diff --check` passed.
- No source deletions or sync-state changes. Hash comparison against the starting
  snapshot confines edits to the documented audit, logging, tests and README work.

No external secret scanner or live server workflow was run during this audit.

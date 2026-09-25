# Setup configuration and utility audit

Reviewed 2026-09-25. Scope: installation, configuration resolution, checkout and
installed entrypoints, setup/AI handoff, operator documentation and skills,
utility callers, and synchronization ownership. Validation uses local fixtures;
this is not a live server or provider assessment. No saved operator configuration,
credential files, case evidence or upstream checkout is changed by this work.

## Supported setup path

1. Install Python dependencies. In the public checkout, `utils/install.sh`
   creates/reuses `.venv` and installs editable `.[ai,anthropic,claude]`. OpenAI
   remains the default provider; Azure Entra needs the optional `azure` extra.
   In a terminal it opens configuration automatically;
   `--no-configure` and non-interactive runs install dependencies only.
2. Continue in the wizard, or run bare `./vraptor setup configure` later. Fresh
   setups suggest server name `live`; enter the existing API-client YAML path.
   It saves workstation,
   connection, SSH, transport and mapping settings and credential-file references
   to the XDG-aware `vraptor/config.toml`. Enter accepts the AI handoff and new
   provider `openai`; saved provider/model choices are retained. Analyst profiles
   are saved in `vraptor/analyst-agents.toml`. Setting flags skip the wizard.
3. Inspect `./vraptor config --server-profile live`, `./vraptor ai config` and `./vraptor ai doctor`.
   A repository `.env` is optional. Explicit arguments, process environment,
   selected credential dotenv, repository dotenv and shared dotenv override
   saved TOML in that order. Existing overrides are preserved.
4. Install native Velociraptor with `./vraptor tools prep -t velociraptor` when
   needed, and link skills/agents separately. Case initialization, server startup,
   remote provisioning, collection and live model testing are separate actions.

The resolver and operational-to-AI handoff were already implemented. This audit
corrects the README/template's implied `.env` requirement, the obsolete Codex
installer reference, and skill examples that led with environment configuration.

## Implementation changes

- Checkout launchers no longer preload dotenv through Bash. `runtime-env.sh`
  only selects Python and repository import paths. `dfir velociraptor` strips
  the old namespace before entering the same Python CLI as `vraptor` and `dfir`.
  Installed console entrypoints already use that CLI.
- Python owns CLI settings/credential precedence and passes the resolved
  environment to child scripts. The packaged `load_repo_env.sh` remains for
  direct bootstrap-script compatibility; it skips loading when a resolved
  environment is supplied. It is not a second normal CLI configuration path.
- The configuration wizard can repair a reference to a missing credential file.
  Operational resolution continues to reject missing selected credential files.
- Offline `artifacts validate-schema` does not require connection credentials.
- Codex linkers resolve relative source overrides before making symlinks.
- CSV review rejects input/output/manifest aliases, including symbolic and hard
  links, before writing. Source evidence is preserved on those errors.
- Wheel-install validation cleans its temporary environment on success or failure
  and builds with the declared setuptools backend, so development environments
  created without pip can still run the offline check.
- Synchronization and public-export validation now have Python-only entrypoints.
  The validator retains all shell syntax, Python compilation, CLI/profile and
  isolated linker dry-run checks. The two shell entrypoints were removed.

## Utility disposition

| Utility | Decision |
| --- | --- |
| `install.sh` | Keep: Python/OpenAI/Anthropic/Claude dependency bootstrap and terminal configuration handoff; supports dependency-only installs. |
| `runtime-env.sh` | Keep: shared checkout interpreter/import bootstrap. |
| `link-codex-skills.sh` | Keep: optional skill installation. |
| `link-codex-agents.sh` | Keep: optional agent installation and owned retired-link cleanup. |
| `link-claude-skills.sh` | Keep: optional Claude skill installation. |
| `sync-repos.py` | Keep: documented directional sync and guarded file/state updates. |
| `validate-public-export.py` | Keep: release-policy, syntax and runtime checks in one entrypoint. |
| `public_audit.py` | Keep: shared metadata-only local audit writer. |
| `check-vraptor-install.py` | Keep: isolated wheel/resource/API-fixture validation. |
| `review_evtx_csv.py` | Keep: offline evidence review with bounded output and coverage manifest. |
| `validate_collection_analysis_forward.py` | Keep: saved-request analysis integration harness; may execute AI and write case outputs. |
| `configure-velociraptor-ssh.sh` | Removed: native `ssh-add` provides enrollment; the wizard saves key references. |
| `validate_velociraptor_artifact_schemas.py` | Removed: use `vraptor artifacts validate-schema --snapshot FILE --strict`. |

There are 11 retained utility files. Generated caches, virtual environments,
GoldenDB assets and packaged bootstrap scripts are not removed. Existing runtime,
evidence provenance, authorization and saved-state contracts remain in scope for
regression validation. The earlier [retention audit](repository-audit.md) records
the broader folder inventory; its original utility recommendations are historical.

## Synchronization ownership

The manifest retains explicit utility/test mappings and shared package trees.
The two retired utility mappings are removed, and CSV evidence-preservation
coverage is added. Do not add a broad `utils/` mapping or restore those wrappers
from an upstream export inventory. The sync baseline is intentionally unchanged;
only a successfully reviewed synchronization should advance accepted fingerprints.
Public commands are `./utils/sync-repos.py` and
`./utils/validate-public-export.py`. Future export tooling and instructions must
use these Python entrypoints rather than recreate shell wrappers.

Keep public README/configuration examples, dependency installer, checkout launcher
glue, CI, public validation and sync tooling under public ownership unless an
explicit mapping is reviewed. Adapt shared behavior to the private repository's
additional consumers instead of copying public root launchers over them.

Before future imports, align the upstream runtime/docs/skills/tests with this
audit. Inspect both directional previews, including `conflict`, `reverse-needed`,
deletions and policy findings. Use `--working-tree` only for deliberately reviewed
uncommitted source content. Apply only the exact reviewed plan with
`--require-plan-hash`; do not hand-edit `.sync-state.json` to suppress drift.
`--allow-reverse-pending` preserves independent destination changes and does not
resolve conflicts. Keep private content and raw diffs outside this public tree.

The refreshed working-tree previews found 12 conflicts in each direction,
including setup/settings code, installation/contract documentation, skill
instructions, the Codex linker and regression tests. Merge the CSV
evidence-preservation tests into the existing upstream review coverage.
From-ai reported 66 destination-only changes, 3 converged files and 281 unchanged
files. To-ai reported 65 updates, 3 converged files, 281 unchanged files and a
proposed deletion of `packages/vraptor/src/vraptor/integrations/__init__.py`;
preserve/review that private-only module before accepting any deletion.
Committed-source previews correctly refused dirty managed source paths in both
repositories. These counts are a snapshot: regenerate previews after upstream
alignment. No sync was applied and the baseline remained unchanged.

## Python entrypoint review

The script review reproduced and fixed three failure classes: reading managed
content through symlinked parent directories, overlapping manifest paths that
could write a destination twice, and malformed baseline records that crashed or
were accepted. Sync now rejects those inputs before managed-file or baseline
writes. The public validator applies the same canonical path, mapping and state
rules, and skips symlinked content instead of reading outside the checkout.

The focused sync, public-security, audit-log and public-layout suite passed all
92 tests. Coverage includes both directions, apply/idempotence, conflicts,
reviewed resolutions, hash drift, deletion guards, policy findings, symlink
parents, malformed state and runtime-check failures. The Python public-export
entrypoint passed its static, syntax, CLI/profile and isolated linker checks.
Actual repository sync was preview-only; this review did not rerun live analysis
or alter operator configuration.

## Validation scope

The fresh-machine installation review used a copied working tree, a clean temporary
HOME/XDG configuration, a new Python 3.12 venv, an unrelated working directory
and a checkout path containing spaces. The real installer installed the OpenAI
extra, `pip check` passed, and the real terminal wizard saved the default live
server and OpenAI profile. Configuration views and offline AI doctor passed with
synthetic credentials. This verifies local installation/configuration, not live
server authentication or model access. No provider/server request was sent and
the temporary environment was removed. The installer/setup/provider regression
suite passed 345 tests; the full suite passed 2,322 tests and 664 subtests. Both
edited skill entrypoints and public-export checks passed. Linux CI is configured
to use `--no-configure`; this local review ran on macOS.

Regression coverage exercises real checkout commands with no dotenv, then each
override layer; the optional AI handoff and credential-path recovery; schema
validation without usable credentials; relative linker sources; and CSV path
alias rejection. Public-export validation and an isolated wheel check cover the
retained release/install paths. Unit and integration fixtures do not prove live
authentication, remote readiness or forensic conclusions.

Initial setup-audit checks, before the Python entrypoint consolidation:

- Full suite: `2280 passed, 664 subtests passed`.
- Public export: `files=397 skills=8 database=ok`; shell/Python syntax, CLI,
  runtime-profile and installer dry-run checks passed.
- Isolated wheel: all ten CLI smoke checks and packaged resources/mocked API
  checks passed without the OpenAI SDK or upstream case package. Setuptools
  emitted resource-directory discovery warnings; the exercised resource loads
  succeeded. Temporary directories were removed after both failed and successful
  validation attempts.
- Both edited skills passed the skill validator; `git diff --check` passed.
- Both directional working-tree sync previews completed with review-required
  drift. No synchronization was applied and `.sync-state.json` is unchanged.

Python entrypoint consolidation checks: 68 focused export, audit-log, package and
sync tests passed, including runtime failure propagation and temporary linker-home
cleanup. The complete public-export validator passed (`files=395 skills=8
database=ok`), direct sync CLI help passed, and no active references to the removed
shell entrypoints remained. The original full-suite result above was not rerun
for this maintenance-only follow-up.

## Prompt for the original ai_skills checkout

Run the following from the original checkout. The public repository is a reference
for behavior and reviewed differences, not a replacement for private functionality.

```text
Align this ai_skills checkout with the setup-configuration audit in the sibling
velociraptor-skills repository. Read its docs/setup-configuration-audit.md and
inspect its current working-tree diff as well as committed source. Start by
reading both repositories' AGENTS.md and preserving dirty work and saved settings.

Make bare vraptor setup configure the primary interactive workflow, including
the optional AI handoff. Keep dependency installation, native tool preparation,
skill linking, key enrollment and live operations distinct. Document XDG TOML
locations, optional credential dotenv/process environment, and override precedence.
Remove obsolete configure-codex references only where they are actually stale;
the private repository may retain separate harness configuration features.

Port shared fixes to packages/vraptor/src/vraptor and their tests: configuration
can repair a missing credential-file reference, operational commands still reject
missing credentials, and offline schema validation needs no connection settings.
Audit private launchers before removing their shell dotenv preload: preserve
non-vraptor consumers, route vraptor operations through the Python resolver, and
verify precedence and the old dfir velociraptor route. Do not replace private root
launchers with public ones wholesale.

Port the relative-source linker and CSV path-alias fixes and behavioral tests.
Audit upstream callers before retiring configure-velociraptor-ssh.sh and
validate_velociraptor_artifact_schemas.py; replace callers with native ssh-add and
vraptor artifacts validate-schema. Keep the saved-request analysis harness and
other utilities that still have distinct consumers. Preserve authentication state.

Inspect sync-repos tooling, the public config/sync-manifest.tsv, upstream
utils/vraptor-export.py, export inventories and tests. Align future exports so
retired wrappers are not reintroduced, relevant regression tests are included,
and public-owned installer/launcher/configuration/CI/sync adaptations survive.
Update callers to the public sync-repos.py and validate-public-export.py
entrypoints; do not recreate their removed shell wrappers. The Python validator
must retain the full syntax, CLI/profile and isolated linker checks.
Align the fresh-machine setup defaults too: a new live server named live,
an enabled-by-default AI handoff, and openai as the provider only when no saved
selection exists. Preserve existing server/provider/model choices. Document
existing API YAML and an external OPENAI_API_KEY credential file, offline checks,
and explicitly requested live tests. The public installer now opens configuration
in a terminal, supports --no-configure for CI/upgrades, checks Python 3.11+, and
bootstraps pip in an existing pip-less venv. Adapt these behaviors to private
installation consumers; do not overwrite private root installation glue.
The standard dependency install includes ai, anthropic and claude extras while
keeping OpenAI selected by default. Preserve the SDK compatibility constraints
in pyproject.toml and document that other providers still need their credentials.
Preserve the new rejection of symlinked parent directories, overlapping mappings,
non-canonical manifest paths and malformed baseline keys/records/fingerprints.
Keep public validation consistent with sync and retain the behavioral tests.
Retain conflict, policy, deletion and reviewed-plan protections. Do not reset or
hand-edit sync baselines. Preview both directions, using --working-tree only for
deliberately reviewed uncommitted changes; review every conflict, reverse-needed
entry, deletion and policy finding. Do not apply a cross-repository sync in this
task; report the reviewed plan and any required manual resolutions.
The refreshed audit previews found 12 conflicts in each direction, including
setup/settings/docs/skills/linker/test changes, plus a reverse-sync deletion of
the private integrations/__init__.py. Merge the CSV evidence-preservation tests
and preserve private functionality; regenerate previews against the current state.

Run focused configuration/launcher/utility tests, the appropriate full suite,
public-export validation and isolated wheel checks. Report actual failures and
coverage limits. Do not contact servers/providers, recollect evidence, alter
operator configuration, commit or push. Finish with changed files, retained versus
retired utilities, validation results and the exact safe next synchronization step.
```

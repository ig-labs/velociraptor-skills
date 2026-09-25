# Velociraptor Skills

Official repository: [ig-labs/velociraptor-skills](https://github.com/ig-labs/velociraptor-skills).

Public, reusable Codex skills and DFIR tooling for Velociraptor setup,
collection, hunting, and host analysis.

## Included skills

- `prep-dfir-tools`
- `velociraptor-artifact-selection`
- `velociraptor-collection`
- `velociraptor-engagement-setup`
- `velociraptor-host-analysis`
- `velociraptor-hunting`
- `velociraptor-live-api-client`
- `velociraptor-mapped-client`

The repository also contains the shared `./vraptor` runtime, bounded custom-agent
templates, and installation helpers used by these skills.

See the [public release review](docs/public-release-review.md) for import scope,
sanitization and validation results.

## Install

Requirements are Python 3.11 or later, Git, and a POSIX shell.

```sh
git clone https://github.com/ig-labs/velociraptor-skills.git
cd velociraptor-skills
./utils/install.sh
./vraptor setup configure
./vraptor config
./utils/link-codex-skills.sh --dry-run
./utils/link-codex-skills.sh
```

For Claude Code, link the repository skills into `~/.claude/skills/`:

```sh
./utils/link-claude-skills.sh --dry-run
./utils/link-claude-skills.sh
```

This creates symlinks, so keep the checkout available for shared runtime,
reference files and configuration. Existing symlinks are updated; real files and
directories are preserved and reported as conflicts with a nonzero exit status.
The script leaves unrelated skills and shell startup files unchanged.
Set `AI_SKILLS_SKILLS_DIR` to override the source directory or
`AI_SKILLS_CLAUDE_SKILLS_DIR` to override the destination directory.
Validate the installer with
`.venv/bin/python -m pytest -q tests/test_link_claude_skills_sh.py`.

Install the optional custom-agent templates with:

```sh
./utils/link-codex-agents.sh --dry-run
./utils/link-codex-agents.sh
```

Start a new Codex task after changing installed links. Run the bare
`./vraptor setup configure` command in a terminal for the complete wizard:
workstation paths, connections, SSH settings, credential-file references and
optional AI configuration. It saves operational settings in
`~/.config/vraptor/config.toml`; the AI wizard saves
`~/.config/vraptor/analyst-agents.toml`. Both follow `$XDG_CONFIG_HOME`.

A repository `.env` is optional. Use a selected credential file or process
environment for provider keys; `config/example.env` is a reference for optional
overrides. Existing environment/dotenv overrides take precedence over saved TOML;
inspect `./vraptor config` and `./vraptor ai config` to see effective sources.
Never commit credentials or Velociraptor API-client YAML.

`utils/install.sh` only bootstraps Python dependencies, including the `ai` extra;
it does not run the configuration wizard or install native tools. For an API-only environment,
install the package with `python -m pip install -e .`; add `.[ai]`,
`.[azure]`, `.[anthropic]`, or `.[claude]` for the selected provider.
See [configuration](CONFIG.md) and the [installation and AI setup guide](docs/vraptor-installation.md).

## vraptor CLI

```sh
./vraptor --help
./vraptor setup configure
./vraptor setup init --id example-case
./vraptor setup show
./vraptor ai config --view defaults
./vraptor tools prep --help
./vraptor query --help
./vraptor collect --help
./vraptor analyze --id example-case --client C.EXAMPLE --flow F.EXAMPLE --skip-ai
./vraptor logs show --id example-case
```

The short CLI covers query, clients, artifacts, collection, analysis, hunting,
export, reusable operational settings, three-mode setup, agent configuration
and tool preparation. Top-level `analyze` consumes
existing evidence and cannot submit collections, retry clients, upload GoldenDB
or publish business case state. Explicit `collect analyze` retains its legacy
collection behavior. `./dfir` accepts the same commands as `./vraptor`;
`./dfir velociraptor` remains a compatibility entrypoint.

Case and engagement paths are unchanged: `<case-root>/<id>/engagement.json`,
`systems/<host>/collection/requests/<request-id>/`, `hunts/<hunt-id>/`,
reports, exports and checkpoints retain their existing names and schemas.
`--id`, `--engagement-id`, `--investigation-id` and `--case-root` remain
supported; `--server` selects the connection profile. See the
[CLI contract](docs/contracts/cli.md) and [architecture](docs/contracts/architecture.md).

Live mutations remain subject to the authorization requirements in
the individual skills. Case-bound commands append progress, automatic numeric
metrics, and bounded sanitized server text to
`<case-root>/<id>/logs/velociraptor-progress.log`. Recognized credentials are
redacted; server text may still contain evidence-sensitive paths, usernames,
hostnames, or VQL. See the [logging reference](docs/reference/velociraptor-logging.md).

Current analysis capabilities include `--skip-ai` deterministic preparation,
caller-led final review by default (`--synthesis none`), optional harness review
with `--synthesis full`, current per-artifact host reports, and reusable
readiness without an elapsed-time expiry. See the [preparation contract](docs/reference/analysis-skip-ai.md)
and [final-review contract](skills/velociraptor-host-analysis/references/final-review.md).
Use `analysis-results` to retrieve saved candidates and `summarize` for a saved-results
review; see the [synthesis contract](docs/reference/analysis-synthesis.md).
Autoruns uses native deduplication and regex filtering with the schema-10
GoldenDB; maintain its reviewed CSV and generated database together using the
[GoldenDB workflow](src/vraptor/resources/golden/README.md).

Current workflows also support failed-stage analysis recovery with `--retry-failed`,
opt-in evidence-bearing prompt debugging, and direct read-only mapping of supported
Velociraptor/KAPE ZIP exports. See [analysis recovery](docs/reference/analysis-recovery.md),
[prompt debugging](docs/reference/chunk-prompt-debug.md), and
[mapped evidence](skills/velociraptor-mapped-client/SKILL.md).
The skills now document a [DetectRaptor prerequisite check](docs/reference/detectraptor-bootstrap.md);
this is an operator workflow, not an automatic CLI import hook.

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

The manifest is `config/sync-manifest.tsv`; `.sync-state.json` records the
content hash at the last successful synchronization.

Preview and import a committed revision from a sibling `ai_skills` checkout:

```sh
./utils/sync-repos.sh from-ai --source ../ai_skills --check
./utils/sync-repos.sh from-ai --source ../ai_skills --apply --require-plan-hash SHA256_FROM_PREVIEW
```

Preview and propagate committed public changes back to `ai_skills`:

```sh
./utils/sync-repos.sh to-ai --target ../ai_skills --check
./utils/sync-repos.sh to-ai --target ../ai_skills --apply --require-plan-hash SHA256_FROM_PREVIEW
```

Committed revisions are used by default. `--working-tree` deliberately uses
tracked and non-ignored untracked working-tree content. Source deletions require `--allow-delete`.
Conflicting changes on both sides are never merged automatically. Use
`--allow-reverse-pending` only to apply independent source changes while
leaving destination-only changes untouched for a later reverse sync.

Every preview prints a `Plan SHA256`. Pass it to `--require-plan-hash` when
applying to reject changes since review before writing files or sync state.
For example, to import uncommitted upstream work while retaining public changes:

```sh
./utils/sync-repos.sh from-ai --source ../ai_skills --working-tree --allow-reverse-pending --check
./utils/sync-repos.sh from-ai --source ../ai_skills --working-tree --allow-reverse-pending --apply --require-plan-hash SHA256_FROM_PREVIEW
```

Use the same options in both commands, except `--check`/`--apply`, `--diff`, and
the hash guard. The hash covers repository paths, revision or working-tree
identity, file bytes and executable modes on both sides, baselines, manifest,
deny rules, accepted resolutions, and allow flags. If any of these change,
preview and review again. Git inventories are loaded once per repository, and
committed content is fetched in one batch containing only managed blobs.

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

When upstream adds dependencies, references, or regression tests, review the
public package metadata and explicit manifest entries as well as managed trees.
Packaged `src/vraptor/resources/profiles/profiles.toml` supplies runtime response
profiles. Generic operational and analyst examples live in `config/`. Setup,
provider, lifecycle, credential handling, and analysis regression tests are
explicitly allowlisted. Custom Codex agents live in `.codex/agents/`; runtime
response profiles are owned solely by the packaged file above.

Public-owned files such as this README, CI, configuration templates, and sync
utilities are outside the managed export unless they are explicitly present in
the manifest.

Retired utility mappings must stay removed from future exports. Use
`vraptor artifacts validate-schema --snapshot FILE --strict` for offline schema
validation and native `ssh-add` for SSH-agent enrollment. See the
[setup audit and upstream alignment instructions](docs/setup-configuration-audit.md)
before changing installer, launcher or sync ownership.

## Validation

```sh
./utils/validate-public-export.sh
./.venv/bin/python -m pip install -e '.[ai,azure,anthropic,claude,test]'
VELO_LOCAL_VERSION_TAG=v0.77.2 ./vraptor tools prep -t velociraptor
./.venv/bin/python -m pytest tests
./.venv/bin/python utils/check-vraptor-install.py
```

The validation checks skill metadata and relative links, public deny patterns,
Python and shell syntax, the tracked Autoruns GoldenDB integrity, CLI help, and
safe installation dry-runs.

The static export validator and synchronization policy scan append metadata to
`.local/public-checks.jsonl`, ignored by Git. Records include UTC time, check
status, rule labels and hashed relative paths, without matched content or raw
filenames. A static-check pass is not a pass of the later shell/CLI checks;
a sync-policy pass is not confirmation that synchronization was applied.
See the [repository audit](docs/repository-audit.md) for coverage, limitations,
and folder-by-folder retention recommendations.

The test suite also executes native VQL against synthetic rows. It requires the
Velociraptor executable, separately from the Python API package. CI installs
version `0.77.2` into the runner's temporary directory and exports `VELO_BIN`;
locally, set `VELO_BIN` to an existing executable or run the preparation command
above. Preparation without `--init-velociraptor-workspace` does not start a server.
CI uses Python 3.12; reproduce failures on that version as well as the local
development interpreter.

The wheel check builds a temporary package and tests it from an unrelated
directory without the AI SDK or upstream case package. It uses local dependency
fixtures and mocked APIs; it does not contact a Velociraptor server.

## Publication status

The repository contains the [Unlicense](LICENSE). Complete the release review
before publishing changes or changing repository visibility.

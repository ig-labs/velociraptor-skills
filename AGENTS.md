# Repository instructions

This repository is the public source for reusable Velociraptor skills for
Codex and Claude Code, and for their DFIR runtime, `vraptor`.

## Upstream and synchronization

- Files listed in `config/sync-manifest.tsv` (`src/vraptor`, `tests/core`,
  `docs/contracts`, `docs/reference`, `pyproject.toml`, the skills and most of
  `tests/`) are maintained upstream in the private `ai_skills` repository.
- Maintainers edit managed files upstream and import them with
  `./utils/sync-repos.py from-ai --check`, then `--apply` after reviewing every
  change. Other contributors may edit here; say so in the PR so the change can
  be upstreamed. Run `to-ai` only with the owner's approval, with the same
  `--check`, review and `--apply` steps.
- Preserve dirty work and never overwrite a managed file that changed on both
  sides. Files in `config/sync-held.tsv` (`.codex/agents/hunt-agent.toml`, the
  per-repository AI setup defaults) keep reviewed public adaptations: the sync
  reports them as `held` and never writes them; an upstream change makes them
  `held-changed` until it is ported by hand and its fingerprint recorded.
- The sync rewrites upstream `packages/vraptor/...` paths to this layout; a
  file that differs only by those paths is converged.
- Repository-owned, not synchronized: this file, `CLAUDE.md`, `README.md`,
  `CONFIG.md`, `.claude-plugin/`, `.github/`, `pytest.ini`, `ruff.toml`,
  `utils/check.sh`, the skill linkers, `docs/vraptor-installation.md`,
  `docs/maintainers.md`, `docs/reference/skill-resource-ownership.md` and the
  sync and export tools.

## Layout

- `src/vraptor/`: runtime. Map of commands, packages and tests:
  `docs/contracts/repo-map.md`.
- `skills/<name>/`: skills; keep folder and file names stable (a rename unlinks
  the skill from saved selections). `tests/core/`: portable tests (no server or
  network).
- `utils/`: install, link, sync and validation scripts. `config/`: examples,
  sync manifest, held files (`sync-held.tsv`) and public deny patterns.

## Commands

- `utils/check.sh setup`: venv, editable install with test extras, tokenizer cache.
- `utils/check.sh fast`: ruff, `git diff --check`, public export validation, core tests.
- `utils/check.sh full`: whole pytest suite, logged to `.local/check/pytest.log`.
  Native VQL tests need the Velociraptor binary (`VELO_BIN`, or
  `./vraptor tools prep -t velociraptor`).
- Develop against the editable install from `utils/check.sh setup`. A plain
  `pip install .` in the checkout runs an installed copy instead of your edits
  and leaves a stale `build/` folder.
- Run `./utils/validate-public-export.py` before committing.

## Safety

- Keep credentials, customer data, case data, API-client YAML, private
  infrastructure details, and generated runtime state out of the repository.
- Keep `SKILL.md`, referenced resources, CLI behavior, tests, and root
  documentation aligned.
- Treat Velociraptor as the evidence authority. Preserve exact flow, hunt,
  client, artifact, scope, and coverage provenance.
- Require explicit authorization before remote collection, hunt creation,
  retries, cancellation, or other server mutation. API-user provisioning follows
  `docs/reference/velociraptor-operation-authorization.md#api-user-provisioning`.

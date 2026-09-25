# Repository instructions

This repository is the public source for reusable Velociraptor Codex skills
and their DFIR runtime.

- Keep credentials, customer data, case data, API-client YAML, private
  infrastructure details, and generated runtime state out of the repository.
- Keep `SKILL.md`, referenced resources, CLI behavior, tests, and root
  documentation aligned.
- Treat Velociraptor as the evidence authority. Preserve exact flow, hunt,
  client, artifact, scope, and coverage provenance.
- Require explicit authorization before remote collection, hunt creation,
  retries, cancellation, API-user generation, or other server mutation.
- Preserve dirty work and never overwrite a managed file that changed on both
  sides of a repository synchronization.
- Use `./utils/sync-repos.py from-ai --check` (or `to-ai --check`) before
  `--apply` and review every change.
- Run `./utils/validate-public-export.py` before committing.

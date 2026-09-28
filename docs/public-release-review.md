# Public release preparation

Reviewed on 2026-09-24 for `ig-labs/velociraptor-skills`.

## Scope

Imported the eight Velociraptor/tool-preparation skills, shared runtime, resources,
tests, public configuration examples and installation helpers. The previous public
export supplied the public adaptations; current allowlisted `ai_skills` working-tree
changes were imported using a reviewed SHA-256-bound synchronization plan.

Retained the destination repository's original Git history and Unlicense. Neither
source checkout was modified. Private Git history, credentials, endpoint YAML,
environment files, case evidence and historical migration reports were not copied.
GoldenDB CSV and SQLite resources were preserved without regeneration.

## Sanitization and retained behavior

- Updated clone and plugin URLs to the official repository.
- Replaced site profiles, private-network addresses, operator identities and
  incident-specific fixture identifiers with neutral examples.
- Preserved generic API-user defaults, public resource paths, launcher compatibility,
  existing-evidence mutation restrictions and the scheduler exception-handling fix.
- Imported caller-led synthesis, saved-result retrieval, model-budget changes and
  associated regression coverage.
- Extended release validation to filenames, large files, binary resources and sync
  state, with regression tests for these previously uncovered cases.
- Kept local environments, private keys and operational evidence ignored by Git.

## Validation

- Public export gate: passed, including skill metadata, relative links, configuration,
  deny patterns, shell syntax, Python compilation, CLI entrypoints, runtime profiles,
  dry-run installers and SQLite integrity.
- Full Python suite after sanitization: **2,240 passed**, **664 subtests passed**.
- Final focused security checks: **8 passed** (including the subsequently added
  filename regression).
- Gitleaks 8.30.1: no findings in the complete Git-visible release snapshot, the
  existing one-commit Git history, or extracted wheel contents. No custom secret
  allowlist or baseline was used; scanner reports were redacted and stored outside
  the repository.
- Wheel built and installed in a separate Python 3.12 environment outside the
  checkout; CLI, packaged profiles and GoldenDB integrity passed.
- Final upstream preview: no pending additions, updates, conflicts or policy findings;
  78 destination-only public adaptations retained, 285 files unchanged.
- Both source checkout inventories matched their pre-import SHA-256 snapshots.

These are checks of the reviewed snapshot, not a guarantee that arbitrary future
changes are safe. Run `./utils/validate-public-export.py`, the tests and a secret
scanner again before publishing. This preparation did not commit, push, change
repository visibility or retire the previous repository.

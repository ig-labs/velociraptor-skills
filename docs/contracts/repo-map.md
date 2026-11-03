# vraptor repository map

Where the `vraptor` runtime keeps each command, package and test. Source paths
are relative to the `vraptor` package folder (the one holding `cli.py`). Test
paths are relative to the repository root; `core` tests are the portable suite
in the package's `tests/core` folder. The repository `AGENTS.md` gives the
exact locations for this checkout.

## Command routing

`vraptor` and `dfir` both start at `cli.py:main`. `cli._configured_main` routes
`logs usage`, bare `config`, `artifacts validate-schema` and the `setup`
subcommands marked below before anything else. `cli._dispatch_main` handles the
other commands that name `cli.py`; every other area goes to
`legacy_cli._dispatch`, which is the live router despite its name.

| Command | Code |
| --- | --- |
| `analyze --flow` or `--request-id` | `cli.analyze` -> `analyze/command.py:async_main` (host analysis in `analyze/host.py`, `analyze/runtime.py`) |
| `analyze --hunt-id` | `hunt/command.py:command_analyze` -> `analyze/coordinator.py:analyze_hunt_flows`, or `hunt/live.py:analyze_live_hunt` for specialised live stacks |
| `analyze --from` | `hunt/command.py:command_analyze_snapshot` -> `hunt/analysis.py:analyze_snapshot` |
| `collect check, ensure, export, plan, poll, queue, status` | `collect/requests.py:main` |
| `collect analyze`, `collect hydrate` | `analyze/command.py:main`, `collect/hydrate.py:main` |
| `hunt run, status, snapshot, analyze, retry-missing` | `hunt/command.py:main` |
| `hunt native check, download-results, ensure, export-results, lookup, profiles, review-results, search, status, stop` | `hunt/operations.py:main` |
| `hunt analyze-saved` | `hunt/analysis.py:main` |
| `autoruns ...` | `autoruns/golden.py:main` |
| `artifacts inventory, linux-plan, policy, profiles, scenarios, validate-schema` | `artifacts/inventory.py`, `linux.py`, `policy_cli.py`, `profile_cli.py`, `scenario_cli.py`, `schema.py` |
| `setup init` | `workspace.py:main` (via `cli.py`) |
| `setup configure, show, migrate`, bare `config` | `settings.py:main`, `settings.py:config_main` (via `cli._configured_main`) |
| `setup export, deploy, reset` | `setup_config.py:main` (via `cli._configured_main`) |
| `setup start, status, resume, stop` | `setup.py:main` (via `cli._configured_main`) |
| `setup local-deaddisk, remote-deaddisk, live-remote` | `readiness.py:main` |
| `config fetch-api, fetch-client`, `mapped add-remote, status` | `resources/scripts/velociraptor/*.sh` via `legacy_cli.run_bootstrap` |
| `query`, `clients` | `query.py:main` (via `cli.py`) |
| `logs` | `logging/command.py:main` |
| `ai setup, doctor, models, test, login`, `ai config` | `agent/manage.py`, `agent/command.py` (via `cli.py`) |
| `reports`, `summarize` | `analyze/report_command.py`, `analyze/saved.py` (via `cli.py`) |
| `tools prep` | `resources/scripts/prep_dfir_tools.sh` (via `cli.py`) |

## Packages

| Package | Role | Largest modules |
| --- | --- | --- |
| `collect/` | One-host collection requests, exports and hydration | `requests.py` (~5.2k lines) |
| `analyze/` | Flow and hunt analysis, chunking, synthesis, reports | `coordinator.py` (~7.7k), `command.py`, `host.py`, `runtime.py` (~2k each) |
| `hunt/` | Native hunt API operations, grouped workflow, live and snapshot analysis | `live.py` (~9k), `operations.py` (~4.6k), `command.py` (~3.9k), `analysis.py` (~2.5k) |
| `autoruns/` | Autoruns GoldenDB build, review and publication | `golden.py` (~3.8k) |
| `artifacts/` | Artifact selection policy, profiles, scenarios, schema checks | `inventory.py`, `profiles.py` |
| `agent/` | AI provider configuration, runners and diagnostics | `config.py`, `runtime.py`, `manage.py` |
| `logging/`, `common/` | Operation and token-usage logs; small shared helpers (`clock.py` UTC timestamps, `hashing.py` canonical JSON and SHA-256, `atomic_io.py` atomic writes) | |
| `resources/` | Packaged JSON policy, VQL, shell scripts, GoldenDB | |
| top level | `api.py` (Velociraptor gRPC API), `settings.py`, `readiness.py`, `paths.py`, `case_layout.py` | |

Do not read the large modules whole: find the symbol with
`rg -n '^(async )?def name'`, then read a line range. Inspect
`resources/preferred-artifacts.json` (~200 KB) one profile at a time with
`vraptor artifacts profiles show --artifact NAME` or `jq '.profiles["NAME"]'`.
Query `resources/windows-rmm-greyware.json` (~120 KB) one tool at a time with
`jq '.tools[] | select(.name == "NAME")'`.

## Source to tests

| Source | Main tests |
| --- | --- |
| `hunt/live.py` | `tests/test_live_hunt_analysis.py` |
| `analyze/coordinator.py`, `analyze/flow_runtime.py` | `tests/test_flow_analysis.py` |
| `analyze/command.py`, `analyze/host.py` | `tests/test_collection_analysis.py`, core `test_core_collection_analysis_cli.py` |
| `analyze/runtime.py` | `tests/test_collection_analysis_runtime.py` |
| `collect/requests.py` | `tests/test_run_velociraptor_collection.py` (loads the file by path) |
| `hunt/operations.py` | `tests/test_run_velociraptor_hunting.py` (loads the file by path) |
| `hunt/command.py`, `hunt/analysis.py` | `tests/test_hunt_workflow.py` (loads the files by path) |
| `autoruns/golden.py` | `tests/test_autoruns_golden.py` |
| `artifacts/inventory.py` | `tests/test_velociraptor_artifact_selection.py` (loads the file by path) |
| `cli.py`, `legacy_cli.py` | core `test_short_cli.py`, `tests/test_velociraptor_cli.py` |
| `readiness.py` | `tests/test_engagement_state.py` |

Tests that load a file by path patch their own copy of the module, so
`rg 'from vraptor.collect import requests'` misses them; search for the file name.

## Names that mislead

- The same function name exists in several modules: `analyze_artifact` and
  `command_analyze` (`hunt/live.py` or `hunt/command.py`, and `hunt/analysis.py`),
  `command_status` (`hunt/command.py`, `hunt/operations.py`), `load_state`
  (`hunt/live.py`, `analyze/coordinator.py`, `autoruns/publication.py`),
  `write_state` (`analyze/coordinator.py`, `collect/requests.py`) and `hunt_dir`
  (`case_layout.py`, `hunt/operations.py`). Confirm the module before editing.
- Route target `collection_analysis` means `analyze/command.py`, but tests import
  `analyze/host.py` under the alias `collection_analysis`.

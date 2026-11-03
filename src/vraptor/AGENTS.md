# vraptor runtime

This folder is mirrored between two repositories through a sync manifest, so
keep new text here repo-agnostic: no repository names, private hosts or
identities.

- Map of commands, packages and tests: [repo-map.md](../../docs/contracts/repo-map.md).
- Entry point is `cli.py:main` for both `vraptor` and `dfir`; most areas then
  dispatch through `legacy_cli.py`, which is the live router despite its name.
- Do not read `hunt/live.py`, `analyze/coordinator.py`, `collect/requests.py`,
  `hunt/operations.py`, `hunt/command.py` or `autoruns/golden.py` whole
  (about 4k-10k lines each). Find the symbol with `rg -n '^(async )?def name'`, then read
  a line range.
- Several modules define the same function name (`analyze_artifact`,
  `load_state`, `command_status`); confirm the module before editing.
- Runtime code must work from an installed wheel: never import from `skills/`
  or `utils/`, and resolve packaged files through `vraptor.resources`.
- Some tests load a module by file path and patch that copy, so moving a symbol
  can silently bypass their patches; check the map's test table first.

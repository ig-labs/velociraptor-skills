# Configuration

Keep reusable operational settings in `~/.config/vraptor/config.toml`, or
`$XDG_CONFIG_HOME/vraptor/config.toml`. Select another file with
`--settings-file`. Start with the [generic template](config/vraptor.example.toml).
Native API YAML and SSH keys remain protected files referenced by path.

```sh
./vraptor setup configure --case-root ~/cases
./vraptor setup configure --velociraptor-bin ~/velociraptor/velociraptor
./vraptor setup configure --server-profile lab --api-client /configs/lab_api_client.yaml
./vraptor setup show --server-profile lab
```

Operational precedence is explicit arguments, process environment, selected
credential dotenv, repository `.env`, shared `~/.codex/.env`, TOML, then defaults.
An investigation-local `.env` is not loaded. The native executable defaults to
`~/velociraptor/velociraptor`; tool preparation and setup use the same setting.

Preview legacy environment migration with `./vraptor setup migrate
--server-profile lab`; add `--write` to save nonconflicting values. Migration
preserves existing TOML values and does not remove original dotenv overrides.

## Analyst configuration

Analyst profiles live separately in `~/.config/vraptor/analyst-agents.toml`.
Default-path resolution migrates the legacy `ai_skills` file only when the new
destination is absent; explicit paths remain unchanged. Ollama is no longer a
supported provider. The `agent` command remains an alias for `ai`.
Use [the profile example](config/analyst-agents.example.toml),
[installation guide](docs/vraptor-installation.md), and
[model execution reference](docs/model-execution.md).

```sh
./vraptor ai setup
./vraptor ai config
./vraptor ai doctor
```

Use `setup configure --analyst-config-file PATH` to save a reference to that
file. Explicit analyst `--config-file` and
`AI_SKILLS_ANALYST_AGENT_CONFIG_FILE` override it. Keep API keys in environment
variables or a selected credential dotenv, never in committed templates.
Offline diagnostics do not prove authentication or inference. `ai test`
sends a small synthetic request and should only be run when live testing is wanted.

## Export and deploy current settings

```sh
./vraptor setup export --output ~/.config/vraptor/presets/current.toml
./vraptor setup deploy --from ~/.config/vraptor/presets/current.toml
./vraptor setup deploy --from ~/.config/vraptor/presets/current.toml --apply
```

Export records effective operational settings and connection paths without
copying credentials or analyst configuration contents. Existing exports are
never overwritten. Deploy previews by default, merges selected settings, and
backs up the changed file. Review `setup show` afterward.

## Reset Velociraptor setup preferences

```sh
./vraptor setup reset
./vraptor setup reset --apply
```

Reset previews by default. Applying it backs up changed files and clears
operational preferences while retaining credential and analyst references,
investigations, and installed tools. Only apply the reset to the intended settings.

See the [setup workflow](skills/velociraptor-engagement-setup/SKILL.md) and
[manual acceptance guide](docs/velociraptor-setup-testing.md) for connection modes,
readiness, mapping ownership, and remote provisioning requirements.

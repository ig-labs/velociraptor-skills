# Configuration

Keep reusable operational settings in `~/.config/vraptor/config.toml`, or
`$XDG_CONFIG_HOME/vraptor/config.toml`. Select another file with
`--settings-file`. Configure them with the interactive wizard; the
[generic template](config/vraptor.example.toml) is optional.
Native API YAML and SSH keys remain protected files referenced by path.

```sh
./vraptor setup configure
./vraptor setup show --server-profile lab
```

Run the bare configure command in a terminal to reach every section, including
the optional AI handoff. Setting flags such as `--case-root` perform targeted
configuration and skip the interactive wizard. Package installation is separate:
`utils/install.sh` creates/reuses `.venv` and installs dependencies only.

A repository `.env` is not required. Keep provider secrets in a selected
credential file or process environment, and use TOML for reusable preferences.
The wizard records file references without copying secret values.

Operational precedence is explicit arguments, process environment, selected
credential dotenv, repository `.env`, shared `~/.codex/.env`, TOML, then defaults.
An investigation-local `.env` is not loaded. The native executable defaults to
`~/velociraptor/velociraptor`; tool preparation and setup use the same setting.
The repository launchers only select Python and import paths; Python resolves
settings. Existing dotenv overrides can mask changes made in the wizard:
inspect effective sources with `./vraptor config` and `./vraptor ai config`.

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

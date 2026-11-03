# Engagement setup configuration

Reference for [velociraptor-engagement-setup](../SKILL.md). Read it before
changing saved operational settings, configuring the analyst agent, exporting,
deploying or resetting settings, or interpreting the configuration checks that
`setup init` reports.

## Operational settings wizard

Use bare `vraptor setup configure` in a terminal for the complete operational
wizard and optional AI handoff. No repository `.env` is required: save reusable
preferences in TOML and reference existing credential files or process credentials.
Environment/dotenv overrides remain supported and can mask wizard changes;
inspect effective sources before changing a saved value again.

```bash
vraptor setup configure
# Targeted updates skip the interactive wizard and AI handoff:
vraptor setup configure --case-root ~/cases
vraptor setup configure --server-profile lab --api-client /configs/lab_api_client.yaml
vraptor setup show --server-profile lab
vraptor setup migrate --server-profile lab          # Preview legacy env migration
vraptor setup migrate --server-profile lab --write  # Apply nonconflicting settings
```

The default file is `$XDG_CONFIG_HOME/vraptor/config.toml`, otherwise
`~/.config/vraptor/config.toml`; `--settings-file` selects another file.
`workstation.binary` defaults to `~/velociraptor/velociraptor` and is shared by
installation and execution. Use `setup configure --velociraptor-bin PATH` before
installing elsewhere or after moving an existing binary.
With no setting flags or template, `configure` runs a terminal wizard grouped
under spaced headings: workstation, remote connection, remote SSH access, local
server, mapped evidence, advanced paths/API transport, and credentials. Optional
sections can be skipped; Enter preserves saved fields. `--server-profile NAME`
edits that named connection; a blank name edits shared connection defaults.
The wizard writes settings only and does not connect, fetch credentials, provision
accounts or start resources. It supports `--preview` and `--template`, and keeps
one backup when replacing an existing file. TOML holds
workstation paths, optional named connections, a credential-env-file reference
and advanced lifecycle defaults. It references native API YAML and SSH-key paths;
never copy credential contents into TOML. `show` reports effective non-secret
values and their sources. Migration preserves conflicting TOML values and leaves
the original dotenv files and their override behavior intact.

## Settings precedence and inspection

Remote profiles inherit `api_user` and `api_role_profile` from
`[connection_defaults]`, including previously unseen profile names. Precedence is
CLI > environment/dotenv > named connection > connection defaults > application
defaults (role profile `provisioning-admin`; no remote API username). Configure
`api_user` or pass `--api-user` before fetching or provisioning API credentials.
Interactive configure leaves an unanswered fresh username unset. Existing API YAML
can supply its own identity when no username is selected. Explicit saved identities,
including explicitly selected legacy names, remain authoritative; change unwanted saved values explicitly.
`setup show --server-profile NAME` reports values and sources.
`[connection_defaults]` also supports shared SSH user/key, remote configuration
paths, binary and service account. Named profiles may select `org_id`.
`[api].grpc_max_message_bytes` and `[mapping].startup_timeout_seconds` /
`ready_timeout_seconds` expose validated transport and startup/readiness limits.
Leave unused environment overrides empty so TOML remains effective.

Operational precedence is explicit arguments, process environment, explicitly
selected credential dotenv, repository `.env`, shared `~/.codex/.env`, named
connection, connection defaults, then application defaults. Other TOML sections
also override application defaults. Settings resolve once per operation. The selected credential dotenv
also feeds analyst operations; analyst profiles remain in `analyst-agents.toml`.
Infrastructure setup does not require AI credentials.
Writable investigation, runtime and fetched-credential paths must stay outside
mounted evidence and must not overwrite an evidence image; setup rejects these
overlaps before creating the affected outputs.

Configure reusable operational defaults independently of analyst settings.
Inspect operational settings with `vraptor config` and analyst settings with
`vraptor ai config`. Both accept `--view effective` (default) or `--view defaults`
and print JSON; defaults inspection ignores local files and environment overrides.
`vraptor config --server NAME` reports the same effective values and sources as
`setup show`. Use `setup configure` and `ai setup` to configure each subsystem.

## AI analyst configuration

This is the full analyst-agent setup walkthrough for the Velociraptor skills.
Runtime budgets, providers and execution rules are in
[model execution](../../../docs/model-execution.md).

Interactive configure offers an **AI analyst configuration** section with
`Configure AI analyst settings [Y/n]:`. Enter or Yes saves operational settings,
then opens the existing `vraptor ai setup` wizard using that settings file. No
skips it. New setups suggest server name `live` and AI provider `openai`; saved
selections remain authoritative. Enter `-` at the server-name prompt for shared
defaults/local-only configuration. Preview never launches AI setup; a failed wizard leaves operational settings
saved and reports a retry command. AI wizard output goes to stderr.

When AI setup is skipped, or after successful start/resume, setup prints
`To configure AI, run: vraptor ai setup`, retaining any explicit settings-file
selector. `agent` remains an alias for `ai`. The note goes to stderr so JSON
stdout remains parseable; the wizard is not started automatically.

### Select the analyst file

Without an explicit analyst path, the default is
`~/.config/vraptor/analyst-agents.toml` (XDG-aware); the legacy `ai_skills` file
migrates only when the destination is absent, preserving contents and permissions.
Optionally select a shared analyst TOML with `setup configure
--analyst-config-file PATH`, stored as `[analyst].config_file`. `setup show`
reports the selected analyst path, existence and an `inspect_command` for
`vraptor ai config`, without dumping analyst settings or loading a provider.
Use the reported command to retain the same operational settings file and
credential source. Analyst `--config-file` and the existing
`AI_SKILLS_ANALYST_AGENT_CONFIG_FILE` environment/dotenv override take precedence.

### Configure and check the profile

When setup includes the analyst agent:

1. Inspect the selected profile with `vraptor ai config`.
2. Run `vraptor ai setup` interactively to review or configure it.
3. Rerun `vraptor ai config` and `vraptor ai doctor`.

Carry the same operational `--settings-file`, analyst `--config-file` and
`--execution-profile` selectors where explicitly selected. Reuse the intended
provider/model and preserve shared analysis budgets. Configure this shared profile
once across investigations; operational export/deploy transfers its file
reference, not analyst settings or credentials. Report the effective profile and
offline diagnostic status separately from server readiness. See the
[setup test guide](../../../docs/velociraptor-setup-testing.md#configure-the-analyst-agent-once)
for the command sequence and limits of offline checks.

### Providers, harnesses and models

- `vraptor ai setup --from-harness codex` reuses Codex settings;
  `--from-harness claude_code` uses Claude-managed login.
- Claude settings discovery prefers an explicit/saved file, then
  `~/Library/Application Support/Claude/settings.json`, then
  `~/.claude/settings.json`; enter a model if neither automatic file exists.
- Use `--provider anthropic --model MODEL_ID` for a separate Anthropic API-key
  profile. Azure requires the deployment name.
- The wizard offers advanced API settings and optional native Claude login; it
  never imports Desktop `config.json` tokens. A native login check is not an
  inference or server check.
- `vraptor ai setup --help` lists grouped options and offline OpenAI/Claude model
  examples. The model prompt shows provider-specific suggestions while accepting
  other supported IDs and preserving saved defaults. These examples do not
  establish account access.
- The reasoning-effort prompt likewise lists model-specific choices, including
  `xhigh` where supported. Enter preserves/inherits effort; recognized Claude
  models with effort support default to `medium` only if no explicit, saved,
  shared or native effort exists. Haiku 4.5 and unknown models receive no
  automatic effort setting.

### Analysis token budgets

The AI wizard groups **Analysis token budgets** separately and saves
`max_input_tokens` / `max_output_tokens` in the selected analyst profile. Inspect
the resolved values and sources with `vraptor ai config`.

- Setup displays the resolved model's published context, standard-price input
  ceiling, output maximum and reference defaults. Per-model figures are in
  [shared token budgets](../../../docs/model-execution.md#shared-token-budgets).
- Known models default to their output recommendation and reference input
  default (the maximum remaining standard-price input unless that table lists a
  lower default), including reruns; smaller model/deployment limits still apply.
  Known models record their context on new and existing profiles, preserving
  explicit smaller deployment caps.
- New OpenAI/Azure profiles suggest 272000 / 128000, deriving 400000 context and
  keeping the shared 200000 evidence ceiling.
- Listed Claude aliases (`opus`, `sonnet`, `haiku`, `fable`, `best`) use the
  reference limits of the model they currently name, and setup names that
  reference model. Unknown IDs and custom deployments show unverified limits and
  use saved/application fallbacks. Do not treat these offline API references as
  account discovery or managed-plan price guarantees.
- On the Claude Code route, Opus/Sonnet 4.6 without `[1m]`, and every model while
  `CLAUDE_CODE_DISABLE_1M_CONTEXT` is `1`, `true`, `yes` or `on`, use a 200000
  context with 64000 output / 120000 input defaults (Haiku 5.5: 100000 input).
  Setup and runtime read the variable from Claude Code's managed settings files,
  the process environment and `.env` (not server-managed settings, MDM policies or
  `~/.claude.json`), and pass it to Claude Code. While it is set, runtime lowers saved profile budgets that overflow 200K to
  those defaults; rerun setup after changing it. See
  [shared token budgets](../../../docs/model-execution.md#shared-token-budgets).
- Setup selects output first and shows the exact remaining input maximum. `max`
  or `auto` at a prompt fills that field's available capacity. Prompt brackets
  show the calculated default, e.g. `Maximum input tokens [872000] (Enter to keep):`.
- Input must be at least 100000 tokens and output at least 32000; a model or
  deployment that cannot hold both is rejected.
- The default `--auto-token-budgets` replaces saved budgets with those model
  output recommendations and reference input defaults.
  `--no-auto-token-budgets` retains saved budgets within the allowed range, with a
  note if they differ from the reference. Oversized saved budgets default to the
  applicable maximum, with a reduction note.
- Oversized interactive entries are adjusted with an explanation; invalid CLI
  flags fail before writing. JSON reports include maxima and adjustments; runtime
  environment precedence is unchanged.
- The fixed 25% context reduction is removed from setup and runtime; evidence
  reserves remain inside input.

See [shared token budgets](../../../docs/model-execution.md#shared-token-budgets)
for reserve calculation, environment precedence and legacy compatibility.

## Configuration checks during setup init

`setup init` also checks repository `.env` and shared `~/.codex/.env` sources,
reporting their paths, loading status and accepted key counts without values.
It reuses the offline `vraptor ai doctor` checks for the selected analyst config
file/profile, provider, transport, model, credential presence, dependencies and
analysis limits. Explicit process values retain precedence over repository and
shared dotenv defaults; analyst TOML/harness selection follows the normal resolver.
An investigation-local `.env` is not a configuration source.

Read `configuration_checks.status` and `configuration_checks.analyst_agent.issues`.
Missing dotenv files are allowed when configuration comes from other sources.
Invalid configuration, missing dependencies/credentials and disabled analysts are
reported as needing attention. They do not prevent folder creation or reuse:
exit 0 means initialization succeeded, even when configuration needs fixing.
Use `vraptor ai doctor` for diagnostics and `vraptor ai setup` to configure the
analyst, then rerun initialization or the doctor before analyst execution.

Checks do not modify dotenv, analyst configuration or existing investigation
guidance. Authentication and inference remain untested; startup makes no server
or model requests. A successful offline check does not prove live access.

## Export, deploy and reset settings

Save/deploy/reset reusable operational settings with:

```bash
vraptor setup export --output ~/.config/vraptor/presets/current.toml
vraptor setup deploy --from ~/.config/vraptor/presets/current.toml
vraptor setup deploy --from ~/.config/vraptor/presets/current.toml --apply
vraptor setup reset
vraptor setup reset --apply
```

Export captures effective settings and all named connections without copying
secrets; local home paths become `~`. An environment-only connection needs
`--server-profile NAME`. Deploy and reset preview unless `--apply` is supplied;
an existing export is never overwritten. Reset backs up changed files and clears
only operational preferences/overrides while preserving credential and analyst
references, investigations and tools. Deploy merges snapshot values into the
selected settings file and preserves unrelated entries. Follow user-authorized
deployment/reset scope and inspect `setup show` afterward; see
[configuration recovery](../../../CONFIG.md#export-and-deploy-current-settings).

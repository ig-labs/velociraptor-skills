# Configuration

The default setup uses an **existing Velociraptor server** and the **OpenAI API**.
Configure both through the installer; no manual TOML editing is needed.
For prerequisites and other deployment options, see the
[installation guide](docs/vraptor-installation.md).

## First-time setup

On macOS or Linux, have Python 3.11+, your server's API-client YAML and an
OpenAI API key ready. From the repository root, run in a terminal:

```sh
./utils/install.sh
```

The installer creates/reuses `.venv`, installs the OpenAI, Anthropic and Claude
Agent SDKs, and opens the setup wizard. For the default live-server setup:

1. Choose a **server reference**, such as `production` or `lab`, and enter its
   existing API-client YAML path. `live` is only the initial name suggestion.
2. Keep the displayed workstation defaults and skip optional SSH, local-server,
   mapped-evidence and advanced sections unless you need them.
3. Select your credential file if needed. At **Configure AI analyst settings
   [Y/n]**, press Enter, then accept `openai` at **Connection** and choose a model
   available to your account. Later runs retain saved selections.

Inspect the result, replacing `<SERVER REFERENCE>` with the name you chose:

```sh
./vraptor config --server-profile "<SERVER REFERENCE>"
./vraptor ai config
./vraptor ai doctor
```

These are local checks; they do not test live authentication or inference.
See the [installation guide](docs/vraptor-installation.md#5-test-ai-if-needed)
for optional connection tests and starting an investigation.

## Change settings later

```sh
./vraptor setup configure
# AI settings only:
./vraptor ai setup
```

Enter keeps displayed values. Answer No at the AI prompt to skip AI configuration.
Use `./utils/install.sh --no-configure` for dependency-only upgrades. Installation
without a terminal also skips configuration; open the wizard afterward.

## Multiple server connections

One installation supports multiple servers. Run `./vraptor setup configure`
again and choose a new reference to add a server, or reuse a reference to edit
it. Other connections are preserved, each with its own API-client YAML path.
References identify saved connections, not server URLs or investigation IDs.
Start names with a letter or number; use letters, numbers, dots, underscores or
hyphens, without spaces.

Select one server per command with `--server-profile "<SERVER REFERENCE>"`
(or `--server`). Run `./vraptor config` to list saved names in `connections`.
Named connections live under `[connections.NAME]` and inherit shared
`[connection_defaults]`. AI profiles are configured separately.

## Settings and credentials

| File | Stores |
| --- | --- |
| `~/.config/vraptor/config.toml` | Workstation settings, named servers and credential-file references |
| `~/.config/vraptor/analyst-agents.toml` | AI providers, models and analysis budgets |

Both paths follow `$XDG_CONFIG_HOME` when configured. Keep API-client YAML and
provider keys outside the checkout. Supply `OPENAI_API_KEY` through your process
environment or a credential `.env` selected in the wizard. If asked for the API
key variable name, enter `OPENAI_API_KEY`, not the key itself. The wizard saves
references, not secret values; a repository `.env` is optional.

Operational precedence, highest first: explicit arguments, process environment,
selected credential `.env`, repository `.env`, shared `~/.codex/.env`, TOML,
then defaults. Investigation-local `.env` files are not loaded. If saved settings
appear ignored, inspect their sources with the configuration commands above.

## Export and deploy current settings

Optional: use `./vraptor setup export --output SNAPSHOT.toml` to save preferences
and file references. Preview a restore with
`./vraptor setup deploy --from SNAPSHOT.toml`; add `--apply` to save with a backup.
Credentials and AI profile contents are not copied. See the
[CLI reference](docs/contracts/cli.md#operational-setup) for migration and recovery.

## Reset Velociraptor setup preferences

Optional: `./vraptor setup reset` previews the changes. Add `--apply` to back up
and clear operational preferences, retaining credential and analyst references,
investigations and installed tools.

---
name: prep-dfir-tools
description: Install or refresh shared DFIR tooling on macOS or Linux, including the standalone vraptor Python package, Velociraptor binary, Plaso, Volatility 3, and Sleuth Kit. Use for generic package installation, preparing a DFIR workstation, satisfying missing-tool prerequisites, or validating the local analysis toolchain.
---

# Prepare DFIR Tools

`vraptor tools prep` and `dfir tools prep` share the same preparation handler,
options and targets. Use `vraptor ai config` for safe configuration inspection;
neither inspection nor preparation needs a case. See the [shared CLI contract](../../docs/contracts/cli.md).

Use the shared installer through:

```bash
vraptor tools prep [OPTIONS]
```

Use the installed command from the activated environment below. In `ai_skills`,
the repository launcher `./dfir` is also available. The implementation lives
under `packages/vraptor`. Keep this skill documentation-only.

## Install the Generic Package

For the complete package → operational setup → optional AI → first investigation
walkthrough, use [Install and set up vraptor](../../docs/vraptor-installation.md).
Interactive `vraptor setup configure` saves operational settings and offers the
AI wizard; setting-value flags skip those questions. This skill covers package
and native tool preparation details.

Use Python 3.11 or newer. Start in the exported `velociraptor-skills` checkout
root containing `pyproject.toml`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
source .venv/bin/activate
vraptor --help
vraptor tools prep --help
```

From the `ai_skills` root, keep `.venv` there and replace the pip command with
`.venv/bin/python -m pip install ./packages/vraptor`. Existing environments can
be reused. For a supplied wheel, install its local path instead of the source
directory. Do not assume the package is published on PyPI.

The base package installs the `vraptor` and `dfir` commands and core API
dependencies. It does not install the native Velociraptor executable, link agent
skills, or start a server. Existing remote API credentials need no site integration,
Slack, Azure or AI setup.

Install an optional extra only for the chosen analyst provider by replacing the
pip target above with `'.[ai]'`, `'.[azure]'`, `'.[anthropic]'` or `'.[claude]'`
for OpenAI, Azure, Anthropic Messages or Claude managed login respectively. In
`ai_skills`, use the corresponding `'./packages/vraptor[EXTRA]'` target. Configure
the analyst through the optional AI section of `vraptor setup configure`, or
directly with `vraptor ai setup` later.

The two help commands verify that the installed CLI and packaged prep helper
load without contacting a server. Report the selected environment and package
location; live authentication remains untested.

For mapping or a managed local server, install the native binary below unless
one is already available. Existing remote live API work does not require it.
Then use [velociraptor-engagement-setup](../velociraptor-engagement-setup/SKILL.md)
for reusable settings and the three investigation workflows. Connection
profiles may reference existing API and endpoint YAML in a common directory;
installation does not move credentials or create investigation runtime state.

## Common Operations

Install only the Velociraptor binary:

```bash
vraptor tools prep -t velociraptor
```

Installation and execution share `[workstation].binary` in
`~/.config/vraptor/config.toml` (or the selected operational settings file).
With no configured path or legacy `VELO_BIN` override, the destination is:

```text
~/velociraptor/velociraptor
```

Select a custom executable path before installation:

```bash
vraptor setup configure --velociraptor-bin /opt/dfir/velociraptor
vraptor setup show
vraptor tools prep -t velociraptor
```

The default is independent of the checkout or current directory. Volatility/TSK
continue using `<AI_SKILLS_TOOLS_DATA_ROOT>/tools`, defaulting to `<repo>/tools`.
Outside a recognized checkout, those tools use the current directory as the repo.

The default operation does not start a local GUI or initialize a local
Velociraptor datastore. This makes it appropriate for remote mapped-client and
live-API work.

When `--init-velociraptor-workspace` is selected, an empty
`VELO_LOCAL_API_PASSWORD` leaves Velociraptor instant mode's loopback-only GUI
credentials at their native default (`admin` / `password`). Set
`VELO_LOCAL_API_PASSWORD` explicitly only when the selected
`VELO_LOCAL_API_USER` must be created or updated with a password. This mode is
for local testing, not a production deployment.

Initialize a deliberate local GUI/API workspace only when required:

```bash
vraptor tools prep \
  -t velociraptor \
  --init-velociraptor-workspace
```

Prepare the repository Python environment:

```bash
vraptor tools prep -t venv
```

Install Plaso into `./.venv`:

```bash
vraptor tools prep -t plaso
```

Install one other tool or the full supported set:

```bash
vraptor tools prep -t volatility
vraptor tools prep -t tsk
vraptor tools prep -t all
```

Use a custom staging directory:

```bash
vraptor tools prep -d /opt/dfir -t velociraptor
```

`-d` selects the parent: the binary above is `/opt/dfir/velociraptor/velociraptor`.
Save that override if it should also become the execution default:

```bash
vraptor setup configure --velociraptor-bin /opt/dfir/velociraptor/velociraptor
```

An existing installation only needs `setup configure --velociraptor-bin` set to
its executable; the legacy `VELO_BIN` environment setting also works. No download
is required. A bare command such as `velociraptor` is resolved on `PATH`; prep
fails if it is missing, so select an executable path or use `-d` in that case.
Check the selected destination before installation because prep
replaces an existing binary there. The installer supports macOS/Linux only;
native Windows and literal `$USERPROFILE` expansion in dotenv paths are not
implemented. Keep service datastores and existing configuration intact during
relocation.

## Requirements

- macOS or Linux
- Python 3.11 or newer for the `vraptor` package and `./.venv`
- package-index access for Python dependencies, or an available offline wheel set
- outbound HTTPS for GitHub release downloads
- `curl` and `tar`
- Homebrew on macOS for automatic Sleuth Kit and `pkg-config` installation
- native build prerequisites when Plaso or Sleuth Kit cannot use packaged
  dependencies

## Configuration

- `workstation.binary`: installation and execution path; default `~/velociraptor/velociraptor`
- `VELO_BIN`: legacy override of that executable path
- `AI_SKILLS_TOOLS_DATA_ROOT`: shared mutable tools-data root for other tools
- `VELO_LOCAL_VERSION_TAG`: optional pinned Velociraptor release tag
- `VELO_LOCAL_API_USER`: local GUI/API user, default `velociraptor`
- `VELO_LOCAL_API_PASSWORD`: optional local GUI/API bootstrap password
- `VELO_LOCAL_PORTS`: local workspace ports checked during shutdown
- `PLASO_VERSION`: Plaso version, default `20260512`

The installer prints the `setup configure --velociraptor-bin` command for the
installed path. Run it when changing the execution default, such as after `-d`
or moving an existing binary. Installation does not modify TOML, `.env` or `safe.env`.

## Guardrails

- Do not initialize a local Velociraptor GUI for remote-only mapped-client
  work.
- Do not overwrite evidence, case data, API credentials, or endpoint client
  configurations.
- Do not commit downloaded binaries, extracted tool trees, virtual
  environments, or generated Velociraptor datastore files.
- Pin `VELO_LOCAL_VERSION_TAG` when repeatable tool versions are required.
- Treat system package installation and source compilation as host mutations;
  review printed commands and failures.

# Install and set up vraptor

Use this guide for the complete workstation setup: install the Python package,
configure an existing live Velociraptor server and OpenAI analysis, check the settings,
then start a live or mapped investigation. Commands assume macOS or Linux with
Python **3.11 or newer** and a supplied source checkout or wheel.

The default path uses an existing server's API-client YAML and an OpenAI API
key. Local servers, mapped evidence and other AI providers are optional.
Commands use `"<SERVER REFERENCE>"` for the saved connection name selected during
setup. Replace the whole placeholder with that name; it is not a server URL.

Before installation:

- Install Git and Python 3.11+ with `venv` support. Check `git --version` and
  `python3 --version`. On macOS, install a current Python from
  [python.org](https://www.python.org/downloads/macos/) if the system Python is too old.
  On Debian/Ubuntu, install the distribution's `python3`, `python3-venv` and `git`
  packages, and check that its Python meets the version requirement.
- Obtain an existing API-client YAML from your Velociraptor administrator.
  Store it outside the checkout, for example `~/.config/vraptor/live-api.yaml`,
  with permissions `chmod 600 ~/.config/vraptor/live-api.yaml`. The YAML contains
  the API endpoint and credentials; a web GUI URL or password is not a substitute.
  Connect your VPN if the server requires it. Setup does not generate API users.
- Supply `OPENAI_API_KEY` from your secret manager/process environment, or create
  a credential file in your editor outside the checkout, such as
  `~/.config/vraptor/credentials.env`, containing `OPENAI_API_KEY=your-key`.
  Before creating it, run `umask 077` and `mkdir -p ~/.config/vraptor`; restrict
  the saved file with `chmod 600 ~/.config/vraptor/credentials.env`, then select
  it in the wizard.
  Use your own key from the [OpenAI API quickstart](https://developers.openai.com/api/docs/quickstart).
  The OpenAI route uses API credentials, not a Codex/ChatGPT application login.

| Stage | Command | Result |
| --- | --- | --- |
| Install | `./utils/install.sh` | Installs vraptor + OpenAI/Anthropic/Claude SDKs and opens configuration in a terminal |
| Configure | `vraptor setup configure` | Saves operational settings and offers the AI wizard |
| Inspect | `vraptor config`, `vraptor ai config`, `vraptor ai doctor` | Checks local configuration without inference |
| Test AI (optional) | `vraptor ai test` | Sends one small synthetic model request |
| Start an investigation | `vraptor setup start --mode ...` | Connects to Velociraptor or starts the requested local resources and verifies readiness |

There is no separate `vraptor ai install` command. AI support is installed as
Python package extras and configured within the operational setup flow. You can
skip AI configuration and add it later. A hosting Codex/Claude application and
vraptor's analyst profiles have separate settings.

1. [Install the package](#1-install-the-package)
2. [Configure Velociraptor and choose the AI handoff](#2-configure-velociraptor-and-choose-the-ai-handoff)
3. [Configure AI if selected](#3-configure-ai-if-selected)
4. [Inspect the configuration offline](#4-inspect-the-configuration-offline)
5. [Test AI if needed](#5-test-ai-if-needed)
6. [Start the first investigation](#6-start-the-first-investigation)
7. [Override AI settings for one analysis](#7-override-ai-settings-for-one-analysis)

## 1. Install the package

Clone the public repository, or open your existing checkout:

```sh
git clone https://github.com/ig-labs/velociraptor-skills.git
cd velociraptor-skills
```

From the repository root, run this in a terminal:

```sh
./utils/install.sh
```

The installer checks Python 3.11+, creates/reuses `.venv`, installs editable
vraptor with `.[ai,anthropic,claude]`, and opens `setup configure` automatically.
OpenAI remains the default provider; both direct Anthropic API and Claude-managed
login routes have their SDK dependencies available when selected. Each route
still needs its own credentials/login. Azure Entra remains an optional `azure` extra.
Continue with step 2 when the wizard opens. For upgrades, use
`./utils/install.sh --no-configure`; add `--no-path` for dependency-only installation
or CI. Runs without a terminal also skip the wizard. `--configure` requires a
terminal and explicitly requests it.
Set `PYTHON_BIN=/path/to/python3.12` when `python3` selects an older interpreter.
An outdated existing `.venv` must be replaced separately after preserving anything
needed; the installer does not silently delete it.
Skill/agent linking remains optional in the [repository instructions](../README.md#install).

Commands below use bare `vraptor`. The installer adds the checkout to its `PATH`
and saves a guarded entry if missing in `~/.zshrc` for zsh (respecting `ZDOTDIR`)
or `~/.bashrc` for Bash, based on `SHELL`. The root `vraptor` and `dfir` launchers
select the checkout's source and `.venv` automatically. Open a new terminal or
run the printed export in your existing terminal. For example:

```sh
export PATH="$HOME/git/velociraptor-skills:$PATH"
vraptor --help
dfir --help
```

An installer subprocess cannot change its parent terminal's environment. The
printed export uses your actual checkout path. For an existing installation,
`./utils/install.sh --path-only` saves the PATH entry without reinstalling
dependencies or opening the wizard. `--no-path` disables PATH setup. Unsupported
shells receive manual guidance without startup edits. Bash login shells need
their login profile to source `~/.bashrc`; existing login profiles are preserved.
New processes must inherit the updated `PATH` to find these commands.
Keep the checkout available; moving it requires updating this entry and any
installed skill links. Use `command -v vraptor` and `command -v dfir` to check for
another installation taking precedence.

You can also use `./vraptor` or `./dfir` from the checkout, their absolute paths,
or activate `.venv` with `source .venv/bin/activate` for that terminal.

For an equivalent manual install, create a venv and run
`python -m pip install '.[ai,anthropic,claude]'`.
In the upstream `ai_skills` checkout use `./packages/vraptor[ai,anthropic,claude]`
as the pip target. Install a supplied wheel by its local path with the same extras.
These instructions do not assume a package published on PyPI.

For a smaller installation, select only the extras you need:

| Connection | Pip extra | Credential source |
| --- | --- | --- |
| Velociraptor without AI | None: `.` | Existing Velociraptor API YAML |
| OpenAI or Azure API key | `ai` | `OPENAI_API_KEY` or `AZURE_OPENAI_API_KEY` |
| Azure Entra | `azure` | Configured Azure identity |
| Anthropic API | `anthropic` | `ANTHROPIC_API_KEY` |
| Claude-managed login | `claude` | Native Claude login |
| Codex-managed login | Base package plus native `codex` on `PATH` | Native Codex login; add the provider extra for a direct imported API route |

For example, OpenAI-only installation uses
`python -m pip install '.[ai]'`.
The Python package does not install Codex. Native login/setup details are below.
If the repository requirements are already installed, vraptor is included;
add any missing provider extra to the same environment.

With the repository on `PATH`, both root launchers work from other directories
without activating the virtual environment or changing the working directory.
`dfir` is an equivalent command. Installing Python dependencies does not install
the native Velociraptor executable, start a server or link skills into a harness.

## 2. Configure Velociraptor and choose the AI handoff

Run this in a terminal for the grouped interactive wizard:

```sh
vraptor setup configure
```

No repository `.env` is required. The wizard saves reusable preferences in TOML;
the optional Credentials section selects an existing credential file. Process
environment and legacy dotenv files remain supported overrides. They can mask
saved settings, so inspect effective sources after configuration.
If a saved credential file has moved, the wizard can repair its path; operational
commands still fail when their selected credential file is missing.

Choose a server reference at the saved-server-name prompt, then enter the path
to that server's existing API-client YAML. A fresh setup suggests `live`; this
is only a suggested name. Later, a single saved server is suggested automatically.
Enter `-` for shared connection defaults or local-only work.

The same installation supports multiple servers. Run setup again with a different
reference to add another connection, or reuse a reference to edit it while
preserving the others. With several saved servers, choose the one to edit
explicitly. Select the intended server for each command with
`--server-profile "<SERVER REFERENCE>"` or `--server "<SERVER REFERENCE>"`.
Run `vraptor config` to list saved names in `connections`. See
[multiple-server configuration](../CONFIG.md#multiple-server-connections) for
profile storage, naming and override behavior.

| Wizard section | Configure it for |
| --- | --- |
| **Workstation** | All workflows: investigation parent and preferred local Velociraptor binary path |
| **Remote connection** | Remote live/mapped work: saved server name, existing local API-client YAML, optional SSH server address, organization and API identity |
| **Remote SSH access** | Optional credential retrieval/provisioning: SSH account/key and remote paths; no remote commands run during configure |
| **Local server** | Local mapped work: local server API username and ports |
| **Mapped evidence** | Local/remote mapped work: supervision limits; remote mappings also need an existing endpoint-client YAML |
| **Advanced paths and API transport** | Optional local configuration/runtime paths and gRPC message-size limit |
| **Credentials** | Optional path to a credential `.env`; enter the path, not key values |
| **AI analyst configuration** | Open the AI wizard after saving operational settings |

The configuration prompts do not connect to Velociraptor, fetch credentials,
create accounts or start a case. Setting an API username alone does not create
that server identity. On a fresh configuration it defaults to `vraptor`, with
`provisioning-admin` as the role profile; existing explicit values are retained.
Named connections inherit shared `[connection_defaults]` unless overridden.
An existing API YAML's embedded server address is used for API connections;
the optional server address in setup is for SSH acquisition.

To configure both operational and AI settings, accept the default with Enter:

```text
AI analyst configuration
────────────────────────
Configure AI analyst settings [Y/n]:
```

Operational settings are saved first, then the same `vraptor ai setup` wizard
opens. Continue at step 3. Answer No to skip AI and print the command for later.
A failed AI wizard leaves the operational settings saved and reports a retry
command. The AI wizard may offer a separate native login check/sign-in; it does
not send an inference request as part of saving settings.

Use the bare command above to get every relevant wizard section. Setting flags
such as `--case-root` skip the interactive questions and AI handoff. Saved settings
are managed interactively; the analysis flags in step 7 are optional overrides
for individual runs.

### Optional SSH-agent enrollment

The wizard saves SSH user/key references. To unlock an existing key in your
local agent, use `ssh-add /path/to/private-key`. On macOS, use
`ssh-add --apple-use-keychain /path/to/private-key` when Keychain storage is wanted.
The native tool obtains the passphrase locally. Configuration does not load keys,
remove existing agent entries or provision remote access.

### Native binary for mapped evidence or a local server

Existing remote live API access does not need a local native executable.
Both mapped modes need it. If it is already installed, save its path at the
**Preferred local Velociraptor binary path** prompt. Otherwise, after saving
the desired path, install it with:

```sh
vraptor setup show
vraptor tools prep -t velociraptor
```

The installer uses the configured path (default `~/velociraptor/velociraptor`)
and replaces a binary already there; inspect the path before running it.
This command installs the executable without starting a server or creating a
local datastore. `setup start --mode local-deaddisk` manages the case's local
server later. Other DFIR tools are optional; see
[prep-dfir-tools](../skills/prep-dfir-tools/SKILL.md).

## 3. Configure AI if selected

If you answered Yes in step 2, this wizard is already open. Otherwise start it
when ready:

```sh
vraptor ai setup
```

The wizard groups connection, model, concurrency and token settings under
separate headings. Enter accepts the displayed value:

| Prompt | What to enter |
| --- | --- |
| Connection | `codex`, `claude_code`, `openai`, `azure_openai` or `anthropic` |
| Profile name | A descriptive name such as `azure_work` or `codex_work` |
| Harness config file | For Codex/Claude, accept the discovered/saved path or enter an explicit file; Claude can use an entered model if neither default file exists |
| Advanced API settings | Optional endpoint, authentication mode and credential environment-variable name; never enter a secret value |
| Azure endpoint URL | For direct Azure, the endpoint supplied by your administrator |
| Model ID / deployment name | OpenAI/Claude examples and descriptions appear before the prompt; enter any supported ID. For Azure, use the **deployment name**; harness profiles can inherit |
| Reasoning effort | Model-specific options include `xhigh` where supported; recognized Claude models default to `medium` when no effort is saved/inherited. Enter keeps the displayed value; Haiku has no effort setting |
| Timeout seconds | Request deadline; a new profile suggests `600` |
| Maximum concurrency | Maximum active requests per analysis scope; start conservatively for your quota |
| Maximum output tokens | Known model recommendation: Haiku 4.5 `32000` (model maximum `64000`); other known models use their output maximum; OpenAI/Azure fallback `128000` |
| Maximum input tokens | Maximum remaining standard-price capacity after output; OpenAI/Azure fallback `272000`. Enter a smaller allowed number if required |

New direct OpenAI/Azure profiles suggest a model and reasoning effort. Check these
against your account or deployment before accepting them. The wizard does not
query your account for available models: the displayed examples are offline
guidance, also shown by `ai setup --help`.
For a new installation, Enter selects `openai`, profile name `openai`, and the
existing suggested model `gpt-5.6-luna`. Its supported API identifier is documented
in the [OpenAI model reference](https://developers.openai.com/api/docs/models/gpt-5.6-luna).
Advanced API endpoint/authentication changes are unnecessary for the standard
OpenAI route. The key is read from `OPENAI_API_KEY`; it is never copied into TOML.
An existing default profile keeps its provider and saved model settings.
The **Analysis token budgets** section asks for output first, then calculates and
displays the available input. Enter `max` or `auto` to use a field's displayed
maximum. Automatic budgets are enabled by default for known models: output uses
the model recommendation and input fills the remaining standard-price capacity.
The calculated default is shown in brackets. Enter a smaller allowed number
at the prompt if that is the budget you want to save.
Input has a 100000-token minimum when available input is at least 100000;
smaller available contexts use a lower minimum. Higher saved values default
to the applicable maximum, with the reduction displayed. Interactive entries
above the maximum are adjusted with an explanation; malformed entries can be
corrected in the wizard.
Known models enforce the standard-price input allowance and output maximum;
smaller configured context/output limits also apply. Verify
the budgets against the model's limits before analysing evidence. See
[shared token budgets](model-execution.md#shared-token-budgets).

Setup prints `config_file`, `execution_profile` and `default_profile`. The normal
destination is `~/.config/vraptor/analyst-agents.toml`, or
`$XDG_CONFIG_HOME/vraptor/analyst-agents.toml` when XDG is configured. An operational
`[analyst].config_file`, environment setting or `--config-file` can select another
destination. Use the reported path as the authority.
Without an explicit path, an existing legacy `ai_skills/analyst-agents.toml` under
the same configuration root migrates to the new path with contents and permissions
preserved, only if the destination is absent. Explicit paths remain unchanged.

Operational and AI inspection use matching commands:

| Purpose | Operational settings | AI settings |
|---|---|---|
| Effective configuration | `vraptor config` | `vraptor ai config` |
| Built-in defaults | `vraptor config --view defaults` | `vraptor ai config --view defaults` |
| Configure | `vraptor setup configure` | `vraptor ai setup` |

Both inspection commands print JSON and default to `--view effective`.
See [operational configuration](../CONFIG.md) for connection selectors and sources.

The first profile becomes the default. When adding or updating a different profile,
interactive setup ends by asking whether to make it the default. Answer Yes to
update `[selection].default_profile`; Enter or No keeps the current selection.
Reruns retain other profiles and saved connection settings and keep one rotating
`.bak` copy. Known-model token budgets use automatic recommendations by default;
enter any smaller desired budget again when editing that profile.
TOML contains settings and credential variable names, never API keys.

### Direct API connection

Choose the connection in the wizard, then provide its model/deployment and
endpoint when prompted:

| Connection choice | Example profile name | Required details |
| --- | --- | --- |
| `openai` | `openai_work` | OpenAI model ID; `OPENAI_API_KEY` in the credential source |
| `azure_openai` | `azure_work` | Azure endpoint URL, deployment name and `AZURE_OPENAI_API_KEY` (or choose Entra in advanced authentication) |
| `anthropic` | `claude_api` | Claude model ID; `ANTHROPIC_API_KEY` in the credential source |

Provide `AZURE_OPENAI_API_KEY` through your process environment or the credential
file selected in setup. The ignored repository-root `.env` remains an optional
compatibility source. The **Advanced API settings** section lets you
choose a different credential variable name, authentication mode or endpoint.
To select a credential dotenv, enter its path in the **Credentials** section
of `vraptor setup configure`.
Use your approved secret store; do not put the key in TOML or command arguments.
Connect the required VPN before testing a private endpoint.

### Reuse a native harness configuration

Choose `codex` or `claude_code` at the connection prompt and give the profile a
name such as `codex_work` or `claude_work`.

Accept or replace the native configuration path when prompted. The saved profile
imports its supported routing/model settings. A Codex configuration pointing to
Azure/API credentials continues to use that API route; selecting Codex does not
force a managed-login connection. Inspect the resulting protocol in step 4.
For native OpenAI managed login, authenticate if needed using
`vraptor ai login --harness codex`. Advanced transport choices are documented in
[model execution](model-execution.md#providers-and-authentication).

For `claude_code`, the wizard offers a native login check and sign-in after
saving; Enter skips it. You can also sign in later with
`vraptor ai login --harness claude_code`.
Claude discovery checks `~/Library/Application Support/Claude/settings.json`
before `~/.claude/settings.json`. Explicit and saved paths take precedence and
must exist. If neither automatic location exists, enter a model when prompted.
A malformed selected file is an error, not a reason
to silently switch files. Desktop `config.json` tokens are not imported.

Models, input/output budgets, timeout and concurrency are per profile.
Full transport and authentication details are in
[model execution](model-execution.md#providers-and-authentication).

## 4. Inspect the configuration offline

Inspect operational settings first. For remote work, select the server profile
you configured; for local-only work, omit `--server-profile "<SERVER REFERENCE>"`:

```sh
vraptor config --server-profile "<SERVER REFERENCE>"
```

Check paths, API username, organization and value sources. This command reads
configuration; it does not prove connectivity. If you configured AI, also run:

```sh
vraptor ai config
vraptor ai doctor
```

Confirm the effective provider, model, protocol, profile and credential presence.
`doctor` should report `status: ready` and an empty `issues` list. Its
`authentication: not_checked` and `inference: not_tested` are expected: this check
does not contact the model. Environment/dotenv overrides still apply to saved
profiles; inspect configuration provenance if the effective values are unexpected.

These commands inspect the saved default AI profile. To inspect another profile,
append `--execution-profile NAME`; use the same selector for its optional AI test.
Analysis `--profile` selects analysis behaviour, while `--execution-profile`
selects an AI connection/model profile.

Settings and credentials have separate locations:

| File | Purpose |
| --- | --- |
| `~/.config/vraptor/config.toml` | Workstation paths, connections, mapping and transport settings; optional credential/analyst file references |
| `~/.config/vraptor/analyst-agents.toml` | AI provider/model profiles and token budgets |
| Selected `.env` / process environment | Provider keys and optional compatibility overrides |
| Existing API-client / endpoint-client YAML | Velociraptor credentials, referenced by path |

Both TOML defaults follow `$XDG_CONFIG_HOME` when configured. Explicit file paths
remain authoritative. `--settings-file` selects operational settings; AI
`--config-file` selects analyst settings. Detailed precedence is in [CONFIG.md](../CONFIG.md).

## 5. Test AI if needed

To check the live server separately, explicitly run this read-only query after
connecting to the required network/VPN:

```sh
vraptor query --server "<SERVER REFERENCE>" --vql 'SELECT 1 AS Ready FROM scope()'
```

Expect a row containing `Ready: 1`. This verifies the selected API connection;
it does not collect endpoint artifacts or create hunts. Configuration and
installation do not run it automatically.

To test OpenAI inference separately:

```sh
vraptor ai test
```

This sends one synthetic request to the selected model and may incur provider
usage. It requests at most 256 output tokens by default, disables retries, uses
one active request and removes its temporary workspace. It sends no case evidence.

The fixed query is `Return exactly READY and nothing else.` and the expected
response is `READY`. The command checks that response internally; it does not
display the query or actual response. This is an illustrative excerpt of the
reported result, not the full configuration/usage output:

```json
{
  "status": "ready",
  "inference": "passed",
  "issues": [],
  "error_classification": ""
}
```

Success requires both a successful execution and exactly `READY` after trimming
surrounding whitespace.
Exit code `0` indicates success; a failed check returns a nonzero code.
`usage` contains reported token counts and `error_classification` identifies a
classified execution failure. A response mismatch reports
`Synthetic inference did not satisfy the output contract`; the actual response
is not included. If a prerequisite fails before inference, `inference` remains
`not_tested`.
The separate `authentication` field can remain `not_checked`: the test verifies
inference rather than performing an account-metadata lookup.

If a reasoning model exhausts the small output budget, inspect the failure and
retry with `vraptor ai test --max-output-tokens 1024`. The allowed range is
1–4096; configured model/runtime limits still apply. For other failures, check
`issues`, the effective route, credentials/login, deployment name and connectivity.
Correct the cause before rerunning.

A pass proves that this profile can complete a small text request and obey a
simple response contract. It does not validate forensic accuracy, structured
outputs, large context budgets or concurrent workloads. Use a sanitised analysis
sample and review its evidence references before adopting the profile for cases.

### Common installation problems

| Symptom | Action |
| --- | --- |
| Python is too old | Select a Python 3.11+ executable with `PYTHON_BIN=/path/to/python3.12 ./utils/install.sh`. An existing old `.venv` needs separate replacement. |
| `venv` / `ensurepip` is unavailable | Install the selected interpreter's venv support, such as `python3-venv` on Debian/Ubuntu, and rerun the installer. |
| `vraptor` is not on `PATH` | Add the checkout's absolute path to `PATH` using the command printed by the installer, or use `./vraptor` from the checkout. |
| AI doctor reports a missing key | Add `OPENAI_API_KEY` to the selected credential file or process environment, then inspect `vraptor ai config` and rerun doctor. |
| API connection fails | Check `vraptor config --server-profile "<SERVER REFERENCE>"`, the API-client YAML path, its server address, VPN/firewall access, and the credential's permissions with your administrator. |
| OpenAI reports model access or quota failure | Check the API account/project and model availability; select an accessible model with `vraptor ai setup`. Offline doctor cannot verify account access or quota. |

## 6. Start the first investigation

Choose one workflow after configuration. Replace example paths, profile names,
investigation IDs and target selectors with your inputs. These commands perform
live readiness checks; they are separate from package installation and local
configuration checks.

| Workflow | Mode | Required resources |
| --- | --- | --- |
| Live endpoints on an existing server | `live-remote` | API-client YAML and a client/hostname/label scope; no local native binary |
| Local evidence mapped to a remote server | `remote-deaddisk` | API-client YAML, matching endpoint-client YAML, native binary and evidence |
| Local evidence with a managed local server | `local-deaddisk` | Native binary and evidence; setup manages local server credentials |

```sh
# Live remote: the selected server reference has its existing API-client YAML.
vraptor setup start --mode live-remote --id live01 --server-profile "<SERVER REFERENCE>" \
  --hostname host01

# Map local evidence to a remote server; use its matching endpoint config.
vraptor setup start --mode remote-deaddisk --id disk01 --server-profile "<SERVER REFERENCE>" \
  --client-config /configs/live_client.config.yaml --evidence-path /evidence/disk.E01

# Map local evidence to a case-owned local server.
vraptor setup start --mode local-deaddisk --id local01 \
  --evidence-path /evidence/disk.E01
```

`setup start` creates/reuses the investigation directory and records verified
readiness in `<case-root>/<id>/engagement.json`. To prepare only the folder
offline, use `vraptor setup init --id CASE_ID`. AI configuration is optional
for all three infrastructure workflows.

The investigation skills also require the
[DetectRaptor bootstrap](../docs/reference/detectraptor-bootstrap.md).
That catalog check/import is a skill workflow requirement, not an automatic
package installer or CLI startup action. Follow the
[setup skill](../skills/velociraptor-engagement-setup/SKILL.md) for credential acquisition,
readiness, resume/stop and evidence formats, or the
[three-workflow acceptance guide](velociraptor-setup-testing.md) for verification.

For later work, use `vraptor setup status --id CASE_ID` and
`vraptor setup resume --id CASE_ID` with the same investigation parent. Resume
uses the saved recipe and verifies readiness. Stop owned mapped processes with
`vraptor setup stop --id CASE_ID`; add `--stop-server` when the owned local
server should also stop. Evidence and existing case data are retained.

## 7. Override AI settings for one analysis

Use the interactive wizards to save defaults. Analysis switches change only the
current run and do not write TOML or dotenv files. Start with your existing flow,
saved request or hunt and add only the overrides needed.

For example, use the selected AI profile's maximum available token budgets for
an existing flow:

```sh
vraptor analyze --id live01 --server-profile "<SERVER REFERENCE>" \
  --client C.EXAMPLE --flow F.EXAMPLE \
  --max-input-tokens max --max-output-tokens max
```

| Override | Effect for this analysis |
| --- | --- |
| `--execution-profile NAME` | Select a saved AI provider/model profile |
| `--model MODEL_ID` | Override the model or Azure deployment within that provider |
| `--reasoning-effort EFFORT` | Select an effort supported by that model, such as `medium` or `xhigh` |
| `--max-input-tokens TOKENS\|max` | Set input budget; `max` fills context remaining after output within the standard-price ceiling |
| `--max-output-tokens TOKENS\|max` | Set output budget; `max` uses the model/deployment maximum |
| `--model-context-tokens TOKENS\|max` | Override a deployment context cap; `max` uses the known model's published context |
| `--model-max-output-tokens TOKENS\|max` | Override a deployment output cap; `max` uses the known model's published output limit |
| `--ai-config-file PATH` | Use an alternative analyst configuration file for this run |

For a different model, select a compatible saved profile. For example, an
Anthropic profile can use `--execution-profile claude_work --model claude-sonnet-5
--reasoning-effort medium`. A model flag does not switch providers by itself.

Omitting the flags preserves normal saved/environment resolution. CLI overrides
win over those sources. Input has the same conditional 100000-token minimum as
setup. Unknown model names need declared numeric ceilings before `max` can
determine capacity. Smaller saved deployment ceilings still apply unless you
explicitly override them. See [analysis model overrides](model-execution.md#analysis-model-overrides)
for the complete rules, and run `vraptor analyze --help` for the option list.

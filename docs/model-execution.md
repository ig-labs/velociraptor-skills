# Model execution and operator setup

Skills and `vraptor` share one configuration resolver, operation-scoped execution
object, provider gate and output validator. A harness is the application launching
work; a provider is its inference backend. Detecting Codex does not imply OpenAI.

## Setup

For package installation, combined operational/AI setup, offline checks and the
optional live AI check, see [Install and set up vraptor](vraptor-installation.md).
Interactive `vraptor setup configure` offers the AI wizard after saving
operational settings. Use `vraptor ai setup` directly to change AI profiles later.

From this repository use `./vraptor ai ...`; installed users use
`vraptor ai ...`. `./dfir ai config` remains the existing compatibility route.

The interactive `./utils/configure-codex.sh` installer offers to run model setup
after configuring Codex. Press Enter to accept, or decline and run setup later.
Use `--skip-agent-setup` to suppress the offer. Non-interactive installation skips
it; the Python dependencies must be installed before running the wizard.

```sh
./vraptor ai setup
./vraptor ai config
./vraptor ai doctor
```

Setup reads the saved TOML before prompting. When no type is supplied, the
selected profile's connection type is the prompt default (or `codex` for a new
configuration). Accepting it edits that profile, even when several profiles share
the type. In a terminal, setup then
offers a profile name, followed by the harness configuration file for Codex/Claude:

```text
Profile name [codex] (Enter to keep): codex_work
Codex config file [/home/analyst/.codex/config.toml] (Enter for default):
```

Enter accepts the suggested profile name; custom text names a new entry or
renames the selected existing entry. For example, `codex_work` is saved as
`[profiles.codex_work]`. A rename also updates `selection.default_profile` when it
references the old name. Names allow 1-100 letters, digits, underscores, hyphens
and dots; `default` is reserved. An occupied destination name is rejected.

Use `--profile-name NAME` to supply that name directly. `--execution-profile NAME`
selects or creates a named profile and skips the name prompt; combine both flags
to rename a particular existing profile during setup. With no terminal, setup
uses the inferred name unless one of these flags supplies a name.

The path prompt first uses the selected profile's saved `source.path`. For example,
after choosing `~/.codex/azure.config.toml`, rerunning setup offers that same file.
Only a new source without a saved path uses discovery: Codex uses
`~/.codex/config.toml`; Claude checks
`~/Library/Application Support/Claude/settings.json`, then `~/.claude/settings.json`.
Press Enter to keep the path or enter a replacement.
Paths support `~`, `$HOME`, and `${HOME}`; relative input resolves from the current
working directory. Setup saves the chosen absolute path in the profile's `source`
table and validates the referenced file before saving. It does not modify that
file. `--harness-config` skips this prompt; without a terminal, omitting the flag
keeps the saved path, falling back to the standard path only for a new source.
Saved relative paths resolve from the shared TOML directory. Saved native profile
names (`source.profile`) are also retained. A missing saved source fails validation;
setup does not silently switch to another config file.
If neither automatic Claude file exists, the wizard requires a model instead;
non-interactive setup accepts `--model MODEL_ID`. That profile saves only
`source = { kind = "claude_code" }` and the model, allowing later discovery.
No placeholder native file is created. A malformed selected file fails clearly.

Prompts and `ai setup --help` group profile selection, connection, model/execution,
token budgets and advanced settings. Direct API setup offers optional endpoint,
authentication mode and credential-variable prompts. Claude setup optionally
checks native login and starts sign-in if required after saving. Enter skips
that step; `ai login --harness claude_code` remains available separately.

Before an interactive model prompt, setup lists the selected provider's model
examples in aligned columns with short descriptions. OpenAI and Codex show GPT-6
and GPT-5.6 examples; Anthropic API and Claude Code show Claude examples. Claude
Code also shows its `sonnet`, `opus`, `haiku` and `fable` aliases. Azure asks for
your actual deployment name. These are offline suggestions, not an account model
inventory or an allowlist. You can enter another supported ID, or press Enter to
retain the displayed model. Supplying `--model` skips the prompt and suggestions.
`ai setup --help` includes both lists. Model defaults and token budgets do not
change when these suggestions are displayed.

The reference lists were checked on 2026-09-23 against the
[OpenAI catalogue](https://developers.openai.com/api/docs/models),
[GPT-5.6 guide](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-5.6),
[Anthropic catalogue](https://platform.claude.com/docs/en/models/overview) and
[Claude Code model configuration](https://code.claude.com/docs/en/model-config).
Access still depends on your account and client version.

The **Reasoning effort** section prints model-specific levels and short
descriptions before its prompt; the same guidance appears in `ai setup --help`.
GPT-6 Astra supports `low`, `medium`, `high`, `xhigh`, `max`; GPT-6 Sol/Luna and
GPT-5.6 also support `none`. Older GPT-5 supports `minimal`, `low`, `medium`, `high`.
OpenAI effort values remain free-form so other supported model-specific levels
can pass through to the selected runtime. Azure deployments must use the levels
supported by their underlying model.

Claude API and Claude Code profiles accept `low`, `medium`, `high`, `xhigh`, `max`.
The selected model must support the value: current Sonnet 5, Opus 5/5.5 and Fable
5/5.1 support all five; older models can support fewer. Haiku does not expose
effort, so leave it unset. Enter preserves saved settings; displaying the helper
does not alter them. Recognized effort-capable Claude models default to `medium`
only when CLI, profile, shared and native settings supply no effort. This applies
to interactive and non-interactive setup, including inherited Claude models.
Haiku, unsupported older versions and unknown IDs receive no automatic effort.
`--reasoning-effort` skips the prompt and helper.
Reference: [OpenAI model specifications](https://developers.openai.com/api/docs/models),
[GPT-5 effort](https://developers.openai.com/api/docs/models/gpt-5), and
[Claude effort support](https://platform.claude.com/docs/en/build-with-claude/effort).

Setup then offers model, reasoning effort, timeout and concurrency. Existing
profile values take precedence over shared `[execution_defaults]` and setup
suggestions; Enter preserves them. For new OpenAI/Azure API profiles the suggestions
are:

```toml
model = "gpt-5.6-luna"  # Must match your Azure deployment name
reasoning_effort = "high"
timeout_seconds = 600
max_concurrency = 20
```

Use `--model`, `--reasoning-effort`, `--timeout-seconds` and `--max-concurrency`
to override a value and skip its prompt. New Anthropic API profiles require a
model. Claude uses the profile/shared analysis budgets unless model limits are
explicitly set.
Harness profiles display `inherit` for an
unset model/effort; Enter retains inheritance from the selected native config.
Codex `model_reasoning_effort` is imported alongside its model, including native
named profiles. Explicit analyst profile/environment values continue to win.

Reruns preserve saved endpoint, credential reference, authentication, transport,
model limits, retries and enabled state. Updating a profile backed by a shared
connection copies those connection settings into that profile without changing
the shared connection or other profiles. Non-interactive reruns keep saved values;
when the type is omitted, an existing default or `--execution-profile` selects it.
Setup suggestions do not change the runtime's code-only defaults.

Examples (supply `--profile-name` or `--execution-profile` to skip the name prompt,
and `--harness-config` to skip the harness-path prompt in a terminal):

```sh
./vraptor ai setup --provider anthropic --model your-claude-model-id
./vraptor ai setup --provider azure_openai --base-url https://example.openai.azure.com \
  --model my-deployment
./vraptor ai setup --from-harness codex
./vraptor ai setup --from-harness codex --execution-profile custom_codex \
  --harness-config ~/.codex/custom.config.toml
./vraptor ai setup --from-harness codex --execution-profile codex \
  --profile-name codex_work --harness-config ~/.codex/custom.config.toml
./vraptor ai setup --from-harness claude_code
```

The Claude command inherits the model from Claude Code. The wizard uses that
resolved model for its offline [token-budget reference](#shared-token-budgets).
Known Claude IDs have model-specific defaults; unknown IDs and moving aliases
fall back to shared budgets (272K input / 64K output unless configured).
New OpenAI/Azure profiles suggest 272K input and 128K output when no saved values
exist. These references do not query account capabilities or enable extended context.
Check [Claude model capacities](https://platform.claude.com/docs/en/build-with-claude/context-windows)
and [Claude Code context availability](https://code.claude.com/docs/en/model-config#extended-context).
Optional `model_context_tokens` and `model_max_output_tokens` overrides remain
available for smaller models. Setup retains existing overrides on reruns.

Setup adds the selected config type to the existing TOML and preserves the other
profiles, shared connections and execution defaults. It also fills missing shared
token defaults, preserving any values already saved. New types get profile names
`openai`, `azure` (for `azure_openai`), `anthropic`, `codex` or `claude_code`.
If exactly one profile already has that provider or harness type, setup updates
it using its existing descriptive name unless renamed during setup. API providers and harness sources are separate types:
an OpenAI API profile can coexist with a Codex profile.

Use `--execution-profile NAME` to add another named configuration of the same
type or update a particular one. If several profiles match an explicitly supplied
type, this flag is required; setup does not guess which to overwrite. An existing name belonging to
a different type is rejected. Same-type updates are automatic; `--replace` is no
longer a setup option.

The first profile becomes the default. Interactive setup asks at the end whether
to make a different configured profile the default: Yes changes the selection,
while Enter or No preserves it. Non-interactive setup preserves the current
default unless `--set-default` is supplied; that flag also skips the interactive
default-selection prompt. Setup reports the selected
`execution_profile`, `profile_action` (`added` or `updated`), and `default_profile`.
The selection value is the exact profile name: for example,
`default_profile = "azure"` in `[selection]` selects `[profiles.azure]`. The TOML table
name is lowercase `selection`.

Setup reserves the generic name `default`; use a type name or a descriptive
`--execution-profile NAME`. When saving an existing `[profiles.default]`, setup
renames it to its provider/harness name and updates `selection.default_profile`
if it pointed there. If that name is occupied, a numeric suffix such as `codex_2`
keeps both profiles. Other named profiles retain their names and settings.
The `renamed_profiles` output reports the old and new names. Any explicit CLI or
environment profile selection should use the new name. Renaming is saved only
after setup validation succeeds; the single backup retains the original file.

Setup stores non-secret configuration with owner-only permissions and validates
the candidate before atomic replacement. Updates reuse one sibling backup named `<config-file>.bak`
(`analyst-agents.toml.bak` by default), replacing it with the existing config before
writing the new config. The first setup creates no backup. Both files use
owner-only permissions. Login is a separate operator action: `ai login --harness codex` or
`ai login --harness claude_code` invokes the native login command. No auth store
is read, copied, hashed or migrated by the Python runtime.

Setup and loading use the same file destination, in this order:

1. `--config-file`, on commands that support it.
2. `AI_SKILLS_ANALYST_AGENT_CONFIG_FILE` from the process environment, the
   operational settings' selected `[credentials].env_file`, repository `.env`,
   then shared `~/.codex/.env` (first non-empty value).
3. Operational `[analyst].config_file`, if configured.
4. `$XDG_CONFIG_HOME/vraptor/analyst-agents.toml`, falling back to
   `~/.config/vraptor/analyst-agents.toml`.

Only default-path resolution migrates the legacy `ai_skills/analyst-agents.toml`
under the same configuration root, preserving bytes and permissions. An existing
destination (including a symlink) prevents migration; explicit paths are unchanged.

Setup creates missing parent directories and reports the absolute destination in
its `config_file` output. No personal TOML is written into the repository by
default; `config/analyst-agents.example.toml` is the committed template. Explicit
file paths support `~` and `$HOME`; relative config-file paths resolve from the
current working directory.

Select a profile with `AI_SKILLS_ANALYST_AGENT_PROFILE`. Diagnostic/setup commands
also support `--execution-profile`. These execution profiles are independent of
`vraptor analyze --profile`, which selects analysis behaviour.

### Shared token budgets

The **Analysis token budgets** section of `vraptor ai setup` prompts for two
values per profile. It first prints the resolved model, published context,
standard-price input ceiling, maximum output and reference defaults. Offline
references checked **2026-09-23** cover the exact IDs in the setup model helper:

| Model IDs | Standard-price input ceiling | Output maximum | Output default | Input default |
| --- | ---: | ---: | ---: | ---: |
| GPT-6 Astra/Sol/Luna; GPT-5.6 Sol/Terra/Luna | 272000 | 128000 | 128000 | 272000 |
| Claude Sonnet 5, Opus 5.5, Fable 5.1 | 1000000 context | 128000 | 128000 | 872000 |
| Claude Haiku `claude-haiku-4-5-20251001` | 200000 context | 64000 | 64000 | 120000 |

[OpenAI model specifications](https://developers.openai.com/api/docs/models/gpt-6-sol)
describe the surcharge above 272K input.
[Claude capacities](https://platform.claude.com/docs/en/models/overview) and
[pricing](https://platform.claude.com/docs/en/about-claude/pricing#long-context-pricing)
include standard pricing across the current models' context. Input capacity is
`min(model context - selected output, standard-price input ceiling)`; Sonnet's
default is `1000000 - 128000 = 872000`. More tokens still cost more at the same
per-token rate. Haiku defaults to 64000 output and 120000 input, leaving 16000
context tokens unallocated. Explicit input `max` permits
`200000 - 64000 = 136000`. The JSON reference reports `default_input_tokens`
separately from `max_input_tokens`. Setup defaults to automatic budgets for known models, including
reruns; use `--no-auto-token-budgets` to retain saved values within the allowed
range. These are API references, not managed-plan allowances or
Azure deployment pricing guarantees. Setup does not change service tiers.

The known model's reference supplies automatic defaults; the selected model's
context is recorded as `model_context_tokens` for
new and existing profiles so the generic 400K application fallback cannot silently
restrict them. Setup also records `model_max_output_tokens`; output `max` can never
expand to nearly the whole context for these models. Smaller explicitly configured
context/output caps remain in force and are displayed.

Claude aliases `haiku`, `sonnet`, `opus`, and `fable` use dated offline references
for the default Anthropic-hosted models (checked **2026-09-24**): Haiku 4.5,
Sonnet 5, Opus 5.5, and Fable 5.1 respectively. Haiku uses 200000 context / 64000
maximum and default output, with 120000 default input. The other three
use 1000000 context / 128000 maximum and default output / 872000 default input.
The alias is retained for execution. The wizard and JSON `alias_reference_model`
identify the reference rather than claiming live alias resolution. A remapped alias
or another hosting provider can have different limits: select the exact supported
model ID or configure smaller deployment caps. `claude-haiku-4-5` is also recognized.
Setup removes stale Haiku effort settings and runtime resolution omits effort for
Haiku 4.5, including inherited settings from a previous model.

Unknown models and custom Azure deployment names retain application/shared
fallbacks and are explicitly marked unverified. Explicit model ceilings still
apply. The JSON setup report includes `model_token_reference` with sources/date.

For example, a new OpenAI profile suggests:

```toml
[profiles.openai]
provider = "openai"
model = "gpt-5.6-luna"
max_input_tokens = 272000
max_output_tokens = 128000
```

For non-interactive setup, use `--max-input-tokens` and `--max-output-tokens`.
Enter accepts the calculated default displayed in brackets. With
`--no-auto-token-budgets`, saved profile values take precedence over shared values,
then model recommendations. Setup accounts for smaller saved model limits before
suggesting a pair. Setup caps an oversized saved budget at the smaller model or
configured ceiling, including the standard-price input allowance and space for
output. It displays the reduction and offers the capped
value as the prompt default. The JSON report exposes `token_budget_maxima` and
`token_budget_adjustments`. Unknown models enforce configured/application context
and output limits without claiming a verified model maximum.

When a lower retained value differs, it prints, for example:

```text
Maximum input tokens: keeping 100000; model reference default is 272000.
Maximum input tokens [100000] (Enter to keep):
```

Output is selected first; the wizard then displays the exact remaining input
capacity before asking for input. Enter `max` or `auto` at either budget prompt
to use its maximum (explicitly choosing this for Haiku output uses 64000).
Oversized interactive values are adjusted to the displayed maximum and setup
continues; non-numeric/too-small entries can be corrected without restarting.
For example, entering `1000000` for Sonnet input with 128000 output selects
872000 input, while selecting 32000 output allows 968000 input.

The default `--auto-token-budgets` replaces the selected profile's saved budgets with
maximum model output and remaining standard-price input, except Haiku's explicit
120000 input default. Smaller deployment caps still apply. Explicit token flags
override this mode and fail before writing if invalid. For Claude, OpenAI and Azure,
input must be at least **100000** and output at least **32000**. Output selection
reserves the input minimum; a model/deployment that cannot accommodate both
minimums is rejected. For example:

```text
Maximum input tokens: allowed 100,000–872,000; enter max (or auto) to use 872,000.
Maximum input tokens [872000] (Enter to keep):
```

Other profiles and the shared defaults table are unchanged.
These checks do not add live model discovery. Native Codex/Claude model
inheritance is resolved locally without pinning the inherited model or running
authentication checks or inference.

The resolver derives operational context as input plus output: **400000** for
this pair. It reserves instruction, prior-context and safety space inside input
(each capped at 10% of input), then caps evidence at the shared
`max_analysis_item_tokens` ceiling. The default pair therefore keeps the
**200000** evidence ceiling. Token encoding and correction attempts remain
independent settings; they cannot be inferred from a token budget.

### Analysis model overrides

Host, hunt, Autoruns and snapshot analysis accept the same optional settings:

| Option | This invocation only |
| --- | --- |
| `--ai-config-file PATH` | Select an analyst configuration file. |
| `--execution-profile NAME` | Select a saved AI profile, separate from artifact/task profiles. |
| `--model ID` | Override model ID / deployment name. |
| `--reasoning-effort EFFORT` | Override the model's reasoning effort. |
| `--max-input-tokens TOKENS\|max` | Set input or fill remaining context within the standard-price ceiling. |
| `--max-output-tokens TOKENS\|max` | Set output or use the model/deployment maximum. |
| `--model-context-tokens TOKENS\|max` | Set deployment context, or replace a saved smaller cap with published context. |
| `--model-max-output-tokens TOKENS\|max` | Set deployment output cap, or use the published cap. |

For example, append `--model claude-sonnet-5 --max-input-tokens max
--max-output-tokens max` to an existing analysis command using an Anthropic
profile: input resolves to 872000 and output to 128000. Specifying 32000 output
instead permits 968000 input. Haiku `--max-output-tokens max` explicitly chooses
64000, which is also its setup default. Haiku's setup input default is 120000;
explicit input `max` permits 136000 with 64000 output.

Explicit smaller deployment ceilings remain binding unless overridden. Unknown
model IDs need declared numeric ceilings before `max` can claim capacity. Input
uses the same 100000 minimum as setup, and output has a 32000 minimum. Numeric overrides outside the
allowed range fail before opening an API connection. Planning and execution share
the resolved limits, including downstream Autoruns review. CLI overrides take
precedence over environment, profile and shared defaults, and never write TOML
or dotenv files. Without overrides, existing runtime resolution is unchanged.

### Shared fallback table

Setup also preserves and fills this legacy/shared fallback table:

```toml
# Check these token budgets against your deployed model's context/output limits.
[analysis_defaults]
context_window_tokens = 360000
max_input_tokens = 272000
token_encoding = "o200k_base"
max_analysis_item_tokens = 200000
max_output_tokens = 64000
```

Profiles without an input/output pair continue using this table unchanged.
These are application budgets, not declarations of a model's capabilities.
Optional `model_context_tokens` and `model_max_output_tokens`
profile overrides tighten the budgets to fit a deployed model.
Planning and runner admission share the same model-limit
calculation: valid caller budgets are retained, including budgets above code
defaults, while smaller caller/model limits still apply.
Runner creation without caller-supplied limits uses the profile and shared TOML budgets
already captured in the execution configuration, then code defaults. It does
not reread configuration files or environment values; callers with resolved
environment overrides pass their effective limits explicitly.
Setup adds the reminder as a TOML comment and in its result.
Check the defaults for your selected model before running analysis.

Each field maps to the corresponding `AI_SKILLS_` environment variable (uppercase,
for example `max_input_tokens` maps to `AI_SKILLS_MAX_INPUT_TOKENS`). Non-empty
process environment values override the selected credential dotenv, repository
`.env`, shared `.env`, selected profile input/output fields, this shared table,
then code defaults. Profile pairs derive context/evidence after environment input/output overrides;
explicit environment context/evidence overrides remain authoritative and must fit.
Token-only planning reads the selected profile's TOML without importing
the harness config. `ai config` reports effective values and their provenance;
`ai config --view defaults` always shows machine-independent code defaults.

`max_analysis_item_tokens` controls both evidence chunk sizing and the per-agent
evidence budget. The unused `AI_SKILLS_CHUNK_SIZE_TOKENS` setting has no TOML alias;
use this single setting. Row and byte limits remain environment-configurable.

See [the complete example](../config/analyst-agents.example.toml). Version 2 uses
one `[profiles.<name>]` table per runnable configuration. Most profiles contain
their provider, endpoint, credential reference, model and limits directly:

```toml
schema_version = 2

[selection]
default_profile = "azure"

[profiles.azure]
provider = "azure_openai"
transport = "api"
base_url = "https://your-resource.openai.azure.com/openai/v1/"
api_key_env = "AZURE_OPENAI_API_KEY"
model = "your-deployment-name"

[profiles.from_codex]
source = { kind = "codex", path = "~/.codex/config.toml" }
transport = "auto"
```

A profile selects exactly one of an inline `provider`, an inline `source` table,
or an optional named `connection`. Model and execution-limit overrides belong in
the profile. A source accepts `kind`, optional `path`, and an optional Codex
`profile`. Paths resolve relative to the TOML file; `~` and `$HOME` expand.
Connection settings cannot be mixed with a source or connection reference.
Unknown keys, invalid types, missing references and credential-bearing endpoint
URLs fail validation. Secrets stay in the selected credential dotenv, root `.env`
or process environment. Standard
credentials and explicit `api_key_env` references are hydrated only after routing.

When several models actually share a connection, add an optional `[connections]`
table to the same version-2 document:

```toml
[connections.team_azure]
provider = "azure_openai"
base_url = "https://your-resource.openai.azure.com/openai/v1/"
api_key_env = "AZURE_OPENAI_API_KEY"

[profiles.fast]
connection = "team_azure"
model = "your-fast-deployment"

[profiles.thorough]
connection = "team_azure"
model = "your-thorough-deployment"
```

Optional `[execution_defaults]` provides shared execution limits/transport;
profile fields override those defaults. Setup writes self-contained version-2
profiles and does not modify named connections when replacing a profile.

Only `schema_version = 2` is supported. Unsupported versions and removed table
names fail validation before any file is changed; setup does not migrate them.

## Resolution and automatic discovery

Explicit CLI values (where supported), process environment, selected credential
dotenv, root `.env`, and shared `~/.codex/.env` apply in that order. Next come the selected
execution profile, its imported settings/defaults, compatible Codex routing, and
code defaults. Empty environment values do not override a lower source. Changing
the provider of a selected profile requires selecting a compatible profile.

Velociraptor commands, including `ai config`, `ai setup`, `ai doctor`
and analyst execution, inherit the selected `[credentials].env_file` from the
operational TOML. Use `--settings-file` to select that TOML; `--config-file` remains
the analyst-profile TOML option. The operational snapshot retains immutable
environment layers and source provenance without modifying `os.environ` or
rereading credential files during the operation. Secret values are excluded from
configuration inspection. `ai config --view defaults` remains independent of
workstation configuration.

For Azure Entra client-secret authentication, keep `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` in the selected credential dotenv or
process environment. The resolved values are passed directly to
`ClientSecretCredential`; no process environment mutation is needed. When a
client secret is supplied, tenant and client IDs are required. Without a client
secret, `DefaultAzureCredential` retains its SDK-native ambient/managed-login
behavior; configure those native identity mechanisms through their normal
environment or login tooling.
Resolved client-secret values are also redacted from provider errors and
persisted analysis manifests.

A selected/default profile wins over harness discovery. Without one, `auto` uses
`AI_SKILLS_ANALYST_AGENT_HARNESS=codex|claude_code|none`, then Codex's
`CODEX_THREAD_ID` or Claude's `CLAUDECODE=1` launch hint. Conflicting hints fail.
Signals are routing hints, not authentication or a security boundary. An explicit
provider or `CONFIG_SOURCE=application` disables automatic harness discovery.
`CONFIG_SOURCE=codex|claude_code` explicitly requests the corresponding source.
Outside a harness, the historical single Codex-config fallback remains; multiple
installed harness configurations require a profile.

Codex routing imports support the selected top-level/embedded profile and named
`<profile>.config.toml` files. Claude imports a selected settings JSON file and
allowlisted model/endpoint/effort environment values. An explicit
`AI_SKILLS_ANALYST_AGENT_CLAUDE_CONFIG` or saved `source.path` takes precedence;
otherwise discovery checks `~/Library/Application Support/Claude/settings.json`
before `~/.claude/settings.json`. No source file is required if the model is
explicitly configured. Desktop `config.json` login tokens are never imported.
Claude aliases are
passed to the SDK, but direct API profiles should pin exact model IDs. Importers
do not load all project/managed layers, execute credential helpers, or observe a
model changed only in an active GUI session. Pin an execution profile when exact
reproducibility is needed. No files are rewritten by automatic discovery.

If a remote tool service launches work for several callers, pass its explicit
configuration through `resolve_agent_execution(cli_values=...,
process_environment=...)` per request. Do not infer every caller from the service's
startup environment or mutate global environment between requests.

## Providers and authentication

| Provider / transport | Authentication | Dependency |
| --- | --- | --- |
| OpenAI / `api` | `OPENAI_API_KEY` or explicit reference | `vraptor[ai]` |
| Azure OpenAI / `api` | API key or Entra | `vraptor[azure]` |
| OpenAI / `codex_app_server` | Native Codex managed login | Installed Codex |
| Anthropic / `api` | `ANTHROPIC_API_KEY` or explicit reference | `vraptor[anthropic]` |
| Anthropic / `claude_agent_sdk` | Native Claude-managed login | `vraptor[claude]` |

The repository requirements install the Python API/Claude extras; standalone
installations can install only the extras they need. Azure uses deployment names.
Anthropic uses Messages with native structured outputs and opt-in adaptive thinking;
the selected model must support requested features. No provider fallback occurs.

`TRANSPORT=auto` selects a compatible transport from launch context. An unset
transport inherits a detected harness where supported; explicitly configured
`api` retains API execution. Codex's existing API endpoint/key route selects `api`.
Claude managed login ignores inherited `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
and `CLAUDE_CODE_OAUTH_TOKEN`: the SDK adapter clears them in its child environment
without changing the parent environment. Direct API profiles still use their
configured credentials. The SDK owns login storage and renewal. It starts an
ephemeral session with tools and filesystem setting sources disabled, strict empty
MCP configuration, hooks disabled, and one turn; observed tool actions fail the run.
It requires SDK >=0.2.140 and does not share a Codex-style daemon. Endpoint-managed
vendor policy still applies. Qualify this transport on the intended managed endpoint
before internal production use; vendor authentication eligibility must also be checked.

## Limits and diagnostics

Claude, OpenAI and Azure use the profile/shared analysis budgets when model limits
are omitted. Use `model_context_tokens` or
`AI_SKILLS_ANALYST_AGENT_MODEL_CONTEXT_TOKENS` to declare a deployment limit. A selected
model context tightens input/output/evidence budgets and scales reserves; set
`model_max_output_tokens` / `AI_SKILLS_ANALYST_AGENT_MODEL_MAX_OUTPUT_TOKENS` too
to declare a smaller deployment output ceiling. Profiles without the new budget
fields retain the legacy 4096-output fallback when an explicit model context
has no output limit; profiles with input/output budgets use those budgets.
If a smaller model context reduces a profile's combined budget, the output
allowance scales proportionally before applying any explicit output ceiling.
Setup and runtime use the full declared model context; there is no fixed 25%
Anthropic context reduction. Instruction, prior-context and safety reserves remain
inside the input budget when deriving evidence capacity. Local tiktoken counts remain
estimates and are not the provider's tokenizer. Validate limits with representative
inputs. Host, hunt and standalone
analysis use the bounded envelope; runtime admission checks remain the final guard.

The shared `MAX_CONCURRENCY` remains a scope ceiling, not an organisation-wide
quota. `READ_TIMEOUT_SECONDS` controls stream idle/read time,
bounded by total `TIMEOUT_SECONDS`. Retries, safe error classification and output
publication remain shared. Failed/incomplete/truncated outputs are not successful.

`ai config` is offline. `ai doctor` checks configuration and installed
dependencies and distinguishes credentials configured from authentication verified.
`ai doctor --live` and `ai models` request account/model metadata, not inference.
For Claude these commands use `claude auth status --json` with a ten-second
timeout, returning only authentication status, never account details or raw
output. Missing/unsupported CLI status reports `not_checked` with an issue;
logged-out status reports `login_required`. No Claude model list is available.
Offline `ai doctor` leaves authentication `not_checked`. Azure model lists do
not establish deployment availability.
`ai test` sends one synthetic READY prompt, with no retries, one active request
and at most 256 requested output tokens by default (SDK ceilings remain local).
Its JSON reports pass/fail, usage and error classification; it does not print the
prompt or model response. A pass requires successful execution and `READY` after
trimming surrounding whitespace. This verifies small-request connectivity and
instruction following, not forensic analysis quality.
Model listings are bounded to one page/200 records and report completeness.
Diagnostics never print keys, tokens or raw provider errors.

## Validation, qualification and rollout

```sh
.venv/bin/python -m pytest -q tests/test_ai_harness_setup.py tests/test_agent_profile_schema.py tests/test_agent_setup.py tests/test_agent_setup_defaults.py tests/test_additional_agent_providers.py \
  tests/test_agent_analysis_defaults.py \
  tests/test_agent_config.py tests/test_agent_providers.py tests/test_agent_runtime.py \
  tests/test_analysis_limits.py tests/test_agent_settings_environment.py
.venv/bin/python -m pytest -q tests/test_public_layout.py tests/core
```

Tests use real SDK clients with mock HTTP responses and mocked Claude execution;
they do not validate real account access or forensic model quality. Before approving
a production profile, run the synthetic check, then a sanitised evaluation covering
extraction, source references, synthesis, noise, truncation and cancellation. Record
model/runtime versions, exact context, latency, token usage, contract failures and
analyst-reviewed findings. Block promotion on lost evidence or unsupported findings.
Use pinned API profiles and deployment-side quotas for shared unattended workloads.
Use managed login for validated per-analyst workflows. Never pool personal credentials.

Pilot new profiles separately; existing environment settings remain active. Roll
back by selecting the prior profile/config backup. Execution identity schema 3 adds
model limits/read timeout, so changed routes invalidate old analysis cache identity;
previous evidence and reports are retained. There is no automatic model migration,
cross-provider fallback, central gateway or automatic approval of model quality.

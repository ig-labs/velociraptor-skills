# Provider analyst execution

DFIR analyst workers use a direct provider API, the installed Codex app-server,
or isolated Claude Agent SDK sessions. Host, hunt, Autoruns, evidence, synthesis, and status orchestration
depend on the provider-neutral `AgentRunner` contract in
`vraptor.agent.runtime`; they do not launch `codex exec` or use provider
conversation state as resumable forensic state.

## Runtime contract

`AgentRequest` contains the bounded prompt, output name, metadata, optional
JSON schema, and required capabilities. `AgentResult` contains final output,
provider/model/protocol, request ID, normalized usage, attempts, terminal
status, and a sanitized error class. `AgentEvent` normalizes request start,
acceptance, progress, usage, retry, completion, failure, timeout, and
cancellation. Progress callbacks are rate-limited and never contain token text
or reasoning traces.

The runtime validates capability requirements and input size before evidence is
submitted. It resolves one effective output ceiling from the per-request and
runtime limits; a per-request value may tighten but never widen the runtime
limit. Providers that advertise request-side output limits receive that ceiling,
while unsupported transports omit it. Every completed output is still
size-checked locally and, when applicable, validated client-side with JSON Schema
before atomic publication. Output paths must remain
under the caller-owned analysis directory. Failed, timed-out, or cancelled
attempts never publish partial output as completed work.

The standalone `run_analyst_agent.py` command publishes a three-file bundle:
the requested report, `<report>.events.jsonl`, and `<report>.manifest.json`. It
refuses to run when any canonical bundle file already exists unless the operator
passes `--replace`. Replacement runs and validates the new analysis while the
current bundle remains untouched. After success, the current files move to
`previous-analysis/<UTC timestamp>-<random id>/` and the staged bundle becomes
canonical. If promotion fails, the runtime restores the archived files. Failed,
timed-out, or cancelled replacement attempts leave the current bundle unchanged.
History directories persist until an operator deliberately removes them; there
is no automatic retention cleanup.

Inside a policy-governed Velociraptor analysis directory, canonical and archived
event logs are classified as `bounded_agent_runtime_events`. The policy permits
only the normalized runtime event fields and bounded scalar provider metadata;
it rejects prompts, model output, raw provider payloads, raw stderr, evidence
fields, nested metadata, malformed archive paths, more than 4,096 events, or
logs larger than 1 MiB. Archive paths are limited to one generated run directory
under `previous-analysis/`.

Provider routing and credential hydration are separate phases. Host, hunt, and
standalone orchestration first resolve a non-secret execution route containing
the effective provider, model, protocol, endpoint, API version, reasoning mode,
and allowlisted query/header shape. A versioned hash of that route participates
in analysis cache identity, so changing an automatically detected model or
endpoint invalidates prior checkpoints. Credential values and credential-source
paths are excluded from the identity, and credentials are hydrated only when a
provider runner is actually created. Cache-only state inspection therefore does
not require provider credentials.

Velociraptor analysis intentionally does not request structured output. Its
artifact, synthesis, Autoruns, generic-stack, and finding-manager lanes use strict
tab-delimited line-v2 contracts so Python retains accounting and validation
authority without repeated JSON keys. Structured output remains available to
non-Velociraptor callers.

Direct OpenAI and Azure Responses adapters submit prompts as standard
input-message lists and forward the effective ceiling as `max_output_tokens`.
The Codex app-server adapter does not advertise that capability, so its
`turn/start` request omits the ceiling. The shared ceiling remains a deterministic
client-side acceptance and validation limit for every transport.
Responses events with terminal `failed` or `incomplete` status fail closed:
partial output is never returned as successful work. Safe provider error codes
and request IDs are retained for retry classification and debug diagnostics.
The requested ceiling, whether it was sent, provider finish reason, reported
usage, and locally measured output tokens are retained as bounded scalar
telemetry; provider error messages and payloads are not persisted.

## Providers

| Provider | SDK and protocol | Structured output | Cancellation and state |
| --- | --- | --- | --- |
| OpenAI | official `openai` SDK, `AsyncOpenAI`, Responses API | Responses JSON Schema plus client validation | sends `max_output_tokens`; local stream cancellation; `store=false`; no response chaining |
| Azure OpenAI | official `openai` SDK, `AsyncOpenAI`, Azure `/openai/v1/responses` | Responses JSON Schema plus client validation | sends `max_output_tokens`; API key or async Entra token provider; local stream cancellation; stateless |
| Codex-managed OpenAI | installed `codex app-server`, JSON-RPC over its version-matched stdio proxy | app-server turn output schema plus client validation | output ceiling remains local; remote turn interruption; one ephemeral thread per request; Codex-managed login |
| Anthropic | official `anthropic` SDK, Messages API | native JSON Schema plus client validation; model support required | sends `max_tokens`; local stream cancellation; no message chaining; incomplete responses fail |
| Claude-managed Anthropic | official `claude-agent-sdk`, native login | SDK output format plus client validation | output ceiling remains local; one ephemeral session; tools, MCP, hooks and setting sources disabled |

Only the providers listed above are implemented. Any other provider selection
fails before evidence is submitted.

Direct API adapters supply no filesystem, shell, MCP, browser, web-search,
code-execution, or other model tools. The app-server adapter requests an empty
dynamic-tool and environment set, an empty capability-root set, read-only
sandboxing, no network, no approvals, and an ephemeral thread in an empty
temporary directory. It also supplies text-only developer instructions and
interrupts the turn if it observes any command, file, MCP, dynamic-tool, web,
image, interaction, or subagent item. A configured Codex daemon still owns its
built-in capability implementation, so operators should not attach
mutation-capable MCP services to a daemon used for untrusted evidence analysis.
Codex can still report an account-level `AGENTS.md` instruction source even
with project-document loading disabled. The adapter's text-only developer
instruction and observed-item interrupt remain the enforcement layers; keep
account-level instructions compatible with this policy.

## Configuration and authentication

Resolution precedence is:

1. explicit CLI input where the command supports it;
2. non-empty process `AI_SKILLS_ANALYST_AGENT_*` values;
3. non-empty root `.env` values;
4. non-empty shared `~/.codex/.env` values;
5. selected execution profile, including shared defaults;
6. compatible imported harness routing;
7. application defaults.

See [model execution and setup](../model-execution.md) for the shared
TOML schema, automatic harness hints, credential boundaries, provider-specific
limits, `vraptor ai setup|doctor|models|test|login`, and qualification steps.

The collector records source presence rather than comparing values with
defaults, so an explicit value equal to an application default remains
explicit. It then resolves and hydrates one immutable execution route. Every
worker in that operation receives the same object; downstream code does not
read analyst environment variables again.

Velociraptor analysis and `run_analyst_agent.py` do not expose provider, model,
reasoning, transport, timeout, retry, or concurrency CLI overrides. Execution
manifests record the actual resolved provider/model route. Behavioral analysis
routing is separate and never selects a provider model.

The root `.env` loader never overwrites an existing process variable. Empty
variables do not mask lower-precedence values. To use automatic harness
selection, leave provider and model empty:

```dotenv
AI_SKILLS_ANALYST_AGENT_ENABLED=true
AI_SKILLS_ANALYST_AGENT_TRANSPORT=auto
AI_SKILLS_ANALYST_AGENT_PROVIDER=
AI_SKILLS_ANALYST_AGENT_MODEL=
AI_SKILLS_ANALYST_AGENT_REASONING_EFFORT=
```

Omitted settings use the code-owned application defaults summarized in
`CONFIG.md`. Set timeout, retry, or concurrency variables only as deliberate
operator overrides, then inspect the effective values with
`./dfir ai config`.

Provider variables:

- Direct OpenAI API: `AI_SKILLS_ANALYST_AGENT_TRANSPORT=api`,
  `OPENAI_API_KEY`, and optional `OPENAI_BASE_URL`.
- Codex-managed OpenAI: `AI_SKILLS_ANALYST_AGENT_TRANSPORT=codex_app_server`.
  The installed Codex login must already work; `OPENAI_API_KEY` is not read.
- Azure OpenAI: `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_AUTH_MODE=api_key|entra`,
  optional `AZURE_OPENAI_API_KEY` for key mode, and optional
  `AZURE_OPENAI_API_VERSION`. Entra mode requires the `azure` project extra.
- Anthropic API: `AI_SKILLS_ANALYST_AGENT_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`,
  an exact model ID and optional model context/output limits.
- Claude-managed Anthropic: `AI_SKILLS_ANALYST_AGENT_TRANSPORT=claude_agent_sdk`,
  native Claude login, a selected model, and no inherited API/token credentials.
- Any API connection can specify `AI_SKILLS_ANALYST_AGENT_API_KEY_ENV` or TOML
  `api_key_env` to bind exactly one credential variable without copying its value.

`AI_SKILLS_ANALYST_AGENT_MAX_CONCURRENCY` is the only concurrency setting. Each
host or hunt scope owns one dynamic `asyncio` scheduler, one shared runner/client,
and artifact-named lanes. Every transport installs the same value as the
provider/endpoint gate on the current event loop, and DetectRaptor EVTX derives
its active partition ceiling from it.

### Codex app-server lifecycle and concurrency

The transport follows the
[official Codex App Server protocol](https://learn.chatgpt.com/docs/app-server).
The Python runtime does not read, parse, print, copy, or persist `auth.json`.
It first asks the installed `codex` executable to start or reuse its
account-scoped app-server daemon, then connects through `codex app-server
proxy`. Some package-manager builds do not include the installer-managed
standalone daemon package; when daemon startup returns nonzero, the harness
falls back to one direct `codex app-server` process. Runners on one Python event
loop share that single connection and multiplex JSON-RPC requests over it.
Closing the last runner closes the proxy or direct app-server process. A shared
daemon, when available, remains available to Codex itself and other harness
processes.

Each analyst request creates one ephemeral Codex thread and one turn. Therefore,
`AI_SKILLS_ANALYST_AGENT_MAX_CONCURRENCY=5` means up to five active turns, not five
Codex processes or persistent desktop tasks. Separate Python commands can each
own one connection/process, so this is not an operating-system-wide gate. This differs from direct API mode:
direct mode shares one `AsyncOpenAI` client per host/hunt scope and uses the
same endpoint gate. Both modes
retain the existing bounded scheduler, production credits, token backpressure,
retry accounting, and deterministic output validation.

Five active turns may still consume the Codex/ChatGPT plan quota quickly. The daemon
can also return JSON-RPC `-32001` when overloaded; this is normalized as a
retryable provider-overload failure and remains bounded by the configured retry
count and total deadline. Reduce the one shared value if the account, machine,
or network cannot sustain five.

Example local configuration with the shared five-request ceiling:

```dotenv
AI_SKILLS_ANALYST_AGENT_ENABLED=true
AI_SKILLS_ANALYST_AGENT_TRANSPORT=codex_app_server
AI_SKILLS_ANALYST_AGENT_PROVIDER=openai
AI_SKILLS_ANALYST_AGENT_MODEL=gpt-5.6-luna
AI_SKILLS_ANALYST_AGENT_MAX_CONCURRENCY=5
```

Confirm that Codex is installed and signed in before analysis:

```bash
codex --version
codex login status
./dfir ai config
```

The config report should show
`execution.effective.protocol=codex_app_server`,
`execution.effective.auth_mode=codex_managed`, a credential record with
`present=true`, and `execution.effective.max_concurrency=5`. That
boolean means authentication remains delegated to Codex; it does not prove
quota availability until a turn is attempted.

The scheduler uses async workers and a global production-credit limit of
`max_concurrency + 1`. Each artifact lane has a one-item queue, while the shared
work queue also has one prefetched item. A producer must acquire credit before
constructing and enqueuing the next scheduled request, so adding artifact lanes
does not multiply the scope-wide backlog. Deterministic validation and its one
bounded correction retry execute inside the same worker item. The collector
releases transient prompts and evidence maps as results complete and reports
value-free `submitted`, `queued`, `active`, `completed`, `failed`, `abandoned`,
`source_exhausted`, and `stop_requested` status.

Velociraptor iterators remain synchronous and are consumed by one dedicated
producer thread per source only because the API iterator is not async. Model API
requests never occupy those producer threads. A stopped producer drains already
accepted work and records explicit accounting instead of silently dropping it.

Direct-provider secrets come only from environment variables. Harness
configuration supplies non-secret routing, never credentials. In app-server
mode Codex owns its managed login and Python receives no secret value. Secret
values are excluded from configuration representations, route identity,
manifests, progress, diagnostics, and normalized exceptions. `./dfir ai
config` exposes only source kind, variable or CLI name, source location,
explicitness, credential variable names, configured booleans, and secret-header
variable names/configured booleans.

## Harness routing and narrow Codex compatibility

The default `AI_SKILLS_ANALYST_AGENT_CONFIG_SOURCE=auto` registers a safe Codex
resolver and uses it when it provides a complete provider/model route. No
import toggle is required. Set the source to `application` to disable harness
discovery or to `codex` to require it. Pass `--codex-config` or request a Codex
profile to select a specific route. Config path precedence is:

1. explicit path;
2. `AI_SKILLS_ANALYST_AGENT_CODEX_CONFIG`;
3. `$CODEX_HOME/config.toml`;
4. `~/.codex/config.toml`.

Profile precedence is explicit profile,
`AI_SKILLS_ANALYST_AGENT_CODEX_PROFILE`, top-level selected profile, then
top-level model/provider. Only model, `model_reasoning_effort`, model provider,
provider name, base URL, `env_key`, wire API, required query parameters, and
environment-backed headers are imported. In direct API mode the secret is
read from the standard provider variable or the variable named by `env_key`. MCP
servers, plugins, hooks, instructions, sandbox settings, shell mutation,
literal headers, and unrelated configuration are ignored.
Application configuration works without Codex installed.

`AI_SKILLS_ANALYST_AGENT_CONFIG_SOURCE=application` short-circuits Codex
discovery before any Codex configuration file is opened. Source `codex` fails
before execution when no complete route exists. Malformed selected TOML,
invalid provider/transport/auth values, missing Azure endpoints, and missing
direct API credentials also fail before any provider request. The removed
`AI_SKILLS_CODEX_CONFIG` and `AI_SKILLS_CODEX_PROFILE` names are ignored rather
than treated as aliases; migrate them to the canonical analyst namespace.

Environment overrides are provider-aware. Changing `AI_SKILLS_ANALYST_AGENT_PROVIDER`
discards an incompatible harness endpoint, query parameters, environment-backed
headers, and `env_key`. For a compatible provider, the standard provider
credential variable takes precedence over the variable named by Codex
`env_key`. If neither variable is populated, direct API execution fails before
any provider request is made. App-server mode ignores both variables and
delegates authentication to Codex.

For example, this Codex Azure route needs only `AZURE_DFIR` to be populated:

```toml
model = "gpt-5.6-luna"
model_provider = "azure"

[model_providers.azure]
name = "Azure OpenAI"
base_url = "https://example.openai.azure.com/openai/v1"
env_key = "AZURE_DFIR"
wire_api = "responses"
```

`AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AI_SKILLS_ANALYST_AGENT_PROVIDER`, and
`AI_SKILLS_ANALYST_AGENT_MODEL` override the corresponding detected values when non-empty.

Inspect the resolved contract without making an API request:

```bash
./dfir ai config --view defaults
./dfir ai config
./dfir ai config --config-source codex --codex-profile azure
```

The versioned JSON contains `execution`, `analysis_limits`,
`analysis_routing`, and `credentials`. Sources identify CLI, environment,
dotenv, Codex-route, provider-default, or application-default provenance.
Credential records contain variable names and presence only; they never contain
credential or header values.

The `defaults` view is derived only from code constants. It does not inspect
process variables, dotenv files, Codex configuration, machine paths, or
credential presence, and cannot be combined with effective-route overrides.

The output includes field sources, the credential variable name, and only a
boolean credential-presence result. It never includes credential values.

The resolver registry is harness-neutral. Codex is the first implemented safe
resolver; additional harnesses can be added without changing provider adapters
or analysis orchestration.

## Timeouts, cancellation, retries, and monitoring

The SDK clients receive explicit connect, read, total, and idle-stream bounds;
provider SDK retries are disabled so the application owns attempt accounting.
The runtime also enforces one monotonic operation deadline across provider-gate
waiting, every API attempt, response validation, and retry backoff. Expiry
cancels the active local operation and is terminal; a new retry cannot start
after the deadline. Explicit cancellation uses the same interruptible wait path,
so it does not depend on another stream event arriving.
Only connection failures, selected timeouts, HTTP 429 or provider code
`rate_limit_exceeded`, retryable HTTP 5xx, and provider overload are retried.
Azure `retry-after-ms` takes precedence over `retry-after`, and an explicit
provider delay is honored within the operation deadline without the ordinary
30-second exponential-backoff cap. A rate limit without either header uses a
code-owned 60-second delay with jitter. The endpoint gate enters the same
cooldown before releasing the failed slot, preventing queued sibling requests
from immediately recreating the burst. Other retryable failures use bounded
exponential backoff with jitter.
Authentication, invalid configuration, unsupported capability, invalid paths,
most HTTP 4xx responses, validation failures, and explicit cancellation are not
transport-retried.
Locally oversized output and provider termination with
`incomplete_details.reason=max_output_tokens` are normalized as deterministic,
non-retryable output-limit failures. They also bypass the outer format-correction
retry. A provider that rejects an advertised output-limit parameter is not
silently retried without the ceiling.

Cancellation stops local direct-API stream consumption and closes the stream.
App-server cancellation sends `turn/interrupt` and then stops local event
consumption. Every transport retry remains a distinct attempt in normalized
events and results. The outer semantic correction runs only after a provider
request succeeds but deterministic output validation fails.
Chunk and synthesis correction each default to two extra attempts (three total)
and resolve independently from transport retries. See
[analysis correction and recovery](analysis-recovery.md) for settings and normal
failure diagnostics.

Provider events and scheduler status are projected into existing analysis
progress callbacks. Direct API workers are `asyncio` tasks using the shared
`AsyncOpenAI` client. App-server workers are also Python `asyncio` tasks, but
their model work is a Codex thread/turn; it is not a spawned Python agent or a
separate `codex exec` process.

## Debug diagnostics

`hunt analyze --debug` and `collect analyze --debug` activate one shared
schema-3 diagnostic session across nested bounded worker pools. It records the
resolved provider/model/protocol, safe endpoint without query parameters,
configuration field sources, credential variable/presence, request-option
presence, requested and sent output ceiling, local output measurement, provider
finish reason, timing, usage, retries, provider request IDs, HTTP status,
normalized provider error code/parameter, validation failures, and final
synthesis status.
Artifact-specific bounded retries may also record value-free failure categories
for each outer review attempt so an earlier local validation failure is not
hidden by a later provider failure.

The diagnostic is capped at 512 attempt records and 1 MiB and is atomically
refreshed while work runs. Unknown identifiers are hashed. Prompts, model output,
raw evidence, raw provider payloads, headers, credential values, stderr, token
deltas, and `.api-runtime` files are never persisted. A later non-debug analysis
preserves the last explicit diagnostic and marks its state reference as not
current.

## Durable state

Every successful artifact produces one durable compact artifact summary with
its provenance. Host synthesis consumes completed summaries rather than all raw
artifact evidence. Reset invalidates only the selected artifact summary and
dependent synthesis. Failed, timed-out, and cancelled work remains resumable.

Hunt workers continue to consume bounded chunks and return findings plus exact
evidence references. Hunt synthesis consumes accepted chunk results. Velociraptor
remains the source of truth; API status is operational metadata only.

Prompts, raw evidence, provider response payloads, token deltas, detailed task
records, and `.api-runtime` files are transient. Normal durable state contains
compact results and bounded failure accounting. Only an explicit `--debug` run
retains the bounded provider/model/protocol, request ID, timestamps, phase,
attempt, normalized usage, terminal status, and sanitized error metadata
described above. Reasoning traces and chain-of-thought are never persisted.

Standalone report bundles and their `previous-analysis/` history are caller-owned
durable files, not `.api-runtime` state. A successful replacement manifest records
the archive directory in `previous_analysis_directory`. Policy-governed
Velociraptor directories audit the event-log portions of both canonical and
archived bundles as bounded operational metadata.

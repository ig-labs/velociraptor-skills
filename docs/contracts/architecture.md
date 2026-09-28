# Package boundary and installation

The shared implementation lives under `src/vraptor`, grouped into `collect`,
`analyze`, `hunt`, `autoruns`, `artifacts`, `agent`, `common` and `logging`. API transport, connection context and case-path resolution have
small root modules. Runtime assets live together under `resources`.
`common.sequences.unique_ordered` owns exact-value deduplication for collection,
hunt and inventory callers, retaining first-seen order and their existing import
names. Artifact-profile normalization remains separate because it strips values
and discards empty entries.
`common.labels.parse_label_values` owns set-valued server-label parsing for
readiness and hunt scope matching, retaining both existing module import names.
Client-query label parsing remains separate because it returns a sorted list and
discards empty scalar values.
`dfir` and `vraptor` share `vraptor.cli:main`. Both repository launchers use
`utils/runtime-env.sh` only to select the interpreter and repository import paths.
`dfir velociraptor` strips the old namespace and uses the same `vraptor.cli:main`
settings resolution as `./vraptor`. Operational commands still dispatch internally
to `vraptor.legacy_cli` where needed. The removed case-management package is not required.

`workspace.initialize` creates/reuses one investigation folder and missing
`AGENTS.md` without connecting to a server. It returns bounded existing-analysis
paths. Operational paths and connection readiness remain separate; no global
current investigation is stored. Each process selects its ID and case root.

`context.resolve_case_paths` resolves paths independently of API access.
`resolve_connection` validates the API/profile/org/readiness identity. There
are no case-state providers, task registers, business result sinks or automatic
case publication. Hydration uses explicit hosts or saved-request scope.

Runtime VQL, policy schemas, analysis profiles, bootstrap helpers and reviewed
GoldenDB bytes are package data. Original evidence/config/data locations are
independent of package installation. Existing user GoldenDB paths and explicit
overrides take precedence over the bundled fallback. No database is rebuilt or
uploaded by package installation or folder export.

```sh
python -m venv .venv
.venv/bin/python -m pip install .                 # core operations
.venv/bin/python -m pip install '.[ai]'           # optional OpenAI execution
.venv/bin/python -m pip install '.[azure]'        # optional Azure authentication
.venv/bin/python -m pip install '.[anthropic]'   # optional Anthropic Messages
.venv/bin/python -m pip install '.[claude]'      # optional Claude managed login
.venv/bin/python -m pip install '.[test]'
.venv/bin/python -m pytest tests/core
```

Run these inside `packages/vraptor` upstream, or the exported public root. Wheels
are installed normally; direct import from a wheel ZIP is not supported.
Core discovery/query and configuration inspection do not require AI SDKs or
model credentials. Tokenizer configuration validates registered encoding names
without fetching encoding data. Actual tokenization retains tiktoken's existing
cache/download behavior.

The agent factory uses caller-supplied runtime limits or the shared TOML budgets
captured in the resolved execution, then applies optional model limits. It does
not reload environment or config files. Callers that resolve environment budget
overrides pass those effective limits explicitly.

Operational settings are resolved once by `settings` and passed to child
processes. The launchers do not pre-load dotenv into the process environment.
`setup` coordinates three workflows over the existing readiness schema;
`lifecycle` manages owned local processes and preserves native configs and
mapped-client writeback. Saved setup intent lives in `engagement.json`.
`status` inspects local processes; `resume` also rechecks API readiness.

Site preferences are materialized into ordinary TOML. An optional private Slack
discovery helper lives outside this package and passes an explicit address and
provisioning options to the shared setup command. The public runtime has no
Slack dependency. Existing environment overrides remain supported.

The initial scope intentionally retains existing command groups and state
schemas. The report's aspirational `doctor`, top-level `status`/`resume`, and
universal manifest import are not new commands in this extraction; use existing
setup verification, `collect status`, repeated request analysis and supported
hunt snapshot validation.

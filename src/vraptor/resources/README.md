# Velociraptor resources

These packaged files are runtime policy or query templates. Edit source files,
not generated inventory, CSV, or resolved-policy exports.

| Resource | Ownership and use |
| --- | --- |
| `collection-groups.json` | Versioned capability-aware IR groups, live/mapped-disk bundles, core/recommended/optional requirements, alternatives, applicability, cost, and triggered follow-up routing. Its canonical hash is persisted with collection state; it does not alter flow run identity. |
| `preferred-artifacts.json` | Canonical artifact selection, field projection, time roles, stack definitions, normalizers, and analysis-route hints. Loaded with ordered site overlays into the operation policy snapshot. |
| `detection-scenarios.json` | Canonical cross-artifact scenario definitions. Loaded and validated with artifact profiles into the same snapshot. |
| `collection-analysis-profiles.json` | Host collection-type objectives and artifact-strategy grouping. It does not select models or duplicate artifact field policy. |
| `artifact-schema-compatibility.json` | Compatibility assertions for expected artifact/component schemas. |
| `model-catalog.toml` | Offline model hints for `ai setup` and analysis budgets: published context, standard-price input and output limits, Claude Code aliases, effort ladders and setup examples. Not an allowlist; loaded by `agent/model_budgets.py`. |
| `windows-lolbins.json` | Windows LOLBin reference data used during deterministic enrichment. |
| `windows-rmm-greyware.json` | Windows remote-management and greyware reference data used during deterministic enrichment. |
| `autoruns/` | Read-only GoldenDB schema and VQL templates. |
| `contracts/` | JSON contracts loaded by the runtime (DetectRaptor analysis, Linux host profile, persistence policy, detached-evidence manifest) and the host-analysis and hunting mode and ownership matrices cited by the docs and hunting skill. |
| `golden/` | Canonical reviewed Autoruns CSV, generated runtime database and maintenance instructions, also included in standalone installations. |
| `profiles/` | `profiles.toml`: analysis intents and `rapid`, `standard` and `deep` response depths, loaded by `agent/profiles.py`. |
| `scripts/` | Shell helpers: `prep_dfir_tools.sh` for `tools prep`, `load_repo_env.sh`, and the `velociraptor/` setup, mapped-client and remote-configuration scripts. |
| `templates/` | `investigation-agents.md`, rendered into a new case's `AGENTS.md` by `setup init`. |
| `vql/` | Packaged bounded VQL templates used by collection and export workflows. |

## Managing artifact policy

Built-in artifact profiles load first. Repeated `--artifact-reference` and
`--scenario-reference` values are applied in command-line order; environment
lists are used only when the corresponding explicit option is absent. One
operation reads and validates every selected source once and passes the
immutable result through all phases. A source edit during a run is visible only
to the next operation.

```bash
./vraptor artifacts policy validate
./vraptor artifacts policy show
./vraptor artifacts policy explain --artifact Windows.NTFS.MFT
./vraptor artifacts policy explain --scenario suspicious-binary-execution
./vraptor artifacts policy export --output /tmp/artifact-policy.json
./vraptor artifacts policy diff --against /tmp/artifact-policy.json --check
```

`validate` returns compact hashes and counts. `show` includes ordered local
source provenance. `export` omits local paths and is safe for review or CI
comparison; it is not an editing source. `diff` rejects portable documents with
invalid schemas, counts, provenance ordering, or declared hashes before
comparison. `diff --check` exits `3` when valid resolved profile or scenario
content differs.

Policy and cache identity use ordered source content hashes, not source paths.
Moving unchanged overlays does not invalidate policy-derived cache state;
changing bytes or overlay order does. There is deliberately no process-global
policy cache.

Collection-analysis cache identity separately hashes the collection profile and
optional GoldenDB bytes without recording their local paths. Moving unchanged
resources is stable; missing or changed resource content invalidates reuse.

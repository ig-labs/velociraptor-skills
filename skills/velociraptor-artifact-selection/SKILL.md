---
name: velociraptor-artifact-selection
description: Inventory and select Velociraptor artifacts and detection scenarios, resolve built-in and site-owned references, and provide field-projection, hunt, stack, normalization, sampling, filtering, and analysis-routing policy. Use when choosing an artifact or scenario, reviewing or optimizing artifact fields, validating site policy, or exporting `artifact_definitions()`. Not for running or reviewing hunts; use velociraptor-hunting.
---

# Velociraptor Artifact Selection

**Server prerequisite:** complete the [DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md) for each new local or connected live/remote server before server work; a failed import blocks the workflow.

Use the shared `vraptor` CLI; `vraptor analyze` only reuses existing evidence.
See the [shared CLI contract](../../docs/contracts/cli.md).

Use this skill before adding a new Velociraptor collection or hunt when the
artifact choice is not already obvious. If the main uncertainty is not the
artifact but the workflow owner, read `../velociraptor-host-analysis/SKILL.md`
first so you choose between the one-host and cross-host workflows before
shortlisting artifacts.

Inventory, profile, scenario and policy commands do not mutate the server.
Read the shared
[Velociraptor operation authorization policy](../../docs/reference/velociraptor-operation-authorization.md)
before any collection, hunt, import or other server mutation. Live inventory
uses the shared
[server-profile and engagement context](../../docs/reference/velociraptor-engagement-context.md);
it is instance-only and therefore needs a server profile but no engagement
readiness manifest.

This skill inventories the live `artifact_definitions()` catalog into a
regenerable CSV/JSON cache, filters it by name, description, type or parameter
names, identifies bounded parameters such as `DateAfter` and `DateBefore`, and
surfaces analyst caveats, row-volume risk and interpretation bias before a hunt
or collection target is chosen. It produces recommendation-oriented shortlists
for hunt, collection or analysis planning without a separate hunt-only selector.
It resolves one canonical artifact profile with named stack views (optional site
or case overlays), owns artifact field review and optimization so workflow skills
keep no field-policy copies, and resolves common cross-artifact detection
scenarios with required fields, expected signals, benign explanations, caveats
and follow-up artifacts.

## Workflow

1. Export the current artifact catalog from the intended Velociraptor org and
   save the raw inventory as both CSV and JSON.
2. If you already know the question shape, filter the catalog by name,
   description, type or parameter regex.
3. Check whether the candidate artifact exposes the parameters you need before
   assuming a bounded hunt or collection is possible. Do not assume an artifact
   supports `DateAfter` / `DateBefore` just because a similar artifact does.
4. Resolve the preferred artifact profile before choosing review fields,
   export projections, stack fields, normalizers, sampling fields, or analysis
   routes.
5. When a profile is absent or its fields do not match current output, use
   [field-selection rules](references/field-selection-rules.md) to generate a
   deterministic, review-required proposal from actual result schemas and
   values. Do not silently update canonical policy. Live hunt stacking may
   instead derive a one-run validated profile from 10-20 transient rows; keep it
   ephemeral and never promote it automatically.
6. Resolve applicable common scenarios before asking the AI to invent a new
   analytical path. Use the scenario as a bounded baseline and let the AI
   adapt filters, time windows, prioritization, and novel correlations.
7. If the main uncertainty is workflow ownership, filter the recommendation
   shortlist by `--workflow`, `--question-shape`, or `--windows-skill` before
   choosing between `velociraptor-hunting` and `velociraptor-host-analysis`.
8. For a one-host Linux workflow, pass the saved JSON inventory to
   `vraptor artifacts linux-plan`. It validates the requested mode,
   focus, artifact names, and required parameters without starting collection.
9. Reuse one case-level disposable cache at
   `<case_root>/<id>/.cache/velociraptor/artifacts`. Refresh or replace it
   instead of creating per-question directories or durable subdirectories for
   individual artifact checks; use a temporary directory only for an
   intentionally short-lived filtered query. The cache is not evidence and must
   never become authoritative workflow state.
10. Use this skill and documented `vraptor artifacts --help`; do not
    inspect Python implementation to infer inventory, profile, or CLI behavior.

## Server-capability recovery

For `--bundle` or `--collection-group`, use `vraptor collect plan` first. The
versioned policy resolves ordered alternatives from server inventory, records
target-inapplicable sources, and continues recommended/optional gaps. A missing
core source blocks a custom lane; a standard bundle marks that lane
`core_missing` and continues other resolvable lanes. Do not replace these
requests with a silently narrowed artifact list.

Use this legacy recovery sequence when a strict `--collection-type` or explicit
artifact request fails server artifact preflight:

1. Treat the failed request's `artifact_preflight` as authoritative for that
   check. Confirm `checked_at`, `api_client_path`, `api_client_sha256`, and
   `org_id`. `available_artifacts` is the requested/server intersection, not the
   complete catalog. Do not poll the request when required flow IDs are absent.
2. Export an inventory only when the preflight is absent, a live artifact
   request fails, or it predates an API config, artifact import, or org change.
   Elapsed time alone does not invalidate the preflight:

   ```bash
   vraptor artifacts inventory \
     --api-client /path/to/api_client.yaml \
     --server-profile lab7 \
     --output-dir <case_root>/IR1234/.cache/velociraptor/artifacts \
     --force-run
   ```

3. Read `artifact_definitions_inventory.json` as the canonical machine-readable
   catalog. Use the generated recommendation JSON/CSV for shortlisting; do not
   parse generated CSV back into control logic.
4. Compare live names with the exact memberships in
   `../velociraptor-collection/references/collection-types.md`.
5. For a broad baseline question, emit repeated explicit `--artifact` values for
   the complete supported intersection. Recommend a named type only when its
   complete membership preserves the intended scope.
6. Keep high-cost or opt-in artifacts such as
   `DetectRaptor.Generic.Detection.YaraWebshell` explicit.
7. Return the selected workflow owner, failed request ID, supported artifacts,
   unavailable artifacts, proposed command, and coverage limitation. The command
   must include `--supersedes-request-id FAILED_ID`, repeated
   `--unavailable-artifact` values for the exact missing set, and repeated
   `--artifact` values for the exact available set.
8. Runtime validation rejects stale or incomplete partitions and requests that
   already own flows. The final report retains supersession provenance and
   cannot claim complete baseline coverage. Do not create readiness manifests,
   queue flows, add `--force-run` to the collection command, or inspect
   implementation code.

## Artifact References and Stack Views

Artifact-reference precedence is:

`explicit --artifact-reference > VELO_ARTIFACT_REFERENCE_PATHS > built-in reference`

The built-in reference always supplies the base profile. Explicit or environment
paths are ordered overlays. A path may name one JSON file or a directory of JSON
files. Site-specific content should remain outside this repository.

Each profile stores stack preferences under `review.stacks`, keyed by a stable
stack id. Treat each named view as one analytical question: single-field
prevalence views and intentional composite views can coexist for the same
artifact, but do not combine unrelated rarity signals merely because they come
from the same artifact. Set `review.default_stack` to the lowest-noise first
view. A site overlay can update one named view without replacing the others
because `stacks` is an object map. Use per-view `collection_parameters` when a
view depends on optional artifact output, such as `Calculate_hashes=Y` for
service executable hash stacking.

## Field Optimization Ownership

`../../src/vraptor/resources/preferred-artifacts.json` is the
canonical schema-4 field policy (sample fields, stacks, aliases, normalizers,
filters, `review.vql_select`/`review.live_vql_select` projections, saved-hunt
projection, `time_filter` and analysis routes) that hunting and host analysis
both resolve. Read the
[profile schema rules](references/artifact-field-optimization.md#profile-schema-rules)
before editing a profile or site overlay, and the rest of
[artifact field optimization](references/artifact-field-optimization.md) when
reviewing the artifact list, deciding which fields to retain, normalize, stack,
or project, or finding unprofiled artifacts and remaining generic `SELECT *`
exports. Read [field-selection rules](references/field-selection-rules.md)
before implementing automated field selection. Apply existing profiles first,
and use automation only to propose missing fields, aliases, normalizers, and
independent stack views for analyst approval.

This skill owns desired review fields, aliases, normalization, stacking and
accepted snapshot field policy. `velociraptor-hunting` and the
`velociraptor-collection` runtime own execution of the actual VQL projection and
provenance; `velociraptor-hunting` and `velociraptor-host-analysis` own workflow
routing and evidence interpretation, not field-policy copies.

Velociraptor remains authoritative for the complete server-side hunt result.
An extraction-time projected snapshot is not a field-for-field raw export and
must record its projection. Use a full export when local preservation of every
source field is required.

## Detection Scenario Ownership

Use
`../../src/vraptor/resources/detection-scenarios.json`
as the canonical common-scenario catalog. Scenarios are separate from artifact
profiles because one scenario normally combines several artifacts.

Each scenario defines:

- analytical objective and selection guidance
- tactics, tags, and supported question shapes
- primary, supporting, and context artifacts
- required and optional fields
- named profile stacks and recommended filters
- expected suspicious signals and benign explanations
- interpretation caveats
- follow-up artifacts and scope-expansion triggers

Do not include `Windows.Registry.Hunter[all]` in a detection scenario. It is a
high-cost explicit collection target, not routine supporting or context
evidence. Prefer a dedicated artifact when one answers the question. When a
registry-specific question genuinely requires Registry Hunter, request one
category-scoped preset such as `Windows.Registry.Hunter[execution]`,
`Windows.Registry.Hunter[persistence]`, or
`Windows.Registry.Hunter[user-accounts]`.

Use `VELO_DETECTION_SCENARIO_PATHS` or repeated `--scenario-reference` values
for ordered site or case overlays. Explicit command-line references replace the
environment value. Built-in artifact profiles and configured artifact-profile
overlays validate every declared scenario stack id.

Treat scenarios as curated starting hypotheses, not automatic verdicts. The AI
may adapt or combine them, but must preserve their field requirements and
caveats unless case evidence justifies a documented override.

## Registry Hunter IOC and Time-Bound Selection

Treat `Windows.Registry.Hunter` as eligible for two additional explicit use
cases when the live artifact definition exposes the required parameters:

- use `IocRegex` for registry IOC or string search
- use `ModifiedAfter` and `ModifiedBefore` for a registry-key `Mtime` window

Prefer one category-scoped preset and combine the filters when possible. Treat
`Windows.Registry.Hunter[all]` as opt-in only: use it as the standalone
`registry` collection when the relevant category cannot be determined and the
wider cost is justified, never in a common scenario, baseline, or fallback
merely for additional context.

For bounded timeline work, treat Registry Hunter as an optional adjacent
registry lane, not a replacement for MFT or event-log timelines. Registry key
`Mtime` does not prove execution time, persistence creation time, or the write
time of one specific value. Preserve the exact regex and bounds in collection
provenance.

Capability-gate these recommendations against the current
`artifact_definitions()` inventory. Older servers may not yet expose
`IocRegex`, `ModifiedAfter`, or `ModifiedBefore`.

## Commands

Export the full catalog to a directory. The helper reuses an existing matching
export by default; add `--force-run` to recollect after artifact imports, org
changes, or server updates:

```bash
vraptor artifacts inventory \
  --api-client /path/to/api_client.yaml \
  --output-dir <case_root>/IR9001/.cache/velociraptor/artifacts

vraptor artifacts inventory \
  --api-client /path/to/api_client.yaml \
  --output-dir <case_root>/IR9001/.cache/velociraptor/artifacts \
  --force-run
```

Export only likely EVTX-friendly artifacts, or hunt-oriented candidates with
bounded-parameter interest:

```bash
vraptor artifacts inventory \
  --api-client /path/to/api_client.yaml \
  --output-dir <case_root>/IR9001/.cache/velociraptor/artifacts \
  --name-regex 'Evtx|EventLogs|DetectRaptor\\.Windows\\.Detection\\.Evtx' \
  --parameter-regex 'DateAfter|DateBefore|IocRegex|ChannelRegex|ProviderRegex|IdRegex'

vraptor artifacts inventory \
  --api-client /path/to/api_client.yaml \
  --output-dir <case_root>/IR9001/.cache/velociraptor/artifacts \
  --description-regex 'hunt|logon|event|service|file|registry' \
  --parameter-regex 'DateAfter|DateBefore|ModifiedAfter|ModifiedBefore|IocRegex|Glob|Regex'
```

Build a Windows hunt shortlist for a cross-host question, or a bounded timeline
shortlist for post-analysis collection planning:

```bash
vraptor artifacts inventory \
  --api-client /path/to/api_client.yaml \
  --output-dir <case_root>/IR9001/.cache/velociraptor/artifacts \
  --workflow hunt \
  --question-shape cross-host \
  --windows-skill velociraptor-hunting

vraptor artifacts inventory \
  --api-client /path/to/api_client.yaml \
  --output-dir <case_root>/IR9001/.cache/velociraptor/artifacts \
  --workflow collection \
  --question-shape bounded-time-window \
  --windows-skill velociraptor-host-analysis
```

Resolve a Linux standard-mode plan from the saved authoritative inventory:

```bash
vraptor artifacts linux-plan \
  --inventory <case_root>/IR9001/.cache/velociraptor/artifacts/artifact_definitions_inventory.json \
  --mode standard \
  --distro debian \
  --include-optional packages \
  --investigation-id IR9001 \
  --client-id C.1234abcd
```

The command emits independent `collect check` and `collect ensure` commands
for available validated artifacts. It fails closed when a required capability
or parameter is unavailable and never emits `--force-run` or export actions.

Validate the built-in reference plus configured site overlays, show one
effective profile, and export the resolved machine-readable reference and
generated CSV index:

```bash
vraptor artifacts profiles \
  validate \
  --artifact-reference /path/to/site/artifact-profiles.json

vraptor artifacts profiles \
  show \
  --artifact DetectRaptor.Windows.Detection.Evtx

vraptor artifacts profiles \
  export \
  --output-dir /path/to/reference-review
```

Validate, list, show, find by artifact, and export the common detection
scenarios, or validate a site scenario overlay:

```bash
vraptor artifacts scenarios validate
vraptor artifacts scenarios list
vraptor artifacts scenarios show \
  --scenario suspicious-service-creation
vraptor artifacts scenarios for-artifact \
  --artifact Windows.System.Services
vraptor artifacts scenarios export \
  --output-dir /path/to/reference-review

vraptor artifacts scenarios validate \
  --scenario-reference /path/to/site/detection-scenarios.json \
  --artifact-reference /path/to/site/artifact-profiles.json
```

Manage profiles and scenarios as one effective policy:

```bash
vraptor artifacts policy validate \
  --artifact-reference /path/to/site/artifact-profiles.json \
  --scenario-reference /path/to/site/detection-scenarios.json

vraptor artifacts policy show

vraptor artifacts policy explain \
  --artifact Windows.NTFS.MFT

vraptor artifacts policy explain \
  --scenario suspicious-binary-execution

vraptor artifacts policy export \
  --output /path/to/reference-review/artifact-policy-resolved.json

vraptor artifacts policy diff \
  --against /path/to/reference-review/artifact-policy-resolved.json \
  --check
```

Each operation loads and validates its policy once, then carries one immutable
snapshot through inventory, filtering, time-scope, stacking, review planning,
and reporting. Treat the reported SHA-256 as the operation policy identity.
Changes to source files during a run apply only to the next operation. The
portable export excludes local absolute paths; source JSON remains the editable
authority, while resolved JSON and CSV files are generated review material.
`diff` validates the portable schema, counts, provenance ordering, and declared
hashes before comparison. `diff --check` exits `3` when valid resolved profile
or scenario content differs.
Policy-derived cache identity uses ordered source content hashes, so moving
unchanged overlays is stable while changing bytes or overlay order invalidates
the identity.

## Outputs

The helper writes a disposable, regenerable cache. Velociraptor remains the source
of truth; deleting this directory must not trigger collection or invalidate evidence.
The cache contains:

- `artifact_definitions_inventory.csv`
- `artifact_definitions_inventory.json`
- `artifact_definitions_inventory_enriched.csv`
- `artifact_definitions_inventory_recommendations.csv`
- `artifact_definitions_inventory_recommendations.json`
- `artifact_definitions_inventory_summary.json`
- `artifact_profiles_resolved.json`
- `artifact_profiles_resolved.csv`
- `detection_scenarios_resolved.json`
- `detection_scenarios_resolved.csv`

It prints the main output paths on stdout, including the recommendation files
and the summary manifest, so callers do not need to hard-code filenames.

The enriched CSV joins the live artifact inventory to the resolved artifact
profiles. JSON is canonical; CSV is a generated analyst-facing index. Use the
resolved JSON profile for execution and do not parse the generated CSV back into
the control plane.

The recommendation files materialize recommendation-oriented rows with:

- recommended workflow owner (`hunt`, `collection`, or `analysis`)
- recommended Windows skill (`velociraptor-hunting` or
  `velociraptor-host-analysis`)
- derived legacy collection-type hints, capability-aware IR group hints, and
  hunt-profile hints where the repo already defines them
- required parameter names when the live artifact metadata marks them
- optional narrowing parameters such as `DateAfter`, `DateBefore`, `Glob`,
  `IocRegex`, and related bounded-scope controls
- review strategy metadata from the resolved artifact profile:
  `review_strategy`, `default_stack`, `stack_view_ids`,
  `stack_view_dimensions`, `preferred_stack_fields`, `server_stack_fields`,
  `stack_metrics`, `preferred_sample_fields`, `avoid_stack_fields`, normalizers,
  analysis routes, and `recommended_filters`
- concrete `review-results` command templates:
  `review_sample_command`, `review_stack_command`, and
  `review_inventory_command`, using `$INVESTIGATION_ID`, `$HUNT_ID`, and
  optional `$REVIEW_WHERE` placeholders for operator-supplied scope
- fallback artifacts from the resolved artifact profile

When one or more recommendation filters are present, those files become a
ranked shortlist capped by `--top`. Without recommendation filters, they stay
as a recommendation-oriented full view of the filtered artifact inventory.

## References

Use these only when needed:

- `../../src/vraptor/resources/preferred-artifacts.json`
  Canonical built-in selection, review, stack, normalization, and analysis-route
  profiles for supported artifacts.
- [references/artifact-field-optimization.md](references/artifact-field-optimization.md)
  Profile schema rules plus the human review checklist for artifact fields,
  fixed schemas, unprofiled artifacts, and projection priorities.
- [references/field-selection-rules.md](references/field-selection-rules.md)
  Deterministic rules and output contract for automated field-selection
  proposals.
- `../../src/vraptor/resources/detection-scenarios.json`
  Canonical common detection-scenario catalog.
- [references/site-artifact-profiles.example.json](references/site-artifact-profiles.example.json)
  Minimal site-overlay example. Copy it outside the repo before adding
  customer-specific artifacts or administrative-tool policy.
- [references/site-detection-scenarios.example.json](references/site-detection-scenarios.example.json)
  Minimal site scenario-overlay example.
- `../velociraptor-host-analysis/references/windows-artifact-analysis.md`
  Deeper interpretation guidance for execution, timeline, and registry-backed
  Windows artifacts.

## Notes

- Treat the live `artifact_definitions()` export as org-specific reality.
  Community imports, custom artifacts, and inherited artifacts can change what
  is available.
- Cache reuse is scoped to the resolved API client, org id, active filters, and
  immutable policy identity. Reference bytes or overlay ordering invalidate
  reuse; moving unchanged references does not.
- `--org-id` resolves to `root` by default. Legacy `orgs/<id>` values are
  normalized to `<id>` first and retained as a compatibility fallback for
  servers that still expect the older form.
- Recommendation filtering is intentionally vocabulary-first. Reuse the repo's
  existing Windows owner names and question-shape terms instead of inventing a
  parallel selector taxonomy.
- Prefer the enriched CSV when planning hunts because it keeps the artifact
  metadata and the analyst caveats in one place.
- For `Windows.System.Services`, keep service name, normalized executable path,
  ServiceDll, account, executable/DLL hashes, failure command, start mode, and
  name-plus-path drift as separate named views. Computing one composite across
  all of those fields would over-fragment the baseline.
- Prefer the recommendation CSV or JSON when the question is "which lane owns
  this next" rather than "what does the full artifact catalog look like."
- For row-heavy artifacts, use the resolved profile to check whether the artifact is a
  poor fit for an unbounded fleet-wide hunt.
- Do not assume every large artifact should be stacked. For example,
  `Windows.EventLogs.EvtxHunter` is marked as `detection_or_keyword`; use
  `IocRegex`, `WhitelistRegex`, `EvtxGlob`, and time bounds before sampling,
  rather than generic `EventID` or `Channel` stacking.

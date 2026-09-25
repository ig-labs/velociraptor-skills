# Windows Live Hunt Analysis

Use this reference with `live-analysis.md` for Windows artifacts.

## Normalization

- Prefer artifact-profile normalizers over ad hoc model transformations.
- Case-fold Windows paths, entry names, and signer identities for grouping.
- Preserve original projected values for findings and drill-down.
- The AI may propose a missing normalizer with `normalization_candidates`.
- A proposed normalizer does not affect coverage until it is validated, added
  to the artifact profile, and the changed profile resets affected watermarks.

## Stack Chunking

1. Query deterministic server-side scope and signature aggregates without a
   total-result limit.
2. Consume aggregate response batches lazily and form token-bounded transient
   analyst parts under the 200,000-token per-part ceiling.
3. Pause acquisition whenever all bounded analyst slots are active.
4. Account expected groups compactly and retain only notable or suspicious
   groups for original-row drill-down.
5. If more than 100 groups are flagged, keep coverage incomplete; decide the
   retained groups and rerun so their deterministic keys are excluded.

Every stack key retains its original category and exact represented-row count.
Aggregate group totals must equal the authoritative scope count or the run
fails closed.

Prefer category-scoped compound filters for recurring benign Windows families.
Combine an anchored normalized path regex with the expected verified signer.
Validate the complete match set before approval, then apply the filter before
future stack generation. Do not spend model output on repeated benign
group-by-group narratives.

## Windows Risk Checks

Do not close a normalized stack solely because its name resembles a Windows
component.

Review:

- signer status and signer identity;
- expected Windows or vendor path;
- path location, including user-writable and temporary directories;
- missing-file or stale-reference status;
- launch string and load context;
- DLL search-order, side-loading, and .NET assembly-loading risk;
- exact variant count and whether version/hash variation is expected;
- prevalence across the scoped fleet.

High prevalence is supporting context, not proof of benignity. Low-prevalence
or unsigned groups should remain open or be drilled down.

## Normalized Stack Closure

A normalized group can close directly when:

- the stack fields are sufficient to identify an expected family;
- `hijack_risk_reviewed: true`;
- multiple or unresolved exact variants also have
  `variant_risk_reviewed: true`;
- the decision has a concrete disposition and reason.

If any material field is hidden by normalization, request a drill-down. The
next pass requeries original rows using the exact scope and normalized stack
predicate.

## Suspicious Drill-Down

Drill-down should return the artifact's full approved projection, including:

- original name or entry;
- original image path;
- signer;
- launch string;
- hash;
- host name or FQDN;
- Velociraptor client ID.

Complete a drill-down only when exhaustive. A truncated drill-down requires a
tighter scope, another deterministic chunk, or explicit evidence extraction.

## DetectRaptor and PowerShell

For `DetectRaptor.Windows.Detection.Evtx`:

- discover all in-scope detection names before row review;
- plan detections rare-first and transport complete evidence for direct review;
- combine the exact detection predicate and optional time predicate in one
  server-side `WHERE` clause; and
- retain exact payload, payload field, count, and first/last timestamps in the
  grouped review without hash equivalence.

Small detections stream directly. Large detections run an exhaustive exact
payload census. Stream every exact group only when consolidation removes at
least 100 model rows and 5 percent; otherwise fall back to exhaustive direct
review. Do not sample, generate filters, or exclude rows. Send every grouped
payload once through the normal live-hunt CSV chunk workflow, with `Payload` as
the final column and standard CSV quoting. Use sparse `reference-line-v3`
findings; clean groups require no per-group response. Batch-query machines and
individual event timestamps only for source references returned in findings,
without a second semantic pass.

Direct live rows should transport:

- host and client identity;
- event time, channel, event ID, user, and detection;
- evidence path;
- complete `Evidence`.

Grouped review transports one complete payload per exact group, not every
occurrence. Targeted context hydration omits the payload because the group has
already been classified.

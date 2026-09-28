# Velociraptor engagement context

Velociraptor workflows separate the remote server identity from the local case
namespace.

- `--server-profile` selects an optional saved connection or deployment/cache
  identity. Its configured API-client path takes precedence over the conventional
  `<config_root>/<server-profile>_api_client.yaml` cache path.
- `--engagement-id` selects the local directory
  `<case-root>/<engagement-id>`.
- The new `setup start` interface requires an explicit investigation ID. Older
  case-bound interfaces can fall back to `--server-profile` when the investigation
  ID is omitted.
- If neither value is available, case-bound commands fail closed.
- Velociraptor labels are independent targeting inputs. A label is never
  inferred from either identifier.

Multiple server references can coexist in one installation. Select the intended
reference per command; it remains separate from the local investigation ID.
Replace `<SERVER REFERENCE>` below with the saved name and use that server's
API-client YAML.

```bash
./dfir setup start --mode live-remote \
  --server-profile "<SERVER REFERENCE>" \
  --id ir1234 \
  --api-client /secure/lab_api_client.yaml \
  --case-root "$HOME/cases"
```

This connects to the selected deployment and writes readiness and later hunt or
collection state under `$HOME/cases/ir1234`. A transient investigation server
does not need a permanent named connection in user settings. Its concrete
credential/server binding is retained in `engagement.json`.

Live setup defaults to server readiness without a hostname prompt. API security,
connectivity and authorization must pass; client visibility is recorded but an
empty inventory is allowed. Explicit hostname, client ID or label selectors
require target visibility without restricting later site-wide operations.
`resume` retains saved verification choices; an explicit new selector replaces
the old selection. The compatible `--environment-only-ok` flag clears saved
target checks. Dead-disk modes remain bound to their evidence and mapped clients.

## Readiness contract

Case-bound live commands require
`<case-root>/<effective-engagement-id>/engagement.json`. Schema v5 records:

- `engagement_id`
- `engagement_id_source`: `explicit` or `server_profile_fallback`
- `connection.server_profile`
- the API credential, server, organization, setup provenance, and
  readiness checks
- API certificate validity and file-security metadata, plus verified
  server-side roles and effective permissions for live readiness

For live server-only readiness, `readiness.scope.verification_method` is
`environment_only`. `target_visible=false` and `matched_client_count=0` report
an empty visible inventory without invalidating server readiness. A positive
count from this bounded check is not a fleet census. Explicit target checks and
dead-disk readiness continue to require `target_visible=true`.

The manifest is authoritative after setup. A supplied server profile must
match it, and an explicit API client must match its recorded credential and
server identity. Older readiness is not migrated automatically; rerun
engagement setup to publish schema v5.

Instance-only commands such as direct VQL, client inventory, artifact inventory,
and config fetch accept `--server-profile` without requiring an engagement
manifest. Case-bound hunt, collection, host-analysis, hydration, and
hunt-backed Autoruns commands require readiness.

## Readiness reuse and recovery

Readiness has no elapsed-time expiry. `verified_at` records when setup verified
it; legacy `expires_at` values are ignored. Credential, server, organization,
provenance and target checks still apply. Artifact preflight supersession also
retains its identity and partition checks without an age limit.

Reuse valid saved readiness and attempt the requested operation. On a connection
or readiness failure, diagnose the same server and investigation binding before
refreshing readiness through setup. Rechecking readiness does not regenerate
credentials. Acquiring existing remote files requires `--fetch-config`; creating
missing files requires `--provision-api` or `--provision-client`; replacing the
remote API credential requires `--regenerate-remote-api`. Do not add provisioning
or replacement flags to recover from an unrelated transport, permission or
analysis failure. An uncertain collection submission must be checked before
retrying. Certificate validity and mapped-client liveness checks retain their
existing behavior.

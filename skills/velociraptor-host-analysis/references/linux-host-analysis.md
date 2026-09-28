# Linux Host Analysis

Use the inventory-validated Linux profile instead of a hard-coded named
collection bundle. The connected Velociraptor server inventory and saved flows
remain authoritative.

`Generic.*` artifacts are eligible cross-platform candidates when their live
definition, precondition, parameters, and result sources support Linux. Do not
infer portability from the prefix alone. The current validated profile uses
`Generic.Client.Info`; add other Generic candidates only after inventory and
schema validation.

The executable mode and capability contract is
[`velociraptor-linux-host-profile.json`](../../../src/vraptor/resources/contracts/velociraptor-linux-host-profile.json).

## Inventory and plan

Export or exactly reuse a Linux artifact inventory:

```bash
dfir artifacts inventory \
  --api-client /path/to/api_client.yaml \
  --output-dir <case_root>/IR1234/.cache/velociraptor/artifacts \
  --name-regex '^(Linux\.|Generic\.Client\.Info)'
```

Resolve one mode without starting collection:

```bash
dfir artifacts linux-plan \
  --inventory <output-dir>/artifact_definitions_inventory.json \
  --mode standard \
  --distro debian \
  --investigation-id IR1234 \
  --client-id C.1234abcd
```

The plan fails closed when a required capability has no available artifact or
the server inventory does not expose the parameters needed by a bounded
request. It emits one `collect check` and `collect ensure` command per artifact
so exact reuse, parameter comparison, and selective refresh remain independent.
Optional capabilities are listed but excluded from emitted commands unless
the operator repeats `--include-optional CAPABILITY` or explicitly uses
`--include-optional all`.

The planner persists a content-hashed `linux-host-plan-*.json` beside the
inventory by default; use `--output` for another case-owned path. Keep that
plan as the request handoff. Analysis-only values are emitted as
`--analysis-input KEY=VALUE`: they create a distinct saved request and are
preserved in live-analysis state, but they do not change the exact raw-flow
reuse identity.

Run every emitted `check` before `ensure`. Do not add `--force-run` unless a
fresh exact collection is intentional. Analyze completed flows in place; do
not export merely to use generic stacking or chunking.

## Modes

| Mode | Rule |
| --- | --- |
| `triage` | Require identity, users/groups, recent logins, cron, and services. Add SSH, process, and network snapshots only when relevant with `--include-optional`. |
| `standard` | Add authorized keys, shell history, privileged/interactive users, mounts, and SUID. Add distro package state explicitly with `--include-optional packages --distro ...`. |
| `deep` | Require at least one focus: `persistence`, `execution`, `authentication`, `web-server`, `container`, or `filesystem`. |
| `timeline` | Require both time bounds and bounded journal review; add a path-bounded file-mtime lane when requested. |

Do not interpret optional unavailable capabilities as negative evidence. Record
them as collection gaps or not-applicable for the distro, init system, server
role, or acquisition mode.

## Deep examples

Bounded web-server planning:

```bash
dfir artifacts linux-plan \
  --inventory <case_root>/<id>/.cache/velociraptor/artifacts/artifact_definitions_inventory.json \
  --mode deep \
  --focus web-server \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --date-after 2026-08-01T10:00:00Z \
  --date-before 2026-08-01T12:00:00Z \
  --log-glob '/var/log/nginx/*.log' \
  --search-regex 'wp-login|xmlrpc|cmd=' \
  --web-root '/var/www/html/**' \
  --server-role nginx-php \
  --application-context 'vhost=app.example app=wordpress' \
  --document-root /var/www/html \
  --log-timezone UTC \
  --log-format nginx-combined-xff \
  --estimated-log-bytes 25000000 \
  --max-log-bytes 100000000 \
  --include-optional journal
```

For the first pass, omit the byte values. The incomplete plan still emits the
`web_log_inventory` FileFinder slice but withholds LogHunter. Analyze that
metadata flow, sum the retained log-file sizes, choose an explicit maximum,
then rerun with `--estimated-log-bytes` and `--max-log-bytes`. The planner
refuses LogHunter when the estimate exceeds the maximum.

Run separate planner requests for materially different log families or search
terms so access, error, WAF/proxy, PHP-FPM, and application coverage remain
independently reusable and auditable. Do not use a common proxy IP, `/`, HTTP
method, or status code as the sole search term.

Bounded timeline planning:

```bash
dfir artifacts linux-plan \
  --inventory <case_root>/<id>/.cache/velociraptor/artifacts/artifact_definitions_inventory.json \
  --mode timeline \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --date-after 2026-08-01T10:00:00Z \
  --date-before 2026-08-01T12:00:00Z \
  --path-glob '/var/www/**' \
  --include-optional file_timeline
```

## Reference routing

- Read [linux-persistence-execution.md](linux-persistence-execution.md) for
  cron, services, shell history, process, package, SUID, and execution claims.
- Read [linux-authentication.md](linux-authentication.md) for accounts, WTMP,
  SSH logs, authorized keys, and privilege interpretation.
- Read
  [linux-web-container-analysis.md](linux-web-container-analysis.md) for
  bounded web-server, webshell, proxy/WAF, and Docker analysis.
- Read
  [linux-timeline-filesystem.md](linux-timeline-filesystem.md) for journal,
  file timestamps, metadata, path bounds, and timeline closure.

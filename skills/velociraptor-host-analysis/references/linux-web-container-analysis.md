# Linux Web-Server and Container Analysis

## Required bounds

Web-server deep planning requires:

- exact client;
- start and end time;
- bounded log glob;
- selective search regex;
- bounded web-root glob; and
- explicit `--server-role`, `--application-context`, `--document-root`,
  `--log-timezone`, and `--log-format` values.

`Linux.Sys.LogHunter` does not expose time parameters. First run the
`web_log_inventory` FileFinder slice, sum retained log-file bytes, then rerun
the planner with `--estimated-log-bytes` and an operator-selected
`--max-log-bytes`. The planner withholds or rejects LogHunter until this gate
passes. Record post-collection match counts, abort or narrow explosive terms,
and deterministically post-filter returned events to the requested interval.
Do not use common proxy IPs, `/`, HTTP methods, status-only expressions, or
broad wildcards as sole collection terms.

Because the requested interval is not a LogHunter collection parameter,
different analysis windows intentionally reuse the same exact raw flow when
the client, log glob, regex, timeout, and artifact version match. The planner
records `date_after` and `date_before` separately as `analysis_inputs`; each
emitted collection command persists them into a distinct request ID and each
live-analysis pass preserves them in compact state and the summary.

Use strict open analysis bounds:
`date_after < normalized_event_time < date_before`. Preserve original
timestamps and state the artifact/parser behavior when it differs. Record each
matched file, retained and rotated/compressed coverage, source rows, retained
rows, parse failures, and excluded out-of-window rows. A site-specific proxy IP
cannot be detected automatically; operator preflight must classify it as
context-only.

Use a separate planner invocation for each materially different log family or
search expression. Reuse the shared identity and web-file flows, but keep
access, error, WAF/proxy, PHP-FPM, and application log requests independently
bounded and attributable.

`Linux.Search.FileFinder` supports modification-time bounds. Those bounds do
not create a complete filesystem timeline and do not cover creation, access,
deletion, or prior content.

## Web correlation

Preserve and correlate where available:

- event time and timezone;
- vhost, method, decoded path/query, status, response size, referrer, and user
  agent;
- direct peer, proxy IP, forwarded client IP, and transaction/request ID;
- Apache/Nginx access and error logs;
- HAProxy, ModSecurity, PHP-FPM, application, auth, and systemd journal data;
- web-root path, owner/group, inode, mode, size, timestamps, SHA-256, package
  or vendor baseline, and symlink target;
- process, command, service/container, socket, and outbound network context.

Group ModSecurity rows by transaction ID before drawing request-level
conclusions. Separate proxy infrastructure from the attributed client and
retain the original forwarding chain.

Large successful responses are exposure leads, not proof of exfiltration.
Status codes do not prove application success, data access, or command
execution.

## Webshell review

For a suspicious web-root file or YARA hit:

1. Preserve exact rule, tags, string, offset, bounded context, path, size,
   owner/mode, timestamps, and hash.
2. Separate known-malicious signatures from generic obfuscation or dangerous
   function heuristics.
3. Compare with trusted package/vendor files and deployment history.
4. Correlate relevant requests, application errors, process execution,
   child processes, network activity, and persistence.
5. Upload file content only when explicitly required as immutable evidence.

For exact content, use a separate exact-path FileFinder request with upload
enabled only after the metadata/hash pass identifies the file. Do not widen the
default web-root metadata request into bulk content collection.

The current collection exporter does not download flow-upload blobs. Preserve
uploaded content only through an explicitly authorized Velociraptor upload
retrieval procedure that records the flow, source path, downloaded object,
size, and SHA-256. Do not claim content preservation from a result CSV alone.

`possibleIndicator` or generic obfuscation alone is not a confirmed webshell.

## Containers

- `Linux.Applications.Docker.Info` and `.Version` are collection-time Docker
  daemon views and require socket access.
- Preserve container/image IDs, names, command, mounts, network mode, labels,
  image provenance, daemon version, and collection time when emitted.
- Host process/network/mount data may not represent the same namespace as a
  container.
- Container absence from Docker artifacts does not exclude containerd,
  Kubernetes, podman, another socket, a stopped/deleted container, or a
  dead-disk workload.
- Pivot to exact container logs, overlay paths, mounted host paths, image
  metadata, orchestrator audit data, and host journal only from a concrete
  lead.

Do not run remediation, quarantine, package installation, or container
commands through an analysis subagent.

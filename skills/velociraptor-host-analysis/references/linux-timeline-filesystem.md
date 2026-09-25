# Linux Timeline and Filesystem Analysis

## Time semantics

Use a bounded interval and record timezone/clock assumptions. Keep these claims
separate:

- journal event time;
- WTMP login/logout time;
- auth/syslog parsed time;
- file mtime, ctime, atime, and birth time when supported;
- package install time;
- process start time when actually emitted; and
- collection time for live snapshots.

Do not substitute collection time for event time. Do not treat ctime as file
creation time. Birth time may be unavailable. FileFinder's `MoreRecentThan`
and `ModifiedBefore` constrain mtime only.

For deterministic local correlation, use a strict open interval:
`date_after < normalized_event_time < date_before`. Preserve the source value
and document any different inclusion behavior enforced by the artifact.

## Timeline workflow

1. Require both `DateAfter` and `DateBefore` for
   `Linux.Forensics.Journal`.
2. Verify the effective flow arguments match the requested interval.
3. Preserve timestamp, unit/identifier, priority, executable, command line,
   PID, message, source journal path, client, and flow.
4. Add a bounded `Linux.Search.FileFinder` path only when filesystem change is
   part of the question.
5. Add auth, package, web/application, or shell-history lanes only when they
   can answer the bounded hypothesis.
6. Normalize times without discarding original values and source timezone.
7. Merge independent source references; do not copy bulk rows into one local
   CSV merely to build a timeline.

## File review

For suspicious paths preserve when available:

- original and normalized path;
- owner UID/name and group GID/name;
- inode, filesystem, file type, octal mode, size;
- atime, mtime, ctime, and birth time;
- SHA-256 and package/vendor provenance;
- symlink target and whether traversal was disabled;
- exact search glob, exclusions, accessor, and one-filesystem behavior.

Keep `Calculate_Hash=Y`, `Upload_File=N`, `LocalFilesystemOnly=Y`, and
`DoNotFollowSymlinks=Y` as safe planning defaults. Change them only for an
explicit evidence question.

Directory-mtime anomalies do not enumerate deleted children. Use filesystem
journal, low-level filesystem parsing, backups, package databases, or other
deleted-entry evidence when available.

## Closure

Do not close a Linux timeline when:

- journal retention or persistent-journal coverage is unknown;
- logs were post-filtered without reproducible counts;
- any source is sampled, truncated, token-limited, or non-terminal;
- time parameters were not enforced by the effective flow;
- required paths, namespaces, containers, or forwarded logs are out of scope;
  or
- one timestamp type is being used as a substitute for another.

Return source coverage, interval coverage, clock/timezone limitations,
correlated events, unresolved gaps, and the next exact pivot.

Export becomes mandatory only when the case requires immutable chain-of-
custody preservation, source expiry/rotation makes server retention
insufficient, exact content is needed, offline/interoperability handoff is
required, or the operator explicitly requests it. Otherwise preserve compact
live-analysis state and exact finding-linked context.

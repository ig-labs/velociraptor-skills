# Linux Persistence and Execution

## Review order

1. Establish distro, kernel, init system, client acquisition mode, users,
   groups, mounts, package manager, and collection time.
2. Review cron/at, systemd services, authorized keys, SUID/SGID files, and
   targeted immutable files.
3. Review shell history and bounded journal/process-accounting evidence.
4. Use live process and network snapshots only as collection-time state.
5. Pivot from a concrete command, path, user, service, hash, package, or time.

## Persistence claims

- `Linux.Sys.Crontab` shows parsed schedule entries and script content. Preserve
  user, schedule, command, source path, script mtime, owner/mode, and symlink
  target. Validate included scripts separately.
- `Linux.Sys.Services` uses live `systemctl` output. It does not enumerate every
  disabled unit file, non-systemd init mechanism, user service, container
  service, or historical service state.
- `Linux.Ssh.AuthorizedKeys` establishes key presence. Preserve account,
  path, options, key type/fingerprint, comment, mtime/ctime, owner, and mode.
  Authorization requires owner and business context.
- `Linux.Sys.SUID` is a lead. Compare path, owner, mode, hash, package
  provenance, and trusted distro baselines before escalating.
- Use immutable-file review only with a bounded path. The upstream artifact is
  ext4-specific and does not prove malicious intent.

Do not call a path persistent solely because it is writable or executable.
Identify the actual launch mechanism and effective user.

Freshness is hypothesis-specific. To make a present-tense claim, force a fresh
live artifact at the decision point. Refresh a cron, key, SUID, or file
snapshot when the prior collection predates the suspected change, containment,
configuration deployment, or other event that could have altered it. Record
the stale-slice rationale and never force the complete baseline solely because
one current-state artifact is stale.

## Execution claims

- `Linux.Sys.BashHistory` proves a line exists in a history file, not that it
  executed successfully or at a known time. Preserve history path and owner;
  correlate with journal, auditd, process accounting, file, and network data.
- `Linux.Sys.Pslist` is a current snapshot. Preserve PID/PPID, name,
  command line, executable, user, deleted-executable marker, start time if
  actually emitted, and collection time.
- A deleted executable path is notable but requires process, file, package,
  and memory context.
- Package inventory proves installed state only. Select the target distro's
  artifact and keep package name, version, source/repository, architecture,
  install state, and install time when available.
- Process-memory YARA is deep and lead-driven. Supply an approved rule, keep
  uploads disabled by default, preserve rule/string/offset/context, and do not
  equate one heuristic hit with malware.

## Exact pivots

- Command or shell lead: bounded journal/auth/audit query, script metadata and
  hash, parent service/cron/key, related network identity.
- Service lead: unit file and drop-ins, `ExecStart`, user, environment,
  enablement links, package ownership, journal, executable hash.
- Cron lead: exact source file, referenced script/binary, owner/mode, package
  ownership, adjacent journal/auth/file events.
- SUID lead: exact path, hash, package verification, owner/mode, mount options,
  recent metadata change, execution evidence.
- Live process lead: executable and maps, package/signature provenance,
  parent/children, sockets, journal/audit evidence, bounded YARA only when
  justified.

Keep zero rows, unsupported init/package systems, failed commands, dead-disk
limitations, and absent historical telemetry explicit.

Default file review keeps `Upload_File=N`. If exact script content becomes
necessary, create a separate single-artifact `Linux.Search.FileFinder` request
for the exact path with `Upload_File=Y`, document the immutable-evidence
purpose, and retrieve the resulting upload explicitly from Velociraptor with
flow/path/size/SHA-256 provenance. The current collection CSV exporter does not
download uploaded blobs. The built-in package inventory does not map an
arbitrary path to its owning package; use a validated site artifact or record
package ownership as an unresolved evidence gap.

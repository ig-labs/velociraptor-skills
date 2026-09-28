# Linux Authentication Analysis

## Evidence lanes

- `Linux.Sys.Users` and `Linux.Sys.Groups`: current account and membership
  state.
- `Linux.Users.RootUsers`: sudo-group leads, not a complete privilege model.
- `Linux.Users.InteractiveUsers`: accounts with interactive shells, not proof
  of recent login.
- `Linux.Sys.LastUserLogin`: WTMP-backed sessions.
- `Linux.Syslog.SSHLogin`: parsed SSH auth-log events.
- `Linux.Ssh.AuthorizedKeys`: key-based access configuration.
- `Linux.Ssh.PrivateKeys`: sensitive, targeted deep-only exposure review.

## Workflow

1. Preserve client, hostname, distro, acquisition mode, collection time, and
   effective artifact parameters.
2. Build current account state: UID/GID, groups, home, shell, lock/expiry
   state when available.
3. Review privileged paths beyond one sudo group: UID 0, sudoers/include files,
   wheel/admin groups, polkit, service accounts, and container controls where
   relevant.
4. Correlate WTMP login/logout records with SSH auth logs, source IP, method,
   attempted user, key configuration, and bounded journal evidence.
5. Retrieve exact key-file metadata and fingerprint before asserting an
   unauthorized key.
6. Record successful, failed, invalid-user, session-open, privilege-change,
   and configuration-presence claims separately.

## Limitations

- WTMP and auth logs may be rotated, forwarded, disabled, tampered with, or
  stored outside defaults.
- Syslog parsing depends on distro and message format. A parser miss is not
  negative evidence.
- Container, chroot, cloud-init, LDAP/SSSD, and centralized identity may not be
  represented by local passwd/group files.
- History-file ownership does not prove who typed a command.
- An authorized key may be shared, automated, expired operationally, or
  expected only for a bounded host/time scope.
- Private-key discovery is sensitive. Do not export key material unless
  explicitly authorized as immutable evidence.

## Exact pivots

- New or privileged account: passwd/group/sudoers metadata, package/config
  management provenance, auth logs, journal, home creation, keys, shell
  history, processes, and services.
- Suspicious SSH source: exact auth events, success/failure sequence, target
  account, key fingerprint, session-open/close, commands/processes, files, and
  network activity.
- Suspicious key: exact path, account, fingerprint, options, comment,
  owner/mode, mtime/ctime, configuration-management provenance, and matching
  auth evidence.

Do not convert one expected key, user, or source IP into a global allowlist.

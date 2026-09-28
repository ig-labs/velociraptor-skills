# Registry Hunter

Use Registry Hunter only for a concrete registry question.

## Category-scoped collection

```bash
dfir collect ensure \
  --investigation-id IR1234 \
  --client-id C.1234abcd \
  --artifact 'Windows.Registry.Hunter[persistence]'
```

Supported categories include execution, persistence, services, autoruns, devices,
network-shares, user-accounts, threat-hunting, antivirus, cloud-storage, event-logs,
installed-software, Microsoft Office, system-info, third-party-applications,
user-activity, volume-shadow-copies, and web-browsers.

Use `[all]` only through the explicit standalone `registry` collection type.

## Bounded IOC search

Use artifact-supported `IocRegex`, `ModifiedAfter`, and `ModifiedBefore` only after
verifying the live artifact exposes them. Registry time bounds apply to key `Mtime`;
they are not generic event-time bounds.

## Curated exports

The execution profile exports AppCompatCache, UserAssist, RADAR, and BAM views.
Additional curated profiles cover system information, browsers, user activity,
services, persistence, network shares, devices, software, event logs, and other
supported categories.

Exports read the exact saved Registry Hunter flow. The explicit export action is
sufficient authorization.

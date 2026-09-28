# macOS Host Analysis

Use explicit artifacts selected from the connected Velociraptor server. This
repo does not yet package a macOS named bundle or canonical macOS artifact
profiles; fail closed rather than guessing artifact names or parameters.

## Artifact discovery

```bash
dfir artifacts inventory \
  --api-client /path/to/api_client.yaml \
  --output-dir <case_root>/IR1234/.cache/velociraptor/artifacts \
  --name-regex '^(MacOS\.|OSX\.|Darwin\.|Generic\.Client\.Info)'
```

Confirm applicability and parameters with the server inventory before each
explicit `collect ensure --artifact` request.

## Mode mapping

### Triage

Select the smallest validated set for system identity, users, current
process/network state, persistence, quarantine/download context, and recent
security or unified-log evidence.

### Standard

Add validated artifacts for launch agents/daemons, login items, applications,
users/groups, shell history, network configuration, browser activity, file
metadata, and relevant logs.

### Deep

Use lead-driven bounded follow-ups for unified logs, launch items, suspicious
applications/binaries, quarantine events, browser/download history, exact file
searches, persistence paths, process/network state, or user activity.

### Bounded timeline

Use explicit time-bounded unified-log and filesystem sources. Verify parameter
enforcement and correlate multiple sources before declaring adjacent activity
complete.

## Interpretation controls

- Treat Gatekeeper, quarantine, notarization, signature, and application
  presence as separate evidence dimensions.
- Treat current process and network rows as volatile snapshots.
- Preserve path, bundle identity, signer/team ID, hashes, quarantine metadata,
  user, timestamps, client ID, flow ID, and source identifiers when available.
- Account for per-user and system launch locations separately.
- Treat unsupported artifacts as coverage gaps, not clean results.
- Keep full rows in Velociraptor unless explicit immutable evidence is needed.

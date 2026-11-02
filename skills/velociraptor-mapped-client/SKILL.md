---
name: velociraptor-mapped-client
description: Create, supervise, validate, and inspect a read-only Velociraptor mapped client for an E01/raw image, mounted Windows volume, or KapeFiles collection, locally or with a remote server, with a verified client id, LastSeen, supervisor, remap, and API-visible identity. Use for low-level mapping when velociraptor-engagement-setup is not used.
---

# Velociraptor Mapped Client

**Server prerequisite:** complete the [DetectRaptor bootstrap](../../docs/reference/detectraptor-bootstrap.md) for each new local or connected live/remote server before server work; a failed import blocks the workflow.

Use this skill to expose local dead-disk evidence through Velociraptor without
modifying the evidence source. Use the shared `vraptor` CLI; `vraptor analyze`
only reuses existing evidence. See the [shared CLI contract](../../docs/contracts/cli.md).

Read the shared
[Velociraptor operation authorization policy](../../docs/reference/velociraptor-operation-authorization.md)
before any `--provision-api`, `--provision-client` or `--regenerate-remote-api`
use or other server mutation, and the shared
[server-profile and engagement context](../../docs/reference/velociraptor-engagement-context.md)
when choosing `--server-profile`, case paths or readiness.

The implementation is shared under `src/vraptor`. Do not add runtime
scripts under this skill directory.

## Required Inputs

- an existing E01/raw image, mounted Windows volume, extracted Velociraptor
  export, or Velociraptor KapeFiles collection ZIP; collections map Windows
  drive uploads only, and results-only collector ZIPs are rejected
- a working local Velociraptor executable, selected in operational TOML,
  with `VELO_BIN`, or with `--velociraptor-bin`; install it when missing with
  `vraptor tools prep -t velociraptor`
- the API client and matching endpoint configuration for an existing server,
  or selection of managed local-server setup. Use explicit configuration names
  such as `~/.config/velociraptor/dfir_api_client.yaml` and
  `~/.config/velociraptor/dfir_client.config.yaml`; do not silently substitute
  an unrelated `ir*` configuration
- an optional unique mapped-client hostname; managed setup derives a stable
  name when omitted

## Extracted Velociraptor KapeFiles collection

Use `--evidence-type velociraptor-export` with `setup start` in either
`local-deaddisk` or `remote-deaddisk` mode. `auto` recognizes `uploads.json`.
Other selectors are `windows-disk`, `windows-directory`, and
`velociraptor-kapefiles-zip` (described below).

This implements extracted Velociraptor/KAPEFiles collection layouts containing
`uploads.json` and `uploads/{auto,file,ntfs}/...`; native KAPE output directories
without that index and ZIP containers are not supported by this selector.
The upload index supplies original drive paths, and percent-encoded disk names
are decoded into a separate `export-view` working copy. Allow disk space for a
full copy of uploaded files. The source folder is never rewritten.

The mapper checks uploaded sizes, hashes copied content, and probes reads for each
accessor and drive. Resume checks the source inventory, remap hash and working-copy
hashes. It rejects sparse/incomplete uploads, symlinks, duplicate virtual paths,
unsupported accessors, non-Windows (Linux/macOS) paths and VSS paths. An existing
manual remap is not replaced; use a separate mapping workspace. Failed preparation
can retain an incomplete view for inspection; inspect it before choosing a fresh
workspace to retry.

Only collected files are visible. Filesystem timestamps reflect extraction and
are not original forensic timestamps. Available standard SYSTEM, SOFTWARE, SAM
and SECURITY hives from auto/file uploads receive registry mappings; user and
Amcache hives are not mapped. Missing artifacts remain coverage gaps.

## Velociraptor KapeFiles zip

Use `--evidence-type velociraptor-kapefiles-zip` (or `auto`) for a collection
ZIP containing `uploads.json`, or an AES-protected Velociraptor `data.zip`
container. A ZIP without `uploads.json` or without uploaded files, such as a
results-only offline collector, is rejected, as are non-Windows drive paths.
The mapper mounts drive roots through the native `collector`
accessor and standard system registry hives through `raw_reg`; no extraction,
import, or evidence working copy is needed. VQL probes verify each accessor/drive
before the existing client/supervisor lifecycle starts. Source SHA-256, remap
hash and hostname bind resume to the original evidence.

For protected containers, set `VRAPTOR_ZIP_PASSWORD_FILE` to an existing
owner-only credential file outside the case/evidence directory containing the
password exactly (no trailing newline). Only its path is recorded, never its
contents. Keep the file available for later client reads and use the same
selector on resume. AES-encrypted `data.zip` is supported; native KAPE archives,
legacy ZipCrypto and certificate-encrypted containers are not supported.

Only captured files are visible. The collector handles sparse-file reads;
ZIP directory metadata/timestamps are not original forensic metadata. Encoded
member basenames retain their ZIP spelling. User/Amcache registry mounts and
external-tool access are not provided. Missing files remain coverage gaps.

```bash
vraptor setup start --mode local-deaddisk --id example --mapping-id kapefiles \
  --evidence-type velociraptor-kapefiles-zip \
  --evidence-path /evidence/collection.zip --hostname example-kapefiles
```

ZIP input needs no up-front extraction but can still use substantial temporary
disk, CPU and memory. Read [KapeFiles ZIP mapping internals](references/kapefiles-zip.md)
before notebook or query-local remapping, changing the VQL mapping generator,
choosing between ZIP and extracted input for repeated broad analysis, or
validating ZIP mapping changes.

## Prepare Remote Configuration

API-account and API-YAML setup is identical to live remote. Reuse the shared
[generation and retrieval procedure](../velociraptor-live-api-client/references/service-account-config.md):
fetch helpers use root or sudo and resume automatically after any terminal sudo
prompt. The configured `run_as` selects the generation account. When sudo is
unavailable, use the supplied manual handoff and Continue prompt. Only remote
dead-disk additionally needs endpoint YAML.

Reuse existing verified files when available. Fetch existing remote files only
when requested, using an explicit server address and configured SSH identity:

```bash
vraptor config fetch-api \
  --server-profile dfir \
  --server-ip 192.0.2.10 \
  --output-path ~/.config/velociraptor/dfir_api_client.yaml

vraptor config fetch-client \
  --server-profile dfir \
  --server-ip 192.0.2.10 \
  --output-path ~/.config/velociraptor/dfir_client.config.yaml
```

Generating missing remote files additionally requires `--provision-api` or
`--provision-client` on the respective helper. A transport or permission failure
does not authorize generation or replacement.

Do not request local GUI workspace initialization for a remote mapped client.

## Create And Verify

Use the engagement setup command when a durable readiness manifest is required:

```bash
vraptor setup start --mode remote-deaddisk \
  --evidence-path /path/to/evidence.E01 \
  --server-profile dfir \
  --engagement-id ir9005 \
  --api-client ~/.config/velociraptor/dfir_api_client.yaml \
  --client-config ~/.config/velociraptor/dfir_client.config.yaml \
  --hostname evidence-host-dfir
```

For a managed local server using the same mapping lifecycle:

```bash
vraptor setup start --mode local-deaddisk --id ir9005 \
  --evidence-path /path/to/evidence.E01
```

Case-owned server state defaults to `<case-root>/<id>/runtime/velociraptor/server/`,
and mapping state to `mapping/` under the same directory. Shared connections
reference native API/client YAML in their configured common location. Existing
cases retain saved paths; explicit `runtime_root` settings retain the external
layout. `--workspace` changes
the mapping directory. Existing caller-managed local infrastructure can be
selected with matching explicit API and endpoint configuration files.

For several images on the same server, keep one investigation and give each
`setup start` a distinct `--mapping-id` and hostname. See
[multi-host setup](../velociraptor-engagement-setup/SKILL.md#several-mapped-hosts-in-one-investigation)
for directory layout and per-host resume/stop. Do not create a separate case for
each image when the user requests a shared investigation.

Setup creates or reuses the read-only remap, client identity and writeback, starts
the client and supervisor as needed,
then fails closed unless all of the following are true:

- the remap contains a mount mapping for the evidence source
- the remote API answers
- the enrolled client id is visible through that API
- the API-visible hostname matches the requested mapped-client name
- `LastSeen` is populated
- the client process is running
- the supervisor process is running
- the final supervisor state is `online`

For lower-level mapping without the unified readiness manifest:

```bash
vraptor mapped add-remote \
  --api-client ~/.config/velociraptor/dfir_api_client.yaml \
  --client-config ~/.config/velociraptor/dfir_client.config.yaml \
  --workspace ~/.local/share/velociraptor-mapped \
  --json-out /path/to/mapping-leaf.json \
  -n evidence-host-dfir \
  /path/to/evidence.E01
```

## Status

For a managed investigation:

```bash
vraptor setup status --id ir9005
vraptor setup resume --id ir9005
vraptor setup stop --id ir9005
```

`status` reports recorded readiness and local process state without an API query.
`resume` restores the saved binding and verifies readiness again. `stop` handles
owned mapping processes only; `--stop-server` additionally stops an owned local
server when no other active mapping uses it. Remote servers are never stopped.
After startup fails before mapping initialization, `stop --stop-server` can
still stop the owned local server.
Evidence, remaps, writeback and datastore files are retained.

For a lower-level mapping, inspect its explicit workspace and client:

```bash
vraptor mapped status \
  --workspace ~/.local/share/velociraptor-mapped \
  --client evidence-host-dfir \
  --json
```

The status record distinguishes process, evidence, identity, API, and restart
backoff failures.

## Configuration

Prefer `vraptor setup configure` and `~/.config/vraptor/config.toml` (or the XDG
configuration directory). `[workstation]` selects `binary` and `runtime_root`;
`[mapping]` exposes `poll_seconds`, `stale_seconds`, `failure_threshold`,
`max_restarts` and `restart_window_seconds`. `[local_server]` optionally selects
`api_user`, `frontend_port`, `api_port` and `gui_port`. Native credentials stay in
their existing YAML files. `vraptor setup show` displays effective settings and
provenance without secrets.

`[mapping].startup_timeout_seconds` (default 120) bounds mapping startup;
`ready_timeout_seconds` (default 45) bounds the wait for online health. Both must
be positive integers. Managed setup accepts matching CLI flags. Increasing a
timeout does not relax evidence, identity, `LastSeen`, or supervisor checks.
Named `connections.NAME.org_id` applies to API readiness and native supervisor
queries. Preserve the saved organization when resuming an existing mapping.
Shared SSH settings belong in `[connection_defaults]`, with named overrides.
`[api].grpc_max_message_bytes` selects the shared transport limit.
Successful setup/resume prints the optional `vraptor ai setup` next step for
AI configuration (`agent` remains an alias). Interactive `setup configure` can
open that wizard after saving settings when the operator accepts
`Configure AI analyst settings [Y/n]:`; No skips it and preview never launches it.
For local-only settings, enter `-` at the suggested `live` server-name prompt.

Legacy environment overrides remain supported:

- `VELO_BIN`: Velociraptor executable
- `VELO_MAPPED_CLIENT_WORKSPACE`: lower-level mapping workspace; managed setup
  uses its saved investigation workspace or explicit `--workspace`
- `VELO_MAPPED_CLIENT_POLL_SECONDS`: supervisor poll interval, default `15`
- `VELO_MAPPED_CLIENT_STALE_SECONDS`: optional `LastSeen` threshold; remote
  mappings default to `600`
- `VELO_MAPPED_CLIENT_FAILURE_THRESHOLD`: failures before restart, default `3`
- `VELO_MAPPED_CLIENT_MAX_RESTARTS`: bounded restart count, default `5`
- `VELO_MAPPED_CLIENT_RESTART_WINDOW_SECONDS`: restart window, default `600`
- `VELO_MAPPED_CLIENT_STARTUP_TIMEOUT_SECONDS`: mapping startup timeout, default `120`
- `VELO_MAPPED_CLIENT_READY_TIMEOUT_SECONDS`: online-health wait, default `45`
- `VRAPTOR_ZIP_PASSWORD_FILE`: protected-collection password-file path; see the ZIP section above

The example dotenv leaves operational overrides empty to preserve TOML values.
Keep password-file selection specific to the protected mapping; never save the
password itself in dotenv or TOML. Lower-level foreground supervision remains
incompatible with managed setup's JSON manifest; it is not a managed default.

## Outputs

The setup manifest records:

- mode and API configuration identity
- client name and client id
- API-visible hostname and `LastSeen`
- evidence, workspace, client directory, and remap paths
- client and supervisor PIDs
- supervisor mode and final health state

## Guardrails

- Never write to, convert, repair, rename, or relocate the evidence image.
- Keep runtime and manifest outputs outside mounted evidence; setup rejects
  output paths inside the source directory or over the image.
- Keep mutable writeback, logs, remaps, manifests, and PID state in the mapped
  workspace, not beside the evidence.
- Do not reuse stale local-GUI mapping state for a remote mapping.
- Preserve existing mapping and server identities on repeated setup. Changed
  evidence, hostname or server bindings require a separate mapping; do not reset
  saved writeback to resolve a mismatch.
- Renew API certificates/keys without changing the endpoint, organization, CA,
  API username or client enrollment nonce, then rerun readiness. Original
  hash-only sessions must resume once with unchanged credentials before renewal;
  unverifiable legacy records block automatic upgrade and preserve writeback.
- Use matching API and endpoint client configurations from the same remote
  Velociraptor deployment.
- Treat a missing client id, missing `LastSeen`, identity mismatch, dead
  supervisor, or non-`online` final state as a blocking setup failure.
- Use a binary that preserves remapping in client mode. The official 0.77.1
  build drops `Remappings` and can enroll the physical workstation identity;
  [0.77.2](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.2)
  preserves it and was validated with synthetic mounted Windows evidence.
  Do not bypass hostname verification to accommodate an incompatible binary.
  Initial enrollment may briefly report the workstation hostname; supervision
  allows 30 seconds for the remapped identity update before holding a mismatch.

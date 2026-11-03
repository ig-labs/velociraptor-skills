# Velociraptor KapeFiles ZIP Mapping Internals

Use this reference with the
[Velociraptor KapeFiles zip](../SKILL.md#velociraptor-kapefiles-zip) section of
the mapped-client skill. It covers how the mount rules are generated, how to use
them in a notebook or query, the performance trade-offs of mapping a ZIP
directly, and how to validate mapping changes.

## Contents

- [VQL mapping generation and notebook use](#vql-mapping-generation-and-notebook-use)
- [ZIP mapping performance](#zip-mapping-performance)
- [Validation](#validation)

## VQL mapping generation and notebook use

`src/vraptor/resources/vql/kapefiles_zip_remapping.vql`
generates the filesystem and registry rules from the validated inventory.
Python retains archive validation (only Windows drive uploads under the `auto`,
`file` or `ntfs` accessors pass; a ZIP without `uploads.json` or uploaded files
is rejected), source hashing, password-file checks and the client lifecycle; it
no longer constructs the mount rules. The VQL inputs are
`RecordsFile`, `BaseFile`, `EvidencePath`, and `MountScope` (a VQL statement
referencing the protected password file, never the password itself).
Preparation consumes the emitted YAML and verifies mapped reads before publishing.
Existing bound remaps remain unchanged on resume.

For notebook or query-local analysis, install that generated YAML directly:

```vql
LET Mapping <= parse_yaml(filename="/runtime/remapping.yaml")
LET Applied <= remap(config=Mapping)
SELECT Name FROM glob(globs="HKEY_LOCAL_MACHINE/System/*", accessor="registry") LIMIT 3
```

`remap()` applies to the current query scope. A persistent virtual client uses
the same YAML through `--remap`, so subsequent server collections use these
VQL-generated mappings. No import or up-front extraction is required.

## ZIP mapping performance

No up-front full extraction or permanent evidence working copy is required.
This does not mean zero temporary disk usage: the native ZIP accessor streams
sequential reads, but can decompress a member into a temporary backing file
when a parser seeks. An encrypted outer `data.zip` can therefore require
substantial temporary space for the inner archive, in addition to parsed members.

Large registry hives, database files and MFT parsing can be more expensive than
reading extracted files. Repeated collections and concurrent parsers can repeat
work or increase temporary disk, CPU and memory demand; do not assume a shared
cache eliminates it. Startup/resume also hashes the entire source ZIP for
identity validation. Archive entry inventory is held in memory.

Prefer local SSD storage, adequate temporary disk space, narrow artifact scopes
and conservative concurrency. For repeated broad analysis, compare representative
ZIP and extracted-folder runs before choosing an input. Record elapsed time,
CPU, peak memory and temporary disk use. The mapping smoke tests prove correctness,
not throughput or maximum supported archive size. No automatic extraction fallback
or performance threshold is configured.

## Validation

Validate with `.venv/bin/python -m pytest tests/test_zip_mapping.py tests/test_export_mapping.py`.
Detection and input-rejection tests (duplicate members, results-only ZIPs,
non-Windows paths) need no binary. Native mapping tests skip individually when
the binary is unavailable; AES fixture tests require `7z`.

# Autoruns GoldenDB maintenance

`autoruns-golden.csv` is the canonical reviewed source. `autoruns-golden.sqlite`
is the generated runtime database. A CSV edit does not update the database until
an explicit build is applied.

## Workflow

ADWS and ADFS service rules use separate fixed executable paths, the exact verified
Microsoft Windows signer, and argument-free launches. Scheduled-task rules cover
System32 CSCUI with `logon` and ShellConfigTask with `idle`, requiring the same
signer and exact DLL paths. MemoryDiagnostic accepts no argument, `event`, or `time`.

Fixed-path service rules cover WSL, Windows Identity Foundation v3.5 and Windows
Media Player Network Sharing with exact verified Microsoft signers and no launch
arguments. Their launch paths allow paired quotes or no quotes. Legacy Defender
UI Logon rules constrain the image paths and verified signers, but check only
the trailing ` -hide -runkey` switches in LaunchString; the preceding command is
unrestricted. The MSASCui image path permits one or two backslashes immediately
before its filename.

The OneDrive service rule accepts dotted numeric version directories with an
optional numeric underscore suffix, such as `26.150.0804.0011_1`, using
`[0-9]+(?:\.[0-9]+)+(?:_[0-9]+)?`. The executable names, installation root,
verified Microsoft signer and argument-free launch constraints still apply.

1. Review prospects from `autoruns_potential_golden.csv` or other candidate inputs.
   Check identity evidence, regex scope and overlap with existing rules.
2. Add, edit, consolidate or remove approved rules in `autoruns-golden.csv`.
   Keep `Category,ImagePath,LaunchString,Signer,Notes,LastModified` in that order.
   Use a CSV writer to preserve quoting and group categories alphabetically.
   Describe filtering scope in Notes; retain dates on untouched rows and set the
   current local date on edited rows. New prospects need only the first five fields.
   The generic System32 Drivers rule accepts a System32 launch path or a bare
   DLL launch string without backslashes. It requires a verified signer, of any
   publisher. ImagePath and LaunchString are matched independently; matching
   DLL names are not required.
   The Sysmon service rule requires the fixed `C:\Windows\sysmon64.exe` path,
   no launch arguments, and the exact verified Microsoft Corporation signer.
   A matching service entry does not validate Sysmon configuration or telemetry.
   The MpCmdRun scheduled-task rule also covers `Program Files\Microsoft Security
   Client`, using the existing verified Microsoft signer and executable-prefix
   launch matching. Arguments remain unrestricted.
   The Program Files Defender service rule also covers `MsMpEng.exe` and
   `NisSrv.exe` under `Microsoft Security Client`, retaining the verified
   Microsoft signer and argument-free launch constraints.
   The Defender definition-update driver rule covers only `MpKslDrv.sys` under
   `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}`,
   with a strict GUID shape and no launch arguments. The signer must contain
   `Microsoft` (case-insensitive); signature verification is not required. Microsoft Antimalware
   paths remain outside this rule.
3. Dry-run a complete build from the repository root:

   ```bash
   ./dfir autoruns regex-build \
     --db src/vraptor/resources/golden/autoruns-golden.sqlite \
     --input src/vraptor/resources/golden/autoruns-golden.csv \
     --backup-dir "$HOME/.local/share/dfir/autoruns-golden-backups" \
     --dry-run
   ```

4. Review the changed rules and compare filtering decisions against the same
   complete saved source before production publication. Synthetic regex tests
   alone are not a full-source regression. Apply the reviewed local build by
   running the command without `--dry-run`.
5. Version the reviewed CSV and generated database together in the same repository
   change. Record their SHA-256 hashes and the validation results in the change
   description. The database content hash identifies the generated version;
   schema version describes the storage format, not the rule revision.

The builder accepts five-column inputs or the six-column canonical CSV. Supplied
LastModified values are ignored during database generation: new or changed rows
receive the build date and unchanged identities/Notes retain their database date.
The CSV dates record source edits; database dates record ingestion. A no-op build
leaves the database byte-identical. Builds validate regexes, schema and round-trip
content, back up the previous database by SHA-256, and replace it atomically.
Neither building nor editing uploads the database or runs a hunt.

Use the canonical CSV and complete `regex-build` for repository maintenance.
`regex-import` remains available for standalone databases; it must not bypass this
CSV-first process for the repository database. Keep backups and unreviewed
prospects outside the repository.

Focused builder validation:

```bash
.venv/bin/python -m pytest tests/test_autoruns_csv_db.py -q
```

# Autoruns GoldenDB maintenance

`autoruns-golden.csv` is the canonical reviewed source. `autoruns-golden.sqlite`
is the generated runtime database. A CSV edit does not update the database until
an explicit build is applied.

## Workflow

1. Review prospects from `autoruns_potential_golden.csv` or other candidate inputs.
   Check identity evidence, regex scope and overlap with existing rules.
2. Add, edit, consolidate or remove approved rules in `autoruns-golden.csv`.
   Keep `Category,ImagePath,LaunchString,Signer,Notes,LastModified` in that order.
   Use a CSV writer to preserve quoting and group categories alphabetically.
   Record each rule's filtering scope in its Notes cell; the few semantics not yet
   there are under [rule notes outside the CSV](#rule-notes-outside-the-csv).
   Retain dates on untouched rows and set edited rows to the build date. New
   prospects need only the first five fields.
3. Dry-run a complete build from the repository root:

   ```bash
   ./vraptor autoruns regex-build \
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
After a build, the CSV dates must equal the database dates;
`tests/test_autoruns_csv_db.py` checks the packaged pair. A no-op build
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

## Rule notes outside the CSV

These rule semantics are not yet in the CSV Notes column:

- The generic System32 Drivers rule accepts a System32 launch path or a bare
  DLL launch string without backslashes. It requires a verified signer, of any
  publisher. ImagePath and LaunchString are matched independently; matching
  DLL names are not required.
- A matching Sysmon service entry does not validate Sysmon configuration or
  telemetry.
- Microsoft Antimalware paths remain outside the Defender definition-update
  `MpKslDrv.sys` driver rule.

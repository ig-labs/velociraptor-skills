"""Local-only format, finite-language and isolation regression coverage."""

import contextlib
import hashlib
import io
import json
import sqlite3
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest import mock

import re2

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import golden
from vraptor.autoruns import test_store as experiment


BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))


class AutorunsTestDatabaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source.sqlite"
        self.output = self.root / "test.sqlite"
        self.reference = self.root / "rmm.json"
        self.reference.write_text(json.dumps({"schema_version": 1, "executables": ["anydesk.exe"],
            "installation_paths": [], "tools": []}), encoding="utf-8")

    def source_database(self, rows=(), rules=()):
        connection = golden.connect_database(self.source)
        try:
            golden.initialize_database(connection, built_at="2026-01-01T00:00:00Z")
            for image, launch, signer in rows:
                record = autoruns.trusted_record(category="Services", image_path=image,
                    launch_string=launch, signer=signer)
                connection.execute("INSERT INTO autoruns_known_good "
                    "(hash_key,image_path,launch_string,signer,description) VALUES (?,?,?,?,?)",
                    (record["hash_key"], record["image_path"], record["launch_string"], record["signer"], ""))
            for image, launch in rules:
                connection.execute("INSERT INTO autoruns_regex_rules "
                    "(image_path_regex,launch_string_regex) VALUES (?,?)", (image, launch))
            connection.commit()
        finally:
            connection.close()

    def build(self, **kwargs):
        return experiment.build_database(self.source, self.output, rmm_reference=self.reference, **kwargs)

    @staticmethod
    def matches(loaded, image, launch, signer, mode="regex"):
        record = autoruns.trusted_record(category="DifferentCategory", image_path=image,
            launch_string=launch, signer=signer)
        payload = autoruns.trusted_key_serialized(image_path=image, launch_string=launch, signer=signer)
        exact = (record["hash_key"] in loaded["exact_hashes"] if mode == "hash" else
                 any(re2.compile(pattern).search(payload) for pattern in loaded["exact_patterns"]))
        regex = any(re2.compile(rule["ImagePathRegex"]).search(record["image_path"])
                    and re2.compile(rule["LaunchStringRegex"]).search(record["launch_string"])
                    for rule in loaded["regex_rules"])
        return bool(exact or regex)

    def test_build_readonly_private_isolated_and_normal_database_rejected(self):
        self.source_database([(r"C:\Vendor\App.exe", "app /service", "Vendor")])
        before = self.source.read_bytes()
        self.source.chmod(0o400)
        result = self.build()
        loaded = experiment.load_database(self.output)
        self.assertEqual(before, self.source.read_bytes())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(loaded["metadata"]["source_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(result["database_sha256"], golden.file_sha256(self.output))
        self.assertFalse(result["production_compatible"])
        with self.assertRaisesRegex(RuntimeError, "schema_version"):
            golden.validate_database(self.output, rmm_reference=self.reference)
        with self.assertRaisesRegex(RuntimeError, "incompatible metadata"):
            experiment.load_database(self.source)
        self.assertEqual(list(self.root.glob("*.building")), [])

    def test_exact_tuples_preserve_correlation_and_unicode_case(self):
        rows = [(r"C:\Vendor\Straße.dll", "x /a", "Acme"),
                (r"C:\Vendor\STRASSE.dll", "y /b", "Other"),
                (r"C:\Vendor\CAFÉ.dll", '<&>\u2028\u2029 "quoted"\n', "Σ"),
                (r"C:\Vendor\café.dll", "", "σ")]
        self.source_database(rows)
        self.build()
        loaded = experiment.load_database(self.output)
        for row in rows:
            for mode in ("hash", "regex"):
                with self.subTest(row=row, mode=mode):
                    self.assertTrue(self.matches(loaded, *row, mode=mode))
        negative = [(rows[0][0], rows[1][1], rows[0][2]),
                    (rows[0][0], rows[0][1], rows[1][2]),
                    (r"C:\Vendor\STRAẞE.dll", rows[0][1], rows[0][2]),
                    (rows[2][0], rows[2][1], "σ"),
                    (r"C:\Vendor\CAFÉ.dll", "", "σ"),
                    (rows[0][0] + "\n", rows[0][1], rows[0][2])]
        for row in negative:
            self.assertFalse(self.matches(loaded, *row))
            self.assertEqual(self.matches(loaded, *row), self.matches(loaded, *row, mode="hash"))

    def test_approved_regex_stays_signer_independent_without_path_checks(self):
        rows = [(r"C:\Users\Alice\App.exe", "app /service", "Vendor")]
        rules = [(r"c:\\vendor\\app\.exe", "app /service"),
                 (r"c:\\vendor\\other\.exe", r"run .*")]
        self.source_database(rows, rules)
        self.build()
        loaded = experiment.load_database(self.output)
        for mode in ("hash", "regex"):
            self.assertTrue(self.matches(loaded, *rows[0], mode=mode))
            self.assertTrue(self.matches(loaded, r"C:\Vendor\App.exe", "app /service", "Unrelated", mode=mode))
            self.assertTrue(self.matches(loaded, r"C:\Vendor\Other.exe", r"run C:\Users\Bob\payload.exe", "Vendor", mode=mode))

    def test_more_than_one_thousand_identities_are_complete(self):
        rows = [(fr"C:\Vendor\{index:04d}-{hashlib.sha256(str(index).encode()).hexdigest()}.dll",
                 "", "Vendor") for index in range(1101)]
        self.source_database(rows)
        self.build(max_pattern_bytes=220)
        loaded = experiment.load_database(self.output)
        self.assertEqual(len(loaded["exact_hashes"]), 1101)
        self.assertEqual(len(loaded["exact_patterns"]), 1101)
        self.assertTrue(all(len(pattern.encode()) <= 220 for pattern in loaded["exact_patterns"]))
        self.assertTrue(self.matches(loaded, *rows[-1]))
        self.assertFalse(self.matches(loaded, rows[-1][0], "", "Other"))

    def test_case_sensitive_patterns_are_deterministic_and_byte_bounded(self):
        values = ["abc<日本語>", "abc&Σ", "abc&σ", "abc\n", "abc\\"]
        first = experiment.exact_patterns(values, max_pattern_bytes=80)
        self.assertEqual(first, experiment.exact_patterns(reversed(values), max_pattern_bytes=80))
        self.assertTrue(all(pattern.startswith(r"(?-i)\A") and len(pattern.encode()) <= 80 for pattern in first))
        self.assertFalse(any(re2.compile(pattern).search("abc&ς") for pattern in first))
        with self.assertRaisesRegex(RuntimeError, "tuple exceeds"):
            experiment.exact_patterns(["日" * 100], max_pattern_bytes=64)
        with self.assertRaisesRegex(RuntimeError, "budget"):
            experiment.exact_patterns(values, max_pattern_bytes=experiment.MAX_PATTERN_BYTES + 1)

    def test_existing_destination_and_symlink_are_never_replaced(self):
        self.source_database()
        self.output.write_bytes(b"operator data")
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.build()
        self.assertEqual(self.output.read_bytes(), b"operator data")
        self.output.unlink()
        self.output.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.build()
        self.assertTrue(self.output.is_symlink())

    def test_destination_race_and_pending_source_wal_fail_closed(self):
        self.source_database()
        def raced_link(source, output):
            Path(output).write_bytes(b"another writer")
            raise FileExistsError(output)
        with mock.patch.object(experiment.os, "link", side_effect=raced_link):
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                self.build()
        self.assertEqual(self.output.read_bytes(), b"another writer")
        self.output.unlink()
        self.source.with_name(self.source.name + "-wal").write_bytes(b"pending")
        with self.assertRaisesRegex(RuntimeError, "pending WAL"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_modified_pattern_count_or_tuple_is_rejected(self):
        for mutation, message in [
            ("UPDATE test_exact_patterns SET pattern='(?i).*'", "patterns differ"),
            ("UPDATE metadata SET value='0' WHERE key='exact_identity_count'", "accounting mismatch"),
            ("UPDATE test_exact_identities SET hash_key='bad'", "tuple/hash verification"),
            ("UPDATE metadata SET value='' WHERE key='matching_policy'", "incompatible matching policy"),
        ]:
            with self.subTest(mutation=mutation):
                if self.source.exists():
                    self.source.unlink()
                self.output.unlink(missing_ok=True)
                self.source_database([(r"C:\Vendor\App.exe", "", "Vendor")])
                self.build()
                with contextlib.closing(sqlite3.connect(self.output)) as connection:
                    connection.execute(mutation)
                    connection.commit()
                with self.assertRaisesRegex(RuntimeError, message):
                    experiment.load_database(self.output)

    def test_finite_signer_rules_are_separate_and_retain_source_and_launch_form(self):
        rows = [(r"C:\Windows\System32\approved.dll", r"C:\Windows\System32\approved.dll", "(Verified) Microsoft Windows"),
                (r"C:\Windows\System32\empty.dll", "", "(Verified) Microsoft Windows"),
                (r"C:\Windows\System32\unverified.dll", "", "Microsoft Windows"),
                (r"C:\Windows\System32\arguments.dll", "arguments /bad", "(Verified) Microsoft Windows"),
                (r"C:\Windows\System32\other.dll", "", "(Verified) Microsoft Corporation")]
        self.source_database(rows)
        self.build()
        loaded = experiment.load_database(self.output)
        self.assertEqual(len(loaded["signer_rules"]), 2)
        self.assertEqual(loaded["metadata"]["signer_source_identity_count"], "2")
        self.assertEqual(loaded["metadata"]["signer_rules_status"], "runtime_artifact_verification_required")
        expected = {"empty": "empty.dll", "same_image": "approved.dll"}
        for rule in loaded["signer_rules"]:
            self.assertEqual(rule["Signer"], "(verified) microsoft windows")
            self.assertEqual(len(rule["SourceExactHashes"]), 1)
            compiled = re2.compile(rule["ImagePathRegex"])
            for directory in ("system32", "syswow64"):
                self.assertIsNotNone(compiled.search(fr"c:\windows\{directory}\{expected[rule['LaunchMode']]}"))
            self.assertIsNone(compiled.search(r"c:\windows\system32\invented.dll"))
            self.assertIsNone(compiled.search(r"c:\users\user\approved.dll"))
        self.assertFalse(self.matches(loaded, r"C:\Windows\SysWOW64\empty.dll", "", "(Verified) Microsoft Windows"))
        with contextlib.closing(sqlite3.connect(self.output)) as connection:
            connection.execute("UPDATE test_signer_rules SET rule_json='{}'")
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "signer rules differ"):
            experiment.load_database(self.output)

    def test_cli_build_requires_explicit_paths_and_does_not_resolve_live_context(self):
        self.source_database()
        with mock.patch.object(golden, "apply_engagement_context", side_effect=AssertionError("live")):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(golden.main(["test-build", "--source-db", str(self.source),
                    "--output", str(self.output), "--rmm-reference", str(self.reference)]), 0)
        self.assertFalse(json.loads(output.getvalue())["production_compatible"])

    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor unavailable")
    def test_shared_serialized_tuple_matches_vql_bytes(self):
        values = ["日本語", "Σσς", '<&>\u2028\u2029 "quoted"', "\n\t\x00", r"C:\Users\Alice\CAFÉ.dll"]
        rows = [{"Image Path": value, "Launch String": value, "Signer": value} for value in values]
        query = "SELECT " + autoruns.trusted_key_serialized_vql() + " AS Payload FROM foreach(row=parse_json_array(data=Rows))"
        completed = subprocess.run([str(BINARY), "query", "--format=jsonl", "--env",
            "Rows=" + json.dumps(rows), query], text=True, capture_output=True, check=True, timeout=30)
        actual = [json.loads(line)["Payload"] for line in completed.stdout.splitlines()]
        self.assertEqual(actual, [autoruns.trusted_key_serialized(image_path=value, launch_string=value,
            signer=value) for value in values])


if __name__ == "__main__":
    unittest.main()

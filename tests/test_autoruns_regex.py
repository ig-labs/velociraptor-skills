"""Combined GoldenDB filtering, storage lifecycle and native VQL parity."""

import base64
import contextlib
import csv
import gzip
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest import mock

from vraptor.autoruns import golden
from vraptor.autoruns import regex as autoruns_regex
from vraptor.analyze import host as collection_analysis
from vraptor.hunt import live


BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))
RULE = {
    "image_path_regex": r"c:\\vendor\\[0-9]+(?:\.[0-9]+){3}\\app\.exe",
    "launch_string_regex": r'(?:"c:\\vendor\\[0-9]+(?:\.[0-9]+){3}\\app\.exe"|c:\\vendor\\[0-9]+(?:\.[0-9]+){3}\\app\.exe)(?: /quiet)?',
    "description": "Vendor service with a four-part version directory",
}
OTHER_RULE = {
    "image_path_regex": r"c:\\other\\app\.exe",
    "launch_string_regex": "other /service", "description": "Other service",
}
EXACT = {"Category": "Services", "Image Path": r"C:\Vendor\Fixed.exe",
         "Launch String": "fixed /service", "Signer": "Vendor"}


class AutorunsRegexTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "golden.sqlite"
        golden.promote_records(self.database, [EXACT], regex_rows=[RULE, OTHER_RULE])

    def rows(self):
        path = r"C:\Vendor\123.4.5.6\APP.EXE"
        version = {"Category": "Services", "Image Path": path,
                   "Launch String": f'"{path}" /quiet', "Signer": "Different metadata"}
        return [
            {**EXACT, "id": "hash"},
            {**version, "id": "version"},
            {**version, "Launch String": path, "id": "unquoted"},
            {**version, "Category": "Drivers", "id": "other-category"},
            {**version, "Category": "", "id": "blank-category"},
            {key: value for key, value in {**version, "id": "missing-category"}.items() if key != "Category"},
            {**EXACT, "Category": "Drivers", "id": "exact-other-category"},
            {key: value for key, value in {**EXACT, "id": "exact-missing-category"}.items() if key != "Category"},
            {**version, "Image Path": r"C:\Temp\APP.EXE", "id": "path-miss"},
            {**version, "Launch String": f'"{path}" /quiet /extra', "id": "extra-argument"},
            {**version, "Launch String": f'"{path}" /quiet\n', "id": "newline"},
            {**version, "Launch String": "other /service", "id": "cross-rule"},
            {**version, "Image Path": r"C:\Vendor\1.2\app.exe", "id": "wrong-version"},
            {**EXACT, "Signer": "Changed signer", "id": "hash-signer-miss"},
        ]

    def expected_ids(self):
        return [row["id"] for row in self.rows()[8:]]

    def run_vql(self, query, env=None):
        command = [str(BINARY), "query", "--format=jsonl"]
        for name, value in (env or {}).items():
            command += ["--env", f"{name}={value}"]
        result = subprocess.run(command + [query], capture_output=True, text=True,
                                timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("ERROR", result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()], result.stderr

    def generated_query(self, *, preserve_priority=False):
        payload = golden.live_lookup_payload(self.database)
        env = {"RowsJSON": json.dumps(self.rows())}
        where = live.autoruns_golden_where(
            golden.DEFAULT_AUTORUNS_ARTIFACT,
            configuration={"enabled": True, "rmm_regex": "nomatch", **payload},
            env=env, preserve_priority=preserve_priority,
        )
        return (live.autoruns_golden_query_preamble(where)
                + "\nSELECT * FROM foreach(row=parse_json_array(data=RowsJSON)) WHERE " + where), env

    def test_local_filters_agree_and_do_not_modify_database(self):
        before = self.database.read_bytes()
        output = self.root / "residual.csv"
        report = golden.filter_autoruns_rows(self.database, self.rows(), output=output)
        with output.open() as handle:
            self.assertEqual([row["id"] for row in csv.DictReader(handle)], self.expected_ids())
        rows, counts = collection_analysis.reduce_autoruns_with_golden_db(self.rows(), database=self.database)
        self.assertEqual([row["id"] for row in rows], self.expected_ids())
        self.assertEqual(report["known_good_filtered_rows"], 8)
        self.assertEqual(counts["known_good_filtered_rows"], 8)
        self.assertEqual(self.database.read_bytes(), before)
        result = golden.lookup_identity(self.database, category="services", signer="",
            image_path=self.rows()[1]["Image Path"], launch_string=self.rows()[1]["Launch String"])
        self.assertTrue(result["regex_match"])
        self.assertTrue(result["filter_match"])
        self.assertFalse(result["hash_match"])

    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor unavailable")
    def test_native_single_pass_any_matches_local(self):
        query, env = self.generated_query()
        self.assertIn("any(items=", query)
        self.assertEqual(query.count("data=RowsJSON"), 1)
        self.assertNotIn("sqlite(", query)
        rows, stderr = self.run_vql(query, env)
        self.assertFalse(stderr, stderr)
        self.assertEqual([row["id"] for row in rows], self.expected_ids())

    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor unavailable")
    def test_hash_hit_skips_any_and_any_stops_at_first_match(self):
        query, env = self.generated_query()
        query = query.replace('rule=>GoldenImage',
            "rule=>set(item=RegexVisits, field='Count', value=RegexVisits.Count+1) AND GoldenImage")
        query = 'LET RegexVisits <= dict(Count=0)\n' + query
        query += '\nSELECT RegexVisits.Count AS Visits FROM scope()'
        env["RowsJSON"] = json.dumps([self.rows()[0]])
        rows, stderr = self.run_vql(query, env)
        self.assertEqual(rows, [{"Visits": 0}])
        env["RowsJSON"] = json.dumps([{
            "Category": "Services", "Image Path": r"C:\Other\App.exe",
            "Launch String": "other /service",
        }])
        rows, stderr = self.run_vql(query, env)
        self.assertEqual(rows, [{"Visits": 1}])

    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor unavailable")
    def test_priority_override_is_preserved(self):
        query, env = self.generated_query(preserve_priority=True)
        rows, _ = self.run_vql(query, env)
        self.assertEqual([row["id"] for row in rows], [row["id"] for row in self.rows()])


    def test_payload_is_compact_deterministic_and_covers_both_indexes(self):
        first = golden.live_lookup_payload(self.database)
        second = golden.live_lookup_payload(self.database)
        self.assertEqual(first, second)
        self.assertEqual(first["regex_rule_count"], 2)
        rules = json.loads(gzip.decompress(base64.b64decode(first["regex_lookup_gzip_base64"])))
        self.assertEqual(len(rules), 2)
        self.assertEqual(set(rules[0]), {"ImagePathRegex", "LaunchStringRegex"})
        self.assertNotIn("category", json.dumps(rules))
        self.assertNotIn("description", json.dumps(rules))
        with mock.patch.object(golden, "MAX_LIVE_LOOKUP_BASE64_BYTES", first["lookup_base64_bytes"] - 1):
            with self.assertRaisesRegex(RuntimeError, "live lookup payload"):
                golden.live_lookup_payload(self.database)

    def test_invalid_patterns_rejected_before_database_mutation(self):
        before = self.database.read_bytes()
        for pattern in ("", "[", "(?=abc)abc", r"(abc)\1", r"\C", "a)|(.+"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(RuntimeError):
                    golden.promote_records(self.database, [], regex_rows=[{**RULE, "image_path_regex": pattern}])
                self.assertEqual(self.database.read_bytes(), before)

    def test_empty_fields_require_explicit_pattern(self):
        rule = {**RULE, "image_path_regex": "^$", "launch_string_regex": "app"}
        index = autoruns_regex.RegexIndex([rule])
        self.assertTrue(index.matches({"category": "services", "image_path": "", "launch_string": "APP"}))
        self.assertFalse(index.matches({"category": "services", "image_path": "", "launch_string": "APP\n"}))

    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor unavailable")
    def test_normalized_paths_empty_fields_and_unicode_regex_parity(self):
        extra = [
            {**RULE, "image_path_regex": r"c:\\windows\\café\.dll", "launch_string_regex": "^$"},
            {**RULE, "image_path_regex": "^$", "launch_string_regex": r"task \$\(arg0\)"},
        ]
        golden.promote_records(self.database, [], regex_rows=extra)
        sources = [
            {"Category": "Services", "Image Path": r"%SystemRoot%\CAFÉ.dll", "Launch String": "", "Signer": ""},
            {"Category": "Services", "Image Path": "", "Launch String": "task $(Arg0)", "Signer": ""},
            {"Category": "Services", "Image Path": "", "Launch String": "task arbitrary", "Signer": ""},
        ]
        local, _ = collection_analysis.reduce_autoruns_with_golden_db(sources, database=self.database)
        query, env = self.generated_query()
        env["RowsJSON"] = json.dumps(sources)
        remote, _ = self.run_vql(query, env)
        self.assertEqual([r["Launch String"] for r in local], ["task arbitrary"])
        self.assertEqual([r["Launch String"] for r in remote], ["task arbitrary"])

    def test_rule_change_updates_combined_lookup_digest(self):
        first = golden.live_lookup_payload(self.database)
        golden.promote_records(self.database, [], regex_rows=[{**RULE, "launch_string_regex": "approved /service"}])
        second = golden.live_lookup_payload(self.database)
        self.assertEqual(first["lookup_gzip_base64"], second["lookup_gzip_base64"])
        self.assertNotEqual(first["lookup_payload_sha256"], second["lookup_payload_sha256"])

    def test_category_metadata_does_not_create_new_regex_rule_or_lookup_payload(self):
        first = golden.live_lookup_payload(self.database)
        golden.promote_records(self.database, [], regex_rows=[{**RULE, "category": "logon"}])
        second = golden.live_lookup_payload(self.database)
        self.assertEqual(second["regex_rule_count"], 2)
        self.assertEqual(first["lookup_payload_sha256"], second["lookup_payload_sha256"])
        with contextlib.closing(golden.connect_database(self.database, readonly=True)) as connection:
            self.assertTrue(all("category" not in rule for rule in golden.regex_records(connection)))

    def test_offline_duplicate_pair_rejected_across_different_or_missing_categories(self):
        source = self.root / "duplicates.json"
        before = self.database.read_bytes()
        args = golden.parser().parse_args([
            "import", "--db", str(self.database), "--regex-input", str(source),
        ])
        for second in (RULE, {**RULE, "category": "drivers"}, {**RULE, "category": ""}):
            with self.subTest(second=second):
                source.write_text(json.dumps([{**RULE, "category": "services"}, second]))
                with self.assertRaisesRegex(RuntimeError, "duplicate rule"):
                    golden.import_offline_rules(args)
                self.assertEqual(self.database.read_bytes(), before)

    def test_publication_preserves_rule_table(self):
        from tests.test_autoruns_golden import FakeInventoryApi
        api = FakeInventoryApi()
        golden.publish_database(api, self.database, tool_name=golden.DEFAULT_TOOL_NAME,
                                tool_version="regex-test")
        copy = self.root / "published.sqlite"
        copy.write_bytes(api.uploaded_bytes)
        self.assertEqual(golden.validate_database(copy)["regex_rule_count"], 2)
        self.assertEqual(copy.read_bytes(), self.database.read_bytes())

    def test_signer_reference_roundtrip_does_not_affect_matching(self):
        updated = {**RULE, "signer_regex": r"\(verified\) vendor"}
        golden.promote_records(self.database, [], regex_rows=[updated])
        with contextlib.closing(golden.connect_database(self.database, readonly=True)) as c:
            rules = golden.regex_records(c)
        self.assertIn(updated["signer_regex"], [r["signer_regex"] for r in rules])
        index = autoruns_regex.RegexIndex([updated])
        for signer in ("", "(not verified) vendor", "unexpected signer"):
            self.assertTrue(index.matches(dict(category="services", image_path=r"c:\vendor\1.2.3.4\app.exe", launch_string=r"c:\vendor\1.2.3.4\app.exe", signer=signer)))

    def test_signer_only_delta_applies_and_replays_without_changes(self):
        source = self.root / "signers.json"
        source.write_text(json.dumps([{**RULE, "signer_regex": r"\(verified\) vendor"}]))
        delta = self.root / "signers.sqlite"
        golden.build_database(delta, [], regex_inputs=[source], baseline_databases=[self.database])
        result = golden.apply_delta_database(self.database, delta)
        self.assertEqual(result["changes"]["improved_regex_signer_reference_count"], 1)
        self.assertTrue(result["installed"])
        replay = golden.database_change_summary(self.database, delta)
        self.assertEqual(replay["effective_change_count"], 0)
        with self.assertRaises(RuntimeError):
            golden.normalized_regex_record({**RULE, "signer_regex": "("})

    def test_schema_four_reads_without_mutation_and_migrates_on_merge(self):
        from tests.test_autoruns_golden import AutorunsCategoryFreeMigrationTest
        self.database = self.root / "legacy4.sqlite"
        AutorunsCategoryFreeMigrationTest().write_legacy_database(self.database, "4")
        before = self.database.read_bytes()
        with contextlib.closing(golden.connect_database(self.database, readonly=True)) as c:
            self.assertTrue(all(r["signer_regex"] == "" for r in golden.regex_records(c)))
        self.assertEqual(before, self.database.read_bytes())
        merged = self.root / "v6.sqlite"
        golden.merge_databases(merged, [self.database])
        self.assertEqual(golden.validate_database(merged)["metadata"]["schema_version"], "6")

    def test_legacy_schema_has_no_regex_overhead_and_is_not_migrated_on_read(self):
        from tests.test_autoruns_golden import AutorunsCategoryFreeMigrationTest
        self.database = self.root / "legacy3.sqlite"
        AutorunsCategoryFreeMigrationTest().write_legacy_database(self.database, "3")
        before = self.database.read_bytes()
        payload = golden.live_lookup_payload(self.database)
        self.assertEqual(payload["regex_rule_count"], 0)
        self.assertEqual(payload["regex_lookup_gzip_base64"], "")
        query, _ = self.generated_query()
        self.assertNotIn("AutorunsGoldenRegex", query)
        self.assertEqual(self.database.read_bytes(), before)
        merged = self.root / "merged.sqlite"
        golden.merge_databases(merged, [self.database])
        self.assertEqual(golden.validate_database(merged)["metadata"]["schema_version"], "6")

    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor unavailable")
    def test_legacy_live_matching_ignore_categories_without_migration(self):
        from tests.test_autoruns_golden import AutorunsCategoryFreeMigrationTest
        for version in ("3", "4", "5"):
            with self.subTest(schema=version):
                self.database = self.root / f"legacy-vql-{version}.sqlite"
                record = AutorunsCategoryFreeMigrationTest().write_legacy_database(self.database, version)
                before = self.database.read_bytes()
                exact = {"Entry Location": "", "Entry": "exact", "SHA-256": "",
                         "Fqdn": "synthetic", "ClientId": "C.synthetic",
                         "Image Path": record["image_path"], "Launch String": record["launch_string"],
                         "Signer": record["signer"]}
                sources = [exact, {**exact, "Entry": "regex", "Category": "Other", "Signer": "Other"}]
                expected = ["regex"] if version == "3" else []
                query, env = self.generated_query()
                env["RowsJSON"] = json.dumps(sources)
                rows, stderr = self.run_vql(query, env)
                self.assertFalse(stderr, stderr)
                self.assertEqual([row["Entry"] for row in rows], expected)
                self.assertEqual(self.database.read_bytes(), before)

    def test_regex_build_delta_merge_apply_and_idempotence(self):
        rules = self.root / "rules.json"
        new_rule = {**OTHER_RULE, "launch_string_regex": "approved /service"}
        better = {**RULE, "description": RULE["description"] + " with approved arguments only"}
        rules.write_text(json.dumps([RULE, better, new_rule]))
        delta = self.root / "delta.sqlite"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(golden.main(["build", "--regex-input", str(rules),
                "--baseline-db", str(self.database), "--output", str(delta)]), 0)
        built = json.loads(output.getvalue())
        self.assertEqual(built["validation"]["regex_rule_count"], 2)
        preview = golden.apply_delta_database(self.database, delta, dry_run=True)
        self.assertEqual(preview["changes"]["new_regex_rule_count"], 1)
        self.assertEqual(preview["changes"]["improved_regex_description_count"], 1)
        self.assertEqual(preview["changes"]["effective_change_count"], 2)
        result = golden.apply_delta_database(self.database, delta)
        self.assertEqual(result["after"]["regex_rule_count"], 3)
        rebuilt = self.root / "empty-delta.sqlite"
        golden.build_database(rebuilt, [], regex_inputs=[rules], baseline_databases=[self.database])
        self.assertEqual(golden.validate_database(rebuilt)["regex_rule_count"], 0)
        self.assertEqual(golden.database_change_summary(self.database, rebuilt)["effective_change_count"], 0)


class ReviewedRuleAuthorityTest(unittest.TestCase):
    """Approved rules remain authoritative after import, in every matcher."""

    run_vql = AutorunsRegexTest.run_vql

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reference = self.root / "rmm.json"
        self.reference.write_text(json.dumps({
            "executables": ["remoteagent.exe", "assist-?.exe", "screen-*.exe"],
            "installation_paths": [r"c:\program files\remote suite\*"],
        }))
        self.classifier = golden.RmmClassifier(self.reference)
        self.broad = {**RULE, "image_path_regex": "(?s).*", "launch_string_regex": "(?s).*"}
        self.index = autoruns_regex.RegexIndex([self.broad], classifier=self.classifier)

    def sources(self):
        paths = [
            r"C:\Program Files\Vendor\remoteagent.exe",
            r"C:\Vendor\assist-X.exe", r"C:\Vendor\screen-2026.exe",
            r"C:\Program Files\Remote Suite\renamed.exe",
            r"File not found: C:\Vendor\gone.exe", "\tFILE NOT FOUND: gone.exe",
            "\u00a0File not found: gone.exe", "\u2003File not found: gone.exe",
            "\x1cFile not found: gone.exe", "c:\\vendor\\remoteagent.exe\u00a0/quiet",
            r"C:\Users\Alice\app.exe", r"D:\Users\Alice\app.exe",
            r"C:\Documents and Settings\Alice\app.exe",
            r"%LOCALAPPDATA%\app.exe", r"%APPDATA%\app.exe", r"%USERPROFILE%\app.exe",
            r"%TEMP%\app.exe", r"%TMP%\app.exe", r"%PUBLIC%\app.exe",
            r"C:\Temp\app.exe", r"C:\Windows\Temp\app.exe", r"D:/tmp/app.exe",
            r"C:\ProgramData\Vendor\app.exe", r"%ProgramData%\Vendor\app.exe",
            r"C:\Staging\Downloads\app.exe", r"C:\$Recycle.Bin\app.exe",
            r"C:\Vendor\..\payload.exe", r"..\payload.exe",
            r"\\server\share\app.exe", "//server/share/app.exe",
        ]
        sources = []
        for number, path in enumerate(paths):
            sources.extend([
                {"id": f"image-{number}", "Category": "Services", "Image Path": path,
                 "Launch String": "service /start", "Signer": "(Verified) Vendor"},
                {"id": f"launch-{number}", "Category": "Services",
                 "Image Path": r"C:\Windows\System32\runner.exe",
                 "Launch String": path, "Signer": "(Verified) Vendor"},
            ])
        sources.extend([
            {"id": "benign", "Category": "Services", "Image Path": r"C:\Vendor\app.exe",
             "Launch String": '"C:\\Vendor\\app.exe" /quiet', "Signer": ""},
            {"id": "benign-empty", "Category": "Services", "Image Path": "",
             "Launch String": "task $(Arg0)", "Signer": ""},
            {"id": "benign-other-category", "Category": "Drivers", "Image Path": r"C:\Vendor\app.exe",
             "Launch String": "service /start", "Signer": ""},
        ])
        return sources

    @staticmethod
    def encode(value):
        return base64.b64encode(gzip.compress(json.dumps(value).encode())).decode()

    def live_query(self, sources, exact_keys=()):
        env = {"RowsJSON": json.dumps(sources)}
        config = {"enabled": True, "lookup_gzip_base64": self.encode(list(exact_keys)),
                  "regex_rule_count": 1, "rmm_reference": str(self.reference),
                  "regex_lookup_gzip_base64": self.encode([{
                      "ImagePathRegex": autoruns_regex.full_pattern(self.broad["image_path_regex"]),
                      "LaunchStringRegex": autoruns_regex.full_pattern(self.broad["launch_string_regex"]),
                  }])}
        where = live.autoruns_golden_where(golden.DEFAULT_AUTORUNS_ARTIFACT,
                                         configuration=config, env=env)
        return (live.autoruns_golden_query_preamble(where)
                + "\nSELECT * FROM foreach(row=parse_json_array(data=RowsJSON)) WHERE " + where), env

    def test_reviewed_rules_match_regardless_of_path_or_rmm_classification(self):
        for source in self.sources():
            with self.subTest(source=source["id"]):
                self.assertTrue(self.index.matches(golden.normalized_record(source)))

    def test_matching_does_not_load_a_secondary_policy(self):
        with mock.patch.object(golden, "RmmClassifier", side_effect=AssertionError("unexpected policy load")):
            index = autoruns_regex.RegexIndex([self.broad])
            self.assertTrue(index.matches(dict(image_path=r"c:\users\user\anydesk.exe", launch_string="")))
            self.assertFalse(autoruns_regex.RegexIndex().matches(dict(category="services")))
            self.assertFalse(autoruns_regex.RegexIndex([RULE]).matches(dict(image_path="unmatched", launch_string="")))

    def test_reviewed_import_keeps_syntax_and_duplicate_validation(self):
        source = self.root / "rules.json"
        source.write_text(json.dumps([self.broad]))
        with mock.patch.object(golden, "RmmClassifier", side_effect=AssertionError("unexpected policy load")):
            self.assertEqual(len(golden._validated_offline_regex_rows([source])), 1)
        for pattern in ("", "[", r"\C", "a(?=b)"):
            source.write_text(json.dumps([{**RULE, "launch_string_regex": pattern}]))
            with self.assertRaises(RuntimeError):
                golden._validated_offline_regex_rows([source])
        source.write_text(json.dumps([self.broad, self.broad]))
        with self.assertRaisesRegex(RuntimeError, "duplicate rule"):
            golden._validated_offline_regex_rows([source])

    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor unavailable")
    def test_native_vql_uses_approved_rules_without_a_policy_binding(self):
        query, env = self.live_query(self.sources())
        self.assertNotIn("Veto", query)
        self.assertNotIn("AutorunsGoldenRegexVeto", env)
        rows, stderr = self.run_vql(query, env)
        self.assertFalse(stderr, stderr)
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()

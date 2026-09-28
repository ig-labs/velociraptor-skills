"""Offline native VQL and database contracts for category-aware field rules."""

import contextlib
import hashlib
import io
import json
import sqlite3
import stat
import unittest
from unittest import mock

import re2

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import testing as autoruns_test
from vraptor.autoruns import golden
from vraptor.autoruns import test_store as database
from vraptor.analyze import source as review_source
from vraptor.autoruns.test_groups import grouped_patterns
from tests import test_autoruns_test as runtime_fixture
from tests import test_autoruns_test_db as database_fixture


def grouped_config(identities, categories=None):
    """Build the same finite source tuples used by the database, in memory."""
    exacts = sorted((autoruns.trusted_key(**identity),
                     autoruns.trusted_key_serialized(**identity))
                    for identity in identities)
    cfg = runtime_fixture.config()
    cfg["exact_hashes"] = [key for key, _ in exacts]
    cfg["exact_groups"] = grouped_patterns(exacts, categories or {})
    cfg["exact_patterns"] = [group["IdentityRegex"] for group in cfg["exact_groups"]]
    return cfg


def endpoint(identity, **fields):
    return {"Image Path": identity["image_path"],
            "Launch String": identity["launch_string"],
            "Signer": identity["signer"], **fields}


@unittest.skipUnless(runtime_fixture.BINARY.exists(), "Bundled Velociraptor unavailable")
class AutorunsGroupedNativeTest(unittest.TestCase):
    execute = runtime_fixture.AutorunsTestNativeTest.execute

    def test_observed_categories_restrict_grouped_mode_but_not_equivalent_mode(self):
        identity = dict(image_path=r"C:\Windows\System32\service.dll",
                        launch_string="service /start", signer="Vendor")
        categories = {autoruns.trusted_key(**identity): ["Services", "Scheduled Tasks"]}
        cfg = grouped_config([identity], categories)
        rows = [endpoint(identity, Category=value) for value in
                ("Services", "SERVICES", "Scheduled Tasks", "Logon", "", None)]
        rows.append(endpoint(identity))
        rows.extend(endpoint(identity, Category="Services", Description=description)
                    for description in ("Original description", "Entirely different description"))
        result = self.execute(rows, cfg, "regex-grouped")
        self.assertEqual(result["SourceRows"], 9)
        self.assertEqual(result["MatchedRows"], 5)
        for mode in ("hash-baseline", "regex-equivalent"):
            with self.subTest(mode=mode):
                self.assertEqual(self.execute(rows, cfg, mode)["MatchedRows"], 9)

    def test_unknown_category_matches_empty_null_missing_and_any_label(self):
        identity = dict(image_path=r"C:\Windows\System32\uncategorized.dll",
                        launch_string="", signer="Vendor")
        cfg = grouped_config([identity])
        self.assertEqual(cfg["exact_groups"][0]["Rules"][0]["CategoryRegex"], ".*")
        rows = [endpoint(identity, Category=value) for value in
                ("Services", "", None, "Unseen label", "\n")]
        rows.append(endpoint(identity))
        self.assertEqual(self.execute(rows, cfg, "regex-grouped")["MatchedRows"], 6)

    def test_fields_preserve_tuple_correlation_and_legacy_paired_rule_semantics(self):
        first = dict(image_path=r"C:\Windows\System32\first.dll",
                     launch_string="service /first", signer="Vendor One")
        second = dict(image_path=r"C:\Windows\System32\second.dll",
                      launch_string="service /second", signer="Vendor Two")
        categories = {autoruns.trusted_key(**item): ["Services"] for item in (first, second)}
        cfg = grouped_config([first, second], categories)
        rows = [endpoint(first, Category="Services"), endpoint(second, Category="Services")]
        rows.extend(endpoint(item, Category="Services") for item in (
            {**first, "launch_string": second["launch_string"]},
            {**first, "signer": second["signer"]},
            {**first, "image_path": second["image_path"]},
            {**first, "image_path": first["image_path"] + ".unexpected"},
        ))
        rows.extend({"Image Path": r"C:\Vendor\known.dll", "Launch String": "",
                     "Signer": signer, "Category": category}
                    for signer, category in (("Unknown signer", "Logon"), (None, None)))
        result = self.execute(rows, cfg, "regex-grouped")
        self.assertEqual(result["SourceRows"], 8)
        self.assertEqual(result["MatchedRows"], 4)

    def test_more_than_1000_scalar_group_rules_evaluate_the_last_entry(self):
        identity = dict(image_path=r"C:\Windows\System32\last.dll", launch_string="", signer="Vendor")
        cfg = grouped_config([identity], {autoruns.trusted_key(**identity): ["Services"]})
        last = cfg["exact_groups"][0]
        cfg["exact_groups"] = [
            {**last, "IdentityRegex": rf"(?-i)\Anever{index}\z"}
            for index in range(1201)
        ] + [last]
        _, _, counts = autoruns_test.build_query(
            cfg, mode="regex-grouped", source=review_source.hunt_source("H.test", "IG.Windows.Sysinternals.Autoruns"))
        self.assertEqual(counts["Exact"], 1202)
        rows = [endpoint(identity, Category="Services"), endpoint(identity, Category="Logon")]
        result = self.execute(rows, cfg, "regex-grouped")
        self.assertEqual(result["SourceRows"], 2)
        self.assertEqual(result["MatchedRows"], 1)

    def test_compiled_groups_match_straightforward_four_field_reference(self):
        first = dict(image_path=r"C:\Windows\System32\first.dll", launch_string="service /first", signer="Vendor One")
        second = dict(image_path=r"C:\Windows\System32\second.dll", launch_string="service /second", signer="Vendor Two")
        unicode_identity = dict(image_path="C:\\Users\\Alice\\CAFÉ.dll", launch_string="quoted\n<&>\u2028", signer="Σ Vendor")
        unknown = dict(image_path=r"C:\Vendor\uncategorized.dll", launch_string="", signer="Vendor")
        categories = {autoruns.trusted_key(**item): ["Services", "Scheduled Tasks"] for item in (first, second)}
        categories[autoruns.trusted_key(**unicode_identity)] = ["É Services"]
        cfg = grouped_config([first, second, unicode_identity, unknown], categories)
        cfg["regex_rules"] = []
        rows = [endpoint(first, Category="Services"), endpoint(first, Category="SCHEDULED TASKS"),
                endpoint(second, Category="Services"),
                endpoint({**unicode_identity, "image_path": "C:\\Users\\Bob\\CAFÉ.dll"}, Category="É Services")]
        rows.extend(endpoint(unknown, Category=category) for category in (None, "", "Unseen", "\n"))
        rows.append(endpoint(unknown))
        rows.extend([
            endpoint(first, Category="Logon"),
            endpoint(unicode_identity, Category="é Services"),
            endpoint({**unicode_identity, "image_path": "C:\\Users\\Bob\\café.dll"}, Category="É Services"),
            endpoint({**unicode_identity, "signer": "σ Vendor"}, Category="É Services"),
            endpoint({**first, "image_path": second["image_path"]}, Category="Services"),
            endpoint({**first, "launch_string": second["launch_string"]}, Category="Services"),
            endpoint({**first, "signer": second["signer"]}, Category="Services"),
        ])
        fields = (("CategoryRegex", "category"), ("ImagePathRegex", "image_path"),
                  ("LaunchStringRegex", "launch_string"), ("SignerRegex", "signer"))
        rules = [rule for group in cfg["exact_groups"] for rule in group["Rules"]]
        compiled = [{field: re2.compile(rule[field]) for field, _ in fields} for rule in rules]
        matches = []
        for row in rows:
            normalized = autoruns.trusted_record(category=row.get("Category"), image_path=row["Image Path"],
                                                launch_string=row["Launch String"], signer=row["Signer"])
            matches.append(any(all((field == "CategoryRegex" and rule[field] == ".*")
                                   or regex[field].search(normalized[value]) is not None
                                   for field, value in fields)
                               for rule, regex in zip(rules, compiled)))
        self.assertEqual(sum(matches), 9)
        _, _, counts = autoruns_test.build_query(
            cfg, mode="regex-grouped", source=review_source.hunt_source("H.test", "IG.Windows.Sysinternals.Autoruns"))
        self.assertEqual(counts["Exact"], len(cfg["exact_groups"]))
        self.assertLess(counts["Exact"], len(rules))
        # Separate positive and negative streams prevent opposing mistakes from
        # hiding behind one aggregate matched-row count.
        for expected in (True, False):
            selected = [row for row, matched in zip(rows, matches) if matched is expected]
            with self.subTest(expected_match=expected):
                result = self.execute(selected, cfg, "regex-grouped")
                self.assertEqual(result["SourceRows"], len(selected))
                self.assertEqual(result["MatchedRows"], len(selected) if expected else 0)

    def test_grouped_fields_preserve_unicode_case_and_exact_veto_bypass(self):
        identity = dict(image_path="C:\\Users\\Alice\\CAFÉ.dll",
                        launch_string='<&>\u2028 "quoted"\n', signer="Σ Vendor")
        cfg = grouped_config([identity], {autoruns.trusted_key(**identity): ["É Services"]})
        rows = [endpoint(identity, Category="É SERVICES"),
                endpoint({**identity, "image_path": "C:\\Users\\Bob\\CAFÉ.dll"}, Category="É Services"),
                endpoint({**identity, "image_path": "C:\\Users\\Bob\\café.dll"}, Category="É Services"),
                endpoint({**identity, "signer": "σ Vendor"}, Category="É Services"),
                endpoint(identity, Category="é Services")]
        result = self.execute(rows, cfg, "regex-grouped")
        self.assertEqual(result["SourceRows"], 5)
        self.assertEqual(result["MatchedRows"], 2)


class AutorunsGroupedDatabaseTest(unittest.TestCase):
    # Reuse fixture helpers without inheriting and rerunning baseline tests.
    setUp = database_fixture.AutorunsTestDatabaseTest.setUp
    source_database = database_fixture.AutorunsTestDatabaseTest.source_database
    build = database_fixture.AutorunsTestDatabaseTest.build

    def category_file(self, categories, *, source_hash=None):
        path = self.root / "categories.json"
        path.write_text(json.dumps({
            "schema_version": "autoruns_test_categories_v1",
            "source_database_sha256": source_hash or hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "identity_categories": categories,
        }), encoding="utf-8")
        return path

    def legacy_database(self, entries, filename="legacy.sqlite"):
        path = self.root / filename
        with contextlib.closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE autoruns_known_good (hash_key TEXT NOT NULL, category TEXT, "
                               "image_path TEXT NOT NULL, launch_string TEXT NOT NULL, signer TEXT NOT NULL)")
            for identity, category in entries:
                image, launch, signer = identity
                key = autoruns.trusted_key(image_path=image, launch_string=launch, signer=signer)
                connection.execute("INSERT INTO autoruns_known_good VALUES (?,?,?,?,?)",
                                   (key, category, image, launch, signer))
            connection.commit()
        return path

    def test_source_pinned_categories_and_descriptions_survive_without_matching_notes(self):
        row = (r"C:\Windows\System32\service.dll", "service /start", "Vendor")
        self.source_database([row])
        key = autoruns.trusted_key(image_path=row[0], launch_string=row[1], signer=row[2])
        description = "Service DLL description; review-only note: <&>"
        with contextlib.closing(sqlite3.connect(self.source)) as connection:
            connection.execute("UPDATE autoruns_known_good SET description=?", (description,))
            connection.commit()
        before = self.source.read_bytes()
        category_map = self.category_file({key: ["Services", "Scheduled Tasks", "Services"]})
        self.build(category_map=category_map)
        loaded = database.load_database(self.output)
        self.assertEqual(loaded["identity_notes"], {key: description})
        self.assertEqual(loaded["identity_categories"], {key: ["Scheduled Tasks", "Services"]})
        self.assertEqual(loaded["metadata"]["category_map_sha256"],
                         hashlib.sha256(category_map.read_bytes()).hexdigest())
        self.assertEqual(loaded["metadata"]["source_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(self.source.read_bytes(), before)
        rules = [rule for group in loaded["exact_groups"] for rule in group["Rules"]]
        self.assertTrue(rules)
        self.assertTrue(all(set(rule) == {"HashKey", "CategoryRegex", "ImagePathRegex",
                                         "LaunchStringRegex", "SignerRegex"} for rule in rules))
        self.assertNotIn(description, json.dumps(rules))

    def test_wrong_source_unknown_identity_and_malformed_category_maps_fail_closed(self):
        row = (r"C:\Windows\System32\service.dll", "", "Vendor")
        self.source_database([row])
        key = autoruns.trusted_key(image_path=row[0], launch_string=row[1], signer=row[2])
        cases = [({key: ["Services"]}, "0" * 64, "exact source"),
                 ({"f" * 40: ["Services"]}, None, "unknown identity"),
                 ({key: "Services"}, None, "nonempty observed"),
                 ({key: [""]}, None, "nonempty observed"),
                 ({key: [None]}, None, "nonempty observed")]
        for categories, source_hash, message in cases:
            with self.subTest(categories=categories, source_hash=source_hash):
                with self.assertRaisesRegex(RuntimeError, message):
                    self.build(category_map=self.category_file(categories, source_hash=source_hash))
                self.assertFalse(self.output.exists())

    def test_modified_groups_category_notes_and_provenance_are_rejected(self):
        row = (r"C:\Windows\System32\service.dll", "", "Vendor")
        self.source_database([row])
        key = autoruns.trusted_key(image_path=row[0], launch_string=row[1], signer=row[2])
        category_map = self.category_file({key: ["Services"]})
        mutations = [
            ("UPDATE test_exact_pattern_groups SET group_json='{}'", "groups differ"),
            ("UPDATE test_exact_pattern_groups SET group_json='invalid json'", "Invalid autoruns_test"),
            ("UPDATE test_identity_categories SET category='Logon'", "category accounting/hash"),
            ("UPDATE test_identity_categories SET category=''", "invalid category association"),
            ("UPDATE test_identity_categories SET hash_key='unknown'", "invalid category association"),
            ("UPDATE test_identity_notes SET description='tampered'", "notes accounting/hash"),
            ("DELETE FROM test_identity_notes", "notes accounting/hash"),
            ("UPDATE metadata SET value='bad' WHERE key='category_map_sha256'", "category map provenance"),
        ]
        for mutation, message in mutations:
            with self.subTest(mutation=mutation):
                self.output.unlink(missing_ok=True)
                self.build(category_map=category_map)
                with contextlib.closing(sqlite3.connect(self.output)) as connection:
                    connection.execute(mutation)
                    connection.commit()
                with self.assertRaisesRegex(RuntimeError, message):
                    database.load_database(self.output)

    def test_legacy_v1_database_still_loads_but_cannot_run_grouped_mode(self):
        self.source_database([(r"C:\Windows\System32\service.dll", "", "Vendor"),
                              (r"C:\Vendor\different.exe", "", "Vendor")])
        self.build()
        with contextlib.closing(sqlite3.connect(self.output)) as connection:
            exacts = list(connection.execute("SELECT hash_key,payload FROM test_exact_identities ORDER BY hash_key"))
            patterns = database.exact_patterns(payload for _, payload in exacts)
            connection.execute("DELETE FROM test_exact_patterns")
            connection.executemany("INSERT INTO test_exact_patterns VALUES (?,?)", enumerate(patterns))
            connection.execute("UPDATE metadata SET value=? WHERE key='exact_pattern_count'", (str(len(patterns)),))
            connection.execute("UPDATE metadata SET value='autoruns_test_v1' WHERE key='schema_version'")
            for table in ("test_identity_categories", "test_exact_pattern_groups", "test_identity_notes"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DELETE FROM metadata WHERE key IN ('exact_pattern_grouping', 'category_content_sha256', "
                               "'category_map_sha256', 'category_identity_count', 'notes_content_sha256')")
            connection.commit()
        loaded = database.load_database(self.output)
        self.assertEqual(loaded["exact_patterns"], patterns)
        self.assertEqual(loaded["exact_groups"], [])
        self.assertEqual(loaded["identity_categories"], {})
        self.assertEqual(loaded["identity_notes"], {})
        for mode in ("hash-baseline", "regex-equivalent"):
            with self.subTest(mode=mode):
                self.assertEqual(autoruns_test.validate_request(database=self.output, mode=mode)["exact_hashes"],
                                 [key for key, _ in exacts])
        with self.assertRaisesRegex(RuntimeError, "rebuilt autoruns_test_v2"):
            autoruns_test.validate_request(database=self.output, mode="regex-grouped")

    def test_recovery_joins_exact_identities_and_retains_multiple_observed_labels(self):
        known = (r"C:\Windows\System32\service.dll", "", "Vendor")
        unknown = (r"C:\Windows\System32\unknown.dll", "", "Vendor")
        unrelated = (r"C:\Vendor\unrelated.dll", "", "Vendor")
        self.source_database([known, unknown])
        first = self.legacy_database([(known, "Services"), (known, "Scheduled Tasks"),
                                      (unknown, ""), (unrelated, "Logon")])
        second = self.legacy_database([(known, "Services"), (unknown, None)], "other.sqlite")
        paths = [self.source, first, second]
        originals = {path: path.read_bytes() for path in paths}
        for path in paths:
            path.chmod(0o400)
        output = self.root / "recovered.json"
        result = database.recover_categories(self.source, [first, second], output)
        payload = json.loads(output.read_text())
        key = autoruns.trusted_key(image_path=known[0], launch_string=known[1], signer=known[2])
        self.assertEqual(payload["identity_categories"], {key: ["Scheduled Tasks", "Services"]})
        self.assertEqual((result["covered_identities"], result["unknown_identities"],
                          result["category_associations"]), (1, 1, 2))
        self.assertEqual(payload["source_database_sha256"], hashlib.sha256(originals[self.source]).hexdigest())
        self.assertEqual([row["rows_read"] for row in payload["sources"]], [4, 2])
        self.assertEqual([row["matched_category_rows"] for row in payload["sources"]], [2, 1])
        for path, provenance in zip((first, second), payload["sources"]):
            self.assertEqual(provenance["sha256"], hashlib.sha256(originals[path]).hexdigest())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual({path: path.read_bytes() for path in paths}, originals)
        self.build(category_map=output)
        self.assertEqual(database.load_database(self.output)["identity_categories"], payload["identity_categories"])

    def test_recovery_rejects_bad_hash_even_for_unrelated_identity(self):
        current = (r"C:\Windows\System32\service.dll", "", "Vendor")
        unrelated = (r"C:\Vendor\unrelated.dll", "", "Vendor")
        self.source_database([current])
        for index, identity in enumerate((current, unrelated)):
            with self.subTest(identity=identity):
                legacy = self.legacy_database([(identity, "Services")], f"bad-{index}.sqlite")
                with contextlib.closing(sqlite3.connect(legacy)) as connection:
                    connection.execute("UPDATE autoruns_known_good SET hash_key='bad'")
                    connection.commit()
                before = legacy.read_bytes()
                output = self.root / f"bad-{index}.json"
                with self.assertRaisesRegex(RuntimeError, "canonical hashing"):
                    database.recover_categories(self.source, [legacy], output)
                self.assertFalse(output.exists())
                self.assertEqual(legacy.read_bytes(), before)

    def test_review_exports_description_and_unknown_wildcard_one_identity_per_line(self):
        known = (r"C:\Windows\System32\service.dll", "", "Vendor")
        unknown = (r"C:\Windows\System32\unknown.dll", "", "Vendor")
        self.source_database([known, unknown])
        known_key = autoruns.trusted_key(image_path=known[0], launch_string=known[1], signer=known[2])
        unknown_key = autoruns.trusted_key(image_path=unknown[0], launch_string=unknown[1], signer=unknown[2])
        description = "Original GoldenDB service description"
        with contextlib.closing(sqlite3.connect(self.source)) as connection:
            connection.execute("UPDATE autoruns_known_good SET description=? WHERE hash_key=?", (description, known_key))
            connection.commit()
        self.build(category_map=self.category_file({known_key: ["Services"]}))
        before = self.output.read_bytes()
        review = self.root / "review.md"
        result = database.export_grouped_review(self.output, review)
        text = review.read_text()
        self.assertIn(description, text)
        self.assertIn(f"Database SHA256: {hashlib.sha256(before).hexdigest()}", text)
        self.assertIn("Notes are review-only", text)
        lines = {key: [line for line in text.splitlines() if key in line] for key in (known_key, unknown_key)}
        self.assertTrue(all(len(rows) == 1 for rows in lines.values()))
        self.assertIn("| ` .* ` |", lines[unknown_key][0])
        self.assertIn(r"services", lines[known_key][0])
        self.assertEqual(result["identities"], 2)
        self.assertEqual(stat.S_IMODE(review.stat().st_mode), 0o600)
        self.assertEqual(self.output.read_bytes(), before)

    def test_recovery_and_review_never_replace_existing_files_or_symlinks(self):
        identity = (r"C:\Windows\System32\service.dll", "", "Vendor")
        self.source_database([identity])
        legacy = self.legacy_database([(identity, "Services")])
        self.build()
        for name, operation in (("categories.json", lambda path: database.recover_categories(self.source, [legacy], path)),
                                ("review.md", lambda path: database.export_grouped_review(self.output, path))):
            for symlink in (False, True):
                with self.subTest(name=name, symlink=symlink):
                    output = self.root / name
                    if symlink:
                        output.symlink_to(self.root / "missing")
                    else:
                        output.write_bytes(b"operator-owned content")
                    with self.assertRaisesRegex(RuntimeError, "already exists"):
                        operation(output)
                    if symlink:
                        self.assertTrue(output.is_symlink())
                    else:
                        self.assertEqual(output.read_bytes(), b"operator-owned content")
                    output.unlink()
        self.assertEqual(list(self.root.glob(".*.building")), [])

    def test_category_build_and_review_cli_require_no_live_context(self):
        identity = (r"C:\Windows\System32\service.dll", "", "Vendor")
        self.source_database([identity])
        legacy = self.legacy_database([(identity, "Services")])
        categories = self.root / "recovered.json"
        review = self.root / "review.md"
        commands = [
            ["test-categories", "--source-db", str(self.source), "--category-source", str(legacy),
             "--output", str(categories)],
            ["test-build", "--source-db", str(self.source), "--category-map", str(categories),
             "--output", str(self.output), "--rmm-reference", str(self.reference)],
            ["test-review", "--db", str(self.output), "--output", str(review)],
        ]
        with mock.patch.object(golden, "apply_engagement_context", side_effect=AssertionError("live context")), \
             mock.patch.object(golden.velociraptor_api, "VeloApiClient", side_effect=AssertionError("live client")):
            for command in commands:
                with self.subTest(command=command[0]), contextlib.redirect_stdout(io.StringIO()) as captured:
                    self.assertEqual(golden.main(command), 0)
                self.assertIsInstance(json.loads(captured.getvalue()), dict)
        self.assertTrue(categories.is_file())
        self.assertTrue(review.is_file())


if __name__ == "__main__":
    unittest.main()

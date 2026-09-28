"""Approved rules are authoritative across storage, migration and native matching."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vraptor.autoruns import regex as rx
from vraptor.autoruns import regex_store as db
from vraptor.autoruns import golden
from vraptor.autoruns import dedup_ai as dedup
from vraptor.autoruns import review
from vraptor.analyze import source as review_source
from tests.test_autoruns_regex import EXACT, RULE
from tests.test_autoruns_regex_review import execute, row


class ApprovedRulesTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.database = self.root / "golden.sqlite"
        golden.promote_records(self.database, [EXACT], regex_rows=[RULE])
        db.migrate(self.database, self.database, backup_dir=self.root / "backups")

    def schema7(self, records=None, version="7"):
        source = self.root / f"schema{version}.sqlite"
        cfg = db.load(self.database)
        records = records or [(r, i % 2) for i, r in enumerate(cfg["records"])]
        flag_column = "apply_veto INTEGER, " if version == "7" else ""
        flag_key = ",apply_veto" if version == "7" else ""
        sql = db.SQL.split("CREATE TABLE autoruns_regex_rules")[0] + f"""
CREATE TABLE autoruns_regex_rules(category_regex TEXT, image_path_regex TEXT,
launch_string_regex TEXT, signer_regex TEXT, {flag_column}description TEXT,
modified_time TEXT, origin TEXT, source_hash TEXT, signer_reference TEXT,
PRIMARY KEY(category_regex,image_path_regex,launch_string_regex,signer_regex{flag_key}));
"""
        meta = {**cfg["metadata"], "schema_version":version, "rule_count":str(len(records))}
        meta["approval_policy"] = "goldendb-reviewed-rules-v1"
        with sqlite3.connect(source) as conn:
            conn.executescript(sql)
            conn.executemany("INSERT INTO metadata VALUES (?,?)", sorted(meta.items()))
            values = [(r["category_regex"],r["image_path_regex"],r["launch_string_regex"],r["signer_regex"],
                       *((flag,) if version == "7" else ()),
                       r["notes"],r["modified_time"],"fixture-origin","fixture-hash","fixture-signer-reference")
                      for r,flag in records]
            conn.executemany("INSERT INTO autoruns_regex_rules VALUES (" + ",".join("?"*len(values[0])) + ")", values)
        return source

    def test_schema7_upgrade_preserves_patterns_and_metadata_and_verified_backup(self):
        source = self.schema7()
        before = source.read_bytes()
        prior = db.load(source, allow_legacy=True)["records"]
        result = db.migrate(source, source, backup_dir=self.root / "upgrade-backup")
        current = db.load(source)
        self.assertEqual(current["metadata"]["schema_version"], "9")
        self.assertEqual(Path(result["backup"]).read_bytes(), before)
        self.assertEqual(current["records"], [{**{k:r[k] for k in db.COLUMNS if k != "notes"}, "notes":r["description"]} for r in prior])
        self.assertTrue(all("ApplyVeto" not in r for r in current["rules"]))
        with sqlite3.connect(source) as conn:
            self.assertNotIn("apply_veto", [r[1] for r in conn.execute("PRAGMA table_info(autoruns_regex_rules)")])
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone(), ("ok",))
        migrated = source.read_bytes()
        self.assertTrue(db.migrate(source, source, backup_dir=self.root / "upgrade-backup")["already_current"])
        self.assertEqual(source.read_bytes(), migrated)
        self.assertEqual(len(list((self.root / "upgrade-backup").glob("*.bak"))), 1)

    def test_flags_collapse_to_one_four_field_identity(self):
        rule = db.load(self.database)["records"][0]
        source = self.schema7([(rule,0),(rule,1)])
        result = db.migrate(source, source, backup_dir=self.root / "upgrade-backup")
        self.assertEqual(result["regex_rule_count"], 1)
        self.assertEqual(result["collapsed_duplicate_rules"], 1)
        self.assertEqual(tuple(db.load(source)["records"][0][k] for k in db.COLUMNS[:4]),
                         tuple(rule[k] for k in db.COLUMNS[:4]))

    def test_schema7_cannot_run_until_explicitly_migrated(self):
        source = self.schema7()
        with self.assertRaisesRegex(RuntimeError, "migrate to schema 9"):
            db.load(source)
        with self.assertRaisesRegex(RuntimeError, "migrate to schema 9"):
            golden.live_lookup_payload(source)
        with self.assertRaisesRegex(RuntimeError, "migrate to schema 9"):
            review.load_database(source)

    def test_failed_atomic_migration_preserves_source_and_backup(self):
        source = self.schema7()
        before = source.read_bytes()
        with patch.object(db.os, "replace", side_effect=OSError("simulated replace failure")):
            with self.assertRaisesRegex(OSError, "simulated replace"):
                db.migrate(source, source, backup_dir=self.root / "upgrade-backup")
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(next((self.root / "upgrade-backup").glob("*.bak")).read_bytes(), before)
        self.assertEqual(list(self.root.glob(".regex-migration-*")), [])

    def test_relabeling_a_schema7_database_is_rejected(self):
        source = self.schema7()
        with sqlite3.connect(source) as conn:
            conn.execute("UPDATE metadata SET value='9' WHERE key='schema_version'")
        with self.assertRaisesRegex(RuntimeError, "schema-9 rule columns"):
            db.load(source)

    def test_imported_paths_and_commands_match_without_secondary_policy(self):
        images = [r"c:\programdata\reviewed\agent.exe", r"c:\users\user\reviewed\app.exe",
                  r"c:\vendor\anydesk.exe", r"\\server\share\reviewed.exe",
                  r"c:\windows\system32\runner.exe"]
        launches = [*images[:-1], images[-1] + r" c:\users\user\reviewed\script.ps1"]
        proposals = [dict(Category=".", ImagePath=db.literal_pattern(image),
            LaunchString=db.literal_pattern(launch), Signer="^vendor$", Notes="Operator-reviewed synthetic rule")
            for image,launch in zip(images,launches)]
        incoming = self.root / "approved.json"
        incoming.write_text(json.dumps(proposals))
        with patch.object(golden, "RmmClassifier", side_effect=AssertionError("secondary policy load")):
            applied = db.import_rules(self.database,incoming,backup_dir=self.root / "import-backup")
            cfg = db.load(self.database)
            payload = golden.live_lookup_payload(self.database)
        self.assertEqual(applied["added_rules"], 5)
        self.assertEqual(db.import_rules(self.database,incoming,backup_dir=self.root / "import-backup")["added_rules"], 0)
        self.assertNotIn("veto", cfg)
        index = rx.RegexIndex(cfg["records"])
        positives=[dict(category="services",image_path=image,launch_string=launch,signer="vendor")
                   for image,launch in zip(images,launches)]
        decoys=[dict(r, **{field:r[field]+suffix}) for r in positives
                for field,suffix in (("image_path",".other"),
                                     ("launch_string"," --extra"),("signer"," other"),("launch_string","\n"))]
        self.assertTrue(all(index.matches(r) for r in positives))
        self.assertFalse(any(index.matches(r) for r in decoys))
        native_rows=[row(Category=r["category"],image=r["image_path"],
                        **{"Launch String":r["launch_string"],"Signer":r["signer"]}) for r in positives+decoys]
        # Eligibility remains a source-stage decision, not a GoldenDB rule veto.
        native_rows += [row(Enabled="disabled"),row(image="File not found: example.exe")]
        stream=execute(native_rows,original=True,config=cfg,vql_file=dedup.template())
        self.assertEqual(stream[-1]["SourceRows"],27)
        self.assertEqual(stream[-1]["EligibleRows"],25)
        self.assertEqual(stream[-1]["MatchedRows"],5)
        self.assertEqual(stream[-1]["ResidualRows"],20)
        query,env,_=review.build_query(cfg,source=review_source.hunt_source("H.test",golden.DEFAULT_AUTORUNS_ARTIFACT),vql_file=dedup.template())
        self.assertNotIn("Veto",query)
        self.assertFalse(any("veto" in k.lower() for k in env))
        self.assertEqual(payload["matching_policy"], rx.MATCHING_POLICY)

    def test_schema8_category_broadening_preserves_notes_and_collapses_duplicates(self):
        rule = db.load(self.database)["records"][0]
        source = self.schema7([({**rule, "category_regex":"logon", "notes":"First note"}, 0),
                               ({**rule, "category_regex":"services", "notes":"Second note"}, 0)], version="8")
        before = source.read_bytes()
        result = db.migrate(source, source, backup_dir=self.root/"category-backup")
        records = db.load(source)["records"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["category_regex"], ".")
        self.assertEqual(set(records[0]), set(db.COLUMNS))
        self.assertEqual(records[0]["notes"], "First note\nSecond note")
        self.assertEqual(result["collapsed_duplicate_rules"], 1)
        self.assertEqual(Path(result["backup"]).read_bytes(), before)

    def test_dot_category_matches_all_without_broadening_other_fields(self):
        incoming = self.root/"wildcard.json"
        incoming.write_text(json.dumps([dict(Category=".", ImagePath=r"c:\\category\\tool\.exe",
            LaunchString="run", Signer="vendor", Notes="All categories")]))
        db.import_rules(self.database, incoming, backup_dir=self.root/"category-backup")
        cfg = db.load(self.database)
        index = rx.RegexIndex(cfg["records"])
        categories = ["Logon", "Services", "X", "", "other\ncategory"]
        samples = [dict(category=category, image_path=r"c:\category\tool.exe", launch_string="run", signer="vendor")
                   for category in categories]
        self.assertTrue(all(index.matches(r) for r in samples))
        self.assertFalse(index.matches({**samples[0], "launch_string":"run extra"}))
        stream = execute([row(Category=r["category"], image=r["image_path"],
            **{"Launch String":r["launch_string"],"Signer":r["signer"]}) for r in samples],
            original=True, config=cfg, vql_file=dedup.template())
        self.assertEqual(stream[-1]["MatchedRows"], len(samples))
        # The host/inventory VQL payload must use exactly the same category expansion.
        import base64, gzip
        payload = golden.live_lookup_payload(self.database)
        rules = json.loads(gzip.decompress(base64.b64decode(payload["regex_lookup_gzip_base64"])))
        for rule in rules:
            self.assertTrue(all(rx.compile_pattern(rule["CategoryRegex"]).search(c) is not None for c in categories))

    def test_invalid_imports_leave_database_unchanged(self):
        incoming=self.root/"invalid.json"
        base=dict(Category=".",ImagePath="valid",LaunchString="valid",Signer="vendor",Notes="Reviewed")
        for bad in ({**base,"ImagePath":"["},{**base,"LaunchString":r"\C"},
                    {**base,"Signer":""},{**base,"ApplyVeto":True},
                    {**base,"Category":"services"},{**base,"Description":"obsolete"}):
            incoming.write_text(json.dumps([bad]))
            before=self.database.read_bytes()
            with self.assertRaises(RuntimeError):
                db.import_rules(self.database,incoming,backup_dir=self.root/"rejected-backup")
            self.assertEqual(self.database.read_bytes(),before)
        self.assertFalse((self.root/"rejected-backup").exists())


if __name__ == "__main__":
    unittest.main()

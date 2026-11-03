"""Native VQL and fail-closed CSV publication tests for regex review."""
import csv
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest.mock import Mock, patch

from vraptor.autoruns import dedup_ai as dedup
from vraptor.autoruns import review
from vraptor.analyze import source as review_source

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))
requires_velociraptor = unittest.skipUnless(BINARY.is_file(), "Local Velociraptor binary unavailable")


def configuration():
    return {"rules": [{"Category": "Logon", "ImagePath": r"^c:\\known\.exe$",
                       "LaunchString": ".", "Signer": r"^\(Verified\) Microsoft"}],
            "metadata": {}, "database_sha256": "0"*64}


def production_configuration():
    # The pinned production template accepts only regex-only schema 9/10 rules.
    return {**configuration(), "metadata": {"schema_version": "10"}}


def execute(rows, cap=20, config=None, **query_options):
    if not BINARY.is_file():
        raise unittest.SkipTest("Local Velociraptor binary unavailable")
    source = review_source.ReviewSource("test", "test", "IG.Windows.Sysinternals.Autoruns",
        "foreach(row=parse_json_array(data=gunzip(string=base64decode(string=TestRowsGzip))))", {})
    query, env, _ = review.build_query(config or configuration(), source=source, max_hostnames=cap, **query_options)
    args = [str(BINARY), "query", "--format", "jsonl"]
    for name, value in {**env, "TestRowsGzip": review._encode(rows)}.items():
        args += ["--env", f"{name}={value}"]
    output = subprocess.run([*args, query], text=True, capture_output=True, check=True, timeout=30)
    if "ERROR" in output.stderr:
        raise AssertionError(output.stderr)
    return [json.loads(line) for line in output.stdout.splitlines() if line.strip()]


def row(host="a", image=r"C:\Users\Alice\tool.exe", **changes):
    return {"Category": "Logon", "Image Path": image, "Launch String": image,
            "Signer": "Vendor", "Enabled": "enabled", "Fqdn": host, **changes}


class RegexReviewTest(unittest.TestCase):
    def test_loader_roundtrip_schema_and_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"db.sqlite"
            with sqlite3.connect(path) as db:
                db.executescript("CREATE TABLE metadata(key TEXT,value TEXT); CREATE TABLE GoldenRules(RuleId INTEGER,Category TEXT,ImagePath TEXT,LaunchString TEXT,Signer TEXT);")
                db.executemany("INSERT INTO metadata VALUES (?,?)",
                               [("schema_version", review.SCHEMA), ("rule_count", "1")])
                db.execute("INSERT INTO GoldenRules VALUES (1,?,?,?,?)",
                           tuple(configuration()["rules"][0].values()))
            self.assertEqual(review.load_database(path)["rules"], configuration()["rules"])
            with sqlite3.connect(path) as db:
                db.execute("UPDATE metadata SET value='2' WHERE key='rule_count'")
            with self.assertRaises(RuntimeError):
                review.load_database(path)

    def test_loader_without_rule_id_ignores_descriptive_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"db.sqlite"
            with sqlite3.connect(path) as db:
                db.executescript("CREATE TABLE metadata(key TEXT,value TEXT); CREATE TABLE GoldenRules(Category TEXT,ImagePath TEXT,LaunchString TEXT,Signer TEXT,Notes TEXT,LastModified TEXT);")
                db.executemany("INSERT INTO metadata VALUES (?,?)",
                               [("schema_version", review.SCHEMA), ("rule_count", "1")])
                db.execute("INSERT INTO GoldenRules VALUES (?,?,?,?,?,?)",
                           (*configuration()["rules"][0].values(), "Descriptive only", "2026-09-12"))
            before = path.read_bytes()
            self.assertEqual(review.load_database(path)["rules"], configuration()["rules"])
            self.assertEqual(path.read_bytes(), before)

    def test_loader_rejects_invalid_files_and_final_request_size(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"template.vql"
            for raw in (b"", b"SELECT * FROM scope()", b"\xff", b"x"*(1024*1024+1)):
                path.write_bytes(raw)
                with self.assertRaises(RuntimeError):
                    review.load_vql_file(path)
            for token in ("SOURCE_QUERY", "RULE_COUNT", "HOST_LIMIT"):
                path.write_text(dedup.template().text.replace(token, "missing"))
                with self.assertRaisesRegex(RuntimeError, token):
                    review.load_vql_file(path)
            path.unlink()
            with self.assertRaises(RuntimeError):
                review.load_vql_file(path)
            api = Mock(org_id="root")
            with patch.object(review, "load_database", return_value=production_configuration()), \
                    patch.object(review, "MAX_REQUEST_BYTES", 1000):
                with self.assertRaisesRegex(RuntimeError, "1 MiB"):
                    review.run(api, hunt_id="H.fixture", artifact="IG.Windows.Sysinternals.Autoruns",
                        database=Path("unused"), output_dir=Path(temp)/"out", vql_file=dedup.template())
            api.query_batches.assert_not_called()
            self.assertFalse((Path(temp)/"out").exists())

    def test_malformed_batch_does_not_publish(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(
                review, "load_database", return_value=production_configuration()):
            target = Path(temp)/"review"
            api = Mock(org_id="root")
            api.query_batches.return_value = iter([{}])
            with self.assertRaisesRegex(RuntimeError, "malformed row batch"):
                review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), output_dir=target, vql_file=dedup.template())
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_publication_only_after_complete_stream(self):
        cfg = production_configuration()
        stream = execute([row()], config=cfg, vql_file=dedup.template())
        with tempfile.TemporaryDirectory() as temp, patch.object(
                review, "load_database", return_value=cfg):
            target = Path(temp)/"review"
            api = Mock(org_id="root")
            api.query_batches.return_value = iter([stream[:-1]])
            with self.assertRaises(RuntimeError):
                review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), output_dir=target, vql_file=dedup.template())
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])
            api.query_batches.return_value = iter([stream])
            result = review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                                database=Path("unused"), output_dir=target, vql_file=dedup.template())
            with (target/"review.csv").open() as f:
                saved = list(csv.DictReader(f))
            self.assertEqual(json.loads(saved[0]["ExampleHosts"]), ["a"])
            self.assertEqual(result["stack_rows_saved"], 1)
            self.assertEqual(json.loads((target/"stats.json").read_text()), result)
            with self.assertRaises(RuntimeError):
                review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), output_dir=target, vql_file=dedup.template())

    def test_transport_error_after_summary_does_not_publish(self):
        cfg = production_configuration()
        stream = execute([row()], config=cfg, vql_file=dedup.template())
        def batches(*args, **kwargs):
            yield stream
            raise TimeoutError("transport ended abnormally")
        with tempfile.TemporaryDirectory() as temp, patch.object(
                review, "load_database", return_value=cfg):
            target = Path(temp)/"review"
            api = Mock(org_id="root")
            api.query_batches.side_effect = batches
            with self.assertRaises(TimeoutError):
                review.run(api, hunt_id="H.test", artifact="IG.Windows.Sysinternals.Autoruns",
                           database=Path("unused"), output_dir=target, vql_file=dedup.template())
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

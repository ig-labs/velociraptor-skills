"""CSV maintenance dates, atomic replacement and native search-matching parity."""
import base64
import csv
import gzip
import json
import sqlite3
from datetime import date
from pathlib import Path
from unittest.mock import patch

import pytest

from vraptor.autoruns import csv_store as db
from vraptor.autoruns import regex_store as storage
from vraptor.autoruns import golden
from vraptor.autoruns import regex
from vraptor.autoruns import dedup_ai as dedup
from tests.test_autoruns_regex_review import execute, row


RULE = dict(Category="^Services", ImagePath=r"^c:\\vendor\\service\.exe$",
            LaunchString=r'^"?c:\\vendor\\service\.exe', Signer=r"^\(Verified\) Vendor$",
            Notes="Filters out the vendor service with any launch suffix.")


def incoming(root, rows, *, dated=False):
    path = root / "rules.csv"
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=db.COLUMNS if dated else db.COLUMNS[:-1])
        writer.writeheader()
        writer.writerows(rows)
    return path


def write(root, rows, *, replace=False, dated=False, **options):
    return db.write_csv(root / "golden.sqlite", incoming(root, rows, dated=dated),
                        backup_dir=root / "backups", replace=replace, **options)


def test_creation_schema_sorting_and_input_dates_are_ignored(tmp_path):
    rows = [RULE, {**RULE, "Category": "^Known DLLs$", "Notes": "Known DLL test"}]
    write(tmp_path, [{**r, "LastModified": "1999-01-01"} for r in rows], dated=True)
    path = tmp_path / "golden.sqlite"
    cfg = storage.load(path)
    assert cfg["metadata"]["schema_version"] == "10"
    assert [r["Category"] for r in cfg["records"]] == ["^Known DLLs$", "^Services"]
    assert all(r["LastModified"] == date.today().isoformat() for r in cfg["records"])
    with sqlite3.connect(path) as connection:
        assert tuple(r[1] for r in connection.execute("PRAGMA table_info(GoldenRules)")) == db.COLUMNS
        assert {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")} == {"metadata", "GoldenRules"}


def test_import_and_snapshot_preserve_unchanged_dates_and_back_up_edits(tmp_path):
    with patch.object(db, "date", wraps=date) as clock:
        clock.today.return_value = date(2026, 1, 1)
        write(tmp_path, [RULE])
    path = tmp_path / "golden.sqlite"
    before = path.read_bytes()
    with patch.object(db, "date", wraps=date) as clock:
        clock.today.return_value = date(2026, 2, 1)
        assert write(tmp_path, [RULE])["unchanged"]
        assert path.read_bytes() == before
        second = {**RULE, "ImagePath": "second", "LaunchString": "second"}
        result = write(tmp_path, [second])
        assert result["added_rules"] == 1
        assert storage.load(path)["records"][0]["LastModified"] == "2026-01-01"
        assert storage.load(path)["records"][1]["LastModified"] == "2026-02-01"
        assert Path(result["backup"]).read_bytes() == before
        result = write(tmp_path, [{**RULE, "Notes": "Reworded description"}])
        assert result["updated_rules"] == 1 and result["added_rules"] == 0
        assert storage.load(path)["records"][0]["LastModified"] == "2026-02-01"
    with patch.object(db, "date", wraps=date) as clock:
        clock.today.return_value = date(2026, 3, 1)
        result = write(tmp_path, [{**RULE, "LaunchString": "edited-pattern"}], replace=True)
        assert result["removed_rules"] == 2 and result["added_rules"] == 1
        assert storage.load(path)["records"][0]["LastModified"] == "2026-03-01"


def test_direct_edits_refresh_dates_but_noop_does_not(tmp_path):
    write(tmp_path, [RULE])
    with sqlite3.connect(tmp_path / "golden.sqlite") as connection:
        connection.execute("UPDATE GoldenRules SET LastModified='2001-01-01'")
        connection.execute("UPDATE GoldenRules SET Notes=Notes")
        assert connection.execute("SELECT LastModified FROM GoldenRules").fetchone()[0] == "2001-01-01"
        connection.execute("UPDATE GoldenRules SET LaunchString='changed'")
        assert connection.execute("SELECT LastModified FROM GoldenRules").fetchone()[0] == date.today().isoformat()


def test_bad_csv_dry_run_and_failed_replacement_preserve_database(tmp_path):
    write(tmp_path, [RULE])
    path = tmp_path / "golden.sqlite"
    before = path.read_bytes()
    for rows in ([], [RULE, RULE], [{**RULE, "Signer": "["}], [{**RULE, "Signer": ""}]):
        with pytest.raises(RuntimeError):
            write(tmp_path, rows)
        assert path.read_bytes() == before
    assert write(tmp_path, [{**RULE, "Notes": "New note"}], dry_run=True)["updated_rules"] == 1
    assert path.read_bytes() == before and not (tmp_path / "backups").exists()
    with patch.object(db.os, "replace", side_effect=OSError("replacement failed")):
        with pytest.raises(OSError, match="replacement failed"):
            write(tmp_path, [{**RULE, "Notes": "New note"}])
    assert path.read_bytes() == before
    assert next((tmp_path / "backups").glob("*.bak")).read_bytes() == before
    assert not list(tmp_path.glob(".golden-csv-*"))


def test_native_hunt_and_host_payload_keep_search_and_exact_category_semantics(tmp_path):
    known = {**RULE, "Category": "^Known DLLs$", "ImagePath": r"^c:\\vendor\\known\.dll$",
             "LaunchString": r"^c:\\vendor\\known\.dll$"}
    write(tmp_path, [RULE, known])
    path = tmp_path / "golden.sqlite"
    cfg = storage.load(path)
    samples = [
        dict(category="Services", image_path=r"c:\vendor\service.exe", launch_string=r'"c:\vendor\service.exe" --new-switch', signer="(Verified) Vendor"),
        dict(category="Services extra", image_path=r"c:\vendor\service.exe", launch_string=r"c:\vendor\service.exe anything", signer="(Verified) Vendor"),
        dict(category="Known DLLs", image_path=r"c:\vendor\known.dll", launch_string=r"c:\vendor\known.dll", signer="(Verified) Vendor"),
    ]
    samples += [{**samples[0], "category": "OtherServices"},
                {**samples[0], "signer": "(Not verified) Vendor"},
                {**samples[2], "category": "Known DLLs extra"},
                {**samples[0], "image_path": r"c:\vendor\service.exe.other"}]
    index = regex.RegexIndex(cfg["records"])
    assert [index.matches(r) for r in samples] == [True] * 3 + [False] * 4
    native = [row(Category=r["category"], image=r["image_path"], **{"Launch String": r["launch_string"], "Signer": r["signer"]}) for r in samples]
    stream = execute(native, original=True, config=cfg, vql_file=dedup.template())
    assert stream[-1]["SourceRows"] == 7
    assert stream[-1]["MatchedRows"] == 3 and stream[-1]["ResidualRows"] == 4
    payload = golden.live_lookup_payload(path)
    rules = json.loads(gzip.decompress(base64.b64decode(payload["regex_lookup_gzip_base64"])))
    assert rules == [{k + "Regex": r[k] for k in db.FIELDS} for r in cfg["rules"]]
    assert payload["matching_policy"] == db.POLICY
    assert golden.lookup_identity(path, **samples[0])["filter_match"]
    result = golden.filter_autoruns_rows(path, native, output=tmp_path / "residual.csv")
    assert result["known_good_filtered_rows"] == 3


def test_schema10_blocks_legacy_writes_and_json_imports(tmp_path):
    write(tmp_path, [RULE])
    path = tmp_path / "golden.sqlite"
    before = path.read_bytes()
    with golden.connect_database(path) as connection:
        with pytest.raises(RuntimeError, match="regex-import"):
            golden.initialize_database(connection, built_at="2026-01-01")
    source = tmp_path / "rules.json"
    source.write_text(json.dumps([RULE]))
    with pytest.raises(RuntimeError, match="CSV"):
        storage.import_rules(path, source, backup_dir=tmp_path / "backups")
    assert path.read_bytes() == before


def test_cli_build_and_import_accept_csv(tmp_path):
    source = incoming(tmp_path, [RULE])
    for command in ("regex-build", "regex-import"):
        args = golden.parser().parse_args([command, "--db", str(tmp_path / "db.sqlite"),
            "--input", str(source), "--backup-dir", str(tmp_path / "backups"), "--dry-run"])
        assert args.command == command and args.dry_run

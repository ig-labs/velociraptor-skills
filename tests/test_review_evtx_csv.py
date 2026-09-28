"""Protect source evidence when output paths alias one another."""
import contextlib
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "utils/review_evtx_csv.py"


def load_review_evtx_csv_module():
    module_name = f"test_review_evtx_csv_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class ReviewEvtxCsvTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_review_evtx_csv_module()

    def write_csv(self, path: Path, rows: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def test_review_handles_large_evtx_field_and_writes_compact_snippet(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "Windows.EventLogs.EvtxHunter_full.csv"
            output_path = Path(tmpdir) / "review" / "snippets.csv"
            manifest_path = Path(tmpdir) / "review" / "snippets.manifest.json"
            large_payload = "A" * 200_000 + " powershell -enc SQBFAFgA " + "B" * 200_000
            self.write_csv(
                input_path,
                [
                    {
                        "EventTime": "2018-09-05T12:00:00Z",
                        "Hostname": "base-file",
                        "Channel": "Microsoft-Windows-PowerShell/Operational",
                        "EventID": "4104",
                        "Provider": "PowerShell",
                        "Message": large_payload,
                    }
                ],
            )

            manifest = module.review_evtx_csv(
                input_path=input_path,
                output_path=output_path,
                manifest_path=manifest_path,
                literals=["powershell -enc"],
                regexes=[],
                fields=["Message"],
                context_chars=24,
                max_matches=10,
                case_sensitive=False,
            )

            self.assertEqual(manifest["rows_read"], 1)
            self.assertEqual(manifest["matches_written"], 1)
            self.assertEqual(manifest["matched_row_count"], 1)
            self.assertGreaterEqual(manifest["csv_field_size_limit"], 400_000)
            self.assertTrue(manifest_path.exists())
            with output_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["MatchedField"], "Message")
            self.assertEqual(rows[0]["MatchedPattern"], "powershell -enc")
            self.assertIn("powershell -enc SQBFAFgA", rows[0]["Snippet"])
            self.assertLess(len(rows[0]["Snippet"]), 120)
            self.assertEqual(rows[0]["Hostname"], "base-file")

    def test_main_requires_at_least_one_literal_or_regex(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "events.csv"
            output_path = Path(tmpdir) / "out.csv"
            self.write_csv(input_path, [{"Message": "hello"}])
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = module.main(["--input", str(input_path), "--output", str(output_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("At least one --literal or --regex value is required", stderr.getvalue())

    def test_review_can_limit_matches_and_records_truncation(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "events.csv"
            output_path = Path(tmpdir) / "out.csv"
            manifest_path = Path(tmpdir) / "out.manifest.json"
            self.write_csv(
                input_path,
                [
                    {"EventID": "1", "Message": "needle one"},
                    {"EventID": "2", "Message": "needle two"},
                ],
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = module.main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(output_path),
                        "--manifest",
                        str(manifest_path),
                        "--literal",
                        "needle",
                        "--max-matches",
                        "1",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn('"truncated": true', stdout.getvalue())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(manifest["truncated"])
            self.assertEqual(manifest["matches_written"], 1)
            with output_path.open("r", encoding="utf-8", newline="") as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 1)


@pytest.mark.parametrize("pair", [("input", "output"), ("input", "manifest"), ("output", "manifest")])
@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink"])
def test_aliases_fail_without_modifying_files(tmp_path, pair, alias):
    paths = {name: tmp_path / name for name in ("input", "output", "manifest")}
    original = "EventID,CommandLine\n1,needle\n"
    for path in paths.values():
        path.write_text(original)
    first, second = (paths[name] for name in pair)
    second.unlink()
    if alias == "same":
        paths[pair[1]] = first
    elif alias == "symlink":
        second.symlink_to(first)
    else:
        os.link(first, second)
    args = [argument for name, path in paths.items() for argument in (f"--{name}", str(path))]
    result = subprocess.run([sys.executable, str(SCRIPT), *args, "--literal", "needle"],
                            text=True, capture_output=True)
    assert result.returncode == 1
    assert "must be different files" in result.stderr
    assert all(path.read_text() == original for path in paths.values())


def test_separate_outputs_preserve_evidence_and_report_coverage(tmp_path):
    source, output = tmp_path / "source.csv", tmp_path / "matches.csv"
    original = "EventID,CommandLine\n1,needle\n2,unrelated\n"
    source.write_text(original)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(source), "--output", str(output),
         "--literal", "needle", "--field", "CommandLine"], text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert source.read_text() == original
    manifest = json.loads(output.with_suffix(".csv.manifest.json").read_text())
    assert manifest["rows_read"] == 2
    assert manifest["matches_written"] == 1
    assert manifest["truncated"] is False

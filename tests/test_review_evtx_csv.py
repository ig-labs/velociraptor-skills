"""Protect source evidence when output paths alias one another."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "utils/review_evtx_csv.py"


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

import json
from pathlib import Path
import subprocess
from urllib.parse import quote

import pytest

from vraptor.export_mapping import detect, inventory, prepare
from vraptor.paths import resolve_velociraptor_binary


def fixture(root):
    source = root / "uploads/auto/C%3A/Windows/a%3Ab.pf"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"evidence")
    row = dict(_Components=["uploads", "auto", "C:", "Windows", "a:b.pf"],
               file_size=8, uploaded_size=8)
    (root / "uploads.json").write_text(json.dumps(row) + "\n")
    return source, row


def test_detection_and_encoded_paths(tmp_path):
    source, _ = fixture(tmp_path)
    assert detect(tmp_path) == "velociraptor-export"
    assert inventory(tmp_path)[0]["source"] == str(source.resolve())
    assert inventory(tmp_path)[0]["target"] == "C:\\Windows\\a:b.pf"
    with pytest.raises(ValueError):
        detect(tmp_path, "windows-directory")


@pytest.mark.parametrize("problem", ["size", "sparse", "symlink", "duplicate"])
def test_invalid_export(tmp_path, problem):
    source, row = fixture(tmp_path)
    if problem == "size":
        source.write_bytes(b"x")
    if problem == "sparse":
        row["uploaded_size"] = 1
    if problem == "symlink":
        source.unlink()
        source.symlink_to(tmp_path / "uploads.json")
    text = json.dumps(row) + "\n"
    (tmp_path / "uploads.json").write_text(text * (2 if problem == "duplicate" else 1))
    with pytest.raises(ValueError):
        inventory(tmp_path)


def test_ambiguous_directory(tmp_path):
    with pytest.raises(ValueError, match="Ambiguous"):
        detect(tmp_path)


def test_output_inside_evidence_rejected(tmp_path):
    fixture(tmp_path)
    with pytest.raises(ValueError, match="outside source"):
        prepare(tmp_path, tmp_path / "runtime/remapping.yaml", "unused", "fixture")
    assert not (tmp_path / "runtime").exists()


def test_native_remap(tmp_path):
    binary = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))
    if not binary.is_file():
        pytest.skip("Native Velociraptor unavailable")
    evidence = tmp_path / "evidence"
    source, _ = fixture(evidence)
    drive = "\\\\.\\D:"
    ntfs = evidence / "uploads/ntfs" / quote(drive, safe="") / "$MFT"
    ntfs.parent.mkdir(parents=True)
    ntfs.write_bytes(b"mft fixture")
    with (evidence / "uploads.json").open("a") as stream:
        stream.write(json.dumps(dict(_Components=["uploads", "ntfs", drive, "$MFT"],
                                     file_size=11, uploaded_size=11)) + "\n")
    remap = tmp_path / "runtime/remapping.yaml"
    saved = prepare(evidence, remap, str(binary), "fixture")
    result = subprocess.run([str(binary), "--remap", str(remap), "query", "--nobanner",
                             "SELECT OSPath, Size FROM glob(globs='C:/Windows/*', accessor='auto')"],
                            capture_output=True, text=True, check=True, timeout=30)
    rows = json.loads(result.stdout)
    assert rows[0]["Size"] == 8
    assert source.read_bytes() == b"evidence"
    assert saved["files"] == 2
    assert prepare(evidence, remap, str(binary), "fixture") == saved
    remap.write_text(remap.read_text() + "# changed\n")
    with pytest.raises(ValueError, match="changed"):
        prepare(evidence, remap, str(binary), "fixture")

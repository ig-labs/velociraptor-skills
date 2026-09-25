"""Audit persistence must not retain sensitive content or follow links."""

import json
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from public_audit import append_audit, finding_metadata


def test_append_preserves_records_and_omits_paths(tmp_path):
    sensitive_path = "private-customer/credential.txt"
    findings = finding_metadata([(sensitive_path, "credential")])
    for status in ("failed", "passed"):
        append_audit(tmp_path, check="test", status=status, findings=findings)
    log = tmp_path / ".local/public-checks.jsonl"
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["status"] for r in records] == ["failed", "passed"]
    assert sensitive_path not in log.read_text()
    assert len(records[0]["findings"][0]["path_sha256"]) == 64
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert stat.S_IMODE(log.parent.stat().st_mode) == 0o700


@pytest.mark.parametrize("target", ["directory", "file", "hardlink"])
def test_log_rejects_links_without_changing_target(tmp_path, target):
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "protected"
    protected.write_text("preserve me")
    local = tmp_path / ".local"
    if target == "directory":
        local.symlink_to(outside, target_is_directory=True)
    else:
        local.mkdir()
        log = local / "public-checks.jsonl"
        if target == "file":
            log.symlink_to(protected)
        else:
            log.hardlink_to(protected)
    with pytest.raises(OSError):
        append_audit(tmp_path, check="test", status="passed")
    assert protected.read_text() == "preserve me"
    assert not (outside / "public-checks.jsonl").exists()


@pytest.mark.parametrize("attempt", range(10))
def test_concurrent_records_remain_valid_json(tmp_path, attempt):
    def write(number):
        append_audit(tmp_path, check="test", status="passed", number=number)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write, range(20)))
    records = [json.loads(line) for line in (tmp_path / ".local/public-checks.jsonl").read_text().splitlines()]
    assert sorted(r["number"] for r in records) == list(range(20))

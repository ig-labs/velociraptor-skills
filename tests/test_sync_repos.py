from __future__ import annotations

import os
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SYNC_SCRIPT = ROOT / "utils" / "sync-repos.py"


def run(command: list[str], cwd: Path, expected: int = 0) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Sync Test",
            "GIT_AUTHOR_EMAIL": "sync@example.invalid",
            "GIT_COMMITTER_NAME": "Sync Test",
            "GIT_COMMITTER_EMAIL": "sync@example.invalid",
        }
    )
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
    assert result.returncode == expected, result.stdout + result.stderr
    return result


def commit_all(repo: Path, message: str) -> None:
    run(["git", "add", "-A"], repo)
    run(["git", "commit", "-m", message], repo)


def initialize_pair(tmp_path: Path) -> tuple[Path, Path, Path]:
    public = tmp_path / "velociraptor-skills"
    ai = tmp_path / "ai_skills"
    (public / "utils").mkdir(parents=True)
    (public / "config").mkdir()
    (ai / "shared").mkdir(parents=True)
    shutil.copy2(SYNC_SCRIPT, public / "utils" / "sync-repos.py")
    for module in ("public_audit.py", "sync_policy.py"):
        shutil.copy2(ROOT / "utils" / module, public / "utils" / module)
    (public / ".gitignore").write_text("/.local/\n/.sync-state.json\n", encoding="utf-8")
    (public / "config" / "sync-manifest.tsv").write_text(
        "shared/file.txt\tmanaged/file.txt\tfile\n", encoding="utf-8"
    )
    (public / "config" / "public-deny-patterns.tsv").write_text(
        "secret\tDO-NOT-EXPORT\n", encoding="utf-8"
    )
    (ai / "shared" / "file.txt").write_text("version one\n", encoding="utf-8")
    for repo in (public, ai):
        run(["git", "init", "-b", "main"], repo)
        commit_all(repo, "initial")
    return public, ai, public / "utils" / "sync-repos.py"


@pytest.mark.parametrize("direction", ["from-ai", "to-ai"])
@pytest.mark.parametrize("mode", ["--check", "--apply"])
def test_working_source_rejects_symlinked_parent(tmp_path, direction, mode):
    public, ai, script = initialize_pair(tmp_path)
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    commit_all(public, "initial import")
    baseline = (public / ".sync-state.json").read_bytes()
    source_dir = ai / "shared" if direction == "from-ai" else public / "managed"
    target_file = public / "managed/file.txt" if direction == "from-ai" else ai / "shared/file.txt"
    target_before = target_file.read_bytes()
    external = tmp_path / "outside"
    external.mkdir()
    (external / "file.txt").write_text("outside repository\n")
    shutil.rmtree(source_dir)
    source_dir.symlink_to(external, target_is_directory=True)
    result = run(
        ["python3", str(script), direction, "--source" if direction == "from-ai" else "--target",
         str(ai), "--working-tree", mode], public, expected=2,
    )
    assert "symlink" in result.stderr
    assert target_file.read_bytes() == target_before
    assert (public / ".sync-state.json").read_bytes() == baseline


@pytest.mark.parametrize("overlap", ["ai", "public"])
def test_overlapping_mappings_are_rejected_before_writing(tmp_path, overlap):
    public, ai, script = initialize_pair(tmp_path)
    (ai / "other").mkdir()
    (ai / "other/file.txt").write_text("other content\n")
    commit_all(ai, "add second source")
    extra = ("shared/file.txt\tother/file.txt\tfile\n" if overlap == "ai"
             else "other/file.txt\tmanaged/file.txt\tfile\n")
    (public / "config/sync-manifest.tsv").write_text("shared\tmanaged\ttree\n" + extra)
    result = run(
        ["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public, expected=2,
    )
    assert "overlapping manifest" in result.stderr
    assert not (public / "managed").exists()
    assert not (public / "other").exists()
    assert not (public / ".sync-state.json").exists()


@pytest.mark.parametrize("state", [
    [], {"schema_version": 1, "files": []},
    {"schema_version": 1, "files": {"bad": "not a record"}},
    {"schema_version": 1, "files": {"bad": {"ai_path": [], "public_path": "x"}}},
    {"schema_version": 1, "files": {"bad": {"ai_path": "shared/file.txt", "public_path": "managed/file.txt", "fingerprint": None}}},
])
def test_malformed_state_fails_cleanly_without_writes(tmp_path, state):
    public, ai, script = initialize_pair(tmp_path)
    baseline = public / ".sync-state.json"
    baseline.write_text(json.dumps(state))
    before = baseline.read_bytes()
    result = run(
        ["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public, expected=2,
    )
    assert "sync state" in result.stderr
    assert "Traceback" not in result.stderr
    assert baseline.read_bytes() == before
    assert not (public / "managed").exists()


def test_directional_sync_is_idempotent_and_reversible(tmp_path: Path) -> None:
    public, ai, script = initialize_pair(tmp_path)
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    assert (public / "managed" / "file.txt").read_text() == "version one\n"
    check = run(
        ["python3", str(script), "from-ai", "--source", str(ai), "--check"], public
    )
    assert "unchanged=1" in check.stdout

    commit_all(public, "import shared file")
    (public / "managed" / "file.txt").write_text("public update\n", encoding="utf-8")
    commit_all(public, "public update")
    preview = run(
        ["python3", str(script), "to-ai", "--target", str(ai), "--check"], public, expected=1
    )
    assert "update" in preview.stdout
    run(["python3", str(script), "to-ai", "--target", str(ai), "--apply"], public)
    assert (ai / "shared" / "file.txt").read_text() == "public update\n"


@pytest.mark.parametrize("direction", ["from-ai", "to-ai"])
def test_source_deletion_requires_reviewed_opt_in(tmp_path, direction):
    public, ai, script = initialize_pair(tmp_path)
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    commit_all(public, "initial import")
    source = ai / "shared/file.txt" if direction == "from-ai" else public / "managed/file.txt"
    target = public / "managed/file.txt" if direction == "from-ai" else ai / "shared/file.txt"
    source.unlink()
    commit_all(ai if direction == "from-ai" else public, "delete source")
    args = ["python3", str(script), direction,
            "--source" if direction == "from-ai" else "--target", str(ai)]
    baseline = public / ".sync-state.json"
    before = baseline.read_bytes(), target.read_bytes()
    rejected = run([*args, "--apply"], public, expected=2)
    assert "without --allow-delete" in rejected.stderr
    assert (baseline.read_bytes(), target.read_bytes()) == before
    preview = run([*args, "--check", "--allow-delete"], public, expected=1)
    run([*args, "--apply", "--allow-delete", "--require-plan-hash", preview_hash(preview)], public)
    assert not target.exists()
    assert json.loads(baseline.read_text())["files"] == {}


def test_retired_mapping_does_not_reimport_file_from_old_baseline(tmp_path: Path) -> None:
    public, ai, script = initialize_pair(tmp_path)
    manifest = public / "config/sync-manifest.tsv"
    original = manifest.read_text()
    manifest.write_text(original + "shared/retired.sh\tutils/retired.sh\tfile\n")
    upstream = ai / "shared/retired.sh"
    upstream.write_text("old helper\n")
    commit_all(ai, "add helper")
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    baseline = json.loads((public / ".sync-state.json").read_text())
    assert "shared/retired.sh => utils/retired.sh" in baseline["files"]
    manifest.write_text(original)
    (public / "utils/retired.sh").unlink()
    preview = run(["python3", str(script), "from-ai", "--source", str(ai), "--check"], public)
    digest = next(line.split(": ", 1)[1] for line in preview.stdout.splitlines() if line.startswith("Plan SHA256:"))
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply",
         "--require-plan-hash", digest], public)
    assert upstream.exists()
    assert not (public / "utils/retired.sh").exists()
    assert "shared/retired.sh => utils/retired.sh" not in json.loads((public / ".sync-state.json").read_text())["files"]


def test_conflicting_changes_are_refused(tmp_path: Path) -> None:
    public, ai, script = initialize_pair(tmp_path)
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    commit_all(public, "import shared file")

    (ai / "shared" / "file.txt").write_text("private update\n", encoding="utf-8")
    commit_all(ai, "private update")
    (public / "managed" / "file.txt").write_text("public update\n", encoding="utf-8")
    commit_all(public, "public update")

    preview = run(
        ["python3", str(script), "from-ai", "--source", str(ai), "--check"],
        public,
        expected=1,
    )
    assert "conflict" in preview.stdout
    run(
        ["python3", str(script), "from-ai", "--source", str(ai), "--apply"],
        public,
        expected=2,
    )
    assert (public / "managed" / "file.txt").read_text() == "public update\n"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32", "binary"])
def test_policy_findings_block_apply(tmp_path: Path, encoding: str) -> None:
    public, ai, script = initialize_pair(tmp_path)
    data = b"binary\0DO-NOT-EXPORT" if encoding == "binary" else "DO-NOT-EXPORT\n".encode(encoding)
    (ai / "shared" / "file.txt").write_bytes(data)
    commit_all(ai, "add denied content")
    result = run(
        ["python3", str(script), "from-ai", "--source", str(ai), "--apply"],
        public,
        expected=2,
    )
    assert "policy-finding" in result.stderr
    assert not (public / "managed" / "file.txt").exists()
    log = public / ".local/public-checks.jsonl"
    record = json.loads(log.read_text())
    assert record["status"] == "findings"
    assert record["findings"][0]["rule"] == "secret"
    assert "DO-NOT-EXPORT" not in log.read_text()
    assert "managed/file.txt" not in log.read_text()
    run(["git", "check-ignore", ".local/public-checks.jsonl"], public)


def test_policy_checks_destination_filename(tmp_path: Path) -> None:
    public, ai, script = initialize_pair(tmp_path)
    (public / "config/sync-manifest.tsv").write_text(
        "shared/file.txt\tmanaged/DO-NOT-EXPORT.txt\tfile\n"
    )
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public, expected=2)
    assert not (public / "managed/DO-NOT-EXPORT.txt").exists()


@pytest.mark.parametrize("direction", ["from-ai", "to-ai"])
def test_reviewed_resolution_preserves_destination_and_future_conflicts(tmp_path: Path, direction: str) -> None:
    public, ai, script = initialize_pair(tmp_path)
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    (ai / "shared/file.txt").write_text("upstream two\n")
    (public / "managed/file.txt").write_text("reviewed public adaptation\n")
    commit_all(ai, "upstream two")
    commit_all(public, "reviewed adaptation")
    dest = "managed/file.txt" if direction == "from-ai" else "shared/file.txt"
    target = public if direction == "from-ai" else ai
    args = ["python3", str(script), direction, "--source" if direction == "from-ai" else "--target", str(ai)]
    original = (target / dest).read_bytes()
    state = (public / ".sync-state.json").read_bytes()
    preview = run([*args, "--check", "--diff", "--accept-resolved", dest], public, expected=1)
    assert "resolved" in preview.stdout and "--- destination/" in preview.stdout
    assert (public / ".sync-state.json").read_bytes() == state
    run([*args, "--apply", "--accept-resolved", dest], public)
    assert (target / dest).read_bytes() == original
    preview = run([*args, "--check"], public, expected=1)
    assert "reverse-needed" in preview.stdout and "conflict" not in preview.stdout
    source = ai if direction == "from-ai" else public
    source_path = "shared/file.txt" if direction == "from-ai" else "managed/file.txt"
    (source / source_path).write_text("new upstream change\n")
    commit_all(source, "next change")
    result = run([*args, "--apply"], public, expected=2)
    assert "conflict" in result.stdout
    assert (target / dest).read_bytes() == original


@pytest.mark.parametrize("content", ["DO-NOT-EXPORT\n", "<<<<<<< ours\nunmerged\n=======\nother\n>>>>>>> theirs\n"])
def test_resolution_rejects_unsafe_content_without_state_change(tmp_path: Path, content: str) -> None:
    public, ai, script = initialize_pair(tmp_path)
    args = ["python3", str(script), "from-ai", "--source", str(ai)]
    run([*args, "--apply"], public)
    before = (public / ".sync-state.json").read_bytes()
    (ai / "shared/file.txt").write_text("upstream two\n")
    commit_all(ai, "upstream two")
    (public / "managed/file.txt").write_text(content)
    run([*args, "--apply", "--accept-resolved", "managed/file.txt"], public, expected=2)
    assert (public / ".sync-state.json").read_bytes() == before
    assert (public / "managed/file.txt").read_text() == content


@pytest.mark.parametrize("dest", ["missing.txt", "managed/file.txt", "../outside.txt"])
def test_resolution_rejects_unknown_or_nonconflicting_paths(tmp_path: Path, dest: str) -> None:
    public, ai, script = initialize_pair(tmp_path)
    args = ["python3", str(script), "from-ai", "--source", str(ai)]
    run([*args, "--apply"], public)
    before = (public / ".sync-state.json").read_bytes()
    run([*args, "--apply", "--accept-resolved", dest], public, expected=2)
    assert (public / ".sync-state.json").read_bytes() == before


def test_symlink_parent_cannot_receive_import(tmp_path: Path) -> None:
    public, ai, script = initialize_pair(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (public / "managed").symlink_to(outside, target_is_directory=True)
    result = run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public, expected=2)
    assert "symlink" in result.stderr
    assert not (outside / "file.txt").exists()
    assert not (public / ".sync-state.json").exists()


def preview_hash(result: subprocess.CompletedProcess[str]) -> str:
    return next(line.split(": ", 1)[1] for line in result.stdout.splitlines() if line.startswith("Plan SHA256: "))


def test_reviewed_working_tree_plan_applies_with_same_hash(tmp_path: Path) -> None:
    public, ai, script = initialize_pair(tmp_path)
    args = ["python3", str(script), "from-ai", "--source", str(ai), "--working-tree"]
    (ai / "shared/file.txt").write_text("uncommitted source\n")
    preview = run([*args, "--check", "--diff"], public, expected=1)
    assert not (public / ".sync-state.json").exists()
    applied = run([*args, "--apply", "--require-plan-hash", preview_hash(preview)], public)
    assert preview_hash(applied) == preview_hash(preview)
    assert (public / "managed/file.txt").read_text() == "uncommitted source\n"


@pytest.mark.parametrize("mutation", [
    "source_content", "source_mode", "target_content", "target_mode", "new_file",
    "deletion", "policy", "manifest", "state", "revision", "allow_flag",
])
def test_reviewed_plan_rejects_drift_before_any_write(tmp_path: Path, mutation: str) -> None:
    public, ai, script = initialize_pair(tmp_path)
    (public / "config/sync-manifest.tsv").write_text("shared\tmanaged\ttree\n")
    args = [
        "python3", str(script), "from-ai", "--source", str(ai), "--working-tree",
        "--allow-reverse-pending", "--allow-delete", "--allow-policy-findings",
    ]
    run([*args, "--apply"], public)
    source, target = ai / "shared/file.txt", public / "managed/file.txt"
    source.write_text("planned update\n")
    preview = run([*args, "--check"], public, expected=1)
    if mutation == "source_content":
        source.write_text("changed after review\n")
    elif mutation == "source_mode":
        source.chmod(0o755)
    elif mutation == "target_content":
        target.write_text("destination work after review\n")
    elif mutation == "target_mode":
        target.chmod(0o755)
    elif mutation == "new_file":
        (ai / "shared/new.txt").write_text("new file after review\n")
    elif mutation == "deletion":
        source.unlink()
    elif mutation == "policy":
        with (public / "config/public-deny-patterns.tsv").open("a") as handle:
            handle.write("new-policy\tNEVER-MATCHES\n")
    elif mutation == "manifest":
        with (public / "config/sync-manifest.tsv").open("a") as handle:
            handle.write("other\tmanaged-other\ttree\n")
    elif mutation == "state":
        path = public / ".sync-state.json"
        state = json.loads(path.read_text())
        state["last_source_revision"] = "changed after review"
        path.write_text(json.dumps(state))
    elif mutation == "revision":
        commit_all(ai, "commit reviewed bytes")
    elif mutation == "allow_flag":
        args.remove("--allow-delete")
    before = target.read_bytes(), target.stat().st_mode, (public / ".sync-state.json").read_bytes()
    rejected = run([*args, "--apply", "--require-plan-hash", preview_hash(preview)], public, expected=2)
    assert "reviewed plan has changed" in rejected.stderr
    assert (target.read_bytes(), target.stat().st_mode, (public / ".sync-state.json").read_bytes()) == before
    assert not (public / "managed/new.txt").exists()


def test_reviewed_plan_covers_resolution_acknowledgement(tmp_path: Path) -> None:
    public, ai, script = initialize_pair(tmp_path)
    args = ["python3", str(script), "from-ai", "--source", str(ai), "--working-tree"]
    run([*args, "--apply"], public)
    (ai / "shared/file.txt").write_text("new upstream content\n")
    (public / "managed/file.txt").write_text("manually merged content\n")
    preview = run([*args, "--check"], public, expected=1)
    before = (public / ".sync-state.json").read_bytes()
    result = run([
        *args, "--apply", "--accept-resolved", "managed/file.txt",
        "--require-plan-hash", preview_hash(preview),
    ], public, expected=2)
    assert "reviewed plan has changed" in result.stderr
    assert (public / ".sync-state.json").read_bytes() == before


def test_committed_reads_batch_only_managed_blobs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    public, ai, script = initialize_pair(tmp_path)
    (public / "config/sync-manifest.tsv").write_text(
        "shared\tmanaged\ttree\nextra.txt\tmanaged-extra.txt\tfile\n"
    )
    contents = {
        "file.txt": b"version one\n",
        "path with spaces.txt": b"no trailing newline",
        "line\nname.bin": b"\x00\xff\nbytes\x00",
        "empty": b"",
        "executable.sh": b"#!/bin/sh\nexit 0\n",
    }
    for name, data in contents.items():
        (ai / "shared" / name).write_bytes(data)
    (ai / "shared/executable.sh").chmod(0o755)
    (ai / "extra.txt").write_text("separate mapping\n")
    (ai / "unmanaged.txt").write_text("DO-NOT-EXPORT private content\n")
    (ai / "unmanaged-link").symlink_to("unmanaged.txt")
    commit_all(ai, "add managed and unmanaged fixtures")
    spec = importlib.util.spec_from_file_location("sync_under_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    original_run_git = module.run_git
    calls = []

    def record_git(repo, arguments, **kwargs):
        calls.append((arguments, kwargs))
        return original_run_git(repo, arguments, **kwargs)

    monkeypatch.setattr(module, "run_git", record_git)
    assert module.main(["from-ai", "--source", str(ai), "--apply"]) == 0
    for name, data in contents.items():
        assert (public / "managed" / name).read_bytes() == data
    assert os.access(public / "managed/executable.sh", os.X_OK)
    assert (public / "managed-extra.txt").read_text() == "separate mapping\n"
    assert not (public / "unmanaged.txt").exists()
    assert sum(arguments[0] == "ls-tree" for arguments, _ in calls) == 1
    assert sum(arguments[0] == "ls-files" for arguments, _ in calls) == 1
    assert not any(arguments[0] == "show" for arguments, _ in calls)
    batches = [kwargs["input_data"] for arguments, kwargs in calls if arguments[0] == "cat-file"]
    assert len(batches) == 1 and len(batches[0].splitlines()) == len(contents) + 1
    private_id = run(["git", "rev-parse", "HEAD:unmanaged.txt"], ai).stdout.strip().encode()
    assert private_id not in batches[0].splitlines()

    (ai / "shared/file.txt").rename(ai / "shared/renamed.txt")
    commit_all(ai, "rename managed file")
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply", "--allow-delete"], public)
    assert not (public / "managed/file.txt").exists()
    assert (public / "managed/renamed.txt").read_bytes() == contents["file.txt"]


def test_private_setup_routing_is_removed_before_policy_and_baseline(tmp_path):
    public, ai, script = initialize_pair(tmp_path)
    rel = "skills/velociraptor-engagement-setup/SKILL.md"
    (public / "config/sync-manifest.tsv").write_text(f"{rel}\t{rel}\tfile\n")
    source = ai / rel
    source.parent.mkdir(parents=True)
    private = "DO-NOT-EXPORT local routing <!-- private-setup-routing -->\n"
    source.write_text("# Setup\n" + private + "Shared instructions\n")
    commit_all(ai, "private routing")
    commit_all(public, "setup mapping")
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    assert (public / rel).read_text() == "# Setup\nShared instructions\n"
    assert private in source.read_text()
    result = run(["python3", str(script), "from-ai", "--source", str(ai), "--check"], public)
    assert "unchanged=1" in result.stdout
    # A reverse update cannot silently discard the local routing.
    (public / rel).write_text("# Setup\nChanged public instructions\n")
    result = run(["python3", str(script), "to-ai", "--target", str(ai), "--working-tree", "--check"], public, expected=1)
    assert "conflict" in result.stdout
    assert private in source.read_text()


def test_package_layout_paths_are_rewritten_and_compared_in_public_layout(tmp_path):
    public, ai, script = initialize_pair(tmp_path)
    (public / "config/sync-manifest.tsv").write_text(
        "skills\tskills\ttree\npackages/vraptor/docs/reference\tdocs/reference\ttree\n"
        "packages/vraptor/docs/contracts\tdocs/contracts\ttree\n"
    )
    skill, ref = ai / "skills/demo/SKILL.md", ai / "packages/vraptor/docs/reference/demo.md"
    contract = ai / "packages/vraptor/docs/contracts/public-import.md"
    for path in (skill, ref, contract):
        path.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text(
        "See [policy](../../packages/vraptor/docs/reference/demo.md) and "
        "`packages/vraptor/src/vraptor/cli.py`.\nfrom packages.vraptor.tests.core import x\n"
    )
    ref.write_text(
        "[setup](../../../../docs/setup.md) [cli](../contracts/cli.md) [config](../../../../CONFIG.md)\n"
    )
    contract.write_text("| `packages/vraptor/src/vraptor` | `src/vraptor` |\n")
    commit_all(ai, "layout content")
    commit_all(public, "layout mapping")
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    assert (public / "skills/demo/SKILL.md").read_text() == (
        "See [policy](../../docs/reference/demo.md) and `src/vraptor/cli.py`.\n"
        "from tests.core import x\n"
    )
    imported_ref = "[setup](../setup.md) [cli](../contracts/cli.md) [config](../../CONFIG.md)\n"
    assert (public / "docs/reference/demo.md").read_text() == imported_ref
    assert (public / "docs/contracts/public-import.md").read_text() == contract.read_text()
    commit_all(public, "import layout content")
    result = run(["python3", str(script), "to-ai", "--target", str(ai), "--check"], public)
    assert "unchanged=3" in result.stdout
    # Reverse imports never guess at ai_skills package paths, including package
    # doc links that leave the docs folder.
    (public / "docs/reference/demo.md").write_text("[config](../../CONFIG.md) [cli](../contracts/cli.md)\n")
    (public / "skills/demo/SKILL.md").write_text("Edited `src/vraptor/cli.py`.\n")
    commit_all(public, "public layout edit")
    before = skill.read_bytes(), ref.read_bytes()
    result = run(["python3", str(script), "to-ai", "--target", str(ai), "--apply"], public, expected=2)
    assert "manual port to ai_skills: packages/vraptor/docs/reference/demo.md" in result.stderr
    (public / "docs/reference/demo.md").write_text(imported_ref)
    commit_all(public, "restore reference")
    result = run(["python3", str(script), "to-ai", "--target", str(ai), "--apply"], public, expected=2)
    assert "manual port to ai_skills: skills/demo/SKILL.md" in result.stderr
    assert (skill.read_bytes(), ref.read_bytes()) == before


def test_tree_exclude_globs_skip_matching_files(tmp_path):
    public, ai, script = initialize_pair(tmp_path)
    (public / "config/sync-manifest.tsv").write_text("shared\tmanaged\ttree\t*.pdf, private/*\n")
    (ai / "shared/private").mkdir()
    (ai / "shared/guide.pdf").write_bytes(b"%PDF-1.7\n")
    (ai / "shared/private/__init__.py").write_text('"""Local marker."""\n')
    commit_all(ai, "excluded content")
    commit_all(public, "exclude mapping")
    result = run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    assert "add=1" in result.stdout
    assert sorted(p.relative_to(public).as_posix() for p in (public / "managed").rglob("*")) == [
        "managed/file.txt"
    ]


@pytest.mark.parametrize("row", ["a\tb\tfile\t*.pdf", "a\tb\ttree\t*.pdf,", "a\tb\ttree\t*\textra"])
def test_invalid_exclude_rows_are_rejected(tmp_path, row):
    public, ai, script = initialize_pair(tmp_path)
    (public / "config/sync-manifest.tsv").write_text(row + "\n")
    result = run(["python3", str(script), "from-ai", "--source", str(ai), "--check"], public, expected=2)
    assert "sync-manifest.tsv:1" in result.stderr


def test_dirty_excluded_source_does_not_block_committed_sync(tmp_path):
    public, ai, script = initialize_pair(tmp_path)
    (public / "config/sync-manifest.tsv").write_text("shared\tmanaged\ttree\tlocal/*\n")
    commit_all(public, "exclude mapping")
    (ai / "shared/local").mkdir()
    (ai / "shared/local/notes.txt").write_text("uncommitted local notes\n")
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    assert (public / "managed/file.txt").read_text() == "version one\n"
    (ai / "shared/file.txt").write_text("dirty managed edit\n")
    result = run(["python3", str(script), "from-ai", "--source", str(ai), "--check"], public, expected=2)
    assert "managed source paths are dirty" in result.stderr
    assert "shared/local" not in result.stderr


def initialize_held_pair(tmp_path: Path) -> tuple[Path, Path, Path]:
    public, ai, script = initialize_pair(tmp_path)
    (public / "config" / "sync-manifest.tsv").write_text(
        "shared/file.txt\tmanaged/file.txt\tfile\nshared/held.txt\tmanaged/held.txt\tfile\n",
        encoding="utf-8",
    )
    (ai / "shared" / "held.txt").write_text("default one\n", encoding="utf-8")
    commit_all(ai, "add held file")
    commit_all(public, "manage held file")
    run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public)
    (ai / "shared" / "held.txt").write_text("ai default\n", encoding="utf-8")
    (public / "managed" / "held.txt").write_text("public default\n", encoding="utf-8")
    commit_all(ai, "ai default")
    commit_all(public, "public default")
    return public, ai, script


def upstream_fingerprint(ai: Path) -> str:
    digest = hashlib.sha256((ai / "shared" / "held.txt").read_bytes()).hexdigest()
    return f"sha256:{digest};mode:100644"


def hold(public: Path, ai: Path) -> None:
    row = f"managed/held.txt\t{upstream_fingerprint(ai)}\treviewed adaptation\n"
    (public / "config" / "sync-held.tsv").write_text(row, encoding="utf-8")
    commit_all(public, "hold files")


@pytest.mark.parametrize("direction", ["from-ai", "to-ai"])
def test_held_file_is_reported_and_never_written(tmp_path: Path, direction: str) -> None:
    public, ai, script = initialize_held_pair(tmp_path)
    if direction == "from-ai":
        # Without the held row, the conflict would block every other import.
        run(["python3", str(script), "from-ai", "--source", str(ai), "--apply"], public, expected=2)
    hold(public, ai)
    source = ai if direction == "from-ai" else public
    source_path = "shared/file.txt" if direction == "from-ai" else "managed/file.txt"
    (source / source_path).write_text("version two\n", encoding="utf-8")
    commit_all(source, "version two")
    args = ["python3", str(script), direction, "--source" if direction == "from-ai" else "--target", str(ai)]

    preview = run([*args, "--check", "--diff"], public, expected=1)
    reported = "managed/held.txt" if direction == "from-ai" else "shared/held.txt"
    assert f"held            {reported}" in preview.stdout
    assert ("+ai default" if direction == "from-ai" else "+public default") in preview.stdout
    result = run([*args, "--apply"], public)
    assert "Left held files untouched: 1" in result.stdout
    assert (public / "managed/file.txt").read_text() == "version two\n"
    assert (ai / "shared/file.txt").read_text() == "version two\n"
    assert (public / "managed/held.txt").read_text() == "public default\n"
    assert (ai / "shared/held.txt").read_text() == "ai default\n"
    # With only held differences left, a check reports nothing to do.
    run([*args, "--check"], public)


@pytest.mark.parametrize("direction", ["from-ai", "to-ai"])
def test_held_file_survives_reverse_apply_after_resolution(tmp_path: Path, direction: str) -> None:
    public, ai, script = initialize_held_pair(tmp_path)
    resolve = "managed/held.txt" if direction == "from-ai" else "shared/held.txt"
    first = ["python3", str(script), direction, "--source" if direction == "from-ai" else "--target", str(ai)]
    run([*first, "--apply", "--accept-resolved", resolve], public)
    reverse = "to-ai" if direction == "from-ai" else "from-ai"
    second = ["python3", str(script), reverse, "--target" if reverse == "to-ai" else "--source", str(ai)]
    # The moved baseline makes the other direction a plain update ...
    assert "update" in run([*second, "--check"], public, expected=1).stdout
    hold(public, ai)
    # ... which the held row turns into a report.
    run([*second, "--apply"], public)
    assert (public / "managed/held.txt").read_text() == "public default\n"
    assert (ai / "shared/held.txt").read_text() == "ai default\n"


def test_held_file_cannot_be_accept_resolved(tmp_path: Path) -> None:
    public, ai, script = initialize_held_pair(tmp_path)
    hold(public, ai)
    result = run(
        ["python3", str(script), "from-ai", "--source", str(ai), "--apply", "--accept-resolved", "managed/held.txt"],
        public,
        expected=2,
    )
    assert "held files are ported by hand" in result.stderr


FINGERPRINT = "sha256:" + "0" * 64 + ";mode:100644"


@pytest.mark.parametrize("row", [
    f"managed/missing.txt\t{FINGERPRINT}\tgone\n",
    "managed/held.txt\treason\n",
    f"../held.txt\t{FINGERPRINT}\tescape\n",
    "managed/held.txt\tnot-a-fingerprint\treason\n",
])
def test_invalid_held_rows_are_rejected(tmp_path: Path, row: str) -> None:
    public, ai, script = initialize_held_pair(tmp_path)
    (public / "config" / "sync-held.tsv").write_text(row, encoding="utf-8")
    commit_all(public, "bad held row")
    run(["python3", str(script), "from-ai", "--source", str(ai), "--check"], public, expected=2)
    assert (public / "managed/held.txt").read_text() == "public default\n"


def test_upstream_change_to_held_file_needs_review(tmp_path: Path) -> None:
    public, ai, script = initialize_held_pair(tmp_path)
    hold(public, ai)
    (ai / "shared" / "held.txt").write_text("ai fix\n", encoding="utf-8")
    commit_all(ai, "upstream fix")
    args = ["python3", str(script), "from-ai", "--source", str(ai)]
    preview = run([*args, "--check"], public, expected=1)
    assert f"held-changed    managed/held.txt (upstream {upstream_fingerprint(ai)})" in preview.stdout
    result = run([*args, "--apply"], public, expected=2)
    assert "port them by hand" in result.stderr
    assert (public / "managed/held.txt").read_text() == "public default\n"
    # Recording the reviewed upstream fingerprint returns the file to held.
    hold(public, ai)
    run([*args, "--apply"], public)
    assert (public / "managed/held.txt").read_text() == "public default\n"


def test_committed_held_list_keeps_ai_setup_defaults() -> None:
    from sync_policy import load_held, load_manifest

    held = load_held(ROOT / "config" / "sync-held.tsv")
    managed = load_manifest(ROOT / "config" / "sync-manifest.tsv")
    for path in held:
        assert (ROOT / path).is_file(), path
        assert any(
            path == row.public_path or (row.kind == "tree" and path.startswith(row.public_path + "/"))
            for row in managed
        ), path
    # These carry the per-repository AI setup defaults; a sync must not flip them.
    assert {
        "docs/model-execution.md",
        "src/vraptor/agent/manage.py",
        "src/vraptor/settings.py",
        "tests/test_agent_setup_defaults.py",
        "tests/test_operational_connection_options.py",
        "tests/test_vraptor_settings.py",
    } <= set(held)

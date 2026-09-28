from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCRIPT = REPO_ROOT / "utils" / "link-codex-agents.sh"


class LinkCodexAgentsShellTest(unittest.TestCase):
    def make_workspace(self) -> tuple[tempfile.TemporaryDirectory, Path, Path, Path]:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name)
        script = root / "repo" / "utils" / "link-codex-agents.sh"
        script.parent.mkdir(parents=True)
        shutil.copy2(SOURCE_SCRIPT, script)
        script.chmod(0o755)
        source = root / "agents"
        source.mkdir()
        (source / "case-manager.toml").write_text(
            'name = "case-manager"\n', encoding="utf-8"
        )
        (source / "README.md").write_text("not an agent\n", encoding="utf-8")
        codex_home = root / "codex-home"
        return temp_dir, script, source, codex_home

    def run_script(self, script: Path, source: Path, codex_home: Path, *args: str):
        return subprocess.run(
            [str(script), *args],
            cwd=script.parents[2],
            env={
                **os.environ,
                "AI_SKILLS_AGENTS_DIR": str(source),
                "CODEX_HOME": str(codex_home),
            },
            text=True,
            capture_output=True,
            check=False,
        )

    def test_dry_run_does_not_create_destination(self):
        _temp, script, source, codex_home = self.make_workspace()

        result = self.run_script(script, source, codex_home, "--dry-run")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Would link:", result.stdout)
        self.assertIn("(dry run)", result.stdout)
        self.assertFalse(codex_home.exists())

    def test_links_only_toml_and_is_idempotent(self):
        _temp, script, source, codex_home = self.make_workspace()

        first = self.run_script(script, source, codex_home)
        second = self.run_script(script, source, codex_home)

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        destination = codex_home / "agents" / "case-manager.toml"
        self.assertTrue(destination.is_symlink())
        self.assertEqual(destination.resolve(), (source / "case-manager.toml").resolve())
        self.assertFalse((codex_home / "agents" / "README.md").exists())
        self.assertIn("unchanged=1", second.stdout)

    def test_refuses_to_replace_real_file(self):
        _temp, script, source, codex_home = self.make_workspace()
        destination = codex_home / "agents" / "case-manager.toml"
        destination.parent.mkdir(parents=True)
        destination.write_text("operator-owned\n", encoding="utf-8")

        result = self.run_script(script, source, codex_home)

        self.assertEqual(result.returncode, 1)
        self.assertIn("Conflict: refusing to replace", result.stderr)
        self.assertEqual(destination.read_text(encoding="utf-8"), "operator-owned\n")

    def test_retired_links_are_removed_only_when_owned_by_this_checkout(self):
        _temp, script, source, codex_home = self.make_workspace()
        (source / "case-manager.toml").unlink()
        (source / "setup-agent.toml").write_text('name = "setup-agent"\n')
        destination = codex_home / "agents"
        destination.mkdir(parents=True)
        (destination / "case-manager.toml").symlink_to(source / "case-manager.toml")
        (destination / "scribe-agent.toml").write_text('operator owned')
        preview = self.run_script(script, source, codex_home, "--dry-run")
        self.assertEqual(preview.returncode, 0)
        self.assertTrue((destination / "case-manager.toml").is_symlink())
        result = self.run_script(script, source, codex_home)
        self.assertEqual(result.returncode, 0)
        self.assertFalse((destination / "case-manager.toml").is_symlink())
        self.assertEqual((destination / "scribe-agent.toml").read_text(), 'operator owned')


if __name__ == "__main__":
    unittest.main()

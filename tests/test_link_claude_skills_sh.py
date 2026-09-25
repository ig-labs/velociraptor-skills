from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "utils" / "link-claude-skills.sh"


class LinkClaudeSkillsShellTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="claude skills ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source skills"
        self.source.mkdir()
        self.skill = self.source / "example"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text("example\n")
        (self.source / "not-a-skill").mkdir()
        self.destination = self.root / "home" / ".claude" / "skills"
        self.env = {
            **os.environ,
            "HOME": str(self.root / "home"),
            "AI_SKILLS_SKILLS_DIR": "source skills",
        }
        self.env.pop("AI_SKILLS_CLAUDE_SKILLS_DIR", None)

    def run_script(self, *args):
        return subprocess.run(
            [str(SCRIPT), *args], cwd=self.root, env=self.env,
            text=True, capture_output=True, check=False,
        )

    def test_dry_run_does_not_create_home(self):
        result = self.run_script("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Would link:", result.stdout)
        self.assertFalse((self.root / "home").exists())

    def test_default_destination_absolute_links_and_idempotence(self):
        first = self.run_script()
        second = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        destination = self.destination / "example"
        self.assertTrue(destination.is_symlink())
        self.assertEqual(destination.resolve(), self.skill.resolve())
        self.assertTrue(Path(os.readlink(destination)).is_absolute())
        self.assertFalse((self.destination / "not-a-skill").exists())
        self.assertIn("unchanged=1", second.stdout)
        self.assertFalse((self.root / "home" / ".zshrc").exists())

    def test_preserves_real_files_directories_and_unrelated_links(self):
        self.destination.mkdir(parents=True)
        destination = self.destination / "example"
        unrelated = self.destination / "other"
        unrelated.symlink_to(self.root / "missing")
        for directory in (False, True):
            with self.subTest(directory=directory):
                if directory:
                    destination.mkdir()
                    sentinel = destination / "keep"
                else:
                    sentinel = destination
                sentinel.write_text("operator owned\n")
                result = self.run_script()
                self.assertEqual(result.returncode, 1)
                self.assertIn("Conflict:", result.stderr)
                self.assertEqual(sentinel.read_text(), "operator owned\n")
                self.assertTrue(unrelated.is_symlink())
                sentinel.unlink()
                if directory:
                    destination.rmdir()

    def test_updates_existing_and_broken_links_only_after_preview(self):
        self.destination.mkdir(parents=True)
        old_source = self.root / "old skill"
        old_source.mkdir()
        (old_source / "keep").write_text("preserve\n")
        destination = self.destination / "example"
        for target in (old_source, self.root / "missing"):
            with self.subTest(target=target):
                destination.symlink_to(target)
                preview = self.run_script("--dry-run")
                self.assertEqual(preview.returncode, 0, preview.stderr)
                self.assertEqual(os.readlink(destination), str(target))
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(destination.resolve(), self.skill.resolve())
                self.assertEqual((old_source / "keep").read_text(), "preserve\n")
                self.assertFalse((old_source / "example").exists())
                destination.unlink()

    def test_destination_override(self):
        self.env["AI_SKILLS_CLAUDE_SKILLS_DIR"] = str(self.root / "custom skills")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "custom skills" / "example").resolve(),
                         self.skill.resolve())
        self.assertFalse(self.destination.exists())

    def test_invalid_source_and_arguments_do_not_write(self):
        invalid = self.run_script("--unknown")
        self.assertEqual(invalid.returncode, 2)
        self.env["AI_SKILLS_SKILLS_DIR"] = str(self.root / "missing")
        missing = self.run_script()
        self.assertEqual(missing.returncode, 1)
        self.assertIn("Skills directory not found", missing.stderr)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()

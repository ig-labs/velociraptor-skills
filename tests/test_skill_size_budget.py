from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_LINES = 500
MAX_BYTES = 30_000


def budgeted_skill_files() -> list[Path]:
    skills = REPO_ROOT / "skills"
    paths = sorted(skills.glob("velociraptor-*/SKILL.md"))
    prep = skills / "prep-dfir-tools" / "SKILL.md"
    if prep.is_file():
        paths.append(prep)
    return paths


class SkillSizeBudgetTest(unittest.TestCase):
    def test_budgeted_skills_are_present(self):
        self.assertTrue(budgeted_skill_files(), "no Velociraptor SKILL.md files found")

    def test_skill_files_stay_within_budget(self):
        for path in budgeted_skill_files():
            relative = path.relative_to(REPO_ROOT).as_posix()
            data = path.read_bytes()
            lines = len(data.decode("utf-8").splitlines())
            with self.subTest(skill=relative):
                self.assertLessEqual(
                    lines,
                    MAX_LINES,
                    f"{relative} has {lines} lines; the budget is {MAX_LINES}. "
                    "Move detail to a linked references/ file.",
                )
                self.assertLessEqual(
                    len(data),
                    MAX_BYTES,
                    f"{relative} has {len(data)} bytes; the budget is {MAX_BYTES}. "
                    "Move detail to a linked references/ file.",
                )


if __name__ == "__main__":
    unittest.main()

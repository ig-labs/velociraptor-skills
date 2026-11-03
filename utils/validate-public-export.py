#!/usr/bin/env python3
"""Run public-release policy, syntax and offline runtime checks."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from public_audit import append_audit, finding_metadata
from sync_policy import PolicyError, load_deny_patterns, load_held, load_manifest, load_state


REPO_ROOT = Path(__file__).resolve().parents[1]
DENY_FILE = REPO_ROOT / "config" / "public-deny-patterns.tsv"
MANIFEST = REPO_ROOT / "config" / "sync-manifest.tsv"
HELD = REPO_ROOT / "config" / "sync-held.tsv"
STATE = REPO_ROOT / ".sync-state.json"
GOLDEN_DB = REPO_ROOT / "src" / "vraptor" / "resources" / "golden" / "autoruns-golden.sqlite"
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SECRET_NAMES = re.compile(r"(?:KEY|TOKEN|PASSWORD|SECRET)$")
# Release-gate wording for each sync_policy problem reason.
MANIFEST_ERRORS = {
    "row": "invalid manifest row: {manifest}:{line}",
    "ai_path": "unsafe manifest source: {value}",
    "public_path": "unsafe manifest target: {value}",
    "overlap": "overlapping manifest paths at line {line}",
    "duplicate": "duplicate manifest path at line {line}",
    "empty": "manifest has no mappings",
}
HELD_ERRORS = {
    "row": "invalid held row: {held}:{line}",
    "path": "unsafe held path: {value}",
    "fingerprint": "invalid reviewed fingerprint at held line {line}",
    "duplicate": "duplicate held path at line {line}",
}
STATE_ERRORS = {
    "schema": "sync state has an unsupported schema",
    "record": "invalid sync state record {line}",
    "paths": "invalid sync state paths or key in record {line}",
    "fingerprint": "invalid sync fingerprint in record {line}",
}


def git_files() -> list[Path]:
    proc = subprocess.run(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [REPO_ROOT / raw.decode("utf-8") for raw in proc.stdout.split(b"\0") if raw]


def has_symlink(path: Path) -> bool:
    relative = path.relative_to(REPO_ROOT)
    return any((REPO_ROOT / part).is_symlink() for part in (relative, *relative.parents))


def check_deny_patterns(files: list[Path], errors: list[str]) -> list[tuple[str, str]]:
    patterns = load_deny_patterns(DENY_FILE)
    findings: list[tuple[str, str]] = []
    excluded = {DENY_FILE}
    for path in files:
        if path in excluded or has_symlink(path) or not path.is_file():
            continue
        data = path.read_bytes()
        # Include binary resources and large files, including SQLite free pages.
        # Removing NULs also exposes ASCII markers embedded in UTF-16/32 data.
        text = data.replace(b"\0", b"").decode("utf-8", "replace")
        for label, pattern in patterns:
            if pattern.search(text) or pattern.search(path.relative_to(REPO_ROOT).as_posix()):
                errors.append(f"deny pattern {label}: {path.relative_to(REPO_ROOT)}")
                findings.append((path.relative_to(REPO_ROOT).as_posix(), label))
    return findings


def check_paths(files: list[Path], errors: list[str]) -> None:
    forbidden_names = {".env", "api_client.yaml", "server.config.yaml", "client.config.yaml"}
    for path in files:
        relative = path.relative_to(REPO_ROOT)
        if relative.parts[0] == ".local":
            errors.append(f"local audit state must not be published: {relative}")
        if has_symlink(path):
            errors.append(f"symlink is not permitted: {relative}")
        if (path.name in forbidden_names
                or path.name.startswith(".env.")
                or path.name.endswith("_api_client.yaml")
                or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}):
            errors.append(f"forbidden configuration filename: {relative}")
        if "IR-Guidebook-Final.pdf" in relative.parts:
            errors.append(f"excluded PDF is present: {relative}")


def parse_frontmatter(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        errors.append(f"missing YAML frontmatter: {path.relative_to(REPO_ROOT)}")
        return
    try:
        end = lines.index("---", 1)
    except ValueError:
        errors.append(f"unterminated YAML frontmatter: {path.relative_to(REPO_ROOT)}")
        return
    fields: dict[str, str] = {}
    for line in lines[1:end]:
        if ":" in line and not line.startswith((" ", "\t")):
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    expected = path.parent.name
    if fields.get("name") != expected:
        errors.append(f"skill name mismatch in {path.relative_to(REPO_ROOT)}")
    if not fields.get("description"):
        errors.append(f"skill description is missing in {path.relative_to(REPO_ROOT)}")


def check_markdown_links(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for raw_target in MARKDOWN_LINK.findall(text):
        target = raw_target.strip().strip("<>").split("#", 1)[0].split("?", 1)[0]
        if not target or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target) or target.startswith("/"):
            continue
        if any(char in target for char in ("{", "}", "*")):
            continue
        candidate = (path.parent / target).resolve()
        try:
            candidate.relative_to(REPO_ROOT)
        except ValueError:
            errors.append(f"relative link escapes repository: {path.relative_to(REPO_ROOT)}")
            continue
        if not candidate.exists():
            errors.append(
                f"broken relative link: {path.relative_to(REPO_ROOT)} -> {raw_target}"
            )


def check_env(errors: list[str]) -> None:
    path = REPO_ROOT / "config" / "example.env"
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if SECRET_NAMES.search(key) and value.strip():
            errors.append(f"secret-like example value must be empty: config/example.env:{number} ({key})")


def check_state(errors: list[str]) -> None:
    # A fresh checkout has no local synchronization baseline yet; load_state
    # treats it as empty.
    problems: list[PolicyError] = []
    try:
        load_state(STATE, problems)
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid sync state: {exc}")
        return
    errors.extend(STATE_ERRORS[problem.reason].format(line=problem.line) for problem in problems)


def check_manifest(errors: list[str]) -> None:
    problems: list[PolicyError] = []
    load_manifest(MANIFEST, problems)
    errors.extend(
        MANIFEST_ERRORS[problem.reason].format(
            manifest=MANIFEST.relative_to(REPO_ROOT), line=problem.line, value=problem.value
        )
        for problem in problems
    )


def check_held(errors: list[str]) -> None:
    problems: list[PolicyError] = []
    held = load_held(HELD, problems)
    errors.extend(
        HELD_ERRORS[problem.reason].format(held=HELD.relative_to(REPO_ROOT), line=problem.line, value=problem.value)
        for problem in problems
    )
    mappings = load_manifest(MANIFEST, []) if MANIFEST.is_file() else []
    for path in held:
        if not (REPO_ROOT / path).is_file():
            errors.append(f"held path is not a file: {path}")
        elif not any(managed(mapping, path) for mapping in mappings):
            errors.append(f"held path is not a managed file: {path}")


def managed(mapping, path: str) -> bool:
    """Match synchronization's file pairing, including tree exclude globs."""
    if mapping.kind == "file":
        return path == mapping.public_path
    suffix = path[len(mapping.public_path) + 1:] if path.startswith(mapping.public_path + "/") else ""
    return bool(suffix) and not any(fnmatch.fnmatchcase(suffix, glob) for glob in mapping.exclude)


def check_database(errors: list[str]) -> None:
    if not GOLDEN_DB.is_file():
        errors.append(f"missing Autoruns GoldenDB: {GOLDEN_DB.relative_to(REPO_ROOT)}")
        return
    try:
        with sqlite3.connect(f"file:{GOLDEN_DB}?mode=ro", uri=True) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as exc:
        errors.append(f"Autoruns GoldenDB could not be opened read-only: {exc}")
        return
    if not result or result[0] != "ok":
        errors.append("Autoruns GoldenDB integrity_check did not return ok")


def validate_static() -> int:
    errors: list[str] = []
    files = git_files()
    check_paths(files, errors)
    findings = []
    if has_symlink(DENY_FILE):
        errors.append("deny-pattern configuration must not use symlinks")
    else:
        # Keep checking local baseline contents even though Git ignores them.
        scan_files = files if STATE in files else [*files, STATE]
        findings = check_deny_patterns(scan_files, errors)
    for path, check in (
        (REPO_ROOT / "config/example.env", check_env), (STATE, check_state),
        (MANIFEST, check_manifest), (HELD, check_held), (GOLDEN_DB, check_database),
    ):
        if has_symlink(path):
            errors.append(f"validation input must not use symlinks: {path.relative_to(REPO_ROOT)}")
        else:
            check(errors)
    for skill_file in sorted((REPO_ROOT / "skills").glob("*/SKILL.md")):
        if not has_symlink(skill_file):
            parse_frontmatter(skill_file, errors)
    for path in files:
        if path.suffix.lower() == ".md" and not has_symlink(path) and path.is_file():
            check_markdown_links(path, errors)
    append_audit(
        REPO_ROOT,
        check="public-export-static",
        status="failed" if errors else "passed",
        files=len(files),
        errors=len(errors),
        findings=finding_metadata(findings),
    )
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        print(f"Public export validation failed: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(
        f"Public export static validation passed: files={len(files)} "
        f"skills={len(list((REPO_ROOT / 'skills').glob('*/SKILL.md')))} database=ok"
    )
    return 0


def validate_runtime() -> None:
    """Retain the syntax and smoke checks formerly run by the shell entrypoint."""
    def run(command: list[str], *, env: dict[str, str] | None = None,
            show_output: bool = False) -> None:
        subprocess.run(command, cwd=REPO_ROOT, env=env, check=True,
                       stdout=None if show_output else subprocess.DEVNULL)

    for script in sorted(REPO_ROOT.rglob("*.sh")):
        if script.is_file() and not script.is_symlink():
            run(["bash", "-n", str(script)])
    run([sys.executable, "-m", "compileall", "-q",
         str(REPO_ROOT / "src/vraptor"), str(REPO_ROOT / "utils")], show_output=True)

    for launcher, arguments in (
        ("dfir", ["--help"]),
        ("dfir", ["tools", "prep", "--help"]),
        ("dfir", ["velociraptor", "--help"]),
        ("vraptor", ["--help"]),
        ("vraptor", ["agent", "config", "--view", "defaults"]),
        ("vraptor", ["tools", "prep", "--help"]),
    ):
        run([str(REPO_ROOT / launcher), *arguments])

    python = REPO_ROOT / ".venv/bin/python3"
    validation_python = str(python) if os.access(python, os.X_OK) else sys.executable
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    run([validation_python, "-c",
         "from vraptor.agent.profiles import load_agent_profile_config; load_agent_profile_config()"],
        env=env)

    with tempfile.TemporaryDirectory(prefix="vraptor-link-check-") as codex_home:
        env = dict(os.environ, CODEX_HOME=codex_home)
        for name in ("link-codex-skills.sh", "link-codex-agents.sh"):
            run([str(REPO_ROOT / "utils" / name), "--dry-run"], env=env)


def main() -> int:
    status = validate_static()
    if status:
        return status
    try:
        validate_runtime()
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Public export runtime validation failed: {exc}", file=sys.stderr)
        return 1
    print("Shell, Python, CLI, runtime-profile, skill-link, and agent-link validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

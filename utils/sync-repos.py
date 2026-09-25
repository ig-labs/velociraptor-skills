#!/usr/bin/env python3
"""Synchronize explicitly managed files between ai_skills and this repository."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from functools import cached_property
from pathlib import Path, PurePosixPath
from typing import Iterable

from public_audit import append_audit, finding_metadata


SCHEMA_VERSION = 1


class SyncError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mapping:
    ai_path: str
    public_path: str
    kind: str


@dataclass(frozen=True)
class FileValue:
    data: bytes
    mode: str

    @cached_property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.data).hexdigest()
        return f"sha256:{digest};mode:{self.mode}"


@dataclass(frozen=True)
class Pair:
    key: str
    ai_path: str
    public_path: str


@dataclass(frozen=True)
class Action:
    status: str
    pair: Pair
    source: FileValue | None
    target: FileValue | None
    base: str | None


def run_git(
    repo: Path, args: list[str], *, text: bool = False, input_data: bytes | None = None
) -> bytes | str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        input=input_data,
        check=False,
    )
    if proc.returncode:
        message = proc.stderr.decode("utf-8", "replace").strip()
        raise SyncError(f"git {' '.join(args)} failed in {repo}: {message}")
    if text:
        return proc.stdout.decode("utf-8", "strict")
    return proc.stdout


def validate_relative_path(raw: str, label: str) -> str:
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts or raw.startswith("./"):
        raise SyncError(f"invalid {label} path: {raw!r}")
    return path.as_posix()


def load_manifest(path: Path) -> list[Mapping]:
    mappings: list[Mapping] = []
    seen_ai: set[str] = set()
    seen_public: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 3:
            raise SyncError(f"{path}:{line_number}: expected three tab-separated fields")
        ai_path = validate_relative_path(fields[0].strip(), "ai_skills")
        public_path = validate_relative_path(fields[1].strip(), "public")
        kind = fields[2].strip()
        if kind not in {"file", "tree"}:
            raise SyncError(f"{path}:{line_number}: kind must be file or tree")
        if ai_path in seen_ai or public_path in seen_public:
            raise SyncError(f"{path}:{line_number}: duplicate manifest path")
        seen_ai.add(ai_path)
        seen_public.add(public_path)
        mappings.append(Mapping(ai_path, public_path, kind))
    if not mappings:
        raise SyncError(f"manifest has no mappings: {path}")
    return mappings


def load_deny_patterns(path: Path) -> list[tuple[str, re.Pattern[str]]]:
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = raw.split("\t", 1)
        if len(fields) != 2:
            raise SyncError(f"{path}:{line_number}: expected label and regex")
        try:
            patterns.append((fields[0], re.compile(fields[1], re.IGNORECASE)))
        except re.error as exc:
            raise SyncError(f"{path}:{line_number}: invalid regex: {exc}") from exc
    return patterns


def ensure_repo(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not (resolved / ".git").exists():
        raise SyncError(f"not a Git working tree: {resolved}")
    run_git(resolved, ["rev-parse", "--is-inside-work-tree"])
    return resolved


class Reader:
    def prepare(self, paths: list[tuple[str, str]]) -> None:
        """Optionally fetch the selected managed content in one operation."""

    def list_files(self, base: str, kind: str) -> dict[str, str]:
        raise NotImplementedError

    def read(self, path: str, mode: str) -> FileValue:
        raise NotImplementedError


class RevisionReader(Reader):
    def __init__(self, repo: Path, revision: str):
        self.repo = repo
        self.revision = revision
        self.resolved_revision = str(run_git(repo, ["rev-parse", revision], text=True)).strip()
        self._files: dict[str, tuple[str, str]] | None = None
        self._values: dict[str, bytes] = {}

    def list_files(self, base: str, kind: str) -> dict[str, str]:
        if self._files is None:
            output = run_git(self.repo, ["ls-tree", "-rz", "--full-tree", self.resolved_revision])
            self._files = {}
            for record in bytes(output).split(b"\0"):
                if not record:
                    continue
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
                if object_type == "blob":
                    self._files[raw_path.decode("utf-8")] = (mode, object_id)
        result: dict[str, str] = {}
        for path, (mode, _object_id) in self._files.items():
            if path != base and (kind == "file" or not path.startswith(base.rstrip("/") + "/")):
                continue
            if mode == "120000":
                raise SyncError(f"symlink is not permitted in managed content: {path}")
            if kind == "file" and path != base:
                continue
            result[path] = mode
        if kind == "file" and len(result) > 1:
            raise SyncError(f"file mapping resolved multiple paths: {base}")
        return result

    def prepare(self, paths: list[tuple[str, str]]) -> None:
        selected = list(dict.fromkeys(path for path, _mode in paths if path not in self._values))
        if not selected:
            return
        if self._files is None:
            raise SyncError("revision content requested before inventory")
        object_ids = [self._files[path][1] for path in selected]
        output = bytes(run_git(
            self.repo, ["cat-file", "--batch"],
            input_data=("\n".join(object_ids) + "\n").encode("ascii"),
        ))
        offset = 0
        for path, object_id in zip(selected, object_ids):
            end = output.find(b"\n", offset)
            header = output[offset:end].split() if end >= 0 else []
            if len(header) != 3 or header[0] != object_id.encode("ascii") or header[1] != b"blob":
                raise SyncError(f"invalid Git batch response for managed file: {path}")
            size = int(header[2])
            start, offset = end + 1, end + 1 + size
            if size < 0 or output[offset:offset + 1] != b"\n":
                raise SyncError(f"truncated Git batch response for managed file: {path}")
            self._values[path] = output[start:offset]
            offset += 1
        if offset != len(output):
            raise SyncError("unexpected trailing Git batch response")

    def read(self, path: str, mode: str) -> FileValue:
        self.prepare([(path, mode)])
        return FileValue(data=self._values[path], mode=mode)


class WorkingReader(Reader):
    def __init__(self, repo: Path):
        self.repo = repo
        self._paths: list[str] | None = None

    def list_files(self, base: str, kind: str) -> dict[str, str]:
        if self._paths is None:
            output = run_git(self.repo, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
            self._paths = sorted({path.decode("utf-8") for path in bytes(output).split(b"\0") if path})
        result: dict[str, str] = {}
        for path in self._paths:
            if path != base and (kind == "file" or not path.startswith(base.rstrip("/") + "/")):
                continue
            full = self.repo / path
            if full.is_symlink():
                raise SyncError(f"symlink is not permitted in managed content: {path}")
            if not full.is_file():
                continue
            result[path] = file_mode(full)
        return result

    def read(self, path: str, mode: str) -> FileValue:
        full = self.repo / path
        if full.is_symlink():
            raise SyncError(f"symlink is not permitted in managed content: {path}")
        return FileValue(data=full.read_bytes(), mode=file_mode(full))


def file_mode(path: Path) -> str:
    executable = bool(path.stat().st_mode & stat.S_IXUSR)
    return "100755" if executable else "100644"


def check_source_clean(repo: Path, mappings: Iterable[Mapping], direction: str) -> None:
    paths = [m.ai_path if direction == "from-ai" else m.public_path for m in mappings]
    output = str(
        run_git(
            repo,
            ["status", "--porcelain", "--untracked-files=all", "--", *paths],
            text=True,
        )
    )
    if output.strip():
        names = [line[3:] for line in output.splitlines()[:10]]
        suffix = "" if len(output.splitlines()) <= 10 else " ..."
        raise SyncError(
            "managed source paths are dirty; commit them or use --working-tree: "
            + ", ".join(names)
            + suffix
        )


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "files": {}}
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("schema_version") != SCHEMA_VERSION or not isinstance(state.get("files"), dict):
        raise SyncError(f"unsupported or malformed sync state: {path}")
    return state


def pair_key(ai_path: str, public_path: str) -> str:
    return f"{ai_path} => {public_path}"


def suffix_for(path: str, base: str, kind: str) -> str:
    if kind == "file":
        if path != base:
            raise SyncError(f"file path {path} does not match manifest entry {base}")
        return ""
    prefix = base.rstrip("/") + "/"
    if not path.startswith(prefix):
        raise SyncError(f"tree path {path} is outside manifest entry {base}")
    return path[len(prefix) :]


def join_mapping(base: str, suffix: str) -> str:
    return base if not suffix else f"{base.rstrip('/')}/{suffix}"


def build_pairs(
    mappings: list[Mapping],
    ai_reader: Reader,
    public_reader: Reader,
    state: dict,
) -> list[tuple[Pair, str | None, str | None]]:
    pairs: dict[str, tuple[Pair, str | None, str | None]] = {}
    for mapping in mappings:
        ai_files = ai_reader.list_files(mapping.ai_path, mapping.kind)
        public_files = public_reader.list_files(mapping.public_path, mapping.kind)
        suffixes: set[str] = set()
        suffixes.update(suffix_for(path, mapping.ai_path, mapping.kind) for path in ai_files)
        suffixes.update(suffix_for(path, mapping.public_path, mapping.kind) for path in public_files)
        for record in state["files"].values():
            ai_path = record.get("ai_path", "")
            public_path = record.get("public_path", "")
            try:
                ai_suffix = suffix_for(ai_path, mapping.ai_path, mapping.kind)
                public_suffix = suffix_for(public_path, mapping.public_path, mapping.kind)
            except SyncError:
                continue
            if ai_suffix != public_suffix:
                raise SyncError(f"state path mapping mismatch: {ai_path} and {public_path}")
            suffixes.add(ai_suffix)
        for suffix in suffixes:
            ai_path = join_mapping(mapping.ai_path, suffix)
            public_path = join_mapping(mapping.public_path, suffix)
            pair = Pair(pair_key(ai_path, public_path), ai_path, public_path)
            if pair.key in pairs:
                raise SyncError(f"overlapping manifest entries manage the same file: {pair.key}")
            pairs[pair.key] = (pair, ai_files.get(ai_path), public_files.get(public_path))
    return [pairs[key] for key in sorted(pairs)]


def read_optional(reader: Reader, path: str, mode: str | None) -> FileValue | None:
    if mode is None:
        return None
    return reader.read(path, mode)


def plan_actions(
    pairs: list[tuple[Pair, str | None, str | None]],
    ai_reader: Reader,
    public_reader: Reader,
    state: dict,
    direction: str,
) -> list[Action]:
    ai_reader.prepare([(pair.ai_path, mode) for pair, mode, _ in pairs if mode is not None])
    public_reader.prepare([(pair.public_path, mode) for pair, _, mode in pairs if mode is not None])
    actions: list[Action] = []
    for pair, ai_mode, public_mode in pairs:
        ai_value = read_optional(ai_reader, pair.ai_path, ai_mode)
        public_value = read_optional(public_reader, pair.public_path, public_mode)
        source = ai_value if direction == "from-ai" else public_value
        target = public_value if direction == "from-ai" else ai_value
        source_fp = source.fingerprint if source else None
        target_fp = target.fingerprint if target else None
        base = state["files"].get(pair.key, {}).get("fingerprint")

        if base is None:
            if source_fp is None and target_fp is None:
                continue
            if source_fp is not None and target_fp is None:
                status = "add"
            elif source_fp is None and target_fp is not None:
                status = "reverse-needed"
            elif source_fp == target_fp:
                status = "converged"
            else:
                status = "conflict"
        else:
            source_changed = source_fp != base
            target_changed = target_fp != base
            if not source_changed and not target_changed:
                status = "unchanged"
            elif source_changed and not target_changed:
                status = "delete" if source_fp is None else "update"
            elif not source_changed and target_changed:
                status = "reverse-needed"
            elif source_fp == target_fp:
                status = "converged"
            else:
                status = "conflict"
        actions.append(Action(status, pair, source, target, base))
    return actions


def plan_fingerprint(actions: list[Action], context: dict) -> str:
    """Bind a reviewed plan to its content, baselines, policy, and destination."""
    payload = {
        "context": context,
        "actions": [
            {
                "ai_path": action.pair.ai_path,
                "public_path": action.pair.public_path,
                "status": action.status,
                "source": action.source.fingerprint if action.source else None,
                "target": action.target.fingerprint if action.target else None,
                "base": action.base,
            }
            for action in actions
        ],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def scan_planned_content(
    actions: list[Action], patterns: list[tuple[str, re.Pattern[str]]]
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for action in actions:
        value = action.target if action.status == "resolved" else action.source
        if action.status not in {"add", "update", "converged", "resolved"} or value is None:
            continue
        text = value.data.replace(b"\0", b"").decode("utf-8", "replace")
        for label, pattern in patterns:
            if pattern.search(text) or pattern.search(action.pair.public_path):
                findings.append((action.pair.public_path, label))
    return findings


def accept_resolutions(actions: list[Action], paths: list[str], direction: str) -> list[Action]:
    """Record explicit manual resolutions without overwriting destination content."""
    requested = {validate_relative_path(path, "resolved destination") for path in paths}
    result = []
    for action in actions:
        path = action.pair.public_path if direction == "from-ai" else action.pair.ai_path
        if path in requested:
            requested.remove(path)
            if action.status != "conflict" or action.source is None or action.target is None:
                raise SyncError(f"--accept-resolved requires a two-file conflict: {path}")
            if re.search(rb"(?m)^(?:<<<<<<< |=======\r?$|>>>>>>> )", action.target.data):
                raise SyncError(f"unresolved merge markers in: {path}")
            action = replace(action, status="resolved")
        result.append(action)
    if requested:
        raise SyncError("unknown resolved destination paths: " + ", ".join(sorted(requested)))
    return result


def render_diffs(actions: list[Action], direction: str) -> None:
    for action in actions:
        if action.status in {"unchanged", "converged"}:
            continue
        path = action.pair.public_path if direction == "from-ai" else action.pair.ai_path
        before = action.target.data if action.target else b""
        after = action.source.data if action.source else b""
        try:
            if b"\0" in before or b"\0" in after:
                raise UnicodeError
            old, new = before.decode("utf-8"), after.decode("utf-8")
        except UnicodeError:
            print(f"Binary comparison: {path} ({len(before)} -> {len(after)} bytes)")
            continue
        print("".join(difflib.unified_diff(
            old.splitlines(keepends=True), new.splitlines(keepends=True),
            fromfile=f"destination/{path}", tofile=f"source/{path}",
        )), end="")
        if action.target and action.source and action.target.mode != action.source.mode:
            print(f"Mode: {path} {action.target.mode} -> {action.source.mode}")


def target_path(pair: Pair, direction: str, ai_repo: Path, public_repo: Path) -> Path:
    if direction == "from-ai":
        return public_repo / pair.public_path
    return ai_repo / pair.ai_path


def write_file(path: Path, value: FileValue) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value.data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o755 if value.mode == "100755" else 0o644)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def render_report(actions: list[Action], direction: str) -> None:
    visible = [action for action in actions if action.status != "unchanged"]
    for action in visible:
        path = action.pair.public_path if direction == "from-ai" else action.pair.ai_path
        print(f"{action.status:15} {path}")
    counts: dict[str, int] = {}
    for action in actions:
        counts[action.status] = counts.get(action.status, 0) + 1
    summary = " ".join(f"{key}={counts[key]}" for key in sorted(counts))
    print(f"Summary: direction={direction} {summary or 'files=0'}")


def save_state(
    path: Path,
    prior: dict,
    actions: list[Action],
    direction: str,
    source_revision: str,
) -> None:
    active_keys = {action.pair.key for action in actions}
    files = {
        key: value for key, value in prior["files"].items() if key in active_keys
    }
    for action in actions:
        if action.status in {"add", "update", "converged", "unchanged", "resolved"}:
            value = action.source
            if value is None:
                files.pop(action.pair.key, None)
            else:
                files[action.pair.key] = {
                    "ai_path": action.pair.ai_path,
                    "public_path": action.pair.public_path,
                    "fingerprint": value.fingerprint,
                }
        elif action.status == "delete" and action.source is None:
            files.pop(action.pair.key, None)
    state = {
        "schema_version": SCHEMA_VERSION,
        "last_direction": direction,
        "last_source_revision": source_revision,
        "files": dict(sorted(files.items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_file(path, FileValue(payload, "100644"))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synchronize allowlisted files between ai_skills and velociraptor-skills."
    )
    parser.add_argument("direction", choices=("from-ai", "to-ai"))
    parser.add_argument("--source", type=Path, help="ai_skills path for from-ai")
    parser.add_argument("--target", type=Path, help="ai_skills path for to-ai")
    parser.add_argument("--rev", default="HEAD", help="committed source revision")
    parser.add_argument(
        "--working-tree",
        action="store_true",
        help="read tracked source files from the working tree instead of --rev",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="report drift without writing")
    mode.add_argument("--apply", action="store_true", help="apply a conflict-free plan")
    parser.add_argument("--diff", action="store_true", help="show destination-to-source comparisons (may contain sensitive text)")
    parser.add_argument(
        "--require-plan-hash", metavar="SHA256",
        help="refuse if the current plan differs from the SHA-256 printed by a reviewed --check",
    )
    parser.add_argument(
        "--accept-resolved", action="append", default=[], metavar="DESTINATION_PATH",
        help="acknowledge a reviewed manual conflict resolution; preserve destination and advance source baseline",
    )
    parser.add_argument(
        "--allow-delete", action="store_true", help="allow source deletions to propagate"
    )
    parser.add_argument(
        "--allow-policy-findings",
        action="store_true",
        help="permit deny-pattern findings for a reviewed bootstrap only",
    )
    parser.add_argument(
        "--allow-reverse-pending",
        action="store_true",
        help="apply independent changes while leaving destination-only changes untouched",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    public_repo = ensure_repo(Path(__file__).resolve().parents[1])
    default_ai = public_repo.parent / "ai_skills"
    if args.direction == "from-ai":
        if args.target is not None:
            raise SyncError("--target is valid only with to-ai")
        ai_repo = ensure_repo(args.source or default_ai)
        source_repo = ai_repo
    else:
        if args.source is not None:
            raise SyncError("--source is valid only with from-ai")
        ai_repo = ensure_repo(args.target or default_ai)
        source_repo = public_repo

    manifest_path = public_repo / "config" / "sync-manifest.tsv"
    deny_path = public_repo / "config" / "public-deny-patterns.tsv"
    state_path = public_repo / ".sync-state.json"
    mappings = load_manifest(manifest_path)
    state = load_state(state_path)

    if args.working_tree:
        source_reader: Reader = WorkingReader(source_repo)
        source_revision = str(run_git(source_repo, ["rev-parse", "HEAD"], text=True)).strip()
        source_revision += "+working-tree"
    else:
        check_source_clean(source_repo, mappings, args.direction)
        source_reader = RevisionReader(source_repo, args.rev)
        source_revision = source_reader.resolved_revision

    target_reader = WorkingReader(public_repo if args.direction == "from-ai" else ai_repo)
    if args.direction == "from-ai":
        ai_reader, public_reader = source_reader, target_reader
    else:
        ai_reader, public_reader = target_reader, source_reader

    pairs = build_pairs(mappings, ai_reader, public_reader, state)
    actions = plan_actions(pairs, ai_reader, public_reader, state, args.direction)
    actions = accept_resolutions(actions, args.accept_resolved, args.direction)
    render_report(actions, args.direction)
    if args.diff:
        render_diffs(actions, args.direction)

    conflicts = [action for action in actions if action.status == "conflict"]
    reverse_pending = [action for action in actions if action.status == "reverse-needed"]
    deletions = [action for action in actions if action.status == "delete"]
    patterns = load_deny_patterns(deny_path)
    findings = scan_planned_content(actions, patterns)
    for path, label in findings:
        print(f"policy-finding  {path} ({label})", file=sys.stderr)

    plan_hash = plan_fingerprint(actions, {
        "direction": args.direction,
        "ai_repo": str(ai_repo),
        "public_repo": str(public_repo),
        "source_revision": source_revision,
        "mappings": [(mapping.ai_path, mapping.public_path, mapping.kind) for mapping in mappings],
        "deny_patterns": [(label, pattern.pattern, pattern.flags) for label, pattern in patterns],
        "state": state,
        "accept_resolved": sorted(set(args.accept_resolved)),
        "allow_delete": args.allow_delete,
        "allow_policy_findings": args.allow_policy_findings,
        "allow_reverse_pending": args.allow_reverse_pending,
    })
    print(f"Plan SHA256: {plan_hash}")
    append_audit(
        public_repo,
        check="sync-policy",
        status="findings" if findings else "passed",
        direction=args.direction,
        mode="apply-requested" if args.apply else "check",
        plan_sha256=plan_hash,
        policy_override=args.allow_policy_findings,
        findings=finding_metadata(findings),
    )
    if args.require_plan_hash is not None and args.require_plan_hash.lower() != plan_hash:
        raise SyncError("reviewed plan has changed; run --check and review again before applying")

    changed = [action for action in actions if action.status not in {"unchanged", "converged"}]
    if not args.apply:
        return 1 if changed or findings else 0
    if conflicts:
        raise SyncError("refusing to apply: resolve files changed differently on both sides")
    if reverse_pending and not args.allow_reverse_pending:
        raise SyncError(
            "refusing to apply: synchronize destination-only changes in the reverse "
            "direction or acknowledge them with --allow-reverse-pending"
        )
    if deletions and not args.allow_delete:
        raise SyncError("refusing to apply source deletions without --allow-delete")
    if findings and not args.allow_policy_findings:
        raise SyncError("refusing to apply content that matches public deny patterns")

    # Preflight every destination before the first write, including resolved files.
    for action in actions:
        destination = target_path(action.pair, args.direction, ai_repo, public_repo)
        if destination.is_symlink() or any(parent.is_symlink() for parent in destination.parents):
            raise SyncError(f"symlink is not permitted in destination path: {destination}")
        current = FileValue(destination.read_bytes(), file_mode(destination)) if destination.is_file() else None
        if current != action.target or (destination.exists() and not destination.is_file()):
            raise SyncError(f"destination changed during planning: {destination}")

    for action in actions:
        destination = target_path(action.pair, args.direction, ai_repo, public_repo)
        if action.status in {"add", "update"}:
            if action.source is None:
                raise SyncError(f"internal error: missing source for {action.pair.key}")
            write_file(destination, action.source)
        elif action.status == "delete":
            if destination.exists() or destination.is_symlink():
                if destination.is_dir():
                    raise SyncError(f"refusing to delete directory as a managed file: {destination}")
                destination.unlink()

    save_state(state_path, state, actions, args.direction, source_revision)
    print(f"Applied synchronization and updated {state_path.relative_to(public_repo)}")
    if reverse_pending:
        print(f"Left destination-only files untouched: {len(reverse_pending)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, SyncError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)

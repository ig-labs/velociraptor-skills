"""Read-only remapping for extracted Velociraptor collection exports."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import unquote

import yaml

from .common.atomic_io import write_json_atomic, write_text_atomic

TYPES = ("auto", "windows-disk", "windows-directory", "velociraptor-export", "velociraptor-kapefiles-zip")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def detect(path: Path, requested: str = "auto") -> str:
    if requested not in TYPES:
        raise ValueError("Unsupported evidence type")
    if path.is_file() and path.suffix.lower() == ".zip":
        import zipfile
        with zipfile.ZipFile(path) as archive:
            if not {"uploads.json", "data.zip"}.intersection(archive.namelist()):
                raise ValueError("KapeFiles ZIP requires uploads.json")
        if requested not in ("auto", "velociraptor-kapefiles-zip"):
            raise ValueError("Collection ZIP requires velociraptor-kapefiles-zip")
        return "velociraptor-kapefiles-zip"
    if requested == "velociraptor-kapefiles-zip":
        raise ValueError("KapeFiles ZIP requires a .zip file")
    export = path.is_dir() and (path / "uploads.json").is_file()
    if requested == "auto":
        if export:
            return "velociraptor-export"
        if path.is_file():
            return "windows-disk"
        if path.is_dir() and any(p.name.casefold() == "windows" for p in path.iterdir()):
            return "windows-directory"
        raise ValueError("Ambiguous evidence directory; select --evidence-type explicitly")
    if requested == "velociraptor-export" and not export:
        raise ValueError("Extracted export requires uploads.json")
    if requested == "windows-directory" and export:
        raise ValueError("Collection export cannot be mapped as a Windows directory")
    if requested == "windows-disk" and not path.is_file():
        raise ValueError("Windows disk requires a file")
    if requested == "windows-directory" and not path.is_dir():
        raise ValueError("Windows directory requires a directory")
    return requested


def inventory(root: Path) -> list[dict]:
    """Validate every upload without modifying evidence or following escaping links."""
    root = root.resolve()
    records = []
    seen = set()
    directories = {}
    with (root / "uploads.json").open() as stream:
        for line in stream:
            row = json.loads(line)
            parts = row.get("_Components")
            if not isinstance(parts, list) or len(parts) < 4 or parts[0] != "uploads":
                raise ValueError("Invalid upload components")
            accessor, drive = parts[1:3]
            if accessor not in {"auto", "file", "ntfs"}:
                raise ValueError("Unsupported upload accessor: " + str(accessor))
            if not re.fullmatch(r"(?:\\\\\.\\)?[A-Za-z]:", drive):
                raise ValueError("Unsupported drive or VSS upload")
            current = root
            for component in parts:
                if not isinstance(component, str) or component in {"", ".", ".."}:
                    raise ValueError("Invalid upload path component")
                if current not in directories:
                    index = {}
                    for child in current.iterdir():
                        index.setdefault(unquote(child.name), []).append(child)
                    directories[current] = index
                matches = directories[current].get(component, [])
                if len(matches) != 1:
                    raise ValueError("Missing or ambiguous uploaded file")
                current = matches[0]
                if current.is_symlink() or not current.resolve().is_relative_to(root):
                    raise ValueError("Upload path escapes evidence or contains a symlink")
            if not current.is_file() or current.stat().st_size != row.get("file_size"):
                raise ValueError("Missing, truncated or sparse upload; expanded files required")
            if row.get("uploaded_size") != row.get("file_size") or Path(str(current) + ".idx").exists():
                raise ValueError("Sparse uploads require expansion before mapping")
            if any("/" in p or "\\" in p for p in parts[3:]):
                raise ValueError("Invalid filename component")
            target = drive + "\\" + "\\".join(parts[3:])
            key = (accessor, target.casefold())
            if key in seen:
                raise ValueError("Duplicate virtual upload path")
            seen.add(key)
            stat = current.stat()
            records.append(dict(accessor=accessor, target=target, source=str(current),
                                size=stat.st_size, mtime_ns=stat.st_mtime_ns,
                                inode=stat.st_ino, device=stat.st_dev))
    if not records:
        raise ValueError("Export contains no uploaded files")
    return records


def prepare(root: Path, remap: Path, binary: str, hostname: str) -> dict:
    if root.is_file():
        from .zip_mapping import prepare_zip
        return prepare_zip(root, remap, binary, hostname)
    root = root.resolve()
    remap = remap.resolve()
    if remap.is_relative_to(root):
        raise ValueError("Mapping workspace must be outside source evidence")
    records = inventory(root)
    identity = hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
    metadata = remap.with_suffix(".export.json")
    if remap.exists():
        if not metadata.exists():
            raise ValueError("Existing remap has no export binding; use a separate mapping workspace")
        saved = json.loads(metadata.read_text())
        if saved["inventory_sha256"] != identity or saved["remap_sha256"] != hashlib.sha256(remap.read_bytes()).hexdigest():
            raise ValueError("Export binding or remap changed; saved identity preserved")
        for item in saved["verified_files"]:
            path = Path(item["path"])
            if path.is_symlink() or not path.resolve().is_relative_to(remap.parent.resolve()) or digest(path) != item["sha256"]:
                raise ValueError("Export working copy changed")
        return saved
    remap.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=remap.parent) as directory:
        base = Path(directory) / "base.yaml"
        subprocess.run([binary, "deaddisk", "--hostname", hostname,
                        "--add_windows_directory", str(root), str(base)],
                       check=True, capture_output=True, timeout=60)
        config = yaml.safe_load(base.read_text())
    config["remappings"] = [r for r in config["remappings"] if r["type"] != "mount"]
    view = remap.parent / "export-view"
    if view.exists():
        raise ValueError("Existing export view without remap; inspect before retrying")
    roots = {}
    verified = []
    for row in records:
        drive = re.match(r"(?:\\\\\.\\)?[A-Za-z]:", row["target"])[0]
        relative = row["target"][len(drive) + 1:].split("\\")
        folder = view / row["accessor"] / drive[-2]
        destination = folder.joinpath(*relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(row["source"], destination)
        source_hash = digest(Path(row["source"]))
        if digest(destination) != source_hash:
            raise ValueError("Evidence changed during copy")
        verified.append(dict(path=str(destination), sha256=source_hash))
        destination.chmod(0o400)
        roots[(row["accessor"], drive)] = folder
    for (accessor, drive), folder in roots.items():
        config["remappings"].append({"type": "mount", "from": {
            "accessor": "file_nocase", "prefix": str(folder)}, "on": {
            "accessor": accessor, "prefix": drive,
            "path_type": "ntfs" if accessor == "ntfs" else "windows"}})
    hives = {"software": "HKEY_LOCAL_MACHINE/Software", "system": "HKEY_LOCAL_MACHINE/System",
             "sam": "HKEY_LOCAL_MACHINE/SAM", "security": "HKEY_LOCAL_MACHINE/Security"}
    for (accessor, drive), folder in roots.items():
        if accessor not in {"auto", "file"}:
            continue
        for hive in folder.glob("**/*"):
            relative = hive.relative_to(folder).as_posix().lower()
            name = hive.name.lower()
            if relative == "windows/system32/config/" + name and name in hives:
                config["remappings"].append({"type": "mount", "from": {
                    "accessor": "raw_reg", "path_type": "registry",
                    "prefix": json.dumps({"DelegateAccessor": "file_nocase", "DelegatePath": str(hive)})},
                    "on": {"accessor": "registry", "prefix": hives[name], "path_type": "registry"}})
    data = yaml.safe_dump(config, sort_keys=False)
    saved = dict(version=1, evidence_type="velociraptor-export", inventory_sha256=identity,
                 remap_sha256=hashlib.sha256(data.encode()).hexdigest(), files=len(records),
                 verified_files=verified,
                 limitations=["extraction timestamps", "no uncollected files", "user and Amcache hives not mapped"])
    # Check actual reads, not just enrollment or the existence of a mount directive.
    write_text_atomic(remap, data)
    probes = {}
    for row in records:
        drive = re.match(r"(?:\\\\\.\\)?[A-Za-z]:", row["target"])[0]
        probes.setdefault((row["accessor"], drive), row)
    for (accessor, _), row in probes.items():
        result = subprocess.run([binary, "--remap", str(remap), "query", "--nobanner",
                                 "--env", "Probe=" + row["target"],
                                 "--env", "Accessor=" + accessor,
                                 "SELECT Size, len(list=read_file(filename=Probe, accessor=Accessor, length=1)) AS ReadBytes FROM stat(filename=Probe, accessor=Accessor)"],
                                check=True, capture_output=True, text=True, timeout=30)
        rows = json.loads(result.stdout)
        if len(rows) != 1 or rows[0]["Size"] != row["size"] or rows[0]["ReadBytes"] != min(1, row["size"]):
            raise ValueError("Export accessor read verification failed")
    write_json_atomic(metadata, saved)
    return saved


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("remap", type=Path)
    parser.add_argument("binary")
    parser.add_argument("hostname")
    parser.add_argument("--evidence-type", choices=TYPES, default="auto")
    args = parser.parse_args()
    selected = detect(args.evidence, args.evidence_type)
    if selected in ("velociraptor-export", "velociraptor-kapefiles-zip"):
        prepare(args.evidence, args.remap, args.binary, args.hostname)
    print(selected)

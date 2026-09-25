#!/usr/bin/env python3
"""Validate an offline wheel with isolated core dependencies and no AI SDK.

Run with the repository .venv Python. Only a temporary validation environment is
installed; tool-preparation commands are help-only and APIs are mocked.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import zipfile

CORE_FIXTURE_MODULES = (
    "yaml", "grpc", "pyvelociraptor", "google", "re2", "jsonschema",
    "jsonschema_specifications", "referencing", "attrs", "attr", "rpds",
    "tiktoken", "tiktoken_ext", "regex", "requests", "urllib3", "certifi",
    "charset_normalizer", "idna", "cryptography", "cffi", "_cffi_backend",
    "typing_extensions",
)

RESOURCE_AND_API_CHECK = '''import importlib.util, json
assert importlib.util.find_spec("openai") is None
assert importlib.util.find_spec("dfir_case_tools") is None
from vraptor.artifacts import policy as artifact_policy
from vraptor.autoruns import regex_store as autoruns_regex_db
from vraptor.collect import catalog as collection_catalog
from vraptor.resources import resource_root
assert artifact_policy.load_artifact_policy()
assert collection_catalog.load_collection_policy()
assert autoruns_regex_db.load(resource_root()/"golden/autoruns-golden.sqlite")
from vraptor.agent.profiles import load_agent_profile_config
assert load_agent_profile_config()
from vraptor import query as client_query
from vraptor import cli
from pathlib import Path
class FakeApi:
    def __init__(self, *args, **kwargs): pass
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def query_batches(self, *args, **kwargs): yield [{"value": 1}]
    def query(self, *args, **kwargs): return [{"client_id":"C.1", "Hostname":"host01", "Labels":[]}]
client_query.VeloApiClient = FakeApi
api = Path("synthetic-api.yaml")
api.write_text("fixture only")
assert cli.main(["query", "--api-client", str(api), "--vql", "SELECT 1 AS value FROM scope()"]) == 0
assert cli.main(["clients", "--api-client", str(api)]) == 0
print("ISOLATED_RESOURCES_AND_MOCK_API_OK")
'''


def main():
    repository = Path(__file__).resolve().parents[1]
    root = Path(tempfile.mkdtemp(prefix="vraptor-install-check-"))
    print("Validation directory:", root, flush=True)
    wheels = root / "wheels"
    wheels.mkdir()
    subprocess.run([sys.executable, "-m", "venv", str(root)], check=True)
    build_source = root / "source"
    build_source.mkdir()
    shutil.copy2(repository / "pyproject.toml", build_source / "pyproject.toml")
    shutil.copytree(repository / "src", build_source / "src",
                    ignore=shutil.ignore_patterns("build", "dist", "*.egg-info", "__pycache__", "*.pyc"))
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
         str(build_source), "-w", str(wheels)],
        check=True, stdout=subprocess.DEVNULL,
    )
    wheel = next(wheels.glob("vraptor-*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)
        assert not any(name.startswith("vraptor/velociraptor/") for name in names)
    python = root / "bin/python"
    subprocess.run(
        [str(python), "-m", "pip", "install", "--force-reinstall", "--no-deps",
         "--no-index", str(wheel)], check=True, stdout=subprocess.DEVNULL,
    )
    source = Path(sysconfig.get_paths()["purelib"])
    target = Path(subprocess.check_output(
        [str(python), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
        text=True,
    ).strip())
    # Offline fixture of installed core dependencies; no AI SDK or upstream runtime.
    for name in CORE_FIXTURE_MODULES:
        candidates = [source / name, source / (name + ".py")]
        paths = [path for path in candidates if path.exists()] or list(source.glob(name + "*.so"))
        if not paths:
            raise RuntimeError(f"Core dependency fixture is missing: {name}")
        for path in paths:
            if path.is_dir():
                shutil.copytree(path, target / path.name, dirs_exist_ok=True)
            else:
                shutil.copy2(path, target / path.name)
    work, home = root / "work", root / "home"
    work.mkdir()
    home.mkdir()
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "PYTHONNOUSERSITE": "1"}
    commands = [
        ["--help"], ["ai", "config", "--view", "defaults"],
        ["tools", "prep", "--help"], ["query", "--help"], ["clients", "--help"],
        ["artifacts", "--help"], ["collect", "--help"], ["analyze", "--help"],
        ["hunt", "--help"], ["export", "--help"],
    ]
    for args in commands:
        result = subprocess.run(
            [str(root / "bin/vraptor"), *args], cwd=work, env=env,
            text=True, capture_output=True,
        )
        print(" ".join(args), result.returncode)
        if result.returncode:
            print(result.stderr)
            return result.returncode
    result = subprocess.run(
        [str(python), "-c", RESOURCE_AND_API_CHECK], cwd=work, env=env,
        text=True, capture_output=True,
    )
    print(result.stdout, result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

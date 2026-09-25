from __future__ import annotations

import argparse
import os
import re
import shutil
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


CASE_ROOT_ENV = "CASE_ROOT"
EVIDENCE_ROOT_ENV = "CASE_EVIDENCE_ROOT"
VELO_LOCAL_API_CLIENT_ENV = "VELO_LOCAL_API_CLIENT"
VELO_LOCAL_CONFIG_ROOT_ENV = "VELO_LOCAL_CONFIG_ROOT"
VELO_BIN_ENV = "VELO_BIN"
TOOLS_DATA_ROOT_ENV = "AI_SKILLS_TOOLS_DATA_ROOT"
AUTORUNS_GOLDEN_DB_ENV = "VELO_AUTORUNS_GOLDEN_DB"
DOTENV_FILE_NAME = ".env"
CODEX_DIRECTORY_NAME = ".codex"
ORIGINAL_PROCESS_ENV_KEYS = "AI_SKILLS_ORIGINAL_PROCESS_ENV_KEYS"
DOTENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DOTENV_DENIED_KEYS = frozenset(
    {
        "BASH_ENV",
        "BASHOPTS",
        "CDPATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "ENV",
        "GLOBIGNORE",
        "IFS",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PATH",
        "PERL5OPT",
        "PROMPT_COMMAND",
        "PS4",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUBYOPT",
        "SHELLOPTS",
    }
)


@dataclass(frozen=True)
class EnvironmentLayer:
    """One immutable environment source with its original location."""

    kind: str
    location: str
    values: Mapping[str, str]


@dataclass(frozen=True)
class RepositoryEnvironment:
    """Immutable environment sources before precedence resolution."""

    process: EnvironmentLayer
    repository: EnvironmentLayer
    shared: EnvironmentLayer
    selected: EnvironmentLayer | None = None

    def priority_layers(self) -> tuple[EnvironmentLayer, ...]:
        return (self.process, *((self.selected,) if self.selected else ()), self.repository, self.shared)


def expand_home_path(value: str | Path) -> Path:
    """Expand supported home-directory prefixes without expanding arbitrary variables."""
    raw_value = str(value)
    home = os.environ.get("HOME") or str(Path.home())
    for prefix in ("$HOME", "${HOME}"):
        if raw_value == prefix:
            raw_value = home
            break
        if raw_value.startswith(f"{prefix}/"):
            raw_value = f"{home}/{raw_value[len(prefix) + 1:]}"
            break
    return Path(raw_value).expanduser()


def parse_dotenv_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value


def load_dotenv_file(path: Path, *, override: bool = False) -> dict[str, str]:
    values = read_dotenv_file(path)
    for key, value in values.items():
        if override or key not in os.environ:
            os.environ[key] = value
    return values


def read_dotenv_file(path: Path) -> dict[str, str]:
    """Parse one dotenv file without mutating the process environment."""

    values: dict[str, str] = {}
    if not path.is_file():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not DOTENV_KEY_RE.fullmatch(key) or key in DOTENV_DENIED_KEYS:
            continue
        value = parse_dotenv_value(raw_value)
        values[key] = value
    return values


def repository_environment(
    repo_root: Path,
    *,
    process_environment: Mapping[str, str] | None = None,
) -> RepositoryEnvironment:
    """Return distinct immutable environment layers without applying precedence."""

    if process_environment is None:
        from .settings import current
        snapshot = current()
        if snapshot is not None:
            return snapshot.environment_layers

    observed_process_values = dict(
        process_environment if process_environment is not None else os.environ
    )
    original_keys = frozenset(str(
        observed_process_values.get(ORIGINAL_PROCESS_ENV_KEYS) or ""
    ).splitlines())
    process_values = (
        {
            key: value
            for key, value in observed_process_values.items()
            if key in original_keys
        }
        if original_keys
        else observed_process_values
    )
    shared_home = str(process_values.get("HOME") or "").strip()
    shared_path = (
        Path(shared_home) / CODEX_DIRECTORY_NAME / DOTENV_FILE_NAME
        if shared_home
        else None
    )
    repository_path = repo_root / DOTENV_FILE_NAME
    return RepositoryEnvironment(
        process=EnvironmentLayer(
            kind="process_environment",
            location="process",
            values=MappingProxyType(process_values),
        ),
        repository=EnvironmentLayer(
            kind="repository_dotenv",
            location=str(repository_path),
            values=MappingProxyType(read_dotenv_file(repository_path)),
        ),
        shared=EnvironmentLayer(
            kind="shared_dotenv",
            location=str(shared_path) if shared_path is not None else "",
            values=MappingProxyType(
                read_dotenv_file(shared_path) if shared_path is not None else {}
            ),
        ),
    )


def load_repo_env(repo_root: Path) -> dict[str, str]:
    """Load shared Codex then repository dotenv values without masking the shell."""

    from .settings import current
    if current() is not None:
        return dict(current().environment)
    return _load_repo_env(repo_root)


@lru_cache(maxsize=8)
def _load_repo_env(repo_root: Path) -> dict[str, str]:

    inherited_keys = frozenset(os.environ)
    shared_home = str(os.environ.get("HOME") or "").strip()
    dotenv_paths = []
    if shared_home:
        dotenv_paths.append(Path(shared_home) / CODEX_DIRECTORY_NAME / DOTENV_FILE_NAME)
    dotenv_paths.append(repo_root / DOTENV_FILE_NAME)

    values: dict[str, str] = {}
    seen_paths: set[Path] = set()
    for dotenv_path in dotenv_paths:
        if dotenv_path in seen_paths:
            continue
        seen_paths.add(dotenv_path)
        for key, value in load_dotenv_file(dotenv_path).items():
            values[key] = value
            if key not in inherited_keys:
                os.environ[key] = value
    return values


load_repo_env.cache_clear = _load_repo_env.cache_clear


def env_value(repo_root: Path, key: str) -> str | None:
    from .settings import current
    if current() is not None:
        value = current().environment.get(key)
        return value.strip() if value and value.strip() else None
    load_repo_env(repo_root)
    value = os.environ.get(key)
    if value and value.strip():
        return value.strip()
    return None


def default_case_root(repo_root: Path) -> Path:
    configured = env_value(repo_root, CASE_ROOT_ENV)
    if configured:
        return expand_home_path(configured).resolve()
    return (Path.home() / "cases").resolve()


def default_evidence_root(repo_root: Path, investigation_id: str | None = None) -> Path:
    configured = env_value(repo_root, EVIDENCE_ROOT_ENV)
    if configured:
        return expand_home_path(configured).resolve()
    return (Path.home() / "data").resolve()


def default_velociraptor_config_root(repo_root: Path) -> Path:
    configured = env_value(repo_root, VELO_LOCAL_CONFIG_ROOT_ENV)
    if configured:
        return expand_home_path(configured).resolve()
    return (Path.home() / ".config" / "velociraptor").resolve()


def resolve_autoruns_golden_db(
    database: str | Path | None,
    repo_root: Path,
) -> Path:
    if database:
        return expand_home_path(database).resolve()
    configured = env_value(repo_root, AUTORUNS_GOLDEN_DB_ENV)
    if configured:
        return expand_home_path(configured).resolve()
    tools_root = env_value(repo_root, TOOLS_DATA_ROOT_ENV)
    if tools_root:
        return (expand_home_path(tools_root) / "tools/Autoruns.GoldenDB/autoruns-golden.sqlite").resolve()
    from vraptor.resources import resource_root
    return resource_root() / "golden" / "autoruns-golden.sqlite"



def resolve_velociraptor_binary(velociraptor_bin: str | None, repo_root: Path) -> str:
    configured = velociraptor_bin or env_value(repo_root, VELO_BIN_ENV) or str(Path.home() / "velociraptor/velociraptor")
    candidate = expand_home_path(configured)
    if candidate.is_absolute() or candidate.parent != Path("."):
        if not candidate.is_absolute():
            candidate = repo_root / candidate
        return str(candidate.resolve())
    return shutil.which(configured) or configured


def resolve_case_root(case_root: str | None, repo_root: Path) -> Path:
    if case_root:
        return expand_home_path(case_root).resolve()
    return default_case_root(repo_root)


def add_case_root_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--case-root", help="Parent directory that holds investigation folders.")


def resolve_velociraptor_api_client_path(
    api_client: str | None,
    repo_root: Path,
    *,
    server_profile: str | None = None,
) -> Path:
    if api_client:
        return expand_home_path(api_client).resolve()

    from .settings import active_value
    configured = active_value("api_client", server_profile)
    if configured:
        return Path(configured)

    if server_profile:
        return (
            default_velociraptor_config_root(repo_root)
            / f"{server_profile}_api_client.yaml"
        ).resolve()

    configured = env_value(repo_root, VELO_LOCAL_API_CLIENT_ENV)
    if configured:
        configured_path = expand_home_path(configured)
        if not configured_path.is_absolute():
            configured_path = repo_root / configured_path
        return configured_path.resolve()

    return (default_velociraptor_config_root(repo_root) / "api_client.yaml").resolve()


def resolve_velociraptor_client_config_path(
    client_config: str | None,
    repo_root: Path,
    *,
    server_profile: str,
) -> Path:
    if client_config:
        return expand_home_path(client_config).resolve()
    from .settings import active_value
    configured = active_value("client_config", server_profile)
    if configured:
        return Path(configured)
    if not str(server_profile or "").strip():
        raise ValueError(
            "Provide --client-config or --server-profile for endpoint config resolution."
        )
    return (
        default_velociraptor_config_root(repo_root)
        / f"{server_profile}_client.config.yaml"
    ).resolve()

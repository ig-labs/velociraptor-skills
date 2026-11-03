"""Code-owned assets and configuration root, independent of case-path resolution."""
from pathlib import Path
import os


def resource_root() -> Path:
    return Path(__file__).resolve().parent


def repository_root() -> Path:
    explicit = os.environ.get("AI_SKILLS_REPO_ROOT")
    if explicit:
        return Path(explicit).expanduser().resolve()
    for parent in Path(__file__).resolve().parents:
        # Probe a file only a checkout has, not any folder named vraptor.
        if (parent / "src/vraptor/resources/__init__.py").is_file():
            return parent
    return Path.cwd().resolve()

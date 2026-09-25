"""Analysis intent and response-depth defaults shared by host and hunt analysis."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import lru_cache

from vraptor.resources import resource_root

PROFILES_PATH = resource_root() / "profiles" / "profiles.toml"
PROFILE_NAMES = ("incident_response", "targeted_hunt", "host_forensics", "compromise_assessment")
PROFILE_ALIASES = {
    "investigation": "incident_response",
    "ad_hoc_hunt": "targeted_hunt",
    "ad_hoc_host_investigation": "host_forensics",
}
RESPONSE_DEPTH_NAMES = ("rapid", "standard", "deep")


def normalize_profile_name(value):
    name = str(value or "").strip().lower().replace("-", "_")
    return PROFILE_ALIASES.get(name, name)


def normalize_response_depth(value):
    return str(value or "").strip().lower()


@dataclass(frozen=True)
class AnalysisProfile:
    name: str
    description: str
    output_contract: str
    default_depth: str


@dataclass(frozen=True)
class ResponseDepth:
    name: str
    description: str
    output_contract: str


@dataclass(frozen=True)
class AgentProfileConfig:
    profiles: dict[str, AnalysisProfile]
    response_depths: dict[str, ResponseDepth]


@lru_cache(maxsize=1)
def load_agent_profile_config():
    with PROFILES_PATH.open("rb") as source:
        payload = tomllib.load(source)
    depths = {name: ResponseDepth(name=name, **payload["response_depths"][name]) for name in RESPONSE_DEPTH_NAMES}
    profiles = {name: AnalysisProfile(name=name, **payload["profiles"][name]) for name in PROFILE_NAMES}
    for profile in profiles.values():
        if profile.default_depth not in depths:
            raise ValueError(f"Unknown response depth {profile.default_depth!r} for {profile.name}")
    return AgentProfileConfig(profiles=profiles, response_depths=depths)

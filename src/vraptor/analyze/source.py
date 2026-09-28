from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ReviewSource:
    """One server-resident result source used by the live review engine."""

    source_type: str
    source_id: str
    artifact: str
    vql: str
    environment: Mapping[str, str]

    def query_environment(self) -> dict[str, str]:
        return dict(self.environment)

    def identity(self) -> dict[str, str]:
        return {
            "source_type": self.source_type,
            "source_id": self.source_id,
            "artifact": self.artifact,
        }


def hunt_source(hunt_id: str, artifact: str) -> ReviewSource:
    return ReviewSource(
        source_type="hunt",
        source_id=hunt_id,
        artifact=artifact,
        vql="hunt_results(hunt_id=HuntId, artifact=ArtifactName)",
        environment={
            "HuntId": hunt_id,
            "ArtifactName": artifact,
        },
    )


def flow_source(
    *,
    client_id: str,
    flow_id: str,
    artifact: str,
) -> ReviewSource:
    return ReviewSource(
        source_type="flow",
        source_id=f"{client_id}:{flow_id}:{artifact}",
        artifact=artifact,
        vql=(
            "source(client_id=ClientId, flow_id=FlowId, "
            "artifact=ArtifactName)"
        ),
        environment={
            "ClientId": client_id,
            "FlowId": flow_id,
            "ArtifactName": artifact,
        },
    )

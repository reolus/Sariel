from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator


class SuggestedRelationship(str, Enum):
    SUGGESTS_CAN_REACH = "SUGGESTS_CAN_REACH"
    SUGGESTS_LATERAL_MOVE = "SUGGESTS_LATERAL_MOVE"
    SUGGESTS_PRIV_ESC = "SUGGESTS_PRIV_ESC"
    SUGGESTS_CREDENTIAL_ACCESS = "SUGGESTS_CREDENTIAL_ACCESS"
    SUGGESTS_EXPLOITABLE_FROM = "SUGGESTS_EXPLOITABLE_FROM"
    SUGGESTS_ATTACK_TECHNIQUE = "SUGGESTS_ATTACK_TECHNIQUE"


class EvidenceItem(BaseModel):
    claim: str = Field(..., min_length=3)
    source: str | None = None
    node_id: str | None = None
    relationship_id: str | None = None


class AttackVectorSuggestion(BaseModel):
    source_asset: str
    target_asset: str | None = None
    suggested_relationship: SuggestedRelationship
    confidence: float = Field(..., ge=0.0, le=1.0)
    attack_method: str = Field(..., min_length=3)
    path_type: Literal[
        "vulnerability_overlap",
        "reachability_based",
        "credential_based",
        "privilege_based",
        "service_exposure_based",
        "unknown"
    ]
    mitre_attack_techniques: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_data_sources: list[str] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def cap_confidence_when_missing_evidence(cls, value: float, info: Any) -> float:
        # Pydantic v2 validates fields independently. Final confidence capping
        # is also enforced in validators.py where the full object is available.
        return value


class AttackMappingResponse(BaseModel):
    source_asset: str
    target_asset: str | None = None
    summary: str
    suggestions: list[AttackVectorSuggestion] = Field(default_factory=list)


class GraphPathNode(BaseModel):
    id: str
    labels: list[str] = Field(default_factory=list)
    hostname: str | None = None
    label: str | None = None
    canonical_id: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphPathRelationship(BaseModel):
    id: str
    type: str
    start_node_id: str
    end_node_id: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphContext(BaseModel):
    source_hostname: str
    target_hostname: str | None = None
    max_hops: int = 4
    nodes: list[GraphPathNode] = Field(default_factory=list)
    relationships: list[GraphPathRelationship] = Field(default_factory=list)
    paths: list[dict[str, Any]] = Field(default_factory=list)

"""
/traversal — dynamic attack path traversal from a compromised node.

POST /traversal/run        — start traversal from a compromised node
GET  /traversal/paths      — query discovered traversal paths
GET  /traversal/paths/{id} — single path with full hop detail
GET  /traversal/techniques — list available techniques
"""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from sariel.api.deps import AuthDep, get_runner
from sariel.engine.runner import AttackPathRunner
from sariel.engine.techniques import ALL_TECHNIQUES

router = APIRouter(prefix="/traversal", tags=["traversal"])


# ── Request / response models ─────────────────────────────────────────────────

class TraversalRunRequest(BaseModel):
    start_node_id: str = Field(
        ...,
        description="canonical_id of the compromised node to start from",
    )
    max_depth: int = Field(5, ge=1, le=10, description="Maximum hops to follow")
    max_paths: int = Field(100, ge=1, le=500, description="Maximum paths to discover")
    snapshot_id: Optional[str] = Field(None, description="Optional snapshot tag")


class TraversalRunResponse(BaseModel):
    start_node_id: str
    total_paths: int
    terminal_paths: int
    max_depth_reached: int
    CRITICAL: int
    HIGH: int
    MEDIUM: int
    LOW: int
    technique_usage: dict
    duration_seconds: float


class HopDetail(BaseModel):
    source_id: str
    source_label: str
    target_id: str
    target_label: str
    technique_id: str
    technique_name: str
    technique_category: str
    mitre_id: str
    edge_type: str
    hop_score: float
    hop_confidence: float
    evidence: list[str]
    missing_evidence: list[str]


class TraversalPathSummary(BaseModel):
    path_id: str
    start_node_id: str
    end_node_id: str
    total_score: float
    severity: str
    depth: int
    is_terminal: bool
    terminal_reason: str
    technique_chain: list[str]


class TraversalPathDetail(TraversalPathSummary):
    hops: list[HopDetail]


class TraversalPathsResponse(BaseModel):
    total: int
    paths: list[TraversalPathSummary]


class TechniqueInfo(BaseModel):
    id: str
    name: str
    category: str
    mitre_id: str
    description: str
    base_confidence: float


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/run", response_model=TraversalRunResponse)
async def run_traversal(
    body: TraversalRunRequest,
    _: AuthDep,
    runner: AttackPathRunner = Depends(get_runner),
):
    """
    Trigger dynamic BFS traversal from a compromised node.

    The engine selects attack techniques at each hop based on the target
    node's actual OS, services, vulnerabilities, and cloud identity —
    not a fixed pattern template.
    """
    result = await runner.run_from_node(
        start_node_id=body.start_node_id,
        max_depth=body.max_depth,
        max_paths=body.max_paths,
        snapshot_id=body.snapshot_id,
    )
    return TraversalRunResponse(**result)


@router.get("/paths", response_model=TraversalPathsResponse)
async def list_traversal_paths(
    _: AuthDep,
    runner: AttackPathRunner = Depends(get_runner),
    start_node_id: Optional[str] = Query(None, description="Filter by originating node"),
    min_score: float = Query(0.0, ge=0, le=100),
    severity: Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    terminal_only: bool = Query(False, description="Only show paths that reached a high-value target"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List traversal paths, optionally filtered."""
    paths = await runner.get_traversal_paths(
        start_node_id=start_node_id,
        min_score=min_score,
        severity=severity,
        terminal_only=terminal_only,
        limit=limit,
        offset=offset,
    )
    return TraversalPathsResponse(
        total=len(paths),
        paths=[
            TraversalPathSummary(
                path_id=p["path_id"],
                start_node_id=p["start_node_id"],
                end_node_id=p["end_node_id"],
                total_score=p["total_score"],
                severity=p["severity"],
                depth=p["depth"],
                is_terminal=p["is_terminal"],
                terminal_reason=p["terminal_reason"],
                technique_chain=p["technique_chain"],
            )
            for p in paths
        ],
    )


@router.get("/paths/{path_id}", response_model=TraversalPathDetail)
async def get_traversal_path(
    path_id: str,
    _: AuthDep,
    runner: AttackPathRunner = Depends(get_runner),
):
    """Get full detail for a single traversal path including all hop data."""
    paths = await runner.get_traversal_paths(limit=1, offset=0)
    # Fetch the specific path
    import asyncpg, json
    from sariel.models.config import get_settings
    s = get_settings()
    dsn = s.postgres_dsn.replace("+asyncpg", "")
    conn = await asyncpg.connect(dsn)
    try:
        row = await conn.fetchrow(
            "SELECT * FROM traversal_paths WHERE path_id = $1", path_id
        )
    finally:
        await conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Traversal path {path_id} not found")

    hops_raw = json.loads(row["hops"])
    return TraversalPathDetail(
        path_id=row["path_id"],
        start_node_id=row["start_node_id"],
        end_node_id=row["end_node_id"],
        total_score=row["total_score"],
        severity=row["severity"],
        depth=row["depth"],
        is_terminal=row["is_terminal"],
        terminal_reason=row["terminal_reason"],
        technique_chain=json.loads(row["technique_chain"]),
        hops=[
            HopDetail(
                source_id=h["source_id"],
                source_label=h["source_label"],
                target_id=h["target_id"],
                target_label=h["target_label"],
                technique_id=h["technique_id"],
                technique_name=h["technique_name"],
                technique_category=h["technique_category"],
                mitre_id=h["mitre_id"],
                edge_type=h["edge_type"],
                hop_score=h["hop_score"],
                hop_confidence=h["hop_confidence"],
                evidence=h.get("evidence", []),
                missing_evidence=h.get("missing_evidence", []),
            )
            for h in hops_raw
        ],
    )


@router.get("/techniques", response_model=list[TechniqueInfo])
async def list_techniques(_: AuthDep):
    """List all available attack techniques with their MITRE mappings."""
    return [
        TechniqueInfo(
            id=t.id,
            name=t.name,
            category=t.category,
            mitre_id=t.mitre_id,
            description=t.description,
            base_confidence=t.base_confidence,
        )
        for t in ALL_TECHNIQUES
    ]

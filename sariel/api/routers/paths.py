"""GET /paths/{id} — full path detail with nodes, edges, and fixes."""
from __future__ import annotations
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from sariel.api.deps import AuthDep, get_runner, get_graph_queries, get_explainer
from sariel.engine.runner import AttackPathRunner
from sariel.graph.queries import GraphQueries
from sariel.explainer.llm import LLMExplainer

router = APIRouter(prefix="/paths", tags=["paths"])


class NodeDetail(BaseModel):
    canonical_id: str
    node_type: str
    label: str
    cloud: Optional[str] = None
    properties: dict[str, Any] = {}


class EdgeDetail(BaseModel):
    from_id: str
    to_id: str
    rel: str
    properties: dict[str, Any] = {}


class FixRecommendation(BaseModel):
    priority: int
    action: str
    category: str


class PathDetail(BaseModel):
    path_id: str
    pattern_name: str
    score: float
    severity: str
    confidence: str
    title: str
    cloud: str
    account_id: str
    factors: dict
    nodes: list[NodeDetail]
    edges: list[EdgeDetail]
    fix_recommendations: list[FixRecommendation]
    suppressed: bool
    scored_at: Optional[str]
    explanation: Optional[str] = None
    snapshot_id: Optional[str] = None


@router.get("/{path_id}", response_model=PathDetail)
async def get_path(
    path_id: str,
    _: AuthDep,
    runner: AttackPathRunner = Depends(get_runner),
    graph: GraphQueries = Depends(get_graph_queries),
    explainer: LLMExplainer = Depends(get_explainer),
    with_explanation: bool = False,
):
    path = await runner.get_path_by_id(path_id)
    if not path:
        raise HTTPException(status_code=404, detail=f"Path {path_id} not found")

    # Fetch full node and edge data from Neo4j
    graph_data = graph.get_path_nodes_and_edges(path["node_ids"])

    nodes = []
    for n in graph_data["nodes"]:
        labels = n.get("_labels", [])
        node_type = next(
            (l for l in labels if l not in ("SarielNode", "ComputeAsset",
             "IdentityPrincipal", "NetworkControl", "DataStoreBase", "CloudAccount")),
            labels[0] if labels else "Unknown",
        )
        nodes.append(NodeDetail(
            canonical_id=n["canonical_id"],
            node_type=node_type,
            label=n.get("label", n["canonical_id"]),
            cloud=n.get("cloud"),
            properties={k: v for k, v in n.items()
                        if k not in ("canonical_id", "label", "cloud", "_labels")},
        ))

    edges = [
        EdgeDetail(
            from_id=e["from_id"],
            to_id=e["to_id"],
            rel=e["rel"],
            properties={k: v for k, v in e.items()
                        if k not in ("from_id", "to_id", "rel")},
        )
        for e in graph_data["edges"]
    ]

    explanation = None
    if with_explanation:
        explanation = await explainer.explain(path)

    return PathDetail(
        path_id=path["path_id"],
        pattern_name=path["pattern_name"],
        score=path["score"],
        severity=path["severity"],
        confidence=path["confidence"],
        title=path["title"],
        cloud=path["cloud"],
        account_id=path["account_id"],
        factors=path["factors"],
        nodes=nodes,
        edges=edges,
        fix_recommendations=[
            FixRecommendation(**f) for f in path.get("fix_recommendations", [])
        ],
        suppressed=path["suppressed"],
        scored_at=path.get("scored_at"),
        explanation=explanation,
        snapshot_id=path.get("snapshot_id"),
    )

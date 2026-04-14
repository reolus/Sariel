"""GET /assets — inventory with exposure and path counts."""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from sariel.api.deps import AuthDep, get_graph_queries
from sariel.graph.queries import GraphQueries

router = APIRouter(prefix="/assets", tags=["assets"])


class AssetSummary(BaseModel):
    canonical_id: str
    node_type: str
    label: str
    cloud: Optional[str] = None
    account_id: Optional[str] = None
    has_public_ip: Optional[bool] = None
    sensitivity: Optional[str] = None
    properties: dict = {}


class AssetsResponse(BaseModel):
    total: int
    assets: list[AssetSummary]


@router.get("", response_model=AssetsResponse)
async def list_assets(
    _: AuthDep,
    graph: GraphQueries = Depends(get_graph_queries),
    node_type: Optional[str] = Query(None, description="EC2Instance | AzureVM | IAMUser | EntraUser | etc."),
    cloud: Optional[str] = Query(None, description="aws | azure"),
    has_public_ip: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    raw = graph.list_assets(
        node_type=node_type,
        cloud=cloud,
        has_public_ip=has_public_ip,
        limit=limit,
        offset=offset,
    )

    assets = []
    for n in raw:
        labels = n.get("_labels", [])
        node_type_val = next(
            (l for l in labels if l not in ("SarielNode", "ComputeAsset",
             "IdentityPrincipal", "NetworkControl", "DataStoreBase", "CloudAccount")),
            labels[0] if labels else "Unknown",
        )
        assets.append(AssetSummary(
            canonical_id=n["canonical_id"],
            node_type=node_type_val,
            label=n.get("label", n["canonical_id"]),
            cloud=n.get("cloud"),
            account_id=n.get("account_id"),
            has_public_ip=n.get("has_public_ip"),
            sensitivity=n.get("sensitivity"),
            properties={k: v for k, v in n.items()
                        if k not in ("canonical_id", "label", "cloud", "account_id",
                                     "has_public_ip", "sensitivity", "_labels")},
        ))

    return AssetsResponse(total=len(assets), assets=assets)


@router.get("/search", response_model=AssetsResponse)
async def search_assets(
    _: AuthDep,
    graph: GraphQueries = Depends(get_graph_queries),
    q: str = Query(..., min_length=2, description="Search term"),
    limit: int = Query(20, ge=1, le=100),
):
    raw = graph.search_assets(q, limit=limit)
    assets = []
    for n in raw:
        labels = n.get("_labels", [])
        node_type_val = next(
            (l for l in labels if l not in ("SarielNode", "ComputeAsset",
             "IdentityPrincipal", "NetworkControl", "DataStoreBase", "CloudAccount")),
            labels[0] if labels else "Unknown",
        )
        assets.append(AssetSummary(
            canonical_id=n["canonical_id"],
            node_type=node_type_val,
            label=n.get("label", n["canonical_id"]),
            cloud=n.get("cloud"),
            account_id=n.get("account_id"),
            has_public_ip=n.get("has_public_ip"),
            sensitivity=n.get("sensitivity"),
        ))
    return AssetsResponse(total=len(assets), assets=assets)

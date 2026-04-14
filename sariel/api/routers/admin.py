"""Admin endpoints — trigger scans, check health, view stats."""
from __future__ import annotations
from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel

from sariel.api.deps import AuthDep, get_runner, get_neo4j_driver, get_graph_queries
from sariel.engine.runner import AttackPathRunner
from sariel.graph.queries import GraphQueries

router = APIRouter(prefix="/admin", tags=["admin"])


class HealthResponse(BaseModel):
    status: str
    neo4j: str
    timestamp: str


class ScanTriggerResponse(BaseModel):
    message: str
    triggered_at: str


class StatsResponse(BaseModel):
    node_count: int
    edge_count: int
    timestamp: str


@router.get("/health", response_model=HealthResponse)
async def health(driver=Depends(get_neo4j_driver)):
    neo4j_status = "ok"
    try:
        driver.verify_connectivity()
    except Exception:
        neo4j_status = "unreachable"
    return HealthResponse(
        status="ok" if neo4j_status == "ok" else "degraded",
        neo4j=neo4j_status,
        timestamp=datetime.utcnow().isoformat(),
    )


@router.get("/stats", response_model=StatsResponse)
async def stats(_: AuthDep, graph: GraphQueries = Depends(get_graph_queries)):
    from sariel.graph.writer import GraphWriter
    from sariel.models.config import get_settings
    s = get_settings()
    writer = GraphWriter(s.neo4j_uri, s.neo4j_user, s.neo4j_password)
    writer.connect()
    node_count = writer.get_node_count()
    edge_count = writer.get_edge_count()
    writer.close()
    return StatsResponse(
        node_count=node_count,
        edge_count=edge_count,
        timestamp=datetime.utcnow().isoformat(),
    )


@router.post("/scan/trigger", response_model=ScanTriggerResponse)
async def trigger_scan(
    _: AuthDep,
    background_tasks: BackgroundTasks,
    runner: AttackPathRunner = Depends(get_runner),
):
    """Trigger attack path analysis in the background (does not re-pull cloud data)."""
    async def run():
        await runner.run_all_patterns()

    background_tasks.add_task(run)
    return ScanTriggerResponse(
        message="Attack path analysis triggered",
        triggered_at=datetime.utcnow().isoformat(),
    )

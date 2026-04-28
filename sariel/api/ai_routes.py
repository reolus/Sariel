from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends

from sariel.ai.attack_mapper import AttackMapper
from sariel.ai.graph_context import build_asset_context
from sariel.ai.graph_writer import write_ai_suggestions

# Replace this import with your actual Sariel dependency.
# from sariel.graph.neo4j import get_neo4j_driver

router = APIRouter(prefix="/ai", tags=["AI Attack Mapping"])


class MapAttackVectorsRequest(BaseModel):
    source_hostname: str = Field(..., examples=["Genetec-06"])
    target_hostname: str | None = Field(None, examples=["GIS-GEO-ARC-01"])
    max_hops: int = Field(4, ge=1, le=8)
    write_to_graph: bool = False


def get_neo4j_driver_placeholder():
    raise RuntimeError("Wire this to Sariel's existing Neo4j driver dependency.")


@router.post("/map-attack-vectors")
def map_attack_vectors(
    request: MapAttackVectorsRequest,
    driver=Depends(get_neo4j_driver_placeholder),
):
    context = build_asset_context(
        driver=driver,
        source_hostname=request.source_hostname,
        target_hostname=request.target_hostname,
        max_hops=request.max_hops,
    )

    mapper = AttackMapper()
    response = mapper.map_attack_vectors(context)

    written = 0
    if request.write_to_graph:
        written = write_ai_suggestions(driver, response)

    return {
        "source_hostname": request.source_hostname,
        "target_hostname": request.target_hostname,
        "written_suggestions": written,
        "result": response.model_dump(),
    }

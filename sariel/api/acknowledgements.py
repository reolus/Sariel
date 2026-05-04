from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException

from sariel.db.neo4j import get_neo4j_driver
from sariel.services.acknowledgements import (
    AcknowledgementService,
    DEFAULT_ACK_DAYS,
)


router = APIRouter(prefix="/acknowledgements", tags=["acknowledgements"])


class AcknowledgeTargetRequest(BaseModel):
    target_ref: str = Field(..., description="canonical_id, hostname, label, sys_name, or IP")
    reason: str
    acknowledged_by: str
    days: int = DEFAULT_ACK_DAYS


@router.post("/targets")
def acknowledge_target(payload: AcknowledgeTargetRequest, driver=Depends(get_neo4j_driver)):
    service = AcknowledgementService(driver)

    try:
        result = service.acknowledge_target(
            target_ref=payload.target_ref,
            acknowledged_by=payload.acknowledged_by,
            reason=payload.reason,
            days=payload.days,
        )
        return result.__dict__
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.delete("/targets/{target_ref}")
def unacknowledge_target(target_ref: str, driver=Depends(get_neo4j_driver)):
    service = AcknowledgementService(driver)

    try:
        return service.unacknowledge_target(target_ref=target_ref)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/targets")
def list_acknowledged_targets(driver=Depends(get_neo4j_driver)):
    service = AcknowledgementService(driver)
    return service.list_acknowledged_targets()
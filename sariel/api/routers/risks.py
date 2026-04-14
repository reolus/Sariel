"""GET /risks — ranked attack paths."""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from sariel.api.deps import AuthDep, get_runner, get_explainer
from sariel.engine.runner import AttackPathRunner
from sariel.explainer.llm import LLMExplainer

router = APIRouter(prefix="/risks", tags=["risks"])


class FactorsModel(BaseModel):
    exposure: float
    exploitability: float
    privilege: float
    sensitivity: float
    modifiers: dict = {}


class RiskSummary(BaseModel):
    path_id: str
    pattern_name: str
    score: float
    severity: str
    confidence: str
    title: str
    cloud: str
    account_id: str
    factors: FactorsModel
    suppressed: bool
    scored_at: Optional[str]
    explanation: Optional[str] = None


class RisksResponse(BaseModel):
    total: int
    paths: list[RiskSummary]
    filters_applied: dict


@router.get("", response_model=RisksResponse)
async def list_risks(
    _: AuthDep,
    runner: AttackPathRunner = Depends(get_runner),
    explainer: LLMExplainer = Depends(get_explainer),
    min_score: float = Query(0.0, ge=0, le=100, description="Minimum risk score"),
    severity: Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    cloud: Optional[str] = Query(None, description="aws | azure"),
    pattern: Optional[str] = Query(None, description="Pattern name filter"),
    include_suppressed: bool = Query(False),
    with_explanations: bool = Query(False, description="Generate LLM explanations (slower)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    paths = await runner.get_paths(
        min_score=min_score,
        severity=severity,
        cloud=cloud,
        pattern=pattern,
        include_suppressed=include_suppressed,
        limit=limit,
        offset=offset,
    )

    if with_explanations:
        explanations = await explainer.explain_batch(paths)
        for path in paths:
            path["explanation"] = explanations.get(path["path_id"])

    return RisksResponse(
        total=len(paths),
        paths=[
            RiskSummary(
                path_id=p["path_id"],
                pattern_name=p["pattern_name"],
                score=p["score"],
                severity=p["severity"],
                confidence=p["confidence"],
                title=p["title"],
                cloud=p["cloud"],
                account_id=p["account_id"],
                factors=FactorsModel(**p["factors"]),
                suppressed=p["suppressed"],
                scored_at=p.get("scored_at"),
                explanation=p.get("explanation"),
            )
            for p in paths
        ],
        filters_applied={
            "min_score": min_score,
            "severity": severity,
            "cloud": cloud,
            "pattern": pattern,
            "include_suppressed": include_suppressed,
        },
    )

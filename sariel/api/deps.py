"""FastAPI dependency injection — shared clients and auth."""
from __future__ import annotations
from functools import lru_cache
from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, status
from neo4j import GraphDatabase, Driver

from sariel.models.config import Settings, get_settings
from sariel.engine.runner import AttackPathRunner
from sariel.graph.queries import GraphQueries
from sariel.scoring.engine import ScoringEngine
from sariel.explainer.llm import LLMExplainer


def get_neo4j_driver(settings: Settings = Depends(get_settings)) -> Driver:
    return GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )


def get_graph_queries(driver: Driver = Depends(get_neo4j_driver)) -> GraphQueries:
    return GraphQueries(driver)


def get_runner(
    driver: Driver = Depends(get_neo4j_driver),
    settings: Settings = Depends(get_settings),
) -> AttackPathRunner:
    scoring = ScoringEngine(
        critical_threshold=settings.score_critical_threshold,
        high_threshold=settings.score_high_threshold,
        suppress_below=settings.score_suppress_below,
    )
    return AttackPathRunner(
        neo4j_driver=driver,
        pg_dsn=settings.postgres_dsn,
        scoring_engine=scoring,
    )


def get_explainer(settings: Settings = Depends(get_settings)) -> LLMExplainer:
    key = settings.anthropic_api_key if settings.llm_provider == "anthropic" else settings.openai_api_key
    return LLMExplainer(provider=settings.llm_provider, api_key=key)


def verify_api_key(
    x_sariel_key: Annotated[Optional[str], Header()] = None,
    settings: Settings = Depends(get_settings),
) -> str:
    if not settings.api_keys:
        # Dev mode — no key required
        return "dev"
    if not x_sariel_key or x_sariel_key not in settings.api_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return x_sariel_key


AuthDep = Annotated[str, Depends(verify_api_key)]

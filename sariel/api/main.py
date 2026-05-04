"""
Sariel FastAPI application entry point.
"""
from __future__ import annotations
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sariel.api.routers import risks, paths, assets, admin
from sariel.models.config import get_settings

from sariel.api.acknowledgements import router as acknowledgements_router

app.include_router(acknowledgements_router)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info("Sariel API starting — neo4j: %s", settings.neo4j_uri)
    yield
    logger.info("Sariel API shutting down")


app = FastAPI(
    title="Sariel Security Platform",
    description="Context-aware cloud attack path detection and risk prioritization.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(risks.router)
app.include_router(paths.router)
app.include_router(assets.router)
app.include_router(admin.router)


@app.get("/")
async def root():
    return {
        "product": "Sariel",
        "version": "0.1.0",
        "docs": "/docs",
    }

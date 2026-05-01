"""
Initialize Postgres schema and Neo4j indexes.
Run once on a fresh install: python scripts/init_db.py
"""
import asyncio
import logging
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import asyncpg
from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_paths (
    path_id             TEXT PRIMARY KEY,
    pattern_name        TEXT NOT NULL,
    score               DOUBLE PRECISION NOT NULL,
    severity            TEXT NOT NULL,
    confidence          TEXT NOT NULL DEFAULT 'partial',
    title               TEXT NOT NULL,
    cloud               TEXT NOT NULL,
    account_id          TEXT NOT NULL,
    node_ids            JSONB NOT NULL DEFAULT '[]',
    factors             JSONB NOT NULL DEFAULT '{}',
    fix_recommendations JSONB NOT NULL DEFAULT '[]',
    suppressed          BOOLEAN NOT NULL DEFAULT FALSE,
    suppression_reason  TEXT NOT NULL DEFAULT '',
    explanation         TEXT,
    snapshot_id         TEXT,
    scored_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_paths_score    ON attack_paths (score DESC);
CREATE INDEX IF NOT EXISTS idx_paths_severity ON attack_paths (severity);
CREATE INDEX IF NOT EXISTS idx_paths_cloud    ON attack_paths (cloud);
CREATE INDEX IF NOT EXISTS idx_paths_scored   ON attack_paths (scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_paths_suppressed ON attack_paths (suppressed);

CREATE TABLE IF NOT EXISTS scan_history (
    id              SERIAL PRIMARY KEY,
    snapshot_id     TEXT NOT NULL,
    cloud           TEXT NOT NULL,
    account_id      TEXT NOT NULL,
    nodes_written   INTEGER NOT NULL DEFAULT 0,
    edges_written   INTEGER NOT NULL DEFAULT 0,
    errors          JSONB NOT NULL DEFAULT '[]',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS traversal_paths (
    path_id         TEXT PRIMARY KEY,
    start_node_id   TEXT NOT NULL,
    end_node_id     TEXT NOT NULL,
    total_score     DOUBLE PRECISION NOT NULL,
    severity        TEXT NOT NULL,
    depth           INTEGER NOT NULL DEFAULT 0,
    is_terminal     BOOLEAN NOT NULL DEFAULT FALSE,
    terminal_reason TEXT NOT NULL DEFAULT '',
    technique_chain JSONB NOT NULL DEFAULT '[]',
    hops            JSONB NOT NULL DEFAULT '[]',
    snapshot_id     TEXT,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tpaths_score     ON traversal_paths (total_score DESC);
CREATE INDEX IF NOT EXISTS idx_tpaths_severity  ON traversal_paths (severity);
CREATE INDEX IF NOT EXISTS idx_tpaths_start     ON traversal_paths (start_node_id);
CREATE INDEX IF NOT EXISTS idx_tpaths_terminal  ON traversal_paths (is_terminal);
CREATE INDEX IF NOT EXISTS idx_tpaths_discovered ON traversal_paths (discovered_at DESC);

CREATE TABLE IF NOT EXISTS suppressions (
    id              SERIAL PRIMARY KEY,
    path_id         TEXT,
    pattern_name    TEXT,
    node_id         TEXT,
    reason          TEXT NOT NULL,
    created_by      TEXT NOT NULL DEFAULT 'system',
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def init_postgres(dsn: str):
    # asyncpg doesn't use the +asyncpg scheme prefix
    clean_dsn = dsn.replace("postgresql+asyncpg://", "postgresql://")
    logger.info("Connecting to Postgres...")
    conn = await asyncpg.connect(clean_dsn)
    try:
        await conn.execute(POSTGRES_SCHEMA)
        logger.info("Postgres schema initialized")
    finally:
        await conn.close()


def init_neo4j(uri: str, user: str, password: str):
    logger.info("Connecting to Neo4j...")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    driver.verify_connectivity()

    from sariel.graph.writer import GraphWriter
    writer = GraphWriter(uri, user, password)
    writer._driver = driver
    writer.setup_indexes()
    driver.close()
    logger.info("Neo4j indexes initialized")


async def main():
    from sariel.models.config import get_settings
    s = get_settings()
    await init_postgres(s.postgres_dsn)
    init_neo4j(s.neo4j_uri, s.neo4j_user, s.neo4j_password)
    logger.info("Database initialization complete")


if __name__ == "__main__":
    asyncio.run(main())

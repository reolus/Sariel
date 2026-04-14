"""
Attack path engine runner — executes all patterns against Neo4j,
scores results, and persists to Postgres.
"""
from __future__ import annotations
import asyncio
import logging
from datetime import datetime
from typing import Optional

import asyncpg
from neo4j import Driver

from sariel.engine.patterns import ALL_PATTERNS, PathPattern
from sariel.scoring.engine import ScoredPath, ScoringEngine

logger = logging.getLogger(__name__)


class AttackPathRunner:
    def __init__(
        self,
        neo4j_driver: Driver,
        pg_dsn: str,
        scoring_engine: Optional[ScoringEngine] = None,
    ):
        self._driver = neo4j_driver
        self._pg_dsn = pg_dsn
        self._scoring = scoring_engine or ScoringEngine()

    async def run_all_patterns(self, snapshot_id: Optional[str] = None) -> dict:
        """
        Execute all attack path patterns, score results, persist to Postgres.
        Returns summary stats.
        """
        started_at = datetime.utcnow()
        all_paths: list[ScoredPath] = []
        pattern_stats: dict[str, int] = {}

        for pattern in ALL_PATTERNS:
            try:
                paths = self._run_pattern(pattern)
                pattern_stats[pattern.name] = len(paths)
                all_paths.extend(paths)
                logger.info("Pattern %s: %d paths found", pattern.name, len(paths))
            except Exception as e:
                logger.error("Pattern %s failed: %s", pattern.name, e)
                pattern_stats[pattern.name] = -1

        # Deduplicate by path_id (same node set may match multiple patterns)
        seen: set[str] = set()
        unique_paths: list[ScoredPath] = []
        for path in all_paths:
            if path.path_id not in seen:
                seen.add(path.path_id)
                unique_paths.append(path)

        # Persist to Postgres
        try:
            await self._persist_paths(unique_paths, snapshot_id)
        except Exception as e:
            logger.error("Failed to persist paths: %s", e)

        summary = {
            "total_paths": len(unique_paths),
            "critical": sum(1 for p in unique_paths if p.severity.value == "CRITICAL" and not p.suppressed),
            "high": sum(1 for p in unique_paths if p.severity.value == "HIGH" and not p.suppressed),
            "medium": sum(1 for p in unique_paths if p.severity.value == "MEDIUM" and not p.suppressed),
            "suppressed": sum(1 for p in unique_paths if p.suppressed),
            "pattern_stats": pattern_stats,
            "duration_seconds": (datetime.utcnow() - started_at).total_seconds(),
        }
        logger.info("Attack path run complete: %s", summary)
        return summary

    def _run_pattern(self, pattern: PathPattern) -> list[ScoredPath]:
        paths: list[ScoredPath] = []
        with self._driver.session() as session:
            result = session.run(pattern.cypher)
            for record in result:
                row = dict(record)
                try:
                    scored = self._scoring.score_path(pattern.name, row)
                    paths.append(scored)
                except Exception as e:
                    logger.warning("Scoring failed for row in %s: %s", pattern.name, e)
        return paths

    async def _persist_paths(self, paths: list[ScoredPath], snapshot_id: Optional[str]) -> None:
        """Upsert scored paths into Postgres attack_paths table."""
        import json
        conn = await asyncpg.connect(self._pg_dsn.replace("+asyncpg", ""))
        try:
            for path in paths:
                await conn.execute(
                    """
                    INSERT INTO attack_paths (
                        path_id, pattern_name, score, severity, confidence,
                        title, cloud, account_id,
                        node_ids, factors, fix_recommendations,
                        suppressed, suppression_reason,
                        snapshot_id, scored_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                    ON CONFLICT (path_id) DO UPDATE SET
                        score = EXCLUDED.score,
                        severity = EXCLUDED.severity,
                        title = EXCLUDED.title,
                        factors = EXCLUDED.factors,
                        fix_recommendations = EXCLUDED.fix_recommendations,
                        suppressed = EXCLUDED.suppressed,
                        snapshot_id = EXCLUDED.snapshot_id,
                        scored_at = EXCLUDED.scored_at
                    """,
                    path.path_id,
                    path.pattern_name,
                    path.score,
                    path.severity.value,
                    path.confidence,
                    path.title,
                    path.cloud,
                    path.account_id,
                    json.dumps(path.node_ids),
                    json.dumps({
                        "exposure": path.factors.exposure,
                        "exploitability": path.factors.exploitability,
                        "privilege": path.factors.privilege,
                        "sensitivity": path.factors.sensitivity,
                        "modifiers": path.factors.modifiers,
                    }),
                    json.dumps(path.fix_recommendations),
                    path.suppressed,
                    path.suppression_reason,
                    snapshot_id,
                    path.scored_at,
                )
        finally:
            await conn.close()

    async def get_paths(
        self,
        min_score: float = 0.0,
        severity: Optional[str] = None,
        cloud: Optional[str] = None,
        pattern: Optional[str] = None,
        include_suppressed: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        import json
        conditions = ["score >= $1"]
        params: list = [min_score]
        idx = 2

        if not include_suppressed:
            conditions.append(f"suppressed = ${idx}")
            params.append(False)
            idx += 1
        if severity:
            conditions.append(f"severity = ${idx}")
            params.append(severity.upper())
            idx += 1
        if cloud:
            conditions.append(f"cloud = ${idx}")
            params.append(cloud.lower())
            idx += 1
        if pattern:
            conditions.append(f"pattern_name = ${idx}")
            params.append(pattern)
            idx += 1

        where = "WHERE " + " AND ".join(conditions)
        params.extend([limit, offset])

        conn = await asyncpg.connect(self._pg_dsn.replace("+asyncpg", ""))
        try:
            rows = await conn.fetch(
                f"""
                SELECT path_id, pattern_name, score, severity, confidence,
                       title, cloud, account_id, node_ids, factors,
                       fix_recommendations, suppressed, scored_at, snapshot_id
                FROM attack_paths
                {where}
                ORDER BY score DESC, scored_at DESC
                LIMIT ${idx} OFFSET ${idx+1}
                """,
                *params,
            )
            return [
                {
                    **dict(row),
                    "node_ids": json.loads(row["node_ids"]),
                    "factors": json.loads(row["factors"]),
                    "fix_recommendations": json.loads(row["fix_recommendations"]),
                    "scored_at": row["scored_at"].isoformat() if row["scored_at"] else None,
                }
                for row in rows
            ]
        finally:
            await conn.close()

    async def get_path_by_id(self, path_id: str) -> Optional[dict]:
        import json
        conn = await asyncpg.connect(self._pg_dsn.replace("+asyncpg", ""))
        try:
            row = await conn.fetchrow(
                "SELECT * FROM attack_paths WHERE path_id = $1", path_id
            )
            if not row:
                return None
            return {
                **dict(row),
                "node_ids": json.loads(row["node_ids"]),
                "factors": json.loads(row["factors"]),
                "fix_recommendations": json.loads(row["fix_recommendations"]),
                "scored_at": row["scored_at"].isoformat() if row["scored_at"] else None,
            }
        finally:
            await conn.close()

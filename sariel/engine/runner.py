"""
Attack path engine runner — executes all patterns against Neo4j,
scores results, and persists to Postgres.

Two complementary modes:
1. run_all_patterns()   — static pattern matching (cloud IAM / identity paths)
2. run_from_node()      — dynamic BFS traversal from a compromised node,
                          selecting attack techniques hop-by-hop based on
                          each node's OS, services, and vulnerabilities
3. run_full()           — runs both and persists everything
"""
from __future__ import annotations
import json
import logging
from datetime import datetime
from typing import Optional

import asyncpg
from neo4j import Driver

from sariel.engine.patterns import ALL_PATTERNS, PathPattern
from sariel.engine.traversal import TraversalEngine, TraversalPath
from sariel.scoring.engine import ScoredPath, ScoringEngine

logger = logging.getLogger(__name__)


def _count_techniques(paths: list[TraversalPath]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in paths:
        for tid in path.technique_chain:
            counts[tid] = counts.get(tid, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


class AttackPathRunner:
    def __init__(self, neo4j_driver: Driver, pg_dsn: str, scoring_engine: Optional[ScoringEngine] = None):
        self._driver = neo4j_driver
        self._pg_dsn = pg_dsn
        self._scoring = scoring_engine or ScoringEngine()

    async def run_all_patterns(self, snapshot_id: Optional[str] = None) -> dict:
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
        seen: set[str] = set()
        unique_paths: list[ScoredPath] = []
        for path in all_paths:
            if path.path_id not in seen:
                seen.add(path.path_id)
                unique_paths.append(path)
        try:
            await self._persist_paths(unique_paths, snapshot_id)
        except Exception as e:
            logger.error("Failed to persist paths: %s", e)
        return {
            "total_paths": len(unique_paths),
            "critical": sum(1 for p in unique_paths if p.severity.value == "CRITICAL" and not p.suppressed),
            "high": sum(1 for p in unique_paths if p.severity.value == "HIGH" and not p.suppressed),
            "medium": sum(1 for p in unique_paths if p.severity.value == "MEDIUM" and not p.suppressed),
            "suppressed": sum(1 for p in unique_paths if p.suppressed),
            "pattern_stats": pattern_stats,
            "duration_seconds": (datetime.utcnow() - started_at).total_seconds(),
        }

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
        conn = await asyncpg.connect(self._pg_dsn.replace("+asyncpg", ""))
        try:
            for path in paths:
                await conn.execute(
                    """
                    INSERT INTO attack_paths (
                        path_id, pattern_name, score, severity, confidence,
                        title, cloud, account_id, node_ids, factors, fix_recommendations,
                        suppressed, suppression_reason, snapshot_id, scored_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                    ON CONFLICT (path_id) DO UPDATE SET
                        score = EXCLUDED.score, severity = EXCLUDED.severity,
                        title = EXCLUDED.title, factors = EXCLUDED.factors,
                        fix_recommendations = EXCLUDED.fix_recommendations,
                        suppressed = EXCLUDED.suppressed, snapshot_id = EXCLUDED.snapshot_id,
                        scored_at = EXCLUDED.scored_at
                    """,
                    path.path_id, path.pattern_name, path.score, path.severity.value,
                    path.confidence, path.title, path.cloud, path.account_id,
                    json.dumps(path.node_ids),
                    json.dumps({"exposure": path.factors.exposure, "exploitability": path.factors.exploitability,
                                "privilege": path.factors.privilege, "sensitivity": path.factors.sensitivity,
                                "modifiers": path.factors.modifiers}),
                    json.dumps(path.fix_recommendations), path.suppressed,
                    path.suppression_reason, snapshot_id, path.scored_at,
                )
        finally:
            await conn.close()

    # ─── Dynamic traversal ────────────────────────────────────────────────────

    async def run_from_node(
        self,
        start_node_id: str,
        max_depth: int = 5,
        max_paths: int = 100,
        snapshot_id: Optional[str] = None,
    ) -> dict:
        """
        Dynamic BFS traversal from a compromised node. Techniques are selected
        at each hop based on the target node's actual OS, services, and
        vulnerabilities — attack methods change freely at every step.
        """
        started_at = datetime.utcnow()
        engine = TraversalEngine(neo4j_driver=self._driver, max_depth=max_depth, max_paths=max_paths)
        paths = engine.traverse_from(start_node_id)
        try:
            await self._persist_traversal_paths(paths, snapshot_id)
        except Exception as e:
            logger.error("Failed to persist traversal paths: %s", e)
        severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for p in paths:
            severity_counts[p.severity] = severity_counts.get(p.severity, 0) + 1
        return {
            "start_node_id": start_node_id,
            "total_paths": len(paths),
            "terminal_paths": sum(1 for p in paths if p.is_terminal),
            "max_depth_reached": max(p.depth for p in paths) if paths else 0,
            **severity_counts,
            "technique_usage": _count_techniques(paths),
            "duration_seconds": (datetime.utcnow() - started_at).total_seconds(),
        }

    async def run_full(
        self,
        compromised_node_ids: Optional[list[str]] = None,
        snapshot_id: Optional[str] = None,
        traversal_max_depth: int = 5,
    ) -> dict:
        pattern_summary = await self.run_all_patterns(snapshot_id)
        traversal_summaries = []
        for node_id in (compromised_node_ids or []):
            summary = await self.run_from_node(node_id, max_depth=traversal_max_depth, snapshot_id=snapshot_id)
            traversal_summaries.append(summary)
        return {"pattern_run": pattern_summary, "traversal_runs": traversal_summaries}

    async def _persist_traversal_paths(self, paths: list[TraversalPath], snapshot_id: Optional[str]) -> None:
        if not paths:
            return
        conn = await asyncpg.connect(self._pg_dsn.replace("+asyncpg", ""))
        try:
            for path in paths:
                hops_payload = [
                    {
                        "source_id": h.source_id, "source_label": h.source_label,
                        "target_id": h.target_id, "target_label": h.target_label,
                        "technique_id": h.technique.id, "technique_name": h.technique.name,
                        "technique_category": h.technique.category, "mitre_id": h.technique.mitre_id,
                        "edge_type": h.edge_type, "hop_score": h.hop_score,
                        "hop_confidence": h.hop_confidence, "evidence": h.evidence,
                        "missing_evidence": h.missing_evidence,
                    }
                    for h in path.hops
                ]
                await conn.execute(
                    """
                    INSERT INTO traversal_paths (
                        path_id, start_node_id, end_node_id, total_score, severity, depth,
                        is_terminal, terminal_reason, technique_chain, hops, snapshot_id, discovered_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                    ON CONFLICT (path_id) DO UPDATE SET
                        total_score=EXCLUDED.total_score, severity=EXCLUDED.severity,
                        is_terminal=EXCLUDED.is_terminal, terminal_reason=EXCLUDED.terminal_reason,
                        hops=EXCLUDED.hops, snapshot_id=EXCLUDED.snapshot_id,
                        discovered_at=EXCLUDED.discovered_at
                    """,
                    path.path_id, path.start_node_id, path.end_node_id,
                    path.total_score, path.severity, path.depth,
                    path.is_terminal, path.terminal_reason,
                    json.dumps(path.technique_chain), json.dumps(hops_payload),
                    snapshot_id, path.discovered_at,
                )
        finally:
            await conn.close()

    async def get_traversal_paths(
        self,
        start_node_id: Optional[str] = None,
        min_score: float = 0.0,
        severity: Optional[str] = None,
        terminal_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        conditions = ["total_score >= $1"]
        params: list = [min_score]
        idx = 2
        if start_node_id:
            conditions.append(f"start_node_id = ${idx}"); params.append(start_node_id); idx += 1
        if severity:
            conditions.append(f"severity = ${idx}"); params.append(severity.upper()); idx += 1
        if terminal_only:
            conditions.append(f"is_terminal = ${idx}"); params.append(True); idx += 1
        where = "WHERE " + " AND ".join(conditions)
        params.extend([limit, offset])
        conn = await asyncpg.connect(self._pg_dsn.replace("+asyncpg", ""))
        try:
            rows = await conn.fetch(
                f"""
                SELECT path_id, start_node_id, end_node_id, total_score, severity, depth,
                       is_terminal, terminal_reason, technique_chain, hops, snapshot_id, discovered_at
                FROM traversal_paths {where}
                ORDER BY total_score DESC, discovered_at DESC
                LIMIT ${idx} OFFSET ${idx+1}
                """,
                *params,
            )
            return [
                {**dict(row), "technique_chain": json.loads(row["technique_chain"]),
                 "hops": json.loads(row["hops"]),
                 "discovered_at": row["discovered_at"].isoformat() if row["discovered_at"] else None}
                for row in rows
            ]
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
        conditions = ["score >= $1"]
        params: list = [min_score]
        idx = 2
        if not include_suppressed:
            conditions.append(f"suppressed = ${idx}"); params.append(False); idx += 1
        if severity:
            conditions.append(f"severity = ${idx}"); params.append(severity.upper()); idx += 1
        if cloud:
            conditions.append(f"cloud = ${idx}"); params.append(cloud.lower()); idx += 1
        if pattern:
            conditions.append(f"pattern_name = ${idx}"); params.append(pattern); idx += 1
        where = "WHERE " + " AND ".join(conditions)
        params.extend([limit, offset])
        conn = await asyncpg.connect(self._pg_dsn.replace("+asyncpg", ""))
        try:
            rows = await conn.fetch(
                f"""
                SELECT path_id, pattern_name, score, severity, confidence, title, cloud,
                       account_id, node_ids, factors, fix_recommendations, suppressed, scored_at, snapshot_id
                FROM attack_paths {where}
                ORDER BY score DESC, scored_at DESC
                LIMIT ${idx} OFFSET ${idx+1}
                """,
                *params,
            )
            return [
                {**dict(row), "node_ids": json.loads(row["node_ids"]),
                 "factors": json.loads(row["factors"]),
                 "fix_recommendations": json.loads(row["fix_recommendations"]),
                 "scored_at": row["scored_at"].isoformat() if row["scored_at"] else None}
                for row in rows
            ]
        finally:
            await conn.close()

    async def get_path_by_id(self, path_id: str) -> Optional[dict]:
        conn = await asyncpg.connect(self._pg_dsn.replace("+asyncpg", ""))
        try:
            row = await conn.fetchrow("SELECT * FROM attack_paths WHERE path_id = $1", path_id)
            if not row:
                return None
            return {
                **dict(row), "node_ids": json.loads(row["node_ids"]),
                "factors": json.loads(row["factors"]),
                "fix_recommendations": json.loads(row["fix_recommendations"]),
                "scored_at": row["scored_at"].isoformat() if row["scored_at"] else None,
            }
        finally:
            await conn.close()

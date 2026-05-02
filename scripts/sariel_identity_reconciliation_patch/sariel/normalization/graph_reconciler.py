"""Repair and reconcile existing Sariel graph identity.

This job fixes the common split-brain graph problem where vulnerability data is
attached to one asset node while network reachability is attached to another
host node representing the same machine.
"""
from __future__ import annotations

import logging
from typing import Any

from neo4j import Driver

from sariel.normalization.host_identity import compute_host_identity

logger = logging.getLogger(__name__)

COMPUTE_LABELS = ["ComputeAsset", "EC2Instance", "AzureVM", "OnPremHost", "Host", "Asset"]


class GraphReconciler:
    def __init__(self, driver: Driver):
        self._driver = driver

    def run(self, dry_run: bool = False) -> dict[str, int]:
        stats = {
            "indexes_ensured": 0,
            "nodes_normalized": 0,
            "vulnerability_names_repaired": 0,
            "same_asset_edges": 0,
            "has_vuln_edges_copied": 0,
        }
        with self._driver.session() as session:
            if not dry_run:
                stats["indexes_ensured"] = session.execute_write(self._ensure_indexes)

            node_updates = self._collect_identity_updates(session)
            stats["nodes_normalized"] = len(node_updates)
            if not dry_run and node_updates:
                session.execute_write(self._write_identity_updates, node_updates)

            vuln_updates = self._collect_vulnerability_name_updates(session)
            stats["vulnerability_names_repaired"] = len(vuln_updates)
            if not dry_run and vuln_updates:
                session.execute_write(self._write_vulnerability_name_updates, vuln_updates)

            link_count = session.execute_write(self._link_duplicate_assets, dry_run)
            stats["same_asset_edges"] = link_count

            copied_count = session.execute_write(self._copy_has_vuln_to_reachable_hosts, dry_run)
            stats["has_vuln_edges_copied"] = copied_count

        logger.info("Graph reconciliation complete: %s", stats)
        return stats

    @staticmethod
    def _ensure_indexes(tx) -> int:
        statements = [
            "CREATE INDEX sariel_compute_hostname_key IF NOT EXISTS FOR (n:ComputeAsset) ON (n.hostname_key)",
            "CREATE INDEX sariel_compute_fqdn_key IF NOT EXISTS FOR (n:ComputeAsset) ON (n.fqdn_key)",
            "CREATE INDEX sariel_compute_ip_key IF NOT EXISTS FOR (n:ComputeAsset) ON (n.ip_key)",
            "CREATE INDEX sariel_asset_hostname_key IF NOT EXISTS FOR (n:Asset) ON (n.hostname_key)",
            "CREATE INDEX sariel_asset_ip_key IF NOT EXISTS FOR (n:Asset) ON (n.ip_key)",
            "CREATE INDEX sariel_vulnerability_name IF NOT EXISTS FOR (v:Vulnerability) ON (v.name)",
        ]
        for stmt in statements:
            tx.run(stmt).consume()
        return len(statements)

    def _collect_identity_updates(self, session) -> list[dict[str, Any]]:
        result = session.run(
            """
            MATCH (n)
            WHERE n:ComputeAsset OR n:EC2Instance OR n:AzureVM OR n:OnPremHost OR n:Host OR n:Asset
            RETURN id(n) AS node_id, properties(n) AS props, n.label AS label
            """
        )
        updates: list[dict[str, Any]] = []
        for record in result:
            props = dict(record["props"] or {})
            label = record.get("label") or props.get("label") or props.get("name") or ""
            identity = compute_host_identity(props, fallback_label=label)
            if not any(identity.values()):
                continue
            updates.append({"node_id": record["node_id"], **identity})
        return updates

    @staticmethod
    def _write_identity_updates(tx, updates: list[dict[str, Any]]) -> None:
        tx.run(
            """
            UNWIND $updates AS u
            MATCH (n) WHERE id(n) = u.node_id
            SET n.hostname_key = CASE WHEN u.hostname_key <> '' THEN u.hostname_key ELSE n.hostname_key END,
                n.fqdn_key = CASE WHEN u.fqdn_key <> '' THEN u.fqdn_key ELSE n.fqdn_key END,
                n.ip_key = CASE WHEN u.ip_key <> '' THEN u.ip_key ELSE n.ip_key END
            """,
            updates=updates,
        ).consume()

    def _collect_vulnerability_name_updates(self, session) -> list[dict[str, Any]]:
        result = session.run(
            """
            MATCH (v:Vulnerability)
            WHERE v.name IS NULL OR v.name = ''
            RETURN id(v) AS node_id, properties(v) AS props, v.label AS label
            """
        )
        updates: list[dict[str, Any]] = []
        for record in result:
            props = dict(record["props"] or {})
            name = (
                props.get("name")
                or props.get("cve_id")
                or props.get("nessus_plugin_name")
                or props.get("plugin_name")
                or record.get("label")
                or props.get("label")
                or props.get("canonical_id")
                or f"Vulnerability {record['node_id']}"
            )
            updates.append({"node_id": record["node_id"], "name": str(name)})
        return updates

    @staticmethod
    def _write_vulnerability_name_updates(tx, updates: list[dict[str, Any]]) -> None:
        tx.run(
            """
            UNWIND $updates AS u
            MATCH (v:Vulnerability) WHERE id(v) = u.node_id
            SET v.name = u.name
            """,
            updates=updates,
        ).consume()

    @staticmethod
    def _link_duplicate_assets(tx, dry_run: bool) -> int:
        query = """
        MATCH (a), (b)
        WHERE id(a) < id(b)
          AND (a:ComputeAsset OR a:EC2Instance OR a:AzureVM OR a:OnPremHost OR a:Host OR a:Asset)
          AND (b:ComputeAsset OR b:EC2Instance OR b:AzureVM OR b:OnPremHost OR b:Host OR b:Asset)
          AND (
                (a.hostname_key IS NOT NULL AND a.hostname_key <> '' AND a.hostname_key = b.hostname_key)
             OR (a.fqdn_key IS NOT NULL AND a.fqdn_key <> '' AND a.fqdn_key = b.fqdn_key)
             OR (a.ip_key IS NOT NULL AND a.ip_key <> '' AND a.ip_key = b.ip_key)
          )
        WITH a, b
        """
        if dry_run:
            return tx.run(query + "RETURN count(*) AS count").single()["count"]
        return tx.run(
            query
            + """
            MERGE (a)-[r:SAME_AS]->(b)
            SET r.reason = 'host_identity_match', r.updated_at = datetime()
            RETURN count(r) AS count
            """
        ).single()["count"]

    @staticmethod
    def _copy_has_vuln_to_reachable_hosts(tx, dry_run: bool) -> int:
        # Keep the original Nessus/asset nodes intact, but copy HAS_VULN to any
        # same-identity node that participates in CAN_REACH. This makes existing
        # attack-path queries work without destructive merges.
        query = """
        MATCH (asset)-[hv:HAS_VULN]->(v:Vulnerability)
        MATCH (asset)-[:SAME_AS|SAME_AS*1..2]-(host)
        WHERE host <> asset
          AND EXISTS { MATCH (host)-[:CAN_REACH]-() }
        WITH DISTINCT host, hv, v
        """
        if dry_run:
            return tx.run(query + "RETURN count(*) AS count").single()["count"]
        return tx.run(
            query
            + """
            MERGE (host)-[copied:HAS_VULN]->(v)
            SET copied += properties(hv),
                copied.source_identity_reconciled = true,
                copied.updated_at = datetime()
            RETURN count(copied) AS count
            """
        ).single()["count"]

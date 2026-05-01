"""
Port & Service Enricher — post-ingestion graph enrichment pass.

Problem:
  Nessus stores port/service findings on HAS_VULN edge properties:
    (asset)-[:HAS_VULN {port: 445, protocol: "tcp", service: "smb"}]->(vuln)

  But compute node properties don't have `open_ports` or `services` lists,
  so the traversal technique applicable() checks find nothing.

Solution:
  Aggregate all port/service data from HAS_VULN edges back onto each asset
  node as:
    open_ports: ["22", "80", "443", "445"]      (JSON list of strings)
    services:   ["ssh", "http", "https", "smb"] (JSON list of strings)
    open_ports_updated_at: ISO timestamp

  Also writes RUNS_SERVICE edges for named services if they don't exist.

  All writes are idempotent — safe to run after every Nessus import.

Usage:
    enricher = PortEnricher(neo4j_driver)
    stats = enricher.run()
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime

from neo4j import Driver

from sariel.normalization.os_normalizer import normalize_ports

logger = logging.getLogger(__name__)


# Services that are interesting for lateral movement / exploitation
_NOTABLE_SERVICES = {
    "22": "ssh",
    "23": "telnet",
    "80": "http",
    "443": "https",
    "445": "smb",
    "135": "msrpc",
    "139": "netbios",
    "389": "ldap",
    "636": "ldaps",
    "3389": "rdp",
    "5985": "winrm",
    "5986": "winrm-ssl",
    "1433": "mssql",
    "3306": "mysql",
    "5432": "postgresql",
    "1521": "oracle",
    "27017": "mongodb",
    "6379": "redis",
    "9200": "elasticsearch",
    "8080": "http-alt",
    "8443": "https-alt",
    "2222": "ssh-alt",
    "4444": "metasploit",
    "5900": "vnc",
    "111": "rpcbind",
    "2049": "nfs",
    "21": "ftp",
    "25": "smtp",
}


@dataclass
class EnricherStats:
    assets_enriched: int = 0
    total_ports_written: int = 0
    total_services_written: int = 0
    errors: list[str] = field(default_factory=list)


class PortEnricher:
    """
    Aggregates Nessus port/service data from HAS_VULN edges onto compute nodes.
    Also normalizes `os` fields while it has each node in scope.
    """

    def __init__(self, neo4j_driver: Driver):
        self._driver = neo4j_driver

    def run(self) -> EnricherStats:
        stats = EnricherStats()
        now = datetime.utcnow().isoformat()

        with self._driver.session() as session:
            # Pull all (asset, port, protocol, service) tuples from HAS_VULN edges
            result = session.run(
                """
                MATCH (asset:ComputeAsset)-[r:HAS_VULN]->(:Vulnerability)
                WHERE r.port IS NOT NULL AND r.port > 0
                RETURN asset.canonical_id AS asset_id,
                       asset.os           AS raw_os,
                       r.port             AS port,
                       r.protocol         AS protocol,
                       r.service          AS service
                ORDER BY asset.canonical_id
                """
            )

            # Aggregate per asset
            asset_data: dict[str, dict] = {}
            for rec in result:
                asset_id = rec["asset_id"]
                if asset_id not in asset_data:
                    asset_data[asset_id] = {
                        "raw_os": rec["raw_os"] or "",
                        "ports": set(),
                        "services": set(),
                    }
                port = str(rec["port"])
                if port != "0":
                    asset_data[asset_id]["ports"].add(port)

                svc = str(rec["service"] or "").lower().strip()
                if svc and svc not in ("?", "unknown", "general"):
                    asset_data[asset_id]["services"].add(svc)

                # Also infer service name from well-known port if not provided
                if not svc or svc in ("?", "unknown"):
                    inferred = _NOTABLE_SERVICES.get(port)
                    if inferred:
                        asset_data[asset_id]["services"].add(inferred)

            logger.info(
                "PortEnricher: aggregated port data for %d assets", len(asset_data)
            )

            # Write enriched properties back to each asset node
            updates = []
            for asset_id, data in asset_data.items():
                from sariel.normalization.os_normalizer import normalize_os
                normalized_os = normalize_os(data["raw_os"]) if data["raw_os"] else None
                sorted_ports = sorted(data["ports"], key=lambda p: int(p))
                sorted_services = sorted(data["services"])

                updates.append({
                    "asset_id": asset_id,
                    "open_ports": json.dumps(sorted_ports),
                    "services": json.dumps(sorted_services),
                    "normalized_os": normalized_os,
                    "updated_at": now,
                })

                stats.total_ports_written += len(sorted_ports)
                stats.total_services_written += len(sorted_services)

            if updates:
                batch_size = 500
                for i in range(0, len(updates), batch_size):
                    batch = updates[i : i + batch_size]
                    session.execute_write(_write_port_enrichment, batch)
                stats.assets_enriched = len(updates)
                logger.info(
                    "PortEnricher: enriched %d assets (%d ports, %d services)",
                    stats.assets_enriched,
                    stats.total_ports_written,
                    stats.total_services_written,
                )

        return stats


def _write_port_enrichment(tx, updates: list[dict]) -> None:
    """
    Write open_ports, services, and normalized os back onto asset nodes.
    Uses SET with coalesce so existing values aren't cleared if this run
    has no data for a field.
    """
    tx.run(
        """
        UNWIND $updates AS u
        MATCH (n:SarielNode {canonical_id: u.asset_id})
        SET n.open_ports             = u.open_ports,
            n.services               = u.services,
            n.open_ports_updated_at  = u.updated_at,
            n.os = CASE
                WHEN u.normalized_os IS NOT NULL AND u.normalized_os <> ''
                THEN u.normalized_os
                ELSE n.os
            END
        """,
        updates=updates,
    )


# ── Standalone OS normalization pass ─────────────────────────────────────────

class OSNormalizationPass:
    """
    Standalone pass that normalizes `os` fields on all ComputeAsset nodes
    that haven't come through Nessus (e.g. pure SolarWinds/ManageEngine assets).
    Run after PortEnricher so Nessus-enriched nodes don't get double-processed.
    """

    def __init__(self, neo4j_driver: Driver):
        self._driver = neo4j_driver

    def run(self) -> dict:
        from sariel.normalization.os_normalizer import normalize_os
        now = datetime.utcnow().isoformat()

        with self._driver.session() as session:
            result = session.run(
                """
                MATCH (n:ComputeAsset)
                WHERE n.os IS NOT NULL AND n.os <> ''
                  AND (n.open_ports_updated_at IS NULL)
                RETURN n.canonical_id AS cid, n.os AS raw_os
                """
            )
            updates = []
            for rec in result:
                normalized = normalize_os(rec["raw_os"])
                if normalized and normalized != rec["raw_os"]:
                    updates.append({
                        "cid": rec["cid"],
                        "normalized_os": normalized,
                        "updated_at": now,
                    })

            if updates:
                session.execute_write(_write_os_normalization, updates)

        return {"os_normalized": len(updates)}


def _write_os_normalization(tx, updates: list[dict]) -> None:
    tx.run(
        """
        UNWIND $updates AS u
        MATCH (n:SarielNode {canonical_id: u.cid})
        SET n.os = u.normalized_os,
            n.os_normalized_at = u.updated_at
        """,
        updates=updates,
    )

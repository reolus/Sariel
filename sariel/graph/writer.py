"""
Graph writer — upserts canonical nodes and edges into Neo4j.
All writes are idempotent: MERGE on canonical_id.
"""
from __future__ import annotations
import logging
from datetime import datetime
from typing import Optional

from neo4j import GraphDatabase, Driver

from sariel.models.entities import CanonicalEdge, CanonicalNode, NormalizedSnapshot

logger = logging.getLogger(__name__)


class GraphWriter:
    def __init__(self, uri: str, user: str, password: str):
        self._driver: Optional[Driver] = None
        self._uri = uri
        self._user = user
        self._password = password

    def connect(self) -> None:
        self._driver = GraphDatabase.driver(
            self._uri, auth=(self._user, self._password)
        )
        self._driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", self._uri)

    def close(self) -> None:
        if self._driver:
            self._driver.close()

    def setup_indexes(self) -> None:
        """Create indexes and constraints. Idempotent — safe to run on every startup."""
        constraints = [
            "CREATE CONSTRAINT sariel_node_id IF NOT EXISTS FOR (n:SarielNode) REQUIRE n.canonical_id IS UNIQUE",
        ]
        indexes = [
            "CREATE INDEX sariel_ec2_pub IF NOT EXISTS FOR (n:EC2Instance) ON (n.has_public_ip)",
            "CREATE INDEX sariel_avm_pub IF NOT EXISTS FOR (n:AzureVM) ON (n.has_public_ip)",
            "CREATE INDEX sariel_vuln_cvss IF NOT EXISTS FOR (n:Vulnerability) ON (n.cvss_score, n.has_exploit)",
            "CREATE INDEX sariel_iam_role_perm IF NOT EXISTS FOR (n:IAMRole) ON (n.is_overpermissioned)",
            "CREATE INDEX sariel_entra_user IF NOT EXISTS FOR (n:EntraUser) ON (n.mfa_enforced, n.is_guest)",
            "CREATE INDEX sariel_entra_sp IF NOT EXISTS FOR (n:EntraServicePrincipal) ON (n.is_managed_identity)",
            "CREATE INDEX sariel_role_def IF NOT EXISTS FOR (n:AzureRoleDefinition) ON (n.is_privileged)",
            "CREATE INDEX sariel_ds_sens IF NOT EXISTS FOR (n:DataStoreBase) ON (n.sensitivity)",
            "CREATE INDEX sariel_node_cloud IF NOT EXISTS FOR (n:SarielNode) ON (n.cloud)",
        ]
        with self._driver.session() as session:
            for stmt in constraints + indexes:
                try:
                    session.run(stmt)
                except Exception as e:
                    logger.debug("Index/constraint already exists or failed: %s", e)
        logger.info("Neo4j indexes/constraints ensured")

    def write_snapshot(self, snapshot: NormalizedSnapshot) -> dict:
        """
        Write all nodes and edges from a snapshot.
        Returns stats dict.
        """
        nodes_written = 0
        edges_written = 0
        errors = []

        with self._driver.session() as session:
            # Batch nodes in groups of 500
            for i in range(0, len(snapshot.nodes), 500):
                batch = snapshot.nodes[i:i+500]
                try:
                    result = session.execute_write(_write_nodes_batch, batch)
                    nodes_written += result
                except Exception as e:
                    errors.append(f"Node batch write failed: {e}")
                    logger.error("Node batch write error: %s", e)

            # Batch edges in groups of 500
            for i in range(0, len(snapshot.edges), 500):
                batch = snapshot.edges[i:i+500]
                try:
                    result = session.execute_write(_write_edges_batch, batch)
                    edges_written += result
                except Exception as e:
                    errors.append(f"Edge batch write failed: {e}")
                    logger.error("Edge batch write error: %s", e)

        stats = {
            "nodes_written": nodes_written,
            "edges_written": edges_written,
            "errors": errors,
            "snapshot_time": snapshot.scanned_at.isoformat(),
        }
        logger.info("Snapshot written: %s", stats)
        return stats

    def get_node_count(self) -> int:
        with self._driver.session() as session:
            result = session.run("MATCH (n:SarielNode) RETURN count(n) AS cnt")
            return result.single()["cnt"]

    def get_edge_count(self) -> int:
        with self._driver.session() as session:
            result = session.run("MATCH ()-[r]->() RETURN count(r) AS cnt")
            return result.single()["cnt"]


def _write_nodes_batch(tx, nodes: list[CanonicalNode]) -> int:
    """
    Upsert a batch of nodes. Each node gets:
    - SarielNode base label (for universal index)
    - Its specific type label(s)
    - All properties merged
    """
    node_data = []
    for node in nodes:
        labels = ":".join(["SarielNode"] + node.all_labels)
        node_data.append({
            "canonical_id": node.canonical_id,
            "labels_str": labels,
            "label": node.label,
            "cloud": node.cloud.value,
            "account_id": node.account_id,
            "node_type": node.node_type.value,
            "scanned_at": node.scanned_at.isoformat(),
            **{k: _serialize(v) for k, v in node.properties.items()},
        })

    # We can't set dynamic labels in a single parameterized Cypher statement,
    # so we group nodes by label set and run per group.
    by_labels: dict[str, list[dict]] = {}
    for i, node in enumerate(nodes):
        label_key = ":".join(["SarielNode"] + node.all_labels)
        by_labels.setdefault(label_key, []).append(node_data[i])

    total = 0
    for labels_str, group in by_labels.items():
        cypher = f"""
        UNWIND $nodes AS props
        MERGE (n:{labels_str} {{canonical_id: props.canonical_id}})
        SET n += props
        """
        result = tx.run(cypher, nodes=group)
        total += result.consume().counters.nodes_created + len(group)

    return total


def _write_edges_batch(tx, edges: list[CanonicalEdge]) -> int:
    """
    Upsert a batch of edges.
    Edge type is baked into the Cypher since Neo4j doesn't support dynamic relationship types.
    Group by edge type and run per group.
    """
    by_type: dict[str, list[dict]] = {}
    for edge in edges:
        by_type.setdefault(edge.edge_type.value, []).append({
            "from_id": edge.from_id,
            "to_id": edge.to_id,
            "scanned_at": edge.scanned_at.isoformat(),
            **{k: _serialize(v) for k, v in edge.properties.items()},
        })

    total = 0
    for edge_type, group in by_type.items():
        cypher = f"""
        UNWIND $edges AS props
        MATCH (a:SarielNode {{canonical_id: props.from_id}})
        MATCH (b:SarielNode {{canonical_id: props.to_id}})
        MERGE (a)-[r:{edge_type}]->(b)
        SET r += props
        """
        tx.run(cypher, edges=group)
        total += len(group)

    return total


def _serialize(value) -> any:
    """Convert non-primitive types for Neo4j storage."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, dict)):
        import json
        return json.dumps(value)
    return value

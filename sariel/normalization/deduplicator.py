"""
Entity deduplicator — ensures canonical_id uniqueness across snapshots.
Uses canonical_id as the stable key for Neo4j MERGE operations.
For AWS: ARN-based. For Azure: lowercase resource ID path.
"""
from __future__ import annotations
import logging
from sariel.models.entities import CanonicalNode, CanonicalEdge, NormalizedSnapshot

logger = logging.getLogger(__name__)


def deduplicate_snapshot(snapshot: NormalizedSnapshot) -> NormalizedSnapshot:
    """
    Remove duplicate nodes and edges from a snapshot.
    Last-write-wins for properties if same canonical_id appears twice.
    """
    node_map: dict[str, CanonicalNode] = {}
    for node in snapshot.nodes:
        if not node.canonical_id:
            logger.warning("Node with empty canonical_id skipped: %s", node.label)
            continue
        node_map[node.canonical_id] = node  # last wins

    edge_set: set[tuple] = set()
    unique_edges: list[CanonicalEdge] = []
    for edge in snapshot.edges:
        key = (edge.from_id, edge.to_id, edge.edge_type.value)
        if key not in edge_set:
            edge_set.add(key)
            unique_edges.append(edge)

    original_nodes = len(snapshot.nodes)
    original_edges = len(snapshot.edges)
    deduped_nodes = list(node_map.values())
    deduped_edges = unique_edges

    if original_nodes != len(deduped_nodes) or original_edges != len(deduped_edges):
        logger.info(
            "Deduplication: nodes %d→%d, edges %d→%d",
            original_nodes, len(deduped_nodes),
            original_edges, len(deduped_edges),
        )

    return NormalizedSnapshot(
        cloud=snapshot.cloud,
        account_id=snapshot.account_id,
        nodes=deduped_nodes,
        edges=deduped_edges,
        raw_source=snapshot.raw_source,
        scanned_at=snapshot.scanned_at,
        errors=snapshot.errors,
    )

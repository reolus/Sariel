from __future__ import annotations

from typing import Any
from neo4j import Driver

from sariel.ai.schemas import GraphContext, GraphPathNode, GraphPathRelationship


def _node_to_model(node: Any) -> GraphPathNode:
    props = dict(node)
    return GraphPathNode(
        id=str(node.element_id),
        labels=list(node.labels),
        hostname=props.get("hostname"),
        label=props.get("label"),
        canonical_id=props.get("canonical_id"),
        properties=props,
    )


def _rel_to_model(rel: Any) -> GraphPathRelationship:
    return GraphPathRelationship(
        id=str(rel.element_id),
        type=rel.type,
        start_node_id=str(rel.start_node.element_id),
        end_node_id=str(rel.end_node.element_id),
        properties=dict(rel),
    )


def build_asset_context(
    driver: Driver,
    source_hostname: str,
    target_hostname: str | None = None,
    max_hops: int = 4,
    limit: int = 25,
) -> GraphContext:
    """Extract a bounded graph context around a source asset.

    This intentionally returns facts only. AI interpretation happens later.
    """

    if target_hostname:
        query = f"""
        MATCH p=(s:SarielNode {{hostname: $source_hostname}})-[*1..{max_hops}]-(t:SarielNode {{hostname: $target_hostname}})
        RETURN p
        LIMIT $limit
        """
        params = {
            "source_hostname": source_hostname,
            "target_hostname": target_hostname,
            "limit": limit,
        }
    else:
        query = f"""
        MATCH p=(s:SarielNode {{hostname: $source_hostname}})-[*1..{max_hops}]-(t:SarielNode)
        WHERE coalesce(t.hostname, '') <> $source_hostname
        RETURN p
        LIMIT $limit
        """
        params = {"source_hostname": source_hostname, "limit": limit}

    nodes_by_id: dict[str, GraphPathNode] = {}
    rels_by_id: dict[str, GraphPathRelationship] = {}
    paths: list[dict[str, Any]] = []

    with driver.session() as session:
        for record in session.run(query, **params):
            path = record["p"]
            path_node_ids = []
            path_rel_ids = []

            for node in path.nodes:
                model = _node_to_model(node)
                nodes_by_id[model.id] = model
                path_node_ids.append(model.id)

            for rel in path.relationships:
                model = _rel_to_model(rel)
                rels_by_id[model.id] = model
                path_rel_ids.append(model.id)

            paths.append(
                {
                    "node_ids": path_node_ids,
                    "relationship_ids": path_rel_ids,
                    "node_names": [
                        dict(n).get("hostname")
                        or dict(n).get("label")
                        or dict(n).get("canonical_id")
                        or str(n.element_id)
                        for n in path.nodes
                    ],
                    "relationship_types": [r.type for r in path.relationships],
                }
            )

    return GraphContext(
        source_hostname=source_hostname,
        target_hostname=target_hostname,
        max_hops=max_hops,
        nodes=list(nodes_by_id.values()),
        relationships=list(rels_by_id.values()),
        paths=paths,
    )

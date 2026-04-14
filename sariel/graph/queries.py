"""
Graph query helpers — shared Cypher for attack path engine and API.
"""
from __future__ import annotations
from neo4j import Driver


class GraphQueries:
    def __init__(self, driver: Driver):
        self._driver = driver

    def get_asset(self, canonical_id: str) -> dict | None:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n:SarielNode {canonical_id: $id}) RETURN properties(n) AS props, labels(n) AS labels",
                id=canonical_id,
            )
            rec = result.single()
            if not rec:
                return None
            return {**rec["props"], "_labels": rec["labels"]}

    def list_assets(
        self,
        node_type: str | None = None,
        cloud: str | None = None,
        has_public_ip: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        filters = []
        params: dict = {"limit": limit, "offset": offset}
        if node_type:
            filters.append(f"n:{node_type}")
        if cloud:
            filters.append("n.cloud = $cloud")
            params["cloud"] = cloud
        if has_public_ip is not None:
            filters.append("n.has_public_ip = $has_public_ip")
            params["has_public_ip"] = has_public_ip

        where = ("WHERE " + " AND ".join(filters)) if filters else ""
        label = node_type or "SarielNode"
        cypher = f"""
        MATCH (n:{label})
        {where}
        RETURN properties(n) AS props, labels(n) AS labels
        ORDER BY n.canonical_id
        SKIP $offset LIMIT $limit
        """
        with self._driver.session() as session:
            results = session.run(cypher, **params)
            return [{**r["props"], "_labels": r["labels"]} for r in results]

    def get_path_nodes_and_edges(self, canonical_ids: list[str]) -> dict:
        """Fetch full node and edge data for a path given an ordered list of canonical IDs."""
        with self._driver.session() as session:
            # Nodes
            node_result = session.run(
                "MATCH (n:SarielNode) WHERE n.canonical_id IN $ids RETURN properties(n) AS props, labels(n) AS labels",
                ids=canonical_ids,
            )
            nodes = [{**r["props"], "_labels": r["labels"]} for r in node_result]

            # Edges between path nodes
            edge_result = session.run(
                """
                MATCH (a:SarielNode)-[r]->(b:SarielNode)
                WHERE a.canonical_id IN $ids AND b.canonical_id IN $ids
                RETURN a.canonical_id AS from_id, b.canonical_id AS to_id,
                       type(r) AS rel_type, properties(r) AS props
                """,
                ids=canonical_ids,
            )
            edges = [
                {
                    "from_id": r["from_id"],
                    "to_id": r["to_id"],
                    "rel": r["rel_type"],
                    **r["props"],
                }
                for r in edge_result
            ]
            return {"nodes": nodes, "edges": edges}

    def search_assets(self, query: str, limit: int = 20) -> list[dict]:
        with self._driver.session() as session:
            results = session.run(
                """
                MATCH (n:SarielNode)
                WHERE toLower(n.label) CONTAINS toLower($q)
                   OR toLower(n.canonical_id) CONTAINS toLower($q)
                RETURN properties(n) AS props, labels(n) AS labels
                LIMIT $limit
                """,
                q=query, limit=limit,
            )
            return [{**r["props"], "_labels": r["labels"]} for r in results]

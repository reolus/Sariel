"""
Identity resolver — correlates IAM users with Entra users via email/UPN.
Creates SAME_IDENTITY edges when a match is found.
Confidence levels: email_match | manual | inferred
"""
from __future__ import annotations
import logging
from neo4j import Driver

from sariel.models.entities import CanonicalEdge, EdgeType

logger = logging.getLogger(__name__)


class IdentityResolver:
    def __init__(self, driver: Driver):
        self._driver = driver

    def correlate_cross_cloud_identities(self) -> list[CanonicalEdge]:
        """
        Find IAM users and Entra users with matching email/UPN.
        Returns SAME_IDENTITY edges to be written to the graph.
        """
        edges: list[CanonicalEdge] = []

        with self._driver.session() as session:
            # Match on UPN = IAM username (common in AWS SSO setups)
            result = session.run("""
                MATCH (iam:IAMUser), (entra:EntraUser)
                WHERE toLower(iam.username) = toLower(entra.upn)
                   OR toLower(iam.username) = toLower(split(entra.upn, '@')[0])
                RETURN iam.canonical_id AS iam_id,
                       entra.canonical_id AS entra_id,
                       'email_match' AS confidence
            """)

            for record in result:
                edges.append(CanonicalEdge(
                    from_id=record["iam_id"],
                    to_id=record["entra_id"],
                    edge_type=EdgeType.SAME_IDENTITY,
                    properties={"confidence": record["confidence"]},
                ))

        logger.info("Identity correlation found %d cross-cloud identity links", len(edges))
        return edges

    def write_correlations(self) -> int:
        """Run correlation and write edges to Neo4j. Returns count written."""
        edges = self.correlate_cross_cloud_identities()
        if not edges:
            return 0

        with self._driver.session() as session:
            def _write(tx, edges_data):
                tx.run("""
                    UNWIND $edges AS e
                    MATCH (a:SarielNode {canonical_id: e.from_id})
                    MATCH (b:SarielNode {canonical_id: e.to_id})
                    MERGE (a)-[r:SAME_IDENTITY]->(b)
                    SET r.confidence = e.confidence
                """, edges=[
                    {"from_id": e.from_id, "to_id": e.to_id,
                     "confidence": e.properties.get("confidence", "inferred")}
                    for e in edges
                ])

            session.execute_write(_write, edges)

        return len(edges)

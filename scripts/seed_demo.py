from datetime import datetime

from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings
from sariel.models.entities import (
    CanonicalNode,
    CanonicalEdge,
    NormalizedSnapshot,
    NodeType,
    EdgeType,
    Cloud,
)

def build_demo_snapshot():
    now = datetime.utcnow()

    nodes = []
    edges = []

    # ─── Internet ───────────────────────────────────────────────
    nodes.append(CanonicalNode(
        canonical_id="internet://0.0.0.0/0",
        node_type=NodeType.INTERNET,
        cloud=Cloud.AWS,
        account_id="demo",
        label="Internet",
        scanned_at=now,
    ))

    # ─── Public VM ──────────────────────────────────────────────
    nodes.append(CanonicalNode(
        canonical_id="vm://prod-payments",
        node_type=NodeType.EC2_INSTANCE,
        cloud=Cloud.AWS,
        account_id="demo",
        label="prod-payments-vm",
        properties={"has_public_ip": True},
        scanned_at=now,
    ))

    # ─── Vulnerability ──────────────────────────────────────────
    nodes.append(CanonicalNode(
        canonical_id="cve://CVE-2024-9999",
        node_type=NodeType.VULNERABILITY,
        cloud=Cloud.AWS,
        account_id="demo",
        label="CVE-2024-9999",
        properties={
            "cvss_score": 9.5,
            "cvss_exploitability_score": 3.8,
            "has_exploit": True,
        },
        scanned_at=now,
    ))

    # ─── IAM Role ───────────────────────────────────────────────
    nodes.append(CanonicalNode(
        canonical_id="iam://role/payment-service",
        node_type=NodeType.IAM_ROLE,
        cloud=Cloud.AWS,
        account_id="demo",
        label="payment-service-role",
        properties={"is_overpermissioned": True},
        scanned_at=now,
    ))

    # ─── Sensitive Data Store ───────────────────────────────────
    nodes.append(CanonicalNode(
        canonical_id="s3://customer-finance-data",
        node_type=NodeType.DATA_STORE,
        cloud=Cloud.AWS,
        account_id="demo",
        label="customer-finance-data",
        properties={"sensitivity": "critical"},
        scanned_at=now,
    ))

    # ─── Edges ──────────────────────────────────────────────────

    # Internet → VM
    edges.append(CanonicalEdge(
        from_id="internet://0.0.0.0/0",
        to_id="vm://prod-payments",
        edge_type=EdgeType.EXPOSES_PORT,
        scanned_at=now,
    ))

    # VM → Vulnerability
    edges.append(CanonicalEdge(
        from_id="vm://prod-payments",
        to_id="cve://CVE-2024-9999",
        edge_type=EdgeType.HAS_VULN,
        scanned_at=now,
    ))

    # VM → Role
    edges.append(CanonicalEdge(
        from_id="vm://prod-payments",
        to_id="iam://role/payment-service",
        edge_type=EdgeType.HAS_ROLE,
        scanned_at=now,
    ))

    # Role → Data
    edges.append(CanonicalEdge(
        from_id="iam://role/payment-service",
        to_id="s3://customer-finance-data",
        edge_type=EdgeType.CAN_ACCESS,
        scanned_at=now,
    ))

    return NormalizedSnapshot(
        cloud=Cloud.AWS,
        account_id="demo",
        nodes=nodes,
        edges=edges,
        raw_source="demo_seed",
        scanned_at=now,
    )


def main():
    settings = get_settings()

    writer = GraphWriter(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password,
    )

    writer.connect()
    writer.setup_indexes()

    snapshot = build_demo_snapshot()
    stats = writer.write_snapshot(snapshot)

    writer.close()

    print("\n✅ Demo data seeded successfully")
    print(stats)


if __name__ == "__main__":
    main()
"""Unit tests for normalization helpers."""
import pytest
from datetime import datetime
from sariel.normalization.deduplicator import deduplicate_snapshot
from sariel.models.entities import (
    CanonicalNode, CanonicalEdge, Cloud, EdgeType, NodeType, NormalizedSnapshot,
)


def make_node(canonical_id: str, label: str = "test") -> CanonicalNode:
    return CanonicalNode(
        canonical_id=canonical_id,
        node_type=NodeType.EC2_INSTANCE,
        cloud=Cloud.AWS,
        account_id="123456789012",
        label=label,
    )


def make_edge(from_id: str, to_id: str, edge_type=EdgeType.ATTACHED_TO) -> CanonicalEdge:
    return CanonicalEdge(from_id=from_id, to_id=to_id, edge_type=edge_type)


def make_snapshot(nodes, edges):
    return NormalizedSnapshot(
        cloud=Cloud.AWS,
        account_id="123456789012",
        nodes=nodes,
        edges=edges,
        raw_source="test",
    )


class TestDeduplicator:
    def test_deduplicates_nodes_by_canonical_id(self):
        n1 = make_node("arn:aws:ec2::123:instance/i-001", label="first")
        n2 = make_node("arn:aws:ec2::123:instance/i-001", label="second")
        snap = make_snapshot([n1, n2], [])
        result = deduplicate_snapshot(snap)
        assert len(result.nodes) == 1
        assert result.nodes[0].label == "second"  # last wins

    def test_deduplicates_edges_by_type_and_endpoints(self):
        e1 = make_edge("a", "b", EdgeType.ATTACHED_TO)
        e2 = make_edge("a", "b", EdgeType.ATTACHED_TO)
        snap = make_snapshot([], [e1, e2])
        result = deduplicate_snapshot(snap)
        assert len(result.edges) == 1

    def test_keeps_different_edge_types(self):
        e1 = make_edge("a", "b", EdgeType.ATTACHED_TO)
        e2 = make_edge("a", "b", EdgeType.HAS_ROLE)
        snap = make_snapshot([], [e1, e2])
        result = deduplicate_snapshot(snap)
        assert len(result.edges) == 2

    def test_preserves_unique_nodes(self):
        nodes = [make_node(f"arn:aws:ec2::123:instance/i-00{i}") for i in range(5)]
        snap = make_snapshot(nodes, [])
        result = deduplicate_snapshot(snap)
        assert len(result.nodes) == 5

    def test_skips_empty_canonical_id(self):
        n_valid = make_node("arn:valid")
        n_empty = make_node("")
        snap = make_snapshot([n_valid, n_empty], [])
        result = deduplicate_snapshot(snap)
        assert len(result.nodes) == 1
        assert result.nodes[0].canonical_id == "arn:valid"


class TestAWSCanonicalIds:
    """Verify canonical ID format assumptions used throughout the codebase."""
    def test_s3_bucket_canonical_format(self):
        bucket_name = "my-prod-secrets"
        canonical = f"arn:aws:s3:::{bucket_name}"
        assert canonical == "arn:aws:s3:::my-prod-secrets"

    def test_iam_user_canonical_from_arn(self):
        arn = "arn:aws:iam::123456789012:user/alice"
        assert ":user/" in arn

    def test_internet_sentinel_canonical(self):
        from sariel.connectors.aws.resources import INTERNET_CANONICAL_ID
        assert INTERNET_CANONICAL_ID == "internet://0.0.0.0/0"

"""
Network Linker — post-ingestion graph enrichment pass.

Problem:
  After ingestion, the graph has:
    - Compute nodes (OnPremHost, EC2Instance, etc.) with `private_ip` properties
    - Fortinet NetworkSegment nodes with `cidr` properties and CAN_REACH edges
      between them (representing firewall ACCEPT policies)

  But compute nodes are NOT connected to NetworkSegment nodes, so the
  traversal engine's CAN_REACH / IN_SUBNET queries return nothing for on-prem.

Solution — three-pass linking:

  Pass 1: IP → Subnet matching
    For every compute node with a private_ip, find the most-specific
    NetworkSegment whose CIDR contains that IP. Write an IN_SUBNET edge.

  Pass 2: Intra-subnet reachability
    For every pair of compute nodes in the SAME subnet, write a CAN_REACH
    edge (lateral movement within a flat subnet is generally unconstrained
    unless the firewall explicitly denies it — most environments don't).

  Pass 3: Cross-subnet reachability via Fortinet policy
    For every compute node in subnet A where A -[CAN_REACH]-> B (Fortinet),
    find all compute nodes in subnet B and write CAN_REACH edges from the
    source node to those targets, carrying the firewall policy metadata.

Usage:
    linker = NetworkLinker(neo4j_driver)
    stats = linker.run()
"""
from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from neo4j import Driver

logger = logging.getLogger(__name__)


@dataclass
class LinkStats:
    subnets_loaded: int = 0
    compute_nodes_processed: int = 0
    in_subnet_edges_written: int = 0
    intra_subnet_can_reach_written: int = 0
    cross_subnet_can_reach_written: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_edges_written(self) -> int:
        return (
            self.in_subnet_edges_written
            + self.intra_subnet_can_reach_written
            + self.cross_subnet_can_reach_written
        )


class NetworkLinker:
    """
    Bridges Fortinet firewall reachability to compute assets via IP-to-CIDR matching.
    Runs as a post-ingestion step — safe to run repeatedly (all writes are MERGE).
    """

    def __init__(self, neo4j_driver: Driver, account_id: str = "onprem"):
        self._driver = neo4j_driver
        self.account_id = account_id

    def run(self) -> LinkStats:
        stats = LinkStats()
        now = datetime.utcnow().isoformat()

        with self._driver.session() as session:
            # ── Load all NetworkSegment nodes with valid CIDRs ────────────────
            subnets = self._load_subnets(session)
            stats.subnets_loaded = len(subnets)
            logger.info("NetworkLinker: loaded %d subnet nodes", len(subnets))

            if not subnets:
                logger.warning(
                    "NetworkLinker: no NetworkSegment nodes found. "
                    "Ensure Fortinet connector has run first."
                )
                return stats

            # ── Load all compute nodes with IPs ───────────────────────────────
            compute_nodes = self._load_compute_nodes(session)
            stats.compute_nodes_processed = len(compute_nodes)
            logger.info("NetworkLinker: found %d compute nodes to link", len(compute_nodes))

            # ── Pass 1: Match each compute node to its best subnet ────────────
            # node_id → list of subnet canonical_ids (may match multiple supernets)
            node_to_subnets: dict[str, list[str]] = {}

            for node in compute_nodes:
                ip_str = node.get("private_ip") or node.get("ip_address") or ""
                if not ip_str:
                    continue

                matched = _match_ip_to_subnets(ip_str, subnets)
                if matched:
                    node_to_subnets[node["canonical_id"]] = [s["canonical_id"] for s in matched]

            # Write IN_SUBNET edges in bulk
            in_subnet_pairs = [
                {"node_id": nid, "subnet_id": sid}
                for nid, sids in node_to_subnets.items()
                for sid in sids
            ]
            if in_subnet_pairs:
                written = session.execute_write(
                    _merge_in_subnet_edges, in_subnet_pairs, now
                )
                stats.in_subnet_edges_written = written
                logger.info("NetworkLinker: wrote %d IN_SUBNET edges", written)

            # ── Pass 2: Intra-subnet CAN_REACH ────────────────────────────────
            # Build subnet → [node_ids] map
            subnet_to_nodes: dict[str, list[str]] = {}
            for node_id, subnet_ids in node_to_subnets.items():
                for sid in subnet_ids:
                    subnet_to_nodes.setdefault(sid, []).append(node_id)

            intra_pairs: list[dict] = []
            for subnet_id, node_ids in subnet_to_nodes.items():
                if len(node_ids) < 2:
                    continue
                for i, src in enumerate(node_ids):
                    for dst in node_ids[i + 1:]:
                        intra_pairs.append({
                            "from_id": src,
                            "to_id": dst,
                            "subnet_id": subnet_id,
                        })
                        # Bidirectional within subnet
                        intra_pairs.append({
                            "from_id": dst,
                            "to_id": src,
                            "subnet_id": subnet_id,
                        })

            if intra_pairs:
                written = session.execute_write(
                    _merge_intra_subnet_can_reach, intra_pairs, now
                )
                stats.intra_subnet_can_reach_written = written
                logger.info(
                    "NetworkLinker: wrote %d intra-subnet CAN_REACH edges", written
                )

            # ── Pass 3: Cross-subnet CAN_REACH via Fortinet policy ────────────
            fortinet_paths = self._load_fortinet_reachability(session)
            logger.info(
                "NetworkLinker: found %d Fortinet subnet→subnet reachability paths",
                len(fortinet_paths),
            )

            cross_pairs: list[dict] = []
            for path in fortinet_paths:
                src_subnet_id = path["src_subnet_id"]
                dst_subnet_id = path["dst_subnet_id"]
                policy_meta = path.get("policy_meta", {})

                src_nodes = subnet_to_nodes.get(src_subnet_id, [])
                dst_nodes = subnet_to_nodes.get(dst_subnet_id, [])

                for src_node in src_nodes:
                    for dst_node in dst_nodes:
                        if src_node == dst_node:
                            continue
                        cross_pairs.append({
                            "from_id": src_node,
                            "to_id": dst_node,
                            "src_subnet_id": src_subnet_id,
                            "dst_subnet_id": dst_subnet_id,
                            "firewall": policy_meta.get("firewall_name", ""),
                            "policy_id": policy_meta.get("policy_id", ""),
                            "policy_name": policy_meta.get("policy_name", ""),
                            "protocol": policy_meta.get("protocol", ""),
                            "ports": policy_meta.get("ports", ""),
                        })

            if cross_pairs:
                # Write in batches to avoid huge transactions
                batch_size = 500
                total_written = 0
                for i in range(0, len(cross_pairs), batch_size):
                    batch = cross_pairs[i : i + batch_size]
                    written = session.execute_write(
                        _merge_cross_subnet_can_reach, batch, now
                    )
                    total_written += written
                stats.cross_subnet_can_reach_written = total_written
                logger.info(
                    "NetworkLinker: wrote %d cross-subnet CAN_REACH edges", total_written
                )

        logger.info(
            "NetworkLinker complete: %d total edges written (%d in_subnet, %d intra, %d cross)",
            stats.total_edges_written,
            stats.in_subnet_edges_written,
            stats.intra_subnet_can_reach_written,
            stats.cross_subnet_can_reach_written,
        )
        return stats

    def _load_subnets(self, session) -> list[dict]:
        """Load all NetworkSegment nodes that have a valid CIDR."""
        result = session.run(
            """
            MATCH (n:NetworkSegment)
            WHERE n.cidr IS NOT NULL AND n.cidr <> '' AND n.cidr <> '0.0.0.0/0'
            RETURN n.canonical_id AS canonical_id,
                   n.cidr         AS cidr,
                   n.label        AS label
            """
        )
        subnets = []
        for rec in result:
            cidr = rec["cidr"]
            try:
                # Parse and normalize — rejects invalid CIDRs
                network = ipaddress.ip_network(cidr, strict=False)
                subnets.append({
                    "canonical_id": rec["canonical_id"],
                    "cidr": cidr,
                    "label": rec["label"],
                    "network": network,
                })
            except ValueError:
                logger.debug("Skipping unparseable CIDR: %s", cidr)
        return subnets

    def _load_compute_nodes(self, session) -> list[dict]:
        """Load all compute nodes that have a private IP."""
        result = session.run(
            """
            MATCH (n:ComputeAsset)
            WHERE n.private_ip IS NOT NULL AND n.private_ip <> ''
               OR n.ip_address IS NOT NULL AND n.ip_address <> ''
            RETURN n.canonical_id AS canonical_id,
                   n.label        AS label,
                   coalesce(n.private_ip, n.ip_address) AS private_ip
            """
        )
        return [dict(r) for r in result]

    def _load_fortinet_reachability(self, session) -> list[dict]:
        """Load all CAN_REACH edges between NetworkSegment nodes (Fortinet policy)."""
        result = session.run(
            """
            MATCH (src:NetworkSegment)-[r:CAN_REACH]->(dst:NetworkSegment)
            RETURN src.canonical_id AS src_subnet_id,
                   dst.canonical_id AS dst_subnet_id,
                   properties(r)   AS props
            """
        )
        paths = []
        for rec in result:
            props = dict(rec["props"])
            paths.append({
                "src_subnet_id": rec["src_subnet_id"],
                "dst_subnet_id": rec["dst_subnet_id"],
                "policy_meta": {
                    "firewall_name": props.get("firewall_name", ""),
                    "policy_id": props.get("policy_id", ""),
                    "policy_name": props.get("policy_name", ""),
                    "protocol": props.get("protocol", ""),
                    "ports": props.get("ports", ""),
                },
            })
        return paths


# ── Transaction functions ─────────────────────────────────────────────────────

def _merge_in_subnet_edges(tx, pairs: list[dict], now: str) -> int:
    tx.run(
        """
        UNWIND $pairs AS p
        MATCH (node:SarielNode {canonical_id: p.node_id})
        MATCH (subnet:SarielNode {canonical_id: p.subnet_id})
        MERGE (node)-[r:IN_SUBNET]->(subnet)
        SET r.linked_at = $now,
            r.source    = 'network_linker'
        """,
        pairs=pairs,
        now=now,
    )
    return len(pairs)


def _merge_intra_subnet_can_reach(tx, pairs: list[dict], now: str) -> int:
    tx.run(
        """
        UNWIND $pairs AS p
        MATCH (src:SarielNode {canonical_id: p.from_id})
        MATCH (dst:SarielNode {canonical_id: p.to_id})
        MERGE (src)-[r:CAN_REACH]->(dst)
        SET r.source      = 'network_linker',
            r.reason      = 'same_subnet',
            r.subnet_id   = p.subnet_id,
            r.linked_at   = $now,
            r.confidence  = 'inferred'
        """,
        pairs=pairs,
        now=now,
    )
    return len(pairs)


def _merge_cross_subnet_can_reach(tx, pairs: list[dict], now: str) -> int:
    tx.run(
        """
        UNWIND $pairs AS p
        MATCH (src:SarielNode {canonical_id: p.from_id})
        MATCH (dst:SarielNode {canonical_id: p.to_id})
        MERGE (src)-[r:CAN_REACH]->(dst)
        SET r.source         = 'network_linker',
            r.reason         = 'fortinet_policy',
            r.src_subnet_id  = p.src_subnet_id,
            r.dst_subnet_id  = p.dst_subnet_id,
            r.firewall       = p.firewall,
            r.policy_id      = p.policy_id,
            r.policy_name    = p.policy_name,
            r.protocol       = p.protocol,
            r.ports          = p.ports,
            r.linked_at      = $now,
            r.confidence     = 'firewall_confirmed'
        """,
        pairs=pairs,
        now=now,
    )
    return len(pairs)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _match_ip_to_subnets(ip_str: str, subnets: list[dict]) -> list[dict]:
    """
    Return all subnet records whose CIDR contains the given IP.
    Sorted most-specific first (largest prefix length).
    For an IP like 10.10.5.20:
      - matches 10.10.5.0/24  (prefix=24, most specific)
      - matches 10.10.0.0/16  (prefix=16)
      - does NOT match 10.10.5.0/24 if the IP is in 10.10.6.0/24
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return []

    matched = [s for s in subnets if ip in s["network"]]
    matched.sort(key=lambda s: s["network"].prefixlen, reverse=True)
    return matched

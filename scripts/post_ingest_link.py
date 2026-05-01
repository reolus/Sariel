"""
Post-ingestion enrichment script.

Run this after all connector ingestion jobs have completed:

    python scripts/post_ingest_link.py

What it does (in order):

  1. OSNormalizationPass
     Normalizes raw OS strings ("Microsoft Windows Server 2019 Standard")
     to canonical forms ("windows server 2019") on all ComputeAsset nodes
     that haven't been touched by the port enricher yet.

  2. PortEnricher
     Aggregates open port and service data from Nessus HAS_VULN edges back
     onto asset nodes as `open_ports` and `services` lists. Also normalizes
     OS where Nessus provides it.

  3. NetworkLinker
     Bridges Fortinet subnet-level CAN_REACH edges to actual compute assets:
       - Matches compute node IPs to NetworkSegment CIDRs → IN_SUBNET edges
       - Writes CAN_REACH edges for nodes in the same subnet (intra-subnet)
       - Writes CAN_REACH edges across subnets where Fortinet policy permits
         (cross-subnet via firewall rules)

After this script completes, the traversal engine will correctly evaluate
lateral movement techniques (SSH, SMB, RDP, CVE exploitation) for on-prem
nodes — not just cloud assets.

Scheduling:
  Run after each full ingestion cycle. The scheduler in sariel/scheduler/jobs.py
  should call run_post_ingest_enrichment() after all connector jobs complete.
"""
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from neo4j import GraphDatabase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def run_post_ingest_enrichment(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    account_id: str = "onprem",
) -> dict:
    """
    Run all post-ingestion enrichment passes.
    Returns a summary dict of what was done.
    """
    from sariel.normalization.os_normalizer import normalize_os
    from sariel.normalization.port_enricher import PortEnricher, OSNormalizationPass
    from sariel.normalization.network_linker import NetworkLinker

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    summary = {}

    try:
        driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", neo4j_uri)

        # Pass 1: Normalize OS strings on nodes not yet touched by Nessus
        logger.info("Pass 1: OS normalization...")
        os_pass = OSNormalizationPass(driver)
        os_stats = os_pass.run()
        summary["os_normalization"] = os_stats
        logger.info("OS normalization: %s", os_stats)

        # Pass 2: Enrich open_ports and services from Nessus data
        logger.info("Pass 2: Port enrichment from Nessus data...")
        enricher = PortEnricher(driver)
        port_stats = enricher.run()
        summary["port_enrichment"] = {
            "assets_enriched": port_stats.assets_enriched,
            "total_ports": port_stats.total_ports_written,
            "total_services": port_stats.total_services_written,
            "errors": port_stats.errors,
        }
        logger.info("Port enrichment: %s", summary["port_enrichment"])

        # Pass 3: Network linking — IP → subnet → CAN_REACH edges
        logger.info("Pass 3: Network linking (IP→subnet→CAN_REACH)...")
        linker = NetworkLinker(driver, account_id=account_id)
        link_stats = linker.run()
        summary["network_linking"] = {
            "subnets_loaded": link_stats.subnets_loaded,
            "compute_nodes_processed": link_stats.compute_nodes_processed,
            "in_subnet_edges": link_stats.in_subnet_edges_written,
            "intra_subnet_can_reach": link_stats.intra_subnet_can_reach_written,
            "cross_subnet_can_reach": link_stats.cross_subnet_can_reach_written,
            "total_edges_written": link_stats.total_edges_written,
            "errors": link_stats.errors,
        }
        logger.info("Network linking: %s", summary["network_linking"])

    finally:
        driver.close()

    logger.info("Post-ingestion enrichment complete: %s", summary)
    return summary


async def main():
    from sariel.models.config import get_settings
    s = get_settings()

    account_id = s.onprem_account_id or "onprem"

    summary = run_post_ingest_enrichment(
        neo4j_uri=s.neo4j_uri,
        neo4j_user=s.neo4j_user,
        neo4j_password=s.neo4j_password,
        account_id=account_id,
    )

    total_edges = summary.get("network_linking", {}).get("total_edges_written", 0)
    if total_edges == 0:
        logger.warning(
            "No network edges were written. Check that:\n"
            "  1. Fortinet connector has run (NetworkSegment nodes with CIDRs exist)\n"
            "  2. On-prem asset connectors have run (OnPremHost nodes with IPs exist)\n"
            "  3. Neo4j is reachable and populated"
        )


if __name__ == "__main__":
    asyncio.run(main())

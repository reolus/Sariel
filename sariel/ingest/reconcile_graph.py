"""CLI entrypoint to reconcile host identity in an existing Sariel Neo4j graph."""
from __future__ import annotations

import argparse
import logging
from neo4j import GraphDatabase

from sariel.models.config import get_settings
from sariel.normalization.graph_reconciler import GraphReconciler

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s - %(message)s")


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconcile duplicate Sariel host identities and repair vulnerability names.")
    parser.add_argument("--dry-run", action="store_true", help="Report what would be changed without writing to Neo4j.")
    args = parser.parse_args()

    settings = get_settings()
    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
    try:
        driver.verify_connectivity()
        stats = GraphReconciler(driver).run(dry_run=args.dry_run)
        print("Sariel graph reconciliation stats:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    finally:
        driver.close()


if __name__ == "__main__":
    main()

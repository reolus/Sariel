"""CLI for Sariel attack path prioritization."""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from neo4j import GraphDatabase

from sariel.analysis.path_prioritizer import PathPrioritizer


def _env(name: str, default: str | None = None) -> str | None:
    return os.getenv(name, default)


def build_driver() -> Any:
    uri = _env("NEO4J_URI", "bolt://localhost:7687")
    user = _env("NEO4J_USER", "neo4j")
    password = _env("NEO4J_PASSWORD") or _env("NEO4J_PASS")
    if not password:
        raise SystemExit("NEO4J_PASSWORD is not set. Set it before running prioritization.")
    return GraphDatabase.driver(uri, auth=(user, password))


def print_paths(paths: list[Any]) -> None:
    if not paths:
        print("No prioritized attack paths found.")
        return
    for i, p in enumerate(paths, start=1):
        print(
            f"{i:03d}. score={p.risk_score:.2f} severity={p.severity} hops={p.hops} "
            f"{p.source_name} -> {p.target_name} "
            f"({p.target_ip or 'no-ip'}) vuln={p.vulnerability_name} "
            f"service={p.service or 'n/a'} port={p.port or 'n/a'}"
        )
        print(f"     path: {p.path_summary}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prioritize Sariel attack paths.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--source", help="Prioritize attack paths starting from one source host/name/IP fragment.")
    group.add_argument("--all", action="store_true", help="Prioritize attack paths from all source hosts.")
    parser.add_argument("--top", type=int, default=25, help="Global result cap. Default: 25.")
    parser.add_argument("--per-source", type=int, default=10, help="Per-source cap when using --all. Default: 10.")
    parser.add_argument("--max-hops", type=int, default=4, help="Maximum subnet CAN_REACH hops. Default: 4.")
    parser.add_argument("--source-limit", type=int, default=None, help="Testing safety cap for --all source enumeration.")
    parser.add_argument("--write", action="store_true", help="Persist ranked paths as :AttackPath nodes.")
    parser.add_argument("--database", default=os.getenv("NEO4J_DATABASE"), help="Neo4j database name, if not default.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    driver = build_driver()
    try:
        prioritizer = PathPrioritizer(driver, database=args.database)
        if args.all:
            paths = prioritizer.prioritize_all(
                top=args.top,
                per_source=args.per_source,
                max_hops=args.max_hops,
                source_limit=args.source_limit,
            )
        else:
            paths = prioritizer.prioritize_for_source(args.source, top=args.top, max_hops=args.max_hops)

        print_paths(paths)

        if args.write:
            written = prioritizer.write_paths(paths)
            print(f"Written AttackPath nodes: {written}")
        return 0
    finally:
        driver.close()


if __name__ == "__main__":
    raise SystemExit(main())

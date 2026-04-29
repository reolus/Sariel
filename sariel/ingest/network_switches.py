"""Sariel network switch ingestion entry point."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import yaml

from sariel.connectors.network_switches import (
    SwitchTarget,
    collect_running_config,
    parse_switch_config,
)
from sariel.graph.network_switch_writer import NetworkSwitchGraphWriter


def load_inventory(path: str | Path) -> list[SwitchTarget]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    targets = []
    for item in data.get("switches", []):
        targets.append(SwitchTarget(**item))
    return targets


def ingest_switches(inventory_path: str, offline_config_dir: str | None = None) -> None:
    writer = NetworkSwitchGraphWriter(
        uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        username=os.getenv("NEO4J_USERNAME", "neo4j"),
        password=os.getenv("NEO4J_PASSWORD", "password"),
    )

    try:
        for target in load_inventory(inventory_path):
            if offline_config_dir:
                config_path = Path(offline_config_dir) / f"{target.name}.cfg"
                config = config_path.read_text()
            else:
                config = collect_running_config(target)

            facts = parse_switch_config(
                device_name=target.name,
                mgmt_ip=target.host,
                vendor=target.vendor,
                config=config,
            )
            writer.write_facts(facts)
            print(f"[OK] ingested {target.name}: {len(facts.interfaces)} interfaces, {len(facts.acl_rules)} ACL rules")
    finally:
        writer.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest Aruba/Cisco switch topology into Sariel")
    parser.add_argument("--inventory", required=True, help="Path to switches.yaml")
    parser.add_argument(
        "--offline-config-dir",
        help="Optional directory of saved configs named <switch-name>.cfg for lab testing",
    )
    args = parser.parse_args()
    ingest_switches(args.inventory, args.offline_config_dir)


if __name__ == "__main__":
    main()

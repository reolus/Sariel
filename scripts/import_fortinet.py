from __future__ import annotations

import os

from sariel.connectors.fortinet import FortinetReachabilityConnector
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings


FORTIGATES = [
    {
        "name": "fg-edge-01",
        "base_url": os.getenv("FORTINET_FG_EDGE_01_URL", ""),
        "api_token": os.getenv("FORTINET_FG_EDGE_01_TOKEN", ""),
        "vdom": os.getenv("FORTINET_FG_EDGE_01_VDOM", "root"),
    },
    {
        "name": "fg-seg-01",
        "base_url": os.getenv("FORTINET_FG_SEG_01_URL", ""),
        "api_token": os.getenv("FORTINET_FG_SEG_01_TOKEN", ""),
        "vdom": os.getenv("FORTINET_FG_SEG_01_VDOM", "root"),
    },
    {
        "name": "fg-dmz-01",
        "base_url": os.getenv("FORTINET_FG_DMZ_01_URL", ""),
        "api_token": os.getenv("FORTINET_FG_DMZ_01_TOKEN", ""),
        "vdom": os.getenv("FORTINET_FG_DMZ_01_VDOM", "root"),
    },
]


def write_snapshot(snapshot):
    settings = get_settings()

    writer = GraphWriter(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password,
    )

    writer.connect()
    writer.setup_indexes()
    stats = writer.write_snapshot(snapshot)
    writer.close()

    print(snapshot.raw_source, stats)

    if snapshot.errors:
        print("Errors:")
        for err in snapshot.errors[:100]:
            print(" -", err)


def main():
    verify_ssl = os.getenv("FORTINET_VERIFY_SSL", "false").lower() == "true"

    for fw in FORTIGATES:
        if not fw["base_url"] or not fw["api_token"]:
            print(f"Skipping {fw['name']}: missing URL or token")
            continue

        print(f"Importing Fortinet device: {fw['name']} ({fw['base_url']})")

        connector = FortinetReachabilityConnector(
            base_url=fw["base_url"],
            api_token=fw["api_token"],
            account_id="fortinet",
            device_name=fw["name"],
            vdom=fw.get("vdom", "root"),
            verify_ssl=verify_ssl,
        )

        snapshot = connector.orchestrate()
        write_snapshot(snapshot)


if __name__ == "__main__":
    main()
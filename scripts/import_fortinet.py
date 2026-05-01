from __future__ import annotations

import os

from sariel.connectors.fortinet import FortinetReachabilityConnector
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings


FORTIGATES = [
    {
        "name": "fg-ch-01",
        "base_url": os.getenv("FORTINET_FG_CH_01_URL", ""),
        "api_token": os.getenv("FORTINET_FG_CH_01_TOKEN", ""),
        "vdom": os.getenv("FORTINET_FG_CH_01_VDOM", "root"),
    },
    {
        "name": "fg-911-01",
        "base_url": os.getenv("FORTINET_FG_911_01_URL", ""),
        "api_token": os.getenv("FORTINET_FG_911_01_TOKEN", ""),
        "vdom": os.getenv("FORTINET_FG_911_01_VDOM", "root"),
    },
    {
        "name": "fg-bl-01",
        "base_url": os.getenv("FORTINET_FG_BL_01_URL", ""),
        "api_token": os.getenv("FORTINET_FG_BL_01_TOKEN", ""),
        "vdom": os.getenv("FORTINET_FG_BL_01_VDOM", "root"),
    },
    {
        "name": "fg-civ-01",
        "base_url": os.getenv("FORTINET_FG_CIV_01_URL", ""),
        "api_token": os.getenv("FORTINET_FG_CIV_01_TOKEN", ""),
        "vdom": os.getenv("FORTINET_FG_CIV_01_VDOM", "root"),
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

    print(f"  nodes={stats['nodes_written']}  edges={stats['edges_written']}")
    if snapshot.errors:
        print("  Errors:")
        for err in snapshot.errors[:20]:
            print("   -", err)


def main():
    verify_ssl = os.getenv("FORTINET_VERIFY_SSL", "false").lower() == "true"

    for fw in FORTIGATES:
        if not fw["base_url"] or not fw["api_token"]:
            print(f"Skipping {fw['name']}: missing URL or token")
            continue

        print(f"Importing {fw['name']} ({fw['base_url']}) ...")

        connector = FortinetReachabilityConnector(
            base_url=fw["base_url"],
            api_token=fw["api_token"],
            account_id="onprem",
            device_name=fw["name"],
            vdom=fw.get("vdom", "root"),
            verify_ssl=verify_ssl,
        )
        connector.authenticate()
        raw = connector.fetch_raw()
        snapshot = connector.normalize_raw(raw)
        write_snapshot(snapshot)

    print("\nDone. Now run: python scripts/post_ingest_link.py")


if __name__ == "__main__":
    main()

from __future__ import annotations

from typing import Optional

from neo4j import GraphDatabase

from sariel.connectors.nessus import NessusConnector
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings
from sariel.models.entities import Cloud


NESSUS_FILE = "data/report.nessus"


def normalize(value: str) -> str:
    return (value or "").strip().lower()


def build_auto_resolver():
    settings = get_settings()
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )

    ip_map: dict[str, str] = {}
    name_map: dict[str, str] = {}

    with driver.session() as session:
        result = session.run(
            """
            MATCH (n:SarielNode)
            RETURN
              n.canonical_id AS canonical_id,
              n.label AS label,
              n.hostname AS hostname,
              n.fqdn AS fqdn,
              n.private_ip AS private_ip,
              n.public_ip AS public_ip,
              n.ip_address AS ip_address,
              n.instance_id AS instance_id,
              n.resource_id AS resource_id
            """
        )

        for row in result:
            canonical_id = row["canonical_id"]
            if not canonical_id:
                continue

            for ip in [
                row.get("private_ip"),
                row.get("public_ip"),
                row.get("ip_address"),
            ]:
                if ip:
                    ip_map[normalize(str(ip))] = canonical_id

            for name in [
                row.get("label"),
                row.get("hostname"),
                row.get("fqdn"),
                row.get("instance_id"),
                row.get("resource_id"),
                row.get("canonical_id"),
            ]:
                if name:
                    name_map[normalize(str(name))] = canonical_id

    driver.close()

    def resolve(finding: dict) -> Optional[str]:
        candidates = [
            finding.get("host_ip"),
            finding.get("hostname"),
            finding.get("fqdn"),
        ]

        for candidate in candidates:
            if not candidate:
                continue

            key = normalize(str(candidate))

            if key in ip_map:
                return ip_map[key]

            if key in name_map:
                return name_map[key]

            if "." in key:
                short_name = key.split(".")[0]
                if short_name in name_map:
                    return name_map[short_name]

        return None

    return resolve


def main():
    settings = get_settings()

    resolver = build_auto_resolver()

    connector = NessusConnector(
        nessus_file=NESSUS_FILE,
        asset_resolver=resolver,
        account_id="nessus-import",
        cloud=Cloud.AWS,
    )

    snapshot = connector.orchestrate()

    writer = GraphWriter(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password,
    )
    writer.connect()
    writer.setup_indexes()
    stats = writer.write_snapshot(snapshot)
    writer.close()

    print("Write stats:", stats)
    print("Errors:")
    for err in snapshot.errors:
        print(" -", err)


if __name__ == "__main__":
    main()
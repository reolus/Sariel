from __future__ import annotations

import tempfile
from pathlib import Path

from neo4j import GraphDatabase

from sariel.connectors.nessus import NessusConnector
from sariel.connectors.nessus.api import NessusAPIClient
from sariel.graph.writer import GraphWriter
from sariel.models.config import get_settings
from sariel.models.entities import Cloud


def normalize(value: str) -> str:
    return (value or "").strip().lower()


def build_auto_resolver():
    settings = get_settings()
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )

    ip_map = {}
    name_map = {}

    with driver.session() as session:
        rows = session.run(
            """
            MATCH (n:SarielNode)
            RETURN
              n.canonical_id AS canonical_id,
              n.label AS label,
              n.hostname AS hostname,
              n.fqdn AS fqdn,
              n.private_ip AS private_ip,
              n.public_ip AS public_ip,
              n.ip_address AS ip_address
            """
        )

        for row in rows:
            canonical_id = row["canonical_id"]
            if not canonical_id:
                continue

            for ip in [row.get("private_ip"), row.get("public_ip"), row.get("ip_address")]:
                if ip:
                    ip_map[normalize(str(ip))] = canonical_id

            for name in [row.get("label"), row.get("hostname"), row.get("fqdn"), row.get("canonical_id")]:
                if name:
                    name_map[normalize(str(name))] = canonical_id

    driver.close()

    print(f"Resolver loaded: {len(ip_map)} IPs, {len(name_map)} names")

    def resolve(finding: dict):
        for candidate in [finding.get("host_ip"), finding.get("hostname"), finding.get("fqdn")]:
            if not candidate:
                continue

            key = normalize(str(candidate))

            if key in ip_map:
                return ip_map[key]
            if key in name_map:
                return name_map[key]

            if "." in key:
                short = key.split(".")[0]
                if short in name_map:
                    return name_map[short]

        return None

    return resolve


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

    print("Write stats:", stats)
    if snapshot.errors:
        print("Errors:")
        for err in snapshot.errors[:50]:
            print(" -", err)
        if len(snapshot.errors) > 50:
            print(f" ... {len(snapshot.errors) - 50} more errors")


def main():
    settings = get_settings()

    print("Starting Nessus API import...")

    client = NessusAPIClient(
        base_url=settings.nessus_base_url,
        access_key=settings.nessus_access_key,
        secret_key=settings.nessus_secret_key,
        verify_ssl=getattr(settings, "nessus_verify_ssl", False),
    )

    payload = client.list_scans_raw()
    scans = payload.get("scans", [])

    print(f"Found {len(scans)} scans")

    if not scans:
        print("No scans returned.")
        print(payload)
        return

    resolver = build_auto_resolver()

    out_dir = Path("data/nessus_exports")
    out_dir.mkdir(parents=True, exist_ok=True)

    completed = [
        s for s in scans
        if str(s.get("status", "")).lower() in ("completed", "imported")
    ]

    print(f"Found {len(completed)} completed/imported scans")

    for scan in completed:
        scan_id = scan.get("id")
        scan_name = scan.get("name", f"scan-{scan_id}")
        status = scan.get("status")

        print(f"\nProcessing scan: {scan_name} id={scan_id} status={status}")

        try:
            file_id = client.export_scan(scan_id)
            print(f"Export requested: file_id={file_id}")

            client.wait_for_export(scan_id, file_id)
            print("Export ready")

            data = client.download_export(scan_id, file_id)

            safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in scan_name)
            export_path = out_dir / f"{scan_id}_{safe_name}.nessus"
            export_path.write_bytes(data)

            print(f"Downloaded: {export_path} ({len(data)} bytes)")

            connector = NessusConnector(
                nessus_file=str(export_path),
                asset_resolver=resolver,
                account_id="nessus-api",
                cloud=Cloud.AWS,
            )

            snapshot = connector.orchestrate()
            write_snapshot(snapshot)

        except Exception as exc:
            print(f"Failed scan {scan_name} id={scan_id}: {exc}")


if __name__ == "__main__":
    main()
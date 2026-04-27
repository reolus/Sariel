from sariel.connectors.nessus.api import NessusAPIClient
from sariel.connectors.nessus import NessusConnector
import tempfile

def import_all_scans():
    client = NessusAPIClient(
        base_url=settings.nessus_base_url,
        access_key=settings.nessus_access_key,
        secret_key=settings.nessus_secret_key,
    )

    scans = client.list_scans()
    print(f"Found {len(scans)} scans")

    for scan in scans:
        print(f"Processing scan: {scan.get('name')} (ID: {scan.get('id')})")
        scan_id = scan["id"]
        name = scan["name"]

        print(f"Processing scan: {name}")

        file_id = client.export_scan(scan_id)
        client.wait_for_export(scan_id, file_id)
        data = client.download_export(scan_id, file_id)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".nessus") as f:
            f.write(data)
            path = f.name

        connector = NessusConnector(
            nessus_file=path,
            asset_resolver=auto_resolver,
            account_id="nessus-api",
        )

        snapshot = connector.orchestrate()
        write_snapshot(snapshot)
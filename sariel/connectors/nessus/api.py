import time
import requests

class NessusAPIClient:
    def __init__(self, base_url, access_key, secret_key, verify_ssl=False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify_ssl

        self.session.headers.update({
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
        })

    def list_scans(self):
        resp = self.session.get(f"{self.base_url}/scans")
        resp.raise_for_status()
        return resp.json()["scans"]

    def export_scan(self, scan_id):
        resp = self.session.post(
            f"{self.base_url}/scans/{scan_id}/export",
            json={"format": "nessus"}
        )
        resp.raise_for_status()
        return resp.json()["file"]

    def wait_for_export(self, scan_id, file_id):
        while True:
            resp = self.session.get(
                f"{self.base_url}/scans/{scan_id}/export/{file_id}/status"
            )
            resp.raise_for_status()
            status = resp.json()["status"]

            if status == "ready":
                return

            time.sleep(2)

    def download_export(self, scan_id, file_id):
        resp = self.session.get(
            f"{self.base_url}/scans/{scan_id}/export/{file_id}/download"
        )
        resp.raise_for_status()
        return resp.content
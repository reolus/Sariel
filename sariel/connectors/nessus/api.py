from __future__ import annotations

import time

import requests


class NessusAPIClient:
    def __init__(self, base_url: str, access_key: str, secret_key: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def list_scans_raw(self) -> dict:
        resp = self.session.get(f"{self.base_url}/scans", timeout=60)
        resp.raise_for_status()
        return resp.json()

    def list_scans(self) -> list[dict]:
        return self.list_scans_raw().get("scans", [])

    def export_scan(self, scan_id: int | str) -> int:
        resp = self.session.post(
            f"{self.base_url}/scans/{scan_id}/export",
            json={"format": "nessus"},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["file"]

    def wait_for_export(self, scan_id: int | str, file_id: int | str, timeout_seconds: int = 300) -> None:
        deadline = time.time() + timeout_seconds

        while time.time() < deadline:
            resp = self.session.get(
                f"{self.base_url}/scans/{scan_id}/export/{file_id}/status",
                timeout=60,
            )
            resp.raise_for_status()

            status = resp.json().get("status")
            if status == "ready":
                return

            time.sleep(2)

        raise TimeoutError(f"Nessus export timed out scan_id={scan_id} file_id={file_id}")

    def download_export(self, scan_id: int | str, file_id: int | str) -> bytes:
        resp = self.session.get(
            f"{self.base_url}/scans/{scan_id}/export/{file_id}/download",
            timeout=300,
        )
        resp.raise_for_status()
        return resp.content
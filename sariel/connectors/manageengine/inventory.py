from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

import requests

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalNode,
    Cloud,
    NodeType,
    NormalizedSnapshot,
)

logger = logging.getLogger(__name__)


class ManageEngineInventoryConnector(BaseConnector):
    """
    Ingest endpoint inventory from ManageEngine Endpoint Central / UEMS.

    Expected env/config:
    - base_url: https://server-or-cloud-host
    - auth_header: full Authorization header value, e.g. "Zoho-oauthtoken ..."
    """

    cloud = Cloud.AWS  # temporary until Sariel has Cloud.ONPREM

    def __init__(
        self,
        base_url: str,
        auth_header: str,
        account_id: str = "onprem",
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.account_id = account_id
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def authenticate(self) -> None:
        if not self.base_url:
            raise ValueError("ManageEngine base_url is required")
        if not self.auth_header:
            raise ValueError("ManageEngine auth_header is required")

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = requests.get(
            url,
            headers={
                "Authorization": self.auth_header,
                "Accept": "application/json",
            },
            params=params or {},
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_raw(self) -> dict:
        raw: dict[str, Any] = {}

        # Primary inventory list.
        raw["scancomputers"] = self._get("/api/1.4/inventory/scancomputers")

        # Optional detail enrichment by resource id.
        computers = _extract_manageengine_records(raw["scancomputers"])
        details = []

        for comp in computers:
            resid = (
                comp.get("resource_id")
                or comp.get("computer_resource_id")
                or comp.get("resid")
                or comp.get("RESOURCE_ID")
            )
            if not resid:
                continue
            try:
                details.append(
                    self._get(
                        "/api/1.4/inventory/compdetailssummary",
                        params={"resid": str(resid)},
                    )
                )
            except Exception as exc:
                logger.warning("ManageEngine detail fetch failed for resid=%s: %s", resid, exc)

        raw["details"] = details
        return raw

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        now = datetime.utcnow()
        nodes: list[CanonicalNode] = []
        errors: list[str] = []

        records = _extract_manageengine_records(raw.get("scancomputers", {}))

        for rec in records:
            try:
                asset = _normalize_manageengine_asset(rec)
                canonical_id = _asset_canonical_id(
                    source="manageengine",
                    account_id=self.account_id,
                    hostname=asset.get("hostname"),
                    ip=asset.get("private_ip"),
                    resource_id=asset.get("resource_id"),
                )

                nodes.append(
                    CanonicalNode(
                        canonical_id=canonical_id,
                        node_type=NodeType.EC2_INSTANCE,  # temporary: replace with ONPREM_HOST later
                        cloud=Cloud.AWS,
                        account_id=self.account_id,
                        label=asset.get("hostname") or asset.get("private_ip") or canonical_id,
                        properties={
                            **asset,
                            "source": "manageengine",
                            "managed": True,
                            "has_public_ip": False,
                        },
                        scanned_at=now,
                    )
                )
            except Exception as exc:
                errors.append(f"ManageEngine asset normalization failed: {exc}")

        return NormalizedSnapshot(
            cloud=Cloud.AWS,
            account_id=self.account_id,
            nodes=nodes,
            edges=[],
            raw_source="manageengine",
            scanned_at=now,
            errors=errors,
        )


def _extract_manageengine_records(payload: dict) -> list[dict]:
    """
    ManageEngine responses vary slightly by endpoint/version.
    This recursively looks for list-like inventory records.
    """
    if isinstance(payload, list):
        return payload

    if not isinstance(payload, dict):
        return []

    candidates = []

    def walk(obj):
        if isinstance(obj, list):
            if obj and isinstance(obj[0], dict):
                candidates.append(obj)
            for item in obj:
                walk(item)
        elif isinstance(obj, dict):
            for value in obj.values():
                walk(value)

    walk(payload)

    # Pick the largest list of dicts as the main inventory collection.
    return max(candidates, key=len, default=[])


def _normalize_manageengine_asset(rec: dict) -> dict:
    hostname = _first(
        rec,
        "resource_name",
        "computer_name",
        "computerName",
        "name",
        "host_name",
        "hostname",
        "dns_name",
    )
    ip = _first(
        rec,
        "ip_address",
        "ipAddress",
        "computer_ip",
        "host_ip",
        "last_contacted_ip",
    )
    fqdn = _first(rec, "fqdn", "dns_name", "fully_qualified_name")
    domain = _first(rec, "domain_name", "domain", "managed_domain")
    os_name = _first(rec, "os_name", "osName", "operating_system", "os_platform")
    mac = _first(rec, "mac_address", "macAddress", "mac")
    resource_id = _first(rec, "resource_id", "computer_resource_id", "resid", "RESOURCE_ID")
    last_seen = _first(rec, "last_contact_time", "last_seen", "computer_status_update_time")

    return {
        "resource_id": str(resource_id or ""),
        "hostname": hostname or "",
        "fqdn": fqdn or "",
        "private_ip": ip or "",
        "mac_address": mac or "",
        "domain": domain or "",
        "os": os_name or "",
        "device_type": _classify_device_type(hostname or "", os_name or ""),
        "last_seen": str(last_seen or ""),
        "raw": rec,
    }


def _first(rec: dict, *keys: str):
    for key in keys:
        value = rec.get(key)
        if value not in (None, ""):
            return value
    return None


def _asset_canonical_id(source: str, account_id: str, hostname: str, ip: str, resource_id: str) -> str:
    if resource_id:
        return f"{source}://{account_id}/assets/{resource_id}"
    if hostname:
        return f"{source}://{account_id}/hosts/{hostname.lower()}"
    if ip:
        return f"{source}://{account_id}/ips/{ip}"
    raise ValueError("Cannot build canonical ID without resource_id, hostname, or IP")


def _classify_device_type(hostname: str, os_name: str) -> str:
    text = f"{hostname} {os_name}".lower()
    if "server" in text or "windows server" in text or "linux" in text:
        return "server"
    if "windows 10" in text or "windows 11" in text or "workstation" in text:
        return "workstation"
    if "printer" in text:
        return "printer"
    return "endpoint"
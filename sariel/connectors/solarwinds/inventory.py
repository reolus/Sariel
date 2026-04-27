from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import requests
from requests.auth import HTTPBasicAuth

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalNode,
    Cloud,
    NodeType,
    NormalizedSnapshot,
)

logger = logging.getLogger(__name__)


class SolarWindsInventoryConnector(BaseConnector):
    """
    Ingest node inventory from SolarWinds Orion/SWIS.
    """

    cloud = Cloud.AWS  # temporary until Sariel has Cloud.ONPREM

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        account_id: str = "onprem",
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.account_id = account_id
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def authenticate(self) -> None:
        if not self.base_url:
            raise ValueError("SolarWinds base_url is required")
        if not self.username or not self.password:
            raise ValueError("SolarWinds username/password are required")

    def _query(self, swql: str) -> list[dict]:
        url = f"{self.base_url}/SolarWinds/InformationService/v3/Json/Query"
        resp = requests.post(
            url,
            json={"query": swql},
            auth=HTTPBasicAuth(self.username, self.password),
            headers={"Accept": "application/json"},
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()
        return resp.json().get("results", [])

    def fetch_raw(self) -> dict:
        swql = """
        SELECT
            NodeID,
            Caption,
            DNS,
            IPAddress,
            IPAddressType,
            ObjectSubType,
            Vendor,
            MachineType,
            NodeDescription,
            Description,
            Status,
            LastBoot,
            SysName,
            Location,
            Contact
        FROM Orion.Nodes
        """
        return {"nodes": self._query(swql)}

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        now = datetime.utcnow()
        nodes: list[CanonicalNode] = []
        errors: list[str] = []

        for rec in raw.get("nodes", []):
            try:
                node_id = str(rec.get("NodeID", ""))
                ip = str(rec.get("IPAddress", "") or "")
                caption = str(rec.get("Caption", "") or "")
                dns = str(rec.get("DNS", "") or "")
                canonical_id = f"solarwinds://{self.account_id}/nodes/{node_id}"

                nodes.append(
                    CanonicalNode(
                        canonical_id=canonical_id,
                        node_type=NodeType.EC2_INSTANCE,  # temporary: replace with ONPREM_HOST/NETWORK_DEVICE later
                        cloud=Cloud.AWS,
                        account_id=self.account_id,
                        label=caption or dns or ip or canonical_id,
                        properties={
                            "source": "solarwinds",
                            "solarwinds_node_id": node_id,
                            "hostname": caption,
                            "fqdn": dns,
                            "private_ip": ip,
                            "ip_address_type": rec.get("IPAddressType", ""),
                            "vendor": rec.get("Vendor", ""),
                            "machine_type": rec.get("MachineType", ""),
                            "object_subtype": rec.get("ObjectSubType", ""),
                            "description": rec.get("Description") or rec.get("NodeDescription") or "",
                            "status": str(rec.get("Status", "")),
                            "last_boot": str(rec.get("LastBoot", "")),
                            "sys_name": rec.get("SysName", ""),
                            "location": rec.get("Location", ""),
                            "contact": rec.get("Contact", ""),
                            "device_type": _classify_solarwinds_device(rec),
                            "managed": True,
                            "has_public_ip": False,
                            "raw": rec,
                        },
                        scanned_at=now,
                    )
                )
            except Exception as exc:
                errors.append(f"SolarWinds node normalization failed: {exc}")

        return NormalizedSnapshot(
            cloud=Cloud.AWS,
            account_id=self.account_id,
            nodes=nodes,
            edges=[],
            raw_source="solarwinds",
            scanned_at=now,
            errors=errors,
        )


def _classify_solarwinds_device(rec: dict) -> str:
    text = " ".join(
        str(rec.get(k, "") or "")
        for k in ["Vendor", "MachineType", "ObjectSubType", "Caption", "Description"]
    ).lower()

    if any(x in text for x in ["cisco", "switch", "router", "firewall", "palo alto", "fortinet"]):
        return "network_device"
    if any(x in text for x in ["windows server", "linux", "vmware", "hyper-v", "esxi"]):
        return "server"
    if "printer" in text:
        return "printer"
    return "host"
from __future__ import annotations

import logging
import socket
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalEdge,
    CanonicalNode,
    Cloud,
    EdgeType,
    NodeType,
    NormalizedSnapshot,
)

logger = logging.getLogger(__name__)


class NessusConnector(BaseConnector):
    """
    Ingest vulnerabilities from a Nessus .nessus XML export.

    Design notes:
    - Nessus is treated as an external vulnerability source, not a scanner Sariel controls.
    - This connector only creates vulnerability nodes + HAS_VULN edges.
    - Asset resolution is done by hostname/IP -> canonical_id mapping.
    - If an asset cannot be resolved, the finding is skipped and recorded in snapshot.errors.

    Typical usage:
        connector = NessusConnector(
            nessus_file="/path/to/export.nessus",
            asset_resolver=my_resolver,
            account_id="demo",
            cloud=Cloud.AWS,
        )
        snapshot = connector.orchestrate()
    """

    def __init__(
        self,
        nessus_file: str,
        asset_resolver: Callable[[dict], Optional[str]],
        account_id: str,
        cloud: Cloud = Cloud.AWS,
        source_name: str = "nessus",
    ):
        self.nessus_file = str(nessus_file)
        self.asset_resolver = asset_resolver
        self.account_id = account_id
        self.cloud = cloud
        self.source_name = source_name

    def authenticate(self) -> None:
        # No auth required for offline .nessus ingestion.
        nessus_path = Path(self.nessus_file)
        if not nessus_path.exists():
            raise FileNotFoundError(f"Nessus file not found: {self.nessus_file}")

    def fetch_raw(self) -> dict:
        return {"nessus_file": self.nessus_file}

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        now = datetime.utcnow()
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []

        nessus_file = raw["nessus_file"]
        root = ET.parse(nessus_file).getroot()

        # De-duplicate CVE nodes across all hosts/plugins
        seen_cves: set[str] = set()
        seen_edges: set[tuple[str, str]] = set()

        for report_host in root.findall(".//ReportHost"):
            host_context = self._extract_host_context(report_host)

            for report_item in report_host.findall("./ReportItem"):
                try:
                    finding = self._extract_finding(report_item, host_context)
                    if not finding["cves"]:
                        continue

                    asset_id = self.asset_resolver(finding)
                    if not asset_id:
                        errors.append(
                            f"Unresolved asset for host={finding.get('hostname') or finding.get('host_ip')}"
                        )
                        continue

                    for cve_id in finding["cves"]:
                        vuln_canonical_id = f"cve://{cve_id}"

                        if cve_id not in seen_cves:
                            seen_cves.add(cve_id)
                            nodes.append(
                                CanonicalNode(
                                    canonical_id=vuln_canonical_id,
                                    node_type=NodeType.VULNERABILITY,
                                    cloud=self.cloud,
                                    account_id=self.account_id,
                                    label=cve_id,
                                    properties={
                                        "cve_id": cve_id,
                                        "cvss_score": finding["cvss_score"],
                                        "cvss_exploitability_score": finding["cvss_exploitability_score"],
                                        "has_exploit": finding["has_exploit"],
                                        "severity": finding["severity"],
                                        "nessus_plugin_id": finding["plugin_id"],
                                        "nessus_plugin_name": finding["plugin_name"],
                                        "nessus_family": finding["plugin_family"],
                                        "port": finding["port"],
                                        "protocol": finding["protocol"],
                                        "service": finding["service"],
                                        "source": self.source_name,
                                        "description": finding["description"][:1000],
                                        "solution": finding["solution"][:1000],
                                        "synopsis": finding["synopsis"][:500],
                                    },
                                    scanned_at=now,
                                )
                            )

                        edge_key = (asset_id, vuln_canonical_id)
                        if edge_key not in seen_edges:
                            seen_edges.add(edge_key)
                            edges.append(
                                CanonicalEdge(
                                    from_id=asset_id,
                                    to_id=vuln_canonical_id,
                                    edge_type=EdgeType.HAS_VULN,
                                    properties={
                                        "source": self.source_name,
                                        "plugin_id": finding["plugin_id"],
                                        "port": finding["port"],
                                        "protocol": finding["protocol"],
                                        "service": finding["service"],
                                        "hostname": finding["hostname"],
                                        "host_ip": finding["host_ip"],
                                    },
                                    scanned_at=now,
                                )
                            )

                except Exception as exc:
                    plugin_id = report_item.attrib.get("pluginID", "unknown")
                    errors.append(f"Failed to process Nessus finding plugin={plugin_id}: {exc}")

        return NormalizedSnapshot(
            cloud=self.cloud,
            account_id=self.account_id,
            nodes=nodes,
            edges=edges,
            raw_source=self.nessus_file,
            scanned_at=now,
            errors=errors,
        )

    def _extract_host_context(self, report_host: ET.Element) -> dict:
        host_context: dict[str, str] = {
            "report_name": report_host.attrib.get("name", ""),
            "host_ip": "",
            "hostname": "",
            "fqdn": "",
            "netbios": "",
            "operating_system": "",
        }

        for tag in report_host.findall("./HostProperties/tag"):
            name = tag.attrib.get("name", "")
            value = (tag.text or "").strip()
            if name == "host-ip":
                host_context["host_ip"] = value
            elif name == "host-fqdn":
                host_context["fqdn"] = value
            elif name == "hostname":
                host_context["hostname"] = value
            elif name == "netbios-name":
                host_context["netbios"] = value
            elif name == "operating-system":
                host_context["operating_system"] = value

        if not host_context["hostname"]:
            host_context["hostname"] = host_context["fqdn"] or host_context["report_name"]

        return host_context

    def _extract_finding(self, item: ET.Element, host_context: dict) -> dict:
        def text(name: str) -> str:
            child = item.find(name)
            return (child.text or "").strip() if child is not None and child.text else ""

        def first_float(*names: str, default: float = 0.0) -> float:
            for name in names:
                value = text(name)
                if value:
                    try:
                        return float(value)
                    except ValueError:
                        continue
            return default

        cves = self._extract_cves(item)

        severity_num = int(item.attrib.get("severity", "0"))
        severity = {
            4: "CRITICAL",
            3: "HIGH",
            2: "MEDIUM",
            1: "LOW",
            0: "INFO",
        }.get(severity_num, "INFO")

        exploit_refs = " ".join(
            [
                text("exploit_available"),
                text("exploitability_ease"),
                text("in_the_news"),
                text("edb-id"),
                text("metasploit_name"),
                text("canvas_package"),
                text("coref_id"),
            ]
        ).lower()

        has_exploit = any(
            token in exploit_refs
            for token in ["true", "high", "metasploit", "exploitdb", "edb-", "canvas", "core impact"]
        )

        cvss_score = first_float("cvss3_base_score", "cvss_base_score", default=0.0)
        cvss_exploitability = first_float(
            "cvss3_temporal_score",
            "cvss_temporal_score",
            default=0.0,
        )

        # Nessus usually does not provide the exact CVSS exploitability subscore in a stable way.
        # If temporal score is absent, estimate conservatively from base score.
        if cvss_exploitability <= 0 and cvss_score > 0:
            cvss_exploitability = min(cvss_score * 0.4, 3.9)

        return {
            "hostname": host_context.get("hostname", ""),
            "fqdn": host_context.get("fqdn", ""),
            "host_ip": host_context.get("host_ip", ""),
            "operating_system": host_context.get("operating_system", ""),
            "plugin_id": item.attrib.get("pluginID", ""),
            "plugin_name": item.attrib.get("pluginName", ""),
            "plugin_family": item.attrib.get("pluginFamily", ""),
            "port": int(item.attrib.get("port", "0")),
            "protocol": item.attrib.get("protocol", ""),
            "service": item.attrib.get("svc_name", ""),
            "severity": severity,
            "cves": cves,
            "cvss_score": cvss_score,
            "cvss_exploitability_score": cvss_exploitability,
            "has_exploit": has_exploit,
            "description": text("description"),
            "solution": text("solution"),
            "synopsis": text("synopsis"),
            "plugin_output": text("plugin_output"),
        }

    def _extract_cves(self, item: ET.Element) -> list[str]:
        cves: set[str] = set()

        # Most common form: multiple <cve> children
        for cve_elem in item.findall("cve"):
            value = (cve_elem.text or "").strip()
            if value.upper().startswith("CVE-"):
                cves.add(value.upper())

        # Fallback: sometimes CVEs appear comma-separated
        if not cves:
            cve_text = ""
            cve_elem = item.find("cve")
            if cve_elem is not None and cve_elem.text:
                cve_text = cve_elem.text
            for part in cve_text.replace(";", ",").split(","):
                value = part.strip().upper()
                if value.startswith("CVE-"):
                    cves.add(value)

        return sorted(cves)


def make_simple_resolver(
    ip_map: Optional[dict[str, str]] = None,
    hostname_map: Optional[dict[str, str]] = None,
    dns_lookup: bool = False,
) -> Callable[[dict], Optional[str]]:
    """
    Simple resolver for demos and early integrations.

    Resolution order:
    1. exact hostname map
    2. exact FQDN map
    3. exact IP map
    4. optional DNS lookup hostname -> IP -> IP map

    Example:
        resolver = make_simple_resolver(
            ip_map={"10.0.1.5": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123"},
            hostname_map={"prod-payments-vm": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123"},
        )
    """
    ip_map = ip_map or {}
    hostname_map = hostname_map or {}

    def resolve(finding: dict) -> Optional[str]:
        for candidate in [finding.get("hostname"), finding.get("fqdn")]:
            if candidate and candidate in hostname_map:
                return hostname_map[candidate]

        host_ip = finding.get("host_ip")
        if host_ip and host_ip in ip_map:
            return ip_map[host_ip]

        if dns_lookup:
            hostname = finding.get("hostname") or finding.get("fqdn")
            if hostname:
                try:
                    resolved_ip = socket.gethostbyname(hostname)
                    return ip_map.get(resolved_ip)
                except Exception:
                    return None

        return None

    return resolve
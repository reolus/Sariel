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
    Ingest Nessus .nessus XML exports.

    This version:
    - ingests CVE-backed findings
    - ingests plugin-only findings
    - deduplicates vulnerability nodes and edges
    - creates placeholder assets for unresolved Nessus hosts
    - keeps CVE correlation intact
    """

    def __init__(
        self,
        nessus_file: str,
        asset_resolver: Callable[[dict], Optional[str]],
        account_id: str,
        cloud: Cloud = Cloud.AWS,
        source_name: str = "nessus",
        include_info: bool = False,
        create_placeholder_assets: bool = True,
    ):
        self.nessus_file = str(nessus_file)
        self.asset_resolver = asset_resolver
        self.account_id = account_id
        self.cloud = cloud
        self.source_name = source_name
        self.include_info = include_info
        self.create_placeholder_assets = create_placeholder_assets

    def authenticate(self) -> None:
        path = Path(self.nessus_file)
        if not path.exists():
            raise FileNotFoundError(f"Nessus file not found: {self.nessus_file}")

    def fetch_raw(self) -> dict:
        return {"nessus_file": self.nessus_file}

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        now = datetime.utcnow()
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []

        root = ET.parse(raw["nessus_file"]).getroot()

        seen_nodes: set[str] = set()
        seen_edges: set[tuple[str, str, str, str]] = set()

        for report_host in root.findall(".//ReportHost"):
            host_context = self._extract_host_context(report_host)

            for item in report_host.findall("./ReportItem"):
                try:
                    finding = self._extract_finding(item, host_context)

                    if finding["severity"] == "INFO" and not self.include_info:
                        continue

                    asset_id = self.asset_resolver(finding)

                    if not asset_id:
                        if not self.create_placeholder_assets:
                            errors.append(
                                f"Unresolved asset for host={finding.get('hostname') or finding.get('host_ip')}"
                            )
                            continue

                        placeholder = self._build_placeholder_asset(finding, now)
                        asset_id = placeholder.canonical_id

                        if placeholder.canonical_id not in seen_nodes:
                            seen_nodes.add(placeholder.canonical_id)
                            nodes.append(placeholder)

                    vuln_nodes = self._build_vulnerability_nodes(finding, now)

                    for vuln in vuln_nodes:
                        if vuln.canonical_id not in seen_nodes:
                            seen_nodes.add(vuln.canonical_id)
                            nodes.append(vuln)

                        edge_key = (
                            asset_id,
                            vuln.canonical_id,
                            finding["plugin_id"],
                            str(finding["port"]),
                        )

                        if edge_key in seen_edges:
                            continue

                        seen_edges.add(edge_key)

                        edges.append(
                            CanonicalEdge(
                                from_id=asset_id,
                                to_id=vuln.canonical_id,
                                edge_type=EdgeType.HAS_VULN,
                                properties={
                                    "source": self.source_name,
                                    "scanner": "nessus",
                                    "plugin_id": finding["plugin_id"],
                                    "plugin_name": finding["plugin_name"],
                                    "plugin_family": finding["plugin_family"],
                                    "severity": finding["severity"],
                                    "port": finding["port"],
                                    "protocol": finding["protocol"],
                                    "service": finding["service"],
                                    "hostname": finding["hostname"],
                                    "host_ip": finding["host_ip"],
                                    "cves": finding["cves"],
                                },
                                scanned_at=now,
                            )
                        )

                except Exception as exc:
                    plugin_id = item.attrib.get("pluginID", "unknown")
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

    def _build_placeholder_asset(self, finding: dict, now: datetime) -> CanonicalNode:
        host_ip = finding.get("host_ip", "")
        hostname = finding.get("hostname", "") or finding.get("fqdn", "") or host_ip
        stable_key = host_ip or hostname

        canonical_id = f"nessus://{self.account_id}/asset/{stable_key}"

        return CanonicalNode(
            canonical_id=canonical_id,
            node_type=NodeType.EC2_INSTANCE,  # temporary on-prem compute representation
            cloud=self.cloud,
            account_id=self.account_id,
            label=hostname or host_ip or canonical_id,
            properties={
                "source": "nessus",
                "scanner": "nessus",
                "discovered_by": "nessus",
                "is_placeholder": True,
                "hostname": hostname,
                "fqdn": finding.get("fqdn", ""),
                "private_ip": host_ip,
                "public_ip": "",
                "os": finding.get("operating_system", ""),
                "device_type": "unknown",
                "has_public_ip": False,
                "managed": False,
            },
            scanned_at=now,
        )

    def _build_vulnerability_nodes(self, finding: dict, now: datetime) -> list[CanonicalNode]:
        nodes: list[CanonicalNode] = []

        plugin_id = finding["plugin_id"]
        plugin_canonical_id = f"plugin://nessus/{plugin_id}"

        base_props = {
            "name": finding["plugin_name"] or f"Nessus Plugin {plugin_id}",
            "source": self.source_name,
            "scanner": "nessus",
            "nessus_plugin_id": plugin_id,
            "nessus_plugin_name": finding["plugin_name"],
            "plugin_family": finding["plugin_family"],
            "severity": finding["severity"],
            "cvss_score": finding["cvss_score"],
            "cvss_exploitability_score": finding["cvss_exploitability_score"],
            "has_exploit": finding["has_exploit"],
            "vpr_score": finding["vpr_score"],
            "epss_score": finding["epss_score"],
            "port": finding["port"],
            "protocol": finding["protocol"],
            "service": finding["service"],
            "synopsis": finding["synopsis"][:500],
            "description": finding["description"][:1000],
            "solution": finding["solution"][:1000],
            "cves": finding["cves"],
            "is_cve_backed": bool(finding["cves"]),
            "vulnerability_kind": "nessus_plugin",
        }

        nodes.append(
            CanonicalNode(
                canonical_id=plugin_canonical_id,
                node_type=NodeType.VULNERABILITY,
                cloud=self.cloud,
                account_id=self.account_id,
                label=finding["plugin_name"] or f"Nessus Plugin {plugin_id}",
                properties=base_props,
                scanned_at=now,
            )
        )

        for cve_id in finding["cves"]:
            nodes.append(
                CanonicalNode(
                    canonical_id=f"cve://{cve_id}",
                    node_type=NodeType.VULNERABILITY,
                    cloud=self.cloud,
                    account_id=self.account_id,
                    label=cve_id,
                    properties={
                        **base_props,
                        "cve_id": cve_id,
                        "related_nessus_plugin_id": plugin_id,
                        "vulnerability_kind": "cve",
                    },
                    scanned_at=now,
                )
            )

        return nodes

    def _extract_host_context(self, report_host: ET.Element) -> dict:
        ctx = {
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
                ctx["host_ip"] = value
            elif name == "host-fqdn":
                ctx["fqdn"] = value
            elif name == "hostname":
                ctx["hostname"] = value
            elif name == "netbios-name":
                ctx["netbios"] = value
            elif name == "operating-system":
                ctx["operating_system"] = value

        if not ctx["hostname"]:
            ctx["hostname"] = ctx["fqdn"] or ctx["netbios"] or ctx["report_name"] or ctx["host_ip"]

        return ctx

    def _extract_finding(self, item: ET.Element, host_context: dict) -> dict:
        def text(name: str) -> str:
            child = item.find(name)
            return (child.text or "").strip() if child is not None and child.text else ""

        def first_float(*names: str, default: float = 0.0) -> float:
            for name in names:
                value = text(name)
                if not value:
                    continue
                try:
                    return float(value)
                except ValueError:
                    continue
            return default

        plugin_id = item.attrib.get("pluginID", "")
        plugin_name = item.attrib.get("pluginName", "")
        plugin_family = item.attrib.get("pluginFamily", "")
        severity_num = int(item.attrib.get("severity", "0"))

        severity = {
            4: "CRITICAL",
            3: "HIGH",
            2: "MEDIUM",
            1: "LOW",
            0: "INFO",
        }.get(severity_num, "INFO")

        cves = self._extract_cves(item)

        cvss_score = first_float("cvss3_base_score", "cvss_base_score", default=0.0)

        if cvss_score <= 0:
            cvss_score = {
                "CRITICAL": 9.5,
                "HIGH": 8.0,
                "MEDIUM": 5.0,
                "LOW": 2.5,
                "INFO": 0.5,
            }.get(severity, 0.5)

        cvss_exploitability_score = first_float(
            "cvss3_temporal_score",
            "cvss_temporal_score",
            default=0.0,
        )

        if cvss_exploitability_score <= 0:
            cvss_exploitability_score = min(cvss_score * 0.4, 3.9)

        exploit_blob = " ".join(
            [
                text("exploit_available"),
                text("exploitability_ease"),
                text("metasploit_name"),
                text("edb-id"),
                text("canvas_package"),
                text("coref_id"),
                text("in_the_news"),
            ]
        ).lower()

        has_exploit = any(
            token in exploit_blob
            for token in ["true", "yes", "metasploit", "exploitdb", "edb", "canvas", "core"]
        )

        return {
            "hostname": host_context.get("hostname", ""),
            "fqdn": host_context.get("fqdn", ""),
            "host_ip": host_context.get("host_ip", ""),
            "operating_system": host_context.get("operating_system", ""),
            "plugin_id": plugin_id,
            "plugin_name": plugin_name,
            "plugin_family": plugin_family,
            "port": int(item.attrib.get("port", "0")),
            "protocol": item.attrib.get("protocol", ""),
            "service": item.attrib.get("svc_name", ""),
            "severity": severity,
            "severity_num": severity_num,
            "cves": cves,
            "cvss_score": cvss_score,
            "cvss_exploitability_score": cvss_exploitability_score,
            "vpr_score": first_float("vpr_score", default=0.0),
            "epss_score": first_float("epss_score", default=0.0),
            "has_exploit": has_exploit,
            "synopsis": text("synopsis"),
            "description": text("description"),
            "solution": text("solution"),
            "plugin_output": text("plugin_output"),
        }

    def _extract_cves(self, item: ET.Element) -> list[str]:
        cves: set[str] = set()

        for cve_elem in item.findall("cve"):
            value = (cve_elem.text or "").strip().upper()
            if value.startswith("CVE-"):
                cves.add(value)

        return sorted(cves)


def make_simple_resolver(
    ip_map: Optional[dict[str, str]] = None,
    hostname_map: Optional[dict[str, str]] = None,
    dns_lookup: bool = False,
):
    ip_map = ip_map or {}
    hostname_map = hostname_map or {}

    def norm(value: str) -> str:
        return (value or "").strip().lower()

    normalized_ip_map = {norm(k): v for k, v in ip_map.items()}
    normalized_hostname_map = {norm(k): v for k, v in hostname_map.items()}

    def resolve(finding: dict) -> Optional[str]:
        for candidate in [
            finding.get("host_ip"),
            finding.get("hostname"),
            finding.get("fqdn"),
        ]:
            if not candidate:
                continue

            key = norm(str(candidate))

            if key in normalized_ip_map:
                return normalized_ip_map[key]

            if key in normalized_hostname_map:
                return normalized_hostname_map[key]

            if "." in key:
                short = key.split(".")[0]
                if short in normalized_hostname_map:
                    return normalized_hostname_map[short]

        if dns_lookup:
            hostname = finding.get("hostname") or finding.get("fqdn")
            if hostname:
                try:
                    resolved_ip = socket.gethostbyname(hostname)
                    return normalized_ip_map.get(norm(resolved_ip))
                except Exception:
                    return None

        return None

    return resolve

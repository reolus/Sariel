from __future__ import annotations

import ipaddress
import socket
from datetime import datetime
from typing import Iterable

from sariel.connectors.base import BaseConnector
from sariel.models.entities import (
    CanonicalEdge,
    CanonicalNode,
    Cloud,
    EdgeType,
    NodeType,
    NormalizedSnapshot,
)


class DNSInventoryConnector(BaseConnector):
    """
    DNS enrichment connector.

    Inputs:
    - hostnames/FQDNs
    - optional reverse lookup CIDRs

    Output:
    - placeholder/on-prem host nodes
    - DNS alias / same-identity style edges when a hostname and IP resolve together
    """

    cloud = Cloud.AWS

    def __init__(
        self,
        account_id: str,
        hostnames: Iterable[str] | None = None,
        reverse_cidrs: Iterable[str] | None = None,
        timeout_seconds: float = 2.0,
    ):
        self.account_id = account_id
        self.hostnames = list(hostnames or [])
        self.reverse_cidrs = list(reverse_cidrs or [])
        self.timeout_seconds = timeout_seconds

    def authenticate(self) -> None:
        socket.setdefaulttimeout(self.timeout_seconds)

    def fetch_raw(self) -> dict:
        forward: list[dict] = []
        reverse: list[dict] = []

        for hostname in self.hostnames:
            try:
                fqdn = socket.getfqdn(hostname)
                ip = socket.gethostbyname(hostname)
                forward.append(
                    {
                        "hostname": hostname,
                        "fqdn": fqdn,
                        "ip": ip,
                    }
                )
            except Exception as exc:
                forward.append(
                    {
                        "hostname": hostname,
                        "error": str(exc),
                    }
                )

        for cidr in self.reverse_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                for ip in network.hosts():
                    ip_str = str(ip)
                    try:
                        name, aliases, addresses = socket.gethostbyaddr(ip_str)
                        reverse.append(
                            {
                                "ip": ip_str,
                                "hostname": name,
                                "aliases": aliases,
                                "addresses": addresses,
                            }
                        )
                    except Exception:
                        continue
            except Exception as exc:
                reverse.append({"cidr": cidr, "error": str(exc)})

        return {"forward": forward, "reverse": reverse}

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        now = datetime.utcnow()
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []
        seen_nodes: set[str] = set()
        seen_edges: set[tuple[str, str]] = set()

        for rec in raw.get("forward", []):
            if rec.get("error"):
                errors.append(f"DNS forward failed for {rec.get('hostname')}: {rec.get('error')}")
                continue

            self._add_dns_asset(rec, now, nodes, edges, seen_nodes, seen_edges)

        for rec in raw.get("reverse", []):
            if rec.get("error"):
                errors.append(f"DNS reverse failed for {rec.get('cidr')}: {rec.get('error')}")
                continue

            self._add_dns_asset(rec, now, nodes, edges, seen_nodes, seen_edges)

        return NormalizedSnapshot(
            cloud=Cloud.AWS,
            account_id=self.account_id,
            nodes=nodes,
            edges=edges,
            raw_source="dns",
            scanned_at=now,
            errors=errors,
        )

    def _add_dns_asset(
        self,
        rec: dict,
        now: datetime,
        nodes: list[CanonicalNode],
        edges: list[CanonicalEdge],
        seen_nodes: set[str],
        seen_edges: set[tuple[str, str]],
    ) -> None:
        ip = rec.get("ip", "")
        hostname = rec.get("hostname", "")
        fqdn = rec.get("fqdn", hostname)

        if not ip and not hostname:
            return

        ip_id = f"dns://{self.account_id}/ip/{ip}" if ip else ""
        host_id = f"dns://{self.account_id}/host/{hostname.lower()}" if hostname else ""

        if ip_id and ip_id not in seen_nodes:
            seen_nodes.add(ip_id)
            nodes.append(
                CanonicalNode(
                    canonical_id=ip_id,
                    node_type=NodeType.EC2_INSTANCE,
                    cloud=Cloud.AWS,
                    account_id=self.account_id,
                    label=ip,
                    properties={
                        "source": "dns",
                        "private_ip": ip,
                        "hostname": hostname,
                        "fqdn": fqdn,
                        "has_public_ip": False,
                        "is_placeholder": True,
                        "device_type": "unknown",
                    },
                    scanned_at=now,
                )
            )

        if host_id and host_id not in seen_nodes:
            seen_nodes.add(host_id)
            nodes.append(
                CanonicalNode(
                    canonical_id=host_id,
                    node_type=NodeType.EC2_INSTANCE,
                    cloud=Cloud.AWS,
                    account_id=self.account_id,
                    label=hostname,
                    properties={
                        "source": "dns",
                        "private_ip": ip,
                        "hostname": hostname,
                        "fqdn": fqdn,
                        "has_public_ip": False,
                        "is_placeholder": True,
                        "device_type": "unknown",
                    },
                    scanned_at=now,
                )
            )

        if ip_id and host_id and (ip_id, host_id) not in seen_edges:
            seen_edges.add((ip_id, host_id))
            edges.append(
                CanonicalEdge(
                    from_id=ip_id,
                    to_id=host_id,
                    edge_type=EdgeType.SAME_IDENTITY,
                    properties={"source": "dns", "relationship": "ip_resolves_to_hostname"},
                    scanned_at=now,
                )
            )
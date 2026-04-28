from __future__ import annotations

import ipaddress
import logging
from datetime import datetime
from typing import Any, Optional

import requests

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


class FortinetReachabilityConnector(BaseConnector):
    """
    FortiGate connector for Sariel.

    Purpose:
    - Pull FortiGate firewall policy/address/service objects
    - Convert ACCEPT policies into reachability facts
    - Create:
        Zone/Subnet placeholder nodes
        CAN_REACH edges

    This intentionally does NOT store raw firewall config as the product model.
    It turns firewall rules into graph reachability.
    """

    cloud = Cloud.AWS  # temporary until Sariel has Cloud.ONPREM

    def __init__(
        self,
        base_url: str,
        api_token: str,
        account_id: str = "fortinet",
        device_name: str = "fortigate",
        vdom: str = "root",
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.account_id = account_id
        self.device_name = device_name
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def authenticate(self) -> None:
        if not self.base_url:
            raise ValueError("Fortinet base_url is required")
        if not self.api_token:
            raise ValueError("Fortinet api_token is required")

    def _get(self, path: str) -> dict:
        url = f"{self.base_url}{path}"
        params = {}
        if self.vdom:
            params["vdom"] = self.vdom

        resp = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Accept": "application/json",
            },
            params=params,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_raw(self) -> dict:
        return {
            "policies": self._get("/api/v2/cmdb/firewall/policy"),
            "addresses": self._get("/api/v2/cmdb/firewall/address"),
            "addrgrps": self._get("/api/v2/cmdb/firewall/addrgrp"),
            "services": self._get("/api/v2/cmdb/firewall.service/custom"),
            "service_groups": self._get("/api/v2/cmdb/firewall.service/group"),
        }

    def normalize_raw(self, raw: dict) -> NormalizedSnapshot:
        now = datetime.utcnow()
        nodes: list[CanonicalNode] = []
        edges: list[CanonicalEdge] = []
        errors: list[str] = []

        address_index = build_address_index(
            raw.get("addresses", {}).get("results", []),
            raw.get("addrgrps", {}).get("results", []),
        )
        service_index = build_service_index(
            raw.get("services", {}).get("results", []),
            raw.get("service_groups", {}).get("results", []),
        )

        seen_nodes: set[str] = set()
        seen_edges: set[tuple[str, str, str, str, str]] = set()

        policies = raw.get("policies", {}).get("results", [])

        for policy in policies:
            try:
                if str(policy.get("status", "enable")).lower() != "enable":
                    continue
                if str(policy.get("action", "")).lower() != "accept":
                    continue

                policy_id = str(policy.get("policyid", ""))
                policy_name = policy.get("name", f"policy-{policy_id}")

                src_intfs = names(policy.get("srcintf"))
                dst_intfs = names(policy.get("dstintf"))
                src_addrs = names(policy.get("srcaddr"))
                dst_addrs = names(policy.get("dstaddr"))
                services = names(policy.get("service"))

                src_networks = expand_address_names(src_addrs, address_index)
                dst_networks = expand_address_names(dst_addrs, address_index)
                service_defs = expand_service_names(services, service_index)

                # Fallbacks so we still create useful zone-level reachability
                if not src_networks:
                    src_networks = [network_record("addr", "unknown-src", "0.0.0.0/0")]
                if not dst_networks:
                    dst_networks = [network_record("addr", "unknown-dst", "0.0.0.0/0")]
                if not service_defs:
                    service_defs = [service_record("ALL", "tcp/udp", "0-65535")]

                for src in src_networks:
                    src_node = make_network_node(
                        account_id=self.account_id,
                        device_name=self.device_name,
                        vdom=self.vdom,
                        name=src["name"],
                        cidr=src["cidr"],
                        role="source",
                        now=now,
                    )
                    add_node(nodes, seen_nodes, src_node)

                    for dst in dst_networks:
                        dst_node = make_network_node(
                            account_id=self.account_id,
                            device_name=self.device_name,
                            vdom=self.vdom,
                            name=dst["name"],
                            cidr=dst["cidr"],
                            role="destination",
                            now=now,
                        )
                        add_node(nodes, seen_nodes, dst_node)

                        for svc in service_defs:
                            edge_key = (
                                src_node.canonical_id,
                                dst_node.canonical_id,
                                policy_id,
                                svc["protocol"],
                                svc["ports"],
                            )

                            if edge_key in seen_edges:
                                continue

                            seen_edges.add(edge_key)

                            edges.append(
                                CanonicalEdge(
                                    from_id=src_node.canonical_id,
                                    to_id=dst_node.canonical_id,
                                    edge_type=EdgeType.CAN_REACH,
                                    properties={
                                        "source": "fortinet",
                                        "firewall_name": self.device_name,
                                        "firewall_base_url": self.base_url,
                                        "firewall": self.base_url,
                                        "vdom": self.vdom,
                                        "policy_id": policy_id,
                                        "policy_name": policy_name,
                                        "src_interfaces": src_intfs,
                                        "dst_interfaces": dst_intfs,
                                        "src_addr_names": src_addrs,
                                        "dst_addr_names": dst_addrs,
                                        "service_names": services,
                                        "protocol": svc["protocol"],
                                        "ports": svc["ports"],
                                        "action": "accept",
                                    },
                                    scanned_at=now,
                                )
                            )

            except Exception as exc:
                errors.append(
                    f"Failed to normalize Fortinet policy "
                    f"{policy.get('policyid', 'unknown')}: {exc}"
                )

        return NormalizedSnapshot(
            cloud=Cloud.AWS,
            account_id=self.account_id,
            nodes=nodes,
            edges=edges,
            raw_source="fortinet",
            scanned_at=now,
            errors=errors,
        )


def names(value: Any) -> list[str]:
    if not value:
        return []

    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, dict):
                name = item.get("name")
                if name:
                    result.append(str(name))
            elif item:
                result.append(str(item))
        return result

    if isinstance(value, dict):
        name = value.get("name")
        return [str(name)] if name else []

    return [str(value)]


def build_address_index(addresses: list[dict], groups: list[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}

    for addr in addresses:
        name = addr.get("name")
        if not name:
            continue

        records = address_to_network_records(addr)
        index[name] = records

    # Address groups can reference addresses or other groups.
    # Resolve shallow first, then iterate a few times for nested groups.
    group_members: dict[str, list[str]] = {}

    for group in groups:
        name = group.get("name")
        if not name:
            continue
        group_members[name] = names(group.get("member"))

    for _ in range(5):
        changed = False
        for group_name, members in group_members.items():
            resolved: list[dict] = []
            for member in members:
                resolved.extend(index.get(member, []))
            if resolved and index.get(group_name) != resolved:
                index[group_name] = dedupe_network_records(resolved)
                changed = True
        if not changed:
            break

    # Fortinet built-ins
    index.setdefault("all", [network_record("addr", "all", "0.0.0.0/0")])
    index.setdefault("ALL", [network_record("addr", "all", "0.0.0.0/0")])

    return index


def address_to_network_records(addr: dict) -> list[dict]:
    name = addr.get("name", "unknown")
    addr_type = str(addr.get("type", "ipmask")).lower()

    if name.lower() == "all":
        return [network_record("addr", name, "0.0.0.0/0")]

    if addr_type == "ipmask":
        subnet = addr.get("subnet")
        if isinstance(subnet, list) and len(subnet) >= 2:
            ip = subnet[0]
            mask = subnet[1]
            return [network_record("addr", name, ip_mask_to_cidr(ip, mask))]

        if isinstance(subnet, str):
            return [network_record("addr", name, subnet)]

    if addr_type == "iprange":
        start = addr.get("start-ip", "")
        end = addr.get("end-ip", "")
        return [network_record("range", name, f"{start}-{end}")]

    if addr_type in ("fqdn", "wildcard-fqdn"):
        fqdn = addr.get("fqdn") or addr.get("wildcard-fqdn") or name
        return [network_record("fqdn", name, fqdn)]

    # Geography, dynamic, fabric objects, etc.
    return [network_record(addr_type, name, name)]


def network_record(kind: str, name: str, cidr: str) -> dict:
    return {
        "kind": kind,
        "name": str(name),
        "cidr": str(cidr),
    }


def dedupe_network_records(records: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for rec in records:
        key = (rec["kind"], rec["name"], rec["cidr"])
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def ip_mask_to_cidr(ip: str, mask: str) -> str:
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network)
    except Exception:
        return f"{ip}/{mask}"


def build_service_index(services: list[dict], groups: list[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}

    # Fortinet built-ins / common aliases.
    index["ALL"] = [service_record("ALL", "tcp/udp", "0-65535")]
    index["all"] = [service_record("ALL", "tcp/udp", "0-65535")]
    index["HTTP"] = [service_record("HTTP", "tcp", "80")]
    index["HTTPS"] = [service_record("HTTPS", "tcp", "443")]
    index["SSH"] = [service_record("SSH", "tcp", "22")]
    index["RDP"] = [service_record("RDP", "tcp", "3389")]
    index["DNS"] = [service_record("DNS", "udp/tcp", "53")]
    index["PING"] = [service_record("PING", "icmp", "")]

    for svc in services:
        name = svc.get("name")
        if not name:
            continue
        index[name] = fortinet_service_to_records(svc)

    group_members: dict[str, list[str]] = {}

    for group in groups:
        name = group.get("name")
        if not name:
            continue
        group_members[name] = names(group.get("member"))

    for _ in range(5):
        changed = False
        for group_name, members in group_members.items():
            resolved: list[dict] = []
            for member in members:
                resolved.extend(index.get(member, []))
            if resolved and index.get(group_name) != resolved:
                index[group_name] = dedupe_services(resolved)
                changed = True
        if not changed:
            break

    return index


def fortinet_service_to_records(svc: dict) -> list[dict]:
    name = svc.get("name", "service")
    records: list[dict] = []

    tcp_range = svc.get("tcp-portrange")
    udp_range = svc.get("udp-portrange")
    sctp_range = svc.get("sctp-portrange")
    protocol = str(svc.get("protocol", "")).upper()

    if tcp_range:
        records.append(service_record(name, "tcp", str(tcp_range)))
    if udp_range:
        records.append(service_record(name, "udp", str(udp_range)))
    if sctp_range:
        records.append(service_record(name, "sctp", str(sctp_range)))
    if protocol == "ICMP" or svc.get("protocol-number") == 1:
        records.append(service_record(name, "icmp", ""))

    if not records:
        records.append(service_record(name, "unknown", ""))

    return records


def service_record(name: str, protocol: str, ports: str) -> dict:
    return {
        "name": str(name),
        "protocol": str(protocol),
        "ports": str(ports),
    }


def dedupe_services(records: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for rec in records:
        key = (rec["name"], rec["protocol"], rec["ports"])
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def expand_address_names(names_: list[str], address_index: dict[str, list[dict]]) -> list[dict]:
    records: list[dict] = []
    for name in names_:
        records.extend(address_index.get(name, [network_record("unknown", name, name)]))
    return dedupe_network_records(records)


def expand_service_names(names_: list[str], service_index: dict[str, list[dict]]) -> list[dict]:
    records: list[dict] = []
    for name in names_:
        records.extend(service_index.get(name, [service_record(name, "unknown", "")]))
    return dedupe_services(records)


def make_network_node(
    account_id: str,
    device_name: str,
    vdom: str,
    name: str,
    cidr: str,
    role: str,
    now: datetime,
) -> CanonicalNode:
    safe_device = safe_id(device_name)
    safe_vdom = safe_id(vdom)
    safe_network = safe_id(f"{name}-{cidr}")

    canonical_id = (
        f"fortinet://{account_id}/"
        f"{safe_device}/"
        f"vdom/{safe_vdom}/"
        f"network/{safe_network}"
    )

    return CanonicalNode(
        canonical_id=canonical_id,
        node_type=NodeType.SECURITY_GROUP,
        cloud=Cloud.AWS,
        account_id=account_id,
        label=f"{device_name}:{name}",
        properties={
            "source": "fortinet",
            "firewall_name": device_name,
            "vdom": vdom,
            "network_name": name,
            "cidr": cidr,
            "network_role": role,
            "device_type": "network_segment",
            "is_network_segment": True,
        },
        scanned_at=now,
    )


def add_node(nodes: list[CanonicalNode], seen: set[str], node: CanonicalNode) -> None:
    if node.canonical_id in seen:
        return
    seen.add(node.canonical_id)
    nodes.append(node)


def safe_id(value: str) -> str:
    return (
        str(value)
        .strip()
        .lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace("*", "star")
    )
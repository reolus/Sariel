"""Aruba/Cisco switch configuration collection and parsing for Sariel.

This connector turns L2/L3 switch configuration into topology facts that Sariel
can use to decide whether a network path actually exists. It supports two modes:

1. Online collection with Netmiko using `show running-config`.
2. Offline lab ingestion from saved configs through sariel.ingest.network_switches.

The parser is intentionally conservative. It extracts facts with strong evidence
and leaves ambiguous data as metadata instead of pretending the switch is a
clairvoyant appliance from a vendor brochure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
import re
from typing import Iterable

from sariel.ingest.normalize import (
    acl_endpoint_to_cidr,
    expand_vlan_list,
    interface_ip_to_cidr,
    ip_mask_to_cidr,
    network_from_interface,
    normalize_cidr,
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    slugify,
)


@dataclass(frozen=True)
class SwitchTarget:
    """A switch to collect from."""

    name: str
    host: str
    vendor: str = "cisco_ios"
    username: str | None = None
    password: str | None = None
    secret: str | None = None
    port: int = 22
    timeout: int = 30


@dataclass
class VlanFact:
    vlan_id: int
    name: str | None = None
    svi_interface: str | None = None
    ip_cidr: str | None = None
    network_cidr: str | None = None
    source: str = "config"


@dataclass
class InterfaceFact:
    name: str
    description: str | None = None
    mode: str | None = None
    access_vlan: int | None = None
    trunk_vlans: list[int] = field(default_factory=list)
    native_vlan: int | None = None
    ip_cidr: str | None = None
    network_cidr: str | None = None
    shutdown: bool = False
    inbound_acl: str | None = None
    outbound_acl: str | None = None
    vrf: str | None = None


@dataclass
class RouteFact:
    destination: str
    next_hop: str | None = None
    interface: str | None = None
    protocol: str = "static"
    distance: int | None = None
    metric: int | None = None
    evidence: str | None = None


@dataclass
class AclRuleFact:
    acl_name: str
    sequence: int | None
    action: str
    protocol: str
    src: str
    dst: str
    src_port: int | None = None
    dst_port: int | None = None
    established: bool = False
    log: bool = False
    remark: str | None = None
    evidence: str | None = None


@dataclass
class SwitchFacts:
    device_name: str
    mgmt_ip: str | None
    vendor: str
    vlans: list[VlanFact] = field(default_factory=list)
    interfaces: list[InterfaceFact] = field(default_factory=list)
    routes: list[RouteFact] = field(default_factory=list)
    acl_rules: list[AclRuleFact] = field(default_factory=list)

    @property
    def routed_networks(self) -> list[str]:
        networks = {v.network_cidr for v in self.vlans if v.network_cidr}
        networks.update(i.network_cidr for i in self.interfaces if i.network_cidr)
        return sorted(n for n in networks if n)


def collect_running_config(target: SwitchTarget) -> str:
    """Collect running configuration with Netmiko.

    Install with: pip install netmiko
    Vendor values should be Netmiko device_type values such as:
    - cisco_ios
    - cisco_nxos
    - aruba_os
    - aruba_osswitch
    - hp_procurve
    """

    try:
        from netmiko import ConnectHandler
    except ImportError as exc:  # pragma: no cover - depends on optional package
        raise RuntimeError(
            "Online switch collection requires netmiko. Install the network extra: "
            "pip install -e '.[network]'"
        ) from exc

    params = {
        "device_type": target.vendor,
        "host": target.host,
        "username": target.username,
        "password": target.password,
        "port": target.port,
        "timeout": target.timeout,
    }
    if target.secret:
        params["secret"] = target.secret

    with ConnectHandler(**params) as conn:  # type: ignore[arg-type]
        if target.secret:
            conn.enable()
        return conn.send_command("show running-config", read_timeout=target.timeout)


def parse_switch_config(device_name: str, mgmt_ip: str | None, vendor: str, config: str) -> SwitchFacts:
    """Parse Cisco IOS/NX-OS and ArubaOS/ProCurve-style switch configs."""

    parser = _ConfigParser(device_name=device_name, mgmt_ip=mgmt_ip, vendor=vendor, config=config)
    return parser.parse()


class _ConfigParser:
    def __init__(self, device_name: str, mgmt_ip: str | None, vendor: str, config: str):
        self.device_name = normalize_hostname(device_name) or device_name
        self.mgmt_ip = normalize_ip(mgmt_ip)
        self.vendor = vendor.lower()
        self.lines = [line.rstrip() for line in config.splitlines()]
        self.vlans: dict[int, VlanFact] = {}
        self.interfaces: dict[str, InterfaceFact] = {}
        self.routes: list[RouteFact] = []
        self.acl_rules: list[AclRuleFact] = []
        self._acl_seq: dict[str, int] = {}

    def parse(self) -> SwitchFacts:
        self._parse_blocks()
        self._parse_global_routes_and_acls()
        self._link_svis_to_vlans()
        return SwitchFacts(
            device_name=self.device_name,
            mgmt_ip=self.mgmt_ip,
            vendor=self.vendor,
            vlans=sorted(self.vlans.values(), key=lambda item: item.vlan_id),
            interfaces=sorted(self.interfaces.values(), key=lambda item: item.name),
            routes=self._dedupe_routes(self.routes),
            acl_rules=self._dedupe_acl_rules(self.acl_rules),
        )

    def _parse_blocks(self) -> None:
        i = 0
        while i < len(self.lines):
            raw = self.lines[i]
            line = raw.strip()
            if not line or line.startswith(("!", "#")):
                i += 1
                continue

            if re.match(r"^vlan\s+\d+", line, re.I):
                i = self._parse_vlan_block(i)
                continue

            if re.match(r"^(interface|int)\s+", line, re.I):
                i = self._parse_interface_block(i)
                continue

            i += 1

    def _parse_vlan_block(self, start: int) -> int:
        line = self.lines[start].strip()
        match = re.match(r"^vlan\s+(\d+)(?:\s+name\s+(.+))?$", line, re.I)
        if not match:
            return start + 1

        vlan_id = int(match.group(1))
        vlan = self.vlans.setdefault(vlan_id, VlanFact(vlan_id=vlan_id))
        if match.group(2):
            vlan.name = match.group(2).strip()

        i = start + 1
        while i < len(self.lines):
            child = self.lines[i]
            stripped = child.strip()
            if self._starts_new_block(child) or stripped in {"!", "exit"}:
                break
            name_match = re.match(r"^(name|description)\s+(.+)$", stripped, re.I)
            if name_match:
                vlan.name = name_match.group(2).strip()
            i += 1
        return i

    def _parse_interface_block(self, start: int) -> int:
        header = self.lines[start].strip()
        name = re.sub(r"^(interface|int)\s+", "", header, flags=re.I).strip()
        intf = self.interfaces.setdefault(name, InterfaceFact(name=name))

        i = start + 1
        while i < len(self.lines):
            child_raw = self.lines[i]
            child = child_raw.strip()
            if self._starts_new_block(child_raw) or child in {"!", "exit"}:
                break
            self._apply_interface_line(intf, child)
            i += 1

        # Aruba configs can express VLAN IP directly under `vlan N` rather than SVI.
        vlan_match = re.match(r"^vlan\s+(\d+)$", name, re.I)
        if vlan_match:
            vlan_id = int(vlan_match.group(1))
            vlan = self.vlans.setdefault(vlan_id, VlanFact(vlan_id=vlan_id))
            vlan.svi_interface = name
            vlan.ip_cidr = intf.ip_cidr
            vlan.network_cidr = intf.network_cidr

        return i

    def _apply_interface_line(self, intf: InterfaceFact, line: str) -> None:
        if not line:
            return

        if line.lower() == "shutdown":
            intf.shutdown = True
            return
        if line.lower() == "no shutdown":
            intf.shutdown = False
            return

        m = re.match(r"^(description|name)\s+(.+)$", line, re.I)
        if m:
            intf.description = m.group(2).strip()
            return

        m = re.match(r"^ip\s+address\s+(.+)$", line, re.I)
        if m:
            value = m.group(1).strip()
            if value.lower().startswith("dhcp"):
                return
            intf.ip_cidr = interface_ip_to_cidr(value)
            intf.network_cidr = network_from_interface(value)
            return

        m = re.match(r"^vrf\s+(?:member|forwarding)\s+(.+)$", line, re.I)
        if m:
            intf.vrf = m.group(1).strip()
            return

        m = re.match(r"^switchport\s+mode\s+(access|trunk|routed)$", line, re.I)
        if m:
            intf.mode = m.group(1).lower()
            return

        m = re.match(r"^switchport\s+access\s+vlan\s+(\d+)$", line, re.I)
        if m:
            intf.access_vlan = int(m.group(1))
            intf.mode = intf.mode or "access"
            self.vlans.setdefault(intf.access_vlan, VlanFact(vlan_id=intf.access_vlan))
            return

        m = re.match(r"^switchport\s+trunk\s+native\s+vlan\s+(\d+)$", line, re.I)
        if m:
            intf.native_vlan = int(m.group(1))
            return

        m = re.match(r"^switchport\s+trunk\s+allowed\s+vlan\s+(.+)$", line, re.I)
        if m:
            intf.trunk_vlans = sorted(set(intf.trunk_vlans) | set(expand_vlan_list(m.group(1))))
            intf.mode = intf.mode or "trunk"
            for vlan_id in intf.trunk_vlans:
                self.vlans.setdefault(vlan_id, VlanFact(vlan_id=vlan_id))
            return

        # Aruba/ProCurve examples: tagged 1/1-1/4, untagged 1/5, ip access-group ACL in
        m = re.match(r"^(tagged|untagged)\s+(.+)$", line, re.I)
        if m:
            intf.mode = "trunk" if m.group(1).lower() == "tagged" else "access"
            return

        m = re.match(r"^(?:ip\s+)?access-group\s+(\S+)\s+(in|out)$", line, re.I)
        if m:
            if m.group(2).lower() == "in":
                intf.inbound_acl = m.group(1)
            else:
                intf.outbound_acl = m.group(1)
            return

        m = re.match(r"^ip\s+access-list\s+(\S+)\s+(in|out)$", line, re.I)
        if m:
            if m.group(2).lower() == "in":
                intf.inbound_acl = m.group(1)
            else:
                intf.outbound_acl = m.group(1)

    def _parse_global_routes_and_acls(self) -> None:
        current_acl: str | None = None
        for raw in self.lines:
            line = raw.strip()
            if not line or line.startswith(("!", "#")):
                continue

            route = self._parse_route_line(line)
            if route:
                self.routes.append(route)
                continue

            acl_header = re.match(r"^ip\s+access-list\s+(?:extended|standard)?\s*(\S+)$", line, re.I)
            if acl_header:
                current_acl = acl_header.group(1)
                continue

            if re.match(r"^(interface|vlan|router)\s+", line, re.I):
                current_acl = None

            named_acl_rule = self._parse_acl_rule_line(current_acl, line) if current_acl else None
            if named_acl_rule:
                self.acl_rules.append(named_acl_rule)
                continue

            numbered_acl = re.match(r"^access-list\s+(\S+)\s+(.+)$", line, re.I)
            if numbered_acl:
                rule = self._parse_acl_rule_line(numbered_acl.group(1), numbered_acl.group(2))
                if rule:
                    self.acl_rules.append(rule)

    def _parse_route_line(self, line: str) -> RouteFact | None:
        # Cisco: ip route 10.0.0.0 255.255.255.0 192.168.1.1
        m = re.match(r"^ip\s+route\s+(?:vrf\s+(\S+)\s+)?(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?", line, re.I)
        if m:
            dest = ip_mask_to_cidr(m.group(2), m.group(3))
            target = m.group(4)
            return RouteFact(
                destination=dest or f"{m.group(2)}/{m.group(3)}",
                next_hop=normalize_ip(target),
                interface=None if normalize_ip(target) else target,
                protocol="static",
                distance=int(m.group(5)) if m.group(5) else None,
                evidence=line,
            )

        # Aruba/ProCurve: ip route 10.0.0.0/24 192.168.1.1
        m = re.match(r"^ip\s+route\s+(\S+/\d+)\s+(\S+)(?:\s+(\d+))?", line, re.I)
        if m:
            target = m.group(2)
            return RouteFact(
                destination=normalize_cidr(m.group(1)) or m.group(1),
                next_hop=normalize_ip(target),
                interface=None if normalize_ip(target) else target,
                protocol="static",
                distance=int(m.group(3)) if m.group(3) else None,
                evidence=line,
            )
        return None

    def _parse_acl_rule_line(self, acl_name: str | None, line: str) -> AclRuleFact | None:
        if not acl_name:
            return None
        tokens = line.split()
        if not tokens:
            return None

        seq: int | None = None
        if tokens[0].isdigit():
            seq = int(tokens.pop(0))

        if not tokens:
            return None

        if tokens[0].lower() == "remark":
            return AclRuleFact(
                acl_name=acl_name,
                sequence=seq,
                action="remark",
                protocol="ip",
                src="0.0.0.0/0",
                dst="0.0.0.0/0",
                remark=" ".join(tokens[1:]),
                evidence=line,
            )

        if tokens[0].lower() not in {"permit", "deny"}:
            return None

        action = tokens[0].lower()
        protocol = normalize_protocol(tokens[1] if len(tokens) > 1 else "ip")
        idx = 2

        # Standard ACLs omit protocol and destination: permit 10.0.0.0 0.0.0.255
        if len(tokens) > 1 and tokens[1].lower() not in {"ip", "tcp", "udp", "icmp", "gre", "esp", "ah"}:
            protocol = "ip"
            idx = 1

        src, idx = acl_endpoint_to_cidr(tokens, idx)
        src_port, idx = self._parse_acl_port(tokens, idx)
        dst, idx = acl_endpoint_to_cidr(tokens, idx)
        dst_port, idx = self._parse_acl_port(tokens, idx)

        if not dst:
            dst = "0.0.0.0/0"

        return AclRuleFact(
            acl_name=acl_name,
            sequence=seq if seq is not None else self._next_acl_sequence(acl_name),
            action=action,
            protocol=protocol,
            src=src or "0.0.0.0/0",
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            established="established" in [t.lower() for t in tokens[idx:]],
            log="log" in [t.lower() for t in tokens[idx:]],
            evidence=line,
        )

    def _parse_acl_port(self, tokens: list[str], idx: int) -> tuple[int | None, int]:
        if idx >= len(tokens):
            return None, idx
        op = tokens[idx].lower()
        if op in {"eq", "gt", "lt", "neq"} and idx + 1 < len(tokens):
            return normalize_port(tokens[idx + 1]), idx + 2
        if op == "range" and idx + 2 < len(tokens):
            # Store the lower bound for graph filtering; evidence keeps the original range.
            return normalize_port(tokens[idx + 1]), idx + 3
        return None, idx

    def _next_acl_sequence(self, acl_name: str) -> int:
        self._acl_seq[acl_name] = self._acl_seq.get(acl_name, 0) + 10
        return self._acl_seq[acl_name]

    def _link_svis_to_vlans(self) -> None:
        for intf in self.interfaces.values():
            match = re.match(r"^(?:vlan|vlanif)(\d+)$", intf.name.replace(" ", ""), re.I)
            if not match:
                continue
            vlan_id = int(match.group(1))
            vlan = self.vlans.setdefault(vlan_id, VlanFact(vlan_id=vlan_id))
            vlan.svi_interface = intf.name
            vlan.ip_cidr = intf.ip_cidr
            vlan.network_cidr = intf.network_cidr

    def _starts_new_block(self, raw_line: str) -> bool:
        if not raw_line or raw_line.startswith((" ", "\t")):
            return False
        stripped = raw_line.strip()
        return bool(re.match(r"^(interface|int|vlan|router|ip\s+access-list)\s+", stripped, re.I))

    @staticmethod
    def _dedupe_routes(routes: Iterable[RouteFact]) -> list[RouteFact]:
        seen = set()
        out = []
        for route in routes:
            key = (route.destination, route.next_hop, route.interface, route.protocol)
            if key in seen:
                continue
            seen.add(key)
            out.append(route)
        return out

    @staticmethod
    def _dedupe_acl_rules(rules: Iterable[AclRuleFact]) -> list[AclRuleFact]:
        seen = set()
        out = []
        for rule in rules:
            key = (rule.acl_name, rule.sequence, rule.action, rule.protocol, rule.src, rule.dst, rule.dst_port)
            if key in seen:
                continue
            seen.add(key)
            out.append(rule)
        return out


def switch_id(device_name: str) -> str:
    return f"switch:{slugify(device_name)}"


def vlan_id(device_name: str, vlan: int) -> str:
    return f"switch:{slugify(device_name)}:vlan:{vlan}"


def interface_id(device_name: str, interface: str) -> str:
    return f"switch:{slugify(device_name)}:interface:{slugify(interface)}"


def subnet_id(cidr: str) -> str:
    return f"subnet:{slugify(cidr)}"


def route_id(device_name: str, destination: str, next_hop: str | None, interface: str | None) -> str:
    return f"route:{slugify(device_name)}:{slugify(destination)}:{slugify(next_hop or interface or 'unknown')}"

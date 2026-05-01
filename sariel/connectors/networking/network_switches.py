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
from ipaddress import ip_address, ip_interface, ip_network
import re
import json
import os
from urllib.parse import unquote
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
    password_env: str | None = None
    secret: str | None = None
    commands: list[str] | None = None
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

    password = target.password
    if not password and target.password_env:
        password = os.getenv(target.password_env)

    if not password:
        raise ValueError(
            f"No password found for switch {target.name}. "
            f"Set password or password_env in inventory."
        )

    params = {
        "device_type": target.vendor,
        "host": target.host,
        "username": target.username,
        "password": password,
        "port": target.port,
        "use_keys": False,
        "allow_agent": False,
        "look_for_keys": False,
        "timeout": 60,
        "conn_timeout": 30,
        "banner_timeout": 30,
        "auth_timeout": 30,
        "fast_cli": False,
    }
    if target.secret:
        params["secret"] = target.secret

    with ConnectHandler(**params) as conn:  # type: ignore[arg-type]
        if target.secret:
            conn.enable()
        return conn.send_command("show running-config", read_timeout=target.timeout)


def parse_switch_config(device_name: str, mgmt_ip: str | None, vendor: str, config: str) -> SwitchFacts:
    """Parse Cisco IOS/NX-OS CLI, Aruba CX CLI, or Aruba CX JSON startup config dumps."""

    stripped = config.lstrip()
    if stripped.startswith("{"):
        try:
            return _parse_aruba_cx_json_config(device_name, mgmt_ip, vendor, config)
        except json.JSONDecodeError:
            pass

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

        # Aruba CX CLI: vlan access 10 / vlan trunk native 10 / vlan trunk allowed 10,20-25
        m = re.match(r"^vlan\s+access\s+(\d+)$", line, re.I)
        if m:
            intf.access_vlan = int(m.group(1))
            intf.mode = "access"
            self.vlans.setdefault(intf.access_vlan, VlanFact(vlan_id=intf.access_vlan))
            return

        m = re.match(r"^vlan\s+trunk\s+native\s+(\d+)$", line, re.I)
        if m:
            intf.native_vlan = int(m.group(1))
            intf.mode = intf.mode or "trunk"
            self.vlans.setdefault(intf.native_vlan, VlanFact(vlan_id=intf.native_vlan))
            return

        m = re.match(r"^vlan\s+trunk\s+allowed\s+(?:all|(.+))$", line, re.I)
        if m:
            if m.group(1):
                intf.trunk_vlans = sorted(set(intf.trunk_vlans) | set(expand_vlan_list(m.group(1))))
                for vlan_id in intf.trunk_vlans:
                    self.vlans.setdefault(vlan_id, VlanFact(vlan_id=vlan_id))
            intf.mode = "trunk"
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

        # Aruba CX: apply access-list ip ACL_NAME in|out
        m = re.match(r"^apply\s+access-list\s+(?:ip|ipv4)?\s*(\S+)\s+(in|out)$", line, re.I)
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



def _parse_aruba_cx_json_config(device_name: str, mgmt_ip: str | None, vendor: str, config: str) -> SwitchFacts:
    """Parse Aruba CX JSON-style startup config exports.

    Some Aruba CX backup/export flows do not produce CLI text. They produce a
    structured JSON object with top-level sections such as Interface, VLAN, VRF,
    ACL, Port, and LAG. This parser extracts the network facts Sariel needs from
    that format.
    """

    data = json.loads(config)
    norm_name = normalize_hostname(device_name) or device_name
    norm_mgmt = normalize_ip(mgmt_ip)

    vlans: dict[int, VlanFact] = {}
    interfaces: dict[str, InterfaceFact] = {}
    routes: list[RouteFact] = []
    acl_rules: list[AclRuleFact] = []

    def get_intf(name: str) -> InterfaceFact:
        clean = _clean_aruba_name(name)
        return interfaces.setdefault(clean, InterfaceFact(name=clean))

    # VLAN inventory. Aruba JSON often stores subnet intent in the VLAN name,
    # which is useful evidence, but we only treat routed interface IPs as L3 facts.
    for vlan_key, vlan_obj in _dict_items(data.get("VLAN")):
        vid = _int_or_none(vlan_obj.get("id") if isinstance(vlan_obj, dict) else vlan_key)
        if vid is None:
            continue
        name = _first_text(vlan_obj.get("name"), vlan_obj.get("description")) if isinstance(vlan_obj, dict) else None
        vlans[vid] = VlanFact(vlan_id=vid, name=name, source="aruba_cx_json")

    # Interface section has physical ports and routed VLAN interfaces.
    for intf_key, intf_obj in _dict_items(data.get("Interface")):
        if not isinstance(intf_obj, dict):
            continue
        name = _clean_aruba_name(_first_text(intf_obj.get("name"), intf_key) or intf_key)
        intf = get_intf(name)
        intf.description = _first_text(intf_obj.get("description"), intf.description)

        user_cfg = intf_obj.get("user_config") if isinstance(intf_obj.get("user_config"), dict) else {}
        other_cfg = intf_obj.get("other_config") if isinstance(intf_obj.get("other_config"), dict) else {}
        admin = str(user_cfg.get("admin", "")).lower()
        if admin == "down":
            intf.shutdown = True
        elif admin == "up":
            intf.shutdown = False

        # Access VLANs can appear in a few shapes depending on export source.
        access_vlan = _int_or_none(_first_present_deep(intf_obj, [
            "vlan_tag", "access_vlan", "access-vlan", "vlan_access", "native_vlan",
        ]))
        if access_vlan:
            intf.access_vlan = access_vlan
            intf.mode = "access"
            vlans.setdefault(access_vlan, VlanFact(vlan_id=access_vlan, source="aruba_cx_json"))

        # Trunk VLANs may be listed directly or hidden in other_config.
        trunk_values = []
        for key in ("trunk_vlans", "trunk-vlans", "allowed_vlans", "allowed-vlans", "vlan_trunks", "vlan-trunks"):
            value = intf_obj.get(key) or other_cfg.get(key)
            if value:
                trunk_values.append(value)
        for value in trunk_values:
            intf.trunk_vlans = sorted(set(intf.trunk_vlans) | set(_expand_aruba_json_vlans(value)))
        if intf.trunk_vlans:
            intf.mode = "trunk"
            for vid in intf.trunk_vlans:
                vlans.setdefault(vid, VlanFact(vlan_id=vid, source="aruba_cx_json"))

        if "lacp-aggregation-key" in other_cfg:
            intf.mode = intf.mode or "lag-member"

        # Routed interface addresses. These names commonly show up as vlan14.
        ip_value = _extract_interface_ip(intf_obj)
        if ip_value:
            intf.ip_cidr = interface_ip_to_cidr(ip_value)
            intf.network_cidr = network_from_interface(ip_value)

        vrf = _first_text(intf_obj.get("vrf"), intf_obj.get("vrf_name"), intf_obj.get("vrf-name"))
        if vrf:
            intf.vrf = vrf

        if _is_vlan_interface(name):
            vid = _vlan_id_from_name(name)
            if vid is not None:
                vlan = vlans.setdefault(vid, VlanFact(vlan_id=vid, source="aruba_cx_json"))
                vlan.svi_interface = name
                if intf.ip_cidr:
                    vlan.ip_cidr = intf.ip_cidr
                    vlan.network_cidr = intf.network_cidr

        inbound, outbound = _extract_interface_acls(intf_obj)
        intf.inbound_acl = inbound or intf.inbound_acl
        intf.outbound_acl = outbound or intf.outbound_acl

    # Some exports include a Port section with VLAN attachment data; merge it.
    for port_key, port_obj in _dict_items(data.get("Port")):
        if not isinstance(port_obj, dict):
            continue
        name = _clean_aruba_name(_first_text(port_obj.get("name"), port_key) or port_key)
        intf = get_intf(name)
        intf.description = _first_text(port_obj.get("description"), intf.description)
        access_vlan = _int_or_none(_first_present_deep(port_obj, ["vlan_tag", "access_vlan", "access-vlan", "native_vlan"]))
        if access_vlan:
            intf.access_vlan = access_vlan
            intf.mode = "access"
            vlans.setdefault(access_vlan, VlanFact(vlan_id=access_vlan, source="aruba_cx_json"))

    # Static routes under each VRF.
    for vrf_name, vrf_obj in _dict_items(data.get("VRF")):
        if not isinstance(vrf_obj, dict):
            continue
        for _, route_obj in _dict_items(vrf_obj.get("Static_Route")):
            if not isinstance(route_obj, dict):
                continue
            prefix = normalize_cidr(route_obj.get("prefix")) or route_obj.get("prefix")
            if not prefix:
                continue
            nexthops = route_obj.get("static_nexthops")
            if isinstance(nexthops, dict):
                for _, hop in _dict_items(nexthops):
                    if not isinstance(hop, dict):
                        continue
                    routes.append(RouteFact(
                        destination=prefix,
                        next_hop=normalize_ip(hop.get("ip_address")),
                        interface=_clean_aruba_name(hop.get("port")) if hop.get("port") else None,
                        protocol="static",
                        distance=_int_or_none(hop.get("distance")),
                        evidence=f"VRF {vrf_name} static route {prefix}",
                    ))
            else:
                routes.append(RouteFact(destination=prefix, protocol="static", evidence=f"VRF {vrf_name} static route {prefix}"))

        # OSPF interfaces prove routed networks participate in L3 reachability,
        # even if the static config dump omits every learned route.
        ospf = vrf_obj.get("ospf_routers")
        if isinstance(ospf, dict):
            for _, router in _dict_items(ospf):
                if not isinstance(router, dict):
                    continue
                for area_id, area in _dict_items(router.get("areas")):
                    if not isinstance(area, dict):
                        continue
                    for _, ospf_if in _dict_items(area.get("ospf_interfaces")):
                        if not isinstance(ospf_if, dict):
                            continue
                        port = _clean_aruba_name(ospf_if.get("port")) if ospf_if.get("port") else None
                        if port and port in interfaces:
                            interfaces[port].vrf = interfaces[port].vrf or str(vrf_name)

    # Aruba ACL JSON varies by version. Recursively find ACL-ish sections and parse rules conservatively.
    _extract_aruba_json_acls(data, acl_rules)

    # Last pass: infer VLAN SVI networks from VLAN names such as "10.100.14.0/24 - Sheriff".
    for vlan in vlans.values():
        if not vlan.network_cidr and vlan.name:
            inferred = _first_cidr_in_text(vlan.name)
            if inferred:
                vlan.network_cidr = inferred

    return SwitchFacts(
        device_name=norm_name,
        mgmt_ip=norm_mgmt,
        vendor=vendor.lower(),
        vlans=sorted(vlans.values(), key=lambda item: item.vlan_id),
        interfaces=sorted(interfaces.values(), key=lambda item: item.name),
        routes=_ConfigParser._dedupe_routes(routes),
        acl_rules=_ConfigParser._dedupe_acl_rules(acl_rules),
    )


def _dict_items(value):
    return value.items() if isinstance(value, dict) else []


def _clean_aruba_name(value) -> str:
    text = str(value or "").strip()
    text = unquote(text)
    text = text.replace("%2F", "/").replace("%2f", "/")
    return text


def _int_or_none(value) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_text(*values) -> str | None:
    for value in values:
        if value is not None and value != "":
            return str(value)
    return None


def _first_present_deep(obj: dict, keys: list[str]):
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return None


def _is_vlan_interface(name: str) -> bool:
    return bool(re.match(r"^vlan\s*\d+$", name.replace(" ", ""), re.I))


def _vlan_id_from_name(name: str) -> int | None:
    m = re.match(r"^vlan\s*(\d+)$", name.replace(" ", ""), re.I)
    return int(m.group(1)) if m else None


def _extract_interface_ip(obj: dict) -> str | None:
    for key in ("ip4_address", "ipv4_address", "ip_address", "address"):
        value = obj.get(key)
        if isinstance(value, str) and interface_ip_to_cidr(value):
            return value
    ip4 = obj.get("ip4_addresses") or obj.get("ipv4_addresses") or obj.get("ip_addresses")
    if isinstance(ip4, dict):
        for _, address_obj in _dict_items(ip4):
            if isinstance(address_obj, dict):
                ip = _first_text(address_obj.get("ip_address"), address_obj.get("address"))
                prefix = _first_text(address_obj.get("prefix_length"), address_obj.get("prefix"), address_obj.get("mask"))
                if ip and prefix:
                    value = f"{ip}/{prefix}" if str(prefix).isdigit() else f"{ip} {prefix}"
                    if interface_ip_to_cidr(value):
                        return value
            elif isinstance(address_obj, str) and interface_ip_to_cidr(address_obj):
                return address_obj
    return None


def _expand_aruba_json_vlans(value) -> list[int]:
    if isinstance(value, list):
        out: set[int] = set()
        for item in value:
            out.update(_expand_aruba_json_vlans(item))
        return sorted(out)
    if isinstance(value, dict):
        out: set[int] = set()
        for key, item in value.items():
            out.update(_expand_aruba_json_vlans(item if item not in (True, False, None) else key))
        return sorted(out)
    return expand_vlan_list(str(value))


def _extract_interface_acls(obj: dict) -> tuple[str | None, str | None]:
    inbound = None
    outbound = None
    for key, value in obj.items():
        low = str(key).lower()
        if "acl" not in low and "access" not in low:
            continue
        if isinstance(value, str):
            if "in" in low or "ingress" in low:
                inbound = value
            elif "out" in low or "egress" in low:
                outbound = value
        elif isinstance(value, dict):
            inbound = inbound or _first_text(value.get("in"), value.get("inbound"), value.get("ingress"))
            outbound = outbound or _first_text(value.get("out"), value.get("outbound"), value.get("egress"))
    return inbound, outbound


def _first_cidr_in_text(value: str) -> str | None:
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", value or "")
    return normalize_cidr(m.group(0)) if m else None


def _extract_aruba_json_acls(data, out: list[AclRuleFact]) -> None:
    def walk(node, path: list[str]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                low = str(key).lower()
                if low in {"acl", "acls", "access_list", "access-list", "access_list_ip", "access-list-ip"} or "access_list" in low or "access-list" in low:
                    _parse_acl_container(str(key), value, out)
                walk(value, path + [str(key)])
        elif isinstance(node, list):
            for item in node:
                walk(item, path)
    walk(data, [])


def _parse_acl_container(name_hint: str, value, out: list[AclRuleFact]) -> None:
    if isinstance(value, dict):
        for acl_name, acl_obj in value.items():
            if isinstance(acl_obj, dict):
                rules = acl_obj.get("aces") or acl_obj.get("rules") or acl_obj.get("entries") or acl_obj.get("cfg_aces") or acl_obj
                _parse_acl_rules(str(acl_name), rules, out)
            elif isinstance(acl_obj, list):
                _parse_acl_rules(str(acl_name), acl_obj, out)
    elif isinstance(value, list):
        _parse_acl_rules(name_hint, value, out)


def _parse_acl_rules(acl_name: str, rules, out: list[AclRuleFact]) -> None:
    if isinstance(rules, dict):
        iterable = list(rules.items())
    elif isinstance(rules, list):
        iterable = [(None, item) for item in rules]
    else:
        return
    for seq_key, rule in iterable:
        if isinstance(rule, str):
            parsed = _ConfigParser("tmp", None, "aruba", "")._parse_acl_rule_line(acl_name, rule)
            if parsed:
                out.append(parsed)
            continue
        if not isinstance(rule, dict):
            continue
        seq = _int_or_none(rule.get("sequence") or rule.get("seq") or rule.get("position") or seq_key)
        action = str(rule.get("action") or rule.get("permit-deny") or rule.get("type") or "permit").lower()
        if action in {"allow", "accept"}:
            action = "permit"
        if action not in {"permit", "deny"}:
            continue
        protocol = normalize_protocol(rule.get("protocol") or rule.get("proto") or "ip")
        src = _normalize_acl_json_endpoint(rule.get("src") or rule.get("source") or rule.get("source_ip") or rule.get("src_ip") or "any")
        dst = _normalize_acl_json_endpoint(rule.get("dst") or rule.get("destination") or rule.get("destination_ip") or rule.get("dst_ip") or "any")
        out.append(AclRuleFact(
            acl_name=acl_name,
            sequence=seq,
            action=action,
            protocol=protocol,
            src=src,
            dst=dst,
            src_port=normalize_port(rule.get("src_port") or rule.get("source_port")),
            dst_port=normalize_port(rule.get("dst_port") or rule.get("destination_port") or rule.get("port")),
            log=bool(rule.get("log", False)),
            remark=_first_text(rule.get("comment"), rule.get("remark")),
            evidence=json.dumps(rule, sort_keys=True)[:500],
        ))


def _normalize_acl_json_endpoint(value) -> str:
    if value in (None, "", "any"):
        return "0.0.0.0/0"
    if isinstance(value, dict):
        ip = _first_text(value.get("ip"), value.get("address"), value.get("host"))
        if ip:
            prefix = _first_text(value.get("prefix"), value.get("prefix_length"), value.get("mask"))
            if prefix:
                cidr = normalize_cidr(f"{ip}/{prefix}") if str(prefix).isdigit() else ip_mask_to_cidr(ip, prefix)
                if cidr:
                    return cidr
            norm_ip = normalize_ip(ip)
            if norm_ip:
                return f"{norm_ip}/32"
        network = _first_text(value.get("network"), value.get("cidr"), value.get("prefix"))
        if network:
            return normalize_cidr(network) or network
    text = str(value)
    if text.lower() == "any":
        return "0.0.0.0/0"
    return normalize_cidr(text) or (f"{normalize_ip(text)}/32" if normalize_ip(text) else text)

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

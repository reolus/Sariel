"""Normalization helpers for Sariel ingestion.

This module provides small, dependency-light helpers used by on-prem connectors
before facts are written into Neo4j. The goal is not to be clever. The goal is
to make every connector emit consistent identifiers, CIDRs, ports, protocols,
and confidence values so the graph does not slowly become a haunted landfill.

Primary uses:
- Normalize hostnames, FQDNs, IP addresses, MAC addresses, ports, and protocols.
- Convert IP + mask pairs into CIDR notation.
- Convert Cisco wildcard masks into CIDR notation.
- Normalize endpoint records into stable Sariel asset identifiers.
- Normalize reachability edge payloads for `CAN_REACH`.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from ipaddress import ip_address, ip_interface, ip_network, IPv4Network, IPv6Network
import re
from typing import Any, Iterable


Network = IPv4Network | IPv6Network


COMMON_SERVICE_PORTS: dict[str, int] = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "dns": 53,
    "domain": 53,
    "http": 80,
    "kerberos": 88,
    "pop3": 110,
    "ntp": 123,
    "imap": 143,
    "snmp": 161,
    "ldap": 389,
    "https": 443,
    "microsoft-ds": 445,
    "smb": 445,
    "ldaps": 636,
    "mssql": 1433,
    "oracle": 1521,
    "mysql": 3306,
    "rdp": 3389,
    "postgres": 5432,
    "winrm": 5985,
    "winrm-ssl": 5986,
}

COMMON_PROTOCOLS: set[str] = {
    "ip",
    "icmp",
    "tcp",
    "udp",
    "gre",
    "esp",
    "ah",
    "ospf",
    "eigrp",
}


@dataclass(frozen=True)
class NormalizedAsset:
    """Connector-neutral asset identity."""

    key: str
    hostname: str | None = None
    fqdn: str | None = None
    ip: str | None = None
    mac: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NormalizedReachability:
    """Normalized payload for a Sariel CAN_REACH edge."""

    src: str
    dst: str
    protocol: str = "ip"
    port: int | None = None
    action: str = "allow"
    confidence: float = 0.5
    source: str | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_hostname(value: str | None) -> str | None:
    """Normalize a short hostname.

    Keeps only the first DNS label, lowercases it, and strips surrounding noise.
    """
    if not value:
        return None

    cleaned = value.strip().strip(".").lower()
    if not cleaned:
        return None

    # Remove common prompt/config suffixes.
    cleaned = cleaned.replace("\\", "/").split("/")[-1]
    cleaned = cleaned.split()[0]

    return cleaned.split(".")[0] or None


def normalize_fqdn(value: str | None) -> str | None:
    """Normalize an FQDN-like string."""
    if not value:
        return None

    cleaned = value.strip().strip(".").lower()
    if not cleaned or "." not in cleaned:
        return None

    if not re.match(r"^[a-z0-9_.-]+$", cleaned):
        return None

    return cleaned


def normalize_ip(value: str | None) -> str | None:
    """Return a canonical IP string, or None when invalid."""
    if not value:
        return None

    cleaned = value.strip()
    try:
        return str(ip_address(cleaned))
    except ValueError:
        return None


def normalize_mac(value: str | None) -> str | None:
    """Normalize MAC addresses to aa:bb:cc:dd:ee:ff."""
    if not value:
        return None

    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(cleaned) != 12:
        return None

    return ":".join(cleaned[i : i + 2].lower() for i in range(0, 12, 2))


def normalize_protocol(value: str | None) -> str:
    """Normalize IP protocol names used by ACLs and reachability edges."""
    if not value:
        return "ip"

    cleaned = value.strip().lower()
    aliases = {
        "any": "ip",
        "ipv4": "ip",
        "6": "tcp",
        "17": "udp",
        "1": "icmp",
    }
    cleaned = aliases.get(cleaned, cleaned)

    if cleaned in COMMON_PROTOCOLS:
        return cleaned

    # Preserve unknown protocols rather than lying. How mature of us.
    return cleaned


def normalize_port(value: str | int | None) -> int | None:
    """Normalize a service name or port value."""
    if value is None or value == "":
        return None

    if isinstance(value, int):
        return value if 0 <= value <= 65535 else None

    cleaned = str(value).strip().lower()
    if cleaned.isdigit():
        port = int(cleaned)
        return port if 0 <= port <= 65535 else None

    return COMMON_SERVICE_PORTS.get(cleaned)


def normalize_cidr(value: str | None, strict: bool = False) -> str | None:
    """Normalize CIDR or IP/interface notation to a network CIDR string."""
    if not value:
        return None

    cleaned = value.strip()
    try:
        if "/" in cleaned:
            return str(ip_network(cleaned, strict=strict))
        ip = ip_address(cleaned)
        suffix = 32 if ip.version == 4 else 128
        return str(ip_network(f"{ip}/{suffix}", strict=False))
    except ValueError:
        return None


def ip_mask_to_cidr(ip: str | None, mask: str | None) -> str | None:
    """Convert IP + subnet mask into CIDR notation."""
    if not ip or not mask:
        return None

    try:
        return str(ip_network(f"{ip.strip()}/{mask.strip()}", strict=False))
    except ValueError:
        return None


def interface_ip_to_cidr(value: str | None) -> str | None:
    """Normalize interface IP forms into CIDR.

    Supports:
    - 10.1.2.1/24
    - 10.1.2.1 255.255.255.0

    Returns the interface address with prefix, not the network.
    """
    if not value:
        return None

    cleaned = value.strip()
    if cleaned.lower().startswith("dhcp"):
        return None

    parts = cleaned.split()
    try:
        if len(parts) == 1 and "/" in parts[0]:
            return str(ip_interface(parts[0]))
        if len(parts) >= 2:
            return str(ip_interface(f"{parts[0]}/{parts[1]}"))
    except ValueError:
        return None

    return None


def network_from_interface(value: str | None) -> str | None:
    """Return network CIDR from interface IP notation."""
    cidr = interface_ip_to_cidr(value)
    if not cidr:
        return None

    try:
        return str(ip_interface(cidr).network)
    except ValueError:
        return None


def wildcard_to_netmask(wildcard: str | None) -> str | None:
    """Convert Cisco wildcard mask to subnet mask.

    Example:
        0.0.0.255 -> 255.255.255.0
    """
    if not wildcard:
        return None

    try:
        octets = [int(part) for part in wildcard.strip().split(".")]
    except ValueError:
        return None

    if len(octets) != 4 or any(part < 0 or part > 255 for part in octets):
        return None

    return ".".join(str(255 - part) for part in octets)


def wildcard_to_cidr(ip: str | None, wildcard: str | None) -> str | None:
    """Convert Cisco ACL IP + wildcard mask into CIDR notation."""
    if not ip or not wildcard:
        return None

    mask = wildcard_to_netmask(wildcard)
    if not mask:
        return None

    return ip_mask_to_cidr(ip, mask)


def acl_endpoint_to_cidr(tokens: list[str], start_index: int = 0) -> tuple[str | None, int]:
    """Parse a Cisco/Aruba ACL endpoint from tokenized config.

    Returns:
        (cidr, next_index)

    Supports:
    - any
    - host 10.1.1.1
    - 10.1.1.0 0.0.0.255
    - 10.1.1.0 255.255.255.0
    """
    idx = start_index
    if idx >= len(tokens):
        return None, idx

    token = tokens[idx].lower()

    if token == "any":
        return "0.0.0.0/0", idx + 1

    if token == "host" and idx + 1 < len(tokens):
        host_ip = normalize_ip(tokens[idx + 1])
        return (f"{host_ip}/32" if host_ip else None), idx + 2

    if idx + 1 < len(tokens):
        base_ip = normalize_ip(tokens[idx])
        mask_or_wildcard = tokens[idx + 1]
        if base_ip and normalize_ip(mask_or_wildcard):
            # Cisco ACLs usually use wildcard masks. If the first octet is 0,
            # treat it as wildcard. If it resembles a subnet mask, use it.
            first_octet = int(mask_or_wildcard.split(".")[0])
            if first_octet == 0:
                return wildcard_to_cidr(base_ip, mask_or_wildcard), idx + 2
            return ip_mask_to_cidr(base_ip, mask_or_wildcard), idx + 2

    single_ip = normalize_ip(tokens[idx])
    if single_ip:
        return f"{single_ip}/32", idx + 1

    return tokens[idx], idx + 1


def expand_vlan_list(value: str | None) -> list[int]:
    """Expand VLAN expressions like '10,20,30-32' into sorted integers."""
    if not value:
        return []

    cleaned = (
        value.lower()
        .replace("add", "")
        .replace("vlan", "")
        .replace("allowed", "")
        .replace(" ", "")
    )

    if cleaned in {"all", "none"}:
        return []

    vlans: set[int] = set()
    for part in cleaned.split(","):
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            if start_text.isdigit() and end_text.isdigit():
                start, end = int(start_text), int(end_text)
                if 1 <= start <= end <= 4094:
                    vlans.update(range(start, end + 1))
        elif part.isdigit():
            vlan = int(part)
            if 1 <= vlan <= 4094:
                vlans.add(vlan)

    return sorted(vlans)


def stable_asset_key(
    *,
    hostname: str | None = None,
    fqdn: str | None = None,
    ip: str | None = None,
    mac: str | None = None,
    source: str | None = None,
) -> str:
    """Create a stable connector-neutral asset key.

    Preference order:
    1. MAC address
    2. FQDN
    3. Hostname
    4. IP address
    5. Source-local fallback
    """
    norm_mac = normalize_mac(mac)
    if norm_mac:
        return f"mac:{norm_mac}"

    norm_fqdn = normalize_fqdn(fqdn)
    if norm_fqdn:
        return f"fqdn:{norm_fqdn}"

    norm_host = normalize_hostname(hostname)
    if norm_host:
        return f"host:{norm_host}"

    norm_ip = normalize_ip(ip)
    if norm_ip:
        return f"ip:{norm_ip}"

    fallback = source or "unknown"
    return f"unknown:{slugify(fallback)}"


def normalize_asset(
    *,
    hostname: str | None = None,
    fqdn: str | None = None,
    ip: str | None = None,
    mac: str | None = None,
    source: str | None = None,
) -> NormalizedAsset:
    """Return a normalized asset record."""
    return NormalizedAsset(
        key=stable_asset_key(hostname=hostname, fqdn=fqdn, ip=ip, mac=mac, source=source),
        hostname=normalize_hostname(hostname),
        fqdn=normalize_fqdn(fqdn),
        ip=normalize_ip(ip),
        mac=normalize_mac(mac),
        source=source,
    )


def normalize_reachability(
    *,
    src: str,
    dst: str,
    protocol: str | None = "ip",
    port: str | int | None = None,
    action: str | None = "allow",
    confidence: float | int | None = 0.5,
    source: str | None = None,
    evidence: str | None = None,
) -> NormalizedReachability:
    """Normalize data for a CAN_REACH-style relationship."""
    norm_action = (action or "allow").strip().lower()
    if norm_action not in {"allow", "permit", "deny", "block"}:
        norm_action = "allow"

    if norm_action == "permit":
        norm_action = "allow"
    elif norm_action == "block":
        norm_action = "deny"

    try:
        norm_confidence = float(confidence if confidence is not None else 0.5)
    except (TypeError, ValueError):
        norm_confidence = 0.5

    norm_confidence = max(0.0, min(1.0, norm_confidence))

    return NormalizedReachability(
        src=src,
        dst=dst,
        protocol=normalize_protocol(protocol),
        port=normalize_port(port),
        action=norm_action,
        confidence=norm_confidence,
        source=source,
        evidence=evidence,
    )


def slugify(value: str | None) -> str:
    """Create a boring stable slug. Boring is good. Boring ships."""
    if not value:
        return "unknown"

    cleaned = value.strip().lower()
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "-", cleaned)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    return cleaned or "unknown"


def first_present(*values: Any) -> Any:
    """Return the first non-empty value."""
    for value in values:
        if value is not None and value != "":
            return value
    return None


def dedupe_dicts(items: Iterable[dict[str, Any]], keys: Iterable[str]) -> list[dict[str, Any]]:
    """Dedupe dictionaries by a list of keys while preserving order."""
    seen: set[tuple[Any, ...]] = set()
    result: list[dict[str, Any]] = []
    key_list = list(keys)

    for item in items:
        marker = tuple(item.get(key) for key in key_list)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)

    return result


def network_contains_ip(network_cidr: str | None, ip: str | None) -> bool:
    """Return True when IP belongs to network CIDR."""
    norm_network = normalize_cidr(network_cidr)
    norm_ip = normalize_ip(ip)

    if not norm_network or not norm_ip:
        return False

    try:
        return ip_address(norm_ip) in ip_network(norm_network, strict=False)
    except ValueError:
        return False


def most_specific_network(ip: str | None, networks: Iterable[str]) -> str | None:
    """Return the most specific network containing the given IP."""
    norm_ip = normalize_ip(ip)
    if not norm_ip:
        return None

    candidates: list[Network] = []
    for network in networks:
        norm_network = normalize_cidr(network)
        if not norm_network:
            continue

        parsed = ip_network(norm_network, strict=False)
        if ip_address(norm_ip) in parsed:
            candidates.append(parsed)

    if not candidates:
        return None

    return str(sorted(candidates, key=lambda item: item.prefixlen, reverse=True)[0])


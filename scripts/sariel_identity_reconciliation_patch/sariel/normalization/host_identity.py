"""Host identity normalization helpers for Sariel.

These helpers intentionally avoid any Neo4j-specific code so connectors,
writers, and repair jobs can use the same identity rules.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

_DOMAIN_SUFFIXES = (
    ".local",
)


def normalize_hostname(value: Any) -> str:
    """Return a stable lowercase short hostname key.

    Examples:
      BL-DC-04 -> bl-dc-04
      BL-DC-04.POTTCOUNTY-IA.NET -> bl-dc-04
    """
    if value is None:
        return ""
    text = str(value).strip().strip(". ")
    if not text:
        return ""

    text = text.lower()
    text = re.sub(r"^https?://", "", text)
    text = text.split("/")[0]
    text = text.split(":")[0] if not _looks_like_ipv6(text) else text

    if _looks_like_ip(text):
        return ""

    # Prefer the short host portion. This is what lets BL-DC-04 match
    # BL-DC-04.pottcounty-ia.net and other scanner-specific forms.
    short = text.split(".")[0]
    short = re.sub(r"[^a-z0-9_-]", "", short)
    return short


def normalize_fqdn(value: Any) -> str:
    """Return a stable lowercase FQDN key when the value looks like an FQDN."""
    if value is None:
        return ""
    text = str(value).strip().strip(". ").lower()
    if not text or _looks_like_ip(text):
        return ""
    text = re.sub(r"^https?://", "", text).split("/")[0]
    if "." not in text:
        return ""
    return re.sub(r"[^a-z0-9_.-]", "", text)


def normalize_ip(value: Any) -> str:
    """Return a canonical IP string, or empty string if the value is not an IP."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    # Handle occasional CIDR values by keeping the host/network address.
    try:
        if "/" in text:
            return str(ipaddress.ip_interface(text).ip)
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def compute_host_identity(properties: dict[str, Any], fallback_label: str = "") -> dict[str, str]:
    """Compute normalized host identity fields from common asset properties."""
    hostname_candidates = [
        properties.get("hostname"),
        properties.get("host_name"),
        properties.get("name"),
        properties.get("dns_name"),
        properties.get("netbios"),
        properties.get("netbios_name"),
        properties.get("fqdn"),
        properties.get("label"),
        fallback_label,
    ]
    fqdn_candidates = [
        properties.get("fqdn"),
        properties.get("dns_name"),
        properties.get("hostname"),
        properties.get("label"),
        fallback_label,
    ]
    ip_candidates = [
        properties.get("private_ip"),
        properties.get("ip"),
        properties.get("ip_address"),
        properties.get("host_ip"),
        properties.get("address"),
        properties.get("management_ip"),
        properties.get("label"),
        fallback_label,
    ]

    hostname_key = next((normalize_hostname(v) for v in hostname_candidates if normalize_hostname(v)), "")
    fqdn_key = next((normalize_fqdn(v) for v in fqdn_candidates if normalize_fqdn(v)), "")
    ip_key = next((normalize_ip(v) for v in ip_candidates if normalize_ip(v)), "")

    return {
        "hostname_key": hostname_key,
        "fqdn_key": fqdn_key,
        "ip_key": ip_key,
    }


def _looks_like_ip(text: str) -> bool:
    return bool(normalize_ip(text))


def _looks_like_ipv6(text: str) -> bool:
    return ":" in text and bool(re.fullmatch(r"[0-9a-fA-F:]+", text))

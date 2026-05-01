"""
OS string normalization.

Raw OS strings from ManageEngine, SolarWinds, AD, and Nessus are messy:
  "Microsoft Windows Server 2019 Standard (10.0.17763)"
  "Ubuntu 22.04.3 LTS"
  "Red Hat Enterprise Linux release 8.7"
  "VMware ESXi 7.0.3"

The technique applicable() functions use _os_is() which checks for lowercase
substrings in the normalized os field.  We normalize to a consistent lowercase
string that preserves the key tokens those checks need.

normalize_os(raw) → str   (always returns a string, never raises)
os_family(raw)   → str   ("windows" | "linux" | "macos" | "network" | "esxi" | "unknown")
"""
from __future__ import annotations
import re

# ── Ordered rules: (regex pattern, normalized output) ──────────────────────
# First match wins. Patterns are case-insensitive.

_RULES: list[tuple[re.Pattern, str]] = [
    # Windows Server
    (re.compile(r"windows\s+server\s+2025",          re.I), "windows server 2025"),
    (re.compile(r"windows\s+server\s+2022",          re.I), "windows server 2022"),
    (re.compile(r"windows\s+server\s+2019",          re.I), "windows server 2019"),
    (re.compile(r"windows\s+server\s+2016",          re.I), "windows server 2016"),
    (re.compile(r"windows\s+server\s+2012\s+r2",     re.I), "windows server 2012 r2"),
    (re.compile(r"windows\s+server\s+2012",          re.I), "windows server 2012"),
    (re.compile(r"windows\s+server\s+2008\s+r2",     re.I), "windows server 2008 r2"),
    (re.compile(r"windows\s+server\s+2008",          re.I), "windows server 2008"),
    (re.compile(r"windows\s+server",                 re.I), "windows server"),
    # Windows Desktop
    (re.compile(r"windows\s+11",                     re.I), "windows 11"),
    (re.compile(r"windows\s+10",                     re.I), "windows 10"),
    (re.compile(r"windows\s+7",                      re.I), "windows 7"),
    (re.compile(r"windows\s+xp",                     re.I), "windows xp"),
    (re.compile(r"microsoft\s+windows",              re.I), "windows"),
    (re.compile(r"\bwindows\b",                      re.I), "windows"),
    # Linux distros
    (re.compile(r"ubuntu\s+([\d.]+\s*lts|[\d.]+)",   re.I), "ubuntu linux"),
    (re.compile(r"\bubuntu\b",                       re.I), "ubuntu linux"),
    (re.compile(r"red\s+hat.*?(\d+\.\d+|\d+)",       re.I), "rhel linux"),
    (re.compile(r"\brhel\b",                         re.I), "rhel linux"),
    (re.compile(r"centos\s*(linux)?\s*\d",           re.I), "centos linux"),
    (re.compile(r"\bcentos\b",                       re.I), "centos linux"),
    (re.compile(r"debian\s*(gnu/linux)?",            re.I), "debian linux"),
    (re.compile(r"amazon\s+linux",                   re.I), "amazon linux"),
    (re.compile(r"oracle\s+linux",                   re.I), "oracle linux"),
    (re.compile(r"suse\s+linux|sles",                re.I), "suse linux"),
    (re.compile(r"fedora",                           re.I), "fedora linux"),
    (re.compile(r"kali\s+linux",                     re.I), "kali linux"),
    (re.compile(r"\blinux\b",                        re.I), "linux"),
    # macOS
    (re.compile(r"macos|mac\s+os\s+x|os\s+x",       re.I), "macos"),
    # Network / infrastructure OS
    (re.compile(r"cisco\s+ios",                      re.I), "cisco ios"),
    (re.compile(r"fortios|fortigate",                re.I), "fortios"),
    (re.compile(r"panos|pan-os",                     re.I), "panos"),
    (re.compile(r"junos",                            re.I), "junos"),
    # Hypervisors
    (re.compile(r"vmware\s+esxi|esxi",               re.I), "esxi"),
    (re.compile(r"hyper-v",                          re.I), "windows hyper-v"),
]

_FAMILY_MAP: list[tuple[re.Pattern, str]] = [
    (re.compile(r"windows",      re.I), "windows"),
    (re.compile(r"linux|ubuntu|centos|rhel|debian|suse|fedora|amazon linux|oracle linux|kali", re.I), "linux"),
    (re.compile(r"macos",        re.I), "macos"),
    (re.compile(r"cisco|fortios|panos|junos", re.I), "network"),
    (re.compile(r"esxi",         re.I), "esxi"),
]


def normalize_os(raw: str | None) -> str:
    """
    Return a lowercase normalized OS string.
    Preserves enough detail for version-specific logic while being consistent.
    """
    if not raw:
        return ""
    raw = str(raw).strip()
    for pattern, normalized in _RULES:
        if pattern.search(raw):
            return normalized
    # Fallback: lowercase + strip noise
    return re.sub(r"\s+", " ", raw.lower()).strip()


def os_family(raw: str | None) -> str:
    """Return the broad OS family: windows | linux | macos | network | esxi | unknown"""
    normalized = normalize_os(raw)
    for pattern, family in _FAMILY_MAP:
        if pattern.search(normalized):
            return family
    return "unknown"


def normalize_ports(raw_ports) -> list[str]:
    """
    Normalize a port collection to a consistent list of string port numbers.
    Accepts: JSON string, list, comma-separated string, int, None.
    Returns: ["22", "80", "443", ...] — deduplicated, sorted numerically.
    """
    if raw_ports is None:
        return []

    if isinstance(raw_ports, list):
        items = raw_ports
    elif isinstance(raw_ports, str):
        import json
        try:
            parsed = json.loads(raw_ports)
            items = parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, ValueError):
            items = [p.strip() for p in raw_ports.replace(";", ",").split(",")]
    elif isinstance(raw_ports, int):
        return [str(raw_ports)]
    else:
        return []

    ports: set[str] = set()
    for item in items:
        s = str(item).strip()
        # Handle "port/protocol" format (e.g. "22/tcp")
        if "/" in s:
            s = s.split("/")[0]
        if s.isdigit():
            n = int(s)
            if 0 < n < 65536:
                ports.add(str(n))

    return sorted(ports, key=lambda p: int(p))

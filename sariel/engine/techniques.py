"""
Attack techniques — atomic, node-aware lateral movement and exploitation methods.

Design:
- Each Technique describes ONE way to move FROM a compromised node TO a next node.
- Techniques are NOT pre-matched to fixed graph shapes. Instead, the traversal
  engine calls `select_techniques(node)` to get all techniques applicable to a
  given compromised node, then executes their Cypher to find reachable targets.
- The Cypher for each technique takes `$source_id` as a parameter and returns
  candidate next-hop rows.
- Techniques carry a `method_selector` — a function that inspects a node's
  properties and returns True if that technique is plausible for that node.

Technique categories (MITRE-aligned):
  LATERAL_MOVE    — host-to-host movement
  CREDENTIAL      — credential / token theft enabling further movement
  PRIV_ESC        — privilege escalation on or from current node
  COLLECTION      — access to sensitive data / secrets
  CLOUD_MOVE      — cloud-specific lateral movement (IAM, IMDS, federation)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------

@dataclass
class Technique:
    id: str                         # unique slug, used in path IDs
    name: str                       # human-readable name
    category: str                   # LATERAL_MOVE | CREDENTIAL | PRIV_ESC | COLLECTION | CLOUD_MOVE
    mitre_id: str                   # e.g. "T1021.002"
    description: str

    # Cypher query.  Must accept $source_id parameter.
    # Must RETURN: target_id, target_label, target_type, edge_type, and any
    # technique-specific scoring fields (cvss_score, port, etc.)
    cypher: str

    # Returns True if this technique is applicable for the given node dict.
    # node dict has keys from Neo4j properties + '_labels' list.
    applicable: Callable[[dict], bool]

    # Base confidence for this technique (0-1). Multiplied by graph evidence.
    base_confidence: float = 0.6

    # Extra scoring modifiers applied when this technique is used
    score_modifiers: dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper: node property accessors
# ---------------------------------------------------------------------------

def _has_service(node: dict, *port_or_names: str | int) -> bool:
    """True if node exposes any of the given ports or service names."""
    services = node.get("open_ports") or node.get("services") or []
    if isinstance(services, str):
        import json
        try:
            services = json.loads(services)
        except Exception:
            services = [services]
    svc_str = " ".join(str(s).lower() for s in services)
    return any(str(p).lower() in svc_str for p in port_or_names)


def _os_is(node: dict, *os_fragments: str) -> bool:
    os_val = (node.get("os") or node.get("platform") or "").lower()
    return any(f.lower() in os_val for f in os_fragments)


def _has_vuln_keyword(node: dict, *keywords: str) -> bool:
    vulns = node.get("vuln_ids") or node.get("cve_ids") or []
    if isinstance(vulns, str):
        import json
        try:
            vulns = json.loads(vulns)
        except Exception:
            vulns = [vulns]
    vuln_str = " ".join(str(v).lower() for v in vulns)
    return any(k.lower() in vuln_str for k in keywords)


def _is_compute(node: dict) -> bool:
    labels = node.get("_labels") or []
    return "ComputeAsset" in labels


def _is_identity(node: dict) -> bool:
    labels = node.get("_labels") or []
    return "IdentityPrincipal" in labels


def _is_cloud(node: dict, *clouds: str) -> bool:
    cloud = (node.get("cloud") or "").lower()
    return any(c.lower() == cloud for c in clouds)


# ---------------------------------------------------------------------------
# Technique definitions
# ---------------------------------------------------------------------------

# ── T1: SMB Lateral Movement (Windows → Windows) ───────────────────────────
TECHNIQUE_SMB_LATERAL = Technique(
    id="smb_lateral",
    name="SMB Lateral Movement",
    category="LATERAL_MOVE",
    mitre_id="T1021.002",
    description="Move to adjacent Windows host via SMB (445). Requires compromised credentials or pass-the-hash.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:CAN_REACH|IN_SUBNET]->(target:ComputeAsset)
    WHERE target.canonical_id <> $source_id
      AND (target.open_ports IS NOT NULL AND '445' IN target.open_ports
           OR target.services IS NOT NULL AND 'smb' IN toLower(target.services))
    OPTIONAL MATCH (target)-[:HAS_VULN]->(vuln:Vulnerability)
    RETURN
      target.canonical_id   AS target_id,
      target.label          AS target_label,
      labels(target)        AS target_labels,
      target.os             AS target_os,
      target.cloud          AS target_cloud,
      target.account_id     AS target_account_id,
      target.has_public_ip  AS target_public_ip,
      'SMB_LATERAL_MOVE'    AS edge_type,
      max(vuln.cvss_score)  AS best_cvss,
      count(vuln)           AS vuln_count
    """,
    applicable=lambda node: (
        _is_compute(node) and
        (_os_is(node, "windows") or _has_service(node, "445", "smb"))
    ),
    base_confidence=0.65,
)

# ── T2: RDP Brute / Pass-the-Hash ──────────────────────────────────────────
TECHNIQUE_RDP_LATERAL = Technique(
    id="rdp_lateral",
    name="RDP Lateral Movement",
    category="LATERAL_MOVE",
    mitre_id="T1021.001",
    description="Move to Windows host exposing RDP (3389) using stolen credentials or pass-the-hash.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:CAN_REACH|IN_SUBNET]->(target:ComputeAsset)
    WHERE target.canonical_id <> $source_id
      AND (target.open_ports IS NOT NULL AND '3389' IN target.open_ports
           OR target.services IS NOT NULL AND 'rdp' IN toLower(target.services))
    OPTIONAL MATCH (target)-[:HAS_VULN]->(vuln:Vulnerability)
    RETURN
      target.canonical_id   AS target_id,
      target.label          AS target_label,
      labels(target)        AS target_labels,
      target.os             AS target_os,
      target.cloud          AS target_cloud,
      target.account_id     AS target_account_id,
      target.has_public_ip  AS target_public_ip,
      'RDP_LATERAL_MOVE'    AS edge_type,
      max(vuln.cvss_score)  AS best_cvss,
      count(vuln)           AS vuln_count
    """,
    applicable=lambda node: (
        _is_compute(node) and
        (_os_is(node, "windows") or _has_service(node, "3389", "rdp"))
    ),
    base_confidence=0.55,
)

# ── T3: SSH Lateral Movement (Linux/Unix) ──────────────────────────────────
TECHNIQUE_SSH_LATERAL = Technique(
    id="ssh_lateral",
    name="SSH Lateral Movement",
    category="LATERAL_MOVE",
    mitre_id="T1021.004",
    description="Move to Linux/Unix host via SSH using stolen keys or credentials.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:CAN_REACH|IN_SUBNET]->(target:ComputeAsset)
    WHERE target.canonical_id <> $source_id
      AND (target.open_ports IS NOT NULL AND '22' IN target.open_ports
           OR target.services IS NOT NULL AND 'ssh' IN toLower(target.services))
    OPTIONAL MATCH (target)-[:HAS_VULN]->(vuln:Vulnerability)
    RETURN
      target.canonical_id   AS target_id,
      target.label          AS target_label,
      labels(target)        AS target_labels,
      target.os             AS target_os,
      target.cloud          AS target_cloud,
      target.account_id     AS target_account_id,
      target.has_public_ip  AS target_public_ip,
      'SSH_LATERAL_MOVE'    AS edge_type,
      max(vuln.cvss_score)  AS best_cvss,
      count(vuln)           AS vuln_count
    """,
    applicable=lambda node: (
        _is_compute(node) and
        (_os_is(node, "linux", "unix", "ubuntu", "centos", "rhel", "debian")
         or _has_service(node, "22", "ssh"))
    ),
    base_confidence=0.60,
    score_modifiers={"linux_keys_likely": 3.0},
)

# ── T4: CVE Exploitation (network-reachable service) ───────────────────────
TECHNIQUE_CVE_EXPLOIT = Technique(
    id="cve_exploit",
    name="Remote CVE Exploitation",
    category="LATERAL_MOVE",
    mitre_id="T1190",
    description="Exploit a known CVE on a network-reachable service on the target node.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:CAN_REACH|IN_SUBNET]->(target:ComputeAsset)
    WHERE target.canonical_id <> $source_id
    MATCH (target)-[:HAS_VULN]->(vuln:Vulnerability)
    WHERE vuln.cvss_score >= 7.0
    RETURN
      target.canonical_id   AS target_id,
      target.label          AS target_label,
      labels(target)        AS target_labels,
      target.os             AS target_os,
      target.cloud          AS target_cloud,
      target.account_id     AS target_account_id,
      target.has_public_ip  AS target_public_ip,
      'CVE_EXPLOIT'         AS edge_type,
      max(vuln.cvss_score)  AS best_cvss,
      count(vuln)           AS vuln_count,
      collect(vuln.label)[0] AS top_cve,
      any(v IN collect(vuln.has_exploit) WHERE v = true) AS has_exploit
    """,
    applicable=lambda node: _is_compute(node),
    base_confidence=0.70,
)

# ── T5: AD Credential Harvest → Identity access ────────────────────────────
TECHNIQUE_AD_CRED_HARVEST = Technique(
    id="ad_cred_harvest",
    name="AD Credential Harvest",
    category="CREDENTIAL",
    mitre_id="T1003.006",
    description="Extract AD credentials (LSASS, NTDS, Kerberoasting) to access identity principals.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:MEMBER_OF|HAS_ROLE|RUNS_AS]->(identity:IdentityPrincipal)
    WITH src, identity
    MATCH (identity)-[:CAN_ASSUME|MEMBER_OF]->(target_identity:IdentityPrincipal)
    WHERE target_identity.canonical_id <> $source_id
    RETURN
      target_identity.canonical_id  AS target_id,
      target_identity.label         AS target_label,
      labels(target_identity)       AS target_labels,
      '' AS target_os,
      target_identity.cloud         AS target_cloud,
      target_identity.account_id    AS target_account_id,
      false                         AS target_public_ip,
      'CREDENTIAL_ACCESS'           AS edge_type,
      null                          AS best_cvss,
      0                             AS vuln_count,
      null                          AS top_cve,
      false                         AS has_exploit
    """,
    applicable=lambda node: _is_compute(node) and _os_is(node, "windows"),
    base_confidence=0.60,
)

# ── T6: IMDS / Cloud metadata credential theft → cloud lateral move ─────────
TECHNIQUE_IMDS_THEFT = Technique(
    id="imds_credential_theft",
    name="IMDS Credential Theft",
    category="CLOUD_MOVE",
    mitre_id="T1552.005",
    description="Steal cloud credentials from instance metadata service (IMDS) and use attached role/identity.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:HAS_ROLE|HAS_MANAGED_IDENTITY]->(identity:IdentityPrincipal)
    WITH src, identity
    MATCH (identity)-[:CAN_ACCESS|CAN_ACCESS_VAULT|CAN_ASSUME]->(target)
    WHERE (target:DataStoreBase OR target:IdentityPrincipal OR target:ComputeAsset)
      AND target.canonical_id <> $source_id
    RETURN
      target.canonical_id   AS target_id,
      target.label          AS target_label,
      labels(target)        AS target_labels,
      '' AS target_os,
      target.cloud          AS target_cloud,
      coalesce(target.account_id, src.account_id) AS target_account_id,
      false                 AS target_public_ip,
      'IMDS_CREDENTIAL_THEFT' AS edge_type,
      null                  AS best_cvss,
      0                     AS vuln_count,
      null                  AS top_cve,
      false                 AS has_exploit
    """,
    applicable=lambda node: (
        _is_compute(node) and _is_cloud(node, "aws", "azure")
    ),
    base_confidence=0.75,
    score_modifiers={"cloud_cred_no_mfa": 8.0},
)

# ── T7: Kerberoasting / AS-REP Roasting → AD privilege escalation ──────────
TECHNIQUE_KERBEROAST = Technique(
    id="kerberoast",
    name="Kerberoasting / AS-REP Roasting",
    category="PRIV_ESC",
    mitre_id="T1558.003",
    description="Request Kerberos service tickets for service accounts with weak passwords.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})
    WITH src
    MATCH (svc:IdentityPrincipal)
    WHERE (svc:IAMUser OR svc:EntraUser)
      AND (svc.spn IS NOT NULL OR svc.service_account = true OR svc.user_type = 'service')
      AND svc.canonical_id <> $source_id
    OPTIONAL MATCH (svc)-[:CAN_ASSUME|ASSIGNED_ROLE]->(priv:IdentityPrincipal)
    WHERE priv.is_privileged = true OR priv.is_overpermissioned = true
    RETURN
      svc.canonical_id      AS target_id,
      svc.label             AS target_label,
      labels(svc)           AS target_labels,
      '' AS target_os,
      svc.cloud             AS target_cloud,
      svc.account_id        AS target_account_id,
      false                 AS target_public_ip,
      'KERBEROAST'          AS edge_type,
      null                  AS best_cvss,
      0                     AS vuln_count,
      null                  AS top_cve,
      false                 AS has_exploit
    """,
    applicable=lambda node: (
        _is_compute(node) and _os_is(node, "windows")
    ),
    base_confidence=0.50,
)

# ── T8: IAM Role Chaining (cloud-to-cloud or cross-account) ─────────────────
TECHNIQUE_IAM_CHAIN = Technique(
    id="iam_role_chain",
    name="IAM Role Chaining",
    category="CLOUD_MOVE",
    mitre_id="T1548.005",
    description="Assume a role that can assume another role, escalating privileges or moving cross-account.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:HAS_ROLE|HAS_MANAGED_IDENTITY]->(r1:IdentityPrincipal)
    WITH src, r1
    MATCH (r1)-[:CAN_ASSUME]->(r2:IdentityPrincipal)
    WHERE r2.canonical_id <> $source_id
    OPTIONAL MATCH (r2)-[:CAN_ACCESS|CAN_ACCESS_VAULT]->(ds:DataStoreBase)
    RETURN
      r2.canonical_id       AS target_id,
      r2.label              AS target_label,
      labels(r2)            AS target_labels,
      '' AS target_os,
      r2.cloud              AS target_cloud,
      r2.account_id         AS target_account_id,
      false                 AS target_public_ip,
      'IAM_ROLE_CHAIN'      AS edge_type,
      null                  AS best_cvss,
      0                     AS vuln_count,
      null                  AS top_cve,
      false                 AS has_exploit
    """,
    applicable=lambda node: _is_cloud(node, "aws", "azure"),
    base_confidence=0.65,
)

# ── T9: WinRM Lateral Movement (Windows remote management) ──────────────────
TECHNIQUE_WINRM_LATERAL = Technique(
    id="winrm_lateral",
    name="WinRM Lateral Movement",
    category="LATERAL_MOVE",
    mitre_id="T1021.006",
    description="Execute commands on remote Windows host via WinRM (5985/5986).",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:CAN_REACH|IN_SUBNET]->(target:ComputeAsset)
    WHERE target.canonical_id <> $source_id
      AND (target.open_ports IS NOT NULL AND
           ('5985' IN target.open_ports OR '5986' IN target.open_ports)
           OR target.services IS NOT NULL AND 'winrm' IN toLower(target.services))
    OPTIONAL MATCH (target)-[:HAS_VULN]->(vuln:Vulnerability)
    RETURN
      target.canonical_id   AS target_id,
      target.label          AS target_label,
      labels(target)        AS target_labels,
      target.os             AS target_os,
      target.cloud          AS target_cloud,
      target.account_id     AS target_account_id,
      target.has_public_ip  AS target_public_ip,
      'WINRM_LATERAL_MOVE'  AS edge_type,
      max(vuln.cvss_score)  AS best_cvss,
      count(vuln)           AS vuln_count,
      null                  AS top_cve,
      false                 AS has_exploit
    """,
    applicable=lambda node: (
        _is_compute(node) and
        (_os_is(node, "windows") or _has_service(node, "5985", "5986", "winrm"))
    ),
    base_confidence=0.60,
)

# ── T10: Data store access via attached identity ─────────────────────────────
TECHNIQUE_DATASTORE_ACCESS = Technique(
    id="datastore_access",
    name="Sensitive Data Store Access",
    category="COLLECTION",
    mitre_id="T1530",
    description="Access sensitive data store (S3, blob, database, vault) via attached identity permissions.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:HAS_ROLE|HAS_MANAGED_IDENTITY]->(identity:IdentityPrincipal)
    WITH src, identity
    MATCH (identity)-[:CAN_ACCESS|CAN_ACCESS_VAULT]->(ds:DataStoreBase)
    WHERE ds.sensitivity IN ['critical', 'high', 'medium']
    RETURN
      ds.canonical_id       AS target_id,
      ds.label              AS target_label,
      labels(ds)            AS target_labels,
      '' AS target_os,
      ds.cloud              AS target_cloud,
      coalesce(ds.account_id, src.account_id) AS target_account_id,
      false                 AS target_public_ip,
      'DATA_ACCESS'         AS edge_type,
      null                  AS best_cvss,
      0                     AS vuln_count,
      null                  AS top_cve,
      false                 AS has_exploit
    """,
    applicable=lambda node: _is_compute(node) and _is_cloud(node, "aws", "azure"),
    base_confidence=0.80,
    score_modifiers={"direct_data_access": 5.0},
)

# ── T11: Database lateral movement (SQL, MySQL, etc.) ────────────────────────
TECHNIQUE_DB_LATERAL = Technique(
    id="db_lateral",
    name="Database Lateral Movement",
    category="LATERAL_MOVE",
    mitre_id="T1021",
    description="Connect to a reachable database service using stolen credentials or SQL injection.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:CAN_REACH|IN_SUBNET]->(target:ComputeAsset)
    WHERE target.canonical_id <> $source_id
      AND target.open_ports IS NOT NULL
      AND any(p IN ['1433','3306','5432','1521','27017'] WHERE p IN target.open_ports)
    OPTIONAL MATCH (target)-[:HAS_VULN]->(vuln:Vulnerability)
    RETURN
      target.canonical_id   AS target_id,
      target.label          AS target_label,
      labels(target)        AS target_labels,
      target.os             AS target_os,
      target.cloud          AS target_cloud,
      target.account_id     AS target_account_id,
      target.has_public_ip  AS target_public_ip,
      'DB_LATERAL_MOVE'     AS edge_type,
      max(vuln.cvss_score)  AS best_cvss,
      count(vuln)           AS vuln_count,
      null                  AS top_cve,
      false                 AS has_exploit
    """,
    applicable=lambda node: _is_compute(node),
    base_confidence=0.55,
)

# ── T12: Identity privilege escalation via group membership ─────────────────
TECHNIQUE_GROUP_PRIV_ESC = Technique(
    id="group_priv_esc",
    name="Identity Group Privilege Escalation",
    category="PRIV_ESC",
    mitre_id="T1078",
    description="Escalate privileges by leveraging group membership that grants elevated roles.",
    cypher="""
    MATCH (src:SarielNode {canonical_id: $source_id})-[:HAS_ROLE|HAS_MANAGED_IDENTITY|RUNS_AS]->(identity:IdentityPrincipal)
    WITH src, identity
    MATCH (identity)-[:MEMBER_OF]->(group:IdentityPrincipal)
    MATCH (group)-[:ASSIGNED_ROLE|CAN_ASSUME]->(target:IdentityPrincipal)
    WHERE (target.is_privileged = true OR target.is_overpermissioned = true)
      AND target.canonical_id <> $source_id
    RETURN
      target.canonical_id   AS target_id,
      target.label          AS target_label,
      labels(target)        AS target_labels,
      '' AS target_os,
      target.cloud          AS target_cloud,
      target.account_id     AS target_account_id,
      false                 AS target_public_ip,
      'GROUP_PRIV_ESC'      AS edge_type,
      null                  AS best_cvss,
      0                     AS vuln_count,
      null                  AS top_cve,
      false                 AS has_exploit
    """,
    applicable=lambda node: True,  # applicable from any node type
    base_confidence=0.55,
)


# ---------------------------------------------------------------------------
# Technique registry and selector
# ---------------------------------------------------------------------------

ALL_TECHNIQUES: list[Technique] = [
    TECHNIQUE_SMB_LATERAL,
    TECHNIQUE_RDP_LATERAL,
    TECHNIQUE_SSH_LATERAL,
    TECHNIQUE_CVE_EXPLOIT,
    TECHNIQUE_AD_CRED_HARVEST,
    TECHNIQUE_IMDS_THEFT,
    TECHNIQUE_KERBEROAST,
    TECHNIQUE_IAM_CHAIN,
    TECHNIQUE_WINRM_LATERAL,
    TECHNIQUE_DATASTORE_ACCESS,
    TECHNIQUE_DB_LATERAL,
    TECHNIQUE_GROUP_PRIV_ESC,
]


def select_techniques(node: dict) -> list[Technique]:
    """
    Given a node dict (from Neo4j properties + '_labels'), return all
    techniques applicable to that node as an attacker entry point.
    """
    return [t for t in ALL_TECHNIQUES if t.applicable(node)]

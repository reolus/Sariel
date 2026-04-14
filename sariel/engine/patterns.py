"""
Attack path patterns — Cypher queries for each pattern type.
Each pattern returns rows that the engine converts into AttackPath objects.

Design rules:
- Patterns return raw node IDs and properties, not pre-scored data
- All patterns use base labels (:ComputeAsset, :IdentityPrincipal) so they
  work on both AWS and Azure without modification
- WHERE clauses must be specific — no full graph scans
- Each pattern has a unique name used in path IDs
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class PathPattern:
    name: str
    description: str
    cypher: str
    # Column names returned by the Cypher that map to path node IDs (in order)
    node_id_columns: list[str]
    # Human-readable pattern for explanation
    pattern_template: str


# ─── Pattern 1: Internet-exposed compute with exploitable CVE leading to sensitive data ─────────
PATTERN_PUBLIC_VULN_DATA = PathPattern(
    name="public_vuln_data_access",
    description="Internet-reachable compute with exploitable CVE and attached role/identity accessing sensitive data",
    cypher="""
    MATCH (net:Internet)-[:EXPOSES_PORT]->(nc:NetworkControl)-[:ATTACHED_TO|ATTACHED_TO_NSG]->(compute:ComputeAsset)
    WHERE compute.has_public_ip = true OR compute.has_public_ip IS NULL
    WITH net, nc, compute
    MATCH (compute)-[:HAS_VULN]->(vuln:Vulnerability)
    WHERE vuln.cvss_score >= 7.0
    WITH net, nc, compute, vuln
    MATCH (compute)-[:HAS_ROLE|HAS_MANAGED_IDENTITY]->(identity:IdentityPrincipal)
    WITH net, nc, compute, vuln, identity
    MATCH (identity)-[:CAN_ACCESS|CAN_ACCESS_VAULT|ASSIGNED_ROLE]->(ds)
    WHERE (ds:DataStoreBase OR ds:AzureRoleDefinition)
      AND (ds.sensitivity IN ['critical','high'] OR ds.is_privileged = true)
    RETURN
      net.canonical_id      AS net_id,
      nc.canonical_id       AS nc_id,
      compute.canonical_id  AS compute_id,
      vuln.canonical_id     AS vuln_id,
      identity.canonical_id AS identity_id,
      ds.canonical_id       AS ds_id,
      compute.cloud         AS cloud,
      compute.account_id    AS account_id,
      compute.label         AS compute_label,
      compute.public_ip     AS public_ip,
      vuln.cvss_score       AS cvss_score,
      vuln.cvss_exploitability_score AS cvss_exploit,
      vuln.has_exploit      AS has_exploit,
      vuln.label            AS cve_id,
      ds.sensitivity        AS ds_sensitivity,
      ds.label              AS ds_label,
      ds.is_privileged      AS ds_privileged
    """,
    node_id_columns=["net_id", "nc_id", "compute_id", "vuln_id", "identity_id", "ds_id"],
    pattern_template="Internet → {nc_label} → {compute_label} → {cve_id} → {identity_label} → {ds_label}",
)

# ─── Pattern 2: Identity abuse — over-permissioned or MFA-less user → sensitive data ──────────
PATTERN_IDENTITY_ABUSE = PathPattern(
    name="identity_abuse",
    description="IAM user without MFA or Entra user without MFA/CA policy can access sensitive data",
    cypher="""
    MATCH (user:IdentityPrincipal)
    WHERE (user:IAMUser AND user.mfa_enabled = false)
       OR (user:EntraUser AND (user.mfa_registered = false OR user.mfa_enforced = false))
    WITH user
    // AWS path: user → role assumption → data access
    OPTIONAL MATCH aws_path = (user)-[:CAN_ASSUME]->(role:IAMRole)-[:CAN_ACCESS]->(ds1)
    WHERE role.is_overpermissioned = true
      AND (ds1:DataStoreBase AND ds1.sensitivity IN ['critical','high'])
    // Azure path: user → role assignment → privileged role
    OPTIONAL MATCH az_path = (user)-[:ASSIGNED_ROLE]->(role_def:AzureRoleDefinition)
    WHERE role_def.is_privileged = true
    WITH user,
         role, ds1,
         role_def,
         CASE WHEN aws_path IS NOT NULL THEN [
           user.canonical_id, role.canonical_id, ds1.canonical_id
         ] ELSE [] END AS aws_nodes,
         CASE WHEN az_path IS NOT NULL THEN [
           user.canonical_id, role_def.canonical_id
         ] ELSE [] END AS az_nodes
    WHERE size(aws_nodes) > 0 OR size(az_nodes) > 0
    RETURN
      user.canonical_id     AS user_id,
      user.label            AS user_label,
      user.cloud            AS cloud,
      user.account_id       AS account_id,
      user.is_guest         AS is_guest,
      user.mfa_enabled      AS mfa_enabled,
      user.mfa_registered   AS mfa_registered,
      role.canonical_id     AS role_id,
      role.label            AS role_label,
      role.is_overpermissioned AS role_overperm,
      ds1.canonical_id      AS ds_id,
      ds1.sensitivity       AS ds_sensitivity,
      ds1.label             AS ds_label,
      role_def.canonical_id AS az_role_def_id,
      role_def.label        AS az_role_def_label,
      role_def.is_privileged AS az_role_privileged
    """,
    node_id_columns=["user_id", "role_id", "ds_id"],
    pattern_template="{user_label} (no MFA) → {role_label} → {ds_label}",
)

# ─── Pattern 3: Over-permissioned role/SP → sensitive data (no user needed) ──────────────────
PATTERN_OVERPERMISSIONED_ROLE = PathPattern(
    name="overpermissioned_role",
    description="IAM role or Azure SP with wildcard/privileged permissions attached to internet-reachable compute",
    cypher="""
    MATCH (compute:ComputeAsset)-[:HAS_ROLE|HAS_MANAGED_IDENTITY]->(identity:IdentityPrincipal)
    WHERE compute.has_public_ip = true
    WITH compute, identity
    MATCH (identity)-[:CAN_ACCESS|CAN_ACCESS_VAULT]->(ds:DataStoreBase)
    WHERE ds.sensitivity IN ['critical','high']
      AND (identity:IAMRole AND identity.is_overpermissioned = true
           OR identity:EntraServicePrincipal)
    RETURN
      compute.canonical_id  AS compute_id,
      compute.label         AS compute_label,
      compute.cloud         AS cloud,
      compute.account_id    AS account_id,
      identity.canonical_id AS identity_id,
      identity.label        AS identity_label,
      ds.canonical_id       AS ds_id,
      ds.sensitivity        AS ds_sensitivity,
      ds.label              AS ds_label
    """,
    node_id_columns=["compute_id", "identity_id", "ds_id"],
    pattern_template="{compute_label} (public) → {identity_label} → {ds_label}",
)

# ─── Pattern 4: Entra role-assignable group privilege escalation ──────────────────────────────
PATTERN_ENTRA_GROUP_ESCALATION = PathPattern(
    name="entra_group_escalation",
    description="Role-assignable Entra group with privileged role assignment — any group member or group.write SP can escalate",
    cypher="""
    MATCH (group:EntraGroup)-[:ASSIGNED_ROLE]->(role_def:AzureRoleDefinition)
    WHERE group.is_role_assignable = true
      AND role_def.is_privileged = true
    RETURN
      group.canonical_id    AS group_id,
      group.label           AS group_label,
      group.account_id      AS account_id,
      role_def.canonical_id AS role_def_id,
      role_def.label        AS role_def_label,
      'azure'               AS cloud
    """,
    node_id_columns=["group_id", "role_def_id"],
    pattern_template="{group_label} (role-assignable) → {role_def_label} (privileged)",
)

# ─── Pattern 5: Cross-cloud — Azure Managed Identity federated to AWS role ────────────────────
PATTERN_CROSS_CLOUD_FEDERATION = PathPattern(
    name="cross_cloud_federation",
    description="Azure VM Managed Identity federated to an AWS IAM role with data access",
    cypher="""
    MATCH (vm:AzureVM)-[:HAS_MANAGED_IDENTITY]->(sp:EntraServicePrincipal)
    WHERE sp.is_managed_identity = true
    WITH vm, sp
    MATCH (aws_role:IAMRole)
    WHERE aws_role.federated_principals CONTAINS sp.object_id
       OR aws_role.federated_principals CONTAINS sp.app_id
    WITH vm, sp, aws_role
    MATCH (aws_role)-[:CAN_ACCESS]->(ds:DataStoreBase)
    WHERE ds.sensitivity IN ['critical','high']
    RETURN
      vm.canonical_id       AS vm_id,
      vm.label              AS vm_label,
      sp.canonical_id       AS sp_id,
      sp.label              AS sp_label,
      aws_role.canonical_id AS aws_role_id,
      aws_role.label        AS aws_role_label,
      ds.canonical_id       AS ds_id,
      ds.sensitivity        AS ds_sensitivity,
      ds.label              AS ds_label,
      'cross_cloud'         AS cloud,
      vm.account_id         AS account_id
    """,
    node_id_columns=["vm_id", "sp_id", "aws_role_id", "ds_id"],
    pattern_template="{vm_label} (Azure MI) → {sp_label} → {aws_role_label} (AWS) → {ds_label}",
)

ALL_PATTERNS: list[PathPattern] = [
    PATTERN_PUBLIC_VULN_DATA,
    PATTERN_IDENTITY_ABUSE,
    PATTERN_OVERPERMISSIONED_ROLE,
    PATTERN_ENTRA_GROUP_ESCALATION,
    PATTERN_CROSS_CLOUD_FEDERATION,
]

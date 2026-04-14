"""
Risk scoring engine — multiplicative formula:
  RiskScore = 100 × E × X × P × S

  E = Exposure        (public=1.0, internal=0.4, isolated=0.1)
  X = Exploitability  (cvss_exploit/3.9, or baseline for identity paths)
  P = Privilege gain  (root/admin=1.0, write=0.7, read=0.4, none=0.1)
  S = Sensitivity     (critical=1.0, high=0.7, medium=0.4, low=0.2, public=0.05)

Multiplicative design: any near-zero factor collapses the score.
A private asset with no exploit path cannot score high.
"""
from __future__ import annotations
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ── Factor tables ──────────────────────────────────────────────────────────────

EXPOSURE_SCORES = {
    "public":   1.0,
    "internal": 0.4,
    "isolated": 0.1,
}

SENSITIVITY_SCORES = {
    "critical": 1.0,
    "high":     0.7,
    "medium":   0.4,
    "low":      0.2,
    "public":   0.05,
    "unknown":  0.5,   # conservative default
}

PRIVILEGE_SCORES = {
    "admin":    1.0,
    "write":    0.7,
    "read":     0.4,
    "none":     0.1,
}

# Azure built-in role name → privilege level
AZURE_ROLE_PRIVILEGE = {
    "owner":                      "admin",
    "contributor":                "write",
    "user access administrator":  "admin",
    "global administrator":       "admin",
    "application administrator":  "admin",
    "key vault secrets officer":  "write",
    "key vault reader":           "read",
    "storage blob data owner":    "admin",
    "storage blob data contributor": "write",
    "storage blob data reader":   "read",
    "reader":                     "read",
}

# Baseline exploitability for paths without a CVE
BASELINE_EXPLOITABILITY = {
    "identity_abuse":             0.70,  # trivial if you have creds
    "overpermissioned_role":      0.60,  # needs compute compromise first
    "entra_group_escalation":     0.65,
    "cross_cloud_federation":     0.55,
    "public_vuln_data_access":    None,  # computed from CVSS
}


@dataclass
class RiskFactors:
    exposure: float        # E
    exploitability: float  # X
    privilege: float       # P
    sensitivity: float     # S
    modifiers: dict[str, float] = field(default_factory=dict)


@dataclass
class ScoredPath:
    path_id: str
    pattern_name: str
    score: float
    severity: Severity
    factors: RiskFactors
    title: str
    node_ids: list[str]
    raw_row: dict[str, Any]
    cloud: str
    account_id: str
    confidence: str        # "modeled" | "partial" | "unverified"
    scored_at: datetime = field(default_factory=datetime.utcnow)
    explanation: Optional[str] = None
    fix_recommendations: list[dict] = field(default_factory=list)
    suppressed: bool = False
    suppression_reason: str = ""


class ScoringEngine:
    def __init__(
        self,
        critical_threshold: float = 70.0,
        high_threshold: float = 40.0,
        suppress_below: float = 10.0,
    ):
        self.critical_threshold = critical_threshold
        self.high_threshold = high_threshold
        self.suppress_below = suppress_below

    def score_path(self, pattern_name: str, row: dict[str, Any]) -> ScoredPath:
        factors = self._compute_factors(pattern_name, row)
        raw_score = 100.0 * factors.exposure * factors.exploitability * factors.privilege * factors.sensitivity

        # Apply modifiers (additive adjustments to the raw score, capped at 100)
        for modifier_name, modifier_val in factors.modifiers.items():
            raw_score = min(100.0, raw_score + modifier_val)

        score = round(min(100.0, max(0.0, raw_score)), 1)
        severity = self._classify_severity(score)
        node_ids = self._extract_node_ids(pattern_name, row)
        path_id = _stable_path_id(pattern_name, node_ids)
        title = self._build_title(pattern_name, row)
        confidence = self._assess_confidence(pattern_name, row)
        fixes = self._generate_fixes(pattern_name, row)

        return ScoredPath(
            path_id=path_id,
            pattern_name=pattern_name,
            score=score,
            severity=severity,
            factors=factors,
            title=title,
            node_ids=node_ids,
            raw_row=row,
            cloud=row.get("cloud", "unknown"),
            account_id=row.get("account_id", ""),
            confidence=confidence,
            fix_recommendations=fixes,
            suppressed=score < self.suppress_below,
        )

    def _compute_factors(self, pattern_name: str, row: dict) -> RiskFactors:
        # ── Exposure ──────────────────────────────────────────────────────────
        has_public_ip = row.get("has_public_ip") or row.get("public_ip")
        exposure_str = "public" if has_public_ip else "internal"
        # Internet-exposed via SG/NSG even without explicit public IP flag
        if row.get("net_id") == "internet://0.0.0.0/0":
            exposure_str = "public"
        # Guest users treated as public regardless
        if row.get("is_guest"):
            exposure_str = "public"
        E = EXPOSURE_SCORES.get(exposure_str, 0.4)

        # ── Exploitability ────────────────────────────────────────────────────
        baseline = BASELINE_EXPLOITABILITY.get(pattern_name)
        if baseline is None:
            # Compute from CVSS
            cvss_exploit = float(row.get("cvss_exploit") or row.get("cvss_exploitability_score") or 0)
            has_exploit = bool(row.get("has_exploit"))
            X = min(1.0, cvss_exploit / 3.9) if cvss_exploit > 0 else 0.5
            if has_exploit:
                X = min(1.0, X * 1.15)  # bump for known public exploit
        else:
            X = baseline

        # ── Privilege ─────────────────────────────────────────────────────────
        P = self._compute_privilege(row)

        # ── Sensitivity ───────────────────────────────────────────────────────
        sensitivity_str = (
            row.get("ds_sensitivity")
            or row.get("sensitivity")
            or "unknown"
        ).lower()
        S = SENSITIVITY_SCORES.get(sensitivity_str, 0.5)

        # If role is privileged (Azure Owner/Contributor), override S to 1.0
        if row.get("ds_privileged") or row.get("az_role_privileged"):
            S = 1.0

        # ── Modifiers ─────────────────────────────────────────────────────────
        modifiers: dict[str, float] = {}
        # No MFA on guest account: +10 to raw score
        if row.get("is_guest") and not row.get("mfa_registered"):
            modifiers["guest_no_mfa"] = 10.0
        # Cross-cloud path: slight reduction (requires multi-step)
        if pattern_name == "cross_cloud_federation":
            modifiers["cross_cloud_complexity"] = -5.0
        # Overpermissioned role with wildcard: +5
        if row.get("role_overperm"):
            modifiers["wildcard_policy"] = 5.0

        return RiskFactors(exposure=E, exploitability=X, privilege=P, sensitivity=S, modifiers=modifiers)

    def _compute_privilege(self, row: dict) -> float:
        # IAM role over-permissioned = admin
        if row.get("role_overperm"):
            return PRIVILEGE_SCORES["admin"]
        # Azure privileged role definition
        if row.get("az_role_privileged") or row.get("ds_privileged"):
            return PRIVILEGE_SCORES["admin"]
        # Azure role name lookup
        az_role_label = (row.get("az_role_def_label") or row.get("role_def_label") or "").lower()
        if az_role_label:
            for role_fragment, level in AZURE_ROLE_PRIVILEGE.items():
                if role_fragment in az_role_label:
                    return PRIVILEGE_SCORES[level]
        # CAN_ACCESS with write actions
        actions = row.get("actions") or []
        if isinstance(actions, str):
            import json
            try:
                actions = json.loads(actions)
            except Exception:
                actions = []
        if any("write" in str(a).lower() or "*" in str(a) for a in actions):
            return PRIVILEGE_SCORES["write"]
        if any("read" in str(a).lower() or "get" in str(a).lower() for a in actions):
            return PRIVILEGE_SCORES["read"]
        # Default: write-level (most IAM roles exist for a reason)
        return PRIVILEGE_SCORES["write"]

    def _classify_severity(self, score: float) -> Severity:
        if score >= self.critical_threshold:
            return Severity.CRITICAL
        if score >= self.high_threshold:
            return Severity.HIGH
        if score >= self.suppress_below:
            return Severity.MEDIUM
        return Severity.LOW

    def _extract_node_ids(self, pattern_name: str, row: dict) -> list[str]:
        # Ordered list of non-null IDs in path order
        columns = {
            "public_vuln_data_access":    ["net_id","nc_id","compute_id","vuln_id","identity_id","ds_id"],
            "identity_abuse":             ["user_id","role_id","ds_id","az_role_def_id"],
            "overpermissioned_role":      ["compute_id","identity_id","ds_id"],
            "entra_group_escalation":     ["group_id","role_def_id"],
            "cross_cloud_federation":     ["vm_id","sp_id","aws_role_id","ds_id"],
        }
        cols = columns.get(pattern_name, [])
        return [row[c] for c in cols if row.get(c)]

    def _build_title(self, pattern_name: str, row: dict) -> str:
        if pattern_name == "public_vuln_data_access":
            return (
                f"{row.get('compute_label','compute')} → "
                f"{row.get('cve_id','CVE')} → "
                f"{row.get('ds_label','data store')}"
            )
        if pattern_name == "identity_abuse":
            user = row.get("user_label", "user")
            target = row.get("ds_label") or row.get("az_role_def_label") or "privileged resource"
            return f"{user} (no MFA) → {target}"
        if pattern_name == "overpermissioned_role":
            return (
                f"{row.get('compute_label','compute')} (public) → "
                f"{row.get('identity_label','role')} → "
                f"{row.get('ds_label','data store')}"
            )
        if pattern_name == "entra_group_escalation":
            return (
                f"{row.get('group_label','group')} (role-assignable) → "
                f"{row.get('role_def_label','privileged role')}"
            )
        if pattern_name == "cross_cloud_federation":
            return (
                f"{row.get('vm_label','AzureVM')} MI → "
                f"{row.get('aws_role_label','AWS role')} → "
                f"{row.get('ds_label','data store')}"
            )
        return f"Attack path: {pattern_name}"

    def _assess_confidence(self, pattern_name: str, row: dict) -> str:
        """
        modeled    = all relevant policy types evaluated
        partial    = some policy types not yet modeled (SCPs, resource policies)
        unverified = cross-cloud or inferred link
        """
        if pattern_name == "cross_cloud_federation":
            return "unverified"
        if pattern_name in ("public_vuln_data_access", "overpermissioned_role"):
            return "partial"  # SCPs and resource-based policies not yet modeled
        return "partial"

    def _generate_fixes(self, pattern_name: str, row: dict) -> list[dict]:
        fixes = []
        if pattern_name == "public_vuln_data_access":
            nc_label = row.get("nc_label") or row.get("nc_id", "security group/NSG")
            compute_label = row.get("compute_label", "instance")
            cve_id = row.get("cve_id", "CVE")
            ds_label = row.get("ds_label", "data store")
            fixes = [
                {"priority": 1, "action": f"Restrict {nc_label}: limit inbound port to known IP ranges", "category": "network"},
                {"priority": 2, "action": f"Patch {cve_id} on {compute_label} (update package or AMI/image)", "category": "patching"},
                {"priority": 3, "action": f"Scope role/identity permissions on {ds_label} — remove wildcard actions", "category": "iam"},
            ]
        elif pattern_name == "identity_abuse":
            user = row.get("user_label", "user")
            fixes = [
                {"priority": 1, "action": f"Enforce MFA for {user} immediately", "category": "identity"},
                {"priority": 2, "action": "Apply Conditional Access policy requiring MFA for all users", "category": "identity"},
                {"priority": 3, "action": "Remove direct role assignment — use Just-in-Time access", "category": "iam"},
            ]
        elif pattern_name == "overpermissioned_role":
            fixes = [
                {"priority": 1, "action": f"Remove instance profile from {row.get('compute_label','instance')} or replace with least-privilege role", "category": "iam"},
                {"priority": 2, "action": f"Restrict access to {row.get('ds_label','data store')} with resource-based policy", "category": "iam"},
            ]
        elif pattern_name == "entra_group_escalation":
            fixes = [
                {"priority": 1, "action": f"Remove is_role_assignable flag from {row.get('group_label','group')} if not required", "category": "identity"},
                {"priority": 2, "action": "Audit all members of role-assignable groups — remove stale members", "category": "identity"},
                {"priority": 3, "action": "Require PIM activation for privileged role assignments", "category": "identity"},
            ]
        elif pattern_name == "cross_cloud_federation":
            fixes = [
                {"priority": 1, "action": f"Add condition to AWS role trust policy — restrict to specific VM resource ID", "category": "iam"},
                {"priority": 2, "action": "Enable Managed Identity credential-based logging on Azure side", "category": "monitoring"},
                {"priority": 3, "action": f"Scope {row.get('aws_role_label','AWS role')} permissions — remove broad data access", "category": "iam"},
            ]
        return fixes


def _stable_path_id(pattern_name: str, node_ids: list[str]) -> str:
    """Generate a stable, deterministic path ID from pattern + node set."""
    content = pattern_name + "::" + "::".join(sorted(node_ids))
    digest = hashlib.sha256(content.encode()).hexdigest()[:12]
    prefix = {
        "public_vuln_data_access":   "VUL",
        "identity_abuse":            "IDN",
        "overpermissioned_role":     "OVP",
        "entra_group_escalation":    "GRP",
        "cross_cloud_federation":    "XCC",
    }.get(pattern_name, "PTH")
    return f"{prefix}-{digest.upper()}"

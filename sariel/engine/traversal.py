"""
Dynamic attack path traversal engine.

Starting from a confirmed-compromised node, this engine:
1. Inspects the node's properties (OS, services, vulnerabilities, cloud, roles)
2. Selects all applicable techniques for that node type
3. Executes each technique's Cypher to find reachable next-hop candidates
4. Scores each candidate hop
5. Recurses into each next hop (BFS, bounded by max_depth and max_paths)
6. Returns a flat list of complete multi-hop TraversalPath objects

Key design decisions:
- Attack method is re-selected at EVERY hop based on the target node's actual
  properties, not the source. If a Windows host pivots to a Linux box, SSH
  techniques are evaluated — SMB/RDP are not.
- Cycles are prevented via visited set per branch (not global), so the same
  node can appear in different paths but not loop within one.
- High-value target detection stops a branch and marks it terminal.
"""
from __future__ import annotations

import hashlib
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from neo4j import Driver

from sariel.engine.techniques import ALL_TECHNIQUES, Technique, select_techniques

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TraversalHop:
    """A single step in an attack path."""
    source_id: str
    source_label: str
    target_id: str
    target_label: str
    technique: Technique
    edge_type: str              # as returned by the technique Cypher
    hop_score: float            # 0-100 score for this specific hop
    hop_confidence: float       # 0-1
    target_props: dict          # full Neo4j properties of the target node
    evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)


@dataclass
class TraversalPath:
    """A complete multi-hop attack path from initial compromise to terminal."""
    path_id: str
    start_node_id: str
    end_node_id: str
    hops: list[TraversalHop]
    total_score: float
    severity: str               # CRITICAL | HIGH | MEDIUM | LOW
    is_terminal: bool           # True if end node is high-value target
    terminal_reason: str        # e.g. "sensitive_datastore", "domain_admin"
    technique_chain: list[str]  # ordered list of technique IDs
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def node_ids(self) -> list[str]:
        if not self.hops:
            return [self.start_node_id]
        result = [self.hops[0].source_id]
        for hop in self.hops:
            result.append(hop.target_id)
        return result


# ---------------------------------------------------------------------------
# High-value target detection
# ---------------------------------------------------------------------------

def _is_high_value_target(node: dict) -> tuple[bool, str]:
    """
    Returns (True, reason) if this node is a terminal high-value target.
    These nodes stop traversal on this branch — they ARE the goal.
    """
    labels = set(node.get("_labels") or [])
    props = node

    # Sensitive data stores
    if "DataStoreBase" in labels:
        sensitivity = (props.get("sensitivity") or "").lower()
        if sensitivity in ("critical", "high"):
            return True, f"sensitive_datastore:{sensitivity}"

    # Privileged identity (domain admin, global admin, etc.)
    if "IdentityPrincipal" in labels:
        if props.get("is_privileged") or props.get("is_overpermissioned"):
            return True, "privileged_identity"
        role_label = (props.get("label") or "").lower()
        privileged_keywords = [
            "global administrator", "domain admin", "enterprise admin",
            "owner", "administrator", "root", "admin"
        ]
        if any(k in role_label for k in privileged_keywords):
            return True, "privileged_identity_label"

    # Domain controller
    if "ComputeAsset" in labels:
        label_lower = (props.get("label") or "").lower()
        os_lower = (props.get("os") or "").lower()
        roles = props.get("roles") or []
        if isinstance(roles, str):
            import json
            try:
                roles = json.loads(roles)
            except Exception:
                roles = [roles]
        roles_str = " ".join(str(r).lower() for r in roles)
        if any(k in label_lower for k in ["dc", "domain-controller", "domaincontroller"]):
            return True, "domain_controller"
        if "domain controller" in roles_str or "active directory" in roles_str:
            return True, "domain_controller"
        # Cloud account root / management plane
        if props.get("is_management_plane"):
            return True, "cloud_management_plane"

    # Cloud accounts / subscriptions
    if "CloudAccount" in labels:
        return True, "cloud_account_root"

    return False, ""


# ---------------------------------------------------------------------------
# Hop scoring
# ---------------------------------------------------------------------------

def _score_hop(technique: Technique, source: dict, target: dict, row: dict) -> tuple[float, float, list[str], list[str]]:
    """
    Returns (hop_score 0-100, confidence 0-1, evidence list, missing_evidence list).

    Hop score considers:
    - Technique base confidence
    - CVSS score if exploit-based
    - Whether target has public IP (exposure)
    - Whether target has known exploits
    - Target sensitivity
    """
    evidence: list[str] = []
    missing: list[str] = []

    # Base from technique
    confidence = technique.base_confidence

    # Exploit availability
    best_cvss = float(row.get("best_cvss") or 0)
    has_exploit = bool(row.get("has_exploit"))
    vuln_count = int(row.get("vuln_count") or 0)
    top_cve = row.get("top_cve") or ""

    exploitability = 0.5
    if best_cvss > 0:
        exploitability = min(1.0, best_cvss / 10.0)
        evidence.append(f"CVSS {best_cvss:.1f}")
        if has_exploit:
            exploitability = min(1.0, exploitability * 1.2)
            evidence.append(f"public exploit for {top_cve}")
        if vuln_count > 1:
            evidence.append(f"{vuln_count} vulnerabilities on target")
    elif technique.category in ("LATERAL_MOVE",):
        # No CVE — inferred from service exposure
        missing.append("No CVE data on target — lateral move via service exposure only")

    # Target exposure
    exposure = 0.4
    target_labels = set(target.get("_labels") or [])
    if target.get("has_public_ip") or target.get("target_public_ip"):
        exposure = 1.0
        evidence.append("target is internet-exposed")
    elif "DataStoreBase" in target_labels:
        sensitivity = (target.get("sensitivity") or "unknown").lower()
        from sariel.scoring.engine import SENSITIVITY_SCORES
        exposure = SENSITIVITY_SCORES.get(sensitivity, 0.5)
        evidence.append(f"data store sensitivity: {sensitivity}")
    else:
        missing.append("Network reachability not confirmed (no flow data)")

    # Privilege gained
    priv = 0.5
    if "IdentityPrincipal" in target_labels:
        if target.get("is_privileged") or target.get("is_overpermissioned"):
            priv = 1.0
            evidence.append("target is privileged identity")
        else:
            priv = 0.6
    elif "DataStoreBase" in target_labels:
        priv = 0.7
    elif "ComputeAsset" in target_labels:
        priv = 0.5

    # Apply technique modifiers
    base_score = 100.0 * confidence * exploitability * exposure * priv
    for _, mod_val in technique.score_modifiers.items():
        base_score = min(100.0, base_score + mod_val)

    hop_score = round(min(100.0, max(0.0, base_score)), 1)

    # Adjust confidence based on evidence density
    if not evidence:
        confidence = max(0.1, confidence * 0.5)
        missing.append("No direct graph evidence — technique inferred from node properties")

    return hop_score, confidence, evidence, missing


# ---------------------------------------------------------------------------
# Path scoring (aggregate across hops)
# ---------------------------------------------------------------------------

def _score_path(hops: list[TraversalHop]) -> tuple[float, str]:
    """
    Aggregate score for a full path.
    Uses a decay model: each additional hop slightly reduces the score
    (harder to chain many steps), but high-scoring hops can compensate.
    """
    if not hops:
        return 0.0, "LOW"

    # Weighted average with depth decay: deeper hops count less
    total = 0.0
    weight_sum = 0.0
    for i, hop in enumerate(hops):
        weight = 1.0 / (1.0 + i * 0.15)  # depth decay
        total += hop.hop_score * weight
        weight_sum += weight

    base = total / weight_sum if weight_sum > 0 else 0.0

    # Bonus: path reaches high-value target at end
    last_hop = hops[-1]
    is_hvt, _ = _is_high_value_target(last_hop.target_props)
    if is_hvt:
        base = min(100.0, base * 1.15)

    score = round(min(100.0, max(0.0, base)), 1)

    if score >= 70:
        severity = "CRITICAL"
    elif score >= 40:
        severity = "HIGH"
    elif score >= 15:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity


# ---------------------------------------------------------------------------
# Node fetching helper
# ---------------------------------------------------------------------------

def _fetch_node(session, canonical_id: str) -> Optional[dict]:
    result = session.run(
        "MATCH (n:SarielNode {canonical_id: $id}) RETURN properties(n) AS props, labels(n) AS lbs",
        id=canonical_id,
    )
    rec = result.single()
    if not rec:
        return None
    return {**rec["props"], "_labels": rec["lbs"]}


def _run_technique(session, technique: Technique, source_id: str) -> list[dict]:
    """Execute a technique's Cypher and return list of candidate rows."""
    try:
        result = session.run(technique.cypher, source_id=source_id)
        return [dict(r) for r in result]
    except Exception as e:
        logger.warning("Technique %s failed for source %s: %s", technique.id, source_id, e)
        return []


# ---------------------------------------------------------------------------
# Main traversal engine
# ---------------------------------------------------------------------------

class TraversalEngine:
    def __init__(
        self,
        neo4j_driver: Driver,
        max_depth: int = 5,
        max_paths: int = 100,
        min_hop_score: float = 5.0,
    ):
        self._driver = neo4j_driver
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.min_hop_score = min_hop_score

    def traverse_from(self, start_node_id: str) -> list[TraversalPath]:
        """
        Starting from a compromised node, find all reachable attack paths.

        Returns a list of TraversalPath objects, deduplicated by path_id.
        """
        with self._driver.session() as session:
            start_node = _fetch_node(session, start_node_id)
            if not start_node:
                logger.warning("Start node %s not found in graph", start_node_id)
                return []

        logger.info(
            "Traversal starting from %s (%s)",
            start_node_id,
            start_node.get("label", "?"),
        )

        completed_paths: list[TraversalPath] = []
        seen_path_ids: set[str] = set()

        # BFS queue: (current_node_id, accumulated_hops, visited_ids_in_branch)
        queue: deque[tuple[str, list[TraversalHop], set[str]]] = deque()
        queue.append((start_node_id, [], {start_node_id}))

        with self._driver.session() as session:
            while queue and len(completed_paths) < self.max_paths:
                current_id, hops_so_far, visited = queue.popleft()

                if len(hops_so_far) >= self.max_depth:
                    # Emit as path even if not HVT — analyst can review
                    if hops_so_far:
                        path = self._build_path(hops_so_far, is_terminal=False, terminal_reason="max_depth")
                        if path.path_id not in seen_path_ids:
                            seen_path_ids.add(path.path_id)
                            completed_paths.append(path)
                    continue

                # Fetch the current node to determine applicable techniques
                current_node = _fetch_node(session, current_id)
                if not current_node:
                    continue

                techniques = select_techniques(current_node)
                if not techniques:
                    logger.debug("No techniques applicable for node %s", current_id)
                    if hops_so_far:
                        path = self._build_path(hops_so_far, is_terminal=False, terminal_reason="no_techniques")
                        if path.path_id not in seen_path_ids:
                            seen_path_ids.add(path.path_id)
                            completed_paths.append(path)
                    continue

                found_next = False

                for technique in techniques:
                    candidate_rows = _run_technique(session, technique, current_id)

                    for row in candidate_rows:
                        target_id = row.get("target_id")
                        if not target_id or target_id in visited:
                            continue

                        # Fetch target node for full properties
                        target_node = _fetch_node(session, target_id)
                        if not target_node:
                            # Build a stub from what the technique returned
                            target_node = {
                                "canonical_id": target_id,
                                "label": row.get("target_label", target_id),
                                "os": row.get("target_os", ""),
                                "cloud": row.get("target_cloud", ""),
                                "account_id": row.get("target_account_id", ""),
                                "has_public_ip": row.get("target_public_ip", False),
                                "_labels": list(row.get("target_labels") or []),
                            }

                        hop_score, confidence, evidence, missing = _score_hop(
                            technique, current_node, target_node, row
                        )

                        if hop_score < self.min_hop_score:
                            continue

                        hop = TraversalHop(
                            source_id=current_id,
                            source_label=current_node.get("label", current_id),
                            target_id=target_id,
                            target_label=target_node.get("label", target_id),
                            technique=technique,
                            edge_type=row.get("edge_type", technique.id.upper()),
                            hop_score=hop_score,
                            hop_confidence=confidence,
                            target_props=target_node,
                            evidence=evidence,
                            missing_evidence=missing,
                        )

                        new_hops = hops_so_far + [hop]
                        new_visited = visited | {target_id}
                        found_next = True

                        # Check if target is a high-value terminal
                        is_hvt, hvt_reason = _is_high_value_target(target_node)
                        if is_hvt:
                            path = self._build_path(new_hops, is_terminal=True, terminal_reason=hvt_reason)
                            if path.path_id not in seen_path_ids:
                                seen_path_ids.add(path.path_id)
                                completed_paths.append(path)
                                logger.info(
                                    "Terminal path found: %s (%d hops, score %.1f)",
                                    path.path_id, path.depth, path.total_score,
                                )
                        else:
                            # Continue traversal from this target
                            queue.append((target_id, new_hops, new_visited))

                # If no next hops found from this node, emit the current path
                if not found_next and hops_so_far:
                    path = self._build_path(hops_so_far, is_terminal=False, terminal_reason="dead_end")
                    if path.path_id not in seen_path_ids:
                        seen_path_ids.add(path.path_id)
                        completed_paths.append(path)

        logger.info(
            "Traversal from %s complete: %d paths discovered",
            start_node_id,
            len(completed_paths),
        )
        return completed_paths

    def _build_path(
        self,
        hops: list[TraversalHop],
        is_terminal: bool,
        terminal_reason: str,
    ) -> TraversalPath:
        total_score, severity = _score_path(hops)
        node_ids = []
        if hops:
            node_ids = [hops[0].source_id] + [h.target_id for h in hops]

        path_id = _stable_traversal_id(node_ids, [h.technique.id for h in hops])
        technique_chain = [h.technique.id for h in hops]

        return TraversalPath(
            path_id=path_id,
            start_node_id=hops[0].source_id if hops else "",
            end_node_id=hops[-1].target_id if hops else "",
            hops=hops,
            total_score=total_score,
            severity=severity,
            is_terminal=is_terminal,
            terminal_reason=terminal_reason,
            technique_chain=technique_chain,
        )


def _stable_traversal_id(node_ids: list[str], technique_ids: list[str]) -> str:
    """Deterministic path ID: hash of ordered node sequence + technique chain."""
    content = "::".join(node_ids) + "|" + "->".join(technique_ids)
    digest = hashlib.sha256(content.encode()).hexdigest()[:14]
    return f"TRV-{digest.upper()}"

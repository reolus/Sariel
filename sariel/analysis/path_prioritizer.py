"""Attack path prioritization for Sariel.

This module ranks reachable vulnerable targets and can persist only the top
attack paths back into Neo4j as :AttackPath nodes. It intentionally does not
materialize every Host->Host CAN_REACH relationship. That way Neo4j remains a
database instead of a bonfire.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Iterable


SEVERITY_POINTS = {
    "CRITICAL": 100.0,
    "HIGH": 70.0,
    "MEDIUM": 35.0,
    "LOW": 10.0,
    "INFO": 0.0,
}

RISKY_SERVICES = {
    "cifs", "smb", "microsoft-ds", "ldap", "ldaps", "kerberos", "krb5",
    "rdp", "msrdp", "ms-wbt-server", "ms-wbt-server?", "ssh", "winrm",
    "mssql", "mysql", "postgres", "http", "https", "www",
}

CROWN_JEWEL_HINTS = {
    "dc": 40.0,
    "domain": 35.0,
    "sql": 30.0,
    "db": 25.0,
    "file": 20.0,
    "backup": 25.0,
    "adfs": 30.0,
    "vpn": 25.0,
    "core": 20.0,
}


@dataclass(frozen=True)
class PrioritizedPath:
    source_id: str
    source_name: str
    source_ip: str | None
    source_subnet: str | None
    target_id: str
    target_name: str
    target_ip: str | None
    target_subnet: str | None
    vulnerability_id: str
    vulnerability_name: str
    severity: str
    cvss_score: float
    epss_score: float
    vpr_score: float
    has_exploit: bool
    service: str | None
    port: int | None
    hops: int
    route_confidence: float
    risk_score: float
    path_summary: str
    path_cidrs: list[str]
    path_id: str


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _name(props: dict[str, Any]) -> str:
    return _norm(props.get("hostname") or props.get("label") or props.get("name") or props.get("canonical_id") or props.get("id"))


def _id(props: dict[str, Any], fallback: Any) -> str:
    return _norm(props.get("canonical_id") or props.get("id") or props.get("hostname_key") or props.get("host_key") or fallback)


def _crown_jewel_score(target_name: str) -> float:
    target = target_name.lower()
    return max((score for hint, score in CROWN_JEWEL_HINTS.items() if hint in target), default=0.0)


def calculate_risk_score(row: dict[str, Any]) -> float:
    severity = _norm(row.get("severity")).upper()
    service = _norm(row.get("service")).lower()
    target_name = _norm(row.get("target_name"))
    hops = _safe_float(row.get("hops"), 1.0)
    route_confidence = _safe_float(row.get("route_confidence"), 0.5)

    score = 0.0
    score += SEVERITY_POINTS.get(severity, 0.0)
    score += _safe_float(row.get("cvss_score")) * 10.0
    score += _safe_float(row.get("epss_score")) * 100.0
    score += _safe_float(row.get("vpr_score")) * 10.0
    score += 25.0 if bool(row.get("has_exploit")) else 0.0
    score += 20.0 if service in RISKY_SERVICES else 0.0
    score += _crown_jewel_score(target_name)
    score += route_confidence * 20.0
    score -= max(hops - 1.0, 0.0) * 7.5
    return round(score, 2)


def _path_id(source_id: str, target_id: str, vulnerability_id: str, path_cidrs: Iterable[str]) -> str:
    raw = "|".join([source_id, target_id, vulnerability_id, *path_cidrs])
    return "attackpath:" + sha256(raw.encode("utf-8")).hexdigest()[:32]


class PathPrioritizer:
    def __init__(self, driver: Any, database: str | None = None):
        self.driver = driver
        self.database = database

    def list_sources(self, limit: int | None = None) -> list[str]:
        query = """
        MATCH (src:SarielNode)-[:IN_SUBNET]->(:Subnet)
        WHERE NOT src:Subnet AND NOT src:Vulnerability
        WITH DISTINCT coalesce(src.hostname, src.label, src.name, src.host_key) AS source
        WHERE source IS NOT NULL
        RETURN source
        ORDER BY source
        """
        if limit:
            query += " LIMIT $limit"
        with self.driver.session(database=self.database) as session:
            return [r["source"] for r in session.run(query, limit=limit)]

    def prioritize_for_source(
        self,
        source: str,
        top: int = 25,
        max_hops: int = 4,
    ) -> list[PrioritizedPath]:
        """
        Prioritize attack paths from a single source host.

        Neo4j does not allow parameters inside variable-length relationship
        bounds, so max_hops must be safely validated and inserted directly
        into the Cypher string.
        """
        top = int(top)
        max_hops = int(max_hops)

        if top < 1:
            top = 25

        if max_hops < 1:
            max_hops = 1

        # Hard cap to prevent accidental graph detonation.
        if max_hops > 8:
            max_hops = 8

        query = f"""
        MATCH (src:SarielNode)-[:IN_SUBNET]->(s1:Subnet)
        WHERE NOT src:Subnet
        AND NOT src:Vulnerability
        AND toLower(coalesce(src.hostname, src.label, src.name, src.host_key, ''))
            CONTAINS toLower($source)

        MATCH p =
        (s1)-[reach:CAN_REACH*1..{max_hops}]->(s2:Subnet)
        <-[:IN_SUBNET]-(target:SarielNode)

        WHERE NOT target:Subnet
        AND NOT target:Vulnerability
        AND src <> target

        MATCH (target)-[:HAS_VULN]->(v:Vulnerability)
        WHERE v.severity IN ['CRITICAL', 'HIGH']

        WITH DISTINCT src, s1, s2, target, v, p, reach

        WITH
        src,
        s1,
        s2,
        target,
        v,
        p,
        reduce(conf = 1.0, r IN reach | conf * coalesce(r.confidence, 0.5)) AS route_confidence,
        [n IN nodes(p) WHERE n.cidr IS NOT NULL | n.cidr] AS path_cidrs

        RETURN
        id(src) AS source_neo4j_id,
        coalesce(src.canonical_id, src.id, src.hostname_key, src.host_key, toString(id(src))) AS source_id,
        coalesce(src.hostname, src.label, src.name, src.host_key) AS source_name,
        coalesce(src.ip_key, src.private_ip, src.ip) AS source_ip,
        s1.cidr AS source_subnet,

        id(target) AS target_neo4j_id,
        coalesce(target.canonical_id, target.id, target.hostname_key, target.host_key, toString(id(target))) AS target_id,
        coalesce(target.hostname, target.label, target.name, target.host_key) AS target_name,
        coalesce(target.ip_key, target.private_ip, target.ip) AS target_ip,
        s2.cidr AS target_subnet,

        id(v) AS vulnerability_neo4j_id,
        coalesce(v.canonical_id, v.cve_id, v.nessus_plugin_id, v.name, v.label, toString(id(v))) AS vulnerability_id,
        coalesce(v.name, v.label, v.cve_id, v.nessus_plugin_name) AS vulnerability_name,
        v.severity AS severity,
        coalesce(v.cvss_score, 0) AS cvss_score,
        coalesce(v.epss_score, 0) AS epss_score,
        coalesce(v.vpr_score, 0) AS vpr_score,
        coalesce(v.has_exploit, false) AS has_exploit,
        coalesce(v.service, '') AS service,
        v.port AS port,

        length(p) + 2 AS hops,
        route_confidence AS route_confidence,
        path_cidrs AS path_cidrs

        LIMIT $query_limit
        """

        # Pull more than top so Python scoring can sort and trim properly.
        query_limit = max(top * 20, 500)
        query_limit = min(query_limit, 5000)

        with self.driver.session(database=self.database) as session:
            records = [
                dict(r)
                for r in session.run(
                    query,
                    source=source,
                    query_limit=query_limit,
                )
            ]

        paths = [self._record_to_path(r) for r in records]
        paths.sort(key=lambda x: x.risk_score, reverse=True)
        return paths[:top]

    def prioritize_for_source_old(self, source: str, top: int = 25, max_hops: int = 4) -> list[PrioritizedPath]:
        query = """
        MATCH (src:SarielNode)-[:IN_SUBNET]->(s1:Subnet)
        WHERE NOT src:Subnet AND NOT src:Vulnerability
          AND toLower(coalesce(src.hostname, src.label, src.name, src.host_key, '')) CONTAINS toLower($source)

        MATCH p = (s1)-[reach:CAN_REACH*1..$max_hops]->(s2:Subnet)<-[:IN_SUBNET]-(target:SarielNode)
        WHERE NOT target:Subnet AND NOT target:Vulnerability AND src <> target

        MATCH (target)-[:HAS_VULN]->(v:Vulnerability)
        WHERE v.severity IN ['CRITICAL','HIGH']

        WITH DISTINCT src, s1, s2, target, v, p, reach
        WITH src, s1, s2, target, v, p,
             reduce(conf = 1.0, r IN reach | conf * coalesce(r.confidence, 0.5)) AS route_confidence,
             [n IN nodes(p) | n.cidr] AS path_cidrs

        RETURN
          id(src) AS source_neo4j_id,
          coalesce(src.canonical_id, src.id, src.hostname_key, src.host_key, toString(id(src))) AS source_id,
          coalesce(src.hostname, src.label, src.name, src.host_key) AS source_name,
          coalesce(src.ip_key, src.private_ip, src.ip) AS source_ip,
          s1.cidr AS source_subnet,
          id(target) AS target_neo4j_id,
          coalesce(target.canonical_id, target.id, target.hostname_key, target.host_key, toString(id(target))) AS target_id,
          coalesce(target.hostname, target.label, target.name, target.host_key) AS target_name,
          coalesce(target.ip_key, target.private_ip, target.ip) AS target_ip,
          s2.cidr AS target_subnet,
          id(v) AS vulnerability_neo4j_id,
          coalesce(v.canonical_id, v.cve_id, v.nessus_plugin_id, v.name, v.label, toString(id(v))) AS vulnerability_id,
          coalesce(v.name, v.label, v.cve_id, v.nessus_plugin_name) AS vulnerability_name,
          v.severity AS severity,
          coalesce(v.cvss_score, 0) AS cvss_score,
          coalesce(v.epss_score, 0) AS epss_score,
          coalesce(v.vpr_score, 0) AS vpr_score,
          coalesce(v.has_exploit, false) AS has_exploit,
          coalesce(v.service, '') AS service,
          v.port AS port,
          length(p) + 2 AS hops,
          route_confidence AS route_confidence,
          path_cidrs AS path_cidrs
        LIMIT 5000
        """
        with self.driver.session(database=self.database) as session:
            records = [dict(r) for r in session.run(query, source=source, top=top, max_hops=max_hops)]
        paths = [self._record_to_path(r) for r in records]
        paths.sort(key=lambda x: x.risk_score, reverse=True)
        return paths[:top]

    def prioritize_all(self, top: int = 100, per_source: int = 10, max_hops: int = 4, source_limit: int | None = None) -> list[PrioritizedPath]:
        all_paths: list[PrioritizedPath] = []
        for source in self.list_sources(limit=source_limit):
            all_paths.extend(self.prioritize_for_source(source, top=per_source, max_hops=max_hops))
        dedup: dict[str, PrioritizedPath] = {p.path_id: p for p in all_paths}
        ranked = sorted(dedup.values(), key=lambda x: x.risk_score, reverse=True)
        return ranked[:top]

    def write_paths(self, paths: list[PrioritizedPath], run_id: str | None = None) -> int:
        if not paths:
            return 0
        run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        payload = [p.__dict__ | {"run_id": run_id, "created_at": datetime.now(timezone.utc).isoformat()} for p in paths]
        query = """
        UNWIND $paths AS row
        MATCH (src:SarielNode {canonical_id: row.source_id})
        MATCH (target:SarielNode {canonical_id: row.target_id})
        MATCH (v:Vulnerability {canonical_id: row.vulnerability_id})
        MERGE (ap:AttackPath:SarielNode {canonical_id: row.path_id})
        SET ap.id = row.path_id,
            ap.source = row.source_name,
            ap.source_id = row.source_id,
            ap.source_ip = row.source_ip,
            ap.source_subnet = row.source_subnet,
            ap.target = row.target_name,
            ap.target_id = row.target_id,
            ap.target_ip = row.target_ip,
            ap.target_subnet = row.target_subnet,
            ap.vulnerability = row.vulnerability_name,
            ap.vulnerability_id = row.vulnerability_id,
            ap.severity = row.severity,
            ap.cvss_score = row.cvss_score,
            ap.epss_score = row.epss_score,
            ap.vpr_score = row.vpr_score,
            ap.has_exploit = row.has_exploit,
            ap.service = row.service,
            ap.port = row.port,
            ap.hops = row.hops,
            ap.route_confidence = row.route_confidence,
            ap.risk_score = row.risk_score,
            ap.path_summary = row.path_summary,
            ap.path_cidrs = row.path_cidrs,
            ap.run_id = row.run_id,
            ap.created_at = row.created_at,
            ap.node_type = 'AttackPath',
            ap.source_system = 'sariel_path_prioritizer'
        MERGE (src)-[:HAS_ATTACK_PATH]->(ap)
        MERGE (ap)-[:TARGETS]->(target)
        MERGE (ap)-[:USES_VULN]->(v)
        RETURN count(ap) AS written
        """
        # Fallback if vulnerability canonical_id matching fails because older data is messy.
        fallback_query = """
        UNWIND $paths AS row
        MATCH (src:SarielNode) WHERE coalesce(src.canonical_id, src.id, src.hostname_key, src.host_key) = row.source_id
        MATCH (target:SarielNode) WHERE coalesce(target.canonical_id, target.id, target.hostname_key, target.host_key) = row.target_id
        MATCH (v:Vulnerability) WHERE coalesce(v.canonical_id, v.cve_id, v.nessus_plugin_id, v.name, v.label) = row.vulnerability_id
        MERGE (ap:AttackPath:SarielNode {canonical_id: row.path_id})
        SET ap += row,
            ap.id = row.path_id,
            ap.node_type = 'AttackPath',
            ap.source_system = 'sariel_path_prioritizer'
        MERGE (src)-[:HAS_ATTACK_PATH]->(ap)
        MERGE (ap)-[:TARGETS]->(target)
        MERGE (ap)-[:USES_VULN]->(v)
        RETURN count(ap) AS written
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, paths=payload).single()
            written = int(result["written"] if result else 0)
            if written == 0:
                result = session.run(fallback_query, paths=payload).single()
                written = int(result["written"] if result else 0)
        return written

    def _record_to_path(self, r: dict[str, Any]) -> PrioritizedPath:
        source_id = _id({"canonical_id": r.get("source_id")}, r.get("source_neo4j_id"))
        target_id = _id({"canonical_id": r.get("target_id")}, r.get("target_neo4j_id"))
        vulnerability_id = _id({"canonical_id": r.get("vulnerability_id")}, r.get("vulnerability_neo4j_id"))
        path_cidrs = [c for c in (r.get("path_cidrs") or []) if c]
        row_for_score = {
            "severity": r.get("severity"),
            "cvss_score": r.get("cvss_score"),
            "epss_score": r.get("epss_score"),
            "vpr_score": r.get("vpr_score"),
            "has_exploit": r.get("has_exploit"),
            "service": r.get("service"),
            "target_name": r.get("target_name"),
            "hops": r.get("hops"),
            "route_confidence": r.get("route_confidence"),
        }
        risk_score = calculate_risk_score(row_for_score)
        source_name = _norm(r.get("source_name"))
        target_name = _norm(r.get("target_name"))
        vuln_name = _norm(r.get("vulnerability_name"))
        summary = f"{source_name} -> {' -> '.join(path_cidrs)} -> {target_name} via {vuln_name}"
        return PrioritizedPath(
            source_id=source_id,
            source_name=source_name,
            source_ip=r.get("source_ip"),
            source_subnet=r.get("source_subnet"),
            target_id=target_id,
            target_name=target_name,
            target_ip=r.get("target_ip"),
            target_subnet=r.get("target_subnet"),
            vulnerability_id=vulnerability_id,
            vulnerability_name=vuln_name,
            severity=_norm(r.get("severity")).upper(),
            cvss_score=_safe_float(r.get("cvss_score")),
            epss_score=_safe_float(r.get("epss_score")),
            vpr_score=_safe_float(r.get("vpr_score")),
            has_exploit=bool(r.get("has_exploit")),
            service=_norm(r.get("service")) or None,
            port=_safe_int(r.get("port")),
            hops=int(_safe_float(r.get("hops"), 0)),
            route_confidence=_safe_float(r.get("route_confidence"), 0.5),
            risk_score=risk_score,
            path_summary=summary,
            path_cidrs=path_cidrs,
            path_id=_path_id(source_id, target_id, vulnerability_id, path_cidrs),
        )

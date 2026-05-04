# fix_duplicate_attack_paths.py
import os
from collections import defaultdict
from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

APOC_AVAILABLE = False  # set True only if APOC is installed and allowed


def normalize_vuln(ap, vuln):
    cves = None

    if vuln:
        cves = vuln.get("cves") or vuln.get("cve_id")

    if isinstance(cves, str):
        import json
        try:
            parsed = json.loads(cves)
            if parsed:
                return f"cve://{sorted(parsed)[0].upper()}"
        except Exception:
            if cves.upper().startswith("CVE-"):
                return f"cve://{cves.upper()}"

    if isinstance(cves, list) and cves:
        return f"cve://{sorted(cves)[0].upper()}"

    vid = ap.get("vulnerability_id") or ""
    if vid.startswith("cve://"):
        return vid.lower().replace("cve://", "cve://").upper().replace("CVE://", "cve://")

    plugin_id = (
        ap.get("nessus_plugin_id")
        or (vuln or {}).get("nessus_plugin_id")
        or (vuln or {}).get("related_nessus_plugin_id")
    )

    if plugin_id:
        return f"plugin://nessus/{plugin_id}"

    return vid or ap.get("vulnerability") or "unknown"


def attack_path_key(ap, vuln):
    return (
        ap.get("source_id"),
        ap.get("target_id"),
        normalize_vuln(ap, vuln),
        str(ap.get("port")),
        ap.get("service"),
        ap.get("source_subnet"),
        ap.get("target_subnet"),
        ap.get("run_id"),
    )


driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

with driver.session() as session:
    rows = session.run("""
        MATCH (ap:AttackPath)
        OPTIONAL MATCH (ap)--(v:Vulnerability)
        RETURN elementId(ap) AS eid, ap AS ap, collect(v)[0] AS vuln
    """).data()

    groups = defaultdict(list)

    for row in rows:
        groups[attack_path_key(dict(row["ap"]), dict(row["vuln"]) if row["vuln"] else None)].append(row)

    duplicates = {k: v for k, v in groups.items() if len(v) > 1}

    print(f"Found {len(duplicates)} duplicate attack-path groups")

    for key, items in duplicates.items():
        def keep_score(row):
            ap = dict(row["ap"])
            vid = ap.get("vulnerability_id", "")
            return (
                1 if vid.startswith("cve://") else 0,
                ap.get("risk_score") or 0,
                ap.get("created_at") or "",
            )

        keeper = sorted(items, key=keep_score, reverse=True)[0]
        victims = [x for x in items if x["eid"] != keeper["eid"]]

        print(f"Keeping {keeper['eid']} deleting {[v['eid'] for v in victims]}")

        for victim in victims:
            session.run("""
                MATCH (ap:AttackPath)
                WHERE elementId(ap) = $eid
                DETACH DELETE ap
            """, eid=victim["eid"])

driver.close()
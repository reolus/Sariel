// Reconciled attack map: source can reach vulnerable target.
// Use this after running: python -m sariel.ingest.reconcile_graph
MATCH (src)
WHERE toLower(coalesce(src.label, src.hostname, src.name, '')) CONTAINS toLower($nodeName)
MATCH p = (src)-[:CAN_REACH*1..4]->(target)
MATCH vulnPath = (target)-[:HAS_VULN]->(v:Vulnerability)
WHERE coalesce(v.severity, vulnPath.severity) IN ['CRITICAL', 'HIGH']
RETURN p, vulnPath
LIMIT 100;

// Show persisted prioritized attack paths
MATCH (src:SarielNode)-[:HAS_ATTACK_PATH]->(ap:AttackPath)-[:TARGETS]->(target:SarielNode)
MATCH (ap)-[:USES_VULN]->(v:Vulnerability)
RETURN
  ap.risk_score AS risk_score,
  ap.severity AS severity,
  ap.hops AS hops,
  ap.source AS source,
  ap.source_subnet AS source_subnet,
  ap.target AS target,
  ap.target_ip AS target_ip,
  ap.target_subnet AS target_subnet,
  ap.vulnerability AS vulnerability,
  ap.service AS service,
  ap.port AS port,
  ap.path_summary AS path_summary
ORDER BY risk_score DESC
LIMIT 100;

// Visualize one persisted path record and its endpoints
MATCH (src:SarielNode)-[:HAS_ATTACK_PATH]->(ap:AttackPath)-[:TARGETS]->(target:SarielNode)
MATCH (ap)-[:USES_VULN]->(v:Vulnerability)
RETURN src, ap, target, v
ORDER BY ap.risk_score DESC
LIMIT 25;

// Host/vulnerability/network identity health checks.
MATCH ()-[r:CAN_REACH]->()
RETURN 'CAN_REACH edges' AS check, count(r) AS count
UNION ALL
MATCH (h)-[:HAS_VULN]->(:Vulnerability)
RETURN 'HAS_VULN host edges' AS check, count(h) AS count
UNION ALL
MATCH (h)-[:HAS_VULN]->(:Vulnerability)
WHERE EXISTS { MATCH (h)-[:CAN_REACH]-() }
RETURN 'Hosts with vuln and reachability' AS check, count(DISTINCT h) AS count
UNION ALL
MATCH (:Vulnerability {name: null})
RETURN 'Vulnerabilities missing name' AS check, count(*) AS count
UNION ALL
MATCH ()-[r:SAME_AS]->()
RETURN 'SAME_AS identity links' AS check, count(r) AS count;

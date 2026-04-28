// Find AI-suggested edges for review
MATCH (s:SarielNode)-[r]->(t:SarielNode)
WHERE type(r) STARTS WITH "SUGGESTS_"
RETURN
  s.hostname AS source,
  type(r) AS suggested_relationship,
  t.hostname AS target,
  r.confidence AS confidence,
  r.attack_method AS attack_method,
  r.path_type AS path_type,
  r.evidence_json AS evidence,
  r.missing_evidence_json AS missing_evidence,
  r.approved AS approved
ORDER BY r.confidence DESC;

// Promote a reviewed suggestion to CAN_REACH
MATCH (s:SarielNode {hostname:$source})-[r:SUGGESTS_CAN_REACH]->(t:SarielNode {hostname:$target})
WHERE r.approved = true
MERGE (s)-[c:CAN_REACH]->(t)
SET c.source = "ai_reviewed",
    c.confidence = r.confidence,
    c.evidence_json = r.evidence_json,
    c.created_at = datetime();

// Show weak vulnerability-only candidate paths
MATCH (s:SarielNode)-[r:SUGGESTS_LATERAL_MOVE]->(t:SarielNode)
WHERE r.path_type = "vulnerability_overlap"
RETURN s.hostname, t.hostname, r.confidence, r.missing_evidence_json
ORDER BY r.confidence DESC;

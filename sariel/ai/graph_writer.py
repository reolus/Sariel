from __future__ import annotations

import json
from neo4j import Driver

from sariel.ai.schemas import AttackMappingResponse, AttackVectorSuggestion


def write_ai_suggestions(driver: Driver, response: AttackMappingResponse) -> int:
    """Write AI suggestions as reviewable graph edges.

    The relationship type is dynamic, so this function validates through
    schemas/validators before it should ever be called.
    """

    count = 0
    with driver.session() as session:
        for suggestion in response.suggestions:
            session.execute_write(_write_one_suggestion, suggestion)
            count += 1
    return count


def _write_one_suggestion(tx, suggestion: AttackVectorSuggestion) -> None:
    rel_type = suggestion.suggested_relationship.value

    # Neo4j does not parameterize relationship type, so rel_type must come
    # from the enum-validated allowlist before query construction.
    query = f"""
    MATCH (source:SarielNode {{hostname: $source_asset}})
    OPTIONAL MATCH (target:SarielNode {{hostname: $target_asset}})
    WITH source, target
    WHERE $target_asset IS NULL OR target IS NOT NULL
    MERGE (source)-[r:{rel_type} {{
        attack_method: $attack_method,
        target_asset: $target_asset
    }}]->(target)
    SET r.confidence = $confidence,
        r.path_type = $path_type,
        r.evidence_json = $evidence_json,
        r.missing_evidence_json = $missing_evidence_json,
        r.limitations_json = $limitations_json,
        r.recommended_data_sources_json = $recommended_data_sources_json,
        r.mitre_attack_techniques_json = $mitre_attack_techniques_json,
        r.approved = false,
        r.source = "ai",
        r.created_at = datetime()
    """

    tx.run(
        query,
        source_asset=suggestion.source_asset,
        target_asset=suggestion.target_asset,
        confidence=suggestion.confidence,
        attack_method=suggestion.attack_method,
        path_type=suggestion.path_type,
        evidence_json=json.dumps([e.model_dump() for e in suggestion.evidence]),
        missing_evidence_json=json.dumps(suggestion.missing_evidence),
        limitations_json=json.dumps(suggestion.limitations),
        recommended_data_sources_json=json.dumps(suggestion.recommended_data_sources),
        mitre_attack_techniques_json=json.dumps(suggestion.mitre_attack_techniques),
    )

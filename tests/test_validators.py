from sariel.ai.schemas import AttackMappingResponse, AttackVectorSuggestion, EvidenceItem
from sariel.ai.validators import validate_attack_mapping


def test_vulnerability_overlap_confidence_is_capped():
    response = AttackMappingResponse(
        source_asset="Genetec-06",
        summary="Candidate path.",
        suggestions=[
            AttackVectorSuggestion(
                source_asset="Genetec-06",
                target_asset="CH-TYLER-SQL-01",
                suggested_relationship="SUGGESTS_LATERAL_MOVE",
                confidence=0.95,
                attack_method="Shared SMB vulnerability overlap",
                path_type="vulnerability_overlap",
                evidence=[EvidenceItem(claim="Both hosts have critical SMB findings.")],
                missing_evidence=["No credential evidence", "No network flow evidence"],
            )
        ],
    )

    validated = validate_attack_mapping(response)
    assert validated.suggestions[0].confidence == 0.60

from __future__ import annotations

from sariel.ai.schemas import AttackMappingResponse, SuggestedRelationship

ALLOWED_AI_EDGES = {edge.value for edge in SuggestedRelationship}

TRUSTED_EDGE_TYPES_BLOCKLIST = {
    "ADMIN_TO",
    "CAN_AUTH_TO",
    "CAN_REACH",
    "EXPLOITABLE_FROM",
    "HAS_CREDENTIAL",
}


def validate_attack_mapping(response: AttackMappingResponse) -> AttackMappingResponse:
    """Validate and defensively adjust AI output before graph write."""

    for suggestion in response.suggestions:
        rel = suggestion.suggested_relationship.value

        if rel not in ALLOWED_AI_EDGES:
            raise ValueError(f"Unsupported AI relationship: {rel}")

        if rel in TRUSTED_EDGE_TYPES_BLOCKLIST:
            raise ValueError(f"AI attempted to create trusted edge: {rel}")

        if suggestion.path_type == "vulnerability_overlap":
            suggestion.confidence = min(suggestion.confidence, 0.60)

        if suggestion.missing_evidence:
            suggestion.confidence = min(suggestion.confidence, 0.75)

        if suggestion.confidence > 0.90:
            suggestion.confidence = 0.90

        if not suggestion.evidence:
            suggestion.confidence = min(suggestion.confidence, 0.35)
            suggestion.limitations.append("No explicit evidence items were supplied by the model.")

    return response

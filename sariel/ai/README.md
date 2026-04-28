# Sariel AI Attack Mapping Engine

This scaffold adds an AI-assisted attack vector mapping layer to Sariel.

It does **not** allow the AI to create trusted attack-path edges directly.  
The AI writes reviewable `SUGGESTS_*` relationships with confidence, evidence, and missing evidence.

## Graph layers

Observed facts:

```text
HAS_VULN
EXPOSES_PORT
RUNS_SERVICE
MEMBER_OF
HAS_SESSION
```

AI-suggested edges:

```text
SUGGESTS_CAN_REACH
SUGGESTS_LATERAL_MOVE
SUGGESTS_PRIV_ESC
SUGGESTS_CREDENTIAL_ACCESS
SUGGESTS_EXPLOITABLE_FROM
SUGGESTS_ATTACK_TECHNIQUE
```

Confirmed edges:

```text
CAN_REACH
CAN_AUTH_TO
ADMIN_TO
EXPLOITABLE_FROM
```

## Install dependencies

```bash
pip install openai pydantic neo4j fastapi
```

## Environment

```bash
export OPENAI_API_KEY="your-key"
export SARIEL_AI_MODEL="gpt-5.5-thinking"
```

## Example usage

```python
from sariel.ai.attack_mapper import AttackMapper
from sariel.ai.graph_context import build_asset_context

context = build_asset_context(driver, "Genetec-06", max_hops=3)
mapper = AttackMapper()
suggestions = mapper.map_attack_vectors(context)

for s in suggestions.suggestions:
    print(s.suggested_relationship, s.confidence, s.attack_method)
```

## API endpoint

This scaffold includes:

```text
POST /ai/map-attack-vectors
```

Request:

```json
{
  "source_hostname": "Genetec-06",
  "target_hostname": "GIS-GEO-ARC-01",
  "max_hops": 4,
  "write_to_graph": true
}
```

Response:

```json
{
  "source_hostname": "Genetec-06",
  "suggestions": [...]
}
```

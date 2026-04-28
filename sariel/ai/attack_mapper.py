from __future__ import annotations

import json
import os
from openai import OpenAI

from sariel.ai.prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from sariel.ai.schemas import AttackMappingResponse, GraphContext
from sariel.ai.validators import validate_attack_mapping


class AttackMapper:
    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.getenv("SARIEL_AI_MODEL", "gpt-5.5-thinking")
        self.client = OpenAI()

    def map_attack_vectors(self, context: GraphContext) -> AttackMappingResponse:
        prompt = USER_PROMPT_TEMPLATE.format(
            source_hostname=context.source_hostname,
            target_hostname=context.target_hostname or "",
            graph_context_json=context.model_dump_json(indent=2),
        )

        completion = self.client.responses.parse(
            model=self.model,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            text_format=AttackMappingResponse,
        )

        parsed = completion.output_parsed
        return validate_attack_mapping(parsed)


def map_attack_vectors_from_json(context_json: str) -> AttackMappingResponse:
    context = GraphContext.model_validate_json(context_json)
    return AttackMapper().map_attack_vectors(context)

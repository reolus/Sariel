"""
LLM explainer — generates plain-English explanations for scored attack paths.
Strictly additive: the LLM receives only structured facts from the graph.
It never influences scores. Explanations are generated async after scoring.

Supports: Anthropic Claude (default), OpenAI GPT-4o, or None (disabled).
"""
from __future__ import annotations
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior cloud security engineer writing explanations for a security platform called Sariel.

You will receive structured data about a detected attack path. Your job is to write a clear, accurate, 3-5 sentence explanation suitable for a security team.

Rules:
- Use plain English. Avoid jargon where possible, but use precise technical terms when needed.
- Explain WHY this is dangerous, not just WHAT it is.
- Do not invent details not present in the data.
- Do not suggest fixes — those are provided separately.
- Do not include any markdown formatting — plain text only.
- Keep it under 100 words."""

AZURE_TERM_MAP = {
    "SecurityGroup": "Network Security Group (NSG)",
    "IAMRole": "IAM role",
    "IAMUser": "IAM user",
    "EntraUser": "Entra ID user",
    "EntraServicePrincipal": "Managed Identity / Service Principal",
    "EntraGroup": "Entra group",
    "AzureRoleDefinition": "Azure RBAC role",
    "AzureVM": "Azure VM",
    "AzureKeyVault": "Azure Key Vault",
    "AzureStorageAccount": "Azure Storage Account",
    "EC2Instance": "EC2 instance",
    "DataStore": "data store",
}


def _build_explanation_prompt(path: dict) -> str:
    factors = path.get("factors", {})
    fixes = path.get("fix_recommendations", [])
    node_ids = path.get("node_ids", [])

    prompt_data = {
        "path_id": path.get("path_id"),
        "pattern": path.get("pattern_name"),
        "title": path.get("title"),
        "severity": path.get("severity"),
        "score": path.get("score"),
        "cloud": path.get("cloud"),
        "risk_factors": {
            "exposure": f"{factors.get('exposure', 0):.2f} (1.0=internet-reachable)",
            "exploitability": f"{factors.get('exploitability', 0):.2f} (1.0=trivially exploitable)",
            "privilege_gained": f"{factors.get('privilege', 0):.2f} (1.0=admin/root)",
            "data_sensitivity": f"{factors.get('sensitivity', 0):.2f} (1.0=critical PII/secrets)",
        },
        "path_nodes": node_ids,
        "confidence": path.get("confidence"),
        "top_fix": fixes[0]["action"] if fixes else None,
    }
    return f"Explain this attack path for a security team:\n\n{json.dumps(prompt_data, indent=2)}"


class LLMExplainer:
    def __init__(self, provider: str, api_key: str):
        self.provider = provider
        self.api_key = api_key
        self._enabled = provider != "none" and bool(api_key)

    async def explain(self, path: dict) -> Optional[str]:
        """Generate explanation for a single path. Returns None if disabled."""
        if not self._enabled:
            return None
        prompt = _build_explanation_prompt(path)
        try:
            if self.provider == "anthropic":
                return await self._call_anthropic(prompt)
            elif self.provider == "openai":
                return await self._call_openai(prompt)
        except Exception as e:
            logger.warning("LLM explanation failed for %s: %s", path.get("path_id"), e)
        return None

    async def explain_batch(self, paths: list[dict], max_score_threshold: float = 40.0) -> dict[str, Optional[str]]:
        """Generate explanations for all paths above threshold. Returns path_id -> explanation."""
        results: dict[str, Optional[str]] = {}
        eligible = [p for p in paths if p.get("score", 0) >= max_score_threshold and not p.get("suppressed")]
        logger.info("Generating LLM explanations for %d/%d paths", len(eligible), len(paths))
        for path in eligible:
            results[path["path_id"]] = await self.explain(path)
        return results

    async def _call_anthropic(self, prompt: str) -> str:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=self.api_key)
        response = await client.messages.create(
            model="claude-opus-4-6",
            max_tokens=300,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()

    async def _call_openai(self, prompt: str) -> str:
        import openai
        client = openai.AsyncOpenAI(api_key=self.api_key)
        response = await client.chat.completions.create(
            model="gpt-4o",
            max_tokens=300,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content.strip()

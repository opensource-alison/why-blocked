"""OpenAI provider using stdlib urllib (no external dependencies)."""

import os
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any

from prompt import build_enrichment_prompt


class OpenAIProvider:
    API_URL = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str, model: str = "gpt-4o", timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def generate_enrichment(
        self,
        policy_findings: List[Dict[str, Any]],
        resource_info: Dict[str, Any],
        locale: str,
    ) -> Dict[str, Any]:
        if not policy_findings:
            return {"summary": "No policy violations found", "nextActions": []}

        prompt = build_enrichment_prompt(policy_findings, resource_info, locale)
        response_text = self._call_api(prompt)
        return self._parse_response(response_text)

    def _call_api(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a Kubernetes security expert. Respond only with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 1000,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.API_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}: {e.read().decode('utf-8')}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Network error: {e.reason}")

    @staticmethod
    def _parse_response(text: str) -> Dict[str, Any]:
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        parsed = json.loads(text)

        if "summary" not in parsed:
            raise ValueError("AI response missing 'summary'")
        if not isinstance(parsed.get("nextActions", []), list):
            raise ValueError("'nextActions' must be a list")
        for a in parsed.get("nextActions", []):
            if not isinstance(a, dict) or "title" not in a or "detail" not in a:
                raise ValueError("Each nextAction must have 'title' and 'detail'")

        return parsed


def create_openai_provider() -> OpenAIProvider:
    api_key = os.environ.get("WHY_AI_API_KEY")
    if not api_key:
        raise RuntimeError("WHY_AI_API_KEY environment variable not set")
    return OpenAIProvider(api_key=api_key)

"""Claude provider using Anthropic Messages API (stdlib only)."""

import os
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from prompt import build_enrichment_prompt


class ClaudeProvider:
    """Claude-based AI enrichment provider using Anthropic Messages API."""

    API_URL = "https://api.anthropic.com/v1/messages"
    ANTHROPIC_VERSION = "2023-06-01"

    def __init__(self, api_key: str, model: str = "claude-3-5-haiku-20241022", timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def generate_enrichment(
        self,
        policy_findings: List[Dict[str, Any]],
        resource_info: Dict[str, Any],
        locale: str,
    ) -> Dict[str, Any]:
        """Generate AI enrichment using Claude API."""
        if not policy_findings:
            return {"summary": "No policy violations found", "nextActions": []}

        prompt = build_enrichment_prompt(policy_findings, resource_info, locale)
        response_text = self._call_api(prompt)
        return self._parse_response(response_text)

    def _call_api(self, prompt: str) -> str:
        """Call Claude REST API using urllib."""
        payload = {
            "model": self.model,
            "max_tokens": 1000,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.API_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": self.ANTHROPIC_VERSION,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))

                # Extract text from Claude response format
                if "content" not in body or len(body["content"]) == 0:
                    raise RuntimeError("No content in Claude response")

                content_block = body["content"][0]
                if "text" not in content_block:
                    raise RuntimeError("No text in Claude response content block")

                return content_block["text"]

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            raise RuntimeError(f"Claude API HTTP {e.code}: {error_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Network error calling Claude: {e.reason}")

    @staticmethod
    def _parse_response(text: str) -> Dict[str, Any]:
        """Parse and validate AI response JSON.

        Reuses the same parsing logic as OpenAI/Gemini for consistency.
        """
        text = text.strip()

        # Remove markdown code block wrapper if present
        if text.startswith("```"):
            lines = text.split("\n")
            lines = lines[1:]  # Skip first line with ```
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]  # Skip last line with ```
            text = "\n".join(lines)

        # Remove json language identifier if present
        if text.startswith("json"):
            text = text[4:].strip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"AI response is not valid JSON: {e}")

        # Validate required fields
        if "summary" not in parsed:
            raise ValueError("AI response missing 'summary'")
        if not isinstance(parsed.get("nextActions", []), list):
            raise ValueError("'nextActions' must be a list")

        for action in parsed.get("nextActions", []):
            if not isinstance(action, dict) or "title" not in action or "detail" not in action:
                raise ValueError("Each nextAction must have 'title' and 'detail'")

        return parsed


def create_claude_provider() -> ClaudeProvider:
    """Factory function to create Claude provider from environment."""
    api_key = os.environ.get("WHY_CLAUDE_API_KEY")
    if not api_key:
        raise RuntimeError("WHY_CLAUDE_API_KEY environment variable not set")

    # Allow model override via env var
    model = os.environ.get("WHY_CLAUDE_MODEL", "claude-3-5-haiku-20241022")

    return ClaudeProvider(api_key=api_key, model=model)

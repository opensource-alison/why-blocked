"""Gemini provider using Google Generative AI REST API (stdlib only)."""

import os
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from prompt import build_enrichment_prompt


class GeminiProvider:
    """Gemini-based AI enrichment provider using Google Generative AI REST API."""

    API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash", timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def generate_enrichment(
        self,
        policy_findings: List[Dict[str, Any]],
        resource_info: Dict[str, Any],
        locale: str,
    ) -> Dict[str, Any]:
        """Generate AI enrichment using Gemini API."""
        if not policy_findings:
            return {"summary": "No policy violations found", "nextActions": []}

        prompt = build_enrichment_prompt(policy_findings, resource_info, locale)
        response_text = self._call_api(prompt)
        return self._parse_response(response_text)

    def _call_api(self, prompt: str) -> str:
        """Call Gemini REST API using urllib."""
        url = f"{self.API_BASE}/{self.model}:generateContent?key={self.api_key}"

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 1000,
                "topP": 0.95,
            }
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))

                # Extract text from Gemini response format
                if "candidates" not in body or len(body["candidates"]) == 0:
                    raise RuntimeError("No candidates in Gemini response")

                candidate = body["candidates"][0]
                if "content" not in candidate or "parts" not in candidate["content"]:
                    raise RuntimeError("Invalid Gemini response structure")

                parts = candidate["content"]["parts"]
                if len(parts) == 0 or "text" not in parts[0]:
                    raise RuntimeError("No text in Gemini response")

                return parts[0]["text"]

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            raise RuntimeError(f"Gemini API HTTP {e.code}: {error_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Network error calling Gemini: {e.reason}")

    @staticmethod
    def _parse_response(text: str) -> Dict[str, Any]:
        """Parse and validate AI response JSON.

        Reuses the same parsing logic as OpenAI for consistency.
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


def create_gemini_provider() -> GeminiProvider:
    """Factory function to create Gemini provider from environment."""
    api_key = os.environ.get("WHY_GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("WHY_GEMINI_API_KEY environment variable not set")

    # Allow model override via env var
    model = os.environ.get("WHY_GEMINI_MODEL", "gemini-1.5-pro")

    return GeminiProvider(api_key=api_key, model=model)

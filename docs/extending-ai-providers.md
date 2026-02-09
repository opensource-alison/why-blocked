# Adding New AI Providers

This guide shows how to add a new AI provider (Gemini, Claude, etc.) to the worker.

## Provider Interface

All providers must implement the `AIProvider` protocol defined in `providers/__init__.py`:

```python
class AIProvider(Protocol):
    def generate_enrichment(
        self,
        policy_findings: List[Dict[str, Any]],
        resource_info: Dict[str, Any],
        locale: str,
    ) -> Dict[str, Any]:
        """
        Returns:
            Dictionary with:
                - summary: str (3-6 short lines)
                - nextActions: List[Dict] with title and detail
                - translations: Dict with translated content if locale != 'en'
        """
```

## Step-by-Step Guide

### 1. Create Provider Module

Create `providers/gemini.py` (or `claude.py`, etc.):

```python
"""Gemini provider implementation."""

import os
import json
import sys
from typing import List, Dict, Any
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from prompt import build_enrichment_prompt


class GeminiProvider:
    """Gemini-based AI enrichment provider."""

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash", timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        # Add Gemini-specific configuration

    def generate_enrichment(
        self,
        policy_findings: List[Dict[str, Any]],
        resource_info: Dict[str, Any],
        locale: str,
    ) -> Dict[str, Any]:
        """Generate AI enrichment using Gemini API."""
        if not policy_findings:
            return {
                "summary": "No policy violations found",
                "nextActions": [],
            }

        prompt = build_enrichment_prompt(policy_findings, resource_info, locale)

        try:
            response_text = self._call_gemini_api(prompt)
            result = self._parse_response(response_text)
            return result
        except Exception as e:
            raise Exception(f"Gemini enrichment failed: {e}")

    def _call_gemini_api(self, prompt: str) -> str:
        """Call Gemini API."""
        # Implement Gemini API call
        # Use urllib or google-generativeai SDK
        pass

    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """Parse and validate the AI response."""
        # Reuse OpenAI's parsing logic or customize
        # See providers/openai.py for reference
        pass


def create_gemini_provider() -> GeminiProvider:
    """Factory function to create Gemini provider from environment."""
    api_key = os.environ.get("WHY_AI_API_KEY")
    if not api_key:
        raise Exception("WHY_AI_API_KEY environment variable not set")

    return GeminiProvider(api_key=api_key)
```

### 2. Register Provider in Factory

Update `providers/__init__.py`:

```python
def create_provider(provider_name: str = None) -> AIProvider:
    """Factory function to create AI provider based on configuration."""
    if provider_name is None:
        provider_name = os.environ.get("WHY_AI_PROVIDER", "openai").lower()

    if provider_name == "openai":
        from providers.openai import create_openai_provider
        return create_openai_provider()

    elif provider_name == "gemini":  # ADD THIS
        from providers.gemini import create_gemini_provider
        return create_gemini_provider()

    # elif provider_name == "claude":
    #     from providers.claude import create_claude_provider
    #     return create_claude_provider()

    else:
        supported = ["openai", "gemini"]  # UPDATE THIS
        raise UnsupportedProviderError(
            f"Unsupported AI provider: '{provider_name}'. "
            f"Supported providers: {', '.join(supported)}"
        )
```

### 3. Add Tests

Add provider-specific tests in `tests/test_worker.py`:

```python
def test_gemini_provider_selection(self):
    """Test gemini provider selection."""
    request = {
        "version": "v1alpha1",
        "requestId": "gemini-001",
        "input": {
            "resource": {
                "kind": "Pod",
                "name": "test",
                "namespace": "default",
            },
            "policyFindings": [
                {
                    "policyId": "TEST-001",
                    "title": "Test",
                    "severity": "HIGH",
                    "message": "Test",
                }
            ],
        },
    }

    # Test with Gemini provider
    result = run_worker(
        request,
        env={
            "WHY_AI_PROVIDER": "gemini",
            "WHY_AI_API_KEY": "test-key",
        },
    )

    # Verify response structure
    assert result["requestId"] == "gemini-001"
    # Add more assertions
```

### 4. Update Documentation

Update README.md:
- Add `gemini` to supported providers list
- Document any Gemini-specific environment variables
- Update examples if needed

## Environment Variable Conventions

Each provider should use:
- `WHY_AI_PROVIDER`: Provider name (e.g., `gemini`, `claude`)
- `WHY_AI_API_KEY`: Provider's API key

For provider-specific config, use:
- `WHY_GEMINI_MODEL`: Override default model
- `WHY_GEMINI_TIMEOUT`: Override timeout
- etc.

## Reusing Prompt Logic

All providers should use the same `build_enrichment_prompt()` function from `prompt.py`. This ensures:
- Consistent instructions across providers
- Technical identifiers are never translated
- Same output format expected

## Parsing Response

The AI response must be JSON with this structure:

```json
{
  "summary": "3-6 short lines explaining issues",
  "nextActions": [
    {
      "title": "Action title",
      "detail": "Action detail"
    }
  ],
  "translations": {
    "summary": "Translated summary",
    "nextActions": [
      {
        "title": "Translated title",
        "detail": "Translated detail"
      }
    ]
  }
}
```

Reuse OpenAI's `_parse_response()` logic or adapt it for your provider's response format.

## Testing Checklist

Before merging a new provider:

- [ ] Provider implements `AIProvider` protocol
- [ ] Factory function registered in `providers/__init__.py`
- [ ] Tests verify provider selection works
- [ ] Tests verify error handling (missing API key, API errors)
- [ ] Documentation updated (README.md, supported providers list)
- [ ] Manual testing with real API key
- [ ] Verify technical identifiers are not translated
- [ ] Verify exit code 0 on all errors
- [ ] Verify stdout is JSON-only (logs to stderr)

## Example: Claude Provider

Here's a minimal Claude provider example:

```python
# providers/claude.py
import os
import json
import urllib.request
from typing import List, Dict, Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from prompt import build_enrichment_prompt


class ClaudeProvider:
    def __init__(self, api_key: str, model: str = "claude-3-5-haiku-20241022"):
        self.api_key = api_key
        self.model = model
        self.api_url = "https://api.anthropic.com/v1/messages"

    def generate_enrichment(self, policy_findings, resource_info, locale):
        prompt = build_enrichment_prompt(policy_findings, resource_info, locale)
        response_text = self._call_claude_api(prompt)
        return self._parse_response(response_text)

    def _call_claude_api(self, prompt: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.model,
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        }

        req = urllib.request.Request(
            self.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data["content"][0]["text"]

    def _parse_response(self, text: str) -> Dict[str, Any]:
        # Reuse OpenAI's parsing logic
        from providers.openai import OpenAIProvider
        return OpenAIProvider("dummy")._parse_response(text)


def create_claude_provider():
    api_key = os.environ.get("WHY_AI_API_KEY")
    if not api_key:
        raise Exception("WHY_AI_API_KEY environment variable not set")
    return ClaudeProvider(api_key=api_key)
```

## Common Pitfalls

1. **Forgetting to update supported providers list** in `create_provider()`
2. **Not handling API errors gracefully** - always raise Exception, never crash
3. **Different response formats** - ensure your provider returns the expected JSON structure
4. **Not testing with missing API key** - must return schema-valid error
5. **Logs to stdout** - all logs must go to stderr only

## Reference Implementation

See `providers/openai.py` for a complete, production-ready reference implementation.

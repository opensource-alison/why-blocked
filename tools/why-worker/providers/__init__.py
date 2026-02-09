"""AI provider interface and factory."""

import os
from typing import Protocol, List, Dict, Any


class AIProvider(Protocol):
    def generate_enrichment(
        self,
        policy_findings: List[Dict[str, Any]],
        resource_info: Dict[str, Any],
        locale: str,
    ) -> Dict[str, Any]: ...


class UnsupportedProviderError(Exception):
    pass


SUPPORTED_PROVIDERS = ["openai", "gemini", "claude"]


def create_provider(provider_name: str = None) -> AIProvider:
    if provider_name is None:
        provider_name = os.environ.get("WHY_AI_PROVIDER", "openai").lower()

    if provider_name == "openai":
        from providers.openai import create_openai_provider
        return create_openai_provider()

    if provider_name == "gemini":
        from providers.gemini import create_gemini_provider
        return create_gemini_provider()

    if provider_name == "claude":
        from providers.claude import create_claude_provider
        return create_claude_provider()

    raise UnsupportedProviderError(
        f"Unsupported AI provider: '{provider_name}'. "
        f"Supported: {', '.join(SUPPORTED_PROVIDERS)}"
    )

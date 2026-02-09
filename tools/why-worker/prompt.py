"""Deterministic prompt builder for AI enrichment."""

from typing import List, Dict, Any
import json

LANGUAGE_NAMES = {
    "en": "English",
    "ko": "Korean",
    "ja": "Japanese",
    "zh": "Chinese",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
}


def build_enrichment_prompt(
    policy_findings: List[Dict[str, Any]],
    resource_info: Dict[str, Any],
    locale: str,
) -> str:
    """Build deterministic prompt for AI enrichment."""
    findings_json = json.dumps(policy_findings, indent=2, sort_keys=True)
    resource_json = json.dumps(resource_info, indent=2, sort_keys=True)
    target_lang = LANGUAGE_NAMES.get(locale, "English")

    return f"""You are analyzing Kubernetes security policy violations for a resource.

RESOURCE:
{resource_json}

POLICY FINDINGS:
{findings_json}

YOUR TASK:
Generate a concise summary and actionable next steps for a developer.

OUTPUT FORMAT (valid JSON only):
{{
  "summary": "3-6 short bullet lines explaining what's wrong and why it's blocked",
  "nextActions": [
    {{
      "title": "Short action title (imperative)",
      "detail": "Concrete step to take"
    }}
  ],
  "translations": {{
    "summary": "Translated summary in {target_lang}",
    "nextActions": [
      {{
        "title": "Translated title in {target_lang}",
        "detail": "Translated detail in {target_lang}"
      }}
    ]
  }}
}}

CRITICAL RULES:
1. DO NOT translate or modify technical identifiers:
   - CVE IDs (e.g., CVE-2024-1234)
   - Kubernetes field paths (e.g., spec.containers[0].securityContext)
   - JSONPath expressions
   - Image references (e.g., nginx:latest, alpine@sha256:...)
   - Policy IDs
   - File paths
   - Resource names/namespaces/kinds
   - Version numbers
   - Command names

2. ONLY translate human-readable sentences and explanations

3. For locale='en' or when locale matches the source, translations.summary and translations.nextActions should be identical to the English version

4. Provide 3-6 nextActions prioritized by impact (most critical first)

5. Keep summary developer-friendly, not verbose

6. Each action must be concrete and actionable

EXAMPLE (locale=ko):
{{
  "summary": "- Pod blocked due to CRITICAL vulnerability CVE-2024-1234\\n- Running as root (spec.securityContext.runAsNonRoot=false)\\n- No resource limits set",
  "nextActions": [
    {{
      "title": "Update base image to fix CVE-2024-1234",
      "detail": "Change image from nginx:1.19 to nginx:1.21.6 or later"
    }},
    {{
      "title": "Enable non-root user",
      "detail": "Set spec.securityContext.runAsNonRoot to true"
    }}
  ],
  "translations": {{
    "summary": "- CVE-2024-1234 CRITICAL 취약점으로 인해 Pod가 차단되었습니다\\n- 루트로 실행 중입니다 (spec.securityContext.runAsNonRoot=false)\\n- 리소스 제한이 설정되지 않았습니다",
    "nextActions": [
      {{
        "title": "CVE-2024-1234 수정을 위해 베이스 이미지 업데이트",
        "detail": "이미지를 nginx:1.19에서 nginx:1.21.6 이상으로 변경"
      }},
      {{
        "title": "non-root 사용자 활성화",
        "detail": "spec.securityContext.runAsNonRoot를 true로 설정"
      }}
    ]
  }}
}}

Generate the JSON response now:"""

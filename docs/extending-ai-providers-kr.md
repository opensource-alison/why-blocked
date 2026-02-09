# 새로운 AI Provider 추가하기

이 가이드는 워커에 새로운 AI Provider(Gemini, Claude 등)를 추가하는 방법을 설명합니다.

## Provider 인터페이스

모든 Provider는 `providers/__init__.py`에 정의된 `AIProvider` 프로토콜을 구현해야 합니다:

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

## 단계별 가이드

### 1. Provider 모듈 생성

`providers/gemini.py` (또는 `claude.py` 등) 파일을 생성합니다:

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

### 2. Factory에 Provider 등록

`providers/__init__.py`를 업데이트합니다:

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

### 3. 테스트 추가

`tests/test_worker.py`에 Provider별 테스트를 추가합니다:

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

### 4. 문서 업데이트

README.md를 업데이트합니다:
- 지원 Provider 목록에 `gemini` 추가
- Gemini 전용 환경 변수 문서화
- 필요시 예시 업데이트

## 환경 변수 규칙

각 Provider는 다음을 사용해야 합니다:
- `WHY_AI_PROVIDER`: Provider 이름 (예: `gemini`, `claude`)
- `WHY_AI_API_KEY`: Provider의 API 키

Provider별 설정에는 다음을 사용합니다:
- `WHY_GEMINI_MODEL`: 기본 모델 재정의
- `WHY_GEMINI_TIMEOUT`: 타임아웃 재정의
- 기타

## 프롬프트 로직 재사용

모든 Provider는 `prompt.py`의 동일한 `build_enrichment_prompt()` 함수를 사용해야 합니다. 이를 통해 다음을 보장합니다:
- Provider 간 일관된 지침
- 기술 식별자는 절대 번역되지 않음
- 동일한 출력 형식 기대

## 응답 파싱

AI 응답은 다음 구조의 JSON이어야 합니다:

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

OpenAI의 `_parse_response()` 로직을 재사용하거나 Provider의 응답 형식에 맞게 조정하세요.

## 테스트 체크리스트

새로운 Provider를 병합하기 전에:

- [ ] Provider가 `AIProvider` 프로토콜 구현
- [ ] Factory 함수가 `providers/__init__.py`에 등록됨
- [ ] 테스트가 Provider 선택 작동을 검증
- [ ] 테스트가 오류 처리 검증 (API 키 누락, API 오류)
- [ ] 문서 업데이트 (README.md, 지원 Provider 목록)
- [ ] 실제 API 키로 수동 테스트
- [ ] 기술 식별자가 번역되지 않음을 검증
- [ ] 모든 오류에서 종료 코드 0 검증
- [ ] stdout이 JSON 전용인지 검증 (로그는 stderr)

## 예시: Claude Provider

최소한의 Claude Provider 예시입니다:

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

## 일반적인 함정

1. **`create_provider()`에서 지원 Provider 목록 업데이트를 잊음**
2. **API 오류를 우아하게 처리하지 않음** - 항상 Exception을 발생시키고, 절대 충돌하지 않음
3. **다른 응답 형식** - Provider가 예상된 JSON 구조를 반환하는지 확인
4. **API 키 누락 테스트를 하지 않음** - 스키마 유효 오류를 반환해야 함
5. **stdout으로 로그 출력** - 모든 로그는 stderr로만 이동해야 함

## 참조 구현

완전하고 프로덕션 준비가 된 참조 구현은 `providers/openai.py`를 참조하세요.

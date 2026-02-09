# why-worker: kubectl-why를 위한 AI 강화 워커

kubectl-why 보안 결정에 대한 AI 기반 강화를 제공하는 Python 워커입니다.

## 개요

이 워커는 **선택 사항**이며 kubectl-why CLI에서 `--ai` 플래그가 활성화될 때만 사용됩니다. CLI는 워커 없이도 완전히 오프라인으로 작동합니다.

### 워커가 수행하는 작업
- STDIN에서 하나의 JSON 요청을 읽음
- AI 기반 요약 및 액션 아이템 생성
- STDOUT으로 하나의 JSON 응답을 작성
- 항상 종료 코드 0으로 종료 (오류는 유효한 JSON 응답으로 반환)

### 워커가 수행하지 않는 작업
- 결정 결과(BLOCKED/ALLOWED 상태)를 변경하지 않음
- 기술 식별자(CVE ID, K8s 경로, 이미지 참조, 정책 ID)를 수정하지 않음
- 요약, 설명, 번역, 제안된 액션으로만 강화

## 사용법

### 기본 사용법
```bash
cat request.json | python3 tools/why-worker/main.py > response.json
```

### OpenAI 사용 (기본값)
```bash
export WHY_AI_API_KEY="your-openai-api-key"
cat request.json | python3 tools/why-worker/main.py > response.json
```

### 환경 변수를 통한 Gemini 사용
```bash
export WHY_AI_PROVIDER="gemini"
export WHY_GEMINI_API_KEY="your-gemini-api-key"
cat request.json | python3 tools/why-worker/main.py > response.json
```

### 요청 파라미터를 통한 Gemini 사용
```bash
export WHY_GEMINI_API_KEY="your-gemini-api-key"
# request.json에 "provider": "gemini" 추가
cat request.json | python3 tools/why-worker/main.py > response.json
```

### 환경 변수를 통한 Claude 사용
```bash
export WHY_AI_PROVIDER="claude"
export WHY_CLAUDE_API_KEY="your-claude-api-key"
cat request.json | python3 tools/why-worker/main.py > response.json
```

### 요청 파라미터를 통한 Claude 사용
```bash
export WHY_CLAUDE_API_KEY="your-claude-api-key"
# request.json에 "provider": "claude" 추가
cat request.json | python3 tools/why-worker/main.py > response.json
```

### 요청 예시
```json
{
  "version": "v1alpha1",
  "requestId": "req-123",
  "locale": "en",
  "provider": "gemini",
  "input": {
    "resource": {
      "kind": "Pod",
      "name": "nginx",
      "namespace": "default"
    },
    "policyFindings": [
      {
        "policyId": "PSP-001",
        "title": "Running as root",
        "severity": "HIGH",
        "message": "Container runs as root user",
        "evidence": [
          {
            "type": "K8S_FIELD",
            "subject": "spec.securityContext.runAsNonRoot",
            "detail": "false"
          }
        ]
      }
    ]
  }
}
```

### 응답 예시
```json
{
  "version": "v1alpha1",
  "requestId": "req-123",
  "decisionAdditions": {
    "summary": "- Pod blocked due to HIGH severity security policy violation\n- Container configured to run as root user (spec.securityContext.runAsNonRoot=false)\n- This violates PSP-001 policy",
    "nextActions": [
      {
        "title": "Enable non-root user constraint",
        "detail": "Set spec.securityContext.runAsNonRoot to true in your Pod spec"
      },
      {
        "title": "Specify a non-root user ID",
        "detail": "Add spec.securityContext.runAsUser with a value > 0 (e.g., 1000)"
      }
    ]
  }
}
```

## 설정

### 환경 변수

#### 프로바이더 선택
- `WHY_AI_PROVIDER`: 사용할 AI 프로바이더 (기본값: `openai`)
  - 지원되는 값: `openai`, `gemini`, `claude`
  - 요청 JSON에서 `"provider": "claude"`로도 지정 가능
  - 우선순위: 요청 파라미터 > 환경 변수 > 기본값 (`openai`)
  - 지원되지 않는 프로바이더가 지정되면 스키마 유효 오류 응답 반환

#### API 키
- **OpenAI**: `WHY_AI_API_KEY`
  - OpenAI API 키 (예: `sk-...`)
  - `WHY_AI_PROVIDER=openai`일 때 사용됨 (기본값)

- **Gemini**: `WHY_GEMINI_API_KEY`
  - Google Generative AI API 키
  - `WHY_AI_PROVIDER=gemini` 또는 요청에 `"provider": "gemini"`일 때 사용됨
  - 키 발급: https://makersuite.google.com/app/apikey

- **Claude**: `WHY_CLAUDE_API_KEY`
  - Anthropic API 키
  - `WHY_AI_PROVIDER=claude` 또는 요청에 `"provider": "claude"`일 때 사용됨
  - 키 발급: https://console.anthropic.com/

#### 선택적 설정
- `WHY_GEMINI_MODEL`: 기본 Gemini 모델 재정의 (기본값: `gemini-1.5-flash`)
  - 다른 옵션: `gemini-1.5-pro`, `gemini-1.5-flash-8b`
- `WHY_CLAUDE_MODEL`: 기본 Claude 모델 재정의 (기본값: `claude-3-5-haiku-20241022`)
  - 다른 옵션: `claude-3-5-sonnet-20241022`, `claude-3-opus-20240229`
- 참고: OpenAI 모델은 기본적으로 `gpt-4o`입니다. 필요시 코드를 통해 재정의 (현재 환경 변수 없음)

### 지원 로케일
- `en` - 영어 (기본값)
- `ko` - 한국어
- `ja` - 일본어
- `zh` - 중국어
- `es` - 스페인어

로케일이 영어가 아닌 경우 번역이 `translations` 필드에 포함됩니다.

## 아키텍처

### 구성 요소
```
tools/why-worker/
├── main.py              # 진입점 (stdin → stdout)
├── models.py            # 스키마 일치 데이터 모델
├── prompt.py            # 결정론적 프롬프트 빌더
├── providers/
│   ├── __init__.py      # AI 프로바이더 인터페이스 및 팩토리
│   ├── openai.py        # OpenAI 구현
│   ├── gemini.py        # Google Gemini 구현
│   └── claude.py        # Anthropic Claude 구현
└── tests/
    └── test_worker.py   # 포괄적인 테스트 (25개 테스트)
```

### 프로바이더 선택

프로바이더는 다음 우선순위로 선택됩니다:
1. **요청 파라미터**: 요청 JSON의 `"provider": "gemini"` (최우선)
2. **환경 변수**: `WHY_AI_PROVIDER=gemini`
3. **기본값**: `openai` (최하위)

워커는 `providers/__init__.py:create_provider()`의 팩토리 패턴을 사용하여 올바른 프로바이더를 인스턴스화합니다.

**지원되는 프로바이더:**
- `openai` - OpenAI GPT 모델 (기본값: `gpt-4o`)
- `gemini` - Google Generative AI (기본값: `gemini-1.5-flash`)
- `claude` - Anthropic Claude 모델 (기본값: `claude-3-5-haiku-20241022`)

**새 프로바이더 추가 방법:**
1. `providers/yourprovider.py`에 `AIProvider` 프로토콜 구현
2. 팩토리 함수 `create_yourprovider_provider()` 추가
3. `providers/__init__.py:create_provider()`를 업데이트하여 새 프로바이더 케이스 추가
4. `SUPPORTED_PROVIDERS` 목록 업데이트
5. 프로바이더 선택 및 오류 처리에 대한 테스트 추가

자세한 지침은 `ADDING_PROVIDERS.md`를 참조하세요.

## 개발

### 의존성 설치
```bash
pip install -r requirements.txt
```

### 테스트 실행
```bash
cd tools/why-worker
python -m pytest tests/ -v
```

### 테스트 커버리지
- 스키마 준수 (요청/응답 파싱)
- 엔드투엔드 stdin → stdout 흐름
- 오류 처리 (API 키 누락, 잘못된 JSON 등)
- 종료 코드 0 검증
- Stdout JSON 전용 검증 (로그 없음)
- 모의 프로바이더를 사용한 AI 강화

### 설계 원칙
1. **최소 의존성**: Python 표준 라이브러리 사용 (json, urllib 등)
2. **스키마 우선**: `schemas/*.schema.json`과 정확히 일치
3. **안전 실패**: 항상 유효한 응답 반환, 절대 충돌하지 않음
4. **플러그 가능**: 새로운 AI 프로바이더 추가 용이
5. **테스트 가능**: 모든 네트워크 호출은 모의 가능

## 스키마 신뢰 출처

워커는 다음 스키마를 엄격하게 따릅니다:
- `schemas/worker-request.schema.json` - 입력 형식
- `schemas/worker-response.schema.json` - 출력 형식
- `schemas/security-decision.schema.json` - 보안 결정 구조

필드 이름을 임의로 만들거나 대소문자를 변경하지 **마십시오**. 스키마에 정의된 정확한 camelCase를 사용하세요.

## 중요 규칙 (프롬프트에 포함됨)

AI 강화를 생성할 때:
1. **번역하지 말아야 할** 기술 식별자:
   - CVE ID (CVE-2024-1234)
   - K8s 필드 경로 (spec.containers[0].image)
   - JSONPath 표현식
   - 이미지 참조 (nginx:latest)
   - 정책 ID
   - 파일 경로
   - 리소스 이름/종류/네임스페이스

2. **오직** 사람이 읽을 수 있는 문장만 번역

3. 요약은 개발자 친화적으로 유지 (3-6줄의 짧은 라인)

4. 3-6개의 구체적이고 우선순위가 지정된 액션 제공

## 로깅

- 모든 로그는 **stderr**로만 출력
- stdout은 JSON 응답 전용으로 예약됨
- 로그 형식: `[why-worker] message`

## 오류 처리

- 잘못된 JSON 입력 → 요약 필드에 오류 반환
- API 키 누락 → 실행 가능한 오류 응답 반환
- AI 타임아웃/실패 → 수동 대체 액션이 포함된 오류 응답 반환
- 항상 종료 코드 0으로 종료하여 Go 대체 처리가 원활하게 진행되도록 함
